/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2001-2019 The ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, the ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* NetIO routines */

#include "conf.h"

/* See RFC 854 for the definition of these Telnet values */

/* Telnet "Interpret As Command" indicator */
#ifndef TELNET_IAC
# define TELNET_IAC	255
#endif

#ifndef TELNET_DONT
# define TELNET_DONT	254
#endif

#ifndef TELNET_DO
# define TELNET_DO	253
#endif

#ifndef TELNET_WONT
# define TELNET_WONT	252
#endif

#ifndef TELNET_WILL
# define TELNET_WILL	251
#endif

/* Telnet "Interrupt Process" code */
#ifndef TELNET_IP
# define TELNET_IP	244
#endif

/* Telnet "Data Mark" code */
#ifndef TELNET_DM
# define TELNET_DM	242
#endif

static const char *trace_channel = "netio";

static pr_netio_t *default_ctrl_netio = NULL, *ctrl_netio = NULL;
static pr_netio_t *default_data_netio = NULL, *data_netio = NULL;
static pr_netio_t *default_othr_netio = NULL, *othr_netio = NULL;

/* Used to track whether the previous text read from the client's control
 * connection was a properly-terminated command.  If so, then read in the
 * next/current text as per normal.  If NOT (e.g. the client sent a too-long
 * command), then read in the next/current text, but ignore it.  Only clear
 * this flag if the next/current command can be read as per normal.
 *
 * The pr_netio_telnet_gets() uses this variable, in conjunction with its
 * saw_newline flag, for handling too-long commands from clients.
 */
static int properly_terminated_prev_command = TRUE;

static pr_netio_stream_t *netio_stream_alloc(pool *parent_pool) {
  pool *netio_pool = NULL;
  pr_netio_stream_t *nstrm = NULL;

  if (!parent_pool) {
    errno = EINVAL;
    return NULL;
  }

  netio_pool = make_sub_pool(parent_pool);
  pr_pool_tag(netio_pool, "netio stream pool");
  nstrm = pcalloc(netio_pool, sizeof(pr_netio_stream_t));

  nstrm->strm_pool = netio_pool;
  nstrm->strm_fd = -1;
  nstrm->strm_mode = 0;
  nstrm->strm_flags = 0;
  nstrm->strm_buf = NULL;
  nstrm->strm_data = NULL;
  nstrm->strm_errno = 0;

  /* This table will not contain that many entries, so a low number
   * of chains should suffice.
   */
  nstrm->notes = pr_table_nalloc(nstrm->strm_pool, 0, 4);

  return nstrm;
}

pr_buffer_t *pr_netio_buffer_alloc(pr_netio_stream_t *nstrm) {
  size_t bufsz;
  pr_buffer_t *pbuf = NULL;

  if (nstrm == NULL) {
    errno = EINVAL;
    return NULL;
  }

  pbuf = pcalloc(nstrm->strm_pool, sizeof(pr_buffer_t));

  /* Allocate a buffer. */
  bufsz = pr_config_get_server_xfer_bufsz(nstrm->strm_mode);
  pbuf->buf = pcalloc(nstrm->strm_pool, bufsz);
  pbuf->buflen = bufsz;

  /* Position the offset at the start of the buffer, and set the
   * remaining bytes value accordingly.
   */
  pbuf->current = pbuf->buf;
  pbuf->remaining = bufsz;

  /* Add this buffer to the given stream. */
  nstrm->strm_buf = pbuf;

  return pbuf;
}

/* Default core NetIO handlers
 */

static void core_netio_abort_cb(pr_netio_stream_t *nstrm) {
  nstrm->strm_flags |= PR_NETIO_SESS_ABORT;
}

static int core_netio_close_cb(pr_netio_stream_t *nstrm) {
  int res = 0;

  if (nstrm->strm_fd != -1) {
    res = close(nstrm->strm_fd);
    nstrm->strm_fd = -1;

  } else {
    errno = EBADF;
    res = -1;
  }

  return res;
}

static pr_netio_stream_t *core_netio_open_cb(pr_netio_stream_t *nstrm, int fd,
    int mode) {

  nstrm->strm_fd = fd;

  /* The stream's strm_mode field does not need to be set, as it is set
   * by the NetIO layer's open() wrapper function.
   */

  return nstrm;
}

static int core_netio_poll_cb(pr_netio_stream_t *nstrm) {
  int res;
  fd_set rfds, *rfdsp, wfds, *wfdsp;
  struct timeval tval;

  FD_ZERO(&rfds);
  rfdsp = NULL;
  FD_ZERO(&wfds);
  wfdsp = NULL;

  if (nstrm->strm_mode == PR_NETIO_IO_RD) {
    if (nstrm->strm_fd >= 0) {
      FD_SET(nstrm->strm_fd, &rfds);
      rfdsp = &rfds;
    }

  } else {
    if (nstrm->strm_fd >= 0) {
      FD_SET(nstrm->strm_fd, &wfds);
      wfdsp = &wfds;
    }
  }

  tval.tv_sec = ((nstrm->strm_flags & PR_NETIO_SESS_INTR) ?
    nstrm->strm_interval: 60);
  tval.tv_usec = 0;

  res = select(nstrm->strm_fd + 1, rfdsp, wfdsp, NULL, &tval);
  while (res < 0) {
    int xerrno = errno;

    if (!(nstrm->strm_flags & PR_NETIO_SESS_INTR)) {
      /* Watch for EAGAIN, and handle it by delaying temporarily. */
      if (xerrno == EAGAIN) {
        errno = EINTR;
        pr_signals_handle();
        continue;
      }
    }

    errno = nstrm->strm_errno = xerrno;
    break; 
  }

  return res;
}

static int core_netio_postopen_cb(pr_netio_stream_t *nstrm) {
  return 0;
}

static int core_netio_read_cb(pr_netio_stream_t *nstrm, char *buf,
    size_t buflen) {
  return read(nstrm->strm_fd, buf, buflen);
}

static pr_netio_stream_t *core_netio_reopen_cb(pr_netio_stream_t *nstrm, int fd,
    int mode) {

  if (nstrm->strm_fd != -1) {
    close(nstrm->strm_fd);
  }

  nstrm->strm_fd = fd;
  nstrm->strm_mode = mode;

  return nstrm;
}

static int core_netio_shutdown_cb(pr_netio_stream_t *nstrm, int how) {
  return shutdown(nstrm->strm_fd, how);
}

static int core_netio_write_cb(pr_netio_stream_t *nstrm, char *buf,
    size_t buflen) {
  return write(nstrm->strm_fd, buf, buflen);
}

static const char *netio_stream_mode(int strm_mode) {
  const char *modestr = "(unknown)";

  switch (strm_mode) {
    case PR_NETIO_IO_RD:
      modestr = "reading";
      break;

    case PR_NETIO_IO_WR:
      modestr = "writing";
      break;

    default:
      break;
  }

  return modestr;
}

/* NetIO API wrapper functions. */

void pr_netio_abort(pr_netio_stream_t *nstrm) {
  const char *nstrm_mode;

  if (nstrm == NULL) {
    errno = EINVAL;
    return;
  }

  nstrm_mode = netio_stream_mode(nstrm->strm_mode);

  switch (nstrm->strm_type) {
    case PR_NETIO_STRM_CTRL:
      if (ctrl_netio != NULL) {
        pr_trace_msg(trace_channel, 19,
          "using %s abort() for control %s stream",
          ctrl_netio->owner_name, nstrm_mode);
        (ctrl_netio->abort)(nstrm);

      } else {
        pr_trace_msg(trace_channel, 19,
          "using %s abort() for control %s stream",
          default_ctrl_netio->owner_name, nstrm_mode);
        (default_ctrl_netio->abort)(nstrm);
      }

      break;

    case PR_NETIO_STRM_DATA:
      if (data_netio != NULL) {
        pr_trace_msg(trace_channel, 19, "using %s abort() for data %s stream",
          data_netio->owner_name, nstrm_mode);
        (data_netio->abort)(nstrm);

      } else {
        pr_trace_msg(trace_channel, 19, "using %s abort() for data %s stream",
          default_data_netio->owner_name, nstrm_mode);
        (default_data_netio->abort)(nstrm);
      }
      break;

    case PR_NETIO_STRM_OTHR:
      if (othr_netio != NULL) {
        pr_trace_msg(trace_channel, 19, "using %s abort() for other %s stream",
          othr_netio->owner_name, nstrm_mode);
        (othr_netio->abort)(nstrm);

      } else {
        pr_trace_msg(trace_channel, 19, "using %s abort() for other %s stream",
          default_othr_netio->owner_name, nstrm_mode);
        (default_othr_netio->abort)(nstrm);
      }
      break;

    default:
      errno = EINVAL;
      return;
  }

  return;
}

int pr_netio_close(pr_netio_stream_t *nstrm) {
  int res = -1, xerrno = 0;
  const char *nstrm_mode;

  if (nstrm == NULL) {
    errno = EINVAL;
    return -1;
  }

  nstrm_mode = netio_stream_mode(nstrm->strm_mode);

  switch (nstrm->strm_type) {
    case PR_NETIO_STRM_CTRL:
      if (ctrl_netio != NULL) {
        pr_trace_msg(trace_channel, 19,
          "using %s close() for control %s stream", ctrl_netio->owner_name,
          nstrm_mode);
        res = (ctrl_netio->close)(nstrm);

      } else {
        pr_trace_msg(trace_channel, 19,
          "using %s close() for control %s stream",
          default_ctrl_netio->owner_name, nstrm_mode);
        res = (default_ctrl_netio->close)(nstrm);
      }
      xerrno = errno;
      break;

    case PR_NETIO_STRM_DATA:
      if (data_netio != NULL) {
        pr_trace_msg(trace_channel, 19, "using %s close() for data %s stream",
          data_netio->owner_name, nstrm_mode);
        res = (data_netio->close)(nstrm);

      } else {
        pr_trace_msg(trace_channel, 19, "using %s close() for data %s stream",
          default_data_netio->owner_name, nstrm_mode);
        res = (default_data_netio->close)(nstrm);
      }
      xerrno = errno;
      break;

    case PR_NETIO_STRM_OTHR:
      if (othr_netio != NULL) {
        pr_trace_msg(trace_channel, 19, "using %s close() for other %s stream",
          othr_netio->owner_name, nstrm_mode);
        res = (othr_netio->close)(nstrm);

      } else {
        pr_trace_msg(trace_channel, 19, "using %s close() for other %s stream",
          default_othr_netio->owner_name, nstrm_mode);
        res = (default_othr_netio->close)(nstrm);
      }
      xerrno = errno;
      break;

    default:
      errno = EPERM;
      return -1;
  }

  /* Make sure to scrub any buffered memory, too. */
  if (nstrm->strm_buf != NULL) {
    pr_buffer_t *pbuf;

    pbuf = nstrm->strm_buf;
    pr_memscrub(pbuf->buf, pbuf->buflen);
  }

  destroy_pool(nstrm->strm_pool);
  errno = xerrno;
  return res;
}

static int netio_lingering_close(pr_netio_stream_t *nstrm, long linger,
    int flags) {
  int res;
  const char *nstrm_mode;

  if (nstrm == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (nstrm->strm_type) {
    case PR_NETIO_STRM_CTRL:
    case PR_NETIO_STRM_DATA:
    case PR_NETIO_STRM_OTHR:
      break;

    default:
      errno = EPERM;
      return -1;
  }

  if (nstrm->strm_fd < 0) {
    /* Already closed. */
    return 0;
  }

  nstrm_mode = netio_stream_mode(nstrm->strm_mode);

  if (!(flags & NETIO_LINGERING_CLOSE_FL_NO_SHUTDOWN)) {
    pr_netio_shutdown(nstrm, 1);
  }

  if (nstrm->strm_fd >= 0) {
    struct timeval tv;
    fd_set rfds;
    time_t when = time(NULL) + linger;

    tv.tv_sec = linger;
    tv.tv_usec = 0L;

    /* Handle timers during reading, once selected for read this
     * should mean all buffers have been flushed and the receiving end
     * has closed.
     */
    while (TRUE) {
      run_schedule();

      FD_ZERO(&rfds);
      FD_SET(nstrm->strm_fd, &rfds);

      pr_trace_msg(trace_channel, 8,
        "lingering %lu %s before closing fd %d",
        (unsigned long) tv.tv_sec, tv.tv_sec != 1 ? "secs" : "sec",
        nstrm->strm_fd);

      res = select(nstrm->strm_fd+1, &rfds, NULL, NULL, &tv);
      if (res == -1) {
        if (errno == EINTR) {
          time_t now = time(NULL);
          pr_signals_handle();

          /* Still here? If the requested lingering interval hasn't passed,
           * continue lingering.  Reset the timeval struct's fields to
           * linger for the interval remaining in the given period of time.
           */
          if (now < when) {
            tv.tv_sec = when - now;
            tv.tv_usec = 0L;
            continue;
          }

        } else {
          nstrm->strm_errno = errno;
          return -1;
        }

      } else {
        if (FD_ISSET(nstrm->strm_fd, &rfds)) {
          pr_trace_msg(trace_channel, 8,
            "received data for reading on fd %d, ignoring", nstrm->strm_fd);
        }
      }

      break;
    }
  }

  pr_trace_msg(trace_channel, 8, "done lingering, closing fd %d",
    nstrm->strm_fd);

  switch (nstrm->strm_type) {
    case PR_NETIO_STRM_CTRL:
      if (ctrl_netio != NULL) {
        pr_trace_msg(trace_channel, 19,
          "using %s close() for control %s stream", ctrl_netio->owner_name,
          nstrm_mode);
        res = (ctrl_netio->close)(nstrm);

      } else {
        pr_trace_msg(trace_channel, 19,
          "using %s close() for control %s stream",
          default_ctrl_netio->owner_name, nstrm_mode);
        res = (default_ctrl_netio->close)(nstrm);
      }
      return res;

    case PR_NETIO_STRM_DATA:
      if (data_netio != NULL) {
        pr_trace_msg(trace_channel, 19, "using %s close() for data %s stream",
          data_netio->owner_name, nstrm_mode);
        res = (data_netio->close)(nstrm);

      } else {
        pr_trace_msg(trace_channel, 19, "using %s close() for data %s stream",
          default_data_netio->owner_name, nstrm_mode);
        res = (default_data_netio->close)(nstrm);
      }
      return res;

    case PR_NETIO_STRM_OTHR:
      if (othr_netio != NULL) {
        pr_trace_msg(trace_channel, 19, "using %s close() for other %s stream",
          othr_netio->owner_name, nstrm_mode);
        res = (othr_netio->close)(nstrm);

      } else {
        pr_trace_msg(trace_channel, 19, "using %s close() for other %s stream",
          default_othr_netio->owner_name, nstrm_mode);
        res = (default_othr_netio->close)(nstrm);
      }
      return res;
  }

  errno = EPERM;
  return -1;
}

int pr_netio_lingering_abort(pr_netio_stream_t *nstrm, long linger) {
  int res;

  if (nstrm == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (nstrm->strm_type) {
    case PR_NETIO_STRM_CTRL:
    case PR_NETIO_STRM_DATA:
    case PR_NETIO_STRM_OTHR:
      break;

    default:
      errno = EPERM;
      return -1;
  }

  /* Send an appropriate response code down the stream asynchronously. */
  pr_response_send_async(R_426, _("Transfer aborted. Data connection closed."));

  pr_netio_shutdown(nstrm, 1);

  if (nstrm->strm_fd >= 0) {
    fd_set rs;
    struct timeval tv;

    /* Wait for just a little while for the shutdown to take effect. */
    tv.tv_sec = 0L;
    tv.tv_usec = 300000L;

    while (TRUE) {
      run_schedule();

      FD_ZERO(&rs);
      FD_SET(nstrm->strm_fd, &rs);

      res = select(nstrm->strm_fd+1, &rs, NULL, NULL, &tv);
      if (res == -1) {
        if (errno == EINTR) {
          pr_signals_handle();

          /* Linger some more. */
          tv.tv_sec = 0L;
          tv.tv_usec = 300000L;
          continue;

        } else {
          nstrm->strm_errno = errno;
          return -1;
        }
      }

      break;
    }
  }

  nstrm->strm_flags |= PR_NETIO_SESS_ABORT;

  /* Now continue with a normal lingering close. */
  return netio_lingering_close(nstrm, linger,
    NETIO_LINGERING_CLOSE_FL_NO_SHUTDOWN);  
}

int pr_netio_lingering_close(pr_netio_stream_t *nstrm, long linger) {
  return netio_lingering_close(nstrm, linger, 0);
}

pr_netio_stream_t *pr_netio_open(pool *parent_pool, int strm_type, int fd,
    int mode) {
  pr_netio_stream_t *nstrm = NULL;
  const char *nstrm_mode;

  if (parent_pool == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* Create a new stream object, then pass that the NetIO open handler. */
  nstrm = netio_stream_alloc(parent_pool);
  nstrm_mode = netio_stream_mode(mode);

  switch (strm_type) {
    case PR_NETIO_STRM_CTRL:
      nstrm->strm_type = PR_NETIO_STRM_CTRL;
      nstrm->strm_mode = mode;

      if (ctrl_netio != NULL) {
        if (pr_table_add(nstrm->notes, pstrdup(nstrm->strm_pool, "core.netio"),
            ctrl_netio, sizeof(pr_netio_t *)) < 0) {
          pr_trace_msg(trace_channel, 9,
            "error stashing 'core.netio' note for ctrl stream: %s",
            strerror(errno));
        }
        pr_trace_msg(trace_channel, 19, "using %s open() for control %s stream",
          ctrl_netio->owner_name, nstrm_mode);
        return (ctrl_netio->open)(nstrm, fd, mode);

      } else {
        if (pr_table_add(nstrm->notes, pstrdup(nstrm->strm_pool, "core.netio"),
            default_ctrl_netio, sizeof(pr_netio_t *)) < 0) {
          pr_trace_msg(trace_channel, 9,
            "error stashing 'core.netio' note for ctrl stream: %s",
            strerror(errno));
        }
        pr_trace_msg(trace_channel, 19, "using %s open() for control %s stream",
          default_ctrl_netio->owner_name, nstrm_mode);
        return (default_ctrl_netio->open)(nstrm, fd, mode);
      }

    case PR_NETIO_STRM_DATA:
      nstrm->strm_type = PR_NETIO_STRM_DATA;
      nstrm->strm_mode = mode;

      if (data_netio != NULL) {
        if (pr_table_add(nstrm->notes, pstrdup(nstrm->strm_pool, "core.netio"),
            data_netio, sizeof(pr_netio_t *)) < 0) {
          pr_trace_msg(trace_channel, 9,
            "error stashing 'core.netio' note for data stream: %s",
            strerror(errno));
        }
        pr_trace_msg(trace_channel, 19, "using %s open() for data %s stream",
          data_netio->owner_name, nstrm_mode);
        return (data_netio->open)(nstrm, fd, mode);

      } else {
        if (pr_table_add(nstrm->notes, pstrdup(nstrm->strm_pool, "core.netio"),
            default_data_netio, sizeof(pr_netio_t *)) < 0) {
          pr_trace_msg(trace_channel, 9,
            "error stashing 'core.netio' note for data stream: %s",
            strerror(errno));
        }
        pr_trace_msg(trace_channel, 19, "using %s open() for data %s stream",
          default_data_netio->owner_name, nstrm_mode);
        return (default_data_netio->open)(nstrm, fd, mode);
      }

    case PR_NETIO_STRM_OTHR:
      nstrm->strm_type = PR_NETIO_STRM_OTHR;
      nstrm->strm_mode = mode;

      if (othr_netio != NULL) {
        if (pr_table_add(nstrm->notes, pstrdup(nstrm->strm_pool, "core.netio"),
            othr_netio, sizeof(pr_netio_t *)) < 0) {
          pr_trace_msg(trace_channel, 9,
            "error stashing 'core.netio' note for othr stream: %s",
            strerror(errno));
        }
        pr_trace_msg(trace_channel, 19, "using %s open() for other %s stream",
          othr_netio->owner_name, nstrm_mode);
        return (othr_netio->open)(nstrm, fd, mode);

      } else {
        if (pr_table_add(nstrm->notes, pstrdup(nstrm->strm_pool, "core.netio"),
            default_othr_netio, sizeof(pr_netio_t *)) < 0) {
          pr_trace_msg(trace_channel, 9,
            "error stashing 'core.netio' note for othr stream: %s",
            strerror(errno));
        }
        pr_trace_msg(trace_channel, 19, "using %s open() for other %s stream",
          default_othr_netio->owner_name, nstrm_mode);
        return (default_othr_netio->open)(nstrm, fd, mode);
      }
  }

  destroy_pool(nstrm->strm_pool);
  nstrm->strm_pool = NULL;

  errno = EPERM;
  return NULL;
}

pr_netio_stream_t *pr_netio_reopen(pr_netio_stream_t *nstrm, int fd, int mode) {
  pr_netio_stream_t *res;
  const char *nstrm_mode;

  if (nstrm == NULL) {
    errno = EINVAL;
    return NULL;
  }

  nstrm_mode = netio_stream_mode(mode);

  switch (nstrm->strm_type) {
    case PR_NETIO_STRM_CTRL:
      if (ctrl_netio != NULL) {
        pr_trace_msg(trace_channel, 19,
          "using %s reopen() for control %s stream", ctrl_netio->owner_name,
          nstrm_mode);
        res = (ctrl_netio->reopen)(nstrm, fd, mode);

      } else {
        pr_trace_msg(trace_channel, 19,
          "using %s reopen() for control %s stream",
          default_ctrl_netio->owner_name, nstrm_mode);
        res = (default_ctrl_netio->reopen)(nstrm, fd, mode);
      }
      return res;

    case PR_NETIO_STRM_DATA:
      if (data_netio != NULL) {
        pr_trace_msg(trace_channel, 19, "using %s reopen() for data %s stream",
          data_netio->owner_name, nstrm_mode);
        res = (data_netio->reopen)(nstrm, fd, mode);

      } else {
        pr_trace_msg(trace_channel, 19, "using %s reopen() for data %s stream",
          default_data_netio->owner_name, nstrm_mode);
        res = (default_data_netio->reopen)(nstrm, fd, mode);
      }
      return res;

    case PR_NETIO_STRM_OTHR:
      if (othr_netio != NULL) {
        pr_trace_msg(trace_channel, 19, "using %s reopen() for other %s stream",
          othr_netio->owner_name, nstrm_mode);
        res = (othr_netio->reopen)(nstrm, fd, mode);

      } else {
        pr_trace_msg(trace_channel, 19, "using %s reopen() for other %s stream",
          default_othr_netio->owner_name, nstrm_mode);
        res = (default_othr_netio->reopen)(nstrm, fd, mode);
      }
      return res;
  }

  errno = EPERM;
  return NULL;
}

void pr_netio_reset_poll_interval(pr_netio_stream_t *nstrm) {
  if (nstrm == NULL) {
    errno = EINVAL;
    return;
  }

  /* Simply clear the "interruptible" flag. */
  nstrm->strm_flags &= ~PR_NETIO_SESS_INTR;
}

void pr_netio_set_poll_interval(pr_netio_stream_t *nstrm, unsigned int secs) {
  if (nstrm == NULL) {
    return;
  }

  nstrm->strm_flags |= PR_NETIO_SESS_INTR;
  nstrm->strm_interval = secs;
}

int pr_netio_poll(pr_netio_stream_t *nstrm) {
  int res = 0, xerrno = 0;
  const char *nstrm_mode;

  /* Sanity checks. */
  if (nstrm == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (nstrm->strm_fd == -1) {
    errno = EBADF;
    return -1;
  }

  /* Has this stream been aborted? */
  if (nstrm->strm_flags & PR_NETIO_SESS_ABORT) {
    nstrm->strm_flags &= ~PR_NETIO_SESS_ABORT;
    return 1;
  }

  nstrm_mode = netio_stream_mode(nstrm->strm_mode);

  while (TRUE) {
    run_schedule();
    pr_signals_handle();

    switch (nstrm->strm_type) {
      case PR_NETIO_STRM_CTRL:
        if (ctrl_netio != NULL) {
          pr_trace_msg(trace_channel, 19,
            "using %s poll() for control %s stream", ctrl_netio->owner_name,
            nstrm_mode);
          res = (ctrl_netio->poll)(nstrm);

        } else {
          pr_trace_msg(trace_channel, 19,
            "using %s poll() for control %s stream",
            default_ctrl_netio->owner_name, nstrm_mode);
          res = (default_ctrl_netio->poll)(nstrm);
        }
        break;

      case PR_NETIO_STRM_DATA:
        if (data_netio != NULL) {
          pr_trace_msg(trace_channel, 19,
            "using %s poll() for data %s stream", data_netio->owner_name,
            nstrm_mode);
          res = (data_netio->poll)(nstrm);

        } else {
          pr_trace_msg(trace_channel, 19,
            "using %s poll() for data %s stream",
            default_data_netio->owner_name, nstrm_mode);
          res = (default_data_netio->poll)(nstrm);
        }
        break;

      case PR_NETIO_STRM_OTHR:
        if (othr_netio != NULL) {
          pr_trace_msg(trace_channel, 19,
            "using %s poll() for other %s stream", othr_netio->owner_name,
            nstrm_mode);
          res = (othr_netio->poll)(nstrm);

        } else {
          pr_trace_msg(trace_channel, 19,
            "using %s poll() for other %s stream",
            default_othr_netio->owner_name, nstrm_mode);
          res = (default_othr_netio->poll)(nstrm);
        }
        break;
    }

    if (res == -1) {
      xerrno = errno;
      if (xerrno == EINTR) {
        if (nstrm->strm_flags & PR_NETIO_SESS_ABORT) {
          nstrm->strm_flags &= ~PR_NETIO_SESS_ABORT;
          return 1;
        }

        if (nstrm->strm_flags & PR_NETIO_SESS_INTR) {
          errno = nstrm->strm_errno = xerrno;
          return -1;
        }

        /* Otherwise, restart the call */
        pr_signals_handle();
        continue;
      }

      /* Some other error occurred */
      nstrm->strm_errno = xerrno;

      /* If this is the control stream, and the error indicates a
       * broken pipe (i.e. the client went away), AND there is a data
       * transfer is progress, abort the transfer.
       */
      if (xerrno == EPIPE &&
          nstrm->strm_type == PR_NETIO_STRM_CTRL &&
          (session.sf_flags & SF_XFER)) {
        pr_trace_msg(trace_channel, 5,
          "received EPIPE on control connection, setting 'aborted' "
          "session flag");
        session.sf_flags |= SF_ABORT;
      }

      errno = nstrm->strm_errno;
      return -1;
    }

    if (res == 0) {
      /* In case the kernel doesn't support interrupted syscalls. */
      if (nstrm->strm_flags & PR_NETIO_SESS_ABORT) {
        nstrm->strm_flags &= ~PR_NETIO_SESS_ABORT;
        return 1;
      }

      /* If the stream has been marked as "interruptible", AND the
       * poll interval is zero seconds (meaning a true poll, not blocking),
       * then return here.
       */
      if ((nstrm->strm_flags & PR_NETIO_SESS_INTR) &&
          nstrm->strm_interval == 0) {
        errno = EOF;
        return -1;
      }

      continue;
    }

    break;
  }

  return 0;
}

int pr_netio_postopen(pr_netio_stream_t *nstrm) {
  int res;
  const char *nstrm_mode;

  if (nstrm == NULL) {
    errno = EINVAL;
    return -1;
  }

  nstrm_mode = netio_stream_mode(nstrm->strm_mode);

  switch (nstrm->strm_type) {
    case PR_NETIO_STRM_CTRL:
      if (ctrl_netio != NULL) {
        pr_trace_msg(trace_channel, 19,
          "using %s postopen() for control %s stream", ctrl_netio->owner_name,
          nstrm_mode);
        res = (ctrl_netio->postopen)(nstrm);

      } else {
        pr_trace_msg(trace_channel, 19,
          "using %s postopen() for control %s stream",
          default_ctrl_netio->owner_name, nstrm_mode);
        res = (default_ctrl_netio->postopen)(nstrm);
      }
      return res;

    case PR_NETIO_STRM_DATA:
      if (data_netio != NULL) {
        pr_trace_msg(trace_channel, 19,
          "using %s postopen() for data %s stream", data_netio->owner_name,
          nstrm_mode);
        res = (data_netio->postopen)(nstrm);

      } else {
        pr_trace_msg(trace_channel, 19,
          "using %s postopen() for data %s stream",
          default_data_netio->owner_name, nstrm_mode);
        res = (default_data_netio->postopen)(nstrm);
      }
      return res;

    case PR_NETIO_STRM_OTHR:
      if (othr_netio != NULL) {
        pr_trace_msg(trace_channel, 19,
          "using %s postopen() for other %s stream", othr_netio->owner_name,
          nstrm_mode);
        res = (othr_netio->postopen)(nstrm);

      } else {
        pr_trace_msg(trace_channel, 19,
          "using %s postopen() for other %s stream",
          default_othr_netio->owner_name, nstrm_mode);
        res = (default_othr_netio->postopen)(nstrm);
      }
      return res;
  }

  errno = EPERM;
  return -1;
}

int pr_netio_vprintf(pr_netio_stream_t *nstrm, const char *fmt, va_list msg) {
  char buf[PR_RESPONSE_BUFFER_SIZE] = {'\0'};

  pr_vsnprintf(buf, sizeof(buf), fmt, msg);
  buf[sizeof(buf)-1] = '\0';

  return pr_netio_write(nstrm, buf, strlen(buf));
}

int pr_netio_printf(pr_netio_stream_t *nstrm, const char *fmt, ...) {
  int res;
  va_list msg;

  if (!nstrm) {
    errno = EINVAL;
    return -1;
  }

  va_start(msg, fmt);
  res = pr_netio_vprintf(nstrm, fmt, msg);
  va_end(msg);

  return res;
}

int pr_netio_printf_async(pr_netio_stream_t *nstrm, char *fmt, ...) {
  va_list msg;
  char buf[PR_RESPONSE_BUFFER_SIZE] = {'\0'};

  if (!nstrm) {
    errno = EINVAL;
    return -1;
  }

  va_start(msg, fmt);
  pr_vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);
  buf[sizeof(buf)-1] = '\0';

  return pr_netio_write_async(nstrm, buf, strlen(buf));
}

int pr_netio_write(pr_netio_stream_t *nstrm, char *buf, size_t buflen) {
  int bwritten = 0, total = 0;
  const char *nstrm_mode;
  pr_buffer_t *pbuf;
  pool *tmp_pool;

  /* Sanity check */
  if (nstrm == NULL ||
      buf == NULL ||
      buflen == 0) {
    errno = EINVAL;
    return -1;
  }

  if (nstrm->strm_fd == -1) {
    errno = (nstrm->strm_errno ? nstrm->strm_errno : EBADF);
    return -1;
  }

  nstrm_mode = netio_stream_mode(nstrm->strm_mode);

  /* Before we send out the data to the client, generate an event
   * for any listeners which may want to examine this data.  To do this, we
   * need to allocate a pr_buffer_t for sending the buffer data to the
   * listeners.
   *
   * We could just use nstrm->strm_pool, but for a long-lived control
   * connection, this would amount to a slow memory increase.  So instead,
   * we create a subpool from the stream's pool, and allocate the
   * pr_buffer_t out of that.  Then simply destroy the subpool when done.
   */

  tmp_pool = make_sub_pool(nstrm->strm_pool);
  pbuf = pcalloc(tmp_pool, sizeof(pr_buffer_t));
  pbuf->buf = buf;
  pbuf->buflen = buflen;
  pbuf->current = pbuf->buf;
  pbuf->remaining = 0;

  switch (nstrm->strm_type) {
    case PR_NETIO_STRM_CTRL:
      pr_event_generate("core.ctrl-write", pbuf);
      break;

    case PR_NETIO_STRM_DATA:
      pr_event_generate("core.data-write", pbuf);
      break;

    case PR_NETIO_STRM_OTHR:
      pr_event_generate("core.othr-write", pbuf);
      break;
  }

  /* The event listeners may have changed the data to write out. */
  buf = pbuf->buf;
  buflen = pbuf->buflen - pbuf->remaining;
  destroy_pool(tmp_pool);

  while (buflen) {

    switch (pr_netio_poll(nstrm)) {
      case 1:
        /* pr_netio_poll() returns 1 only if the stream has been aborted. */
        errno = ECONNABORTED;
        return -2;

      case -1:
        return -1;

      default:
        /* We have to potentially restart here as well, in case we get EINTR. */
        do {
          pr_signals_handle(); 
          run_schedule();

          switch (nstrm->strm_type) {
            case PR_NETIO_STRM_CTRL:
              if (ctrl_netio != NULL) {
                pr_trace_msg(trace_channel, 19,
                  "using %s write() for control %s stream",
                  ctrl_netio->owner_name, nstrm_mode);
                bwritten = (ctrl_netio->write)(nstrm, buf, buflen);

              } else {
                pr_trace_msg(trace_channel, 19,
                  "using %s write() for control %s stream",
                  default_ctrl_netio->owner_name, nstrm_mode);
                bwritten = (default_ctrl_netio->write)(nstrm, buf, buflen);
              }
              break;

            case PR_NETIO_STRM_DATA:
              if (XFER_ABORTED) {
                break;
              }

              if (data_netio != NULL) {
                pr_trace_msg(trace_channel, 19,
                  "using %s write() for data %s stream", data_netio->owner_name,
                  nstrm_mode);
                bwritten = (data_netio->write)(nstrm, buf, buflen);

              } else {
                pr_trace_msg(trace_channel, 19,
                  "using %s write() for data %s stream",
                  default_data_netio->owner_name, nstrm_mode);
                bwritten = (default_data_netio->write)(nstrm, buf, buflen);
              }
              break;

            case PR_NETIO_STRM_OTHR:
              if (othr_netio != NULL) {
                pr_trace_msg(trace_channel, 19,
                  "using %s write() for other %s stream",
                  othr_netio->owner_name, nstrm_mode);
                bwritten = (othr_netio->write)(nstrm, buf, buflen);

              } else {
                pr_trace_msg(trace_channel, 19,
                  "using %s write() for other %s stream",
                  default_othr_netio->owner_name, nstrm_mode);
                bwritten = (default_othr_netio->write)(nstrm, buf, buflen);
              }
              break;
          }

        } while (bwritten == -1 && errno == EINTR);
        break;
    }

    if (bwritten == -1) {
      nstrm->strm_errno = errno;
      return -1;
    }

    buf += bwritten;
    total += bwritten;
    buflen -= bwritten;
  }

  session.total_raw_out += total;
  return total;
}

int pr_netio_write_async(pr_netio_stream_t *nstrm, char *buf, size_t buflen) {
  int bwritten = 0, flags = 0, total = 0;
  const char *nstrm_mode;
  pr_buffer_t *pbuf;
  pool *tmp_pool;

  /* Sanity check */
  if (nstrm == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (nstrm->strm_fd == -1) {
    errno = (nstrm->strm_errno ? nstrm->strm_errno : EBADF);
    return -1;
  }

  /* Prepare the descriptor for nonblocking IO. */
  flags = fcntl(nstrm->strm_fd, F_GETFL);
  if (flags < 0) {
    return -1;
  }

  if (fcntl(nstrm->strm_fd, F_SETFL, flags|O_NONBLOCK) < 0) {
    return -1;
  }

  nstrm_mode = netio_stream_mode(nstrm->strm_mode);

  /* Before we send out the data to the client, generate an event
   * for any listeners which may want to examine this data.
   */

  tmp_pool = make_sub_pool(nstrm->strm_pool);
  pbuf = pcalloc(tmp_pool, sizeof(pr_buffer_t));
  pbuf->buf = buf;
  pbuf->buflen = buflen;
  pbuf->current = pbuf->buf;
  pbuf->remaining = 0;

  switch (nstrm->strm_type) {
    case PR_NETIO_STRM_CTRL:
      pr_event_generate("core.ctrl-write", pbuf);
      break;

    case PR_NETIO_STRM_DATA:
      pr_event_generate("core.data-write", pbuf);
      break;

    case PR_NETIO_STRM_OTHR:
      pr_event_generate("core.othr-write", pbuf);
      break;
  }

  /* The event listeners may have changed the data to write out. */
  buf = pbuf->buf;
  buflen = pbuf->buflen - pbuf->remaining;
  destroy_pool(tmp_pool);

  while (buflen) {
    do {

      /* Do NOT check for XFER_ABORTED here.  After a client aborts a
       * transfer, proftpd still needs to send the 426 response code back
       * to the client via the control connection; checking for XFER_ABORTED
       * here would block that response code sending, which in turn causes
       * problems for clients waiting for that response code.
       */

      pr_signals_handle();

      switch (nstrm->strm_type) {
        case PR_NETIO_STRM_CTRL:
          if (ctrl_netio != NULL) {
            pr_trace_msg(trace_channel, 19,
              "using %s write() for control %s stream", ctrl_netio->owner_name,
              nstrm_mode);
            bwritten = (ctrl_netio->write)(nstrm, buf, buflen);

          } else {
            pr_trace_msg(trace_channel, 19,
              "using %s write() for control %s stream",
              default_ctrl_netio->owner_name, nstrm_mode);
            bwritten = (default_ctrl_netio->write)(nstrm, buf, buflen);
          }
          break;

        case PR_NETIO_STRM_DATA:
          if (data_netio != NULL) {
            pr_trace_msg(trace_channel, 19,
              "using %s write() for data %s stream", data_netio->owner_name,
              nstrm_mode);
            bwritten = (data_netio->write)(nstrm, buf, buflen);

          } else {
            pr_trace_msg(trace_channel, 19,
              "using %s write() for data %s stream",
              default_data_netio->owner_name, nstrm_mode);
            bwritten = (default_data_netio->write)(nstrm, buf, buflen);
          }
          break;

        case PR_NETIO_STRM_OTHR:
          if (othr_netio != NULL) {
            pr_trace_msg(trace_channel, 19,
              "using %s write() for other %s stream", othr_netio->owner_name,
              nstrm_mode);
            bwritten = (othr_netio->write)(nstrm, buf, buflen);

          } else {
            pr_trace_msg(trace_channel, 19,
              "using %s write() for other %s stream",
              default_othr_netio->owner_name, nstrm_mode);
            bwritten = (default_othr_netio->write)(nstrm, buf, buflen);
          }
          break;
      }

    } while (bwritten == -1 && errno == EINTR);

    if (bwritten < 0) {
      nstrm->strm_errno = errno;
      (void) fcntl(nstrm->strm_fd, F_SETFL, flags);

      if (nstrm->strm_errno == EWOULDBLOCK) {
        /* Give up ... */
        return total;
      }

      return -1;
    }

    buf += bwritten;
    total += bwritten;
    buflen -= bwritten;
  }

  (void) fcntl(nstrm->strm_fd, F_SETFL, flags);
  return total;
}

int pr_netio_read(pr_netio_stream_t *nstrm, char *buf, size_t buflen,
    int bufmin) {
  int bread = 0, total = 0;
  const char *nstrm_mode;
  pr_buffer_t *pbuf;
  pool *tmp_pool;

  /* Sanity check. */
  if (nstrm == NULL ||
      buf == NULL ||
      buflen == 0) {
    errno = EINVAL;
    return -1;
  }

  if (nstrm->strm_fd == -1) {
    errno = (nstrm->strm_errno ? nstrm->strm_errno : EBADF);
    return -1;
  }

  if (bufmin < 1) {
    bufmin = 1;
  }

  if (bufmin > 0 &&
      (size_t) bufmin > buflen) {
    bufmin = buflen;
  }

  nstrm_mode = netio_stream_mode(nstrm->strm_mode);

  while (bufmin > 0) {
    polling:

    switch (pr_netio_poll(nstrm)) {
      case 1:
        return -2;

      case -1:
        return -1;

      default:
        do {
          pr_signals_handle();

          run_schedule();

          switch (nstrm->strm_type) {
            case PR_NETIO_STRM_CTRL:
              if (ctrl_netio != NULL) {
                pr_trace_msg(trace_channel, 19,
                  "using %s read() for control %s stream",
                  ctrl_netio->owner_name, nstrm_mode);
                bread = (ctrl_netio->read)(nstrm, buf, buflen);

              } else {
                pr_trace_msg(trace_channel, 19,
                  "using %s read() for control %s stream",
                  default_ctrl_netio->owner_name, nstrm_mode);
                bread = (default_ctrl_netio->read)(nstrm, buf, buflen);
              }
              break;

            case PR_NETIO_STRM_DATA:
              if (XFER_ABORTED) {
                break;
              }

              if (data_netio != NULL) {
                pr_trace_msg(trace_channel, 19,
                  "using %s read() for data %s stream", data_netio->owner_name,
                  nstrm_mode);
                bread = (data_netio->read)(nstrm, buf, buflen);

              } else {
                pr_trace_msg(trace_channel, 19,
                  "using %s read() for data %s stream",
                  default_data_netio->owner_name, nstrm_mode);
                bread = (default_data_netio->read)(nstrm, buf, buflen);
              }
              break;

            case PR_NETIO_STRM_OTHR:
              if (othr_netio != NULL) {
                pr_trace_msg(trace_channel, 19,
                  "using %s read() for other %s stream",
                  othr_netio->owner_name, nstrm_mode);
                bread = (othr_netio->read)(nstrm, buf, buflen);

              } else {
                pr_trace_msg(trace_channel, 19,
                  "using %s read() for other %s stream",
                  default_othr_netio->owner_name, nstrm_mode);
                bread = (default_othr_netio->read)(nstrm, buf, buflen);
              }
              break;
          }

#ifdef EAGAIN
	  if (bread == -1 &&
              errno == EAGAIN) {
            int xerrno = EAGAIN;

            /* Treat this as an interrupted call, call pr_signals_handle()
             * (which will delay for a few msecs because of EINTR), and try
             * again.
             *
             * This should avoid a tightly spinning loop if read(2) returns
             * EAGAIN, as on a data transfer (Bug#3639).
             */

            errno = EINTR;
            pr_signals_handle();

            errno = xerrno;
            goto polling;
          }
#endif

        } while (bread == -1 && errno == EINTR);
        break;
    }

    if (bread == -1) {
      nstrm->strm_errno = errno;
      return -1;
    }

    /* EOF? */
    if (bread == 0) {
      if (nstrm->strm_type == PR_NETIO_STRM_CTRL) {
        pr_trace_msg(trace_channel, 7,
          "read %d bytes from control stream fd %d, handling as EOF", bread,
          nstrm->strm_fd);
      }

      nstrm->strm_errno = 0;
      errno = EOF;
      break;
    }

    /* Before we provide the data from the client, generate an event
     * for any listeners which may want to examine this data.  To do this, we
     * need to allocate a pr_buffer_t for sending the buffer data to the
     * listeners.
     *
     * We could just use nstrm->strm_pool, but for a long-lived control
     * connection, this would amount to a slow memory increase.  So instead,
     * we create a subpool from the stream's pool, and allocate the
     * pr_buffer_t out of that.  Then simply destroy the subpool when done.
     */

    tmp_pool = make_sub_pool(nstrm->strm_pool);
    pbuf = pcalloc(tmp_pool, sizeof(pr_buffer_t));
    pbuf->buf = buf;
    pbuf->buflen = bread;
    pbuf->current = pbuf->buf;
    pbuf->remaining = 0;

    switch (nstrm->strm_type) {
      case PR_NETIO_STRM_CTRL:
        pr_event_generate("core.ctrl-read", pbuf);
        break;

      case PR_NETIO_STRM_DATA:
        pr_event_generate("core.data-read", pbuf);
        break;

      case PR_NETIO_STRM_OTHR:
        pr_event_generate("core.othr-read", pbuf);
        break;
    }

    /* The event listeners may have changed the data read in out. */
    buf = pbuf->buf;
    bread = pbuf->buflen - pbuf->remaining;
    destroy_pool(tmp_pool);

    buf += bread;
    total += bread;
    bufmin -= bread;
    buflen -= bread;
  }

  session.total_raw_in += total;
  return total;
}

int pr_netio_shutdown(pr_netio_stream_t *nstrm, int how) {
  int res = -1;
  const char *nstrm_mode;

  if (nstrm == NULL) {
    errno = EINVAL;
    return -1;
  }

  nstrm_mode = netio_stream_mode(nstrm->strm_mode);

  switch (nstrm->strm_type) {
    case PR_NETIO_STRM_CTRL:
      if (ctrl_netio != NULL) {
        pr_trace_msg(trace_channel, 19,
          "using %s shutdown() for control %s stream", ctrl_netio->owner_name,
          nstrm_mode);
        res = (ctrl_netio->shutdown)(nstrm, how);

      } else {
        pr_trace_msg(trace_channel, 19,
          "using %s shutdown() for control %s stream",
          default_ctrl_netio->owner_name, nstrm_mode);
        res = (default_ctrl_netio->shutdown)(nstrm, how);
      }
      return res;

    case PR_NETIO_STRM_DATA:
      if (data_netio != NULL) {
        pr_trace_msg(trace_channel, 19,
          "using %s shutdown() for data %s stream", data_netio->owner_name,
          nstrm_mode);
        res = (data_netio->shutdown)(nstrm, how);

      } else {
        pr_trace_msg(trace_channel, 19,
          "using %s shutdown() for data %s stream",
          default_data_netio->owner_name, nstrm_mode);
        res = (default_data_netio->shutdown)(nstrm, how);
      }
      return res;

    case PR_NETIO_STRM_OTHR:
      if (othr_netio != NULL) {
        pr_trace_msg(trace_channel, 19,
          "using %s shutdown() for other %s stream", othr_netio->owner_name,
          nstrm_mode);
        res = (othr_netio->shutdown)(nstrm, how);

      } else {
        pr_trace_msg(trace_channel, 19,
          "using %s shutdown() for other %s stream",
          default_othr_netio->owner_name, nstrm_mode);
        res = (default_othr_netio->shutdown)(nstrm, how);
      }
      return res;
  }

  errno = EPERM;
  return res;
}

char *pr_netio_gets(char *buf, size_t buflen, pr_netio_stream_t *nstrm) {
  char *bp = buf;
  int toread;
  pr_buffer_t *pbuf = NULL;

  if (nstrm == NULL ||
      buf == NULL ||
      buflen == 0) {
    errno = EINVAL;
    return NULL;
  }

  buflen--;

  if (nstrm->strm_buf) {
    pbuf = nstrm->strm_buf;

  } else {
    pbuf = pr_netio_buffer_alloc(nstrm);
  }

  while (buflen) {

    /* Is the buffer empty? */
    if (!pbuf->current ||
        pbuf->remaining == pbuf->buflen) {

      toread = pr_netio_read(nstrm, pbuf->buf,
        (buflen < pbuf->buflen ?  buflen : pbuf->buflen), 1);

      if (toread <= 0) {
        if (bp != buf) {
          *bp = '\0';
          return buf;
        }

        return NULL;
      }

      pbuf->remaining = pbuf->buflen - toread;
      pbuf->current = pbuf->buf;

      pbuf->remaining = pbuf->buflen - toread;
      pbuf->current = pbuf->buf;

      /* Before we begin iterating through the data read in from the
       * network, generate an event for any listeners which may want to
       * examine this data as well.
       */
      pr_event_generate("core.othr-read", pbuf);
    }

    toread = pbuf->buflen - pbuf->remaining;

    while (buflen && *pbuf->current != '\n' && toread--) {
      if (*pbuf->current & 0x80) {
        pbuf->current++;

      } else {
        *bp++ = *pbuf->current++;
        buflen--;
      }
      pbuf->remaining++;
    }

    if (buflen && toread && *pbuf->current == '\n') {
      buflen--;
      toread--;
      *bp++ = *pbuf->current++;
      pbuf->remaining++;
      break;
    }

    if (!toread) {
      pbuf->current = NULL;
    }
  }

  *bp = '\0';
  return buf;
}

static int telnet_mode = 0;

int pr_netio_telnet_gets2(char *buf, size_t bufsz,
    pr_netio_stream_t *in_nstrm, pr_netio_stream_t *out_nstrm) {
  char *bp = buf;
  unsigned char cp;
  int toread, handle_iac = TRUE, saw_newline = FALSE;
  pr_buffer_t *pbuf = NULL;
  size_t buflen = bufsz;

  if (buflen == 0 ||
      in_nstrm == NULL ||
      out_nstrm == NULL) {
    errno = EINVAL;
    return -1;
  }

#ifdef PR_USE_NLS
  handle_iac = pr_encode_supports_telnet_iac();
#endif /* PR_USE_NLS */

  buflen--;

  if (in_nstrm->strm_buf) {
    pbuf = in_nstrm->strm_buf;

  } else {
    pbuf = pr_netio_buffer_alloc(in_nstrm);
  }

  while (buflen > 0) {
    pr_signals_handle();

    /* Is the buffer empty? */
    if (pbuf->current == NULL ||
        pbuf->remaining == pbuf->buflen) {

      toread = pr_netio_read(in_nstrm, pbuf->buf,
        (buflen < pbuf->buflen ? buflen : pbuf->buflen), 1);

      if (toread <= 0) {
        if (bp != buf) {
          *bp = '\0';
          return (bufsz - buflen - 1);
        }

        return -1;
      }

      pbuf->remaining = pbuf->buflen - toread;
      pbuf->current = pbuf->buf;

      /* Before we begin iterating through the data read in from the
       * network, handing any Telnet characters and such, generate an event
       * for any listeners which may want to examine this data as well.
       */
      pr_event_generate("core.ctrl-read", pbuf);
    }

    toread = pbuf->buflen - pbuf->remaining;

    while (buflen > 0 &&
           toread > 0 &&
           (*pbuf->current != '\n' ||
            (*pbuf->current == '\n' && *(pbuf->current - 1) != '\r')) &&
           toread--) {
      pr_signals_handle();

      cp = *pbuf->current++;
      pbuf->remaining++;

      if (handle_iac == TRUE) {
        switch (telnet_mode) {
          case TELNET_IAC:
            switch (cp) {
              case TELNET_WILL:
              case TELNET_WONT:
              case TELNET_DO:
              case TELNET_DONT:
              case TELNET_IP:
              case TELNET_DM:
                /* Why do we do this crazy thing where we set the "telnet mode"
                 * to be the action, and let the while loop, on the next pass,
                 * handle that action?  It's because we don't know, right now,
                 * whether there actually a "next byte" in the input buffer.
                 * There _should_ be -- but we can't be sure.  And that next
                 * byte is needed for properly responding with WONT/DONT
                 * responses.
                 */
                telnet_mode = cp;
                continue;

              case TELNET_IAC:
                /* In this case, we know that the previous byte was TELNET_IAC,
                 * and that the current byte is another TELNET_IAC.  The
                 * first TELNET_IAC thus "escapes" the second, telling us
                 * that the current byte (TELNET_IAC) should be written out
                 * as is (Bug#3697).
                 */
                telnet_mode = 0;
                break;

              default:
                /* In this case, we know that the previous byte was TELNET_IAC,
                 * but the current byte is not a value we care about.  So
                 * write the TELNET_IAC into the output buffer, break out of
                 * of the switch, and let that handle the writing of the
                 * current byte into the output buffer.
                 */
                *bp++ = TELNET_IAC;
                buflen--;

                telnet_mode = 0;
                break;
            }
            break;

          case TELNET_WILL:
          case TELNET_WONT:
            pr_netio_printf(out_nstrm, "%c%c%c", TELNET_IAC, TELNET_DONT, cp);
            telnet_mode = 0;
            continue;

          case TELNET_DO:
          case TELNET_DONT:
            pr_netio_printf(out_nstrm, "%c%c%c", TELNET_IAC, TELNET_WONT, cp);
            telnet_mode = 0;
            continue;

          case TELNET_IP:
          case TELNET_DM:
          default:
            if (cp == TELNET_IAC) {
              telnet_mode = cp;
              continue;
            }
            break;
        }
      }

      /* In the situation where the previous byte was an IAC, we wrote IAC
       * into the output buffer, and decremented buflen (size of the output
       * buffer remaining).  Thus we need to check here if buflen is zero,
       * before trying to decrement buflen again (and possibly underflowing
       * the buflen size_t data type).
       */
      if (buflen == 0) {
        break;
      }

      *bp++ = cp;
      buflen--;
    }

    if (buflen > 0 &&
        toread > 0 &&
        *pbuf->current == '\n') {

      /* If the current character is LF, and the previous character we
       * copied was a CR, then strip the CR by overwriting it with the LF,
       * turning the copied data from Telnet CRLF line termination to
       * Unix LF line termination.
       */
      if (*(bp-1) == '\r') {
        /* We already decrement the buffer length for the CR; no need to
         * do it again since we are overwriting that CR.
         */
        *(bp-1) = *pbuf->current++;

      } else {
        *bp++ = *pbuf->current++;
        buflen--;
      }

      pbuf->remaining++;
      toread--;
      saw_newline = TRUE;
      break;
    }

    if (toread == 0) {
      /* No more input?  Set pbuf->current to null, so that at the top of
       * the loop, we read more.
       */
      pbuf->current = NULL;
    }
  }

  if (!saw_newline) {
    /* If we haven't seen a newline, then assume the client is deliberately
     * sending a too-long command, trying to exploit buffer sizes and make
     * the server make some possibly bad assumptions.
     */

    properly_terminated_prev_command = FALSE;
    errno = E2BIG;
    return -1;
  }

  if (!properly_terminated_prev_command) {
    properly_terminated_prev_command = TRUE;
    pr_log_pri(PR_LOG_NOTICE, "client sent too-long command, ignoring");
    errno = E2BIG;
    return -1;
  }

  properly_terminated_prev_command = TRUE;
  *bp = '\0';
  return (bufsz - buflen - 1);
}

char *pr_netio_telnet_gets(char *buf, size_t bufsz,
    pr_netio_stream_t *in_nstrm, pr_netio_stream_t *out_nstrm) {
  int res;

  res = pr_netio_telnet_gets2(buf, bufsz, in_nstrm, out_nstrm);
  if (res < 0) {
    return NULL;
  }

  return buf;
}

int pr_register_netio(pr_netio_t *netio, int strm_types) {

  if (netio == NULL) {
    pr_netio_t *default_netio = NULL;

    /* Only instantiate the default NetIO objects once, reusing the same
     * pointer.
     */
    if (default_ctrl_netio == NULL) {
      default_ctrl_netio = default_netio = pr_alloc_netio2(permanent_pool,
        NULL, NULL);
    }

    if (default_data_netio == NULL) {
      default_data_netio = default_netio ? default_netio :
        (default_netio = pr_alloc_netio2(permanent_pool, NULL, NULL));
    }

    if (default_othr_netio == NULL) {
      default_othr_netio = default_netio ? default_netio :
        (default_netio = pr_alloc_netio2(permanent_pool, NULL, NULL));
    }

    return 0;
  }

  if (!netio->abort || !netio->close || !netio->open || !netio->poll ||
      !netio->postopen || !netio->read || !netio->reopen ||
      !netio->shutdown || !netio->write) {
    errno = EINVAL;
    return -1;
  }

  if (strm_types & PR_NETIO_STRM_CTRL) {
    ctrl_netio = netio;
  }

  if (strm_types & PR_NETIO_STRM_DATA) {
    data_netio = netio;
  }

  if (strm_types & PR_NETIO_STRM_OTHR) {
    othr_netio = netio;
  }

  return 0;
}

int pr_unregister_netio(int strm_types) {
  if (!strm_types) {
    errno = EINVAL;
    return -1;
  }

  /* NOTE: consider using cleanups here in the future? */

  if (strm_types & PR_NETIO_STRM_CTRL) {
    ctrl_netio = NULL;
  }

  if (strm_types & PR_NETIO_STRM_DATA) {
    data_netio = NULL;
  }

  if (strm_types & PR_NETIO_STRM_OTHR) {
    othr_netio = NULL;
  }

  return 0;
}

pr_netio_t *pr_get_netio(int strm_type) {
  pr_netio_t *netio = NULL;

  if (strm_type == 0) {
    errno = EINVAL;
    return NULL;
  }

  switch (strm_type) {
    case PR_NETIO_STRM_CTRL:
      netio = ctrl_netio;
      break;

    case PR_NETIO_STRM_DATA:
      netio = data_netio;
      break;

    case PR_NETIO_STRM_OTHR:
      netio = othr_netio;
      break;

    default:
      errno = ENOENT;
  }

  return netio;
}

extern pid_t mpid;

pr_netio_t *pr_alloc_netio2(pool *parent_pool, module *owner,
    const char *owner_name) {
  pr_netio_t *netio = NULL;
  pool *netio_pool = NULL;

  if (parent_pool == NULL) {
    errno = EINVAL;
    return NULL;
  }

  netio_pool = make_sub_pool(parent_pool);

  /* If this is the daemon process, we are allocating a sub-pool from the
   * permanent_pool.  You might wonder why the daemon process needs netio
   * objects.  It doesn't, really -- but it's for use by all of the session
   * processes that will be forked.  They will be able to reuse the memory
   * already allocated for the main ctrl/data/other netios, as is.
   *
   * This being the case, we should label the sub-pool accordingly.
   */
  if (mpid == getpid()) {
    pr_pool_tag(netio_pool, "Shared Netio Pool");

  } else {
    pr_pool_tag(netio_pool, "netio pool");
  }

  netio = pcalloc(netio_pool, sizeof(pr_netio_t));
  netio->pool = netio_pool;
  netio->owner = owner;

  if (owner != NULL) {
    if (owner_name != NULL) {
      netio->owner_name = pstrdup(netio_pool, owner_name);

    } else {
      netio->owner_name = pstrdup(netio_pool, owner->name);
    }

  } else {
    if (owner_name != NULL) {
      netio->owner_name = owner_name;

    } else {
      netio->owner_name = "default";
    }
  }

  /* Set the default NetIO handlers to the core handlers. */
  netio->abort = core_netio_abort_cb;
  netio->close = core_netio_close_cb;
  netio->open = core_netio_open_cb;
  netio->poll = core_netio_poll_cb;
  netio->postopen = core_netio_postopen_cb;
  netio->read = core_netio_read_cb;
  netio->reopen = core_netio_reopen_cb;
  netio->shutdown = core_netio_shutdown_cb;
  netio->write = core_netio_write_cb;

  return netio;
}

pr_netio_t *pr_alloc_netio(pool *parent_pool) {
  return pr_alloc_netio2(parent_pool, NULL, NULL);
}

void init_netio(void) {
  signal(SIGPIPE, SIG_IGN);
  signal(SIGURG, SIG_IGN);

  pr_register_netio(NULL, 0);
}
