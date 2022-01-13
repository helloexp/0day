/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2018 The ProFTPD Project team
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
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* Data connection management functions */

#include "conf.h"

#ifdef HAVE_SYS_SENDFILE_H
#include <sys/sendfile.h>
#endif /* HAVE_SYS_SENDFILE_H */

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif /* HAVE_SYS_UIO_H */

static const char *trace_channel = "data";
static const char *timing_channel = "timing";

#define PR_DATA_OPT_IGNORE_ASCII	0x0001
static unsigned long data_opts = 0UL;
static uint64_t data_start_ms = 0L;
static int data_first_byte_read = FALSE;
static int data_first_byte_written = FALSE;

/* local macro */

#define MODE_STRING	(session.sf_flags & (SF_ASCII|SF_ASCII_OVERRIDE) ? \
			 "ASCII" : "BINARY")

/* Internal usage: pointer to current data connection stream in use (may be
 * in either read or write mode)
 */
static pr_netio_stream_t *nstrm = NULL;

static long timeout_linger = PR_TUNABLE_TIMEOUTLINGER;

static int timeout_idle = PR_TUNABLE_TIMEOUTIDLE;
static int timeout_noxfer = PR_TUNABLE_TIMEOUTNOXFER;
static int timeout_stalled = PR_TUNABLE_TIMEOUTSTALLED;

/* Called if the "Stalled" timer goes off
 */
static int stalled_timeout_cb(CALLBACK_FRAME) {
  pr_event_generate("core.timeout-stalled", NULL);
  pr_log_pri(PR_LOG_NOTICE, "Data transfer stall timeout: %d %s",
    timeout_stalled, timeout_stalled != 1 ? "seconds" : "second");
  pr_session_disconnect(NULL, PR_SESS_DISCONNECT_TIMEOUT,
    "TimeoutStalled during data transfer");

  /* Prevent compiler warning. */
  return 0;
}

/* This signal is raised if we get OOB data on the control connection, and
 * a data transfer is in progress.
 */
static RETSIGTYPE data_urgent(int signo) {
  if (session.sf_flags & SF_XFER) {
    pr_trace_msg(trace_channel, 5, "received SIGURG signal (signal %d), "
      "setting 'aborted' session flag", signo);
    session.sf_flags |= SF_ABORT;

    if (nstrm) {
      pr_netio_abort(nstrm);
    }
  }

  signal(SIGURG, data_urgent);
}

static void data_new_xfer(char *filename, int direction) {
  pr_data_clear_xfer_pool();

  session.xfer.p = make_sub_pool(session.pool);
  pr_pool_tag(session.xfer.p, "Data Transfer pool");

  session.xfer.filename = pstrdup(session.xfer.p, filename);
  session.xfer.direction = direction;
  session.xfer.bufsize = pr_config_get_server_xfer_bufsz(direction);
  session.xfer.buf = pcalloc(session.xfer.p, session.xfer.bufsize + 1);
  pr_trace_msg(trace_channel, 8, "allocated data transfer buffer of %lu bytes",
    (unsigned long) session.xfer.bufsize);
  session.xfer.buf++;	/* leave room for ascii translation */
  session.xfer.buflen = 0;
}

static int data_passive_open(const char *reason, off_t size) {
  conn_t *c;
  int rev, xerrno = 0;

  if (reason == NULL &&
      session.xfer.filename) {
    reason = session.xfer.filename;
  }

  /* Set the "stalled" timer, if any, to prevent the connection
   * open from taking too long
   */
  if (timeout_stalled) {
    pr_timer_add(timeout_stalled, PR_TIMER_STALLED, NULL, stalled_timeout_cb,
      "TimeoutStalled");
  }

  /* We save the state of our current disposition for doing reverse
   * lookups, and then set it to what the configuration wants it to
   * be.
   */
  rev = pr_netaddr_set_reverse_dns(ServerUseReverseDNS);

  /* Protocol and socket options should be set before handshaking. */

  if (session.xfer.direction == PR_NETIO_IO_RD) {
    pr_inet_set_socket_opts(session.d->pool, session.d,
      (main_server->tcp_rcvbuf_override ? main_server->tcp_rcvbuf_len : 0), 0,
      main_server->tcp_keepalive);

  } else {
    pr_inet_set_socket_opts(session.d->pool, session.d,
      0, (main_server->tcp_sndbuf_override ? main_server->tcp_sndbuf_len : 0),
      main_server->tcp_keepalive);
  }

  c = pr_inet_accept(session.pool, session.d, session.c, -1, -1, TRUE);
  pr_netaddr_set_reverse_dns(rev);

  if (c && c->mode != CM_ERROR) {
    pr_inet_close(session.pool, session.d);
    (void) pr_inet_set_nonblock(session.pool, c);
    session.d = c;

    pr_log_debug(DEBUG4, "passive data connection opened - local  : %s:%d",
      pr_netaddr_get_ipstr(session.d->local_addr), session.d->local_port);
    pr_log_debug(DEBUG4, "passive data connection opened - remote : %s:%d",
      pr_netaddr_get_ipstr(session.d->remote_addr), session.d->remote_port);

    if (session.xfer.xfer_type != STOR_UNIQUE) {
      if (size) {
        pr_response_send(R_150, _("Opening %s mode data connection for %s "
          "(%" PR_LU " %s)"), MODE_STRING, reason, (pr_off_t) size,
          size != 1 ? "bytes" : "byte");

      } else {
        pr_response_send(R_150, _("Opening %s mode data connection for %s"),
          MODE_STRING, reason);
      }

    } else {

      /* Format of 150 responses for STOU is explicitly dictated by
       * RFC 1123:
       *
       *  4.1.2.9  STOU Command: RFC-959 Section 4.1.3
       *
       *    The STOU command stores into a uniquely named file.  When it
       *    receives an STOU command, a Server-FTP MUST return the
       *    actual file name in the "125 Transfer Starting" or the "150
       *    Opening Data Connection" message that precedes the transfer
       *    (the 250 reply code mentioned in RFC-959 is incorrect).  The
       *    exact format of these messages is hereby defined to be as
       *    follows:
       *
       *        125 FILE: pppp
       *        150 FILE: pppp
       *
       *    where pppp represents the unique pathname of the file that
       *    will be written.
       */
      pr_response_send(R_150, "FILE: %s", reason);
    }

    return 0;
  }

  /* Check for error conditions. */
  if (c != NULL &&
      c->mode == CM_ERROR) {
    pr_log_pri(PR_LOG_ERR, "error: unable to accept an incoming data "
      "connection: %s", strerror(c->xerrno));
  }

  xerrno = session.d->xerrno;
  pr_response_add_err(R_425, _("Unable to build data connection: %s"),
    strerror(xerrno));
  destroy_pool(session.d->pool);
  session.d = NULL;

  errno = xerrno;
  return -1;
}

static int data_active_open(const char *reason, off_t size) {
  conn_t *c;
  int bind_port, rev, *root_revoke = NULL;
  const pr_netaddr_t *bind_addr = NULL;

  if (session.c->remote_addr == NULL) {
    /* An opened but unconnected connection? */
    errno = EINVAL;
    return -1;
  }

  if (reason == NULL &&
      session.xfer.filename) {
    reason = session.xfer.filename;
  }

  if (pr_netaddr_get_family(session.c->local_addr) == pr_netaddr_get_family(session.c->remote_addr)) {
    bind_addr = session.c->local_addr;

  } else {
    /* In this scenario, the server has an IPv6 socket, but the remote client
     * is an IPv4 (or IPv4-mapped IPv6) peer.
     */
    bind_addr = pr_netaddr_v6tov4(session.xfer.p, session.c->local_addr);
  }

  /* Default source port to which to bind for the active transfer, as
   * per RFC959.
   */
  bind_port = session.c->local_port-1;

  root_revoke = get_param_ptr(TOPLEVEL_CONF, "RootRevoke", FALSE);
  if (root_revoke == NULL) {
    /* In the absence of any explicit RootRevoke, the default behavior is to
     * change the source port.  This means we are technically noncompliant,
     * but most clients do not enforce this behavior.
     */
    bind_port = INPORT_ANY;

  } else {
    /* A RootRevoke value of 0 indicates 'false', 1 indicates 'true', and
     * 2 indicates 'NonCompliantActiveTransfer'.  We change the source port for
     * a RootRevoke value of 2, and for a value of 1, we make sure that
     * that the port is not a privileged port.
     */
    switch (*root_revoke) {
      case 1:
        if (bind_port < 1024) {
          pr_log_debug(DEBUG0, "RootRevoke in effect, unable to bind to local "
            "port %d for active transfer", bind_port);
          errno = EPERM;
          return -1;
        }
        break;

      case 2:
        bind_port = INPORT_ANY;
        break;

      default:
        break;
    }
  }

  session.d = pr_inet_create_conn(session.pool, -1, bind_addr, bind_port, TRUE);
  if (session.d == NULL) {
    int xerrno = errno;

    pr_response_add_err(R_425, _("Unable to build data connection: %s"),
      strerror(xerrno));
    session.d = NULL;

    errno = xerrno;
    return -1;
  }

  /* Default remote address to which to connect for an active transfer,
   * if the client has not specified a different address via PORT/EPRT,
   * as per RFC 959.
   */
  if (pr_netaddr_get_family(&session.data_addr) == AF_UNSPEC) {
    pr_log_debug(DEBUG6, "Client has not sent previous PORT/EPRT command, "
      "defaulting to %s#%u for active transfer",
      pr_netaddr_get_ipstr(session.c->remote_addr), session.c->remote_port);

    pr_netaddr_set_family(&session.data_addr, pr_netaddr_get_family(session.c->remote_addr));
    pr_netaddr_set_sockaddr(&session.data_addr, pr_netaddr_get_sockaddr(session.c->remote_addr));
  }

  /* Set the "stalled" timer, if any, to prevent the connection
   * open from taking too long
   */
  if (timeout_stalled) {
    pr_timer_add(timeout_stalled, PR_TIMER_STALLED, NULL, stalled_timeout_cb,
      "TimeoutStalled");
  }

  rev = pr_netaddr_set_reverse_dns(ServerUseReverseDNS);

  /* Protocol and socket options should be set before handshaking. */

  if (session.xfer.direction == PR_NETIO_IO_RD) {
    pr_inet_set_socket_opts(session.d->pool, session.d,
      (main_server->tcp_rcvbuf_override ? main_server->tcp_rcvbuf_len : 0), 0,
      main_server->tcp_keepalive);
    
  } else {
    pr_inet_set_socket_opts(session.d->pool, session.d,
      0, (main_server->tcp_sndbuf_override ? main_server->tcp_sndbuf_len : 0),
      main_server->tcp_keepalive);
  }

  /* Make sure that the necessary socket options are set on the socket prior
   * to the call to connect(2).
   */
  pr_inet_set_proto_opts(session.pool, session.d, main_server->tcp_mss_len, 0,
    IPTOS_THROUGHPUT, 1);
  pr_inet_generate_socket_event("core.data-connect", main_server,
    session.d->local_addr, session.d->listen_fd);

  if (pr_inet_connect(session.d->pool, session.d, &session.data_addr,
      session.data_port) < 0) {
    int xerrno = session.d->xerrno;

    pr_log_debug(DEBUG6,
      "Error connecting to %s#%u for active data transfer: %s",
      pr_netaddr_get_ipstr(&session.data_addr), session.data_port,
      strerror(xerrno));
    pr_response_add_err(R_425, _("Unable to build data connection: %s"),
      strerror(xerrno));

    destroy_pool(session.d->pool);
    session.d = NULL;

    errno = xerrno;
    return -1;
  }

  c = pr_inet_openrw(session.pool, session.d, NULL, PR_NETIO_STRM_DATA,
    session.d->listen_fd, -1, -1, TRUE);

  pr_netaddr_set_reverse_dns(rev);

  if (c) {
    pr_log_debug(DEBUG4, "active data connection opened - local  : %s:%d",
      pr_netaddr_get_ipstr(session.d->local_addr), session.d->local_port);
    pr_log_debug(DEBUG4, "active data connection opened - remote : %s:%d",
      pr_netaddr_get_ipstr(session.d->remote_addr), session.d->remote_port);

    if (session.xfer.xfer_type != STOR_UNIQUE) {
      if (size) {
        pr_response_send(R_150, _("Opening %s mode data connection for %s "
          "(%" PR_LU " %s)"), MODE_STRING, reason, (pr_off_t) size,
          size != 1 ? "bytes" : "byte");

      } else {
        pr_response_send(R_150, _("Opening %s mode data connection for %s"),
          MODE_STRING, reason);
      }

    } else {

      /* Format of 150 responses for STOU is explicitly dictated by
       * RFC 1123:
       *
       *  4.1.2.9  STOU Command: RFC-959 Section 4.1.3
       *
       *    The STOU command stores into a uniquely named file.  When it
       *    receives an STOU command, a Server-FTP MUST return the
       *    actual file name in the "125 Transfer Starting" or the "150
       *    Opening Data Connection" message that precedes the transfer
       *    (the 250 reply code mentioned in RFC-959 is incorrect).  The
       *    exact format of these messages is hereby defined to be as
       *    follows:
       *
       *        125 FILE: pppp
       *        150 FILE: pppp
       *
       *    where pppp represents the unique pathname of the file that
       *    will be written.
       */
      pr_response_send(R_150, "FILE: %s", reason);
    }

    pr_inet_close(session.pool, session.d);
    (void) pr_inet_set_nonblock(session.pool, session.d);
    session.d = c;
    return 0;
  }

  pr_response_add_err(R_425, _("Unable to build data connection: %s"),
    strerror(session.d->xerrno));
  errno = session.d->xerrno;

  destroy_pool(session.d->pool);
  session.d = NULL;
  return -1;
}

void pr_data_set_linger(long linger) {
  timeout_linger = linger;
}

int pr_data_get_timeout(int id) {
  switch (id) {
    case PR_DATA_TIMEOUT_IDLE:
      return timeout_idle;

    case PR_DATA_TIMEOUT_NO_TRANSFER:
      return timeout_noxfer;

    case PR_DATA_TIMEOUT_STALLED:
      return timeout_stalled;
  }

  errno = EINVAL;
  return -1;
}

void pr_data_set_timeout(int id, int timeout) {
  switch (id) {
    case PR_DATA_TIMEOUT_IDLE:
      timeout_idle = timeout;
      break;

    case PR_DATA_TIMEOUT_NO_TRANSFER:
      timeout_noxfer = timeout;
      break;

    case PR_DATA_TIMEOUT_STALLED:
      timeout_stalled = timeout;
      break;
  }
}

void pr_data_clear_xfer_pool(void) {
  int xfer_type;

  if (session.xfer.p)
    destroy_pool(session.xfer.p);

  /* Note that session.xfer.xfer_type may have been set already, e.g.
   * for STOR_UNIQUE uploads.  To support this, we need to preserve that
   * value.
   */
  xfer_type = session.xfer.xfer_type;

  memset(&session.xfer, 0, sizeof(session.xfer));
  session.xfer.xfer_type = xfer_type;  
}

void pr_data_reset(void) {
  if (session.d &&
      session.d->pool) {
    destroy_pool(session.d->pool);
  }

  /* Clear any leftover state from previous transfers. */
  pr_ascii_ftp_reset();

  session.d = NULL;
  session.sf_flags &= (SF_ALL^(SF_ABORT|SF_POST_ABORT|SF_XFER|SF_PASSIVE|SF_ASCII_OVERRIDE|SF_EPSV_ALL));
}

int pr_data_ignore_ascii(int ignore_ascii) {
  int res;

  if (ignore_ascii != TRUE && 
      ignore_ascii != FALSE) {
    errno = EINVAL;
    return -1;
  }

  if (data_opts & PR_DATA_OPT_IGNORE_ASCII) {
    if (!ignore_ascii) {
      data_opts &= ~PR_DATA_OPT_IGNORE_ASCII;
    }

    res = TRUE;

  } else {
    if (ignore_ascii) {
      data_opts |= PR_DATA_OPT_IGNORE_ASCII;
    }

    res = FALSE;
  }

  return res;
}

void pr_data_init(char *filename, int direction) {
  if (session.xfer.p == NULL) {
    data_new_xfer(filename, direction);

  } else {
    if (!(session.sf_flags & SF_PASSIVE)) {
      pr_log_debug(DEBUG5,
        "data_init oddity: session.xfer exists in non-PASV mode");
    }

    session.xfer.direction = direction;
  }

  /* Clear any leftover state from previous transfers. */
  pr_ascii_ftp_reset();
}

int pr_data_open(char *filename, char *reason, int direction, off_t size) {
  int res = 0;

  if (session.c == NULL) {
    errno = EINVAL;
    return -1;
  }

  if ((session.sf_flags & SF_PASSIVE) ||
      (session.sf_flags & SF_EPSV_ALL)) {
    /* For passive transfers, we expect there to already be an existing
     * data connection...
     */
    if (session.d == NULL) {
      errno = EINVAL;
      return -1;
    }

  } else {
    /* ...but for active transfers, we expect there to NOT be an existing
     * data connection.
     */
    if (session.d != NULL) {
      errno = session.d->xerrno = EINVAL;
      return -1;
    }
  }

  /* Make sure that any abort flags have been cleared. */
  session.sf_flags &= ~(SF_ABORT|SF_POST_ABORT);

  if (session.xfer.p == NULL) {
    data_new_xfer(filename, direction);

  } else {
    session.xfer.direction = direction;
  }

  if (!reason) {
    reason = filename;
  }

  /* Passive data transfers... */
  if ((session.sf_flags & SF_PASSIVE) ||
      (session.sf_flags & SF_EPSV_ALL)) {
    res = data_passive_open(reason, size);

  /* Active data transfers... */
  } else {
    res = data_active_open(reason, size);
  }

  if (res >= 0) {
    struct sigaction act;

    if (pr_netio_postopen(session.d->instrm) < 0) {
      pr_response_add_err(R_425, _("Unable to build data connection: %s"),
        strerror(session.d->xerrno));
      destroy_pool(session.d->pool);
      errno = session.d->xerrno;
      session.d = NULL;
      return -1;
    }

    if (pr_netio_postopen(session.d->outstrm) < 0) {
      pr_response_add_err(R_425, _("Unable to build data connection: %s"),
        strerror(session.d->xerrno));
      destroy_pool(session.d->pool);
      errno = session.d->xerrno;
      session.d = NULL;
      return -1;
    }

    memset(&session.xfer.start_time, '\0', sizeof(session.xfer.start_time));
    gettimeofday(&session.xfer.start_time, NULL);

    if (session.xfer.direction == PR_NETIO_IO_RD) {
      nstrm = session.d->instrm;

    } else {
      nstrm = session.d->outstrm;
    }

    session.sf_flags |= SF_XFER;

    if (timeout_noxfer) {
      pr_timer_reset(PR_TIMER_NOXFER, ANY_MODULE);
    }

    /* Allow aborts -- set the current NetIO stream to allow interrupted
     * syscalls, so our SIGURG handler can interrupt it
     */
    pr_netio_set_poll_interval(nstrm, 1);

    /* PORTABILITY: sigaction is used here to allow us to indicate
     * (w/ POSIX at least) that we want SIGURG to interrupt syscalls.  Put
     * in whatever is necessary for your arch here; probably not necessary
     * as the only _important_ interrupted syscall is select(), which on
     * any sensible system is interrupted.
     */

    act.sa_handler = data_urgent;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
#ifdef SA_INTERRUPT
    act.sa_flags |= SA_INTERRUPT;
#endif

    if (sigaction(SIGURG, &act, NULL) < 0) {
      pr_log_pri(PR_LOG_WARNING,
        "warning: unable to set SIGURG signal handler: %s", strerror(errno));
    }

#ifdef HAVE_SIGINTERRUPT
    /* This is the BSD way of ensuring interruption.
     * Linux uses it too (??)
     */
    if (siginterrupt(SIGURG, 1) < 0) {
      pr_log_pri(PR_LOG_WARNING,
        "warning: unable to make SIGURG interrupt system calls: %s",
        strerror(errno));
    }
#endif

    /* Reset all of the timing-related variables for data transfers. */
    pr_gettimeofday_millis(&data_start_ms);
    data_first_byte_read = FALSE;
    data_first_byte_written = FALSE;
  }

  return res;
}

/* close == successful transfer */
void pr_data_close(int quiet) {
  nstrm = NULL;

  if (session.d) {
    pr_inet_lingering_close(session.pool, session.d, timeout_linger);
    session.d = NULL;
  }

  /* Aborts no longer necessary */
  signal(SIGURG, SIG_IGN);

  if (timeout_noxfer) {
    pr_timer_reset(PR_TIMER_NOXFER, ANY_MODULE);
  }

  if (timeout_stalled) {
    pr_timer_remove(PR_TIMER_STALLED, ANY_MODULE);
  }

  session.sf_flags &= (SF_ALL^SF_PASSIVE);
  session.sf_flags &= (SF_ALL^(SF_ABORT|SF_XFER|SF_PASSIVE|SF_ASCII_OVERRIDE));
  pr_session_set_idle();

  if (!quiet) {
    pr_response_add(R_226, _("Transfer complete"));
  }
}

/* Note: true_abort may be false in real abort situations, because
 * some ftp clients close the data connection at the same time as they
 * send the OOB byte (which results in a broken pipe on our
 * end).  Thus, it's a race between the OOB data and the tcp close
 * finishing.  Either way, it's ok (client will see either "Broken pipe"
 * error or "Aborted").  xfer_abor() in mod_xfer cleans up the session
 * flags in any case.  session flags will end up have SF_POST_ABORT
 * set if the OOB byte won the race.
 */
void pr_data_cleanup(void) {
  /* sanity check */
  if (session.d) {
    pr_inet_lingering_close(session.pool, session.d, timeout_linger);
    session.d = NULL;
  }

  pr_data_clear_xfer_pool();

  /* Clear/restore the default data transfer type. Otherwise, things like
   * APPEs or STOUs will be preserved for the next upload erroneously
   * (see Bug#3612).
   */
  session.xfer.xfer_type = STOR_DEFAULT;
}

/* In order to avoid clearing the transfer counters in session.xfer, we don't
 * clear session.xfer here, it should be handled by the appropriate
 * LOG_CMD/LOG_CMD_ERR handler calling pr_data_cleanup().
 */
void pr_data_abort(int err, int quiet) {
  int true_abort = XFER_ABORTED;
  nstrm = NULL;

  pr_trace_msg(trace_channel, 9,
    "aborting data transfer (errno = %s (%d), quiet = %s, true abort = %s)",
    strerror(err), err, quiet ? "true" : "false",
    true_abort ? "true" : "false");

  if (session.d) {
    if (true_abort == FALSE) {
      pr_inet_lingering_close(session.pool, session.d, timeout_linger);

    } else {
      pr_inet_lingering_abort(session.pool, session.d, timeout_linger);
    }

    session.d = NULL;
  }

  if (timeout_noxfer) {
    pr_timer_reset(PR_TIMER_NOXFER, ANY_MODULE);
  }

  if (timeout_stalled) {
    pr_timer_remove(PR_TIMER_STALLED, ANY_MODULE);
  }

  session.sf_flags &= (SF_ALL^SF_PASSIVE);
  session.sf_flags &= (SF_ALL^(SF_XFER|SF_PASSIVE|SF_ASCII_OVERRIDE));
  pr_session_set_idle();

  /* Aborts no longer necessary */
  signal(SIGURG, SIG_IGN);

  if (!quiet) {
    char *respcode = R_426;
    char *msg = NULL;
    char msgbuf[64];

    switch (err) {

    case 0:
      respcode = R_426;
      msg = _("Data connection closed");
      break;

#ifdef ENXIO
    case ENXIO:
      respcode = R_451;
      msg = _("Unexpected streams hangup");
      break;

#endif

#ifdef EAGAIN
    case EAGAIN:		/* FALLTHROUGH */
#endif
#ifdef ENOMEM
    case ENOMEM:
#endif
#if defined(EAGAIN) || defined(ENOMEM)
      respcode = R_451;
      msg = _("Insufficient memory or file locked");
      break;
#endif

#ifdef ETXTBSY
    case ETXTBSY:		/* FALLTHROUGH */
#endif
#ifdef EBUSY
    case EBUSY:
#endif
#if defined(ETXTBSY) || defined(EBUSY)
      respcode = R_451;
      break;
#endif

#ifdef ENOSPC
    case ENOSPC:
      respcode = R_452;
      break;
#endif

#ifdef EDQUOT
    case EDQUOT:		/* FALLTHROUGH */
#endif
#ifdef EFBIG
    case EFBIG:
#endif
#if defined(EDQUOT) || defined(EFBIG)
      respcode = R_552;
      break;
#endif

#ifdef ECOMM
    case ECOMM:		/* FALLTHROUGH */
#endif
#ifdef EDEADLK
    case EDEADLK:		/* FALLTHROUGH */
#endif
#ifdef EDEADLOCK
# if !defined(EDEADLK) || (EDEADLOCK != EDEADLK)
    case EDEADLOCK:		/* FALLTHROUGH */
# endif
#endif
#ifdef EXFULL
    case EXFULL:		/* FALLTHROUGH */
#endif
#ifdef ENOSR
    case ENOSR:		/* FALLTHROUGH */
#endif
#ifdef EPROTO
    case EPROTO:		/* FALLTHROUGH */
#endif
#ifdef ETIME
    case ETIME:		/* FALLTHROUGH */
#endif
#ifdef EIO
    case EIO:		/* FALLTHROUGH */
#endif
#ifdef EFAULT
    case EFAULT:		/* FALLTHROUGH */
#endif
#ifdef ESPIPE
    case ESPIPE:		/* FALLTHROUGH */
#endif
#ifdef EPIPE
    case EPIPE:
#endif
#if defined(ECOMM) || defined(EDEADLK) ||  defined(EDEADLOCK) \
	|| defined(EXFULL) || defined(ENOSR) || defined(EPROTO) \
	|| defined(ETIME) || defined(EIO) || defined(EFAULT) \
	|| defined(ESPIPE) || defined(EPIPE)
      respcode = R_451;
      break;
#endif

#ifdef EREMCHG
    case EREMCHG:		/* FALLTHROUGH */
#endif
#ifdef ESRMNT
    case ESRMNT:		/* FALLTHROUGH */
#endif
#ifdef ESTALE
    case ESTALE:		/* FALLTHROUGH */
#endif
#ifdef ENOLINK
    case ENOLINK:		/* FALLTHROUGH */
#endif
#ifdef ENOLCK
    case ENOLCK:		/* FALLTHROUGH */
#endif
#ifdef ENETRESET
    case ENETRESET:		/* FALLTHROUGH */
#endif
#ifdef ECONNABORTED
    case ECONNABORTED:	/* FALLTHROUGH */
#endif
#ifdef ECONNRESET
    case ECONNRESET:	/* FALLTHROUGH */
#endif
#ifdef ETIMEDOUT
    case ETIMEDOUT:
#endif
#if defined(EREMCHG) || defined(ESRMNT) ||  defined(ESTALE) \
	|| defined(ENOLINK) || defined(ENOLCK) || defined(ENETRESET) \
	|| defined(ECONNABORTED) || defined(ECONNRESET) || defined(ETIMEDOUT)
      respcode = R_450;
      msg = _("Link to file server lost");
      break;
#endif
    }

    if (msg == NULL &&
        (msg = strerror(err)) == NULL ) {

      if (pr_snprintf(msgbuf, sizeof(msgbuf),
          _("Unknown or out of range errno [%d]"), err) > 0)
	msg = msgbuf;
    }

    pr_log_pri(PR_LOG_NOTICE, "notice: user %s: aborting transfer: %s",
      session.user ? session.user : "(unknown)", msg);

    /* If we are aborting, then a 426 response has already been sent,
     * and we don't want to add another to the error queue.
     */
    if (true_abort == FALSE) {
      pr_response_add_err(respcode, _("Transfer aborted. %s"), msg ? msg : "");
    }
  }

  if (true_abort) {
    session.sf_flags |= SF_POST_ABORT;
  }
}

/* From response.c.  XXX Need to provide these symbols another way. */
extern pr_response_t *resp_list, *resp_err_list;

static void poll_ctrl(void) {
  int res;

  if (session.c == NULL) {
    return;
  }

  pr_trace_msg(trace_channel, 4, "polling for commands on control channel");
  pr_netio_set_poll_interval(session.c->instrm, 0);
  res = pr_netio_poll(session.c->instrm);
  pr_netio_reset_poll_interval(session.c->instrm);

  if (res == 0 &&
      !(session.sf_flags & SF_ABORT)) {
    cmd_rec *cmd = NULL;

    pr_trace_msg(trace_channel, 1,
      "data available for reading on control channel during data transfer, "
      "reading control data");
    res = pr_cmd_read(&cmd);
    if (res < 0) {
      int xerrno;
#if defined(ECONNABORTED)
      xerrno = ECONNABORTED;
#elif defined(ENOTCONN)
      xerrno = ENOTCONN;
#else
      xerrno = EIO;
#endif

      pr_trace_msg(trace_channel, 1,
        "unable to read control command during data transfer: %s",
        strerror(xerrno));
      errno = xerrno;

#ifndef PR_DEVEL_NO_DAEMON
      /* Otherwise, EOF */
      pr_session_disconnect(NULL, PR_SESS_DISCONNECT_CLIENT_EOF, NULL);
#else
      return;
#endif /* PR_DEVEL_NO_DAEMON */

    } else if (cmd != NULL) {
      char *ch;

      for (ch = cmd->argv[0]; *ch; ch++) {
        *ch = toupper(*ch);
      }

      cmd->cmd_id = pr_cmd_get_id(cmd->argv[0]);

      /* Only handle commands which do not involve data transfers; we
       * already have a data transfer in progress.  For any data transfer
       * command, send a 450 ("busy") reply.  Looks like almost all of the
       * data transfer commands accept that response, as per RFC959.
       *
       * We also prevent the EPRT, EPSV, PASV, and PORT commands, since
       * they will also interfere with the current data transfer.  In doing
       * so, we break RFC compliance a little; RFC959 does not allow a
       * response code of 450 for those commands (although it should).
       */
      if (pr_cmd_cmp(cmd, PR_CMD_APPE_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_LIST_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_MLSD_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_NLST_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_RETR_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_STOR_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_STOU_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_RNFR_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_RNTO_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_PORT_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_EPRT_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_PASV_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_EPSV_ID) == 0) {
        pool *resp_pool;

        pr_trace_msg(trace_channel, 5,
          "client sent '%s' command during data transfer, denying",
          (char *) cmd->argv[0]);

        resp_list = resp_err_list = NULL;
        resp_pool = pr_response_get_pool();

        pr_response_set_pool(cmd->pool);

        pr_response_add_err(R_450, _("%s: data transfer in progress"),
          (char *) cmd->argv[0]);

        pr_response_flush(&resp_err_list);

        destroy_pool(cmd->pool);
        pr_response_set_pool(resp_pool);

      /* We don't want to actually dispatch the NOOP command, since that
       * would overwrite the scoreboard with the NOOP state; admins probably
       * want to see the command that caused the data transfer.  And since
       * NOOP doesn't take a 450 response (as per RFC959), we will simply
       * return 200.
       */
      } else if (pr_cmd_cmp(cmd, PR_CMD_NOOP_ID) == 0) {
        pool *resp_pool;

        pr_trace_msg(trace_channel, 5,
          "client sent '%s' command during data transfer, ignoring",
          (char *) cmd->argv[0]);

        resp_list = resp_err_list = NULL;
        resp_pool = pr_response_get_pool();

        pr_response_set_pool(cmd->pool);

        pr_response_add(R_200, _("%s: data transfer in progress"),
          (char *) cmd->argv[0]);

        pr_response_flush(&resp_list);

        destroy_pool(cmd->pool);
        pr_response_set_pool(resp_pool);

      } else {
        char *title_buf = NULL;
        int title_len = -1;
        const char *sce_cmd = NULL, *sce_cmd_arg = NULL;

        pr_trace_msg(trace_channel, 5,
          "client sent '%s' command during data transfer, dispatching",
          (char *) cmd->argv[0]);

        title_len = pr_proctitle_get(NULL, 0);
        if (title_len > 0) {
          title_buf = pcalloc(cmd->pool, title_len + 1);
          pr_proctitle_get(title_buf, title_len + 1); 
        }

        sce_cmd = pr_scoreboard_entry_get(PR_SCORE_CMD);
        sce_cmd_arg = pr_scoreboard_entry_get(PR_SCORE_CMD_ARG);

        pr_cmd_dispatch(cmd);

        pr_scoreboard_entry_update(session.pid,
          PR_SCORE_CMD, "%s", sce_cmd, NULL, NULL);
        pr_scoreboard_entry_update(session.pid,
          PR_SCORE_CMD_ARG, "%s", sce_cmd_arg, NULL, NULL);

        if (title_len > 0) {
          pr_proctitle_set_str(title_buf);
        }

        destroy_pool(cmd->pool);
      }

    } else {
      pr_trace_msg(trace_channel, 3,
        "invalid command sent, sending error response");
      pr_response_send(R_500, _("Invalid command: try being more creative"));
    }
  }
}

/* pr_data_xfer() actually transfers the data on the data connection.  ASCII
 * translation is performed if necessary.  `direction' is set when the data
 * connection was opened.
 *
 * We determine if the client buffer is read from or written to.  Returns 0 if
 * reading and data connection closes, or -1 if error (with errno set).
 */
int pr_data_xfer(char *cl_buf, size_t cl_size) {
  int len = 0;
  int total = 0;
  int res = 0;
  pool *tmp_pool = NULL;

  if (cl_buf == NULL ||
      cl_size == 0) {
    errno = EINVAL;
    return -1;
  }

  /* Poll the control channel for any commands we should handle, like
   * QUIT or ABOR.
   */
  poll_ctrl();

  /* If we don't have a data connection here (e.g. might have been closed
   * by an ABOR), then return zero (no data transferred).
   */
  if (session.d == NULL) {
    int xerrno;

#if defined(ECONNABORTED)
    xerrno = ECONNABORTED;
#elif defined(ENOTCONN)
    xerrno = ENOTCONN;
#else
    xerrno = EIO;
#endif

    pr_trace_msg(trace_channel, 1,
      "data connection is null prior to data transfer (possibly from "
      "aborted transfer), returning '%s' error", strerror(xerrno));
    pr_log_debug(DEBUG5, 
      "data connection is null prior to data transfer (possibly from "
       "aborted transfer), returning '%s' error", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (session.xfer.direction == PR_NETIO_IO_RD) {
    char *buf;

    buf = session.xfer.buf;

    /* We use ASCII translation if:
     *
     * - SF_ASCII session flag is set, AND IGNORE_ASCII data opt NOT set
     */
    if (((session.sf_flags & SF_ASCII) &&
        !(data_opts & PR_DATA_OPT_IGNORE_ASCII))) {
      int adjlen, buflen;

      do {
        buflen = session.xfer.buflen;        /* how much remains in buf */
        adjlen = 0;

        pr_signals_handle();

        len = pr_netio_read(session.d->instrm, buf + buflen,
          session.xfer.bufsize - buflen, 1);
        while (len < 0) {
          int xerrno = errno;
 
          if (xerrno == EAGAIN || xerrno == EINTR) {
            /* Since our socket is in non-blocking mode, read(2) can return
             * EAGAIN if there is no data yet for us.  Handle this by
             * delaying temporarily, then trying again.
             */
            errno = EINTR;
            pr_signals_handle();
            
            len = pr_netio_read(session.d->instrm, buf + buflen,
              session.xfer.bufsize - buflen, 1);
            continue;
          }

          destroy_pool(tmp_pool);
          errno = xerrno;
          return -1;
        }

        if (len > 0 &&
            data_first_byte_read == FALSE) {
          if (pr_trace_get_level(timing_channel)) {
            unsigned long elapsed_ms;
            uint64_t read_ms;

            pr_gettimeofday_millis(&read_ms);
            elapsed_ms = (unsigned long) (read_ms - data_start_ms);

            pr_trace_msg(timing_channel, 7,
              "Time for first data byte read: %lu ms", elapsed_ms);
          }

          data_first_byte_read = TRUE;
        }

        if (len > 0) {
          pr_trace_msg(trace_channel, 19, "read %d %s from network", len,
            len != 1 ? "bytes" : "byte");

          buflen += len;

          if (timeout_stalled) {
            pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);
          }
        }

        /* If buflen > 0, data remains in the buffer to be copied. */
        if (len >= 0 &&
            buflen > 0) {

          /* Perform ASCII translation:
           *
           * buflen: is returned as the modified buffer length after
           *         translation
           * res:    is returned as the number of characters unprocessed in
           *         the buffer (to be dealt with later)
           *
           * We skip the call to pr_ascii_ftp_from_crlf() in one case:
           * when we have one character in the buffer and have reached
           * end of data, this is so that pr_ascii_ftp_from_crlf() won't sit
           * forever waiting for the next character after a final '\r'.
           */
          if (len > 0 ||
              buflen > 1) {
            size_t outlen = 0;

            if (tmp_pool == NULL) {
              tmp_pool = make_sub_pool(session.xfer.p);
              pr_pool_tag(tmp_pool, "ASCII upload");
            }

            res = pr_ascii_ftp_from_crlf(tmp_pool, buf, buflen, &buf, &outlen);
            if (res < 0) {
              pr_trace_msg(trace_channel, 3, "error reading ASCII data: %s",
                strerror(errno));

            } else {
              adjlen += res;
              buflen = (int) outlen;
            }
          }

          /* Now copy everything we can into cl_buf */
          if ((size_t) buflen > cl_size) {
            /* Because we have to cut our buffer short, make sure this
             * is made up for later by increasing adjlen.
             */
            adjlen += (buflen - cl_size);
            buflen = cl_size;
          }

          memcpy(cl_buf, buf, buflen);

          /* Copy whatever remains at the end of session.xfer.buf to the
           * head of the buffer and adjust buf accordingly.
           *
           * adjlen is now the total bytes still waiting in buf, if
           * anything remains, copy it to the start of the buffer.
           */

          if (adjlen > 0) {
            memcpy(buf, buf + buflen, adjlen);
          }

          /* Store everything back in session.xfer. */
          session.xfer.buflen = adjlen;
          total += buflen;
        }
	
        /* Restart if data was returned by pr_netio_read() (len > 0) but no
         * data was copied to the client buffer (buflen = 0).  This indicates
         * that pr_ascii_ftp_from_crlf() needs more data in order to
         * translate, so we need to call pr_netio_read() again.
         */
      } while (len > 0 && buflen == 0);

      /* Return how much data we actually copied into the client buffer. */
      len = buflen;

    } else {
      len = pr_netio_read(session.d->instrm, cl_buf, cl_size, 1);
      while (len < 0) {
        int xerrno = errno;

        if (xerrno == EAGAIN || xerrno == EINTR) {
          /* Since our socket is in non-blocking mode, read(2) can return
           * EAGAIN if there is no data yet for us.  Handle this by
           * delaying temporarily, then trying again.
           */
          errno = EINTR;
          pr_signals_handle();
           
          len = pr_netio_read(session.d->instrm, cl_buf, cl_size, 1);
          continue;
        }

        break;
      }

      if (len > 0) {
        pr_trace_msg(trace_channel, 19, "read %d %s from network", len,
          len != 1 ? "bytes" : "byte");

        if (data_first_byte_read == FALSE) {
          if (pr_trace_get_level(timing_channel)) {
            unsigned long elapsed_ms;
            uint64_t read_ms;

            pr_gettimeofday_millis(&read_ms);
            elapsed_ms = (unsigned long) (read_ms - data_start_ms);

            pr_trace_msg(timing_channel, 7,
              "Time for first data byte read: %lu ms", elapsed_ms);
          }

          data_first_byte_read = TRUE;
        }

        /* Non-ASCII mode doesn't need to use session.xfer.buf */
        if (timeout_stalled) {
          pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);
        }

        total += len;
      } 
    }

  } else { /* PR_NETIO_IO_WR */
  
    while (cl_size) {
      int bwrote = 0;
      int buflen = cl_size;
      unsigned int xferbuflen;
      char *xfer_buf = NULL;

      pr_signals_handle();

      if (buflen > pr_config_get_server_xfer_bufsz(PR_NETIO_IO_WR)) {
        buflen = pr_config_get_server_xfer_bufsz(PR_NETIO_IO_WR);
      }

      xferbuflen = buflen;

      /* Fill up our internal buffer. */
      memcpy(session.xfer.buf, cl_buf, buflen);

      /* We use ASCII translation if:
       *
       * - SF_ASCII_OVERRIDE session flag is set (e.g. for LIST/NLST)
       * - SF_ASCII session flag is set, AND IGNORE_ASCII data opt NOT set
       */
      if ((session.sf_flags & SF_ASCII_OVERRIDE) ||
          ((session.sf_flags & SF_ASCII) &&
           !(data_opts & PR_DATA_OPT_IGNORE_ASCII))) {
        char *out = NULL;
        size_t outlen = 0;

        if (tmp_pool == NULL) {
          tmp_pool = make_sub_pool(session.xfer.p);
          pr_pool_tag(tmp_pool, "ASCII download");
        }

        /* Scan the internal buffer, looking for LFs with no preceding CRs.
         * Add CRs (and expand the internal buffer) as necessary. xferbuflen
         * will be adjusted so that it contains the length of data in
         * the internal buffer, including any added CRs.
         */
        res = pr_ascii_ftp_to_crlf(tmp_pool, session.xfer.buf, xferbuflen,
          &out, &outlen);
        if (res < 0) {
          pr_trace_msg(trace_channel, 1, "error writing ASCII data: %s",
            strerror(errno));

        } else {
          xfer_buf = session.xfer.buf;
          session.xfer.buf = out;
          session.xfer.buflen = xferbuflen = outlen;
        }
      }

      bwrote = pr_netio_write(session.d->outstrm, session.xfer.buf, xferbuflen);
      while (bwrote < 0) {
        int xerrno = errno;

        if (xerrno == EAGAIN || xerrno == EINTR) {
          /* Since our socket is in non-blocking mode, write(2) can return
           * EAGAIN if there is not enough from for our data yet.  Handle
           * this by delaying temporarily, then trying again.
           */
          errno = EINTR;
          pr_signals_handle();
             
          bwrote = pr_netio_write(session.d->outstrm, session.xfer.buf,
            xferbuflen);
          continue;
        }

        destroy_pool(tmp_pool);
        if (xfer_buf != NULL) {
          /* Free up the malloc'd memory. */
          free(session.xfer.buf);
          session.xfer.buf = xfer_buf;
        }

        errno = xerrno;
        return -1;
      }

      if (bwrote > 0) {
        pr_trace_msg(trace_channel, 19, "wrote %d %s to network", bwrote,
          bwrote != 1 ? "bytes" : "byte");

        if (data_first_byte_written == FALSE) {
          if (pr_trace_get_level(timing_channel)) {
            unsigned long elapsed_ms;
            uint64_t write_ms;

            pr_gettimeofday_millis(&write_ms);
            elapsed_ms = (unsigned long) (write_ms - data_start_ms);

            pr_trace_msg(timing_channel, 7,
              "Time for first data byte written: %lu ms", elapsed_ms);
          }

          data_first_byte_written = TRUE;
        }

        if (timeout_stalled) {
          pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);
        }

        cl_size -= buflen;
        cl_buf += buflen;
        total += buflen;
      }

      if (xfer_buf != NULL) {
        /* Yes, we are using malloc et al here, rather than the memory pools.
         * See Bug#4352 for details.
         */
        free(session.xfer.buf);
        session.xfer.buf = xfer_buf;
      }
    }

    len = total;
  }

  if (total &&
      timeout_idle) {
    pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
  }

  session.xfer.total_bytes += total;
  session.total_bytes += total;
  if (session.xfer.direction == PR_NETIO_IO_RD) {
    session.total_bytes_in += total;

  } else {
    session.total_bytes_out += total;
  }

  destroy_pool(tmp_pool);
  return (len < 0 ? -1 : len);
}

#ifdef HAVE_SENDFILE
/* pr_data_sendfile() actually transfers the data on the data connection.
 * ASCII translation is not performed.
 * return 0 if reading and data connection closes, or -1 if error
 */
pr_sendfile_t pr_data_sendfile(int retr_fd, off_t *offset, off_t count) {
  int flags, error;
  pr_sendfile_t len = 0, total = 0;
#if defined(HAVE_AIX_SENDFILE)
  struct sf_parms parms;
  int rc;
#endif /* HAVE_AIX_SENDFILE */

  if (offset == NULL ||
      count == 0) {
    errno = EINVAL;
    return -1;
  }

  if (session.xfer.direction == PR_NETIO_IO_RD) {
    errno = EPERM;
    return -1;
  }

  if (session.d == NULL) {
    errno = EPERM;
    return -1;
  }

  flags = fcntl(PR_NETIO_FD(session.d->outstrm), F_GETFL);
  if (flags < 0) {
    return -1;
  }

  /* Set fd to blocking-mode for sendfile() */
  if (flags & O_NONBLOCK) {
    if (fcntl(PR_NETIO_FD(session.d->outstrm), F_SETFL, flags^O_NONBLOCK) < 0) {
      return -1;
    }
  }

  for (;;) {
#if defined(HAVE_LINUX_SENDFILE) || defined(HAVE_SOLARIS_SENDFILE)
    off_t orig_offset = *offset;

    /* Linux semantics are fairly straightforward in a glibc 2.x world:
     *
     *   #include <sys/sendfile.h>
     *
     *   ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
     *
     * Unfortunately, this API does not allow for an off_t number of bytes
     * to be sent, only a size_t.  This means we need to make sure that
     * the given count does not exceed the maximum value for a size_t.  Even
     * worse, the return value is a ssize_t, not a size_t, which means
     * the maximum value used can only be of the maximum _signed_ value,
     * not the maximum unsigned value.  This means calling sendfile() more
     * times.  How annoying.
     */

#if defined(HAVE_LINUX_SENDFILE)
    if (count > INT_MAX) {
      count = INT_MAX;
    }
#elif defined(HAVE_SOLARIS_SENDFILE)
# if SIZEOF_SIZE_T == SIZEOF_INT
    if (count > INT_MAX) {
      count = INT_MAX;
    }
# elif SIZEOF_SIZE_T == SIZEOF_LONG
    if (count > LONG_MAX) {
      count = LONG_MAX;
    }
# elif SIZEOF_SIZE_T == SIZEOF_LONG_LONG
    if (count > LLONG_MAX) {
      count = LLONG_MAX;
    }
# endif
#endif /* !HAVE_SOLARIS_SENDFILE */

    errno = 0;
    len = sendfile(PR_NETIO_FD(session.d->outstrm), retr_fd, offset, count);

    /* If no data could be written (e.g. the file was truncated), we're
     * done (Bug#4318).
     */
    if (len == 0) {
      if (errno != EINTR &&
          errno != EAGAIN) {
        break;
      }

      /* Handle our interrupting signal, and continue. */
      pr_signals_handle();
    }

    if (len != -1 &&
        len < count) {
      /* Under Linux semantics, this occurs when a signal has interrupted
       * sendfile().
       */
      if (XFER_ABORTED) {
        errno = EINTR;

        session.xfer.total_bytes += len;
        session.total_bytes += len;
        session.total_bytes_out += len;
        session.total_raw_out += len;

        return -1;
      }

      count -= len;

      /* Only reset the timers if data have actually been written out. */
      if (len > 0) {
        if (timeout_stalled) {
          pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);
        }

        if (timeout_idle) {
          pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
        }
      }

      session.xfer.total_bytes += len;
      session.total_bytes += len;
      session.total_bytes_out += len;
      session.total_raw_out += len;
      total += len;

      pr_signals_handle();
      continue;

    } else if (len == -1) {
      /* Linux updates offset on error, not len like BSD, fix up so
       * BSD-based code works.
       */
      len = *offset - orig_offset;
      *offset = orig_offset;

#elif defined(HAVE_BSD_SENDFILE)
    /* BSD semantics for sendfile are flexible...it'd be nice if we could
     * standardize on something like it.  The semantics are:
     *
     *   #include <sys/types.h>
     *   #include <sys/socket.h>
     *   #include <sys/uio.h>
     *
     *   int sendfile(int in_fd, int out_fd, off_t offset, size_t count,
     *                struct sf_hdtr *hdtr, off_t *len, int flags)
     *
     *  The comments above, about size_t versus off_t, apply here as
     *  well.  Except that BSD's sendfile() uses an off_t * for returning
     *  the number of bytes sent, so we can use the maximum unsigned
     *  value.
     */

#if SIZEOF_SIZE_T == SIZEOF_INT
    if (count > UINT_MAX) {
      count = UINT_MAX;
    }
#elif SIZEOF_SIZE_T == SIZEOF_LONG
    if (count > ULONG_MAX) {
      count = ULONG_MAX;
    }
#elif SIZEOF_SIZE_T == SIZEOF_LONG_LONG
    if (count > ULLONG_MAX) {
      count = ULLONG_MAX;
    }
#endif

    if (sendfile(retr_fd, PR_NETIO_FD(session.d->outstrm), *offset, count,
        NULL, &len, 0) == -1) {

#elif defined(HAVE_MACOSX_SENDFILE)
    off_t orig_len = count;
    int res;

    /* Since Mac OSX uses the fourth argument as a value-return parameter,
     * success or failure, we need to put the result into len after the
     * call.
     */

    res = sendfile(retr_fd, PR_NETIO_FD(session.d->outstrm), *offset, &orig_len,
      NULL, 0);
    len = orig_len;

    if (res < 0) {
#elif defined(HAVE_AIX_SENDFILE)

    memset(&parms, 0, sizeof(parms));

    parms.file_descriptor = retr_fd;
    parms.file_offset = (uint64_t) *offset;
    parms.file_bytes = (int64_t) count;

    rc = send_file(&(PR_NETIO_FD(session.d->outstrm)), &(parms), (uint_t)0);
    len = (int) parms.bytes_sent;

    if (rc < -1 || rc == 1) {
#endif /* HAVE_AIX_SENDFILE */

      /* IMO, BSD's semantics are warped.  Apparently, since we have our
       * alarms tagged SA_INTERRUPT (allowing system calls to be
       * interrupted - primarily for select), BSD will interrupt a
       * sendfile operation as well, so we have to catch and handle this
       * case specially.  It should also be noted that the sendfile(2) man
       * page doesn't state any of this.
       *
       * HP/UX has the same semantics, however, EINTR is well documented
       * as a side effect in the sendfile(2) man page.  HP/UX, however,
       * is implemented horribly wrong.  If a signal would result in
       * -1 being returned and EINTR being set, what ACTUALLY happens is
       * that errno is cleared and the number of bytes written is returned.
       *
       * For obvious reasons, HP/UX sendfile is not supported yet.
       */
      if (errno == EINTR) {
        if (XFER_ABORTED) {
          session.xfer.total_bytes += len;
          session.total_bytes += len;
          session.total_bytes_out += len;
          session.total_raw_out += len;

          return -1;
        }

        pr_signals_handle();

        /* If we got everything in this transaction, we're done. */
        if (len >= count) {
          break;

        } else {
          count -= len;
        }

        *offset += len;

        if (timeout_stalled) {
          pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);
        }

        if (timeout_idle) {
          pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
        }

        session.xfer.total_bytes += len;
        session.total_bytes += len;
        session.total_bytes_out += len;
        session.total_raw_out += len;
        total += len;

        continue;
      }

      error = errno;
      (void) fcntl(PR_NETIO_FD(session.d->outstrm), F_SETFL, flags);
      errno = error;

      return -1;
    }

    break;
  }

  if (flags & O_NONBLOCK) {
    (void) fcntl(PR_NETIO_FD(session.d->outstrm), F_SETFL, flags);
  }

  if (timeout_stalled) {
    pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);
  }

  if (timeout_idle) {
    pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
  }

  session.xfer.total_bytes += len;
  session.total_bytes += len;
  session.total_bytes_out += len;
  session.total_raw_out += len;
  total += len;

  return total;
}
#else
pr_sendfile_t pr_data_sendfile(int retr_fd, off_t *offset, off_t count) {
  errno = ENOSYS;
  return -1;
}
#endif /* HAVE_SENDFILE */
