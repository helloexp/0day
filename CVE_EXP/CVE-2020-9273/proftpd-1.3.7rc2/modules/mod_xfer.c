/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
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
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* Data transfer module for ProFTPD */

#include "conf.h"
#include "privs.h"
#include "error.h"

#ifdef HAVE_SYS_SENDFILE_H
# include <sys/sendfile.h>
#endif

/* Minimum priority a process can have. */
#ifndef PRIO_MIN
# define PRIO_MIN	-20
#endif

/* Maximum priority a process can have.  */
#ifndef PRIO_MAX
# define PRIO_MAX	20
#endif

extern module auth_module;
extern pid_t mpid;

/* Variables for this module */
static pr_fh_t *retr_fh = NULL;
static pr_fh_t *stor_fh = NULL;
static pr_fh_t *displayfilexfer_fh = NULL;

static unsigned char have_rfc2228_data = FALSE;
static unsigned char have_type = FALSE;
static unsigned char have_zmode = FALSE;
static unsigned char use_sendfile = TRUE;
static off_t use_sendfile_len = 0;
static float use_sendfile_pct = -1.0;

static int xfer_check_limit(cmd_rec *);

/* TransferOptions */
#define PR_XFER_OPT_HANDLE_ALLO		0x0001
#define PR_XFER_OPT_IGNORE_ASCII	0x0002
static unsigned long xfer_opts = PR_XFER_OPT_HANDLE_ALLO;

static void xfer_exit_ev(const void *, void *);
static void xfer_sigusr2_ev(const void *, void *);
static void xfer_timeout_session_ev(const void *, void *);
static void xfer_timeout_stalled_ev(const void *, void *);
static int xfer_sess_init(void);

/* Used for MaxTransfersPerHost and TransferRate */
static int xfer_parse_cmdlist(const char *, config_rec *, char *);

module xfer_module;

static int xfer_logged_sendfile_decline_msg = FALSE;

static const char *trace_channel = "xfer";

static off_t find_max_nbytes(char *directive) {
  config_rec *c = NULL;
  unsigned int ctxt_precedence = 0;
  unsigned char have_user_limit, have_group_limit, have_class_limit,
    have_all_limit;
  off_t max_nbytes = 0UL;

  have_user_limit = have_group_limit = have_class_limit =
    have_all_limit = FALSE;

  c = find_config(CURRENT_CONF, CONF_PARAM, directive, FALSE);
  while (c) {

    /* This check is for more than three arguments: one argument is the
     * classifier (i.e. "user", "group", or "class"), one argument is
     * the precedence, one is the number of bytes; the remaining arguments
     * are the individual items in the configured expression.
     */

    if (c->argc > 3) {
      if (strncmp(c->argv[2], "user", 5) == 0) {

        if (pr_expr_eval_user_or((char **) &c->argv[3]) == TRUE) {
          if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

            /* Set the context precedence */
            ctxt_precedence = *((unsigned int *) c->argv[1]);

            max_nbytes = *((off_t *) c->argv[0]);

            have_group_limit = have_class_limit = have_all_limit = FALSE;
            have_user_limit = TRUE;
          }
        }

      } else if (strncmp(c->argv[2], "group", 6) == 0) {

        if (pr_expr_eval_group_or((char **) &c->argv[3]) == TRUE) {
          if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

            /* Set the context precedence */
            ctxt_precedence = *((unsigned int *) c->argv[1]);

            max_nbytes = *((off_t *) c->argv[0]);

            have_user_limit = have_class_limit = have_all_limit = FALSE;
            have_group_limit = TRUE;
          }
        }

      } else if (strncmp(c->argv[2], "class", 6) == 0) {

        if (pr_expr_eval_class_or((char **) &c->argv[3]) == TRUE) {
          if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

            /* Set the context precedence */
            ctxt_precedence = *((unsigned int *) c->argv[1]);

            max_nbytes = *((off_t *) c->argv[0]);

            have_user_limit = have_group_limit = have_all_limit = FALSE;
            have_class_limit = TRUE;
          }
        }
      }

    } else {

      if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

        /* Set the context precedence. */
        ctxt_precedence = *((unsigned int *) c->argv[1]);

        max_nbytes = *((off_t *) c->argv[0]);

        have_user_limit = have_group_limit = have_class_limit = FALSE;
        have_all_limit = TRUE;
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, directive, FALSE);
  }

  /* Print out some nice debugging information. */
  if (max_nbytes > 0 &&
      (have_user_limit || have_group_limit ||
       have_class_limit || have_all_limit)) {
    pr_log_debug(DEBUG5, "%s (%" PR_LU " bytes) in effect for %s",
      directive, (pr_off_t) max_nbytes,
      have_user_limit ? "user " : have_group_limit ? "group " :
      have_class_limit ? "class " : "all");
  }

  return max_nbytes;
}

static void _log_transfer(char direction, char abort_flag) {
  struct timeval end_time;
  char *fullpath = NULL;

  memset(&end_time, '\0', sizeof(end_time));

  if (session.xfer.start_time.tv_sec != 0) {
    gettimeofday(&end_time, NULL);
    end_time.tv_sec -= session.xfer.start_time.tv_sec;

    if (end_time.tv_usec >= session.xfer.start_time.tv_usec) {
      end_time.tv_usec -= session.xfer.start_time.tv_usec;

    } else {
      end_time.tv_usec = 1000000L - (session.xfer.start_time.tv_usec -
        end_time.tv_usec);
      end_time.tv_sec--;
    }
  }

  fullpath = dir_abs_path(session.xfer.p, session.xfer.path, TRUE);

  if ((session.sf_flags & SF_ANON) != 0) {
    xferlog_write(end_time.tv_sec, pr_netaddr_get_sess_remote_name(),
      session.xfer.total_bytes, fullpath,
      (session.sf_flags & SF_ASCII ? 'a' : 'b'), direction,
      'a', session.anon_user, abort_flag, "_");

  } else {
    xferlog_write(end_time.tv_sec, pr_netaddr_get_sess_remote_name(),
      session.xfer.total_bytes, fullpath,
      (session.sf_flags & SF_ASCII ? 'a' : 'b'), direction,
      'r', session.user, abort_flag, "_");
  }

  pr_log_debug(DEBUG1, "Transfer %s %" PR_LU " bytes in %ld.%02lu seconds",
    abort_flag == 'c' ? "completed:" : "aborted after",
    (pr_off_t) session.xfer.total_bytes, (long) end_time.tv_sec,
    (unsigned long)(end_time.tv_usec / 10000));
}

/* Code borrowed from src/dirtree.c's get_word() -- modified to separate
 * words on commas as well as spaces.
 */
static char *get_cmd_from_list(char **list) {
  char *res = NULL, *dst = NULL;
  unsigned char quote_mode = FALSE;

  while (**list && PR_ISSPACE(**list)) {
    (*list)++;
  }

  if (!**list)
    return NULL;

  res = dst = *list;

  if (**list == '\"') {
    quote_mode = TRUE;
    (*list)++;
  }

  while (**list && **list != ',' &&
      (quote_mode ? (**list != '\"') : (!PR_ISSPACE(**list)))) {

    if (**list == '\\' && quote_mode) {

      /* escaped char */
      if (*((*list) + 1))
        *dst = *(++(*list));
    }

    *dst++ = **list;
    ++(*list);
  }

  if (**list)
    (*list)++;

  *dst = '\0';

  return res;
}

static int xfer_check_limit(cmd_rec *cmd) {
  config_rec *c = NULL;
  const char *client_addr = pr_netaddr_get_ipstr(session.c->remote_addr);
  char server_addr[128];

  memset(server_addr, '\0', sizeof(server_addr));
  pr_snprintf(server_addr, sizeof(server_addr)-1, "%s:%d",
    pr_netaddr_get_ipstr(main_server->addr), main_server->ServerPort);
  server_addr[sizeof(server_addr)-1] = '\0';

  c = find_config(CURRENT_CONF, CONF_PARAM, "MaxTransfersPerHost", FALSE);
  while (c) {
    char *xfer_cmd = NULL, **cmdlist = (char **) c->argv[0];
    unsigned char matched_cmd = FALSE;
    unsigned int curr = 0, max = 0;
    pr_scoreboard_entry_t *score = NULL;

    pr_signals_handle();

    /* Does this MaxTransfersPerHost apply to the current command?  Note: this
     * could be made more efficient by using bitmasks rather than string
     * comparisons.
     */
    for (xfer_cmd = *cmdlist; xfer_cmd; xfer_cmd = *(cmdlist++)) {
      if (strcasecmp(xfer_cmd, cmd->argv[0]) == 0) {
        matched_cmd = TRUE;
        break;
      }
    }

    if (!matched_cmd) {
      c = find_config_next(c, c->next, CONF_PARAM, "MaxTransfersPerHost",
        FALSE);
      continue;
    }

    max = *((unsigned int *) c->argv[1]);

    /* Count how many times the current IP address is logged in, AND how
     * many of those other logins are currently using this command.
     */

    (void) pr_rewind_scoreboard();
    while ((score = pr_scoreboard_entry_read()) != NULL) {
      pr_signals_handle();

      /* Scoreboard entry must match local server address and remote client
       * address to be counted.
       */
      if (strcmp(score->sce_server_addr, server_addr) != 0)
        continue;

      if (strcmp(score->sce_client_addr, client_addr) != 0)
        continue;

      if (strcmp(score->sce_cmd, xfer_cmd) == 0)
        curr++;
    }

    pr_restore_scoreboard();

    if (curr >= max) {
      char maxn[20];

      char *maxstr = "Sorry, the maximum number of data transfers (%m) from "
        "your host are currently being used.";

      if (c->argv[2] != NULL)
        maxstr = c->argv[2];

      pr_event_generate("mod_xfer.max-transfers-per-host", session.c);

      memset(maxn, '\0', sizeof(maxn));
      pr_snprintf(maxn, sizeof(maxn)-1, "%u", max);
      pr_response_send(R_451, "%s", sreplace(cmd->tmp_pool, maxstr, "%m",
        maxn, NULL));
      pr_log_debug(DEBUG4, "MaxTransfersPerHost %u exceeded for %s for "
        "client '%s'", max, xfer_cmd, client_addr);

      return -1;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "MaxTransfersPerHost", FALSE);
  }

  c = find_config(CURRENT_CONF, CONF_PARAM, "MaxTransfersPerUser", FALSE);
  while (c) {
    char *xfer_cmd = NULL, **cmdlist = (char **) c->argv[0];
    unsigned char matched_cmd = FALSE;
    unsigned int curr = 0, max = 0;
    pr_scoreboard_entry_t *score = NULL;

    pr_signals_handle();

    /* Does this MaxTransfersPerUser apply to the current command?  Note: this
     * could be made more efficient by using bitmasks rather than string
     * comparisons.
     */
    for (xfer_cmd = *cmdlist; xfer_cmd; xfer_cmd = *(cmdlist++)) {
      if (strcasecmp(xfer_cmd, cmd->argv[0]) == 0) {
        matched_cmd = TRUE;
        break;
      }
    }

    if (!matched_cmd) {
      c = find_config_next(c, c->next, CONF_PARAM, "MaxTransfersPerUser",
        FALSE);
      continue;
    }

    max = *((unsigned int *) c->argv[1]);

    /* Count how many times the current user is logged in, AND how many of
     * those other logins are currently using this command.
     */

    (void) pr_rewind_scoreboard();
    while ((score = pr_scoreboard_entry_read()) != NULL) {
      pr_signals_handle();

      if (strcmp(score->sce_server_addr, server_addr) != 0)
        continue;

      if (strcmp(score->sce_user, session.user) != 0)
        continue;

      if (strcmp(score->sce_cmd, xfer_cmd) == 0)
        curr++;
    }

    pr_restore_scoreboard();

    if (curr >= max) {
      char maxn[20];

      char *maxstr = "Sorry, the maximum number of data transfers (%m) from "
        "this user are currently being used.";

      if (c->argv[2] != NULL)
        maxstr = c->argv[2];

      pr_event_generate("mod_xfer.max-transfers-per-user", session.user);

      memset(maxn, '\0', sizeof(maxn));
      pr_snprintf(maxn, sizeof(maxn)-1, "%u", max);
      pr_response_send(R_451, "%s", sreplace(cmd->tmp_pool, maxstr, "%m",
        maxn, NULL));
      pr_log_debug(DEBUG4, "MaxTransfersPerUser %u exceeded for %s for "
        "user '%s'", max, xfer_cmd, session.user);

      return -1;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "MaxTransfersPerUser", FALSE);
  }

  return 0;
}

static void xfer_displayfile(void) {

  if (displayfilexfer_fh) {
    if (pr_display_fh(displayfilexfer_fh, session.vwd, R_226, 0) < 0) {
      pr_log_debug(DEBUG6, "unable to display DisplayFileTransfer "
        "file '%s': %s", displayfilexfer_fh->fh_path, strerror(errno));
    }

    /* Rewind the filehandle, so that it can be used again. */
    if (pr_fsio_lseek(displayfilexfer_fh, 0, SEEK_SET) < 0) {
      pr_log_debug(DEBUG6, "error rewinding DisplayFileTransfer "
        "file '%s': %s", displayfilexfer_fh->fh_path, strerror(errno));
    }

  } else {
    char *displayfilexfer;

    displayfilexfer = get_param_ptr(main_server->conf, "DisplayFileTransfer",
      FALSE);
    if (displayfilexfer) {
      if (pr_display_file(displayfilexfer, session.vwd, R_226, 0) < 0) {
        pr_log_debug(DEBUG6, "unable to display DisplayFileTransfer "
          "file '%s': %s", displayfilexfer, strerror(errno));
      }
    }
  }
}

static int xfer_parse_cmdlist(const char *name, config_rec *c,
    char *cmdlist) {
  char *cmd = NULL;
  array_header *cmds = NULL;

  /* Allocate an array_header. */
  cmds = make_array(c->pool, 0, sizeof(char *));

  /* Add each command to the array, checking for invalid commands or
   * duplicates.
   */
  while ((cmd = get_cmd_from_list(&cmdlist)) != NULL) {

    /* Is the given command a valid one for this directive? */
    if (strcasecmp(cmd, C_APPE) != 0 &&
        strcasecmp(cmd, C_RETR) != 0 &&
        strcasecmp(cmd, C_STOR) != 0 &&
        strcasecmp(cmd, C_STOU) != 0) {
      pr_log_debug(DEBUG0, "invalid %s command: %s", name, cmd);
      errno = EINVAL;
      return -1;
    }

    *((char **) push_array(cmds)) = pstrdup(c->pool, cmd);
  }

  /* Terminate the array with a NULL. */
  *((char **) push_array(cmds)) = NULL;

  /* Store the array of commands in the config_rec. */
  c->argv[0] = (void *) cmds->elts;

  return 0;
}

static int transmit_normal(pool *p, char *buf, size_t bufsz) {
  int xerrno;
  long nread;
  size_t read_len;
  pr_error_t *err = NULL;

  read_len = bufsz;
  if (session.range_len > 0) {
    if (((off_t) read_len) > session.range_len) {
      read_len = session.range_len;
    }
  }

  nread = pr_fsio_read_with_error(p, retr_fh, buf, read_len, &err);
  xerrno = errno;

  if (nread < 0) {
    pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 4);
    pr_error_set_why(err, pstrcat(p, "normal download of '", retr_fh->fh_path,
      "'", NULL));

    (void) pr_trace_msg("fileperms", 1, "RETR, user '%s' (UID %s, GID %s): "
      "error reading from '%s': %s", session.user,
      pr_uid2str(p, session.uid), pr_gid2str(p, session.gid),
      retr_fh->fh_path, strerror(xerrno));

    if (err != NULL) {
      pr_log_debug(DEBUG9, "%s", pr_error_strerror(err, 0));
      pr_error_destroy(err);
      err = NULL;
    }

    errno = xerrno;
    return 0;
  }

  if (nread == 0) {
    return 0;
  }

  return pr_data_xfer(buf, nread);
}

#ifdef HAVE_SENDFILE
static int transmit_sendfile(off_t data_len, off_t *data_offset,
    pr_sendfile_t *sent_len) {
  off_t send_len;

  /* We don't use sendfile() if:
   * - We're using bandwidth throttling.
   * - We're transmitting an ASCII file.
   * - We're using RFC2228 data channel protection
   * - We're using MODE Z compression
   * - There's no data left to transmit.
   * - UseSendfile is set to off.
   */
  if (pr_throttle_have_rate() ||
     !(session.xfer.file_size - data_len) ||
     (session.sf_flags & (SF_ASCII|SF_ASCII_OVERRIDE)) ||
     have_rfc2228_data || have_zmode ||
     !use_sendfile) {

    if (!xfer_logged_sendfile_decline_msg) {
      if (!use_sendfile) {
        pr_log_debug(DEBUG10, "declining use of sendfile due to UseSendfile "
          "configuration setting");

      } else if (pr_throttle_have_rate()) {
        pr_log_debug(DEBUG10, "declining use of sendfile due to TransferRate "
          "restrictions");
    
      } else if (session.sf_flags & (SF_ASCII|SF_ASCII_OVERRIDE)) {
        pr_log_debug(DEBUG10, "declining use of sendfile for ASCII data");

      } else if (have_rfc2228_data) {
        pr_log_debug(DEBUG10, "declining use of sendfile due to RFC2228 data "
          "channel protections");

      } else if (have_zmode) {
        pr_log_debug(DEBUG10, "declining use of sendfile due to MODE Z "
          "restrictions");

      } else {
        pr_log_debug(DEBUG10, "declining use of sendfile due to lack of data "
          "to transmit");
      }

      xfer_logged_sendfile_decline_msg = TRUE;
    }

    return 0;
  }

  pr_log_debug(DEBUG10, "using sendfile capability for transmitting data");

  /* Determine how many bytes to send using sendfile(2).  By default,
   * we want to send all of the remaining bytes.
   *
   * However, the admin may have configured either a length in bytes, or
   * a percentage, using the UseSendfile directive.  We will send the smaller
   * of the remaining size, or the length/percentage.
   */

  if (session.range_len > 0) {
    send_len = session.range_len;

  } else {
    send_len = session.xfer.file_size - data_len;
  }

  if (use_sendfile_len > 0 &&
      send_len > use_sendfile_len) {
    pr_log_debug(DEBUG10, "using sendfile with configured UseSendfile length "
      "(%" PR_LU " bytes)", (pr_off_t) use_sendfile_len);
    send_len = use_sendfile_len;

  } else if (use_sendfile_pct > 0.0) {
    off_t pct_len;

    pct_len = (off_t) (session.xfer.file_size * use_sendfile_pct);
    if (send_len > pct_len) {
      pr_log_debug(DEBUG10, "using sendfile with configured UseSendfile "
        "percentage %0.0f%% (%" PR_LU " bytes)", use_sendfile_pct * 100.0,
        (pr_off_t) pct_len);
      send_len = pct_len;
    }
  }

 retry:
  *sent_len = pr_data_sendfile(PR_FH_FD(retr_fh), data_offset, send_len);

  if (*sent_len == -1) {
    int xerrno = errno;

    switch (xerrno) {
      case EAGAIN:
      case EINTR:
        if (XFER_ABORTED) {
          pr_log_pri(PR_LOG_NOTICE, "sendfile transmission aborted: %s",
            strerror(xerrno));
          errno = xerrno;
          return -1;
        }

        /* Interrupted call, or the other side wasn't ready yet. */
        pr_signals_handle();
        goto retry;

      case EPIPE:
      case ECONNRESET:
      case ETIMEDOUT:
      case EHOSTUNREACH:
        /* Other side broke the connection. */
        break;

#ifdef ENOSYS
      case ENOSYS:
#endif /* ENOSYS */

#ifdef EOVERFLOW
      case EOVERFLOW:
#endif /* EOVERFLOW */

      case EINVAL:
        /* No sendfile support, apparently.  Try it the normal way. */
        return 0;
        break;

    default:
      pr_log_pri(PR_LOG_WARNING, "error using sendfile(): [%d] %s", xerrno,
        strerror(xerrno));
      errno = xerrno;
      return -1;
    }
  }

  return 1;
}
#endif /* HAVE_SENDFILE */

/* Note: the data_len and data_offset arguments are only for the benefit of
 * transmit_sendfile(), if sendfile support is enabled.  The transmit_normal()
 * function only needs/uses buf and bufsz.
 */
static long transmit_data(pool *p, off_t data_len, off_t *data_offset,
    char *buf, size_t bufsz) {
  long res;
  int xerrno = 0;

#ifdef HAVE_SENDFILE
  pr_sendfile_t sent_len;
  int ret;
#endif /* HAVE_SENDFILE */

  if (pr_inet_set_proto_cork(PR_NETIO_FD(session.d->outstrm), 1) < 0) {
    pr_log_pri(PR_LOG_NOTICE, "error corking socket fd %d: %s",
      PR_NETIO_FD(session.d->outstrm), strerror(errno));
  }

#ifdef HAVE_SENDFILE
  ret = transmit_sendfile(data_len, data_offset, &sent_len);
  if (ret > 0) {
    /* sendfile() was used, so return the value of sent_len. */
    res = (long) sent_len;

  } else if (ret == 0) {
    /* sendfile() should not be used for some reason, fallback to using
     * normal data transmission methods.
     */
    res = transmit_normal(p, buf, bufsz);
    xerrno = errno;

  } else {
    /* There was an error with sendfile(); do NOT attempt to re-send the
     * data using normal data transmission methods, unless the cause
     * of the error is one of an accepted few cases.
     */
# ifdef EOVERFLOW
    pr_log_debug(DEBUG10, "use of sendfile(2) failed due to %s (%d), "
      "falling back to normal data transmission", strerror(errno),
      errno);
    res = transmit_normal(p, buf, bufsz);
    xerrno = errno;

# else
    if (session.d != NULL) {
      (void) pr_inet_set_proto_cork(PR_NETIO_FD(session.d->outstrm), 0);
    }

    errno = EIO;
    res = -1;
# endif
  }

#else
  res = transmit_normal(p, buf, bufsz);
  xerrno = errno;
#endif /* HAVE_SENDFILE */

  if (session.d != NULL) {
    /* The session.d struct can become null after transmit_normal() if the
     * client aborts the transfer, thus we need to check for this.
     */
    if (pr_inet_set_proto_cork(PR_NETIO_FD(session.d->outstrm), 0) < 0) {
      if (errno != EINVAL) {
        pr_log_pri(PR_LOG_NOTICE, "error uncorking socket fd %d: %s",
          PR_NETIO_FD(session.d->outstrm), strerror(errno));
      }
    }
  }

  errno = xerrno;
  return res;
}

static void stor_chown(pool *p) {
  struct stat st;
  const char *xfer_path = NULL;

  if (session.xfer.xfer_type == STOR_HIDDEN) {
    xfer_path = session.xfer.path_hidden;

  } else {
    xfer_path = session.xfer.path;
  }

  /* session.fsgid defaults to -1, so chown(2) won't chgrp unless specifically
   * requested via GroupOwner.
   */
  if (session.fsuid != (uid_t) -1 &&
      xfer_path != NULL) {
    int res, xerrno = 0;
    pr_error_t *err = NULL;

    PRIVS_ROOT
    res = pr_fsio_lchown_with_error(p, xfer_path, session.fsuid, session.fsgid,
      &err);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res < 0) {
      pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 6);
      pr_error_set_why(err, pstrcat(p, "set UserOwner of '", xfer_path,
        "'", NULL));

      if (err != NULL) {
        pr_log_pri(PR_LOG_WARNING, "%s", pr_error_strerror(err, 0));
        pr_error_destroy(err);
        err = NULL;

      } else {
        pr_log_pri(PR_LOG_WARNING, "lchown(%s) as root failed: %s", xfer_path,
          strerror(xerrno));
      }

    } else {
      if (session.fsgid != (gid_t) -1) {
        pr_log_debug(DEBUG2, "root lchown(%s) to UID %s, GID %s successful",
          xfer_path, pr_uid2str(p, session.fsuid),
          pr_gid2str(p, session.fsgid));

      } else {
        pr_log_debug(DEBUG2, "root lchown(%s) to UID %s successful", xfer_path,
          pr_uid2str(p, session.fsuid));
      }

      pr_fs_clear_cache2(xfer_path);
      if (pr_fsio_stat(xfer_path, &st) < 0) {
        pr_log_debug(DEBUG0,
          "'%s' stat(2) error during root chmod: %s", xfer_path,
          strerror(errno));
      }

      /* The chmod happens after the chown because chown will remove
       * the S{U,G}ID bits on some files (namely, directories); the subsequent
       * chmod is used to restore those dropped bits.  This makes it
       * necessary to use root privs when doing the chmod as well (at least
       * in the case of chown'ing the file via root privs) in order to ensure
       * that the mode can be set (a file might be being "given away", and if
       * root privs aren't used, the chmod() will fail because the old owner/
       * session user doesn't have the necessary privileges to do so).
       */
      xerrno = 0;
      PRIVS_ROOT
      res = pr_fsio_chmod_with_error(p, xfer_path, st.st_mode, &err);
      xerrno = errno;
      PRIVS_RELINQUISH

      if (res < 0) {
        pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 5);
        pr_error_set_why(err, pstrcat(p, "restore SUID/SGID on '", xfer_path,
          "'", NULL));

        if (err != NULL) {
          pr_log_debug(DEBUG0, "%s", pr_error_strerror(err, 0));
          pr_error_destroy(err);
          err = NULL;

        } else {
          pr_log_debug(DEBUG0, "root chmod(%s) to %04o failed: %s", xfer_path,
            (unsigned int) st.st_mode, strerror(xerrno));
        }

      } else {
        pr_log_debug(DEBUG2, "root chmod(%s) to %04o successful", xfer_path,
          (unsigned int) st.st_mode);
      }
    }

  } else if (session.fsgid != (gid_t) -1 &&
             xfer_path != NULL) {
    register unsigned int i;
    int res, use_root_privs = TRUE, xerrno = 0;
    pr_error_t *err = NULL;

    /* Check if session.fsgid is in session.gids.  If not, use root privs. */
    for (i = 0; i < session.gids->nelts; i++) {
      gid_t *group_ids = session.gids->elts;

      if (group_ids[i] == session.fsgid) {
        use_root_privs = FALSE;
        break;
      }
    }

    if (use_root_privs) {
      PRIVS_ROOT
    }

    res = pr_fsio_lchown_with_error(p, xfer_path, (uid_t) -1, session.fsgid,
      &err);
    xerrno = errno;

    if (use_root_privs) {
      PRIVS_RELINQUISH
    }

    if (res < 0) {
      pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 9);
      pr_error_set_why(err, pstrcat(p, "set GroupOwner of '", xfer_path, "'",
        NULL));

      if (err != NULL) {
        pr_log_pri(PR_LOG_WARNING, "%s", pr_error_strerror(err, 0));
        pr_error_destroy(err);
        err = NULL;

      } else {
        pr_log_pri(PR_LOG_WARNING, "%slchown(%s) failed: %s",
          use_root_privs ? "root " : "", xfer_path, strerror(xerrno));
      }

    } else {
      pr_log_debug(DEBUG2, "%slchown(%s) to GID %s successful",
        use_root_privs ? "root " : "", xfer_path,
        pr_gid2str(p, session.fsgid));

      pr_fs_clear_cache2(xfer_path);
      if (pr_fsio_stat(xfer_path, &st) < 0) {
        pr_log_debug(DEBUG0,
          "'%s' stat(2) error during %schmod: %s", xfer_path,
          use_root_privs ? "root " : "", strerror(errno));
      }

      if (use_root_privs) {
        PRIVS_ROOT
      }

      res = pr_fsio_chmod_with_error(p, xfer_path, st.st_mode, &err);
      xerrno = errno;

      if (use_root_privs) {
        PRIVS_RELINQUISH
      }

      if (res < 0) {
        pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 8);
        pr_error_set_why(err, pstrcat(p, "restore SUID/SGID of '", xfer_path,
          "'", NULL));

        if (err != NULL) {
          pr_log_debug(DEBUG0, "%s", pr_error_strerror(err, 0));
          pr_error_destroy(err);
          err = NULL;

        } else {
          pr_log_debug(DEBUG0, "%schmod(%s) to %04o failed: %s",
            use_root_privs ? "root " : "", xfer_path, (unsigned int) st.st_mode,
            strerror(xerrno));
        }
      }
    }
  }
}

static void retr_abort(pool *p) {
  /* Isn't necessary to send anything here, just cleanup */

  if (retr_fh) {
    pr_fsio_close(retr_fh);
    retr_fh = NULL;
  }

  _log_transfer('o', 'i');
}

static void retr_complete(pool *p) {
  pr_fsio_close(retr_fh);
  retr_fh = NULL;
}

static void stor_abort(pool *p) {
  int res, xerrno = 0;
  pool *tmp_pool;
  pr_error_t *err = NULL;
  unsigned char *delete_stores = NULL;

  tmp_pool = make_sub_pool(p);

  if (stor_fh != NULL) {
    res = pr_fsio_close_with_error(tmp_pool, stor_fh, &err);
    xerrno = errno;

    if (res < 0) {
      pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 4);
      pr_error_set_why(err, pstrcat(tmp_pool, "close file '", stor_fh->fh_path,
        "'", NULL));

      if (err != NULL) {
        pr_log_pri(PR_LOG_NOTICE, "%s", pr_error_strerror(err, 0));
        pr_error_destroy(err);
        err = NULL;

      } else {
        pr_log_pri(PR_LOG_NOTICE, "notice: error closing '%s': %s",
         stor_fh->fh_path, strerror(xerrno));
      }
 
      errno = xerrno;
    }

    stor_fh = NULL;
  }

  delete_stores = get_param_ptr(CURRENT_CONF, "DeleteAbortedStores", FALSE);

  if (session.xfer.xfer_type == STOR_HIDDEN) {
    if (delete_stores == NULL ||
        *delete_stores == TRUE) {
      /* If a hidden store was aborted, remove only hidden file, not real
       * one.
       */
      if (session.xfer.path_hidden) {
        pr_log_debug(DEBUG5, "removing aborted HiddenStores file '%s'",
          session.xfer.path_hidden);

        res = pr_fsio_unlink_with_error(tmp_pool, session.xfer.path_hidden,
          &err);
        xerrno = errno;

        if (res < 0) {
          pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 5);
          pr_error_set_why(err, pstrcat(tmp_pool, "delete HiddenStores file '",
            session.xfer.path_hidden, "'", NULL));

          if (xerrno != ENOENT) {
            if (err != NULL) {
              pr_log_debug(DEBUG0, "%s", pr_error_strerror(err, 0));

            } else {
              pr_log_debug(DEBUG0, "error deleting HiddenStores file '%s': %s",
                session.xfer.path_hidden, strerror(xerrno));
            }
          }

          pr_error_destroy(err);
          err = NULL;
        } 
      }
    }
  }

  if (session.xfer.path != NULL) {
    if (delete_stores != NULL &&
        *delete_stores == TRUE) {
      pr_log_debug(DEBUG5, "removing aborted file '%s'", session.xfer.path);

      res = pr_fsio_unlink_with_error(tmp_pool, session.xfer.path, &err);
      xerrno = errno;

      if (res < 0) {
        pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 4);
        pr_error_set_why(err, pstrcat(tmp_pool, "delete aborted file '",
          session.xfer.path, "'", NULL));

        if (err != NULL) {
          pr_log_debug(DEBUG0, "%s", pr_error_strerror(err, 0));
          pr_error_destroy(err);
          err = NULL;

        } else {
          pr_log_debug(DEBUG0, "error deleting aborted file '%s': %s",
            session.xfer.path, strerror(xerrno));
        }
      }
    }
  }

  destroy_pool(tmp_pool);
  _log_transfer('i', 'i');
}

static int stor_complete(pool *p) {
  int res, xerrno = 0;
  pool *tmp_pool;
  pr_error_t *err = NULL;

  tmp_pool = make_sub_pool(p);
  res = pr_fsio_close_with_error(tmp_pool, stor_fh, &err);
  xerrno = errno;

  if (res < 0) {
    pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 4);
    pr_error_set_why(err, pstrcat(tmp_pool, "close uploaded file '",
      stor_fh->fh_path, "'", NULL));

    if (err != NULL) {
      pr_log_pri(PR_LOG_NOTICE, "%s", pr_error_strerror(err, 0));
      pr_error_destroy(err);
      err = NULL;

    } else {
      pr_log_pri(PR_LOG_NOTICE, "notice: error closing '%s': %s",
        stor_fh->fh_path, strerror(xerrno));
    }

    /* We will unlink failed writes, but only if it's a HiddenStores file.
     * Other files will need to be explicitly deleted/removed by the client.
     */
    if (session.xfer.xfer_type == STOR_HIDDEN) {
      if (session.xfer.path_hidden) {
        pr_log_debug(DEBUG5, "failed to close HiddenStores file '%s', removing",
          session.xfer.path_hidden);

        res = pr_fsio_unlink_with_error(tmp_pool, session.xfer.path_hidden,
          &err);
        xerrno = errno;

        if (res < 0) {
          pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 4);
          pr_error_set_why(err, pstrcat(tmp_pool, "close HiddenStores file '",
            session.xfer.path_hidden, "'", NULL));

          if (xerrno != ENOENT) {
            if (err != NULL) {
              pr_log_debug(DEBUG0, "%s", pr_error_strerror(err, 0));

            } else {
              pr_log_debug(DEBUG0, "error deleting HiddenStores file '%s': %s",
                session.xfer.path_hidden, strerror(xerrno));
            }
          }

          pr_error_destroy(err);
          err = NULL;
        } 
      }
    }

    errno = xerrno;
    res = -1;
  }

  destroy_pool(tmp_pool);
  stor_fh = NULL;
  return res;
}

static int get_hidden_store_path(cmd_rec *cmd, const char *path,
    const char *prefix, const char *suffix) {
  const char *c = NULL;
  char *hidden_path, *parent_dir = NULL;
  int dotcount = 0, found_slash = FALSE, basenamestart = 0, maxlen;

  /* We have to also figure out the temporary hidden file name for receiving
   * this transfer.  Length is +(N+M) due to prepended prefix and suffix.
   */

  /* Figure out where the basename starts */
  for (c = path; *c; ++c) {

    if (*c == '/') {
      found_slash = TRUE;
      basenamestart = dotcount = 0;

    } else if (*c == '.') {
      ++dotcount;

      /* Keep track of leading dots, ... is normal, . and .. are special.
       * So if we exceed ".." it becomes a normal file. Retroactively consider
       * this the possible start of the basename.
       */
      if ((dotcount > 2) &&
          !basenamestart) {
        basenamestart = ((unsigned long) c - (unsigned long) path) - dotcount;
      }

    } else {

      /* We found a nonslash, nondot character; if this is the first time
       * we found one since the last slash, remember this as the possible
       * start of the basename.
       */
      if (!basenamestart) {
        basenamestart = ((unsigned long) c - (unsigned long) path) - dotcount;
      }
    }
  }

  if (!basenamestart) {
    session.xfer.xfer_type = STOR_DEFAULT;

    pr_log_debug(DEBUG6, "could not determine HiddenStores path for '%s'",
      path);

    /* This probably shouldn't happen */
    pr_response_add_err(R_451, _("%s: Bad file name"), path);
    errno = EINVAL;
    return -1;
  }

  /* Add N+M for the prefix and suffix characters, plus one for a terminating
   * NUL.
   */
  maxlen = strlen(prefix) + strlen(path) + strlen(suffix) + 1;

  if (maxlen > PR_TUNABLE_PATH_MAX) {
    session.xfer.xfer_type = STOR_DEFAULT;

    pr_log_pri(PR_LOG_NOTICE, "making path '%s' a hidden path exceeds max "
      "path length (%u)", path, PR_TUNABLE_PATH_MAX);

    /* This probably shouldn't happen */
    pr_response_add_err(R_451, _("%s: File name too long"), path);
    errno = EPERM;
    return -1;
  }

  if (pr_table_add(cmd->notes, "mod_xfer.store-hidden-path", NULL, 0) < 0) {
    if (errno != EEXIST) {
      pr_log_pri(PR_LOG_NOTICE,
        "notice: error adding 'mod_xfer.store-hidden-path': %s",
        strerror(errno));
    }
  }

  if (found_slash == FALSE) {

    /* Simple local file name */
    hidden_path = pstrcat(cmd->tmp_pool, prefix, path, suffix, NULL);

    pr_log_debug(DEBUG2, "HiddenStore: local path, will rename %s to %s",
      hidden_path, path);

  } else {

    /* Complex relative path or absolute path */
    hidden_path = pstrndup(cmd->pool, path, maxlen);
    hidden_path[basenamestart] = '\0';

    hidden_path = pstrcat(cmd->pool, hidden_path, prefix,
      path + basenamestart, suffix, NULL);

    pr_log_debug(DEBUG2, "HiddenStore: complex path, will rename %s to %s",
      hidden_path, path);
  }

  pr_fs_clear_cache2(hidden_path);
  if (file_mode2(cmd->tmp_pool, hidden_path)) {
    session.xfer.xfer_type = STOR_DEFAULT;

    pr_log_debug(DEBUG3, "HiddenStore path '%s' already exists",
      hidden_path);

    pr_response_add_err(R_550, _("%s: Temporary hidden file %s already exists"),
      cmd->arg, hidden_path);
    errno = EEXIST;
    return -1;
  }

  if (pr_table_set(cmd->notes, "mod_xfer.store-hidden-path",
      hidden_path, 0) < 0) {
    pr_log_pri(PR_LOG_NOTICE,
      "notice: error setting 'mod_xfer.store-hidden-path': %s",
      strerror(errno));
  }

  /* Only use the O_EXCL open(2) flag if the path is NOT on an NFS-mounted
   * filesystem (see Bug#3874).
   */
  if (found_slash == FALSE) {
    parent_dir = "./";

  } else {
    parent_dir = pstrndup(cmd->tmp_pool, path, basenamestart);
  }

  if (pr_fs_is_nfs(parent_dir) == TRUE) {
    if (pr_table_add(cmd->notes, "mod_xfer.store-hidden-nfs",
        pstrdup(cmd->pool, "1"), 0) < 0) {
      pr_log_pri(PR_LOG_NOTICE,
        "notice: error adding 'mod_xfer.store-hidden-nfs' note: %s",
        strerror(errno));
    }
  }

  session.xfer.xfer_type = STOR_HIDDEN;
  return 0;
}

MODRET xfer_post_prot(cmd_rec *cmd) {
  CHECK_CMD_ARGS(cmd, 2);

  if (strncmp(cmd->argv[1], "C", 2) != 0) {
    have_rfc2228_data = TRUE;

  } else {
    have_rfc2228_data = FALSE;
  }

  return PR_DECLINED(cmd);
}

MODRET xfer_post_mode(cmd_rec *cmd) {
  CHECK_CMD_ARGS(cmd, 2);

  if (strncmp(cmd->argv[1], "Z", 2) == 0) {
    have_zmode = TRUE;

  } else {
    have_zmode = FALSE;
  }

  return PR_DECLINED(cmd);
}

/* This is a PRE_CMD handler that checks security, etc, and places the full
 * filename to receive in cmd->notes, under the key 'mod_xfer.store-path'.
 * Note that we CANNOT use cmd->tmp_pool for this, as tmp_pool only lasts for
 * the duration of this function.
 */
MODRET xfer_pre_stor(cmd_rec *cmd) {
  char *decoded_path, *path;
  mode_t fmode;
  unsigned char *allow_overwrite = NULL, *allow_restart = NULL;
  config_rec *c;
  int res;

  if (cmd->argc < 2) {
    pr_response_add_err(R_500, _("'%s' not understood"),
      pr_cmd_get_displayable_str(cmd, NULL));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  decoded_path = pr_fs_decode_path2(cmd->tmp_pool, cmd->arg,
    FSIO_DECODE_FL_TELL_ERRORS);
  if (decoded_path == NULL) {
    int xerrno = errno;

    pr_log_debug(DEBUG8, "'%s' failed to decode properly: %s", cmd->arg,
      strerror(xerrno));
    pr_response_add_err(R_550, _("%s: Illegal character sequence in filename"),
      cmd->arg);

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  pr_fs_clear_cache2(decoded_path);
  path = dir_best_path(cmd->tmp_pool, decoded_path);

  if (path == NULL ||
      !dir_check(cmd->tmp_pool, cmd, cmd->group, path, NULL)) {
    int xerrno = errno;

    pr_log_debug(DEBUG8, "%s %s denied by <Limit> configuration",
      (char *) cmd->argv[0], cmd->arg);
    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  res = pr_filter_allow_path(CURRENT_CONF, path);
  switch (res) {
    case 0:
      break;

    case PR_FILTER_ERR_FAILS_ALLOW_FILTER:
      pr_log_debug(DEBUG2, "'%s %s' denied by PathAllowFilter",
        (char *) cmd->argv[0], path);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);

    case PR_FILTER_ERR_FAILS_DENY_FILTER:
      pr_log_debug(DEBUG2, "'%s %s' denied by PathDenyFilter",
        (char *) cmd->argv[0], path);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);
  }

  if (xfer_check_limit(cmd) < 0) {
    pr_response_add_err(R_451, _("%s: Too many transfers"), cmd->arg);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  fmode = file_mode2(cmd->tmp_pool, path);

  allow_overwrite = get_param_ptr(CURRENT_CONF, "AllowOverwrite", FALSE);

  if (fmode && (session.xfer.xfer_type != STOR_APPEND) &&
      (!allow_overwrite || *allow_overwrite == FALSE)) {
    pr_log_debug(DEBUG6, "AllowOverwrite denied permission for %s", cmd->arg);
    pr_response_add_err(R_550, _("%s: Overwrite permission denied"), cmd->arg);

    pr_cmd_set_errno(cmd, EACCES);
    errno = EACCES;
    return PR_ERROR(cmd);
  }

  if (fmode &&
      !S_ISREG(fmode) &&
      !S_ISFIFO(fmode)) {

    /* Make an exception for the non-regular /dev/null file.  This will allow
     * network link testing by uploading as much data as necessary directly
     * to /dev/null.
     *
     * On Linux, allow another exception for /dev/full; this is useful for
     * tests which want to simulate running out-of-space scenarios.
     */
    if (strcasecmp(path, "/dev/null") != 0
#ifdef LINUX
        && strcasecmp(path, "/dev/full") != 0
#endif
       ) {
      pr_response_add_err(R_550, _("%s: Not a regular file"), cmd->arg);

      /* Deliberately use EISDIR for anything non-file (e.g. directories). */
      pr_cmd_set_errno(cmd, EISDIR);
      errno = EISDIR;
      return PR_ERROR(cmd);
    }
  }

  /* If restarting, check permissions on this directory, if
   * AllowStoreRestart is set, permit it
   */
  allow_restart = get_param_ptr(CURRENT_CONF, "AllowStoreRestart", FALSE);

  if (fmode &&
     ((session.restart_pos > 0 || session.range_len > 0) ||
      (session.xfer.xfer_type == STOR_APPEND)) &&
     (!allow_restart || *allow_restart == FALSE)) {

    pr_response_add_err(R_451, _("%s: Append/Restart not permitted, try again"),
      cmd->arg);
    session.restart_pos = 0L;
    session.xfer.xfer_type = STOR_DEFAULT;

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* Reject APPE preceded by RANG. */
  if (session.xfer.xfer_type == STOR_APPEND &&
      session.range_len > 0) {
    pr_response_add_err(R_550, _("APPE incompatible with RANG"));
    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* If the file exists, add a note indicating that it is being modified. */
  if (fmode) {
    /* Clear any existing key in the notes. */
    (void) pr_table_remove(cmd->notes, "mod_xfer.file-modified", NULL);

    if (pr_table_add(cmd->notes, "mod_xfer.file-modified",
        pstrdup(cmd->pool, "true"), 0) < 0) {
      if (errno != EEXIST) {
        pr_log_pri(PR_LOG_NOTICE,
          "notice: error adding 'mod_xfer.file-modified' note: %s",
          strerror(errno));
      }
    }
  }

  /* Otherwise everything is good */
  if (pr_table_add(cmd->notes, "mod_xfer.store-path",
      pstrdup(cmd->pool, path), 0) < 0) {
    if (errno != EEXIST) {
      pr_log_pri(PR_LOG_NOTICE,
        "notice: error adding 'mod_xfer.store-path': %s", strerror(errno));
    }
  }

  c = find_config(CURRENT_CONF, CONF_PARAM, "HiddenStores", FALSE);
  if (c != NULL &&
      *((int *) c->argv[0]) == TRUE) {
    const char *prefix, *suffix;

    /* If we're using HiddenStores, then RANG/REST won't work. */
    if (session.restart_pos > 0 ||
        session.range_len > 0) {
      int used_rest = TRUE;

      if (session.range_len > 0) {
        used_rest = FALSE;
      }

      pr_log_debug(DEBUG9, "HiddenStore in effect, refusing %s upload",
        used_rest ? "restarted" : "range");
      pr_response_add_err(R_501,
        _("%s not compatible with server configuration"),
        used_rest ? C_REST : C_RANG);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);
    }

    /* For Bug#3598, we rejected any APPE command when HiddenStores are in
     * effect (for good reasons).
     *
     * However, for Bug#4144, we're relaxing that policy.  Instead of rejecting
     * the APPE command, we accept that command, but we disable the HiddenStores
     * functionality.
     */
    if (session.xfer.xfer_type != STOR_APPEND) {
      prefix = c->argv[1];
      suffix = c->argv[2];

      /* Substitute the %P variable for the PID, if present. */
      if (strstr(prefix, "%P") != NULL) {
        char pid_buf[32];

        memset(pid_buf, '\0', sizeof(pid_buf));
        pr_snprintf(pid_buf, sizeof(pid_buf)-1, "%lu",
          (unsigned long) session.pid);
        prefix = sreplace(cmd->pool, prefix, "%P", pid_buf, NULL);
      }

      if (strstr(suffix, "%P") != NULL) {
        char pid_buf[32];

        memset(pid_buf, '\0', sizeof(pid_buf));
        pr_snprintf(pid_buf, sizeof(pid_buf)-1, "%lu",
          (unsigned long) session.pid);
        suffix = sreplace(cmd->pool, suffix, "%P", pid_buf, NULL);
      }

      if (get_hidden_store_path(cmd, path, prefix, suffix) < 0) {
        int xerrno = errno;

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return PR_ERROR(cmd);
      }

    } else {
      pr_log_debug(DEBUG9,
        "HiddenStores in effect for APPE, ignoring HiddenStores");
    }
  }

  return PR_HANDLED(cmd);
}

/* xfer_pre_stou() is a PRE_CMD handler that changes the uploaded filename
 * to a unique one, after making the requisite security and authorization
 * checks.
 */
MODRET xfer_pre_stou(cmd_rec *cmd) {
  config_rec *c = NULL;
  char *prefix = "ftp", *filename = NULL;
  int stou_fd;
  mode_t mode;
  unsigned char *allow_overwrite = NULL;

  session.xfer.xfer_type = STOR_DEFAULT;

  /* Some FTP clients are "broken" in that they will send a filename
   * along with STOU.  Technically this violates RFC959, but for now, just
   * ignore that filename.  Stupid client implementors.
   */

  if (cmd->argc > 2) {
    pr_response_add_err(R_500, _("'%s' not understood"),
      pr_cmd_get_displayable_str(cmd, NULL));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  if (xfer_check_limit(cmd) < 0) {
    pr_response_add_err(R_451, _("%s: Too many transfers"), cmd->arg);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* Watch for STOU preceded by REST, which makes no sense.  Similarly
   * for STOU preceded by RANG.
   */
  if (session.restart_pos > 0 ||
      session.range_len > 0) {

    if (session.restart_pos > 0) {
      pr_response_add_err(R_550, _("STOU incompatible with REST"));

    } else {
      pr_response_add_err(R_550, _("STOU incompatible with RANG"));
    }

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* Generate the filename to be stored, depending on the configured
   * unique filename prefix.
   */
  c = find_config(CURRENT_CONF, CONF_PARAM, "StoreUniquePrefix", FALSE);
  if (c != NULL) {
    prefix = c->argv[0];
  }

  /* Now, construct the unique filename using the cmd_rec's pool, the
   * prefix, and mkstemp().
   */
  filename = pstrcat(cmd->pool, prefix, "XXXXXX", NULL);

  stou_fd = mkstemp(filename);
  if (stou_fd < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "error: unable to use mkstemp(): %s",
      strerror(xerrno));

    /* If we can't guarantee a unique filename, refuse the command. */
    pr_response_add_err(R_450, _("%s: unable to generate unique filename"),
      (char *) cmd->argv[0]);

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  cmd->arg = filename;

  /* Close the unique file.  This introduces a small race condition
   * between the time this function returns, and the STOU CMD handler
   * opens the unique file, but this may have to do, as closing that
   * race would involve some major restructuring.
   */
  (void) close(stou_fd);

  filename = dir_best_path(cmd->tmp_pool, cmd->arg);

  if (filename == NULL ||
      !dir_check(cmd->tmp_pool, cmd, cmd->group, filename, NULL)) {
    int xerrno = errno;

    /* Do not forget to delete the file created by mkstemp(3) if there is
     * an error.
     */
    (void) pr_fsio_unlink(cmd->arg);

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  mode = file_mode2(cmd->tmp_pool, filename);

  /* Note: this case should never happen: how one can be appending to
   * a supposedly unique filename?  Should probably be removed...
   */
  allow_overwrite = get_param_ptr(CURRENT_CONF, "AllowOverwrite", FALSE);

  if (mode && session.xfer.xfer_type != STOR_APPEND &&
      (!allow_overwrite || *allow_overwrite == FALSE)) {
    pr_log_debug(DEBUG6, "AllowOverwrite denied permission for %s", cmd->arg);
    pr_response_add_err(R_550, _("%s: Overwrite permission denied"), cmd->arg);

    pr_cmd_set_errno(cmd, EACCES);
    errno = EACCES;
    return PR_ERROR(cmd);
  }

  /* Not likely to _not_ be a regular file, but just to be certain... */
  if (mode &&
      !S_ISREG(mode)) {
    (void) pr_fsio_unlink(cmd->arg);
    pr_response_add_err(R_550, _("%s: Not a regular file"), cmd->arg);

    /* Deliberately use EISDIR for anything non-file (e.g. directories). */
    pr_cmd_set_errno(cmd, EISDIR);
    errno = EISDIR;
    return PR_ERROR(cmd);
  }

  /* Otherwise everything is good */
  if (pr_table_add(cmd->notes, "mod_xfer.store-path",
      pstrdup(cmd->pool, filename), 0) < 0) {
    if (errno != EEXIST) {
      pr_log_pri(PR_LOG_NOTICE,
        "notice: error adding 'mod_xfer.store-path': %s", strerror(errno));
    }
  }

  session.xfer.xfer_type = STOR_UNIQUE;
  return PR_HANDLED(cmd);
}

MODRET xfer_post_stor(cmd_rec *cmd) {
  const char *path;

  path = pr_table_get(cmd->notes, "mod_xfer.store-path", NULL);
  if (path != NULL) {
    struct stat st;

    if (pr_fsio_stat(path, &st) == 0) {
      off_t *file_size;

      file_size = palloc(cmd->pool, sizeof(off_t));
      *file_size = st.st_size;
      (void) pr_table_add(cmd->notes, "mod_xfer.file-size", file_size,
        sizeof(off_t));
    }
  }

  return PR_DECLINED(cmd);
}

/* xfer_post_stou() is a POST_CMD handler that changes the mode of the
 * STOU file from 0600, which is what mkstemp() makes it, to 0666 (modulo
 * Umask), the default for files uploaded via STOR.  This is to prevent users
 * from being surprised.
 */
MODRET xfer_post_stou(cmd_rec *cmd) {
  mode_t mask, perms, *umask_setting;
  struct stat st;

  /* mkstemp(3) creates a file with 0600 perms; we need to adjust this
   * for the Umask (Bug#4223).
   */
  umask_setting = get_param_ptr(CURRENT_CONF, "Umask", FALSE);
  if (umask_setting != NULL) {
    mask = *umask_setting;

  } else {
    mask = (mode_t) 0022;
  }

  perms = (0666 & ~mask);

  if (pr_fsio_chmod(cmd->arg, perms) < 0) {
    /* Not much to do but log the error. */
    pr_log_pri(PR_LOG_NOTICE, "error: unable to chmod '%s' to %04o: %s",
      cmd->arg, perms, strerror(errno));
  }

  if (pr_fsio_stat(cmd->arg, &st) == 0) {
    off_t *file_size;

    file_size = palloc(cmd->pool, sizeof(off_t));
    *file_size = st.st_size;
    (void) pr_table_add(cmd->notes, "mod_xfer.file-size", file_size,
      sizeof(off_t));
  }

  return PR_DECLINED(cmd);
}

/* xfer_pre_appe() is the PRE_CMD handler for the APPE command, which
 * simply sets xfer_type to STOR_APPEND and calls xfer_pre_stor().
 */
MODRET xfer_pre_appe(cmd_rec *cmd) {
  session.xfer.xfer_type = STOR_DEFAULT;

  if (xfer_check_limit(cmd) < 0) {
    pr_response_add_err(R_451, _("%s: Too many transfers"), cmd->arg);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  session.xfer.xfer_type = STOR_APPEND;
  return xfer_pre_stor(cmd);
}

MODRET xfer_stor(cmd_rec *cmd) {
  const char *path;
  char *lbuf;
  int bufsz, len, xerrno = 0, res;
  off_t nbytes_stored, nbytes_max_store = 0;
  unsigned char have_limit = FALSE;
  struct stat st;
  off_t start_offset = 0, upload_len = 0;
  off_t curr_offset, curr_pos = 0;
  pr_error_t *err = NULL;

  memset(&st, 0, sizeof(st));

  /* Prepare for any potential throttling. */
  pr_throttle_init(cmd);

  session.xfer.path = pr_table_get(cmd->notes, "mod_xfer.store-path", NULL);
  session.xfer.path_hidden = pr_table_get(cmd->notes,
    "mod_xfer.store-hidden-path", NULL);

  path = session.xfer.path;

  /* Make sure the proper current working directory is set in the FSIO
   * layer, so that the proper FS can be used for the open().
   */
  pr_fs_setcwd(pr_fs_getcwd());

  if (session.xfer.xfer_type == STOR_HIDDEN) {
    const void *nfs;
    int oflags;

    oflags = O_WRONLY;

    if (session.restart_pos == 0) {
      oflags |= O_CREAT;
    }

    nfs = pr_table_get(cmd->notes, "mod_xfer.store-hidden-nfs", NULL);
    if (nfs == NULL) {
      pr_trace_msg("fsio", 9,
        "HiddenStores path '%s' is NOT on NFS, using O_EXCL open(2) flags",
        session.xfer.path_hidden);
      oflags |= O_EXCL;

    } else {
      pr_trace_msg("fsio", 9,
        "HiddenStores path '%s' is on NFS, NOT using O_EXCL open(2) flags",
        session.xfer.path_hidden);
    }

    stor_fh = pr_fsio_open_with_error(cmd->pool, session.xfer.path_hidden,
      oflags, &err);
    xerrno = errno;

    if (stor_fh == NULL) {
      pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 5);
      pr_error_set_why(err, pstrcat(cmd->pool, "open HiddenStores file '",
        session.xfer.path_hidden, "'", NULL));

      (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
        "error opening '%s': %s", (char *) cmd->argv[0], session.user,
        pr_uid2str(cmd->tmp_pool, session.uid),
        pr_gid2str(cmd->tmp_pool, session.gid), session.xfer.path_hidden,
        strerror(xerrno));
    }

  } else if (session.xfer.xfer_type == STOR_APPEND) {
    stor_fh = pr_fsio_open_with_error(cmd->pool, session.xfer.path,
      O_CREAT|O_WRONLY, &err);
    xerrno = errno;

    if (stor_fh != NULL) {
      if (pr_fsio_lseek(stor_fh, 0, SEEK_END) == (off_t) -1) {
        pr_log_debug(DEBUG4, "unable to seek to end of '%s' for appending: %s",
          cmd->arg, strerror(errno));
        (void) pr_fsio_close(stor_fh);
        stor_fh = NULL;
      }

    } else {
      xerrno = errno;

      pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 15);
      pr_error_set_why(err, pstrcat(cmd->pool, "append to file '",
        session.xfer.path, "'", NULL));

      (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
        "error opening '%s': %s", (char *) cmd->argv[0], session.user,
        pr_uid2str(cmd->tmp_pool, session.uid),
        pr_gid2str(cmd->tmp_pool, session.gid), session.xfer.path,
        strerror(xerrno));
    }

  } else {
    int open_flags = O_WRONLY|O_CREAT;

    if (session.range_len == 0 &&
        session.restart_pos == 0) {
      /* If we are not resuming an upload or handling a byte range transfer,
       * then we should truncate the file to receive the new data.
       */
      open_flags |= O_TRUNC;
    }

    /* Normal session */
    stor_fh = pr_fsio_open_with_error(cmd->pool, path, open_flags, &err);
    xerrno = errno;

    if (stor_fh == NULL) {
      pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 4);
      pr_error_set_why(err, pstrcat(cmd->pool, "upload file '", path, "'",
        NULL));

      (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
        "error opening '%s': %s", (char *) cmd->argv[0], session.user,
        pr_uid2str(cmd->tmp_pool, session.uid),
        pr_gid2str(cmd->tmp_pool, session.gid), path, strerror(xerrno));
    }
  }

  if (session.restart_pos > 0) {
    start_offset = session.restart_pos;

  } else if (session.range_start > 0) {
    start_offset = session.range_start;
  }

  if (stor_fh != NULL &&
      start_offset > 0) {
    xerrno = 0;

    pr_fs_clear_cache2(path);
    if (pr_fsio_lseek(stor_fh, start_offset, SEEK_SET) == -1) {
      pr_log_debug(DEBUG4, "unable to seek to position %" PR_LU " of '%s': %s",
        (pr_off_t) start_offset, cmd->arg, strerror(errno));
      xerrno = errno;

    } else if (pr_fsio_stat(path, &st) < 0) {
      pr_log_debug(DEBUG4, "unable to stat '%s': %s", cmd->arg,
        strerror(errno));
      xerrno = errno;
    }

    if (xerrno) {
      (void) pr_fsio_close(stor_fh);
      errno = xerrno;
      stor_fh = NULL;
    }

    /* Make sure that the requested offset is valid (within the size of the
     * file being resumed).
     */
    if (stor_fh != NULL &&
        start_offset > st.st_size) {
      int used_rest = TRUE;

      if (session.range_start > 0) {
        used_rest = FALSE;
      }

      pr_response_add_err(R_554, _("%s: invalid %s argument"),
        used_rest ? C_REST : C_RANG, cmd->arg);
      (void) pr_fsio_close(stor_fh);
      stor_fh = NULL;

      pr_cmd_set_errno(cmd, EINVAL);
      errno = EINVAL;
      return PR_ERROR(cmd);
    }

    curr_pos = start_offset;

    if (session.restart_pos > 0) {
      session.restart_pos = 0L;

    } else if (session.range_start > 0) {
      session.range_start = 0;
    }
  }

  if (stor_fh == NULL) {
    if (err != NULL) {
      pr_log_debug(DEBUG4, "%s", pr_error_strerror(err, 0));
      pr_error_destroy(err);
      err = NULL;

    } else {
      pr_log_debug(DEBUG4, "unable to open '%s' for writing: %s", cmd->arg,
        strerror(xerrno));
    }

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* Advise the platform that we will be only writing this file.  Note that a
   * preceding REST command does not mean we need to use a different offset
   * value here; we can/should still tell the platform that the entire file
   * should be treated this way.
   */
  pr_fs_fadvise(PR_FH_FD(stor_fh), 0, 0, PR_FS_FADVISE_DONTNEED);

  /* Stash the offset at which we're writing to this file. */
  curr_offset = pr_fsio_lseek(stor_fh, (off_t) 0, SEEK_CUR);
  if (curr_offset != (off_t) -1) {
    off_t *file_offset;

    file_offset = palloc(cmd->pool, sizeof(off_t));
    *file_offset = (off_t) curr_offset;
    (void) pr_table_add(cmd->notes, "mod_xfer.file-offset", file_offset,
      sizeof(off_t));
  }

  /* Get the latest stats on the file.  If the file already existed, we
   * want to know its current size.
   */
  (void) pr_fsio_fstat(stor_fh, &st);

  /* Block any timers for this section, where we want to prepare the
   * data connection, then need to reprovision the session.xfer struct,
   * and do NOT want timers (which may want/need that session.xfer data)
   * to fire until after the reprovisioning (Bug#4168).
   */
  pr_alarms_block();

  /* Perform the actual transfer now */
  pr_data_init(cmd->arg, PR_NETIO_IO_RD);

  /* Note that we have to re-populate the session.xfer variables here,
   * AFTER the pr_data_init() call.  pr_data_init() ensures that there is
   * no leftover information in session.xfer, as from aborted tranfers.
   */
  session.xfer.path = pr_table_get(cmd->notes, "mod_xfer.store-path", NULL);
  session.xfer.path_hidden = pr_table_get(cmd->notes,
    "mod_xfer.store-hidden-path", NULL);
  session.xfer.file_size = curr_pos;

  pr_alarms_unblock();

  /* First, make sure the uploaded file has the requested ownership. */
  stor_chown(cmd->tmp_pool);

  if (session.range_len > 0) {
    upload_len = session.range_len;
  }

  if (pr_data_open(cmd->arg, NULL, PR_NETIO_IO_RD, upload_len) < 0) {
    xerrno = errno;

    stor_abort(cmd->pool);
    pr_data_abort(0, TRUE);

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* Initialize the number of bytes stored */
  nbytes_stored = 0;

  /* Retrieve the number of bytes to store, maximum, if present.
   * This check is needed during the pr_data_xfer() loop, below, because
   * the size of the file being uploaded isn't known in advance
   */
  nbytes_max_store = find_max_nbytes("MaxStoreFileSize");
  if (nbytes_max_store == 0UL) {
    have_limit = FALSE;

  } else {
    have_limit = TRUE;
  }

  bufsz = pr_config_get_server_xfer_bufsz(PR_NETIO_IO_RD);
  lbuf = (char *) palloc(cmd->tmp_pool, bufsz);
  pr_trace_msg("data", 8, "allocated upload buffer of %lu bytes",
    (unsigned long) bufsz);

  while ((len = pr_data_xfer(lbuf, bufsz)) > 0) {
    pr_signals_handle();

    if (XFER_ABORTED) {
      break;
    }

    nbytes_stored += len;

    /* If MaxStoreFileSize is configured, double-check the number of bytes
     * uploaded so far against the configured limit.  Also make sure that
     * we take into account the size of the file, i.e. if it already existed.
     */
    if (have_limit &&
        (nbytes_stored + st.st_size > nbytes_max_store)) {
      pr_log_pri(PR_LOG_NOTICE, "MaxStoreFileSize (%" PR_LU " bytes) reached: "
        "aborting transfer of '%s'", (pr_off_t) nbytes_max_store, path);

      /* Abort the transfer. */
      stor_abort(cmd->pool);

      /* Set errno to EFBIG (or the most appropriate alternative). */
#if defined(EFBIG)
      xerrno = EFBIG;
#elif defined(EDQUOT)
      xerrno = EDQUOT;
#else
      xerrno = EPERM;
#endif

      pr_data_abort(xerrno, FALSE);
      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    /* XXX Need to handle short writes better here.  It is possible that
     * the underlying filesystem (e.g. a network-mounted filesystem) could
     * be doing short writes, and we ideally should be more resilient/graceful
     * in the face of such things.
     */
    res = pr_fsio_write_with_error(cmd->pool, stor_fh, lbuf, len, &err);
    xerrno = errno;

    if (res != len) {
      xerrno = EIO;

      if (res < 0) {
        xerrno = errno;

        pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 9);
        pr_error_set_why(err, pstrcat(cmd->pool, "writing '", stor_fh->fh_path,
          "'", NULL));
      }

      (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
        "error writing to '%s': %s", (char *) cmd->argv[0], session.user,
        pr_uid2str(cmd->tmp_pool, session.uid),
        pr_gid2str(cmd->tmp_pool, session.gid), stor_fh->fh_path,
        strerror(xerrno));

      if (err != NULL) {
        pr_log_debug(DEBUG9, "%s", pr_error_strerror(err, 0));
        pr_error_destroy(err);
        err = NULL;
      }

      stor_abort(cmd->pool);
      pr_data_abort(xerrno, FALSE);

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    /* If no throttling is configured, this does nothing. */
    pr_throttle_pause(nbytes_stored, FALSE);

    if (session.range_len > 0) {
      if (nbytes_stored == upload_len) {
        break;
      }

      if (nbytes_stored > upload_len) {
        xerrno = EPERM;

        pr_log_pri(PR_LOG_NOTICE, "Transfer range length (%" PR_LU
          " %s) exceeded; aborting transfer of '%s'", (pr_off_t) upload_len,
          upload_len != 1 ? "bytes" : "byte", path);

        /* Abort the transfer. */
        stor_abort(cmd->pool);

        pr_data_abort(xerrno, FALSE);
        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return PR_ERROR(cmd);
      }
    }
  }

  if (XFER_ABORTED) {
    stor_abort(cmd->pool);
    pr_data_abort(0, FALSE);

    pr_cmd_set_errno(cmd, EIO);
    errno = EIO; 
    return PR_ERROR(cmd);
  }

  if (len < 0) {
    /* Default abort errno, in case session.d et al has already gone away */
    xerrno = ECONNABORTED;

    stor_abort(cmd->pool);

    if (session.d != NULL &&
        session.d->instrm != NULL) {
      xerrno = PR_NETIO_ERRNO(session.d->instrm);
    }

    pr_data_abort(xerrno, FALSE);
    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* Did we receive all of the expected bytes in a range? */
  if (session.range_len > 0 &&
      nbytes_stored < upload_len) {
    xerrno = EPERM;

    pr_log_pri(PR_LOG_NOTICE, "Transfer range length (%" PR_LU
      " %s) not provided; aborting transfer of '%s'", (pr_off_t) upload_len,
      upload_len != 1 ? "bytes" : "byte", path);

    /* Abort the transfer. */
    stor_abort(cmd->pool);

    pr_data_abort(xerrno, FALSE);
    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* If no throttling is configured, this does nothing. */
  pr_throttle_pause(nbytes_stored, TRUE);

  if (stor_complete(cmd->pool) < 0) {
    xerrno = errno;

    _log_transfer('i', 'i');

    /* Check errno for EDQOUT (or the most appropriate alternative).
     * (I hate the fact that FTP has a special response code just for
     * this, and that clients actually expect it.  Special cases are
     * stupid.)
     */
#if defined(EDQUOT)
    if (xerrno == EDQUOT) {
      pr_response_add_err(R_552, "%s: %s", cmd->arg, strerror(xerrno));

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }
#elif defined(EFBIG)
    if (xerrno == EFBIG) {
      pr_response_add_err(R_552, "%s: %s", cmd->arg, strerror(xerrno));

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }
#endif

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (session.xfer.path &&
      session.xfer.path_hidden) {
    if (pr_fsio_rename(session.xfer.path_hidden, session.xfer.path) < 0) {
      xerrno = errno;

      /* This should only fail on a race condition with a chmod/chown or if
       * STOR_APPEND is on and the permissions are squirrely.  The poor user
       * will have to re-upload, but we've got more important problems to worry
       * about and this failure should be fairly rare.
       */
      pr_log_pri(PR_LOG_WARNING, "Rename of %s to %s failed: %s.",
        session.xfer.path_hidden, session.xfer.path, strerror(xerrno));

      pr_response_add_err(R_550, _("%s: Rename of hidden file %s failed: %s"),
        session.xfer.path, session.xfer.path_hidden, strerror(xerrno));

      if (pr_fsio_unlink(session.xfer.path_hidden) < 0) {
        if (errno != ENOENT) {
          pr_log_debug(DEBUG0, "failed to delete HiddenStores file '%s': %s",
            session.xfer.path_hidden, strerror(errno));
        }
      }

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    /* One way or another, we've dealt with the HiddenStores file. */
    session.xfer.path_hidden = NULL;
  }

  xfer_displayfile();
  pr_data_close(FALSE);

  return PR_HANDLED(cmd);
}

/* Should this become part of the String API? */
static int parse_offset(char *str, off_t *num) {
  char *ptr, *tmp = NULL;

  /* Don't allow negative numbers.  strtoul()/strtoull() will silently
   * handle them.
   */
  ptr = str;
  if (*ptr == '-') {
    errno = EINVAL;
    return -1;
  }

#ifdef HAVE_STRTOULL
  *num = strtoull(ptr, &tmp, 10);
#else
  *num = strtoul(ptr, &tmp, 10);
#endif /* HAVE_STRTOULL */

  if (tmp && *tmp) {
    errno = EINVAL;
    return -1;
  }

  return 0;
}

MODRET xfer_rest(cmd_rec *cmd) {
  int res;
  off_t pos = 0;

  if (cmd->argc != 2) {
    pr_response_add_err(R_500, _("'%s' not understood"),
      pr_cmd_get_displayable_str(cmd, NULL));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  res = parse_offset(cmd->argv[1], &pos);
  if (res < 0) {
    int xerrno = errno;

    pr_response_add_err(R_501,
      _("REST requires a value greater than or equal to 0"));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* Refuse the command if we're in ASCII mode, and the restart position
   * is anything other than zero.
   *
   * Ideally, we would refuse the REST command when in ASCII mode regardless
   * of position.  However, some (IMHO, stupid) clients "test" the FTP
   * server by sending "REST 0" to see if the server supports REST, without
   * regard to the transfer type.  This, then, is a hack to handle such
   * clients.
   */
  if ((session.sf_flags & SF_ASCII) &&
      pos != 0 &&
      !(xfer_opts & PR_XFER_OPT_IGNORE_ASCII)) {
    pr_log_debug(DEBUG5, "%s not allowed in ASCII mode", (char *) cmd->argv[0]);
    pr_response_add_err(R_501,
      _("%s: Resuming transfers not allowed in ASCII mode"),
      (char *) cmd->argv[0]);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  } 

  session.restart_pos = pos;

  /* We can honor REST, or RANG, but not both at the same time. */
  session.range_start = session.range_len = 0;

  pr_response_add(R_350, _("Restarting at %" PR_LU
    ". Send STORE or RETRIEVE to initiate transfer"), (pr_off_t) pos);
  return PR_HANDLED(cmd);
}

MODRET xfer_rang(cmd_rec *cmd) {
  int res;
  off_t range_start, range_end;

  if (cmd->argc != 3) {
    pr_response_add_err(R_500, _("'%s' not understood"),
      pr_cmd_get_displayable_str(cmd, NULL));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, session.cwd, NULL)) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG8, "RANG denied by <Limit> configuration");
    pr_response_add_err(R_552, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  res = parse_offset(cmd->argv[1], &range_start);
  if (res < 0) {
    int xerrno = errno;

    pr_response_add_err(R_501,
      _("RANG requires a value greater than or equal to 0"));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  res = parse_offset(cmd->argv[2], &range_end);
  if (res < 0) {
    int xerrno = errno;

    pr_response_add_err(R_501,
      _("RANG requires a value greater than or equal to 0"));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (range_start > range_end) {
    /* Per Draft, such ranges will automatically reset the range. */
    session.range_start = session.range_len = 0;

    /* Iff start = 1 AND end = 0, then this is the acceptable way to reset
     * the range.  Otherwise, it is an error.
     */
    if (range_start == 1 &&
        range_end == 0) {
      pr_response_add(R_350, _("Reset byte transfer range"));
      return PR_HANDLED(cmd);
    }

    pr_log_debug(DEBUG9, "rejecting RANG: start %" PR_LU " > end %" PR_LU,
      (pr_off_t) range_start, (pr_off_t) range_end);
    pr_response_add_err(R_501, _("RANG start must be less than end"));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  /* Per Draft, refuse (with 551) if we are not in IMAGE type, STREAM mode. */
  if (session.sf_flags & SF_ASCII) {
    pr_log_debug(DEBUG5, "%s not allowed in ASCII mode", (char *) cmd->argv[0]);
    pr_response_add_err(R_551,
      _("%s: Transfer ranges not allowed in ASCII mode"),
      (char *) cmd->argv[0]);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* Per Draft, the values given are positions, inclusive.  Thus
   * "RANG 0 1" would be a transfer range of TWO bytes.
   *
   * For consistency, we store offset+len, rather than start/end positions.
   */
  session.range_start = range_start;
  session.range_len = (range_end - range_start + 1);

  /* We can honor RANG, or REST, but not both at the same time. */
  session.restart_pos = 0;

  pr_response_add(R_350, _("Transferring byte range of %" PR_LU
    " %s starting from %" PR_LU), (pr_off_t) session.range_len,
    session.range_len != 1 ? "bytes" : "byte", (pr_off_t) range_start);
  return PR_HANDLED(cmd);
}

/* This is a PRE_CMD handler that checks security, etc, and places the full
 * filename to send in cmd->notes (note that we CANNOT use cmd->tmp_pool
 * for this, as tmp_pool only lasts for the duration of this function).
 */
MODRET xfer_pre_retr(cmd_rec *cmd) {
  char *decoded_path, *dir = NULL;
  mode_t fmode;
  unsigned char *allow_restart = NULL;
  config_rec *c;

  xfer_logged_sendfile_decline_msg = FALSE;

  if (cmd->argc < 2) {
    pr_response_add_err(R_500, _("'%s' not understood"),
      pr_cmd_get_displayable_str(cmd, NULL));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  decoded_path = pr_fs_decode_path2(cmd->tmp_pool, cmd->arg,
    FSIO_DECODE_FL_TELL_ERRORS);
  if (decoded_path == NULL) {
    int xerrno = errno;

    pr_log_debug(DEBUG8, "'%s' failed to decode properly: %s", cmd->arg,
      strerror(xerrno));
    pr_response_add_err(R_550, _("%s: Illegal character sequence in filename"),
      cmd->arg);

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  pr_fs_clear_cache2(decoded_path);
  dir = dir_realpath(cmd->tmp_pool, decoded_path);
  if (dir == NULL ||
      !dir_check(cmd->tmp_pool, cmd, cmd->group, dir, NULL)) {
    int xerrno = errno;

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* Check for UseSendfile. */
  use_sendfile = TRUE;
  use_sendfile_len = 0;
  use_sendfile_pct = -1.0;

  c = find_config(CURRENT_CONF, CONF_PARAM, "UseSendfile", FALSE);
  if (c != NULL) {
    use_sendfile = *((unsigned char *) c->argv[0]);
    use_sendfile_len = *((off_t *) c->argv[1]);
    use_sendfile_pct = *((float *) c->argv[2]);
  }

  if (xfer_check_limit(cmd) < 0) {
    pr_response_add_err(R_451, _("%s: Too many transfers"), cmd->arg);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  fmode = file_mode2(cmd->tmp_pool, dir);
  if (fmode == 0) {
    int xerrno = errno;

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (!S_ISREG(fmode)
#ifdef S_ISFIFO
      && !S_ISFIFO(fmode)
#endif
     ) {
    pr_response_add_err(R_550, _("%s: Not a regular file"), cmd->arg);

    /* Deliberately use EISDIR for anything non-file (e.g. directories). */
    pr_cmd_set_errno(cmd, EISDIR);
    errno = EISDIR;
    return PR_ERROR(cmd);
  }

  /* If restart is on, check to see if AllowRestartRetrieve is off, in
   * which case we disallow the transfer and clear restart_pos.
   */
  allow_restart = get_param_ptr(CURRENT_CONF, "AllowRetrieveRestart", FALSE);

  if ((session.restart_pos > 0 || session.range_len > 0) &&
      (allow_restart && *allow_restart == FALSE)) {
    pr_response_add_err(R_451, _("%s: Restart not permitted, try again"),
      cmd->arg);
    session.restart_pos = 0L;

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* Otherwise everything is good */
  if (pr_table_add(cmd->notes, "mod_xfer.retr-path",
      pstrdup(cmd->pool, dir), 0) < 0) {
    if (errno != EEXIST) {
      pr_log_pri(PR_LOG_NOTICE, "notice: error adding 'mod_xfer.retr-path': %s",
        strerror(errno));
    }
  }

  return PR_HANDLED(cmd);
}

MODRET xfer_post_retr(cmd_rec *cmd) {
  const char *path;

  path = pr_table_get(cmd->notes, "mod_xfer.retr-path", NULL);
  if (path != NULL) {
    struct stat st;

    if (pr_fsio_stat(path, &st) == 0) {
      off_t *file_size;

      file_size = palloc(cmd->pool, sizeof(off_t));
      *file_size = st.st_size;
      (void) pr_table_add(cmd->notes, "mod_xfer.file-size", file_size,
        sizeof(off_t));
    }
  }

  return PR_DECLINED(cmd);
}

MODRET xfer_retr(cmd_rec *cmd) {
  int xerrno = 0;
  const char *dir = NULL;
  char *lbuf;
  struct stat st;
  off_t nbytes_max_retrieve = 0;
  unsigned char have_limit = FALSE;
  long bufsz, len = 0;
  off_t start_offset = 0, download_len = 0;
  off_t curr_offset, curr_pos = 0, nbytes_sent = 0, cnt_steps = 0, cnt_next = 0;
  pr_error_t *err = NULL;

  /* Prepare for any potential throttling. */
  pr_throttle_init(cmd);

  dir = pr_table_get(cmd->notes, "mod_xfer.retr-path", NULL);

  retr_fh = pr_fsio_open_with_error(cmd->pool, dir, O_RDONLY, &err);
  xerrno = errno;

  if (retr_fh == NULL) {
    pr_error_set_where(err, &xfer_module, __FILE__, __LINE__ - 4);
    pr_error_set_why(err, pstrcat(cmd->pool, "download file '", dir, "'",
      NULL));

    (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
      "error opening '%s': %s", (char *) cmd->argv[0], session.user,
      pr_uid2str(cmd->tmp_pool, session.uid),
      pr_gid2str(cmd->tmp_pool, session.gid), dir, strerror(xerrno));

    if (err != NULL) {
      pr_log_debug(DEBUG9, "%s", pr_error_strerror(err, 0));
      pr_error_destroy(err);
      err = NULL;
    }

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (pr_fsio_fstat(retr_fh, &st) < 0) {
    /* Error stat'ing the file. */
    xerrno = errno;

    pr_fsio_close(retr_fh);
    retr_fh = NULL;
    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* Advise the platform that we will be only reading this file
   * sequentially.  Note that a preceding REST command does not mean we
   * need to use a different offset value here; we can/should still
   * tell the platform that the entire file should be treated this way.
   */
  pr_fs_fadvise(PR_FH_FD(retr_fh), 0, 0, PR_FS_FADVISE_SEQUENTIAL);

  if (session.restart_pos > 0) {
    start_offset = session.restart_pos;

  } else if (session.range_start > 0) {
    start_offset = session.range_start;
  }

  if (start_offset > 0) {
    char *offset_cmd;

    offset_cmd = C_REST;
    if (session.range_start > 0) {
      offset_cmd = C_RANG;
    }

    /* Make sure that the requested offset is valid (within the size of the
     * file being resumed).
     */

    if (start_offset > st.st_size) {
      pr_trace_msg(trace_channel, 4,
        "%s offset %" PR_LU " exceeds file size (%" PR_LU " bytes)",
        offset_cmd, (pr_off_t) start_offset, (pr_off_t) st.st_size);
      pr_response_add_err(R_554, _("%s: invalid %s argument"), offset_cmd,
        cmd->arg);
      pr_fsio_close(retr_fh);
      retr_fh = NULL;

      pr_cmd_set_errno(cmd, EINVAL);
      errno = EINVAL;
      return PR_ERROR(cmd);
    }

    /* The RANG Draft says, on this topic:
     *
     *   The server-PI SHOULD transfer 0 octets with RETR if the specified
     *   start point or start point and end point are larger than the actual
     *   file size.
     *
     * However, I vehemently disagree.  Sending zero bytes in such a case
     * would be treated as a successful download by the client, not informing
     * the user of the erroneous conditions.  Thus, IMHO, violating the
     * principle of least surprise; the user might end up asking "Why did
     * my download succeed, but I have zero bytes?".  That is a terrible user
     * experience.  So instead, we return an error in this case.
     */

    if ((start_offset + session.range_len) > st.st_size) {
      pr_trace_msg(trace_channel, 4,
        "%s offset %" PR_LU " exceeds file size (%" PR_LU " bytes)",
        offset_cmd, (pr_off_t) (start_offset + session.range_len),
        (pr_off_t) st.st_size);
      pr_response_add_err(R_554, _("%s: invalid RANG argument"), cmd->arg);
      pr_fsio_close(retr_fh);
      retr_fh = NULL;

      pr_cmd_set_errno(cmd, EINVAL);
      errno = EINVAL;
      return PR_ERROR(cmd);
    }

    if (pr_fsio_lseek(retr_fh, start_offset, SEEK_SET) == (off_t) -1) {
      xerrno = errno;
      pr_fsio_close(retr_fh);
      errno = xerrno;
      retr_fh = NULL;

      (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
        "error seeking to byte %" PR_LU " of '%s': %s", (char *) cmd->argv[0],
        session.user, pr_uid2str(cmd->tmp_pool, session.uid),
        pr_gid2str(cmd->tmp_pool, session.gid), (pr_off_t) start_offset,
        dir, strerror(xerrno));

      pr_log_debug(DEBUG0, "error seeking to offset %" PR_LU
        " for file %s: %s", (pr_off_t) start_offset, dir, strerror(xerrno));
      pr_response_add_err(R_554, _("%s: invalid %s argument"), offset_cmd,
        cmd->arg);

      pr_cmd_set_errno(cmd, EINVAL);
      errno = EINVAL;
      return PR_ERROR(cmd);
    }

    curr_pos = start_offset;

    if (session.restart_pos > 0) {
      session.restart_pos = 0L;

    } else if (session.range_start > 0) {
      session.range_start = 0;
    }
  }

  /* Stash the offset at which we're writing from this file. */
  curr_offset = pr_fsio_lseek(retr_fh, (off_t) 0, SEEK_CUR);
  if (curr_offset != (off_t) -1) {
    off_t *file_offset;

    file_offset = palloc(cmd->pool, sizeof(off_t));
    *file_offset = (off_t) curr_offset;
    (void) pr_table_add(cmd->notes, "mod_xfer.file-offset", file_offset,
      sizeof(off_t));
  }

  /* Block any timers for this section, where we want to prepare the
   * data connection, then need to reprovision the session.xfer struct,
   * and do NOT want timers (which may want/need that session.xfer data)
   * to fire until after the reprovisioning (Bug#4168).
   */
  pr_alarms_block();

  /* Send the data */
  pr_data_init(cmd->arg, PR_NETIO_IO_WR);

  session.xfer.path = dir;
  session.xfer.file_size = st.st_size;

  pr_alarms_unblock();

  cnt_steps = session.xfer.file_size / 100;
  if (cnt_steps == 0) {
    cnt_steps = 1;
  }

  if (session.range_len > 0) {
    if (curr_pos + session.range_len > st.st_size) {
      /* If the RANG end point is past the end of our file, ignore it and
       * treat this as the remainder of the file, from the starting offset.
       */
      download_len = st.st_size - curr_pos;

    } else {
      download_len = session.range_len;
    }

  } else {
    download_len = st.st_size - curr_pos;
  }

  if (pr_data_open(cmd->arg, NULL, PR_NETIO_IO_WR, download_len) < 0) {
    xerrno = errno;

    retr_abort(cmd->pool);
    pr_data_abort(0, TRUE);

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* Retrieve the number of bytes to retrieve, maximum, if present */
  nbytes_max_retrieve = find_max_nbytes("MaxRetrieveFileSize");
  if (nbytes_max_retrieve == 0UL) {
    have_limit = FALSE;

  } else {
    have_limit = TRUE;
  }

  /* Check the MaxRetrieveFileSize.  If it is zero, or if the size
   * of the file being retrieved is greater than the MaxRetrieveFileSize,
   * then signal an error and abort the transfer now.
   */
  if (have_limit &&
      ((nbytes_max_retrieve == 0) || (st.st_size > nbytes_max_retrieve))) {

    pr_log_pri(PR_LOG_NOTICE, "MaxRetrieveFileSize (%" PR_LU " %s) reached: "
      "aborting transfer of '%s'", (pr_off_t) nbytes_max_retrieve,
      nbytes_max_retrieve != 1 ? "bytes" : "byte", dir);

    /* Abort the transfer. */
    retr_abort(cmd->pool);

    /* Set errno to EPERM ("Operation not permitted") */
    pr_data_abort(EPERM, FALSE);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  bufsz = pr_config_get_server_xfer_bufsz(PR_NETIO_IO_WR);
  lbuf = (char *) palloc(cmd->tmp_pool, bufsz);
  pr_trace_msg("data", 8, "allocated download buffer of %lu bytes",
    (unsigned long) bufsz);

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_XFER_SIZE, download_len,
    PR_SCORE_XFER_DONE, (off_t) 0,
    NULL);

  if (session.range_len > 0) {
    if (bufsz > session.range_len) {
      bufsz = session.range_len;
    }
  }

  while (nbytes_sent != download_len) {
    pr_signals_handle();

    if (XFER_ABORTED) {
      break;
    }

    len = transmit_data(cmd->pool, curr_offset, &curr_pos, lbuf, bufsz);
    if (len == 0) {
      break;
    }

    if (len < 0) {
      /* Make sure that the errno value, needed for the pr_data_abort() call,
       * is preserved; errno itself might be overwritten in retr_abort().
       */
      int already_aborted = FALSE;

      xerrno = errno;
      retr_abort(cmd->pool);

      /* Do we need to abort the data transfer here?  It's possible that
       * the transfer has already been aborted, e.g. via the TCP OOB marker
       * and/or the ABOR command.  And if that is the case, then calling
       * pr_data_abort() here will only lead to a spurious response code
       * (see Bug#4252).
       *
       * However, there are OTHER error conditions which would lead to this
       * code path.  So we need to resort to some heuristics to differentiate
       * between these cases.  The errno value checks match those in the
       * pr_data_xfer() function, after the control channel has been polled
       * for commands such as ABOR.
       */

      if (session.d == NULL &&
#if defined(ECONNABORTED)
          xerrno == ECONNABORTED &&
#elif defined(ENOTCONN)
          xerrno == ENOTCONN &&
#else
          xerrno == EIO &&
#endif
          session.xfer.xfer_type == STOR_DEFAULT) {

        /* If the ABOR command has been sent, then pr_data_reset() and
         * pr_data_cleanup() will have been called; the latter resets the
         * xfer_type value to DEFAULT.
         */
        already_aborted = TRUE;
      }

      if (already_aborted == FALSE) {
        pr_data_abort(xerrno, FALSE);
      }

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    nbytes_sent += len;
    curr_offset += len;

    if ((nbytes_sent / cnt_steps) != cnt_next) {
      cnt_next = nbytes_sent / cnt_steps;

      pr_scoreboard_entry_update(session.pid,
        PR_SCORE_XFER_DONE, nbytes_sent,
        NULL);
    }

    /* If no throttling is configured, this simply updates the scoreboard.
     * In this case, we want to use session.xfer.total_bytes, rather than
     * nbytes_sent, as the latter incorporates a REST position and the
     * former does not.  (When handling STOR, this is not an issue: different
     * end-of-loop conditions).
     */
    pr_throttle_pause(session.xfer.total_bytes, FALSE);
  }

  if (XFER_ABORTED) {
    retr_abort(cmd->pool);
    pr_data_abort(0, FALSE);

    pr_cmd_set_errno(cmd, EIO);
    errno = EIO;
    return PR_ERROR(cmd);

  } else {

    /* If no throttling is configured, this simply updates the scoreboard.
     * In this case, we want to use session.xfer.total_bytes, rather than
     * nbytes_sent, as the latter incorporates a REST position and the
     * former does not.  (When handling STOR, this is not an issue: different
     * end-of-loop conditions).
     */
    pr_throttle_pause(session.xfer.total_bytes, TRUE);

    retr_complete(cmd->pool);
    xfer_displayfile();
    pr_data_close(FALSE);
  }

  return PR_HANDLED(cmd);
}

MODRET xfer_abor(cmd_rec *cmd) {
  if (cmd->argc != 1) {
    pr_response_add_err(R_500, _("'%s' not understood"),
      pr_cmd_get_displayable_str(cmd, NULL));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  if (session.xfer.direction == PR_NETIO_IO_RD) {
    stor_abort(cmd->pool);

  } else if (session.xfer.direction == PR_NETIO_IO_WR) {
    retr_abort(cmd->pool);
  }

  pr_data_abort(0, FALSE);

  pr_response_add(R_226, _("Abort successful"));
  return PR_HANDLED(cmd);
}

MODRET xfer_log_abor(cmd_rec *cmd) {

  /* Clean up the data connection info in the session structure. */
  pr_data_reset();
  pr_data_cleanup();

  return PR_DECLINED(cmd);
}

MODRET xfer_type(cmd_rec *cmd) {
  char *type;

  if (cmd->argc < 2 ||
      cmd->argc > 3) {
    pr_response_add_err(R_500, _("'%s' not understood"),
      pr_cmd_get_displayable_str(cmd, NULL));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  type = pstrdup(cmd->tmp_pool, cmd->argv[1]);
  type[0] = toupper(type[0]);

  if (strncmp(type, "A", 2) == 0 ||
      (cmd->argc == 3 &&
       strncmp(type, "L", 2) == 0 &&
       strncmp(cmd->argv[2], "7", 2) == 0)) {

    /* TYPE A(SCII) or TYPE L 7. */
    session.sf_flags |= SF_ASCII;

  } else if (strncmp(type, "I", 2) == 0 ||
      (cmd->argc == 3 &&
       strncmp(type, "L", 2) == 0 &&
       strncmp(cmd->argv[2], "8", 2) == 0)) {

    /* TYPE I(MAGE) or TYPE L 8. */
    session.sf_flags &= (SF_ALL^(SF_ASCII|SF_ASCII_OVERRIDE));

  } else {
    pr_response_add_err(R_504, _("%s not implemented for '%s' parameter"),
      (char *) cmd->argv[0], (char *) cmd->argv[1]);

    pr_cmd_set_errno(cmd, ENOSYS);
    errno = ENOSYS;
    return PR_ERROR(cmd);
  }

  /* Note that the client may NOT be authenticated at this point in time.
   * If that is the case, set a flag so that the POST_CMD PASS handler does
   * not overwrite the TYPE command's setting.
   *
   * Alternatively, we COULD bar/reject any TYPE commands before authentication.
   * However, I think that doing so would interfere with many existing clients
   * which assume that they can send TYPE before authenticating.
   */
  if (session.auth_mech == NULL) {
    have_type = TRUE;
  }

  pr_response_add(R_200, _("Type set to %s"), (char *) cmd->argv[1]);
  return PR_HANDLED(cmd);
}

MODRET xfer_stru(cmd_rec *cmd) {
  char *stru;

  if (cmd->argc != 2) {
    pr_response_add_err(R_501, _("'%s' not understood"),
      pr_cmd_get_displayable_str(cmd, NULL));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  stru = cmd->argv[1];
  stru[0] = toupper(stru[0]);

  switch ((int) stru[0]) {
    case 'F':
      /* Should 202 be returned instead??? */
      pr_response_add(R_200, _("Structure set to F"));
      return PR_HANDLED(cmd);
      break;

    case 'R':
      /* Accept R but with no operational difference from F???
       * R is required in minimum implementations by RFC-959, 5.1.
       * RFC-1123, 4.1.2.13, amends this to only apply to servers whose file
       * systems support record structures, but also suggests that such a
       * server "may still accept files with STRU R, recording the byte stream
       * literally." Another configurable choice, perhaps?
       *
       * NOTE: wu-ftpd does not so accept STRU R.
       */

       /* FALLTHROUGH */

    case 'P':
      /* RFC-1123 recommends against implementing P. */
      pr_response_add_err(R_504, _("'%s' unsupported structure type"),
        pr_cmd_get_displayable_str(cmd, NULL));

      pr_cmd_set_errno(cmd, ENOSYS);
      errno = ENOSYS;
      return PR_ERROR(cmd);

    default:
      pr_response_add_err(R_501, _("'%s' unrecognized structure type"),
        pr_cmd_get_displayable_str(cmd, NULL));

      pr_cmd_set_errno(cmd, EINVAL);
      errno = EINVAL;
      return PR_ERROR(cmd);
  }
}

MODRET xfer_mode(cmd_rec *cmd) {
  char *mode;

  if (cmd->argc != 2) {
    pr_response_add_err(R_501, _("'%s' not understood"),
      pr_cmd_get_displayable_str(cmd, NULL));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  mode = cmd->argv[1];
  mode[0] = toupper(mode[0]);

  switch ((int) mode[0]) {
    case 'S':
      /* Should 202 be returned instead??? */
      pr_response_add(R_200, _("Mode set to S"));
      return PR_HANDLED(cmd);

    case 'B':
      /* FALLTHROUGH */

    case 'C':
      pr_response_add_err(R_504, _("'%s' unsupported transfer mode"),
        pr_cmd_get_displayable_str(cmd, NULL));

      pr_cmd_set_errno(cmd, ENOSYS);
      errno = ENOSYS;
      return PR_ERROR(cmd);
  }

  pr_response_add_err(R_501, _("'%s' unrecognized transfer mode"),
    pr_cmd_get_displayable_str(cmd, NULL));

  pr_cmd_set_errno(cmd, EINVAL);
  errno = EINVAL;
  return PR_ERROR(cmd);
}

MODRET xfer_allo(cmd_rec *cmd) {
  off_t requested_sz;
  char *tmp = NULL;

  /* Even though we only handle the "ALLO <size>" command, we should not
   * barf on the unlikely (but RFC-compliant) "ALLO <size> R <size>" commands.
   * See RFC 959, Section 4.1.3.
   */
  if (cmd->argc != 2 &&
      cmd->argc != 4) {
    pr_response_add_err(R_504, _("'%s' not understood"),
      pr_cmd_get_displayable_str(cmd, NULL));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

#ifdef HAVE_STRTOULL
  requested_sz = strtoull(cmd->argv[1], &tmp, 10);
#else
  requested_sz = strtoul(cmd->argv[1], &tmp, 10);
#endif /* !HAVE_STRTOULL */

  if (tmp && *tmp) {
    pr_response_add_err(R_504, _("%s: Invalid ALLO argument"), cmd->arg);

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  if (xfer_opts & PR_XFER_OPT_HANDLE_ALLO) {
    const char *path;
    off_t avail_kb;
    int res;

    path = pr_fs_getcwd();

    res = pr_fs_getsize2((char *) path, &avail_kb);
    if (res < 0) {
      /* If we can't check the filesystem stats for any reason, let the request
       * proceed anyway.
       */
      pr_log_debug(DEBUG7,
        "error getting available size for filesystem containing '%s': %s",
        path, strerror(errno));
      pr_response_add(R_202, _("No storage allocation necessary"));

    } else {
      off_t requested_kb;

      /* The requested size is in bytes; the size returned from
       * pr_fs_getsize2() is in KB.
       */
      requested_kb = requested_sz / 1024;

      if (requested_kb > avail_kb) {
        pr_log_debug(DEBUG5, "%s requested %" PR_LU " KB, only %" PR_LU
          " KB available on '%s'", (char *) cmd->argv[0],
          (pr_off_t) requested_kb, (pr_off_t) avail_kb, path);
        pr_response_add_err(R_552, "%s: %s", cmd->arg, strerror(ENOSPC));

        pr_cmd_set_errno(cmd, ENOSPC);
        errno = ENOSPC;
        return PR_ERROR(cmd);
      }

      pr_log_debug(DEBUG9, "%s requested %" PR_LU " KB, %" PR_LU
        " KB available on '%s'", (char *) cmd->argv[0], (pr_off_t) requested_kb,
        (pr_off_t) avail_kb, path);
      pr_response_add(R_200, _("%s command successful"), (char *) cmd->argv[0]);
    }

  } else {
    pr_response_add(R_202, _("No storage allocation necessary"));
  }

  return PR_HANDLED(cmd);
}

MODRET xfer_smnt(cmd_rec *cmd) {
  pr_response_add(R_502, _("SMNT command not implemented"));
  return PR_HANDLED(cmd);
}

MODRET xfer_err_cleanup(cmd_rec *cmd) {

  /* If a hidden store was aborted, remove it. */
  if (session.xfer.xfer_type == STOR_HIDDEN) {
    unsigned char *delete_stores = NULL;

    delete_stores = get_param_ptr(CURRENT_CONF, "DeleteAbortedStores", FALSE);
    if (delete_stores == NULL ||
        *delete_stores == TRUE) {
      if (session.xfer.path_hidden) {
        pr_log_debug(DEBUG5, "removing aborted HiddenStores file '%s'",
          session.xfer.path_hidden);
        if (pr_fsio_unlink(session.xfer.path_hidden) < 0) {
          if (errno != ENOENT) {
            pr_log_debug(DEBUG0, "error deleting HiddenStores file '%s': %s",
              session.xfer.path_hidden, strerror(errno));
          }
        }
      }
    }
  }

  pr_data_clear_xfer_pool();

  memset(&session.xfer, '\0', sizeof(session.xfer));

  /* Don't forget to clear any possible RANG/REST parameters as well. */
  session.range_start = session.range_len = 0;
  session.restart_pos = 0;

  return PR_DECLINED(cmd);
}

MODRET xfer_log_stor(cmd_rec *cmd) {
  _log_transfer('i', 'c');

  /* Increment the file counters. */
  session.total_files_in++;
  session.total_files_xfer++;

  pr_data_cleanup();

  /* Don't forget to clear any possible RANG/REST parameters as well. */
  session.range_start = session.range_len = 0;
  session.restart_pos = 0;

  return PR_DECLINED(cmd);
}

MODRET xfer_log_retr(cmd_rec *cmd) {
  _log_transfer('o', 'c');

  /* Increment the file counters. */
  session.total_files_out++;
  session.total_files_xfer++;

  pr_data_cleanup();

  /* Don't forget to clear any possible RANG/REST parameters as well. */
  session.range_start = session.range_len = 0;
  session.restart_pos = 0;

  return PR_DECLINED(cmd);
}

static int noxfer_timeout_cb(CALLBACK_FRAME) {
  int timeout;
  const char *proto;

  timeout = pr_data_get_timeout(PR_DATA_TIMEOUT_NO_TRANSFER);

  if (session.sf_flags & SF_XFER) {
    pr_trace_msg("timer", 4,
      "TimeoutNoTransfer (%d %s) reached, but data transfer in progress, "
      "ignoring", timeout, timeout != 1 ? "seconds" : "second");

    /* Transfer in progress, ignore this timeout */
    return 1;
  }

  pr_event_generate("core.timeout-no-transfer", NULL);
  pr_response_send_async(R_421,
    _("No transfer timeout (%d seconds): closing control connection"), timeout);

  pr_timer_remove(PR_TIMER_IDLE, ANY_MODULE);
  pr_timer_remove(PR_TIMER_LOGIN, ANY_MODULE);

  /* If this timeout is encountered and we are expecting a passive transfer,
   * add some logging that suggests things to check and possibly fix
   * (e.g. network/firewall rules).
   */
  if (session.sf_flags & SF_PASSIVE) {
    pr_log_pri(PR_LOG_NOTICE,
      "Passive data transfer failed, possibly due to network issues");
    pr_log_pri(PR_LOG_NOTICE,
      "Check your PassivePorts and MasqueradeAddress settings,");
    pr_log_pri(PR_LOG_NOTICE,
       "and any router, NAT, and firewall rules in the network path.");
  }

  proto = pr_session_get_protocol(PR_SESS_PROTO_FL_LOGOUT);

  pr_log_pri(PR_LOG_NOTICE, "%s no transfer timeout, disconnected", proto);
  pr_session_disconnect(&xfer_module, PR_SESS_DISCONNECT_TIMEOUT,
    "TimeoutNoTransfer");

  return 0;
}

MODRET xfer_post_pass(cmd_rec *cmd) {
  config_rec *c;

  /* Default transfer mode is ASCII, per RFC 959, Section 3.1.1.1.  Unless
   * the client has already sent a TYPE command.
   */
  if (have_type == FALSE) {
    session.sf_flags |= SF_ASCII;
    c = find_config(main_server->conf, CONF_PARAM, "DefaultTransferMode",
      FALSE);
    if (c != NULL) {
      char *default_transfer_mode;

      default_transfer_mode = c->argv[0];
      if (strcasecmp(default_transfer_mode, "binary") == 0) {
        session.sf_flags &= (SF_ALL^SF_ASCII);
      }
    }
  }

  c = find_config(TOPLEVEL_CONF, CONF_PARAM, "TimeoutNoTransfer", FALSE);
  if (c != NULL) {
    int timeout = *((int *) c->argv[0]);
    pr_data_set_timeout(PR_DATA_TIMEOUT_NO_TRANSFER, timeout);

    /* Setup timer */
    if (timeout > 0) {
      pr_timer_add(timeout, PR_TIMER_NOXFER, &xfer_module, noxfer_timeout_cb,
        "TimeoutNoTransfer");
    }
  }

  c = find_config(TOPLEVEL_CONF, CONF_PARAM, "TimeoutStalled", FALSE);
  if (c != NULL) {
    int timeout = *((int *) c->argv[0]);
    pr_data_set_timeout(PR_DATA_TIMEOUT_STALLED, timeout);

    /* Note: timers for handling TimeoutStalled timeouts are handled in the
     * data transfer routines, not here.
     */
  }

  c = find_config(main_server->conf, CONF_PARAM, "TransferOptions", FALSE);
  while (c != NULL) {
    unsigned long opts = 0;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    xfer_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "TransferOptions", FALSE);
  }

  if (xfer_opts & PR_XFER_OPT_IGNORE_ASCII) {
    pr_log_debug(DEBUG8, "Ignoring ASCII translation for this session");
    pr_data_ignore_ascii(TRUE);
  }

  /* If we are chrooted, then skip actually processing the ALLO command
   * (Bug#3996).
   */
  if (session.chroot_path != NULL) {
    xfer_opts &= ~PR_XFER_OPT_HANDLE_ALLO;
  }

  return PR_DECLINED(cmd);
}

/* Configuration handlers
 */

MODRET set_allowoverwrite(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR|CONF_DYNDIR);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = (unsigned char) bool;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET set_allowrestart(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR|CONF_DYNDIR);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: DefaultTransferMode ascii|binary */
MODRET set_defaulttransfermode(cmd_rec *cmd) {
  char *default_mode;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  default_mode = cmd->argv[1];
  if (strcasecmp(default_mode, "ascii") != 0 &&
      strcasecmp(default_mode, "binary") != 0) {
    CONF_ERROR(cmd, "parameter must be 'ascii' or 'binary'");
  }

  add_config_param_str(cmd->argv[0], 1, default_mode);
  return PR_HANDLED(cmd);
}

MODRET set_deleteabortedstores(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR|CONF_DYNDIR);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: DisplayFileTransfer path */
MODRET set_displayfiletransfer(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

MODRET set_hiddenstores(cmd_rec *cmd) {
  int enabled = -1, add_periods = TRUE;
  config_rec *c = NULL;
  char *prefix = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR);

  c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);

  /* Handle the case where the admin may, for some reason, want a custom
   * prefix which could also be construed to be a Boolean value by
   * get_boolean(): if the value begins AND ends with a period, then treat
   * it as a custom prefix.
   */
  prefix = cmd->argv[1];
  if (prefix[0] == '.' &&
      prefix[strlen(prefix)-1] == '.') {
    add_periods = FALSE;
    enabled = -1;

  } else {
    enabled = get_boolean(cmd, 1);
  }

  /* If a suffix has been configured as well, assume that we do NOT
   * automatically want periods.
   */
  if (cmd->argc == 3) {
    add_periods = FALSE;
  }

  if (enabled == -1) {
    /* If the parameter is not a Boolean parameter, assume that the
     * admin is configuring a specific prefix to use instead of the
     * default ".in.".
     */

    c->argv[0] = pcalloc(c->pool, sizeof(int));
    *((int *) c->argv[0]) = TRUE;

    if (add_periods) {
      /* Automatically add the leading and trailing periods. */
      c->argv[1] = pstrcat(c->pool, ".", cmd->argv[1], ".", NULL);

    } else {
      c->argv[1] = pstrdup(c->pool, cmd->argv[1]);
    }

    if (cmd->argc == 3) {
      c->argv[2] = pstrdup(c->pool, cmd->argv[2]);

    } else {
      c->argv[2] = pstrdup(c->pool, ".");
    }

  } else {
    c->argv[0] = pcalloc(c->pool, sizeof(int));
    *((int *) c->argv[0]) = enabled;

    if (enabled) {
      /* The default HiddenStore prefix */
      c->argv[1] = pstrdup(c->pool, ".in.");

      /* The default HiddenStores suffix. */
      c->argv[2] = pstrdup(c->pool, ".");
    }
  }

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

MODRET set_maxfilesize(cmd_rec *cmd) {
  config_rec *c = NULL;
  off_t nbytes;
  unsigned int precedence = 0;

  int ctxt = (cmd->config && cmd->config->config_type != CONF_PARAM ?
     cmd->config->config_type : cmd->server->config_type ?
     cmd->server->config_type : CONF_ROOT);

  if (cmd->argc-1 == 1) {
    if (strncmp(cmd->argv[1], "*", 2) != 0) {
      CONF_ERROR(cmd, "incorrect number of parameters");
    }

  } else if (cmd->argc-1 != 2 && cmd->argc-1 != 4) {
    CONF_ERROR(cmd, "incorrect number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_ANON|CONF_VIRTUAL|CONF_GLOBAL|CONF_DIR|
    CONF_DYNDIR);

  /* Set the precedence for this config_rec based on its configuration
   * context.
   */
  if (ctxt & CONF_GLOBAL) {
    precedence = 1;

  /* These will never appear simultaneously */
  } else if ((ctxt & CONF_ROOT) ||
             (ctxt & CONF_VIRTUAL)) {
    precedence = 2;

  } else if (ctxt & CONF_ANON) {
    precedence = 3;

  } else if (ctxt & CONF_DIR) {
    precedence = 4;

  } else if (ctxt & CONF_DYNDIR) {
    precedence = 5;
  }

  /* If the directive was used with four arguments, it means the optional
   * classifiers and expression were used.  Make sure the classifier is a valid
   * one.
   */
  if (cmd->argc-1 == 4) {
    if (strncmp(cmd->argv[3], "user", 5) == 0 ||
        strncmp(cmd->argv[3], "group", 6) == 0 ||
        strncmp(cmd->argv[3], "class", 6) == 0) {

       /* no-op */

     } else {
       CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown classifier used: '",
         cmd->argv[3], "'", NULL));
    }
  }

  if (cmd->argc-1 == 1) {

    /* Do nothing here -- the "*" (the only parameter allowed if there is
     * only a single parameter given) signifies an unlimited size, which is
     * what the server provides by default.
     */
    nbytes = 0UL;

  } else {

    /* Pass the cmd_rec off to see what number of bytes was
     * requested/configured.
     */
    if (pr_str_get_nbytes(cmd->argv[1], cmd->argv[2], &nbytes) < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to parse: ",
        cmd->argv[1], " ", cmd->argv[2], ": ", strerror(errno), NULL));
    }

    if (nbytes == 0) {
      CONF_ERROR(cmd, "size must be greater than zero");
    }
  }

  if (cmd->argc-1 == 1 ||
      cmd->argc-1 == 2) {
    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(off_t));
    *((off_t *) c->argv[0]) = nbytes;
    c->argv[1] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[1]) = precedence;

  } else {
    array_header *acl = NULL;
    unsigned int argc;
    void **argv;

    argc = cmd->argc - 4;
    argv = cmd->argv + 3;

    acl = pr_expr_create(cmd->tmp_pool, &argc, (char **) argv);

    c = add_config_param(cmd->argv[0], 0);
    c->argc = argc + 3;
    c->argv = pcalloc(c->pool, ((argc + 4) * sizeof(void *)));

    argv = c->argv;

    /* Copy in the configured bytes */
    *argv = pcalloc(c->pool, sizeof(unsigned long));
    *((unsigned long *) *argv++) = nbytes;

    /* Copy in the precedence */
    *argv = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) *argv++) = precedence;

    /* Copy in the classifier. */
    *argv++ = pstrdup(c->pool, cmd->argv[3]);

    if (argc && acl) {
      while (argc--) {
        *argv++ = pstrdup(c->pool, *((char **) acl->elts));
        acl->elts = ((char **) acl->elts) + 1;
      }
    }

    /* Don't forget the terminating NULL */
    *argv = NULL;
  }

  c->flags |= CF_MERGEDOWN_MULTI;

  return PR_HANDLED(cmd);
}

/* usage: MaxTransfersPerHost cmdlist count [msg] */
MODRET set_maxtransfersperhost(cmd_rec *cmd) {
  config_rec *c = NULL;
  int count = 0;

  if (cmd->argc-1 < 2 ||
      cmd->argc-1 > 3)
    CONF_ERROR(cmd, "bad number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR|CONF_DYNDIR);

  count = atoi(cmd->argv[2]);
  if (count < 1)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "count must be greater than zero: '",
      cmd->argv[2], "'", NULL));

  c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);

  /* Parse the command list. */
  if (xfer_parse_cmdlist(cmd->argv[0], c, cmd->argv[1]) < 0)
    CONF_ERROR(cmd, "error with command list");

  c->argv[1] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[1]) = count;

  if (cmd->argc-1 == 3)
    c->argv[2] = pstrdup(c->pool, cmd->argv[3]);

  c->flags |= CF_MERGEDOWN_MULTI;

  return PR_HANDLED(cmd);
}

/* usage: MaxTransfersPerUser cmdlist count [msg] */
MODRET set_maxtransfersperuser(cmd_rec *cmd) {
  config_rec *c = NULL;
  int count = 0;

  if (cmd->argc-1 < 2 ||
      cmd->argc-1 > 3) 
    CONF_ERROR(cmd, "bad number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR|CONF_DYNDIR);

  count = atoi(cmd->argv[2]);
  if (count < 1)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "count must be greater than zero: '",
      cmd->argv[2], "'", NULL));

  c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);

  /* Parse the command list. */
  if (xfer_parse_cmdlist(cmd->argv[0], c, cmd->argv[1]) < 0)
    CONF_ERROR(cmd, "error with command list");

  c->argv[1] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[1]) = count;

  if (cmd->argc-1 == 3)
    c->argv[2] = pstrdup(c->pool, cmd->argv[3]);

  c->flags |= CF_MERGEDOWN_MULTI;

  return PR_HANDLED(cmd);
}

MODRET set_storeuniqueprefix(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR|CONF_DYNDIR);

  /* make sure there are no slashes in the prefix */
  if (strchr(cmd->argv[1], '/') != NULL)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "no slashes allowed in prefix: '",
      cmd->argv[1], "'", NULL));

  c = add_config_param_str(cmd->argv[0], 1, (void *) cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET set_timeoutnoxfer(cmd_rec *cmd) {
  int timeout = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if (pr_str_get_duration(cmd->argv[1], &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      cmd->argv[1], "': ", strerror(errno), NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET set_timeoutstalled(cmd_rec *cmd) {
  int timeout = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if (pr_str_get_duration(cmd->argv[1], &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      cmd->argv[1], "': ", strerror(errno), NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: TransferOptions opt1 opt2 ... */
MODRET set_transferoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcasecmp(cmd->argv[i], "IgnoreASCII") == 0) {
      opts |= PR_XFER_OPT_IGNORE_ASCII;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown TransferOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: TransferRate cmds kbps[:free-bytes] ["user"|"group"|"class"
 *          expression]
 */
MODRET set_transferrate(cmd_rec *cmd) {
  config_rec *c = NULL;
  char *tmp = NULL, *endp = NULL;
  long double rate = 0.0;
  off_t freebytes = 0;
  unsigned int precedence = 0;

  int ctxt = (cmd->config && cmd->config->config_type != CONF_PARAM ?
     cmd->config->config_type : cmd->server->config_type ?
     cmd->server->config_type : CONF_ROOT);

  /* Must have two or four parameters */
  if (cmd->argc-1 != 2 && cmd->argc-1 != 4)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR|CONF_DYNDIR);

  /* Set the precedence for this config_rec based on its configuration
   * context.
   */
  if (ctxt & CONF_GLOBAL)
    precedence = 1;

  /* These will never appear simultaneously */
  else if (ctxt & CONF_ROOT || ctxt & CONF_VIRTUAL)
    precedence = 2;

  else if (ctxt & CONF_ANON)
    precedence = 3;

  else if (ctxt & CONF_DIR)
    precedence = 4;

  /* Note: by tweaking this value to be lower than the precedence for
   * <Directory> appearances of this directive, I can effectively cause
   * any .ftpaccess appearances not to override...
   */
  else if (ctxt & CONF_DYNDIR)
    precedence = 5;

  /* Check for a valid classifier. */
  if (cmd->argc-1 > 2) {
    if (strncmp(cmd->argv[3], "user", 5) == 0 ||
        strncmp(cmd->argv[3], "group", 6) == 0 ||
        strncmp(cmd->argv[3], "class", 6) == 0) {
      /* do nothing */
      ;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown classifier requested: '",
        cmd->argv[3], "'", NULL));
    }
  }

  if ((tmp = strchr(cmd->argv[2], ':')) != NULL)
    *tmp = '\0';

  /* Parse the 'kbps' part.  Ideally, we'd be using strtold(3) rather than
   * strtod(3) here, but FreeBSD doesn't have strtold(3).  Yay.  Portability.
   */
  rate = (long double) strtod(cmd->argv[2], &endp);

  if (rate < 0.0)
    CONF_ERROR(cmd, "rate must be greater than zero");

  if (endp && *endp)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "invalid number: '",
      cmd->argv[2], "'", NULL));

  /* Parse any 'free-bytes' part */
  if (tmp) {
    cmd->argv[2] = ++tmp;

    freebytes = strtoul(cmd->argv[2], &endp, 10);
    if (endp && *endp) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "invalid number: '",
        cmd->argv[2], "'", NULL));
    }
  }

  /* Construct the config_rec */
  if (cmd->argc-1 == 2) {
    c = add_config_param(cmd->argv[0], 4, NULL, NULL, NULL, NULL);

    /* Parse the command list. */
    if (xfer_parse_cmdlist(cmd->argv[0], c, cmd->argv[1]) < 0)
      CONF_ERROR(cmd, "error with command list");

    c->argv[1] = pcalloc(c->pool, sizeof(long double));
    *((long double *) c->argv[1]) = rate;
    c->argv[2] = pcalloc(c->pool, sizeof(off_t));
    *((off_t *) c->argv[2]) = freebytes;
    c->argv[3] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[3]) = precedence;

  } else {
    array_header *acl = NULL;
    unsigned int argc;
    void **argv;

    argc = cmd->argc - 4;
    argv = cmd->argv + 3;

    acl = pr_expr_create(cmd->tmp_pool, &argc, (char **) argv);
    c = add_config_param(cmd->argv[0], 0);

    /* Parse the command list.
     *
     * The five additional slots are for: cmd-list, bps, free-bytes,
     * precedence, user/group/class.
     */
    c->argc = argc + 5;

    c->argv = pcalloc(c->pool, ((c->argc + 1) * sizeof(void *)));
    argv = c->argv;

    if (xfer_parse_cmdlist(cmd->argv[0], c, cmd->argv[1]) < 0) {
      CONF_ERROR(cmd, "error with command list");
    }

    /* Note: the command list is at index 0, hence this increment. */
    argv++;

    *argv = pcalloc(c->pool, sizeof(long double));
    *((long double *) *argv++) = rate;
    *argv = pcalloc(c->pool, sizeof(off_t));
    *((unsigned long *) *argv++) = freebytes;
    *argv = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) *argv++) = precedence;

    *argv++ = pstrdup(c->pool, cmd->argv[3]);

    if (argc && acl) {
      while (argc--) {
        *argv++ = pstrdup(c->pool, *((char **) acl->elts));
        acl->elts = ((char **) acl->elts) + 1;
      }
    }

    /* don't forget the terminating NULL */
    *argv = NULL;
  }

  c->flags |= CF_MERGEDOWN_MULTI;
  return PR_HANDLED(cmd);
}

/* usage: UseSendfile on|off|"len units"|percentage"%" */
MODRET set_usesendfile(cmd_rec *cmd) {
  int bool = -1;
  off_t sendfile_len = 0;
  float sendfile_pct = -1.0;
  config_rec *c;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR|CONF_DYNDIR);

  if (cmd->argc-1 == 1) {
    /* Is the given parameter a boolean, or a percentage?  Try parsing it a
     * boolean first.
     */
    bool = get_boolean(cmd, 1);
    if (bool == -1) {
      char *arg;
      size_t arglen;

      /* See if the given parameter is a percentage. */
      arg = cmd->argv[1];
      arglen = strlen(arg);
      if (arglen > 1 &&
          arg[arglen-1] == '%') {
          char *ptr = NULL;
  
          arg[arglen-1] = '\0';

#ifdef HAVE_STRTOF
          sendfile_pct = strtof(arg, &ptr);
#elif HAVE_STRTOD
          sendfile_pct = strtod(arg, &ptr);
#else
          sendfile_pct = atof(arg);
#endif /* !HAVE_STRTOF and !HAVE_STRTOD */

          if (ptr && *ptr) {
            CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad percentage value '",
              arg, "%'", NULL));
          }

          sendfile_pct /= 100.0;
          bool = TRUE;

      } else {
        CONF_ERROR(cmd, "expected Boolean parameter");
      }
    }

  } else if (cmd->argc-1 == 2) {
    off_t nbytes;

    if (pr_str_get_nbytes(cmd->argv[1], cmd->argv[2], &nbytes) < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to parse: ",
        cmd->argv[1], " ", cmd->argv[2], ": ", strerror(errno), NULL));
    }

    sendfile_len = nbytes;
    bool = TRUE;
  
  } else {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;
  c->argv[1] = pcalloc(c->pool, sizeof(off_t));
  *((off_t *) c->argv[1]) = sendfile_len;
  c->argv[2] = pcalloc(c->pool, sizeof(float));
  *((float *) c->argv[2]) = sendfile_pct;

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

/* Event handlers
 */

static void xfer_exit_ev(const void *event_data, void *user_data) {

  if (stor_fh != NULL) {
     /* An upload is occurring... */
    pr_trace_msg(trace_channel, 6, "session exiting, aborting upload");
    stor_abort(session.pool);
  
  } else if (retr_fh != NULL) {
    /* A download is occurring... */
    pr_trace_msg(trace_channel, 6, "session exiting, aborting download");
    retr_abort(session.pool);
  }

  if (session.sf_flags & SF_XFER) {
    cmd_rec *cmd;
    pr_data_abort(0, FALSE);

    cmd = session.curr_cmd_rec;
    if (cmd == NULL) {
      cmd = pr_cmd_alloc(session.pool, 2, session.curr_cmd, session.xfer.path);
    }

    (void) pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
    (void) pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
  }

  return;
}

static void xfer_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&xfer_module, "core.exit", xfer_exit_ev);
  pr_event_unregister(&xfer_module, "core.session-reinit", xfer_sess_reinit_ev);
  pr_event_unregister(&xfer_module, "core.signal.USR2", xfer_sigusr2_ev);
  pr_event_unregister(&xfer_module, "core.timeout-stalled",
    xfer_timeout_stalled_ev);

  if (displayfilexfer_fh != NULL) {
    (void) pr_fsio_close(displayfilexfer_fh);
    displayfilexfer_fh = NULL;
  }

  res = xfer_sess_init();
  if (res < 0) {
    pr_session_disconnect(&xfer_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

static void xfer_sigusr2_ev(const void *event_data, void *user_data) {

  if (pr_module_exists("mod_shaper.c")) {
    /* Only do this if we're currently involved in a data transfer.
     * This is a hack put in to support mod_shaper's antics.
     */
    if (session.curr_cmd_id == PR_CMD_APPE_ID ||
        session.curr_cmd_id == PR_CMD_RETR_ID ||
        session.curr_cmd_id == PR_CMD_STOR_ID ||
        session.curr_cmd_id == PR_CMD_STOU_ID) {
      pool *tmp_pool;
      cmd_rec *cmd;

      tmp_pool = make_sub_pool(session.pool);
      pr_pool_tag(tmp_pool, "Data Transfer SIGUSR2 pool");

      cmd = pr_cmd_alloc(tmp_pool, 1, session.curr_cmd);

      /* Rescan the config tree for TransferRates, picking up any possible
       * changes.
       */
      pr_log_debug(DEBUG2, "rechecking TransferRates");
      pr_throttle_init(cmd);

      destroy_pool(tmp_pool);
    }
  }

  return;
}

static void xfer_timedout(const char *reason) {
  if (stor_fh != NULL) {
    pr_trace_msg(trace_channel, 6, "%s, aborting upload", reason);
    stor_abort(session.pool);

  } else if (retr_fh != NULL) {
    pr_trace_msg(trace_channel, 6, "%s, aborting download", reason);
    retr_abort(session.pool);
  }
}

static void xfer_timeout_session_ev(const void *event_data, void *user_data) {
  xfer_timedout("session timeout");
}

static void xfer_timeout_stalled_ev(const void *event_data, void *user_data) {
  /* In this event handler, the "else" case, for a stalled transfer, will
   * be handled by the 'core.exit' event handler above.  For in that
   * scenario, a data transfer WILL have actually been in progress,
   * whereas in the !SF_XFER case, the client requested a transfer, but
   * never actually opened the data connection.
   */

  if (!(session.sf_flags & SF_XFER)) {
    xfer_timedout("transfer stalled");
  }
}

/* Initialization routines
 */

static int xfer_init(void) {

  /* Add the commands handled by this module to the HELP list. */
  pr_help_add(C_TYPE, _("<sp> type-code (A, I, L 7, L 8)"), TRUE);
  pr_help_add(C_STRU, _("is not implemented (always F)"), TRUE);
  pr_help_add(C_MODE, _("is not implemented (always S)"), TRUE);
  pr_help_add(C_RETR, _("<sp> pathname"), TRUE);
  pr_help_add(C_STOR, _("<sp> pathname"), TRUE);
  pr_help_add(C_STOU, _("(store unique filename)"), TRUE);
  pr_help_add(C_APPE, _("<sp> pathname"), TRUE);
  pr_help_add(C_REST, _("<sp> byte-count"), TRUE);
  pr_help_add(C_ABOR, _("(abort current operation)"), TRUE);
  pr_help_add(C_RANG, _("<sp> start-point <sp> end-point"), TRUE);

  /* Add the additional features implemented by this module into the
   * list, to be displayed in response to a FEAT command.
   */
  pr_feat_add(C_RANG " STREAM");

  return 0;
}

static int xfer_sess_init(void) {
  char *displayfilexfer = NULL;

  /* Exit handlers for HiddenStores cleanup */
  pr_event_register(&xfer_module, "core.exit", xfer_exit_ev, NULL);
  pr_event_register(&xfer_module, "core.session-reinit", xfer_sess_reinit_ev,
    NULL);
  pr_event_register(&xfer_module, "core.signal.USR2", xfer_sigusr2_ev,
    NULL);
  pr_event_register(&xfer_module, "core.timeout-session",
    xfer_timeout_session_ev, NULL);
  pr_event_register(&xfer_module, "core.timeout-stalled",
    xfer_timeout_stalled_ev, NULL);

  have_type = FALSE;

  /* Look for a DisplayFileTransfer file which has an absolute path.  If we
   * find one, open a filehandle, such that that file can be displayed
   * even if the session is chrooted.  DisplayFileTransfer files with
   * relative paths will be handled after chroot, preserving the old
   * behavior.
   */
  displayfilexfer = get_param_ptr(main_server->conf, "DisplayFileTransfer",
    FALSE);
  if (displayfilexfer &&
      *displayfilexfer == '/') {
    struct stat st;

    displayfilexfer_fh = pr_fsio_open(displayfilexfer, O_RDONLY);
    if (displayfilexfer_fh == NULL) {
      pr_log_debug(DEBUG6, "unable to open DisplayFileTransfer file '%s': %s",
        displayfilexfer, strerror(errno));

    } else {
      if (pr_fsio_fstat(displayfilexfer_fh, &st) < 0) {
        pr_log_debug(DEBUG6, "unable to stat DisplayFileTransfer file '%s': %s",
          displayfilexfer, strerror(errno));
        pr_fsio_close(displayfilexfer_fh);
        displayfilexfer_fh = NULL;

      } else {
        if (S_ISDIR(st.st_mode)) {
          errno = EISDIR;

          pr_log_debug(DEBUG6,
            "unable to use DisplayFileTransfer file '%s': %s",
            displayfilexfer, strerror(errno));
          pr_fsio_close(displayfilexfer_fh);
          displayfilexfer_fh = NULL;
        }
      }
    }
  }

  /* IF the RFC2228 mechanism is "TLS" at this point in time, then set the flag
   * to disable use of sendfile; the client is probably an FTPS client using
   * implicit SSL (Bug#4073).
   */
  if (session.rfc2228_mech != NULL &&
      strncmp(session.rfc2228_mech, "TLS", 4) == 0) {
    have_rfc2228_data = TRUE;
  }

  return 0;
}

/* Module API tables
 */

static conftable xfer_conftab[] = {
  { "AllowOverwrite",		set_allowoverwrite,		NULL },
  { "AllowRetrieveRestart",	set_allowrestart,		NULL },
  { "AllowStoreRestart",	set_allowrestart,		NULL },
  { "DefaultTransferMode",	set_defaulttransfermode,	NULL },
  { "DeleteAbortedStores",	set_deleteabortedstores,	NULL },
  { "DisplayFileTransfer",	set_displayfiletransfer,	NULL },
  { "HiddenStores",		set_hiddenstores,		NULL },
  { "MaxRetrieveFileSize",	set_maxfilesize,		NULL },
  { "MaxStoreFileSize",		set_maxfilesize,		NULL },
  { "MaxTransfersPerHost",	set_maxtransfersperhost,	NULL },
  { "MaxTransfersPerUser",	set_maxtransfersperuser,	NULL },
  { "StoreUniquePrefix",	set_storeuniqueprefix,		NULL },
  { "TimeoutNoTransfer",	set_timeoutnoxfer,		NULL },
  { "TimeoutStalled",		set_timeoutstalled,		NULL },
  { "TransferOptions",		set_transferoptions,		NULL },
  { "TransferRate",		set_transferrate,		NULL },
  { "UseSendfile",		set_usesendfile,		NULL },

  { NULL }
};

static cmdtable xfer_cmdtab[] = {
  { CMD,     C_TYPE,	G_NONE,	 xfer_type,	FALSE,	FALSE, CL_MISC },
  { CMD,     C_STRU,	G_NONE,	 xfer_stru,	TRUE,	FALSE, CL_MISC },
  { CMD,     C_MODE,	G_NONE,	 xfer_mode,	TRUE,	FALSE, CL_MISC },
  { POST_CMD,C_MODE,	G_NONE,  xfer_post_mode,FALSE,	FALSE },
  { CMD,     C_ALLO,	G_NONE,	 xfer_allo,	TRUE,	FALSE, CL_MISC },
  { CMD,     C_SMNT,	G_NONE,	 xfer_smnt,	TRUE,	FALSE, CL_MISC },
  { PRE_CMD, C_RETR,	G_READ,	 xfer_pre_retr,	TRUE,	FALSE },
  { CMD,     C_RETR,	G_READ,	 xfer_retr,	TRUE,	FALSE, CL_READ },
  { POST_CMD,C_RETR,	G_NONE,  xfer_post_retr,FALSE,	FALSE },
  { LOG_CMD, C_RETR,	G_NONE,	 xfer_log_retr,	FALSE,  FALSE },
  { LOG_CMD_ERR, C_RETR,G_NONE,  xfer_err_cleanup,  FALSE,  FALSE },
  { PRE_CMD, C_STOR,	G_WRITE, xfer_pre_stor,	TRUE,	FALSE },
  { CMD,     C_STOR,	G_WRITE, xfer_stor,	TRUE,	FALSE, CL_WRITE },
  { POST_CMD,C_STOR,	G_NONE,  xfer_post_stor,FALSE,	FALSE },
  { LOG_CMD, C_STOR,    G_NONE,	 xfer_log_stor,	FALSE,  FALSE },
  { LOG_CMD_ERR, C_STOR,G_NONE,  xfer_err_cleanup,  FALSE,  FALSE },
  { PRE_CMD, C_STOU,	G_WRITE, xfer_pre_stou,	TRUE,	FALSE },
  { CMD,     C_STOU,	G_WRITE, xfer_stor,	TRUE,	FALSE, CL_WRITE },
  { POST_CMD,C_STOU,	G_WRITE, xfer_post_stou,FALSE,	FALSE },
  { LOG_CMD, C_STOU,	G_NONE,  xfer_log_stor,	FALSE,	FALSE },
  { LOG_CMD_ERR, C_STOU,G_NONE,  xfer_err_cleanup,  FALSE,  FALSE },
  { PRE_CMD, C_APPE,	G_WRITE, xfer_pre_appe,	TRUE,	FALSE },
  { CMD,     C_APPE,	G_WRITE, xfer_stor,	TRUE,	FALSE, CL_WRITE },
  { POST_CMD,C_APPE,	G_NONE,  xfer_post_stor,FALSE,	FALSE },
  { LOG_CMD, C_APPE,	G_NONE,  xfer_log_stor,	FALSE,  FALSE },
  { LOG_CMD_ERR, C_APPE,G_NONE,  xfer_err_cleanup,  FALSE,  FALSE },
  { CMD,     C_ABOR,	G_NONE,	 xfer_abor,	TRUE,	TRUE,  CL_MISC  },
  { LOG_CMD, C_ABOR,	G_NONE,	 xfer_log_abor,	TRUE,	TRUE,  CL_MISC  },
  { CMD,     C_REST,	G_NONE,	 xfer_rest,	TRUE,	FALSE, CL_MISC  },
  { CMD,     C_RANG,	G_NONE,	 xfer_rang,	TRUE,	FALSE, CL_MISC  },
  { POST_CMD,C_PROT,	G_NONE,  xfer_post_prot,	FALSE,	FALSE },
  { POST_CMD,C_PASS,	G_NONE,	 xfer_post_pass,	FALSE, FALSE },
  { 0, NULL }
};

module xfer_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "xfer",

  /* Module configuration directive table */
  xfer_conftab,

  /* Module command handler table */
  xfer_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  xfer_init,

  /* Session initialization function */
  xfer_sess_init
};
