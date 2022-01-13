/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2009-2017 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

#include "conf.h"

/* From src/main.c */
extern unsigned char is_master;

static void sess_cleanup(int flags) {

  /* Clear the scoreboard entry. */
  if (ServerType == SERVER_STANDALONE) {

    /* For standalone daemons, we only clear the scoreboard slot if we are
     * an exiting child process.
     */

    if (!is_master) {
      if (pr_scoreboard_entry_del(TRUE) < 0 &&
          errno != EINVAL &&
          errno != ENOENT) {
        pr_log_debug(DEBUG1, "error deleting scoreboard entry: %s",
          strerror(errno));
      }
    }

  } else if (ServerType == SERVER_INETD) {
    /* For inetd-spawned daemons, we always clear the scoreboard slot. */
    if (pr_scoreboard_entry_del(TRUE) < 0 &&
        errno != EINVAL &&
        errno != ENOENT) {
      pr_log_debug(DEBUG1, "error deleting scoreboard entry: %s",
        strerror(errno));
    }
  }

  /* If session.user is set, we have a valid login. */
  if (session.user &&
      session.wtmp_log) {
    const char *sess_ttyname;

    sess_ttyname = pr_session_get_ttyname(session.pool);
    log_wtmp(sess_ttyname, "", pr_netaddr_get_sess_remote_name(),
      pr_netaddr_get_sess_remote_addr());
  }

  /* These are necessary in order that cleanups associated with these pools
   * (and their subpools) are properly run.
   */
  if (session.d) {
    pr_inet_close(session.pool, session.d);
    session.d = NULL;
  }

  if (session.c) {
    pr_inet_close(session.pool, session.c);
    session.c = NULL;
  }

  /* Run all the exit handlers */
  pr_event_generate("core.exit", NULL);

  if (!is_master ||
      (ServerType == SERVER_INETD &&
      !(flags & PR_SESS_END_FL_SYNTAX_CHECK))) {
    pr_log_pri(PR_LOG_INFO, "%s session closed.",
      pr_session_get_protocol(PR_SESS_PROTO_FL_LOGOUT));
  }

  log_closesyslog();
}

void pr_session_disconnect(module *m, int reason_code,
    const char *details) {
  int flags = 0;

  session.disconnect_reason = reason_code;
  session.disconnect_module = m;

  if (details != NULL &&
      session.notes != NULL) {
    /* Stash any extra details in the session.notes table */
    if (pr_table_add_dup(session.notes, "core.disconnect-details",
        (char *) details, 0) < 0) {
      int xerrno = errno;

      if (xerrno != EEXIST) {
        pr_log_debug(DEBUG5, "error stashing 'core.disconnect-details' in "
          "session.notes: %s", strerror(xerrno));
      }
    }
  }

  if (reason_code == PR_SESS_DISCONNECT_SEGFAULT) {
    flags |= PR_SESS_END_FL_ERROR;
  }

  pr_session_end(flags);
}

void pr_session_end(int flags) {
  int exitcode = 0;

  sess_cleanup(flags);

  if (flags & PR_SESS_END_FL_NOEXIT) {
    return;
  }

  if (flags & PR_SESS_END_FL_ERROR) {
    exitcode = 1;
  }

#ifdef PR_USE_DEVEL
  destroy_pool(session.pool);

  if (is_master) {
    main_server = NULL;
    free_pools();
    pr_proctitle_free();
  }
#endif /* PR_USE_DEVEL */

#ifdef PR_DEVEL_PROFILE
  /* Populating the gmon.out gprof file requires that the process exit
   * via exit(3) or by returning from main().  Using _exit(2) doesn't allow
   * the process the time to write its profile data out.
   */
  exit(exitcode);
#else
  _exit(exitcode);
#endif /* PR_DEVEL_PROFILE */
}

const char *pr_session_get_disconnect_reason(const char **details) {
  const char *reason_str = NULL;

  switch (session.disconnect_reason) {
    case PR_SESS_DISCONNECT_UNSPECIFIED:
      reason_str = "Unknown/unspecified";
      break;

    case PR_SESS_DISCONNECT_CLIENT_QUIT:
      reason_str = "Quit";
      break;

    case PR_SESS_DISCONNECT_CLIENT_EOF:
      reason_str = "Read EOF from client";
      break;

    case PR_SESS_DISCONNECT_SESSION_INIT_FAILED:
      reason_str = "Session initialized failed";
      break;

    case PR_SESS_DISCONNECT_SIGNAL:
      reason_str = "Terminated by signal";
      break;

    case PR_SESS_DISCONNECT_NOMEM:
      reason_str = "Low memory";
      break;

    case PR_SESS_DISCONNECT_SERVER_SHUTDOWN:
      reason_str = "Server shutting down";
      break;

    case PR_SESS_DISCONNECT_TIMEOUT:
      reason_str = "Timeout exceeded";
      break;

    case PR_SESS_DISCONNECT_BANNED:
      reason_str = "Banned";
      break;

    case PR_SESS_DISCONNECT_CONFIG_ACL:
      reason_str = "Configured policy";
      break;

    case PR_SESS_DISCONNECT_MODULE_ACL:
      reason_str = "Module-specific policy";
      break;

    case PR_SESS_DISCONNECT_BAD_CONFIG:
      reason_str = "Server misconfiguration";
      break;

    case PR_SESS_DISCONNECT_BY_APPLICATION:
      reason_str = "Application error";
      break;
  }

  if (details != NULL) {
    *details = pr_table_get(session.notes, "core.disconnect-details", NULL);
  }

  return reason_str;
}

const char *pr_session_get_protocol(int flags) {
  const char *sess_proto;

  sess_proto = pr_table_get(session.notes, "protocol", NULL);
  if (sess_proto == NULL) {
    sess_proto = "ftp";
  }

  if (!(flags & PR_SESS_PROTO_FL_LOGOUT)) {
    /* Return the protocol as is. */
    return sess_proto;
  }

  /* Otherwise, we need to return either "FTP" or "SSH2", for consistency. */
  if (strncmp(sess_proto, "ftp", 4) == 0 ||
      strncmp(sess_proto, "ftps", 5) == 0) {
    return "FTP";
  
  } else if (strncmp(sess_proto, "ssh2", 5) == 0 ||
             strncmp(sess_proto, "sftp", 5) == 0 ||
             strncmp(sess_proto, "scp", 4) == 0 ||
             strncmp(sess_proto, "publickey", 10) == 0) {
    return "SSH2";
  }

  /* Should never reach here, but just in case... */
  return "unknown";
}

void pr_session_send_banner(server_rec *s, int flags) {
  config_rec *c = NULL;
  char *display = NULL;
  const char *serveraddress = NULL;
  config_rec *masq = NULL;

  display = get_param_ptr(s->conf, "DisplayConnect", FALSE);
  if (display != NULL) {
    if (pr_display_file(display, NULL, R_220, flags) < 0) {
      pr_log_debug(DEBUG6, "unable to display DisplayConnect file '%s': %s",
        display, strerror(errno));
    }
  }

  serveraddress = pr_netaddr_get_ipstr(session.c->local_addr);

  masq = find_config(s->conf, CONF_PARAM, "MasqueradeAddress", FALSE);
  if (masq != NULL) {
    const pr_netaddr_t *masq_addr = NULL;

    if (masq->argv[0] != NULL) {
      masq_addr = masq->argv[0];

    } else {
      const char *name;

      /* Here we do a delayed lookup, to see if the configured name
       * can be resolved yet (e.g. the network is now up); see Bug#4104.
       */

      name = masq->argv[1];

      pr_log_debug(DEBUG10,
        "performing delayed resolution of MasqueradeAddress '%s'", name);
      masq_addr = pr_netaddr_get_addr(session.pool, name, NULL);
      if (masq_addr != NULL) {
        /* Stash the resolved pr_netaddr_t in the config_rec, so that other
         * code paths will find it (within this session process).
         */
        masq->argv[0] = (void *) masq_addr;

      } else {
        pr_log_debug(DEBUG5, "unable to resolve '%s'", name);
      }
    }

    if (masq_addr != NULL) {
      serveraddress = pr_netaddr_get_ipstr(masq_addr);
    }
  }

  c = find_config(s->conf, CONF_PARAM, "ServerIdent", FALSE);
  if (c == NULL ||
      *((unsigned char *) c->argv[0]) == TRUE) {
    unsigned char *defer_welcome;

    defer_welcome = get_param_ptr(s->conf, "DeferWelcome", FALSE);

    if (c &&
        c->argc > 1) {
      const char *server_ident;

      server_ident = c->argv[1];

      if (strstr(server_ident, "%L") != NULL) {
        server_ident = sreplace(session.pool, server_ident, "%L",
          serveraddress, NULL);
      }

      if (strstr(server_ident, "%V") != NULL) {
        server_ident = sreplace(session.pool, server_ident, "%V",
          main_server->ServerFQDN, NULL);
      }

      if (strstr(server_ident, "%v") != NULL) {
        server_ident = sreplace(session.pool, server_ident, "%v",
          main_server->ServerName, NULL);
      }

      if (strstr(server_ident, "%{version}") != NULL) {
        server_ident = sreplace(session.pool, server_ident, "%{version}",
          PROFTPD_VERSION_TEXT, NULL);
      }

      if (flags & PR_DISPLAY_FL_SEND_NOW) {
        pr_response_send(R_220, "%s", server_ident);

      } else {
        pr_response_add(R_220, "%s", server_ident);
      }

    } else if (defer_welcome &&
               *defer_welcome == TRUE) {

      if (flags & PR_DISPLAY_FL_SEND_NOW) {
        pr_response_send(R_220, _("ProFTPD Server ready."));

      } else {
        pr_response_add(R_220, _("ProFTPD Server ready."));
      }

    } else {
      if (flags & PR_DISPLAY_FL_SEND_NOW) {
        pr_response_send(R_220, _("ProFTPD Server (%s) [%s]"), s->ServerName,
          serveraddress);

      } else {
        pr_response_add(R_220, _("ProFTPD Server (%s) [%s]"), s->ServerName,
          serveraddress);
      }
    }

  } else {
    if (flags & PR_DISPLAY_FL_SEND_NOW) {
      pr_response_send(R_220, _("%s FTP server ready"), serveraddress);

    } else {
      pr_response_add(R_220, _("%s FTP server ready"), serveraddress);
    }
  }
}

int pr_session_set_idle(void) {
  const char *user = NULL;

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_BEGIN_IDLE, time(NULL),
    PR_SCORE_CMD, "%s", "idle", NULL, NULL);

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", "", NULL, NULL);

  if (session.user) {
    user = session.user;

  } else {
    user = "(authenticating)";
  }

  pr_proctitle_set("%s - %s: IDLE", user, session.proc_prefix);
  return 0;
}

int pr_session_set_protocol(const char *sess_proto) {
  int count, res = 0, xerrno = 0;

  if (sess_proto == NULL) {
    errno = EINVAL;
    return -1;
  }

  count = pr_table_exists(session.notes, "protocol");
  if (count > 0) {
    res = pr_table_set(session.notes, pstrdup(session.pool, "protocol"),
      pstrdup(session.pool, sess_proto), 0);
    xerrno = errno;

  } else {
    res = pr_table_add(session.notes, pstrdup(session.pool, "protocol"),
      pstrdup(session.pool, sess_proto), 0);
    xerrno = errno;
  }

  /* Update the scoreboard entry for this session with the protocol. */
  pr_scoreboard_entry_update(session.pid, PR_SCORE_PROTOCOL, sess_proto, NULL);

  errno = xerrno;
  return res;
}

static const char *sess_ttyname = NULL;

const char *pr_session_get_ttyname(pool *p) {
  char ttybuf[32];
  const char *sess_proto, *tty_proto = NULL;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (sess_ttyname) {
    /* Return the cached name. */
    return pstrdup(p, sess_ttyname);
  }

  sess_proto = pr_table_get(session.notes, "protocol", NULL);
  if (sess_proto) {
    if (strncmp(sess_proto, "ftp", 4) == 0 ||
        strncmp(sess_proto, "ftps", 5) == 0) {
#if (defined(BSD) && (BSD >= 199103))
      tty_proto = "ftp";
#else
      tty_proto = "ftpd";
#endif

    } else if (strncmp(sess_proto, "ssh2", 5) == 0 ||
               strncmp(sess_proto, "sftp", 5) == 0 ||
               strncmp(sess_proto, "scp", 4) == 0 ||
               strncmp(sess_proto, "publickey", 10) == 0) {

      /* Just use the plain "ssh" string for the tty name for these cases. */
      tty_proto = "ssh";

      /* Cache the originally constructed tty name for any later retrievals. */
      sess_ttyname = pstrdup(session.pool, tty_proto);
      return pstrdup(p, sess_ttyname);
    }
  }

  if (tty_proto == NULL) {
#if (defined(BSD) && (BSD >= 199103))
    tty_proto = "ftp";
#else
    tty_proto = "ftpd";
#endif
  }

  memset(ttybuf, '\0', sizeof(ttybuf));
#if (defined(BSD) && (BSD >= 199103))
  pr_snprintf(ttybuf, sizeof(ttybuf), "%s%ld", tty_proto,
    (long) (session.pid ? session.pid : getpid()));
#else
  pr_snprintf(ttybuf, sizeof(ttybuf), "%s%d", tty_proto,
    (int) (session.pid ? session.pid : getpid()));
#endif

  /* Cache the originally constructed tty name for any later retrievals. */
  sess_ttyname = pstrdup(session.pool, ttybuf);

  return pstrdup(p, sess_ttyname);
}
