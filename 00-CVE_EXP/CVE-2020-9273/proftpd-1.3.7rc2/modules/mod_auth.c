/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2017 The ProFTPD Project team
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

/* Authentication module for ProFTPD */

#include "conf.h"
#include "privs.h"

#ifdef HAVE_USERSEC_H
# include <usersec.h>
#endif

#ifdef HAVE_SYS_AUDIT_H
# include <sys/audit.h>
#endif

extern pid_t mpid;

module auth_module;

#ifdef PR_USE_LASTLOG
static unsigned char lastlog = FALSE;
#endif /* PR_USE_LASTLOG */

static unsigned char mkhome = FALSE;
static unsigned char authenticated_without_pass = FALSE;
static int TimeoutLogin = PR_TUNABLE_TIMEOUTLOGIN;
static int logged_in = FALSE;
static int auth_anon_allow_robots = FALSE;
static int auth_anon_allow_robots_enabled = FALSE;
static int auth_client_connected = FALSE;
static unsigned int auth_tries = 0;
static char *auth_pass_resp_code = R_230;
static pr_fh_t *displaylogin_fh = NULL;
static int TimeoutSession = 0;

static int saw_first_user_cmd = FALSE;
static const char *timing_channel = "timing";

static int auth_count_scoreboard(cmd_rec *, const char *);
static int auth_scan_scoreboard(void);
static int auth_sess_init(void);

/* auth_cmd_chk_cb() is hooked into the main server's auth_hook function,
 * so that we can deny all commands until authentication is complete.
 *
 * Note: Once this function returns true (i.e. client has authenticated),
 * it will ALWAYS return true.  At least until REIN is implemented.  Thus
 * we have a flag for such a situation, to save on redundant lookups for
 * the "authenticated" record.
 */
static int auth_have_authenticated = FALSE;

static int auth_cmd_chk_cb(cmd_rec *cmd) {
  if (auth_have_authenticated == FALSE) {
    unsigned char *authd;

    authd = get_param_ptr(cmd->server->conf, "authenticated", FALSE);

    if (authd == NULL ||
        *authd == FALSE) {
      pr_response_send(R_530, _("Please login with USER and PASS"));
      return FALSE;
    }

    auth_have_authenticated = TRUE;
  }

  return TRUE;
}

static int auth_login_timeout_cb(CALLBACK_FRAME) {
  pr_response_send_async(R_421,
    _("Login timeout (%d %s): closing control connection"), TimeoutLogin,
    TimeoutLogin != 1 ? "seconds" : "second");

  /* It's possible that any listeners of this event might terminate the
   * session process themselves (e.g. mod_ban).  So write out that the
   * TimeoutLogin has been exceeded to the log here, in addition to the
   * scheduled session exit message.
   */
  pr_log_pri(PR_LOG_INFO, "%s", "Login timeout exceeded, disconnected");
  pr_event_generate("core.timeout-login", NULL);

  pr_session_disconnect(&auth_module, PR_SESS_DISCONNECT_TIMEOUT,
    "TimeoutLogin");

  /* Do not restart the timer (should never be reached). */
  return 0;
}

static int auth_session_timeout_cb(CALLBACK_FRAME) {
  pr_event_generate("core.timeout-session", NULL);
  pr_response_send_async(R_421,
    _("Session Timeout (%d seconds): closing control connection"),
    TimeoutSession);

  pr_log_pri(PR_LOG_INFO, "%s", "FTP session timed out, disconnected");
  pr_session_disconnect(&auth_module, PR_SESS_DISCONNECT_TIMEOUT,
    "TimeoutSession");

  /* no need to restart the timer -- session's over */
  return 0;
}

/* Event listeners
 */

static void auth_exit_ev(const void *event_data, void *user_data) {
  pr_auth_cache_clear();

  /* Close the scoreboard descriptor that we opened. */
  (void) pr_close_scoreboard(FALSE);
}

static void auth_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&auth_module, "core.exit", auth_exit_ev);
  pr_event_unregister(&auth_module, "core.session-reinit", auth_sess_reinit_ev);

  pr_timer_remove(PR_TIMER_LOGIN, &auth_module);

  /* Reset the CreateHome setting. */
  mkhome = FALSE;

  /* Reset any MaxPasswordSize setting. */
  (void) pr_auth_set_max_password_len(session.pool, 0);

#if defined(PR_USE_LASTLOG)
  lastlog = FALSE;
#endif /* PR_USE_LASTLOG */
  mkhome = FALSE;

  res = auth_sess_init();
  if (res < 0) {
    pr_session_disconnect(&auth_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Initialization functions
 */

static int auth_init(void) {
  /* Add the commands handled by this module to the HELP list. */ 
  pr_help_add(C_USER, _("<sp> username"), TRUE);
  pr_help_add(C_PASS, _("<sp> password"), TRUE);
  pr_help_add(C_ACCT, _("is not implemented"), FALSE);
  pr_help_add(C_REIN, _("is not implemented"), FALSE);

  /* By default, enable auth checking */
  set_auth_check(auth_cmd_chk_cb);

  return 0;
}

static int auth_sess_init(void) {
  config_rec *c = NULL;
  unsigned char *tmp = NULL;

  pr_event_register(&auth_module, "core.session-reinit", auth_sess_reinit_ev,
    NULL);

  /* Check for any MaxPasswordSize. */
  c = find_config(main_server->conf, CONF_PARAM, "MaxPasswordSize", FALSE);
  if (c != NULL) {
    size_t len;

    len = *((size_t *) c->argv[0]);
    (void) pr_auth_set_max_password_len(session.pool, len);
  }

  /* Check for a server-specific TimeoutLogin */
  c = find_config(main_server->conf, CONF_PARAM, "TimeoutLogin", FALSE);
  if (c != NULL) {
    TimeoutLogin = *((int *) c->argv[0]);
  }

  /* Start the login timer */
  if (TimeoutLogin) {
    pr_timer_remove(PR_TIMER_LOGIN, &auth_module);
    pr_timer_add(TimeoutLogin, PR_TIMER_LOGIN, &auth_module,
      auth_login_timeout_cb, "TimeoutLogin");
  }

  if (auth_client_connected == FALSE) {
    int res = 0;

    PRIVS_ROOT
    res = pr_open_scoreboard(O_RDWR);
    PRIVS_RELINQUISH

    if (res < 0) {
      switch (res) {
        case PR_SCORE_ERR_BAD_MAGIC:
          pr_log_debug(DEBUG0, "error opening scoreboard: bad/corrupted file");
          break;

        case PR_SCORE_ERR_OLDER_VERSION:
          pr_log_debug(DEBUG0,
            "error opening scoreboard: bad version (too old)");
          break;

        case PR_SCORE_ERR_NEWER_VERSION:
          pr_log_debug(DEBUG0,
            "error opening scoreboard: bad version (too new)");
          break;

        default:
          pr_log_debug(DEBUG0, "error opening scoreboard: %s", strerror(errno));
          break;
      }
    }
  }

  pr_event_register(&auth_module, "core.exit", auth_exit_ev, NULL);

  if (auth_client_connected == FALSE) {
    /* Create an entry in the scoreboard for this session, if we don't already
     * have one.
     */
    if (pr_scoreboard_entry_get(PR_SCORE_CLIENT_ADDR) == NULL) {
      if (pr_scoreboard_entry_add() < 0) {
        pr_log_pri(PR_LOG_NOTICE, "notice: unable to add scoreboard entry: %s",
          strerror(errno));
      }

      pr_scoreboard_entry_update(session.pid,
        PR_SCORE_USER, "(none)",
        PR_SCORE_SERVER_PORT, main_server->ServerPort,
        PR_SCORE_SERVER_ADDR, session.c->local_addr, session.c->local_port,
        PR_SCORE_SERVER_LABEL, main_server->ServerName,
        PR_SCORE_CLIENT_ADDR, session.c->remote_addr,
        PR_SCORE_CLIENT_NAME, session.c->remote_name,
        PR_SCORE_CLASS, session.conn_class ? session.conn_class->cls_name : "",
        PR_SCORE_PROTOCOL, "ftp",
        PR_SCORE_BEGIN_SESSION, time(NULL),
        NULL);
    }

  } else {
    /* We're probably handling a HOST command, and the server changed; just
     * update the SERVER_LABEL field.
     */
    pr_scoreboard_entry_update(session.pid,
      PR_SCORE_SERVER_LABEL, main_server->ServerName,
      NULL);
  }

  /* Should we create the home for a user, if they don't have one? */
  tmp = get_param_ptr(main_server->conf, "CreateHome", FALSE);
  if (tmp != NULL &&
      *tmp == TRUE) {
    mkhome = TRUE;

  } else {
    mkhome = FALSE;
  }

#ifdef PR_USE_LASTLOG
  /* Use the lastlog file, if supported and requested. */
  tmp = get_param_ptr(main_server->conf, "UseLastlog", FALSE);
  if (tmp &&
      *tmp == TRUE) {
    lastlog = TRUE;

  } else {
    lastlog = FALSE;
  }
#endif /* PR_USE_LASTLOG */

  /* Scan the scoreboard now, in order to tally up certain values for
   * substituting in any of the Display* file variables.  This function
   * also performs the MaxConnectionsPerHost enforcement.
   */
  auth_scan_scoreboard();

  auth_client_connected = TRUE;
  return 0;
}

static int do_auth(pool *p, xaset_t *conf, const char *u, char *pw) {
  char *cpw = NULL;
  config_rec *c;

  if (conf != NULL) {
    c = find_config(conf, CONF_PARAM, "UserPassword", FALSE);
    while (c != NULL) {
      pr_signals_handle();

      if (strcmp(c->argv[0], u) == 0) {
        cpw = (char *) c->argv[1];
        break;
      }

      c = find_config_next(c, c->next, CONF_PARAM, "UserPassword", FALSE);
    }
  }

  if (cpw != NULL) {
    if (pr_auth_getpwnam(p, u) == NULL) {
      int xerrno = errno;

      if (xerrno == ENOENT) {
        pr_log_pri(PR_LOG_NOTICE, "no such user '%s'", u);
      }

      errno = xerrno;
      return PR_AUTH_NOPWD;
    }

    return pr_auth_check(p, cpw, u, pw);
  }

  return pr_auth_authenticate(p, u, pw);
}

/* Command handlers
 */

static void login_failed(pool *p, const char *user) {
#ifdef HAVE_LOGINFAILED
  const char *host, *sess_ttyname;
  int res, xerrno;

  host = pr_netaddr_get_dnsstr(session.c->remote_addr);
  sess_ttyname = pr_session_get_ttyname(p);

  PRIVS_ROOT
  res = loginfailed((char *) user, (char *) host, (char *) sess_ttyname,
    AUDIT_FAIL);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (res < 0) {
    pr_trace_msg("auth", 3, "AIX loginfailed() error for user '%s', "
      "host '%s', tty '%s', reason %d: %s", user, host, sess_ttyname,
      AUDIT_FAIL, strerror(errno));
  }
#endif /* HAVE_LOGINFAILED */
}

MODRET auth_err_pass(cmd_rec *cmd) {
  const char *user;

  user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
  if (user != NULL) {
    login_failed(cmd->tmp_pool, user);
  }

  /* Remove the stashed original USER name here in a LOG_CMD_ERR handler, so
   * that other modules, who may want to lookup the original USER parameter on
   * a failed login in an earlier command handler phase, have a chance to do
   * so.  This removal of the USER parameter on failure was happening directly
   * in the CMD handler previously, thus preventing POST_CMD_ERR handlers from
   * using USER.
   */
  pr_table_remove(session.notes, "mod_auth.orig-user", NULL);

  return PR_HANDLED(cmd);
}

MODRET auth_log_pass(cmd_rec *cmd) {

  /* Only log, to the syslog, that the login has succeeded here, where we
   * know that the login has definitely succeeded.
   */
  pr_log_auth(PR_LOG_INFO, "%s %s: Login successful.",
    (session.anon_config != NULL) ? "ANON" : C_USER, session.user);

  if (cmd->arg != NULL) {
    size_t passwd_len;

    /* And scrub the memory holding the password sent by the client, for
     * safety/security.
     */
    passwd_len = strlen(cmd->arg);
    pr_memscrub(cmd->arg, passwd_len);
  }

  return PR_DECLINED(cmd);
}

static void login_succeeded(pool *p, const char *user) {
#ifdef HAVE_LOGINSUCCESS
  const char *host, *sess_ttyname;
  char *msg = NULL;
  int res, xerrno;

  host = pr_netaddr_get_dnsstr(session.c->remote_addr);
  sess_ttyname = pr_session_get_ttyname(p);

  PRIVS_ROOT
  res = loginsuccess((char *) user, (char *) host, (char *) sess_ttyname, &msg);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (res == 0) {
    if (msg != NULL) {
      pr_trace_msg("auth", 14, "AIX loginsuccess() report: %s", msg);
    }

  } else {
    pr_trace_msg("auth", 3, "AIX loginsuccess() error for user '%s', "
      "host '%s', tty '%s': %s", user, host, sess_ttyname, strerror(errno));
  }

  if (msg != NULL) {
    free(msg);
  }
#endif /* HAVE_LOGINSUCCESS */
}

MODRET auth_post_pass(cmd_rec *cmd) {
  config_rec *c = NULL;
  const char *grantmsg = NULL, *user;
  unsigned int ctxt_precedence = 0;
  unsigned char have_user_timeout, have_group_timeout, have_class_timeout,
    have_all_timeout, *authenticated;
  int root_revoke = TRUE;
  struct stat st;

  /* Was there a preceding USER command? Was the client successfully
   * authenticated?
   */
  authenticated = get_param_ptr(cmd->server->conf, "authenticated", FALSE);

  /* Clear the list of auth-only modules. */
  pr_auth_clear_auth_only_modules();

  if (authenticated != NULL &&
      *authenticated == TRUE) {

    /* At this point, we can look up the Protocols config if the client
     * has been authenticated, which may have been tweaked via mod_ifsession's
     * user/group/class-specific sections.
     */
    c = find_config(main_server->conf, CONF_PARAM, "Protocols", FALSE);
    if (c != NULL) {
      register unsigned int i;
      array_header *protocols;
      char **elts;
      const char *protocol;

      protocols = c->argv[0];
      elts = protocols->elts;

      protocol = pr_session_get_protocol(PR_SESS_PROTO_FL_LOGOUT);

      /* We only want to check for 'ftp' in the configured Protocols list
       * if a) a RFC2228 mechanism (e.g. SSL or GSS) is not in use, and
       *    b) an SSH protocol is not in use.
       */
      if (session.rfc2228_mech == NULL &&
          strncmp(protocol, "SSH2", 5) != 0) {
        int allow_ftp = FALSE;

        for (i = 0; i < protocols->nelts; i++) {
          char *proto;

          proto = elts[i];
          if (proto != NULL) {
            if (strncasecmp(proto, "ftp", 4) == 0) {
              allow_ftp = TRUE;
              break;
            }
          }
        }

        if (!allow_ftp) {
          pr_log_debug(DEBUG0, "%s", "ftp protocol denied by Protocols config");
          pr_response_send(R_530, "%s", _("Login incorrect."));
          pr_session_disconnect(&auth_module, PR_SESS_DISCONNECT_CONFIG_ACL,
            "Denied by Protocols setting");
        }
      }
    }
  }

  user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);

  /* Count up various quantities in the scoreboard, checking them against
   * the Max* limits to see if the session should be barred from going
   * any further.
   */
  auth_count_scoreboard(cmd, session.user);

  /* Check for dynamic configuration.  This check needs to be after the
   * setting of any possible anon_config, as that context may be allowed
   * or denied .ftpaccess-parsing separately from the containing server.
   */
  if (pr_fsio_stat(session.cwd, &st) != -1)
    build_dyn_config(cmd->tmp_pool, session.cwd, &st, TRUE);

  have_user_timeout = have_group_timeout = have_class_timeout =
    have_all_timeout = FALSE;

  c = find_config(TOPLEVEL_CONF, CONF_PARAM, "TimeoutSession", FALSE);
  while (c != NULL) {
    pr_signals_handle();

    if (c->argc == 3) {
      if (strncmp(c->argv[1], "user", 5) == 0) {
        if (pr_expr_eval_user_or((char **) &c->argv[2]) == TRUE) {

          if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

            /* Set the context precedence. */
            ctxt_precedence = *((unsigned int *) c->argv[1]);

            TimeoutSession = *((int *) c->argv[0]);

            have_group_timeout = have_class_timeout = have_all_timeout = FALSE;
            have_user_timeout = TRUE;
          }
        }

      } else if (strncmp(c->argv[1], "group", 6) == 0) {
        if (pr_expr_eval_group_and((char **) &c->argv[2]) == TRUE) {

          if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

            /* Set the context precedence. */
            ctxt_precedence = *((unsigned int *) c->argv[1]);

            TimeoutSession = *((int *) c->argv[0]);

            have_user_timeout = have_class_timeout = have_all_timeout = FALSE;
            have_group_timeout = TRUE;
          }
        }

      } else if (strncmp(c->argv[1], "class", 6) == 0) {
        if (session.conn_class != NULL &&
            strcmp(session.conn_class->cls_name, c->argv[2]) == 0) {

          if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

            /* Set the context precedence. */
            ctxt_precedence = *((unsigned int *) c->argv[1]);

            TimeoutSession = *((int *) c->argv[0]);

            have_user_timeout = have_group_timeout = have_all_timeout = FALSE;
            have_class_timeout = TRUE;
          }
        }
      }

    } else {

      if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

        /* Set the context precedence. */
        ctxt_precedence = *((unsigned int *) c->argv[1]);

        TimeoutSession = *((int *) c->argv[0]);

        have_user_timeout = have_group_timeout = have_class_timeout = FALSE;
        have_all_timeout = TRUE;
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "TimeoutSession", FALSE);
  }

  /* If configured, start a session timer.  The timer ID value for
   * session timers will not be #defined, as I think that is a bad approach.
   * A better mechanism would be to use the random timer ID generation, and
   * store the returned ID in order to later remove the timer.
   */

  if (have_user_timeout || have_group_timeout ||
      have_class_timeout || have_all_timeout) {
    pr_log_debug(DEBUG4, "setting TimeoutSession of %d seconds for current %s",
      TimeoutSession,
      have_user_timeout ? "user" : have_group_timeout ? "group" :
      have_class_timeout ? "class" : "all");
    pr_timer_add(TimeoutSession, PR_TIMER_SESSION, &auth_module,
      auth_session_timeout_cb, "TimeoutSession");
  }

  /* Handle a DisplayLogin file. */
  if (displaylogin_fh) {
    if (!(session.sf_flags & SF_ANON)) {
      if (pr_display_fh(displaylogin_fh, NULL, auth_pass_resp_code, 0) < 0) {
        pr_log_debug(DEBUG6, "unable to display DisplayLogin file '%s': %s",
          displaylogin_fh->fh_path, strerror(errno));
      }

      pr_fsio_close(displaylogin_fh);
      displaylogin_fh = NULL;

    } else {
      /* We're an <Anonymous> login, but there was a previous DisplayLogin
       * configured which was picked up earlier.  Close that filehandle,
       * and look for a new one.
       */
      char *displaylogin;

      pr_fsio_close(displaylogin_fh);
      displaylogin_fh = NULL;

      displaylogin = get_param_ptr(TOPLEVEL_CONF, "DisplayLogin", FALSE);
      if (displaylogin) {
        if (pr_display_file(displaylogin, NULL, auth_pass_resp_code, 0) < 0) {
          pr_log_debug(DEBUG6, "unable to display DisplayLogin file '%s': %s",
            displaylogin, strerror(errno));
        }
      }
    }

  } else {
    char *displaylogin = get_param_ptr(TOPLEVEL_CONF, "DisplayLogin", FALSE);
    if (displaylogin) {
      if (pr_display_file(displaylogin, NULL, auth_pass_resp_code, 0) < 0) {
        pr_log_debug(DEBUG6, "unable to display DisplayLogin file '%s': %s",
          displaylogin, strerror(errno));
      }
    }
  }

  grantmsg = get_param_ptr(TOPLEVEL_CONF, "AccessGrantMsg", FALSE);
  if (grantmsg == NULL) {
    /* Append the final greeting lines. */
    if (session.sf_flags & SF_ANON) {
      pr_response_add(auth_pass_resp_code, "%s",
        _("Anonymous access granted, restrictions apply"));

    } else {
      pr_response_add(auth_pass_resp_code, _("User %s logged in"), user);
    }

  } else {
     /* Handle any AccessGrantMsg directive. */
     grantmsg = sreplace(cmd->tmp_pool, grantmsg, "%u", user, NULL);
     pr_response_add(auth_pass_resp_code, "%s", grantmsg);
  }

  login_succeeded(cmd->tmp_pool, user);

  /* Should we give up root privs completely here? */
  c = find_config(main_server->conf, CONF_PARAM, "RootRevoke", FALSE);
  if (c != NULL) {
    root_revoke = *((int *) c->argv[0]);

    if (root_revoke == FALSE) {
      pr_log_debug(DEBUG8, "retaining root privileges per RootRevoke setting");
    }

  } else {
    /* Do a recursive look for any UserOwner directives; honoring that
     * configuration also requires root privs.
     */
    c = find_config(main_server->conf, CONF_PARAM, "UserOwner", TRUE);
    if (c != NULL) {
      pr_log_debug(DEBUG9, "retaining root privileges per UserOwner setting");
      root_revoke = FALSE;
    }
  }

  if (root_revoke) {
    pr_signals_block();
    PRIVS_ROOT
    PRIVS_REVOKE
    pr_signals_unblock();

    /* Disable future attempts at UID/GID manipulation. */
    session.disable_id_switching = TRUE;

    pr_log_debug(DEBUG0, "RootRevoke in effect, dropped root privs");
  }

  c = find_config(TOPLEVEL_CONF, CONF_PARAM, "AnonAllowRobots", FALSE);
  if (c != NULL) {
    auth_anon_allow_robots = *((int *) c->argv[0]);
  }

  return PR_DECLINED(cmd);
}

/* Determine any applicable chdirs. */
static const char *get_default_chdir(pool *p, xaset_t *conf) {
  config_rec *c;
  const char *dir = NULL;

  c = find_config(conf, CONF_PARAM, "DefaultChdir", FALSE);
  while (c != NULL) {
    int res;

    pr_signals_handle();

    /* Check the groups acl */
    if (c->argc < 2) {
      dir = c->argv[0];
      break;
    }

    res = pr_expr_eval_group_and(((char **) c->argv)+1);
    if (res) {
      dir = c->argv[0];
      break;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "DefaultChdir", FALSE);
  }

  /* If the directory is relative, concatenate w/ session.cwd. */
  if (dir != NULL &&
      *dir != '/' &&
      *dir != '~') {
    dir = pdircat(p, session.cwd, dir, NULL);
  }

  /* Check for any expandable variables. */
  if (dir != NULL) {
    dir = path_subst_uservar(p, &dir);
  }

  return dir;
}

static int is_symlink_path(pool *p, const char *path, size_t pathlen) {
  int res, xerrno = 0;
  struct stat st;
  char *ptr;

  if (pathlen == 0) {
    return 0;
  }

  pr_fs_clear_cache2(path);
  res = pr_fsio_lstat(path, &st);
  if (res < 0) {
    xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "error: unable to check %s: %s", path,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (S_ISLNK(st.st_mode)) {
    errno = EPERM;
    return -1;
  }

  /* To handle the case where a component further up the path might be a
   * symlink (which lstat(2) will NOT handle), we walk the path backwards,
   * calling ourselves recursively.
   */

  ptr = strrchr(path, '/');
  if (ptr != NULL) {
    char *new_path;
    size_t new_pathlen;

    pr_signals_handle();

    new_pathlen = ptr - path;

    /* Make sure our pointer actually changed position. */
    if (new_pathlen == pathlen) {
      return 0;
    }

    new_path = pstrndup(p, path, new_pathlen);

    pr_log_debug(DEBUG10,
      "AllowChrootSymlink: path '%s' not a symlink, checking '%s'", path,
      new_path);
    res = is_symlink_path(p, new_path, new_pathlen);
    if (res < 0) {
      return -1;
    }
  }

  return 0;
}

/* Determine if the user (non-anon) needs a default root dir other than /. */
static int get_default_root(pool *p, int allow_symlinks, const char **root) {
  config_rec *c = NULL;
  const char *dir = NULL;
  int res;

  c = find_config(main_server->conf, CONF_PARAM, "DefaultRoot", FALSE);
  while (c != NULL) {
    pr_signals_handle();

    /* Check the groups acl */
    if (c->argc < 2) {
      dir = c->argv[0];
      break;
    }

    res = pr_expr_eval_group_and(((char **) c->argv)+1);
    if (res) {
      dir = c->argv[0];
      break;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "DefaultRoot", FALSE);
  }

  if (dir != NULL) {
    const char *new_dir;

    /* Check for any expandable variables. */
    new_dir = path_subst_uservar(p, &dir);
    if (new_dir != NULL) {
      dir = new_dir;
    }

    if (strncmp(dir, "/", 2) == 0) {
      dir = NULL;

    } else {
      char *realdir;
      int xerrno = 0;

      if (allow_symlinks == FALSE) {
        char *path, target_path[PR_TUNABLE_PATH_MAX + 1];
        size_t pathlen;

        /* First, deal with any possible interpolation.  dir_realpath() will
         * do this for us, but dir_realpath() ALSO automatically follows
         * symlinks, which is what we do NOT want to do here.
         */

        path = pstrdup(p, dir);
        if (*path != '/') {
          if (*path == '~') {
            if (pr_fs_interpolate(dir, target_path,
                sizeof(target_path)-1) < 0) {
              return -1;
            }

            path = target_path;
          }
        }

        /* Note: lstat(2) is sensitive to the presence of a trailing slash on
         * the path, particularly in the case of a symlink to a directory.
         * Thus to get the correct test, we need to remove any trailing slash
         * that might be present.  Subtle.
         */
        pathlen = strlen(path);
        if (pathlen > 1 &&
            path[pathlen-1] == '/') {
          path[pathlen-1] = '\0';
        }

        PRIVS_USER
        res = is_symlink_path(p, path, pathlen);
        xerrno = errno;
        PRIVS_RELINQUISH

        if (res < 0) {
          if (xerrno == EPERM) {
            pr_log_pri(PR_LOG_WARNING, "error: DefaultRoot %s is a symlink "
              "(denied by AllowChrootSymlinks config)", path);
          }

          errno = EPERM;
          return -1;
        }
      }

      /* We need to be the final user here so that if the user has their home
       * directory with a mode the user proftpd is running (i.e. the User
       * directive) as can not traverse down, we can still have the default
       * root.
       */

      pr_fs_clear_cache2(dir);

      PRIVS_USER
      realdir = dir_realpath(p, dir);
      xerrno = errno;
      PRIVS_RELINQUISH

      if (realdir) {
        dir = realdir;

      } else {
        /* Try to provide a more informative message. */
        char interp_dir[PR_TUNABLE_PATH_MAX + 1];

        memset(interp_dir, '\0', sizeof(interp_dir));
        (void) pr_fs_interpolate(dir, interp_dir, sizeof(interp_dir)-1); 

        pr_log_pri(PR_LOG_NOTICE,
          "notice: unable to use DefaultRoot '%s' [resolved to '%s']: %s",
          dir, interp_dir, strerror(xerrno));

        errno = xerrno;
      }
    }
  }

  *root = dir;
  return 0;
}

static struct passwd *passwd_dup(pool *p, struct passwd *pw) {
  struct passwd *npw;

  npw = pcalloc(p, sizeof(struct passwd));

  npw->pw_name = pstrdup(p, pw->pw_name);
  npw->pw_passwd = pstrdup(p, pw->pw_passwd);
  npw->pw_uid = pw->pw_uid;
  npw->pw_gid = pw->pw_gid;
  npw->pw_gecos = pstrdup(p, pw->pw_gecos);
  npw->pw_dir = pstrdup(p, pw->pw_dir);
  npw->pw_shell = pstrdup(p, pw->pw_shell);

  return npw;
}

static void ensure_open_passwd(pool *p) {
  /* Make sure pass/group is open. */
  pr_auth_setpwent(p);
  pr_auth_setgrent(p);

  /* On some unices the following is necessary to ensure the files
   * are open (BSDI 3.1)
   */
  pr_auth_getpwent(p);
  pr_auth_getgrent(p);

  /* Per Debian bug report:
   *   https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=717235
   * we might want to do another set{pw,gr}ent(), to play better with
   * some NSS modules.
   */
  pr_auth_setpwent(p);
  pr_auth_setgrent(p);
}

/* Next function (the biggie) handles all authentication, setting
 * up chroot() jail, etc.
 */
static int setup_env(pool *p, cmd_rec *cmd, const char *user, char *pass) {
  struct passwd *pw;
  config_rec *c, *tmpc;
  const char *defchdir = NULL, *defroot = NULL, *origuser, *sess_ttyname;
  char *ourname = NULL, *anonname = NULL, *anongroup = NULL, *ugroup = NULL;
  char *xferlog = NULL;
  int aclp, i, res = 0, allow_chroot_symlinks = TRUE, showsymlinks;
  unsigned char *wtmp_log = NULL, *anon_require_passwd = NULL;

  /********************* Authenticate the user here *********************/

  session.hide_password = TRUE;

  origuser = user;
  c = pr_auth_get_anon_config(p, &user, &ourname, &anonname);
  if (c != NULL) {
    pr_trace_msg("auth", 13,
      "found <Anonymous> config: login user = %s, config user = %s, "
      "anon name = %s", user != NULL ? user : "(null)",
      ourname != NULL ? ourname : "(null)",
      anonname != NULL ? anonname : "(null)");
    session.anon_config = c;
  }

  if (user == NULL) {
    pr_log_auth(PR_LOG_NOTICE, "USER %s: user is not a UserAlias from %s [%s] "
      "to %s:%i", origuser, session.c->remote_name,
      pr_netaddr_get_ipstr(session.c->remote_addr),
      pr_netaddr_get_ipstr(session.c->local_addr), session.c->local_port);
    goto auth_failure;
  }

  pw = pr_auth_getpwnam(p, user);
  if (pw == NULL &&
      c != NULL &&
      ourname != NULL) {
    /* If the client is authenticating using an alias (e.g. "AuthAliasOnly on"),
     * then we need to try checking using the real username, too (Bug#4255).
     */
    pr_trace_msg("auth", 16,
      "no user entry found for <Anonymous> alias '%s', using '%s'", user,
      ourname);
    pw = pr_auth_getpwnam(p, ourname);
  }

  if (pw == NULL) {
    int auth_code = PR_AUTH_NOPWD;

    pr_log_auth(PR_LOG_NOTICE,
      "USER %s: no such user found from %s [%s] to %s:%i",
      user, session.c->remote_name,
      pr_netaddr_get_ipstr(session.c->remote_addr),
      pr_netaddr_get_ipstr(session.c->local_addr), session.c->local_port);
    pr_event_generate("mod_auth.authentication-code", &auth_code); 

    goto auth_failure;
  }

  /* Security: other functions perform pw lookups, thus we need to make
   * a local copy of the user just looked up.
   */
  pw = passwd_dup(p, pw);

  if (pw->pw_uid == PR_ROOT_UID) {
    unsigned char *root_allow = NULL;

    pr_event_generate("mod_auth.root-login", NULL);

    /* If RootLogin is set to true, we allow this... even though we
     * still log a warning. :)
     */
    if ((root_allow = get_param_ptr(c ? c->subset : main_server->conf,
        "RootLogin", FALSE)) == NULL || *root_allow != TRUE) {
      if (pass) {
        pr_memscrub(pass, strlen(pass));
      }

      pr_log_auth(PR_LOG_NOTICE, "SECURITY VIOLATION: Root login attempted");
      return 0;
    }
  }

  session.user = pstrdup(p, pw->pw_name);
  session.group = pstrdup(p, pr_auth_gid2name(p, pw->pw_gid));

  /* Set the login_uid and login_uid */
  session.login_uid = pw->pw_uid;
  session.login_gid = pw->pw_gid;

  /* Check for any expandable variables in session.cwd. */
  pw->pw_dir = (char *) path_subst_uservar(p, (const char **) &pw->pw_dir);

  /* Before we check for supplemental groups, check to see if the locally
   * resolved name of the user, returned via auth_getpwnam(), is different
   * from the USER argument sent by the client.  The name can change, since
   * auth modules can play all sorts of neat tricks on us.
   *
   * If the names differ, assume that any cached data in the session.gids
   * and session.groups lists are stale, and clear them out.
   */
  if (strcmp(pw->pw_name, user) != 0) {
    pr_trace_msg("auth", 10, "local user name '%s' differs from client-sent "
      "user name '%s', clearing cached group data", pw->pw_name, user);
    session.gids = NULL;
    session.groups = NULL;
  }

  if (!session.gids &&
      !session.groups) {
    /* Get the supplemental groups.  Note that we only look up the
     * supplemental group credentials if we have not cached the group
     * credentials before, in session.gids and session.groups.  
     *
     * Those credentials may have already been retrieved, as part of the
     * pr_auth_get_anon_config() call.
     */
     res = pr_auth_getgroups(p, pw->pw_name, &session.gids, &session.groups);
     if (res < 1) {
       pr_log_debug(DEBUG5, "no supplemental groups found for user '%s'",
         pw->pw_name);
     }
  }

  tmpc = find_config(main_server->conf, CONF_PARAM, "AllowChrootSymlinks",
    FALSE);
  if (tmpc != NULL) {
    allow_chroot_symlinks = *((int *) tmpc->argv[0]);
  }

  /* If c != NULL from this point on, we have an anonymous login */
  aclp = login_check_limits(main_server->conf, FALSE, TRUE, &i);

  if (c != NULL) {
    anongroup = get_param_ptr(c->subset, "GroupName", FALSE);
    if (anongroup == NULL) {
      anongroup = get_param_ptr(main_server->conf, "GroupName",FALSE);
    }

#ifdef PR_USE_REGEX
    /* Check for configured AnonRejectPasswords regex here, and fail the login
     * if the given password matches the regex.
     */
    tmpc = find_config(c->subset, CONF_PARAM, "AnonRejectPasswords", FALSE);
    if (tmpc != NULL) {
      int re_notmatch;
      pr_regex_t *pw_regex;

      pw_regex = (pr_regex_t *) tmpc->argv[0];
      re_notmatch = *((int *) tmpc->argv[1]);

      if (pw_regex != NULL &&
          pass != NULL) {
        int re_res;

        re_res = pr_regexp_exec(pw_regex, pass, 0, NULL, 0, 0, 0);
        if (re_res == 0 ||
            (re_res != 0 && re_notmatch == TRUE)) {
          char errstr[200] = {'\0'};

          pr_regexp_error(re_res, pw_regex, errstr, sizeof(errstr));
          pr_log_auth(PR_LOG_NOTICE,
            "ANON %s: AnonRejectPasswords denies login", origuser);
 
          pr_event_generate("mod_auth.anon-reject-passwords", session.c);
          goto auth_failure;
        }
      }
    }
#endif

    if (!login_check_limits(c->subset, FALSE, TRUE, &i) || (!aclp && !i) ){
      pr_log_auth(PR_LOG_NOTICE, "ANON %s (Login failed): Limit access denies "
        "login", origuser);
      goto auth_failure;
    }
  }

  if (c == NULL &&
      aclp == 0) {
    pr_log_auth(PR_LOG_NOTICE,
      "USER %s (Login failed): Limit access denies login", origuser);
    goto auth_failure;
  }

  if (c != NULL) {
    anon_require_passwd = get_param_ptr(c->subset, "AnonRequirePassword",
      FALSE);
  }

  if (c == NULL ||
      (anon_require_passwd != NULL &&
       *anon_require_passwd == TRUE)) {
    int auth_code;
    const char *user_name = user;

    if (c != NULL &&
        origuser != NULL &&
        strcasecmp(user, origuser) != 0) {
      unsigned char *auth_using_alias;

      auth_using_alias = get_param_ptr(c->subset, "AuthUsingAlias", FALSE);

      /* If 'AuthUsingAlias' set and we're logging in under an alias,
       * then auth using that alias.
       */
      if (auth_using_alias &&
          *auth_using_alias == TRUE) {
        user_name = origuser;
        pr_log_auth(PR_LOG_INFO,
          "ANON AUTH: User %s, authenticating using alias %s", user,
          user_name);
      }
    }

    /* It is possible for the user to have already been authenticated during
     * the handling of the USER command, as by an RFC2228 mechanism.  If
     * that had happened, we won't need to call do_auth() here.
     */
    if (!authenticated_without_pass) {
      auth_code = do_auth(p, c ? c->subset : main_server->conf, user_name,
        pass);

    } else {
      auth_code = PR_AUTH_OK_NO_PASS;
    }

    pr_event_generate("mod_auth.authentication-code", &auth_code);

    if (pass != NULL) {
      pr_memscrub(pass, strlen(pass));
    }

    if (session.auth_mech != NULL)
      pr_log_debug(DEBUG2, "user '%s' authenticated by %s", user,
        session.auth_mech);

    switch (auth_code) {
      case PR_AUTH_OK_NO_PASS:
        auth_pass_resp_code = R_232;
        break;

      case PR_AUTH_OK:
        auth_pass_resp_code = R_230;
        break;

      case PR_AUTH_NOPWD:
        pr_log_auth(PR_LOG_NOTICE,
          "USER %s (Login failed): No such user found", user);
        goto auth_failure;

      case PR_AUTH_BADPWD:
        pr_log_auth(PR_LOG_NOTICE,
          "USER %s (Login failed): Incorrect password", origuser);
        goto auth_failure;

      case PR_AUTH_AGEPWD:
        pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): Password expired",
          user);
        goto auth_failure;

      case PR_AUTH_DISABLEDPWD:
        pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): Account disabled",
          user);
        goto auth_failure;

      case PR_AUTH_CRED_INSUFFICIENT:
        pr_log_auth(PR_LOG_NOTICE,
          "USER %s (Login failed): Insufficient credentials", user);
        goto auth_failure;

      case PR_AUTH_CRED_UNAVAIL:
        pr_log_auth(PR_LOG_NOTICE,
          "USER %s (Login failed): Unavailable credentials", user);
        goto auth_failure;

      case PR_AUTH_CRED_ERROR:
        pr_log_auth(PR_LOG_NOTICE,
          "USER %s (Login failed): Failure setting credentials", user);
        goto auth_failure;

      case PR_AUTH_INFO_UNAVAIL:
        pr_log_auth(PR_LOG_NOTICE,
          "USER %s (Login failed): Unavailable authentication service", user);
        goto auth_failure;

      case PR_AUTH_MAX_ATTEMPTS_EXCEEDED:
        pr_log_auth(PR_LOG_NOTICE,
          "USER %s (Login failed): Max authentication service attempts reached",
          user);
        goto auth_failure;

      case PR_AUTH_INIT_ERROR:
        pr_log_auth(PR_LOG_NOTICE,
          "USER %s (Login failed): Failed initializing authentication service",
          user);
        goto auth_failure;

      case PR_AUTH_NEW_TOKEN_REQUIRED:
        pr_log_auth(PR_LOG_NOTICE,
          "USER %s (Login failed): New authentication token required", user);
        goto auth_failure;

      default:
        break;
    };

    /* Catch the case where we forgot to handle a bad auth code above. */
    if (auth_code < 0)
      goto auth_failure;

    if (pw->pw_uid == PR_ROOT_UID) {
      pr_log_auth(PR_LOG_WARNING, "ROOT FTP login successful");
    }

  } else if (c && (!anon_require_passwd || *anon_require_passwd == FALSE)) {
    session.hide_password = FALSE;
  }

  pr_auth_setgrent(p);

  res = pr_auth_is_valid_shell(c ? c->subset : main_server->conf,
    pw->pw_shell);
  if (res == FALSE) {
    pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): Invalid shell: '%s'",
      user, pw->pw_shell);
    goto auth_failure;
  }

  res = pr_auth_banned_by_ftpusers(c ? c->subset : main_server->conf,
    pw->pw_name);
  if (res == TRUE) {
    pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): User in "
      PR_FTPUSERS_PATH, user);
    goto auth_failure;
  }

  if (c) {
    struct group *grp = NULL;
    unsigned char *add_userdir = NULL;
    const char *u;
    char *chroot_dir;

    u = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
    add_userdir = get_param_ptr(c->subset, "UserDirRoot", FALSE);

    /* If resolving an <Anonymous> user, make sure that user's groups
     * are set properly for the check of the home directory path (which
     * depend on those supplemental group memberships).  Additionally,
     * temporarily switch to the new user's uid.
     */

    pr_signals_block();

    PRIVS_ROOT
    res = set_groups(p, pw->pw_gid, session.gids);
    if (res < 0) {
      if (errno != ENOSYS) {
        pr_log_pri(PR_LOG_WARNING, "error: unable to set groups: %s",
          strerror(errno));
      }
    }

#ifndef PR_DEVEL_COREDUMP
# ifdef __hpux
    if (setresuid(0, 0, 0) < 0) {
      pr_log_pri(PR_LOG_ERR, "unable to setresuid(): %s", strerror(errno));
    }

    if (setresgid(0, 0, 0) < 0) {
      pr_log_pri(PR_LOG_ERR, "unable to setresgid(): %s", strerror(errno));
    }
# else
    if (setuid(PR_ROOT_UID) < 0) {
      pr_log_pri(PR_LOG_ERR, "unable to setuid(): %s", strerror(errno));
    }

    if (setgid(PR_ROOT_GID) < 0) {
      pr_log_pri(PR_LOG_ERR, "unable to setgid(): %s", strerror(errno));
    }
# endif /* __hpux */
#endif /* PR_DEVEL_COREDUMP */

    PRIVS_SETUP(pw->pw_uid, pw->pw_gid)

    if ((add_userdir && *add_userdir == TRUE) &&
        strcmp(u, user) != 0) {
      chroot_dir = pdircat(p, c->name, u, NULL);

    } else {
      chroot_dir = c->name;
    }

    if (allow_chroot_symlinks == FALSE) {
      char *chroot_path, target_path[PR_TUNABLE_PATH_MAX+1];
      struct stat st;

      chroot_path = chroot_dir;
      if (chroot_path[0] != '/') {
        if (chroot_path[0] == '~') {
          if (pr_fs_interpolate(chroot_path, target_path,
              sizeof(target_path)-1) == 0) {
            chroot_path = target_path;

          } else {
            chroot_path = NULL;
          }
        }
      }

      if (chroot_path != NULL) {
        size_t chroot_pathlen;

        /* Note: lstat(2) is sensitive to the presence of a trailing slash on
         * the path, particularly in the case of a symlink to a directory.
         * Thus to get the correct test, we need to remove any trailing slash
         * that might be present.  Subtle.
         */
        chroot_pathlen = strlen(chroot_path);
        if (chroot_pathlen > 1 &&
            chroot_path[chroot_pathlen-1] == '/') {
          chroot_path[chroot_pathlen-1] = '\0';
        }

        pr_fs_clear_cache2(chroot_path);
        res = pr_fsio_lstat(chroot_path, &st);
        if (res < 0) {
          int xerrno = errno;

          pr_log_pri(PR_LOG_WARNING, "error: unable to check %s: %s",
            chroot_path, strerror(xerrno));

          errno = xerrno;
          chroot_path = NULL;

        } else {
          if (S_ISLNK(st.st_mode)) {
            pr_log_pri(PR_LOG_WARNING,
              "error: <Anonymous %s> is a symlink (denied by "
              "AllowChrootSymlinks config)", chroot_path);
            errno = EPERM;
            chroot_path = NULL;
          }
        }
      }

      if (chroot_path != NULL) {
        session.chroot_path = dir_realpath(p, chroot_dir);

      } else {
        session.chroot_path = NULL;
      }

      if (session.chroot_path == NULL) {
        pr_log_debug(DEBUG8, "error resolving '%s': %s", chroot_dir,
          strerror(errno));
      }

    } else {
      session.chroot_path = dir_realpath(p, chroot_dir);
      if (session.chroot_path == NULL) {
        pr_log_debug(DEBUG8, "error resolving '%s': %s", chroot_dir,
          strerror(errno));
      }
    }

    if (session.chroot_path &&
        pr_fsio_access(session.chroot_path, X_OK, session.uid,
          session.gid, session.gids) != 0) {
      session.chroot_path = NULL;

    } else {
      session.chroot_path = pstrdup(session.pool, session.chroot_path);
    }

    /* Return all privileges back to that of the daemon, for now. */
    PRIVS_ROOT
    res = set_groups(p, daemon_gid, daemon_gids);
    if (res < 0) {
      if (errno != ENOSYS) {
        pr_log_pri(PR_LOG_ERR, "error: unable to set groups: %s",
          strerror(errno));
      }
    }

#ifndef PR_DEVEL_COREDUMP
# ifdef __hpux
    if (setresuid(0, 0, 0) < 0) {
      pr_log_pri(PR_LOG_ERR, "unable to setresuid(): %s", strerror(errno));
    }

    if (setresgid(0, 0, 0) < 0) {
      pr_log_pri(PR_LOG_ERR, "unable to setresgid(): %s", strerror(errno));
    }
# else
    if (setuid(PR_ROOT_UID) < 0) {
      pr_log_pri(PR_LOG_ERR, "unable to setuid(): %s", strerror(errno));
    }

    if (setgid(PR_ROOT_GID) < 0) {
      pr_log_pri(PR_LOG_ERR, "unable to setgid(): %s", strerror(errno));
    }
# endif /* __hpux */
#endif /* PR_DEVEL_COREDUMP */

    PRIVS_SETUP(daemon_uid, daemon_gid)

    pr_signals_unblock();

    /* Sanity check, make sure we have daemon_uid and daemon_gid back */
#ifdef HAVE_GETEUID
    if (getegid() != daemon_gid ||
        geteuid() != daemon_uid) {

      PRIVS_RELINQUISH

      pr_log_pri(PR_LOG_WARNING,
        "switching IDs from user %s back to daemon uid/gid failed: %s",
        session.user, strerror(errno));
      pr_session_disconnect(&auth_module, PR_SESS_DISCONNECT_BY_APPLICATION,
        NULL);
    }
#endif /* HAVE_GETEUID */

    if (anon_require_passwd &&
        *anon_require_passwd == TRUE) {
      session.anon_user = pstrdup(session.pool, origuser);

    } else {
      session.anon_user = pstrdup(session.pool, pass);
    }

    if (!session.chroot_path) {
      pr_log_pri(PR_LOG_NOTICE, "%s: Directory %s is not accessible",
        session.user, c->name);
      pr_response_add_err(R_530, _("Unable to set anonymous privileges."));
      goto auth_failure;
    }

    sstrncpy(session.cwd, "/", sizeof(session.cwd));
    xferlog = get_param_ptr(c->subset, "TransferLog", FALSE);

    if (anongroup) {
      grp = pr_auth_getgrnam(p, anongroup);
      if (grp) {
        pw->pw_gid = grp->gr_gid;
        session.group = pstrdup(p, grp->gr_name);
      }
    }

  } else {
    struct group *grp;
    char *homedir;

    if (ugroup) {
      grp = pr_auth_getgrnam(p, ugroup);
      if (grp) {
        pw->pw_gid = grp->gr_gid;
        session.group = pstrdup(p, grp->gr_name);
      }
    }

    /* Attempt to resolve any possible symlinks. */
    PRIVS_USER
    homedir = dir_realpath(p, pw->pw_dir);
    PRIVS_RELINQUISH

    if (homedir)
      sstrncpy(session.cwd, homedir, sizeof(session.cwd));
    else
      sstrncpy(session.cwd, pw->pw_dir, sizeof(session.cwd));
  }

  /* Create the home directory, if need be. */

  if (!c && mkhome) {
    if (create_home(p, session.cwd, origuser, pw->pw_uid, pw->pw_gid) < 0) {

      /* NOTE: should this cause the login to fail? */
      goto auth_failure;
    }
  }

  /* Get default chdir (if any) */
  defchdir = get_default_chdir(p, (c ? c->subset : main_server->conf));
  if (defchdir != NULL) {
    sstrncpy(session.cwd, defchdir, sizeof(session.cwd));
  }

  /* Check limits again to make sure deny/allow directives still permit
   * access.
   */

  if (!login_check_limits((c ? c->subset : main_server->conf), FALSE, TRUE,
      &i)) {
    pr_log_auth(PR_LOG_NOTICE, "%s %s: Limit access denies login",
      (c != NULL) ? "ANON" : C_USER, origuser);
    goto auth_failure;
  }

  /* Perform a directory fixup. */
  resolve_deferred_dirs(main_server);
  fixup_dirs(main_server, CF_DEFER);

  /* If running under an anonymous context, resolve all <Directory>
   * blocks inside it.
   */
  if (c && c->subset)
    resolve_anonymous_dirs(c->subset);

  /* Write the login to wtmp.  This must be done here because we won't
   * have access after we give up root.  This can result in falsified
   * wtmp entries if an error kicks the user out before we get
   * through with the login process.  Oh well.
   */

  sess_ttyname = pr_session_get_ttyname(p);

  /* Perform wtmp logging only if not turned off in <Anonymous>
   * or the current server
   */
  if (c)
    wtmp_log = get_param_ptr(c->subset, "WtmpLog", FALSE);

  if (wtmp_log == NULL)
    wtmp_log = get_param_ptr(main_server->conf, "WtmpLog", FALSE);

  /* As per Bug#3482, we need to disable WtmpLog for FreeBSD 9.0, as
   * an interim measure.
   *
   * The issue is that some platforms update multiple files for a single
   * pututxline(3) call; proftpd tries to update those files manually,
   * do to chroots (after which a pututxline(3) call will fail).  A proper
   * solution requires a separate process, running with the correct
   * privileges, which would handle wtmp logging. The proftpd session
   * processes would send messages to this logging daemon (via Unix domain
   * socket, or FIFO, or TCP socket).
   *
   * Also note that this hack to disable WtmpLog may need to be extended
   * to other platforms in the future.
   */
#if defined(HAVE_UTMPX_H) && \
    defined(__FreeBSD_version) && __FreeBSD_version >= 900007
  if (wtmp_log == NULL ||
      *wtmp_log == TRUE) {
    wtmp_log = pcalloc(p, sizeof(unsigned char));
    *wtmp_log = FALSE;

    pr_log_debug(DEBUG5,
      "WtpmLog automatically disabled; see Bug#3482 for details");
  }
#endif

  PRIVS_ROOT

  if (wtmp_log == NULL ||
      *wtmp_log == TRUE) {
    log_wtmp(sess_ttyname, session.user, session.c->remote_name,
      session.c->remote_addr);
    session.wtmp_log = TRUE;
  }

#ifdef PR_USE_LASTLOG
  if (lastlog) {
    log_lastlog(pw->pw_uid, session.user, sess_ttyname, session.c->remote_addr);
  }
#endif /* PR_USE_LASTLOG */

  /* Open any TransferLogs */
  if (!xferlog) {
    if (c)
      xferlog = get_param_ptr(c->subset, "TransferLog", FALSE);

    if (!xferlog)
      xferlog = get_param_ptr(main_server->conf, "TransferLog", FALSE);

    if (!xferlog)
      xferlog = PR_XFERLOG_PATH;
  }

  if (strcasecmp(xferlog, "NONE") == 0) {
    xferlog_open(NULL);

  } else {
    xferlog_open(xferlog);
  }

  res = set_groups(p, pw->pw_gid, session.gids);
  if (res < 0) {
    if (errno != ENOSYS) {
      pr_log_pri(PR_LOG_ERR, "error: unable to set groups: %s",
        strerror(errno));
    }
  }

  PRIVS_RELINQUISH

  /* Now check to see if the user has an applicable DefaultRoot */
  if (c == NULL) {
    if (get_default_root(session.pool, allow_chroot_symlinks, &defroot) < 0) {
      pr_log_pri(PR_LOG_NOTICE,
        "error: unable to determine DefaultRoot directory");
      pr_response_send(R_530, _("Login incorrect."));
      pr_session_end(0);
    }

    ensure_open_passwd(p);

    if (defroot != NULL) {
      if (pr_auth_chroot(defroot) == -1) {
        pr_log_pri(PR_LOG_NOTICE, "error: unable to set DefaultRoot directory");
        pr_response_send(R_530, _("Login incorrect."));
        pr_session_end(0);
      }

      /* Re-calc the new cwd based on this root dir.  If not applicable
       * place the user in / (of defroot)
       */

      if (strncmp(session.cwd, defroot, strlen(defroot)) == 0) {
        char *newcwd = &session.cwd[strlen(defroot)];

        if (*newcwd == '/')
          newcwd++;
        session.cwd[0] = '/';
        sstrncpy(&session.cwd[1], newcwd, sizeof(session.cwd));
      }
    }
  }

  if (c)
    ensure_open_passwd(p);

  if (c &&
      pr_auth_chroot(session.chroot_path) == -1) {
    pr_log_pri(PR_LOG_NOTICE, "error: unable to set anonymous privileges");
    pr_response_send(R_530, _("Login incorrect."));
    pr_session_end(0);
  }

  /* new in 1.1.x, I gave in and we don't give up root permanently..
   * sigh.
   */

  PRIVS_ROOT

#ifndef PR_DEVEL_COREDUMP
# ifdef __hpux
    if (setresuid(0, 0, 0) < 0) {
      pr_log_pri(PR_LOG_ERR, "unable to setresuid(): %s", strerror(errno));
    }

    if (setresgid(0, 0, 0) < 0) {
      pr_log_pri(PR_LOG_ERR, "unable to setresgid(): %s", strerror(errno));
    }
# else
    if (setuid(PR_ROOT_UID) < 0) {
      pr_log_pri(PR_LOG_ERR, "unable to setuid(): %s", strerror(errno));
    }

    if (setgid(PR_ROOT_GID) < 0) {
      pr_log_pri(PR_LOG_ERR, "unable to setgid(): %s", strerror(errno));
    }
# endif /* __hpux */
#endif /* PR_DEVEL_COREDUMP */

  PRIVS_SETUP(pw->pw_uid, pw->pw_gid)

#ifdef HAVE_GETEUID
  if (getegid() != pw->pw_gid ||
     geteuid() != pw->pw_uid) {

    PRIVS_RELINQUISH
    pr_log_pri(PR_LOG_ERR, "error: %s setregid() or setreuid(): %s",
      session.user, strerror(errno));
    pr_response_send(R_530, _("Login incorrect."));
    pr_session_end(0);
  }
#endif

  /* If the home directory is NULL or "", reject the login. */
  if (pw->pw_dir == NULL ||
      strncmp(pw->pw_dir, "", 1) == 0) {
    pr_log_pri(PR_LOG_WARNING, "error: user %s home directory is NULL or \"\"",
      session.user);
    pr_response_send(R_530, _("Login incorrect."));
    pr_session_end(0);
  }

  {
    unsigned char *show_symlinks = get_param_ptr(
      c ? c->subset : main_server->conf, "ShowSymlinks", FALSE);

    if (!show_symlinks || *show_symlinks == TRUE)
      showsymlinks = TRUE;
    else
      showsymlinks = FALSE;
  }

  /* chdir to the proper directory, do this even if anonymous
   * to make sure we aren't outside our chrooted space.
   */

  /* Attempt to change to the correct directory -- use session.cwd first.
   * This will contain the DefaultChdir directory, if configured...
   */
  if (pr_fsio_chdir_canon(session.cwd, !showsymlinks) == -1) {

    /* if we've got DefaultRoot or anonymous login, ignore this error
     * and chdir to /
     */

    if (session.chroot_path != NULL || defroot) {

      pr_log_debug(DEBUG2, "unable to chdir to %s (%s), defaulting to chroot "
        "directory %s", session.cwd, strerror(errno),
        (session.chroot_path ? session.chroot_path : defroot));

      if (pr_fsio_chdir_canon("/", !showsymlinks) == -1) {
        pr_log_pri(PR_LOG_NOTICE, "%s chdir(\"/\") failed: %s", session.user,
          strerror(errno));
        pr_response_send(R_530, _("Login incorrect."));
        pr_session_end(0);
      }

    } else if (defchdir) {

      /* If we've got defchdir, failure is ok as well, simply switch to
       * user's homedir.
       */
      pr_log_debug(DEBUG2, "unable to chdir to %s (%s), defaulting to home "
        "directory %s", session.cwd, strerror(errno), pw->pw_dir);

      if (pr_fsio_chdir_canon(pw->pw_dir, !showsymlinks) == -1) {
        pr_log_pri(PR_LOG_NOTICE, "%s chdir(\"%s\") failed: %s", session.user,
          session.cwd, strerror(errno));
        pr_response_send(R_530, _("Login incorrect."));
        pr_session_end(0);
      }

    } else {

      /* Unable to switch to user's real home directory, which is not
       * allowed.
       */
      pr_log_pri(PR_LOG_NOTICE, "%s chdir(\"%s\") failed: %s", session.user,
        session.cwd, strerror(errno));
      pr_response_send(R_530, _("Login incorrect."));
      pr_session_end(0);
    }
  }

  sstrncpy(session.cwd, pr_fs_getcwd(), sizeof(session.cwd));
  sstrncpy(session.vwd, pr_fs_getvwd(), sizeof(session.vwd));

  /* Make sure directory config pointers are set correctly */
  dir_check_full(p, cmd, G_NONE, session.cwd, NULL);

  if (c) {
    if (!session.hide_password) {
      session.proc_prefix = pstrcat(session.pool, session.c->remote_name,
        ": anonymous/", pass, NULL);

    } else {
      session.proc_prefix = pstrcat(session.pool, session.c->remote_name,
        ": anonymous", NULL);
    }

    session.sf_flags = SF_ANON;

  } else {
    session.proc_prefix = pstrdup(session.pool, session.c->remote_name);
    session.sf_flags = 0;
  }

  /* While closing the pointer to the password database would avoid any
   * potential attempt to hijack this information, it is unfortunately needed
   * in a chroot()ed environment.  Otherwise, mappings from UIDs to names,
   * among other things, would fail.
   */
  /* pr_auth_endpwent(p); */

  /* Authentication complete, user logged in, now kill the login
   * timer.
   */

  /* Update the scoreboard entry */
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_USER, session.user,
    PR_SCORE_CWD, session.cwd,
    NULL);

  pr_session_set_idle();

  pr_timer_remove(PR_TIMER_LOGIN, &auth_module);

  /* These copies are made from the session.pool, instead of the more
   * volatile pool used originally, in order that the copied data maintain
   * its integrity for the lifetime of the session.
   */
  session.user = pstrdup(session.pool, session.user);

  if (session.group)
    session.group = pstrdup(session.pool, session.group);

  if (session.gids)
    session.gids = copy_array(session.pool, session.gids);

  /* session.groups is an array of strings, so we must copy the string data
   * as well as the pointers.
   */
  session.groups = copy_array_str(session.pool, session.groups);

  /* Resolve any deferred-resolution paths in the FS layer */
  pr_resolve_fs_map();

  return 1;

auth_failure:
  if (pass)
    pr_memscrub(pass, strlen(pass));
  session.user = session.group = NULL;
  session.gids = session.groups = NULL;
  session.wtmp_log = FALSE;
  return 0;
}

/* This function counts the number of connected users. It only fills in the
 * Class-based counters and an estimate for the number of clients. The primary
 * purpose is to make it so that the %N/%y escapes work in a DisplayConnect
 * greeting.  A secondary purpose is to enforce any configured
 * MaxConnectionsPerHost limit.
 */
static int auth_scan_scoreboard(void) {
  char *key;
  void *v;
  config_rec *c = NULL;
  pr_scoreboard_entry_t *score = NULL;
  unsigned int cur = 0, ccur = 0, hcur = 0;
  char curr_server_addr[80] = {'\0'};
  const char *client_addr = pr_netaddr_get_ipstr(session.c->remote_addr);

  pr_snprintf(curr_server_addr, sizeof(curr_server_addr), "%s:%d",
    pr_netaddr_get_ipstr(session.c->local_addr), main_server->ServerPort);
  curr_server_addr[sizeof(curr_server_addr)-1] = '\0';

  /* Determine how many users are currently connected */
  if (pr_rewind_scoreboard() < 0) {
    pr_log_pri(PR_LOG_NOTICE, "error rewinding scoreboard: %s",
      strerror(errno));
  }

  while ((score = pr_scoreboard_entry_read()) != NULL) {
    pr_signals_handle();

    /* Make sure it matches our current server */
    if (strcmp(score->sce_server_addr, curr_server_addr) == 0) {
      cur++;

      if (strcmp(score->sce_client_addr, client_addr) == 0)
        hcur++;

      /* Only count up authenticated clients, as per the documentation. */
      if (strncmp(score->sce_user, "(none)", 7) == 0)
        continue;

      /* Note: the class member of the scoreboard entry will never be
       * NULL.  At most, it may be the empty string.
       */
      if (session.conn_class != NULL &&
          strcasecmp(score->sce_class, session.conn_class->cls_name) == 0) {
        ccur++;
      }
    }
  }
  pr_restore_scoreboard();

  key = "client-count";
  (void) pr_table_remove(session.notes, key, NULL);
  v = palloc(session.pool, sizeof(unsigned int));
  *((unsigned int *) v) = cur;

  if (pr_table_add(session.notes, key, v, sizeof(unsigned int)) < 0) {
    if (errno != EEXIST) {
      pr_log_pri(PR_LOG_WARNING,
        "warning: error stashing '%s': %s", key, strerror(errno));
    }
  }

  if (session.conn_class != NULL) {
    key = "class-client-count";
    (void) pr_table_remove(session.notes, key, NULL);
    v = palloc(session.pool, sizeof(unsigned int));
    *((unsigned int *) v) = ccur;

    if (pr_table_add(session.notes, key, v, sizeof(unsigned int)) < 0) {
      if (errno != EEXIST) {
        pr_log_pri(PR_LOG_WARNING,
          "warning: error stashing '%s': %s", key, strerror(errno));
      }
    }
  }

  /* Lookup any configured MaxConnectionsPerHost. */
  c = find_config(main_server->conf, CONF_PARAM, "MaxConnectionsPerHost",
    FALSE);

  if (c) {
    unsigned int *max = c->argv[0];

    if (*max &&
        hcur > *max) {

      char maxstr[20];
      char *msg = "Sorry, the maximum number of connections (%m) for your host "
        "are already connected.";

      pr_event_generate("mod_auth.max-connections-per-host", session.c);

      if (c->argc == 2)
        msg = c->argv[1];

      memset(maxstr, '\0', sizeof(maxstr));
      pr_snprintf(maxstr, sizeof(maxstr), "%u", *max);
      maxstr[sizeof(maxstr)-1] = '\0';

      pr_response_send(R_530, "%s", sreplace(session.pool, msg,
        "%m", maxstr, NULL));

      pr_log_auth(PR_LOG_NOTICE,
        "Connection refused (MaxConnectionsPerHost %u)", *max);
      pr_session_disconnect(&auth_module, PR_SESS_DISCONNECT_CONFIG_ACL,
        "Denied by MaxConnectionsPerHost");
    }
  }

  return 0;
}

static int have_client_limits(cmd_rec *cmd) {
  if (find_config(TOPLEVEL_CONF, CONF_PARAM, "MaxClientsPerClass", FALSE) != NULL) {
    return TRUE;
  }

  if (find_config(TOPLEVEL_CONF, CONF_PARAM, "MaxClientsPerHost", FALSE) != NULL) {
    return TRUE;
  }

  if (find_config(TOPLEVEL_CONF, CONF_PARAM, "MaxClientsPerUser", FALSE) != NULL) {
    return TRUE;
  }

  if (find_config(TOPLEVEL_CONF, CONF_PARAM, "MaxClients", FALSE) != NULL) {
    return TRUE;
  }

  if (find_config(TOPLEVEL_CONF, CONF_PARAM, "MaxHostsPerUser", FALSE) != NULL) {
    return TRUE;
  }

  return FALSE;
}

static int auth_count_scoreboard(cmd_rec *cmd, const char *user) {
  char *key;
  void *v;
  pr_scoreboard_entry_t *score = NULL;
  long cur = 0, hcur = 0, ccur = 0, hostsperuser = 1, usersessions = 0;
  config_rec *c = NULL, *maxc = NULL;

  /* First, check to see which Max* directives are configured.  If none
   * are configured, then there is no need for us to needlessly scan the
   * ScoreboardFile.
   */
  if (have_client_limits(cmd) == FALSE) {
    return 0;
  }

  /* Determine how many users are currently connected. */

  /* We use this call to get the possibly-changed user name. */
  c = pr_auth_get_anon_config(cmd->tmp_pool, &user, NULL, NULL);

  /* Gather our statistics. */
  if (user != NULL) {
    char curr_server_addr[80] = {'\0'};

    pr_snprintf(curr_server_addr, sizeof(curr_server_addr), "%s:%d",
      pr_netaddr_get_ipstr(session.c->local_addr), main_server->ServerPort);
    curr_server_addr[sizeof(curr_server_addr)-1] = '\0';

    if (pr_rewind_scoreboard() < 0) {
      pr_log_pri(PR_LOG_NOTICE, "error rewinding scoreboard: %s",
        strerror(errno));
    }

    while ((score = pr_scoreboard_entry_read()) != NULL) {
      unsigned char same_host = FALSE;

      pr_signals_handle();

      /* Make sure it matches our current server. */
      if (strcmp(score->sce_server_addr, curr_server_addr) == 0) {

        if ((c != NULL &&
             c->config_type == CONF_ANON &&
             strcmp(score->sce_user, user) == 0) ||
            c == NULL) {

          /* Only count authenticated clients, as per the documentation. */
          if (strncmp(score->sce_user, "(none)", 7) == 0) {
            continue;
          }

          cur++;

          /* Count up sessions on a per-host basis. */

          if (strcmp(score->sce_client_addr,
              pr_netaddr_get_ipstr(session.c->remote_addr)) == 0) {
            same_host = TRUE;
            hcur++;
          }

          /* Take a per-user count of connections. */
          if (strcmp(score->sce_user, user) == 0) {
            usersessions++;

            /* Count up unique hosts. */
            if (same_host == FALSE) {
              hostsperuser++;
            }
          }
        }

        if (session.conn_class != NULL &&
            strcasecmp(score->sce_class, session.conn_class->cls_name) == 0) {
          ccur++;
        }
      }
    }
    pr_restore_scoreboard();
    PRIVS_RELINQUISH
  }

  key = "client-count";
  (void) pr_table_remove(session.notes, key, NULL);
  v = palloc(session.pool, sizeof(unsigned int));
  *((unsigned int *) v) = cur;

  if (pr_table_add(session.notes, key, v, sizeof(unsigned int)) < 0) {
    if (errno != EEXIST) {
      pr_log_pri(PR_LOG_WARNING,
        "warning: error stashing '%s': %s", key, strerror(errno));
    }
  }

  if (session.conn_class != NULL) {
    key = "class-client-count";
    (void) pr_table_remove(session.notes, key, NULL);
    v = palloc(session.pool, sizeof(unsigned int));
    *((unsigned int *) v) = ccur;

    if (pr_table_add(session.notes, key, v, sizeof(unsigned int)) < 0) {
      if (errno != EEXIST) {
        pr_log_pri(PR_LOG_WARNING,
          "warning: error stashing '%s': %s", key, strerror(errno));
      }
    }
  }

  /* Try to determine what MaxClients/MaxHosts limits apply to this session
   * (if any) and count through the runtime file to see if this limit would
   * be exceeded.
   */

  maxc = find_config(cmd->server->conf, CONF_PARAM, "MaxClientsPerClass",
    FALSE);
  while (session.conn_class != NULL && maxc) {
    char *maxstr = "Sorry, the maximum number of clients (%m) from your class "
      "are already connected.";
    unsigned int *max = maxc->argv[1];

    if (strcmp(maxc->argv[0], session.conn_class->cls_name) != 0) {
      maxc = find_config_next(maxc, maxc->next, CONF_PARAM,
        "MaxClientsPerClass", FALSE);
      continue;
    }

    if (maxc->argc > 2) {
      maxstr = maxc->argv[2];
    }

    if (*max &&
        ccur > *max) {
      char maxn[20] = {'\0'};

      pr_event_generate("mod_auth.max-clients-per-class",
        session.conn_class->cls_name);

      pr_snprintf(maxn, sizeof(maxn), "%u", *max);
      pr_response_send(R_530, "%s", sreplace(cmd->tmp_pool, maxstr, "%m", maxn,
        NULL));
      (void) pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

      pr_log_auth(PR_LOG_NOTICE,
        "Connection refused (MaxClientsPerClass %s %u)",
        session.conn_class->cls_name, *max);
      pr_session_disconnect(&auth_module, PR_SESS_DISCONNECT_CONFIG_ACL,
        "Denied by MaxClientsPerClass");
    }

    break;
  }

  maxc = find_config(TOPLEVEL_CONF, CONF_PARAM, "MaxClientsPerHost", FALSE);
  if (maxc) {
    char *maxstr = "Sorry, the maximum number of clients (%m) from your host "
      "are already connected.";
    unsigned int *max = maxc->argv[0];

    if (maxc->argc > 1) {
      maxstr = maxc->argv[1];
    }

    if (*max &&
        hcur > *max) {
      char maxn[20] = {'\0'};

      pr_event_generate("mod_auth.max-clients-per-host", session.c);

      pr_snprintf(maxn, sizeof(maxn), "%u", *max);
      pr_response_send(R_530, "%s", sreplace(cmd->tmp_pool, maxstr, "%m", maxn,
        NULL));
      (void) pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

      pr_log_auth(PR_LOG_NOTICE,
        "Connection refused (MaxClientsPerHost %u)", *max);
      pr_session_disconnect(&auth_module, PR_SESS_DISCONNECT_CONFIG_ACL,
        "Denied by MaxClientsPerHost");
    }
  }

  /* Check for any configured MaxClientsPerUser. */
  maxc = find_config(TOPLEVEL_CONF, CONF_PARAM, "MaxClientsPerUser", FALSE);
  if (maxc) {
    char *maxstr = "Sorry, the maximum number of clients (%m) for this user "
      "are already connected.";
    unsigned int *max = maxc->argv[0];

    if (maxc->argc > 1) {
      maxstr = maxc->argv[1];
    }

    if (*max &&
        usersessions > *max) {
      char maxn[20] = {'\0'};

      pr_event_generate("mod_auth.max-clients-per-user", user);

      pr_snprintf(maxn, sizeof(maxn), "%u", *max);
      pr_response_send(R_530, "%s", sreplace(cmd->tmp_pool, maxstr, "%m", maxn,
        NULL));
      (void) pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

      pr_log_auth(PR_LOG_NOTICE,
        "Connection refused (MaxClientsPerUser %u)", *max);
      pr_session_disconnect(&auth_module, PR_SESS_DISCONNECT_CONFIG_ACL,
        "Denied by MaxClientsPerUser");
    }
  }

  maxc = find_config(TOPLEVEL_CONF, CONF_PARAM, "MaxClients", FALSE);
  if (maxc) {
    char *maxstr = "Sorry, the maximum number of allowed clients (%m) are "
      "already connected.";
    unsigned int *max = maxc->argv[0];

    if (maxc->argc > 1) {
      maxstr = maxc->argv[1];
    }

    if (*max &&
        cur > *max) {
      char maxn[20] = {'\0'};

      pr_event_generate("mod_auth.max-clients", NULL);

      pr_snprintf(maxn, sizeof(maxn), "%u", *max);
      pr_response_send(R_530, "%s", sreplace(cmd->tmp_pool, maxstr, "%m", maxn,
        NULL));
      (void) pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

      pr_log_auth(PR_LOG_NOTICE, "Connection refused (MaxClients %u)", *max);
      pr_session_disconnect(&auth_module, PR_SESS_DISCONNECT_CONFIG_ACL,
        "Denied by MaxClients");
    }
  }

  maxc = find_config(TOPLEVEL_CONF, CONF_PARAM, "MaxHostsPerUser", FALSE);
  if (maxc) {
    char *maxstr = "Sorry, the maximum number of hosts (%m) for this user are "
      "already connected.";
    unsigned int *max = maxc->argv[0];

    if (maxc->argc > 1) {
      maxstr = maxc->argv[1];
    }

    if (*max && hostsperuser > *max) {
      char maxn[20] = {'\0'};

      pr_event_generate("mod_auth.max-hosts-per-user", user);

      pr_snprintf(maxn, sizeof(maxn), "%u", *max);
      pr_response_send(R_530, "%s", sreplace(cmd->tmp_pool, maxstr, "%m", maxn,
        NULL));
      (void) pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

      pr_log_auth(PR_LOG_NOTICE, "Connection refused (MaxHostsPerUser %u)",
        *max);
      pr_session_disconnect(&auth_module, PR_SESS_DISCONNECT_CONFIG_ACL,
        "Denied by MaxHostsPerUser");
    }
  }

  return 0;
}

MODRET auth_pre_user(cmd_rec *cmd) {

  if (saw_first_user_cmd == FALSE) {
    if (pr_trace_get_level(timing_channel)) {
      unsigned long elapsed_ms;
      uint64_t finish_ms;

      pr_gettimeofday_millis(&finish_ms);
      elapsed_ms = (unsigned long) (finish_ms - session.connect_time_ms);

      pr_trace_msg(timing_channel, 4, "Time before first USER: %lu ms",
        elapsed_ms);
    }
    saw_first_user_cmd = TRUE;
  }

  if (logged_in) {
    return PR_DECLINED(cmd);
  }

  /* Close the passwd and group databases, because libc won't let us see new
   * entries to these files without this (only in PersistentPasswd mode).
   */
  pr_auth_endpwent(cmd->tmp_pool);
  pr_auth_endgrent(cmd->tmp_pool);

  /* Check for a user name that exceeds PR_TUNABLE_LOGIN_MAX. */
  if (strlen(cmd->arg) > PR_TUNABLE_LOGIN_MAX) {
    pr_log_pri(PR_LOG_NOTICE, "USER %s (Login failed): "
      "maximum USER length exceeded", cmd->arg);
    pr_response_add_err(R_501, _("Login incorrect."));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  return PR_DECLINED(cmd);
}

MODRET auth_user(cmd_rec *cmd) {
  int nopass = FALSE;
  config_rec *c;
  const char *denymsg = NULL, *user, *origuser;
  unsigned char *anon_require_passwd = NULL;

  if (cmd->argc < 2) {
    return PR_ERROR_MSG(cmd, R_500, _("USER: command requires a parameter"));
  }

  if (logged_in) {
    /* If the client has already authenticated, BUT the given USER command
     * here is for the exact same user name, then allow the command to
     * succeed (Bug#4217).
     */
    origuser = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
    if (origuser != NULL &&
        strcmp(origuser, cmd->arg) == 0) {
      pr_response_add(R_230, _("User %s logged in"), origuser);
      return PR_HANDLED(cmd);
    }

    pr_response_add_err(R_501, "%s", _("Reauthentication not supported"));
    return PR_ERROR(cmd);
  }

  user = cmd->arg;

  (void) pr_table_remove(session.notes, "mod_auth.orig-user", NULL);
  (void) pr_table_remove(session.notes, "mod_auth.anon-passwd", NULL);

  if (pr_table_add_dup(session.notes, "mod_auth.orig-user", user, 0) < 0) {
    pr_log_debug(DEBUG3, "error stashing 'mod_auth.orig-user' in "
      "session.notes: %s", strerror(errno));
  }

  origuser = user;
  c = pr_auth_get_anon_config(cmd->tmp_pool, &user, NULL, NULL);

  /* Check for AccessDenyMsg */
  denymsg = get_param_ptr((c ? c->subset : cmd->server->conf), "AccessDenyMsg",
    FALSE);
  if (denymsg != NULL) {
    if (strstr(denymsg, "%u") != NULL) {
      denymsg = sreplace(cmd->tmp_pool, denymsg, "%u", user, NULL);
    }
  }

  if (c != NULL) {
    anon_require_passwd = get_param_ptr(c->subset, "AnonRequirePassword",
      FALSE);
  }

  if (c && user && (!anon_require_passwd || *anon_require_passwd == FALSE))
    nopass = TRUE;

  session.gids = NULL;
  session.groups = NULL;
  session.user = NULL;
  session.group = NULL;

  if (nopass) {
    pr_response_add(R_331, _("Anonymous login ok, send your complete email "
      "address as your password"));

  } else if (pr_auth_requires_pass(cmd->tmp_pool, user) == FALSE) {
    /* Check to see if a password from the client is required.  In the
     * vast majority of cases, a password will be required.
     */

    /* Act as if we received a PASS command from the client. */
    cmd_rec *fakecmd = pr_cmd_alloc(cmd->pool, 2, NULL);

    /* We use pstrdup() here, rather than assigning C_PASS directly, since
     * code elsewhere will attempt to modify this buffer, and C_PASS is
     * a string literal.
     */
    fakecmd->argv[0] = pstrdup(fakecmd->pool, C_PASS);
    fakecmd->argv[1] = NULL;
    fakecmd->arg = NULL;

    c = add_config_param_set(&cmd->server->conf, "authenticated", 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) c->argv[0]) = TRUE;

    authenticated_without_pass = TRUE;
    pr_log_auth(PR_LOG_NOTICE, "USER %s: Authenticated without password", user);

    pr_cmd_dispatch(fakecmd);

  } else {
    pr_response_add(R_331, _("Password required for %s"),
      (char *) cmd->argv[1]);
  }

  return PR_HANDLED(cmd);
}

/* Close the passwd and group databases, similar to auth_pre_user(). */
MODRET auth_pre_pass(cmd_rec *cmd) {
  const char *user;
  char *displaylogin;

  pr_auth_endpwent(cmd->tmp_pool);
  pr_auth_endgrent(cmd->tmp_pool);

  /* Handle cases where PASS might be sent before USER. */
  user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
  if (user != NULL) {
    config_rec *c;

    c = find_config(main_server->conf, CONF_PARAM, "AllowEmptyPasswords",
      FALSE);
    if (c == NULL) {
      const char *anon_user;
      config_rec *anon_config;

      /* Since we have not authenticated yet, we cannot use the TOPLEVEL_CONF
       * macro to handle <Anonymous> sections.  So we do it manually.
       */
      anon_user = pstrdup(cmd->tmp_pool, user);
      anon_config = pr_auth_get_anon_config(cmd->tmp_pool, &anon_user, NULL,
        NULL);
      if (anon_config != NULL) {
        c = find_config(anon_config->subset, CONF_PARAM, "AllowEmptyPasswords",
          FALSE);
      }
    }
 
    if (c != NULL) {
      int allow_empty_passwords;

      allow_empty_passwords = *((int *) c->argv[0]);
      if (allow_empty_passwords == FALSE) {
        const char *proto;
        int reject_empty_passwd = FALSE, using_ssh2 = FALSE;
        size_t passwd_len = 0;
 
        proto = pr_session_get_protocol(0);
        if (strcmp(proto, "ssh2") == 0) {
          using_ssh2 = TRUE;
        }

        if (cmd->argc > 1) {
          if (cmd->arg != NULL) {
            passwd_len = strlen(cmd->arg);
          }
        }

        if (passwd_len == 0) {
          reject_empty_passwd = TRUE;

          /* Make sure to NOT enforce 'AllowEmptyPasswords off' if e.g.
           * the AllowDotLogin TLSOption is in effect, or if the protocol is
           * SSH2 (for mod_sftp uses "fake" PASS commands for the SSH login
           * protocol).
           */

          if (session.auth_mech != NULL &&
              strcmp(session.auth_mech, "mod_tls.c") == 0) {
            pr_log_debug(DEBUG9, "%s", "'AllowEmptyPasswords off' in effect, "
              "BUT client authenticated via the AllowDotLogin TLSOption");
            reject_empty_passwd = FALSE;
          }

          if (using_ssh2 == TRUE) {
            reject_empty_passwd = FALSE;
          }
        }

        if (reject_empty_passwd == TRUE) {
          pr_log_debug(DEBUG5,
            "Refusing empty password from user '%s' (AllowEmptyPasswords "
            "false)", user);
          pr_log_auth(PR_LOG_NOTICE,
            "Refusing empty password from user '%s'", user);

          pr_event_generate("mod_auth.empty-password", user);
          pr_response_add_err(R_501, _("Login incorrect."));
          return PR_ERROR(cmd);
        }
      }
    }
  }

  /* Look for a DisplayLogin file which has an absolute path.  If we find one,
   * open a filehandle, such that that file can be displayed even if the
   * session is chrooted.  DisplayLogin files with relative paths will be
   * handled after chroot, preserving the old behavior.
   */

  displaylogin = get_param_ptr(TOPLEVEL_CONF, "DisplayLogin", FALSE);
  if (displaylogin &&
      *displaylogin == '/') {
    struct stat st;

    displaylogin_fh = pr_fsio_open(displaylogin, O_RDONLY);
    if (displaylogin_fh == NULL) {
      pr_log_debug(DEBUG6, "unable to open DisplayLogin file '%s': %s",
        displaylogin, strerror(errno));

    } else {
      if (pr_fsio_fstat(displaylogin_fh, &st) < 0) {
        pr_log_debug(DEBUG6, "unable to stat DisplayLogin file '%s': %s",
          displaylogin, strerror(errno));
        pr_fsio_close(displaylogin_fh);
        displaylogin_fh = NULL;

      } else {
        if (S_ISDIR(st.st_mode)) {
          errno = EISDIR;
          pr_log_debug(DEBUG6, "unable to use DisplayLogin file '%s': %s",
            displaylogin, strerror(errno));
          pr_fsio_close(displaylogin_fh);
          displaylogin_fh = NULL;
        }
      }
    }
  }

  return PR_DECLINED(cmd);
}

MODRET auth_pass(cmd_rec *cmd) {
  const char *user = NULL;
  int res = 0;

  if (logged_in) {
    return PR_ERROR_MSG(cmd, R_503, _("You are already logged in"));
  }

  user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
  if (user == NULL) {
    (void) pr_table_remove(session.notes, "mod_auth.orig-user", NULL);
    (void) pr_table_remove(session.notes, "mod_auth.anon-passwd", NULL);

    return PR_ERROR_MSG(cmd, R_503, _("Login with USER first"));
  }

  /* Clear any potentially cached directory config */
  session.anon_config = NULL;
  session.dir_config = NULL;

  res = setup_env(cmd->tmp_pool, cmd, user, cmd->arg);
  if (res == 1) {
    config_rec *c = NULL;

    c = add_config_param_set(&cmd->server->conf, "authenticated", 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) c->argv[0]) = TRUE;

    set_auth_check(NULL);

    (void) pr_table_remove(session.notes, "mod_auth.anon-passwd", NULL);

    if (session.sf_flags & SF_ANON) {
      if (pr_table_add_dup(session.notes, "mod_auth.anon-passwd",
          pr_fs_decode_path(cmd->server->pool, cmd->arg), 0) < 0) {
        pr_log_debug(DEBUG3,
          "error stashing anonymous password in session.notes: %s",
          strerror(errno));
      }
    }

    logged_in = TRUE;

    if (pr_trace_get_level(timing_channel)) {
      unsigned long elapsed_ms;
      uint64_t finish_ms;

      pr_gettimeofday_millis(&finish_ms);
      elapsed_ms = (unsigned long) (finish_ms - session.connect_time_ms);

      pr_trace_msg(timing_channel, 4,
        "Time before successful login (via '%s'): %lu ms", session.auth_mech,
        elapsed_ms);
    }

    return PR_HANDLED(cmd);
  }

  (void) pr_table_remove(session.notes, "mod_auth.anon-passwd", NULL);

  if (res == 0) {
    unsigned int max_logins, *max = NULL;
    const char *denymsg = NULL;

    /* check for AccessDenyMsg */
    if ((denymsg = get_param_ptr((session.anon_config ?
        session.anon_config->subset : cmd->server->conf),
        "AccessDenyMsg", FALSE)) != NULL) {

      if (strstr(denymsg, "%u") != NULL) {
        denymsg = sreplace(cmd->tmp_pool, denymsg, "%u", user, NULL);
      }
    }

    max = get_param_ptr(main_server->conf, "MaxLoginAttempts", FALSE);
    if (max != NULL) {
      max_logins = *max;

    } else {
      max_logins = 3;
    }

    if (max_logins > 0 &&
        ++auth_tries >= max_logins) {
      if (denymsg) {
        pr_response_send(R_530, "%s", denymsg);

      } else {
        pr_response_send(R_530, "%s", _("Login incorrect."));
      }

      pr_log_auth(PR_LOG_NOTICE,
        "Maximum login attempts (%u) exceeded, connection refused", max_logins);

      /* Generate an event about this limit being exceeded. */
      pr_event_generate("mod_auth.max-login-attempts", session.c);

      pr_session_disconnect(&auth_module, PR_SESS_DISCONNECT_CONFIG_ACL,
        "Denied by MaxLoginAttempts");
    }

    return PR_ERROR_MSG(cmd, R_530, denymsg ? denymsg : _("Login incorrect."));
  }

  return PR_HANDLED(cmd);
}

MODRET auth_acct(cmd_rec *cmd) {
  pr_response_add(R_502, _("ACCT command not implemented"));
  return PR_HANDLED(cmd);
}

MODRET auth_rein(cmd_rec *cmd) {
  pr_response_add(R_502, _("REIN command not implemented"));
  return PR_HANDLED(cmd);
}

/* FSIO callbacks for providing a fake robots.txt file, for the AnonAllowRobots
 * functionality.
 */

#define AUTH_ROBOTS_TXT			"User-agent: *\nDisallow: /\n"
#define AUTH_ROBOTS_TXT_FD		6742

static int robots_fsio_stat(pr_fs_t *fs, const char *path, struct stat *st) {
  st->st_dev = (dev_t) 0;
  st->st_ino = (ino_t) 0;
  st->st_mode = (S_IFREG|S_IRUSR|S_IRGRP|S_IROTH);
  st->st_nlink = 0;
  st->st_uid = (uid_t) 0;
  st->st_gid = (gid_t) 0;
  st->st_atime = 0;
  st->st_mtime = 0;
  st->st_ctime = 0;
  st->st_size = strlen(AUTH_ROBOTS_TXT);
  st->st_blksize = 1024;
  st->st_blocks = 1;

  return 0;
}

static int robots_fsio_fstat(pr_fh_t *fh, int fd, struct stat *st) {
  if (fd != AUTH_ROBOTS_TXT_FD) {
    errno = EINVAL;
    return -1;
  }

  return robots_fsio_stat(NULL, NULL, st);
}

static int robots_fsio_lstat(pr_fs_t *fs, const char *path, struct stat *st) {
  return robots_fsio_stat(fs, path, st);
}

static int robots_fsio_unlink(pr_fs_t *fs, const char *path) {
  return 0;
}

static int robots_fsio_open(pr_fh_t *fh, const char *path, int flags) {
  if (flags != O_RDONLY) {
    errno = EINVAL;
    return -1;
  }

  return AUTH_ROBOTS_TXT_FD;
}

static int robots_fsio_close(pr_fh_t *fh, int fd) {
  if (fd != AUTH_ROBOTS_TXT_FD) {
    errno = EINVAL;
    return -1;
  }

  return 0;
}

static int robots_fsio_read(pr_fh_t *fh, int fd, char *buf, size_t bufsz) {
  size_t robots_len;

  if (fd != AUTH_ROBOTS_TXT_FD) {
    errno = EINVAL;
    return -1;
  }

  robots_len = strlen(AUTH_ROBOTS_TXT);

  if (bufsz < robots_len) {
    errno = EINVAL;
    return -1;
  }

  memcpy(buf, AUTH_ROBOTS_TXT, robots_len);
  return (int) robots_len;
}

static int robots_fsio_write(pr_fh_t *fh, int fd, const char *buf,
    size_t bufsz) {
  if (fd != AUTH_ROBOTS_TXT_FD) {
    errno = EINVAL;
    return -1;
  }

  return (int) bufsz;
}

static int robots_fsio_access(pr_fs_t *fs, const char *path, int mode,
    uid_t uid, gid_t gid, array_header *suppl_gids) {
  if (mode != R_OK) {
    errno = EACCES;
    return -1;
  }

  return 0;
}

static int robots_fsio_faccess(pr_fh_t *fh, int mode, uid_t uid, gid_t gid,
    array_header *suppl_gids) {

  if (fh->fh_fd != AUTH_ROBOTS_TXT_FD) {
    errno = EINVAL;
    return -1;
  }

  if (mode != R_OK) {
    errno = EACCES;
    return -1;
  }

  return 0;
}

MODRET auth_pre_retr(cmd_rec *cmd) {
  const char *path;
  pr_fs_t *curr_fs = NULL;
  struct stat st;

  /* Only apply this for <Anonymous> logins. */
  if (session.anon_config == NULL) {
    return PR_DECLINED(cmd);
  }

  if (auth_anon_allow_robots == TRUE) {
    return PR_DECLINED(cmd);
  }

  auth_anon_allow_robots_enabled = FALSE;

  path = dir_canonical_path(cmd->tmp_pool, cmd->arg);
  if (strcasecmp(path, "/robots.txt") != 0) {
    return PR_DECLINED(cmd);
  }

  /* If a previous REST command, with a non-zero value, has been sent, then
   * do nothing.  Ugh.
   */
  if (session.restart_pos > 0) {
    pr_log_debug(DEBUG10, "'AnonAllowRobots off' in effect, but cannot "
      "support resumed download (REST %" PR_LU " previously sent by client)",
      (pr_off_t) session.restart_pos);
    return PR_DECLINED(cmd);
  }

  pr_fs_clear_cache2(path);
  if (pr_fsio_lstat(path, &st) == 0) {
    /* There's an existing REAL "robots.txt" file on disk; use that, and
     * preserve the principle of least surprise.
     */
    pr_log_debug(DEBUG10, "'AnonAllowRobots off' in effect, but have "
      "real 'robots.txt' file on disk; using that");
    return PR_DECLINED(cmd);
  }

  curr_fs = pr_get_fs(path, NULL);
  if (curr_fs != NULL) {
    pr_fs_t *robots_fs;

    robots_fs = pr_register_fs(cmd->pool, "robots", path);
    if (robots_fs == NULL) {
      pr_log_debug(DEBUG8, "'AnonAllowRobots off' in effect, but failed to "
        "register FS: %s", strerror(errno));
      return PR_DECLINED(cmd);
    }

    /* Use enough of our own custom FSIO callbacks to be able to provide
     * a fake "robots.txt" file.
     */
    robots_fs->stat = robots_fsio_stat;
    robots_fs->fstat = robots_fsio_fstat;
    robots_fs->lstat = robots_fsio_lstat;
    robots_fs->unlink = robots_fsio_unlink;
    robots_fs->open = robots_fsio_open;
    robots_fs->close = robots_fsio_close;
    robots_fs->read = robots_fsio_read;
    robots_fs->write = robots_fsio_write;
    robots_fs->access = robots_fsio_access;
    robots_fs->faccess = robots_fsio_faccess;

    /* For all other FSIO callbacks, use the underlying FS. */
    robots_fs->rename = curr_fs->rename;
    robots_fs->lseek = curr_fs->lseek;
    robots_fs->link = curr_fs->link;
    robots_fs->readlink = curr_fs->readlink;
    robots_fs->symlink = curr_fs->symlink;
    robots_fs->ftruncate = curr_fs->ftruncate;
    robots_fs->truncate = curr_fs->truncate;
    robots_fs->chmod = curr_fs->chmod;
    robots_fs->fchmod = curr_fs->fchmod;
    robots_fs->chown = curr_fs->chown;
    robots_fs->fchown = curr_fs->fchown;
    robots_fs->lchown = curr_fs->lchown;
    robots_fs->utimes = curr_fs->utimes;
    robots_fs->futimes = curr_fs->futimes;
    robots_fs->fsync = curr_fs->fsync;

    pr_fs_clear_cache2(path);
    auth_anon_allow_robots_enabled = TRUE;
  }

  return PR_DECLINED(cmd);
}

MODRET auth_post_retr(cmd_rec *cmd) {
  if (auth_anon_allow_robots == TRUE) {
    return PR_DECLINED(cmd);
  }

  if (auth_anon_allow_robots_enabled == TRUE) {
    int res;

    res = pr_unregister_fs("/robots.txt");
    if (res < 0) {
      pr_log_debug(DEBUG9, "error removing 'robots' FS for '/robots.txt': %s",
        strerror(errno));
    }

    auth_anon_allow_robots_enabled = FALSE;
  }

  return PR_DECLINED(cmd);
}

/* Configuration handlers
 */

MODRET set_accessdenymsg(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET set_accessgrantmsg(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: AllowChrootSymlinks on|off */
MODRET set_allowchrootsymlinks(cmd_rec *cmd) {
  int allow_chroot_symlinks = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  allow_chroot_symlinks = get_boolean(cmd, 1);
  if (allow_chroot_symlinks == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = allow_chroot_symlinks;

  return PR_HANDLED(cmd);
}

/* usage: AllowEmptyPasswords on|off */
MODRET set_allowemptypasswords(cmd_rec *cmd) {
  int allow_empty_passwords = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  allow_empty_passwords = get_boolean(cmd, 1);
  if (allow_empty_passwords == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = allow_empty_passwords;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: AnonAllowRobots on|off */
MODRET set_anonallowrobots(cmd_rec *cmd) {
  int allow_robots = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON);

  allow_robots = get_boolean(cmd, 1);
  if (allow_robots == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = allow_robots;

  return PR_HANDLED(cmd);
}

MODRET set_anonrequirepassword(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: AnonRejectPasswords pattern [flags] */
MODRET set_anonrejectpasswords(cmd_rec *cmd) {
#ifdef PR_USE_REGEX
  config_rec *c;
  pr_regex_t *pre = NULL;
  int notmatch = FALSE, regex_flags = REG_EXTENDED|REG_NOSUB, res = 0;
  char *pattern = NULL;

  if (cmd->argc-1 < 1 ||
      cmd->argc-1 > 2) {
    CONF_ERROR(cmd, "bad number of parameters");
  }

  CHECK_CONF(cmd, CONF_ANON);

  /* Make sure that, if present, the flags parameter is correctly formatted. */
  if (cmd->argc-1 == 2) {
    int flags = 0;

    /* We need to parse the flags parameter here, to see if any flags which
     * affect the compilation of the regex (e.g. NC) are present.
     */

    flags = pr_filter_parse_flags(cmd->tmp_pool, cmd->argv[2]);
    if (flags < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        ": badly formatted flags parameter: '", cmd->argv[2], "'", NULL));
    }

    if (flags == 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        ": unknown flags '", cmd->argv[2], "'", NULL));
    }

    regex_flags |= flags;
  }

  pre = pr_regexp_alloc(&auth_module);

  pattern = cmd->argv[1];
  if (*pattern == '!') {
    notmatch = TRUE;
    pattern++;
  }

  res = pr_regexp_compile(pre, pattern, regex_flags);
  if (res != 0) {
    char errstr[200] = {'\0'};

    pr_regexp_error(res, pre, errstr, 200);
    pr_regexp_free(NULL, pre);

    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "Unable to compile regex '",
      cmd->argv[1], "': ", errstr, NULL));
  }

  c = add_config_param(cmd->argv[0], 2, pre, NULL);
  c->argv[1] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = notmatch;
  return PR_HANDLED(cmd);

#else
  CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "The ", cmd->argv[0], " directive "
    "cannot be used on this system, as you do not have POSIX compliant "
    "regex support", NULL));
#endif
}

MODRET set_authaliasonly(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

MODRET set_authusingalias(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

MODRET set_createhome(cmd_rec *cmd) {
  int bool = -1, start = 2;
  mode_t mode = (mode_t) 0700, dirmode = (mode_t) 0711;
  char *skel_path = NULL;
  config_rec *c = NULL;
  uid_t cuid = 0;
  gid_t cgid = 0, hgid = -1;
  unsigned long flags = 0UL;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  /* No need to process the rest if bool is FALSE. */
  if (bool == FALSE) {
    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) c->argv[0]) = bool;

    return PR_HANDLED(cmd);
  }

  /* Check the mode parameter, if present */
  if (cmd->argc-1 >= 2 &&
      strcasecmp(cmd->argv[2], "dirmode") != 0 &&
      strcasecmp(cmd->argv[2], "skel") != 0) {
    char *tmp = NULL;

    mode = strtol(cmd->argv[2], &tmp, 8);

    if (tmp && *tmp)
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": bad mode parameter: '",
        cmd->argv[2], "'", NULL));

    start = 3;
  }

  if (cmd->argc-1 > 2) {
    register unsigned int i;

    /* Cycle through the rest of the parameters */
    for (i = start; i < cmd->argc;) {
      if (strcasecmp(cmd->argv[i], "skel") == 0) {
        struct stat st;

        /* Check that the skel directory, if configured, meets the
         * requirements.
         */

        skel_path = cmd->argv[++i];

        if (*skel_path != '/') {
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "skel path '",
            skel_path, "' is not a full path", NULL));
        }

        if (pr_fsio_stat(skel_path, &st) < 0) {
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to stat '",
            skel_path, "': ", strerror(errno), NULL));
        }

        if (!S_ISDIR(st.st_mode)) {
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", skel_path,
            "' is not a directory", NULL));
        }

        /* Must not be world-writable. */
        if (st.st_mode & S_IWOTH) {
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", skel_path,
            "' is world-writable", NULL));
        }

        /* Move the index past the skel parameter */
        i++;

      } else if (strcasecmp(cmd->argv[i], "dirmode") == 0) {
        char *tmp = NULL;

        dirmode = strtol(cmd->argv[++i], &tmp, 8);
 
        if (tmp && *tmp)
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad mode parameter: '",
            cmd->argv[i], "'", NULL));

        /* Move the index past the dirmode parameter */
        i++;

      } else if (strcasecmp(cmd->argv[i], "uid") == 0) {

        /* Check for a "~" parameter. */
        if (strncmp(cmd->argv[i+1], "~", 2) != 0) {
          uid_t uid;

          if (pr_str2uid(cmd->argv[++i], &uid) < 0) { 
            CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad UID parameter: '",
              cmd->argv[i], "'", NULL));
          }

          cuid = uid;

        } else {
          cuid = (uid_t) -1;       
          i++;
        }

        /* Move the index past the uid parameter */
        i++;

      } else if (strcasecmp(cmd->argv[i], "gid") == 0) {

        /* Check for a "~" parameter. */
        if (strncmp(cmd->argv[i+1], "~", 2) != 0) {
          gid_t gid;

          if (pr_str2gid(cmd->argv[++i], &gid) < 0) {
            CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad GID parameter: '",
              cmd->argv[i], "'", NULL));
          }

          cgid = gid;

        } else {
          cgid = (gid_t) -1;
          i++;
        }

        /* Move the index past the gid parameter */
        i++;

      } else if (strcasecmp(cmd->argv[i], "homegid") == 0) {
        char *tmp = NULL;
        gid_t gid;

        gid = strtol(cmd->argv[++i], &tmp, 10);

        if (tmp && *tmp) {
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad GID parameter: '",
            cmd->argv[i], "'", NULL));
        }

        hgid = gid;

        /* Move the index past the homegid parameter */
        i++;

      } else if (strcasecmp(cmd->argv[i], "NoRootPrivs") == 0) {
        flags |= PR_MKHOME_FL_USE_USER_PRIVS;
        i++;

      } else {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown parameter: '",
          cmd->argv[i], "'", NULL));
      }
    }
  }

  c = add_config_param(cmd->argv[0], 8, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL);

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;
  c->argv[1] = pcalloc(c->pool, sizeof(mode_t));
  *((mode_t *) c->argv[1]) = mode;
  c->argv[2] = pcalloc(c->pool, sizeof(mode_t));
  *((mode_t *) c->argv[2]) = dirmode;

  if (skel_path) {
    c->argv[3] = pstrdup(c->pool, skel_path);
  }

  c->argv[4] = pcalloc(c->pool, sizeof(uid_t));
  *((uid_t *) c->argv[4]) = cuid;
  c->argv[5] = pcalloc(c->pool, sizeof(gid_t));
  *((gid_t *) c->argv[5]) = cgid;
  c->argv[6] = pcalloc(c->pool, sizeof(gid_t));
  *((gid_t *) c->argv[6]) = hgid;
  c->argv[7] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[7]) = flags;
 
  return PR_HANDLED(cmd);
}

MODRET add_defaultroot(cmd_rec *cmd) {
  config_rec *c;
  char *dir;
  unsigned int argc;
  void **argv;
  array_header *acl = NULL;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "syntax: DefaultRoot <directory> [<group-expression>]");
  }

  argc = cmd->argc - 2;
  argv = cmd->argv;

  dir = *++argv;

  /* dir must be / or ~. */
  if (*dir != '/' &&
      *dir != '~') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "(", dir, ") absolute pathname "
      "required", NULL));
  }

  if (strchr(dir, '*')) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "(", dir, ") wildcards not allowed "
      "in pathname", NULL));
  }

  if (*(dir + strlen(dir) - 1) != '/') {
    dir = pstrcat(cmd->tmp_pool, dir, "/", NULL);
  }

  acl = pr_expr_create(cmd->tmp_pool, &argc, (char **) argv);
  c = add_config_param(cmd->argv[0], 0);

  c->argc = argc + 1;
  c->argv = pcalloc(c->pool, (argc + 2) * sizeof(void *));
  argv = c->argv;
  *argv++ = pstrdup(c->pool, dir);

  if (argc && acl)
    while(argc--) {
      *argv++ = pstrdup(c->pool, *((char **) acl->elts));
      acl->elts = ((char **) acl->elts) + 1;
    }

  *argv = NULL;
  return PR_HANDLED(cmd);
}

MODRET add_defaultchdir(cmd_rec *cmd) {
  config_rec *c;
  char *dir;
  unsigned int argc;
  void **argv;
  array_header *acl = NULL;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "syntax: DefaultChdir <directory> [<group-expression>]");
  }

  argc = cmd->argc - 2;
  argv = cmd->argv;

  dir = *++argv;

  if (strchr(dir, '*')) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "(", dir, ") wildcards not allowed "
      "in pathname", NULL));
  }

  if (*(dir + strlen(dir) - 1) != '/') {
    dir = pstrcat(cmd->tmp_pool, dir, "/", NULL);
  }

  acl = pr_expr_create(cmd->tmp_pool, &argc, (char **) argv);
  c = add_config_param(cmd->argv[0], 0);

  c->argc = argc + 1;
  c->argv = pcalloc(c->pool, (argc + 2) * sizeof(void *));
  argv = c->argv;
  *argv++ = pstrdup(c->pool, dir);

  if (argc && acl) {
    while(argc--) {
      *argv++ = pstrdup(c->pool, *((char **) acl->elts));
      acl->elts = ((char **) acl->elts) + 1;
    }
  }

  *argv = NULL;

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

MODRET set_displaylogin(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: MaxClientsPerClass class max|"none" ["message"] */
MODRET set_maxclientsclass(cmd_rec *cmd) {
  int max;
  config_rec *c;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[2], "none") == 0)
    max = 0;

  else {
    char *endp = NULL;

    max = (int) strtol(cmd->argv[2], &endp, 10);

    if ((endp && *endp) || max < 1)
      CONF_ERROR(cmd, "max must be 'none' or a number greater than 0");
  }

  if (cmd->argc == 4) {
    c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);
    c->argv[0] = pstrdup(c->pool, cmd->argv[1]);
    c->argv[1] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[1]) = max;
    c->argv[2] = pstrdup(c->pool, cmd->argv[3]);

  } else {
    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[0] = pstrdup(c->pool, cmd->argv[1]);
    c->argv[1] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[1]) = max;
  }

  return PR_HANDLED(cmd);
}

/* usage: MaxClients max|"none" ["message"] */
MODRET set_maxclients(cmd_rec *cmd) {
  int max;
  config_rec *c = NULL;

  if (cmd->argc < 2 || cmd->argc > 3)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if (!strcasecmp(cmd->argv[1], "none"))
    max = 0;

  else {
    char *endp = NULL;

    max = (int) strtol(cmd->argv[1], &endp, 10);

    if ((endp && *endp) || max < 1)
      CONF_ERROR(cmd, "parameter must be 'none' or a number greater than 0");
  }

  if (cmd->argc == 3) {
    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[0]) = max;
    c->argv[1] = pstrdup(c->pool, cmd->argv[2]);

  } else {
    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[0]) = max;
  }

  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: MaxClientsPerHost max|"none" ["message"] */
MODRET set_maxhostclients(cmd_rec *cmd) {
  int max;
  config_rec *c = NULL;

  if (cmd->argc < 2 || cmd->argc > 3)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if (!strcasecmp(cmd->argv[1], "none"))
    max = 0;

  else {
    char *endp = NULL;

    max = (int) strtol(cmd->argv[1], &endp, 10);

    if ((endp && *endp) || max < 1)
      CONF_ERROR(cmd, "parameter must be 'none' or a number greater than 0");
  }

  if (cmd->argc == 3) {
    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[0]) = max;
    c->argv[1] = pstrdup(c->pool, cmd->argv[2]);

  } else {
    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[0]) = max;
  }

  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}


/* usage: MaxClientsPerUser max|"none" ["message"] */
MODRET set_maxuserclients(cmd_rec *cmd) {
  int max;
  config_rec *c = NULL;

  if (cmd->argc < 2 || cmd->argc > 3)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if (!strcasecmp(cmd->argv[1], "none"))
    max = 0;

  else {
    char *endp = NULL;

    max = (int) strtol(cmd->argv[1], &endp, 10);

    if ((endp && *endp) || max < 1)
      CONF_ERROR(cmd, "parameter must be 'none' or a number greater than 0");
  }

  if (cmd->argc == 3) {
    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[0]) = max;
    c->argv[1] = pstrdup(c->pool, cmd->argv[2]);

  } else {
    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[0]) = max;
  }

  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: MaxConnectionsPerHost max|"none" ["message"] */
MODRET set_maxconnectsperhost(cmd_rec *cmd) {
  int max;
  config_rec *c;

  if (cmd->argc < 2 || cmd->argc > 3)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "none") == 0)
    max = 0;

  else {
    char *tmp = NULL;

    max = (int) strtol(cmd->argv[1], &tmp, 10);

    if ((tmp && *tmp) || max < 1)
      CONF_ERROR(cmd, "parameter must be 'none' or a number greater than 0");
  }

  if (cmd->argc == 3) {
    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[1] = pstrdup(c->pool, cmd->argv[2]);

  } else
    c = add_config_param(cmd->argv[0], 1, NULL);

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = max;

  return PR_HANDLED(cmd);
}

/* usage: MaxHostsPerUser max|"none" ["message"] */
MODRET set_maxhostsperuser(cmd_rec *cmd) {
  int max;
  config_rec *c = NULL;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if (cmd->argc < 2 || cmd->argc > 3)
    CONF_ERROR(cmd, "wrong number of parameters");

  if (!strcasecmp(cmd->argv[1], "none"))
    max = 0;

  else {
    char *endp = NULL;

    max = (int) strtol(cmd->argv[1], &endp, 10);

    if ((endp && *endp) || max < 1)
      CONF_ERROR(cmd, "parameter must be 'none' or a number greater than 0");
  }

  if (cmd->argc == 3) {
    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[0]) = max;
    c->argv[1] = pstrdup(c->pool, cmd->argv[2]);

  } else {
    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[0]) = max;
  }

  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET set_maxloginattempts(cmd_rec *cmd) {
  int max;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "none") == 0) {
    max = 0;

  } else {
    char *endp = NULL;
    max = (int) strtol(cmd->argv[1], &endp, 10);

    if ((endp && *endp) || max < 1)
      CONF_ERROR(cmd, "parameter must be 'none' or a number greater than 0");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = max;

  return PR_HANDLED(cmd);
}

/* usage: MaxPasswordSize len */
MODRET set_maxpasswordsize(cmd_rec *cmd) {
  config_rec *c;
  size_t password_len;
  char *len, *ptr = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  len = cmd->argv[1];
  if (*len == '-') {
    CONF_ERROR(cmd, "badly formatted parameter");
  }

  password_len = strtoul(len, &ptr, 10);
  if (ptr && *ptr) {
    CONF_ERROR(cmd, "badly formatted parameter");
  }

/* XXX Applies to the following modules, which use crypt(3):
 *
 *  mod_ldap (ldap_auth_check; "check" authtab)
 *    ldap_auth_auth ("auth" authtab) calls pr_auth_check()
 *  mod_sql (sql_auth_crypt, via SQLAuthTypes; cmd_check "check" authtab dispatches here)
 *    cmd_auth ("auth" authtab) calls pr_auth_check()
 *  mod_auth_file (authfile_chkpass, "check" authtab)
 *    authfile_auth ("auth" authtab) calls pr_auth_check()
 *  mod_auth_unix (pw_check, "check" authtab)
 *    pw_auth ("auth" authtab) calls pr_auth_check()
 *
 *  mod_sftp uses pr_auth_authenticate(), which will dispatch into above
 *
 *  mod_radius does NOT use either -- up to RADIUS server policy?
 *
 * Is there a common code path that all of the above go through?
 */

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(size_t));
  *((size_t *) c->argv[0]) = password_len;

  return PR_HANDLED(cmd);
}

MODRET set_requirevalidshell(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: RewriteHome on|off */
MODRET set_rewritehome(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

MODRET set_rootlogin(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd,1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = (unsigned char) bool;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: RootRevoke on|off|UseNonCompliantActiveTransfer */
MODRET set_rootrevoke(cmd_rec *cmd) {
  int root_revoke = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  /* A RootRevoke value of 0 indicates 'false', 1 indicates 'true', and
   * 2 indicates 'NonCompliantActiveTransfer'.
   */
  root_revoke = get_boolean(cmd, 1);
  if (root_revoke == -1) {
    if (strcasecmp(cmd->argv[1], "UseNonCompliantActiveTransfer") != 0 &&
        strcasecmp(cmd->argv[1], "UseNonCompliantActiveTransfers") != 0) {
      CONF_ERROR(cmd, "expected Boolean parameter");
    }

    root_revoke = 2;
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = root_revoke;

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

MODRET set_timeoutlogin(cmd_rec *cmd) {
  int timeout = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (pr_str_get_duration(cmd->argv[1], &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      cmd->argv[1], "': ", strerror(errno), NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;

  return PR_HANDLED(cmd);
}

MODRET set_timeoutsession(cmd_rec *cmd) {
  int timeout = 0, precedence = 0;
  config_rec *c = NULL;

  int ctxt = (cmd->config && cmd->config->config_type != CONF_PARAM ?
     cmd->config->config_type : cmd->server->config_type ?
     cmd->server->config_type : CONF_ROOT);

  /* this directive must have either 1 or 3 arguments */
  if (cmd->argc-1 != 1 &&
      cmd->argc-1 != 3) {
    CONF_ERROR(cmd, "missing parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

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
  }

  if (pr_str_get_duration(cmd->argv[1], &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      cmd->argv[1], "': ", strerror(errno), NULL));
  }

  if (timeout == 0) {
    /* do nothing */
    return PR_HANDLED(cmd);
  }

  if (cmd->argc-1 == 3) {
    if (strncmp(cmd->argv[2], "user", 5) == 0 ||
        strncmp(cmd->argv[2], "group", 6) == 0 ||
        strncmp(cmd->argv[2], "class", 6) == 0) {

       /* no op */

     } else {
       CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, cmd->argv[0],
         ": unknown classifier used: '", cmd->argv[2], "'", NULL));
    }
  }

  if (cmd->argc-1 == 1) {
    c = add_config_param(cmd->argv[0], 2, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(int));
    *((int *) c->argv[0]) = timeout;
    c->argv[1] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[1]) = precedence;

  } else if (cmd->argc-1 == 3) {
    array_header *acl = NULL;
    unsigned int argc;
    void **argv;

    argc = cmd->argc - 3;
    argv = cmd->argv + 2;

    acl = pr_expr_create(cmd->tmp_pool, &argc, (char **) argv);

    c = add_config_param(cmd->argv[0], 0);
    c->argc = argc + 2;

    /* Add 3 to argc for the argv of the config_rec: one for the
     * seconds value, one for the precedence, one for the classifier,
     * and one for the terminating NULL.
     */
    c->argv = pcalloc(c->pool, ((argc + 4) * sizeof(void *)));

    /* Capture the config_rec's argv pointer for doing the by-hand
     * population.
     */
    argv = c->argv;

    /* Copy in the seconds. */
    *argv = pcalloc(c->pool, sizeof(int));
    *((int *) *argv++) = timeout;

    /* Copy in the precedence. */
    *argv = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) *argv++) = precedence;

    /* Copy in the classifier. */
    *argv++ = pstrdup(c->pool, cmd->argv[2]);

    /* now, copy in the expression arguments */
    if (argc && acl) {
      while (argc--) {
        *argv++ = pstrdup(c->pool, *((char **) acl->elts));
        acl->elts = ((char **) acl->elts) + 1;
      }
    }

    /* don't forget the terminating NULL */
    *argv = NULL;

  } else {
    /* Should never reach here. */
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  c->flags |= CF_MERGEDOWN_MULTI;
  return PR_HANDLED(cmd);
}

MODRET set_useftpusers(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: UseLastlog on|off */
MODRET set_uselastlog(cmd_rec *cmd) {
#ifdef PR_USE_LASTLOG
  int bool;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
#else
  CONF_ERROR(cmd, "requires lastlog support (--with-lastlog)");
#endif /* PR_USE_LASTLOG */
}

/* usage: UserAlias alias real-user */
MODRET set_useralias(cmd_rec *cmd) {
  config_rec *c = NULL;
  char *alias, *real_user;

  CHECK_ARGS(cmd, 2);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  /* Make sure that the given names differ. */
  alias = cmd->argv[1];
  real_user = cmd->argv[2];

  if (strcmp(alias, real_user) == 0) {
    CONF_ERROR(cmd, "alias and real user names must differ");
  }

  c = add_config_param_str(cmd->argv[0], 2, alias, real_user);

  /* Note: only merge this directive down if it is not appearing in an
   * <Anonymous> context.
   */
  if (!check_context(cmd, CONF_ANON)) {
    c->flags |= CF_MERGEDOWN_MULTI;
  }

  return PR_HANDLED(cmd);
}

MODRET set_userdirroot(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

MODRET set_userpassword(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 2);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param_str(cmd->argv[0], 2, cmd->argv[1], cmd->argv[2]);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: WtmpLog on|off */
MODRET set_wtmplog(cmd_rec *cmd) {
  int use_wtmp = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if (strcasecmp(cmd->argv[1], "NONE") == 0) {
    use_wtmp = FALSE;

  } else {
    use_wtmp = get_boolean(cmd, 1);
    if (use_wtmp == -1) {
      CONF_ERROR(cmd, "expected Boolean parameter");
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = use_wtmp;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* Module API tables
 */

static conftable auth_conftab[] = {
  { "AccessDenyMsg",		set_accessdenymsg,		NULL },
  { "AccessGrantMsg",		set_accessgrantmsg,		NULL },
  { "AllowChrootSymlinks",	set_allowchrootsymlinks,	NULL },
  { "AllowEmptyPasswords",	set_allowemptypasswords,	NULL },
  { "AnonAllowRobots",		set_anonallowrobots,		NULL },
  { "AnonRequirePassword",	set_anonrequirepassword,	NULL },
  { "AnonRejectPasswords",	set_anonrejectpasswords,	NULL },
  { "AuthAliasOnly",		set_authaliasonly,		NULL },
  { "AuthUsingAlias",		set_authusingalias,		NULL },
  { "CreateHome",		set_createhome,			NULL },
  { "DefaultChdir",		add_defaultchdir,		NULL },
  { "DefaultRoot",		add_defaultroot,		NULL },
  { "DisplayLogin",		set_displaylogin,		NULL },
  { "MaxClients",		set_maxclients,			NULL },
  { "MaxClientsPerClass",	set_maxclientsclass,		NULL },
  { "MaxClientsPerHost",	set_maxhostclients,		NULL },
  { "MaxClientsPerUser",	set_maxuserclients,		NULL },
  { "MaxConnectionsPerHost",	set_maxconnectsperhost,		NULL },
  { "MaxHostsPerUser",		set_maxhostsperuser,		NULL },
  { "MaxLoginAttempts",		set_maxloginattempts,		NULL },
  { "MaxPasswordSize",		set_maxpasswordsize,		NULL },
  { "RequireValidShell",	set_requirevalidshell,		NULL },
  { "RewriteHome",		set_rewritehome,		NULL },
  { "RootLogin",		set_rootlogin,			NULL },
  { "RootRevoke",		set_rootrevoke,			NULL },
  { "TimeoutLogin",		set_timeoutlogin,		NULL },
  { "TimeoutSession",		set_timeoutsession,		NULL },
  { "UseFtpUsers",		set_useftpusers,		NULL },
  { "UseLastlog",		set_uselastlog,			NULL },
  { "UserAlias",		set_useralias,			NULL },
  { "UserDirRoot",		set_userdirroot,		NULL },
  { "UserPassword",		set_userpassword,		NULL },
  { "WtmpLog",			set_wtmplog,			NULL },

  { NULL,			NULL,				NULL }
};

static cmdtable auth_cmdtab[] = {
  { PRE_CMD,	C_USER,	G_NONE,	auth_pre_user,	FALSE,	FALSE,	CL_AUTH },
  { CMD,	C_USER,	G_NONE,	auth_user,	FALSE,	FALSE,	CL_AUTH },
  { PRE_CMD,	C_PASS,	G_NONE,	auth_pre_pass,	FALSE,	FALSE,	CL_AUTH },
  { CMD,	C_PASS,	G_NONE,	auth_pass,	FALSE,	FALSE,	CL_AUTH },
  { POST_CMD,	C_PASS,	G_NONE,	auth_post_pass,	FALSE,	FALSE,	CL_AUTH },
  { LOG_CMD,	C_PASS,	G_NONE,	auth_log_pass,  FALSE,  FALSE },
  { LOG_CMD_ERR,C_PASS,	G_NONE,	auth_err_pass,  FALSE,  FALSE },
  { CMD,	C_ACCT,	G_NONE,	auth_acct,	FALSE,	FALSE,	CL_AUTH },
  { CMD,	C_REIN,	G_NONE,	auth_rein,	FALSE,	FALSE,	CL_AUTH },

  /* For the automatic robots.txt handling */
  { PRE_CMD,	C_RETR,	G_NONE,	auth_pre_retr,	FALSE,	FALSE },
  { POST_CMD,	C_RETR,	G_NONE,	auth_post_retr,	FALSE,	FALSE },
  { POST_CMD_ERR,C_RETR,G_NONE,	auth_post_retr,	FALSE,	FALSE },

  { 0, NULL }
};

/* Module interface */

module auth_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "auth",

  /* Module configuration directive table */
  auth_conftab,	

  /* Module command handler table */
  auth_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  auth_init,

  /* Session initialization function */
  auth_sess_init
};

