/*
 * ProFTPD: mod_sftp_pam -- a module which provides an SSH2
 *                          "keyboard-interactive" driver using PAM
 * Copyright (c) 2008-2017 TJ Saunders
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
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_sftp_pam, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 *
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Libraries: -lpam$
 */

#include "conf.h"
#include "privs.h"
#include "mod_sftp.h"

#ifndef HAVE_PAM
# error "mod_sftp_pam requires PAM support on your system"
#endif

#define MOD_SFTP_PAM_VERSION		"mod_sftp_pam/0.3"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030202
# error "ProFTPD 1.3.2rc2 or later required"
#endif

#ifdef HAVE_SECURITY_PAM_APPL_H
# ifdef HPUX11
#  ifndef COMSEC
#    define COMSEC 1
#  endif
# endif /* HPUX11 */
# include <security/pam_appl.h>
#endif /* HAVE_SECURITY_PAM_APPL_H */

#ifdef HAVE_SECURITY_PAM_MODULES_H
# include <security/pam_modules.h>
#endif /* HAVE_SECURITY_PAM_MODULES_H */

/* Needed for the MAXLOGNAME restriction. */
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif

#ifdef HAVE_PAM_PAM_APPL_H
#include <pam/pam_appl.h>
#endif /* HAVE_PAM_PAM_APPL_H */

/* There is ambiguity in the PAM spec, with regard to the list of
 * struct pam_message that is passed to the conversation callback.  Is it
 * a pointer to an array, or an array of pointers?
 */
#if defined(SOLARIS2) || defined(HPUX11)
# define SFTP_PAM_MSG_MEMBER(msg, n, member)	((*(msg))[(n)].member)
#else
# define SFTP_PAM_MSG_MEMBER(msg, n, member)	((msg)[(n)]->member)
#endif

/* On non-Solaris systems, the struct pam_message argument of pam_conv is
 * declared const, but on Solaris, it isn't.  To avoid compiler warnings about
 * incompatible pointer types, we need to use const or not as appropriate.
 */
#ifndef SOLARIS2
# define PR_PAM_CONST   const
#else
# define PR_PAM_CONST 
#endif 

#define SFTP_PAM_OPT_NO_TTY		0x001
#define SFTP_PAM_OPT_NO_INFO_MSGS	0x002
#define SFTP_PAM_OPT_NO_RADIO_MSGS	0x004

module sftp_pam_module;

static void sftppam_exit_ev(const void *, void *);
MODRET sftppam_auth(cmd_rec *);

static sftp_kbdint_driver_t sftppam_driver;
static authtable sftppam_authtab[];

static pam_handle_t *sftppam_pamh = NULL;
static const char *sftppam_service = "sshd";

static int sftppam_authoritative = FALSE;
static int sftppam_auth_code = PR_AUTH_OK;
static int sftppam_handle_auth = FALSE;
static unsigned long sftppam_opts = 0UL;
static char *sftppam_user = NULL;
static size_t sftppam_userlen = 0;
static char sftppam_tty[32];

static const char *trace_channel = "ssh2";

/* PAM interaction
 */

static int sftppam_converse(int nmsgs, PR_PAM_CONST struct pam_message **msgs,
    struct pam_response **resps, void *app_data) {
  register int i = 0, j = 0;
  array_header *list;
  uint32_t recvd_count = 0;
  const char **recvd_responses = NULL;
  struct pam_response *res = NULL;

  if (nmsgs <= 0 ||
      nmsgs > PAM_MAX_NUM_MSG) {
    pr_trace_msg(trace_channel, 3, "bad number of PAM messages (%d)", nmsgs);
    return PAM_CONV_ERR;
  }

  pr_trace_msg(trace_channel, 9, "handling %d PAM %s", nmsgs,
    nmsgs == 1 ? "message" : "messages");

  /* First, send these messages to the client. */

  list = make_array(sftppam_driver.driver_pool, 1,
    sizeof(sftp_kbdint_challenge_t));

  for (i = 0; i < nmsgs; i++) {
    sftp_kbdint_challenge_t *challenge;

    /* Skip PAM_ERROR_MSG messages; we don't want to send these to the client.
     */
    if (SFTP_PAM_MSG_MEMBER(msgs, i, msg_style) == PAM_TEXT_INFO) {
      if (sftppam_opts & SFTP_PAM_OPT_NO_INFO_MSGS) {
        pr_trace_msg(trace_channel, 9,
          "skipping sending of PAM_TEXT_INFO '%s' to client",
          SFTP_PAM_MSG_MEMBER(msgs, i, msg));

      } else {
        pr_trace_msg(trace_channel, 9, "sending PAM_TEXT_INFO '%s' to client",
          SFTP_PAM_MSG_MEMBER(msgs, i, msg));

        sftp_auth_send_banner(SFTP_PAM_MSG_MEMBER(msgs, i, msg));
      }

      continue;

#ifdef PAM_RADIO_TYPE
    } else if (SFTP_PAM_MSG_MEMBER(msgs, i, msg_style) == PAM_RADIO_TYPE) {
      if (sftppam_opts & SFTP_PAM_OPT_NO_RADIO_MSGS) {
        pr_trace_msg(trace_channel, 9,
          "skipping sending of PAM_RADIO_TYPE '%s' to client",
          SFTP_PAM_MSG_MEMBER(msgs, i, msg));

      } else {
        pr_trace_msg(trace_channel, 9, "sending PAM_RADIO_TYPE '%s' to client",
          SFTP_PAM_MSG_MEMBER(msgs, i, msg));

        sftp_auth_send_banner(SFTP_PAM_MSG_MEMBER(msgs, i, msg));
      }

      continue;
#endif /* PAM_RADIO_TYPE */

    } else if (SFTP_PAM_MSG_MEMBER(msgs, i, msg_style) == PAM_ERROR_MSG) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_PAM_VERSION,
        "received PAM_ERROR_MSG '%s'", SFTP_PAM_MSG_MEMBER(msgs, i, msg));
      continue;
    }

    challenge = push_array(list);
    challenge->challenge = pstrdup(sftppam_driver.driver_pool,
      SFTP_PAM_MSG_MEMBER(msgs, i, msg));
    challenge->display_response = FALSE;
  }

  if (list->nelts == 0) {
    /* Nothing to see here, move along. */
    return PAM_SUCCESS;
  }

  if (sftp_kbdint_send_challenge(NULL, NULL, list->nelts, list->elts) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error sending keyboard-interactive challenges: %s", strerror(errno));
    return PAM_CONV_ERR;
  }

  if (sftp_kbdint_recv_response(sftppam_driver.driver_pool, list->nelts,
      &recvd_count, &recvd_responses) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error receiving keyboard-interactive responses: %s", strerror(errno));
    return PAM_CONV_ERR;
  }

  res = calloc(nmsgs, sizeof(struct pam_response));
  if (res == NULL) {
    pr_log_pri(PR_LOG_ALERT, MOD_SFTP_PAM_VERSION ": Out of memory!");
    return PAM_BUF_ERR;
  }

  for (i = 0; i < nmsgs; i++) {
    res[i].resp_retcode = 0;

    switch (SFTP_PAM_MSG_MEMBER(msgs, i, msg_style)) {
      case PAM_PROMPT_ECHO_ON:
        pr_trace_msg(trace_channel, 9,
          "received PAM_PROMPT_ECHO_ON message '%s', responding with '%s'",
          SFTP_PAM_MSG_MEMBER(msgs, i, msg), recvd_responses[i]);
        res[i].resp = strdup(recvd_responses[i]); 
        break;

      case PAM_PROMPT_ECHO_OFF:
        pr_trace_msg(trace_channel, 9,
          "received PAM_PROMPT_ECHO_OFF message '%s', responding with text",
          SFTP_PAM_MSG_MEMBER(msgs, i, msg));
        res[i].resp = strdup(recvd_responses[i]); 
        break;

      case PAM_TEXT_INFO:
        pr_trace_msg(trace_channel, 9, "received PAM_TEXT_INFO message: %s",
          SFTP_PAM_MSG_MEMBER(msgs, i, msg));
        res[i].resp = NULL;
        break;

      case PAM_ERROR_MSG:
        pr_trace_msg(trace_channel, 9, "received PAM_ERROR_MSG message: %s",
          SFTP_PAM_MSG_MEMBER(msgs, i, msg));
        res[i].resp = NULL;
        break;

#ifdef PAM_RADIO_TYPE
    case PAM_RADIO_TYPE:
        pr_trace_msg(trace_channel, 9, "received PAM_RADIO_TYPE message: %s",
          SFTP_PAM_MSG_MEMBER(msgs, i, msg));
        res[i].resp = NULL;
        break;
#endif /* PAM_RADIO_TYPE */

      default:
        pr_trace_msg(trace_channel, 3,
          "received unknown PAM message style (%d), treating it as an error",
          SFTP_PAM_MSG_MEMBER(msgs, i, msg_style));
        for (j = 0; j < nmsgs; j++) {
          if (res[i].resp != NULL) {
            free(res[i].resp);
            res[i].resp = NULL;
          }
        }

        free(res);

        return PAM_CONV_ERR;
    }
  }

  *resps = res;
  return PAM_SUCCESS;
}

static const struct pam_conv sftppam_conv = { &sftppam_converse, NULL };

/* Driver callbacks
 */

static int sftppam_driver_open(sftp_kbdint_driver_t *driver, const char *user) {
  int res;
  config_rec *c;

  /* XXX Should we pay attention to AuthOrder here?  I.e. if AuthOrder
   * does not include mod_sftp_pam or mod_auth_pam, should we fail to
   * open this driver, since the AuthOrder indicates that no PAM check is
   * desired?  For this to work, AuthOrder needs to have been processed
   * prior to this callback being invoked...
   */

  /* Figure out our default return style: whether or not PAM should allow
   * other auth modules a shot at this user or not is controlled by adding
   * '*' to a module name in the AuthOrder directive.  By default, auth
   * modules are not authoritative, and allow other auth modules a chance at
   * authenticating the user.  This is not the most secure configuration, but
   * it allows things like AuthUserFile to work "out of the box".
   */
  if (sftppam_authtab[0].auth_flags & PR_AUTH_FL_REQUIRED) {
    sftppam_authoritative = TRUE;
  }

  sftppam_userlen = strlen(user) + 1;
  if (sftppam_userlen > (PAM_MAX_MSG_SIZE + 1)) {
    sftppam_userlen = PAM_MAX_MSG_SIZE + 1;
  }

#ifdef MAXLOGNAME
  /* Some platforms' PAM libraries do not handle login strings that exceed
   * this length.
   */
  if (sftppam_userlen > MAXLOGNAME) {
    pr_log_pri(PR_LOG_NOTICE,
      "PAM(%s): Name exceeds maximum login length (%u)", user, MAXLOGNAME);
    pr_trace_msg(trace_channel, 1,
      "user name '%s' exceeds maximum login length %u, declining", user,
      MAXLOGNAME);
    errno = EPERM;
    return -1;
  }
#endif

  sftppam_user = malloc(sftppam_userlen);
  if (sftppam_user == NULL) {
    pr_log_pri(PR_LOG_ALERT, MOD_SFTP_PAM_VERSION ": Out of memory!");
    exit(1);
  }

  memset(sftppam_user, '\0', sftppam_userlen);
  sstrncpy(sftppam_user, user, sftppam_userlen);

  c = find_config(main_server->conf, CONF_PARAM, "SFTPPAMOptions", FALSE);
  while (c != NULL) {
    unsigned long opts;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    sftppam_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "SFTPPAMOptions", FALSE);
  }
 
#ifdef SOLARIS2
  /* For Solaris environments, the TTY environment will always be set,
   * in order to workaround a bug (Solaris Bug ID 4250887) where
   * pam_open_session() will crash unless both PAM_RHOST and PAM_TTY are
   * set, and the PAM_TTY setting is at least greater than the length of
   * the string "/dev/".
   */
  sftppam_opts &= ~SFTP_PAM_OPT_NO_TTY;
#endif /* SOLARIS2 */
 
  pr_signals_block();
  PRIVS_ROOT

  res = pam_start(sftppam_service, sftppam_user, &sftppam_conv, &sftppam_pamh);
  if (res != PAM_SUCCESS) {
    PRIVS_RELINQUISH
    pr_signals_unblock();

    free(sftppam_user);
    sftppam_user = NULL;
    sftppam_userlen = 0;

    switch (res) {
      case PAM_SYSTEM_ERR:
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_PAM_VERSION,
          "error starting PAM service: %s", strerror(errno));
        break;

      case PAM_BUF_ERR:
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_PAM_VERSION,
          "error starting PAM service: Memory buffer error");
        break;
    }

    return -1;
  }

  pam_set_item(sftppam_pamh, PAM_RUSER, sftppam_user);
  pam_set_item(sftppam_pamh, PAM_RHOST, session.c->remote_name);

  if (!(sftppam_opts & SFTP_PAM_OPT_NO_TTY)) {
    memset(sftppam_tty, '\0', sizeof(sftppam_tty));
    pr_snprintf(sftppam_tty, sizeof(sftppam_tty), "/dev/ftpd%02lu",
      (unsigned long) (session.pid ? session.pid : getpid()));
    sftppam_tty[sizeof(sftppam_tty)-1] = '\0';

    pr_trace_msg(trace_channel, 9, "setting PAM_TTY to '%s'", sftppam_tty);
    pam_set_item(sftppam_pamh, PAM_TTY, sftppam_tty);
  }

  PRIVS_RELINQUISH
  pr_signals_unblock();

  /* We need to disable mod_auth_pam, since both mod_auth_pam and us want
   * to talk to the PAM API, just in different fashions.
   */

  c = add_config_param_set(&(main_server->conf), "AuthPAM", 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = FALSE;

  if (pr_auth_remove_auth_only_module("mod_auth_pam.c") < 0) {
    if (errno != ENOENT) {
      pr_log_pri(PR_LOG_NOTICE, MOD_SFTP_PAM_VERSION
        ": error removing 'mod_auth_pam.c' from the auth-only module list: %s",
        strerror(errno));
    }
  }

  if (pr_auth_add_auth_only_module("mod_sftp_pam.c") < 0) {
    if (errno != EEXIST) {
      pr_log_pri(PR_LOG_NOTICE, MOD_SFTP_PAM_VERSION
        ": error adding 'mod_sftp_pam.c' to the auth-only module list: %s",
        strerror(errno));
    }
  }

  sftppam_handle_auth = TRUE;

  driver->driver_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(driver->driver_pool, "PAM keyboard-interactive driver pool");

  return 0;
}

static int sftppam_driver_authenticate(sftp_kbdint_driver_t *driver,
    const char *user) {
  int res;

  pr_signals_block();
  PRIVS_ROOT

  res = pam_authenticate(sftppam_pamh, 0);
  if (res != PAM_SUCCESS) {
    switch (res) {
      case PAM_USER_UNKNOWN:
        sftppam_auth_code = PR_AUTH_NOPWD;
        break;

      default:
        sftppam_auth_code = PR_AUTH_BADPWD;
    }

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_PAM_VERSION,
      "PAM authentication error (%d) for user '%s': %s", res, user,
      pam_strerror(sftppam_pamh, res));
    (void) pr_log_pri(PR_LOG_NOTICE, MOD_SFTP_PAM_VERSION
      ": PAM authentication error (%d) for user '%s': %s", res, user,
      pam_strerror(sftppam_pamh, res));

    PRIVS_RELINQUISH
    pr_signals_unblock();

    errno = EPERM;
    return -1;
  }

  res = pam_acct_mgmt(sftppam_pamh, 0);
  if (res != PAM_SUCCESS) {
    switch (res) {
#ifdef PAM_AUTHTOKEN_REQD
      case PAM_AUTHTOKEN_REQD:
        pr_trace_msg(trace_channel, 8,
          "PAM account mgmt error: PAM_AUTHTOKEN_REQD");
        break;
#endif

      case PAM_ACCT_EXPIRED:
        pr_trace_msg(trace_channel, 8,
          "PAM account mgmt error: PAM_ACCT_EXPIRED");
        sftppam_auth_code = PR_AUTH_DISABLEDPWD;
        break;

#ifdef PAM_ACCT_DISABLED
      case PAM_ACCT_DISABLED:
        pr_trace_msg(trace_channel, 8,
          "PAM account mgmt error: PAM_ACCT_DISABLED");
        sftppam_auth_code = PR_AUTH_DISABLEDPWD;
        break;
#endif

      case PAM_USER_UNKNOWN:
        pr_trace_msg(trace_channel, 8,
          "PAM account mgmt error: PAM_USER_UNKNOWN");
        sftppam_auth_code = PR_AUTH_NOPWD;
        break;

      default:
        sftppam_auth_code = PR_AUTH_BADPWD;
        break;
    }

    pr_trace_msg(trace_channel, 1,
      "PAM account mgmt error (%d) for user '%s': %s", res, user,
      pam_strerror(sftppam_pamh, res));

    PRIVS_RELINQUISH
    pr_signals_unblock();

    errno = EPERM;
    return -1;
  }
 
  res = pam_open_session(sftppam_pamh, 0);
  if (res != PAM_SUCCESS) { 
    sftppam_auth_code = PR_AUTH_DISABLEDPWD;

    pr_trace_msg(trace_channel, 1,
      "PAM session error (%d) for user '%s': %s", res, user,
      pam_strerror(sftppam_pamh, res));

    PRIVS_RELINQUISH
    pr_signals_unblock();

    errno = EPERM;
    return -1;
  }

#ifdef PAM_CRED_ESTABLISH
  res = pam_setcred(sftppam_pamh, PAM_CRED_ESTABLISH);
#else
  res = pam_setcred(sftppam_pamh, PAM_ESTABLISH_CRED);
#endif /* !PAM_CRED_ESTABLISH */
  if (res != PAM_SUCCESS) {
    switch (res) {
      case PAM_CRED_EXPIRED:
        pr_trace_msg(trace_channel, 8,
          "PAM credentials error: PAM_CRED_EXPIRED");
        sftppam_auth_code = PR_AUTH_AGEPWD;
        break;

      case PAM_USER_UNKNOWN:
        pr_trace_msg(trace_channel, 8,
          "PAM credentials error: PAM_USER_UNKNOWN");
        sftppam_auth_code = PR_AUTH_NOPWD;
        break;

      default:
        sftppam_auth_code = PR_AUTH_BADPWD;
        break;
    }

    pr_trace_msg(trace_channel, 1,
      "PAM credentials error (%d) for user '%s': %s", res, user,
      pam_strerror(sftppam_pamh, res));

    PRIVS_RELINQUISH
    pr_signals_unblock();

    errno = EPERM;
    return -1;
  }

  /* XXX Not sure why these platforms have different treatment...? */
#if defined(SOLARIS2) || defined(HPUX10) || defined(HPUX11)
  res = pam_close_session(sftppam_pamh, 0);
  if (sftppam_pamh) {
    pam_end(sftppam_pamh, res);
    sftppam_pamh = NULL;
  }
#endif

  PRIVS_RELINQUISH
  pr_signals_unblock();

  return 0;
}

static int sftppam_driver_close(sftp_kbdint_driver_t *driver) {
  if (driver->driver_pool) {
    destroy_pool(driver->driver_pool);
    driver->driver_pool = NULL;
  }

  if (sftppam_user) {
    free(sftppam_user);
    sftppam_user = NULL;
    sftppam_userlen = 0;
  }

  return 0;
}

/* Auth handlers
 */

MODRET sftppam_auth(cmd_rec *cmd) {
  if (!sftppam_handle_auth) {
    return PR_DECLINED(cmd);
  }

  if (sftppam_auth_code != PR_AUTH_OK) {
    if (sftppam_authoritative) {
      return PR_ERROR_INT(cmd, sftppam_auth_code);
    }

    return PR_DECLINED(cmd);
  }

  session.auth_mech = "mod_sftp_pam.c";
  pr_event_register(&sftp_pam_module, "core.exit", sftppam_exit_ev, NULL);
  return PR_HANDLED(cmd);
}

/* Configuration handlers
 */

/* usage: SFTPPAMEngine on|off */
MODRET set_sftppamengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: SFTPPAMOptions opt1 ... */
MODRET set_sftppamoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "NoTTY") == 0) {
      opts |= SFTP_PAM_OPT_NO_TTY;

    } else if (strcmp(cmd->argv[i], "NoInfoMsgs") == 0) {
      opts |= SFTP_PAM_OPT_NO_INFO_MSGS;

    } else if (strcmp(cmd->argv[i], "NoRadioMsgs") == 0) {
      opts |= SFTP_PAM_OPT_NO_RADIO_MSGS;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown SFTPPAMOption: '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: SFTPPAMServiceName name */
MODRET set_sftppamservicename(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Event Handlers
 */

static void sftppam_exit_ev(const void *event_data, void *user_data) {

  /* Close the PAM session */

  if (sftppam_pamh != NULL) {
    int res;

#ifdef PAM_CRED_DELETE
    res = pam_setcred(sftppam_pamh, PAM_CRED_DELETE);
#else
    res = pam_setcred(sftppam_pamh, PAM_DELETE_CRED);
#endif
    if (res != PAM_SUCCESS) {
      pr_trace_msg(trace_channel, 9, "PAM error setting PAM_DELETE_CRED: %s",
        pam_strerror(sftppam_pamh, res));
    }

    res = pam_close_session(sftppam_pamh, PAM_SILENT);
    pam_end(sftppam_pamh, res);
    sftppam_pamh = NULL;
  }

  if (sftppam_user != NULL) {
    free(sftppam_user);
    sftppam_user = NULL;
    sftppam_userlen = 0;
  }
}

#if defined(PR_SHARED_MODULE)
static void sftppam_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_sftp_pam.c", (const char *) event_data) == 0) {
    if (sftppam_user) {
      free(sftppam_user);
      sftppam_user = NULL;
      sftppam_userlen = 0;
    }

    sftp_kbdint_unregister_driver("pam");
    pr_event_unregister(&sftp_pam_module, NULL, NULL);
  }
}
#endif /* !PR_SHARED_MODULE */

/* Initialization functions
 */

static int sftppam_init(void) {
#if defined(PR_SHARED_MODULE)
  pr_event_register(&sftp_pam_module, "core.module-unload",
    sftppam_mod_unload_ev, NULL);
#endif /* !PR_SHARED_MODULE */

  /* Prepare our driver. */
  memset(&sftppam_driver, 0, sizeof(sftppam_driver));
  sftppam_driver.open = sftppam_driver_open;
  sftppam_driver.authenticate = sftppam_driver_authenticate;
  sftppam_driver.close = sftppam_driver_close;

  /* Register ourselves with mod_sftp. */
  if (sftp_kbdint_register_driver("pam", &sftppam_driver) < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_NOTICE, MOD_SFTP_PAM_VERSION
      ": notice: error registering 'keyboard-interactive' driver: %s",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

static int sftppam_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "SFTPPAMEngine", FALSE);
  if (c != NULL) {
    int engine;

    engine = *((int *) c->argv[0]);
    if (engine == FALSE) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_PAM_VERSION,
        "disabled by SFTPPAMEngine setting, unregistered 'pam' driver");
      sftp_kbdint_unregister_driver("pam");
      return 0;
    }
  }

  /* To preserve the principle of least surprise, also check for the AuthPAM
   * directive.
   */
  c = find_config(main_server->conf, CONF_PARAM, "AuthPAM", FALSE);
  if (c != NULL) {
    unsigned char auth_pam;

    auth_pam = *((unsigned char *) c->argv[0]);
    if (auth_pam == FALSE) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_PAM_VERSION,
        "disabled by AuthPAM setting, unregistered 'pam' driver");
      sftp_kbdint_unregister_driver("pam");
      return 0;
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "SFTPPAMServiceName", FALSE);
  if (c != NULL) {
    sftppam_service = c->argv[0];
  }

  pr_trace_msg(trace_channel, 8, "using PAM service name '%s'",
    sftppam_service);

  return 0;
}

/* Module API tables
 */

static conftable sftppam_conftab[] = {
  { "SFTPPAMEngine",		set_sftppamengine,		NULL },
  { "SFTPPAMOptions",		set_sftppamoptions,		NULL },
  { "SFTPPAMServiceName",	set_sftppamservicename,		NULL },
  { NULL }
};

static authtable sftppam_authtab[] = {
  { 0, "auth", sftppam_auth },
  { 0, NULL, NULL }
};

module sftp_pam_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "sftp_pam",

  /* Module configuration handler table */
  sftppam_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  sftppam_authtab,

  /* Module initialization function */
  sftppam_init,

  /* Session initialization function */
  sftppam_sess_init,

  /* Module version */
  MOD_SFTP_PAM_VERSION
};
