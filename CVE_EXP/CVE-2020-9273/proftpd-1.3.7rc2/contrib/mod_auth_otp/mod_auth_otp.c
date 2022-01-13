/*
 * ProFTPD: mod_auth_otp
 * Copyright (c) 2015-2017 TJ Saunders
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
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Archive: mod_auth_otp.a $
 * $Libraries: -lcrypto$
 */

#include "mod_auth_otp.h"
#if defined(HAVE_SFTP)
# include "mod_sftp.h"
#endif /* HAVE_SFTP */
#include "db.h"
#include "otp.h"

/* mod_auth_otp option flags */
#define AUTH_OTP_OPT_STANDARD_RESPONSE		0x001
#define AUTH_OTP_OPT_REQUIRE_TABLE_ENTRY	0x002
#define AUTH_OTP_OPT_DISPLAY_VERIFICATION_CODE	0x004

#define AUTH_OTP_VERIFICATION_CODE_PROMPT	"Verification code: "

/* From src/response.c */
extern pr_response_t *resp_list;

pool *auth_otp_pool = NULL;
int auth_otp_logfd = -1;
unsigned long auth_otp_opts = 0UL;
module auth_otp_module;

static authtable auth_otp_authtab[3];
static int auth_otp_engine = FALSE;
static unsigned int auth_otp_algo = AUTH_OTP_ALGO_TOTP_SHA1;
static struct auth_otp_db *dbh = NULL;
static config_rec *auth_otp_db_config = NULL;
static int auth_otp_auth_code = PR_AUTH_BADPWD;

/* Necessary prototypes */
static int auth_otp_sess_init(void);
static int handle_user_otp(pool *p, const char *user, const char *user_otp,
  int authoritative);

#if defined(HAVE_SFTP)
/* mod_sftp support */
static int auth_otp_using_sftp = FALSE;
static sftp_kbdint_driver_t auth_otp_kbdint_driver;
#endif /* HAVE_SFTP */

static const char *trace_channel = "auth_otp";

#if defined(HAVE_SFTP)
static int auth_otp_kbdint_open(sftp_kbdint_driver_t *driver,
    const char *user) {
  const char *tabinfo;
  int xerrno;

  tabinfo = auth_otp_db_config->argv[0];

  PRIVS_ROOT
  dbh = auth_otp_db_open(driver->driver_pool, tabinfo);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (dbh == NULL) {
    pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "unable to open AuthOTPTable: %s", strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  driver->driver_pool = make_sub_pool(auth_otp_pool);
  pr_pool_tag(driver->driver_pool, "AuthOTP keyboard-interactive driver pool");

  return 0;
}

static int auth_otp_kbdint_authenticate(sftp_kbdint_driver_t *driver,
    const char *user) {
  int authoritative = FALSE, res, xerrno;
  sftp_kbdint_challenge_t *challenge;
  unsigned int recvd_count = 0;
  const char **recvd_responses = NULL, *user_otp = NULL;

  if (auth_otp_authtab[0].auth_flags & PR_AUTH_FL_REQUIRED) {
    authoritative = TRUE;
  }

  /* Check first to see if we even have information for this user, for to
   * use when verifying them.  If not, then don't prompt the user for info
   * that we know, a priori, we cannot verify.
   */
  res = auth_otp_db_rlock(dbh);
  if (res < 0) {
    (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "failed to read-lock AuthOTPTable: %s", strerror(errno));
  }

  res = auth_otp_db_have_user_info(driver->driver_pool, dbh, user);
  xerrno = errno;

  if (auth_otp_db_unlock(dbh) < 0) {
    (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "failed to unlock AuthOTPTable: %s", strerror(errno));
  }

  if (res < 0) {
    (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "no info for user '%s' found in AuthOTPTable, skipping "
      "SSH2 keyboard-interactive challenge", user);
    errno = xerrno;
    return -1;
  }

  challenge = pcalloc(driver->driver_pool, sizeof(sftp_kbdint_challenge_t));
  challenge->challenge = pstrdup(driver->driver_pool,
    AUTH_OTP_VERIFICATION_CODE_PROMPT);
  challenge->display_response = FALSE;

  if (auth_otp_opts & AUTH_OTP_OPT_DISPLAY_VERIFICATION_CODE) {
    challenge->display_response = TRUE;
  }

  if (sftp_kbdint_send_challenge(NULL, NULL, 1, challenge) < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "error sending keyboard-interactive challenges: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (sftp_kbdint_recv_response(driver->driver_pool, 1,
      &recvd_count, &recvd_responses) < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "error receiving keyboard-interactive responses: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  user_otp = recvd_responses[0];
  res = handle_user_otp(driver->driver_pool, user, user_otp, authoritative);
  if (res == 1) {
    return 0;
  }

  errno = EPERM;
  return -1;
}

static int auth_otp_kbdint_close(sftp_kbdint_driver_t *driver) {
  if (dbh != NULL) {
    if (auth_otp_db_close(dbh) < 0) {
      (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
        "error closing AuthOTPTable: %s", strerror(errno));
    }

    dbh = NULL;
  }
  
  if (driver->driver_pool) {
    destroy_pool(driver->driver_pool);
    driver->driver_pool = NULL;
  }

  return 0;
}
#endif /* HAVE_SFTP */

static int check_otp_code(pool *p, const char *user, const char *user_otp,
    const unsigned char *secret, size_t secret_len, unsigned long counter) {
  int res;
  char code_str[9];
  unsigned int code;

  switch (auth_otp_algo) {
    case AUTH_OTP_ALGO_TOTP_SHA1:
    case AUTH_OTP_ALGO_TOTP_SHA256:
    case AUTH_OTP_ALGO_TOTP_SHA512:
      res = auth_otp_totp(p, secret, secret_len, counter, auth_otp_algo, &code);
      if (res < 0) {
        pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
          "error generating TOTP code for user '%s': %s", user,
          strerror(errno));
      }
      break;

    case AUTH_OTP_ALGO_HOTP:
      res = auth_otp_hotp(p, secret, secret_len, counter, &code);
      if (res < 0) {
        pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
          "error generating HOTP code for user '%s': %s", user,
          strerror(errno));
      }
      break;

    default:
      errno = EINVAL;
      res = -1;
      break;
  }

  if (res < 0) {
    return -1;
  }

  memset(code_str, '\0', sizeof(code_str));

  /* Note: If/when more than 6 digits are needed, the following format string
   * would need to change to match.
   */
  pr_snprintf(code_str, sizeof(code_str)-1, "%06u", code);

  pr_trace_msg(trace_channel, 13,
    "computed code '%s', client sent code '%s'", code_str, user_otp);

  res = pr_auth_check(p, code_str, user, user_otp);
  if (res == PR_AUTH_OK ||
      res == PR_AUTH_RFC2228_OK) {
    return 0;
  }
 
  return -1;
}

static int update_otp_counter(pool *p, const char *user,
    unsigned long next_counter) {
  int res = 0;

  if (auth_otp_algo == AUTH_OTP_ALGO_HOTP) {
    int lock;

    lock = auth_otp_db_wlock(dbh);
    if (lock < 0) {
      (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
        "failed to write-lock AuthOTPTable: %s", strerror(errno));
    }

    res = auth_otp_db_update_counter(dbh, user, next_counter);
    if (res < 0) {
      (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
        "error updating AuthOTPTable for HOTP counter for user '%s': %s",
        user, strerror(errno));
    }

    lock = auth_otp_db_unlock(dbh);
    if (lock < 0) {
      (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
        "failed to unlock AuthOTPTable: %s", strerror(errno));
    }
  }

  return res;
}

/* Sets the auth_otp_auth_code variable upon failure. */
static int handle_user_otp(pool *p, const char *user, const char *user_otp,
    int authoritative) {
  int res = 0, xerrno = 0;
  const unsigned char *secret = NULL;
  size_t secret_len = 0;
  unsigned long counter = 0, *counter_ptr = NULL, next_counter = 0;

  if (user_otp == NULL ||
      (strlen(user_otp) == 0)) {
    pr_trace_msg(trace_channel, 1,
      "no OTP code provided by user, rejecting");
    (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "FAILED: user '%s' provided invalid OTP code", user);
    auth_otp_auth_code = PR_AUTH_BADPWD;
    return -1;
  }

  switch (auth_otp_algo) {
    case AUTH_OTP_ALGO_TOTP_SHA1:
    case AUTH_OTP_ALGO_TOTP_SHA256:
    case AUTH_OTP_ALGO_TOTP_SHA512: {
      counter = (unsigned long) time(NULL);
      break;
    }

    case AUTH_OTP_ALGO_HOTP:
      counter_ptr = &counter;
      break;

    default:
      pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
        "unsupported AuthOTPAlgorithm configured");
      return 0;
  }

  res = auth_otp_db_rlock(dbh);
  if (res < 0) {
    (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "failed to read-lock AuthOTPTable: %s", strerror(errno));
  }

  res = auth_otp_db_get_user_info(p, dbh, user, &secret, &secret_len,
    counter_ptr);
  xerrno = errno;

  if (auth_otp_db_unlock(dbh) < 0) {
    (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "failed to unlock AuthOTPTable: %s", strerror(errno));
  }

  if (res < 0) {
    if (xerrno == ENOENT) {
      pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
        "user '%s' has no OTP info in AuthOTPTable", user);

    } else {
      pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
        "unable to retrieve OTP info for user '%s': %s", user,
        strerror(xerrno));
    }

    /* If there was no entry found in the table (errno = ENOENT), should we
     * returned ERROR or DECLINED?
     *
     * If we are not authoritative, then we returned DECLINED, regardless of
     * the errno value, in order to allow other modules a chance at handling
     * the authentication.  This module can only be "authoritative" about
     * OTP codes it can generate, and if there is no entry in the table,
     * REQUIRE_TABLE_ENTRY option or not, we cannot generate a code for
     * comparisons.
     *
     * If we ARE authoritative, and the REQUIRE_TABLE_ENTRY option is in
     * effect, then we return ERROR -- this is how we require OTP codes for
     * ALL users.  Otherwise we return DECLINED, despite being authoritative,
     * because again, we don't have the necessary data for computing the code.
     */

    if (authoritative) {
      if (auth_otp_opts & AUTH_OTP_OPT_REQUIRE_TABLE_ENTRY) {
        (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
          "FAILED: user '%s' does not have entry in OTP tables", user);
        auth_otp_auth_code = PR_AUTH_BADPWD;
        return -1;
      }
    }

    return 0;
  }

  res = check_otp_code(p, user, user_otp, secret, secret_len, counter);
  if (res == 0) {
    pr_memscrub((char *) secret, secret_len);
    
    (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "SUCCESS: user '%s' provided valid OTP code", user);

    /* XXX Update state with details about the expected OTP found,
     * e.g. for clock drift.
     */
    update_otp_counter(p, user, counter + 1);
    return 1;
  }

  /* We SHOULD be allowing for clock skew/counter drift here.  We
   * currently check one window ahead AND behind; is this policy too lenient?
   * RFC 6238, Section 5.2 recommends one window for network transmission
   * delay (which assumes that the client's OTP is always "behind" the
   * server's OTP).
   *
   * By checking one window ahead/behind, we allow for clock skew in either
   * direction: server ahead of client (most likely), client ahead of server.
   */
  pr_trace_msg(trace_channel, 3,
    "current counter check failed, checking one window behind");
 
  switch (auth_otp_algo) {
    case AUTH_OTP_ALGO_TOTP_SHA1:
    case AUTH_OTP_ALGO_TOTP_SHA256:
    case AUTH_OTP_ALGO_TOTP_SHA512:
      next_counter = counter - AUTH_OTP_TOTP_TIMESTEP_SECS;
      break;

    case AUTH_OTP_ALGO_HOTP:
      next_counter = counter - 1;
      break;
  }

  res = check_otp_code(p, user, user_otp, secret, secret_len, next_counter);
  if (res == 0) {
    pr_memscrub((char *) secret, secret_len);

    pr_trace_msg(trace_channel, 3,
      "counter check SUCCEEDED for one counter window behind; client is "
      "out-of-sync");
 
    (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "SUCCESS: user '%s' provided valid OTP code", user);

    /* XXX Update state with details about the expected OTP found,
     * e.g. for clock drift, event counter increment, etc.
     *
     * Note that here, the client is "behind".  Expected for TOTP, but not
     * for HOTP.  Hmm.
     */
    update_otp_counter(p, user, counter + 1);
    return 1;
  }

  pr_trace_msg(trace_channel, 3,
    "counter one window ahead check failed, checking one window ahead");

  switch (auth_otp_algo) {
    case AUTH_OTP_ALGO_TOTP_SHA1:
    case AUTH_OTP_ALGO_TOTP_SHA256:
    case AUTH_OTP_ALGO_TOTP_SHA512:
      next_counter = counter + AUTH_OTP_TOTP_TIMESTEP_SECS;
      break;

    case AUTH_OTP_ALGO_HOTP:
      next_counter = counter + 1;
      break;
  }

  res = check_otp_code(p, user, user_otp, secret, secret_len, next_counter);
  if (res == 0) {
    pr_memscrub((char *) secret, secret_len);

    pr_trace_msg(trace_channel, 3,
      "counter check SUCCEEDED for one counter window ahead; client is "
      "out-of-sync");
 
    (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "SUCCESS: user '%s' provided valid OTP code", user);

    /* XXX Update state with details about the expected OTP found,
     * e.g. for clock drift, event counter increment, etc.
     *
     * Note that here, the client is "ahead".  NOT expected for TOTP, but is
     * for HOTP.  Hmm.
     */
    update_otp_counter(p, user, counter + 1);
    return 1;
  }

  pr_memscrub((char *) secret, secret_len);

  if (authoritative) {
    (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "FAILED: user '%s' provided invalid OTP code", user);
    auth_otp_auth_code = PR_AUTH_BADPWD;
    return -1;
  }

  return 0;
}

/* Authentication handlers
 */

MODRET auth_otp_auth(cmd_rec *cmd) {
  int authoritative = FALSE, res = 0;
  char *user = NULL, *user_otp = NULL;

  if (auth_otp_engine == FALSE ||
      dbh == NULL) {
    return PR_DECLINED(cmd);
  }

  user = cmd->argv[0];
  user_otp = cmd->argv[1];

  /* Figure out our default return style: whether or not we should allow
   * other auth modules a shot at this user or not is controlled by adding
   * '*' to a module name in the AuthOrder directive.  By default, auth
   * modules are not authoritative, and allow other auth modules a chance at
   * authenticating the user.  This is not the most secure configuration, but
   * it allows things like AuthUserFile to work "out of the box".
   */
  if (auth_otp_authtab[0].auth_flags & PR_AUTH_FL_REQUIRED) {
    authoritative = TRUE;
  }

#if defined(HAVE_SFTP)
  if (auth_otp_using_sftp) {
    const char *proto = NULL;

    proto = pr_session_get_protocol(0);
    if (strcmp(proto, "ssh2") == 0) {
      /* We should already have done the keyboard-interactive challenge by
       * this point in the session.
       */

      if (auth_otp_auth_code != PR_AUTH_OK &&
          auth_otp_auth_code != PR_AUTH_RFC2228_OK) {
        if (authoritative) {
          /* Indicate ERROR. */
          res = -1;

        } else {
          /* Indicate DECLINED. */
          res = 0;
        }

      } else {
        /* Indicate HANDLED. */
        res = 1;
      }

    } else {
      res = handle_user_otp(cmd->tmp_pool, user, user_otp, authoritative);
    }

  } else {
    res = handle_user_otp(cmd->tmp_pool, user, user_otp, authoritative);
  }
#else
  res = handle_user_otp(cmd->tmp_pool, user, user_otp, authoritative);
#endif /* HAVE_SFTP */

  if (res == 1) {
    session.auth_mech = "mod_auth_otp.c";
    return PR_HANDLED(cmd);

  } else if (res < 0) {
    return PR_ERROR_INT(cmd, auth_otp_auth_code);
  }

  return PR_DECLINED(cmd);
}

MODRET auth_otp_chkpass(cmd_rec *cmd) {
  const char *real_otp, *user, *user_otp;

  if (auth_otp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  real_otp = cmd->argv[0];
  user = cmd->argv[1];
  user_otp = cmd->argv[2];

  if (strcmp(real_otp, user_otp) == 0) {
    return PR_HANDLED(cmd);
  }

  switch (auth_otp_algo) {
    case AUTH_OTP_ALGO_TOTP_SHA1:
      pr_trace_msg(trace_channel, 9,
        "expected TOTP-SHA1 '%s', got '%s' for user '%s'", real_otp, user_otp,
        user);
      break;

    case AUTH_OTP_ALGO_TOTP_SHA256:
      pr_trace_msg(trace_channel, 9,
        "expected TOTP-SHA256 '%s', got '%s' for user '%s'", real_otp, user_otp,
        user);
      break;

    case AUTH_OTP_ALGO_TOTP_SHA512:
      pr_trace_msg(trace_channel, 9,
        "expected TOTP-SHA512 '%s', got '%s' for user '%s'", real_otp, user_otp,
        user);
      break;

    case AUTH_OTP_ALGO_HOTP:
      pr_trace_msg(trace_channel, 9,
        "expected HOTP '%s', got '%s' for user '%s'", real_otp, user_otp, user);
      break;
  }

  return PR_DECLINED(cmd);
}

/* Configuration handlers
 */

/* usage: AuthOTPAlgorithm algo */
MODRET set_authotpalgo(cmd_rec *cmd) {
  int algo = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "hotp") == 0) {
    algo = AUTH_OTP_ALGO_HOTP;

  } else if (strcasecmp(cmd->argv[1], "totp") == 0 ||
             strcasecmp(cmd->argv[1], "totp-sha1") == 0) {
    algo = AUTH_OTP_ALGO_TOTP_SHA1;

#ifdef HAVE_SHA256_OPENSSL
  } else if (strcasecmp(cmd->argv[1], "totp-sha256") == 0) {
    algo = AUTH_OTP_ALGO_TOTP_SHA256;
#endif /* SHA256 OpenSSL support */

#ifdef HAVE_SHA512_OPENSSL
  } else if (strcasecmp(cmd->argv[1], "totp-sha512") == 0) {
    algo = AUTH_OTP_ALGO_TOTP_SHA512;
#endif /* SHA512 OpenSSL support */

  } else {
    CONF_ERROR(cmd, "expected supported OTP algorithm");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = algo;

  return PR_HANDLED(cmd);
}

/* usage: AuthOTPEngine on|off */
MODRET set_authotpengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c = NULL;

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

/* usage: AuthOTPLog path|"none" */
MODRET set_authotplog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: AuthOTPOptions opt1 opt2 ... */
MODRET set_authotpoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "StandardResponse") == 0) {
      opts |= AUTH_OTP_OPT_STANDARD_RESPONSE;

    } else if (strcmp(cmd->argv[i], "RequireTableEntry") == 0) {
      opts |= AUTH_OTP_OPT_REQUIRE_TABLE_ENTRY;

    } else if (strcmp(cmd->argv[i], "DisplayVerificationCode") == 0) {
      opts |= AUTH_OTP_OPT_DISPLAY_VERIFICATION_CODE;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown AuthOTPOption: '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: AuthOTPTable sql:/... */
MODRET set_authotptable(cmd_rec *cmd) {
  char *ptr = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* Separate the parameter into the separate pieces.  The parameter is
   * given as one string to enhance its similarity to URL syntax.
   */
  ptr = strchr(cmd->argv[1], ':');
  if (ptr == NULL) {
    CONF_ERROR(cmd, "badly formatted parameter");
  }

  if (strncasecmp(cmd->argv[1], "sql:/", 5) != 0) {
    CONF_ERROR(cmd, "badly formatted parameter");
  }

  *ptr++ = '\0';

  add_config_param_str(cmd->argv[0], 1, ptr);
  return PR_HANDLED(cmd);
}

/* usage: AuthOTPTableLock path */
MODRET set_authotptablelock(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET auth_otp_post_pass(cmd_rec *cmd) {
  if (auth_otp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (dbh != NULL) {
    if (auth_otp_db_close(dbh) < 0) {
      (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
        "error closing AuthOTPTable: %s", strerror(errno));
    }

    dbh = NULL;
  }

  return PR_DECLINED(cmd);
}

MODRET auth_otp_pre_user(cmd_rec *cmd) {
  const char *tabinfo;
  int xerrno;

  if (auth_otp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  tabinfo = auth_otp_db_config->argv[0];

  PRIVS_ROOT
  dbh = auth_otp_db_open(auth_otp_pool, tabinfo);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (dbh == NULL) {
    pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "unable to open AuthOTPTable: %s", strerror(xerrno));
  }

  return PR_DECLINED(cmd);
}

MODRET auth_otp_post_user(cmd_rec *cmd) {
  const char *user;

  if (auth_otp_engine == FALSE ||
      dbh == NULL) {
    return PR_DECLINED(cmd);
  }

  user = cmd->argv[1];

  /* We want to respond using the normal 331 response code, BUT we'd like
   * to change the response message.  Note that this might be considered
   * an information leak, i.e. we're leaking the server's expectation of
   * OTPs from the connecting client.
   */

  if (!(auth_otp_opts & AUTH_OTP_OPT_STANDARD_RESPONSE)) {
    pr_response_clear(&resp_list);
#if defined(HAVE_SFTP)
    /* Note: for some reason, when building with mod_sftp, the '_' function
     * used for localization is not resolvable by the linker, thus we
     * work around the problem.  For now.
     */
    pr_response_add(R_331, "One-time password required for %s", user);
#else
    pr_response_add(R_331, _("One-time password required for %s"), user);
#endif /* HAVE_SFTP */
  }

  return PR_DECLINED(cmd);
}

/* Event listeners
 */

static void auth_otp_exit_ev(const void *event_data, void *user_data) {
  if (dbh != NULL) {
    (void) auth_otp_db_close(dbh);
    dbh = NULL;
  }
}

#if defined(PR_SHARED_MODULE)
static void auth_otp_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_auth_otp.c", (const char *) event_data) == 0) {
# if defined(HAVE_SFTP)
    if (pr_module_exists("mod_sftp.c") == TRUE) {
      sftp_kbdint_unregister_driver("auth_otp");
    }
# endif /* HAVE_SFTP */
    pr_event_unregister(&auth_otp_module, NULL, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

static void auth_otp_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer; reinitialize ourselves. */

  pr_event_unregister(&auth_otp_module, "core.exit", auth_otp_exit_ev);
  pr_event_unregister(&auth_otp_module, "core.session-reinit",
    auth_otp_sess_reinit_ev);

  auth_otp_engine = FALSE;
  auth_otp_opts = 0UL;
  auth_otp_algo = AUTH_OTP_ALGO_TOTP_SHA1;
  auth_otp_db_config = NULL;

  if (auth_otp_logfd >= 0) {
    (void) close(auth_otp_logfd);
    auth_otp_logfd = -1;
  }

#if defined(HAVE_SFTP)
  auth_otp_using_sftp = FALSE;
  (void) sftp_kbdint_register_driver("auth_otp", &auth_otp_kbdint_driver);
#endif /* HAVE_SFTP */

  if (auth_otp_pool != NULL) {
    destroy_pool(auth_otp_pool);
  }

  res = auth_otp_sess_init();
  if (res < 0) {
    pr_session_disconnect(&auth_otp_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Initialization routines
 */

static int auth_otp_init(void) {

#if defined(PR_SHARED_MODULE)
  pr_event_register(&auth_otp_module, "core.module-unload",
    auth_otp_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  if (pr_module_exists("mod_sql.c") == FALSE) {
    pr_log_pri(PR_LOG_NOTICE, MOD_AUTH_OTP_VERSION
      ": Missing required 'mod_sql.c'; HOTP/TOTP logins will FAIL");
  }

#if defined(HAVE_SFTP)
  auth_otp_using_sftp = pr_module_exists("mod_sftp.c");
  if (auth_otp_using_sftp) {
    /* Prepare our keyboard-interactive driver. */
    memset(&auth_otp_kbdint_driver, 0, sizeof(auth_otp_kbdint_driver));
    auth_otp_kbdint_driver.open = auth_otp_kbdint_open;
    auth_otp_kbdint_driver.authenticate = auth_otp_kbdint_authenticate;
    auth_otp_kbdint_driver.close = auth_otp_kbdint_close;

    if (sftp_kbdint_register_driver("auth_otp", &auth_otp_kbdint_driver) < 0) {
      int xerrno = errno;

      pr_log_pri(PR_LOG_NOTICE, MOD_AUTH_OTP_VERSION
        ": notice: error registering 'keyboard-interactive' driver: %s",
        strerror(xerrno));

      errno = xerrno;
      return -1;
    }

  } else {
    pr_log_debug(DEBUG1, MOD_AUTH_OTP_VERSION
      ": mod_sftp not loaded, skipping keyboard-interactive support");
  }
#endif /* HAVE_SFTP */

  return 0;
}

static int auth_otp_sess_init(void) {
  config_rec *c;

  pr_event_register(&auth_otp_module, "core.session-reinit",
    auth_otp_sess_reinit_ev, NULL);

  if (pr_auth_add_auth_only_module("mod_auth_otp.c") < 0 &&
      errno != EEXIST) {
    pr_log_pri(PR_LOG_NOTICE, MOD_AUTH_OTP_VERSION
      ": unable to add 'mod_auth_otp.c' as an auth-only module: %s",
      strerror(errno));

    errno = EPERM;
    return -1;
  }

  /* XXX Can we handle both FTP and SSH2 connections in the same module? */

  c = find_config(main_server->conf, CONF_PARAM, "AuthOTPEngine", FALSE);
  if (c != NULL) {
    auth_otp_engine = *((int *) c->argv[0]);
  }

  if (auth_otp_engine == FALSE) {
#if defined(HAVE_SFTP)
    if (auth_otp_using_sftp) {
      sftp_kbdint_unregister_driver("auth_otp");
    }
#endif /* HAVE_SFTP */
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "AuthOTPLog", FALSE);
  if (c != NULL) {
    char *path;

    path = c->argv[0];
    if (strncasecmp(path, "none", 5) != 0) {
      int res, xerrno;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(path, &auth_otp_logfd, 0600); 
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      if (res < 0) {
        if (res == -1) {
          pr_log_pri(PR_LOG_NOTICE, MOD_AUTH_OTP_VERSION
            ": notice: unable to open AuthOTPLog '%s': %s", path,
            strerror(xerrno));

        } else if (res == PR_LOG_WRITABLE_DIR) {
          pr_log_pri(PR_LOG_WARNING, MOD_AUTH_OTP_VERSION
            ": notice: unable to open AuthOTPLog '%s': parent directory is "
            "world-writable", path);

        } else if (res == PR_LOG_SYMLINK) {
          pr_log_pri(PR_LOG_WARNING, MOD_AUTH_OTP_VERSION
            ": notice: unable to open AuthOTPLog '%s': cannot log to a symlink",
            path);
        }
      }
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "AuthOTPTable", FALSE);
  if (c == NULL) {
    pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "missing required AuthOTPTable directive, disabling module");
    pr_log_pri(PR_LOG_NOTICE, MOD_AUTH_OTP_VERSION
      ": missing required AuthOTPTable directive, disabling module");
    auth_otp_engine = FALSE;
    (void) close(auth_otp_logfd);
    auth_otp_logfd = -1;

#if defined(HAVE_SFTP)
    if (auth_otp_using_sftp) {
      sftp_kbdint_unregister_driver("auth_otp");
    }
#endif /* HAVE_SFTP */

    return 0;
  }
  auth_otp_db_config = c;

  auth_otp_pool = make_sub_pool(session.pool);
  pr_pool_tag(auth_otp_pool, MOD_AUTH_OTP_VERSION);

  c = find_config(main_server->conf, CONF_PARAM, "AuthOTPAlgorithm", FALSE);
  if (c != NULL) {
    auth_otp_algo = *((int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "AuthOTPOptions", FALSE);
  while (c != NULL) {
    unsigned long opts = 0;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    auth_otp_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "AuthOTPOptions", FALSE);
  }

  pr_event_register(&auth_otp_module, "core.exit", auth_otp_exit_ev, NULL);
  return 0;
}

static cmdtable auth_otp_cmdtab[] = {
  { PRE_CMD,		C_USER, G_NONE,	auth_otp_pre_user,	FALSE, FALSE },
  { POST_CMD,		C_USER, G_NONE,	auth_otp_post_user,	FALSE, FALSE },
  { POST_CMD,		C_PASS, G_NONE,	auth_otp_post_pass,	FALSE, FALSE },
  { POST_CMD_ERR,	C_PASS, G_NONE,	auth_otp_post_pass,	FALSE, FALSE },
  { 0, NULL },
};

static authtable auth_otp_authtab[] = {
  { 0, "auth",	auth_otp_auth },
  { 0, "check",	auth_otp_chkpass },
  { 0, NULL, NULL }
};

static conftable auth_otp_conftab[] = {
  { "AuthOTPAlgorithm",		set_authotpalgo,		NULL },
  { "AuthOTPEngine",		set_authotpengine,		NULL },
  { "AuthOTPLog",		set_authotplog,			NULL },
  { "AuthOTPOptions",		set_authotpoptions,		NULL },
  { "AuthOTPTable",		set_authotptable,		NULL },
  { "AuthOTPTableLock",		set_authotptablelock,		NULL },
  { NULL, NULL, NULL }
};

module auth_otp_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "auth_otp",

  /* Module configuration handler table */
  auth_otp_conftab,

  /* Module command handler table */
  auth_otp_cmdtab,

  /* Module authentication handler table */
  auth_otp_authtab,

  /* Module initialization */
  auth_otp_init,

  /* Session initialization */
  auth_otp_sess_init,

  /* Module version */
  MOD_AUTH_OTP_VERSION
};
