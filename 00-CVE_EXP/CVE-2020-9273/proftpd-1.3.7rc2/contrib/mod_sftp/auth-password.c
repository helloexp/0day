/*
 * ProFTPD - mod_sftp 'password' user authentication
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
 */

#include "mod_sftp.h"
#include "packet.h"
#include "auth.h"
#include "msg.h"
#include "cipher.h"
#include "mac.h"
#include "utf8.h"

int sftp_auth_password(struct ssh2_packet *pkt, cmd_rec *pass_cmd,
    const char *orig_user, const char *user, const char *service,
    unsigned char **buf, uint32_t *buflen, int *send_userauth_fail) {
  const char *cipher_algo, *mac_algo;
  char *passwd;
  int have_new_passwd, res;
  struct passwd *pw;
  size_t passwd_len;

  cipher_algo = sftp_cipher_get_read_algo();
  mac_algo = sftp_mac_get_read_algo();

  if (strncmp(cipher_algo, "none", 5) == 0 ||
      strncmp(mac_algo, "none", 5) == 0) {

    if (sftp_opts & SFTP_OPT_ALLOW_INSECURE_LOGIN) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "WARNING: cipher algorithm '%s' or MAC algorithm '%s' INSECURE for "
        "password authentication (SFTPOption AllowInsecureLogin in effect)",
        cipher_algo, mac_algo);

    } else {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "cipher algorithm '%s' or MAC algorithm '%s' unacceptable for "
        "password authentication, denying password authentication request",
        cipher_algo, mac_algo);

      pr_log_auth(PR_LOG_NOTICE,
        "USER %s (Login failed): cipher algorithm '%s' or MAC algorithm '%s' "
        "unsupported for password authentication", user,
        cipher_algo, mac_algo);

      *send_userauth_fail = TRUE;
      errno = EPERM;
      return 0;
    }
  }

  /* XXX We currently don't do anything with this. */
  have_new_passwd = sftp_msg_read_bool(pkt->pool, buf, buflen);
  if (have_new_passwd) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION, "%s",
      "client says they have provided a new password; this functionality "
      "is not currently supported");
  }

  passwd = sftp_msg_read_string(pkt->pool, buf, buflen);
  passwd = sftp_utf8_decode_str(pkt->pool, passwd);
  passwd_len = strlen(passwd);

  pass_cmd->arg = passwd;

  if (pr_cmd_dispatch_phase(pass_cmd, PRE_CMD, 0) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "authentication request for user '%s' blocked by '%s' handler",
      orig_user, (char *) pass_cmd->argv[0]);

    pr_log_auth(PR_LOG_NOTICE,
      "USER %s (Login failed): blocked by '%s' handler", orig_user,
      (char *) pass_cmd->argv[0]);

    pr_cmd_dispatch_phase(pass_cmd, POST_CMD_ERR, 0);
    pr_cmd_dispatch_phase(pass_cmd, LOG_CMD_ERR, 0);

    pr_memscrub(passwd, passwd_len);

    *send_userauth_fail = TRUE;
    errno = EPERM;
    return 0;
  }

  pw = pr_auth_getpwnam(pkt->pool, user);
  if (pw == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no account for user '%s' found", user);

    pr_log_auth(PR_LOG_NOTICE,
      "USER %s: no such user found from %s [%s] to %s:%d", user,
      session.c->remote_name, pr_netaddr_get_ipstr(session.c->remote_addr),
      pr_netaddr_get_ipstr(session.c->local_addr), session.c->local_port);

    pr_memscrub(passwd, passwd_len);

    *send_userauth_fail = TRUE;
    errno = ENOENT;
    return 0;
  }

  if (passwd_len == 0) {
    config_rec *c;
    int allow_empty_passwords = TRUE;

    c = find_config(main_server->conf, CONF_PARAM, "AllowEmptyPasswords",
      FALSE);
    if (c != NULL) {
      allow_empty_passwords = *((int *) c->argv[0]);
    }

    if (allow_empty_passwords == FALSE) {
      pr_log_debug(DEBUG5,
        "Refusing empty password from user '%s' (AllowEmptyPasswords false)",
         user);
      pr_log_auth(PR_LOG_NOTICE,
        "Refusing empty password from user '%s'", user);

      pr_event_generate("mod_auth.empty-password", user);
      pr_response_add_err(R_501, "Login incorrect.");

      pr_cmd_dispatch_phase(pass_cmd, POST_CMD_ERR, 0);
      pr_cmd_dispatch_phase(pass_cmd, LOG_CMD_ERR, 0);

      pr_memscrub(passwd, passwd_len);

      *send_userauth_fail = TRUE;
      errno = EPERM;
      return 0;
    }
  }

  res = pr_auth_authenticate(pkt->pool, user, passwd);
  pr_memscrub(passwd, passwd_len);

  switch (res) {
    case PR_AUTH_OK:
      break;

    case PR_AUTH_NOPWD:  
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "password authentication for user '%s' failed: No such user", user);
      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): No such user found",
        user);
      *send_userauth_fail = TRUE;
      errno = ENOENT;
      return 0;

    case PR_AUTH_BADPWD:
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "password authentication for user '%s' failed: Incorrect password",
        user);
      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): Incorrect password",
        user);
      *send_userauth_fail = TRUE;
      errno = EINVAL;
      return 0;

    case PR_AUTH_AGEPWD:
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "password authentication for user '%s' failed: Password expired",
        user);
      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): Password expired",
        user);
      *send_userauth_fail = TRUE;
      errno = EINVAL;
      return 0;

    case PR_AUTH_DISABLEDPWD:
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "password authentication for user '%s' failed: Account disabled",
        user);
      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): Account disabled",
        user);
      *send_userauth_fail = TRUE;
      errno = EINVAL;
      return 0;

    default:
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "unknown authentication value (%d), returning error", res);
      *send_userauth_fail = TRUE;
      errno = EINVAL;
      return 0;
  }

  return 1;
}

int sftp_auth_password_init(pool *p) {
  return 0;
}
