/*
 * ProFTPD - mod_sftp 'keyboard-interactive' user authentication
 * Copyright (c) 2008-2015 TJ Saunders
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
#include "ssh2.h"
#include "packet.h"
#include "auth.h"
#include "msg.h"
#include "cipher.h"
#include "mac.h"
#include "utf8.h"
#include "kbdint.h"

/* This array tracks the names of kbdint drivers that have successfully
 * authenticated the user.  In any given session, the same kbdint driver CANNOT
 * be used twice for authentication; this supports authentication chains
 * like "keyboard-interactive+keyboard-interactive", requiring clients to
 * authenticate using multiple different kbdint means.
 */
static array_header *kbdint_drivers = NULL;

static const char *trace_channel = "ssh2";

int sftp_auth_kbdint(struct ssh2_packet *pkt, cmd_rec *pass_cmd,
    const char *orig_user, const char *user, const char *service,
    unsigned char **buf, uint32_t *buflen, int *send_userauth_fail) {
  const char *cipher_algo, *mac_algo;
  struct passwd *pw;
  char *submethods;
  sftp_kbdint_driver_t *driver;
  int res = -1;

  if (sftp_kbdint_have_drivers() == 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no 'keyboard-interactive' drivers currently registered, unable to "
      "authenticate user '%s' via 'keyboard-interactive' method", user);

    pr_log_auth(PR_LOG_NOTICE,
      "USER %s (Login failed): keyboard-interactive authentication disabled",
      user);

    *send_userauth_fail = TRUE;
    errno = EPERM;
    return 0;
  }

  if (pr_cmd_dispatch_phase(pass_cmd, PRE_CMD, 0) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "authentication request for user '%s' blocked by '%s' handler",
      orig_user, (char *) pass_cmd->argv[0]);

    pr_log_auth(PR_LOG_NOTICE,
      "USER %s (Login failed): blocked by '%s' handler", orig_user,
      (char *) pass_cmd->argv[0]);

    pr_cmd_dispatch_phase(pass_cmd, POST_CMD_ERR, 0);
    pr_cmd_dispatch_phase(pass_cmd, LOG_CMD_ERR, 0);

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

    *send_userauth_fail = TRUE;
    errno = ENOENT;
    return 0;
  }

  cipher_algo = sftp_cipher_get_read_algo();
  mac_algo = sftp_mac_get_read_algo();

  /* XXX Is this too strict?  For PAM authentication, no -- but for S/Key or
   * one-time password authencation, maybe yes.
   */
  if (strncmp(cipher_algo, "none", 5) == 0 ||
      strncmp(mac_algo, "none", 5) == 0) {

    if (sftp_opts & SFTP_OPT_ALLOW_INSECURE_LOGIN) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "WARNING: cipher algorithm '%s' or MAC algorithm '%s' INSECURE for "
        "keyboard-interactive authentication "
        "(SFTPOption AllowInsecureLogin in effect)", cipher_algo, mac_algo);

    } else {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "cipher algorithm '%s' or MAC algorithm '%s' unacceptable for "
        "keyboard-interactive authentication, denying authentication request",
        cipher_algo, mac_algo);

      pr_log_auth(PR_LOG_NOTICE,
        "USER %s (Login failed): cipher algorithm '%s' or MAC algorithm '%s' "
        "unsupported for keyboard-interactive authentication", user,
        cipher_algo, mac_algo);

      *send_userauth_fail = TRUE;
      errno = EPERM;
      return 0;
    }
  }

  /* XXX Read off the deprecated language string. */
  sftp_msg_read_string(pkt->pool, buf, buflen);

  submethods = sftp_msg_read_string(pkt->pool, buf, buflen);

  if (strlen(submethods) > 0) {
    pr_trace_msg(trace_channel, 8, "client suggested 'keyboard-interactive' "
      "methods: %s", submethods);
  }

  /* XXX get our own get_shared_name() function (see kex.c), to see if
   * any of the "hints" sent by the client match any of the registered
   * kbdint drivers.
   */

  driver = sftp_kbdint_first_driver();
  while (driver != NULL) {
    register unsigned int i;
    int skip_driver = FALSE;

    pr_signals_handle();

    /* If this driver has already successfully handled this user, skip it. */
    for (i = 0; i < kbdint_drivers->nelts; i++) {
      char *dri;

      dri = ((char **) kbdint_drivers->elts)[i];
      if (strcmp(driver->driver_name, dri) == 0) {
        skip_driver = TRUE;
        break;
      }
    }

    if (skip_driver) {
      pr_trace_msg(trace_channel, 9,
        "skipping already-used kbdint driver '%s' for user '%s'",
        driver->driver_name, user);
      driver = sftp_kbdint_next_driver();
      continue;
    }

    pr_trace_msg(trace_channel, 3, "trying kbdint driver '%s' for user '%s'",
      driver->driver_name, user);

    res = driver->open(driver, user);
    if (res < 0) {
      driver = sftp_kbdint_next_driver();
      continue;
    }

    res = driver->authenticate(driver, user);
    driver->close(driver);

    if (res == 0) {
      /* Store the driver name for future checking. */
      *((char **) push_array(kbdint_drivers)) = pstrdup(sftp_pool,
        driver->driver_name);
      break; 
    }

    driver = sftp_kbdint_next_driver();
  }

  if (res < 0) {
    *send_userauth_fail = TRUE;

    /* We explicitly want to use an errno value other than EPERM here, so
     * that the calling code allows the connecting client to make other
     * login attempts, rather than failing this authentication method
     * after a single failure (Bug#3921).
     */
    errno = EACCES;
    return 0;
  }

  return 1;
}

int sftp_auth_kbdint_init(pool *p) {
  kbdint_drivers = make_array(p, 0, sizeof(char *));

  return 0;
}
