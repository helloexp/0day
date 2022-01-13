/*
 * ProFTPD - mod_sftp 'hostbased' user authentication
 * Copyright (c) 2008-2016 TJ Saunders
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
#include "msg.h"
#include "auth.h"
#include "session.h"
#include "keys.h"
#include "keystore.h"
#include "interop.h"
#include "blacklist.h"
#include "utf8.h"

static const char *trace_channel = "ssh2";

int sftp_auth_hostbased(struct ssh2_packet *pkt, cmd_rec *pass_cmd,
    const char *orig_user, const char *user, const char *service,
    unsigned char **buf, uint32_t *buflen, int *send_userauth_fail) {
  struct passwd *pw;
  char *hostkey_algo, *host_fqdn, *host_user, *host_user_utf8;
  const char *fp = NULL, *fp_algo = NULL;
  unsigned char *hostkey_data, *signature_data;
  unsigned char *buf2, *ptr2;
  const unsigned char *id;
  uint32_t buflen2, bufsz2, hostkey_datalen, id_len, signature_len;
  enum sftp_key_type_e pubkey_type;
  int fp_algo_id;

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

  hostkey_algo = sftp_msg_read_string(pkt->pool, buf, buflen);
  if (hostkey_algo == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "missing required host key algorithm, rejecting request");

    *send_userauth_fail = TRUE;
    errno = EINVAL;
    return 0;
  }

  hostkey_datalen = sftp_msg_read_int(pkt->pool, buf, buflen);
  hostkey_data = sftp_msg_read_data(pkt->pool, buf, buflen, hostkey_datalen);

  host_fqdn = sftp_msg_read_string(pkt->pool, buf, buflen);

  host_user_utf8 = sftp_msg_read_string(pkt->pool, buf, buflen);
  host_user = sftp_utf8_decode_str(pkt->pool, host_user_utf8);

  signature_len = sftp_msg_read_int(pkt->pool, buf, buflen);
  signature_data = sftp_msg_read_data(pkt->pool, buf, buflen, signature_len);

  pr_trace_msg(trace_channel, 9,
    "client sent '%s' host key, FQDN %s, and remote user '%s'",
    hostkey_algo, host_fqdn, host_user);

  if (strncmp(hostkey_algo, "ssh-rsa", 8) == 0) {
    pubkey_type = SFTP_KEY_RSA;

  } else if (strncmp(hostkey_algo, "ssh-dss", 8) == 0) {
    pubkey_type = SFTP_KEY_DSA;

#ifdef PR_USE_OPENSSL_ECC
  } else if (strncmp(hostkey_algo, "ecdsa-sha2-nistp256", 20) == 0) {
    pubkey_type = SFTP_KEY_ECDSA_256;

  } else if (strncmp(hostkey_algo, "ecdsa-sha2-nistp256", 20) == 0) {
    pubkey_type = SFTP_KEY_ECDSA_384;

  } else if (strncmp(hostkey_algo, "ecdsa-sha2-nistp256", 20) == 0) {
    pubkey_type = SFTP_KEY_ECDSA_521;
#endif /* PR_USE_OPENSSL_ECC */

  /* XXX Need to support X509v3 certs here */

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unsupported host key algorithm '%s' requested, rejecting request",
      hostkey_algo);

    pr_log_auth(PR_LOG_NOTICE,
      "USER %s (Login failed): unsupported host key algorithm '%s' requested",
      user, hostkey_algo);

    *send_userauth_fail = TRUE;
    errno = EINVAL;
    return 0;
  }

  if (sftp_keys_verify_pubkey_type(pkt->pool, hostkey_data, hostkey_datalen,
      pubkey_type) != TRUE) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unable to verify that given host key matches given '%s' algorithm",
      hostkey_algo);

    *send_userauth_fail = TRUE;
    errno = EINVAL;
    return 0;
  }

#ifdef OPENSSL_FIPS
  if (FIPS_mode()) {
# if defined(HAVE_SHA256_OPENSSL)
    fp_algo_id = SFTP_KEYS_FP_DIGEST_SHA256;
    fp_algo = "SHA256";
# else
    fp_algo_id = SFTP_KEYS_FP_DIGEST_SHA1;
    fp_algo = "SHA1";
# endif /* HAVE_SHA256_OPENSSL */

    fp = sftp_keys_get_fingerprint(pkt->pool, hostkey_data, hostkey_datalen,
      fp_algo_id);
    if (fp != NULL) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "public key %s fingerprint: %s", fp_algo, fp);

    } else {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error obtaining public key %s fingerprint: %s", fp_algo,
        strerror(errno));
    }

  } else {
#endif /* OPENSSL_FIPS */
#if defined(HAVE_SHA256_OPENSSL)
    fp_algo_id = SFTP_KEYS_FP_DIGEST_SHA256;
    fp_algo = "SHA256";
#else
    fp_algo_id = SFTP_KEYS_FP_DIGEST_MD5;
    fp_algo = "MD5";
#endif /* HAVE_SHA256_OPENSSL */

    fp = sftp_keys_get_fingerprint(pkt->pool, hostkey_data, hostkey_datalen,
      fp_algo_id);
    if (fp != NULL) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "public key %s fingerprint: %s", fp_algo, fp);

    } else {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error obtaining public key %s fingerprint: %s", fp_algo,
        strerror(errno));
    }
#ifdef OPENSSL_FIPS
  }
#endif /* OPENSSL_FIPS */

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

  /* XXX Should we check the given FQDN here against the client's actual
   * DNS name and/or IP address?  Or leave that up to the keystore's
   * verify_host_key() function?
   */

  if (sftp_blacklist_reject_key(pkt->pool, hostkey_data, hostkey_datalen)) {
    pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): requested host "
      "key is blacklisted", user);

    *send_userauth_fail = TRUE;
    errno = EACCES;
    return 0;
  }

  /* The client signed the request as well; we need to authenticate the
   * host with the given key now.  If that succeeds, we use the signature to
   * verify the request.  And if that succeeds, then we're done authenticating.
   */

  if (sftp_keystore_verify_host_key(pkt->pool, user, host_fqdn, host_user,
      hostkey_data, hostkey_datalen) < 0) {
    pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): authentication "
      "via '%s' host key failed", user, hostkey_algo);

    *send_userauth_fail = TRUE;
    errno = EACCES;
    return 0;
  }

  /* Make sure the signature matches as well. */

  id_len = sftp_session_get_id(&id);

  /* XXX Is this buffer large enough?  Too large? */
  bufsz2 = buflen2 = 2048;
  ptr2 = buf2 = sftp_msg_getbuf(pkt->pool, bufsz2);

  sftp_msg_write_data(&buf2, &buflen2, id, id_len, TRUE);
  sftp_msg_write_byte(&buf2, &buflen2, SFTP_SSH2_MSG_USER_AUTH_REQUEST);
  sftp_msg_write_string(&buf2, &buflen2, orig_user);

  if (sftp_interop_supports_feature(SFTP_SSH2_FEAT_SERVICE_IN_HOST_SIG)) {
    sftp_msg_write_string(&buf2, &buflen2, service);

  } else {
    sftp_msg_write_string(&buf2, &buflen2, "ssh-userauth");
  }

  sftp_msg_write_string(&buf2, &buflen2, "hostbased");
  sftp_msg_write_string(&buf2, &buflen2, hostkey_algo);
  sftp_msg_write_data(&buf2, &buflen2, hostkey_data, hostkey_datalen, TRUE);
  sftp_msg_write_string(&buf2, &buflen2, host_fqdn);
  sftp_msg_write_string(&buf2, &buflen2, host_user_utf8);

  if (sftp_keys_verify_signed_data(pkt->pool, hostkey_algo, hostkey_data,
      hostkey_datalen, signature_data, signature_len, (unsigned char *) ptr2,
      (bufsz2 - buflen2)) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "failed to verify '%s' signature on hostbased auth request for "
      "user '%s', host %s", hostkey_algo, orig_user, host_fqdn);

    pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): signature "
      "verification of '%s' host key failed", user, hostkey_algo);

    *send_userauth_fail = TRUE;
    errno = EACCES;
    return 0;
  }

  /* Make sure the user is authorized to login.  Normally this is checked
   * as part of the password verification process, but in the case of
   * hostbased authentication, there is no password to verify.
   */

  if (pr_auth_authorize(pkt->pool, user) != PR_AUTH_OK) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "authentication for user '%s' failed: User not authorized", user);
    pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): User not authorized "
      "for login", user);
    *send_userauth_fail = TRUE;
    errno = EACCES;
    return 0;
  }

  return 1;
}

int sftp_auth_hostbased_init(pool *p) {
  return 0;
}
