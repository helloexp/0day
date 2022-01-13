/*
 * ProFTPD - mod_sftp 'publickey' user authentication
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
#include "ssh2.h"
#include "packet.h"
#include "msg.h"
#include "auth.h"
#include "session.h"
#include "keys.h"
#include "keystore.h"
#include "interop.h"
#include "blacklist.h"

/* This array tracks the fingerprints of publickeys that have been
 * successfully verified.  In any given session, the same publickey CANNOT
 * be used twice for authentication; this supports authentication chains
 * like "publickey+publickey", requiring clients to authenticate using multiple
 * different publickeys.
 */
static array_header *publickey_fps = NULL;

static const char *trace_channel = "ssh2";

static int send_pubkey_ok(const char *algo, const unsigned char *pubkey_data,
    uint32_t pubkey_len) {
  struct ssh2_packet *pkt;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;
  int res;

  /* Make sure to allocate a buffer large enough to hold the publickey
   * data we're sending back.
   */
  bufsz = buflen = pubkey_len + 1024;

  pkt = sftp_ssh2_packet_create(sftp_pool);

  buflen = bufsz;
  ptr = buf = palloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_USER_AUTH_PK_OK);
  sftp_msg_write_string(&buf, &buflen, algo);
  sftp_msg_write_data(&buf, &buflen, pubkey_data, pubkey_len, TRUE);

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION, "sending publickey OK");

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    return -1;
  }

  destroy_pool(pkt->pool);
  return 0;
}

int sftp_auth_publickey(struct ssh2_packet *pkt, cmd_rec *pass_cmd,
    const char *orig_user, const char *user, const char *service,
    unsigned char **buf, uint32_t *buflen, int *send_userauth_fail) {
  register unsigned int i;
  int fp_algo_id = 0, have_signature, res;
  enum sftp_key_type_e pubkey_type;
  unsigned char *pubkey_data;
  char *pubkey_algo = NULL;
  const char *fp = NULL, *fp_algo = NULL;
  uint32_t pubkey_len;
  struct passwd *pw;

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

  have_signature = sftp_msg_read_bool(pkt->pool, buf, buflen);

  if (sftp_interop_supports_feature(SFTP_SSH2_FEAT_HAVE_PUBKEY_ALGO)) {
    pubkey_algo = sftp_msg_read_string(pkt->pool, buf, buflen);
  }
  pubkey_len = sftp_msg_read_int(pkt->pool, buf, buflen);
  pubkey_data = sftp_msg_read_data(pkt->pool, buf, buflen, pubkey_len);

  if (pubkey_algo == NULL) {
    /* The client did not send the string identifying the public key algorithm.
     * Thus we need to extract the algorithm string from the public key data.
     */
    pubkey_algo = sftp_msg_read_string(pkt->pool, &pubkey_data, &pubkey_len);
  }

  pr_trace_msg(trace_channel, 9, "client sent '%s' public key %s",
    pubkey_algo, have_signature ? "with signature" : "without signature");

  if (strncmp(pubkey_algo, "ssh-rsa", 8) == 0) {
    pubkey_type = SFTP_KEY_RSA;

  } else if (strncmp(pubkey_algo, "ssh-dss", 8) == 0) {
    pubkey_type = SFTP_KEY_DSA;

#ifdef PR_USE_OPENSSL_ECC
  } else if (strncmp(pubkey_algo, "ecdsa-sha2-nistp256", 20) == 0) {
    pubkey_type = SFTP_KEY_ECDSA_256;

  } else if (strncmp(pubkey_algo, "ecdsa-sha2-nistp384", 20) == 0) {
    pubkey_type = SFTP_KEY_ECDSA_384;

  } else if (strncmp(pubkey_algo, "ecdsa-sha2-nistp521", 20) == 0) {
    pubkey_type = SFTP_KEY_ECDSA_521;
#endif /* PR_USE_OPENSSL_ECC */

  /* XXX This is where we would add support for X509 public keys, e.g.:
   *
   *  x509v3-ssh-dss
   *  x509v3-ssh-rsa
   *  x509v3-sign (older)
   *
   */

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unsupported public key algorithm '%s' requested, rejecting request",
      pubkey_algo);

    pr_log_auth(PR_LOG_NOTICE,
      "USER %s (Login failed): unsupported public key algorithm '%s' requested",
      user, pubkey_algo);

    *send_userauth_fail = TRUE;
    errno = EINVAL;
    return 0;
  }

  res = sftp_keys_verify_pubkey_type(pkt->pool, pubkey_data, pubkey_len,
    pubkey_type);
  if (res != TRUE) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unable to verify that given public key matches given '%s' algorithm",
      pubkey_algo);

    if (res < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error verifying public key algorithm '%s': %s", pubkey_algo,
        strerror(xerrno));
    }

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

    fp = sftp_keys_get_fingerprint(pkt->pool, pubkey_data, pubkey_len,
      fp_algo_id);
    if (fp != NULL) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "public key %s fingerprint: %s", fp_algo, fp);

    } else {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error obtaining public key %s fingerprint: %s", fp_algo,
        strerror(errno));
      fp_algo = NULL;
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

    fp = sftp_keys_get_fingerprint(pkt->pool, pubkey_data, pubkey_len,
      fp_algo_id);
    if (fp != NULL) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "public key %s fingerprint: %s", fp_algo, fp);

    } else {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error obtaining public key %s fingerprint: %s", fp_algo,
        strerror(errno));
      fp_algo = NULL;
    }
#ifdef OPENSSL_FIPS
  }
#endif /* OPENSSL_FIPS */

  if (fp != NULL) {
    const char *k, *v;

    /* Log the fingerprint (and fingerprinting algorithm used), for
     * debugging/auditing; make it available via environment variable as well.
     */

    k = pstrdup(session.pool, "SFTP_USER_PUBLICKEY_ALGO");
    v = pstrdup(session.pool, pubkey_algo);
    pr_env_unset(session.pool, k);
    pr_env_set(session.pool, k, v);

    k = pstrdup(session.pool, "SFTP_USER_PUBLICKEY_FINGERPRINT");
    v = pstrdup(session.pool, fp);
    pr_env_unset(session.pool, k);
    pr_env_set(session.pool, k, v);

    k = pstrdup(session.pool, "SFTP_USER_PUBLICKEY_FINGERPRINT_ALGO");
    v = pstrdup(session.pool, fp_algo);
    pr_env_unset(session.pool, k);
    pr_env_set(session.pool, k, v);
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

  if (!have_signature) {
    /* We don't perform the actual authentication just yet; we need to
     * let the client know that the pubkey algorithms are acceptable.
     */
    if (send_pubkey_ok(pubkey_algo, pubkey_data, pubkey_len) < 0) {
      return -1;
    }

    return 0;

  } else {
    const unsigned char *id;
    unsigned char *buf2, *ptr2, *signature_data;
    uint32_t buflen2, bufsz2, id_len, signature_len;

    /* XXX This should become a more generic "is this key data
     * usable/acceptable?" check (and take the pubkey_type parameter), so that
     * that is where we would check the validity/usability of an X509v3 cert
     * (if a cert), or if the key is on the blacklist (if a key).
     */

    if (sftp_blacklist_reject_key(pkt->pool, pubkey_data, pubkey_len)) {
      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): requested public "
        "key is blacklisted", user);

      *send_userauth_fail = TRUE;
      errno = EPERM;
      return 0;
    }

    signature_len = sftp_msg_read_int(pkt->pool, buf, buflen);
    signature_data = sftp_msg_read_data(pkt->pool, buf, buflen, signature_len);

    /* The client signed the request as well; we need to authenticate the
     * user with the given pubkey now.  If that succeeds, we use the
     * signature to verify the request.  And if that succeeds, then we're
     * done authenticating.
     */

    /* XXX Need to pass the pubkey_type here as well, so that the
     * verification routines can handle different databases of keys/certs.
     * 
     * For X509v3 certs, we will want a way to enforce/restrict which
     * user names can be used with the provided cert.  Perhaps a database
     * mapping cert fingerprints to user names/UIDs?  Configurable callback
     * check (HOOK?), for modules to enforce.
     */

    if (sftp_keystore_verify_user_key(pkt->pool, user, pubkey_data,
        pubkey_len) < 0) {
      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): authentication "
        "via '%s' public key failed", user, pubkey_algo);

      *send_userauth_fail = TRUE;
      errno = EACCES;
      return 0;
    }

    /* Make sure the signature matches as well. */

    id_len = sftp_session_get_id(&id);

    /* Make sure to allocate a buffer large enough to hold the publickey
     * signature and data we want to send back.
     */
    bufsz2 = buflen2 = pubkey_len + 1024;
    ptr2 = buf2 = sftp_msg_getbuf(pkt->pool, bufsz2);

    sftp_msg_write_data(&buf2, &buflen2, id, id_len, TRUE);
    sftp_msg_write_byte(&buf2, &buflen2, SFTP_SSH2_MSG_USER_AUTH_REQUEST);
    sftp_msg_write_string(&buf2, &buflen2, orig_user);

    if (sftp_interop_supports_feature(SFTP_SSH2_FEAT_SERVICE_IN_PUBKEY_SIG)) {
      sftp_msg_write_string(&buf2, &buflen2, service);

    } else {
      sftp_msg_write_string(&buf2, &buflen2, "ssh-userauth");
    }

    if (sftp_interop_supports_feature(SFTP_SSH2_FEAT_HAVE_PUBKEY_ALGO)) {
      sftp_msg_write_string(&buf2, &buflen2, "publickey");
      sftp_msg_write_bool(&buf2, &buflen2, TRUE);
      sftp_msg_write_string(&buf2, &buflen2, pubkey_algo);

    } else {
      sftp_msg_write_bool(&buf2, &buflen2, TRUE);
    }

    sftp_msg_write_data(&buf2, &buflen2, pubkey_data, pubkey_len, TRUE);

    if (sftp_keys_verify_signed_data(pkt->pool, pubkey_algo, pubkey_data,
        pubkey_len, signature_data, signature_len, (unsigned char *) ptr2,
        (bufsz2 - buflen2)) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "failed to verify '%s' signature on public key auth request for "
        "user '%s'", pubkey_algo, orig_user);

      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): signature "
        "verification of '%s' public key failed", user, pubkey_algo);

      *send_userauth_fail = TRUE;
      errno = EACCES;
      return 0;
    }
  }

  /* Make sure the user is authorized to login.  Normally this is checked
   * as part of the password verification process, but in the case of
   * publickey authentication, there is no password to verify.
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

  /* Check the key fingerprint against any previously used keys, to see if the
   * same key is being reused.
   */
  for (i = 0; i < publickey_fps->nelts; i++) {
    char *fpi;

    fpi = ((char **) publickey_fps->elts)[i];
    if (strcmp(fp, fpi) == 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "publickey request reused previously verified publickey "
        "(fingerprint %s), rejecting", fp);

      pr_log_auth(PR_LOG_NOTICE, "USER %s (Login failed): public key request "
       "reused previously verified public key (fingerprint %s)", user, fp);

      *send_userauth_fail = TRUE;
      errno = EACCES;
      return 0;
    }
  }

  /* Store the fingerprint for future checking. */
  *((char **) push_array(publickey_fps)) = pstrdup(sftp_pool, fp);

  return 1;
}

int sftp_auth_publickey_init(pool *p) {
  publickey_fps = make_array(p, 0, sizeof(char *));

  return 0;
}
