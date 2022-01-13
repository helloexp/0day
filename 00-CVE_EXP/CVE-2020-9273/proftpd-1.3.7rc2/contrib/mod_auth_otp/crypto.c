/*
 * ProFTPD - mod_auth_otp OpenSSL interface
 * Copyright (c) 2015-2018 TJ Saunders
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

#include "mod_auth_otp.h"
#include "crypto.h"

int auth_otp_crypto_init(void) {
  return 0;
}

void auth_otp_crypto_free(int flags) {
  /* Only call EVP_cleanup() et al if other OpenSSL-using modules are not
   * present.  If we called EVP_cleanup() here during a restart,
   * and other modules want to use OpenSSL, we may be depriving those modules
   * of OpenSSL functionality.
   *
   * At the moment, the modules known to use OpenSSL are mod_ldap,
   * mod_sftp, mod_sql, and mod_sql_passwd, and mod_tls.
   */
  if (pr_module_get("mod_digest.c") == NULL &&
      pr_module_get("mod_ldap.c") == NULL &&
      pr_module_get("mod_proxy.c") == NULL &&
      pr_module_get("mod_radius.c") == NULL &&
      pr_module_get("mod_sftp.c") == NULL &&
      pr_module_get("mod_sql.c") == NULL &&
      pr_module_get("mod_sql_passwd.c") == NULL &&
      pr_module_get("mod_tls.c") == NULL) {

    ERR_free_strings();

#if OPENSSL_VERSION_NUMBER >= 0x10000001L
# if OPENSSL_VERSION_NUMBER >= 0x10100000L
    /* The ERR_remove_state(0) usage is deprecated due to thread ID
     * differences among platforms; see the OpenSSL-1.0.0c CHANGES file
     * for details.  So for new enough OpenSSL installations, use the
     * proper way to clear the error queue state.
     */
    ERR_remove_thread_state(NULL);
# endif /* OpenSSL-1.1.x and later */
#else
    ERR_remove_state(0);
#endif /* OpenSSL prior to 1.0.0-beta1 */

    EVP_cleanup();
    RAND_cleanup();
  }
}

const char *auth_otp_crypto_get_errors(void) {
  unsigned int count = 0;
  unsigned long e = ERR_get_error();
  BIO *bio = NULL;
  char *data = NULL;
  long datalen;
  const char *str = "(unknown)";

  /* Use ERR_print_errors() and a memory BIO to build up a string with
   * all of the error messages from the error queue.
   */

  if (e) {
    bio = BIO_new(BIO_s_mem());
  }

  while (e) {
    pr_signals_handle();
    BIO_printf(bio, "\n  (%u) %s", ++count, ERR_error_string(e, NULL));
    e = ERR_get_error();
  }

  datalen = BIO_get_mem_data(bio, &data);
  if (data) {
    data[datalen] = '\0';
    str = pstrndup(auth_otp_pool, data, datalen-1);
  }

  if (bio) {
    BIO_free(bio);
  }

  return str;
}

int auth_otp_hmac(const EVP_MD *md, const unsigned char *key, size_t key_len,
    const unsigned char *data, size_t data_len, unsigned char *mac,
    size_t *mac_len) {

  if ((key == NULL || key_len == 0) ||
      (data == NULL || data_len == 0) ||
      (mac == NULL || mac_len == NULL)) {
    errno = EINVAL;
    return -1;
  }

  if (HMAC(md, key, key_len, data, data_len, mac,
      (unsigned int *) mac_len) == NULL) {
    (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "HMAC error: %s", auth_otp_crypto_get_errors());
    errno = EPERM;
    return -1;
  }
 
  return 0;
}
