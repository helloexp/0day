/*
 * ProFTPD - mod_sftp key mgmt (keys)
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

#ifndef MOD_SFTP_KEYS_H
#define MOD_SFTP_KEYS_H

#include "mod_sftp.h"

enum sftp_key_type_e {
  SFTP_KEY_UNKNOWN = 0,
  SFTP_KEY_DSA,
  SFTP_KEY_RSA,
  SFTP_KEY_ECDSA_256,
  SFTP_KEY_ECDSA_384,
  SFTP_KEY_ECDSA_521
};

/* Returns a string of colon-separated lowercase hex characters, representing
 * the key "fingerprint" which has been run through the specified digest
 * algorithm.
 *
 * As per draft-ietf-secsh-fingerprint-00, only MD5 fingerprints are currently
 * supported.
 */
const char *sftp_keys_get_fingerprint(pool *, unsigned char *, uint32_t, int);
#define SFTP_KEYS_FP_DIGEST_MD5		1
#define SFTP_KEYS_FP_DIGEST_SHA1	2
#define SFTP_KEYS_FP_DIGEST_SHA256	3

void sftp_keys_free(void);
int sftp_keys_get_hostkey(pool *p, const char *);
const unsigned char *sftp_keys_get_hostkey_data(pool *, enum sftp_key_type_e,
  uint32_t *);
void sftp_keys_get_passphrases(void);
int sftp_keys_set_passphrase_provider(const char *);
const unsigned char *sftp_keys_sign_data(pool *, enum sftp_key_type_e,
  const unsigned char *, size_t, size_t *);
#ifdef PR_USE_OPENSSL_ECC
int sftp_keys_validate_ecdsa_params(const EC_GROUP *, const EC_POINT *);
#endif /* PR_USE_OPENSSL_ECC */
int sftp_keys_verify_pubkey_type(pool *, unsigned char *, uint32_t,
  enum sftp_key_type_e);
int sftp_keys_verify_signed_data(pool *, const char *,
  unsigned char *, uint32_t, unsigned char *, uint32_t,
  unsigned char *, size_t);

/* Sets minimum key sizes. */
int sftp_keys_set_key_limits(int rsa_min, int dsa_min, int ec_min);

int sftp_keys_clear_dsa_hostkey(void);
int sftp_keys_clear_ecdsa_hostkey(void);
int sftp_keys_clear_rsa_hostkey(void);
int sftp_keys_have_dsa_hostkey(void);
int sftp_keys_have_ecdsa_hostkey(pool *, int **);
int sftp_keys_have_rsa_hostkey(void);

#endif /* MOD_SFTP_KEYS_H */
