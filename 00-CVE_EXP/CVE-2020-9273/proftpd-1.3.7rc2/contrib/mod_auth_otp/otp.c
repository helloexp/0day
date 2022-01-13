/*
 * ProFTPD - mod_auth_otp
 * Copyright (c) 2015 TJ Saunders
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

#include "otp.h"
#include "crypto.h"

static const char *trace_channel = "auth_otp";

static int otp(pool *p, const EVP_MD *md,
    const unsigned char *key, size_t key_len,
    unsigned long counter, unsigned int *code) {
  register unsigned int i;
  unsigned char hash[EVP_MAX_MD_SIZE], value[8];
  size_t hash_len;
  int offset = 0;
  unsigned int truncated = 0;

  /* RFC 4226 requires a big-endian ordering of the counter value.  While
   * arranging that, encode the counter value into an unsigned char buffer
   * for feeding into the HMAC function.
   */
  for (i = sizeof(value); i--; counter >>= 8) {
    value[i] = counter;
  }

  hash_len = EVP_MAX_MD_SIZE;
  if (auth_otp_hmac(md, key, key_len, value, sizeof(value), hash,
      &hash_len) < 0) {
    return -1;
  }

  pr_memscrub(value, sizeof(value));

  offset = hash[hash_len-1] & 0x0f;

  truncated = ((hash[offset+0] & 0x7f) << 24) |
              ((hash[offset+1] & 0xff) << 16) |
              ((hash[offset+2] & 0xff) << 8) |
               (hash[offset+3] & 0xff);

  pr_memscrub(hash, sizeof(hash));

  truncated &= 0x7fffffff;

  /* Note the 6 zeroes here; this determines the number of digits in the
   * generated code. 
   */
  *code = truncated % 1000000;
  return 0;
}

int auth_otp_hotp(pool *p, const unsigned char *key, size_t key_len,
    unsigned long counter, unsigned int *code) {
  const EVP_MD *md;
  int res;

  if (p == NULL ||
      key == NULL ||
      key_len == 0 ||
      code == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* RFC 4226 (HOTP) uses HMAC-SHA1. */
  md = EVP_sha1();

  res = otp(p, md, key, key_len, counter, code);
  return res;
}

int auth_otp_totp(pool *p, const unsigned char *key, size_t key_len,
    unsigned long ts, unsigned int algo, unsigned int *code) {
  const EVP_MD *md;
  unsigned long counter;
  int res;

  if (p == NULL ||
      key == NULL ||
      key_len == 0 ||
      code == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (algo) {
    case AUTH_OTP_ALGO_TOTP_SHA1:
      md = EVP_sha1();
      break;

#ifdef HAVE_SHA256_OPENSSL
    case AUTH_OTP_ALGO_TOTP_SHA256:
      md = EVP_sha256();
      break;
#endif /* SHA256 OpenSSL support */

#ifdef HAVE_SHA512_OPENSSL
    case AUTH_OTP_ALGO_TOTP_SHA512:
      md = EVP_sha512();
      break;
#endif /* SHA512 OpenSSL support */

    default:
      pr_trace_msg(trace_channel, 4,
        "unsupported TOTP algorithm ID %u requested", algo);
      errno = EINVAL;
      return -1;
  }

  counter = ts / AUTH_OTP_TOTP_TIMESTEP_SECS;
  res = otp(p, md, key, key_len, counter, code);
  return res;
}
