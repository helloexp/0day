/*
 * ProFTPD - mod_auth_otp base32 implementation
 * Copyright (c) 2015-2016 TJ Saunders
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
#include "base32.h"

/* Note that this base32 implementation does NOT emit the padding characters,
 * as an "optimization".
 *
 * The base32 encoded values are used for interoperability with e.g. Google
 * Authenticator, for entering into the app via human interaction.  To
 * reduce the friction, then, the padding characters are omitted.
 */

static const unsigned char base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int auth_otp_base32_encode(pool *p, const unsigned char *raw,
    size_t raw_len, const unsigned char **encoded, size_t *encoded_len) {
  unsigned char *buf;
  size_t buflen, bufsz;

  if (p == NULL ||
      raw == NULL ||
      encoded == NULL ||
      encoded_len == NULL) {
    errno = EINVAL;
    return -1;
  }

  bufsz = (raw_len * 8) / 5 + 5;
  buf = palloc(p, bufsz);
  buflen = 0;

  if (raw_len > 0) {
    int d, i;
    int bits_rem = 0;

    d = raw[0];
    i = 1;
    bits_rem = 8;

    while ((buflen < bufsz) &&
           (bits_rem > 0 || (size_t) i < raw_len)) {
      int j;

      pr_signals_handle();

      if (bits_rem < 5) {
        if ((size_t) i < raw_len) {
          d <<= 8;
          d |= raw[i++] & 0xff;
          bits_rem += 8;

        } else {
          int padding;

          padding = 5 - bits_rem;
          d <<= padding;
          bits_rem += padding;
        }
      }

      j = 0x1f & (d >> (bits_rem - 5));
      bits_rem -= 5;
      buf[buflen++] = base32[j];
    }
  }

  if (buflen < bufsz) {
    buf[buflen] = '\0';
  }

  *encoded = buf;
  *encoded_len = buflen;
  return 0;
}

int auth_otp_base32_decode(pool *p, const unsigned char *encoded,
    size_t encoded_len, const unsigned char **raw, size_t *raw_len) {
  register const unsigned char *ptr;
  int d;
  unsigned char *buf;
  size_t buflen, bufsz;
  int bits_rem;

  if (p == NULL ||
      encoded == NULL ||
      raw == NULL ||
      raw_len == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (encoded_len == 0) {
    /* We were given an empty string; make sure we allocate at least one
     * character, for the NUL.
     */
    encoded_len = 1;
  }

  bufsz = encoded_len;
  buf = palloc(p, bufsz);
  buflen = 0;

  bits_rem = 0;
  d = 0;

  for (ptr = encoded; buflen < bufsz && *ptr; ++ptr) {
    char c;

    pr_signals_handle();

    c = *ptr;

    /* Per RFC 4648 recommendations, skip linefeeds and other similar
     * characters in decoding.
     */
    if (c == ' ' ||
        c == '\t' ||
        c == '\r' ||
        c == '\n' ||
        c == '-') {
      continue;
    }

    d <<= 5;

    if ((c >= 'A' && c <= 'Z') ||
        (c >= 'a' && c <= 'z')) {
      c = (c & 0x1f) - 1;

    } else if (c >= '2' && c <= '7') {
      c -= ('2' - 26);

    } else {
      /* Invalid character. */
      errno = EPERM;
      return -1;
    }

    d |= c;
    bits_rem += 5;
    if (bits_rem >= 8) {
      buf[buflen++] = (d >> (bits_rem - 8));
      bits_rem -= 8;
    }
  }

  if (buflen < bufsz) {
    buf[buflen] = '\0';
  }

  *raw = buf;
  *raw_len = buflen;
  return 0;
}
