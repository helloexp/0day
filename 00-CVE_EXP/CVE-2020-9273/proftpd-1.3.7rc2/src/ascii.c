/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2015-2018 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* FTP ASCII conversions. */

#include "conf.h"

int pr_ascii_ftp_from_crlf(pool *p, char *in, size_t inlen, char **out,
    size_t *outlen) {
  char *src, *dst;
  size_t rem;
  int adj;

  (void) p;

  if (in == NULL ||
      out == NULL ||
      outlen == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (inlen == 0) {
    *outlen = inlen;
    return 0;
  }

  src = in;
  rem = inlen;
  dst = *out;
  adj = 0;

  while (rem--) {
    if (*src != '\r') {
      *dst++ = *src++;
      (*outlen)++;

    } else {
      if (rem == 0) {
        /* copy, but save it for later */
        adj++;
        *dst++ = *src++;

      } else {
        if (*(src+1) == '\n') {
          /* Skip the CR. */
          src++;

        } else {
          *dst++ = *src++;
          (*outlen)++;
        }
      }
    }
  }

  return adj;
}

static int have_dangling_cr = FALSE;

/* This function rewrites the contents of the given buffer, making sure that
 * each LF has a preceding CR, as required by RFC959.
 */
int pr_ascii_ftp_to_crlf(pool *p, char *in, size_t inlen, char **out,
    size_t *outlen) {
  register unsigned int i = 0, j = 0;
  char *dst = NULL, *src;
  size_t src_len, lf_pos;

  if (p == NULL ||
      in == NULL ||
      out == NULL ||
      outlen == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (inlen == 0) {
    *out = in;
    return 0;
  }

  src = in;
  src_len = lf_pos = inlen;

  /* First, determine the position of the first bare LF. */
  if (have_dangling_cr == FALSE &&
      src[0] == '\n') {
    lf_pos = 0;
    goto found_lf;
  }

  for (i = 1; i < src_len; i++) {
    if (src[i] == '\n' &&
        src[i-1] != '\r') {
      lf_pos = i;
      break;
    }
  }

found_lf:
  /* If the last character in the buffer is CR, then we have a dangling CR.
   * The first character in the next buffer could be an LF, and without
   * this flag, that LF would be treated as a bare LF, thus resulting in
   * an added extraneous CR in the stream.
   */
  have_dangling_cr = (src[src_len-1] == '\r') ? TRUE : FALSE;

  if (lf_pos == src_len) {
    /* No translation needed. */
    *outlen = inlen;

    dst = malloc(inlen);
    if (dst == NULL) {
      pr_log_pri(PR_LOG_ALERT, "Out of memory!");
      exit(1);
    }

    memcpy(dst, in, inlen);
    *out = dst;

    return 0;
  }

  /* Assume the worst: a block containing only LF characters, needing twice
   * the size for holding the corresponding CRs.
   */
  dst = malloc(src_len * 2);
  if (dst == NULL) {
    pr_log_pri(PR_LOG_ALERT, "Out of memory!");
    exit(1);
  }

  if (lf_pos > 0) {
    memcpy(dst, src, lf_pos);
    i = j = lf_pos;

  } else {
    dst[0] = '\r';
    dst[1] = '\n';
    i = 2;
    j = 1;
  }

  while (j < src_len) {
    if (src[j] == '\n' &&
        src[j-1] != '\r') {
      dst[i++] = '\r';
    }

    dst[i++] = src[j++];
  }
  pr_signals_handle();

  *outlen = i;
  *out = dst;

  return i - j;
}

void pr_ascii_ftp_reset(void) {
  have_dangling_cr = FALSE;
}
