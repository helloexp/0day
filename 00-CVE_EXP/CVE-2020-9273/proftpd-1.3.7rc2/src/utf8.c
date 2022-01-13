/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2006-2016 The ProFTPD Project team
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

/* UTF8 encoding/decoding */

#include "conf.h"

#ifdef PR_USE_NLS

#ifdef HAVE_ICONV_H
# include <iconv.h>
#endif

#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif

#ifdef HAVE_ICONV_H
static iconv_t decode_conv = (iconv_t) -1;
static iconv_t encode_conv = (iconv_t) -1;

static int utf8_convert(iconv_t conv, char *inbuf, size_t *inbuflen,
    char *outbuf, size_t *outbuflen) {
# ifdef HAVE_ICONV
  char *start = inbuf;

  while (inbuflen > 0) {
    size_t nconv = iconv(conv, &inbuf, inbuflen, &outbuf, outbuflen);

    if (nconv == (size_t) -1) {
      if (errno == EINVAL) {
        memmove(start, inbuf, *inbuflen);
        continue;

      } else
        return -1;
    }

    break;
  }
  return 0;
# else
  errno = ENOSYS;
  return -1;
# endif /* HAVE_ICONV */
}
#endif /* !HAVE_ICONV_H */

int utf8_free(void) {
# ifdef HAVE_ICONV
  int res;

  /* Close the iconv handles. */
  res = iconv_close(encode_conv);
  if (res < 0) 
    return -1;

  res = iconv_close(decode_conv);
  if (res < 0)
    return -1;

  return 0;
# else
  errno = ENOSYS;
  return -1;
# endif
}

int utf8_init(void) {
  const char *local_charset;

#ifdef HAVE_NL_LANGINFO
  /* Look up the current charset.  If there's a problem, default to
   * UCS-2.
   */
  local_charset = nl_langinfo(CODESET);
  if (!local_charset) {
    local_charset = "C";
    pr_trace_msg("utf8", 1,
      "unable to determine locale, defaulting to 'C' for UTF8 conversion");

  } else {
    pr_trace_msg("utf8", 1, "converting UTF8 to local character set '%s'",
      local_charset);
  }
#else
  local_charset = "C";
  pr_trace_msg("utf8", 1,
    "nl_langinfo(3) not supported, defaulting to using 'C' for UTF8 "
    "conversion");
#endif /* HAVE_NL_LANGINFO */

# ifdef HAVE_ICONV
  /* Get the iconv handles. */
  encode_conv = iconv_open("UTF-8", local_charset);
  if (encode_conv == (iconv_t) -1)
    return -1;
 
  decode_conv = iconv_open(local_charset, "UTF-8");
  if (decode_conv == (iconv_t) -1)
    return -1;

  return 0;
# else
  errno = ENOSYS;
  return -1;
# endif /* HAVE_ICONV */
}

char *pr_utf8_decode(pool *p, const char *in, size_t inlen, size_t *outlen) {
#ifdef HAVE_ICONV_H
  size_t inbuflen, outbuflen;
  char *inbuf, outbuf[PR_TUNABLE_PATH_MAX*2], *res = NULL;

  if (!p || !in || !outlen) {
    errno = EINVAL;
    return NULL;
  }

  if (decode_conv == (iconv_t) -1) {
    errno = EPERM;
    return NULL;
  }

  inbuf = pcalloc(p, inlen);
  memcpy(inbuf, in, inlen);
  inbuflen = inlen;

  outbuflen = sizeof(outbuf);

  if (utf8_convert(decode_conv, inbuf, &inbuflen, outbuf, &outbuflen) < 0)
    return NULL;

  *outlen = sizeof(outbuf) - outbuflen;
  res = pcalloc(p, *outlen);
  memcpy(res, outbuf, *outlen);

  return res;
#else
  pr_trace_msg("utf8", 1, "missing iconv support, no UTF8 decoding possible");
  return pstrdup(p, in);
#endif /* !HAVE_ICONV_H */
}

char *pr_utf8_encode(pool *p, const char *in, size_t inlen, size_t *outlen) {
#ifdef HAVE_ICONV_H
  size_t inbuflen, outbuflen;
  char *inbuf, outbuf[PR_TUNABLE_PATH_MAX*2], *res;

  if (!p || !in || !outlen) {
    errno = EINVAL;
    return NULL;
  }

  if (encode_conv == (iconv_t) -1) {
    errno = EPERM;
    return NULL;
  }

  inbuf = pcalloc(p, inlen);
  memcpy(inbuf, in, inlen);
  inbuflen = inlen;

  outbuflen = sizeof(outbuf);

  if (utf8_convert(encode_conv, inbuf, &inbuflen, outbuf, &outbuflen) < 0)
    return NULL;

  *outlen = sizeof(outbuf) - outbuflen;
  res = pcalloc(p, *outlen);
  memcpy(res, outbuf, *outlen);

  return res;
#else
  pr_trace_msg("utf8", 1, "missing iconv support, no UTF8 encoding possible");
  return pstrdup(p, in);
#endif /* !HAVE_ICONV_H */
}

#endif /* PR_USE_NLS */
