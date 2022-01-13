/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2006-2015 The ProFTPD Project team
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

/* UTF8/charset encoding/decoding. */

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

static unsigned long encoding_policy = 0UL;
static const char *local_charset = NULL;
static const char *encoding = "UTF-8";
static int supports_telnet_iac = TRUE;

static const char *trace_channel = "encode";

static int str_convert(iconv_t conv, const char *inbuf, size_t *inbuflen,
    char *outbuf, size_t *outbuflen) {
# ifdef HAVE_ICONV

  /* Reset the state machine before each conversion. */
  (void) iconv(conv, NULL, NULL, NULL, NULL);

  while (*inbuflen > 0) {
    size_t nconv;

    pr_signals_handle();

    /* Solaris/FreeBSD's iconv(3) takes a const char ** for the input buffer,
     * whereas Linux/Mac OSX iconv(3) use char ** for the input buffer.
     */
#if defined(LINUX) || defined(DARWIN6) || defined(DARWIN7) || \
    defined(DARWIN8) || defined(DARWIN9) || defined(DARWIN10) || \
    defined(DARWIN11) || defined(DARWIN12)

    nconv = iconv(conv, (char **) &inbuf, inbuflen, &outbuf, outbuflen);
#else
    nconv = iconv(conv, &inbuf, inbuflen, &outbuf, outbuflen);
#endif

    if (nconv == (size_t) -1) {

      /* Note: an errno of EILSEQ here can indicate badly encoded strings OR
       * (more likely) that the source character set used in the iconv_open(3)
       * call for this iconv_t descriptor does not accurately describe the
       * character encoding of the given string.  E.g. a filename may use
       * the ISO8859-1 character set, but iconv_open(3) was called using
       * US-ASCII.
       */

      return -1;
    }

    /* XXX We should let the loop condition work, rather than breaking out
     * of the loop here.
     */
    break;
  }

  return 0;
# else
  errno = ENOSYS;
  return -1;
# endif /* HAVE_ICONV */
}
#endif /* !HAVE_ICONV_H */

#ifdef HAVE_ICONV
static void set_supports_telnet_iac(const char *codeset) {

  /* The full list of character sets which use 0xFF could be obtained from
   * the libiconv sources; for now, this list should contain the most
   * commonly used character sets.
   */

  if (strncasecmp(codeset, "CP1251", 7) == 0 ||
      strncasecmp(codeset, "CP866", 6) == 0 ||
      strncasecmp(codeset, "ISO-8859-1", 11) == 0 ||
      strncasecmp(codeset, "KOI8-R", 7) == 0 ||
      strncasecmp(codeset, "WINDOWS-1251", 13) == 0) {
    supports_telnet_iac = FALSE;
    return;
  }

  supports_telnet_iac = TRUE;
}
#endif /* !HAVE_ICONV */

int encode_free(void) {
# ifdef HAVE_ICONV
  int res = 0;

  /* Close the iconv handles. */
  if (encode_conv != (iconv_t) -1) {
    if (iconv_close(encode_conv) < 0) {
      pr_trace_msg(trace_channel, 1,
        "error closing conversion handle from '%s' to '%s': %s",
        local_charset, encoding, strerror(errno));
      res = -1;
    }

    encode_conv = (iconv_t) -1;
  }

  if (decode_conv != (iconv_t) -1) {
    if (iconv_close(decode_conv) < 0) {
      pr_trace_msg(trace_channel, 1,
        "error closing conversion handle from '%s' to '%s': %s",
        encoding, local_charset, strerror(errno));
      res = -1;
    }

    decode_conv = (iconv_t) -1;
  }

  return res;
# else
  errno = ENOSYS;
  return -1;
# endif
}

int encode_init(void) {

  if (encoding == NULL) {
    pr_trace_msg(trace_channel, 3, "no encoding configured");
    return 0;
  }

  if (local_charset == NULL) {
    local_charset = pr_encode_get_local_charset();
  }

  pr_log_debug(DEBUG10, "using '%s' as local charset for %s conversion",
    local_charset, encoding);

# ifdef HAVE_ICONV

  /* If the local charset matches the remote charset, then there's no point
   * in converting; the charsets are the same.  Indeed, on some libiconv
   * implementations, attempting to convert between the same charsets results
   * in a tightly spinning CPU, or worse (see Bug#3272).
   */
  if (strcasecmp(local_charset, encoding) != 0) {

    /* Get the iconv handles. */
    encode_conv = iconv_open(encoding, local_charset);
    if (encode_conv == (iconv_t) -1) {
      int xerrno = errno;

      pr_log_pri(PR_LOG_NOTICE, "error opening conversion handle "
        "from '%s' to '%s': %s", local_charset, encoding, strerror(xerrno));

      errno = xerrno;
      return -1;
    }
 
    decode_conv = iconv_open(local_charset, encoding);
    if (decode_conv == (iconv_t) -1) {
      int xerrno = errno;

      pr_log_pri(PR_LOG_NOTICE, "error opening conversion handle "
        "from '%s' to '%s': %s", encoding, local_charset, strerror(xerrno));

      (void) iconv_close(encode_conv);
      encode_conv = (iconv_t) -1;

      errno = xerrno;
      return -1;
    }
  }

  set_supports_telnet_iac(encoding);
  return 0;
# else
  errno = ENOSYS;
  return -1;
# endif /* HAVE_ICONV */
}

char *pr_decode_str(pool *p, const char *in, size_t inlen, size_t *outlen) {
#ifdef HAVE_ICONV
  size_t inbuflen, outbuflen, outbufsz;
  char *inbuf, outbuf[PR_TUNABLE_PATH_MAX*2], *res = NULL;

  if (p == NULL ||
      in == NULL ||
      outlen == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* If the local charset matches the remote charset, then there's no point
   * in converting; the charsets are the same.  Indeed, on some libiconv
   * implementations, attempting to convert between the same charsets results
   * in a tightly spinning CPU (see Bug#3272).
   */
  if (local_charset != NULL &&
      encoding != NULL &&
      strcasecmp(local_charset, encoding) == 0) {
    return pstrdup(p, in);
  }

  if (decode_conv == (iconv_t) -1) {
    pr_trace_msg(trace_channel, 1, "invalid decoding conversion handle, "
      "unable to decode string");
    return pstrdup(p, in);
  }

  inbuf = pcalloc(p, inlen);
  memcpy(inbuf, in, inlen);
  inbuflen = inlen;

  outbuflen = sizeof(outbuf);

  if (str_convert(decode_conv, inbuf, &inbuflen, outbuf, &outbuflen) < 0) {
    return NULL;
  }

  *outlen = sizeof(outbuf) - outbuflen;

  /* We allocate one byte more, for a terminating NUL. */
  outbufsz = sizeof(outbuf) - outbuflen + 1;
  res = pcalloc(p, outbufsz);

  memcpy(res, outbuf, *outlen);

  return res;
#else
  pr_trace_msg(trace_channel, 1,
    "missing iconv support, no %s decoding possible", encoding);
  return pstrdup(p, in);
#endif /* !HAVE_ICONV */
}

char *pr_encode_str(pool *p, const char *in, size_t inlen, size_t *outlen) {
#ifdef HAVE_ICONV
  size_t inbuflen, outbuflen, outbufsz;
  char *inbuf, outbuf[PR_TUNABLE_PATH_MAX*2], *res;

  if (p == NULL ||
      in == NULL ||
      outlen == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* If the local charset matches the remote charset, then there's no point
   * in converting; the charsets are the same.  Indeed, on some libiconv
   * implementations, attempting to convert between the same charsets results
   * in a tightly spinning CPU (see Bug#3272).
   */
  if (local_charset != NULL &&
      encoding != NULL &&
      strcasecmp(local_charset, encoding) == 0) {
    return pstrdup(p, in);
  }

  if (encode_conv == (iconv_t) -1) {
    pr_trace_msg(trace_channel, 1, "invalid encoding conversion handle, "
      "unable to encode string");
    return pstrdup(p, in);
  }

  inbuf = pcalloc(p, inlen);
  memcpy(inbuf, in, inlen);
  inbuflen = inlen;

  outbuflen = sizeof(outbuf);

  if (str_convert(encode_conv, inbuf, &inbuflen, outbuf, &outbuflen) < 0) {
    return NULL;
  }

  *outlen = sizeof(outbuf) - outbuflen;

  /* We allocate one byte more, for a terminating NUL. */
  outbufsz = sizeof(outbuf) - outbuflen + 1;

  res = pcalloc(p, outbufsz);
  memcpy(res, outbuf, *outlen);

  return res;
#else
  pr_trace_msg(trace_channel, 1,
    "missing iconv support, no %s encoding possible", encoding);
  return pstrdup(p, in);
#endif /* !HAVE_ICONV */
}

void pr_encode_disable_encoding(void) {
#ifdef HAVE_ICONV_H
  pr_trace_msg(trace_channel, 8, "%s encoding disabled", encoding);
  (void) encode_free();
  encoding = NULL;
#endif
}

/* Enables runtime use of encoding using the specified character set (assuming
 * NLS is supported).  Note that "UTF8", "utf8", "utf-8", and "UTF-8" are
 * accepted "character set" designations.
 */
int pr_encode_enable_encoding(const char *codeset) {
#ifdef HAVE_ICONV_H
  int res;

  if (codeset == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (encoding != NULL &&
      strcasecmp(encoding, codeset) == 0) {
    pr_trace_msg(trace_channel, 5, "'%s' encoding already being used", codeset);
    return 0;
  }

  if (encoding) {
    pr_trace_msg(trace_channel, 5,
      "attempting to switch encoding from %s to %s", encoding, codeset);

  } else {
    pr_trace_msg(trace_channel, 5, "attempting to enable %s encoding", codeset);
  }

  (void) encode_free();
  encoding = pstrdup(permanent_pool, codeset);

  res = encode_init();
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "failed to initialize encoding for %s, disabling encoding: %s", codeset,
      strerror(xerrno));

    encoding = NULL;
    errno = xerrno;
  }

  return res;

#else
  errno = ENOSYS;
  return -1;
#endif /* !HAVE_ICONV_H */
}

unsigned long pr_encode_get_policy(void) {
  return encoding_policy;
}

int pr_encode_set_policy(unsigned long policy) {
  encoding_policy = policy;
  return 0;
}

const char *pr_encode_get_local_charset(void) {
  const char *charset = NULL;

#ifdef HAVE_NL_LANGINFO
  /* Look up the current charset.  If there's a problem, default to
   * UCS-2.  Make sure we pick up the locale of the environment.
   */
  charset = nl_langinfo(CODESET);
  if (charset == NULL ||
      strlen(charset) == 0) {
    charset = "UTF-8";
    pr_trace_msg(trace_channel, 1,
      "unable to determine locale, defaulting to 'UTF-8' for %s conversion",
      encoding);

  } else {

    /* Workaround a stupid bug in many implementations where nl_langinfo()
     * returns "646" to mean "US-ASCII".  The problem is that iconv_open(3)
     * doesn't accept "646" as an acceptable encoding.
     */
    if (strncmp(charset, "646", 4) == 0) {
      charset = "US-ASCII";
    }

    pr_trace_msg(trace_channel, 1,
      "converting %s to local character set '%s'", encoding, charset);
    }
#else
  charset = "UTF-8";
  pr_trace_msg(trace_channel, 1,
    "nl_langinfo(3) not supported, defaulting to using 'UTF-8' for "
    "%s conversion", encoding);
#endif /* HAVE_NL_LANGINFO */

  return charset;
}

const char *pr_encode_get_charset(void) {
#ifdef HAVE_ICONV_H
  return local_charset;

#else
  errno = ENOSYS;
  return NULL;
#endif /* !HAVE_ICONV_H */
}

const char *pr_encode_get_encoding(void) {
#ifdef HAVE_ICONV_H
  return encoding;

#else
  errno = ENOSYS;
  return NULL;
#endif /* !HAVE_ICONV_H */
}

int pr_encode_set_charset_encoding(const char *charset, const char *codeset) {
#ifdef HAVE_ICONV_H
  int res;

  if (charset == NULL ||
      codeset == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (local_charset) {
    pr_trace_msg(trace_channel, 5,
      "attempting to switch local charset from %s to %s", local_charset,
      charset);

  } else {
    pr_trace_msg(trace_channel, 5, "attempting to use %s as local charset",
      charset);
  }

  if (encoding) {
    pr_trace_msg(trace_channel, 5,
      "attempting to switch encoding from %s to %s", encoding, codeset);

  } else {
    pr_trace_msg(trace_channel, 5, "attempting to use %s encoding", codeset);
  }

  (void) encode_free();

  local_charset = pstrdup(permanent_pool, charset);
  encoding = pstrdup(permanent_pool, codeset);

  res = encode_init();
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "failed to initialize encoding for local charset %s, encoding %s, "
      "disabling encoding", charset, codeset);
    local_charset = NULL;
    encoding = NULL;

    errno = xerrno;
  }

  return res;

#else
  errno = ENOSYS;
  return -1;
#endif /* !HAVE_ICONV_H */
}

int pr_encode_is_utf8(const char *codeset) {
  if (codeset == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (strncasecmp(codeset, "UTF8", 5) == 0 ||
      strncasecmp(codeset, "UTF-8", 6) == 0) {
    return TRUE;
  }

  return FALSE;
}

int pr_encode_supports_telnet_iac(void) {
  return supports_telnet_iac;
}

#endif /* PR_USE_NLS */
