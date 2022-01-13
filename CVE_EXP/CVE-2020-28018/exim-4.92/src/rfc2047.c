/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* This file contains a function for decoding message header lines that may
contain encoded "words" according to the rules described in

  RFC-2047 at http://www.ietf.org/rfc/rfc2047.txt

The function is a rewritten version of code created by Norihisa Washitake.
The original could be used both inside Exim (as part of a patch) or in a
freestanding form. The original contained some built-in code conversions; I
have chosen only to do code conversions if iconv() is supported by the OS.
Because there were quite a lot of hacks to be done, for a variety of reasons,
I rewrote the code.

You can find the latest version of the original library at

  http://washitake.com/mail/exim/mime/

The code below is almost completely unlike the original. */


#include "exim.h"


/*************************************************
*                Do a QP conversion              *
*************************************************/

/* This function decodes "quoted printable" into bytes.

Arguments:
  string      the string that includes QP escapes
  ptrptr      where to return pointer to the decoded string

Returns:      the length of the decoded string, or -1 on failure
*/

static int
rfc2047_qpdecode(uschar *string, uschar **ptrptr)
{
int len = 0;
uschar *ptr;

ptr = *ptrptr = store_get(Ustrlen(string) + 1);  /* No longer than this */

while (*string != 0)
  {
  int ch = *string++;

  if (ch == '_') *ptr++ = ' ';
  else if (ch == '=')
    {
    int a = *string;
    int b = (a == 0)? 0 : string[1];
    if (!isxdigit(a) || !isxdigit(b)) return -1;  /* Bad QP string */
    *ptr++ = ((Ustrchr(hex_digits, tolower(a)) - hex_digits) << 4) +
               Ustrchr(hex_digits, tolower(b)) - hex_digits;
    string += 2;
    }
  else if (ch == ' ' || ch == '\t') return -1;    /* Whitespace is illegal */
  else *ptr++ = ch;

  len++;
  }

*ptr = 0;
return len;
}



/*************************************************
*            Decode next MIME word               *
*************************************************/

/* Scan a string to see if a MIME word exists; pass back the separator
points in the string.

Arguments:
  string     subject string
  lencheck   TRUE to enforce maximum length check
  q1ptr      pass back address of first question mark
  q2ptr      pass back address of second question mark
  endptr     pass back address of final ?=
  dlenptr    pass back length of decoded string
  dptrptr    pass back pointer to decoded string

Returns:     address of =? or NULL if not present
*/

static uschar *
decode_mimeword(uschar *string, BOOL lencheck, uschar **q1ptr, uschar **q2ptr,
  uschar **endptr, size_t *dlenptr, uschar **dptrptr)
{
uschar *mimeword;
for (;; string = mimeword + 2)
  {
  int encoding;
  int dlen = -1;

  if ((mimeword = Ustrstr(string, "=?"))  == NULL ||
      (*q1ptr = Ustrchr(mimeword+2, '?')) == NULL ||
      (*q2ptr = Ustrchr(*q1ptr+1, '?')) == NULL ||
      (*endptr = Ustrstr(*q2ptr+1, "?=")) == NULL) return NULL;

  /* We have found =?xxx?xxx?xxx?= in the string. Optionally check the
  length, and that the second field is just one character long. If not,
  continue the loop to search again. We must start just after the initial =?
  because we might have found =?xxx=?xxx?xxx?xxx?=. */

  if ((lencheck && *endptr - mimeword > 73) || *q2ptr - *q1ptr != 2) continue;

  /* Get the encoding letter, and decode the data string. */

  encoding = toupper((*q1ptr)[1]);
  **endptr = 0;
  if (encoding == 'B')
    dlen = b64decode(*q2ptr+1, dptrptr);
  else if (encoding == 'Q')
    dlen = rfc2047_qpdecode(*q2ptr+1, dptrptr);
  **endptr = '?';   /* restore */

  /* If the decoding succeeded, we are done. Set the length of the decoded
  string, and pass back the initial pointer. Otherwise, the loop continues. */

  if (dlen >= 0)
    {
    *dlenptr = (size_t)dlen;
    return mimeword;
    }
  }

/* Control should never actually get here */
}



/*************************************************
*    Decode and convert an RFC 2047 string       *
*************************************************/

/* There are two functions defined here. The original one was rfc2047_decode()
and it was documented in the local_scan() interface. I needed to add an extra
argument for use by expand_string(), so I created rfc2047_decode2() for that
purpose. The original function became a stub that just supplies NULL for the
new argument (sizeptr).

An RFC 2047-encoded string may contain one or more "words", each of the
form  =?...?.?...?=  with the first ... specifying the character code, the
second being Q (for quoted printable) or B for Base64 encoding. The third ...
is the actual data.

This function first decodes each "word" into bytes from the Q or B encoding.
Then, if provided with the name of a charset encoding, and if iconv() is
available, it attempts to translate the result to the named character set.
If this fails, the binary string is returned with an error message.

If a binary zero is encountered in the decoded string, it is replaced by the
contents of the zeroval argument. For use with Exim headers, the value must not
be 0 because they are handled as zero-terminated strings. When zeroval==0,
lenptr should not be NULL.

Arguments:
    string       the subject string
    lencheck     TRUE to enforce maximum MIME word length
    target       the name of the target encoding for MIME words, or NULL for
                   no charset translation
    zeroval      the value to use for binary zero bytes
    lenptr       if not NULL, the length of the result is returned via
                   this variable
    sizeptr      if not NULL, the length of a new store block in which the
                   result is built is placed here; if no new store is obtained,
                   the value is not changed
    error        for error messages; NULL if no problem; this can be set
                   when the yield is non-NULL if there was a charset
                   translation problem

Returns:         the decoded, converted string, or NULL on error; if there are
                   no MIME words in the string, the original string is returned
*/

uschar *
rfc2047_decode2(uschar *string, BOOL lencheck, uschar *target, int zeroval,
  int *lenptr, int *sizeptr, uschar **error)
{
int size = Ustrlen(string);
size_t dlen;
uschar *dptr;
gstring *yield;
uschar *mimeword, *q1, *q2, *endword;

*error = NULL;
mimeword = decode_mimeword(string, lencheck, &q1, &q2, &endword, &dlen, &dptr);

if (!mimeword)
  {
  if (lenptr) *lenptr = size;
  return string;
  }

/* Scan through the string, decoding MIME words and copying intermediate text,
building the result as we go. The result may be longer than the input if it is
translated into a multibyte code such as UTF-8. That's why we use the dynamic
string building code. */

yield = store_get(sizeof(gstring) + ++size);
yield->size = size;
yield->ptr = 0;
yield->s = US(yield + 1);

while (mimeword)
  {

  #if HAVE_ICONV
  iconv_t icd = (iconv_t)(-1);
  #endif

  if (mimeword != string)
    yield = string_catn(yield, string, mimeword - string);

  /* Do a charset translation if required. This is supported only on hosts
  that have the iconv() function. Translation errors set error, but carry on,
  using the untranslated data. If there is more than one error, the message
  passed back refers to the final one. We use a loop to cater for the case
  of long strings - the RFC puts limits on the length, but it's best to be
  robust. */

  #if HAVE_ICONV
  *q1 = 0;
  if (target != NULL && strcmpic(target, mimeword+2) != 0)
    {
    icd = iconv_open(CS target, CS(mimeword+2));

    if (icd == (iconv_t)(-1))
      {
      *error = string_sprintf("iconv_open(\"%s\", \"%s\") failed: %s%s",
        target, mimeword+2, strerror(errno),
        (errno == EINVAL)? " (maybe unsupported conversion)" : "");
      }
    }
  *q1 = '?';
  #endif

  while (dlen > 0)
    {
    uschar *tptr = NULL;   /* Stops compiler warning */
    int tlen = -1;

    #if HAVE_ICONV
    uschar tbuffer[256];
    uschar *outptr = tbuffer;
    size_t outleft = sizeof(tbuffer);

    /* If translation is required, go for it. */

    if (icd != (iconv_t)(-1))
      {
      (void)iconv(icd, (ICONV_ARG2_TYPE)(&dptr), &dlen, CSS &outptr, &outleft);

      /* If outptr has been adjusted, there is some output. Set up to add it to
      the output buffer. The function will have adjusted dptr and dlen. If
      iconv() stopped because of an error, we'll pick it up next time when
      there's no output.

      If there is no output, we expect there to have been a translation
      error, because we know there was at least one input byte. We leave the
      value of tlen as -1, which causes the rest of the input to be copied
      verbatim. */

      if (outptr > tbuffer)
        {
        tptr = tbuffer;
        tlen = outptr - tbuffer;
        }
      else
        {
        DEBUG(D_any) debug_printf("iconv error translating \"%.*s\" to %s: "
        "%s\n", (int)(endword + 2 - mimeword), mimeword, target, strerror(errno));
        }
      }

    #endif

    /* No charset translation is happening or there was a translation error;
    just set up the original as the string to be added, and mark it all used.
    */

    if (tlen == -1)
      {
      tptr = dptr;
      tlen = dlen;
      dlen = 0;
      }

    /* Deal with zero values; convert them if requested. */

    if (zeroval != 0)
      {
      int i;
      for (i = 0; i < tlen; i++)
        if (tptr[i] == 0) tptr[i] = zeroval;
      }

    /* Add the new string onto the result */

    yield = string_catn(yield, tptr, tlen);
    }

  #if HAVE_ICONV
  if (icd != (iconv_t)(-1))  iconv_close(icd);
  #endif

  /* Update string past the MIME word; skip any white space if the next thing
  is another MIME word. */

  string = endword + 2;
  mimeword = decode_mimeword(string, lencheck, &q1, &q2, &endword, &dlen, &dptr);
  if (mimeword)
    {
    uschar *s = string;
    while (isspace(*s)) s++;
    if (s == mimeword) string = s;
    }
  }

/* Copy the remaining characters of the string, zero-terminate it, and return
the length as well if requested. */

yield = string_cat(yield, string);

if (lenptr) *lenptr = yield->ptr;
if (sizeptr) *sizeptr = yield->size;
return string_from_gstring(yield);
}


/* This is the stub that provides the original interface without the sizeptr
argument. */

uschar *
rfc2047_decode(uschar *string, BOOL lencheck, uschar *target, int zeroval,
  int *lenptr, uschar **error)
{
return rfc2047_decode2(string, lencheck, target, zeroval, lenptr, NULL, error);
}

/* End of rfc2047.c */
