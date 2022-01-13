/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"


/*************************************************
*          Decode byte-string in xtext           *
*************************************************/

/* This function decodes a string in xtextformat as defined in RFC 1891 and
required by the SMTP AUTH extension (RFC 2554). We put the result in a piece of
store of equal length - it cannot be longer than this. Although in general the
result of decoding an xtext may be binary, in the context in which it is used
by Exim (for decoding the value of AUTH on a MAIL command), the result is
expected to be an addr-spec. We therefore add on a terminating zero, for
convenience.

Arguments:
  code        points to the coded string, zero-terminated
  ptr         where to put the pointer to the result, which is in
              dynamic store

Returns:      the number of bytes in the result, excluding the final zero;
              -1 if the input is malformed
*/

int
auth_xtextdecode(uschar *code, uschar **ptr)
{
register int x;
uschar *result = store_get(Ustrlen(code) + 1);
*ptr = result;

while ((x = (*code++)) != 0)
  {
  if (x < 33 || x > 127 || x == '=') return -1;
  if (x == '+')
    {
    register int y;
    if (!isxdigit((x = (*code++)))) return -1;
    y = ((isdigit(x))? x - '0' : (tolower(x) - 'a' + 10)) << 4;
    if (!isxdigit((x = (*code++)))) return -1;
    *result++ = y | ((isdigit(x))? x - '0' : (tolower(x) - 'a' + 10));
    }
  else *result++ = x;
  }

*result = 0;
return result - *ptr;
}

/* End of xtextdecode.c */
