/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"


/*************************************************
*          Encode byte-string in xtext           *
*************************************************/

/* This function encodes a string of bytes, containing any values whatsoever,
as "xtext", as defined in RFC 1891 and required by the SMTP AUTH extension (RFC
2554).

Arguments:
  clear       points to the clear text bytes
  len         the number of bytes to encode

Returns:      a pointer to the zero-terminated xtext string, which
              is in working store
*/

uschar *
auth_xtextencode(uschar *clear, int len)
{
uschar *code;
uschar *p = US clear;
uschar *pp;
int c = len;
int count = 1;
register int x;

/* We have to do a prepass to find out how many specials there are,
in order to get the right amount of store. */

while (c -- > 0)
  count += ((x = *p++) < 33 || x > 127 || x == '+' || x == '=')? 3 : 1;

pp = code = store_get(count);

p = US clear;
c = len;
while (c-- > 0)
  if ((x = *p++) < 33 || x > 127 || x == '+' || x == '=')
    pp += sprintf(CS pp, "+%.02x", x);   /* There's always room */
  else
    *pp++ = x;

*pp = 0;
return code;
}

/* End of xtextencode.c */
