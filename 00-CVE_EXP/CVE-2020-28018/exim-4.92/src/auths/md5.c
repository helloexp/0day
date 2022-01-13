/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#ifndef STAND_ALONE
#include "../exim.h"

/* For stand-alone testing, we need to have the structure defined, and
to be able to do I/O */

#else
#include <stdio.h>
#include "../mytypes.h"
typedef struct md5 {
  unsigned int length;
  unsigned int abcd[4];
  }
md5;
#endif



/*************************************************
*        Start off a new MD5 computation.        *
*************************************************/

/*
Argument:  pointer to md5 storage structure
Returns:   nothing
*/

void
md5_start(md5 *base)
{
base->abcd[0] = 0x67452301;
base->abcd[1] = 0xefcdab89;
base->abcd[2] = 0x98badcfe;
base->abcd[3] = 0x10325476;
base->length = 0;
}



/*************************************************
*       Process another 64-byte block            *
*************************************************/

/* This function implements central part of the algorithm which is described
in RFC 1321.

Arguments:
  base       pointer to md5 storage structure
  text       pointer to next 64 bytes of subject text

Returns:     nothing
*/

void
md5_mid(md5 *base, const uschar *text)
{
register unsigned int a = base->abcd[0];
register unsigned int b = base->abcd[1];
register unsigned int c = base->abcd[2];
register unsigned int d = base->abcd[3];
int i;
unsigned int X[16];
base->length += 64;

/* Load the 64 bytes into a set of working integers, treating them as 32-bit
numbers in little-endian order. */

for (i = 0; i < 16; i++)
  {
  X[i] = (unsigned int)(text[0]) |
         ((unsigned int)(text[1]) << 8) |
         ((unsigned int)(text[2]) << 16) |
         ((unsigned int)(text[3]) << 24);
  text += 4;
  }

/* For each round of processing there is a function to be applied. We define it
as a macro each time round. */

/***********************************************
*                    Round 1                   *
*            F(X,Y,Z) = XY v not(X) Z          *
* a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s) *
***********************************************/

#define OP(a, b, c, d, k, s, ti) \
     a += ((b & c) | (~b & d)) + X[k] + (unsigned int)ti; \
     a = b + ((a << s) | (a >> (32 - s)))

OP(a, b, c, d,  0,  7, 0xd76aa478);
OP(d, a, b, c,  1, 12, 0xe8c7b756);
OP(c, d, a, b,  2, 17, 0x242070db);
OP(b, c, d, a,  3, 22, 0xc1bdceee);
OP(a, b, c, d,  4,  7, 0xf57c0faf);
OP(d, a, b, c,  5, 12, 0x4787c62a);
OP(c, d, a, b,  6, 17, 0xa8304613);
OP(b, c, d, a,  7, 22, 0xfd469501);
OP(a, b, c, d,  8,  7, 0x698098d8);
OP(d, a, b, c,  9, 12, 0x8b44f7af);
OP(c, d, a, b, 10, 17, 0xffff5bb1);
OP(b, c, d, a, 11, 22, 0x895cd7be);
OP(a, b, c, d, 12,  7, 0x6b901122);
OP(d, a, b, c, 13, 12, 0xfd987193);
OP(c, d, a, b, 14, 17, 0xa679438e);
OP(b, c, d, a, 15, 22, 0x49b40821);

#undef OP

/***********************************************
*                    Round 2                   *
*            F(X,Y,Z) = XZ v Y not(Z)          *
* a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s) *
***********************************************/

#define OP(a, b, c, d, k, s, ti) \
     a += ((b & d) | (c & ~d)) + X[k] + (unsigned int)ti; \
     a = b + ((a << s) | (a >> (32 - s)))

OP(a, b, c, d,  1,  5, 0xf61e2562);
OP(d, a, b, c,  6,  9, 0xc040b340);
OP(c, d, a, b, 11, 14, 0x265e5a51);
OP(b, c, d, a,  0, 20, 0xe9b6c7aa);
OP(a, b, c, d,  5,  5, 0xd62f105d);
OP(d, a, b, c, 10,  9, 0x02441453);
OP(c, d, a, b, 15, 14, 0xd8a1e681);
OP(b, c, d, a,  4, 20, 0xe7d3fbc8);
OP(a, b, c, d,  9,  5, 0x21e1cde6);
OP(d, a, b, c, 14,  9, 0xc33707d6);
OP(c, d, a, b,  3, 14, 0xf4d50d87);
OP(b, c, d, a,  8, 20, 0x455a14ed);
OP(a, b, c, d, 13,  5, 0xa9e3e905);
OP(d, a, b, c,  2,  9, 0xfcefa3f8);
OP(c, d, a, b,  7, 14, 0x676f02d9);
OP(b, c, d, a, 12, 20, 0x8d2a4c8a);

#undef OP

/***********************************************
*                    Round 3                   *
*            F(X,Y,Z) = X xor Y xor Z          *
* a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s) *
***********************************************/

#define OP(a, b, c, d, k, s, ti) \
     a += (b ^ c ^ d) + X[k] + (unsigned int)ti; \
     a = b + ((a << s) | (a >> (32 - s)))

OP(a, b, c, d,  5,  4, 0xfffa3942);
OP(d, a, b, c,  8, 11, 0x8771f681);
OP(c, d, a, b, 11, 16, 0x6d9d6122);
OP(b, c, d, a, 14, 23, 0xfde5380c);
OP(a, b, c, d,  1,  4, 0xa4beea44);
OP(d, a, b, c,  4, 11, 0x4bdecfa9);
OP(c, d, a, b,  7, 16, 0xf6bb4b60);
OP(b, c, d, a, 10, 23, 0xbebfbc70);
OP(a, b, c, d, 13,  4, 0x289b7ec6);
OP(d, a, b, c,  0, 11, 0xeaa127fa);
OP(c, d, a, b,  3, 16, 0xd4ef3085);
OP(b, c, d, a,  6, 23, 0x04881d05);
OP(a, b, c, d,  9,  4, 0xd9d4d039);
OP(d, a, b, c, 12, 11, 0xe6db99e5);
OP(c, d, a, b, 15, 16, 0x1fa27cf8);
OP(b, c, d, a,  2, 23, 0xc4ac5665);

#undef OP

/***********************************************
*                    Round 4                   *
*          F(X,Y,Z) = Y xor (X v not(Z))       *
* a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s) *
***********************************************/

#define OP(a, b, c, d, k, s, ti) \
     a += (c ^ (b | ~d)) + X[k] + (unsigned int)ti; \
     a = b + ((a << s) | (a >> (32 - s)))

OP(a, b, c, d,  0,  6, 0xf4292244);
OP(d, a, b, c,  7, 10, 0x432aff97);
OP(c, d, a, b, 14, 15, 0xab9423a7);
OP(b, c, d, a,  5, 21, 0xfc93a039);
OP(a, b, c, d, 12,  6, 0x655b59c3);
OP(d, a, b, c,  3, 10, 0x8f0ccc92);
OP(c, d, a, b, 10, 15, 0xffeff47d);
OP(b, c, d, a,  1, 21, 0x85845dd1);
OP(a, b, c, d,  8,  6, 0x6fa87e4f);
OP(d, a, b, c, 15, 10, 0xfe2ce6e0);
OP(c, d, a, b,  6, 15, 0xa3014314);
OP(b, c, d, a, 13, 21, 0x4e0811a1);
OP(a, b, c, d,  4,  6, 0xf7537e82);
OP(d, a, b, c, 11, 10, 0xbd3af235);
OP(c, d, a, b,  2, 15, 0x2ad7d2bb);
OP(b, c, d, a,  9, 21, 0xeb86d391);

#undef OP

/* Add the new values back into the accumulators. */

base->abcd[0] += a;
base->abcd[1] += b;
base->abcd[2] += c;
base->abcd[3] += d;
}




/*************************************************
*     Process the final text string              *
*************************************************/

/* The string may be of any length. It is padded out according to the rules
for computing MD5 digests. The final result is then converted to text form
and returned.

Arguments:
  base      pointer to the md5 storage structure
  text      pointer to the final text vector
  length    length of the final text vector
  digest    points to 16 bytes in which to place the result

Returns:    nothing
*/

void
md5_end(md5 *base, const uschar *text, int length, uschar *digest)
{
int i;
uschar work[64];

/* Process in chunks of 64 until we have less than 64 bytes left. */

while (length >= 64)
  {
  md5_mid(base, text);
  text += 64;
  length -= 64;
  }

/* If the remaining string contains more than 55 bytes, we must pad it
out to 64, process it, and then set up the final chunk as 56 bytes of
padding. If it has less than 56 bytes, we pad it out to 56 bytes as the
final chunk. */

memcpy(work, text, length);
work[length] = 0x80;

if (length > 55)
  {
  memset(work+length+1, 0, 63-length);
  md5_mid(base, work);
  base->length -= 64;
  memset(work, 0, 56);
  }
else
  {
  memset(work+length+1, 0, 55-length);
  }

/* The final 8 bytes of the final chunk are a 64-bit representation of the
length of the input string *bits*, before padding, low order word first, and
low order bytes first in each word. This implementation is designed for short
strings, and so operates with a single int counter only. */

length += base->length;   /* Total length in bytes */
length <<= 3;             /* Total length in bits */

work[56] = length         & 0xff;
work[57] = (length >>  8) & 0xff;
work[58] = (length >> 16) & 0xff;
work[59] = (length >> 24) & 0xff;

memset(work+60, 0, 4);

/* Process the final 64-byte chunk */

md5_mid(base, work);

/* Pass back the result, low-order byte first in each word. */

for (i = 0; i < 4; i++)
  {
  register int x = base->abcd[i];
  *digest++ =  x        & 0xff;
  *digest++ = (x >>  8) & 0xff;
  *digest++ = (x >> 16) & 0xff;
  *digest++ = (x >> 24) & 0xff;
  }
}



/*************************************************
**************************************************
*             Stand-alone test program           *
**************************************************
*************************************************/

#if defined STAND_ALONE & !defined CRAM_STAND_ALONE

/* Test values */

static uschar *tests[] = {
  "", "d41d8cd98f00b204e9800998ecf8427e",

  "a", "0cc175b9c0f1b6a831c399e269772661",

  "abc", "900150983cd24fb0d6963f7d28e17f72",

  "message digest", "f96b697d7cb7938d525a2f31aaf161d0",

  "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b",

  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
     "d174ab98d277d9f5a5611c2c9f419d9f",

  "1234567890123456789012345678901234567890123456789012345678901234567890"
  "1234567890",
    "57edf4a22be3c955ac49da2e2107b67a",

  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "a0842fcc02167127b0bb9a7c38e71ba8"
};

int main(void)
{
md5 base;
int i = 0x01020304;
uschar *ctest = US (&i);
uschar buffer[256];
uschar digest[16];
printf("Checking md5: %s-endian\n", (ctest[0] == 0x04)? "little" : "big");

for (i = 0; i < sizeof(tests)/sizeof(uschar *); i += 2)
  {
  int j;
  uschar s[33];
  printf("%s\nShould be: %s\n", tests[i], tests[i+1]);
  md5_start(&base);
  md5_end(&base, tests[i], strlen(tests[i]), digest);
  for (j = 0; j < 16; j++) sprintf(s+2*j, "%02x", digest[j]);
  printf("Computed:  %s\n", s);
  if (strcmp(s, tests[i+1]) != 0) printf("*** No match ***\n");
  printf("\n");
  }
}
#endif

/* End of md5.c */
