/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/*
 * This file provides the necessary methods for authenticating with
 * Microsoft's Secure Password Authentication.

 * All the original code used here was torn by Marc Prud'hommeaux out of the
 * Samba project (by Andrew Tridgell, Jeremy Allison, and others).

 * Tom Kistner provided additional code, adding spa_build_auth_challenge() to
 * support server authentication mode.

 * Mark Lyda provided a patch to solve this problem:

 - Exim is indicating in its Authentication Request message (Type 1) that it
   can transmit text in either Unicode or OEM format.

 - Microsoft's SMTP server (smtp.email.msn.com) is responding in its
   Challenge message (Type 2) that it will be expecting the OEM format.

 - Exim does not pay attention to the text format requested by Microsoft's
   SMTP server and, instead, defaults to using the Unicode format.

 * References:
 * http://www.innovation.ch/java/ntlm.html
 * http://www.kuro5hin.org/story/2002/4/28/1436/66154

 * It seems that some systems have existing but different definitions of some
 * of the following types. I received a complaint about "int16" causing
 * compilation problems. So I (PH) have renamed them all, to be on the safe
 * side, by adding 'x' on the end.

 * typedef signed short int16;
 * typedef unsigned short uint16;
 * typedef unsigned uint32;
 * typedef unsigned char  uint8;

 * The API is extremely simple:
 * 1. Form a SPA authentication request based on the username
 *    and (optional) domain
 * 2. Send the request to the server and get an SPA challenge
 * 3. Build the challenge response and send it back.
 *
 * Example usage is as
 * follows:
 *
int main (int argc, char ** argv)
{
       SPAAuthRequest   request;
       SPAAuthChallenge challenge;
       SPAAuthResponse  response;
       char msgbuf[2048];
       char buffer[512];
       char *username, *password, *domain, *challenge_str;

       if (argc < 3)
       {
               printf ("Usage: %s <username> <password> [SPA Challenge]\n",
                       argv [0]);
               exit (1);
       }

       username = argv [1];
       password = argv [2];
       domain = 0;

       spa_build_auth_request (&request, username, domain);

       spa_bits_to_base64 (msgbuf, US &request,
               spa_request_length(&request));

       printf ("SPA Login request for username=%s:\n   %s\n",
               argv [1], msgbuf);

       if (argc < 4)
       {
               printf ("Run: %s <username> <password> [NTLM Challenge] " \
                       "to complete authenitcation\n", argv [0]);
               exit (0);
       }

       challenge_str = argv [3];

       if (spa_base64_to_bits (CS &challenge, sizeof(challenge),
                CCS (challenge_str))<0)
       {
                printf("bad base64 data in challenge: %s\n", challenge_str);
                exit (1);
       }

       spa_build_auth_response (&challenge, &response, username, password);
       spa_bits_to_base64 (msgbuf, US &response,
               spa_request_length(&response));

       printf ("SPA Response to challenge:\n   %s\n for " \
               "username=%s, password=%s:\n   %s\n",
               argv[3], argv [1], argv [2], msgbuf);
       return 0;
}
 *
 *
 * All the client code used here was torn by Marc Prud'hommeaux out of the
 * Samba project (by Andrew Tridgell, Jeremy Allison, and others).
 * Previous comments are below:
 */

/*
   Unix SMB/Netbios implementation.
   Version 1.9.

   a partial implementation of DES designed for use in the
   SMB authentication protocol

   Copyright (C) Andrew Tridgell 1998

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/


/* NOTES:

   This code makes no attempt to be fast! In fact, it is a very
   slow implementation

   This code is NOT a complete DES implementation. It implements only
   the minimum necessary for SMB authentication, as used by all SMB
   products (including every copy of Microsoft Windows95 ever sold)

   In particular, it can only do a unchained forward DES pass. This
   means it is not possible to use this code for encryption/decryption
   of data, instead it is only useful as a "hash" algorithm.

   There is no entry point into this code that allows normal DES operation.

   I believe this means that this code does not come under ITAR
   regulations but this is NOT a legal opinion. If you are concerned
   about the applicability of ITAR regulations to this code then you
   should confirm it for yourself (and maybe let me know if you come
   up with a different answer to the one above)
*/

#define DEBUG_X(a,b) ;

extern int DEBUGLEVEL;

#include "../exim.h"
#include "auth-spa.h"
#include <assert.h>


#ifndef _BYTEORDER_H
# define _BYTEORDER_H

# define RW_PCVAL(read,inbuf,outbuf,len) \
       { if (read) { PCVAL (inbuf,0,outbuf,len); } \
       else      { PSCVAL(inbuf,0,outbuf,len); } }

# define RW_PIVAL(read,big_endian,inbuf,outbuf,len) \
       { if (read) { if (big_endian) { RPIVAL(inbuf,0,outbuf,len); } else { PIVAL(inbuf,0,outbuf,len); } } \
       else      { if (big_endian) { RPSIVAL(inbuf,0,outbuf,len); } else { PSIVAL(inbuf,0,outbuf,len); } } }

# define RW_PSVAL(read,big_endian,inbuf,outbuf,len) \
       { if (read) { if (big_endian) { RPSVAL(inbuf,0,outbuf,len); } else { PSVAL(inbuf,0,outbuf,len); } } \
       else      { if (big_endian) { RPSSVAL(inbuf,0,outbuf,len); } else { PSSVAL(inbuf,0,outbuf,len); } } }

# define RW_CVAL(read, inbuf, outbuf, offset) \
       { if (read) { (outbuf) = CVAL (inbuf,offset); } \
       else      { SCVAL(inbuf,offset,outbuf); } }

# define RW_IVAL(read, big_endian, inbuf, outbuf, offset) \
       { if (read) { (outbuf) = ((big_endian) ? RIVAL(inbuf,offset) : IVAL (inbuf,offset)); } \
       else      { if (big_endian) { RSIVAL(inbuf,offset,outbuf); } else { SIVAL(inbuf,offset,outbuf); } } }

# define RW_SVAL(read, big_endian, inbuf, outbuf, offset) \
       { if (read) { (outbuf) = ((big_endian) ? RSVAL(inbuf,offset) : SVAL (inbuf,offset)); } \
       else      { if (big_endian) { RSSVAL(inbuf,offset,outbuf); } else { SSVAL(inbuf,offset,outbuf); } } }

# undef CAREFUL_ALIGNMENT

/* we know that the 386 can handle misalignment and has the "right"
   byteorder */
# ifdef __i386__
#  define CAREFUL_ALIGNMENT 0
# endif

# ifndef CAREFUL_ALIGNMENT
#  define CAREFUL_ALIGNMENT 1
# endif

# define CVAL(buf,pos) ((US (buf))[pos])
# define PVAL(buf,pos) ((unsigned)CVAL(buf,pos))
# define SCVAL(buf,pos,val) (CVAL(buf,pos) = (val))


# if CAREFUL_ALIGNMENT

#  define SVAL(buf,pos) (PVAL(buf,pos)|PVAL(buf,(pos)+1)<<8)
#  define IVAL(buf,pos) (SVAL(buf,pos)|SVAL(buf,(pos)+2)<<16)
#  define SSVALX(buf,pos,val) (CVAL(buf,pos)=(val)&0xFF,CVAL(buf,pos+1)=(val)>>8)
#  define SIVALX(buf,pos,val) (SSVALX(buf,pos,val&0xFFFF),SSVALX(buf,pos+2,val>>16))
#  define SVALS(buf,pos) ((int16x)SVAL(buf,pos))
#  define IVALS(buf,pos) ((int32x)IVAL(buf,pos))
#  define SSVAL(buf,pos,val) SSVALX((buf),(pos),((uint16x)(val)))
#  define SIVAL(buf,pos,val) SIVALX((buf),(pos),((uint32x)(val)))
#  define SSVALS(buf,pos,val) SSVALX((buf),(pos),((int16x)(val)))
#  define SIVALS(buf,pos,val) SIVALX((buf),(pos),((int32x)(val)))

# else /* CAREFUL_ALIGNMENT */

/* this handles things for architectures like the 386 that can handle
   alignment errors */
/*
   WARNING: This section is dependent on the length of int16x and int32x
   being correct
*/

/* get single value from an SMB buffer */
#  define SVAL(buf,pos) (*(uint16x *)(CS (buf) + (pos)))
#  define IVAL(buf,pos) (*(uint32x *)(CS (buf) + (pos)))
#  define SVALS(buf,pos) (*(int16x *)(CS (buf) + (pos)))
#  define IVALS(buf,pos) (*(int32x *)(CS (buf) + (pos)))

/* store single value in an SMB buffer */
#  define SSVAL(buf,pos,val) SVAL(buf,pos)=((uint16x)(val))
#  define SIVAL(buf,pos,val) IVAL(buf,pos)=((uint32x)(val))
#  define SSVALS(buf,pos,val) SVALS(buf,pos)=((int16x)(val))
#  define SIVALS(buf,pos,val) IVALS(buf,pos)=((int32x)(val))

# endif /* CAREFUL_ALIGNMENT */

/* macros for reading / writing arrays */

# define SMBMACRO(macro,buf,pos,val,len,size) \
{ int l; for (l = 0; l < (len); l++) (val)[l] = macro((buf), (pos) + (size)*l); }

# define SSMBMACRO(macro,buf,pos,val,len,size) \
{ int l; for (l = 0; l < (len); l++) macro((buf), (pos) + (size)*l, (val)[l]); }

/* reads multiple data from an SMB buffer */
# define PCVAL(buf,pos,val,len) SMBMACRO(CVAL,buf,pos,val,len,1)
# define PSVAL(buf,pos,val,len) SMBMACRO(SVAL,buf,pos,val,len,2)
# define PIVAL(buf,pos,val,len) SMBMACRO(IVAL,buf,pos,val,len,4)
# define PCVALS(buf,pos,val,len) SMBMACRO(CVALS,buf,pos,val,len,1)
# define PSVALS(buf,pos,val,len) SMBMACRO(SVALS,buf,pos,val,len,2)
# define PIVALS(buf,pos,val,len) SMBMACRO(IVALS,buf,pos,val,len,4)

/* stores multiple data in an SMB buffer */
# define PSCVAL(buf,pos,val,len) SSMBMACRO(SCVAL,buf,pos,val,len,1)
# define PSSVAL(buf,pos,val,len) SSMBMACRO(SSVAL,buf,pos,val,len,2)
# define PSIVAL(buf,pos,val,len) SSMBMACRO(SIVAL,buf,pos,val,len,4)
# define PSCVALS(buf,pos,val,len) SSMBMACRO(SCVALS,buf,pos,val,len,1)
# define PSSVALS(buf,pos,val,len) SSMBMACRO(SSVALS,buf,pos,val,len,2)
# define PSIVALS(buf,pos,val,len) SSMBMACRO(SIVALS,buf,pos,val,len,4)


/* now the reverse routines - these are used in nmb packets (mostly) */
# define SREV(x) ((((x)&0xFF)<<8) | (((x)>>8)&0xFF))
# define IREV(x) ((SREV(x)<<16) | (SREV((x)>>16)))

# define RSVAL(buf,pos) SREV(SVAL(buf,pos))
# define RSVALS(buf,pos) SREV(SVALS(buf,pos))
# define RIVAL(buf,pos) IREV(IVAL(buf,pos))
# define RIVALS(buf,pos) IREV(IVALS(buf,pos))
# define RSSVAL(buf,pos,val) SSVAL(buf,pos,SREV(val))
# define RSSVALS(buf,pos,val) SSVALS(buf,pos,SREV(val))
# define RSIVAL(buf,pos,val) SIVAL(buf,pos,IREV(val))
# define RSIVALS(buf,pos,val) SIVALS(buf,pos,IREV(val))

/* reads multiple data from an SMB buffer (big-endian) */
# define RPSVAL(buf,pos,val,len) SMBMACRO(RSVAL,buf,pos,val,len,2)
# define RPIVAL(buf,pos,val,len) SMBMACRO(RIVAL,buf,pos,val,len,4)
# define RPSVALS(buf,pos,val,len) SMBMACRO(RSVALS,buf,pos,val,len,2)
# define RPIVALS(buf,pos,val,len) SMBMACRO(RIVALS,buf,pos,val,len,4)

/* stores multiple data in an SMB buffer (big-endian) */
# define RPSSVAL(buf,pos,val,len) SSMBMACRO(RSSVAL,buf,pos,val,len,2)
# define RPSIVAL(buf,pos,val,len) SSMBMACRO(RSIVAL,buf,pos,val,len,4)
# define RPSSVALS(buf,pos,val,len) SSMBMACRO(RSSVALS,buf,pos,val,len,2)
# define RPSIVALS(buf,pos,val,len) SSMBMACRO(RSIVALS,buf,pos,val,len,4)

# define DBG_RW_PCVAL(charmode,string,depth,base,read,inbuf,outbuf,len) \
       { RW_PCVAL(read,inbuf,outbuf,len) \
       DEBUG_X(5,("%s%04x %s: ", \
             tab_depth(depth), base,string)); \
    if (charmode) print_asc(5, US (outbuf), (len)); else \
       { int idx; for (idx = 0; idx < len; idx++) { DEBUG_X(5,("%02x ", (outbuf)[idx])); } } \
       DEBUG_X(5,("\n")); }

# define DBG_RW_PSVAL(charmode,string,depth,base,read,big_endian,inbuf,outbuf,len) \
       { RW_PSVAL(read,big_endian,inbuf,outbuf,len) \
       DEBUG_X(5,("%s%04x %s: ", \
             tab_depth(depth), base,string)); \
    if (charmode) print_asc(5, US (outbuf), 2*(len)); else \
       { int idx; for (idx = 0; idx < len; idx++) { DEBUG_X(5,("%04x ", (outbuf)[idx])); } } \
       DEBUG_X(5,("\n")); }

# define DBG_RW_PIVAL(charmode,string,depth,base,read,big_endian,inbuf,outbuf,len) \
       { RW_PIVAL(read,big_endian,inbuf,outbuf,len) \
       DEBUG_X(5,("%s%04x %s: ", \
             tab_depth(depth), base,string)); \
    if (charmode) print_asc(5, US (outbuf), 4*(len)); else \
       { int idx; for (idx = 0; idx < len; idx++) { DEBUG_X(5,("%08x ", (outbuf)[idx])); } } \
       DEBUG_X(5,("\n")); }

# define DBG_RW_CVAL(string,depth,base,read,inbuf,outbuf) \
       { RW_CVAL(read,inbuf,outbuf,0) \
       DEBUG_X(5,("%s%04x %s: %02x\n", \
             tab_depth(depth), base, string, outbuf)); }

# define DBG_RW_SVAL(string,depth,base,read,big_endian,inbuf,outbuf) \
       { RW_SVAL(read,big_endian,inbuf,outbuf,0) \
       DEBUG_X(5,("%s%04x %s: %04x\n", \
             tab_depth(depth), base, string, outbuf)); }

# define DBG_RW_IVAL(string,depth,base,read,big_endian,inbuf,outbuf) \
       { RW_IVAL(read,big_endian,inbuf,outbuf,0) \
       DEBUG_X(5,("%s%04x %s: %08x\n", \
             tab_depth(depth), base, string, outbuf)); }

#endif /* _BYTEORDER_H */

void E_P16 (uschar *p14, uschar *p16);
void E_P24 (uschar *p21, uschar *c8, uschar *p24);
void D_P16 (uschar *p14, uschar *in, uschar *out);
void SMBOWFencrypt (uschar passwd[16], uschar * c8, uschar p24[24]);

void mdfour (uschar *out, uschar *in, int n);


/*
 * base64.c -- base-64 conversion routines.
 *
 * For license terms, see the file COPYING in this directory.
 *
 * This base 64 encoding is defined in RFC2045 section 6.8,
 * "Base64 Content-Transfer-Encoding", but lines must not be broken in the
 * scheme used here.
 */

static const char base64digits[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define BAD    (char) -1
static const char base64val[] = {
  BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD,
    BAD,
  BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD,
    BAD,
  BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD, 62, BAD, BAD, BAD,
    63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, BAD, BAD, BAD, BAD, BAD, BAD,
  BAD, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, BAD, BAD, BAD, BAD, BAD,
  BAD, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, BAD, BAD, BAD, BAD, BAD
};
#define DECODE64(c)  (isascii(c) ? base64val[c] : BAD)

void
spa_bits_to_base64 (uschar *out, const uschar *in, int inlen)
/* raw bytes in quasi-big-endian order to base 64 string (NUL-terminated) */
{
  for (; inlen >= 3; inlen -= 3)
    {
      *out++ = base64digits[in[0] >> 2];
      *out++ = base64digits[((in[0] << 4) & 0x30) | (in[1] >> 4)];
      *out++ = base64digits[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
      *out++ = base64digits[in[2] & 0x3f];
      in += 3;
    }
  if (inlen > 0)
    {
      uschar fragment;

      *out++ = base64digits[in[0] >> 2];
      fragment = (in[0] << 4) & 0x30;
      if (inlen > 1)
       fragment |= in[1] >> 4;
      *out++ = base64digits[fragment];
      *out++ = (inlen < 2) ? '=' : base64digits[(in[1] << 2) & 0x3c];
      *out++ = '=';
    }
  *out = '\0';
}


/* The outlength parameter was added by PH, December 2004 */

int
spa_base64_to_bits (char *out, int outlength, const char *in)
/* base 64 to raw bytes in quasi-big-endian order, returning count of bytes */
{
  int len = 0;
  register uschar digit1, digit2, digit3, digit4;

  if (in[0] == '+' && in[1] == ' ')
    in += 2;
  if (*in == '\r')
    return (0);

  do
    {
      if (len >= outlength)                   /* Added by PH */
        return (-1);                          /* Added by PH */
      digit1 = in[0];
      if (DECODE64 (digit1) == BAD)
       return (-1);
      digit2 = in[1];
      if (DECODE64 (digit2) == BAD)
       return (-1);
      digit3 = in[2];
      if (digit3 != '=' && DECODE64 (digit3) == BAD)
       return (-1);
      digit4 = in[3];
      if (digit4 != '=' && DECODE64 (digit4) == BAD)
       return (-1);
      in += 4;
      *out++ = (DECODE64 (digit1) << 2) | (DECODE64 (digit2) >> 4);
      ++len;
      if (digit3 != '=')
       {
         if (len >= outlength)                   /* Added by PH */
           return (-1);                          /* Added by PH */
         *out++ =
           ((DECODE64 (digit2) << 4) & 0xf0) | (DECODE64 (digit3) >> 2);
         ++len;
         if (digit4 != '=')
           {
             if (len >= outlength)                   /* Added by PH */
               return (-1);                          /* Added by PH */
             *out++ = ((DECODE64 (digit3) << 6) & 0xc0) | DECODE64 (digit4);
             ++len;
           }
       }
    }
  while (*in && *in != '\r' && digit4 != '=');

  return (len);
}


static uschar perm1[56] = { 57, 49, 41, 33, 25, 17, 9,
  1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27,
  19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,
  7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29,
  21, 13, 5, 28, 20, 12, 4
};

static uschar perm2[48] = { 14, 17, 11, 24, 1, 5,
  3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8,
  16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55,
  30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32
};

static uschar perm3[64] = { 58, 50, 42, 34, 26, 18, 10, 2,
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6,
  64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7
};

static uschar perm4[48] = { 32, 1, 2, 3, 4, 5,
  4, 5, 6, 7, 8, 9,
  8, 9, 10, 11, 12, 13,
  12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21,
  20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29,
  28, 29, 30, 31, 32, 1
};

static uschar perm5[32] = { 16, 7, 20, 21,
  29, 12, 28, 17,
  1, 15, 23, 26,
  5, 18, 31, 10,
  2, 8, 24, 14,
  32, 27, 3, 9,
  19, 13, 30, 6,
  22, 11, 4, 25
};


static uschar perm6[64] = { 40, 8, 48, 16, 56, 24, 64, 32,
  39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30,
  37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28,
  35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26,
  33, 1, 41, 9, 49, 17, 57, 25
};


static uschar sc[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

static uschar sbox[8][4][16] = {
  {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
   {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
   {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
   {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},

  {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
   {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
   {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
   {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},

  {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
   {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
   {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
   {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},

  {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
   {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
   {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
   {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},

  {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
   {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
   {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
   {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},

  {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
   {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
   {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
   {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},

  {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
   {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
   {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
   {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},

  {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
   {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
   {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
   {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}
};

static void
permute (char *out, char *in, uschar * p, int n)
{
  int i;
  for (i = 0; i < n; i++)
    out[i] = in[p[i] - 1];
}

static void
lshift (char *d, int count, int n)
{
  char out[64];
  int i;
  for (i = 0; i < n; i++)
    out[i] = d[(i + count) % n];
  for (i = 0; i < n; i++)
    d[i] = out[i];
}

static void
concat (char *out, char *in1, char *in2, int l1, int l2)
{
  while (l1--)
    *out++ = *in1++;
  while (l2--)
    *out++ = *in2++;
}

static void
xor (char *out, char *in1, char *in2, int n)
{
  int i;
  for (i = 0; i < n; i++)
    out[i] = in1[i] ^ in2[i];
}

static void
dohash (char *out, char *in, char *key, int forw)
{
  int i, j, k;
  char pk1[56];
  char c[28];
  char d[28];
  char cd[56];
  char ki[16][48];
  char pd1[64];
  char l[32], r[32];
  char rl[64];

  permute (pk1, key, perm1, 56);

  for (i = 0; i < 28; i++)
    c[i] = pk1[i];
  for (i = 0; i < 28; i++)
    d[i] = pk1[i + 28];

  for (i = 0; i < 16; i++)
    {
      lshift (c, sc[i], 28);
      lshift (d, sc[i], 28);

      concat (cd, c, d, 28, 28);
      permute (ki[i], cd, perm2, 48);
    }

  permute (pd1, in, perm3, 64);

  for (j = 0; j < 32; j++)
    {
      l[j] = pd1[j];
      r[j] = pd1[j + 32];
    }

  for (i = 0; i < 16; i++)
    {
      char er[48];
      char erk[48];
      char b[8][6];
      char cb[32];
      char pcb[32];
      char r2[32];

      permute (er, r, perm4, 48);

      xor (erk, er, ki[forw ? i : 15 - i], 48);

      for (j = 0; j < 8; j++)
       for (k = 0; k < 6; k++)
         b[j][k] = erk[j * 6 + k];

      for (j = 0; j < 8; j++)
       {
         int m, n;
         m = (b[j][0] << 1) | b[j][5];

         n = (b[j][1] << 3) | (b[j][2] << 2) | (b[j][3] << 1) | b[j][4];

         for (k = 0; k < 4; k++)
           b[j][k] = (sbox[j][m][n] & (1 << (3 - k))) ? 1 : 0;
       }

      for (j = 0; j < 8; j++)
       for (k = 0; k < 4; k++)
         cb[j * 4 + k] = b[j][k];
      permute (pcb, cb, perm5, 32);

      xor (r2, l, pcb, 32);

      for (j = 0; j < 32; j++)
       l[j] = r[j];

      for (j = 0; j < 32; j++)
       r[j] = r2[j];
    }

  concat (rl, r, l, 32, 32);

  permute (out, rl, perm6, 64);
}

static void
str_to_key (uschar *str, uschar *key)
{
  int i;

  key[0] = str[0] >> 1;
  key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2);
  key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3);
  key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4);
  key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5);
  key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6);
  key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7);
  key[7] = str[6] & 0x7F;
  for (i = 0; i < 8; i++)
    {
      key[i] = (key[i] << 1);
    }
}


static void
smbhash (uschar *out, uschar *in, uschar *key, int forw)
{
  int i;
  char outb[64];
  char inb[64];
  char keyb[64];
  uschar key2[8];

  str_to_key (key, key2);

  for (i = 0; i < 64; i++)
    {
      inb[i] = (in[i / 8] & (1 << (7 - (i % 8)))) ? 1 : 0;
      keyb[i] = (key2[i / 8] & (1 << (7 - (i % 8)))) ? 1 : 0;
      outb[i] = 0;
    }

  dohash (outb, inb, keyb, forw);

  for (i = 0; i < 8; i++)
    {
      out[i] = 0;
    }

  for (i = 0; i < 64; i++)
    {
      if (outb[i])
       out[i / 8] |= (1 << (7 - (i % 8)));
    }
}

void
E_P16 (uschar *p14, uschar *p16)
{
  uschar sp8[8] = { 0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 };
  smbhash (p16, sp8, p14, 1);
  smbhash (p16 + 8, sp8, p14 + 7, 1);
}

void
E_P24 (uschar *p21, uschar *c8, uschar *p24)
{
  smbhash (p24, c8, p21, 1);
  smbhash (p24 + 8, c8, p21 + 7, 1);
  smbhash (p24 + 16, c8, p21 + 14, 1);
}

void
D_P16 (uschar *p14, uschar *in, uschar *out)
{
  smbhash (out, in, p14, 0);
  smbhash (out + 8, in + 8, p14 + 7, 0);
}

/****************************************************************************
 Like strncpy but always null terminates. Make sure there is room!
 The variable n should always be one less than the available size.
****************************************************************************/

char *
StrnCpy (char *dest, const char *src, size_t n)
{
  char *d = dest;
  if (!dest)
    return (NULL);
  if (!src)
    {
      *dest = 0;
      return (dest);
    }
  while (n-- && (*d++ = *src++));
  *d = 0;
  return (dest);
}

size_t
skip_multibyte_char (char c)
{
  /* bogus if to get rid of unused compiler warning */
  if (c)
    return 0;
  else
    return 0;
}


/*******************************************************************
safe string copy into a known length string. maxlength does not
include the terminating zero.
********************************************************************/

char *
safe_strcpy (char *dest, const char *src, size_t maxlength)
{
  size_t len;

  if (!dest)
    {
      DEBUG_X (0, ("ERROR: NULL dest in safe_strcpy\n"));
      return NULL;
    }

  if (!src)
    {
      *dest = 0;
      return dest;
    }

  len = strlen (src);

  if (len > maxlength)
    {
      DEBUG_X (0, ("ERROR: string overflow by %d in safe_strcpy [%.50s]\n",
                (int) (len - maxlength), src));
      len = maxlength;
    }

  memcpy (dest, src, len);
  dest[len] = 0;
  return dest;
}


void
strupper (char *s)
{
  while (*s)
    {
      {
       size_t skip = skip_multibyte_char (*s);
       if (skip != 0)
         s += skip;
       else
         {
           if (islower ((uschar)(*s)))
             *s = toupper (*s);
           s++;
         }
      }
    }
}


/*
 This implements the X/Open SMB password encryption
 It takes a password, a 8 byte "crypt key" and puts 24 bytes of
 encrypted password into p24
 */

void
spa_smb_encrypt (uschar * passwd, uschar * c8, uschar * p24)
{
  uschar p14[15], p21[21];

  memset (p21, '\0', 21);
  memset (p14, '\0', 14);
  StrnCpy (CS  p14, CS  passwd, 14);

  strupper (CS  p14);
  E_P16 (p14, p21);

  SMBOWFencrypt (p21, c8, p24);

#ifdef DEBUG_PASSWORD
  DEBUG_X (100, ("spa_smb_encrypt: lm#, challenge, response\n"));
  dump_data (100, CS  p21, 16);
  dump_data (100, CS  c8, 8);
  dump_data (100, CS  p24, 24);
#endif
}

/* Routines for Windows NT MD4 Hash functions. */
static int
_my_wcslen (int16x * str)
{
  int len = 0;
  while (*str++ != 0)
    len++;
  return len;
}

/*
 * Convert a string into an NT UNICODE string.
 * Note that regardless of processor type
 * this must be in intel (little-endian)
 * format.
 */

static int
_my_mbstowcs (int16x * dst, uschar * src, int len)
{
  int i;
  int16x val;

  for (i = 0; i < len; i++)
    {
      val = *src;
      SSVAL (dst, 0, val);
      dst++;
      src++;
      if (val == 0)
       break;
    }
  return i;
}

/*
 * Creates the MD4 Hash of the users password in NT UNICODE.
 */

void
E_md4hash (uschar * passwd, uschar * p16)
{
  int len;
  int16x wpwd[129];

  /* Password cannot be longer than 128 characters */
  len = strlen (CS  passwd);
  if (len > 128)
    len = 128;
  /* Password must be converted to NT unicode */
  _my_mbstowcs (wpwd, passwd, len);
  wpwd[len] = 0;               /* Ensure string is null terminated */
  /* Calculate length in bytes */
  len = _my_wcslen (wpwd) * sizeof (int16x);

  mdfour (p16, US wpwd, len);
}

/* Does both the NT and LM owfs of a user's password */
void
nt_lm_owf_gen (char *pwd, uschar nt_p16[16], uschar p16[16])
{
  char passwd[130];

  memset (passwd, '\0', 130);
  safe_strcpy (passwd, pwd, sizeof (passwd) - 1);

  /* Calculate the MD4 hash (NT compatible) of the password */
  memset (nt_p16, '\0', 16);
  E_md4hash (US passwd, nt_p16);

#ifdef DEBUG_PASSWORD
  DEBUG_X (100, ("nt_lm_owf_gen: pwd, nt#\n"));
  dump_data (120, passwd, strlen (passwd));
  dump_data (100, CS  nt_p16, 16);
#endif

  /* Mangle the passwords into Lanman format */
  passwd[14] = '\0';
  strupper (passwd);

  /* Calculate the SMB (lanman) hash functions of the password */

  memset (p16, '\0', 16);
  E_P16 (US passwd, US p16);

#ifdef DEBUG_PASSWORD
  DEBUG_X (100, ("nt_lm_owf_gen: pwd, lm#\n"));
  dump_data (120, passwd, strlen (passwd));
  dump_data (100, CS  p16, 16);
#endif
  /* clear out local copy of user's password (just being paranoid). */
  memset (passwd, '\0', sizeof (passwd));
}

/* Does the des encryption from the NT or LM MD4 hash. */
void
SMBOWFencrypt (uschar passwd[16], uschar * c8, uschar p24[24])
{
  uschar p21[21];

  memset (p21, '\0', 21);

  memcpy (p21, passwd, 16);
  E_P24 (p21, c8, p24);
}

/* Does the des encryption from the FIRST 8 BYTES of the NT or LM MD4 hash. */
void
NTLMSSPOWFencrypt (uschar passwd[8], uschar * ntlmchalresp, uschar p24[24])
{
  uschar p21[21];

  memset (p21, '\0', 21);
  memcpy (p21, passwd, 8);
  memset (p21 + 8, 0xbd, 8);

  E_P24 (p21, ntlmchalresp, p24);
#ifdef DEBUG_PASSWORD
  DEBUG_X (100, ("NTLMSSPOWFencrypt: p21, c8, p24\n"));
  dump_data (100, CS  p21, 21);
  dump_data (100, CS  ntlmchalresp, 8);
  dump_data (100, CS  p24, 24);
#endif
}


/* Does the NT MD4 hash then des encryption. */

void
spa_smb_nt_encrypt (uschar * passwd, uschar * c8, uschar * p24)
{
  uschar p21[21];

  memset (p21, '\0', 21);

  E_md4hash (passwd, p21);
  SMBOWFencrypt (p21, c8, p24);

#ifdef DEBUG_PASSWORD
  DEBUG_X (100, ("spa_smb_nt_encrypt: nt#, challenge, response\n"));
  dump_data (100, CS  p21, 16);
  dump_data (100, CS  c8, 8);
  dump_data (100, CS  p24, 24);
#endif
}

static uint32x A, B, C, D;

static uint32x
F (uint32x X, uint32x Y, uint32x Z)
{
  return (X & Y) | ((~X) & Z);
}

static uint32x
G (uint32x X, uint32x Y, uint32x Z)
{
  return (X & Y) | (X & Z) | (Y & Z);
}

static uint32x
H (uint32x X, uint32x Y, uint32x Z)
{
  return X ^ Y ^ Z;
}

static uint32x
lshift_a (uint32x x, int s)
{
  x &= 0xFFFFFFFF;
  return ((x << s) & 0xFFFFFFFF) | (x >> (32 - s));
}

#define ROUND1(a,b,c,d,k,s) a = lshift_a(a + F(b,c,d) + X[k], s)
#define ROUND2(a,b,c,d,k,s) a = lshift_a(a + G(b,c,d) + X[k] + (uint32x)0x5A827999,s)
#define ROUND3(a,b,c,d,k,s) a = lshift_a(a + H(b,c,d) + X[k] + (uint32x)0x6ED9EBA1,s)

/* this applies md4 to 64 byte chunks */
static void
spa_mdfour64 (uint32x * M)
{
  int j;
  uint32x AA, BB, CC, DD;
  uint32x X[16];

  for (j = 0; j < 16; j++)
    X[j] = M[j];

  AA = A;
  BB = B;
  CC = C;
  DD = D;

  ROUND1 (A, B, C, D, 0, 3);
  ROUND1 (D, A, B, C, 1, 7);
  ROUND1 (C, D, A, B, 2, 11);
  ROUND1 (B, C, D, A, 3, 19);
  ROUND1 (A, B, C, D, 4, 3);
  ROUND1 (D, A, B, C, 5, 7);
  ROUND1 (C, D, A, B, 6, 11);
  ROUND1 (B, C, D, A, 7, 19);
  ROUND1 (A, B, C, D, 8, 3);
  ROUND1 (D, A, B, C, 9, 7);
  ROUND1 (C, D, A, B, 10, 11);
  ROUND1 (B, C, D, A, 11, 19);
  ROUND1 (A, B, C, D, 12, 3);
  ROUND1 (D, A, B, C, 13, 7);
  ROUND1 (C, D, A, B, 14, 11);
  ROUND1 (B, C, D, A, 15, 19);

  ROUND2 (A, B, C, D, 0, 3);
  ROUND2 (D, A, B, C, 4, 5);
  ROUND2 (C, D, A, B, 8, 9);
  ROUND2 (B, C, D, A, 12, 13);
  ROUND2 (A, B, C, D, 1, 3);
  ROUND2 (D, A, B, C, 5, 5);
  ROUND2 (C, D, A, B, 9, 9);
  ROUND2 (B, C, D, A, 13, 13);
  ROUND2 (A, B, C, D, 2, 3);
  ROUND2 (D, A, B, C, 6, 5);
  ROUND2 (C, D, A, B, 10, 9);
  ROUND2 (B, C, D, A, 14, 13);
  ROUND2 (A, B, C, D, 3, 3);
  ROUND2 (D, A, B, C, 7, 5);
  ROUND2 (C, D, A, B, 11, 9);
  ROUND2 (B, C, D, A, 15, 13);

  ROUND3 (A, B, C, D, 0, 3);
  ROUND3 (D, A, B, C, 8, 9);
  ROUND3 (C, D, A, B, 4, 11);
  ROUND3 (B, C, D, A, 12, 15);
  ROUND3 (A, B, C, D, 2, 3);
  ROUND3 (D, A, B, C, 10, 9);
  ROUND3 (C, D, A, B, 6, 11);
  ROUND3 (B, C, D, A, 14, 15);
  ROUND3 (A, B, C, D, 1, 3);
  ROUND3 (D, A, B, C, 9, 9);
  ROUND3 (C, D, A, B, 5, 11);
  ROUND3 (B, C, D, A, 13, 15);
  ROUND3 (A, B, C, D, 3, 3);
  ROUND3 (D, A, B, C, 11, 9);
  ROUND3 (C, D, A, B, 7, 11);
  ROUND3 (B, C, D, A, 15, 15);

  A += AA;
  B += BB;
  C += CC;
  D += DD;

  A &= 0xFFFFFFFF;
  B &= 0xFFFFFFFF;
  C &= 0xFFFFFFFF;
  D &= 0xFFFFFFFF;

  for (j = 0; j < 16; j++)
    X[j] = 0;
}

static void
copy64 (uint32x * M, uschar *in)
{
  int i;

  for (i = 0; i < 16; i++)
    M[i] = (in[i * 4 + 3] << 24) | (in[i * 4 + 2] << 16) |
      (in[i * 4 + 1] << 8) | (in[i * 4 + 0] << 0);
}

static void
copy4 (uschar *out, uint32x x)
{
  out[0] = x & 0xFF;
  out[1] = (x >> 8) & 0xFF;
  out[2] = (x >> 16) & 0xFF;
  out[3] = (x >> 24) & 0xFF;
}

/* produce a md4 message digest from data of length n bytes */
void
mdfour (uschar *out, uschar *in, int n)
{
  uschar buf[128];
  uint32x M[16];
  uint32x b = n * 8;
  int i;

  A = 0x67452301;
  B = 0xefcdab89;
  C = 0x98badcfe;
  D = 0x10325476;

  while (n > 64)
    {
      copy64 (M, in);
      spa_mdfour64 (M);
      in += 64;
      n -= 64;
    }

  for (i = 0; i < 128; i++)
    buf[i] = 0;
  memcpy (buf, in, n);
  buf[n] = 0x80;

  if (n <= 55)
    {
      copy4 (buf + 56, b);
      copy64 (M, buf);
      spa_mdfour64 (M);
    }
  else
    {
      copy4 (buf + 120, b);
      copy64 (M, buf);
      spa_mdfour64 (M);
      copy64 (M, buf + 64);
      spa_mdfour64 (M);
    }

  for (i = 0; i < 128; i++)
    buf[i] = 0;
  copy64 (M, buf);

  copy4 (out, A);
  copy4 (out + 4, B);
  copy4 (out + 8, C);
  copy4 (out + 12, D);

  A = B = C = D = 0;
}

char versionString[] = "libntlm version 0.21";

/* Utility routines that handle NTLM auth structures. */

/* The [IS]VAL macros are to take care of byte order for non-Intel
 * Machines -- I think this file is OK, but it hasn't been tested.
 * The other files (the ones stolen from Samba) should be OK.
 */


/* I am not crazy about these macros -- they seem to have gotten
 * a bit complex.  A new scheme for handling string/buffer fields
 * in the structures probably needs to be designed
 */

#define spa_bytes_add(ptr, header, buf, count) \
{ \
if (buf != NULL  &&  count != 0) /* we hate -Wint-in-bool-contex */ \
  { \
  SSVAL(&ptr->header.len,0,count); \
  SSVAL(&ptr->header.maxlen,0,count); \
  SIVAL(&ptr->header.offset,0,((ptr->buffer - ((uint8x*)ptr)) + ptr->bufIndex)); \
  memcpy(ptr->buffer+ptr->bufIndex, buf, count); \
  ptr->bufIndex += count; \
  } \
else \
  { \
  ptr->header.len = \
  ptr->header.maxlen = 0; \
  SIVAL(&ptr->header.offset,0,((ptr->buffer - ((uint8x*)ptr)) + ptr->bufIndex)); \
  } \
}

#define spa_string_add(ptr, header, string) \
{ \
char *p = string; \
int len = 0; \
if (p) len = strlen(p); \
spa_bytes_add(ptr, header, (US p), len); \
}

#define spa_unicode_add_string(ptr, header, string) \
{ \
char *p = string; \
uschar *b = NULL; \
int len = 0; \
if (p) \
  { \
  len = strlen(p); \
  b = strToUnicode(p); \
  } \
spa_bytes_add(ptr, header, b, len*2); \
}


#define GetUnicodeString(structPtr, header) \
unicodeToString(((char*)structPtr) + IVAL(&structPtr->header.offset,0) , SVAL(&structPtr->header.len,0)/2)
#define GetString(structPtr, header) \
toString(((CS structPtr) + IVAL(&structPtr->header.offset,0)), SVAL(&structPtr->header.len,0))

#ifdef notdef

#define DumpBuffer(fp, structPtr, header) \
dumpRaw(fp,(US structPtr)+IVAL(&structPtr->header.offset,0),SVAL(&structPtr->header.len,0))


static void
dumpRaw (FILE * fp, uschar *buf, size_t len)
{
  int i;

  for (i = 0; i < len; ++i)
    fprintf (fp, "%02x ", buf[i]);

  fprintf (fp, "\n");
}

#endif

char *
unicodeToString (char *p, size_t len)
{
  int i;
  static char buf[1024];

  assert (len + 1 < sizeof buf);

  for (i = 0; i < len; ++i)
    {
      buf[i] = *p & 0x7f;
      p += 2;
    }

  buf[i] = '\0';
  return buf;
}

static uschar *
strToUnicode (char *p)
{
  static uschar buf[1024];
  size_t l = strlen (p);
  int i = 0;

  assert (l * 2 < sizeof buf);

  while (l--)
    {
      buf[i++] = *p++;
      buf[i++] = 0;
    }

  return buf;
}

static uschar *
toString (char *p, size_t len)
{
  static uschar buf[1024];

  assert (len + 1 < sizeof buf);

  memcpy (buf, p, len);
  buf[len] = 0;
  return buf;
}

#ifdef notdef

void
dumpSmbNtlmAuthRequest (FILE * fp, SPAAuthRequest * request)
{
  fprintf (fp, "NTLM Request:\n");
  fprintf (fp, "      Ident = %s\n", request->ident);
  fprintf (fp, "      mType = %d\n", IVAL (&request->msgType, 0));
  fprintf (fp, "      Flags = %08x\n", IVAL (&request->flags, 0));
  fprintf (fp, "       User = %s\n", GetString (request, user));
  fprintf (fp, "     Domain = %s\n", GetString (request, domain));
}

void
dumpSmbNtlmAuthChallenge (FILE * fp, SPAAuthChallenge * challenge)
{
  fprintf (fp, "NTLM Challenge:\n");
  fprintf (fp, "      Ident = %s\n", challenge->ident);
  fprintf (fp, "      mType = %d\n", IVAL (&challenge->msgType, 0));
  fprintf (fp, "     Domain = %s\n", GetUnicodeString (challenge, uDomain));
  fprintf (fp, "      Flags = %08x\n", IVAL (&challenge->flags, 0));
  fprintf (fp, "  Challenge = ");
  dumpRaw (fp, challenge->challengeData, 8);
}

void
dumpSmbNtlmAuthResponse (FILE * fp, SPAAuthResponse * response)
{
  fprintf (fp, "NTLM Response:\n");
  fprintf (fp, "      Ident = %s\n", response->ident);
  fprintf (fp, "      mType = %d\n", IVAL (&response->msgType, 0));
  fprintf (fp, "     LmResp = ");
  DumpBuffer (fp, response, lmResponse);
  fprintf (fp, "     NTResp = ");
  DumpBuffer (fp, response, ntResponse);
  fprintf (fp, "     Domain = %s\n", GetUnicodeString (response, uDomain));
  fprintf (fp, "       User = %s\n", GetUnicodeString (response, uUser));
  fprintf (fp, "        Wks = %s\n", GetUnicodeString (response, uWks));
  fprintf (fp, "       sKey = ");
  DumpBuffer (fp, response, sessionKey);
  fprintf (fp, "      Flags = %08x\n", IVAL (&response->flags, 0));
}
#endif

void
spa_build_auth_request (SPAAuthRequest * request, char *user, char *domain)
{
  char *u = strdup (user);
  char *p = strchr (u, '@');

  if (p)
    {
      if (!domain)
       domain = p + 1;
      *p = '\0';
    }

  request->bufIndex = 0;
  memcpy (request->ident, "NTLMSSP\0\0\0", 8);
  SIVAL (&request->msgType, 0, 1);
  SIVAL (&request->flags, 0, 0x0000b207);      /* have to figure out what these mean */
  spa_string_add (request, user, u);
  spa_string_add (request, domain, domain);
  free (u);
}



void
spa_build_auth_challenge (SPAAuthRequest * request, SPAAuthChallenge * challenge)
{
  char chalstr[8];
  int i;
  int p = (int)getpid();
  int random_seed = (int)time(NULL) ^ ((p << 16) | p);

  request = request;  /* Added by PH to stop compilers whinging */

  /* Ensure challenge data is cleared, in case it isn't all used. This
  patch added by PH on suggestion of Russell King */

  memset(challenge, 0, sizeof(SPAAuthChallenge));

  challenge->bufIndex = 0;
  memcpy (challenge->ident, "NTLMSSP\0", 8);
  SIVAL (&challenge->msgType, 0, 2);
  SIVAL (&challenge->flags, 0, 0x00008201);
  SIVAL (&challenge->uDomain.len, 0, 0x0000);
  SIVAL (&challenge->uDomain.maxlen, 0, 0x0000);
  SIVAL (&challenge->uDomain.offset, 0, 0x00002800);

  /* generate eight pseudo random bytes (method ripped from host.c) */

  for(i=0;i<8;i++) {
    chalstr[i] = (uschar)(random_seed >> 16) % 256;
    random_seed = (1103515245 - (chalstr[i])) * random_seed + 12345;
  };

  memcpy(challenge->challengeData,chalstr,8);
}




/* This is the original source of this function, preserved here for reference.
The new version below was re-organized by PH following a patch and some further
suggestions from Mark Lyda to fix the problem that is described at the head of
this module. At the same time, I removed the untidiness in the code below that
involves the "d" and "domain" variables. */

#ifdef NEVER
void
spa_build_auth_response (SPAAuthChallenge * challenge,
                        SPAAuthResponse * response, char *user,
                        char *password)
{
  uint8x lmRespData[24];
  uint8x ntRespData[24];
  char *d = strdup (GetUnicodeString (challenge, uDomain));
  char *domain = d;
  char *u = strdup (user);
  char *p = strchr (u, '@');

  if (p)
    {
      domain = p + 1;
      *p = '\0';
    }

  spa_smb_encrypt (US password, challenge->challengeData, lmRespData);
  spa_smb_nt_encrypt (US password, challenge->challengeData, ntRespData);

  response->bufIndex = 0;
  memcpy (response->ident, "NTLMSSP\0\0\0", 8);
  SIVAL (&response->msgType, 0, 3);

  spa_bytes_add (response, lmResponse, lmRespData, 24);
  spa_bytes_add (response, ntResponse, ntRespData, 24);
  spa_unicode_add_string (response, uDomain, domain);
  spa_unicode_add_string (response, uUser, u);
  spa_unicode_add_string (response, uWks, u);
  spa_string_add (response, sessionKey, NULL);

  response->flags = challenge->flags;

  free (d);
  free (u);
}
#endif


/* This is the re-organized version (see comments above) */

void
spa_build_auth_response (SPAAuthChallenge * challenge,
                        SPAAuthResponse * response, char *user,
                        char *password)
{
  uint8x lmRespData[24];
  uint8x ntRespData[24];
  uint32x cf = IVAL(&challenge->flags, 0);
  char *u = strdup (user);
  char *p = strchr (u, '@');
  char *d = NULL;
  char *domain;

  if (p)
    {
    domain = p + 1;
    *p = '\0';
    }

  else domain = d = strdup((cf & 0x1)?
    CCS GetUnicodeString(challenge, uDomain) :
    CCS GetString(challenge, uDomain));

  spa_smb_encrypt (US password, challenge->challengeData, lmRespData);
  spa_smb_nt_encrypt (US password, challenge->challengeData, ntRespData);

  response->bufIndex = 0;
  memcpy (response->ident, "NTLMSSP\0\0\0", 8);
  SIVAL (&response->msgType, 0, 3);

  spa_bytes_add (response, lmResponse, lmRespData, (cf & 0x200) ? 24 : 0);
  spa_bytes_add (response, ntResponse, ntRespData, (cf & 0x8000) ? 24 : 0);

  if (cf & 0x1) {      /* Unicode Text */
       spa_unicode_add_string (response, uDomain, domain);
       spa_unicode_add_string (response, uUser, u);
       spa_unicode_add_string (response, uWks, u);
  } else {             /* OEM Text */
       spa_string_add (response, uDomain, domain);
       spa_string_add (response, uUser, u);
       spa_string_add (response, uWks, u);
  }

  spa_string_add (response, sessionKey, NULL);
  response->flags = challenge->flags;

  if (d != NULL) free (d);
  free (u);
}
