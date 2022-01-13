/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004, 2015 */
/* License: GPL */

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "exim.h"
#ifdef WITH_CONTENT_SCAN	/* file-IO specific decode function */
# include "mime.h"

/* BASE64 decoder matrix */
static unsigned char mime_b64[256]={
/*   0 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/*  16 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/*  32 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,   62,  128,  128,  128,   63,
/*  48 */   52,   53,   54,   55,   56,   57,   58,   59,   60,   61,  128,  128,  128,  255,  128,  128,
/*  64 */  128,    0,    1,    2,    3,    4,    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,
/*  80 */   15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25,  128,  128,  128,  128,  128,
/*  96 */  128,   26,   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,   37,   38,   39,   40,
/* 112 */   41,   42,   43,   44,   45,   46,   47,   48,   49,   50,   51,  128,  128,  128,  128,  128,
/* 128 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/* 144 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/* 160 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/* 176 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/* 192 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/* 208 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/* 224 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/* 240 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128
};

/* decode base64 MIME part */
ssize_t
mime_decode_base64(FILE * in, FILE * out, uschar * boundary)
{
uschar ibuf[MIME_MAX_LINE_LENGTH], obuf[MIME_MAX_LINE_LENGTH];
uschar *ipos, *opos;
ssize_t len, size = 0;
int bytestate = 0;

opos = obuf;

while (Ufgets(ibuf, MIME_MAX_LINE_LENGTH, in) != NULL)
  {
  if (boundary != NULL
     && Ustrncmp(ibuf, "--", 2) == 0
     && Ustrncmp((ibuf+2), boundary, Ustrlen(boundary)) == 0
     )
    break;

  for (ipos = ibuf ; *ipos != '\r' && *ipos != '\n' && *ipos != 0; ++ipos)
    if (*ipos == '=')			/* skip padding */
      ++bytestate;

    else if (mime_b64[*ipos] == 128)	/* skip bad characters */
      mime_set_anomaly(MIME_ANOMALY_BROKEN_BASE64);

    /* simple state-machine */
    else switch((bytestate++) & 3)
      {
      case 0:
	*opos = mime_b64[*ipos] << 2; break;
      case 1:
	*opos++ |= mime_b64[*ipos] >> 4;
	*opos = mime_b64[*ipos] << 4; break;
      case 2:
	*opos++ |= mime_b64[*ipos] >> 2;
	*opos = mime_b64[*ipos] << 6; break;
      case 3:
	*opos++ |= mime_b64[*ipos]; break;
      }

  /* something to write? */
  len = opos - obuf;
  if (len > 0)
    {
    if (fwrite(obuf, 1, len, out) != len) return -1; /* error */
    size += len;
    /* copy incomplete last byte to start of obuf, where we continue */
    if ((bytestate & 3) != 0)
      *obuf = *opos;
    opos = obuf;
    }
  } /* while */

/* write out last byte if it was incomplete */
if (bytestate & 3)
  {
  if (fwrite(obuf, 1, 1, out) != 1) return -1;
  ++size;
  }

return size;
}

#endif	/*WITH_CONTENT_SCAN*/

/*************************************************
 *************************************************
 *************************************************
 *************************************************
 *************************************************
 *************************************************
 *************************************************
 *************************************************
 *************************************************
 *************************************************
 *************************************************
 *************************************************
 *************************************************
 *************************************************
 *************************************************
 *************************************************/


/*************************************************
*          Decode byte-string in base 64         *
*************************************************/

/* This function decodes a string in base 64 format as defined in RFC 2045
(MIME) and required by the SMTP AUTH extension (RFC 2554). The decoding
algorithm is written out in a straightforward way. Turning it into some kind of
compact loop is messy and would probably run more slowly.

Arguments:
  code        points to the coded string, zero-terminated
  ptr         where to put the pointer to the result, which is in
              allocated store, and zero-terminated

Returns:      the number of bytes in the result,
              or -1 if the input was malformed

Whitespace in the input is ignored.
A zero is added on to the end to make it easy in cases where the result is to
be interpreted as text. This is not included in the count. */

static uschar dec64table[] = {
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, /*  0-15 */
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, /* 16-31 */
  255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63, /* 32-47 */
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,255,255,255, /* 48-63 */
  255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /* 64-79 */
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255, /* 80-95 */
  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 96-111 */
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255  /* 112-127*/
};

int
b64decode(const uschar *code, uschar **ptr)
{

int x, y;
uschar *result;

{
  int l = Ustrlen(code);
  *ptr = result = store_get(1 + l/4 * 3 + l%4);
}

/* Each cycle of the loop handles a quantum of 4 input bytes. For the last
quantum this may decode to 1, 2, or 3 output bytes. */

while ((x = *code++) != 0)
  {
  if (isspace(x)) continue;
  /* debug_printf("b64d: '%c'\n", x); */

  if (x > 127 || (x = dec64table[x]) == 255) return -1;

  while (isspace(y = *code++)) ;
  /* debug_printf("b64d: '%c'\n", y); */
  if (y > 127 || (y = dec64table[y]) == 255)
    return -1;

  *result++ = (x << 2) | (y >> 4);
  /* debug_printf("b64d:      -> %02x\n", result[-1]); */

  while (isspace(x = *code++)) ;
  /* debug_printf("b64d: '%c'\n", x); */
  if (x == '=')		/* endmarker, but there should be another */
    {
    while (isspace(x = *code++)) ;
    /* debug_printf("b64d: '%c'\n", x); */
    if (x != '=') return -1;
    while (isspace(y = *code++)) ;
    if (y != 0) return -1;
    /* debug_printf("b64d: DONE\n"); */
    break;
    }
  else
    {
    if (x > 127 || (x = dec64table[x]) == 255) return -1;
    *result++ = (y << 4) | (x >> 2);
    /* debug_printf("b64d:      -> %02x\n", result[-1]); */

    while (isspace(y = *code++)) ;
    /* debug_printf("b64d: '%c'\n", y); */
    if (y == '=')
      {
      while (isspace(y = *code++)) ;
      if (y != 0) return -1;
      /* debug_printf("b64d: DONE\n"); */
      break;
      }
    else
      {
      if (y > 127 || (y = dec64table[y]) == 255) return -1;
      *result++ = (x << 6) | y;
      /* debug_printf("b64d:      -> %02x\n", result[-1]); */
      }
    }
  }

*result = 0;
return result - *ptr;
}


/*************************************************
*          Encode byte-string in base 64         *
*************************************************/

/* This function encodes a string of bytes, containing any values whatsoever,
in base 64 as defined in RFC 2045 (MIME) and required by the SMTP AUTH
extension (RFC 2554). The encoding algorithm is written out in a
straightforward way. Turning it into some kind of compact loop is messy and
would probably run more slowly.

Arguments:
  clear       points to the clear text bytes
  len         the number of bytes to encode

Returns:      a pointer to the zero-terminated base 64 string, which
              is in working store
*/

static uschar *enc64table =
  US"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

uschar *
b64encode(uschar *clear, int len)
{
uschar *code = store_get(4*((len+2)/3) + 1);
uschar *p = code;

while (len-- >0)
  {
  int x, y;

  x = *clear++;
  *p++ = enc64table[(x >> 2) & 63];

  if (len-- <= 0)
    {
    *p++ = enc64table[(x << 4) & 63];
    *p++ = '=';
    *p++ = '=';
    break;
    }

  y = *clear++;
  *p++ = enc64table[((x << 4) | ((y >> 4) & 15)) & 63];

  if (len-- <= 0)
    {
    *p++ = enc64table[(y << 2) & 63];
    *p++ = '=';
    break;
    }

  x = *clear++;
  *p++ = enc64table[((y << 2) | ((x >> 6) & 3)) & 63];

  *p++ = enc64table[x & 63];
  }

*p = 0;

return code;
}


/* End of base64.c */
/* vi: sw ai sw=2
*/
