/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "exim.h"

#ifdef SUPPORT_I18N

uschar *
imap_utf7_encode(uschar *string, const uschar *charset, uschar sep,
  uschar *specials, uschar **error)
{
static uschar encode_base64[64] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
size_t slen;
uschar *sptr;
gstring * yield = NULL;
int i = 0, j;	/* compiler quietening */
uschar c = 0;	/* compiler quietening */
BOOL base64mode = FALSE;
BOOL lastsep = FALSE;
uschar utf16buf[256];
uschar *utf16ptr;
uschar *s;
uschar outbuf[256];
uschar *outptr = outbuf;
#if HAVE_ICONV
iconv_t icd;
#endif

if (!specials) specials = US"";

/* Pass over the string. If it consists entirely of "normal" characters
   (possibly with leading seps), return it as is. */
for (s = string; *s; s++)
  {
  if (s == string && *s == sep)
    string++;
  if (  *s >= 0x7f
     || *s < 0x20
     || strchr("./&", *s)
     || *s == sep
     || Ustrchr(specials, *s)
     )
    break;
  }

if (!*s)
  return string;

sptr = string;
slen = Ustrlen(string);

#if HAVE_ICONV
if ((icd = iconv_open("UTF-16BE", CCS charset)) == (iconv_t)-1)
  {
  *error = string_sprintf(
	"imapfolder: iconv_open(\"UTF-16BE\", \"%s\") failed: %s%s",
    charset, strerror(errno),
    errno == EINVAL ? " (maybe unsupported conversion)" : "");
  return NULL;
  }
#endif

while (slen > 0)
  {
#if HAVE_ICONV
  size_t left = sizeof(utf16buf);
  utf16ptr = utf16buf;

  if (  iconv(icd, (ICONV_ARG2_TYPE)&sptr, &slen, CSS &utf16ptr, &left)
		== (size_t)-1
     && errno != E2BIG
	 )
    {
    *error = string_sprintf("imapfolder: iconv() failed to convert from %s: %s",
			      charset, strerror(errno));
    iconv_close(icd);
    return NULL;
    }
#else
  for (utf16ptr = utf16buf;
       slen > 0 && (utf16ptr - utf16buf) < sizeof(utf16buf);
       utf16ptr += 2, slen--, sptr++)
    {
    *utf16ptr = *sptr;
    *(utf16ptr+1) = '\0';
    }
#endif

  s = utf16buf;
  while (s < utf16ptr)
    {
    /* Now encode utf16buf as modified UTF-7 */
    if (  s[0] != 0
       || s[1] >= 0x7f
       || s[1] < 0x20
       || (Ustrchr(specials, s[1]) && s[1] != sep)
       )
      {
      lastsep = FALSE;
      /* Encode as modified BASE64 */
      if (!base64mode)
        {
        *outptr++ = '&';
        base64mode = TRUE;
        i = 0;
        }

      for (j = 0; j < 2; j++, s++) switch (i++)
	{
	case 0:
	  /* Top 6 bits of the first octet */
	  *outptr++ = encode_base64[(*s >> 2) & 0x3F];
	  c = (*s & 0x03); break;
	case 1:
	  /* Bottom 2 bits of the first octet, and top 4 bits of the second */
	  *outptr++ = encode_base64[(c << 4) | ((*s >> 4) & 0x0F)];
	  c = (*s & 0x0F); break;
	case 2:
	  /* Bottom 4 bits of the second octet and top 2 bits of the third */
	  *outptr++ = encode_base64[(c << 2) | ((*s >> 6) & 0x03)];
	  /* Bottom 6 bits of the third octet */
	  *outptr++ = encode_base64[*s & 0x3F];
	  i = 0;
	}
      }

    else if (  (s[1] != '.' && s[1] != '/')
	    || s[1] == sep
	    )
      {
      /* Encode as self (almost) */
      if (base64mode)
        {
        switch (i)
          {
          case 1:
		/* Remaining bottom 2 bits of the last octet */
		*outptr++ = encode_base64[c << 4];
		break;
	  case 2:
		/* Remaining bottom 4 bits of the last octet */
		*outptr++ = encode_base64[c << 2];
	  }
	*outptr++ = '-';
	base64mode = FALSE;
	}

      if (*++s == sep)
	{
	if (!lastsep)
	  {
	  *outptr++ = '.';
	  lastsep = TRUE;
	  }
	}
      else
        {
        *outptr++ = *s;
        if (*s == '&')
	  *outptr++ = '-';
	lastsep = FALSE;
        }

      s++;
      }
    else
      {
      *error = string_sprintf("imapfolder: illegal character '%c'", s[1]);
      return NULL;
      }

    if (outptr > outbuf + sizeof(outbuf) - 3)
      {
      yield = string_catn(yield, outbuf, outptr - outbuf);
      outptr = outbuf;
      }

    }
  } /* End of input string */

if (base64mode)
  {
  switch (i)
    {
    case 1:
      /* Remaining bottom 2 bits of the last octet */
      *outptr++ = encode_base64[c << 4];
      break;
    case 2:
      /* Remaining bottom 4 bits of the last octet */
      *outptr++ = encode_base64[c << 2];
    }
  *outptr++ = '-';
  }

#if HAVE_ICONV
iconv_close(icd);
#endif

yield = string_catn(yield, outbuf, outptr - outbuf);

if (yield->s[yield->ptr-1] == '.')
  yield->ptr--;

return string_from_gstring(yield);
}

#endif	/* whole file */
/* vi: aw ai sw=2
*/
