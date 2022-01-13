/* Copyright (C) 1991,1992,1993,1996,1997,1998,1999,2000,2001,2002,2003,2007
	Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA
   02110-1335, USA.  */

/* This file comes from the GNU C Library and has been modified for use in
 * ProFTPD.
 *
 * Changes are released under the GNU Public License, version 2.
 * Copyright (C) 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (C) 2010-2012 The ProFTPD Project
 */

/* AIX requires this to be the first thing in the file.  */
#if defined _AIX && !defined __GNUC__
 #pragma alloca
#endif

#include <config.h>

/* Make alloca work the best possible way.  */
#ifdef __GNUC__
#define alloca __builtin_alloca
#else /* not __GNUC__ */
#if HAVE_ALLOCA_H
#include <alloca.h>
#else /* not __GNUC__ or HAVE_ALLOCA_H */
#ifndef _AIX /* Already did AIX, up at the top.  */
char *alloca ();
#endif /* not _AIX */
#endif /* not HAVE_ALLOCA_H */
#endif /* not __GNUC__ */

/* Necessary for platforms which don't use __alloca. */
#define __alloca alloca

/* Required to tell conf.h not to include the standard ProFTPD
 * header files
 */

#define __PROFTPD_SUPPORT_LIBRARY

#include <conf.h>
#include <libsupp.h>

#if 0 /* Not used in ProFTPD */
/* Enable GNU extensions in fnmatch.h.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE	1
#endif

#include <assert.h>
#include <errno.h>
#include <fnmatch.h>
#include <ctype.h>

#if HAVE_STRING_H || defined _LIBC
# include <string.h>
#else
# include <strings.h>
#endif

#if defined STDC_HEADERS || defined _LIBC
# include <stdlib.h>
#endif

/* For platform which support the ISO C amendement 1 functionality we
   support user defined character classes.  */
#if defined _LIBC || (defined HAVE_WCTYPE_H && defined HAVE_WCHAR_H)
/* Solaris 2.5 has a bug: <wchar.h> must be included before <wctype.h>.  */
# include <wchar.h>
# include <wctype.h>
#endif

/* We need some of the locale data (the collation sequence information)
   but there is no interface to get this information in general.  Therefore
   we support a correct implementation only in glibc.  */
#ifdef _LIBC
# include "../locale/localeinfo.h"
# include "../locale/elem-hash.h"
# include "../locale/coll-lookup.h"
# include <shlib-compat.h>

# define CONCAT(a,b) __CONCAT(a,b)
# define mbsrtowcs __mbsrtowcs
# define fnmatch __fnmatch
extern int fnmatch (const char *pattern, const char *string, int flags);
#endif
#endif /* Not used in ProFTPD */

/* We often have to test for FNM_FILE_NAME and FNM_PERIOD being both set.  */
#define NO_LEADING_PERIOD(flags) \
  ((flags & (PR_FNM_FILE_NAME | PR_FNM_PERIOD)) == (PR_FNM_FILE_NAME | PR_FNM_PERIOD))

/* Comment out all this code if we are using the GNU C Library, and are not
   actually compiling the library itself.  This code is part of the GNU C
   Library, but also included in many other GNU distributions.  Compiling
   and linking in this code is a waste when using the GNU C library
   (especially if it is a shared library).  Rather than having every GNU
   program understand `configure --with-gnu-libc' and omit the object files,
   it is simpler to just do this in the source for each such file.  */

/* The comment above notwithstanding, we do want to use our own version to
 * ensure cross-platform compatibility...among other things.
 */
#undef _LIBC
#undef __GNU_LIBRARY__

/* Provide an implementation of the gcc-specific __builtin_expect macro,
 * for the non-gcc compilers out there.
 */
#ifndef __builtin_expect
# define __builtin_expect(e, n)	(e)
#endif /* __builtin_expect */

#if defined _LIBC || !defined __GNU_LIBRARY__


# if defined STDC_HEADERS || !defined isascii
#  define ISASCII(c) 1
# else
#  define ISASCII(c) isascii(c)
# endif

# ifdef isblank
#  define ISBLANK(c) (ISASCII (c) && isblank (c))
# else
#  define ISBLANK(c) ((c) == ' ' || (c) == '\t')
# endif
# ifdef isgraph
#  define ISGRAPH(c) (ISASCII (c) && isgraph (c))
# else
#  define ISGRAPH(c) (ISASCII (c) && isprint (c) && !isspace (c))
# endif

# define ISPRINT(c) (ISASCII (c) && isprint (c))
# define ISDIGIT(c) (ISASCII (c) && isdigit (c))
# define ISALNUM(c) (ISASCII (c) && isalnum (c))
# define ISALPHA(c) (ISASCII (c) && isalpha (c))
# define ISCNTRL(c) (ISASCII (c) && iscntrl (c))
# define ISLOWER(c) (ISASCII (c) && islower (c))
# define ISPUNCT(c) (ISASCII (c) && ispunct (c))
# define ISSPACE(c) (ISASCII (c) && isspace (c))
# define ISUPPER(c) (ISASCII (c) && isupper (c))
# define ISXDIGIT(c) (ISASCII (c) && isxdigit (c))

# define STREQ(s1, s2) ((strcmp (s1, s2) == 0))

# define HANDLE_MULTIBYTE       0

# if defined _LIBC || (defined HAVE_WCTYPE_H && defined HAVE_WCHAR_H)
/* The GNU C library provides support for user-defined character classes
   and the functions from ISO C amendement 1.  */
#  ifdef CHARCLASS_NAME_MAX
#   define CHAR_CLASS_MAX_LENGTH CHARCLASS_NAME_MAX
#  else
/* This shouldn't happen but some implementation might still have this
   problem.  Use a reasonable default value.  */
#   define CHAR_CLASS_MAX_LENGTH 256
#  endif

#  ifdef _LIBC
#   define IS_CHAR_CLASS(string) __wctype (string)
#  else
#   define IS_CHAR_CLASS(string) wctype (string)
#  endif

#  ifdef _LIBC
#   define ISWCTYPE(WC, WT)	__iswctype (WC, WT)
#  else
#   define ISWCTYPE(WC, WT)	iswctype (WC, WT)
#  endif

#  if (HAVE_MBSTATE_T && HAVE_MBSRTOWCS) || _LIBC
/* In this case we are implementing the multibyte character handling.  */
#   define HANDLE_MULTIBYTE	1
#  endif

# else
#  define CHAR_CLASS_MAX_LENGTH  6 /* Namely, `xdigit'.  */

#  define IS_CHAR_CLASS(string)						      \
   (STREQ (string, "alpha") || STREQ (string, "upper")			      \
    || STREQ (string, "lower") || STREQ (string, "digit")		      \
    || STREQ (string, "alnum") || STREQ (string, "xdigit")		      \
    || STREQ (string, "space") || STREQ (string, "print")		      \
    || STREQ (string, "punct") || STREQ (string, "graph")		      \
    || STREQ (string, "cntrl") || STREQ (string, "blank"))
# endif

/* Avoid depending on library functions or files
   whose names are inconsistent.  */

# ifndef errno
extern int errno;
# endif

/* Global variable.  */
static int posixly_correct;

# if HANDLE_MULTIBYTE && !defined HAVE___STRCHRNUL && !defined _LIBC
static wchar_t *
__wcschrnul (const wchar_t *s, wint_t c)
{
  wchar_t *result = wcschr (s, c);
  if (result == NULL)
    result = wcschr (s, '\0');
  return result;
}
# endif

# ifndef internal_function
/* Inside GNU libc we mark some function in a special way.  In other
   environments simply ignore the marking.  */
#  define internal_function
# endif

/* Note that this evaluates C many times.  */
# ifdef _LIBC
#  define FOLD(c) ((flags & PR_FNM_CASEFOLD) ? tolower (c) : (c))
# else
#  define FOLD(c) ((flags & PR_FNM_CASEFOLD) && ISUPPER (c) ? tolower (c) : (c))
# endif
# define CHAR	char
# define UCHAR	unsigned char
# define INT	int
# define FCT	internal_fnmatch
# define EXT	ext_match
# define END	end_pattern
# define STRUCT	fnmatch_struct
# define L(CS)	CS
# ifdef _LIBC
#  define BTOWC(C)	__btowc (C)
# else
#  define BTOWC(C)	btowc (C)
# endif
# define STRLEN(S) strlen (S)
# define STRCAT(D, S) strcat (D, S)
# ifdef HAVE_MEMPCPY
#  define MEMPCPY(D, S, N) mempcpy (D, S, N)
# else
#  define MEMPCPY(D, S, N) __mempcpy (D, S, N)
# endif
# define MEMCHR(S, C, N) memchr (S, C, N)
# define STRCOLL(S1, S2) strcoll (S1, S2)
# include "pr_fnmatch_loop.c"


# if HANDLE_MULTIBYTE
/* Note that this evaluates C many times.  */
#  ifdef _LIBC
#   define FOLD(c) ((flags & PR_FNM_CASEFOLD) ? towlower (c) : (c))
#  else
#   define FOLD(c) ((flags & PR_FNM_CASEFOLD) && ISUPPER (c) ? towlower (c) : (c))
#  endif
#  define CHAR	wchar_t
#  define UCHAR	wint_t
#  define INT	wint_t
#  define FCT	internal_fnwmatch
#  define EXT	ext_wmatch
#  define END	end_wpattern
#  define STRUCT fnwmatch_struct
#  define L(CS)	L##CS
#  define BTOWC(C)	(C)
#  define STRLEN(S) __wcslen (S)
#  define STRCAT(D, S) __wcscat (D, S)
#  define MEMPCPY(D, S, N) __wmempcpy (D, S, N)
#  define MEMCHR(S, C, N) wmemchr (S, C, N)
#  define STRCOLL(S1, S2) wcscoll (S1, S2)
#  define WIDE_CHAR_VERSION 1

#  undef IS_CHAR_CLASS
/* We have to convert the wide character string in a multibyte string.  But
   we know that the character class names consist of alphanumeric characters
   from the portable character set, and since the wide character encoding
   for a member of the portable character set is the same code point as
   its single-byte encoding, we can use a simplified method to convert the
   string to a multibyte character string.  */
static wctype_t
is_char_class (const wchar_t *wcs)
{
  char s[CHAR_CLASS_MAX_LENGTH + 1];
  char *cp = s;

  do
    {
      /* Test for a printable character from the portable character set.  */
#  ifdef _LIBC
      if (*wcs < 0x20 || *wcs > 0x7e
	  || *wcs == 0x24 || *wcs == 0x40 || *wcs == 0x60)
	return (wctype_t) 0;
#  else
      switch (*wcs)
	{
	case L' ': case L'!': case L'"': case L'#': case L'%':
	case L'&': case L'\'': case L'(': case L')': case L'*':
	case L'+': case L',': case L'-': case L'.': case L'/':
	case L'0': case L'1': case L'2': case L'3': case L'4':
	case L'5': case L'6': case L'7': case L'8': case L'9':
	case L':': case L';': case L'<': case L'=': case L'>':
	case L'?':
	case L'A': case L'B': case L'C': case L'D': case L'E':
	case L'F': case L'G': case L'H': case L'I': case L'J':
	case L'K': case L'L': case L'M': case L'N': case L'O':
	case L'P': case L'Q': case L'R': case L'S': case L'T':
	case L'U': case L'V': case L'W': case L'X': case L'Y':
	case L'Z':
	case L'[': case L'\\': case L']': case L'^': case L'_':
	case L'a': case L'b': case L'c': case L'd': case L'e':
	case L'f': case L'g': case L'h': case L'i': case L'j':
	case L'k': case L'l': case L'm': case L'n': case L'o':
	case L'p': case L'q': case L'r': case L's': case L't':
	case L'u': case L'v': case L'w': case L'x': case L'y':
	case L'z': case L'{': case L'|': case L'}': case L'~':
	  break;
	default:
	  return (wctype_t) 0;
	}
#  endif

      /* Avoid overrunning the buffer.  */
      if (cp == s + CHAR_CLASS_MAX_LENGTH)
	return (wctype_t) 0;

      *cp++ = (char) *wcs++;
    }
  while (*wcs != L'\0');

  *cp = '\0';

#  ifdef _LIBC
  return __wctype (s);
#  else
  return wctype (s);
#  endif
}
#  define IS_CHAR_CLASS(string) is_char_class (string)

#  include "pr_fnmatch_loop.c"
# endif


int
pr_fnmatch (pattern, string, flags)
     const char *pattern;
     const char *string;
     int flags;
{
# if HANDLE_MULTIBYTE
  if (__builtin_expect (MB_CUR_MAX, 1) != 1)
    {
      mbstate_t ps;
      size_t n;
      const char *p;
      wchar_t *wpattern;
      wchar_t *wstring;

      /* Convert the strings into wide characters.  */
      memset (&ps, '\0', sizeof (ps));
      p = pattern;
#ifdef _LIBC
      n = strnlen (pattern, 1024);
#else
      n = strlen (pattern);
#endif
      if (__builtin_expect (n < 1024, 1))
	{
	  wpattern = (wchar_t *) __alloca ((n + 1) * sizeof (wchar_t));
	  n = mbsrtowcs (wpattern, &p, n + 1, &ps);
	  if (__builtin_expect (n == (size_t) -1, 0))
	    /* Something wrong.
	       XXX Do we have to set `errno' to something which mbsrtows hasn't
	       already done?  */
	    return -1;
	  if (p)
	    {
	      memset (&ps, '\0', sizeof (ps));
	      goto prepare_wpattern;
	    }
	}
      else
	{
	prepare_wpattern:
	  n = mbsrtowcs (NULL, &pattern, 0, &ps);
	  if (__builtin_expect (n == (size_t) -1, 0))
	    /* Something wrong.
	       XXX Do we have to set `errno' to something which mbsrtows hasn't
	       already done?  */
	    return -1;
	  wpattern = (wchar_t *) __alloca ((n + 1) * sizeof (wchar_t));
	  assert (mbsinit (&ps));
	  (void) mbsrtowcs (wpattern, &pattern, n + 1, &ps);
	}

      assert (mbsinit (&ps));
#ifdef _LIBC
      n = strnlen (string, 1024);
#else
      n = strlen (string);
#endif
      p = string;
      if (__builtin_expect (n < 1024, 1))
	{
	  wstring = (wchar_t *) __alloca ((n + 1) * sizeof (wchar_t));
	  n = mbsrtowcs (wstring, &p, n + 1, &ps);
	  if (__builtin_expect (n == (size_t) -1, 0))
	    /* Something wrong.
	       XXX Do we have to set `errno' to something which mbsrtows hasn't
	       already done?  */
	    return -1;
	  if (p)
	    {
	      memset (&ps, '\0', sizeof (ps));
	      goto prepare_wstring;
	    }
	}
      else
	{
	prepare_wstring:
	  n = mbsrtowcs (NULL, &string, 0, &ps);
	  if (__builtin_expect (n == (size_t) -1, 0))
	    /* Something wrong.
	       XXX Do we have to set `errno' to something which mbsrtows hasn't
	       already done?  */
	    return -1;
	  wstring = (wchar_t *) __alloca ((n + 1) * sizeof (wchar_t));
	  assert (mbsinit (&ps));
	  (void) mbsrtowcs (wstring, &string, n + 1, &ps);
	}

      return internal_fnwmatch (wpattern, wstring, wstring + n,
				flags & PR_FNM_PERIOD, flags, NULL);
    }
# endif  /* mbstate_t and mbsrtowcs or _LIBC.  */

  return internal_fnmatch (pattern, string, string + strlen (string),
			   flags & PR_FNM_PERIOD, flags, NULL);
}

#endif	/* _LIBC or not __GNU_LIBRARY__.  */
