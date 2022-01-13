/* Copyright (C) 1991, 1992, 1993 Free Software Foundation, Inc.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with this library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 51 Franklin Street,
Suite 500, Boston, MA 02110-1335, USA.  */

/* Required to tell conf.h not to include the standard ProFTPD
 * header files
 */

#define __PROFTPD_SUPPORT_LIBRARY

#include <conf.h>

#include <libsupp.h>

#undef _LIBC
#undef __GNU_LIBRARY__
#if defined (_LIBC) || !defined (__GNU_LIBRARY__)


#if !defined(__GNU_LIBRARY__) && !defined(STDC_HEADERS)
extern int errno;
#endif

#ifndef HAVE_STRSEP
/* Match STRING against the filename pattern PATTERN, returning zero if
   it matches, nonzero if not.  */
char
*strsep(char **stringp, const char *delim)
{
  char *res;

  if (!stringp || !*stringp || !**stringp)
    return (char*)0;

  res = *stringp;
  while(**stringp && !strchr(delim, **stringp))
    ++(*stringp);

  if (**stringp) {
    **stringp = '\0';
    ++(*stringp);
  }

  return res;
}
#else
void
pr_os_already_has_strsep(void)
{
}
#endif  /* HAVE_STRSEP */

#endif	/* _LIBC or not __GNU_LIBRARY__.  */
