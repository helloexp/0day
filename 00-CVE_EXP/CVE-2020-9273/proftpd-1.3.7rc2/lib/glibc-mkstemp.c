/* Copyright (C) 1991,92,93,94,95,96,97,98,99 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 51 Franklin Street, Suite 500,
   Boston, MA 02110-1335, USA.  */

#define __PROFTPD_SUPPORT_LIBRARY

#include <conf.h>
#include <libsupp.h>

#ifndef HAVE_MKSTEMP

/* These are the characters used in temporary filenames.  */
static const char letters[] =
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* Generate a temporary file name based on TMPL.  TMPL must match the
   rules for mk[s]temp (i.e. end in "XXXXXX").  The name constructed
   does not exist at the time of the call to mkstemp().  TMPL is
   overwritten with the result.  Creates the file and returns a read-write
   fd; the file is mode 0600 modulo umask.

   We use a clever algorithm to get hard-to-predict names. */
int mkstemp (char *tmpl) {
  int len;
  char *XXXXXX;
  static uint64_t value;
  struct timeval tv;
  int count, fd;
  int save_errno = errno;

  len = strlen (tmpl);
  if (len < 6 || strcmp (&tmpl[len - 6], "XXXXXX"))
    {
      errno = EINVAL;
      return -1;
    }

  /* This is where the Xs start.  */
  XXXXXX = &tmpl[len - 6];

  /* Get some more or less random data.  */
  gettimeofday (&tv, NULL);
  value += ((uint64_t) tv.tv_usec << 16) ^ tv.tv_sec ^ getpid ();

  for (count = 0; count < TMP_MAX; value += 7777, ++count)
    {
      uint64_t v = value;

      /* Fill in the random bits.  */
      XXXXXX[0] = letters[v % 62];
      v /= 62;
      XXXXXX[1] = letters[v % 62];
      v /= 62;
      XXXXXX[2] = letters[v % 62];
      v /= 62;
      XXXXXX[3] = letters[v % 62];
      v /= 62;
      XXXXXX[4] = letters[v % 62];
      v /= 62;
      XXXXXX[5] = letters[v % 62];

/* NOTE: this, or test for _LARGEFILE_SOURCE in order to use the O_LARGEFILE
 *  open flag
 */

#ifdef _LARGEFILE_SOURCE
      fd = open64 (tmpl, O_RDWR | O_CREAT | O_EXCL, 0600);
#else
      fd = open (tmpl, O_RDWR | O_CREAT | O_EXCL, 0600);
#endif
      if (fd >= 0)
	{
          errno = save_errno;
          return fd;
        }
      else if (errno != EEXIST)
        /* Any other error will apply also to other names we might
           try, and there are 2^32 or so of them, so give up now. */
        return -1;
    }

  /* We got out of the loop because we ran out of combinations to try.  */
  errno = EEXIST;
  return -1;
}

#else /* HAVE_MKSTEMP */
void
pr_os_already_has_mkstemp(void)
{
}
#endif /* HAVE_MKSTEMP */
