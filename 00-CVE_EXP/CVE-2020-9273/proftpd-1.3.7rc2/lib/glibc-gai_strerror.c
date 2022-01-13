/* Copyright (C) 1997,2001,02 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Philip Blundell <pjb27@cam.ac.uk>, 1997.

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

#include <netdb.h>

/* It's possible that <netdb.h> doesn't define EAI_ values. */

#ifndef EAI_BADFLAGS
# define EAI_BADFLAGS     -1    /* Invalid value for `ai_flags' field.  */
#endif

#ifndef EAI_NONAME
# define EAI_NONAME       -2    /* NAME or SERVICE is unknown.  */
#endif

#ifndef EAI_AGAIN
# define EAI_AGAIN        -3    /* Temporary failure in name resolution.  */
#endif

#ifndef EAI_FAIL
# define EAI_FAIL         -4    /* Non-recoverable failure in name res.  */
#endif

#ifndef EAI_NODATA
# define EAI_NODATA       -5    /* No address associated with NAME.  */
#endif

#ifndef EAI_FAMILY
# define EAI_FAMILY       -6    /* `ai_family' not supported.  */
#endif

#ifndef EAI_SOCKTYPE
# define EAI_SOCKTYPE     -7    /* `ai_socktype' not supported.  */
#endif

#ifndef EAI_SERVICE
# define EAI_SERVICE      -8    /* SERVICE not supported for `ai_socktype'.  */
#endif

#ifndef EAI_ADDRFAMILY
# define EAI_ADDRFAMILY   -9    /* Address family for NAME not supported.  */
#endif

#ifndef EAI_MEMORY
# define EAI_MEMORY       -10   /* Memory allocation failure.  */
#endif

#ifndef EAI_SYSTEM
# define EAI_SYSTEM       -11   /* System error returned in `errno'.  */
#endif

/* GNU-specific EAI values. */

#ifndef EAI_INPROGRESS
# define EAI_INPROGRESS  -100  /* Processing request in progress.  */
#endif

#ifndef EAI_CANCELED
# define EAI_CANCELED    -101  /* Request canceled.  */
#endif

#ifndef EAI_NOTCANCELED
# define EAI_NOTCANCELED -102  /* Request not canceled.  */
#endif

#ifndef EAI_ALLDONE
# define EAI_ALLDONE     -103  /* All requests done.  */
#endif

#ifndef EAI_INTR
# define EAI_INTR        -104  /* Interrupted by a signal.  */
#endif

static struct {
  int code;
  const char *msg;

} values[] = {

  { EAI_ADDRFAMILY,	"Address family for hostname not supported" },
  { EAI_AGAIN,		"Temporary failure in name resolution" },
  { EAI_BADFLAGS,	"Bad value for ai_flags" },
  { EAI_FAIL,		"Non-recoverable failure in name resolution" },
  { EAI_FAMILY,		"ai_family not supported" },
  { EAI_MEMORY,		"Memory allocation failure" },
  { EAI_NODATA,		"No address associated with hostname" },
  { EAI_NONAME,		"Name or service not known" },
  { EAI_SERVICE,	"Servname not supported for ai_socktype" },
  { EAI_SOCKTYPE,	"ai_socktype not supported" },
  { EAI_SYSTEM,		"System error" },
  { EAI_INPROGRESS,	"Processing request in progress" },
  { EAI_CANCELED,	"Request canceled" },
  { EAI_NOTCANCELED, 	"Request not canceled" },
  { EAI_ALLDONE,	"All requests done" },
  { EAI_INTR,		"Interrupted by a signal" }
};

const char *pr_gai_strerror(int code) {
  register unsigned int i;
  for (i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
    if (values[i].code == code)
      return values[i].msg;

  return "Unknown error";
}
