/*
 * Copyright (c) 2000-2002
 *   Chris Adams <cmadams@iruntheinter.net>
 *   written for HiWAAY Internet Services
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 * USA
 */

/*
 * Adapted for Exim by Tamas TEVESZ <ice@extreme.hu>
 * Further adapted by Philip Hazel to cut out this function for operating
 *   systems that have a built-in version.
 */

/* The OS has a built-in crypt16(). Some compilers don't like compiling empty
modules, so keep them happy with a dummy when skipping the rest. */

#include "config.h"

#ifdef HAVE_CRYPT16
static void dummy(int x) { dummy(x-1); }
#else

/* The OS doesn't have a built-in crypt16(). Compile this one. */

#include <unistd.h>
#include <string.h>
#include "os.h"

#ifdef CRYPT_H
#include <crypt.h>
#endif

char *
crypt16(char *key, char *salt)
{
static char res[25];	/* Not threadsafe; like crypt() */
static char s2[3];
char *p;

/* Clear the string of any previous data */
memset (res, 0, sizeof (res));

/* crypt the first part */
if (!(p = crypt (key, salt))) return NULL;
strncpy (res, p, 13);

if (strlen (key) > 8)
  {
  /* crypt the rest
   * the first two characters of the first block (not counting
   * the salt) make up the new salt */

  strncpy (s2, res+2, 2);
  p = crypt (key+8, s2);
  strncpy (res+13, p+2, 11);
  memset (s2, 0, sizeof(s2));
  }

return (res);
}
#endif

/* End of crypt16.c */
