/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* Copyright (c) The Exim Maintainers 2010 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "exim.h"


/*************************************************
*           Attempt to create a directory        *
*************************************************/

/* All the directories that Exim ever creates for itself are within the spool
directory as defined by spool_directory. We are prepared to create as many as
necessary from that directory downwards, inclusive. However, directory creation
can also be required in appendfile and sieve filters. The making function
therefore has a parent argument, below which the new directories are to go. It
can be NULL if the name is absolute.

If a non-root uid has been specified for exim, and we are currently running as
root, ensure the directory is owned by the non-root id if the parent is the
spool directory.

Arguments:
  parent    parent directory name; if NULL the name must be absolute
  name      directory name within the parent that we want
  mode      mode for the new directory
  panic     if TRUE, panic on failure

Returns:    panic on failure if panic is set; otherwise return FALSE;
            TRUE on success.
*/

BOOL
directory_make(const uschar *parent, const uschar *name,
               int mode, BOOL panic)
{
BOOL use_chown = parent == spool_directory && geteuid() == root_uid;
uschar * p;
uschar c = 1;
struct stat statbuf;
uschar * path;

if (parent)
  {
  path = string_sprintf("%s%s%s", parent, US"/", name);
  p = path + Ustrlen(parent);
  }
else
  {
  path = string_copy(name);
  p = path + 1;
  }

/* Walk the path creating any missing directories */

while (c && *p)
  {
  while (*p && *p != '/') p++;
  c = *p;
  *p = '\0';
  if (Ustat(path, &statbuf) != 0)
    {
    if (mkdir(CS path, mode) < 0 && errno != EEXIST)
      { p = US"create"; goto bad; }

    /* Set the ownership if necessary. */

    if (use_chown && Uchown(path, exim_uid, exim_gid))
      { p = US"set owner on"; goto bad; }

    /* It appears that any mode bits greater than 0777 are ignored by
    mkdir(), at least on some operating systems. Therefore, if the mode
    contains any such bits, do an explicit mode setting. */

    if (mode & 0777000) (void) Uchmod(path, mode);
    }
  *p++ = c;
  }

return TRUE;

bad:
  if (panic) log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "Failed to %s directory \"%s\": %s\n", p, path, strerror(errno));
  return FALSE;
}

/* End of directory.c */
