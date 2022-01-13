/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "lf_functions.h"



/*************************************************
*         Check a file's credentials             *
*************************************************/

/* fstat can normally be expected to work on an open file, but there are some
NFS states where it may not.

Arguments:
  fd         an open file descriptor or -1
  filename   a file name if fd is -1
  s_type     type of file (S_IFREG or S_IFDIR)
  modemask   a mask specifying mode bits that must *not* be set
  owners     NULL or a list of of allowable uids, count in the first item
  owngroups  NULL or a list of allowable gids, count in the first item
  type       name of lookup type for putting in error message
  errmsg     where to put an error message

Returns:     -1 stat() or fstat() failed
              0 OK
             +1 something didn't match

Side effect: sets errno to ERRNO_BADUGID, ERRNO_NOTREGULAR or ERRNO_BADMODE for
             bad uid/gid, not a regular file, or bad mode; otherwise leaves it
             to what fstat set it to.
*/

int
lf_check_file(int fd, uschar *filename, int s_type, int modemask, uid_t *owners,
  gid_t *owngroups, const char *type, uschar **errmsg)
{
int i;
struct stat statbuf;

if ((fd >= 0 && fstat(fd, &statbuf) != 0) ||
    (fd  < 0 && Ustat(filename, &statbuf) != 0))
  {
  int save_errno = errno;
  *errmsg = string_sprintf("%s: stat failed", filename);
  errno = save_errno;
  return -1;
  }

if ((statbuf.st_mode & S_IFMT) != s_type)
  {
  if (s_type == S_IFREG)
    {
    *errmsg = string_sprintf("%s is not a regular file (%s lookup)",
      filename, type);
    errno = ERRNO_NOTREGULAR;
    }
  else
    {
    *errmsg = string_sprintf("%s is not a directory (%s lookup)",
      filename, type);
    errno = ERRNO_NOTDIRECTORY;
    }
  return +1;
  }

if ((statbuf.st_mode & modemask) != 0)
  {
  *errmsg = string_sprintf("%s (%s lookup): file mode %.4o should not contain "
    "%.4o", filename, type,  statbuf.st_mode & 07777,
    statbuf.st_mode & modemask);
  errno = ERRNO_BADMODE;
  return +1;
  }

if (owners != NULL)
  {
  BOOL uid_ok = FALSE;
  for (i = 1; i <= (int)owners[0]; i++)
    if (owners[i] == statbuf.st_uid) { uid_ok = TRUE; break; }
  if (!uid_ok)
    {
    *errmsg = string_sprintf("%s (%s lookup): file has wrong owner", filename,
      type);
    errno = ERRNO_BADUGID;
    return +1;
    }
  }

if (owngroups != NULL)
  {
  BOOL gid_ok = FALSE;
  for (i = 1; i <= (int)owngroups[0]; i++)
    if (owngroups[i] == statbuf.st_gid) { gid_ok = TRUE; break; }
  if (!gid_ok)
    {
    *errmsg = string_sprintf("%s (%s lookup): file has wrong group", filename,
      type);
    errno = ERRNO_BADUGID;
    return +1;
    }
  }

return 0;
}

/* End of lf_check_file.c */
