/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* The idea for this code came from Matthew Byng-Maddick, but his original has
been heavily reworked a lot for Exim 4 (and it now uses stat() (more precisely:
lstat()) rather than a directory scan). */


#include "../exim.h"
#include "lf_functions.h"



/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. We open the directory to test
whether it exists and whether it is searchable. However, we don't need to keep
it open, because the "search" can be done by a call to lstat() rather than
actually scanning through the list of files. */

static void *
dsearch_open(uschar *dirname, uschar **errmsg)
{
DIR *dp = opendir(CS dirname);
if (dp == NULL)
  {
  int save_errno = errno;
  *errmsg = string_open_failed(errno, "%s for directory search", dirname);
  errno = save_errno;
  return NULL;
  }
closedir(dp);
return (void *)(-1);
}


/*************************************************
*             Check entry point                  *
*************************************************/

/* The handle will always be (void *)(-1), but don't try casting it to an
integer as this gives warnings on 64-bit systems. */

BOOL
static dsearch_check(void *handle, uschar *filename, int modemask, uid_t *owners,
  gid_t *owngroups, uschar **errmsg)
{
handle = handle;
return lf_check_file(-1, filename, S_IFDIR, modemask, owners, owngroups,
  "dsearch", errmsg) == 0;
}


/*************************************************
*              Find entry point                  *
*************************************************/

/* See local README for interface description. We use lstat() instead of
scanning the directory, as it is hopefully faster to let the OS do the scanning
for us. */

int
static dsearch_find(void *handle, uschar *dirname, const uschar *keystring, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
struct stat statbuf;
int save_errno;
uschar filename[PATH_MAX];

handle = handle;  /* Keep picky compilers happy */
length = length;
do_cache = do_cache;

if (Ustrchr(keystring, '/') != 0)
  {
  *errmsg = string_sprintf("key for dsearch lookup contains a slash: %s",
    keystring);
  return DEFER;
  }

if (!string_format(filename, sizeof(filename), "%s/%s", dirname, keystring))
  {
  *errmsg = US"path name too long";
  return DEFER;
  }

if (Ulstat(filename, &statbuf) >= 0)
  {
  *result = string_copy(keystring);
  return OK;
  }

if (errno == ENOENT) return FAIL;

save_errno = errno;
*errmsg = string_sprintf("%s: lstat failed", filename);
errno = save_errno;
return DEFER;
}


/*************************************************
*              Close entry point                 *
*************************************************/

/* See local README for interface description */

void
static dsearch_close(void *handle)
{
handle = handle;   /* Avoid compiler warning */
}


/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
dsearch_version_report(FILE *f)
{
#ifdef DYNLOOKUP
fprintf(f, "Library version: dsearch: Exim version %s\n", EXIM_VERSION_STR);
#endif
}


static lookup_info _lookup_info = {
  US"dsearch",                   /* lookup name */
  lookup_absfile,                /* uses absolute file name */
  dsearch_open,                  /* open function */
  dsearch_check,                 /* check function */
  dsearch_find,                  /* find function */
  dsearch_close,                 /* close function */
  NULL,                          /* no tidy function */
  NULL,                          /* no quoting function */
  dsearch_version_report         /* version reporting */
};

#ifdef DYNLOOKUP
#define dsearch_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info dsearch_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/dsearch.c */
