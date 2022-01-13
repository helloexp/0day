/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"



/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description */

static void *
passwd_open(uschar *filename, uschar **errmsg)
{
filename = filename;     /* Keep picky compilers happy */
errmsg = errmsg;
return (void *)(-1);     /* Just return something non-null */
}




/*************************************************
*         Find entry point for passwd           *
*************************************************/

/* See local README for interface description */

static int
passwd_find(void *handle, uschar *filename, const uschar *keystring, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
struct passwd *pw;

handle = handle;         /* Keep picky compilers happy */
filename = filename;
length = length;
errmsg = errmsg;
do_cache = do_cache;

if (!route_finduser(keystring, &pw, NULL)) return FAIL;
*result = string_sprintf("*:%d:%d:%s:%s:%s", (int)pw->pw_uid, (int)pw->pw_gid,
  pw->pw_gecos, pw->pw_dir, pw->pw_shell);
return OK;
}



/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
passwd_version_report(FILE *f)
{
#ifdef DYNLOOKUP
fprintf(f, "Library version: passwd: Exim version %s\n", EXIM_VERSION_STR);
#endif
}

static lookup_info _lookup_info = {
  US"passwd",                    /* lookup name */
  lookup_querystyle,             /* query-style lookup */
  passwd_open,                   /* open function */
  NULL,                          /* no check function */
  passwd_find,                   /* find function */
  NULL,                          /* no close function */
  NULL,                          /* no tidy function */
  NULL,                          /* no quoting function */
  passwd_version_report          /* version reporting */
};

#ifdef DYNLOOKUP
#define passwd_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info passwd_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/passwd.c */
