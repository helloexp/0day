/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* This code originally came from Robert Wal. */

#include "../exim.h"


#include <whoson.h>        /* Public header */


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

static void *
whoson_open(uschar *filename, uschar **errmsg)
{
filename = filename;   /* Keep picky compilers happy */
errmsg = errmsg;
return (void *)(1);    /* Just return something non-null */
}


/*************************************************
*               Find entry point                 *
*************************************************/

/* See local README for interface description. */

static int
whoson_find(void *handle, uschar *filename, uschar *query, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
uschar buffer[80];
handle = handle;          /* Keep picky compilers happy */
filename = filename;
length = length;
errmsg = errmsg;
do_cache = do_cache;

switch (wso_query(CS query, CS buffer, sizeof(buffer)))
  {
  case 0:
  *result = string_copy(buffer);    /* IP in database; return name of user */
  return OK;

  case +1:
  return FAIL;                      /* IP not in database */

  default:
  *errmsg = string_sprintf("WHOSON: failed to complete: %s", buffer);
  return DEFER;
  }
}



/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
whoson_version_report(FILE *f)
{
fprintf(f, "Library version: Whoson: Runtime: %s\n", wso_version());
#ifdef DYNLOOKUP
fprintf(f, "                         Exim version %s\n", EXIM_VERSION_STR);
#endif
}

static lookup_info _lookup_info = {
  US"whoson",                    /* lookup name */
  lookup_querystyle,             /* query-style lookup */
  whoson_open,                   /* open function */
  NULL,                          /* check function */
  whoson_find,                   /* find function */
  NULL,                          /* no close function */
  NULL,                          /* no tidy function */
  NULL,                          /* no quoting function */
  whoson_version_report          /* version reporting */
};

#ifdef DYNLOOKUP
#define whoson_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info whoson_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/whoson.c */
