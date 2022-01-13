/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "lf_functions.h"


/* These are not real lookup functions; they are just a way of testing the
rest of Exim by providing an easy way of specifying particular yields from
the find function. */


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

static void *
testdb_open(uschar *filename, uschar **errmsg)
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
testdb_find(void *handle, uschar *filename, const uschar *query, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
handle = handle;          /* Keep picky compilers happy */
filename = filename;
length = length;

if (Ustrcmp(query, "fail") == 0)
  {
  *errmsg = US"testdb lookup forced FAIL";
  DEBUG(D_lookup) debug_printf("%s\n", *errmsg);
  return FAIL;
  }
if (Ustrcmp(query, "defer") == 0)
  {
  *errmsg = US"testdb lookup forced DEFER";
  DEBUG(D_lookup) debug_printf("%s\n", *errmsg);
  return DEFER;
  }

if (Ustrcmp(query, "nocache") == 0) *do_cache = 0;

*result = string_copy(query);
return OK;
}


/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
testdb_version_report(FILE *f)
{
#ifdef DYNLOOKUP
fprintf(f, "Library version: TestDB: Exim version %s\n", EXIM_VERSION_STR);
#endif
}


static lookup_info _lookup_info = {
  US"testdb",                    /* lookup name */
  lookup_querystyle,             /* query-style lookup */
  testdb_open,                   /* open function */
  NULL,                          /* check function */
  testdb_find,                   /* find function */
  NULL,                          /* no close function */
  NULL,                          /* no tidy function */
  NULL,                          /* no quoting function */
  testdb_version_report          /* version reporting */
};

#ifdef DYNLOOKUP
#define testdb_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info testdb_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/testdb.c */
