/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "lf_functions.h"


/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description */

static void *
dbmdb_open(uschar *filename, uschar **errmsg)
{
uschar * dirname = string_copy(filename);
uschar * s;
EXIM_DB *yield = NULL;

if ((s = Ustrrchr(dirname, '/'))) *s = '\0';
EXIM_DBOPEN(filename, dirname, O_RDONLY, 0, &yield);
if (yield == NULL)
  {
  int save_errno = errno;
  *errmsg = string_open_failed(errno, "%s as a %s file", filename, EXIM_DBTYPE);
  errno = save_errno;
  }
return yield;
}



/*************************************************
*             Check entry point                  *
*************************************************/

/* This needs to know more about the underlying files than is good for it!
We need to know what the real file names are in order to check the owners and
modes. If USE_DB is set, we know it is Berkeley DB, which uses an unmodified
file name. If USE_TDB or USE_GDBM is set, we know it is tdb or gdbm, which do
the same. Otherwise, for safety, we have to check for x.db or x.dir and x.pag.
*/

static BOOL
dbmdb_check(void *handle, uschar *filename, int modemask, uid_t *owners,
  gid_t *owngroups, uschar **errmsg)
{
int rc;
handle = handle;    /* Keep picky compilers happy */

#if defined(USE_DB) || defined(USE_TDB) || defined(USE_GDBM)
rc = lf_check_file(-1, filename, S_IFREG, modemask, owners, owngroups,
  "dbm", errmsg);
#else
  {
  uschar filebuffer[256];
  (void)sprintf(CS filebuffer, "%.250s.db", filename);
  rc = lf_check_file(-1, filebuffer, S_IFREG, modemask, owners, owngroups,
    "dbm", errmsg);
  if (rc < 0)        /* stat() failed */
    {
    (void)sprintf(CS filebuffer, "%.250s.dir", filename);
    rc = lf_check_file(-1, filebuffer, S_IFREG, modemask, owners, owngroups,
      "dbm", errmsg);
    if (rc == 0)     /* x.dir was OK */
      {
      (void)sprintf(CS filebuffer, "%.250s.pag", filename);
      rc = lf_check_file(-1, filebuffer, S_IFREG, modemask, owners, owngroups,
        "dbm", errmsg);
      }
    }
  }
#endif

return rc == 0;
}



/*************************************************
*              Find entry point                  *
*************************************************/

/* See local README for interface description. This function adds 1 to
the keylength in order to include the terminating zero. */

static int
dbmdb_find(void *handle, uschar *filename, const uschar *keystring, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
EXIM_DB *d = (EXIM_DB *)handle;
EXIM_DATUM key, data;

filename = filename;    /* Keep picky compilers happy */
errmsg = errmsg;
do_cache = do_cache;

EXIM_DATUM_INIT(key);               /* Some DBM libraries require datums to */
EXIM_DATUM_INIT(data);              /* be cleared before use. */
EXIM_DATUM_DATA(key) = CS keystring;
EXIM_DATUM_SIZE(key) = length + 1;

if (EXIM_DBGET(d, key, data))
  {
  *result = string_copyn(US EXIM_DATUM_DATA(data), EXIM_DATUM_SIZE(data));
  EXIM_DATUM_FREE(data);            /* Some DBM libraries need a free() call */
  return OK;
  }
return FAIL;
}



/*************************************************
*      Find entry point - no zero on key         *
*************************************************/

/* See local README for interface description */

int
static dbmnz_find(void *handle, uschar *filename, const uschar *keystring, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
return dbmdb_find(handle, filename, keystring, length-1, result, errmsg,
  do_cache);
}



/*************************************************
*     Find entry point - zero-joined list key    *
*************************************************/

/*
 * The parameter passed as a key is a list in normal Exim list syntax.
 * The elements of that list are joined together on NUL, with no trailing
 * NUL, to form the key.
 */

static int
dbmjz_find(void *handle, uschar *filename, const uschar *keystring, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
uschar *key_item, *key_buffer, *key_p;
const uschar *key_elems = keystring;
int buflen, bufleft, key_item_len, sep = 0;

/* To a first approximation, the size of the lookup key needs to be about,
or less than, the length of the delimited list passed in + 1. */

buflen = length + 3;
key_buffer = store_get(buflen);

key_buffer[0] = '\0';

key_p = key_buffer;
bufleft = buflen;

/* In all cases of an empty list item, we can set 1 and advance by 1 and then
pick up the trailing NUL from the previous list item, EXCEPT when at the
beginning of the output string, in which case we need to supply that NUL
ourselves.  */
while ((key_item = string_nextinlist(&key_elems, &sep, key_p, bufleft)) != NULL)
  {
  key_item_len = Ustrlen(key_item) + 1;
  if (key_item_len == 1)
    {
    key_p[0] = '\0';
    if (key_p == key_buffer)
      {
      key_p[1] = '\0';
      key_item_len += 1;
      }
    }

  bufleft -= key_item_len;
  if (bufleft <= 0)
    {
    /* The string_nextinlist() will stop at buffer size, but we should always
    have at least 1 character extra, so some assumption has failed. */
    *errmsg = string_copy(US"Ran out of buffer space for joining elements");
    return DEFER;
    }
  key_p += key_item_len;
  }

if (key_p == key_buffer)
  {
  *errmsg = string_copy(US"empty list key");
  return FAIL;
  }

/* We do not pass in the final NULL; if needed, the list should include an
empty element to put one in. Boundary: key length 1, is a NULL */
key_item_len = key_p - key_buffer - 1;

DEBUG(D_lookup) debug_printf("NUL-joined key length: %d\n", key_item_len);

/* beware that dbmdb_find() adds 1 to length to get back terminating NUL, so
because we've calculated the real length, we need to subtract one more here */
return dbmdb_find(handle, filename,
    key_buffer, key_item_len - 1,
    result, errmsg, do_cache);
}



/*************************************************
*              Close entry point                 *
*************************************************/

/* See local README for interface description */

void
static dbmdb_close(void *handle)
{
EXIM_DBCLOSE((EXIM_DB *)handle);
}



/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
dbm_version_report(FILE *f)
{
#ifdef DYNLOOKUP
fprintf(f, "Library version: DBM: Exim version %s\n", EXIM_VERSION_STR);
#endif
}


lookup_info dbm_lookup_info = {
  US"dbm",                       /* lookup name */
  lookup_absfile,                /* uses absolute file name */
  dbmdb_open,                    /* open function */
  dbmdb_check,                   /* check function */
  dbmdb_find,                    /* find function */
  dbmdb_close,                   /* close function */
  NULL,                          /* no tidy function */
  NULL,                          /* no quoting function */
  dbm_version_report             /* version reporting */
};

lookup_info dbmz_lookup_info = {
  US"dbmnz",                     /* lookup name */
  lookup_absfile,                /* uses absolute file name */
  dbmdb_open,      /* sic */     /* open function */
  dbmdb_check,     /* sic */     /* check function */
  dbmnz_find,                    /* find function */
  dbmdb_close,     /* sic */     /* close function */
  NULL,                          /* no tidy function */
  NULL,                          /* no quoting function */
  NULL                           /* no version reporting (redundant) */
};

lookup_info dbmjz_lookup_info = {
  US"dbmjz",                     /* lookup name */
  lookup_absfile,                /* uses absolute file name */
  dbmdb_open,      /* sic */     /* open function */
  dbmdb_check,     /* sic */     /* check function */
  dbmjz_find,                    /* find function */
  dbmdb_close,     /* sic */     /* close function */
  NULL,                          /* no tidy function */
  NULL,                          /* no quoting function */
  NULL                           /* no version reporting (redundant) */
};

#ifdef DYNLOOKUP
#define dbmdb_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &dbm_lookup_info, &dbmz_lookup_info, &dbmjz_lookup_info };
lookup_module_info dbmdb_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 3 };

/* End of lookups/dbmdb.c */
