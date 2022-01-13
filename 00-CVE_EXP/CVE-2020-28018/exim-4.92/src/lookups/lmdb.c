/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 2016 - 2018*/
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"

#ifdef EXPERIMENTAL_LMDB

#include <lmdb.h>

typedef struct lmdbstrct
{
MDB_txn *txn;
MDB_dbi db_dbi;
} Lmdbstrct;


/*************************************************
*              Open entry point                  *
*************************************************/

static void *
lmdb_open(uschar * filename, uschar ** errmsg)
{
MDB_env * db_env = NULL;
Lmdbstrct * lmdb_p;
int ret, save_errno;
const uschar * errstr;

lmdb_p = store_get(sizeof(Lmdbstrct));
lmdb_p->txn = NULL;

if ((ret = mdb_env_create(&db_env)))
  {
  errstr = US"create environment";
  goto bad;
  }

if ((ret = mdb_env_open(db_env, CS filename, MDB_NOSUBDIR|MDB_RDONLY, 0660)))
  {
  errstr = string_sprintf("open environment with %s", filename);
  goto bad;
  }

if ((ret = mdb_txn_begin(db_env, NULL, MDB_RDONLY, &lmdb_p->txn)))
  {
  errstr = US"start transaction";
  goto bad;
  }

if ((ret = mdb_open(lmdb_p->txn, NULL, 0, &lmdb_p->db_dbi)))
  {
  errstr = US"open database";
  goto bad;
  }

return lmdb_p;

bad:
  save_errno = errno;
  if (lmdb_p->txn) mdb_txn_abort(lmdb_p->txn);
  if (db_env) mdb_env_close(db_env);
  *errmsg = string_sprintf("LMDB: Unable to %s: %s", errstr,  mdb_strerror(ret));
  errno = save_errno;
  return NULL;
}


/*************************************************
*              Find entry point                  *
*************************************************/

static int
lmdb_find(void * handle, uschar * filename,
    const uschar * keystring, int length, uschar ** result, uschar ** errmsg,
    uint * do_cache)
{
int ret;
MDB_val dbkey, data;
Lmdbstrct * lmdb_p = handle;

dbkey.mv_data = CS keystring;
dbkey.mv_size = length;

DEBUG(D_lookup) debug_printf("LMDB: lookup key: %s\n", CS keystring);

if ((ret = mdb_get(lmdb_p->txn, lmdb_p->db_dbi, &dbkey, &data)) == 0)
  {
  *result = string_copyn(US data.mv_data, data.mv_size);
  DEBUG(D_lookup) debug_printf("LMDB: lookup result: %s\n", *result);
  return OK;
  }
else if (ret == MDB_NOTFOUND)
  {
  *errmsg = US"LMDB: lookup, no data found";
  DEBUG(D_lookup) debug_printf("%s\n", *errmsg);
  return FAIL;
  }
else
  {
  *errmsg = string_sprintf("LMDB: lookup error: %s", mdb_strerror(ret));
  DEBUG(D_lookup) debug_printf("%s\n", *errmsg);
  return DEFER;
  }
}


/*************************************************
*              Close entry point                 *
*************************************************/

static void
lmdb_close(void * handle)
{
Lmdbstrct * lmdb_p = handle;
MDB_env * db_env = mdb_txn_env(lmdb_p->txn);
mdb_txn_abort(lmdb_p->txn);
mdb_env_close(db_env);
}


/*************************************************
*         Version reporting entry point          *
*************************************************/

#include "../version.h"

void
lmdb_version_report(FILE * f)
{
fprintf(f, "Library version: LMDB: Compile: %d.%d.%d\n",
    MDB_VERSION_MAJOR, MDB_VERSION_MINOR, MDB_VERSION_PATCH);
#ifdef DYNLOOKUP
fprintf(f, "                        Exim version %s\n", EXIM_VERSION_STR);
#endif
}

static lookup_info lmdb_lookup_info = {
  US"lmdb",                     /* lookup name */
  lookup_absfile,               /* query-style lookup */
  lmdb_open,                    /* open function */
  NULL,                         /* no check function */
  lmdb_find,                    /* find function */
  lmdb_close,                   /* close function */
  NULL,                         /* tidy function */
  NULL,                         /* quoting function */
  lmdb_version_report           /* version reporting */
};

#ifdef DYNLOOKUP
# define lmdb_lookup_module_info _lookup_module_info
#endif /* DYNLOOKUP */

static lookup_info *_lookup_list[] = { &lmdb_lookup_info };
lookup_module_info lmdb_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

#endif /* EXPERIMENTAL_LMDB */
