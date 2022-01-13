/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* This header file contains macro definitions so that a variety of DBM
libraries can be used by Exim. Nigel Metheringham provided the original set for
Berkeley DB 1.x in native mode and ndbm. Subsequently, versions for Berkeley DB
2.x and 3.x were added. Later still, support for tdb was added, courtesy of
James Antill. Most recently, support for native mode gdbm was added, with code
from Pierre A. Humblet, so Exim could be made to work with Cygwin.

For convenience, the definitions of the structures used in the various hints
databases are also kept in this file, which is used by the maintenance
utilities as well as the main Exim binary. */


# ifdef USE_TDB

/* ************************* tdb interface ************************ */

#include <tdb.h>

/* Basic DB type */
#define EXIM_DB TDB_CONTEXT

/* Cursor type: tdb uses the previous "key" in _nextkey() (really it wants
tdb_traverse to be called) */
#define EXIM_CURSOR TDB_DATA

/* The datum type used for queries */
#define EXIM_DATUM TDB_DATA

/* Some text for messages */
#define EXIM_DBTYPE "tdb"

/* Access functions */

/* EXIM_DBOPEN - sets *dbpp to point to an EXIM_DB, NULL if failed */
#define EXIM_DBOPEN__(name, dirname, flags, mode, dbpp) \
       *(dbpp) = tdb_open(CS name, 0, TDB_DEFAULT, flags, mode)

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
#define EXIM_DBGET(db, key, data)      \
       (data = tdb_fetch(db, key), data.dptr != NULL)

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
#define EXIM_DBPUT(db, key, data)      \
       tdb_store(db, key, data, TDB_REPLACE)

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */
#define EXIM_DBPUTB(db, key, data)      \
       tdb_store(db, key, data, TDB_INSERT)

/* Returns from EXIM_DBPUTB */

#define EXIM_DBPUTB_OK  0
#define EXIM_DBPUTB_DUP (-1)

/* EXIM_DBDEL */
#define EXIM_DBDEL(db, key) tdb_delete(db, key)

/* EXIM_DBCREATE_CURSOR - initialize for scanning operation */
#define EXIM_DBCREATE_CURSOR(db, cursor) { \
   *(cursor) = store_malloc(sizeof(TDB_DATA)); (*(cursor))->dptr = NULL; }

/* EXIM_DBSCAN - This is complicated because we have to free the last datum
free() must not die when passed NULL */
#define EXIM_DBSCAN(db, key, data, first, cursor)      \
       (key = (first ? tdb_firstkey(db) : tdb_nextkey(db, *(cursor))), \
        free((cursor)->dptr), *(cursor) = key, \
        key.dptr != NULL)

/* EXIM_DBDELETE_CURSOR - terminate scanning operation. */
#define EXIM_DBDELETE_CURSOR(cursor) free(cursor)

/* EXIM_DBCLOSE */
#define EXIM_DBCLOSE__(db)        tdb_close(db)

/* Datum access types - these are intended to be assignable */

#define EXIM_DATUM_SIZE(datum)  (datum).dsize
#define EXIM_DATUM_DATA(datum)  (datum).dptr

/* Free the stuff inside the datum. */

#define EXIM_DATUM_FREE(datum)  (free((datum).dptr), (datum).dptr = NULL)

/* No initialization is needed. */

#define EXIM_DATUM_INIT(datum)



/********************* Berkeley db native definitions **********************/

#elif defined USE_DB

#include <db.h>


/* We can distinguish between versions 1.x and 2.x/3.x by looking for a
definition of DB_VERSION_STRING, which is present in versions 2.x onwards. */

#ifdef DB_VERSION_STRING

# if DB_VERSION_MAJOR >= 6
#  error Version 6 and later BDB API is not supported
# endif

/* The API changed (again!) between the 2.x and 3.x versions */

#if DB_VERSION_MAJOR >= 3

/***************** Berkeley db 3.x/4.x native definitions ******************/

/* Basic DB type */
# if DB_VERSION_MAJOR > 4 || (DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 1)
#  define EXIM_DB       DB_ENV
/* Cursor type, for scanning */
#  define EXIM_CURSOR   DBC

/* The datum type used for queries */
#  define EXIM_DATUM    DBT

/* Some text for messages */
#  define EXIM_DBTYPE   "db (v4.1+)"

/* Only more-recent versions.  5+ ? */
#  ifndef DB_FORCESYNC
#   define DB_FORCESYNC 0
#  endif


/* Access functions */

/* EXIM_DBOPEN - sets *dbpp to point to an EXIM_DB, NULL if failed. The
API changed for DB 4.1. - and we also starting using the "env" with a
specified working dir, to avoid the DBCONFIG file trap. */

#  define ENV_TO_DB(env) ((DB *)((env)->app_private))

#  define EXIM_DBOPEN__(name, dirname, flags, mode, dbpp) \
  if (  db_env_create(dbpp, 0) != 0						\
     || ((*dbpp)->set_errcall(*dbpp, dbfn_bdb_error_callback), 0)		\
     || (*dbpp)->open(*dbpp, CS dirname, DB_CREATE|DB_INIT_MPOOL|DB_PRIVATE, 0) != 0\
     )										\
    *dbpp = NULL;					\
  else if (db_create((DB **) &((*dbpp)->app_private), *dbpp, 0) != 0)		\
    {							\
    ((DB_ENV *)(*dbpp))->close((DB_ENV *)(*dbpp), 0);	\
    *dbpp = NULL;					\
    }							\
  else if (ENV_TO_DB(*dbpp)->open(ENV_TO_DB(*dbpp), NULL, CS name, NULL,	\
	      (flags) == O_RDONLY ? DB_UNKNOWN : DB_HASH,			\
	      (flags) == O_RDONLY ? DB_RDONLY : DB_CREATE,			\
	      mode) != 0							\
	  )									\
    {							\
    ENV_TO_DB(*dbpp)->close(ENV_TO_DB(*dbpp), 0);	\
    ((DB_ENV *)(*dbpp))->close((DB_ENV *)(*dbpp), 0);	\
    *dbpp = NULL;					\
    }

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
#  define EXIM_DBGET(db, key, data)      \
       (ENV_TO_DB(db)->get(ENV_TO_DB(db), NULL, &key, &data, 0) == 0)

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
#  define EXIM_DBPUT(db, key, data)      \
       ENV_TO_DB(db)->put(ENV_TO_DB(db), NULL, &key, &data, 0)

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */
#  define EXIM_DBPUTB(db, key, data)      \
       ENV_TO_DB(db)->put(ENV_TO_DB(db), NULL, &key, &data, DB_NOOVERWRITE)

/* Return values from EXIM_DBPUTB */

#  define EXIM_DBPUTB_OK  0
#  define EXIM_DBPUTB_DUP DB_KEYEXIST

/* EXIM_DBDEL */
#  define EXIM_DBDEL(db, key)     ENV_TO_DB(db)->del(ENV_TO_DB(db), NULL, &key, 0)

/* EXIM_DBCREATE_CURSOR - initialize for scanning operation */

#  define EXIM_DBCREATE_CURSOR(db, cursor) \
       ENV_TO_DB(db)->cursor(ENV_TO_DB(db), NULL, cursor, 0)

/* EXIM_DBSCAN - returns TRUE if data is returned, FALSE at end */
#  define EXIM_DBSCAN(db, key, data, first, cursor)      \
       ((cursor)->c_get(cursor, &key, &data,         \
         (first? DB_FIRST : DB_NEXT)) == 0)

/* EXIM_DBDELETE_CURSOR - terminate scanning operation */
#  define EXIM_DBDELETE_CURSOR(cursor) \
       (cursor)->c_close(cursor)

/* EXIM_DBCLOSE */
#  define EXIM_DBCLOSE__(db) \
	(ENV_TO_DB(db)->close(ENV_TO_DB(db), 0) , ((DB_ENV *)(db))->close((DB_ENV *)(db), DB_FORCESYNC))

/* Datum access types - these are intended to be assignable. */

#  define EXIM_DATUM_SIZE(datum)  (datum).size
#  define EXIM_DATUM_DATA(datum)  (datum).data

/* The whole datum structure contains other fields that must be cleared
before use, but we don't have to free anything after reading data. */

#  define EXIM_DATUM_INIT(datum)   memset(&datum, 0, sizeof(datum))
#  define EXIM_DATUM_FREE(datum)

# else	/* pre- 4.1 */

#  define EXIM_DB       DB

/* Cursor type, for scanning */
#  define EXIM_CURSOR   DBC

/* The datum type used for queries */
#  define EXIM_DATUM    DBT

/* Some text for messages */
#  define EXIM_DBTYPE   "db (v3/4)"

/* Access functions */

/* EXIM_DBOPEN - sets *dbpp to point to an EXIM_DB, NULL if failed. */

#  define EXIM_DBOPEN__(name, dirname, flags, mode, dbpp) \
       if (db_create(dbpp, NULL, 0) != 0 || \
         ((*dbpp)->set_errcall(*dbpp, dbfn_bdb_error_callback), \
         ((*dbpp)->open)(*dbpp, CS name, NULL, \
         ((flags) == O_RDONLY)? DB_UNKNOWN : DB_HASH, \
         ((flags) == O_RDONLY)? DB_RDONLY : DB_CREATE, \
         mode)) != 0) *(dbpp) = NULL

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
#  define EXIM_DBGET(db, key, data)      \
       ((db)->get(db, NULL, &key, &data, 0) == 0)

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
#  define EXIM_DBPUT(db, key, data)      \
       (db)->put(db, NULL, &key, &data, 0)

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */
#  define EXIM_DBPUTB(db, key, data)      \
       (db)->put(db, NULL, &key, &data, DB_NOOVERWRITE)

/* Return values from EXIM_DBPUTB */

#  define EXIM_DBPUTB_OK  0
#  define EXIM_DBPUTB_DUP DB_KEYEXIST

/* EXIM_DBDEL */
#  define EXIM_DBDEL(db, key)     (db)->del(db, NULL, &key, 0)

/* EXIM_DBCREATE_CURSOR - initialize for scanning operation */

#  define EXIM_DBCREATE_CURSOR(db, cursor) \
       (db)->cursor(db, NULL, cursor, 0)

/* EXIM_DBSCAN - returns TRUE if data is returned, FALSE at end */
#  define EXIM_DBSCAN(db, key, data, first, cursor)      \
       ((cursor)->c_get(cursor, &key, &data,         \
         (first? DB_FIRST : DB_NEXT)) == 0)

/* EXIM_DBDELETE_CURSOR - terminate scanning operation */
#  define EXIM_DBDELETE_CURSOR(cursor) \
       (cursor)->c_close(cursor)

/* EXIM_DBCLOSE */
#  define EXIM_DBCLOSE__(db)        (db)->close(db, 0)

/* Datum access types - these are intended to be assignable. */

#  define EXIM_DATUM_SIZE(datum)  (datum).size
#  define EXIM_DATUM_DATA(datum)  (datum).data

/* The whole datum structure contains other fields that must be cleared
before use, but we don't have to free anything after reading data. */

#  define EXIM_DATUM_INIT(datum)   memset(&datum, 0, sizeof(datum))
#  define EXIM_DATUM_FREE(datum)

# endif


#else /* DB_VERSION_MAJOR >= 3 */

/******************* Berkeley db 2.x native definitions ********************/

/* Basic DB type */
#define EXIM_DB       DB

/* Cursor type, for scanning */
#define EXIM_CURSOR   DBC

/* The datum type used for queries */
#define EXIM_DATUM    DBT

/* Some text for messages */
#define EXIM_DBTYPE   "db (v2)"

/* Access functions */

/* EXIM_DBOPEN - sets *dbpp to point to an EXIM_DB, NULL if failed */
#define EXIM_DBOPEN__(name, dirname, flags, mode, dbpp)         \
       if ((errno = db_open(CS name, DB_HASH,           \
         ((flags) == O_RDONLY)? DB_RDONLY : DB_CREATE, \
         mode, NULL, NULL, dbpp)) != 0) *(dbpp) = NULL

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
#define EXIM_DBGET(db, key, data)      \
       ((db)->get(db, NULL, &key, &data, 0) == 0)

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
#define EXIM_DBPUT(db, key, data)      \
       (db)->put(db, NULL, &key, &data, 0)

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */
#define EXIM_DBPUTB(db, key, data)      \
       (db)->put(db, NULL, &key, &data, DB_NOOVERWRITE)

/* Return values from EXIM_DBPUTB */

#define EXIM_DBPUTB_OK  0
#define EXIM_DBPUTB_DUP DB_KEYEXIST

/* EXIM_DBDEL */
#define EXIM_DBDEL(db, key)     (db)->del(db, NULL, &key, 0)

/* EXIM_DBCREATE_CURSOR - initialize for scanning operation */

/* The API of this function was changed between releases 2.4.14 and 2.7.3. I do
not know exactly where the change happened, but the Change Log for 2.5.9 lists
the new option that is available, so I guess that it happened at 2.5.x. */

#if DB_VERSION_MINOR >= 5
#define EXIM_DBCREATE_CURSOR(db, cursor) \
       (db)->cursor(db, NULL, cursor, 0)
#else
#define EXIM_DBCREATE_CURSOR(db, cursor) \
       (db)->cursor(db, NULL, cursor)
#endif

/* EXIM_DBSCAN - returns TRUE if data is returned, FALSE at end */
#define EXIM_DBSCAN(db, key, data, first, cursor)      \
       ((cursor)->c_get(cursor, &key, &data,         \
         (first? DB_FIRST : DB_NEXT)) == 0)

/* EXIM_DBDELETE_CURSOR - terminate scanning operation */
#define EXIM_DBDELETE_CURSOR(cursor) \
       (cursor)->c_close(cursor)

/* EXIM_DBCLOSE */
#define EXIM_DBCLOSE__(db)        (db)->close(db, 0)

/* Datum access types - these are intended to be assignable. */

#define EXIM_DATUM_SIZE(datum)  (datum).size
#define EXIM_DATUM_DATA(datum)  (datum).data

/* The whole datum structure contains other fields that must be cleared
before use, but we don't have to free anything after reading data. */

#define EXIM_DATUM_INIT(datum)   memset(&datum, 0, sizeof(datum))
#define EXIM_DATUM_FREE(datum)

#endif /* DB_VERSION_MAJOR >= 3 */


/* If DB_VERSION_TYPE is not defined, we have version 1.x */

#else  /* DB_VERSION_TYPE */

/******************* Berkeley db 1.x native definitions ********************/

/* Basic DB type */
#define EXIM_DB       DB

/* Cursor type, not used with DB 1.x: just set up a dummy */
#define EXIM_CURSOR   int

/* The datum type used for queries */
#define EXIM_DATUM    DBT

/* Some text for messages */
#define EXIM_DBTYPE   "db (v1)"

/* When scanning, for the non-first case we historically just passed 0
as the flags field and it worked.  On FreeBSD 8 it no longer works and
instead leads to memory exhaustion.  The man-page on FreeBSD says to use
R_NEXT, but this 1.x is a historical fallback and I've no idea how portable
the use of that flag is; so the solution is to define R_NEXT here if it's not
already defined, with a default value of 0 because that's what we've always
before been able to pass successfully. */
#ifndef R_NEXT
#define R_NEXT 0
#endif

/* Access functions */

/* EXIM_DBOPEN - sets *dbpp to point to an EXIM_DB, NULL if failed */
#define EXIM_DBOPEN__(name, dirname, flags, mode, dbpp) \
       *(dbpp) = dbopen(CS name, flags, mode, DB_HASH, NULL)

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
#define EXIM_DBGET(db, key, data)      \
       ((db)->get(db, &key, &data, 0) == 0)

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
#define EXIM_DBPUT(db, key, data)      \
       (db)->put(db, &key, &data, 0)

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */
#define EXIM_DBPUTB(db, key, data)      \
       (db)->put(db, &key, &data, R_NOOVERWRITE)

/* Returns from EXIM_DBPUTB */

#define EXIM_DBPUTB_OK  0
#define EXIM_DBPUTB_DUP 1

/* EXIM_DBDEL */
#define EXIM_DBDEL(db, key)     (db)->del(db, &key, 0)

/* EXIM_DBCREATE_CURSOR - initialize for scanning operation (null) */
#define EXIM_DBCREATE_CURSOR(db, cursor) {}

/* EXIM_DBSCAN - returns TRUE if data is returned, FALSE at end */
#define EXIM_DBSCAN(db, key, data, first, cursor)      \
       ((db)->seq(db, &key, &data, (first? R_FIRST : R_NEXT)) == 0)

/* EXIM_DBDELETE_CURSOR - terminate scanning operation (null). Make it
refer to cursor, to keep picky compilers happy. */
#define EXIM_DBDELETE_CURSOR(cursor) { cursor = cursor; }

/* EXIM_DBCLOSE */
#define EXIM_DBCLOSE__(db)        (db)->close(db)

/* Datum access types - these are intended to be assignable */

#define EXIM_DATUM_SIZE(datum)  (datum).size
#define EXIM_DATUM_DATA(datum)  (datum).data

/* There's no clearing required before use, and we don't have to free anything
after reading data. */

#define EXIM_DATUM_INIT(datum)
#define EXIM_DATUM_FREE(datum)

#endif /* DB_VERSION_STRING */



/********************* gdbm interface definitions **********************/

#elif defined USE_GDBM

#include <gdbm.h>

/* Basic DB type */
typedef struct {
       GDBM_FILE gdbm;  /* Database */
       datum lkey;      /* Last key, for scans */
} EXIM_DB;

/* Cursor type, not used with gdbm: just set up a dummy */
#define EXIM_CURSOR int

/* The datum type used for queries */
#define EXIM_DATUM datum

/* Some text for messages */

#define EXIM_DBTYPE "gdbm"

/* Access functions */

/* EXIM_DBOPEN - returns a EXIM_DB *, NULL if failed */
#define EXIM_DBOPEN__(name, dirname, flags, mode, dbpp) \
     { (*(dbpp)) = (EXIM_DB *) malloc(sizeof(EXIM_DB));\
       if (*(dbpp) != NULL) { \
         (*(dbpp))->lkey.dptr = NULL;\
         (*(dbpp))->gdbm = gdbm_open(CS name, 0, (((flags) & O_CREAT))?GDBM_WRCREAT:(((flags) & (O_RDWR|O_WRONLY))?GDBM_WRITER:GDBM_READER), mode, 0);\
          if ((*(dbpp))->gdbm == NULL) {\
              free(*(dbpp));\
              *(dbpp) = NULL;\
          }\
       }\
     }

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
#define EXIM_DBGET(db, key, data)      \
       (data = gdbm_fetch(db->gdbm, key), data.dptr != NULL)

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
#define EXIM_DBPUT(db, key, data)      \
       gdbm_store(db->gdbm, key, data, GDBM_REPLACE)

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */
#define EXIM_DBPUTB(db, key, data)      \
       gdbm_store(db->gdbm, key, data, GDBM_INSERT)

/* Returns from EXIM_DBPUTB */

#define EXIM_DBPUTB_OK  0
#define EXIM_DBPUTB_DUP 1

/* EXIM_DBDEL */
#define EXIM_DBDEL(db, key) gdbm_delete(db->gdbm, key)

/* EXIM_DBCREATE_CURSOR - initialize for scanning operation (null) */
#define EXIM_DBCREATE_CURSOR(db, cursor) {}

/* EXIM_DBSCAN */
#define EXIM_DBSCAN(db, key, data, first, cursor)      \
  ( key = ((first)? gdbm_firstkey(db->gdbm) : gdbm_nextkey(db->gdbm, db->lkey)), \
    (((db)->lkey.dptr != NULL)? (free((db)->lkey.dptr),1) : 1),\
    db->lkey = key, key.dptr != NULL)

/* EXIM_DBDELETE_CURSOR - terminate scanning operation (null). Make it
refer to cursor, to keep picky compilers happy. */
#define EXIM_DBDELETE_CURSOR(cursor) { cursor = cursor; }

/* EXIM_DBCLOSE */
#define EXIM_DBCLOSE__(db) \
{ gdbm_close((db)->gdbm);\
  if ((db)->lkey.dptr != NULL) free((db)->lkey.dptr);\
  free(db); }

/* Datum access types - these are intended to be assignable */

#define EXIM_DATUM_SIZE(datum) (datum).dsize
#define EXIM_DATUM_DATA(datum) (datum).dptr

/* There's no clearing required before use, but we have to free the dptr
after reading data. */

#define EXIM_DATUM_INIT(datum)
#define EXIM_DATUM_FREE(datum) free(datum.dptr)

#else  /* USE_GDBM */


/* If none of USE_DB, USG_GDBM, or USE_TDB are set, the default is the NDBM
interface */


/********************* ndbm interface definitions **********************/

#include <ndbm.h>

/* Basic DB type */
#define EXIM_DB DBM

/* Cursor type, not used with ndbm: just set up a dummy */
#define EXIM_CURSOR int

/* The datum type used for queries */
#define EXIM_DATUM datum

/* Some text for messages */

#define EXIM_DBTYPE "ndbm"

/* Access functions */

/* EXIM_DBOPEN - returns a EXIM_DB *, NULL if failed */
#define EXIM_DBOPEN__(name, dirname, flags, mode, dbpp) \
       *(dbpp) = dbm_open(CS name, flags, mode)

/* EXIM_DBGET - returns TRUE if successful, FALSE otherwise */
#define EXIM_DBGET(db, key, data)      \
       (data = dbm_fetch(db, key), data.dptr != NULL)

/* EXIM_DBPUT - returns nothing useful, assumes replace mode */
#define EXIM_DBPUT(db, key, data)      \
       dbm_store(db, key, data, DBM_REPLACE)

/* EXIM_DBPUTB - non-overwriting for use by dbmbuild */
#define EXIM_DBPUTB(db, key, data)      \
       dbm_store(db, key, data, DBM_INSERT)

/* Returns from EXIM_DBPUTB */

#define EXIM_DBPUTB_OK  0
#define EXIM_DBPUTB_DUP 1

/* EXIM_DBDEL */
#define EXIM_DBDEL(db, key) dbm_delete(db, key)

/* EXIM_DBCREATE_CURSOR - initialize for scanning operation (null) */
#define EXIM_DBCREATE_CURSOR(db, cursor) {}

/* EXIM_DBSCAN */
#define EXIM_DBSCAN(db, key, data, first, cursor)      \
       (key = (first? dbm_firstkey(db) : dbm_nextkey(db)), key.dptr != NULL)

/* EXIM_DBDELETE_CURSOR - terminate scanning operation (null). Make it
refer to cursor, to keep picky compilers happy. */
#define EXIM_DBDELETE_CURSOR(cursor) { cursor = cursor; }

/* EXIM_DBCLOSE */
#define EXIM_DBCLOSE__(db) dbm_close(db)

/* Datum access types - these are intended to be assignable */

#define EXIM_DATUM_SIZE(datum) (datum).dsize
#define EXIM_DATUM_DATA(datum) (datum).dptr

/* There's no clearing required before use, and we don't have to free anything
after reading data. */

#define EXIM_DATUM_INIT(datum)
#define EXIM_DATUM_FREE(datum)

#endif /* USE_GDBM */





# ifdef COMPILE_UTILITY

#  define EXIM_DBOPEN(name, dirname, flags, mode, dbpp) \
  EXIM_DBOPEN__(name, dirname, flags, mode, dbpp)
#  define EXIM_DBCLOSE(db) EXIM_DBCLOSE__(db)

# else

#  define EXIM_DBOPEN(name, dirname, flags, mode, dbpp) \
  do { \
  DEBUG(D_hints_lookup) \
    debug_printf_indent("EXIM_DBOPEN: file <%s> dir <%s> flags=%s\n", \
      (name), (dirname),		\
      (flags) == O_RDONLY ? "O_RDONLY"	\
      : (flags) == O_RDWR ? "O_RDWR"	\
      : (flags) == (O_RDWR|O_CREAT) ? "O_RDWR|O_CREAT"	\
      : "??");	\
  EXIM_DBOPEN__(name, dirname, flags, mode, dbpp); \
  DEBUG(D_hints_lookup) debug_printf_indent("returned from EXIM_DBOPEN: %p\n", *dbpp); \
  } while(0)
#  define EXIM_DBCLOSE(db) \
  do { \
  DEBUG(D_hints_lookup) debug_printf_indent("EXIM_DBCLOSE(%p)\n", db); \
  EXIM_DBCLOSE__(db); \
  } while(0)

#  endif

/********************* End of dbm library definitions **********************/


/* Structure for carrying around an open DBM file, and an open locking file
that relates to it. */

typedef struct {
  EXIM_DB *dbptr;
  int lockfd;
} open_db;


/* Structures for records stored in exim database dbm files. They all
start with the same fields, described in the generic type. */


typedef struct {
  time_t time_stamp;      /* Timestamp of writing */
} dbdata_generic;


/* This structure keeps track of retry information for a host or a local
address. */

typedef struct {
  time_t time_stamp;
  /*************/
  time_t first_failed;    /* Time of first failure */
  time_t last_try;        /* Time of last try */
  time_t next_try;        /* Time of next try */
  BOOL   expired;         /* Retry time has expired */
  int    basic_errno;     /* Errno of last failure */
  int    more_errno;      /* Additional information */
  uschar text[1];         /* Text message for last failure */
} dbdata_retry;

/* These structures keep track of addresses that have had callout verification
performed on them. There are two groups of records:

1. keyed by localpart@domain -
     Full address was tested and record holds result

2. keyed by domain -
     Domain response upto MAIL FROM:<>, postmaster, random local part;

If a record exists, the result field is either ccache_accept or ccache_reject,
or, for a domain record only, ccache_reject_mfnull when MAIL FROM:<> was
rejected. The other fields, however, (which are only relevant to domain
records) may also contain ccache_unknown if that particular test has not been
done.

Originally, there was only one structure, used for both types. However, it got
expanded for domain records, so it got split. To make it possible for Exim to
handle the old type of record, we retain the old definition. The different
kinds of record can be distinguished by their different lengths. */

typedef struct {
  time_t time_stamp;
  /*************/
  int   result;
  int   postmaster_result; /* Postmaster is accepted */
  int   random_result;     /* Random local part was accepted */
} dbdata_callout_cache_obs;

typedef struct {
  time_t time_stamp;       /* Timestamp of last address check */
  /*************/
  int   result;            /* accept or reject */
} dbdata_callout_cache_address;

/* For this new layout, we put the additional fields (the timestamps)
last so that if somebody reverts to an older Exim, the new records will
still make sense because they match the old layout. */

typedef struct {
  time_t time_stamp;       /* Time stamp of last connection */
  /*************/
  int   result;            /* Domain reject or accept */
  int   postmaster_result; /* Postmaster result */
  int   random_result;     /* Random result */
  time_t postmaster_stamp; /* Timestamp of postmaster check */
  time_t random_stamp;     /* Timestamp of random check */
} dbdata_callout_cache;

/* This structure keeps track of messages that are waiting for a particular
host for a particular transport. */

typedef struct {
  time_t time_stamp;
  /*************/
  int    count;           /* Count of message ids */
  int    sequence;        /* Sequence for continued records */
  uschar text[1];         /* One long character string */
} dbdata_wait;


/* The contents of the "misc" database are a mixture of different kinds of
record, as defined below. The keys used for a specific type all start with a
given string such as "etrn-" or "host-serialize-". */


/* This structure records a connection to a particular host, for the
purpose of serializing access to certain hosts. For possible future extension,
a field is defined for holding the count of connections, but it is not
at present in use. The same structure is used for recording a running ETRN
process. */

typedef struct {
  time_t time_stamp;
  /*************/
  int    count;           /* Reserved for possible connection count */
} dbdata_serialize;


/* This structure records the information required for the ratelimit
ACL condition. */

typedef struct {
  time_t time_stamp;
  /*************/
  int    time_usec;       /* Fractional part of time, from gettimeofday() */
  double rate;            /* Smoothed sending rate at that time */
} dbdata_ratelimit;

/* Same as above, plus a Bloom filter for uniquifying events. */

typedef struct {
  dbdata_ratelimit dbd;
  time_t   bloom_epoch;   /* When the Bloom filter was last reset */
  unsigned bloom_size;    /* Number of bytes in the Bloom filter */
  uschar   bloom[40];     /* Bloom filter which may be larger than this */
} dbdata_ratelimit_unique;

#ifdef EXPERIMENTAL_PIPE_CONNECT
/* This structure records the EHLO responses, cleartext and crypted,
for an IP, as bitmasks (cf. OPTION_TLS) */

typedef struct {
  unsigned short cleartext_features;
  unsigned short crypted_features;
  unsigned short cleartext_auths;
  unsigned short crypted_auths;
} ehlo_resp_precis;

typedef struct {
  time_t time_stamp;
  /*************/
  ehlo_resp_precis data;
} dbdata_ehlo_resp;
#endif


/* End of dbstuff.h */
