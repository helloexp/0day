/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */


/* Functions for reading/writing exim database files */

void     dbfn_close(open_db *);
int      dbfn_delete(open_db *, const uschar *);
open_db *dbfn_open(uschar *, int, open_db *, BOOL);
void    *dbfn_read_with_length(open_db *, const uschar *, int *);
uschar  *dbfn_scan(open_db *, BOOL, EXIM_CURSOR **);
int      dbfn_write(open_db *, const uschar *, void *, int);

/* Macro for the common call to read without wanting to know the length. */

#define  dbfn_read(a, b) dbfn_read_with_length(a, b, NULL)

/* Berkeley DB uses a callback function to pass back error details. Its API
changed at release 4.3. */

#if defined(USE_DB) && defined(DB_VERSION_STRING)
#if DB_VERSION_MAJOR > 4 || (DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 3)
void     dbfn_bdb_error_callback(const DB_ENV *, const char *, const char *);
#else
void     dbfn_bdb_error_callback(const char *, char *);
#endif
#endif

/* End of dbfunctions.h */
