/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


/* This single source file is used to compile three utility programs for
maintaining Exim hints databases.

  exim_dumpdb     dumps out the contents
  exim_fixdb      patches the database (really for Exim maintenance/testing)
  exim_tidydb     removed obsolete data

In all cases, the first argument is the name of the spool directory. The second
argument is the name of the database file. The available names are:

  retry:      retry delivery information
  misc:       miscellaneous hints data
  wait-<t>:   message waiting information; <t> is a transport name
  callout:    callout verification cache

There are a number of common subroutines, followed by three main programs,
whose inclusion is controlled by -D on the compilation command. */


#include "exim.h"


/* Identifiers for the different database types. */

#define type_retry     1
#define type_wait      2
#define type_misc      3
#define type_callout   4
#define type_ratelimit 5


/* This is used by our cut-down dbfn_open(). */

uschar *spool_directory;



/*************************************************
*         Berkeley DB error callback             *
*************************************************/

/* For Berkeley DB >= 2, we can define a function to be called in case of DB
errors. This should help with debugging strange DB problems, e.g. getting "File
exists" when you try to open a db file. The API changed at release 4.3. */

#if defined(USE_DB) && defined(DB_VERSION_STRING)
void
#if DB_VERSION_MAJOR > 4 || (DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 3)
dbfn_bdb_error_callback(const DB_ENV *dbenv, const char *pfx, const char *msg)
{
dbenv = dbenv;
#else
dbfn_bdb_error_callback(const char *pfx, char *msg)
{
#endif
pfx = pfx;
printf("Berkeley DB error: %s\n", msg);
}
#endif



/*************************************************
*              SIGALRM handler                   *
*************************************************/

SIGNAL_BOOL sigalrm_seen;

void
sigalrm_handler(int sig)
{
sig = sig;            /* Keep picky compilers happy */
sigalrm_seen = 1;
}



/*************************************************
*        Output usage message and exit           *
*************************************************/

static void
usage(uschar *name, uschar *options)
{
printf("Usage: exim_%s%s  <spool-directory> <database-name>\n", name, options);
printf("  <database-name> = retry | misc | wait-<transport-name> | callout | ratelimit\n");
exit(1);
}



/*************************************************
*           Sort out the command arguments       *
*************************************************/

/* This function checks that there are exactly 2 arguments, and checks the
second of them to be sure it is a known database name. */

static int
check_args(int argc, uschar **argv, uschar *name, uschar *options)
{
if (argc == 3)
  {
  if (Ustrcmp(argv[2], "retry") == 0) return type_retry;
  if (Ustrcmp(argv[2], "misc") == 0) return type_misc;
  if (Ustrncmp(argv[2], "wait-", 5) == 0) return type_wait;
  if (Ustrcmp(argv[2], "callout") == 0) return type_callout;
  if (Ustrcmp(argv[2], "ratelimit") == 0) return type_ratelimit;
  }
usage(name, options);
return -1;              /* Never obeyed */
}



/*************************************************
*         Handle attempts to write the log       *
*************************************************/

/* The message gets written to stderr when log_write() is called from a
utility. The message always gets '\n' added on the end of it. These calls come
from modules such as store.c when things go drastically wrong (e.g. malloc()
failing). In normal use they won't get obeyed.

Arguments:
  selector  not relevant when running a utility
  flags     not relevant when running a utility
  format    a printf() format
  ...       arguments for format

Returns:    nothing
*/

void
log_write(unsigned int selector, int flags, const char *format, ...)
{
va_list ap;
va_start(ap, format);
vfprintf(stderr, format, ap);
fprintf(stderr, "\n");
va_end(ap);
selector = selector;     /* Keep picky compilers happy */
flags = flags;
}



/*************************************************
*        Format a time value for printing        *
*************************************************/

static uschar time_buffer[sizeof("09-xxx-1999 hh:mm:ss  ")];

uschar *
print_time(time_t t)
{
struct tm *tmstr = localtime(&t);
Ustrftime(time_buffer, sizeof(time_buffer), "%d-%b-%Y %H:%M:%S", tmstr);
return time_buffer;
}



/*************************************************
*        Format a cache value for printing       *
*************************************************/

uschar *
print_cache(int value)
{
return (value == ccache_accept)? US"accept" :
       (value == ccache_reject)? US"reject" :
       US"unknown";
}


#ifdef EXIM_FIXDB
/*************************************************
*                Read time value                 *
*************************************************/

static time_t
read_time(uschar *s)
{
uschar *t = s;
int field = 0;
int value;
time_t now = time(NULL);
struct tm *tm = localtime(&now);

tm->tm_sec = 0;
tm->tm_isdst = -1;

for (t = s + Ustrlen(s) - 1; t >= s; t--)
  {
  if (*t == ':') continue;
  if (!isdigit((uschar)*t)) return -1;

  value = *t - '0';
  if (--t >= s)
    {
    if (!isdigit((uschar)*t)) return -1;
    value = value + (*t - '0')*10;
    }

  switch (field++)
    {
    case 0: tm->tm_min = value; break;
    case 1: tm->tm_hour = value; break;
    case 2: tm->tm_mday = value; break;
    case 3: tm->tm_mon = value - 1; break;
    case 4: tm->tm_year = (value < 90)? value + 100 : value; break;
    default: return -1;
    }
  }

return mktime(tm);
}
#endif  /* EXIM_FIXDB */



/*************************************************
*       Open and lock a database file            *
*************************************************/

/* This is a cut-down version from the function in dbfn.h that Exim itself
uses. We assume the database exists, and therefore give up if we cannot open
the lock file.

Arguments:
  name     The single-component name of one of Exim's database files.
  flags    O_RDONLY or O_RDWR
  dbblock  Points to an open_db block to be filled in.
  lof      Unused.

Returns:   NULL if the open failed, or the locking failed.
           On success, dbblock is returned. This contains the dbm pointer and
           the fd of the locked lock file.
*/

open_db *
dbfn_open(uschar *name, int flags, open_db *dbblock, BOOL lof)
{
int rc;
struct flock lock_data;
BOOL read_only = flags == O_RDONLY;
uschar * dirname, * filename;

/* The first thing to do is to open a separate file on which to lock. This
ensures that Exim has exclusive use of the database before it even tries to
open it. If there is a database, there should be a lock file in existence. */

#ifdef COMPILE_UTILITY
if (  asprintf(CSS &dirname, "%s/db", spool_directory) < 0
   || asprintf(CSS &filename, "%s/%s.lockfile", dirname, name) < 0)
  return NULL;
#else
dirname = string_sprintf("%s/db", spool_directory);
filename = string_sprintf("%s/%s.lockfile", dirname, name);
#endif

dbblock->lockfd = Uopen(filename, flags, 0);
if (dbblock->lockfd < 0)
  {
  printf("** Failed to open database lock file %s: %s\n", filename,
    strerror(errno));
  return NULL;
  }

/* Now we must get a lock on the opened lock file; do this with a blocking
lock that times out. */

lock_data.l_type = read_only ? F_RDLCK : F_WRLCK;
lock_data.l_whence = lock_data.l_start = lock_data.l_len = 0;

sigalrm_seen = FALSE;
os_non_restarting_signal(SIGALRM, sigalrm_handler);
ALARM(EXIMDB_LOCK_TIMEOUT);
rc = fcntl(dbblock->lockfd, F_SETLKW, &lock_data);
ALARM_CLR(0);

if (sigalrm_seen) errno = ETIMEDOUT;
if (rc < 0)
  {
  printf("** Failed to get %s lock for %s: %s",
    flags & O_WRONLY ? "write" : "read",
    filename,
    errno == ETIMEDOUT ? "timed out" : strerror(errno));
  (void)close(dbblock->lockfd);
  return NULL;
  }

/* At this point we have an opened and locked separate lock file, that is,
exclusive access to the database, so we can go ahead and open it. */

#ifdef COMPILE_UTILITY
if (asprintf(CSS &filename, "%s/%s", dirname, name) < 0) return NULL;
#else
filename = string_sprintf("%s/%s", dirname, name);
#endif
EXIM_DBOPEN(filename, dirname, flags, 0, &(dbblock->dbptr));

if (!dbblock->dbptr)
  {
  printf("** Failed to open DBM file %s for %s:\n   %s%s\n", filename,
    read_only? "reading" : "writing", strerror(errno),
    #ifdef USE_DB
    " (or Berkeley DB error while opening)"
    #else
    ""
    #endif
    );
  (void)close(dbblock->lockfd);
  return NULL;
  }

return dbblock;
}




/*************************************************
*         Unlock and close a database file       *
*************************************************/

/* Closing a file automatically unlocks it, so after closing the database, just
close the lock file.

Argument: a pointer to an open database block
Returns:  nothing
*/

void
dbfn_close(open_db *dbblock)
{
EXIM_DBCLOSE(dbblock->dbptr);
(void)close(dbblock->lockfd);
}




/*************************************************
*             Read from database file            *
*************************************************/

/* Passing back the pointer unchanged is useless, because there is no guarantee
of alignment. Since all the records used by Exim need to be properly aligned to
pick out the timestamps, etc., do the copying centrally here.

Arguments:
  dbblock   a pointer to an open database block
  key       the key of the record to be read
  length    where to put the length (or NULL if length not wanted)

Returns: a pointer to the retrieved record, or
         NULL if the record is not found
*/

void *
dbfn_read_with_length(open_db *dbblock, const uschar *key, int *length)
{
void *yield;
EXIM_DATUM key_datum, result_datum;
int klen = Ustrlen(key) + 1;
uschar * key_copy = store_get(klen);

memcpy(key_copy, key, klen);

EXIM_DATUM_INIT(key_datum);         /* Some DBM libraries require the datum */
EXIM_DATUM_INIT(result_datum);      /* to be cleared before use. */
EXIM_DATUM_DATA(key_datum) = CS key_copy;
EXIM_DATUM_SIZE(key_datum) = klen;

if (!EXIM_DBGET(dbblock->dbptr, key_datum, result_datum)) return NULL;

yield = store_get(EXIM_DATUM_SIZE(result_datum));
memcpy(yield, EXIM_DATUM_DATA(result_datum), EXIM_DATUM_SIZE(result_datum));
if (length != NULL) *length = EXIM_DATUM_SIZE(result_datum);

EXIM_DATUM_FREE(result_datum);    /* Some DBM libs require freeing */
return yield;
}



#if defined(EXIM_TIDYDB) || defined(EXIM_FIXDB)

/*************************************************
*             Write to database file             *
*************************************************/

/*
Arguments:
  dbblock   a pointer to an open database block
  key       the key of the record to be written
  ptr       a pointer to the record to be written
  length    the length of the record to be written

Returns:    the yield of the underlying dbm or db "write" function. If this
            is dbm, the value is zero for OK.
*/

int
dbfn_write(open_db *dbblock, const uschar *key, void *ptr, int length)
{
EXIM_DATUM key_datum, value_datum;
dbdata_generic *gptr = (dbdata_generic *)ptr;
int klen = Ustrlen(key) + 1;
uschar * key_copy = store_get(klen);

memcpy(key_copy, key, klen);
gptr->time_stamp = time(NULL);

EXIM_DATUM_INIT(key_datum);         /* Some DBM libraries require the datum */
EXIM_DATUM_INIT(value_datum);       /* to be cleared before use. */
EXIM_DATUM_DATA(key_datum) = CS key_copy;
EXIM_DATUM_SIZE(key_datum) = klen;
EXIM_DATUM_DATA(value_datum) = CS ptr;
EXIM_DATUM_SIZE(value_datum) = length;
return EXIM_DBPUT(dbblock->dbptr, key_datum, value_datum);
}



/*************************************************
*           Delete record from database file     *
*************************************************/

/*
Arguments:
  dbblock    a pointer to an open database block
  key        the key of the record to be deleted

Returns: the yield of the underlying dbm or db "delete" function.
*/

int
dbfn_delete(open_db *dbblock, const uschar *key)
{
int klen = Ustrlen(key) + 1;
uschar * key_copy = store_get(klen);

memcpy(key_copy, key, klen);
EXIM_DATUM key_datum;
EXIM_DATUM_INIT(key_datum);         /* Some DBM libraries require clearing */
EXIM_DATUM_DATA(key_datum) = CS key_copy;
EXIM_DATUM_SIZE(key_datum) = klen;
return EXIM_DBDEL(dbblock->dbptr, key_datum);
}

#endif  /* EXIM_TIDYDB || EXIM_FIXDB */



#if defined(EXIM_DUMPDB) || defined(EXIM_TIDYDB)
/*************************************************
*         Scan the keys of a database file       *
*************************************************/

/*
Arguments:
  dbblock  a pointer to an open database block
  start    TRUE if starting a new scan
           FALSE if continuing with the current scan
  cursor   a pointer to a pointer to a cursor anchor, for those dbm libraries
           that use the notion of a cursor

Returns:   the next record from the file, or
           NULL if there are no more
*/

uschar *
dbfn_scan(open_db *dbblock, BOOL start, EXIM_CURSOR **cursor)
{
EXIM_DATUM key_datum, value_datum;
uschar *yield;
value_datum = value_datum;    /* dummy; not all db libraries use this */

/* Some dbm require an initialization */

if (start) EXIM_DBCREATE_CURSOR(dbblock->dbptr, cursor);

EXIM_DATUM_INIT(key_datum);         /* Some DBM libraries require the datum */
EXIM_DATUM_INIT(value_datum);       /* to be cleared before use. */

yield = (EXIM_DBSCAN(dbblock->dbptr, key_datum, value_datum, start, *cursor))?
  US EXIM_DATUM_DATA(key_datum) : NULL;

/* Some dbm require a termination */

if (!yield) EXIM_DBDELETE_CURSOR(*cursor);
return yield;
}
#endif  /* EXIM_DUMPDB || EXIM_TIDYDB */



#ifdef EXIM_DUMPDB
/*************************************************
*           The exim_dumpdb main program         *
*************************************************/

int
main(int argc, char **cargv)
{
int dbdata_type = 0;
int yield = 0;
open_db dbblock;
open_db *dbm;
EXIM_CURSOR *cursor;
uschar **argv = USS cargv;
uschar *key;
uschar keybuffer[1024];

/* Check the arguments, and open the database */

dbdata_type = check_args(argc, argv, US"dumpdb", US"");
spool_directory = argv[1];
if (!(dbm = dbfn_open(argv[2], O_RDONLY, &dbblock, FALSE)))
  exit(1);

/* Scan the file, formatting the information for each entry. Note
that data is returned in a malloc'ed block, in order that it be
correctly aligned. */

for (key = dbfn_scan(dbm, TRUE, &cursor);
     key;
     key = dbfn_scan(dbm, FALSE, &cursor))
  {
  dbdata_retry *retry;
  dbdata_wait *wait;
  dbdata_callout_cache *callout;
  dbdata_ratelimit *ratelimit;
  dbdata_ratelimit_unique *rate_unique;
  int count_bad = 0;
  int i, length;
  uschar *t;
  uschar name[MESSAGE_ID_LENGTH + 1];
  void *value;

  /* Keep a copy of the key separate, as in some DBM's the pointer is into data
  which might change. */

  if (Ustrlen(key) > sizeof(keybuffer) - 1)
    {
    printf("**** Overlong key encountered: %s\n", key);
    return 1;
    }
  Ustrcpy(keybuffer, key);

  if (!(value = dbfn_read_with_length(dbm, keybuffer, &length)))
    fprintf(stderr, "**** Entry \"%s\" was in the key scan, but the record "
                    "was not found in the file - something is wrong!\n",
      CS keybuffer);
  else
    {
    /* Note: don't use print_time more than once in one statement, since
    it uses a single buffer. */

    switch(dbdata_type)
      {
      case type_retry:
      retry = (dbdata_retry *)value;
      printf("  %s %d %d %s\n%s  ", keybuffer, retry->basic_errno,
        retry->more_errno, retry->text,
        print_time(retry->first_failed));
      printf("%s  ", print_time(retry->last_try));
      printf("%s %s\n", print_time(retry->next_try),
        (retry->expired)? "*" : "");
      break;

      case type_wait:
      wait = (dbdata_wait *)value;
      printf("%s ", keybuffer);
      t = wait->text;
      name[MESSAGE_ID_LENGTH] = 0;

      if (wait->count > WAIT_NAME_MAX)
        {
        fprintf(stderr,
          "**** Data for %s corrupted\n  count=%d=0x%x max=%d\n",
          CS keybuffer, wait->count, wait->count, WAIT_NAME_MAX);
        wait->count = WAIT_NAME_MAX;
        yield = count_bad = 1;
        }
      for (i = 1; i <= wait->count; i++)
        {
        Ustrncpy(name, t, MESSAGE_ID_LENGTH);
        if (count_bad && name[0] == 0) break;
        if (Ustrlen(name) != MESSAGE_ID_LENGTH ||
            Ustrspn(name, "0123456789"
                          "abcdefghijklmnopqrstuvwxyz"
                          "ABCDEFGHIJKLMNOPQRSTUVWXYZ-") != MESSAGE_ID_LENGTH)
          {
          int j;
          fprintf(stderr,
            "**** Data for %s corrupted: bad character in message id\n",
            CS keybuffer);
          for (j = 0; j < MESSAGE_ID_LENGTH; j++)
            fprintf(stderr, "%02x ", name[j]);
          fprintf(stderr, "\n");
          yield = 1;
          break;
          }
        printf("%s ", name);
        t += MESSAGE_ID_LENGTH;
        }
      printf("\n");
      break;

      case type_misc:
      printf("%s %s\n", print_time(((dbdata_generic *)value)->time_stamp),
        keybuffer);
      break;

      case type_callout:
      callout = (dbdata_callout_cache *)value;

      /* New-style address record */

      if (length == sizeof(dbdata_callout_cache_address))
        {
        printf("%s %s callout=%s\n",
          print_time(((dbdata_generic *)value)->time_stamp),
          keybuffer,
          print_cache(callout->result));
        }

      /* New-style domain record */

      else if (length == sizeof(dbdata_callout_cache))
        {
        printf("%s %s callout=%s postmaster=%s",
          print_time(((dbdata_generic *)value)->time_stamp),
          keybuffer,
          print_cache(callout->result),
          print_cache(callout->postmaster_result));
        if (callout->postmaster_result != ccache_unknown)
          printf(" (%s)", print_time(callout->postmaster_stamp));
        printf(" random=%s", print_cache(callout->random_result));
        if (callout->random_result != ccache_unknown)
          printf(" (%s)", print_time(callout->random_stamp));
        printf("\n");
        }

      break;

      case type_ratelimit:
      if (Ustrstr(key, "/unique/") != NULL && length >= sizeof(*rate_unique))
        {
        ratelimit = (dbdata_ratelimit *)value;
        rate_unique = (dbdata_ratelimit_unique *)value;
        printf("%s.%06d rate: %10.3f epoch: %s size: %u key: %s\n",
          print_time(ratelimit->time_stamp),
          ratelimit->time_usec, ratelimit->rate,
          print_time(rate_unique->bloom_epoch), rate_unique->bloom_size,
          keybuffer);
        }
      else
        {
        ratelimit = (dbdata_ratelimit *)value;
        printf("%s.%06d rate: %10.3f key: %s\n",
          print_time(ratelimit->time_stamp),
          ratelimit->time_usec, ratelimit->rate,
          keybuffer);
        }
      break;
      }
    store_reset(value);
    }
  }

dbfn_close(dbm);
return yield;
}

#endif  /* EXIM_DUMPDB */




#ifdef EXIM_FIXDB
/*************************************************
*           The exim_fixdb main program          *
*************************************************/

/* In order not to hold the database lock any longer than is necessary, each
operation on the database uses a separate open/close call. This is expensive,
but then using this utility is not expected to be very common. Its main use is
to provide a way of patching up hints databases in order to run tests.

Syntax of commands:

(1) <record name>
    This causes the data from the given record to be displayed, or "not found"
    to be output. Note that in the retry database, destination names are
    preceded by R: or T: for router or transport retry info.

(2) <record name> d
    This causes the given record to be deleted or "not found" to be output.

(3) <record name> <field number> <value>
    This sets the given value into the given field, identified by a number
    which is output by the display command. Not all types of record can
    be changed.

(4) q
    This exits from exim_fixdb.

If the record name is omitted from (2) or (3), the previously used record name
is re-used. */


int main(int argc, char **cargv)
{
int dbdata_type;
uschar **argv = USS cargv;
uschar buffer[256];
uschar name[256];
void *reset_point = store_get(0);

name[0] = 0;  /* No name set */

/* Sort out the database type, verify what we are working on and then process
user requests */

dbdata_type = check_args(argc, argv, US"fixdb", US"");
printf("Modifying Exim hints database %s/db/%s\n", argv[1], argv[2]);

for(;;)
  {
  open_db dbblock;
  open_db *dbm;
  void *record;
  dbdata_retry *retry;
  dbdata_wait *wait;
  dbdata_callout_cache *callout;
  dbdata_ratelimit *ratelimit;
  dbdata_ratelimit_unique *rate_unique;
  int i, oldlength;
  uschar *t;
  uschar field[256], value[256];

  store_reset(reset_point);

  printf("> ");
  if (Ufgets(buffer, 256, stdin) == NULL) break;

  buffer[Ustrlen(buffer)-1] = 0;
  field[0] = value[0] = 0;

  /* If the buffer contains just one digit, or just consists of "d", use the
  previous name for an update. */

  if ((isdigit((uschar)buffer[0]) && (buffer[1] == ' ' || buffer[1] == '\0'))
       || Ustrcmp(buffer, "d") == 0)
    {
    if (name[0] == 0)
      {
      printf("No previous record name is set\n");
      continue;
      }
    (void)sscanf(CS buffer, "%s %s", field, value);
    }
  else
    {
    name[0] = 0;
    (void)sscanf(CS buffer, "%s %s %s", name, field, value);
    }

  /* Handle an update request */

  if (field[0] != 0)
    {
    int verify = 1;
    spool_directory = argv[1];

    if (!(dbm = dbfn_open(argv[2], O_RDWR, &dbblock, FALSE)))
      continue;

    if (Ustrcmp(field, "d") == 0)
      {
      if (value[0] != 0) printf("unexpected value after \"d\"\n");
        else printf("%s\n", (dbfn_delete(dbm, name) < 0)?
          "not found" : "deleted");
      dbfn_close(dbm);
      continue;
      }

    else if (isdigit((uschar)field[0]))
      {
      int fieldno = Uatoi(field);
      if (value[0] == 0)
        {
        printf("value missing\n");
        dbfn_close(dbm);
        continue;
        }
      else
        {
        record = dbfn_read_with_length(dbm, name, &oldlength);
        if (record == NULL) printf("not found\n"); else
          {
          time_t tt;
          /*int length = 0;      Stops compiler warning */

          switch(dbdata_type)
            {
            case type_retry:
            retry = (dbdata_retry *)record;
            /* length = sizeof(dbdata_retry) + Ustrlen(retry->text); */

            switch(fieldno)
              {
              case 0:
              retry->basic_errno = Uatoi(value);
              break;

              case 1:
              retry->more_errno = Uatoi(value);
              break;

              case 2:
              if ((tt = read_time(value)) > 0) retry->first_failed = tt;
                else printf("bad time value\n");
              break;

              case 3:
              if ((tt = read_time(value)) > 0) retry->last_try = tt;
                else printf("bad time value\n");
              break;

              case 4:
              if ((tt = read_time(value)) > 0) retry->next_try = tt;
                else printf("bad time value\n");
              break;

              case 5:
              if (Ustrcmp(value, "yes") == 0) retry->expired = TRUE;
              else if (Ustrcmp(value, "no") == 0) retry->expired = FALSE;
              else printf("\"yes\" or \"no\" expected=n");
              break;

              default:
              printf("unknown field number\n");
              verify = 0;
              break;
              }
            break;

            case type_wait:
            printf("Can't change contents of wait database record\n");
            break;

            case type_misc:
            printf("Can't change contents of misc database record\n");
            break;

            case type_callout:
            callout = (dbdata_callout_cache *)record;
            /* length = sizeof(dbdata_callout_cache); */
            switch(fieldno)
              {
              case 0:
              callout->result = Uatoi(value);
              break;

              case 1:
              callout->postmaster_result = Uatoi(value);
              break;

              case 2:
              callout->random_result = Uatoi(value);
              break;

              default:
              printf("unknown field number\n");
              verify = 0;
              break;
              }
            break;

            case type_ratelimit:
            ratelimit = (dbdata_ratelimit *)record;
            switch(fieldno)
              {
              case 0:
              if ((tt = read_time(value)) > 0) ratelimit->time_stamp = tt;
                else printf("bad time value\n");
              break;

              case 1:
              ratelimit->time_usec = Uatoi(value);
              break;

              case 2:
              ratelimit->rate = Ustrtod(value, NULL);
              break;

              case 3:
              if (Ustrstr(name, "/unique/") != NULL
                && oldlength >= sizeof(dbdata_ratelimit_unique))
                {
                rate_unique = (dbdata_ratelimit_unique *)record;
                if ((tt = read_time(value)) > 0) rate_unique->bloom_epoch = tt;
                  else printf("bad time value\n");
                break;
                }
              /* else fall through */

              case 4:
              case 5:
              if (Ustrstr(name, "/unique/") != NULL
                && oldlength >= sizeof(dbdata_ratelimit_unique))
                {
                /* see acl.c */
                BOOL seen;
                unsigned n, hash, hinc;
                uschar md5sum[16];
                md5 md5info;
                md5_start(&md5info);
                md5_end(&md5info, value, Ustrlen(value), md5sum);
                hash = md5sum[0] <<  0 | md5sum[1] <<  8
                     | md5sum[2] << 16 | md5sum[3] << 24;
                hinc = md5sum[4] <<  0 | md5sum[5] <<  8
                     | md5sum[6] << 16 | md5sum[7] << 24;
                rate_unique = (dbdata_ratelimit_unique *)record;
                seen = TRUE;
                for (n = 0; n < 8; n++, hash += hinc)
                  {
                  int bit = 1 << (hash % 8);
                  int byte = (hash / 8) % rate_unique->bloom_size;
                  if ((rate_unique->bloom[byte] & bit) == 0)
                    {
                    seen = FALSE;
                    if (fieldno == 5) rate_unique->bloom[byte] |= bit;
                    }
                  }
                printf("%s %s\n",
                  seen ? "seen" : fieldno == 5 ? "added" : "unseen", value);
                break;
                }
              /* else fall through */

              default:
              printf("unknown field number\n");
              verify = 0;
              break;
              }
            break;
            }

          dbfn_write(dbm, name, record, oldlength);
          }
        }
      }

    else
      {
      printf("field number or d expected\n");
      verify = 0;
      }

    dbfn_close(dbm);
    if (!verify) continue;
    }

  /* The "name" q causes an exit */

  else if (Ustrcmp(name, "q") == 0) return 0;

  /* Handle a read request, or verify after an update. */

  spool_directory = argv[1];
  if (!(dbm = dbfn_open(argv[2], O_RDONLY, &dbblock, FALSE)))
    continue;

  if (!(record = dbfn_read_with_length(dbm, name, &oldlength)))
    {
    printf("record %s not found\n", name);
    name[0] = 0;
    }
  else
    {
    int count_bad = 0;
    printf("%s\n", CS print_time(((dbdata_generic *)record)->time_stamp));
    switch(dbdata_type)
      {
      case type_retry:
      retry = (dbdata_retry *)record;
      printf("0 error number: %d %s\n", retry->basic_errno, retry->text);
      printf("1 extra data:   %d\n", retry->more_errno);
      printf("2 first failed: %s\n", print_time(retry->first_failed));
      printf("3 last try:     %s\n", print_time(retry->last_try));
      printf("4 next try:     %s\n", print_time(retry->next_try));
      printf("5 expired:      %s\n", (retry->expired)? "yes" : "no");
      break;

      case type_wait:
      wait = (dbdata_wait *)record;
      t = wait->text;
      printf("Sequence: %d\n", wait->sequence);
      if (wait->count > WAIT_NAME_MAX)
        {
        printf("**** Data corrupted: count=%d=0x%x max=%d ****\n", wait->count,
          wait->count, WAIT_NAME_MAX);
        wait->count = WAIT_NAME_MAX;
        count_bad = 1;
        }
      for (i = 1; i <= wait->count; i++)
        {
        Ustrncpy(value, t, MESSAGE_ID_LENGTH);
        value[MESSAGE_ID_LENGTH] = 0;
        if (count_bad && value[0] == 0) break;
        if (Ustrlen(value) != MESSAGE_ID_LENGTH ||
            Ustrspn(value, "0123456789"
                          "abcdefghijklmnopqrstuvwxyz"
                          "ABCDEFGHIJKLMNOPQRSTUVWXYZ-") != MESSAGE_ID_LENGTH)
          {
          int j;
          printf("\n**** Data corrupted: bad character in message id ****\n");
          for (j = 0; j < MESSAGE_ID_LENGTH; j++)
            printf("%02x ", value[j]);
          printf("\n");
          break;
          }
        printf("%s ", value);
        t += MESSAGE_ID_LENGTH;
        }
      printf("\n");
      break;

      case type_misc:
      break;

      case type_callout:
      callout = (dbdata_callout_cache *)record;
      printf("0 callout:    %s (%d)\n", print_cache(callout->result),
          callout->result);
      if (oldlength > sizeof(dbdata_callout_cache_address))
        {
        printf("1 postmaster: %s (%d)\n", print_cache(callout->postmaster_result),
            callout->postmaster_result);
        printf("2 random:     %s (%d)\n", print_cache(callout->random_result),
            callout->random_result);
        }
      break;

      case type_ratelimit:
      ratelimit = (dbdata_ratelimit *)record;
      printf("0 time stamp:  %s\n", print_time(ratelimit->time_stamp));
      printf("1 fract. time: .%06d\n", ratelimit->time_usec);
      printf("2 sender rate: % .3f\n", ratelimit->rate);
      if (Ustrstr(name, "/unique/") != NULL
       && oldlength >= sizeof(dbdata_ratelimit_unique))
       {
       rate_unique = (dbdata_ratelimit_unique *)record;
       printf("3 filter epoch: %s\n", print_time(rate_unique->bloom_epoch));
       printf("4 test filter membership\n");
       printf("5 add element to filter\n");
       }
      break;
      }
    }

  /* The database is closed after each request */

  dbfn_close(dbm);
  }

printf("\n");
return 0;
}

#endif  /* EXIM_FIXDB */



#ifdef EXIM_TIDYDB
/*************************************************
*           The exim_tidydb main program         *
*************************************************/


/* Utility program to tidy the contents of an exim database file. There is one
option:

   -t <time>  expiry time for old records - default 30 days

For backwards compatibility, an -f option is recognized and ignored. (It used
to request a "full" tidy. This version always does the whole job.) */


typedef struct key_item {
  struct key_item *next;
  uschar key[1];
} key_item;


int main(int argc, char **cargv)
{
struct stat statbuf;
int maxkeep = 30 * 24 * 60 * 60;
int dbdata_type, i, oldest, path_len;
key_item *keychain = NULL;
void *reset_point;
open_db dbblock;
open_db *dbm;
EXIM_CURSOR *cursor;
uschar **argv = USS cargv;
uschar buffer[256];
uschar *key;

/* Scan the options */

for (i = 1; i < argc; i++)
  {
  if (argv[i][0] != '-') break;
  if (Ustrcmp(argv[i], "-f") == 0) continue;
  if (Ustrcmp(argv[i], "-t") == 0)
    {
    uschar *s;
    s = argv[++i];
    maxkeep = 0;
    while (*s != 0)
      {
      int value, count;
      if (!isdigit(*s)) usage(US"tidydb", US" [-t <time>]");
      (void)sscanf(CS s, "%d%n", &value, &count);
      s += count;
      switch (*s)
        {
        case 'w': value *= 7;
        case 'd': value *= 24;
        case 'h': value *= 60;
        case 'm': value *= 60;
        case 's': s++;
        break;
        default: usage(US"tidydb", US" [-t <time>]");
        }
      maxkeep += value;
      }
    }
  else usage(US"tidydb", US" [-t <time>]");
  }

/* Adjust argument values and process arguments */

argc -= --i;
argv += i;

dbdata_type = check_args(argc, argv, US"tidydb", US" [-t <time>]");

/* Compute the oldest keep time, verify what we are doing, and open the
database */

oldest = time(NULL) - maxkeep;
printf("Tidying Exim hints database %s/db/%s\n", argv[1], argv[2]);

spool_directory = argv[1];
if (!(dbm = dbfn_open(argv[2], O_RDWR, &dbblock, FALSE)))
  exit(1);

/* Prepare for building file names */

sprintf(CS buffer, "%s/input/", argv[1]);
path_len = Ustrlen(buffer);


/* It appears, by experiment, that it is a bad idea to make changes
to the file while scanning it. Pity the man page doesn't warn you about that.
Therefore, we scan and build a list of all the keys. Then we use that to
read the records and possibly update them. */

for (key = dbfn_scan(dbm, TRUE, &cursor);
     key;
     key = dbfn_scan(dbm, FALSE, &cursor))
  {
  key_item *k = store_get(sizeof(key_item) + Ustrlen(key));
  k->next = keychain;
  keychain = k;
  Ustrcpy(k->key, key);
  }

/* Now scan the collected keys and operate on the records, resetting
the store each time round. */

reset_point = store_get(0);

while (keychain)
  {
  dbdata_generic *value;

  store_reset(reset_point);
  key = keychain->key;
  keychain = keychain->next;
  value = dbfn_read_with_length(dbm, key, NULL);

  /* A continuation record may have been deleted or renamed already, so
  non-existence is not serious. */

  if (value == NULL) continue;

  /* Delete if too old */

  if (value->time_stamp < oldest)
    {
    printf("deleted %s (too old)\n", key);
    dbfn_delete(dbm, key);
    continue;
    }

  /* Do database-specific tidying for wait databases, and message-
  specific tidying for the retry database. */

  if (dbdata_type == type_wait)
    {
    dbdata_wait *wait = (dbdata_wait *)value;
    BOOL update = FALSE;

    /* Leave corrupt records alone */

    if (wait->count > WAIT_NAME_MAX)
      {
      printf("**** Data for %s corrupted\n  count=%d=0x%x max=%d\n",
        key, wait->count, wait->count, WAIT_NAME_MAX);
      continue;
      }

    /* Loop for renamed continuation records. For each message id,
    check to see if the message exists, and if not, remove its entry
    from the record. Because of the possibility of split input directories,
    we must look in both possible places for a -D file. */

    for (;;)
      {
      int offset;
      int length = wait->count * MESSAGE_ID_LENGTH;

      for (offset = length - MESSAGE_ID_LENGTH;
           offset >= 0; offset -= MESSAGE_ID_LENGTH)
        {
        Ustrncpy(buffer+path_len, wait->text + offset, MESSAGE_ID_LENGTH);
        sprintf(CS(buffer+path_len + MESSAGE_ID_LENGTH), "-D");

        if (Ustat(buffer, &statbuf) != 0)
          {
          buffer[path_len] = wait->text[offset+5];
          buffer[path_len+1] = '/';
          Ustrncpy(buffer+path_len+2, wait->text + offset, MESSAGE_ID_LENGTH);
          sprintf(CS(buffer+path_len+2 + MESSAGE_ID_LENGTH), "-D");

          if (Ustat(buffer, &statbuf) != 0)
            {
            int left = length - offset - MESSAGE_ID_LENGTH;
            if (left > 0) Ustrncpy(wait->text + offset,
              wait->text + offset + MESSAGE_ID_LENGTH, left);
            wait->count--;
            length -= MESSAGE_ID_LENGTH;
            update = TRUE;
            }
          }
        }

      /* If record is empty and the main record, either delete it or rename
      the next continuation, repeating if that is also empty. */

      if (wait->count == 0 && Ustrchr(key, ':') == NULL)
        {
        while (wait->count == 0 && wait->sequence > 0)
          {
          uschar newkey[256];
          dbdata_generic *newvalue;
          sprintf(CS newkey, "%s:%d", key, wait->sequence - 1);
          newvalue = dbfn_read_with_length(dbm, newkey, NULL);
          if (newvalue != NULL)
            {
            value = newvalue;
            wait = (dbdata_wait *)newvalue;
            dbfn_delete(dbm, newkey);
            printf("renamed %s\n", newkey);
            update = TRUE;
            }
          else wait->sequence--;
          }

        /* If we have ended up with an empty main record, delete it
        and break the loop. Otherwise the new record will be scanned. */

        if (wait->count == 0 && wait->sequence == 0)
          {
          dbfn_delete(dbm, key);
          printf("deleted %s (empty)\n", key);
          update = FALSE;
          break;
          }
        }

      /* If not an empty main record, break the loop */

      else break;
      }

    /* Re-write the record if required */

    if (update)
      {
      printf("updated %s\n", key);
      dbfn_write(dbm, key, wait, sizeof(dbdata_wait) +
        wait->count * MESSAGE_ID_LENGTH);
      }
    }

  /* If a retry record's key ends with a message-id, check that that message
  still exists; if not, remove this record. */

  else if (dbdata_type == type_retry)
    {
    uschar *id;
    int len = Ustrlen(key);

    if (len < MESSAGE_ID_LENGTH + 1) continue;
    id = key + len - MESSAGE_ID_LENGTH - 1;
    if (*id++ != ':') continue;

    for (i = 0; i < MESSAGE_ID_LENGTH; i++)
      {
      if (i == 6 || i == 13)
        { if (id[i] != '-') break; }
      else
        { if (!isalnum(id[i])) break; }
      }
    if (i < MESSAGE_ID_LENGTH) continue;

    Ustrncpy(buffer + path_len, id, MESSAGE_ID_LENGTH);
    sprintf(CS(buffer + path_len + MESSAGE_ID_LENGTH), "-D");

    if (Ustat(buffer, &statbuf) != 0)
      {
      sprintf(CS(buffer + path_len), "%c/%s-D", id[5], id);
      if (Ustat(buffer, &statbuf) != 0)
        {
        dbfn_delete(dbm, key);
        printf("deleted %s (no message)\n", key);
        }
      }
    }
  }

dbfn_close(dbm);
printf("Tidying complete\n");
return 0;
}

#endif  /* EXIM_TIDYDB */

/* End of exim_dbutil.c */
