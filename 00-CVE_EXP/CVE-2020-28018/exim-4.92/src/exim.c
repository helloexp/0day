/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


/* The main function: entry point, initialization, and high-level control.
Also a few functions that don't naturally fit elsewhere. */


#include "exim.h"

#if defined(__GLIBC__) && !defined(__UCLIBC__)
# include <gnu/libc-version.h>
#endif

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
# if GNUTLS_VERSION_NUMBER < 0x030103 && !defined(DISABLE_OCSP)
#  define DISABLE_OCSP
# endif
#endif

extern void init_lookup_list(void);



/*************************************************
*      Function interface to store functions     *
*************************************************/

/* We need some real functions to pass to the PCRE regular expression library
for store allocation via Exim's store manager. The normal calls are actually
macros that pass over location information to make tracing easier. These
functions just interface to the standard macro calls. A good compiler will
optimize out the tail recursion and so not make them too expensive. There
are two sets of functions; one for use when we want to retain the compiled
regular expression for a long time; the other for short-term use. */

static void *
function_store_get(size_t size)
{
return store_get((int)size);
}

static void
function_dummy_free(void *block) { block = block; }

static void *
function_store_malloc(size_t size)
{
return store_malloc((int)size);
}

static void
function_store_free(void *block)
{
store_free(block);
}




/*************************************************
*         Enums for cmdline interface            *
*************************************************/

enum commandline_info { CMDINFO_NONE=0,
  CMDINFO_HELP, CMDINFO_SIEVE, CMDINFO_DSCP };




/*************************************************
*  Compile regular expression and panic on fail  *
*************************************************/

/* This function is called when failure to compile a regular expression leads
to a panic exit. In other cases, pcre_compile() is called directly. In many
cases where this function is used, the results of the compilation are to be
placed in long-lived store, so we temporarily reset the store management
functions that PCRE uses if the use_malloc flag is set.

Argument:
  pattern     the pattern to compile
  caseless    TRUE if caseless matching is required
  use_malloc  TRUE if compile into malloc store

Returns:      pointer to the compiled pattern
*/

const pcre *
regex_must_compile(const uschar *pattern, BOOL caseless, BOOL use_malloc)
{
int offset;
int options = PCRE_COPT;
const pcre *yield;
const uschar *error;
if (use_malloc)
  {
  pcre_malloc = function_store_malloc;
  pcre_free = function_store_free;
  }
if (caseless) options |= PCRE_CASELESS;
yield = pcre_compile(CCS pattern, options, (const char **)&error, &offset, NULL);
pcre_malloc = function_store_get;
pcre_free = function_dummy_free;
if (yield == NULL)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "regular expression error: "
    "%s at offset %d while compiling %s", error, offset, pattern);
return yield;
}




/*************************************************
*   Execute regular expression and set strings   *
*************************************************/

/* This function runs a regular expression match, and sets up the pointers to
the matched substrings.

Arguments:
  re          the compiled expression
  subject     the subject string
  options     additional PCRE options
  setup       if < 0 do full setup
              if >= 0 setup from setup+1 onwards,
                excluding the full matched string

Returns:      TRUE or FALSE
*/

BOOL
regex_match_and_setup(const pcre *re, const uschar *subject, int options, int setup)
{
int ovector[3*(EXPAND_MAXN+1)];
uschar * s = string_copy(subject);	/* de-constifying */
int n = pcre_exec(re, NULL, CS s, Ustrlen(s), 0,
  PCRE_EOPT | options, ovector, nelem(ovector));
BOOL yield = n >= 0;
if (n == 0) n = EXPAND_MAXN + 1;
if (yield)
  {
  int nn;
  expand_nmax = setup < 0 ? 0 : setup + 1;
  for (nn = setup < 0 ? 0 : 2; nn < n*2; nn += 2)
    {
    expand_nstring[expand_nmax] = s + ovector[nn];
    expand_nlength[expand_nmax++] = ovector[nn+1] - ovector[nn];
    }
  expand_nmax--;
  }
return yield;
}




/*************************************************
*            Set up processing details           *
*************************************************/

/* Save a text string for dumping when SIGUSR1 is received.
Do checks for overruns.

Arguments: format and arguments, as for printf()
Returns:   nothing
*/

void
set_process_info(const char *format, ...)
{
gstring gs = { .size = PROCESS_INFO_SIZE - 2, .ptr = 0, .s = process_info };
gstring * g;
int len;
va_list ap;

g = string_fmt_append(&gs, "%5d ", (int)getpid());
len = g->ptr;
va_start(ap, format);
if (!string_vformat(g, FALSE, format, ap))
  {
  gs.ptr = len;
  g = string_cat(&gs, US"**** string overflowed buffer ****");
  }
g = string_catn(g, US"\n", 1);
string_from_gstring(g);
process_info_len = g->ptr;
DEBUG(D_process_info) debug_printf("set_process_info: %s", process_info);
va_end(ap);
}

/***********************************************
*            Handler for SIGTERM               *
***********************************************/

static void
term_handler(int sig)
{
  exit(1);
}


/*************************************************
*             Handler for SIGUSR1                *
*************************************************/

/* SIGUSR1 causes any exim process to write to the process log details of
what it is currently doing. It will only be used if the OS is capable of
setting up a handler that causes automatic restarting of any system call
that is in progress at the time.

This function takes care to be signal-safe.

Argument: the signal number (SIGUSR1)
Returns:  nothing
*/

static void
usr1_handler(int sig)
{
int fd;

os_restarting_signal(sig, usr1_handler);

if ((fd = Uopen(process_log_path, O_APPEND|O_WRONLY, LOG_MODE)) < 0)
  {
  /* If we are already running as the Exim user, try to create it in the
  current process (assuming spool_directory exists). Otherwise, if we are
  root, do the creation in an exim:exim subprocess. */

  int euid = geteuid();
  if (euid == exim_uid)
    fd = Uopen(process_log_path, O_CREAT|O_APPEND|O_WRONLY, LOG_MODE);
  else if (euid == root_uid)
    fd = log_create_as_exim(process_log_path);
  }

/* If we are neither exim nor root, or if we failed to create the log file,
give up. There is not much useful we can do with errors, since we don't want
to disrupt whatever is going on outside the signal handler. */

if (fd < 0) return;

(void)write(fd, process_info, process_info_len);
(void)close(fd);
}



/*************************************************
*             Timeout handler                    *
*************************************************/

/* This handler is enabled most of the time that Exim is running. The handler
doesn't actually get used unless alarm() has been called to set a timer, to
place a time limit on a system call of some kind. When the handler is run, it
re-enables itself.

There are some other SIGALRM handlers that are used in special cases when more
than just a flag setting is required; for example, when reading a message's
input. These are normally set up in the code module that uses them, and the
SIGALRM handler is reset to this one afterwards.

Argument: the signal value (SIGALRM)
Returns:  nothing
*/

void
sigalrm_handler(int sig)
{
sig = sig;      /* Keep picky compilers happy */
sigalrm_seen = TRUE;
os_non_restarting_signal(SIGALRM, sigalrm_handler);
}



/*************************************************
*      Sleep for a fractional time interval      *
*************************************************/

/* This function is called by millisleep() and exim_wait_tick() to wait for a
period of time that may include a fraction of a second. The coding is somewhat
tedious. We do not expect setitimer() ever to fail, but if it does, the process
will wait for ever, so we panic in this instance. (There was a case of this
when a bug in a function that calls milliwait() caused it to pass invalid data.
That's when I added the check. :-)

We assume it to be not worth sleeping for under 100us; this value will
require revisiting as hardware advances.  This avoids the issue of
a zero-valued timer setting meaning "never fire".

Argument:  an itimerval structure containing the interval
Returns:   nothing
*/

static void
milliwait(struct itimerval *itval)
{
sigset_t sigmask;
sigset_t old_sigmask;

if (itval->it_value.tv_usec < 100 && itval->it_value.tv_sec == 0)
  return;
(void)sigemptyset(&sigmask);                           /* Empty mask */
(void)sigaddset(&sigmask, SIGALRM);                    /* Add SIGALRM */
(void)sigprocmask(SIG_BLOCK, &sigmask, &old_sigmask);  /* Block SIGALRM */
if (setitimer(ITIMER_REAL, itval, NULL) < 0)           /* Start timer */
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "setitimer() failed: %s", strerror(errno));
(void)sigfillset(&sigmask);                            /* All signals */
(void)sigdelset(&sigmask, SIGALRM);                    /* Remove SIGALRM */
(void)sigsuspend(&sigmask);                            /* Until SIGALRM */
(void)sigprocmask(SIG_SETMASK, &old_sigmask, NULL);    /* Restore mask */
}




/*************************************************
*         Millisecond sleep function             *
*************************************************/

/* The basic sleep() function has a granularity of 1 second, which is too rough
in some cases - for example, when using an increasing delay to slow down
spammers.

Argument:    number of millseconds
Returns:     nothing
*/

void
millisleep(int msec)
{
struct itimerval itval;
itval.it_interval.tv_sec = 0;
itval.it_interval.tv_usec = 0;
itval.it_value.tv_sec = msec/1000;
itval.it_value.tv_usec = (msec % 1000) * 1000;
milliwait(&itval);
}



/*************************************************
*         Compare microsecond times              *
*************************************************/

/*
Arguments:
  tv1         the first time
  tv2         the second time

Returns:      -1, 0, or +1
*/

static int
exim_tvcmp(struct timeval *t1, struct timeval *t2)
{
if (t1->tv_sec > t2->tv_sec) return +1;
if (t1->tv_sec < t2->tv_sec) return -1;
if (t1->tv_usec > t2->tv_usec) return +1;
if (t1->tv_usec < t2->tv_usec) return -1;
return 0;
}




/*************************************************
*          Clock tick wait function              *
*************************************************/

/* Exim uses a time + a pid to generate a unique identifier in two places: its
message IDs, and in file names for maildir deliveries. Because some OS now
re-use pids within the same second, sub-second times are now being used.
However, for absolute certainty, we must ensure the clock has ticked before
allowing the relevant process to complete. At the time of implementation of
this code (February 2003), the speed of processors is such that the clock will
invariably have ticked already by the time a process has done its job. This
function prepares for the time when things are faster - and it also copes with
clocks that go backwards.

Arguments:
  then_tv      A timeval which was used to create uniqueness; its usec field
                 has been rounded down to the value of the resolution.
                 We want to be sure the current time is greater than this.
  resolution   The resolution that was used to divide the microseconds
                 (1 for maildir, larger for message ids)

Returns:       nothing
*/

void
exim_wait_tick(struct timeval *then_tv, int resolution)
{
struct timeval now_tv;
long int now_true_usec;

(void)gettimeofday(&now_tv, NULL);
now_true_usec = now_tv.tv_usec;
now_tv.tv_usec = (now_true_usec/resolution) * resolution;

if (exim_tvcmp(&now_tv, then_tv) <= 0)
  {
  struct itimerval itval;
  itval.it_interval.tv_sec = 0;
  itval.it_interval.tv_usec = 0;
  itval.it_value.tv_sec = then_tv->tv_sec - now_tv.tv_sec;
  itval.it_value.tv_usec = then_tv->tv_usec + resolution - now_true_usec;

  /* We know that, overall, "now" is less than or equal to "then". Therefore, a
  negative value for the microseconds is possible only in the case when "now"
  is more than a second less than "then". That means that itval.it_value.tv_sec
  is greater than zero. The following correction is therefore safe. */

  if (itval.it_value.tv_usec < 0)
    {
    itval.it_value.tv_usec += 1000000;
    itval.it_value.tv_sec -= 1;
    }

  DEBUG(D_transport|D_receive)
    {
    if (!f.running_in_test_harness)
      {
      debug_printf("tick check: " TIME_T_FMT ".%06lu " TIME_T_FMT ".%06lu\n",
        then_tv->tv_sec, (long) then_tv->tv_usec,
       	now_tv.tv_sec, (long) now_tv.tv_usec);
      debug_printf("waiting " TIME_T_FMT ".%06lu\n",
        itval.it_value.tv_sec, (long) itval.it_value.tv_usec);
      }
    }

  milliwait(&itval);
  }
}




/*************************************************
*   Call fopen() with umask 777 and adjust mode  *
*************************************************/

/* Exim runs with umask(0) so that files created with open() have the mode that
is specified in the open() call. However, there are some files, typically in
the spool directory, that are created with fopen(). They end up world-writeable
if no precautions are taken. Although the spool directory is not accessible to
the world, this is an untidiness. So this is a wrapper function for fopen()
that sorts out the mode of the created file.

Arguments:
   filename       the file name
   options        the fopen() options
   mode           the required mode

Returns:          the fopened FILE or NULL
*/

FILE *
modefopen(const uschar *filename, const char *options, mode_t mode)
{
mode_t saved_umask = umask(0777);
FILE *f = Ufopen(filename, options);
(void)umask(saved_umask);
if (f != NULL) (void)fchmod(fileno(f), mode);
return f;
}




/*************************************************
*   Ensure stdin, stdout, and stderr exist       *
*************************************************/

/* Some operating systems grumble if an exec() happens without a standard
input, output, and error (fds 0, 1, 2) being defined. The worry is that some
file will be opened and will use these fd values, and then some other bit of
code will assume, for example, that it can write error messages to stderr.
This function ensures that fds 0, 1, and 2 are open if they do not already
exist, by connecting them to /dev/null.

This function is also used to ensure that std{in,out,err} exist at all times,
so that if any library that Exim calls tries to use them, it doesn't crash.

Arguments:  None
Returns:    Nothing
*/

void
exim_nullstd(void)
{
int i;
int devnull = -1;
struct stat statbuf;
for (i = 0; i <= 2; i++)
  {
  if (fstat(i, &statbuf) < 0 && errno == EBADF)
    {
    if (devnull < 0) devnull = open("/dev/null", O_RDWR);
    if (devnull < 0) log_write(0, LOG_MAIN|LOG_PANIC_DIE, "%s",
      string_open_failed(errno, "/dev/null"));
    if (devnull != i) (void)dup2(devnull, i);
    }
  }
if (devnull > 2) (void)close(devnull);
}




/*************************************************
*   Close unwanted file descriptors for delivery *
*************************************************/

/* This function is called from a new process that has been forked to deliver
an incoming message, either directly, or using exec.

We want any smtp input streams to be closed in this new process. However, it
has been observed that using fclose() here causes trouble. When reading in -bS
input, duplicate copies of messages have been seen. The files will be sharing a
file pointer with the parent process, and it seems that fclose() (at least on
some systems - I saw this on Solaris 2.5.1) messes with that file pointer, at
least sometimes. Hence we go for closing the underlying file descriptors.

If TLS is active, we want to shut down the TLS library, but without molesting
the parent's SSL connection.

For delivery of a non-SMTP message, we want to close stdin and stdout (and
stderr unless debugging) because the calling process might have set them up as
pipes and be waiting for them to close before it waits for the submission
process to terminate. If they aren't closed, they hold up the calling process
until the initial delivery process finishes, which is not what we want.

Exception: We do want it for synchronous delivery!

And notwithstanding all the above, if D_resolver is set, implying resolver
debugging, leave stdout open, because that's where the resolver writes its
debugging output.

When we close stderr (which implies we've also closed stdout), we also get rid
of any controlling terminal.

Arguments:   None
Returns:     Nothing
*/

static void
close_unwanted(void)
{
if (smtp_input)
  {
#ifdef SUPPORT_TLS
  tls_close(NULL, TLS_NO_SHUTDOWN);      /* Shut down the TLS library */
#endif
  (void)close(fileno(smtp_in));
  (void)close(fileno(smtp_out));
  smtp_in = NULL;
  }
else
  {
  (void)close(0);                                          /* stdin */
  if ((debug_selector & D_resolver) == 0) (void)close(1);  /* stdout */
  if (debug_selector == 0)                                 /* stderr */
    {
    if (!f.synchronous_delivery)
      {
      (void)close(2);
      log_stderr = NULL;
      }
    (void)setsid();
    }
  }
}




/*************************************************
*          Set uid and gid                       *
*************************************************/

/* This function sets a new uid and gid permanently, optionally calling
initgroups() to set auxiliary groups. There are some special cases when running
Exim in unprivileged modes. In these situations the effective uid will not be
root; if we already have the right effective uid/gid, and don't need to
initialize any groups, leave things as they are.

Arguments:
  uid        the uid
  gid        the gid
  igflag     TRUE if initgroups() wanted
  msg        text to use in debugging output and failure log

Returns:     nothing; bombs out on failure
*/

void
exim_setugid(uid_t uid, gid_t gid, BOOL igflag, uschar *msg)
{
uid_t euid = geteuid();
gid_t egid = getegid();

if (euid == root_uid || euid != uid || egid != gid || igflag)
  {
  /* At least one OS returns +1 for initgroups failure, so just check for
  non-zero. */

  if (igflag)
    {
    struct passwd *pw = getpwuid(uid);
    if (!pw)
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "cannot run initgroups(): "
	"no passwd entry for uid=%ld", (long int)uid);

    if (initgroups(pw->pw_name, gid) != 0)
      log_write(0,LOG_MAIN|LOG_PANIC_DIE,"initgroups failed for uid=%ld: %s",
	(long int)uid, strerror(errno));
    }

  if (setgid(gid) < 0 || setuid(uid) < 0)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "unable to set gid=%ld or uid=%ld "
      "(euid=%ld): %s", (long int)gid, (long int)uid, (long int)euid, msg);
  }

/* Debugging output included uid/gid and all groups */

DEBUG(D_uid)
  {
  int group_count, save_errno;
  gid_t group_list[EXIM_GROUPLIST_SIZE];
  debug_printf("changed uid/gid: %s\n  uid=%ld gid=%ld pid=%ld\n", msg,
    (long int)geteuid(), (long int)getegid(), (long int)getpid());
  group_count = getgroups(nelem(group_list), group_list);
  save_errno = errno;
  debug_printf("  auxiliary group list:");
  if (group_count > 0)
    {
    int i;
    for (i = 0; i < group_count; i++) debug_printf(" %d", (int)group_list[i]);
    }
  else if (group_count < 0)
    debug_printf(" <error: %s>", strerror(save_errno));
  else debug_printf(" <none>");
  debug_printf("\n");
  }
}




/*************************************************
*               Exit point                       *
*************************************************/

/* Exim exits via this function so that it always clears up any open
databases.

Arguments:
  rc         return code

Returns:     does not return
*/

void
exim_exit(int rc, const uschar * process)
{
search_tidyup();
DEBUG(D_any)
  debug_printf(">>>>>>>>>>>>>>>> Exim pid=%d %s%s%sterminating with rc=%d "
    ">>>>>>>>>>>>>>>>\n", (int)getpid(),
    process ? "(" : "", process, process ? ") " : "", rc);
exit(rc);
}



/* Print error string, then die */
static void
exim_fail(const char * fmt, ...)
{
va_list ap;
va_start(ap, fmt);
vfprintf(stderr, fmt, ap);
exit(EXIT_FAILURE);
}



/*************************************************
*         Extract port from host address         *
*************************************************/

/* Called to extract the port from the values given to -oMa and -oMi.
It also checks the syntax of the address, and terminates it before the
port data when a port is extracted.

Argument:
  address   the address, with possible port on the end

Returns:    the port, or zero if there isn't one
            bombs out on a syntax error
*/

static int
check_port(uschar *address)
{
int port = host_address_extract_port(address);
if (string_is_ip_address(address, NULL) == 0)
  exim_fail("exim abandoned: \"%s\" is not an IP address\n", address);
return port;
}



/*************************************************
*              Test/verify an address            *
*************************************************/

/* This function is called by the -bv and -bt code. It extracts a working
address from a full RFC 822 address. This isn't really necessary per se, but it
has the effect of collapsing source routes.

Arguments:
  s            the address string
  flags        flag bits for verify_address()
  exit_value   to be set for failures

Returns:       nothing
*/

static void
test_address(uschar *s, int flags, int *exit_value)
{
int start, end, domain;
uschar *parse_error = NULL;
uschar *address = parse_extract_address(s, &parse_error, &start, &end, &domain,
  FALSE);
if (address == NULL)
  {
  fprintf(stdout, "syntax error: %s\n", parse_error);
  *exit_value = 2;
  }
else
  {
  int rc = verify_address(deliver_make_addr(address,TRUE), stdout, flags, -1,
    -1, -1, NULL, NULL, NULL);
  if (rc == FAIL) *exit_value = 2;
    else if (rc == DEFER && *exit_value == 0) *exit_value = 1;
  }
}



/*************************************************
*          Show supported features               *
*************************************************/

static void
show_db_version(FILE * f)
{
#ifdef DB_VERSION_STRING
DEBUG(D_any)
  {
  fprintf(f, "Library version: BDB: Compile: %s\n", DB_VERSION_STRING);
  fprintf(f, "                      Runtime: %s\n",
    db_version(NULL, NULL, NULL));
  }
else
  fprintf(f, "Berkeley DB: %s\n", DB_VERSION_STRING);

#elif defined(BTREEVERSION) && defined(HASHVERSION)
  #ifdef USE_DB
  fprintf(f, "Probably Berkeley DB version 1.8x (native mode)\n");
  #else
  fprintf(f, "Probably Berkeley DB version 1.8x (compatibility mode)\n");
  #endif

#elif defined(_DBM_RDONLY) || defined(dbm_dirfno)
fprintf(f, "Probably ndbm\n");
#elif defined(USE_TDB)
fprintf(f, "Using tdb\n");
#else
  #ifdef USE_GDBM
  fprintf(f, "Probably GDBM (native mode)\n");
  #else
  fprintf(f, "Probably GDBM (compatibility mode)\n");
  #endif
#endif
}


/* This function is called for -bV/--version and for -d to output the optional
features of the current Exim binary.

Arguments:  a FILE for printing
Returns:    nothing
*/

static void
show_whats_supported(FILE * fp)
{
auth_info * authi;

DEBUG(D_any) {} else show_db_version(fp);

fprintf(fp, "Support for:");
#ifdef SUPPORT_CRYPTEQ
  fprintf(fp, " crypteq");
#endif
#if HAVE_ICONV
  fprintf(fp, " iconv()");
#endif
#if HAVE_IPV6
  fprintf(fp, " IPv6");
#endif
#ifdef HAVE_SETCLASSRESOURCES
  fprintf(fp, " use_setclassresources");
#endif
#ifdef SUPPORT_PAM
  fprintf(fp, " PAM");
#endif
#ifdef EXIM_PERL
  fprintf(fp, " Perl");
#endif
#ifdef EXPAND_DLFUNC
  fprintf(fp, " Expand_dlfunc");
#endif
#ifdef USE_TCP_WRAPPERS
  fprintf(fp, " TCPwrappers");
#endif
#ifdef SUPPORT_TLS
# ifdef USE_GNUTLS
  fprintf(fp, " GnuTLS");
# else
  fprintf(fp, " OpenSSL");
# endif
#endif
#ifdef SUPPORT_TRANSLATE_IP_ADDRESS
  fprintf(fp, " translate_ip_address");
#endif
#ifdef SUPPORT_MOVE_FROZEN_MESSAGES
  fprintf(fp, " move_frozen_messages");
#endif
#ifdef WITH_CONTENT_SCAN
  fprintf(fp, " Content_Scanning");
#endif
#ifdef SUPPORT_DANE
  fprintf(fp, " DANE");
#endif
#ifndef DISABLE_DKIM
  fprintf(fp, " DKIM");
#endif
#ifndef DISABLE_DNSSEC
  fprintf(fp, " DNSSEC");
#endif
#ifndef DISABLE_EVENT
  fprintf(fp, " Event");
#endif
#ifdef SUPPORT_I18N
  fprintf(fp, " I18N");
#endif
#ifndef DISABLE_OCSP
  fprintf(fp, " OCSP");
#endif
#ifndef DISABLE_PRDR
  fprintf(fp, " PRDR");
#endif
#ifdef SUPPORT_PROXY
  fprintf(fp, " PROXY");
#endif
#ifdef SUPPORT_SOCKS
  fprintf(fp, " SOCKS");
#endif
#ifdef SUPPORT_SPF
  fprintf(fp, " SPF");
#endif
#ifdef TCP_FASTOPEN
  deliver_init();
  if (f.tcp_fastopen_ok) fprintf(fp, " TCP_Fast_Open");
#endif
#ifdef EXPERIMENTAL_LMDB
  fprintf(fp, " Experimental_LMDB");
#endif
#ifdef EXPERIMENTAL_QUEUEFILE
  fprintf(fp, " Experimental_QUEUEFILE");
#endif
#ifdef EXPERIMENTAL_SRS
  fprintf(fp, " Experimental_SRS");
#endif
#ifdef EXPERIMENTAL_ARC
  fprintf(fp, " Experimental_ARC");
#endif
#ifdef EXPERIMENTAL_BRIGHTMAIL
  fprintf(fp, " Experimental_Brightmail");
#endif
#ifdef EXPERIMENTAL_DCC
  fprintf(fp, " Experimental_DCC");
#endif
#ifdef EXPERIMENTAL_DMARC
  fprintf(fp, " Experimental_DMARC");
#endif
#ifdef EXPERIMENTAL_DSN_INFO
  fprintf(fp, " Experimental_DSN_info");
#endif
#ifdef EXPERIMENTAL_REQUIRETLS
  fprintf(fp, " Experimental_REQUIRETLS");
#endif
#ifdef EXPERIMENTAL_PIPE_CONNECT
  fprintf(fp, " Experimental_PIPE_CONNECT");
#endif
fprintf(fp, "\n");

fprintf(fp, "Lookups (built-in):");
#if defined(LOOKUP_LSEARCH) && LOOKUP_LSEARCH!=2
  fprintf(fp, " lsearch wildlsearch nwildlsearch iplsearch");
#endif
#if defined(LOOKUP_CDB) && LOOKUP_CDB!=2
  fprintf(fp, " cdb");
#endif
#if defined(LOOKUP_DBM) && LOOKUP_DBM!=2
  fprintf(fp, " dbm dbmjz dbmnz");
#endif
#if defined(LOOKUP_DNSDB) && LOOKUP_DNSDB!=2
  fprintf(fp, " dnsdb");
#endif
#if defined(LOOKUP_DSEARCH) && LOOKUP_DSEARCH!=2
  fprintf(fp, " dsearch");
#endif
#if defined(LOOKUP_IBASE) && LOOKUP_IBASE!=2
  fprintf(fp, " ibase");
#endif
#if defined(LOOKUP_LDAP) && LOOKUP_LDAP!=2
  fprintf(fp, " ldap ldapdn ldapm");
#endif
#ifdef EXPERIMENTAL_LMDB
  fprintf(fp, " lmdb");
#endif
#if defined(LOOKUP_MYSQL) && LOOKUP_MYSQL!=2
  fprintf(fp, " mysql");
#endif
#if defined(LOOKUP_NIS) && LOOKUP_NIS!=2
  fprintf(fp, " nis nis0");
#endif
#if defined(LOOKUP_NISPLUS) && LOOKUP_NISPLUS!=2
  fprintf(fp, " nisplus");
#endif
#if defined(LOOKUP_ORACLE) && LOOKUP_ORACLE!=2
  fprintf(fp, " oracle");
#endif
#if defined(LOOKUP_PASSWD) && LOOKUP_PASSWD!=2
  fprintf(fp, " passwd");
#endif
#if defined(LOOKUP_PGSQL) && LOOKUP_PGSQL!=2
  fprintf(fp, " pgsql");
#endif
#if defined(LOOKUP_REDIS) && LOOKUP_REDIS!=2
  fprintf(fp, " redis");
#endif
#if defined(LOOKUP_SQLITE) && LOOKUP_SQLITE!=2
  fprintf(fp, " sqlite");
#endif
#if defined(LOOKUP_TESTDB) && LOOKUP_TESTDB!=2
  fprintf(fp, " testdb");
#endif
#if defined(LOOKUP_WHOSON) && LOOKUP_WHOSON!=2
  fprintf(fp, " whoson");
#endif
fprintf(fp, "\n");

auth_show_supported(fp);
route_show_supported(fp);
transport_show_supported(fp);

#ifdef WITH_CONTENT_SCAN
malware_show_supported(fp);
#endif

if (fixed_never_users[0] > 0)
  {
  int i;
  fprintf(fp, "Fixed never_users: ");
  for (i = 1; i <= (int)fixed_never_users[0] - 1; i++)
    fprintf(fp, "%d:", (unsigned int)fixed_never_users[i]);
  fprintf(fp, "%d\n", (unsigned int)fixed_never_users[i]);
  }

fprintf(fp, "Configure owner: %d:%d\n", config_uid, config_gid);

fprintf(fp, "Size of off_t: " SIZE_T_FMT "\n", sizeof(off_t));

/* Everything else is details which are only worth reporting when debugging.
Perhaps the tls_version_report should move into this too. */
DEBUG(D_any) do {

  int i;

/* clang defines __GNUC__ (at least, for me) so test for it first */
#if defined(__clang__)
  fprintf(fp, "Compiler: CLang [%s]\n", __clang_version__);
#elif defined(__GNUC__)
  fprintf(fp, "Compiler: GCC [%s]\n",
# ifdef __VERSION__
      __VERSION__
# else
      "? unknown version ?"
# endif
      );
#else
  fprintf(fp, "Compiler: <unknown>\n");
#endif

#if defined(__GLIBC__) && !defined(__UCLIBC__)
  fprintf(fp, "Library version: Glibc: Compile: %d.%d\n",
	       	__GLIBC__, __GLIBC_MINOR__);
  if (__GLIBC_PREREQ(2, 1))
    fprintf(fp, "                        Runtime: %s\n",
	       	gnu_get_libc_version());
#endif

show_db_version(fp);

#ifdef SUPPORT_TLS
  tls_version_report(fp);
#endif
#ifdef SUPPORT_I18N
  utf8_version_report(fp);
#endif

  for (authi = auths_available; *authi->driver_name != '\0'; ++authi)
    if (authi->version_report)
      (*authi->version_report)(fp);

  /* PCRE_PRERELEASE is either defined and empty or a bare sequence of
  characters; unless it's an ancient version of PCRE in which case it
  is not defined. */
#ifndef PCRE_PRERELEASE
# define PCRE_PRERELEASE
#endif
#define QUOTE(X) #X
#define EXPAND_AND_QUOTE(X) QUOTE(X)
  fprintf(fp, "Library version: PCRE: Compile: %d.%d%s\n"
             "                       Runtime: %s\n",
          PCRE_MAJOR, PCRE_MINOR,
          EXPAND_AND_QUOTE(PCRE_PRERELEASE) "",
          pcre_version());
#undef QUOTE
#undef EXPAND_AND_QUOTE

  init_lookup_list();
  for (i = 0; i < lookup_list_count; i++)
    if (lookup_list[i]->version_report)
      lookup_list[i]->version_report(fp);

#ifdef WHITELIST_D_MACROS
  fprintf(fp, "WHITELIST_D_MACROS: \"%s\"\n", WHITELIST_D_MACROS);
#else
  fprintf(fp, "WHITELIST_D_MACROS unset\n");
#endif
#ifdef TRUSTED_CONFIG_LIST
  fprintf(fp, "TRUSTED_CONFIG_LIST: \"%s\"\n", TRUSTED_CONFIG_LIST);
#else
  fprintf(fp, "TRUSTED_CONFIG_LIST unset\n");
#endif

} while (0);
}


/*************************************************
*     Show auxiliary information about Exim      *
*************************************************/

static void
show_exim_information(enum commandline_info request, FILE *stream)
{
const uschar **pp;

switch(request)
  {
  case CMDINFO_NONE:
    fprintf(stream, "Oops, something went wrong.\n");
    return;
  case CMDINFO_HELP:
    fprintf(stream,
"The -bI: flag takes a string indicating which information to provide.\n"
"If the string is not recognised, you'll get this help (on stderr).\n"
"\n"
"  exim -bI:help    this information\n"
"  exim -bI:dscp    list of known dscp value keywords\n"
"  exim -bI:sieve   list of supported sieve extensions\n"
);
    return;
  case CMDINFO_SIEVE:
    for (pp = exim_sieve_extension_list; *pp; ++pp)
      fprintf(stream, "%s\n", *pp);
    return;
  case CMDINFO_DSCP:
    dscp_list_to_stream(stream);
    return;
  }
}


/*************************************************
*               Quote a local part               *
*************************************************/

/* This function is used when a sender address or a From: or Sender: header
line is being created from the caller's login, or from an authenticated_id. It
applies appropriate quoting rules for a local part.

Argument:    the local part
Returns:     the local part, quoted if necessary
*/

uschar *
local_part_quote(uschar *lpart)
{
BOOL needs_quote = FALSE;
gstring * g;
uschar *t;

for (t = lpart; !needs_quote && *t != 0; t++)
  {
  needs_quote = !isalnum(*t) && strchr("!#$%&'*+-/=?^_`{|}~", *t) == NULL &&
    (*t != '.' || t == lpart || t[1] == 0);
  }

if (!needs_quote) return lpart;

g = string_catn(NULL, US"\"", 1);

for (;;)
  {
  uschar *nq = US Ustrpbrk(lpart, "\\\"");
  if (nq == NULL)
    {
    g = string_cat(g, lpart);
    break;
    }
  g = string_catn(g, lpart, nq - lpart);
  g = string_catn(g, US"\\", 1);
  g = string_catn(g, nq, 1);
  lpart = nq + 1;
  }

g = string_catn(g, US"\"", 1);
return string_from_gstring(g);
}



#ifdef USE_READLINE
/*************************************************
*         Load readline() functions              *
*************************************************/

/* This function is called from testing executions that read data from stdin,
but only when running as the calling user. Currently, only -be does this. The
function loads the readline() function library and passes back the functions.
On some systems, it needs the curses library, so load that too, but try without
it if loading fails. All this functionality has to be requested at build time.

Arguments:
  fn_readline_ptr   pointer to where to put the readline pointer
  fn_addhist_ptr    pointer to where to put the addhistory function

Returns:            the dlopen handle or NULL on failure
*/

static void *
set_readline(char * (**fn_readline_ptr)(const char *),
             void   (**fn_addhist_ptr)(const char *))
{
void *dlhandle;
void *dlhandle_curses = dlopen("libcurses." DYNLIB_FN_EXT, RTLD_GLOBAL|RTLD_LAZY);

dlhandle = dlopen("libreadline." DYNLIB_FN_EXT, RTLD_GLOBAL|RTLD_NOW);
if (dlhandle_curses != NULL) dlclose(dlhandle_curses);

if (dlhandle != NULL)
  {
  /* Checked manual pages; at least in GNU Readline 6.1, the prototypes are:
   *   char * readline (const char *prompt);
   *   void add_history (const char *string);
   */
  *fn_readline_ptr = (char *(*)(const char*))dlsym(dlhandle, "readline");
  *fn_addhist_ptr = (void(*)(const char*))dlsym(dlhandle, "add_history");
  }
else
  {
  DEBUG(D_any) debug_printf("failed to load readline: %s\n", dlerror());
  }

return dlhandle;
}
#endif



/*************************************************
*    Get a line from stdin for testing things    *
*************************************************/

/* This function is called when running tests that can take a number of lines
of input (for example, -be and -bt). It handles continuations and trailing
spaces. And prompting and a blank line output on eof. If readline() is in use,
the arguments are non-NULL and provide the relevant functions.

Arguments:
  fn_readline   readline function or NULL
  fn_addhist    addhist function or NULL

Returns:        pointer to dynamic memory, or NULL at end of file
*/

static uschar *
get_stdinput(char *(*fn_readline)(const char *), void(*fn_addhist)(const char *))
{
int i;
gstring * g = NULL;

if (!fn_readline) { printf("> "); fflush(stdout); }

for (i = 0;; i++)
  {
  uschar buffer[1024];
  uschar *p, *ss;

  #ifdef USE_READLINE
  char *readline_line = NULL;
  if (fn_readline != NULL)
    {
    if ((readline_line = fn_readline((i > 0)? "":"> ")) == NULL) break;
    if (*readline_line != 0 && fn_addhist != NULL) fn_addhist(readline_line);
    p = US readline_line;
    }
  else
  #endif

  /* readline() not in use */

    {
    if (Ufgets(buffer, sizeof(buffer), stdin) == NULL) break;
    p = buffer;
    }

  /* Handle the line */

  ss = p + (int)Ustrlen(p);
  while (ss > p && isspace(ss[-1])) ss--;

  if (i > 0)
    {
    while (p < ss && isspace(*p)) p++;   /* leading space after cont */
    }

  g = string_catn(g, p, ss - p);

  #ifdef USE_READLINE
  if (fn_readline) free(readline_line);
  #endif

  /* g can only be NULL if ss==p */
  if (ss == p || g->s[g->ptr-1] != '\\')
    break;

  --g->ptr;
  (void) string_from_gstring(g);
  }

if (!g) printf("\n");
return string_from_gstring(g);
}



/*************************************************
*    Output usage information for the program    *
*************************************************/

/* This function is called when there are no recipients
   or a specific --help argument was added.

Arguments:
  progname      information on what name we were called by

Returns:        DOES NOT RETURN
*/

static void
exim_usage(uschar *progname)
{

/* Handle specific program invocation variants */
if (Ustrcmp(progname, US"-mailq") == 0)
  exim_fail(
    "mailq - list the contents of the mail queue\n\n"
    "For a list of options, see the Exim documentation.\n");

/* Generic usage - we output this whatever happens */
exim_fail(
  "Exim is a Mail Transfer Agent. It is normally called by Mail User Agents,\n"
  "not directly from a shell command line. Options and/or arguments control\n"
  "what it does when called. For a list of options, see the Exim documentation.\n");
}



/*************************************************
*    Validate that the macros given are okay     *
*************************************************/

/* Typically, Exim will drop privileges if macros are supplied.  In some
cases, we want to not do so.

Arguments:    opt_D_used - true if the commandline had a "-D" option
Returns:      true if trusted, false otherwise
*/

static BOOL
macros_trusted(BOOL opt_D_used)
{
#ifdef WHITELIST_D_MACROS
macro_item *m;
uschar *whitelisted, *end, *p, **whites, **w;
int white_count, i, n;
size_t len;
BOOL prev_char_item, found;
#endif

if (!opt_D_used)
  return TRUE;
#ifndef WHITELIST_D_MACROS
return FALSE;
#else

/* We only trust -D overrides for some invoking users:
root, the exim run-time user, the optional config owner user.
I don't know why config-owner would be needed, but since they can own the
config files anyway, there's no security risk to letting them override -D. */
if ( ! ((real_uid == root_uid)
     || (real_uid == exim_uid)
#ifdef CONFIGURE_OWNER
     || (real_uid == config_uid)
#endif
   ))
  {
  debug_printf("macros_trusted rejecting macros for uid %d\n", (int) real_uid);
  return FALSE;
  }

/* Get a list of macros which are whitelisted */
whitelisted = string_copy_malloc(US WHITELIST_D_MACROS);
prev_char_item = FALSE;
white_count = 0;
for (p = whitelisted; *p != '\0'; ++p)
  {
  if (*p == ':' || isspace(*p))
    {
    *p = '\0';
    if (prev_char_item)
      ++white_count;
    prev_char_item = FALSE;
    continue;
    }
  if (!prev_char_item)
    prev_char_item = TRUE;
  }
end = p;
if (prev_char_item)
  ++white_count;
if (!white_count)
  return FALSE;
whites = store_malloc(sizeof(uschar *) * (white_count+1));
for (p = whitelisted, i = 0; (p != end) && (i < white_count); ++p)
  {
  if (*p != '\0')
    {
    whites[i++] = p;
    if (i == white_count)
      break;
    while (*p != '\0' && p < end)
      ++p;
    }
  }
whites[i] = NULL;

/* The list of commandline macros should be very short.
Accept the N*M complexity. */
for (m = macros_user; m; m = m->next) if (m->command_line)
  {
  found = FALSE;
  for (w = whites; *w; ++w)
    if (Ustrcmp(*w, m->name) == 0)
      {
      found = TRUE;
      break;
      }
  if (!found)
    return FALSE;
  if (!m->replacement)
    continue;
  if ((len = m->replen) == 0)
    continue;
  n = pcre_exec(regex_whitelisted_macro, NULL, CS m->replacement, len,
   0, PCRE_EOPT, NULL, 0);
  if (n < 0)
    {
    if (n != PCRE_ERROR_NOMATCH)
      debug_printf("macros_trusted checking %s returned %d\n", m->name, n);
    return FALSE;
    }
  }
DEBUG(D_any) debug_printf("macros_trusted overridden to true by whitelisting\n");
return TRUE;
#endif
}


/*************************************************
*          Expansion testing			 *
*************************************************/

/* Expand and print one item, doing macro-processing.

Arguments:
  item		line for expansion
*/

static void
expansion_test_line(uschar * line)
{
int len;
BOOL dummy_macexp;

Ustrncpy(big_buffer, line, big_buffer_size);
big_buffer[big_buffer_size-1] = '\0';
len = Ustrlen(big_buffer);

(void) macros_expand(0, &len, &dummy_macexp);

if (isupper(big_buffer[0]))
  {
  if (macro_read_assignment(big_buffer))
    printf("Defined macro '%s'\n", mlast->name);
  }
else
  if ((line = expand_string(big_buffer))) printf("%s\n", CS line);
  else printf("Failed: %s\n", expand_string_message);
}



/*************************************************
*          Entry point and high-level code       *
*************************************************/

/* Entry point for the Exim mailer. Analyse the arguments and arrange to take
the appropriate action. All the necessary functions are present in the one
binary. I originally thought one should split it up, but it turns out that so
much of the apparatus is needed in each chunk that one might as well just have
it all available all the time, which then makes the coding easier as well.

Arguments:
  argc      count of entries in argv
  argv      argument strings, with argv[0] being the program name

Returns:    EXIT_SUCCESS if terminated successfully
            EXIT_FAILURE otherwise, except when a message has been sent
              to the sender, and -oee was given
*/

int
main(int argc, char **cargv)
{
uschar **argv = USS cargv;
int  arg_receive_timeout = -1;
int  arg_smtp_receive_timeout = -1;
int  arg_error_handling = error_handling;
int  filter_sfd = -1;
int  filter_ufd = -1;
int  group_count;
int  i, rv;
int  list_queue_option = 0;
int  msg_action = 0;
int  msg_action_arg = -1;
int  namelen = (argv[0] == NULL)? 0 : Ustrlen(argv[0]);
int  queue_only_reason = 0;
#ifdef EXIM_PERL
int  perl_start_option = 0;
#endif
int  recipients_arg = argc;
int  sender_address_domain = 0;
int  test_retry_arg = -1;
int  test_rewrite_arg = -1;
gid_t original_egid;
BOOL arg_queue_only = FALSE;
BOOL bi_option = FALSE;
BOOL checking = FALSE;
BOOL count_queue = FALSE;
BOOL expansion_test = FALSE;
BOOL extract_recipients = FALSE;
BOOL flag_G = FALSE;
BOOL flag_n = FALSE;
BOOL forced_delivery = FALSE;
BOOL f_end_dot = FALSE;
BOOL deliver_give_up = FALSE;
BOOL list_queue = FALSE;
BOOL list_options = FALSE;
BOOL list_config = FALSE;
BOOL local_queue_only;
BOOL more = TRUE;
BOOL one_msg_action = FALSE;
BOOL opt_D_used = FALSE;
BOOL queue_only_set = FALSE;
BOOL receiving_message = TRUE;
BOOL sender_ident_set = FALSE;
BOOL session_local_queue_only;
BOOL unprivileged;
BOOL removed_privilege = FALSE;
BOOL usage_wanted = FALSE;
BOOL verify_address_mode = FALSE;
BOOL verify_as_sender = FALSE;
BOOL version_printed = FALSE;
uschar *alias_arg = NULL;
uschar *called_as = US"";
uschar *cmdline_syslog_name = NULL;
uschar *start_queue_run_id = NULL;
uschar *stop_queue_run_id = NULL;
uschar *expansion_test_message = NULL;
uschar *ftest_domain = NULL;
uschar *ftest_localpart = NULL;
uschar *ftest_prefix = NULL;
uschar *ftest_suffix = NULL;
uschar *log_oneline = NULL;
uschar *malware_test_file = NULL;
uschar *real_sender_address;
uschar *originator_home = US"/";
size_t sz;
void *reset_point;

struct passwd *pw;
struct stat statbuf;
pid_t passed_qr_pid = (pid_t)0;
int passed_qr_pipe = -1;
gid_t group_list[EXIM_GROUPLIST_SIZE];

/* For the -bI: flag */
enum commandline_info info_flag = CMDINFO_NONE;
BOOL info_stdout = FALSE;

/* Possible options for -R and -S */

static uschar *rsopts[] = { US"f", US"ff", US"r", US"rf", US"rff" };

/* Need to define this in case we need to change the environment in order
to get rid of a bogus time zone. We have to make it char rather than uschar
because some OS define it in /usr/include/unistd.h. */

extern char **environ;

/* If the Exim user and/or group and/or the configuration file owner/group were
defined by ref:name at build time, we must now find the actual uid/gid values.
This is a feature to make the lives of binary distributors easier. */

#ifdef EXIM_USERNAME
if (route_finduser(US EXIM_USERNAME, &pw, &exim_uid))
  {
  if (exim_uid == 0)
    exim_fail("exim: refusing to run with uid 0 for \"%s\"\n", EXIM_USERNAME);

  /* If ref:name uses a number as the name, route_finduser() returns
  TRUE with exim_uid set and pw coerced to NULL. */
  if (pw)
    exim_gid = pw->pw_gid;
#ifndef EXIM_GROUPNAME
  else
    exim_fail(
        "exim: ref:name should specify a usercode, not a group.\n"
        "exim: can't let you get away with it unless you also specify a group.\n");
#endif
  }
else
  exim_fail("exim: failed to find uid for user name \"%s\"\n", EXIM_USERNAME);
#endif

#ifdef EXIM_GROUPNAME
if (!route_findgroup(US EXIM_GROUPNAME, &exim_gid))
  exim_fail("exim: failed to find gid for group name \"%s\"\n", EXIM_GROUPNAME);
#endif

#ifdef CONFIGURE_OWNERNAME
if (!route_finduser(US CONFIGURE_OWNERNAME, NULL, &config_uid))
  exim_fail("exim: failed to find uid for user name \"%s\"\n",
    CONFIGURE_OWNERNAME);
#endif

/* We default the system_filter_user to be the Exim run-time user, as a
sane non-root value. */
system_filter_uid = exim_uid;

#ifdef CONFIGURE_GROUPNAME
if (!route_findgroup(US CONFIGURE_GROUPNAME, &config_gid))
  exim_fail("exim: failed to find gid for group name \"%s\"\n",
    CONFIGURE_GROUPNAME);
#endif

/* In the Cygwin environment, some initialization used to need doing.
It was fudged in by means of this macro; now no longer but we'll leave
it in case of others. */

#ifdef OS_INIT
OS_INIT
#endif

/* Check a field which is patched when we are running Exim within its
testing harness; do a fast initial check, and then the whole thing. */

f.running_in_test_harness =
  *running_status == '<' && Ustrcmp(running_status, "<<<testing>>>") == 0;
if (f.running_in_test_harness)
  debug_store = TRUE;

/* The C standard says that the equivalent of setlocale(LC_ALL, "C") is obeyed
at the start of a program; however, it seems that some environments do not
follow this. A "strange" locale can affect the formatting of timestamps, so we
make quite sure. */

setlocale(LC_ALL, "C");

/* Set up the default handler for timing using alarm(). */

os_non_restarting_signal(SIGALRM, sigalrm_handler);

/* Ensure we have a buffer for constructing log entries. Use malloc directly,
because store_malloc writes a log entry on failure. */

if (!(log_buffer = US malloc(LOG_BUFFER_SIZE)))
  exim_fail("exim: failed to get store for log buffer\n");

/* Initialize the default log options. */

bits_set(log_selector, log_selector_size, log_default);

/* Set log_stderr to stderr, provided that stderr exists. This gets reset to
NULL when the daemon is run and the file is closed. We have to use this
indirection, because some systems don't allow writing to the variable "stderr".
*/

if (fstat(fileno(stderr), &statbuf) >= 0) log_stderr = stderr;

/* Arrange for the PCRE regex library to use our store functions. Note that
the normal calls are actually macros that add additional arguments for
debugging purposes so we have to assign specially constructed functions here.
The default is to use store in the stacking pool, but this is overridden in the
regex_must_compile() function. */

pcre_malloc = function_store_get;
pcre_free = function_dummy_free;

/* Ensure there is a big buffer for temporary use in several places. It is put
in malloc store so that it can be freed for enlargement if necessary. */

big_buffer = store_malloc(big_buffer_size);

/* Set up the handler for the data request signal, and set the initial
descriptive text. */

set_process_info("initializing");
os_restarting_signal(SIGUSR1, usr1_handler);

/* If running in a dockerized environment, the TERM signal is only
delegated to the PID 1 if we request it by setting an signal handler */
if (getpid() == 1) signal(SIGTERM, term_handler);

/* SIGHUP is used to get the daemon to reconfigure. It gets set as appropriate
in the daemon code. For the rest of Exim's uses, we ignore it. */

signal(SIGHUP, SIG_IGN);

/* We don't want to die on pipe errors as the code is written to handle
the write error instead. */

signal(SIGPIPE, SIG_IGN);

/* Under some circumstance on some OS, Exim can get called with SIGCHLD
set to SIG_IGN. This causes subprocesses that complete before the parent
process waits for them not to hang around, so when Exim calls wait(), nothing
is there. The wait() code has been made robust against this, but let's ensure
that SIGCHLD is set to SIG_DFL, because it's tidier to wait and get a process
ending status. We use sigaction rather than plain signal() on those OS where
SA_NOCLDWAIT exists, because we want to be sure it is turned off. (There was a
problem on AIX with this.) */

#ifdef SA_NOCLDWAIT
  {
  struct sigaction act;
  act.sa_handler = SIG_DFL;
  sigemptyset(&(act.sa_mask));
  act.sa_flags = 0;
  sigaction(SIGCHLD, &act, NULL);
  }
#else
signal(SIGCHLD, SIG_DFL);
#endif

/* Save the arguments for use if we re-exec exim as a daemon after receiving
SIGHUP. */

sighup_argv = argv;

/* Set up the version number. Set up the leading 'E' for the external form of
message ids, set the pointer to the internal form, and initialize it to
indicate no message being processed. */

version_init();
message_id_option[0] = '-';
message_id_external = message_id_option + 1;
message_id_external[0] = 'E';
message_id = message_id_external + 1;
message_id[0] = 0;

/* Set the umask to zero so that any files Exim creates using open() are
created with the modes that it specifies. NOTE: Files created with fopen() have
a problem, which was not recognized till rather late (February 2006). With this
umask, such files will be world writeable. (They are all content scanning files
in the spool directory, which isn't world-accessible, so this is not a
disaster, but it's untidy.) I don't want to change this overall setting,
however, because it will interact badly with the open() calls. Instead, there's
now a function called modefopen() that fiddles with the umask while calling
fopen(). */

(void)umask(0);

/* Precompile the regular expression for matching a message id. Keep this in
step with the code that generates ids in the accept.c module. We need to do
this here, because the -M options check their arguments for syntactic validity
using mac_ismsgid, which uses this. */

regex_ismsgid =
  regex_must_compile(US"^(?:[^\\W_]{6}-){2}[^\\W_]{2}$", FALSE, TRUE);

/* Precompile the regular expression that is used for matching an SMTP error
code, possibly extended, at the start of an error message. Note that the
terminating whitespace character is included. */

regex_smtp_code =
  regex_must_compile(US"^\\d\\d\\d\\s(?:\\d\\.\\d\\d?\\d?\\.\\d\\d?\\d?\\s)?",
    FALSE, TRUE);

#ifdef WHITELIST_D_MACROS
/* Precompile the regular expression used to filter the content of macros
given to -D for permissibility. */

regex_whitelisted_macro =
  regex_must_compile(US"^[A-Za-z0-9_/.-]*$", FALSE, TRUE);
#endif

for (i = 0; i < REGEX_VARS; i++) regex_vars[i] = NULL;

/* If the program is called as "mailq" treat it as equivalent to "exim -bp";
this seems to be a generally accepted convention, since one finds symbolic
links called "mailq" in standard OS configurations. */

if ((namelen == 5 && Ustrcmp(argv[0], "mailq") == 0) ||
    (namelen  > 5 && Ustrncmp(argv[0] + namelen - 6, "/mailq", 6) == 0))
  {
  list_queue = TRUE;
  receiving_message = FALSE;
  called_as = US"-mailq";
  }

/* If the program is called as "rmail" treat it as equivalent to
"exim -i -oee", thus allowing UUCP messages to be input using non-SMTP mode,
i.e. preventing a single dot on a line from terminating the message, and
returning with zero return code, even in cases of error (provided an error
message has been sent). */

if ((namelen == 5 && Ustrcmp(argv[0], "rmail") == 0) ||
    (namelen  > 5 && Ustrncmp(argv[0] + namelen - 6, "/rmail", 6) == 0))
  {
  f.dot_ends = FALSE;
  called_as = US"-rmail";
  errors_sender_rc = EXIT_SUCCESS;
  }

/* If the program is called as "rsmtp" treat it as equivalent to "exim -bS";
this is a smail convention. */

if ((namelen == 5 && Ustrcmp(argv[0], "rsmtp") == 0) ||
    (namelen  > 5 && Ustrncmp(argv[0] + namelen - 6, "/rsmtp", 6) == 0))
  {
  smtp_input = smtp_batched_input = TRUE;
  called_as = US"-rsmtp";
  }

/* If the program is called as "runq" treat it as equivalent to "exim -q";
this is a smail convention. */

if ((namelen == 4 && Ustrcmp(argv[0], "runq") == 0) ||
    (namelen  > 4 && Ustrncmp(argv[0] + namelen - 5, "/runq", 5) == 0))
  {
  queue_interval = 0;
  receiving_message = FALSE;
  called_as = US"-runq";
  }

/* If the program is called as "newaliases" treat it as equivalent to
"exim -bi"; this is a sendmail convention. */

if ((namelen == 10 && Ustrcmp(argv[0], "newaliases") == 0) ||
    (namelen  > 10 && Ustrncmp(argv[0] + namelen - 11, "/newaliases", 11) == 0))
  {
  bi_option = TRUE;
  receiving_message = FALSE;
  called_as = US"-newaliases";
  }

/* Save the original effective uid for a couple of uses later. It should
normally be root, but in some esoteric environments it may not be. */

original_euid = geteuid();
original_egid = getegid();

/* Get the real uid and gid. If the caller is root, force the effective uid/gid
to be the same as the real ones. This makes a difference only if Exim is setuid
(or setgid) to something other than root, which could be the case in some
special configurations. */

real_uid = getuid();
real_gid = getgid();

if (real_uid == root_uid)
  {
  if ((rv = setgid(real_gid)))
    exim_fail("exim: setgid(%ld) failed: %s\n",
        (long int)real_gid, strerror(errno));
  if ((rv = setuid(real_uid)))
    exim_fail("exim: setuid(%ld) failed: %s\n",
        (long int)real_uid, strerror(errno));
  }

/* If neither the original real uid nor the original euid was root, Exim is
running in an unprivileged state. */

unprivileged = (real_uid != root_uid && original_euid != root_uid);

/* Scan the program's arguments. Some can be dealt with right away; others are
simply recorded for checking and handling afterwards. Do a high-level switch
on the second character (the one after '-'), to save some effort. */

for (i = 1; i < argc; i++)
  {
  BOOL badarg = FALSE;
  uschar *arg = argv[i];
  uschar *argrest;
  int switchchar;

  /* An argument not starting with '-' is the start of a recipients list;
  break out of the options-scanning loop. */

  if (arg[0] != '-')
    {
    recipients_arg = i;
    break;
    }

  /* An option consisting of -- terminates the options */

  if (Ustrcmp(arg, "--") == 0)
    {
    recipients_arg = i + 1;
    break;
    }

  /* Handle flagged options */

  switchchar = arg[1];
  argrest = arg+2;

  /* Make all -ex options synonymous with -oex arguments, since that
  is assumed by various callers. Also make -qR options synonymous with -R
  options, as that seems to be required as well. Allow for -qqR too, and
  the same for -S options. */

  if (Ustrncmp(arg+1, "oe", 2) == 0 ||
      Ustrncmp(arg+1, "qR", 2) == 0 ||
      Ustrncmp(arg+1, "qS", 2) == 0)
    {
    switchchar = arg[2];
    argrest++;
    }
  else if (Ustrncmp(arg+1, "qqR", 3) == 0 || Ustrncmp(arg+1, "qqS", 3) == 0)
    {
    switchchar = arg[3];
    argrest += 2;
    f.queue_2stage = TRUE;
    }

  /* Make -r synonymous with -f, since it is a documented alias */

  else if (arg[1] == 'r') switchchar = 'f';

  /* Make -ov synonymous with -v */

  else if (Ustrcmp(arg, "-ov") == 0)
    {
    switchchar = 'v';
    argrest++;
    }

  /* deal with --option_aliases */
  else if (switchchar == '-')
    {
    if (Ustrcmp(argrest, "help") == 0)
      {
      usage_wanted = TRUE;
      break;
      }
    else if (Ustrcmp(argrest, "version") == 0)
      {
      switchchar = 'b';
      argrest = US"V";
      }
    }

  /* High-level switch on active initial letter */

  switch(switchchar)
    {

    /* sendmail uses -Ac and -Am to control which .cf file is used;
    we ignore them. */
    case 'A':
    if (*argrest == '\0') { badarg = TRUE; break; }
    else
      {
      BOOL ignore = FALSE;
      switch (*argrest)
        {
        case 'c':
        case 'm':
          if (*(argrest + 1) == '\0')
            ignore = TRUE;
          break;
        }
      if (!ignore) { badarg = TRUE; break; }
      }
    break;

    /* -Btype is a sendmail option for 7bit/8bit setting. Exim is 8-bit clean
    so has no need of it. */

    case 'B':
    if (*argrest == 0) i++;       /* Skip over the type */
    break;


    case 'b':
    receiving_message = FALSE;    /* Reset TRUE for -bm, -bS, -bs below */

    /* -bd:  Run in daemon mode, awaiting SMTP connections.
       -bdf: Ditto, but in the foreground.
    */

    if (*argrest == 'd')
      {
      f.daemon_listen = TRUE;
      if (*(++argrest) == 'f') f.background_daemon = FALSE;
        else if (*argrest != 0) { badarg = TRUE; break; }
      }

    /* -be:  Run in expansion test mode
       -bem: Ditto, but read a message from a file first
    */

    else if (*argrest == 'e')
      {
      expansion_test = checking = TRUE;
      if (argrest[1] == 'm')
        {
        if (++i >= argc) { badarg = TRUE; break; }
        expansion_test_message = argv[i];
        argrest++;
        }
      if (argrest[1] != 0) { badarg = TRUE; break; }
      }

    /* -bF:  Run system filter test */

    else if (*argrest == 'F')
      {
      filter_test |= checking = FTEST_SYSTEM;
      if (*(++argrest) != 0) { badarg = TRUE; break; }
      if (++i < argc) filter_test_sfile = argv[i]; else
        exim_fail("exim: file name expected after %s\n", argv[i-1]);
      }

    /* -bf:  Run user filter test
       -bfd: Set domain for filter testing
       -bfl: Set local part for filter testing
       -bfp: Set prefix for filter testing
       -bfs: Set suffix for filter testing
    */

    else if (*argrest == 'f')
      {
      if (*(++argrest) == 0)
        {
        filter_test |= checking = FTEST_USER;
        if (++i < argc) filter_test_ufile = argv[i]; else
          exim_fail("exim: file name expected after %s\n", argv[i-1]);
        }
      else
        {
        if (++i >= argc)
          exim_fail("exim: string expected after %s\n", arg);
        if (Ustrcmp(argrest, "d") == 0) ftest_domain = argv[i];
        else if (Ustrcmp(argrest, "l") == 0) ftest_localpart = argv[i];
        else if (Ustrcmp(argrest, "p") == 0) ftest_prefix = argv[i];
        else if (Ustrcmp(argrest, "s") == 0) ftest_suffix = argv[i];
        else { badarg = TRUE; break; }
        }
      }

    /* -bh: Host checking - an IP address must follow. */

    else if (Ustrcmp(argrest, "h") == 0 || Ustrcmp(argrest, "hc") == 0)
      {
      if (++i >= argc) { badarg = TRUE; break; }
      sender_host_address = argv[i];
      host_checking = checking = f.log_testing_mode = TRUE;
      f.host_checking_callout = argrest[1] == 'c';
      message_logs = FALSE;
      }

    /* -bi: This option is used by sendmail to initialize *the* alias file,
    though it has the -oA option to specify a different file. Exim has no
    concept of *the* alias file, but since Sun's YP make script calls
    sendmail this way, some support must be provided. */

    else if (Ustrcmp(argrest, "i") == 0) bi_option = TRUE;

    /* -bI: provide information, of the type to follow after a colon.
    This is an Exim flag. */

    else if (argrest[0] == 'I' && Ustrlen(argrest) >= 2 && argrest[1] == ':')
      {
      uschar *p = &argrest[2];
      info_flag = CMDINFO_HELP;
      if (Ustrlen(p))
        {
        if (strcmpic(p, CUS"sieve") == 0)
          {
          info_flag = CMDINFO_SIEVE;
          info_stdout = TRUE;
          }
        else if (strcmpic(p, CUS"dscp") == 0)
          {
          info_flag = CMDINFO_DSCP;
          info_stdout = TRUE;
          }
        else if (strcmpic(p, CUS"help") == 0)
          {
          info_stdout = TRUE;
          }
        }
      }

    /* -bm: Accept and deliver message - the default option. Reinstate
    receiving_message, which got turned off for all -b options. */

    else if (Ustrcmp(argrest, "m") == 0) receiving_message = TRUE;

    /* -bmalware: test the filename given for malware */

    else if (Ustrcmp(argrest, "malware") == 0)
      {
      if (++i >= argc) { badarg = TRUE; break; }
      checking = TRUE;
      malware_test_file = argv[i];
      }

    /* -bnq: For locally originating messages, do not qualify unqualified
    addresses. In the envelope, this causes errors; in header lines they
    just get left. */

    else if (Ustrcmp(argrest, "nq") == 0)
      {
      f.allow_unqualified_sender = FALSE;
      f.allow_unqualified_recipient = FALSE;
      }

    /* -bpxx: List the contents of the mail queue, in various forms. If
    the option is -bpc, just a queue count is needed. Otherwise, if the
    first letter after p is r, then order is random. */

    else if (*argrest == 'p')
      {
      if (*(++argrest) == 'c')
        {
        count_queue = TRUE;
        if (*(++argrest) != 0) badarg = TRUE;
        break;
        }

      if (*argrest == 'r')
        {
        list_queue_option = 8;
        argrest++;
        }
      else list_queue_option = 0;

      list_queue = TRUE;

      /* -bp: List the contents of the mail queue, top-level only */

      if (*argrest == 0) {}

      /* -bpu: List the contents of the mail queue, top-level undelivered */

      else if (Ustrcmp(argrest, "u") == 0) list_queue_option += 1;

      /* -bpa: List the contents of the mail queue, including all delivered */

      else if (Ustrcmp(argrest, "a") == 0) list_queue_option += 2;

      /* Unknown after -bp[r] */

      else
        {
        badarg = TRUE;
        break;
        }
      }


    /* -bP: List the configuration variables given as the address list.
    Force -v, so configuration errors get displayed. */

    else if (Ustrcmp(argrest, "P") == 0)
      {
      /* -bP config: we need to setup here, because later,
       * when list_options is checked, the config is read already */
      if (argv[i+1] && Ustrcmp(argv[i+1], "config") == 0)
        {
        list_config = TRUE;
        readconf_save_config(version_string);
        }
      else
        {
        list_options = TRUE;
        debug_selector |= D_v;
        debug_file = stderr;
        }
      }

    /* -brt: Test retry configuration lookup */

    else if (Ustrcmp(argrest, "rt") == 0)
      {
      checking = TRUE;
      test_retry_arg = i + 1;
      goto END_ARG;
      }

    /* -brw: Test rewrite configuration */

    else if (Ustrcmp(argrest, "rw") == 0)
      {
      checking = TRUE;
      test_rewrite_arg = i + 1;
      goto END_ARG;
      }

    /* -bS: Read SMTP commands on standard input, but produce no replies -
    all errors are reported by sending messages. */

    else if (Ustrcmp(argrest, "S") == 0)
      smtp_input = smtp_batched_input = receiving_message = TRUE;

    /* -bs: Read SMTP commands on standard input and produce SMTP replies
    on standard output. */

    else if (Ustrcmp(argrest, "s") == 0) smtp_input = receiving_message = TRUE;

    /* -bt: address testing mode */

    else if (Ustrcmp(argrest, "t") == 0)
      f.address_test_mode = checking = f.log_testing_mode = TRUE;

    /* -bv: verify addresses */

    else if (Ustrcmp(argrest, "v") == 0)
      verify_address_mode = checking = f.log_testing_mode = TRUE;

    /* -bvs: verify sender addresses */

    else if (Ustrcmp(argrest, "vs") == 0)
      {
      verify_address_mode = checking = f.log_testing_mode = TRUE;
      verify_as_sender = TRUE;
      }

    /* -bV: Print version string and support details */

    else if (Ustrcmp(argrest, "V") == 0)
      {
      printf("Exim version %s #%s built %s\n", version_string,
        version_cnumber, version_date);
      printf("%s\n", CS version_copyright);
      version_printed = TRUE;
      show_whats_supported(stdout);
      f.log_testing_mode = TRUE;
      }

    /* -bw: inetd wait mode, accept a listening socket as stdin */

    else if (*argrest == 'w')
      {
      f.inetd_wait_mode = TRUE;
      f.background_daemon = FALSE;
      f.daemon_listen = TRUE;
      if (*(++argrest) != '\0')
        if ((inetd_wait_timeout = readconf_readtime(argrest, 0, FALSE)) <= 0)
          exim_fail("exim: bad time value %s: abandoned\n", argv[i]);
      }

    else badarg = TRUE;
    break;


    /* -C: change configuration file list; ignore if it isn't really
    a change! Enforce a prefix check if required. */

    case 'C':
    if (*argrest == 0)
      {
      if(++i < argc) argrest = argv[i]; else
        { badarg = TRUE; break; }
      }
    if (Ustrcmp(config_main_filelist, argrest) != 0)
      {
      #ifdef ALT_CONFIG_PREFIX
      int sep = 0;
      int len = Ustrlen(ALT_CONFIG_PREFIX);
      const uschar *list = argrest;
      uschar *filename;
      while((filename = string_nextinlist(&list, &sep, big_buffer,
             big_buffer_size)) != NULL)
        {
        if ((Ustrlen(filename) < len ||
             Ustrncmp(filename, ALT_CONFIG_PREFIX, len) != 0 ||
             Ustrstr(filename, "/../") != NULL) &&
             (Ustrcmp(filename, "/dev/null") != 0 || real_uid != root_uid))
          exim_fail("-C Permission denied\n");
        }
      #endif
      if (real_uid != root_uid)
        {
        #ifdef TRUSTED_CONFIG_LIST

        if (real_uid != exim_uid
            #ifdef CONFIGURE_OWNER
            && real_uid != config_uid
            #endif
            )
          f.trusted_config = FALSE;
        else
          {
          FILE *trust_list = Ufopen(TRUSTED_CONFIG_LIST, "rb");
          if (trust_list)
            {
            struct stat statbuf;

            if (fstat(fileno(trust_list), &statbuf) != 0 ||
                (statbuf.st_uid != root_uid        /* owner not root */
                 #ifdef CONFIGURE_OWNER
                 && statbuf.st_uid != config_uid   /* owner not the special one */
                 #endif
                   ) ||                            /* or */
                (statbuf.st_gid != root_gid        /* group not root */
                 #ifdef CONFIGURE_GROUP
                 && statbuf.st_gid != config_gid   /* group not the special one */
                 #endif
                 && (statbuf.st_mode & 020) != 0   /* group writeable */
                   ) ||                            /* or */
                (statbuf.st_mode & 2) != 0)        /* world writeable */
              {
              f.trusted_config = FALSE;
              fclose(trust_list);
              }
	    else
              {
              /* Well, the trust list at least is up to scratch... */
              void *reset_point = store_get(0);
              uschar *trusted_configs[32];
              int nr_configs = 0;
              int i = 0;

              while (Ufgets(big_buffer, big_buffer_size, trust_list))
                {
                uschar *start = big_buffer, *nl;
                while (*start && isspace(*start))
                start++;
                if (*start != '/')
                  continue;
                nl = Ustrchr(start, '\n');
                if (nl)
                  *nl = 0;
                trusted_configs[nr_configs++] = string_copy(start);
                if (nr_configs == 32)
                  break;
                }
              fclose(trust_list);

              if (nr_configs)
                {
                int sep = 0;
                const uschar *list = argrest;
                uschar *filename;
                while (f.trusted_config && (filename = string_nextinlist(&list,
                        &sep, big_buffer, big_buffer_size)) != NULL)
                  {
                  for (i=0; i < nr_configs; i++)
                    {
                    if (Ustrcmp(filename, trusted_configs[i]) == 0)
                      break;
                    }
                  if (i == nr_configs)
                    {
                    f.trusted_config = FALSE;
                    break;
                    }
                  }
                store_reset(reset_point);
                }
              else
                {
                /* No valid prefixes found in trust_list file. */
                f.trusted_config = FALSE;
                }
              }
	    }
          else
            {
            /* Could not open trust_list file. */
            f.trusted_config = FALSE;
            }
          }
      #else
        /* Not root; don't trust config */
        f.trusted_config = FALSE;
      #endif
        }

      config_main_filelist = argrest;
      f.config_changed = TRUE;
      }
    break;


    /* -D: set up a macro definition */

    case 'D':
#ifdef DISABLE_D_OPTION
      exim_fail("exim: -D is not available in this Exim binary\n");
#else
      {
      int ptr = 0;
      macro_item *m;
      uschar name[24];
      uschar *s = argrest;

      opt_D_used = TRUE;
      while (isspace(*s)) s++;

      if (*s < 'A' || *s > 'Z')
        exim_fail("exim: macro name set by -D must start with "
          "an upper case letter\n");

      while (isalnum(*s) || *s == '_')
        {
        if (ptr < sizeof(name)-1) name[ptr++] = *s;
        s++;
        }
      name[ptr] = 0;
      if (ptr == 0) { badarg = TRUE; break; }
      while (isspace(*s)) s++;
      if (*s != 0)
        {
        if (*s++ != '=') { badarg = TRUE; break; }
        while (isspace(*s)) s++;
        }

      for (m = macros_user; m; m = m->next)
        if (Ustrcmp(m->name, name) == 0)
          exim_fail("exim: duplicated -D in command line\n");

      m = macro_create(name, s, TRUE);

      if (clmacro_count >= MAX_CLMACROS)
        exim_fail("exim: too many -D options on command line\n");
      clmacros[clmacro_count++] = string_sprintf("-D%s=%s", m->name,
        m->replacement);
      }
    #endif
    break;

    /* -d: Set debug level (see also -v below) or set the drop_cr option.
    The latter is now a no-op, retained for compatibility only. If -dd is used,
    debugging subprocesses of the daemon is disabled. */

    case 'd':
    if (Ustrcmp(argrest, "ropcr") == 0)
      {
      /* drop_cr = TRUE; */
      }

    /* Use an intermediate variable so that we don't set debugging while
    decoding the debugging bits. */

    else
      {
      unsigned int selector = D_default;
      debug_selector = 0;
      debug_file = NULL;
      if (*argrest == 'd')
        {
        f.debug_daemon = TRUE;
        argrest++;
        }
      if (*argrest != 0)
        decode_bits(&selector, 1, debug_notall, argrest,
          debug_options, debug_options_count, US"debug", 0);
      debug_selector = selector;
      }
    break;


    /* -E: This is a local error message. This option is not intended for
    external use at all, but is not restricted to trusted callers because it
    does no harm (just suppresses certain error messages) and if Exim is run
    not setuid root it won't always be trusted when it generates error
    messages using this option. If there is a message id following -E, point
    message_reference at it, for logging. */

    case 'E':
    f.local_error_message = TRUE;
    if (mac_ismsgid(argrest)) message_reference = argrest;
    break;


    /* -ex: The vacation program calls sendmail with the undocumented "-eq"
    option, so it looks as if historically the -oex options are also callable
    without the leading -o. So we have to accept them. Before the switch,
    anything starting -oe has been converted to -e. Exim does not support all
    of the sendmail error options. */

    case 'e':
    if (Ustrcmp(argrest, "e") == 0)
      {
      arg_error_handling = ERRORS_SENDER;
      errors_sender_rc = EXIT_SUCCESS;
      }
    else if (Ustrcmp(argrest, "m") == 0) arg_error_handling = ERRORS_SENDER;
    else if (Ustrcmp(argrest, "p") == 0) arg_error_handling = ERRORS_STDERR;
    else if (Ustrcmp(argrest, "q") == 0) arg_error_handling = ERRORS_STDERR;
    else if (Ustrcmp(argrest, "w") == 0) arg_error_handling = ERRORS_SENDER;
    else badarg = TRUE;
    break;


    /* -F: Set sender's full name, used instead of the gecos entry from
    the password file. Since users can usually alter their gecos entries,
    there's no security involved in using this instead. The data can follow
    the -F or be in the next argument. */

    case 'F':
    if (*argrest == 0)
      {
      if(++i < argc) argrest = argv[i]; else
        { badarg = TRUE; break; }
      }
    originator_name = argrest;
    f.sender_name_forced = TRUE;
    break;


    /* -f: Set sender's address - this value is only actually used if Exim is
    run by a trusted user, or if untrusted_set_sender is set and matches the
    address, except that the null address can always be set by any user. The
    test for this happens later, when the value given here is ignored when not
    permitted. For an untrusted user, the actual sender is still put in Sender:
    if it doesn't match the From: header (unless no_local_from_check is set).
    The data can follow the -f or be in the next argument. The -r switch is an
    obsolete form of -f but since there appear to be programs out there that
    use anything that sendmail has ever supported, better accept it - the
    synonymizing is done before the switch above.

    At this stage, we must allow domain literal addresses, because we don't
    know what the setting of allow_domain_literals is yet. Ditto for trailing
    dots and strip_trailing_dot. */

    case 'f':
      {
      int dummy_start, dummy_end;
      uschar *errmess;
      if (*argrest == 0)
        {
        if (i+1 < argc) argrest = argv[++i]; else
          { badarg = TRUE; break; }
        }
      if (*argrest == 0)
        sender_address = string_sprintf("");  /* Ensure writeable memory */
      else
        {
        uschar *temp = argrest + Ustrlen(argrest) - 1;
        while (temp >= argrest && isspace(*temp)) temp--;
        if (temp >= argrest && *temp == '.') f_end_dot = TRUE;
        allow_domain_literals = TRUE;
        strip_trailing_dot = TRUE;
#ifdef SUPPORT_I18N
	allow_utf8_domains = TRUE;
#endif
        sender_address = parse_extract_address(argrest, &errmess,
          &dummy_start, &dummy_end, &sender_address_domain, TRUE);
#ifdef SUPPORT_I18N
	message_smtputf8 =  string_is_utf8(sender_address);
	allow_utf8_domains = FALSE;
#endif
        allow_domain_literals = FALSE;
        strip_trailing_dot = FALSE;
        if (!sender_address)
          exim_fail("exim: bad -f address \"%s\": %s\n", argrest, errmess);
        }
      f.sender_address_forced = TRUE;
      }
    break;

    /* -G: sendmail invocation to specify that it's a gateway submission and
    sendmail may complain about problems instead of fixing them.
    We make it equivalent to an ACL "control = suppress_local_fixups" and do
    not at this time complain about problems. */

    case 'G':
    flag_G = TRUE;
    break;

    /* -h: Set the hop count for an incoming message. Exim does not currently
    support this; it always computes it by counting the Received: headers.
    To put it in will require a change to the spool header file format. */

    case 'h':
    if (*argrest == 0)
      {
      if(++i < argc) argrest = argv[i]; else
        { badarg = TRUE; break; }
      }
    if (!isdigit(*argrest)) badarg = TRUE;
    break;


    /* -i: Set flag so dot doesn't end non-SMTP input (same as -oi, seems
    not to be documented for sendmail but mailx (at least) uses it) */

    case 'i':
    if (*argrest == 0) f.dot_ends = FALSE; else badarg = TRUE;
    break;


    /* -L: set the identifier used for syslog; equivalent to setting
    syslog_processname in the config file, but needs to be an admin option. */

    case 'L':
    if (*argrest == '\0')
      {
      if(++i < argc) argrest = argv[i]; else
        { badarg = TRUE; break; }
      }
    if ((sz = Ustrlen(argrest)) > 32)
      exim_fail("exim: the -L syslog name is too long: \"%s\"\n", argrest);
    if (sz < 1)
      exim_fail("exim: the -L syslog name is too short\n");
    cmdline_syslog_name = argrest;
    break;

    case 'M':
    receiving_message = FALSE;

    /* -MC:  continue delivery of another message via an existing open
    file descriptor. This option is used for an internal call by the
    smtp transport when there is a pending message waiting to go to an
    address to which it has got a connection. Five subsequent arguments are
    required: transport name, host name, IP address, sequence number, and
    message_id. Transports may decline to create new processes if the sequence
    number gets too big. The channel is stdin. This (-MC) must be the last
    argument. There's a subsequent check that the real-uid is privileged.

    If we are running in the test harness. delay for a bit, to let the process
    that set this one up complete. This makes for repeatability of the logging,
    etc. output. */

    if (Ustrcmp(argrest, "C") == 0)
      {
      union sockaddr_46 interface_sock;
      EXIM_SOCKLEN_T size = sizeof(interface_sock);

      if (argc != i + 6)
        exim_fail("exim: too many or too few arguments after -MC\n");

      if (msg_action_arg >= 0)
        exim_fail("exim: incompatible arguments\n");

      continue_transport = argv[++i];
      continue_hostname = argv[++i];
      continue_host_address = argv[++i];
      continue_sequence = Uatoi(argv[++i]);
      msg_action = MSG_DELIVER;
      msg_action_arg = ++i;
      forced_delivery = TRUE;
      queue_run_pid = passed_qr_pid;
      queue_run_pipe = passed_qr_pipe;

      if (!mac_ismsgid(argv[i]))
        exim_fail("exim: malformed message id %s after -MC option\n",
          argv[i]);

      /* Set up $sending_ip_address and $sending_port, unless proxied */

      if (!continue_proxy_cipher)
	if (getsockname(fileno(stdin), (struct sockaddr *)(&interface_sock),
	    &size) == 0)
	  sending_ip_address = host_ntoa(-1, &interface_sock, NULL,
	    &sending_port);
	else
	  exim_fail("exim: getsockname() failed after -MC option: %s\n",
	    strerror(errno));

      if (f.running_in_test_harness) millisleep(500);
      break;
      }

    else if (*argrest == 'C' && argrest[1] && !argrest[2])
      {
      switch(argrest[1])
	{
    /* -MCA: set the smtp_authenticated flag; this is useful only when it
    precedes -MC (see above). The flag indicates that the host to which
    Exim is connected has accepted an AUTH sequence. */

	case 'A': f.smtp_authenticated = TRUE; break;

    /* -MCD: set the smtp_use_dsn flag; this indicates that the host
       that exim is connected to supports the esmtp extension DSN */

	case 'D': smtp_peer_options |= OPTION_DSN; break;

    /* -MCG: set the queue name, to a non-default value */

	case 'G': if (++i < argc) queue_name = string_copy(argv[i]);
		  else badarg = TRUE;
		  break;

    /* -MCK: the peer offered CHUNKING.  Must precede -MC */

	case 'K': smtp_peer_options |= OPTION_CHUNKING; break;

    /* -MCP: set the smtp_use_pipelining flag; this is useful only when
    it preceded -MC (see above) */

	case 'P': smtp_peer_options |= OPTION_PIPE; break;

    /* -MCQ: pass on the pid of the queue-running process that started
    this chain of deliveries and the fd of its synchronizing pipe; this
    is useful only when it precedes -MC (see above) */

	case 'Q': if (++i < argc) passed_qr_pid = (pid_t)(Uatol(argv[i]));
		  else badarg = TRUE;
		  if (++i < argc) passed_qr_pipe = (int)(Uatol(argv[i]));
		  else badarg = TRUE;
		  break;

    /* -MCS: set the smtp_use_size flag; this is useful only when it
    precedes -MC (see above) */

	case 'S': smtp_peer_options |= OPTION_SIZE; break;

#ifdef SUPPORT_TLS
    /* -MCt: similar to -MCT below but the connection is still open
    via a proxy process which handles the TLS context and coding.
    Require three arguments for the proxied local address and port,
    and the TLS cipher.  */

	case 't': if (++i < argc) sending_ip_address = argv[i];
		  else badarg = TRUE;
		  if (++i < argc) sending_port = (int)(Uatol(argv[i]));
		  else badarg = TRUE;
		  if (++i < argc) continue_proxy_cipher = argv[i];
		  else badarg = TRUE;
		  /*FALLTHROUGH*/

    /* -MCT: set the tls_offered flag; this is useful only when it
    precedes -MC (see above). The flag indicates that the host to which
    Exim is connected has offered TLS support. */

	case 'T': smtp_peer_options |= OPTION_TLS; break;
#endif

	default:  badarg = TRUE; break;
	}
      break;
      }

#if defined(SUPPORT_TLS) && defined(EXPERIMENTAL_REQUIRETLS)
    /* -MS   set REQUIRETLS on (new) message */

    else if (*argrest == 'S')
      {
      tls_requiretls |= REQUIRETLS_MSG;
      break;
      }
#endif

    /* -M[x]: various operations on the following list of message ids:
       -M    deliver the messages, ignoring next retry times and thawing
       -Mc   deliver the messages, checking next retry times, no thawing
       -Mf   freeze the messages
       -Mg   give up on the messages
       -Mt   thaw the messages
       -Mrm  remove the messages
    In the above cases, this must be the last option. There are also the
    following options which are followed by a single message id, and which
    act on that message. Some of them use the "recipient" addresses as well.
       -Mar  add recipient(s)
       -Mmad mark all recipients delivered
       -Mmd  mark recipients(s) delivered
       -Mes  edit sender
       -Mset load a message for use with -be
       -Mvb  show body
       -Mvc  show copy (of whole message, in RFC 2822 format)
       -Mvh  show header
       -Mvl  show log
    */

    else if (*argrest == 0)
      {
      msg_action = MSG_DELIVER;
      forced_delivery = f.deliver_force_thaw = TRUE;
      }
    else if (Ustrcmp(argrest, "ar") == 0)
      {
      msg_action = MSG_ADD_RECIPIENT;
      one_msg_action = TRUE;
      }
    else if (Ustrcmp(argrest, "c") == 0)  msg_action = MSG_DELIVER;
    else if (Ustrcmp(argrest, "es") == 0)
      {
      msg_action = MSG_EDIT_SENDER;
      one_msg_action = TRUE;
      }
    else if (Ustrcmp(argrest, "f") == 0)  msg_action = MSG_FREEZE;
    else if (Ustrcmp(argrest, "g") == 0)
      {
      msg_action = MSG_DELIVER;
      deliver_give_up = TRUE;
      }
    else if (Ustrcmp(argrest, "mad") == 0)
      {
      msg_action = MSG_MARK_ALL_DELIVERED;
      }
    else if (Ustrcmp(argrest, "md") == 0)
      {
      msg_action = MSG_MARK_DELIVERED;
      one_msg_action = TRUE;
      }
    else if (Ustrcmp(argrest, "rm") == 0) msg_action = MSG_REMOVE;
    else if (Ustrcmp(argrest, "set") == 0)
      {
      msg_action = MSG_LOAD;
      one_msg_action = TRUE;
      }
    else if (Ustrcmp(argrest, "t") == 0)  msg_action = MSG_THAW;
    else if (Ustrcmp(argrest, "vb") == 0)
      {
      msg_action = MSG_SHOW_BODY;
      one_msg_action = TRUE;
      }
    else if (Ustrcmp(argrest, "vc") == 0)
      {
      msg_action = MSG_SHOW_COPY;
      one_msg_action = TRUE;
      }
    else if (Ustrcmp(argrest, "vh") == 0)
      {
      msg_action = MSG_SHOW_HEADER;
      one_msg_action = TRUE;
      }
    else if (Ustrcmp(argrest, "vl") == 0)
      {
      msg_action = MSG_SHOW_LOG;
      one_msg_action = TRUE;
      }
    else { badarg = TRUE; break; }

    /* All the -Mxx options require at least one message id. */

    msg_action_arg = i + 1;
    if (msg_action_arg >= argc)
      exim_fail("exim: no message ids given after %s option\n", arg);

    /* Some require only message ids to follow */

    if (!one_msg_action)
      {
      int j;
      for (j = msg_action_arg; j < argc; j++) if (!mac_ismsgid(argv[j]))
        exim_fail("exim: malformed message id %s after %s option\n",
          argv[j], arg);
      goto END_ARG;   /* Remaining args are ids */
      }

    /* Others require only one message id, possibly followed by addresses,
    which will be handled as normal arguments. */

    else
      {
      if (!mac_ismsgid(argv[msg_action_arg]))
        exim_fail("exim: malformed message id %s after %s option\n",
          argv[msg_action_arg], arg);
      i++;
      }
    break;


    /* Some programs seem to call the -om option without the leading o;
    for sendmail it askes for "me too". Exim always does this. */

    case 'm':
    if (*argrest != 0) badarg = TRUE;
    break;


    /* -N: don't do delivery - a debugging option that stops transports doing
    their thing. It implies debugging at the D_v level. */

    case 'N':
    if (*argrest == 0)
      {
      f.dont_deliver = TRUE;
      debug_selector |= D_v;
      debug_file = stderr;
      }
    else badarg = TRUE;
    break;


    /* -n: This means "don't alias" in sendmail, apparently.
    For normal invocations, it has no effect.
    It may affect some other options. */

    case 'n':
    flag_n = TRUE;
    break;

    /* -O: Just ignore it. In sendmail, apparently -O option=value means set
    option to the specified value. This form uses long names. We need to handle
    -O option=value and -Ooption=value. */

    case 'O':
    if (*argrest == 0)
      {
      if (++i >= argc)
        exim_fail("exim: string expected after -O\n");
      }
    break;

    case 'o':

    /* -oA: Set an argument for the bi command (sendmail's "alternate alias
    file" option). */

    if (*argrest == 'A')
      {
      alias_arg = argrest + 1;
      if (alias_arg[0] == 0)
        {
        if (i+1 < argc) alias_arg = argv[++i]; else
          exim_fail("exim: string expected after -oA\n");
        }
      }

    /* -oB: Set a connection message max value for remote deliveries */

    else if (*argrest == 'B')
      {
      uschar *p = argrest + 1;
      if (p[0] == 0)
        {
        if (i+1 < argc && isdigit((argv[i+1][0]))) p = argv[++i]; else
          {
          connection_max_messages = 1;
          p = NULL;
          }
        }

      if (p != NULL)
        {
        if (!isdigit(*p))
          exim_fail("exim: number expected after -oB\n");
        connection_max_messages = Uatoi(p);
        }
      }

    /* -odb: background delivery */

    else if (Ustrcmp(argrest, "db") == 0)
      {
      f.synchronous_delivery = FALSE;
      arg_queue_only = FALSE;
      queue_only_set = TRUE;
      }

    /* -odf: foreground delivery (smail-compatible option); same effect as
       -odi: interactive (synchronous) delivery (sendmail-compatible option)
    */

    else if (Ustrcmp(argrest, "df") == 0 || Ustrcmp(argrest, "di") == 0)
      {
      f.synchronous_delivery = TRUE;
      arg_queue_only = FALSE;
      queue_only_set = TRUE;
      }

    /* -odq: queue only */

    else if (Ustrcmp(argrest, "dq") == 0)
      {
      f.synchronous_delivery = FALSE;
      arg_queue_only = TRUE;
      queue_only_set = TRUE;
      }

    /* -odqs: queue SMTP only - do local deliveries and remote routing,
    but no remote delivery */

    else if (Ustrcmp(argrest, "dqs") == 0)
      {
      f.queue_smtp = TRUE;
      arg_queue_only = FALSE;
      queue_only_set = TRUE;
      }

    /* -oex: Sendmail error flags. As these are also accepted without the
    leading -o prefix, for compatibility with vacation and other callers,
    they are handled with -e above. */

    /* -oi:     Set flag so dot doesn't end non-SMTP input (same as -i)
       -oitrue: Another sendmail syntax for the same */

    else if (Ustrcmp(argrest, "i") == 0 ||
             Ustrcmp(argrest, "itrue") == 0)
      f.dot_ends = FALSE;

    /* -oM*: Set various characteristics for an incoming message; actually
    acted on for trusted callers only. */

    else if (*argrest == 'M')
      {
      if (i+1 >= argc)
        exim_fail("exim: data expected after -o%s\n", argrest);

      /* -oMa: Set sender host address */

      if (Ustrcmp(argrest, "Ma") == 0) sender_host_address = argv[++i];

      /* -oMaa: Set authenticator name */

      else if (Ustrcmp(argrest, "Maa") == 0)
        sender_host_authenticated = argv[++i];

      /* -oMas: setting authenticated sender */

      else if (Ustrcmp(argrest, "Mas") == 0) authenticated_sender = argv[++i];

      /* -oMai: setting authenticated id */

      else if (Ustrcmp(argrest, "Mai") == 0) authenticated_id = argv[++i];

      /* -oMi: Set incoming interface address */

      else if (Ustrcmp(argrest, "Mi") == 0) interface_address = argv[++i];

      /* -oMm: Message reference */

      else if (Ustrcmp(argrest, "Mm") == 0)
        {
        if (!mac_ismsgid(argv[i+1]))
            exim_fail("-oMm must be a valid message ID\n");
        if (!f.trusted_config)
            exim_fail("-oMm must be called by a trusted user/config\n");
          message_reference = argv[++i];
        }

      /* -oMr: Received protocol */

      else if (Ustrcmp(argrest, "Mr") == 0)

        if (received_protocol)
          exim_fail("received_protocol is set already\n");
        else
	  received_protocol = argv[++i];

      /* -oMs: Set sender host name */

      else if (Ustrcmp(argrest, "Ms") == 0) sender_host_name = argv[++i];

      /* -oMt: Set sender ident */

      else if (Ustrcmp(argrest, "Mt") == 0)
        {
        sender_ident_set = TRUE;
        sender_ident = argv[++i];
        }

      /* Else a bad argument */

      else
        {
        badarg = TRUE;
        break;
        }
      }

    /* -om: Me-too flag for aliases. Exim always does this. Some programs
    seem to call this as -m (undocumented), so that is also accepted (see
    above). */

    else if (Ustrcmp(argrest, "m") == 0) {}

    /* -oo: An ancient flag for old-style addresses which still seems to
    crop up in some calls (see in SCO). */

    else if (Ustrcmp(argrest, "o") == 0) {}

    /* -oP <name>: set pid file path for daemon */

    else if (Ustrcmp(argrest, "P") == 0)
      override_pid_file_path = argv[++i];

    /* -or <n>: set timeout for non-SMTP acceptance
       -os <n>: set timeout for SMTP acceptance */

    else if (*argrest == 'r' || *argrest == 's')
      {
      int *tp = (*argrest == 'r')?
        &arg_receive_timeout : &arg_smtp_receive_timeout;
      if (argrest[1] == 0)
        {
        if (i+1 < argc) *tp= readconf_readtime(argv[++i], 0, FALSE);
        }
      else *tp = readconf_readtime(argrest + 1, 0, FALSE);
      if (*tp < 0)
        exim_fail("exim: bad time value %s: abandoned\n", argv[i]);
      }

    /* -oX <list>: Override local_interfaces and/or default daemon ports */

    else if (Ustrcmp(argrest, "X") == 0)
      override_local_interfaces = argv[++i];

    /* Unknown -o argument */

    else badarg = TRUE;
    break;


    /* -ps: force Perl startup; -pd force delayed Perl startup */

    case 'p':
    #ifdef EXIM_PERL
    if (*argrest == 's' && argrest[1] == 0)
      {
      perl_start_option = 1;
      break;
      }
    if (*argrest == 'd' && argrest[1] == 0)
      {
      perl_start_option = -1;
      break;
      }
    #endif

    /* -panythingelse is taken as the Sendmail-compatible argument -prval:sval,
    which sets the host protocol and host name */

    if (*argrest == 0)
      if (i+1 < argc)
	argrest = argv[++i];
      else
        { badarg = TRUE; break; }

    if (*argrest != 0)
      {
      uschar *hn;

      if (received_protocol)
        exim_fail("received_protocol is set already\n");

      hn = Ustrchr(argrest, ':');
      if (hn == NULL)
        received_protocol = argrest;
      else
        {
	int old_pool = store_pool;
	store_pool = POOL_PERM;
        received_protocol = string_copyn(argrest, hn - argrest);
	store_pool = old_pool;
        sender_host_name = hn + 1;
        }
      }
    break;


    case 'q':
    receiving_message = FALSE;
    if (queue_interval >= 0)
      exim_fail("exim: -q specified more than once\n");

    /* -qq...: Do queue runs in a 2-stage manner */

    if (*argrest == 'q')
      {
      f.queue_2stage = TRUE;
      argrest++;
      }

    /* -qi...: Do only first (initial) deliveries */

    if (*argrest == 'i')
      {
      f.queue_run_first_delivery = TRUE;
      argrest++;
      }

    /* -qf...: Run the queue, forcing deliveries
       -qff..: Ditto, forcing thawing as well */

    if (*argrest == 'f')
      {
      f.queue_run_force = TRUE;
      if (*++argrest == 'f')
        {
        f.deliver_force_thaw = TRUE;
        argrest++;
        }
      }

    /* -q[f][f]l...: Run the queue only on local deliveries */

    if (*argrest == 'l')
      {
      f.queue_run_local = TRUE;
      argrest++;
      }

    /* -q[f][f][l][G<name>]... Work on the named queue */

    if (*argrest == 'G')
      {
      int i;
      for (argrest++, i = 0; argrest[i] && argrest[i] != '/'; ) i++;
      queue_name = string_copyn(argrest, i);
      argrest += i;
      if (*argrest == '/') argrest++;
      }

    /* -q[f][f][l][G<name>]: Run the queue, optionally forced, optionally local
    only, optionally named, optionally starting from a given message id. */

    if (*argrest == 0 &&
        (i + 1 >= argc || argv[i+1][0] == '-' || mac_ismsgid(argv[i+1])))
      {
      queue_interval = 0;
      if (i+1 < argc && mac_ismsgid(argv[i+1]))
        start_queue_run_id = argv[++i];
      if (i+1 < argc && mac_ismsgid(argv[i+1]))
        stop_queue_run_id = argv[++i];
      }

    /* -q[f][f][l][G<name>/]<n>: Run the queue at regular intervals, optionally
    forced, optionally local only, optionally named. */

    else if ((queue_interval = readconf_readtime(*argrest ? argrest : argv[++i],
						0, FALSE)) <= 0)
      exim_fail("exim: bad time value %s: abandoned\n", argv[i]);
    break;


    case 'R':   /* Synonymous with -qR... */
    receiving_message = FALSE;

    /* -Rf:   As -R (below) but force all deliveries,
       -Rff:  Ditto, but also thaw all frozen messages,
       -Rr:   String is regex
       -Rrf:  Regex and force
       -Rrff: Regex and force and thaw

    in all cases provided there are no further characters in this
    argument. */

    if (*argrest != 0)
      {
      int i;
      for (i = 0; i < nelem(rsopts); i++)
        if (Ustrcmp(argrest, rsopts[i]) == 0)
          {
          if (i != 2) f.queue_run_force = TRUE;
          if (i >= 2) f.deliver_selectstring_regex = TRUE;
          if (i == 1 || i == 4) f.deliver_force_thaw = TRUE;
          argrest += Ustrlen(rsopts[i]);
          }
      }

    /* -R: Set string to match in addresses for forced queue run to
    pick out particular messages. */

    if (*argrest)
      deliver_selectstring = argrest;
    else if (i+1 < argc)
      deliver_selectstring = argv[++i];
    else
      exim_fail("exim: string expected after -R\n");
    break;


    /* -r: an obsolete synonym for -f (see above) */


    /* -S: Like -R but works on sender. */

    case 'S':   /* Synonymous with -qS... */
    receiving_message = FALSE;

    /* -Sf:   As -S (below) but force all deliveries,
       -Sff:  Ditto, but also thaw all frozen messages,
       -Sr:   String is regex
       -Srf:  Regex and force
       -Srff: Regex and force and thaw

    in all cases provided there are no further characters in this
    argument. */

    if (*argrest)
      {
      int i;
      for (i = 0; i < nelem(rsopts); i++)
        if (Ustrcmp(argrest, rsopts[i]) == 0)
          {
          if (i != 2) f.queue_run_force = TRUE;
          if (i >= 2) f.deliver_selectstring_sender_regex = TRUE;
          if (i == 1 || i == 4) f.deliver_force_thaw = TRUE;
          argrest += Ustrlen(rsopts[i]);
          }
      }

    /* -S: Set string to match in addresses for forced queue run to
    pick out particular messages. */

    if (*argrest)
      deliver_selectstring_sender = argrest;
    else if (i+1 < argc)
      deliver_selectstring_sender = argv[++i];
    else
      exim_fail("exim: string expected after -S\n");
    break;

    /* -Tqt is an option that is exclusively for use by the testing suite.
    It is not recognized in other circumstances. It allows for the setting up
    of explicit "queue times" so that various warning/retry things can be
    tested. Otherwise variability of clock ticks etc. cause problems. */

    case 'T':
    if (f.running_in_test_harness && Ustrcmp(argrest, "qt") == 0)
      fudged_queue_times = argv[++i];
    else badarg = TRUE;
    break;


    /* -t: Set flag to extract recipients from body of message. */

    case 't':
    if (*argrest == 0) extract_recipients = TRUE;

    /* -ti: Set flag to extract recipients from body of message, and also
    specify that dot does not end the message. */

    else if (Ustrcmp(argrest, "i") == 0)
      {
      extract_recipients = TRUE;
      f.dot_ends = FALSE;
      }

    /* -tls-on-connect: don't wait for STARTTLS (for old clients) */

    #ifdef SUPPORT_TLS
    else if (Ustrcmp(argrest, "ls-on-connect") == 0) tls_in.on_connect = TRUE;
    #endif

    else badarg = TRUE;
    break;


    /* -U: This means "initial user submission" in sendmail, apparently. The
    doc claims that in future sendmail may refuse syntactically invalid
    messages instead of fixing them. For the moment, we just ignore it. */

    case 'U':
    break;


    /* -v: verify things - this is a very low-level debugging */

    case 'v':
    if (*argrest == 0)
      {
      debug_selector |= D_v;
      debug_file = stderr;
      }
    else badarg = TRUE;
    break;


    /* -x: AIX uses this to indicate some fancy 8-bit character stuff:

      The -x flag tells the sendmail command that mail from a local
      mail program has National Language Support (NLS) extended characters
      in the body of the mail item. The sendmail command can send mail with
      extended NLS characters across networks that normally corrupts these
      8-bit characters.

    As Exim is 8-bit clean, it just ignores this flag. */

    case 'x':
    if (*argrest != 0) badarg = TRUE;
    break;

    /* -X: in sendmail: takes one parameter, logfile, and sends debugging
    logs to that file.  We swallow the parameter and otherwise ignore it. */

    case 'X':
    if (*argrest == '\0')
      if (++i >= argc)
        exim_fail("exim: string expected after -X\n");
    break;

    case 'z':
    if (*argrest == '\0')
      if (++i < argc)
	log_oneline = argv[i];
      else
        exim_fail("exim: file name expected after %s\n", argv[i-1]);
    break;

    /* All other initial characters are errors */

    default:
    badarg = TRUE;
    break;
    }         /* End of high-level switch statement */

  /* Failed to recognize the option, or syntax error */

  if (badarg)
    exim_fail("exim abandoned: unknown, malformed, or incomplete "
      "option %s\n", arg);
  }


/* If -R or -S have been specified without -q, assume a single queue run. */

if (  (deliver_selectstring || deliver_selectstring_sender)
   && queue_interval < 0)
    queue_interval = 0;


END_ARG:
/* If usage_wanted is set we call the usage function - which never returns */
if (usage_wanted) exim_usage(called_as);

/* Arguments have been processed. Check for incompatibilities. */
if ((
    (smtp_input || extract_recipients || recipients_arg < argc) &&
    (f.daemon_listen || queue_interval >= 0 || bi_option ||
      test_retry_arg >= 0 || test_rewrite_arg >= 0 ||
      filter_test != FTEST_NONE || (msg_action_arg > 0 && !one_msg_action))
    ) ||
    (
    msg_action_arg > 0 &&
    (f.daemon_listen || queue_interval > 0 || list_options ||
      (checking && msg_action != MSG_LOAD) ||
      bi_option || test_retry_arg >= 0 || test_rewrite_arg >= 0)
    ) ||
    (
    (f.daemon_listen || queue_interval > 0) &&
    (sender_address != NULL || list_options || list_queue || checking ||
      bi_option)
    ) ||
    (
    f.daemon_listen && queue_interval == 0
    ) ||
    (
    f.inetd_wait_mode && queue_interval >= 0
    ) ||
    (
    list_options &&
    (checking || smtp_input || extract_recipients ||
      filter_test != FTEST_NONE || bi_option)
    ) ||
    (
    verify_address_mode &&
    (f.address_test_mode || smtp_input || extract_recipients ||
      filter_test != FTEST_NONE || bi_option)
    ) ||
    (
    f.address_test_mode && (smtp_input || extract_recipients ||
      filter_test != FTEST_NONE || bi_option)
    ) ||
    (
    smtp_input && (sender_address != NULL || filter_test != FTEST_NONE ||
      extract_recipients)
    ) ||
    (
    deliver_selectstring != NULL && queue_interval < 0
    ) ||
    (
    msg_action == MSG_LOAD &&
      (!expansion_test || expansion_test_message != NULL)
    )
   )
  exim_fail("exim: incompatible command-line options or arguments\n");

/* If debugging is set up, set the file and the file descriptor to pass on to
child processes. It should, of course, be 2 for stderr. Also, force the daemon
to run in the foreground. */

if (debug_selector != 0)
  {
  debug_file = stderr;
  debug_fd = fileno(debug_file);
  f.background_daemon = FALSE;
  if (f.running_in_test_harness) millisleep(100);   /* lets caller finish */
  if (debug_selector != D_v)    /* -v only doesn't show this */
    {
    debug_printf("Exim version %s uid=%ld gid=%ld pid=%d D=%x\n",
      version_string, (long int)real_uid, (long int)real_gid, (int)getpid(),
      debug_selector);
    if (!version_printed)
      show_whats_supported(stderr);
    }
  }

/* When started with root privilege, ensure that the limits on the number of
open files and the number of processes (where that is accessible) are
sufficiently large, or are unset, in case Exim has been called from an
environment where the limits are screwed down. Not all OS have the ability to
change some of these limits. */

if (unprivileged)
  {
  DEBUG(D_any) debug_print_ids(US"Exim has no root privilege:");
  }
else
  {
  struct rlimit rlp;

  #ifdef RLIMIT_NOFILE
  if (getrlimit(RLIMIT_NOFILE, &rlp) < 0)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "getrlimit(RLIMIT_NOFILE) failed: %s",
      strerror(errno));
    rlp.rlim_cur = rlp.rlim_max = 0;
    }

  /* I originally chose 1000 as a nice big number that was unlikely to
  be exceeded. It turns out that some older OS have a fixed upper limit of
  256. */

  if (rlp.rlim_cur < 1000)
    {
    rlp.rlim_cur = rlp.rlim_max = 1000;
    if (setrlimit(RLIMIT_NOFILE, &rlp) < 0)
      {
      rlp.rlim_cur = rlp.rlim_max = 256;
      if (setrlimit(RLIMIT_NOFILE, &rlp) < 0)
        log_write(0, LOG_MAIN|LOG_PANIC, "setrlimit(RLIMIT_NOFILE) failed: %s",
          strerror(errno));
      }
    }
  #endif

  #ifdef RLIMIT_NPROC
  if (getrlimit(RLIMIT_NPROC, &rlp) < 0)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "getrlimit(RLIMIT_NPROC) failed: %s",
      strerror(errno));
    rlp.rlim_cur = rlp.rlim_max = 0;
    }

  #ifdef RLIM_INFINITY
  if (rlp.rlim_cur != RLIM_INFINITY && rlp.rlim_cur < 1000)
    {
    rlp.rlim_cur = rlp.rlim_max = RLIM_INFINITY;
  #else
  if (rlp.rlim_cur < 1000)
    {
    rlp.rlim_cur = rlp.rlim_max = 1000;
  #endif
    if (setrlimit(RLIMIT_NPROC, &rlp) < 0)
      log_write(0, LOG_MAIN|LOG_PANIC, "setrlimit(RLIMIT_NPROC) failed: %s",
        strerror(errno));
    }
  #endif
  }

/* Exim is normally entered as root (but some special configurations are
possible that don't do this). However, it always spins off sub-processes that
set their uid and gid as required for local delivery. We don't want to pass on
any extra groups that root may belong to, so we want to get rid of them all at
this point.

We need to obey setgroups() at this stage, before possibly giving up root
privilege for a changed configuration file, but later on we might need to
check on the additional groups for the admin user privilege - can't do that
till after reading the config, which might specify the exim gid. Therefore,
save the group list here first. */

if ((group_count = getgroups(nelem(group_list), group_list)) < 0)
  exim_fail("exim: getgroups() failed: %s\n", strerror(errno));

/* There is a fundamental difference in some BSD systems in the matter of
groups. FreeBSD and BSDI are known to be different; NetBSD and OpenBSD are
known not to be different. On the "different" systems there is a single group
list, and the first entry in it is the current group. On all other versions of
Unix there is a supplementary group list, which is in *addition* to the current
group. Consequently, to get rid of all extraneous groups on a "standard" system
you pass over 0 groups to setgroups(), while on a "different" system you pass
over a single group - the current group, which is always the first group in the
list. Calling setgroups() with zero groups on a "different" system results in
an error return. The following code should cope with both types of system.

 Unfortunately, recent MacOS, which should be a FreeBSD, "helpfully" succeeds
 the "setgroups() with zero groups" - and changes the egid.
 Thanks to that we had to stash the original_egid above, for use below
 in the call to exim_setugid().

However, if this process isn't running as root, setgroups() can't be used
since you have to be root to run it, even if throwing away groups. Not being
root here happens only in some unusual configurations. We just ignore the
error. */

if (setgroups(0, NULL) != 0 && setgroups(1, group_list) != 0 && !unprivileged)
  exim_fail("exim: setgroups() failed: %s\n", strerror(errno));

/* If the configuration file name has been altered by an argument on the
command line (either a new file name or a macro definition) and the caller is
not root, or if this is a filter testing run, remove any setuid privilege the
program has and run as the underlying user.

The exim user is locked out of this, which severely restricts the use of -C
for some purposes.

Otherwise, set the real ids to the effective values (should be root unless run
from inetd, which it can either be root or the exim uid, if one is configured).

There is a private mechanism for bypassing some of this, in order to make it
possible to test lots of configurations automatically, without having either to
recompile each time, or to patch in an actual configuration file name and other
values (such as the path name). If running in the test harness, pretend that
configuration file changes and macro definitions haven't happened. */

if ((                                            /* EITHER */
    (!f.trusted_config ||                          /* Config changed, or */
     !macros_trusted(opt_D_used)) &&		 /*  impermissible macros and */
    real_uid != root_uid &&                      /* Not root, and */
    !f.running_in_test_harness                     /* Not fudged */
    ) ||                                         /*   OR   */
    expansion_test                               /* expansion testing */
    ||                                           /*   OR   */
    filter_test != FTEST_NONE)                   /* Filter testing */
  {
  setgroups(group_count, group_list);
  exim_setugid(real_uid, real_gid, FALSE,
    US"-C, -D, -be or -bf forces real uid");
  removed_privilege = TRUE;

  /* In the normal case when Exim is called like this, stderr is available
  and should be used for any logging information because attempts to write
  to the log will usually fail. To arrange this, we unset really_exim. However,
  if no stderr is available there is no point - we might as well have a go
  at the log (if it fails, syslog will be written).

  Note that if the invoker is Exim, the logs remain available. Messing with
  this causes unlogged successful deliveries.  */

  if (log_stderr && real_uid != exim_uid)
    f.really_exim = FALSE;
  }

/* Privilege is to be retained for the moment. It may be dropped later,
depending on the job that this Exim process has been asked to do. For now, set
the real uid to the effective so that subsequent re-execs of Exim are done by a
privileged user. */

else
  exim_setugid(geteuid(), original_egid, FALSE, US"forcing real = effective");

/* If testing a filter, open the file(s) now, before wasting time doing other
setups and reading the message. */

if (filter_test & FTEST_SYSTEM)
  if ((filter_sfd = Uopen(filter_test_sfile, O_RDONLY, 0)) < 0)
    exim_fail("exim: failed to open %s: %s\n", filter_test_sfile,
      strerror(errno));

if (filter_test & FTEST_USER)
  if ((filter_ufd = Uopen(filter_test_ufile, O_RDONLY, 0)) < 0)
    exim_fail("exim: failed to open %s: %s\n", filter_test_ufile,
      strerror(errno));

/* Initialise lookup_list
If debugging, already called above via version reporting.
In either case, we initialise the list of available lookups while running
as root.  All dynamically modules are loaded from a directory which is
hard-coded into the binary and is code which, if not a module, would be
part of Exim already.  Ability to modify the content of the directory
is equivalent to the ability to modify a setuid binary!

This needs to happen before we read the main configuration. */
init_lookup_list();

#ifdef SUPPORT_I18N
if (f.running_in_test_harness) smtputf8_advertise_hosts = NULL;
#endif

/* Read the main runtime configuration data; this gives up if there
is a failure. It leaves the configuration file open so that the subsequent
configuration data for delivery can be read if needed.

NOTE: immediately after opening the configuration file we change the working
directory to "/"! Later we change to $spool_directory. We do it there, because
during readconf_main() some expansion takes place already. */

/* Store the initial cwd before we change directories.  Can be NULL if the
dir has already been unlinked. */
initial_cwd = os_getcwd(NULL, 0);

/* checking:
    -be[m] expansion test        -
    -b[fF] filter test           new
    -bh[c] host test             -
    -bmalware malware_test_file  new
    -brt   retry test            new
    -brw   rewrite test          new
    -bt    address test          -
    -bv[s] address verify        -
   list_options:
    -bP <option> (except -bP config, which sets list_config)

If any of these options is set, we suppress warnings about configuration
issues (currently about tls_advertise_hosts and keep_environment not being
defined) */

readconf_main(checking || list_options);


/* Now in directory "/" */

if (cleanup_environment() == FALSE)
  log_write(0, LOG_PANIC_DIE, "Can't cleanup environment");


/* If an action on specific messages is requested, or if a daemon or queue
runner is being started, we need to know if Exim was called by an admin user.
This is the case if the real user is root or exim, or if the real group is
exim, or if one of the supplementary groups is exim or a group listed in
admin_groups. We don't fail all message actions immediately if not admin_user,
since some actions can be performed by non-admin users. Instead, set admin_user
for later interrogation. */

if (real_uid == root_uid || real_uid == exim_uid || real_gid == exim_gid)
  f.admin_user = TRUE;
else
  {
  int i, j;
  for (i = 0; i < group_count && !f.admin_user; i++)
    if (group_list[i] == exim_gid)
      f.admin_user = TRUE;
    else if (admin_groups)
      for (j = 1; j <= (int)admin_groups[0] && !f.admin_user; j++)
        if (admin_groups[j] == group_list[i])
          f.admin_user = TRUE;
  }

/* Another group of privileged users are the trusted users. These are root,
exim, and any caller matching trusted_users or trusted_groups. Trusted callers
are permitted to specify sender_addresses with -f on the command line, and
other message parameters as well. */

if (real_uid == root_uid || real_uid == exim_uid)
  f.trusted_caller = TRUE;
else
  {
  int i, j;

  if (trusted_users)
    for (i = 1; i <= (int)trusted_users[0] && !f.trusted_caller; i++)
      if (trusted_users[i] == real_uid)
        f.trusted_caller = TRUE;

  if (trusted_groups)
    for (i = 1; i <= (int)trusted_groups[0] && !f.trusted_caller; i++)
      if (trusted_groups[i] == real_gid)
        f.trusted_caller = TRUE;
      else for (j = 0; j < group_count && !f.trusted_caller; j++)
        if (trusted_groups[i] == group_list[j])
          f.trusted_caller = TRUE;
  }

/* At this point, we know if the user is privileged and some command-line
options become possibly impermissible, depending upon the configuration file. */

if (checking && commandline_checks_require_admin && !f.admin_user)
  exim_fail("exim: those command-line flags are set to require admin\n");

/* Handle the decoding of logging options. */

decode_bits(log_selector, log_selector_size, log_notall,
  log_selector_string, log_options, log_options_count, US"log", 0);

DEBUG(D_any)
  {
  int i;
  debug_printf("configuration file is %s\n", config_main_filename);
  debug_printf("log selectors =");
  for (i = 0; i < log_selector_size; i++)
    debug_printf(" %08x", log_selector[i]);
  debug_printf("\n");
  }

/* If domain literals are not allowed, check the sender address that was
supplied with -f. Ditto for a stripped trailing dot. */

if (sender_address)
  {
  if (sender_address[sender_address_domain] == '[' && !allow_domain_literals)
    exim_fail("exim: bad -f address \"%s\": domain literals not "
      "allowed\n", sender_address);
  if (f_end_dot && !strip_trailing_dot)
    exim_fail("exim: bad -f address \"%s.\": domain is malformed "
      "(trailing dot not allowed)\n", sender_address);
  }

/* See if an admin user overrode our logging. */

if (cmdline_syslog_name)
  if (f.admin_user)
    {
    syslog_processname = cmdline_syslog_name;
    log_file_path = string_copy(CUS"syslog");
    }
  else
    /* not a panic, non-privileged users should not be able to spam paniclog */
    exim_fail(
        "exim: you lack sufficient privilege to specify syslog process name\n");

/* Paranoia check of maximum lengths of certain strings. There is a check
on the length of the log file path in log.c, which will come into effect
if there are any calls to write the log earlier than this. However, if we
get this far but the string is very long, it is better to stop now than to
carry on and (e.g.) receive a message and then have to collapse. The call to
log_write() from here will cause the ultimate panic collapse if the complete
file name exceeds the buffer length. */

if (Ustrlen(log_file_path) > 200)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "log_file_path is longer than 200 chars: aborting");

if (Ustrlen(pid_file_path) > 200)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "pid_file_path is longer than 200 chars: aborting");

if (Ustrlen(spool_directory) > 200)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "spool_directory is longer than 200 chars: aborting");

/* Length check on the process name given to syslog for its TAG field,
which is only permitted to be 32 characters or less. See RFC 3164. */

if (Ustrlen(syslog_processname) > 32)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE,
    "syslog_processname is longer than 32 chars: aborting");

if (log_oneline)
  if (f.admin_user)
    {
    log_write(0, LOG_MAIN, "%s", log_oneline);
    return EXIT_SUCCESS;
    }
  else
    return EXIT_FAILURE;

/* In some operating systems, the environment variable TMPDIR controls where
temporary files are created; Exim doesn't use these (apart from when delivering
to MBX mailboxes), but called libraries such as DBM libraries may require them.
If TMPDIR is found in the environment, reset it to the value defined in the
EXIM_TMPDIR macro, if this macro is defined.  For backward compatibility this
macro may be called TMPDIR in old "Local/Makefile"s. It's converted to
EXIM_TMPDIR by the build scripts.
*/

#ifdef EXIM_TMPDIR
  {
  uschar **p;
  if (environ) for (p = USS environ; *p; p++)
    if (Ustrncmp(*p, "TMPDIR=", 7) == 0 && Ustrcmp(*p+7, EXIM_TMPDIR) != 0)
      {
      uschar * newp = store_malloc(Ustrlen(EXIM_TMPDIR) + 8);
      sprintf(CS newp, "TMPDIR=%s", EXIM_TMPDIR);
      *p = newp;
      DEBUG(D_any) debug_printf("reset TMPDIR=%s in environment\n", EXIM_TMPDIR);
      }
  }
#endif

/* Timezone handling. If timezone_string is "utc", set a flag to cause all
timestamps to be in UTC (gmtime() is used instead of localtime()). Otherwise,
we may need to get rid of a bogus timezone setting. This can arise when Exim is
called by a user who has set the TZ variable. This then affects the timestamps
in log files and in Received: headers, and any created Date: header lines. The
required timezone is settable in the configuration file, so nothing can be done
about this earlier - but hopefully nothing will normally be logged earlier than
this. We have to make a new environment if TZ is wrong, but don't bother if
timestamps_utc is set, because then all times are in UTC anyway. */

if (timezone_string && strcmpic(timezone_string, US"UTC") == 0)
  f.timestamps_utc = TRUE;
else
  {
  uschar *envtz = US getenv("TZ");
  if (envtz
      ? !timezone_string || Ustrcmp(timezone_string, envtz) != 0
      : timezone_string != NULL
     )
    {
    uschar **p = USS environ;
    uschar **new;
    uschar **newp;
    int count = 0;
    if (environ) while (*p++) count++;
    if (!envtz) count++;
    newp = new = store_malloc(sizeof(uschar *) * (count + 1));
    if (environ) for (p = USS environ; *p; p++)
      if (Ustrncmp(*p, "TZ=", 3) != 0) *newp++ = *p;
    if (timezone_string)
      {
      *newp = store_malloc(Ustrlen(timezone_string) + 4);
      sprintf(CS *newp++, "TZ=%s", timezone_string);
      }
    *newp = NULL;
    environ = CSS new;
    tzset();
    DEBUG(D_any) debug_printf("Reset TZ to %s: time is %s\n", timezone_string,
      tod_stamp(tod_log));
    }
  }

/* Handle the case when we have removed the setuid privilege because of -C or
-D. This means that the caller of Exim was not root.

There is a problem if we were running as the Exim user. The sysadmin may
expect this case to retain privilege because "the binary was called by the
Exim user", but it hasn't, because either the -D option set macros, or the
-C option set a non-trusted configuration file. There are two possibilities:

  (1) If deliver_drop_privilege is set, Exim is not going to re-exec in order
      to do message deliveries. Thus, the fact that it is running as a
      non-privileged user is plausible, and might be wanted in some special
      configurations. However, really_exim will have been set false when
      privilege was dropped, to stop Exim trying to write to its normal log
      files. Therefore, re-enable normal log processing, assuming the sysadmin
      has set up the log directory correctly.

  (2) If deliver_drop_privilege is not set, the configuration won't work as
      apparently intended, and so we log a panic message. In order to retain
      root for -C or -D, the caller must either be root or be invoking a
      trusted configuration file (when deliver_drop_privilege is false). */

if (  removed_privilege
   && (!f.trusted_config || opt_D_used)
   && real_uid == exim_uid)
  if (deliver_drop_privilege)
    f.really_exim = TRUE; /* let logging work normally */
  else
    log_write(0, LOG_MAIN|LOG_PANIC,
      "exim user lost privilege for using %s option",
      f.trusted_config? "-D" : "-C");

/* Start up Perl interpreter if Perl support is configured and there is a
perl_startup option, and the configuration or the command line specifies
initializing starting. Note that the global variables are actually called
opt_perl_xxx to avoid clashing with perl's namespace (perl_*). */

#ifdef EXIM_PERL
if (perl_start_option != 0)
  opt_perl_at_start = (perl_start_option > 0);
if (opt_perl_at_start && opt_perl_startup != NULL)
  {
  uschar *errstr;
  DEBUG(D_any) debug_printf("Starting Perl interpreter\n");
  if ((errstr = init_perl(opt_perl_startup)))
    exim_fail("exim: error in perl_startup code: %s\n", errstr);
  opt_perl_started = TRUE;
  }
#endif /* EXIM_PERL */

/* Log the arguments of the call if the configuration file said so. This is
a debugging feature for finding out what arguments certain MUAs actually use.
Don't attempt it if logging is disabled, or if listing variables or if
verifying/testing addresses or expansions. */

if (  (debug_selector & D_any  ||  LOGGING(arguments))
   && f.really_exim && !list_options && !checking)
  {
  int i;
  uschar *p = big_buffer;
  Ustrcpy(p, "cwd= (failed)");

  if (!initial_cwd)
    p += 13;
  else
    {
    Ustrncpy(p + 4, initial_cwd, big_buffer_size-5);
    p += 4 + Ustrlen(initial_cwd);
    /* in case p is near the end and we don't provide enough space for
     * string_format to be willing to write. */
    *p = '\0';
    }

  (void)string_format(p, big_buffer_size - (p - big_buffer), " %d args:", argc);
  while (*p) p++;
  for (i = 0; i < argc; i++)
    {
    int len = Ustrlen(argv[i]);
    const uschar *printing;
    uschar *quote;
    if (p + len + 8 >= big_buffer + big_buffer_size)
      {
      Ustrcpy(p, " ...");
      log_write(0, LOG_MAIN, "%s", big_buffer);
      Ustrcpy(big_buffer, "...");
      p = big_buffer + 3;
      }
    printing = string_printing(argv[i]);
    if (printing[0] == 0) quote = US"\""; else
      {
      const uschar *pp = printing;
      quote = US"";
      while (*pp != 0) if (isspace(*pp++)) { quote = US"\""; break; }
      }
    p += sprintf(CS p, " %s%.*s%s", quote, (int)(big_buffer_size -
      (p - big_buffer) - 4), printing, quote);
    }

  if (LOGGING(arguments))
    log_write(0, LOG_MAIN, "%s", big_buffer);
  else
    debug_printf("%s\n", big_buffer);
  }

/* Set the working directory to be the top-level spool directory. We don't rely
on this in the code, which always uses fully qualified names, but it's useful
for core dumps etc. Don't complain if it fails - the spool directory might not
be generally accessible and calls with the -C option (and others) have lost
privilege by now. Before the chdir, we try to ensure that the directory exists.
*/

if (Uchdir(spool_directory) != 0)
  {
  int dummy;
  (void)directory_make(spool_directory, US"", SPOOL_DIRECTORY_MODE, FALSE);
  dummy = /* quieten compiler */ Uchdir(spool_directory);
  dummy = dummy;	/* yet more compiler quietening, sigh */
  }

/* Handle calls with the -bi option. This is a sendmail option to rebuild *the*
alias file. Exim doesn't have such a concept, but this call is screwed into
Sun's YP makefiles. Handle this by calling a configured script, as the real
user who called Exim. The -oA option can be used to pass an argument to the
script. */

if (bi_option)
  {
  (void)fclose(config_file);
  if (bi_command != NULL)
    {
    int i = 0;
    uschar *argv[3];
    argv[i++] = bi_command;
    if (alias_arg != NULL) argv[i++] = alias_arg;
    argv[i++] = NULL;

    setgroups(group_count, group_list);
    exim_setugid(real_uid, real_gid, FALSE, US"running bi_command");

    DEBUG(D_exec) debug_printf("exec %.256s %.256s\n", argv[0],
      (argv[1] == NULL)? US"" : argv[1]);

    execv(CS argv[0], (char *const *)argv);
    exim_fail("exim: exec failed: %s\n", strerror(errno));
    }
  else
    {
    DEBUG(D_any) debug_printf("-bi used but bi_command not set; exiting\n");
    exit(EXIT_SUCCESS);
    }
  }

/* We moved the admin/trusted check to be immediately after reading the
configuration file.  We leave these prints here to ensure that syslog setup,
logfile setup, and so on has already happened. */

if (f.trusted_caller) DEBUG(D_any) debug_printf("trusted user\n");
if (f.admin_user) DEBUG(D_any) debug_printf("admin user\n");

/* Only an admin user may start the daemon or force a queue run in the default
configuration, but the queue run restriction can be relaxed. Only an admin
user may request that a message be returned to its sender forthwith. Only an
admin user may specify a debug level greater than D_v (because it might show
passwords, etc. in lookup queries). Only an admin user may request a queue
count. Only an admin user can use the test interface to scan for email
(because Exim will be in the spool dir and able to look at mails). */

if (!f.admin_user)
  {
  BOOL debugset = (debug_selector & ~D_v) != 0;
  if (deliver_give_up || f.daemon_listen || malware_test_file ||
     (count_queue && queue_list_requires_admin) ||
     (list_queue && queue_list_requires_admin) ||
     (queue_interval >= 0 && prod_requires_admin) ||
     (debugset && !f.running_in_test_harness))
    exim_fail("exim:%s permission denied\n", debugset? " debugging" : "");
  }

/* If the real user is not root or the exim uid, the argument for passing
in an open TCP/IP connection for another message is not permitted, nor is
running with the -N option for any delivery action, unless this call to exim is
one that supplied an input message, or we are using a patched exim for
regression testing. */

if (real_uid != root_uid && real_uid != exim_uid &&
     (continue_hostname != NULL ||
       (f.dont_deliver &&
         (queue_interval >= 0 || f.daemon_listen || msg_action_arg > 0)
       )) && !f.running_in_test_harness)
  exim_fail("exim: Permission denied\n");

/* If the caller is not trusted, certain arguments are ignored when running for
real, but are permitted when checking things (-be, -bv, -bt, -bh, -bf, -bF).
Note that authority for performing certain actions on messages is tested in the
queue_action() function. */

if (!f.trusted_caller && !checking)
  {
  sender_host_name = sender_host_address = interface_address =
    sender_ident = received_protocol = NULL;
  sender_host_port = interface_port = 0;
  sender_host_authenticated = authenticated_sender = authenticated_id = NULL;
  }

/* If a sender host address is set, extract the optional port number off the
end of it and check its syntax. Do the same thing for the interface address.
Exim exits if the syntax is bad. */

else
  {
  if (sender_host_address != NULL)
    sender_host_port = check_port(sender_host_address);
  if (interface_address != NULL)
    interface_port = check_port(interface_address);
  }

/* If the caller is trusted, then they can use -G to suppress_local_fixups. */
if (flag_G)
  {
  if (f.trusted_caller)
    {
    f.suppress_local_fixups = f.suppress_local_fixups_default = TRUE;
    DEBUG(D_acl) debug_printf("suppress_local_fixups forced on by -G\n");
    }
  else
    exim_fail("exim: permission denied (-G requires a trusted user)\n");
  }

/* If an SMTP message is being received check to see if the standard input is a
TCP/IP socket. If it is, we assume that Exim was called from inetd if the
caller is root or the Exim user, or if the port is a privileged one. Otherwise,
barf. */

if (smtp_input)
  {
  union sockaddr_46 inetd_sock;
  EXIM_SOCKLEN_T size = sizeof(inetd_sock);
  if (getpeername(0, (struct sockaddr *)(&inetd_sock), &size) == 0)
    {
    int family = ((struct sockaddr *)(&inetd_sock))->sa_family;
    if (family == AF_INET || family == AF_INET6)
      {
      union sockaddr_46 interface_sock;
      size = sizeof(interface_sock);

      if (getsockname(0, (struct sockaddr *)(&interface_sock), &size) == 0)
        interface_address = host_ntoa(-1, &interface_sock, NULL,
          &interface_port);

      if (host_is_tls_on_connect_port(interface_port)) tls_in.on_connect = TRUE;

      if (real_uid == root_uid || real_uid == exim_uid || interface_port < 1024)
        {
        f.is_inetd = TRUE;
        sender_host_address = host_ntoa(-1, (struct sockaddr *)(&inetd_sock),
          NULL, &sender_host_port);
        if (mua_wrapper) log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Input from "
          "inetd is not supported when mua_wrapper is set");
        }
      else
        exim_fail(
          "exim: Permission denied (unprivileged user, unprivileged port)\n");
      }
    }
  }

/* If the load average is going to be needed while receiving a message, get it
now for those OS that require the first call to os_getloadavg() to be done as
root. There will be further calls later for each message received. */

#ifdef LOAD_AVG_NEEDS_ROOT
if (receiving_message &&
      (queue_only_load >= 0 ||
        (f.is_inetd && smtp_load_reserve >= 0)
      ))
  {
  load_average = OS_GETLOADAVG();
  }
#endif

/* The queue_only configuration option can be overridden by -odx on the command
line, except that if queue_only_override is false, queue_only cannot be unset
from the command line. */

if (queue_only_set && (queue_only_override || arg_queue_only))
  queue_only = arg_queue_only;

/* The receive_timeout and smtp_receive_timeout options can be overridden by
-or and -os. */

if (arg_receive_timeout >= 0) receive_timeout = arg_receive_timeout;
if (arg_smtp_receive_timeout >= 0)
  smtp_receive_timeout = arg_smtp_receive_timeout;

/* If Exim was started with root privilege, unless we have already removed the
root privilege above as a result of -C, -D, -be, -bf or -bF, remove it now
except when starting the daemon or doing some kind of delivery or address
testing (-bt). These are the only cases when root need to be retained. We run
as exim for -bv and -bh. However, if deliver_drop_privilege is set, root is
retained only for starting the daemon. We always do the initgroups() in this
situation (controlled by the TRUE below), in order to be as close as possible
to the state Exim usually runs in. */

if (!unprivileged &&                      /* originally had root AND */
    !removed_privilege &&                 /* still got root AND      */
    !f.daemon_listen &&                     /* not starting the daemon */
    queue_interval <= 0 &&                /* (either kind of daemon) */
      (                                   /*    AND EITHER           */
      deliver_drop_privilege ||           /* requested unprivileged  */
        (                                 /*       OR                */
        queue_interval < 0 &&             /* not running the queue   */
        (msg_action_arg < 0 ||            /*       and               */
          msg_action != MSG_DELIVER) &&   /* not delivering and      */
        (!checking || !f.address_test_mode) /* not address checking    */
   )  ) )
  exim_setugid(exim_uid, exim_gid, TRUE, US"privilege not needed");

/* When we are retaining a privileged uid, we still change to the exim gid. */

else
  {
  int rv;
  rv = setgid(exim_gid);
  /* Impact of failure is that some stuff might end up with an incorrect group.
  We track this for failures from root, since any attempt to change privilege
  by root should succeed and failures should be examined.  For non-root,
  there's no security risk.  For me, it's { exim -bV } on a just-built binary,
  no need to complain then. */
  if (rv == -1)
    if (!(unprivileged || removed_privilege))
      exim_fail("exim: changing group failed: %s\n", strerror(errno));
    else
      DEBUG(D_any) debug_printf("changing group to %ld failed: %s\n",
          (long int)exim_gid, strerror(errno));
  }

/* Handle a request to scan a file for malware */
if (malware_test_file)
  {
#ifdef WITH_CONTENT_SCAN
  int result;
  set_process_info("scanning file for malware");
  result = malware_in_file(malware_test_file);
  if (result == FAIL)
    {
    printf("No malware found.\n");
    exit(EXIT_SUCCESS);
    }
  if (result != OK)
    {
    printf("Malware lookup returned non-okay/fail: %d\n", result);
    exit(EXIT_FAILURE);
    }
  if (malware_name)
    printf("Malware found: %s\n", malware_name);
  else
    printf("Malware scan detected malware of unknown name.\n");
#else
  printf("Malware scanning not enabled at compile time.\n");
#endif
  exit(EXIT_FAILURE);
  }

/* Handle a request to list the delivery queue */

if (list_queue)
  {
  set_process_info("listing the queue");
  queue_list(list_queue_option, argv + recipients_arg, argc - recipients_arg);
  exit(EXIT_SUCCESS);
  }

/* Handle a request to count the delivery queue */

if (count_queue)
  {
  set_process_info("counting the queue");
  queue_count();
  exit(EXIT_SUCCESS);
  }

/* Handle actions on specific messages, except for the force delivery and
message load actions, which are done below. Some actions take a whole list of
message ids, which are known to continue up to the end of the arguments. Others
take a single message id and then operate on the recipients list. */

if (msg_action_arg > 0 && msg_action != MSG_DELIVER && msg_action != MSG_LOAD)
  {
  int yield = EXIT_SUCCESS;
  set_process_info("acting on specified messages");

  /* ACL definitions may be needed when removing a message (-Mrm) because
  event_action gets expanded */

  if (msg_action == MSG_REMOVE)
    readconf_rest();

  if (!one_msg_action)
    {
    for (i = msg_action_arg; i < argc; i++)
      if (!queue_action(argv[i], msg_action, NULL, 0, 0))
        yield = EXIT_FAILURE;
    }

  else if (!queue_action(argv[msg_action_arg], msg_action, argv, argc,
    recipients_arg)) yield = EXIT_FAILURE;
  exit(yield);
  }

/* We used to set up here to skip reading the ACL section, on
 (msg_action_arg > 0 || (queue_interval == 0 && !f.daemon_listen)
Now, since the intro of the ${acl } expansion, ACL definitions may be
needed in transports so we lost the optimisation. */

readconf_rest();

/* The configuration data will have been read into POOL_PERM because we won't
ever want to reset back past it. Change the current pool to POOL_MAIN. In fact,
this is just a bit of pedantic tidiness. It wouldn't really matter if the
configuration were read into POOL_MAIN, because we don't do any resets till
later on. However, it seems right, and it does ensure that both pools get used.
*/

store_pool = POOL_MAIN;

/* Handle the -brt option. This is for checking out retry configurations.
The next three arguments are a domain name or a complete address, and
optionally two error numbers. All it does is to call the function that
scans the retry configuration data. */

if (test_retry_arg >= 0)
  {
  retry_config *yield;
  int basic_errno = 0;
  int more_errno = 0;
  uschar *s1, *s2;

  if (test_retry_arg >= argc)
    {
    printf("-brt needs a domain or address argument\n");
    exim_exit(EXIT_FAILURE, US"main");
    }
  s1 = argv[test_retry_arg++];
  s2 = NULL;

  /* If the first argument contains no @ and no . it might be a local user
  or it might be a single-component name. Treat as a domain. */

  if (Ustrchr(s1, '@') == NULL && Ustrchr(s1, '.') == NULL)
    {
    printf("Warning: \"%s\" contains no '@' and no '.' characters. It is "
      "being \ntreated as a one-component domain, not as a local part.\n\n",
      s1);
    }

  /* There may be an optional second domain arg. */

  if (test_retry_arg < argc && Ustrchr(argv[test_retry_arg], '.') != NULL)
    s2 = argv[test_retry_arg++];

  /* The final arg is an error name */

  if (test_retry_arg < argc)
    {
    uschar *ss = argv[test_retry_arg];
    uschar *error =
      readconf_retry_error(ss, ss + Ustrlen(ss), &basic_errno, &more_errno);
    if (error != NULL)
      {
      printf("%s\n", CS error);
      return EXIT_FAILURE;
      }

    /* For the {MAIL,RCPT,DATA}_4xx errors, a value of 255 means "any", and a
    code > 100 as an error is for matching codes to the decade. Turn them into
    a real error code, off the decade. */

    if (basic_errno == ERRNO_MAIL4XX ||
        basic_errno == ERRNO_RCPT4XX ||
        basic_errno == ERRNO_DATA4XX)
      {
      int code = (more_errno >> 8) & 255;
      if (code == 255)
        more_errno = (more_errno & 0xffff00ff) | (21 << 8);
      else if (code > 100)
        more_errno = (more_errno & 0xffff00ff) | ((code - 96) << 8);
      }
    }

  if (!(yield = retry_find_config(s1, s2, basic_errno, more_errno)))
    printf("No retry information found\n");
  else
    {
    retry_rule *r;
    more_errno = yield->more_errno;
    printf("Retry rule: %s  ", yield->pattern);

    if (yield->basic_errno == ERRNO_EXIMQUOTA)
      {
      printf("quota%s%s  ",
        (more_errno > 0)? "_" : "",
        (more_errno > 0)? readconf_printtime(more_errno) : US"");
      }
    else if (yield->basic_errno == ECONNREFUSED)
      {
      printf("refused%s%s  ",
        (more_errno > 0)? "_" : "",
        (more_errno == 'M')? "MX" :
        (more_errno == 'A')? "A" : "");
      }
    else if (yield->basic_errno == ETIMEDOUT)
      {
      printf("timeout");
      if ((more_errno & RTEF_CTOUT) != 0) printf("_connect");
      more_errno &= 255;
      if (more_errno != 0) printf("_%s",
        (more_errno == 'M')? "MX" : "A");
      printf("  ");
      }
    else if (yield->basic_errno == ERRNO_AUTHFAIL)
      printf("auth_failed  ");
    else printf("*  ");

    for (r = yield->rules; r; r = r->next)
      {
      printf("%c,%s", r->rule, readconf_printtime(r->timeout)); /* Do not */
      printf(",%s", readconf_printtime(r->p1));                 /* amalgamate */
      if (r->rule == 'G')
        {
        int x = r->p2;
        int f = x % 1000;
        int d = 100;
        printf(",%d.", x/1000);
        do
          {
          printf("%d", f/d);
          f %= d;
          d /= 10;
          }
        while (f != 0);
        }
      printf("; ");
      }

    printf("\n");
    }
  exim_exit(EXIT_SUCCESS, US"main");
  }

/* Handle a request to list one or more configuration options */
/* If -n was set, we suppress some information */

if (list_options)
  {
  BOOL fail = FALSE;
  set_process_info("listing variables");
  if (recipients_arg >= argc)
    fail = !readconf_print(US"all", NULL, flag_n);
  else for (i = recipients_arg; i < argc; i++)
    {
    if (i < argc - 1 &&
	(Ustrcmp(argv[i], "router") == 0 ||
	 Ustrcmp(argv[i], "transport") == 0 ||
	 Ustrcmp(argv[i], "authenticator") == 0 ||
	 Ustrcmp(argv[i], "macro") == 0 ||
	 Ustrcmp(argv[i], "environment") == 0))
      {
      fail |= !readconf_print(argv[i+1], argv[i], flag_n);
      i++;
      }
    else
      fail = !readconf_print(argv[i], NULL, flag_n);
    }
  exim_exit(fail ? EXIT_FAILURE : EXIT_SUCCESS, US"main");
  }

if (list_config)
  {
  set_process_info("listing config");
  exim_exit(readconf_print(US"config", NULL, flag_n)
		? EXIT_SUCCESS : EXIT_FAILURE, US"main");
  }


/* Initialise subsystems as required */
#ifndef DISABLE_DKIM
dkim_exim_init();
#endif
deliver_init();


/* Handle a request to deliver one or more messages that are already on the
queue. Values of msg_action other than MSG_DELIVER and MSG_LOAD are dealt with
above. MSG_LOAD is handled with -be (which is the only time it applies) below.

Delivery of specific messages is typically used for a small number when
prodding by hand (when the option forced_delivery will be set) or when
re-execing to regain root privilege. Each message delivery must happen in a
separate process, so we fork a process for each one, and run them sequentially
so that debugging output doesn't get intertwined, and to avoid spawning too
many processes if a long list is given. However, don't fork for the last one;
this saves a process in the common case when Exim is called to deliver just one
message. */

if (msg_action_arg > 0 && msg_action != MSG_LOAD)
  {
  if (prod_requires_admin && !f.admin_user)
    {
    fprintf(stderr, "exim: Permission denied\n");
    exim_exit(EXIT_FAILURE, US"main");
    }
  set_process_info("delivering specified messages");
  if (deliver_give_up) forced_delivery = f.deliver_force_thaw = TRUE;
  for (i = msg_action_arg; i < argc; i++)
    {
    int status;
    pid_t pid;
    if (i == argc - 1)
      (void)deliver_message(argv[i], forced_delivery, deliver_give_up);
    else if ((pid = fork()) == 0)
      {
      (void)deliver_message(argv[i], forced_delivery, deliver_give_up);
      _exit(EXIT_SUCCESS);
      }
    else if (pid < 0)
      {
      fprintf(stderr, "failed to fork delivery process for %s: %s\n", argv[i],
        strerror(errno));
      exim_exit(EXIT_FAILURE, US"main");
      }
    else wait(&status);
    }
  exim_exit(EXIT_SUCCESS, US"main");
  }


/* If only a single queue run is requested, without SMTP listening, we can just
turn into a queue runner, with an optional starting message id. */

if (queue_interval == 0 && !f.daemon_listen)
  {
  DEBUG(D_queue_run) debug_printf("Single queue run%s%s%s%s\n",
    (start_queue_run_id == NULL)? US"" : US" starting at ",
    (start_queue_run_id == NULL)? US"" : start_queue_run_id,
    (stop_queue_run_id == NULL)?  US"" : US" stopping at ",
    (stop_queue_run_id == NULL)?  US"" : stop_queue_run_id);
  if (*queue_name)
    set_process_info("running the '%s' queue (single queue run)", queue_name);
  else
    set_process_info("running the queue (single queue run)");
  queue_run(start_queue_run_id, stop_queue_run_id, FALSE);
  exim_exit(EXIT_SUCCESS, US"main");
  }


/* Find the login name of the real user running this process. This is always
needed when receiving a message, because it is written into the spool file. It
may also be used to construct a from: or a sender: header, and in this case we
need the user's full name as well, so save a copy of it, checked for RFC822
syntax and munged if necessary, if it hasn't previously been set by the -F
argument. We may try to get the passwd entry more than once, in case NIS or
other delays are in evidence. Save the home directory for use in filter testing
(only). */

for (i = 0;;)
  {
  if ((pw = getpwuid(real_uid)) != NULL)
    {
    originator_login = string_copy(US pw->pw_name);
    originator_home = string_copy(US pw->pw_dir);

    /* If user name has not been set by -F, set it from the passwd entry
    unless -f has been used to set the sender address by a trusted user. */

    if (!originator_name)
      {
      if (!sender_address || (!f.trusted_caller && filter_test == FTEST_NONE))
        {
        uschar *name = US pw->pw_gecos;
        uschar *amp = Ustrchr(name, '&');
        uschar buffer[256];

        /* Most Unix specify that a '&' character in the gecos field is
        replaced by a copy of the login name, and some even specify that
        the first character should be upper cased, so that's what we do. */

        if (amp)
          {
          int loffset;
          string_format(buffer, sizeof(buffer), "%.*s%n%s%s",
            (int)(amp - name), name, &loffset, originator_login, amp + 1);
          buffer[loffset] = toupper(buffer[loffset]);
          name = buffer;
          }

        /* If a pattern for matching the gecos field was supplied, apply
        it and then expand the name string. */

        if (gecos_pattern && gecos_name)
          {
          const pcre *re;
          re = regex_must_compile(gecos_pattern, FALSE, TRUE); /* Use malloc */

          if (regex_match_and_setup(re, name, 0, -1))
            {
            uschar *new_name = expand_string(gecos_name);
            expand_nmax = -1;
            if (new_name)
              {
              DEBUG(D_receive) debug_printf("user name \"%s\" extracted from "
                "gecos field \"%s\"\n", new_name, name);
              name = new_name;
              }
            else DEBUG(D_receive) debug_printf("failed to expand gecos_name string "
              "\"%s\": %s\n", gecos_name, expand_string_message);
            }
          else DEBUG(D_receive) debug_printf("gecos_pattern \"%s\" did not match "
            "gecos field \"%s\"\n", gecos_pattern, name);
          store_free((void *)re);
          }
        originator_name = string_copy(name);
        }

      /* A trusted caller has used -f but not -F */

      else originator_name = US"";
      }

    /* Break the retry loop */

    break;
    }

  if (++i > finduser_retries) break;
  sleep(1);
  }

/* If we cannot get a user login, log the incident and give up, unless the
configuration specifies something to use. When running in the test harness,
any setting of unknown_login overrides the actual name. */

if (originator_login == NULL || f.running_in_test_harness)
  {
  if (unknown_login != NULL)
    {
    originator_login = expand_string(unknown_login);
    if (originator_name == NULL && unknown_username != NULL)
      originator_name = expand_string(unknown_username);
    if (originator_name == NULL) originator_name = US"";
    }
  if (originator_login == NULL)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Failed to get user name for uid %d",
      (int)real_uid);
  }

/* Ensure that the user name is in a suitable form for use as a "phrase" in an
RFC822 address.*/

originator_name = string_copy(parse_fix_phrase(originator_name,
  Ustrlen(originator_name), big_buffer, big_buffer_size));

/* If a message is created by this call of Exim, the uid/gid of its originator
are those of the caller. These values are overridden if an existing message is
read in from the spool. */

originator_uid = real_uid;
originator_gid = real_gid;

DEBUG(D_receive) debug_printf("originator: uid=%d gid=%d login=%s name=%s\n",
  (int)originator_uid, (int)originator_gid, originator_login, originator_name);

/* Run in daemon and/or queue-running mode. The function daemon_go() never
returns. We leave this till here so that the originator_ fields are available
for incoming messages via the daemon. The daemon cannot be run in mua_wrapper
mode. */

if (f.daemon_listen || f.inetd_wait_mode || queue_interval > 0)
  {
  if (mua_wrapper)
    {
    fprintf(stderr, "Daemon cannot be run when mua_wrapper is set\n");
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Daemon cannot be run when "
      "mua_wrapper is set");
    }
  daemon_go();
  }

/* If the sender ident has not been set (by a trusted caller) set it to
the caller. This will get overwritten below for an inetd call. If a trusted
caller has set it empty, unset it. */

if (sender_ident == NULL) sender_ident = originator_login;
  else if (sender_ident[0] == 0) sender_ident = NULL;

/* Handle the -brw option, which is for checking out rewriting rules. Cause log
writes (on errors) to go to stderr instead. Can't do this earlier, as want the
originator_* variables set. */

if (test_rewrite_arg >= 0)
  {
  f.really_exim = FALSE;
  if (test_rewrite_arg >= argc)
    {
    printf("-brw needs an address argument\n");
    exim_exit(EXIT_FAILURE, US"main");
    }
  rewrite_test(argv[test_rewrite_arg]);
  exim_exit(EXIT_SUCCESS, US"main");
  }

/* A locally-supplied message is considered to be coming from a local user
unless a trusted caller supplies a sender address with -f, or is passing in the
message via SMTP (inetd invocation or otherwise). */

if ((sender_address == NULL && !smtp_input) ||
    (!f.trusted_caller && filter_test == FTEST_NONE))
  {
  f.sender_local = TRUE;

  /* A trusted caller can supply authenticated_sender and authenticated_id
  via -oMas and -oMai and if so, they will already be set. Otherwise, force
  defaults except when host checking. */

  if (authenticated_sender == NULL && !host_checking)
    authenticated_sender = string_sprintf("%s@%s", originator_login,
      qualify_domain_sender);
  if (authenticated_id == NULL && !host_checking)
    authenticated_id = originator_login;
  }

/* Trusted callers are always permitted to specify the sender address.
Untrusted callers may specify it if it matches untrusted_set_sender, or if what
is specified is the empty address. However, if a trusted caller does not
specify a sender address for SMTP input, we leave sender_address unset. This
causes the MAIL commands to be honoured. */

if ((!smtp_input && sender_address == NULL) ||
    !receive_check_set_sender(sender_address))
  {
  /* Either the caller is not permitted to set a general sender, or this is
  non-SMTP input and the trusted caller has not set a sender. If there is no
  sender, or if a sender other than <> is set, override with the originator's
  login (which will get qualified below), except when checking things. */

  if (sender_address == NULL             /* No sender_address set */
       ||                                /*         OR            */
       (sender_address[0] != 0 &&        /* Non-empty sender address, AND */
       !checking))                       /* Not running tests, including filter tests */
    {
    sender_address = originator_login;
    f.sender_address_forced = FALSE;
    sender_address_domain = 0;
    }
  }

/* Remember whether an untrusted caller set the sender address */

f.sender_set_untrusted = sender_address != originator_login && !f.trusted_caller;

/* Ensure that the sender address is fully qualified unless it is the empty
address, which indicates an error message, or doesn't exist (root caller, smtp
interface, no -f argument). */

if (sender_address != NULL && sender_address[0] != 0 &&
    sender_address_domain == 0)
  sender_address = string_sprintf("%s@%s", local_part_quote(sender_address),
    qualify_domain_sender);

DEBUG(D_receive) debug_printf("sender address = %s\n", sender_address);

/* Handle a request to verify a list of addresses, or test them for delivery.
This must follow the setting of the sender address, since routers can be
predicated upon the sender. If no arguments are given, read addresses from
stdin. Set debug_level to at least D_v to get full output for address testing.
*/

if (verify_address_mode || f.address_test_mode)
  {
  int exit_value = 0;
  int flags = vopt_qualify;

  if (verify_address_mode)
    {
    if (!verify_as_sender) flags |= vopt_is_recipient;
    DEBUG(D_verify) debug_print_ids(US"Verifying:");
    }

  else
    {
    flags |= vopt_is_recipient;
    debug_selector |= D_v;
    debug_file = stderr;
    debug_fd = fileno(debug_file);
    DEBUG(D_verify) debug_print_ids(US"Address testing:");
    }

  if (recipients_arg < argc)
    {
    while (recipients_arg < argc)
      {
      uschar *s = argv[recipients_arg++];
      while (*s != 0)
        {
        BOOL finished = FALSE;
        uschar *ss = parse_find_address_end(s, FALSE);
        if (*ss == ',') *ss = 0; else finished = TRUE;
        test_address(s, flags, &exit_value);
        s = ss;
        if (!finished)
          while (*(++s) != 0 && (*s == ',' || isspace(*s)));
        }
      }
    }

  else for (;;)
    {
    uschar *s = get_stdinput(NULL, NULL);
    if (s == NULL) break;
    test_address(s, flags, &exit_value);
    }

  route_tidyup();
  exim_exit(exit_value, US"main");
  }

/* Handle expansion checking. Either expand items on the command line, or read
from stdin if there aren't any. If -Mset was specified, load the message so
that its variables can be used, but restrict this facility to admin users.
Otherwise, if -bem was used, read a message from stdin. */

if (expansion_test)
  {
  dns_init(FALSE, FALSE, FALSE);
  if (msg_action_arg > 0 && msg_action == MSG_LOAD)
    {
    uschar spoolname[256];  /* Not big_buffer; used in spool_read_header() */
    if (!f.admin_user)
      exim_fail("exim: permission denied\n");
    message_id = argv[msg_action_arg];
    (void)string_format(spoolname, sizeof(spoolname), "%s-H", message_id);
    if ((deliver_datafile = spool_open_datafile(message_id)) < 0)
      printf ("Failed to load message datafile %s\n", message_id);
    if (spool_read_header(spoolname, TRUE, FALSE) != spool_read_OK)
      printf ("Failed to load message %s\n", message_id);
    }

  /* Read a test message from a file. We fudge it up to be on stdin, saving
  stdin itself for later reading of expansion strings. */

  else if (expansion_test_message)
    {
    int save_stdin = dup(0);
    int fd = Uopen(expansion_test_message, O_RDONLY, 0);
    if (fd < 0)
      exim_fail("exim: failed to open %s: %s\n", expansion_test_message,
        strerror(errno));
    (void) dup2(fd, 0);
    filter_test = FTEST_USER;      /* Fudge to make it look like filter test */
    message_ended = END_NOTENDED;
    read_message_body(receive_msg(extract_recipients));
    message_linecount += body_linecount;
    (void)dup2(save_stdin, 0);
    (void)close(save_stdin);
    clearerr(stdin);               /* Required by Darwin */
    }

  /* Only admin users may see config-file macros this way */

  if (!f.admin_user) macros_user = macros = mlast = NULL;

  /* Allow $recipients for this testing */

  f.enable_dollar_recipients = TRUE;

  /* Expand command line items */

  if (recipients_arg < argc)
    while (recipients_arg < argc)
      expansion_test_line(argv[recipients_arg++]);

  /* Read stdin */

  else
    {
    char *(*fn_readline)(const char *) = NULL;
    void (*fn_addhist)(const char *) = NULL;
    uschar * s;

#ifdef USE_READLINE
    void *dlhandle = set_readline(&fn_readline, &fn_addhist);
#endif

    while (s = get_stdinput(fn_readline, fn_addhist))
      expansion_test_line(s);

#ifdef USE_READLINE
    if (dlhandle) dlclose(dlhandle);
#endif
    }

  /* The data file will be open after -Mset */

  if (deliver_datafile >= 0)
    {
    (void)close(deliver_datafile);
    deliver_datafile = -1;
    }

  exim_exit(EXIT_SUCCESS, US"main: expansion test");
  }


/* The active host name is normally the primary host name, but it can be varied
for hosts that want to play several parts at once. We need to ensure that it is
set for host checking, and for receiving messages. */

smtp_active_hostname = primary_hostname;
if (raw_active_hostname != NULL)
  {
  uschar *nah = expand_string(raw_active_hostname);
  if (nah == NULL)
    {
    if (!f.expand_string_forcedfail)
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to expand \"%s\" "
        "(smtp_active_hostname): %s", raw_active_hostname,
        expand_string_message);
    }
  else if (nah[0] != 0) smtp_active_hostname = nah;
  }

/* Handle host checking: this facility mocks up an incoming SMTP call from a
given IP address so that the blocking and relay configuration can be tested.
Unless a sender_ident was set by -oMt, we discard it (the default is the
caller's login name). An RFC 1413 call is made only if we are running in the
test harness and an incoming interface and both ports are specified, because
there is no TCP/IP call to find the ident for. */

if (host_checking)
  {
  int x[4];
  int size;

  if (!sender_ident_set)
    {
    sender_ident = NULL;
    if (f.running_in_test_harness && sender_host_port != 0 &&
        interface_address != NULL && interface_port != 0)
      verify_get_ident(1413);
    }

  /* In case the given address is a non-canonical IPv6 address, canonicalize
  it. The code works for both IPv4 and IPv6, as it happens. */

  size = host_aton(sender_host_address, x);
  sender_host_address = store_get(48);  /* large enough for full IPv6 */
  (void)host_nmtoa(size, x, -1, sender_host_address, ':');

  /* Now set up for testing */

  host_build_sender_fullhost();
  smtp_input = TRUE;
  smtp_in = stdin;
  smtp_out = stdout;
  f.sender_local = FALSE;
  f.sender_host_notsocket = TRUE;
  debug_file = stderr;
  debug_fd = fileno(debug_file);
  fprintf(stdout, "\n**** SMTP testing session as if from host %s\n"
    "**** but without any ident (RFC 1413) callback.\n"
    "**** This is not for real!\n\n",
      sender_host_address);

  memset(sender_host_cache, 0, sizeof(sender_host_cache));
  if (verify_check_host(&hosts_connection_nolog) == OK)
    BIT_CLEAR(log_selector, log_selector_size, Li_smtp_connection);
  log_write(L_smtp_connection, LOG_MAIN, "%s", smtp_get_connection_info());

  /* NOTE: We do *not* call smtp_log_no_mail() if smtp_start_session() fails,
  because a log line has already been written for all its failure exists
  (usually "connection refused: <reason>") and writing another one is
  unnecessary clutter. */

  if (smtp_start_session())
    {
    for (reset_point = store_get(0); ; store_reset(reset_point))
      {
      if (smtp_setup_msg() <= 0) break;
      if (!receive_msg(FALSE)) break;

      return_path = sender_address = NULL;
      dnslist_domain = dnslist_matched = NULL;
#ifndef DISABLE_DKIM
      dkim_cur_signer = NULL;
#endif
      acl_var_m = NULL;
      deliver_localpart_orig = NULL;
      deliver_domain_orig = NULL;
      callout_address = sending_ip_address = NULL;
      sender_rate = sender_rate_limit = sender_rate_period = NULL;
      }
    smtp_log_no_mail();
    }
  exim_exit(EXIT_SUCCESS, US"main");
  }


/* Arrange for message reception if recipients or SMTP were specified;
otherwise complain unless a version print (-bV) happened or this is a filter
verification test or info dump.
In the former case, show the configuration file name. */

if (recipients_arg >= argc && !extract_recipients && !smtp_input)
  {
  if (version_printed)
    {
    if (Ustrchr(config_main_filelist, ':'))
      printf("Configuration file search path is %s\n", config_main_filelist);
    printf("Configuration file is %s\n", config_main_filename);
    return EXIT_SUCCESS;
    }

  if (info_flag != CMDINFO_NONE)
    {
    show_exim_information(info_flag, info_stdout ? stdout : stderr);
    return info_stdout ? EXIT_SUCCESS : EXIT_FAILURE;
    }

  if (filter_test == FTEST_NONE)
    exim_usage(called_as);
  }


/* If mua_wrapper is set, Exim is being used to turn an MUA that submits on the
standard input into an MUA that submits to a smarthost over TCP/IP. We know
that we are not called from inetd, because that is rejected above. The
following configuration settings are forced here:

  (1) Synchronous delivery (-odi)
  (2) Errors to stderr (-oep == -oeq)
  (3) No parallel remote delivery
  (4) Unprivileged delivery

We don't force overall queueing options because there are several of them;
instead, queueing is avoided below when mua_wrapper is set. However, we do need
to override any SMTP queueing. */

if (mua_wrapper)
  {
  f.synchronous_delivery = TRUE;
  arg_error_handling = ERRORS_STDERR;
  remote_max_parallel = 1;
  deliver_drop_privilege = TRUE;
  f.queue_smtp = FALSE;
  queue_smtp_domains = NULL;
#ifdef SUPPORT_I18N
  message_utf8_downconvert = -1;	/* convert-if-needed */
#endif
  }


/* Prepare to accept one or more new messages on the standard input. When a
message has been read, its id is returned in message_id[]. If doing immediate
delivery, we fork a delivery process for each received message, except for the
last one, where we can save a process switch.

It is only in non-smtp mode that error_handling is allowed to be changed from
its default of ERRORS_SENDER by argument. (Idle thought: are any of the
sendmail error modes other than -oem ever actually used? Later: yes.) */

if (!smtp_input) error_handling = arg_error_handling;

/* If this is an inetd call, ensure that stderr is closed to prevent panic
logging being sent down the socket and make an identd call to get the
sender_ident. */

else if (f.is_inetd)
  {
  (void)fclose(stderr);
  exim_nullstd();                       /* Re-open to /dev/null */
  verify_get_ident(IDENT_PORT);
  host_build_sender_fullhost();
  set_process_info("handling incoming connection from %s via inetd",
    sender_fullhost);
  }

/* If the sender host address has been set, build sender_fullhost if it hasn't
already been done (which it will have been for inetd). This caters for the
case when it is forced by -oMa. However, we must flag that it isn't a socket,
so that the test for IP options is skipped for -bs input. */

if (sender_host_address && !sender_fullhost)
  {
  host_build_sender_fullhost();
  set_process_info("handling incoming connection from %s via -oMa",
    sender_fullhost);
  f.sender_host_notsocket = TRUE;
  }

/* Otherwise, set the sender host as unknown except for inetd calls. This
prevents host checking in the case of -bs not from inetd and also for -bS. */

else if (!f.is_inetd) f.sender_host_unknown = TRUE;

/* If stdout does not exist, then dup stdin to stdout. This can happen
if exim is started from inetd. In this case fd 0 will be set to the socket,
but fd 1 will not be set. This also happens for passed SMTP channels. */

if (fstat(1, &statbuf) < 0) (void)dup2(0, 1);

/* Set up the incoming protocol name and the state of the program. Root is
allowed to force received protocol via the -oMr option above. If we have come
via inetd, the process info has already been set up. We don't set
received_protocol here for smtp input, as it varies according to
batch/HELO/EHLO/AUTH/TLS. */

if (smtp_input)
  {
  if (!f.is_inetd) set_process_info("accepting a local %sSMTP message from <%s>",
    smtp_batched_input? "batched " : "",
    (sender_address!= NULL)? sender_address : originator_login);
  }
else
  {
  int old_pool = store_pool;
  store_pool = POOL_PERM;
  if (!received_protocol)
    received_protocol = string_sprintf("local%s", called_as);
  store_pool = old_pool;
  set_process_info("accepting a local non-SMTP message from <%s>",
    sender_address);
  }

/* Initialize the session_local_queue-only flag (this will be ignored if
mua_wrapper is set) */

queue_check_only();
session_local_queue_only = queue_only;

/* For non-SMTP and for batched SMTP input, check that there is enough space on
the spool if so configured. On failure, we must not attempt to send an error
message! (For interactive SMTP, the check happens at MAIL FROM and an SMTP
error code is given.) */

if ((!smtp_input || smtp_batched_input) && !receive_check_fs(0))
  exim_fail("exim: insufficient disk space\n");

/* If this is smtp input of any kind, real or batched, handle the start of the
SMTP session.

NOTE: We do *not* call smtp_log_no_mail() if smtp_start_session() fails,
because a log line has already been written for all its failure exists
(usually "connection refused: <reason>") and writing another one is
unnecessary clutter. */

if (smtp_input)
  {
  smtp_in = stdin;
  smtp_out = stdout;
  memset(sender_host_cache, 0, sizeof(sender_host_cache));
  if (verify_check_host(&hosts_connection_nolog) == OK)
    BIT_CLEAR(log_selector, log_selector_size, Li_smtp_connection);
  log_write(L_smtp_connection, LOG_MAIN, "%s", smtp_get_connection_info());
  if (!smtp_start_session())
    {
    mac_smtp_fflush();
    exim_exit(EXIT_SUCCESS, US"smtp_start toplevel");
    }
  }

/* Otherwise, set up the input size limit here. */

else
  {
  thismessage_size_limit = expand_string_integer(message_size_limit, TRUE);
  if (expand_string_message)
    if (thismessage_size_limit == -1)
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to expand "
        "message_size_limit: %s", expand_string_message);
    else
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "invalid value for "
        "message_size_limit: %s", expand_string_message);
  }

/* Loop for several messages when reading SMTP input. If we fork any child
processes, we don't want to wait for them unless synchronous delivery is
requested, so set SIGCHLD to SIG_IGN in that case. This is not necessarily the
same as SIG_DFL, despite the fact that documentation often lists the default as
"ignore". This is a confusing area. This is what I know:

At least on some systems (e.g. Solaris), just setting SIG_IGN causes child
processes that complete simply to go away without ever becoming defunct. You
can't then wait for them - but we don't want to wait for them in the
non-synchronous delivery case. However, this behaviour of SIG_IGN doesn't
happen for all OS (e.g. *BSD is different).

But that's not the end of the story. Some (many? all?) systems have the
SA_NOCLDWAIT option for sigaction(). This requests the behaviour that Solaris
has by default, so it seems that the difference is merely one of default
(compare restarting vs non-restarting signals).

To cover all cases, Exim sets SIG_IGN with SA_NOCLDWAIT here if it can. If not,
it just sets SIG_IGN. To be on the safe side it also calls waitpid() at the end
of the loop below. Paranoia rules.

February 2003: That's *still* not the end of the story. There are now versions
of Linux (where SIG_IGN does work) that are picky. If, having set SIG_IGN, a
process then calls waitpid(), a grumble is written to the system log, because
this is logically inconsistent. In other words, it doesn't like the paranoia.
As a consequence of this, the waitpid() below is now excluded if we are sure
that SIG_IGN works. */

if (!f.synchronous_delivery)
  {
  #ifdef SA_NOCLDWAIT
  struct sigaction act;
  act.sa_handler = SIG_IGN;
  sigemptyset(&(act.sa_mask));
  act.sa_flags = SA_NOCLDWAIT;
  sigaction(SIGCHLD, &act, NULL);
  #else
  signal(SIGCHLD, SIG_IGN);
  #endif
  }

/* Save the current store pool point, for resetting at the start of
each message, and save the real sender address, if any. */

reset_point = store_get(0);
real_sender_address = sender_address;

/* Loop to receive messages; receive_msg() returns TRUE if there are more
messages to be read (SMTP input), or FALSE otherwise (not SMTP, or SMTP channel
collapsed). */

while (more)
  {
  message_id[0] = 0;

  /* Handle the SMTP case; call smtp_setup_mst() to deal with the initial SMTP
  input and build the recipients list, before calling receive_msg() to read the
  message proper. Whatever sender address is given in the SMTP transaction is
  often ignored for local senders - we use the actual sender, which is normally
  either the underlying user running this process or a -f argument provided by
  a trusted caller. It is saved in real_sender_address. The test for whether to
  accept the SMTP sender is encapsulated in receive_check_set_sender(). */

  if (smtp_input)
    {
    int rc;
    if ((rc = smtp_setup_msg()) > 0)
      {
      if (real_sender_address != NULL &&
          !receive_check_set_sender(sender_address))
        {
        sender_address = raw_sender = real_sender_address;
        sender_address_unrewritten = NULL;
        }

      /* For batched SMTP, we have to run the acl_not_smtp_start ACL, since it
      isn't really SMTP, so no other ACL will run until the acl_not_smtp one at
      the very end. The result of the ACL is ignored (as for other non-SMTP
      messages). It is run for its potential side effects. */

      if (smtp_batched_input && acl_not_smtp_start != NULL)
        {
        uschar *user_msg, *log_msg;
        f.enable_dollar_recipients = TRUE;
        (void)acl_check(ACL_WHERE_NOTSMTP_START, NULL, acl_not_smtp_start,
          &user_msg, &log_msg);
        f.enable_dollar_recipients = FALSE;
        }

      /* Now get the data for the message */

      more = receive_msg(extract_recipients);
      if (message_id[0] == 0)
        {
	cancel_cutthrough_connection(TRUE, US"receive dropped");
        if (more) goto moreloop;
        smtp_log_no_mail();               /* Log no mail if configured */
        exim_exit(EXIT_FAILURE, US"receive toplevel");
        }
      }
    else
      {
      cancel_cutthrough_connection(TRUE, US"message setup dropped");
      smtp_log_no_mail();               /* Log no mail if configured */
      exim_exit(rc ? EXIT_FAILURE : EXIT_SUCCESS, US"msg setup toplevel");
      }
    }

  /* In the non-SMTP case, we have all the information from the command
  line, but must process it in case it is in the more general RFC822
  format, and in any case, to detect syntax errors. Also, it appears that
  the use of comma-separated lists as single arguments is common, so we
  had better support them. */

  else
    {
    int i;
    int rcount = 0;
    int count = argc - recipients_arg;
    uschar **list = argv + recipients_arg;

    /* These options cannot be changed dynamically for non-SMTP messages */

    f.active_local_sender_retain = local_sender_retain;
    f.active_local_from_check = local_from_check;

    /* Save before any rewriting */

    raw_sender = string_copy(sender_address);

    /* Loop for each argument */

    for (i = 0; i < count; i++)
      {
      int start, end, domain;
      uschar *errmess;
      uschar *s = list[i];

      /* Loop for each comma-separated address */

      while (*s != 0)
        {
        BOOL finished = FALSE;
        uschar *recipient;
        uschar *ss = parse_find_address_end(s, FALSE);

        if (*ss == ',') *ss = 0; else finished = TRUE;

        /* Check max recipients - if -t was used, these aren't recipients */

        if (recipients_max > 0 && ++rcount > recipients_max &&
            !extract_recipients)
          if (error_handling == ERRORS_STDERR)
            {
            fprintf(stderr, "exim: too many recipients\n");
            exim_exit(EXIT_FAILURE, US"main");
            }
          else
            return
              moan_to_sender(ERRMESS_TOOMANYRECIP, NULL, NULL, stdin, TRUE)?
                errors_sender_rc : EXIT_FAILURE;

#ifdef SUPPORT_I18N
	{
	BOOL b = allow_utf8_domains;
	allow_utf8_domains = TRUE;
#endif
        recipient =
          parse_extract_address(s, &errmess, &start, &end, &domain, FALSE);

#ifdef SUPPORT_I18N
	if (string_is_utf8(recipient))
	  message_smtputf8 = TRUE;
	else
	  allow_utf8_domains = b;
	}
#endif
        if (domain == 0 && !f.allow_unqualified_recipient)
          {
          recipient = NULL;
          errmess = US"unqualified recipient address not allowed";
          }

        if (recipient == NULL)
          {
          if (error_handling == ERRORS_STDERR)
            {
            fprintf(stderr, "exim: bad recipient address \"%s\": %s\n",
              string_printing(list[i]), errmess);
            exim_exit(EXIT_FAILURE, US"main");
            }
          else
            {
            error_block eblock;
            eblock.next = NULL;
            eblock.text1 = string_printing(list[i]);
            eblock.text2 = errmess;
            return
              moan_to_sender(ERRMESS_BADARGADDRESS, &eblock, NULL, stdin, TRUE)?
                errors_sender_rc : EXIT_FAILURE;
            }
          }

        receive_add_recipient(recipient, -1);
        s = ss;
        if (!finished)
          while (*(++s) != 0 && (*s == ',' || isspace(*s)));
        }
      }

    /* Show the recipients when debugging */

    DEBUG(D_receive)
      {
      int i;
      if (sender_address != NULL) debug_printf("Sender: %s\n", sender_address);
      if (recipients_list != NULL)
        {
        debug_printf("Recipients:\n");
        for (i = 0; i < recipients_count; i++)
          debug_printf("  %s\n", recipients_list[i].address);
        }
      }

    /* Run the acl_not_smtp_start ACL if required. The result of the ACL is
    ignored; rejecting here would just add complication, and it can just as
    well be done later. Allow $recipients to be visible in the ACL. */

    if (acl_not_smtp_start)
      {
      uschar *user_msg, *log_msg;
      f.enable_dollar_recipients = TRUE;
      (void)acl_check(ACL_WHERE_NOTSMTP_START, NULL, acl_not_smtp_start,
        &user_msg, &log_msg);
      f.enable_dollar_recipients = FALSE;
      }

    /* Pause for a while waiting for input.  If none received in that time,
    close the logfile, if we had one open; then if we wait for a long-running
    datasource (months, in one use-case) log rotation will not leave us holding
    the file copy. */

    if (!receive_timeout)
      {
      struct timeval t = { .tv_sec = 30*60, .tv_usec = 0 };	/* 30 minutes */
      fd_set r;

      FD_ZERO(&r); FD_SET(0, &r);
      if (select(1, &r, NULL, NULL, &t) == 0) mainlog_close();
      }

    /* Read the data for the message. If filter_test is not FTEST_NONE, this
    will just read the headers for the message, and not write anything onto the
    spool. */

    message_ended = END_NOTENDED;
    more = receive_msg(extract_recipients);

    /* more is always FALSE here (not SMTP message) when reading a message
    for real; when reading the headers of a message for filter testing,
    it is TRUE if the headers were terminated by '.' and FALSE otherwise. */

    if (message_id[0] == 0) exim_exit(EXIT_FAILURE, US"main");
    }  /* Non-SMTP message reception */

  /* If this is a filter testing run, there are headers in store, but
  no message on the spool. Run the filtering code in testing mode, setting
  the domain to the qualify domain and the local part to the current user,
  unless they have been set by options. The prefix and suffix are left unset
  unless specified. The the return path is set to to the sender unless it has
  already been set from a return-path header in the message. */

  if (filter_test != FTEST_NONE)
    {
    deliver_domain = (ftest_domain != NULL)?
      ftest_domain : qualify_domain_recipient;
    deliver_domain_orig = deliver_domain;
    deliver_localpart = (ftest_localpart != NULL)?
      ftest_localpart : originator_login;
    deliver_localpart_orig = deliver_localpart;
    deliver_localpart_prefix = ftest_prefix;
    deliver_localpart_suffix = ftest_suffix;
    deliver_home = originator_home;

    if (return_path == NULL)
      {
      printf("Return-path copied from sender\n");
      return_path = string_copy(sender_address);
      }
    else
      printf("Return-path = %s\n", (return_path[0] == 0)? US"<>" : return_path);
    printf("Sender      = %s\n", (sender_address[0] == 0)? US"<>" : sender_address);

    receive_add_recipient(
      string_sprintf("%s%s%s@%s",
        (ftest_prefix == NULL)? US"" : ftest_prefix,
        deliver_localpart,
        (ftest_suffix == NULL)? US"" : ftest_suffix,
        deliver_domain), -1);

    printf("Recipient   = %s\n", recipients_list[0].address);
    if (ftest_prefix != NULL) printf("Prefix    = %s\n", ftest_prefix);
    if (ftest_suffix != NULL) printf("Suffix    = %s\n", ftest_suffix);

    if (chdir("/"))   /* Get away from wherever the user is running this from */
      {
      DEBUG(D_receive) debug_printf("chdir(\"/\") failed\n");
      exim_exit(EXIT_FAILURE, US"main");
      }

    /* Now we run either a system filter test, or a user filter test, or both.
    In the latter case, headers added by the system filter will persist and be
    available to the user filter. We need to copy the filter variables
    explicitly. */

    if ((filter_test & FTEST_SYSTEM) != 0)
      if (!filter_runtest(filter_sfd, filter_test_sfile, TRUE, more))
        exim_exit(EXIT_FAILURE, US"main");

    memcpy(filter_sn, filter_n, sizeof(filter_sn));

    if ((filter_test & FTEST_USER) != 0)
      if (!filter_runtest(filter_ufd, filter_test_ufile, FALSE, more))
        exim_exit(EXIT_FAILURE, US"main");

    exim_exit(EXIT_SUCCESS, US"main");
    }

  /* Else act on the result of message reception. We should not get here unless
  message_id[0] is non-zero. If queue_only is set, session_local_queue_only
  will be TRUE. If it is not, check on the number of messages received in this
  connection. */

  if (!session_local_queue_only &&
      smtp_accept_queue_per_connection > 0 &&
      receive_messagecount > smtp_accept_queue_per_connection)
    {
    session_local_queue_only = TRUE;
    queue_only_reason = 2;
    }

  /* Initialize local_queue_only from session_local_queue_only. If it is false,
  and queue_only_load is set, check that the load average is below it. If it is
  not, set local_queue_only TRUE. If queue_only_load_latch is true (the
  default), we put the whole session into queue_only mode. It then remains this
  way for any subsequent messages on the same SMTP connection. This is a
  deliberate choice; even though the load average may fall, it doesn't seem
  right to deliver later messages on the same call when not delivering earlier
  ones. However, there are odd cases where this is not wanted, so this can be
  changed by setting queue_only_load_latch false. */

  local_queue_only = session_local_queue_only;
  if (!local_queue_only && queue_only_load >= 0)
    {
    local_queue_only = (load_average = OS_GETLOADAVG()) > queue_only_load;
    if (local_queue_only)
      {
      queue_only_reason = 3;
      if (queue_only_load_latch) session_local_queue_only = TRUE;
      }
    }

  /* If running as an MUA wrapper, all queueing options and freezing options
  are ignored. */

  if (mua_wrapper)
    local_queue_only = f.queue_only_policy = f.deliver_freeze = FALSE;

  /* Log the queueing here, when it will get a message id attached, but
  not if queue_only is set (case 0). Case 1 doesn't happen here (too many
  connections). */

  if (local_queue_only)
    {
    cancel_cutthrough_connection(TRUE, US"no delivery; queueing");
    switch(queue_only_reason)
      {
      case 2:
	log_write(L_delay_delivery,
		LOG_MAIN, "no immediate delivery: more than %d messages "
	  "received in one connection", smtp_accept_queue_per_connection);
	break;

      case 3:
	log_write(L_delay_delivery,
		LOG_MAIN, "no immediate delivery: load average %.2f",
		(double)load_average/1000.0);
      break;
      }
    }

  else if (f.queue_only_policy || f.deliver_freeze)
    cancel_cutthrough_connection(TRUE, US"no delivery; queueing");

  /* Else do the delivery unless the ACL or local_scan() called for queue only
  or froze the message. Always deliver in a separate process. A fork failure is
  not a disaster, as the delivery will eventually happen on a subsequent queue
  run. The search cache must be tidied before the fork, as the parent will
  do it before exiting. The child will trigger a lookup failure and
  thereby defer the delivery if it tries to use (for example) a cached ldap
  connection that the parent has called unbind on. */

  else
    {
    pid_t pid;
    search_tidyup();

    if ((pid = fork()) == 0)
      {
      int rc;
      close_unwanted();      /* Close unwanted file descriptors and TLS */
      exim_nullstd();        /* Ensure std{in,out,err} exist */

      /* Re-exec Exim if we need to regain privilege (note: in mua_wrapper
      mode, deliver_drop_privilege is forced TRUE). */

      if (geteuid() != root_uid && !deliver_drop_privilege && !unprivileged)
        {
	delivery_re_exec(CEE_EXEC_EXIT);
        /* Control does not return here. */
        }

      /* No need to re-exec */

      rc = deliver_message(message_id, FALSE, FALSE);
      search_tidyup();
      _exit((!mua_wrapper || rc == DELIVER_MUA_SUCCEEDED)?
        EXIT_SUCCESS : EXIT_FAILURE);
      }

    if (pid < 0)
      {
      cancel_cutthrough_connection(TRUE, US"delivery fork failed");
      log_write(0, LOG_MAIN|LOG_PANIC, "failed to fork automatic delivery "
        "process: %s", strerror(errno));
      }
    else
      {
      release_cutthrough_connection(US"msg passed for delivery");

      /* In the parent, wait if synchronous delivery is required. This will
      always be the case in MUA wrapper mode. */

      if (f.synchronous_delivery)
	{
	int status;
	while (wait(&status) != pid);
	if ((status & 0x00ff) != 0)
	  log_write(0, LOG_MAIN|LOG_PANIC,
	    "process %d crashed with signal %d while delivering %s",
	    (int)pid, status & 0x00ff, message_id);
	if (mua_wrapper && (status & 0xffff) != 0) exim_exit(EXIT_FAILURE, US"main");
	}
      }
    }

  /* The loop will repeat if more is TRUE. If we do not know know that the OS
  automatically reaps children (see comments above the loop), clear away any
  finished subprocesses here, in case there are lots of messages coming in
  from the same source. */

  #ifndef SIG_IGN_WORKS
  while (waitpid(-1, NULL, WNOHANG) > 0);
  #endif

moreloop:
  return_path = sender_address = NULL;
  authenticated_sender = NULL;
  deliver_localpart_orig = NULL;
  deliver_domain_orig = NULL;
  deliver_host = deliver_host_address = NULL;
  dnslist_domain = dnslist_matched = NULL;
#ifdef WITH_CONTENT_SCAN
  malware_name = NULL;
#endif
  callout_address = NULL;
  sending_ip_address = NULL;
  acl_var_m = NULL;
  { int i; for(i=0; i<REGEX_VARS; i++) regex_vars[i] = NULL; }

  store_reset(reset_point);
  }

exim_exit(EXIT_SUCCESS, US"main");   /* Never returns */
return 0;                  /* To stop compiler warning */
}


/* End of exim.c */
