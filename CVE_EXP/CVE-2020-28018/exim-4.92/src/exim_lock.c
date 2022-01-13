/* A program to lock a file exactly as Exim would, for investigation of
interlocking problems.

Options:  -fcntl    use fcntl() lock
          -flock    use flock() lock
          -lockfile use lock file
          -mbx      use mbx locking rules, with either fcntl() or flock()

Default is -fcntl -lockfile.

Argument: the name of the lock file

Copyright (c) The Exim Maintainers 2016
*/

#include "os.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <utime.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <pwd.h>

/* Not all systems have flock() available. Those that do must define LOCK_SH
in sys/file.h. */

#ifndef LOCK_SH
#define NO_FLOCK
#endif


typedef unsigned BOOL;
#define FALSE 0
#define TRUE  1


/* Flag for timeout signal handler */

static int sigalrm_seen = FALSE;


/* We need to pull in strerror() and os_non_restarting_signal() from the
os.c source, if they are required for this OS. However, we don't need any of
the other stuff in os.c, so force the other macros to omit it. */

#ifndef OS_RESTARTING_SIGNAL
  #define OS_RESTARTING_SIGNAL
#endif

#ifndef OS_STRSIGNAL
  #define OS_STRSIGNAL
#endif

#ifndef OS_STREXIT
  #define OS_STREXIT
#endif

#ifndef OS_LOAD_AVERAGE
  #define OS_LOAD_AVERAGE
#endif

#ifndef FIND_RUNNING_INTERFACES
  #define FIND_RUNNING_INTERFACES
#endif

#ifndef OS_GET_DNS_RESOLVER_RES
  #define OS_GET_DNS_RESOLVER_RES
#endif

#include "../src/os.c"



/*************************************************
*             Timeout handler                    *
*************************************************/

static void
sigalrm_handler(int sig)
{
sig = sig;      /* Keep picky compilers happy */
sigalrm_seen = TRUE;
}



/*************************************************
*           Give usage and die                   *
*************************************************/

static void
usage(void)
{
printf("usage: exim_lock [-v] [-q] [-lockfile] [-fcntl] [-flock] [-mbx]\n"
       "       [-retries <n>] [-interval <n>] [-timeout <n>] [-restore-times]\n"
       "       <file name> [command]\n");
exit(1);
}



/*************************************************
*         Apply a lock to a file descriptor      *
*************************************************/

static int
apply_lock(int fd, int fcntltype, BOOL dofcntl, int fcntltime, BOOL doflock,
    int flocktime)
{
int yield = 0;
int save_errno;
struct flock lock_data;
lock_data.l_type = fcntltype;
lock_data.l_whence = lock_data.l_start = lock_data.l_len = 0;

sigalrm_seen = FALSE;

if (dofcntl)
  {
  if (fcntltime > 0)
    {
    os_non_restarting_signal(SIGALRM, sigalrm_handler);
    alarm(fcntltime);
    yield = fcntl(fd, F_SETLKW, &lock_data);
    save_errno = errno;
    alarm(0);
    errno = save_errno;
    }
  else yield = fcntl(fd, F_SETLK, &lock_data);
  if (yield < 0) printf("exim_lock: fcntl() failed: %s\n", strerror(errno));
  }

#ifndef NO_FLOCK
if (doflock && (yield >= 0))
  {
  int flocktype = (fcntltype == F_WRLCK)? LOCK_EX : LOCK_SH;
  if (flocktime > 0)
    {
    os_non_restarting_signal(SIGALRM, sigalrm_handler);
    alarm(flocktime);
    yield = flock(fd, flocktype);
    save_errno = errno;
    alarm(0);
    errno = save_errno;
    }
  else yield = flock(fd, flocktype | LOCK_NB);
  if (yield < 0) printf("exim_lock: flock() failed: %s\n", strerror(errno));
  }
#endif

return yield;
}



/*************************************************
*           The exim_lock program                *
*************************************************/

int main(int argc, char **argv)
{
int  lock_retries = 10;
int  lock_interval = 3;
int  lock_fcntl_timeout = 0;
int  lock_flock_timeout = 0;
int  i, j, len;
int  fd = -1;
int  hd = -1;
int  md = -1;
int  yield = 0;
time_t now = time(NULL);
BOOL use_lockfile = FALSE;
BOOL use_fcntl = FALSE;
BOOL use_flock = FALSE;
BOOL use_mbx = FALSE;
BOOL verbose = FALSE;
BOOL quiet = FALSE;
BOOL restore_times = FALSE;
char *filename;
char *lockname = NULL, *hitchname = NULL;
char *primary_hostname;
const char *command;
struct utsname s;
char buffer[256];
char tempname[256];

/* Decode options */

for (i = 1; i < argc; i++)
  {
  char *arg = argv[i];
  if (*arg != '-') break;
  if (strcmp(arg, "-fcntl") == 0) use_fcntl = TRUE;
  else if (strcmp(arg, "-flock") == 0) use_flock = TRUE;
  else if (strcmp(arg, "-lockfile") == 0) use_lockfile = TRUE;
  else if (strcmp(arg, "-mbx") == 0) use_mbx = TRUE;
  else if (strcmp(arg, "-v") == 0) verbose = TRUE;
  else if (strcmp(arg, "-q") == 0) quiet = TRUE;
  else if (strcmp(arg, "-restore-times") == 0) restore_times = TRUE;
  else if (++i < argc)
    {
    int value = atoi(argv[i]);
    if (strcmp(arg, "-retries") == 0) lock_retries = value;
    else if (strcmp(arg, "-interval") == 0) lock_interval = value;
    else if (strcmp(arg, "-timeout") == 0)
      lock_fcntl_timeout = lock_flock_timeout = value;
    else usage();
    }
  else usage();
  }

if (quiet) verbose = FALSE;

/* Can't use flock() if the OS doesn't provide it */

#ifdef NO_FLOCK
if (use_flock)
  {
  printf("exim_lock: can't use flock() because it was not available in the\n"
         "           operating system when exim_lock was compiled\n");
  exit(1);
  }
#endif

/* Default is to use lockfiles and fcntl(). */

if (!use_lockfile && !use_fcntl && !use_flock && !use_mbx)
  use_lockfile = use_fcntl = TRUE;

/* Default fcntl() for use with mbx */

if (use_mbx && !use_fcntl && !use_flock) use_fcntl = TRUE;

/* Unset unused timeouts */

if (!use_fcntl) lock_fcntl_timeout = 0;
if (!use_flock) lock_flock_timeout = 0;

/* A file name is required */

if (i >= argc) usage();

filename = argv[i++];

/* Expand file names starting with ~ */

if (*filename == '~')
  {
  struct passwd *pw;

  if (*(++filename) == '/')
    pw = getpwuid(getuid());
  else
    {
    char *s = buffer;
    while (*filename != 0 && *filename != '/')
      *s++ = *filename++;
    *s = 0;
    pw = getpwnam(buffer);
    }

  if (pw == NULL)
    {
    printf("exim_lock: unable to expand file name %s\n", argv[i-1]);
    exit(1);
    }

  if ((int)strlen(pw->pw_dir) + (int)strlen(filename) + 1 > sizeof(buffer))
    {
    printf("exim_lock: expanded file name %s%s is too long", pw->pw_dir,
      filename);
    exit(1);
    }

  strcpy(buffer, pw->pw_dir);
  strcat(buffer, filename);
  filename = buffer;
  }

/* If using a lock file, prepare by creating the lock file name and
the hitching post name. */

if (use_lockfile)
  {
  if (uname(&s) < 0)
    {
    printf("exim_lock: failed to find host name using uname()\n");
    exit(1);
    }
  primary_hostname = s.nodename;

  len = (int)strlen(filename);
  lockname = malloc(len + 8);
  sprintf(lockname, "%s.lock", filename);
  hitchname = malloc(len + 32 + (int)strlen(primary_hostname));

  /* Presumably, this must match appendfile.c */
  sprintf(hitchname, "%s.%s.%08x.%08x", lockname, primary_hostname,
    (unsigned int)now, (unsigned int)getpid());

  if (verbose)
    printf("exim_lock: lockname =  %s\n           hitchname = %s\n", lockname,
      hitchname);
  }

/* Locking retry loop */

for (j = 0; j < lock_retries; j++)
  {
  int sleep_before_retry = TRUE;
  struct stat statbuf, ostatbuf, lstatbuf, statbuf2;
  int mbx_tmp_oflags;

  /* Try to build a lock file if so configured */

  if (use_lockfile)
    {
    int rc, rc2;
    if (verbose) printf("exim_lock: creating lock file\n");
    hd = open(hitchname, O_WRONLY | O_CREAT | O_EXCL, 0440);
    if (hd < 0)
      {
      printf("exim_lock: failed to create hitching post %s: %s\n", hitchname,
        strerror(errno));
      exit(1);
      }

    /* Apply hitching post algorithm. */

    if ((rc = link(hitchname, lockname)) != 0)
     rc2 = fstat(hd, &statbuf);
    (void)close(hd);
    unlink(hitchname);

    if (rc != 0 && (rc2 != 0 || statbuf.st_nlink != 2))
      {
      printf("exim_lock: failed to link hitching post to lock file\n");
      hd = -1;
      goto RETRY;
      }

    if (!quiet) printf("exim_lock: lock file successfully created\n");
    }

  /* We are done if no other locking required. */

  if (!use_fcntl && !use_flock && !use_mbx) break;

  /* Open the file for writing. */

  if ((fd = open(filename, O_RDWR + O_APPEND)) < 0)
    {
    printf("exim_lock: failed to open %s for writing: %s\n", filename,
      strerror(errno));
    yield = 1;
    goto CLEAN_UP;
    }

  /* If there is a timeout, implying blocked locking, we don't want to
  sleep before any retries after this. */

  if (lock_fcntl_timeout > 0 || lock_flock_timeout > 0)
    sleep_before_retry = FALSE;

  /* Lock using fcntl. There are pros and cons to using a blocking call vs
  a non-blocking call and retries. Exim is non-blocking by default, but setting
  a timeout changes it to blocking. */

  if (!use_mbx && (use_fcntl || use_flock))
    if (apply_lock(fd, F_WRLCK, use_fcntl, lock_fcntl_timeout, use_flock,
        lock_flock_timeout) >= 0)
      {
      if (!quiet)
        {
        if (use_fcntl) printf("exim_lock: fcntl() lock successfully applied\n");
        if (use_flock) printf("exim_lock: flock() lock successfully applied\n");
        }
      break;
      }
    else
      goto RETRY;   /* Message already output */

  /* Lock using MBX rules. This is complicated and is documented with the
  source of the c-client library that goes with Pine and IMAP. What has to
  be done to interwork correctly is to take out a shared lock on the mailbox,
  and an exclusive lock on a /tmp file. */

  else
    {
    if (apply_lock(fd, F_RDLCK, use_fcntl, lock_fcntl_timeout, use_flock,
        lock_flock_timeout) >= 0)
      {
      if (!quiet)
        {
        if (use_fcntl)
          printf("exim_lock: fcntl() read lock successfully applied\n");
        if (use_flock)
          printf("exim_lock: fcntl() read lock successfully applied\n");
        }
      }
    else goto RETRY;   /* Message already output */

    if (fstat(fd, &statbuf) < 0)
      {
      printf("exim_lock: fstat() of %s failed: %s\n", filename,
        strerror(errno));
      yield = 1;
      goto CLEAN_UP;
      }

    /* Set up file in /tmp and check its state if already existing. */

    sprintf(tempname, "/tmp/.%lx.%lx", (long)statbuf.st_dev,
      (long)statbuf.st_ino);

    if (lstat(tempname, &statbuf) >= 0)
      {
      if ((statbuf.st_mode & S_IFMT) == S_IFLNK)
        {
        printf("exim_lock: symbolic link on lock name %s\n", tempname);
        yield = 1;
        goto CLEAN_UP;
        }
      if (statbuf.st_nlink > 1)
        {
        printf("exim_lock: hard link to lock name %s\n", tempname);
        yield = 1;
        goto CLEAN_UP;
        }
      }

    mbx_tmp_oflags = O_RDWR | O_CREAT;
#ifdef O_NOFOLLOW
    mbx_tmp_oflags |= O_NOFOLLOW;
#endif
    md = open(tempname, mbx_tmp_oflags, 0600);
    if (md < 0)
      {
      printf("exim_lock: failed to create mbx lock file %s: %s\n",
        tempname, strerror(errno));
      goto CLEAN_UP;
      }

    /* security fixes from 2010-05 */
    if (lstat(tempname, &lstatbuf) < 0)
      {
      printf("exim_lock: failed to lstat(%s) after opening it: %s\n",
          tempname, strerror(errno));
      goto CLEAN_UP;
      }
    if (fstat(md, &statbuf2) < 0)
      {
      printf("exim_lock: failed to fstat() open fd of \"%s\": %s\n",
          tempname, strerror(errno));
      goto CLEAN_UP;
      }
    if ((statbuf2.st_nlink > 1) ||
        (lstatbuf.st_nlink > 1) ||
        (!S_ISREG(lstatbuf.st_mode)) ||
        (lstatbuf.st_dev != statbuf2.st_dev) ||
        (lstatbuf.st_ino != statbuf2.st_ino))
      {
      printf("exim_lock: race condition exploited against us when "
          "locking \"%s\"\n", tempname);
      goto CLEAN_UP;
      }

    (void)chmod(tempname, 0600);

    if (apply_lock(md, F_WRLCK, use_fcntl, lock_fcntl_timeout, use_flock,
        lock_flock_timeout) >= 0)
      {
      if (!quiet)
        {
        if (use_fcntl)
          printf("exim_lock: fcntl() lock successfully applied to mbx "
            "lock file %s\n", tempname);
        if (use_flock)
          printf("exim_lock: flock() lock successfully applied to mbx "
            "lock file %s\n", tempname);
        }

      /* This test checks for a race condition */

      if (lstat(tempname, &statbuf) != 0 ||
          fstat(md, &ostatbuf) != 0 ||
          statbuf.st_dev != ostatbuf.st_dev ||
          statbuf.st_ino != ostatbuf.st_ino)
       {
       if (!quiet) printf("exim_lock: mbx lock file %s changed between "
           "creation and locking\n", tempname);
       goto RETRY;
       }
      else break;
      }
    else goto RETRY;   /* Message already output */
    }

  /* Clean up before retrying */

  RETRY:

  if (md >= 0)
    {
    if (close(md) < 0)
      printf("exim_lock: close %s failed: %s\n", tempname, strerror(errno));
    else
      if (!quiet) printf("exim_lock: %s closed\n", tempname);
    md = -1;
    }

  if (fd >= 0)
    {
    if (close(fd) < 0)
      printf("exim_lock: close failed: %s\n", strerror(errno));
    else
      if (!quiet) printf("exim_lock: file closed\n");
    fd = -1;
    }

  if (hd >= 0)
    {
    if (unlink(lockname) < 0)
      printf("exim_lock: unlink of %s failed: %s\n", lockname, strerror(errno));
    else
      if (!quiet) printf("exim_lock: lock file removed\n");
    hd = -1;
    }

  /* If a blocking call timed out, break the retry loop if the total time
  so far is not less than than retries * interval. */

  if (sigalrm_seen &&
      (j + 1) * ((lock_fcntl_timeout > lock_flock_timeout)?
        lock_fcntl_timeout : lock_flock_timeout) >=
          lock_retries * lock_interval)
    j = lock_retries;

  /* Wait a bit before retrying, except when it was a blocked fcntl() that
  caused the problem. */

  if (j < lock_retries && sleep_before_retry)
    {
    printf(" ... waiting\n");
    sleep(lock_interval);
    }
  }

if (j >= lock_retries)
  {
  printf("exim_lock: locking failed too many times\n");
  yield = 1;
  goto CLEAN_UP;
  }

if (!quiet) printf("exim_lock: locking %s succeeded: ", filename);

/* If there are no further arguments, run the user's shell; otherwise
the next argument is a command to run. */

if (i >= argc)
  {
  command = getenv("SHELL");
  if (command == NULL || *command == 0) command = "/bin/sh";
  if (!quiet) printf("running %s ...\n", command);
  }
else
  {
  command = argv[i];
  if (!quiet) printf("running the command ...\n");
  }

/* Run the command, saving and restoring the times if required. */

if (restore_times)
  {
  struct stat strestore;
#ifdef EXIM_HAVE_OPENAT
  int fd = open(filename, O_RDWR); /* use fd for both get & restore */
  struct timespec tt[2];

  if (fd < 0)
    {
    printf("open '%s': %s\n", filename, strerror(errno));
    yield = 1;
    goto CLEAN_UP;
    }
  if (fstat(fd, &strestore) != 0)
    {
    printf("fstat '%s': %s\n", filename, strerror(errno));
    yield = 1;
    close(fd);
    goto CLEAN_UP;
    }
  i = system(command);
  tt[0] = strestore.st_atim;
  tt[1] = strestore.st_mtim;
  (void) futimens(fd, tt);
  (void) close(fd);
#else
  struct utimbuf ut;

  stat(filename, &strestore);
  i = system(command);
  ut.actime = strestore.st_atime;
  ut.modtime = strestore.st_mtime;
  utime(filename, &ut);
#endif
  }
else i = system(command);

if(i && !quiet) printf("warning: nonzero status %d\n", i);

/* Remove the locks and exit. Unlink the /tmp file if we can get an exclusive
lock on the mailbox. This should be a non-blocking lock call, as there is no
point in waiting. */

CLEAN_UP:

if (md >= 0)
  {
  if (apply_lock(fd, F_WRLCK, use_fcntl, 0, use_flock, 0) >= 0)
    {
    if (!quiet) printf("exim_lock: %s unlinked - no sharers\n", tempname);
    unlink(tempname);
    }
  else if (!quiet)
    printf("exim_lock: %s not unlinked - unable to get exclusive mailbox lock\n",
      tempname);
  if (close(md) < 0)
    printf("exim_lock: close %s failed: %s\n", tempname, strerror(errno));
  else
    if (!quiet) printf("exim_lock: %s closed\n", tempname);
  }

if (fd >= 0)
  {
  if (close(fd) < 0)
    printf("exim_lock: close %s failed: %s\n", filename, strerror(errno));
  else
    if (!quiet) printf("exim_lock: %s closed\n", filename);
  }

if (hd >= 0)
  {
  if (unlink(lockname) < 0)
    printf("exim_lock: unlink %s failed: %s\n", lockname, strerror(errno));
  else
    if (!quiet) printf("exim_lock: lock file removed\n");
  }

return yield;
}

/* End */
