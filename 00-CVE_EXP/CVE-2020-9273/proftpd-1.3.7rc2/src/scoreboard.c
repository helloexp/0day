/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2001-2019 The ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, The ProFTPD Project and other respective copyright
 * holders give permission to link this program with OpenSSL, and distribute
 * the resulting executable, without including the source code for OpenSSL in
 * the source distribution.
 */

/* ProFTPD scoreboard support. */

#include "conf.h"
#include "privs.h"

/* From src/dirtree.c */
extern char ServerType;

static pid_t scoreboard_opener = 0;

static int scoreboard_engine = TRUE;
static int scoreboard_fd = -1;
static char scoreboard_file[PR_TUNABLE_PATH_MAX] = PR_RUN_DIR "/proftpd.scoreboard";

static int scoreboard_mutex_fd = -1;
static char scoreboard_mutex[PR_TUNABLE_PATH_MAX] = PR_RUN_DIR "/proftpd.scoreboard.lck";

static off_t current_pos = 0;
static pr_scoreboard_header_t header;
static pr_scoreboard_entry_t entry;
static int have_entry = FALSE;
static struct flock entry_lock;

static unsigned char scoreboard_read_locked = FALSE;
static unsigned char scoreboard_write_locked = FALSE;

/* Max number of attempts for lock requests */
#define SCOREBOARD_MAX_LOCK_ATTEMPTS	10

static const char *trace_channel = "scoreboard";

/* Internal routines */

static char *handle_score_str(const char *fmt, va_list cmdap) {
  static char buf[PR_TUNABLE_SCOREBOARD_BUFFER_SIZE] = {'\0'};
  memset(buf, '\0', sizeof(buf));

  /* Note that we deliberately do NOT use pr_vsnprintf() here, since
   * truncation of long strings is often normal for these entries; consider
   * paths longer than PR_TUNABLE_SCOREBOARD_BUFFER_SIZE (Issue#683).
   */
  vsnprintf(buf, sizeof(buf)-1, fmt, cmdap);

  buf[sizeof(buf)-1] = '\0';
  return buf;
}

static int read_scoreboard_header(pr_scoreboard_header_t *sch) {
  int res = 0;

  pr_trace_msg(trace_channel, 7, "reading scoreboard header");

  /* NOTE: reading a struct from a file using read(2) -- bad (in general).
   * Better would be to use readv(2).  Should also handle short-reads here.
   */
  while ((res = read(scoreboard_fd, sch, sizeof(pr_scoreboard_header_t))) !=
      sizeof(pr_scoreboard_header_t)) {
    int rd_errno = errno;

    if (res == 0) {
      errno = EIO;
      return -1;
    }

    if (errno == EINTR) {
      pr_signals_handle();
      continue;
    }

    errno = rd_errno;
    return -1;
  }

  /* Note: these errors will most likely occur only for inetd-run daemons.
   * Standalone daemons erase the scoreboard on startup.
   */
 
  if (sch->sch_magic != PR_SCOREBOARD_MAGIC) {
    pr_close_scoreboard(FALSE);
    return PR_SCORE_ERR_BAD_MAGIC;
  }

  if (sch->sch_version < PR_SCOREBOARD_VERSION) {
    pr_close_scoreboard(FALSE);
    return PR_SCORE_ERR_OLDER_VERSION;
  }

  if (sch->sch_version > PR_SCOREBOARD_VERSION) {
    pr_close_scoreboard(FALSE);
    return PR_SCORE_ERR_NEWER_VERSION;
  }

  return 0;
}

static const char *get_lock_type(struct flock *lock) {
  const char *lock_type;

  switch (lock->l_type) {
    case F_RDLCK:
      lock_type = "read";
      break;

    case F_WRLCK:
      lock_type = "write";
      break;

    case F_UNLCK:
      lock_type = "unlock";
      break;

    default:
      errno = EINVAL;
      lock_type = NULL;
  }

  return lock_type;
}

int pr_lock_scoreboard(int mutex_fd, int lock_type) {
  struct flock lock;
  unsigned int nattempts = 1;
  const char *lock_label;

  lock.l_type = lock_type;
  lock.l_whence = SEEK_SET;
  lock.l_start = 0;
  lock.l_len = 0;

  lock_label = get_lock_type(&lock);
  if (lock_label == NULL) {
    return -1;
  }

  pr_trace_msg("lock", 9, "attempt #%u to %s-lock scoreboard mutex fd %d",
    nattempts, lock_label, mutex_fd);

  while (fcntl(mutex_fd, F_SETLK, &lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg("lock", 3,
      "%s-lock (attempt #%u) of scoreboard mutex fd %d failed: %s",
      lock_label, nattempts, mutex_fd, strerror(xerrno));
    if (xerrno == EACCES) {
      struct flock locker;

      /* Get the PID of the process blocking this lock. */
      if (fcntl(mutex_fd, F_GETLK, &locker) == 0) {
        pr_trace_msg("lock", 3, "process ID %lu has blocking %s lock on "
          "scoreboard mutex fd %d", (unsigned long) locker.l_pid,
          get_lock_type(&locker), mutex_fd);
      }
    }

    if (xerrno == EAGAIN ||
        xerrno == EACCES) {
      /* Treat this as an interrupted call, call pr_signals_handle() (which
       * will delay for a few msecs because of EINTR), and try again.
       * After MAX_LOCK_ATTEMPTS attempts, give up altogether.
       */

      nattempts++;
      if (nattempts <= SCOREBOARD_MAX_LOCK_ATTEMPTS) {
        errno = EINTR;

        pr_signals_handle();

        errno = 0;
        pr_trace_msg("lock", 9,
          "attempt #%u to %s-lock scoreboard mutex fd %d", nattempts,
          lock_label, mutex_fd);
        continue;
      }

      pr_trace_msg("lock", 9, "unable to acquire %s-lock on "
        "scoreboard mutex fd %d after %u attempts: %s", lock_label, mutex_fd,
        nattempts, strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  pr_trace_msg("lock", 9,
    "%s-lock of scoreboard mutex fd %d successful after %u %s", lock_label,
    mutex_fd, nattempts, nattempts != 1 ? "attempts" : "attempt");

  return 0;
}

static int rlock_scoreboard(void) {
  int res;

  res = pr_lock_scoreboard(scoreboard_mutex_fd, F_RDLCK);
  if (res == 0) {
    scoreboard_read_locked = TRUE;
  }

  return res;
}

static int wlock_scoreboard(void) {
  int res;

  res = pr_lock_scoreboard(scoreboard_mutex_fd, F_WRLCK);
  if (res == 0) {
    scoreboard_write_locked = TRUE;
  }

  return res;
}

static int unlock_scoreboard(void) {
  int res;

  res = pr_lock_scoreboard(scoreboard_mutex_fd, F_UNLCK);
  if (res == 0) {
    scoreboard_read_locked = scoreboard_write_locked = FALSE;
  }

  return res;
}

int pr_scoreboard_entry_lock(int fd, int lock_type) {
  unsigned int nattempts = 1;
  const char *lock_label;

  entry_lock.l_type = lock_type;
  entry_lock.l_whence = SEEK_CUR;
  entry_lock.l_len = sizeof(pr_scoreboard_entry_t);

  lock_label = get_lock_type(&entry_lock);
  if (lock_label == NULL) {
    return -1;
  }

  pr_trace_msg("lock", 9, "attempting to %s scoreboard fd %d entry, "
    "offset %" PR_LU, lock_label, fd, (pr_off_t) entry_lock.l_start);

  while (fcntl(fd, F_SETLK, &entry_lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    if (xerrno == EAGAIN) {
      /* Treat this as an interrupted call, call pr_signals_handle() (which
       * will delay for a few msecs because of EINTR), and try again.
       * After MAX_LOCK_ATTEMPTS attempts, give up altogether.
       */

      nattempts++;
      if (nattempts <= SCOREBOARD_MAX_LOCK_ATTEMPTS) {
        errno = EINTR;

        pr_signals_handle();

        errno = 0;
        pr_trace_msg("lock", 9,
          "attempt #%u to to %s scoreboard fd %d entry, offset %" PR_LU,
          nattempts, lock_label, fd, (pr_off_t) entry_lock.l_start);
        continue;
      }
    }

    pr_trace_msg("lock", 3, "%s of scoreboard fd %d entry failed: %s",
      lock_label, fd, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  pr_trace_msg("lock", 9, "%s of scoreboard fd %d entry, "
    "offset %" PR_LU " succeeded", lock_label, fd,
    (pr_off_t) entry_lock.l_start);

  return 0;
}

static int unlock_entry(int fd) {
  int res;

  res = pr_scoreboard_entry_lock(fd, F_UNLCK);
  return res;
}

static int wlock_entry(int fd) {
  int res;

  res = pr_scoreboard_entry_lock(fd, F_UNLCK);
  return res;
}

static int write_entry(int fd) {
  int res;

  if (fd < 0) {
    errno = EINVAL;
    return -1;
  }

#if !defined(HAVE_PWRITE)
  if (lseek(fd, entry_lock.l_start, SEEK_SET) < 0) {
    return -1;
  }
#endif /* HAVE_PWRITE */

#if defined(HAVE_PWRITE)
  res = pwrite(fd, &entry, sizeof(entry), entry_lock.l_start);
#else
  res = write(fd, &entry, sizeof(entry));
#endif /* HAVE_PWRITE */

  while (res != sizeof(entry)) {
    if (res < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
#if defined(HAVE_PWRITE)
        res = pwrite(fd, &entry, sizeof(entry), entry_lock.l_start);
#else
        res = write(fd, &entry, sizeof(entry));
#endif /* HAVE_PWRITE */
        continue;
      }

      return -1;
    }

    /* Watch out for short writes here. */
    pr_log_pri(PR_LOG_NOTICE,
      "error updating scoreboard entry: only wrote %d of %lu bytes", res,
      (unsigned long) sizeof(entry));
    errno = EIO;
    return -1;
  }

#if !defined(HAVE_PWRITE)
  /* Rewind. */
  if (lseek(fd, entry_lock.l_start, SEEK_SET) < 0) {
    return -1;
  }
#endif /* HAVE_PWRITE */

  return 0;
}

/* Public routines */

int pr_close_scoreboard(int keep_mutex) {
  if (scoreboard_engine == FALSE) {
    return 0;
  }

  if (scoreboard_fd == -1) {
    return 0;
  }

  if (scoreboard_read_locked || scoreboard_write_locked)
    unlock_scoreboard();

  pr_trace_msg(trace_channel, 4, "closing scoreboard fd %d", scoreboard_fd);

  while (close(scoreboard_fd) < 0) {
    if (errno == EINTR) {
      pr_signals_handle();
      continue;
    }

    break;
  }

  scoreboard_fd = -1;

  if (!keep_mutex) {
    pr_trace_msg(trace_channel, 4, "closing scoreboard mutex fd %d",
      scoreboard_mutex_fd);

    while (close(scoreboard_mutex_fd) < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
        continue;
      }

      break;
    }

    scoreboard_mutex_fd = -1;
  }

  scoreboard_opener = 0;
  return 0;
}

void pr_delete_scoreboard(void) {
  if (scoreboard_engine == FALSE) {
    return;
  }

  if (scoreboard_fd > -1) {
    while (close(scoreboard_fd) < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
        continue;
      }

      break;
    }
  }

  if (scoreboard_mutex_fd > -1) {
    while (close(scoreboard_mutex_fd) < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
        continue;
      }

      break;
    }
  }

  scoreboard_fd = -1;
  scoreboard_mutex_fd = -1;
  scoreboard_opener = 0;

  /* As a performance hack, setting "ScoreboardFile /dev/null" makes
   * proftpd write all its scoreboard entries to /dev/null.  But we don't
   * want proftpd to delete /dev/null.
   */
  if (*scoreboard_file &&
      strcmp(scoreboard_file, "/dev/null") != 0) {
    struct stat st;

    if (stat(scoreboard_file, &st) == 0) {
      pr_log_debug(DEBUG3, "deleting existing scoreboard '%s'",
        scoreboard_file);
    }

    (void) unlink(scoreboard_file);
    (void) unlink(scoreboard_mutex);
  }

  if (*scoreboard_mutex) {
    struct stat st;

    if (stat(scoreboard_mutex, &st) == 0) {
      pr_log_debug(DEBUG3, "deleting existing scoreboard mutex '%s'",
        scoreboard_mutex);
    }

    (void) unlink(scoreboard_mutex);
  }
}

const char *pr_get_scoreboard(void) {
  return scoreboard_file;
}

const char *pr_get_scoreboard_mutex(void) {
  return scoreboard_mutex;
}

int pr_open_scoreboard(int flags) {
  int res;
  struct stat st;

  if (scoreboard_engine == FALSE) {
    return 0;
  }

  if (flags != O_RDWR) {
    errno = EINVAL;
    return -1;
  }

  /* Try to prevent a file descriptor leak by only opening the scoreboard
   * file if the scoreboard file descriptor is not already positive, i.e.
   * if the scoreboard has not already been opened.
   */
  if (scoreboard_fd >= 0 &&
      scoreboard_opener == getpid()) {
    pr_log_debug(DEBUG7, "scoreboard already opened");
    return 0;
  }

  /* Check for symlinks prior to opening the file. */
  if (lstat(scoreboard_file, &st) == 0) {
    if (S_ISLNK(st.st_mode)) {
      scoreboard_fd = -1;
      errno = EPERM;
      return -1;
    }
  }

  if (lstat(scoreboard_mutex, &st) == 0) {
    if (S_ISLNK(st.st_mode)) {
      errno = EPERM;
      return -1;
    }
  }

  pr_log_debug(DEBUG7, "opening scoreboard '%s'", scoreboard_file);

  scoreboard_fd = open(scoreboard_file, flags|O_CREAT, PR_SCOREBOARD_MODE);
  while (scoreboard_fd < 0) {
    if (errno == EINTR) {
      pr_signals_handle();
      scoreboard_fd = open(scoreboard_file, flags|O_CREAT, PR_SCOREBOARD_MODE);
      continue;
    }

    return -1;
  }

  /* Find a usable fd for the just-opened scoreboard fd. */
  if (pr_fs_get_usable_fd2(&scoreboard_fd) < 0) {
    pr_log_debug(DEBUG0, "warning: unable to find good fd for ScoreboardFile "
      "fd %d: %s", scoreboard_fd, strerror(errno));
  }

  /* Make certain that the scoreboard mode will be read-only for everyone
   * except the user owner (this allows for non-root-running daemons to
   * still modify the scoreboard).
   */
  while (fchmod(scoreboard_fd, 0644) < 0) {
    if (errno == EINTR) {
      pr_signals_handle();
      continue;
    }

    break;
  }

  /* Make sure the ScoreboardMutex file exists.  We keep a descriptor to the
   * ScoreboardMutex open just as we do for the ScoreboardFile, for the same
   * reasons: we need to able to use the descriptor throughout the lifetime of
   * the session despite any possible chroot, and we get a minor system call
   * saving by not calling open(2)/close(2) repeatedly to get the descriptor
   * (at the cost of having another open fd for the lifetime of the session
   * process).
   */
  if (scoreboard_mutex_fd == -1) {
    scoreboard_mutex_fd = open(scoreboard_mutex, flags|O_CREAT,
      PR_SCOREBOARD_MODE);
    while (scoreboard_mutex_fd < 0) {
      int xerrno = errno;

      if (errno == EINTR) {
        pr_signals_handle();
        scoreboard_mutex_fd = open(scoreboard_mutex, flags|O_CREAT,
          PR_SCOREBOARD_MODE);
        continue;
      }

      close(scoreboard_fd);
      scoreboard_fd = -1;

      pr_trace_msg(trace_channel, 9, "error opening ScoreboardMutex '%s': %s",
        scoreboard_mutex, strerror(xerrno));

      errno = xerrno;
      return -1;
    }

    /* Find a usable fd for the just-opened mutex fd. */
    if (pr_fs_get_usable_fd2(&scoreboard_mutex_fd) < 0) {
      pr_log_debug(DEBUG0, "warning: unable to find good fd for "
        "ScoreboardMutex fd %d: %s", scoreboard_mutex_fd, strerror(errno));
    }

  } else {
    pr_trace_msg(trace_channel, 9, "using already-open scoreboard mutex fd %d",
      scoreboard_mutex_fd);
  }

  scoreboard_opener = getpid();

  /* Check the header of this scoreboard file. */
  res = read_scoreboard_header(&header);
  if (res == -1) {

    /* If this file is newly created, it needs to have the header
     * written.
     */
    header.sch_magic = PR_SCOREBOARD_MAGIC;
    header.sch_version = PR_SCOREBOARD_VERSION;

    if (ServerType == SERVER_STANDALONE) {
      header.sch_pid = getpid();
      header.sch_uptime = time(NULL);

    } else {
      header.sch_pid = 0;
      header.sch_uptime = 0;
    }

    /* Write-lock the scoreboard file. */
    PR_DEVEL_CLOCK(res = wlock_scoreboard());
    if (res < 0) {
      int xerrno = errno;

      close(scoreboard_mutex_fd);
      scoreboard_mutex_fd = -1;

      close(scoreboard_fd);
      scoreboard_fd = -1;

      errno = xerrno;
      return -1;
    }

    pr_trace_msg(trace_channel, 7, "writing scoreboard header");

    while (write(scoreboard_fd, &header, sizeof(header)) != sizeof(header)) {
      int xerrno = errno;

      if (errno == EINTR) {
        pr_signals_handle();
        continue;
      }

      unlock_scoreboard();

      close(scoreboard_mutex_fd);
      scoreboard_mutex_fd = -1;

      close(scoreboard_fd);
      scoreboard_fd = -1;

      errno = xerrno;
      return -1;
    }

    unlock_scoreboard();
    return 0;
  }

  return res;
}

int pr_restore_scoreboard(void) {
  if (scoreboard_engine == FALSE) {
    return 0;
  }

  if (scoreboard_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  if (current_pos == 0) {
    /* This can happen if pr_restore_scoreboard() is called BEFORE
     * pr_rewind_scoreboard() has been called.
     */
    errno = EPERM;
    return -1;
  }

  /* Position the file position pointer of the scoreboard back to
   * where it was, prior to the last pr_rewind_scoreboard() call.
   */
  if (lseek(scoreboard_fd, current_pos, SEEK_SET) == (off_t) -1) {
    return -1;
  }

  return 0;
}

int pr_rewind_scoreboard(void) {
  off_t res;

  if (scoreboard_engine == FALSE) {
    return 0;
  }

  if (scoreboard_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  res = lseek(scoreboard_fd, (off_t) 0, SEEK_CUR);
  if (res == (off_t) -1) {
    return -1;
  }

  current_pos = res;

  /* Position the file position pointer of the scoreboard at the
   * start of the scoreboard (past the header).
   */
  if (lseek(scoreboard_fd, (off_t) sizeof(pr_scoreboard_header_t),
      SEEK_SET) == (off_t) -1) {
    return -1;
  }

  return 0;
}

static int set_scoreboard_path(const char *path) {
  char dir[PR_TUNABLE_PATH_MAX] = {'\0'};
  struct stat st;
  char *ptr = NULL;

  if (*path != '/') {
    errno = EINVAL;
    return -1;
  }

  sstrncpy(dir, path, sizeof(dir));

  ptr = strrchr(dir + 1, '/');
  if (ptr == NULL) {
    errno = EINVAL;
    return -1;
  }

  *ptr = '\0';

  /* Check for the possibility that the '/' just found is at the end
   * of the given string.
   */
  if (*(ptr + 1) == '\0') {
    *ptr = '/';
    errno = EINVAL;
    return -1;
  }

  /* Parent directory must not be world-writable */

  if (stat(dir, &st) < 0) {
    return -1;
  }

  if (!S_ISDIR(st.st_mode)) {
    errno = ENOTDIR;
    return -1;
  }

  if (st.st_mode & S_IWOTH) {
    errno = EPERM;
    return -1;
  }

  return 0;
}

int pr_set_scoreboard(const char *path) {

  /* By default, scoreboarding is enabled. */
  scoreboard_engine = TRUE;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Check to see if the given path is "off" or something related, i.e. is
   * telling us to disable scoreboarding.  Other ways of disabling
   * scoreboarding are to configure a path of "none", or "/dev/null".
   */
  if (pr_str_is_boolean(path) == FALSE) {
    pr_trace_msg(trace_channel, 3,
      "ScoreboardFile set to '%s', disabling scoreboarding", path);
    scoreboard_engine = FALSE;
    return 0;
  }

  if (strncasecmp(path, "none", 5) == 0) {
    pr_trace_msg(trace_channel, 3,
      "ScoreboardFile set to '%s', disabling scoreboarding", path);
    scoreboard_engine = FALSE;
    return 0;
  }

  if (strncmp(path, "/dev/null", 10) == 0) {
    pr_trace_msg(trace_channel, 3,
      "ScoreboardFile set to '%s', disabling scoreboarding", path);
    scoreboard_engine = FALSE;
    return 0;
  }

  if (set_scoreboard_path(path) < 0) {
    return -1;
  }

  sstrncpy(scoreboard_file, path, sizeof(scoreboard_file));

  /* For best operability, automatically set the ScoreboardMutex file to
   * be the same as the ScoreboardFile with a ".lck" suffix.
   */
  sstrncpy(scoreboard_mutex, path, sizeof(scoreboard_file));
  strncat(scoreboard_mutex, ".lck", sizeof(scoreboard_mutex)-strlen(path)-1);

  return 0;
}

int pr_set_scoreboard_mutex(const char *path) {
  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  sstrncpy(scoreboard_mutex, path, sizeof(scoreboard_mutex));
  return 0;
}

int pr_scoreboard_entry_add(void) {
  int res;
  unsigned char found_slot = FALSE;

  if (scoreboard_engine == FALSE) {
    return 0;
  }

  if (scoreboard_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  if (have_entry) {
    pr_trace_msg(trace_channel, 9,
      "unable to add scoreboard entry: already have entry");
    errno = EPERM;
    return -1;
  }

  pr_trace_msg(trace_channel, 3, "adding new scoreboard entry");

  /* Write-lock the scoreboard file. */
  PR_DEVEL_CLOCK(res = wlock_scoreboard());
  if (res < 0)
    return -1;

  /* No interruptions, please. */
  pr_signals_block();

  /* If the scoreboard is open, the file position is already past the
   * header.
   */
  while (TRUE) {
    while ((res = read(scoreboard_fd, &entry, sizeof(entry))) ==
        sizeof(entry)) {

      /* If this entry's PID is marked as zero, it means this slot can be
       * reused.
       */
      if (!entry.sce_pid) {
        entry_lock.l_start = lseek(scoreboard_fd, (off_t) 0, SEEK_CUR) - sizeof(entry);
        found_slot = TRUE;
        break;
      }
    }

    if (res == 0) {
      entry_lock.l_start = lseek(scoreboard_fd, (off_t) 0, SEEK_CUR);
      found_slot = TRUE;
    }

    if (found_slot)
      break;
  }

  memset(&entry, '\0', sizeof(entry));

  entry.sce_pid = session.pid ? session.pid : getpid();
  entry.sce_uid = geteuid();
  entry.sce_gid = getegid();

  res = write_entry(scoreboard_fd);
  if (res < 0) {
    pr_log_pri(PR_LOG_NOTICE, "error writing scoreboard entry: %s",
      strerror(errno));

  } else {
    have_entry = TRUE;
  }

  pr_signals_unblock();

  /* We can unlock the scoreboard now. */
  unlock_scoreboard();

  return res;
}

int pr_scoreboard_entry_del(unsigned char verbose) {
  if (scoreboard_engine == FALSE) {
    return 0;
  }

  if (scoreboard_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  if (!have_entry) {
    errno = ENOENT;
    return -1;
  }

  pr_trace_msg(trace_channel, 3, "deleting scoreboard entry");

  memset(&entry, '\0', sizeof(entry));

  /* Write-lock this entry */
  wlock_entry(scoreboard_fd);

  /* Write-lock the scoreboard (using the ScoreboardMutex), since new
   * connections might try to use the slot being opened up here.
   */
  wlock_scoreboard();

  if (write_entry(scoreboard_fd) < 0 &&
      verbose) {
    pr_log_pri(PR_LOG_NOTICE, "error deleting scoreboard entry: %s",
      strerror(errno));
  }

  have_entry = FALSE;
  unlock_scoreboard();
  unlock_entry(scoreboard_fd);

  return 0;
}

pid_t pr_scoreboard_get_daemon_pid(void) {
  if (scoreboard_engine == FALSE) {
    return 0;
  }

  return header.sch_pid;
}

time_t pr_scoreboard_get_daemon_uptime(void) {
  if (scoreboard_engine == FALSE) {
    return 0;
  }

  return header.sch_uptime;
}

pr_scoreboard_entry_t *pr_scoreboard_entry_read(void) {
  static pr_scoreboard_entry_t scan_entry;
  int res = 0;

  if (scoreboard_engine == FALSE) {
    return NULL;
  }

  if (scoreboard_fd < 0) {
    errno = EINVAL;
    return NULL;
  }

  /* Make sure the scoreboard file is read-locked. */
  if (!scoreboard_read_locked) {

    /* Do not proceed if we cannot lock the scoreboard. */
    res = rlock_scoreboard();
    if (res < 0) {
      return NULL; 
    }
  }

  pr_trace_msg(trace_channel, 5, "reading scoreboard entry");

  memset(&scan_entry, '\0', sizeof(scan_entry));

  /* NOTE: use readv(2), pread(2)? */
  while (TRUE) {
    while ((res = read(scoreboard_fd, &scan_entry, sizeof(scan_entry))) <= 0) {
      int xerrno = errno;

      if (res < 0 &&
          xerrno == EINTR) {
        pr_signals_handle();
        continue;
      }

      unlock_scoreboard();
      errno = xerrno;
      return NULL;
    }

    if (scan_entry.sce_pid) {
      unlock_scoreboard();
      return &scan_entry;
    }
  }

  /* Technically we never reach this. */
  return NULL;
}

/* We get clever with the next functions, so that they can be used for
 * various entry attributes.
 */

const char *pr_scoreboard_entry_get(int field) {
  if (scoreboard_engine == FALSE) {
    errno = ENOENT;
    return NULL;
  }

  if (scoreboard_fd < 0) {
    errno = EINVAL;
    return NULL;
  }

  if (!have_entry) {
    errno = EPERM;
    return NULL;
  }

  switch (field) {
    case PR_SCORE_USER:
      return entry.sce_user;

    case PR_SCORE_CLIENT_ADDR:
      return entry.sce_client_addr;

    case PR_SCORE_CLIENT_NAME:
      return entry.sce_client_name;

    case PR_SCORE_CLASS:
      return entry.sce_class;

    case PR_SCORE_CWD:
      return entry.sce_cwd;

    case PR_SCORE_CMD:
      return entry.sce_cmd;

    case PR_SCORE_CMD_ARG:
      return entry.sce_cmd_arg;

    case PR_SCORE_PROTOCOL:
      return entry.sce_protocol;
  }

  errno = ENOENT;
  return NULL;
}

int pr_scoreboard_entry_kill(pr_scoreboard_entry_t *sce, int signo) {
  int res;

  if (scoreboard_engine == FALSE) {
    return 0;
  }

  if (sce == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (ServerType == SERVER_STANDALONE) {
#ifdef HAVE_GETPGID
    pid_t curr_pgrp;

# ifdef HAVE_GETPGRP
    curr_pgrp = getpgrp();
# else
    curr_pgrp = getpgid(0);
# endif /* HAVE_GETPGRP */

    if (getpgid(sce->sce_pid) != curr_pgrp) {
      pr_trace_msg(trace_channel, 1, "scoreboard entry PID %lu process group "
        "does not match current process group, refusing to send signal",
        (unsigned long) sce->sce_pid);
      errno = EPERM;
      return -1;
    }
#endif /* HAVE_GETPGID */
  }

  res = kill(sce->sce_pid, signo);
  return res;
}

/* Given a NUL-terminated string -- possibly UTF8-encoded -- and a maximum
 * buffer length, return the number of bytes in the string which can fit in
 * that buffer without truncating a character.  This is needed since UTF8
 * characters are variable-width.
 */
static size_t str_getlen(const char *str, size_t maxsz) {
#ifdef PR_USE_NLS
  register unsigned int i = 0;

  while (str[i] > 0 &&
         i < maxsz) {
ascii:
    pr_signals_handle();
    i++;
  }

  while (str[i] &&
         i < maxsz) {
    size_t len;

    if (str[i] > 0) {
      goto ascii;
    }

    pr_signals_handle();

    len = 0;

    switch (str[i] & 0xF0) {
      case 0xE0:
        len = 3;
        break;

      case 0xF0:
        len = 4;
        break;

      default:
        len = 2;
        break;
    }

    if ((i + len) < maxsz) {
      i += len;

    } else {
      break;
    }
  }

  return i;
#else
  /* No UTF8 support in this proftpd build; just return the max size. */
  return maxsz;
#endif /* !PR_USE_NLS */
}

int pr_scoreboard_entry_update(pid_t pid, ...) {
  va_list ap;
  char *tmp = NULL;
  int entry_tag = 0;

  if (scoreboard_engine == FALSE) {
    return 0;
  }

  if (scoreboard_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  if (!have_entry) {
    errno = EPERM;
    return -1;
  }

  pr_trace_msg(trace_channel, 3, "updating scoreboard entry");

  va_start(ap, pid);

  while ((entry_tag = va_arg(ap, int)) != 0) {
    pr_signals_handle();

    switch (entry_tag) {
      case PR_SCORE_USER:
        tmp = va_arg(ap, char *);
        memset(entry.sce_user, '\0', sizeof(entry.sce_user));
        sstrncpy(entry.sce_user, tmp,
          str_getlen(tmp, sizeof(entry.sce_user)-1) + 1);

        pr_trace_msg(trace_channel, 15, "updated scoreboard entry user to '%s'",
          entry.sce_user);
        break;

      case PR_SCORE_CLIENT_ADDR: {
          pr_netaddr_t *remote_addr = va_arg(ap, pr_netaddr_t *);

          pr_snprintf(entry.sce_client_addr, sizeof(entry.sce_client_addr),
            "%s", remote_addr ? pr_netaddr_get_ipstr(remote_addr) :
            "(unknown)");
          entry.sce_client_addr[sizeof(entry.sce_client_addr) - 1] = '\0';

          pr_trace_msg(trace_channel, 15, "updated scoreboard entry client "
            "address to '%s'", entry.sce_client_addr);
        }
        break;

      case PR_SCORE_CLIENT_NAME: {
          char *remote_name = va_arg(ap, char *);

          if (remote_name == NULL) {
            remote_name = "(unknown)";
          }

          memset(entry.sce_client_name, '\0', sizeof(entry.sce_client_name));

          snprintf(entry.sce_client_name,
            str_getlen(remote_name, sizeof(entry.sce_client_name)-1) + 1,
            "%s", remote_name);
          entry.sce_client_name[sizeof(entry.sce_client_name)-1] = '\0';

          pr_trace_msg(trace_channel, 15, "updated scoreboard entry client "
            "name to '%s'", entry.sce_client_name);
        }
        break;

      case PR_SCORE_CLASS:
        tmp = va_arg(ap, char *);
        memset(entry.sce_class, '\0', sizeof(entry.sce_class));
        sstrncpy(entry.sce_class, tmp, sizeof(entry.sce_class));

        pr_trace_msg(trace_channel, 15, "updated scoreboard entry class to "
          "'%s'", entry.sce_class);
        break;

      case PR_SCORE_CWD:
        tmp = va_arg(ap, char *);
        memset(entry.sce_cwd, '\0', sizeof(entry.sce_cwd));
        sstrncpy(entry.sce_cwd, tmp,
          str_getlen(tmp, sizeof(entry.sce_cwd)-1) + 1);

        pr_trace_msg(trace_channel, 15, "updated scoreboard entry cwd to '%s'",
          entry.sce_cwd);
        break;

      case PR_SCORE_CMD: {
          char *cmdstr = NULL;
          tmp = va_arg(ap, char *);
          cmdstr = handle_score_str(tmp, ap);

          memset(entry.sce_cmd, '\0', sizeof(entry.sce_cmd));
          sstrncpy(entry.sce_cmd, cmdstr, sizeof(entry.sce_cmd));
          (void) va_arg(ap, void *);

          pr_trace_msg(trace_channel, 15, "updated scoreboard entry "
            "command to '%s'", entry.sce_cmd);
        }
        break;

      case PR_SCORE_CMD_ARG: {
          char *argstr = NULL;
          tmp = va_arg(ap, char *);
          argstr = handle_score_str(tmp, ap);

          memset(entry.sce_cmd_arg, '\0', sizeof(entry.sce_cmd_arg));
          sstrncpy(entry.sce_cmd_arg, argstr,
            str_getlen(argstr, sizeof(entry.sce_cmd_arg)-1) + 1);
          (void) va_arg(ap, void *);

          pr_trace_msg(trace_channel, 15, "updated scoreboard entry "
            "command args to '%s'", entry.sce_cmd_arg);
        }
        break;

      case PR_SCORE_SERVER_PORT:
        entry.sce_server_port = va_arg(ap, int);
        pr_trace_msg(trace_channel, 15, "updated scoreboard entry "
          "server port to %d", entry.sce_server_port);
        break;

      case PR_SCORE_SERVER_ADDR: {
          pr_netaddr_t *server_addr = va_arg(ap, pr_netaddr_t *);
          int server_port = va_arg(ap, int);

          pr_snprintf(entry.sce_server_addr, sizeof(entry.sce_server_addr),
            "%s:%d", server_addr ? pr_netaddr_get_ipstr(server_addr) :
            "(unknown)", server_port);
          entry.sce_server_addr[sizeof(entry.sce_server_addr)-1] = '\0';

          pr_trace_msg(trace_channel, 15, "updated scoreboard entry server "
            "address to '%s'", entry.sce_server_addr);
        }
        break;

      case PR_SCORE_SERVER_LABEL:
        tmp = va_arg(ap, char *);
        memset(entry.sce_server_label, '\0', sizeof(entry.sce_server_label));
        sstrncpy(entry.sce_server_label, tmp, sizeof(entry.sce_server_label));

        pr_trace_msg(trace_channel, 15, "updated scoreboard entry server "
          "label to '%s'", entry.sce_server_label);
        break;

      case PR_SCORE_BEGIN_IDLE:
        /* Ignore this */
        (void) va_arg(ap, time_t);

        time(&entry.sce_begin_idle);
        pr_trace_msg(trace_channel, 15, "updated scoreboard entry idle "
          "start time to %lu", (unsigned long) entry.sce_begin_idle);
        break;

      case PR_SCORE_BEGIN_SESSION:
        /* Ignore this */
        (void) va_arg(ap, time_t);

        time(&entry.sce_begin_session);
        pr_trace_msg(trace_channel, 15, "updated scoreboard entry session "
          "start time to %lu", (unsigned long) entry.sce_begin_session);
        break;

      case PR_SCORE_XFER_DONE:
        entry.sce_xfer_done = va_arg(ap, off_t);
        pr_trace_msg(trace_channel, 15, "updated scoreboard entry transfer "
          "bytes done to %" PR_LU " bytes", (pr_off_t) entry.sce_xfer_done);
        break;

      case PR_SCORE_XFER_SIZE:
        entry.sce_xfer_size = va_arg(ap, off_t);
        pr_trace_msg(trace_channel, 15, "updated scoreboard entry transfer "
          "size to %" PR_LU " bytes", (pr_off_t) entry.sce_xfer_size);
        break;

      case PR_SCORE_XFER_LEN:
        entry.sce_xfer_len = va_arg(ap, off_t);
        pr_trace_msg(trace_channel, 15, "updated scoreboard entry transfer "
          "length to %" PR_LU " bytes", (pr_off_t) entry.sce_xfer_len);
        break;

      case PR_SCORE_XFER_ELAPSED:
        entry.sce_xfer_elapsed = va_arg(ap, unsigned long);
        pr_trace_msg(trace_channel, 15, "updated scoreboard entry transfer "
          "elapsed to %lu ms", (unsigned long) entry.sce_xfer_elapsed);
        break;

      case PR_SCORE_PROTOCOL:
        tmp = va_arg(ap, char *);
        memset(entry.sce_protocol, '\0', sizeof(entry.sce_protocol));
        sstrncpy(entry.sce_protocol, tmp, sizeof(entry.sce_protocol));
        pr_trace_msg(trace_channel, 15, "updated scoreboard entry protocol to "
          "'%s'", entry.sce_protocol);
        break;

      default:
        va_end(ap);
        errno = ENOENT;
        return -1;
    }
  }

  va_end(ap);

  /* Write-lock this entry */
  wlock_entry(scoreboard_fd);
  if (write_entry(scoreboard_fd) < 0) {
    pr_log_pri(PR_LOG_NOTICE, "error writing scoreboard entry: %s",
      strerror(errno));
  }
  unlock_entry(scoreboard_fd);

  pr_trace_msg(trace_channel, 3, "finished updating scoreboard entry");
  return 0;
}

/* Validate the PID in a scoreboard entry.  A PID can be invalid in a couple
 * of ways:
 *
 *  1.  The PID refers to a process no longer present on the system.
 *  2.  The PID refers to a process not in the daemon process group
 *      (for "ServerType standalone" servers only).
 */
static int scoreboard_valid_pid(pid_t pid, pid_t curr_pgrp) {
  int res;

  res = kill(pid, 0);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  if (ServerType == SERVER_STANDALONE &&
      curr_pgrp > 0) {
#ifdef HAVE_GETPGID
    if (getpgid(pid) != curr_pgrp) { 
      pr_trace_msg(trace_channel, 1, "scoreboard entry PID %lu process group "
        "does not match current process group, removing entry",
        (unsigned long) pid);
      errno = EPERM;
      return -1;
    }
#endif /* HAVE_GETPGID */
  }

  return 0;
}

int pr_scoreboard_scrub(void) {
  int fd = -1, res, xerrno;
  off_t curr_offset = 0;
  pid_t curr_pgrp = 0;
  pr_scoreboard_entry_t sce;

  if (scoreboard_engine == FALSE) {
    return 0;
  }

  pr_log_debug(DEBUG9, "scrubbing scoreboard");
  pr_trace_msg(trace_channel, 9, "%s", "scrubbing scoreboard");

  /* Manually open the scoreboard.  It won't hurt if the process already
   * has a descriptor opened on the scoreboard file.
   */
  PRIVS_ROOT
  fd = open(pr_get_scoreboard(), O_RDWR);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (fd < 0) {
    pr_log_debug(DEBUG1, "unable to scrub ScoreboardFile '%s': %s",
      pr_get_scoreboard(), strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* Write-lock the scoreboard file. */
  PR_DEVEL_CLOCK(res = wlock_scoreboard());
  if (res < 0) {
    xerrno = errno;

    (void) close(fd);

    errno = xerrno;
    return -1;
  }

#ifdef HAVE_GETPGRP
  curr_pgrp = getpgrp();
#elif HAVE_GETPGID
  curr_pgrp = getpgid(0);
#endif /* !HAVE_GETPGRP and !HAVE_GETPGID */
 
  /* Skip past the scoreboard header. */
  curr_offset = lseek(fd, (off_t) sizeof(pr_scoreboard_header_t), SEEK_SET);
  if (curr_offset < 0) {
    xerrno = errno;

    unlock_scoreboard();
    (void) close(fd);

    errno = xerrno;
    return -1;
  }

  entry_lock.l_start = curr_offset;
 
  PRIVS_ROOT

  while (TRUE) {
    pr_signals_handle();

    /* First, lock the scoreboard entry/slot about to be checked.  If we can't
     * (e.g. because the session process has it locked), then just move on.
     * If another process has it locked, then it is presumed to be valid.
     */
    if (wlock_entry(fd) < 0) {
      /* Seek to the next entry/slot.  If it fails for any reason, just
       * be done with the scrubbing.
       */
      curr_offset = lseek(fd, sizeof(sce), SEEK_CUR);
      entry_lock.l_start = curr_offset;

      if (curr_offset < 0) {
        pr_trace_msg(trace_channel, 3,
          "error seeking to next scoreboard entry (fd %d): %s", fd,
          strerror(xerrno));
        break;
      }

      continue;
    }

    memset(&sce, 0, sizeof(sce));
    res = read(fd, &sce, sizeof(sce));
    if (res == 0) {
      /* EOF */
      unlock_entry(fd);
      break;
    }

    if (res == sizeof(sce)) {

      /* Check to see if the PID in this entry is valid.  If not, erase
       * the slot.
       */
      if (sce.sce_pid &&
          scoreboard_valid_pid(sce.sce_pid, curr_pgrp) < 0) {
        pid_t slot_pid;

        slot_pid = sce.sce_pid;

        /* OK, the recorded PID is no longer valid. */
        pr_log_debug(DEBUG9, "scrubbing scoreboard entry for PID %lu",
          (unsigned long) slot_pid);

        /* Rewind to the start of this slot. */
        if (lseek(fd, curr_offset, SEEK_SET) < 0) {
          xerrno = errno;

          pr_log_debug(DEBUG0, "error seeking to scoreboard entry to scrub: %s",
            strerror(xerrno));

          pr_trace_msg(trace_channel, 3,
            "error seeking to scoreboard entry for PID %lu (offset %" PR_LU ") "
            "to scrub: %s", (unsigned long) slot_pid, (pr_off_t) curr_offset,
            strerror(xerrno));
        }

        memset(&sce, 0, sizeof(sce));

        /* Note: It does not matter that we only have a read-lock on this
         * slot; we can safely write over the byte range here, since we know
         * that the process for this slot is not around anymore, and there
         * are no incoming processes to use take it.
         */

        res = write(fd, &sce, sizeof(sce));
        while (res != sizeof(sce)) {
          if (res < 0) {
            xerrno = errno;

            if (xerrno == EINTR) {
              pr_signals_handle();
              res = write(fd, &sce, sizeof(sce));
              continue;
            }

            pr_log_debug(DEBUG0, "error scrubbing scoreboard: %s",
              strerror(xerrno));
            pr_trace_msg(trace_channel, 3,
              "error writing out scrubbed scoreboard entry for PID %lu: %s",
              (unsigned long) slot_pid, strerror(xerrno));

          } else {
            /* Watch out for short writes here. */
            pr_log_pri(PR_LOG_NOTICE,
              "error scrubbing scoreboard entry: only wrote %d of %lu bytes",
              res, (unsigned long) sizeof(sce));
          }
        }
      }

      /* Unlock the slot, and move to the next one. */
      unlock_entry(fd);

      /* Mark the current offset. */
      curr_offset = lseek(fd, (off_t) 0, SEEK_CUR);
      if (curr_offset < 0) {
        break;
      }

      entry_lock.l_start = curr_offset;
    }
  }

  PRIVS_RELINQUISH

  /* Release the scoreboard. */
  unlock_scoreboard();

  /* Don't need the descriptor anymore. */
  (void) close(fd);

  pr_log_debug(DEBUG9, "finished scrubbing scoreboard");
  pr_trace_msg(trace_channel, 9, "%s", "finished scrubbing scoreboard");

  return 0;
}
