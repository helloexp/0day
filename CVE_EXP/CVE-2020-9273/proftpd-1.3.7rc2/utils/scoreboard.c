/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2001-2016 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* ProFTPD scoreboard support (modified for use by external utilities). */

#include "utils.h"

static int util_scoreboard_fd = -1;
static char util_scoreboard_file[PR_TUNABLE_PATH_MAX] = PR_RUN_DIR "/proftpd.scoreboard";

static pr_scoreboard_header_t util_header;

static unsigned char util_scoreboard_read_locked = FALSE;

/* Internal routines
 */

static int read_scoreboard_header(pr_scoreboard_header_t *header) {
  int res = 0;

  /* NOTE: reading a struct from a file using read(2) -- bad (in general). */
  while ((res = read(util_scoreboard_fd, &util_header,
      sizeof(pr_scoreboard_header_t))) != sizeof(pr_scoreboard_header_t)) {
    if (res == 0)
      return -1;

    if (errno == EINTR)
      continue;

    return -1;
  }

  /* Note: these errors will most likely occur only for inetd-run daemons.
   * Standalone daemons erase the scoreboard on startup.
   */

  if (header->sch_magic != UTIL_SCOREBOARD_MAGIC)
    return UTIL_SCORE_ERR_BAD_MAGIC;

  if (header->sch_version < UTIL_SCOREBOARD_VERSION)
    return UTIL_SCORE_ERR_OLDER_VERSION;

  if (header->sch_version > UTIL_SCOREBOARD_VERSION)
    return UTIL_SCORE_ERR_NEWER_VERSION;

  return 0;
}

static int rlock_scoreboard(void) {
  struct flock lock;

  lock.l_type = F_RDLCK;
  lock.l_whence = 0;
  lock.l_start = 0;
  lock.l_len = 0;

  while (fcntl(util_scoreboard_fd, F_SETLKW, &lock) < 0) {

    /* It would be nice to try to restart the fcntl(2) in cases where
     * it is interrupted.  However, that could possibly lead to a tight
     * loop which leaves the scoreboard file locked, which in turn causes
     * problems for the proftpd daemon trying to read that scoreboard.
     *
     * Instead, only retry the fcntl(2) on EAGAIN, and NOT on EINTR.
     */
    if (errno == EAGAIN)
      continue;

    return -1;
  }

  util_scoreboard_read_locked = TRUE;
  return 0;
}

static int unlock_scoreboard(void) {
  struct flock lock;

  lock.l_type = F_UNLCK;
  lock.l_whence = 0;
  lock.l_start = 0;
  lock.l_len = 0;

  util_scoreboard_read_locked = FALSE;

  while (fcntl(util_scoreboard_fd, F_SETLK, &lock) < 0) {
    if (errno == EAGAIN)
      continue;

    return -1;
  }

  return 0;
}

/* Public routines
 */

int util_close_scoreboard(void) {
  if (util_scoreboard_fd == -1)
    return 0;

  if (util_scoreboard_read_locked) {
    unlock_scoreboard();
  }

  (void) close(util_scoreboard_fd);
  util_scoreboard_fd = -1;

  return 0;
}

const char *util_get_scoreboard(void) {
  return util_scoreboard_file;
}

int util_open_scoreboard(int flags) {
  int res;
  struct stat st;

  /* Prevent writing to a symlink while avoiding a race condition: open
   * the file name O_RDWR|O_CREAT first, then check to see if it's a symlink.
   * If so, close the file and error out.  If not, truncate as necessary,
   * and continue.
   */
  util_scoreboard_fd = open(util_scoreboard_file, flags);
  if (util_scoreboard_fd < 0)
    return -1;

  if (fstat(util_scoreboard_fd, &st) < 0) {
    close(util_scoreboard_fd);
    util_scoreboard_fd = -1;
    return -1;
  }

  if (S_ISLNK(st.st_mode)) {
    close(util_scoreboard_fd);
    util_scoreboard_fd = -1;
    errno = EPERM;
    return -1;
  }

  /* Check the header of this scoreboard file. */
  res = read_scoreboard_header(&util_header);
  if (res < 0)
    return res;

  return 0;
}

int util_set_scoreboard(const char *path) {
  char dir[PR_TUNABLE_PATH_MAX] = {'\0'};
  struct stat st;
  char *tmp = NULL;

  util_sstrncpy(dir, path, sizeof(dir));

  tmp = strrchr(dir, '/');
  if (tmp == NULL) {
    errno = EINVAL;
    return -1;
  }
  *tmp = '\0';

  /* Parent directory must not be world-writable. */
  if (stat(dir, &st) < 0)
    return -1;

  if (!S_ISDIR(st.st_mode)) {
    errno = ENOTDIR;
    return -1;
  }

  if (st.st_mode & S_IWOTH) {
    errno = EPERM;
    return -1;
  }

  *tmp = '/';

  /* Make sure file exists. */
  if (stat(dir, &st) < 0)
    return -1;

  util_sstrncpy(util_scoreboard_file, path, sizeof(util_scoreboard_file));
  return 0;
}

pid_t util_scoreboard_get_daemon_pid(void) {
  return util_header.sch_pid;
}

time_t util_scoreboard_get_daemon_uptime(void) {
  return util_header.sch_uptime;
}

pr_scoreboard_entry_t *util_scoreboard_entry_read(void) {
  static pr_scoreboard_entry_t scan_entry;
  int res = 0;

  if (util_scoreboard_fd < 0) {
    errno = EINVAL;
    return NULL;
  }

  /* Make sure the scoreboard file is read-locked. */
  if (!util_scoreboard_read_locked)
    rlock_scoreboard();

  memset(&scan_entry, '\0', sizeof(scan_entry));

  /* NOTE: use readv(2)? */
  errno = 0;
  while (scan_entry.sce_pid == 0) {
    while ((res = read(util_scoreboard_fd, &scan_entry,
        sizeof(scan_entry))) <= 0) {

      if (res < 0 &&
          errno == EINTR) {
        continue;
 
      } else {
        unlock_scoreboard();

        if (errno) {
          fprintf(stdout, "error reading scoreboard entry: %s\n",
            strerror(errno));
        }

        return NULL;
      }
    }

    if (scan_entry.sce_pid) {
      unlock_scoreboard();
      return &scan_entry;
    }
  }

  unlock_scoreboard();
  return NULL;
}

int util_scoreboard_scrub(int verbose) {
  int fd = -1, res = 0;
  off_t curr_offset = 0;
  struct flock lock;
  pr_scoreboard_entry_t sce;

  if (verbose) {
    fprintf(stdout, "scrubbing ScoreboardFile %s\n", util_get_scoreboard());
  }

  /* Manually open the scoreboard.  It won't hurt if the process already
   * has a descriptor opened on the scoreboard file.
   */
  fd = open(util_get_scoreboard(), O_RDWR);
  if (fd < 0) {
    if (verbose) {
      fprintf(stdout, "error opening scoreboard: %s", strerror(errno));
    }

    return -1;
  }

  /* Lock the entire scoreboard. */
  lock.l_type = F_WRLCK;
  lock.l_whence = 0;

  lock.l_start = 0;
  lock.l_len = 0;

  /* We can afford to block/wait until we obtain our lock on the file. */
  while (fcntl(fd, F_SETLKW, &lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      continue;
    }

    (void) close(fd);
    errno = xerrno;
    return -1;
  }

  /* Skip past the scoreboard header. */
  curr_offset = lseek(fd, (off_t) sizeof(pr_scoreboard_header_t), SEEK_SET);
  if (curr_offset < 0) {
    int xerrno = errno;

    /* Release the scoreboard. */
    lock.l_type = F_UNLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;

    while (fcntl(fd, F_SETLKW, &lock) < 0) {
      if (errno == EINTR) {
        continue;
      }
    }

    /* Don't need the descriptor anymore. */
    (void) close(fd);

    errno = xerrno;
    return -1;
  }

  memset(&sce, 0, sizeof(sce));

  while (read(fd, &sce, sizeof(sce)) == sizeof(sce)) {

    /* Check to see if the PID in this entry is valid.  If not, erase
     * the slot.
     */
    if (sce.sce_pid &&
        kill(sce.sce_pid, 0) < 0 &&
        errno == ESRCH) {

      /* OK, the recorded PID is no longer valid. */
      if (verbose) {
        fprintf(stdout, "scrubbing scoreboard slot for PID %u",
          (unsigned int) sce.sce_pid);
      }

      /* Rewind to the start of this slot. */
      if (lseek(fd, curr_offset, SEEK_SET) < 0) {
        if (verbose) {
          fprintf(stdout, "error scrubbing scoreboard: %s",
            strerror(errno));
        }
      }

      memset(&sce, 0, sizeof(sce));
      while (write(fd, &sce, sizeof(sce)) != sizeof(sce)) {
        if (errno == EINTR) {
          continue;
        }

        if (verbose) {
          fprintf(stdout, "error scrubbing scoreboard: %s",
            strerror(errno));
        }
      }
    }

    /* Mark the current offset. */
    curr_offset = lseek(fd, (off_t) 0, SEEK_CUR);
    if (curr_offset < 0) {
      res = -1;
      break;
    }
  }

  /* Release the scoreboard. */
  lock.l_type = F_UNLCK;
  lock.l_whence = SEEK_SET;
  lock.l_start = 0;
  lock.l_len = 0;

  while (fcntl(fd, F_SETLKW, &lock) < 0) {
    if (errno == EINTR) {
      continue;
    }
  }

  /* Don't need the descriptor anymore. */
  (void) close(fd);

  return res;
}
