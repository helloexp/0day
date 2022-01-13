/*
 * ProFTPD: mod_statcache -- a module implementing caching of stat(2),
 *                           fstat(2), and lstat(2) calls
 * Copyright (c) 2013-2018 TJ Saunders
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
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_statcache, contrib software for proftpd 1.3.x.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"
#ifdef PR_USE_CTRLS
# include "mod_ctrls.h"
#endif /* PR_USE_CTRLS */

#include <signal.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#if HAVE_SYS_MMAN_H
# include <sys/mman.h>
#endif

#if HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif

#define MOD_STATCACHE_VERSION			"mod_statcache/0.2"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030402
# error "ProFTPD 1.3.4rc2 or later required"
#endif

/* On some platforms, this may not be defined.  On AIX, for example, this
 * symbol is only defined when _NO_PROTO is defined, and _XOPEN_SOURCE is 500.
 * How annoying.
 */
#ifndef MAP_FAILED
# define MAP_FAILED     ((void *) -1)
#endif

#define STATCACHE_DEFAULT_CAPACITY	5000
#define STATCACHE_DEFAULT_MAX_AGE	5

/* A path is hashed, and that hash % ncols indicates the row index.  For
 * each row, there can be N columns.  This value indicates the number of
 * columns for a row; it controls how many collisions can be handled.
 */
#define STATCACHE_COLS_PER_ROW		10

/* Max number of lock attempts */
#define STATCACHE_MAX_LOCK_ATTEMPTS	10

/* Subpool size */
#define STATCACHE_POOL_SIZE		256

/* From src/main.c */
extern pid_t mpid;

module statcache_module;

#ifdef PR_USE_CTRLS
static ctrls_acttab_t statcache_acttab[];
#endif

/* Pool for this module's use */
static pool *statcache_pool = NULL;

/* Copied from src/fsio.c. */
struct statcache_entry {
  uint32_t sce_hash;
  char sce_path[PR_TUNABLE_PATH_MAX+1];
  size_t sce_pathlen;
  struct stat sce_stat;
  int sce_errno;
  unsigned char sce_op;
  time_t sce_ts;
};

/*  Storage structure:
 *
 *    Header (stats):
 *      uint32_t count
 *      uint32_t highest
 *      uint32_t hits
 *      uint32_t misses
 *      uint32_t expires
 *      uint32_t rejects
 *
 *  Data (entries):
 *    nrows = capacity / STATCACHE_COLS_PER_ROW
 *    row_len = sizeof(struct statcache_entry) * STATCACHE_COLS_PER_ROW
 *    row_start = ((hash % nrows) * row_len) + data_start
 */

static int statcache_engine = FALSE;
static unsigned int statcache_max_positive_age = STATCACHE_DEFAULT_MAX_AGE;
static unsigned int statcache_max_negative_age = 1;
static unsigned int statcache_capacity = STATCACHE_DEFAULT_CAPACITY;
static unsigned int statcache_nrows = 0;
static size_t statcache_rowlen = 0;

static char *statcache_table_path = NULL;
static pr_fh_t *statcache_tabfh = NULL;

static void *statcache_table = NULL;
static size_t statcache_tablesz = 0;
static void *statcache_table_stats = NULL;
static struct statcache_entry *statcache_table_data = NULL;

static const char *trace_channel = "statcache";

static int statcache_wlock_row(int fd, uint32_t hash);
static int statcache_unlock_row(int fd, uint32_t hash);

#ifdef PR_USE_CTRLS
static int statcache_rlock_stats(int fd);
static int statcache_rlock_table(int fd);
static int statcache_unlock_table(int fd);
#endif /* PR_USE_CTRLS */
static int statcache_wlock_stats(int fd);
static int statcache_unlock_stats(int fd);

static void statcache_fs_statcache_clear_ev(const void *event_data,
  void *user_data);
static int statcache_sess_init(void);

/* Functions for marshalling key/value data to/from local cache (SysV shm). */
static void *statcache_get_shm(pr_fh_t *tabfh, size_t datasz) {
  void *data;
  int fd, mmap_flags, res, xerrno;
#if defined(MADV_RANDOM) || defined(MADV_ACCESS_MANY)
  int advice = 0;
#endif

  fd = tabfh->fh_fd;

  /* Truncate the table first; any existing data should be deleted. */
  res = ftruncate(fd, 0);
  if (res < 0) {
    xerrno = errno;

    pr_log_debug(DEBUG0, MOD_STATCACHE_VERSION
      ": error truncating StatCacheTable '%s' to size 0: %s", tabfh->fh_path,
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  /* Seek to the desired table size (actually, one byte less than the desired
   * size) and write a single byte, so that there's enough allocated backing
   * store on the filesystem to support the ensuing mmap() call.
   */
  if (lseek(fd, datasz, SEEK_SET) == (off_t) -1) {
    xerrno = errno;

    pr_log_debug(DEBUG0, MOD_STATCACHE_VERSION
      ": error seeking to offset %lu in StatCacheTable '%s': %s",
      (unsigned long) datasz-1, tabfh->fh_path, strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  res = write(fd, "", 1);
  if (res != 1) {
    xerrno = errno;

    pr_log_debug(DEBUG0, MOD_STATCACHE_VERSION
      ": error writing single byte to StatCacheTable '%s': %s",
      tabfh->fh_path, strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  mmap_flags = MAP_SHARED;

  /* Make sure to set the fd to -1 if MAP_ANON(YMOUS) is used.  By definition,
   * anonymous mapped memory does not need (or want) a valid file backing
   * store; some implementations will not do what is expected when anonymous
   * memory is requested AND a valid fd is passed in.
   *
   * However, we want to keep a valid fd open anyway, for later use by
   * fcntl(2) for byte range locking; we simply don't use the valid fd for
   * the mmap(2) call.
   */

#if defined(MAP_ANONYMOUS)
  /* Linux */
  mmap_flags |= MAP_ANONYMOUS;
  fd = -1;

#elif defined(MAP_ANON)
  /* FreeBSD, MacOSX, Solaris, others? */
  mmap_flags |= MAP_ANON;
  fd = -1;

#else
  pr_log_debug(DEBUG8, MOD_STATCACHE_VERSION
    ": mmap(2) MAP_ANONYMOUS and MAP_ANON flags not defined");
#endif

  data = mmap(NULL, datasz, PROT_READ|PROT_WRITE, mmap_flags, fd, 0);
  if (data == MAP_FAILED) {
    xerrno = errno;

    pr_log_debug(DEBUG0, MOD_STATCACHE_VERSION
      ": error mapping StatCacheTable '%s' fd %d size %lu into memory: %s",
      tabfh->fh_path, fd, (unsigned long) datasz, strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  /* Make sure the data are zeroed. */
  memset(data, 0, datasz);

#if defined(MADV_RANDOM) || defined(MADV_ACCESS_MANY)
  /* Provide some hints to the kernel, for hopefully better handling of
   * this buffer.
   */
# if defined(MADV_RANDOM)
  advice = MADV_RANDOM;
# elif defined(MADV_ACCESS_MANY)
  /* Oracle-ism? */
  advice = MADV_ACCESS_MANY;
# endif /* Random access pattern memory advice */

  res = madvise(data, datasz, advice);
  if (res < 0) {
    pr_log_debug(DEBUG5, MOD_STATCACHE_VERSION
      ": madvise(2) error with MADV_RANDOM: %s", strerror(errno));
  }
#endif

  return data;
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
      lock_type = "[UNKNOWN]";
  }

  return lock_type;
}

/* Header locking routines */
static int lock_table(int fd, int lock_type, off_t lock_len) {
  struct flock lock;
  unsigned int nattempts = 1;

  lock.l_type = lock_type;
  lock.l_whence = 0;
  lock.l_start = 0;
  lock.l_len = (6 * sizeof(uint32_t));

  pr_trace_msg(trace_channel, 15,
    "attempt #%u to acquire %s lock on StatCacheTable fd %d (off %lu, len %lu)",
    nattempts, get_lock_type(&lock), fd, (unsigned long) lock.l_start,
    (unsigned long) lock.l_len);

  while (fcntl(fd, F_SETLK, &lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg(trace_channel, 3,
      "%s lock (attempt #%u) of StatCacheTable fd %d failed: %s",
      get_lock_type(&lock), nattempts, fd, strerror(xerrno));
    if (xerrno == EACCES) {
      struct flock locker;

      /* Get the PID of the process blocking this lock. */
      if (fcntl(fd, F_GETLK, &locker) == 0) {
        pr_trace_msg(trace_channel, 3, "process ID %lu has blocking %s lock on "
          "StatCacheTable fd %d", (unsigned long) locker.l_pid,
          get_lock_type(&locker), fd);
      }
    }

    if (xerrno == EAGAIN ||
        xerrno == EACCES) {
      /* Treat this as an interrupted call, call pr_signals_handle() (which
       * will delay for a few msecs because of EINTR), and try again.
       * After MAX_LOCK_ATTEMPTS attempts, give up altogether.
       */

      nattempts++;
      if (nattempts <= STATCACHE_MAX_LOCK_ATTEMPTS) {
        errno = EINTR;

        pr_signals_handle();

        errno = 0;
        pr_trace_msg(trace_channel, 15,
          "attempt #%u to acquire %s lock on StatCacheTable fd %d", nattempts,
          get_lock_type(&lock), fd);
        continue;
      }

      pr_trace_msg(trace_channel, 15, "unable to acquire %s lock on "
        "StatCacheTable fd %d after %u attempts: %s", get_lock_type(&lock),
        nattempts, fd, strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 15,
    "acquired %s lock of StatCacheTable fd %d successfully",
    get_lock_type(&lock), fd);
  return 0;
}

#ifdef PR_USE_CTRLS
static int statcache_rlock_stats(int fd) {
  return lock_table(fd, F_RDLCK, (6 * sizeof(uint32_t)));
}

static int statcache_rlock_table(int fd) {
  return lock_table(fd, F_RDLCK, 0);
}

static int statcache_unlock_table(int fd) {
  return lock_table(fd, F_RDLCK, 0);
}
#endif /* PR_USE_CTRLS */

static int statcache_wlock_stats(int fd) {
  return lock_table(fd, F_WRLCK, (6 * sizeof(uint32_t)));
}

static int statcache_unlock_stats(int fd) {
  return lock_table(fd, F_UNLCK, (6 * sizeof(uint32_t)));
}

#ifdef PR_USE_CTRLS
static uint32_t statcache_stats_get_count(void) {
  uint32_t count = 0;

  /* count = statcache_table_stats + (0 * sizeof(uint32_t)) */
  count = *((uint32_t *) statcache_table_stats);
  return count;
}

static uint32_t statcache_stats_get_highest(void) {
  uint32_t highest = 0;

  /* highest = statcache_table_stats + (1 * sizeof(uint32_t)) */
  highest = *((uint32_t *) ((char *) statcache_table_stats +
    (1 * sizeof(uint32_t))));
  return highest;
}

static uint32_t statcache_stats_get_hits(void) {
  uint32_t hits = 0;

  /* hits = statcache_table_stats + (2 * sizeof(uint32_t)) */
  hits = *((uint32_t *) ((char *) statcache_table_stats +
    (2 * sizeof(uint32_t))));
  return hits;
}

static uint32_t statcache_stats_get_misses(void) {
  uint32_t misses = 0;

  /* misses = statcache_table_stats + (3 * sizeof(uint32_t)) */
  misses = *((uint32_t *) ((char *) statcache_table_stats +
    (3 * sizeof(uint32_t))));
  return misses;
}

static uint32_t statcache_stats_get_expires(void) {
  uint32_t expires = 0;

  /* expires = statcache_table_stats + (4 * sizeof(uint32_t)) */
  expires = *((uint32_t *) ((char *) statcache_table_stats +
    (4 * sizeof(uint32_t))));
  return expires;
}

static uint32_t statcache_stats_get_rejects(void) {
  uint32_t rejects = 0;

  /* rejects = statcache_table_stats + (5 * sizeof(uint32_t)) */
  rejects = *((uint32_t *) ((char *) statcache_table_stats +
    (5 * sizeof(uint32_t))));
  return rejects;
}
#endif /* PR_USE_CTRLS */

static int statcache_stats_incr_count(int32_t incr) {
  uint32_t *count = NULL, *highest = NULL;

  if (incr == 0) {
    return 0;
  }

  /* count = statcache_table_stats + (0 * sizeof(uint32_t)) */
  count = ((uint32_t *) statcache_table_stats);

  /* highest = statcache_table_stats + (1 * sizeof(uint32_t)) */
  highest = ((uint32_t *) ((char *) statcache_table_stats) +
    (1 * sizeof(uint32_t)));

  if (incr < 0) {
    /* Prevent underflow. */
    if (*count <= incr) {
      *count = 0;

    } else {
      *count += incr;
    }

  } else {
    *count += incr;

    if (*count > *highest) {
      *highest = *count;
    }
  }

  return 0;
}

static int statcache_stats_incr_hits(int32_t incr) {
  uint32_t *hits = NULL;

  if (incr == 0) {
    return 0;
  }

  /* hits = statcache_table_stats + (2 * sizeof(uint32_t)) */
  hits = ((uint32_t *) ((char *) statcache_table_stats) +
    (2 * sizeof(uint32_t)));

  /* Prevent underflow. */
  if (incr < 0 &&
      *hits <= incr) {
    *hits = 0;

  } else {
    *hits += incr;
  }

  return 0;
} 

static int statcache_stats_incr_misses(int32_t incr) {
  uint32_t *misses = NULL;
 
  if (incr == 0) {
    return 0;
  }
 
  /* misses = statcache_table_stats + (3 * sizeof(uint32_t)) */
  misses = ((uint32_t *) ((char *) statcache_table_stats) +
    (3 * sizeof(uint32_t)));

  /* Prevent underflow. */
  if (incr < 0 &&
      *misses <= incr) {
    *misses = 0;

  } else {
    *misses += incr;
  }

  return 0;
} 

static int statcache_stats_incr_expires(int32_t incr) {
  uint32_t *expires = NULL;
 
  if (incr == 0) {
    return 0;
  }
 
  /* expires = statcache_table_stats + (4 * sizeof(uint32_t)) */
  expires = ((uint32_t *) ((char *) statcache_table_stats) +
    (4 * sizeof(uint32_t)));

  /* Prevent underflow. */
  if (incr < 0 &&
      *expires <= incr) {
    *expires = 0;

  } else {
    *expires += incr;
  }

  return 0;
} 

static int statcache_stats_incr_rejects(int32_t incr) {
  uint32_t *rejects = NULL;

  if (incr == 0) {
    return 0;
  }

  /* rejects = statcache_table_stats + (5 * sizeof(uint32_t)) */
  rejects = ((uint32_t *) ((char *) statcache_table_stats) +
    (5 * sizeof(uint32_t)));

  /* Prevent underflow. */
  if (incr < 0 &&
      *rejects <= incr) {
    *rejects = 0;

  } else {
    *rejects += incr;
  }

  return 0;
}

/* Data locking routines */

static int get_row_range(uint32_t hash, off_t *row_start, off_t *row_len) {
  uint32_t row_idx;

  row_idx = hash % statcache_nrows;
  *row_start = (row_idx * statcache_rowlen);
  *row_len = statcache_rowlen;

  return 0;
}

static int lock_row(int fd, int lock_type, uint32_t hash) {
  struct flock lock;
  unsigned int nattempts = 1;

  lock.l_type = lock_type;
  lock.l_whence = 0;
  get_row_range(hash, &lock.l_start, &lock.l_len);

  pr_trace_msg(trace_channel, 15,
    "attempt #%u to acquire row %s lock on StatCacheTable fd %d "
    "(off %lu, len %lu)", nattempts, get_lock_type(&lock), fd,
    (unsigned long) lock.l_start,
    (unsigned long) lock.l_len);

  while (fcntl(fd, F_SETLK, &lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg(trace_channel, 3,
      "%s lock (attempt #%u) of StatCacheTable fd %d failed: %s",
      get_lock_type(&lock), nattempts, fd, strerror(xerrno));
    if (xerrno == EACCES) {
      struct flock locker;

      /* Get the PID of the process blocking this lock. */
      if (fcntl(fd, F_GETLK, &locker) == 0) {
        pr_trace_msg(trace_channel, 3, "process ID %lu has blocking %s lock on "
          "StatCacheTable fd %d", (unsigned long) locker.l_pid,
          get_lock_type(&locker), fd);
      }
    }

    if (xerrno == EAGAIN ||
        xerrno == EACCES) {
      /* Treat this as an interrupted call, call pr_signals_handle() (which
       * will delay for a few msecs because of EINTR), and try again.
       * After MAX_LOCK_ATTEMPTS attempts, give up altogether.
       */

      nattempts++;
      if (nattempts <= STATCACHE_MAX_LOCK_ATTEMPTS) {
        errno = EINTR;

        pr_signals_handle();

        errno = 0;
        pr_trace_msg(trace_channel, 15,
          "attempt #%u to acquire %s row lock on StatCacheTable fd %d",
          nattempts, get_lock_type(&lock), fd);
        continue;
      }

      pr_trace_msg(trace_channel, 15, "unable to acquire %s row lock on "
        "StatCacheTable fd %d after %u attempts: %s", get_lock_type(&lock),
        nattempts, fd, strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 15,
    "acquired %s row lock of StatCacheTable fd %d successfully",
    get_lock_type(&lock), fd);
  return 0;
}

static int statcache_wlock_row(int fd, uint32_t hash) {
  return lock_row(fd, F_WRLCK, hash);
}

static int statcache_unlock_row(int fd, uint32_t hash) {
  return lock_row(fd, F_UNLCK, hash);
}

/* Table manipulation routines */

/* See http://www.cse.yorku.ca/~oz/hash.html */
static uint32_t statcache_hash(const char *path, size_t pathlen) {
  register unsigned int i;
  uint32_t h = 5381;

  for (i = 0; i < pathlen; i++) {
    h = ((h << 5) + h) + path[i];
  }

  /* Strip off the high bit. */
  h &= ~(1 << 31);

  return h;
}

/* Add an entry to the table. */
static int statcache_table_add(int fd, const char *path, size_t pathlen,
    struct stat *st, int xerrno, uint32_t hash, unsigned char op) {
  register unsigned int i;
  uint32_t row_idx, row_start;
  int found_slot = FALSE, expired_entries = 0;
  time_t now;
  struct statcache_entry *sce = NULL;

  if (statcache_table == NULL) {
    errno = EPERM;
    return -1;
  }

  /* Find an open slot in the list for this new entry. */
  now = time(NULL);

  row_idx = hash % statcache_nrows;
  row_start = (row_idx * statcache_rowlen);

  for (i = 0; i < STATCACHE_COLS_PER_ROW; i++) {
    uint32_t col_start;

    pr_signals_handle();

    col_start = (row_start + (i * sizeof(struct statcache_entry)));
    sce = (((char *) statcache_table_data) + col_start);
    if (sce->sce_ts == 0) {
      /* Empty slot */
      found_slot = TRUE;
      break;
    }

    /* If existing item is too old, use this slot.  Note that there
     * are different expiry rules for negative cache entries (i.e.
     * errors) than for positive cache entries.
     */
    if (sce->sce_errno == 0) {
      if (now > (sce->sce_ts + statcache_max_positive_age)) {
        found_slot = TRUE;
        expired_entries++;
        break;
      }

    } else {
      if (now > (sce->sce_ts + statcache_max_negative_age)) {
        found_slot = TRUE;
        expired_entries++;
        break;
      }
    }
  }

  if (found_slot == FALSE) {
    if (statcache_wlock_stats(fd) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }

    statcache_stats_incr_rejects(1);

    if (statcache_unlock_stats(fd) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error un-locking shared memory: %s", strerror(errno));
    }

    errno = ENOSPC;
    return -1;
  }

  if (st != NULL) {
    pr_trace_msg(trace_channel, 9,
      "adding entry for path '%s' (hash %lu) at row %lu, col %u "
      "(op %s, type %s)", path,
      (unsigned long) hash, (unsigned long) row_idx + 1, i + 1,
      op == FSIO_FILE_LSTAT ? "LSTAT" : "STAT",
      S_ISLNK(st->st_mode) ? "symlink" :
        S_ISDIR(st->st_mode) ? "dir" : "file");

  } else {
    pr_trace_msg(trace_channel, 9,
      "adding entry for path '%s' (hash %lu) at row %lu, col %u "
      "(op %s, errno %d)", path,
      (unsigned long) hash, (unsigned long) row_idx + 1, i + 1,
      op == FSIO_FILE_LSTAT ? "LSTAT" : "STAT", xerrno);
  }

  sce->sce_hash = hash;
  sce->sce_pathlen = pathlen;

  /* Include trailing NUL. */
  memcpy(sce->sce_path, path, pathlen + 1);
  if (st != NULL) {
    memcpy(&(sce->sce_stat), st, sizeof(struct stat));
  }
  sce->sce_errno = xerrno;
  sce->sce_ts = now;
  sce->sce_op = op;

  if (statcache_wlock_stats(fd) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error write-locking shared memory: %s", strerror(errno));
  }

  statcache_stats_incr_count(1);
  if (expired_entries > 0) {
    statcache_stats_incr_count(-expired_entries);
    statcache_stats_incr_expires(expired_entries);
  }

  if (statcache_unlock_stats(fd) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error un-locking shared memory: %s", strerror(errno));
  }

  return 0;
}

static int statcache_table_get(int fd, const char *path, size_t pathlen,
    struct stat *st, int *xerrno, uint32_t hash, unsigned char op) {
  register unsigned int i;
  int expired_entries = 0, res = -1;
  uint32_t row_idx, row_start;

  if (statcache_table == NULL) {
    errno = EPERM;
    return -1;
  }

  row_idx = hash % statcache_nrows;
  row_start = (row_idx * statcache_rowlen);

  /* Find the matching entry for this path. */
  for (i = 0; i < STATCACHE_COLS_PER_ROW; i++) {
    uint32_t col_start;
    struct statcache_entry *sce;

    pr_signals_handle();

    col_start = (row_start + (i * sizeof(struct statcache_entry)));
    sce = (((char *) statcache_table_data) + col_start);
    if (sce->sce_ts > 0) {
      if (sce->sce_hash == hash) {
        /* Possible collision; check paths. */
        if (sce->sce_pathlen == pathlen) {

          /* Include the trailing NUL in the comparison... */
          if (strncmp(sce->sce_path, path, pathlen + 1) == 0) {
            time_t now;

            now = time(NULL);

            /* Check the age.  If it's aged out, clear it now, for later use. */
            if (sce->sce_errno == 0) {
              if (now > (sce->sce_ts + statcache_max_positive_age)) {
                pr_trace_msg(trace_channel, 17,
                  "clearing expired cache entry for path '%s' (hash %lu) "
                  "at row %lu, col %u: aged %lu secs",
                  sce->sce_path, (unsigned long) hash,
                  (unsigned long) row_idx + 1, i + 1,
                  (unsigned long) (now - sce->sce_ts));
                sce->sce_ts = 0;
                expired_entries++;
                continue;
              }

            } else {
              if (now > (sce->sce_ts + statcache_max_negative_age)) {
                pr_trace_msg(trace_channel, 17,
                  "clearing expired negative cache entry for path '%s' "
                  "(hash %lu) at row %lu, col %u: aged %lu secs",
                  sce->sce_path, (unsigned long) hash,
                  (unsigned long) row_idx + 1, i + 1,
                  (unsigned long) (now - sce->sce_ts));
                sce->sce_ts = 0;
                expired_entries++;
                continue;
              }
            }

            /* If the ops match, OR if the entry is from a LSTAT AND the entry
             * is NOT a symlink, we can use it.
             */
            if (sce->sce_op == op ||
                (sce->sce_op == FSIO_FILE_LSTAT &&
                 S_ISLNK(sce->sce_stat.st_mode) == FALSE)) {
              /* Found matching entry. */
              pr_trace_msg(trace_channel, 9,
                "found entry for path '%s' (hash %lu) at row %lu, col %u",
                path, (unsigned long) hash, (unsigned long) row_idx + 1, i + 1);

              *xerrno = sce->sce_errno;
              if (sce->sce_errno == 0) {
                memcpy(st, &(sce->sce_stat), sizeof(struct stat));
              }

              res = 0;
              break;
            }
          }
        }
      }
    }
  }

  if (statcache_wlock_stats(fd) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error write-locking shared memory: %s", strerror(errno));
  }

  if (res == 0) {
    statcache_stats_incr_hits(1);

  } else {
    statcache_stats_incr_misses(1);
  }

  if (expired_entries > 0) {
    statcache_stats_incr_count(-expired_entries);
    statcache_stats_incr_expires(expired_entries);
  }

  if (statcache_unlock_stats(fd) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error un-locking shared memory: %s", strerror(errno));
  }

  if (res < 0) {
    errno = ENOENT;
  }

  return res;
}

static int statcache_table_remove(int fd, const char *path, size_t pathlen,
    uint32_t hash) {
  register unsigned int i;
  uint32_t row_idx, row_start;
  int removed_entries = 0, res = -1;

  if (statcache_table == NULL) {
    errno = EPERM;
    return -1;
  }

  row_idx = hash % statcache_nrows;
  row_start = (row_idx * statcache_rowlen);

  /* Find the matching entry for this path. */
  for (i = 0; i < STATCACHE_COLS_PER_ROW; i++) {
    uint32_t col_start;
    struct statcache_entry *sce;

    pr_signals_handle();

    col_start = (row_start + (i * sizeof(struct statcache_entry)));
    sce = (((char *) statcache_table_data) + col_start);
    if (sce->sce_ts > 0) {
      if (sce->sce_hash == hash) {
        /* Possible collision; check paths. */
        if (sce->sce_pathlen == pathlen) {

          /* Include the trailing NUL in the comparison... */
          if (strncmp(sce->sce_path, path, pathlen + 1) == 0) {
            /* Found matching entry.  Clear it by zeroing timestamp field. */

            pr_trace_msg(trace_channel, 9,
              "removing entry for path '%s' (hash %lu) at row %lu, col %u",
              path, (unsigned long) hash, (unsigned long) row_idx + 1, i + 1);

            sce->sce_ts = 0;
            removed_entries++;
            res = 0;

            /* Rather than returning now, we finish iterating through
             * the bucket, in order to clear out multiple entries for
             * the same path (e.g. one for LSTAT, and another for STAT).
             */
          }
        }
      }
    }
  }

  if (res == 0) {
    if (statcache_wlock_stats(fd) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }

    if (removed_entries > 0) {
      statcache_stats_incr_count(-removed_entries);
    }

    if (statcache_unlock_stats(fd) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error un-locking shared memory: %s", strerror(errno));
    }

  } else {
    errno = ENOENT;
  }

  return res;
}

static const char *statcache_get_canon_path(pool *p, const char *path,
    size_t *pathlen) {
  int res;
  char *canon_path = NULL, *interp_path = NULL;
  size_t canon_pathlen = PR_TUNABLE_PATH_MAX + 1;

  /* Handle any '~' interpolation needed. */
  interp_path = dir_interpolate(p, path);
  if (interp_path == NULL) {
    /* This happens when the '~' was just that, and did NOT refer to
     * any known user.
     */
    interp_path = (char *) path;
  }

  canon_path = palloc(p, canon_pathlen);
  res = pr_fs_dircat(canon_path, canon_pathlen, pr_fs_getcwd(), interp_path);
  if (res < 0) {
    errno = ENOMEM;
    return NULL;
  }

  *pathlen = strlen(canon_path);
  return canon_path;
}

/* FSIO callbacks
 */

static int statcache_fsio_stat(pr_fs_t *fs, const char *path,
    struct stat *st) {
  int res, tab_fd, xerrno = 0;
  const char *canon_path = NULL;
  size_t canon_pathlen = 0;
  pool *p;
  uint32_t hash;

  p = make_sub_pool(statcache_pool);
  pr_pool_tag(p, "statcache_fsio_stat sub-pool");
  canon_path = statcache_get_canon_path(p, path, &canon_pathlen);
  if (canon_path == NULL) {
    xerrno = errno;

    destroy_pool(p);
    errno = xerrno;
    return -1;
  }

  hash = statcache_hash(canon_path, canon_pathlen);
  tab_fd = statcache_tabfh->fh_fd;

  if (statcache_wlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error write-locking shared memory: %s", strerror(errno));
  }

  res = statcache_table_get(tab_fd, canon_path, canon_pathlen, st, &xerrno,
    hash, FSIO_FILE_STAT);

  if (statcache_unlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error unlocking shared memory: %s", strerror(errno));
  }

  if (res == 0) {
    if (xerrno != 0) {
      res = -1;

    } else {
      pr_trace_msg(trace_channel, 11,
        "using cached stat for path '%s'", canon_path);
    }

    destroy_pool(p);
    errno = xerrno;
    return res;
  }

  res = stat(path, st);
  xerrno = errno;

  if (statcache_wlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error write-locking shared memory: %s", strerror(errno));
  }

  if (statcache_wlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error write-locking shared memory: %s", strerror(errno));
  }

  if (res < 0) {
    if (statcache_max_negative_age > 0) {
      /* Negatively cache the failed stat(2). */
      if (statcache_table_add(tab_fd, canon_path, canon_pathlen, NULL, xerrno,
          hash, FSIO_FILE_STAT) < 0) {
        pr_trace_msg(trace_channel, 3, "error adding entry for path '%s': %s",
          canon_path, strerror(errno));
      }
    }

  } else {
    if (statcache_table_add(tab_fd, canon_path, canon_pathlen, st, 0, hash,
        FSIO_FILE_STAT) < 0) {
      pr_trace_msg(trace_channel, 3, "error adding entry for path '%s': %s",
        canon_path, strerror(errno));
    }
  }

  if (statcache_unlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error unlocking shared memory: %s", strerror(errno));
  }

  destroy_pool(p);
  errno = xerrno;
  return res;
}

static int statcache_fsio_fstat(pr_fh_t *fh, int fd, struct stat *st) {
  int res, tab_fd, xerrno = 0;
  size_t pathlen = 0;
  uint32_t hash;

  /* XXX Core FSIO API should have an fh_pathlen member.
   *
   * XXX Core FSIO API should have an fh_notes table, so that e.g.
   * mod_statcache could generate its hash for this handle only once, and
   * stash it in the table.
   */

  pathlen = strlen(fh->fh_path);
  hash = statcache_hash(fh->fh_path, pathlen);
  tab_fd = statcache_tabfh->fh_fd;

  if (statcache_wlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error write-locking shared memory: %s", strerror(errno));
  }

  res = statcache_table_get(tab_fd, fh->fh_path, pathlen, st, &xerrno, hash,
    FSIO_FILE_STAT);

  if (statcache_unlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error unlocking shared memory: %s", strerror(errno));
  }

  if (res == 0) {
    if (xerrno != 0) {
      res = -1;

    } else {
      pr_trace_msg(trace_channel, 11,
        "using cached stat for path '%s'", fh->fh_path);
    }

    errno = xerrno;
    return res;
  }

  res = fstat(fd, st);
  xerrno = errno;

  if (statcache_wlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error write-locking shared memory: %s", strerror(errno));
  }

  if (res < 0) {
    if (statcache_max_negative_age > 0) {
      /* Negatively cache the failed fstat(2). */
      if (statcache_table_add(tab_fd, fh->fh_path, pathlen, NULL, xerrno,
          hash, FSIO_FILE_STAT) < 0) {
        pr_trace_msg(trace_channel, 3, "error adding entry for path '%s': %s",
          fh->fh_path, strerror(errno));
      }
    }

  } else {
    if (statcache_table_add(tab_fd, fh->fh_path, pathlen, st, 0, hash,
        FSIO_FILE_STAT) < 0) {
      pr_trace_msg(trace_channel, 3, "error adding entry for path '%s': %s",
        fh->fh_path, strerror(errno));
    }
  }

  if (statcache_unlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error unlocking shared memory: %s", strerror(errno));
  }

  errno = xerrno;
  return res;
}

static int statcache_fsio_lstat(pr_fs_t *fs, const char *path,
    struct stat *st) {
  int res, tab_fd, xerrno = 0;
  const char *canon_path = NULL;
  size_t canon_pathlen = 0;
  pool *p;
  uint32_t hash;

  p = make_sub_pool(statcache_pool);
  pr_pool_tag(p, "statcache_fsio_lstat sub-pool");
  canon_path = statcache_get_canon_path(p, path, &canon_pathlen);
  if (canon_path == NULL) {
    xerrno = errno;
    
    destroy_pool(p);
    errno = xerrno; 
    return -1;
  }

  hash = statcache_hash(canon_path, canon_pathlen);
  tab_fd = statcache_tabfh->fh_fd;

  if (statcache_wlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error write-locking shared memory: %s", strerror(errno));
  }

  res = statcache_table_get(tab_fd, canon_path, canon_pathlen, st, &xerrno,
    hash, FSIO_FILE_LSTAT);

  if (statcache_unlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error unlocking shared memory: %s", strerror(errno));
  }

  if (res == 0) {
    if (xerrno != 0) {
      res = -1;

    } else {
      pr_trace_msg(trace_channel, 11,
        "using cached lstat for path '%s'", canon_path);
    }

    destroy_pool(p);
    errno = xerrno;
    return res;
  }

  res = lstat(path, st);
  xerrno = errno;

  if (statcache_wlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error write-locking shared memory: %s", strerror(errno));
  }

  if (res < 0) {
    if (statcache_max_negative_age > 0) {
      /* Negatively cache the failed lstat(2). */
      if (statcache_table_add(tab_fd, canon_path, canon_pathlen, NULL, xerrno,
          hash, FSIO_FILE_LSTAT) < 0) {
        pr_trace_msg(trace_channel, 3, "error adding entry for path '%s': %s",
          canon_path, strerror(errno));
      }
    }

  } else {
    if (statcache_table_add(tab_fd, canon_path, canon_pathlen, st, 0, hash,
        FSIO_FILE_LSTAT) < 0) {
      pr_trace_msg(trace_channel, 3, "error adding entry for path '%s': %s",
        canon_path, strerror(errno));
    }
  }

  if (statcache_unlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error unlocking shared memory: %s", strerror(errno));
  }

  destroy_pool(p);
  errno = xerrno;
  return res;
}

static int statcache_fsio_rename(pr_fs_t *fs, const char *rnfm,
    const char *rnto) {
  int res, xerrno;

  res = rename(rnfm, rnto);
  xerrno = errno;

  if (res == 0) {
    int tab_fd;
    const char *canon_rnfm = NULL, *canon_rnto = NULL;
    size_t canon_rnfmlen = 0, canon_rntolen = 0;
    pool *p;
    uint32_t hash_rnfm, hash_rnto;

    p = make_sub_pool(statcache_pool);
    pr_pool_tag(p, "statcache_fsio_rename sub-pool");

    canon_rnfm = statcache_get_canon_path(p, rnfm, &canon_rnfmlen);
    if (canon_rnfm == NULL) {
      xerrno = errno;

      destroy_pool(p);
      errno = xerrno;
      return res;
    }

    canon_rnto = statcache_get_canon_path(p, rnto, &canon_rntolen);
    if (canon_rnto == NULL) {
      xerrno = errno;

      destroy_pool(p);
      errno = xerrno;
      return res;
    }

    hash_rnfm = statcache_hash(canon_rnfm, canon_rnfmlen);
    hash_rnto = statcache_hash(canon_rnto, canon_rntolen);
    tab_fd = statcache_tabfh->fh_fd;

    if (statcache_wlock_row(tab_fd, hash_rnfm) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }   

    (void) statcache_table_remove(tab_fd, canon_rnfm, canon_rnfmlen, hash_rnfm);

    if (statcache_unlock_row(tab_fd, hash_rnfm) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    }

    if (statcache_wlock_row(tab_fd, hash_rnto) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }

    (void) statcache_table_remove(tab_fd, canon_rnto, canon_rntolen, hash_rnto);

    if (statcache_unlock_row(tab_fd, hash_rnto) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    }

    destroy_pool(p);
  }

  errno = xerrno;
  return res;
}

static int statcache_fsio_unlink(pr_fs_t *fs, const char *path) {
  int res, xerrno;

  res = unlink(path);
  xerrno = errno;

  if (res == 0) {
    int tab_fd;
    const char *canon_path = NULL;
    size_t canon_pathlen = 0;
    pool *p;
    uint32_t hash;

    p = make_sub_pool(statcache_pool);
    pr_pool_tag(p, "statcache_fsio_unlink sub-pool");
    canon_path = statcache_get_canon_path(p, path, &canon_pathlen);
    if (canon_path == NULL) {
      xerrno = errno;

      destroy_pool(p);
      errno = xerrno;
      return res;
    }

    hash = statcache_hash(canon_path, canon_pathlen);
    tab_fd = statcache_tabfh->fh_fd;

    if (statcache_wlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }

    (void) statcache_table_remove(tab_fd, canon_path, canon_pathlen, hash);

    if (statcache_unlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    }

    destroy_pool(p);
  }

  errno = xerrno;
  return res;
}

static int statcache_fsio_open(pr_fh_t *fh, const char *path, int flags) {
  int res, xerrno;

  res = open(path, flags, PR_OPEN_MODE);
  xerrno = errno;

  if (res >= 0) {
    /* Clear the cache for this patch, but only if O_CREAT or O_TRUNC are
     * present.
     */
    if ((flags & O_CREAT) ||
        (flags & O_TRUNC)) {
      int tab_fd;
      const char *canon_path = NULL;
      size_t canon_pathlen = 0;
      pool *p;
      uint32_t hash;

      p = make_sub_pool(statcache_pool);
      pr_pool_tag(p, "statcache_fsio_open sub-pool");
      canon_path = statcache_get_canon_path(p, path, &canon_pathlen);
      if (canon_path == NULL) {
        xerrno = errno;

        destroy_pool(p);
        errno = xerrno;
        return res;
      }

      hash = statcache_hash(canon_path, canon_pathlen);
      tab_fd = statcache_tabfh->fh_fd;

      if (statcache_wlock_row(tab_fd, hash) < 0) {
        pr_trace_msg(trace_channel, 3,
          "error write-locking shared memory: %s", strerror(errno));
      } 

      pr_trace_msg(trace_channel, 14,
        "removing entry for path '%s' due to open(2) flags", canon_path);
      (void) statcache_table_remove(tab_fd, canon_path, canon_pathlen, hash);

      if (statcache_unlock_row(tab_fd, hash) < 0) {
        pr_trace_msg(trace_channel, 3,
          "error unlocking shared memory: %s", strerror(errno));
      }

      destroy_pool(p);
    }
  } 

  errno = xerrno;  
  return res;
}

static int statcache_fsio_write(pr_fh_t *fh, int fd, const char *buf,
    size_t buflen) {
  int res, xerrno;

  res = write(fd, buf, buflen);
  xerrno = errno;

  if (res > 0) {
    int tab_fd;
    size_t pathlen = 0;
    uint32_t hash;

    pathlen = strlen(fh->fh_path);
    hash = statcache_hash(fh->fh_path, pathlen);
    tab_fd = statcache_tabfh->fh_fd;
 
    if (statcache_wlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
  
    (void) statcache_table_remove(tab_fd, fh->fh_path, pathlen, hash);

    if (statcache_unlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }

  errno = xerrno; 
  return res;
}

static int statcache_fsio_truncate(pr_fs_t *fs, const char *path, off_t len) {
  int res, xerrno;

  res = truncate(path, len);
  xerrno = errno;

  if (res == 0) {
    int tab_fd;
    const char *canon_path = NULL;
    size_t canon_pathlen = 0;
    pool *p;
    uint32_t hash;

    p = make_sub_pool(statcache_pool);
    pr_pool_tag(p, "statcache_fsio_truncate sub-pool");
    canon_path = statcache_get_canon_path(p, path, &canon_pathlen);
    if (canon_path == NULL) {
      xerrno = errno;

      destroy_pool(p);
      errno = xerrno;
      return res;
    }

    hash = statcache_hash(canon_path, canon_pathlen);
    tab_fd = statcache_tabfh->fh_fd;

    if (statcache_wlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(tab_fd, canon_path, canon_pathlen, hash);

    if (statcache_unlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    }

    destroy_pool(p);
  }

  errno = xerrno;  
  return res;
}

static int statcache_fsio_ftruncate(pr_fh_t *fh, int fd, off_t len) {
  int res, xerrno;

  res = ftruncate(fd, len);
  xerrno = errno;

  if (res == 0) {
    int tab_fd;
    size_t pathlen = 0;
    uint32_t hash;

    pathlen = strlen(fh->fh_path);
    hash = statcache_hash(fh->fh_path, pathlen);
    tab_fd = statcache_tabfh->fh_fd;

    if (statcache_wlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(tab_fd, fh->fh_path, pathlen, hash);

    if (statcache_unlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }

  errno = xerrno; 
  return res;
}

static int statcache_fsio_chmod(pr_fs_t *fs, const char *path, mode_t mode) {
  int res, xerrno;

  res = chmod(path, mode);
  xerrno = errno;

  if (res == 0) {
    int tab_fd;
    const char *canon_path = NULL;
    size_t canon_pathlen = 0;
    pool *p;
    uint32_t hash;

    p = make_sub_pool(statcache_pool);
    pr_pool_tag(p, "statcache_fsio_chmod sub-pool");
    canon_path = statcache_get_canon_path(p, path, &canon_pathlen);
    if (canon_path == NULL) {
      xerrno = errno;

      destroy_pool(p);
      errno = xerrno;
      return res;
    }

    hash = statcache_hash(canon_path, canon_pathlen);
    tab_fd = statcache_tabfh->fh_fd;

    if (statcache_wlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(tab_fd, canon_path, canon_pathlen, hash);

    if (statcache_unlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    }

    destroy_pool(p);
  }

  errno = xerrno;
  return res;
}

static int statcache_fsio_fchmod(pr_fh_t *fh, int fd, mode_t mode) {
  int res, xerrno;

  res = fchmod(fd, mode);
  xerrno = errno;

  if (res == 0) {
    int tab_fd;
    size_t pathlen = 0;
    uint32_t hash;

    pathlen = strlen(fh->fh_path);
    hash = statcache_hash(fh->fh_path, pathlen);
    tab_fd = statcache_tabfh->fh_fd;

    if (statcache_wlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(tab_fd, fh->fh_path, pathlen, hash);

    if (statcache_unlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }

  errno = xerrno;
  return res;
}

static int statcache_fsio_chown(pr_fs_t *fs, const char *path, uid_t uid,
    gid_t gid) {
  int res, xerrno;

  res = chown(path, uid, gid);
  xerrno = errno;

  if (res == 0) {
    int tab_fd;
    const char *canon_path = NULL;
    size_t canon_pathlen = 0;
    pool *p;
    uint32_t hash;

    p = make_sub_pool(statcache_pool);
    pr_pool_tag(p, "statcache_fsio_chown sub-pool");
    canon_path = statcache_get_canon_path(p, path, &canon_pathlen);
    if (canon_path == NULL) {
      xerrno = errno;

      destroy_pool(p);
      errno = xerrno;
      return res;
    }

    hash = statcache_hash(canon_path, canon_pathlen);
    tab_fd = statcache_tabfh->fh_fd;

    if (statcache_wlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(tab_fd, canon_path, canon_pathlen, hash);

    if (statcache_unlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    }

    destroy_pool(p);
  }

  errno = xerrno;
  return res;
}

static int statcache_fsio_fchown(pr_fh_t *fh, int fd, uid_t uid, gid_t gid) {
  int res, xerrno;

  res = fchown(fd, uid, gid);
  xerrno = errno;

  if (res == 0) {
    int tab_fd;
    size_t pathlen = 0;
    uint32_t hash;

    pathlen = strlen(fh->fh_path);
    hash = statcache_hash(fh->fh_path, pathlen);
    tab_fd = statcache_tabfh->fh_fd;

    if (statcache_wlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(tab_fd, fh->fh_path, pathlen, hash);

    if (statcache_unlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }

  errno = xerrno;
  return res;
}

#if PROFTPD_VERSION_NUMBER >= 0x0001030407
static int statcache_fsio_lchown(pr_fs_t *fs, const char *path, uid_t uid,
    gid_t gid) {
  int res, xerrno;

  res = lchown(path, uid, gid);
  xerrno = errno;

  if (res == 0) {
    int tab_fd;
    const char *canon_path = NULL;
    size_t canon_pathlen = 0;
    pool *p;
    uint32_t hash;

    p = make_sub_pool(statcache_pool);
    pr_pool_tag(p, "statcache_fsio_lchown sub-pool");
    canon_path = statcache_get_canon_path(p, path, &canon_pathlen);
    if (canon_path == NULL) {
      xerrno = errno;

      destroy_pool(p);
      errno = xerrno;
      return res;
    }

    hash = statcache_hash(canon_path, canon_pathlen);
    tab_fd = statcache_tabfh->fh_fd;

    if (statcache_wlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(tab_fd, canon_path, canon_pathlen, hash);

    if (statcache_unlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    }

    destroy_pool(p);
  }

  errno = xerrno;
  return res;
}
#endif /* ProFTPD 1.3.4c or later */

static int statcache_fsio_utimes(pr_fs_t *fs, const char *path,
    struct timeval *tvs) {
  int res, xerrno;

  res = utimes(path, tvs);
  xerrno = errno;

  if (res == 0) {
    int tab_fd;
    const char *canon_path = NULL;
    size_t canon_pathlen = 0;
    pool *p;
    uint32_t hash;

    p = make_sub_pool(statcache_pool);
    pr_pool_tag(p, "statcache_fsio_utimes sub-pool");
    canon_path = statcache_get_canon_path(p, path, &canon_pathlen);
    if (canon_path == NULL) {
      xerrno = errno;

      destroy_pool(p);
      errno = xerrno;
      return res;
    }

    hash = statcache_hash(canon_path, canon_pathlen);
    tab_fd = statcache_tabfh->fh_fd;

    if (statcache_wlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(tab_fd, canon_path, canon_pathlen, hash);

    if (statcache_unlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    }

    destroy_pool(p);
  }

  errno = xerrno;
  return res;
}

static int statcache_fsio_futimes(pr_fh_t *fh, int fd, struct timeval *tvs) {
#ifdef HAVE_FUTIMES
  int res, xerrno;

  /* Check for an ENOSYS errno; if so, fallback to using fsio_utimes.  Some
   * platforms will provide a futimes(2) stub which does not actually do
   * anything.
   */
  res = futimes(fd, tvs);
  xerrno = errno;

  if (res < 0 &&
      xerrno == ENOSYS) {
    return statcache_fsio_utimes(fh->fh_fs, fh->fh_path, tvs);
  }

  if (res == 0) {
    int tab_fd;
    size_t pathlen = 0;
    uint32_t hash;

    pathlen = strlen(fh->fh_path);
    hash = statcache_hash(fh->fh_path, pathlen);
    tab_fd = statcache_tabfh->fh_fd;

    if (statcache_wlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(tab_fd, fh->fh_path, pathlen, hash);

    if (statcache_unlock_row(tab_fd, hash) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }

  errno = xerrno;
  return res;
#else
  return statcache_fsio_utimes(fh->fh_fs, fh->fh_path, tvs);
#endif /* HAVE_FUTIMES */
}

#ifdef PR_USE_CTRLS
/* Controls handlers
 */

static int statcache_handle_statcache(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  /* Check the ban ACL */
  if (!pr_ctrls_check_acl(ctrl, statcache_acttab, "statcache")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */
  if (reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "missing parameters");
    return -1;
  }

  if (statcache_engine != TRUE) {
    pr_ctrls_add_response(ctrl, MOD_STATCACHE_VERSION " not enabled");
    return -1;
  }

  /* Check for options. */
  pr_getopt_reset();

  if (strcmp(reqargv[0], "info") == 0) {
    uint32_t count, highest, hits, misses, expires, rejects;
    float current_usage = 0.0, highest_usage = 0.0, hit_rate = 0.0;

    if (statcache_rlock_stats(statcache_tabfh->fh_fd) < 0) {
      pr_ctrls_add_response(ctrl, "error locking shared memory: %s",
        strerror(errno));
      return -1;
    }

    count = statcache_stats_get_count();
    highest = statcache_stats_get_highest();
    hits = statcache_stats_get_hits();
    misses = statcache_stats_get_misses();
    expires = statcache_stats_get_expires();
    rejects = statcache_stats_get_rejects();

    if (statcache_unlock_stats(statcache_tabfh->fh_fd) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error un-locking shared memory: %s", strerror(errno));
    }

    current_usage = (((float) count / (float) statcache_capacity) * 100.0);
    highest_usage = (((float) highest / (float) statcache_capacity) * 100.0);
    if ((hits + misses) > 0) {
      hit_rate = (((float) hits / (float) (hits + misses)) * 100.0);
    }

    pr_log_debug(DEBUG7, MOD_STATCACHE_VERSION
      ": showing statcache statistics");

    pr_ctrls_add_response(ctrl,
      " hits %lu, misses %lu: %02.1f%% hit rate",
      (unsigned long) hits, (unsigned long) misses, hit_rate);
    pr_ctrls_add_response(ctrl,
      "   expires %lu, rejects %lu", (unsigned long) expires,
      (unsigned long) rejects);
    pr_ctrls_add_response(ctrl, " current count: %lu (of %lu) (%02.1f%% usage)",
      (unsigned long) count, (unsigned long) statcache_capacity, current_usage);
    pr_ctrls_add_response(ctrl, " highest count: %lu (of %lu) (%02.1f%% usage)",
      (unsigned long) highest, (unsigned long) statcache_capacity,
      highest_usage);

  } else if (strcmp(reqargv[0], "dump") == 0) {
    register unsigned int i;
    time_t now;

    if (statcache_rlock_table(statcache_tabfh->fh_fd) < 0) {
      pr_ctrls_add_response(ctrl, "error locking shared memory: %s",
        strerror(errno));
      return -1;
    }

    pr_log_debug(DEBUG7, MOD_STATCACHE_VERSION ": dumping statcache");

    pr_ctrls_add_response(ctrl, "StatCache Contents:");
    now = time(NULL);

    for (i = 0; i < statcache_nrows; i++) {
      register unsigned int j;
      unsigned long row_start;

      pr_ctrls_add_response(ctrl, "  Row %u:", i + 1);
      row_start = (i * statcache_rowlen);

      for (j = 0; j < STATCACHE_COLS_PER_ROW; j++) {
        unsigned long col_start;
        struct statcache_entry *sce;

        pr_signals_handle();

        col_start = (row_start + (j * sizeof(struct statcache_entry)));
        sce = (((char *) statcache_table_data) + col_start);
        if (sce->sce_ts > 0) {
          if (sce->sce_errno == 0) {
            pr_ctrls_add_response(ctrl, "    Col %u: '%s' (%u secs old)",
              j + 1, sce->sce_path, (unsigned int) (now - sce->sce_ts));

          } else {
            pr_ctrls_add_response(ctrl, "    Col %u: '%s' (error: %s)",
              j + 1, sce->sce_path, strerror(sce->sce_errno));
          }

        } else {
          pr_ctrls_add_response(ctrl, "    Col %u: <empty>", j + 1);
        }
      }
    }

    statcache_unlock_table(statcache_tabfh->fh_fd);

  } else {
    pr_ctrls_add_response(ctrl, "unknown statcache action requested: '%s'",
      reqargv[0]);
    return -1;
  }

  return 0;
}

#endif /* PR_USE_CTRLS */

/* Configuration handlers
 */

/* usage: StatCacheCapacity count */
MODRET set_statcachecapacity(cmd_rec *cmd) {
  int capacity;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  capacity = atoi(cmd->argv[1]);
  if (capacity < STATCACHE_COLS_PER_ROW) {
    char str[32];

    memset(str, '\0', sizeof(str));
    pr_snprintf(str, sizeof(str), "%d", (int) STATCACHE_COLS_PER_ROW);
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "parameter must be ", str,
      " or greater", NULL));
  }

  /* Always round UP to the nearest multiple of STATCACHE_COLS_PER_ROW. */
  if (capacity % STATCACHE_COLS_PER_ROW != 0) {
    int factor;

    factor = (capacity / (int) STATCACHE_COLS_PER_ROW);
    capacity = ((factor * (int) STATCACHE_COLS_PER_ROW) +
      (int) STATCACHE_COLS_PER_ROW);
  }

  statcache_capacity = capacity;
  return PR_HANDLED(cmd);
}

/* usage: StatCacheControlsACLs actions|all allow|deny user|group list */
MODRET set_statcachectrlsacls(cmd_rec *cmd) {
#ifdef PR_USE_CTRLS
  char *bad_action = NULL, **actions = NULL;

  CHECK_ARGS(cmd, 4);
  CHECK_CONF(cmd, CONF_ROOT);

  /* We can cheat here, and use the ctrls_parse_acl() routine to
   * separate the given string...
   */
  actions = ctrls_parse_acl(cmd->tmp_pool, cmd->argv[1]);

  /* Check the second parameter to make sure it is "allow" or "deny" */
  if (strcmp(cmd->argv[2], "allow") != 0 &&
      strcmp(cmd->argv[2], "deny") != 0) {
    CONF_ERROR(cmd, "second parameter must be 'allow' or 'deny'");
  }

  /* Check the third parameter to make sure it is "user" or "group" */
  if (strcmp(cmd->argv[3], "user") != 0 &&
      strcmp(cmd->argv[3], "group") != 0) {
    CONF_ERROR(cmd, "third parameter must be 'user' or 'group'");
  }

  bad_action = pr_ctrls_set_module_acls(statcache_acttab, statcache_pool,
    actions, cmd->argv[2], cmd->argv[3], cmd->argv[4]);
  if (bad_action != NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown action: '",
      bad_action, "'", NULL));
  }

  return PR_HANDLED(cmd);
#else
  CONF_ERROR(cmd, "requires Controls support (use --enable-ctrls)");
#endif /* PR_USE_CTRLS */
}

/* usage: StatCacheEngine on|off */
MODRET set_statcacheengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  statcache_engine = engine;

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: StatCacheMaxAge secs */
MODRET set_statcachemaxage(cmd_rec *cmd) {
  int positive_age;

  if (cmd->argc < 2 ||
      cmd->argc > 3) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT);

  positive_age = atoi(cmd->argv[1]);
  if (positive_age <= 0) {
    CONF_ERROR(cmd, "positive-age parameter must be 1 or greater");
  }

  if (cmd->argc == 2) {
    statcache_max_positive_age = statcache_max_negative_age = positive_age;

  } else {
    int negative_age;

    negative_age = atoi(cmd->argv[2]);
    if (negative_age < 0) {
      negative_age = 0;
    }

    statcache_max_positive_age = positive_age;
    statcache_max_negative_age = negative_age;
  }

  return PR_HANDLED(cmd);
}

/* usage: StatCacheTable path */
MODRET set_statcachetable(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  statcache_table_path = pstrdup(statcache_pool, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET statcache_post_pass(cmd_rec *cmd) {
  pr_fs_t *fs;
  const char *proto;

  if (statcache_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Unmount the default/system FS, so that our FS is used for relative
   * paths, too.
   */
  (void) pr_unmount_fs("/", NULL);

  fs = pr_register_fs(statcache_pool, "statcache", "/");
  if (fs == NULL) {
    pr_log_debug(DEBUG3, MOD_STATCACHE_VERSION
      ": error registering 'statcache' fs: %s", strerror(errno));
    statcache_engine = FALSE;
    return PR_DECLINED(cmd);
  }

  /* Add the module's custom FS callbacks here. */
  fs->stat = statcache_fsio_stat;
  fs->fstat = statcache_fsio_fstat;
  fs->lstat = statcache_fsio_lstat;
  fs->rename = statcache_fsio_rename;
  fs->unlink = statcache_fsio_unlink;
  fs->open = statcache_fsio_open;;
  fs->truncate = statcache_fsio_truncate;
  fs->ftruncate = statcache_fsio_ftruncate;
  fs->write = statcache_fsio_write;
  fs->chmod = statcache_fsio_chmod;
  fs->fchmod = statcache_fsio_fchmod;
  fs->chown = statcache_fsio_chown;
  fs->fchown = statcache_fsio_fchown;
#if PROFTPD_VERSION_NUMBER >= 0x0001030407
  fs->lchown = statcache_fsio_lchown;
#endif /* ProFTPD 1.3.4c or later */
  fs->utimes = statcache_fsio_utimes;
  fs->futimes = statcache_fsio_futimes;

  pr_fs_setcwd(pr_fs_getvwd());
  pr_fs_clear_cache();

  pr_event_register(&statcache_module, "fs.statcache.clear",
    statcache_fs_statcache_clear_ev, NULL);

  /* If we are handling an SSH2 session, then we need to disable all
   * negative caching; something about ProFTPD's stat caching interacting
   * with mod_statcache's caching, AND mod_sftp's dispatching through
   * the main FTP handlers, causes unexpected behavior.
   */

  proto = pr_session_get_protocol(0);
  if (strncmp(proto, "ssh2", 5) == 0 ||
      strncmp(proto, "sftp", 5) == 0 ||
      strncmp(proto, "scp", 4) == 0) {
    pr_trace_msg(trace_channel, 9,
      "disabling negative caching for %s protocol", proto);
    statcache_max_negative_age = 0;
  }

  return PR_DECLINED(cmd);
}

#ifdef MADV_WILLNEED
MODRET statcache_pre_list(cmd_rec *cmd) {
  int res;

  if (statcache_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  res = madvise(statcache_table, statcache_tablesz, MADV_WILLNEED);
  if (res < 0) {
    pr_log_debug(DEBUG5, MOD_STATCACHE_VERSION
      ": madvise(2) error with MADV_WILLNEED: %s", strerror(errno));
  }

  return PR_DECLINED(cmd);
}
#endif /* MADV_WILLNEED */

/* Event handlers
 */

static void statcache_fs_statcache_clear_ev(const void *event_data,
    void *user_data) {
  int tab_fd;
  const char *canon_path = NULL, *path;
  size_t canon_pathlen = 0;
  pool *p;
  uint32_t hash;

  path = event_data;
  if (path == NULL) {
    return;
  }

  p = make_sub_pool(statcache_pool);
  pr_pool_tag(p, "statcache_clear_ev sub-pool");
  canon_path = statcache_get_canon_path(p, path, &canon_pathlen);
  if (canon_path == NULL) {
    destroy_pool(p);
    return;
  }

  hash = statcache_hash(canon_path, canon_pathlen);
  tab_fd = statcache_tabfh->fh_fd;

  if (statcache_wlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error write-locking shared memory: %s", strerror(errno));
  }

  pr_trace_msg(trace_channel, 14,
    "removing entry for path '%s' due to event", canon_path);
  (void) statcache_table_remove(tab_fd, canon_path, canon_pathlen, hash);

  if (statcache_unlock_row(tab_fd, hash) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error unlocking shared memory: %s", strerror(errno));
  }

  destroy_pool(p);
}

static void statcache_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer; reinitialize ourselves. */

  pr_event_unregister(&statcache_module, "core.session-reinit",
    statcache_sess_reinit_ev);

  /* Restore defaults */
  statcache_engine = FALSE;

  res = statcache_sess_init();
  if (res < 0) {
    pr_session_disconnect(&statcache_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

static void statcache_shutdown_ev(const void *event_data, void *user_data) {

  /* Remove the mmap from the system.  We can only do this reliably
   * when the standalone daemon process exits; if it's an inetd process,
   * there many be other proftpd processes still running.
   */

  if (getpid() == mpid &&
      ServerType == SERVER_STANDALONE &&
      (statcache_table != NULL && statcache_tabfh->fh_fd >= 0)) {
    int res;

    res = munmap(statcache_table, statcache_tablesz);
    if (res < 0) {
      pr_log_debug(DEBUG1, MOD_STATCACHE_VERSION
        ": error detaching shared memory: %s", strerror(errno));

    } else {
      pr_log_debug(DEBUG7, MOD_STATCACHE_VERSION
        ": detached %lu bytes of shared memory for StatCacheTable '%s'",
        (unsigned long) statcache_tablesz, statcache_table_path);
    }

    res = pr_fsio_close(statcache_tabfh);
    if (res < 0) {
      pr_log_debug(DEBUG1, MOD_STATCACHE_VERSION
        ": error closing StatCacheTable '%s': %s", statcache_table_path,
        strerror(errno));
    }
  }
}

#if defined(PR_SHARED_MODULE)
static void statcache_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_statcache.c", (const char *) event_data) == 0) {
#ifdef PR_USE_CTRLS
    register unsigned int i;

    for (i = 0; statcache_acttab[i].act_action; i++) {
      (void) pr_ctrls_unregister(&statcache_module,
        statcache_acttab[i].act_action);
    }
#endif /* PR_USE_CTRLS */

    pr_event_unregister(&statcache_module, NULL, NULL);

    if (statcache_tabfh) {
      (void) pr_fsio_close(statcache_tabfh);
      statcache_tabfh = NULL;
    }

    if (statcache_pool) {
      destroy_pool(statcache_pool);
      statcache_pool = NULL;
    }

    statcache_engine = FALSE;
  }
}
#endif /* PR_SHARED_MODULE */

static void statcache_postparse_ev(const void *event_data, void *user_data) {
  size_t tablesz;
  void *table;
  int xerrno;
  struct stat st;

  if (statcache_engine == FALSE) {
    return;
  }

  /* Make sure the StatCacheTable exists. */
  if (statcache_table_path == NULL) {
    pr_log_pri(PR_LOG_NOTICE, MOD_STATCACHE_VERSION
      ": missing required StatCacheTable configuration");
    pr_session_disconnect(&statcache_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      NULL);
  }

  PRIVS_ROOT
  statcache_tabfh = pr_fsio_open(statcache_table_path, O_RDWR|O_CREAT);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (statcache_tabfh == NULL) {
    pr_log_pri(PR_LOG_NOTICE, MOD_STATCACHE_VERSION
      ": unable to open StatCacheTable '%s': %s", statcache_table_path,
      strerror(xerrno));
    pr_session_disconnect(&statcache_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      NULL);
  }

  if (pr_fsio_fstat(statcache_tabfh, &st) < 0) {
    xerrno = errno;

    pr_log_pri(PR_LOG_NOTICE, MOD_STATCACHE_VERSION
      ": unable to stat StatCacheTable '%s': %s", statcache_table_path,
      strerror(xerrno));
    pr_fsio_close(statcache_tabfh);
    statcache_tabfh = NULL;
    pr_session_disconnect(&statcache_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      NULL);
  }

  if (S_ISDIR(st.st_mode)) {
    xerrno = EISDIR;

    pr_log_pri(PR_LOG_NOTICE, MOD_STATCACHE_VERSION
      ": unable to stat StatCacheTable '%s': %s", statcache_table_path,
      strerror(xerrno));
    pr_fsio_close(statcache_tabfh);
    statcache_tabfh = NULL;
    pr_session_disconnect(&statcache_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      NULL);
  }

  if (statcache_tabfh->fh_fd <= STDERR_FILENO) {
    int usable_fd;

    usable_fd = pr_fs_get_usable_fd(statcache_tabfh->fh_fd);
    if (usable_fd < 0) {
      pr_log_debug(DEBUG0, MOD_STATCACHE_VERSION
        "warning: unable to find good fd for StatCacheTable %s: %s",
        statcache_table_path, strerror(errno));

    } else {
      close(statcache_tabfh->fh_fd);
      statcache_tabfh->fh_fd = usable_fd;
    }
  } 

  /* The size of the table, in bytes, is:
   *
   *  sizeof(header) + sizeof(data)
   *
   * thus:
   *
   *  header = 6 * sizeof(uint32_t)
   *  data = capacity * sizeof(struct statcache_entry)
   */

  tablesz = (6 * sizeof(uint32_t)) +
    (statcache_capacity * sizeof(struct statcache_entry));

  /* Get the shm for storing all of our stat info. */
  table = statcache_get_shm(statcache_tabfh, tablesz);
  if (table == NULL) {
    pr_log_pri(PR_LOG_NOTICE, MOD_STATCACHE_VERSION
      ": unable to get shared memory for StatCacheTable '%s': %s",
      statcache_table_path, strerror(errno));
    pr_session_disconnect(&statcache_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      NULL);
  }

  pr_trace_msg(trace_channel, 9,
    "allocated %lu bytes of shared memory for %u cache entries",
    (unsigned long) tablesz, statcache_capacity);

  statcache_table = table;
  statcache_tablesz = tablesz;
  statcache_table_stats = statcache_table;
  statcache_table_data = (struct statcache_entry *) (statcache_table + (6 * sizeof(uint32_t)));

  statcache_nrows = (statcache_capacity / STATCACHE_COLS_PER_ROW);
  statcache_rowlen = (STATCACHE_COLS_PER_ROW * sizeof(struct statcache_entry));

  return;
}

static void statcache_restart_ev(const void *event_data, void *user_data) {
#ifdef PR_USE_CTRLS
  register unsigned int i;
#endif /* PR_USE_CTRLS */

  if (statcache_pool) {
    destroy_pool(statcache_pool);
    statcache_pool = NULL;
  }

  statcache_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(statcache_pool, MOD_STATCACHE_VERSION);

#ifdef PR_USE_CTRLS
  /* Register the control handlers */
  for (i = 0; statcache_acttab[i].act_action; i++) {

    /* Allocate and initialize the ACL for this control. */
    statcache_acttab[i].act_acl = pcalloc(statcache_pool, sizeof(ctrls_acl_t));
    pr_ctrls_init_acl(statcache_acttab[i].act_acl);
  }
#endif /* PR_USE_CTRLS */

  /* Close the StatCacheTable file descriptor; it will be reopened by the
   * postparse event listener.
   */
  if (statcache_tabfh != NULL) {
    pr_fsio_close(statcache_tabfh);
    statcache_tabfh = NULL;
  }

  return;
}

/* Initialization routines
 */

static int statcache_init(void) {
#ifdef PR_USE_CTRLS
  register unsigned int i = 0;
#endif /* PR_USE_CTRLS */

  /* Allocate the pool for this module's use. */
  statcache_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(statcache_pool, MOD_STATCACHE_VERSION);

#ifdef PR_USE_CTRLS
  /* Register the control handlers */
  for (i = 0; statcache_acttab[i].act_action; i++) {

    /* Allocate and initialize the ACL for this control. */
    statcache_acttab[i].act_acl = pcalloc(statcache_pool, sizeof(ctrls_acl_t));
    pr_ctrls_init_acl(statcache_acttab[i].act_acl);

    if (pr_ctrls_register(&statcache_module, statcache_acttab[i].act_action,
        statcache_acttab[i].act_desc, statcache_acttab[i].act_cb) < 0) {
      pr_log_pri(PR_LOG_INFO, MOD_STATCACHE_VERSION
        ": error registering '%s' control: %s",
        statcache_acttab[i].act_action, strerror(errno));
    }
  }
#endif /* PR_USE_CTRLS */

#if defined(PR_SHARED_MODULE)
  pr_event_register(&statcache_module, "core.module-unload",
    statcache_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&statcache_module, "core.postparse",
    statcache_postparse_ev, NULL);
  pr_event_register(&statcache_module, "core.restart",
    statcache_restart_ev, NULL);
  pr_event_register(&statcache_module, "core.shutdown",
    statcache_shutdown_ev, NULL);

  return 0;
}

static int statcache_sess_init(void) {
  config_rec *c;

  pr_event_register(&statcache_module, "core.session-reinit",
    statcache_sess_reinit_ev, NULL);

  /* Check to see if the BanEngine directive is set to 'off'. */
  c = find_config(main_server->conf, CONF_PARAM, "StatCacheEngine", FALSE);
  if (c != NULL) {
    statcache_engine = *((int *) c->argv[0]);
  }

  return 0;
}

#ifdef PR_USE_CTRLS

/* Controls table
 */
static ctrls_acttab_t statcache_acttab[] = {
  { "statcache",	"display cache stats", NULL,
    statcache_handle_statcache },

  { NULL, NULL, NULL, NULL }
};
#endif /* PR_USE_CTRLS */

/* Module API tables
 */

static conftable statcache_conftab[] = {
  { "StatCacheCapacity",	set_statcachecapacity,	NULL },
  { "StatCacheControlsACLs",	set_statcachectrlsacls,	NULL },
  { "StatCacheEngine",		set_statcacheengine,	NULL },
  { "StatCacheMaxAge",		set_statcachemaxage,	NULL },
  { "StatCacheTable",		set_statcachetable,	NULL },
  { NULL }
};

static cmdtable statcache_cmdtab[] = {
  { POST_CMD,   C_PASS, G_NONE, statcache_post_pass,	FALSE,	FALSE },

#ifdef MADV_WILLNEED
  /* If the necessary madvise(2) flag is present, register a PRE_CMD
   * handler for directory listings, to suggest to the kernel that
   * it read in some pages of the mmap()'d region.
   */
  { PRE_CMD,	C_LIST,	G_NONE,	statcache_pre_list,	FALSE,	FALSE },
  { PRE_CMD,	C_MLSD,	G_NONE,	statcache_pre_list,	FALSE,	FALSE },
  { PRE_CMD,	C_NLST,	G_NONE,	statcache_pre_list,	FALSE,	FALSE },
#endif /* MADV_WILLNEED */

  { 0, NULL }
};

module statcache_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "statcache",

  /* Module configuration handler table */
  statcache_conftab,

  /* Module command handler table */
  statcache_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  statcache_init,

  /* Session initialization function */
  statcache_sess_init,

  /* Module version */
  MOD_STATCACHE_VERSION
};
