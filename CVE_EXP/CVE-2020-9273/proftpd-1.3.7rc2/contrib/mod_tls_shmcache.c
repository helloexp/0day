/*
 * ProFTPD: mod_tls_shmcache -- a module which provides shared SSL session
 *                              and OCSP response caches using SysV shared
 *                              memory segments
 * Copyright (c) 2009-2017 TJ Saunders
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
 * This is mod_tls_shmcache, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"
#include "mod_tls.h"

#include <sys/ipc.h>
#include <sys/shm.h>

#ifdef HAVE_MLOCK
# include <sys/mman.h>
#endif

/* Define if you have the LibreSSL library.  */
#if defined(LIBRESSL_VERSION_NUMBER)
# define HAVE_LIBRESSL	1
#endif

#define MOD_TLS_SHMCACHE_VERSION		"mod_tls_shmcache/0.2"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030602
# error "ProFTPD 1.3.6rc2 or later required"
#endif

module tls_shmcache_module;

#define TLS_SHMCACHE_SESS_PROJECT_ID		247

/* Assume a maximum SSL session (serialized) length of 10K.  Note that this
 * is different from the SSL_MAX_SSL_SESSION_ID_LENGTH provided by OpenSSL.
 * There is no limit imposed on the length of the ASN1 description of the
 * SSL session data.
 */
#ifndef TLS_MAX_SSL_SESSION_SIZE
# define TLS_MAX_SSL_SESSION_SIZE	1024 * 10
#endif

/* The default number of SSL sessions cached in OpenSSL's internal cache
 * is SSL_SESSION_CACHE_MAX_SIZE_DEFAULT, which is defined as 1024*20.
 * This is NOT a size in _bytes_, but is a size in _counts_ of sessions.
 *
 * Thus the default size of our shm segment should also, in theory, be
 * able to hold the same number of sessions.
 *
 * The recommended default size for Apache's mod_ssl shm segment is 512000
 * bytes (500KB).
 */

struct sesscache_entry {
  time_t expires;
  unsigned int sess_id_len;
  unsigned char sess_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
  unsigned int sess_datalen;
  unsigned char sess_data[TLS_MAX_SSL_SESSION_SIZE];
};

/* The difference between sesscache_entry and sesscache_large_entry is that the
 * buffers in the latter are dynamically allocated from the heap, not
 * allocated out of the shm segment.  The large_entry struct is used for
 * storing sessions which don't fit into the normal entry struct; this also
 * means that these large entries are NOT shared across processes.
 */
struct sesscache_large_entry {
  time_t expires;
  unsigned int sess_id_len;
  const unsigned char *sess_id;
  unsigned int sess_datalen;
  const unsigned char *sess_data;
};

/* The number of entries in the list is determined at run-time, based on
 * the maximum desired size of the shared memory segment.
 */
struct sesscache_data {

  /* Cache metadata. */
  unsigned int nhits;
  unsigned int nmisses;

  unsigned int nstored;
  unsigned int ndeleted;
  unsigned int nexpired;
  unsigned int nerrors;

  /* This tracks the number of sessions that could not be added because
   * they exceeded TLS_MAX_SSL_SESSION_SIZE.
   */
  unsigned int nexceeded;
  unsigned int exceeded_maxsz;

  /* Track the timestamp of the next session to expire in the cache; used
   * as an optimization when flushing the cache of expired sessions.
   */
  time_t next_expiring;

  /* These listlen/listsz track the number of entries in the cache and total
   * entries possible, and thus can be used for determining the fullness of
   * the cache.
   */
  unsigned int sd_listlen, sd_listsz;

  /* It is important that this field be the last in the struct! */
  struct sesscache_entry *sd_entries;
};

static tls_sess_cache_t sess_cache;
static struct sesscache_data *sesscache_data = NULL;
static size_t sesscache_datasz = 0;
static int sesscache_shmid = -1;
static pr_fh_t *sesscache_fh = NULL;
static array_header *sesscache_sess_list = NULL;

#if defined(PR_USE_OPENSSL_OCSP)
# define TLS_SHMCACHE_OCSP_PROJECT_ID		249

/* Assume a maximum OCSP response (serialized) length of 4K.
 */
# ifndef TLS_MAX_OCSP_RESPONSE_SIZE
#  define TLS_MAX_OCSP_RESPONSE_SIZE		1024 * 4
# endif

struct ocspcache_entry {
  time_t age;
  unsigned int fingerprint_len;
  unsigned char fingerprint[EVP_MAX_MD_SIZE];
  unsigned int resp_derlen;
  unsigned char resp_der[TLS_MAX_OCSP_RESPONSE_SIZE];
};

/* The difference between ocspcache_entry and ocspcache_large_entry is that the
 * buffers in the latter are dynamically allocated from the heap, not
 * allocated out of the shm segment.  The large_entry struct is used for
 * storing sessions which don't fit into the normal entry struct; this also
 * means that these large entries are NOT shared across processes.
 */
struct ocspcache_large_entry {
  time_t age;
  unsigned int fingerprint_len;
  unsigned char *fingerprint;
  unsigned int resp_derlen;
  unsigned char *resp_der;
};

/* The number of entries in the list is determined at run-time, based on
 * the maximum desired size of the shared memory segment.
 */
struct ocspcache_data {

  /* Cache metadata. */
  unsigned int nhits;
  unsigned int nmisses;

  unsigned int nstored;
  unsigned int ndeleted;
  unsigned int nexpired;
  unsigned int nerrors;

  /* This tracks the number of sessions that could not be added because
   * they exceeded TLS_MAX_OCSP_RESPONSE_SIZE.
   */
  unsigned int nexceeded;
  unsigned int exceeded_maxsz;

  /* These listlen/listsz track the number of entries in the cache and total
   * entries possible, and thus can be used for determining the fullness of
   * the cache.
   */
  unsigned int od_listlen, od_listsz;

  /* It is important that this field be the last in the struct! */
  struct ocspcache_entry *od_entries;
};

static tls_ocsp_cache_t ocsp_cache;
static struct ocspcache_data *ocspcache_data = NULL;
static size_t ocspcache_datasz = 0;
static int ocspcache_shmid = -1;
static pr_fh_t *ocspcache_fh = NULL;
static array_header *ocspcache_resp_list = NULL;
#endif /* PR_USE_OPENSSL_OCSP */

static const char *trace_channel = "tls.shmcache";

static int sess_cache_close(tls_sess_cache_t *);
#if defined(PR_USE_OPENSSL_OCSP)
static int ocsp_cache_close(tls_ocsp_cache_t *);
#endif /* PR_USE_OPENSSL_OCSP */

static const char *shmcache_get_errors(void) {
  unsigned int count = 0;
  unsigned long error_code;
  BIO *bio = NULL;
  char *data = NULL;
  long datalen;
  const char *error_data = NULL, *str = "(unknown)";
  int error_flags = 0;

  /* Use ERR_print_errors() and a memory BIO to build up a string with
   * all of the error messages from the error queue.
   */

  error_code = ERR_get_error_line_data(NULL, NULL, &error_data, &error_flags);
  if (error_code) {
    bio = BIO_new(BIO_s_mem());
  }

  while (error_code) {
    pr_signals_handle();

    if (error_flags & ERR_TXT_STRING) {
      BIO_printf(bio, "\n  (%u) %s [%s]", ++count,
        ERR_error_string(error_code, NULL), error_data);

    } else {
      BIO_printf(bio, "\n  (%u) %s", ++count,
        ERR_error_string(error_code, NULL));
    }

    error_data = NULL;
    error_flags = 0;
    error_code = ERR_get_error_line_data(NULL, NULL, &error_data, &error_flags);
  }

  datalen = BIO_get_mem_data(bio, &data);
  if (data) {
    data[datalen] = '\0';
    str = pstrdup(permanent_pool, data);
  }

  if (bio != NULL) {
    BIO_free(bio);
  }

  return str;
}

static const char *shmcache_get_lock_desc(int lock_type) {
  const char *lock_desc;

  switch (lock_type) {
    case F_RDLCK:
      lock_desc = "read-lock";
      break;

    case F_WRLCK:
      lock_desc = "write-lock";
      break;

    case F_UNLCK:
      lock_desc = "unlock";
      break;

    default:
      lock_desc = "[unknown]";
  }

  return lock_desc;
}

/* XXX There is anecdotal (and real) evidence that using SysV semaphores
 * is faster than fcntl(2)/flock(3).  However, semaphores are not cleaned up
 * if the process dies tragically.  Could possibly deal with this in an
 * exit event handler, though.  Something to keep in mind.
 */
static int shmcache_lock_shm(pr_fh_t *fh, int lock_type) {
  const char *lock_desc;
  int fd;
  struct flock lock;
  unsigned int nattempts = 1;

  lock.l_type = lock_type;
  lock.l_whence = SEEK_SET;
  lock.l_start = 0;
  lock.l_len = 0;

  fd = PR_FH_FD(fh);
  lock_desc = shmcache_get_lock_desc(lock_type);

  pr_trace_msg(trace_channel, 19, "attempting to %s shmcache fd %d", lock_desc,
    fd);

  while (fcntl(fd, F_SETLK, &lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg(trace_channel, 3, "%s of shmcache fd %d failed: %s",
      lock_desc, fd, strerror(xerrno));
    if (xerrno == EACCES) {
      struct flock locker;

      /* Get the PID of the process blocking this lock. */
      if (fcntl(fd, F_GETLK, &locker) == 0) {
        pr_trace_msg(trace_channel, 3, "process ID %lu has blocking %s on "
          "shmcache fd %d", (unsigned long) locker.l_pid,
          shmcache_get_lock_desc(locker.l_type), fd);
      }

      /* Treat this as an interrupted call, call pr_signals_handle() (which
       * will delay for a few msecs because of EINTR), and try again.
       * After 10 attempts, give up altogether.
       */

      nattempts++;
      if (nattempts <= 10) {
        errno = EINTR;

        pr_signals_handle();
        continue;
      }

      errno = xerrno;
      return -1;
    }

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 19, "%s of shmcache fd %d succeeded", lock_desc,
    fd);
  return 0;
}

/* Use a hash function to hash the given lookup key to a slot in the entries
 * list.  This hash, module the number of entries, is the initial iteration
 * start point.  This will hopefully avoid having to do many linear scans for
 * the add/get/delete operations.
 *
 * Use Perl's hashing algorithm.
 */
static unsigned int shmcache_hash(const unsigned char *id, unsigned int len) {
  unsigned int i = 0;
  size_t sz = len;

  while (sz--) {
    const unsigned char *k = id;
    unsigned int c = *k;
    k++;

    /* Always handle signals in potentially long-running while loops. */
    pr_signals_handle();

    i = (i * 33) + c;
  }

  return i;
}

static void *shmcache_get_shm(pr_fh_t *fh, size_t *shm_size, int project_id,
    int *shm_id) {
  int rem, shm_existed = FALSE, xerrno = 0;
  key_t key;
  void *data = NULL;

  key = ftok(fh->fh_path, project_id);
  if (key == (key_t) -1) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "unable to get key for path '%s': %s", fh->fh_path, strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  /* Round the requested segment size up to the nearest SHMBLA boundary. */
  rem = *shm_size % SHMLBA;
  if (rem != 0) {
    *shm_size = (*shm_size - rem + SHMLBA);
    pr_trace_msg(trace_channel, 9,
      "rounded requested size up to %lu bytes", (unsigned long) *shm_size);
  }

  /* Try first using IPC_CREAT|IPC_EXCL, to check if there is an existing
   * shm for this key.  If so, use a flags value of zero.
   *
   * We use root privs for this, to make sure that the shm can only be
   * access by a process with root privs.  This is equivalent to having
   * a root-owned file in the filesystem.  We need to protect the sensitive
   * session data (which contains master keys and such) from prying eyes.
   */

  PRIVS_ROOT
  *shm_id = shmget(key, *shm_size, IPC_CREAT|IPC_EXCL|0600);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (*shm_id < 0) {
    if (xerrno == EEXIST) {
      shm_existed = TRUE;

      PRIVS_ROOT
      *shm_id = shmget(key, 0, 0);
      xerrno = errno;
      PRIVS_RELINQUISH

      if (*shm_id < 0) {
        pr_trace_msg(trace_channel, 1,
          "unable to get shm for existing key: %s", strerror(xerrno));
        errno = xerrno;
        return NULL;
      }

    } else {
      /* Try to provide more helpful/informative log messages. */
      if (xerrno == ENOMEM) {
        pr_trace_msg(trace_channel, 1,
          "not enough memory for %lu shm bytes; try specifying a smaller size",
          (unsigned long) *shm_size);

      } else if (xerrno == ENOSPC) {
        pr_trace_msg(trace_channel, 1, "%s",
          "unable to allocate a new shm ID; system limit of shm IDs reached");
      }

      errno = xerrno;
      return NULL;
    }
  }

  /* Attach to the shm. */
  pr_trace_msg(trace_channel, 10, "attempting to attach to shm ID %d",
    *shm_id);

  PRIVS_ROOT
  data = shmat(*shm_id, NULL, 0);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (data == NULL) {
    pr_trace_msg(trace_channel, 1,
      "unable to attach to shm ID %d: %s", *shm_id, strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  if (shm_existed) {
    struct shmid_ds ds;
    int res;

    /* If we already have a shmid, check for size differences; the admin
     * may have configured a larger/smaller cache size.  Use shmctl(IP_STAT)
     * to determine the existing segment size.
     */

    PRIVS_ROOT
    res = shmctl(*shm_id, IPC_STAT, &ds);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res == 0) {
      pr_trace_msg(trace_channel, 10,
        "existing shm size: %u bytes", (unsigned int) ds.shm_segsz);

      if ((unsigned long) ds.shm_segsz != (unsigned long) *shm_size) {
        if ((unsigned long) ds.shm_segsz > (unsigned long) *shm_size) {
          pr_log_pri(PR_LOG_NOTICE, MOD_TLS_SHMCACHE_VERSION
            ": requested shm size (%lu bytes) is smaller than existing shm "
            "size, migrating to smaller shm (may result in loss of cache data)",
            (unsigned long) *shm_size);

        } else if ((unsigned long) ds.shm_segsz < (unsigned long) *shm_size) {
          pr_log_pri(PR_LOG_NOTICE, MOD_TLS_SHMCACHE_VERSION
            ": requested shm size (%lu bytes) is larger than existing shm "
            "size, migrating to larger shm", (unsigned long) *shm_size);
        }

        pr_log_pri(PR_LOG_NOTICE, MOD_TLS_SHMCACHE_VERSION
          ": remove existing shmcache using 'ftpdctl tls sesscache remove' "
          "or 'ftpdctl tls ocspcache remove' before using new size");

        errno = EEXIST;
        return NULL;
      }

    } else {
      pr_trace_msg(trace_channel, 1,
        "unable to stat shm ID %d: %s", *shm_id, strerror(xerrno));
      errno = xerrno;
    }

  } else {
    /* Make sure the memory is initialized. */
    if (shmcache_lock_shm(fh, F_WRLCK) < 0) {
      pr_trace_msg(trace_channel, 1, "error write-locking shm: %s",
        strerror(errno));
    }

    memset(data, 0, *shm_size);

    if (shmcache_lock_shm(fh, F_UNLCK) < 0) {
      pr_trace_msg(trace_channel, 1, "error unlocking shm: %s",
        strerror(errno));
    }
  }

  return data;
}

static struct sesscache_data *sess_cache_get_shm(pr_fh_t *fh,
    size_t requested_size) {
  int shmid, xerrno = 0;
  struct sesscache_data *data = NULL;
  size_t shm_size;
  unsigned int shm_sess_max = 0;

  /* Calculate the size to allocate.  First, calculate the maximum number
   * of sessions we can cache, given the configured size.  Then
   * calculate the shm segment size to allocate to hold that number of
   * sessions.
   */
  shm_sess_max = (requested_size - sizeof(struct sesscache_data)) /
    (sizeof(struct sesscache_entry));
  shm_size = sizeof(struct sesscache_data) +
    (shm_sess_max * sizeof(struct sesscache_entry));

  data = shmcache_get_shm(fh, &shm_size, TLS_SHMCACHE_SESS_PROJECT_ID, &shmid);
  if (data == NULL) {
    xerrno = errno;

    if (errno == EEXIST) {
      sess_cache_close(NULL);
    }

    errno = xerrno;
    return NULL;
  }

  sesscache_datasz = shm_size;
  sesscache_shmid = shmid;
  pr_trace_msg(trace_channel, 9,
    "using shm ID %d for sesscache path '%s' (%u sessions)", sesscache_shmid,
    fh->fh_path, shm_sess_max);

  data->sd_entries = (struct sesscache_entry *) (data + sizeof(struct sesscache_data));
  data->sd_listsz = shm_sess_max;

  return data;
}

#if defined(PR_USE_OPENSSL_OCSP)
static struct ocspcache_data *ocsp_cache_get_shm(pr_fh_t *fh,
    size_t requested_size) {
  int shmid, xerrno = 0;
  struct ocspcache_data *data = NULL;
  size_t shm_size;
  unsigned int shm_resp_max = 0;

  /* Calculate the size to allocate.  First, calculate the maximum number
   * of responses we can cache, given the configured size.  Then
   * calculate the shm segment size to allocate to hold that number of
   * responses.
   */
  shm_resp_max = (requested_size - sizeof(struct ocspcache_data)) /
    (sizeof(struct ocspcache_entry));
  shm_size = sizeof(struct ocspcache_data) +
    (shm_resp_max * sizeof(struct ocspcache_entry));

  data = shmcache_get_shm(fh, &shm_size, TLS_SHMCACHE_OCSP_PROJECT_ID, &shmid);
  if (data == NULL) {
    xerrno = errno;

    if (errno == EEXIST) {
      ocsp_cache_close(NULL);
    }

    errno = xerrno;
    return NULL;
  }

  ocspcache_datasz = shm_size;
  ocspcache_shmid = shmid;
  pr_trace_msg(trace_channel, 9,
    "using shm ID %d for ocspcache path '%s' (%u responses)", ocspcache_shmid,
    fh->fh_path, shm_resp_max);

  data->od_entries = (struct ocspcache_entry *) (data + sizeof(struct ocspcache_data));
  data->od_listsz = shm_resp_max;

  return data;
}
#endif /* PR_USE_OPENSSL_OCSP */

/* SSL session cache implementation callbacks.
 */

/* Scan the entire list, clearing out expired sessions.  Logs the number
 * of sessions that expired and updates the header stat.
 *
 * NOTE: Callers are assumed to handle the locking of the shm before/after
 * calling this function!
 */
static unsigned int sess_cache_flush(void) {
  register unsigned int i;
  unsigned int flushed = 0;
  time_t now, next_expiring = 0;

  now = time(NULL);

  /* We always scan the in-memory large session entry list. */
  if (sesscache_sess_list != NULL) {
    struct sesscache_large_entry *entries;

    entries = sesscache_sess_list->elts;
    for (i = 0; i < sesscache_sess_list->nelts; i++) {
      struct sesscache_large_entry *entry;

      entry = &(entries[i]);

      if (entry->expires > now) {
        /* This entry has expired; clear its slot. */
        entry->expires = 0;
        pr_memscrub((void *) entry->sess_data, entry->sess_datalen);
      }
    }
  }

  /* If now is earlier than the earliest expiring session in the cache,
   * then a scan will be pointless.
   */
  if (now < sesscache_data->next_expiring) {
    unsigned int secs;

    secs = sesscache_data->next_expiring - now;
    tls_log("shmcache: no expired sessions to flush; %u secs to next "
      "expiration", secs);
    return 0;
  }

  tls_log("shmcache: flushing session cache of expired sessions");

  for (i = 0; i < sesscache_data->sd_listsz; i++) {
    struct sesscache_entry *entry;

    entry = &(sesscache_data->sd_entries[i]);
    if (entry->expires > 0) {
      if (entry->expires > now) {
        if (entry->expires < next_expiring) {
          next_expiring = entry->expires;
        }

      } else {
        /* This entry has expired; clear its slot. */
        entry->expires = 0;
        pr_memscrub((void *) entry->sess_data, entry->sess_datalen);

        /* Don't forget to update the stats. */
        sesscache_data->nexpired++;

        if (sesscache_data->sd_listlen > 0) {
          sesscache_data->sd_listlen--;
        }

        flushed++;
      }
    }

    sesscache_data->next_expiring = next_expiring;
  }

  tls_log("shmcache: flushed %u expired %s from session cache", flushed,
    flushed != 1 ? "sessions" : "session");
  return flushed;
}

static int sess_cache_open(tls_sess_cache_t *cache, char *info, long timeout) {
  int fd, xerrno;
  char *ptr;
  size_t requested_size;
  struct stat st;

  pr_trace_msg(trace_channel, 9, "opening shmcache session cache %p", cache);

  /* The info string must be formatted like:
   *
   *  /path=%s[&size=%u]
   *
   * where the optional size is in bytes.  There is a minimum size; if the
   * configured size is less than the minimum, it's an error.  The default
   * size (when no size is explicitly configured) is, of course, larger than
   * the minimum size.
   */

  if (strncmp(info, "/file=", 6) != 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_SHMCACHE_VERSION
      ": badly formatted info '%s', unable to open shmcache", info);
    errno = EINVAL;
    return -1;
  }

  info += 6;

  /* Check for the optional size parameter. */
  ptr = strchr(info, '&');
  if (ptr != NULL) {
    if (strncmp(ptr + 1, "size=", 5) == 0) {
      char *tmp = NULL;
      long size; 

      size = strtol(ptr + 6, &tmp, 10);
      if (tmp && *tmp) {
        pr_trace_msg(trace_channel, 1,
          "badly formatted size parameter '%s', ignoring", ptr + 1);

        /* Default size of 1.5M.  That should hold around 100 sessions. */
        requested_size = 1538 * 1024;

      } else {
        size_t min_size;

        /* The bare minimum size MUST be able to hold at least one session. */
        min_size = sizeof(struct sesscache_data) +
          sizeof(struct sesscache_entry);

        if ((size_t) size < min_size) {
          pr_trace_msg(trace_channel, 1,
            "requested size (%lu bytes) smaller than minimum size "
            "(%lu bytes), ignoring", (unsigned long) size,
            (unsigned long) min_size);
        
          /* Default size of 1.5M.  That should hold around 100 sessions. */
          requested_size = 1538 * 1024;

        } else {
          requested_size = size;
        }
      }

    } else {
      pr_trace_msg(trace_channel, 1, 
        "badly formatted size parameter '%s', ignoring", ptr + 1);

      /* Default size of 1.5M.  That should hold around 100 sessions. */
      requested_size = 1538 * 1024;
    }

    *ptr = '\0';

  } else {
    /* Default size of 1.5M.  That should hold around 100 sessions. */
    requested_size = 1538 * 1024;
  }

  /* We could change the cache_mode flags here, based on the given
   * info, if needs be.
   */

  if (pr_fs_valid_path(info) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_SHMCACHE_VERSION
      ": file '%s' not an absolute path", info);

    errno = EINVAL;
    return -1;
  }

  /* If sesscache_fh is not null, then we are a restarted server.  And if
   * the 'info' path does not match that previous fh, then the admin
   * has changed the configuration.
   *
   * For now, we complain about this, and tell the admin to manually remove
   * the old file/shm.
   */
  if (sesscache_fh != NULL &&
      strcmp(sesscache_fh->fh_path, info) != 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_SHMCACHE_VERSION
      ": file '%s' does not match previously configured file '%s'",
      info, sesscache_fh->fh_path);
    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_SHMCACHE_VERSION
      ": remove existing shmcache using 'ftpdctl tls sesscache remove' "
      "before using new file");

    errno = EINVAL;
    return -1;
  }

  PRIVS_ROOT
  sesscache_fh = pr_fsio_open(info, O_RDWR|O_CREAT);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (sesscache_fh == NULL) {
    pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
      ": error: unable to open file '%s': %s", info, strerror(xerrno));

    errno = EINVAL;
    return -1;
  }

  if (pr_fsio_fstat(sesscache_fh, &st) < 0) {
    xerrno = errno;

    pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
      ": error: unable to stat file '%s': %s", info, strerror(xerrno));

    pr_fsio_close(sesscache_fh);
    sesscache_fh = NULL;

    errno = EINVAL;
    return -1;
  }

  if (S_ISDIR(st.st_mode)) {
    xerrno = EISDIR;

    pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
      ": error: unable to use file '%s': %s", info, strerror(xerrno));

    pr_fsio_close(sesscache_fh);
    sesscache_fh = NULL;
    
    errno = EINVAL;
    return -1;
  }

  /* Make sure that we don't inadvertently get one of the Big Three file
   * descriptors (stdin/stdout/stderr), as can happen especially if the
   * server has restarted.
   */
  fd = PR_FH_FD(sesscache_fh);
  if (fd <= STDERR_FILENO) {
    int res;

    res = pr_fs_get_usable_fd(fd);
    if (res < 0) { 
      pr_log_debug(DEBUG0,
        "warning: unable to find good fd for shmcache fd %d: %s",
        fd, strerror(errno));
 
    } else {
      close(fd);
      PR_FH_FD(sesscache_fh) = res;
    }
  }

  pr_trace_msg(trace_channel, 9,
    "requested session cache file: %s (fd %d)", sesscache_fh->fh_path,
    PR_FH_FD(sesscache_fh));
  pr_trace_msg(trace_channel, 9, 
    "requested session cache size: %lu bytes", (unsigned long) requested_size);

  sesscache_data = sess_cache_get_shm(sesscache_fh, requested_size);
  if (sesscache_data == NULL) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "unable to allocate session shm: %s", strerror(xerrno));
    pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
      ": unable to allocate session shm: %s", strerror(xerrno));

    pr_fsio_close(sesscache_fh);
    sesscache_fh = NULL;

    errno = EINVAL;
    return -1;
  }

  cache->cache_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(cache->cache_pool, MOD_TLS_SHMCACHE_VERSION);

  cache->cache_timeout = timeout;
  return 0;
}

static int sess_cache_close(tls_sess_cache_t *cache) {

  if (cache != NULL) {
    pr_trace_msg(trace_channel, 9, "closing shmcache session cache %p", cache);
  }

  if (cache != NULL &&
      cache->cache_pool != NULL) {
    destroy_pool(cache->cache_pool);

    if (sesscache_sess_list != NULL) {
      register unsigned int i;
      struct sesscache_large_entry *entries;

      entries = sesscache_sess_list->elts;
      for (i = 0; i < sesscache_sess_list->nelts; i++) {
        struct sesscache_large_entry *entry;

        entry = &(entries[i]);
        if (entry->expires > 0) {
          pr_memscrub((void *) entry->sess_data, entry->sess_datalen);
        }
      }

      sesscache_sess_list = NULL;
    }
  }

  if (sesscache_shmid >= 0) {
    int res, xerrno = 0;

    PRIVS_ROOT
#if !defined(_POSIX_SOURCE)
    res = shmdt((char *) sesscache_data);
#else
    res = shmdt((const char *) sesscache_data);
#endif
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res < 0) {
      pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
        ": error detaching session shm ID %d: %s", sesscache_shmid,
        strerror(xerrno));
    }

    sesscache_data = NULL;
  }

  pr_fsio_close(sesscache_fh);
  sesscache_fh = NULL;
  return 0;
}

static int sess_cache_add_large_sess(tls_sess_cache_t *cache,
    const unsigned char *sess_id, unsigned int sess_id_len, time_t expires,
    SSL_SESSION *sess, int sess_len) {
  struct sesscache_large_entry *entry = NULL;

  if (sess_len > TLS_MAX_SSL_SESSION_SIZE) {
    /* We may get sessions to add to the list which do not exceed the max
     * size, but instead are here because we couldn't get the lock on the
     * shmcache.  Don't track these in the 'exceeded' stats'.
     */

    if (shmcache_lock_shm(sesscache_fh, F_WRLCK) == 0) {
      sesscache_data->nexceeded++;
      if ((size_t) sess_len > sesscache_data->exceeded_maxsz) {
        sesscache_data->exceeded_maxsz = sess_len;
      }

      if (shmcache_lock_shm(sesscache_fh, F_UNLCK) < 0) {
        tls_log("shmcache: error unlocking shmcache: %s", strerror(errno));
      }

    } else {
      tls_log("shmcache: error write-locking shmcache: %s", strerror(errno));
    }
  }

  if (sesscache_sess_list != NULL) {
    register unsigned int i;
    struct sesscache_large_entry *entries;
    time_t now;

    /* Look for any expired sessions in the list to overwrite/reuse. */
    entries = sesscache_sess_list->elts;
    now = time(NULL);
    for (i = 0; i < sesscache_sess_list->nelts; i++) {
      entry = &(entries[i]);

      if (entry->expires > now) {
        /* This entry has expired; clear and reuse its slot. */
        entry->expires = 0;
        pr_memscrub((void *) entry->sess_data, entry->sess_datalen);

        break;
      }
    }

  } else {
    sesscache_sess_list = make_array(cache->cache_pool, 1,
      sizeof(struct sesscache_large_entry));
    entry = push_array(sesscache_sess_list);
  }

  /* Be defensive, and catch the case where entry might still be null here. */
  if (entry == NULL) {
    errno = EPERM;
    return -1;
  }

  entry->expires = expires;
  entry->sess_id_len = sess_id_len;
  entry->sess_id = palloc(cache->cache_pool, sess_id_len);
  memcpy((char *) entry->sess_id, sess_id, sess_id_len);
  entry->sess_datalen = sess_len;
  entry->sess_data = palloc(cache->cache_pool, sess_len);
  i2d_SSL_SESSION(sess, (unsigned char **) &(entry->sess_data));

  return 0;
}

static int sess_cache_add(tls_sess_cache_t *cache, const unsigned char *sess_id,
    unsigned int sess_id_len, time_t expires, SSL_SESSION *sess) {
  register unsigned int i;
  unsigned int h, idx, last;
  int found_slot = FALSE, need_lock = TRUE, res = 0, sess_len;

  pr_trace_msg(trace_channel, 9, "adding session to shmcache session cache %p",
    cache);

  /* First we need to find out how much space is needed for the serialized
   * session data.  There is no known maximum size for SSL session data;
   * this module is currently designed to allow only up to a certain size.
   */
  sess_len = i2d_SSL_SESSION(sess, NULL);
  if (sess_len > TLS_MAX_SSL_SESSION_SIZE) {
    tls_log("shmcache: length of serialized SSL session data (%d) exceeds "
      "maximum size (%u), unable to add to shared shmcache, adding to list",
      sess_len, TLS_MAX_SSL_SESSION_SIZE);

    /* Instead of rejecting the add here, we add the session to a "large
     * session" list.  Thus the large session would still be cached per process
     * and will not be lost.
     *
     * XXX We should also track how often this happens, and possibly trigger
     * a shmcache resize (using a larger record size, vs larger cache size)
     * so that we can cache these large records in the shm segment.
     */

    return sess_cache_add_large_sess(cache, sess_id, sess_id_len, expires,
      sess, sess_len);
  }

  if (sesscache_data->sd_listlen == sesscache_data->sd_listsz) {
    /* It appears that the cache is full.  Try flushing any expired
     * sessions.
     */

    if (shmcache_lock_shm(sesscache_fh, F_WRLCK) == 0) {
      if (sess_cache_flush() > 0) {
        /* If we made room, then do NOT release the lock; we keep the lock
         * so that we can add the session.
         */
        need_lock = FALSE;

      } else {
        /* Release the lock, and use the "large session" list fallback. */
        if (shmcache_lock_shm(sesscache_fh, F_UNLCK) < 0) {
          tls_log("shmcache: error unlocking shmcache: %s", strerror(errno));
        }

        return sess_cache_add_large_sess(cache, sess_id, sess_id_len, expires,
          sess, sess_len);
      }

    } else {
      tls_log("shmcache: unable to flush shm cache: error write-locking "
        "shmcache: %s", strerror(errno));

      /* Add this session to the "large session" list instead as a fallback. */
      return sess_cache_add_large_sess(cache, sess_id, sess_id_len, expires,
        sess, sess_len);
    }
  }

  /* Hash the key, start looking for an open slot. */
  h = shmcache_hash(sess_id, sess_id_len);
  idx = h % sesscache_data->sd_listsz;

  if (need_lock) {
    if (shmcache_lock_shm(sesscache_fh, F_WRLCK) < 0) {
      tls_log("shmcache: unable to add session to shm cache: error "
        "write-locking shmcache: %s", strerror(errno));

      /* Add this session to the "large session" list instead as a fallback. */
      return sess_cache_add_large_sess(cache, sess_id, sess_id_len, expires,
        sess, sess_len);
    }
  }

  i = idx;
  last = idx > 0 ? (idx - 1) : 0;

  do {
    struct sesscache_entry *entry;

    pr_signals_handle();

    /* Look for the first open slot (i.e. expires == 0). */
    entry = &(sesscache_data->sd_entries[i]);
    if (entry->expires == 0) {
      unsigned char *ptr;

      entry->expires = expires;
      entry->sess_id_len = sess_id_len;
      memcpy(entry->sess_id, sess_id, sess_id_len);
      entry->sess_datalen = sess_len;

      ptr = entry->sess_data;
      i2d_SSL_SESSION(sess, &ptr);

      sesscache_data->sd_listlen++;
      sesscache_data->nstored++;

      if (sesscache_data->next_expiring > 0) {
        if (expires < sesscache_data->next_expiring) {
          sesscache_data->next_expiring = expires;
        }

      } else {
        sesscache_data->next_expiring = expires;
      }

      found_slot = TRUE;
      break;
    }

    if (i < sesscache_data->sd_listsz) {
      i++;

    } else {
      i = 0;
    }

  } while (i != last);

  /* There is a race condition possible between the open slots check
   * above and the scan through the slots.  So if we didn't actually find
   * an open slot at this point, add it to the "large session" list.
   */
  if (!found_slot) {
    res = sess_cache_add_large_sess(cache, sess_id, sess_id_len, expires, sess,
      sess_len);
  }

  if (need_lock) {
    if (shmcache_lock_shm(sesscache_fh, F_UNLCK) < 0) {
      tls_log("shmcache: error unlocking shmcache: %s", strerror(errno));
    }
  }

  return res;
}

static SSL_SESSION *sess_cache_get(tls_sess_cache_t *cache,
    const unsigned char *sess_id, unsigned int sess_id_len) {
  unsigned int h, idx;
  SSL_SESSION *sess = NULL;

  pr_trace_msg(trace_channel, 9,
    "getting session from shmcache session cache %p", cache);

  /* Look for the requested session in the "large session" list first. */
  if (sesscache_sess_list != NULL) {
    register unsigned int i;
    struct sesscache_large_entry *entries;

    entries = sesscache_sess_list->elts;
    for (i = 0; i < sesscache_sess_list->nelts; i++) {
      struct sesscache_large_entry *entry;

      entry = &(entries[i]);
      if (entry->expires > 0 &&
          entry->sess_id_len == sess_id_len &&
          memcmp(entry->sess_id, sess_id, entry->sess_id_len) == 0) {
        time_t now;

        now = time(NULL);
        if (entry->expires <= now) {
          TLS_D2I_SSL_SESSION_CONST unsigned char *ptr;

          ptr = entry->sess_data;
          sess = d2i_SSL_SESSION(NULL, &ptr, entry->sess_datalen);
          if (sess == NULL) {
            tls_log("shmcache: error retrieving session from session cache: %s",
              shmcache_get_errors());

          } else {
            break;
          }
        }
      }
    }
  }

  if (sess) {
    return sess;
  }

  h = shmcache_hash(sess_id, sess_id_len);
  idx = h % sesscache_data->sd_listsz;

  if (shmcache_lock_shm(sesscache_fh, F_WRLCK) == 0) {
    register unsigned int i;
    unsigned int last;

    i = idx;
    last = idx > 0 ? (idx -1) : 0;

    do {
      struct sesscache_entry *entry;

      pr_signals_handle();

      entry = &(sesscache_data->sd_entries[i]);
      if (entry->expires > 0 &&
          entry->sess_id_len == sess_id_len &&
          memcmp(entry->sess_id, sess_id, entry->sess_id_len) == 0) {
        time_t now;

        /* Don't forget to update the stats. */
        now = time(NULL);

        if (entry->expires > now) {
          TLS_D2I_SSL_SESSION_CONST unsigned char *ptr;

          ptr = entry->sess_data;
          sess = d2i_SSL_SESSION(NULL, &ptr, entry->sess_datalen);
          if (sess != NULL) {
            sesscache_data->nhits++;

          } else {
            tls_log("shmcache: error retrieving session from session cache: %s",
              shmcache_get_errors());
            sesscache_data->nerrors++;
          }
        }

        break;
      }

      if (i < sesscache_data->sd_listsz) {
        i++;

      } else {
        i = 0;
      }

    } while (i != last);

    if (sess == NULL) {
      sesscache_data->nmisses++;
      errno = ENOENT;
    }

    if (shmcache_lock_shm(sesscache_fh, F_UNLCK) < 0) {
      tls_log("shmcache: error unlocking shmcache: %s", strerror(errno));
    }

  } else {
    tls_log("shmcache: unable to retrieve session from session cache: error "
      "write-locking shmcache: %s", strerror(errno));

    errno = EPERM;
  }

  return sess;
}

static int sess_cache_delete(tls_sess_cache_t *cache,
    const unsigned char *sess_id, unsigned int sess_id_len) {
  unsigned int h, idx;
  int res;

  pr_trace_msg(trace_channel, 9,
    "removing session from shmcache session cache %p", cache);

  /* Look for the requested session in the "large session" list first. */
  if (sesscache_sess_list != NULL) {
    register unsigned int i;
    struct sesscache_large_entry *entries;

    entries = sesscache_sess_list->elts;
    for (i = 0; i < sesscache_sess_list->nelts; i++) {
      struct sesscache_large_entry *entry;

      entry = &(entries[i]);
      if (entry->sess_id_len == sess_id_len &&
          memcmp(entry->sess_id, sess_id, entry->sess_id_len) == 0) {

        pr_memscrub((void *) entry->sess_data, entry->sess_datalen);
        entry->expires = 0;
        return 0;
      }
    }
  }

  h = shmcache_hash(sess_id, sess_id_len);
  idx = h % sesscache_data->sd_listsz;

  if (shmcache_lock_shm(sesscache_fh, F_WRLCK) == 0) {
    register unsigned int i;
    unsigned int last;

    i = idx;
    last = idx > 0 ? (idx - 1) : 0;

    do {
      struct sesscache_entry *entry;

      pr_signals_handle();

      entry = &(sesscache_data->sd_entries[i]);
      if (entry->sess_id_len == sess_id_len &&
          memcmp(entry->sess_id, sess_id, entry->sess_id_len) == 0) {
        time_t now;

        pr_memscrub((void *) entry->sess_data, entry->sess_datalen);

        if (sesscache_data->sd_listlen > 0) {
          sesscache_data->sd_listlen--;
        }

        /* Don't forget to update the stats. */
        now = time(NULL);
        if (entry->expires > now) {
          sesscache_data->ndeleted++;

        } else {
          sesscache_data->nexpired++;
        }

        entry->expires = 0;
        break;
      }

      if (i < sesscache_data->sd_listsz) {
        i++;

      } else {
        i = 0;
      }

    } while (i != last);

    if (shmcache_lock_shm(sesscache_fh, F_UNLCK) < 0) {
      tls_log("shmcache: error unlocking shmcache: %s", strerror(errno));
    }

    res = 0;

  } else {
    tls_log("shmcache: unable to delete session from session cache: error "
      "write-locking shmcache: %s", strerror(errno));

    errno = EPERM;
    res = -1;
  }

  return res;
}

static int sess_cache_clear(tls_sess_cache_t *cache) {
  register unsigned int i;
  int res;

  pr_trace_msg(trace_channel, 9, "clearing shmcache session cache %p", cache);

  if (sesscache_shmid < 0) {
    errno = EINVAL;
    return -1;
  }

  if (sesscache_sess_list != NULL) {
    struct sesscache_large_entry *entries;
    
    entries = sesscache_sess_list->elts;
    for (i = 0; i < sesscache_sess_list->nelts; i++) {
      struct sesscache_large_entry *entry;

      entry = &(entries[i]);
      entry->expires = 0;
      pr_memscrub((void *) entry->sess_data, entry->sess_datalen);
    }
  }

  if (shmcache_lock_shm(sesscache_fh, F_WRLCK) < 0) {
    tls_log("shmcache: unable to clear cache: error write-locking shmcache: %s",
      strerror(errno));
    return -1;
  }

  for (i = 0; i < sesscache_data->sd_listsz; i++) {
    struct sesscache_entry *entry;

    entry = &(sesscache_data->sd_entries[i]);

    entry->expires = 0;
    pr_memscrub((void *) entry->sess_data, entry->sess_datalen);
  }

  res = sesscache_data->sd_listlen; 
  sesscache_data->sd_listlen = 0;

  if (shmcache_lock_shm(sesscache_fh, F_UNLCK) < 0) {
    tls_log("shmcache: error unlocking shmcache: %s", strerror(errno));
  }

  return res;
}

static int sess_cache_remove(tls_sess_cache_t *cache) {
  int res;
  struct shmid_ds ds;
  const char *cache_file;

  if (sesscache_fh == NULL) {
    return 0;
  }

  if (cache != NULL) {
    pr_trace_msg(trace_channel, 9, "removing shmcache session cache %p",
      cache);
  }

  cache_file = sesscache_fh->fh_path;
  (void) sess_cache_close(cache);

  if (sesscache_shmid < 0) {
    errno = EINVAL;
    return -1;
  }

  pr_log_debug(DEBUG9, MOD_TLS_SHMCACHE_VERSION
    ": attempting to remove session cache shm ID %d", sesscache_shmid);

  PRIVS_ROOT
  res = shmctl(sesscache_shmid, IPC_RMID, &ds);
  PRIVS_RELINQUISH

  if (res < 0) {
    pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
      ": error removing session cache shm ID %d: %s", sesscache_shmid,
      strerror(errno));

  } else {
    pr_log_debug(DEBUG9, MOD_TLS_SHMCACHE_VERSION
      ": removed session cache shm ID %d", sesscache_shmid);
    sesscache_shmid = -1;
  }

  /* Don't forget to remove the on-disk file as well. */
  unlink(cache_file);

  return res;
}

static int sess_cache_status(tls_sess_cache_t *cache,
    void (*statusf)(void *, const char *, ...), void *arg, int flags) {
  int res, xerrno = 0;
  struct shmid_ds ds;
  pool *tmp_pool;

  pr_trace_msg(trace_channel, 9, "checking shmcache session cache %p", cache);

  if (shmcache_lock_shm(sesscache_fh, F_RDLCK) < 0) {
    pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
      ": error read-locking shmcache: %s", strerror(errno));
    return -1;
  }

  tmp_pool = make_sub_pool(permanent_pool);

  statusf(arg, "%s", "Shared memory (shm) SSL session cache provided by "
    MOD_TLS_SHMCACHE_VERSION);
  statusf(arg, "%s", "");
  statusf(arg, "Shared memory segment ID: %d", sesscache_shmid);

  PRIVS_ROOT
  res = shmctl(sesscache_shmid, IPC_STAT, &ds);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (res == 0) {
    statusf(arg, "Shared memory segment size: %u bytes",
      (unsigned int) ds.shm_segsz);
    statusf(arg, "Shared memory cache created on: %s",
      pr_strtime(ds.shm_ctime));
    statusf(arg, "Shared memory attach count: %u",
      (unsigned int) ds.shm_nattch);

  } else {
    statusf(arg, "Unable to stat shared memory segment ID %d: %s",
      sesscache_shmid, strerror(xerrno));
  } 

  statusf(arg, "%s", "");
  statusf(arg, "Max session cache size: %u", sesscache_data->sd_listsz);
  statusf(arg, "Current session cache size: %u", sesscache_data->sd_listlen);
  statusf(arg, "%s", "");
  statusf(arg, "Cache lifetime hits: %u", sesscache_data->nhits);
  statusf(arg, "Cache lifetime misses: %u", sesscache_data->nmisses);
  statusf(arg, "%s", "");
  statusf(arg, "Cache lifetime sessions stored: %u", sesscache_data->nstored);
  statusf(arg, "Cache lifetime sessions deleted: %u", sesscache_data->ndeleted);
  statusf(arg, "Cache lifetime sessions expired: %u", sesscache_data->nexpired);
  statusf(arg, "%s", "");
  statusf(arg, "Cache lifetime errors handling sessions in cache: %u",
    sesscache_data->nerrors);
  statusf(arg, "Cache lifetime sessions exceeding max entry size: %u",
    sesscache_data->nexceeded);
  if (sesscache_data->nexceeded > 0) {
    statusf(arg, "  Largest session exceeding max entry size: %u",
      sesscache_data->exceeded_maxsz);
  }

  if (flags & TLS_SESS_CACHE_STATUS_FL_SHOW_SESSIONS) {
    register unsigned int i;

    statusf(arg, "%s", "");
    statusf(arg, "%s", "Cached sessions:");

    if (sesscache_data->sd_listlen == 0) {
      statusf(arg, "%s", "  (none)");
    }

    /* We _could_ use SSL_SESSION_print(), which is what the sess_id
     * command-line tool does.  The problem is that SSL_SESSION_print() shows
     * too much (particularly, it shows the master secret).  And
     * SSL_SESSION_print() does not support a flags argument to use for
     * specifying which bits of the session we want to print.
     *
     * Instead, we get to do the more dangerous (compatibility-wise) approach
     * of rolling our own printing function.
     */

    for (i = 0; i < sesscache_data->sd_listsz; i++) {
      struct sesscache_entry *entry;

      pr_signals_handle();

      entry = &(sesscache_data->sd_entries[i]);
      if (entry->expires > 0) {
        SSL_SESSION *sess;
        TLS_D2I_SSL_SESSION_CONST unsigned char *ptr;
        time_t ts;
        int ssl_version;

        ptr = entry->sess_data;
        sess = d2i_SSL_SESSION(NULL, &ptr, entry->sess_datalen); 
        if (sess == NULL) {
          pr_log_pri(PR_LOG_NOTICE, MOD_TLS_SHMCACHE_VERSION
            ": error retrieving session from session cache: %s",
            shmcache_get_errors());
          continue;
        }

        statusf(arg, "%s", "  -----BEGIN SSL SESSION PARAMETERS-----");

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        /* XXX Directly accessing these fields cannot be a Good Thing. */
        if (sess->session_id_length > 0) {
          char *sess_id_str;

          sess_id_str = pr_str_bin2hex(tmp_pool, sess->session_id,
            sess->session_id_length, PR_STR_FL_HEX_USE_UC);

          statusf(arg, "    Session ID: %s", sess_id_str);
        }

        if (sess->sid_ctx_length > 0) {
          char *sid_ctx_str;

          sid_ctx_str = pr_str_bin2hex(tmp_pool, sess->sid_ctx,
            sess->sid_ctx_length, PR_STR_FL_HEX_USE_UC);

          statusf(arg, "    Session ID Context: %s", sid_ctx_str);
        }

        ssl_version = sess->ssl_version;
#else
# if OPENSSL_VERSION_NUMBER >= 0x10100006L && \
     !defined(HAVE_LIBRESSL)
        ssl_version = SSL_SESSION_get_protocol_version(sess);
# else
        ssl_version = 0;
# endif /* prior to OpenSSL-1.1.0-pre5 */
#endif /* prior to OpenSSL-1.1.x */

        switch (ssl_version) {
          case SSL3_VERSION:
            statusf(arg, "    Protocol: %s", "SSLv3");
            break;

          case TLS1_VERSION:
            statusf(arg, "    Protocol: %s", "TLSv1");
            break;

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
          case TLS1_1_VERSION:
            statusf(arg, "    Protocol: %s", "TLSv1.1");
            break;

          case TLS1_2_VERSION:
            statusf(arg, "    Protocol: %s", "TLSv1.2");
            break;
#endif

          default:
            statusf(arg, "    Protocol: %s", "unknown");
        }

        ts = SSL_SESSION_get_time(sess);
        statusf(arg, "    Started: %s", pr_strtime(ts));
        ts = entry->expires;
        statusf(arg, "    Expires: %s (%u secs)", pr_strtime(ts),
          SSL_SESSION_get_timeout(sess));

        SSL_SESSION_free(sess);
        statusf(arg, "%s", "  -----END SSL SESSION PARAMETERS-----");
        statusf(arg, "%s", "");
      }
    }
  }

  if (shmcache_lock_shm(sesscache_fh, F_UNLCK) < 0) {
    pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
      ": error unlocking shmcache: %s", strerror(errno));
  }

  destroy_pool(tmp_pool);
  return 0;
}

#if defined(PR_USE_OPENSSL_OCSP)

/* OCSP response cache implementation callbacks.
 */

/* Scan the entire list, and clear out the oldest response.  Logs the number
 * of responses cleared and updates the header stat.
 *
 * NOTE: Callers are assumed to handle the locking of the shm before/after
 * calling this function!
 */
static unsigned int ocsp_cache_flush(void) {
  register unsigned int i;
  unsigned int flushed = 0;
  time_t now;

  now = time(NULL);

  /* We always scan the in-memory large response entry list. */
  if (ocspcache_resp_list != NULL) {
    struct ocspcache_large_entry *entries;

    entries = ocspcache_resp_list->elts;
    for (i = 0; i < ocspcache_resp_list->nelts; i++) {
      struct ocspcache_large_entry *entry;

      entry = &(entries[i]);

      if (entry->age > (now - 3600)) {
        /* This entry has expired; clear its slot. */
        pr_memscrub(entry->resp_der, entry->resp_derlen);
        entry->resp_derlen = 0;
        pr_memscrub(entry->fingerprint, entry->fingerprint_len);
        entry->fingerprint_len = 0;
      }
    }
  }

  tls_log("shmcache: flushing ocsp cache of oldest responses");

  for (i = 0; i < ocspcache_data->od_listsz; i++) {
    struct ocspcache_entry *entry;

    entry = &(ocspcache_data->od_entries[i]);
    if (entry->age > (now - 3600)) {
      /* This entry has expired; clear its slot. */
      pr_memscrub(entry->resp_der, entry->resp_derlen);
      entry->resp_derlen = 0;
      pr_memscrub(entry->fingerprint, entry->fingerprint_len);
      entry->fingerprint_len = 0;
      entry->age = 0;

      /* Don't forget to update the stats. */
      ocspcache_data->nexpired++;

      if (ocspcache_data->od_listlen > 0) {
        ocspcache_data->od_listlen--;
      }

      flushed++;
    }
  }

  tls_log("shmcache: flushed %u old %s from ocsp cache", flushed,
    flushed != 1 ? "responses" : "response");
  return flushed;
}

static int ocsp_cache_open(tls_ocsp_cache_t *cache, char *info) {
  int fd, xerrno;
  char *ptr;
  size_t requested_size;
  struct stat st;

  pr_trace_msg(trace_channel, 9, "opening shmcache ocsp cache %p", cache);

  /* The info string must be formatted like:
   *
   *  /file=%s[&size=%u]
   *
   * where the optional size is in bytes.  There is a minimum size; if the
   * configured size is less than the minimum, it's an error.  The default
   * size (when no size is explicitly configured) is, of course, larger than
   * the minimum size.
   */

  if (strncmp(info, "/file=", 6) != 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_SHMCACHE_VERSION
      ": badly formatted info '%s', unable to open shmcache", info);
    errno = EINVAL;
    return -1;
  }

  info += 6;

  /* Check for the optional size parameter. */
  ptr = strchr(info, '&');
  if (ptr != NULL) {
    if (strncmp(ptr + 1, "size=", 5) == 0) {
      char *tmp = NULL;
      long size;

      size = strtol(ptr + 6, &tmp, 10);
      if (tmp && *tmp) {
        pr_trace_msg(trace_channel, 1,
          "badly formatted size parameter '%s', ignoring", ptr + 1);

        /* Default size of 1.5M. */
        requested_size = 1538 * 1024;

      } else {
        size_t min_size;

        /* The bare minimum size MUST be able to hold at least one response. */
        min_size = sizeof(struct ocspcache_data) +
          sizeof(struct ocspcache_entry);

        if ((size_t) size < min_size) {
          pr_trace_msg(trace_channel, 1,
            "requested size (%lu bytes) smaller than minimum size "
            "(%lu bytes), ignoring", (unsigned long) size,
            (unsigned long) min_size);

          /* Default size of 1.5M.  */
          requested_size = 1538 * 1024;

        } else {
          requested_size = size;
        }
      }

    } else {
      pr_trace_msg(trace_channel, 1,
        "badly formatted size parameter '%s', ignoring", ptr + 1);

      /* Default size of 1.5M.  */
      requested_size = 1538 * 1024;
    }

    *ptr = '\0';

  } else {
    /* Default size of 1.5M.  */
    requested_size = 1538 * 1024;
  }

  if (pr_fs_valid_path(info) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_SHMCACHE_VERSION
      ": file '%s' not an absolute path", info);

    errno = EINVAL;
    return -1;
  }

  /* If ocspcache_fh is not null, then we are a restarted server.  And if
   * the 'info' path does not match that previous fh, then the admin
   * has changed the configuration.
   *
   * For now, we complain about this, and tell the admin to manually remove
   * the old file/shm.
   */

  if (ocspcache_fh != NULL &&
      strcmp(ocspcache_fh->fh_path, info) != 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_SHMCACHE_VERSION
      ": file '%s' does not match previously configured file '%s'",
      info, ocspcache_fh->fh_path);
    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_SHMCACHE_VERSION
      ": remove existing shmcache using 'ftpdctl tls ocspcache remove' "
      "before using new file");

    errno = EINVAL;
    return -1;
  }

  PRIVS_ROOT
  ocspcache_fh = pr_fsio_open(info, O_RDWR|O_CREAT);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (ocspcache_fh == NULL) {
    pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
      ": error: unable to open file '%s': %s", info, strerror(xerrno));

    errno = EINVAL;
    return -1;
  }

  if (pr_fsio_fstat(ocspcache_fh, &st) < 0) {
    xerrno = errno;

    pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
      ": error: unable to stat file '%s': %s", info, strerror(xerrno));

    pr_fsio_close(ocspcache_fh);
    ocspcache_fh = NULL;

    errno = EINVAL;
    return -1;
  }

  if (S_ISDIR(st.st_mode)) {
    xerrno = EISDIR;

    pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
      ": error: unable to use file '%s': %s", info, strerror(xerrno));

    pr_fsio_close(ocspcache_fh);
    ocspcache_fh = NULL;

    errno = EINVAL;
    return -1;
  }

  /* Make sure that we don't inadvertently get one of the Big Three file
   * descriptors (stdin/stdout/stderr), as can happen especially if the
   * server has restarted.
   */
  fd = PR_FH_FD(ocspcache_fh);
  if (fd <= STDERR_FILENO) {
    int res;

    res = pr_fs_get_usable_fd(fd);
    if (res < 0) {
      pr_log_debug(DEBUG0,
        "warning: unable to find good fd for shmcache fd %d: %s", fd,
        strerror(errno));

    } else {
      close(fd);
      PR_FH_FD(ocspcache_fh) = res;
    }
  }

  pr_trace_msg(trace_channel, 9,
    "requested OCSP response cache file: %s (fd %d)", ocspcache_fh->fh_path,
    PR_FH_FD(ocspcache_fh));
  pr_trace_msg(trace_channel, 9,
    "requested OCSP cache size: %lu bytes", (unsigned long) requested_size);
  ocspcache_data = ocsp_cache_get_shm(ocspcache_fh, requested_size);
  if (ocspcache_data == NULL) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "unable to allocate OCSP response shm: %s", strerror(xerrno));
    pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
      ": unable to allocate OCSP response shm: %s", strerror(xerrno));

    pr_fsio_close(ocspcache_fh);
    ocspcache_fh = NULL;

    errno = EINVAL;
    return -1;
  }

  cache->cache_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(cache->cache_pool, MOD_TLS_SHMCACHE_VERSION);

  return 0;
}

static int ocsp_cache_close(tls_ocsp_cache_t *cache) {
  if (cache != NULL) {
    pr_trace_msg(trace_channel, 9, "closing shmcache ocsp cache %p", cache);
  }

  if (cache != NULL &&
      cache->cache_pool != NULL) {
    if (ocspcache_resp_list != NULL) {
      register unsigned int i;
      struct ocspcache_large_entry *entries;

      entries = ocspcache_resp_list->elts;
      for (i = 0; i < ocspcache_resp_list->nelts; i++) {
        struct ocspcache_large_entry *entry;

        entry = &(entries[i]);
        pr_memscrub(entry->resp_der, entry->resp_derlen);
      }

      ocspcache_resp_list = NULL;
    }

    destroy_pool(cache->cache_pool);
  }

  if (ocspcache_shmid >= 0) {
    int res, xerrno = 0;

    PRIVS_ROOT
#if !defined(_POSIX_SOURCE)
    res = shmdt((char *) ocspcache_data);
#else
    res = shmdt((const char *) ocspcache_data);
#endif
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res < 0) {
      pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
        ": error detaching ocsp shm ID %d: %s", ocspcache_shmid,
        strerror(xerrno));
    }

    ocspcache_data = NULL;
  }

  pr_fsio_close(ocspcache_fh);
  ocspcache_fh = NULL;
  return 0;
}

static int ocsp_cache_add_large_resp(tls_ocsp_cache_t *cache,
    const char *fingerprint, OCSP_RESPONSE *resp, time_t resp_age) {
  struct ocspcache_large_entry *entry = NULL;
  int resp_derlen = 0;
  unsigned char *ptr;

  resp_derlen = i2d_OCSP_RESPONSE(resp, NULL);

  if (resp_derlen > TLS_MAX_OCSP_RESPONSE_SIZE) {
    /* We may get responses to add to the list which do not exceed the max
     * size, but instead are here because we couldn't get the lock on the
     * shmcache.  Don't track these in the 'exceeded' stats'.
     */

    if (shmcache_lock_shm(ocspcache_fh, F_WRLCK) == 0) {
      ocspcache_data->nexceeded++;
      if ((size_t) resp_derlen > ocspcache_data->exceeded_maxsz) {
        ocspcache_data->exceeded_maxsz = resp_derlen;
      }

      if (shmcache_lock_shm(ocspcache_fh, F_UNLCK) < 0) {
        tls_log("shmcache: error unlocking shmcache: %s", strerror(errno));
      }

    } else {
      tls_log("shmcache: error write-locking shmcache: %s", strerror(errno));
    }
  }

  if (ocspcache_resp_list != NULL) {
    register unsigned int i;
    struct ocspcache_large_entry *entries;
    time_t now;

    /* Look for any expired responses in the list to overwrite/reuse. */
    entries = ocspcache_resp_list->elts;
    now = time(NULL);
    for (i = 0; i < ocspcache_resp_list->nelts; i++) {
      entry = &(entries[i]);

      if (entry->age > (now - 3600)) {
        /* This entry has expired; clear and reuse its slot. */
        entry->age = 0;
        pr_memscrub(entry->resp_der, entry->resp_derlen);
        entry->resp_derlen = 0;
        pr_memscrub(entry->fingerprint, entry->fingerprint_len);
        entry->fingerprint_len = 0;

        break;
      }
    }

  } else {
    ocspcache_resp_list = make_array(cache->cache_pool, 1,
      sizeof(struct ocspcache_large_entry));
    entry = push_array(ocspcache_resp_list);
  }

  /* Be defensive, and catch the case where entry might still be null here. */
  if (entry == NULL) {
    errno = EPERM;
    return -1;
  }

  entry->age = resp_age;
  entry->fingerprint_len = strlen(fingerprint);
  entry->fingerprint = palloc(cache->cache_pool, entry->fingerprint_len);
  memcpy(entry->fingerprint, fingerprint, entry->fingerprint_len);
  entry->resp_derlen = resp_derlen;
  entry->resp_der = palloc(cache->cache_pool, resp_derlen);

  ptr = entry->resp_der;
  i2d_OCSP_RESPONSE(resp, &ptr);

  return 0;
}

static int ocsp_cache_add(tls_ocsp_cache_t *cache, const char *fingerprint,
    OCSP_RESPONSE *resp, time_t resp_age) {
  register unsigned int i;
  unsigned int h, idx, last;
  int found_slot = FALSE, need_lock = TRUE, res = 0, resp_derlen;
  size_t fingerprint_len;

  pr_trace_msg(trace_channel, 9, "adding response to shmcache ocsp cache %p",
    cache);

  /* First we need to find out how much space is needed for the serialized
   * response data.  There is no known maximum size for OCSP response data;
   * this module is currently designed to allow only up to a certain size.
   */

  resp_derlen = i2d_OCSP_RESPONSE(resp, NULL);
  if (resp_derlen <= 0) {
    pr_trace_msg(trace_channel, 1,
      "error DER-encoding OCSP response: %s", shmcache_get_errors());
    errno = EINVAL;
    return -1;
  }

  if (resp_derlen > TLS_MAX_OCSP_RESPONSE_SIZE) {
    tls_log("shmcache: length of serialized OCSP response data (%d) exceeds "
      "maximum size (%u), unable to add to shared shmcache", resp_derlen,
      TLS_MAX_OCSP_RESPONSE_SIZE);

    /* Instead of rejecting the add here, we add the response to a "large
     * response" list.  Thus the large response would still be cached per
     * process and will not be lost.
     *
     * XXX We should also track how often this happens, and possibly trigger
     * a shmcache resize (using a larger record size, vs larger cache size)
     * so that we can cache these large records in the shm segment.
     */

    return ocsp_cache_add_large_resp(cache, fingerprint, resp, resp_age);
  }

  if (ocspcache_data->od_listlen == ocspcache_data->od_listsz) {
    /* It appears that the cache is full.  Flush the oldest response. */
    if (shmcache_lock_shm(ocspcache_fh, F_WRLCK) == 0) {
      if (ocsp_cache_flush() > 0) {
        /* If we made room, then do NOT release the lock; we keep the lock
         * so that we can add the response.
         */
        need_lock = FALSE;

      } else {
        /* Release the lock, and use the "large response" list fallback. */
        if (shmcache_lock_shm(ocspcache_fh, F_UNLCK) < 0) {
          tls_log("shmcache: error unlocking shmcache: %s", strerror(errno));
        }

        return ocsp_cache_add_large_resp(cache, fingerprint, resp, resp_age);
      }

    } else {
      tls_log("shmcache: unable to flush ocsp shmcache: error write-locking "
        "shmcache: %s", strerror(errno));

      /* Add this response to the "large response" list instead as a
       * fallback.
       */
      return ocsp_cache_add_large_resp(cache, fingerprint, resp, resp_age);
    }
  }

  /* Hash the key, start looking for an open slot. */
  fingerprint_len = strlen(fingerprint);
  h = shmcache_hash((unsigned char *) fingerprint, fingerprint_len);
  idx = h % ocspcache_data->od_listsz;

  if (need_lock) {
    if (shmcache_lock_shm(ocspcache_fh, F_WRLCK) < 0) {
      tls_log("shmcache: unable to add response to ocsp shmcache: error "
        "write-locking shmcache: %s", strerror(errno));

      /* Add this response to the "large response" list instead as a
       * fallback.
       */
      return ocsp_cache_add_large_resp(cache, fingerprint, resp, resp_age);
    }
  }

  i = idx;
  last = idx > 0 ? (idx - 1) : 0;

  do {
    struct ocspcache_entry *entry;

    pr_signals_handle();

    /* Look for the first open slot (i.e. fingerprint_len == 0). */
    entry = &(ocspcache_data->od_entries[i]);
    if (entry->fingerprint_len == 0) {
      unsigned char *ptr;

      entry->age = resp_age;
      entry->fingerprint_len = fingerprint_len;
      memcpy(entry->fingerprint, fingerprint, fingerprint_len);
      entry->resp_derlen = resp_derlen;

      ptr = entry->resp_der;
      i2d_OCSP_RESPONSE(resp, &ptr);

      ocspcache_data->od_listlen++;
      ocspcache_data->nstored++;

      found_slot = TRUE;
      break;
    }

    if (i < ocspcache_data->od_listsz) {
      i++;

    } else {
      i = 0;
    }
  } while (i != last);

  /* There is a race condition possible between the open slots check
   * above and the scan through the slots.  So if we didn't actually find
   * an open slot at this point, add it to the "large response" list.
   */
  if (!found_slot) {
    res = ocsp_cache_add_large_resp(cache, fingerprint, resp, resp_age);
  }

  if (need_lock) {
    if (shmcache_lock_shm(ocspcache_fh, F_UNLCK) < 0) {
      tls_log("shmcache: error unlocking shmcache: %s", strerror(errno));
    }
  }

  return res;
}

static OCSP_RESPONSE *ocsp_cache_get(tls_ocsp_cache_t *cache,
    const char *fingerprint, time_t *resp_age) {
  unsigned int h, idx;
  OCSP_RESPONSE *resp = NULL;
  size_t fingerprint_len = 0;

  pr_trace_msg(trace_channel, 9,
    "getting response from shmcache ocsp cache %p", cache);

  fingerprint_len = strlen(fingerprint);

  /* Look for the requested response in the "large response" list first. */
  if (ocspcache_resp_list != NULL) {
    register unsigned int i;
    struct ocspcache_large_entry *entries;

    entries = ocspcache_resp_list->elts;
    for (i = 0; i < ocspcache_resp_list->nelts; i++) {
      struct ocspcache_large_entry *entry;

      entry = &(entries[i]);
      if (entry->fingerprint_len > 0 &&
          entry->fingerprint_len == fingerprint_len &&
          memcmp(entry->fingerprint, fingerprint, fingerprint_len) == 0) {
        const unsigned char *ptr;

        ptr = entry->resp_der;
        resp = d2i_OCSP_RESPONSE(NULL, &ptr, entry->resp_derlen);
        if (resp == NULL) {
          tls_log("shmcache: error retrieving response from ocsp cache: %s",
            shmcache_get_errors());

        } else {
          *resp_age = entry->age;
          break;
        }
      }
    }
  }

  if (resp) {
    return resp;
  }

  h = shmcache_hash((unsigned char *) fingerprint, fingerprint_len);
  idx = h % ocspcache_data->od_listsz;

  if (shmcache_lock_shm(ocspcache_fh, F_WRLCK) == 0) {
    register unsigned int i;
    unsigned int last;

    i = idx;
    last = idx > 0 ? (idx -1) : 0;

    do {
      struct ocspcache_entry *entry;

      pr_signals_handle();

      entry = &(ocspcache_data->od_entries[i]);
      if (entry->fingerprint_len > 0 &&
          entry->fingerprint_len == fingerprint_len &&
          memcmp(entry->fingerprint, fingerprint, fingerprint_len) == 0) {
        const unsigned char *ptr;

        /* Don't forget to update the stats. */

        ptr = entry->resp_der;
        resp = d2i_OCSP_RESPONSE(NULL, &ptr, entry->resp_derlen);
        if (resp != NULL) {
          *resp_age = entry->age;
          ocspcache_data->nhits++;

        } else {
          tls_log("shmcache: error retrieving response from ocsp cache: %s",
            shmcache_get_errors());
          ocspcache_data->nerrors++;
        }

        break;
      }

      if (i < ocspcache_data->od_listsz) {
        i++;

      } else {
        i = 0;
      }
    } while (i != last);

    if (resp == NULL) {
      ocspcache_data->nmisses++;
      errno = ENOENT;
    }

    if (shmcache_lock_shm(ocspcache_fh, F_UNLCK) < 0) {
      tls_log("shmcache: error unlocking shmcache: %s", strerror(errno));
    }

  } else {
    tls_log("shmcache: unable to retrieve response from ocsp cache: error "
      "write-locking shmcache: %s", strerror(errno));

    errno = EPERM;
  }

  return resp;
}

static int ocsp_cache_delete(tls_ocsp_cache_t *cache, const char *fingerprint) {
  unsigned int h, idx;
  int res;
  size_t fingerprint_len = 0;

  pr_trace_msg(trace_channel, 9,
    "removing response from shmcache ocsp cache %p", cache);

  fingerprint_len = strlen(fingerprint);

  /* Look for the requested response in the "large response" list first. */
  if (ocspcache_resp_list != NULL) {
    register unsigned int i;
    struct ocspcache_large_entry *entries;

    entries = ocspcache_resp_list->elts;
    for (i = 0; i < ocspcache_resp_list->nelts; i++) {
      struct ocspcache_large_entry *entry;

      entry = &(entries[i]);
      if (entry->fingerprint_len == fingerprint_len &&
          memcmp(entry->fingerprint, fingerprint, fingerprint_len) == 0) {

        pr_memscrub(entry->resp_der, entry->resp_derlen);
        entry->resp_derlen = 0;
        pr_memscrub(entry->fingerprint, entry->fingerprint_len);
        entry->fingerprint_len = 0;
        entry->age = 0;
        return 0;
      }
    }
  }

  h = shmcache_hash((unsigned char *) fingerprint, fingerprint_len);
  idx = h % ocspcache_data->od_listsz;

  if (shmcache_lock_shm(ocspcache_fh, F_WRLCK) == 0) {
    register unsigned int i;
    unsigned int last;

    i = idx;
    last = idx > 0 ? (idx - 1) : 0;

    do {
      struct ocspcache_entry *entry;

      pr_signals_handle();

      entry = &(ocspcache_data->od_entries[i]);
      if (entry->fingerprint_len == fingerprint_len &&
          memcmp(entry->fingerprint, fingerprint, fingerprint_len) == 0) {
        time_t now;

        pr_memscrub(entry->resp_der, entry->resp_derlen);
        entry->resp_derlen = 0;
        pr_memscrub(entry->fingerprint, entry->fingerprint_len);
        entry->fingerprint_len = 0;

        if (ocspcache_data->od_listlen > 0) {
          ocspcache_data->od_listlen--;
        }

        /* Don't forget to update the stats. */
        now = time(NULL);
        if (entry->age > (now - 3600)) {
          ocspcache_data->nexpired++;

        } else {
          ocspcache_data->ndeleted++;
        }

        entry->age = 0;
        break;
      }

      if (i < ocspcache_data->od_listsz) {
        i++;

      } else {
        i = 0;
      }

    } while (i != last);

    if (shmcache_lock_shm(ocspcache_fh, F_UNLCK) < 0) {
      tls_log("shmcache: error unlocking shmcache: %s", strerror(errno));
    }

    res = 0;

  } else {
    tls_log("shmcache: unable to delete response from ocsp cache: error "
      "write-locking shmcache: %s", strerror(errno));

    errno = EPERM;
    res = -1;
  }

  return res;
}

static int ocsp_cache_clear(tls_ocsp_cache_t *cache) {
  register unsigned int i;
  int res;

  pr_trace_msg(trace_channel, 9, "clearing shmcache ocsp cache %p", cache);

  if (ocspcache_shmid < 0) {
    errno = EINVAL;
    return -1;
  }

  if (ocspcache_resp_list != NULL) {
    struct ocspcache_large_entry *entries;

    entries = ocspcache_resp_list->elts;
    for (i = 0; i < ocspcache_resp_list->nelts; i++) {
      struct ocspcache_large_entry *entry;

      entry = &(entries[i]);
      entry->age = 0;
      pr_memscrub(entry->resp_der, entry->resp_derlen);
      entry->resp_derlen = 0;
      pr_memscrub(entry->fingerprint, entry->fingerprint_len);
      entry->fingerprint_len = 0;
    }
  }

  if (shmcache_lock_shm(ocspcache_fh, F_WRLCK) < 0) {
    tls_log("shmcache: unable to clear cache: error write-locking shmcache: %s",
      strerror(errno));
    return -1;
  }

  for (i = 0; i < ocspcache_data->od_listsz; i++) {
    struct ocspcache_entry *entry;

    entry = &(ocspcache_data->od_entries[i]);

    entry->age = 0;
    pr_memscrub(entry->resp_der, entry->resp_derlen);
    entry->resp_derlen = 0;
    pr_memscrub(entry->fingerprint, entry->fingerprint_len);
    entry->fingerprint_len = 0;
  }

  res = ocspcache_data->od_listlen;
  ocspcache_data->od_listlen = 0;

  if (shmcache_lock_shm(ocspcache_fh, F_UNLCK) < 0) {
    tls_log("shmcache: error unlocking shmcache: %s", strerror(errno));
  }

  return res;
}

static int ocsp_cache_remove(tls_ocsp_cache_t *cache) {
  int res;
  struct shmid_ds ds;
  const char *cache_file;

  if (ocspcache_fh == NULL) {
    return 0;
  }

  if (cache != NULL) {
    pr_trace_msg(trace_channel, 9, "removing shmcache ocsp cache %p", cache);
  }

  cache_file = ocspcache_fh->fh_path;
  (void) ocsp_cache_close(cache);

  if (ocspcache_shmid < 0) {
    errno = EINVAL;
    return -1;
  }

  pr_log_debug(DEBUG9, MOD_TLS_SHMCACHE_VERSION
    ": attempting to remove OCSP response cache shm ID %d", ocspcache_shmid);

  PRIVS_ROOT
  res = shmctl(ocspcache_shmid, IPC_RMID, &ds);
  PRIVS_RELINQUISH

  if (res < 0) {
    pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
      ": error removing OCSP response cache shm ID %d: %s", ocspcache_shmid,
      strerror(errno));

  } else {
    pr_log_debug(DEBUG9, MOD_TLS_SHMCACHE_VERSION
      ": removed OCSP response cache shm ID %d", ocspcache_shmid);
    ocspcache_shmid = -1;
  }

  /* Don't forget to remove the on-disk file as well. */
  unlink(cache_file);

  return res;
}

static int ocsp_cache_status(tls_ocsp_cache_t *cache,
    void (*statusf)(void *, const char *, ...), void *arg, int flags) {
  int res, xerrno = 0;
  struct shmid_ds ds;
  pool *tmp_pool;

  pr_trace_msg(trace_channel, 9, "checking shmcache ocsp cache %p", cache);

  if (shmcache_lock_shm(ocspcache_fh, F_RDLCK) < 0) {
    pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
      ": error read-locking shmcache: %s", strerror(errno));
    return -1;
  }

  tmp_pool = make_sub_pool(permanent_pool);

  statusf(arg, "%s", "Shared memory (shm) OCSP response cache provided by "
    MOD_TLS_SHMCACHE_VERSION);
  statusf(arg, "%s", "");
  statusf(arg, "Shared memory segment ID: %d", ocspcache_shmid);

  PRIVS_ROOT
  res = shmctl(ocspcache_shmid, IPC_STAT, &ds);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (res == 0) {
    statusf(arg, "Shared memory segment size: %u bytes",
      (unsigned int) ds.shm_segsz);
    statusf(arg, "Shared memory cache created on: %s",
      pr_strtime(ds.shm_ctime));
    statusf(arg, "Shared memory attach count: %u",
      (unsigned int) ds.shm_nattch);

  } else {
    statusf(arg, "Unable to stat shared memory segment ID %d: %s",
      ocspcache_shmid, strerror(xerrno));
  }

  statusf(arg, "%s", "");
  statusf(arg, "Max response cache size: %u", ocspcache_data->od_listsz);
  statusf(arg, "Current response cache size: %u", ocspcache_data->od_listlen);
  statusf(arg, "%s", "");
  statusf(arg, "Cache lifetime hits: %u", ocspcache_data->nhits);
  statusf(arg, "Cache lifetime misses: %u", ocspcache_data->nmisses);
  statusf(arg, "%s", "");
  statusf(arg, "Cache lifetime responses stored: %u", ocspcache_data->nstored);
  statusf(arg, "Cache lifetime responses deleted: %u",
    ocspcache_data->ndeleted);
  statusf(arg, "Cache lifetime responses expired: %u",
    ocspcache_data->nexpired);
  statusf(arg, "%s", "");
  statusf(arg, "Cache lifetime errors handling responses in cache: %u",
    ocspcache_data->nerrors);
  statusf(arg, "Cache lifetime responses exceeding max entry size: %u",
    ocspcache_data->nexceeded);
  if (ocspcache_data->nexceeded > 0) {
    statusf(arg, "  Largest response exceeding max entry size: %u",
      ocspcache_data->exceeded_maxsz);
  }

  if (shmcache_lock_shm(ocspcache_fh, F_UNLCK) < 0) {
    pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
      ": error unlocking shmcache: %s", strerror(errno));
  }

  destroy_pool(tmp_pool);
  return 0;
}

#endif /* PR_USE_OPENSSL_OCSP */

/* Event Handlers
 */

/* Daemon PID */
extern pid_t mpid;

static void shmcache_shutdown_ev(const void *event_data, void *user_data) {
  if (mpid == getpid() &&
      ServerType == SERVER_STANDALONE) {

    /* Remove external session caches on shutdown; the security policy/config
     * may have changed, e.g. becoming more strict, and allow clients to
     * resumed cached sessions from a more relaxed security config is not a
     * Good Thing at all.
     */
    sess_cache_remove(NULL);
#if defined(PR_USE_OPENSSL_OCSP)
    ocsp_cache_remove(NULL);
#endif /* PR_USE_OPENSSL_OCSP */
  }
}

#if defined(PR_SHARED_MODULE)
static void shmcache_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_tls_shmcache.c", (const char *) event_data) == 0) {
    pr_event_unregister(&tls_shmcache_module, NULL, NULL);
    tls_sess_cache_unregister("shm");

    /* This clears our cache by detaching and destroying the shared memory
     * segment.
     */
    sess_cache_remove(NULL);

#if defined(PR_USE_OPENSSL_OCSP)
    tls_ocsp_cache_unregister("shm");
#endif /* PR_USE_OPENSSL_OCSP */
  }
}
#endif /* !PR_SHARED_MODULE */

static void shmcache_restart_ev(const void *event_data, void *user_data) {
  /* Clear external session caches on shutdown; the security policy/config
   * may have changed, e.g. becoming more strict, and allow clients to
   * resumed cached sessions from a more relaxed security config is not a
   * Good Thing at all.
   */
  sess_cache_clear(NULL);
}

/* Initialization functions
 */

static int tls_shmcache_init(void) {
#if defined(PR_SHARED_MODULE)
  pr_event_register(&tls_shmcache_module, "core.module-unload",
    shmcache_mod_unload_ev, NULL);
#endif /* !PR_SHARED_MODULE */
  pr_event_register(&tls_shmcache_module, "core.restart", shmcache_restart_ev,
    NULL);
  pr_event_register(&tls_shmcache_module, "core.shutdown", shmcache_shutdown_ev,
    NULL);

  /* Prepare our SSL session cache handler. */
  memset(&sess_cache, 0, sizeof(sess_cache));
  sess_cache.open = sess_cache_open;
  sess_cache.close = sess_cache_close;
  sess_cache.add = sess_cache_add;
  sess_cache.get = sess_cache_get;
  sess_cache.delete = sess_cache_delete;
  sess_cache.clear = sess_cache_clear;
  sess_cache.remove = sess_cache_remove;
  sess_cache.status = sess_cache_status;

#ifdef SSL_SESS_CACHE_NO_INTERNAL_LOOKUP
  /* Take a chance, and inform OpenSSL that it does not need to use its own
   * internal session cache lookups; using the external session cache (i.e. us)
   * will be enough.
   */
  sess_cache.cache_mode = SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;
#endif

  /* Register ourselves with mod_tls. */
  if (tls_sess_cache_register("shm", &sess_cache) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_SHMCACHE_VERSION
      ": notice: error registering 'shm' SSL session cache: %s",
      strerror(errno));
    return -1;
  }

#if defined(PR_USE_OPENSSL_OCSP)
  /* Prepare our OCSP response cache handler. */
  memset(&ocsp_cache, 0, sizeof(ocsp_cache));
  ocsp_cache.open = ocsp_cache_open;
  ocsp_cache.close = ocsp_cache_close;
  ocsp_cache.add = ocsp_cache_add;
  ocsp_cache.get = ocsp_cache_get;
  ocsp_cache.delete = ocsp_cache_delete;
  ocsp_cache.clear = ocsp_cache_clear;
  ocsp_cache.remove = ocsp_cache_remove;
  ocsp_cache.status = ocsp_cache_status;

  /* Register ourselves with mod_tls. */
  if (tls_ocsp_cache_register("shm", &ocsp_cache) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_SHMCACHE_VERSION
      ": notice: error registering 'shm' OCSP response cache: %s",
      strerror(errno));
    return -1;
  }
#endif /* PR_USE_OPENSSL_OCSP */

  return 0;
}

static int tls_shmcache_sess_init(void) {

#ifdef HAVE_MLOCK
  if (sesscache_data != NULL) {
    int res, xerrno = 0;

    /* Make sure the memory is pinned in RAM where possible.
     *
     * Since this is a session process, we do not need to worry about
     * explicitly unlocking the locked memory; that will happen automatically
     * when the session process exits.
     */
    PRIVS_ROOT
    res = mlock(sesscache_data, sesscache_datasz);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res < 0) {
      pr_log_debug(DEBUG1, MOD_TLS_SHMCACHE_VERSION
        ": error locking 'shm' session cache (%lu bytes) into memory: %s",
        (unsigned long) sesscache_datasz, strerror(xerrno));

    } else {
      pr_log_debug(DEBUG5, MOD_TLS_SHMCACHE_VERSION
        ": 'shm' session cache locked into memory (%lu bytes)",
        (unsigned long) sesscache_datasz);
    }
  }
#endif

  return 0;
}

/* Module API tables
 */

module tls_shmcache_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "tls_shmcache",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  tls_shmcache_init,

  /* Session initialization function */
  tls_shmcache_sess_init,

  /* Module version */
  MOD_TLS_SHMCACHE_VERSION
};
