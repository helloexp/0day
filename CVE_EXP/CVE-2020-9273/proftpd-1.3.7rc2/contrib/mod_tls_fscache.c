/*
 * ProFTPD: mod_tls_fscache -- a module which provides a shared OCSP response
 *                              cache using the filesystem
 * Copyright (c) 2015-2016 TJ Saunders
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
 * This is mod_tls_fscache, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"
#include "mod_tls.h"

#define MOD_TLS_FSCACHE_VERSION			"mod_tls_fscache/0.0"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030602
# error "ProFTPD 1.3.6rc2 or later required"
#endif

extern xaset_t *server_list;

module tls_fscache_module;

#if defined(PR_USE_OPENSSL_OCSP)
static tls_ocsp_cache_t ocsp_cache;
#endif /* PR_USE_OPENSSL_OCSP */

static const char *trace_channel = "tls.fscache";

#if defined(PR_USE_OPENSSL_OCSP)
static const char *fscache_get_errors(void) {
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

/* OCSP Cache implementation callbacks.
 */

static int ocsp_cache_open(tls_ocsp_cache_t *cache, char *info) {
  int res, xerrno = 0;
  struct stat st;

  pr_trace_msg(trace_channel, 9, "opening fscache cache %p", cache);

  /* The info string must be formatted like:
   *
   *  /path=%s
   */

  if (strncmp(info, "/path=", 6) != 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_FSCACHE_VERSION
      ": badly formatted info '%s', unable to open fscache", info);
    errno = EINVAL;
    return -1;
  }

  info += 6;

  if (pr_fs_valid_path(info) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_FSCACHE_VERSION
      ": path '%s' not an absolute path", info);

    errno = EINVAL;
    return -1;
  }

  res = lstat(info, &st);
  if (res < 0) {
    xerrno = errno;

    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_FSCACHE_VERSION
      ": unable to check '%s': %s", info, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (!S_ISDIR(st.st_mode)) {
    xerrno = ENOTDIR;

    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_FSCACHE_VERSION
      ": unable to use '%s': %s", info, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* Make sure that the directory is not world-writable; we don't want
   * any/all users on the system to be able to futz with these.
   */
  if (st.st_mode & S_IWOTH) {
    xerrno = EPERM;

    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_FSCACHE_VERSION
      ": unable to use world-writable '%s' (perms %04o)", info,
      st.st_mode & ~S_IFMT);

    errno = xerrno;
    return -1;
  }

  if (cache->cache_pool != NULL) {
    char *prev_cache_dir;

    /* XXX Are we a restarted server if this happens?
     *
     * If so, AND if cache->cache_data is NOT NULL, AND points to a
     * directory which is NOT 'path', then should we clean up that
     * other directory?  (No; it could be used by another process on
     * the machine, e.g. multiple different proftpd servers.)
     *
     * For now, we complain about this, and tell the admin to manually remove
     * the old directory.
     */

    prev_cache_dir = cache->cache_data;
    if (prev_cache_dir != NULL &&
        strcmp(prev_cache_dir, info) != 0) {
      pr_log_pri(PR_LOG_DEBUG, MOD_TLS_FSCACHE_VERSION
        ": path '%s' does not match previously configured path '%s'",
        info, prev_cache_dir);
    }

    destroy_pool(cache->cache_pool);
  }

  cache->cache_pool = make_sub_pool(session.pool);
  pr_pool_tag(cache->cache_pool, MOD_TLS_FSCACHE_VERSION);

  cache->cache_data = pstrdup(cache->cache_pool, info);
  return 0;
}

static int ocsp_cache_close(tls_ocsp_cache_t *cache) {

  if (cache != NULL) {
    pr_trace_msg(trace_channel, 9, "closing fscache cache %p", cache);

    if (cache->cache_pool != NULL) {
      destroy_pool(cache->cache_pool);

      /* XXX TODO */
    }
  }

  return 0;
}

static int ocsp_cache_add(tls_ocsp_cache_t *cache, const char *fingerprint,
    OCSP_RESPONSE *resp, time_t resp_age) {
  int fd, res, resp_derlen = -1, xerrno = 0;
  unsigned char *resp_der = NULL;
  const char *cache_dir;
  char *path, *tmpl;
  pool *tmp_pool;
  struct timeval tvs[2];

  pr_trace_msg(trace_channel, 9, "adding OCSP response to fscache cache %p",
    cache);

  resp_derlen = i2d_OCSP_RESPONSE(resp, &resp_der);
  if (resp_derlen <= 0) {
    pr_trace_msg(trace_channel, 1,
      "error DER-encoding OCSP response: %s", fscache_get_errors());
    errno = EINVAL;
    return -1;
  }

  cache_dir = cache->cache_data;
  tmp_pool = make_sub_pool(cache->cache_pool);
  pr_pool_tag(tmp_pool, "OCSP fscache add pool");

  tmpl = pdircat(tmp_pool, cache_dir, "XXXXXX", NULL);
  fd = mkstemp(tmpl);
  if (fd < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "unable to obtain secure temporary file for OCSP response: %s",
      strerror(xerrno));

    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 15,
    "writing OCSP response to temporary file '%s'", tmpl);

  res = write(fd, resp_der, resp_derlen);
  if (res != resp_derlen) {
    if (res < 0) {
      xerrno = errno;

      pr_trace_msg(trace_channel, 1,
        "error writing OCSP response to '%s' (fd %d): %s", tmpl, fd,
        strerror(xerrno));
      errno = xerrno;

    } else {
      /* XXX Deal with short writes? */

      pr_trace_msg(trace_channel, 1,
        "only wrote %d of %d bytes of OCSP response to '%s' (fd %d)", res,
        resp_derlen, tmpl, fd);
      xerrno = EIO;
    }

    (void) unlink(tmpl);
    (void) close(fd);
    destroy_pool(tmp_pool);

    errno = xerrno;
    return -1;
  }

  res = close(fd);
  if (res < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error writing OCSP response to '%s': %s", tmpl, strerror(xerrno));

    (void) unlink(tmpl);
    destroy_pool(tmp_pool);

    errno = xerrno;
    return -1;
  }

  /* We ASSUME that rename(2) does not modify the mtime of the file.  Ideally
   * we would futimes(2) on the file descriptor, but calling close(2) on that
   * fd might also change the mtime (due to close flushing out buffered data),
   * thus we use the path.
   */
  tvs[0].tv_sec = tvs[1].tv_sec = resp_age;
  tvs[0].tv_usec = tvs[1].tv_usec = 0;
  res = utimes(tmpl, tvs);
  if (res < 0) {
    pr_trace_msg(trace_channel, 9,
      "error setting atime/mtime on '%s' to %lu secs: %s", tmpl,
      (unsigned long) resp_age, strerror(errno));
  }

  /* Atomically rename the temporary file into place. */
  path = pstrcat(tmp_pool, cache_dir, "/", fingerprint, ".der", NULL);
  res = rename(tmpl, path);
  if (res < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error renaming '%s' to '%s': %s", tmpl, path, strerror(xerrno));

    (void) unlink(tmpl);

  } else {
    pr_trace_msg(trace_channel, 15, "renamed '%s' to '%s' (%d bytes)", tmpl,
      path, resp_derlen);
  } 

  destroy_pool(tmp_pool);
  errno = xerrno;
  return res;
}

static OCSP_RESPONSE *ocsp_cache_get(tls_ocsp_cache_t *cache,
    const char *fingerprint, time_t *resp_age) {
  int res, xerrno = 0;
  const char *cache_dir, *path;
  pool *tmp_pool;
  BIO *bio = NULL;
  OCSP_RESPONSE *resp = NULL;
  struct stat st;
  pr_fh_t *fh;

  pr_trace_msg(trace_channel, 9, "getting OCSP response from fscache cache %p",
    cache); 

  cache_dir = cache->cache_data;
  tmp_pool = make_sub_pool(cache->cache_pool);
  pr_pool_tag(tmp_pool, "OCSP fscache retrieval pool");

  path = pstrcat(tmp_pool, cache_dir, "/", fingerprint, ".der", NULL);
  pr_trace_msg(trace_channel, 15, "getting OCSP response at path '%s'", path);

  fh = pr_fsio_open(path, O_RDONLY);
  if (fh == NULL) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 3, "error opening '%s': %s", path,
      strerror(xerrno));

    destroy_pool(tmp_pool);
    errno = xerrno;
    return NULL;
  }

  res = pr_fsio_fstat(fh, &st);
  if (res < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 3, "error checking '%s': %s", path,
      strerror(xerrno));

    (void) pr_fsio_close(fh);
    destroy_pool(tmp_pool);
    errno = xerrno;
    return NULL;
  }

  /* No symlinks or directories, only regular files. */
  if (!S_ISREG(st.st_mode)) {
    pr_trace_msg(trace_channel, 3, "path '%s' is NOT a regular file", path);

    /* If it's a symlink, remove it.  We cannot just do the same with
     * a directory.
     */
    if (S_ISLNK(st.st_mode)) {
      (void) unlink(path);
    }

    (void) pr_fsio_close(fh);
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return NULL;
  }

  bio = BIO_new_file(path, "r");
  if (bio == NULL) {
    xerrno = errno;

    tls_log(MOD_TLS_FSCACHE_VERSION ": BIO_new_file('%s') failed: %s", path,
      fscache_get_errors());
    (void) pr_fsio_close(fh);
    destroy_pool(tmp_pool);

    errno = xerrno;
    return NULL;
  }

  resp = d2i_OCSP_RESPONSE_bio(bio, NULL);
  if (resp == NULL) {
    pr_trace_msg(trace_channel, 3,
      "error reading valid OCSP response from path '%s': %s", path,
      fscache_get_errors());

    /* If we can't read a valid OCSP response from this file, delete it. */
    (void) unlink(path);

    (void) pr_fsio_close(fh);
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return NULL;
  }

  BIO_free(bio);

  /* Use the mtime of the file to determine how old it is. */
  *resp_age = st.st_mtime;

  (void) pr_fsio_close(fh);
  destroy_pool(tmp_pool);
  errno = xerrno;
  return resp;
}

static int ocsp_cache_delete(tls_ocsp_cache_t *cache, const char *fingerprint) {
  int res, xerrno = 0;
  const char *cache_dir, *path;
  pool *tmp_pool;

  pr_trace_msg(trace_channel, 9,
    "removing OCSP response from fscache cache %p", cache);

  cache_dir = cache->cache_data;
  tmp_pool = make_sub_pool(cache->cache_pool);
  pr_pool_tag(tmp_pool, "OCSP fscache delete pool");

  path = pstrcat(tmp_pool, cache_dir, "/", fingerprint, ".der", NULL);
  pr_trace_msg(trace_channel, 15, "deleting OCSP response at path '%s'", path);

  /* XXX Do we need root privs here?  Should we use the FSIO API? */
  res = unlink(path);
  xerrno = errno;

  destroy_pool(tmp_pool);
  errno = xerrno;
  return res;
}

static int ocsp_cache_clear(tls_ocsp_cache_t *cache) {
  int res, xerrno = 0;
  const char *cache_dir;
  pool *tmp_pool;
  DIR *dirh;
  struct dirent *dent;

  pr_trace_msg(trace_channel, 9, "clearing fscache cache %p", cache); 

  cache_dir = cache->cache_data;

  dirh = opendir(cache_dir);
  if (dirh == NULL) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 3, "unable to open directory '%s': %s",
      cache_dir, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  tmp_pool = make_sub_pool(cache->cache_pool);
  pr_pool_tag(tmp_pool, "OCSP fscache clear pool");

  dent = readdir(dirh);
  while (dent != NULL) {
    struct stat st;
    size_t namelen;

    pr_signals_handle();

    namelen = strlen(dent->d_name);
    /* Skip any path which does not end in ".der". */
    if (pr_strnrstr(dent->d_name, namelen, ".der", 4, 0) == TRUE) {
      pr_fh_t *fh;
      char *path;

      path = pstrcat(tmp_pool, cache_dir, "/", dent->d_name, ".der", NULL);

      fh = pr_fsio_open(path, O_RDONLY);
      if (fh != NULL) {
        res = pr_fsio_fstat(fh, &st);
        if (res < 0) {
          pr_trace_msg(trace_channel, 3, "error checking path '%s': %s", path,
            strerror(errno));

        } else {
          if (S_ISREG(st.st_mode) ||
              S_ISLNK(st.st_mode)) {

            pr_trace_msg(trace_channel, 15,
              "deleting OCSP response at path '%s'", path);
            res = unlink(path);
            if (res < 0) {
              pr_trace_msg(trace_channel, 3,
                "error deleting path '%s': %s", path, strerror(errno));
            }

          } else {
            pr_trace_msg(trace_channel, 3,
              "ignoring non-file/symlink path '%s'", path);
          }
        }

        (void) pr_fsio_close(fh);

      } else {
        pr_trace_msg(trace_channel, 3, "error opening path '%s': %s", path,
          strerror(errno));
      }
    }

    dent = readdir(dirh);
  }

  (void) closedir(dirh);
  destroy_pool(tmp_pool);

  return 0;
}

static int ocsp_cache_remove(tls_ocsp_cache_t *cache) {
  int res;

  if (cache == NULL) {
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 9, "removing fscache cache %p", cache);
  res = ocsp_cache_clear(cache);
  return res;
}

static int ocsp_cache_status(tls_ocsp_cache_t *cache,
    void (*statusf)(void *, const char *, ...), void *arg, int flags) {
  int res, xerrno = 0;
  unsigned int resp_count = 0;
  const char *cache_dir;
  pool *tmp_pool;
  DIR *dirh;
  struct dirent *dent;

  pr_trace_msg(trace_channel, 9, "checking fscache cache %p", cache); 

  /* XXX TODO:
   *  If flags says "SHOW RESPONSES", print out the PEM versions of the
   *  responses?
   */

  cache_dir = cache->cache_data;

  dirh = opendir(cache_dir);
  if (dirh == NULL) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 3, "unable to open directory '%s': %s",
      cache_dir, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  tmp_pool = make_sub_pool(cache->cache_pool);
  pr_pool_tag(tmp_pool, "OCSP fscache status pool");

  dent = readdir(dirh);
  while (dent != NULL) {
    struct stat st;
    size_t namelen;

    pr_signals_handle();

    /* Skip any path which does not end in ".der". */
    namelen = strlen(dent->d_name);
    if (pr_strnrstr(dent->d_name, namelen, ".der", 4, 0) == TRUE) {
      pr_fh_t *fh;
      char *path;

      path = pstrcat(tmp_pool, cache_dir, "/", dent->d_name, ".der", NULL);

      fh = pr_fsio_open(path, O_RDONLY);
      if (fh != NULL) {
        res = pr_fsio_fstat(fh, &st);
        if (res < 0) {
          pr_trace_msg(trace_channel, 3, "error checking path '%s': %s", path,
            strerror(errno));

        } else {
          if (S_ISREG(st.st_mode) ||
              S_ISLNK(st.st_mode)) {
            resp_count++;

          } else {
            pr_trace_msg(trace_channel, 3,
              "ignoring non-file/symlink path '%s'", path);
          }
        }

        (void) pr_fsio_close(fh);

      } else {
        pr_trace_msg(trace_channel, 3, "error opening path '%s': %s", path,
          strerror(errno));
      }
    }

    dent = readdir(dirh);
  }

  (void) closedir(dirh);
  destroy_pool(tmp_pool);

  statusf(arg, "%s", "Filesystem (fs) OCSP response cache provided by "
    MOD_TLS_FSCACHE_VERSION);
  statusf(arg, "%s", "");
  statusf(arg, "Current OCSP responses cached: %u", resp_count);

  return 0;
}
#endif /* PR_USE_OPENSSL_OCSP */

/* Event Handlers
 */

#if defined(PR_SHARED_MODULE)
static void fscache_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_tls_fscache.c", (const char *) event_data) == 0) {
    pr_event_unregister(&tls_fscache_module, NULL, NULL);
    (void) tls_ocsp_cache_unregister("fs");
  }
}
#endif /* !PR_SHARED_MODULE */

/* Initialization functions
 */

static int tls_fscache_init(void) {
#if defined(PR_USE_OPENSSL_OCSP)
# if defined(PR_SHARED_MODULE)
  pr_event_register(&tls_fscache_module, "core.module-unload",
    fscache_mod_unload_ev, NULL);
# endif /* !PR_SHARED_MODULE */

  /* Prepare our cache handler. */
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
  if (tls_ocsp_cache_register("fs", &ocsp_cache) < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_NOTICE, MOD_TLS_FSCACHE_VERSION
      ": notice: error registering 'fs' OCSP cache: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }
#endif /* PR_USE_OPENSSL_OCSP */

  return 0;
}

/* Module API tables
 */

module tls_fscache_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "tls_fscache",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  tls_fscache_init,

  /* Session initialization function */
  NULL,

  /* Module version */
  MOD_TLS_FSCACHE_VERSION
};
