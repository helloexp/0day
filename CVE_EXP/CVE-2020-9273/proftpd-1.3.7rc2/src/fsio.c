/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2019 The ProFTPD Project
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
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* ProFTPD virtual/modular file-system support */

#include "error.h"
#include "conf.h"
#include "privs.h"

#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#endif

#ifdef HAVE_SYS_VFS_H
# include <sys/vfs.h>
#endif

#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif

#ifdef HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#endif

#ifdef AIX3
# include <sys/statfs.h>
#endif

#ifdef HAVE_ACL_LIBACL_H
# include <acl/libacl.h>
#endif

/* We will reset timers in the progress callback every Nth iteration of the
 * callback when copying a file.
 */
static size_t copy_iter_count = 0;

#ifndef COPY_PROGRESS_NTH_ITER
# define COPY_PROGRESS_NTH_ITER       50000
#endif

/* For determining whether a file is on an NFS filesystem.  Note that
 * this value is Linux specific.  See Bug#3874 for details.
 */
#ifndef NFS_SUPER_MAGIC
# define NFS_SUPER_MAGIC	0x6969
#endif

typedef struct fsopendir fsopendir_t;

struct fsopendir {
  fsopendir_t *next,*prev;

  /* pool for this object's use */
  pool *pool;

  pr_fs_t *fsdir;
  DIR *dir;
};

static pr_fs_t *root_fs = NULL, *fs_cwd = NULL;
static array_header *fs_map = NULL;

static fsopendir_t *fsopendir_list;

static void *fs_cache_dir = NULL;
static pr_fs_t *fs_cache_fsdir = NULL;

/* Internal flag set whenever a new pr_fs_t has been added or removed, and
 * cleared once the fs_map has been scanned
 */
static unsigned char chk_fs_map = FALSE;

/* Virtual working directory */
static char vwd[PR_TUNABLE_PATH_MAX + 1] = "/";

static char cwd[PR_TUNABLE_PATH_MAX + 1] = "/";
static size_t cwd_len = 1;

static int fsio_guard_chroot = FALSE;
static unsigned long fsio_opts = 0UL;

/* Runtime enabling/disabling of mkdtemp(3) use. */
#ifdef HAVE_MKDTEMP
static int fsio_use_mkdtemp = TRUE;
#else
static int fsio_use_mkdtemp = FALSE;
#endif /* HAVE_MKDTEMP */

/* Runtime enabling/disabling of encoding of paths. */
static int use_encoding = TRUE;

static const char *trace_channel = "fsio";

/* Guard against attacks like "Roaring Beast" when we are chrooted.  See:
 *
 *  https://auscert.org.au/15286
 *  https://auscert.org.au/15526
 *
 * Currently, we guard the /etc and /lib directories.
 */
static int chroot_allow_path(const char *path) {
  size_t path_len;
  int res = 0;

  /* Note: we expect to get (and DO get) the absolute path here.  Should that
   * ever not be the case, this check will not work.
   */

  path_len = strlen(path);
  if (path_len < 4) {
    /* Path is not long enough to include one of the guarded directories. */
    return 0;
  }

  if (path_len == 4) {
    if (strcmp(path, "/etc") == 0 ||
        strcmp(path, "/lib") == 0) {
      res = -1;
    }

  } else {
    if (strncmp(path, "/etc/", 5) == 0 ||
        strncmp(path, "/lib/", 5) == 0) {
      res = -1;
    }
  }

  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "rejecting path '%s' within chroot '%s'",
      path, session.chroot_path);
    pr_log_debug(DEBUG2,
      "WARNING: attempt to use sensitive path '%s' within chroot '%s', "
      "rejecting", path, session.chroot_path);

    errno = EACCES;
  }

  return res;
}

/* Builtin/default "progress" callback for long-running file copies. */
static void copy_progress_cb(int nwritten) {
  int res;

  copy_iter_count++;
  if ((copy_iter_count % COPY_PROGRESS_NTH_ITER) != 0) {
    return;
  }

  /* Reset some of the Timeouts which might interfere, i.e. TimeoutIdle and
   * TimeoutNoDataTransfer.
   */

  res = pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
  if (res < 0) {
    pr_trace_msg(trace_channel, 14, "error resetting TimeoutIdle timer: %s",
      strerror(errno));
  }

  res = pr_timer_reset(PR_TIMER_NOXFER, ANY_MODULE);
  if (res < 0) {
    pr_trace_msg(trace_channel, 14,
      "error resetting TimeoutNoTransfer timer: %s", strerror(errno));
  }

  res = pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);
  if (res < 0) {
    pr_trace_msg(trace_channel, 14,
      "error resetting TimeoutStalled timer: %s", strerror(errno));
  }
}

/* The following static functions are simply wrappers for system functions
 */

static int sys_stat(pr_fs_t *fs, const char *path, struct stat *sbuf) {
  return stat(path, sbuf);
}

static int sys_fstat(pr_fh_t *fh, int fd, struct stat *sbuf) {
  return fstat(fd, sbuf);
}

static int sys_lstat(pr_fs_t *fs, const char *path, struct stat *sbuf) {
  return lstat(path, sbuf);
}

static int sys_rename(pr_fs_t *fs, const char *rnfm, const char *rnto) {
  int res;

  if (fsio_guard_chroot) {
    res = chroot_allow_path(rnfm);
    if (res < 0) {
      return -1;
    }

    res = chroot_allow_path(rnto);
    if (res < 0) {
      return -1;
    }
  }

  res = rename(rnfm, rnto);
  return res;
}

static int sys_unlink(pr_fs_t *fs, const char *path) {
  int res;

  if (fsio_guard_chroot) {
    res = chroot_allow_path(path);
    if (res < 0) {
      return -1;
    }
  }

  res = unlink(path);
  return res;
}

static int sys_open(pr_fh_t *fh, const char *path, int flags) {
  int res;

#ifdef O_BINARY
  /* On Cygwin systems, we need the open(2) equivalent of fopen(3)'s "b"
   * option.  Cygwin defines an O_BINARY flag for this purpose.
   */
  flags |= O_BINARY;
#endif

  if (fsio_guard_chroot) {
    /* If we are creating (or truncating) a file, then we need to check.
     * Note: should O_RDWR be added to this list?
     */
    if (flags & (O_APPEND|O_CREAT|O_TRUNC|O_WRONLY)) {
      res = chroot_allow_path(path);
      if (res < 0) {
        return -1;
      }
    }
  }

  res = open(path, flags, PR_OPEN_MODE);
  return res;
}

static int sys_close(pr_fh_t *fh, int fd) {
  return close(fd);
}

static int sys_read(pr_fh_t *fh, int fd, char *buf, size_t size) {
  return read(fd, buf, size);
}

static int sys_write(pr_fh_t *fh, int fd, const char *buf, size_t size) {
  return write(fd, buf, size);
}

static off_t sys_lseek(pr_fh_t *fh, int fd, off_t offset, int whence) {
  return lseek(fd, offset, whence);
}

static int sys_link(pr_fs_t *fs, const char *target_path,
    const char *link_path) {
  int res;

  if (fsio_guard_chroot) {
    res = chroot_allow_path(link_path);
    if (res < 0) {
      return -1;
    }
  }

  res = link(target_path, link_path);
  return res;
}

static int sys_symlink(pr_fs_t *fs, const char *target_path,
    const char *link_path) {
  int res;

  if (fsio_guard_chroot) {
    res = chroot_allow_path(link_path);
    if (res < 0) {
      return -1;
    }
  }

  res = symlink(target_path, link_path);
  return res;
}

static int sys_readlink(pr_fs_t *fs, const char *path, char *buf,
    size_t buflen) {
  return readlink(path, buf, buflen);
}

static int sys_ftruncate(pr_fh_t *fh, int fd, off_t len) {
  return ftruncate(fd, len);
}

static int sys_truncate(pr_fs_t *fs, const char *path, off_t len) {
  int res;

  if (fsio_guard_chroot) {
    res = chroot_allow_path(path);
    if (res < 0) {
      return -1;
    }
  }

  res = truncate(path, len);
  return res;
}

static int sys_chmod(pr_fs_t *fs, const char *path, mode_t mode) {
  int res;

  if (fsio_guard_chroot) {
    res = chroot_allow_path(path);
    if (res < 0) {
      return -1;
    }
  }

  res = chmod(path, mode);
  return res;
}

static int sys_fchmod(pr_fh_t *fh, int fd, mode_t mode) {
  return fchmod(fd, mode);
}

static int sys_chown(pr_fs_t *fs, const char *path, uid_t uid, gid_t gid) {
  int res;

  if (fsio_guard_chroot) {
    res = chroot_allow_path(path);
    if (res < 0) {
      return -1;
    }
  }

  res = chown(path, uid, gid);
  return res;
}

static int sys_fchown(pr_fh_t *fh, int fd, uid_t uid, gid_t gid) {
  return fchown(fd, uid, gid);
}

static int sys_lchown(pr_fs_t *fs, const char *path, uid_t uid, gid_t gid) {
  int res;

  if (fsio_guard_chroot) {
    res = chroot_allow_path(path);
    if (res < 0) {
      return -1;
    }
  }

  res = lchown(path, uid, gid);
  return res;
}

/* We provide our own equivalent of access(2) here, rather than using
 * access(2) directly, because access(2) uses the real IDs, rather than
 * the effective IDs, of the process.
 */
static int sys_access(pr_fs_t *fs, const char *path, int mode, uid_t uid,
    gid_t gid, array_header *suppl_gids) {
  struct stat st;

  if (pr_fsio_stat(path, &st) < 0) {
    return -1;
  }

  return pr_fs_have_access(&st, mode, uid, gid, suppl_gids);
}

static int sys_faccess(pr_fh_t *fh, int mode, uid_t uid, gid_t gid,
    array_header *suppl_gids) {
  return sys_access(fh->fh_fs, fh->fh_path, mode, uid, gid, suppl_gids);
}

static int sys_utimes(pr_fs_t *fs, const char *path, struct timeval *tvs) {
  int res;

  if (fsio_guard_chroot) {
    res = chroot_allow_path(path);
    if (res < 0) {
      return -1;
    }
  }

  res = utimes(path, tvs);
  return res;
}

static int sys_futimes(pr_fh_t *fh, int fd, struct timeval *tvs) {
#ifdef HAVE_FUTIMES
  int res;

  /* Check for an ENOSYS errno; if so, fallback to using sys_utimes.  Some
   * platforms will provide a futimes(2) stub which does not actually do
   * anything.
   */
  res = futimes(fd, tvs);
  if (res < 0 &&
      errno == ENOSYS) {
    return sys_utimes(fh->fh_fs, fh->fh_path, tvs);
  }

  return res;
#else
  return sys_utimes(fh->fh_fs, fh->fh_path, tvs);
#endif
}

static int sys_fsync(pr_fh_t *fh, int fd) {
  int res;

#ifdef HAVE_FSYNC
  res = fsync(fd);
#else
  errno = ENOSYS;
  res = -1;
#endif /* HAVE_FSYNC */

  return res;
}

static ssize_t sys_getxattr(pool *p, pr_fs_t *fs, const char *path,
    const char *name, void *val, size_t valsz) {
  ssize_t res;

  (void) p;

#ifdef PR_USE_XATTR
# if defined(HAVE_SYS_EXTATTR_H)
  res = extattr_get_file(path, EXTATTR_NAMESPACE_USER, name, val, valsz);
# elif defined(HAVE_SYS_XATTR_H)
#  if defined(XATTR_NOFOLLOW)
  res = getxattr(path, name, val, valsz, 0, 0);
#  else
  res = getxattr(path, name, val, valsz);
#  endif /* XATTR_NOFOLLOW */
# endif /* HAVE_SYS_XATTR_H */
#else
  (void) fs;
  (void) path;
  (void) name;
  (void) val;
  (void) valsz;
  errno = ENOSYS;
  res = -1;
#endif /* PR_USE_XATTR */

  return res;
}

static ssize_t sys_lgetxattr(pool *p, pr_fs_t *fs, const char *path,
    const char *name, void *val, size_t valsz) {
  ssize_t res;

  (void) p;

#ifdef PR_USE_XATTR
# if defined(HAVE_SYS_EXTATTR_H)
#  if defined(HAVE_EXTATTR_GET_LINK)
  res = extattr_get_link(path, EXTATTR_NAMESPACE_USER, name, val, valsz);
#  else
  res = extattr_get_file(path, EXTATTR_NAMESPACE_USER, name, val, valsz);
#  endif /* HAVE_EXTATTR_GET_LINK */
# elif defined(HAVE_SYS_XATTR_H)
#  if defined(HAVE_LGETXATTR)
  res = lgetxattr(path, name, val, valsz);
#  elif defined(XATTR_NOFOLLOW)
  res = getxattr(path, name, val, valsz, 0, XATTR_NOFOLLOW);
#  else
  res = getxattr(path, name, val, valsz);
#  endif /* HAVE_LGETXATTR */
# endif /* HAVE_SYS_XATTR_H */
#else
  (void) fs;
  (void) path;
  (void) name;
  (void) val;
  (void) valsz;
  errno = ENOSYS;
  res = -1;
#endif /* PR_USE_XATTR */

  return res;
}

static ssize_t sys_fgetxattr(pool *p, pr_fh_t *fh, int fd, const char *name,
    void *val, size_t valsz) {
  ssize_t res;

  (void) p;

#ifdef PR_USE_XATTR
# if defined(HAVE_SYS_EXTATTR_H)
  res = extattr_get_fd(fd, EXTATTR_NAMESPACE_USER, name, val, valsz);
# elif defined(HAVE_SYS_XATTR_H)
#  if defined(XATTR_NOFOLLOW)
  res = fgetxattr(fd, name, val, valsz, 0, 0);
#  else
  res = fgetxattr(fd, name, val, valsz);
#  endif /* XATTR_NOFOLLOW */
# endif /* HAVE_SYS_XATTR_H */
#else
  (void) fh;
  (void) fd;
  (void) name;
  (void) val;
  (void) valsz;
  errno = ENOSYS;
  res = -1;
#endif /* PR_USE_XATTR */

  return res;
}

#ifdef PR_USE_XATTR
static array_header *parse_xattr_namelist(pool *p, char *namelist, size_t sz) {
  array_header *names;
  char *ptr;

  names = make_array(p, 0, sizeof(char *));
  ptr = namelist;

# if defined(HAVE_SYS_EXTATTR_H)
  /* BSD style name lists use a one-byte length prefix (limiting xattr names
   * to a maximum length of 255 bytes), followed by the name, without any
   * terminating NUL.
   */
  while (sz > 0) {
    unsigned char len;

    pr_signals_handle();

    len = (unsigned char) *ptr;
    ptr++;
    sz--;

    *((char **) push_array(names)) = pstrndup(p, ptr, len);

    ptr += len;
    sz -= len;
  }

# elif defined(HAVE_SYS_XATTR_H)
  /* Linux/MacOSX style name lists use NUL-terminated xattr names. */
  while (sz > 0) {
    char *ptr2;
    size_t len;

    pr_signals_handle();

    for (ptr2 = ptr; *ptr2; ptr2++);
    len = ptr2 - ptr;
    *((char **) push_array(names)) = pstrndup(p, ptr, len);

    ptr = ptr2 + 1;
    sz -= (len + 1);
  }
# endif /* HAVE_SYS_XATTR_H */

  return names;
}

static ssize_t unix_listxattr(const char *path, char *namelist, size_t len) {
  ssize_t res;

#if defined(HAVE_SYS_EXTATTR_H)
  res = extattr_list_file(path, EXTATTR_NAMESPACE_USER, namelist, len);
#elif defined(HAVE_SYS_XATTR_H)
# if defined(XATTR_NOFOLLOW)
  res = listxattr(path, namelist, len, 0);
# else
  res = listxattr(path, namelist, len);
# endif /* XATTR_NOFOLLOW */
#endif /* HAVE_SYS_XATTR_H */

  return res;
}

static ssize_t unix_llistxattr(const char *path, char *namelist, size_t len) {
  ssize_t res;

# if defined(HAVE_SYS_EXTATTR_H)
#  if defined(HAVE_EXTATTR_LIST_LINK)
  res = extattr_list_link(path, EXTATTR_NAMESPACE_USER, namelist, len);
#  else
  res = extattr_list_file(path, EXTATTR_NAMESPACE_USER, namelist, len);
#  endif /* HAVE_EXTATTR_LIST_LINK */
# elif defined(HAVE_SYS_XATTR_H)
#  if defined(HAVE_LLISTXATTR)
  res = llistxattr(path, namelist, len);
#  elif defined(XATTR_NOFOLLOW)
  res = listxattr(path, namelist, len, XATTR_NOFOLLOW);
#  else
  res = listxattr(path, namelist, len);
#  endif /* XATTR_NOFOLLOW */
# endif /* HAVE_SYS_XATTR_H */

  return res;
}

static ssize_t unix_flistxattr(int fd, char *namelist, size_t len) {
  ssize_t res;

# if defined(HAVE_SYS_EXTATTR_H)
  res = extattr_list_fd(fd, EXTATTR_NAMESPACE_USER, namelist, len);
# elif defined(HAVE_SYS_XATTR_H)
#  if defined(XATTR_NOFOLLOW)
  res = flistxattr(fd, namelist, len, 0);
#  else
  res = flistxattr(fd, namelist, len);
#  endif /* XATTR_NOFOLLOW */
# endif /* HAVE_SYS_XATTR_H */

  return res;
}
#endif /* PR_USE_XATTR */

static int sys_listxattr(pool *p, pr_fs_t *fs, const char *path,
    array_header **names) {
  ssize_t res;
  char *namelist = NULL;
  size_t len = 0;

#ifdef PR_USE_XATTR
  /* We need to handle the different formats of namelists that listxattr et al
   * can provide.  On *BSDs, the namelist buffer uses length prefixes and no
   * terminating NULs; on Linux/Mac, the namelist buffer uses ONLY
   * NUL-terminated names.
   *
   * Thus we ALWAYS provide all the available attribute names, by first
   * querying for the full namelist buffer size, allocating that out of
   * given pool, querying for the names (using the buffer), and then parsing
   * them into an array.
   */

  res = unix_listxattr(path, NULL, 0);
  if (res < 0) {
    return -1;
  }

  len = res;
  namelist = palloc(p, len);

  res = unix_listxattr(path, namelist, len);
  if (res < 0) {
    return -1;
  }

  *names = parse_xattr_namelist(p, namelist, len);
  if (pr_trace_get_level(trace_channel) >= 15) {
    register unsigned int i;
    unsigned int count;
    const char **attr_names;

    count = (*names)->nelts;
    attr_names = (*names)->elts;

    pr_trace_msg(trace_channel, 15, "listxattr: found %d xattr names for '%s'",
      count, path);
    for (i = 0; i < count; i++) {
      pr_trace_msg(trace_channel, 15, " [%u]: '%s'", i, attr_names[i]);
    }
  }

  res = (*names)->nelts;

#else
  (void) fs;
  (void) path;
  (void) names;
  (void) namelist;
  (void) len;
  errno = ENOSYS;
  res = -1;
#endif /* PR_USE_XATTR */

  return (int) res;
}

static int sys_llistxattr(pool *p, pr_fs_t *fs, const char *path,
    array_header **names) {
  ssize_t res;
  char *namelist = NULL;
  size_t len = 0;

#ifdef PR_USE_XATTR
  /* See sys_listxattr for a description of why we use this approach. */
  res = unix_llistxattr(path, NULL, 0);
  if (res < 0) {
    return -1;
  }

  len = res;
  namelist = palloc(p, len);

  res = unix_llistxattr(path, namelist, len);
  if (res < 0) {
    return -1;
  }

  *names = parse_xattr_namelist(p, namelist, len);
  if (pr_trace_get_level(trace_channel) >= 15) {
    register unsigned int i;
    unsigned int count;
    const char **attr_names;

    count = (*names)->nelts;
    attr_names = (*names)->elts;

    pr_trace_msg(trace_channel, 15, "llistxattr: found %d xattr names for '%s'",
      count, path);
    for (i = 0; i < count; i++) {
      pr_trace_msg(trace_channel, 15, " [%u]: '%s'", i, attr_names[i]);
    }
  }

  res = (*names)->nelts;

#else
  (void) fs;
  (void) path;
  (void) names;
  (void) namelist;
  (void) len;
  errno = ENOSYS;
  res = -1;
#endif /* PR_USE_XATTR */

  return (int) res;
}

static int sys_flistxattr(pool *p, pr_fh_t *fh, int fd, array_header **names) {
  ssize_t res;
  char *namelist = NULL;
  size_t len = 0;

#ifdef PR_USE_XATTR
  /* See sys_listxattr for a description of why we use this approach. */
  res = unix_flistxattr(fd, NULL, 0);
  if (res < 0) {
    return -1;
  }

  len = res;
  namelist = palloc(p, len);

  res = unix_flistxattr(fd, namelist, len);
  if (res < 0) {
    return -1;
  }

  *names = parse_xattr_namelist(p, namelist, len);
  if (pr_trace_get_level(trace_channel) >= 15) {
    register unsigned int i;
    unsigned int count;
    const char **attr_names;

    count = (*names)->nelts;
    attr_names = (*names)->elts;

    pr_trace_msg(trace_channel, 15, "flistxattr: found %d xattr names for '%s'",
      count, fh->fh_path);
    for (i = 0; i < count; i++) {
      pr_trace_msg(trace_channel, 15, " [%u]: '%s'", i, attr_names[i]);
    }
  }

  res = (*names)->nelts;

#else
  (void) fh;
  (void) fd;
  (void) names;
  (void) namelist;
  (void) len;
  errno = ENOSYS;
  res = -1;
#endif /* PR_USE_XATTR */

  return (int) res;
}

static int sys_removexattr(pool *p, pr_fs_t *fs, const char *path,
    const char *name) {
  int res;

  (void) p;

#ifdef PR_USE_XATTR
# if defined(HAVE_SYS_EXTATTR_H)
  res = extattr_delete_file(path, EXTATTR_NAMESPACE_USER, name);
# elif defined(HAVE_SYS_XATTR_H)
#  if defined(XATTR_NOFOLLOW)
  res = removexattr(path, name, 0);
#  else
  res = removexattr(path, name);
#  endif /* XATTR_NOFOLLOW */
# endif /* HAVE_SYS_XATTR_H */
#else
  (void) fs;
  (void) path;
  (void) name;
  errno = ENOSYS;
  res = -1;
#endif /* PR_USE_XATTR */

  return res;
}

static int sys_lremovexattr(pool *p, pr_fs_t *fs, const char *path,
    const char *name) {
  int res;

  (void) p;

#ifdef PR_USE_XATTR
# if defined(HAVE_SYS_EXTATTR_H)
#  if defined(HAVE_EXTATTR_DELETE_LINK)
  res = extattr_delete_link(path, EXTATTR_NAMESPACE_USER, name);
#  else
  res = extattr_delete_file(path, EXTATTR_NAMESPACE_USER, name);
#  endif /* HAVE_EXTATTR_DELETE_LINK */
# elif defined(HAVE_SYS_XATTR_H)
#  if defined(HAVE_LREMOVEXATTR)
  res = lremovexattr(path, name);
#  elif defined(XATTR_NOFOLLOW)
  res = removexattr(path, name, XATTR_NOFOLLOW);
#  else
  res = removexattr(path, name);
#  endif /* XATTR_NOFOLLOW */
# endif /* HAVE_SYS_XATTR_H */
#else
  (void) fs;
  (void) path;
  (void) name;
  errno = ENOSYS;
  res = -1;
#endif /* PR_USE_XATTR */

  return res;
}

static int sys_fremovexattr(pool *p, pr_fh_t *fh, int fd, const char *name) {
  int res;

  (void) p;

#ifdef PR_USE_XATTR
# if defined(HAVE_SYS_EXTATTR_H)
  res = extattr_delete_fd(fd, EXTATTR_NAMESPACE_USER, name);
# elif defined(HAVE_SYS_XATTR_H)
#  if defined(XATTR_NOFOLLOW)
  res = fremovexattr(fd, name, 0);
#  else
  res = fremovexattr(fd, name);
#  endif /* XATTR_NOFOLLOW */
# endif /* HAVE_SYS_XATTR_H */
#else
  (void) fh;
  (void) fd;
  (void) name;
  errno = ENOSYS;
  res = -1;
#endif /* PR_USE_XATTR */

  return res;
}

#if defined(PR_USE_XATTR) && defined(HAVE_SYS_XATTR_H)
/* Map the given flags onto the sys/xattr.h flags */
static int get_setxattr_flags(int fsio_flags) {
  int xattr_flags = 0;

  /* If both CREATE and REPLACE are set, use a value of zero; per the
   * man pages, this value gives the desired "create or replace" semantics.
   * Right?
   */

  if (fsio_flags & PR_FSIO_XATTR_FL_CREATE) {
#if defined(XATTR_CREATE)
    xattr_flags = XATTR_CREATE;
#endif /* XATTR_CREATE */

    if (fsio_flags & PR_FSIO_XATTR_FL_REPLACE) {
      xattr_flags = 0;
    }

  } else if (fsio_flags & PR_FSIO_XATTR_FL_REPLACE) {
#if defined(XATTR_REPLACE)
    xattr_flags = XATTR_REPLACE;
#endif /* XATTR_REPLACE */
  }

  return xattr_flags;
}
#endif /* PR_USE_XATTR and <sys/xattr.h> */

static int sys_setxattr(pool *p, pr_fs_t *fs, const char *path,
    const char *name, void *val, size_t valsz, int flags) {
  int res, xattr_flags = 0;

  (void) p;

#ifdef PR_USE_XATTR
# if defined(HAVE_SYS_EXTATTR_H)
  (void) xattr_flags;
  res = extattr_set_file(path, EXTATTR_NAMESPACE_USER, name, val, valsz);

# elif defined(HAVE_SYS_XATTR_H)
  xattr_flags = get_setxattr_flags(flags);

#  if defined(XATTR_NOFOLLOW)
  res = setxattr(path, name, val, valsz, 0, xattr_flags);
#  else
  res = setxattr(path, name, val, valsz, xattr_flags);
#  endif /* XATTR_NOFOLLOW */
# endif /* HAVE_SYS_XATTR_H */
#else
  (void) fs;
  (void) path;
  (void) name;
  (void) val;
  (void) valsz;
  (void) flags;
  (void) xattr_flags;
  errno = ENOSYS;
  res = -1;
#endif /* PR_USE_XATTR */

  return res;
}

static int sys_lsetxattr(pool *p, pr_fs_t *fs, const char *path,
    const char *name, void *val, size_t valsz, int flags) {
  int res, xattr_flags = 0;

  (void) p;

#ifdef PR_USE_XATTR
# if defined(HAVE_SYS_EXTATTR_H)
  (void) xattr_flags;
#  if defined(HAVE_EXTATTR_SET_LINK)
  res = extattr_set_link(path, EXTATTR_NAMESPACE_USER, name, val, valsz);
#  else
  res = extattr_set_file(path, EXTATTR_NAMESPACE_USER, name, val, valsz);
#  endif /* HAVE_EXTATTR_SET_LINK */
# elif defined(HAVE_SYS_XATTR_H)
  xattr_flags = get_setxattr_flags(flags);

#  if defined(HAVE_LSETXATTR)
  res = lsetxattr(path, name, val, valsz, xattr_flags);
#  elif defined(XATTR_NOFOLLOW)
  xattr_flags |= XATTR_NOFOLLOW;
  res = setxattr(path, name, val, valsz, 0, xattr_flags);
#  else
  res = setxattr(path, name, val, valsz, xattr_flags);
#  endif /* XATTR_NOFOLLOW */
# endif /* HAVE_SYS_XATTR_H */
#else
  (void) fs;
  (void) path;
  (void) name;
  (void) val;
  (void) valsz;
  (void) flags;
  (void) xattr_flags;
  errno = ENOSYS;
  res = -1;
#endif /* PR_USE_XATTR */

  return res;
}

static int sys_fsetxattr(pool *p, pr_fh_t *fh, int fd, const char *name,
    void *val, size_t valsz, int flags) {
  int res, xattr_flags = 0;

  (void) p;

#ifdef PR_USE_XATTR
# if defined(HAVE_SYS_EXTATTR_H)
  (void) xattr_flags;
  res = extattr_set_fd(fd, EXTATTR_NAMESPACE_USER, name, val, valsz);

# elif defined(HAVE_SYS_XATTR_H)
  xattr_flags = get_setxattr_flags(flags);

#  if defined(XATTR_NOFOLLOW)
  res = fsetxattr(fd, name, val, valsz, 0, xattr_flags);
#  else
  res = fsetxattr(fd, name, val, valsz, xattr_flags);
#  endif /* XATTR_NOFOLLOW */
# endif /* HAVE_SYS_XATTR_H */
#else
  (void) fh;
  (void) fd;
  (void) name;
  (void) val;
  (void) valsz;
  (void) flags;
  (void) xattr_flags;
  errno = ENOSYS;
  res = -1;
#endif /* PR_USE_XATTR */

  return res;
}

static int sys_chroot(pr_fs_t *fs, const char *path) {
  if (chroot(path) < 0) {
    return -1;
  }

  session.chroot_path = (char *) path;
  return 0;
}

static int sys_chdir(pr_fs_t *fs, const char *path) {
  if (chdir(path) < 0) {
    return -1;
  }

  pr_fs_setcwd(path);
  return 0;
}

static void *sys_opendir(pr_fs_t *fs, const char *path) {
  return opendir(path);
}

static int sys_closedir(pr_fs_t *fs, void *dir) {
  return closedir((DIR *) dir);
}

static struct dirent *sys_readdir(pr_fs_t *fs, void *dir) {
  return readdir((DIR *) dir);
}

static int sys_mkdir(pr_fs_t *fs, const char *path, mode_t mode) {
  int res;

  if (fsio_guard_chroot) {
    res = chroot_allow_path(path);
    if (res < 0) {
      return -1;
    }
  }

  res = mkdir(path, mode);
  return res;
}

static int sys_rmdir(pr_fs_t *fs, const char *path) {
  int res;

  if (fsio_guard_chroot) {
    res = chroot_allow_path(path);
    if (res < 0) {
      return -1;
    }
  }

  res = rmdir(path);
  return res;
}

static int fs_cmp(const void *a, const void *b) {
  pr_fs_t *fsa, *fsb;

  if (a == NULL) {
    if (b == NULL) {
      return 0;
    }

    return 1;

  } else {
    if (b == NULL) {
      return -1;
    }
  }

  fsa = *((pr_fs_t **) a);
  fsb = *((pr_fs_t **) b);

  return strcmp(fsa->fs_path, fsb->fs_path);
}

/* Statcache stuff */
struct fs_statcache {
  pool *sc_pool;
  struct stat sc_stat;
  int sc_errno;
  int sc_retval;
  time_t sc_cached_ts;
};

struct fs_statcache_evict_data {
  time_t now;
  time_t max_age;
  pr_table_t *cache_tab;
};

static const char *statcache_channel = "fs.statcache";
static pool *statcache_pool = NULL;
static unsigned int statcache_size = 0;
static unsigned int statcache_max_age = 0;
static unsigned int statcache_flags = 0;

/* We need to maintain two different caches: one for stat(2) data, and one
 * for lstat(2) data.  For some files (e.g. symlinks), the struct stat data
 * for the same path will be different for the two system calls.
 */
static pr_table_t *stat_statcache_tab = NULL;
static pr_table_t *lstat_statcache_tab = NULL;

#define fs_cache_lstat(f, p, s) cache_stat((f), (p), (s), FSIO_FILE_LSTAT)
#define fs_cache_stat(f, p, s) cache_stat((f), (p), (s), FSIO_FILE_STAT)

static const struct fs_statcache *fs_statcache_get(pr_table_t *cache_tab,
    const char *path, size_t path_len, time_t now) {
  const struct fs_statcache *sc = NULL;

  if (pr_table_count(cache_tab) == 0) {
    errno = EPERM;
    return NULL;
  }

  sc = pr_table_get(cache_tab, path, NULL);
  if (sc != NULL) {
    time_t age;

    /* If this item hasn't expired yet, return it, otherwise, remove it. */
    age = now - sc->sc_cached_ts;
    if (age <= statcache_max_age) {
      pr_trace_msg(statcache_channel, 19,
        "using cached entry for '%s' (age %lu %s)", path,
        (unsigned long) age, age != 1 ? "secs" : "sec");
      return sc;
    }

    pr_trace_msg(statcache_channel, 14,
      "entry for '%s' expired (age %lu %s > max age %lu), removing", path,
      (unsigned long) age, age != 1 ? "secs" : "sec",
      (unsigned long) statcache_max_age);
    (void) pr_table_remove(cache_tab, path, NULL);
    destroy_pool(sc->sc_pool);
  }

  errno = ENOENT;
  return NULL;
}

static int fs_statcache_evict_expired(const void *key_data, size_t key_datasz,
    const void *value_data, size_t value_datasz, void *user_data) {
  const struct fs_statcache *sc;
  struct fs_statcache_evict_data *evict_data;
  time_t age;
  pr_table_t *cache_tab = NULL;

  sc = value_data;
  evict_data = user_data;

  cache_tab = evict_data->cache_tab;
  age = evict_data->now - sc->sc_cached_ts;
  if (age > evict_data->max_age) {
    pr_trace_msg(statcache_channel, 14,
      "entry for '%s' expired (age %lu %s > max age %lu), evicting",
      (char *) key_data, (unsigned long) age, age != 1 ? "secs" : "sec",
      (unsigned long) evict_data->max_age);
    (void) pr_table_kremove(cache_tab, key_data, key_datasz, NULL);
    destroy_pool(sc->sc_pool);
  }

  return 0;
}

static int fs_statcache_evict(pr_table_t *cache_tab, time_t now) {
  int res, table_count;
  struct fs_statcache_evict_data evict_data;

  /* We try to make room in two passes.  First, evict any item that has
   * exceeded the maximum age.  After that, if we are still not low enough,
   * lower the maximum age, and try again.  If not enough room by then, then
   * we'll try again on the next stat.
   */

  evict_data.now = now;
  evict_data.max_age = statcache_max_age;
  evict_data.cache_tab = cache_tab;

  res = pr_table_do(cache_tab, fs_statcache_evict_expired, &evict_data,
    PR_TABLE_DO_FL_ALL);
  if (res < 0) {
    pr_trace_msg(statcache_channel, 4,
      "error evicting expired items: %s", strerror(errno));
  }

  table_count = pr_table_count(cache_tab);
  if (table_count < 0 ||
      (unsigned int) table_count < statcache_size) {
    return 0;
  }

  /* Try for a shorter max age. */
  if (statcache_max_age > 10) {
    evict_data.max_age = (statcache_max_age - 10);
    res = pr_table_do(cache_tab, fs_statcache_evict_expired, &evict_data,
      PR_TABLE_DO_FL_ALL);
    if (res < 0) {
      pr_trace_msg(statcache_channel, 4,
        "error evicting expired items: %s", strerror(errno));
    }
  }

  table_count = pr_table_count(cache_tab);
  if (table_count < 0 ||
      (unsigned int) table_count < statcache_size) {
    return 0;
  }

  pr_trace_msg(statcache_channel, 14,
    "still not enough room in cache (size %d >= max %d)",
    pr_table_count(cache_tab), statcache_size);
  errno = EPERM;
  return -1;
}

/* Returns 1 if we successfully added a cache entry, 0 if not, and -1 if
 * there was an error.
 */
static int fs_statcache_add(pr_table_t *cache_tab, const char *path,
    size_t path_len, struct stat *st, int xerrno, int retval, time_t now) {
  int res, table_count;
  pool *sc_pool;
  struct fs_statcache *sc;

  if (statcache_size == 0 ||
      statcache_max_age == 0) {
    /* Caching disabled; nothing to do here. */
    return 0;
  }

  table_count = pr_table_count(cache_tab);
  if (table_count > 0 &&
      (unsigned int) table_count >= statcache_size) {
    /* We've reached capacity, and need to evict some items to make room. */
    if (fs_statcache_evict(cache_tab, now) < 0) {
      pr_trace_msg(statcache_channel, 8,
        "unable to evict enough items from the cache: %s", strerror(errno));
    }
  }

  sc_pool = make_sub_pool(statcache_pool);
  pr_pool_tag(sc_pool, "FS statcache entry pool");
  sc = pcalloc(sc_pool, sizeof(struct fs_statcache));
  sc->sc_pool = sc_pool;
  memcpy(&(sc->sc_stat), st, sizeof(struct stat));
  sc->sc_errno = xerrno;
  sc->sc_retval = retval;
  sc->sc_cached_ts = now;

  res = pr_table_add(cache_tab, pstrndup(sc_pool, path, path_len), sc,
    sizeof(struct fs_statcache *));
  if (res < 0) {
    int tmp_errno = errno;

    if (tmp_errno == EEXIST) {
      res = 0;
    }

    destroy_pool(sc->sc_pool);
    errno = tmp_errno;
  }

  return (res == 0 ? 1 : res);
}

static int cache_stat(pr_fs_t *fs, const char *path, struct stat *st,
    unsigned int op) {
  int res = -1, retval, xerrno = 0;
  char cleaned_path[PR_TUNABLE_PATH_MAX+1], pathbuf[PR_TUNABLE_PATH_MAX+1];
  int (*mystat)(pr_fs_t *, const char *, struct stat *) = NULL;
  size_t path_len;
  pr_table_t *cache_tab = NULL;
  const struct fs_statcache *sc = NULL;
  time_t now;

  now = time(NULL);
  memset(cleaned_path, '\0', sizeof(cleaned_path));
  memset(pathbuf, '\0', sizeof(pathbuf));

  if (fs->non_std_path == FALSE) {
    /* Use only absolute path names.  Construct them, if given a relative
     * path, based on cwd.  This obviates the need for something like
     * realpath(3), which only introduces more stat(2) system calls.
     */
    if (*path != '/') {
      size_t pathbuf_len;

      sstrcat(pathbuf, cwd, sizeof(pathbuf)-1);
      pathbuf_len = cwd_len;

      /* If the cwd is "/", we don't need to duplicate the path separator.
       * On some systems (e.g. Cygwin), this duplication can cause problems,
       * as the path may then have different semantics.
       */
      if (strncmp(cwd, "/", 2) != 0) {
        sstrcat(pathbuf + pathbuf_len, "/", sizeof(pathbuf) - pathbuf_len - 1);
        pathbuf_len++;
      }

      /* If the given directory is ".", then we don't need to append it. */
      if (strncmp(path, ".", 2) != 0) {
        sstrcat(pathbuf + pathbuf_len, path, sizeof(pathbuf)- pathbuf_len - 1);
      }

    } else {
      sstrncpy(pathbuf, path, sizeof(pathbuf)-1);
    }

    pr_fs_clean_path2(pathbuf, cleaned_path, sizeof(cleaned_path)-1, 0);

  } else {
    sstrncpy(cleaned_path, path, sizeof(cleaned_path)-1);
  }

  /* Determine which filesystem function to use, stat() or lstat() */
  if (op == FSIO_FILE_STAT) {
    mystat = fs->stat ? fs->stat : sys_stat;
    cache_tab = stat_statcache_tab;

  } else {
    mystat = fs->lstat ? fs->lstat : sys_lstat;
    cache_tab = lstat_statcache_tab;
  }

  path_len = strlen(cleaned_path);

  sc = fs_statcache_get(cache_tab, cleaned_path, path_len, now);
  if (sc != NULL) {

    /* Update the given struct stat pointer with the cached info */
    memcpy(st, &(sc->sc_stat), sizeof(struct stat));

    pr_trace_msg(trace_channel, 18,
      "using cached stat for %s for path '%s' (retval %d, errno %s)",
      op == FSIO_FILE_STAT ? "stat()" : "lstat()", path, sc->sc_retval,
      strerror(sc->sc_errno));

    /* Use the cached errno as well */
    errno = sc->sc_errno;

    return sc->sc_retval;
  }

  pr_trace_msg(trace_channel, 8, "using %s %s for path '%s'",
    fs->fs_name, op == FSIO_FILE_STAT ? "stat()" : "lstat()", path);
  retval = mystat(fs, cleaned_path, st);
  xerrno = errno;

  if (retval == 0) {
    xerrno = 0;
  }

  /* Update the cache */
  res = fs_statcache_add(cache_tab, cleaned_path, path_len, st, xerrno, retval,     now);
  if (res < 0) {
    pr_trace_msg(trace_channel, 8,
      "error adding cached stat for '%s': %s", cleaned_path, strerror(errno));

  } else if (res > 0) {
    pr_trace_msg(trace_channel, 18,
      "added cached stat for path '%s' (retval %d, errno %s)", path,
      retval, strerror(xerrno));
  }

  if (retval < 0) {
    errno = xerrno;
  }

  return retval;
}

/* Lookup routines */

/* Necessary prototype for static function */
static pr_fs_t *lookup_file_canon_fs(const char *, char **, int);

/* lookup_dir_fs() is called when we want to perform some sort of directory
 * operation on a directory or file.  A "closest" match algorithm is used.  If
 * the lookup fails or is not "close enough" (i.e. the final target does not
 * exactly match an existing filesystem handle) scan the list of fs_matches for
 * matchable targets and call any callback functions, then rescan the pr_fs_t
 * list.  The rescan is performed in case any modules registered pr_fs_ts
 * during the hit.
 */
static pr_fs_t *lookup_dir_fs(const char *path, int op) {
  char buf[PR_TUNABLE_PATH_MAX + 1], tmp_path[PR_TUNABLE_PATH_MAX + 1];
  pr_fs_t *fs = NULL;
  int exact = FALSE;
  size_t tmp_pathlen = 0;

  memset(buf, '\0', sizeof(buf));
  memset(tmp_path, '\0', sizeof(tmp_path));
  sstrncpy(buf, path, sizeof(buf));

  /* Check if the given path is an absolute path.  Since there may be
   * alternate fs roots, this is not a simple check.  If the path is
   * not absolute, prepend the current location.
   */
  if (pr_fs_valid_path(path) < 0) {
    if (pr_fs_dircat(tmp_path, sizeof(tmp_path), cwd, buf) < 0) {
      return NULL;
    }

  } else {
    sstrncpy(tmp_path, buf, sizeof(tmp_path));
  }

  /* Make sure that if this is a directory operation, the path being
   * search ends in a trailing slash -- this is how files and directories
   * are differentiated in the fs_map.
   */
  tmp_pathlen = strlen(tmp_path);
  if ((FSIO_DIR_COMMON & op) &&
      tmp_pathlen > 0 &&
      tmp_pathlen < sizeof(tmp_path) &&
      tmp_path[tmp_pathlen - 1] != '/') {
    sstrcat(tmp_path, "/", sizeof(tmp_path));
  }

  fs = pr_get_fs(tmp_path, &exact);
  if (fs == NULL) {
    fs = root_fs;
  }

  return fs;
}

/* lookup_file_fs() performs the same function as lookup_dir_fs, however
 * because we are performing a file lookup, the target is the subdirectory
 * _containing_ the actual target.  A basic optimization is used here,
 * if the path contains no '/' characters, fs_cwd is returned.
 */
static pr_fs_t *lookup_file_fs(const char *path, char **deref, int op) {
  pr_fs_t *fs = fs_cwd;
  struct stat st;
  int (*mystat)(pr_fs_t *, const char *, struct stat *) = NULL, res;
  char linkbuf[PR_TUNABLE_PATH_MAX + 1];

  if (strchr(path, '/') != NULL) {
    return lookup_dir_fs(path, op);
  }

  /* Determine which function to use, stat() or lstat(). */
  if (op == FSIO_FILE_STAT) {
    while (fs && fs->fs_next && !fs->stat) {
      fs = fs->fs_next;
    }

    mystat = fs->stat;

  } else {
    while (fs && fs->fs_next && !fs->lstat) {
      fs = fs->fs_next;
    }

    mystat = fs->lstat;
  }

  res = mystat(fs, path, &st);
  if (res < 0) {
    return fs;
  }

  if (!S_ISLNK(st.st_mode)) {
    return fs;
  }

  /* The given path is a symbolic link, in which case we need to find
   * the actual path referenced, and return an pr_fs_t for _that_ path
   */

  /* Three characters are reserved at the end of linkbuf for some path
   * characters (and a trailing NUL).
   */
  if (fs->readlink != NULL) {
    res = (fs->readlink)(fs, path, &linkbuf[2], sizeof(linkbuf)-3);

  } else {
    errno = ENOSYS;
    res = -1;
  }

  if (res != -1) {
    linkbuf[res] = '\0';

    if (strchr(linkbuf, '/') == NULL) {
      if (res + 3 > PR_TUNABLE_PATH_MAX) {
        res = PR_TUNABLE_PATH_MAX - 3;
      }

      memmove(&linkbuf[2], linkbuf, res + 1);

      linkbuf[res+2] = '\0';
      linkbuf[0] = '.';
      linkbuf[1] = '/';
      return lookup_file_canon_fs(linkbuf, deref, op);
    }
  }

  /* What happens if fs_cwd->readlink is NULL, or readlink() returns -1?
   * I guess, for now, we punt, and return fs_cwd.
   */
  return fs_cwd;
}

static pr_fs_t *lookup_file_canon_fs(const char *path, char **deref, int op) {
  static char workpath[PR_TUNABLE_PATH_MAX + 1];

  memset(workpath,'\0',sizeof(workpath));

  if (pr_fs_resolve_partial(path, workpath, sizeof(workpath)-1,
      FSIO_FILE_OPEN) == -1) {
    if (*path == '/' || *path == '~') {
      if (pr_fs_interpolate(path, workpath, sizeof(workpath)-1) != -1) {
        sstrncpy(workpath, path, sizeof(workpath));
      }

    } else {
      if (pr_fs_dircat(workpath, sizeof(workpath), cwd, path) < 0) {
        return NULL;
      }
    }
  }

  if (deref) {
    *deref = workpath;
  }

  return lookup_file_fs(workpath, deref, op);
}

/* FS Statcache API */

static void statcache_dumpf(const char *fmt, ...) {
  char buf[PR_TUNABLE_BUFFER_SIZE];
  va_list msg;

  memset(buf, '\0', sizeof(buf));

  va_start(msg, fmt);
  pr_vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  buf[sizeof(buf)-1] = '\0';
  (void) pr_trace_msg(statcache_channel, 9, "%s", buf);
}

void pr_fs_statcache_dump(void) {
  pr_table_dump(statcache_dumpf, stat_statcache_tab);
  pr_table_dump(statcache_dumpf, lstat_statcache_tab);
}

void pr_fs_statcache_free(void) {
  if (stat_statcache_tab != NULL) {
    int size;

    size = pr_table_count(stat_statcache_tab);
    pr_trace_msg(statcache_channel, 11,
      "resetting stat(2) statcache (clearing %d %s)", size,
      size != 1 ? "entries" : "entry");
    pr_table_empty(stat_statcache_tab);
    pr_table_free(stat_statcache_tab);
    stat_statcache_tab = NULL;
  }

  if (lstat_statcache_tab != NULL) {
    int size;

    size = pr_table_count(lstat_statcache_tab);
    pr_trace_msg(statcache_channel, 11,
      "resetting lstat(2) statcache (clearing %d %s)", size,
      size != 1 ? "entries" : "entry");
    pr_table_empty(lstat_statcache_tab);
    pr_table_free(lstat_statcache_tab);
    lstat_statcache_tab = NULL;
  }

  /* Note: we do not need to explicitly destroy each entry in the statcache
   * tables, since ALL entries are allocated out of this statcache_pool.
   * And we destroy this pool here.  Much easier cleanup that way.
   */
  if (statcache_pool != NULL) {
    destroy_pool(statcache_pool);
    statcache_pool = NULL;
  }
}

void pr_fs_statcache_reset(void) {
  pr_fs_statcache_free();

  if (statcache_pool == NULL) {
    statcache_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(statcache_pool, "FS Statcache Pool");
  }

  stat_statcache_tab = pr_table_alloc(statcache_pool, 0);
  lstat_statcache_tab = pr_table_alloc(statcache_pool, 0);
}

int pr_fs_statcache_set_policy(unsigned int size, unsigned int max_age,
    unsigned int flags) {

  statcache_size = size;
  statcache_max_age = max_age;
  statcache_flags = flags;

  return 0;
}

int pr_fs_clear_cache2(const char *path) {
  int res;

  (void) pr_event_generate("fs.statcache.clear", path);

  if (pr_table_count(stat_statcache_tab) == 0 &&
      pr_table_count(lstat_statcache_tab) == 0) {
    return 0;
  }

  if (path != NULL) {
    char cleaned_path[PR_TUNABLE_PATH_MAX+1], pathbuf[PR_TUNABLE_PATH_MAX+1];
    int lstat_count, stat_count;

    if (*path != '/') {
      size_t pathbuf_len;

      memset(cleaned_path, '\0', sizeof(cleaned_path));
      memset(pathbuf, '\0', sizeof(pathbuf));

      sstrcat(pathbuf, cwd, sizeof(pathbuf)-1);
      pathbuf_len = cwd_len;

      if (strncmp(cwd, "/", 2) != 0) {
        sstrcat(pathbuf + pathbuf_len, "/", sizeof(pathbuf) - pathbuf_len - 1);
        pathbuf_len++;
      }

      if (strncmp(path, ".", 2) != 0) {
        sstrcat(pathbuf + pathbuf_len, path, sizeof(pathbuf)- pathbuf_len - 1);
      }

    } else {
      sstrncpy(pathbuf, path, sizeof(pathbuf)-1);
    }

    pr_fs_clean_path2(pathbuf, cleaned_path, sizeof(cleaned_path)-1, 0);

    res = 0;

    stat_count = pr_table_exists(stat_statcache_tab, cleaned_path);
    if (stat_count > 0) {
      const struct fs_statcache *sc;

      sc = pr_table_remove(stat_statcache_tab, cleaned_path, NULL);
      if (sc != NULL) {
        destroy_pool(sc->sc_pool);
      }

      pr_trace_msg(statcache_channel, 17, "cleared stat(2) entry for '%s'",
        path);
      res += stat_count;
    }

    lstat_count = pr_table_exists(lstat_statcache_tab, cleaned_path);
    if (lstat_count > 0) {
      const struct fs_statcache *sc;

      sc = pr_table_remove(lstat_statcache_tab, cleaned_path, NULL);
      if (sc != NULL) {
        destroy_pool(sc->sc_pool);
      }

      pr_trace_msg(statcache_channel, 17, "cleared lstat(2) entry for '%s'",
        path);
      res += lstat_count;
    }

  } else {
    /* Caller is requesting that we empty the entire cache. */
    pr_fs_statcache_reset();
    res = 0;
  }

  return res;
}

void pr_fs_clear_cache(void) {
  (void) pr_fs_clear_cache2(NULL);
}

/* FS functions proper */

int pr_fs_copy_file2(const char *src, const char *dst, int flags,
    void (*progress_cb)(int)) {
  pr_fh_t *src_fh, *dst_fh;
  struct stat src_st, dst_st;
  char *buf;
  size_t bufsz;
  int dst_existed = FALSE, res;
#ifdef PR_USE_XATTR
  array_header *xattrs = NULL;
#endif /* PR_USE_XATTR */

  if (src == NULL ||
      dst == NULL) {
    errno = EINVAL;
    return -1;
  }

  copy_iter_count = 0;

  /* Use a nonblocking open() for the path; it could be a FIFO, and we don't
   * want to block forever if the other end of the FIFO is not running.
   */
  src_fh = pr_fsio_open(src, O_RDONLY|O_NONBLOCK);
  if (src_fh == NULL) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "error opening source file '%s' "
      "for copying: %s", src, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* Do not allow copying of directories. open(2) may not fail when
   * opening the source path, since it is only doing a read-only open,
   * which does work on directories.
   */

  /* This should never fail. */
  if (pr_fsio_fstat(src_fh, &src_st) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error fstat'ing '%s': %s", src, strerror(errno));
  }

  if (S_ISDIR(src_st.st_mode)) {
    int xerrno = EISDIR;

    pr_fsio_close(src_fh);

    pr_log_pri(PR_LOG_WARNING, "warning: cannot copy source '%s': %s", src,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (pr_fsio_set_block(src_fh) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error putting '%s' into blocking mode: %s", src, strerror(errno));
  }

  /* We use stat() here, not lstat(), since open() would follow a symlink
   * to its target, and what we really want to know here is whether the
   * ultimate destination file exists or not.
   */
  pr_fs_clear_cache2(dst);
  if (pr_fsio_stat(dst, &dst_st) == 0) {
    if (S_ISDIR(dst_st.st_mode)) {
      int xerrno = EISDIR;

      (void) pr_fsio_close(src_fh);

      pr_log_pri(PR_LOG_WARNING,
        "warning: cannot copy to destination '%s': %s", dst, strerror(xerrno));

      errno = xerrno;
      return -1;
    }

    dst_existed = TRUE;
    pr_fs_clear_cache2(dst);
  }

  /* Use a nonblocking open() for the path; it could be a FIFO, and we don't
   * want to block forever if the other end of the FIFO is not running.
   */
  dst_fh = pr_fsio_open(dst, O_WRONLY|O_CREAT|O_NONBLOCK);
  if (dst_fh == NULL) {
    int xerrno = errno;

    (void) pr_fsio_close(src_fh);

    pr_log_pri(PR_LOG_WARNING, "error opening destination file '%s' "
      "for copying: %s", dst, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (pr_fsio_set_block(dst_fh) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error putting '%s' into blocking mode: %s", dst, strerror(errno));
  }

  /* Stat the source file to find its optimal copy block size. */
  if (pr_fsio_fstat(src_fh, &src_st) < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "error checking source file '%s' "
      "for copying: %s", src, strerror(xerrno));

    (void) pr_fsio_close(src_fh);
    (void) pr_fsio_close(dst_fh);

    /* Don't unlink the destination file if it already existed. */
    if (!dst_existed) {
      if (!(flags & PR_FSIO_COPY_FILE_FL_NO_DELETE_ON_FAILURE)) {
        if (pr_fsio_unlink(dst) < 0) {
          pr_trace_msg(trace_channel, 12,
            "error deleting failed copy of '%s': %s", dst, strerror(errno));
        }
      }
    }

    errno = xerrno;
    return -1;
  }

  if (pr_fsio_fstat(dst_fh, &dst_st) == 0) {

    /* Check to see if the source and destination paths are identical.
     * We wait until now, rather than simply comparing the path strings
     * earlier, in order to do stats on the paths and compare things like
     * file size, mtime, inode, etc.
     */

    if (strcmp(src, dst) == 0 &&
        src_st.st_dev == dst_st.st_dev &&
        src_st.st_ino == dst_st.st_ino &&
        src_st.st_size == dst_st.st_size &&
        src_st.st_mtime == dst_st.st_mtime) {

      (void) pr_fsio_close(src_fh);
      (void) pr_fsio_close(dst_fh);

      /* No need to copy the same file. */
      return 0;
    }
  }

  bufsz = src_st.st_blksize;
  buf = malloc(bufsz);
  if (buf == NULL) {
    pr_log_pri(PR_LOG_ALERT, "Out of memory!");
    exit(1);
  }

#ifdef S_ISFIFO
  if (!S_ISFIFO(dst_st.st_mode)) {
    /* Make sure the destination file starts with a zero size. */
    pr_fsio_truncate(dst, 0);
  }
#endif

  while ((res = pr_fsio_read(src_fh, buf, bufsz)) > 0) {
    size_t datalen;
    off_t offset;

    pr_signals_handle();

    /* Be sure to handle short writes. */
    datalen = res;
    offset = 0;

    while (datalen > 0) {
      res = pr_fsio_write(dst_fh, buf + offset, datalen);
      if (res < 0) {
        int xerrno = errno;

        if (xerrno == EINTR ||
            xerrno == EAGAIN) {
          pr_signals_handle();
          continue;
        }

        (void) pr_fsio_close(src_fh);
        (void) pr_fsio_close(dst_fh);

        /* Don't unlink the destination file if it already existed. */
        if (!dst_existed) {
          if (!(flags & PR_FSIO_COPY_FILE_FL_NO_DELETE_ON_FAILURE)) {
            if (pr_fsio_unlink(dst) < 0) {
              pr_trace_msg(trace_channel, 12,
                "error deleting failed copy of '%s': %s", dst, strerror(errno));
            }
          }
        }

        pr_log_pri(PR_LOG_WARNING, "error copying to '%s': %s", dst,
          strerror(xerrno));
        free(buf);

        errno = xerrno;
        return -1;
      }

      if (progress_cb != NULL) {
        (progress_cb)(res);

      } else {
        copy_progress_cb(res);
      }

      if ((size_t) res == datalen) {
        break;
      }

      offset += res;
      datalen -= res;
    }
  }

  free(buf);

#if defined(HAVE_POSIX_ACL) && defined(PR_USE_FACL)
  {
    /* Copy any ACLs from the source file to the destination file as well. */
# if defined(HAVE_BSD_POSIX_ACL)
    acl_t facl, facl_dup = NULL;
    int have_facl = FALSE, have_dup = FALSE;

    facl = acl_get_fd(PR_FH_FD(src_fh));
    if (facl) {
      have_facl = TRUE;
    }

    if (have_facl) {
      facl_dup = acl_dup(facl);
    }

    if (facl_dup) {
      have_dup = TRUE;
    }

    if (have_dup &&
        acl_set_fd(PR_FH_FD(dst_fh), facl_dup) < 0) {
      pr_log_debug(DEBUG3, "error applying ACL to destination file: %s",
        strerror(errno));
    }

    if (have_dup) {
      acl_free(facl_dup);
    }
# elif defined(HAVE_LINUX_POSIX_ACL)

#  if defined(HAVE_PERM_COPY_FD)
    /* Linux provides the handy perm_copy_fd(3) function in its libacl
     * library just for this purpose.
     */
    if (perm_copy_fd(src, PR_FH_FD(src_fh), dst, PR_FH_FD(dst_fh), NULL) < 0) {
      pr_log_debug(DEBUG3, "error copying ACL to destination file: %s",
        strerror(errno));
    }

#  else
    acl_t src_acl = acl_get_fd(PR_FH_FD(src_fh));
    if (src_acl == NULL) {
      pr_log_debug(DEBUG3, "error obtaining ACL for fd %d: %s",
        PR_FH_FD(src_fh), strerror(errno));

    } else {
      if (acl_set_fd(PR_FH_FD(dst_fh), src_acl) < 0) {
        pr_log_debug(DEBUG3, "error setting ACL on fd %d: %s",
          PR_FH_FD(dst_fh), strerror(errno));

      } else {
        acl_free(src_acl);
      }
    }

#  endif /* !HAVE_PERM_COPY_FD */

# elif defined(HAVE_SOLARIS_POSIX_ACL)
    int nents;

    nents = facl(PR_FH_FD(src_fh), GETACLCNT, 0, NULL);
    if (nents < 0) {
      pr_log_debug(DEBUG3, "error getting source file ACL count: %s",
        strerror(errno));

    } else {
      aclent_t *acls;

      acls = malloc(sizeof(aclent_t) * nents);
      if (!acls) { 
        pr_log_pri(PR_LOG_ALERT, "Out of memory!");
        exit(1);
      }

      if (facl(PR_FH_FD(src_fh), GETACL, nents, acls) < 0) {
        pr_log_debug(DEBUG3, "error getting source file ACLs: %s",
          strerror(errno));

      } else {
        if (facl(PR_FH_FD(dst_fh), SETACL, nents, acls) < 0) {
          pr_log_debug(DEBUG3, "error setting dest file ACLs: %s",
            strerror(errno));
        }
      }

      free(acls);
    }
# endif /* HAVE_SOLARIS_POSIX_ACL && PR_USE_FACL */
  }
#endif /* HAVE_POSIX_ACL */

#ifdef PR_USE_XATTR
  /* Copy any xattrs that the source file may have. We'll use the
   * destination file handle's pool for our xattr allocations.
   */
  if (pr_fsio_flistxattr(dst_fh->fh_pool, src_fh, &xattrs) > 0) {
    register unsigned int i;
    const char **names;

    names = xattrs->elts;
    for (i = 0; i < xattrs->nelts; i++) {
      ssize_t valsz;

      /* First, find out how much memory we need for this attribute's
       * value.
       */
      valsz = pr_fsio_fgetxattr(dst_fh->fh_pool, src_fh, names[i], NULL, 0);
      if (valsz > 0) {
        void *val;
        ssize_t sz;

        val = palloc(dst_fh->fh_pool, valsz);
        sz = pr_fsio_fgetxattr(dst_fh->fh_pool, src_fh, names[i], val, valsz);
        if (sz > 0) {
          sz = pr_fsio_fsetxattr(dst_fh->fh_pool, dst_fh, names[i], val,
            valsz, 0);
          if (sz < 0 &&
              errno != ENOSYS) {
            pr_trace_msg(trace_channel, 7,
              "error copying xattr '%s' (%lu bytes) from '%s' to '%s': %s",
              names[i], (unsigned long) valsz, src, dst, strerror(errno));
          }
        }
      }
    }
  }
#endif /* PR_USE_XATTR */

  (void) pr_fsio_close(src_fh);

  if (progress_cb != NULL) {
    (progress_cb)(0);

  } else {
    copy_progress_cb(0);
  }

  res = pr_fsio_close(dst_fh);
  if (res < 0) {
    int xerrno = errno;

    /* Don't unlink the destination file if it already existed. */
    if (!dst_existed) {
      if (!(flags & PR_FSIO_COPY_FILE_FL_NO_DELETE_ON_FAILURE)) {
        if (pr_fsio_unlink(dst) < 0) {
          pr_trace_msg(trace_channel, 12,
            "error deleting failed copy of '%s': %s", dst, strerror(errno));
        }
      }
    }

    pr_log_pri(PR_LOG_WARNING, "error closing '%s': %s", dst,
      strerror(xerrno));

    errno = xerrno;
  }

  return res;
}

int pr_fs_copy_file(const char *src, const char *dst) {
  return pr_fs_copy_file2(src, dst, 0, NULL);
}

pr_fs_t *pr_register_fs(pool *p, const char *name, const char *path) {
  pr_fs_t *fs = NULL;
  int xerrno = 0;

  /* Sanity check */
  if (p == NULL ||
      name == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* Instantiate an pr_fs_t */
  fs = pr_create_fs(p, name);
  xerrno = errno;

  if (fs != NULL) {
    if (pr_insert_fs(fs, path) == FALSE) {
      xerrno = errno;

      pr_trace_msg(trace_channel, 4, "error inserting FS '%s' at path '%s'",
        name, path);

      destroy_pool(fs->fs_pool);
      fs->fs_pool = NULL;

      errno = xerrno;
      return NULL;
    }

  } else {
    pr_trace_msg(trace_channel, 6, "error creating FS '%s': %s", name,
      strerror(errno));
  }

  errno = xerrno;
  return fs;
}

pr_fs_t *pr_create_fs(pool *p, const char *name) {
  pr_fs_t *fs = NULL;
  pool *fs_pool = NULL;

  /* Sanity check */
  if (p == NULL ||
      name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* Allocate a subpool, then allocate an pr_fs_t object from that subpool */
  fs_pool = make_sub_pool(p);
  pr_pool_tag(fs_pool, "FS Pool");

  fs = pcalloc(fs_pool, sizeof(pr_fs_t));
  fs->fs_pool = fs_pool;
  fs->fs_next = fs->fs_prev = NULL;
  fs->fs_name = pstrdup(fs->fs_pool, name);
  fs->fs_next = root_fs;
  fs->allow_xdev_link = TRUE;
  fs->allow_xdev_rename = TRUE;

  /* This is NULL until set by pr_insert_fs() */
  fs->fs_path = NULL;

  return fs;
}

int pr_insert_fs(pr_fs_t *fs, const char *path) {
  char cleaned_path[PR_TUNABLE_PATH_MAX] = {'\0'};

  if (fs == NULL ||
      path == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fs_map == NULL) {
    pool *map_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(map_pool, "FSIO Map Pool");

    fs_map = make_array(map_pool, 0, sizeof(pr_fs_t *));
  }

  /* Clean the path, but only if it starts with a '/'.  Non-local-filesystem
   * paths may not want/need to be cleaned.
   */
  if (*path == '/') {
    pr_fs_clean_path(path, cleaned_path, sizeof(cleaned_path));

    /* Cleaning the path may have removed a trailing slash, which the
     * caller may actually have wanted.  Make sure one is present in
     * the cleaned version, if it was present in the original version and
     * is not present in the cleaned version.
     */
    if (path[strlen(path)-1] == '/') {
      size_t len = strlen(cleaned_path);

      if (len > 1 &&
          len < (PR_TUNABLE_PATH_MAX-3) &&
          cleaned_path[len-1] != '/') {
        cleaned_path[len] = '/';
        cleaned_path[len+1] = '\0';
      }
    }

  } else {
    sstrncpy(cleaned_path, path, sizeof(cleaned_path));
  }

  if (fs->fs_path == NULL) {
    fs->fs_path = pstrdup(fs->fs_pool, cleaned_path);
  }

  /* Check for duplicates. */
  if (fs_map->nelts > 0) {
    pr_fs_t *fsi = NULL, **fs_objs = (pr_fs_t **) fs_map->elts;
    register unsigned int i;

    for (i = 0; i < fs_map->nelts; i++) {
      fsi = fs_objs[i];

      if (strcmp(fsi->fs_path, cleaned_path) == 0) {
        /* An entry for this path already exists.  Make sure the FS being
         * mounted is not the same as the one already present.
         */
        if (strcmp(fsi->fs_name, fs->fs_name) == 0) {
          pr_log_pri(PR_LOG_NOTICE,
            "error: duplicate fs paths not allowed: '%s'", cleaned_path);
          errno = EEXIST;
          return FALSE;
        }

        /* "Push" the given FS on top of the existing one. */
        fs->fs_next = fsi;
        fsi->fs_prev = fs;
        fs_objs[i] = fs;

        chk_fs_map = TRUE;
        return TRUE;
      }
    }
  }

  /* Push the new FS into the container, then resort the contents. */
  *((pr_fs_t **) push_array(fs_map)) = fs;

  /* Sort the FSs in the map according to their paths, but only if there
   * are more than one element in the array_header.
   */
  if (fs_map->nelts > 1) {
    qsort(fs_map->elts, fs_map->nelts, sizeof(pr_fs_t *), fs_cmp);
  }

  /* Set the flag so that the fs wrapper functions know that a new FS
   * has been registered.
   */
  chk_fs_map = TRUE;

  return TRUE;
}

pr_fs_t *pr_unmount_fs(const char *path, const char *name) {
  pr_fs_t *fsi = NULL, **fs_objs = NULL;
  register unsigned int i = 0;

  /* Sanity check */
  if (path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* This should never be called before pr_register_fs(), but, just in case...*/
  if (fs_map == NULL) {
    errno = EACCES;
    return NULL;
  }

  fs_objs = (pr_fs_t **) fs_map->elts;

  for (i = 0; i < fs_map->nelts; i++) {
    fsi = fs_objs[i];

    if (strcmp(fsi->fs_path, path) == 0 &&
        (name ? strcmp(fsi->fs_name, name) == 0 : TRUE)) {

      /* Exact match -- remove this FS.  If there is an FS underneath, pop 
       * the top FS off the stack.  Otherwise, allocate a new map.  Then
       * iterate through the old map, pushing all other FSs into the new map.
       * Destroy the old map.  Move the new map into place.
       */

      if (fsi->fs_next == NULL) {
        register unsigned int j = 0;
        pr_fs_t *tmp_fs, **old_objs = NULL;
        pool *map_pool;
        array_header *new_map;

        /* If removing this FS would leave an empty map, don't bother
         * allocating a new one.
         */
        if (fs_map->nelts == 1) {
          destroy_pool(fs_map->pool);
          fs_map = NULL;
          fs_cwd = root_fs;

          chk_fs_map = TRUE;
          return NULL;
        }

        map_pool = make_sub_pool(permanent_pool);
        new_map = make_array(map_pool, 0, sizeof(pr_fs_t *));

        pr_pool_tag(map_pool, "FSIO Map Pool");
        old_objs = (pr_fs_t **) fs_map->elts;

        for (j = 0; j < fs_map->nelts; j++) {
          tmp_fs = old_objs[j];

          if (strcmp(tmp_fs->fs_path, path) != 0) {
            *((pr_fs_t **) push_array(new_map)) = old_objs[j];
          }
        }

        destroy_pool(fs_map->pool);
        fs_map = new_map;

        /* Don't forget to set the flag so that wrapper functions scan the
         * new map.
         */
        chk_fs_map = TRUE;

        return fsi;
      }

      /* "Pop" this FS off the stack. */
      if (fsi->fs_next) {
        fsi->fs_next->fs_prev = NULL;
      }
      fs_objs[i] = fsi->fs_next;
      fsi->fs_next = fsi->fs_prev = NULL; 

      chk_fs_map = TRUE;
      return fsi;
    }
  }

  errno = ENOENT;
  return NULL;
}

pr_fs_t *pr_remove_fs(const char *path) {
  return pr_unmount_fs(path, NULL);
}

int pr_unregister_fs(const char *path) {
  pr_fs_t *fs = NULL;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Call pr_remove_fs() to get the fs for this path removed from the map. */
  fs = pr_remove_fs(path);
  if (fs != NULL) {
    destroy_pool(fs->fs_pool);
    fs->fs_pool = NULL;
    return 0;
  }

  errno = ENOENT;
  return -1;
}

/* This function returns the best pr_fs_t to handle the given path.  It will
 * return NULL if there are no registered pr_fs_ts to handle the given path,
 * in which case the default root_fs should be used.  This is so that
 * functions can look to see if an pr_fs_t, other than the default, for a
 * given path has been registered, if necessary.  If the return value is
 * non-NULL, that will be a registered pr_fs_t to handle the given path.  In
 * this case, if the exact argument is not NULL, it will either be TRUE,
 * signifying that the returned pr_fs_t is an exact match for the given
 * path, or FALSE, meaning the returned pr_fs_t is a "best match" -- most
 * likely the pr_fs_t that handles the directory in which the given path
 * occurs.
 */
pr_fs_t *pr_get_fs(const char *path, int *exact) {
  pr_fs_t *fs = NULL, **fs_objs = NULL, *best_match_fs = NULL;
  register unsigned int i = 0;

  /* Sanity check */
  if (path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* Basic optimization -- if there're no elements in the fs_map,
   * return the root_fs.
   */
  if (fs_map == NULL ||
      fs_map->nelts == 0) {
    return root_fs;
  }

  fs_objs = (pr_fs_t **) fs_map->elts;
  best_match_fs = root_fs;

  /* In order to handle deferred-resolution paths (eg "~" paths), the given
   * path will need to be passed through dir_realpath(), if necessary.
   *
   * The chk_fs_map flag, if TRUE, should be cleared on return of this
   * function -- all that flag says is, if TRUE, that this function _might_
   * return something different than it did on a previous call.
   */

  for (i = 0; i < fs_map->nelts; i++) {
    int res = 0;

    fs = fs_objs[i];

    /* If the current pr_fs_t's path ends in a slash (meaning it is a
     * directory, and it matches the first part of the given path,
     * assume it to be the best pr_fs_t found so far.
     */
    if ((fs->fs_path)[strlen(fs->fs_path) - 1] == '/' &&
        !strncmp(path, fs->fs_path, strlen(fs->fs_path))) {
      best_match_fs = fs;
    }

    res = strcmp(fs->fs_path, path);
    if (res == 0) {
      /* Exact match */
      if (exact) {
        *exact = TRUE;
      }

      chk_fs_map = FALSE;
      return fs;

    } else if (res > 0) {
      if (exact != NULL) {
        *exact = FALSE;
      }

      chk_fs_map = FALSE;

      /* Gone too far - return the best-match pr_fs_t */
      return best_match_fs;
    }
  }

  chk_fs_map = FALSE;

  if (exact != NULL) {
    *exact = FALSE;
  }

  /* Return best-match by default */
  return best_match_fs;
}

int pr_fs_setcwd(const char *dir) {
  if (pr_fs_resolve_path(dir, cwd, sizeof(cwd)-1, FSIO_DIR_CHDIR) < 0) {
    return -1;
  }

  if (sstrncpy(cwd, dir, sizeof(cwd)) < 0) {
    return -1;
  }

  fs_cwd = lookup_dir_fs(cwd, FSIO_DIR_CHDIR);
  cwd[sizeof(cwd) - 1] = '\0';
  cwd_len = strlen(cwd);

  return 0;
}

const char *pr_fs_getcwd(void) {
  return cwd;
}

const char *pr_fs_getvwd(void) {
  return vwd;
}

int pr_fs_dircat(char *buf, int buflen, const char *dir1, const char *dir2) {
  /* Make temporary copies so that memory areas can overlap */
  char *_dir1 = NULL, *_dir2 = NULL, *ptr = NULL;
  size_t dir1len = 0, dir2len = 0;

  /* The shortest possible path is "/", which requires 2 bytes. */

  if (buf == NULL ||
      buflen < 2 ||
      dir1 == NULL ||
      dir2 == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* This is a test to see if we've got reasonable directories to concatenate.
   */
  dir1len = strlen(dir1);
  dir2len = strlen(dir2);

  /* If both strings are empty, then the "concatenation" becomes trivial. */
  if (dir1len == 0 &&
      dir2len == 0) {
    buf[0] = '/';
    buf[1] = '\0';
    return 0;
  }

  /* If dir2 is non-empty, but dir1 IS empty... */
  if (dir1len == 0) {
    sstrncpy(buf, dir2, buflen);
    buflen -= dir2len;
    sstrcat(buf, "/", buflen);
    return 0;
  }

  /* Likewise, if dir1 is non-empty, but dir2 IS empty... */
  if (dir2len == 0) {
    sstrncpy(buf, dir1, buflen);
    buflen -= dir1len;
    sstrcat(buf, "/", buflen);
    return 0;
  }

  if ((dir1len + dir2len + 1) >= PR_TUNABLE_PATH_MAX) {
    errno = ENAMETOOLONG;
    buf[0] = '\0';  
    return -1;
  }

  _dir1 = strdup(dir1);
  if (_dir1 == NULL) {
    return -1;
  }

  _dir2 = strdup(dir2);
  if (_dir2 == NULL) {
    int xerrno = errno;

    free(_dir1);

    errno = xerrno;
    return -1;
  }

  if (*_dir2 == '/') {
    sstrncpy(buf, _dir2, buflen);
    free(_dir1);
    free(_dir2);
    return 0;
  }

  ptr = buf;
  sstrncpy(ptr, _dir1, buflen);
  ptr += dir1len;
  buflen -= dir1len;

  if (buflen > 0 &&
      dir1len >= 1 &&
      *(_dir1 + (dir1len-1)) != '/') {
    sstrcat(ptr, "/", buflen);
    ptr += 1;
    buflen -= 1;
  }

  sstrcat(ptr, _dir2, buflen);

  if (*buf == '\0') {
   *buf++ = '/';
   *buf = '\0';
  }

  free(_dir1);
  free(_dir2);

  return 0;
}

/* This function performs any tilde expansion needed and then returns the
 * resolved path, if any.
 *
 * Returns: -1 (errno = ENOENT): user does not exist
 *           0 : no interpolation done (path exists)
 *           1 : interpolation done
 */
int pr_fs_interpolate(const char *path, char *buf, size_t buflen) {
  char *ptr = NULL;
  size_t currlen, pathlen;
  char user[PR_TUNABLE_LOGIN_MAX+1];

  if (path == NULL ||
      buf == NULL ||
      buflen == 0) {
    errno = EINVAL;
    return -1;
  }

  if (path[0] != '~') {
    sstrncpy(buf, path, buflen);
    return 1;
  }

  memset(user, '\0', sizeof(user));

  /* The first character of the given path is '~'.
   *
   * We next need to see what the rest of the path looks like.  Could be:
   *
   *  "~"
   *  "~user"
   *  "~/"
   *  "~/path"
   *  "~user/path"
   */

  pathlen = strlen(path);
  if (pathlen == 1) {
    /* If the path is just "~", AND we're chrooted, then the interpolation
     * is easy.
     */
    if (session.chroot_path != NULL) {
      sstrncpy(buf, session.chroot_path, buflen);
      return 1;
    }
  }

  ptr = strchr(path, '/');
  if (ptr == NULL) {
    struct stat st;

    /* No path separator present, which means path must be "~user".
     *
     * This means that a path of "~foo" could be a file with that exact
     * name, or it could be that user's home directory.  Let's find out
     * which it is.
     */

    if (pr_fsio_stat(path, &st) < 0) {
       /* Must be a user, if anything...otherwise it's probably a typo.
        *
        * The user name, then, is everything just past the '~' character.
        */
      sstrncpy(user, path+1,
        pathlen-1 > sizeof(user)-1 ? sizeof(user)-1 : pathlen-1);

    } else {
      /* This IS the file in question, perform no interpolation. */
      return 0;
    }

  } else {
    currlen = ptr - path;
    if (currlen > 1) {
      /* Copy over the username. */
      sstrncpy(user, path+1,
        currlen > sizeof(user)-1 ? sizeof(user)-1 : currlen);
    }

    /* Advance past the '/'. */
    ptr++;
  }

  if (user[0] == '\0') {
    /* No user name provided.  If we are chrooted, we leave it that way.
     * Otherwise, we're not chrooted, and we can assume the current user.
     */
    if (session.chroot_path == NULL) {
      sstrncpy(user, session.user, sizeof(user)-1);
    }
  }

  if (user[0] != '\0') {
    struct passwd *pw = NULL;
    pool *p = NULL;

    /* We need to look up the info for the given username, and add it
     * into the buffer.
     *
     * The permanent pool is used here, rather than session.pool, as path
     * interpolation can occur during startup parsing, when session.pool does
     * not exist.  It does not really matter, since the allocated sub pool
     * is destroyed shortly.
     */
    p = make_sub_pool(permanent_pool);
    pr_pool_tag(p, "pr_fs_interpolate() pool");

    pw = pr_auth_getpwnam(p, user);
    if (pw == NULL) {
      destroy_pool(p);
      errno = ENOENT;
      return -1;
    }

    sstrncpy(buf, pw->pw_dir, buflen);

    /* Done with pw, which means we can destroy the temporary pool now. */
    destroy_pool(p);

  } else {
    /* We're chrooted. */
    sstrncpy(buf, "/", buflen);
  }
 
  currlen = strlen(buf);

  if (ptr != NULL &&
      currlen < buflen &&
      buf[currlen-1] != '/') {
    buf[currlen++] = '/';
  }

  if (ptr != NULL) {
    sstrncpy(&buf[currlen], ptr, buflen - currlen);
  }
 
  return 1;
}

int pr_fs_resolve_partial(const char *path, char *buf, size_t buflen, int op) {
  char curpath[PR_TUNABLE_PATH_MAX + 1]  = {'\0'},
       workpath[PR_TUNABLE_PATH_MAX + 1] = {'\0'},
       namebuf[PR_TUNABLE_PATH_MAX + 1]  = {'\0'},
       *where = NULL, *ptr = NULL, *last = NULL;
  pr_fs_t *fs = NULL;
  int len = 0, fini = 1, link_cnt = 0;
  ino_t prev_inode = 0;
  dev_t prev_device = 0;
  struct stat sbuf;

  if (path == NULL ||
      buf == NULL ||
      buflen == 0) {
    errno = EINVAL;
    return -1;
  }

  if (*path != '/') {
    if (*path == '~') {
      switch (pr_fs_interpolate(path, curpath, sizeof(curpath)-1)) {
        case -1:
          return -1;

        case 0:
          sstrncpy(curpath, path, sizeof(curpath));
          sstrncpy(workpath, cwd, sizeof(workpath));
          break;
      }

    } else {
      sstrncpy(curpath, path, sizeof(curpath));
      sstrncpy(workpath, cwd, sizeof(workpath));
    }

  } else {
    sstrncpy(curpath, path, sizeof(curpath));
  }

  while (fini--) {
    where = curpath;

    while (*where != '\0') {
      pr_signals_handle();

      /* Handle "." */
      if (strncmp(where, ".", 2) == 0) {
        where++;
        continue;
      }

      /* Handle ".." */
      if (strncmp(where, "..", 3) == 0) {
        where += 2;
        ptr = last = workpath;

        while (*ptr) {
          if (*ptr == '/') {
            last = ptr;
          }
          ptr++;
        }

        *last = '\0';
        continue;
      }

      /* Handle "./" */
      if (strncmp(where, "./", 2) == 0) {
        where += 2;
        continue;
      }

      /* Handle "../" */
      if (strncmp(where, "../", 3) == 0) {
        where += 3;
        ptr = last = workpath;

        while (*ptr) {
          if (*ptr == '/') {
            last = ptr;
          }
          ptr++;
        }

        *last = '\0';
        continue;
      }

      ptr = strchr(where, '/');
      if (ptr == NULL) {
        size_t wherelen = strlen(where);

        ptr = where;
        if (wherelen >= 1) {
          ptr += (wherelen - 1);
        }

      } else {
        *ptr = '\0';
      }

      sstrncpy(namebuf, workpath, sizeof(namebuf));

      if (*namebuf) {
        for (last = namebuf; *last; last++);
        if (*--last != '/') {
          sstrcat(namebuf, "/", sizeof(namebuf)-1);
        }

      } else {
        sstrcat(namebuf, "/", sizeof(namebuf)-1);
      }

      sstrcat(namebuf, where, sizeof(namebuf)-1);

      where = ++ptr;

      fs = lookup_dir_fs(namebuf, op);

      if (fs_cache_lstat(fs, namebuf, &sbuf) == -1) {
        return -1;
      }

      if (S_ISLNK(sbuf.st_mode)) {
        char linkpath[PR_TUNABLE_PATH_MAX + 1] = {'\0'};

        /* Detect an obvious recursive symlink */
        if (sbuf.st_ino && (ino_t) sbuf.st_ino == prev_inode &&
            sbuf.st_dev && (dev_t) sbuf.st_dev == prev_device) {
          errno = ELOOP;
          return -1;
        }

        prev_inode = (ino_t) sbuf.st_ino;
        prev_device = (dev_t) sbuf.st_dev;

        if (++link_cnt > PR_FSIO_MAX_LINK_COUNT) {
          errno = ELOOP;
          return -1;
        }
	
        len = pr_fsio_readlink(namebuf, linkpath, sizeof(linkpath)-1);
        if (len <= 0) {
          errno = ENOENT;
          return -1;
        }

        *(linkpath + len) = '\0';
        if (*linkpath == '/') {
          *workpath = '\0';
        }

        /* Trim any trailing slash. */
        if (linkpath[len-1] == '/') {
          linkpath[len-1] = '\0';
        }

        if (*linkpath == '~') {
          char tmpbuf[PR_TUNABLE_PATH_MAX + 1] = {'\0'};

          *workpath = '\0';
          sstrncpy(tmpbuf, linkpath, sizeof(tmpbuf));

          if (pr_fs_interpolate(tmpbuf, linkpath, sizeof(linkpath)-1) < 0) {
	    return -1;
          }
        }

        if (*where) {
          sstrcat(linkpath, "/", sizeof(linkpath)-1);
          sstrcat(linkpath, where, sizeof(linkpath)-1);
        }

        sstrncpy(curpath, linkpath, sizeof(curpath));
        fini++;
        break; /* continue main loop */
      }

      if (S_ISDIR(sbuf.st_mode)) {
        sstrncpy(workpath, namebuf, sizeof(workpath));
        continue;
      }

      if (*where) {
        errno = ENOENT;
        return -1;               /* path/notadir/morepath */
      }

      sstrncpy(workpath, namebuf, sizeof(workpath));
    }
  }

  if (!workpath[0]) {
    sstrncpy(workpath, "/", sizeof(workpath));
  }

  sstrncpy(buf, workpath, buflen);
  return 0;
}

int pr_fs_resolve_path(const char *path, char *buf, size_t buflen, int op) {
  char curpath[PR_TUNABLE_PATH_MAX + 1]  = {'\0'},
       workpath[PR_TUNABLE_PATH_MAX + 1] = {'\0'},
       namebuf[PR_TUNABLE_PATH_MAX + 1]  = {'\0'},
       *where = NULL, *ptr = NULL, *last = NULL;
  pr_fs_t *fs = NULL;
  int len = 0, fini = 1, link_cnt = 0;
  ino_t prev_inode = 0;
  dev_t prev_device = 0;
  struct stat sbuf;

  if (path == NULL ||
      buf == NULL ||
      buflen == 0) {
    errno = EINVAL;
    return -1;
  }

  if (pr_fs_interpolate(path, curpath, sizeof(curpath)-1) != -1) {
    sstrncpy(curpath, path, sizeof(curpath));
  }

  if (curpath[0] != '/') {
    sstrncpy(workpath, cwd, sizeof(workpath));

  } else {
    workpath[0] = '\0';
  }

  while (fini--) {
    where = curpath;

    while (*where != '\0') {
      pr_signals_handle();

      if (strncmp(where, ".", 2) == 0) {
        where++;
        continue;
      }

      /* handle "./" */
      if (strncmp(where, "./", 2) == 0) {
        where += 2;
        continue;
      }

      /* handle "../" */
      if (strncmp(where, "../", 3) == 0) {
        where += 3;
        ptr = last = workpath;
        while (*ptr) {
          if (*ptr == '/') {
            last = ptr;
          }
          ptr++;
        }

        *last = '\0';
        continue;
      }

      ptr = strchr(where, '/');
      if (ptr == NULL) {
        size_t wherelen = strlen(where);

        ptr = where;
        if (wherelen >= 1) {
          ptr += (wherelen - 1);
        }

      } else {
        *ptr = '\0';
      }

      sstrncpy(namebuf, workpath, sizeof(namebuf));

      if (*namebuf) {
        for (last = namebuf; *last; last++);
        if (*--last != '/') {
          sstrcat(namebuf, "/", sizeof(namebuf)-1);
        }

      } else {
        sstrcat(namebuf, "/", sizeof(namebuf)-1);
      }

      sstrcat(namebuf, where, sizeof(namebuf)-1);

      where = ++ptr;

      fs = lookup_dir_fs(namebuf, op);

      if (fs_cache_lstat(fs, namebuf, &sbuf) == -1) {
        errno = ENOENT;
        return -1;
      }

      if (S_ISLNK(sbuf.st_mode)) {
        char linkpath[PR_TUNABLE_PATH_MAX + 1] = {'\0'};

        /* Detect an obvious recursive symlink */
        if (sbuf.st_ino && (ino_t) sbuf.st_ino == prev_inode &&
            sbuf.st_dev && (dev_t) sbuf.st_dev == prev_device) {
          errno = ELOOP;
          return -1;
        }

        prev_inode = (ino_t) sbuf.st_ino;
        prev_device = (dev_t) sbuf.st_dev;

        if (++link_cnt > PR_FSIO_MAX_LINK_COUNT) {
          errno = ELOOP;
          return -1;
        }

        len = pr_fsio_readlink(namebuf, linkpath, sizeof(linkpath)-1);
        if (len <= 0) {
          errno = ENOENT;
          return -1;
        }

        *(linkpath+len) = '\0';

        if (*linkpath == '/') {
          *workpath = '\0';
        }

        /* Trim any trailing slash. */
        if (linkpath[len-1] == '/') {
          linkpath[len-1] = '\0';
        }

        if (*linkpath == '~') {
          char tmpbuf[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
          *workpath = '\0';

          sstrncpy(tmpbuf, linkpath, sizeof(tmpbuf));

          if (pr_fs_interpolate(tmpbuf, linkpath, sizeof(linkpath)-1) < 0) {
	    return -1;
          }
        }

        if (*where) {
          sstrcat(linkpath, "/", sizeof(linkpath)-1);
          sstrcat(linkpath, where, sizeof(linkpath)-1);
        }

        sstrncpy(curpath, linkpath, sizeof(curpath));
        fini++;
        break; /* continue main loop */
      }

      if (S_ISDIR(sbuf.st_mode)) {
        sstrncpy(workpath, namebuf, sizeof(workpath));
        continue;
      }

      if (*where) {
        errno = ENOENT;
        return -1;               /* path/notadir/morepath */
      }

      sstrncpy(workpath, namebuf, sizeof(workpath));
    }
  }

  if (!workpath[0]) {
    sstrncpy(workpath, "/", sizeof(workpath));
  }

  sstrncpy(buf, workpath, buflen);
  return 0;
}

int pr_fs_clean_path2(const char *path, char *buf, size_t buflen, int flags) {
  char workpath[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
  char curpath[PR_TUNABLE_PATH_MAX + 1]  = {'\0'};
  char namebuf[PR_TUNABLE_PATH_MAX + 1]  = {'\0'};
  int fini = 1, have_abs_path = FALSE;

  if (path == NULL ||
      buf == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (buflen == 0) {
    return 0;
  }

  sstrncpy(curpath, path, sizeof(curpath));

  if (*curpath == '/') {
    have_abs_path = TRUE;
  }

  /* main loop */
  while (fini--) {
    char *where = NULL, *ptr = NULL, *last = NULL;

    where = curpath;
    while (*where != '\0') {
      pr_signals_handle();

      if (strncmp(where, ".", 2) == 0) {
        where++;
        continue;
      }

      /* handle "./" */
      if (strncmp(where, "./", 2) == 0) {
        where += 2;
        continue;
      }

      /* handle ".." */
      if (strncmp(where, "..", 3) == 0) {
        where += 2;
        ptr = last = workpath;

        while (*ptr) {
          pr_signals_handle();

          if (*ptr == '/') {
            last = ptr;
          }

          ptr++;
        }

        *last = '\0';
        continue;
      }

      /* handle "../" */
      if (strncmp(where, "../", 3) == 0) {
        where += 3;
        ptr = last = workpath;

        while (*ptr) {
          pr_signals_handle();

          if (*ptr == '/') {
            last = ptr;
          }
          ptr++;
        }

        *last = '\0';
        continue;
      }

      ptr = strchr(where, '/');
      if (ptr == NULL) {
        size_t wherelen = strlen(where);

        ptr = where;
        if (wherelen >= 1) {
          ptr += (wherelen - 1);
        }

      } else {
        *ptr = '\0';
      }

      sstrncpy(namebuf, workpath, sizeof(namebuf));

      if (*namebuf) {
        for (last = namebuf; *last; last++);
        if (*--last != '/') {
          sstrcat(namebuf, "/", sizeof(namebuf)-1);
        }

      } else {
        if (have_abs_path ||
            (flags & PR_FSIO_CLEAN_PATH_FL_MAKE_ABS_PATH)) {
          sstrcat(namebuf, "/", sizeof(namebuf)-1);
          have_abs_path = FALSE;
        }
      }

      sstrcat(namebuf, where, sizeof(namebuf)-1);
      namebuf[sizeof(namebuf)-1] = '\0';

      where = ++ptr;

      sstrncpy(workpath, namebuf, sizeof(workpath));
    }
  }

  if (!workpath[0]) {
    sstrncpy(workpath, "/", sizeof(workpath));
  }

  sstrncpy(buf, workpath, buflen);
  return 0;
}

void pr_fs_clean_path(const char *path, char *buf, size_t buflen) {
  pr_fs_clean_path2(path, buf, buflen, PR_FSIO_CLEAN_PATH_FL_MAKE_ABS_PATH);
}

int pr_fs_use_encoding(int bool) {
  int curr_setting = use_encoding;

  if (bool != TRUE &&
      bool != FALSE) {
    errno = EINVAL;
    return -1;
  }

  use_encoding = bool;
  return curr_setting;
}

char *pr_fs_decode_path2(pool *p, const char *path, int flags) {
#ifdef PR_USE_NLS
  size_t outlen;
  char *res;

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (!use_encoding) {
    return (char *) path;
  }

  res = pr_decode_str(p, path, strlen(path), &outlen);
  if (res == NULL) {
    int xerrno = errno;

    pr_trace_msg("encode", 1, "error decoding path '%s': %s", path,
      strerror(xerrno));

    if (pr_trace_get_level("encode") >= 14) {
      /* Write out the path we tried (and failed) to decode, in hex. */
      register unsigned int i;
      unsigned char *raw_path;
      size_t pathlen, raw_pathlen;

      pathlen = strlen(path);
      raw_pathlen = (pathlen * 5) + 1;
      raw_path = pcalloc(p, raw_pathlen + 1);

      for (i = 0; i < pathlen; i++) {
        pr_snprintf((char *) (raw_path + (i * 5)), (raw_pathlen - 1) - (i * 5),
          "0x%02x ", (unsigned char) path[i]);
      }

      pr_trace_msg("encode", 14, "unable to decode path (raw bytes): %s",
        raw_path);
    } 

    if (flags & FSIO_DECODE_FL_TELL_ERRORS) {
      unsigned long policy;

      policy = pr_encode_get_policy();
      if (policy & PR_ENCODE_POLICY_FL_REQUIRE_VALID_ENCODING) {
        /* Note: At present, we DO return null here to callers, to indicate
         * the illegal encoding (Bug#4125), if configured to do so via
         * e.g. the RequireValidEncoding LangOption.
         */
        errno = xerrno;
        return NULL;
      }
    }

    return (char *) path;
  }

  pr_trace_msg("encode", 5, "decoded '%s' into '%s'", path, res);
  return res;
#else
  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return (char *) path;
#endif /* PR_USE_NLS */
}

char *pr_fs_decode_path(pool *p, const char *path) {
  return pr_fs_decode_path2(p, path, 0);
}

char *pr_fs_encode_path(pool *p, const char *path) {
#ifdef PR_USE_NLS
  size_t outlen;
  char *res;

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (!use_encoding) {
    return (char *) path;
  }

  res = pr_encode_str(p, path, strlen(path), &outlen);
  if (res == NULL) {
    int xerrno = errno;

    pr_trace_msg("encode", 1, "error encoding path '%s': %s", path,
      strerror(xerrno));

    if (pr_trace_get_level("encode") >= 14) {
      /* Write out the path we tried (and failed) to encode, in hex. */
      register unsigned int i; 
      unsigned char *raw_path;
      size_t pathlen, raw_pathlen;
      
      pathlen = strlen(path);
      raw_pathlen = (pathlen * 5) + 1;
      raw_path = pcalloc(p, raw_pathlen + 1);

      for (i = 0; i < pathlen; i++) {
        pr_snprintf((char *) (raw_path + (i * 5)), (raw_pathlen - 1) - (i * 5),
          "0x%02x ", (unsigned char) path[i]);
      }

      pr_trace_msg("encode", 14, "unable to encode path (raw bytes): %s",
        raw_path);
    } 

    /* Note: At present, we do NOT return null here to callers; we assume
     * that all local names, being encoded for the remote client, are OK.
     * Revisit this assumption if necessary (Bug#4125).
     */

    return (char *) path;
  }

  pr_trace_msg("encode", 5, "encoded '%s' into '%s'", path, res);
  return res;
#else
  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return (char *) path;
#endif /* PR_USE_NLS */
}

array_header *pr_fs_split_path(pool *p, const char *path) {
  int res, have_abs_path = FALSE;
  char *buf;
  size_t buflen, bufsz, pathlen;
  array_header *components;

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  pathlen = strlen(path);
  if (pathlen == 0) {
    errno = EINVAL;
    return NULL;
  }

  if (*path == '/') {
    have_abs_path = TRUE;
  }

  /* Clean the path first */
  bufsz = PR_TUNABLE_PATH_MAX;
  buf = pcalloc(p, bufsz + 1);

  res = pr_fs_clean_path2(path, buf, bufsz,
    PR_FSIO_CLEAN_PATH_FL_MAKE_ABS_PATH);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 7, "error cleaning path '%s': %s", path,
      strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  buflen = strlen(buf);

  /* Special-case handling of just "/", since pr_str_text_to_array() will
   * "eat" that delimiter.
   */
  if (buflen == 1 &&
      buf[0] == '/') {
    pr_trace_msg(trace_channel, 18, "split path '%s' into 1 component", path);

    components = make_array(p, 1, sizeof(char *));
    *((char **) push_array(components)) = pstrdup(p, "/");

    return components;
  }

  components = pr_str_text_to_array(p, buf, '/');
  if (components != NULL) {
    pr_trace_msg(trace_channel, 17, "split path '%s' into %u %s", path,
      components->nelts, components->nelts != 1 ? "components" : "component");

    if (pr_trace_get_level(trace_channel) >= 18) {
      register unsigned int i;

      for (i = 0; i < components->nelts; i++) {
        char *component;

        component = ((char **) components->elts)[i];
        if (component == NULL) {
          component = "NULL";
        }

        pr_trace_msg(trace_channel, 18, "path '%s' component #%u: '%s'",
          path, i + 1, component);
      }
    }
  }

  if (have_abs_path == TRUE) {
    array_header *root_component;

    /* Since pr_str_text_to_array() will treat the leading '/' as a delimiter,
     * it will be stripped and not included as a path component.  But it
     * DOES need to be there.
     */
    root_component = make_array(p, 1, sizeof(char *));
    *((char **) push_array(root_component)) = pstrdup(p, "/");

    array_cat(root_component, components);
    components = root_component;
  }

  return components;
}

char *pr_fs_join_path(pool *p, array_header *components, size_t count) {
  register unsigned int i;
  char *path = NULL;

  if (p == NULL ||
      components == NULL ||
      components->nelts == 0 ||
      count == 0) {
    errno = EINVAL;
    return NULL;
  }

  /* Can't join more components than we have. */
  if (count > components->nelts) {
    errno = EINVAL;
    return NULL;
  }

  path = ((char **) components->elts)[0];

  for (i = 1; i < count; i++) {
    char *elt;

    elt = ((char **) components->elts)[i];
    path = pdircat(p, path, elt, NULL);
  }

  return path;
}

/* This function checks the given path's prefix against the paths that
 * have been registered.  If no matching path prefix has been registered,
 * the path is considered invalid.
 */
int pr_fs_valid_path(const char *path) {
  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fs_map != NULL &&
      fs_map->nelts > 0) {
    pr_fs_t *fsi = NULL, **fs_objs = (pr_fs_t **) fs_map->elts;
    register unsigned int i;

    for (i = 0; i < fs_map->nelts; i++) {
      fsi = fs_objs[i];

      if (strncmp(fsi->fs_path, path, strlen(fsi->fs_path)) == 0) {
        return 0;
      }
    }
  }

  /* Also check the path against the default '/' path. */
  if (*path == '/') {
    return 0;
  }

  errno = ENOENT;
  return -1;
}

void pr_fs_virtual_path(const char *path, char *buf, size_t buflen) {
  char curpath[PR_TUNABLE_PATH_MAX + 1]  = {'\0'},
       workpath[PR_TUNABLE_PATH_MAX + 1] = {'\0'},
       namebuf[PR_TUNABLE_PATH_MAX + 1]  = {'\0'},
       *where = NULL, *ptr = NULL, *last = NULL;
  int fini = 1;

  if (path == NULL) {
    return;
  }

  if (pr_fs_interpolate(path, curpath, sizeof(curpath)-1) != -1) {
    sstrncpy(curpath, path, sizeof(curpath));
  }

  if (curpath[0] != '/') {
    sstrncpy(workpath, vwd, sizeof(workpath));

  } else {
    workpath[0] = '\0';
  }

  /* curpath is path resolving */
  /* linkpath is path a symlink pointed to */
  /* workpath is the path we've resolved */

  /* main loop */
  while (fini--) {
    where = curpath;
    while (*where != '\0') {
      if (strncmp(where, ".", 2) == 0) {
        where++;
        continue;
      }

      /* handle "./" */
      if (strncmp(where, "./", 2) == 0) {
        where += 2;
        continue;
      }

      /* handle ".." */
      if (strncmp(where, "..", 3) == 0) {
        where += 2;
        ptr = last = workpath;
        while (*ptr) {
          if (*ptr == '/') {
            last = ptr;
          }
          ptr++;
        }

        *last = '\0';
        continue;
      }

      /* handle "../" */
      if (strncmp(where, "../", 3) == 0) {
        where += 3;
        ptr = last = workpath;
        while (*ptr) {
          if (*ptr == '/') {
            last = ptr;
          }
          ptr++;
        }

        *last = '\0';
        continue;
      }

      ptr = strchr(where, '/');
      if (ptr == NULL) {
        size_t wherelen = strlen(where);

        ptr = where;
        if (wherelen >= 1) {
          ptr += (wherelen - 1);
        }

      } else {
        *ptr = '\0';
      }

      sstrncpy(namebuf, workpath, sizeof(namebuf));

      if (*namebuf) {
        for (last = namebuf; *last; last++);
        if (*--last != '/') {
          sstrcat(namebuf, "/", sizeof(namebuf)-1);
        }

      } else {
        sstrcat(namebuf, "/", sizeof(namebuf)-1);
      }

      sstrcat(namebuf, where, sizeof(namebuf)-1);

      where = ++ptr;

      sstrncpy(workpath, namebuf, sizeof(workpath));
    }
  }

  if (!workpath[0]) {
    sstrncpy(workpath, "/", sizeof(workpath));
  }

  sstrncpy(buf, workpath, buflen);
}

int pr_fsio_chdir_canon(const char *path, int hidesymlink) {
  char resbuf[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
  pr_fs_t *fs = NULL;
  int res = 0;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (pr_fs_resolve_partial(path, resbuf, sizeof(resbuf)-1,
      FSIO_DIR_CHDIR) < 0) {
    return -1;
  }

  fs = lookup_dir_fs(resbuf, FSIO_DIR_CHDIR);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom chdir handler.  If there are none,
   * use the system chdir.
   */
  while (fs && fs->fs_next && !fs->chdir) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s chdir() for path '%s'", fs->fs_name,
    path);
  res = (fs->chdir)(fs, resbuf);

  if (res == 0) {
    /* chdir succeeded, so we set fs_cwd for future references. */
     fs_cwd = fs;

     if (hidesymlink) {
       pr_fs_virtual_path(path, vwd, sizeof(vwd)-1);

     } else {
       sstrncpy(vwd, resbuf, sizeof(vwd));
     }
  }

  return res;
}

int pr_fsio_chdir(const char *path, int hidesymlink) {
  char resbuf[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
  pr_fs_t *fs = NULL;
  int res;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  pr_fs_clean_path(path, resbuf, sizeof(resbuf)-1);

  fs = lookup_dir_fs(path, FSIO_DIR_CHDIR);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom chdir handler.  If there are none,
   * use the system chdir.
   */
  while (fs && fs->fs_next && !fs->chdir) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s chdir() for path '%s'", fs->fs_name,
    path);
  res = (fs->chdir)(fs, resbuf);
  if (res == 0) {
    /* chdir succeeded, so we set fs_cwd for future references. */
    fs_cwd = fs;

    if (hidesymlink) {
      pr_fs_virtual_path(path, vwd, sizeof(vwd)-1);

    } else {
      sstrncpy(vwd, resbuf, sizeof(vwd));
    }
  }

  return res;
}

/* fs_opendir, fs_closedir and fs_readdir all use a nifty
 * optimization, caching the last-recently-used pr_fs_t, and
 * avoid future pr_fs_t lookups when iterating via readdir.
 */
void *pr_fsio_opendir(const char *path) {
  pr_fs_t *fs = NULL;
  fsopendir_t *fsod = NULL, *fsodi = NULL;
  pool *fsod_pool = NULL;
  DIR *res = NULL;

  if (path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (strchr(path, '/') == NULL) {
    pr_fs_setcwd(pr_fs_getcwd());
    fs = fs_cwd;

  } else {
    char buf[PR_TUNABLE_PATH_MAX + 1] = {'\0'};

    if (pr_fs_resolve_partial(path, buf, sizeof(buf)-1, FSIO_DIR_OPENDIR) < 0) {
      return NULL;
    }

    fs = lookup_dir_fs(buf, FSIO_DIR_OPENDIR);
  }

  /* Find the first non-NULL custom opendir handler.  If there are none,
   * use the system opendir.
   */
  while (fs && fs->fs_next && !fs->opendir) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s opendir() for path '%s'",
    fs->fs_name, path);
  res = (fs->opendir)(fs, path);
  if (res == NULL) {
    return NULL;
  }

  /* Cache it here */
  fs_cache_dir = res;
  fs_cache_fsdir = fs;

  fsod_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(fsod_pool, "fsod subpool");

  fsod = pcalloc(fsod_pool, sizeof(fsopendir_t));
  if (fsod == NULL) {
    if (fs->closedir) {
      (fs->closedir)(fs, res);
      errno = ENOMEM;
      return NULL;
    }

    sys_closedir(fs, res);
    errno = ENOMEM;
    return NULL;
  }

  fsod->pool = fsod_pool;
  fsod->dir = res;
  fsod->fsdir = fs;
  fsod->next = NULL;
  fsod->prev = NULL;

  if (fsopendir_list) {

    /* find the end of the fsopendir list */
    fsodi = fsopendir_list;
    while (fsodi->next) {
      pr_signals_handle();
      fsodi = fsodi->next;
    }

    fsod->next = NULL;
    fsod->prev = fsodi;
    fsodi->next = fsod;

  } else {
    /* This fsopendir _becomes_ the start of the fsopendir list */
    fsopendir_list = fsod;
  }

  return res;
}

static pr_fs_t *find_opendir(void *dir, int closing) {
  pr_fs_t *fs = NULL;

  if (fsopendir_list) {
    fsopendir_t *fsod;

    for (fsod = fsopendir_list; fsod; fsod = fsod->next) {
      if (fsod->dir != NULL &&
          fsod->dir == dir) {
        fs = fsod->fsdir;
        break;
      }
    }
   
    if (closing && fsod) {
      if (fsod->prev) {
        fsod->prev->next = fsod->next;
      }
 
      if (fsod->next) {
        fsod->next->prev = fsod->prev;
      }

      if (fsod == fsopendir_list) {
        fsopendir_list = fsod->next;
      }

      destroy_pool(fsod->pool);
      fsod->pool = NULL;
    }
  }

  if (dir == fs_cache_dir) {
    fs = fs_cache_fsdir;

    if (closing) {
      fs_cache_dir = NULL;
      fs_cache_fsdir = NULL;
    }
  }

  if (fs == NULL) {
    errno = ENOTDIR;
  }

  return fs;
}

int pr_fsio_closedir(void *dir) {
  int res;
  pr_fs_t *fs;

  if (dir == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = find_opendir(dir, TRUE);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom closedir handler.  If there are none,
   * use the system closedir.
   */
  while (fs && fs->fs_next && !fs->closedir) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s closedir()", fs->fs_name);
  res = (fs->closedir)(fs, dir);

  return res;
}

struct dirent *pr_fsio_readdir(void *dir) {
  struct dirent *res;
  pr_fs_t *fs;

  if (dir == NULL) {
    errno = EINVAL;
    return NULL;
  }

  fs = find_opendir(dir, FALSE);
  if (fs == NULL) {
    return NULL;
  }

  /* Find the first non-NULL custom readdir handler.  If there are none,
   * use the system readdir.
   */
  while (fs && fs->fs_next && !fs->readdir) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s readdir()", fs->fs_name);
  res = (fs->readdir)(fs, dir);

  return res;
}

int pr_fsio_mkdir(const char *path, mode_t mode) {
  int res, xerrno;
  pr_fs_t *fs;
  mode_t dir_umask = -1, prev_umask = -1, *umask_ptr = NULL;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = lookup_dir_fs(path, FSIO_DIR_MKDIR);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom mkdir handler.  If there are none,
   * use the system mkdir.
   */
  while (fs && fs->fs_next && !fs->mkdir) {
    fs = fs->fs_next;
  }

  /* Make sure we honor the directory Umask, if any (Bug#4311). */
  umask_ptr = get_param_ptr(CURRENT_CONF, "DirUmask", FALSE);
  if (umask_ptr == NULL) {
    /* If Umask was configured with a single parameter, then DirUmask
     * would not be present; we still should check for Umask.
     */
    umask_ptr = get_param_ptr(CURRENT_CONF, "Umask", FALSE);
  }

  if (umask_ptr != NULL) {
    dir_umask = *umask_ptr;

    if (dir_umask != (mode_t) -1) {
      prev_umask = umask(dir_umask);
    }
  }

  pr_trace_msg(trace_channel, 8, "using %s mkdir() for path '%s'", fs->fs_name,
    path);
  res = (fs->mkdir)(fs, path, mode);
  xerrno = errno;

  if (res == 0) {
    pr_fs_clear_cache2(path);
  }

  if (dir_umask != (mode_t) -1) {
    (void) umask(prev_umask);
  }

  errno = xerrno;
  return res;
}

int pr_fsio_mkdir_with_error(pool *p, const char *path, mode_t mode,
    pr_error_t **err) {
  int res;

  res = pr_fsio_mkdir(path, mode);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_mkdir(*err, path, mode) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

int pr_fsio_guard_chroot(int guard) {
  int prev;

  prev = fsio_guard_chroot;
  fsio_guard_chroot = guard;

  return prev;
}

unsigned long pr_fsio_set_options(unsigned long opts) {
  unsigned long prev;

  prev = fsio_opts;
  fsio_opts = opts;

  return prev;
}

int pr_fsio_set_use_mkdtemp(int value) {
  int prev_value;

  if (value != TRUE &&
      value != FALSE) {
    errno = EINVAL;
    return -1;
  }

  prev_value = fsio_use_mkdtemp;

#ifdef HAVE_MKDTEMP
  fsio_use_mkdtemp = value;
#endif /* HAVE_MKDTEMP */

  return prev_value;
}

/* Directory-specific "safe" chmod(2) which attempts to avoid/mitigate
 * symlink attacks.
 * 
 * To do this, we first open a file descriptor on the given path, using
 * O_NOFOLLOW to avoid symlinks.  If the fd is not to a directory, it's
 * an error.  Then we use fchmod(2) to set the perms.  There is still a
 * race condition here, between the time the directory is created and
 * when we call open(2).  But hopefully the ensuing checks on the fd
 * (i.e. that it IS a directory) can mitigate that race.
 *
 * The fun part is ensuring that the OS/filesystem will give us an fd
 * on a directory path (using O_RDONLY to avoid getting an EISDIR error),
 * whilst being able to do a write (effectively) on the fd by changing
 * its permissions.
 */
static int schmod_dir(pool *p, const char *path, mode_t perms, int use_root) {
  int flags, fd, ignore_eacces = FALSE, ignore_eperm = FALSE, res, xerrno = 0;
  struct stat st;
  mode_t dir_mode;

  /* We're not using the pool at the moment. */
  (void) p;

  /* Open an fd on the path using O_RDONLY|O_NOFOLLOW, so that we a)
   * avoid symlinks, and b) get an fd on the (hopefully) directory.
   */
  flags = O_RDONLY;
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
  fd = open(path, flags);
  xerrno = errno;

  if (fd < 0) {
    pr_trace_msg(trace_channel, 3,
      "schmod: unable to open path '%s': %s", path, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = fstat(fd, &st);
  if (res < 0) {
    xerrno = errno;

    (void) close(fd);

    pr_trace_msg(trace_channel, 3,
      "schmod: unable to fstat path '%s': %s", path, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  /* We expect only directories. */
  if (!S_ISDIR(st.st_mode)) {
    xerrno = ENOTDIR;

    (void) close(fd);
  
    pr_trace_msg(trace_channel, 3,
      "schmod: unable to use path '%s': %s", path, strerror(xerrno));

    /* This is such an unexpected (and possibly malicious) situation that
     * it warrants louder logging.
     */
    pr_log_pri(PR_LOG_WARNING,
      "WARNING: detected non-directory '%s' during directory creation: "
      "possible symlink attack", path);

    errno = xerrno;
    return -1;
  }

  /* Note that some filesystems (e.g. CIFS) may not actually create a
   * directory with the expected 0700 mode.  If that is the case, then a
   * subsequence chmod(2) on that directory will likely fail.  Thus we also
   * double-check the mode of the directory created via mkdtemp(3), and
   * attempt to mitigate Bug#4063.
   */
  dir_mode = (st.st_mode & ~S_IFMT);
  if (dir_mode != 0700) {
    ignore_eacces = ignore_eperm = TRUE;

    pr_trace_msg(trace_channel, 3,
      "schmod: path '%s' has mode %04o, expected 0700", path, dir_mode);

    /* This is such an unexpected situation that it warrants some logging. */
    pr_log_pri(PR_LOG_DEBUG,
      "NOTICE: directory '%s' has unexpected mode %04o (expected 0700)", path,
      dir_mode);
  }

  if (use_root) {
    PRIVS_ROOT
  }

  res = fchmod(fd, perms);
  xerrno = errno;

  /* Using fchmod(2) on a directory descriptor is not really kosher
   * behavior, but appears to work on most filesystems.  Still, if we
   * get an ENOENT back (as seen on some CIFS mounts, per Bug#4134), try
   * using chmod(2) on the path.
   */
  if (res < 0 &&
      xerrno == ENOENT) {
    ignore_eacces = TRUE;
    res = chmod(path, perms);
    xerrno = errno;
  }

  if (use_root) {
    PRIVS_RELINQUISH
  }

  /* At this point, succeed or fail, we're done with the fd. */
  (void) close(fd);

  if (res < 0) {
    /* Note: Some filesystem implementations, particularly via FUSE,
     * may not actually implement ownership/permissions (e.g. FAT-based
     * filesystems).  In such cases, chmod(2) et al will return ENOSYS
     * (see Bug#3986).
     *
     * Other filesystem implementations (e.g. CIFS, depending on the mount
     * options) will a chmod(2) that returns ENOENT (see Bug#4134).
     *
     * Should this fail the entire operation?  I'm of two minds about this.
     * On the one hand, such filesystem behavior can undermine wider site
     * security policies; on the other, prohibiting a MKD/MKDIR operation
     * on such filesystems, deliberately used by the site admin, is not
     * useful/friendly behavior.
     *
     * Maybe these exceptions for ENOSYS/ENOENT here should be made
     * configurable?
     */

    if (xerrno == ENOSYS ||
        xerrno == ENOENT ||
        (xerrno == EACCES && ignore_eacces == TRUE) ||
        (xerrno == EPERM && ignore_eperm == TRUE)) {
      pr_log_debug(DEBUG0, "schmod: unable to set perms %04o on "
        "path '%s': %s (chmod(2) not supported by underlying filesystem?)",
        perms, path, strerror(xerrno));
      return 0;
    }

    pr_trace_msg(trace_channel, 3,
      "schmod: unable to set perms %04o on path '%s': %s", perms, path,
      strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  return 0;
}

/* "safe mkdir" variant of mkdir(2), uses mkdtemp(3), lchown(2), and
 * rename(2) to create a directory which cannot be hijacked by a symlink
 * race (hopefully) before the UserOwner/GroupOwner ownership changes are
 * applied.
 */
int pr_fsio_smkdir(pool *p, const char *path, mode_t mode, uid_t uid,
    gid_t gid) {
  int res, set_sgid = FALSE, use_mkdtemp, use_root_chown = FALSE, xerrno = 0;
  char *tmpl_path;
  char *dst_dir, *tmpl;
  size_t dst_dirlen, tmpl_len;

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 9,
    "smkdir: path '%s', mode %04o, UID %s, GID %s", path, (unsigned int) mode,
    pr_uid2str(p, uid), pr_gid2str(p, gid));

  if (fsio_guard_chroot) {
    res = chroot_allow_path(path);
    if (res < 0) {
      return -1;
    }
  }

  use_mkdtemp = fsio_use_mkdtemp;
  if (use_mkdtemp == TRUE) {

    /* Note that using mkdtemp(3) is a way of dealing with Bug#3841.  The
     * problem in question, though, only applies if root privs are used
     * to set the ownership.  Thus if root privs are NOT needed, then there
     * is no need to use mkdtemp(3).
     */

    if (uid != (uid_t) -1) {
      use_root_chown = TRUE;

    } else if (gid != (gid_t) -1) {
      register unsigned int i;

      use_root_chown = TRUE;

      /* Check if session.fsgid is in session.gids.  If not, use root privs.  */
      for (i = 0; i < session.gids->nelts; i++) {
        gid_t *group_ids = session.gids->elts;

        if (group_ids[i] == gid) {
          use_root_chown = FALSE;
          break;
        }
      }
    }

    if (use_root_chown == FALSE) {
      use_mkdtemp = FALSE;
    }
  }

#ifdef HAVE_MKDTEMP
  if (use_mkdtemp == TRUE) {
    char *ptr;
    struct stat st;

    ptr = strrchr(path, '/');
    if (ptr == NULL) {
      errno = EINVAL;
      return -1;
    }

    if (ptr != path) {
      dst_dirlen = (ptr - path);
      dst_dir = pstrndup(p, path, dst_dirlen);

    } else {
      dst_dirlen = 1;
      dst_dir = "/";
    }

    res = lstat(dst_dir, &st);
    if (res < 0) {
      xerrno = errno;

      pr_log_pri(PR_LOG_WARNING,
        "smkdir: unable to lstat(2) parent directory '%s': %s", dst_dir,
        strerror(xerrno));
      pr_trace_msg(trace_channel, 1,
        "smkdir: unable to lstat(2) parent directory '%s': %s", dst_dir,
        strerror(xerrno));

      errno = xerrno;
      return -1;
    }

    if (!S_ISDIR(st.st_mode) &&
        !S_ISLNK(st.st_mode)) {
      errno = EPERM;
      return -1;
    }

    if (st.st_mode & S_ISGID) {
      set_sgid = TRUE;
    }

    /* Allocate enough space for the temporary name: the length of the
     * destination directory, a slash, 9 X's, 3 for the prefix, and 1 for the
     * trailing NUL.
     */
    tmpl_len = dst_dirlen + 15;
    tmpl = pcalloc(p, tmpl_len);
    pr_snprintf(tmpl, tmpl_len-1, "%s/.dstXXXXXXXXX",
      dst_dirlen > 1 ? dst_dir : "");

    /* Use mkdtemp(3) to create the temporary directory (in the same destination
     * directory as the target path).
     */
    tmpl_path = mkdtemp(tmpl);
    if (tmpl_path == NULL) {
      xerrno = errno;

      pr_log_pri(PR_LOG_WARNING,
        "smkdir: mkdtemp(3) failed to create directory using '%s': %s", tmpl,
        strerror(xerrno));
      pr_trace_msg(trace_channel, 1,
        "smkdir: mkdtemp(3) failed to create directory using '%s': %s", tmpl,
        strerror(xerrno));

      errno = xerrno;
      return -1;
    }

  } else {
    res = pr_fsio_mkdir(path, mode);
    if (res < 0) {
      xerrno = errno;

      pr_trace_msg(trace_channel, 1,
        "mkdir(2) failed to create directory '%s' with perms %04o: %s", path,
        mode, strerror(xerrno));

      errno = xerrno;
      return -1;
    }

    tmpl_path = pstrdup(p, path);
  }
#else

  res = pr_fsio_mkdir(path, mode);
  if (res < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "mkdir(2) failed to create directory '%s' with perms %04o: %s", path,
      mode, strerror(xerrno));
        
    errno = xerrno;
    return -1;
  }

  tmpl_path = pstrdup(p, path);
#endif /* HAVE_MKDTEMP */

  if (use_mkdtemp == TRUE) {
    mode_t mask, *dir_umask, perms;

    /* mkdtemp(3) creates a directory with 0700 perms; we are given the
     * target mode (modulo the configured Umask).
     */
    dir_umask = get_param_ptr(CURRENT_CONF, "DirUmask", FALSE);
    if (dir_umask == NULL) {
      /* If Umask was configured with a single parameter, then DirUmask
       * would not be present; we still should check for Umask.
       */
      dir_umask = get_param_ptr(CURRENT_CONF, "Umask", FALSE);
    }

    if (dir_umask) {
      mask = *dir_umask;

    } else {
      mask = (mode_t) 0022;
    }

    perms = (mode & ~mask);

    if (set_sgid) {
      perms |= S_ISGID;
    }

    /* If we're setting the SGID bit, we need to use root privs, in order
     * to reliably set the SGID bit.  Sigh.
     */
    res = schmod_dir(p, tmpl_path, perms, set_sgid);
    xerrno = errno;

    if (set_sgid) {
      if (res < 0 &&
          xerrno == EPERM) {
        /* Try again, this time without root privs.  NFS situations which
         * squash root privs could cause the above chmod(2) to fail; it
         * might succeed now that we've dropped root privs (Bug#3962).
         */
        res = schmod_dir(p, tmpl_path, perms, FALSE);
        xerrno = errno;
      }
    }

    if (res < 0) {
      pr_log_pri(PR_LOG_WARNING, "chmod(%s) failed: %s", tmpl_path,
        strerror(xerrno));

      (void) rmdir(tmpl_path);

      errno = xerrno;
      return -1;
    }
  }

  if (uid != (uid_t) -1) {
    if (use_root_chown) {
      PRIVS_ROOT
    }

    res = pr_fsio_lchown(tmpl_path, uid, gid);
    xerrno = errno;

    if (use_root_chown) {
      PRIVS_RELINQUISH
    }

    if (res < 0) {
      pr_log_pri(PR_LOG_WARNING, "lchown(%s) as root failed: %s", tmpl_path,
        strerror(xerrno));

    } else {
      if (gid != (gid_t) -1) {
        pr_log_debug(DEBUG2, "root lchown(%s) to UID %s, GID %s successful",
          tmpl_path, pr_uid2str(p, uid), pr_gid2str(p, gid));

      } else {
        pr_log_debug(DEBUG2, "root lchown(%s) to UID %s successful",
          tmpl_path, pr_uid2str(NULL, uid));
      }
    }

  } else if (gid != (gid_t) -1) {
    if (use_root_chown) {
      PRIVS_ROOT
    }

    res = pr_fsio_lchown(tmpl_path, (uid_t) -1, gid);
    xerrno = errno;

    if (use_root_chown) {
      PRIVS_RELINQUISH
    }

    if (res < 0) {
      pr_log_pri(PR_LOG_WARNING, "%slchown(%s) failed: %s",
        use_root_chown ? "root " : "", tmpl_path, strerror(xerrno));

    } else {
      pr_log_debug(DEBUG2, "%slchown(%s) to GID %s successful",
        use_root_chown ? "root " : "", tmpl_path, pr_gid2str(p, gid));
    }
  }

  if (use_mkdtemp == TRUE) {
    /* Use rename(2) to move the temporary directory into place at the
     * target path.
     */
    res = rename(tmpl_path, path);
    if (res < 0) {
      xerrno = errno;

      pr_log_pri(PR_LOG_INFO, "renaming '%s' to '%s' failed: %s", tmpl_path,
        path, strerror(xerrno));

      (void) rmdir(tmpl_path);

#ifdef ENOTEMPTY
      if (xerrno == ENOTEMPTY) {
        /* If the rename(2) failed with "Directory not empty" (ENOTEMPTY),
         * then change the errno to "File exists" (EEXIST), so that the
         * error reported to the client is more indicative of the actual
         * cause.
         */
        xerrno = EEXIST;
      }
#endif /* ENOTEMPTY */
 
      errno = xerrno;
      return -1;
    }
  }

  pr_fs_clear_cache2(path);
  return 0;
}

int pr_fsio_rmdir(const char *path) {
  int res;
  pr_fs_t *fs;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = lookup_dir_fs(path, FSIO_DIR_RMDIR);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom rmdir handler.  If there are none,
   * use the system rmdir.
   */
  while (fs && fs->fs_next && !fs->rmdir) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s rmdir() for path '%s'", fs->fs_name,
    path);
  res = (fs->rmdir)(fs, path);
  if (res == 0) {
    pr_fs_clear_cache2(path);
  }

  return res;
}

int pr_fsio_rmdir_with_error(pool *p, const char *path, pr_error_t **err) {
  int res;

  res = pr_fsio_rmdir(path);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_rmdir(*err, path) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

int pr_fsio_stat(const char *path, struct stat *st) {
  pr_fs_t *fs = NULL;

  if (path == NULL ||
      st == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = lookup_file_fs(path, NULL, FSIO_FILE_STAT);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom stat handler.  If there are none,
   * use the system stat.
   */
  while (fs && fs->fs_next && !fs->stat) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s stat() for path '%s'", fs->fs_name,
    path);
  return fs_cache_stat(fs ? fs : root_fs, path, st);
}

int pr_fsio_stat_with_error(pool *p, const char *path, struct stat *st,
    pr_error_t **err) {
  int res;

  res = pr_fsio_stat(path, st);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_stat(*err, path, st) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

int pr_fsio_fstat(pr_fh_t *fh, struct stat *st) {
  int res;
  pr_fs_t *fs;

  if (fh == NULL ||
      st == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Find the first non-NULL custom fstat handler.  If there are none,
   * use the system fstat.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->fstat) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s fstat() for path '%s'", fs->fs_name,
    fh->fh_path);
  res = (fs->fstat)(fh, fh->fh_fd, st);

  return res;
}

int pr_fsio_lstat(const char *path, struct stat *st) {
  pr_fs_t *fs;

  if (path == NULL ||
      st == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = lookup_file_fs(path, NULL, FSIO_FILE_LSTAT);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom lstat handler.  If there are none,
   * use the system lstat.
   */
  while (fs && fs->fs_next && !fs->lstat) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s lstat() for path '%s'", fs->fs_name,
    path);
  return fs_cache_lstat(fs ? fs : root_fs, path, st);
}

int pr_fsio_lstat_with_error(pool *p, const char *path, struct stat *st,
    pr_error_t **err) {
  int res;

  res = pr_fsio_lstat(path, st);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_lstat(*err, path, st) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

int pr_fsio_readlink(const char *path, char *buf, size_t buflen) {
  int res;
  pr_fs_t *fs;

  if (path == NULL ||
      buf == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = lookup_file_fs(path, NULL, FSIO_FILE_READLINK);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom readlink handler.  If there are none,
   * use the system readlink.
   */
  while (fs && fs->fs_next && !fs->readlink) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s readlink() for path '%s'",
    fs->fs_name, path);
  res = (fs->readlink)(fs, path, buf, buflen);

  return res;
}

/* pr_fs_glob() is just a wrapper for glob(3), setting the various gl_
 * callbacks to our fs functions.
 */
int pr_fs_glob(const char *pattern, int flags,
    int (*errfunc)(const char *, int), glob_t *pglob) {

  if (pattern == NULL ||
      pglob == NULL) {
    errno = EINVAL;
    return -1;
  }

  flags |= GLOB_ALTDIRFUNC;

  pglob->gl_closedir = (void (*)(void *)) pr_fsio_closedir;
  pglob->gl_readdir = pr_fsio_readdir;
  pglob->gl_opendir = pr_fsio_opendir;
  pglob->gl_lstat = pr_fsio_lstat;
  pglob->gl_stat = pr_fsio_stat;

  return glob(pattern, flags, errfunc, pglob);
}

void pr_fs_globfree(glob_t *pglob) {
  if (pglob != NULL) {
    globfree(pglob);
  }
}

int pr_fsio_rename(const char *rnfr, const char *rnto) {
  int res;
  pr_fs_t *from_fs, *to_fs, *fs;

  if (rnfr == NULL ||
      rnto == NULL) {
    errno = EINVAL;
    return -1;
  }

  from_fs = lookup_file_fs(rnfr, NULL, FSIO_FILE_RENAME);
  if (from_fs == NULL) {
    return -1;
  }

  to_fs = lookup_file_fs(rnto, NULL, FSIO_FILE_RENAME);
  if (to_fs == NULL) {
    return -1;
  }

  if (from_fs->allow_xdev_rename == FALSE ||
      to_fs->allow_xdev_rename == FALSE) {
    if (from_fs != to_fs) {
      errno = EXDEV;
      return -1;
    }
  }

  fs = to_fs;

  /* Find the first non-NULL custom rename handler.  If there are none,
   * use the system rename.
   */
  while (fs && fs->fs_next && !fs->rename) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s rename() for paths '%s', '%s'",
    fs->fs_name, rnfr, rnto);
  res = (fs->rename)(fs, rnfr, rnto);
  if (res == 0) {
    pr_fs_clear_cache2(rnfr);
    pr_fs_clear_cache2(rnto);
  }

  return res;
}

int pr_fsio_rename_with_error(pool *p, const char *rnfr, const char *rnto,
    pr_error_t **err) {
  int res;

  res = pr_fsio_rename(rnfr, rnto);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_rename(*err, rnfr, rnto) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

int pr_fsio_unlink(const char *name) {
  int res;
  pr_fs_t *fs;

  if (name == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = lookup_file_fs(name, NULL, FSIO_FILE_UNLINK);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom unlink handler.  If there are none,
   * use the system unlink.
   */
  while (fs && fs->fs_next && !fs->unlink) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s unlink() for path '%s'",
    fs->fs_name, name);
  res = (fs->unlink)(fs, name);
  if (res == 0) {
    pr_fs_clear_cache2(name);
  }

  return res;
}

int pr_fsio_unlink_with_error(pool *p, const char *path, pr_error_t **err) {
  int res;

  res = pr_fsio_unlink(path);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_unlink(*err, path) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

pr_fh_t *pr_fsio_open_canon(const char *name, int flags) {
  char *deref = NULL;
  pool *tmp_pool = NULL;
  pr_fh_t *fh = NULL;
  pr_fs_t *fs = NULL;

  if (name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  fs = lookup_file_canon_fs(name, &deref, FSIO_FILE_OPEN);
  if (fs == NULL) {
    return NULL;
  }

  /* Allocate a filehandle. */
  tmp_pool = make_sub_pool(fs->fs_pool);
  pr_pool_tag(tmp_pool, "pr_fsio_open_canon() subpool");

  fh = pcalloc(tmp_pool, sizeof(pr_fh_t));
  fh->fh_pool = tmp_pool;
  fh->fh_path = pstrdup(fh->fh_pool, name);
  fh->fh_fd = -1;
  fh->fh_buf = NULL;
  fh->fh_fs = fs;

  /* Find the first non-NULL custom open handler.  If there are none,
   * use the system open.
   */
  while (fs && fs->fs_next && !fs->open) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s open() for path '%s'", fs->fs_name,
    name);
  fh->fh_fd = (fs->open)(fh, deref, flags);
  if (fh->fh_fd < 0) {
    int xerrno = errno;

    destroy_pool(fh->fh_pool);
    fh->fh_pool = NULL;

    errno = xerrno;
    return NULL;
  }

  if ((flags & O_CREAT) ||
      (flags & O_TRUNC)) {
    pr_fs_clear_cache2(name);
  }

  if (fcntl(fh->fh_fd, F_SETFD, FD_CLOEXEC) < 0) {
    if (errno != EBADF) {
      pr_trace_msg(trace_channel, 1, "error setting CLOEXEC on file fd %d: %s",
        fh->fh_fd, strerror(errno));
    }
  }

  return fh;
}

pr_fh_t *pr_fsio_open(const char *name, int flags) {
  pool *tmp_pool = NULL;
  pr_fh_t *fh = NULL;
  pr_fs_t *fs = NULL;

  if (name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  fs = lookup_file_fs(name, NULL, FSIO_FILE_OPEN);
  if (fs == NULL) {
    return NULL;
  }

  /* Allocate a filehandle. */
  tmp_pool = make_sub_pool(fs->fs_pool);
  pr_pool_tag(tmp_pool, "pr_fsio_open() subpool");

  fh = pcalloc(tmp_pool, sizeof(pr_fh_t));
  fh->fh_pool = tmp_pool;
  fh->fh_path = pstrdup(fh->fh_pool, name);
  fh->fh_fd = -1;
  fh->fh_buf = NULL;
  fh->fh_fs = fs;

  /* Find the first non-NULL custom open handler.  If there are none,
   * use the system open.
   */
  while (fs && fs->fs_next && !fs->open) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s open() for path '%s'", fs->fs_name,
    name);
  fh->fh_fd = (fs->open)(fh, name, flags);
  if (fh->fh_fd < 0) {
    int xerrno = errno;

    destroy_pool(fh->fh_pool);
    fh->fh_pool = NULL;

    errno = xerrno;
    return NULL;
  }

  if ((flags & O_CREAT) ||
      (flags & O_TRUNC)) {
    pr_fs_clear_cache2(name);
  }

  if (fcntl(fh->fh_fd, F_SETFD, FD_CLOEXEC) < 0) {
    if (errno != EBADF) {
      pr_trace_msg(trace_channel, 1, "error setting CLOEXEC on file fd %d: %s",
        fh->fh_fd, strerror(errno));
    }
  }

  return fh;
}

pr_fh_t *pr_fsio_open_with_error(pool *p, const char *name, int flags,
    pr_error_t **err) {
  pr_fh_t *fh;

  fh = pr_fsio_open(name, flags);
  if (fh == NULL) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_open(*err, name, flags, PR_OPEN_MODE) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return fh;
}

int pr_fsio_close(pr_fh_t *fh) {
  int res = 0, xerrno = 0;
  pr_fs_t *fs;

  if (fh == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Find the first non-NULL custom close handler.  If there are none,
   * use the system close.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->close) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s close() for path '%s'", fs->fs_name,
    fh->fh_path);
  res = (fs->close)(fh, fh->fh_fd);
  xerrno = errno;

  if (res == 0) {
    pr_fs_clear_cache2(fh->fh_path);
  }

  /* Make sure to scrub any buffered memory, too. */
  if (fh->fh_buf != NULL) {
    pr_buffer_t *pbuf;

    pbuf = fh->fh_buf;
    pr_memscrub(pbuf->buf, pbuf->buflen);
  }

  if (fh->fh_pool != NULL) {
    destroy_pool(fh->fh_pool);
    fh->fh_pool = NULL;
  }

  errno = xerrno;
  return res;
}

int pr_fsio_close_with_error(pool *p, pr_fh_t *fh, pr_error_t **err) {
  int res;

  res = pr_fsio_close(fh);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      int fd = -1;

      *err = pr_error_create(p, xerrno);

      if (fh != NULL) {
        fd = fh->fh_fd;
      }

      if (pr_error_explain_close(*err, fd) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

int pr_fsio_read(pr_fh_t *fh, char *buf, size_t size) {
  int res;
  pr_fs_t *fs;

  if (fh == NULL ||
      buf == NULL ||
      size == 0) {
    errno = EINVAL;
    return -1;
  }

  /* Find the first non-NULL custom read handler.  If there are none,
   * use the system read.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->read) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s read() for path '%s' (%lu bytes)",
    fs->fs_name, fh->fh_path, (unsigned long) size);
  res = (fs->read)(fh, fh->fh_fd, buf, size);

  return res;
}

int pr_fsio_read_with_error(pool *p, pr_fh_t *fh, char *buf, size_t sz,
    pr_error_t **err) {
  int res;

  res = pr_fsio_read(fh, buf, sz);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      int fd = -1;

      if (fh != NULL) {
        fd = fh->fh_fd;
      }

      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_read(*err, fd, buf, sz) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

int pr_fsio_write(pr_fh_t *fh, const char *buf, size_t size) {
  int res;
  pr_fs_t *fs;

  if (fh == NULL ||
      buf == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Find the first non-NULL custom write handler.  If there are none,
   * use the system write.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->write) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s write() for path '%s' (%lu bytes)",
    fs->fs_name, fh->fh_path, (unsigned long) size);
  res = (fs->write)(fh, fh->fh_fd, buf, size);

  return res;
}

int pr_fsio_write_with_error(pool *p, pr_fh_t *fh, const char *buf, size_t sz,
    pr_error_t **err) {
  int res;

  res = pr_fsio_write(fh, buf, sz);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      int fd = -1;

      if (fh != NULL) {
        fd = fh->fh_fd;
      }

      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_write(*err, fd, buf, sz) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

off_t pr_fsio_lseek(pr_fh_t *fh, off_t offset, int whence) {
  off_t res;
  pr_fs_t *fs;

  if (fh == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Find the first non-NULL custom lseek handler.  If there are none,
   * use the system lseek.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->lseek) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s lseek() for path '%s'", fs->fs_name,
    fh->fh_path);
  res = (fs->lseek)(fh, fh->fh_fd, offset, whence);

  return res;
}

int pr_fsio_link(const char *target_path, const char *link_path) {
  int res;
  pr_fs_t *target_fs, *link_fs, *fs;

  if (target_path == NULL ||
      link_path == NULL) {
    errno = EINVAL;
    return -1;
  }

  target_fs = lookup_file_fs(target_path, NULL, FSIO_FILE_LINK);
  if (target_fs == NULL) {
    return -1;
  }

  link_fs = lookup_file_fs(link_path, NULL, FSIO_FILE_LINK);
  if (link_fs == NULL) {
    return -1;
  }

  if (target_fs->allow_xdev_link == FALSE ||
      link_fs->allow_xdev_link == FALSE) {
    if (target_fs != link_fs) {
      errno = EXDEV;
      return -1;
    }
  }

  fs = link_fs;

  /* Find the first non-NULL custom link handler.  If there are none,
   * use the system link.
   */
  while (fs && fs->fs_next && !fs->link) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s link() for paths '%s', '%s'",
    fs->fs_name, target_path, link_path);
  res = (fs->link)(fs, target_path, link_path);
  if (res == 0) {
    pr_fs_clear_cache2(link_path);
  }

  return res;
}

int pr_fsio_symlink(const char *target_path, const char *link_path) {
  int res;
  pr_fs_t *fs;

  if (target_path == NULL ||
      link_path == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = lookup_file_fs(link_path, NULL, FSIO_FILE_SYMLINK);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom symlink handler.  If there are none,
   * use the system symlink.
   */
  while (fs && fs->fs_next && !fs->symlink) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s symlink() for path '%s'",
    fs->fs_name, link_path);
  res = (fs->symlink)(fs, target_path, link_path);
  if (res == 0) {
    pr_fs_clear_cache2(link_path);
  }

  return res;
}

int pr_fsio_ftruncate(pr_fh_t *fh, off_t len) {
  int res;
  pr_fs_t *fs;

  if (fh == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Find the first non-NULL custom ftruncate handler.  If there are none,
   * use the system ftruncate.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->ftruncate) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s ftruncate() for path '%s'",
    fs->fs_name, fh->fh_path);
  res = (fs->ftruncate)(fh, fh->fh_fd, len);
  if (res == 0) {
    pr_fs_clear_cache2(fh->fh_path);

    /* Clear any read buffer. */
    if (fh->fh_buf != NULL) {
      fh->fh_buf->current = fh->fh_buf->buf;
      fh->fh_buf->remaining = fh->fh_buf->buflen;
    }
  }

  return res;
}

int pr_fsio_truncate(const char *path, off_t len) {
  int res;
  pr_fs_t *fs;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = lookup_file_fs(path, NULL, FSIO_FILE_TRUNC);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom truncate handler.  If there are none,
   * use the system truncate.
   */
  while (fs && fs->fs_next && !fs->truncate) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s truncate() for path '%s'",
    fs->fs_name, path);
  res = (fs->truncate)(fs, path, len);
  if (res == 0) {
    pr_fs_clear_cache2(path);
  }
  
  return res;
}

int pr_fsio_chmod(const char *name, mode_t mode) {
  int res;
  pr_fs_t *fs;

  if (name == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = lookup_file_fs(name, NULL, FSIO_FILE_CHMOD);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom chmod handler.  If there are none,
   * use the system chmod.
   */
  while (fs && fs->fs_next && !fs->chmod) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s chmod() for path '%s'",
    fs->fs_name, name);
  res = (fs->chmod)(fs, name, mode);
  if (res == 0) {
    pr_fs_clear_cache2(name);
  }

  return res;
}

int pr_fsio_chmod_with_error(pool *p, const char *path, mode_t mode,
    pr_error_t **err) {
  int res;

  res = pr_fsio_chmod(path, mode);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_chmod(*err, path, mode) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

int pr_fsio_fchmod(pr_fh_t *fh, mode_t mode) {
  int res;
  pr_fs_t *fs;

  if (fh == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Find the first non-NULL custom fchmod handler.  If there are none, use
   * the system fchmod.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->fchmod) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s fchmod() for path '%s'",
    fs->fs_name, fh->fh_path);
  res = (fs->fchmod)(fh, fh->fh_fd, mode);
  if (res == 0) {
    pr_fs_clear_cache2(fh->fh_path);
  }

  return res;
}

int pr_fsio_fchmod_with_error(pool *p, pr_fh_t *fh, mode_t mode,
    pr_error_t **err) {
  int res;

  res = pr_fsio_fchmod(fh, mode);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      int fd = -1;

      if (fh != NULL) {
        fd = fh->fh_fd;
      }

      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_fchmod(*err, fd, mode) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

int pr_fsio_chown(const char *name, uid_t uid, gid_t gid) {
  int res;
  pr_fs_t *fs;

  if (name == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = lookup_file_fs(name, NULL, FSIO_FILE_CHOWN);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom chown handler.  If there are none,
   * use the system chown.
   */
  while (fs && fs->fs_next && !fs->chown) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s chown() for path '%s'",
    fs->fs_name, name);
  res = (fs->chown)(fs, name, uid, gid);
  if (res == 0) {
    pr_fs_clear_cache2(name);
  }

  return res;
}

int pr_fsio_chown_with_error(pool *p, const char *path, uid_t uid, gid_t gid,
    pr_error_t **err) {
  int res;

  res = pr_fsio_chown(path, uid, gid);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_chown(*err, path, uid, gid) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

int pr_fsio_fchown(pr_fh_t *fh, uid_t uid, gid_t gid) {
  int res;
  pr_fs_t *fs;

  if (fh == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Find the first non-NULL custom fchown handler.  If there are none, use
   * the system fchown.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->fchown) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s fchown() for path '%s'",
    fs->fs_name, fh->fh_path);
  res = (fs->fchown)(fh, fh->fh_fd, uid, gid);
  if (res == 0) {
    pr_fs_clear_cache2(fh->fh_path);
  }

  return res;
}

int pr_fsio_fchown_with_error(pool *p, pr_fh_t *fh, uid_t uid, gid_t gid,
    pr_error_t **err) {
  int res;

  res = pr_fsio_fchown(fh, uid, gid);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      int fd = -1;

      if (fh != NULL) {
        fd = fh->fh_fd;
      }

      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_fchown(*err, fd, uid, gid) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

int pr_fsio_lchown(const char *name, uid_t uid, gid_t gid) {
  int res;
  pr_fs_t *fs;

  if (name == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = lookup_file_fs(name, NULL, FSIO_FILE_CHOWN);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom lchown handler.  If there are none,
   * use the system chown.
   */
  while (fs && fs->fs_next && !fs->lchown) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s lchown() for path '%s'",
    fs->fs_name, name);
  res = (fs->lchown)(fs, name, uid, gid);
  if (res == 0) {
    pr_fs_clear_cache2(name);
  }

  return res;
}

int pr_fsio_lchown_with_error(pool *p, const char *path, uid_t uid, gid_t gid,
    pr_error_t **err) {
  int res;

  res = pr_fsio_lchown(path, uid, gid);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_lchown(*err, path, uid, gid) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

int pr_fsio_access(const char *path, int mode, uid_t uid, gid_t gid,
    array_header *suppl_gids) {
  pr_fs_t *fs;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = lookup_file_fs(path, NULL, FSIO_FILE_ACCESS);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom access handler.  If there are none,
   * use the system access.
   */
  while (fs && fs->fs_next && !fs->access) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s access() for path '%s'",
    fs->fs_name, path);
  return (fs->access)(fs, path, mode, uid, gid, suppl_gids);
}

int pr_fsio_faccess(pr_fh_t *fh, int mode, uid_t uid, gid_t gid,
    array_header *suppl_gids) {
  pr_fs_t *fs;

  if (fh == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Find the first non-NULL custom faccess handler.  If there are none,
   * use the system faccess.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->faccess) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s faccess() for path '%s'",
    fs->fs_name, fh->fh_path);
  return (fs->faccess)(fh, mode, uid, gid, suppl_gids);
}

int pr_fsio_utimes(const char *path, struct timeval *tvs) {
  int res;
  pr_fs_t *fs;

  if (path == NULL ||
      tvs == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = lookup_file_fs(path, NULL, FSIO_FILE_UTIMES);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom utimes handler.  If there are none,
   * use the system utimes.
   */
  while (fs && fs->fs_next && !fs->utimes) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s utimes() for path '%s'",
    fs->fs_name, path);
  res = (fs->utimes)(fs, path, tvs);
  if (res == 0) {
    pr_fs_clear_cache2(path);
  }

  return res;
}

/* If the utimes(2) call fails because the process UID does not match the file
 * UID, then check to see if the GIDs match (and that the file has group write
 * permissions).
 *
 * This can be alleviated in two ways: a) if mod_cap is present, enable the
 * CAP_FOWNER capability for the session, or b) use root privs.
 */
int pr_fsio_utimes_with_root(const char *path, struct timeval *tvs) {
  int res, xerrno, matching_gid = FALSE;
  struct stat st;

  res = pr_fsio_utimes(path, tvs);
  xerrno = errno;

  if (res == 0) {
    return 0;
  }

  /* We only try these workarounds for EPERM. */
  if (xerrno != EPERM) {
    return res;
  }

  pr_fs_clear_cache2(path);
  if (pr_fsio_stat(path, &st) < 0) {
    errno = xerrno;
    return -1;
  }

  /* Be sure to check the primary and all the supplemental groups to which
   * this session belongs.
   */
  if (st.st_gid == session.gid) {
    matching_gid = TRUE;

  } else if (session.gids != NULL) {
    register unsigned int i;
    gid_t *gids;

    gids = session.gids->elts;
    for (i = 0; i < session.gids->nelts; i++) {
      if (st.st_gid == gids[i]) {
        matching_gid = TRUE;
        break;
      }
    }
  }

  if (matching_gid == TRUE &&
      (st.st_mode & S_IWGRP)) {

    /* Try the utimes(2) call again, this time with root privs. */
    pr_signals_block();
    PRIVS_ROOT
    res = pr_fsio_utimes(path, tvs);
    PRIVS_RELINQUISH
    pr_signals_unblock();

    if (res == 0) {
      return 0;
    }
  }

  errno = xerrno;
  return -1;
}

int pr_fsio_futimes(pr_fh_t *fh, struct timeval *tvs) {
  int res;
  pr_fs_t *fs;

  if (fh == NULL ||
      tvs == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Find the first non-NULL custom futimes handler.  If there are none,
   * use the system futimes.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->futimes) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s futimes() for path '%s'",
    fs->fs_name, fh->fh_path);
  res = (fs->futimes)(fh, fh->fh_fd, tvs);
  if (res == 0) {
    pr_fs_clear_cache2(fh->fh_path);
  }

  return res;
}

int pr_fsio_fsync(pr_fh_t *fh) {
  int res;
  pr_fs_t *fs;

  if (fh == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Find the first non-NULL custom fsync handler.  If there are none,
   * use the system fsync.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->fsync) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s fsync() for path '%s'",
    fs->fs_name, fh->fh_path);
  res = (fs->fsync)(fh, fh->fh_fd);
  if (res == 0) {
    pr_fs_clear_cache2(fh->fh_path);
  }

  return res;
}

ssize_t pr_fsio_getxattr(pool *p, const char *path, const char *name, void *val,
    size_t valsz) {
  ssize_t res;
  pr_fs_t *fs;

  if (p == NULL ||
      path == NULL ||
      name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fsio_opts & PR_FSIO_OPT_IGNORE_XATTR) {
    errno = ENOSYS;
    return -1;
  }

  fs = lookup_file_fs(path, NULL, FSIO_FILE_GETXATTR);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom getxattr handler.  If there are none,
   * use the system getxattr.
   */
  while (fs && fs->fs_next && !fs->getxattr) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s getxattr() for path '%s'",
    fs->fs_name, path);
  res = (fs->getxattr)(p, fs, path, name, val, valsz);
  return res;
}

ssize_t pr_fsio_lgetxattr(pool *p, const char *path, const char *name,
    void *val, size_t valsz) {
  ssize_t res;
  pr_fs_t *fs;

  if (p == NULL ||
      path == NULL ||
      name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fsio_opts & PR_FSIO_OPT_IGNORE_XATTR) {
    errno = ENOSYS;
    return -1;
  }

  fs = lookup_file_fs(path, NULL, FSIO_FILE_LGETXATTR);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom lgetxattr handler.  If there are none,
   * use the system lgetxattr.
   */
  while (fs && fs->fs_next && !fs->lgetxattr) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s lgetxattr() for path '%s'",
    fs->fs_name, path);
  res = (fs->lgetxattr)(p, fs, path, name, val, valsz);
  return res;
}

ssize_t pr_fsio_fgetxattr(pool *p, pr_fh_t *fh, const char *name, void *val,
    size_t valsz) {
  ssize_t res;
  pr_fs_t *fs;

  if (p == NULL ||
      fh == NULL ||
      name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fsio_opts & PR_FSIO_OPT_IGNORE_XATTR) {
    errno = ENOSYS;
    return -1;
  }

  /* Find the first non-NULL custom fgetxattr handler.  If there are none,
   * use the system fgetxattr.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->fgetxattr) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s fgetxattr() for path '%s'",
    fs->fs_name, fh->fh_path);
  res = (fs->fgetxattr)(p, fh, fh->fh_fd, name, val, valsz);
  return res;
}

int pr_fsio_listxattr(pool *p, const char *path, array_header **names) {
  int res;
  pr_fs_t *fs;

  if (p == NULL ||
      path == NULL ||
      names == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fsio_opts & PR_FSIO_OPT_IGNORE_XATTR) {
    errno = ENOSYS;
    return -1;
  }

  fs = lookup_file_fs(path, NULL, FSIO_FILE_LISTXATTR);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom listxattr handler.  If there are none,
   * use the system listxattr.
   */
  while (fs && fs->fs_next && !fs->listxattr) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s listxattr() for path '%s'",
    fs->fs_name, path);
  res = (fs->listxattr)(p, fs, path, names);
  return res;
}

int pr_fsio_llistxattr(pool *p, const char *path, array_header **names) {
  int res;
  pr_fs_t *fs;

  if (p == NULL ||
      path == NULL ||
      names == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fsio_opts & PR_FSIO_OPT_IGNORE_XATTR) {
    errno = ENOSYS;
    return -1;
  }

  fs = lookup_file_fs(path, NULL, FSIO_FILE_LLISTXATTR);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom llistxattr handler.  If there are none,
   * use the system llistxattr.
   */
  while (fs && fs->fs_next && !fs->llistxattr) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s llistxattr() for path '%s'",
    fs->fs_name, path);
  res = (fs->llistxattr)(p, fs, path, names);
  return res;
}

int pr_fsio_flistxattr(pool *p, pr_fh_t *fh, array_header **names) {
  int res;
  pr_fs_t *fs;

  if (p == NULL ||
      fh == NULL ||
      names == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fsio_opts & PR_FSIO_OPT_IGNORE_XATTR) {
    errno = ENOSYS;
    return -1;
  }

  /* Find the first non-NULL custom flistxattr handler.  If there are none,
   * use the system flistxattr.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->flistxattr) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s flistxattr() for path '%s'",
    fs->fs_name, fh->fh_path);
  res = (fs->flistxattr)(p, fh, fh->fh_fd, names);
  return res;
}

int pr_fsio_removexattr(pool *p, const char *path, const char *name) {
  int res;
  pr_fs_t *fs;

  if (p == NULL ||
      path == NULL ||
      name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fsio_opts & PR_FSIO_OPT_IGNORE_XATTR) {
    errno = ENOSYS;
    return -1;
  }

  fs = lookup_file_fs(path, NULL, FSIO_FILE_REMOVEXATTR);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom removexattr handler.  If there are none,
   * use the system removexattr.
   */
  while (fs && fs->fs_next && !fs->removexattr) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s removexattr() for path '%s'",
    fs->fs_name, path);
  res = (fs->removexattr)(p, fs, path, name);
  return res;
}

int pr_fsio_lremovexattr(pool *p, const char *path, const char *name) {
  int res;
  pr_fs_t *fs;

  if (p == NULL ||
      path == NULL ||
      name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fsio_opts & PR_FSIO_OPT_IGNORE_XATTR) {
    errno = ENOSYS;
    return -1;
  }

  fs = lookup_file_fs(path, NULL, FSIO_FILE_LREMOVEXATTR);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom lremovexattr handler.  If there are none,
   * use the system lremovexattr.
   */
  while (fs && fs->fs_next && !fs->lremovexattr) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s lremovexattr() for path '%s'",
    fs->fs_name, path);
  res = (fs->lremovexattr)(p, fs, path, name);
  return res;
}

int pr_fsio_fremovexattr(pool *p, pr_fh_t *fh, const char *name) {
  int res;
  pr_fs_t *fs;

  if (p == NULL ||
      fh == NULL ||
      name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fsio_opts & PR_FSIO_OPT_IGNORE_XATTR) {
    errno = ENOSYS;
    return -1;
  }

  /* Find the first non-NULL custom fremovexattr handler.  If there are none,
   * use the system fremovexattr.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->fremovexattr) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s fremovexattr() for path '%s'",
    fs->fs_name, fh->fh_path);
  res = (fs->fremovexattr)(p, fh, fh->fh_fd, name);
  return res;
}

int pr_fsio_setxattr(pool *p, const char *path, const char *name, void *val,
    size_t valsz, int flags) {
  int res;
  pr_fs_t *fs;

  if (p == NULL ||
      path == NULL ||
      name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fsio_opts & PR_FSIO_OPT_IGNORE_XATTR) {
    errno = ENOSYS;
    return -1;
  }

  fs = lookup_file_fs(path, NULL, FSIO_FILE_SETXATTR);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom setxattr handler.  If there are none,
   * use the system setxattr.
   */
  while (fs && fs->fs_next && !fs->setxattr) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s setxattr() for path '%s'",
    fs->fs_name, path);
  res = (fs->setxattr)(p, fs, path, name, val, valsz, flags);
  return res;
}

int pr_fsio_lsetxattr(pool *p, const char *path, const char *name, void *val,
    size_t valsz, int flags) {
  int res;
  pr_fs_t *fs;

  if (p == NULL ||
      path == NULL ||
      name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fsio_opts & PR_FSIO_OPT_IGNORE_XATTR) {
    errno = ENOSYS;
    return -1;
  }

  fs = lookup_file_fs(path, NULL, FSIO_FILE_LSETXATTR);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom lsetxattr handler.  If there are none,
   * use the system lsetxattr.
   */
  while (fs && fs->fs_next && !fs->lsetxattr) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s lsetxattr() for path '%s'",
    fs->fs_name, path);
  res = (fs->lsetxattr)(p, fs, path, name, val, valsz, flags);
  return res;
}

int pr_fsio_fsetxattr(pool *p, pr_fh_t *fh, const char *name, void *val,
    size_t valsz, int flags) {
  int res;
  pr_fs_t *fs;

  if (p == NULL ||
      fh == NULL ||
      name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fsio_opts & PR_FSIO_OPT_IGNORE_XATTR) {
    errno = ENOSYS;
    return -1;
  }

  /* Find the first non-NULL custom fsetxattr handler.  If there are none,
   * use the system fsetxattr.
   */
  fs = fh->fh_fs;
  while (fs && fs->fs_next && !fs->fsetxattr) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s fsetxattr() for path '%s'",
    fs->fs_name, fh->fh_path);
  res = (fs->fsetxattr)(p, fh, fh->fh_fd, name, val, valsz, flags);
  return res;
}

/* If the wrapped chroot() function succeeds (e.g. returns 0), then all
 * pr_fs_ts currently registered in the fs_map will have their paths
 * rewritten to reflect the new root.
 */
int pr_fsio_chroot(const char *path) {
  int res = 0, xerrno = 0;
  pr_fs_t *fs;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  fs = lookup_dir_fs(path, FSIO_DIR_CHROOT);
  if (fs == NULL) {
    return -1;
  }

  /* Find the first non-NULL custom chroot handler.  If there are none,
   * use the system chroot.
   */
  while (fs && fs->fs_next && !fs->chroot) {
    fs = fs->fs_next;
  }

  pr_trace_msg(trace_channel, 8, "using %s chroot() for path '%s'",
    fs->fs_name, path);
  res = (fs->chroot)(fs, path);
  xerrno = errno;

  if (res == 0) {
    unsigned int iter_start = 0;

    /* The filesystem handles in fs_map need to be readjusted to the new root.
     */
    register unsigned int i = 0;
    pool *map_pool = make_sub_pool(permanent_pool);
    array_header *new_map = make_array(map_pool, 0, sizeof(pr_fs_t *));
    pr_fs_t **fs_objs = NULL;

    pr_pool_tag(map_pool, "FSIO Map Pool");

    if (fs_map) {
      fs_objs = (pr_fs_t **) fs_map->elts;
    }

    if (fs != root_fs) {
      if (strncmp(fs->fs_path, path, strlen(path)) == 0) {
        memmove(fs->fs_path, fs->fs_path + strlen(path),
          strlen(fs->fs_path) - strlen(path) + 1);
      }

      *((pr_fs_t **) push_array(new_map)) = fs;
      iter_start = 1;
    }

    for (i = iter_start; i < (fs_map ? fs_map->nelts : 0); i++) {
      pr_fs_t *tmpfs = fs_objs[i];

      /* The memory for this field has already been allocated, so futzing
       * with it like this should be fine.  Watch out for any paths that
       * may be different, e.g. added manually, not through pr_register_fs().
       * Any absolute paths that are outside of the chroot path are discarded.
       * Deferred-resolution paths (eg "~" paths) and relative paths are kept.
       */

      if (strncmp(tmpfs->fs_path, path, strlen(path)) == 0) {
        pr_fs_t *next;

        memmove(tmpfs->fs_path, tmpfs->fs_path + strlen(path),
          strlen(tmpfs->fs_path) - strlen(path) + 1);

        /* Need to do this for any stacked FSs as well. */
        next = tmpfs->fs_next;
        while (next) {
          pr_signals_handle();

          memmove(next->fs_path, next->fs_path + strlen(path),
            strlen(next->fs_path) - strlen(path) + 1);

          next = next->fs_next;
        }
      }

      /* Add this FS to the new fs_map. */
      *((pr_fs_t **) push_array(new_map)) = tmpfs;
    }

    /* Sort the new map */
    qsort(new_map->elts, new_map->nelts, sizeof(pr_fs_t *), fs_cmp);

    /* Destroy the old map */
    if (fs_map != NULL) {
      destroy_pool(fs_map->pool);
    }

    fs_map = new_map;
    chk_fs_map = TRUE;
  }

  errno = xerrno;
  return res;
}

int pr_fsio_chroot_with_error(pool *p, const char *path, pr_error_t **err) {
  int res;

  res = pr_fsio_chroot(path);
  if (res < 0) {
    int xerrno = errno;

    if (p != NULL &&
        err != NULL) {
      *err = pr_error_create(p, xerrno);
      if (pr_error_explain_chroot(*err, path) < 0) {
        pr_error_destroy(*err);
        *err = NULL;
      }
    }

    errno = xerrno;
  }

  return res;
}

char *pr_fsio_getpipebuf(pool *p, int fd, long *bufsz) {
  char *buf = NULL;
  long buflen;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (fd < 0) {
    errno = EBADF;
    return NULL;
  }

#if defined(PIPE_BUF)
  buflen = PIPE_BUF;

#elif defined(HAVE_FPATHCONF)
  /* Some platforms do not define a PIPE_BUF constant.  For them, we need
   * to use fpathconf(2), if available.
   */
  buflen = fpathconf(fd, _PC_PIPE_BUF);
  if (buflen < 0) {
    return NULL;
  }

#else
  errno = ENOSYS;
  return NULL;
#endif

  if (bufsz != NULL) {
    *bufsz = buflen;
  }

  buf = palloc(p, buflen);
  return buf;
}

char *pr_fsio_gets(char *buf, size_t size, pr_fh_t *fh) {
  char *bp = NULL;
  int toread = 0;
  pr_buffer_t *pbuf = NULL;

  if (buf == NULL ||
      fh == NULL ||
      size == 0) {
    errno = EINVAL;
    return NULL;
  }

  if (fh->fh_buf == NULL) {
    size_t bufsz;

    /* Conscientious callers who want the optimal IO on the file should
     * set the fh->fh_iosz hint.
     */
    bufsz = fh->fh_iosz ? fh->fh_iosz : PR_TUNABLE_BUFFER_SIZE;

    fh->fh_buf = pcalloc(fh->fh_pool, sizeof(pr_buffer_t));
    fh->fh_buf->buf = fh->fh_buf->current = pcalloc(fh->fh_pool, bufsz);
    fh->fh_buf->remaining = fh->fh_buf->buflen = bufsz;
  }

  pbuf = fh->fh_buf;
  bp = buf;

  while (size) {
    pr_signals_handle();

    if (pbuf->current == NULL ||
        pbuf->remaining == pbuf->buflen) { /* empty buffer */

      toread = pr_fsio_read(fh, pbuf->buf, pbuf->buflen);
      if (toread <= 0) {
        if (bp != buf) {
          *bp = '\0';
          return buf;
        }

        return NULL;
      }

      pbuf->remaining = pbuf->buflen - toread;
      pbuf->current = pbuf->buf;

    } else {
      toread = pbuf->buflen - pbuf->remaining;
    }

    /* TODO: Improve the efficiency of this copy by using a strnchr(3)
     * scan to find the next LF, and then a memmove(2) to do the copy.
     */
    while (size &&
           toread > 0 &&
           *pbuf->current != '\n' &&
           toread--) {
      pr_signals_handle();

      *bp++ = *pbuf->current++;
      size--;
      pbuf->remaining++;
    }

    if (size &&
        toread &&
        *pbuf->current == '\n') {
      size--;
      toread--;
      *bp++ = *pbuf->current++;
      pbuf->remaining++;
      break;
    }

    if (!toread) {
      pbuf->current = NULL;
    }
  }

  *bp = '\0';
  return buf;
}

/* pr_fsio_getline() is an fgets() with backslash-newline stripping, copied from
 * Wietse Venema's tcpwrapppers-7.6 code.  The extra *lineno argument is
 * needed, at the moment, to properly track which line of the configuration
 * file is being read in, so that errors can be reported with line numbers
 * correctly.
 */
char *pr_fsio_getline(char *buf, size_t buflen, pr_fh_t *fh,
    unsigned int *lineno) {
  int inlen;
  char *start;

  if (buf == NULL ||
      fh == NULL ||
      buflen == 0) {
    errno = EINVAL;
    return NULL;
  }

  start = buf;
  while (pr_fsio_gets(buf, buflen, fh) != NULL) {
    pr_signals_handle();

    inlen = strlen(buf);

    if (inlen >= 1) {
      if (buf[inlen - 1] == '\n') {
        if (lineno != NULL) {
          (*lineno)++;
        }

        if (inlen >= 2 && buf[inlen - 2] == '\\') {
          char *bufp;

          inlen -= 2;
      
          /* Watch for commented lines when handling line continuations.
           * Advance past any leading whitespace, to see if the first
           * non-whitespace character is the comment character.
           */
          for (bufp = buf; *bufp && PR_ISSPACE(*bufp); bufp++);

          if (*bufp == '#') {
            continue;
          }
 
        } else {
          return start;
        }
      }
    }

    /* Be careful of reading too much. */
    if (buflen - inlen == 0) {
      return buf;
    }

    buf += inlen;
    buflen -= inlen;
    buf[0] = 0;
  }

  return (buf > start ? start : NULL);
}

#define FSIO_MAX_FD_COUNT		1024

void pr_fs_close_extra_fds(void) {
  register unsigned int i;
  long nfiles = 0;
  struct rlimit rlim;

  /* Close any but the big three open fds.
   *
   * First, use getrlimit() to obtain the maximum number of open files
   * for this process -- then close that number.
   */
#if defined(RLIMIT_NOFILE) || defined(RLIMIT_OFILE)
# if defined(RLIMIT_NOFILE)
  if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
# elif defined(RLIMIT_OFILE)
  if (getrlimit(RLIMIT_OFILE, &rlim) < 0) {
# endif
    /* Ignore ENOSYS (and EPERM, since some libc's use this as ENOSYS); pick
     * some arbitrary high number.
     */
    nfiles = FSIO_MAX_FD_COUNT;

  } else {
    nfiles = rlim.rlim_max;
  }

#else /* no RLIMIT_NOFILE or RLIMIT_OFILE */
   nfiles = FSIO_MAX_FD_COUNT;
#endif

  /* Yes, using a long for the nfiles variable is not quite kosher; it should
   * be an unsigned type, otherwise a large limit (say, RLIMIT_INFINITY)
   * might overflow the data type.  In that case, though, we want to know
   * about it -- and using a signed type, we will know if the overflowed
   * value is a negative number.  Chances are we do NOT want to be closing
   * fds whose value is as high as they can possibly get; that's too many
   * fds to iterate over.  Long story short, using a long int is just fine.
   * (Plus it makes mod_exec work on Mac OSX 10.4; without this tweak,
   * mod_exec's forked processes never return/exit.)
   */

  if (nfiles < 0 ||
      nfiles > FSIO_MAX_FD_COUNT) {
    nfiles = FSIO_MAX_FD_COUNT;
  }

  /* Close the "non-standard" file descriptors. */
  for (i = 3; i < nfiles; i++) {
    /* This is a potentially long-running loop, so handle signals. */
    pr_signals_handle();
    (void) close(i);
  }
}

/* Be generous in the maximum allowed number of dup fds, in our search for
 * one that is outside the big three.
 *
 * In theory, this should be a runtime lookup using getdtablesize(2), being
 * sure to handle the ENOSYS case (for older systems).
 */
#define FSIO_MAX_DUPFDS		512

/* The main three fds (stdin, stdout, stderr) need to be protected, reserved
 * for use.  This function uses dup(2) to open new fds on the given fd
 * until the new fd is not one of the big three.
 */
int pr_fs_get_usable_fd(int fd) {
  register int i;
  int fdi, dup_fds[FSIO_MAX_DUPFDS], n; 

  if (fd > STDERR_FILENO) {
    return fd;
  }
 
  memset(dup_fds, -1, sizeof(dup_fds));
  i = 0;
  n = -1;

  fdi = fd;
  while (i < FSIO_MAX_DUPFDS) {
    pr_signals_handle();

    dup_fds[i] = dup(fdi);
    if (dup_fds[i] < 0) {
      register int j;
      int xerrno  = errno;

      /* Need to clean up any previously opened dups as well. */
      for (j = 0; j <= i; j++) {
        close(dup_fds[j]);
        dup_fds[j] = -1;
      }

      errno = xerrno;
      return -1;
    }

    if (dup_fds[i] <= STDERR_FILENO) {
      /* Continue searching for an open fd that isn't 0, 1, or 2. */
      fdi = dup_fds[i];
      i++;
      continue;
    }

    n = i;
    fdi = dup_fds[n];
    break;
  }

  /* If n is -1, we reached the max number of dups without finding an
   * open one.  Hard to imagine this happening, but catch the case anyway.
   */
  if (n == -1) {
    /* Free up the fds we opened in our search. */
    for (i = 0; i < FSIO_MAX_DUPFDS; i++) {
      if (dup_fds[i] >= 0) {
        close(dup_fds[i]);
        dup_fds[i] = -1;
      }
    }

    errno = EPERM;
    return -1;
  }

  /* Free up the fds we opened in our search. */
  for (i = 0; i < n; i++) {
    (void) close(dup_fds[i]);
    dup_fds[i] = -1;
  }

  return fdi;
}

int pr_fs_get_usable_fd2(int *fd) {
  int new_fd = -1, res = 0;

  if (fd == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (*fd > STDERR_FILENO) {
    /* No need to obtain a different fd; the given one is already not one
     * of the big three.
     */
    return 0;
  }

  new_fd = pr_fs_get_usable_fd(*fd);
  if (new_fd >= 0) {
    (void) close(*fd);
    *fd = new_fd;

  } else {
    res = -1;
  }

  return res;
}

/* Simple multiplication and division doesn't work with very large
 * filesystems (overflows 32 bits).  This code should handle it.
 *
 * Note that this returns a size in KB, not bytes.
 */
static off_t get_fs_size(size_t nblocks, size_t blocksz) {
  off_t bl_lo, bl_hi;
  off_t res_lo, res_hi, tmp;

  bl_lo = nblocks & 0x0000ffff;
  bl_hi = nblocks & 0xffff0000;

  tmp = (bl_hi >> 16) * blocksz;
  res_hi = tmp & 0xffff0000;
  res_lo = (tmp & 0x0000ffff) << 16;
  res_lo += bl_lo * blocksz;

  if (res_hi & 0xfc000000) {
    /* Overflow */
    return 0;
  }

  return (res_lo >> 10) | (res_hi << 6);
}

static int fs_getsize(int fd, char *path, off_t *fs_size) {
  int res = -1;

# if defined(HAVE_SYS_STATVFS_H)

#  if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64 && \
    defined(SOLARIS2) && !defined(SOLARIS2_5_1) && !defined(SOLARIS2_6) && \
    !defined(SOLARIS2_7)
  /* Note: somewhere along the way, Sun decided that the prototype for
   * its statvfs64(2) function would include a statvfs64_t rather than
   * struct statvfs64.  In 2.6 and 2.7, it's struct statvfs64, and
   * in 8, 9 it's statvfs64_t.  This should silence compiler warnings.
   * (The statvfs_t will be redefined to a statvfs64_t as appropriate on
   * LFS systems).
   */
  statvfs_t fs;
#  else
  struct statvfs fs;
#  endif /* LFS && !Solaris 2.5.1 && !Solaris 2.6 && !Solaris 2.7 */

  if (fs_size == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (path != NULL) {
    pr_trace_msg(trace_channel, 18, "using statvfs() on '%s'", path);

  } else {
    pr_trace_msg(trace_channel, 18, "using statvfs() on fd %d", fd);
  }

  if (path != NULL) {
    res = statvfs(path, &fs);

  } else {
    res = fstatvfs(fd, &fs);
  }

  if (res < 0) {
    int xerrno = errno;

    if (path != NULL) {
      pr_trace_msg(trace_channel, 3, "statvfs() error using '%s': %s",
        path, strerror(xerrno));

    } else {
      pr_trace_msg(trace_channel, 3, "statvfs() error using fd %d: %s",
        fd, strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  /* The get_fs_size() function is only useful for 32-bit numbers;
   * if either of our two values are in datatypes larger than 4 bytes,
   * we'll use typecasting.
   */
  if (sizeof(fs.f_bavail) > 4 ||
      sizeof(fs.f_frsize) > 4) {

    /* In order to return a size in KB, as get_fs_size() does, we need
     * to divide by 1024.
     */
    *fs_size = (((off_t) fs.f_bavail * (off_t) fs.f_frsize) / 1024);

  } else {
    *fs_size = get_fs_size(fs.f_bavail, fs.f_frsize);
  }

  res = 0;

# elif defined(HAVE_SYS_VFS_H)
  struct statfs fs;

  if (fs_size == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (path != NULL) {
    pr_trace_msg(trace_channel, 18, "using statfs() on '%s'", path);

  } else {
    pr_trace_msg(trace_channel, 18, "using statfs() on fd %d", fd);
  }

  if (path != NULL) {
    res = statfs(path, &fs);

  } else {
    res = fstatfs(fd, &fs);
  }

  if (res < 0) {
    int xerrno = errno;

    if (path != NULL) {
      pr_trace_msg(trace_channel, 3, "statfs() error using '%s': %s",
        path, strerror(xerrno));

    } else {
      pr_trace_msg(trace_channel, 3, "statfs() error using fd %d: %s",
        fd, strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  /* The get_fs_size() function is only useful for 32-bit numbers;
   * if either of our two values are in datatypes larger than 4 bytes,
   * we'll use typecasting.
   */
  if (sizeof(fs.f_bavail) > 4 ||
      sizeof(fs.f_frsize) > 4) {

    /* In order to return a size in KB, as get_fs_size() does, we need
     * to divide by 1024.
     */
    *fs_size = (((off_t) fs.f_bavail * (off_t) fs.f_frsize) / 1024);

  } else {
    *fs_size = get_fs_size(fs.f_bavail, fs.f_frsize);
  }

  res = 0;

# elif defined(HAVE_STATFS)
  struct statfs fs;

  if (fs_size == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (path != NULL) {
    pr_trace_msg(trace_channel, 18, "using statfs() on '%s'", path);

  } else {
    pr_trace_msg(trace_channel, 18, "using statfs() on fd %d", fd);
  }

  if (path != NULL) {
    res = statfs(path, &fs);

  } else {
    res = fstatfs(fd, &fs);
  }

  if (res < 0) {
    int xerrno = errno;

    if (path != NULL) {
      pr_trace_msg(trace_channel, 3, "statfs() error using '%s': %s",
        path, strerror(xerrno));

    } else {
      pr_trace_msg(trace_channel, 3, "statfs() error using fd %d: %s",
        fd, strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  /* The get_fs_size() function is only useful for 32-bit numbers;
   * if either of our two values are in datatypes larger than 4 bytes,
   * we'll use typecasting.
   */
  if (sizeof(fs.f_bavail) > 4 ||
      sizeof(fs.f_frsize) > 4) {

    /* In order to return a size in KB, as get_fs_size() does, we need
     * to divide by 1024.
     */
    *fs_size = (((off_t) fs.f_bavail * (off_t) fs.f_frsize) / 1024);

  } else {
    *fs_size = get_fs_size(fs.f_bavail, fs.f_frsize);
  }

  res = 0;

# else
  errno = ENOSYS:
  res = -1;
# endif /* !HAVE_STATFS && !HAVE_SYS_STATVFS && !HAVE_SYS_VFS */

  return res;
}

#if defined(HAVE_STATFS) || defined(HAVE_SYS_STATVFS_H) || \
  defined(HAVE_SYS_VFS_H)
off_t pr_fs_getsize(char *path) {
  int res;
  off_t fs_size;

  res = pr_fs_getsize2(path, &fs_size);
  if (res < 0) {
    errno = EINVAL;
    fs_size = -1;
  }

  return fs_size;
}
#endif /* !HAVE_STATFS && !HAVE_SYS_STATVFS && !HAVE_SYS_VFS */

/* Returns the size in KB via the `fs_size' argument. */
int pr_fs_getsize2(char *path, off_t *fs_size) {
  return fs_getsize(-1, path, fs_size);
}

int pr_fs_fgetsize(int fd, off_t *fs_size) {
  return fs_getsize(fd, NULL, fs_size);
}

void pr_fs_fadvise(int fd, off_t offset, off_t len, int advice) {
#if defined(HAVE_POSIX_ADVISE)
  int res, posix_advice;
  const char *advice_str;

  /* Convert from our advice values to the ones from the header; the
   * indirection is needed for platforms which do not provide posix_fadvise(3).
   */
  switch (advice) {
    case PR_FS_FADVISE_NORMAL:
      advice_str = "NORMAL";
      posix_advice = POSIX_FADV_NORMAL;
      break;

    case PR_FS_FADVISE_RANDOM:
      advice_str = "RANDOM";
      posix_advice = POSIX_FADV_RANDOM;
      break;

    case PR_FS_FADVISE_SEQUENTIAL:
      advice_str = "SEQUENTIAL";
      posix_advice = POSIX_FADV_SEQUENTIAL;
      break;

    case PR_FS_FADVISE_WILLNEED:
      advice_str = "WILLNEED";
      posix_advice = POSIX_FADV_WILLNEED;
      break;

    case PR_FS_FADVISE_DONTNEED:
      advice_str = "DONTNEED";
      posix_advice = POSIX_FADV_DONTNEED;
      break;

    case PR_FS_FADVISE_NOREUSE:
      advice_str = "NOREUSE";
      posix_advice = POSIX_FADV_NOREUSE;
      break;

    default:
      pr_trace_msg(trace_channel, 9,
        "unknown/unsupported advice: %d", advice);
      return;
  }

  res = posix_fadvise(fd, offset, len, posix_advice);
  if (res < 0) {
    pr_trace_msg(trace_channel, 9,
      "posix_fadvise() error on fd %d (off %" PR_LU ", len %" PR_LU ", "
      "advice %s): %s", fd, (pr_off_t) offset, (pr_off_t) len, advice_str,
      strerror(errno));
  }
#endif

  return;
}

int pr_fs_have_access(struct stat *st, int mode, uid_t uid, gid_t gid,
    array_header *suppl_gids) {
  mode_t mask;

  if (st == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Root always succeeds. */
  if (uid == PR_ROOT_UID) {
    return 0;
  }

  /* Initialize mask to reflect the permission bits that are applicable for
   * the given user. mask contains the user-bits if the user ID equals the
   * ID of the file owner. mask contains the group bits if the group ID
   * belongs to the group of the file. mask will always contain the other
   * bits of the permission bits.
   */
  mask = S_IROTH|S_IWOTH|S_IXOTH;

  if (st->st_uid == uid) {
    mask |= S_IRUSR|S_IWUSR|S_IXUSR;
  }

  /* Check the current group, as well as all supplementary groups.
   * Fortunately, we have this information cached, so accessing it is
   * almost free.
   */
  if (st->st_gid == gid) {
    mask |= S_IRGRP|S_IWGRP|S_IXGRP;

  } else {
    if (suppl_gids != NULL) {
      register unsigned int i = 0;

      for (i = 0; i < suppl_gids->nelts; i++) {
        if (st->st_gid == ((gid_t *) suppl_gids->elts)[i]) {
          mask |= S_IRGRP|S_IWGRP|S_IXGRP;
          break;
        }
      }
    }
  }

  mask &= st->st_mode;

  /* Perform requested access checks. */
  if (mode & R_OK) {
    if (!(mask & (S_IRUSR|S_IRGRP|S_IROTH))) {
      errno = EACCES;
      return -1;
    }
  }

  if (mode & W_OK) {
    if (!(mask & (S_IWUSR|S_IWGRP|S_IWOTH))) {
      errno = EACCES;
      return -1;
    }
  }

  if (mode & X_OK) {
    if (!(mask & (S_IXUSR|S_IXGRP|S_IXOTH))) {
      errno = EACCES;
      return -1;
    }
  }

  /* F_OK already checked by checking the return value of stat. */
  return 0;
}

int pr_fs_is_nfs(const char *path) {
#if defined(HAVE_STATFS_F_TYPE) || defined(HAVE_STATFS_F_FSTYPENAME)
  struct statfs fs;
  int res = FALSE;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 18, "using statfs() on '%s'", path);
  if (statfs(path, &fs) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "statfs() error using '%s': %s",
      path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

# if defined(HAVE_STATFS_F_FSTYPENAME)
  pr_trace_msg(trace_channel, 12,
    "path '%s' resides on a filesystem of type '%s'", path, fs.f_fstypename);
  if (strcasecmp(fs.f_fstypename, "nfs") == 0) {
    res = TRUE;
  }
# elif defined(HAVE_STATFS_F_TYPE)
  /* Probably a Linux system. */
  if (fs.f_type == NFS_SUPER_MAGIC) {
    pr_trace_msg(trace_channel, 12,
      "path '%s' resides on an NFS_SUPER_MAGIC filesystem (type 0x%08x)", path,
      (int) fs.f_type);
    res = TRUE;

  } else {
    pr_trace_msg(trace_channel, 12,
      "path '%s' resides on a filesystem of type 0x%08x (not NFS_SUPER_MAGIC)",
      path, (int) fs.f_type);
  }
# endif

  return res;

#else
  errno = ENOSYS;
  return -1;
#endif /* No HAVE_STATFS_F_FSTYPENAME or HAVE_STATFS_F_TYPE */
}

int pr_fsio_puts(const char *buf, pr_fh_t *fh) {
  if (fh == NULL ||
      buf == NULL) {
    errno = EINVAL;
    return -1;
  }

  return pr_fsio_write(fh, buf, strlen(buf));
}

int pr_fsio_set_block(pr_fh_t *fh) {
  int flags, res;

  if (fh == NULL) {
    errno = EINVAL;
    return -1;
  }

  flags = fcntl(fh->fh_fd, F_GETFL);
  if (flags < 0) {
    return -1;
  }

  res = fcntl(fh->fh_fd, F_SETFL, flags & (U32BITS ^ O_NONBLOCK));
  return res;
}

void pr_resolve_fs_map(void) {
  register unsigned int i = 0;

  if (fs_map == NULL) {
    return;
  }

  for (i = 0; i < fs_map->nelts; i++) {
    char *newpath = NULL;
    int add_slash = FALSE;
    pr_fs_t *fsi;

    pr_signals_handle();
    fsi = ((pr_fs_t **) fs_map->elts)[i];

    /* Skip if this fs is the root fs. */
    if (fsi == root_fs) {
      continue;
    }

    /* Note that dir_realpath() does _not_ handle "../blah" paths
     * well, so...at least for now, hope that such paths are screened
     * by the code adding such paths into the fs_map.  Check for
     * a trailing slash in the unadjusted path, so that I know if I need
     * to re-add that slash to the adjusted path -- these trailing slashes
     * are important!
     */
    if ((strncmp(fsi->fs_path, "/", 2) != 0 &&
        (fsi->fs_path)[strlen(fsi->fs_path) - 1] == '/')) {
      add_slash = TRUE;
    }

    newpath = dir_realpath(fsi->fs_pool, fsi->fs_path);
    if (newpath != NULL) {

      if (add_slash) {
        newpath = pstrcat(fsi->fs_pool, newpath, "/", NULL);
      }

      /* Note that this does cause a slightly larger memory allocation from
       * the pr_fs_t's pool, as the original path value was also allocated
       * from that pool, and that original pointer is being overwritten.
       * However, as this function is only called once, and that pool
       * is freed later, I think this may be acceptable.
       */
      fsi->fs_path = newpath;
    }
  }

  /* Resort the map */
  qsort(fs_map->elts, fs_map->nelts, sizeof(pr_fs_t *), fs_cmp);

  return;
}

int init_fs(void) {
  char cwdbuf[PR_TUNABLE_PATH_MAX + 1] = {'\0'};

  /* Establish the default pr_fs_t that will handle any path */
  root_fs = pr_create_fs(permanent_pool, "system");
  if (root_fs == NULL) {

    /* Do not insert this fs into the FS map.  This will allow other
     * modules to insert filesystems at "/", if they want.
     */
    pr_log_pri(PR_LOG_WARNING, "error: unable to initialize default FS");
    exit(1);
  }

  root_fs->fs_path = pstrdup(root_fs->fs_pool, "/");

  /* Set the root FSIO handlers. */
  root_fs->stat = sys_stat;
  root_fs->fstat = sys_fstat;
  root_fs->lstat = sys_lstat;
  root_fs->rename = sys_rename;
  root_fs->unlink = sys_unlink;
  root_fs->open = sys_open;
  root_fs->close = sys_close;
  root_fs->read = sys_read;
  root_fs->write = sys_write;
  root_fs->lseek = sys_lseek;
  root_fs->link = sys_link;
  root_fs->readlink = sys_readlink;
  root_fs->symlink = sys_symlink;
  root_fs->ftruncate = sys_ftruncate;
  root_fs->truncate = sys_truncate;
  root_fs->chmod = sys_chmod;
  root_fs->fchmod = sys_fchmod;
  root_fs->chown = sys_chown;
  root_fs->fchown = sys_fchown;
  root_fs->lchown = sys_lchown;
  root_fs->access = sys_access;
  root_fs->faccess = sys_faccess;
  root_fs->utimes = sys_utimes;
  root_fs->futimes = sys_futimes;
  root_fs->fsync = sys_fsync;

  root_fs->getxattr = sys_getxattr;
  root_fs->lgetxattr = sys_lgetxattr;
  root_fs->fgetxattr = sys_fgetxattr;
  root_fs->listxattr = sys_listxattr;
  root_fs->llistxattr = sys_llistxattr;
  root_fs->flistxattr = sys_flistxattr;
  root_fs->removexattr = sys_removexattr;
  root_fs->lremovexattr = sys_lremovexattr;
  root_fs->fremovexattr = sys_fremovexattr;
  root_fs->setxattr = sys_setxattr;
  root_fs->lsetxattr = sys_lsetxattr;
  root_fs->fsetxattr = sys_fsetxattr;

  root_fs->chdir = sys_chdir;
  root_fs->chroot = sys_chroot;
  root_fs->opendir = sys_opendir;
  root_fs->closedir = sys_closedir;
  root_fs->readdir = sys_readdir;
  root_fs->mkdir = sys_mkdir;
  root_fs->rmdir = sys_rmdir;

  if (getcwd(cwdbuf, sizeof(cwdbuf)-1)) {
    cwdbuf[sizeof(cwdbuf)-1] = '\0';
    pr_fs_setcwd(cwdbuf);

  } else {
    pr_fsio_chdir("/", FALSE);
    pr_fs_setcwd("/");
  }

  /* Prepare the stat cache as well. */
  statcache_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(statcache_pool, "FS Statcache Pool");
  stat_statcache_tab = pr_table_alloc(statcache_pool, 0);
  lstat_statcache_tab = pr_table_alloc(statcache_pool, 0);

  return 0;
}

#ifdef PR_USE_DEVEL

static const char *get_fs_hooks_str(pool *p, pr_fs_t *fs) {
  char *hooks = "";

  if (fs->stat) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "stat(2)", NULL);
  }

  if (fs->lstat) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "lstat(2)", NULL);
  }

  if (fs->fstat) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "fstat(2)", NULL);
  }

  if (fs->rename) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "rename(2)", NULL);
  }

  if (fs->link) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "link(2)", NULL);
  }

  if (fs->unlink) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "unlink(2)", NULL);
  }

  if (fs->open) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "open(2)", NULL);
  }

  if (fs->close) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "close(2)", NULL);
  }

  if (fs->read) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "read(2)", NULL);
  }

  if (fs->lseek) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "lseek(2)", NULL);
  }

  if (fs->readlink) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "readlink(2)", NULL);
  }

  if (fs->symlink) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "symlink(2)", NULL);
  }

  if (fs->ftruncate) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "ftruncate(2)", NULL);
  }

  if (fs->truncate) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "truncate(2)", NULL);
  }

  if (fs->chmod) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "chmod(2)", NULL);
  }

  if (fs->chown) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "chown(2)", NULL);
  }

  if (fs->fchown) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "fchown(2)", NULL);
  }

  if (fs->lchown) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "lchown(2)", NULL);
  }

  if (fs->access) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "access(2)", NULL);
  }

  if (fs->faccess) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "faccess(2)", NULL);
  }

  if (fs->utimes) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "utimes(2)", NULL);
  }

  if (fs->futimes) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "futimes(2)", NULL);
  }

  if (fs->fsync) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "fsync(2)", NULL);
  }

  if (fs->chdir) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "chdir(2)", NULL);
  }

  if (fs->chroot) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "chroot(2)", NULL);
  }

  if (fs->opendir) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "opendir(3)", NULL);
  }

  if (fs->closedir) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "closedir(3)", NULL);
  }

  if (fs->readdir) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "readdir(3)", NULL);
  }

  if (fs->mkdir) {
    hooks = pstrcat(p, hooks, *hooks ? ", " : "", "mkdir(2)", NULL);
  }

  if (!*hooks) {
    return pstrdup(p, "(none)");
  }

  return hooks;
}

static void get_fs_info(pool *p, int depth, pr_fs_t *fs,
    void (*dumpf)(const char *, ...)) {

  dumpf("FS#%u: '%s', mounted at '%s', implementing the following hooks:",
    depth, fs->fs_name, fs->fs_path);
  dumpf("FS#%u:    %s", depth, get_fs_hooks_str(p, fs));
}

static void fs_printf(const char *fmt, ...) {
  char buf[PR_TUNABLE_BUFFER_SIZE+1];
  va_list msg;

  memset(buf, '\0', sizeof(buf));
  va_start(msg, fmt);
  pr_vsnprintf(buf, sizeof(buf)-1, fmt, msg);
  va_end(msg);

  buf[sizeof(buf)-1] = '\0';
  pr_trace_msg(trace_channel, 19, "%s", buf);
}

void pr_fs_dump(void (*dumpf)(const char *, ...)) {
  pool *p;

  if (dumpf == NULL) {
    dumpf = fs_printf;
  }

  dumpf("FS#0: 'system' mounted at '/', implementing the following hooks:");
  dumpf("FS#0:    (all)");

  if (!fs_map ||
      fs_map->nelts == 0) {
    return;
  }

  p = make_sub_pool(permanent_pool);

  if (fs_map->nelts > 0) {
    pr_fs_t **fs_objs = (pr_fs_t **) fs_map->elts;
    register unsigned int i;

    for (i = 0; i < fs_map->nelts; i++) {
      pr_fs_t *fsi = fs_objs[i];

      for (; fsi->fs_next; fsi = fsi->fs_next) {
        get_fs_info(p, i+1, fsi, dumpf);
      }
    }
  }

  destroy_pool(p);
}
#endif /* PR_USE_DEVEL */
