/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2017 The ProFTPD Project
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

/* ProFTPD virtual/modular filesystem support. */

#ifndef PR_FSIO_H
#define PR_FSIO_H

#include "conf.h"
#include "error.h"

#ifdef PR_USE_XATTR
# if defined(HAVE_SYS_EXTATTR_H)
#  include <sys/extattr.h>
# elif defined(HAVE_SYS_XATTR_H)
#  include <sys/xattr.h>
#  if defined(HAVE_ATTR_XATTR_H)
#   include <attr/xattr.h>
#  endif /* HAVE_ATTR_XATTR_H */
# endif /* HAVE_SYS_XATTR_H */
#endif /* PR_USE_XATTR */

/* This is a Tru64-specific hack, to work around some macro funkiness
 * in their /usr/include/sys/mount.h header.
 */
#ifdef OSF5
# undef fh_data
#endif

/* Operation codes */
#define FSIO_FILE_STAT		(1 << 0)
#define FSIO_FILE_LSTAT		(1 << 1)
#define FSIO_FILE_RENAME	(1 << 2)
#define FSIO_FILE_UNLINK	(1 << 3)
#define FSIO_FILE_OPEN		(1 << 4)
/* Was FSIO_FILE_CREAT, now unused */
#define FSIO_FILE_CLOSE		(1 << 6)
#define FSIO_FILE_READ		(1 << 7)
#define FSIO_FILE_WRITE		(1 << 8)
#define FSIO_FILE_LINK		(1 << 9)
#define FSIO_FILE_SYMLINK	(1 << 10)
#define FSIO_FILE_READLINK	(1 << 11)
#define FSIO_FILE_TRUNC		(1 << 12)
#define FSIO_FILE_CHMOD		(1 << 13)
#define FSIO_FILE_CHOWN		(1 << 14)
#define FSIO_FILE_ACCESS	(1 << 15)
#define FSIO_FILE_UTIMES	(1 << 23)
#define FSIO_FILE_GETXATTR	(1 << 24)
#define FSIO_FILE_LGETXATTR	(1 << 25)
#define FSIO_FILE_LISTXATTR	(1 << 26)
#define FSIO_FILE_LLISTXATTR	(1 << 27)
#define FSIO_FILE_REMOVEXATTR	(1 << 28)
#define FSIO_FILE_LREMOVEXATTR	(1 << 29)
#define FSIO_FILE_SETXATTR	(1 << 30)
#define FSIO_FILE_LSETXATTR	(1 << 31)

/* Macro that defines the most common file ops */
#define FSIO_FILE_COMMON	(FSIO_FILE_OPEN|FSIO_FILE_READ|FSIO_FILE_WRITE|\
                                 FSIO_FILE_CLOSE)

#define FSIO_DIR_CHROOT		(1 << 16)
#define FSIO_DIR_CHDIR		(1 << 17)
#define FSIO_DIR_OPENDIR	(1 << 18)
#define FSIO_DIR_CLOSEDIR	(1 << 19)
#define FSIO_DIR_READDIR	(1 << 20)
#define FSIO_DIR_MKDIR		(1 << 21)
#define FSIO_DIR_RMDIR		(1 << 22)

/* Macro that defines directory operations */
#define FSIO_DIR_COMMON		(FSIO_DIR_CHROOT|FSIO_DIR_CHDIR|\
                                 FSIO_DIR_OPENDIR|FSIO_DIR_READDIR|\
                                 FSIO_DIR_CLOSEDIR|FSIO_DIR_MKDIR|\
                                 FSIO_DIR_RMDIR)

/* Default mode used when creating files */
#define PR_OPEN_MODE		0666

/* Modular filesystem object */

typedef struct fs_rec pr_fs_t;
typedef struct fh_rec pr_fh_t;

struct fs_rec {

  /* These pointers will be effective once layered FS modules are
   * supported
   */
  pr_fs_t *fs_next, *fs_prev;

  /* Descriptive tag for this fs object */
  char *fs_name;

  char *fs_path;

  /* Slot for module-specific data */
  void *fs_data;

  /* Pool for this object's use */
  struct pool_rec *fs_pool;

  /* FS function pointers */
  int (*stat)(pr_fs_t *, const char *, struct stat *);
  int (*fstat)(pr_fh_t *, int, struct stat *);
  int (*lstat)(pr_fs_t *, const char *, struct stat *);
  int (*rename)(pr_fs_t *, const char *, const char *);
  int (*unlink)(pr_fs_t *, const char *);
  int (*open)(pr_fh_t *, const char *, int);
  int (*close)(pr_fh_t *, int);
  int (*read)(pr_fh_t *, int, char *, size_t);
  int (*write)(pr_fh_t *, int, const char *, size_t);
  off_t (*lseek)(pr_fh_t *, int, off_t, int);
  int (*link)(pr_fs_t *, const char *, const char *);
  int (*readlink)(pr_fs_t *, const char *, char *, size_t);
  int (*symlink)(pr_fs_t *, const char *, const char *);
  int (*ftruncate)(pr_fh_t *, int, off_t);
  int (*truncate)(pr_fs_t *, const char *, off_t);
  int (*chmod)(pr_fs_t *, const char *, mode_t);
  int (*fchmod)(pr_fh_t *, int, mode_t);
  int (*chown)(pr_fs_t *, const char *, uid_t, gid_t);
  int (*fchown)(pr_fh_t *, int, uid_t, gid_t);
  int (*lchown)(pr_fs_t *, const char *, uid_t, gid_t);
  int (*access)(pr_fs_t *, const char *, int, uid_t, gid_t, array_header *);
  int (*faccess)(pr_fh_t *, int, uid_t, gid_t, array_header *);
  int (*utimes)(pr_fs_t *, const char *, struct timeval *);
  int (*futimes)(pr_fh_t *, int, struct timeval *);
  int (*fsync)(pr_fh_t *, int);

  /* Extended attribute support */
  ssize_t (*getxattr)(pool *, pr_fs_t *, const char *, const char *, void *,
    size_t);
  ssize_t (*lgetxattr)(pool *, pr_fs_t *, const char *, const char *, void *,
    size_t);
  ssize_t (*fgetxattr)(pool *, pr_fh_t *, int, const char *, void *, size_t);
  int (*listxattr)(pool *, pr_fs_t *, const char *, array_header **);
  int (*llistxattr)(pool *, pr_fs_t *, const char *, array_header **);
  int (*flistxattr)(pool *, pr_fh_t *, int, array_header **);
  int (*removexattr)(pool *, pr_fs_t *, const char *, const char *);
  int (*lremovexattr)(pool *, pr_fs_t *, const char *, const char *);
  int (*fremovexattr)(pool *, pr_fh_t *, int, const char *);
  int (*setxattr)(pool *, pr_fs_t *, const char *, const char *, void *,
    size_t, int);
  int (*lsetxattr)(pool *, pr_fs_t *, const char *, const char *, void *,
    size_t, int);
  int (*fsetxattr)(pool *, pr_fh_t *, int, const char *, void *, size_t, int);

  /* For actual operations on the directory (or subdirs)
   * we cast the return from opendir to DIR* in src/fs.c, so
   * modules can use their own data type
   */

  int (*chdir)(pr_fs_t *, const char *);
  int (*chroot)(pr_fs_t *, const char *);
  void *(*opendir)(pr_fs_t *, const char *);
  int (*closedir)(pr_fs_t *, void *);
  struct dirent *(*readdir)(pr_fs_t *, void *);
  int (*mkdir)(pr_fs_t *, const char *, mode_t);
  int (*rmdir)(pr_fs_t *, const char *);

  /* This flag determines whether this FS handler allows cross-FS hardlinks,
   * either from this FS to another FS, or from another FS to this FS.
   *
   * If the flag is set to FALSE by the FS registrant, then a hardlink
   * across FS handlers will fail, with errno set to EXDEV.  The caller
   * will then have to handle the EXDEV error appropriately.
   */
  int allow_xdev_link;

  /* This flag determines whether this FS handler allows cross-FS renames,
   * either from this FS to another FS, or from another FS to this FS.
   *
   * If the flag is set to FALSE by the FS registrant, then a rename
   * across FS handlers will fail, with errno set to EXDEV.  The caller
   * will then have to handle the EXDEV error appropriately.
   *
   * In the core engine, a RNFR/RNTO sequence which encounters an EXDEV
   * error will cause a copy/delete of the file.  This can be more IO
   * intensive than expected, and lead to longer times for the RNTO
   * command to complete.
   */
  int allow_xdev_rename;

  /* This flag determines whether the paths handled by this FS handler
   * are standard, filesystem-based paths, and such use the standard
   * path separator, glob semantics, etc.
   */
  int non_std_path;
};

struct fh_rec {

  /* Pool for this object's use */
  pool *fh_pool;

  int fh_fd;
  char *fh_path;

  /* Arbitrary data associated with this file. */
  void *fh_data;

  /* Pointer to the filesystem in which this file is located. */
  pr_fs_t *fh_fs;

  /* For buffer I/O on this file, should anything choose to use it. */
  pr_buffer_t *fh_buf;

  /* Hint of the optimal buffer size for IO on this file. */
  size_t fh_iosz;
};

/* Maximum symlink count, for loop detection. */
#define PR_FSIO_MAX_LINK_COUNT		32

/* Macros for that code that needs to get into the internals of pr_fs_t.
 * (These will help keep the internals as opaque as possible).
 */
#define PR_FH_FD(f)	((f)->fh_fd)

int pr_fsio_stat(const char *, struct stat *);
int pr_fsio_fstat(pr_fh_t *, struct stat *);
int pr_fsio_lstat(const char *, struct stat *);
int pr_fsio_readlink(const char *, char *, size_t);
int pr_fsio_chdir(const char *, int);
int pr_fsio_chdir_canon(const char *, int);
void *pr_fsio_opendir(const char *);
int pr_fsio_closedir(void *);
struct dirent *pr_fsio_readdir(void *);
int pr_fsio_mkdir(const char *, mode_t);
int pr_fsio_rmdir(const char *);
int pr_fsio_rename(const char *, const char *);
int pr_fsio_smkdir(pool *, const char *, mode_t, uid_t, gid_t);
int pr_fsio_unlink(const char *);
pr_fh_t *pr_fsio_open(const char *, int);
pr_fh_t *pr_fsio_open_canon(const char *, int);
int pr_fsio_close(pr_fh_t *);
int pr_fsio_read(pr_fh_t *, char *, size_t);
int pr_fsio_write(pr_fh_t *, const char *, size_t);
int pr_fsio_link(const char *, const char *);
int pr_fsio_symlink(const char *, const char *);
int pr_fsio_ftruncate(pr_fh_t *, off_t);
int pr_fsio_truncate(const char *, off_t);
int pr_fsio_chmod(const char *, mode_t);
int pr_fsio_fchmod(pr_fh_t *, mode_t);
int pr_fsio_chown(const char *, uid_t, gid_t);
int pr_fsio_fchown(pr_fh_t *, uid_t, gid_t);
int pr_fsio_lchown(const char *, uid_t, gid_t);
int pr_fsio_chroot(const char *);
int pr_fsio_access(const char *, int, uid_t, gid_t, array_header *);
int pr_fsio_faccess(pr_fh_t *, int, uid_t, gid_t, array_header *);
int pr_fsio_utimes(const char *, struct timeval *);
int pr_fsio_utimes_with_root(const char *, struct timeval *);
int pr_fsio_futimes(pr_fh_t *, struct timeval *);
int pr_fsio_fsync(pr_fh_t *fh);
off_t pr_fsio_lseek(pr_fh_t *, off_t, int);

/* Extended attribute support */
ssize_t pr_fsio_getxattr(pool *p, const char *, const char *, void *, size_t);
ssize_t pr_fsio_lgetxattr(pool *, const char *, const char *, void *, size_t);
ssize_t pr_fsio_fgetxattr(pool *, pr_fh_t *, const char *, void *, size_t);
int pr_fsio_listxattr(pool *, const char *, array_header **);
int pr_fsio_llistxattr(pool *, const char *, array_header **);
int pr_fsio_flistxattr(pool *, pr_fh_t *, array_header **);
int pr_fsio_removexattr(pool *, const char *, const char *);
int pr_fsio_lremovexattr(pool *, const char *, const char *);
int pr_fsio_fremovexattr(pool *, pr_fh_t *, const char *);
int pr_fsio_setxattr(pool *, const char *, const char *, void *, size_t, int);
int pr_fsio_lsetxattr(pool *, const char *, const char *, void *, size_t, int);
int pr_fsio_fsetxattr(pool *, pr_fh_t *, const char *, void *, size_t, int);

/* setxattr flags */
#define PR_FSIO_XATTR_FL_CREATE		0x001
#define PR_FSIO_XATTR_FL_REPLACE	0x002

/* Error-using variants of the FSIO API. */
int pr_fsio_chmod_with_error(pool *p, const char *path, mode_t mode,
  pr_error_t **err);
int pr_fsio_chown_with_error(pool *p, const char *path, uid_t uid, gid_t gid,
  pr_error_t **err);
int pr_fsio_chroot_with_error(pool *p, const char *path, pr_error_t **err);
int pr_fsio_close_with_error(pool *p, pr_fh_t *fh, pr_error_t **err);
int pr_fsio_fchmod_with_error(pool *p, pr_fh_t *fh, mode_t mode,
  pr_error_t **err);
int pr_fsio_fchown_with_error(pool *p, pr_fh_t *fh, uid_t uid, gid_t gid,
  pr_error_t **err);
int pr_fsio_lchown_with_error(pool *p, const char *path, uid_t uid, gid_t gid,
  pr_error_t **err);
int pr_fsio_lstat_with_error(pool *p, const char *path, struct stat *st,
  pr_error_t **err);
int pr_fsio_mkdir_with_error(pool *p, const char *path, mode_t mode,
  pr_error_t **err);
pr_fh_t *pr_fsio_open_with_error(pool *p, const char *path, int flags,
  pr_error_t **err);
int pr_fsio_read_with_error(pool *p, pr_fh_t *fh, char *buf, size_t sz,
  pr_error_t **err);
int pr_fsio_rename_with_error(pool *p, const char *from, const char *to,
  pr_error_t **err);
int pr_fsio_rmdir_with_error(pool *p, const char *path, pr_error_t **err);
int pr_fsio_stat_with_error(pool *p, const char *path, struct stat *st,
  pr_error_t **err);
int pr_fsio_unlink_with_error(pool *p, const char *path, pr_error_t **err);
int pr_fsio_write_with_error(pool *p, pr_fh_t *fh, const char *buf, size_t sz,
  pr_error_t **err);

/* Set a flag determining whether we guard against write operations in
 * certain sensitive directories while we are chrooted, e.g. "Roaring Beast"
 * style attacks.
 */
int pr_fsio_guard_chroot(int);

/* Set a flag determining whether to use mkdtemp(3) (if available) or not.
 * Returns the previously-set value.
 */
int pr_fsio_set_use_mkdtemp(int);

/* Sets a bitmask of various FSIO API options.  Returns the previously
 * set options.
 */
unsigned long pr_fsio_set_options(unsigned long opts);
#define PR_FSIO_OPT_IGNORE_XATTR		0x00001

/* FS-related functions */

char *pr_fsio_getline(char *, size_t, pr_fh_t *, unsigned int *);
char *pr_fsio_getpipebuf(pool *, int, long *);
char *pr_fsio_gets(char *, size_t, pr_fh_t *);
int pr_fsio_puts(const char *, pr_fh_t *);
int pr_fsio_set_block(pr_fh_t *);

pr_fs_t *pr_register_fs(pool *, const char *, const char *);
pr_fs_t *pr_create_fs(pool *, const char *);
pr_fs_t *pr_get_fs(const char *, int *);
int pr_insert_fs(pr_fs_t *, const char *);
pr_fs_t *pr_remove_fs(const char *);
pr_fs_t *pr_unmount_fs(const char *, const char *);
int pr_unregister_fs(const char *);

/* FS Statcache API */
void pr_fs_clear_cache(void);
int pr_fs_clear_cache2(const char *path);

/* Dump the current contents of the statcache via trace logging, to the
 * "fs.statcache" trace channel.
 */
void pr_fs_statcache_dump(void);

/* Clears the entire statcache. */
void pr_fs_statcache_free(void);

/* Clears the entire statcache and re-creates the memory pool. */
void pr_fs_statcache_reset(void);

/* Tune the statcache policy: max number of items in the cache at any
 * one time, the max age (in seconds) for items in the cache, and the policy
 * flags.
 *
 * Note that setting a size of zero, OR setting a max age of zero, effectively
 * disables the statcache.
 */
int pr_fs_statcache_set_policy(unsigned int size, unsigned int max_age,
  unsigned int flags);

/* Copy a file from the given source path to the destination path. */
int pr_fs_copy_file(const char *src, const char *dst);

/* Similar to pr_fs_copy_file(), with the addition of an optional progress
 * callback, invoked during the potentially long-running copy process.
 *
 * The callback, when present, will be invoked with the number of bytes
 * just written to the destination file in that iteration.
 */
int pr_fs_copy_file2(const char *src, const char *dst, int flags,
  void (*progress_cb)(int));
#define PR_FSIO_COPY_FILE_FL_NO_DELETE_ON_FAILURE	0x0001

int pr_fs_setcwd(const char *);
const char *pr_fs_getcwd(void);
const char *pr_fs_getvwd(void);
int pr_fs_dircat(char *, int, const char *, const char *);
int pr_fs_interpolate(const char *, char *, size_t);
int pr_fs_resolve_partial(const char *, char *, size_t, int);
int pr_fs_resolve_path(const char *, char *, size_t, int);
char *pr_fs_decode_path(pool *, const char *);

/* Similar to pr_fs_decode_path(), but allows callers to provide flags.  These
 * flags can be used, for example, to request that if there are errors during
 * the decoding, the function NOT hide/mask them, as is done by default, but
 * convey them to the caller for handling at a higher code layer.
 */ 
char *pr_fs_decode_path2(pool *, const char *, int);
#define FSIO_DECODE_FL_TELL_ERRORS		0x001

char *pr_fs_encode_path(pool *, const char *);
int pr_fs_use_encoding(int);

/* Split the given path into its individual path components. */
array_header *pr_fs_split_path(pool *p, const char *path);

/* Given an array of individual path components, join them into a single
 * path.  The count parameter indicates how many components in the array,
 * starting from zero, to use.
 */
char *pr_fs_join_path(pool *p, array_header *components, size_t count);

int pr_fs_valid_path(const char *);
void pr_fs_virtual_path(const char *, char *, size_t);

void pr_fs_clean_path(const char *, char *, size_t);
int pr_fs_clean_path2(const char *, char *, size_t, int);
#define PR_FSIO_CLEAN_PATH_FL_MAKE_ABS_PATH	0x001

int pr_fs_glob(const char *, int, int (*errfunc)(const char *, int), glob_t *);
void pr_fs_globfree(glob_t *);
void pr_resolve_fs_map(void);

/* Close all but the main three fds. */
void pr_fs_close_extra_fds(void);

/* The main three fds (stdin, stdout, stderr) need to be protected, reserved
 * for use.  This function uses dup(2) to open new fds on the given fd
 * until the new fd is not one of the big three.
 */
int pr_fs_get_usable_fd(int);

/* Similar to pr_fs_get_usable_fd(), except that it automatically closes the
 * old (given) fd if a usable fd was found.  Returns -1 (with errno set) if
 * a usable fd could not be found.
 */
int pr_fs_get_usable_fd2(int *);

#if defined(HAVE_STATFS) || defined(HAVE_SYS_STATVFS_H) || \
  defined(HAVE_SYS_VFS_H)
off_t pr_fs_getsize(char *);
#endif

/* Unlike pr_fs_getsize(), this function is always present, and is also
 * capable of returning an error when there is a problem checking the
 * filesystem stats.
 */
int pr_fs_getsize2(char *, off_t *);

/* Similar to pr_fs_getsize2(), except that this operates on an already-opened
 * file descriptor, rather than a path.
 */
int pr_fs_fgetsize(int, off_t *);

/* Perform access(2)-like checks on the given struct stat. */
int pr_fs_have_access(struct stat *st, int mode, uid_t uid, gid_t gid,
  array_header *suppl_gids);

/* Returns TRUE if the given path is on an NFS-mounted filesystem, FALSE
 * if not on an NFS-mounted filesystem, and -1 if there was an error
 * determining which (with errno set appropriately).
 */
int pr_fs_is_nfs(const char *path);

/* Provide advice/hints to the OS about what we are going to do with the
 * given section of the opened file.
 */
void pr_fs_fadvise(int fd, off_t offset, off_t len, int advice);
#define PR_FS_FADVISE_NORMAL		10
#define PR_FS_FADVISE_RANDOM		11
#define PR_FS_FADVISE_SEQUENTIAL	12
#define PR_FS_FADVISE_WILLNEED		13
#define PR_FS_FADVISE_DONTNEED		14
#define PR_FS_FADVISE_NOREUSE		15

/* For internal use only. */
int init_fs(void);

#ifdef PR_USE_DEVEL
void pr_fs_dump(void (*)(const char *, ...));
#endif /* PR_USE_DEVEL */

#endif /* PR_FSIO_H */
