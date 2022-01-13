/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2016-2017 The ProFTPD Project team
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

/* Error API */

#ifndef PR_ERROR_H
#define PR_ERROR_H

#include "os.h"
#include "pool.h"
#include "table.h"
#include "dirtree.h"
#include "modules.h"

typedef struct err_rec pr_error_t;

struct err_explain_rec {
  /* Explain accept(2) errors. */
  const char *(*explain_accept)(pool *p, int xerrno, int fd,
    struct sockaddr *addr, socklen_t *addr_len, const char **args);

  /* Explain bind(2) errors. */
  const char *(*explain_bind)(pool *p, int xerrno, int fd,
    const struct sockaddr *addr, socklen_t addr_len, const char **args);

  /* Explain chdir(2) errors. */
  const char *(*explain_chdir)(pool *p, int xerrno, const char *path,
    const char **args);

  /* Explain chmod(2) errors. */
  const char *(*explain_chmod)(pool *p, int xerrno, const char *path,
    mode_t mode, const char **args);

  /* Explain chown(2) errors. */
  const char *(*explain_chown)(pool *p, int xerrno, const char *path,
    uid_t uid, gid_t gid, const char **args);

  /* Explain chroot(2) errors. */
  const char *(*explain_chroot)(pool *p, int xerrno, const char *path,
    const char **args);

  /* Explain close(2) errors. */
  const char *(*explain_close)(pool *p, int xerrno, int fd, const char **args);

  /* Explain closedir(3) errors. */
  const char *(*explain_closedir)(pool *p, int xerrno, void *dirh,
    const char **args);

  /* Explain connect(2) errors. */
  const char *(*explain_connect)(pool *p, int xerrno, int fd,
    const struct sockaddr *addr, socklen_t addr_len, const char **args);

  /* Explain fchmod(2) errors. */
  const char *(*explain_fchmod)(pool *p, int xerrno, int fd, mode_t mode,
    const char **args);

  /* Explain fchown(2) errors. */
  const char *(*explain_fchown)(pool *p, int xerrno, int fd, uid_t uid,
    gid_t gid, const char **args);

  /* Explain fclose(3) errors. */
  const char *(*explain_fclose)(pool *p, int xerrno, FILE *fh,
    const char **args);

  /* Explain fcntl(2) errors. */
  const char *(*explain_fcntl)(pool *p, int xerrno, int fd, int oper,
    long arg, const char **args);

  /* Explain fdopen(3) errors. */
  const char *(*explain_fdopen)(pool *p, int xerrno, int fd, const char *mode,
    const char **args);

  /* Explain flock(2) errors. */
  const char *(*explain_flock)(pool *p, int xerrno, int fd, int oper,
    const char **args);

  /* Explain fopen(3) errors. */
  const char *(*explain_fopen)(pool *p, int xerrno, const char *path,
    const char *mode, const char **args);

  /* Explain fork(2) errors. */
  const char *(*explain_fork)(pool *p, int xerrno, const char **args);

  /* Explain fstat(2) errors. */
  const char *(*explain_fstat)(pool *p, int xerrno, int fd, struct stat *st,
    const char **args);

  /* Explain fstatfs(2) errors. */
  const char *(*explain_fstatfs)(pool *p, int xerrno, int fd, void *stfs,
    const char **args);

  /* Explain fstatvfs(2) errors. */
  const char *(*explain_fstatvfs)(pool *p, int xerrno, int fd, void *stfs,
    const char **args);

  /* Explain fsync(2) errors. */
  const char *(*explain_fsync)(pool *p, int xerrno, int fd, const char **args);

  /* Explain ftruncate(2) errors. */
  const char *(*explain_ftruncate)(pool *p, int xerrno, int fd, off_t len,
    const char **args);

  /* Explain futimes(2) errors. */
  const char *(*explain_futimes)(pool *p, int xerrno, int fd,
    const struct timeval *tvs, const char **args);

  /* Explain getaddrinfo(2) errors. */
  const char *(*explain_getaddrinfo)(pool *p, int xerrno, const char *name,
    const char *service, const struct addrinfo *hints, struct addrinfo **res,
    const char **args);

  /* Explain gethostbyname(2) errors. */
  const char *(*explain_gethostbyname)(pool *p, int xerrno, const char *name,
    const char **args);

  /* Explain gethostbyname2(2) errors. */
  const char *(*explain_gethostbyname2)(pool *p, int xerrno, const char *name,
    int family, const char **args);

  /* Explain gethostname(2) errors. */
  const char *(*explain_gethostname)(pool *p, int xernro, char *buf,
    size_t sz, const char **args);

  /* Explain getnameinfo(2) errors. */
  const char *(*explain_getnameinfo)(pool *p, int xerrno,
    const struct sockaddr *addr, socklen_t addr_len, char *host,
    size_t host_len, char *service, size_t service_len, int flags,
    const char **args);

  /* Explain getpeername(2) errors. */
  const char *(*explain_getpeername)(pool *p, int xerrno, int fd,
    struct sockaddr *addr, socklen_t *addr_len, const char **args);

  /* Explain getrlimit(2) errors. */
  const char *(*explain_getrlimit)(pool *p, int xerrno, int resource,
    struct rlimit *rlim, const char **args);

  /* Explain getsockname(2) errors. */
  const char *(*explain_getsockname)(pool *p, int xerrno, int fd,
    struct sockaddr *addr, socklen_t *addr_len, const char **args);

  /* Explain getsockopt(2) errors. */
  const char *(*explain_getsockopt)(pool *p, int xerrno, int fd, int level,
    int option, void *val, socklen_t *valsz, const char **args);

  /* Explain lchown(2) errors. */
  const char *(*explain_lchown)(pool *p, int xerrno, const char *path,
    uid_t uid, gid_t gid, const char **args);

  /* Explain link(2) errors. */
  const char *(*explain_link)(pool *p, int xerrno, const char *target_path,
    const char *link_path, const char **args);

  /* Explain listen(2) errors. */
  const char *(*explain_listen)(pool *p, int xerrno, int fd, int backlog,
    const char **args);

  /* Explain lseek(2) errors. */
  const char *(*explain_lseek)(pool *p, int xerrno, int fd, off_t offset,
    int whence, const char **args);

  /* Explain lstat(2) errors. */
  const char *(*explain_lstat)(pool *p, int xerrno, const char *path,
    struct stat *st, const char **args);

  /* Explain mkdir(2) errors. */
  const char *(*explain_mkdir)(pool *p, int xerrno, const char *path,
    mode_t mode, const char **args);

  /* Explain mkdtemp(3) errors. */
  const char *(*explain_mkdtemp)(pool *p, int xerrno, char *tmpl,
    const char **args);

  /* Explain mkstemp(3) errors. */
  const char *(*explain_mkstemp)(pool *p, int xerrno, char *tmpl,
    const char **args);

  /* Explain open(2) errors. */
  const char *(*explain_open)(pool *p, int xerrno, const char *path, int flags,
    mode_t mode, const char **args);

  /* Explain opendir(3) errors. */
  const char *(*explain_opendir)(pool *p, int xerrno, const char *path,
    const char **args);

  /* Explain read(2) errors. */
  const char *(*explain_read)(pool *p, int xerrno, int fd, void *buf,
    size_t sz, const char **args);

  /* Explain readdir(3) errors. */
  const char *(*explain_readdir)(pool *p, int xerrno, void *dirh,
    const char **args);

  /* Explain readlink(2) errors. */
  const char *(*explain_readlink)(pool *p, int xerrno, const char *path,
    char *buf, size_t sz, const char **args);

  /* Explain readv(2) errors. */
  const char *(*explain_readv)(pool *p, int xerrno, int fd,
    const struct iovec *iov, int iov_len, const char **args);

  /* Explain rename(2) errors. */
  const char *(*explain_rename)(pool *p, int xerrno, const char *old_path,
    const char *new_path, const char **args);

  /* Explain rmdir(2) errors. */
  const char *(*explain_rmdir)(pool *p, int xerrno, const char *path,
    const char **args);

  /* Explain setegid(2) errors. */
  const char *(*explain_setegid)(pool *p, int xerrno, gid_t gid,
    const char **args);

  /* Explain seteuid(2) errors. */
  const char *(*explain_seteuid)(pool *p, int xerrno, uid_t uid,
    const char **args);

  /* Explain setgid(2) errors. */
  const char *(*explain_setgid)(pool *p, int xerrno, gid_t gid,
    const char **args);

  /* Explain setregid(2) errors. */
  const char *(*explain_setregid)(pool *p, int xerrno, gid_t rgid,
    gid_t egid, const char **args);

  /* Explain setresgid(2) errors. */
  const char *(*explain_setresgid)(pool *p, int xerrno, gid_t rgid, gid_t egid,
    gid_t sgid, const char **args);

  /* Explain setresuid(2) errors. */
  const char *(*explain_setresuid)(pool *p, int xerrno, uid_t ruid, uid_t euid,
    uid_t suid, const char **args);

  /* Explain setreuid(2) errors. */
  const char *(*explain_setreuid)(pool *p, int xerrno, uid_t ruid, uid_t euid,
    const char **args);

  /* Explain setrlimit(2) errors. */
  const char *(*explain_setrlimit)(pool *p, int xerrno, int resource,
    const struct rlimit *rlim, const char **args);

  /* Explain setsockopt(2) errors. */
  const char *(*explain_setsockopt)(pool *p, int xerrno, int fd, int level,
    int option, const void *val, socklen_t valsz, const char **args);

  /* Explain setuid(2) errors. */
  const char *(*explain_setuid)(pool *p, int xerrno, uid_t uid,
    const char **args);

  /* Explain socket(2) errors. */
  const char *(*explain_socket)(pool *p, int xerrno, int domain, int type,
    int proto, const char **args);

  /* Explain stat(2) errors. */
  const char *(*explain_stat)(pool *p, int xerrno, const char *path,
    struct stat *st, const char **args);

  /* Explain statfs(2) errors. */
  const char *(*explain_statfs)(pool *p, int xerrno, const char *path,
    void *stfs, const char **args);

  /* Explain statvfs(2) errors. */
  const char *(*explain_statvfs)(pool *p, int xerrno, const char *path,
    void *stfs, const char **args);

  /* Explain symlink(2) errors. */
  const char *(*explain_symlink)(pool *p, int xerrno, const char *target_path,
    const char *link_path, const char **args);

  /* Explain truncate(2) errors. */
  const char *(*explain_truncate)(pool *p, int xerrno, const char *path,
    off_t len, const char **args);

  /* Explain unlink(2) errors. */
  const char *(*explain_unlink)(pool *p, int xerrno, const char *path,
    const char **args);

  /* Explain utimes(2) errors. */
  const char *(*explain_utimes)(pool *p, int xerrno, const char *path,
    const struct timeval *tvs, const char **args);

  /* Explain write(2) errors. */
  const char *(*explain_write)(pool *p, int xerrno, int fd, const void *buf,
    size_t sz, const char **args);

  /* Explain writev(2) errors. */
  const char *(*explain_writev)(pool *p, int xerrno, int fd,
    const struct iovec *iov, int iov_len, const char **args);
};

typedef struct err_explain_rec pr_error_explainer_t;

pr_error_t *pr_error_create(pool *p, int xerrno);
void pr_error_destroy(pr_error_t *err);

/* Get the identity of the process at the time this error was created. */
int pr_error_get_who(pr_error_t *err, uid_t *err_uid, gid_t *err_gid);

int pr_error_set_why(pr_error_t *err, const char *goal);
int pr_error_set_where(pr_error_t *err, module *m, const char *file,
  unsigned int lineno);
int pr_error_set_what(pr_error_t *err, const char *what);

unsigned int pr_error_use_details(unsigned int use_details);
#define PR_ERROR_DETAILS_USE_NAMES		0x00001
#define PR_ERROR_DETAILS_USE_IDS		0x00002
#define PR_ERROR_DETAILS_USE_PROTOCOL		0x00004
#define PR_ERROR_DETAILS_USE_MODULE		0x00008
#define PR_ERROR_DETAILS_USE_FILE		0x00010

#define PR_ERROR_DETAILS_DEFAULT \
  (PR_ERROR_DETAILS_USE_NAMES|PR_ERROR_DETAILS_USE_IDS| \
   PR_ERROR_DETAILS_USE_PROTOCOL|PR_ERROR_DETAILS_USE_MODULE| \
   PR_ERROR_DETAILS_USE_FILE)

/* Set the list of allowed formats (verbosity). */
unsigned int pr_error_use_formats(unsigned int use_formats);
#define PR_ERROR_FORMAT_USE_DETAILED		0x001
#define PR_ERROR_FORMAT_USE_TERSE		0x002
#define PR_ERROR_FORMAT_USE_MINIMAL		0x004

#define PR_ERROR_FORMAT_DEFAULT \
  (PR_ERROR_FORMAT_USE_DETAILED|PR_ERROR_FORMAT_USE_MINIMAL)

/* Convert the error into a textual representation (determined by use_format)
 * for consumption/use in e.g. logging.
 */
const char *pr_error_strerror(pr_error_t *err, int use_format);

pr_error_explainer_t *pr_error_register_explainer(pool *p, module *m,
  const char *name);
int pr_error_unregister_explainer(pool *p, module *m, const char *name);

/* Choose which explainer to use by name. */
int pr_error_use_explainer(pool *p, module *m, const char *name);

/* Explain individual operations' errors.  The list of explainable operations
 * is NOT meant to be a comprehensive list of all system/library calls used
 * by ProFTPD and its modules.  Instead, the list of operations is meant
 * mostly for those operations whose failure will be user/admin-visible, AND
 * whose explanations can be useful for the user/admin for correcting the
 * cause of the problem.
 */

int pr_error_explain_accept(pr_error_t *err, int fd,
  struct sockaddr *addr, socklen_t *addr_len);

int pr_error_explain_bind(pr_error_t *err, int fd,
  const struct sockaddr *addr, socklen_t addr_len);

int pr_error_explain_chdir(pr_error_t *err, const char *path);

int pr_error_explain_chmod(pr_error_t *err, const char *path, mode_t mode);

int pr_error_explain_chown(pr_error_t *err, const char *path,
  uid_t uid, gid_t gid);

int pr_error_explain_chroot(pr_error_t *err, const char *path);

int pr_error_explain_close(pr_error_t *err, int fd);

int pr_error_explain_closedir(pr_error_t *err, void *dirh);

int pr_error_explain_connect(pr_error_t *err, int fd,
  const struct sockaddr *addr, socklen_t addr_len);

int pr_error_explain_fchmod(pr_error_t *err, int fd, mode_t mode);

int pr_error_explain_fchown(pr_error_t *err, int fd, uid_t uid, gid_t gid);

int pr_error_explain_fclose(pr_error_t *err, FILE *fh);

int pr_error_explain_fcntl(pr_error_t *err, int fd, int oper, long arg);

int pr_error_explain_fdopen(pr_error_t *err, int fd, const char *mode);

int pr_error_explain_flock(pr_error_t *err, int fd, int oper);

int pr_error_explain_fopen(pr_error_t *err, const char *path, const char *mode);

int pr_error_explain_fork(pr_error_t *err);

int pr_error_explain_fstat(pr_error_t *err, int fd, struct stat *st);

int pr_error_explain_fstatfs(pr_error_t *err, int fd, void *stfs);

int pr_error_explain_fstatvfs(pr_error_t *err, int fd, void *stfs);

int pr_error_explain_fsync(pr_error_t *err, int fd);

int pr_error_explain_ftruncate(pr_error_t *err, int fd, off_t len);

int pr_error_explain_futimes(pr_error_t *err, int fd,
  const struct timeval *tvs);

int pr_error_explain_getaddrinfo(pr_error_t *err, const char *name,
  const char *service, const struct addrinfo *hints, struct addrinfo **res);

int pr_error_explain_gethostbyname(pr_error_t *err, const char *name);

int pr_error_explain_gethostbyname2(pr_error_t *err, const char *name,
  int family);

int pr_error_explain_gethostname(pr_error_t *err, char *buf, size_t sz);

int pr_error_explain_getnameinfo(pr_error_t *err, const struct sockaddr *addr,
  socklen_t addr_len, char *host, size_t host_len, char *service,
  size_t service_len, int flags);

int pr_error_explain_getpeername(pr_error_t *err, int fd, struct sockaddr *addr,
  socklen_t *addr_len);

int pr_error_explain_getrlimit(pr_error_t *err, int resource,
  struct rlimit *rlim);

int pr_error_explain_getsockname(pr_error_t *err, int fd, struct sockaddr *addr,
  socklen_t *addr_len);

int pr_error_explain_getsockopt(pr_error_t *err, int fd, int level, int option,
  void *val, socklen_t *valsz);

int pr_error_explain_lchown(pr_error_t *err, const char *path,
  uid_t uid, gid_t gid);

int pr_error_explain_link(pr_error_t *err, const char *target_path,
  const char *link_path);

int pr_error_explain_listen(pr_error_t *err, int fd, int backlog);

int pr_error_explain_lseek(pr_error_t *err, int fd, off_t offset, int whence);

int pr_error_explain_lstat(pr_error_t *err, const char *path, struct stat *st);

int pr_error_explain_mkdir(pr_error_t *err, const char *path, mode_t mode);

int pr_error_explain_mkdtemp(pr_error_t *err, char *tmpl);

int pr_error_explain_mkstemp(pr_error_t *err, char *tmpl);

int pr_error_explain_open(pr_error_t *err, const char *path, int flags,
  mode_t mode);

int pr_error_explain_opendir(pr_error_t *err, const char *path);

int pr_error_explain_read(pr_error_t *err, int fd, void *buf, size_t sz);

int pr_error_explain_readdir(pr_error_t *err, void *dirh);

int pr_error_explain_readlink(pr_error_t *err, const char *path, char *buf,
  size_t sz);

int pr_error_explain_readv(pr_error_t *err, int fd, const struct iovec *iov,
  int iov_len);

int pr_error_explain_rename(pr_error_t *err, const char *old_path,
  const char *new_path);

int pr_error_explain_rmdir(pr_error_t *err, const char *path);

int pr_error_explain_setegid(pr_error_t *err, gid_t gid);

int pr_error_explain_seteuid(pr_error_t *err, uid_t uid);

int pr_error_explain_setgid(pr_error_t *err, gid_t gid);

int pr_error_explain_setregid(pr_error_t *err, gid_t rgid, gid_t egid);

int pr_error_explain_setresgid(pr_error_t *err, gid_t rgid, gid_t egid,
  gid_t sgid);

int pr_error_explain_setresuid(pr_error_t *err, uid_t ruid, uid_t euid,
  uid_t suid);

int pr_error_explain_setreuid(pr_error_t *err, uid_t ruid, uid_t euid);

int pr_error_explain_setrlimit(pr_error_t *err, int resource,
  const struct rlimit *rlim);

int pr_error_explain_setsockopt(pr_error_t *err, int fd, int level, int option,
  const void *val, socklen_t valsz);

int pr_error_explain_setuid(pr_error_t *err, uid_t uid);

int pr_error_explain_socket(pr_error_t *err, int domain, int type, int proto);

int pr_error_explain_stat(pr_error_t *err, const char *path, struct stat *st);

int pr_error_explain_statfs(pr_error_t *err, const char *path, void *stfs);

int pr_error_explain_statvfs(pr_error_t *err, const char *path, void *stfs);

int pr_error_explain_symlink(pr_error_t *err, const char *target_path,
  const char *link_path);

int pr_error_explain_truncate(pr_error_t *err, const char *path, off_t len);

int pr_error_explain_unlink(pr_error_t *err, const char *path);

int pr_error_explain_utimes(pr_error_t *err, const char *path,
  const struct timeval *tvs);

int pr_error_explain_write(pr_error_t *err, int fd, const void *buf, size_t sz);

int pr_error_explain_writev(pr_error_t *err, int fd,
  const struct iovec *iov, int iov_len);

#endif /* PR_ERROR_H */
