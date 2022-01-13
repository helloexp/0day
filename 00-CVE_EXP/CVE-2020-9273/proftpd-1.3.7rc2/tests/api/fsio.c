/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2008-2018 The ProFTPD Project team
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

/* FSIO API tests */

#include "tests.h"

#ifdef PR_USE_XATTR
/* Handle the case where ENOATTR may not be defined. */
# ifndef ENOATTR
#  define ENOATTR ENODATA
# endif
#endif

static pool *p = NULL;

static char *fsio_cwd = NULL;
static const char *fsio_test_path = "/tmp/prt-foo.bar.baz";
static const char *fsio_test2_path = "/tmp/prt-foo.bar.baz.quxx.quzz";
static const char *fsio_unlink_path = "/tmp/prt-fsio-link.dat";
static const char *fsio_link_path = "/tmp/prt-fsio-symlink.lnk";
static const char *fsio_testdir_path = "/tmp/prt-fsio-test.d";
static const char *fsio_copy_src_path = "/tmp/prt-fs-src.dat";
static const char *fsio_copy_dst_path = "/tmp/prt-fs-dst.dat";

/* Fixtures */

static void set_up(void) {
  (void) unlink(fsio_test_path);
  (void) unlink(fsio_test2_path);
  (void) unlink(fsio_link_path);
  (void) unlink(fsio_unlink_path);
  (void) rmdir(fsio_testdir_path);

  if (fsio_cwd != NULL) {
    free(fsio_cwd);
  }

  fsio_cwd = getcwd(NULL, 0);

  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_fs();
  pr_fs_statcache_set_policy(PR_TUNABLE_FS_STATCACHE_SIZE,
    PR_TUNABLE_FS_STATCACHE_MAX_AGE, 0);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("error", 1, 20);
    pr_trace_set_levels("fsio", 1, 20);
    pr_trace_set_levels("fs.statcache", 1, 20);
  }

}

static void tear_down(void) {
  if (fsio_cwd != NULL) {
    free(fsio_cwd);
    fsio_cwd = NULL;
  }

  (void) pr_fsio_guard_chroot(FALSE);
  pr_fs_statcache_set_policy(PR_TUNABLE_FS_STATCACHE_SIZE,
    PR_TUNABLE_FS_STATCACHE_MAX_AGE, 0);

  pr_unregister_fs("/testuite");

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("error", 0, 0);
    pr_trace_set_levels("fsio", 0, 0);
    pr_trace_set_levels("fs.statcache", 0, 0);
  }

  (void) unlink(fsio_test_path);
  (void) unlink(fsio_test2_path);
  (void) unlink(fsio_link_path);
  (void) unlink(fsio_unlink_path);
  (void) rmdir(fsio_testdir_path);

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

static const char *get_errnum(pool *err_pool, int xerrno) {
  char errnum[32];
  memset(errnum, '\0', sizeof(errnum));
  snprintf(errnum, sizeof(errnum)-1, "%d", xerrno);
  return pstrdup(err_pool, errnum);
}

/* Tests */

START_TEST (fsio_sys_open_test) {
  int flags;
  pr_fh_t *fh;

  mark_point();
  flags = O_CREAT|O_EXCL|O_RDONLY;
  fh = pr_fsio_open(NULL, flags);
  fail_unless(fh == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  flags = O_RDONLY;
  fh = pr_fsio_open(fsio_test_path, flags);
  fail_unless(fh == NULL, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  flags = O_RDONLY;
  fh = pr_fsio_open("/etc/hosts", flags);
  fail_unless(fh != NULL, "Failed to open /etc/hosts: %s", strerror(errno));

  (void) pr_fsio_close(fh);
}
END_TEST

START_TEST (fsio_sys_open_canon_test) {
  int flags;
  pr_fh_t *fh;

  flags = O_CREAT|O_EXCL|O_RDONLY;
  fh = pr_fsio_open_canon(NULL, flags);
  fail_unless(fh == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);

  flags = O_RDONLY;
  fh = pr_fsio_open_canon(fsio_test_path, flags);
  fail_unless(fh == NULL, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);

  flags = O_RDONLY;
  fh = pr_fsio_open_canon("/etc/hosts", flags);
  fail_unless(fh != NULL, "Failed to open /etc/hosts: %s", strerror(errno));

  (void) pr_fsio_close(fh);
}
END_TEST

START_TEST (fsio_sys_open_chroot_guard_test) {
  int flags, res;
  pr_fh_t *fh;
  const char *path;

  res = pr_fsio_guard_chroot(TRUE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);

  path = "/etc/hosts";
  flags = O_CREAT|O_RDONLY;
  fh = pr_fsio_open(path, flags);
  if (fh != NULL) {
    (void) pr_fsio_close(fh);
    fail("open(2) of %s succeeded unexpectedly", path);
  }

  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  path = "/&Z";
  flags = O_WRONLY;
  fh = pr_fsio_open(path, flags);
  if (fh != NULL) {
    (void) pr_fsio_close(fh);
    fail("open(2) of %s succeeded unexpectedly", path);
  }

  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno));

  path = "/etc";
  fh = pr_fsio_open(path, flags);
  if (fh != NULL) {
    (void) pr_fsio_close(fh);
    fail("open(2) of %s succeeded unexpectedly", path);
  }

  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno));

  path = "/lib";
  fh = pr_fsio_open(path, flags);
  if (fh != NULL) {
    (void) pr_fsio_close(fh);
    fail("open(2) of %s succeeded unexpectedly", path);
  }

  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno));

  (void) pr_fsio_guard_chroot(FALSE);

  path = "/etc/hosts";
  flags = O_RDONLY;
  fh = pr_fsio_open(path, flags);
  fail_unless(fh != NULL, "Failed to open '%s': %s", path, strerror(errno));
  (void) pr_fsio_close(fh);
}
END_TEST

START_TEST (fsio_sys_close_test) {
  int res;
  pr_fh_t *fh;

  res = pr_fsio_close(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s %d", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open("/etc/hosts", O_RDONLY);
  fail_unless(fh != NULL, "Failed to open /etc/hosts: %s",
    strerror(errno));

  res = pr_fsio_close(fh);
  fail_unless(res == 0, "Failed to close file handle: %s", strerror(errno));

  mark_point();

  /* Deliberately try to close an already-closed handle, to make sure we
   * don't segfault.
   */
  res = pr_fsio_close(fh);
  fail_unless(res < 0, "Failed to handle already-closed file handle");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);
}
END_TEST

START_TEST (fsio_sys_unlink_test) {
  int res;
  pr_fh_t *fh;

  res = pr_fsio_unlink(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_unlink_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to open '%s': %s", fsio_unlink_path,
    strerror(errno));
  (void) pr_fsio_close(fh);

  res = pr_fsio_unlink(fsio_unlink_path);
  fail_unless(res == 0, "Failed to unlink '%s': %s", fsio_unlink_path,
    strerror(errno));
}
END_TEST

START_TEST (fsio_sys_unlink_chroot_guard_test) {
  int res;

  res = pr_fsio_guard_chroot(TRUE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);

  res = pr_fsio_unlink("/etc/hosts");
  fail_unless(res < 0, "Deleted /etc/hosts unexpectedly");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s %d", EACCES,
    strerror(errno), errno);

  (void) pr_fsio_guard_chroot(FALSE);

  res = pr_fsio_unlink("/lib/foo.bar.baz");
  fail_unless(res < 0, "Deleted /lib/foo.bar.baz unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s %d", ENOENT,
    strerror(errno), errno);
}
END_TEST

START_TEST (fsio_sys_stat_test) {
  int res;
  struct stat st;
  unsigned int cache_size = 3, max_age = 1, policy_flags = 0;

  res = pr_fsio_stat(NULL, &st);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  res = pr_fsio_stat("/", NULL);
  fail_unless(res < 0, "Failed to handle null struct stat");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  res = pr_fsio_stat("/", &st);
  fail_unless(res == 0, "Unexpected stat(2) error on '/': %s",
    strerror(errno));
  fail_unless(S_ISDIR(st.st_mode), "'/' is not a directory as expected");

  /* Now, do the stat(2) again, and make sure we get the same information
   * from the cache.
   */
  res = pr_fsio_stat("/", &st);
  fail_unless(res == 0, "Unexpected stat(2) error on '/': %s",
    strerror(errno));
  fail_unless(S_ISDIR(st.st_mode), "'/' is not a directory as expected");

  pr_fs_statcache_reset();
  res = pr_fs_statcache_set_policy(cache_size, max_age, policy_flags);
  fail_unless(res == 0, "Failed to set statcache policy: %s", strerror(errno));

  res = pr_fsio_stat("/foo/bar/baz/quxx", &st);
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT, got %s (%d)", strerror(errno),
    errno);

  res = pr_fsio_stat("/foo/bar/baz/quxx", &st);
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT, got %s (%d)", strerror(errno),
    errno);

  /* Now wait for longer than 1 second (our configured max age) */
  sleep(max_age + 1);

  res = pr_fsio_stat("/foo/bar/baz/quxx", &st);
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT, got %s (%d)", strerror(errno),
    errno);

  /* Stat a symlink path */
  res = pr_fsio_symlink("/tmp", fsio_link_path);
  fail_unless(res == 0, "Failed to create symlink to '%s': %s", fsio_link_path,
    strerror(errno));

  res = pr_fsio_stat(fsio_link_path, &st);
  fail_unless(res == 0, "Failed to stat '%s': %s", fsio_link_path,
    strerror(errno));

  (void) unlink(fsio_link_path);
}
END_TEST

START_TEST (fsio_sys_fstat_test) {
  int res;
  pr_fh_t *fh;
  struct stat st;

  res = pr_fsio_fstat(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open("/etc/hosts", O_RDONLY);
  fail_unless(fh != NULL, "Failed to open /etc/hosts: %s",
    strerror(errno));

  res = pr_fsio_fstat(fh, &st);
  fail_unless(res == 0, "Failed to fstat /etc/hosts: %s",
    strerror(errno));
  (void) pr_fsio_close(fh);
}
END_TEST

START_TEST (fsio_sys_read_test) {
  int res;
  pr_fh_t *fh;
  char *buf;
  size_t buflen;

  res = pr_fsio_read(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open("/etc/hosts", O_RDONLY);
  fail_unless(fh != NULL, "Failed to open /etc/hosts: %s",
    strerror(errno));

  res = pr_fsio_read(fh, NULL, 0);
  fail_unless(res < 0, "Failed to handle null buffer");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  buflen = 32;
  buf = palloc(p, buflen);

  res = pr_fsio_read(fh, buf, 0);
  fail_unless(res < 0, "Failed to handle zero buffer length");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_read(fh, buf, 1);
  fail_unless(res == 1, "Failed to read 1 byte: %s", strerror(errno));

  (void) pr_fsio_close(fh);
}
END_TEST

START_TEST (fsio_sys_write_test) {
  int res;
  pr_fh_t *fh;
  char *buf;
  size_t buflen;

  res = pr_fsio_write(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to open '%s': %s", strerror(errno));

  /* XXX What happens if we use NULL buffer, zero length? */
  res = pr_fsio_write(fh, NULL, 0);
  fail_unless(res < 0, "Failed to handle null buffer");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  buflen = 32;
  buf = palloc(p, buflen);
  memset(buf, 'c', buflen);

  res = pr_fsio_write(fh, buf, 0);
  fail_unless(res == 0, "Failed to handle zero buffer length");

  res = pr_fsio_write(fh, buf, buflen);
  fail_unless((size_t) res == buflen, "Failed to write %lu bytes: %s",
    (unsigned long) buflen, strerror(errno));

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_lseek_test) {
  int res;
  pr_fh_t *fh;

  res = pr_fsio_lseek(NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open("/etc/hosts", O_RDONLY);
  fail_unless(fh != NULL, "Failed to open /etc/hosts: %s",
    strerror(errno));

  res = pr_fsio_lseek(fh, 0, 0);
  fail_unless(res == 0, "Failed to seek to byte 0: %s", strerror(errno));

  (void) pr_fsio_close(fh);
}
END_TEST

START_TEST (fsio_sys_link_test) {
  int res;
  const char *target_path, *link_path;
  pr_fh_t *fh;

  target_path = link_path = NULL;
  res = pr_fsio_link(target_path, link_path);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  target_path = fsio_test_path;
  link_path = NULL;
  res = pr_fsio_link(target_path, link_path);
  fail_unless(res < 0, "Failed to handle null link_path argument");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  target_path = NULL;
  link_path = fsio_link_path;
  res = pr_fsio_link(target_path, link_path);
  fail_unless(res < 0, "Failed to handle null target_path argument");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to create '%s': %s", fsio_test_path,
    strerror(errno));
  (void) pr_fsio_close(fh);

  /* Link a file (that exists) to itself */
  link_path = target_path = fsio_test_path;
  res = pr_fsio_link(target_path, link_path);
  fail_unless(res < 0, "Failed to handle same existing source/destination");
  fail_unless(errno == EEXIST, "Expected EEXIST, got %s (%d)", strerror(errno),
    errno);

  /* Create expected link */
  link_path = fsio_link_path;
  target_path = fsio_test_path;
  res = pr_fsio_link(target_path, link_path);
  fail_unless(res == 0, "Failed to create link from '%s' to '%s': %s",
    link_path, target_path, strerror(errno));
  (void) unlink(link_path);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_link_chroot_guard_test) {
  int res;

  res = pr_fsio_guard_chroot(TRUE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);

  res = pr_fsio_link(fsio_link_path, "/etc/foo.bar.baz");
  fail_unless(res < 0, "Linked /etc/foo.bar.baz unexpectedly");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s %d", EACCES,
    strerror(errno), errno);

  (void) pr_fsio_guard_chroot(FALSE);

  (void) pr_fsio_unlink(fsio_link_path);
  res = pr_fsio_link(fsio_link_path, "/lib/foo/bar/baz");
  fail_unless(res < 0, "Linked /lib/foo/bar/baz unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s %d", ENOENT,
    strerror(errno), errno);
}
END_TEST

START_TEST (fsio_sys_symlink_test) {
  int res;
  const char *target_path, *link_path;

  target_path = link_path = NULL;
  res = pr_fsio_symlink(target_path, link_path);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  target_path = "/tmp";
  link_path = NULL;
  res = pr_fsio_symlink(target_path, link_path);
  fail_unless(res < 0, "Failed to handle null link_path argument");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  target_path = NULL;
  link_path = fsio_link_path;
  res = pr_fsio_symlink(target_path, link_path);
  fail_unless(res < 0, "Failed to handle null target_path argument");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  /* Symlink a file (that exists) to itself */
  link_path = target_path = "/tmp";
  res = pr_fsio_symlink(target_path, link_path);
  fail_unless(res < 0, "Failed to handle same existing source/destination");
  fail_unless(errno == EEXIST, "Expected EEXIST, got %s (%d)", strerror(errno),
    errno);

  /* Create expected symlink */
  link_path = fsio_link_path;
  target_path = "/tmp";
  res = pr_fsio_symlink(target_path, link_path);
  fail_unless(res == 0, "Failed to create symlink from '%s' to '%s': %s",
    link_path, target_path, strerror(errno));
  (void) unlink(link_path);
}
END_TEST

START_TEST (fsio_sys_symlink_chroot_guard_test) {
  int res;

  res = pr_fsio_guard_chroot(TRUE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);

  res = pr_fsio_symlink(fsio_link_path, "/etc/foo.bar.baz");
  fail_unless(res < 0, "Symlinked /etc/foo.bar.baz unexpectedly");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s %d", EACCES,
    strerror(errno), errno);

  (void) pr_fsio_guard_chroot(FALSE);
  (void) pr_fsio_unlink(fsio_link_path);

  res = pr_fsio_symlink(fsio_link_path, "/lib/foo/bar/baz");
  fail_unless(res < 0, "Symlinked /lib/foo/bar/baz unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s %d", ENOENT,
    strerror(errno), errno);
}
END_TEST

START_TEST (fsio_sys_readlink_test) {
  int res;
  char buf[PR_TUNABLE_BUFFER_SIZE];
  const char *link_path, *target_path, *path;

  res = pr_fsio_readlink(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  /* Read a non-symlink file */
  path = "/";
  res = pr_fsio_readlink(path, buf, sizeof(buf)-1);
  fail_unless(res < 0, "Failed to handle non-symlink path");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  /* Read a symlink file */
  target_path = "/tmp";
  link_path = fsio_link_path;
  res = pr_fsio_symlink(target_path, link_path);
  fail_unless(res == 0, "Failed to create symlink from '%s' to '%s': %s",
    link_path, target_path, strerror(errno));

  memset(buf, '\0', sizeof(buf));
  res = pr_fsio_readlink(link_path, buf, sizeof(buf)-1);
  fail_unless(res > 0, "Failed to read symlink '%s': %s", link_path,
    strerror(errno));
  buf[res] = '\0';
  fail_unless(strcmp(buf, target_path) == 0, "Expected '%s', got '%s'",
    target_path, buf);

  /* Read a symlink file using a zero-length buffer */
  res = pr_fsio_readlink(link_path, buf, 0);
  fail_unless(res <= 0, "Expected length <= 0, got %d", res);

  (void) unlink(link_path);
}
END_TEST

START_TEST (fsio_sys_lstat_test) {
  int res;
  struct stat st;
  unsigned int cache_size = 3, max_age = 1, policy_flags = 0;

  res = pr_fsio_lstat(NULL, &st);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  res = pr_fsio_lstat("/", NULL);
  fail_unless(res < 0, "Failed to handle null struct stat");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  res = pr_fsio_lstat("/", &st);
  fail_unless(res == 0, "Unexpected lstat(2) error on '/': %s",
    strerror(errno));
  fail_unless(S_ISDIR(st.st_mode), "'/' is not a directory as expected");

  /* Now, do the lstat(2) again, and make sure we get the same information
   * from the cache.
   */
  res = pr_fsio_lstat("/", &st);
  fail_unless(res == 0, "Unexpected lstat(2) error on '/': %s",
    strerror(errno));
  fail_unless(S_ISDIR(st.st_mode), "'/' is not a directory as expected");

  pr_fs_statcache_reset();
  res = pr_fs_statcache_set_policy(cache_size, max_age, policy_flags);
  fail_unless(res == 0, "Failed to set statcache policy: %s", strerror(errno));

  res = pr_fsio_lstat("/foo/bar/baz/quxx", &st);
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT, got %s (%d)", strerror(errno),
    errno);

  res = pr_fsio_lstat("/foo/bar/baz/quxx", &st);
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT, got %s (%d)", strerror(errno),
    errno);

  /* Now wait for longer than 1 second (our configured max age) */
  sleep(max_age + 1);

  res = pr_fsio_lstat("/foo/bar/baz/quxx", &st);
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT, got %s (%d)", strerror(errno),
    errno);

  /* lstat a symlink path */
  res = pr_fsio_symlink("/tmp", fsio_link_path);
  fail_unless(res == 0, "Failed to create symlink to '%s': %s", fsio_link_path,
    strerror(errno));

  res = pr_fsio_lstat(fsio_link_path, &st);
  fail_unless(res == 0, "Failed to lstat '%s': %s", fsio_link_path,
    strerror(errno));

  (void) unlink(fsio_link_path);
}
END_TEST

START_TEST (fsio_sys_access_dir_test) {
  int res;
  uid_t uid = getuid();
  gid_t gid = getgid();
  mode_t perms;
  array_header *suppl_gids;

  res = pr_fsio_access(NULL, X_OK, uid, gid, NULL);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL, got %s (%d)", strerror(errno),
    errno);

  res = pr_fsio_access("/baz/bar/foo", X_OK, uid, gid, NULL);
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  /* Make the directory to check; we want it to have perms 771.*/
  perms = (mode_t) 0771;
  res = mkdir(fsio_testdir_path, perms);
  fail_if(res < 0, "Unable to create directory '%s': %s", fsio_testdir_path,
    strerror(errno));

  /* Use chmod(2) to ensure that the directory has the perms we want,
   * regardless of any umask settings.
   */
  res = chmod(fsio_testdir_path, perms);
  fail_if(res < 0, "Unable to set perms %04o on directory '%s': %s", perms,
    fsio_testdir_path, strerror(errno));

  /* First, check that we ourselves can access our own directory. */

  pr_fs_clear_cache2(fsio_testdir_path);
  res = pr_fsio_access(fsio_testdir_path, F_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for file access on directory: %s",
    strerror(errno));

  pr_fs_clear_cache2(fsio_testdir_path);
  res = pr_fsio_access(fsio_testdir_path, R_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for read access on directory: %s",
    strerror(errno));

  pr_fs_clear_cache2(fsio_testdir_path);
  res = pr_fsio_access(fsio_testdir_path, W_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for write access on directory: %s",
    strerror(errno));

  pr_fs_clear_cache2(fsio_testdir_path);
  res = pr_fsio_access(fsio_testdir_path, X_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for execute access on directory: %s",
    strerror(errno));

  suppl_gids = make_array(p, 1, sizeof(gid_t));
  *((gid_t *) push_array(suppl_gids)) = gid;

  pr_fs_clear_cache2(fsio_testdir_path);
  res = pr_fsio_access(fsio_testdir_path, X_OK, uid, gid, suppl_gids);
  fail_unless(res == 0, "Failed to check for execute access on directory: %s",
    strerror(errno));

  pr_fs_clear_cache2(fsio_testdir_path);
  res = pr_fsio_access(fsio_testdir_path, R_OK, uid, gid, suppl_gids);
  fail_unless(res == 0, "Failed to check for read access on directory: %s",
    strerror(errno));

  pr_fs_clear_cache2(fsio_testdir_path);
  res = pr_fsio_access(fsio_testdir_path, W_OK, uid, gid, suppl_gids);
  fail_unless(res == 0, "Failed to check for write access on directory: %s",
    strerror(errno));

  if (getenv("TRAVIS") == NULL) {
    uid_t other_uid;
    gid_t other_gid;

    /* Deliberately use IDs other than the current ones. */
    other_uid = uid - 1;
    other_gid = gid - 1;

    /* Next, check that others can access the directory. */
    pr_fs_clear_cache2(fsio_testdir_path);
    res = pr_fsio_access(fsio_testdir_path, F_OK, other_uid, other_gid,
      NULL);
    fail_unless(res == 0,
      "Failed to check for other file access on directory: %s",
      strerror(errno));

    pr_fs_clear_cache2(fsio_testdir_path);
    res = pr_fsio_access(fsio_testdir_path, R_OK, other_uid, other_gid,
      NULL);
    fail_unless(res < 0,
      "other read access on directory succeeded unexpectedly");
    fail_unless(errno == EACCES, "Expected EACCES, got %s (%d)",
      strerror(errno), errno);

    pr_fs_clear_cache2(fsio_testdir_path);
    res = pr_fsio_access(fsio_testdir_path, W_OK, other_uid, other_gid,
      NULL);
    fail_unless(res < 0,
      "other write access on directory succeeded unexpectedly");
    fail_unless(errno == EACCES, "Expected EACCES, got %s (%d)",
      strerror(errno), errno);

    pr_fs_clear_cache2(fsio_testdir_path);
    res = pr_fsio_access(fsio_testdir_path, X_OK, other_uid, other_gid,
      NULL);
    fail_unless(res == 0, "Failed to check for execute access on directory: %s",
      strerror(errno));
  }

  (void) rmdir(fsio_testdir_path);
}
END_TEST

START_TEST (fsio_sys_access_file_test) {
  int fd, res;
  uid_t uid = getuid();
  gid_t gid = getgid();
  mode_t perms = 0665;
  array_header *suppl_gids;

  /* Make the file to check; we want it to have perms 664.*/
  fd = open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
  fail_if(fd < 0, "Unable to create file '%s': %s", fsio_test_path,
    strerror(errno));

  /* Use chmod(2) to ensure that the file has the perms we want,
   * regardless of any umask settings.
   */
  res = chmod(fsio_test_path, perms);
  fail_if(res < 0, "Unable to set perms %04o on file '%s': %s", perms,
    fsio_test_path, strerror(errno));

  /* First, check that we ourselves can access our own file. */

  pr_fs_clear_cache2(fsio_test_path);
  res = pr_fsio_access(fsio_test_path, F_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for file access on '%s': %s",
    fsio_test_path, strerror(errno));

  pr_fs_clear_cache2(fsio_test_path);
  res = pr_fsio_access(fsio_test_path, R_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for read access on '%s': %s",
    fsio_test_path, strerror(errno));

  pr_fs_clear_cache2(fsio_test_path);
  res = pr_fsio_access(fsio_test_path, W_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for write access on '%s': %s",
    fsio_test_path, strerror(errno));

  pr_fs_clear_cache2(fsio_test_path);
  res = pr_fsio_access(fsio_test_path, X_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for execute access on '%s': %s",
    fsio_test_path, strerror(errno));

  suppl_gids = make_array(p, 1, sizeof(gid_t));
  *((gid_t *) push_array(suppl_gids)) = gid;

  pr_fs_clear_cache2(fsio_test_path);
  res = pr_fsio_access(fsio_test_path, X_OK, uid, gid, suppl_gids);
  fail_unless(res == 0, "Failed to check for execute access on '%s': %s",
    fsio_test_path, strerror(errno));

  pr_fs_clear_cache2(fsio_test_path);
  res = pr_fsio_access(fsio_test_path, R_OK, uid, gid, suppl_gids);
  fail_unless(res == 0, "Failed to check for read access on '%s': %s",
    fsio_test_path, strerror(errno));

  pr_fs_clear_cache2(fsio_test_path);
  res = pr_fsio_access(fsio_test_path, W_OK, uid, gid, suppl_gids);
  fail_unless(res == 0, "Failed to check for write access on '%s': %s",
    fsio_test_path, strerror(errno));

  (void) unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_faccess_test) {
  int res;
  uid_t uid = getuid();
  gid_t gid = getgid();
  mode_t perms = 0664;
  pr_fh_t *fh;

  res = pr_fsio_faccess(NULL, F_OK, uid, gid, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Unable to create file '%s': %s", fsio_test_path,
    strerror(errno));

  /* Use chmod(2) to ensure that the file has the perms we want,
   * regardless of any umask settings.
   */
  res = chmod(fsio_test_path, perms);
  fail_if(res < 0, "Unable to set perms %04o on file '%s': %s", perms,
    fsio_test_path, strerror(errno));

  /* First, check that we ourselves can access our own file. */

  pr_fs_clear_cache2(fsio_test_path);
  res = pr_fsio_faccess(fh, F_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for file access on '%s': %s",
    fsio_test_path, strerror(errno));

  pr_fs_clear_cache2(fsio_test_path);
  res = pr_fsio_faccess(fh, R_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for read access on '%s': %s",
    fsio_test_path, strerror(errno));

  pr_fs_clear_cache2(fsio_test_path);
  res = pr_fsio_faccess(fh, W_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to check for write access on '%s': %s",
    fsio_test_path, strerror(errno));

  pr_fs_clear_cache2(fsio_test_path);
  res = pr_fsio_faccess(fh, X_OK, uid, gid, NULL);
  fail_unless(res < 0, "Failed to check for execute access on '%s': %s",
    fsio_test_path, strerror(errno));

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_truncate_test) {
  int res;
  off_t len = 0;
  pr_fh_t *fh;

  res = pr_fsio_truncate(NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_truncate(fsio_test_path, 0);
  fail_unless(res < 0, "Truncated '%s' unexpectedly", fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to create '%s': %s", fsio_test_path,
    strerror(errno));

  res = pr_fsio_truncate(fsio_test_path, len);
  fail_unless(res == 0, "Failed to truncate '%s': %s", fsio_test_path,
    strerror(errno));

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_truncate_chroot_guard_test) {
  int res;

  res = pr_fsio_guard_chroot(TRUE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);

  res = pr_fsio_truncate("/etc/foo.bar.baz", 0);
  fail_unless(res < 0, "Truncated /etc/foo.bar.baz unexpectedly");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s %d", EACCES,
    strerror(errno), errno);

  (void) pr_fsio_guard_chroot(FALSE);

  res = pr_fsio_truncate("/lib/foo/bar/baz", 0);
  fail_unless(res < 0, "Truncated /lib/foo/bar/baz unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s %d", ENOENT,
    strerror(errno), errno);
}
END_TEST

START_TEST (fsio_sys_ftruncate_test) {
  int res;
  off_t len = 0;
  pr_fh_t *fh;
  pr_buffer_t *buf;

  res = pr_fsio_ftruncate(NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to create '%s': %s", fsio_test_path,
    strerror(errno));

  mark_point();
  res = pr_fsio_ftruncate(fh, len);
  fail_unless(res == 0, "Failed to truncate '%s': %s", fsio_test_path,
    strerror(errno));

  /* Attach a read buffer to the handle, make sure it is cleared. */
  buf = pcalloc(fh->fh_pool, sizeof(pr_buffer_t));
  buf->buflen = 100;
  buf->remaining = 1;

  fh->fh_buf = buf;

  mark_point();
  res = pr_fsio_ftruncate(fh, len);
  fail_unless(res == 0, "Failed to truncate '%s': %s", fsio_test_path,
    strerror(errno));
  fail_unless(buf->remaining == buf->buflen,
    "Expected %lu, got %lu", (unsigned long) buf->buflen,
    (unsigned long) buf->remaining);

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_chmod_test) {
  int res;
  mode_t mode = 0644;
  pr_fh_t *fh;

  res = pr_fsio_chmod(NULL, mode);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_chmod(fsio_test_path, 0);
  fail_unless(res < 0, "Changed perms of '%s' unexpectedly", fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to create '%s': %s", fsio_test_path,
    strerror(errno));

  res = pr_fsio_chmod(fsio_test_path, mode);
  fail_unless(res == 0, "Failed to set perms of '%s': %s", fsio_test_path,
    strerror(errno));

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_chmod_chroot_guard_test) {
  int res;
  mode_t mode = 0644;

  res = pr_fsio_guard_chroot(TRUE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);

  res = pr_fsio_chmod("/etc/foo.bar.baz", mode);
  fail_unless(res < 0, "Set mode on /etc/foo.bar.baz unexpectedly");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s %d", EACCES,
    strerror(errno), errno);

  (void) pr_fsio_guard_chroot(FALSE);

  res = pr_fsio_chmod("/lib/foo/bar/baz", mode);
  fail_unless(res < 0, "Set mode on /lib/foo/bar/baz unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s %d", ENOENT,
    strerror(errno), errno);
}
END_TEST

START_TEST (fsio_sys_fchmod_test) {
  int res;
  mode_t mode = 0644;
  pr_fh_t *fh;

  res = pr_fsio_fchmod(NULL, mode);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to create '%s': %s", fsio_test_path,
    strerror(errno));

  res = pr_fsio_fchmod(fh, mode);
  fail_unless(res == 0, "Failed to set perms of '%s': %s", fsio_test_path,
    strerror(errno));

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_chown_test) {
  int res;
  uid_t uid = getuid();
  gid_t gid = getgid();
  pr_fh_t *fh;

  res = pr_fsio_chown(NULL, uid, gid);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_chown(fsio_test_path, uid, gid);
  fail_unless(res < 0, "Changed ownership of '%s' unexpectedly",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to create '%s': %s", fsio_test_path,
    strerror(errno));

  res = pr_fsio_chown(fsio_test_path, uid, gid);
  fail_unless(res == 0, "Failed to set ownership of '%s': %s", fsio_test_path,
    strerror(errno));

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_chown_chroot_guard_test) {
  int res;
  uid_t uid = getuid();
  gid_t gid = getgid();

  res = pr_fsio_guard_chroot(TRUE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);

  res = pr_fsio_chown("/etc/foo.bar.baz", uid, gid);
  fail_unless(res < 0, "Set ownership on /etc/foo.bar.baz unexpectedly");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s %d", EACCES,
    strerror(errno), errno);

  (void) pr_fsio_guard_chroot(FALSE);

  res = pr_fsio_chown("/lib/foo/bar/baz", uid, gid);
  fail_unless(res < 0, "Set ownership on /lib/foo/bar/baz unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s %d", ENOENT,
    strerror(errno), errno);
}
END_TEST

START_TEST (fsio_sys_fchown_test) {
  int res;
  uid_t uid = getuid();
  gid_t gid = getgid();
  pr_fh_t *fh;

  res = pr_fsio_fchown(NULL, uid, gid);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to create '%s': %s", fsio_test_path,
    strerror(errno));

  res = pr_fsio_fchown(fh, uid, gid);
  fail_unless(res == 0, "Failed to set ownership of '%s': %s", fsio_test_path,
    strerror(errno));

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_lchown_test) {
  int res;
  uid_t uid = getuid();
  gid_t gid = getgid();
  pr_fh_t *fh;

  res = pr_fsio_lchown(NULL, uid, gid);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_lchown(fsio_test_path, uid, gid);
  fail_unless(res < 0, "Changed ownership of '%s' unexpectedly",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to create '%s': %s", fsio_test_path,
    strerror(errno));

  res = pr_fsio_lchown(fsio_test_path, uid, gid);
  fail_unless(res == 0, "Failed to set ownership of '%s': %s", fsio_test_path,
    strerror(errno));

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_lchown_chroot_guard_test) {
  int res;
  uid_t uid = getuid();
  gid_t gid = getgid();

  res = pr_fsio_guard_chroot(TRUE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);

  res = pr_fsio_lchown("/etc/foo.bar.baz", uid, gid);
  fail_unless(res < 0, "Set ownership on /etc/foo.bar.baz unexpectedly");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s %d", EACCES,
    strerror(errno), errno);

  (void) pr_fsio_guard_chroot(FALSE);

  res = pr_fsio_lchown("/lib/foo/bar/baz", uid, gid);
  fail_unless(res < 0, "Set ownership on /lib/foo/bar/baz unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s %d", ENOENT,
    strerror(errno), errno);
}
END_TEST

START_TEST (fsio_sys_rename_test) {
  int res;
  pr_fh_t *fh;

  res = pr_fsio_rename(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_rename(fsio_test_path, NULL);
  fail_unless(res < 0, "Failed to handle null dst argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_rename(fsio_test_path, fsio_test2_path);
  fail_unless(res < 0, "Failed to handle non-existent files");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to create '%s': %s", fsio_test_path,
    strerror(errno));
  (void) pr_fsio_close(fh);

  res = pr_fsio_rename(fsio_test_path, fsio_test2_path);
  fail_unless(res == 0, "Failed to rename '%s' to '%s': %s", fsio_test_path,
    fsio_test2_path, strerror(errno));

  (void) pr_fsio_unlink(fsio_test_path);
  (void) pr_fsio_unlink(fsio_test2_path);
}
END_TEST

START_TEST (fsio_sys_rename_chroot_guard_test) {
  int res;
  pr_fh_t *fh;

  res = pr_fsio_guard_chroot(TRUE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to create '%s': %s", fsio_test_path,
    strerror(errno));
  (void) pr_fsio_close(fh);

  res = pr_fsio_rename(fsio_test_path, "/etc/foo.bar.baz");
  fail_unless(res < 0, "Renamed '%s' unexpectedly", fsio_test_path);
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  res = pr_fsio_rename("/etc/foo.bar.baz", fsio_test_path);
  fail_unless(res < 0, "Renamed '/etc/foo.bar.baz' unexpectedly");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  (void) pr_fsio_guard_chroot(FALSE);

  res = pr_fsio_rename("/etc/foo/bar/baz", "/lib/quxx/quzz");
  fail_unless(res < 0, "Renamed '/etc/foo/bar/baz' unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_utimes_test) {
  int res;
  struct timeval tvs[3];
  pr_fh_t *fh;

  memset(tvs, 0, sizeof(tvs));

  res = pr_fsio_utimes(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_utimes(fsio_test_path, (struct timeval *) &tvs);
  fail_unless(res < 0, "Changed times of '%s' unexpectedly", fsio_test_path);
  fail_unless(errno == ENOENT || errno == EINVAL,
    "Expected ENOENT (%d) or EINVAL (%d), got %s (%d)", ENOENT, EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to create '%s': %s", fsio_test_path,
    strerror(errno));

  memset(&tvs, 0, sizeof(tvs));
  res = pr_fsio_utimes(fsio_test_path, (struct timeval *) &tvs);
  fail_unless(res == 0, "Failed to set times of '%s': %s", fsio_test_path,
    strerror(errno));

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_utimes_chroot_guard_test) {
  int res;
  struct timeval tvs[3];

  memset(tvs, 0, sizeof(tvs));

  res = pr_fsio_guard_chroot(TRUE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);
 
  res = pr_fsio_utimes("/etc/foo.bar.baz", (struct timeval *) &tvs);
  fail_unless(res < 0, "Set times on /etc/foo.bar.baz unexpectedly");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s %d", EACCES,
    strerror(errno), errno);

  (void) pr_fsio_guard_chroot(FALSE);

  res = pr_fsio_utimes("/lib/foo/bar/baz", (struct timeval *) &tvs);
  fail_unless(res < 0, "Set times on /lib/foo/bar/baz unexpectedly");
  fail_unless(errno == ENOENT || errno == EINVAL,
    "Expected ENOENT (%d) or EINVAL (%d), got %s %d", ENOENT, EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (fsio_sys_futimes_test) {
  int res;
  struct timeval tvs[3];
  pr_fh_t *fh;
  
  memset(tvs, 0, sizeof(tvs));

  res = pr_fsio_futimes(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to create '%s': %s", fsio_test_path,
    strerror(errno));

  memset(&tvs, 0, sizeof(tvs));
  res = pr_fsio_futimes(fh, (struct timeval *) &tvs);
  fail_unless(res == 0, "Failed to set times of '%s': %s", fsio_test_path,
    strerror(errno));

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_fsync_test) {
  int res;
  pr_fh_t *fh;

  res = pr_fsio_fsync(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to open '%s': %s", fsio_test_path,
    strerror(errno));

  res = pr_fsio_fsync(fh);
#ifdef HAVE_FSYNC
  fail_unless(res == 0, "fsync of '%s' failed: %s", fsio_test_path,
    strerror(errno));
#else
  fail_unless(res < 0, "fsync of '%s' succeeded unexpectedly", fsio_test_path);
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);
#endif /* HAVE_FSYNC */

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_getxattr_test) {
  ssize_t res;
  const char *path, *name;
  unsigned long fsio_opts;

  res = pr_fsio_getxattr(NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_getxattr(p, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = fsio_test_path;
  res = pr_fsio_getxattr(p, path, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "foo.bar";

  fsio_opts = pr_fsio_set_options(PR_FSIO_OPT_IGNORE_XATTR);
  res = pr_fsio_getxattr(p, path, name, NULL, 0);
  fail_unless(res < 0, "Failed to handle disabled xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  (void) pr_fsio_set_options(fsio_opts);
  res = pr_fsio_getxattr(p, path, name, NULL, 0);
#ifdef PR_USE_XATTR
  fail_unless(res < 0, "Failed to handle nonexist attribute '%s'", name);
  fail_unless(errno == ENOENT || errno == ENOATTR || errno == ENOTSUP,
    "Expected ENOENT (%d), ENOATTR (%d) or ENOTSUP (%d), got %s (%d)",
    ENOENT, ENOATTR, ENOTSUP, strerror(errno), errno);

#else
  fail_unless(res < 0, "Failed to handle --disable-xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);
#endif /* PR_USE_XATTR */
}
END_TEST

START_TEST (fsio_sys_lgetxattr_test) {
  ssize_t res;
  const char *path, *name;
  unsigned long fsio_opts;

  res = pr_fsio_lgetxattr(NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_lgetxattr(p, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = fsio_test_path;
  res = pr_fsio_lgetxattr(p, path, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null xattr name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "foo.bar";

  fsio_opts = pr_fsio_set_options(PR_FSIO_OPT_IGNORE_XATTR);
  res = pr_fsio_lgetxattr(p, path, name, NULL, 0);
  fail_unless(res < 0, "Failed to handle disabled xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  pr_fsio_set_options(fsio_opts);
  res = pr_fsio_lgetxattr(p, path, name, NULL, 0);
#ifdef PR_USE_XATTR
  fail_unless(res < 0, "Failed to handle nonexist attribute '%s'", name);
  fail_unless(errno == ENOENT || errno == ENOATTR || errno == ENOTSUP,
    "Expected ENOENT (%d), ENOATTR (%d) or ENOTSUP (%d), got %s (%d)",
    ENOENT, ENOATTR, ENOTSUP, strerror(errno), errno);

#else
  fail_unless(res < 0, "Failed to handle --disable-xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);
#endif /* PR_USE_XATTR */
}
END_TEST

START_TEST (fsio_sys_fgetxattr_test) {
  ssize_t res;
  pr_fh_t *fh;
  const char *name;
  unsigned long fsio_opts;

  res = pr_fsio_fgetxattr(NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_fgetxattr(p, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null file handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(fsio_test_path);
  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_RDWR);
  fail_unless(fh != NULL, "Failed to open '%s': %s", fsio_test_path,
    strerror(errno));

  res = pr_fsio_fgetxattr(p, fh, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null xattr name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "foo.bar";

  fsio_opts = pr_fsio_set_options(PR_FSIO_OPT_IGNORE_XATTR);
  res = pr_fsio_fgetxattr(p, fh, name, NULL, 0);
  fail_unless(res < 0, "Failed to handle disabled xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  pr_fsio_set_options(fsio_opts);
  res = pr_fsio_fgetxattr(p, fh, name, NULL, 0);
#ifdef PR_USE_XATTR
  fail_unless(res < 0, "Failed to handle nonexist attribute '%s'", name);
  fail_unless(errno == ENOENT || errno == ENOATTR || errno == ENOTSUP,
    "Expected ENOENT (%d), ENOATTR (%d) or ENOTSUP (%d), got %s (%d)",
    ENOENT, ENOATTR, ENOTSUP, strerror(errno), errno);

#else
  fail_unless(res < 0, "Failed to handle --disable-xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);
#endif /* PR_USE_XATTR */

  pr_fsio_close(fh);
  (void) unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_listxattr_test) {
  int res;
  const char *path;
  pr_fh_t *fh = NULL;
  array_header *names = NULL;
  unsigned long fsio_opts;

  res = pr_fsio_listxattr(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_listxattr(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = fsio_test_path;
  res = pr_fsio_listxattr(p, path, NULL);
  fail_unless(res < 0, "Failed to handle null array");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fsio_opts = pr_fsio_set_options(PR_FSIO_OPT_IGNORE_XATTR);
  res = pr_fsio_listxattr(p, path, &names);
  fail_unless(res < 0, "Failed to handle disabled xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  pr_fsio_set_options(fsio_opts);
  res = pr_fsio_listxattr(p, path, &names);
#ifdef PR_USE_XATTR
  fail_unless(res < 0, "Failed to handle nonexistent path '%s'", path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  (void) unlink(fsio_test_path);
  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to open '%s': %s", fsio_test_path,
    strerror(errno));
  pr_fsio_close(fh);

  res = pr_fsio_listxattr(p, path, &names);
  fail_if(res < 0, "Failed to list xattrs for '%s': %s", path, strerror(errno));

  pr_fsio_close(fh);
  (void) unlink(fsio_test_path);
#else
  (void) fh;
  fail_unless(res < 0, "Failed to handle --disable-xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);
#endif /* PR_USE_XATTR */
}
END_TEST

START_TEST (fsio_sys_llistxattr_test) {
  int res;
  const char *path;
  pr_fh_t *fh = NULL;
  array_header *names = NULL;
  unsigned long fsio_opts;

  res = pr_fsio_llistxattr(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_llistxattr(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = fsio_test_path;
  res = pr_fsio_llistxattr(p, path, NULL);
  fail_unless(res < 0, "Failed to handle null array");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fsio_opts = pr_fsio_set_options(PR_FSIO_OPT_IGNORE_XATTR);
  res = pr_fsio_llistxattr(p, path, &names);
  fail_unless(res < 0, "Failed to handle disabled xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  pr_fsio_set_options(fsio_opts);
  res = pr_fsio_llistxattr(p, path, &names);
#ifdef PR_USE_XATTR
  fail_unless(res < 0, "Failed to handle nonexistent path '%s'", path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  (void) unlink(fsio_test_path);
  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to open '%s': %s", fsio_test_path,
    strerror(errno));
  pr_fsio_close(fh);

  res = pr_fsio_listxattr(p, path, &names);
  fail_if(res < 0, "Failed to list xattrs for '%s': %s", path, strerror(errno));

  pr_fsio_close(fh);
  (void) unlink(fsio_test_path);
#else
  (void) fh;
  fail_unless(res < 0, "Failed to handle --disable-xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);
#endif /* PR_USE_XATTR */
}
END_TEST

START_TEST (fsio_sys_flistxattr_test) {
  int res;
  pr_fh_t *fh;
  array_header *names = NULL;
  unsigned long fsio_opts;

  res = pr_fsio_flistxattr(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_flistxattr(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null file handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(fsio_test_path);
  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_RDWR);
  fail_unless(fh != NULL, "Failed to open '%s': %s", fsio_test_path,
    strerror(errno));

  res = pr_fsio_flistxattr(p, fh, NULL);
  fail_unless(res < 0, "Failed to handle null array");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fsio_opts = pr_fsio_set_options(PR_FSIO_OPT_IGNORE_XATTR);
  res = pr_fsio_flistxattr(p, fh, &names);
  fail_unless(res < 0, "Failed to handle disabled xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  pr_fsio_set_options(fsio_opts);
  res = pr_fsio_flistxattr(p, fh, &names);
#ifdef PR_USE_XATTR
  fail_if(res < 0, "Failed to list xattrs for '%s': %s", fsio_test_path,
    strerror(errno));

#else
  fail_unless(res < 0, "Failed to handle --disable-xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);
#endif /* PR_USE_XATTR */

  pr_fsio_close(fh);
  (void) unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_removexattr_test) {
  int res;
  const char *path, *name;
  unsigned long fsio_opts;

  res = pr_fsio_removexattr(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_removexattr(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = fsio_test_path;
  res = pr_fsio_removexattr(p, path, NULL);
  fail_unless(res < 0, "Failed to handle null attribute name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "foo.bar";

  fsio_opts = pr_fsio_set_options(PR_FSIO_OPT_IGNORE_XATTR);
  res = pr_fsio_removexattr(p, path, name);
  fail_unless(res < 0, "Failed to handle disabled xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  pr_fsio_set_options(fsio_opts);
  res = pr_fsio_removexattr(p, path, name);
#ifdef PR_USE_XATTR
  fail_unless(res < 0, "Failed to handle nonexistent attribute '%s'", name);
  fail_unless(errno == ENOENT || errno == ENOATTR || errno == ENOTSUP,
    "Expected ENOENT (%d), ENOATTR (%d) or ENOTSUP (%d), got %s (%d)",
    ENOENT, ENOATTR, ENOTSUP, strerror(errno), errno);

#else
  fail_unless(res < 0, "Failed to handle --disable-xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);
#endif /* PR_USE_XATTR */
}
END_TEST

START_TEST (fsio_sys_lremovexattr_test) {
  int res;
  const char *path, *name;
  unsigned long fsio_opts;

  res = pr_fsio_lremovexattr(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_lremovexattr(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = fsio_test_path;
  res = pr_fsio_lremovexattr(p, path, NULL);
  fail_unless(res < 0, "Failed to handle null attribute name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "foo.bar";

  fsio_opts = pr_fsio_set_options(PR_FSIO_OPT_IGNORE_XATTR);
  res = pr_fsio_lremovexattr(p, path, name);
  fail_unless(res < 0, "Failed to handle disabled xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  pr_fsio_set_options(fsio_opts);
  res = pr_fsio_lremovexattr(p, path, name);
#ifdef PR_USE_XATTR
  fail_unless(res < 0, "Failed to handle nonexistent attribute '%s'", name);
  fail_unless(errno == ENOENT || errno == ENOATTR || errno == ENOTSUP,
    "Expected ENOENT (%d), ENOATTR (%d) or ENOTSUP (%d), got %s (%d)",
    ENOENT, ENOATTR, ENOTSUP, strerror(errno), errno);

#else
  fail_unless(res < 0, "Failed to handle --disable-xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);
#endif /* PR_USE_XATTR */
}
END_TEST

START_TEST (fsio_sys_fremovexattr_test) {
  int res;
  pr_fh_t *fh;
  const char *name;
  unsigned long fsio_opts;

  res = pr_fsio_fremovexattr(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_fremovexattr(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(fsio_test_path);
  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_RDWR);
  fail_unless(fh != NULL, "Failed to open '%s': %s", fsio_test_path,
    strerror(errno));

  res = pr_fsio_fremovexattr(p, fh, NULL);
  fail_unless(res < 0, "Failed to handle null attribute name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "foo.bar";

  fsio_opts = pr_fsio_set_options(PR_FSIO_OPT_IGNORE_XATTR);
  res = pr_fsio_fremovexattr(p, fh, name);
  fail_unless(res < 0, "Failed to handle disabled xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  pr_fsio_set_options(fsio_opts);
  res = pr_fsio_fremovexattr(p, fh, name);
#ifdef PR_USE_XATTR
  fail_unless(res < 0, "Failed to handle nonexistent attribute '%s'", name);
  fail_unless(errno == ENOENT || errno == ENOATTR || errno == ENOTSUP,
    "Expected ENOENT (%d), ENOATTR (%d) or ENOTSUP (%d), got %s (%d)",
    ENOENT, ENOATTR, ENOTSUP, strerror(errno), errno);

#else
  fail_unless(res < 0, "Failed to handle --disable-xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);
#endif /* PR_USE_XATTR */

  pr_fsio_close(fh);
  (void) unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_setxattr_test) {
  int res, flags;
  const char *path, *name;
  pr_fh_t *fh;
  unsigned long fsio_opts;

  res = pr_fsio_setxattr(NULL, NULL, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_setxattr(p, NULL, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = fsio_test_path;
  res = pr_fsio_setxattr(p, path, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null attribute name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "foo.bar";
  flags = PR_FSIO_XATTR_FL_CREATE;

  fsio_opts = pr_fsio_set_options(PR_FSIO_OPT_IGNORE_XATTR);
  res = pr_fsio_setxattr(p, path, name, NULL, 0, flags);
  fail_unless(res < 0, "Failed to handle disabled xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  pr_fsio_set_options(fsio_opts);
  res = pr_fsio_setxattr(p, path, name, NULL, 0, flags);
#ifdef PR_USE_XATTR
  fail_unless(res < 0, "Failed to handle nonexistent file '%s'", path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  (void) unlink(fsio_test_path);
  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to open '%s': %s", fsio_test_path,
    strerror(errno));
  pr_fsio_close(fh);

  res = pr_fsio_setxattr(p, path, name, NULL, 0, flags);
  if (res < 0) {
    fail_unless(errno == ENOTSUP, "Expected ENOTSUP (%d), got %s (%d)", ENOTSUP,
      strerror(errno), errno);
  }

  (void) unlink(fsio_test_path);
#else
  (void) fh;
  fail_unless(res < 0, "Failed to handle --disable-xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);
#endif /* PR_USE_XATTR */
}
END_TEST

START_TEST (fsio_sys_lsetxattr_test) {
  int res, flags;
  const char *path, *name;
  pr_fh_t *fh;
  unsigned long fsio_opts;

  res = pr_fsio_lsetxattr(NULL, NULL, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_lsetxattr(p, NULL, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = fsio_test_path;
  res = pr_fsio_lsetxattr(p, path, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null attribute name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "foo.bar";
  flags = PR_FSIO_XATTR_FL_CREATE;

  fsio_opts = pr_fsio_set_options(PR_FSIO_OPT_IGNORE_XATTR);
  res = pr_fsio_lsetxattr(p, path, name, NULL, 0, flags);
  fail_unless(res < 0, "Failed to handle disabled xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  pr_fsio_set_options(fsio_opts);
  res = pr_fsio_lsetxattr(p, path, name, NULL, 0, flags);
#ifdef PR_USE_XATTR
  fail_unless(res < 0, "Failed to handle nonexistent file '%s'", path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  (void) unlink(fsio_test_path);
  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to open '%s': %s", fsio_test_path,
    strerror(errno));
  pr_fsio_close(fh);

  res = pr_fsio_lsetxattr(p, path, name, NULL, 0, flags);
  if (res < 0) {
    fail_unless(errno == ENOTSUP, "Expected ENOTSUP (%d), got %s (%d)", ENOTSUP,
      strerror(errno), errno);
  }

  (void) unlink(fsio_test_path);
#else
  (void) fh;
  fail_unless(res < 0, "Failed to handle --disable-xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);
#endif /* PR_USE_XATTR */
}
END_TEST

START_TEST (fsio_sys_fsetxattr_test) {
  int res, flags;
  pr_fh_t *fh;
  const char *name;
  unsigned long fsio_opts;

  res = pr_fsio_fsetxattr(NULL, NULL, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_fsetxattr(p, NULL, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null file handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(fsio_test_path);
  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_RDWR);
  fail_unless(fh != NULL, "Failed to open '%s': %s", fsio_test_path,
    strerror(errno));

  res = pr_fsio_fsetxattr(p, fh, NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null attribute name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "foo.bar";
  flags = PR_FSIO_XATTR_FL_CREATE;

  fsio_opts = pr_fsio_set_options(PR_FSIO_OPT_IGNORE_XATTR);
  res = pr_fsio_fsetxattr(p, fh, name, NULL, 0, flags);
  fail_unless(res < 0, "Failed to handle disabled xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  pr_fsio_set_options(fsio_opts);
  res = pr_fsio_fsetxattr(p, fh, name, NULL, 0, flags);
#ifdef PR_USE_XATTR
  if (res < 0) {
    fail_unless(errno == ENOTSUP, "Expected ENOTSUP (%d), got %s (%d)", ENOTSUP,
      strerror(errno), errno);
  }

#else
  fail_unless(res < 0, "Failed to handle --disable-xattr");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);
#endif /* PR_USE_XATTR */

  pr_fsio_close(fh);
  (void) unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_sys_mkdir_test) {
  int res;
  mode_t mode = 0755;

  res = pr_fsio_mkdir(NULL, mode);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_mkdir(fsio_testdir_path, mode);
  fail_unless(res == 0, "Failed to create '%s': %s", fsio_testdir_path,
    strerror(errno));

  (void) pr_fsio_rmdir(fsio_testdir_path);
}
END_TEST

START_TEST (fsio_sys_mkdir_chroot_guard_test) {
  int res;
  mode_t mode = 0755;

  res = pr_fsio_guard_chroot(TRUE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);
  
  res = pr_fsio_mkdir("/etc/foo.bar.baz.d", mode);
  fail_unless(res < 0, "Created /etc/foo.bar.baz.d unexpectedly");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s %d", EACCES,
    strerror(errno), errno);

  (void) pr_fsio_guard_chroot(FALSE);

  res = pr_fsio_mkdir("/lib/foo/bar/baz.d", mode);
  fail_unless(res < 0, "Created /lib/foo/bar/baz.d unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s %d", ENOENT,
    strerror(errno), errno);
}
END_TEST

START_TEST (fsio_sys_rmdir_test) {
  int res;
  mode_t mode = 0755;

  res = pr_fsio_rmdir(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_rmdir(fsio_testdir_path);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  res = pr_fsio_mkdir(fsio_testdir_path, mode);
  fail_unless(res == 0, "Failed to create '%s': %s", fsio_testdir_path,
    strerror(errno));

  res = pr_fsio_rmdir(fsio_testdir_path);
  fail_unless(res == 0, "Failed to remove '%s': %s", fsio_testdir_path,
    strerror(errno));
}
END_TEST

START_TEST (fsio_sys_rmdir_chroot_guard_test) {
  int res;

  res = pr_fsio_guard_chroot(TRUE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);

  res = pr_fsio_rmdir("/etc/foo.bar.baz.d");
  fail_unless(res < 0, "Removed /etc/foo.bar.baz.d unexpectedly");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s %d", EACCES,
    strerror(errno), errno);

  (void) pr_fsio_guard_chroot(FALSE);

  res = pr_fsio_rmdir("/lib/foo/bar/baz.d");
  fail_unless(res < 0, "Removed /lib/etc/foo.bar.baz.d unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s %d", ENOENT,
    strerror(errno), errno);
}
END_TEST

START_TEST (fsio_sys_chdir_test) {
  int res;

  res = pr_fsio_chdir(NULL, FALSE);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_chdir("/etc/hosts", FALSE);
  fail_unless(res < 0, "Failed to handle file argument");
  fail_unless(errno == EINVAL || errno == ENOTDIR,
    "Expected EINVAL (%d) or ENOTDIR (%d), got %s (%d)", EINVAL, ENOTDIR,
    strerror(errno), errno);

  res = pr_fsio_chdir("/tmp", FALSE);
  fail_unless(res == 0, "Failed to chdir to '%s': %s", fsio_cwd,
    strerror(errno));

  res = pr_fsio_chdir(fsio_cwd, FALSE);
  fail_unless(res == 0, "Failed to chdir to '%s': %s", fsio_cwd,
    strerror(errno));
}
END_TEST

START_TEST (fsio_sys_chdir_canon_test) {
  int res;

  res = pr_fsio_chdir_canon(NULL, FALSE);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_chdir_canon("/tmp", FALSE);
  fail_unless(res == 0, "Failed to chdir to '%s': %s", fsio_cwd,
    strerror(errno));

  res = pr_fsio_chdir_canon(fsio_cwd, FALSE);
  fail_unless(res == 0, "Failed to chdir to '%s': %s", fsio_cwd,
    strerror(errno));
}
END_TEST

START_TEST (fsio_sys_chroot_test) {
  int res;

  res = pr_fsio_chroot(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  if (getuid() != 0) {
    res = pr_fsio_chroot("/tmp");
    fail_unless(res < 0, "Failed to chroot without root privs");
    fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
      strerror(errno), errno);
  }
}
END_TEST

START_TEST (fsio_sys_opendir_test) {
  void *res = NULL, *res2 = NULL;
  const char *path;

  mark_point();
  res = pr_fsio_opendir(NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno); 

  mark_point();
  path = "/etc/hosts";
  res = pr_fsio_opendir(path);
  fail_unless(res == NULL, "Failed to handle file argument");
  fail_unless(errno == ENOTDIR, "Expected ENOTDIR (%d), got %s (%d)", ENOTDIR,
    strerror(errno), errno);

  mark_point();
  path = "/tmp/";
  res = pr_fsio_opendir(path);
  fail_unless(res != NULL, "Failed to open '%s': %s", path, strerror(errno));

  mark_point();
  path = "/usr/";
  res2 = pr_fsio_opendir(path);
  fail_unless(res != NULL, "Failed to open '%s': %s", path, strerror(errno));

  (void) pr_fsio_closedir(res);
  (void) pr_fsio_closedir(res2);
}
END_TEST

START_TEST (fsio_sys_readdir_test) {
  void *dirh;
  struct dirent *dent;

  dent = pr_fsio_readdir(NULL);
  fail_unless(dent == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  dent = pr_fsio_readdir("/etc/hosts");
  fail_unless(dent == NULL, "Failed to handle file argument");
  fail_unless(errno == ENOTDIR, "Expected ENOTDIR (%d), got %s (%d)", ENOTDIR,
    strerror(errno), errno);

  mark_point();
  dirh = pr_fsio_opendir("/tmp/");
  fail_unless(dirh != NULL, "Failed to open '/tmp/': %s", strerror(errno));

  dent = pr_fsio_readdir(dirh);
  fail_unless(dent != NULL, "Failed to read directory entry: %s",
    strerror(errno));

  (void) pr_fsio_closedir(dirh);
}
END_TEST

START_TEST (fsio_sys_closedir_test) {
  void *dirh;
  int res;

  res = pr_fsio_closedir(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  dirh = pr_fsio_opendir("/tmp/");
  fail_unless(dirh != NULL, "Failed to open '/tmp/': %s", strerror(errno));

  res = pr_fsio_closedir(dirh);
  fail_unless(res == 0, "Failed to close '/tmp/': %s", strerror(errno));

  /* Closing an already-closed directory descriptor should fail. */
  res = pr_fsio_closedir(dirh);
  fail_unless(res < 0, "Failed to handle already-closed directory handle");
  fail_unless(errno == ENOTDIR, "Expected ENOTDIR (%d), got %s (%d)", ENOTDIR,
    strerror(errno), errno);
}
END_TEST

static const char *test_chmod_explainer(pool *err_pool, int xerrno,
    const char *path, mode_t mode, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_chmod_with_error_test) {
  int res;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  res = pr_fsio_chmod_with_error(NULL, fsio_test_path, 0755, NULL);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_fsio_chmod_with_error(p, fsio_test_path, 0755, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_chmod = test_chmod_explainer;

  mark_point();
  res = pr_fsio_chmod_with_error(p, fsio_test_path, 0755, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "chmod() failed with \"No such file or directory [ENOENT (",
    get_errnum(p, ENOENT), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_chown_explainer(pool *err_pool, int xerrno,
    const char *path, uid_t uid, gid_t gid, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_chown_with_error_test) {
  int res;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  res = pr_fsio_chown_with_error(NULL, fsio_test_path, 1, 1, NULL);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_fsio_chown_with_error(p, fsio_test_path, 1, 1, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_chown = test_chown_explainer;

  mark_point();
  res = pr_fsio_chown_with_error(p, fsio_test_path, 1, 1, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "chown() failed with \"No such file or directory [ENOENT (",
    get_errnum(p, ENOENT), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_chroot_explainer(pool *err_pool, int xerrno,
    const char *path, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_chroot_with_error_test) {
  int res, xerrno = 0;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  res = pr_fsio_chroot_with_error(NULL, fsio_testdir_path, NULL);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_testdir_path);
  fail_unless(errno == EPERM || errno == ENOENT,
    "Expected EPERM (%d) or ENOENT (%d), %s (%d)", EPERM, ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_fsio_chroot_with_error(p, fsio_testdir_path, &err);
  xerrno = errno;
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_testdir_path);
  fail_unless(errno == EPERM || errno == ENOENT,
    "Expected EPERM (%d) or ENOENT (%d), %s (%d)", EPERM, ENOENT,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_chroot = test_chroot_explainer;

  mark_point();
  res = pr_fsio_chroot_with_error(p, fsio_testdir_path, &err);
  xerrno = errno;
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_testdir_path);
  fail_unless(errno == EPERM || errno == ENOENT,
    "Expected EPERM (%d) or ENOENT (%d), %s (%d)", EPERM, ENOENT,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "chroot() failed with \"", strerror(xerrno), " [",
    xerrno == ENOENT ? "ENOENT" : "EPERM", " (",
    get_errnum(p, xerrno), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_close_explainer(pool *err_pool, int xerrno, int fd,
    const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_close_with_error_test) {
  int res;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  res = pr_fsio_close_with_error(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null fh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_fsio_close_with_error(p, NULL, &err);
  fail_unless(res < 0, "Failed to handle null fh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_close = test_close_explainer;

  mark_point();
  res = pr_fsio_close_with_error(p, NULL, &err);
  fail_unless(res < 0, "Failed to handle null fh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "close() failed with \"Invalid argument [EINVAL (",
    get_errnum(p, EINVAL), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_fchmod_explainer(pool *err_pool, int xerrno, int fd,
    mode_t mode, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_fchmod_with_error_test) {
  int res;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  res = pr_fsio_fchmod_with_error(NULL, NULL, 0755, NULL);
  fail_unless(res < 0, "Failed to handle null fh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_fsio_fchmod_with_error(p, NULL, 0755, &err);
  fail_unless(res < 0, "Failed to handle null fh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_fchmod = test_fchmod_explainer;

  mark_point();
  res = pr_fsio_fchmod_with_error(p, NULL, 0755, &err);
  fail_unless(res < 0, "Failed to handle null fh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "fchmod() failed with \"Invalid argument [EINVAL (",
    get_errnum(p, EINVAL), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_fchown_explainer(pool *err_pool, int xerrno, int fd,
    uid_t uid, gid_t gid, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_fchown_with_error_test) {
  int res;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  res = pr_fsio_fchown_with_error(NULL, NULL, 1, 1, NULL);
  fail_unless(res < 0, "Failed to handle null fh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_fsio_fchown_with_error(p, NULL, 1, 1, &err);
  fail_unless(res < 0, "Failed to handle null fh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_fchown = test_fchown_explainer;

  mark_point();
  res = pr_fsio_fchown_with_error(p, NULL, 1, 1, &err);
  fail_unless(res < 0, "Failed to handle null fh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "fchown() failed with \"Invalid argument [EINVAL (",
    get_errnum(p, EINVAL), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_lchown_explainer(pool *err_pool, int xerrno,
    const char *path, uid_t uid, gid_t gid, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_lchown_with_error_test) {
  int res;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  res = pr_fsio_lchown_with_error(NULL, fsio_test_path, 1, 1, NULL);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_fsio_lchown_with_error(p, fsio_test_path, 1, 1, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_lchown = test_lchown_explainer;

  mark_point();
  res = pr_fsio_lchown_with_error(p, fsio_test_path, 1, 1, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "lchown() failed with \"No such file or directory [ENOENT (",
    get_errnum(p, ENOENT), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_lstat_explainer(pool *err_pool, int xerrno,
    const char *path, struct stat *st, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_lstat_with_error_test) {
  int res;
  struct stat st;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  res = pr_fsio_lstat_with_error(NULL, fsio_test_path, &st, NULL);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_fsio_lstat_with_error(p, fsio_test_path, &st, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_lstat = test_lstat_explainer;

  mark_point();
  res = pr_fsio_lstat_with_error(p, fsio_test_path, &st, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "lstat() failed with \"No such file or directory [ENOENT (",
    get_errnum(p, ENOENT), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_mkdir_explainer(pool *err_pool, int xerrno,
    const char *path, mode_t mode, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_mkdir_with_error_test) {
  int res;
  pr_error_t *err = NULL;
  const char *errstr, *expected, *path;
  module m;
  pr_error_explainer_t *explainer;

  path = "/tmp/foo/bar/baz/quxx/quzz.d";

  mark_point();
  res = pr_fsio_mkdir_with_error(NULL, path, 0755, NULL);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_testdir_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_fsio_mkdir_with_error(p, path, 0755, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_testdir_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_mkdir = test_mkdir_explainer;

  mark_point();
  res = pr_fsio_mkdir_with_error(p, path, 0755, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_testdir_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "mkdir() failed with \"No such file or directory [ENOENT (",
    get_errnum(p, ENOENT), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_open_explainer(pool *err_pool, int xerrno,
    const char *path, int flags, mode_t mode, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_open_with_error_test) {
  pr_fh_t *fh;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  fh = pr_fsio_open_with_error(NULL, fsio_test_path, O_RDONLY, NULL);
  fail_unless(fh == NULL, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  fh = pr_fsio_open_with_error(p, fsio_test_path, O_RDONLY, &err);
  fail_unless(fh == NULL, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_open = test_open_explainer;

  mark_point();
  fh = pr_fsio_open_with_error(p, fsio_test_path, O_RDONLY, &err);
  fail_unless(fh == NULL, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "open() failed with \"No such file or directory [ENOENT (",
    get_errnum(p, ENOENT), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_read_explainer(pool *err_pool, int xerrno, int fd,
    void *buf, size_t sz, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_read_with_error_test) {
  int res;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  res = pr_fsio_read_with_error(NULL, NULL, NULL, 0, NULL);
  fail_unless(res < 0, "Failed to handle null fh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_fsio_read_with_error(p, NULL, NULL, 0, &err);
  fail_unless(res < 0, "Failed to handle null fh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_read = test_read_explainer;

  mark_point();
  res = pr_fsio_read_with_error(p, NULL, NULL, 0, &err);
  fail_unless(res < 0, "Failed to handle null fh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "read() failed with \"Invalid argument [EINVAL (",
    get_errnum(p, EINVAL), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_rename_explainer(pool *err_pool, int xerrno,
    const char *from, const char *to, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_rename_with_error_test) {
  int res;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  res = pr_fsio_rename_with_error(NULL, fsio_test_path, fsio_test2_path, NULL);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_fsio_rename_with_error(p, fsio_test_path, fsio_test2_path, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_rename = test_rename_explainer;

  mark_point();
  res = pr_fsio_rename_with_error(p, fsio_test_path, fsio_test2_path, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "rename() failed with \"No such file or directory [ENOENT (",
    get_errnum(p, ENOENT), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_rmdir_explainer(pool *err_pool, int xerrno,
    const char *path, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_rmdir_with_error_test) {
  int res;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  res = pr_fsio_rmdir_with_error(NULL, fsio_testdir_path, NULL);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_testdir_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_rmdir = test_rmdir_explainer;

  mark_point();
  res = pr_fsio_rmdir_with_error(p, fsio_testdir_path, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_testdir_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "rmdir() failed with \"No such file or directory [ENOENT (",
    get_errnum(p, ENOENT), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_stat_explainer(pool *err_pool, int xerrno,
    const char *path, struct stat *st, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_stat_with_error_test) {
  int res;
  struct stat st;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  res = pr_fsio_stat_with_error(NULL, fsio_test_path, &st, NULL);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_fsio_stat_with_error(p, fsio_test_path, &st, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_stat = test_stat_explainer;

  mark_point();
  res = pr_fsio_stat_with_error(p, fsio_test_path, &st, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "stat() failed with \"No such file or directory [ENOENT (",
    get_errnum(p, ENOENT), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_unlink_explainer(pool *err_pool, int xerrno,
    const char *path, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_unlink_with_error_test) {
  int res;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  res = pr_fsio_unlink_with_error(NULL, fsio_test_path, NULL);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_fsio_unlink_with_error(p, fsio_test_path, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_unlink = test_unlink_explainer;

  mark_point();
  res = pr_fsio_unlink_with_error(p, fsio_test_path, &err);
  fail_unless(res < 0, "Failed to handle non-existent file '%s'",
    fsio_test_path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), %s (%d)", ENOENT,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "unlink() failed with \"No such file or directory [ENOENT (",
    get_errnum(p, ENOENT), ")]\"", NULL);
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static const char *test_write_explainer(pool *err_pool, int xerrno, int fd,
    const void *buf, size_t sz, const char **args) {
  *args = pstrdup(err_pool, "fake args");
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (fsio_sys_write_with_error_test) {
  int res;
  pr_error_t *err = NULL;
  const char *errstr, *expected;
  module m;
  pr_error_explainer_t *explainer;

  mark_point();
  res = pr_fsio_write_with_error(NULL, NULL, NULL, 0, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_fsio_write_with_error(p, NULL, NULL, 0, &err);
  fail_unless(res < 0, "Failed to handle null fh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);
  fail_unless(err == NULL, "Unexpectedly populated error");

  memset(&m, 0, sizeof(m));
  m.name = "error";

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_write = test_write_explainer;

  mark_point();
  res = pr_fsio_write_with_error(p, NULL, NULL, 0, &err);
  fail_unless(res < 0, "Failed to handle null fh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);
  fail_unless(err != NULL, "Failed to populate error");

  expected = pstrcat(p,
    "write() failed with \"Invalid argument [EINVAL (",
    get_errnum(p, EINVAL), ")]\"", NULL);
  expected = "write() failed with \"Invalid argument [EINVAL (22)]\"";
  errstr = pr_error_strerror(err, PR_ERROR_FORMAT_USE_MINIMAL);
  fail_unless(strcmp(errstr, expected) == 0, "Expected '%s', got '%s'",
    expected, errstr);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

START_TEST (fsio_statcache_clear_cache_test) {
  int expected, res;
  struct stat st;
  char *cwd;

  mark_point();
  pr_fs_clear_cache();

  res = pr_fs_clear_cache2("/testsuite");
  fail_unless(res == 0, "Failed to clear cache: %s", strerror(errno));

  res = pr_fsio_stat("/tmp", &st);
  fail_unless(res == 0, "Failed to stat '/tmp': %s", strerror(errno));

  res = pr_fs_clear_cache2("/tmp");
  expected = 1;
  fail_unless(res == expected, "Expected %d, got %d", expected, res);

  res = pr_fs_clear_cache2("/testsuite");
  expected = 0;
  fail_unless(res == expected, "Expected %d, got %d", expected, res);

  res = pr_fsio_stat("/tmp", &st);
  fail_unless(res == 0, "Failed to stat '/tmp': %s", strerror(errno));

  res = pr_fsio_lstat("/tmp", &st);
  fail_unless(res == 0, "Failed to lstat '/tmp': %s", strerror(errno));

  res = pr_fs_clear_cache2("/tmp");
  expected = 2;
  fail_unless(res == expected, "Expected %d, got %d", expected, res);

  res = pr_fsio_stat("/tmp", &st);
  fail_unless(res == 0, "Failed to stat '/tmp': %s", strerror(errno));

  res = pr_fsio_lstat("/tmp", &st);
  fail_unless(res == 0, "Failed to lstat '/tmp': %s", strerror(errno));

  cwd = getcwd(NULL, 0);
  fail_unless(cwd != NULL, "Failed to get cwd: %s", strerror(errno));

  res = pr_fs_setcwd("/");
  fail_unless(res == 0, "Failed to set cwd to '/': %s", strerror(errno));

  res = pr_fs_clear_cache2("tmp");
  expected = 2;
  fail_unless(res == expected, "Expected %d, got %d", expected, res);

  res = pr_fs_setcwd(cwd);
  fail_unless(res == 0, "Failed to set cwd to '%s': %s", cwd, strerror(errno)); 

  free(cwd);
}
END_TEST

START_TEST (fsio_statcache_cache_hit_test) {
  int res;
  struct stat st;

  /* First is a cache miss...*/
  res = pr_fsio_stat("/tmp", &st);
  fail_unless(res == 0, "Failed to stat '/tmp': %s", strerror(errno));

  /* This is a cache hit, hopefully. */
  res = pr_fsio_stat("/tmp", &st);
  fail_unless(res == 0, "Failed to stat '/tmp': %s", strerror(errno));

  pr_fs_clear_cache();
}
END_TEST

START_TEST (fsio_statcache_negative_cache_test) {
  int res;
  struct stat st;

  /* First is a cache miss...*/
  res = pr_fsio_stat("/foo.bar.baz.d", &st);
  fail_unless(res < 0, "Check of '/foo.bar.baz.d' succeeded unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  /* This is a cache hit, hopefully. */
  res = pr_fsio_stat("/foo.bar.baz.d", &st);
  fail_unless(res < 0, "Check of '/foo.bar.baz.d' succeeded unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  pr_fs_clear_cache();
}
END_TEST

START_TEST (fsio_statcache_expired_test) {
  unsigned int cache_size, max_age;
  int res;
  struct stat st;

  cache_size = max_age = 1;
  pr_fs_statcache_set_policy(cache_size, max_age, 0);

  /* First is a cache miss...*/
  res = pr_fsio_stat("/tmp", &st);
  fail_unless(res == 0, "Failed to stat '/tmp': %s", strerror(errno));

  /* Wait for that cached data to expire...*/
  sleep(max_age + 1);

  /* This is another cache miss, hopefully. */
  res = pr_fsio_stat("/tmp2", &st);
  fail_unless(res < 0, "Check of '/tmp2' succeeded unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  pr_fs_clear_cache();
}
END_TEST

START_TEST (fsio_statcache_dump_test) {
  mark_point();
  pr_fs_statcache_dump();
}
END_TEST

START_TEST (fs_create_fs_test) {
  pr_fs_t *fs;

  fs = pr_create_fs(NULL, NULL);
  fail_unless(fs == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fs = pr_create_fs(p, NULL);
  fail_unless(fs == NULL, "Failed to handle null name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fs = pr_create_fs(p, "testsuite");
  fail_unless(fs != NULL, "Failed to create FS: %s", strerror(errno));
}
END_TEST

START_TEST (fs_insert_fs_test) {
  pr_fs_t *fs, *fs2;
  int res;

  res = pr_insert_fs(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fs = pr_create_fs(p, "testsuite");
  fail_unless(fs != NULL, "Failed to create FS: %s", strerror(errno));

  res = pr_insert_fs(fs, NULL);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_insert_fs(fs, "/testsuite");
  fail_unless(res == TRUE, "Failed to insert FS: %s", strerror(errno));

  res = pr_insert_fs(fs, "/testsuite");
  fail_unless(res == FALSE, "Failed to handle duplicate paths");
  fail_unless(errno == EEXIST, "Expected EEXIST (%d), got %s (%d)", EEXIST,
    strerror(errno), errno);

  fs2 = pr_create_fs(p, "testsuite2");
  fail_unless(fs2 != NULL, "Failed to create FS: %s", strerror(errno));

  res = pr_insert_fs(fs2, "/testsuite2");
  fail_unless(res == TRUE, "Failed to insert FS: %s", strerror(errno));

  fs2 = pr_create_fs(p, "testsuite3");
  fail_unless(fs2 != NULL, "Failed to create FS: %s", strerror(errno));

  /* Push this FS on top of the previously registered path; FSes can be
   * stacked like this.
   */
  res = pr_insert_fs(fs2, "/testsuite2");
  fail_unless(res == TRUE, "Failed to insert FS: %s", strerror(errno));

  (void) pr_remove_fs("/testsuite");
  (void) pr_remove_fs("/testsuite2");
  (void) pr_remove_fs("/testsuite3");
}
END_TEST

START_TEST (fs_get_fs_test) {
  pr_fs_t *fs, *fs2, *fs3;
  int exact_match = FALSE, res;

  fs = pr_get_fs(NULL, NULL);
  fail_unless(fs == NULL, "Failed to handle null arguments");

  fs = pr_get_fs("/testsuite", &exact_match);
  fail_unless(fs != NULL, "Failed to get FS: %s", strerror(errno));
  fail_unless(exact_match == FALSE, "Expected FALSE, got TRUE");

  fs2 = pr_create_fs(p, "testsuite");
  fail_unless(fs2 != NULL, "Failed to create FS: %s", strerror(errno));

  res = pr_insert_fs(fs2, "/testsuite");
  fail_unless(res == TRUE, "Failed to insert FS: %s", strerror(errno));

  fs = pr_get_fs("/testsuite", &exact_match);
  fail_unless(fs != NULL, "Failed to get FS: %s", strerror(errno));
  fail_unless(exact_match == TRUE, "Expected TRUE, got FALSE");

  fs3 = pr_create_fs(p, "testsuite2");
  fail_unless(fs3 != NULL, "Failed to create FS: %s", strerror(errno));

  res = pr_insert_fs(fs3, "/testsuite2/");
  fail_unless(res == TRUE, "Failed to insert FS: %s", strerror(errno));

  exact_match = FALSE;
  fs = pr_get_fs("/testsuite2/foo/bar/baz", &exact_match);
  fail_unless(fs != NULL, "Failed to get FS: %s", strerror(errno));
  fail_unless(exact_match == FALSE, "Expected FALSE, got TRUE");

  (void) pr_remove_fs("/testsuite2");
  (void) pr_remove_fs("/testsuite");
}
END_TEST

START_TEST (fs_unmount_fs_test) {
  pr_fs_t *fs, *fs2;
  int res;

  fs = pr_unmount_fs(NULL, NULL);
  fail_unless(fs == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fs = pr_unmount_fs("/testsuite", NULL);
  fail_unless(fs == NULL, "Failed to handle absent FS");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  fs2 = pr_create_fs(p, "testsuite");
  fail_unless(fs2 != NULL, "Failed to create FS: %s", strerror(errno));

  res = pr_insert_fs(fs2, "/testsuite");
  fail_unless(res == TRUE, "Failed to insert FS: %s", strerror(errno));

  fs = pr_unmount_fs("/testsuite", "foo bar");
  fail_unless(fs == NULL, "Failed to mismatched path AND name");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  fs = pr_unmount_fs("/testsuite2", NULL);
  fail_unless(fs == NULL, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  fs2 = pr_unmount_fs("/testsuite", NULL);
  fail_unless(fs2 != NULL, "Failed to unmount '/testsuite': %s",
    strerror(errno));

  fs2 = pr_create_fs(p, "testsuite");
  fail_unless(fs2 != NULL, "Failed to create FS: %s", strerror(errno));

  res = pr_insert_fs(fs2, "/testsuite");
  fail_unless(res == TRUE, "Failed to insert FS: %s", strerror(errno));

  fs2 = pr_create_fs(p, "testsuite2");
  fail_unless(fs2 != NULL, "Failed to create FS: %s", strerror(errno));

  res = pr_insert_fs(fs2, "/testsuite");
  fail_unless(res == TRUE, "Failed to insert FS: %s", strerror(errno));

  fs2 = pr_unmount_fs("/testsuite", NULL);
  fail_unless(fs2 != NULL, "Failed to unmount '/testsuite': %s",
    strerror(errno));

  fs2 = pr_unmount_fs("/testsuite", NULL);
  fail_unless(fs2 != NULL, "Failed to unmount '/testsuite': %s",
    strerror(errno));

  (void) pr_remove_fs("/testsuite");
  (void) pr_remove_fs("/testsuite");
}
END_TEST

START_TEST (fs_remove_fs_test) {
  pr_fs_t *fs, *fs2;
  int res;

  fs = pr_remove_fs(NULL);
  fail_unless(fs == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fs = pr_remove_fs("/testsuite");
  fail_unless(fs == NULL, "Failed to handle absent FS");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  fs2 = pr_create_fs(p, "testsuite");
  fail_unless(fs2 != NULL, "Failed to create FS: %s", strerror(errno));

  res = pr_insert_fs(fs2, "/testsuite");
  fail_unless(res == TRUE, "Failed to insert FS: %s", strerror(errno));

  fs = pr_remove_fs("/testsuite2");
  fail_unless(fs == NULL, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  fs2 = pr_remove_fs("/testsuite");
  fail_unless(fs2 != NULL, "Failed to remove '/testsuite': %s",
    strerror(errno));
}
END_TEST

START_TEST (fs_register_fs_test) {
  pr_fs_t *fs, *fs2;

  fs = pr_register_fs(NULL, NULL, NULL);
  fail_unless(fs == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fs = pr_register_fs(p, NULL, NULL);
  fail_unless(fs == NULL, "Failed to handle null name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fs = pr_register_fs(p, "testsuite", NULL);
  fail_unless(fs == NULL, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fs = pr_register_fs(p, "testsuite", "/testsuite");
  fail_unless(fs != NULL, "Failed to register FS: %s", strerror(errno));

  fs2 = pr_register_fs(p, "testsuite", "/testsuite");
  fail_unless(fs2 == NULL, "Failed to handle duplicate names");
  fail_unless(errno == EEXIST, "Expected EEXIST (%d), got %s (%d)", EEXIST,
    strerror(errno), errno);

  (void) pr_remove_fs("/testsuite");
}
END_TEST

START_TEST (fs_unregister_fs_test) {
  pr_fs_t *fs;
  int res;

  res = pr_unregister_fs(NULL);
  fail_unless(res < 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_unregister_fs("/testsuite");
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  fs = pr_register_fs(p, "testsuite", "/testsuite");
  fail_unless(fs != NULL, "Failed to register FS: %s", strerror(errno));

  res = pr_unregister_fs("/testsuite");
  fail_unless(res == 0, "Failed to unregister '/testsuite': %s",
    strerror(errno));
}
END_TEST

START_TEST (fs_resolve_fs_map_test) {
  pr_fs_t *fs;
  int res;

  mark_point();
  pr_resolve_fs_map();

  fs = pr_register_fs(p, "testsuite", "/testsuite");
  fail_unless(fs != NULL, "Failed to register FS: %s", strerror(errno));

  mark_point();
  pr_resolve_fs_map();

  res = pr_unregister_fs("/testsuite");
  fail_unless(res == 0, "Failed to unregister '/testsuite': %s",
    strerror(errno));

  mark_point();
  pr_resolve_fs_map();
}
END_TEST

#if defined(PR_USE_DEVEL)
START_TEST (fs_dump_fs_test) {
  pr_fs_t *fs, *root_fs;

  mark_point();
  pr_fs_dump(NULL);

  root_fs = pr_get_fs("/", NULL);
  fs = pr_register_fs(p, "testsuite", "/testsuite");

  mark_point();
  pr_fs_dump(NULL);

  fs->stat = root_fs->stat;
  fs->fstat = root_fs->fstat;
  fs->lstat = root_fs->lstat;
  fs->rename = root_fs->rename;
  fs->unlink = root_fs->unlink;
  fs->open = root_fs->open;
  fs->close = root_fs->close;
  fs->read = root_fs->read;
  fs->write = root_fs->write;
  fs->lseek = root_fs->lseek;
  fs->link = root_fs->link;
  fs->readlink = root_fs->readlink;
  fs->symlink = root_fs->symlink;
  fs->ftruncate = root_fs->ftruncate;
  fs->truncate = root_fs->truncate;
  fs->chmod = root_fs->chmod;
  fs->fchmod = root_fs->fchmod;
  fs->chown = root_fs->chown;
  fs->fchown = root_fs->fchown;
  fs->lchown = root_fs->lchown;
  fs->access = root_fs->access;
  fs->faccess = root_fs->faccess;
  fs->utimes = root_fs->utimes;
  fs->futimes = root_fs->futimes;
  fs->fsync = root_fs->fsync;
  fs->chdir = root_fs->chdir;
  fs->chroot = root_fs->chroot;
  fs->opendir = root_fs->opendir;
  fs->closedir = root_fs->closedir;
  fs->readdir = root_fs->readdir;
  fs->mkdir = root_fs->mkdir;
  fs->rmdir = root_fs->rmdir;

  mark_point();
  pr_fs_dump(NULL);

  pr_unregister_fs("/testsuite");
}
END_TEST
#endif /* PR_USE_DEVEL */

static int fsio_chroot_cb(pr_fs_t *fs, const char *path) {
  return 0;
}

START_TEST (fsio_custom_chroot_test) {
  pr_fs_t *fs;
  int res;
  const char *path;

  fs = pr_register_fs(p, "custom", "/testsuite/");
  fail_unless(fs != NULL, "Failed to register custom FS: %s", strerror(errno));

  fs->chroot = fsio_chroot_cb;

  mark_point();
  pr_resolve_fs_map();

  path = "/testsuite/foo/bar";
  res = pr_fsio_chroot(path);
  fail_unless(res == 0, "Failed to chroot (via custom FS) to '%s': %s", path,
    strerror(errno));

  pr_unregister_fs("/testsuite");
}
END_TEST

START_TEST (fs_clean_path_test) {
  char res[PR_TUNABLE_PATH_MAX+1], *path, *expected;

  mark_point();
  pr_fs_clean_path(NULL, NULL, 0);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/";

  mark_point();
  pr_fs_clean_path(path, NULL, 0);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res[sizeof(res)-1] = '\0';

  mark_point();
  pr_fs_clean_path(path, res, 0);

  pr_fs_clean_path(path, res, sizeof(res)-1);
  fail_unless(strcmp(res, path) == 0, "Expected cleaned path '%s', got '%s'",
    path, res);

  res[sizeof(res)-1] = '\0';
  path = "/test.txt";
  pr_fs_clean_path(path, res, sizeof(res)-1);
  fail_unless(strcmp(res, path) == 0, "Expected cleaned path '%s', got '%s'",
    path, res);

  res[sizeof(res)-1] = '\0';
  path = "/test.txt";
  pr_fs_clean_path(path, res, sizeof(res)-1);
  fail_unless(strcmp(res, path) == 0, "Expected cleaned path '%s', got '%s'",
    path, res);

  res[sizeof(res)-1] = '\0';
  path = "/./test.txt";
  pr_fs_clean_path(path, res, sizeof(res)-1);
  expected = "/test.txt";
  fail_unless(strcmp(res, expected) == 0,
    "Expected cleaned path '%s', got '%s'", expected, res);

  res[sizeof(res)-1] = '\0';
  path = "test.txt";
  pr_fs_clean_path(path, res, sizeof(res)-1);
  expected = "/test.txt";
  fail_unless(strcmp(res, expected) == 0,
    "Expected cleaned path '%s', got '%s'", path, res);
}
END_TEST

START_TEST (fs_clean_path2_test) {
  char res[PR_TUNABLE_PATH_MAX+1], *path, *expected;
  int code;

  mark_point();
  code = pr_fs_clean_path2(NULL, NULL, 0, 0);
  fail_unless(code < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/";

  mark_point();
  code = pr_fs_clean_path2(path, NULL, 0, 0);
  fail_unless(code < 0, "Failed to handle null buf");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res[sizeof(res)-1] = '\0';

  mark_point();
  code = pr_fs_clean_path2(path, res, 0, 0);
  fail_unless(code == 0, "Failed to handle zero length buf: %s",
    strerror(errno));

  res[sizeof(res)-1] = '\0';
  path = "test.txt";
  code = pr_fs_clean_path2(path, res, sizeof(res)-1, 0);
  fail_unless(code == 0, "Failed to clean path '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, path) == 0, "Expected cleaned path '%s', got '%s'",
    path, res);

  res[sizeof(res)-1] = '\0';
  path = "/./test.txt";
  code = pr_fs_clean_path2(path, res, sizeof(res)-1, 0);
  fail_unless(code == 0, "Failed to clean path '%s': %s", path,
    strerror(errno));
  expected = "/test.txt";
  fail_unless(strcmp(res, expected) == 0,
    "Expected cleaned path '%s', got '%s'", expected, res);

  res[sizeof(res)-1] = '\0';
  path = "test.d///test.txt";
  code = pr_fs_clean_path2(path, res, sizeof(res)-1, 0);
  fail_unless(code == 0, "Failed to clean path '%s': %s", path,
    strerror(errno));
  expected = "test.d/test.txt";
  fail_unless(strcmp(res, expected) == 0,
    "Expected cleaned path '%s', got '%s'", expected, res);

  res[sizeof(res)-1] = '\0';
  path = "/test.d///test.txt";
  code = pr_fs_clean_path2(path, res, sizeof(res)-1,
    PR_FSIO_CLEAN_PATH_FL_MAKE_ABS_PATH);
  fail_unless(code == 0, "Failed to clean path '%s': %s", path,
    strerror(errno));
  expected = "/test.d/test.txt";
  fail_unless(strcmp(res, expected) == 0,
    "Expected cleaned path '%s', got '%s'", expected, res);
}
END_TEST

START_TEST (fs_dircat_test) {
  char buf[PR_TUNABLE_PATH_MAX+1], *a, *b, *ok;
  int res;

  res = pr_fs_dircat(NULL, 0, NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL,
    "Failed to set errno to EINVAL for null arguments");

  res = pr_fs_dircat(buf, 0, "foo", "bar");
  fail_unless(res == -1, "Failed to handle zero-length buffer");
  fail_unless(errno == EINVAL,
    "Failed to set errno to EINVAL for zero-length buffer");

  res = pr_fs_dircat(buf, -1, "foo", "bar");
  fail_unless(res == -1, "Failed to handle negative-length buffer");
  fail_unless(errno == EINVAL,
    "Failed to set errno to EINVAL for negative-length buffer");

  a = pcalloc(p, PR_TUNABLE_PATH_MAX);
  memset(a, 'A', PR_TUNABLE_PATH_MAX-1);

  b = "foo";

  res = pr_fs_dircat(buf, sizeof(buf)-1, a, b);
  fail_unless(res == -1, "Failed to handle too-long paths");
  fail_unless(errno == ENAMETOOLONG,
    "Failed to set errno to ENAMETOOLONG for too-long paths");

  a = "foo";
  b = "/bar";
  ok = b;
  res = pr_fs_dircat(buf, sizeof(buf)-1, a, b);
  fail_unless(res == 0, "Failed to concatenate abs-path path second dir");
  fail_unless(strcmp(buf, ok) == 0, "Expected concatenated dir '%s', got '%s'",
    ok, buf);
 
  a = "foo";
  b = "bar";
  ok = "foo/bar";
  res = pr_fs_dircat(buf, sizeof(buf)-1, a, b);
  fail_unless(res == 0, "Failed to concatenate two normal paths");
  fail_unless(strcmp(buf, ok) == 0, "Expected concatenated dir '%s', got '%s'",
    ok, buf);
 
  a = "foo/";
  b = "bar";
  ok = "foo/bar";
  res = pr_fs_dircat(buf, sizeof(buf)-1, a, b);
  fail_unless(res == 0, "Failed to concatenate first dir with trailing slash");
  fail_unless(strcmp(buf, ok) == 0, "Expected concatenated dir '%s', got '%s'",
    ok, buf);

  a = "";
  b = "";
  ok = "/";
  res = pr_fs_dircat(buf, sizeof(buf)-1, a, b);
  fail_unless(res == 0, "Failed to concatenate two empty paths");
  fail_unless(strcmp(buf, ok) == 0, "Expected concatenated dir '%s', got '%s'",
    ok, buf);

  a = "/foo";
  b = "";
  ok = "/foo/";
  res = pr_fs_dircat(buf, sizeof(buf)-1, a, b);
  fail_unless(res == 0, "Failed to concatenate two empty paths");
  fail_unless(strcmp(buf, ok) == 0, "Expected concatenated dir '%s', got '%s'",
    ok, buf);

  a = "";
  b = "/bar";
  ok = "/bar/";
  res = pr_fs_dircat(buf, sizeof(buf)-1, a, b);
  fail_unless(res == 0, "Failed to concatenate two empty paths");
  fail_unless(strcmp(buf, ok) == 0, "Expected concatenated dir '%s', got '%s'",
    ok, buf);
}
END_TEST

START_TEST (fs_setcwd_test) {
  int res;
  const char *wd;

  /* Make sure that we don't segfault if we call pr_fs_setcwd() on the
   * buffer that it is already using.
   */
  res = pr_fs_setcwd(pr_fs_getcwd());
  fail_unless(res == 0, "Failed to set cwd to '%s': %s", pr_fs_getcwd(),
    strerror(errno));

  wd = pr_fs_getcwd();
  fail_unless(wd != NULL, "Failed to get working directory: %s",
    strerror(errno));
  fail_unless(strcmp(wd, fsio_cwd) == 0,
    "Expected '%s', got '%s'", fsio_cwd, wd);

  wd = pr_fs_getvwd();
  fail_unless(wd != NULL, "Failed to get working directory: %s",
    strerror(errno));
  fail_unless(strcmp(wd, "/") == 0, "Expected '/', got '%s'", wd);
}
END_TEST

START_TEST (fs_glob_test) {
  glob_t pglob;
  int res;

  res = pr_fs_glob(NULL, 0, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fs_glob(NULL, 0, NULL, &pglob);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  memset(&pglob, 0, sizeof(pglob));
  res = pr_fs_glob("*", 0, NULL, &pglob);
  fail_unless(res == 0, "Failed to glob: glob(3) returned %d: %s", res,
    strerror(errno));
  fail_unless(pglob.gl_pathc > 0, "Expected >0, got %lu",
    (unsigned long) pglob.gl_pathc);

  mark_point();
  pr_fs_globfree(NULL);
  if (res == 0) {
    pr_fs_globfree(&pglob);
  }
}
END_TEST

START_TEST (fs_copy_file_test) {
  int res;
  char *src_path = NULL, *dst_path = NULL, *text;
  pr_fh_t *fh;

  res = pr_fs_copy_file(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  src_path = (char *) fsio_copy_src_path;
  res = pr_fs_copy_file(src_path, NULL);
  fail_unless(res < 0, "Failed to handle null destination path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  dst_path = (char *) fsio_copy_dst_path;
  res = pr_fs_copy_file(src_path, dst_path);
  fail_unless(res < 0, "Failed to handle nonexistent source path");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  res = pr_fs_copy_file("/tmp", dst_path);
  fail_unless(res < 0, "Failed to handle directory source path");
  fail_unless(errno == EISDIR, "Expected EISDIR (%d), got %s (%d)", EISDIR,
    strerror(errno), errno);

  (void) unlink(src_path);
  fh = pr_fsio_open(src_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to open '%s': %s", src_path, strerror(errno));

  text = "Hello, World!\n";
  res = pr_fsio_write(fh, text, strlen(text));
  fail_if(res < 0, "Failed to write '%s' to '%s': %s", text, src_path,
    strerror(errno));

  res = pr_fsio_close(fh);
  fail_unless(res == 0, "Failed to close '%s': %s", src_path, strerror(errno));

  res = pr_fs_copy_file(src_path, "/tmp");
  fail_unless(res < 0, "Failed to handle directory destination path");
  fail_unless(errno == EISDIR, "Expected EISDIR (%d), got %s (%d)", EISDIR,
    strerror(errno), errno);

  res = pr_fs_copy_file(src_path, "/tmp/foo/bar/baz/quxx/quzz.dat");
  fail_unless(res < 0, "Failed to handle nonexistent destination path");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = pr_fs_copy_file(src_path, src_path);
  fail_unless(res == 0, "Failed to copy file to itself: %s", strerror(errno));

  (void) unlink(dst_path);

  mark_point();
  res = pr_fs_copy_file(src_path, dst_path);
  fail_unless(res == 0, "Failed to copy file: %s", strerror(errno));

  (void) pr_fsio_unlink(src_path);
  (void) pr_fsio_unlink(dst_path);
}
END_TEST

static unsigned int copy_progress_iter = 0;
static void copy_progress_cb(int nwritten) {
  copy_progress_iter++;
}

START_TEST (fs_copy_file2_test) {
  int res, flags;
  char *src_path, *dst_path, *text;
  pr_fh_t *fh;

  src_path = (char *) fsio_copy_src_path;
  dst_path = (char *) fsio_copy_dst_path;
  flags = PR_FSIO_COPY_FILE_FL_NO_DELETE_ON_FAILURE;

  (void) unlink(src_path);
  (void) unlink(dst_path);

  fh = pr_fsio_open(src_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to open '%s': %s", src_path, strerror(errno));

  text = "Hello, World!\n";
  res = pr_fsio_write(fh, text, strlen(text));
  fail_if(res < 0, "Failed to write '%s' to '%s': %s", text, src_path,
    strerror(errno));

  res = pr_fsio_close(fh);
  fail_unless(res == 0, "Failed to close '%s': %s", src_path, strerror(errno));

  copy_progress_iter = 0;

  mark_point();
  res = pr_fs_copy_file2(src_path, dst_path, flags, copy_progress_cb);
  fail_unless(res == 0, "Failed to copy file: %s", strerror(errno));

  (void) pr_fsio_unlink(src_path);
  (void) pr_fsio_unlink(dst_path);

  fail_unless(copy_progress_iter > 0, "Unexpected progress callback count (%u)",
    copy_progress_iter);
}
END_TEST

START_TEST (fs_interpolate_test) {
  int res;
  char buf[PR_TUNABLE_PATH_MAX], *path;

  memset(buf, '\0', sizeof(buf));

  res = pr_fs_interpolate(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/tmp";
  res = pr_fs_interpolate(path, NULL, 0);
  fail_unless(res < 0, "Failed to handle null buffer");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fs_interpolate(path, buf, 0);
  fail_unless(res < 0, "Failed to handle zero buffer length");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fs_interpolate(path, buf, sizeof(buf)-1);
  fail_unless(res == 1, "Failed to interpolate path '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(buf, path) == 0, "Expected '%s', got '%s'", path, buf);

  path = "~/foo/bar/baz/quzz/quzz.d";
  res = pr_fs_interpolate(path, buf, sizeof(buf)-1);
  fail_unless(res == 1, "Failed to interpolate path '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(buf, path+1) == 0, "Expected '%s', got '%s'", path+1, buf);

  path = "~";
  res = pr_fs_interpolate(path, buf, sizeof(buf)-1);
  fail_unless(res == 1, "Failed to interpolate path '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(buf, "/") == 0, "Expected '/', got '%s'", buf);

  session.chroot_path = "/tmp";
  res = pr_fs_interpolate(path, buf, sizeof(buf)-1);
  fail_unless(res == 1, "Failed to interpolate path '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(buf, session.chroot_path) == 0, "Expected '%s', got '%s'",
    session.chroot_path, buf);

  session.chroot_path = NULL;

  path = "~foo.bar.baz.quzz";
  res = pr_fs_interpolate(path, buf, sizeof(buf)-1);
  fail_unless(res < 0, "Interpolated '%s' unexpectedly", path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  session.user = "testsuite";
  path = "~/tmp.d/test.d/foo.d/bar.d";
  res = pr_fs_interpolate(path, buf, sizeof(buf)-1);
  fail_unless(res < 0, "Interpolated '%s' unexpectedly", path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);
  session.user = NULL;
}
END_TEST

START_TEST (fs_resolve_partial_test) {
  int op = FSIO_FILE_STAT, res;
  char buf[PR_TUNABLE_PATH_MAX], *path;

  res = pr_fs_resolve_partial(NULL, NULL, 0, op);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/tmp";
  res = pr_fs_resolve_partial(path, NULL, 0, op);
  fail_unless(res < 0, "Failed to handle null buffer");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  memset(buf, '\0', sizeof(buf));
  res = pr_fs_resolve_partial(path, buf, 0, op);
  fail_unless(res < 0, "Failed to handle zero buffer length");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fs_resolve_partial(path, buf, sizeof(buf)-1, op);
  fail_unless(res == 0, "Failed to resolve '%s': %s", path, strerror(errno));
  if (strcmp(buf, path) != 0) {
    /* Mac-specific hack */
    const char *prefix = "/private";

    if (strncmp(buf, prefix, strlen(prefix)) != 0) {
      fail("Expected '%s', got '%s'", path, buf);
    }
  }

  path = "/tmp/.////./././././.";
  res = pr_fs_resolve_partial(path, buf, sizeof(buf)-1, op);
  fail_unless(res == 0, "Failed to resolve '%s': %s", path, strerror(errno));
  if (strcmp(buf, path) != 0) {
    /* Mac-specific hack */
    const char *prefix = "/private";

    if (strncmp(buf, prefix, strlen(prefix)) != 0 &&
        strcmp(buf, "/tmp/") != 0) {
      fail("Expected '%s', got '%s'", path, buf);
    }
  }

  path = "/../../../.././..///../";
  res = pr_fs_resolve_partial(path, buf, sizeof(buf)-1, op);
  fail_unless(res == 0, "Failed to resolve '%s': %s", path, strerror(errno));
  if (strcmp(buf, "/") != 0) {
    /* Mac-specific hack */
    const char *prefix = "/private";

    if (strncmp(buf, prefix, strlen(prefix)) != 0) {
      fail("Expected '%s', got '%s'", path, buf);
    }
  }

  path = "/tmp/.///../../..../";
  res = pr_fs_resolve_partial(path, buf, sizeof(buf)-1, op);
  fail_unless(res < 0, "Resolved '%s' unexpectedly", path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  path = "~foo/.///../../..../";
  res = pr_fs_resolve_partial(path, buf, sizeof(buf)-1, op);
  fail_unless(res < 0, "Resolved '%s' unexpectedly", path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  path = "../../..../";
  res = pr_fs_resolve_partial(path, buf, sizeof(buf)-1, op);
  fail_unless(res < 0, "Resolved '%s' unexpectedly", path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  /* Resolve a symlink path */
  res = pr_fsio_symlink("/tmp", fsio_link_path);
  fail_unless(res == 0, "Failed to create symlink to '%s': %s", fsio_link_path,
    strerror(errno));

  res = pr_fs_resolve_partial(fsio_link_path, buf, sizeof(buf)-1, op);
  fail_unless(res == 0, "Failed to resolve '%s': %s", fsio_link_path,
    strerror(errno));

  (void) unlink(fsio_link_path);
}
END_TEST

START_TEST (fs_resolve_path_test) {
  int op = FSIO_FILE_STAT, res;
  char buf[PR_TUNABLE_PATH_MAX], *path;

  memset(buf, '\0', sizeof(buf));

  res = pr_fs_resolve_path(NULL, NULL, 0, op);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/tmp";
  res = pr_fs_resolve_path(path, NULL, 0, op);
  fail_unless(res < 0, "Failed to handle null buffer");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fs_resolve_path(path, buf, 0, op);
  fail_unless(res < 0, "Failed to handle zero buffer length");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fs_resolve_path(path, buf, sizeof(buf)-1, op);
  fail_unless(res == 0, "Failed to resolve path '%s': %s", path,
    strerror(errno));
  if (strcmp(buf, path) != 0) {
    /* Mac-specific hack */
    const char *prefix = "/private";

    if (strncmp(buf, prefix, strlen(prefix)) != 0) {
      fail("Expected '%s', got '%s'", path, buf);
    }
  }

  /* Resolve a symlink path */
  res = pr_fsio_symlink("/tmp", fsio_link_path);
  fail_unless(res == 0, "Failed to create symlink to '%s': %s", fsio_link_path,
    strerror(errno));

  res = pr_fs_resolve_path(fsio_link_path, buf, sizeof(buf)-1, op);
  fail_unless(res == 0, "Failed to resolve '%s': %s", fsio_link_path,
    strerror(errno));

  (void) unlink(fsio_link_path);
}
END_TEST

START_TEST (fs_use_encoding_test) {
  int res;

  res = pr_fs_use_encoding(-1);
  fail_unless(res < 0, "Failed to handle invalid setting");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fs_use_encoding(TRUE);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);

  res = pr_fs_use_encoding(FALSE);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);

  res = pr_fs_use_encoding(TRUE);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);
}
END_TEST

START_TEST (fs_decode_path2_test) {
  int flags = 0;
  char junk[32], *res;
  const char *path;

  res = pr_fs_decode_path(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fs_decode_path(p, NULL);
  fail_unless(res == NULL, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/tmp";
  res = pr_fs_decode_path2(p, path, flags);
  fail_unless(res != NULL, "Failed to decode path '%s': %s", path,
    strerror(errno));

  path = "/tmp";
  res = pr_fs_decode_path2(p, path, flags);
  fail_unless(res != NULL, "Failed to decode path '%s': %s", path,
    strerror(errno));

  /* Test a path that cannot be decoded, using junk data from the stack */
  junk[sizeof(junk)-1] = '\0';
  path = junk;
  res = pr_fs_decode_path2(p, path, flags);
  fail_unless(res != NULL, "Failed to decode path: %s", strerror(errno));

  /* XXX Use the FSIO_DECODE_FL_TELL_ERRORS flags, AND set the encode
   * policy to use PR_ENCODE_POLICY_FL_REQUIRE_VALID_ENCODING.
   */
}
END_TEST

START_TEST (fs_encode_path_test) {
  char junk[32], *res;
  const char *path;

  res = pr_fs_encode_path(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fs_encode_path(p, NULL);
  fail_unless(res == NULL, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/tmp";
  res = pr_fs_encode_path(p, path);
  fail_unless(res != NULL, "Failed to encode path '%s': %s", path,
    strerror(errno));

  /* Test a path that cannot be encoded, using junk data from the stack */
  junk[sizeof(junk)-1] = '\0';
  path = junk;
  res = pr_fs_encode_path(p, path);
  fail_unless(res != NULL, "Failed to encode path: %s", strerror(errno));
}
END_TEST

START_TEST (fs_split_path_test) {
  array_header *res;
  const char *path, *elt;

  mark_point();
  res = pr_fs_split_path(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_fs_split_path(p, NULL);
  fail_unless(res == NULL, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "";

  mark_point();
  res = pr_fs_split_path(p, path);
  fail_unless(res == NULL, "Failed to handle empty path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/";

  mark_point();
  res = pr_fs_split_path(p, path);
  fail_unless(res != NULL, "Failed to split path '%s': %s", path,
    strerror(errno));
  fail_unless(res->nelts == 1, "Expected 1, got %u", res->nelts);
  elt = ((char **) res->elts)[0];
  fail_unless(strcmp(elt, "/") == 0, "Expected '/', got '%s'", elt);

  path = "///";

  mark_point();
  res = pr_fs_split_path(p, path);
  fail_unless(res != NULL, "Failed to split path '%s': %s", path,
    strerror(errno));
  fail_unless(res->nelts == 1, "Expected 1, got %u", res->nelts);
  elt = ((char **) res->elts)[0];
  fail_unless(strcmp(elt, "/") == 0, "Expected '/', got '%s'", elt);

  path = "/foo/bar/baz/";

  mark_point();
  res = pr_fs_split_path(p, path);
  fail_unless(res != NULL, "Failed to split path '%s': %s", path,
    strerror(errno));
  fail_unless(res->nelts == 4, "Expected 4, got %u", res->nelts);
  elt = ((char **) res->elts)[0];
  fail_unless(strcmp(elt, "/") == 0, "Expected '/', got '%s'", elt);
  elt = ((char **) res->elts)[1];
  fail_unless(strcmp(elt, "foo") == 0, "Expected 'foo', got '%s'", elt);
  elt = ((char **) res->elts)[2];
  fail_unless(strcmp(elt, "bar") == 0, "Expected 'bar', got '%s'", elt);
  elt = ((char **) res->elts)[3];
  fail_unless(strcmp(elt, "baz") == 0, "Expected 'baz', got '%s'", elt);

  path = "/foo//bar//baz//";

  mark_point();
  res = pr_fs_split_path(p, path);
  fail_unless(res != NULL, "Failed to split path '%s': %s", path,
    strerror(errno));
  fail_unless(res->nelts == 4, "Expected 4, got %u", res->nelts);
  elt = ((char **) res->elts)[0];
  fail_unless(strcmp(elt, "/") == 0, "Expected '/', got '%s'", elt);
  elt = ((char **) res->elts)[1];
  fail_unless(strcmp(elt, "foo") == 0, "Expected 'foo', got '%s'", elt);
  elt = ((char **) res->elts)[2];
  fail_unless(strcmp(elt, "bar") == 0, "Expected 'bar', got '%s'", elt);
  elt = ((char **) res->elts)[3];
  fail_unless(strcmp(elt, "baz") == 0, "Expected 'baz', got '%s'", elt);

  path = "/foo/bar/baz";

  mark_point();
  res = pr_fs_split_path(p, path);
  fail_unless(res != NULL, "Failed to split path '%s': %s", path,
    strerror(errno));
  fail_unless(res->nelts == 4, "Expected 4, got %u", res->nelts);
  elt = ((char **) res->elts)[0];
  fail_unless(strcmp(elt, "/") == 0, "Expected '/', got '%s'", elt);
  elt = ((char **) res->elts)[1];
  fail_unless(strcmp(elt, "foo") == 0, "Expected 'foo', got '%s'", elt);
  elt = ((char **) res->elts)[2];
  fail_unless(strcmp(elt, "bar") == 0, "Expected 'bar', got '%s'", elt);
  elt = ((char **) res->elts)[3];
  fail_unless(strcmp(elt, "baz") == 0, "Expected 'baz', got '%s'", elt);

  path = "foo/bar/baz";

  mark_point();
  res = pr_fs_split_path(p, path);
  fail_unless(res != NULL, "Failed to split path '%s': %s", path,
    strerror(errno));
  fail_unless(res->nelts == 3, "Expected 3, got %u", res->nelts);
  elt = ((char **) res->elts)[0];
  fail_unless(strcmp(elt, "foo") == 0, "Expected 'foo', got '%s'", elt);
  elt = ((char **) res->elts)[1];
  fail_unless(strcmp(elt, "bar") == 0, "Expected 'bar', got '%s'", elt);
  elt = ((char **) res->elts)[2];
  fail_unless(strcmp(elt, "baz") == 0, "Expected 'baz', got '%s'", elt);
}
END_TEST

START_TEST (fs_join_path_test) {
  char *path;
  array_header *components;

  mark_point();
  path = pr_fs_join_path(NULL, NULL, 0);
  fail_unless(path == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  path = pr_fs_join_path(p, NULL, 0);
  fail_unless(path == NULL, "Failed to handle null components");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  components = make_array(p, 0, sizeof(char **));

  mark_point();
  path = pr_fs_join_path(p, components, 0);
  fail_unless(path == NULL, "Failed to handle empty components");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  *((char **) push_array(components)) = pstrdup(p, "/");

  mark_point();
  path = pr_fs_join_path(p, components, 0);
  fail_unless(path == NULL, "Failed to handle empty count");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  path = pr_fs_join_path(p, components, 3);
  fail_unless(path == NULL, "Failed to handle invalid count");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  path = pr_fs_join_path(p, components, 1);
  fail_unless(path != NULL, "Failed to join path: %s", strerror(errno));
  fail_unless(strcmp(path, "/") == 0, "Expected '/', got '%s'", path);

  *((char **) push_array(components)) = pstrdup(p, "foo");
  *((char **) push_array(components)) = pstrdup(p, "bar");
  *((char **) push_array(components)) = pstrdup(p, "baz");

  mark_point();
  path = pr_fs_join_path(p, components, 4);
  fail_unless(path != NULL, "Failed to join path: %s", strerror(errno));
  fail_unless(strcmp(path, "/foo/bar/baz") == 0,
    "Expected '/foo/bar/baz', got '%s'", path);

  mark_point();
  path = pr_fs_join_path(p, components, 3);
  fail_unless(path != NULL, "Failed to join path: %s", strerror(errno));
  fail_unless(strcmp(path, "/foo/bar") == 0, "Expected '/foo/bar', got '%s'",
    path);
}
END_TEST

START_TEST (fs_virtual_path_test) {
  const char *path;
  char buf[PR_TUNABLE_PATH_MAX];

  mark_point();
  pr_fs_virtual_path(NULL, NULL, 0);

  mark_point();
  path = "/tmp";
  pr_fs_virtual_path(path, NULL, 0);

  mark_point();
  memset(buf, '\0', sizeof(buf));
  pr_fs_virtual_path(path, buf, 0);
  fail_unless(*buf == '\0', "Expected empty buffer, got '%s'", buf);

  mark_point();
  memset(buf, '\0', sizeof(buf));
  pr_fs_virtual_path(path, buf, sizeof(buf)-1);
  fail_unless(strcmp(buf, path) == 0, "Expected '%s', got '%s'", path, buf);

  mark_point();
  memset(buf, '\0', sizeof(buf));
  path = "tmp";
  pr_fs_virtual_path(path, buf, sizeof(buf)-1);
  fail_unless(strcmp(buf, "/tmp") == 0, "Expected '/tmp', got '%s'", path, buf);

  mark_point();
  memset(buf, '\0', sizeof(buf));
  path = "/tmp/././";
  pr_fs_virtual_path(path, buf, sizeof(buf)-1);
  fail_unless(strcmp(buf, "/tmp") == 0 || strcmp(buf, "/tmp/") == 0,
    "Expected '/tmp', got '%s'", path, buf);

  mark_point();
  memset(buf, '\0', sizeof(buf));
  path = "tmp/../../";
  pr_fs_virtual_path(path, buf, sizeof(buf)-1);
  fail_unless(strcmp(buf, "/") == 0, "Expected '/', got '%s'", path, buf);
}
END_TEST

#if 0
/* This test is commented out, since libcheck is very unhappy when we
 * close its logging fds out from underneath it.  Thus we keep this
 * test here, for any future tinkering, just not enabled by default.
 */
START_TEST (fs_close_extra_fds_test) {
  mark_point();
  pr_fs_close_extra_fds();
}
END_TEST
#endif

START_TEST (fs_get_usable_fd_test) {
  int fd, res;

  fd = -1;
  res = pr_fs_get_usable_fd(fd);
  fail_unless(res < 0, "Failed to handle bad fd");
  fail_unless(errno == EBADF || errno == EINVAL,
    "Expected EBADF (%d) or EINVAL (%d), got %s (%d)", EBADF, EINVAL,
    strerror(errno), errno);

  fd = STDERR_FILENO + 1;
  res = pr_fs_get_usable_fd(fd);
  fail_unless(res == fd, "Expected %d, got %d", fd, res);

  fd = STDERR_FILENO - 1;
  res = pr_fs_get_usable_fd(fd);
  fail_unless(res > STDERR_FILENO, "Failed to get usable fd for %d: %s", fd,
    strerror(errno));
  (void) close(res);
}
END_TEST

START_TEST (fs_get_usable_fd2_test) {
  int fd, res;

  res = pr_fs_get_usable_fd2(NULL);
  fail_unless(res < 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fd = -1;
  res = pr_fs_get_usable_fd2(&fd);
  fail_unless(res < 0, "Failed to handle bad fd");
  fail_unless(errno == EBADF || errno == EINVAL,
    "Expected EBADF (%d) or EINVAL (%d), got %s (%d)", EBADF, EINVAL,
    strerror(errno), errno);

  fd = STDERR_FILENO + 1;
  res = pr_fs_get_usable_fd2(&fd);
  fail_unless(res == 0, "Failed to handle fd: %s", strerror(errno));
  fail_unless(fd == (STDERR_FILENO + 1), "Expected %d, got %d",
    STDERR_FILENO + 1, fd);

  fd = STDERR_FILENO - 1;
  res = pr_fs_get_usable_fd2(&fd);
  fail_unless(res == 0, "Failed to handle fd: %s", strerror(errno));
  fail_unless(fd > STDERR_FILENO, "Expected >%d, got %d", STDERR_FILENO, fd);
  (void) close(fd);
}
END_TEST

START_TEST (fs_getsize_test) {
  off_t res;
  char *path;

  res = pr_fs_getsize(NULL);
  fail_unless(res == (off_t) -1, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/tmp";
  res = pr_fs_getsize(path);
  fail_unless(res != (off_t) -1, "Failed to get fs size for '%s': %s", path,
    strerror(errno));
}
END_TEST

START_TEST (fs_getsize2_test) {
  int res;
  char *path;
  off_t sz = 0;

  res = pr_fs_getsize2(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/tmp";
  res = pr_fs_getsize2(path, NULL);
  fail_unless(res < 0, "Failed to handle null size argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fs_getsize2(path, &sz);
  fail_unless(res == 0, "Failed to get fs size for '%s': %s", path,
    strerror(errno));
}
END_TEST

START_TEST (fs_fgetsize_test) {
  int fd = -1, res;
  off_t fs_sz = 0;

  mark_point();
  res = pr_fs_fgetsize(fd, &fs_sz);
  fail_unless(res < 0, "Failed to handle bad file descriptor");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  mark_point();
  fd = 0;
  fs_sz = 0;
  res = pr_fs_fgetsize(fd, NULL);
  fail_unless(res < 0, "Failed to handle null size argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  fd = 0;
  fs_sz = 0;
  res = pr_fs_fgetsize(fd, &fs_sz);
  fail_unless(res == 0, "Failed to get fs size for fd %d: %s", fd,
    strerror(errno));
}
END_TEST

START_TEST (fs_fadvise_test) {
  int advice, fd = -1;
  off_t off = 0, len = 0;

  /* We make these function calls to exercise the code paths, even
   * though there's no good way to verify the behavior changed.
   */

  advice = PR_FS_FADVISE_NORMAL;
  pr_fs_fadvise(fd, off, len, advice);

  advice = PR_FS_FADVISE_RANDOM;
  pr_fs_fadvise(fd, off, len, advice);

  advice = PR_FS_FADVISE_SEQUENTIAL;
  pr_fs_fadvise(fd, off, len, advice);

  advice = PR_FS_FADVISE_WILLNEED;
  pr_fs_fadvise(fd, off, len, advice);

  advice = PR_FS_FADVISE_DONTNEED;
  pr_fs_fadvise(fd, off, len, advice);

  advice = PR_FS_FADVISE_NOREUSE;
  pr_fs_fadvise(fd, off, len, advice);
}
END_TEST

START_TEST (fs_have_access_test) {
  int res;
  struct stat st;
  uid_t uid;
  gid_t gid;
  array_header *suppl_gids;

  mark_point();
  res = pr_fs_have_access(NULL, R_OK, 0, 0, NULL);
  fail_unless(res < 0, "Failed to handle null stat");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  memset(&st, 0, sizeof(struct stat));

  mark_point();
  res = pr_fs_have_access(&st, R_OK, 0, 0, NULL);
  fail_unless(res == 0, "Failed to handle root access: %s", strerror(errno));

  /* Use cases: no matching UID or GID; R_OK, W_OK, X_OK. */
  memset(&st, 0, sizeof(struct stat));
  uid = 1;
  gid = 1;

  mark_point();
  res = pr_fs_have_access(&st, R_OK, uid, gid, NULL);
  fail_unless(res < 0, "Failed to handle missing other R_OK access");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  mark_point();
  res = pr_fs_have_access(&st, W_OK, uid, gid, NULL);
  fail_unless(res < 0, "Failed to handle missing other W_OK access");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  mark_point();
  res = pr_fs_have_access(&st, X_OK, uid, gid, NULL);
  fail_unless(res < 0, "Failed to handle missing other X_OK access");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  st.st_mode = S_IFMT|S_IROTH|S_IWOTH|S_IXOTH;

  mark_point();
  res = pr_fs_have_access(&st, R_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to handle other R_OK access: %s",
    strerror(errno));

  mark_point();
  res = pr_fs_have_access(&st, W_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to handle other W_OK access: %s",
    strerror(errno));

  mark_point();
  res = pr_fs_have_access(&st, X_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to handle other X_OK access: %s",
    strerror(errno));

  /* Use cases: matching UID, not GID; R_OK, W_OK, X_OK. */
  memset(&st, 0, sizeof(struct stat));

  st.st_uid = uid;

  mark_point();
  res = pr_fs_have_access(&st, R_OK, uid, gid, NULL);
  fail_unless(res < 0, "Failed to handle missing user R_OK access");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  mark_point();
  res = pr_fs_have_access(&st, W_OK, uid, gid, NULL);
  fail_unless(res < 0, "Failed to handle missing user W_OK access");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  mark_point();
  res = pr_fs_have_access(&st, X_OK, uid, gid, NULL);
  fail_unless(res < 0, "Failed to handle missing user X_OK access");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  st.st_mode = S_IFMT|S_IRUSR|S_IWUSR|S_IXUSR;

  mark_point();
  res = pr_fs_have_access(&st, R_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to handle user R_OK access: %s",
    strerror(errno));

  mark_point();
  res = pr_fs_have_access(&st, W_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to handle user W_OK access: %s",
    strerror(errno));

  mark_point();
  res = pr_fs_have_access(&st, X_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to handle user X_OK access: %s",
    strerror(errno));

  /* Use cases: matching GID, not UID; R_OK, W_OK, X_OK. */
  memset(&st, 0, sizeof(struct stat));

  st.st_gid = gid;

  mark_point();
  res = pr_fs_have_access(&st, R_OK, uid, gid, NULL);
  fail_unless(res < 0, "Failed to handle missing group R_OK access");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  mark_point();
  res = pr_fs_have_access(&st, W_OK, uid, gid, NULL);
  fail_unless(res < 0, "Failed to handle missing group W_OK access");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  mark_point();
  res = pr_fs_have_access(&st, X_OK, uid, gid, NULL);
  fail_unless(res < 0, "Failed to handle missing group X_OK access");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  st.st_mode = S_IFMT|S_IRGRP|S_IWGRP|S_IXGRP;

  mark_point();
  res = pr_fs_have_access(&st, R_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to handle group R_OK access: %s",
    strerror(errno));

  mark_point();
  res = pr_fs_have_access(&st, W_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to handle group W_OK access: %s",
    strerror(errno));

  mark_point();
  res = pr_fs_have_access(&st, X_OK, uid, gid, NULL);
  fail_unless(res == 0, "Failed to handle group X_OK access: %s",
    strerror(errno));

  /* Use cases: matching suppl GID, not UID; R_OK, W_OK, X_OK. */
  memset(&st, 0, sizeof(struct stat));

  suppl_gids = make_array(p, 1, sizeof(gid_t));
  *((gid_t *) push_array(suppl_gids)) = 100;
  *((gid_t *) push_array(suppl_gids)) = gid;
  st.st_gid = gid;

  mark_point();
  res = pr_fs_have_access(&st, R_OK, uid, 0, suppl_gids);
  fail_unless(res < 0, "Failed to handle missing group R_OK access");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  mark_point();
  res = pr_fs_have_access(&st, W_OK, uid, 0, suppl_gids);
  fail_unless(res < 0, "Failed to handle missing group W_OK access");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  mark_point();
  res = pr_fs_have_access(&st, X_OK, uid, 0, suppl_gids);
  fail_unless(res < 0, "Failed to handle missing group X_OK access");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  st.st_mode = S_IFMT|S_IRGRP|S_IWGRP|S_IXGRP;

  mark_point();
  res = pr_fs_have_access(&st, R_OK, uid, 0, suppl_gids);
  fail_unless(res == 0, "Failed to handle group R_OK access: %s",
    strerror(errno));

  mark_point();
  res = pr_fs_have_access(&st, W_OK, uid, 0, suppl_gids);
  fail_unless(res == 0, "Failed to handle group W_OK access: %s",
    strerror(errno));

  mark_point();
  res = pr_fs_have_access(&st, X_OK, uid, 0, suppl_gids);
  fail_unless(res == 0, "Failed to handle group X_OK access: %s",
    strerror(errno));
}
END_TEST

START_TEST (fs_is_nfs_test) {
  int res;

  res = pr_fs_is_nfs(NULL);
  fail_unless(res < 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fs_is_nfs("/tmp");
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);
}
END_TEST

START_TEST (fs_valid_path_test) {
  int res;
  const char *path;
  pr_fs_t *fs;

  res = pr_fs_valid_path(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/";
  res = pr_fs_valid_path(path);
  fail_unless(res == 0, "'%s' is not a valid path: %s", path, strerror(errno));

  path = ":tmp";
  res = pr_fs_valid_path(path);
  fail_unless(res < 0, "Failed to handle invalid path");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  fs = pr_register_fs(p, "testsuite", "&");
  fail_unless(fs != NULL, "Failed to register FS: %s", strerror(errno));

  fs = pr_register_fs(p, "testsuite2", ":");
  fail_unless(fs != NULL, "Failed to register FS: %s", strerror(errno));

  res = pr_fs_valid_path(path);
  fail_unless(res == 0, "Failed to handle valid path: %s", strerror(errno));

  (void) pr_remove_fs("/testsuite2");
  (void) pr_remove_fs("/testsuite");
}
END_TEST

START_TEST (fsio_smkdir_test) {
  int res;
  const char *path;
  mode_t mode = 0755;
  uid_t uid = getuid();
  gid_t gid = getgid();

  res = pr_fsio_smkdir(NULL, NULL, mode, uid, gid);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_smkdir(p, NULL, mode, uid, gid);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = fsio_testdir_path;
  res = pr_fsio_smkdir(p, path, mode, uid, gid);
  fail_unless(res == 0, "Failed to securely create '%s': %s", fsio_testdir_path,
    strerror(errno));
  (void) pr_fsio_rmdir(fsio_testdir_path);

  res = pr_fsio_set_use_mkdtemp(-1);
  fail_unless(res < 0, "Failed to handle invalid setting");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

#ifdef HAVE_MKDTEMP
  res = pr_fsio_set_use_mkdtemp(FALSE);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);

  res = pr_fsio_smkdir(p, path, mode, uid, gid);
  fail_unless(res == 0, "Failed to securely create '%s': %s", fsio_testdir_path,
    strerror(errno));
  (void) pr_fsio_rmdir(fsio_testdir_path);

  res = pr_fsio_set_use_mkdtemp(TRUE);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);
#else
  res = pr_fsio_set_use_mkdtemp(TRUE);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);

  res = pr_fsio_set_use_mkdtemp(FALSE);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);
#endif /* HAVE_MKDTEMP */

  (void) pr_fsio_rmdir(fsio_testdir_path);
}
END_TEST

START_TEST (fsio_getpipebuf_test) {
  char *res;
  int fd = -1;
  long bufsz = 0;

  res = pr_fsio_getpipebuf(NULL, fd, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_getpipebuf(p, fd, NULL);
  fail_unless(res == NULL, "Failed to handle bad file descriptor");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  fd = 0;
  res = pr_fsio_getpipebuf(p, fd, NULL);
  fail_unless(res != NULL, "Failed to get pipebuf for fd %d: %s", fd,
    strerror(errno));

  res = pr_fsio_getpipebuf(p, fd, &bufsz);
  fail_unless(res != NULL, "Failed to get pipebuf for fd %d: %s", fd,
    strerror(errno));
  fail_unless(bufsz > 0, "Expected >0, got %ld", bufsz);
}
END_TEST

START_TEST (fsio_gets_test) {
  char buf[PR_TUNABLE_PATH_MAX], *res, *text;
  pr_fh_t *fh;
  int res2;

  res = pr_fsio_gets(NULL, 0, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_gets(buf, 0, NULL);
  fail_unless(res == NULL, "Failed to handle null file handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_RDWR);
  fail_unless(fh != NULL, "Failed to open '%s': %s", fsio_test_path,
    strerror(errno));

  res = pr_fsio_gets(buf, 0, fh);
  fail_unless(res == NULL, "Failed to handle zero buffer length");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text = "Hello, World!\n";
  res2 = pr_fsio_puts(text, fh);
  fail_if(res2 < 0, "Error writing to '%s': %s", fsio_test_path,
    strerror(errno));
  pr_fsio_fsync(fh);
  pr_fsio_lseek(fh, 0, SEEK_SET);

  memset(buf, '\0', sizeof(buf));
  res = pr_fsio_gets(buf, sizeof(buf)-1, fh);
  fail_if(res == NULL, "Failed reading from '%s': %s", fsio_test_path,
    strerror(errno));
  fail_unless(strcmp(res, text) == 0, "Expected '%s', got '%s'", text, res);

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_getline_test) {
  char buf[PR_TUNABLE_PATH_MAX], *res, *text;
  pr_fh_t *fh;
  unsigned int lineno = 0;
  int res2;

  res = pr_fsio_getline(NULL, 0, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_getline(buf, 0, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle file handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_RDWR);
  fail_unless(fh != NULL, "Failed to open '%s': %s", fsio_test_path,
    strerror(errno));

  res = pr_fsio_getline(buf, 0, fh, NULL);
  fail_unless(res == NULL, "Failed to handle zero buffer length");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_fsio_getline(buf, sizeof(buf)-1, fh, &lineno);
  fail_unless(res == NULL, "Failed to read empty '%s' file", fsio_test_path);

  text = "Hello, World!\n";
  res2 = pr_fsio_puts(text, fh);
  fail_if(res2 < 0, "Error writing to '%s': %s", fsio_test_path,
    strerror(errno));

  text = "How\\\n are you?\n";
  res2 = pr_fsio_puts(text, fh);
  fail_if(res2 < 0, "Error writing to '%s': %s", fsio_test_path,
    strerror(errno));

  pr_fsio_fsync(fh);
  pr_fsio_lseek(fh, 0, SEEK_SET);

  memset(buf, '\0', sizeof(buf));
  res = pr_fsio_getline(buf, sizeof(buf)-1, fh, &lineno);
  fail_if(res == NULL, "Failed to read line from '%s': %s", fsio_test_path,
    strerror(errno));
  fail_unless(strcmp(res, "Hello, World!\n") == 0,
    "Expected 'Hello, World!\n', got '%s'", res);
  fail_unless(lineno == 1, "Expected 1, got %u", lineno);

  memset(buf, '\0', sizeof(buf));
  res = pr_fsio_getline(buf, sizeof(buf)-1, fh, &lineno);
  fail_if(res == NULL, "Failed to read line from '%s': %s", fsio_test_path,
    strerror(errno));
  fail_unless(strcmp(res, "How are you?\n") == 0,
    "Expected 'How are you?\n', got '%s'", res);
  fail_unless(lineno == 3, "Expected 3, got %u", lineno);

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_puts_test) {
  int res;
  const char *text;
  pr_fh_t *fh;

  res = pr_fsio_puts(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text = "Hello, World!\n";
  res = pr_fsio_puts(text, NULL);
  fail_unless(res < 0, "Failed to handle null file handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to open '%s': %s", fsio_test_path,
    strerror(errno));

  res = pr_fsio_puts(NULL, fh);
  fail_unless(res < 0, "Failed to handle null buffer");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

START_TEST (fsio_blocking_test) {
  int fd, res;
  pr_fh_t *fh;

  res = pr_fsio_set_block(NULL);
  fail_unless(res < 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open(fsio_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to open '%s': %s", fsio_test_path,
    strerror(errno));

  fd = fh->fh_fd;
  fh->fh_fd = -1;

  res = pr_fsio_set_block(fh);
  fail_unless(res < 0, "Failed to handle bad file descriptor");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  fh->fh_fd = fd;
  res = pr_fsio_set_block(fh);
  fail_unless(res == 0, "Failed to make '%s' blocking: %s", fsio_test_path,
    strerror(errno));

  (void) pr_fsio_close(fh);
  (void) pr_fsio_unlink(fsio_test_path);
}
END_TEST

Suite *tests_get_fsio_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("fsio");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  /* Main FSIO API tests */
  tcase_add_test(testcase, fsio_sys_open_test);
  tcase_add_test(testcase, fsio_sys_open_canon_test);
  tcase_add_test(testcase, fsio_sys_open_chroot_guard_test);
  tcase_add_test(testcase, fsio_sys_close_test);
  tcase_add_test(testcase, fsio_sys_unlink_test);
  tcase_add_test(testcase, fsio_sys_unlink_chroot_guard_test);
  tcase_add_test(testcase, fsio_sys_stat_test);
  tcase_add_test(testcase, fsio_sys_fstat_test);
  tcase_add_test(testcase, fsio_sys_read_test);
  tcase_add_test(testcase, fsio_sys_write_test);
  tcase_add_test(testcase, fsio_sys_lseek_test);
  tcase_add_test(testcase, fsio_sys_link_test);
  tcase_add_test(testcase, fsio_sys_link_chroot_guard_test);
  tcase_add_test(testcase, fsio_sys_symlink_test);
  tcase_add_test(testcase, fsio_sys_symlink_chroot_guard_test);
  tcase_add_test(testcase, fsio_sys_readlink_test);
  tcase_add_test(testcase, fsio_sys_lstat_test);
  tcase_add_test(testcase, fsio_sys_access_dir_test);
  tcase_add_test(testcase, fsio_sys_access_file_test);
  tcase_add_test(testcase, fsio_sys_faccess_test);
  tcase_add_test(testcase, fsio_sys_truncate_test);
  tcase_add_test(testcase, fsio_sys_truncate_chroot_guard_test);
  tcase_add_test(testcase, fsio_sys_ftruncate_test);
  tcase_add_test(testcase, fsio_sys_chmod_test);
  tcase_add_test(testcase, fsio_sys_chmod_chroot_guard_test);
  tcase_add_test(testcase, fsio_sys_fchmod_test);
  tcase_add_test(testcase, fsio_sys_chown_test);
  tcase_add_test(testcase, fsio_sys_chown_chroot_guard_test);
  tcase_add_test(testcase, fsio_sys_fchown_test);
  tcase_add_test(testcase, fsio_sys_lchown_test);
  tcase_add_test(testcase, fsio_sys_lchown_chroot_guard_test);
  tcase_add_test(testcase, fsio_sys_rename_test);
  tcase_add_test(testcase, fsio_sys_rename_chroot_guard_test);
  tcase_add_test(testcase, fsio_sys_utimes_test);
  tcase_add_test(testcase, fsio_sys_utimes_chroot_guard_test);
  tcase_add_test(testcase, fsio_sys_futimes_test);
  tcase_add_test(testcase, fsio_sys_fsync_test);

  /* Extended attribute tests */
  tcase_add_test(testcase, fsio_sys_getxattr_test);
  tcase_add_test(testcase, fsio_sys_lgetxattr_test);
  tcase_add_test(testcase, fsio_sys_fgetxattr_test);
  tcase_add_test(testcase, fsio_sys_listxattr_test);
  tcase_add_test(testcase, fsio_sys_llistxattr_test);
  tcase_add_test(testcase, fsio_sys_flistxattr_test);
  tcase_add_test(testcase, fsio_sys_removexattr_test);
  tcase_add_test(testcase, fsio_sys_lremovexattr_test);
  tcase_add_test(testcase, fsio_sys_fremovexattr_test);
  tcase_add_test(testcase, fsio_sys_setxattr_test);
  tcase_add_test(testcase, fsio_sys_lsetxattr_test);
  tcase_add_test(testcase, fsio_sys_fsetxattr_test);

  tcase_add_test(testcase, fsio_sys_mkdir_test);
  tcase_add_test(testcase, fsio_sys_mkdir_chroot_guard_test);
  tcase_add_test(testcase, fsio_sys_rmdir_test);
  tcase_add_test(testcase, fsio_sys_rmdir_chroot_guard_test);
  tcase_add_test(testcase, fsio_sys_chdir_test);
  tcase_add_test(testcase, fsio_sys_chdir_canon_test);
  tcase_add_test(testcase, fsio_sys_chroot_test);
  tcase_add_test(testcase, fsio_sys_opendir_test);
  tcase_add_test(testcase, fsio_sys_readdir_test);
  tcase_add_test(testcase, fsio_sys_closedir_test);

  /* FSIO with error tests */
  tcase_add_test(testcase, fsio_sys_chmod_with_error_test);
  tcase_add_test(testcase, fsio_sys_chown_with_error_test);
  tcase_add_test(testcase, fsio_sys_chroot_with_error_test);
  tcase_add_test(testcase, fsio_sys_close_with_error_test);
  tcase_add_test(testcase, fsio_sys_fchmod_with_error_test);
  tcase_add_test(testcase, fsio_sys_fchown_with_error_test);
  tcase_add_test(testcase, fsio_sys_lchown_with_error_test);
  tcase_add_test(testcase, fsio_sys_lstat_with_error_test);
  tcase_add_test(testcase, fsio_sys_mkdir_with_error_test);
  tcase_add_test(testcase, fsio_sys_open_with_error_test);
  tcase_add_test(testcase, fsio_sys_read_with_error_test);
  tcase_add_test(testcase, fsio_sys_rename_with_error_test);
  tcase_add_test(testcase, fsio_sys_rmdir_with_error_test);
  tcase_add_test(testcase, fsio_sys_stat_with_error_test);
  tcase_add_test(testcase, fsio_sys_unlink_with_error_test);
  tcase_add_test(testcase, fsio_sys_write_with_error_test);

  /* FSIO statcache tests */
  tcase_add_test(testcase, fsio_statcache_clear_cache_test);
  tcase_add_test(testcase, fsio_statcache_cache_hit_test);
  tcase_add_test(testcase, fsio_statcache_negative_cache_test);
  tcase_add_test(testcase, fsio_statcache_expired_test);
  tcase_add_test(testcase, fsio_statcache_dump_test);

  /* Custom FSIO management tests */
  tcase_add_test(testcase, fs_create_fs_test);
  tcase_add_test(testcase, fs_insert_fs_test);
  tcase_add_test(testcase, fs_get_fs_test);
  tcase_add_test(testcase, fs_unmount_fs_test);
  tcase_add_test(testcase, fs_remove_fs_test);
  tcase_add_test(testcase, fs_register_fs_test);
  tcase_add_test(testcase, fs_unregister_fs_test);
  tcase_add_test(testcase, fs_resolve_fs_map_test);
#if defined(PR_USE_DEVEL)
  tcase_add_test(testcase, fs_dump_fs_test);
#endif /* PR_USE_DEVEL */

  /* Custom FSIO tests */
  tcase_add_test(testcase, fsio_custom_chroot_test);

  /* Misc */
  tcase_add_test(testcase, fs_clean_path_test);
  tcase_add_test(testcase, fs_clean_path2_test);

  tcase_add_test(testcase, fs_dircat_test);
  tcase_add_test(testcase, fs_setcwd_test);
  tcase_add_test(testcase, fs_glob_test);
  tcase_add_test(testcase, fs_copy_file_test);
  tcase_add_test(testcase, fs_copy_file2_test);
  tcase_add_test(testcase, fs_interpolate_test);
  tcase_add_test(testcase, fs_resolve_partial_test);
  tcase_add_test(testcase, fs_resolve_path_test);
  tcase_add_test(testcase, fs_use_encoding_test);
  tcase_add_test(testcase, fs_decode_path2_test);
  tcase_add_test(testcase, fs_encode_path_test);
  tcase_add_test(testcase, fs_split_path_test);
  tcase_add_test(testcase, fs_join_path_test);
  tcase_add_test(testcase, fs_virtual_path_test);
#if 0
  tcase_add_test(testcase, fs_close_extra_fds_test);
#endif
  tcase_add_test(testcase, fs_get_usable_fd_test);
  tcase_add_test(testcase, fs_get_usable_fd2_test);
  tcase_add_test(testcase, fs_getsize_test);
  tcase_add_test(testcase, fs_getsize2_test);
  tcase_add_test(testcase, fs_fgetsize_test);
  tcase_add_test(testcase, fs_fadvise_test);
  tcase_add_test(testcase, fs_have_access_test);
#if defined(HAVE_STATFS_F_TYPE) || defined(HAVE_STATFS_F_FSTYPENAME)
  tcase_add_test(testcase, fs_is_nfs_test);
#endif
  tcase_add_test(testcase, fs_valid_path_test);
  tcase_add_test(testcase, fsio_smkdir_test);
  tcase_add_test(testcase, fsio_getpipebuf_test);
  tcase_add_test(testcase, fsio_gets_test);
  tcase_add_test(testcase, fsio_getline_test);
  tcase_add_test(testcase, fsio_puts_test);
  tcase_add_test(testcase, fsio_blocking_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
