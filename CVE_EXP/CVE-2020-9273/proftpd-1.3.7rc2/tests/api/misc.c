/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2015-2018 The ProFTPD Project team
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

/* Miscellaneous tests
 */

#include "tests.h"

static pool *p = NULL;

static unsigned int schedule_called = 0;
static const char *misc_test_shutmsg = "/tmp/prt-shutmsg.dat";
static const char *misc_test_readlink = "/tmp/prt-readlink.lnk";
static const char *misc_test_readlink2_dir = "/tmp/prt-readlink/";
static const char *misc_test_readlink2 = "/tmp/prt-readlink/test.lnk";

/* Fixtures */

static void set_up(void) {
  (void) unlink(misc_test_readlink);
  (void) unlink(misc_test_readlink2);
  (void) unlink(misc_test_shutmsg);
  (void) rmdir(misc_test_readlink2_dir);

  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_fs();
  pr_fs_statcache_set_policy(PR_TUNABLE_FS_STATCACHE_SIZE,
    PR_TUNABLE_FS_STATCACHE_MAX_AGE, 0);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("auth", 1, 20);
    pr_trace_set_levels("fsio", 1, 20);
    pr_trace_set_levels("fs.statcache", 1, 20);
  }

  schedule_called = 0;
  session.user = NULL;
}

static void tear_down(void) {
  (void) unlink(misc_test_readlink);
  (void) unlink(misc_test_readlink2);
  (void) unlink(misc_test_shutmsg);
  (void) rmdir(misc_test_readlink2_dir);

  pr_fs_statcache_set_policy(PR_TUNABLE_FS_STATCACHE_SIZE,
    PR_TUNABLE_FS_STATCACHE_MAX_AGE, 0);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("auth", 0, 0);
    pr_trace_set_levels("fsio", 0, 0);
    pr_trace_set_levels("fs.statcache", 0, 0);
  }

  session.user = NULL;

  if (p) {
    destroy_pool(p);
    p = session.pool = permanent_pool = NULL;
  }
}

static void schedule_cb(void *arg1, void *arg2, void *arg3, void *arg4) {
  schedule_called++;
}

/* Tests */

START_TEST (schedule_test) {
  mark_point();
  schedule(NULL, 0, NULL, NULL, NULL, NULL);

  mark_point();
  schedule(schedule_cb, -1, NULL, NULL, NULL, NULL);

  mark_point();
  run_schedule();

  mark_point();
  schedule(schedule_cb, 0, NULL, NULL, NULL, NULL);

  run_schedule();
  fail_unless(schedule_called == 1, "Expected 1, got %u", schedule_called);

  run_schedule();
  fail_unless(schedule_called == 1, "Expected 1, got %u", schedule_called);

  mark_point();
  schedule(schedule_cb, 0, NULL, NULL, NULL, NULL);
  schedule(schedule_cb, 0, NULL, NULL, NULL, NULL);

  run_schedule();
  fail_unless(schedule_called == 3, "Expected 3, got %u", schedule_called);

  run_schedule();
  fail_unless(schedule_called == 3, "Expected 3, got %u", schedule_called);

  mark_point();

  /* Schedule this callback to run after 2 "loops", i.e. calls to
   * run_schedule().
   */
  schedule(schedule_cb, 2, NULL, NULL, NULL, NULL);

  run_schedule();
  fail_unless(schedule_called == 3, "Expected 3, got %u", schedule_called);

  run_schedule();
  fail_unless(schedule_called == 3, "Expected 3, got %u", schedule_called);

  run_schedule();
  fail_unless(schedule_called == 4, "Expected 4, got %u", schedule_called);
}
END_TEST

START_TEST (get_name_max_test) {
  long res;
  char *path;
  int fd;

  res = get_name_max(NULL, -1);
  fail_unless(res < 0, "Failed to handle invalid arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/";
  res = get_name_max(path, -1);
  fail_if(res < 0, "Failed to handle path '%s': %s", path, strerror(errno));

  fd = 1;
  res = get_name_max(NULL, fd);

  /* It seems that fpathconf(2) on some platforms will handle stdin as a
   * valid file descriptor, and some will not.
   */
  if (res < 0) {
    fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
      strerror(errno), errno);
  }
}
END_TEST

START_TEST (dir_interpolate_test) {
  char *res;
  const char *path;

  res = dir_interpolate(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = dir_interpolate(p, NULL);
  fail_unless(res == NULL, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  path = "/foo";
  res = dir_interpolate(p, path);
  fail_unless(path != NULL, "Failed to interpolate '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, path) == 0, "Expected '%s', got '%s'", path, res);

  mark_point();
  path = "~foo.bar.bar.quxx.quzz/foo";
  res = dir_interpolate(p, path);
  fail_unless(path != NULL, "Failed to interpolate '%s': %s", path,
    strerror(errno));
  fail_unless(*path == '~', "Interpolated path with unknown user unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);
}
END_TEST

START_TEST (dir_best_path_test) {
  char *res;
  const char *path;

  res = dir_best_path(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = dir_best_path(p, NULL);
  fail_unless(res == NULL, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  path = "/foo";
  res = dir_best_path(p, path);
  fail_unless(path != NULL, "Failed to get best path for '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, path) == 0, "Expected '%s', got '%s'", path, res);
}
END_TEST

START_TEST (dir_canonical_path_test) {
  char *res;
  const char *path;

  res = dir_canonical_path(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = dir_canonical_path(p, NULL);
  fail_unless(res == NULL, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  path = "/foo";
  res = dir_canonical_path(p, path);
  fail_unless(path != NULL, "Failed to get canonical path for '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, path) == 0, "Expected '%s', got '%s'", path, res);
}
END_TEST

START_TEST (dir_canonical_vpath_test) {
  char *res;
  const char *path;

  res = dir_canonical_vpath(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = dir_canonical_vpath(p, NULL);
  fail_unless(res == NULL, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  path = "/foo";
  res = dir_canonical_vpath(p, path);
  fail_unless(path != NULL, "Failed to get canonical vpath for '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, path) == 0, "Expected '%s', got '%s'", path, res);
}
END_TEST

START_TEST (dir_readlink_test) {
  int res, flags = 0;
  const char *path;
  char *buf, *dst_path, *expected_path;
  size_t bufsz, dst_pathlen, expected_pathlen;

  (void) unlink(misc_test_readlink);

  /* Parameter validation */
  res = dir_readlink(NULL, NULL, NULL, 0, flags);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = dir_readlink(p, NULL, NULL, 0, flags);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = misc_test_readlink;
  res = dir_readlink(p, path, NULL, 0, flags);
  fail_unless(res < 0, "Failed to handle null buffer");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  bufsz = 1024;
  buf = palloc(p, bufsz);
  res = dir_readlink(p, path, buf, 0, flags);
  fail_unless(res == 0, "Failed to handle zero buffer length");

  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_unless(res < 0, "Failed to handle nonexistent file");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  dst_path = "";
  res = symlink(dst_path, path);
  if (res == 0) {
    /* Some platforms will not allow creation of empty symlinks.  Nice of
     * them.
     */
    res = dir_readlink(p, path, buf, bufsz, flags);
    fail_unless(res == 0, "Failed to handle empty symlink");
  }

  /* Not chrooted, absolute dst path */
  memset(buf, '\0', bufsz);
  dst_path = "/home/user/file.dat";
  dst_pathlen = strlen(dst_path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == dst_pathlen, "Expected length %lu, got %d",
    (unsigned long) dst_pathlen, res);
  fail_unless(strcmp(buf, dst_path) == 0, "Expected '%s', got '%s'",
    dst_path, buf);

  /* Not chrooted, relative dst path, flags to ignore rel path */
  memset(buf, '\0', bufsz);
  dst_path = "./file.dat";
  dst_pathlen = strlen(dst_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == dst_pathlen, "Expected length %lu, got %d",
    (unsigned long) dst_pathlen, res);
  fail_unless(strcmp(buf, dst_path) == 0, "Expected '%s', got '%s'",
    dst_path, buf);

  /* Not chrooted, relative dst path without leading '.', flags to ignore rel
   * path.
   */
  memset(buf, '\0', bufsz);
  dst_path = "file.dat";
  dst_pathlen = strlen(dst_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == dst_pathlen, "Expected length %lu, got %d",
    (unsigned long) dst_pathlen, res);
  fail_unless(strcmp(buf, dst_path) == 0, "Expected '%s', got '%s'",
    dst_path, buf);

  /* Not chrooted, relative dst path, flags to HANDLE rel path */
  memset(buf, '\0', bufsz);
  dst_path = "./file.dat";
  dst_pathlen = strlen(dst_path);
  expected_path = "/tmp/file.dat";
  expected_pathlen = strlen(expected_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  flags = PR_DIR_READLINK_FL_HANDLE_REL_PATH;
  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == expected_pathlen, "Expected length %lu, got %d",
    (unsigned long) expected_pathlen, res);
  fail_unless(strcmp(buf, expected_path) == 0, "Expected '%s', got '%s'",
    expected_path, buf);

  /* Not chrooted, relative dst path without leading '.', flags to HANDLE rel
   * path.
   */
  memset(buf, '\0', bufsz);
  dst_path = "file.dat";
  dst_pathlen = strlen(dst_path);
  expected_path = "/tmp/file.dat";
  expected_pathlen = strlen(expected_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  flags = PR_DIR_READLINK_FL_HANDLE_REL_PATH;
  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == expected_pathlen, "Expected length %lu, got %d",
    (unsigned long) expected_pathlen, res);
  fail_unless(strcmp(buf, expected_path) == 0, "Expected '%s', got '%s'",
    expected_path, buf);

  /* Not chrooted, dst path longer than given buffer */
  flags = 0;
  memset(buf, '\0', bufsz);
  res = dir_readlink(p, path, buf, 2, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless(res == 2, "Expected length 2, got %d", res);
  fail_unless(strncmp(buf, dst_path, 2) == 0, "Expected '%*s', got '%*s'",
    2, dst_path, 2, buf);

  /* Chrooted to "/" */
  session.chroot_path = "/";
  memset(buf, '\0', bufsz);
  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == dst_pathlen, "Expected length %lu, got %d",
    (unsigned long) dst_pathlen, res);
  fail_unless(strcmp(buf, dst_path) == 0, "Expected '%s', got '%s'",
    dst_path, buf);

  /* Chrooted, absolute destination path shorter than chroot path */
  session.chroot_path = "/home/user";
  memset(buf, '\0', bufsz);
  dst_path = "/foo";
  dst_pathlen = strlen(dst_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == dst_pathlen, "Expected length %lu, got %d",
    (unsigned long) dst_pathlen, res);
  fail_unless(strcmp(buf, dst_path) == 0, "Expected '%s', got '%s'",
    dst_path, buf);

  /* Chrooted, overlapping chroot to non-dir */
  memset(buf, '\0', bufsz);
  dst_path = "/home/user2";
  dst_pathlen = strlen(dst_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == dst_pathlen, "Expected length %lu, got %d",
    (unsigned long) dst_pathlen, res);
  fail_unless(strcmp(buf, dst_path) == 0, "Expected '%s', got '%s'",
    dst_path, buf);

  /* Chrooted, absolute destination within chroot */
  memset(buf, '\0', bufsz);
  dst_path = "/home/user/file.txt";
  dst_pathlen = strlen(dst_path);
  expected_path = "/file.txt";
  expected_pathlen = strlen(expected_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == expected_pathlen, "Expected length %lu, got %d",
    (unsigned long) expected_pathlen, res);
  fail_unless(strcmp(buf, expected_path) == 0, "Expected '%s', got '%s'",
    expected_path, buf);

  /* Chrooted, absolute destination outside of chroot */
  memset(buf, '\0', bufsz);
  dst_path = "/home/user/../file.txt";
  dst_pathlen = strlen(dst_path);
  expected_path = "/home/file.txt";
  expected_pathlen = strlen(expected_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == expected_pathlen, "Expected length %lu, got %d",
    (unsigned long) expected_pathlen, res);
  fail_unless(strcmp(buf, expected_path) == 0, "Expected '%s', got '%s'",
    expected_path, buf);

  /* Chrooted, relative destination within chroot */
  memset(buf, '\0', bufsz);
  dst_path = "./file.txt";
  dst_pathlen = strlen(dst_path);
  expected_path = "./file.txt";
  expected_pathlen = strlen(expected_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == expected_pathlen, "Expected length %lu, got %d",
    (unsigned long) expected_pathlen, res);
  fail_unless(strcmp(buf, expected_path) == 0, "Expected '%s', got '%s'",
    expected_path, buf);

  /* Chrooted, relative destination (without leading '.') within chroot */
  memset(buf, '\0', bufsz);
  dst_path = "file.txt";
  dst_pathlen = strlen(dst_path);
  expected_path = "file.txt";
  expected_pathlen = strlen(expected_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == expected_pathlen, "Expected length %lu, got %d",
    (unsigned long) expected_pathlen, res);
  fail_unless(strcmp(buf, expected_path) == 0, "Expected '%s', got '%s'",
    expected_path, buf);

  /* Chrooted, relative destination outside of chroot */
  memset(buf, '\0', bufsz);
  dst_path = "../file.txt";
  dst_pathlen = strlen(dst_path);
  expected_path = "../file.txt";
  expected_pathlen = strlen(expected_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  /* First, tell dir_readlink() to ignore relative destination paths. */
  flags = 0;
  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == expected_pathlen, "Expected length %lu, got %d",
    (unsigned long) expected_pathlen, res);
  fail_unless(strcmp(buf, expected_path) == 0, "Expected '%s', got '%s'",
    expected_path, buf);

  /* Now do it again, telling dir_readlink() to handle relative destination
   * paths.
   */
  memset(buf, '\0', bufsz);
  dst_path = "../file.txt";
  dst_pathlen = strlen(dst_path);
  expected_path = "/file.txt";
  expected_pathlen = strlen(expected_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  flags = PR_DIR_READLINK_FL_HANDLE_REL_PATH;
  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == expected_pathlen, "Expected length %lu, got %d",
    (unsigned long) expected_pathlen, res);
  fail_unless(strcmp(buf, expected_path) == 0, "Expected '%s', got '%s'",
    expected_path, buf);

  /* One more time, this time changing the chroot path to align with the
   * source path.
   */
  memset(buf, '\0', bufsz);
  dst_path = "../file.txt";
  dst_pathlen = strlen(dst_path);
  expected_path = "/file.txt";
  expected_pathlen = strlen(expected_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  session.chroot_path = "/tmp";
  flags = PR_DIR_READLINK_FL_HANDLE_REL_PATH;
  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == expected_pathlen, "Expected length %lu, got %d",
    (unsigned long) expected_pathlen, res);
  fail_unless(strcmp(buf, expected_path) == 0, "Expected '%s', got '%s'",
    expected_path, buf);

  /* Now use a relative path that does not start with '.' */
  memset(buf, '\0', bufsz);
  dst_path = "file.txt";
  dst_pathlen = strlen(dst_path);
  expected_path = "./file.txt";
  expected_pathlen = strlen(expected_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  session.chroot_path = "/tmp";
  flags = PR_DIR_READLINK_FL_HANDLE_REL_PATH;
  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == expected_pathlen,
    "Expected length %lu, got %d (%s)", (unsigned long) expected_pathlen, res,
    buf);
  fail_unless(strcmp(buf, expected_path) == 0, "Expected '%s', got '%s'",
    expected_path, buf);

  /* Now use a relative path that does not start with '.', and a chroot
   * deeper down than one directory.
   */
  memset(buf, '\0', bufsz);
  dst_path = "file.txt";
  dst_pathlen = strlen(dst_path);
  expected_path = "/tmp/file.txt";
  expected_pathlen = strlen(expected_path);

  (void) unlink(path);
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  session.chroot_path = "/tmp/foo/bar";
  flags = PR_DIR_READLINK_FL_HANDLE_REL_PATH;
  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == expected_pathlen,
    "Expected length %lu, got %d (%s)", (unsigned long) expected_pathlen, res,
    buf);
  fail_unless(strcmp(buf, expected_path) == 0, "Expected '%s', got '%s'",
    expected_path, buf);

  /* Now use a relative path, and a chroot deeper down than one directory, and
   * a deeper/longer source path.
   */
  memset(buf, '\0', bufsz);
  dst_path = "./file.txt";
  dst_pathlen = strlen(dst_path);
  expected_path = "/tmp/prt-readlink/file.txt";
  expected_pathlen = strlen(expected_path);

  (void) unlink(path);
  (void) rmdir(misc_test_readlink2_dir);
  (void) mkdir(misc_test_readlink2_dir, 0777);
  path = misc_test_readlink2;
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  session.chroot_path = "/tmp/foo/bar";
  flags = PR_DIR_READLINK_FL_HANDLE_REL_PATH;
  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == expected_pathlen,
    "Expected length %lu, got %d (%s)", (unsigned long) expected_pathlen, res,
    buf);
  fail_unless(strcmp(buf, expected_path) == 0, "Expected '%s', got '%s'",
    expected_path, buf);

  /* Now use a relative path that does not start with '.', and a chroot
   * deeper down than one directory, and a deeper/longer source path.
   */
  memset(buf, '\0', bufsz);
  dst_path = "file.txt";
  dst_pathlen = strlen(dst_path);
  expected_path = "/tmp/prt-readlink/file.txt";
  expected_pathlen = strlen(expected_path);

  (void) unlink(path);
  (void) rmdir(misc_test_readlink2_dir);
  (void) mkdir(misc_test_readlink2_dir, 0777);
  path = misc_test_readlink2;
  res = symlink(dst_path, path);
  fail_unless(res == 0, "Failed to symlink '%s' to '%s': %s", path, dst_path,
    strerror(errno));

  session.chroot_path = "/tmp/foo/bar";
  flags = PR_DIR_READLINK_FL_HANDLE_REL_PATH;
  res = dir_readlink(p, path, buf, bufsz, flags);
  fail_if(res < 0, "Failed to read '%s' symlink: %s", path, strerror(errno));
  fail_unless((size_t) res == expected_pathlen,
    "Expected length %lu, got %d (%s)", (unsigned long) expected_pathlen, res,
    buf);
  fail_unless(strcmp(buf, expected_path) == 0, "Expected '%s', got '%s'",
    expected_path, buf);

  (void) unlink(misc_test_readlink);
  (void) unlink(misc_test_readlink2);
  (void) rmdir(misc_test_readlink2_dir);
}
END_TEST

START_TEST (dir_realpath_test) {
  char *res;
  const char *path;

  res = dir_realpath(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = dir_realpath(p, NULL);
  fail_unless(res == NULL, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  path = "/foo";
  res = dir_realpath(p, path);
  fail_unless(res == NULL, "Got real path for '%s' unexpectedly", path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  path = "/";
  res = dir_realpath(p, path);
  fail_unless(res != NULL, "Failed to get real path for '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, path) == 0, "Expected '%s', got '%s'", path, res);
}
END_TEST

START_TEST (dir_abs_path_test) {
  char *res;
  const char *path;

  res = dir_abs_path(NULL, NULL, TRUE);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = dir_abs_path(p, NULL, TRUE);
  fail_unless(res == NULL, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  path = "/foo";
  res = dir_abs_path(p, path, TRUE);
  fail_unless(path != NULL, "Failed to get absolute path for '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, path) == 0, "Expected '%s', got '%s'", path, res);
}
END_TEST

START_TEST (safe_token_test) {
  char *res, *text, *expected;

  mark_point();
  expected = "";
  res = safe_token(NULL);
  fail_unless(res != NULL, "Failed to handle null arguments");
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  mark_point();
  text = "";
  expected = "";
  res = safe_token(&text);
  fail_unless(res != NULL, "Failed to handle null arguments");
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  mark_point();
  text = "foo";
  expected = text;
  res = safe_token(&text);
  fail_unless(res != NULL, "Failed to handle null arguments");
  fail_unless(res == expected, "Expected '%s', got '%s'", expected, res);
  fail_unless(strcmp(text, "") == 0, "Expected '', got '%s'", text);

  mark_point();
  text = "  foo";
  expected = text + 2;
  res = safe_token(&text);
  fail_unless(res != NULL, "Failed to handle null arguments");
  fail_unless(res == expected, "Expected '%s', got '%s'", expected, res);
  fail_unless(strcmp(text, "") == 0, "Expected '', got '%s'", text);

  mark_point();
  text = "  \t";
  expected = "";
  res = safe_token(&text);
  fail_unless(res != NULL, "Failed to handle null arguments");
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);
}
END_TEST

static int write_shutmsg(const char *path, const char *line) {
  FILE *fh;
  int res;
  size_t line_len;

  fh = fopen(path, "w+");
  if (fh == NULL) {
    return -1;
  }


  line_len = strlen(line);
  fwrite(line, line_len, 1, fh);

  res = fclose(fh);
  return res;
}

START_TEST (check_shutmsg_test) {
  int res;
  const char *path;
  time_t when_shutdown = 0, when_deny = 0, when_disconnect = 0;
  char shutdown_msg[PR_TUNABLE_BUFFER_SIZE];

  res = check_shutmsg(NULL, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/foo/bar/baz/quxx/quzz";
  res = check_shutmsg(path, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle nonexistent path");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  path = "/";
  res = check_shutmsg(path, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle directory path");
  fail_unless(errno == EISDIR, "Expected EISDIR (%d), got %s (%d)", EISDIR,
    strerror(errno), errno);

  /* XXX More testing needed */

  path = misc_test_shutmsg;

  (void) unlink(path);
  res = write_shutmsg(path,
    "1970 1 1 0 0 0 0000 0000\nGoodbye, cruel world!\n");
  fail_unless(res == 0, "Failed to write '%s': %s", path, strerror(errno));

  memset(shutdown_msg, '\0', sizeof(shutdown_msg));
  pr_env_set(p, "TZ", "GMT");

  mark_point();
  res = check_shutmsg(path, &when_shutdown, &when_deny, &when_disconnect,
    shutdown_msg, sizeof(shutdown_msg));
  fail_unless(res == 1, "Expected 1, got %d", res);
  fail_unless(when_shutdown == (time_t) 0, "Expected 0, got %lu",
    (unsigned long) when_shutdown);
  fail_unless(when_deny == (time_t) 0, "Expected 0, got %lu",
    (unsigned long) when_deny);
  fail_unless(when_disconnect == (time_t) 0, "Expected 0, got %lu",
    (unsigned long) when_disconnect);
  fail_unless(strcmp(shutdown_msg, "Goodbye, cruel world!") == 0,
    "Expected 'Goodbye, cruel world!', got '%s'", shutdown_msg);

  (void) unlink(path);
  res = write_shutmsg(path,
    "2037 1 1 0 0 0 0000 0000\nGoodbye, cruel world!\n");
  fail_unless(res == 0, "Failed to write '%s': %s", path, strerror(errno));

  mark_point();
  res = check_shutmsg(path, NULL, NULL, NULL, NULL, 0);
  fail_unless(res == 1, "Expected 1, got %d", res);

  (void) unlink(path);
  res = write_shutmsg(path,
    "0 0 0 0 0 0 0000 0000\nGoodbye, cruel world!\n");
  fail_unless(res == 0, "Failed to write '%s': %s", path, strerror(errno));

  mark_point();
  res = check_shutmsg(path, NULL, NULL, NULL, NULL, 0);

  (void) unlink(misc_test_shutmsg);
}
END_TEST

START_TEST (memscrub_test) {
  size_t len;
  char *expected, *text;

  mark_point();
  pr_memscrub(NULL, 1);

  expected = "Hello, World!";
  text = pstrdup(p, expected);

  mark_point();
  pr_memscrub(text, 0);

  len = strlen(text);

  mark_point();
  pr_memscrub(text, len);
  fail_unless(strncmp(text, expected, len + 1) != 0,
    "Expected other than '%s'", expected);
}
END_TEST

START_TEST (getopt_reset_test) {
  mark_point();
  pr_getopt_reset();
}
END_TEST

START_TEST (exists_test) {
  int res;
  const char *path;

  res = exists(NULL);
  fail_unless(res == FALSE, "Failed to handle null path");

  path = "/";
  res = exists(path);
  fail_unless(res == TRUE, "Expected TRUE for path '%s', got FALSE", path);
}
END_TEST

START_TEST (exists2_test) {
  int res;
  const char *path;

  res = exists2(NULL, NULL);
  fail_unless(res == FALSE, "Failed to handle null arguments");

  res = exists2(p, NULL);
  fail_unless(res == FALSE, "Failed to handle null path");

  path = "/";
  res = exists2(p, path);
  fail_unless(res == TRUE, "Expected TRUE for path '%s', got FALSE", path);
}
END_TEST

START_TEST (dir_exists_test) {
  int res;
  const char *path;

  res = dir_exists(NULL);
  fail_unless(res == FALSE, "Failed to handle null path");

  path = "/";
  res = dir_exists(path);
  fail_unless(res == TRUE, "Expected TRUE for path '%s', got FALSE", path);

  path = "./api-tests";
  res = dir_exists(path);
  fail_unless(res == FALSE, "Expected FALSE for path '%s', got TRUE", path);
}
END_TEST

START_TEST (dir_exists2_test) {
  int res;
  const char *path;

  res = dir_exists2(NULL, NULL);
  fail_unless(res == FALSE, "Failed to handle null arguments");

  res = dir_exists2(p, NULL);
  fail_unless(res == FALSE, "Failed to handle null path");

  path = "/";
  res = dir_exists2(p, path);
  fail_unless(res == TRUE, "Expected TRUE for path '%s', got FALSE", path);

  path = "./api-tests";
  res = dir_exists2(p, path);
  fail_unless(res == FALSE, "Expected FALSE for path '%s', got TRUE", path);
}
END_TEST

START_TEST (symlink_mode_test) {
  mode_t res;
  const char *path;

  res = symlink_mode(NULL);
  fail_unless(res == 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/";
  res = symlink_mode(path);
  fail_unless(res == 0, "Found mode for non-symlink '%s'", path);
}
END_TEST

START_TEST (symlink_mode2_test) {
  mode_t res;
  const char *path;

  res = symlink_mode2(NULL, NULL);
  fail_unless(res == 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = symlink_mode2(p, NULL);
  fail_unless(res == 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/";
  res = symlink_mode2(p, path);
  fail_unless(res == 0, "Found mode for non-symlink '%s'", path);
}
END_TEST

START_TEST (file_mode_test) {
  mode_t res;
  const char *path;

  res = file_mode(NULL);
  fail_unless(res == 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/";
  res = file_mode(path);
  fail_unless(res != 0, "Failed to find mode for '%s': %s", path,
    strerror(errno));
}
END_TEST

START_TEST (file_mode2_test) {
  mode_t res;
  const char *path;

  res = file_mode2(NULL, NULL);
  fail_unless(res == 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = file_mode2(p, NULL);
  fail_unless(res == 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/";
  res = file_mode2(p, path);
  fail_unless(res != 0, "Failed to find mode for '%s': %s", path,
    strerror(errno));
}
END_TEST

START_TEST (file_exists_test) {
  int res;
  const char *path;

  res = file_exists(NULL);
  fail_unless(res == FALSE, "Failed to handle null path");

  path = "/";
  res = file_exists(path);
  fail_unless(res == FALSE, "Expected FALSE for path '%s', got TRUE", path);

  path = "./api-tests";
  res = file_exists(path);
  fail_unless(res == TRUE, "Expected TRUE for path '%s', got FALSE", path);
}
END_TEST

START_TEST (file_exists2_test) {
  int res;
  const char *path;

  res = file_exists2(NULL, NULL);
  fail_unless(res == FALSE, "Failed to handle null arguments");

  res = file_exists2(p, NULL);
  fail_unless(res == FALSE, "Failed to handle null path");

  path = "/";
  res = file_exists2(p, path);
  fail_unless(res == FALSE, "Expected FALSE for path '%s', got TRUE", path);

  path = "./api-tests";
  res = file_exists2(p, path);
  fail_unless(res == TRUE, "Expected TRUE for path '%s', got FALSE", path);
}
END_TEST

START_TEST (gmtime_test) {
  struct tm *res;
  time_t now;

  mark_point();
  res = pr_gmtime(NULL, NULL); 
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  time(&now);

  mark_point();
  res = pr_gmtime(NULL, &now);
  fail_unless(res != NULL, "Failed to handle %lu: %s", (unsigned long) now,
    strerror(errno));

  mark_point();
  res = pr_gmtime(p, &now);
  fail_unless(res != NULL, "Failed to handle %lu: %s", (unsigned long) now,
    strerror(errno));
}
END_TEST

START_TEST (localtime_test) {
  struct tm *res;
  time_t now;

  mark_point();
  res = pr_localtime(NULL, NULL); 
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  time(&now);

  mark_point();
  res = pr_localtime(NULL, &now);
  fail_unless(res != NULL, "Failed to handle %lu: %s", (unsigned long) now,
    strerror(errno));

  mark_point();
  res = pr_localtime(p, &now);
  fail_unless(res != NULL, "Failed to handle %lu: %s", (unsigned long) now,
    strerror(errno));
}
END_TEST

START_TEST (strtime_test) {
  const char *res;
  time_t now;

  mark_point();
  now = 0;
  res = pr_strtime(now);
  fail_unless(res != NULL, "Failed to convert time %lu: %s",
    (unsigned long) now, strerror(errno));
}
END_TEST

START_TEST (strtime2_test) {
  const char *res;
  char *expected;
  time_t now;

  mark_point();
  now = 0;
  expected = "Thu Jan 01 00:00:00 1970";
  res = pr_strtime2(now, TRUE);
  fail_unless(res != NULL, "Failed to convert time %lu: %s",
    (unsigned long) now, strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);
}
END_TEST

START_TEST (timeval2millis_test) {
  int res;
  struct timeval tv;
  uint64_t ms;

  res = pr_timeval2millis(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_timeval2millis(&tv, NULL);
  fail_unless(res < 0, "Failed to handle null millis argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  tv.tv_sec = tv.tv_usec = 0;
  res = pr_timeval2millis(&tv, &ms);
  fail_unless(res == 0, "Failed to convert timeval to millis: %s",
    strerror(errno));
  fail_unless(ms == 0, "Expected 0 ms, got %lu", (unsigned long) ms);
}
END_TEST

START_TEST (gettimeofday_millis_test) {
  int res;
  uint64_t ms;

  res = pr_gettimeofday_millis(NULL);
  fail_unless(res < 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  ms = 0;
  res = pr_gettimeofday_millis(&ms);
  fail_unless(res == 0, "Failed to get current time ms: %s", strerror(errno));
  fail_unless(ms > 0, "Expected >0, got %lu", (unsigned long) ms);
}
END_TEST

START_TEST (snprintf_test) {
  char *buf;
  size_t bufsz;
  int res, expected;

  res = pr_snprintf(NULL, 0, NULL);
  fail_unless(res < 0, "Failed to handle null buffer");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  bufsz = 1;
  buf = palloc(p, bufsz);

  res = pr_snprintf(buf, 0, NULL);
  fail_unless(res < 0, "Failed to handle null format");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_snprintf(buf, 0, "%d", 0);
  fail_unless(res == 0, "Failed to handle zero-length buffer");

  res = pr_snprintf(buf, bufsz, "%d", 0);
  fail_unless(res < 0, "Failed to handle too-small buffer");
  fail_unless(errno == ENOSPC, "Expected ENOSPC (%d), got %s (%d)", ENOSPC,
    strerror(errno), errno);

  res = pr_snprintf(buf, bufsz, "%s", "foobar");
  fail_unless(res < 0, "Failed to handle too-small buffer");
  fail_unless(errno == ENOSPC, "Expected ENOSPC (%d), got %s (%d)", ENOSPC,
    strerror(errno), errno);

  bufsz = 32;
  buf = palloc(p, bufsz);

  expected = 6;
  res = pr_snprintf(buf, bufsz, "%s", "foobar");
  fail_unless(res == expected, "Expected %d, got %d", expected, res);
}
END_TEST

START_TEST (snprintfl_test) {
  char *buf;
  size_t bufsz;
  int res, expected;

  res = pr_snprintfl(NULL, -1, NULL, 0, NULL);
  fail_unless(res < 0, "Failed to handle null buffer");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  bufsz = 1;
  buf = palloc(p, bufsz);

  res = pr_snprintfl(NULL, -1, buf, 0, NULL);
  fail_unless(res < 0, "Failed to handle null format");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_snprintfl(__FILE__, __LINE__, buf, 0, "%d", 0);
  fail_unless(res == 0, "Failed to handle zero-length buffer");

  res = pr_snprintfl(__FILE__, __LINE__, buf, bufsz, "%d", 0);
  fail_unless(res < 0, "Failed to handle too-small buffer");
  fail_unless(errno == ENOSPC, "Expected ENOSPC (%d), got %s (%d)", ENOSPC,
    strerror(errno), errno);

  res = pr_snprintfl(__FILE__, __LINE__, buf, bufsz, "%s", "foobar");
  fail_unless(res < 0, "Failed to handle too-small buffer");
  fail_unless(errno == ENOSPC, "Expected ENOSPC (%d), got %s (%d)", ENOSPC,
    strerror(errno), errno);

  bufsz = 32;
  buf = palloc(p, bufsz);

  expected = 6;
  res = pr_snprintfl(__FILE__, __LINE__, buf, bufsz, "%s", "foobar");
  fail_unless(res == expected, "Expected %d, got %d", expected, res);
}
END_TEST

START_TEST (path_subst_uservar_test) {
  const char *path = NULL, *res, *original, *expected;

  res = path_subst_uservar(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = path_subst_uservar(p, NULL);
  fail_unless(res == NULL, "Failed to handle null path pointer");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = path_subst_uservar(p, &path);
  fail_unless(res == NULL, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  original = expected = "somepathhere";
  path = pstrdup(p, expected);
  mark_point();
  res = path_subst_uservar(p, &path);
  fail_unless(res != NULL, "Failed to handle path '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  session.user = "user";
  original = "/home/%u";
  expected = "/home/user";
  path = pstrdup(p, original);
  mark_point();
  res = path_subst_uservar(p, &path);
  fail_unless(res != NULL, "Failed to handle path '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  session.user = "user";
  original = "/home/%u[";
  expected = "/home/user[";
  path = pstrdup(p, original);
  mark_point();
  res = path_subst_uservar(p, &path);
  fail_unless(res != NULL, "Failed to handle path '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  session.user = "user";
  original = "/home/%u[]";
  expected = "/home/user[]";
  path = pstrdup(p, original);
  mark_point();
  res = path_subst_uservar(p, &path);
  fail_unless(res != NULL, "Failed to handle path '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  session.user = "user";
  original = "/home/users/%u[0]/%u[0]%u[1]/%u";
  expected = "/home/users/u/us/user";
  path = pstrdup(p, original);
  mark_point();
  res = path_subst_uservar(p, &path);
  fail_unless(res != NULL, "Failed to handle path '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  /* Attempt to use an invalid index */
  session.user = "user";
  original = "/home/users/%u[a]/%u[b]%u[c]/%u";
  expected = original;
  path = pstrdup(p, original);
  mark_point();
  res = path_subst_uservar(p, &path);
  fail_unless(res != NULL, "Failed to handle path '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  /* Attempt to use an out-of-bounds index */
  session.user = "user";
  original = "/home/users/%u[0]/%u[-1]%u[1]/%u";
  expected = original;
  path = pstrdup(p, original);
  mark_point();
  res = path_subst_uservar(p, &path);
  fail_unless(res != NULL, "Failed to handle path '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  /* Attempt to use an out-of-bounds index */
  session.user = "user";
  original = "/home/users/%u[0]/%u[0]%u[4]/%u";
  expected = original;
  path = pstrdup(p, original);
  mark_point();
  res = path_subst_uservar(p, &path);
  fail_unless(res != NULL, "Failed to handle path '%s': %s", path,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);
}
END_TEST

Suite *tests_get_misc_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("misc");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, schedule_test);
  tcase_add_test(testcase, get_name_max_test);
  tcase_add_test(testcase, dir_interpolate_test);
  tcase_add_test(testcase, dir_best_path_test);
  tcase_add_test(testcase, dir_canonical_path_test);
  tcase_add_test(testcase, dir_canonical_vpath_test);
  tcase_add_test(testcase, dir_readlink_test);
  tcase_add_test(testcase, dir_realpath_test);
  tcase_add_test(testcase, dir_abs_path_test);
  tcase_add_test(testcase, symlink_mode_test);
  tcase_add_test(testcase, symlink_mode2_test);
  tcase_add_test(testcase, file_mode_test);
  tcase_add_test(testcase, file_mode2_test);
  tcase_add_test(testcase, exists_test);
  tcase_add_test(testcase, exists2_test);
  tcase_add_test(testcase, dir_exists_test);
  tcase_add_test(testcase, dir_exists2_test);
  tcase_add_test(testcase, file_exists_test);
  tcase_add_test(testcase, file_exists2_test);
  tcase_add_test(testcase, safe_token_test);
  tcase_add_test(testcase, check_shutmsg_test);
  tcase_add_test(testcase, memscrub_test);
  tcase_add_test(testcase, getopt_reset_test);
  tcase_add_test(testcase, gmtime_test);
  tcase_add_test(testcase, localtime_test);
  tcase_add_test(testcase, strtime_test);
  tcase_add_test(testcase, strtime2_test);
  tcase_add_test(testcase, timeval2millis_test);
  tcase_add_test(testcase, gettimeofday_millis_test);
  tcase_add_test(testcase, snprintf_test);
  tcase_add_test(testcase, snprintfl_test);
  tcase_add_test(testcase, path_subst_uservar_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
