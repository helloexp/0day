/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2014 The ProFTPD Project team
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

/* Pidfile API tests. */

#include "tests.h"

static pool *p = NULL;
static const char *pidfile_path = "/tmp/prt-pidfile";

/* Fixtures */

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }

  (void) unlink(pidfile_path);
}

/* Tests */

START_TEST (pidfile_set_test) {
  int res;
  const char *path;

  res = pr_pidfile_set(NULL);
  fail_unless(res < 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  path = "foo";
  res = pr_pidfile_set(path);
  fail_unless(res < 0, "Failed to handle relative path");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  path = "/foo";
  res = pr_pidfile_set(path);
  fail_unless(res == 0, "Failed to handle path '%s': %s", path,
    strerror(errno));

  path = pr_pidfile_get();
  fail_unless(strcmp(path, "/foo") == 0, "Expected path '/foo', got '%s'",
    path);
}
END_TEST

START_TEST (pidfile_remove_test) {
  int res;

  res = pr_pidfile_remove();
  fail_unless(res < 0, "Removed nonexistent file unexpectedly");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));
}
END_TEST

START_TEST (pidfile_write_test) {
  int res;

  res = pr_pidfile_set(pidfile_path);
  fail_unless(res == 0, "Failed to set path '%s': %s", pidfile_path,
    strerror(errno));

  res = pr_pidfile_write();
  fail_unless(res == 0, "Failed to write to path '%s': %s", pidfile_path,
    strerror(errno));

  res = pr_pidfile_remove();
  fail_unless(res == 0, "Failed to remove path '%s': %s", pidfile_path,
    strerror(errno));

  res = pr_pidfile_remove();
  fail_unless(res < 0, "Removed nonexistent file unexpectedly");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));
}
END_TEST

Suite *tests_get_pidfile_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("pidfile");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, pidfile_set_test);
  tcase_add_test(testcase, pidfile_remove_test);
  tcase_add_test(testcase, pidfile_write_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
