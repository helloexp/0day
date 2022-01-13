/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2015-2016 The ProFTPD Project team
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

/* Privs API tests */

#include "tests.h"

static pool *p = NULL;

static uid_t privs_uid = (uid_t) -1;
static gid_t privs_gid = (gid_t) -1;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_privs();
  privs_uid = getuid();
  privs_gid = getgid();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("privs", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("privs", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (privs_set_nonroot_daemon_test) {
  int nonroot, res;

  res = set_nonroot_daemon(-1);
  fail_unless(res < 0, "Failed to handle non-Boolean parameter");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  nonroot = set_nonroot_daemon(TRUE);
  fail_if(nonroot != FALSE && nonroot != TRUE,  "Expected true/false, got %d",
    nonroot);
  set_nonroot_daemon(nonroot);
}
END_TEST

START_TEST (privs_setup_test) {
  int nonroot, res;

  if (privs_uid != 0) {
    res = pr_privs_setup(privs_uid, privs_gid, __FILE__, __LINE__);
    fail_unless(res == 0, "Failed to setup privs: %s", strerror(errno));
    fail_unless(session.uid == privs_uid, "Expected %lu, got %lu",
      (unsigned long) privs_uid, (unsigned long) session.uid);
    fail_unless(session.gid == privs_gid, "Expected %lu, got %lu",
      (unsigned long) privs_gid, (unsigned long) session.gid);

    nonroot = set_nonroot_daemon(FALSE);

    res = pr_privs_setup(privs_uid, privs_gid, __FILE__, __LINE__);
    fail_unless(res == 0, "Failed to setup privs: %s", strerror(errno));
    fail_unless(session.uid == privs_uid, "Expected %lu, got %lu",
      (unsigned long) privs_uid, (unsigned long) session.uid);
    fail_unless(session.gid == privs_gid, "Expected %lu, got %lu",
      (unsigned long) privs_gid, (unsigned long) session.gid);

    set_nonroot_daemon(nonroot);
  }
}
END_TEST

START_TEST (privs_root_test) {
  int nonroot, res;

  if (privs_uid != 0) {
    res = pr_privs_root(__FILE__, __LINE__);
    fail_unless(res == 0, "Failed to set root privs: %s", strerror(errno));

    nonroot = set_nonroot_daemon(FALSE);

    res = pr_privs_root(__FILE__, __LINE__);
    fail_unless(res == 0, "Failed to set root privs: %s", strerror(errno));

    set_nonroot_daemon(nonroot);
  }
}
END_TEST

START_TEST (privs_user_test) {
  int nonroot, res;

  if (privs_uid != 0) {
    res = pr_privs_user(__FILE__, __LINE__);
    fail_unless(res == 0, "Failed to set user privs: %s", strerror(errno));

    nonroot = set_nonroot_daemon(FALSE);

    res = pr_privs_user(__FILE__, __LINE__);
    fail_unless(res == 0, "Failed to set user privs: %s", strerror(errno));

    set_nonroot_daemon(nonroot);
  }
}
END_TEST

START_TEST (privs_relinquish_test) {
  int nonroot, res;

  if (privs_uid != 0) {
    res = pr_privs_relinquish(__FILE__, __LINE__);
    fail_unless(res == 0, "Failed to relinquish privs: %s", strerror(errno));

    nonroot = set_nonroot_daemon(FALSE);

    res = pr_privs_relinquish(__FILE__, __LINE__);
    fail_unless(res == 0, "Failed to relinquish privs: %s", strerror(errno));

    set_nonroot_daemon(nonroot);
  }
}
END_TEST

START_TEST (privs_revoke_test) {
  int nonroot, res;

  if (privs_uid != 0) {
    res = pr_privs_revoke(__FILE__, __LINE__);
    fail_unless(res == 0, "Failed to revoke privs: %s", strerror(errno));

    nonroot = set_nonroot_daemon(FALSE);

    res = pr_privs_revoke(__FILE__, __LINE__);
    fail_unless(res == 0, "Failed to revoke privs: %s", strerror(errno));

    set_nonroot_daemon(nonroot);
  }
}
END_TEST

Suite *tests_get_privs_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("privs");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, privs_set_nonroot_daemon_test);
  tcase_add_test(testcase, privs_setup_test);
  tcase_add_test(testcase, privs_root_test);
  tcase_add_test(testcase, privs_user_test);
  tcase_add_test(testcase, privs_relinquish_test);
  tcase_add_test(testcase, privs_revoke_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
