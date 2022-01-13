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

/* RLimit API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
  }
}

START_TEST (rlimit_core_test) {
  int res;
  rlim_t curr_rlim = 0, max_rlim = 0 ;

  res = pr_rlimit_get_core(NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  res = pr_rlimit_get_core(&curr_rlim, &max_rlim);
  fail_unless(res == 0, "Failed to get core resource limits: %s",
    strerror(errno));

  curr_rlim = max_rlim = -1;
  res = pr_rlimit_set_core(curr_rlim, max_rlim);

  /* Note that some platforms will NOT fail a setrlimit(2) command if the
   * arguments are negative.  Hence this conditional check.
   */
  if (res < 0) {
    fail_unless(errno == EPERM, "Failed to set errno to EPERM, got %s (%d)",
      strerror(errno), errno);
  }
}
END_TEST

START_TEST (rlimit_cpu_test) {
  int res;
  rlim_t curr_rlim = 0, max_rlim = 0 ;

  res = pr_rlimit_get_cpu(NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  res = pr_rlimit_get_cpu(&curr_rlim, &max_rlim);
  fail_unless(res == 0, "Failed to get CPU resource limits: %s",
    strerror(errno));

  curr_rlim = max_rlim = -1;
  res = pr_rlimit_set_cpu(curr_rlim, max_rlim);

  /* Note that some platforms will NOT fail a setrlimit(2) command if the
   * arguments are negative.  Hence this conditional check.
   */
  if (res < 0) {
    fail_unless(errno == EPERM, "Failed to set errno to EPERM, got %s (%d)",
      strerror(errno), errno);
  }
}
END_TEST

START_TEST (rlimit_files_test) {
  int res;
  rlim_t curr_rlim = 0, max_rlim = 0 ;

  res = pr_rlimit_get_files(NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  res = pr_rlimit_get_files(&curr_rlim, &max_rlim);
  fail_unless(res == 0, "Failed to get file resource limits: %s",
    strerror(errno));

  curr_rlim = max_rlim = -1;
  res = pr_rlimit_set_files(curr_rlim, max_rlim);

  /* Note that some platforms will NOT fail a setrlimit(2) command if the
   * arguments are negative.  Hence this conditional check.
   */
  if (res < 0) {
    fail_unless(errno == EPERM, "Failed to set errno to EPERM, got %s (%d)",
      strerror(errno), errno);
  }
}
END_TEST

START_TEST (rlimit_memory_test) {
  int res;
  rlim_t curr_rlim = 0, max_rlim = 0 ;

  res = pr_rlimit_get_memory(NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  res = pr_rlimit_get_memory(&curr_rlim, &max_rlim);
  fail_unless(res == 0, "Failed to get memory resource limits: %s",
    strerror(errno));

  curr_rlim = max_rlim = -1;
  res = pr_rlimit_set_memory(curr_rlim, max_rlim);

  /* Note that some platforms will NOT fail a setrlimit(2) command if the
   * arguments are negative.  Hence this conditional check.
   */
  if (res < 0) {
    fail_unless(errno == EPERM, "Failed to set errno to EPERM, got %s (%d)",
      strerror(errno), errno);
  }
}
END_TEST

#ifdef RLIMIT_NPROC
START_TEST (rlimit_nproc_test) {
  int res;
  rlim_t curr_rlim = 0, max_rlim = 0 ;

  res = pr_rlimit_get_nproc(NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  res = pr_rlimit_get_nproc(&curr_rlim, &max_rlim);
  fail_unless(res == 0, "Failed to get nproc resource limits: %s",
    strerror(errno));

  curr_rlim = max_rlim = -1;
  res = pr_rlimit_set_nproc(curr_rlim, max_rlim);

  /* Note that some platforms will NOT fail a setrlimit(2) command if the
   * arguments are negative.  Hence this conditional check.
   */
  if (res < 0) {
    fail_unless(errno == EPERM, "Failed to set errno to EPERM, got %s (%d)",
      strerror(errno), errno);
  }
}
END_TEST
#endif /* RLIMIT_NPROC */

Suite *tests_get_rlimit_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("rlimit");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, rlimit_core_test);
  tcase_add_test(testcase, rlimit_cpu_test);
  tcase_add_test(testcase, rlimit_files_test);
  tcase_add_test(testcase, rlimit_memory_test);
#ifdef RLIMIT_NPROC
  tcase_add_test(testcase, rlimit_nproc_test);
#endif /* RLIMIT_NPROC */

  suite_add_tcase(suite, testcase);
  return suite;
}
