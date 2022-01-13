/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2008-2017 The ProFTPD Project team
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

/* Regexp API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_regexp();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("regexp", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("regexp", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (regexp_alloc_test) {
  pr_regex_t *res;

  res = pr_regexp_alloc(NULL);
  fail_unless(res != NULL, "Failed to allocate regex: %s", strerror(errno));
  pr_regexp_free(NULL, res);
}
END_TEST

START_TEST (regexp_free_test) {
  mark_point();
  pr_regexp_free(NULL, NULL);
}
END_TEST

START_TEST (regexp_error_test) {
  size_t bufsz, res;
  const pr_regex_t *pre;
  char *buf;

  mark_point();
  res = pr_regexp_error(0, NULL, NULL, 0);
  fail_unless(res == 0, "Failed to handle null regexp");

  pre = (const pr_regex_t *) 3;

  mark_point();
  res = pr_regexp_error(0, pre, NULL, 0);
  fail_unless(res == 0, "Failed to handle null buf");

  bufsz = 256;
  buf = pcalloc(p, bufsz);

  mark_point();
  res = pr_regexp_error(0, pre, buf, 0);
  fail_unless(res == 0, "Failed to handle zero bufsz");
}
END_TEST

START_TEST (regexp_compile_test) {
  pr_regex_t *pre = NULL;
  int res;
  char errstr[256], *pattern;
  size_t errstrlen;

  res = pr_regexp_compile(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pre = pr_regexp_alloc(NULL);

  res = pr_regexp_compile(pre, NULL, 0);
  fail_unless(res < 0, "Failed to handle null pattern");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pattern = "[=foo";
  res = pr_regexp_compile(pre, pattern, 0); 
  fail_unless(res != 0, "Successfully compiled pattern unexpectedly"); 

  errstrlen = pr_regexp_error(1, NULL, NULL, 0);
  fail_unless(errstrlen == 0, "Failed to handle null arguments");

  errstrlen = pr_regexp_error(1, pre, NULL, 0);
  fail_unless(errstrlen == 0, "Failed to handle null buffer");

  errstrlen = pr_regexp_error(1, pre, errstr, 0);
  fail_unless(errstrlen == 0, "Failed to handle zero buffer length");

  errstrlen = pr_regexp_error(res, pre, errstr, sizeof(errstr));
  fail_unless(errstrlen > 0, "Failed to get regex compilation error string");

  pattern = "foo";
  res = pr_regexp_compile(pre, pattern, 0);
  fail_unless(res == 0, "Failed to compile regex pattern '%s'", pattern);

  pattern = "foo";
  res = pr_regexp_compile(pre, pattern, REG_ICASE);
  fail_unless(res == 0, "Failed to compile regex pattern '%s'", pattern);

  pr_regexp_free(NULL, pre);
}
END_TEST

START_TEST (regexp_compile_posix_test) {
  pr_regex_t *pre = NULL;
  int res;
  char errstr[256], *pattern;
  size_t errstrlen;

  res = pr_regexp_compile_posix(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pre = pr_regexp_alloc(NULL);

  res = pr_regexp_compile_posix(pre, NULL, 0);
  fail_unless(res < 0, "Failed to handle null pattern");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pattern = "[=foo";
  res = pr_regexp_compile_posix(pre, pattern, 0);
  fail_unless(res != 0, "Successfully compiled pattern unexpectedly");

  errstrlen = pr_regexp_error(res, pre, errstr, sizeof(errstr));
  fail_unless(errstrlen > 0, "Failed to get regex compilation error string");

  pattern = "foo";
  res = pr_regexp_compile_posix(pre, pattern, 0);
  fail_unless(res == 0, "Failed to compile regex pattern '%s'", pattern);

  pattern = "foo";
  res = pr_regexp_compile_posix(pre, pattern, REG_ICASE);
  fail_unless(res == 0, "Failed to compile regex pattern '%s'", pattern);

  pr_regexp_free(NULL, pre);
}
END_TEST

START_TEST (regexp_get_pattern_test) {
  pr_regex_t *pre = NULL;
  int res;
  const char *str;
  char *pattern;

  str = pr_regexp_get_pattern(NULL);
  fail_unless(str == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pre = pr_regexp_alloc(NULL);

  str = pr_regexp_get_pattern(pre);
  fail_unless(str == NULL, "Failed to handle null pattern");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  pattern = "^foo";
  res = pr_regexp_compile(pre, pattern, 0);
  fail_unless(res == 0, "Failed to compile regex pattern '%s'", pattern);

  str = pr_regexp_get_pattern(pre);
  fail_unless(str != NULL, "Failed to get regex pattern: %s", strerror(errno));
  fail_unless(strcmp(str, pattern) == 0, "Expected '%s', got '%s'", pattern,
    str);

  pr_regexp_free(NULL, pre);
}
END_TEST

START_TEST (regexp_set_limits_test) {
  int res;
  pr_regex_t *pre = NULL;
  const char *pattern, *str;

  res = pr_regexp_set_limits(0, 0);
  fail_unless(res == 0, "Failed to set limits: %s", strerror(errno));

  /* Set the limits, and compile/execute a regex. */
  res = pr_regexp_set_limits(1, 1);
  fail_unless(res == 0, "Failed to set limits: %s", strerror(errno));

  pre = pr_regexp_alloc(NULL);

  pattern = "^foo";
  res = pr_regexp_compile(pre, pattern, REG_ICASE);
  fail_unless(res == 0, "Failed to compile regex pattern '%s'", pattern);

  str = "fooBAR";
  (void) pr_regexp_exec(pre, str, 0, NULL, 0, 0, 0);

  pr_regexp_free(NULL, pre);
}
END_TEST

START_TEST (regexp_exec_test) {
  pr_regex_t *pre = NULL;
  int res;
  char *pattern, *str;

  res = pr_regexp_exec(NULL, NULL, 0, NULL, 0, 0, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pre = pr_regexp_alloc(NULL);

  pattern = "^foo";
  res = pr_regexp_compile(pre, pattern, 0);
  fail_unless(res == 0, "Failed to compile regex pattern '%s'", pattern);

  res = pr_regexp_exec(pre, NULL, 0, NULL, 0, 0, 0);
  fail_unless(res != 0, "Failed to handle null string");

  str = "bar";
  res = pr_regexp_exec(pre, str, 0, NULL, 0, 0, 0);
  fail_unless(res != 0, "Matched string unexpectedly");

  str = "foobar";
  res = pr_regexp_exec(pre, str, 0, NULL, 0, 0, 0);
  fail_unless(res == 0, "Failed to match string");

  pr_regexp_free(NULL, pre);

  pre = pr_regexp_alloc(NULL);

  pattern = "^foo";
  res = pr_regexp_compile_posix(pre, pattern, REG_ICASE);
  fail_unless(res == 0, "Failed to compile regex pattern '%s'", pattern);

  res = pr_regexp_exec(pre, NULL, 0, NULL, 0, 0, 0);
  fail_unless(res != 0, "Failed to handle null string");

  str = "BAR";
  res = pr_regexp_exec(pre, str, 0, NULL, 0, 0, 0);
  fail_unless(res != 0, "Matched string unexpectedly");

  str = "FOOBAR";
  res = pr_regexp_exec(pre, str, 0, NULL, 0, 0, 0);
  fail_unless(res == 0, "Failed to match string");

  pr_regexp_free(NULL, pre);
}
END_TEST

START_TEST (regexp_cleanup_test) {
  pr_regex_t *pre, *pre2, *pre3;
  int res;
  char *pattern;

  pattern = "^foo";

  pre = pr_regexp_alloc(NULL);
  res = pr_regexp_compile(pre, pattern, 0);
  fail_unless(res == 0, "Failed to compile regexp pattern '%s'", pattern);

  pattern = "bar$";
  pre2 = pr_regexp_alloc(NULL);
  res = pr_regexp_compile(pre2, pattern, 0);
  fail_unless(res == 0, "Failed to compile regexp pattern '%s'", pattern);

  pattern = "&baz$";
  pre3 = pr_regexp_alloc(NULL);
  res = pr_regexp_compile_posix(pre3, pattern, 0);
  fail_unless(res == 0, "Failed to compile POSIX regexp pattern '%s'", pattern);

  mark_point();
  pr_event_generate("core.restart", NULL);

  mark_point();
  pr_event_generate("core.exit", NULL);

  mark_point();
  pr_regexp_free(NULL, pre);

  mark_point();
  pr_regexp_free(NULL, pre2);
}
END_TEST

Suite *tests_get_regexp_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("regexp");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, regexp_alloc_test);
  tcase_add_test(testcase, regexp_free_test);
  tcase_add_test(testcase, regexp_error_test);
  tcase_add_test(testcase, regexp_compile_test);
  tcase_add_test(testcase, regexp_compile_posix_test);
  tcase_add_test(testcase, regexp_exec_test);
  tcase_add_test(testcase, regexp_get_pattern_test);
  tcase_add_test(testcase, regexp_set_limits_test);
  tcase_add_test(testcase, regexp_cleanup_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
