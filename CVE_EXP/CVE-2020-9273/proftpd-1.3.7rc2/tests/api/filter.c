/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2014-2016 The ProFTPD Project team
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

/* Filter API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }

  init_config();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_use_stderr(TRUE);
    pr_trace_set_levels("filter", 0, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_use_stderr(FALSE);
  }

  if (p) {
    destroy_pool(p);
    p = NULL;
  }
}

START_TEST (filter_parse_flags_test) {
  const char *flags_str = NULL;
  int res;

  res = pr_filter_parse_flags(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_filter_parse_flags(p, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_filter_parse_flags(NULL, flags_str);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  flags_str = "foo";
  res = pr_filter_parse_flags(p, flags_str);
  fail_unless(res < 0, "Failed to handle badly formatted flags '%s'",
    flags_str);
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  flags_str = "[foo]";
  res = pr_filter_parse_flags(p, flags_str);
  fail_unless(res == 0, "Expected %d, got %d", 0, res);

  flags_str = "[NC]";
  res = pr_filter_parse_flags(p, flags_str);
  fail_unless(res == REG_ICASE, "Expected REG_ICASE (%d), got %d", REG_ICASE,
    res);

  flags_str = "[nocase]";
  res = pr_filter_parse_flags(p, flags_str);
  fail_unless(res == REG_ICASE, "Expected REG_ICASE (%d), got %d", REG_ICASE,
    res);
}
END_TEST

START_TEST (filter_allow_path_test) {
  int res;
  config_rec *c;
  pr_regex_t *allow_pre, *deny_pre;
  xaset_t *set = NULL;
  const char *path = NULL;

  res = pr_filter_allow_path(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  mark_point();
  c = add_config_param_set(&set, "test", 1, "test");
  fail_if(c == NULL, "Failed to add config param: %s", strerror(errno));

  path = "/foo/bar";
  res = pr_filter_allow_path(set, path);
  fail_unless(res == 0, "Failed to allow path '%s' with no configured filters",
    path);

  /* First, let's add a PathDenyFilter. */
  deny_pre = pr_regexp_alloc(NULL);
  res = pr_regexp_compile(deny_pre, "/bar$", 0);
  fail_unless(res == 0, "Error compiling deny filter");

  c = add_config_param_set(&set, "PathDenyFilter", 1, deny_pre);
  fail_if(c == NULL, "Failed to add config param: %s", strerror(errno));

  mark_point();
  res = pr_filter_allow_path(set, path);
  fail_unless(res == PR_FILTER_ERR_FAILS_DENY_FILTER,
    "Failed to reject path '%s' with matching PathDenyFilter", path);

  mark_point();
  path = "/foo/baz";
  res = pr_filter_allow_path(set, path);
  fail_unless(res == 0,
    "Failed to allow path '%s' with non-matching PathDenyFilter", path);
  pr_regexp_free(NULL, deny_pre);

  /* Now, let's add a PathAllowFilter. */
  allow_pre = pr_regexp_alloc(NULL);
  res = pr_regexp_compile(allow_pre, "/baz$", 0);
  fail_unless(res == 0, "Error compiling allow filter");

  c = add_config_param_set(&set, "PathAllowFilter", 1, allow_pre);
  fail_if(c == NULL, "Failed to add config param: %s", strerror(errno));

  mark_point();
  path = "/foo/quxx";
  res = pr_filter_allow_path(set, path);
  fail_unless(res == PR_FILTER_ERR_FAILS_ALLOW_FILTER,
    "Failed to allow path '%s' with matching PathAllowFilter", path);
  pr_regexp_free(NULL, allow_pre);
}
END_TEST

Suite *tests_get_filter_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("filter");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, filter_parse_flags_test);
  tcase_add_test(testcase, filter_allow_path_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
