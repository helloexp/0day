/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2015-2017 The ProFTPD Project team
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

/* Help API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }
  pr_response_set_pool(p);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_use_stderr(TRUE);
    pr_trace_set_levels("response", 0, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_use_stderr(FALSE);
  }

  pr_response_set_pool(NULL);

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (help_add_test) {
  const char *cmd, *syntax;

  mark_point();
  pr_help_add(NULL, NULL, 0);

  cmd = "FOO";

  mark_point();
  pr_help_add(cmd, NULL, 0);

  syntax = "<path>";

  mark_point();
  pr_help_add(cmd, syntax, FALSE);

  mark_point();
  pr_help_add(cmd, syntax, TRUE);

  cmd = "BAR";

  mark_point();
  pr_help_add(cmd, syntax, FALSE);
}
END_TEST

START_TEST (help_add_response_test) {
  int res;
  const char *resp_code = NULL, *resp_msg = NULL;
  cmd_rec *cmd;

  res = pr_help_add_response(NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  mark_point();

  cmd = pr_cmd_alloc(p, 2, C_HELP, "FOO");
  res = pr_help_add_response(cmd, NULL);
  fail_unless(res == -1, "Failed to handle empty help list");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %s (%d)",
    strerror(errno), errno);

  mark_point();

  /* Now add one command to the help list, and try again. */
  pr_help_add("FOO", "", TRUE);

  mark_point();

  res = pr_help_add_response(cmd, NULL);
  fail_unless(res == 0, "Failed to add help response: %s", strerror(errno));

  mark_point();

  resp_code = resp_msg = NULL;
  res = pr_response_get_last(p, &resp_code, &resp_msg);
  fail_unless(res == 0, "Failed to get last response: %s", strerror(errno));
  fail_unless(resp_code != NULL, "Expected non-null response code");
  fail_unless(strcmp(resp_code, R_214) == 0,
    "Expected response code %s, got %s", R_214, resp_code);
  fail_unless(resp_msg != NULL, "Expected non-null response message");
  fail_unless(strcmp(resp_msg, "Direct comments to ftp-admin") == 0,
    "Expected response message '%s', got '%s'", "Direct comments to ftp-admin",
    resp_msg);

  mark_point();

  res = pr_help_add_response(cmd, "FOO");
  fail_unless(res == 0, "Failed to add help response: %s", strerror(errno));

  mark_point();

  resp_code = resp_msg = NULL;
  res = pr_response_get_last(p, &resp_code, &resp_msg);
  fail_unless(res == 0, "Failed to get last response: %s", strerror(errno));
  fail_unless(resp_code != NULL, "Expected non-null response code");
  fail_unless(strcmp(resp_code, R_214) == 0,
    "Expected response code %s, got %s", R_214, resp_code);
  fail_unless(resp_msg != NULL, "Expected non-null response message");
  fail_unless(strcmp(resp_msg, "Syntax: FOO ") == 0,
    "Expected response message '%s', got '%s'", "Syntax: FOO ", resp_msg);

  /* Now add an unimplemented command, and test that one. */

  mark_point();

  pr_help_add("BAR", "<path>", FALSE);

  res = pr_help_add_response(cmd, "BAR");
  fail_unless(res == 0, "Failed to add help response: %s", strerror(errno));

  mark_point();

  resp_code = resp_msg = NULL;
  res = pr_response_get_last(p, &resp_code, &resp_msg);
  fail_unless(res == 0, "Failed to get last response: %s", strerror(errno));
  fail_unless(resp_code != NULL, "Expected non-null response code");
  fail_unless(strcmp(resp_code, R_214) == 0,
    "Expected response code %s, got %s", R_214, resp_code);
  fail_unless(resp_msg != NULL, "Expected non-null response message");
  fail_unless(strcmp(resp_msg, "Syntax: BAR <path>") == 0,
    "Expected response message '%s', got '%s'", "Syntax: BAR <path>", resp_msg);
}
END_TEST

Suite *tests_get_help_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("help");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, help_add_test);
  tcase_add_test(testcase, help_add_response_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
