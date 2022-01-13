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

/* Display API tests
 */

#include "tests.h"

extern pr_response_t *resp_list, *resp_err_list;

static pool *p = NULL;

static const char *display_test_file = "/tmp/prt-display.txt";

static const char *display_lines[] = {
  "Hello, %U\n",
  "Environment: %{env:FOO} (%{env:NO_FOO})\n",
  "Variable: %{BAR}\n",
  "Time: %{time:%Y%m%d}\n",
  NULL
};

/* Fixtures */

static void set_up(void) {
  (void) unlink(display_test_file);

  if (p == NULL) {
    p = session.pool = permanent_pool = make_sub_pool(NULL);
  }

  init_dirtree();
  init_fs();
  init_netio();
  init_inet();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 1, 20);
    pr_trace_set_levels("response", 1, 20);
  }
}

static void tear_down(void) {
  pr_response_register_handler(NULL);

  if (session.c != NULL) {
    pr_inet_close(p, session.c);
    session.c = NULL;
  }

  pr_unregister_netio(PR_NETIO_STRM_CTRL);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 0, 0);
    pr_trace_set_levels("response", 0, 0);
  }

  (void) unlink(display_test_file);

  if (p) {
    destroy_pool(p);
    p = session.pool = permanent_pool = NULL;
  }
}

static int write_file(const char *path, const char **lines,
    unsigned int nlines) {
  register unsigned int i;
  FILE *fh;
  int res;

  /* Write out a test Display file. */
  fh = fopen(path, "w+");
  if (fh == NULL) {
    return -1;
  }

  for (i = 0; i < nlines; i++) {
    const char *line;
    size_t line_len;

    line = lines[i];
    line_len = strlen(line);
    fwrite(line, line_len, 1, fh);
  }

  res = fclose(fh);
  return res; 
}

/* Tests */

START_TEST (display_file_test) {
  int res;
  const char *path = NULL, *resp_code = NULL;
  const char *last_resp_code = NULL, *last_resp_msg = NULL;
  pr_class_t *conn_class;

  res = pr_display_file(NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = display_test_file;
  res = pr_display_file(path, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null resp_code argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  resp_code = R_200;
  path = "/";
  res = pr_display_file(path, NULL, resp_code, 0);
  fail_unless(res < 0, "Failed to handle directory");
  fail_unless(errno == EISDIR, "Expected EISDIR (%d), got %s (%d)", EISDIR,
    strerror(errno), errno);

  mark_point();
  path = display_test_file;
  res = pr_display_file(path, NULL, resp_code, 0);
  fail_unless(res < 0, "Failed to handle nonexistent file");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  res = write_file(path, display_lines, 4);
  fail_unless(res == 0, "Failed to write display file: %s", strerror(errno));

  pr_response_set_pool(p);

  conn_class = pcalloc(p, sizeof(pr_class_t));
  conn_class->cls_pool = p;
  conn_class->cls_name = "foo.bar";
  session.conn_class = conn_class;

  mark_point();
  res = pr_display_file(path, NULL, resp_code, 0);
  fail_unless(res == 0, "Failed to display file: %s", strerror(errno));

  mark_point();
  res = pr_response_get_last(p, &last_resp_code, &last_resp_msg);
  fail_unless(res == 0, "Failed to get last response values: %s (%d)",
    strerror(errno), errno);

  fail_unless(last_resp_code != NULL,
    "Last response code is unexpectedly null");
  fail_unless(strcmp(last_resp_code, resp_code) == 0,
    "Expected response code '%s', got '%s'", resp_code, last_resp_code);

  fail_unless(last_resp_msg != NULL,
    "Last response message is unexpectedly null");

  /* Send the display file NOW */
  mark_point();
  res = pr_display_file(path, NULL, resp_code, PR_DISPLAY_FL_SEND_NOW);
  fail_unless(res == 0, "Failed to display file: %s", strerror(errno));

  mark_point();
  res = pr_response_get_last(p, &last_resp_code, &last_resp_msg);
  fail_unless(res == 0, "Failed to get last response values: %s (%d)",
    strerror(errno), errno);

  fail_unless(last_resp_code != NULL,
    "Last response code is unexpectedly null");
  fail_unless(strcmp(last_resp_code, resp_code) == 0,
    "Expected response code '%s', got '%s'", resp_code, last_resp_code);

  fail_unless(last_resp_msg != NULL,
    "Last response message is unexpectedly null");

  /* Send the display file NOW, with no EOM */

  mark_point();
  res = pr_display_file(path, NULL, resp_code,
    PR_DISPLAY_FL_SEND_NOW|PR_DISPLAY_FL_NO_EOM);
  fail_unless(res == 0, "Failed to display file: %s", strerror(errno));

  mark_point();
  res = pr_response_get_last(p, &last_resp_code, &last_resp_msg);
  fail_unless(res == 0, "Failed to get last response values: %s (%d)",
    strerror(errno), errno);

  fail_unless(last_resp_code != NULL,
    "Last response code is unexpectedly null");
  fail_unless(strcmp(last_resp_code, resp_code) == 0,
    "Expected response code '%s', got '%s'", resp_code, last_resp_code);

  fail_unless(last_resp_msg != NULL,
    "Last response message is unexpectedly null");

  /* With MultilineRFC2228 on */
  mark_point();
  res = pr_display_file(path, NULL, resp_code,
    PR_DISPLAY_FL_SEND_NOW|PR_DISPLAY_FL_NO_EOM);
  fail_unless(res == 0, "Failed to display file: %s", strerror(errno));

  mark_point();
  res = pr_display_file(path, NULL, resp_code, PR_DISPLAY_FL_SEND_NOW);
  fail_unless(res == 0, "Failed to display file: %s", strerror(errno));

  /* With session.auth_mech */
  session.auth_mech = "testsuite";

  mark_point();
  res = pr_display_file(path, NULL, resp_code,
    PR_DISPLAY_FL_SEND_NOW|PR_DISPLAY_FL_NO_EOM);
  fail_unless(res == 0, "Failed to display file: %s", strerror(errno));

  mark_point();
  res = pr_display_file(path, NULL, resp_code, PR_DISPLAY_FL_SEND_NOW);
  fail_unless(res == 0, "Failed to display file: %s", strerror(errno));
}
END_TEST

START_TEST (display_fh_test) {
  pr_fh_t *fh;
  int res;
  const char *path = NULL, *resp_code = NULL;
  const char *last_resp_code = NULL, *last_resp_msg = NULL;

  res = pr_display_fh(NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(display_test_file);
  res = write_file(display_test_file, display_lines, 4);
  fail_unless(res == 0, "Failed to write display file: %s", strerror(errno));

  path = display_test_file;
  fh = pr_fsio_open(path, O_RDONLY);
  fail_unless(fh != NULL, "Failed to open '%s': %s", path, strerror(errno));

  mark_point();
  res = pr_display_fh(fh, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null resp_code argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  resp_code = R_200;
  pr_response_set_pool(p);

  mark_point();
  res = pr_display_fh(fh, NULL, resp_code, 0);
  fail_unless(res == 0, "Failed to display file: %s", strerror(errno));

  mark_point();
  res = pr_response_get_last(p, &last_resp_code, &last_resp_msg);
  fail_unless(res == 0, "Failed to get last response values: %s (%d)",
    strerror(errno), errno);

  fail_unless(last_resp_code != NULL,
    "Last response code is unexpectedly null");
  fail_unless(strcmp(last_resp_code, resp_code) == 0,
    "Expected response code '%s', got '%s'", resp_code, last_resp_code);

  fail_unless(last_resp_msg != NULL,
    "Last response message is unexpectedly null");
}
END_TEST

Suite *tests_get_display_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("display");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, display_file_test);
  tcase_add_test(testcase, display_fh_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
