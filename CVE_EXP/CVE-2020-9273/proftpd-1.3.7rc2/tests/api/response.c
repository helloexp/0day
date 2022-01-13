/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2011-2016 The ProFTPD Project team
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

/* Response API tests */

#include "tests.h"

extern pr_response_t *resp_list, *resp_err_list;

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

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

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (response_pool_get_test) {
  pool *res;

  res = pr_response_get_pool();
  fail_unless(res == NULL, "Response pool not null as expected");
}
END_TEST

START_TEST (response_pool_set_test) {
  pool *res;

  pr_response_set_pool(p);
  res = pr_response_get_pool();
  fail_unless(res == p, "Response pool not %p as expected", p);
}
END_TEST

START_TEST (response_add_test) {
  int res;
  const char *last_resp_code = NULL, *last_resp_msg = NULL;
  char *resp_code = R_200, *resp_msg = "OK";

  pr_response_set_pool(p);

  mark_point();
  pr_response_add(NULL, NULL);

  mark_point();
  pr_response_add(NULL, "%s", resp_msg);

  mark_point();
  pr_response_add(resp_code, "%s", resp_msg);
  pr_response_add(NULL, "%s", resp_msg);

  res = pr_response_get_last(p, &last_resp_code, &last_resp_msg);
  fail_unless(res == 0, "Failed to get last values: %d (%s)", errno,
    strerror(errno));

  fail_unless(last_resp_code != NULL, "Last response code unexpectedly null");
  fail_unless(strcmp(last_resp_code, resp_code) == 0,
    "Expected response code '%s', got '%s'", resp_code, last_resp_code);
  
  fail_unless(last_resp_msg != NULL, "Last response message unexpectedly null");
  fail_unless(strcmp(last_resp_msg, resp_msg) == 0,
    "Expected response message '%s', got '%s'", resp_msg, last_resp_msg);
}
END_TEST

START_TEST (response_add_err_test) {
  int res;
  const char *last_resp_code = NULL, *last_resp_msg = NULL;
  char *resp_code = R_450, *resp_msg = "Busy";

  pr_response_set_pool(p);

  mark_point();
  pr_response_add_err(NULL, NULL);

  mark_point();
  pr_response_add_err(resp_code, "%s", resp_msg);

  res = pr_response_get_last(p, &last_resp_code, &last_resp_msg);
  fail_unless(res == 0, "Failed to get last values: %d (%s)", errno,
    strerror(errno));

  fail_unless(last_resp_code != NULL, "Last response code unexpectedly null");
  fail_unless(strcmp(last_resp_code, resp_code) == 0,
    "Expected response code '%s', got '%s'", resp_code, last_resp_code);

  fail_unless(last_resp_msg != NULL, "Last response message unexpectedly null");
  fail_unless(strcmp(last_resp_msg, resp_msg) == 0,
    "Expected response message '%s', got '%s'", resp_msg, last_resp_msg);
}
END_TEST

START_TEST (response_get_last_test) {
  int res;
  const char *resp_code = NULL, *resp_msg = NULL;

  res = pr_response_get_last(NULL, NULL, NULL);
  fail_unless(res == -1, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected errno %d (%s), got %d (%s)",
    EINVAL, strerror(EINVAL), errno, strerror(errno));

  res = pr_response_get_last(p, NULL, NULL);
  fail_unless(res == -1, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected errno %d (%s), got %d (%s)",
    EINVAL, strerror(EINVAL), errno, strerror(errno));

  res = pr_response_get_last(p, &resp_code, &resp_msg);
  fail_unless(res == 0, "Failed to get last values: %d (%s)", errno,
    strerror(errno));

  fail_unless(resp_code == NULL,
    "Last response code not null as expected: %s", resp_code);
  fail_unless(resp_msg == NULL,
    "Last response message not null as expected: %s", resp_msg);
}
END_TEST

START_TEST (response_block_test) {
  int res;

  res = pr_response_block(-1);
  fail_unless(res == -1, "Failed to handle invalid argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)",
    EINVAL, strerror(errno), errno);

  res = pr_response_block(TRUE);
  fail_unless(res == 0, "Failed to block responses: %s", strerror(errno));

  res = pr_response_block(FALSE);
  fail_unless(res == 0, "Failed to unblock responses: %s", strerror(errno));
}
END_TEST

START_TEST (response_clear_test) {
  mark_point();
  pr_response_clear(NULL);

  pr_response_set_pool(p);
  pr_response_add(R_200, "%s", "OK");
  pr_response_clear(&resp_list);
}
END_TEST

static int response_netio_poll_cb(pr_netio_stream_t *nstrm) {
  /* Always return >0, to indicate that we haven't timed out, AND that there
   * is a writable fd available.
   */
  return 7;
}

static int response_netio_write_cb(pr_netio_stream_t *nstrm, char *buf,
    size_t buflen) {
  return buflen;
}

static unsigned int resp_nlines = 0;
static char *resp_line = NULL;

static char *response_handler_cb(pool *cb_pool, const char *fmt, ...) {
  char buf[PR_RESPONSE_BUFFER_SIZE] = {'\0'};
  va_list msg;

  va_start(msg, fmt);
  vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  buf[sizeof(buf)-1] = '\0';

  resp_nlines++;
  resp_line = pstrdup(cb_pool, buf);
  return resp_line;
}

START_TEST (response_flush_test) {
  int res, sockfd = -2;
  conn_t *conn;
  pr_netio_t *netio;

  mark_point();
  pr_response_flush(NULL);

  netio = pr_alloc_netio2(p, NULL, "testsuite");
  netio->poll = response_netio_poll_cb;
  netio->write = response_netio_write_cb;

  res = pr_register_netio(netio, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to register custom ctrl NetIO: %s",
    strerror(errno));

  conn = pr_inet_create_conn(p, sockfd, NULL, INPORT_ANY, FALSE);
  session.c = conn;

  pr_response_register_handler(response_handler_cb);

  resp_nlines = 0;
  resp_line = NULL;
  pr_response_set_pool(p);

  pr_response_add(R_200, "%s", "OK");
  pr_response_add(R_DUP, "%s", "Still OK");
  pr_response_add(R_DUP, "%s", "OK already!");
  pr_response_flush(&resp_list);

  pr_response_register_handler(NULL);
  pr_inet_close(p, session.c);
  session.c = NULL;
  pr_unregister_netio(PR_NETIO_STRM_CTRL);

  fail_unless(resp_nlines == 3, "Expected 3 response lines flushed, got %u",
    resp_nlines);
}
END_TEST

START_TEST (response_send_test) {
  int res, sockfd = -2;
  conn_t *conn;
  pr_netio_t *netio;

  netio = pr_alloc_netio2(p, NULL, "testsuite");
  netio->poll = response_netio_poll_cb;
  netio->write = response_netio_write_cb;

  res = pr_register_netio(netio, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to register custom ctrl NetIO: %s",
    strerror(errno));

  conn = pr_inet_create_conn(p, sockfd, NULL, INPORT_ANY, FALSE);
  session.c = conn;

  pr_response_register_handler(response_handler_cb);

  resp_nlines = 0;
  resp_line = NULL;
  pr_response_set_pool(p);

  pr_response_send(R_200, "%s", "OK");

  pr_response_register_handler(NULL);
  pr_inet_close(p, session.c);
  session.c = NULL;
  pr_unregister_netio(PR_NETIO_STRM_CTRL);

  fail_unless(resp_nlines == 1, "Expected 1 response line flushed, got %u",
    resp_nlines);
}
END_TEST

START_TEST (response_send_async_test) {
  int res, sockfd = -2;
  conn_t *conn;
  pr_netio_t *netio;

  netio = pr_alloc_netio2(p, NULL, "testsuite");
  netio->poll = response_netio_poll_cb;
  netio->write = response_netio_write_cb;

  res = pr_register_netio(netio, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to register custom ctrl NetIO: %s",
    strerror(errno));

  conn = pr_inet_create_conn(p, sockfd, NULL, INPORT_ANY, FALSE);
  session.c = conn;

  pr_response_register_handler(response_handler_cb);

  resp_nlines = 0;
  resp_line = NULL;
  pr_response_set_pool(p);

  pr_response_send_async(R_200, "%s", "OK");

  pr_response_register_handler(NULL);
  pr_inet_close(p, session.c);
  session.c = NULL;
  pr_unregister_netio(PR_NETIO_STRM_CTRL);

  fail_unless(resp_nlines == 1, "Expected 1 response line flushed, got %u",
    resp_nlines);
  fail_unless(resp_line != NULL, "Expected response line");
  fail_unless(strcmp(resp_line, "200 OK\r\n") == 0,
    "Expected '200 OK', got '%s'", resp_line);
}
END_TEST

START_TEST (response_send_raw_test) {
  int res, sockfd = -2;
  conn_t *conn;
  pr_netio_t *netio;

  netio = pr_alloc_netio2(p, NULL, "testsuite");
  netio->poll = response_netio_poll_cb;
  netio->write = response_netio_write_cb;

  res = pr_register_netio(netio, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to register custom ctrl NetIO: %s",
    strerror(errno));

  conn = pr_inet_create_conn(p, sockfd, NULL, INPORT_ANY, FALSE);
  session.c = conn;

  pr_response_register_handler(response_handler_cb);

  resp_nlines = 0;
  resp_line = NULL;
  pr_response_set_pool(p);

  pr_response_send_raw("%s", "OK");

  pr_response_register_handler(NULL);
  pr_inet_close(p, session.c);
  session.c = NULL;
  pr_unregister_netio(PR_NETIO_STRM_CTRL);

  fail_unless(resp_nlines == 1, "Expected 1 response line flushed, got %u",
    resp_nlines);
}
END_TEST

#if defined(TEST_BUG3711)
START_TEST (response_pool_bug3711_test) {
  cmd_rec *cmd;
  pool *resp_pool, *cmd_pool;
  char *err_code = R_450, *err_msg = "Busy";

  resp_pool = make_sub_pool(p);
  cmd_pool = make_sub_pool(p);

  cmd = pr_cmd_alloc(cmd_pool, 1, "foo");

  pr_response_set_pool(cmd->pool);
  pr_response_add_err(err_code, "%s", err_msg);

  /* We expect segfaults here, so use the mark_point() function to get
   * more accurate reporting of the problematic line of code in the
   * error logs.
   */
  mark_point();

  /* We explicitly do NOT reset the Response API pool here, to emulate the
   * behavior of Bug#3711.
   *
   * In the future, we could address this by proving a Pool API function
   * that e.g. the Response API could use, to check whether the given
   * pool is still a valid pool.  To do this, the Pool API would keep a
   * list of allocated pools, which would then be scanned.  In practice such
   * a list is maintained, albeit in a tree form.  And there is tracking
   * of the root trees for pools; permanent_pool is not the only root pool
   * which can be created/used.
   */
  destroy_pool(cmd_pool);

  mark_point();
  pr_response_add_err(err_code, "%s", err_msg);

  mark_point();
  pr_response_add_err(err_code, "%s", err_msg);

  mark_point();
  pr_response_add_err(err_code, "%s", err_msg);
}
END_TEST
#endif /* TEST_BUG3711 */

Suite *tests_get_response_suite(void) {
  Suite *suite;
  TCase *testcase;
#if defined(TEST_BUG3711)
  int bug3711_signo = 0;
#endif /* TEST_BUG3711 */

  suite = suite_create("response");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, response_pool_get_test);
  tcase_add_test(testcase, response_pool_set_test);
  tcase_add_test(testcase, response_add_test);
  tcase_add_test(testcase, response_add_err_test);
  tcase_add_test(testcase, response_get_last_test);

  tcase_add_test(testcase, response_block_test);
  tcase_add_test(testcase, response_clear_test);
  tcase_add_test(testcase, response_flush_test);
  tcase_add_test(testcase, response_send_test);
  tcase_add_test(testcase, response_send_async_test);
  tcase_add_test(testcase, response_send_raw_test);

#if defined(TEST_BUG3711)
  /* We expect this test to fail due to a segfault; see Bug#3711.
   *
   * Note that on some platforms (e.g. Darwin), the test case should fail
   * with a SIGBUS rather than SIGSEGV, hence the conditional here.
   */
#if defined(DARWIN9) || defined(DARWIN10) || defined(DARWIN11)
  bug3711_signo = SIGBUS;
#else
  bug3711_signo = SIGSEGV;
#endif

  /* Disable this test for now; it's a reproduction recipe rather than
   * a regression test, and only generates core files which can litter
   * the filesystems of build/test machines needlessly.
   */
  tcase_add_test_raise_signal(testcase, response_pool_bug3711_test,
    bug3711_signo);
#endif /* TEST_BUG3711 */

  suite_add_tcase(suite, testcase);
  return suite;
}
