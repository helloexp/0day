/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2008-2015 The ProFTPD Project team
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

/* Timers API tests */

#include "tests.h"

static pool *p = NULL;

static int repeat_cb = FALSE;
static unsigned int timer_triggered_count = 0;

/* Fixtures */

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  repeat_cb = FALSE;
  timer_triggered_count = 0;

  timers_init();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_use_stderr(TRUE);
    pr_trace_set_levels("timers", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_use_stderr(FALSE);
    pr_trace_set_levels("timers", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

/* Helper functions */

static void timers_handle_signals(void) {
  if (recvd_signal_flags) {
    recvd_signal_flags &= ~RECEIVED_SIG_ALRM;
    handle_alarm();
  }
}

static int timers_test_cb(CALLBACK_FRAME) {
  timer_triggered_count++;

  if (repeat_cb)
    return 1;

  return 0;
}

/* Tests */

START_TEST (timer_add_test) {
  int res;
  unsigned int ok = 0;

  res = pr_timer_add(-1, 0, NULL, NULL, NULL);
  fail_unless(res == -1, "Failed to handle negative seconds");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_timer_add(0, 0, NULL, NULL, NULL);
  fail_unless(res == -1, "Failed to handle null description");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_timer_add(0, 0, NULL, NULL, "test");
  fail_unless(res == -1, "Failed to handle zero count");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_timer_add(1, 0, NULL, NULL, "test");
  fail_unless(res == -1, "Failed to handle null callback");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_timer_add(1, 0, NULL, timers_test_cb, "test");
  fail_unless(res == 0, "Failed to allocate timer: %s", strerror(errno));

  res = pr_timer_add(1, 0, NULL, timers_test_cb, "test");
  fail_unless(res == -1, "Failed to handle duplicate timer: %s",
    strerror(errno));
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  sleep(2);
  timers_handle_signals();

  ok = 1;
  fail_unless(timer_triggered_count == ok ||
              timer_triggered_count == (ok - 1),
    "Timer failed to fire (expected count %u, got %u)", ok,
    timer_triggered_count);

  repeat_cb = TRUE;

  /* Make sure that pr_timer_add() returns an incrementing timer ID,
   * starting with 1024, if the input timer ID is -1.
   */
  res = pr_timer_add(1, -1, NULL, timers_test_cb, "test");
  fail_unless(res == 1024, "Failed to allocate timer: %s", strerror(errno));

  sleep(1);
  timers_handle_signals();

  /* Allow for races between timers and testsuite. Aren't timing-based
   * unit tests fun?
   */

  ok = 2;
  fail_unless(timer_triggered_count == ok || timer_triggered_count == (ok + 1),
    "Timer failed to fire (expected count %u, got %u)", ok,
    timer_triggered_count);

  sleep(1);
  timers_handle_signals();

  ok = 3;
  fail_unless(timer_triggered_count == ok || timer_triggered_count == (ok + 1),
    "Timer failed to fire (expected count %u, got %u)", ok,
    timer_triggered_count);
}
END_TEST

START_TEST (timer_remove_test) {
  int res;

  res = pr_timer_remove(0, NULL);
  fail_unless(res == 0);

  res = pr_timer_add(1, 0, NULL, timers_test_cb, "test");
  fail_unless(res == 0, "Failed to add timer (%d): %s", res, strerror(errno));

  res = pr_timer_remove(1, NULL);
  fail_unless(res == -1, "Failed to return -1 for non-matching timer ID");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");

  res = pr_timer_remove(0, NULL);
  fail_unless(res == 0, "Failed to remove timer (%d): %s", res,
    strerror(errno));

  fail_unless(timer_triggered_count == 0,
    "Expected trigger count of 0, got %u", timer_triggered_count);
}
END_TEST

START_TEST (timer_remove_multi_test) {
  int res;
  module m;

  /* By providing a negative timerno, the return value should be the
   * dynamically generated timerno, which is greater than or equal to
   * 1024.
   */
  res = pr_timer_add(3, -1, &m, timers_test_cb, "test1");
  fail_unless(res >= 1024, "Failed to add timer (%d): %s", res,
    strerror(errno));

  res = pr_timer_add(3, -1, &m, timers_test_cb, "test2");
  fail_unless(res >= 1024, "Failed to add timer (%d): %s", res,
    strerror(errno));

  res = pr_timer_add(3, -1, &m, timers_test_cb, "test3");
  fail_unless(res >= 1024, "Failed to add timer (%d): %s", res,
    strerror(errno));

  res = pr_timer_remove(-1, &m);
  fail_unless(res == 3, "Failed to remove timers (%d): %s", res,
    strerror(errno));
}
END_TEST

START_TEST (timer_reset_test) {
  int res;
  unsigned int ok = 0;

  mark_point();
  res = pr_timer_reset(0, NULL);
  fail_unless(res == -1, "Failed to handle empty timer list");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  mark_point();
  res = pr_timer_add(2, 1, NULL, timers_test_cb, "test");
  fail_unless(res == 1, "Failed to add timer: %s", strerror(errno));

  mark_point();
  res = pr_timer_reset(2, NULL);
  fail_unless(res == 0, "Expected timer ID 1, got %d", res);

  sleep(1);
  timers_handle_signals();

  mark_point();
  fail_unless(timer_triggered_count == ok,
    "Timer fired unexpectedly (expected count %u, got %u)", ok,
    timer_triggered_count);

  mark_point();
  res = pr_timer_reset(1, NULL);
  fail_unless(res == 1, "Failed to reset timer");

  sleep(1);
  timers_handle_signals();

  fail_unless(timer_triggered_count == ok,
    "Timer fired unexpectedly (expected count %u, got %u)", ok,
    timer_triggered_count);

  sleep(1);
  timers_handle_signals();

  ok = 1;
  fail_unless(timer_triggered_count == ok ||
              timer_triggered_count == (ok - 1),
    "Timer failed to fire (expected count %u, got %u)", ok,
    timer_triggered_count);
}
END_TEST

START_TEST (timer_sleep_test) {
  int res;

  res = pr_timer_sleep(0);
  fail_unless(res == -1, "Failed to handle sleep len of zero");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  pr_alarms_block();
  res = pr_timer_sleep(1);
  fail_unless(res == -1, "Failed to handle blocked alarms when sleeping");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  pr_alarms_unblock();

  res = pr_timer_sleep(1);
  fail_unless(res == 0, "Failed to sleep: %s", strerror(errno));
}
END_TEST

START_TEST (timer_usleep_test) {
  int res;

  res = pr_timer_usleep(0);
  fail_unless(res == -1, "Failed to handle sleep len of zero");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_timer_usleep(500000);
  fail_unless(res == 0, "Failed to sleep: %s", strerror(errno));
}
END_TEST

Suite *tests_get_timers_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("timers");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, timer_add_test);
  tcase_add_test(testcase, timer_remove_test);
  tcase_add_test(testcase, timer_remove_multi_test);
  tcase_add_test(testcase, timer_reset_test);
  tcase_add_test(testcase, timer_sleep_test);
  tcase_add_test(testcase, timer_usleep_test);

  /* Allow a longer timeout on these tests, as they will need a second or
   * two to actually run through the test itself, plus overhead.
   */
  tcase_set_timeout(testcase, 5);

  suite_add_tcase(suite, testcase);
  return suite;
}
