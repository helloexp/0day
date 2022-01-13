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

/* Event API tests */

#include "tests.h"

static pool *p = NULL;

/* Fixtures */

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  pr_event_unregister(NULL, NULL, NULL);
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

/* Helper functions */

static unsigned int event_triggered = 0;

static void event_cb(const void *event_data, void *user_data) {
  event_triggered++;
}

static void event_cb2(const void *event_data, void *user_data) {
}

static void event_cb3(const void *event_data, void *user_data) {
}

static unsigned int event_dumped = 0;

static void event_dump(const char *fmt, ...) {
  if (strncmp(fmt, "  ", 2) == 0) {
    event_dumped++;
  }
}

/* Tests */

START_TEST (event_register_test) {
  int res;
  const char *event = "foo";
  module m;

  res = pr_event_register(NULL, NULL, NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_event_register(NULL, event, NULL, NULL);
  fail_unless(res == -1, "Failed to handle null callback");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_event_register(NULL, NULL, event_cb, NULL);
  fail_unless(res == -1, "Failed to handle null event");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_event_register(NULL, event, event_cb, NULL);
  fail_unless(res == 0, "Failed to register event: %s", strerror(errno));

  res = pr_event_register(NULL, event, event_cb, NULL);
  fail_unless(res == -1, "Failed to handle duplicate registration");
  fail_unless(errno == EEXIST, "Failed to set errno to EEXIST");

  memset(&m, 0, sizeof(m));
  m.name = "testsuite";

  (void) pr_event_unregister(NULL, event, NULL);

  res = pr_event_register(&m, event, event_cb, NULL);
  fail_unless(res == 0, "Failed to register event with module: %s",
    strerror(errno));

  res = pr_event_register(&m, event, event_cb2, NULL);
  fail_unless(res == 0, "Failed to register event with module: %s",
    strerror(errno));

  pr_event_unregister(&m, event, event_cb2);
  pr_event_unregister(&m, event, event_cb);
  pr_event_unregister(&m, NULL, NULL);
}
END_TEST

START_TEST (event_unregister_test) {
  int res;
  const char *event = "foo";

  res = pr_event_unregister(NULL, NULL, NULL);
  fail_unless(res == 0, "Failed to handle empty event lists");

  res = pr_event_register(NULL, event, event_cb, NULL);
  fail_unless(res == 0, "Failed to register event: %s", strerror(errno));

  res = pr_event_unregister(NULL, "bar", NULL);
  fail_unless(res == -1, "Failed to handle unregistered event");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");

  res = pr_event_unregister(NULL, event, event_cb2);
  fail_unless(res == -1, "Failed to handle unregistered event");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");

  res = pr_event_unregister(NULL, event, event_cb);
  fail_unless(res == 0, "Failed to unregister event: %s", strerror(errno));

  res = pr_event_register(NULL, event, event_cb, NULL);
  fail_unless(res == 0, "Failed to register event: %s", strerror(errno));

  res = pr_event_unregister(NULL, event, NULL);
  fail_unless(res == 0, "Failed to unregister event: %s", strerror(errno));

  res = pr_event_register(NULL, event, event_cb, NULL);
  fail_unless(res == 0, "Failed to register event: %s", strerror(errno));

  res = pr_event_unregister(NULL, NULL, NULL);
  fail_unless(res == 0, "Failed to unregister event: %s", strerror(errno));
}
END_TEST

START_TEST (event_listening_test) {
  const char *event = "foo", *event2 = "bar";
  int res;

  res = pr_event_listening(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_event_listening(event);
  fail_unless(res == 0, "Failed to check for '%s' listeners: %s", event,
    strerror(errno));

  res = pr_event_register(NULL, event, event_cb2, NULL);
  fail_unless(res == 0, "Failed to register event '%s: %s", event,
    strerror(errno));

  res = pr_event_register(NULL, event2, event_cb2, NULL);
  fail_unless(res == 0, "Failed to register event '%s: %s", event2,
    strerror(errno));

  res = pr_event_listening(event);
  fail_unless(res == 1, "Expected 1 listener, got %d", res);

  res = pr_event_register(NULL, event, event_cb3, NULL);
  fail_unless(res == 0, "Failed to register event '%s: %s", event,
    strerror(errno));

  res = pr_event_listening(event);
  fail_unless(res == 2, "Expected 2 listeners, got %d", res);

  /* Unregister our listener, and make sure that the API indicates there
   * are no more listeners.
   */
  res = pr_event_unregister(NULL, event, NULL);
  fail_unless(res == 0, "Failed to unregister event '%s': %s", event,
    strerror(errno));

  res = pr_event_listening(event);
  fail_unless(res == 0, "Failed to check for '%s' listeners: %s", event,
    strerror(errno));

  res = pr_event_unregister(NULL, event2, NULL);
  fail_unless(res == 0, "Failed to unregister event '%s': %s", event2,
    strerror(errno));

  res = pr_event_listening(event);
  fail_unless(res == 0, "Failed to check for '%s' listeners: %s", event,
    strerror(errno));
}
END_TEST

START_TEST (event_generate_test) {
  int res;
  const char *event = "foo";

  pr_event_generate(NULL, NULL);
  fail_unless(event_triggered == 0, "Expected triggered count %u, got %u",
    0, event_triggered);
  
  pr_event_generate(event, NULL);
  fail_unless(event_triggered == 0, "Expected triggered count %u, got %u",
    0, event_triggered);

  res = pr_event_register(NULL, event, event_cb, NULL);
  fail_unless(res == 0, "Failed to register event: %s", strerror(errno));

  pr_event_generate("bar", NULL);
  fail_unless(event_triggered == 0, "Expected triggered count %u, got %u",
    0, event_triggered);

  pr_event_generate(event, NULL);
  fail_unless(event_triggered == 1, "Expected triggered count %u, got %u",
    1, event_triggered);

  pr_event_generate(event, NULL);
  fail_unless(event_triggered == 2, "Expected triggered count %u, got %u",
    2, event_triggered);

  res = pr_event_unregister(NULL, NULL, NULL);
  fail_unless(res == 0, "Failed to unregister events: %s", strerror(errno));

  pr_event_generate(event, NULL);
  fail_unless(event_triggered == 2, "Expected triggered count %u, got %u",
    2, event_triggered);
}
END_TEST

START_TEST (event_dump_test) {
  int res;
  const char *event = "foo";
  module m;

  pr_event_dump(NULL);
  fail_unless(event_dumped == 0, "Expected dumped count of %u, got %u",
    0, event_dumped);

  pr_event_dump(event_dump);
  fail_unless(event_dumped == 0, "Expected dumped count of %u, got %u",
    0, event_dumped);

  memset(&m, 0, sizeof(m));
  m.name = "testsuite";
  res = pr_event_register(&m, event, event_cb, NULL);
  fail_unless(res == 0, "Failed to register event '%s', callback %p: %s",
    event, event_cb, strerror(errno));

  pr_event_dump(event_dump);
  fail_unless(event_dumped == 1, "Expected dumped count of %u, got %u",
    1, event_dumped);

  event_dumped = 0;

  res = pr_event_register(NULL, event, event_cb2, NULL);
  fail_unless(res == 0, "Failed to register event '%s', callback %p: %s",
    event, event_cb2, strerror(errno));

  res = pr_event_register(NULL, "bar", event_cb2, NULL);
  fail_unless(res == 0, "Failed to register event 'bar', callback %p: %s",
    event_cb2, strerror(errno));

  pr_event_dump(event_dump);
  fail_unless(event_dumped == 3, "Expected dumped count of %u, got %u",
    3, event_dumped);
}
END_TEST

Suite *tests_get_event_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("event");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, event_register_test);
  tcase_add_test(testcase, event_unregister_test);
  tcase_add_test(testcase, event_listening_test);
  tcase_add_test(testcase, event_generate_test);
  tcase_add_test(testcase, event_dump_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
