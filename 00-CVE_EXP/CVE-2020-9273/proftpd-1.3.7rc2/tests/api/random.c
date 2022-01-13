/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2017 The ProFTPD Project team
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
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

/* Random API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
    session.c = NULL;
    session.notes = NULL;
  }

  pr_random_init();
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
    session.c = NULL;
    session.notes = NULL;
  } 
}

START_TEST (random_next_range_10_test) {
  register unsigned int i;
  long min, max;

  min = -4;
  max = 5;

  for (i = 0; i < 10; i++) {
    long num;

    num = pr_random_next(min, max);
    fail_if(num < min, "random number %ld less than minimum %ld", num, min);
    fail_if(num > max, "random number %ld greater than maximum %ld", num, max);
  }
}
END_TEST

START_TEST (random_next_range_1000_test) {
  register int i;
  long min, max;
  int count = 10, seen[10];

  min = 0;
  max = count-1;

  memset(seen, 0, sizeof(seen));

  for (i = 0; i < 1000; i++) {
    long num;

    num = pr_random_next(min, max);
    fail_if(num < min, "random number %ld less than minimum %ld", num, min);
    fail_if(num > max, "random number %ld greater than maximum %ld", num, max);

    seen[num] = 1;
  }

  /* In 1000 rounds, the chances of seeing all 10 possible numbers is pretty
   * good, right?
   */
  for (i = 0; i < count; i++) {
    fail_unless(seen[i] == 1, "Expected to have generated number %d", i);
  }
}
END_TEST

Suite *tests_get_random_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("random");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, random_next_range_10_test);
  tcase_add_test(testcase, random_next_range_1000_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
