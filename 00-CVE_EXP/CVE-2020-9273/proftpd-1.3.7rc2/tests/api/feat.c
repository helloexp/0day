/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2008-2016 The ProFTPD Project team
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

/* Feat API tests */

#include "tests.h"

static pool *p = NULL;

/* Fixtures */

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
    permanent_pool = NULL;
  } 
}

/* Tests */

START_TEST (feat_add_test) {
  int res;
  const char *key;

  res = pr_feat_add(NULL);
  fail_unless(res == -1, "Failed to handle null feat");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  key = "foo";

  res = pr_feat_add(key);
  fail_unless(res == 0, "Failed to add feat: %s", strerror(errno));

  res = pr_feat_add(key);
  fail_unless(res == -1, "Failed to handle duplicate feat");
  fail_unless(errno == EEXIST, "Failed to set errno to EEXIST");
}
END_TEST

START_TEST (feat_get_test) {
  int ok;
  const char *res;

  res = pr_feat_get();
  fail_unless(res == NULL, "Failed to handle empty feat");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  ok = pr_feat_add("foo");
  fail_unless(ok == 0, "Failed to add feat: %s", strerror(errno));

  res = pr_feat_get();
  fail_unless(res != NULL, "Failed to get feat: %s", strerror(errno));
  fail_unless(strcmp(res, "foo") == 0, "Expected '%s', got '%s'", "foo", res);

  res = pr_feat_get();
  fail_unless(res != NULL, "Failed to get feat: %s", strerror(errno));
  fail_unless(strcmp(res, "foo") == 0, "Expected '%s', got '%s'", "foo", res);
}
END_TEST

START_TEST (feat_get_next_test) {
  int ok;
  const char *res;

  res = pr_feat_get_next();
  fail_unless(res == NULL, "Failed to handle empty feat");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  ok = pr_feat_add("foo");
  fail_unless(ok == 0, "Failed to add feat: %s", strerror(errno));

  res = pr_feat_get_next();
  fail_unless(res != NULL, "Failed to get feat: %s", strerror(errno));
  fail_unless(strcmp(res, "foo") == 0, "Expected '%s', got '%s'", "foo", res);

  res = pr_feat_get_next();
  fail_unless(res == NULL, "Expected null, got '%s'", res);
}
END_TEST

START_TEST (feat_remove_test) {
  int res;
  const char *feat;

  res = pr_feat_remove(NULL);
  fail_unless(res == -1, "Failed to handle empty feat");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  feat = "foo";
  res = pr_feat_add(feat);
  fail_unless(res == 0, "Failed to add feat: %s", strerror(errno));

  res = pr_feat_remove(NULL);
  fail_unless(res == -1, "Failed to handle null feat");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_feat_remove(feat);
  fail_unless(res == 0, "Failed to remove feat: %s", strerror(errno));

  res = pr_feat_remove(feat);
  fail_unless(res == -1, "Failed to detected removed feat");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");
}
END_TEST

Suite *tests_get_feat_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("feat");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, feat_add_test);
  tcase_add_test(testcase, feat_get_test);
  tcase_add_test(testcase, feat_get_next_test);
  tcase_add_test(testcase, feat_remove_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
