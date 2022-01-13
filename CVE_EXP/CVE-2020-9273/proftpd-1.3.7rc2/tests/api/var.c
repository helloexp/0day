/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2008-2011 The ProFTPD Project team
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

/* Var API tests */

#include "tests.h"

static pool *p = NULL;

/* Fixtures */

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  (void) var_init();
}

static void tear_down(void) {
  (void) var_free();

  if (p) {
    destroy_pool(p);
    p = NULL;
    permanent_pool = NULL;
  } 
}

/* Helper functions */

static const char *var_cb(void *data, size_t datasz) {
  return "baz";
}

/* Tests */

START_TEST (var_set_test) {
  int res;
  const char *key;

  (void) var_free();

  res = pr_var_set(NULL, NULL, NULL, 0, NULL, NULL, 0);
  fail_unless(res == -1, "Failed to handle uninitialized Var table");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  (void) var_init();

  res = pr_var_set(NULL, NULL, NULL, 0, NULL, NULL, 0);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_var_set(p, NULL, NULL, 0, NULL, NULL, 0);
  fail_unless(res == -1, "Failed to handle null key");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  key = "fo";

  res = pr_var_set(p, key, NULL, 0, NULL, NULL, 0);
  fail_unless(res == -1, "Failed to handle null val");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_var_set(p, key, NULL, 0, "bar", NULL, 0);
  fail_unless(res == -1, "Failed to handle bad key name");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  key = "fooo";

  res = pr_var_set(p, key, NULL, 0, "bar", NULL, 0);
  fail_unless(res == -1, "Failed to handle bad key name");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  key = "%{foo";

  res = pr_var_set(p, key, NULL, 0, "bar", NULL, 0);
  fail_unless(res == -1, "Failed to handle bad key name");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  key = "%{}";

  res = pr_var_set(p, key, NULL, 0, "bar", NULL, 0);
  fail_unless(res == -1, "Failed to handle bad key name");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  key = "%{foo}";

  res = pr_var_set(p, key, NULL, 0, "bar", NULL, 0);
  fail_unless(res == -1, "Failed to handle unknown type");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_var_set(p, key, NULL, PR_VAR_TYPE_STR, "bar", "bar", 0);
  fail_unless(res == -1, "Failed to handle data with zero len");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_var_set(p, key, NULL, PR_VAR_TYPE_STR, "bar", NULL, 1);
  fail_unless(res == -1, "Failed to handle null data with non-zero len");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_var_set(p, key, NULL, PR_VAR_TYPE_STR, "bar", NULL, 0);
  fail_unless(res == 0, "Failed to add str var: %s", strerror(errno));

  res = pr_var_set(p, key, "test", PR_VAR_TYPE_FUNC, var_cb, NULL, 0);
  fail_unless(res == 0, "Failed to add cb var: %s", strerror(errno));
}
END_TEST

START_TEST (var_delete_test) {
  int res;
  const char *key = "%{foo}";

  (void) var_free();

  res = pr_var_delete(NULL);
  fail_unless(res == -1, "Failed to handle uninitialized Var table");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  (void) var_init();

  res = pr_var_delete(NULL);
  fail_unless(res == -1, "Failed to handle null key");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_var_delete(key);
  fail_unless(res == -1, "Failed to handle absent key");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");

  res = pr_var_set(p, key, "test", PR_VAR_TYPE_STR, "bar", NULL, 0);
  fail_unless(res == 0, "Failed to add var: %s", strerror(errno));

  res = pr_var_delete(key);
  fail_unless(res == 0, "Failed to delete var: %s", strerror(errno));

  res = pr_var_delete(key);
  fail_unless(res == -1, "Failed to handle absent key");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");
}
END_TEST

START_TEST (var_exists_test) {
  int res;
  const char *key; 

  (void) var_free();

  res = pr_var_exists(NULL);
  fail_unless(res == -1, "Failed to handle uninitialized Var table");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  (void) var_init();

  res = pr_var_exists(NULL);
  fail_unless(res == -1, "Failed to handle null key");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  key = "%{foo}";
  res = pr_var_exists(key);
  fail_unless(res == FALSE, "Failed to handle absent key");

  res = pr_var_set(p, key, NULL, PR_VAR_TYPE_STR, "bar", NULL, 0);
  fail_unless(res == 0, "Failed to add var: %s", strerror(errno));

  res = pr_var_exists(key);
  fail_unless(res == TRUE, "Failed to detect present key");
}
END_TEST

START_TEST (var_get_test) {
  int ok;
  const char *key, *res;

  (void) var_free();

  res = pr_var_get(NULL);
  fail_unless(res == NULL, "Failed to handle uninitialized Var table");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  (void) var_init();

  res = pr_var_get(NULL);
  fail_unless(res == NULL, "Failed to handle null key");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  key = "%{foo}";

  res = pr_var_get(key);
  fail_unless(res == NULL, "Failed to absent key");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");

  ok = pr_var_set(p, key, NULL, PR_VAR_TYPE_STR, "bar", NULL, 0);
  fail_unless(ok == 0, "Failed to add str var: %s", strerror(errno));

  res = pr_var_get(key);
  fail_unless(res != NULL, "Failed to get str var: %s", strerror(errno));
  fail_unless(strcmp(res, "bar") == 0, "Expected '%s', got '%s'", "bar", res);

  ok = pr_var_set(p, key, "test", PR_VAR_TYPE_FUNC, var_cb, NULL, 0);
  fail_unless(ok == 0, "Failed to add cb var: %s", strerror(errno));

  res = pr_var_get(key);
  fail_unless(res != NULL, "Failed to get str var: %s", strerror(errno));
  fail_unless(strcmp(res, "baz") == 0, "Expected '%s', got '%s'", "baz", res);
}
END_TEST

START_TEST (var_next_test) {
  int ok;
  const char *res, *desc;

  (void) var_free();

  res = pr_var_next(NULL);
  fail_unless(res == NULL, "Failed to handle uninitialized Var table");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  (void) var_init();

  res = pr_var_next(NULL);
  fail_unless(res == NULL, "Failed to handle empty table");

  ok = pr_var_set(p, "%{foo}", NULL, PR_VAR_TYPE_STR, "bar", NULL, 0);
  fail_unless(ok == 0, "Failed to add var: %s", strerror(errno));

  res = pr_var_next(&desc);
  fail_unless(res != NULL, "Failed to get next key: %s", strerror(errno));
  fail_unless(desc == NULL, "Expected no desc, got '%s'", desc);

  res = pr_var_next(&desc);
  fail_unless(res == NULL, "Expected no more keys, got '%s'", res);
}
END_TEST

START_TEST (var_rewind_test) {
  int ok;
  const char *res, *desc;

  (void) var_free();

  mark_point();
  pr_var_rewind();

  (void) var_init();

  pr_var_rewind();

  ok = pr_var_set(p, "%{foo}", "test", PR_VAR_TYPE_STR, "bar", NULL, 0);
  fail_unless(ok == 0, "Failed to add var: %s", strerror(errno));

  res = pr_var_next(&desc);
  fail_unless(res != NULL, "Failed to get next key: %s", strerror(errno));
  fail_unless(desc != NULL, "Expected non-null desc");
  fail_unless(strcmp(desc, "test") == 0, "Expected desc '%s', got '%s'",
    "test", desc);

  res = pr_var_next(&desc);
  fail_unless(res == NULL, "Expected no more keys, got '%s'", res);

  pr_var_rewind();

  res = pr_var_next(&desc);
  fail_unless(res != NULL, "Failed to get next key: %s", strerror(errno));
  fail_unless(desc != NULL, "Expected non-null desc");
  fail_unless(strcmp(desc, "test") == 0, "Expected desc '%s', got '%s'",
    "test", desc);

  res = pr_var_next(&desc);
  fail_unless(res == NULL, "Expected no more keys, got '%s'", res);
}
END_TEST

Suite *tests_get_var_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("var");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, var_set_test);
  tcase_add_test(testcase, var_delete_test);
  tcase_add_test(testcase, var_exists_test);
  tcase_add_test(testcase, var_get_test);
  tcase_add_test(testcase, var_next_test);
  tcase_add_test(testcase, var_rewind_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
