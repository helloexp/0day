/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2014-2017 The ProFTPD Project team
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

/* Configuration API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_config();
  pr_parser_prepare(p, NULL);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("config", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("config", 0, 0);
  }

  pr_parser_cleanup();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

START_TEST (config_init_config_test) {
  mark_point();
  init_config();

  mark_point();
  init_config();

  mark_point();
  init_config();
}
END_TEST

START_TEST (config_add_config_test) {
  int res;
  const char *name = NULL;
  config_rec *c = NULL;
  server_rec *s = NULL;

  s = pr_parser_server_ctxt_open("127.0.0.1");
  fail_unless(s != NULL, "Failed to open server context: %s", strerror(errno));

  name = "foo";

  mark_point();
  c = add_config(NULL, name);
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));
  fail_unless(c->config_type == 0, "Expected config_type 0, got %d",
    c->config_type);

  mark_point();
  pr_config_dump(NULL, s->conf, NULL);

  c = add_config_param_set(&(c->subset), "bar", 1, "baz");

  mark_point();
  pr_config_dump(NULL, s->conf, NULL);

  mark_point();
  res = remove_config(s->conf, name, FALSE);
  fail_unless(res > 0, "Failed to remove config '%s': %s", name,
    strerror(errno));
}
END_TEST

START_TEST (config_add_config_param_test) {
  int res;
  const char *name = NULL;
  config_rec *c = NULL;
  server_rec *s = NULL;

  s = pr_parser_server_ctxt_open("127.0.0.1");
  fail_unless(s != NULL, "Failed to open server context: %s", strerror(errno));
 
  c = add_config_param(NULL, 0, NULL);
  fail_unless(c == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno); 

  name = "foo";

  mark_point();
  c = add_config_param(name, 1, "bar");
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));
  fail_unless(c->config_type == CONF_PARAM, "Expected config_type %d, got %d",
    CONF_PARAM, c->config_type);

  mark_point();
  pr_config_dump(NULL, s->conf, NULL);

  mark_point();
  res = pr_config_remove(s->conf, name, PR_CONFIG_FL_PRESERVE_ENTRY, FALSE);
  fail_unless(res > 0, "Failed to remove config '%s': %s", name,
    strerror(errno));
}
END_TEST

START_TEST (config_add_config_param_set_test) {
  xaset_t *set = NULL;
  const char *name = NULL;
  config_rec *c = NULL;

  name = "foo";

  c = add_config_param_set(NULL, name, 0);
  fail_unless(c == NULL, "Failed to handle null set argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  c = add_config_param_set(&set, name, 0);
  fail_unless(c != NULL, "Failed to add config '%s' to set: %s", name,
    strerror(errno));
  fail_unless(c->config_type == CONF_PARAM, "Expected config_type %d, got %d",
    CONF_PARAM, c->config_type);
  fail_unless(c->argc == 0, "Expected argc 0, got %d", c->argc);

  c = add_config_param_set(&set, name, 2, "bar", "baz");
  fail_unless(c != NULL, "Failed to add config '%s' to set: %s", name,
    strerror(errno));
  fail_unless(c->config_type == CONF_PARAM, "Expected config_type %d, got %d",
    CONF_PARAM, c->config_type);
  fail_unless(c->argc == 2, "Expected argc 2, got %d", c->argc);
  fail_unless(strcmp("bar", (char *) c->argv[0]) == 0,
    "Expected argv[0] to be 'bar', got '%s'", (char *) c->argv[0]);
  fail_unless(strcmp("baz", (char *) c->argv[1]) == 0,
    "Expected argv[1] to be 'baz', got '%s'", (char *) c->argv[1]);
  fail_unless(c->argv[2] == NULL, "Expected argv[2] to be null");
}
END_TEST

START_TEST (config_add_config_param_str_test) {
  int res;
  const char *name = NULL;
  config_rec *c = NULL, *c2;
  server_rec *s = NULL;

  s = pr_parser_server_ctxt_open("127.0.0.1");
  fail_unless(s != NULL, "Failed to open server context: %s", strerror(errno));

  name = "foo";

  mark_point();
  c = add_config_param_str(name, 1, "bar");
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));
  fail_unless(c->config_type == CONF_PARAM, "Expected config_type %d, got %d",
    CONF_PARAM, c->config_type);

  c2 = add_config_param_str("foo2", 1, NULL);
  fail_unless(c2 != NULL, "Failed to add config 'foo2': %s", strerror(errno));

  mark_point();
  pr_config_dump(NULL, s->conf, NULL);

  mark_point();
  res = remove_config(s->conf, name, FALSE);
  fail_unless(res > 0, "Failed to remove config '%s': %s", name,
    strerror(errno));
}
END_TEST

START_TEST (config_add_server_config_param_str_test) {
  const char *name;
  config_rec *c;
  server_rec *s;

  mark_point();
  c = pr_conf_add_server_config_param_str(NULL, NULL, 0);
  fail_unless(c == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno));

  mark_point();
  s = pr_parser_server_ctxt_open("127.0.0.2");
  fail_unless(s != NULL, "Failed to open server context: %s", strerror(errno));

  mark_point();
  name = "foo";

  c = pr_conf_add_server_config_param_str(s, name, 1, "bar");
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  (void) remove_config(s->conf, name, FALSE);
}
END_TEST

START_TEST (config_add_config_set_test) {
  int flags = PR_CONFIG_FL_INSERT_HEAD, res;
  xaset_t *set = NULL;
  const char *name = NULL;
  config_rec *c = NULL;

  res = remove_config(NULL, NULL, FALSE);
  fail_unless(res == 0, "Failed to handle null arguments: %s", strerror(errno));

  name = "foo";

  c = add_config_set(NULL, name);
  fail_unless(c == NULL, "Failed to handle null set argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  c = add_config_set(&set, name);
  fail_unless(c != NULL, "Failed to add config '%s' to set: %s", name,
    strerror(errno));
  fail_unless(c->config_type == 0, "Expected config_type 0, got %d",
    c->config_type);

  res = remove_config(set, name, FALSE);
  fail_unless(res > 0, "Failed to remove config '%s': %s", name,
    strerror(errno));

  name = "bar";
  res = remove_config(set, name, FALSE);
  fail_unless(res == 0, "Removed config '%s' unexpectedly", name,
    strerror(errno));

  c = pr_config_add_set(&set, name, flags);
  fail_unless(c != NULL, "Failed to add config '%s' to set: %s", name,
    strerror(errno));

  /* XXX Note that calling this with recurse=TRUE yields a test timeout,
   * suggestive of an infinite loop that needs to be tracked down and
   * fixed.
   *
   * I suspect it's in find_config_next2() bit of code near the comment:
   *
   *  Restart the search at the previous level if required
   *
   * Given the "shallowness" of this particular set.
   */
  res = remove_config(set, name, FALSE);
  fail_unless(res > 0, "Failed to remove config '%s': %s", name,
    strerror(errno));
}
END_TEST

START_TEST (config_find_config_test) {
  int res;
  config_rec *c;
  xaset_t *set = NULL;
  const char *name;

  c = find_config(NULL, -1, NULL, FALSE);
  fail_unless(c == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  c = find_config_next(NULL, NULL, CONF_PARAM, NULL, FALSE);
  fail_unless(c == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();

  name = "foo";
  c = add_config_param_set(&set, name, 0);
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  name = "bar";
  c = find_config(set, -1, name, FALSE);
  fail_unless(c == NULL, "Failed to handle null arguments");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  mark_point();

  /* We expect to find "foo", but a 'next' should be empty. */

  name = "foo";
  c = find_config(set, -1, name, FALSE);
  fail_unless(c != NULL, "Failed to find config '%s': %s", name,
    strerror(errno));

  mark_point();

  c = find_config_next(c, c->next, -1, name, FALSE);
  fail_unless(c == NULL, "Found next config unexpectedly");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  /* Now add another config, find "foo" again; this time, a 'next' should
   * NOT be empty; it should find the 2nd config we added.
   */

  name = "foo2";
  c = add_config_param_set(&set, name, 0);
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  name = NULL;
  c = find_config(set, -1, name, FALSE);
  fail_unless(c != NULL, "Failed to find any config: %s", strerror(errno));

  mark_point();

  c = find_config_next(c, c->next, -1, name, FALSE);
  fail_unless(c != NULL, "Expected to find another config");

  mark_point();

  name = "foo";
  res = remove_config(set, name, FALSE);
  fail_unless(res > 0, "Failed to remove config '%s': %s", name,
    strerror(errno));

  mark_point();

  c = find_config(set, -1, name, FALSE);
  fail_unless(c == NULL, "Found config '%s' unexpectedly", name);
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  name = "other";
  c = find_config(set, -1, name, TRUE);
  fail_unless(c == NULL, "Found config '%s' unexpectedly (recurse = true)",
    name);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);
}
END_TEST

START_TEST (config_find_config2_test) {
  int res;
  config_rec *c;
  xaset_t *set = NULL;
  const char *name;
  unsigned long flags = 0;

  c = find_config2(NULL, -1, NULL, FALSE, flags);
  fail_unless(c == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();

  name = "foo";
  c = add_config_param_set(&set, name, 0);
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  name = "bar";
  c = find_config2(set, -1, name, FALSE, flags);
  fail_unless(c == NULL, "Failed to handle null arguments");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  mark_point();

  /* We expect to find "foo", but a 'next' should be empty. */
  name = "foo";
  c = find_config2(set, -1, name, FALSE, flags);
  fail_unless(c != NULL, "Failed to find config '%s': %s", name,
    strerror(errno));

  mark_point();

  c = find_config_next2(c, c->next, -1, name, FALSE, flags);
  fail_unless(c == NULL, "Found next config unexpectedly");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  /* Now add another config, find "foo" again; this time, a 'next' should
   * NOT be empty; it should find the 2nd config we added.
   */

  name = "foo2";
  c = add_config_param_set(&set, name, 0);
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  name = NULL;
  c = find_config2(set, -1, name, FALSE, flags);
  fail_unless(c != NULL, "Failed to find any config: %s", strerror(errno));

  mark_point();

  c = find_config_next2(c, c->next, -1, name, FALSE, flags);
  fail_unless(c != NULL, "Expected to find another config");

  mark_point();

  name = "foo";
  res = remove_config(set, name, FALSE);
  fail_unless(res > 0, "Failed to remove config '%s': %s", name,
    strerror(errno));

  mark_point();

  c = find_config2(set, -1, name, FALSE, flags);
  fail_unless(c == NULL, "Found config '%s' unexpectedly", name);
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));
}
END_TEST

START_TEST (config_find_config2_recurse_test) {
  int res;
  config_rec *c;
  xaset_t *set = NULL;
  const char *name;
  unsigned long flags = 0;

  c = find_config2(NULL, -1, NULL, TRUE, flags);
  fail_unless(c == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  mark_point();

  name = "foo";
  c = add_config_param_set(&set, name, 0);
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  name = "bar";
  c = find_config2(set, -1, name, TRUE, flags);
  fail_unless(c == NULL, "Failed to handle null arguments");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  mark_point();

  /* We expect to find "foo", but a 'next' should be empty. */
  name = "foo";
  c = find_config2(set, -1, name, TRUE, flags);
  fail_unless(c != NULL, "Failed to find config '%s': %s", name,
    strerror(errno));

  mark_point();

  c = find_config_next2(c, c->next, -1, name, TRUE, flags);
  fail_unless(c == NULL, "Found next config unexpectedly");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  /* Now add another config, find "foo" again; this time, a 'next' should
   * NOT be empty; it should find the 2nd config we added.
   */

  name = "foo2";
  c = add_config_param_set(&set, name, 0);
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  name = NULL;
  c = find_config2(set, -1, name, TRUE, flags);
  fail_unless(c != NULL, "Failed to find any config: %s", strerror(errno));

  mark_point();

  c = find_config_next2(c, c->next, -1, name, TRUE, flags);
  fail_unless(c != NULL, "Expected to find another config");

  mark_point();

  name = "foo";
  res = remove_config(set, name, FALSE);
  fail_unless(res > 0, "Failed to remove config '%s': %s", name,
    strerror(errno));

  mark_point();

  c = find_config2(set, -1, name, TRUE, flags);
  fail_unless(c == NULL, "Found config '%s' unexpectedly", name);
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));
}
END_TEST

START_TEST (config_get_param_ptr_test) {
  void *res;
  int count;
  xaset_t *set = NULL;
  config_rec *c;
  const char *name = NULL;

  res = get_param_ptr(NULL, NULL, FALSE);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  mark_point();

  name = "foo";
  c = add_config_param_set(&set, name, 1, "bar");
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  name = "bar";
  res = get_param_ptr(set, name, FALSE);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  mark_point();

  /* We expect to find "foo", but a 'next' should be empty. Note that we
   * need to reset the get_param_ptr tree.
   */
  get_param_ptr(NULL, NULL, FALSE);

  name = "foo";
  res = get_param_ptr(set, name, FALSE);
  fail_unless(res != NULL, "Failed to find config '%s': %s", name,
    strerror(errno));

  mark_point();

  res = get_param_ptr_next(name, FALSE);
  fail_unless(res == NULL, "Found next config unexpectedly");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));

  /* Now add another config, find "foo" again; this time, a 'next' should
   * NOT be empty; it should find the 2nd config we added.
   */

  name = "foo2";
  c = add_config_param_set(&set, name, 1, "baz");
  fail_unless(c != NULL, "Failed to add config '%s': %s", name,
    strerror(errno));

  get_param_ptr(NULL, NULL, FALSE);

  name = NULL;
  res = get_param_ptr(set, name, FALSE);
  fail_unless(res != NULL, "Failed to find any config: %s", strerror(errno));

  mark_point();

  res = get_param_ptr_next(name, FALSE);
  fail_unless(res != NULL, "Expected to find another config");

  res = get_param_ptr_next(name, FALSE);
  fail_unless(res == NULL, "Found another config unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();

  name = "foo";
  count = remove_config(set, name, FALSE);
  fail_unless(count > 0, "Failed to remove config '%s': %s", name,
    strerror(errno));

  mark_point();

  res = get_param_ptr(set, name, FALSE);
  fail_unless(res == NULL, "Found config '%s' unexpectedly", name);
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT, got %d (%s)",
    errno, strerror(errno));
}
END_TEST

START_TEST (config_set_get_id_test) {
  unsigned int id, res;
  const char *name;

  res = pr_config_get_id(NULL);
  fail_unless(res == 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  res = pr_config_set_id(NULL);
  fail_unless(res == 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %d (%s)",
    errno, strerror(errno));

  name = "foo";

  id = pr_config_set_id(name);
  fail_unless(id > 0, "Failed to set ID for config '%s': %s", name,
    strerror(errno));

  res = pr_config_get_id(name);
  fail_unless(res == id, "Expected ID %u for config '%s', found %u", id,
    name, res);
}
END_TEST

START_TEST (config_merge_down_test) {
  xaset_t *set;
  config_rec *c, *src, *dst;
  const char *name;

  mark_point();
  pr_config_merge_down(NULL, FALSE);

  mark_point();
  set = xaset_create(p, NULL);
  pr_config_merge_down(set, FALSE);

  name = "foo";
  c = add_config_param_set(&set, name, 0);

  mark_point();
  pr_config_merge_down(set, FALSE);

  name = "bar";
  c = add_config_param_set(&set, name, 1, "baz");
  c->flags |= CF_MERGEDOWN;

  mark_point();
  pr_config_merge_down(set, FALSE);

  name = "BAZ";
  c = add_config_param_set(&set, name, 2, "quxx", "Quzz");
  c->flags |= CF_MERGEDOWN_MULTI;

  mark_point();
  pr_config_merge_down(set, FALSE);

  /* Add a config to the subsets, with the same name and same args. */
  name = "<Anonymous>";
  src = add_config_param_set(&set, name, 0);
  src->config_type = CONF_ANON;

  mark_point();
  pr_config_merge_down(set, FALSE);

  name = "<Directory>";
  dst = add_config_param_set(&set, name, 1, "/baz");
  dst->config_type = CONF_DIR;

  name = "foo";
  c = add_config_param_set(&(src->subset), name, 1, "alef");
  c->flags |= CF_MERGEDOWN;

  c = add_config_param_set(&(dst->subset), name, 1, "alef");
  c->flags |= CF_MERGEDOWN;

  mark_point();
  pr_config_merge_down(set, FALSE);

  /* Add a config to the subsets, with the same name and diff args. */
  name = "alef";
  c = add_config_param_set(&(src->subset), name, 1, "alef");
  c->flags |= CF_MERGEDOWN;

  c = add_config_param_set(&(dst->subset), name, 2, "bet", "vet");
  c->flags |= CF_MERGEDOWN;

  c = add_config_param_set(&(src->subset), "Bet", 3, "1", "2", "3");
  c->config_type = CONF_LIMIT;
  c->flags |= CF_MERGEDOWN;

  mark_point();
  pr_config_merge_down(set, FALSE);
}
END_TEST

Suite *tests_get_config_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("config");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, config_init_config_test);
  tcase_add_test(testcase, config_add_config_test);
  tcase_add_test(testcase, config_add_config_param_test);
  tcase_add_test(testcase, config_add_config_param_set_test);
  tcase_add_test(testcase, config_add_config_param_str_test);
  tcase_add_test(testcase, config_add_server_config_param_str_test);
  tcase_add_test(testcase, config_add_config_set_test);
  tcase_add_test(testcase, config_find_config_test);
  tcase_add_test(testcase, config_find_config2_test);
  tcase_add_test(testcase, config_find_config2_recurse_test);
  tcase_add_test(testcase, config_get_param_ptr_test);
  tcase_add_test(testcase, config_set_get_id_test);
  tcase_add_test(testcase, config_merge_down_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
