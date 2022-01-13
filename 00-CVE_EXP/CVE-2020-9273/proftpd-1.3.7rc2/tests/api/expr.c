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

/* Expression API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  main_server = pcalloc(p, sizeof(server_rec));
  main_server->pool = p;
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
    permanent_pool = NULL;
  } 
}

START_TEST (expr_create_test) {
  array_header *res;
  unsigned int expr_argc = 2;
  char *expr_argv[4] = { NULL, NULL, NULL, NULL };
  char **elts;

  res = pr_expr_create(NULL, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_expr_create(p, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null count, argv arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_expr_create(p, &expr_argc, NULL);
  fail_unless(res == NULL, "Failed to handle null argv argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_expr_create(p, NULL, expr_argv);
  fail_unless(res == NULL, "Failed to handle null argc argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_expr_create(NULL, &expr_argc, expr_argv);
  fail_unless(res == NULL, "Failed to handle null pool argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_expr_create(p, &expr_argc, expr_argv);
  fail_unless(res == NULL, "Failed to handle empty argv argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  expr_argc = 0;
  expr_argv[0] = "foo";
  expr_argv[1] = "bar";

  res = pr_expr_create(p, &expr_argc, expr_argv);
  fail_unless(res != NULL, "Failed to create expr: %s", strerror(errno));
  fail_unless(expr_argc == 0, "Failed to set negative argc to zero");
  fail_unless(res->nelts == expr_argc, "Expected %d, got %d", expr_argc,
    res->nelts);

  expr_argc = 1;
  expr_argv[0] = pstrdup(p, "foo");
  expr_argv[1] = NULL;

  res = pr_expr_create(p, &expr_argc, expr_argv);
  fail_unless(res != NULL, "Failed to create expr: %s", strerror(errno));
  fail_unless(res->nelts == expr_argc, "Expected %d, got %d", expr_argc,
    res->nelts);

  elts = res->elts;
  fail_unless(elts[0] == NULL, "Expected null, got '%s'", elts[0]);

  expr_argc = 2;
  expr_argv[0] = pstrdup(p, "foo");
  expr_argv[1] = pstrdup(p, "bar,baz,quxx");

  res = pr_expr_create(p, &expr_argc, expr_argv);
  fail_unless(res != NULL, "Failed to create expr: %s", strerror(errno));
  fail_unless(res->nelts == 3, "Expected %d, got %d", 3, res->nelts);

  elts = res->elts;
  fail_unless(strcmp(elts[0], "bar") == 0, "Expected '%s', got '%s'",
    "bar", elts[0]);

  elts = res->elts;
  fail_unless(strcmp(elts[1], "baz") == 0, "Expected '%s', got '%s'",
    "baz", elts[1]);

  elts = res->elts;
  fail_unless(strcmp(elts[2], "quxx") == 0, "Expected '%s', got '%s'",
    "quxx", elts[2]);

  expr_argc = 3;
  expr_argv[0] = pstrdup(p, "foo");
  expr_argv[1] = pstrdup(p, "bar,baz,quxx");
  expr_argv[2] = pstrdup(p, "alef");

  res = pr_expr_create(p, &expr_argc, expr_argv);
  fail_unless(res != NULL, "Failed to create expr: %s", strerror(errno));
  fail_unless(res->nelts == 4, "Expected %d, got %d", 4, res->nelts);

  elts = res->elts;
  fail_unless(strcmp(elts[0], "bar") == 0, "Expected '%s', got '%s'",
    "bar", elts[0]);

  elts = res->elts;
  fail_unless(strcmp(elts[1], "baz") == 0, "Expected '%s', got '%s'",
    "baz", elts[1]);

  elts = res->elts;
  fail_unless(strcmp(elts[2], "quxx") == 0, "Expected '%s', got '%s'",
    "quxx", elts[2]);

  elts = res->elts;
  fail_unless(strcmp(elts[3], "alef") == 0, "Expected '%s', got '%s'",
    "alef", elts[3]);
}
END_TEST

START_TEST (expr_eval_class_and_test) {
  pr_netacl_t *acl;
  char *names1[3] = { "foo", "bar", NULL }, *names2[2] = { "test", NULL },
    *names3[2] = { "!baz", NULL };
  int res;

  res = pr_expr_eval_class_and(NULL);
  fail_unless(res == -1, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  session.conn_class = NULL;

  res = pr_expr_eval_class_and(names1);
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  init_netaddr();
  init_class();

  res = pr_class_open(p, "test");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "all");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  session.conn_class = pr_class_find("test");
  fail_unless(session.conn_class != NULL, "Failed to find 'test' class: %s",
    strerror(errno));

  res = pr_expr_eval_class_and(names1);
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  res = pr_expr_eval_class_and(names2);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_class_and(names3);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");
}
END_TEST

START_TEST (expr_eval_class_or_test) {
  pr_netacl_t *acl;
  char *names1[3] = { "foo", "test", NULL }, *names2[2] = { "test", NULL },
    *names3[2] = { "!baz", NULL }, *names4[2] = { "foo", NULL };
  int res;

  res = pr_expr_eval_class_or(NULL);
  fail_unless(res == -1, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  session.conn_class = NULL;

  res = pr_expr_eval_class_or(names1);
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  init_netaddr();
  init_class();

  res = pr_class_open(p, "test");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "all");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  session.conn_class = pr_class_find("test");
  fail_unless(session.conn_class != NULL, "Failed to find 'test' class: %s",
    strerror(errno));

  res = pr_expr_eval_class_or(names1);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_class_or(names2);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_class_or(names3);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_class_or(names4);
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");
}
END_TEST

START_TEST (expr_eval_group_and_test) {
  char *names1[3] = { "foo", "bar", NULL }, *names2[2] = { "test", NULL },
    *names3[2] = { "!baz", NULL };
  int res;

  res = pr_expr_eval_group_and(NULL);
  fail_unless(res == -1, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  session.group = NULL;
  session.groups = NULL;

  res = pr_expr_eval_group_and(names1);
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  session.group = "test";

  res = pr_expr_eval_group_and(names1);
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  res = pr_expr_eval_group_and(names2);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_group_and(names3);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  session.group = NULL;
  session.groups = make_array(p, 2, sizeof(char *));
  *((char **) push_array(session.groups)) = "test";
  *((char **) push_array(session.groups)) = NULL;
  *((char **) push_array(session.groups)) = "spank";

  res = pr_expr_eval_group_and(names1);
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  res = pr_expr_eval_group_and(names2);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_group_and(names3);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");
}
END_TEST

START_TEST (expr_eval_group_or_test) {
  char *names1[3] = { "foo", "test", NULL }, *names2[2] = { "test", NULL },
    *names3[2] = { "!baz", NULL }, *names4[2] = { "foo", NULL };
  int res;

  res = pr_expr_eval_group_or(NULL);
  fail_unless(res == -1, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  session.group = NULL;
  session.groups = NULL;

  res = pr_expr_eval_group_or(names1);
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  session.group = "test";

  res = pr_expr_eval_group_or(names1);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_group_or(names2);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_group_or(names3);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_group_or(names4);
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  session.group = NULL;
  session.groups = make_array(p, 1, sizeof(char *));
  *((char **) push_array(session.groups)) = "test";

  res = pr_expr_eval_group_or(names1);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_group_or(names2);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_group_or(names3);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_group_or(names4);
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");
}
END_TEST

START_TEST (expr_eval_user_and_test) {
  char *names1[3] = { "foo", "bar", NULL }, *names2[2] = { "test", NULL },
    *names3[2] = { "!baz", NULL };
  int res;

  res = pr_expr_eval_user_and(NULL);
  fail_unless(res == -1, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  session.user = NULL;

  res = pr_expr_eval_user_and(names1);
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  session.user = "test";

  res = pr_expr_eval_user_and(names1);
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  res = pr_expr_eval_user_and(names2);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_user_and(names3);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");
}
END_TEST

START_TEST (expr_eval_user_or_test) {
  char *names1[3] = { "foo", "test", NULL }, *names2[2] = { "test", NULL },
    *names3[2] = { "!baz", NULL }, *names4[2] = { "foo", NULL };
  int res;

  res = pr_expr_eval_user_or(NULL);
  fail_unless(res == -1, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  session.user = NULL;

  res = pr_expr_eval_user_or(names1);
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  session.user = "test";

  res = pr_expr_eval_user_or(names1);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_user_or(names2);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_user_or(names3);
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_expr_eval_user_or(names4);
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");
}
END_TEST

Suite *tests_get_expr_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("expr");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, expr_create_test);
  tcase_add_test(testcase, expr_eval_class_and_test);
  tcase_add_test(testcase, expr_eval_class_or_test);
  tcase_add_test(testcase, expr_eval_group_and_test);
  tcase_add_test(testcase, expr_eval_group_or_test);
  tcase_add_test(testcase, expr_eval_user_and_test);
  tcase_add_test(testcase, expr_eval_user_or_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
