/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2008-2017 The ProFTPD Project team
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

/* Class API tests */

#include "tests.h"

static pool *p = NULL;

/* Fixtures */

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  main_server = pcalloc(p, sizeof(server_rec));
  main_server->pool = p;

  init_class();
  init_netaddr();
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
    permanent_pool = NULL;
  } 
}

/* Tests */

START_TEST (class_open_test) {
  int res;
  const char *name;

  res = pr_class_open(NULL, NULL);
  fail_unless(res == -1, "Failed to handle NULL arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_class_open(p, NULL);
  fail_unless(res == -1, "Failed to handle NULL name argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  name = "foo";
  res = pr_class_open(NULL, name);
  fail_unless(res == -1, "Failed to handle NULL pool argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_class_open(p, name);
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));
  fail_unless(main_server->config_type == CONF_CLASS,
    "Expected config_type of %d, got %d", CONF_CLASS, main_server->config_type);
}
END_TEST

START_TEST (class_add_acl_test) {
  pr_netacl_t *acl;
  int res;

  res = pr_class_add_acl(NULL);
  fail_unless(res == -1, "Failed to handle NULL argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  acl = pr_netacl_create(p, "all");
  fail_unless(acl != NULL, "Failed to handle ACL string 'all': %s",
    strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == -1, "Failed to handle unopened class");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  res = pr_class_open(p, "foo");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL: %s", strerror(errno));
}
END_TEST

START_TEST (class_add_note_test) {
  const char *k = NULL;
  void *v = NULL;
  size_t vsz = 0;
  int res;

  res = pr_class_add_note(k, v, vsz);
  fail_unless(res == -1, "Failed to handle NULL argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  k = "KEY";
  v = "VALUE";
  vsz = 6;

  res = pr_class_add_note(k, v, vsz);
  fail_unless(res == -1, "Failed to handle unopened class");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  res = pr_class_open(p, "foo");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  res = pr_class_add_note(k, v, vsz);
  fail_unless(res == 0, "Failed to add note: %s", strerror(errno));
}
END_TEST

START_TEST (class_close_test) {
  pr_netacl_t *acl;
  int res;

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close nonexistent current class: %s",
    strerror(errno));

  res = pr_class_open(p, "foo");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == -1, "Failed to close empty class");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");
  fail_unless(main_server->config_type == CONF_ROOT,
    "Expected config_type of %d, got %d", CONF_ROOT, main_server->config_type);

  res = pr_class_open(p, "foo");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "all");
  fail_unless(acl != NULL, "Failed to handle ACL string 'all': %s",
    strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));
  fail_unless(main_server->config_type == CONF_ROOT,
    "Expected config_type of %d, got %d", CONF_ROOT, main_server->config_type);
}
END_TEST

START_TEST (class_set_satisfy_test) {
  int res;

  res = pr_class_set_satisfy(PR_CLASS_SATISFY_ANY);
  fail_unless(res == -1, "Failed to handle nonexistent current class");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  res = pr_class_open(p, "foo");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  res = pr_class_set_satisfy(PR_CLASS_SATISFY_ANY);
  fail_unless(res == 0, "Failed to set SATISFY_ANY: %s", strerror(errno));

  res = pr_class_set_satisfy(PR_CLASS_SATISFY_ALL);
  fail_unless(res == 0, "Failed to set SATISFY_ALL: %s", strerror(errno));

  res = pr_class_set_satisfy(-1);
  fail_unless(res == -1, "Failed to handle bad satisfy value");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");
}
END_TEST

START_TEST (class_get_test) {
  const pr_class_t *class;
  int res;
  pr_netacl_t *acl;

  class = pr_class_get(NULL);
  fail_unless(class == NULL, "Failed to handle empty class list");

  acl = pr_netacl_create(p, "all");
  fail_unless(acl != NULL, "Failed to handle ACL string 'all': %s",
    strerror(errno));

  res = pr_class_open(p, "foo");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL: %s", strerror(errno));

  class = pr_class_get(NULL);
  fail_unless(class == NULL, "Failed to handle unclosed class in list");

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  class = pr_class_get(NULL);
  fail_unless(class != NULL, "Failed to get class in list: %s",
    strerror(errno));
  fail_unless(strcmp(class->cls_name, "foo") == 0,
    "Expected '%s', got '%s'", "foo", class->cls_name);

  class = pr_class_get(class);
  fail_unless(class == NULL, "Failed to return NULL for end-of-list");
}
END_TEST

START_TEST (class_find_test) {
  const pr_class_t *class;
  pr_netacl_t *acl;
  int res;

  class = pr_class_find(NULL);
  fail_unless(class == NULL, "Failed to handle NULL argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  class = pr_class_find("foo");
  fail_unless(class == NULL, "Failed to handle empty list");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");

  acl = pr_netacl_create(p, "all");
  fail_unless(acl != NULL, "Failed to handle ACL string 'all': %s",
    strerror(errno));

  res = pr_class_open(p, "foo");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL: %s", strerror(errno));

  class = pr_class_find("foo");
  fail_unless(class == NULL, "Failed to handle empty list");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  class = pr_class_find("foo");
  fail_unless(class != NULL, "Failed to handle class 'foo': %s",
    strerror(errno));

  class = pr_class_find("bar");
  fail_unless(class == NULL, "Failed to handle nonexistent class");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");
}
END_TEST

START_TEST (class_satisfied_test) {
  const pr_netaddr_t *addr;
  const pr_class_t *cls;
  pr_netacl_t *acl;
  int res;

  /* Reset the class list. */
  init_class();

  mark_point();
  res = pr_class_satisfied(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null class");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_class_open(p, "localhost");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  cls = pr_class_find("localhost");
  fail_unless(cls != NULL, "Failed to find class 'localhost': %s",
    strerror(errno));

  mark_point();
  res = pr_class_satisfied(p, cls, NULL);
  fail_unless(res < 0, "Failed to handle null addr");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  addr = pr_netaddr_get_addr(p, "localhost", FALSE);
  fail_unless(addr != NULL, "Failed to get addr: %s", strerror(errno));

  mark_point();
  res = pr_class_satisfied(p, cls, addr);
  fail_unless(res == TRUE, "Class not satisfied by address: %s",
    strerror(errno));

  res = pr_class_open(p, "!localhost");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "!127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  cls = pr_class_find("!localhost");
  fail_unless(cls != NULL, "Failed to find class '!localhost': %s",
    strerror(errno));

  mark_point();
  res = pr_class_satisfied(p, cls, addr);
  fail_unless(res == FALSE, "Class satisfied unexpectedly by address");
}
END_TEST

START_TEST (class_match_addr_test) {
  const pr_netaddr_t *addr;
  const pr_class_t *class;
  pr_netacl_t *acl;
  int res;

  /* Reset the class list. */
  init_class();

  mark_point();
  class = pr_class_match_addr(NULL);
  fail_unless(class == NULL, "Failed to handle NULL argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  addr = pr_netaddr_get_addr(p, "localhost", FALSE);
  fail_unless(addr != NULL, "Failed to get addr: %s", strerror(errno));

  class = pr_class_match_addr(addr);
  fail_unless(class == NULL, "Failed to handle empty class list");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");

  res = pr_class_open(p, "localhost");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  res = pr_class_open(p, "!localhost");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "!127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  class = pr_class_match_addr(addr);
  fail_unless(class != NULL, "Failed to match class for addr: %s",
    strerror(errno));
  fail_unless(strcmp(class->cls_name, "localhost") == 0,
    "Expected '%s', got '%s'", "localhost", class->cls_name);

  /* Reset the class list, add classes in a different order, and try again. */
  init_class();

  res = pr_class_open(p, "!localhost");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "!127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  res = pr_class_open(p, "localhost");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  class = pr_class_match_addr(addr);
  fail_unless(class != NULL, "Failed to match class for addr: %s",
    strerror(errno));
  fail_unless(strcmp(class->cls_name, "localhost") == 0,
    "Expected '%s', got '%s'", "localhost", class->cls_name);

  /* Reset the class list, and see what happens when we try to match
   * the addr against an impossible set of rules.
   */
  init_class();

  res = pr_class_open(p, "impossible");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "!127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  acl = pr_netacl_create(p, "127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  res = pr_class_set_satisfy(PR_CLASS_SATISFY_ALL);
  fail_unless(res == 0, "Failed to set satisfy value: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  class = pr_class_match_addr(addr);
  fail_unless(class == NULL, "Unexpectedly matched class for addr");
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");

  /* Reset the class list, add two classes with identical rules, and
   * verify that the first matching class wins.
   */
  init_class();

  res = pr_class_open(p, "first");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  res = pr_class_open(p, "second");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  class = pr_class_match_addr(addr);
  fail_unless(class != NULL, "Failed to match class for addr: %s",
    strerror(errno));
  fail_unless(strcmp(class->cls_name, "first") == 0,
    "Expected '%s', got '%s'", "first", class->cls_name);

  init_class();

  res = pr_class_open(p, "second");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  res = pr_class_open(p, "first");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  class = pr_class_match_addr(addr);
  fail_unless(class != NULL, "Failed to match class for addr: %s",
    strerror(errno));
  fail_unless(strcmp(class->cls_name, "second") == 0,
    "Expected '%s', got '%s'", "second", class->cls_name);

  init_class();

  res = pr_class_open(p, "match");
  fail_unless(res == 0, "Failed to open class: %s", strerror(errno));

  acl = pr_netacl_create(p, "127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_class_add_acl(acl);
  fail_unless(res == 0, "Failed to add ACL to class: %s", strerror(errno));

  res = pr_class_set_satisfy(PR_CLASS_SATISFY_ALL);
  fail_unless(res == 0, "Failed to set satisfy value: %s", strerror(errno));

  res = pr_class_close();
  fail_unless(res == 0, "Failed to close class: %s", strerror(errno));

  class = pr_class_match_addr(addr);
  fail_unless(class != NULL, "Failed to match class for addr: %s",
    strerror(errno));
  fail_unless(strcmp(class->cls_name, "match") == 0,
    "Expected '%s', got '%s'", "match", class->cls_name);

}
END_TEST

Suite *tests_get_class_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("class");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, class_open_test);
  tcase_add_test(testcase, class_add_acl_test);
  tcase_add_test(testcase, class_add_note_test);
  tcase_add_test(testcase, class_close_test);
  tcase_add_test(testcase, class_set_satisfy_test);
  tcase_add_test(testcase, class_get_test);
  tcase_add_test(testcase, class_find_test);
  tcase_add_test(testcase, class_satisfied_test);
  tcase_add_test(testcase, class_match_addr_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
