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

/* Version API tests */

#include "tests.h"

START_TEST (version_get_module_api_number_test) {
  unsigned long res;

  res = pr_version_get_module_api_number();
  fail_if(res == 0, "Expected value, got zero");
  fail_unless(res == PR_MODULE_API_VERSION, "Expected %lu, got %lu",
    PR_MODULE_API_VERSION, res);
}
END_TEST

START_TEST (version_get_number_test) {
  unsigned long res;

  res = pr_version_get_number();
  fail_if(res == 0, "Expected value, got zero");
  fail_unless(res == PROFTPD_VERSION_NUMBER, "Expected %lu, got %lu",
    PROFTPD_VERSION_NUMBER, res);
}
END_TEST

START_TEST (version_get_str_test) {
  const char *res;

  res = pr_version_get_str();
  fail_if(res == NULL, "Expected string, got null");
  fail_unless(strcmp(res, PROFTPD_VERSION_TEXT) == 0, "Expected '%s', '%s'",
    PROFTPD_VERSION_TEXT, res);
}
END_TEST

Suite *tests_get_version_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("version");
  testcase = tcase_create("base");

  tcase_add_test(testcase, version_get_module_api_number_test);
  tcase_add_test(testcase, version_get_number_test);
  tcase_add_test(testcase, version_get_str_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
