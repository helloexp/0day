/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2015 The ProFTPD Project team
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

/* Encode API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

#ifdef PR_USE_NLS
  encode_init();
#endif /* PR_USE_NLS */

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("encode", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("encode", 0, 0);
  }

#ifdef PR_USE_NLS
  encode_free();
#endif /* PR_USE_NLS */

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

#ifdef PR_USE_NLS
START_TEST (encode_encode_str_test) {
  char *res;
  const char *in_str, junk[1024];
  size_t in_len, out_len = 0;

  res = pr_encode_str(NULL, NULL, 0, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_encode_str(p, NULL, 0, NULL);
  fail_unless(res == NULL, "Failed to handle null input string");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  in_str = "OK";
  in_len = 2;
  res = pr_encode_str(p, in_str, in_len, NULL);
  fail_unless(res == NULL, "Failed to handle null output string len");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_encode_str(p, in_str, in_len, &out_len);
  fail_unless(res != NULL, "Failed to encode '%s': %s", in_str,
    strerror(errno));
  fail_unless(strcmp(res, in_str) == 0, "Expected '%s', got '%s'", in_str,
    res);

  in_str = junk;
  in_len = sizeof(junk);
  res = pr_encode_str(p, in_str, in_len, &out_len);
  fail_unless(res == NULL, "Failed to handle bad input");
  fail_unless(errno == EILSEQ, "Expected EILSEQ (%d), got %s (%d)", EILSEQ,
    strerror(errno), errno);
}
END_TEST

START_TEST (encode_decode_str_test) {
  char *res;
  const char *in_str, junk[1024];
  size_t in_len, out_len = 0;

  res = pr_decode_str(NULL, NULL, 0, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_decode_str(p, NULL, 0, NULL);
  fail_unless(res == NULL, "Failed to handle null input string");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  in_str = "OK";
  in_len = 2;
  res = pr_decode_str(p, in_str, in_len, NULL);
  fail_unless(res == NULL, "Failed to handle null output string len");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_decode_str(p, in_str, in_len, &out_len);
  fail_unless(res != NULL, "Failed to decode '%s': %s", in_str,
    strerror(errno));
  fail_unless(strcmp(res, in_str) == 0, "Expected '%s', got '%s'", in_str,
    res);

  in_str = junk;
  in_len = sizeof(junk);
  res = pr_encode_str(p, in_str, in_len, &out_len);
  fail_unless(res == NULL, "Failed to handle bad input");
  fail_unless(errno == EILSEQ, "Expected EILSEQ (%d), got %s (%d)", EILSEQ,
    strerror(errno), errno);
}
END_TEST

START_TEST (encode_charset_test) {
  int res;
  const char *charset, *encoding;

  charset = pr_encode_get_charset();
  fail_unless(charset != NULL, "Failed to get current charset: %s",
    strerror(errno));

  res = pr_encode_is_utf8(NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  charset = "utf8";
  res = pr_encode_is_utf8(charset);
  fail_unless(res == TRUE, "Expected TRUE for '%s', got %d", charset, res);

  charset = "utf-8";
  res = pr_encode_is_utf8(charset);
  fail_unless(res == TRUE, "Expected TRUE for '%s', got %d", charset, res);

  charset = "ascii";
  res = pr_encode_is_utf8(charset);
  fail_unless(res == FALSE, "Expected FALSE for '%s', got %d", charset, res);

  res = pr_encode_set_charset_encoding(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  charset = "us-ascii";
  res = pr_encode_set_charset_encoding(charset, NULL);
  fail_unless(res < 0, "Failed to handle null encoding");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  encoding = "utf-8";
  res = pr_encode_set_charset_encoding(charset, encoding);
  fail_unless(res == 0, "Failed to set charset '%s', encoding '%s': %s",
    charset, encoding, strerror(errno));

  charset = "foo";
  res = pr_encode_set_charset_encoding(charset, encoding);
  fail_unless(res < 0, "Failed to handle bad charset '%s'", charset);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  charset = "us-ascii";
  encoding = "foo";
  res = pr_encode_set_charset_encoding(charset, encoding);
  fail_unless(res < 0, "Failed to handle bad encoding '%s'", encoding);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (encode_encoding_test) {
  int res;
  const char *encoding;

  res = pr_encode_enable_encoding(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  encoding = "utf-8";
  res = pr_encode_enable_encoding(encoding);
  fail_unless(res == 0, "Failed to enable encoding '%s': %s", encoding,
    strerror(errno));

  encoding = "iso-8859-1";
  res = pr_encode_enable_encoding(encoding);
  fail_unless(res == 0, "Failed to enable encoding '%s': %s", encoding,
    strerror(errno));

  encoding = "foo";
  res = pr_encode_enable_encoding(encoding);
  fail_unless(res < 0, "Failed to handle bad encoding '%s'", encoding);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pr_encode_disable_encoding();

  encoding = "utf-8";
  res = pr_encode_enable_encoding(encoding);
  fail_unless(res == 0, "Failed to enable encoding '%s': %s", encoding,
    strerror(errno));

  encoding = pr_encode_get_encoding();
  fail_unless(encoding != NULL, "Failed to get encoding: %s", strerror(errno));
  fail_unless(strcasecmp(encoding, "utf-8") == 0,
    "Expected 'utf-8', got '%s'", encoding);
}
END_TEST

START_TEST (encode_policy_test) {
  unsigned long res;

  res = pr_encode_get_policy();
  fail_unless(res == 0, "Expected policy 0, got %lu", res);

  res = pr_encode_set_policy(7);
  fail_unless(res == 0, "Expected policy 0, got %lu", res);

  res = pr_encode_get_policy();
  fail_unless(res == 7, "Expected policy 7, got %lu", res);

  (void) pr_encode_set_policy(0);
}
END_TEST

START_TEST (encode_supports_telnet_iac_test) {
  register unsigned int i;
  int res;
  const char *charset, *encoding;
  const char *non_iac_encodings[] = {
    "cp1251",
    "cp866",
    "iso-8859-1",
    "koi8-r",
    "windows-1251",
    NULL
  };

  res = pr_encode_supports_telnet_iac();
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);

  charset = "us-ascii";

  for (i = 0; non_iac_encodings[i]; i++) {
    encoding = non_iac_encodings[i];

    res = pr_encode_set_charset_encoding(charset, encoding);
    fail_unless(res == 0, "Failed to set charset '%s', encoding '%s': %s",
      charset, encoding, strerror(errno));

    res = pr_encode_supports_telnet_iac();
    fail_unless(res == FALSE, "Expected FALSE, got %d", res);
  }

  encoding = "utf-8";
  res = pr_encode_set_charset_encoding(charset, encoding);
  fail_unless(res == 0, "Failed to set charset '%s', encoding '%s': %s",
    charset, encoding, strerror(errno));
}
END_TEST
#endif /* PR_USE_NLS */

Suite *tests_get_encode_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("encode");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

#ifdef PR_USE_NLS
  tcase_add_test(testcase, encode_encode_str_test);
  tcase_add_test(testcase, encode_decode_str_test);
  tcase_add_test(testcase, encode_charset_test);
  tcase_add_test(testcase, encode_encoding_test);
  tcase_add_test(testcase, encode_policy_test);
  tcase_add_test(testcase, encode_supports_telnet_iac_test);
#endif /* PR_USE_NLS */

  suite_add_tcase(suite, testcase);
  return suite;
}
