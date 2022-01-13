/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2015-2018 The ProFTPD Project team
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

/* ASCII API tests */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
  } 
}

START_TEST (ascii_ftp_from_crlf_test) {
  int res;
  char *src, *dst, *expected;
  size_t src_len, dst_len, expected_len;

  pr_ascii_ftp_reset();
  res = pr_ascii_ftp_from_crlf(NULL, NULL, 0, NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL ('%s' [%d]), got '%s' [%d]",
    strerror(errno), errno);

  /* Handle an empty input buffer. */
  pr_ascii_ftp_reset();
  src = "";
  src_len = 0;
  dst = pcalloc(p, 1);
  dst_len = 0;
  res = pr_ascii_ftp_from_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 0, "Failed to handle empty input buffer");
  fail_unless(dst_len == src_len, "Failed to set output buffer length");

  /* Handle an input buffer with no CRLFs. */
  pr_ascii_ftp_reset();
  src = "hello";
  src_len = 5;
  dst = pcalloc(p, src_len + 1);
  dst_len = 0;
  res = pr_ascii_ftp_from_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 0, "Failed to handle input buffer with no CRLFs");
  expected = src;
  expected_len = src_len;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  res = strcmp(expected, dst);
  fail_unless(res == 0, "Expected output buffer '%s', got '%s' (%d)", expected,
    dst, res);

  /* Handle an input buffer with CRs, no LFs. */
  pr_ascii_ftp_reset();
  src = "he\rl\rlo";
  src_len = 7;
  dst = pcalloc(p, src_len + 1);
  dst_len = 0;
  res = pr_ascii_ftp_from_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 0, "Failed to handle input buffer with CRs, no LFs");
  expected = src;
  expected_len = src_len;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  fail_unless(strcmp(dst, expected) == 0,
    "Expected output buffer '%s', got '%s'", expected, dst);

  /* Handle an input buffer with LFs, no CRs. */
  pr_ascii_ftp_reset();
  src = "he\nl\nlo";
  src_len = 7;
  dst = pcalloc(p, src_len + 1);
  dst_len = 0;
  res = pr_ascii_ftp_from_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 0, "Failed to handle input buffer with LFs, no CRs");
  expected = src;
  expected_len = src_len;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  fail_unless(strcmp(dst, expected) == 0,
    "Expected output buffer '%s', got '%s'", expected, dst);

  /* Handle an input buffer with several CRLFs. */
  pr_ascii_ftp_reset();
  src = "he\r\nl\r\nlo"; 
  src_len = 9;
  dst = pcalloc(p, src_len + 1);
  dst_len = 0;
  res = pr_ascii_ftp_from_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 0, "Failed to handle input buffer with CRLFs");
  expected = "he\nl\nlo";
  expected_len = 7;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  fail_unless(strcmp(dst, expected) == 0,
    "Expected output buffer '%s', got '%s'", expected, dst);

  /* Handle an input buffer ending with a CR. */
  pr_ascii_ftp_reset();
  src = "he\r\nl\r\nlo\r";
  src_len = 10;
  dst = pcalloc(p, src_len + 1);
  dst_len = 0;
  res = pr_ascii_ftp_from_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 1,
    "Failed to handle input buffer with trailing CR: expected %d, got %d", 1,
    res);
  expected = "he\nl\nlo\r";
  expected_len = 7;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  fail_unless(strcmp(dst, expected) == 0,
    "Expected output buffer '%s', got '%s'", expected, dst);

  /* Handle an input buffer of just an LF. */
  pr_ascii_ftp_reset();
  src = "\n";
  src_len = 1;
  dst = pcalloc(p, src_len + 1);
  dst_len = 0;
  res = pr_ascii_ftp_from_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 0,
    "Failed to handle input buffer of single LF: expected %d, got %d", 0, res);
  expected = "\n";
  expected_len = 1;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  fail_unless(strcmp(dst, expected) == 0,
    "Expected output buffer '%s', got '%s'", expected, dst);

  /* Handle an input buffer of just a CR. */
  pr_ascii_ftp_reset();
  src = "\r";
  src_len = 1;
  dst = pcalloc(p, src_len + 1);
  dst_len = 0;
  res = pr_ascii_ftp_from_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 1,
    "Failed to handle input buffer of single CR: expected %d, got %d", 1, res);
  expected = "\r";
  expected_len = 0;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  fail_unless(strcmp(dst, expected) == 0,
    "Expected output buffer '%s', got '%s'", expected, dst);

  /* Handle an input buffer of just CRs. */
  pr_ascii_ftp_reset();
  src = "\r\r\r";
  src_len = 3;
  dst = pcalloc(p, src_len + 1);
  dst_len = 0;
  res = pr_ascii_ftp_from_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 1,
    "Failed to handle input buffer of single CR: expected %d, got %d", 3, res);
  expected = "\r\r\r";
  expected_len = 2;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  fail_unless(strcmp(dst, expected) == 0,
    "Expected output buffer '%s', got '%s'", expected, dst);
}
END_TEST

START_TEST (ascii_ftp_to_crlf_test) {
  int res;
  char *src, *dst, *expected;
  size_t src_len, dst_len, expected_len;

  mark_point();
  pr_ascii_ftp_reset();
  res = pr_ascii_ftp_to_crlf(NULL, NULL, 0, NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL ('%s' [%d]), got '%s' [%d]",
    strerror(errno), errno);

  /* Handle empty input buffer. */
  mark_point();
  pr_ascii_ftp_reset();
  src = "";
  src_len = 0;
  dst = NULL;
  dst_len = 0;
  res = pr_ascii_ftp_to_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 0, "Failed to handle empty input buffer");
  fail_unless(dst_len == src_len, "Failed to set output buffer length");
  fail_unless(dst == src, "Failed to set output buffer");

  /* Handle input buffer with no CRLFs. */
  mark_point();
  pr_ascii_ftp_reset();
  src = "hello";
  src_len = 5;
  dst = NULL;
  dst_len = 0;
  res = pr_ascii_ftp_to_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 0, "Failed to handle input buffer with no CRLFs");
  expected = src;
  expected_len = src_len;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  fail_unless(strncmp(dst, expected, dst_len) == 0,
    "Expected output buffer '%s', got '%s'", expected, dst);
  free(dst);

  /* Handle input buffer with CRs, no LFs. */
  mark_point();
  pr_ascii_ftp_reset();
  src = "he\rl\rlo";
  src_len = 7;
  dst = NULL;
  dst_len = 0;
  res = pr_ascii_ftp_to_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 0, "Failed to handle input buffer with CRs, no LFs");
  expected = src; 
  expected_len = src_len;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  fail_unless(strncmp(dst, expected, dst_len) == 0,
    "Expected output buffer '%s', got '%s'", expected, dst);
  free(dst);

  /* Handle input buffer with LFs, no CRs. */
  mark_point();
  pr_ascii_ftp_reset();
  src = "he\nl\nlo";
  src_len = 7;
  dst = NULL;
  dst_len = 0;
  res = pr_ascii_ftp_to_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 2, "Failed to handle input buffer with CRs, no LFs");
  expected = "he\r\nl\r\nlo";
  expected_len = 9;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  fail_unless(strncmp(dst, expected, dst_len) == 0,
    "Expected output buffer '%s', got '%s'", expected, dst);
  free(dst);

  /* Handle input buffer CRLFs. */
  mark_point();
  pr_ascii_ftp_reset();
  src = "he\r\nl\r\nlo";
  src_len = 9;
  dst = NULL;
  dst_len = 0;
  res = pr_ascii_ftp_to_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 0, "Failed to handle input buffer with CRs, no LFs");
  expected = src;
  expected_len = src_len;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  fail_unless(strncmp(dst, expected, dst_len) == 0,
    "Expected output buffer '%s', got '%s'", expected, dst);
  free(dst);

  /* Handle input buffer with leading LF. */
  mark_point();
  pr_ascii_ftp_reset();
  src = "\nhello";
  src_len = 6;
  dst = NULL;
  dst_len = 0;
  res = pr_ascii_ftp_to_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 1, "Failed to handle input buffer with leading LF");
  expected = "\r\nhello";
  expected_len = 7;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  fail_unless(strncmp(dst, expected, dst_len) == 0,
    "Expected output buffer '%s', got '%s'", expected, dst);
  free(dst);

  /* Handle input buffer with trailing CR. */
  mark_point();
  pr_ascii_ftp_reset();
  src = "hel\r";
  src_len = 4;
  dst = NULL;
  dst_len = 0;
  res = pr_ascii_ftp_to_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 0, "Failed to handle input buffer with trailing CR");
  expected = src;
  expected_len = src_len;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  fail_unless(strncmp(dst, expected, dst_len) == 0,
    "Expected output buffer '%s', got '%s'", expected, dst);
  free(dst);

  mark_point();
  src = "\nlo\n";
  src_len = 4;
  dst = NULL;
  dst_len = 0;
  res = pr_ascii_ftp_to_crlf(p, src, src_len, &dst, &dst_len);
  fail_unless(res == 1, "Failed to handle next input buffer after trailing CR");
  expected = "\nlo\r\n";
  expected_len = 5;
  fail_unless(dst_len == expected_len,
    "Expected output buffer length %lu, got %lu", (unsigned long) expected_len,
    (unsigned long) dst_len);
  fail_unless(strncmp(dst, expected, dst_len) == 0,
    "Expected output buffer '%s', got '%s'", expected, dst);
  free(dst);
}
END_TEST

Suite *tests_get_ascii_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("ascii");

  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, ascii_ftp_from_crlf_test);
  tcase_add_test(testcase, ascii_ftp_to_crlf_test);

  suite_add_tcase(suite, testcase);

  return suite;
}
