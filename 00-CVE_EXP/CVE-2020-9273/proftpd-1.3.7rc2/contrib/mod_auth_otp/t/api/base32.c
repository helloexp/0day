/*
 * ProFTPD - mod_auth_otp testsuite
 * Copyright (c) 2015-2016 The ProFTPD Project team
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

/* Base32 API tests
 */

#include "tests.h"
#include "base32.h"

static pool *p = NULL;

/* These values are taken from RFC 4458, Section 10.
 *
 * Note that this base32 implementation does NOT emit the padding characters,
 * as an "optimization".
 *
 * The base32 encoded values are used for interoperability with e.g. Google
 * Authenticator, for entering into the app via human interaction.  To
 * reduce the friction, then, the padding characters are omitted.
 */

struct kat {
  const char *raw;
  const char *encoded;
};

static struct kat expected_codes[] = {
  { "",       "" },
  { "f",      "MY", },
  { "fo",     "MZXQ" },
  { "foo",    "MZXW6" },
  { "foob",   "MZXW6YQ" },
  { "foobar", "MZXW6YTBOI" }
};
static unsigned int expected_code_count = 6;

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

START_TEST (base32_encode_test) {
  register unsigned int i;
  int res;

  res = auth_otp_base32_encode(p, NULL, 0, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno %s (%d), got %s (%d)",
    strerror(EINVAL), EINVAL, strerror(errno), errno);

  for (i = 0; i < expected_code_count; i++) {
    const unsigned char *raw, *encoded = NULL;
    size_t raw_len, encoded_len = 0;

    raw = (const unsigned char *) expected_codes[i].raw;
    raw_len = strlen((char *) raw);

    res = auth_otp_base32_encode(p, raw, raw_len, &encoded, &encoded_len);
    fail_unless(res == 0, "Failed to base32 encode '%s': %s",
      expected_codes[i].raw, strerror(errno));
    fail_unless(strcmp((char *) encoded, expected_codes[i].encoded) == 0,
      "Expected '%s' for value '%s', got '%s'", expected_codes[i].encoded,
      expected_codes[i].raw, encoded);
  }
}
END_TEST

START_TEST (base32_decode_test) {
  register unsigned int i;
  int res;

  res = auth_otp_base32_decode(p, NULL, 0, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno %s (%d), got %s (%d)",
    strerror(EINVAL), EINVAL, strerror(errno), errno);

  mark_point();

  for (i = 0; i < expected_code_count; i++) {
    const unsigned char *encoded, *raw = NULL;
    size_t encoded_len, raw_len = 0;

    encoded = (const unsigned char *) expected_codes[i].encoded;
    encoded_len = strlen((char *) encoded);

    res = auth_otp_base32_decode(p, encoded, encoded_len, &raw, &raw_len);
    fail_unless(res == 0, "Failed to base32 decode '%s': %s",
      expected_codes[i].encoded, strerror(errno));
    fail_unless(strcmp((char *) raw, expected_codes[i].raw) == 0,
      "Expected '%s' for value '%s', got '%s'", expected_codes[i].raw,
      expected_codes[i].encoded, raw);
  }
}
END_TEST

Suite *tests_get_base32_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("base32");

  testcase = tcase_create("base32");
  tcase_add_checked_fixture(testcase, set_up, tear_down);
  tcase_add_test(testcase, base32_encode_test);
  tcase_add_test(testcase, base32_decode_test);
  suite_add_tcase(suite, testcase);

  return suite;
}
