/*
 * ProFTPD - mod_auth_otp testsuite
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

/* HOTP/TOTP API tests
 */

#include "tests.h"

static pool *p = NULL;

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

START_TEST (hotp_test) {
  register unsigned int i;
  int res;

  /* These values are taken from RFC 4226, Appendix D. */  
  const char *key = "12345678901234567890";
  size_t key_len = strlen((char *) key);
  struct kat {
    unsigned long count;
    unsigned int hotp;
  };

  struct kat expected_codes[] = {
    { 0, 755224 },
    { 1, 287082 },
    { 2, 359152 },
    { 3, 969429 },
    { 4, 338314 },
    { 5, 254676 },
    { 6, 287922 },
    { 7, 162583 },
    { 8, 399871 },
    { 9, 520489 }
  };

  res = auth_otp_hotp(p, (const unsigned char *) key, key_len, 0, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno %s (%d), got %s (%d)",
    strerror(EINVAL), EINVAL, strerror(errno), errno);

  for (i = 0; i < 10; i++) {
    unsigned int code;

    res = auth_otp_hotp(p, (const unsigned char *) key, key_len,
      expected_codes[i].count, &code);
    fail_unless(res == 0, "Failed to generate HOTP for value %lu: %s",
      expected_codes[i].count, strerror(errno));
    fail_unless(code == expected_codes[i].hotp,
      "Expected HOTP %u for value %lu, got %u", expected_codes[i].hotp,
      expected_codes[i].count, code);
  }
}
END_TEST

START_TEST (totp_sha1_test) {
  register unsigned int i;
  int res;

  /* These values are taken from RFC 6238, Appendix B. */  
  const char *key = "12345678901234567890";
  size_t key_len = strlen(key);
  struct kat {
    unsigned long count;
    unsigned int totp;
  };

  /* Note: since we are generating 6 digit codes (for interoperability with
   * e.g. Google Authenticator), not 8 as provided in the KAT in the RFC,
   * these numbers are adjusted.
   */
  struct kat expected_codes[] = {
    { 59,		  287082 },
    { 1111111109,	   81804 },
    { 1111111111,	   50471 },
    { 1234567890,	    5924 },
    { 2000000000,	  279037 },
    { 20000000000,	  353130 }
  };

  res = auth_otp_totp(p, (const unsigned char *) key, key_len, 0, 0, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno %s (%d), got %s (%d)",
    strerror(EINVAL), EINVAL, strerror(errno), errno);

  for (i = 0; i < 5; i++) {
    unsigned int code;

    res = auth_otp_totp(p, (const unsigned char *) key, key_len,
      expected_codes[i].count, AUTH_OTP_ALGO_TOTP_SHA1, &code);
    fail_unless(res == 0, "Failed to generate TOTP-SHA1 for value %lu: %s",
      expected_codes[i].count, strerror(errno));
    fail_unless(code == expected_codes[i].totp,
      "Expected TOTP-SHA1 %u for value %lu, got %u", expected_codes[i].totp,
      expected_codes[i].count, code);
  }
}
END_TEST

#ifdef HAVE_SHA256_OPENSSL
START_TEST (totp_sha256_test) {
  register unsigned int i;
  int res;

  /* These values are taken from RFC 6238, Appendix B.  Note that the key
   * for SHA256 needs to be longer.
   */  
  const char *key = "12345678901234567890123456789012";
  size_t key_len = strlen(key);
  struct kat {
    unsigned long count;
    unsigned int totp;
  };

  /* Note: since we are generating 6 digit codes (for interoperability with
   * e.g. Google Authenticator), not 8 as provided in the KAT in the RFC,
   * these numbers are adjusted.
   */
  struct kat expected_codes[] = {
    { 59,		  119246 },
    { 1111111109,	   84774 },
    { 1111111111,	   62674 },
    { 1234567890,	  819424 },
    { 2000000000,	  698825 },
    { 20000000000,	  737706 }
  };

  res = auth_otp_totp(p, (const unsigned char *) key, key_len, 0, 0, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno %s (%d), got %s (%d)",
    strerror(EINVAL), EINVAL, strerror(errno), errno);

  for (i = 0; i < 5; i++) {
    unsigned int code;

    res = auth_otp_totp(p, (const unsigned char *) key, key_len,
      expected_codes[i].count, AUTH_OTP_ALGO_TOTP_SHA256, &code);
    fail_unless(res == 0, "Failed to generate TOTP-SHA256 for value %lu: %s",
      expected_codes[i].count, strerror(errno));
    fail_unless(code == expected_codes[i].totp,
      "Expected TOTP-SHA256 %u for value %lu, got %u", expected_codes[i].totp,
      expected_codes[i].count, code);
  }
}
END_TEST
#endif /* SHA256 OpenSSL support */

#ifdef HAVE_SHA512_OPENSSL
START_TEST (totp_sha512_test) {
  register unsigned int i;
  int res;

  /* These values are taken from RFC 6238, Appendix B.  Note that the key
   * for SHA512 needs to be longer.
   */  
  const char *key = "1234567890123456789012345678901234567890123456789012345678901234";
  size_t key_len = strlen(key);
  struct kat {
    unsigned long count;
    unsigned int totp;
  };

  /* Note: since we are generating 6 digit codes (for interoperability with
   * e.g. Google Authenticator), not 8 as provided in the KAT in the RFC,
   * these numbers are adjusted.
   */
  struct kat expected_codes[] = {
    { 59,		  693936 },
    { 1111111109,	   91201 },
    { 1111111111,	  943326 },
    { 1234567890,	  441116 },
    { 2000000000,	  618901 },
    { 20000000000,	  863826 }
  };

  res = auth_otp_totp(p, (const unsigned char *) key, key_len, 0, 0, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno %s (%d), got %s (%d)",
    strerror(EINVAL), EINVAL, strerror(errno), errno);

  for (i = 0; i < 5; i++) {
    unsigned int code;

    res = auth_otp_totp(p, (const unsigned char *) key, key_len,
      expected_codes[i].count, AUTH_OTP_ALGO_TOTP_SHA512, &code);
    fail_unless(res == 0, "Failed to generate TOTP-SHA512 for value %lu: %s",
      expected_codes[i].count, strerror(errno));
    fail_unless(code == expected_codes[i].totp,
      "Expected TOTP-SHA512 %u for value %lu, got %u", expected_codes[i].totp,
      expected_codes[i].count, code);
  }
}
END_TEST
#endif /* SHA512 OpenSSL support */

Suite *tests_get_hotp_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("hotp");

  testcase = tcase_create("hotp");
  tcase_add_checked_fixture(testcase, set_up, tear_down);
  tcase_add_test(testcase, hotp_test);
  suite_add_tcase(suite, testcase);

  return suite;
}

Suite *tests_get_totp_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("totp");

  testcase = tcase_create("totp");
  tcase_add_checked_fixture(testcase, set_up, tear_down);
  tcase_add_test(testcase, totp_sha1_test);
#ifdef HAVE_SHA256_OPENSSL
  tcase_add_test(testcase, totp_sha256_test);
#endif /* SHA256 OpenSSL support */
#ifdef HAVE_SHA512_OPENSSL
  tcase_add_test(testcase, totp_sha512_test);
#endif /* SHA512 OpenSSL support */
  suite_add_tcase(suite, testcase);

  return suite;
}
