/*
 * ProFTPD - mod_auth_otp API testsuite
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

#include "tests.h"

struct testsuite_info {
  const char *name;
  Suite *(*get_suite)(void);
};

static struct testsuite_info suites[] = {
  { "base32", 		tests_get_base32_suite },
  { "hotp", 		tests_get_hotp_suite },
  { "totp", 		tests_get_totp_suite },

  { NULL, NULL }
};

static Suite *tests_get_suite(const char *suite) { 
  if (strcmp(suite, "base32") == 0) { 
    return tests_get_base32_suite();

  } else if (strcmp(suite, "hotp") == 0) { 
    return tests_get_hotp_suite();

  } else if (strcmp(suite, "totp") == 0) { 
    return tests_get_totp_suite();
  }

  return NULL;
}

int main(int argc, char *argv[]) {
  const char *log_file = "auth-otp-tests.log";
  int nfailed = 0;
  SRunner *runner = NULL;
  char *requested = NULL;

  runner = srunner_create(NULL);

  /* XXX This log name should be set outside this code, e.g. via environment
   * variable or command-line option.
   */
  srunner_set_log(runner, log_file);

  requested = getenv("AUTH_OTP_TEST_SUITE");
  if (requested) {
    Suite *suite;

    suite = tests_get_suite(requested);
    if (suite) {
      srunner_add_suite(runner, suite);

    } else {
      fprintf(stderr,
        "No such test suite ('%s') requested via AUTH_OTP_TEST_SUITE\n",
        requested);
      return EXIT_FAILURE;
    }

  } else {
    register unsigned int i;

    for (i = 0; suites[i].name; i++) {
      Suite *suite;

      suite = (suites[i].get_suite)();
      if (suite) {
        srunner_add_suite(runner, suite);
      }
    }
  }

  requested = getenv("PR_TEST_NOFORK");
  if (requested) {
    srunner_set_fork_status(runner, CK_NOFORK);
  }

  srunner_run_all(runner, CK_NORMAL);

  nfailed = srunner_ntests_failed(runner);

  if (runner)
    srunner_free(runner);

  if (nfailed != 0) {
    fprintf(stderr, "-------------------------------------------------\n");
    fprintf(stderr, " FAILED %d %s\n\n", nfailed,
      nfailed != 1 ? "tests" : "test");
    fprintf(stderr, " Please send email to:\n\n");
    fprintf(stderr, "   tj@castaglia.org\n\n");
    fprintf(stderr, " containing the `%s' file (in the t/ directory)\n", log_file);
    fprintf(stderr, " and the output from running `proftpd -V'\n");
    fprintf(stderr, "-------------------------------------------------\n");

    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
