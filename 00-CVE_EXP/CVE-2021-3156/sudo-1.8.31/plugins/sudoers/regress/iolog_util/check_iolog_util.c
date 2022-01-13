/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2018 Todd C. Miller <Todd.Miller@sudo.ws>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <time.h>
#include <unistd.h>

#define SUDO_ERROR_WRAP 0

#include "sudo_compat.h"
#include "sudo_util.h"
#include "sudo_fatal.h"
#include "iolog.h"

__dso_public int main(int argc, char *argv[]);

static struct parse_delay_test {
    const char *input;
    const char *next_field;
    struct timespec expected_delay;
} parse_delay_tests[] = {
    { "10.99999999999 X", "X", { 10, 999999999 } },	/* clamp to nsec */
    { "10.999999999 X",   "X", { 10, 999999999 } },	/* nsec */
    { "10.999999 X",      "X", { 10, 999999000 } },	/* usec -> nsec */
    { "10.000999999 X",   "X", { 10, 999999 } },
    { "10.9 X",           "X", { 10, 900000000 } },
    { "10.0 X",           "X", { 10, 0 } }
};

/*
 * Test parse_delay()
 */
void
test_parse_delay(int *ntests, int *nerrors)
{
    unsigned int i;

    for (i = 0; i < nitems(parse_delay_tests); i++) {
	struct timespec delay;
	struct parse_delay_test *test = &parse_delay_tests[i];
	char *cp = parse_delay(test->input, &delay, ".");
	if (cp == NULL) {
	    sudo_warnx("%s:%u failed to parse delay: %s", __func__,
		i, test->input);
	    (*nerrors)++;
	    continue;
	}
	if (strcmp(cp, test->next_field) != 0) {
	    sudo_warnx("%s:%u next field (want \"%s\", got \"%s\"", __func__,
		i, test->next_field, cp);
	    (*nerrors)++;
	    continue;
	}
	if (delay.tv_sec != test->expected_delay.tv_sec) {
	    sudo_warnx("%s:%u wrong seconds (want %lld, got %lld)", __func__,
		i, (long long)test->expected_delay.tv_sec,
		(long long)delay.tv_sec);
	    (*nerrors)++;
	    continue;
	}
	if (delay.tv_nsec != test->expected_delay.tv_nsec) {
	    sudo_warnx("%s:%u wrong nanoseconds (want %ld, got %ld)", __func__,
		i, test->expected_delay.tv_nsec, delay.tv_nsec);
	    (*nerrors)++;
	    continue;
	}
    }
    (*ntests) += i;
}

static struct adjust_delay_test {
    struct timespec in_delay;
    struct timespec out_delay;
    struct timespec max_delay;
    double scale_factor;
} adjust_delay_tests[] = {
    { { 10,       300 }, { 10,       300 }, { 0, 0 }, 1.0 },
    { { 10,       300 }, {  5,       150 }, { 0, 0 }, 2.0 },
    { {  5,       300 }, {  2, 500000150 }, { 0, 0 }, 2.0 },
    { {  0,   1000000 }, {  0,    333333 }, { 0, 0 },   3 },
    { { 10,   1000000 }, {  3, 333666666 }, { 0, 0 },   3 },
    { {  5,       150 }, { 10,       300 }, { 0, 0 }, 0.5 },
    { {  5, 500000000 }, { 11,         0 }, { 0, 0 }, 0.5 },
    { {  5,       150 }, {  5,         0 }, { 5, 0 }, 0.5 }
};

/*
 * Test adjust_delay()
 */
void
test_adjust_delay(int *ntests, int *nerrors)
{
    unsigned int i;

    for (i = 0; i < nitems(adjust_delay_tests); i++) {
	struct adjust_delay_test *test = &adjust_delay_tests[i];

	adjust_delay(&test->in_delay, sudo_timespecisset(&test->max_delay) ?
	    &test->max_delay : NULL, test->scale_factor);
	if (!sudo_timespeccmp(&test->in_delay, &test->out_delay, ==)) {
	    sudo_warnx("%s:%u want {%lld, %ld}, got {%lld, %ld}", __func__, i,
		(long long)test->out_delay.tv_sec, test->out_delay.tv_nsec,
		(long long)test->in_delay.tv_sec, test->in_delay.tv_nsec);
	    (*nerrors)++;
	}
    }
    (*ntests) += i;
}

int
main(int argc, char *argv[])
{
    int tests = 0, errors = 0;

    initprogname(argc > 0 ? argv[0] : "check_iolog_util");

    test_parse_delay(&tests, &errors);

    test_adjust_delay(&tests, &errors);

    if (tests != 0) {
	printf("check_iolog_util: %d test%s run, %d errors, %d%% success rate\n",
	    tests, tests == 1 ? "" : "s", errors,
	    (tests - errors) * 100 / tests);
    }

    exit(errors);
}
