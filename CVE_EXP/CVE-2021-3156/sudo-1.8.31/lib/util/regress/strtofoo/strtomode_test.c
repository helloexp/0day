/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2014-2019 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include "sudo_compat.h"
#include "sudo_util.h"
#include "sudo_fatal.h"

__dso_public int main(int argc, char *argv[]);

/* sudo_strtomode() tests */
static struct strtomode_data {
    const char *mode_str;
    mode_t mode;
} strtomode_data[] = {
    { "755", 0755 },
    { "007", 007 },
    { "7", 7 },
    { "8", (mode_t)-1 },
    { NULL, 0 }
};

/*
 * Simple tests for sudo_strtomode().
 */
int
main(int argc, char *argv[])
{
    struct strtomode_data *d;
    const char *errstr;
    int errors = 0;
    int ntests = 0;
    mode_t mode;

    initprogname(argc > 0 ? argv[0] : "strtomode_test");

    for (d = strtomode_data; d->mode_str != NULL; d++) {
	ntests++;
	errstr = "some error";
	mode = sudo_strtomode(d->mode_str, &errstr);
	if (errstr != NULL) {
	    if (d->mode != (mode_t)-1) {
		sudo_warnx_nodebug("FAIL: %s: %s", d->mode_str, errstr);
		errors++;
	    }
	} else if (mode != d->mode) {
	    sudo_warnx_nodebug("FAIL: %s != 0%o", d->mode_str,
		(unsigned int) d->mode);
	    errors++;
	}
    }

    if (ntests != 0) {
	printf("%s: %d tests run, %d errors, %d%% success rate\n",
	    getprogname(), ntests, errors, (ntests - errors) * 100 / ntests);
    }

    return errors;
}
