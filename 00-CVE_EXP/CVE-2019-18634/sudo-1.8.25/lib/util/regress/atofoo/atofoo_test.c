/*
 * Copyright (c) 2014 Todd C. Miller <Todd.Miller@sudo.ws>
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
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif

#include "sudo_compat.h"
#include "sudo_util.h"
#include "sudo_fatal.h"

__dso_public int main(int argc, char *argv[]);

/* sudo_strtobool() tests */
static struct strtobool_data {
    const char *bool_str;
    int value;
} strtobool_data[] = {
    { "true", true },
    { "false", false },
    { "TrUe", true },
    { "fAlSe", false },
    { "1", true },
    { "0", false },
    { "on", true },
    { "off", false },
    { "yes", true },
    { "no", false },
    { "nope", -1 },
    { "10", -1 },
    { "one", -1 },
    { "zero", -1 },
    { NULL, 0 }
};

static int
test_strtobool(int *ntests)
{
    struct strtobool_data *d;
    int errors = 0;
    int value;

    for (d = strtobool_data; d->bool_str != NULL; d++) {
	(*ntests)++;
	value = sudo_strtobool(d->bool_str);
	if (value != d->value) {
	    sudo_warnx_nodebug("FAIL: %s != %d", d->bool_str, d->value);
	    errors++;
	}
    }

    return errors;
}

/* sudo_strtoid() tests */
static struct strtoid_data {
    const char *idstr;
    id_t id;
    const char *sep;
    const char *ep;
} strtoid_data[] = {
    { "0,1", 0, ",", "," },
    { "10", 10, NULL, NULL },
    { "-2", -2, NULL, NULL },
#if SIZEOF_ID_T != SIZEOF_LONG_LONG
    { "-2", (id_t)4294967294U, NULL, NULL },
#endif
    { "4294967294", (id_t)4294967294U, NULL, NULL },
    { NULL, 0, NULL, NULL }
};

static int
test_strtoid(int *ntests)
{
    struct strtoid_data *d;
    const char *errstr;
    char *ep;
    int errors = 0;
    id_t value;

    for (d = strtoid_data; d->idstr != NULL; d++) {
	(*ntests)++;
	errstr = "some error";
	value = sudo_strtoid(d->idstr, d->sep, &ep, &errstr);
	if (errstr != NULL) {
	    if (d->id != (id_t)-1) {
		sudo_warnx_nodebug("FAIL: %s: %s", d->idstr, errstr);
		errors++;
	    }
	} else if (value != d->id) {
	    sudo_warnx_nodebug("FAIL: %s != %u", d->idstr, (unsigned int)d->id);
	    errors++;
	} else if (d->ep != NULL && ep[0] != d->ep[0]) {
	    sudo_warnx_nodebug("FAIL: ep[0] %d != %d", (int)(unsigned char)ep[0],
		(int)(unsigned char)d->ep[0]);
	    errors++;
	}
    }

    return errors;
}

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

static int
test_strtomode(int *ntests)
{
    struct strtomode_data *d;
    const char *errstr;
    int errors = 0;
    mode_t mode;

    for (d = strtomode_data; d->mode_str != NULL; d++) {
	(*ntests)++;
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

    return errors;
}

/*
 * Simple tests for sudo_strtobool(), sudo_strtoid(), sudo_strtomode().
 */
int
main(int argc, char *argv[])
{
    int errors = 0;
    int ntests = 0;

    initprogname(argc > 0 ? argv[0] : "atofoo");

    errors += test_strtobool(&ntests);
    errors += test_strtoid(&ntests);
    errors += test_strtomode(&ntests);

    if (ntests != 0) {
	printf("%s: %d tests run, %d errors, %d%% success rate\n",
	    getprogname(), ntests, errors, (ntests - errors) * 100 / ntests);
    }

    exit(errors);
}
