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
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif

#include "sudo_compat.h"
#include "sudo_util.h"

__dso_public int main(int argc, char *argv[]);

/*
 * Test that getprogname() returns the expected result.
 * On some systems (AIX), we may have issues with symbolic links.
 */

int
main(int argc, char *argv[])
{
    char *progbase = "progname_test";

    if (argc > 0) {
	if ((progbase = strrchr(argv[0], '/')) != NULL)
	    progbase++;
	else
	    progbase = argv[0];
    }
    initprogname(progbase);

    /* Make sure getprogname() matches basename of argv[0]. */
    if (strcmp(getprogname(), progbase) != 0) {
	printf("%s: FAIL: incorrect program name \"%s\"\n",
	    progbase, getprogname());
	exit(1);
    }

    exit(0);
}
