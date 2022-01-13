/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2015 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include "sudo_fatal.h"
#include "sudo_util.h"

__dso_public int main(int argc, char *argv[]);

/*
 * Test that sudo_parse_gids() works as expected.
 */

struct parse_gids_test {
    const char *gids;
    gid_t *baseptr;
    gid_t basegid;
    int ngids;
    const GETGROUPS_T *gidlist;
};

static const GETGROUPS_T test1_out[] = { 0, 1, 2, 3, 4 };
static const GETGROUPS_T test2_out[] = { 1, 2, 3, 4 };
static const GETGROUPS_T test3_out[] = { 0, 1, (gid_t)-2, 3, 4 };

/* XXX - test syntax errors too */
static struct parse_gids_test test_data[] = {
    { "1,2,3,4", &test_data[0].basegid, 0, 5, test1_out },
    { "1,2,3,4", NULL, 0, 4, test2_out },
    { "1,-2,3,4", &test_data[2].basegid, 0, 5, test3_out },
    { NULL, false, 0, 0, NULL }
};

static void
dump_gids(const char *prefix, int ngids, const GETGROUPS_T *gidlist)
{
    int i;

    fprintf(stderr, "%s: %s: ", getprogname(), prefix);
    for (i = 0; i < ngids; i++) {
	fprintf(stderr, "%s%d", i ? ", " : "", (int)gidlist[i]);
    }
    fputc('\n', stderr);
}

int
main(int argc, char *argv[])
{
    GETGROUPS_T *gidlist = NULL;
    int i, j, errors = 0, ntests = 0;
    int ngids;
    initprogname(argc > 0 ? argv[0] : "parse_gids_test");

    for (i = 0; test_data[i].gids != NULL; i++) {
	free(gidlist);
	ngids = sudo_parse_gids(test_data[i].gids, test_data[i].baseptr, &gidlist);
	if (ngids == -1)
	    exit(1);	/* out of memory? */
	ntests++;
	if (ngids != test_data[i].ngids) {
	    sudo_warnx_nodebug("test #%d: expected %d gids, got %d",
		ntests, test_data[i].ngids, ngids);
	    dump_gids("expected", test_data[i].ngids, test_data[i].gidlist);
	    dump_gids("received", ngids, gidlist);
	    errors++;
	    continue;
	}
	ntests++;
	for (j = 0; j < ngids; j++) {
	    if (test_data[i].gidlist[j] != gidlist[j]) {
		sudo_warnx_nodebug("test #%d: gid mismatch", ntests);
		dump_gids("expected", test_data[i].ngids, test_data[i].gidlist);
		dump_gids("received", ngids, gidlist);
		errors++;
		break;
	    }
	}
    }
    if (ntests != 0) {
	printf("%s: %d tests run, %d errors, %d%% success rate\n",
	    getprogname(), ntests, errors, (ntests - errors) * 100 / ntests);
    }
    exit(errors);
}
