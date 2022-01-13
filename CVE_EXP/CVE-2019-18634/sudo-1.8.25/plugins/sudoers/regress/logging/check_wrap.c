/*
 * Copyright (c) 2011-2013 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <limits.h>

#define SUDO_ERROR_WRAP 0

#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "sudo_plugin.h"
#include "sudo_util.h"

extern void writeln_wrap(FILE *fp, char *line, size_t len, size_t maxlen);

__dso_public int main(int argc, char *argv[]);

static void
usage(void)
{
    fprintf(stderr, "usage: %s inputfile\n", getprogname());
    exit(1);
}

int
main(int argc, char *argv[])
{
    size_t len;
    FILE *fp;
    char *line, lines[2][2048];
    int lineno = 0;
    int which = 0;

    initprogname(argc > 0 ? argv[0] : "check_wrap");

    if (argc != 2)
	usage();

    fp = fopen(argv[1], "r");
    if (fp == NULL)
	sudo_fatalx("unable to open %s", argv[1]);

    /*
     * Each test record consists of a log entry on one line and a list of
     * line lengths to test it with on the next.  E.g.
     *
     * Jun 30 14:49:51 : millert : TTY=ttypn ; PWD=/usr/src/local/millert/hg/sudo/trunk/plugins/sudoers ; USER=root ; TSID=0004LD ; COMMAND=/usr/local/sbin/visudo
     * 60-80,40
     */
    while ((line = fgets(lines[which], sizeof(lines[which]), fp)) != NULL) {
	char *cp, *last;

	len = strcspn(line, "\n");
	line[len] = '\0';

	/* If we read the 2nd line, parse list of line lengths and check. */
	if (which) {
	    lineno++;
	    for (cp = strtok_r(lines[1], ",", &last); cp != NULL; cp = strtok_r(NULL, ",", &last)) {
		char *dash;
		size_t maxlen;

		/* May be either a number or a range. */
		dash = strchr(cp, '-');
		if (dash != NULL) {
		    *dash = '\0';
		    len = strtonum(cp, 1, INT_MAX, NULL);
		    maxlen = strtonum(dash + 1, 1, INT_MAX, NULL);
		} else {
		    len = maxlen = strtonum(cp, 1, INT_MAX, NULL);
		}
		if (len == 0 || maxlen == 0)
		    sudo_fatalx("%s: invalid length on line %d\n", argv[1], lineno);
		while (len <= maxlen) {
		    printf("# word wrap at %d characters\n", (int)len);
		    writeln_wrap(stdout, lines[0], strlen(lines[0]), len);
		    len++;
		}
	    }
	}
	which = !which;
    }

    exit(0);
}
