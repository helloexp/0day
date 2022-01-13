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
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define SUDO_ERROR_WRAP 0

#include "sudoers.h"
#include "interfaces.h"

__dso_public int main(int argc, char *argv[]);

static int
check_addr(char *input)
{
    int expected, matched;
    const char *errstr;
    size_t len;
    char *cp;

    while (isspace((unsigned char)*input))
	input++;

    /* input: "addr[/mask] 1/0" */
    len = strcspn(input, " \t");
    cp = input + len;
    while (isspace((unsigned char)*cp))
	cp++;
    expected = strtonum(cp, 0, 1, &errstr);
    if (errstr != NULL)
	sudo_fatalx("expecting 0 or 1, got %s", cp);
    input[len] = '\0';

    matched = addr_matches(input);
    if (matched != expected) {
	sudo_warnx("%s %smatched: FAIL", input, matched ? "" : "not ");
	return 1;
    }
    return 0;
}

static void
usage(void)
{
    fprintf(stderr, "usage: %s datafile\n", getprogname());
    exit(1);
}

int
main(int argc, char *argv[])
{
    int ntests = 0, errors = 0;
    char *cp, line[2048];
    size_t len;
    FILE *fp;

    initprogname(argc > 0 ? argv[0] : "check_addr");

    if (argc != 2)
	usage();

    fp = fopen(argv[1], "r");
    if (fp == NULL)
	sudo_fatalx("unable to open %s", argv[1]);

    /*
     * Input is in the following format.  There are two types of
     * lines: interfaces, which sets the address and mask of the
     * locally connected ethernet interfaces for the lines that
     * follow and, address lines that include and address (with
     * optional netmask) to match, followed by expected match status
     * (1 or 0).  E.g.
     *
     * interfaces: addr1/mask addr2/mask ...
     * address: addr[/mask] 1/0
     * address: addr[/mask] 1/0
     * interfaces: addr3/mask addr4/mask ...
     * address: addr[/mask] 1/0
     */

    while (fgets(line, sizeof(line), fp) != NULL) {
	len = strcspn(line, "\n");
	line[len] = '\0';

	/* Ignore comments */
	if ((cp = strchr(line, '#')) != NULL)
	    *cp = '\0';

	/* Skip blank lines. */
	if (line[0] == '\0')
	    continue;

	if (strncmp(line, "interfaces:", sizeof("interfaces:") - 1) == 0) {
	    if (!set_interfaces(line + sizeof("interfaces:") - 1)) {
		sudo_warn("unable to parse interfaces list");
		errors++;
	    }
	} else if (strncmp(line, "address:", sizeof("address:") - 1) == 0) {
	    errors += check_addr(line + sizeof("address:") - 1);
	    ntests++;
	} else {
	    sudo_warnx("unexpected data line: %s\n", line);
	    continue;
	}
    }

    if (ntests != 0) {
	printf("check_addr: %d tests run, %d errors, %d%% success rate\n",
	    ntests, errors, (ntests - errors) * 100 / ntests);
    }

    exit(errors);
}
