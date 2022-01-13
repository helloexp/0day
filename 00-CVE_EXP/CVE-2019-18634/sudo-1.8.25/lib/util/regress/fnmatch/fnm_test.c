/*	$OpenBSD: fnm_test.c,v 1.1 2008/10/01 23:04:58 millert Exp $	*/

/*
 * Public domain, 2008, Todd C. Miller <Todd.Miller@sudo.ws>
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

#include "sudo_compat.h"
#include "sudo_util.h"

#ifdef HAVE_FNMATCH
# include <fnmatch.h>
#else
# include "compat/fnmatch.h"
#endif

__dso_public int main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
	FILE *fp = stdin;
	char pattern[1024], string[1024], flagstr[1024];
	int errors = 0, tests = 0, flags, got, want;

	initprogname(argc > 0 ? argv[0] : "fnm_test");

	if (argc > 1) {
		if ((fp = fopen(argv[1], "r")) == NULL) {
			perror(argv[1]);
			exit(1);
		}
	}

	/*
	 * Read in test file, which is formatted thusly:
	 *
	 * pattern string flags expected_result
	 *
	 */
	for (;;) {
		got = fscanf(fp, "%s %s %s %d\n", pattern, string, flagstr,
		    &want);
		if (got == EOF)
			break;
		if (got == 4) {
			flags = 0;
			if (strcmp(flagstr, "FNM_NOESCAPE") == 0)
				flags |= FNM_NOESCAPE;
			else if (strcmp(flagstr, "FNM_PATHNAME") == 0)
				flags |= FNM_PATHNAME;
			else if (strcmp(flagstr, "FNM_PERIOD") == 0)
				flags |= FNM_PERIOD;
			else if (strcmp(flagstr, "FNM_LEADING_DIR") == 0)
				flags |= FNM_LEADING_DIR;
			else if (strcmp(flagstr, "FNM_CASEFOLD") == 0)
				flags |= FNM_CASEFOLD;
			got = fnmatch(pattern, string, flags);
			if (got != want) {
				fprintf(stderr,
				    "fnmatch: %s %s %d: want %d, got %d\n",
				    pattern, string, flags, want, got);
				errors++;
			}
			tests++;
		}
	}
	if (tests != 0) {
		printf("fnmatch: %d test%s run, %d errors, %d%% success rate\n",
		    tests, tests == 1 ? "" : "s", errors,
		    (tests - errors) * 100 / tests);
	}
	exit(errors);
}
