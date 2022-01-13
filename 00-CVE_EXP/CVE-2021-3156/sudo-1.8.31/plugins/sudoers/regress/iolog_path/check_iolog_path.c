/*
 * SPDX-License-Identifier: ISC
 *
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
#include <pwd.h>
#include <grp.h>
#include <time.h>

#define SUDO_ERROR_WRAP 0

#include "sudoers.h"
#include "def_data.c"

struct sudo_user sudo_user;
struct passwd *list_pw;

static char sessid[7];

__dso_public int main(int argc, char *argv[]);

static void
usage(void)
{
    fprintf(stderr, "usage: %s datafile\n", getprogname());
    exit(1);
}

static int
do_check(char *dir_in, char *file_in, char *tdir_out, char *tfile_out)
{
    char *path, *slash;
    char dir_out[4096], file_out[4096];
    struct tm *timeptr;
    time_t now;
    int error = 0;

    /*
     * Expand any strftime(3) escapes
     * XXX - want to pass timeptr to expand_iolog_path
     */
    time(&now);
    timeptr = localtime(&now);
    if (timeptr == NULL)
	sudo_fatalx("localtime returned NULL");
    strftime(dir_out, sizeof(dir_out), tdir_out, timeptr);
    strftime(file_out, sizeof(file_out), tfile_out, timeptr);

    path = expand_iolog_path(NULL, dir_in, file_in, &slash);
    if (path == NULL)
	sudo_fatalx("unable to expand I/O log path");
    *slash = '\0';
    if (strcmp(path, dir_out) != 0) {
	sudo_warnx("%s: expected %s, got %s", dir_in, dir_out, path);
	error = 1;
    }
    if (strcmp(slash + 1, file_out) != 0) {
	sudo_warnx("%s: expected %s, got %s", file_in, file_out, slash + 1);
	error = 1;
    }
    free(path);

    return error;
}

#define MAX_STATE	12

int
main(int argc, char *argv[])
{
    struct passwd pw, rpw;
    size_t len;
    FILE *fp;
    char line[2048];
    char *file_in = NULL, *file_out = NULL;
    char *dir_in = NULL, *dir_out = NULL;
    const char *errstr;
    int state = 0;
    int errors = 0;
    int tests = 0;

    initprogname(argc > 0 ? argv[0] : "check_iolog_path");

    if (argc != 2)
	usage();

    fp = fopen(argv[1], "r");
    if (fp == NULL)
	sudo_fatalx("unable to open %s", argv[1]);

    memset(&pw, 0, sizeof(pw));
    memset(&rpw, 0, sizeof(rpw));
    sudo_user.pw = &pw;
    sudo_user._runas_pw = &rpw;

    /*
     * Input consists of 12 lines:
     * sequence number
     * user name
     * user gid
     * runas user name
     * runas gid
     * hostname [short form]
     * command
     * dir [with escapes]
     * file [with escapes]
     * expanded dir
     * expanded file
     * empty line
     */
    while (fgets(line, sizeof(line), fp) != NULL) {
	len = strcspn(line, "\n");
	line[len] = '\0';

	switch (state) {
	case 0:
	    strlcpy(sessid, line, sizeof(sessid));
	    break;
	case 1:
	    if (user_name != NULL)
		free(user_name);
	    user_name = strdup(line);
	    break;
	case 2:
	    user_gid = (gid_t)sudo_strtoid(line, &errstr);
	    if (errstr != NULL)
		sudo_fatalx("group ID %s: %s", line, errstr);
	    break;
	case 3:
	    if (runas_pw->pw_name != NULL)
		free(runas_pw->pw_name);
	    runas_pw->pw_name = strdup(line);
	    break;
	case 4:
	    runas_pw->pw_gid = (gid_t)sudo_strtoid(line, &errstr);
	    if (errstr != NULL)
		sudo_fatalx("group ID %s: %s", line, errstr);
	    break;
	case 5:
	    if (user_shost != NULL)
		free(user_shost);
	    user_shost = strdup(line);
	    break;
	case 6:
	    if (user_base != NULL)
		free(user_base);
	    user_base = strdup(line);
	    break;
	case 7:
	    if (dir_in != NULL)
		free(dir_in);
	    dir_in = strdup(line);
	    break;
	case 8:
	    if (file_in != NULL)
		free(file_in);
	    file_in = strdup(line);
	    break;
	case 9:
	    if (dir_out != NULL)
		free(dir_out);
	    dir_out = strdup(line);
	    break;
	case 10:
	    if (file_out != NULL)
		free(file_out);
	    file_out = strdup(line);
	    break;
	case 11:
	    errors += do_check(dir_in, file_in, dir_out, file_out);
	    tests++;
	    break;
	default:
	    sudo_fatalx("internal error, invalid state %d", state);
	}
	state = (state + 1) % MAX_STATE;
    }

    if (tests != 0) {
	printf("iolog_path: %d test%s run, %d errors, %d%% success rate\n",
	    tests, tests == 1 ? "" : "s", errors,
	    (tests - errors) * 100 / tests);
    }

    exit(errors);
}

bool
io_nextid(char *iolog_dir, char *fallback, char id[7])
{
    memcpy(id, sessid, sizeof(sessid));
    return true;
}
