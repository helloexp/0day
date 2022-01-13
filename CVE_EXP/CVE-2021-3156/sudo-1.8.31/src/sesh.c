/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2008, 2010-2018 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

#include "sudo_gettext.h"	/* must be included before sudo_compat.h */

#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_exec.h"
#include "sudo_plugin.h"
#include "sudo_util.h"

__dso_public int main(int argc, char *argv[], char *envp[]);

static int sesh_sudoedit(int argc, char *argv[]);

/*
 * Exit codes defined in sudo_exec.h:
 *  SESH_SUCCESS (0)         ... successful operation
 *  SESH_ERR_FAILURE (1)     ... unspecified error
 *  SESH_ERR_INVALID (30)    ... invalid -e arg value
 *  SESH_ERR_BAD_PATHS (31)  ... odd number of paths
 *  SESH_ERR_NO_FILES (32)   ... copy error, no files copied
 *  SESH_ERR_SOME_FILES (33) ... copy error, no files copied
 */
int
main(int argc, char *argv[], char *envp[])
{
    int ret;
    debug_decl(main, SUDO_DEBUG_MAIN)

    initprogname(argc > 0 ? argv[0] : "sesh");

    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE_NAME, LOCALEDIR);
    textdomain(PACKAGE_NAME);

    if (argc < 2)
	sudo_fatalx(U_("requires at least one argument"));

    /* Read sudo.conf and initialize the debug subsystem. */
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG) == -1)
	exit(EXIT_FAILURE);
    sudo_debug_register(getprogname(), NULL, NULL,
	sudo_conf_debug_files(getprogname()));

    if (strcmp(argv[1], "-e") == 0) {
	ret = sesh_sudoedit(argc, argv);
    } else {
	bool login_shell, noexec = false;
	char *cp, *cmnd;
	int fd = -1;

	/* If the first char of argv[0] is '-', we are running a login shell. */
	login_shell = argv[0][0] == '-';

	/* If argv[0] ends in -noexec, pass the flag to sudo_execve() */
	if ((cp = strrchr(argv[0], '-')) != NULL && cp != argv[0])
	    noexec = strcmp(cp, "-noexec") == 0;

	/* If argv[1] is --execfd=%d, extract the fd to exec with. */
	if (strncmp(argv[1], "--execfd=", 9) == 0) {
	    const char *errstr;

	    cp = argv[1] + 9;
	    fd = sudo_strtonum(cp, 0, INT_MAX, &errstr);
	    if (errstr != NULL)
		sudo_fatalx(U_("invalid file descriptor number: %s"), cp);
	    argv++;
	    argc--;
	}

	/* Shift argv and make a copy of the command to execute. */
	argv++;
	argc--;
	if ((cmnd = strdup(argv[0])) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

	/* If invoked as a login shell, modify argv[0] accordingly. */
	if (login_shell) {
	    if ((cp = strrchr(argv[0], '/')) == NULL)
		sudo_fatal(U_("unable to run %s as a login shell"), argv[0]);
	    *cp = '-';
	    argv[0] = cp;
	}
	sudo_execve(fd, cmnd, argv, envp, noexec);
	sudo_warn(U_("unable to execute %s"), cmnd);
	ret = SESH_ERR_FAILURE;
    }
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, ret);
    _exit(ret);
}

static int
sesh_sudoedit(int argc, char *argv[])
{
    int i, oflags_dst, post, ret = SESH_ERR_FAILURE;
    int fd_src = -1, fd_dst = -1, follow = 0;
    ssize_t nread, nwritten;
    struct stat sb;
    struct timespec times[2];
    char buf[BUFSIZ];
    debug_decl(sesh_sudoedit, SUDO_DEBUG_EDIT)

    /* Check for -h flag (don't follow links). */
    if (strcmp(argv[2], "-h") == 0) {
	argv++;
	argc--;
	follow = O_NOFOLLOW;
    }

    if (argc < 3)
	debug_return_int(SESH_ERR_FAILURE);

    /*
     * We need to know whether we are performing the copy operation
     * before or after the editing. Without this we would not know
     * which files are temporary and which are the originals.
     *  post = 0 ... before
     *  post = 1 ... after
     */
    if (strcmp(argv[2], "0") == 0)
	post = 0;
    else if (strcmp(argv[2], "1") == 0)
	post = 1;
    else /* invalid value */
	debug_return_int(SESH_ERR_INVALID);

    /* Align argv & argc to the beggining of the file list. */
    argv += 3;
    argc -= 3;

    /* no files specified, nothing to do */
    if (argc == 0)
	debug_return_int(SESH_SUCCESS);
    /* odd number of paths specified */
    if (argc & 1)
	debug_return_int(SESH_ERR_BAD_PATHS);

    /*
     * Use O_EXCL if we are not in the post editing stage
     * so that it's ensured that the temporary files are
     * created by us and that we are not opening any symlinks.
     */
    oflags_dst = O_WRONLY|O_TRUNC|O_CREAT|(post ? follow : O_EXCL);
    for (i = 0; i < argc - 1; i += 2) {
	const char *path_src = argv[i];
	const char *path_dst = argv[i + 1];
	/*
	 * Try to open the source file for reading. If it
	 * doesn't exist, that's OK, we'll create an empty
	 * destination file.
	 */
	if ((fd_src = open(path_src, O_RDONLY|follow, S_IRUSR|S_IWUSR)) < 0) {
	    if (errno != ENOENT) {
		sudo_warn("%s", path_src);
		if (post) {
		    ret = SESH_ERR_SOME_FILES;
		    goto nocleanup;
		} else
		    goto cleanup_0;
	    }
	}

	if ((fd_dst = open(path_dst, oflags_dst, post ?
	    (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) : (S_IRUSR|S_IWUSR))) < 0) {
	    /* error - cleanup */
	    sudo_warn("%s", path_dst);
	    if (post) {
		ret = SESH_ERR_SOME_FILES;
		goto nocleanup;
	    } else
		goto cleanup_0;
	}

	if (fd_src != -1) {
	    while ((nread = read(fd_src, buf, sizeof(buf))) > 0) {
		if ((nwritten = write(fd_dst, buf, nread)) != nread) {
		    sudo_warn("%s", path_src);
		    if (post) {
			ret = SESH_ERR_SOME_FILES;
			goto nocleanup;
		    } else
			goto cleanup_0;
		}
	    }
	}

	if (!post) {
	    if (fd_src == -1 || fstat(fd_src, &sb) != 0)
		memset(&sb, 0, sizeof(sb));
	    /* Make mtime on temp file match src. */
	    mtim_get(&sb, times[0]);
	    times[1].tv_sec = times[0].tv_sec;
	    times[1].tv_nsec = times[0].tv_nsec;
	    if (futimens(fd_dst, times) == -1) {
		if (utimensat(AT_FDCWD, path_dst, times, 0) == -1)
		    sudo_warn("%s", path_dst);
	    }
	}
	close(fd_dst);
	fd_dst = -1;
	if (fd_src != -1) {
	    close(fd_src);
	    fd_src = -1;
	}
    }

    ret = SESH_SUCCESS;
    if (post) {
	/* Remove temporary files (post=1) */
	for (i = 0; i < argc - 1; i += 2)
	    unlink(argv[i]);
    }
nocleanup:
    if (fd_dst != -1)
	close(fd_dst);
    if (fd_src != -1)
	close(fd_src);
    return(ret);
cleanup_0:
    /* Remove temporary files (post=0) */
    for (i = 0; i < argc - 1; i += 2)
	unlink(argv[i + 1]);
    if (fd_dst != -1)
	close(fd_dst);
    if (fd_src != -1)
	close(fd_src);
    return(SESH_ERR_NO_FILES);
}
