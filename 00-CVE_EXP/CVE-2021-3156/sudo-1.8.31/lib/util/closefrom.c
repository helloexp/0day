/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2004-2005, 2007, 2010, 2012-2015, 2017-2018
 *	Todd C. Miller <Todd.Miller@sudo.ws>
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

#ifndef HAVE_CLOSEFROM

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#ifdef HAVE_PSTAT_GETPROC
# include <sys/pstat.h>
#else
# include <dirent.h>
#endif

#include "sudo_compat.h"
#include "sudo_util.h"
#include "pathnames.h"

#ifndef _POSIX_OPEN_MAX
# define _POSIX_OPEN_MAX	20
#endif

/*
 * Close all file descriptors greater than or equal to lowfd.
 * This is the expensive (fallback) method.
 */
static void
closefrom_fallback(int lowfd)
{
    long fd, maxfd;

    /*
     * Fall back on sysconf(_SC_OPEN_MAX).  We avoid checking
     * resource limits since it is possible to open a file descriptor
     * and then drop the rlimit such that it is below the open fd.
     */
    maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0)
	maxfd = _POSIX_OPEN_MAX;

    for (fd = lowfd; fd < maxfd; fd++) {
#ifdef __APPLE__
	/* Avoid potential libdispatch crash when we close its fds. */
	(void) fcntl((int) fd, F_SETFD, FD_CLOEXEC);
#else
	(void) close((int) fd);
#endif
    }
}

/*
 * Close all file descriptors greater than or equal to lowfd.
 * We try the fast way first, falling back on the slow method.
 */
void
sudo_closefrom(int lowfd)
{
#if defined(HAVE_PSTAT_GETPROC)
    struct pst_status pstat;
#elif defined(HAVE_DIRFD)
    const char *path;
    DIR *dirp;
#endif

    /* Try the fast method first, if possible. */
#if defined(HAVE_FCNTL_CLOSEM)
    if (fcntl(lowfd, F_CLOSEM, 0) != -1)
	return;
#endif
#if defined(HAVE_PSTAT_GETPROC)
    /*
     * EOVERFLOW is not a fatal error for the fields we use.
     * See the "EOVERFLOW Error" section of pstat_getvminfo(3).
     */                             
    if (pstat_getproc(&pstat, sizeof(pstat), 0, getpid()) != -1 ||
	errno == EOVERFLOW) {
	int fd;

	for (fd = lowfd; fd <= pstat.pst_highestfd; fd++)
	    (void) close(fd);
	return;
    }
#elif defined(HAVE_DIRFD)
    /* Use /proc/self/fd (or /dev/fd on macOS) if it exists. */
# ifdef __APPLE__
    path = _PATH_DEV "fd";
# else
    path = "/proc/self/fd";
# endif
    if ((dirp = opendir(path)) != NULL) {
	struct dirent *dent;
	while ((dent = readdir(dirp)) != NULL) {
	    const char *errstr;
	    int fd = sudo_strtonum(dent->d_name, lowfd, INT_MAX, &errstr);
	    if (errstr == NULL && fd != dirfd(dirp)) {
# ifdef __APPLE__
		/* Avoid potential libdispatch crash when we close its fds. */
		(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
# else
		(void) close(fd);
# endif
	    }
	}
	(void) closedir(dirp);
	return;
    }
#endif /* HAVE_DIRFD */

    /* Do things the slow way. */
    closefrom_fallback(lowfd);
}

#endif /* HAVE_CLOSEFROM */
