/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2012, 2014-2016
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_STROPTS_H
#include <sys/stropts.h>
#endif /* HAVE_SYS_STROPTS_H */
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>

#if defined(HAVE_LIBUTIL_H)
# include <libutil.h>
#elif defined(HAVE_UTIL_H)
# include <util.h>
#endif
#ifdef HAVE_PTY_H
# include <pty.h>
#endif

#include "sudo.h"

#if defined(HAVE_OPENPTY)
bool
get_pty(int *master, int *slave, char *name, size_t namesz, uid_t ttyuid)
{
    struct group *gr;
    gid_t ttygid = -1;
    bool ret = false;
    debug_decl(get_pty, SUDO_DEBUG_PTY)

    if ((gr = getgrnam("tty")) != NULL)
	ttygid = gr->gr_gid;

    if (openpty(master, slave, name, NULL, NULL) == 0) {
	if (chown(name, ttyuid, ttygid) == 0)
	    ret = true;
    }

    debug_return_bool(ret);
}

#elif defined(HAVE__GETPTY)
bool
get_pty(int *master, int *slave, char *name, size_t namesz, uid_t ttyuid)
{
    char *line;
    bool ret = false;
    debug_decl(get_pty, SUDO_DEBUG_PTY)

    /* IRIX-style dynamic ptys (may fork) */
    line = _getpty(master, O_RDWR, S_IRUSR|S_IWUSR|S_IWGRP, 0);
    if (line != NULL) {
	*slave = open(line, O_RDWR|O_NOCTTY, 0);
	if (*slave != -1) {
	    (void) chown(line, ttyuid, -1);
	    strlcpy(name, line, namesz);
	    ret = true;
	} else {
	    close(*master);
	    *master = -1;
	}
    }
    debug_return_bool(ret);
}
#elif defined(HAVE_GRANTPT)
# ifndef HAVE_POSIX_OPENPT
static int
posix_openpt(int oflag)
{
    int fd;

#  ifdef _AIX
    fd = open(_PATH_DEV "ptc", oflag);
#  else
    fd = open(_PATH_DEV "ptmx", oflag);
#  endif
    return fd;
}
# endif /* HAVE_POSIX_OPENPT */

bool
get_pty(int *master, int *slave, char *name, size_t namesz, uid_t ttyuid)
{
    char *line;
    bool ret = false;
    debug_decl(get_pty, SUDO_DEBUG_PTY)

    *master = posix_openpt(O_RDWR|O_NOCTTY);
    if (*master != -1) {
	(void) grantpt(*master); /* may fork */
	if (unlockpt(*master) != 0) {
	    close(*master);
	    goto done;
	}
	line = ptsname(*master);
	if (line == NULL) {
	    close(*master);
	    goto done;
	}
	*slave = open(line, O_RDWR|O_NOCTTY, 0);
	if (*slave == -1) {
	    close(*master);
	    goto done;
	}
# if defined(I_PUSH) && !defined(_AIX)
	ioctl(*slave, I_PUSH, "ptem");	/* pseudo tty emulation module */
	ioctl(*slave, I_PUSH, "ldterm");	/* line discipline module */
# endif
	(void) chown(line, ttyuid, -1);
	strlcpy(name, line, namesz);
	ret = true;
    }
done:
    debug_return_bool(ret);
}

#else /* Old-style BSD ptys */

static char line[] = _PATH_DEV "ptyXX";

bool
get_pty(int *master, int *slave, char *name, size_t namesz, uid_t ttyuid)
{
    char *bank, *cp;
    struct group *gr;
    gid_t ttygid = -1;
    bool ret = false;
    debug_decl(get_pty, SUDO_DEBUG_PTY)

    if ((gr = getgrnam("tty")) != NULL)
	ttygid = gr->gr_gid;

    for (bank = "pqrs"; *bank != '\0'; bank++) {
	line[sizeof(_PATH_DEV "ptyX") - 2] = *bank;
	for (cp = "0123456789abcdef"; *cp != '\0'; cp++) {
	    line[sizeof(_PATH_DEV "ptyXX") - 2] = *cp;
	    *master = open(line, O_RDWR|O_NOCTTY, 0);
	    if (*master == -1) {
		if (errno == ENOENT)
		    goto done; /* out of ptys */
		continue; /* already in use */
	    }
	    line[sizeof(_PATH_DEV "p") - 2] = 't';
	    (void) chown(line, ttyuid, ttygid);
	    (void) chmod(line, S_IRUSR|S_IWUSR|S_IWGRP);
# ifdef HAVE_REVOKE
	    (void) revoke(line);
# endif
	    *slave = open(line, O_RDWR|O_NOCTTY, 0);
	    if (*slave != -1) {
		    strlcpy(name, line, namesz);
		    ret = true; /* success */
		    goto done;
	    }
	    (void) close(*master);
	}
    }
done:
    debug_return_bool(ret);
}
#endif /* HAVE_OPENPTY */
