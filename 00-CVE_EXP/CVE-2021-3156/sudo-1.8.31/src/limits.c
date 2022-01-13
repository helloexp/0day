/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1999-2019 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#ifdef __linux__
# include <sys/prctl.h>
#endif
#include <errno.h>
#include <limits.h>

#include "sudo.h"

#if defined(OPEN_MAX) && OPEN_MAX > 256
# define SUDO_OPEN_MAX	OPEN_MAX
#else
# define SUDO_OPEN_MAX	256
#endif

#ifdef __LP64__
# define SUDO_STACK_MIN	(4 * 1024 * 1024)
#else
# define SUDO_STACK_MIN	(2 * 1024 * 1024)
#endif

#ifdef HAVE_SETRLIMIT64
# define getrlimit(a, b) getrlimit64((a), (b))
# define setrlimit(a, b) setrlimit64((a), (b))
# define rlimit rlimit64
# define rlim_t rlim64_t
# undef RLIM_INFINITY
# define RLIM_INFINITY RLIM64_INFINITY
#endif /* HAVE_SETRLIMIT64 */

/*
 * macOS doesn't allow nofile soft limit to be infinite or
 * the stack hard limit to be infinite.
 * Linux containers have a problem with an infinite stack soft limit.
 */
static struct rlimit nofile_fallback = { SUDO_OPEN_MAX, RLIM_INFINITY };
static struct rlimit stack_fallback = { SUDO_STACK_MIN, 65532 * 1024 };

static struct saved_limit {
    const char *name;
    int resource;
    bool saved;
    struct rlimit *fallback;
    struct rlimit newlimit;
    struct rlimit oldlimit;
} saved_limits[] = {
#ifdef RLIMIT_AS
    { "RLIMIT_AS", RLIMIT_AS, false, NULL, { RLIM_INFINITY, RLIM_INFINITY } },
#endif
    { "RLIMIT_CPU", RLIMIT_CPU, false, NULL, { RLIM_INFINITY, RLIM_INFINITY } },
    { "RLIMIT_DATA", RLIMIT_DATA, false, NULL, { RLIM_INFINITY, RLIM_INFINITY } },
    { "RLIMIT_FSIZE", RLIMIT_FSIZE, false, NULL, { RLIM_INFINITY, RLIM_INFINITY } },
    { "RLIMIT_NOFILE", RLIMIT_NOFILE, false, &nofile_fallback, { RLIM_INFINITY, RLIM_INFINITY } },
#ifdef RLIMIT_NPROC
    { "RLIMIT_NPROC", RLIMIT_NPROC, false, NULL, { RLIM_INFINITY, RLIM_INFINITY } },
#endif
#ifdef RLIMIT_RSS
    { "RLIMIT_RSS", RLIMIT_RSS, false, NULL, { RLIM_INFINITY, RLIM_INFINITY } },
#endif
    { "RLIMIT_STACK", RLIMIT_STACK, false, &stack_fallback, { SUDO_STACK_MIN, RLIM_INFINITY } }
};

static struct rlimit corelimit;
static bool coredump_disabled;
#ifdef __linux__
static struct rlimit nproclimit;
static int dumpflag;
#endif

/*
 * Disable core dumps to avoid dropping a core with user password in it.
 * Not all operating systems disable core dumps for setuid processes.
 */
void
disable_coredump(void)
{
    struct rlimit rl = { 0, 0 };
    debug_decl(disable_coredump, SUDO_DEBUG_UTIL)

    if (getrlimit(RLIMIT_CORE, &corelimit) == -1)
	sudo_warn("getrlimit(RLIMIT_CORE)");
    if (setrlimit(RLIMIT_CORE, &rl) == -1)
	sudo_warn("setrlimit(RLIMIT_CORE)");
#ifdef __linux__
    /* On Linux, also set PR_SET_DUMPABLE to zero (reset by execve). */
    if ((dumpflag = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)) == -1)
	dumpflag = 0;
    (void) prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif /* __linux__ */
    coredump_disabled = true;

    debug_return;
}

/*
 * Restore core resource limit before executing the command.
 */
static void
restore_coredump(void)
{
    debug_decl(restore_coredump, SUDO_DEBUG_UTIL)

    if (coredump_disabled) {
	if (setrlimit(RLIMIT_CORE, &corelimit) == -1)
	    sudo_warn("setrlimit(RLIMIT_CORE)");
#ifdef __linux__
	(void) prctl(PR_SET_DUMPABLE, dumpflag, 0, 0, 0);
#endif /* __linux__ */
    }
    debug_return;
}

/*
 * Unlimit the number of processes since Linux's setuid() will
 * apply resource limits when changing uid and return EAGAIN if
 * nproc would be exceeded by the uid switch.
 *
 * This function is called *after* session setup and before the
 * final setuid() call.
 */
void
unlimit_nproc(void)
{
#ifdef __linux__
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    debug_decl(unlimit_nproc, SUDO_DEBUG_UTIL)

    if (getrlimit(RLIMIT_NPROC, &nproclimit) != 0)
	sudo_warn("getrlimit(RLIMIT_NPROC)");
    if (setrlimit(RLIMIT_NPROC, &rl) == -1) {
	rl.rlim_cur = rl.rlim_max = nproclimit.rlim_max;
	if (setrlimit(RLIMIT_NPROC, &rl) != 0)
	    sudo_warn("setrlimit(RLIMIT_NPROC)");
    }
    debug_return;
#endif /* __linux__ */
}

/*
 * Restore saved value of RLIMIT_NPROC before execve().
 */
void
restore_nproc(void)
{
#ifdef __linux__
    debug_decl(restore_nproc, SUDO_DEBUG_UTIL)

    if (setrlimit(RLIMIT_NPROC, &nproclimit) != 0)
	sudo_warn("setrlimit(RLIMIT_NPROC)");

    debug_return;
#endif /* __linux__ */
}

/*
 * Unlimit resource limits so sudo is not limited by, e.g.
 * stack, data or file table sizes.
 */
void
unlimit_sudo(void)
{
    unsigned int idx;
    int rc;
    debug_decl(unlimit_sudo, SUDO_DEBUG_UTIL)

    /* Set resource limits to unlimited and stash the old values. */
    for (idx = 0; idx < nitems(saved_limits); idx++) {
	struct saved_limit *lim = &saved_limits[idx];
	if (getrlimit(lim->resource, &lim->oldlimit) == -1)
	    continue;
	lim->saved = true;
	if (lim->newlimit.rlim_cur != RLIM_INFINITY) {
	    /* Don't reduce the soft resource limit. */
	    if (lim->oldlimit.rlim_cur == RLIM_INFINITY ||
		    lim->oldlimit.rlim_cur > lim->newlimit.rlim_cur)
		lim->newlimit.rlim_cur = lim->oldlimit.rlim_cur;
	}
	if (lim->newlimit.rlim_max != RLIM_INFINITY) {
	    /* Don't reduce the hard resource limit. */
	    if (lim->oldlimit.rlim_max == RLIM_INFINITY ||
		    lim->oldlimit.rlim_max > lim->newlimit.rlim_max)
		lim->newlimit.rlim_max = lim->oldlimit.rlim_max;
	}
	if ((rc = setrlimit(lim->resource, &lim->newlimit)) == -1) {
	    if (lim->fallback != NULL)
		rc = setrlimit(lim->resource, lim->fallback);
	    if (rc == -1) {
		/* Try setting new rlim_cur to old rlim_max. */
		lim->newlimit.rlim_cur = lim->oldlimit.rlim_max;
		lim->newlimit.rlim_max = lim->oldlimit.rlim_max;
		rc = setrlimit(lim->resource, &lim->newlimit);
	    }
	    if (rc == -1)
		sudo_warn("setrlimit(%s)", lim->name);
	}
    }

    debug_return;
}

/*
 * Restore resource limits modified by unlimit_sudo() and disable_coredump().
 */
void
restore_limits(void)
{
    unsigned int idx;
    debug_decl(restore_limits, SUDO_DEBUG_UTIL)

    /* Restore resource limits to saved values. */
    for (idx = 0; idx < nitems(saved_limits); idx++) {
	struct saved_limit *lim = &saved_limits[idx];
	if (lim->saved) {
	    struct rlimit rl = lim->oldlimit;
	    int i, rc;

	    for (i = 0; i < 10; i++) {
		rc = setrlimit(lim->resource, &rl);
		if (rc != -1 || errno != EINVAL)
		    break;

		/*
		 * Soft limit could be lower than current resource usage.
		 * This can be an issue on NetBSD with RLIMIT_STACK and ASLR.
		 */
		if (rl.rlim_cur > LLONG_MAX / 2)
		    break;
		rl.rlim_cur *= 2;
		if (lim->newlimit.rlim_cur != RLIM_INFINITY &&
			rl.rlim_cur > lim->newlimit.rlim_cur) {
		    rl.rlim_cur = lim->newlimit.rlim_cur;
		}
		if (rl.rlim_max != RLIM_INFINITY &&
			rl.rlim_cur > rl.rlim_max) {
		    rl.rlim_max = rl.rlim_cur;
		}
		rc = setrlimit(lim->resource, &rl);
		if (rc != -1 || errno != EINVAL)
		    break;
	    }
	    if (rc == -1)
		sudo_warn("setrlimit(%s)", lim->name);
	}
    }
    restore_coredump();

    debug_return;
}
