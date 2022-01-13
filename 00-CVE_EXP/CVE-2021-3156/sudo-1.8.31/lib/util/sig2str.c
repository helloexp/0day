/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2012-2015, 2017-2019 Todd C. Miller <Todd.Miller@sudo.ws>
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

#ifndef HAVE_SIG2STR

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <ctype.h>
#include <signal.h>
#include <unistd.h>

#include "sudo_compat.h"

#if defined(HAVE_DECL_SYS_SIGNAME) && HAVE_DECL_SYS_SIGNAME == 1
#  define sudo_sys_signame	sys_signame
#elif defined(HAVE_DECL__SYS_SIGNAME) && HAVE_DECL__SYS_SIGNAME == 1
#  define sudo_sys_signame	_sys_signame
#elif defined(HAVE_DECL_SYS_SIGABBREV) && HAVE_DECL_SYS_SIGABBREV == 1
#  define sudo_sys_signame	sys_sigabbrev
#else
# ifdef HAVE_SYS_SIGABBREV
   /* sys_sigabbrev is not declared by glibc */
#  define sudo_sys_signame	sys_sigabbrev
# endif
extern const char *const sudo_sys_signame[NSIG];
#endif

/*
 * Translate signal number to name.
 */
int
sudo_sig2str(int signo, char *signame)
{
#if defined(SIGRTMIN) && defined(SIGRTMAX)
    /* Realtime signal support. */
    if (signo >= SIGRTMIN && signo <= SIGRTMAX) {
# ifdef _SC_RTSIG_MAX
	const long rtmax = sysconf(_SC_RTSIG_MAX);
# else
	const long rtmax = SIGRTMAX - SIGRTMIN;
# endif
	if (rtmax > 0) {
	    if (signo == SIGRTMIN) {
		strlcpy(signame, "RTMIN", SIG2STR_MAX);
	    } else if (signo == SIGRTMAX) {
		strlcpy(signame, "RTMAX", SIG2STR_MAX);
	    } else if (signo <= SIGRTMIN + (rtmax / 2) - 1) {
		(void)snprintf(signame, SIG2STR_MAX, "RTMIN+%d",
		    (signo - SIGRTMIN));
	    } else {
		(void)snprintf(signame, SIG2STR_MAX, "RTMAX-%d",
		    (SIGRTMAX - signo));
	    }
	}
	return 0;
    }
#endif
    if (signo > 0 && signo < NSIG && sudo_sys_signame[signo] != NULL) {
	strlcpy(signame, sudo_sys_signame[signo], SIG2STR_MAX);
	/* Make sure we always return an upper case signame. */
	if (islower((unsigned char)signame[0])) {
	    int i;
	    for (i = 0; signame[i] != '\0'; i++)
		signame[i] = toupper((unsigned char)signame[i]);
	}
	return 0;
    }
    errno = EINVAL;
    return -1;
}
#endif /* HAVE_SIG2STR */
