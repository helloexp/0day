/*
 * Copyright (c) 2012-2014 Todd C. Miller <Todd.Miller@sudo.ws>
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
    /* Realtime signal support as per Solaris. */
    if (signo >= SIGRTMIN && signo <= SIGRTMAX) {
	snprintf(signame, SIG2STR_MAX, "RTMIN+%d", (signo - SIGRTMIN));
	return 0;
    }
#endif
    if (signo > 0 && signo < NSIG && sudo_sys_signame[signo] != NULL) {
	strlcpy(signame, sudo_sys_signame[signo], SIG2STR_MAX);
	return 0;
    }
    errno = EINVAL;
    return -1;
}
#endif /* HAVE_SIG2STR */
