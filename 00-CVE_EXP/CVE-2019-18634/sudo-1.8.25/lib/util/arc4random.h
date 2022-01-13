/*	$OpenBSD: arc4random.h,v 1.4 2015/01/15 06:57:18 deraadt Exp $	*/

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2014, Theo de Raadt <deraadt@openbsd.org>
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
 * Stub functions for portability.
 */

#include <sys/mman.h>

#include <signal.h>
#ifdef HAVE_PTHREAD_H
#include <pthread.h>

static pthread_mutex_t arc4random_mtx = PTHREAD_MUTEX_INITIALIZER;
#define _ARC4_LOCK()   pthread_mutex_lock(&arc4random_mtx)
#define _ARC4_UNLOCK() pthread_mutex_unlock(&arc4random_mtx)
#else
#define _ARC4_LOCK()
#define _ARC4_UNLOCK()
#endif /* HAVE_PTHREAD_H */

#ifdef HAVE_PTHREAD_ATFORK
# define _ARC4_ATFORK(f) pthread_atfork(NULL, NULL, (f))
# else
# define _ARC4_ATFORK(f)
#endif

#if !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
# define MAP_ANON MAP_ANONYMOUS
#endif

static inline void
_getentropy_fail(void)
{
	raise(SIGKILL);
}

static volatile sig_atomic_t _rs_forked;

#ifdef HAVE_PTHREAD_ATFORK
static inline void
_rs_forkhandler(void)
{
	_rs_forked = 1;
}
#endif /* HAVE_PTHREAD_ATFORK */

static int wipeonfork;

static inline void
_rs_forkdetect(void)
{
	if (!wipeonfork) {
		static pid_t _rs_pid = 0;
		pid_t pid = getpid();

		if (_rs_pid == 0 || _rs_pid != pid || _rs_forked) {
			_rs_pid = pid;
			_rs_forked = 0;
			if (rs)
				memset(rs, 0, sizeof(*rs));
		}
	}
}

static inline int
_rs_allocate(struct _rs **rsp, struct _rsx **rsxp)
{
	if ((*rsp = (void *)mmap(NULL, sizeof(**rsp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		return (-1);

	if ((*rsxp = (void *)mmap(NULL, sizeof(**rsxp), PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
		munmap((void *)*rsp, sizeof(**rsp));
		*rsp = NULL;
		return (-1);
	}

#ifdef MADV_WIPEONFORK
	if (madvise (*rsp, sizeof(**rsp), MADV_WIPEONFORK) == 0 &&
	    madvise (*rsxp, sizeof(**rsxp), MADV_WIPEONFORK) == 0) {
		wipeonfork = 1;
	}
#endif

	_ARC4_ATFORK(_rs_forkhandler);
	return (0);
}
