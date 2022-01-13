/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2013-2015 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include "sudo_compat.h"
#include "sudo_util.h"
#include "sudo_fatal.h"
#include "sudo_debug.h"
#include "sudo_event.h"

int
sudo_ev_base_alloc_impl(struct sudo_event_base *base)
{
    int i;
    debug_decl(sudo_ev_base_alloc_impl, SUDO_DEBUG_EVENT)

    base->pfd_high = -1;
    base->pfd_max = 32;
    base->pfds = reallocarray(NULL, base->pfd_max, sizeof(struct pollfd));
    if (base->pfds == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "%s: unable to allocate %d pollfds", __func__, base->pfd_max);
	base->pfd_max = 0;
	debug_return_int(-1);
    }
    for (i = 0; i < base->pfd_max; i++) {
	base->pfds[i].fd = -1;
    }

    debug_return_int(0);
}

void
sudo_ev_base_free_impl(struct sudo_event_base *base)
{
    debug_decl(sudo_ev_base_free_impl, SUDO_DEBUG_EVENT)
    free(base->pfds);
    debug_return;
}

int
sudo_ev_add_impl(struct sudo_event_base *base, struct sudo_event *ev)
{
    struct pollfd *pfd;
    debug_decl(sudo_ev_add_impl, SUDO_DEBUG_EVENT)

    /* If out of space in pfds array, realloc. */
    if (base->pfd_free == base->pfd_max) {
	struct pollfd *pfds;
	int i;

	pfds =
	    reallocarray(base->pfds, base->pfd_max, 2 * sizeof(struct pollfd));
	if (pfds == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"%s: unable to allocate %d pollfds", __func__, base->pfd_max * 2);
	    debug_return_int(-1);
	}
	base->pfds = pfds;
	base->pfd_max *= 2;
	for (i = base->pfd_free; i < base->pfd_max; i++) {
	    base->pfds[i].fd = -1;
	}
    }

    /* Fill in pfd entry. */
    ev->pfd_idx = base->pfd_free;
    pfd = &base->pfds[ev->pfd_idx];
    pfd->fd = ev->fd;
    pfd->events = 0;
    if (ISSET(ev->events, SUDO_EV_READ))
	pfd->events |= POLLIN;
    if (ISSET(ev->events, SUDO_EV_WRITE))
	pfd->events |= POLLOUT;

    /* Update pfd_high and pfd_free. */
    if (ev->pfd_idx > base->pfd_high)
	base->pfd_high = ev->pfd_idx;
    for (;;) {
	if (++base->pfd_free == base->pfd_max)
	    break;
	if (base->pfds[base->pfd_free].fd == -1)
	    break;
    }

    debug_return_int(0);
}

int
sudo_ev_del_impl(struct sudo_event_base *base, struct sudo_event *ev)
{
    debug_decl(sudo_ev_del_impl, SUDO_DEBUG_EVENT)

    /* Mark pfd entry unused, add to free list and adjust high slot. */
    base->pfds[ev->pfd_idx].fd = -1;
    if (ev->pfd_idx < base->pfd_free)
	base->pfd_free = ev->pfd_idx;
    while (base->pfd_high >= 0 && base->pfds[base->pfd_high].fd == -1)
	base->pfd_high--;

    debug_return_int(0);
}

#ifdef HAVE_PPOLL
static int
sudo_ev_poll(struct pollfd *fds, nfds_t nfds, const struct timespec *timo)
{
    return ppoll(fds, nfds, timo, NULL);
}
#else
static int
sudo_ev_poll(struct pollfd *fds, nfds_t nfds, const struct timespec *timo)
{
    const int timeout =
	timo ? (timo->tv_sec * 1000) + (timo->tv_nsec / 1000000) : -1;

    return poll(fds, nfds, timeout);
}
#endif /* HAVE_PPOLL */

int
sudo_ev_scan_impl(struct sudo_event_base *base, int flags)
{
    struct timespec now, ts, *timeout;
    struct sudo_event *ev;
    int nready;
    debug_decl(sudo_ev_scan_impl, SUDO_DEBUG_EVENT)

    if ((ev = TAILQ_FIRST(&base->timeouts)) != NULL) {
	sudo_gettime_mono(&now);
	sudo_timespecsub(&ev->timeout, &now, &ts);
	if (ts.tv_sec < 0)
	    sudo_timespecclear(&ts);
	timeout = &ts;
    } else {
	if (ISSET(flags, SUDO_EVLOOP_NONBLOCK)) {
	    sudo_timespecclear(&ts);
	    timeout = &ts;
	} else {
	    timeout = NULL;
	}
    }

    nready = sudo_ev_poll(base->pfds, base->pfd_high + 1, timeout);
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: %d fds ready", __func__, nready);
    switch (nready) {
    case -1:
	/* Error or interrupted by signal. */
	debug_return_int(-1);
    case 0:
	/* Front end will activate timeout events. */
	break;
    default:
	/* Activate each I/O event that fired. */
	TAILQ_FOREACH(ev, &base->events, entries) {
	    if (ev->pfd_idx != -1 && base->pfds[ev->pfd_idx].revents) {
		int what = 0;
		if (base->pfds[ev->pfd_idx].revents & (POLLIN|POLLHUP|POLLNVAL|POLLERR))
		    what |= (ev->events & SUDO_EV_READ);
		if (base->pfds[ev->pfd_idx].revents & (POLLOUT|POLLHUP|POLLNVAL|POLLERR))
		    what |= (ev->events & SUDO_EV_WRITE);
		/* Make event active. */
		sudo_debug_printf(SUDO_DEBUG_DEBUG,
		    "%s: polled fd %d, events %d, activating %p",
		    __func__, ev->fd, what, ev);
		ev->revents = what;
		sudo_ev_activate(base, ev);
	    }
	}
	break;
    }
    debug_return_int(nready);
}
