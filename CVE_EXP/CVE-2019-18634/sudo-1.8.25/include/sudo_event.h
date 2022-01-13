/*
 * Copyright (c) 2013-2015, 2017 Todd C. Miller <Todd.Miller@sudo.ws>
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

#ifndef SUDO_EVENT_H
#define SUDO_EVENT_H

#include <signal.h>	/* for sigatomic_t and NSIG */
#include "sudo_queue.h"

/* Event types */
#define SUDO_EV_TIMEOUT		0x01	/* fire after timeout */
#define SUDO_EV_READ		0x02	/* fire when readable */
#define SUDO_EV_WRITE		0x04	/* fire when writable */
#define SUDO_EV_PERSIST		0x08	/* persist until deleted */
#define SUDO_EV_SIGNAL		0x10	/* fire on signal receipt */
#define SUDO_EV_SIGINFO		0x20	/* fire on signal receipt (siginfo) */

/* Event flags (internal) */
#define SUDO_EVQ_INSERTED	0x01	/* event is on the event queue */
#define SUDO_EVQ_ACTIVE		0x02	/* event is on the active queue */
#define SUDO_EVQ_TIMEOUTS	0x04	/* event is on the timeouts queue */

/* Event loop flags */
#define SUDO_EVLOOP_ONCE	0x01	/* Only run once through the loop */
#define SUDO_EVLOOP_NONBLOCK	0x02	/* Do not block in event loop */

/* Event base flags (internal) */
#define SUDO_EVBASE_LOOPONCE	SUDO_EVLOOP_ONCE
#define SUDO_EVBASE_LOOPEXIT	0x02
#define SUDO_EVBASE_LOOPBREAK	0x04
#define SUDO_EVBASE_LOOPCONT	0x08
#define SUDO_EVBASE_GOT_EXIT	0x10
#define SUDO_EVBASE_GOT_BREAK	0x20
#define SUDO_EVBASE_GOT_MASK	0xf0

typedef void (*sudo_ev_callback_t)(int fd, int what, void *closure);

/*
 * Container for SUDO_EV_SIGINFO events that gets passed as the closure
 * pointer.  This allows us to pass a siginfo_t without changing everything.
 */
struct sudo_ev_siginfo_container {
    void *closure;
    siginfo_t *siginfo;
    char si_buf[1];
};

/* Member of struct sudo_event_base. */
struct sudo_event {
    TAILQ_ENTRY(sudo_event) entries;
    TAILQ_ENTRY(sudo_event) active_entries;
    TAILQ_ENTRY(sudo_event) timeouts_entries;
    struct sudo_event_base *base; /* base this event belongs to */
    int fd;			/* fd/signal we are interested in */
    short events;		/* SUDO_EV_* flags (in) */
    short revents;		/* SUDO_EV_* flags (out) */
    short flags;		/* internal event flags */
    short pfd_idx;		/* index into pfds array (XXX) */
    sudo_ev_callback_t callback;/* user-provided callback */
    struct timespec timeout;	/* for SUDO_EV_TIMEOUT */
    void *closure;		/* user-provided data pointer */
};
TAILQ_HEAD(sudo_event_list, sudo_event);

struct sudo_event_base {
    struct sudo_event_list events; /* tail queue of all events */
    struct sudo_event_list active; /* tail queue of active events */
    struct sudo_event_list timeouts; /* tail queue of timeout events */
    struct sudo_event signal_event; /* storage for signal pipe event */
    struct sudo_event_list signals[NSIG]; /* array of signal event tail queues */
    struct sigaction *orig_handlers[NSIG]; /* original signal handlers */
    siginfo_t *siginfo[NSIG];	/* detailed signal info */
    sig_atomic_t signal_pending[NSIG]; /* pending signals */
    sig_atomic_t signal_caught;	/* at least one signal caught */
    int num_handlers;		/* number of installed handlers */
    int signal_pipe[2];		/* so we can wake up on singal */
#if defined(HAVE_POLL) || defined(HAVE_PPOLL)
    struct pollfd *pfds;	/* array of struct pollfd */
    int pfd_max;		/* size of the pfds array */
    int pfd_high;		/* highest slot used */
    int pfd_free;		/* idx of next free entry or pfd_max if full */
#else
    fd_set *readfds_in;		/* read I/O descriptor set (in) */
    fd_set *writefds_in;	/* write I/O descriptor set (in) */
    fd_set *readfds_out;	/* read I/O descriptor set (out) */
    fd_set *writefds_out;	/* write I/O descriptor set (out) */
    int maxfd;			/* max fd we can store in readfds/writefds */
    int highfd;			/* highest fd to pass as 1st arg to select */
#endif /* HAVE_POLL */
    unsigned int flags;		/* SUDO_EVBASE_* */
};

/* Allocate a new event base. */
__dso_public struct sudo_event_base *sudo_ev_base_alloc_v1(void);
#define sudo_ev_base_alloc() sudo_ev_base_alloc_v1()

/* Free an event base. */
__dso_public void sudo_ev_base_free_v1(struct sudo_event_base *base);
#define sudo_ev_base_free(_a) sudo_ev_base_free_v1((_a))

/* Set the default event base. */
__dso_public void sudo_ev_base_setdef_v1(struct sudo_event_base *base);
#define sudo_ev_base_setdef(_a) sudo_ev_base_setdef_v1((_a))

/* Allocate a new event. */
__dso_public struct sudo_event *sudo_ev_alloc_v1(int fd, short events, sudo_ev_callback_t callback, void *closure);
#define sudo_ev_alloc(_a, _b, _c, _d) sudo_ev_alloc_v1((_a), (_b), (_c), (_d))

/* Free an event. */
__dso_public void sudo_ev_free_v1(struct sudo_event *ev);
#define sudo_ev_free(_a) sudo_ev_free_v1((_a))

/* Add an event, returns 0 on success, -1 on error */
__dso_public int sudo_ev_add_v1(struct sudo_event_base *head, struct sudo_event *ev, struct timeval *timo, bool tohead);
__dso_public int sudo_ev_add_v2(struct sudo_event_base *head, struct sudo_event *ev, struct timespec *timo, bool tohead);
#define sudo_ev_add(_a, _b, _c, _d) sudo_ev_add_v2((_a), (_b), (_c), (_d))

/* Delete an event, returns 0 on success, -1 on error */
__dso_public int sudo_ev_del_v1(struct sudo_event_base *head, struct sudo_event *ev);
#define sudo_ev_del(_a, _b) sudo_ev_del_v1((_a), (_b))

/* Dispatch events, returns SUDO_CB_SUCCESS, SUDO_CB_BREAK or SUDO_CB_ERROR */
__dso_public int sudo_ev_dispatch_v1(struct sudo_event_base *head);
#define sudo_ev_dispatch(_a) sudo_ev_dispatch_v1((_a))

/* Main event loop, returns SUDO_CB_SUCCESS, SUDO_CB_BREAK or SUDO_CB_ERROR */
__dso_public int sudo_ev_loop_v1(struct sudo_event_base *head, int flags);
#define sudo_ev_loop(_a, _b) sudo_ev_loop_v1((_a), (_b))

/* Return the remaining timeout associated with an event. */
__dso_public int sudo_ev_get_timeleft_v1(struct sudo_event *ev, struct timeval *tv);
__dso_public int sudo_ev_get_timeleft_v2(struct sudo_event *ev, struct timespec *tv);
#define sudo_ev_get_timeleft(_a, _b) sudo_ev_get_timeleft_v2((_a), (_b))

/* Cause the event loop to exit after one run through. */
__dso_public void sudo_ev_loopexit_v1(struct sudo_event_base *base);
#define sudo_ev_loopexit(_a) sudo_ev_loopexit_v1((_a))

/* Break out of the event loop right now. */
__dso_public void sudo_ev_loopbreak_v1(struct sudo_event_base *base);
#define sudo_ev_loopbreak(_a) sudo_ev_loopbreak_v1((_a))

/* Rescan for events and restart the event loop. */
__dso_public void sudo_ev_loopcontinue_v1(struct sudo_event_base *base);
#define sudo_ev_loopcontinue(_a) sudo_ev_loopcontinue_v1((_a))

/* Returns true if event loop stopped due to sudo_ev_loopexit(). */
__dso_public bool sudo_ev_got_exit_v1(struct sudo_event_base *base);
#define sudo_ev_got_exit(_a) sudo_ev_got_exit_v1((_a))

/* Returns true if event loop stopped due to sudo_ev_loopbreak(). */
__dso_public bool sudo_ev_got_break_v1(struct sudo_event_base *base);
#define sudo_ev_got_break(_a) sudo_ev_got_break_v1((_a))

/* Return the fd associated with an event. */
#define sudo_ev_get_fd(_ev) ((_ev) ? (_ev)->fd : -1)

/* Return the (absolute) timeout associated with an event or NULL. */
#define sudo_ev_get_timeout(_ev) \
    (ISSET((_ev)->flags, SUDO_EVQ_TIMEOUTS) ? &(_ev)->timeout : NULL)

/* Return the base an event is associated with or NULL. */
#define sudo_ev_get_base(_ev) ((_ev) ? (_ev)->base : NULL)

/* Magic pointer value to use self pointer as callback arg. */
#define sudo_ev_self_cbarg() ((void *)-1)

/* Add an event to the base's active queue and mark it active (internal). */
void sudo_ev_activate(struct sudo_event_base *base, struct sudo_event *ev);

/*
 * Backend implementation.
 */
int sudo_ev_base_alloc_impl(struct sudo_event_base *base);
void sudo_ev_base_free_impl(struct sudo_event_base *base);
int sudo_ev_add_impl(struct sudo_event_base *base, struct sudo_event *ev);
int sudo_ev_del_impl(struct sudo_event_base *base, struct sudo_event *ev);
int sudo_ev_scan_impl(struct sudo_event_base *base, int flags);

#endif /* SUDO_EVENT_H */
