/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2019 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
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
#include <signal.h>
#include <termios.h>		/* for struct winsize on HP-UX */

#include "sudo.h"
#include "sudo_event.h"
#include "sudo_exec.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

/* Evaluates to true if the event has /dev/tty as its fd. */
#define USERTTY_EVENT(_ev)	(sudo_ev_get_fd((_ev)) == io_fds[SFD_USERTTY])

#define TERM_COOKED	0
#define TERM_RAW	1

/* Tail queue of messages to send to the monitor. */
struct monitor_message {
    TAILQ_ENTRY(monitor_message) entries;
    struct command_status cstat;
};
TAILQ_HEAD(monitor_message_list, monitor_message);

struct exec_closure_pty {
    pid_t monitor_pid;
    pid_t cmnd_pid;
    pid_t ppgrp;
    short rows;
    short cols;
    struct command_status *cstat;
    struct command_details *details;
    struct sudo_event_base *evbase;
    struct sudo_event *backchannel_event;
    struct sudo_event *fwdchannel_event;
    struct sudo_event *sigint_event;
    struct sudo_event *sigquit_event;
    struct sudo_event *sigtstp_event;
    struct sudo_event *sigterm_event;
    struct sudo_event *sighup_event;
    struct sudo_event *sigalrm_event;
    struct sudo_event *sigusr1_event;
    struct sudo_event *sigusr2_event;
    struct sudo_event *sigchld_event;
    struct sudo_event *sigwinch_event;
    struct monitor_message_list monitor_messages;
};

/*
 * I/O buffer with associated read/write events and a logging action.
 * Used to, e.g. pass data from the pty to the user's terminal
 * and any I/O logging plugins.
 */
struct io_buffer;
typedef bool (*sudo_io_action_t)(const char *, unsigned int, struct io_buffer *);
struct io_buffer {
    SLIST_ENTRY(io_buffer) entries;
    struct exec_closure_pty *ec;
    struct sudo_event *revent;
    struct sudo_event *wevent;
    sudo_io_action_t action;
    int len; /* buffer length (how much produced) */
    int off; /* write position (how much already consumed) */
    char buf[64 * 1024];
};
SLIST_HEAD(io_buffer_list, io_buffer);

static char ptyname[PATH_MAX];
int io_fds[6] = { -1, -1, -1, -1, -1, -1};
static bool foreground, pipeline;
static int ttymode = TERM_COOKED;
static sigset_t ttyblock;
static struct io_buffer_list iobufs;
static const char *utmp_user;

static void del_io_events(bool nonblocking);
static void sync_ttysize(struct exec_closure_pty *ec);
static int safe_close(int fd);
static void ev_free_by_fd(struct sudo_event_base *evbase, int fd);
static void check_foreground(struct exec_closure_pty *ec);
static void add_io_events(struct sudo_event_base *evbase);
static void schedule_signal(struct exec_closure_pty *ec, int signo);

/*
 * Cleanup hook for sudo_fatal()/sudo_fatalx()
 */
void
pty_cleanup(void)
{
    debug_decl(cleanup, SUDO_DEBUG_EXEC);

    if (io_fds[SFD_USERTTY] != -1)
	sudo_term_restore(io_fds[SFD_USERTTY], false);
    if (utmp_user != NULL)
	utmp_logout(ptyname, 0);

    debug_return;
}

/*
 * Allocate a pty if /dev/tty is a tty.
 * Fills in io_fds[SFD_USERTTY], io_fds[SFD_MASTER], io_fds[SFD_SLAVE]
 * and ptyname globals.
 */
static bool
pty_setup(struct command_details *details, const char *tty)
{
    debug_decl(pty_setup, SUDO_DEBUG_EXEC);

    io_fds[SFD_USERTTY] = open(_PATH_TTY, O_RDWR);
    if (io_fds[SFD_USERTTY] == -1) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: no %s, not allocating a pty",
	    __func__, _PATH_TTY);
	debug_return_bool(false);
    }

    if (!get_pty(&io_fds[SFD_MASTER], &io_fds[SFD_SLAVE],
	ptyname, sizeof(ptyname), details->euid))
	sudo_fatal(U_("unable to allocate pty"));

    /* Update tty name in command details (used by SELinux and AIX). */
    details->tty = ptyname;

    /* Add entry to utmp/utmpx? */
    if (ISSET(details->flags, CD_SET_UTMP)) {
	utmp_user =
	    details->utmp_user ? details->utmp_user : user_details.username;
	utmp_login(tty, ptyname, io_fds[SFD_SLAVE], utmp_user);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: %s fd %d, pty master fd %d, pty slave fd %d",
	__func__, _PATH_TTY, io_fds[SFD_USERTTY], io_fds[SFD_MASTER],
	io_fds[SFD_SLAVE]);

    debug_return_bool(true);
}

/*
 * Make the tty slave the controlling tty.
 * This is only used by the monitor but ptyname[] is static.
 */
int
pty_make_controlling(void)
{
    if (io_fds[SFD_SLAVE] != -1) {
#ifdef TIOCSCTTY
	if (ioctl(io_fds[SFD_SLAVE], TIOCSCTTY, NULL) != 0)
	    return -1;
#else
	/* Set controlling tty by reopening pty slave. */
	int fd = open(ptyname, O_RDWR);
	if (fd == -1)
	    return -1;
	close(fd);
#endif
    }
    return 0;
}

/* Call I/O plugin tty input log method. */
static bool
log_ttyin(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool ret = true;
    debug_decl(log_ttyin, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->log_ttyin) {
	    int rc;

	    sudo_debug_set_active_instance(plugin->debug_instance);
	    rc = plugin->u.io->log_ttyin(buf, n);
	    if (rc <= 0) {
		if (rc < 0) {
		    /* Error: disable plugin's I/O function. */
		    plugin->u.io->log_ttyin = NULL;
		}
		ret = false;
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(ret);
}

/* Call I/O plugin stdin log method. */
static bool
log_stdin(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool ret = true;
    debug_decl(log_stdin, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->log_stdin) {
	    int rc;

	    sudo_debug_set_active_instance(plugin->debug_instance);
	    rc = plugin->u.io->log_stdin(buf, n);
	    if (rc <= 0) {
		if (rc < 0) {
		    /* Error: disable plugin's I/O function. */
		    plugin->u.io->log_stdin = NULL;
		}
		ret = false;
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(ret);
}

/* Call I/O plugin tty output log method. */
static bool
log_ttyout(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool ret = true;
    debug_decl(log_ttyout, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->log_ttyout) {
	    int rc;

	    sudo_debug_set_active_instance(plugin->debug_instance);
	    rc = plugin->u.io->log_ttyout(buf, n);
	    if (rc <= 0) {
		if (rc < 0) {
		    /* Error: disable plugin's I/O function. */
		    plugin->u.io->log_ttyout = NULL;
		}
		ret = false;
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    if (!ret) {
	/*
	 * I/O plugin rejected the output, delete the write event
	 * (user's tty) so we do not display the rejected output.
	 */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: deleting and freeing devtty wevent %p", __func__, iob->wevent);
	sudo_ev_free(iob->wevent);
	iob->wevent = NULL;
	iob->off = iob->len = 0;
    }
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(ret);
}

/* Call I/O plugin stdout log method. */
static bool
log_stdout(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool ret = true;
    debug_decl(log_stdout, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->log_stdout) {
	    int rc;

	    sudo_debug_set_active_instance(plugin->debug_instance);
	    rc = plugin->u.io->log_stdout(buf, n);
	    if (rc <= 0) {
		if (rc < 0) {
		    /* Error: disable plugin's I/O function. */
		    plugin->u.io->log_stdout = NULL;
		}
		ret = false;
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    if (!ret) {
	/*
	 * I/O plugin rejected the output, delete the write event
	 * (user's stdout) so we do not display the rejected output.
	 */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: deleting and freeing stdout wevent %p", __func__, iob->wevent);
	sudo_ev_free(iob->wevent);
	iob->wevent = NULL;
	iob->off = iob->len = 0;
    }
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(ret);
}

/* Call I/O plugin stderr log method. */
static bool
log_stderr(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool ret = true;
    debug_decl(log_stderr, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->log_stderr) {
	    int rc;

	    sudo_debug_set_active_instance(plugin->debug_instance);
	    rc = plugin->u.io->log_stderr(buf, n);
	    if (rc <= 0) {
		if (rc < 0) {
		    /* Error: disable plugin's I/O function. */
		    plugin->u.io->log_stderr = NULL;
		}
		ret = false;
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    if (!ret) {
	/*
	 * I/O plugin rejected the output, delete the write event
	 * (user's stderr) so we do not display the rejected output.
	 */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: deleting and freeing stderr wevent %p", __func__, iob->wevent);
	sudo_ev_free(iob->wevent);
	iob->wevent = NULL;
	iob->off = iob->len = 0;
    }
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(ret);
}

/* Call I/O plugin suspend log method. */
static void
log_suspend(int signo)
{
    struct plugin_container *plugin;
    sigset_t omask;
    debug_decl(log_suspend, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->version < SUDO_API_MKVERSION(1, 13))
	    continue;
	if (plugin->u.io->log_suspend) {
	    int rc;

	    sudo_debug_set_active_instance(plugin->debug_instance);
	    rc = plugin->u.io->log_suspend(signo);
	    if (rc <= 0) {
		if (rc < 0) {
		    /* Error: disable plugin's I/O function. */
		    plugin->u.io->log_suspend = NULL;
		}
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return;
}

/* Call I/O plugin window change log method. */
static void
log_winchange(unsigned int rows, unsigned int cols)
{
    struct plugin_container *plugin;
    sigset_t omask;
    debug_decl(log_winchange, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->version < SUDO_API_MKVERSION(1, 12))
	    continue;
	if (plugin->u.io->change_winsize) {
	    int rc;

	    sudo_debug_set_active_instance(plugin->debug_instance);
	    rc = plugin->u.io->change_winsize(rows, cols);
	    if (rc <= 0) {
		if (rc < 0) {
		    /* Error: disable plugin's I/O function. */
		    plugin->u.io->change_winsize = NULL;
		}
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return;
}

/*
 * Check whether we are running in the foregroup.
 * Updates the foreground global and does lazy init of the
 * the pty slave as needed.
 */
static void
check_foreground(struct exec_closure_pty *ec)
{
    debug_decl(check_foreground, SUDO_DEBUG_EXEC);

    if (io_fds[SFD_USERTTY] != -1) {
	foreground = tcgetpgrp(io_fds[SFD_USERTTY]) == ec->ppgrp;

	/* Also check for window size changes. */
	sync_ttysize(ec);
    }

    debug_return;
}

/*
 * Suspend sudo if the underlying command is suspended.
 * Returns SIGCONT_FG if the command should be resumed in the
 * foreground or SIGCONT_BG if it is a background process.
 */
static int
suspend_sudo(struct exec_closure_pty *ec, int signo)
{
    char signame[SIG2STR_MAX];
    struct sigaction sa, osa;
    int ret = 0;
    debug_decl(suspend_sudo, SUDO_DEBUG_EXEC);

    switch (signo) {
    case SIGTTOU:
    case SIGTTIN:
	/*
	 * If sudo is already the foreground process, just resume the command
	 * in the foreground.  If not, we'll suspend sudo and resume later.
	 */
	if (!foreground)
	    check_foreground(ec);
	if (foreground) {
	    if (ttymode != TERM_RAW) {
		if (sudo_term_raw(io_fds[SFD_USERTTY], 0))
		    ttymode = TERM_RAW;
	    }
	    ret = SIGCONT_FG; /* resume command in foreground */
	    break;
	}
	/* FALLTHROUGH */
    case SIGSTOP:
    case SIGTSTP:
	/* Flush any remaining output and deschedule I/O events. */
	del_io_events(true);

	/* Restore original tty mode before suspending. */
	if (ttymode != TERM_COOKED)
	    sudo_term_restore(io_fds[SFD_USERTTY], false);

	/* Log the suspend event. */
	log_suspend(signo);

	if (sig2str(signo, signame) == -1)
	    (void)snprintf(signame, sizeof(signame), "%d", signo);

	/* Suspend self and continue command when we resume. */
	if (signo != SIGSTOP) {
	    memset(&sa, 0, sizeof(sa));
	    sigemptyset(&sa.sa_mask);
	    sa.sa_flags = SA_RESTART;
	    sa.sa_handler = SIG_DFL;
	    if (sudo_sigaction(signo, &sa, &osa) != 0)
		sudo_warn(U_("unable to set handler for signal %d"), signo);
	}
	sudo_debug_printf(SUDO_DEBUG_INFO, "kill parent SIG%s", signame);
	if (killpg(ec->ppgrp, signo) != 0)
	    sudo_warn("killpg(%d, SIG%s)", (int)ec->ppgrp, signame);

	/* Log the resume event. */
	log_suspend(SIGCONT);

	/* Check foreground/background status on resume. */
	check_foreground(ec);

	/*
	 * We always resume the command in the foreground if sudo itself
	 * is the foreground process.  This helps work around poorly behaved
	 * programs that catch SIGTTOU/SIGTTIN but suspend themselves with
	 * SIGSTOP.  At worst, sudo will go into the background but upon
	 * resume the command will be runnable.  Otherwise, we can get into
	 * a situation where the command will immediately suspend itself.
	 */
	sudo_debug_printf(SUDO_DEBUG_INFO, "parent is in %s, ttymode %d -> %d",
	    foreground ? "foreground" : "background", ttymode,
	    foreground ? TERM_RAW : TERM_COOKED);

	if (foreground) {
	    /* Foreground process, set tty to raw mode. */
	    if (sudo_term_raw(io_fds[SFD_USERTTY], 0))
		ttymode = TERM_RAW;
	} else {
	    /* Background process, no access to tty. */
	    ttymode = TERM_COOKED;
	}

	if (signo != SIGSTOP) {
	    if (sudo_sigaction(signo, &osa, NULL) != 0)
		sudo_warn(U_("unable to restore handler for signal %d"), signo);
	}

	ret = ttymode == TERM_RAW ? SIGCONT_FG : SIGCONT_BG;
	break;
    }

    debug_return_int(ret);
}

/*
 * SIGTTIN signal handler for read_callback that just sets a flag.
 */
static volatile sig_atomic_t got_sigttin;

static void
sigttin(int signo)
{
    got_sigttin = 1;
}

/*
 * Read an iobuf that is ready.
 */
static void
read_callback(int fd, int what, void *v)
{
    struct io_buffer *iob = v;
    struct sudo_event_base *evbase = sudo_ev_get_base(iob->revent);
    struct sigaction sa, osa;
    int saved_errno;
    ssize_t n;
    debug_decl(read_callback, SUDO_DEBUG_EXEC);

    /*
     * We ignore SIGTTIN by default but we need to handle it when reading
     * from the terminal.  A signal event won't work here because the
     * read() would be restarted, preventing the callback from running.
     */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sigttin;
    got_sigttin = 0;
    sigaction(SIGTTIN, &sa, &osa);
    n = read(fd, iob->buf + iob->len, sizeof(iob->buf) - iob->len);
    saved_errno = errno;
    sigaction(SIGTTIN, &osa, NULL);
    errno = saved_errno;

    switch (n) {
	case -1:
	    if (got_sigttin) {
		/* Schedule SIGTTIN to be forwared to the command. */
		schedule_signal(iob->ec, SIGTTIN);
	    }
	    if (errno == EAGAIN || errno == EINTR)
		break;
	    /* treat read error as fatal and close the fd */
	    sudo_debug_printf(SUDO_DEBUG_ERROR,
		"error reading fd %d: %s", fd, strerror(errno));
	    /* FALLTHROUGH */
	case 0:
	    /* got EOF or pty has gone away */
	    if (n == 0) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "read EOF from fd %d", fd);
	    }
	    safe_close(fd);
	    ev_free_by_fd(evbase, fd);
	    /* If writer already consumed the buffer, close it too. */
	    if (iob->wevent != NULL && iob->off == iob->len) {
		safe_close(sudo_ev_get_fd(iob->wevent));
		ev_free_by_fd(evbase, sudo_ev_get_fd(iob->wevent));
		iob->off = iob->len = 0;
	    }
	    break;
	default:
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"read %zd bytes from fd %d", n, fd);
	    if (!iob->action(iob->buf + iob->len, n, iob)) {
		terminate_command(iob->ec->cmnd_pid, true);
		iob->ec->cmnd_pid = -1;
	    }
	    iob->len += n;
	    /* Enable writer now that there is data in the buffer. */
	    if (iob->wevent != NULL) {
		if (sudo_ev_add(evbase, iob->wevent, NULL, false) == -1)
		    sudo_fatal(U_("unable to add event to queue"));
	    }
	    /* Re-enable reader if buffer is not full. */
	    if (iob->len != sizeof(iob->buf)) {
		if (sudo_ev_add(evbase, iob->revent, NULL, false) == -1)
		    sudo_fatal(U_("unable to add event to queue"));
	    }
	    break;
    }
}

/*
 * SIGTTOU signal handler for write_callback that just sets a flag.
 */
static volatile sig_atomic_t got_sigttou;

static void
sigttou(int signo)
{
    got_sigttou = 1;
}

/*
 * Write an iobuf that is ready.
 */
static void
write_callback(int fd, int what, void *v)
{
    struct io_buffer *iob = v;
    struct sudo_event_base *evbase = sudo_ev_get_base(iob->wevent);
    struct sigaction sa, osa;
    int saved_errno;
    ssize_t n;
    debug_decl(write_callback, SUDO_DEBUG_EXEC);

    /*
     * We ignore SIGTTOU by default but we need to handle it when writing
     * to the terminal.  A signal event won't work here because the
     * write() would be restarted, preventing the callback from running.
     */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sigttou;
    got_sigttou = 0;
    sigaction(SIGTTOU, &sa, &osa);
    n = write(fd, iob->buf + iob->off, iob->len - iob->off);
    saved_errno = errno;
    sigaction(SIGTTOU, &osa, NULL);
    errno = saved_errno;

    if (n == -1) {
	switch (errno) {
	case EPIPE:
	case ENXIO:
	case EIO:
	case EBADF:
	    /* other end of pipe closed or pty revoked */
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"unable to write %d bytes to fd %d",
		iob->len - iob->off, fd);
	    /* Close reader if there is one. */
	    if (iob->revent != NULL) {
		safe_close(sudo_ev_get_fd(iob->revent));
		ev_free_by_fd(evbase, sudo_ev_get_fd(iob->revent));
	    }
	    safe_close(fd);
	    ev_free_by_fd(evbase, fd);
	    break;
	case EINTR:
	    if (got_sigttou) {
		/* Schedule SIGTTOU to be forwared to the command. */
		schedule_signal(iob->ec, SIGTTOU);
	    }
	    /* FALLTHROUGH */
	case EAGAIN:
	    /* not an error */
	    break;
	default:
	    /* XXX - need a way to distinguish non-exec error. */
	    iob->ec->cstat->type = CMD_ERRNO;
	    iob->ec->cstat->val = errno;
	    sudo_debug_printf(SUDO_DEBUG_ERROR,
		"error writing fd %d: %s", fd, strerror(errno));
	    sudo_ev_loopbreak(evbase);
	    break;
	}
    } else {
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "wrote %zd bytes to fd %d", n, fd);
	iob->off += n;
	/* Reset buffer if fully consumed. */
	if (iob->off == iob->len) {
	    iob->off = iob->len = 0;
	    /* Forward the EOF from reader to writer. */
	    if (iob->revent == NULL) {
		safe_close(fd);
		ev_free_by_fd(evbase, fd);
	    }
	}
	/* Re-enable writer if buffer is not empty. */
	if (iob->len > iob->off) {
	    if (sudo_ev_add(evbase, iob->wevent, NULL, false) == -1)
		sudo_fatal(U_("unable to add event to queue"));
	}
	/* Enable reader if buffer is not full. */
	if (iob->revent != NULL &&
	    (ttymode == TERM_RAW || !USERTTY_EVENT(iob->revent))) {
	    if (iob->len != sizeof(iob->buf)) {
		if (sudo_ev_add(evbase, iob->revent, NULL, false) == -1)
		    sudo_fatal(U_("unable to add event to queue"));
	    }
	}
    }
}

static void
io_buf_new(int rfd, int wfd,
    bool (*action)(const char *, unsigned int, struct io_buffer *),
    struct exec_closure_pty *ec, struct io_buffer_list *head)
{
    int n;
    struct io_buffer *iob;
    debug_decl(io_buf_new, SUDO_DEBUG_EXEC);

    /* Set non-blocking mode. */
    n = fcntl(rfd, F_GETFL, 0);
    if (n != -1 && !ISSET(n, O_NONBLOCK))
	(void) fcntl(rfd, F_SETFL, n | O_NONBLOCK);
    n = fcntl(wfd, F_GETFL, 0);
    if (n != -1 && !ISSET(n, O_NONBLOCK))
	(void) fcntl(wfd, F_SETFL, n | O_NONBLOCK);

    /* Allocate and add to head of list. */
    if ((iob = malloc(sizeof(*iob))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    iob->ec = ec;
    iob->revent = sudo_ev_alloc(rfd, SUDO_EV_READ, read_callback, iob);
    iob->wevent = sudo_ev_alloc(wfd, SUDO_EV_WRITE, write_callback, iob);
    iob->len = 0;
    iob->off = 0;
    iob->action = action;
    iob->buf[0] = '\0';
    if (iob->revent == NULL || iob->wevent == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    SLIST_INSERT_HEAD(head, iob, entries);

    debug_return;
}

/*
 * We already closed the slave pty so reads from the master will not block.
 */
static void
pty_finish(struct command_status *cstat)
{
    struct io_buffer *iob;
    int n;
    debug_decl(pty_finish, SUDO_DEBUG_EXEC);

    /* Flush any remaining output (the plugin already got it). */
    if (io_fds[SFD_USERTTY] != -1) {
	n = fcntl(io_fds[SFD_USERTTY], F_GETFL, 0);
	if (n != -1 && ISSET(n, O_NONBLOCK)) {
	    CLR(n, O_NONBLOCK);
	    (void) fcntl(io_fds[SFD_USERTTY], F_SETFL, n);
	}
    }
    del_io_events(false);

    /* Free I/O buffers. */
    while ((iob = SLIST_FIRST(&iobufs)) != NULL) {
	SLIST_REMOVE_HEAD(&iobufs, entries);
	if (iob->revent != NULL)
	    sudo_ev_free(iob->revent);
	if (iob->wevent != NULL)
	    sudo_ev_free(iob->wevent);
	free(iob);
    }

    /* Restore terminal settings. */
    if (io_fds[SFD_USERTTY] != -1)
	sudo_term_restore(io_fds[SFD_USERTTY], false);

    /* Update utmp */
    if (utmp_user != NULL)
	utmp_logout(ptyname, cstat->type == CMD_WSTATUS ? cstat->val : 0);

    debug_return;
}

/*
 * Send command status to the monitor (signal or window size change).
 */
static void
send_command_status(struct exec_closure_pty *ec, int type, int val)
{
    struct monitor_message *msg;
    debug_decl(send_command, SUDO_DEBUG_EXEC)

    if ((msg = calloc(1, sizeof(*msg))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    msg->cstat.type = type;
    msg->cstat.val = val;
    TAILQ_INSERT_TAIL(&ec->monitor_messages, msg, entries);

    if (sudo_ev_add(ec->evbase, ec->fwdchannel_event, NULL, true) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    /* Restart event loop to send the command immediately. */
    sudo_ev_loopcontinue(ec->evbase);

    debug_return;
}

/*
 * Schedule a signal to be forwarded.
 */
static void
schedule_signal(struct exec_closure_pty *ec, int signo)
{
    char signame[SIG2STR_MAX];
    debug_decl(schedule_signal, SUDO_DEBUG_EXEC)

    if (signo == SIGCONT_FG)
	strlcpy(signame, "CONT_FG", sizeof(signame));
    else if (signo == SIGCONT_BG)
	strlcpy(signame, "CONT_BG", sizeof(signame));
    else if (sig2str(signo, signame) == -1)
	(void)snprintf(signame, sizeof(signame), "%d", signo);
    sudo_debug_printf(SUDO_DEBUG_DIAG, "scheduled SIG%s for command", signame);

    send_command_status(ec, CMD_SIGNO, signo);

    debug_return;
}

static void
backchannel_cb(int fd, int what, void *v)
{
    struct exec_closure_pty *ec = v;
    struct command_status cstat;
    ssize_t nread;
    debug_decl(backchannel_cb, SUDO_DEBUG_EXEC)

    /*
     * Read command status from the monitor.
     * Note that the backchannel is a *blocking* socket.
     */
    nread = recv(fd, &cstat, sizeof(cstat), MSG_WAITALL);
    switch (nread) {
    case -1:
	switch (errno) {
	case EINTR:
	case EAGAIN:
	    /* Nothing ready. */
	    break;
	default:
	    if (ec->cstat->val == CMD_INVALID) {
		ec->cstat->type = CMD_ERRNO;
		ec->cstat->val = errno;
		sudo_debug_printf(SUDO_DEBUG_ERROR,
		    "%s: failed to read command status: %s",
		    __func__, strerror(errno));
		sudo_ev_loopbreak(ec->evbase);
	    }
	    break;
	}
	break;
    case 0:
	/* EOF, monitor exited or was killed. */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "EOF on backchannel, monitor dead?");
	if (ec->cstat->type == CMD_INVALID) {
	    /* XXX - need new CMD_ type for monitor errors. */
	    ec->cstat->type = CMD_ERRNO;
	    ec->cstat->val = ECONNRESET;
	}
	sudo_ev_loopexit(ec->evbase);
	break;
    case sizeof(cstat):
	/* Check command status. */
	switch (cstat.type) {
	case CMD_PID:
	    ec->cmnd_pid = cstat.val;
	    sudo_debug_printf(SUDO_DEBUG_INFO, "executed %s, pid %d",
		ec->details->command, (int)ec->cmnd_pid);
	    break;
	case CMD_WSTATUS:
	    if (WIFSTOPPED(cstat.val)) {
		int signo;

		/* Suspend parent and tell monitor how to resume on return. */
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "command stopped, suspending parent");
		signo = suspend_sudo(ec, WSTOPSIG(cstat.val));
		schedule_signal(ec, signo);
		/* Re-enable I/O events */
		add_io_events(ec->evbase);
	    } else {
		/* Command exited or was killed, either way we are done. */
		sudo_debug_printf(SUDO_DEBUG_INFO, "command exited or was killed");
		sudo_ev_loopexit(ec->evbase);
	    }
	    *ec->cstat = cstat;
	    break;
	case CMD_ERRNO:
	    /* Monitor was unable to execute command or broken pipe. */
	    sudo_debug_printf(SUDO_DEBUG_INFO, "errno from monitor: %s",
		strerror(cstat.val));
	    sudo_ev_loopbreak(ec->evbase);
	    *ec->cstat = cstat;
	    break;
	}
	/* Keep reading command status messages until EAGAIN or EOF. */
	break;
    default:
	/* Short read, should not happen. */
	if (ec->cstat->val == CMD_INVALID) {
	    ec->cstat->type = CMD_ERRNO;
	    ec->cstat->val = EIO;
	    sudo_debug_printf(SUDO_DEBUG_ERROR,
		"%s: failed to read command status: short read", __func__);
	    sudo_ev_loopbreak(ec->evbase);
	}
	break;
    }
    debug_return;
}

/*
 * Handle changes to the monitors's status (SIGCHLD).
 */
static void
handle_sigchld_pty(struct exec_closure_pty *ec)
{
    int n, status;
    pid_t pid;
    debug_decl(handle_sigchld_pty, SUDO_DEBUG_EXEC)

    /*
     * Monitor process was signaled; wait for it as needed.
     */
    do {
	pid = waitpid(ec->monitor_pid, &status, WUNTRACED|WNOHANG);
    } while (pid == -1 && errno == EINTR);
    switch (pid) {
    case 0:
	errno = ECHILD;
	/* FALLTHROUGH */
    case -1:
	sudo_warn(U_("%s: %s"), __func__, "waitpid");
	debug_return;
    }

    /*
     * If the monitor dies we get notified via backchannel_cb().
     * If it was stopped, we should stop too (the command keeps
     * running in its pty) and continue it when we come back.
     */
    if (WIFSTOPPED(status)) {
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "monitor stopped, suspending sudo");
	n = suspend_sudo(ec, WSTOPSIG(status));
	kill(pid, SIGCONT);
	schedule_signal(ec, n);
	/* Re-enable I/O events */
	add_io_events(ec->evbase);
    } else if (WIFSIGNALED(status)) {
	char signame[SIG2STR_MAX];
	if (sig2str(WTERMSIG(status), signame) == -1)
	    (void)snprintf(signame, sizeof(signame), "%d", WTERMSIG(status));
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: monitor (%d) killed, SIG%s",
	    __func__, (int)ec->monitor_pid, signame);
	ec->monitor_pid = -1;
    } else {
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: monitor exited, status %d", __func__, WEXITSTATUS(status));
	ec->monitor_pid = -1;
    }
    debug_return;
}

/* Signal callback */
static void
signal_cb_pty(int signo, int what, void *v)
{
    struct sudo_ev_siginfo_container *sc = v;
    struct exec_closure_pty *ec = sc->closure;
    char signame[SIG2STR_MAX];
    debug_decl(signal_cb_pty, SUDO_DEBUG_EXEC)

    if (ec->monitor_pid == -1)
	debug_return;

    if (sig2str(signo, signame) == -1)
	(void)snprintf(signame, sizeof(signame), "%d", signo);
    sudo_debug_printf(SUDO_DEBUG_DIAG,
	"%s: evbase %p, monitor: %d, signo %s(%d), cstat %p", __func__,
	ec->evbase, (int)ec->monitor_pid, signame, signo, ec->cstat);

    switch (signo) {
    case SIGCHLD:
	handle_sigchld_pty(ec);
	break;
    case SIGWINCH:
	sync_ttysize(ec);
	break;
    default:
	/*
	 * Do not forward signals sent by a process in the command's process
	 * group, as we don't want the command to indirectly kill itself.
	 * For example, this can happen with some versions of reboot that
	 * call kill(-1, SIGTERM) to kill all other processes.
	 */
	if (USER_SIGNALED(sc->siginfo) && sc->siginfo->si_pid != 0) {
	    pid_t si_pgrp = getpgid(sc->siginfo->si_pid);
	    if (si_pgrp != -1) {
		if (si_pgrp == ec->ppgrp || si_pgrp == ec->cmnd_pid)
		    debug_return;
	    } else if (sc->siginfo->si_pid == ec->cmnd_pid) {
		debug_return;
	    }
	}
	/* Schedule signal to be forwared to the command. */
	schedule_signal(ec, signo);
	break;
    }

    debug_return;
}

/*
 * Forward signals in monitor_messages to the monitor so it can
 * deliver them to the command.
 */
static void
fwdchannel_cb(int sock, int what, void *v)
{
    struct exec_closure_pty *ec = v;
    char signame[SIG2STR_MAX];
    struct monitor_message *msg;
    ssize_t nsent;
    debug_decl(fwdchannel_cb, SUDO_DEBUG_EXEC)

    while ((msg = TAILQ_FIRST(&ec->monitor_messages)) != NULL) {
	switch (msg->cstat.type) {
	case CMD_SIGNO:
	    if (msg->cstat.val == SIGCONT_FG)
		strlcpy(signame, "CONT_FG", sizeof(signame));
	    else if (msg->cstat.val == SIGCONT_BG)
		strlcpy(signame, "CONT_BG", sizeof(signame));
	    else if (sig2str(msg->cstat.val, signame) == -1)
		(void)snprintf(signame, sizeof(signame), "%d", msg->cstat.val);
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"sending SIG%s to monitor over backchannel", signame);
	    break;
	case CMD_TTYWINCH:
	    sudo_debug_printf(SUDO_DEBUG_INFO, "sending window size change "
		"to monitor over backchannelL %d x %d",
		msg->cstat.val & 0xffff, (msg->cstat.val >> 16) & 0xffff);
	    break;
	default:
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"sending cstat type %d, value %d to monitor over backchannel",
		msg->cstat.type, msg->cstat.val);
	    break;
	}
	TAILQ_REMOVE(&ec->monitor_messages, msg, entries);
	nsent = send(sock, &msg->cstat, sizeof(msg->cstat), 0);
	if (nsent != sizeof(msg->cstat)) {
	    if (errno == EPIPE) {
		sudo_debug_printf(SUDO_DEBUG_ERROR,
		    "broken pipe writing to monitor over backchannel");
		/* Other end of socket gone, empty out monitor_messages. */
		free(msg);
		while ((msg = TAILQ_FIRST(&ec->monitor_messages)) != NULL) {
		    TAILQ_REMOVE(&ec->monitor_messages, msg, entries);
		    free(msg);
		}
		/* XXX - need new CMD_ type for monitor errors. */
		ec->cstat->type = CMD_ERRNO;
		ec->cstat->val = errno;
		sudo_ev_loopbreak(ec->evbase);
	    }
	    break;
	}
	free(msg);
    }
}

/*
 * Fill in the exec closure and setup initial exec events.
 * Allocates events for the signal pipe and backchannel.
 * Forwarded signals on the backchannel are enabled on demand.
 */
static void
fill_exec_closure_pty(struct exec_closure_pty *ec, struct command_status *cstat,
    struct command_details *details, pid_t ppgrp, int backchannel)
{
    debug_decl(fill_exec_closure_pty, SUDO_DEBUG_EXEC)

    /* Fill in the non-event part of the closure. */
    ec->cmnd_pid = -1;
    ec->ppgrp = ppgrp;
    ec->cstat = cstat;
    ec->details = details;
    ec->rows = user_details.ts_rows;
    ec->cols = user_details.ts_cols;
    TAILQ_INIT(&ec->monitor_messages);

    /* Setup event base and events. */
    ec->evbase = sudo_ev_base_alloc();
    if (ec->evbase == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* Event for command status via backchannel. */
    ec->backchannel_event = sudo_ev_alloc(backchannel,
	SUDO_EV_READ|SUDO_EV_PERSIST, backchannel_cb, ec);
    if (ec->backchannel_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->backchannel_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));
    sudo_debug_printf(SUDO_DEBUG_INFO, "backchannel fd %d\n", backchannel);

    /* Events for local signals. */
    ec->sigint_event = sudo_ev_alloc(SIGINT,
	SUDO_EV_SIGINFO, signal_cb_pty, ec);
    if (ec->sigint_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigint_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigquit_event = sudo_ev_alloc(SIGQUIT,
	SUDO_EV_SIGINFO, signal_cb_pty, ec);
    if (ec->sigquit_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigquit_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigtstp_event = sudo_ev_alloc(SIGTSTP,
	SUDO_EV_SIGINFO, signal_cb_pty, ec);
    if (ec->sigtstp_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigtstp_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigterm_event = sudo_ev_alloc(SIGTERM,
	SUDO_EV_SIGINFO, signal_cb_pty, ec);
    if (ec->sigterm_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigterm_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sighup_event = sudo_ev_alloc(SIGHUP,
	SUDO_EV_SIGINFO, signal_cb_pty, ec);
    if (ec->sighup_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sighup_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigalrm_event = sudo_ev_alloc(SIGALRM,
	SUDO_EV_SIGINFO, signal_cb_pty, ec);
    if (ec->sigalrm_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigalrm_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigusr1_event = sudo_ev_alloc(SIGUSR1,
	SUDO_EV_SIGINFO, signal_cb_pty, ec);
    if (ec->sigusr1_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigusr1_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigusr2_event = sudo_ev_alloc(SIGUSR2,
	SUDO_EV_SIGINFO, signal_cb_pty, ec);
    if (ec->sigusr2_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigusr2_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigchld_event = sudo_ev_alloc(SIGCHLD,
	SUDO_EV_SIGINFO, signal_cb_pty, ec);
    if (ec->sigchld_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigchld_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigwinch_event = sudo_ev_alloc(SIGWINCH,
	SUDO_EV_SIGINFO, signal_cb_pty, ec);
    if (ec->sigwinch_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigwinch_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    /* The signal forwarding event gets added on demand. */
    ec->fwdchannel_event = sudo_ev_alloc(backchannel,
	SUDO_EV_WRITE, fwdchannel_cb, ec);
    if (ec->fwdchannel_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* Set the default event base. */
    sudo_ev_base_setdef(ec->evbase);

    debug_return;
}

/*
 * Free the dynamically-allocated contents of the exec closure.
 */
static void
free_exec_closure_pty(struct exec_closure_pty *ec)
{
    struct monitor_message *msg;
    debug_decl(free_exec_closure_pty, SUDO_DEBUG_EXEC)

    sudo_ev_base_free(ec->evbase);
    sudo_ev_free(ec->backchannel_event);
    sudo_ev_free(ec->fwdchannel_event);
    sudo_ev_free(ec->sigint_event);
    sudo_ev_free(ec->sigquit_event);
    sudo_ev_free(ec->sigtstp_event);
    sudo_ev_free(ec->sigterm_event);
    sudo_ev_free(ec->sighup_event);
    sudo_ev_free(ec->sigalrm_event);
    sudo_ev_free(ec->sigusr1_event);
    sudo_ev_free(ec->sigusr2_event);
    sudo_ev_free(ec->sigchld_event);
    sudo_ev_free(ec->sigwinch_event);

    while ((msg = TAILQ_FIRST(&ec->monitor_messages)) != NULL) {
	TAILQ_REMOVE(&ec->monitor_messages, msg, entries);
	free(msg);
    }

    debug_return;
}

/*
 * Execute a command in a pty, potentially with I/O loggging, and
 * wait for it to finish.
 * This is a little bit tricky due to how POSIX job control works and
 * we fact that we have two different controlling terminals to deal with.
 */
bool
exec_pty(struct command_details *details, struct command_status *cstat)
{
    int io_pipe[3][2] = { { -1, -1 }, { -1, -1 }, { -1, -1 } };
    bool interpose[3] = { false, false, false };
    struct exec_closure_pty ec = { 0 };
    struct plugin_container *plugin;
    sigset_t set, oset;
    struct sigaction sa;
    struct stat sb;
    pid_t ppgrp;
    int sv[2];
    debug_decl(exec_pty, SUDO_DEBUG_EXEC)

    /*
     * Allocate a pty.
     */
    if (!pty_setup(details, user_details.tty)) {
	if (TAILQ_EMPTY(&io_plugins)) {
	    /* Not logging I/O and didn't allocate a pty. */
	    debug_return_bool(false);
	}
    }

    /*
     * We communicate with the monitor over a bi-directional pair of sockets.
     * Parent sends signal info to monitor and monitor sends back wait status.
     */
    if (socketpair(PF_UNIX, SOCK_STREAM, 0, sv) == -1 ||
	    fcntl(sv[0], F_SETFD, FD_CLOEXEC) == -1 ||
	    fcntl(sv[1], F_SETFD, FD_CLOEXEC) == -1)
	sudo_fatal(U_("unable to create sockets"));

    /*
     * We don't want to receive SIGTTIN/SIGTTOU.
     * XXX - this affects tcsetattr() and tcsetpgrp() too.
     */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_IGN;
    if (sudo_sigaction(SIGTTIN, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTTIN);
    if (sudo_sigaction(SIGTTOU, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTTOU);

    /*
     * The policy plugin's session init must be run before we fork
     * or certain pam modules won't be able to track their state.
     */
    if (policy_init_session(details) != true)
	sudo_fatalx(U_("policy plugin failed session initialization"));

    /*
     * Child will run the command in the pty, parent will pass data
     * to and from pty.
     */

    /* So we can block tty-generated signals */
    sigemptyset(&ttyblock);
    sigaddset(&ttyblock, SIGINT);
    sigaddset(&ttyblock, SIGQUIT);
    sigaddset(&ttyblock, SIGTSTP);
    sigaddset(&ttyblock, SIGTTIN);
    sigaddset(&ttyblock, SIGTTOU);

    ppgrp = getpgrp();	/* parent's pgrp, so child can signal us */

    /* Determine whether any of std{in,out,err} should be logged. */
    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->log_stdin)
	    interpose[STDIN_FILENO] = true;
	if (plugin->u.io->log_stdout)
	    interpose[STDOUT_FILENO] = true;
	if (plugin->u.io->log_stderr)
	    interpose[STDERR_FILENO] = true;
    }

    /*
     * Setup stdin/stdout/stderr for command, to be duped after forking.
     * In background mode there is no stdin.
     */
    if (!ISSET(details->flags, CD_BACKGROUND))
	io_fds[SFD_STDIN] = io_fds[SFD_SLAVE];
    io_fds[SFD_STDOUT] = io_fds[SFD_SLAVE];
    io_fds[SFD_STDERR] = io_fds[SFD_SLAVE];

    if (io_fds[SFD_USERTTY] != -1) {
	/* Read from /dev/tty, write to pty master */
	if (!ISSET(details->flags, CD_BACKGROUND)) {
	    io_buf_new(io_fds[SFD_USERTTY], io_fds[SFD_MASTER],
		log_ttyin, &ec, &iobufs);
	}

	/* Read from pty master, write to /dev/tty */
	io_buf_new(io_fds[SFD_MASTER], io_fds[SFD_USERTTY],
	    log_ttyout, &ec, &iobufs);

	/* Are we the foreground process? */
	foreground = tcgetpgrp(io_fds[SFD_USERTTY]) == ppgrp;
    }

    /*
     * If stdin, stdout or stderr is not a tty and logging is enabled,
     * use a pipe to interpose ourselves instead of using the pty fd.
     */
    if (io_fds[SFD_STDIN] == -1 || !isatty(STDIN_FILENO)) {
	if (!interpose[STDIN_FILENO]) {
	    /* Not logging stdin, do not interpose. */
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"stdin not a tty, not logging");
	    if (fstat(STDIN_FILENO, &sb) == 0 && S_ISFIFO(sb.st_mode))
		pipeline = true;
	    io_fds[SFD_STDIN] = dup(STDIN_FILENO);
	    if (io_fds[SFD_STDIN] == -1)
		sudo_fatal("dup");
	} else {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"stdin not a tty, creating a pipe");
	    pipeline = true;
	    if (pipe2(io_pipe[STDIN_FILENO], O_CLOEXEC) != 0)
		sudo_fatal(U_("unable to create pipe"));
	    io_buf_new(STDIN_FILENO, io_pipe[STDIN_FILENO][1],
		log_stdin, &ec, &iobufs);
	    io_fds[SFD_STDIN] = io_pipe[STDIN_FILENO][0];
	}
    }
    if (io_fds[SFD_STDOUT] == -1 || !isatty(STDOUT_FILENO)) {
	if (!interpose[STDOUT_FILENO]) {
	    /* Not logging stdout, do not interpose. */
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"stdout not a tty, not logging");
	    if (fstat(STDOUT_FILENO, &sb) == 0 && S_ISFIFO(sb.st_mode))
		pipeline = true;
	    io_fds[SFD_STDOUT] = dup(STDOUT_FILENO);
	    if (io_fds[SFD_STDOUT] == -1)
		sudo_fatal("dup");
	} else {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"stdout not a tty, creating a pipe");
	    pipeline = true;
	    if (pipe2(io_pipe[STDOUT_FILENO], O_CLOEXEC) != 0)
		sudo_fatal(U_("unable to create pipe"));
	    io_buf_new(io_pipe[STDOUT_FILENO][0], STDOUT_FILENO,
		log_stdout, &ec, &iobufs);
	    io_fds[SFD_STDOUT] = io_pipe[STDOUT_FILENO][1];
	}
    }
    if (io_fds[SFD_STDERR] == -1 || !isatty(STDERR_FILENO)) {
	if (!interpose[STDERR_FILENO]) {
	    /* Not logging stderr, do not interpose. */
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"stderr not a tty, not logging");
	    if (fstat(STDERR_FILENO, &sb) == 0 && S_ISFIFO(sb.st_mode))
		pipeline = true;
	    io_fds[SFD_STDERR] = dup(STDERR_FILENO);
	    if (io_fds[SFD_STDERR] == -1)
		sudo_fatal("dup");
	} else {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"stderr not a tty, creating a pipe");
	    if (pipe2(io_pipe[STDERR_FILENO], O_CLOEXEC) != 0)
		sudo_fatal(U_("unable to create pipe"));
	    io_buf_new(io_pipe[STDERR_FILENO][0], STDERR_FILENO,
		log_stderr, &ec, &iobufs);
	    io_fds[SFD_STDERR] = io_pipe[STDERR_FILENO][1];
	}
    }

    if (foreground) {
	/* Copy terminal attrs from user tty -> pty slave. */
	if (!sudo_term_copy(io_fds[SFD_USERTTY], io_fds[SFD_SLAVE])) {
            sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
                "%s: unable to copy terminal settings to pty", __func__);
	    foreground = false;
	} else {
	    /* Start in raw mode unless part of a pipeline or backgrounded. */
	    if (!pipeline && !ISSET(details->flags, CD_EXEC_BG)) {
		if (sudo_term_raw(io_fds[SFD_USERTTY], 0))
		    ttymode = TERM_RAW;
	    }
	}
    }

    /*
     * Block signals until we have our handlers setup in the parent so
     * we don't miss SIGCHLD if the command exits immediately.
     */
    sigfillset(&set);
    sigprocmask(SIG_BLOCK, &set, &oset);

    /* Check for early termination or suspend signals before we fork. */
    if (sudo_terminated(cstat)) {
	sigprocmask(SIG_SETMASK, &oset, NULL);
	debug_return_int(true);
    }

    ec.monitor_pid = sudo_debug_fork();
    switch (ec.monitor_pid) {
    case -1:
	sudo_fatal(U_("unable to fork"));
	break;
    case 0:
	/* child */
	close(sv[0]);
	/* Close the other end of the stdin/stdout/stderr pipes and exec. */
	if (io_pipe[STDIN_FILENO][1] != -1)
	    close(io_pipe[STDIN_FILENO][1]);
	if (io_pipe[STDOUT_FILENO][0] != -1)
	    close(io_pipe[STDOUT_FILENO][0]);
	if (io_pipe[STDERR_FILENO][0] != -1)
	    close(io_pipe[STDERR_FILENO][0]);
	/*                      
	 * If stdin/stdout is not a tty, start command in the background
	 * since it might be part of a pipeline that reads from /dev/tty.
	 * In this case, we rely on the command receiving SIGTTOU or SIGTTIN
	 * when it needs access to the controlling tty.
	 */                                                              
	exec_monitor(details, &oset, foreground && !pipeline, sv[1]);
	cstat->type = CMD_ERRNO;
	cstat->val = errno;
	if (send(sv[1], cstat, sizeof(*cstat), 0) == -1) {
            sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
                "%s: unable to send status to parent", __func__);
	}
	_exit(1);
    }

    /*
     * We close the pty slave so only the monitor and command have a
     * reference to it.  This ensures that we can don't block reading
     * from the master when the command and monitor have exited.
     */
    if (io_fds[SFD_SLAVE] != -1) {
	close(io_fds[SFD_SLAVE]);
	io_fds[SFD_SLAVE] = -1;
    }

    /* Tell the monitor to continue now that the slave is closed. */
    cstat->type = CMD_SIGNO;
    cstat->val = 0;
    while (send(sv[0], cstat, sizeof(*cstat), 0) == -1) {
	if (errno != EINTR && errno != EAGAIN)
	    sudo_fatal(U_("unable to send message to monitor process"));
    }

    /* Close the other end of the stdin/stdout/stderr pipes and socketpair. */
    if (io_pipe[STDIN_FILENO][0] != -1)
	close(io_pipe[STDIN_FILENO][0]);
    if (io_pipe[STDOUT_FILENO][1] != -1)
	close(io_pipe[STDOUT_FILENO][1]);
    if (io_pipe[STDERR_FILENO][1] != -1)
	close(io_pipe[STDERR_FILENO][1]);
    close(sv[1]);

    /* No longer need execfd. */
    if (details->execfd != -1) {
	close(details->execfd);
	details->execfd = -1;
    }

    /* Set command timeout if specified. */
    if (ISSET(details->flags, CD_SET_TIMEOUT))
	alarm(details->timeout);

    /*
     * Fill in exec closure, allocate event base, signal events and
     * the backchannel event.
     */
    fill_exec_closure_pty(&ec, cstat, details, ppgrp, sv[0]);

    /* Restore signal mask now that signal handlers are setup. */
    sigprocmask(SIG_SETMASK, &oset, NULL);

    /*
     * I/O logging must be in the C locale for floating point numbers
     * to be logged consistently.
     */
    setlocale(LC_ALL, "C");

    /*
     * In the event loop we pass input from user tty to master
     * and pass output from master to stdout and IO plugin.
     */
    add_io_events(ec.evbase);
    if (sudo_ev_dispatch(ec.evbase) == -1)
	sudo_warn(U_("error in event loop"));
    if (sudo_ev_got_break(ec.evbase)) {
	/* error from callback or monitor died */
	sudo_debug_printf(SUDO_DEBUG_ERROR, "event loop exited prematurely");
	/* XXX - may need to terminate command if cmnd_pid != -1 */
    }

    /* Flush any remaining output, free I/O bufs and events, do logout. */
    pty_finish(cstat);

    /* Free things up. */
    free_exec_closure_pty(&ec);

    debug_return_bool(true);
}

/*
 * Schedule I/O events before starting the main event loop or
 * resuming from suspend.
 */
static void
add_io_events(struct sudo_event_base *evbase)
{
    struct io_buffer *iob;
    debug_decl(add_io_events, SUDO_DEBUG_EXEC);

    /*
     * Schedule all readers as long as the buffer is not full.
     * Schedule writers that contain buffered data.
     * Normally, write buffers are added on demand when data is read.
     */
    SLIST_FOREACH(iob, &iobufs, entries) {
	/* Don't read from /dev/tty if we are not in the foreground. */
	if (iob->revent != NULL &&
	    (ttymode == TERM_RAW || !USERTTY_EVENT(iob->revent))) {
	    if (iob->len != sizeof(iob->buf)) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "added I/O revent %p, fd %d, events %d",
		    iob->revent, iob->revent->fd, iob->revent->events);
		if (sudo_ev_add(evbase, iob->revent, NULL, false) == -1)
		    sudo_fatal(U_("unable to add event to queue"));
	    }
	}
	if (iob->wevent != NULL) {
	    /* Enable writer if buffer is not empty. */
	    if (iob->len > iob->off) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "added I/O wevent %p, fd %d, events %d",
		    iob->wevent, iob->wevent->fd, iob->wevent->events);
		if (sudo_ev_add(evbase, iob->wevent, NULL, false) == -1)
		    sudo_fatal(U_("unable to add event to queue"));
	    }
	}
    }
    debug_return;
}

/*
 * Flush any output buffered in iobufs or readable from fds other
 * than /dev/tty.  Removes I/O events from the event base when done.
 */
static void
del_io_events(bool nonblocking)
{
    struct io_buffer *iob;
    struct sudo_event_base *evbase;
    debug_decl(del_io_events, SUDO_DEBUG_EXEC);

    /* Remove iobufs from existing event base. */
    SLIST_FOREACH(iob, &iobufs, entries) {
	if (iob->revent != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"deleted I/O revent %p, fd %d, events %d",
		iob->revent, iob->revent->fd, iob->revent->events);
	    sudo_ev_del(NULL, iob->revent);
	}
	if (iob->wevent != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"deleted I/O wevent %p, fd %d, events %d",
		iob->wevent, iob->wevent->fd, iob->wevent->events);
	    sudo_ev_del(NULL, iob->wevent);
	}
    }

    /* Create temporary event base for flushing. */
    evbase = sudo_ev_base_alloc();
    if (evbase == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* Avoid reading from /dev/tty, just flush existing data. */
    SLIST_FOREACH(iob, &iobufs, entries) {
	/* Don't read from /dev/tty while flushing. */
	if (iob->revent != NULL && !USERTTY_EVENT(iob->revent)) {
	    if (iob->len != sizeof(iob->buf)) {
		if (sudo_ev_add(evbase, iob->revent, NULL, false) == -1)
		    sudo_fatal(U_("unable to add event to queue"));
	    }
	}
	/* Flush any write buffers with data in them. */
	if (iob->wevent != NULL) {
	    if (iob->len > iob->off) {
		if (sudo_ev_add(evbase, iob->wevent, NULL, false) == -1)
		    sudo_fatal(U_("unable to add event to queue"));
	    }
	}
    }
    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: flushing remaining I/O buffers (nonblocking)", __func__);
    (void) sudo_ev_loop(evbase, SUDO_EVLOOP_NONBLOCK);

    /*
     * If not in non-blocking mode, make sure we flush write buffers.
     * We don't want to read from the pty or stdin since that might block
     * and the command is no longer running anyway.
     */
    if (!nonblocking) {
	/* Clear out iobufs from event base. */
	SLIST_FOREACH(iob, &iobufs, entries) {
	    if (iob->revent != NULL && !USERTTY_EVENT(iob->revent))
		sudo_ev_del(evbase, iob->revent);
	    if (iob->wevent != NULL)
		sudo_ev_del(evbase, iob->wevent);
	}

	SLIST_FOREACH(iob, &iobufs, entries) {
	    /* Flush any write buffers with data in them. */
	    if (iob->wevent != NULL) {
		if (iob->len > iob->off) {
		    if (sudo_ev_add(evbase, iob->wevent, NULL, false) == -1)
			sudo_fatal(U_("unable to add event to queue"));
		}
	    }
	}
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: flushing remaining write buffers (blocking)", __func__);
	(void) sudo_ev_dispatch(evbase);
     
	/* We should now have flushed all write buffers. */
	SLIST_FOREACH(iob, &iobufs, entries) {
	    if (iob->wevent != NULL) {
		if (iob->len > iob->off) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR,
			"unflushed data: wevent %p, fd %d, events %d",
			iob->wevent, iob->wevent->fd, iob->wevent->events);
		}
	    }
	}
    }

    /* Free temporary event base, removing its events. */
    sudo_ev_base_free(evbase);

    debug_return;
}

/*
 * Check for tty size changes.
 * Passes the new window size to the I/O plugin and to the monitor.
 */
static void
sync_ttysize(struct exec_closure_pty *ec)
{
    struct winsize wsize;
    debug_decl(sync_ttysize, SUDO_DEBUG_EXEC);

    if (ioctl(io_fds[SFD_USERTTY], TIOCGWINSZ, &wsize) == 0) {
	if (wsize.ws_row != ec->rows || wsize.ws_col != ec->cols) {
	    const unsigned int wsize_packed = (wsize.ws_row & 0xffff) |
		((wsize.ws_col & 0xffff) << 16);

	    /* Log window change event. */
	    log_winchange(wsize.ws_row, wsize.ws_col);

	    /* Send window change event to monitor process. */
	    send_command_status(ec, CMD_TTYWINCH, wsize_packed);

	    /* Update rows/cols. */
	    ec->rows = wsize.ws_row;
	    ec->cols = wsize.ws_col;
	}
    }

    debug_return;
}

/*
 * Remove and free any events associated with the specified
 * file descriptor present in the I/O buffers list.
 */
static void
ev_free_by_fd(struct sudo_event_base *evbase, int fd)
{
    struct io_buffer *iob;
    debug_decl(ev_free_by_fd, SUDO_DEBUG_EXEC);

    /* Deschedule any users of the fd and free up the events. */
    SLIST_FOREACH(iob, &iobufs, entries) {
	if (iob->revent != NULL) {
	    if (sudo_ev_get_fd(iob->revent) == fd) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "%s: deleting and freeing revent %p with fd %d",
		    __func__, iob->revent, fd);
		sudo_ev_free(iob->revent);
		iob->revent = NULL;
	    }
	}
	if (iob->wevent != NULL) {
	    if (sudo_ev_get_fd(iob->wevent) == fd) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "%s: deleting and freeing wevent %p with fd %d",
		    __func__, iob->wevent, fd);
		sudo_ev_free(iob->wevent);
		iob->wevent = NULL;
	    }
	}
    }
    debug_return;
}

/*
 * Only close the fd if it is not /dev/tty or std{in,out,err}.
 * Return value is the same as close(2).
 */
static int
safe_close(int fd)
{
    debug_decl(safe_close, SUDO_DEBUG_EXEC);

    /* Avoid closing /dev/tty or std{in,out,err}. */
    if (fd < 3 || fd == io_fds[SFD_USERTTY]) {
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: not closing fd %d (%s)", __func__, fd, _PATH_TTY);
	errno = EINVAL;
	debug_return_int(-1);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: closing fd %d", __func__, fd);
    debug_return_int(close(fd));
}
