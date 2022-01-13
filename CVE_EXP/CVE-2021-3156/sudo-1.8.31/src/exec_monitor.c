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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>

#include "sudo.h"
#include "sudo_event.h"
#include "sudo_exec.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

struct monitor_closure {
    pid_t cmnd_pid;
    pid_t cmnd_pgrp;
    pid_t mon_pgrp;
    int backchannel;
    struct command_status *cstat;
    struct sudo_event_base *evbase;
    struct sudo_event *errpipe_event;
    struct sudo_event *backchannel_event;
    struct sudo_event *sigint_event;
    struct sudo_event *sigquit_event;
    struct sudo_event *sigtstp_event;
    struct sudo_event *sigterm_event;
    struct sudo_event *sighup_event;
    struct sudo_event *sigusr1_event;
    struct sudo_event *sigusr2_event;
    struct sudo_event *sigchld_event;
};

static bool tty_initialized;

/*
 * Deliver a signal to the running command.
 * The signal was either forwarded to us by the parent sudo process
 * or was received by the monitor itself.
 *
 * There are two "special" signals, SIGCONT_FG and SIGCONT_BG that
 * also specify whether the command should have the controlling tty.
 */
static void
deliver_signal(struct monitor_closure *mc, int signo, bool from_parent)
{
    char signame[SIG2STR_MAX];
    debug_decl(deliver_signal, SUDO_DEBUG_EXEC);

    /* Avoid killing more than a single process or process group. */
    if (mc->cmnd_pid <= 0)
	debug_return;

    if (signo == SIGCONT_FG)
	(void)strlcpy(signame, "CONT_FG", sizeof(signame));
    else if (signo == SIGCONT_BG)
	(void)strlcpy(signame, "CONT_BG", sizeof(signame));
    else if (sig2str(signo, signame) == -1)
	(void)snprintf(signame, sizeof(signame), "%d", signo);

    /* Handle signal from parent or monitor. */
    sudo_debug_printf(SUDO_DEBUG_INFO, "received SIG%s%s",
	signame, from_parent ? " from parent" : "");
    switch (signo) {
    case SIGALRM:
	terminate_command(mc->cmnd_pid, true);
	break;
    case SIGCONT_FG:
	/* Continue in foreground, grant it controlling tty. */
	if (tcsetpgrp(io_fds[SFD_SLAVE], mc->cmnd_pgrp) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: unable to set foreground pgrp to %d (command)",
		__func__, (int)mc->cmnd_pgrp);
	}
	/* Lazily initialize the pty if needed. */
	if (!tty_initialized) {
	    if (sudo_term_copy(io_fds[SFD_USERTTY], io_fds[SFD_SLAVE]))
		    tty_initialized = true;
	}
	killpg(mc->cmnd_pid, SIGCONT);
	break;
    case SIGCONT_BG:
	/* Continue in background, I take controlling tty. */
	if (tcsetpgrp(io_fds[SFD_SLAVE], mc->mon_pgrp) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: unable to set foreground pgrp to %d (monitor)",
		__func__, (int)mc->mon_pgrp);
	}
	killpg(mc->cmnd_pid, SIGCONT);
	break;
    case SIGKILL:
	_exit(1); /* XXX */
	/* NOTREACHED */
    default:
	/* Relay signal to command. */
	killpg(mc->cmnd_pid, signo);
	break;
    }
    debug_return;
}

/*
 * Unpack rows and cols from a CMD_TTYWINCH value, set the new window
 * size on the pty slave and inform the command of the change.
 */
static void
handle_winch(struct monitor_closure *mc, unsigned int wsize_packed)
{
    struct winsize wsize, owsize;
    debug_decl(handle_winch, SUDO_DEBUG_EXEC);

    /* Rows and colums are stored as two shorts packed into a single int. */
    wsize.ws_row = wsize_packed & 0xffff;
    wsize.ws_col = (wsize_packed >> 16) & 0xffff;

    if (ioctl(io_fds[SFD_SLAVE], TIOCGWINSZ, &owsize) == 0 &&
	(wsize.ws_row != owsize.ws_row || wsize.ws_col != owsize.ws_col)) {

	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "window size change %dx%d -> %dx%d",
	    owsize.ws_col, owsize.ws_row, wsize.ws_col, wsize.ws_row);

	(void)ioctl(io_fds[SFD_SLAVE], TIOCSWINSZ, &wsize);
	deliver_signal(mc, SIGWINCH, true);
    }

    debug_return;
}

/*
 * Send status to parent over socketpair.
 * Return value is the same as send(2).
 */
static int
send_status(int fd, struct command_status *cstat)
{
    int n = -1;
    debug_decl(send_status, SUDO_DEBUG_EXEC);

    if (cstat->type != CMD_INVALID) {
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "sending status message to parent: [%d, %d]",
	    cstat->type, cstat->val);
	n = send(fd, cstat, sizeof(*cstat), 0);
	if (n != sizeof(*cstat)) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: unable to send status to parent", __func__);
	}
	cstat->type = CMD_INVALID; /* prevent re-sending */
    }
    debug_return_int(n);
}

/*
 * Wait for command status after receiving SIGCHLD.
 * If the command was stopped, the status is send back to the parent.
 * Otherwise, cstat is filled in but not sent.
 */
static void
mon_handle_sigchld(struct monitor_closure *mc)
{
    char signame[SIG2STR_MAX];
    int status;
    pid_t pid;
    debug_decl(mon_handle_sigchld, SUDO_DEBUG_EXEC);

    /* Read command status. */
    do {
	pid = waitpid(mc->cmnd_pid, &status, WUNTRACED|WCONTINUED|WNOHANG);
    } while (pid == -1 && errno == EINTR);
    switch (pid) {
    case 0:
	errno = ECHILD;
	/* FALLTHROUGH */
    case -1:
	sudo_warn(U_("%s: %s"), __func__, "waitpid");
	debug_return;
    }

    if (WIFCONTINUED(status)) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: command (%d) resumed",
	    __func__, (int)mc->cmnd_pid);
    } else if (WIFSTOPPED(status)) {
	if (sig2str(WSTOPSIG(status), signame) == -1)
	    (void)snprintf(signame, sizeof(signame), "%d", WSTOPSIG(status));
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: command (%d) stopped, SIG%s",
	    __func__, (int)mc->cmnd_pid, signame);
    } else if (WIFSIGNALED(status)) {
	if (sig2str(WTERMSIG(status), signame) == -1)
	    (void)snprintf(signame, sizeof(signame), "%d", WTERMSIG(status));
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: command (%d) killed, SIG%s",
	    __func__, (int)mc->cmnd_pid, signame);
	mc->cmnd_pid = -1;
    } else if (WIFEXITED(status)) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: command (%d) exited: %d",
	    __func__, (int)mc->cmnd_pid, WEXITSTATUS(status));
	mc->cmnd_pid = -1;
    } else {
	sudo_debug_printf(SUDO_DEBUG_WARN,
	    "%s: unexpected wait status %d for command (%d)",
	    __func__, status, (int)mc->cmnd_pid);
    }

    /* Don't overwrite execve() failure with child exit status. */
    if (mc->cstat->type == CMD_INVALID) {
	/*
	 * Store wait status in cstat and forward to parent if stopped.
	 * Parent does not expect SIGCONT so don't bother sending it.
	 */
	if (!WIFCONTINUED(status)) {
	    mc->cstat->type = CMD_WSTATUS;
	    mc->cstat->val = status;
	    if (WIFSTOPPED(status)) {
		/* Save the foreground pgid so we can restore it later. */
		pid = tcgetpgrp(io_fds[SFD_SLAVE]);
		if (pid != mc->mon_pgrp)
		    mc->cmnd_pgrp = pid;
		send_status(mc->backchannel, mc->cstat);
	    }
	}
    } else {
	sudo_debug_printf(SUDO_DEBUG_WARN,
	    "%s: not overwriting command status %d,%d with %d,%d",
	    __func__, mc->cstat->type, mc->cstat->val, CMD_WSTATUS, status);
    }

    debug_return;
}

static void
mon_signal_cb(int signo, int what, void *v)
{
    struct sudo_ev_siginfo_container *sc = v;
    struct monitor_closure *mc = sc->closure;
    debug_decl(mon_signal_cb, SUDO_DEBUG_EXEC);

    /*
     * Handle SIGCHLD specially and deliver other signals
     * directly to the command.
     */
    if (signo == SIGCHLD) {
	mon_handle_sigchld(mc);
	if (mc->cmnd_pid == -1) {
	    /* Command exited or was killed, exit event loop. */
	    sudo_ev_loopexit(mc->evbase);
	}
    } else {
	/*
	 * If the signal came from the process group of the command we ran,
	 * do not forward it as we don't want the child to indirectly kill
	 * itself.  This can happen with, e.g., BSD-derived versions of
	 * reboot that call kill(-1, SIGTERM) to kill all other processes.
	 */
	if (USER_SIGNALED(sc->siginfo) && sc->siginfo->si_pid != 0) {
	    pid_t si_pgrp = getpgid(sc->siginfo->si_pid);
	    if (si_pgrp != -1) {
		if (si_pgrp == mc->cmnd_pgrp)
		    debug_return;
	    } else if (sc->siginfo->si_pid == mc->cmnd_pid) {
		    debug_return;
	    }
	}
	deliver_signal(mc, signo, false);
    }
    debug_return;
}

/* Note: this is basically the same as errpipe_cb() in exec_nopty.c */
static void
mon_errpipe_cb(int fd, int what, void *v)
{
    struct monitor_closure *mc = v;
    ssize_t nread;
    int errval;
    debug_decl(mon_errpipe_cb, SUDO_DEBUG_EXEC);

    /*
     * Read errno from child or EOF when command is executed.
     * Note that the error pipe is *blocking*.
     */
    nread = read(fd, &errval, sizeof(errval));
    switch (nread) {
    case -1:
	if (errno != EAGAIN && errno != EINTR) {
	    if (mc->cstat->val == CMD_INVALID) {
		/* XXX - need a way to distinguish non-exec error. */
		mc->cstat->type = CMD_ERRNO;
		mc->cstat->val = errno;
	    }
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: failed to read error pipe", __func__);
	    sudo_ev_loopbreak(mc->evbase);
	}
	break;
    default:
	if (nread == 0) {
	    /* The error pipe closes when the command is executed. */
	    sudo_debug_printf(SUDO_DEBUG_INFO, "EOF on error pipe");
	} else {
	    /* Errno value when child is unable to execute command. */
	    sudo_debug_printf(SUDO_DEBUG_INFO, "errno from child: %s",
		strerror(errval));
	    mc->cstat->type = CMD_ERRNO;
	    mc->cstat->val = errval;
	}
	sudo_ev_del(mc->evbase, mc->errpipe_event);
	close(fd);
	break;
    }
    debug_return;
}

static void
mon_backchannel_cb(int fd, int what, void *v)
{
    struct monitor_closure *mc = v;
    struct command_status cstmp;
    ssize_t n;
    debug_decl(mon_backchannel_cb, SUDO_DEBUG_EXEC);

    /*
     * Read command from backchannel, should be a signal.
     * Note that the backchannel is a *blocking* socket.
     */
    n = recv(fd, &cstmp, sizeof(cstmp), MSG_WAITALL);
    if (n != sizeof(cstmp)) {
	if (n == -1) {
	    if (errno == EINTR || errno == EAGAIN)
		debug_return;
	    sudo_warn(U_("error reading from socketpair"));
	} else {
	    /* short read or EOF, parent process died? */
	}
	/* XXX - need a way to distinguish non-exec error. */
	mc->cstat->type = CMD_ERRNO;
	mc->cstat->val = n ? EIO : ECONNRESET;
	sudo_ev_loopbreak(mc->evbase);
    } else {
	switch (cstmp.type) {
	case CMD_TTYWINCH:
	    handle_winch(mc, cstmp.val);
	    break;
	case CMD_SIGNO:
	    deliver_signal(mc, cstmp.val, true);
	    break;
	default:
	    sudo_warnx(U_("unexpected reply type on backchannel: %d"), cstmp.type);
	    break;
	}
    }
    debug_return;
}

/*
 * Sets up std{in,out,err} and executes the actual command.
 * Returns only if execve() fails.
 */
static void
exec_cmnd_pty(struct command_details *details, bool foreground, int errfd)
{
    volatile pid_t self = getpid();
    debug_decl(exec_cmnd_pty, SUDO_DEBUG_EXEC);

    /* Register cleanup function */
    sudo_fatal_callback_register(pty_cleanup);

    /* Set command process group here too to avoid a race. */
    setpgid(0, self);

    /* Wire up standard fds, note that stdout/stderr may be pipes. */
    if (io_fds[SFD_STDIN] != STDIN_FILENO) {
	if (dup2(io_fds[SFD_STDIN], STDIN_FILENO) == -1)
	    sudo_fatal("dup2");
	if (io_fds[SFD_STDIN] != io_fds[SFD_SLAVE])
	    close(io_fds[SFD_STDIN]);
    } else {
	if (fcntl(io_fds[SFD_STDIN], F_SETFD, 0) == -1)
	    sudo_fatal("fcntl");
    }
    if (io_fds[SFD_STDOUT] != STDOUT_FILENO) {
	if (dup2(io_fds[SFD_STDOUT], STDOUT_FILENO) == -1)
	    sudo_fatal("dup2");
	if (io_fds[SFD_STDOUT] != io_fds[SFD_SLAVE])
	    close(io_fds[SFD_STDOUT]);
    } else {
	if (fcntl(io_fds[SFD_STDOUT], F_SETFD, 0) == -1)
	    sudo_fatal("fcntl");
    }
    if (io_fds[SFD_STDERR] != STDERR_FILENO) {
	if (dup2(io_fds[SFD_STDERR], STDERR_FILENO) == -1)
	    sudo_fatal("dup2");
	if (io_fds[SFD_STDERR] != io_fds[SFD_SLAVE])
	    close(io_fds[SFD_STDERR]);
    } else {
	if (fcntl(io_fds[SFD_STDERR], F_SETFD, 0) == -1)
	    sudo_fatal("fcntl");
    }

    /* Wait for parent to grant us the tty if we are foreground. */
    if (foreground && !ISSET(details->flags, CD_EXEC_BG)) {
	struct timespec ts = { 0, 1000 };  /* 1us */
	sudo_debug_printf(SUDO_DEBUG_DEBUG, "%s: waiting for controlling tty",
	    __func__);
	while (tcgetpgrp(io_fds[SFD_SLAVE]) != self)
	    nanosleep(&ts, NULL);
	sudo_debug_printf(SUDO_DEBUG_DEBUG, "%s: got controlling tty",
	    __func__);
    }

    /* Done with the pty slave, don't leak it. */
    if (io_fds[SFD_SLAVE] != -1)
	close(io_fds[SFD_SLAVE]);

    /* Execute command; only returns on error. */
    sudo_debug_printf(SUDO_DEBUG_INFO, "executing %s in the %s",
	details->command, foreground ? "foreground" : "background");
    exec_cmnd(details, errfd);

    debug_return;
}

/*
 * Fill in the monitor closure and setup initial events.
 * Allocates read events for the signal pipe, error pipe and backchannel.
 */
static void
fill_exec_closure_monitor(struct monitor_closure *mc,
    struct command_status *cstat, int errfd, int backchannel)
{
    debug_decl(fill_exec_closure_monitor, SUDO_DEBUG_EXEC);
    
    /* Fill in the non-event part of the closure. */
    mc->cstat = cstat;
    mc->backchannel = backchannel;
    mc->mon_pgrp = getpgrp();

    /* Setup event base and events. */
    mc->evbase = sudo_ev_base_alloc();
    if (mc->evbase == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* Event for command status via errfd. */
    mc->errpipe_event = sudo_ev_alloc(errfd,
	SUDO_EV_READ|SUDO_EV_PERSIST, mon_errpipe_cb, mc);
    if (mc->errpipe_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(mc->evbase, mc->errpipe_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    /* Event for forwarded signals via backchannel. */
    mc->backchannel_event = sudo_ev_alloc(backchannel,
	SUDO_EV_READ|SUDO_EV_PERSIST, mon_backchannel_cb, mc);
    if (mc->backchannel_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(mc->evbase, mc->backchannel_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    /* Events for local signals. */
    mc->sigint_event = sudo_ev_alloc(SIGINT,
	SUDO_EV_SIGINFO, mon_signal_cb, mc);
    if (mc->sigint_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(mc->evbase, mc->sigint_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    mc->sigquit_event = sudo_ev_alloc(SIGQUIT,
	SUDO_EV_SIGINFO, mon_signal_cb, mc);
    if (mc->sigquit_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(mc->evbase, mc->sigquit_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    mc->sigtstp_event = sudo_ev_alloc(SIGTSTP,
	SUDO_EV_SIGINFO, mon_signal_cb, mc);
    if (mc->sigtstp_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(mc->evbase, mc->sigtstp_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    mc->sigterm_event = sudo_ev_alloc(SIGTERM,
	SUDO_EV_SIGINFO, mon_signal_cb, mc);
    if (mc->sigterm_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(mc->evbase, mc->sigterm_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    mc->sighup_event = sudo_ev_alloc(SIGHUP,
	SUDO_EV_SIGINFO, mon_signal_cb, mc);
    if (mc->sighup_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(mc->evbase, mc->sighup_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    mc->sigusr1_event = sudo_ev_alloc(SIGUSR1,
	SUDO_EV_SIGINFO, mon_signal_cb, mc);
    if (mc->sigusr1_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(mc->evbase, mc->sigusr1_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    mc->sigusr2_event = sudo_ev_alloc(SIGUSR2,
	SUDO_EV_SIGINFO, mon_signal_cb, mc);
    if (mc->sigusr2_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(mc->evbase, mc->sigusr2_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    mc->sigchld_event = sudo_ev_alloc(SIGCHLD,
	SUDO_EV_SIGINFO, mon_signal_cb, mc);
    if (mc->sigchld_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(mc->evbase, mc->sigchld_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    /* Clear the default event base. */
    sudo_ev_base_setdef(NULL);

    debug_return;
}

/*
 * Monitor process that creates a new session with the controlling tty,
 * resets signal handlers and forks a child to call exec_cmnd_pty().
 * Waits for status changes from the command and relays them to the
 * parent and relays signals from the parent to the command.
 * Must be called with signals blocked and the old signal mask in oset.
 * Returns an error if fork(2) fails, else calls _exit(2).
 */
int
exec_monitor(struct command_details *details, sigset_t *oset,
    bool foreground, int backchannel)
{
    struct monitor_closure mc = { 0 };
    struct command_status cstat;
    struct sigaction sa;
    int errpipe[2];
    debug_decl(exec_monitor, SUDO_DEBUG_EXEC);

    /* The pty master is not used by the monitor. */
    if (io_fds[SFD_MASTER] != -1)
	close(io_fds[SFD_MASTER]);

    /* Ignore any SIGTTIN or SIGTTOU we receive (shouldn't be possible). */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_IGN;
    if (sudo_sigaction(SIGTTIN, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTTIN);
    if (sudo_sigaction(SIGTTOU, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTTOU);

    /* If we are starting in the foreground, the pty was already initialized. */
    if (foreground)
	tty_initialized = true;

    /*
     * Start a new session with the parent as the session leader
     * and the slave pty as the controlling terminal.
     * This allows us to be notified when the command has been suspended.
     */
    if (setsid() == -1) {
	sudo_warn("setsid");
	goto bad;
    }
    if (pty_make_controlling() == -1) {
	sudo_warn(U_("unable to set controlling tty"));
	goto bad;
    }

    /*
     * We use a pipe to get errno if execve(2) fails in the child.
     */
    if (pipe2(errpipe, O_CLOEXEC) != 0)
	sudo_fatal(U_("unable to create pipe"));

    /*
     * Before forking, wait for the main sudo process to tell us to go.
     * Avoids race conditions when the command exits quickly.
     */
    while (recv(backchannel, &cstat, sizeof(cstat), MSG_WAITALL) == -1) {
	if (errno != EINTR && errno != EAGAIN)
	    sudo_fatal(U_("unable to receive message from parent"));
    }

#ifdef HAVE_SELINUX
    if (ISSET(details->flags, CD_RBAC_ENABLED)) {
        if (selinux_setup(details->selinux_role, details->selinux_type,
            details->tty, io_fds[SFD_SLAVE]) == -1)
            goto bad;
    }
#endif

    mc.cmnd_pid = sudo_debug_fork();
    switch (mc.cmnd_pid) {
    case -1:
	sudo_warn(U_("unable to fork"));
#ifdef HAVE_SELINUX
	if (ISSET(details->flags, CD_RBAC_ENABLED)) {
	    if (selinux_restore_tty() != 0)
		sudo_warnx(U_("unable to restore tty label"));
	}
#endif
	goto bad;
    case 0:
	/* child */
	sigprocmask(SIG_SETMASK, oset, NULL);
	close(backchannel);
	close(errpipe[0]);
	if (io_fds[SFD_USERTTY] != -1)
	    close(io_fds[SFD_USERTTY]);
	restore_signals();

	/* setup tty and exec command */
	exec_cmnd_pty(details, foreground, errpipe[1]);
	if (write(errpipe[1], &errno, sizeof(int)) == -1)
	    sudo_warn(U_("unable to execute %s"), details->command);
	_exit(1);
    }
    close(errpipe[1]);

    /* No longer need execfd. */
    if (details->execfd != -1) {
	close(details->execfd);
	details->execfd = -1;
    }

    /* Send the command's pid to main sudo process. */
    cstat.type = CMD_PID;
    cstat.val = mc.cmnd_pid;
    send_status(backchannel, &cstat);

    /*
     * Create new event base and register read events for the
     * signal pipe, error pipe, and backchannel.
     */
    fill_exec_closure_monitor(&mc, &cstat, errpipe[0], backchannel);

    /* Restore signal mask now that signal handlers are setup. */
    sigprocmask(SIG_SETMASK, oset, NULL);

    /* If any of stdin/stdout/stderr are pipes, close them in parent. */
    if (io_fds[SFD_STDIN] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDIN]);
    if (io_fds[SFD_STDOUT] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDOUT]);
    if (io_fds[SFD_STDERR] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDERR]);

    /* Put command in its own process group. */
    mc.cmnd_pgrp = mc.cmnd_pid;
    setpgid(mc.cmnd_pid, mc.cmnd_pgrp);

    /* Make the command the foreground process for the pty slave. */
    if (foreground && !ISSET(details->flags, CD_EXEC_BG)) {
	if (tcsetpgrp(io_fds[SFD_SLAVE], mc.cmnd_pgrp) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: unable to set foreground pgrp to %d (command)",
		__func__, (int)mc.cmnd_pgrp);
	}
    }

    /*
     * Wait for errno on pipe, signal on backchannel or for SIGCHLD.
     * The event loop ends when the child is no longer running and
     * the error pipe is closed.
     */
    cstat.type = CMD_INVALID;
    cstat.val = 0;
    (void) sudo_ev_dispatch(mc.evbase);
    if (mc.cmnd_pid != -1) {
	pid_t pid;

	/* Command still running, did the parent die? */
	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "Command still running after event loop exit, terminating");
	terminate_command(mc.cmnd_pid, true);
	do {
	    pid = waitpid(mc.cmnd_pid, NULL, 0);
	} while (pid == -1 && errno == EINTR);
	/* XXX - update cstat with wait status? */
    }

    /*
     * Take the controlling tty.  This prevents processes spawned by the
     * command from receiving SIGHUP when the session leader (us) exits.
     */
    if (tcsetpgrp(io_fds[SFD_SLAVE], mc.mon_pgrp) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to set foreground pgrp to %d (monitor)",
	    __func__, (int)mc.mon_pgrp);
    }

    /* Send parent status. */
    send_status(backchannel, &cstat);

#ifdef HAVE_SELINUX
    if (ISSET(details->flags, CD_RBAC_ENABLED)) {
	if (selinux_restore_tty() != 0)
	    sudo_warnx(U_("unable to restore tty label"));
    }
#endif
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, 1);
    _exit(1);

bad:
    debug_return_int(-1);
}
