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
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include "sudo.h"
#include "sudo_exec.h"
#include "sudo_event.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

struct exec_closure_nopty {
    pid_t cmnd_pid;
    pid_t ppgrp;
    struct command_status *cstat;
    struct command_details *details;
    struct sudo_event_base *evbase;
    struct sudo_event *errpipe_event;
    struct sudo_event *sigint_event;
    struct sudo_event *sigquit_event;
    struct sudo_event *sigtstp_event;
    struct sudo_event *sigterm_event;
    struct sudo_event *sighup_event;
    struct sudo_event *sigalrm_event;
    struct sudo_event *sigpipe_event;
    struct sudo_event *sigusr1_event;
    struct sudo_event *sigusr2_event;
    struct sudo_event *sigchld_event;
    struct sudo_event *sigcont_event;
    struct sudo_event *siginfo_event;
};

static void handle_sigchld_nopty(struct exec_closure_nopty *ec);

/* Note: this is basically the same as mon_errpipe_cb() in exec_monitor.c */
static void
errpipe_cb(int fd, int what, void *v)
{
    struct exec_closure_nopty *ec = v;
    ssize_t nread;
    int errval;
    debug_decl(errpipe_cb, SUDO_DEBUG_EXEC);

    /*
     * Read errno from child or EOF when command is executed.
     * Note that the error pipe is *blocking*.
     */
    nread = read(fd, &errval, sizeof(errval));
    switch (nread) {
    case -1:
	if (errno != EAGAIN && errno != EINTR) {
	    if (ec->cstat->val == CMD_INVALID) {
		/* XXX - need a way to distinguish non-exec error. */
		ec->cstat->type = CMD_ERRNO;
		ec->cstat->val = errno;
	    }
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: failed to read error pipe", __func__);
	    sudo_ev_loopbreak(ec->evbase);
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
	    ec->cstat->type = CMD_ERRNO;
	    ec->cstat->val = errval;
	}
	sudo_ev_del(ec->evbase, ec->errpipe_event);
	close(fd);
	break;
    }
    debug_return;
}

/* Signal callback */
static void
signal_cb_nopty(int signo, int what, void *v)
{
    struct sudo_ev_siginfo_container *sc = v;
    struct exec_closure_nopty *ec = sc->closure;
    char signame[SIG2STR_MAX];
    debug_decl(signal_cb_nopty, SUDO_DEBUG_EXEC)

    if (ec->cmnd_pid == -1)
	debug_return;

    if (sig2str(signo, signame) == -1)
	(void)snprintf(signame, sizeof(signame), "%d", signo);
    sudo_debug_printf(SUDO_DEBUG_DIAG,
	"%s: evbase %p, command: %d, signo %s(%d), cstat %p",
	__func__, ec->evbase, (int)ec->cmnd_pid, signame, signo, ec->cstat);

    switch (signo) {
    case SIGCHLD:
	handle_sigchld_nopty(ec);
	if (ec->cmnd_pid == -1) {
	    /* Command exited or was killed, exit event loop. */
	    sudo_ev_loopexit(ec->evbase);
	}
	debug_return;
#ifdef SIGINFO
    case SIGINFO:
#endif
    case SIGINT:
    case SIGQUIT:
    case SIGTSTP:
	/*
	 * Only forward user-generated signals not sent by a process in
	 * the command's own process group.  Signals sent by the kernel
	 * may include SIGTSTP when the user presses ^Z.  Curses programs
	 * often trap ^Z and send SIGTSTP to their own pgrp, so we don't
	 * want to send an extra SIGTSTP.
	 */
	if (!USER_SIGNALED(sc->siginfo))
	    debug_return;
	if (sc->siginfo->si_pid != 0) {
	    pid_t si_pgrp = getpgid(sc->siginfo->si_pid);
	    if (si_pgrp != -1) {
		if (si_pgrp == ec->ppgrp || si_pgrp == ec->cmnd_pid)
		    debug_return;
	    } else if (sc->siginfo->si_pid == ec->cmnd_pid) {
		debug_return;
	    }
	}
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
	break;
    }

    /* Send signal to command. */
    if (signo == SIGALRM) {
	terminate_command(ec->cmnd_pid, false);
    } else if (kill(ec->cmnd_pid, signo) != 0) {
	sudo_warn("kill(%d, SIG%s)", (int)ec->cmnd_pid, signame);
    }

    debug_return;
}


/*
 * Fill in the exec closure and setup initial exec events.
 * Allocates events for the signal pipe and error pipe.
 */
static void
fill_exec_closure_nopty(struct exec_closure_nopty *ec,
    struct command_status *cstat, struct command_details *details, int errfd)
{
    debug_decl(fill_exec_closure_nopty, SUDO_DEBUG_EXEC)

    /* Fill in the non-event part of the closure. */
    ec->ppgrp = getpgrp();
    ec->cstat = cstat;
    ec->details = details;

    /* Setup event base and events. */
    ec->evbase = sudo_ev_base_alloc();
    if (ec->evbase == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* Event for command status via errfd. */
    ec->errpipe_event = sudo_ev_alloc(errfd,
	SUDO_EV_READ|SUDO_EV_PERSIST, errpipe_cb, ec);
    if (ec->errpipe_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->errpipe_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));
    sudo_debug_printf(SUDO_DEBUG_INFO, "error pipe fd %d\n", errfd);

    /* Events for local signals. */
    ec->sigint_event = sudo_ev_alloc(SIGINT,
	SUDO_EV_SIGINFO, signal_cb_nopty, ec);
    if (ec->sigint_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigint_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigquit_event = sudo_ev_alloc(SIGQUIT,
	SUDO_EV_SIGINFO, signal_cb_nopty, ec);
    if (ec->sigquit_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigquit_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigtstp_event = sudo_ev_alloc(SIGTSTP,
	SUDO_EV_SIGINFO, signal_cb_nopty, ec);
    if (ec->sigtstp_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigtstp_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigterm_event = sudo_ev_alloc(SIGTERM,
	SUDO_EV_SIGINFO, signal_cb_nopty, ec);
    if (ec->sigterm_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigterm_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sighup_event = sudo_ev_alloc(SIGHUP,
	SUDO_EV_SIGINFO, signal_cb_nopty, ec);
    if (ec->sighup_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sighup_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigalrm_event = sudo_ev_alloc(SIGALRM,
	SUDO_EV_SIGINFO, signal_cb_nopty, ec);
    if (ec->sigalrm_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigalrm_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigpipe_event = sudo_ev_alloc(SIGPIPE,
	SUDO_EV_SIGINFO, signal_cb_nopty, ec);
    if (ec->sigpipe_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigpipe_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigusr1_event = sudo_ev_alloc(SIGUSR1,
	SUDO_EV_SIGINFO, signal_cb_nopty, ec);
    if (ec->sigusr1_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigusr1_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigusr2_event = sudo_ev_alloc(SIGUSR2,
	SUDO_EV_SIGINFO, signal_cb_nopty, ec);
    if (ec->sigusr2_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigusr2_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigchld_event = sudo_ev_alloc(SIGCHLD,
	SUDO_EV_SIGINFO, signal_cb_nopty, ec);
    if (ec->sigchld_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigchld_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    ec->sigcont_event = sudo_ev_alloc(SIGCONT,
	SUDO_EV_SIGINFO, signal_cb_nopty, ec);
    if (ec->sigcont_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->sigcont_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

#ifdef SIGINFO
    ec->siginfo_event = sudo_ev_alloc(SIGINFO,
	SUDO_EV_SIGINFO, signal_cb_nopty, ec);
    if (ec->siginfo_event == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (sudo_ev_add(ec->evbase, ec->siginfo_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));
#endif

    /* Set the default event base. */
    sudo_ev_base_setdef(ec->evbase);

    debug_return;
}

/*
 * Free the dynamically-allocated contents of the exec closure.
 */
static void
free_exec_closure_nopty(struct exec_closure_nopty *ec)
{
    debug_decl(free_exec_closure_nopty, SUDO_DEBUG_EXEC)

    sudo_ev_base_free(ec->evbase);
    sudo_ev_free(ec->errpipe_event);
    sudo_ev_free(ec->sigint_event);
    sudo_ev_free(ec->sigquit_event);
    sudo_ev_free(ec->sigtstp_event);
    sudo_ev_free(ec->sigterm_event);
    sudo_ev_free(ec->sighup_event);
    sudo_ev_free(ec->sigalrm_event);
    sudo_ev_free(ec->sigpipe_event);
    sudo_ev_free(ec->sigusr1_event);
    sudo_ev_free(ec->sigusr2_event);
    sudo_ev_free(ec->sigchld_event);
    sudo_ev_free(ec->sigcont_event);
    sudo_ev_free(ec->siginfo_event);

    debug_return;
}

/*
 * Execute a command and wait for it to finish.
 */
void
exec_nopty(struct command_details *details, struct command_status *cstat)
{
    struct exec_closure_nopty ec = { 0 };
    sigset_t set, oset;
    int errpipe[2];
    debug_decl(exec_nopty, SUDO_DEBUG_EXEC)

    /*
     * The policy plugin's session init must be run before we fork
     * or certain pam modules won't be able to track their state.
     */
    if (policy_init_session(details) != true)
	sudo_fatalx(U_("policy plugin failed session initialization"));

    /*
     * We use a pipe to get errno if execve(2) fails in the child.
     */
    if (pipe2(errpipe, O_CLOEXEC) != 0)
	sudo_fatal(U_("unable to create pipe"));

    /*
     * Block signals until we have our handlers setup in the parent so
     * we don't miss SIGCHLD if the command exits immediately.
     */
    sigfillset(&set);
    sigprocmask(SIG_BLOCK, &set, &oset);

    /* Check for early termination or suspend signals before we fork. */
    if (sudo_terminated(cstat)) {
	sigprocmask(SIG_SETMASK, &oset, NULL);
	debug_return;
    }

#ifdef HAVE_SELINUX
    if (ISSET(details->flags, CD_RBAC_ENABLED)) {
        if (selinux_setup(details->selinux_role, details->selinux_type,
		details->tty, -1) == -1) {
	    cstat->type = CMD_ERRNO;
	    cstat->val = errno;
	    debug_return;
	}
    }
#endif

    ec.cmnd_pid = sudo_debug_fork();
    switch (ec.cmnd_pid) {
    case -1:
	sudo_fatal(U_("unable to fork"));
	break;
    case 0:
	/* child */
	sigprocmask(SIG_SETMASK, &oset, NULL);
	close(errpipe[0]);
	exec_cmnd(details, errpipe[1]);
	while (write(errpipe[1], &errno, sizeof(int)) == -1) {
	    if (errno != EINTR)
		break;
	}
	sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, 1);
	_exit(1);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "executed %s, pid %d", details->command,
	(int)ec.cmnd_pid);
    close(errpipe[1]);

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
     * the error pipe event.
     */
    fill_exec_closure_nopty(&ec, cstat, details, errpipe[0]);

    /* Restore signal mask now that signal handlers are setup. */
    sigprocmask(SIG_SETMASK, &oset, NULL);

    /*
     * Non-pty event loop.
     * Wait for command to exit, handles signals and the error pipe.
     */
    if (sudo_ev_dispatch(ec.evbase) == -1)
	sudo_warn(U_("error in event loop"));
    if (sudo_ev_got_break(ec.evbase)) {
	/* error from callback */
	sudo_debug_printf(SUDO_DEBUG_ERROR, "event loop exited prematurely");
	/* kill command */
	terminate_command(ec.cmnd_pid, true);
    }

#ifdef HAVE_SELINUX
    if (ISSET(details->flags, CD_RBAC_ENABLED)) {
	if (selinux_restore_tty() != 0)
	    sudo_warnx(U_("unable to restore tty label"));
    }
#endif

    /* Free things up. */
    free_exec_closure_nopty(&ec);
    debug_return;
}

/*
 * Wait for command status after receiving SIGCHLD.
 * If the command exits, fill in cstat and stop the event loop.
 * If the command stops, save the tty pgrp, suspend sudo, then restore
 * the tty pgrp when sudo resumes.
 */
static void
handle_sigchld_nopty(struct exec_closure_nopty *ec)
{
    pid_t pid;
    int status;
    char signame[SIG2STR_MAX];
    debug_decl(handle_sigchld_nopty, SUDO_DEBUG_EXEC)

    /* Read command status. */
    do {
	pid = waitpid(ec->cmnd_pid, &status, WUNTRACED|WNOHANG);
    } while (pid == -1 && errno == EINTR);
    switch (pid) {
    case 0:
	/* waitpid() will return 0 for SIGCONT, which we don't care about */
	debug_return;
    case -1:
	sudo_warn(U_("%s: %s"), __func__, "waitpid");
	debug_return;
    }

    if (WIFSTOPPED(status)) {
	/*
	 * Save the controlling terminal's process group so we can restore it
	 * after we resume, if needed.  Most well-behaved shells change the
	 * pgrp back to its original value before suspending so we must
	 * not try to restore in that case, lest we race with the command upon
	 * resume, potentially stopping sudo with SIGTTOU while the command
	 * continues to run.
	 */
	struct sigaction sa, osa;
	pid_t saved_pgrp = -1;
	int fd, signo = WSTOPSIG(status);

	if (sig2str(signo, signame) == -1)
	    (void)snprintf(signame, sizeof(signame), "%d", signo);
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: command (%d) stopped, SIG%s",
	    __func__, (int)ec->cmnd_pid, signame);

	fd = open(_PATH_TTY, O_RDWR);
	if (fd != -1) {
	    saved_pgrp = tcgetpgrp(fd);
	    if (saved_pgrp == -1) {
		close(fd);
		fd = -1;
	    }
	}
	if (saved_pgrp != -1) {
	    /*
	     * Command was stopped trying to access the controlling terminal.
	     * If the command has a different pgrp and we own the controlling
	     * terminal, give it to the command's pgrp and let it continue.
	     */
	    if (signo == SIGTTOU || signo == SIGTTIN) {
		if (saved_pgrp == ec->ppgrp) {
		    pid_t cmnd_pgrp = getpgid(ec->cmnd_pid);
		    if (cmnd_pgrp != ec->ppgrp) {
			if (tcsetpgrp_nobg(fd, cmnd_pgrp) == 0) {
			    if (killpg(cmnd_pgrp, SIGCONT) != 0) {
				sudo_warn("kill(%d, SIGCONT)",
				    (int)cmnd_pgrp);
			    }
			    close(fd);
			    goto done;
			}
		    }
		}
	    }
	}
	if (signo == SIGTSTP) {
	    memset(&sa, 0, sizeof(sa));
	    sigemptyset(&sa.sa_mask);
	    sa.sa_flags = SA_RESTART;
	    sa.sa_handler = SIG_DFL;
	    if (sudo_sigaction(SIGTSTP, &sa, &osa) != 0) {
		sudo_warn(U_("unable to set handler for signal %d"),
		    SIGTSTP);
	    }
	}
	if (kill(getpid(), signo) != 0)
	    sudo_warn("kill(%d, SIG%s)", (int)getpid(), signame);
	if (signo == SIGTSTP) {
	    if (sudo_sigaction(SIGTSTP, &osa, NULL) != 0) {
		sudo_warn(U_("unable to restore handler for signal %d"),
		    SIGTSTP);
	    }
	}
	if (saved_pgrp != -1) {
	    /*
	     * On resume, restore foreground process group, if different.
	     * Otherwise, we cannot resume some shells (pdksh).
	     *
	     * It is possible that we are no longer the foreground process so
	     * use tcsetpgrp_nobg() to prevent sudo from receiving SIGTTOU.
	     */
	    if (saved_pgrp != ec->ppgrp)
		tcsetpgrp_nobg(fd, saved_pgrp);
	    close(fd);
	}
    } else {
	/* Command has exited or been killed, we are done. */
	if (WIFSIGNALED(status)) {
	    if (sig2str(WTERMSIG(status), signame) == -1)
		(void)snprintf(signame, sizeof(signame), "%d", WTERMSIG(status));
	    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: command (%d) killed, SIG%s",
		__func__, (int)ec->cmnd_pid, signame);
	} else {
	    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: command (%d) exited: %d",
		__func__, (int)ec->cmnd_pid, WEXITSTATUS(status));
	}
	/* Don't overwrite execve() failure with command exit status. */
	if (ec->cstat->type == CMD_INVALID) {
	    ec->cstat->type = CMD_WSTATUS;
	    ec->cstat->val = status;
	} else {
	    sudo_debug_printf(SUDO_DEBUG_WARN,
		"%s: not overwriting command status %d,%d with %d,%d",
		__func__, ec->cstat->type, ec->cstat->val, CMD_WSTATUS, status);
	}
	ec->cmnd_pid = -1;
    }
done:
    debug_return;
}
