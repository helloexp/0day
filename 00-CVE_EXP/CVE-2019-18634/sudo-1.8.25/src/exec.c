/*
 * Copyright (c) 2009-2017 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
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
#include <pwd.h>
#include <signal.h>
#ifdef HAVE_LOGIN_CAP_H
# include <login_cap.h>
# ifndef LOGIN_SETENV
#  define LOGIN_SETENV  0
# endif
#endif
#ifdef HAVE_PROJECT_H
# include <project.h>
# include <sys/task.h>
#endif

#include "sudo.h"
#include "sudo_exec.h"
#include "sudo_event.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

#ifdef __linux__
static struct rlimit nproclimit;
#endif

/*
 * Unlimit the number of processes since Linux's setuid() will
 * apply resource limits when changing uid and return EAGAIN if
 * nproc would be exceeded by the uid switch.
 */
static void
unlimit_nproc(void)
{
#ifdef __linux__
    struct rlimit rl;
    debug_decl(unlimit_nproc, SUDO_DEBUG_UTIL)

    if (getrlimit(RLIMIT_NPROC, &nproclimit) != 0)
	sudo_warn("getrlimit");
    rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
	rl.rlim_cur = rl.rlim_max = nproclimit.rlim_max;
	if (setrlimit(RLIMIT_NPROC, &rl) != 0)
	    sudo_warn("setrlimit");
    }
    debug_return;
#endif /* __linux__ */
}

/*
 * Restore saved value of RLIMIT_NPROC.
 */
static void
restore_nproc(void)
{
#ifdef __linux__
    debug_decl(restore_nproc, SUDO_DEBUG_UTIL)

    if (setrlimit(RLIMIT_NPROC, &nproclimit) != 0)
	sudo_warn("setrlimit");

    debug_return;
#endif /* __linux__ */
}

/*
 * Setup the execution environment immediately prior to the call to execve().
 * Group setup is performed by policy_init_session(), called earlier.
 * Returns true on success and false on failure.
 */
static bool
exec_setup(struct command_details *details, const char *ptyname, int ptyfd)
{
    bool ret = false;
    debug_decl(exec_setup, SUDO_DEBUG_EXEC)

#ifdef HAVE_SELINUX
    if (ISSET(details->flags, CD_RBAC_ENABLED)) {
	if (selinux_setup(details->selinux_role, details->selinux_type,
	    ptyname ? ptyname : user_details.tty, ptyfd) == -1)
	    goto done;
    }
#endif

    /* Restore coredumpsize resource limit before running. */
    if (sudo_conf_disable_coredump())
	disable_coredump(true);

    if (details->pw != NULL) {
#ifdef HAVE_PROJECT_H
	set_project(details->pw);
#endif
#ifdef HAVE_PRIV_SET
	if (details->privs != NULL) {
	    if (setppriv(PRIV_SET, PRIV_INHERITABLE, details->privs) != 0) {
		sudo_warn("unable to set privileges");
		goto done;
	    }
	}
	if (details->limitprivs != NULL) {
	    if (setppriv(PRIV_SET, PRIV_LIMIT, details->limitprivs) != 0) {
		sudo_warn("unable to set limit privileges");
		goto done;
	    }
	} else if (details->privs != NULL) {
	    if (setppriv(PRIV_SET, PRIV_LIMIT, details->privs) != 0) {
		sudo_warn("unable to set limit privileges");
		goto done;
	    }
	}
#endif /* HAVE_PRIV_SET */

#ifdef HAVE_GETUSERATTR
	if (aix_prep_user(details->pw->pw_name, ptyname ? ptyname : user_details.tty) != 0) {
	    /* error message displayed by aix_prep_user */
	    goto done;
	}
#endif
#ifdef HAVE_LOGIN_CAP_H
	if (details->login_class) {
	    int flags;
	    login_cap_t *lc;

	    /*
	     * We only use setusercontext() to set the nice value and rlimits
	     * unless this is a login shell (sudo -i).
	     */
	    lc = login_getclass((char *)details->login_class);
	    if (!lc) {
		sudo_warnx(U_("unknown login class %s"), details->login_class);
		errno = ENOENT;
		goto done;
	    }
	    if (ISSET(details->flags, CD_LOGIN_SHELL)) {
		/* Set everything except user, group and login name. */
		flags = LOGIN_SETALL;
		CLR(flags, LOGIN_SETGROUP|LOGIN_SETLOGIN|LOGIN_SETUSER|LOGIN_SETENV|LOGIN_SETPATH);
		CLR(details->flags, CD_SET_UMASK); /* LOGIN_UMASK instead */
	    } else {
		flags = LOGIN_SETRESOURCES|LOGIN_SETPRIORITY;
	    }
	    if (setusercontext(lc, details->pw, details->pw->pw_uid, flags)) {
		sudo_warn(U_("unable to set user context"));
		if (details->pw->pw_uid != ROOT_UID)
		    goto done;
	    }
	}
#endif /* HAVE_LOGIN_CAP_H */
    }

    if (ISSET(details->flags, CD_SET_GROUPS)) {
	/* set_user_groups() prints error message on failure. */
	if (!set_user_groups(details))
	    goto done;
    }

    if (ISSET(details->flags, CD_SET_PRIORITY)) {
	if (setpriority(PRIO_PROCESS, 0, details->priority) != 0) {
	    sudo_warn(U_("unable to set process priority"));
	    goto done;
	}
    }
    if (ISSET(details->flags, CD_SET_UMASK))
	(void) umask(details->umask);
    if (details->chroot) {
	if (chroot(details->chroot) != 0 || chdir("/") != 0) {
	    sudo_warn(U_("unable to change root to %s"), details->chroot);
	    goto done;
	}
    }

    /* 
     * Unlimit the number of processes since Linux's setuid() will
     * return EAGAIN if RLIMIT_NPROC would be exceeded by the uid switch.
     */
    unlimit_nproc();

#if defined(HAVE_SETRESUID)
    if (setresuid(details->uid, details->euid, details->euid) != 0) {
	sudo_warn(U_("unable to change to runas uid (%u, %u)"),
	    (unsigned int)details->uid, (unsigned int)details->euid);
	goto done;
    }
#elif defined(HAVE_SETREUID)
    if (setreuid(details->uid, details->euid) != 0) {
	sudo_warn(U_("unable to change to runas uid (%u, %u)"),
	    (unsigned int)details->uid, (unsigned int)details->euid);
	goto done;
    }
#else
    /* Cannot support real user ID that is different from effective user ID. */
    if (setuid(details->euid) != 0) {
	sudo_warn(U_("unable to change to runas uid (%u, %u)"),
	    (unsigned int)details->euid, (unsigned int)details->euid);
	goto done;
    }
#endif /* !HAVE_SETRESUID && !HAVE_SETREUID */

    /* Restore previous value of RLIMIT_NPROC. */
    restore_nproc();

    /*
     * Only change cwd if we have chroot()ed or the policy modules
     * specifies a different cwd.  Must be done after uid change.
     */
    if (details->cwd != NULL) {
	if (details->chroot || user_details.cwd == NULL ||
	    strcmp(details->cwd, user_details.cwd) != 0) {
	    /* Note: cwd is relative to the new root, if any. */
	    if (chdir(details->cwd) != 0) {
		sudo_warn(U_("unable to change directory to %s"), details->cwd);
		goto done;
	    }
	}
    }

    ret = true;

done:
    debug_return_bool(ret);
}

/*
 * Setup the execution environment and execute the command.
 * If SELinux is enabled, run the command via sesh, otherwise
 * execute it directly.
 * If the exec fails, cstat is filled in with the value of errno.
 */
void
exec_cmnd(struct command_details *details, int errfd)
{
    debug_decl(exec_cmnd, SUDO_DEBUG_EXEC)

    restore_signals();
    if (exec_setup(details, NULL, -1) == true) {
	/* headed for execve() */
	if (details->closefrom >= 0) {
	    int fd, maxfd;
	    unsigned char *debug_fds;

	    /* Preserve debug fds and error pipe as needed. */
	    maxfd = sudo_debug_get_fds(&debug_fds);
	    for (fd = 0; fd <= maxfd; fd++) {
		if (sudo_isset(debug_fds, fd))
		    add_preserved_fd(&details->preserved_fds, fd);
	    }
	    if (errfd != -1)
		add_preserved_fd(&details->preserved_fds, errfd);

	    /* Close all fds except those explicitly preserved. */
	    closefrom_except(details->closefrom, &details->preserved_fds);
	}
#ifdef HAVE_SELINUX
	if (ISSET(details->flags, CD_RBAC_ENABLED)) {
	    selinux_execve(details->execfd, details->command, details->argv,
		details->envp, ISSET(details->flags, CD_NOEXEC));
	} else
#endif
	{
	    sudo_execve(details->execfd, details->command, details->argv,
		details->envp, ISSET(details->flags, CD_NOEXEC));
	}
    }
    sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to exec %s: %s",
	details->command, strerror(errno));
    debug_return;
}

/*
 * Check for caught signals sent to sudo before command execution.
 * Also suspends the process if SIGTSTP was caught.
 * Returns true if we should terminate, else false.
 */
bool
sudo_terminated(struct command_status *cstat)
{
    int signo;
    bool sigtstp = false;
    debug_decl(sudo_terminated, SUDO_DEBUG_EXEC)

    for (signo = 0; signo < NSIG; signo++) {
	if (signal_pending(signo)) {
	    switch (signo) {
	    case SIGCHLD:
		/* Ignore. */
		break;
	    case SIGTSTP:
		/* Suspend below if not terminated. */
		sigtstp = true;
		break;
	    default:
		/* Terminal signal, do not exec command. */
		cstat->type = CMD_WSTATUS;
		cstat->val = signo + 128;
		debug_return_bool(true);
		break;
	    }
	}
    }
    if (sigtstp) {
	struct sigaction sa;
	sigset_t set, oset;

	/* Send SIGTSTP to ourselves, unblocking it if needed. */
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = SIG_DFL;
	if (sudo_sigaction(SIGTSTP, &sa, NULL) != 0)
	    sudo_warn(U_("unable to set handler for signal %d"), SIGTSTP);
	sigemptyset(&set);
	sigaddset(&set, SIGTSTP);
	sigprocmask(SIG_UNBLOCK, &set, &oset);
	if (kill(getpid(), SIGTSTP) != 0)
	    sudo_warn("kill(%d, SIGTSTP)", (int)getpid());
	sigprocmask(SIG_SETMASK, &oset, NULL);
	/* No need to restore old SIGTSTP handler. */
    }
    debug_return_bool(false);
}

/*
 * Execute a command, potentially in a pty with I/O loggging, and
 * wait for it to finish.
 * This is a little bit tricky due to how POSIX job control works and
 * we fact that we have two different controlling terminals to deal with.
 */
int
sudo_execute(struct command_details *details, struct command_status *cstat)
{
    debug_decl(sudo_execute, SUDO_DEBUG_EXEC)

    /* If running in background mode, fork and exit. */
    if (ISSET(details->flags, CD_BACKGROUND)) {
	switch (sudo_debug_fork()) {
	    case -1:
		cstat->type = CMD_ERRNO;
		cstat->val = errno;
		debug_return_int(-1);
	    case 0:
		/* child continues without controlling terminal */
		(void)setpgid(0, 0);
		break;
	    default:
		/* parent exits (but does not flush buffers) */
		sudo_debug_exit_int(__func__, __FILE__, __LINE__,
		    sudo_debug_subsys, 0);
		_exit(0);
	}
    }

    /*
     * Run the command in a new pty if there is an I/O plugin or the policy
     * has requested a pty.  If /dev/tty is unavailable and no I/O plugin
     * is configured, this returns false and we run the command without a pty.
     */
    if (!TAILQ_EMPTY(&io_plugins) || ISSET(details->flags, CD_USE_PTY)) {
	if (exec_pty(details, cstat))
	    goto done;
    }

    /*
     * If we are not running the command in a pty, we were not invoked
     * as sudoedit, there is no command timeout and there is no close
     * function, just exec directly.  Only returns on error.
     */
    if (!ISSET(details->flags, CD_SET_TIMEOUT|CD_SUDOEDIT) &&
	policy_plugin.u.policy->close == NULL) {
	if (!sudo_terminated(cstat)) {
	    exec_cmnd(details, -1);
	    cstat->type = CMD_ERRNO;
	    cstat->val = errno;
	}
	goto done;
    }

    /*
     * Run the command in the existing tty (if any) and wait for it to finish.
     */
    exec_nopty(details, cstat);

done:
    /* The caller will run any plugin close functions. */
    debug_return_int(cstat->type == CMD_ERRNO ? -1 : 0);
}

/*
 * Kill command with increasing urgency.
 */
void
terminate_command(pid_t pid, bool use_pgrp)
{
    debug_decl(terminate_command, SUDO_DEBUG_EXEC);

    /* Avoid killing more than a single process or process group. */
    if (pid <= 0)
	debug_return;

    /*
     * Note that SIGCHLD will interrupt the sleep()
     */
    if (use_pgrp) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "killpg %d SIGHUP", (int)pid);
	killpg(pid, SIGHUP);
	sudo_debug_printf(SUDO_DEBUG_INFO, "killpg %d SIGTERM", (int)pid);
	killpg(pid, SIGTERM);
	sleep(2);
	sudo_debug_printf(SUDO_DEBUG_INFO, "killpg %d SIGKILL", (int)pid);
	killpg(pid, SIGKILL);
    } else {
	sudo_debug_printf(SUDO_DEBUG_INFO, "kill %d SIGHUP", (int)pid);
	kill(pid, SIGHUP);
	sudo_debug_printf(SUDO_DEBUG_INFO, "kill %d SIGTERM", (int)pid);
	kill(pid, SIGTERM);
	sleep(2);
	sudo_debug_printf(SUDO_DEBUG_INFO, "kill %d SIGKILL", (int)pid);
	kill(pid, SIGKILL);
    }

    debug_return;
}
