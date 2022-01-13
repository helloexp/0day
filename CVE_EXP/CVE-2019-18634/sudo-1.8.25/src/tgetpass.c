/*
 * Copyright (c) 1996, 1998-2005, 2007-2016
 *	Todd C. Miller <Todd.Miller@sudo.ws>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#ifdef __TANDEM
# include <floss.h>
#endif

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
#include <pwd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include "sudo.h"
#include "sudo_plugin.h"

static volatile sig_atomic_t signo[NSIG];

static bool tty_present(void);
static void tgetpass_handler(int);
static char *getln(int, char *, size_t, int);
static char *sudo_askpass(const char *, const char *);

static int
suspend(int signo, struct sudo_conv_callback *callback)
{
    int ret = 0;
    debug_decl(suspend, SUDO_DEBUG_CONV)

    if (callback != NULL && SUDO_API_VERSION_GET_MAJOR(callback->version) != SUDO_CONV_CALLBACK_VERSION_MAJOR) {
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
	    "callback major version mismatch, expected %u, got %u",
	    SUDO_CONV_CALLBACK_VERSION_MAJOR,
	    SUDO_API_VERSION_GET_MAJOR(callback->version));
	callback = NULL;
    }

    if (callback != NULL && callback->on_suspend != NULL) {
	if (callback->on_suspend(signo, callback->closure) == -1)
	    ret = -1;
    }
    kill(getpid(), signo);
    if (callback != NULL && callback->on_resume != NULL) {
	if (callback->on_resume(signo, callback->closure) == -1)
	    ret = -1;
    }
    debug_return_int(ret);
}

/*
 * Like getpass(3) but with timeout and echo flags.
 */
char *
tgetpass(const char *prompt, int timeout, int flags,
    struct sudo_conv_callback *callback)
{
    struct sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
    struct sigaction savetstp, savettin, savettou;
    char *pass;
    static const char *askpass;
    static char buf[SUDO_CONV_REPL_MAX + 1];
    int i, input, output, save_errno, neednl = 0, need_restart;
    debug_decl(tgetpass, SUDO_DEBUG_CONV)

    (void) fflush(stdout);

    if (askpass == NULL) {
	askpass = getenv_unhooked("SUDO_ASKPASS");
	if (askpass == NULL || *askpass == '\0')
	    askpass = sudo_conf_askpass_path();
    }

    /* If no tty present and we need to disable echo, try askpass. */
    if (!ISSET(flags, TGP_STDIN|TGP_ECHO|TGP_ASKPASS|TGP_NOECHO_TRY) &&
	!tty_present()) {
	if (askpass == NULL || getenv_unhooked("DISPLAY") == NULL) {
	    sudo_warnx(U_("no tty present and no askpass program specified"));
	    debug_return_str(NULL);
	}
	SET(flags, TGP_ASKPASS);
    }

    /* If using a helper program to get the password, run it instead. */
    if (ISSET(flags, TGP_ASKPASS)) {
	if (askpass == NULL || *askpass == '\0')
	    sudo_fatalx(U_("no askpass program specified, try setting SUDO_ASKPASS"));
	debug_return_str_masked(sudo_askpass(askpass, prompt));
    }

restart:
    for (i = 0; i < NSIG; i++)
	signo[i] = 0;
    pass = NULL;
    save_errno = 0;
    need_restart = 0;
    /* Open /dev/tty for reading/writing if possible else use stdin/stderr. */
    if (ISSET(flags, TGP_STDIN) ||
	(input = output = open(_PATH_TTY, O_RDWR)) == -1) {
	input = STDIN_FILENO;
	output = STDERR_FILENO;
    }

    /*
     * If we are using a tty but are not the foreground pgrp this will
     * return EINTR.  We send ourself SIGTTOU bracketed by callbacks.
     */
    if (!ISSET(flags, TGP_ECHO)) {
	for (;;) {
	    if (ISSET(flags, TGP_MASK))
		neednl = sudo_term_cbreak(input);
	    else
		neednl = sudo_term_noecho(input);
	    if (neednl || errno != EINTR)
		break;
	    /* Received SIGTTOU, suspend the process. */
	    if (suspend(SIGTTOU, callback) == -1) {
		if (input != STDIN_FILENO)
		    (void) close(input);
		debug_return_ptr(NULL);
	    }
	}
    }

    /*
     * Catch signals that would otherwise cause the user to end
     * up with echo turned off in the shell.
     */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;	/* don't restart system calls */
    sa.sa_handler = tgetpass_handler;
    (void) sigaction(SIGALRM, &sa, &savealrm);
    (void) sigaction(SIGINT, &sa, &saveint);
    (void) sigaction(SIGHUP, &sa, &savehup);
    (void) sigaction(SIGQUIT, &sa, &savequit);
    (void) sigaction(SIGTERM, &sa, &saveterm);
    (void) sigaction(SIGTSTP, &sa, &savetstp);
    (void) sigaction(SIGTTIN, &sa, &savettin);
    (void) sigaction(SIGTTOU, &sa, &savettou);

    if (prompt) {
	if (write(output, prompt, strlen(prompt)) == -1)
	    goto restore;
    }

    if (timeout > 0)
	alarm(timeout);
    pass = getln(input, buf, sizeof(buf), ISSET(flags, TGP_MASK));
    alarm(0);
    save_errno = errno;

    if (neednl || pass == NULL) {
	if (write(output, "\n", 1) == -1)
	    goto restore;
    }

restore:
    /* Restore old signal handlers. */
    (void) sigaction(SIGALRM, &savealrm, NULL);
    (void) sigaction(SIGINT, &saveint, NULL);
    (void) sigaction(SIGHUP, &savehup, NULL);
    (void) sigaction(SIGQUIT, &savequit, NULL);
    (void) sigaction(SIGTERM, &saveterm, NULL);
    (void) sigaction(SIGTSTP, &savetstp, NULL);
    (void) sigaction(SIGTTIN, &savettin, NULL);
    (void) sigaction(SIGTTOU, &savettou, NULL);

    /* Restore old tty settings. */
    if (!ISSET(flags, TGP_ECHO)) {
	/* Restore old tty settings if possible. */
	(void) sudo_term_restore(input, true);
    }
    if (input != STDIN_FILENO)
	(void) close(input);

    /*
     * If we were interrupted by a signal, resend it to ourselves
     * now that we have restored the signal handlers.
     */
    for (i = 0; i < NSIG; i++) {
	if (signo[i]) {
	    switch (i) {
		case SIGTSTP:
		case SIGTTIN:
		case SIGTTOU:
		    if (suspend(i, callback) == 0)
			need_restart = 1;
		    break;
		default:
		    kill(getpid(), i);
		    break;
	    }
	}
    }
    if (need_restart)
	goto restart;

    if (save_errno)
	errno = save_errno;

    debug_return_str_masked(pass);
}

/*
 * Fork a child and exec sudo-askpass to get the password from the user.
 */
static char *
sudo_askpass(const char *askpass, const char *prompt)
{
    static char buf[SUDO_CONV_REPL_MAX + 1], *pass;
    struct sigaction sa, savechld;
    int pfd[2], status;
    pid_t child;
    debug_decl(sudo_askpass, SUDO_DEBUG_CONV)

    /* Set SIGCHLD handler to default since we call waitpid() below. */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_DFL;
    (void) sigaction(SIGCHLD, &sa, &savechld);

    if (pipe(pfd) == -1)
	sudo_fatal(U_("unable to create pipe"));

    child = sudo_debug_fork();
    if (child == -1)
	sudo_fatal(U_("unable to fork"));

    if (child == 0) {
	/* child, point stdout to output side of the pipe and exec askpass */
	if (dup2(pfd[1], STDOUT_FILENO) == -1) {
	    sudo_warn("dup2");
	    _exit(255);
	}
	if (setuid(ROOT_UID) == -1)
	    sudo_warn("setuid(%d)", ROOT_UID);
	if (setgid(user_details.gid)) {
	    sudo_warn(U_("unable to set gid to %u"), (unsigned int)user_details.gid);
	    _exit(255);
	}
	if (setuid(user_details.uid)) {
	    sudo_warn(U_("unable to set uid to %u"), (unsigned int)user_details.uid);
	    _exit(255);
	}
	closefrom(STDERR_FILENO + 1);
	execl(askpass, askpass, prompt, (char *)NULL);
	sudo_warn(U_("unable to run %s"), askpass);
	_exit(255);
    }

    /* Get response from child (askpass). */
    (void) close(pfd[1]);
    pass = getln(pfd[0], buf, sizeof(buf), 0);
    (void) close(pfd[0]);

    /* Wait for child to exit. */
    for (;;) {
	pid_t rv = waitpid(child, &status, 0);
	if (rv == -1 && errno != EINTR)
	    break;
	if (rv != -1 && !WIFSTOPPED(status))
	    break;
    }

    if (pass == NULL)
	errno = EINTR;	/* make cancel button simulate ^C */

    /* Restore saved SIGCHLD handler. */
    (void) sigaction(SIGCHLD, &savechld, NULL);

    debug_return_str_masked(pass);
}

extern int sudo_term_erase, sudo_term_kill;

static char *
getln(int fd, char *buf, size_t bufsiz, int feedback)
{
    size_t left = bufsiz;
    ssize_t nr = -1;
    char *cp = buf;
    char c = '\0';
    debug_decl(getln, SUDO_DEBUG_CONV)

    if (left == 0) {
	errno = EINVAL;
	debug_return_str(NULL);		/* sanity */
    }

    while (--left) {
	nr = read(fd, &c, 1);
	if (nr != 1 || c == '\n' || c == '\r')
	    break;
	if (feedback) {
	    if (c == sudo_term_kill) {
		while (cp > buf) {
		    if (write(fd, "\b \b", 3) == -1)
			break;
		    --cp;
		}
		left = bufsiz;
		continue;
	    } else if (c == sudo_term_erase) {
		if (cp > buf) {
		    if (write(fd, "\b \b", 3) == -1)
			break;
		    --cp;
		    left++;
		}
		continue;
	    }
	    ignore_result(write(fd, "*", 1));
	}
	*cp++ = c;
    }
    *cp = '\0';
    if (feedback) {
	/* erase stars */
	while (cp > buf) {
	    if (write(fd, "\b \b", 3) == -1)
		break;
	    --cp;
	}
    }

    debug_return_str_masked(nr == 1 ? buf : NULL);
}

static void
tgetpass_handler(int s)
{
    if (s != SIGALRM)
	signo[s] = 1;
}

static bool
tty_present(void)
{
#if defined(HAVE_KINFO_PROC2_NETBSD) || defined(HAVE_KINFO_PROC_OPENBSD) || defined(HAVE_KINFO_PROC_FREEBSD) || defined(HAVE_KINFO_PROC_44BSD) || defined(HAVE_STRUCT_PSINFO_PR_TTYDEV) || defined(HAVE_PSTAT_GETPROC) || defined(__linux__)
    debug_decl(tty_present, SUDO_DEBUG_UTIL)
    debug_return_bool(user_details.tty != NULL);
#else
    int fd;
    debug_decl(tty_present, SUDO_DEBUG_UTIL)

    if ((fd = open(_PATH_TTY, O_RDWR)) != -1)
	close(fd);
    debug_return_bool(fd != -1);
#endif
}
