/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1994-1996, 1998-2019 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#ifdef __TANDEM
# include <floss.h>
#endif

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
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
#ifdef HAVE_NL_LANGINFO
# include <langinfo.h>
#endif /* HAVE_NL_LANGINFO */
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>

#include "sudoers.h"

#ifndef HAVE_GETADDRINFO
# include "compat/getaddrinfo.h"
#endif

/* Special message for log_warning() so we know to use ngettext() */
#define INCORRECT_PASSWORD_ATTEMPT	((char *)0x01)

static void do_syslog(int, char *);
static bool do_logfile(const char *);
static bool send_mail(const char *fmt, ...);
static bool should_mail(int);
static void mysyslog(int, const char *, ...);
static char *new_logline(const char *, const char *);

#define MAXSYSLOGTRIES	16	/* num of retries for broken syslogs */

/*
 * We do an openlog(3)/closelog(3) for each message because some
 * authentication methods (notably PAM) use syslog(3) for their
 * own nefarious purposes and may call openlog(3) and closelog(3).
 */
static void
mysyslog(int pri, const char *fmt, ...)
{
    const int flags = def_syslog_pid ? LOG_PID : 0;
    va_list ap;
    debug_decl(mysyslog, SUDOERS_DEBUG_LOGGING)

    openlog("sudo", flags, def_syslog);
    va_start(ap, fmt);
    vsyslog(pri, fmt, ap);
    va_end(ap);
    closelog();
    debug_return;
}

/*
 * Log a message to syslog, pre-pending the username and splitting the
 * message into parts if it is longer than syslog_maxlen.
 */
static void
do_syslog(int pri, char *msg)
{
    size_t len, maxlen;
    char *p, *tmp, save;
    const char *fmt;
    int oldlocale;
    debug_decl(do_syslog, SUDOERS_DEBUG_LOGGING)

    /* A priority of -1 corresponds to "none". */
    if (pri == -1)
	debug_return;

    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

    /*
     * Log the full line, breaking into multiple syslog(3) calls if necessary
     */
    fmt = _("%8s : %s");
    maxlen = def_syslog_maxlen - (strlen(fmt) - 5 + strlen(user_name));
    for (p = msg; *p != '\0'; ) {
	len = strlen(p);
	if (len > maxlen) {
	    /*
	     * Break up the line into what will fit on one syslog(3) line
	     * Try to avoid breaking words into several lines if possible.
	     */
	    tmp = memrchr(p, ' ', maxlen);
	    if (tmp == NULL)
		tmp = p + maxlen;

	    /* NULL terminate line, but save the char to restore later */
	    save = *tmp;
	    *tmp = '\0';

	    mysyslog(pri, fmt, user_name, p);

	    *tmp = save;			/* restore saved character */

	    /* Advance p and eliminate leading whitespace */
	    for (p = tmp; *p == ' '; p++)
		continue;
	} else {
	    mysyslog(pri, fmt, user_name, p);
	    p += len;
	}
	fmt = _("%8s : (command continued) %s");
	maxlen = def_syslog_maxlen - (strlen(fmt) - 5 + strlen(user_name));
    }

    sudoers_setlocale(oldlocale, NULL);

    debug_return;
}

static bool
do_logfile(const char *msg)
{
    static bool warned = false;
    const char *timestr;
    int len, oldlocale;
    bool ret = false;
    char *full_line;
    mode_t oldmask;
    FILE *fp;
    debug_decl(do_logfile, SUDOERS_DEBUG_LOGGING)

    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

    oldmask = umask(S_IRWXG|S_IRWXO);
    fp = fopen(def_logfile, "a");
    (void) umask(oldmask);
    if (fp == NULL) {
	if (!warned) {
	    log_warning(SLOG_SEND_MAIL|SLOG_NO_LOG,
		N_("unable to open log file: %s"), def_logfile);
	    warned = true;
	}
	goto done;
    }
    if (!sudo_lock_file(fileno(fp), SUDO_LOCK)) {
	if (!warned) {
	    log_warning(SLOG_SEND_MAIL|SLOG_NO_LOG,
		N_("unable to lock log file: %s"), def_logfile);
	    warned = true;
	}
	goto done;
    }

    timestr = get_timestr(time(NULL), def_log_year);
    if (timestr == NULL)
	timestr = "invalid date";
    if (def_log_host) {
	len = asprintf(&full_line, "%s : %s : HOST=%s : %s",
	    timestr, user_name, user_srunhost, msg);
    } else {
	len = asprintf(&full_line, "%s : %s : %s",
	    timestr, user_name, msg);
    }
    if (len == -1) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto done;
    }
    if ((size_t)def_loglinelen < sizeof(LOG_INDENT)) {
	/* Don't pretty-print long log file lines (hard to grep). */
	(void) fputs(full_line, fp);
	(void) fputc('\n', fp);
    } else {
	/* Write line with word wrap around def_loglinelen chars. */
	writeln_wrap(fp, full_line, len, def_loglinelen);
    }
    free(full_line);
    (void) fflush(fp);
    if (ferror(fp)) {
	if (!warned) {
	    log_warning(SLOG_SEND_MAIL|SLOG_NO_LOG,
		N_("unable to write log file: %s"), def_logfile);
	    warned = true;
	}
	goto done;
    }
    ret = true;

done:
    if (fp != NULL)
	(void) fclose(fp);
    sudoers_setlocale(oldlocale, NULL);

    debug_return_bool(ret);
}

/*
 * Log, audit and mail the denial message, optionally informing the user.
 */
bool
log_denial(int status, bool inform_user)
{
    const char *message;
    char *logline;
    int oldlocale;
    bool uid_changed, ret = true;
    bool mailit;
    debug_decl(log_denial, SUDOERS_DEBUG_LOGGING)

    /* Handle auditing first (audit_failure() handles the locale itself). */
    if (ISSET(status, FLAG_NO_USER | FLAG_NO_HOST))
	audit_failure(NewArgc, NewArgv, N_("No user or host"));
    else
	audit_failure(NewArgc, NewArgv, N_("validation failure"));

    /* Send mail based on status. */
    mailit = should_mail(status);

    if (def_log_denied || mailit) {
	/* Log and mail messages should be in the sudoers locale. */
	sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

	/* Set error message. */
	if (ISSET(status, FLAG_NO_USER))
	    message = _("user NOT in sudoers");
	else if (ISSET(status, FLAG_NO_HOST))
	    message = _("user NOT authorized on host");
	else
	    message = _("command not allowed");

	logline = new_logline(message, NULL);
	if (logline == NULL)
	    debug_return_bool(false);

	/* Become root if we are not already. */
	uid_changed = set_perms(PERM_ROOT);

	if (mailit)
	    send_mail("%s", logline);	/* XXX - return value */

	/* Log via syslog and/or a file. */
	if (def_log_denied) {
	    if (def_syslog)
		do_syslog(def_syslog_badpri, logline);
	    if (def_logfile && !do_logfile(logline))
		ret = false;
	}

	if (uid_changed) {
	    if (!restore_perms())
		ret = false;		/* XXX - return -1 instead? */
	}

	free(logline);

	/* Restore locale. */
	sudoers_setlocale(oldlocale, NULL);
    }

    /* Inform the user if they failed to authenticate (in their locale).  */
    if (inform_user) {
	sudoers_setlocale(SUDOERS_LOCALE_USER, &oldlocale);

	if (ISSET(status, FLAG_NO_USER)) {
	    sudo_printf(SUDO_CONV_ERROR_MSG, _("%s is not in the sudoers "
		"file.  This incident will be reported.\n"), user_name);
	} else if (ISSET(status, FLAG_NO_HOST)) {
	    sudo_printf(SUDO_CONV_ERROR_MSG, _("%s is not allowed to run sudo "
		"on %s.  This incident will be reported.\n"),
		user_name, user_srunhost);
	} else if (ISSET(status, FLAG_NO_CHECK)) {
	    sudo_printf(SUDO_CONV_ERROR_MSG, _("Sorry, user %s may not run "
		"sudo on %s.\n"), user_name, user_srunhost);
	} else {
	    sudo_printf(SUDO_CONV_ERROR_MSG, _("Sorry, user %s is not allowed "
		"to execute '%s%s%s' as %s%s%s on %s.\n"),
		user_name, user_cmnd, user_args ? " " : "",
		user_args ? user_args : "",
		list_pw ? list_pw->pw_name : runas_pw ?
		runas_pw->pw_name : user_name, runas_gr ? ":" : "",
		runas_gr ? runas_gr->gr_name : "", user_host);
	}
	sudoers_setlocale(oldlocale, NULL);
    }
    debug_return_bool(ret);
}

/*
 * Log and audit that user was not allowed to run the command.
 */
bool
log_failure(int status, int flags)
{
    bool ret, inform_user = true;
    debug_decl(log_failure, SUDOERS_DEBUG_LOGGING)

    /* The user doesn't always get to see the log message (path info). */
    if (!ISSET(status, FLAG_NO_USER | FLAG_NO_HOST) && def_path_info &&
	(flags == NOT_FOUND_DOT || flags == NOT_FOUND))
	inform_user = false;
    ret = log_denial(status, inform_user);

    if (!inform_user) {
	/*
	 * We'd like to not leak path info at all here, but that can
	 * *really* confuse the users.  To really close the leak we'd
	 * have to say "not allowed to run foo" even when the problem
	 * is just "no foo in path" since the user can trivially set
	 * their path to just contain a single dir.
	 */
	if (flags == NOT_FOUND)
	    sudo_warnx(U_("%s: command not found"), user_cmnd);
	else if (flags == NOT_FOUND_DOT)
	    sudo_warnx(U_("ignoring \"%s\" found in '.'\nUse \"sudo ./%s\" if this is the \"%s\" you wish to run."), user_cmnd, user_cmnd, user_cmnd);
    }

    debug_return_bool(ret);
}

/*
 * Log and audit that user was not able to authenticate themselves.
 */
bool
log_auth_failure(int status, unsigned int tries)
{
    int flags = 0;
    bool ret = true;
    debug_decl(log_auth_failure, SUDOERS_DEBUG_LOGGING)

    /* Handle auditing first. */
    audit_failure(NewArgc, NewArgv, N_("authentication failure"));

    /*
     * Do we need to send mail?
     * We want to avoid sending multiple messages for the same command
     * so if we are going to send an email about the denial, that takes
     * precedence.
     */
    if (ISSET(status, VALIDATE_SUCCESS)) {
	/* Command allowed, auth failed; do we need to send mail? */
	if (def_mail_badpass || def_mail_always)
	    SET(flags, SLOG_SEND_MAIL);
    } else {
	/* Command denied, auth failed; make sure we don't send mail twice. */
	if (def_mail_badpass && !should_mail(status))
	    SET(flags, SLOG_SEND_MAIL);
	/* Don't log the bad password message, we'll log a denial instead. */
	SET(flags, SLOG_NO_LOG);
    }

    /*
     * If sudoers denied the command we'll log that separately.
     */
    if (ISSET(status, FLAG_BAD_PASSWORD))
	ret = log_warningx(flags, INCORRECT_PASSWORD_ATTEMPT, tries);
    else if (ISSET(status, FLAG_NON_INTERACTIVE))
	ret = log_warningx(flags, N_("a password is required"));

    debug_return_bool(ret);
}

/*
 * Log and potentially mail the allowed command.
 */
bool
log_allowed(int status)
{
    char *logline;
    int oldlocale;
    bool uid_changed, ret = true;
    bool mailit;
    debug_decl(log_allowed, SUDOERS_DEBUG_LOGGING)

    /* Send mail based on status. */
    mailit = should_mail(status);

    if (def_log_allowed || mailit) {
	/* Log and mail messages should be in the sudoers locale. */
	sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

	if ((logline = new_logline(NULL, NULL)) == NULL)
	    debug_return_bool(false);

	/* Become root if we are not already. */
	uid_changed = set_perms(PERM_ROOT);

	if (mailit)
	    send_mail("%s", logline);	/* XXX - return value */

	/*
	 * Log via syslog and/or a file.
	 */
	if (def_log_allowed) {
	    if (def_syslog)
		do_syslog(def_syslog_goodpri, logline);
	    if (def_logfile && !do_logfile(logline))
		ret = false;
	}

	if (uid_changed) {
	    if (!restore_perms())
		ret = false;		/* XXX - return -1 instead? */
	}

	free(logline);

	sudoers_setlocale(oldlocale, NULL);
    }

    debug_return_bool(ret);
}

/*
 * Format an authentication failure message, using either
 * authfail_message from sudoers or a locale-specific message.
 */
static int
fmt_authfail_message(char **str, va_list ap)
{
    unsigned int tries = va_arg(ap, unsigned int);
    char *src, *dst0, *dst, *dst_end;
    size_t size;
    int len;
    debug_decl(fmt_authfail_message, SUDOERS_DEBUG_LOGGING)

    if (def_authfail_message == NULL) {
	debug_return_int(asprintf(str, ngettext("%u incorrect password attempt",
	    "%u incorrect password attempts", tries), tries));
    }

    src = def_authfail_message;
    size = strlen(src) + 33;
    if ((dst0 = dst = malloc(size)) == NULL)
	debug_return_int(-1);
    dst_end = dst + size;

    /* Always leave space for the terminating NUL. */
    while (*src != '\0' && dst + 1 < dst_end) {
	if (src[0] == '%') {
	    switch (src[1]) {
	    case '%':
		src++;
		break;
	    case 'd':
		len = snprintf(dst, dst_end - dst, "%u", tries);
		if (len < 0 || len >= (int)(dst_end - dst))
		    goto done;
		dst += len;
		src += 2;
		continue;
	    default:
		break;
	    }
	}
	*dst++ = *src++;
    }
done:
    *dst = '\0';

    *str = dst0;
#ifdef __clang_analyzer__
    /* clang analyzer false positive */
    if (__builtin_expect(dst < dst0, 0))
	__builtin_trap();
#endif
    debug_return_int(dst - dst0);
}

/*
 * Perform logging for log_warning()/log_warningx().
 */
static bool
vlog_warning(int flags, int errnum, const char *fmt, va_list ap)
{
    int oldlocale;
    const char *errstr = NULL;
    char *logline, *message;
    bool uid_changed, ret = true;
    va_list ap2;
    int len;
    debug_decl(vlog_warning, SUDOERS_DEBUG_LOGGING)

    /* Need extra copy of ap for sudo_vwarn()/sudo_vwarnx() below. */
    va_copy(ap2, ap);

    /* Log messages should be in the sudoers locale. */
    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

    /* Expand printf-style format + args (with a special case). */
    if (fmt == INCORRECT_PASSWORD_ATTEMPT) {
	len = fmt_authfail_message(&message, ap);
    } else {
	len = vasprintf(&message, _(fmt), ap);
    }
    if (len == -1) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	ret = false;
	goto done;
    }

    if (ISSET(flags, SLOG_USE_ERRNO))
	errstr = strerror(errnum);
    else if (ISSET(flags, SLOG_GAI_ERRNO))
	errstr = gai_strerror(errnum);

    /* Log to debug file. */
    if (errstr != NULL) {
	sudo_debug_printf2(NULL, NULL, 0,
	    SUDO_DEBUG_WARN|sudo_debug_subsys, "%s: %s", message, errstr);
    } else {
	sudo_debug_printf2(NULL, NULL, 0,
	    SUDO_DEBUG_WARN|sudo_debug_subsys, "%s", message);
    }

    if (ISSET(flags, SLOG_RAW_MSG)) {
	logline = message;
    } else {
	logline = new_logline(message, errstr);
        free(message);
	if (logline == NULL) {
	    ret = false;
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto done;
	}
    }

    /* Become root if we are not already. */
    uid_changed = set_perms(PERM_ROOT);

    /*
     * Send a copy of the error via mail.
     * XXX - return value
     */
    if (ISSET(flags, SLOG_SEND_MAIL))
	send_mail("%s", logline);

    /*
     * Log to syslog and/or a file.
     */
    if (!ISSET(flags, SLOG_NO_LOG)) {
	if (def_syslog)
	    do_syslog(def_syslog_badpri, logline);
	if (def_logfile && !do_logfile(logline))
	    ret = false;
    }

    if (uid_changed) {
	if (!restore_perms())
	    ret = false;
    }

    free(logline);

    /*
     * Tell the user (in their locale).
     */
    if (!ISSET(flags, SLOG_NO_STDERR)) {
	sudoers_setlocale(SUDOERS_LOCALE_USER, NULL);
	if (fmt == INCORRECT_PASSWORD_ATTEMPT) {
	    len = fmt_authfail_message(&message, ap2);
	    if (len == -1) {
		sudo_warnx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
		ret = false;
		goto done;
	    }
	    sudo_warnx_nodebug("%s", message);
	    free(message);
	} else {
	    if (ISSET(flags, SLOG_USE_ERRNO)) {
		errno = errnum;
		sudo_vwarn_nodebug(_(fmt), ap2);
	    } else if (ISSET(flags, SLOG_GAI_ERRNO)) {
		sudo_gai_vwarn_nodebug(errnum, _(fmt), ap2);
	    } else
		sudo_vwarnx_nodebug(_(fmt), ap2);
	}
    }

done:
    va_end(ap2);
    sudoers_setlocale(oldlocale, NULL);

    debug_return_bool(ret);
}

bool
log_warning(int flags, const char *fmt, ...)
{
    va_list ap;
    bool ret;
    debug_decl(log_warning, SUDOERS_DEBUG_LOGGING)

    /* Log the error. */
    va_start(ap, fmt);
    ret = vlog_warning(flags|SLOG_USE_ERRNO, errno, fmt, ap);
    va_end(ap);

    debug_return_bool(ret);
}

bool
log_warningx(int flags, const char *fmt, ...)
{
    va_list ap;
    bool ret;
    debug_decl(log_warningx, SUDOERS_DEBUG_LOGGING)

    /* Log the error. */
    va_start(ap, fmt);
    ret = vlog_warning(flags, 0, fmt, ap);
    va_end(ap);

    debug_return_bool(ret);
}

bool
gai_log_warning(int flags, int errnum, const char *fmt, ...)
{
    va_list ap;
    bool ret;
    debug_decl(gai_log_warning, SUDOERS_DEBUG_LOGGING)

    /* Log the error. */
    va_start(ap, fmt);
    ret = vlog_warning(flags|SLOG_GAI_ERRNO, errnum, fmt, ap);
    va_end(ap);

    debug_return_bool(ret);
}

static void
closefrom_nodebug(int lowfd)
{
    unsigned char *debug_fds;
    int fd, startfd;
    debug_decl(closefrom_nodebug, SUDOERS_DEBUG_LOGGING)

    startfd = sudo_debug_get_fds(&debug_fds) + 1;
    if (lowfd > startfd)
	startfd = lowfd;

    /* Close fds higher than the debug fds. */
    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"closing fds >= %d", startfd);
    closefrom(startfd);

    /* Close fds [lowfd, startfd) that are not in debug_fds. */
    for (fd = lowfd; fd < startfd; fd++) {
	if (sudo_isset(debug_fds, fd))
	    continue;
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	    "closing fd %d", fd);
#ifdef __APPLE__
	/* Avoid potential libdispatch crash when we close its fds. */
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
#else
	(void) close(fd);
#endif
    }
    debug_return;
}

#define MAX_MAILFLAGS	63

static void __attribute__((__noreturn__))
exec_mailer(int pipein)
{
    char *last, *p, *argv[MAX_MAILFLAGS + 1];
    char *mflags, *mpath = def_mailerpath;
    int i;
#ifdef NO_ROOT_MAILER
    int perm = PERM_FULL_USER;
#else
    int perm = PERM_ROOT;
    static char *envp[] = {
	"HOME=/",
	"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
	"LOGNAME=root",
	"USER=root",
# ifdef _AIX
	"LOGIN=root",
# endif
	NULL
    };
#endif /* NO_ROOT_MAILER */
    debug_decl(exec_mailer, SUDOERS_DEBUG_LOGGING)

    /* Set stdin to read side of the pipe or clear FD_CLOEXEC */
    if (pipein == STDIN_FILENO)
	i = fcntl(pipein, F_SETFD, 0);
    else 
    	i = dup2(pipein, STDIN_FILENO);
    if (i == -1) {
	mysyslog(LOG_ERR, _("unable to dup stdin: %m"));
	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "unable to dup stdin: %s", strerror(errno));
	sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
	_exit(127);
    }

    /* Build up an argv based on the mailer path and flags */
    if ((mflags = strdup(def_mailerflags)) == NULL) {
	mysyslog(LOG_ERR, _("unable to allocate memory"));
	sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
	_exit(127);
    }
    if ((argv[0] = strrchr(mpath, '/')))
	argv[0]++;
    else
	argv[0] = mpath;

    i = 1;
    if ((p = strtok_r(mflags, " \t", &last))) {
	do {
	    argv[i] = p;
	} while (++i < MAX_MAILFLAGS && (p = strtok_r(NULL, " \t", &last)));
    }
    argv[i] = NULL;

    /*
     * Depending on the config, either run the mailer as root
     * (so user cannot kill it) or as the user (for the paranoid).
     */
    (void) set_perms(perm);
    sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
#ifdef NO_ROOT_MAILER
    execv(mpath, argv);
#else
    execve(mpath, argv, envp);
#endif
    mysyslog(LOG_ERR, _("unable to execute %s: %m"), mpath);
    sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to execute %s: %s",
	mpath, strerror(errno));
    _exit(127);
}

/*
 * Send a message to MAILTO user
 */
static bool
send_mail(const char *fmt, ...)
{
    FILE *mail;
    char *p;
    const char *timestr;
    int fd, pfd[2], status;
    pid_t pid, rv;
    struct stat sb;
    va_list ap;
    debug_decl(send_mail, SUDOERS_DEBUG_LOGGING)

    /* If mailer is disabled just return. */
    if (!def_mailerpath || !def_mailto)
	debug_return_bool(true);

    /* Make sure the mailer exists and is a regular file. */
    if (stat(def_mailerpath, &sb) != 0 || !S_ISREG(sb.st_mode))
	debug_return_bool(false);

    /* Fork and return, child will daemonize. */
    switch (pid = sudo_debug_fork()) {
	case -1:
	    /* Error. */
	    sudo_warn(U_("unable to fork"));
	    debug_return_bool(false);
	    break;
	case 0:
	    /* Child. */
	    switch (pid = fork()) {
		case -1:
		    /* Error. */
		    mysyslog(LOG_ERR, _("unable to fork: %m"));
		    sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to fork: %s",
			strerror(errno));
		    sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
		    _exit(1);
		case 0:
		    /* Grandchild continues below. */
		    sudo_debug_enter(__func__, __FILE__, __LINE__, sudo_debug_subsys);
		    break;
		default:
		    /* Parent will wait for us. */
		    _exit(0);
	    }
	    break;
	default:
	    /* Parent. */
	    for (;;) {
		rv = waitpid(pid, &status, 0);
		if (rv == -1 && errno != EINTR)
		    break;
		if (rv != -1 && !WIFSTOPPED(status))
		    break;
	    }
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"child (%d) exit value %d", (int)rv, status);
	    debug_return_bool(true);
    }

    /* Daemonize - disassociate from session/tty. */
    if (setsid() == -1)
      sudo_warn("setsid");
    if (chdir("/") == -1)
      sudo_warn("chdir(/)");
    fd = open(_PATH_DEVNULL, O_RDWR, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (fd != -1) {
	(void) dup2(fd, STDIN_FILENO);
	(void) dup2(fd, STDOUT_FILENO);
	(void) dup2(fd, STDERR_FILENO);
    }

    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, NULL);

    /* Close non-debug fds so we don't leak anything. */
    closefrom_nodebug(STDERR_FILENO + 1);

    if (pipe2(pfd, O_CLOEXEC) == -1) {
	mysyslog(LOG_ERR, _("unable to open pipe: %m"));
	sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to open pipe: %s",
	    strerror(errno));
	sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
	_exit(1);
    }

    switch (pid = sudo_debug_fork()) {
	case -1:
	    /* Error. */
	    mysyslog(LOG_ERR, _("unable to fork: %m"));
	    sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to fork: %s",
		strerror(errno));
	    sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
	    _exit(1);
	    break;
	case 0:
	    /* Child. */
	    exec_mailer(pfd[0]);
	    /* NOTREACHED */
    }

    (void) close(pfd[0]);
    mail = fdopen(pfd[1], "w");

    /* Pipes are all setup, send message. */
    (void) fprintf(mail, "To: %s\nFrom: %s\nAuto-Submitted: %s\nSubject: ",
	def_mailto, def_mailfrom ? def_mailfrom : user_name, "auto-generated");
    for (p = _(def_mailsub); *p; p++) {
	/* Expand escapes in the subject */
	if (*p == '%' && *(p+1) != '%') {
	    switch (*(++p)) {
		case 'h':
		    (void) fputs(user_host, mail);
		    break;
		case 'u':
		    (void) fputs(user_name, mail);
		    break;
		default:
		    p--;
		    break;
	    }
	} else
	    (void) fputc(*p, mail);
    }

#if defined(HAVE_NL_LANGINFO) && defined(CODESET)
    if (strcmp(def_sudoers_locale, "C") != 0)
	(void) fprintf(mail, "\nContent-Type: text/plain; charset=\"%s\"\nContent-Transfer-Encoding: 8bit", nl_langinfo(CODESET));
#endif /* HAVE_NL_LANGINFO && CODESET */

    if ((timestr = get_timestr(time(NULL), def_log_year)) == NULL)
	timestr = "invalid date";
    (void) fprintf(mail, "\n\n%s : %s : %s : ", user_host, timestr, user_name);
    va_start(ap, fmt);
    (void) vfprintf(mail, fmt, ap);
    va_end(ap);
    fputs("\n\n", mail);

    fclose(mail);
    for (;;) {
	rv = waitpid(pid, &status, 0);
	if (rv == -1 && errno != EINTR)
	    break;
	if (rv != -1 && !WIFSTOPPED(status))
	    break;
    }
    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"child (%d) exit value %d", (int)rv, status);
    sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
    _exit(0);
}

/*
 * Determine whether we should send mail based on "status" and defaults options.
 */
static bool
should_mail(int status)
{
    debug_decl(should_mail, SUDOERS_DEBUG_LOGGING)

    debug_return_bool(def_mail_always || ISSET(status, VALIDATE_ERROR) ||
	(def_mail_all_cmnds && ISSET(sudo_mode, (MODE_RUN|MODE_EDIT))) ||
	(def_mail_no_user && ISSET(status, FLAG_NO_USER)) ||
	(def_mail_no_host && ISSET(status, FLAG_NO_HOST)) ||
	(def_mail_no_perms && !ISSET(status, VALIDATE_SUCCESS)));
}

#define	LL_TTY_STR	"TTY="
#define	LL_CWD_STR	"PWD="		/* XXX - should be CWD= */
#define	LL_USER_STR	"USER="
#define	LL_GROUP_STR	"GROUP="
#define	LL_ENV_STR	"ENV="
#define	LL_CMND_STR	"COMMAND="
#define	LL_TSID_STR	"TSID="

#define IS_SESSID(s) ( \
    isalnum((unsigned char)(s)[0]) && isalnum((unsigned char)(s)[1]) && \
    (s)[2] == '/' && \
    isalnum((unsigned char)(s)[3]) && isalnum((unsigned char)(s)[4]) && \
    (s)[5] == '/' && \
    isalnum((unsigned char)(s)[6]) && isalnum((unsigned char)(s)[7]) && \
    (s)[8] == '\0')

/*
 * Allocate and fill in a new logline.
 */
static char *
new_logline(const char *message, const char *errstr)
{
    char *line = NULL, *evstr = NULL;
#ifndef SUDOERS_NO_SEQ
    char sessid[7];
#endif
    const char *tsid = NULL;
    size_t len = 0;
    debug_decl(new_logline, SUDOERS_DEBUG_LOGGING)

#ifndef SUDOERS_NO_SEQ
    /* A TSID may be a sudoers-style session ID or a free-form string. */
    if (sudo_user.iolog_file != NULL) {
	if (IS_SESSID(sudo_user.iolog_file)) {
	    sessid[0] = sudo_user.iolog_file[0];
	    sessid[1] = sudo_user.iolog_file[1];
	    sessid[2] = sudo_user.iolog_file[3];
	    sessid[3] = sudo_user.iolog_file[4];
	    sessid[4] = sudo_user.iolog_file[6];
	    sessid[5] = sudo_user.iolog_file[7];
	    sessid[6] = '\0';
	    tsid = sessid;
	} else {
	    tsid = sudo_user.iolog_file;
	}
    }
#endif

    /*
     * Compute line length
     */
    if (message != NULL)
	len += strlen(message) + 3;
    if (errstr != NULL)
	len += strlen(errstr) + 3;
    len += sizeof(LL_TTY_STR) + 2 + strlen(user_tty);
    len += sizeof(LL_CWD_STR) + 2 + strlen(user_cwd);
    if (runas_pw != NULL)
	len += sizeof(LL_USER_STR) + 2 + strlen(runas_pw->pw_name);
    if (runas_gr != NULL)
	len += sizeof(LL_GROUP_STR) + 2 + strlen(runas_gr->gr_name);
    if (tsid != NULL)
	len += sizeof(LL_TSID_STR) + 2 + strlen(tsid);
    if (sudo_user.env_vars != NULL) {
	size_t evlen = 0;
	char * const *ep;

	for (ep = sudo_user.env_vars; *ep != NULL; ep++)
	    evlen += strlen(*ep) + 1;
	if (evlen != 0) {
	    if ((evstr = malloc(evlen)) == NULL)
		goto oom;
	    evstr[0] = '\0';
	    for (ep = sudo_user.env_vars; *ep != NULL; ep++) {
		strlcat(evstr, *ep, evlen);
		strlcat(evstr, " ", evlen);	/* NOTE: last one will fail */
	    }
	    len += sizeof(LL_ENV_STR) + 2 + evlen;
	}
    }
    if (user_cmnd != NULL) {
	/* Note: we log "sudo -l command arg ..." as "list command arg ..." */
	len += sizeof(LL_CMND_STR) - 1 + strlen(user_cmnd);
	if (ISSET(sudo_mode, MODE_CHECK))
	    len += sizeof("list ") - 1;
	if (user_args != NULL)
	    len += strlen(user_args) + 1;
    }

    /*
     * Allocate and build up the line.
     */
    if ((line = malloc(++len)) == NULL)
	goto oom;
    line[0] = '\0';

    if (message != NULL) {
	if (strlcat(line, message, len) >= len ||
	    strlcat(line, errstr ? " : " : " ; ", len) >= len)
	    goto toobig;
    }
    if (errstr != NULL) {
	if (strlcat(line, errstr, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
    }
    if (strlcat(line, LL_TTY_STR, len) >= len ||
	strlcat(line, user_tty, len) >= len ||
	strlcat(line, " ; ", len) >= len)
	goto toobig;
    if (strlcat(line, LL_CWD_STR, len) >= len ||
	strlcat(line, user_cwd, len) >= len ||
	strlcat(line, " ; ", len) >= len)
	goto toobig;
    if (runas_pw != NULL) {
	if (strlcat(line, LL_USER_STR, len) >= len ||
	    strlcat(line, runas_pw->pw_name, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
    }
    if (runas_gr != NULL) {
	if (strlcat(line, LL_GROUP_STR, len) >= len ||
	    strlcat(line, runas_gr->gr_name, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
    }
    if (tsid != NULL) {
	if (strlcat(line, LL_TSID_STR, len) >= len ||
	    strlcat(line, tsid, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
    }
    if (evstr != NULL) {
	if (strlcat(line, LL_ENV_STR, len) >= len ||
	    strlcat(line, evstr, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
	free(evstr);
	evstr = NULL;
    }
    if (user_cmnd != NULL) {
	if (strlcat(line, LL_CMND_STR, len) >= len)
	    goto toobig;
	if (ISSET(sudo_mode, MODE_CHECK) && strlcat(line, "list ", len) >= len)
	    goto toobig;
	if (strlcat(line, user_cmnd, len) >= len)
	    goto toobig;
	if (user_args != NULL) {
	    if (strlcat(line, " ", len) >= len ||
		strlcat(line, user_args, len) >= len)
		goto toobig;
	}
    }

    debug_return_str(line);
oom:
    free(evstr);
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    debug_return_str(NULL);
toobig:
    free(evstr);
    free(line);
    sudo_warnx(U_("internal error, %s overflow"), __func__);
    debug_return_str(NULL);
}
