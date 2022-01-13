/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1999-2005, 2009-2018
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
 */

#ifndef SUDOERS_LOGGING_H
#define SUDOERS_LOGGING_H

#ifdef __STDC__
# include <stdarg.h>
#else
# include <varargs.h>
#endif

/*
 * Values for sudoers_setlocale()
 */
#define SUDOERS_LOCALE_USER     0
#define SUDOERS_LOCALE_SUDOERS  1

/* Logging types */
#define SLOG_SYSLOG		0x01
#define SLOG_FILE		0x02
#define SLOG_BOTH		0x03

/* Flags for log_warning()/log_warningx() */
#define SLOG_USE_ERRNO		0x01	/* internal use only */
#define SLOG_GAI_ERRNO		0x02	/* internal use only */
#define SLOG_RAW_MSG		0x04	/* do not format msg before logging */
#define SLOG_SEND_MAIL		0x08	/* log via mail */
#define SLOG_NO_STDERR		0x10	/* do not log via stderr */
#define SLOG_NO_LOG		0x20	/* do not log via file or syslog */

/*
 * Maximum number of characters to log per entry.  The syslogger
 * will log this much, after that, it truncates the log line.
 * We need this here to make sure that we continue with another
 * syslog(3) call if the internal buffer is more than 1023 characters.
 */
#ifndef MAXSYSLOGLEN
# define MAXSYSLOGLEN		960
#endif

/*
 * Indentation level for file-based logs when word wrap is enabled.
 */
#define LOG_INDENT	"    "

/* XXX - needed for auditing */
extern int NewArgc;
extern char **NewArgv;

union sudo_defs_val;

bool sudoers_warn_setlocale(bool restore, int *cookie);
bool sudoers_setlocale(int newlocale, int *prevlocale);
int sudoers_getlocale(void);
int audit_success(int argc, char *argv[]);
int audit_failure(int argc, char *argv[], char const *const fmt, ...) __printflike(3, 4);
bool log_allowed(int status);
bool log_auth_failure(int status, unsigned int tries);
bool log_denial(int status, bool inform_user);
bool log_failure(int status, int flags);
bool log_warning(int flags, const char *fmt, ...) __printflike(2, 3);
bool log_warningx(int flags, const char *fmt, ...) __printflike(2, 3);
bool gai_log_warning(int flags, int errnum, const char *fmt, ...) __printflike(3, 4);
bool sudoers_initlocale(const char *ulocale, const char *slocale);
bool sudoers_locale_callback(const union sudo_defs_val *);
int writeln_wrap(FILE *fp, char *line, size_t len, size_t maxlen);

#endif /* SUDOERS_LOGGING_H */
