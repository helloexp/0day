/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2016 The ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* Logging, either to syslog or stderr, as well as debug logging
 * and debug levels.
 */

#ifndef PR_LOG_H
#define PR_LOG_H

#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV LOG_AUTH
#endif

#if !defined(WTMP_FILE) && defined(_PATH_WTMP)
#define WTMP_FILE _PATH_WTMP
#endif

/* These are the debug levels, higher numbers print more debugging
 * info.  DEBUG0 (the default) prints nothing.
 */

#define DEBUG10		10
#define DEBUG9		9
#define DEBUG8		8
#define DEBUG7		7
#define DEBUG6		6
#define DEBUG5		5
#define DEBUG4		4
#define	DEBUG3		3
#define DEBUG2		2
#define DEBUG1		1
#define DEBUG0		0

/* pr_log_openfile() return values */
#define PR_LOG_WRITABLE_DIR	-2
#define PR_LOG_SYMLINK		-3

/* Log file modes */
#define PR_LOG_SYSTEM_MODE	0640

#ifdef PR_USE_LASTLOG

/* It is tempting to want to have these lastlog-related includes separated
 * out into their own lastlog.h file.  However, on some systems, such a
 * proftpd-specific lastlog.h file may collide with the system's lastlog.h
 * file.  Ultimately it's an issue with the default search order of the
 * system C preprocessor, not with us -- and not every installation has
 * this problem.
 *
 * In the meantime, the most portable thing is to keep these lastlog-related
 * includes in this file.  Yay portability.
 */

#ifdef HAVE_LASTLOG_H
# include <lastlog.h>
#endif

#ifdef HAVE_LOGIN_H
# include <login.h>
#endif

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif

#ifndef PR_LASTLOG_PATH
# ifdef _PATH_LASTLOG
#   define PR_LASTLOG_PATH      _PATH_LASTLOG
# else
#   ifdef LASTLOG_FILE
#     define PR_LASTLOG_PATH    LASTLOG_FILE
#   else
#     error "Missing path to lastlog file (use --with-lastlog=PATH)"
#   endif
# endif
#endif


int log_lastlog(uid_t uid, const char *user_name, const char *tty,
  const pr_netaddr_t *remote_addr);
#endif /* PR_USE_LASTLOG */

/* Note: Like lastlog.h, it would be tempting to split out the declaration of
 * this function, and its necessary system headers, into a proftpd-specific
 * wtmp.h file.  But that would collide with the system wtmp.h file on
 * some systems.
 */
int log_wtmp(const char *, const char *, const char *, const pr_netaddr_t *);

/* file-based logging functions */
int pr_log_openfile(const char *, int *, mode_t);

int pr_log_writefile(int, const char *, const char *, ...)
#ifdef __GNUC__
  __attribute__ ((format (printf, 3, 4)));
#else
  ;
#endif

/* Same as pr_log_writefile(), only this function takes a va_list.
 * Useful for modules which provide their own varargs wrapper log functions,
 * but still want to use the core facilities for writing to the log fd.
 */
int pr_log_vwritefile(int, const char *, const char *, va_list ap);

/* syslog-based logging functions.  Note that the open/close functions are
 * not part of the public API; use the pr_log_pri() function to log via
 * syslog.
 */
void log_closesyslog(void);
int log_opensyslog(const char *);
int log_getfacility(void);
void log_setfacility(int);

void pr_log_pri(int, const char *, ...)
#ifdef __GNUC__
       __attribute__ ((format (printf, 2, 3)));
#else
       ;
#endif

void pr_log_auth(int, const char *, ...)
#ifdef __GNUC__
       __attribute__ ((format (printf, 2, 3)));
#else
       ;
#endif

void pr_log_debug(int, const char *, ...)
#ifdef __GNUC__
       __attribute__ ((format (printf, 2, 3)));
#else
       ;
#endif

int pr_log_setdebuglevel(int);
int pr_log_setdefaultlevel(int);

void log_stderr(int);
void log_discard(void);
void init_log(void);

int pr_log_str2sysloglevel(const char *);

/* Define a struct, and some constants, for logging events and any listeners
 * for those events.
 */
typedef struct log_event {

  /* Type of log event/message; the values are defined below */
  unsigned int log_type;

  /* Log fd associated with this log for this event */
  int log_fd;

  /* Log level of this message; the semantics of the log level depend on
   * on the log type.
   */
  int log_level;

  /* The message being logged. */
  const char *log_msg;
  size_t log_msglen;

} pr_log_event_t;

#define PR_LOG_TYPE_UNSPEC	0
#define PR_LOG_NAME_UNSPEC	"core.log.unspec"

#define PR_LOG_TYPE_XFERLOG	1
#define PR_LOG_NAME_XFERLOG	"core.log.xferlog"

#define PR_LOG_TYPE_SYSLOG	2
#define PR_LOG_NAME_SYSLOG	"core.log.syslog"

#define PR_LOG_TYPE_SYSTEMLOG	3
#define PR_LOG_NAME_SYSTEMLOG	"core.log.systemlog"

#define PR_LOG_TYPE_EXTLOG	4
#define PR_LOG_NAME_EXTLOG	"core.log.extendedlog"

#define PR_LOG_TYPE_TRACELOG	5
#define PR_LOG_NAME_TRACELOG	"core.log.tracelog"

/* Helper function to generate the necessary log event, passing along the
 * log event context data.
 */
int pr_log_event_generate(unsigned int log_type, int log_fd, int log_level,
  const char *log_msg, size_t log_msglen);

/* Returns TRUE if there are listeners for the specified log type, FALSE
 * otherwise.
 */
int pr_log_event_listening(unsigned int log_type);

/* Log a stacktrace, starting at the location of the calling function.
 * Note that if fd is less than zero, OR if the given name is null, then the
 * stacktrace will be logged using pr_log_pri(), otherwise the stacktrace will
 * be written to the provided file descriptor.
 */
void pr_log_stacktrace(int fd, const char *name);

#endif /* PR_LOG_H */
