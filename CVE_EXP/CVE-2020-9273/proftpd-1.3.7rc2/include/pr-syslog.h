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

/* ProFTPD internal implementation of syslog(3) routines */

#include "conf.h"

#ifndef PR_SYSLOG_H
#define PR_SYSLOG_H 1

/* These are log levels used to determine at which level we should log to.
 */
#ifdef HAVE_SYSLOG

#define PR_LOG_EMERG     LOG_EMERG     /* system is unusable */
#define PR_LOG_ALERT     LOG_ALERT     /* action must be taken immediately */
#define PR_LOG_CRIT      LOG_CRIT      /* critical conditions */
#define PR_LOG_ERR       LOG_ERR       /* error conditions */
#define PR_LOG_WARNING   LOG_WARNING   /* warning conditions */
#define PR_LOG_NOTICE    LOG_NOTICE    /* normal but significant condition */
#define PR_LOG_INFO      LOG_INFO      /* informational */
#define PR_LOG_DEBUG     LOG_DEBUG     /* debug-level messages */

#define PR_LOG_PRIMASK LOG_PRIMASK   /* mask off the level value */

#else

#define PR_LOG_EMERG            0       /* system is unusable */
#define PR_LOG_ALERT            1       /* action must be taken immediately */
#define PR_LOG_CRIT             2       /* critical conditions */
#define PR_LOG_ERR              3       /* error conditions */
#define PR_LOG_WARNING          4       /* warning conditions */
#define PR_LOG_NOTICE           5       /* normal but significant condition */
#define PR_LOG_INFO             6       /* informational */
#define PR_LOG_DEBUG            7       /* debug-level messages */

#define PR_LOG_PRIMASK          7       /* mask off the level value */

#endif /* HAVE_SYSLOG */

#ifdef _PATH_LOG
# define PR_PATH_LOG	_PATH_LOG
#elif defined(__hpux)
# define PR_PATH_LOG	"/dev/log.un"
#else
# if defined(SOLARIS2)
#  define PR_PATH_LOG	"/dev/conslog"
# else
#  define PR_PATH_LOG	"/dev/log"
# endif /* !Solaris */
#endif

/* Close descriptor used to write to system logger. */
void pr_closelog(int sockfd);

/* Open a connection to system logger.  Returns a file descriptor to the socket
 * opened for the connection, or -1 if there was an error.
 */
int pr_openlog(const char *ident, int option, int facility);

/* Set the log mask level.  */
int pr_setlogmask(int mask);

/* Set the facility of the system logger.  */
int pr_setlogfacility(int facility);

/* Generate a log message using the given format string and option arguments.
 */
void pr_syslog(int sockfd, int pri, const char *fmt, ...);

#endif /* PR_SYSLOG_H */
