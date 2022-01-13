/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2006-2016 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Lastlog API */

#ifndef PR_LASTLOG_H
#define PR_LASTLOG_H

#ifdef PR_USE_LASTLOG

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
#   define PR_LASTLOG_PATH	_PATH_LASTLOG
# else
#   ifdef LASTLOG_FILE
#     define PR_LASTLOG_PATH	LASTLOG_FILE
#   endif
# endif
#endif

int log_lastlog(uid_t uid, const char *user_name, const char *tty,
  const pr_netaddr_t *remote_addr);
#endif /* PR_USE_LASTLOG */

#endif /* PR_LASTLOG_H */
