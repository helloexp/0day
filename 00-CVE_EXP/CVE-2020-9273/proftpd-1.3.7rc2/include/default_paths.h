/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2017 The ProFTPD Project team
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

/* ProFTPD default path configuration.  Normally, Makefiles generated
 * by the top-level configuration script define the PR_RUN_DIR and
 * PR_CONFIG_FILE_PATH macros, so the two below are typically not used.
 */

#ifndef PROFTPD_PATHS_H
#define PROFTPD_PATHS_H

/* The location you wish to place the "run-time" status file used by
 * ftpcount, ftpwho, etc.
 */
#ifndef PR_RUN_DIR
# define PR_RUN_DIR		"/var/run/proftpd"
#endif

/* The location you wish to place any core files produced as a result of
 * fatal errors (memory problems, etc).
 */
#ifndef PR_CORE_DIR
# define PR_CORE_DIR		PR_RUN_DIR
#endif

/* The file in which to write the pid (in ASCII) after the initial fork,
 * when run in standalone daemon mode.
 */
#ifndef PR_PID_FILE_PATH
# define PR_PID_FILE_PATH	"/var/run/proftpd.pid"
#endif

/* The default location of the proftpd configuration file.  Can be
 * overridden at runtime with the '-c' switch
 */
#ifndef PR_CONFIG_FILE_PATH
# define PR_CONFIG_FILE_PATH	"/etc/proftpd.conf"
#endif

/* The location of your `shells' file; a newline delimited list of
 * valid shells on your system.
 */
#ifndef PR_VALID_SHELL_PATH
# define PR_VALID_SHELL_PATH	"/etc/shells"
#endif

/* Where your log files are kept.  The "wu-ftpd style" xferlog is
 * stored here, as well as "extended" (not yet available) transfer
 * log files.  These can be overridden in the configuration file via
 * "TransferLog" and "ExtendedLog".
 */
#ifndef PR_XFERLOG_PATH
# define PR_XFERLOG_PATH	"/var/log/xferlog"
#endif

/* Location of the file that tells proftpd to discontinue servicing
 * requests.
 */
#ifndef PR_SHUTMSG_PATH
# define PR_SHUTMSG_PATH	"/etc/shutmsg"
#endif

/* Location of the file containing users that *cannot* use ftp
 * services (odd, eh?)
 */
#ifndef PR_FTPUSERS_PATH
# define PR_FTPUSERS_PATH	"/etc/ftpusers"
#endif

#endif /* PROFTPD_PATHS_H */
