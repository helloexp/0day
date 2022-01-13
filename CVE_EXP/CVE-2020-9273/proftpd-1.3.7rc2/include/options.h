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

/* User configurable defaults and tunable parameters. */

#ifndef PR_OPTIONS_H
#define PR_OPTIONS_H

/* Tunable parameters */

/* This defines the timeout for the main select() loop, defines the number
 * of seconds to wait for a session request before checking for things such
 * as shutdown requests, perform signal dispatching, etc before waitinng
 * for requests again.
 */

#define PR_TUNABLE_SELECT_TIMEOUT	30

/* Hash table size is the number of items in the module hash tables.
 */

#define PR_TUNABLE_HASH_TABLE_SIZE 40

/* "Backlog" is the number of connections that can be received at one
 * burst before the kernel rejects.  This can be configured by the
 * "tcpBackLog" configuration directive, this value is just the default.
 */
#ifndef PR_TUNABLE_DEFAULT_BACKLOG
# define PR_TUNABLE_DEFAULT_BACKLOG	128
#endif /* PR_TUNABLE_DEFAULT_BACKLOG */

/* The default TCP send/receive buffer sizes, should explicit sizes not
 * be defined at compile time, or should the runtime determination process
 * fail.
 *
 * Note that these default buffer sizes are only used if the service cannot
 * determine the platform's favored network buffer sizes using getsockopt(2).
 * If you wish to override the use of getsockopt(2) to determine the network
 * buffer sizes to use, you can use the PR_TUNABLE_RCVBUFSZ and
 * PR_TUNABLE_SNDBUFSZ macros to define, at compile-time, the network buffer
 * sizes to use.
 */

#ifndef PR_TUNABLE_DEFAULT_RCVBUFSZ
# define PR_TUNABLE_DEFAULT_RCVBUFSZ	8192
#endif /* PR_TUNABLE_DEFAULT_RCVBUFSZ */

#ifndef PR_TUNABLE_DEFAULT_SNDBUFSZ
# define PR_TUNABLE_DEFAULT_SNDBUFSZ	8192
#endif /* PR_TUNABLE_DEFAULT_SNDBUFSZ */

/* Default internal buffer size used for data transfers and other
 * miscellaneous tasks.
 */
#ifndef PR_TUNABLE_BUFFER_SIZE
# define PR_TUNABLE_BUFFER_SIZE		1024
#endif

/* There is also a definable buffer size used specifically for parsing
 * lines of text from the config file: PR_TUNABLE_PARSER_BUFFER_SIZE.
 *
 * You should manually set the PR_TUNABLE_PARSER_BUFFER_SIZE only if you
 * have exceptionally long configuration lines.
 */
#ifndef PR_TUNABLE_PARSER_BUFFER_SIZE
# define PR_TUNABLE_PARSER_BUFFER_SIZE	4096
#endif

/* There is also a definable buffer size used specifically for data
 * transfers: PR_TUNABLE_XFER_BUFFER_SIZE.  By default, this buffer
 * size is automatically determined, at runtime, as the smaller of the
 * TCP receive and send buffer sizes.
 *
 * You should manually set the PR_TUNABLE_XFER_BUFFER_SIZE only in
 * special circumstances, when you need to explicitly control that
 * buffer size.
 */
#ifndef PR_TUNABLE_XFER_BUFFER_SIZE
# define PR_TUNABLE_XFER_BUFFER_SIZE	PR_TUNABLE_BUFFER_SIZE
#endif

/* Maximum FTP command size.  For details on this size of 512KB, see
 * the Bug#4014 discussion.
 */
#ifndef PR_TUNABLE_CMD_BUFFER_SIZE
# define PR_TUNABLE_CMD_BUFFER_SIZE	(512 * 1024)
#endif

/* Maximum path length.  GNU HURD (and some others) do not define
 * MAXPATHLEN.  POSIX' PATH_MAX is mandated to be at least 256 
 * (according to some), so 1K, in the absence of MAXPATHLEN, should be
 * a reasonable default.
 */

#ifndef PR_TUNABLE_PATH_MAX
# ifdef MAXPATHLEN
#  define PR_TUNABLE_PATH_MAX           MAXPATHLEN
# else
#  define PR_TUNABLE_PATH_MAX           1024
# endif
#endif

/* Default timeouts, if not explicitly configured via
 * the TimeoutLogin, TimeoutIdle, etc directives.
 */

#ifndef PR_TUNABLE_TIMEOUTIDENT
# define PR_TUNABLE_TIMEOUTIDENT	10
#endif

#ifndef PR_TUNABLE_TIMEOUTIDLE
# define PR_TUNABLE_TIMEOUTIDLE		600
#endif

/* The default command timeout in many command-line FTP clients (e.g.
 * lukemftp, used on BSDs and maybe Linux?) is 60 seconds.  To avoid having
 * those clients close the control connection because proftpd takes too
 * long, while performing lingering closes, to send a response, keep the
 * default linger timeout under 60 seconds.
 */
#ifndef PR_TUNABLE_TIMEOUTLINGER
# define PR_TUNABLE_TIMEOUTLINGER	10
#endif

#ifndef PR_TUNABLE_TIMEOUTLOGIN
# define PR_TUNABLE_TIMEOUTLOGIN	300
#endif

#ifndef PR_TUNABLE_TIMEOUTNOXFER
# define PR_TUNABLE_TIMEOUTNOXFER	300
#endif

#ifndef PR_TUNABLE_TIMEOUTSTALLED
# define PR_TUNABLE_TIMEOUTSTALLED	3600
#endif

/* Number of bytes in a new memory pool.  During file transfers,
 * quite a few pools can be created, which eat up a lot of memory.
 * Tune this if ProFTPD seems too memory hungry (warning! too low
 * can negatively impact performance)
 */

#ifndef PR_TUNABLE_NEW_POOL_SIZE
# define PR_TUNABLE_NEW_POOL_SIZE	512
#endif

/* Number of bytes in certain scoreboard fields, usually for reporting
 * the full command received from the connected client, or the current
 * working directory for the session.
 */

#ifndef PR_TUNABLE_SCOREBOARD_BUFFER_SIZE
# define PR_TUNABLE_SCOREBOARD_BUFFER_SIZE	80
#endif

/* Number of seconds between scoreboard scrubs, where the scoreboard is
 * scanned for slots containing invalid PIDs.  Defaults to 30 seconds.
 */

#ifndef PR_TUNABLE_SCOREBOARD_SCRUB_TIMER
# define PR_TUNABLE_SCOREBOARD_SCRUB_TIMER	30
#endif

/* Maximum number of attempted updates to the scoreboard during a
 * file transfer before an actual write is done.  This is to allow
 * an optimization where the scoreboard is not updated on every loop
 * through the transfer buffer.
 */

#ifndef PR_TUNABLE_XFER_SCOREBOARD_UPDATES
# define PR_TUNABLE_XFER_SCOREBOARD_UPDATES	10
#endif

#ifndef PR_TUNABLE_CALLER_DEPTH
/* Max depth of call stack if stacktrace support is enabled. */
# define PR_TUNABLE_CALLER_DEPTH	32
#endif

#ifndef PR_TUNABLE_ENV_MAX
/* Max length of environment variable values allowed by proftpd. */
# define PR_TUNABLE_ENV_MAX			2048
#endif

#ifndef PR_TUNABLE_GLOBBING_MAX_RECURSION
/* Max number of recursion/directory levels to support when globbing.
 */
# define PR_TUNABLE_GLOBBING_MAX_RECURSION	8
#endif

#ifndef PR_TUNABLE_GLOBBING_MAX_MATCHES
/* Max number of matches to support when globbing.
 */
# define PR_TUNABLE_GLOBBING_MAX_MATCHES	100000UL
#endif

#ifndef PR_TUNABLE_LOGIN_MAX
/* Maximum length of login name.
 *
 * Ideally, we'd use _POSIX_LOGIN_NAME_MAX here, if it was defined.  However,
 * doing so would cause trouble for those sites that use databases for
 * storing user information; such sites often use email addresses as
 * login names.  Given that, let's use 256 as a login name size.
 */
# define PR_TUNABLE_LOGIN_MAX		256
#endif

#ifndef PR_TUNABLE_PASSWORD_MAX
/* Maximum length of a password. */
# define PR_TUNABLE_PASSWORD_MAX	1024
#endif

#ifndef PR_TUNABLE_EINTR_RETRY_INTERVAL
/* Define the time to delay, in seconds, after a system call has been
 * interrupted (errno is EINTR) before retrying that call.
 *
 * The default behavior is delay 0.2 secs between retries.
 */
# define PR_TUNABLE_EINTR_RETRY_INTERVAL	0.2
#endif

#ifndef PR_TUNABLE_XFER_LOG_MODE
# define PR_TUNABLE_XFER_LOG_MODE		0644
#endif

/* FS Statcache tuning. */
#ifndef PR_TUNABLE_FS_STATCACHE_SIZE
# define PR_TUNABLE_FS_STATCACHE_SIZE		32
#endif

#ifndef PR_TUNABLE_FS_STATCACHE_MAX_AGE
# define PR_TUNABLE_FS_STATCACHE_MAX_AGE	30
#endif

#endif /* PR_OPTIONS_H */
