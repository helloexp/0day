/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
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

/* Generic configuration and standard header file includes. */

#ifndef PR_CONF_H
#define PR_CONF_H

#include "os.h"
#include "version.h"

/* The tunable options header needs to be included after all the system headers,
 * so that limits are picked up properly.
 */
#include "options.h"

#if defined(HAVE_LLU) && SIZEOF_OFF_T == 8
# define PR_LU		"llu"
# define pr_off_t	unsigned long long
#else
# define PR_LU		"lu"
# define pr_off_t	unsigned long
#endif

/********************************************************************
 * This is NOT the user configurable section.  Look in options.h
 * for tunable parameters.
 ********************************************************************/

#ifndef __PROFTPD_SUPPORT_LIBRARY

/* This section is only needed for modules and the core source files,
 * not for the support library.
 */

#include "pool.h"
#include "str.h"
#include "ascii.h"
#include "table.h"
#include "signals.h"
#include "proftpd.h"
#include "support.h"
#include "str.h"
#include "sets.h"
#include "configdb.h"
#include "dirtree.h"
#include "expr.h"
#include "rlimit.h"
#include "filter.h"
#include "modules.h"
#include "netio.h"
#include "regexp.h"
#include "stash.h"
#include "auth.h"
#include "response.h"
#include "timers.h"
#include "inet.h"
#include "child.h"
#include "netaddr.h"
#include "netacl.h"
#include "class.h"
#include "cmd.h"
#include "bindings.h"
#include "help.h"
#include "feat.h"
#include "ftp.h"
#include "log.h"
#include "parser.h"
#include "xferlog.h"
#include "scoreboard.h"
#include "data.h"
#include "display.h"
#include "libsupp.h"
#include "fsio.h"
#include "mkhome.h"
#include "ctrls.h"
#include "session.h"
#include "event.h"
#include "var.h"
#include "throttle.h"
#include "trace.h"
#include "encode.h"
#include "compat.h"
#include "proctitle.h"
#include "pidfile.h"
#include "env.h"
#include "random.h"
#include "pr-syslog.h"
#include "json.h"
#include "memcache.h"
#include "redis.h"

# ifdef HAVE_SETPASSENT
#  define setpwent()	setpassent(1)
# endif /* HAVE_SETPASSENT */

# ifdef HAVE_SETGROUPENT
#  define setgrent()	setgroupent(1)
# endif /* HAVE_SETGROUPENT */

/* Define a buffer size to use for responses, making sure it is big enough
 * to handle large path names (e.g. for MKD responses).
 */
#define PR_RESPONSE_BUFFER_SIZE	 (PR_TUNABLE_BUFFER_SIZE + PR_TUNABLE_PATH_MAX)

#endif /* __PROFTPD_SUPPORT_LIBRARY */

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif /* WITH_DMALLOC */

#endif /* PR_CONF_H */
