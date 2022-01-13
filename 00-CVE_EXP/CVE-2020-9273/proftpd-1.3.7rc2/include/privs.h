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

#ifndef PR_PRIVS_H
#define PR_PRIVS_H

#if defined(HPUX10) || defined(HPUX11)
# define setreuid(r, e) setresuid((r), (e), 0)
#endif /* HPUX */

#ifdef PR_DEVEL_COREDUMP
/* Unix kernels can be notoriously picky about dumping the core for
 * processes that have fiddled with their effective/actual UID and GID.
 * So, to make it possible for people to have their proftpd processes
 * actually be able to coredump, these PRIVS macros, which switch
 * privileges, are effectively disabled.
 *
 * Hence it is not a Good Idea to run a proftpd built with PR_DEVEL_COREDUMP
 * defined in production.
 */

# define PRIVS_SETUP(u, g)
# define PRIVS_ROOT
# define PRIVS_USER
# define PRIVS_RELINQUISH
# define PRIVS_REVOKE

#else

# define PRIVS_SETUP(u, g)	pr_privs_setup((u), (g), __FILE__, __LINE__);
# define PRIVS_ROOT		pr_privs_root(__FILE__, __LINE__);
# define PRIVS_USER		pr_privs_user(__FILE__, __LINE__);
# define PRIVS_RELINQUISH	pr_privs_relinquish(__FILE__, __LINE__);
# define PRIVS_REVOKE		pr_privs_revoke(__FILE__, __LINE__);

#endif /* PR_DEVEL_COREDUMP */

int pr_privs_setup(uid_t, gid_t, const char *, int);
int pr_privs_root(const char *, int);
int pr_privs_user(const char *, int);
int pr_privs_relinquish(const char *, int);
int pr_privs_revoke(const char *, int);

/* For internal use only. */
int init_privs(void);
int set_nonroot_daemon(int);

#endif /* PR_PRIVS_H */
