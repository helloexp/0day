/*
 * ProFTPD - FTP server daemon
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Home-on-demand support */

#ifndef PR_MKHOME_H
#define PR_MKHOME_H

int create_home(pool *, const char *, const char *, uid_t, gid_t);

/* This flag indicates that root privs should NOT be used when creating
 * the parent directories for the home directory.  This flag is useful
 * mostly in cases where the home directory lies on a root-squashed
 * NFS share; using root privs will ultimately fail in such cases.
 */
#define PR_MKHOME_FL_USE_USER_PRIVS	0x0001

#endif /* PR_MKHOME_H */
