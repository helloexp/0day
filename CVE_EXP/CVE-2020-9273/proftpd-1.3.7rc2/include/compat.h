/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2005-2015 The ProFTPD Project team
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

/* Compatibility macros */

#ifndef PR_COMPAT_H
#define PR_COMPAT_H

/* Legacy redefines, for compatibility (for a while). */

/* The following macros first appeared in 1.3.3rc1. */
#define ctrls_check_acl			pr_ctrls_check_acl
#define ctrls_check_group_acl		pr_ctrls_check_group_acl
#define ctrls_check_user_acl		pr_ctrls_check_user_acl
#define ctrls_init_acl			pr_ctrls_init_acl
#define ctrls_parse_acl			pr_ctrls_parse_acl
#define ctrls_set_group_acl		pr_ctrls_set_group_acl
#define ctrls_set_module_acls		pr_ctrls_set_module_acls
#define ctrls_set_user_acl		pr_ctrls_set_user_acl
#define ctrls_unregister_module_actions	pr_ctrls_unregister_module_actions
#define ctrls_log			pr_ctrls_log

/* The following macros first appeared in 1.3.4rc1. */
#define is_fnmatch			pr_str_is_fnmatch

/* The following macros first appeared in 1.3.4rc2. */
#define end_login			pr_session_end

/* The following macros first appeared in 1.3.6rc2. */
#define _sql_make_cmd			sql_make_cmd

#endif /* PR_COMPAT_H */
