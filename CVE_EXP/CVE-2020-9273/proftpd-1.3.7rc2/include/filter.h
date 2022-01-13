/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2009-2014 The ProFTPD Project team
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

#ifndef PR_FILTER_H
#define PR_FILTER_H

/* Checks the given path against any configured PathAllowFilter and
 * PathDenyFilter directives that may appear in the configuration set.
 *
 * Returns 0 if the path is allowed by the filters, or a negative value if
 * the path fails to pass a filter.  A return value of
 * PR_FILTER_ERR_FAILS_ALLOW_FILTER indicates that a PathAllowFilter was
 * configured which does not match the given path.  Likewise, a return
 * value of PR_FILTER_ERR_FAILS_DENY_FILTER indicates that the path DID
 * match a configured PathDenyFilter.
 */
int pr_filter_allow_path(xaset_t *set, const char *path);
#define PR_FILTER_ERR_FAILS_ALLOW_FILTER	-2
#define PR_FILTER_ERR_FAILS_DENY_FILTER		-3

/* Parse the optional flags parameter for PathAllowFilter, PathDenyFilter
 * directive configurations.
 *
 * Returns -1 (with errno set appropriately) if there was an error, otherwise
 * returns the pertinent regcomp(3) flags.
 */
int pr_filter_parse_flags(pool *p, const char *flags_str);

#endif /* PR_FILTER_H */
