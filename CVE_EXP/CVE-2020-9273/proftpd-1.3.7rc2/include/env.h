/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2007-2016 The ProFTPD Project team
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

/* Environment handling */

#ifndef PR_ENV_H
#define PR_ENV_H

/* Returns the value of the environment variable named key, or NULL if no
 * such value is present.
 */
char *pr_env_get(pool *p, const char *key);

/* Set an environment variable named key, with the given value.  Returns
 * zero if successful, or -1 (with errno set appropriately) if there was
 * a problem.
 *
 * The memory of the strings in the environment are the responsibility of
 * the caller; if allocating those strings from a memory pool, please be
 * sure to use a pool of the proper lifetime.
 */
int pr_env_set(pool *p, const char *key, const char *value);

/* Clear the environment of any variables named key.  Returns zero if
 * successful, -1 otherwise (with errno set appropriately.
 */
int pr_env_unset(pool *p, const char *key);

#endif /* PR_ENV_H */
