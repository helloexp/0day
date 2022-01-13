/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2004-2016 The ProFTPD Project team
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
 * As a special exemption, the ProFTPD Project and other respective copyright
 * holders give permission to link this program with OpenSSL, and distribute
 * the resulting executable, without including the source code for OpenSSL in
 * the source distribution.
 */

/* ProFTPD Auth API */

#ifndef PR_AUTH_H
#define PR_AUTH_H

/* Possible return codes for auth handlers
 */

/* Account authenticated by means other than PASS (e.g. RFC2228 modules).
 * This value is more generic than PR_AUTH_RFC2228_OK.
 */
#define PR_AUTH_OK_NO_PASS		3

/* Account authenticated by RFC2228 security data exchange */
#define PR_AUTH_RFC2228_OK		2

/* Account authenticated normally */
#define PR_AUTH_OK			0

/* Error occurred in auth handler */
#define PR_AUTH_ERROR			-1

/* Account does not exist */
#define PR_AUTH_NOPWD			-2

/* Password mismatch */
#define PR_AUTH_BADPWD			-3

/* Password hasn't been changed recently enough */
#define PR_AUTH_AGEPWD			-4

/* Account has been disabled */
#define PR_AUTH_DISABLEDPWD		-5

/* Insufficient credentials. */
#define PR_AUTH_CRED_INSUFFICIENT	-6

/* Unavailable credentials. */
#define PR_AUTH_CRED_UNAVAIL		-7

/* Failure setting/using credentials. */
#define PR_AUTH_CRED_ERROR		-8

/* Unavailable credential/authentication service. */
#define PR_AUTH_INFO_UNAVAIL		-9

/* Max authentication attempts reached. */
#define PR_AUTH_MAX_ATTEMPTS_EXCEEDED	-10

/* Authentication service initialization failure. */
#define PR_AUTH_INIT_ERROR		-11

/* New authentication token/credentials needed. */
#define PR_AUTH_NEW_TOKEN_REQUIRED	-12

void pr_auth_setpwent(pool *);
void pr_auth_endpwent(pool *);
void pr_auth_setgrent(pool *);
void pr_auth_endgrent(pool *);
struct passwd *pr_auth_getpwent(pool *);
struct group *pr_auth_getgrent(pool *);
struct passwd *pr_auth_getpwnam(pool *, const char *);
struct passwd *pr_auth_getpwuid(pool *, uid_t);
struct group *pr_auth_getgrnam(pool *, const char *);
struct group *pr_auth_getgrgid(pool *, gid_t);
int pr_auth_authenticate(pool *, const char *, const char *);
int pr_auth_authorize(pool *, const char *);
int pr_auth_check(pool *, const char *, const char *, const char *);
const char *pr_auth_uid2name(pool *, uid_t);
const char *pr_auth_gid2name(pool *, gid_t);
uid_t pr_auth_name2uid(pool *, const char *);
gid_t pr_auth_name2gid(pool *, const char *);
int pr_auth_getgroups(pool *, const char *, array_header **, array_header **);
int pr_auth_requires_pass(pool *, const char *);

/* This is a convenience function used by mod_auth as part of the 
 * authentication process.  Given a user name, retrieve the <Anonymous>
 * configuration for that user.  If the user name is not be handled as
 * an anonymous login, NULL is returned.
 */
config_rec *pr_auth_get_anon_config(pool *p, const char **login_user,
  char **real_user, char **anon_user);

/* Wrapper function around the chroot(2) system call, handles setting of
 * appropriate environment variables if necessary.
 */
int pr_auth_chroot(const char *);

/* Check the /etc/ftpusers file, as per the UseFtpUsers directive, to see
 * if the given user is allowed.  Returns TRUE if the user is banned by
 * /etc/ftpusers, FALSE if not banned, and -1 if there was an error.
 */
int pr_auth_banned_by_ftpusers(xaset_t *, const char *);

/* Check the /etc/shells file, as per the RequireValidShell directive, to
 * ensure that the given shell is valid.  Returns TRUE if the user has
 * a valid shell, FALSE if an invalid shell, and -1 if there was an error.
 */
int pr_auth_is_valid_shell(xaset_t *, const char *);

/* Add to the list of authenticating-only modules (e.g. PAM). */
int pr_auth_add_auth_only_module(const char *);

/* Remove the named module from the list of authenticating-only modules. */
int pr_auth_remove_auth_only_module(const char *);

/* Clear the authenticating-only module list, e.g. when authentication has
 * completed.
 */
int pr_auth_clear_auth_only_modules(void);

/* Clears any cached IDs/names. */
void pr_auth_cache_clear(void);

/* Enable caching of certain data within the Auth API. */
int pr_auth_cache_set(int enable, unsigned int flags);
#define PR_AUTH_CACHE_FL_UID2NAME	0x00001
#define PR_AUTH_CACHE_FL_GID2NAME	0x00002
#define PR_AUTH_CACHE_FL_AUTH_MODULE	0x00004
#define PR_AUTH_CACHE_FL_NAME2UID	0x00008
#define PR_AUTH_CACHE_FL_NAME2GID	0x00010
#define PR_AUTH_CACHE_FL_BAD_UID2NAME	0x00020
#define PR_AUTH_CACHE_FL_BAD_GID2NAME	0x00040
#define PR_AUTH_CACHE_FL_BAD_NAME2UID	0x00080
#define PR_AUTH_CACHE_FL_BAD_NAME2GID	0x00100

/* Default Auth API cache flags/settings. */
#define PR_AUTH_CACHE_FL_DEFAULT \
  (PR_AUTH_CACHE_FL_UID2NAME|\
   PR_AUTH_CACHE_FL_GID2NAME|\
   PR_AUTH_CACHE_FL_AUTH_MODULE|\
   PR_AUTH_CACHE_FL_NAME2UID|\
   PR_AUTH_CACHE_FL_NAME2GID|\
   PR_AUTH_CACHE_FL_BAD_UID2NAME|\
   PR_AUTH_CACHE_FL_BAD_GID2NAME|\
   PR_AUTH_CACHE_FL_BAD_NAME2UID|\
   PR_AUTH_CACHE_FL_BAD_NAME2GID)

/* Wrapper function for retrieving the user's home directory.  This handles
 * any possible RewriteHome configuration.
 */
const char *pr_auth_get_home(pool *, const char *pw_dir);

/* Policy setting for the maximum allowable password length.  This is
 * supported for mitigating potential resource consumption attack via the
 * crypt(3) function.
 */
size_t pr_auth_set_max_password_len(pool *p, size_t len);

/* For internal use only. */
int init_auth(void);
int set_groups(pool *, gid_t, array_header *);

#endif /* PR_MODULES_H */
