/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2010 Todd C. Miller <Todd.Miller@sudo.ws>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Trivial replacements for the libc get{gr,pw}{uid,nam}() routines
 * for use by testsudoers in the sudo test harness.
 * We need our own since many platforms don't provide set{pw,gr}file().
 */

#include <config.h>

/*
 * Define away the system prototypes so we don't have any conflicts.
 */

#define setgrfile	sys_setgrfile
#define setgrent	sys_setgrent
#define endgrent	sys_endgrent
#define getgrent	sys_getgrent
#define getgrnam	sys_getgrnam
#define getgrgid	sys_getgrgid

#define setpwfile	sys_setpwfile
#define setpwent	sys_setpwent
#define endpwent	sys_endpwent
#define getpwent	sys_getpwent
#define getpwnam	sys_getpwnam
#define getpwuid	sys_getpwuid

#include <pwd.h>
#include <grp.h>

#undef setgrfile
#undef setgrent
#undef endgrent
#undef getgrent
#undef getgrnam
#undef getgrgid

void setgrfile(const char *);
void setgrent(void);
void endgrent(void);
struct group *getgrent(void);
struct group *getgrnam(const char *);
struct group *getgrgid(gid_t);

#undef setpwfile
#undef setpwent
#undef endpwent
#undef getpwent
#undef getpwnam
#undef getpwuid

void setpwfile(const char *);
void setpwent(void);
void endpwent(void);
struct passwd *getpwent(void);
struct passwd *getpwnam(const char *);
struct passwd *getpwuid(uid_t);
