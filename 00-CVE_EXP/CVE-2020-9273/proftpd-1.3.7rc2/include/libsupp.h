/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2016 The ProFTPD Project team
 *
 * Parts Copyright (C) 1991, 1992, 1993, 1999, 2000 Free Software
 *   Foundation, Inc.
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

/* ProFTPD support library definitions. */

#include <glibc-glob.h>

/* Bits set in the FLAGS argument to `pr_fnmatch'.  */
#define	PR_FNM_PATHNAME	(1 << 0) /* No wildcard can ever match `/'.  */
#define	PR_FNM_NOESCAPE	(1 << 1) /* Backslashes don't quote special chars.  */
#define	PR_FNM_PERIOD	(1 << 2) /* Leading `.' is matched only explicitly.  */

#define	PR_FNM_FILE_NAME	PR_FNM_PATHNAME /* Preferred GNU name.  */
#define	PR_FNM_LEADING_DIR	(1 << 3) /* Ignore `/...' after a match.  */
#define	PR_FNM_CASEFOLD		(1 << 4) /* Compare without regard to case.  */
#define PR_FNM_EXTMATCH         (1 << 5) /* Use ksh-like extended matching. */

/* Value returned by `pr_fnmatch' if STRING does not match PATTERN.  */
#define	PR_FNM_NOMATCH	1

int pr_fnmatch(const char *, const char *, int);
int sstrncpy(char *, const char *, size_t);

#ifndef HAVE_GAI_STRERROR
const char *pr_gai_strerror(int);
#else
# define pr_gai_strerror	gai_strerror
#endif /* HAVE_GAI_STRERROR */

#ifndef HAVE_FGETPWENT
struct passwd *fgetpwent(FILE *);
#endif /* HAVE_FGETPWENT */

#ifndef HAVE_FGETGRENT
struct group *fgetgrent(FILE *);
#endif /* HAVE_FGETGRENT */

#ifndef HAVE_HSTRERROR
const char *hstrerror(int);
#else
void pr_os_already_has_hstrerror(void);
#endif /* HAVE_HSTRERROR */

#ifndef HAVE_MKSTEMP
int mkstemp(char *);
#else
void pr_os_already_has_mkstemp(void);
#endif /* HAVE_MKSTEMP */

#ifndef HAVE_SNPRINTF
int snprintf(char *, size_t, const char *, ...);
#else
void pr_os_already_has_snprintf(void);
#endif /* HAVE_SNPRINTF */

#if defined(HAVE_VSNPRINTF) && defined(HAVE_SNPRINTF)
void pr_os_already_has_snprintf_and_vsnprintf(void);
#endif /* !HAVE_VSNPRINTF || !HAVE_SNPRINTF */

#ifndef HAVE_STRSEP
char *strsep(char **, const char *);
#else
void pr_os_already_has_strsep(void);
#endif /* HAVE_STRSEP */

#ifndef HAVE_VSNPRINTF
int vsnprintf(char *, size_t, const char *, va_list);
#else
void pr_os_already_has_vsnprintf(void);
#endif /* HAVE_VSNPRINTF */

#if defined(HAVE_VSNPRINTF) && defined(HAVE_SNPRINTF)
void pr_os_already_has_snprintf_and_vsnprintf(void);
#endif /* !HAVE_VSNPRINTF || !HAVE_SNPRINTF */
