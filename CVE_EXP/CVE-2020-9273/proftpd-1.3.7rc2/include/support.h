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

/* Non-specific support functions. */

#ifndef PR_SUPPORT_H
#define PR_SUPPORT_H

#include <sys/time.h>
#include <time.h>

#if defined(NAME_MAX)
# define NAME_MAX_GUESS		(NAME_MAX)
#elif defined(MAXNAMELEN)
# define NAME_MAX_GUESS		(MAXNAMELEN - 1)
#else
# define NAME_MAX_GUESS		(255)
#endif

/* Functions [optionally] provided by libsupp.a */
#ifndef HAVE_GETOPT
int getopt(int, char * const [], const char *);
extern char *optarg;
extern int optind,opterr,optopt;

#ifndef HAVE_GETOPT_LONG
struct option {
  const char *name;
  int has_arg;
  int *flag;
  int val;
};

int getopt_long(int, char * const [], const char *, const struct option *,
  int *);
# endif /* !HAVE_GETOPT_LONG */
#endif /* !HAVE_GETOPT */

char *dir_interpolate(pool *, const char *);
char *dir_abs_path(pool *, const char *, int);

/* Performs chroot-aware handling of symlinks. */
int dir_readlink(pool *, const char *, char *, size_t, int);
#define PR_DIR_READLINK_FL_HANDLE_REL_PATH		0x0001

char *dir_realpath(pool *, const char *);
char *dir_canonical_path(pool *, const char *);
char *dir_canonical_vpath(pool *, const char *);
char *dir_best_path(pool *, const char *);

/* Schedulables. */
void schedule(void (*f)(void *, void *, void *, void *), int, void *, void *,
  void *, void *);
void run_schedule(void);
void restart_daemon(void *, void *, void *, void *);
void shutdown_end_session(void *, void *, void *, void *);

long get_name_max(char *path, int fd);

mode_t file_mode(const char *);
mode_t file_mode2(pool *, const char *);

mode_t symlink_mode(const char *);
mode_t symlink_mode2(pool *, const char *);

int file_exists(const char *);
int file_exists2(pool *, const char *);

int dir_exists(const char *);
int dir_exists2(pool *, const char *);

int exists(const char *);
int exists2(pool *, const char *);

char *safe_token(char **);
int check_shutmsg(const char *, time_t *, time_t *, time_t *, char *, size_t);

void pr_memscrub(void *, size_t);

void pr_getopt_reset(void);
struct tm *pr_gmtime(pool *, const time_t *);
struct tm *pr_localtime(pool *, const time_t *);
const char *pr_strtime(time_t);
const char *pr_strtime2(time_t, int);

int pr_gettimeofday_millis(uint64_t *);
int pr_timeval2millis(struct timeval *, uint64_t *);

/* Wrappers around snprintf(3)/vsnprintf(3) which carefully check the
 * return values.
 */

int pr_snprintf(char *buf, size_t bufsz, const char *fmt, ...)
#ifdef __GNUC__
  __attribute__ ((format (printf, 3, 4)));
#else
  ;
#endif

/* Just like pr_snprintf(), except that the caller can provide their
 * source code location.
 */
int pr_snprintfl(const char *file, int lineno, char *buf, size_t bufsz,
  const char *fmt, ...)
#ifdef __GNUC__
  __attribute__ ((format (printf, 5, 6)));
#else
  ;
#endif

int pr_vsnprintf(char *buf, size_t bufsz, const char *fmt, va_list msg);
int pr_vsnprintfl(const char *file, int lineno, char *buf, size_t bufsz,
  const char *fmt, va_list msg);

/* Resolve/substitute any "%u" variables in the path.  Returns the resolved
 * path, or NULL if there was an error.
 */
const char *path_subst_uservar(pool *p, const char **path);

#endif /* PR_SUPPORT_H */
