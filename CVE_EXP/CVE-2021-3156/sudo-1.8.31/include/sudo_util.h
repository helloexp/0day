/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2013-2018 Todd C. Miller <Todd.Miller@sudo.ws>
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

#ifndef SUDO_UTIL_H
#define SUDO_UTIL_H

#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

#ifndef TIME_T_MAX
# if SIZEOF_TIME_T == 8
#  define TIME_T_MAX	LLONG_MAX
# else
#  define TIME_T_MAX	INT_MAX
# endif
#endif

/*
 * Macros for operating on struct timeval.
 */
#define sudo_timevalclear(tv)	((tv)->tv_sec = (tv)->tv_usec = 0)

#define sudo_timevalisset(tv)	((tv)->tv_sec || (tv)->tv_usec)

#define sudo_timevalcmp(tv1, tv2, op)					       \
    (((tv1)->tv_sec == (tv2)->tv_sec) ?					       \
	((tv1)->tv_usec op (tv2)->tv_usec) :				       \
	((tv1)->tv_sec op (tv2)->tv_sec))

#define sudo_timevaladd(tv1, tv2, tv3)					       \
    do {								       \
	(tv3)->tv_sec = (tv1)->tv_sec + (tv2)->tv_sec;			       \
	(tv3)->tv_usec = (tv1)->tv_usec + (tv2)->tv_usec;		       \
	if ((tv3)->tv_usec >= 1000000) {				       \
	    (tv3)->tv_sec++;						       \
	    (tv3)->tv_usec -= 1000000;					       \
	}								       \
    } while (0)

#define sudo_timevalsub(tv1, tv2, tv3)					       \
    do {								       \
	(tv3)->tv_sec = (tv1)->tv_sec - (tv2)->tv_sec;			       \
	(tv3)->tv_usec = (tv1)->tv_usec - (tv2)->tv_usec;		       \
	if ((tv3)->tv_usec < 0) {					       \
	    (tv3)->tv_sec--;						       \
	    (tv3)->tv_usec += 1000000;					       \
	}								       \
    } while (0)

#ifndef TIMEVAL_TO_TIMESPEC
# define TIMEVAL_TO_TIMESPEC(tv, ts)					       \
    do {								       \
	(ts)->tv_sec = (tv)->tv_sec;					       \
	(ts)->tv_nsec = (tv)->tv_usec * 1000;				       \
    } while (0)
#endif

/*
 * Macros for operating on struct timespec.
 */
#define sudo_timespecclear(ts)	((ts)->tv_sec = (ts)->tv_nsec = 0)

#define sudo_timespecisset(ts)	((ts)->tv_sec || (ts)->tv_nsec)

#define sudo_timespeccmp(ts1, ts2, op)					       \
    (((ts1)->tv_sec == (ts2)->tv_sec) ?					       \
	((ts1)->tv_nsec op (ts2)->tv_nsec) :				       \
	((ts1)->tv_sec op (ts2)->tv_sec))

#define sudo_timespecadd(ts1, ts2, ts3)					       \
    do {								       \
	(ts3)->tv_sec = (ts1)->tv_sec + (ts2)->tv_sec;			       \
	(ts3)->tv_nsec = (ts1)->tv_nsec + (ts2)->tv_nsec;		       \
	while ((ts3)->tv_nsec >= 1000000000) {				       \
	    (ts3)->tv_sec++;						       \
	    (ts3)->tv_nsec -= 1000000000;				       \
	}								       \
    } while (0)

#define sudo_timespecsub(ts1, ts2, ts3)					       \
    do {								       \
	(ts3)->tv_sec = (ts1)->tv_sec - (ts2)->tv_sec;			       \
	(ts3)->tv_nsec = (ts1)->tv_nsec - (ts2)->tv_nsec;		       \
	while ((ts3)->tv_nsec < 0) {					       \
	    (ts3)->tv_sec--;						       \
	    (ts3)->tv_nsec += 1000000000;				       \
	}								       \
    } while (0)

#ifndef TIMESPEC_TO_TIMEVAL
# define TIMESPEC_TO_TIMEVAL(tv, ts)					       \
    do {								       \
	(tv)->tv_sec = (ts)->tv_sec;					       \
	(tv)->tv_usec = (ts)->tv_nsec / 1000;				       \
    } while (0)
#endif

/*
 * The timespec version of st_mtime may vary on different platforms.
 */
#if defined(HAVE_ST_MTIM)
# if defined(HAVE_ST__TIM)
#  define SUDO_ST_MTIM		st_mtim.st__tim
# else
#  define SUDO_ST_MTIM		st_mtim
# endif
#elif defined(HAVE_ST_MTIMESPEC)
# define SUDO_ST_MTIM		st_mtimespec
#endif

/*
 * Macro to extract mtime as timespec.
 * If there is no way to set the timestamp using nanosecond precision,
 * we only fetch microsecond precision.  Otherwise there is a mismatch
 * between the timestamp we read and the one we wrote.
 */
#if defined(SUDO_ST_MTIM)
# if defined(HAVE_FUTIMENS) && defined(HAVE_UTIMENSAT)
#  define mtim_get(_x, _y)	do { (_y).tv_sec = (_x)->SUDO_ST_MTIM.tv_sec; (_y).tv_nsec = (_x)->SUDO_ST_MTIM.tv_nsec; } while (0)
# else
#  define mtim_get(_x, _y)	do { (_y).tv_sec = (_x)->SUDO_ST_MTIM.tv_sec; (_y).tv_nsec = ((_x)->SUDO_ST_MTIM.tv_nsec / 1000) * 1000; } while (0)
# endif
#elif defined(HAVE_ST_NMTIME)
# define mtim_get(_x, _y)	do { (_y).tv_sec = (_x)->st_mtime; (_y).tv_nsec = (_x)->st_nmtime; } while (0)
#else
# define mtim_get(_x, _y)	do { (_y).tv_sec = (_x)->st_mtime; (_y).tv_nsec = 0; } while (0)
#endif /* HAVE_ST_MTIM */

/* sizeof() that returns a signed value */
#define ssizeof(_x)	((ssize_t)sizeof(_x))

/* Bit map macros. */
#define sudo_setbit(_a, _i)	((_a)[(_i) / NBBY] |= 1 << ((_i) % NBBY))
#define sudo_clrbit(_a, _i)	((_a)[(_i) / NBBY] &= ~(1<<((_i) % NBBY)))
#define sudo_isset(_a, _i)	((_a)[(_i) / NBBY] & (1<<((_i) % NBBY)))
#define sudo_isclr(_a, _i)	(((_a)[(_i) / NBBY] & (1<<((_i) % NBBY))) == 0)

/* sudo_parseln() flags */
#define PARSELN_COMM_BOL	0x01	/* comments only at begining of line */
#define PARSELN_CONT_IGN	0x02	/* ignore line continuation char */

/*
 * Macros to quiet gcc's warn_unused_result attribute.
 */
#ifdef __GNUC__
# define ignore_result(x) do {						       \
    __typeof__(x) y = (x);						       \
    (void)y;								       \
} while(0)
#else
# define ignore_result(x)	(void)(x)
#endif

/* aix.c */
__dso_public int aix_getauthregistry_v1(char *user, char *saved_registry);
#define aix_getauthregistry(_a, _b) aix_getauthregistry_v1((_a), (_b))
__dso_public int aix_prep_user_v1(char *user, const char *tty);
#define aix_prep_user(_a, _b) aix_prep_user_v1((_a), (_b))
__dso_public int aix_restoreauthdb_v1(void);
#define aix_restoreauthdb() aix_restoreauthdb_v1()
__dso_public int aix_setauthdb_v1(char *user);
__dso_public int aix_setauthdb_v2(char *user, char *registry);
#define aix_setauthdb(_a, _b) aix_setauthdb_v2((_a), (_b))

/* gethostname.c */
__dso_public char *sudo_gethostname_v1(void);
#define sudo_gethostname() sudo_gethostname_v1()

/* gettime.c */
__dso_public int sudo_gettime_awake_v1(struct timespec *ts);
#define sudo_gettime_awake(_a) sudo_gettime_awake_v1((_a))
__dso_public int sudo_gettime_mono_v1(struct timespec *ts);
#define sudo_gettime_mono(_a) sudo_gettime_mono_v1((_a))
__dso_public int sudo_gettime_real_v1(struct timespec *ts);
#define sudo_gettime_real(_a) sudo_gettime_real_v1((_a))

/* gidlist.c */
__dso_public int sudo_parse_gids_v1(const char *gidstr, const gid_t *basegid, GETGROUPS_T **gidsp);
#define sudo_parse_gids(_a, _b, _c) sudo_parse_gids_v1((_a), (_b), (_c))

/* getgrouplist.c */
__dso_public int sudo_getgrouplist2_v1(const char *name, gid_t basegid, GETGROUPS_T **groupsp, int *ngroupsp);
#define sudo_getgrouplist2(_a, _b, _c, _d) sudo_getgrouplist2_v1((_a), (_b), (_c), (_d))

/* key_val.c */
__dso_public char *sudo_new_key_val_v1(const char *key, const char *value);
#define sudo_new_key_val(_a, _b) sudo_new_key_val_v1((_a), (_b))

/* locking.c */
#define SUDO_LOCK	1		/* lock a file */
#define SUDO_TLOCK	2		/* test & lock a file (non-blocking) */
#define SUDO_UNLOCK	4		/* unlock a file */
__dso_public bool sudo_lock_file_v1(int fd, int action);
#define sudo_lock_file(_a, _b) sudo_lock_file_v1((_a), (_b))
__dso_public bool sudo_lock_region_v1(int fd, int action, off_t len);
#define sudo_lock_region(_a, _b, _c) sudo_lock_region_v1((_a), (_b), (_c))

/* parseln.c */
__dso_public ssize_t sudo_parseln_v1(char **buf, size_t *bufsize, unsigned int *lineno, FILE *fp);
__dso_public ssize_t sudo_parseln_v2(char **buf, size_t *bufsize, unsigned int *lineno, FILE *fp, int flags);
#define sudo_parseln(_a, _b, _c, _d, _e) sudo_parseln_v2((_a), (_b), (_c), (_d), (_e))

/* progname.c */
__dso_public void initprogname(const char *);

/* secure_path.c */
#define SUDO_PATH_SECURE		0
#define SUDO_PATH_MISSING		-1
#define SUDO_PATH_BAD_TYPE		-2
#define SUDO_PATH_WRONG_OWNER		-3
#define SUDO_PATH_WORLD_WRITABLE	-4
#define SUDO_PATH_GROUP_WRITABLE	-5
struct stat;
__dso_public int sudo_secure_dir_v1(const char *path, uid_t uid, gid_t gid, struct stat *sbp);
#define sudo_secure_dir(_a, _b, _c, _d) sudo_secure_dir_v1((_a), (_b), (_c), (_d))
__dso_public int sudo_secure_file_v1(const char *path, uid_t uid, gid_t gid, struct stat *sbp);
#define sudo_secure_file(_a, _b, _c, _d) sudo_secure_file_v1((_a), (_b), (_c), (_d))

/* setgroups.c */
__dso_public int sudo_setgroups_v1(int ngids, const GETGROUPS_T *gids);
#define sudo_setgroups(_a, _b) sudo_setgroups_v1((_a), (_b))

/* strsplit.c */
__dso_public const char *sudo_strsplit_v1(const char *str, const char *endstr, const char *sep, const char **last);
#define sudo_strsplit(_a, _b, _c, _d) sudo_strsplit_v1(_a, _b, _c, _d)

/* strtobool.c */
__dso_public int sudo_strtobool_v1(const char *str);
#define sudo_strtobool(_a) sudo_strtobool_v1((_a))

/* strtonum.c */
/* Not versioned for historical reasons. */
__dso_public long long sudo_strtonum(const char *, long long, long long, const char **);

/* strtoid.c */
__dso_public id_t sudo_strtoid_v1(const char *str, const char *sep, char **endp, const char **errstr);
__dso_public id_t sudo_strtoid_v2(const char *str, const char **errstr);
#define sudo_strtoid(_a, _b) sudo_strtoid_v2((_a), (_b))
__dso_public id_t sudo_strtoidx_v1(const char *str, const char *sep, char **endp, const char **errstr);
#define sudo_strtoidx(_a, _b, _c, _d) sudo_strtoidx_v1((_a), (_b), (_c), (_d))

/* strtomode.c */
__dso_public int sudo_strtomode_v1(const char *cp, const char **errstr);
#define sudo_strtomode(_a, _b) sudo_strtomode_v1((_a), (_b))

/* sudo_printf.c */
extern int (*sudo_printf)(int msg_type, const char *fmt, ...);

/* term.c */
__dso_public bool sudo_term_cbreak_v1(int fd);
#define sudo_term_cbreak(_a) sudo_term_cbreak_v1((_a))
__dso_public bool sudo_term_copy_v1(int src, int dst);
#define sudo_term_copy(_a, _b) sudo_term_copy_v1((_a), (_b))
__dso_public bool sudo_term_noecho_v1(int fd);
#define sudo_term_noecho(_a) sudo_term_noecho_v1((_a))
__dso_public bool sudo_term_raw_v1(int fd, int isig);
#define sudo_term_raw(_a, _b) sudo_term_raw_v1((_a), (_b))
__dso_public bool sudo_term_restore_v1(int fd, bool flush);
#define sudo_term_restore(_a, _b) sudo_term_restore_v1((_a), (_b))

/* ttyname_dev.c */
__dso_public char *sudo_ttyname_dev_v1(dev_t tdev, char *name, size_t namelen);
#define sudo_ttyname_dev(_a, _b, _c) sudo_ttyname_dev_v1((_a), (_b), (_c))

/* ttysize.c */
__dso_public void sudo_get_ttysize_v1(int *rowp, int *colp);
#define sudo_get_ttysize(_a, _b) sudo_get_ttysize_v1((_a), (_b))

#endif /* SUDO_UTIL_H */
