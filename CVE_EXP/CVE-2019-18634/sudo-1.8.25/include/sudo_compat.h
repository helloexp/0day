/*
 * Copyright (c) 1996, 1998-2005, 2008, 2009-2018
 *	Todd C. Miller <Todd.Miller@sudo.ws>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#ifndef SUDO_COMPAT_H
#define SUDO_COMPAT_H

#include <stdio.h>
#if !defined(HAVE_VSNPRINTF) || !defined(HAVE_VASPRINTF) || \
    !defined(HAVE_VSYSLOG) || defined(PREFER_PORTABLE_SNPRINTF)
# include <stdarg.h>
#endif
#if !defined(HAVE_MEMSET_S) && !defined(rsize_t)
# include <stddef.h>	/* for rsize_t */
# ifdef HAVE_STRING_H
#  include <string.h>	/* for rsize_t on AIX */
# endif /* HAVE_STRING_H */
#endif /* HAVE_MEMSET_S && rsize_t */

/*
 * Macros and functions that may be missing on some operating systems.
 */

#ifndef __GNUC_PREREQ__
# ifdef __GNUC__
#  define __GNUC_PREREQ__(ma, mi) \
	((__GNUC__ > (ma)) || (__GNUC__ == (ma) && __GNUC_MINOR__ >= (mi)))
# else
#  define __GNUC_PREREQ__(ma, mi)	0
# endif
#endif

/* Define away __attribute__ for non-gcc or old gcc */
#if !defined(__attribute__) && !__GNUC_PREREQ__(2, 5)
# define __attribute__(x)
#endif

/* For catching format string mismatches */
#ifndef __printflike
# if __GNUC_PREREQ__(3, 3)
#  define __printflike(f, v) 	__attribute__((__format__ (__printf__, f, v))) __attribute__((__nonnull__ (f)))
# elif __GNUC_PREREQ__(2, 7)
#  define __printflike(f, v) 	__attribute__((__format__ (__printf__, f, v)))
# else
#  define __printflike(f, v)
# endif
#endif
#ifndef __printf0like
# if __GNUC_PREREQ__(2, 7)
#  define __printf0like(f, v) 	__attribute__((__format__ (__printf__, f, v)))
# else
#  define __printf0like(f, v)
# endif
#endif
#ifndef __format_arg
# if __GNUC_PREREQ__(2, 7)
#  define __format_arg(f) 	__attribute__((__format_arg__ (f)))
# else
#  define __format_arg(f)
# endif
#endif

/*
 * Given the pointer x to the member m of the struct s, return
 * a pointer to the containing structure.
 */
#ifndef __containerof
# define __containerof(x, s, m)	((s *)((char *)(x) - offsetof(s, m)))
#endif

#ifndef __dso_public
# ifdef HAVE_DSO_VISIBILITY
#  if defined(__GNUC__)
#   define __dso_public	__attribute__((__visibility__("default")))
#   define __dso_hidden	__attribute__((__visibility__("hidden")))
#  elif defined(__SUNPRO_C)
#   define __dso_public	__global
#   define __dso_hidden __hidden
#  else
#   define __dso_public	__declspec(dllexport)
#   define __dso_hidden
#  endif
# else
#  define __dso_public
#  define __dso_hidden
# endif
#endif

/*
 * Pre-C99 compilers may lack a va_copy macro.
 */
#ifndef va_copy
# ifdef __va_copy
#  define va_copy(d, s) __va_copy(d, s)
# else
#  define va_copy(d, s) memcpy(&(d), &(s), sizeof(d));
# endif
#endif

/*
 * Some systems lack full limit definitions.
 */
#if defined(HAVE_DECL_LLONG_MAX) && !HAVE_DECL_LLONG_MAX
# if defined(HAVE_DECL_QUAD_MAX) && HAVE_DECL_QUAD_MAX
#  define LLONG_MAX	QUAD_MAX
# else
#  define LLONG_MAX	0x7fffffffffffffffLL
# endif
#endif

#if defined(HAVE_DECL_LLONG_MIN) && !HAVE_DECL_LLONG_MIN
# if defined(HAVE_DECL_QUAD_MIN) && HAVE_DECL_QUAD_MIN
#  define LLONG_MIN	QUAD_MIN
# else
#  define LLONG_MIN	(-0x7fffffffffffffffLL-1)
# endif
#endif

#if defined(HAVE_DECL_ULLONG_MAX) && !HAVE_DECL_ULLONG_MAX
# if defined(HAVE_DECL_UQUAD_MAX) && HAVE_DECL_UQUAD_MAX
#  define ULLONG_MAX	UQUAD_MAX
# else
#  define ULLONG_MAX	0xffffffffffffffffULL
# endif
#endif

#if defined(HAVE_DECL_SIZE_MAX) && !HAVE_DECL_SIZE_MAX
# if defined(HAVE_DECL_SIZE_T_MAX) && HAVE_DECL_SIZE_T_MAX
#  define SIZE_MAX	SIZE_T_MAX
# else
#  define SIZE_MAX	ULONG_MAX
# endif
#endif

#if defined(HAVE_DECL_PATH_MAX) && !HAVE_DECL_PATH_MAX
# if defined(HAVE_DECL__POSIX_PATH_MAX) && HAVE_DECL__POSIX_PATH_MAX
#  define PATH_MAX		_POSIX_PATH_MAX
# else
#  define PATH_MAX		256
# endif
#endif

/*
 * POSIX versions for those without...
 */
#ifndef _S_IFMT
# define _S_IFMT		S_IFMT
#endif /* _S_IFMT */
#ifndef _S_IFREG
# define _S_IFREG		S_IFREG
#endif /* _S_IFREG */
#ifndef _S_IFDIR
# define _S_IFDIR		S_IFDIR
#endif /* _S_IFDIR */
#ifndef _S_IFLNK
# define _S_IFLNK		S_IFLNK
#endif /* _S_IFLNK */
#ifndef _S_IFIFO
# define _S_IFIFO		S_IFIFO
#endif /* _S_IFIFO */
#ifndef S_ISREG
# define S_ISREG(m)		(((m) & _S_IFMT) == _S_IFREG)
#endif /* S_ISREG */
#ifndef S_ISDIR
# define S_ISDIR(m)		(((m) & _S_IFMT) == _S_IFDIR)
#endif /* S_ISDIR */
#ifndef S_ISLNK
# define S_ISLNK(m)		(((m) & _S_IFMT) == _S_IFLNK)
#endif /* S_ISLNK */
#ifndef S_ISFIFO
# define S_ISFIFO(m)		(((m) & _S_IFMT) == _S_IFIFO)
#endif /* S_ISLNK */
#ifndef S_ISTXT
# define S_ISTXT		0001000
#endif /* S_ISTXT */

/*
 * ACCESSPERMS (00777) and ALLPERMS (07777) are handy BSDisms
 */
#ifndef ACCESSPERMS
# define ACCESSPERMS	(S_IRWXU|S_IRWXG|S_IRWXO)
#endif /* ACCESSPERMS */
#ifndef ALLPERMS
# define ALLPERMS	(S_ISUID|S_ISGID|S_ISTXT|S_IRWXU|S_IRWXG|S_IRWXO)
#endif /* ALLPERMS */

/* For futimens() and utimensat() emulation. */
#if !defined(HAVE_FUTIMENS) && !defined(HAVE_UTIMENSAT)
# ifndef UTIME_OMIT
#  define UTIME_OMIT	-1L
# endif
# ifndef UTIME_NOW
#  define UTIME_NOW	-2L
# endif
#endif
#if !defined(HAVE_OPENAT) || (!defined(HAVE_FUTIMENS) && !defined(HAVE_UTIMENSAT))
# ifndef AT_FDCWD
#  define AT_FDCWD	-100
# endif
#endif

/* For pipe2() emulation. */
#if !defined(HAVE_PIPE2) && defined(O_NONBLOCK) && !defined(O_CLOEXEC)
# define O_CLOEXEC	0x80000000
#endif

/*
 * BSD defines these in <sys/param.h> but we don't include that anymore.
 */
#ifndef MIN
# define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
#endif

/* Macros to set/clear/test flags. */
#undef SET
#define SET(t, f)	((t) |= (f))
#undef CLR
#define CLR(t, f)	((t) &= ~(f))
#undef ISSET
#define ISSET(t, f)     ((t) & (f))

/*
 * Some systems define this in <sys/param.h> but we don't include that anymore.
 */
#ifndef howmany
# define howmany(x, y)	(((x) + ((y) - 1)) / (y))
#endif

/*
 * Simple isblank() macro and function for systems without it.
 */
#ifndef HAVE_ISBLANK
__dso_public int isblank(int);
# define isblank(_x)	((_x) == ' ' || (_x) == '\t')
#endif

/*
 * NCR's SVr4 has _innetgr(3) instead of innetgr(3) for some reason.
 */
#ifdef HAVE__INNETGR
# define innetgr(n, h, u, d)	(_innetgr(n, h, u, d))
# define HAVE_INNETGR 1
#endif /* HAVE__INNETGR */

/*
 * The nitems macro may be defined in sys/param.h
 */
#ifndef nitems
# define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

/*
 * If dirfd() does not exists, hopefully dd_fd does.
 */
#if !defined(HAVE_DIRFD) && defined(HAVE_DD_FD)
# define dirfd(_d)	((_d)->dd_fd)
# define HAVE_DIRFD
#endif

#if !defined(HAVE_KILLPG) && !defined(killpg)
# define killpg(p, s)	kill(-(p), (s))
#endif

/*
 * Declare errno if errno.h doesn't do it for us.
 */
#if defined(HAVE_DECL_ERRNO) && !HAVE_DECL_ERRNO
extern int errno;
#endif /* !HAVE_DECL_ERRNO */

/* Not all systems define NSIG in signal.h */
#if !defined(NSIG)
# if defined(_NSIG)
#  define NSIG _NSIG
# elif defined(__NSIG)
#  define NSIG __NSIG
# else
#  define NSIG 64
# endif
#endif

/* For sig2str() */
#if !defined(HAVE_DECL_SIG2STR_MAX) || !HAVE_DECL_SIG2STR_MAX
# define SIG2STR_MAX 32
#endif

/* WCOREDUMP is not POSIX, this usually works (verified on AIX). */
#ifndef WCOREDUMP
# define WCOREDUMP(x)	((x) & 0x80)
#endif

/* W_EXITCODE is not POSIX but the encoding of wait status is. */
#ifndef W_EXITCODE
# define W_EXITCODE(ret, sig)	((ret) << 8 | (sig))
#endif

/* Number of bits in a byte. */
#ifndef NBBY
# ifdef __NBBY
#  define NBBY __NBBY
# else
#  define NBBY 8
# endif
#endif

#ifndef HAVE_SETEUID
#  if defined(HAVE_SETRESUID)
#    define seteuid(u)	setresuid(-1, (u), -1)
#    define setegid(g)	setresgid(-1, (g), -1)
#    define HAVE_SETEUID 1
#  elif defined(HAVE_SETREUID)
#    define seteuid(u)	setreuid(-1, (u))
#    define setegid(g)	setregid(-1, (g))
#    define HAVE_SETEUID 1
#  endif
#endif /* HAVE_SETEUID */

/*
 * Older HP-UX does not declare setresuid() or setresgid().
 */
#if defined(HAVE_DECL_SETRESUID) && !HAVE_DECL_SETRESUID
int setresuid(uid_t, uid_t, uid_t);
int setresgid(gid_t, gid_t, gid_t);
#endif
#if defined(HAVE_DECL_GETRESUID) && !HAVE_DECL_GETRESUID
int getresuid(uid_t *, uid_t *, uid_t *);
int getresgid(gid_t *, gid_t *, gid_t *);
#endif

/*
 * HP-UX does not declare innetgr() or getdomainname().
 * Solaris does not declare getdomainname().
 */
#if defined(HAVE_DECL_INNETGR) && !HAVE_DECL_INNETGR
int innetgr(const char *, const char *, const char *, const char *);
#endif
#if defined(HAVE_DECL__INNETGR) && !HAVE_DECL__INNETGR
int _innetgr(const char *, const char *, const char *, const char *);
#endif
#if defined(HAVE_DECL_GETDOMAINNAME) && !HAVE_DECL_GETDOMAINNAME
int getdomainname(char *, size_t);
#endif

/*
 * HP-UX 11.00 has broken pread/pwrite that can't handle a 64-bit off_t
 * on 32-bit machines.
 */
#if defined(__hpux) && !defined(__LP64__)
# ifdef HAVE_PREAD64
#  undef pread
#  define pread(_a, _b, _c, _d) pread64((_a), (_b), (_c), (_d))
# endif
# ifdef HAVE_PWRITE64
#  undef pwrite
#  define pwrite(_a, _b, _c, _d) pwrite64((_a), (_b), (_c), (_d))
# endif
#endif /* __hpux && !__LP64__ */

/* We wrap OpenBSD's strtonum() to get translatable error strings. */
__dso_public long long sudo_strtonum(const char *, long long, long long, const char **);
#undef strtonum
#define strtonum(_a, _b, _c, _d) sudo_strtonum((_a), (_b), (_c), (_d))

/*
 * Functions "missing" from libc.
 * All libc replacements are prefixed with "sudo_" to avoid namespace issues.
 */

struct passwd;
struct timespec;

#ifndef HAVE_CLOSEFROM
__dso_public void sudo_closefrom(int);
# undef closefrom
# define closefrom(_a) sudo_closefrom((_a))
#endif /* HAVE_CLOSEFROM */
#ifdef PREFER_PORTABLE_GETCWD
__dso_public char *sudo_getcwd(char *, size_t size);
# undef getcwd
# define getcwd(_a, _b) sudo_getcwd((_a), (_b))
#endif /* PREFER_PORTABLE_GETCWD */
#ifndef HAVE_GETGROUPLIST
__dso_public int sudo_getgrouplist(const char *name, GETGROUPS_T basegid, GETGROUPS_T *groups, int *ngroupsp);
# undef getgrouplist
# define getgrouplist(_a, _b, _c, _d) sudo_getgrouplist((_a), (_b), (_c), (_d))
#endif /* GETGROUPLIST */
#ifndef HAVE_GETLINE
__dso_public ssize_t sudo_getline(char **bufp, size_t *bufsizep, FILE *fp);
# undef getline
# define getline(_a, _b, _c) sudo_getline((_a), (_b), (_c))
#endif /* HAVE_GETLINE */
#ifndef HAVE_UTIMENSAT
__dso_public int sudo_utimensat(int fd, const char *file, const struct timespec *times, int flag);
# undef utimensat
# define utimensat(_a, _b, _c, _d) sudo_utimensat((_a), (_b), (_c), (_d))
#endif /* HAVE_UTIMENSAT */
#ifndef HAVE_FUTIMENS
__dso_public int sudo_futimens(int fd, const struct timespec *times);
# undef futimens
# define futimens(_a, _b) sudo_futimens((_a), (_b))
#endif /* HAVE_FUTIMENS */
#if !defined(HAVE_SNPRINTF) || defined(PREFER_PORTABLE_SNPRINTF)
__dso_public int sudo_snprintf(char *str, size_t n, char const *fmt, ...) __printflike(3, 4);
# undef snprintf
# define snprintf sudo_snprintf
#endif /* HAVE_SNPRINTF */
#if !defined(HAVE_VSNPRINTF) || defined(PREFER_PORTABLE_SNPRINTF)
__dso_public int sudo_vsnprintf(char *str, size_t n, const char *fmt, va_list ap) __printflike(3, 0);
# undef vsnprintf
# define vsnprintf sudo_vsnprintf
#endif /* HAVE_VSNPRINTF */
#if !defined(HAVE_ASPRINTF) || defined(PREFER_PORTABLE_SNPRINTF)
__dso_public int sudo_asprintf(char **str, char const *fmt, ...) __printflike(2, 3);
# undef asprintf
# define asprintf sudo_asprintf
#endif /* HAVE_ASPRINTF */
#if !defined(HAVE_VASPRINTF) || defined(PREFER_PORTABLE_SNPRINTF)
__dso_public int sudo_vasprintf(char **str, const char *fmt, va_list ap) __printflike(2, 0);
# undef vasprintf
# define vasprintf sudo_vasprintf
#endif /* HAVE_VASPRINTF */
#ifndef HAVE_STRLCAT
__dso_public size_t sudo_strlcat(char *dst, const char *src, size_t siz);
# undef strlcat
# define strlcat(_a, _b, _c) sudo_strlcat((_a), (_b), (_c))
#endif /* HAVE_STRLCAT */
#ifndef HAVE_STRLCPY
__dso_public size_t sudo_strlcpy(char *dst, const char *src, size_t siz);
# undef strlcpy
# define strlcpy(_a, _b, _c) sudo_strlcpy((_a), (_b), (_c))
#endif /* HAVE_STRLCPY */
#ifndef HAVE_STRNDUP
__dso_public char *sudo_strndup(const char *str, size_t maxlen);
# undef strndup
# define strndup(_a, _b) sudo_strndup((_a), (_b))
#endif /* HAVE_STRNDUP */
#ifndef HAVE_STRNLEN
__dso_public size_t sudo_strnlen(const char *str, size_t maxlen);
# undef strnlen
# define strnlen(_a, _b) sudo_strnlen((_a), (_b))
#endif /* HAVE_STRNLEN */
#ifndef HAVE_MEMRCHR
__dso_public void *sudo_memrchr(const void *s, int c, size_t n);
# undef memrchr
# define memrchr(_a, _b, _c) sudo_memrchr((_a), (_b), (_c))
#endif /* HAVE_MEMRCHR */
#ifndef HAVE_MEMSET_S
__dso_public errno_t sudo_memset_s(void *v, rsize_t smax, int c, rsize_t n);
# undef memset_s
# define memset_s(_a, _b, _c, _d) sudo_memset_s((_a), (_b), (_c), (_d))
#endif /* HAVE_MEMSET_S */
#if !defined(HAVE_MKDTEMP) || !defined(HAVE_MKSTEMPS)
__dso_public char *sudo_mkdtemp(char *path);
# undef mkdtemp
# define mkdtemp(_a) sudo_mkdtemp((_a))
__dso_public int sudo_mkstemps(char *path, int slen);
# undef mkstemps
# define mkstemps(_a, _b) sudo_mkstemps((_a), (_b))
#endif /* !HAVE_MKDTEMP || !HAVE_MKSTEMPS */
#ifndef HAVE_NANOSLEEP
__dso_public int sudo_nanosleep(const struct timespec *timeout, struct timespec *remainder);
#undef nanosleep
# define nanosleep(_a, _b) sudo_nanosleep((_a), (_b))
#endif
#ifndef HAVE_PW_DUP
__dso_public struct passwd *sudo_pw_dup(const struct passwd *pw);
# undef pw_dup
# define pw_dup(_a) sudo_pw_dup((_a))
#endif /* HAVE_PW_DUP */
#ifndef HAVE_STRSIGNAL
__dso_public char *sudo_strsignal(int signo);
# undef strsignal
# define strsignal(_a) sudo_strsignal((_a))
#endif /* HAVE_STRSIGNAL */
#ifndef HAVE_SIG2STR
__dso_public int sudo_sig2str(int signo, char *signame);
# undef sig2str
# define sig2str(_a, _b) sudo_sig2str((_a), (_b))
#endif /* HAVE_SIG2STR */
#if !defined(HAVE_INET_NTOP) && defined(SUDO_NET_IFS_C)
__dso_public char *sudo_inet_ntop(int af, const void *src, char *dst, socklen_t size);
# undef inet_ntop
# define inet_ntop(_a, _b, _c, _d) sudo_inet_ntop((_a), (_b), (_c), (_d))
#endif /* HAVE_INET_NTOP */
#ifndef HAVE_INET_PTON
__dso_public int sudo_inet_pton(int af, const char *src, void *dst);
# undef inet_pton
# define inet_pton(_a, _b, _c) sudo_inet_pton((_a), (_b), (_c))
#endif /* HAVE_INET_PTON */
#ifndef HAVE_GETPROGNAME
__dso_public const char *sudo_getprogname(void);
# undef getprogname
# define getprogname() sudo_getprogname()
#endif /* HAVE_GETPROGNAME */
#ifndef HAVE_REALLOCARRAY
__dso_public void *sudo_reallocarray(void *ptr, size_t nmemb, size_t size);
# undef reallocarray
# define reallocarray(_a, _b, _c) sudo_reallocarray((_a), (_b), (_c))
#endif /* HAVE_REALLOCARRAY */
#ifndef HAVE_VSYSLOG
__dso_public void sudo_vsyslog(int pri, const char *fmt, va_list ap);
# undef vsyslog
# define vsyslog(_a, _b, _c) sudo_vsyslog((_a), (_b), (_c))
#endif /* HAVE_VSYSLOG */
#ifndef HAVE_PIPE2
__dso_public int sudo_pipe2(int fildes[2], int flags);
# undef pipe2
# define pipe2(_a, _b) sudo_pipe2((_a), (_b))
#endif /* HAVE_PIPE2 */

#endif /* SUDO_COMPAT_H */
