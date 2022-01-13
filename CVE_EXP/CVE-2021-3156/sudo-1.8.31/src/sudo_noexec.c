/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2004-2005, 2010-2018 Todd C. Miller <Todd.Miller@sudo.ws>
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
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <sys/types.h>

#if defined(HAVE_DECL_SECCOMP_SET_MODE_FILTER) && HAVE_DECL_SECCOMP_SET_MODE_FILTER
# include <sys/prctl.h>
# include <asm/unistd.h>
# include <linux/filter.h>
# include <linux/seccomp.h>
#endif

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#ifdef HAVE_SPAWN_H
#include <spawn.h>
#endif
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_WORDEXP_H
#include <wordexp.h>
#endif
#if defined(HAVE_SHL_LOAD)
# include <dl.h>
#elif defined(HAVE_DLOPEN)
# include <dlfcn.h>
#endif

#include "sudo_compat.h"
#include "pathnames.h"

#ifdef HAVE___INTERPOSE
/*
 * Mac OS X 10.4 and above has support for library symbol interposition.
 * There is a good explanation of this in the Mac OS X Internals book.
 */
typedef struct interpose_s {
    void *new_func;
    void *orig_func;
} interpose_t;

# define FN_NAME(fn)	dummy_ ## fn
# define INTERPOSE(fn) \
    __attribute__((__used__)) static const interpose_t interpose_ ## fn \
    __attribute__((__section__("__DATA,__interpose"))) = \
	{ (void *)dummy_ ## fn, (void *)fn };
#else
# define FN_NAME(fn)	fn
# define INTERPOSE(fn)
#endif

/*
 * Dummy versions of the exec(3) family of syscalls.  It is not enough to
 * just dummy out execve(2) since many C libraries do not call the public
 * execve(2) interface.  Note that it is still possible to access the real
 * syscalls via the syscall(2) interface, but that is rarely done.
 */

#define DUMMY_BODY				\
{						\
    errno = EACCES;				\
    return -1;					\
}

#define DUMMY1(fn, t1)				\
__dso_public int				\
FN_NAME(fn)(t1 a1)				\
DUMMY_BODY					\
INTERPOSE(fn)

#define DUMMY2(fn, t1, t2)			\
__dso_public int				\
FN_NAME(fn)(t1 a1, t2 a2)			\
DUMMY_BODY					\
INTERPOSE(fn)

#define DUMMY3(fn, t1, t2, t3)			\
__dso_public int				\
FN_NAME(fn)(t1 a1, t2 a2, t3 a3)		\
DUMMY_BODY					\
INTERPOSE(fn)

#define DUMMY6(fn, t1, t2, t3, t4, t5, t6)	\
__dso_public int				\
FN_NAME(fn)(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6)	\
DUMMY_BODY					\
INTERPOSE(fn)

#define DUMMY_VA(fn, t1, t2)			\
__dso_public int				\
FN_NAME(fn)(t1 a1, t2 a2, ...)			\
DUMMY_BODY					\
INTERPOSE(fn)

/*
 * Standard exec(3) family of functions.
 */
DUMMY_VA(execl, const char *, const char *)
DUMMY_VA(execle, const char *, const char *)
DUMMY_VA(execlp, const char *, const char *)
DUMMY2(execv, const char *, char * const *)
DUMMY2(execvp, const char *, char * const *)
DUMMY3(execve, const char *, char * const *, char * const *)

/*
 * Non-standard exec(3) functions and corresponding private versions.
 */
#ifdef HAVE_EXECVP
DUMMY3(execvP, const char *, const char *, char * const *)
#endif
#ifdef HAVE_EXECVPE
DUMMY3(execvpe, const char *, char * const *, char * const *)
#endif
#ifdef HAVE_EXECT
DUMMY3(exect, const char *, char * const *, char * const *)
#endif

/*
 * Not all systems support fexecve(2), posix_spawn(2) and posix_spawnp(2).
 */
#ifdef HAVE_FEXECVE
DUMMY3(fexecve, int , char * const *, char * const *)
#endif
#ifdef HAVE_POSIX_SPAWN
DUMMY6(posix_spawn, pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char * const *, char * const *)
#endif
#ifdef HAVE_POSIX_SPAWNP
DUMMY6(posix_spawnp, pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char * const *, char * const *)
#endif

/*
 * system(3) and popen(3).
 * We can't use a wrapper for popen since it returns FILE *, not int.
 */
DUMMY1(system, const char *)

__dso_public FILE *
FN_NAME(popen)(const char *c, const char *t)
{
    errno = EACCES;
    return NULL;
}
INTERPOSE(popen)

#if defined(HAVE_WORDEXP) && (defined(RTLD_NEXT) || defined(HAVE_SHL_LOAD) || defined(HAVE___INTERPOSE))
/*
 * We can't use a wrapper for wordexp(3) since we still want to call
 * the real wordexp(3) but with WRDE_NOCMD added to the flags argument.
 */
typedef int (*sudo_fn_wordexp_t)(const char *, wordexp_t *, int);

__dso_public int
FN_NAME(wordexp)(const char *words, wordexp_t *we, int flags)
{
#if defined(HAVE___INTERPOSE)
    return wordexp(words, we, flags | WRDE_NOCMD);
#else
# if defined(HAVE_DLOPEN)
    void *fn = dlsym(RTLD_NEXT, "wordexp");
# elif defined(HAVE_SHL_LOAD)
    const char *name, *myname = _PATH_SUDO_NOEXEC;
    struct shl_descriptor *desc;
    void *fn = NULL;
    int idx = 0;

    name = strrchr(myname, '/');
    if (name != NULL)
	myname = name + 1;

    /* Search for wordexp() but skip this shared object. */
    while (shl_get(idx++, &desc) == 0) {
	name = strrchr(desc->filename, '/');
	if (name == NULL)
		name = desc->filename;
	else
		name++;
	if (strcmp(name, myname) == 0)
	    continue;
	if (shl_findsym(&desc->handle, "wordexp", TYPE_PROCEDURE, &fn) == 0)
	    break;
    }
# else
    void *fn = NULL;
# endif
    if (fn == NULL) {
	errno = EACCES;
	return -1;
    }
    return ((sudo_fn_wordexp_t)fn)(words, we, flags | WRDE_NOCMD);
#endif /* HAVE___INTERPOSE */
}
INTERPOSE(wordexp)
#endif /* HAVE_WORDEXP && (RTLD_NEXT || HAVE_SHL_LOAD || HAVE___INTERPOSE) */

/*
 * On Linux we can use a seccomp() filter to disable exec.
 */
#if defined(HAVE_DECL_SECCOMP_SET_MODE_FILTER) && HAVE_DECL_SECCOMP_SET_MODE_FILTER

/* Older systems may not support execveat(2). */
#ifndef __NR_execveat
# define __NR_execveat -1
#endif

static void noexec_ctor(void) __attribute__((constructor));

static void
noexec_ctor(void)
{
    struct sock_filter exec_filter[] = {
	/* Load syscall number into the accumulator */
	BPF_STMT(BPF_LD | BPF_ABS, offsetof(struct seccomp_data, nr)),
	/* Jump to deny for execve/execveat */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 2, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 1, 0),
	/* Allow non-matching syscalls */
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	/* Deny execve/execveat syscall */
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA))
    };
    const struct sock_fprog exec_fprog = {
	nitems(exec_filter),
	exec_filter
    };

    /*
     * SECCOMP_MODE_FILTER will fail unless the process has
     * CAP_SYS_ADMIN or the no_new_privs bit is set.
     */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0)
	(void)prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &exec_fprog);
}
#endif /* HAVE_DECL_SECCOMP_SET_MODE_FILTER */
