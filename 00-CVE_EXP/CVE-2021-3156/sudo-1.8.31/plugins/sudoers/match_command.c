/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1996, 1998-2005, 2007-2019
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#ifdef HAVE_GLOB
# include <glob.h>
#else
# include "compat/glob.h"
#endif /* HAVE_GLOB */
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>

#include "sudoers.h"
#include <gram.h>

#ifdef HAVE_FNMATCH
# include <fnmatch.h>
#else
# include "compat/fnmatch.h"
#endif /* HAVE_FNMATCH */

#if !defined(O_EXEC) && defined(O_PATH)
# define O_EXEC O_PATH
#endif

static bool
command_args_match(const char *sudoers_cmnd, const char *sudoers_args)
{
    int flags = 0;
    debug_decl(command_args_match, SUDOERS_DEBUG_MATCH)

    /*
     * If no args specified in sudoers, any user args are allowed.
     * If the empty string is specified in sudoers, no user args are allowed.
     */
    if (!sudoers_args || (!user_args && !strcmp("\"\"", sudoers_args)))
	debug_return_bool(true);

    /*
     * If args are specified in sudoers, they must match the user args.
     * If running as sudoedit, all args are assumed to be paths.
     */
    if (strcmp(sudoers_cmnd, "sudoedit") == 0)
	flags = FNM_PATHNAME;
    if (fnmatch(sudoers_args, user_args ? user_args : "", flags) == 0)
	debug_return_bool(true);

    debug_return_bool(false);
}

/*
 * Stat file by fd is possible, else by path.
 * Returns true on success, else false.
 */
static bool
do_stat(int fd, const char *path, struct stat *sb)
{
    debug_decl(do_stat, SUDOERS_DEBUG_MATCH)

    if (fd != -1)
	debug_return_bool(fstat(fd, sb) == 0);
    debug_return_bool(stat(path, sb) == 0);
}

/*
 * Check whether the fd refers to a shell script with a "#!" shebang.
 */
static bool
is_script(int fd)
{
    bool ret = false;
    char magic[2];
    debug_decl(is_script, SUDOERS_DEBUG_MATCH)

    if (read(fd, magic, 2) == 2) {
	if (magic[0] == '#' && magic[1] == '!')
	    ret = true;
    }
    if (lseek(fd, (off_t)0, SEEK_SET) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
	    "unable to rewind script fd");
    }
    debug_return_int(ret);
}

/*
 * Open path if fdexec is enabled or if a digest is present.
 * Returns false on error, else true.
 */
static bool
open_cmnd(const char *path, const struct command_digest *digest, int *fdp)
{
    int fd = -1;
    debug_decl(open_cmnd, SUDOERS_DEBUG_MATCH)

    /* Only open the file for fdexec or for digest matching. */
    if (def_fdexec != always && digest == NULL)
	debug_return_bool(true);

    fd = open(path, O_RDONLY|O_NONBLOCK);
# ifdef O_EXEC
    if (fd == -1 && errno == EACCES && digest == NULL) {
	/* Try again with O_EXEC if no digest is specified. */
	const int saved_errno = errno;
	if ((fd = open(path, O_EXEC)) == -1)
	    errno = saved_errno;
    }
# endif
    if (fd == -1)
	debug_return_bool(false);

    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    *fdp = fd;
    debug_return_bool(true);
}

static void
set_cmnd_fd(int fd)
{
    debug_decl(set_cmnd_fd, SUDOERS_DEBUG_MATCH)

    if (cmnd_fd != -1)
	close(cmnd_fd);

    if (fd != -1) {
	if (def_fdexec == never) {
	    /* Never use fexedcve() */
	    close(fd);
	    fd = -1;
	} else if (is_script(fd)) {
	    char fdpath[PATH_MAX];
	    struct stat sb;
	    int flags;

	    /* We can only use fexecve() on a script if /dev/fd/N exists. */
	    (void)snprintf(fdpath, sizeof(fdpath), "/dev/fd/%d", fd);
	    if (stat(fdpath, &sb) != 0) {
		/* Missing /dev/fd file, can't use fexecve(). */
		close(fd);
		fd = -1;
	    } else {
		/*
		 * Shell scripts go through namei twice so we can't have the
		 * close on exec flag set on the fd for fexecve(2).
		 */
		flags = fcntl(fd, F_GETFD) & ~FD_CLOEXEC;
		(void)fcntl(fd, F_SETFD, flags);
	    }
	}
    }

    cmnd_fd = fd;

    debug_return;
}

/*
 * Return true if user_cmnd names one of the inodes in dir, else false.
 */
static bool
command_matches_dir(const char *sudoers_dir, size_t dlen,
    const struct command_digest *digest)
{
    struct stat sudoers_stat;
    struct dirent *dent;
    char buf[PATH_MAX];
    int fd = -1;
    DIR *dirp;
    debug_decl(command_matches_dir, SUDOERS_DEBUG_MATCH)

    /*
     * Grot through directory entries, looking for user_base.
     */
    dirp = opendir(sudoers_dir);
    if (dirp == NULL)
	debug_return_bool(false);

    if (strlcpy(buf, sudoers_dir, sizeof(buf)) >= sizeof(buf)) {
	closedir(dirp);
	debug_return_bool(false);
    }
    while ((dent = readdir(dirp)) != NULL) {
	if (fd != -1) {
	    close(fd);
	    fd = -1;
	}

	/* ignore paths > PATH_MAX (XXX - log) */
	buf[dlen] = '\0';
	if (strlcat(buf, dent->d_name, sizeof(buf)) >= sizeof(buf))
	    continue;

	/* only stat if basenames are the same */
	if (strcmp(user_base, dent->d_name) != 0)
	    continue;

	/* Open the file for fdexec or for digest matching. */
	if (!open_cmnd(buf, digest, &fd))
	    continue;
	if (!do_stat(fd, buf, &sudoers_stat))
	    continue;

	if (user_stat == NULL ||
	    (user_stat->st_dev == sudoers_stat.st_dev &&
	    user_stat->st_ino == sudoers_stat.st_ino)) {
	    if (digest != NULL && !digest_matches(fd, buf, digest))
		continue;
	    free(safe_cmnd);
	    if ((safe_cmnd = strdup(buf)) == NULL) {
		sudo_warnx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
		dent = NULL;
	    }
	    break;
	}
    }
    closedir(dirp);

    if (dent != NULL) {
	set_cmnd_fd(fd);
	debug_return_bool(true);
    }
    if (fd != -1)
	close(fd);
    debug_return_bool(false);
}

static bool
command_matches_fnmatch(const char *sudoers_cmnd, const char *sudoers_args,
    const struct command_digest *digest)
{
    struct stat sb; /* XXX - unused */
    int fd = -1;
    debug_decl(command_matches_fnmatch, SUDOERS_DEBUG_MATCH)

    /*
     * Return true if fnmatch(3) succeeds AND
     *  a) there are no args in sudoers OR
     *  b) there are no args on command line and none required by sudoers OR
     *  c) there are args in sudoers and on command line and they match
     * else return false.
     */
    if (fnmatch(sudoers_cmnd, user_cmnd, FNM_PATHNAME) != 0)
	debug_return_bool(false);
    if (command_args_match(sudoers_cmnd, sudoers_args)) {
	/* Open the file for fdexec or for digest matching. */
	if (!open_cmnd(user_cmnd, digest, &fd))
	    goto bad;
	if (!do_stat(fd, user_cmnd, &sb))
	    goto bad;
	/* Check digest of user_cmnd since sudoers_cmnd is a pattern. */
	if (digest != NULL && !digest_matches(fd, user_cmnd, digest))
	    goto bad;
	set_cmnd_fd(fd);

	/* No need to set safe_cmnd since user_cmnd matches sudoers_cmnd */
	debug_return_bool(true);
bad:
	if (fd != -1) {
	    close(fd);
	    fd = -1;
	}
	debug_return_bool(false);
    }
    debug_return_bool(false);
}

static bool
command_matches_glob(const char *sudoers_cmnd, const char *sudoers_args,
    const struct command_digest *digest)
{
    struct stat sudoers_stat;
    bool bad_digest = false;
    char **ap, *base, *cp;
    int fd = -1;
    size_t dlen;
    glob_t gl;
    debug_decl(command_matches_glob, SUDOERS_DEBUG_MATCH)

    /*
     * First check to see if we can avoid the call to glob(3).
     * Short circuit if there are no meta chars in the command itself
     * and user_base and basename(sudoers_cmnd) don't match.
     */
    dlen = strlen(sudoers_cmnd);
    if (sudoers_cmnd[dlen - 1] != '/') {
	if ((base = strrchr(sudoers_cmnd, '/')) != NULL) {
	    base++;
	    if (!has_meta(base) && strcmp(user_base, base) != 0)
		debug_return_bool(false);
	}
    }
    /*
     * Return true if we find a match in the glob(3) results AND
     *  a) there are no args in sudoers OR
     *  b) there are no args on command line and none required by sudoers OR
     *  c) there are args in sudoers and on command line and they match
     * else return false.
     */
    if (glob(sudoers_cmnd, GLOB_NOSORT, NULL, &gl) != 0 || gl.gl_pathc == 0) {
	globfree(&gl);
	debug_return_bool(false);
    }
    /* If user_cmnd is fully-qualified, check for an exact match. */
    if (user_cmnd[0] == '/') {
	for (ap = gl.gl_pathv; (cp = *ap) != NULL; ap++) {
	    if (fd != -1) {
		close(fd);
		fd = -1;
	    }
	    if (strcmp(cp, user_cmnd) != 0)
		continue;
	    /* Open the file for fdexec or for digest matching. */
	    if (!open_cmnd(cp, digest, &fd))
		continue;
	    if (!do_stat(fd, cp, &sudoers_stat))
		continue;
	    if (user_stat == NULL ||
		(user_stat->st_dev == sudoers_stat.st_dev &&
		user_stat->st_ino == sudoers_stat.st_ino)) {
		/* There could be multiple matches, check digest early. */
		if (digest != NULL && !digest_matches(fd, cp, digest)) {
		    bad_digest = true;
		    continue;
		}
		free(safe_cmnd);
		if ((safe_cmnd = strdup(cp)) == NULL) {
		    sudo_warnx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		    cp = NULL;		/* fail closed */
		}
	    } else {
		/* Paths match, but st_dev and st_ino are different. */
		cp = NULL;		/* fail closed */
	    }
	    goto done;
	}
    }
    /* No exact match, compare basename, st_dev and st_ino. */
    if (!bad_digest) {
	for (ap = gl.gl_pathv; (cp = *ap) != NULL; ap++) {
	    if (fd != -1) {
		close(fd);
		fd = -1;
	    }

	    /* If it ends in '/' it is a directory spec. */
	    dlen = strlen(cp);
	    if (cp[dlen - 1] == '/') {
		if (command_matches_dir(cp, dlen, digest))
		    debug_return_bool(true);
		continue;
	    }

	    /* Only proceed if user_base and basename(cp) match */
	    if ((base = strrchr(cp, '/')) != NULL)
		base++;
	    else
		base = cp;
	    if (strcmp(user_base, base) != 0)
		continue;

	    /* Open the file for fdexec or for digest matching. */
	    if (!open_cmnd(cp, digest, &fd))
		continue;
	    if (!do_stat(fd, cp, &sudoers_stat))
		continue;
	    if (user_stat == NULL ||
		(user_stat->st_dev == sudoers_stat.st_dev &&
		user_stat->st_ino == sudoers_stat.st_ino)) {
		if (digest != NULL && !digest_matches(fd, cp, digest))
		    continue;
		free(safe_cmnd);
		if ((safe_cmnd = strdup(cp)) == NULL) {
		    sudo_warnx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		    cp = NULL;		/* fail closed */
		}
		goto done;
	    }
	}
    }
done:
    globfree(&gl);
    if (cp != NULL) {
	if (command_args_match(sudoers_cmnd, sudoers_args)) {
	    /* safe_cmnd was set above. */
	    set_cmnd_fd(fd);
	    debug_return_bool(true);
	}
    }
    if (fd != -1)
	close(fd);
    debug_return_bool(false);
}

static bool
command_matches_normal(const char *sudoers_cmnd, const char *sudoers_args, const struct command_digest *digest)
{
    struct stat sudoers_stat;
    const char *base;
    size_t dlen;
    int fd = -1;
    debug_decl(command_matches_normal, SUDOERS_DEBUG_MATCH)

    /* If it ends in '/' it is a directory spec. */
    dlen = strlen(sudoers_cmnd);
    if (sudoers_cmnd[dlen - 1] == '/')
	debug_return_bool(command_matches_dir(sudoers_cmnd, dlen, digest));

    /* Only proceed if user_base and basename(sudoers_cmnd) match */
    if ((base = strrchr(sudoers_cmnd, '/')) == NULL)
	base = sudoers_cmnd;
    else
	base++;
    if (strcmp(user_base, base) != 0)
	debug_return_bool(false);

    /* Open the file for fdexec or for digest matching. */
    if (!open_cmnd(sudoers_cmnd, digest, &fd))
	goto bad;

    /*
     * Return true if command matches AND
     *  a) there are no args in sudoers OR
     *  b) there are no args on command line and none req by sudoers OR
     *  c) there are args in sudoers and on command line and they match
     *  d) there is a digest and it matches
     */
    if (user_stat != NULL && do_stat(fd, sudoers_cmnd, &sudoers_stat)) {
	if (user_stat->st_dev != sudoers_stat.st_dev ||
	    user_stat->st_ino != sudoers_stat.st_ino)
	    goto bad;
    } else {
	/* Either user or sudoers command does not exist, match by name. */
	if (strcmp(user_cmnd, sudoers_cmnd) != 0)
	    goto bad;
    }
    if (!command_args_match(sudoers_cmnd, sudoers_args))
	goto bad;
    if (digest != NULL && !digest_matches(fd, sudoers_cmnd, digest)) {
	/* XXX - log functions not available but we should log very loudly */
	goto bad;
    }
    free(safe_cmnd);
    if ((safe_cmnd = strdup(sudoers_cmnd)) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto bad;
    }
    set_cmnd_fd(fd);
    debug_return_bool(true);
bad:
    if (fd != -1)
	close(fd);
    debug_return_bool(false);
}

/*
 * If path doesn't end in /, return true iff cmnd & path name the same inode;
 * otherwise, return true if user_cmnd names one of the inodes in path.
 */
bool
command_matches(const char *sudoers_cmnd, const char *sudoers_args, const struct command_digest *digest)
{
    bool rc = false;
    debug_decl(command_matches, SUDOERS_DEBUG_MATCH)

    /* Check for pseudo-commands */
    if (sudoers_cmnd[0] != '/') {
	/*
	 * Return true if both sudoers_cmnd and user_cmnd are "sudoedit" AND
	 *  a) there are no args in sudoers OR
	 *  b) there are no args on command line and none req by sudoers OR
	 *  c) there are args in sudoers and on command line and they match
	 */
	if (strcmp(sudoers_cmnd, "sudoedit") == 0 &&
	    strcmp(user_cmnd, "sudoedit") == 0 &&
	    command_args_match(sudoers_cmnd, sudoers_args)) {
	    /* No need to set safe_cmnd since user_cmnd matches sudoers_cmnd */
	    rc = true;
	}
	goto done;
    }

    if (has_meta(sudoers_cmnd)) {
	/*
	 * If sudoers_cmnd has meta characters in it, we need to
	 * use glob(3) and/or fnmatch(3) to do the matching.
	 */
	if (def_fast_glob)
	    rc = command_matches_fnmatch(sudoers_cmnd, sudoers_args, digest);
	else
	    rc = command_matches_glob(sudoers_cmnd, sudoers_args, digest);
    } else {
	rc = command_matches_normal(sudoers_cmnd, sudoers_args, digest);
    }
done:
    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"user command \"%s%s%s\" matches sudoers command \"%s%s%s\": %s",
	user_cmnd, user_args ? " " : "", user_args ? user_args : "",
	sudoers_cmnd, sudoers_args ? " " : "", sudoers_args ? sudoers_args : "",
	rc ? "true" : "false");
    debug_return_bool(rc);
}
