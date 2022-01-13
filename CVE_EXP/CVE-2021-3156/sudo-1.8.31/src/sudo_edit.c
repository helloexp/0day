/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2004-2008, 2010-2018 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include "sudo.h"
#include "sudo_exec.h"

#if defined(HAVE_SETRESUID) || defined(HAVE_SETREUID) || defined(HAVE_SETEUID)

/*
 * Editor temporary file name along with original name, mtime and size.
 */
struct tempfile {
    char *tfile;
    char *ofile;
    off_t osize;
    struct timespec omtim;
};

static char edit_tmpdir[MAX(sizeof(_PATH_VARTMP), sizeof(_PATH_TMP))];

static void
switch_user(uid_t euid, gid_t egid, int ngroups, GETGROUPS_T *groups)
{
    int serrno = errno;
    debug_decl(switch_user, SUDO_DEBUG_EDIT)

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"set uid:gid to %u:%u(%u)", (unsigned int)euid, (unsigned int)egid,
	ngroups ? (unsigned int)groups[0] : (unsigned int)egid);

    /* When restoring root, change euid first; otherwise change it last. */
    if (euid == ROOT_UID) {
	if (seteuid(ROOT_UID) != 0)
	    sudo_fatal("seteuid(ROOT_UID)");
    }
    if (setegid(egid) != 0)
	sudo_fatal("setegid(%d)", (int)egid);
    if (ngroups != -1) {
	if (sudo_setgroups(ngroups, groups) != 0)
	    sudo_fatal("setgroups");
    }
    if (euid != ROOT_UID) {
	if (seteuid(euid) != 0)
	    sudo_fatal("seteuid(%u)", (unsigned int)euid);
    }
    errno = serrno;

    debug_return;
}

#ifdef HAVE_FACCESSAT
/*
 * Returns true if the open directory fd is owned or writable by the user.
 */
static int
dir_is_writable(int dfd, struct user_details *ud, struct command_details *cd)
{
    struct stat sb;
    int rc;
    debug_decl(dir_is_writable, SUDO_DEBUG_EDIT)

    if (fstat(dfd, &sb) == -1)
	debug_return_int(-1);

    /* If the user owns the dir we always consider it writable. */
    if (sb.st_uid == ud->uid) {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "user uid %u matches directory uid %u", (unsigned int)ud->uid,
	    (unsigned int)sb.st_uid);
	debug_return_int(true);
    }

    /* Change uid/gid/groups to invoking user, usually needs root perms. */
    if (cd->euid != ROOT_UID) {
	if (seteuid(ROOT_UID) != 0)
	    sudo_fatal("seteuid(ROOT_UID)");
    }
    switch_user(ud->uid, ud->gid, ud->ngroups, ud->groups);

    /* Access checks are done using the euid/egid and group vector. */
    rc = faccessat(dfd, ".", W_OK, AT_EACCESS);

    /* Change uid/gid/groups back to target user, may need root perms. */
    if (ud->uid != ROOT_UID) {
	if (seteuid(ROOT_UID) != 0)
	    sudo_fatal("seteuid(ROOT_UID)");
    }
    switch_user(cd->euid, cd->egid, cd->ngroups, cd->groups);

    if (rc == 0)
	debug_return_int(true);
    if (errno == EACCES || errno == EROFS)
	debug_return_int(false);
    debug_return_int(-1);
}
#else
static bool
group_matches(gid_t target, gid_t gid, int ngroups, GETGROUPS_T *groups)
{
    int i;
    debug_decl(group_matches, SUDO_DEBUG_EDIT)

    if (target == gid) {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "user gid %u matches directory gid %u", (unsigned int)gid,
	    (unsigned int)target);
	debug_return_bool(true);
    }
    for (i = 0; i < ngroups; i++) {
	if (target == groups[i]) {
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"user gid %u matches directory gid %u", (unsigned int)gid,
		(unsigned int)target);
	    debug_return_bool(true);
	}
    }
    debug_return_bool(false);
}

/*
 * Returns true if the open directory fd is owned or writable by the user.
 */
static int
dir_is_writable(int dfd, struct user_details *ud, struct command_details *cd)
{
    struct stat sb;
    debug_decl(dir_is_writable, SUDO_DEBUG_EDIT)

    if (fstat(dfd, &sb) == -1)
	debug_return_int(-1);

    /* If the user owns the dir we always consider it writable. */
    if (sb.st_uid == ud->uid) {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "user uid %u matches directory uid %u", (unsigned int)ud->uid,
	    (unsigned int)sb.st_uid);
	debug_return_int(true);
    }

    /* Other writable? */
    if (ISSET(sb.st_mode, S_IWOTH)) {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "directory is writable by other");
	debug_return_int(true);
    }

    /* Group writable? */
    if (ISSET(sb.st_mode, S_IWGRP)) {
	if (group_matches(sb.st_gid, ud->gid, ud->ngroups, ud->groups)) {
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"directory is writable by one of the user's groups");
	    debug_return_int(true);
	}
    }

    errno = EACCES;
    debug_return_int(false);
}
#endif /* HAVE_FACCESSAT */

/*
 * Find our temporary directory, one of /var/tmp, /usr/tmp, or /tmp
 * Returns true on success, else false;
 */
static bool
set_tmpdir(struct command_details *command_details)
{
    const char *tdir = NULL;
    const char *tmpdirs[] = {
	_PATH_VARTMP,
#ifdef _PATH_USRTMP
	_PATH_USRTMP,
#endif
	_PATH_TMP
    };
    unsigned int i;
    size_t len;
    int dfd;
    debug_decl(set_tmpdir, SUDO_DEBUG_EDIT)

    for (i = 0; tdir == NULL && i < nitems(tmpdirs); i++) {
	if ((dfd = open(tmpdirs[i], O_RDONLY)) != -1) {
	    if (dir_is_writable(dfd, &user_details, command_details) == true)
		tdir = tmpdirs[i];
	    close(dfd);
	}
    }
    if (tdir == NULL)
	sudo_fatalx(U_("no writable temporary directory found"));
   
    len = strlcpy(edit_tmpdir, tdir, sizeof(edit_tmpdir));
    if (len >= sizeof(edit_tmpdir)) {
	errno = ENAMETOOLONG;
	sudo_warn("%s", tdir);
	debug_return_bool(false);
    }
    while (len > 0 && edit_tmpdir[--len] == '/')
	edit_tmpdir[len] = '\0';
    debug_return_bool(true);
}

/*
 * Construct a temporary file name for file and return an
 * open file descriptor.  The temporary file name is stored
 * in tfile which the caller is responsible for freeing.
 */
static int
sudo_edit_mktemp(const char *ofile, char **tfile)
{
    const char *cp, *suff;
    int len, tfd;
    debug_decl(sudo_edit_mktemp, SUDO_DEBUG_EDIT)

    if ((cp = strrchr(ofile, '/')) != NULL)
	cp++;
    else
	cp = ofile;
    suff = strrchr(cp, '.');
    if (suff != NULL) {
	len = asprintf(tfile, "%s/%.*sXXXXXXXX%s", edit_tmpdir,
	    (int)(size_t)(suff - cp), cp, suff);
    } else {
	len = asprintf(tfile, "%s/%s.XXXXXXXX", edit_tmpdir, cp);
    }
    if (len == -1)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    tfd = mkstemps(*tfile, suff ? strlen(suff) : 0);
    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"%s -> %s, fd %d", ofile, *tfile, tfd);
    debug_return_int(tfd);
}

#ifndef HAVE_OPENAT
static int
sudo_openat(int dfd, const char *path, int flags, mode_t mode)
{
    int fd, odfd;
    debug_decl(sudo_openat, SUDO_DEBUG_EDIT)

    if (dfd == AT_FDCWD)
	debug_return_int(open(path, flags, mode));

    /* Save cwd */
    if ((odfd = open(".", O_RDONLY)) == -1)
	debug_return_int(-1);

    if (fchdir(dfd) == -1) {
	close(odfd);
	debug_return_int(-1);
    }

    fd = open(path, flags, mode);

    /* Restore cwd */
    if (fchdir(odfd) == -1)
	sudo_fatal(U_("unable to restore current working directory"));
    close(odfd);

    debug_return_int(fd);
}
#define openat sudo_openat
#endif /* HAVE_OPENAT */

#ifdef O_NOFOLLOW
static int
sudo_edit_openat_nofollow(int dfd, char *path, int oflags, mode_t mode)
{
    debug_decl(sudo_edit_openat_nofollow, SUDO_DEBUG_EDIT)

    debug_return_int(openat(dfd, path, oflags|O_NOFOLLOW, mode));
}
#else
/*
 * Returns true if fd and path don't match or path is a symlink.
 * Used on older systems without O_NOFOLLOW.
 */
static bool
sudo_edit_is_symlink(int fd, char *path)
{
    struct stat sb1, sb2;
    debug_decl(sudo_edit_is_symlink, SUDO_DEBUG_EDIT)

    /*
     * Treat [fl]stat() failure like there was a symlink.
     */
    if (fstat(fd, &sb1) == -1 || lstat(path, &sb2) == -1)
	debug_return_bool(true);

    /*
     * Make sure we did not open a link and that what we opened
     * matches what is currently on the file system.
     */
    if (S_ISLNK(sb2.st_mode) ||
	sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino) {
	debug_return_bool(true);
    }

    debug_return_bool(false);
}

static int
sudo_edit_openat_nofollow(int dfd, char *path, int oflags, mode_t mode)
{
    int fd = -1, odfd = -1;
    struct stat sb;
    debug_decl(sudo_edit_openat_nofollow, SUDO_DEBUG_EDIT)

    /* Save cwd and chdir to dfd */
    if ((odfd = open(".", O_RDONLY)) == -1)
	debug_return_int(-1);
    if (fchdir(dfd) == -1) {
	close(odfd);
	debug_return_int(-1);
    }

    /*
     * Check if path is a symlink.  This is racey but we detect whether
     * we lost the race in sudo_edit_is_symlink() after the open.
     */
    if (lstat(path, &sb) == -1 && errno != ENOENT)
	goto done;
    if (S_ISLNK(sb.st_mode)) {
	errno = ELOOP;
	goto done;
    }

    fd = open(path, oflags, mode);
    if (fd == -1)
	goto done;

    /*
     * Post-open symlink check.  This will leave a zero-length file if
     * O_CREAT was specified but it is too dangerous to try and remove it.
     */
    if (sudo_edit_is_symlink(fd, path)) {
	close(fd);
	fd = -1;
	errno = ELOOP;
    }

done:
    /* Restore cwd */
    if (odfd != -1) {
	if (fchdir(odfd) == -1)
	    sudo_fatal(U_("unable to restore current working directory"));
	close(odfd);
    }

    debug_return_int(fd);
}
#endif /* O_NOFOLLOW */

/*
 * Directory open flags for use with openat(2).
 * Use O_SEARCH/O_PATH and/or O_DIRECTORY where possible.
 */
#if defined(O_SEARCH)
# if defined(O_DIRECTORY)
#  define DIR_OPEN_FLAGS	(O_SEARCH|O_DIRECTORY)
# else
#  define DIR_OPEN_FLAGS	(O_SEARCH)
# endif
#elif defined(O_PATH)
# if defined(O_DIRECTORY)
#  define DIR_OPEN_FLAGS	(O_PATH|O_DIRECTORY)
# else
#  define DIR_OPEN_FLAGS	(O_PATH)
# endif
#elif defined(O_DIRECTORY)
# define DIR_OPEN_FLAGS		(O_RDONLY|O_DIRECTORY)
#else
# define DIR_OPEN_FLAGS		(O_RDONLY|O_NONBLOCK)
#endif

static int
sudo_edit_open_nonwritable(char *path, int oflags, mode_t mode,
    struct command_details *command_details)
{
    const int dflags = DIR_OPEN_FLAGS;
    int dfd, fd, is_writable;
    debug_decl(sudo_edit_open_nonwritable, SUDO_DEBUG_EDIT)

    if (path[0] == '/') {
	dfd = open("/", dflags);
	path++;
    } else {
	dfd = open(".", dflags);
	if (path[0] == '.' && path[1] == '/')
	    path += 2;
    }
    if (dfd == -1)
	debug_return_int(-1);

    for (;;) {
	char *slash;
	int subdfd;

	/*
	 * Look up one component at a time, avoiding symbolic links in
	 * writable directories.
	 */
	is_writable = dir_is_writable(dfd, &user_details, command_details);
	if (is_writable == -1) {
	    close(dfd);
	    debug_return_int(-1);
	}

	while (path[0] == '/')
	    path++;
	slash = strchr(path, '/');
	if (slash == NULL)
	    break;
	*slash = '\0';
	if (is_writable)
	    subdfd = sudo_edit_openat_nofollow(dfd, path, dflags, 0);
	else
	    subdfd = openat(dfd, path, dflags, 0);
	*slash = '/';			/* restore path */
	close(dfd);
	if (subdfd == -1)
	    debug_return_int(-1);
	path = slash + 1;
	dfd = subdfd;
    }

    if (is_writable) {
	close(dfd);
	errno = EISDIR;
	debug_return_int(-1);
    }

    /*
     * For "sudoedit /" we will receive ENOENT from openat() and sudoedit
     * will try to create a file with an empty name.  We treat an empty
     * path as the cwd so sudoedit can give a sensible error message.
     */
    fd = openat(dfd, *path ? path : ".", oflags, mode);
    close(dfd);
    debug_return_int(fd);
}

#ifdef O_NOFOLLOW
static int
sudo_edit_open(char *path, int oflags, mode_t mode,
    struct command_details *command_details)
{
    const int sflags = command_details ? command_details->flags : 0;
    int fd;
    debug_decl(sudo_edit_open, SUDO_DEBUG_EDIT)

    if (!ISSET(sflags, CD_SUDOEDIT_FOLLOW))
	oflags |= O_NOFOLLOW;
    if (ISSET(sflags, CD_SUDOEDIT_CHECKDIR) && user_details.uid != ROOT_UID) {
	fd = sudo_edit_open_nonwritable(path, oflags|O_NONBLOCK, mode,
	    command_details);
    } else {
	fd = open(path, oflags|O_NONBLOCK, mode);
    }
    if (fd != -1 && !ISSET(oflags, O_NONBLOCK))
	(void) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
    debug_return_int(fd);
}
#else
static int
sudo_edit_open(char *path, int oflags, mode_t mode,
    struct command_details *command_details)
{
    const int sflags = command_details ? command_details->flags : 0;
    struct stat sb;
    int fd;
    debug_decl(sudo_edit_open, SUDO_DEBUG_EDIT)

    /*
     * Check if path is a symlink.  This is racey but we detect whether
     * we lost the race in sudo_edit_is_symlink() after the file is opened.
     */
    if (!ISSET(sflags, CD_SUDOEDIT_FOLLOW)) {
	if (lstat(path, &sb) == -1 && errno != ENOENT)
	    debug_return_int(-1);
	if (S_ISLNK(sb.st_mode)) {
	    errno = ELOOP;
	    debug_return_int(-1);
	}
    }

    if (ISSET(sflags, CD_SUDOEDIT_CHECKDIR) && user_details.uid != ROOT_UID) {
	fd = sudo_edit_open_nonwritable(path, oflags|O_NONBLOCK, mode,
	    command_details);
    } else {
	fd = open(path, oflags|O_NONBLOCK, mode);
    }
    if (fd == -1)
	debug_return_int(-1);
    if (!ISSET(oflags, O_NONBLOCK))
	(void) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);

    /*
     * Post-open symlink check.  This will leave a zero-length file if
     * O_CREAT was specified but it is too dangerous to try and remove it.
     */
    if (!ISSET(sflags, CD_SUDOEDIT_FOLLOW) && sudo_edit_is_symlink(fd, path)) {
	close(fd);
	fd = -1;
	errno = ELOOP;
    }

    debug_return_int(fd);
}
#endif /* O_NOFOLLOW */

/*
 * Create temporary copies of files[] and store the temporary path name
 * along with the original name, size and mtime in tf.
 * Returns the number of files copied (which may be less than nfiles)
 * or -1 if a fatal error occurred.
 */
static int
sudo_edit_create_tfiles(struct command_details *command_details,
    struct tempfile *tf, char *files[], int nfiles)
{
    int i, j, tfd, ofd, rc;
    char buf[BUFSIZ];
    ssize_t nwritten, nread;
    struct timespec times[2];
    struct stat sb;
    debug_decl(sudo_edit_create_tfiles, SUDO_DEBUG_EDIT)

    /*
     * For each file specified by the user, make a temporary version
     * and copy the contents of the original to it.
     */
    for (i = 0, j = 0; i < nfiles; i++) {
	rc = -1;
	switch_user(command_details->euid, command_details->egid,
	    command_details->ngroups, command_details->groups);
	ofd = sudo_edit_open(files[i], O_RDONLY,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH, command_details);
	if (ofd != -1 || errno == ENOENT) {
	    if (ofd == -1) {
		/* New file, verify parent dir exists unless in cwd. */
		char *slash = strrchr(files[i], '/');
		if (slash != NULL && slash != files[i]) {
		    int serrno = errno;
		    *slash = '\0';
		    if (stat(files[i], &sb) == 0 && S_ISDIR(sb.st_mode)) {
			memset(&sb, 0, sizeof(sb));
			rc = 0;
		    }
		    *slash = '/';
		    errno = serrno;
		} else {
		    memset(&sb, 0, sizeof(sb));
		    rc = 0;
		}
	    } else {
		rc = fstat(ofd, &sb);
	    }
	}
	switch_user(ROOT_UID, user_details.egid,
	    user_details.ngroups, user_details.groups);
	if (ofd != -1 && !S_ISREG(sb.st_mode)) {
	    sudo_warnx(U_("%s: not a regular file"), files[i]);
	    close(ofd);
	    continue;
	}
	if (rc == -1) {
	    /* open() or fstat() error. */
	    if (ofd == -1 && errno == ELOOP) {
		sudo_warnx(U_("%s: editing symbolic links is not permitted"),
		    files[i]);
	    } else if (ofd == -1 && errno == EISDIR) {
		sudo_warnx(U_("%s: editing files in a writable directory is not permitted"),
		    files[i]);
	    } else {
		sudo_warn("%s", files[i]);
	    }
	    if (ofd != -1)
		close(ofd);
	    continue;
	}
	tf[j].ofile = files[i];
	tf[j].osize = sb.st_size;
	mtim_get(&sb, tf[j].omtim);
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "seteuid(%u)", (unsigned int)user_details.uid);
	if (seteuid(user_details.uid) != 0)
	    sudo_fatal("seteuid(%u)", (unsigned int)user_details.uid);
	tfd = sudo_edit_mktemp(tf[j].ofile, &tf[j].tfile);
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "seteuid(%u)", ROOT_UID);
	if (seteuid(ROOT_UID) != 0)
	    sudo_fatal("seteuid(ROOT_UID)");
	if (tfd == -1) {
	    sudo_warn("mkstemps");
	    if (ofd != -1)
		close(ofd);
	    debug_return_int(-1);
	}
	if (ofd != -1) {
	    while ((nread = read(ofd, buf, sizeof(buf))) > 0) {
		if ((nwritten = write(tfd, buf, nread)) != nread) {
		    if (nwritten == -1)
			sudo_warn("%s", tf[j].tfile);
		    else
			sudo_warnx(U_("%s: short write"), tf[j].tfile);
		    break;
		}
	    }
	    if (nread != 0) {
		if (nread < 0)
		    sudo_warn("%s", files[i]);
		close(ofd);
		close(tfd);
		debug_return_int(-1);
	    }
	    close(ofd);
	}
	/*
	 * We always update the stashed mtime because the time
	 * resolution of the filesystem the temporary file is on may
	 * not match that of the filesystem where the file to be edited
	 * resides.  It is OK if futimens() fails since we only use the
	 * info to determine whether or not a file has been modified.
	 */
	times[0].tv_sec = times[1].tv_sec = tf[j].omtim.tv_sec;
	times[0].tv_nsec = times[1].tv_nsec = tf[j].omtim.tv_nsec;
	if (futimens(tfd, times) == -1) {
	    if (utimensat(AT_FDCWD, tf[j].tfile, times, 0) == -1)
		sudo_warn("%s", tf[j].tfile);
	}
	rc = fstat(tfd, &sb);
	if (!rc)
	    mtim_get(&sb, tf[j].omtim);
	close(tfd);
	j++;
    }
    debug_return_int(j);
}

/*
 * Copy the temporary files specified in tf to the originals.
 * Returns the number of copy errors or 0 if completely successful.
 */
static int
sudo_edit_copy_tfiles(struct command_details *command_details,
    struct tempfile *tf, int nfiles, struct timespec *times)
{
    int i, tfd, ofd, rc, errors = 0;
    char buf[BUFSIZ];
    ssize_t nwritten, nread;
    struct timespec ts;
    struct stat sb;
    mode_t oldmask;
    debug_decl(sudo_edit_copy_tfiles, SUDO_DEBUG_EDIT)

    /* Copy contents of temp files to real ones. */
    for (i = 0; i < nfiles; i++) {
	rc = -1;
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "seteuid(%u)", (unsigned int)user_details.uid);
	if (seteuid(user_details.uid) != 0)
	    sudo_fatal("seteuid(%u)", (unsigned int)user_details.uid);
	tfd = sudo_edit_open(tf[i].tfile, O_RDONLY,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH, NULL);
	if (tfd != -1)
	    rc = fstat(tfd, &sb);
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "seteuid(%u)", ROOT_UID);
	if (seteuid(ROOT_UID) != 0)
	    sudo_fatal("seteuid(ROOT_UID)");
	if (rc || !S_ISREG(sb.st_mode)) {
	    if (rc)
		sudo_warn("%s", tf[i].tfile);
	    else
		sudo_warnx(U_("%s: not a regular file"), tf[i].tfile);
	    sudo_warnx(U_("%s left unmodified"), tf[i].ofile);
	    if (tfd != -1)
		close(tfd);
	    errors++;
	    continue;
	}
	mtim_get(&sb, ts);
	if (tf[i].osize == sb.st_size && sudo_timespeccmp(&tf[i].omtim, &ts, ==)) {
	    /*
	     * If mtime and size match but the user spent no measurable
	     * time in the editor we can't tell if the file was changed.
	     */
	    if (sudo_timespeccmp(&times[0], &times[1], !=)) {
		sudo_warnx(U_("%s unchanged"), tf[i].ofile);
		unlink(tf[i].tfile);
		close(tfd);
		continue;
	    }
	}
	switch_user(command_details->euid, command_details->egid,
	    command_details->ngroups, command_details->groups);
	oldmask = umask(command_details->umask);
	ofd = sudo_edit_open(tf[i].ofile, O_WRONLY|O_TRUNC|O_CREAT,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH, command_details);
	umask(oldmask);
	switch_user(ROOT_UID, user_details.egid,
	    user_details.ngroups, user_details.groups);
	if (ofd == -1) {
	    sudo_warn(U_("unable to write to %s"), tf[i].ofile);
	    sudo_warnx(U_("contents of edit session left in %s"), tf[i].tfile);
	    close(tfd);
	    errors++;
	    continue;
	}
	while ((nread = read(tfd, buf, sizeof(buf))) > 0) {
	    if ((nwritten = write(ofd, buf, nread)) != nread) {
		if (nwritten == -1)
		    sudo_warn("%s", tf[i].ofile);
		else
		    sudo_warnx(U_("%s: short write"), tf[i].ofile);
		break;
	    }
	}
	if (nread == 0) {
	    /* success, got EOF */
	    unlink(tf[i].tfile);
	} else if (nread < 0) {
	    sudo_warn(U_("unable to read temporary file"));
	    sudo_warnx(U_("contents of edit session left in %s"), tf[i].tfile);
	} else {
	    sudo_warn(U_("unable to write to %s"), tf[i].ofile);
	    sudo_warnx(U_("contents of edit session left in %s"), tf[i].tfile);
	}
	close(ofd);
	close(tfd);
    }
    debug_return_int(errors);
}

#ifdef HAVE_SELINUX
static int
selinux_edit_create_tfiles(struct command_details *command_details,
    struct tempfile *tf, char *files[], int nfiles)
{
    char **sesh_args, **sesh_ap;
    int i, rc, sesh_nargs;
    struct stat sb;
    struct command_details saved_command_details;
    debug_decl(selinux_edit_create_tfiles, SUDO_DEBUG_EDIT)
    
    /* Prepare selinux stuff (setexeccon) */
    if (selinux_setup(command_details->selinux_role,
	command_details->selinux_type, NULL, -1) != 0)
	debug_return_int(-1);

    if (nfiles < 1)
	debug_return_int(0);

    /* Construct common args for sesh */
    memcpy(&saved_command_details, command_details, sizeof(struct command_details));
    command_details->command = _PATH_SUDO_SESH;
    command_details->flags |= CD_SUDOEDIT_COPY;
    
    sesh_nargs = 4 + (nfiles * 2) + 1;
    sesh_args = sesh_ap = reallocarray(NULL, sesh_nargs, sizeof(char *));
    if (sesh_args == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(-1);
    }
    *sesh_ap++ = "sesh";
    *sesh_ap++ = "-e";
    if (!ISSET(command_details->flags, CD_SUDOEDIT_FOLLOW))
	*sesh_ap++ = "-h";
    *sesh_ap++ = "0";

    for (i = 0; i < nfiles; i++) {
	char *tfile, *ofile = files[i];
	int tfd;
	*sesh_ap++  = ofile;
	tf[i].ofile = ofile;
	if (stat(ofile, &sb) == -1)
	    memset(&sb, 0, sizeof(sb));		/* new file */
	tf[i].osize = sb.st_size;
	mtim_get(&sb, tf[i].omtim);
	/*
	 * The temp file must be created by the sesh helper,
	 * which uses O_EXCL | O_NOFOLLOW to make this safe.
	 */
	tfd = sudo_edit_mktemp(ofile, &tfile);
	if (tfd == -1) {
	    sudo_warn("mkstemps");
	    free(tfile);
	    free(sesh_args);
	    debug_return_int(-1);
	}
	/* Helper will re-create temp file with proper security context. */
	close(tfd);
	unlink(tfile);
	*sesh_ap++  = tfile;
	tf[i].tfile = tfile;
    }
    *sesh_ap = NULL;

    /* Run sesh -e [-h] 0 <o1> <t1> ... <on> <tn> */
    command_details->argv = sesh_args;
    rc = run_command(command_details);
    switch (rc) {
    case SESH_SUCCESS:
	break;
    case SESH_ERR_BAD_PATHS:
	sudo_fatalx(U_("sesh: internal error: odd number of paths"));
    case SESH_ERR_NO_FILES:
	sudo_fatalx(U_("sesh: unable to create temporary files"));
    default:
	sudo_fatalx(U_("sesh: unknown error %d"), rc);
    }

    /* Restore saved command_details. */
    command_details->command = saved_command_details.command;
    command_details->flags = saved_command_details.flags;
    command_details->argv = saved_command_details.argv;
    
    /* Chown to user's UID so they can edit the temporary files. */
    for (i = 0; i < nfiles; i++) {
	if (chown(tf[i].tfile, user_details.uid, user_details.gid) != 0) {
	    sudo_warn("unable to chown(%s) to %d:%d for editing",
		tf[i].tfile, user_details.uid, user_details.gid);
	}
    }

    /* Contents of tf will be freed by caller. */
    free(sesh_args);

    return (nfiles);
}

static int
selinux_edit_copy_tfiles(struct command_details *command_details,
    struct tempfile *tf, int nfiles, struct timespec *times)
{
    char **sesh_args, **sesh_ap;
    int i, rc, sesh_nargs, ret = 1;
    struct command_details saved_command_details;
    struct timespec ts;
    struct stat sb;
    debug_decl(selinux_edit_copy_tfiles, SUDO_DEBUG_EDIT)
    
    /* Prepare selinux stuff (setexeccon) */
    if (selinux_setup(command_details->selinux_role,
	command_details->selinux_type, NULL, -1) != 0)
	debug_return_int(1);

    if (nfiles < 1)
	debug_return_int(0);

    /* Construct common args for sesh */
    memcpy(&saved_command_details, command_details, sizeof(struct command_details));
    command_details->command = _PATH_SUDO_SESH;
    command_details->flags |= CD_SUDOEDIT_COPY;
    
    sesh_nargs = 3 + (nfiles * 2) + 1;
    sesh_args = sesh_ap = reallocarray(NULL, sesh_nargs, sizeof(char *));
    if (sesh_args == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(-1);
    }
    *sesh_ap++ = "sesh";
    *sesh_ap++ = "-e";
    *sesh_ap++ = "1";

    /* Construct args for sesh -e 1 */
    for (i = 0; i < nfiles; i++) {
	if (stat(tf[i].tfile, &sb) == 0) {
	    mtim_get(&sb, ts);
	    if (tf[i].osize == sb.st_size && sudo_timespeccmp(&tf[i].omtim, &ts, ==)) {
		/*
		 * If mtime and size match but the user spent no measurable
		 * time in the editor we can't tell if the file was changed.
		 */
		if (sudo_timespeccmp(&times[0], &times[1], !=)) {
		    sudo_warnx(U_("%s unchanged"), tf[i].ofile);
		    unlink(tf[i].tfile);
		    continue;
		}
	    }
	}
	*sesh_ap++ = tf[i].tfile;
	*sesh_ap++ = tf[i].ofile;
	if (chown(tf[i].tfile, command_details->uid, command_details->gid) != 0) {
	    sudo_warn("unable to chown(%s) back to %d:%d", tf[i].tfile,
		command_details->uid, command_details->gid);
	}
    }
    *sesh_ap = NULL;

    if (sesh_ap - sesh_args > 3) {
	/* Run sesh -e 1 <t1> <o1> ... <tn> <on> */
	command_details->argv = sesh_args;
	rc = run_command(command_details);
	switch (rc) {
	case SESH_SUCCESS:
	    ret = 0;
	    break;
	case SESH_ERR_NO_FILES:
	    sudo_warnx(U_("unable to copy temporary files back to their original location"));
	    sudo_warnx(U_("contents of edit session left in %s"), edit_tmpdir);
	    break;
	case SESH_ERR_SOME_FILES:
	    sudo_warnx(U_("unable to copy some of the temporary files back to their original location"));
	    sudo_warnx(U_("contents of edit session left in %s"), edit_tmpdir);
	    break;
	default:
	    sudo_warnx(U_("sesh: unknown error %d"), rc);
	    break;
	}
    }
    free(sesh_args);

    /* Restore saved command_details. */
    command_details->command = saved_command_details.command;
    command_details->flags = saved_command_details.flags;
    command_details->argv = saved_command_details.argv;

    debug_return_int(ret);
}
#endif /* HAVE_SELINUX */

/*
 * Wrapper to allow users to edit privileged files with their own uid.
 * Returns the wait status of the command on success and a wait status
 * of 1 on failure.
 */
int
sudo_edit(struct command_details *command_details)
{
    struct command_details saved_command_details;
    char **nargv = NULL, **ap, **files = NULL;
    int errors, i, ac, nargc, rc;
    int editor_argc = 0, nfiles = 0;
    struct timespec times[2];
    struct tempfile *tf = NULL;
    debug_decl(sudo_edit, SUDO_DEBUG_EDIT)

    if (!set_tmpdir(command_details))
	goto cleanup;

    /*
     * Set real, effective and saved uids to root.
     * We will change the euid as needed below.
     */
    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"setuid(%u)", ROOT_UID);
    if (setuid(ROOT_UID) != 0) {
	sudo_warn(U_("unable to change uid to root (%u)"), ROOT_UID);
	goto cleanup;
    }

    /*
     * The user's editor must be separated from the files to be
     * edited by a "--" option.
     */
    for (ap = command_details->argv; *ap != NULL; ap++) {
	if (files)
	    nfiles++;
	else if (strcmp(*ap, "--") == 0)
	    files = ap + 1;
	else
	    editor_argc++;
    }
    if (nfiles == 0) {
	sudo_warnx(U_("plugin error: missing file list for sudoedit"));
	goto cleanup;
    }

    /* Copy editor files to temporaries. */
    tf = calloc(nfiles, sizeof(*tf));
    if (tf == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto cleanup;
    }
#ifdef HAVE_SELINUX
    if (ISSET(command_details->flags, CD_RBAC_ENABLED))
	nfiles = selinux_edit_create_tfiles(command_details, tf, files, nfiles);
    else 
#endif
	nfiles = sudo_edit_create_tfiles(command_details, tf, files, nfiles);
    if (nfiles <= 0)
	goto cleanup;

    /*
     * Allocate space for the new argument vector and fill it in.
     * We concatenate the editor with its args and the file list
     * to create a new argv.
     */
    nargc = editor_argc + nfiles;
    nargv = reallocarray(NULL, nargc + 1, sizeof(char *));
    if (nargv == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto cleanup;
    }
    for (ac = 0; ac < editor_argc; ac++)
	nargv[ac] = command_details->argv[ac];
    for (i = 0; i < nfiles && ac < nargc; )
	nargv[ac++] = tf[i++].tfile;
    nargv[ac] = NULL;

    /*
     * Run the editor with the invoking user's creds,
     * keeping track of the time spent in the editor.
     */
    if (sudo_gettime_real(&times[0]) == -1) {
	sudo_warn(U_("unable to read the clock"));
	goto cleanup;
    }
    memcpy(&saved_command_details, command_details, sizeof(struct command_details));
    command_details->uid = user_details.uid;
    command_details->euid = user_details.uid;
    command_details->gid = user_details.gid;
    command_details->egid = user_details.gid;
    command_details->ngroups = user_details.ngroups;
    command_details->groups = user_details.groups;
    command_details->argv = nargv;
    rc = run_command(command_details);
    if (sudo_gettime_real(&times[1]) == -1) {
	sudo_warn(U_("unable to read the clock"));
	goto cleanup;
    }

    /* Restore saved command_details. */
    command_details->uid = saved_command_details.uid;
    command_details->euid = saved_command_details.euid;
    command_details->gid = saved_command_details.gid;
    command_details->egid = saved_command_details.egid;
    command_details->ngroups = saved_command_details.ngroups;
    command_details->groups = saved_command_details.groups;
    command_details->argv = saved_command_details.argv;

    /* Copy contents of temp files to real ones. */
#ifdef HAVE_SELINUX
    if (ISSET(command_details->flags, CD_RBAC_ENABLED))
	errors = selinux_edit_copy_tfiles(command_details, tf, nfiles, times);
    else
#endif
	errors = sudo_edit_copy_tfiles(command_details, tf, nfiles, times);
    if (errors)
	goto cleanup;

    for (i = 0; i < nfiles; i++)
	free(tf[i].tfile);
    free(tf);
    free(nargv);
    debug_return_int(rc);

cleanup:
    /* Clean up temp files and return. */
    if (tf != NULL) {
	for (i = 0; i < nfiles; i++) {
	    if (tf[i].tfile != NULL)
		unlink(tf[i].tfile);
	}
    }
    free(tf);
    free(nargv);
    debug_return_int(W_EXITCODE(1, 0));
}

#else /* HAVE_SETRESUID || HAVE_SETREUID || HAVE_SETEUID */

/*
 * Must have the ability to change the effective uid to use sudoedit.
 */
int
sudo_edit(struct command_details *command_details)
{
    debug_decl(sudo_edit, SUDO_DEBUG_EDIT)
    debug_return_int(W_EXITCODE(1, 0));
}

#endif /* HAVE_SETRESUID || HAVE_SETREUID || HAVE_SETEUID */
