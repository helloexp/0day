/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2019 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>

#include "sudoers.h"
#include "iolog.h"
#include "iolog_files.h"

/* XXX - separate sudoers.h and iolog.h? */
#undef runas_pw
#undef runas_gr

struct iolog_details {
    const char *cwd;
    const char *tty;
    const char *user;
    const char *command;
    const char *iolog_path;
    struct passwd *runas_pw;
    struct group *runas_gr;
    int lines;
    int cols;
    bool ignore_iolog_errors;
};

static struct iolog_details iolog_details;
static bool iolog_compress = false;
static bool warned = false;
static struct timespec last_time;
static unsigned int sessid_max = SESSID_MAX;
static mode_t iolog_filemode = S_IRUSR|S_IWUSR;
static mode_t iolog_dirmode = S_IRWXU;
static bool iolog_gid_set;

/* shared with set_perms.c */
uid_t iolog_uid = ROOT_UID;
gid_t iolog_gid = ROOT_GID;

/* sudoers_io is declared at the end of this file. */
extern __dso_public struct io_plugin sudoers_io;

/*
 * Create directory and any parent directories as needed.
 */
static bool
io_mkdirs(char *path)
{
    struct stat sb;
    bool ok, uid_changed = false;
    debug_decl(io_mkdirs, SUDOERS_DEBUG_UTIL)

    ok = stat(path, &sb) == 0;
    if (!ok && errno == EACCES) {
	/* Try again as the I/O log owner (for NFS). */
	if (set_perms(PERM_IOLOG)) {
	    ok = stat(path, &sb) == 0;
	    if (!restore_perms())
		ok = false;
	}
    }
    if (ok) {
	if (S_ISDIR(sb.st_mode)) {
	    if (sb.st_uid != iolog_uid || sb.st_gid != iolog_gid) {
		if (chown(path, iolog_uid, iolog_gid) != 0) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
			"%s: unable to chown %d:%d %s", __func__,
			(int)iolog_uid, (int)iolog_gid, path);
		}
	    }
	    if ((sb.st_mode & ALLPERMS) != iolog_dirmode) {
		if (chmod(path, iolog_dirmode) != 0) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
			"%s: unable to chmod 0%o %s", __func__,
			(int)iolog_dirmode, path);
		}
	    }
	} else {
	    sudo_warnx(U_("%s exists but is not a directory (0%o)"),
		path, (unsigned int) sb.st_mode);
	    ok = false;
	}
	goto done;
    }

    ok = sudo_mkdir_parents(path, iolog_uid, iolog_gid, iolog_dirmode, true);
    if (!ok && errno == EACCES) {
	/* Try again as the I/O log owner (for NFS). */
	uid_changed = set_perms(PERM_IOLOG);
	ok = sudo_mkdir_parents(path, -1, -1, iolog_dirmode, false);
    }
    if (ok) {
	/* Create final path component. */
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	    "mkdir %s, mode 0%o", path, (unsigned int) iolog_dirmode);
	ok = mkdir(path, iolog_dirmode) == 0 || errno == EEXIST;
	if (!ok) {
	    if (errno == EACCES && !uid_changed) {
		/* Try again as the I/O log owner (for NFS). */
		uid_changed = set_perms(PERM_IOLOG);
		ok = mkdir(path, iolog_dirmode) == 0 || errno == EEXIST;
	    }
	    if (!ok)
		sudo_warn(U_("unable to mkdir %s"), path);
	} else {
	    if (chown(path, iolog_uid, iolog_gid) != 0) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		    "%s: unable to chown %d:%d %s", __func__,
		    (int)iolog_uid, (int)iolog_gid, path);
	    }
	}
    }
    if (uid_changed) {
	if (!restore_perms())
	    ok = false;
    }
done:
    debug_return_bool(ok);
}

/*
 * Create temporary directory and any parent directories as needed.
 */
static bool
io_mkdtemp(char *path)
{
    bool ok, uid_changed = false;
    debug_decl(io_mkdtemp, SUDOERS_DEBUG_UTIL)

    ok = sudo_mkdir_parents(path, iolog_uid, iolog_gid, iolog_dirmode, true);
    if (!ok && errno == EACCES) {
	/* Try again as the I/O log owner (for NFS). */
	uid_changed = set_perms(PERM_IOLOG);
	ok = sudo_mkdir_parents(path, -1, -1, iolog_dirmode, false);
    }
    if (ok) {
	/* Create final path component. */
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	    "mkdtemp %s", path);
	/* We cannot retry mkdtemp() so always use PERM_IOLOG */
	if (!uid_changed)
	    uid_changed = set_perms(PERM_IOLOG);
	if (mkdtemp(path) == NULL) {
	    sudo_warn(U_("unable to mkdir %s"), path);
	    ok = false;
	} else {
	    if (chmod(path, iolog_dirmode) != 0) {
		sudo_warn(U_("unable to change mode of %s to 0%o"),
		    path, (unsigned int)iolog_dirmode);
	    }
	}
    }

    if (uid_changed) {
	if (!restore_perms())
	    ok = false;
    }
    debug_return_bool(ok);
}

/*
 * Set max session ID (aka sequence number)
 */
static bool
io_set_max_sessid(const char *maxval)
{
    const char *errstr;
    unsigned int value;
    debug_decl(io_set_max_sessid, SUDOERS_DEBUG_UTIL)

    value = sudo_strtonum(maxval, 0, SESSID_MAX, &errstr);
    if (errstr != NULL) {
	if (errno != ERANGE) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"bad maxseq: %s: %s", maxval, errstr);
	    debug_return_bool(false);
	}
	/* Out of range, clamp to SESSID_MAX as documented. */
	value = SESSID_MAX;
    }
    sessid_max = value;
    debug_return_bool(true);
}

/*
 * Sudoers callback for maxseq Defaults setting.
 */
bool
cb_maxseq(const union sudo_defs_val *sd_un)
{
    debug_decl(cb_maxseq, SUDOERS_DEBUG_UTIL)

    /* Clamp value to SESSID_MAX as documented. */
    sessid_max = sd_un->uival < SESSID_MAX ? sd_un->uival : SESSID_MAX;
    debug_return_bool(true);
}

/*
 * Look up I/O log user-ID from user name.  Sets iolog_uid.
 * Also sets iolog_gid if iolog_group not specified.
 */
static bool
iolog_set_user(const char *name)
{
    struct passwd *pw;
    debug_decl(iolog_set_user, SUDOERS_DEBUG_UTIL)

    if (name != NULL) {
	pw = sudo_getpwnam(name);
	if (pw != NULL) {
	    iolog_uid = pw->pw_uid;
	    if (!iolog_gid_set)
		iolog_gid = pw->pw_gid;
	    sudo_pw_delref(pw);
	} else {
	    log_warningx(SLOG_SEND_MAIL,
		N_("unknown user: %s"), name);
	}
    } else {
	/* Reset to default. */
	iolog_uid = ROOT_UID;
	if (!iolog_gid_set)
	    iolog_gid = ROOT_GID;
    }

    debug_return_bool(true);
}

/*
 * Sudoers callback for iolog_user Defaults setting.
 */
bool
cb_iolog_user(const union sudo_defs_val *sd_un)
{
    return iolog_set_user(sd_un->str);
}

/*
 * Look up I/O log group-ID from group name.
 * Sets iolog_gid.
 */
static bool
iolog_set_group(const char *name)
{
    struct group *gr;
    debug_decl(iolog_set_group, SUDOERS_DEBUG_UTIL)

    if (name != NULL) {
	gr = sudo_getgrnam(name);
	if (gr != NULL) {
	    iolog_gid = gr->gr_gid;
	    iolog_gid_set = true;
	    sudo_gr_delref(gr);
	} else {
	    log_warningx(SLOG_SEND_MAIL,
		N_("unknown group: %s"), name);
	}
    } else {
	/* Reset to default. */
	iolog_gid = ROOT_GID;
	iolog_gid_set = false;
    }

    debug_return_bool(true);
}

/*
 * Look up I/O log group-ID from group name.
 */
bool
cb_iolog_group(const union sudo_defs_val *sd_un)
{
    return iolog_set_group(sd_un->str);
}

/*
 * Set iolog_filemode and iolog_dirmode.
 */
static bool
iolog_set_mode(mode_t mode)
{
    debug_decl(iolog_set_mode, SUDOERS_DEBUG_UTIL)

    /* I/O log files must be readable and writable by owner. */
    iolog_filemode = S_IRUSR|S_IWUSR;

    /* Add in group and other read/write if specified. */
    iolog_filemode |= mode & (S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);

    /* For directory mode, add execute bits as needed. */
    iolog_dirmode = iolog_filemode | S_IXUSR;
    if (iolog_dirmode & (S_IRGRP|S_IWGRP))
	iolog_dirmode |= S_IXGRP;
    if (iolog_dirmode & (S_IROTH|S_IWOTH))
	iolog_dirmode |= S_IXOTH;

    debug_return_bool(true);
}

/*
 * Sudoers callback for iolog_mode Defaults setting.
 */
bool
cb_iolog_mode(const union sudo_defs_val *sd_un)
{
    return iolog_set_mode(sd_un->mode);
}

/*
 * Wrapper for open(2) that retries with PERM_IOLOG if open(2)
 * returns EACCES.
 */
static int
io_open(const char *path, int flags, mode_t perm)
{
    int fd;
    debug_decl(io_open, SUDOERS_DEBUG_UTIL)

    fd = open(path, flags, perm);
    if (fd == -1 && errno == EACCES) {
	/* Try again as the I/O log owner (for NFS). */
	if (set_perms(PERM_IOLOG)) {
	    fd = open(path, flags, perm);
	    if (!restore_perms()) {
		/* restore_perms() warns on error. */
		if (fd != -1) {
		    close(fd);
		    fd = -1;
		}
	    }
	}
    }
    debug_return_int(fd);
}

/*
 * Read the on-disk sequence number, set sessid to the next
 * number, and update the on-disk copy.
 * Uses file locking to avoid sequence number collisions.
 */
bool
io_nextid(char *iolog_dir, char *iolog_dir_fallback, char sessid[7])
{
    struct stat sb;
    char buf[32], *ep;
    int i, len, fd = -1;
    unsigned long id = 0;
    mode_t omask;
    ssize_t nread;
    bool ret = false;
    char pathbuf[PATH_MAX];
    static const char b36char[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    debug_decl(io_nextid, SUDOERS_DEBUG_UTIL)

    /* umask must not be more restrictive than the file modes. */
    omask = umask(ACCESSPERMS & ~(iolog_filemode|iolog_dirmode));

    /*
     * Create I/O log directory if it doesn't already exist.
     */
    if (!io_mkdirs(iolog_dir))
	goto done;

    /*
     * Open sequence file
     */
    len = snprintf(pathbuf, sizeof(pathbuf), "%s/seq", iolog_dir);
    if (len < 0 || len >= ssizeof(pathbuf)) {
	errno = ENAMETOOLONG;
	log_warning(SLOG_SEND_MAIL, "%s/seq", pathbuf);
	goto done;
    }
    fd = io_open(pathbuf, O_RDWR|O_CREAT, iolog_filemode);
    if (fd == -1) {
	log_warning(SLOG_SEND_MAIL, N_("unable to open %s"), pathbuf);
	goto done;
    }
    sudo_lock_file(fd, SUDO_LOCK);
    if (fchown(fd, iolog_uid, iolog_gid) != 0) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to fchown %d:%d %s", __func__,
	    (int)iolog_uid, (int)iolog_gid, pathbuf);
    }

    /*
     * If there is no seq file in iolog_dir and a fallback dir was
     * specified, look for seq in the fallback dir.  This is to work
     * around a bug in sudo 1.8.5 and older where iolog_dir was not
     * expanded before the sequence number was updated.
     */
    if (iolog_dir_fallback != NULL && fstat(fd, &sb) == 0 && sb.st_size == 0) {
	char fallback[PATH_MAX];

	len = snprintf(fallback, sizeof(fallback), "%s/seq",
	    iolog_dir_fallback);
	if (len > 0 && len < ssizeof(fallback)) {
	    int fd2 = io_open(fallback, O_RDWR|O_CREAT, iolog_filemode);
	    if (fd2 != -1) {
		if (fchown(fd2, iolog_uid, iolog_gid) != 0) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
			"%s: unable to fchown %d:%d %s", __func__,
			(int)iolog_uid, (int)iolog_gid, fallback);
		}
		nread = read(fd2, buf, sizeof(buf) - 1);
		if (nread > 0) {
		    if (buf[nread - 1] == '\n')
			nread--;
		    buf[nread] = '\0';
		    id = strtoul(buf, &ep, 36);
		    if (ep == buf || *ep != '\0' || id >= sessid_max) {
			sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			    "%s: bad sequence number: %s", fallback, buf);
			id = 0;
		    }
		}
		close(fd2);
	    }
	}
    }

    /* Read current seq number (base 36). */
    if (id == 0) {
	nread = read(fd, buf, sizeof(buf) - 1);
	if (nread != 0) {
	    if (nread == -1) {
		log_warning(SLOG_SEND_MAIL, N_("unable to read %s"), pathbuf);
		goto done;
	    }
	    if (buf[nread - 1] == '\n')
		nread--;
	    buf[nread] = '\0';
	    id = strtoul(buf, &ep, 36);
	    if (ep == buf || *ep != '\0' || id >= sessid_max) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "%s: bad sequence number: %s", pathbuf, buf);
		id = 0;
	    }
	}
    }
    id++;

    /*
     * Convert id to a string and stash in sessid.
     * Note that that least significant digits go at the end of the string.
     */
    for (i = 5; i >= 0; i--) {
	buf[i] = b36char[id % 36];
	id /= 36;
    }
    buf[6] = '\n';

    /* Stash id for logging purposes. */
    memcpy(sessid, buf, 6);
    sessid[6] = '\0';

    /* Rewind and overwrite old seq file, including the NUL byte. */
#ifdef HAVE_PWRITE
    if (pwrite(fd, buf, 7, 0) != 7) {
#else
    if (lseek(fd, 0, SEEK_SET) == -1 || write(fd, buf, 7) != 7) {
#endif
	log_warning(SLOG_SEND_MAIL, N_("unable to write to %s"), pathbuf);
	warned = true;
	goto done;
    }
    ret = true;

done:
    umask(omask);
    if (fd != -1)
	close(fd);
    debug_return_bool(ret);
}

/*
 * Copy iolog_path to pathbuf and create the directory and any intermediate
 * directories.  If iolog_path ends in 'XXXXXX', use mkdtemp().
 * Returns SIZE_MAX on error.
 */
static size_t
mkdir_iopath(const char *iolog_path, char *pathbuf, size_t pathsize)
{
    size_t len;
    bool ok;
    debug_decl(mkdir_iopath, SUDOERS_DEBUG_UTIL)

    len = strlcpy(pathbuf, iolog_path, pathsize);
    if (len >= pathsize) {
	errno = ENAMETOOLONG;
	log_warning(SLOG_SEND_MAIL, "%s", iolog_path);
	debug_return_size_t((size_t)-1);
    }

    /*
     * Create path and intermediate subdirs as needed.
     * If path ends in at least 6 Xs (ala POSIX mktemp), use mkdtemp().
     * Sets iolog_gid (if it is not already set) as a side effect.
     */
    if (len >= 6 && strcmp(&pathbuf[len - 6], "XXXXXX") == 0)
	ok = io_mkdtemp(pathbuf);
    else
	ok = io_mkdirs(pathbuf);

    debug_return_size_t(ok ? len : (size_t)-1);
}

/*
 * Append suffix to pathbuf after len chars and open the resulting file.
 * Note that the size of pathbuf is assumed to be PATH_MAX.
 * Uses zlib if docompress is true.
 * Stores the open file handle which has the close-on-exec flag set.
 */
static bool
open_io_fd(char *pathbuf, size_t len, struct io_log_file *iol, bool docompress)
{
    debug_decl(open_io_fd, SUDOERS_DEBUG_UTIL)

    pathbuf[len] = '\0';
    strlcat(pathbuf, iol->suffix, PATH_MAX);
    if (iol->enabled) {
	int fd = io_open(pathbuf, O_CREAT|O_TRUNC|O_WRONLY, iolog_filemode);
	if (fd != -1) {
	    if (fchown(fd, iolog_uid, iolog_gid) != 0) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		    "%s: unable to fchown %d:%d %s", __func__,
		    (int)iolog_uid, (int)iolog_gid, pathbuf);
	    }
	    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
#ifdef HAVE_ZLIB_H
	    if (docompress)
		iol->fd.g = gzdopen(fd, "w");
	    else
#endif
		iol->fd.f = fdopen(fd, "w");
	    if (iol->fd.v == NULL) {
		close(fd);
		fd = -1;
	    }
	}
	if (fd == -1) {
	    log_warning(SLOG_SEND_MAIL, N_("unable to create %s"), pathbuf);
	    debug_return_bool(false);
	}
    } else {
	/* Remove old log file if we recycled sequence numbers. */
	unlink(pathbuf);
    }
    debug_return_bool(true);
}

/*
 * Pull out I/O log related data from user_info and command_info arrays.
 * Returns true if I/O logging is enabled, else false.
 */
static bool
iolog_deserialize_info(struct iolog_details *details, char * const user_info[],
    char * const command_info[])
{
    const char *runas_uid_str = "0", *runas_euid_str = NULL;
    const char *runas_gid_str = "0", *runas_egid_str = NULL;
    const char *errstr;
    char idbuf[MAX_UID_T_LEN + 2];
    char * const *cur;
    id_t id;
    uid_t runas_uid = 0;
    gid_t runas_gid = 0;
    debug_decl(iolog_deserialize_info, SUDOERS_DEBUG_UTIL)

    details->lines = 24;
    details->cols = 80;

    for (cur = user_info; *cur != NULL; cur++) {
	switch (**cur) {
	case 'c':
	    if (strncmp(*cur, "cols=", sizeof("cols=") - 1) == 0) {
		int n = sudo_strtonum(*cur + sizeof("cols=") - 1, 1, INT_MAX,
		    NULL);
		if (n > 0)
		    details->cols = n;
		continue;
	    }
	    if (strncmp(*cur, "cwd=", sizeof("cwd=") - 1) == 0) {
		details->cwd = *cur + sizeof("cwd=") - 1;
		continue;
	    }
	    break;
	case 'l':
	    if (strncmp(*cur, "lines=", sizeof("lines=") - 1) == 0) {
		int n = sudo_strtonum(*cur + sizeof("lines=") - 1, 1, INT_MAX,
		    NULL);
		if (n > 0)
		    details->lines = n;
		continue;
	    }
	    break;
	case 't':
	    if (strncmp(*cur, "tty=", sizeof("tty=") - 1) == 0) {
		details->tty = *cur + sizeof("tty=") - 1;
		continue;
	    }
	    break;
	case 'u':
	    if (strncmp(*cur, "user=", sizeof("user=") - 1) == 0) {
		details->user = *cur + sizeof("user=") - 1;
		continue;
	    }
	    break;
	}
    }

    for (cur = command_info; *cur != NULL; cur++) {
	switch (**cur) {
	case 'c':
	    if (strncmp(*cur, "command=", sizeof("command=") - 1) == 0) {
		details->command = *cur + sizeof("command=") - 1;
		continue;
	    }
	    break;
	case 'i':
	    if (strncmp(*cur, "ignore_iolog_errors=", sizeof("ignore_iolog_errors=") - 1) == 0) {
		if (sudo_strtobool(*cur + sizeof("ignore_iolog_errors=") - 1) == true)
		    details->ignore_iolog_errors = true;
		continue;
	    }
	    if (strncmp(*cur, "iolog_path=", sizeof("iolog_path=") - 1) == 0) {
		details->iolog_path = *cur + sizeof("iolog_path=") - 1;
		continue;
	    }
	    if (strncmp(*cur, "iolog_stdin=", sizeof("iolog_stdin=") - 1) == 0) {
		if (sudo_strtobool(*cur + sizeof("iolog_stdin=") - 1) == true)
		    io_log_files[IOFD_STDIN].enabled = true;
		continue;
	    }
	    if (strncmp(*cur, "iolog_stdout=", sizeof("iolog_stdout=") - 1) == 0) {
		if (sudo_strtobool(*cur + sizeof("iolog_stdout=") - 1) == true)
		    io_log_files[IOFD_STDOUT].enabled = true;
		continue;
	    }
	    if (strncmp(*cur, "iolog_stderr=", sizeof("iolog_stderr=") - 1) == 0) {
		if (sudo_strtobool(*cur + sizeof("iolog_stderr=") - 1) == true)
		    io_log_files[IOFD_STDERR].enabled = true;
		continue;
	    }
	    if (strncmp(*cur, "iolog_ttyin=", sizeof("iolog_ttyin=") - 1) == 0) {
		if (sudo_strtobool(*cur + sizeof("iolog_ttyin=") - 1) == true)
		    io_log_files[IOFD_TTYIN].enabled = true;
		continue;
	    }
	    if (strncmp(*cur, "iolog_ttyout=", sizeof("iolog_ttyout=") - 1) == 0) {
		if (sudo_strtobool(*cur + sizeof("iolog_ttyout=") - 1) == true)
		    io_log_files[IOFD_TTYOUT].enabled = true;
		continue;
	    }
	    if (strncmp(*cur, "iolog_compress=", sizeof("iolog_compress=") - 1) == 0) {
		if (sudo_strtobool(*cur + sizeof("iolog_compress=") - 1) == true)
		    iolog_compress = true; /* must be global */
		continue;
	    }
	    if (strncmp(*cur, "iolog_mode=", sizeof("iolog_mode=") - 1) == 0) {
		mode_t mode = sudo_strtomode(*cur + sizeof("iolog_mode=") - 1, &errstr);
		if (errstr == NULL)
		    iolog_set_mode(mode);
		continue;
	    }
	    if (strncmp(*cur, "iolog_group=", sizeof("iolog_group=") - 1) == 0) {
		iolog_set_group(*cur + sizeof("iolog_group=") - 1);
		continue;
	    }
	    if (strncmp(*cur, "iolog_user=", sizeof("iolog_user=") - 1) == 0) {
		iolog_set_user(*cur + sizeof("iolog_user=") - 1);
		continue;
	    }
	    break;
	case 'm':
	    if (strncmp(*cur, "maxseq=", sizeof("maxseq=") - 1) == 0) {
		io_set_max_sessid(*cur + sizeof("maxseq=") - 1);
		continue;
	    }
	    break;
	case 'r':
	    if (strncmp(*cur, "runas_gid=", sizeof("runas_gid=") - 1) == 0) {
		runas_gid_str = *cur + sizeof("runas_gid=") - 1;
		continue;
	    }
	    if (strncmp(*cur, "runas_egid=", sizeof("runas_egid=") - 1) == 0) {
		runas_egid_str = *cur + sizeof("runas_egid=") - 1;
		continue;
	    }
	    if (strncmp(*cur, "runas_uid=", sizeof("runas_uid=") - 1) == 0) {
		runas_uid_str = *cur + sizeof("runas_uid=") - 1;
		continue;
	    }
	    if (strncmp(*cur, "runas_euid=", sizeof("runas_euid=") - 1) == 0) {
		runas_euid_str = *cur + sizeof("runas_euid=") - 1;
		continue;
	    }
	    break;
	}
    }

    /*
     * Lookup runas user and group, preferring effective over real uid/gid.
     */
    if (runas_euid_str != NULL)
	runas_uid_str = runas_euid_str;
    if (runas_uid_str != NULL) {
	id = sudo_strtoid(runas_uid_str, &errstr);
	if (errstr != NULL)
	    sudo_warnx("runas uid %s: %s", runas_uid_str, U_(errstr));
	else
	    runas_uid = (uid_t)id;
    }
    if (runas_egid_str != NULL)
	runas_gid_str = runas_egid_str;
    if (runas_gid_str != NULL) {
	id = sudo_strtoid(runas_gid_str, &errstr);
	if (errstr != NULL)
	    sudo_warnx("runas gid %s: %s", runas_gid_str, U_(errstr));
	else
	    runas_gid = (gid_t)id;
    }

    details->runas_pw = sudo_getpwuid(runas_uid);
    if (details->runas_pw == NULL) {
	idbuf[0] = '#';
	strlcpy(&idbuf[1], runas_uid_str, sizeof(idbuf) - 1);
	details->runas_pw = sudo_fakepwnam(idbuf, runas_gid);
    }

    if (runas_gid != details->runas_pw->pw_gid) {
	details->runas_gr = sudo_getgrgid(runas_gid);
	if (details->runas_gr == NULL) {
	    idbuf[0] = '#';
	    strlcpy(&idbuf[1], runas_gid_str, sizeof(idbuf) - 1);
	    details->runas_gr = sudo_fakegrnam(idbuf);
	}
    }
    debug_return_bool(
	io_log_files[IOFD_STDIN].enabled || io_log_files[IOFD_STDOUT].enabled ||
	io_log_files[IOFD_STDERR].enabled || io_log_files[IOFD_TTYIN].enabled ||
	io_log_files[IOFD_TTYOUT].enabled);
}

/*
 * Write the "/log" file that contains the user and command info.
 * This file is not compressed.
 */
static bool
write_info_log(char *pathbuf, size_t len, struct iolog_details *details,
    char * const argv[])
{
    time_t now;
    char * const *av;
    FILE *fp;
    int fd;
    bool ret = true;
    debug_decl(write_info_log, SUDOERS_DEBUG_UTIL)

    pathbuf[len] = '\0';
    strlcat(pathbuf, "/log", PATH_MAX);
    fd = io_open(pathbuf, O_CREAT|O_TRUNC|O_WRONLY, iolog_filemode);
    if (fd == -1 || (fp = fdopen(fd, "w")) == NULL) {
	log_warning(SLOG_SEND_MAIL, N_("unable to create %s"), pathbuf);
	debug_return_bool(false);
    }
    if (fchown(fd, iolog_uid, iolog_gid) != 0) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to fchown %d:%d %s", __func__,
	    (int)iolog_uid, (int)iolog_gid, pathbuf);
    }

    fprintf(fp, "%lld:%s:%s:%s:%s:%d:%d\n%s\n%s", (long long)time(&now),
	details->user ? details->user : "unknown", details->runas_pw->pw_name,
	details->runas_gr ? details->runas_gr->gr_name : "",
	details->tty ? details->tty : "unknown", details->lines, details->cols,
	details->cwd ? details->cwd : "unknown",
	details->command ? details->command : "unknown");
    for (av = argv + 1; *av != NULL; av++) {
	fputc(' ', fp);
	fputs(*av, fp);
    }
    fputc('\n', fp);
    fflush(fp);
    if (ferror(fp)) {
	log_warning(SLOG_SEND_MAIL,
	    N_("unable to write to I/O log file: %s"), strerror(errno));
	warned = true;
	ret = false;
    }
    fclose(fp);
    debug_return_bool(ret);
}

#ifdef HAVE_ZLIB_H
static const char *
gzstrerror(gzFile file)
{
    int errnum;

    return gzerror(file, &errnum);
}
#endif /* HAVE_ZLIB_H */

/*
 * Write to an I/O log, compressing if iolog_compress is enabled.
 * If def_iolog_flush is true, flush the buffer immediately.
 */
static const char *
iolog_write(union io_fd ifd, const void *buf, unsigned int len)
{
    const char *errstr = NULL;
    debug_decl(iolog_write, SUDOERS_DEBUG_PLUGIN)

#ifdef HAVE_ZLIB_H
    if (iolog_compress) {
	if (gzwrite(ifd.g, (const voidp)buf, len) != (int)len) {
	    errstr = gzstrerror(ifd.g);
	    goto done;
	}
	if (def_iolog_flush) {
	    if (gzflush(ifd.g, Z_SYNC_FLUSH) != Z_OK) {
		errstr = gzstrerror(ifd.g);
		goto done;
	    }
	}
    } else
#endif
    {
	if (fwrite(buf, 1, len, ifd.f) != len) {
	    errstr = strerror(errno);
	    goto done;
	}
	if (def_iolog_flush) {
	    if (fflush(ifd.f) != 0) {
		errstr = strerror(errno);
		goto done;
	    }
	}
    }

done:
    debug_return_const_str(errstr);
}

static int
sudoers_io_open(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, char * const settings[],
    char * const user_info[], char * const command_info[],
    int argc, char * const argv[], char * const user_env[], char * const args[])
{
    struct sudo_conf_debug_file_list debug_files = TAILQ_HEAD_INITIALIZER(debug_files);
    char pathbuf[PATH_MAX], sessid[7];
    char *tofree = NULL;
    char * const *cur;
    const char *cp, *plugin_path = NULL;
    size_t len;
    mode_t omask;
    int i, ret = -1;
    debug_decl(sudoers_io_open, SUDOERS_DEBUG_PLUGIN)

    sudo_conv = conversation;
    sudo_printf = plugin_printf;

    /* If we have no command (because -V was specified) just return. */
    if (argc == 0)
	debug_return_int(true);

    bindtextdomain("sudoers", LOCALEDIR);

    /* Initialize the debug subsystem.  */
    for (cur = settings; (cp = *cur) != NULL; cur++) {
	if (strncmp(cp, "debug_flags=", sizeof("debug_flags=") - 1) == 0) {
	    cp += sizeof("debug_flags=") - 1;
	    if (!sudoers_debug_parse_flags(&debug_files, cp))
		debug_return_int(-1);
	    continue;
	}
	if (strncmp(cp, "plugin_path=", sizeof("plugin_path=") - 1) == 0) {
	    plugin_path = cp + sizeof("plugin_path=") - 1;
	    continue;
	}
    }

    /* umask must not be more restrictive than the file modes. */
    omask = umask(ACCESSPERMS & ~(iolog_filemode|iolog_dirmode));

    if (!sudoers_debug_register(plugin_path, &debug_files)) {
	ret = -1;
	goto done;
    }

    /*
     * Pull iolog settings out of command_info.
     */
    if (!iolog_deserialize_info(&iolog_details, user_info, command_info)) {
	ret = false;
	goto done;
    }

    /* If no I/O log path defined we need to figure it out ourselves. */
    if (iolog_details.iolog_path == NULL) {
	/* Get next session ID and convert it into a path. */
	tofree = malloc(sizeof(_PATH_SUDO_IO_LOGDIR) + sizeof(sessid) + 2);
	if (tofree == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto done;
	}
	memcpy(tofree, _PATH_SUDO_IO_LOGDIR, sizeof(_PATH_SUDO_IO_LOGDIR));
	if (!io_nextid(tofree, NULL, sessid)) {
	    ret = false;
	    goto done;
	}
	(void)snprintf(tofree + sizeof(_PATH_SUDO_IO_LOGDIR),
	    sizeof(sessid) + 2, "%c%c/%c%c/%c%c", sessid[0], sessid[1],
	    sessid[2], sessid[3], sessid[4], sessid[5]);
	iolog_details.iolog_path = tofree;
    }

    /*
     * Make local copy of I/O log path and create it, along with any
     * intermediate subdirs.  Calls mkdtemp() if iolog_path ends in XXXXXX.
     */
    len = mkdir_iopath(iolog_details.iolog_path, pathbuf, sizeof(pathbuf));
    if (len >= sizeof(pathbuf))
	goto done;

    /* Write log file with user and command details. */
    if (!write_info_log(pathbuf, len, &iolog_details, argv))
	goto done;

    /* Create the timing and I/O log files. */
    for (i = 0; i < IOFD_MAX; i++) {
	if (!open_io_fd(pathbuf, len, &io_log_files[i], iolog_compress))
	    goto done;
    }

    /*
     * Clear I/O log function pointers for disabled log functions.
     */
    if (!io_log_files[IOFD_STDIN].enabled)
	sudoers_io.log_stdin = NULL;
    if (!io_log_files[IOFD_STDOUT].enabled)
	sudoers_io.log_stdout = NULL;
    if (!io_log_files[IOFD_STDERR].enabled)
	sudoers_io.log_stderr = NULL;
    if (!io_log_files[IOFD_TTYIN].enabled)
	sudoers_io.log_ttyin = NULL;
    if (!io_log_files[IOFD_TTYOUT].enabled)
	sudoers_io.log_ttyout = NULL;

    if (sudo_gettime_awake(&last_time) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to get time of day", __func__);
	goto done;
    }

    ret = true;

done:
    umask(omask);
    free(tofree);
    if (iolog_details.runas_pw)
	sudo_pw_delref(iolog_details.runas_pw);
    if (iolog_details.runas_gr)
	sudo_gr_delref(iolog_details.runas_gr);
    sudo_freepwcache();
    sudo_freegrcache();

    /* Ignore errors if they occur if the policy says so. */
    if (ret == -1 && iolog_details.ignore_iolog_errors)
	ret = 0;

    debug_return_int(ret);
}

static void
sudoers_io_close(int exit_status, int error)
{
    const char *errstr = NULL;
    int i;
    debug_decl(sudoers_io_close, SUDOERS_DEBUG_PLUGIN)

    for (i = 0; i < IOFD_MAX; i++) {
	if (io_log_files[i].fd.v == NULL)
	    continue;
#ifdef HAVE_ZLIB_H
	if (iolog_compress) {
	    int errnum;

	    if (gzclose(io_log_files[i].fd.g) != Z_OK)
		errstr = gzerror(io_log_files[i].fd.g, &errnum);
	} else
#endif
	if (fclose(io_log_files[i].fd.f) != 0)
	    errstr = strerror(errno);
    }

    if (errstr != NULL && !warned) {
	/* Only warn about I/O log file errors once. */
	log_warning(SLOG_SEND_MAIL,
	    N_("unable to write to I/O log file: %s"), errstr);
	warned = true;
    }

    sudoers_debug_deregister();

    return;
}

static int
sudoers_io_version(int verbose)
{
    debug_decl(sudoers_io_version, SUDOERS_DEBUG_PLUGIN)

    sudo_printf(SUDO_CONV_INFO_MSG, "Sudoers I/O plugin version %s\n",
	PACKAGE_VERSION);

    debug_return_int(true);
}

/*
 * Generic I/O logging function.  Called by the I/O logging entry points.
 * Returns 1 on success and -1 on error.
 */
static int
sudoers_io_log(union io_fd ifd, const char *buf, unsigned int len, int event)
{
    struct timespec now, delay;
    char tbuf[1024];
    const char *errstr = NULL;
    int ret = -1;
    debug_decl(sudoers_io_log, SUDOERS_DEBUG_PLUGIN)

    if (ifd.v == NULL) {
	sudo_warnx(U_("%s: internal error, I/O log file for event %d not open"),
	    __func__, event);
	debug_return_int(-1);
    }

    if (sudo_gettime_awake(&now) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to get time of day", __func__);
	errstr = strerror(errno);
	goto bad;
    }

    /* Write I/O log file entry. */
    errstr = iolog_write(ifd, buf, len);
    if (errstr != NULL)
	goto done;

    /* Write timing file entry. */
    sudo_timespecsub(&now, &last_time, &delay);
    len = (unsigned int)snprintf(tbuf, sizeof(tbuf), "%d %lld.%09ld %u\n",
	event, (long long)delay.tv_sec, delay.tv_nsec, len);
    if (len >= sizeof(tbuf)) {
	/* Not actually possible due to the size of tbuf[]. */
	errstr = strerror(EOVERFLOW);
	goto done;
    }
    errstr = iolog_write(io_log_files[IOFD_TIMING].fd, tbuf, len);
    if (errstr != NULL)
	goto done;

    /* Success. */
    ret = 1;

done:
    last_time.tv_sec = now.tv_sec;
    last_time.tv_nsec = now.tv_nsec;

bad:
    if (ret == -1) {
	if (errstr != NULL && !warned) {
	    /* Only warn about I/O log file errors once. */
	    log_warning(SLOG_SEND_MAIL,
		N_("unable to write to I/O log file: %s"), errstr);
	    warned = true;
	}

	/* Ignore errors if they occur if the policy says so. */
	if (iolog_details.ignore_iolog_errors)
	    ret = 1;
    }

    debug_return_int(ret);
}

static int
sudoers_io_log_stdin(const char *buf, unsigned int len)
{
    const union io_fd ifd = io_log_files[IOFD_STDIN].fd;

    return sudoers_io_log(ifd, buf, len, IO_EVENT_STDIN);
}

static int
sudoers_io_log_stdout(const char *buf, unsigned int len)
{
    const union io_fd ifd = io_log_files[IOFD_STDOUT].fd;

    return sudoers_io_log(ifd, buf, len, IO_EVENT_STDOUT);
}

static int
sudoers_io_log_stderr(const char *buf, unsigned int len)
{
    const union io_fd ifd = io_log_files[IOFD_STDERR].fd;

    return sudoers_io_log(ifd, buf, len, IO_EVENT_STDERR);
}

static int
sudoers_io_log_ttyin(const char *buf, unsigned int len)
{
    const union io_fd ifd = io_log_files[IOFD_TTYIN].fd;

    return sudoers_io_log(ifd, buf, len, IO_EVENT_TTYIN);
}

static int
sudoers_io_log_ttyout(const char *buf, unsigned int len)
{
    const union io_fd ifd = io_log_files[IOFD_TTYOUT].fd;

    return sudoers_io_log(ifd, buf, len, IO_EVENT_TTYOUT);
}

static int
sudoers_io_change_winsize(unsigned int lines, unsigned int cols)
{
    struct timespec now, delay;
    unsigned int len;
    char tbuf[1024];
    const char *errstr = NULL;
    int ret = -1;
    debug_decl(sudoers_io_change_winsize, SUDOERS_DEBUG_PLUGIN)

    if (sudo_gettime_awake(&now) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to get time of day", __func__);
	errstr = strerror(errno);
	goto bad;
    }

    /* Write window change event to the timing file. */
    sudo_timespecsub(&now, &last_time, &delay);
    len = (unsigned int)snprintf(tbuf, sizeof(tbuf), "%d %lld.%09ld %u %u\n",
	IO_EVENT_WINSIZE, (long long)delay.tv_sec, delay.tv_nsec, lines, cols);
    if (len >= sizeof(tbuf)) {
	/* Not actually possible due to the size of tbuf[]. */
	errstr = strerror(EOVERFLOW);
	goto done;
    }
    errstr = iolog_write(io_log_files[IOFD_TIMING].fd, tbuf, len);
    if (errstr != NULL)
	goto done;

    /* Success. */
    ret = 1;

done:
    last_time.tv_sec = now.tv_sec;
    last_time.tv_nsec = now.tv_nsec;

bad:
    if (ret == -1) {
	if (errstr != NULL && !warned) {
	    /* Only warn about I/O log file errors once. */
	    log_warning(SLOG_SEND_MAIL,
		N_("unable to write to I/O log file: %s"), errstr);
	    warned = true;
	}

	/* Ignore errors if they occur if the policy says so. */
	if (iolog_details.ignore_iolog_errors)
	    ret = 1;
    }

    debug_return_int(ret);
}

static int
sudoers_io_suspend(int signo)
{
    struct timespec now, delay;
    unsigned int len;
    char signame[SIG2STR_MAX];
    char tbuf[1024];
    const char *errstr = NULL;
    int ret = -1;
    debug_decl(sudoers_io_suspend, SUDOERS_DEBUG_PLUGIN)

    if (signo <= 0 || sig2str(signo, signame) == -1) {
	sudo_warnx(U_("%s: internal error, invalid signal %d"),
	    __func__, signo);
	debug_return_int(-1);
    }

    if (sudo_gettime_awake(&now) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to get time of day", __func__);
	errstr = strerror(errno);
	goto bad;
    }

    /* Write suspend event to the timing file. */
    sudo_timespecsub(&now, &last_time, &delay);
    len = (unsigned int)snprintf(tbuf, sizeof(tbuf), "%d %lld.%09ld %s\n",
	IO_EVENT_SUSPEND, (long long)delay.tv_sec, delay.tv_nsec, signame);
    if (len >= sizeof(tbuf)) {
	/* Not actually possible due to the size of tbuf[]. */
	errstr = strerror(EOVERFLOW);
	goto done;
    }
    errstr = iolog_write(io_log_files[IOFD_TIMING].fd, tbuf, len);
    if (errstr != NULL)
	goto done;

    /* Success. */
    ret = 1;

done:
    last_time.tv_sec = now.tv_sec;
    last_time.tv_nsec = now.tv_nsec;

bad:
    if (ret == -1) {
	if (errstr != NULL && !warned) {
	    /* Only warn about I/O log file errors once. */
	    log_warning(SLOG_SEND_MAIL,
		N_("unable to write to I/O log file: %s"), errstr);
	    warned = true;
	}

	/* Ignore errors if they occur if the policy says so. */
	if (iolog_details.ignore_iolog_errors)
	    ret = 1;
    }

    debug_return_int(ret);
}

__dso_public struct io_plugin sudoers_io = {
    SUDO_IO_PLUGIN,
    SUDO_API_VERSION,
    sudoers_io_open,
    sudoers_io_close,
    sudoers_io_version,
    sudoers_io_log_ttyin,
    sudoers_io_log_ttyout,
    sudoers_io_log_stdin,
    sudoers_io_log_stdout,
    sudoers_io_log_stderr,
    NULL, /* register_hooks */
    NULL, /* deregister_hooks */
    sudoers_io_change_winsize,
    sudoers_io_suspend
};
