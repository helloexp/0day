/*
 * Copyright (c) 2011-2018 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <config.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
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
#ifdef HAVE_UTMPX_H
# include <utmpx.h>
#else
# include <utmp.h>
#endif /* HAVE_UTMPX_H */
#ifdef HAVE_GETTTYENT
# include <ttyent.h>
#endif
#include <fcntl.h>
#include <signal.h>

#include "sudo.h"
#include "sudo_exec.h"

/*
 * Simplify handling of utmp vs. utmpx
 */
#if !defined(HAVE_GETUTXID) && defined(HAVE_GETUTID)
# define getutxline(u)	getutline(u)
# define pututxline(u)	pututline(u)
# define setutxent()	setutent()
# define endutxent()	endutent()
#endif /* !HAVE_GETUTXID && HAVE_GETUTID */

#ifdef HAVE_GETUTXID
typedef struct utmpx sudo_utmp_t;
#else
typedef struct utmp sudo_utmp_t;
/* Older systems have ut_name, not us_user */
# if !defined(HAVE_STRUCT_UTMP_UT_USER) && !defined(ut_user)
#  define ut_user ut_name
# endif
#endif

/* HP-UX has __e_termination and __e_exit, others lack the __ */
#if defined(HAVE_STRUCT_UTMPX_UT_EXIT_E_TERMINATION) || defined(HAVE_STRUCT_UTMP_UT_EXIT_E_TERMINATION)
# undef  __e_termination
# define __e_termination	e_termination
# undef  __e_exit
# define __e_exit		e_exit
#endif

#if defined(HAVE_GETUTXID) || defined(HAVE_GETUTID)
/*
 * Create ut_id from the new ut_line and the old ut_id.
 */
static void
utmp_setid(sudo_utmp_t *old, sudo_utmp_t *new)
{
    const char *line = new->ut_line;
    size_t idlen;
    debug_decl(utmp_setid, SUDO_DEBUG_UTMP)

    /* Skip over "tty" in the id if old entry did too. */
    if (old != NULL) {
	/* cppcheck-suppress uninitdata */
	if (strncmp(line, "tty", 3) == 0) {
	    idlen = MIN(sizeof(old->ut_id), 3);
	    if (strncmp(old->ut_id, "tty", idlen) != 0)
		line += 3;
	}
    }
    
    /* Store as much as will fit, skipping parts of the beginning as needed. */
    /* cppcheck-suppress uninitdata */
    idlen = strlen(line);
    if (idlen > sizeof(new->ut_id)) {
	line += idlen - sizeof(new->ut_id);
	idlen = sizeof(new->ut_id);
    }
    strncpy(new->ut_id, line, idlen);

    debug_return;
}
#endif /* HAVE_GETUTXID || HAVE_GETUTID */

/*
 * Store time in utmp structure.
 */
static void
utmp_settime(sudo_utmp_t *ut)
{
    struct timeval tv;
    debug_decl(utmp_settime, SUDO_DEBUG_UTMP)

    if (gettimeofday(&tv, NULL) == 0) {
#if defined(HAVE_STRUCT_UTMP_UT_TV) || defined(HAVE_STRUCT_UTMPX_UT_TV)
	ut->ut_tv.tv_sec = tv.tv_sec;
	ut->ut_tv.tv_usec = tv.tv_usec;
#else
	ut->ut_time = tv.tv_sec;
#endif
    }

    debug_return;
}

/*
 * Fill in a utmp entry, using an old entry as a template if there is one.
 */
static void
utmp_fill(const char *line, const char *user, sudo_utmp_t *ut_old,
    sudo_utmp_t *ut_new)
{
    debug_decl(utmp_file, SUDO_DEBUG_UTMP)

    if (ut_old == NULL) {
	memset(ut_new, 0, sizeof(*ut_new));
	if (user == NULL) {
	    strncpy(ut_new->ut_user, user_details.username,
		sizeof(ut_new->ut_user));
	}
    } else if (ut_old != ut_new) {
	memcpy(ut_new, ut_old, sizeof(*ut_new));
    }
    if (user != NULL)
	strncpy(ut_new->ut_user, user, sizeof(ut_new->ut_user));
    strncpy(ut_new->ut_line, line, sizeof(ut_new->ut_line));
#if defined(HAVE_STRUCT_UTMPX_UT_ID) || defined(HAVE_STRUCT_UTMP_UT_ID)
    utmp_setid(ut_old, ut_new);
#endif
#if defined(HAVE_STRUCT_UTMPX_UT_PID) || defined(HAVE_STRUCT_UTMP_UT_PID)
    ut_new->ut_pid = getpid();
#endif
    utmp_settime(ut_new);
#if defined(HAVE_STRUCT_UTMPX_UT_TYPE) || defined(HAVE_STRUCT_UTMP_UT_TYPE)
    ut_new->ut_type = USER_PROCESS;
#endif
    debug_return;
}

/*
 * There are two basic utmp file types:
 *
 *  POSIX:  sequential access with new entries appended to the end.
 *	    Manipulated via {get,put}utent()/{get,put}getutxent().
 *
 *  Legacy: sparse file indexed by ttyslot() * sizeof(struct utmp)
 */
#if defined(HAVE_GETUTXID) || defined(HAVE_GETUTID)
bool
utmp_login(const char *from_line, const char *to_line, int ttyfd,
    const char *user)
{
    sudo_utmp_t utbuf, *ut_old = NULL;
    bool ret = false;
    debug_decl(utmp_login, SUDO_DEBUG_UTMP)

    /* Strip off /dev/ prefix from line as needed. */
    if (strncmp(to_line, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
	to_line += sizeof(_PATH_DEV) - 1;
    setutxent();
    if (from_line != NULL) {
	if (strncmp(from_line, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
	    from_line += sizeof(_PATH_DEV) - 1;

	/* Lookup old line. */
	memset(&utbuf, 0, sizeof(utbuf));
	strncpy(utbuf.ut_line, from_line, sizeof(utbuf.ut_line));
	ut_old = getutxline(&utbuf);
    }
    utmp_fill(to_line, user, ut_old, &utbuf);
    if (pututxline(&utbuf) != NULL)
	ret = true;
    endutxent();

    debug_return_bool(ret);
}

bool
utmp_logout(const char *line, int status)
{
    bool ret = false;
    sudo_utmp_t *ut, utbuf;
    debug_decl(utmp_logout, SUDO_DEBUG_UTMP)

    /* Strip off /dev/ prefix from line as needed. */
    if (strncmp(line, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
	line += sizeof(_PATH_DEV) - 1;
   
    memset(&utbuf, 0, sizeof(utbuf));
    strncpy(utbuf.ut_line, line, sizeof(utbuf.ut_line));
    if ((ut = getutxline(&utbuf)) != NULL) {
	memset(ut->ut_user, 0, sizeof(ut->ut_user));
# if defined(HAVE_STRUCT_UTMPX_UT_TYPE) || defined(HAVE_STRUCT_UTMP_UT_TYPE)
	ut->ut_type = DEAD_PROCESS;
# endif
# if defined(HAVE_STRUCT_UTMPX_UT_EXIT) || defined(HAVE_STRUCT_UTMP_UT_EXIT)
	ut->ut_exit.__e_termination = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
	ut->ut_exit.__e_exit = WIFEXITED(status) ? WEXITSTATUS(status) : 0;
# endif
	utmp_settime(ut);
	if (pututxline(ut) != NULL)
	    ret = true;
    }
    debug_return_bool(ret);
}

#else /* !HAVE_GETUTXID && !HAVE_GETUTID */

/*
 * Find the slot for the specified line (tty name and file descriptor).
 * Returns a slot suitable for seeking into utmp on success or <= 0 on error.
 * If getttyent() is available we can use that to compute the slot.
 */
# ifdef HAVE_GETTTYENT
static int
utmp_slot(const char *line, int ttyfd)
{
    int slot = 1;
    struct ttyent *tty;
    debug_decl(utmp_slot, SUDO_DEBUG_UTMP)

    setttyent();
    while ((tty = getttyent()) != NULL) {
	if (strcmp(line, tty->ty_name) == 0)
	    break;
	slot++;
    }
    endttyent();
    debug_return_int(tty ? slot : 0);
}
# else
static int
utmp_slot(const char *line, int ttyfd)
{
    int sfd, slot;
    debug_decl(utmp_slot, SUDO_DEBUG_UTMP)

    /*
     * Temporarily point stdin to the tty since ttyslot()
     * doesn't take an argument.
     */
    if ((sfd = dup(STDIN_FILENO)) == -1)
	sudo_fatal(U_("unable to save stdin"));
    if (dup2(ttyfd, STDIN_FILENO) == -1)
	sudo_fatal(U_("unable to dup2 stdin"));
    slot = ttyslot();
    if (dup2(sfd, STDIN_FILENO) == -1)
	sudo_fatal(U_("unable to restore stdin"));
    close(sfd);

    debug_return_int(slot);
}
# endif /* HAVE_GETTTYENT */

bool
utmp_login(const char *from_line, const char *to_line, int ttyfd,
    const char *user)
{
    sudo_utmp_t utbuf, *ut_old = NULL;
    bool ret = false;
    int slot;
    FILE *fp;
    debug_decl(utmp_login, SUDO_DEBUG_UTMP)

    /* Strip off /dev/ prefix from line as needed. */
    if (strncmp(to_line, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
	to_line += sizeof(_PATH_DEV) - 1;

    /* Find slot for new entry. */
    slot = utmp_slot(to_line, ttyfd);
    if (slot <= 0)
	goto done;

    if ((fp = fopen(_PATH_UTMP, "r+")) == NULL)
	goto done;

    if (from_line != NULL) {
	if (strncmp(from_line, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
	    from_line += sizeof(_PATH_DEV) - 1;

	/* Lookup old line. */
	while (fread(&utbuf, sizeof(utbuf), 1, fp) == 1) {
# ifdef HAVE_STRUCT_UTMP_UT_ID
	    if (utbuf.ut_type != LOGIN_PROCESS && utbuf.ut_type != USER_PROCESS)
		continue;
# endif
	    if (utbuf.ut_user[0] &&
		!strncmp(utbuf.ut_line, from_line, sizeof(utbuf.ut_line))) {
		ut_old = &utbuf;
		break;
	    }
	}
    }
    utmp_fill(to_line, user, ut_old, &utbuf);
#ifdef HAVE_FSEEKO
    if (fseeko(fp, slot * (off_t)sizeof(utbuf), SEEK_SET) == 0) {
#else
    if (fseek(fp, slot * (long)sizeof(utbuf), SEEK_SET) == 0) {
#endif
	if (fwrite(&utbuf, sizeof(utbuf), 1, fp) == 1)
	    ret = true;
    }
    fclose(fp);

done:
    debug_return_bool(ret);
}

bool
utmp_logout(const char *line, int status)
{
    sudo_utmp_t utbuf;
    bool ret = false;
    FILE *fp;
    debug_decl(utmp_logout, SUDO_DEBUG_UTMP)

    if ((fp = fopen(_PATH_UTMP, "r+")) == NULL)
	debug_return_int(ret);

    /* Strip off /dev/ prefix from line as needed. */
    if (strncmp(line, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
	line += sizeof(_PATH_DEV) - 1;
   
    while (fread(&utbuf, sizeof(utbuf), 1, fp) == 1) {
	if (!strncmp(utbuf.ut_line, line, sizeof(utbuf.ut_line))) {
	    memset(utbuf.ut_user, 0, sizeof(utbuf.ut_user));
# if defined(HAVE_STRUCT_UTMP_UT_TYPE)
	    utbuf.ut_type = DEAD_PROCESS;
# endif
	    utmp_settime(&utbuf);
	    /* Back up and overwrite record. */
#ifdef HAVE_FSEEKO
	    if (fseeko(fp, (off_t)0 - (off_t)sizeof(utbuf), SEEK_CUR) == 0) {
#else
	    if (fseek(fp, 0L - (long)sizeof(utbuf), SEEK_CUR) == 0) {
#endif
		if (fwrite(&utbuf, sizeof(utbuf), 1, fp) == 1)
		    ret = true;
	    }
	    break;
	}
    }
    fclose(fp);

    debug_return_bool(ret);
}
#endif /* HAVE_GETUTXID || HAVE_GETUTID */
