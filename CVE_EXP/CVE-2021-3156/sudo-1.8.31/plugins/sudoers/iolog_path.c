/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2011-2015 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <pwd.h>
#include <grp.h>
#include <time.h>

#include "sudoers.h"

struct path_escape {
    const char *name;
    size_t (*copy_fn)(char *, size_t, char *);
};

static size_t
fill_seq(char *str, size_t strsize, char *logdir)
{
#ifdef SUDOERS_NO_SEQ
    debug_decl(fill_seq, SUDOERS_DEBUG_UTIL)
    debug_return_size_t(strlcpy(str, "%{seq}", strsize));
#else
    static char sessid[7];
    int len;
    debug_decl(fill_seq, SUDOERS_DEBUG_UTIL)

    if (sessid[0] == '\0') {
	if (!io_nextid(logdir, def_iolog_dir, sessid))
	    debug_return_size_t((size_t)-1);
    }

    /* Path is of the form /var/log/sudo-io/00/00/01. */
    len = snprintf(str, strsize, "%c%c/%c%c/%c%c", sessid[0],
	sessid[1], sessid[2], sessid[3], sessid[4], sessid[5]);
    if (len < 0)
	debug_return_size_t(strsize); /* handle non-standard snprintf() */
    debug_return_size_t(len);
#endif /* SUDOERS_NO_SEQ */
}

static size_t
fill_user(char *str, size_t strsize, char *unused)
{
    debug_decl(fill_user, SUDOERS_DEBUG_UTIL)
    debug_return_size_t(strlcpy(str, user_name, strsize));
}

static size_t
fill_group(char *str, size_t strsize, char *unused)
{
    struct group *grp;
    size_t len;
    debug_decl(fill_group, SUDOERS_DEBUG_UTIL)

    if ((grp = sudo_getgrgid(user_gid)) != NULL) {
	len = strlcpy(str, grp->gr_name, strsize);
	sudo_gr_delref(grp);
    } else {
	len = strlen(str);
	len = snprintf(str + len, strsize - len, "#%u",
	    (unsigned int) user_gid);
    }
    debug_return_size_t(len);
}

static size_t
fill_runas_user(char *str, size_t strsize, char *unused)
{
    debug_decl(fill_runas_user, SUDOERS_DEBUG_UTIL)
    debug_return_size_t(strlcpy(str, runas_pw->pw_name, strsize));
}

static size_t
fill_runas_group(char *str, size_t strsize, char *unused)
{
    struct group *grp;
    size_t len;
    debug_decl(fill_runas_group, SUDOERS_DEBUG_UTIL)

    if (runas_gr != NULL) {
	len = strlcpy(str, runas_gr->gr_name, strsize);
    } else {
	if ((grp = sudo_getgrgid(runas_pw->pw_gid)) != NULL) {
	    len = strlcpy(str, grp->gr_name, strsize);
	    sudo_gr_delref(grp);
	} else {
	    len = strlen(str);
	    len = snprintf(str + len, strsize - len, "#%u",
		(unsigned int) runas_pw->pw_gid);
	}
    }
    debug_return_size_t(len);
}

static size_t
fill_hostname(char *str, size_t strsize, char *unused)
{
    debug_decl(fill_hostname, SUDOERS_DEBUG_UTIL)
    debug_return_size_t(strlcpy(str, user_shost, strsize));
}

static size_t
fill_command(char *str, size_t strsize, char *unused)
{
    debug_decl(fill_command, SUDOERS_DEBUG_UTIL)
    debug_return_size_t(strlcpy(str, user_base, strsize));
}

/* Note: "seq" must be first in the list. */
static struct path_escape io_path_escapes[] = {
    { "seq", fill_seq },
    { "user", fill_user },
    { "group", fill_group },
    { "runas_user", fill_runas_user },
    { "runas_group", fill_runas_group },
    { "hostname", fill_hostname },
    { "command", fill_command },
    { NULL, NULL }
};

/*
 * Concatenate dir + file, expanding any escape sequences.
 * Returns the concatenated path and sets slashp point to
 * the path separator between the expanded dir and file.
 */
char *
expand_iolog_path(const char *prefix, const char *dir, const char *file,
    char **slashp)
{
    size_t len, prelen = 0;
    char *dst, *dst0, *path, *pathend, tmpbuf[PATH_MAX];
    char *slash = NULL;
    const char *endbrace, *src = dir;
    struct path_escape *escapes = NULL;
    int pass, oldlocale;
    bool strfit;
    debug_decl(expand_iolog_path, SUDOERS_DEBUG_UTIL)

    /* Expanded path must be <= PATH_MAX */
    if (prefix != NULL)
	prelen = strlen(prefix);
    path = malloc(prelen + PATH_MAX);
    if (path == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto bad;
    }
    *path = '\0';
    pathend = path + prelen + PATH_MAX;
    dst = path;

    /* Copy prefix, if present. */
    if (prefix != NULL) {
	memcpy(path, prefix, prelen);
	dst += prelen;
	*dst = '\0';
    }

    /* Trim leading slashes from file component. */
    while (*file == '/')
	file++;

    for (pass = 0; pass < 3; pass++) {
	strfit = false;
	switch (pass) {
	case 0:
	    src = dir;
	    escapes = io_path_escapes + 1; /* skip "%{seq}" */
	    break;
	case 1:
	    /* Trim trailing slashes from dir component. */
	    while (dst > path + prelen + 1 && dst[-1] == '/')
		dst--;
	    /* The NUL will be replaced with a '/' at the end. */
	    if (dst + 1 >= pathend)
		goto bad;
	    slash = dst++;
	    continue;
	case 2:
	    src = file;
	    escapes = io_path_escapes;
	    break;
	}
	dst0 = dst;
	for (; *src != '\0'; src++) {
	    if (src[0] == '%') {
		if (src[1] == '{') {
		    endbrace = strchr(src + 2, '}');
		    if (endbrace != NULL) {
			struct path_escape *esc;
			len = (size_t)(endbrace - src - 2);
			for (esc = escapes; esc->name != NULL; esc++) {
			    if (strncmp(src + 2, esc->name, len) == 0 &&
				esc->name[len] == '\0')
				break;
			}
			if (esc->name != NULL) {
			    len = esc->copy_fn(dst, (size_t)(pathend - dst),
				path + prelen);
			    if (len >= (size_t)(pathend - dst))
				goto bad;
			    dst += len;
			    src = endbrace;
			    continue;
			}
		    }
		} else if (src[1] == '%') {
		    /* Collapse %% -> % */
		    src++;
		} else {
		    /* May need strftime() */
		    strfit = 1;
		}
	    }
	    /* Need at least 2 chars, including the NUL terminator. */
	    if (dst + 1 >= pathend)
		goto bad;
	    *dst++ = *src;
	}
	*dst = '\0';

	/* Expand strftime escapes as needed. */
	if (strfit) {
	    time_t now;
	    struct tm *timeptr;

	    time(&now);
	    if ((timeptr = localtime(&now)) == NULL)
		goto bad;

	    /* Use sudoers locale for strftime() */
	    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

	    /* We only call strftime() on the current part of the buffer. */
	    tmpbuf[sizeof(tmpbuf) - 1] = '\0';
	    len = strftime(tmpbuf, sizeof(tmpbuf), dst0, timeptr);

	    /* Restore old locale. */
	    sudoers_setlocale(oldlocale, NULL);

	    if (len == 0 || tmpbuf[sizeof(tmpbuf) - 1] != '\0')
		goto bad;		/* strftime() failed, buf too small? */

	    if (len >= (size_t)(pathend - dst0))
		goto bad;		/* expanded buffer too big to fit. */
	    memcpy(dst0, tmpbuf, len);
	    dst = dst0 + len;
	    *dst = '\0';
	}
    }
    if (slash != NULL)
	*slash = '/';
    if (slashp != NULL)
	*slashp = slash;

    debug_return_str(path);
bad:
    free(path);
    debug_return_str(NULL);
}
