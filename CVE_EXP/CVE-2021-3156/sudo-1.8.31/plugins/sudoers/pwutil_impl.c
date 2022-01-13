/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1996, 1998-2005, 2007-2018
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>

#include "sudoers.h"
#include "pwutil.h"

#ifndef LOGIN_NAME_MAX
# ifdef _POSIX_LOGIN_NAME_MAX
#  define LOGIN_NAME_MAX _POSIX_LOGIN_NAME_MAX
# else
#  define LOGIN_NAME_MAX 9
# endif
#endif /* LOGIN_NAME_MAX */

#define FIELD_SIZE(src, name, size)			\
do {							\
	if (src->name) {				\
		size = strlen(src->name) + 1;		\
		total += size;				\
	}                                               \
} while (0)

#define FIELD_COPY(src, dst, name, size)		\
do {							\
	if (src->name) {				\
		memcpy(cp, src->name, size);		\
		dst->name = cp;				\
		cp += size;				\
	}						\
} while (0)

/*
 * Dynamically allocate space for a struct item plus the key and data
 * elements.  If name is non-NULL it is used as the key, else the
 * uid is the key.  Fills in datum from struct password.
 * Returns NULL on calloc error or unknown name/id, setting errno
 * to ENOMEM or ENOENT respectively.
 */
struct cache_item *
sudo_make_pwitem(uid_t uid, const char *name)
{
    char *cp;
    const char *pw_shell;
    size_t nsize, psize, csize, gsize, dsize, ssize, total;
    struct cache_item_pw *pwitem;
    struct passwd *pw, *newpw;
    debug_decl(sudo_make_pwitem, SUDOERS_DEBUG_NSS)

    /* Look up by name or uid. */
    pw = name ? getpwnam(name) : getpwuid(uid);
    if (pw == NULL) {
	errno = ENOENT;
	debug_return_ptr(NULL);
    }

    /* If shell field is empty, expand to _PATH_BSHELL. */
    pw_shell = (pw->pw_shell == NULL || pw->pw_shell[0] == '\0')
	? _PATH_BSHELL : pw->pw_shell;

    /* Allocate in one big chunk for easy freeing. */
    nsize = psize = csize = gsize = dsize = ssize = 0;
    total = sizeof(*pwitem);
    FIELD_SIZE(pw, pw_name, nsize);
    FIELD_SIZE(pw, pw_passwd, psize);
#ifdef HAVE_LOGIN_CAP_H
    FIELD_SIZE(pw, pw_class, csize);
#endif
    FIELD_SIZE(pw, pw_gecos, gsize);
    FIELD_SIZE(pw, pw_dir, dsize);
    /* Treat shell specially since we expand "" -> _PATH_BSHELL */
    ssize = strlen(pw_shell) + 1;
    total += ssize;
    if (name != NULL)
	total += strlen(name) + 1;

    /* Allocate space for struct item, struct passwd and the strings. */
    if ((pwitem = calloc(1, total)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_ptr(NULL);
    }
    newpw = &pwitem->pw;

    /*
     * Copy in passwd contents and make strings relative to space
     * at the end of the struct.
     */
    memcpy(newpw, pw, sizeof(*pw));
    cp = (char *)(pwitem + 1);
    FIELD_COPY(pw, newpw, pw_name, nsize);
    FIELD_COPY(pw, newpw, pw_passwd, psize);
#ifdef HAVE_LOGIN_CAP_H
    FIELD_COPY(pw, newpw, pw_class, csize);
#endif
    FIELD_COPY(pw, newpw, pw_gecos, gsize);
    FIELD_COPY(pw, newpw, pw_dir, dsize);
    /* Treat shell specially since we expand "" -> _PATH_BSHELL */
    memcpy(cp, pw_shell, ssize);
    newpw->pw_shell = cp;
    cp += ssize;

    /* Set key and datum. */
    if (name != NULL) {
	memcpy(cp, name, strlen(name) + 1);
	pwitem->cache.k.name = cp;
    } else {
	pwitem->cache.k.uid = pw->pw_uid;
    }
    pwitem->cache.d.pw = newpw;
    pwitem->cache.refcnt = 1;

    debug_return_ptr(&pwitem->cache);
}

/*
 * Dynamically allocate space for a struct item plus the key and data
 * elements.  If name is non-NULL it is used as the key, else the
 * gid is the key.  Fills in datum from struct group.
 * Returns NULL on calloc error or unknown name/id, setting errno
 * to ENOMEM or ENOENT respectively.
 */
struct cache_item *
sudo_make_gritem(gid_t gid, const char *name)
{
    char *cp;
    size_t nsize, psize, nmem, total, len;
    struct cache_item_gr *gritem;
    struct group *gr, *newgr;
    debug_decl(sudo_make_gritem, SUDOERS_DEBUG_NSS)

    /* Look up by name or gid. */
    gr = name ? getgrnam(name) : getgrgid(gid);
    if (gr == NULL) {
	errno = ENOENT;
	debug_return_ptr(NULL);
    }

    /* Allocate in one big chunk for easy freeing. */
    nsize = psize = nmem = 0;
    total = sizeof(*gritem);
    FIELD_SIZE(gr, gr_name, nsize);
    FIELD_SIZE(gr, gr_passwd, psize);
    if (gr->gr_mem) {
	for (nmem = 0; gr->gr_mem[nmem] != NULL; nmem++)
	    total += strlen(gr->gr_mem[nmem]) + 1;
	nmem++;
	total += sizeof(char *) * nmem;
    }
    if (name != NULL)
	total += strlen(name) + 1;

    if ((gritem = calloc(1, total)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_ptr(NULL);
    }

    /*
     * Copy in group contents and make strings relative to space
     * at the end of the buffer.  Note that gr_mem must come
     * immediately after struct group to guarantee proper alignment.
     */
    newgr = &gritem->gr;
    memcpy(newgr, gr, sizeof(*gr));
    cp = (char *)(gritem + 1);
    if (gr->gr_mem) {
	newgr->gr_mem = (char **)cp;
	cp += sizeof(char *) * nmem;
	for (nmem = 0; gr->gr_mem[nmem] != NULL; nmem++) {
	    len = strlen(gr->gr_mem[nmem]) + 1;
	    memcpy(cp, gr->gr_mem[nmem], len);
	    newgr->gr_mem[nmem] = cp;
	    cp += len;
	}
	newgr->gr_mem[nmem] = NULL;
    }
    FIELD_COPY(gr, newgr, gr_passwd, psize);
    FIELD_COPY(gr, newgr, gr_name, nsize);

    /* Set key and datum. */
    if (name != NULL) {
	memcpy(cp, name, strlen(name) + 1);
	gritem->cache.k.name = cp;
    } else {
	gritem->cache.k.gid = gr->gr_gid;
    }
    gritem->cache.d.gr = newgr;
    gritem->cache.refcnt = 1;

    debug_return_ptr(&gritem->cache);
}

/*
 * Dynamically allocate space for a struct item plus the key and data
 * elements.  Fills in datum from user_gids or from sudo_getgrouplist2(3).
 */
struct cache_item *
sudo_make_gidlist_item(const struct passwd *pw, char * const *unused1,
    unsigned int type)
{
    char *cp;
    size_t nsize, total;
    struct cache_item_gidlist *glitem;
    struct gid_list *gidlist;
    GETGROUPS_T *gids;
    int i, ngids;
    debug_decl(sudo_make_gidlist_item, SUDOERS_DEBUG_NSS)

    /* Don't use user_gids if the entry type says we must query the db. */
    if (type != ENTRY_TYPE_QUERIED && pw == sudo_user.pw && sudo_user.gids != NULL) {
	gids = user_gids;
	ngids = user_ngids;
	user_gids = NULL;
	user_ngids = 0;
	type = ENTRY_TYPE_FRONTEND;
    } else {
	type = ENTRY_TYPE_QUERIED;
	if (sudo_user.max_groups > 0) {
	    ngids = sudo_user.max_groups;
	    gids = reallocarray(NULL, ngids, sizeof(GETGROUPS_T));
	    if (gids == NULL) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "unable to allocate memory");
		debug_return_ptr(NULL);
	    }
	    (void)sudo_getgrouplist2(pw->pw_name, pw->pw_gid, &gids, &ngids);
	} else {
	    gids = NULL;
	    if (sudo_getgrouplist2(pw->pw_name, pw->pw_gid, &gids, &ngids) == -1) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "unable to allocate memory");
		debug_return_ptr(NULL);
	    }
	}
    }
    if (ngids <= 0) {
	free(gids);
	errno = ENOENT;
	debug_return_ptr(NULL);
    }

    /* Allocate in one big chunk for easy freeing. */
    nsize = strlen(pw->pw_name) + 1;
    total = sizeof(*glitem) + nsize;
    total += sizeof(gid_t *) * ngids;

    if ((glitem = calloc(1, total)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	free(gids);
	debug_return_ptr(NULL);
    }

    /*
     * Copy in group list and make pointers relative to space
     * at the end of the buffer.  Note that the groups array must come
     * immediately after struct group to guarantee proper alignment.
     */
    gidlist = &glitem->gidlist;
    cp = (char *)(glitem + 1);
    gidlist->gids = (gid_t *)cp;
    cp += sizeof(gid_t) * ngids;

    /* Set key and datum. */
    memcpy(cp, pw->pw_name, nsize);
    glitem->cache.k.name = cp;
    glitem->cache.d.gidlist = gidlist;
    glitem->cache.refcnt = 1;
    glitem->cache.type = type;

    /*
     * Store group IDs.
     */
    for (i = 0; i < ngids; i++)
	gidlist->gids[i] = gids[i];
    gidlist->ngids = ngids;
    free(gids);

    debug_return_ptr(&glitem->cache);
}

/*
 * Dynamically allocate space for a struct item plus the key and data
 * elements.  Fills in group names from a call to sudo_get_gidlist().
 */
struct cache_item *
sudo_make_grlist_item(const struct passwd *pw, char * const *unused1)
{
    char *cp;
    size_t nsize, ngroups, total, len;
    struct cache_item_grlist *grlitem;
    struct group_list *grlist;
    struct gid_list *gidlist;
    struct group *grp = NULL;
    int i, groupname_len;
    debug_decl(sudo_make_grlist_item, SUDOERS_DEBUG_NSS)

    gidlist = sudo_get_gidlist(pw, ENTRY_TYPE_ANY);
    if (gidlist == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "no gid list for use %s", pw->pw_name);
	errno = ENOENT;
	debug_return_ptr(NULL);
    }

#ifdef _SC_LOGIN_NAME_MAX
    groupname_len = MAX((int)sysconf(_SC_LOGIN_NAME_MAX), 32);
#else
    groupname_len = MAX(LOGIN_NAME_MAX, 32);
#endif

    /* Allocate in one big chunk for easy freeing. */
    nsize = strlen(pw->pw_name) + 1;
    total = sizeof(*grlitem) + nsize;
    total += sizeof(char *) * gidlist->ngids;
    total += groupname_len * gidlist->ngids;

again:
    if ((grlitem = calloc(1, total)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	sudo_gidlist_delref(gidlist);
	debug_return_ptr(NULL);
    }

    /*
     * Copy in group list and make pointers relative to space
     * at the end of the buffer.  Note that the groups array must come
     * immediately after struct group to guarantee proper alignment.
     */
    grlist = &grlitem->grlist;
    cp = (char *)(grlitem + 1);
    grlist->groups = (char **)cp;
    cp += sizeof(char *) * gidlist->ngids;

    /* Set key and datum. */
    memcpy(cp, pw->pw_name, nsize);
    grlitem->cache.k.name = cp;
    grlitem->cache.d.grlist = grlist;
    grlitem->cache.refcnt = 1;
    cp += nsize;

    /*
     * Resolve and store group names by ID.
     */
#ifdef HAVE_SETAUTHDB
    if (grp == NULL)
	aix_setauthdb((char *) pw->pw_name, NULL);
#endif
    ngroups = 0;
    for (i = 0; i < gidlist->ngids; i++) {
	if ((grp = sudo_getgrgid(gidlist->gids[i])) != NULL) {
	    len = strlen(grp->gr_name) + 1;
	    if (cp - (char *)grlitem + len > total) {
		total += len + groupname_len;
		free(grlitem);
		sudo_gr_delref(grp);
		goto again;
	    }
	    memcpy(cp, grp->gr_name, len);
	    grlist->groups[ngroups++] = cp;
	    cp += len;
	    sudo_gr_delref(grp);
	}
    }
    grlist->ngroups = ngroups;
    sudo_gidlist_delref(gidlist);

#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif

    debug_return_ptr(&grlitem->cache);
}
