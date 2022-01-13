/*
 * Copyright (c) 2005, 2008, 2010-2015
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
 */

/*
 * Trivial replacements for the libc get{gr,pw}{uid,nam}() routines
 * for use by testsudoers in the sudo test harness.
 * We need our own since many platforms don't provide set{pw,gr}file().
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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

#include "tsgetgrpw.h"
#include "sudoers.h"

#undef GRMEM_MAX
#define GRMEM_MAX 200

#ifndef UID_MAX
# define UID_MAX 0xffffffffU
#endif

#ifndef GID_MAX
# define GID_MAX UID_MAX
#endif

static FILE *pwf;
static const char *pwfile = "/etc/passwd";
static int pw_stayopen;

static FILE *grf;
static const char *grfile = "/etc/group";
static int gr_stayopen;

void setgrfile(const char *);
void setgrent(void);
void endgrent(void);
struct group *getgrent(void);
struct group *getgrnam(const char *);
struct group *getgrgid(gid_t);

void setpwfile(const char *);
void setpwent(void);
void endpwent(void);
struct passwd *getpwent(void);
struct passwd *getpwnam(const char *);
struct passwd *getpwuid(uid_t);

void
setpwfile(const char *file)
{
    pwfile = file;
    if (pwf != NULL)
	endpwent();
}

void
setpwent(void)
{
    if (pwf == NULL) {
	pwf = fopen(pwfile, "r");
	if (pwf != NULL)
	    (void)fcntl(fileno(pwf), F_SETFD, FD_CLOEXEC);
    } else {
	rewind(pwf);
    }
    pw_stayopen = 1;
}

void
endpwent(void)
{
    if (pwf != NULL) {
	fclose(pwf);
	pwf = NULL;
    }
    pw_stayopen = 0;
}

struct passwd *
getpwent(void)
{
    static struct passwd pw;
    static char pwbuf[LINE_MAX];
    size_t len;
    id_t id;
    char *cp, *colon;
    const char *errstr;

next_entry:
    if ((colon = fgets(pwbuf, sizeof(pwbuf), pwf)) == NULL)
	return NULL;

    memset(&pw, 0, sizeof(pw));
    if ((colon = strchr(cp = colon, ':')) == NULL)
	goto next_entry;
    *colon++ = '\0';
    pw.pw_name = cp;
    if ((colon = strchr(cp = colon, ':')) == NULL)
	goto next_entry;
    *colon++ = '\0';
    pw.pw_passwd = cp;
    if ((colon = strchr(cp = colon, ':')) == NULL)
	goto next_entry;
    *colon++ = '\0';
    id = sudo_strtoid(cp, NULL, NULL, &errstr);
    if (errstr != NULL)
	goto next_entry;
    pw.pw_uid = (uid_t)id;
    if ((colon = strchr(cp = colon, ':')) == NULL)
	goto next_entry;
    *colon++ = '\0';
    id = sudo_strtoid(cp, NULL, NULL, &errstr);
    if (errstr != NULL)
	goto next_entry;
    pw.pw_gid = (gid_t)id;
    if ((colon = strchr(cp = colon, ':')) == NULL)
	goto next_entry;
    *colon++ = '\0';
    pw.pw_gecos = cp;
    if ((colon = strchr(cp = colon, ':')) == NULL)
	goto next_entry;
    *colon++ = '\0';
    pw.pw_dir = cp;
    pw.pw_shell = colon;
    len = strlen(colon);
    if (len > 0 && colon[len - 1] == '\n')
	colon[len - 1] = '\0';
    return &pw;
}

struct passwd *
getpwnam(const char *name)
{
    struct passwd *pw;

    if (pwf == NULL) {
	if ((pwf = fopen(pwfile, "r")) == NULL)
	    return NULL;
	(void)fcntl(fileno(pwf), F_SETFD, FD_CLOEXEC);
    } else {
	rewind(pwf);
    }
    while ((pw = getpwent()) != NULL) {
	if (strcmp(pw->pw_name, name) == 0)
	    break;
    }
    if (!pw_stayopen) {
	fclose(pwf);
	pwf = NULL;
    }
    return pw;
}

struct passwd *
getpwuid(uid_t uid)
{
    struct passwd *pw;

    if (pwf == NULL) {
	if ((pwf = fopen(pwfile, "r")) == NULL)
	    return NULL;
	(void)fcntl(fileno(pwf), F_SETFD, FD_CLOEXEC);
    } else {
	rewind(pwf);
    }
    while ((pw = getpwent()) != NULL) {
	if (pw->pw_uid == uid)
	    break;
    }
    if (!pw_stayopen) {
	fclose(pwf);
	pwf = NULL;
    }
    return pw;
}

void
setgrfile(const char *file)
{
    grfile = file;
    if (grf != NULL)
	endgrent();
}

void
setgrent(void)
{
    if (grf == NULL) {
	grf = fopen(grfile, "r");
	if (grf != NULL)
	    (void)fcntl(fileno(grf), F_SETFD, FD_CLOEXEC);
    } else {
	rewind(grf);
    }
    gr_stayopen = 1;
}

void
endgrent(void)
{
    if (grf != NULL) {
	fclose(grf);
	grf = NULL;
    }
    gr_stayopen = 0;
}

struct group *
getgrent(void)
{
    static struct group gr;
    static char grbuf[LINE_MAX], *gr_mem[GRMEM_MAX+1];
    size_t len;
    id_t id;
    char *cp, *colon;
    const char *errstr;
    int n;

next_entry:
    if ((colon = fgets(grbuf, sizeof(grbuf), grf)) == NULL)
	return NULL;

    memset(&gr, 0, sizeof(gr));
    if ((colon = strchr(cp = colon, ':')) == NULL)
	goto next_entry;
    *colon++ = '\0';
    gr.gr_name = cp;
    if ((colon = strchr(cp = colon, ':')) == NULL)
	goto next_entry;
    *colon++ = '\0';
    gr.gr_passwd = cp;
    if ((colon = strchr(cp = colon, ':')) == NULL)
	goto next_entry;
    *colon++ = '\0';
    id = sudo_strtoid(cp, NULL, NULL, &errstr);
    if (errstr != NULL)
	goto next_entry;
    gr.gr_gid = (gid_t)id;
    len = strlen(colon);
    if (len > 0 && colon[len - 1] == '\n')
	colon[len - 1] = '\0';
    if (*colon != '\0') {
	char *last;

	gr.gr_mem = gr_mem;
	cp = strtok_r(colon, ",", &last);
	for (n = 0; cp != NULL && n < GRMEM_MAX; n++) {
	    gr.gr_mem[n] = cp;
	    cp = strtok_r(NULL, ",", &last);
	}
	gr.gr_mem[n++] = NULL;
    } else
	gr.gr_mem = NULL;
    return &gr;
}

struct group *
getgrnam(const char *name)
{
    struct group *gr;

    if (grf == NULL) {
	if ((grf = fopen(grfile, "r")) == NULL)
	    return NULL;
	(void)fcntl(fileno(grf), F_SETFD, FD_CLOEXEC);
    } else {
	rewind(grf);
    }
    while ((gr = getgrent()) != NULL) {
	if (strcmp(gr->gr_name, name) == 0)
	    break;
    }
    if (!gr_stayopen) {
	fclose(grf);
	grf = NULL;
    }
    return gr;
}

struct group *
getgrgid(gid_t gid)
{
    struct group *gr;

    if (grf == NULL) {
	if ((grf = fopen(grfile, "r")) == NULL)
	    return NULL;
	(void)fcntl(fileno(grf), F_SETFD, FD_CLOEXEC);
    } else {
	rewind(grf);
    }
    while ((gr = getgrent()) != NULL) {
	if (gr->gr_gid == gid)
	    break;
    }
    if (!gr_stayopen) {
	fclose(grf);
	grf = NULL;
    }
    return gr;
}
