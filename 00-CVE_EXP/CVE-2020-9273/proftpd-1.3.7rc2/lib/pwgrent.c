/* Copyright (C) 1991, 1992, 1993 Free Software Foundation, Inc.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with this library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 51 Franklin Street,
Suite 500, Boston, MA 02110-1335, USA.  */

/* Required to tell conf.h not to include the standard ProFTPD
 * header files
 */

#define __PROFTPD_SUPPORT_LIBRARY

#include <conf.h>
#include "libsupp.h"

/* From log.c/log.h */
#define PR_LOG_ERR LOG_ERR
extern void pr_log_pri(int, char *, ...);

/* From support.c */
extern int sstrncpy(char *dst, const char *src, size_t n);

#define NPWDFIELDS 	7
#define NGRPFIELDS 	4

#ifndef BUFSIZ
#define BUFSIZ		PR_TUNABLE_BUFFER_SIZE
#endif

/* Provides fgetpwent()/fgetgrent() functions.  Note that the format of the
 * files is probably NOT platform dependent, so use of these functions will
 * require a strict format:
 *
 *   "username:password:uid:gid:gecos:home:shell"
 */

#ifndef HAVE_FGETPWENT

static char pwdbuf[BUFSIZ];
static char *pwdfields[NPWDFIELDS];
static struct passwd pwent;

static struct passwd *supp_getpwent(const char *buf) {
  register unsigned int i;
  register char *cp;
  char *ep = NULL, *buffer = NULL;
  char **fields = NULL;
  struct passwd *pwd = NULL;

  fields = pwdfields;
  buffer = pwdbuf;
  pwd = &pwent;

  sstrncpy(buffer, buf, BUFSIZ-1);
  buffer[BUFSIZ-1] = '\0';

  for(cp = buffer, i = 0; i < NPWDFIELDS && cp; i++) {
    fields[i] = cp;
    while (*cp && *cp != ':')
      ++cp;

    if (*cp)
      *cp++ = '\0';
    else
      cp = 0;
  }

  if (i != NPWDFIELDS || *fields[2] == '\0' || *fields[3] == '\0')
    return 0;

  pwd->pw_name = fields[0];
  pwd->pw_passwd = fields[1];

  if (fields[2][0] == '\0' ||
     ((pwd->pw_uid = strtol(fields[2], &ep, 10)) == 0 && *ep))
       return 0;

  if (fields[3][0] == '\0' ||
     ((pwd->pw_gid = strtol(fields[3], &ep, 10)) == 0 && *ep))
       return 0;

  pwd->pw_gecos = fields[4];
  pwd->pw_dir = fields[5];
  pwd->pw_shell = fields[6];

  return pwd;
}

struct passwd *fgetpwent(FILE *fp) {
  char buf[BUFSIZ] = {'\0'};

  while (fgets(buf, sizeof(buf), fp) != (char*) 0) {

    /* ignore empty and comment lines */
    if (buf[0] == '\0' || buf[0] == '#')
      continue;

    buf[strlen(buf)-1] = '\0';
    return supp_getpwent(buf);
  }

  return NULL;
}
#endif /* HAVE_FGETPWENT */

#ifndef HAVE_FGETGRENT
#define MAXMEMBERS 4096

static char *grpbuf = NULL;
static struct group grent;
static char *grpfields[NGRPFIELDS];
static char *members[MAXMEMBERS+1];

static char *fgetbufline(char **buf, int *buflen, FILE *fp) {
  char *cp = *buf;

  while (fgets(cp, (*buflen) - (cp - *buf), fp) != NULL) {

    /* Is this a full line? */
    if (strchr(cp, '\n'))
      return *buf;

    /* No -- allocate a larger buffer, doubling buflen. */
    *buflen += *buflen;

    {
      char *new_buf;

      new_buf = realloc(*buf, *buflen);
      if (new_buf == NULL)
        break;

      *buf = new_buf;
    }

    cp = *buf + (cp - *buf);
    cp = strchr(cp, '\0');
  }

  free(*buf);
  *buf = NULL;
  *buflen = 0;

  return NULL;
}

static char **supp_grplist(char *s) {
  int nmembers = 0;

  while (s && *s && nmembers < MAXMEMBERS) {
    members[nmembers++] = s;
    while (*s && *s != ',')
      s++;

    if (*s)
      *s++ = '\0';
  }

  members[nmembers] = NULL;
  return members;
}

static struct group *supp_getgrent(const char *buf) {
  int i;
  char *cp;

  i = strlen(buf) + 1;

  if (!grpbuf) {
    grpbuf = malloc(i);

  } else {
    char *new_buf;

    new_buf = realloc(grpbuf, i);
    if (new_buf == NULL)
      return NULL;

    grpbuf = new_buf;
  }

  if (!grpbuf)
    return NULL;

  sstrncpy(grpbuf, buf, i);

  if ((cp = strrchr(grpbuf, '\n')))
    *cp = '\0';

  for (cp = grpbuf, i = 0; i < NGRPFIELDS && cp; i++) {
    grpfields[i] = cp;

    if ((cp = strchr(cp, ':')))
      *cp++ = 0;
  }

  if (i < (NGRPFIELDS - 1)) {
    pr_log_pri(PR_LOG_ERR, "Malformed entry in group file: %s", buf);
    return NULL;
  }

  if (*grpfields[2] == '\0')
    return NULL;

  grent.gr_name = grpfields[0];
  grent.gr_passwd = grpfields[1];
  grent.gr_gid = atoi(grpfields[2]);
  grent.gr_mem = supp_grplist(grpfields[3]);

  return &grent;
}

struct group *fgetgrent(FILE *fp) {
  char *cp = NULL, *buf = malloc(BUFSIZ);
  int buflen = BUFSIZ;
  struct group *grp = NULL;

  if (!buf)
    return NULL;

  while (fgetbufline(&buf, &buflen, fp) != NULL) {

    /* ignore comment and empty lines */
    if (buf[0] == '\0' || buf[0] == '#')
      continue;

    if ((cp = strchr(buf, '\n')) != NULL)
      *cp = '\0';

    grp = supp_getgrent(buf);
    free(buf);

    return grp;
  }

  return NULL;
}

#endif /* HAVE_FGETGRENT */
