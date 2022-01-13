/*
 * ProFTPD: mod_auth_file - file-based authentication module that supports
 *                          restrictions on the file contents
 * Copyright (c) 2002-2017 The ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, the ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

#include "conf.h"
#include "privs.h"

/* AIX has some rather stupid function prototype inconsistencies between
 * their crypt.h and stdlib.h's setkey() declarations.
 */
#if defined(HAVE_CRYPT_H) && !defined(AIX4) && !defined(AIX5)
# include <crypt.h>
#endif

#define MOD_AUTH_FILE_VERSION	"mod_auth_file/1.0"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001020702
# error "ProFTPD 1.2.7rc2 or later required"
#endif

#ifndef BUFSIZ
# define BUFSIZ          PR_TUNABLE_BUFFER_SIZE
#endif /* !BUFSIZ */

module auth_file_module;

typedef union {
  uid_t uid;
  gid_t gid;

} authfile_id_t;

typedef struct file_rec {
  char *af_path;
  FILE *af_file;
  unsigned int af_lineno;

  unsigned char af_restricted_ids;
  authfile_id_t af_min_id;
  authfile_id_t af_max_id;

#ifdef PR_USE_REGEX
  unsigned char af_restricted_names;
  char *af_name_filter;
  pr_regex_t *af_name_regex;
  unsigned char af_name_regex_inverted;

  /* These are AuthUserFile-specific */
  unsigned char af_restricted_homes;
  char *af_home_filter;
  pr_regex_t *af_home_regex;
  unsigned char af_home_regex_inverted;

#endif /* regex support */

} authfile_file_t;

/* List of server-specific AuthFiles */
static authfile_file_t *af_user_file = NULL;
static authfile_file_t *af_group_file = NULL;
static unsigned long auth_file_opts = 0UL;

/* Tell mod_auth_file to skip/ignore the permissions checks on the configured
 * AuthUserFile/AuthGroupFile.
 */
#define AUTH_FILE_OPT_INSECURE_PERMS		0x0001

static int handle_empty_salt = FALSE;

static int authfile_sess_init(void);

static int af_setpwent(pool *);
static int af_setgrent(pool *);

static const char *trace_channel = "auth.file";

/* Support routines.  Move the passwd/group functions out of lib/ into here. */

#define PR_AUTH_FILE_FL_ALLOW_WORLD_READABLE		0x001

static int af_check_parent_dir(pool *p, const char *name, const char *path) {
  struct stat st;
  int res;
  char *dir_path, *ptr = NULL;

  ptr = strrchr(path, '/');
  if (ptr != path) {
    dir_path = pstrndup(p, path, ptr - path);

  } else {
    dir_path = "/";
  }

  res = stat(dir_path, &st);
  if (res < 0) {
    int xerrno = errno;

    pr_log_debug(DEBUG0, MOD_AUTH_FILE_VERSION
      ": unable to stat %s directory '%s': %s", name, dir_path,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (st.st_mode & S_IWOTH) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG0, MOD_AUTH_FILE_VERSION
      ": unable to use %s from world-writable directory '%s' (perms %04o): %s",
      name, dir_path, st.st_mode & ~S_IFMT, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

static int af_check_file(pool *p, const char *name, const char *path,
    int flags) {
  struct stat st;
  int res;
  const char *orig_path;

  orig_path = path;

  res = lstat(path, &st);
  if (res < 0) {
    int xerrno = errno;

    pr_log_debug(DEBUG0, MOD_AUTH_FILE_VERSION ": unable to lstat %s '%s': %s",
      name, path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (S_ISLNK(st.st_mode)) {
    char buf[PR_TUNABLE_PATH_MAX+1];

    /* Check the permissions on the parent directory; if they're world-writable,
     * then this symlink can be deleted/pointed somewhere else.
     */
    res = af_check_parent_dir(p, name, path);
    if (res < 0) {
      return -1;
    }

    /* Follow the link to the target path; that path will then have its
     * parent directory checked.
     */
    memset(buf, '\0', sizeof(buf));
    res = pr_fsio_readlink(path, buf, sizeof(buf)-1);
    if (res > 0) {

      /* The path contained in the symlink might itself be relative, thus
       * we need to make sure that we get an absolute path (Bug#4145).
       */
      path = dir_abs_path(p, buf, FALSE);
      if (path != NULL) {
        orig_path = path;
      }
    }

    res = stat(orig_path, &st);
    if (res < 0) {
      int xerrno = errno;

      pr_log_debug(DEBUG0, MOD_AUTH_FILE_VERSION ": unable to stat %s '%s': %s",
        name, orig_path, strerror(xerrno));

      errno = xerrno;
      return -1;
    }
  }

  if (S_ISDIR(st.st_mode)) {
    int xerrno = EISDIR;

    pr_log_debug(DEBUG0, MOD_AUTH_FILE_VERSION ": unable to use %s '%s': %s",
      name, orig_path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* World-readable files MAY be insecure, and are thus not usable/trusted. */
  if ((st.st_mode & S_IROTH) &&
       !(flags & PR_AUTH_FILE_FL_ALLOW_WORLD_READABLE)) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG0, MOD_AUTH_FILE_VERSION
      ": unable to use world-readable %s '%s' (perms %04o): %s",
      name, orig_path, st.st_mode & ~S_IFMT, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* World-writable files are insecure, and are thus not usable/trusted. */
  if (st.st_mode & S_IWOTH) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG0, MOD_AUTH_FILE_VERSION
      ": unable to use world-writable %s '%s' (perms %04o): %s",
      name, orig_path, st.st_mode & ~S_IFMT, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (!S_ISREG(st.st_mode)) {
    pr_log_pri(PR_LOG_WARNING, MOD_AUTH_FILE_VERSION
      ": %s '%s' is not a regular file", name, orig_path);
  }

  /* Check the parent directory of this file.  If the parent directory
   * is world-writable, that too is insecure.
   */
  res = af_check_parent_dir(p, name, orig_path);
  if (res < 0) {
    return -1;
  }

  return 0;
}

#ifndef HAVE_FGETPWENT

#define NPWDFIELDS      7

static char pwdbuf[BUFSIZ];
static char *pwdfields[NPWDFIELDS];
static struct passwd pwent;

static struct passwd *af_getpasswd(const char *buf, unsigned int lineno) {
  register unsigned int i;
  register char *cp = NULL;
  char *ep = NULL, *buffer = NULL;
  char **fields = NULL;
  struct passwd *pwd = NULL;

  fields = pwdfields;
  buffer = pwdbuf;
  pwd = &pwent;

  sstrncpy(buffer, buf, BUFSIZ-1);
  buffer[BUFSIZ-1] = '\0';

  for (cp = buffer, i = 0; i < NPWDFIELDS && cp; i++) {
    fields[i] = cp;
    while (*cp && *cp != ':') {
      ++cp;
    }

    if (*cp) {
      *cp++ = '\0';

    } else {
      cp = 0;
    }
  }

  if (i != NPWDFIELDS) {
    pr_log_pri(PR_LOG_ERR, "Malformed entry in AuthUserFile file (line %u)",
      lineno);
    return NULL;
  }

  if (*fields[2] == '\0' ||
      *fields[3] == '\0') {
    return NULL;
  }

  pwd->pw_name = fields[0];
  pwd->pw_passwd = fields[1];

  if (fields[2][0] == '\0' ||
     ((pwd->pw_uid = strtol(fields[2], &ep, 10)) == 0 && *ep)) {
       return NULL;
  }

  if (fields[3][0] == '\0' ||
     ((pwd->pw_gid = strtol(fields[3], &ep, 10)) == 0 && *ep)) {
       return NULL;
  }

  pwd->pw_gecos = fields[4];
  pwd->pw_dir = fields[5];
  pwd->pw_shell = fields[6];

  return pwd;
}
#endif /* !HAVE_FGETPWENT */

#ifndef HAVE_FGETGRENT

#define MAXMEMBERS	4096
#define NGRPFIELDS      4

static char *grpbuf = NULL;
static struct group grent;
static char *grpfields[NGRPFIELDS];
static char *members[MAXMEMBERS+1];

static char *af_getgrentline(char **buf, int *buflen, FILE *fp,
    unsigned int *lineno) {
  char *cp = *buf;

  while (fgets(cp, (*buflen) - (cp - *buf), fp) != NULL) {
    pr_signals_handle();

    (*lineno)++;

    /* Is this a full line? */
    if (strchr(cp, '\n')) {
      return *buf;
    }

    /* No -- allocate a larger buffer, doubling buflen. */
    *buflen += *buflen;

    {
      char *new_buf;

      new_buf = realloc(*buf, *buflen);
      if (new_buf == NULL) {
        break;
      }

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

static char **af_getgrmems(char *s) {
  int nmembers = 0;

  while (s && *s && nmembers < MAXMEMBERS) {
    pr_signals_handle();

    members[nmembers++] = s;
    while (*s && *s != ',') {
      s++;
    }

    if (*s) {
      *s++ = '\0';
    }
  }

  members[nmembers] = NULL;
  return members;
}

static struct group *af_getgrp(const char *buf, unsigned int lineno) {
  int i;
  char *cp;

  i = strlen(buf) + 1;

  if (!grpbuf) {
    grpbuf = malloc(i);

  } else {
    char *new_buf;

    new_buf = realloc(grpbuf, i);
    if (new_buf == NULL) {
      return NULL;
    }

    grpbuf = new_buf;
  }

  if (!grpbuf)
    return NULL;

  sstrncpy(grpbuf, buf, i);

  cp = strrchr(grpbuf, '\n');
  if (cp) {
    *cp = '\0';
  }

  for (cp = grpbuf, i = 0; i < NGRPFIELDS && cp; i++) {
    grpfields[i] = cp;

    cp = strchr(cp, ':');
    if (cp) {
      *cp++ = 0;
    }
  }

  if (i < (NGRPFIELDS - 1)) {
    pr_log_pri(PR_LOG_ERR, "Malformed entry in AuthGroupFile file (line %u)",
      lineno);
    return NULL;
  }

  if (*grpfields[2] == '\0') {
    return NULL;
  }

  grent.gr_name = grpfields[0];
  grent.gr_passwd = grpfields[1];
  grent.gr_gid = atoi(grpfields[2]);
  grent.gr_mem = af_getgrmems(grpfields[3]);

  return &grent;
}
#endif /* !HAVE_FGETGRENT */

static int af_allow_grent(pool *p, struct group *grp) {
  if (af_group_file == NULL) {
    errno = EPERM;
    return -1;
  }

  /* Check that the grent is within the ID restrictions (if present). */
  if (af_group_file->af_restricted_ids) {

    if (grp->gr_gid < af_group_file->af_min_id.gid) {
      pr_log_debug(DEBUG3, MOD_AUTH_FILE_VERSION ": skipping group '%s': "
        "GID %s below the minimum allowed (%s)", grp->gr_name,
        pr_gid2str(p, grp->gr_gid),
        pr_gid2str(p, af_group_file->af_min_id.gid));
      errno = EINVAL;
      return -1;
    }

    if (grp->gr_gid > af_group_file->af_max_id.gid) {
      pr_log_debug(DEBUG3, MOD_AUTH_FILE_VERSION ": skipping group '%s': "
        "GID %s above the maximum allowed (%s)", grp->gr_name,
        pr_gid2str(p, grp->gr_gid),
        pr_gid2str(p, af_group_file->af_max_id.gid));
      errno = EINVAL;
      return -1;
    }
  }

#ifdef PR_USE_REGEX
  /* Check if the grent has an acceptable name. */
  if (af_group_file->af_restricted_names) {
    int res;

    res = pr_regexp_exec(af_group_file->af_name_regex, grp->gr_name, 0,
      NULL, 0, 0, 0);

    if ((res != 0 && !af_group_file->af_name_regex_inverted) ||
        (res == 0 && af_group_file->af_name_regex_inverted)) {
      pr_log_debug(DEBUG3, MOD_AUTH_FILE_VERSION ": skipping group '%s': "
        "name '%s' does not meet allowed filter '%s'", grp->gr_name,
        grp->gr_name, af_group_file->af_name_filter);
      errno = EINVAL;
      return -1;
    }
  }
#endif /* regex support */

  return 0;
}

static void af_endgrent(void) {
  if (af_group_file &&
      af_group_file->af_file) {
    fclose(af_group_file->af_file);
    af_group_file->af_file = NULL;
    af_group_file->af_lineno = 0;
  }

  return;
}

static struct group *af_getgrent(pool *p) {
  struct group *grp = NULL, *res = NULL;

  if (!af_group_file ||
      !af_group_file->af_file) {
    errno = EINVAL;
    return NULL;
  }

  while (TRUE) {
#ifdef HAVE_FGETGRENT
    pr_signals_handle();
    grp = fgetgrent(af_group_file->af_file);
#else
    char *cp = NULL, *buf = NULL;
    int buflen = BUFSIZ;

    pr_signals_handle();

    buf = malloc(BUFSIZ);
    if (buf == NULL) {
      pr_log_pri(PR_LOG_ALERT, "Out of memory!");
      _exit(1);
    }
    grp = NULL;

    while (af_getgrentline(&buf, &buflen, af_group_file->af_file,
        &(af_group_file->af_lineno)) != NULL) {

      pr_signals_handle();

      /* Ignore comment and empty lines */
      if (buf[0] == '\0' ||
          buf[0] == '#') {
        continue;
      }

      cp = strchr(buf, '\n');
      if (cp != NULL) {
        *cp = '\0';
      }

      grp = af_getgrp(buf, af_group_file->af_lineno);
      free(buf);

      break;
    }
#endif /* !HAVE_FGETGRENT */

    /* If grp is NULL now, the file is empty - nothing more to be read. */
    if (grp == NULL) {
      break;
    }

    if (af_allow_grent(p, grp) < 0) {
      continue;
    }

    res = grp;
    break;
  }

  return res;
}

static struct group *af_getgrnam(pool *p, const char *name) {
  struct group *grp = NULL;

  if (af_setgrent(p) < 0) {
    return NULL;
  }

  while ((grp = af_getgrent(p)) != NULL) {
    pr_signals_handle();

    if (strcmp(name, grp->gr_name) == 0) {
      /* Found the requested group */
      break;
    }
  }

  return grp;
}

static struct group *af_getgrgid(pool *p, gid_t gid) {
  struct group *grp = NULL;

  if (af_setgrent(p) < 0) {
    return NULL;
  }

  while ((grp = af_getgrent(p)) != NULL) {
    pr_signals_handle();

    if (grp->gr_gid == gid) {
      /* Found the requested GID */
      break;
    }
  }

  return grp;
}

static int af_setgrent(pool *p) {

  if (af_group_file != NULL) {
    if (af_group_file->af_file != NULL) {
      /* If already opened, rewind */
      rewind(af_group_file->af_file);
      return 0;

    } else {
      int xerrno;

      PRIVS_ROOT
      af_group_file->af_file = fopen(af_group_file->af_path, "r");
      xerrno = errno;
      PRIVS_RELINQUISH

      if (af_group_file->af_file == NULL) {
        struct stat st;

        if (pr_fsio_stat(af_group_file->af_path, &st) == 0) {
          pr_log_pri(PR_LOG_WARNING,
            "error: unable to open AuthGroupFile file '%s' (file owned by "
            "UID %s, GID %s, perms %04o, accessed by UID %s, GID %s): %s",
            af_group_file->af_path, pr_uid2str(p, st.st_uid),
            pr_gid2str(p, st.st_gid), st.st_mode & ~S_IFMT,
            pr_uid2str(p, geteuid()), pr_gid2str(p, getegid()),
            strerror(xerrno));

        } else {
          pr_log_pri(PR_LOG_WARNING,
            "error: unable to open AuthGroupFile file '%s': %s",
            af_group_file->af_path, strerror(xerrno));
        }

        errno = xerrno;
        return -1;
      }

      /* As the file may contain sensitive data, we do not want it lingering
       * around in stdio buffers.
       */
      (void) setvbuf(af_group_file->af_file, NULL, _IONBF, 0);

      if (fcntl(fileno(af_group_file->af_file), F_SETFD, FD_CLOEXEC) < 0) {
        pr_log_pri(PR_LOG_WARNING, MOD_AUTH_FILE_VERSION
          ": unable to set CLOEXEC on AuthGroupFile %s (fd %d): %s",
          af_group_file->af_path, fileno(af_group_file->af_file),
          strerror(errno));
      }

      pr_log_debug(DEBUG7, MOD_AUTH_FILE_VERSION ": using group file '%s'",
        af_group_file->af_path);
      return 0;
    }
  }

  pr_trace_msg(trace_channel, 8, "no AuthGroupFile configured");
  errno = EPERM;
  return -1;
}

static int af_allow_pwent(pool *p, struct passwd *pwd) {
  if (af_user_file == NULL) {
    errno = EPERM;
    return -1;
  }

  /* Check that the pwent is within the ID restrictions (if present). */
  if (af_user_file->af_restricted_ids) {

    if (pwd->pw_uid < af_user_file->af_min_id.uid) {
      pr_log_debug(DEBUG3, MOD_AUTH_FILE_VERSION ": skipping user '%s': "
        "UID %s below the minimum allowed (%s)", pwd->pw_name,
        pr_uid2str(p, pwd->pw_uid),
        pr_uid2str(p, af_user_file->af_min_id.uid));
      errno = EINVAL;
      return -1;
    }

    if (pwd->pw_uid > af_user_file->af_max_id.gid) {
      pr_log_debug(DEBUG3, MOD_AUTH_FILE_VERSION ": skipping user '%s': "
        "UID %s above the maximum allowed (%s)", pwd->pw_name,
        pr_uid2str(p, pwd->pw_uid),
        pr_uid2str(p, af_user_file->af_max_id.uid));
      errno = EINVAL;
      return -1;
    }
  }

#ifdef PR_USE_REGEX
  /* Check if the pwent has an acceptable name. */
  if (af_user_file->af_restricted_names) {
    int res;

    res = pr_regexp_exec(af_user_file->af_name_regex, pwd->pw_name, 0, NULL,
      0, 0, 0);

    if ((res != 0 && !af_user_file->af_name_regex_inverted) ||
        (res == 0 && af_user_file->af_name_regex_inverted)) {
      pr_log_debug(DEBUG3, MOD_AUTH_FILE_VERSION ": skipping user '%s': "
        "name '%s' does not meet allowed filter '%s'", pwd->pw_name,
        pwd->pw_name, af_user_file->af_name_filter);
      errno = EINVAL;
      return -1;
    }
  }

  /* Check if the pwent has an acceptable home directory. */
  if (af_user_file->af_restricted_homes) {
    int res;

    res = pr_regexp_exec(af_user_file->af_home_regex, pwd->pw_dir, 0, NULL,
      0, 0, 0);

    if ((res != 0 && !af_user_file->af_home_regex_inverted) ||
        (res == 0 && af_user_file->af_home_regex_inverted)) {
      pr_log_debug(DEBUG3, MOD_AUTH_FILE_VERSION ": skipping user '%s': "
        "home '%s' does not meet allowed filter '%s'", pwd->pw_name,
        pwd->pw_dir, af_user_file->af_home_filter);
      errno = EINVAL;
      return -1;
    }
  }
#endif /* regex support */

  return 0;
}

static void af_endpwent(void) {
  if (af_user_file &&
      af_user_file->af_file) {
    fclose(af_user_file->af_file);
    af_user_file->af_file = NULL;
    af_user_file->af_lineno = 0;
  }

  return;
}

static struct passwd *af_getpwent(pool *p) {
  struct passwd *pwd = NULL, *res = NULL;

  if (af_user_file == NULL ||
      af_user_file->af_file == NULL) {
    errno = EINVAL;
    return NULL;
  }

  while (TRUE) {
#ifdef HAVE_FGETPWENT
    pr_signals_handle();
    pwd = fgetpwent(af_user_file->af_file);
#else
    char buf[BUFSIZ+1] = {'\0'};

    pr_signals_handle();

    memset(buf, '\0', sizeof(buf));
    pwd = NULL;

    while (fgets(buf, sizeof(buf)-1, af_user_file->af_file) != NULL) {
      pr_signals_handle();

      af_user_file->af_lineno++;

      /* Ignore empty and comment lines */
      if (buf[0] == '\0' ||
          buf[0] == '#') {
        memset(buf, '\0', sizeof(buf));
        continue;
      }

      buf[strlen(buf)-1] = '\0';
      pwd = af_getpasswd(buf, af_user_file->af_lineno);
      break;
    }
#endif /* !HAVE_FGETPWENT */

    /* If pwd is NULL now, the file is empty - nothing more to be read. */
    if (pwd == NULL) {
      break;
    }

    if (af_allow_pwent(p, pwd) < 0) {
#ifndef HAVE_FGETPWENT
      memset(buf, '\0', sizeof(buf));
#endif
      continue;
    }

    res = pwd;
    break;
  }

  return res;
}

static struct passwd *af_getpwnam(pool *p, const char *name) {
  struct passwd *pwd = NULL;

  if (af_setpwent(p) < 0) {
    return NULL;
  }

  while ((pwd = af_getpwent(p)) != NULL) {
    pr_signals_handle();

    if (strcmp(name, pwd->pw_name) == 0) {
      /* Found the requested user */
      break;
    }
  }

  return pwd;
}

static char *af_getpwpass(pool *p, const char *name) {
  struct passwd *pwd = af_getpwnam(p, name);
  return pwd ? pwd->pw_passwd : NULL;
}

static struct passwd *af_getpwuid(pool *p, uid_t uid) {
  struct passwd *pwd = NULL;

  if (af_setpwent(p) < 0) {
    return NULL;
  }

  while ((pwd = af_getpwent(p)) != NULL) {
    pr_signals_handle();

    if (pwd->pw_uid == uid) {
      /* Found the requested UID */
      break;
    }
  }

  return pwd;
}

static int af_setpwent(pool *p) {

  if (af_user_file != NULL) {
    if (af_user_file->af_file != NULL) {
      /* If already opened, rewind */
      rewind(af_user_file->af_file);
      return 0;

    } else {
      int xerrno;

      PRIVS_ROOT
      af_user_file->af_file = fopen(af_user_file->af_path, "r");
      xerrno = errno;
      PRIVS_RELINQUISH

      if (af_user_file->af_file == NULL) {
        struct stat st;

        if (pr_fsio_stat(af_user_file->af_path, &st) == 0) {
          pr_log_pri(PR_LOG_WARNING,
            "error: unable to open AuthUserFile file '%s' (file owned by "
            "UID %s, GID %s, perms %04o, accessed by UID %s, GID %s): %s",
            af_user_file->af_path, pr_uid2str(p, st.st_uid),
            pr_gid2str(p, st.st_gid), st.st_mode & ~S_IFMT,
            pr_uid2str(p, geteuid()), pr_gid2str(p, getegid()),
            strerror(xerrno));

        } else {
          pr_log_pri(PR_LOG_WARNING,
            "error: unable to open AuthUserFile file '%s': %s",
            af_user_file->af_path, strerror(xerrno));
        }

        errno = xerrno;
        return -1;
      }

      /* As the file may contain sensitive data, we do not want it lingering
       * around in stdio buffers.
       */
      (void) setvbuf(af_user_file->af_file, NULL, _IONBF, 0);

      if (fcntl(fileno(af_user_file->af_file), F_SETFD, FD_CLOEXEC) < 0) {
        pr_log_pri(PR_LOG_WARNING, MOD_AUTH_FILE_VERSION
          ": unable to set CLOEXEC on AuthUserFile %s (fd %d): %s",
          af_user_file->af_path, fileno(af_user_file->af_file),
          strerror(errno));
      }

      pr_log_debug(DEBUG7, MOD_AUTH_FILE_VERSION ": using passwd file '%s'",
        af_user_file->af_path);
      return 0;
    }
  }

  pr_trace_msg(trace_channel, 8, "no AuthUserFile configured");
  errno = EPERM;
  return -1;
}

/* Authentication handlers.
 */

MODRET authfile_endpwent(cmd_rec *cmd) {
  af_endpwent();
  return PR_DECLINED(cmd);
}

MODRET authfile_getpwent(cmd_rec *cmd) {
  struct passwd *pwd = NULL;

  pwd = af_getpwent(cmd->tmp_pool);

  return pwd ? mod_create_data(cmd, pwd) : PR_DECLINED(cmd);
}

MODRET authfile_getpwnam(cmd_rec *cmd) {
  struct passwd *pwd = NULL;
  const char *name = cmd->argv[0];

  if (af_setpwent(cmd->tmp_pool) < 0) {
    return PR_DECLINED(cmd);
  }

  /* Ugly -- we iterate through the file.  Time-consuming. */
  while ((pwd = af_getpwent(cmd->tmp_pool)) != NULL) {
    pr_signals_handle();

    if (strcmp(name, pwd->pw_name) == 0) {
      /* Found the requested name */
      break;
    }
  }

  return pwd ? mod_create_data(cmd, pwd) : PR_DECLINED(cmd);
}

MODRET authfile_getpwuid(cmd_rec *cmd) {
  struct passwd *pwd = NULL;
  uid_t uid = *((uid_t *) cmd->argv[0]);

  if (af_setpwent(cmd->tmp_pool) < 0) {
    return PR_DECLINED(cmd);
  }

  pwd = af_getpwuid(cmd->tmp_pool, uid);

  return pwd ? mod_create_data(cmd, pwd) : PR_DECLINED(cmd);
}

MODRET authfile_name2uid(cmd_rec *cmd) {
  struct passwd *pwd = NULL;

  if (af_setpwent(cmd->tmp_pool) < 0) {
    return PR_DECLINED(cmd);
  }

  pwd = af_getpwnam(cmd->tmp_pool, cmd->argv[0]);

  return pwd ? mod_create_data(cmd, (void *) &pwd->pw_uid) : PR_DECLINED(cmd);
}

MODRET authfile_setpwent(cmd_rec *cmd) {
  if (af_setpwent(cmd->tmp_pool) == 0) {
    return PR_DECLINED(cmd);
  }

  return PR_DECLINED(cmd);
}

MODRET authfile_uid2name(cmd_rec *cmd) {
  struct passwd *pwd = NULL;

  if (af_setpwent(cmd->tmp_pool) < 0) {
    return PR_DECLINED(cmd);
  }

  pwd = af_getpwuid(cmd->tmp_pool, *((uid_t *) cmd->argv[0]));

  return pwd ? mod_create_data(cmd, pwd->pw_name) : PR_DECLINED(cmd);
}

MODRET authfile_endgrent(cmd_rec *cmd) {
  af_endgrent();
  return PR_DECLINED(cmd);
}

MODRET authfile_getgrent(cmd_rec *cmd) {
  struct group *grp = NULL;

  grp = af_getgrent(cmd->tmp_pool);

  return grp ? mod_create_data(cmd, grp) : PR_DECLINED(cmd);
}

MODRET authfile_getgrgid(cmd_rec *cmd) {
  struct group *grp = NULL;
  gid_t gid = *((gid_t *) cmd->argv[0]);

  if (af_setgrent(cmd->tmp_pool) < 0) {
    return PR_DECLINED(cmd);
  }

  grp = af_getgrgid(cmd->tmp_pool, gid);

  return grp ? mod_create_data(cmd, grp) : PR_DECLINED(cmd);
}

MODRET authfile_getgrnam(cmd_rec *cmd) {
  struct group *grp = NULL;
  const char *name = cmd->argv[0];

  if (af_setgrent(cmd->tmp_pool) < 0) {
    return PR_DECLINED(cmd);
  }

  while ((grp = af_getgrent(cmd->tmp_pool)) != NULL) {
    pr_signals_handle();

    if (strcmp(name, grp->gr_name) == 0) {
      /* Found the name requested */
      break;
    }
  }

  return grp ? mod_create_data(cmd, grp) : PR_DECLINED(cmd);
}

MODRET authfile_getgroups(cmd_rec *cmd) {
  struct passwd *pwd = NULL;
  struct group *grp = NULL;
  array_header *gids = NULL, *groups = NULL;
  char *name = cmd->argv[0];

  if (name == NULL) {
    return PR_DECLINED(cmd);
  }

  if (af_setpwent(cmd->tmp_pool) < 0) {
    return PR_DECLINED(cmd);
  }

  if (af_setgrent(cmd->tmp_pool) < 0) {
    return PR_DECLINED(cmd);
  }

  /* Check for NULLs */
  if (cmd->argv[1]) {
    gids = (array_header *) cmd->argv[1];
  }

  if (cmd->argv[2]) {
    groups = (array_header *) cmd->argv[2];
  }

  /* Retrieve the necessary info. */
  pwd = af_getpwnam(cmd->tmp_pool, name);
  if (pwd == NULL) {
    return PR_DECLINED(cmd);
  }

  /* Populate the first group ID and name. */
  if (gids) {
    *((gid_t *) push_array(gids)) = pwd->pw_gid;
  }

  if (groups &&
      (grp = af_getgrgid(cmd->tmp_pool, pwd->pw_gid)) != NULL) {
    *((char **) push_array(groups)) = pstrdup(session.pool, grp->gr_name);
  }

  (void) af_setgrent(cmd->tmp_pool);

  /* This is where things get slow, expensive, and ugly.  Loop through
   * everything, checking to make sure we haven't already added it.
   */
  while ((grp = af_getgrent(cmd->tmp_pool)) != NULL &&
      grp->gr_mem) {
    char **gr_mems = NULL;

    pr_signals_handle();

    /* Loop through each member name listed */
    for (gr_mems = grp->gr_mem; *gr_mems; gr_mems++) {

      /* If it matches the given username... */
      if (strcmp(*gr_mems, pwd->pw_name) == 0) {

        /* ...add the GID and name */
        if (gids) {
          *((gid_t *) push_array(gids)) = grp->gr_gid;
        }

        if (groups) {
          *((char **) push_array(groups)) = pstrdup(session.pool, grp->gr_name);
        }
      }
    }
  }

  if (gids && gids->nelts > 0) {
    return mod_create_data(cmd, (void *) &gids->nelts);

  } else if (groups && groups->nelts > 0) {
    return mod_create_data(cmd, (void *) &groups->nelts);
  }

  return PR_DECLINED(cmd);
}

MODRET authfile_gid2name(cmd_rec *cmd) {
  struct group *grp = NULL;

  if (af_setgrent(cmd->tmp_pool) < 0) {
    return PR_DECLINED(cmd);
  }

  grp = af_getgrgid(cmd->tmp_pool, *((gid_t *) cmd->argv[0]));

  return grp ? mod_create_data(cmd, grp->gr_name) : PR_DECLINED(cmd);
}

MODRET authfile_name2gid(cmd_rec *cmd) {
  struct group *grp = NULL;

  if (af_setgrent(cmd->tmp_pool) < 0) {
    return PR_DECLINED(cmd);
  }

  grp = af_getgrnam(cmd->tmp_pool, cmd->argv[0]);

  return grp ? mod_create_data(cmd, (void *) &grp->gr_gid) : PR_DECLINED(cmd);
}

MODRET authfile_setgrent(cmd_rec *cmd) {
  if (af_setgrent(cmd->tmp_pool) == 0) {
    return PR_DECLINED(cmd);
  }

  return PR_DECLINED(cmd);
}

MODRET authfile_auth(cmd_rec *cmd) {
  char *tmp = NULL, *cleartxt_pass = NULL;
  const char *name = cmd->argv[0];

  if (af_setpwent(cmd->tmp_pool) < 0) {
    return PR_DECLINED(cmd);
  }

  /* Lookup the cleartxt password for this user. */
  tmp = af_getpwpass(cmd->tmp_pool, name);
  if (tmp == NULL) {

    /* For now, return DECLINED.  Ideally, we could stash an auth module
     * identifier in the session structure, so that all auth modules could
     * coordinate/use their methods as long as they matched the auth module
     * used.
     */
    return PR_DECLINED(cmd);

#if 0
    /* When the above is implemented, and if the user being checked was
     * provided by mod_auth_file, we'd return this.
     */
    return PR_ERROR_INT(cmd, PR_AUTH_NOPWD);
#endif
  }

  cleartxt_pass = pstrdup(cmd->tmp_pool, tmp);

  if (pr_auth_check(cmd->tmp_pool, cleartxt_pass, name, cmd->argv[1])) {
    return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
  }

  session.auth_mech = "mod_auth_file.c";
  return PR_HANDLED(cmd);
}

/* Per Bug#4171, if we see EINVAL (or EPERM, as documented in same man pages),
 * check the /proc/sys/crypto/fips_enabled setting and the salt string, to see
 * if an unsupported algorithm in FIPS mode, e.g. DES or MD5, was used to
 * generate this salt string.
 *
 * There's not much we can do at this point other than log a message for the
 * admin that this is the case, and let them know how to fix things (if they
 * can).  Ultimately this breakage comes from those kind folks distributing
 * glibc.  Sigh.
 */
static void check_unsupported_algo(const char *user,
    const char *ciphertxt_pass, size_t ciphertxt_passlen) {
  FILE *fp = NULL;
  char fips_enabled[256];
  size_t len = 0, sz = 0;

  /* First, read in /proc/sys/crypto/fips_enabled. */
  fp = fopen("/proc/sys/crypto/fips_enabled", "r");
  if (fp == NULL) {
    pr_trace_msg(trace_channel, 4,
      "unable to open /proc/sys/crypto/fips_enabled: %s", strerror(errno));
    return;
  }

  memset(fips_enabled, '\0', sizeof(fips_enabled));
  sz = sizeof(fips_enabled)-1;
  len = fread(fips_enabled, 1, sz, fp);
  if (len == 0) {
    if (feof(fp)) {
      /* An empty /proc/sys/crypto/fips_enabled?  Weird. */
      pr_trace_msg(trace_channel, 4,
        "/proc/sys/crypto/fips_enabled is unexpectedly empty!");

    } else if (ferror(fp)) {
      pr_trace_msg(trace_channel, 4,
        "error reading /proc/sys/crypto/fips_enabled: %s", strerror(errno));
    }

    fclose(fp);
    return;
  }

  fclose(fp);

  /* Trim any newline. */
  if (fips_enabled[len-1] == '\n') {
    fips_enabled[len-1] = '\0';
  }

  if (strcmp(fips_enabled, "0") != 0) {
    /* FIPS mode enabled on this system.  If our salt string doesn't start
     * with a '$', it uses DES; if it starts with '$1$', it uses MD5.  Either
     * way, on a FIPS-enabled system, those algorithms aren't supported.
     */
    if (ciphertxt_pass[0] != '$') {
      /* DES */
      pr_log_pri(PR_LOG_ERR, MOD_AUTH_FILE_VERSION
        ": AuthUserFile entry for user '%s' uses DES, which is not supported "
        "on a FIPS-enabled system (see /proc/sys/crypto/fips_enabled)", user);
      pr_log_pri(PR_LOG_ERR, MOD_AUTH_FILE_VERSION
        ": recommend updating user '%s' entry to use SHA256/SHA512 "
        "(using ftpasswd --sha256/--sha512)", user);

    } else if (ciphertxt_passlen >= 3 &&
               strncmp(ciphertxt_pass, "$1$", 3) == 0) {
      /* MD5 */
      pr_log_pri(PR_LOG_ERR, MOD_AUTH_FILE_VERSION
        ": AuthUserFile entry for user '%s' uses MD5, which is not supported "
        "on a FIPS-enabled system (see /proc/sys/crypto/fips_enabled)", user);
      pr_log_pri(PR_LOG_ERR, MOD_AUTH_FILE_VERSION
        ": recommend updating user '%s' entry to use SHA256/SHA512 "
        "(using ftpasswd --sha256/--sha512)", user);

    } else {
      pr_log_debug(DEBUG0, MOD_AUTH_FILE_VERSION
        ": possible illegal salt characters in AuthUserFile entry "
        "for user '%s'?", user);
    }

  } else {
    /* The only other time crypt(3) would return EINVAL/EPERM, on a system
     * with procfs, is if the salt characters were illegal.  Right?
     */
    pr_log_debug(DEBUG0, MOD_AUTH_FILE_VERSION
      ": possible illegal salt characters in AuthUserFile entry for "
      "user '%s'?", user);
  }
}

MODRET authfile_chkpass(cmd_rec *cmd) {
  const char *ciphertxt_pass = cmd->argv[0];
  const char *cleartxt_pass = cmd->argv[2];
  char *crypted_pass = NULL;
  size_t ciphertxt_passlen = 0;
  int xerrno;

  if (ciphertxt_pass == NULL) {
    pr_log_debug(DEBUG2, MOD_AUTH_FILE_VERSION
      ": missing ciphertext password for comparison");
    return PR_DECLINED(cmd);
  }

  if (cleartxt_pass == NULL) {
    pr_log_debug(DEBUG2, MOD_AUTH_FILE_VERSION
      ": missing client-provided password for comparison");
    return PR_DECLINED(cmd);
  }

  /* Even though the AuthUserFile is not used here, there must be one
   * configured before this function should attempt to check the password.
   * Otherwise, it could be checking a password retrieved by some other
   * auth module.
   */
  if (af_user_file == NULL) {
    return PR_DECLINED(cmd);
  }

  crypted_pass = crypt(cleartxt_pass, ciphertxt_pass);
  xerrno = errno;

  ciphertxt_passlen = strlen(ciphertxt_pass);
  if (handle_empty_salt == TRUE &&
      ciphertxt_passlen == 0) {
    crypted_pass = "";
  }

  if (crypted_pass == NULL) {
    const char *user;

    user = cmd->argv[1];
    pr_log_debug(DEBUG0, MOD_AUTH_FILE_VERSION
      ": error using crypt(3) for user '%s': %s", user, strerror(xerrno));

    if (ciphertxt_passlen > 0 &&
        (xerrno == EINVAL ||
         xerrno == EPERM)) {
      check_unsupported_algo(user, ciphertxt_pass, ciphertxt_passlen);
    }

    return PR_DECLINED(cmd);
  }

  if (strcmp(crypted_pass, ciphertxt_pass) == 0) {
    session.auth_mech = "mod_auth_file.c";
    return PR_HANDLED(cmd);
  }  

  return PR_DECLINED(cmd);
}

/* Configuration handlers
 */

/* usage: AuthFileOptions opt1 ... */
MODRET set_authfileoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "InsecurePerms") == 0) {
      opts |= AUTH_FILE_OPT_INSECURE_PERMS;

      /* Note that this option disables some parse-time checks, so we need
       * to set it globally now, rather than at sess_init time.
       */
      auth_file_opts |= AUTH_FILE_OPT_INSECURE_PERMS;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown AuthFileOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: AuthGroupFile path [id <min-max>] [name <regex>] */
MODRET set_authgroupfile(cmd_rec *cmd) {
  config_rec *c = NULL;
  authfile_file_t *file = NULL;
  int flags = 0;
  char *path;

#ifdef PR_USE_REGEX
  if (cmd->argc-1 < 1 ||
      cmd->argc-1 > 5) {
#else
  if (cmd->argc-1 < 1 ||
      cmd->argc-1 > 2) {
#endif /* regex support */
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  path = cmd->argv[1];
  if (*path != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "unable to use relative path for ", (char *) cmd->argv[0], " '",
      path, "'.", NULL));
  }

  if (!(auth_file_opts & AUTH_FILE_OPT_INSECURE_PERMS)) {
    /* Make sure the configured file has the correct permissions.  Note that
     * AuthGroupFiles, unlike AuthUserFiles, do not contain any sensitive
     * information, and can thus be world-readable.
     */
    flags = PR_AUTH_FILE_FL_ALLOW_WORLD_READABLE;
    if (af_check_file(cmd->tmp_pool, cmd->argv[0], cmd->argv[1], flags) < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "unable to use ", path, ": ", strerror(errno), NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);

  file = pcalloc(c->pool, sizeof(authfile_file_t));
  file->af_path = pstrdup(c->pool, path);
  c->argv[0] = (void *) file;

  /* Check for restrictions */
  if (cmd->argc-1 != 1) {
    register unsigned int i = 0;

    for (i = 2; i < cmd->argc; i++) {
      if (strncmp(cmd->argv[i], "id", 3) == 0) {
        gid_t min, max;
        char *sep = NULL, *tmp = NULL;

        /* The range restriction parameter is of the form "min-max", where max
         * must be >= min.
         */

        sep = strchr(cmd->argv[++i], '-');
        if (sep == NULL) {
          CONF_ERROR(cmd, "badly formatted ID restriction parameter");
        }

        *sep = '\0';

        min = strtol(cmd->argv[i], &tmp, 10);
        if (tmp && *tmp) {
          CONF_ERROR(cmd, "badly formatted minimum ID");
        }

        tmp = NULL;

        max = strtol(sep+1, &tmp, 10);
        if (tmp && *tmp) {
          CONF_ERROR(cmd, "badly formatted maximum ID");
        }

        if (min > max) {
          CONF_ERROR(cmd, "minimum cannot be larger than maximum");
        }

        file->af_min_id.gid = min;
        file->af_max_id.gid = max;
        file->af_restricted_ids = TRUE;

#ifdef PR_USE_REGEX
      } else if (strncmp(cmd->argv[i], "name", 5) == 0) {
        char *filter = cmd->argv[++i];
        pr_regex_t *pre = NULL;
        int res = 0;

        pre = pr_regexp_alloc(&auth_file_module);

        /* Check for a ! negation/inversion filter prefix. */
        if (*filter == '!') {
          filter++;
          file->af_name_regex_inverted = TRUE;
        }

        res = pr_regexp_compile(pre, filter, REG_EXTENDED|REG_NOSUB);
        if (res != 0) {
          char errstr[200] = {'\0'};

          pr_regexp_error(res, pre, errstr, sizeof(errstr));
          pr_regexp_free(NULL, pre);

          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", filter, "' failed "
            "regex compilation: ", errstr, NULL));
        }

        file->af_name_filter = pstrdup(c->pool, cmd->argv[i]);
        file->af_name_regex = pre;
        file->af_restricted_names = TRUE;
#endif /* regex support */

      } else {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown restriction '",
          cmd->argv[i], "'", NULL));
      }
    }
  }

  return PR_HANDLED(cmd);
}

/* usage: AuthUserFile path [home <regexp>] [id <min-max>] [name <regex>] */
MODRET set_authuserfile(cmd_rec *cmd) {
  config_rec *c = NULL;
  authfile_file_t *file = NULL;
  int flags = 0;
  char *path;

#ifdef PR_USE_REGEX
  if (cmd->argc-1 < 1 ||
      cmd->argc-1 > 7) {
#else
  if (cmd->argc-1 < 1 ||
      cmd->argc-1 > 2) {
#endif /* regex support */
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  path = cmd->argv[1];
  if (*path != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "unable to use relative path for ", (char *) cmd->argv[0], " '",
      path, "'.", NULL));
  }

  if (!(auth_file_opts & AUTH_FILE_OPT_INSECURE_PERMS)) {
    /* Make sure the configured file has the correct permissions.  Note that
     * AuthUserFiles, unlike AuthGroupFiles, DO contain any sensitive
     * information, and thus CANNOT be world-readable.
     */
    flags = 0;
    if (af_check_file(cmd->tmp_pool, cmd->argv[0], cmd->argv[1], flags) < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "unable to use ", path, ": ", strerror(errno), NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);

  file = pcalloc(c->pool, sizeof(authfile_file_t));
  file->af_path = pstrdup(c->pool, path);
  c->argv[0] = (void *) file;

  /* Check for restrictions */
  if (cmd->argc-1 != 1) {
    register unsigned int i = 0;

    for (i = 2; i < cmd->argc; i++) {
      if (strncmp(cmd->argv[i], "id", 3) == 0) {
        uid_t min, max;
        char *sep = NULL, *tmp = NULL;

        /* The range restriction parameter is of the form "min-max", where max
         * must be >= min.
         */

        sep = strchr(cmd->argv[++i], '-');
        if (sep == NULL) {
          CONF_ERROR(cmd, "badly formatted ID restriction parameter");
        }

        *sep = '\0';

        min = strtol(cmd->argv[i], &tmp, 10);
        if (tmp && *tmp) {
          CONF_ERROR(cmd, "badly formatted minimum ID");
        }

        tmp = NULL;

        max = strtol(sep+1, &tmp, 10);

        if (tmp && *tmp) {
          CONF_ERROR(cmd, "badly formatted maximum ID");
        }

        if (min > max) {
          CONF_ERROR(cmd, "minimum cannot be larger than maximum");
        }

        file->af_min_id.uid = min;
        file->af_max_id.uid = max;
        file->af_restricted_ids = TRUE;

#ifdef PR_USE_REGEX
      } else if (strncmp(cmd->argv[i], "home", 5) == 0) {
        char *filter = cmd->argv[++i];
        pr_regex_t *pre = NULL;
        int res = 0;

        pre = pr_regexp_alloc(&auth_file_module);

        /* Check for a ! negation/inversion filter prefix. */
        if (*filter == '!') {
          filter++;
          file->af_home_regex_inverted = TRUE;
        }

        res = pr_regexp_compile(pre, filter, REG_EXTENDED|REG_NOSUB);
        if (res != 0) {
          char errstr[200] = {'\0'};

          pr_regexp_error(res, pre, errstr, sizeof(errstr));
          pr_regexp_free(NULL, pre);

          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", filter, "' failed "
            "regex compilation: ", errstr, NULL));
        }

        file->af_home_filter = pstrdup(c->pool, cmd->argv[i]);
        file->af_home_regex = pre;
        file->af_restricted_homes = TRUE;

      } else if (strncmp(cmd->argv[i], "name", 5) == 0) {
        char *filter = cmd->argv[++i];
        pr_regex_t *pre = NULL;
        int res = 0;

        pre = pr_regexp_alloc(&auth_file_module);

        /* Check for a ! negation/inversion filter prefix. */
        if (*filter == '!') {
          filter++;
          file->af_name_regex_inverted = TRUE;
        }

        res = pr_regexp_compile(pre, filter, REG_EXTENDED|REG_NOSUB);
        if (res != 0) {
          char errstr[200] = {'\0'};

          pr_regexp_error(res, pre, errstr, sizeof(errstr));
          pr_regexp_free(NULL, pre);

          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", filter, "' failed "
            "regex compilation: ", errstr, NULL));
        }

        file->af_name_filter = pstrdup(c->pool, cmd->argv[i]);
        file->af_name_regex = pre;
        file->af_restricted_names = TRUE;
#endif /* regex support */

      } else {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown restriction '",
          cmd->argv[i], "'", NULL));
      }
    }
  }

  return PR_HANDLED(cmd);
}

/* Event listeners
 */

static void authfile_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&auth_file_module, "core.session-reinit",
    authfile_sess_reinit_ev);

  af_user_file = NULL;
  af_group_file = NULL;

  res = authfile_sess_init();
  if (res < 0) {
    pr_session_disconnect(&auth_file_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Initialization routines
 */

static int authfile_init(void) {
  const char *key, *salt, *hash;

  /* On some Unix platforms, giving crypt(3) an empty string for the salt,
   * no matter what the input key, results in an empty string being returned.
   * (The salt string is what is obtained from the AuthUserFile that has been
   * configured.)
   *
   * On other platforms, given crypt(3) a real key and an empty string for
   * the salt returns in a real string.  (I'm looking at you, Mac OSX.)
   *
   * Thus in order to handle the edge case of an AuthUserFile with a passwd
   * field being empty the same on such differing platforms, we perform a
   * runtime check (at startup), to see how crypt(3) behaves -- and then
   * preserve the principle of least surprise appropriately.
   */

  key = "key";
  salt = "";
  hash = crypt(key, salt);
  if (hash != NULL) {
    if (strcmp(hash, "") != 0) {
      /* We're probably on a Mac OSX or similar platform. */
      handle_empty_salt = TRUE;
    }
  }

  return 0;
}

static int authfile_sess_init(void) {
  config_rec *c = NULL;

  pr_event_register(&auth_file_module, "core.session-reinit",
    authfile_sess_reinit_ev, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "AuthUserFile", FALSE);
  if (c != NULL) {
    af_user_file = c->argv[0];
  }

  c = find_config(main_server->conf, CONF_PARAM, "AuthGroupFile", FALSE);
  if (c != NULL) {
    af_group_file = c->argv[0];
  }

  return 0;
}

/* Module API tables
 */

static conftable authfile_conftab[] = {
  { "AuthFileOptions",	set_authfileoptions,	NULL },
  { "AuthGroupFile",	set_authgroupfile,	NULL },
  { "AuthUserFile",	set_authuserfile,	NULL },
  { NULL }
};

static authtable authfile_authtab[] = {

  /* User information callbacks */
  { 0, "endpwent",	authfile_endpwent },
  { 0, "getpwent",	authfile_getpwent },
  { 0, "getpwnam",	authfile_getpwnam },
  { 0, "getpwuid",	authfile_getpwuid },
  { 0, "name2uid",	authfile_name2uid },
  { 0, "setpwent",	authfile_setpwent },
  { 0, "uid2name",	authfile_uid2name },

  /* Group information callbacks */
  { 0, "endgrent",	authfile_endgrent },
  { 0, "getgrent",	authfile_getgrent },
  { 0, "getgrgid",	authfile_getgrgid },
  { 0, "getgrnam",	authfile_getgrnam },
  { 0, "getgroups",	authfile_getgroups },
  { 0, "gid2name",	authfile_gid2name },
  { 0, "name2gid",	authfile_name2gid },
  { 0, "setgrent",	authfile_setgrent },

  /* Miscellaneous callbacks */
  { 0, "auth",		authfile_auth },
  { 0, "check",		authfile_chkpass },

  { 0, NULL, NULL }
};

module auth_file_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "auth_file",

  /* Module configuration handler table */
  authfile_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  authfile_authtab,

  /* Module initialization function */
  authfile_init,

  /* Session initialization function */
  authfile_sess_init,

  /* Module version */
  MOD_AUTH_FILE_VERSION
};

