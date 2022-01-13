/*
 * ProFTPD: mod_facts -- a module for handling "facts" [RFC3659]
 * Copyright (c) 2007-2019 The ProFTPD Project
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
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#include "conf.h"
#include "privs.h"
#include "error.h"

#define MOD_FACTS_VERSION		"mod_facts/0.6"

#if PROFTPD_VERSION_NUMBER < 0x0001030101
# error "ProFTPD 1.3.1rc1 or later required"
#endif

module facts_module;

static unsigned long facts_opts = 0;
#define FACTS_OPT_SHOW_MODIFY		0x00001
#define FACTS_OPT_SHOW_PERM		0x00002
#define FACTS_OPT_SHOW_SIZE		0x00004
#define FACTS_OPT_SHOW_TYPE		0x00008
#define FACTS_OPT_SHOW_UNIQUE		0x00010
#define FACTS_OPT_SHOW_UNIX_GROUP	0x00020
#define FACTS_OPT_SHOW_UNIX_MODE	0x00040
#define FACTS_OPT_SHOW_UNIX_OWNER	0x00080
#define FACTS_OPT_SHOW_MEDIA_TYPE	0x00100
#define FACTS_OPT_SHOW_UNIX_OWNER_NAME	0x00200
#define FACTS_OPT_SHOW_UNIX_GROUP_NAME	0x00400

static unsigned long facts_mlinfo_opts = 0;
#define FACTS_MLINFO_FL_SHOW_SYMLINKS			0x00001
#define FACTS_MLINFO_FL_SHOW_SYMLINKS_USE_SLINK		0x00002
#define FACTS_MLINFO_FL_NO_CDIR				0x00004
#define FACTS_MLINFO_FL_APPEND_CRLF			0x00008
#define FACTS_MLINFO_FL_ADJUSTED_SYMLINKS		0x00010
#define FACTS_MLINFO_FL_NO_NAMES			0x00020

struct mlinfo {
  pool *pool;
  struct stat st;
  struct tm *tm;
  const char *user;
  const char *group;
  const char *type;
  const char *perm;
  const char *path;
  const char *real_path;
};

/* Necessary prototypes */
static void facts_mlinfobuf_flush(void);
static int facts_sess_init(void);

/* Support functions
 */

static int facts_filters_allow_path(cmd_rec *cmd, const char *path) {
#ifdef PR_USE_REGEX
  pr_regex_t *pre = get_param_ptr(CURRENT_CONF, "PathAllowFilter", FALSE);
  if (pre != NULL &&
      pr_regexp_exec(pre, path, 0, NULL, 0, 0, 0) != 0) {
    pr_log_debug(DEBUG2, MOD_FACTS_VERSION
      ": %s denied by PathAllowFilter on '%s'", (char *) cmd->argv[0],
      cmd->arg);
    return -1;
  }

  pre = get_param_ptr(CURRENT_CONF, "PathDenyFilter", FALSE);
  if (pre != NULL &&
      pr_regexp_exec(pre, path, 0, NULL, 0, 0, 0) == 0) {
    pr_log_debug(DEBUG2, MOD_FACTS_VERSION
      ": %s denied by PathDenyFilter on '%s'", (char *) cmd->argv[0], cmd->arg);
    return -1;
  }
#endif

  return 0;
}

#define FACTS_SECS_PER_MIN	(60)
#define FACTS_SECS_PER_HOUR	(60 * FACTS_SECS_PER_MIN)
#define FACTS_SECS_PER_DAY	(24 * FACTS_SECS_PER_HOUR)
#define FACTS_EPOCH_YEAR	1970

/* How many days come before each month (0-12).  */
static const unsigned short int facts_ydays_for_mon[2][13] = {
  /* Normal years.  */
  { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },

  /* Leap years.  */
  { 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }
};

static unsigned long facts_secs_per_min(unsigned int min) {
  unsigned long nsecs;

  nsecs = (min * FACTS_SECS_PER_MIN);
  return nsecs;
}

static unsigned long facts_secs_per_hour(unsigned int hour) {
  unsigned long nsecs;

  nsecs = (hour * FACTS_SECS_PER_HOUR);
  return nsecs;
}

static unsigned long facts_secs_per_day(unsigned long ndays) {
  unsigned long nsecs;

  nsecs = (ndays * FACTS_SECS_PER_DAY);
  return nsecs;
}

/* Every 4th year is a leap year, except for every 100th year, but including
 * every 400th year.
 */
static int facts_leap_year(unsigned int year) {
  int leap_year = 0;

  if ((year % 4) == 0) {
    leap_year = 1;

    if ((year % 100) == 0) {
      leap_year = 0;

      if ((year % 400) == 0) {
        leap_year = 1;
      }
    }
  }

  return leap_year;
}

static unsigned long facts_secs_per_mon(unsigned int mon, unsigned int year) {
  int leap_year;
  static unsigned int ndays;
  static unsigned long nsecs;

  leap_year = facts_leap_year(year);
  ndays = facts_ydays_for_mon[leap_year][mon-1];

  nsecs = facts_secs_per_day(ndays);
  return nsecs;
}

static unsigned long facts_secs_per_year(unsigned int year) {
  unsigned long ndays, nsecs;

  ndays = (year - FACTS_EPOCH_YEAR) * 365;

  /* Compute the number of leap days between 1970 and the given year
   * (exclusive).  There is a leap day every 4th year...
   */
  ndays += (((year - 1) / 4) - (FACTS_EPOCH_YEAR / 4));

  /* ...except every 100th year...*/
  ndays -= (((year - 1) / 100) - (FACTS_EPOCH_YEAR / 100));

  /* ...but still every 400th year. */
  ndays += (((year - 1) / 400) - (FACTS_EPOCH_YEAR / 400));

  nsecs = facts_secs_per_day(ndays);
  return nsecs;
}

static time_t facts_mktime(unsigned int year, unsigned int month,
    unsigned int mday, unsigned int hour, unsigned int min, unsigned int sec) {
  time_t res;

  /* Rather than using the system mktime(3) function (which requires external
   * files such as /etc/localtime and the timezone definition files, depending
   * on the TZ environment value setting), we use a custom mktime collection
   * of functions.
   *
   * Fortunately, our homegrown collection of time conversion functions
   * ONLY needs to generate GMT seconds here, and so we don't have to worry
   * about DST, timezones, etc (Bug#3790).
   */

  res = facts_secs_per_year(year) +
        facts_secs_per_mon(month, year) +

        /* Subtract one day to make the mday zero-based. */
        facts_secs_per_day(mday - 1) +

        facts_secs_per_hour(hour) +
        facts_secs_per_min(min) +
        sec;

  return res;
}

static const char *facts_mime_type(struct mlinfo *info) {
  cmdtable *cmdtab;
  cmd_rec *cmd;
  modret_t *res;

  cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "mime_type", NULL, NULL, NULL);
  if (cmdtab == NULL) {
    errno = EPERM;
    return NULL;
  }

  cmd = pr_cmd_alloc(info->pool, 1, info->real_path);
  res = pr_module_call(cmdtab->m, cmdtab->handler, cmd);
  if (MODRET_ISHANDLED(res) &&
      MODRET_HASDATA(res)) {
    return res->data;
  }

  errno = ENOENT;
  return NULL;
}

static size_t facts_mlinfo_fmt(struct mlinfo *info, char *buf, size_t bufsz,
    int flags) {
  int len;
  char *ptr;
  size_t buflen = 0;

  memset(buf, '\0', bufsz);

  ptr = buf;

  if (facts_opts & FACTS_OPT_SHOW_MODIFY) {
    if (info->tm != NULL) {
      len = pr_snprintf(ptr, bufsz, "modify=%04d%02d%02d%02d%02d%02d;",
        info->tm->tm_year+1900, info->tm->tm_mon+1, info->tm->tm_mday,
        info->tm->tm_hour, info->tm->tm_min, info->tm->tm_sec);

    } else {
      len = 0;
    }

    buflen += len;
    ptr = buf + buflen;
  }

  if (facts_opts & FACTS_OPT_SHOW_PERM) {
    len = pr_snprintf(ptr, bufsz - buflen, "perm=%s;", info->perm);
    buflen += len;
    ptr = buf + buflen;
  }

  if (!S_ISDIR(info->st.st_mode) &&
      (facts_opts & FACTS_OPT_SHOW_SIZE)) {
    len = pr_snprintf(ptr, bufsz - buflen, "size=%" PR_LU ";",
      (pr_off_t) info->st.st_size);
    buflen += len;
    ptr = buf + buflen;
  }

  if (facts_opts & FACTS_OPT_SHOW_TYPE) {
    len = pr_snprintf(ptr, bufsz - buflen, "type=%s;", info->type);
    buflen += len;
    ptr = buf + buflen;
  }

  if (facts_opts & FACTS_OPT_SHOW_UNIQUE) {
    len = pr_snprintf(ptr, bufsz - buflen, "unique=%lXU%lX;",
      (unsigned long) info->st.st_dev, (unsigned long) info->st.st_ino);
    buflen += len;
    ptr = buf + buflen;
  }

  if (facts_opts & FACTS_OPT_SHOW_UNIX_GROUP) {
    len = pr_snprintf(ptr, bufsz - buflen, "UNIX.group=%s;",
      pr_gid2str(NULL, info->st.st_gid));
    buflen += len;
    ptr = buf + buflen;
  }

  if (!(facts_mlinfo_opts & FACTS_MLINFO_FL_NO_NAMES)) {
    if (facts_opts & FACTS_OPT_SHOW_UNIX_GROUP_NAME) {
      len = pr_snprintf(ptr, bufsz - buflen, "UNIX.groupname=%s;", info->group);
      buflen += len;
      ptr = buf + buflen;
    }
  }

  if (facts_opts & FACTS_OPT_SHOW_UNIX_MODE) {
    len = pr_snprintf(ptr, bufsz - buflen, "UNIX.mode=0%o;",
      (unsigned int) info->st.st_mode & 07777);
    buflen += len;
    ptr = buf + buflen;
  }

  if (facts_opts & FACTS_OPT_SHOW_UNIX_OWNER) {
    len = pr_snprintf(ptr, bufsz - buflen, "UNIX.owner=%s;",
      pr_uid2str(NULL, info->st.st_uid));
    buflen += len;
    ptr = buf + buflen;
  }

  if (!(facts_mlinfo_opts & FACTS_MLINFO_FL_NO_NAMES)) {
    if (facts_opts & FACTS_OPT_SHOW_UNIX_OWNER_NAME) {
      len = pr_snprintf(ptr, bufsz - buflen, "UNIX.ownername=%s;", info->user);
      buflen += len;
      ptr = buf + buflen;
    }
  }

  if (facts_opts & FACTS_OPT_SHOW_MEDIA_TYPE) {
    const char *mime_type;

    mime_type = facts_mime_type(info);
    if (mime_type != NULL) {
      len = pr_snprintf(ptr, bufsz - buflen, "media-type=%s;",
        mime_type);
      buflen += len;
      ptr = buf + buflen;
    }
  }

  if (flags & FACTS_MLINFO_FL_APPEND_CRLF) {
    len = pr_snprintf(ptr, bufsz - buflen, " %s\r\n", info->path);

  } else {
    len = pr_snprintf(ptr, bufsz - buflen, " %s", info->path);
  }

  buf[bufsz-1] = '\0';
  buflen += len;

  return buflen;
}

/* This buffer is used by the MLSD handler, to buffer up the output lines.
 * When all the lines have been added, or when the buffer is full, it will
 * flushed out.
 *
 * This handling is different from the MLST handler's use of
 * facts_mlinfo_add() because MLST gets to send its line back on the control
 * channel, whereas MLSD's output is sent via a data transfer, much like
 * LIST or NLST.
 */
static pool *mlinfo_pool = NULL;
static char *mlinfo_buf = NULL, *mlinfo_bufptr = NULL;
static size_t mlinfo_bufsz = 0;
static size_t mlinfo_buflen = 0;

static void facts_mlinfobuf_init(void) {
  if (mlinfo_buf == NULL) {
    mlinfo_bufsz = pr_config_get_server_xfer_bufsz(PR_NETIO_IO_WR);

    if (mlinfo_pool != NULL) {
      destroy_pool(mlinfo_pool);
    }

    mlinfo_pool = make_sub_pool(session.pool);
    pr_pool_tag(mlinfo_pool, "Facts MLSD Buffer Pool");

    mlinfo_buf = palloc(mlinfo_pool, mlinfo_bufsz);
    pr_trace_msg("data", 8, "allocated facts buffer of %lu bytes",
      (unsigned long) mlinfo_bufsz);
  }

  memset(mlinfo_buf, '\0', mlinfo_bufsz);
  mlinfo_bufptr = mlinfo_buf;
  mlinfo_buflen = 0;
}

static void facts_mlinfobuf_add(struct mlinfo *info, int flags) {
  char buf[PR_TUNABLE_BUFFER_SIZE];
  size_t buflen;
 
  buflen = facts_mlinfo_fmt(info, buf, sizeof(buf), flags);

  /* If this buffer will exceed the capacity of mlinfo_buf, then flush
   * mlinfo_buf.
   */
  if (buflen >= (mlinfo_bufsz - mlinfo_buflen)) {
    (void) facts_mlinfobuf_flush();
  }

  sstrcat(mlinfo_bufptr, buf, mlinfo_bufsz - mlinfo_buflen);
  mlinfo_bufptr += buflen;
  mlinfo_buflen += buflen;
}

static void facts_mlinfobuf_flush(void) {
  if (mlinfo_buflen > 0) {
    int res;

    /* Make sure the ASCII flags are cleared from the session flags,
     * so that the pr_data_xfer() function does not try to perform
     * ASCII translation on this data.
     */
    session.sf_flags &= ~SF_ASCII_OVERRIDE;

    res = pr_data_xfer(mlinfo_buf, mlinfo_buflen);
    if (res < 0 &&
        errno != 0) {
      pr_log_debug(DEBUG3, MOD_FACTS_VERSION
        ": error transferring data: [%d] %s", errno, strerror(errno));
    }

    session.sf_flags |= SF_ASCII_OVERRIDE;
  }

  facts_mlinfobuf_init();
}

static int facts_mlinfo_get(struct mlinfo *info, const char *path,
    const char *dent_name, int flags, const char *user, uid_t uid,
    const char *group, gid_t gid, mode_t *mode) {
  char *perm = "";
  int res;

  pr_fs_clear_cache2(path);
  res = pr_fsio_lstat(path, &(info->st));
  if (res < 0) {
    int xerrno = errno;

    pr_log_debug(DEBUG4, MOD_FACTS_VERSION ": error lstat'ing '%s': %s",
      path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (user != NULL) {
    info->user = pstrdup(info->pool, user);

  } else {
    info->user = session.user;
  }

  if (uid != (uid_t) -1) {
    info->st.st_uid = uid;
  }

  if (group != NULL) {
    info->group = pstrdup(info->pool, group);

  } else {
    info->group = session.group;
  }

  if (gid != (gid_t) -1) {
    info->st.st_gid = gid;
  }

  info->tm = pr_gmtime(info->pool, &(info->st.st_mtime));

  if (!S_ISDIR(info->st.st_mode)) {
#ifdef S_ISLNK
    if (S_ISLNK(info->st.st_mode)) {
      struct stat target_st;
      const char *dst_path;
      int len = 0;

      /* Now we need to use stat(2) on the path (versus lstat(2)) to get the
       * info for the target, and copy its st_dev and st_ino values to our
       * stat in order to ensure that the unique fact values are the same.
       *
       * If we are chrooted, however, then the stat(2) on the symlink will
       * almost certainly fail, especially if the destination path is an
       * absolute path.
       */

      if (flags & FACTS_MLINFO_FL_ADJUSTED_SYMLINKS) {
        char *link_path;
        size_t link_pathsz;

        link_pathsz = PR_TUNABLE_PATH_MAX;
        link_path = pcalloc(info->pool, link_pathsz);
        len = dir_readlink(info->pool, path, link_path, link_pathsz-1,
          PR_DIR_READLINK_FL_HANDLE_REL_PATH);
        if (len > 0 &&
            (size_t) len < link_pathsz) {
          char *best_path;

          best_path = dir_best_path(info->pool, link_path);
          if (best_path != NULL) {
            dst_path = best_path;

          } else {
            dst_path = link_path;
          }

        } else {
          dst_path = path;
        }

        pr_fs_clear_cache2(dst_path);
        res = pr_fsio_stat(dst_path, &target_st);

      } else {
        dst_path = path;
        res = pr_fsio_stat(dst_path, &target_st);
      }

      if (res < 0) {
        int xerrno = errno;

        pr_log_debug(DEBUG4, MOD_FACTS_VERSION ": error stat'ing '%s': %s",
          dst_path, strerror(xerrno));

        errno = xerrno;
        return -1;
      }

      info->st.st_dev = target_st.st_dev;
      info->st.st_ino = target_st.st_ino;

      if (flags & FACTS_MLINFO_FL_SHOW_SYMLINKS) {

        /* Do we use the proper RFC 3659 syntax (i.e. following the BNF rules
         * of RFC 3659), which would be:
         *
         *   type=OS.unix=symlink
         *
         * See:
         *   http://www.rfc-editor.org/errata_search.php?rfc=3659
         *
         * and search for "OS.unix=slink".
         *
         * Or do we use the syntax in the _examples_ presented in RFC 3659,
         * which is what clients such as FileZilla expect:
         *
         *   type=OS.unix=slink:<target>
         *
         * See:
         *   http://trac.filezilla-project.org/ticket/4490
         */

        if (flags & FACTS_MLINFO_FL_SHOW_SYMLINKS_USE_SLINK) {
          char target[PR_TUNABLE_PATH_MAX+1];
          int targetlen;

          if (flags & FACTS_MLINFO_FL_ADJUSTED_SYMLINKS) {
            sstrncpy(target, dst_path, sizeof(target)-1);
            targetlen = len;

          } else {
            targetlen = pr_fsio_readlink(path, target, sizeof(target)-1);
          }

          if (targetlen < 0) { 
            int xerrno = errno;

            pr_log_debug(DEBUG4, MOD_FACTS_VERSION
              ": error reading symlink '%s': %s", path, strerror(xerrno));

            errno = xerrno;
            return -1;
          }

          if ((size_t) targetlen >= sizeof(target)-1) {
            targetlen = sizeof(target)-1;
          }

          target[targetlen] = '\0';

          info->type = pstrcat(info->pool, "OS.unix=slink:",
            dir_best_path(info->pool, target), NULL);

        } else {
          /* Use the proper syntax.  Too bad for the not-really-compliant
           * FileZilla.
           */
          info->type = "OS.unix=symlink";
        }

      } else {
        if (S_ISDIR(target_st.st_mode)) {
          info->type = "dir";

        } else {
          info->type = "file";
        }
      }

    } else {
      info->type = "file";
    }
#else
    info->type = "file";
#endif

    if (pr_fsio_access(path, R_OK, session.uid, session.gid,
        session.gids) == 0) {

      /* XXX Need to come up with a good way of determining whether 'd'
       * should be listed.  For example, if the parent directory does not
       * allow write privs to the current user/group, then the file cannot
       * be deleted.
       */

      perm = pstrcat(info->pool, perm, "adfr", NULL);

    } else {
      perm = pstrcat(info->pool, perm, "dfr", NULL);
    }

    if (pr_fsio_access(path, W_OK, session.uid, session.gid,
        session.gids) == 0) {
      perm = pstrcat(info->pool, perm, "w", NULL);
    }

  } else {
    info->type = "dir";

    if (!(flags & FACTS_MLINFO_FL_NO_CDIR)) {
      if (dent_name[0] == '.') {
        if (dent_name[1] == '\0') {
          info->type = "cdir";
        }

        if (strlen(dent_name) >= 2) {
          if (dent_name[1] == '.' &&
              dent_name[2] == '\0') {
            info->type = "pdir";
          }
        }
      }
    }

    if (pr_fsio_access(path, R_OK, session.uid, session.gid,
        session.gids) == 0) {
      perm = pstrcat(info->pool, perm, "fl", NULL);
    }

    if (pr_fsio_access(path, W_OK, session.uid, session.gid,
        session.gids) == 0) {
      perm = pstrcat(info->pool, perm, "cdmp", NULL);
    }

    if (pr_fsio_access(path, X_OK, session.uid, session.gid,
        session.gids) == 0) {
      perm = pstrcat(info->pool, perm, "e", NULL);
    }
  }

  info->perm = perm;

  if (mode != NULL) {
    /* We cheat here by simply overwriting the entire st.st_mode value with
     * the DirFakeMode.  This works because later operations on this data
     * don't pay attention to the file type.
     */
    info->st.st_mode = *mode;
  }

  info->real_path = pstrdup(info->pool, path);
  return 0;
}

static void facts_mlinfo_add(struct mlinfo *info, int flags) {
  char buf[PR_TUNABLE_BUFFER_SIZE];

  (void) facts_mlinfo_fmt(info, buf, sizeof(buf), flags);

  /* The trailing CRLF will be added by pr_response_add(). */
  pr_response_add(R_DUP, "%s", buf);
}

static void facts_mlst_feat_add(pool *p) {
  char *feat_str = "";

  feat_str = pstrcat(p, feat_str, "modify", NULL);
  if (facts_opts & FACTS_OPT_SHOW_MODIFY) {
    feat_str = pstrcat(p, feat_str, "*;", NULL);

  } else {
    feat_str = pstrcat(p, feat_str, ";", NULL);
  }

  feat_str = pstrcat(p, feat_str, "perm", NULL);
  if (facts_opts & FACTS_OPT_SHOW_PERM) {
    feat_str = pstrcat(p, feat_str, "*;", NULL);

  } else {
    feat_str = pstrcat(p, feat_str, ";", NULL);
  }

  feat_str = pstrcat(p, feat_str, "size", NULL);
  if (facts_opts & FACTS_OPT_SHOW_SIZE) {
    feat_str = pstrcat(p, feat_str, "*;", NULL);

  } else {
    feat_str = pstrcat(p, feat_str, ";", NULL);
  }

  feat_str = pstrcat(p, feat_str, "type", NULL);
  if (facts_opts & FACTS_OPT_SHOW_TYPE) {
    feat_str = pstrcat(p, feat_str, "*;", NULL);

  } else {
    feat_str = pstrcat(p, feat_str, ";", NULL);
  }

  feat_str = pstrcat(p, feat_str, "unique", NULL);
  if (facts_opts & FACTS_OPT_SHOW_UNIQUE) {
    feat_str = pstrcat(p, feat_str, "*;", NULL);

  } else {
    feat_str = pstrcat(p, feat_str, ";", NULL);
  }

  feat_str = pstrcat(p, feat_str, "UNIX.group", NULL);
  if (facts_opts & FACTS_OPT_SHOW_UNIX_GROUP) {
    feat_str = pstrcat(p, feat_str, "*;", NULL);

  } else {
    feat_str = pstrcat(p, feat_str, ";", NULL);
  }

  if (!(facts_mlinfo_opts & FACTS_MLINFO_FL_NO_NAMES)) {
    feat_str = pstrcat(p, feat_str, "UNIX.groupname", NULL);
    if (facts_opts & FACTS_OPT_SHOW_UNIX_GROUP_NAME) {
      feat_str = pstrcat(p, feat_str, "*;", NULL);

    } else {
      feat_str = pstrcat(p, feat_str, ";", NULL);
    }
  }

  feat_str = pstrcat(p, feat_str, "UNIX.mode", NULL);
  if (facts_opts & FACTS_OPT_SHOW_UNIX_MODE) {
    feat_str = pstrcat(p, feat_str, "*;", NULL);

  } else {
    feat_str = pstrcat(p, feat_str, ";", NULL);
  }

  feat_str = pstrcat(p, feat_str, "UNIX.owner", NULL);
  if (facts_opts & FACTS_OPT_SHOW_UNIX_OWNER) {
    feat_str = pstrcat(p, feat_str, "*;", NULL);

  } else {
    feat_str = pstrcat(p, feat_str, ";", NULL);
  }

  if (!(facts_mlinfo_opts & FACTS_MLINFO_FL_NO_NAMES)) {
    feat_str = pstrcat(p, feat_str, "UNIX.ownername", NULL);
    if (facts_opts & FACTS_OPT_SHOW_UNIX_OWNER_NAME) {
      feat_str = pstrcat(p, feat_str, "*;", NULL);

    } else {
      feat_str = pstrcat(p, feat_str, ";", NULL);
    }
  }

  /* Note: we only show the 'media-type' fact IFF mod_mime is present AND
   * is enabled via MIMEEngine.
   */
  if (pr_module_exists("mod_mime.c") == TRUE &&
      (facts_opts & FACTS_OPT_SHOW_MEDIA_TYPE)) {
    feat_str = pstrcat(p, feat_str, "media-type*;", NULL);
  }

  feat_str = pstrcat(p, "MLST ", feat_str, NULL);
  pr_feat_add(feat_str);
}

static void facts_mlst_feat_remove(void) {
  const char *feat, *mlst_feat = NULL;

  feat = pr_feat_get();
  while (feat) {
    pr_signals_handle();

    if (strncmp(feat, C_MLST, 4) == 0) {
      mlst_feat = feat;
      break;
    }

    feat = pr_feat_get_next();
  }

  if (mlst_feat)
    pr_feat_remove(mlst_feat);
}

static int facts_modify_mtime(pool *p, const char *path, char *timestamp) {
  char c, *ptr;
  int year, month, day, hour, min, sec;
  struct timeval tvs[2];
  int res;

  (void) p;

  ptr = timestamp;
  c = timestamp[4];
  timestamp[4] = '\0';
  year = atoi(ptr);
  timestamp[4] = c;

  if (year < FACTS_EPOCH_YEAR) {
    pr_log_debug(DEBUG8, MOD_FACTS_VERSION
      ": bad year value (%d) in timestamp '%s'", year, timestamp);
    errno = EINVAL;
    return -1;
  }

  ptr = &(timestamp[4]);
  c = timestamp[6];
  timestamp[6] = '\0';
  month = atoi(ptr);
  timestamp[6] = c;

  if (month < 1 ||
      month > 12) {
    pr_log_debug(DEBUG8, MOD_FACTS_VERSION
      ": bad number of months (%d) in timestamp '%s'", month, timestamp);
    errno = EINVAL;
    return -1;
  }

  ptr = &(timestamp[6]);
  c = timestamp[8];
  timestamp[8] = '\0';
  day = atoi(ptr);
  timestamp[8] = c;

  if (day < 1 ||
      day > 31) {
    pr_log_debug(DEBUG8, MOD_FACTS_VERSION
      ": bad number of days (%d) in timestamp '%s'", day, timestamp);
    errno = EINVAL;
    return -1;
  }

  ptr = &(timestamp[8]);
  c = timestamp[10];
  timestamp[10] = '\0';
  hour = atoi(ptr);
  timestamp[10] = c;

  if (hour < 0 ||
      hour > 24) {
    pr_log_debug(DEBUG8, MOD_FACTS_VERSION
      ": bad number of hours (%d) in timestamp '%s'", hour, timestamp);
    errno = EINVAL;
    return -1;
  }

  ptr = &(timestamp[10]);
  c = timestamp[12];
  timestamp[12] = '\0';
  min = atoi(ptr);
  timestamp[12] = c;

  if (min < 0 ||
      min > 60) {
    pr_log_debug(DEBUG8, MOD_FACTS_VERSION
      ": bad number of minutes (%d) in timestamp '%s'", min, timestamp);
    errno = EINVAL;
    return -1;
  }

  ptr = &(timestamp[12]);
  sec = atoi(ptr);

  if (sec < 0 ||
      sec > 61) {
    pr_log_debug(DEBUG8, MOD_FACTS_VERSION
      ": bad number of seconds (%d) in timestamp '%s'", sec, timestamp);
    errno = EINVAL;
    return -1;
  }

  tvs[0].tv_usec = tvs[1].tv_usec = 0;
  tvs[0].tv_sec = tvs[1].tv_sec = facts_mktime(year, month, day, hour, min,
    sec);

  res = pr_fsio_utimes_with_root(path, tvs);
  if (res < 0) {
    int xerrno = errno;

    pr_log_debug(DEBUG2, MOD_FACTS_VERSION
      ": error modifying modify fact for '%s': %s", path, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  return 0;
}

static int facts_modify_unix_group(pool *p, const char *path,
    const char *group) {
  int res, xerrno = 0;
  gid_t gid;
  char *ptr = NULL;
  pr_error_t *err = NULL;

  gid = strtoul(group, &ptr, 10);
  if (ptr &&
      *ptr) {
    /* Try to lookup the GID using the value as a name. */
    gid = pr_auth_name2gid(p, group);
    if (gid == (gid_t) -1) {
      pr_log_debug(DEBUG7, MOD_FACTS_VERSION ": no such group '%s'", group);
      errno = EINVAL;
      return -1;
    }
  }

  res = pr_fsio_chown_with_error(p, path, (uid_t) -1, gid, &err);
  xerrno = errno;

  if (res < 0) {
    pr_error_set_where(err, &facts_module, __FILE__, __LINE__ - 4);
    pr_error_set_why(err, pstrcat(p, "modify UNIX.group fact for '", path,
      "'", NULL));

    if (err != NULL) {
      pr_log_debug(DEBUG5, MOD_FACTS_VERSION ": %s", pr_error_strerror(err, 0));
      pr_error_destroy(err);
      err = NULL;

    } else {
      pr_log_debug(DEBUG5, MOD_FACTS_VERSION
        ": error modifying UNIX.group fact for '%s': %s", path,
        strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  return 0;
}

static int facts_modify_unix_mode(pool *p, const char *path, char *mode_str) {
  int res, xerrno = 0;
  mode_t mode;
  char *ptr = NULL;
  pr_error_t *err = NULL;

  mode = strtoul(mode_str, &ptr, 8);
  if (ptr &&
      *ptr) {
    pr_log_debug(DEBUG3, MOD_FACTS_VERSION
      ": UNIX.mode fact '%s' is not an octal number", mode_str);
    errno = EINVAL;
    return -1;
  }

  res = pr_fsio_chmod_with_error(p, path, mode, &err);
  xerrno = errno;

  if (res < 0) {
    pr_error_set_where(err, &facts_module, __FILE__, __LINE__ - 4);
    pr_error_set_why(err, pstrcat(p, "modify UNIX.mode fact for '", path, "'",
      NULL));

    if (err != NULL) {
      pr_log_debug(DEBUG5, MOD_FACTS_VERSION ": %s", pr_error_strerror(err, 0));
      pr_error_destroy(err);
      err = NULL;

    } else {
      pr_log_debug(DEBUG5, MOD_FACTS_VERSION
        ": error modifying UNIX.mode fact for '%s': %s", path,
        strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  return 0;
}

/* Command handlers
 */

MODRET facts_mff(cmd_rec *cmd) {
  const char *path, *canon_path, *decoded_path;
  char *facts, *ptr;

  if (cmd->argc < 3) {
    pr_response_add_err(R_501, _("Invalid number of parameters"));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  facts = cmd->argv[1];

  /* The path can contain spaces.  Thus we need to use cmd->arg, not cmd->argv,
   * to find the path.  But cmd->arg contains the facts as well.  Thus we
   * find the FIRST space in cmd->arg; the path is everything past that space.
   */
  ptr = strchr(cmd->arg, ' ');
  if (ptr == NULL) {
    pr_response_add_err(R_501, _("Invalid command syntax"));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  path = pstrdup(cmd->tmp_pool, ptr + 1);

  decoded_path = pr_fs_decode_path2(cmd->tmp_pool, path,
    FSIO_DECODE_FL_TELL_ERRORS);
  if (decoded_path == NULL) {
    int xerrno = errno;

    pr_log_debug(DEBUG8, "'%s' failed to decode properly: %s", path,
      strerror(xerrno));
    pr_response_add_err(R_550, _("%s: Illegal character sequence in filename"),
      path);

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  canon_path = dir_canonical_path(cmd->tmp_pool, decoded_path);
  if (canon_path == NULL) {
    int xerrno = EINVAL;

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, canon_path, NULL)) {
    pr_log_debug(DEBUG4, MOD_FACTS_VERSION ": %s command denied by <Limit>",
      (char *) cmd->argv[0]);
    pr_response_add_err(R_550, _("Unable to handle command"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  if (facts_filters_allow_path(cmd, decoded_path) < 0) {
    int xerrno = EACCES;

    pr_response_add_err(R_550, "%s: %s", path, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  ptr = strchr(facts, ';');
  if (ptr == NULL) {
    int xerrno = EINVAL;

    pr_response_add_err(R_550, "%s: %s", facts, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  while (ptr) {
    pr_signals_handle();

    *ptr = '\0';

    if (strncasecmp(facts, "modify", 6) == 0) {
      /* Equivalent to SITE UTIME, or MFMT */

      char *timestamp, *ptr2;

      ptr2 = strchr(facts, '=');
      if (ptr2 == NULL) {
        int xerrno = EINVAL;

        pr_response_add_err(R_501, "%s: %s", (char *) cmd->argv[1],
          strerror(xerrno));

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return PR_ERROR(cmd);
      }

      timestamp = ptr2 + 1;

      if (strlen(timestamp) < 14) {
        int xerrno = EINVAL;

        pr_response_add_err(R_501, "%s: %s", timestamp, strerror(xerrno));

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return PR_ERROR(cmd);
      }

      ptr2 = strchr(timestamp, '.');
      if (ptr2) {
        pr_log_debug(DEBUG7, MOD_FACTS_VERSION
          ": %s: ignoring unsupported timestamp precision in '%s'",
          (char *) cmd->argv[0], timestamp);
        *ptr2 = '\0';
      }

      if (facts_modify_mtime(cmd->tmp_pool, decoded_path, timestamp) < 0) {
        int xerrno = errno;

        pr_response_add_err(xerrno == ENOENT ? R_550 : R_501, "%s: %s", path,
          strerror(xerrno));

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return PR_ERROR(cmd);
      }

    } else if (strncasecmp(facts, "UNIX.group", 10) == 0) {
      /* Equivalent to SITE CHGRP */

      char *group, *ptr2;

      ptr2 = strchr(facts, '=');
      if (ptr2 == NULL) {
        int xerrno = EINVAL;

        *ptr = ';';
        pr_response_add_err(R_501, "%s: %s", (char *) cmd->argv[1],
          strerror(xerrno));

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return PR_ERROR(cmd);
      }

      group = ptr2 + 1;

      if (facts_modify_unix_group(cmd->tmp_pool, decoded_path, group) < 0) {
        int xerrno = errno;

        pr_response_add_err(xerrno == ENOENT ? R_550 : R_501, "%s: %s", path,
          strerror(xerrno));

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return PR_ERROR(cmd);
      }

    } else if (strncasecmp(facts, "UNIX.mode", 9) == 0) {
      /* Equivalent to SITE CHMOD */

      char *mode_str, *ptr2;

      ptr2 = strchr(facts, '=');
      if (ptr2 == NULL) {
        int xerrno = errno;

        *ptr = ';';
        pr_response_add_err(R_501, "%s: %s", (char *) cmd->argv[1],
          strerror(xerrno));

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return PR_ERROR(cmd);
      }

      mode_str = ptr2 + 1;

      if (facts_modify_unix_mode(cmd->tmp_pool, decoded_path, mode_str) < 0) {
        int xerrno = errno;

        pr_response_add_err(xerrno == ENOENT ? R_550 : R_501, "%s: %s", path,
          strerror(xerrno));

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return PR_ERROR(cmd);
      }

    } else {
      /* Unlike the OPTS MLST handling, if MFF is sent with an unsupported
       * fact, we get to return an error.
       */
      pr_log_debug(DEBUG5, MOD_FACTS_VERSION
        ": %s: fact '%s' unsupported for modification, denying request",
        (char *) cmd->argv[0], facts);
      pr_response_add_err(R_504, _("Cannot modify fact '%s'"), facts);

      *ptr = ';';

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);
    }

    *ptr = ';';
    facts = ptr + 1;
    ptr = strchr(facts, ';');
  }

  /* Due to Draft requirements/recommendations, the list of facts that
   * were successfully modified are to be included in the response, for
   * possible client parsing.  This means that the list is NOT localisable.
   */
  pr_response_add(R_213, "%s %s", (char *) cmd->argv[1], path);
  return PR_HANDLED(cmd);
}

MODRET facts_mfmt(cmd_rec *cmd) {
  const char *path, *canon_path, *decoded_path;
  char *timestamp, *ptr;
  int res;

  if (cmd->argc < 3) {
    pr_response_add_err(R_501, _("Invalid number of parameters"));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  timestamp = cmd->argv[1];

  /* The path can contain spaces.  Thus we need to use cmd->arg, not cmd->argv,
   * to find the path.  But cmd->arg contains the facts as well.  Thus we
   * find the FIRST space in cmd->arg; the path is everything past that space.
   */
  ptr = strchr(cmd->arg, ' ');
  if (ptr == NULL) {
    pr_response_add_err(R_501, _("Invalid command syntax"));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  path = pstrdup(cmd->tmp_pool, ptr + 1);

  decoded_path = pr_fs_decode_path2(cmd->tmp_pool, path,
    FSIO_DECODE_FL_TELL_ERRORS);
  if (decoded_path == NULL) {
    int xerrno = errno;

    pr_log_debug(DEBUG8, "'%s' failed to decode properly: %s", path,
      strerror(xerrno));
    pr_response_add_err(R_550, _("%s: Illegal character sequence in filename"),
      path);

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  canon_path = dir_canonical_path(cmd->tmp_pool, decoded_path);
  if (canon_path == NULL) {
    int xerrno = EINVAL;

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, canon_path, NULL)) {
    pr_log_debug(DEBUG4, MOD_FACTS_VERSION ": %s command denied by <Limit>",
      (char *) cmd->argv[0]);
    pr_response_add_err(R_550, _("Unable to handle command"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  if (facts_filters_allow_path(cmd, decoded_path) < 0) {
    int xerrno = EACCES;

    pr_response_add_err(R_550, "%s: %s", path, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (strlen(timestamp) < 14) {
    int xerrno = EINVAL;

    pr_response_add_err(R_501, "%s: %s", timestamp, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  ptr = strchr(timestamp, '.');
  if (ptr) {
    pr_log_debug(DEBUG7, MOD_FACTS_VERSION
      ": %s: ignoring unsupported timestamp precision in '%s'",
      (char *) cmd->argv[0], timestamp);
    *ptr = '\0';
  }

  res = facts_modify_mtime(cmd->tmp_pool, decoded_path, timestamp);
  if (res < 0) {
    int xerrno = errno;

    if (ptr) {
      *ptr = '.';
    }

    pr_response_add_err(xerrno == ENOENT ? R_550 : R_501, "%s: %s", path,
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* We need to capitalize the 'modify' fact name in the response, as
   * per the Draft, so that clients can parse it to see the actual
   * time used by the server; it is possible for the server to ignore some
   * of the precision requested by the client.
   *
   * This same requirement means that the string is NOT localisable.
   */
  pr_response_add(R_213, "Modify=%s; %s", timestamp, path);

  if (ptr) {
    *ptr = '.';
  }

  return PR_HANDLED(cmd);
}

MODRET facts_mlsd(cmd_rec *cmd) {
  const char *path, *decoded_path, *best_path;
  const char *fake_user = NULL, *fake_group = NULL;
  config_rec *c;
  uid_t fake_uid = -1;
  gid_t fake_gid = -1;
  mode_t *fake_mode = NULL;
  struct mlinfo info;
  unsigned char *ptr;
  int flags = 0;
  DIR *dirh;
  struct dirent *dent;

  if (cmd->argc != 1) {
    path = pstrdup(cmd->tmp_pool, cmd->arg);

    decoded_path = pr_fs_decode_path2(cmd->tmp_pool, path,
      FSIO_DECODE_FL_TELL_ERRORS);
    if (decoded_path == NULL) {
      int xerrno = errno;

      pr_log_debug(DEBUG8, "'%s' failed to decode properly: %s", path,
        strerror(xerrno));
      pr_response_add_err(R_550,
        _("%s: Illegal character sequence in filename"), path);

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

  } else {
    decoded_path = path = pr_fs_getcwd();
  }

  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, (char *) decoded_path, NULL)) {
    pr_log_debug(DEBUG4, MOD_FACTS_VERSION ": %s command denied by <Limit>",
      (char *) cmd->argv[0]);
    pr_response_add_err(R_550, _("Unable to handle command"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* RFC3659 explicitly does NOT support glob characters.  So warn about
   * this, but let the command continue as is.  We don't actually call
   * glob(3) here, so no expansion will occur.
   */
  if (strpbrk(decoded_path, "{[*?") != NULL) {
    pr_log_debug(DEBUG9, MOD_FACTS_VERSION ": glob characters in MLSD ('%s') "
      "ignored", decoded_path);
  }

  /* Make sure that the given path is actually a directory. */
  if (pr_fsio_stat(decoded_path, &(info.st)) < 0) {
    int xerrno = errno;

    pr_log_debug(DEBUG4, MOD_FACTS_VERSION ": unable to stat '%s' (%s), "
      "denying %s", decoded_path, strerror(xerrno), (char *) cmd->argv[0]);

    pr_response_add_err(R_550, "%s: %s", path, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (!S_ISDIR(info.st.st_mode)) {
    pr_response_add_err(R_550, _("'%s' is not a directory"), path);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* Determine whether to display symlinks as such. */
  ptr = get_param_ptr(TOPLEVEL_CONF, "ShowSymlinks", FALSE);
  if (ptr != NULL) {
    if (*ptr == TRUE) {
      flags |= FACTS_MLINFO_FL_SHOW_SYMLINKS;

      if (facts_mlinfo_opts & FACTS_MLINFO_FL_SHOW_SYMLINKS_USE_SLINK) {
        flags |= FACTS_MLINFO_FL_SHOW_SYMLINKS_USE_SLINK;
      }
    }

  } else {
    /* ShowSymlinks is documented as being 'on' by default. */
    flags |= FACTS_MLINFO_FL_SHOW_SYMLINKS;

    if (facts_mlinfo_opts & FACTS_MLINFO_FL_SHOW_SYMLINKS_USE_SLINK) {
      flags |= FACTS_MLINFO_FL_SHOW_SYMLINKS_USE_SLINK;
    }
  }

  best_path = dir_best_path(cmd->tmp_pool, decoded_path);

  fake_mode = get_param_ptr(get_dir_ctxt(cmd->tmp_pool, (char *) best_path),
    "DirFakeMode", FALSE);
 
  c = find_config(get_dir_ctxt(cmd->tmp_pool, (char *) best_path), CONF_PARAM,
    "DirFakeUser", FALSE);
  if (c) {
    if (c->argc > 0) {
      fake_user = c->argv[0];
      if (fake_user != NULL &&
          strncmp(fake_user, "~", 2) != 0) {
        fake_uid = pr_auth_name2uid(cmd->tmp_pool, fake_user);

      } else {
        fake_uid = session.uid;
        fake_user = session.user;
      }

    } else {
      /* Handle the "DirFakeUser off" case (Bug#3715). */
      fake_uid = (uid_t) -1;
      fake_user = NULL;
    }
  }

  c = find_config(get_dir_ctxt(cmd->tmp_pool, (char *) best_path), CONF_PARAM,
    "DirFakeGroup", FALSE);
  if (c) {
    if (c->argc > 0) {
      fake_group = c->argv[0];
      if (fake_group != NULL &&
          strncmp(fake_group, "~", 2) != 0) {
        fake_gid = pr_auth_name2gid(cmd->tmp_pool, fake_group);

      } else {
        fake_gid = session.gid;
        fake_group = session.group;
      }

    } else {
      /* Handle the "DirFakeGroup off" case (Bug#3715). */
      fake_gid = (gid_t) -1;
      fake_group = NULL;
    }
  }

  dirh = pr_fsio_opendir(best_path);
  if (dirh == NULL) {
    int xerrno = errno;

    pr_trace_msg("fileperms", 1, "MLSD, user '%s' (UID %s, GID %s): "
      "error opening directory '%s': %s", session.user,
      pr_uid2str(cmd->tmp_pool, session.uid),
      pr_gid2str(cmd->tmp_pool, session.gid),
      best_path, strerror(xerrno));

    pr_response_add_err(R_550, "%s: %s", path, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* Open data connection */
  if (pr_data_open(NULL, C_MLSD, PR_NETIO_IO_WR, 0) < 0) {
    int xerrno = errno;

    pr_fsio_closedir(dirh);

    pr_response_add_err(R_550, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }
  session.sf_flags |= SF_ASCII_OVERRIDE;

  facts_mlinfobuf_init();

  while ((dent = pr_fsio_readdir(dirh)) != NULL) {
    int hidden = FALSE, res;
    char *rel_path, *abs_path;

    pr_signals_handle();

    rel_path = pdircat(cmd->tmp_pool, best_path, dent->d_name, NULL);
    res = dir_check(cmd->tmp_pool, cmd, cmd->group, rel_path, &hidden);
    if (!res || hidden) {
      continue;
    }

    /* Check that the file can be listed. */
    abs_path = dir_realpath(cmd->tmp_pool, rel_path);
    if (abs_path) {
      res = dir_check(cmd->tmp_pool, cmd, cmd->group, abs_path, &hidden);
      
    } else {
      abs_path = dir_canonical_path(cmd->tmp_pool, rel_path);
      if (abs_path == NULL) {
        abs_path = rel_path;
      }

      res = dir_check_canon(cmd->tmp_pool, cmd, cmd->group, abs_path, &hidden);
    }

    if (!res || hidden) {
      continue;
    }

    memset(&info, 0, sizeof(struct mlinfo));

    info.pool = make_sub_pool(cmd->tmp_pool);
    pr_pool_tag(info.pool, "MLSD facts pool");
    if (facts_mlinfo_get(&info, rel_path, dent->d_name, flags,
        fake_user, fake_uid, fake_group, fake_gid, fake_mode) < 0) {
      pr_log_debug(DEBUG3, MOD_FACTS_VERSION
        ": MLSD: unable to get info for '%s': %s", abs_path, strerror(errno));
      continue;
    }

    /* As per RFC3659, the directory being listed should not appear as a
     * component in the paths of the directory contents.
     */
    info.path = pr_fs_encode_path(info.pool, dent->d_name);

    facts_mlinfobuf_add(&info, FACTS_MLINFO_FL_APPEND_CRLF);

    destroy_pool(info.pool);
    info.pool = NULL;

    if (XFER_ABORTED) {
      pr_data_abort(0, 0);
      break;
    }
  }

  pr_fsio_closedir(dirh);

  if (XFER_ABORTED) {
    pr_data_close(TRUE);

  } else {
    facts_mlinfobuf_flush();
    pr_data_close(FALSE);
  }

  return PR_HANDLED(cmd);
}

MODRET facts_mlsd_cleanup(cmd_rec *cmd) {
  const char *proto;

  proto = pr_session_get_protocol(0);

  /* Ignore this for SFTP connections. */
  if (strncmp(proto, "sftp", 5) == 0) {
    return PR_DECLINED(cmd);
  }

  if (session.xfer.p) {
    destroy_pool(session.xfer.p);
  }

  memset(&session.xfer, '\0', sizeof(session.xfer));
  return PR_DECLINED(cmd);
}

MODRET facts_mlst(cmd_rec *cmd) {
  int flags = 0, hidden = FALSE;
  config_rec *c;
  uid_t fake_uid = -1;
  gid_t fake_gid = -1;
  mode_t *fake_mode = NULL;
  unsigned char *ptr;
  const char *path, *decoded_path;
  const char *fake_user = NULL, *fake_group = NULL;
  struct mlinfo info;

  if (cmd->argc != 1) {
    path = pstrdup(cmd->tmp_pool, cmd->arg);

    decoded_path = pr_fs_decode_path2(cmd->tmp_pool, path,
      FSIO_DECODE_FL_TELL_ERRORS);
    if (decoded_path == NULL) {
      int xerrno = errno;

      pr_log_debug(DEBUG8, "'%s' failed to decode properly: %s", path,
        strerror(xerrno));
      pr_response_add_err(R_550,
        _("%s: Illegal character sequence in filename"), path);

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

  } else {
    decoded_path = path = pr_fs_getcwd();
  }

  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, (char *) decoded_path,
      &hidden)) {
    pr_log_debug(DEBUG4, MOD_FACTS_VERSION ": %s command denied by <Limit>",
      (char *) cmd->argv[0]);
    pr_response_add_err(R_550, _("Unable to handle command"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  if (hidden) {
    /* Simply send an empty list, much like we do for a STAT command for
     * a hidden file.
     */
    pr_response_add(R_250, _("Start of list for %s"), path);
    pr_response_add(R_250, _("End of list"));

    return PR_HANDLED(cmd);
  }

  /* Determine whether to display symlinks as such. */
  ptr = get_param_ptr(TOPLEVEL_CONF, "ShowSymlinks", FALSE);
  if (ptr &&
      *ptr == TRUE) {
    flags |= FACTS_MLINFO_FL_SHOW_SYMLINKS;

    if (facts_mlinfo_opts & FACTS_MLINFO_FL_SHOW_SYMLINKS_USE_SLINK) {
      flags |= FACTS_MLINFO_FL_SHOW_SYMLINKS_USE_SLINK;
    }
  }

  fake_mode = get_param_ptr(get_dir_ctxt(cmd->tmp_pool, (char *) decoded_path),
    "DirFakeMode", FALSE);

  c = find_config(get_dir_ctxt(cmd->tmp_pool, (char *) decoded_path),
    CONF_PARAM, "DirFakeUser", FALSE);
  if (c) {
    if (c->argc > 0) {
      fake_user = c->argv[0];
      if (fake_user != NULL &&
          strncmp(fake_user, "~", 2) != 0) {
        fake_uid = pr_auth_name2uid(cmd->tmp_pool, fake_user);

      } else {
        fake_uid = session.uid;
        fake_user = session.user;
      }

    } else {
      /* Handle the "DirFakeUser off" case (Bug#3715). */
      fake_uid = (uid_t) -1;
      fake_user = NULL;
    }
  }

  c = find_config(get_dir_ctxt(cmd->tmp_pool, (char *) decoded_path),
    CONF_PARAM, "DirFakeGroup", FALSE);
  if (c) {
    if (c->argc > 0) {
      fake_group = c->argv[0];
      if (fake_group != NULL &&
          strncmp(fake_group, "~", 2) != 0) {
        fake_gid = pr_auth_name2gid(cmd->tmp_pool, fake_group);

      } else {
        fake_gid = session.gid;
        fake_group = session.group;
      }

    } else {
      /* Handle the "DirFakeGroup off" case (Bug#3715). */
      fake_gid = (gid_t) -1;
      fake_group = NULL;
    }
  }

  info.pool = cmd->tmp_pool;

  /* Since this is an MLST command, we are not listing the contents of
   * of a directory, we're only showing the entry for a path, whether
   * directory or not.  Thus the "cdir" type fact should not be used
   * (Bug#4198).
   */
  flags |= FACTS_MLINFO_FL_NO_CDIR;

  pr_fs_clear_cache2(decoded_path);
  if (facts_mlinfo_get(&info, decoded_path, decoded_path, flags,
      fake_user, fake_uid, fake_group, fake_gid, fake_mode) < 0) {
    pr_response_add_err(R_550, _("'%s' cannot be listed"), path);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* No need to re-encode the path here as UTF8, since 'path' is the
   * original parameter as sent by the client.
   *
   * However, as per RFC3659 Section 7.3.1, since we advertise TVFS in our
   * FEAT output, the path here should be the full path (as seen by the
   * client).
   */

  /* XXX What about chroots? */

  if (flags & FACTS_MLINFO_FL_SHOW_SYMLINKS) {
    if (flags & FACTS_MLINFO_FL_SHOW_SYMLINKS_USE_SLINK) {
      info.path = dir_canonical_path(cmd->tmp_pool, path);

    } else {
      /* If we are supposed to show symlinks, then use dir_best_path() to get
       * the full path, including dereferencing the symlink.
       */
      info.path = dir_best_path(cmd->tmp_pool, path);
    }

  } else {
    info.path = dir_canonical_path(cmd->tmp_pool, path);
  }

  pr_response_add(R_250, _("Start of list for %s"), path);
  facts_mlinfo_add(&info, 0);
  pr_response_add(R_250, _("End of list"));

  return PR_HANDLED(cmd);
}

MODRET facts_opts_mlst(cmd_rec *cmd) {
  register unsigned int i;
  char *method, *facts, *ptr, *resp_str = "";

  method = pstrdup(cmd->tmp_pool, cmd->argv[0]);

  /* Convert underscores to spaces in the method name, for prettier logging. */
  for (i = 0; method[i]; i++) {
    if (method[i] == '_') {
      method[i] = ' ';
    }
  }

  if (cmd->argc > 2) {
    pr_response_add_err(R_501, _("'%s' not understood"), method);

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  if (cmd->argc == 1) {
    facts_opts = 0;

    /* Update MLST FEAT listing to match the showing of no facts. */
    facts_mlst_feat_remove();
    facts_mlst_feat_add(cmd->tmp_pool);

    /* This response is mandated by RFC3659, therefore it is not
     * localisable.
     */
    pr_response_add(R_200, "%s", "MLST OPTS");
    return PR_HANDLED(cmd);
  }

  /* Do not show any facts by default at this point; the processing of the
   * facts requested by the client will enable just the ones the client
   * wishes to receive.
   */
  facts_opts = 0;
  facts_mlst_feat_remove();

  facts = cmd->argv[1];
  ptr = strchr(facts, ';');

  while (ptr) {
    pr_signals_handle();

    *ptr = '\0';

    if (strcasecmp(facts, "modify") == 0) {
      facts_opts |= FACTS_OPT_SHOW_MODIFY;
      resp_str = pstrcat(cmd->tmp_pool, resp_str, "modify;", NULL);

    } else if (strcasecmp(facts, "perm") == 0) {
      facts_opts |= FACTS_OPT_SHOW_PERM;
      resp_str = pstrcat(cmd->tmp_pool, resp_str, "perm;", NULL);

    } else if (strcasecmp(facts, "size") == 0) {
      facts_opts |= FACTS_OPT_SHOW_SIZE;
      resp_str = pstrcat(cmd->tmp_pool, resp_str, "size;", NULL);

    } else if (strcasecmp(facts, "type") == 0) {
      facts_opts |= FACTS_OPT_SHOW_TYPE;
      resp_str = pstrcat(cmd->tmp_pool, resp_str, "type;", NULL);

    } else if (strcasecmp(facts, "unique") == 0) {
      facts_opts |= FACTS_OPT_SHOW_UNIQUE;
      resp_str = pstrcat(cmd->tmp_pool, resp_str, "unique;", NULL);

    } else if (strcasecmp(facts, "UNIX.group") == 0) {
      facts_opts |= FACTS_OPT_SHOW_UNIX_GROUP;
      resp_str = pstrcat(cmd->tmp_pool, resp_str, "UNIX.group;", NULL);

    } else if (strcasecmp(facts, "UNIX.groupname") == 0) {
      facts_opts |= FACTS_OPT_SHOW_UNIX_GROUP_NAME;
      resp_str = pstrcat(cmd->tmp_pool, resp_str, "UNIX.groupname;", NULL);

    } else if (strcasecmp(facts, "UNIX.mode") == 0) {
      facts_opts |= FACTS_OPT_SHOW_UNIX_MODE;
      resp_str = pstrcat(cmd->tmp_pool, resp_str, "UNIX.mode;", NULL);

    } else if (strcasecmp(facts, "UNIX.owner") == 0) {
      facts_opts |= FACTS_OPT_SHOW_UNIX_OWNER;
      resp_str = pstrcat(cmd->tmp_pool, resp_str, "UNIX.owner;", NULL);

    } else if (strcasecmp(facts, "UNIX.ownername") == 0) {
      facts_opts |= FACTS_OPT_SHOW_UNIX_OWNER_NAME;
      resp_str = pstrcat(cmd->tmp_pool, resp_str, "UNIX.ownername;", NULL);

    } else if (strcasecmp(facts, "media-type") == 0) {
      facts_opts |= FACTS_OPT_SHOW_MEDIA_TYPE;
      resp_str = pstrcat(cmd->tmp_pool, resp_str, "media-type;", NULL);

    } else {
      pr_log_debug(DEBUG3, MOD_FACTS_VERSION
        ": %s: client requested unsupported fact '%s'", method, facts);
    }

    *ptr = ';';
    facts = ptr + 1;
    ptr = strchr(facts, ';');
  }

  facts_mlst_feat_add(cmd->tmp_pool);

  /* This response is mandated by RFC3659, therefore it is not localisable. */
  pr_response_add(R_200, "MLST OPTS %s", resp_str);
  return PR_HANDLED(cmd);
}

/* Configuration handlers
 */

/* usage: FactsAdvertise on|off */
MODRET set_factsadvertise(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: FactsOptions opt1 ... optN */
MODRET set_factsoptions(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "UseSlink") == 0) {
      opts |= FACTS_MLINFO_FL_SHOW_SYMLINKS_USE_SLINK;

    } else if (strcmp(cmd->argv[i], "AdjustedSymlinks") == 0) {
      opts |= FACTS_MLINFO_FL_ADJUSTED_SYMLINKS;

    } else if (strcmp(cmd->argv[i], "NoAdjustedSymlinks") == 0) {
      /* Ignore; retained for backward compatibility. */

    } else if (strcmp(cmd->argv[i], "NoNames") == 0) {
      opts |= FACTS_MLINFO_FL_NO_NAMES;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown FactsOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* Event listeners
 */

static void facts_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&facts_module, "core.session-reinit",
    facts_sess_reinit_ev);

  facts_opts = 0;
  facts_mlinfo_opts = 0;

  pr_feat_remove("MFF modify;UNIX.group;UNIX.mode;");
  pr_feat_remove("MFMT");
  pr_feat_remove("TVFS");
  facts_mlst_feat_remove();

  res = facts_sess_init();
  if (res < 0) {
    pr_session_disconnect(&facts_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Initialization functions
 */

static int facts_init(void) {
  pr_help_add(C_MLSD, _("[<sp> pathname]"), TRUE);
  pr_help_add(C_MLST, _("[<sp> pathname]"), TRUE);

  return 0;
}

static int facts_sess_init(void) {
  config_rec *c;
  int advertise = TRUE;

  pr_event_register(&facts_module, "core.session-reinit",
    facts_sess_reinit_ev, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "FactsAdvertise", FALSE);
  if (c) {
    advertise = *((int *) c->argv[0]);
  }

  if (advertise == FALSE) {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "FactsOptions", FALSE);
  while (c != NULL) {
    unsigned long opts;

    pr_signals_handle();
  
    opts = *((unsigned long *) c->argv[0]);
    facts_mlinfo_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "FactsOptions", FALSE);
  }

  facts_opts = FACTS_OPT_SHOW_MODIFY|FACTS_OPT_SHOW_PERM|FACTS_OPT_SHOW_SIZE|
    FACTS_OPT_SHOW_TYPE|FACTS_OPT_SHOW_UNIQUE|
    FACTS_OPT_SHOW_UNIX_GROUP|FACTS_OPT_SHOW_UNIX_GROUP_NAME|
    FACTS_OPT_SHOW_UNIX_MODE|FACTS_OPT_SHOW_UNIX_OWNER|
    FACTS_OPT_SHOW_UNIX_OWNER_NAME;

  if (pr_module_exists("mod_mime.c") == TRUE) {
    /* Check to see if MIMEEngine is enabled.  Yes, this is slightly
     * naughty, looking at some other module's configuration directives,
     * but for compliance with RFC 3659, specifically for implementing the
     * "media-type" fact for MLSx commands, we need to do this.
     */
    c = find_config(main_server->conf, CONF_PARAM, "MIMEEngine", FALSE);
    if (c != NULL) {
      int engine;

      engine = *((int *) c->argv[0]);
      if (engine == TRUE) {
        facts_opts |= FACTS_OPT_SHOW_MEDIA_TYPE;
      }
    }
  }

  pr_feat_add("MFF modify;UNIX.group;UNIX.mode;");
  pr_feat_add("MFMT");
  pr_feat_add("TVFS");

  facts_mlst_feat_add(session.pool);

  return 0;
}

/* Module API tables
 */

static conftable facts_conftab[] = {
  { "FactsAdvertise",	set_factsadvertise,	NULL },
  { "FactsOptions",	set_factsoptions,	NULL },
  { NULL }
};

static cmdtable facts_cmdtab[] = {
  { CMD,	C_MFF,		G_WRITE,facts_mff,  TRUE, FALSE, CL_WRITE },
  { CMD,	C_MFMT,		G_WRITE,facts_mfmt, TRUE, FALSE, CL_WRITE },
  { CMD,	C_MLSD,		G_DIRS,	facts_mlsd, TRUE, FALSE, CL_DIRS },
  { LOG_CMD,	C_MLSD,		G_NONE,	facts_mlsd_cleanup, FALSE, FALSE },
  { LOG_CMD_ERR,C_MLSD,		G_NONE,	facts_mlsd_cleanup, FALSE, FALSE },
  { CMD,	C_MLST,		G_DIRS,	facts_mlst, TRUE, FALSE, CL_DIRS },
  { CMD,	C_OPTS "_MLST", G_NONE, facts_opts_mlst, FALSE, FALSE },
  { 0, NULL }
};

module facts_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "facts",

  /* Module configuration handler table */
  facts_conftab,

  /* Module command handler table */
  facts_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  facts_init,

  /* Session initialization function */
  facts_sess_init,

  /* Module version */
  MOD_FACTS_VERSION
};
