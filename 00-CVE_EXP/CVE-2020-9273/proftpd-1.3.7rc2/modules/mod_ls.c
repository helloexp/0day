/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2019 The ProFTPD Project
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
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* Directory listing module for ProFTPD. */

#include "conf.h"

#ifndef GLOB_ABORTED
#define GLOB_ABORTED GLOB_ABEND
#endif

#define MAP_UID(x) \
  (fakeuser ? fakeuser : pr_auth_uid2name(cmd->tmp_pool, (x)))

#define MAP_GID(x) \
  (fakegroup ? fakegroup : pr_auth_gid2name(cmd->tmp_pool, (x)))

static void addfile(cmd_rec *, const char *, const char *, time_t, off_t);
static int outputfiles(cmd_rec *);

static int listfile(cmd_rec *, pool *, const char *, const char *);
static int listdir(cmd_rec *, pool *, const char *, const char *);

static int sendline(int flags, char *fmt, ...)
#ifdef __GNUC__
       __attribute__ ((format (printf, 2, 3)));
#else
       ;
#endif
#define LS_SENDLINE_FL_FLUSH	0x0001

#define LS_FL_NO_ERROR_IF_ABSENT	0x0001
#define LS_FL_LIST_ONLY			0x0002
#define LS_FL_NLST_ONLY			0x0004
#define LS_FL_ADJUSTED_SYMLINKS		0x0008
#define LS_FL_SORTED_NLST		0x0010
static unsigned long list_flags = 0UL;

/* Maximum size of the "dsize" directory block we'll allocate for all of the
 * entries in a directory (Bug#4247).
 */
#define LS_MAX_DSIZE			(1024 * 1024 * 8)

static unsigned char list_strict_opts = FALSE;
static char *list_options = NULL;
static unsigned char list_show_symlinks = TRUE, list_times_gmt = TRUE;
static unsigned char show_symlinks_hold;
static const char *fakeuser = NULL, *fakegroup = NULL;
static mode_t fakemode;
static unsigned char have_fake_mode = FALSE;
static int ls_errno = 0;
static time_t ls_curtime = 0;

static unsigned char use_globbing = TRUE;

/* Directory listing limits */
struct list_limit_rec {
  unsigned int curr, max;
  unsigned char logged;
};

static struct list_limit_rec list_ndepth;
static struct list_limit_rec list_ndirs;
static struct list_limit_rec list_nfiles;

/* ls options */
static int
    opt_1 = 0,
    opt_a = 0,
    opt_A = 0,
    opt_B = 0,
    opt_C = 0,
    opt_c = 0,
    opt_d = 0,
    opt_F = 0,
    opt_h = 0,
    opt_l = 0,
    opt_L = 0,
    opt_n = 0,
    opt_R = 0,
    opt_r = 0,
    opt_S = 0,
    opt_t = 0,
    opt_U = 0,
    opt_u = 0,
    opt_STAT = 0;

/* Determines which struct st timestamp is used for sorting, if any. */
static int ls_sort_by = 0;
#define LS_SORT_BY_MTIME	100
#define LS_SORT_BY_CTIME	101
#define LS_SORT_BY_ATIME	102

static char cwd[PR_TUNABLE_PATH_MAX+1] = "";

/* Find a <Limit> block that limits the given command (which will probably
 * be LIST).  This code borrowed for src/dirtree.c's dir_check_limit().
 * Note that this function is targeted specifically for ls commands (eg
 * LIST, NLST, DIRS, and ALL) that might be <Limit>'ed.
 */
static config_rec *find_ls_limit(char *cmd_name) {
  config_rec *c = NULL, *limit_c = NULL;

  if (!cmd_name)
    return NULL;

  if (!session.dir_config)
    return NULL;

  /* Determine whether this command is <Limit>'ed. */
  for (c = session.dir_config; c; c = c->parent) {
    pr_signals_handle();

    if (c->subset) {
      for (limit_c = (config_rec *) (c->subset->xas_list); limit_c;
          limit_c = limit_c->next) {

        if (limit_c->config_type == CONF_LIMIT) {
          register unsigned int i = 0;

          for (i = 0; i < limit_c->argc; i++) {

            /* match any of the appropriate <Limit> arguments
             */
            if (strcasecmp(cmd_name, (char *) (limit_c->argv[i])) == 0 ||
                strcasecmp("DIRS", (char *) (limit_c->argv[i])) == 0 ||
                strcasecmp("ALL", (char *) (limit_c->argv[i])) == 0) {
              break;
            }
          }

          if (i == limit_c->argc)
            continue;

          /* Found a <Limit> directive associated with the current command. */
          return limit_c;
        }
      }
    }
  }

  return NULL;
}

static int is_safe_symlink(pool *p, const char *path, size_t pathlen) {

  /* First, check the most common cases: '.', './', '..', and '../'. */
  if ((pathlen == 1 && path[0] == '.') ||
      (pathlen == 2 && path[0] == '.' && (path[1] == '.' || path[1] == '/')) ||
      (pathlen == 3 && path[0] == '.' && path[1] == '.' && path[2] == '/')) {
    return FALSE;
  }

  /* Next, paranoidly check for uncommon occurrences, e.g. './///', '../////',
   * etc.
   */
  if (pathlen >= 2 &&
      path[0] == '.' &&
      (path[pathlen-1] == '/' || path[pathlen-1] == '.')) {
    char buf[PR_TUNABLE_PATH_MAX + 1], *full_path;
    size_t buflen;

    full_path = pdircat(p, pr_fs_getcwd(), path, NULL);

    buf[sizeof(buf)-1] = '\0';
    pr_fs_clean_path(full_path, buf, sizeof(buf)-1);
    buflen = strlen(buf);

    /* If the cleaned path appears in the current working directory, we
     * have an "unsafe" symlink pointing to the current directory (or higher
     * up the path).
     */
    if (strncmp(pr_fs_getcwd(), buf, buflen) == 0) {
      return FALSE;
    }
  }

  return TRUE;
}

static void push_cwd(char *_cwd, unsigned char *symhold) {
  if (!_cwd)
    _cwd = cwd;

  *symhold = show_symlinks_hold;
  sstrncpy(_cwd, pr_fs_getcwd(), PR_TUNABLE_PATH_MAX + 1);
  *symhold = list_show_symlinks;
}

static void pop_cwd(char *_cwd, unsigned char *symhold) {
  if (!_cwd)
    _cwd = cwd;

  *symhold = show_symlinks_hold;
  pr_fsio_chdir(_cwd, *symhold);
  list_show_symlinks = *symhold;
}

static int ls_perms_full(pool *p, cmd_rec *cmd, const char *path, int *hidden) {
  int res, use_canon = FALSE;
  char *fullpath;
  mode_t *fake_mode = NULL;

  fullpath = dir_realpath(p, path);
  if (fullpath == NULL) {
    fullpath = dir_canonical_path(p, path);
    use_canon = TRUE;
  }

  if (fullpath == NULL) {
    fullpath = pstrdup(p, path);
  }
 
  if (use_canon) {
    res = dir_check_canon(p, cmd, cmd->group, fullpath, hidden);

  } else {
    res = dir_check(p, cmd, cmd->group, fullpath, hidden);
  }

  if (session.dir_config) {
    unsigned char *tmp = get_param_ptr(session.dir_config->subset,
      "ShowSymlinks", FALSE);

    if (tmp)
      list_show_symlinks = *tmp;
  }

  fake_mode = get_param_ptr(CURRENT_CONF, "DirFakeMode", FALSE);
  if (fake_mode) {
    fakemode = *fake_mode;
    have_fake_mode = TRUE;

  } else {
    have_fake_mode = FALSE;
  }

  return res;
}

static int ls_perms(pool *p, cmd_rec *cmd, const char *path, int *hidden) {
  int res = 0;
  char fullpath[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
  mode_t *fake_mode = NULL;

  /* No need to process dotdirs. */
  if (is_dotdir(path)) {
    return 1;
  }

  if (*path == '~') {
    return ls_perms_full(p, cmd, path, hidden);
  }

  if (*path != '/') {
    pr_fs_clean_path(pdircat(p, pr_fs_getcwd(), path, NULL), fullpath,
      PR_TUNABLE_PATH_MAX);

  } else {
    pr_fs_clean_path(path, fullpath, PR_TUNABLE_PATH_MAX);
  }

  res = dir_check(p, cmd, cmd->group, fullpath, hidden);

  if (session.dir_config) {
    unsigned char *tmp = get_param_ptr(session.dir_config->subset,
      "ShowSymlinks", FALSE);

    if (tmp)
      list_show_symlinks = *tmp;
  }

  fake_mode = get_param_ptr(CURRENT_CONF, "DirFakeMode", FALSE);
  if (fake_mode) {
    fakemode = *fake_mode;
    have_fake_mode = TRUE;

  } else {
    have_fake_mode = FALSE;
  }

  return res;
}

/* sendline() now has an internal buffer, to help speed up LIST output.
 * This buffer is allocated once, the first time sendline() is called.
 * By using a runtime allocation, we can use pr_config_get_server_xfer_bufsz()
 * to get the optimal buffer size for network transfers.
 */
static char *listbuf = NULL, *listbuf_ptr = NULL;
static size_t listbufsz = 0;

static int sendline(int flags, char *fmt, ...) {
  va_list msg;
  char buf[PR_TUNABLE_BUFFER_SIZE+1];
  int res = 0;
  size_t buflen, listbuflen;

  memset(buf, '\0', sizeof(buf));

  if (listbuf == NULL) {
    listbufsz = pr_config_get_server_xfer_bufsz(PR_NETIO_IO_WR);
    listbuf = listbuf_ptr = pcalloc(session.pool, listbufsz);
    pr_trace_msg("data", 8, "allocated list buffer of %lu bytes",
      (unsigned long) listbufsz);
  }

  if (flags & LS_SENDLINE_FL_FLUSH) {
    listbuflen = (listbuf_ptr - listbuf) + strlen(listbuf_ptr);

    if (listbuflen > 0) {
      int using_ascii = FALSE;

      /* Make sure the ASCII flags are cleared from the session flags,
       * so that the pr_data_xfer() function does not try to perform
       * ASCII translation on this data.
       */
      if (session.sf_flags & SF_ASCII) {
        using_ascii = TRUE;
      }

      session.sf_flags &= ~SF_ASCII;
      session.sf_flags &= ~SF_ASCII_OVERRIDE;

      res = pr_data_xfer(listbuf, listbuflen);
      if (res < 0 &&
          errno != 0) {
        int xerrno = errno;

        if (session.d != NULL) {
          xerrno = PR_NETIO_ERRNO(session.d->outstrm);
        }

        pr_log_debug(DEBUG3, "pr_data_xfer returned %d, error = %s", res,
          strerror(xerrno));
      }

      if (using_ascii) {
        session.sf_flags |= SF_ASCII;
      }
      session.sf_flags |= SF_ASCII_OVERRIDE;

      memset(listbuf, '\0', listbufsz);
      listbuf_ptr = listbuf;
      pr_trace_msg("data", 8, "flushed %lu bytes of list buffer",
        (unsigned long) listbuflen);
      listbuflen = 0;
    }

    return res;
  }

  va_start(msg, fmt);
  pr_vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  buf[sizeof(buf)-1] = '\0';

  /* If buf won't fit completely into listbuf, flush listbuf */
  listbuflen = (listbuf_ptr - listbuf) + strlen(listbuf_ptr);

  buflen = strlen(buf);
  if (buflen >= (listbufsz - listbuflen)) {
    /* Make sure the ASCII flags are cleared from the session flags,
     * so that the pr_data_xfer() function does not try to perform
     * ASCII translation on this data.
     */
    session.sf_flags &= ~SF_ASCII_OVERRIDE;

    res = pr_data_xfer(listbuf, listbuflen);
    if (res < 0 &&
        errno != 0) {
      int xerrno = errno;

      if (session.d != NULL &&
          session.d->outstrm) {
        xerrno = PR_NETIO_ERRNO(session.d->outstrm);
      }

      pr_log_debug(DEBUG3, "pr_data_xfer returned %d, error = %s", res,
        strerror(xerrno));
    }

    session.sf_flags |= SF_ASCII_OVERRIDE;

    memset(listbuf, '\0', listbufsz);
    listbuf_ptr = listbuf;
    pr_trace_msg("data", 8, "flushed %lu bytes of list buffer",
      (unsigned long) listbuflen);
    listbuflen = 0;
  }

  sstrcat(listbuf_ptr, buf, listbufsz - listbuflen);
  listbuf_ptr += buflen;

  return res;
}

static void ls_done(cmd_rec *cmd) {
  int quiet = FALSE;

  if (session.sf_flags & SF_ABORT) {
    quiet = TRUE;
  }

  pr_data_close(quiet);
}

static char units[6][2] = 
  { "", "k", "M", "G", "T", "P" };

static void ls_fmt_filesize(char *buf, size_t buflen, off_t sz) {
  if (!opt_h || sz < 1000) {
    pr_snprintf(buf, buflen, "%8" PR_LU, (pr_off_t) sz);

  } else {
    register unsigned int i = 0;
    float size = sz;

    /* Determine the appropriate units label to use. */
    while (size >= 1024.0) {
      size /= 1024.0;
      i++;
    }

    pr_snprintf(buf, buflen, "%7.1f%s", size, units[i]);
  }
}

static char months[12][4] =
  { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

static int listfile(cmd_rec *cmd, pool *p, const char *resp_code,
    const char *name) {
  register unsigned int i;
  int rval = 0, len;
  time_t sort_time;
  char m[PR_TUNABLE_PATH_MAX+1] = {'\0'}, l[PR_TUNABLE_PATH_MAX+1] = {'\0'}, s[16] = {'\0'};
  struct stat st;
  struct tm *t = NULL;
  char suffix[2];
  int hidden = 0;
  char *filename, *ptr;
  size_t namelen;

  /* Note that listfile() expects to be given the file name, NOT the path.
   * So strip off any path elements, watching out for any trailing slashes
   * (Bug#4259).
   */
  namelen = strlen(name);
  for (i = namelen-1; i > 0; i--) {
    if (name[i] != '/') {
      break;
    }

    namelen--;
  }

  filename = pstrndup(p, name, namelen);

  ptr = strrchr(filename, '/');
  if (ptr != NULL) {
    /* Advance past that path separator to get just the filename. */
    filename = ptr + 1;
  }

  if (list_nfiles.curr && list_nfiles.max &&
      list_nfiles.curr >= list_nfiles.max) {

    if (!list_nfiles.logged) {
      pr_log_debug(DEBUG8, "ListOptions maxfiles (%u) reached",
        list_nfiles.max);
      list_nfiles.logged = TRUE;
    }
 
    return 2;
  }
  list_nfiles.curr++;

  if (p == NULL) {
    p = cmd->tmp_pool;
  }

  pr_fs_clear_cache2(name);
  if (pr_fsio_lstat(name, &st) == 0) {
    char *display_name = NULL;

    suffix[0] = suffix[1] = '\0';

    display_name = pstrdup(p, name);

#ifndef PR_USE_NLS
    if (opt_B) {
      register unsigned int j;
      size_t display_namelen, printable_namelen;
      char *printable_name = NULL;

      display_namelen = strlen(display_name);

      /* Allocate 4 times as much space as necessary, in case every single
       * character is non-printable.
       */
      printable_namelen = (display_namelen * 4);
      printable_name = pcalloc(p, printable_namelen + 1);

      /* Check for any non-printable characters, and replace them with the
       * octal escape sequence equivalent.
       */
      for (i = 0, j = 0; i < display_namelen && j < printable_namelen; i++) {
        if (!PR_ISPRINT(display_name[i])) {
          register int k;
          int replace_len = 0;
          char replace[32];

          memset(replace, '\0', sizeof(replace));
          replace_len = pr_snprintf(replace, sizeof(replace)-1, "\\%03o",
            display_name[i]);

          for (k = 0; k < replace_len; k++) {
            printable_name[j++] = replace[k];
          }

        } else {
          printable_name[j++] = display_name[i];
        }
      }

      display_name = pstrdup(p, printable_name);
    }
#endif /* PR_USE_NLS */

    if (S_ISLNK(st.st_mode) &&
        (opt_L || !list_show_symlinks)) {
      /* Attempt to fully dereference symlink */
      struct stat l_st;

      if (pr_fsio_stat(name, &l_st) != -1) {
        memcpy(&st, &l_st, sizeof(struct stat));

        /* First see if the symlink itself is hidden e.g. by HideFiles
         * (see Bug#3924).
         */
        if (!ls_perms_full(p, cmd, name, &hidden)) {
          return 0;
        }

        if (hidden) {
          return 0;
        }

        if (list_flags & LS_FL_ADJUSTED_SYMLINKS) {
          len = dir_readlink(p, name, m, sizeof(m) - 1,
            PR_DIR_READLINK_FL_HANDLE_REL_PATH);

        } else {
          len = pr_fsio_readlink(name, m, sizeof(m) - 1);
        }

        if (len < 0) {
          return 0;
        }

        if ((size_t) len >= sizeof(m)) {
          return 0;
        }

        m[len] = '\0';

        /* If the symlink points to either '.' or '..', skip it (Bug#3719). */
        if (is_safe_symlink(p, m, len) == FALSE) {
          return 0;
        }

        if (!ls_perms_full(p, cmd, m, NULL)) {
          return 0;
        }

      } else {
        return 0;
      }

    } else if (S_ISLNK(st.st_mode)) {
      /* First see if the symlink itself is hidden e.g. by HideFiles
       * (see Bug#3924).
       */
      if (!ls_perms(p, cmd, name, &hidden)) {
        return 0;
      }

      if (hidden) {
        return 0;
      }

      if (list_flags & LS_FL_ADJUSTED_SYMLINKS) {
        len = dir_readlink(p, name, l, sizeof(l) - 1,
          PR_DIR_READLINK_FL_HANDLE_REL_PATH);

      } else {
        len = pr_fsio_readlink(name, l, sizeof(l) - 1);
      }

      if (len < 0) {
        return 0;
      }

      if ((size_t) len >= sizeof(l)) {
        return 0;
      }

      l[len] = '\0';

      /* If the symlink points to either '.' or '..', skip it (Bug#3719). */
      if (is_safe_symlink(p, l, len) == FALSE) {
        return 0;
      }

      if (!ls_perms_full(p, cmd, l, &hidden)) {
        return 0;
      }

    } else if (!ls_perms(p, cmd, name, &hidden)) {
      return 0;
    }

    /* Skip dotfiles, unless requested not to via -a or -A. */
    if (*filename == '.' &&
        (!opt_a && (!opt_A || is_dotdir(filename)))) {
      pr_log_debug(DEBUG10,
        "skipping listing of hidden file '%s' (no -A/-a options in effect)",
        filename);
      return 0;
    }

    if (hidden) {
      return 0;
    }

    switch (ls_sort_by) {
      case LS_SORT_BY_MTIME:
        sort_time = st.st_mtime;
        break;

      case LS_SORT_BY_CTIME:
        sort_time = st.st_ctime;
        break;

      case LS_SORT_BY_ATIME:
        sort_time = st.st_atime;
        break;

      default:
        sort_time = st.st_mtime;
        break;
    }

    if (list_times_gmt) {
      t = pr_gmtime(p, (const time_t *) &sort_time);

    } else {
      t = pr_localtime(p, (const time_t *) &sort_time);
    }

    if (opt_F) {
      if (S_ISLNK(st.st_mode)) {
        suffix[0] = '@';

      } else if (S_ISDIR(st.st_mode)) {
        suffix[0] = '/';
        rval = 1;

      } else if (st.st_mode & 0111) {
        suffix[0] = '*';
      }
    }

    if (opt_l) {
      sstrncpy(m, " ---------", sizeof(m));
      switch (st.st_mode & S_IFMT) {
        case S_IFREG:
          m[0] = '-';
          break;

        case S_IFLNK:
          m[0] = 'l';
          break;

#ifdef S_IFSOCK
        case S_IFSOCK:
          m[0] = 's';
          break;
#endif /* S_IFSOCK */

        case S_IFBLK:
          m[0] = 'b';
          break;

        case S_IFCHR:
          m[0] = 'c';
          break;

        case S_IFIFO:
          m[0] = 'p';
          break;

        case S_IFDIR:
          m[0] = 'd';
          rval = 1;
          break;
      }

      if (m[0] != ' ') {
        char nameline[(PR_TUNABLE_PATH_MAX * 2) + 128] = {'\0'};
        char timeline[6] = {'\0'};
        mode_t mode = st.st_mode;

        if (have_fake_mode) {
          mode = fakemode;

          if (S_ISDIR(st.st_mode)) {
            if (mode & S_IROTH) mode |= S_IXOTH;
            if (mode & S_IRGRP) mode |= S_IXGRP;
            if (mode & S_IRUSR) mode |= S_IXUSR;
          }
        }

        m[9] = (mode & S_IXOTH)
                ? ((mode & S_ISVTX) ? 't' : 'x')
                : ((mode & S_ISVTX) ? 'T' : '-');
        m[8] = (mode & S_IWOTH) ? 'w' : '-';
        m[7] = (mode & S_IROTH) ? 'r' : '-';
        m[6] = (mode & S_IXGRP)
                ? ((mode & S_ISGID) ? 's' : 'x')
                : ((mode & S_ISGID) ? 'S' : '-');
        m[5] = (mode & S_IWGRP) ? 'w' : '-';
        m[4] = (mode & S_IRGRP) ? 'r' : '-';
        m[3] = (mode & S_IXUSR) ? ((mode & S_ISUID)
                ? 's' : 'x')
                :  ((mode & S_ISUID) ? 'S' : '-');
        m[2] = (mode & S_IWUSR) ? 'w' : '-';
        m[1] = (mode & S_IRUSR) ? 'r' : '-';

        if (ls_curtime - sort_time > 180 * 24 * 60 * 60) {
          pr_snprintf(timeline, sizeof(timeline), "%5d", t->tm_year+1900);

        } else {
          pr_snprintf(timeline, sizeof(timeline), "%02d:%02d", t->tm_hour,
            t->tm_min);
        }

        ls_fmt_filesize(s, sizeof(s), st.st_size);

        if (opt_1) {
          /* One file per line, with no info other than the file name.  Easy. */
          pr_snprintf(nameline, sizeof(nameline)-1, "%s",
            pr_fs_encode_path(cmd->tmp_pool, display_name));

        } else {
          if (!opt_n) {
            /* Format nameline using user/group names. */
            pr_snprintf(nameline, sizeof(nameline)-1,
              "%s %3d %-8s %-8s %s %s %2d %s %s", m, (int) st.st_nlink,
              MAP_UID(st.st_uid), MAP_GID(st.st_gid), s,
              months[t->tm_mon], t->tm_mday, timeline,
              pr_fs_encode_path(cmd->tmp_pool, display_name));

          } else {
            /* Format nameline using user/group IDs. */
            pr_snprintf(nameline, sizeof(nameline)-1,
              "%s %3d %-8u %-8u %s %s %2d %s %s", m, (int) st.st_nlink,
              (unsigned) st.st_uid, (unsigned) st.st_gid, s,
              months[t->tm_mon], t->tm_mday, timeline,
              pr_fs_encode_path(cmd->tmp_pool, name));
          }
        }

        nameline[sizeof(nameline)-1] = '\0';

        if (S_ISLNK(st.st_mode)) {
          char *buf = nameline + strlen(nameline);

          suffix[0] = '\0';
          if (opt_F) {
            if (pr_fsio_stat(name, &st) == 0) {
              if (S_ISLNK(st.st_mode)) {
                suffix[0] = '@';

              } else if (S_ISDIR(st.st_mode)) {
                suffix[0] = '/';

              } else if (st.st_mode & 0111) {
                suffix[0] = '*';
              }
           }
          }

          if (!opt_L && list_show_symlinks) {
            if (sizeof(nameline) - strlen(nameline) > 4) {
              pr_snprintf(buf, sizeof(nameline) - strlen(nameline) - 4,
                " -> %s", l);
            } else {
              pr_log_pri(PR_LOG_NOTICE, "notice: symlink '%s' yields an "
                "excessive string, ignoring", name);
            }
          }

          nameline[sizeof(nameline)-1] = '\0';
        }

        if (opt_STAT) {
          pr_response_add(resp_code, "%s%s", nameline, suffix);

        } else {
          addfile(cmd, nameline, suffix, sort_time, st.st_size);
        }
      }

    } else {
      if (S_ISREG(st.st_mode) ||
          S_ISDIR(st.st_mode) ||
          S_ISLNK(st.st_mode)) {
        addfile(cmd, pr_fs_encode_path(cmd->tmp_pool, name), suffix, sort_time,
          st.st_size);
      }
    }
  }

  return rval;
}

static size_t colwidth = 0;
static unsigned int filenames = 0;

struct filename {
  struct filename *down;
  struct filename *right;
  char *line;
  int top;
};

struct sort_filename {
  time_t sort_time;
  off_t size;
  char *name;
  char *suffix;
};

static struct filename *head = NULL;
static struct filename *tail = NULL;
static array_header *sort_arr = NULL;
static pool *fpool = NULL;

static void addfile(cmd_rec *cmd, const char *name, const char *suffix,
    time_t sort_time, off_t size) {
  struct filename *p;
  size_t l;

  if (name == NULL ||
      suffix == NULL) {
    return;
  }

  /* If we are not sorting (-U is in effect), then we have no need to buffer
   * up the line, and can send it immediately.  This can provide quite a bit
   * of memory/CPU savings, especially for LIST commands on wide/deep
   * directories (Bug#4060).
   */
  if (opt_U == 1) {
    (void) sendline(0, "%s%s\r\n", name, suffix);
    return;
  }

  if (fpool == NULL) {
    fpool = make_sub_pool(cmd->tmp_pool);
    pr_pool_tag(fpool, "mod_ls addfile pool");
  }

  if (opt_S || opt_t) {
    struct sort_filename *s;

    if (sort_arr == NULL) {
      sort_arr = make_array(fpool, 50, sizeof(struct sort_filename));
    }

    s = (struct sort_filename *) push_array(sort_arr);
    s->sort_time = sort_time;
    s->size = size;
    s->name = pstrdup(fpool, name);
    s->suffix = pstrdup(fpool, suffix);

    return;
  }

  l = strlen(name) + strlen(suffix);
  if (l > colwidth) {
    colwidth = l;
  }

  p = (struct filename *) pcalloc(fpool, sizeof(struct filename));
  p->line = pcalloc(fpool, l + 2);
  pr_snprintf(p->line, l + 1, "%s%s", name, suffix);

  if (tail) {
    tail->down = p;

  } else {
    head = p;
  }

  tail = p;
  filenames++;
}

static int file_time_cmp(const struct sort_filename *f1,
    const struct sort_filename *f2) {

  if (f1->sort_time > f2->sort_time)
    return -1;

  else if (f1->sort_time < f2->sort_time)
    return 1;

  return 0;
}

static int file_time_reverse_cmp(const struct sort_filename *f1,
    const struct sort_filename *f2) {
  return -file_time_cmp(f1, f2);
}

static int file_size_cmp(const struct sort_filename *f1,
    const struct sort_filename *f2) {

  if (f1->size > f2->size)
    return -1;

  else if (f1->size < f2->size)
    return 1;

  return 0;
}

static int file_size_reverse_cmp(const struct sort_filename *f1,
    const struct sort_filename *f2) {
  return -file_size_cmp(f1, f2);
}

static void sortfiles(cmd_rec *cmd) {

  if (sort_arr) {

    /* Sort by time? */
    if (opt_t) {
      register unsigned int i = 0;
      int setting = opt_S;
      struct sort_filename *elts = sort_arr->elts;

      qsort(sort_arr->elts, sort_arr->nelts, sizeof(struct sort_filename),
        (int (*)(const void *, const void *))
          (opt_r ? file_time_reverse_cmp : file_time_cmp));

      opt_S = opt_t = 0;

      for (i = 0; i < sort_arr->nelts; i++) {
        addfile(cmd, elts[i].name, elts[i].suffix, elts[i].sort_time,
          elts[i].size);
      }

      opt_S = setting;
      opt_t = 1;

    /* Sort by file size? */
    } else if (opt_S) {
      register unsigned int i = 0;
      int setting = opt_t;
      struct sort_filename *elts = sort_arr->elts;

      qsort(sort_arr->elts, sort_arr->nelts, sizeof(struct sort_filename),
        (int (*)(const void *, const void *))
          (opt_r ? file_size_reverse_cmp : file_size_cmp));

      opt_S = opt_t = 0;

      for (i = 0; i < sort_arr->nelts; i++) {
        addfile(cmd, elts[i].name, elts[i].suffix, elts[i].sort_time,
          elts[i].size);
      }

      opt_S = 1;
      opt_t = setting;
    }
  }

  sort_arr = NULL;
}

static int outputfiles(cmd_rec *cmd) {
  int n, res = 0;
  struct filename *p = NULL, *q = NULL;

  if (opt_S || opt_t) {
    sortfiles(cmd);
  }

  if (head == NULL) {
    /* Nothing to display. */
    if (sendline(LS_SENDLINE_FL_FLUSH, " ") < 0) {
      res = -1;
    }

    destroy_pool(fpool);
    fpool = NULL;
    sort_arr = NULL;
    head = tail = NULL;
    colwidth = 0;
    filenames = 0;

    return res;
  }

  tail->down = NULL;
  tail = NULL;
  colwidth = (colwidth | 7) + 1;
  if (opt_l || !opt_C) {
    colwidth = 75;
  }

  /* avoid division by 0 if colwidth > 75 */
  if (colwidth > 75) {
    colwidth = 75;
  }

  if (opt_C) {
    p = head;
    p->top = 1;
    n = (filenames + (75 / colwidth)-1) / (75 / colwidth);

    while (n && p) {
      pr_signals_handle();

      p = p->down;
      if (p) {
        p->top = 0;
      }
      n--;
    }

    q = head;
    while (p) {
      pr_signals_handle();

      p->top = q->top;
      q->right = p;
      q = q->down;
      p = p->down;
    }

    while (q) {
      pr_signals_handle();

      q->right = NULL;
      q = q->down;
    }

    p = head;
    while (p && p->down && !p->down->top) {
      pr_signals_handle();
      p = p->down;
    }

    if (p && p->down) {
      p->down = NULL;
    }
  }

  p = head;
  while (p) {
    pr_signals_handle();

    q = p;
    p = p->down;
    while (q) {
      char pad[6] = {'\0'};

      pr_signals_handle();

      if (!q->right) {
        sstrncpy(pad, "\r\n", sizeof(pad));

      } else {
        unsigned int idx = 0;

        sstrncpy(pad, "\t\t\t\t\t", sizeof(pad));

        idx = (colwidth + 7 - strlen(q->line)) / 8;
        if (idx >= sizeof(pad)) {
          idx = sizeof(pad)-1;
        }

        pad[idx] = '\0';
      }

      if (sendline(0, "%s%s", q->line, pad) < 0) {
        return -1;
      }

      q = q->right;
    }
  }

  if (sendline(LS_SENDLINE_FL_FLUSH, " ") < 0) {
    res = -1;
  }

  destroy_pool(fpool);
  fpool = NULL;
  sort_arr = NULL;
  head = tail = NULL;
  colwidth = 0;
  filenames = 0;

  return res;
}

static void discard_output(void) {
  if (fpool) {
    destroy_pool(fpool);
  }
  fpool = NULL;

  head = tail = NULL;
  colwidth = 0;
  filenames = 0;
}

static int dircmp(const void *a, const void *b) {
#if defined(PR_USE_NLS) && defined(HAVE_STRCOLL)
  return strcoll(*(const char **)a, *(const char **)b);
#else
  return strcmp(*(const char **)a, *(const char **)b);
#endif /* !PR_USE_NLS or !HAVE_STRCOLL */
}

static char **sreaddir(const char *dirname, const int sort) {
  DIR *d;
  struct dirent *de;
  struct stat st;
  int i, dir_fd;
  char **p;
  long ssize;
  size_t dsize;

  pr_fs_clear_cache2(dirname);
  if (pr_fsio_stat(dirname, &st) < 0) {
    return NULL;
  }

  if (!S_ISDIR(st.st_mode)) {
    errno = ENOTDIR;
    return NULL;
  }

  d = pr_fsio_opendir(dirname);
  if (d == NULL) {
    return NULL;
  }

  /* It doesn't matter if the following guesses are wrong, but it slows
   * the system a bit and wastes some memory if they are wrong, so
   * don't guess *too* naively!
   *
   * 'dsize' must be greater than zero or we loop forever.
   * 'ssize' must be at least big enough to hold a maximum-length name.
   */

  /* Guess the number of entries in the directory. */
  dsize = (((size_t) st.st_size) / 4) + 10;
  if (dsize > LS_MAX_DSIZE) {
    dsize = LS_MAX_DSIZE;
  }

  /* The directory has been opened already, but portably accessing the file
   * descriptor inside the DIR struct isn't easy.  Some systems use "dd_fd" or
   * "__dd_fd" rather than "d_fd".  Still others work really hard at opacity.
   */
#if defined(HAVE_DIRFD) 
  dir_fd = dirfd(d);
#elif defined(HAVE_STRUCT_DIR_D_FD)
  dir_fd = d->d_fd;
#elif defined(HAVE_STRUCT_DIR_DD_FD)
  dir_fd = d->dd_fd;
#elif defined(HAVE_STRUCT_DIR___DD_FD)
  dir_fd = d->__dd_fd;
#else
  dir_fd = 0;
#endif

  ssize = get_name_max((char *) dirname, dir_fd);
  if (ssize < 1) {
    pr_log_debug(DEBUG1, "get_name_max(%s, %d) = %lu, using %d", dirname,
      dir_fd, (unsigned long) ssize, NAME_MAX_GUESS);
    ssize = NAME_MAX_GUESS;
  }

  ssize *= ((dsize / 4) + 1);

  /* Allocate first block for holding filenames.  Yes, we are explicitly using
   * malloc (and realloc, and calloc, later) rather than the memory pools.
   * Recursive directory listings would eat up a lot of pool memory that is
   * only freed when the _entire_ directory structure has been parsed.  Also,
   * this helps to keep the memory footprint a little smaller.
   */
  pr_trace_msg("data", 8, "allocating readdir buffer of %lu bytes",
    (unsigned long) (dsize * sizeof(char *)));

  p = malloc(dsize * sizeof(char *));
  if (p == NULL) {
    pr_log_pri(PR_LOG_ALERT, "Out of memory!");
    exit(1);
  }

  i = 0;

  while ((de = pr_fsio_readdir(d)) != NULL) {
    pr_signals_handle();

    if ((size_t) i >= dsize - 1) {
      char **newp;

      /* The test above goes off one item early in case this is the last item
       * in the directory and thus next time we will want to NULL-terminate
       * the array.
       */
      pr_log_debug(DEBUG0, "Reallocating sreaddir buffer from %lu entries to "
        "%lu entries", (unsigned long) dsize, (unsigned long) dsize * 2);

      /* Allocate bigger array for pointers to filenames */
      pr_trace_msg("data", 8, "allocating readdir buffer of %lu bytes",
        (unsigned long) (2 * dsize * sizeof(char *)));

      newp = (char **) realloc(p, 2 * dsize * sizeof(char *));
      if (newp == NULL) {
        pr_log_pri(PR_LOG_ALERT, "Out of memory!");
        exit(1);
      }
      p = newp;
      dsize *= 2;
    }

    /* Append the filename to the block. */
    p[i] = (char *) calloc(strlen(de->d_name) + 1, sizeof(char));
    if (p[i] == NULL) {
      pr_log_pri(PR_LOG_ALERT, "Out of memory!");
      exit(1);
    }
    sstrncpy(p[i++], de->d_name, strlen(de->d_name) + 1);
  }

  pr_fsio_closedir(d);

  /* This is correct, since the above is off by one element.
   */
  p[i] = NULL;

  if (sort) {
    PR_DEVEL_CLOCK(qsort(p, i, sizeof(char *), dircmp));
  }

  return p;
}

/* This listdir() requires a chdir() first. */
static int listdir(cmd_rec *cmd, pool *workp, const char *resp_code,
    const char *name) {
  char **dir;
  int dest_workp = 0;
  register unsigned int i = 0;

  if (list_ndepth.curr && list_ndepth.max &&
      list_ndepth.curr >= list_ndepth.max) {

    if (!list_ndepth.logged) {
      /* Don't forget to take away the one we add to maxdepth internally. */
      pr_log_debug(DEBUG8, "ListOptions maxdepth (%u) reached",
        list_ndepth.max - 1);
      list_ndepth.logged = TRUE;
    }
 
    return 1;
  }

  if (list_ndirs.curr && list_ndirs.max &&
      list_ndirs.curr >= list_ndirs.max) {

    if (!list_ndirs.logged) {
      pr_log_debug(DEBUG8, "ListOptions maxdirs (%u) reached", list_ndirs.max);
      list_ndirs.logged = TRUE;
    }

    return 1;
  }
  list_ndirs.curr++;

  if (XFER_ABORTED) {
    return -1;
  }

  if (workp == NULL) {
    workp = make_sub_pool(cmd->tmp_pool);
    pr_pool_tag(workp, "mod_ls: listdir(): workp (from cmd->tmp_pool)");
    dest_workp++;

  } else {
    workp = make_sub_pool(workp);
    pr_pool_tag(workp, "mod_ls: listdir(): workp (from workp)");
    dest_workp++;
  }

  PR_DEVEL_CLOCK(dir = sreaddir(".", opt_U ? FALSE : TRUE));
  if (dir) {
    char **s;
    char **r;

    int d = 0;

    s = dir;
    while (*s) {
      if (**s == '.') {
        if (!opt_a && (!opt_A || is_dotdir(*s))) {
          d = 0;

        } else {
          d = listfile(cmd, workp, resp_code, *s);
        }

      } else {
        d = listfile(cmd, workp, resp_code, *s);
      }

      if (opt_R && d == 0) {

        /* This is a nasty hack.  If listfile() returns a zero, and we
         * will be recursing (-R option), make sure we don't try to list
         * this file again by changing the first character of the path
         * to ".".  Such files are skipped later.
         */
        **s = '.';
        *(*s + 1) = '\0';

      } else if (d == 2) {
        break;
      }

      s++;
    }

    if (outputfiles(cmd) < 0) {
      if (dest_workp) {
        destroy_pool(workp);
      }

      /* Explicitly free the memory allocated for containing the list of
       * filenames.
       */
      i = 0;
      while (dir[i] != NULL) {
        free(dir[i++]);
      }
      free(dir);

      return -1;
    }

    r = dir;
    while (opt_R && r != s) {
      char cwd_buf[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
      unsigned char symhold;

      if (*r && (strcmp(*r, ".") == 0 || strcmp(*r, "..") == 0)) {
        r++;
        continue;
      }

      /* Add some signal processing to this while loop, as it can
       * potentially recurse deeply.
       */
      pr_signals_handle();

      if (list_ndirs.curr && list_ndirs.max &&
          list_ndirs.curr >= list_ndirs.max) {

        if (!list_ndirs.logged) {
          pr_log_debug(DEBUG8, "ListOptions maxdirs (%u) reached",
            list_ndirs.max);
          list_ndirs.logged = TRUE;
        }

        break;
      }

      if (list_nfiles.curr && list_nfiles.max &&
          list_nfiles.curr >= list_nfiles.max) {

        if (!list_nfiles.logged) {
          pr_log_debug(DEBUG8, "ListOptions maxfiles (%u) reached",
            list_nfiles.max);
          list_nfiles.logged = TRUE;
        }

        break;
      }

      push_cwd(cwd_buf, &symhold);

      if (*r && ls_perms_full(workp, cmd, (char *) *r, NULL) &&
          !pr_fsio_chdir_canon(*r, !opt_L && list_show_symlinks)) {
        char *subdir;
        int res = 0;

        if (strcmp(name, ".") == 0) {
          subdir = *r;

        } else {
          subdir = pdircat(workp, name, *r, NULL);
        }

        if (opt_STAT) {
          pr_response_add(resp_code, "%s", "");
          pr_response_add(resp_code, "%s:",
            pr_fs_encode_path(cmd->tmp_pool, subdir));

        } else if (sendline(0, "\r\n%s:\r\n",
                   pr_fs_encode_path(cmd->tmp_pool, subdir)) < 0 ||
            sendline(LS_SENDLINE_FL_FLUSH, " ") < 0) {
          pop_cwd(cwd_buf, &symhold);

          if (dest_workp) {
            destroy_pool(workp);
          }

          /* Explicitly free the memory allocated for containing the list of
           * filenames.
           */
          i = 0;
          while (dir[i] != NULL) {
            free(dir[i++]);
          }
          free(dir);

          return -1;
        }

        list_ndepth.curr++;
        res = listdir(cmd, workp, resp_code, subdir);
        list_ndepth.curr--;
        pop_cwd(cwd_buf, &symhold);

        if (res > 0) {
          break;

        } else if (res < 0) {
          if (dest_workp) {
            destroy_pool(workp);
          }

          /* Explicitly free the memory allocated for containing the list of
           * filenames.
           */
          i = 0;
          while (dir[i] != NULL) {
            free(dir[i++]);
          }
          free(dir);

          return -1;
        }
      }
      r++;
    }

  } else {
    pr_trace_msg("fsio", 9,
      "sreaddir() error on '.': %s", strerror(errno));
  }

  if (dest_workp) {
    destroy_pool(workp);
  }

  /* Explicitly free the memory allocated for containing the list of
   * filenames.
   */
  if (dir) {
    i = 0;
    while (dir[i] != NULL) {
      free(dir[i++]);
    }
    free(dir);
  }

  return 0;
}

static void ls_terminate(void) {
  if (!opt_STAT) {
    discard_output();

    if (!XFER_ABORTED) {
      /* An error has occurred, other than client ABOR */
      if (ls_errno) {
        pr_data_abort(ls_errno,FALSE);

      } else {
        pr_data_abort((session.d && session.d->outstrm ?
                      PR_NETIO_ERRNO(session.d->outstrm) : errno), FALSE);
      }
    }
    ls_errno = 0;

  } else if (ls_errno) {
    pr_response_add(R_211, _("ERROR: %s"), strerror(ls_errno));
    ls_errno = 0;
  }
}

static void parse_list_opts(char **opt, int *glob_flags, int handle_plus_opts) {
  char *ptr;

  /* First, scan for options.  Any leading whitespace before options can
   * be skipped, as long as there ARE options.
   */
  ptr = *opt;

  while (PR_ISSPACE(*ptr)) {
    pr_signals_handle();
    ptr++;
  }

  if (*ptr == '-') {
    /* Options are found; skip past the leading whitespace. */
    *opt = ptr;
  }

  /* Check for standard /bin/ls options */
  while (*opt && **opt == '-') {
    pr_signals_handle();

    while ((*opt)++ && PR_ISALNUM(**opt)) {
      switch (**opt) {
        case '1':
          if (session.curr_cmd_id != PR_CMD_STAT_ID) {
            opt_1 = 1;
            opt_l = opt_C = 0;
          }
          break;

        case 'A':
          opt_A = 1;
          break;

        case 'a':
          opt_a = 1;
          break;

        case 'B':
          opt_B = 1;
          break;

        case 'C':
          if (session.curr_cmd_id != PR_CMD_NLST_ID) {
            opt_l = 0;
            opt_C = 1;
          }
          break;

        case 'c':
          opt_c = 1;
          ls_sort_by = LS_SORT_BY_CTIME;
          break;

        case 'd':
          opt_d = 1;
          break;

        case 'F':
          if (session.curr_cmd_id != PR_CMD_NLST_ID) {
            opt_F = 1;
          }
          break;

        case 'h':
          if (session.curr_cmd_id != PR_CMD_NLST_ID) {
            opt_h = 1;
          }
          break;

        case 'L':
          opt_L = 1;
          break;

        case 'l':
          if (session.curr_cmd_id != PR_CMD_NLST_ID) {
            opt_l = 1;
            opt_C = 0;
            opt_1 = 0;
          }
          break;

        case 'n':
          if (session.curr_cmd_id != PR_CMD_NLST_ID) {
            opt_n = 1;
          }
          break;

        case 'R':
          opt_R = 1;
          break;

        case 'r':
          opt_r = 1;
          break;

        case 'S':
          opt_S = 1;
          break;

        case 't':
          opt_t = 1;
          if (glob_flags) {
            *glob_flags |= GLOB_NOSORT;
          }
          break;

        case 'U':
          opt_U = 1;
          opt_c = opt_S = opt_t = 0;
          break;

        case 'u':
          opt_u = 1;
          ls_sort_by = LS_SORT_BY_ATIME;
          break;
      }
    }

    ptr = *opt;

    while (*ptr &&
           PR_ISSPACE(*ptr)) {
      pr_signals_handle();
      ptr++;
    }

    if (*ptr == '-') {
      /* Options are found; skip past the leading whitespace. */
      *opt = ptr;

    } else if (**opt && *(*opt + 1) == ' ') {
      /* If the next character is a blank space, advance just one character. */
      (*opt)++;
      break;

    } else {
      *opt = ptr;
      break;
    }
  }

  if (!handle_plus_opts) {
    return;
  }

  /* Check for non-standard options */
  while (*opt && **opt == '+') {
    pr_signals_handle();

    while ((*opt)++ && PR_ISALNUM(**opt)) {
      switch (**opt) {
        case '1':
          opt_1 = opt_l = opt_C = 0;
          break;

        case 'A':
          opt_A = 0;
          break;

        case 'a':
          opt_a = 0;
          break;

        case 'B':
          opt_B = 0;
          break;

        case 'C':
          opt_l = opt_C = 0;
          break;

        case 'c':
          opt_c = 0;

          /* -u is still in effect, sort by that, otherwise use the default. */
          ls_sort_by = opt_u ? LS_SORT_BY_ATIME : LS_SORT_BY_MTIME;
          break;

        case 'd':
          opt_d = 0;
          break;

        case 'F':
          opt_F = 0;
          break;

        case 'h':
          opt_h = 0;
          break;

        case 'L':
          opt_L = 0;
          break;

        case 'l':
          opt_l = opt_C = 0;
          break;

        case 'n':
          opt_n = 0;
          break;

        case 'R':
          opt_R = 0;
          break;

        case 'r':
          opt_r = 0;
          break;

        case 'S':
          opt_S = 0;
          break;

        case 't':
          opt_t = 0;
          if (glob_flags)
            *glob_flags &= GLOB_NOSORT;
          break;

        case 'U':
          opt_U = 0;
          break;

        case 'u':
          opt_u = 0;

          /* -c is still in effect, sort by that, otherwise use the default. */
          ls_sort_by = opt_c ? LS_SORT_BY_CTIME : LS_SORT_BY_MTIME;
          break;
      }
    }

    ptr = *opt;

    while (*ptr &&
           PR_ISSPACE(*ptr)) {
      pr_signals_handle();
      ptr++;
    }

    if (*ptr == '+') {
      /* Options are found; skip past the leading whitespace. */
      *opt = ptr;

    } else if (**opt && *(*opt + 1) == ' ') {
      /* If the next character is a blank space, advance just one character. */
      (*opt)++;
      break;

    } else {
      *opt = ptr;
      break;
    }
  }
}

/* Only look for and parse options if there are more than two arguments.
 * This will avoid trying to handle the file/path in a command like:
 *
 *  LIST -filename
 *
 * as if it were options.
 *
 * Returns TRUE if the given command has options that should be parsed,
 * FALSE otherwise.
 */
static int have_options(cmd_rec *cmd, const char *arg) {
  struct stat st;
  int res;

  /* If we have more than 2 arguments, then we definitely have parseable
   * options.
   */

  if (cmd->argc > 2) {
    return TRUE;
  }

  /* Now we need to determine if the given string (arg) should be handled
   * as options (as when the target path is implied, e.g. "LIST -al") or
   * as a real path.  We'll simply do a stat on the string; if it exists,
   * then it's a path.
   */

  pr_fs_clear_cache2(arg);
  res = pr_fsio_stat(arg, &st);

  if (res == 0) {
    return FALSE;
  }

  return TRUE;
}

/* The main work for LIST and STAT (not NLST).  Returns -1 on error, 0 if
 * successful.
 */
static int dolist(cmd_rec *cmd, const char *opt, const char *resp_code,
    int clear_flags) {
  int skiparg = 0;
  int glob_flags = 0;

  char *arg = (char*) opt;

  ls_curtime = time(NULL);

  if (clear_flags) {
    opt_1 = opt_A = opt_a = opt_B = opt_C = opt_d = opt_F = opt_h = opt_n =
      opt_r = opt_R = opt_S = opt_t = opt_STAT = opt_L = 0;
  }

  if (have_options(cmd, arg)) {
    if (!list_strict_opts) {
      parse_list_opts(&arg, &glob_flags, FALSE);

    } else {
      char *ptr;

      /* Even if the user-given options are ignored, they still need to
       * "processed" (i.e. skip past options) in order to get to the paths.
       *
       * First, scan for options.  Any leading whitespace before options can
       * be skipped, as long as there ARE options.
       */
      ptr = arg;

      while (PR_ISSPACE(*ptr)) {
        pr_signals_handle();
        ptr++;
      }

      if (*ptr == '-') {
        /* Options are found; skip past the leading whitespace. */
        arg = ptr;
      }

      while (arg && *arg == '-') {
        /* Advance to the next whitespace */
        while (*arg != '\0' && !PR_ISSPACE(*arg)) {
          arg++;
        }

        ptr = arg;

        while (*ptr &&
               PR_ISSPACE(*ptr)) {
          pr_signals_handle();
          ptr++;
        }

        if (*ptr == '-') {
          /* Options are found; skip past the leading whitespace. */
          arg = ptr;

        } else if (*(arg + 1) == ' ') {
          /* If the next character is a blank space, advance just one
           * character.
           */
          arg++;
          break;

        } else {
          arg = ptr;
          break;
        }
      }
    }
  }

  if (list_options) {
    parse_list_opts(&list_options, &glob_flags, TRUE);
  }

  if (arg && *arg) {
    int justone = 1;
    glob_t g;
    int globbed = FALSE;
    int a;
    char pbuffer[PR_TUNABLE_PATH_MAX + 1] = "";
    char *target;

    /* Make sure the glob_t is initialized. */
    memset(&g, '\0', sizeof(g));

    if (*arg == '~') {
      struct passwd *pw;
      int i;
      const char *p;

      for (i = 0, p = arg + 1;
          ((size_t) i < sizeof(pbuffer) - 1) && p && *p && *p != '/';
          pbuffer[i++] = *p++);

      pbuffer[i] = '\0';

      pw = pr_auth_getpwnam(cmd->tmp_pool, i ? pbuffer : session.user);
      if (pw) {
        pr_snprintf(pbuffer, sizeof(pbuffer), "%s%s", pw->pw_dir, p);

      } else {
        pbuffer[0] = '\0';
      }
    }

    target = *pbuffer ? pbuffer : arg;

    /* Open data connection */
    if (!opt_STAT) {
      if (pr_data_open(NULL, "file list", PR_NETIO_IO_WR, 0) < 0) {
        int xerrno = errno;

        pr_response_add_err(R_450, "%s: %s", (char *) cmd->argv[0],
          strerror(xerrno));

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return -1;
      }

      session.sf_flags |= SF_ASCII_OVERRIDE;
    }

    /* If there are no globbing characters in the given target,
     * we can check to see if it even exists.
     */
    if (pr_str_is_fnmatch(target) == FALSE) {
      struct stat st;

      pr_fs_clear_cache2(target);
      if (pr_fsio_stat(target, &st) < 0) {
        int xerrno = errno;

        if (xerrno == ENOENT &&
            (list_flags & LS_FL_NO_ERROR_IF_ABSENT)) {
          return 0;
        }

        pr_response_add_err(R_450, "%s: %s",
          pr_fs_encode_path(cmd->tmp_pool, target), strerror(xerrno));

        errno = xerrno;
        return -1;
      }
    }

    /* Check perms on the directory/file we are about to scan. */
    if (!ls_perms_full(cmd->tmp_pool, cmd, target, NULL)) {
      a = -1;
      skiparg = TRUE;

    } else {
      skiparg = FALSE;

      if (use_globbing &&
          pr_str_is_fnmatch(target)) {
        a = pr_fs_glob(target, glob_flags, NULL, &g);
        if (a == 0) {
          pr_log_debug(DEBUG8, "LIST: glob(3) returned %lu %s",
            (unsigned long) g.gl_pathc, g.gl_pathc != 1 ? "paths" : "path");
          globbed = TRUE;

        } else {
          if (a == GLOB_NOMATCH) {
            pr_log_debug(DEBUG10, "LIST: glob(3) returned GLOB_NOMATCH "
              "for '%s', handling as literal path", target);

            /* Trick the following code into using the non-glob() processed
             * path.
             */
            a = 0;
            g.gl_pathv = (char **) pcalloc(cmd->tmp_pool, 2 * sizeof(char *));
            g.gl_pathv[0] = (char *) pstrdup(cmd->tmp_pool, target);
            g.gl_pathv[1] = NULL;
          }
        }

      } else {
        /* Trick the following code into using the non-glob() processed path */
        a = 0;
        g.gl_pathv = (char **) pcalloc(cmd->tmp_pool, 2 * sizeof(char *));
        g.gl_pathv[0] = (char *) pstrdup(cmd->tmp_pool, target);
        g.gl_pathv[1] = NULL;
      }
    }

    if (!a) {
      char **path;

      path = g.gl_pathv;

      if (path && path[0] && path[1]) {
        justone = 0;
      }

      while (path &&
             *path) {
        struct stat st;

        pr_signals_handle();

        pr_fs_clear_cache2(*path);
        if (pr_fsio_lstat(*path, &st) == 0) {
          mode_t target_mode, lmode;
          target_mode = st.st_mode;

          if (S_ISLNK(st.st_mode) &&
              (lmode = symlink_mode2(cmd->tmp_pool, (char *) *path)) != 0) {
            if (opt_L || !list_show_symlinks) {
              st.st_mode = lmode;
            }

            if (lmode != 0) {
              target_mode = lmode;
            }
          }

          /* If the -d option is used or the file is not a directory, OR
           * if the -R option is NOT used AND the file IS a directory AND
           * the file is NOT the target/given parameter, then list the file
           * as is.
           */
          if (opt_d ||
              !(S_ISDIR(target_mode)) ||
              (!opt_R && S_ISDIR(target_mode) && strcmp(*path, target) != 0)) {

            if (listfile(cmd, cmd->tmp_pool, resp_code, *path) < 0) {
              ls_terminate();
              if (use_globbing && globbed) {
                pr_fs_globfree(&g);
              }
              return -1;
            }

            **path = '\0';
          }

        } else {
          **path = '\0';
        }

        path++;
      }

      if (outputfiles(cmd) < 0) {
        ls_terminate();
        if (use_globbing && globbed) {
          pr_fs_globfree(&g);
        }
        return -1;
      }

      /* At this point, the only paths left in g.gl_pathv should be
       * directories; anything else should have been listed/handled
       * above.
       */

      path = g.gl_pathv;
      while (path &&
             *path) {
        pr_signals_handle();

        if (**path &&
            ls_perms_full(cmd->tmp_pool, cmd, *path, NULL)) {
          char cwd_buf[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
          unsigned char symhold;

          if (!justone) {
            if (opt_STAT) {
              pr_response_add(resp_code, "%s", "");
              pr_response_add(resp_code, "%s:",
                pr_fs_encode_path(cmd->tmp_pool, *path));

            } else {
              sendline(0, "\r\n%s:\r\n",
                pr_fs_encode_path(cmd->tmp_pool, *path));
              sendline(LS_SENDLINE_FL_FLUSH, " ");
            }
          }

          /* Recurse into the directory. */
          push_cwd(cwd_buf, &symhold);

          if (!pr_fsio_chdir_canon(*path, !opt_L && list_show_symlinks)) {
            int res = 0;

            list_ndepth.curr++;
            res = listdir(cmd, cmd->tmp_pool, resp_code, *path);
            list_ndepth.curr--;

            pop_cwd(cwd_buf, &symhold);

            if (res > 0) {
              break;

            } else if (res < 0) {
              ls_terminate();
              if (use_globbing && globbed) {
                pr_fs_globfree(&g);
              }
              return -1;
            }
          }
        }

        if (XFER_ABORTED) {
          discard_output();
          if (use_globbing && globbed) {
            pr_fs_globfree(&g);
          }
          return -1;
        }

        path++;
      }

      if (outputfiles(cmd) < 0) {
        ls_terminate();
        if (use_globbing && globbed) {
          pr_fs_globfree(&g);
        }
        return -1;
      }

    } else if (!skiparg) {
      if (a == GLOB_NOSPACE) {
        pr_response_add(R_226, _("Out of memory during globbing of %s"),
          pr_fs_encode_path(cmd->tmp_pool, arg));

      } else if (a == GLOB_ABORTED) {
        pr_response_add(R_226, _("Read error during globbing of %s"),
          pr_fs_encode_path(cmd->tmp_pool, arg));

      } else if (a != GLOB_NOMATCH) {
        pr_response_add(R_226, _("Unknown error during globbing of %s"),
          pr_fs_encode_path(cmd->tmp_pool, arg));
      }
    }

    if (!skiparg && use_globbing && globbed) {
      pr_fs_globfree(&g);
    }

    if (XFER_ABORTED) {
      discard_output();
      return -1;
    }

  } else {

    /* Open data connection */
    if (!opt_STAT) {
      if (pr_data_open(NULL, "file list", PR_NETIO_IO_WR, 0) < 0) {
        int xerrno = errno;

        pr_response_add_err(R_450, "%s: %s", (char *) cmd->argv[0], 
          strerror(xerrno));

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return -1;
      }

      session.sf_flags |= SF_ASCII_OVERRIDE;
    }

    if (ls_perms_full(cmd->tmp_pool, cmd, ".", NULL)) {

      if (opt_d) {
        if (listfile(cmd, NULL, resp_code, ".") < 0) {
          ls_terminate();
          return -1;
        }

      } else {
        list_ndepth.curr++;
        if (listdir(cmd, NULL, resp_code, ".") < 0) {
          ls_terminate();
          return -1;
        }

        list_ndepth.curr--;
      }
    }

    if (outputfiles(cmd) < 0) {
      ls_terminate();
      return -1;
    }
  }

  return 0;
}

/* Display listing of a single file, no permission checking is done.
 * An error is only returned if the data connection cannot be opened or is
 * aborted.
 */
static int nlstfile(cmd_rec *cmd, const char *file) {
  int res = 0;
  char *display_name;

  /* If the data connection isn't open, return an error */
  if ((session.sf_flags & SF_XFER) == 0) {
    errno = EPERM;
    return -1;
  }

  /* XXX Note that "NLST <glob>" was sent, we might be receiving paths
   * here, not just file names.  And that is not what dir_hide_file() is
   * expecting.
   */
  if (dir_hide_file(file))
    return 1;

  display_name = pstrdup(cmd->tmp_pool, file);

#ifndef PR_USE_NLS
  if (opt_B) {
    register unsigned int i, j;
    size_t display_namelen, printable_namelen;
    char *printable_name = NULL;

    display_namelen = strlen(display_name);

    /* Allocate 4 times as much space as necessary, in case every single
     * character is non-printable.
     */
    printable_namelen = (display_namelen * 4);
    printable_name = pcalloc(cmd->tmp_pool, printable_namelen + 1);

    /* Check for any non-printable characters, and replace them with the octal
     * escape sequence equivalent.
     */
    for (i = 0, j = 0; i < display_namelen && j < printable_namelen; i++) {
      if (!PR_ISPRINT(display_name[i])) {
        register int k;
        int replace_len = 0;
        char replace[32];

        memset(replace, '\0', sizeof(replace));
        replace_len = pr_snprintf(replace, sizeof(replace)-1, "\\%03o",
          display_name[i]);

        for (k = 0; k < replace_len; k++) {
          printable_name[j++] = replace[k];
        }

      } else {
        printable_name[j++] = display_name[i];
      }
    }

    display_name = pstrdup(cmd->tmp_pool, printable_name);
  }
#endif /* PR_USE_NLS */

  if (opt_1) {
    char *ptr;

    /* If the -1 option is configured, we want to make sure that we only
     * display a file, not a path.  And it's possible that we given a path
     * here.
     */
    ptr = strrchr(display_name, '/');
    if (ptr != NULL) {
      size_t display_namelen;

      display_namelen = strlen(display_name);
      if (display_namelen > 1) {
        /* Make sure that we handle a possible display_name of '/' properly. */
        display_name = ptr + 1;
      }
    }
  }

  /* Be sure to flush the output */
  res = sendline(0, "%s\r\n", pr_fs_encode_path(cmd->tmp_pool, display_name));
  if (res < 0)
    return res;

  return 1;
}

/* Display listing of a directory, ACL checks performed on each entry,
 * sent in NLST fashion.  Files which are inaccessible via ACL are skipped,
 * error returned if data conn cannot be opened or is aborted.
 */
static int nlstdir(cmd_rec *cmd, const char *dir) {
  char **list, *p, *f,
       file[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
  char cwd_buf[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
  pool *workp;
  unsigned char symhold;
  int curdir = FALSE, i, j, count = 0, hidden = 0, use_sorting = FALSE;
  mode_t mode;
  config_rec *c = NULL;
  unsigned char ignore_hidden = FALSE;

  if (list_ndepth.curr && list_ndepth.max &&
      list_ndepth.curr >= list_ndepth.max) {

    if (!list_ndepth.logged) {
      /* Don't forget to take away the one we add to maxdepth internally. */
      pr_log_debug(DEBUG8, "ListOptions maxdepth (%u) reached",
        list_ndepth.max - 1);
      list_ndepth.logged = TRUE;
    }

    return 0;
  }

  if (list_ndirs.curr && list_ndirs.max &&
      list_ndirs.curr >= list_ndirs.max) {

    if (!list_ndirs.logged) {
      pr_log_debug(DEBUG8, "ListOptions maxdirs (%u) reached", list_ndirs.max);
      list_ndirs.logged = TRUE;
    }

    return 0;
  }
  list_ndirs.curr++;

  workp = make_sub_pool(cmd->tmp_pool);
  pr_pool_tag(workp, "mod_ls: nlstdir(): workp (from cmd->tmp_pool)");

  if (!*dir || (*dir == '.' && !dir[1]) || strcmp(dir, "./") == 0) {
    curdir = TRUE;
    dir = "";

  } else {

    /* If dir is not '.', then we need to change directories.  Hence we
     * push our current working directory onto the stack, do the chdir,
     * and pop back, afterwards.
     */
    push_cwd(cwd_buf, &symhold);

    if (pr_fsio_chdir_canon(dir, !opt_L && list_show_symlinks) < 0) {
      pop_cwd(cwd_buf, &symhold);

      destroy_pool(workp);
      return 0;
    }
  }

  if (list_flags & LS_FL_SORTED_NLST) {
    use_sorting = TRUE;
  }

  PR_DEVEL_CLOCK(list = sreaddir(".", use_sorting));
  if (list == NULL) {
    pr_trace_msg("fsio", 9,
      "sreaddir() error on '.': %s", strerror(errno));

    if (!curdir) {
      pop_cwd(cwd_buf, &symhold);
    }

    destroy_pool(workp);
    return 0;
  }

  /* Search for relevant <Limit>'s to this NLST command.  If found,
   * check to see whether hidden files should be ignored.
   */
  c = find_ls_limit(cmd->argv[0]);
  if (c != NULL) {
    unsigned char *ignore = get_param_ptr(c->subset, "IgnoreHidden", FALSE);

    if (ignore &&
        *ignore == TRUE) {
      ignore_hidden = TRUE;
    }
  }

  j = 0;
  while (list[j] && count >= 0) {
    p = list[j++];

    pr_signals_handle();

    if (*p == '.') {
      if (!opt_a && (!opt_A || is_dotdir(p))) {
        continue;

      /* Make sure IgnoreHidden is properly honored. */
      } else if (ignore_hidden) {
        continue;
      }
    }

    if (list_flags & LS_FL_ADJUSTED_SYMLINKS) {
      i = dir_readlink(cmd->tmp_pool, p, file, sizeof(file) - 1,
        PR_DIR_READLINK_FL_HANDLE_REL_PATH);

    } else {
      i = pr_fsio_readlink(p, file, sizeof(file) - 1);
    }

    if (i > 0) {
      if ((size_t) i >= sizeof(file)) {
        continue;
      }

      file[i] = '\0';
      f = file;

    } else {
      f = p;
    }

    if (ls_perms(workp, cmd, dir_best_path(cmd->tmp_pool, f), &hidden)) {
      if (hidden) {
        continue;
      }

      mode = file_mode2(cmd->tmp_pool, f);
      if (mode == 0) {
        continue;
      }

      if (!curdir) {
        char *str = NULL;

        if (opt_1) {
          /* Send just the file name, not the path. */
          str = pr_fs_encode_path(cmd->tmp_pool, p);

        } else {
          str = pr_fs_encode_path(cmd->tmp_pool,
            pdircat(cmd->tmp_pool, dir, p, NULL));
        }

        if (sendline(0, "%s\r\n", str) < 0) {
          count = -1;

        } else {
          count++;

          if (list_nfiles.curr > 0 &&
              list_nfiles.max > 0 &&
              list_nfiles.curr >= list_nfiles.max) {

            if (!list_nfiles.logged) {
              pr_log_debug(DEBUG8, "ListOptions maxfiles (%u) reached",
                list_nfiles.max);
              list_nfiles.logged = TRUE;
            }

            break;
          }
          list_nfiles.curr++;
        }

      } else {
        if (sendline(0, "%s\r\n", pr_fs_encode_path(cmd->tmp_pool, p)) < 0) {
          count = -1;

        } else {
          count++;

          if (list_nfiles.curr > 0 &&
              list_nfiles.max > 0 &&
              list_nfiles.curr >= list_nfiles.max) {

            if (!list_nfiles.logged) {
              pr_log_debug(DEBUG8, "ListOptions maxfiles (%u) reached",
                list_nfiles.max);
              list_nfiles.logged = TRUE;
            }

            break;
          }
          list_nfiles.curr++;
        }
      }
    }
  }

  sendline(LS_SENDLINE_FL_FLUSH, " ");

  if (!curdir) {
    pop_cwd(cwd_buf, &symhold);
  }
  destroy_pool(workp);

  /* Explicitly free the memory allocated for containing the list of
   * filenames.
   */
  i = 0;
  while (list[i] != NULL) {
    free(list[i++]);
  }
  free(list);

  return count;
}

/* The LIST command.  */
MODRET genericlist(cmd_rec *cmd) {
  int res = 0;
  char *decoded_path = NULL;
  unsigned char *tmp = NULL;
  mode_t *fake_mode = NULL;
  config_rec *c = NULL;

  tmp = get_param_ptr(TOPLEVEL_CONF, "ShowSymlinks", FALSE);
  if (tmp != NULL) {
    list_show_symlinks = *tmp;
  }

  list_strict_opts = FALSE;
  list_nfiles.max = list_ndirs.max = list_ndepth.max = 0;

  c = find_config(CURRENT_CONF, CONF_PARAM, "ListOptions", FALSE);
  while (c != NULL) {
    unsigned long flags;

    pr_signals_handle();

    flags = *((unsigned long *) c->argv[5]);

    /* Make sure that this ListOptions can be applied to the LIST command.
     * If not, keep looking for other applicable ListOptions.
     */
    if (flags & LS_FL_NLST_ONLY) {
      pr_log_debug(DEBUG10, "%s: skipping NLSTOnly ListOptions",
        (char *) cmd->argv[0]);
      c = find_config_next(c, c->next, CONF_PARAM, "ListOptions", FALSE);
      continue;
    }

    list_options = c->argv[0];
    list_strict_opts = *((unsigned char *) c->argv[1]);
    list_ndepth.max = *((unsigned int *) c->argv[2]);

    /* We add one to the configured maxdepth in order to allow it to
     * function properly: if one configures a maxdepth of 2, one should
     * allowed to list the current directory, and all subdirectories one
     * layer deeper.  For the checks to work, the maxdepth of 2 needs to
     * handled internally as a maxdepth of 3.
     */
    if (list_ndepth.max) {
      list_ndepth.max += 1;
    }

    list_nfiles.max = *((unsigned int *) c->argv[3]);
    list_ndirs.max = *((unsigned int *) c->argv[4]);
    list_flags = *((unsigned long *) c->argv[5]);

    break;
  }

  fakeuser = get_param_ptr(CURRENT_CONF, "DirFakeUser", FALSE);

  /* Check for a configured "logged in user" DirFakeUser. */
  if (fakeuser != NULL &&
      strncmp(fakeuser, "~", 2) == 0) {
    fakeuser = session.user;
  }

  fakegroup = get_param_ptr(CURRENT_CONF, "DirFakeGroup", FALSE);

  /* Check for a configured "logged in user" DirFakeGroup. */
  if (fakegroup != NULL &&
      strncmp(fakegroup, "~", 2) == 0) {
    fakegroup = session.group;
  }

  fake_mode = get_param_ptr(CURRENT_CONF, "DirFakeMode", FALSE);
  if (fake_mode) {
    fakemode = *fake_mode;
    have_fake_mode = TRUE;

  } else {
    have_fake_mode = FALSE;
  }

  tmp = get_param_ptr(TOPLEVEL_CONF, "TimesGMT", FALSE);
  if (tmp != NULL) {
    list_times_gmt = *tmp;
  }

  decoded_path = pr_fs_decode_path2(cmd->tmp_pool, cmd->arg,
    FSIO_DECODE_FL_TELL_ERRORS);
  if (decoded_path == NULL) {
    int xerrno = errno;

    pr_log_debug(DEBUG8, "'%s' failed to decode properly: %s", cmd->arg,
      strerror(xerrno));
    pr_response_add_err(R_550, _("%s: Illegal character sequence in filename"),
      cmd->arg);

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  res = dolist(cmd, decoded_path, R_211, TRUE);

  if (XFER_ABORTED) {
    pr_data_abort(0, 0);
    res = -1;

  } else if (session.sf_flags & SF_XFER) {
    ls_done(cmd);
  }

  opt_l = 0;

  return (res == -1 ? PR_ERROR(cmd) : PR_HANDLED(cmd));
}

MODRET ls_log_nlst(cmd_rec *cmd) {
  pr_data_cleanup();
  return PR_DECLINED(cmd);
}

MODRET ls_err_nlst(cmd_rec *cmd) {
  pr_data_cleanup();
  return PR_DECLINED(cmd);
}

MODRET ls_stat(cmd_rec *cmd) {
  struct stat st;
  int res;
  char *arg = cmd->arg, *decoded_path, *path, *resp_code = NULL;
  unsigned char *ptr = NULL;
  mode_t *fake_mode = NULL;
  config_rec *c = NULL;

  if (cmd->argc == 1) {
    /* In this case, the client is requesting the current session status. */

    if (!dir_check(cmd->tmp_pool, cmd, cmd->group, session.cwd, NULL)) {
      int xerrno = EPERM;

      pr_response_add_err(R_500, "%s: %s", (char *) cmd->argv[0],
        strerror(xerrno));

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    pr_response_add(R_211, _("Status of '%s'"), main_server->ServerName);
    pr_response_add(R_DUP, _("Connected from %s (%s)"), session.c->remote_name,
      pr_netaddr_get_ipstr(session.c->remote_addr));
    pr_response_add(R_DUP, _("Logged in as %s"), session.user);
    pr_response_add(R_DUP, _("TYPE: %s, STRUcture: File, Mode: Stream"),
      (session.sf_flags & SF_ASCII) ? "ASCII" : "BINARY");

    if (session.total_bytes) {
      pr_response_add(R_DUP, _("Total bytes transferred for session: %" PR_LU),
        (pr_off_t) session.total_bytes);
    }

    if (session.sf_flags & SF_XFER) {
      /* Report on the data transfer attributes. */

      pr_response_add(R_DUP, _("%s from %s port %u"),
        (session.sf_flags & SF_PASSIVE) ?
          _("Passive data transfer from") : _("Active data transfer to"),
        pr_netaddr_get_ipstr(session.d->remote_addr), session.d->remote_port);

      if (session.xfer.file_size) {
        pr_response_add(R_DUP, "%s %s (%" PR_LU "/%" PR_LU ")",
          session.xfer.direction == PR_NETIO_IO_RD ? C_STOR : C_RETR,
          session.xfer.path, (pr_off_t) session.xfer.file_size,
          (pr_off_t) session.xfer.total_bytes);

      } else {
        pr_response_add(R_DUP, "%s %s (%" PR_LU ")",
          session.xfer.direction == PR_NETIO_IO_RD ? C_STOR : C_RETR,
          session.xfer.path, (pr_off_t) session.xfer.total_bytes);
      }

    } else {
      pr_response_add(R_DUP, _("No data connection"));
    }

    pr_response_add(R_DUP, _("End of status"));
    return PR_HANDLED(cmd);
  }

  list_nfiles.curr = list_ndirs.curr = list_ndepth.curr = 0;
  list_nfiles.logged = list_ndirs.logged = list_ndepth.logged = FALSE;

  decoded_path = pr_fs_decode_path2(cmd->tmp_pool, arg,
    FSIO_DECODE_FL_TELL_ERRORS);
  if (decoded_path == NULL) {
    int xerrno = errno;

    pr_log_debug(DEBUG8, "'%s' failed to decode properly: %s", arg,
      strerror(xerrno));
    pr_response_add_err(R_550, _("%s: Illegal character sequence in filename"),
      arg);

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  arg = decoded_path;

  /* Get to the actual argument. */
  if (*arg == '-') {
    while (arg && *arg && !PR_ISSPACE(*arg)) {
      arg++;
    }
  }

  while (arg && *arg && PR_ISSPACE(*arg)) {
    arg++;
  }

  ptr = get_param_ptr(TOPLEVEL_CONF, "ShowSymlinks", FALSE);
  if (ptr != NULL) {
    list_show_symlinks = *ptr;
  }

  list_strict_opts = FALSE;
  list_ndepth.max = list_nfiles.max = list_ndirs.max = 0;

  c = find_config(CURRENT_CONF, CONF_PARAM, "ListOptions", FALSE);
  while (c != NULL) {
    unsigned long flags;

    pr_signals_handle();

    flags = *((unsigned long *) c->argv[5]);

    /* Make sure that this ListOptions can be applied to the STAT command.
     * If not, keep looking for other applicable ListOptions.
     */
    if (flags & LS_FL_LIST_ONLY) {
      pr_log_debug(DEBUG10, "%s: skipping LISTOnly ListOptions",
        (char *) cmd->argv[0]);
      c = find_config_next(c, c->next, CONF_PARAM, "ListOptions", FALSE);
      continue;
    }

    if (flags & LS_FL_NLST_ONLY) {
      pr_log_debug(DEBUG10, "%s: skipping NLSTOnly ListOptions",
        (char *) cmd->argv[0]);
      c = find_config_next(c, c->next, CONF_PARAM, "ListOptions", FALSE);
      continue;
    }

    list_options = c->argv[0];
    list_strict_opts = *((unsigned char *) c->argv[1]);

    list_ndepth.max = *((unsigned int *) c->argv[2]);

    /* We add one to the configured maxdepth in order to allow it to
     * function properly: if one configures a maxdepth of 2, one should
     * allowed to list the current directory, and all subdirectories one
     * layer deeper.  For the checks to work, the maxdepth of 2 needs to
     * handled internally as a maxdepth of 3.
     */
    if (list_ndepth.max) {
      list_ndepth.max += 1;
    }

    list_nfiles.max = *((unsigned int *) c->argv[3]);
    list_ndirs.max = *((unsigned int *) c->argv[4]);
    list_flags = *((unsigned long *) c->argv[5]);

    break;
  }

  fakeuser = get_param_ptr(CURRENT_CONF, "DirFakeUser", FALSE);

  /* Check for a configured "logged in user" DirFakeUser. */
  if (fakeuser != NULL &&
      strncmp(fakeuser, "~", 2) == 0) {
    fakeuser = session.user;
  }

  fakegroup = get_param_ptr(CURRENT_CONF, "DirFakeGroup", FALSE);

  /* Check for a configured "logged in user" DirFakeGroup. */
  if (fakegroup != NULL &&
      strncmp(fakegroup, "~", 2) == 0) {
    fakegroup = session.group;
  }

  fake_mode = get_param_ptr(CURRENT_CONF, "DirFakeMode", FALSE);
  if (fake_mode) {
    fakemode = *fake_mode;
    have_fake_mode = TRUE;

  } else {
    have_fake_mode = FALSE;
  }

  ptr = get_param_ptr(TOPLEVEL_CONF, "TimesGMT", FALSE);
  if (ptr != NULL) {
    list_times_gmt = *ptr;
  }

  opt_C = opt_d = opt_F = opt_R = 0;
  opt_a = opt_l = opt_STAT = 1;

  path = (arg && *arg) ? arg : ".";

  pr_fs_clear_cache2(path);
  if (list_show_symlinks) {
    res = pr_fsio_lstat(path, &st);

  } else {
    res = pr_fsio_stat(path, &st);
  }

  if (res < 0) {
    int xerrno = errno;

    pr_response_add_err(R_450, "%s: %s", path, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (S_ISDIR(st.st_mode)) {
    resp_code = R_212;

  } else {
    resp_code = R_213;
  }

  pr_response_add(resp_code, _("Status of %s:"),
    pr_fs_encode_path(cmd->tmp_pool, path));
  res = dolist(cmd, path, resp_code, FALSE);
  pr_response_add(resp_code, _("End of status"));
  return (res == -1 ? PR_ERROR(cmd) : PR_HANDLED(cmd));
}

MODRET ls_list(cmd_rec *cmd) {
  list_nfiles.curr = list_ndirs.curr = list_ndepth.curr = 0;
  list_nfiles.logged = list_ndirs.logged = list_ndepth.logged = FALSE;

  opt_l = 1;

  return genericlist(cmd);
}

/* NLST is a very simplistic directory listing, unlike LIST (which emulates
 * ls(1)), it only sends a list of all files/directories matching the glob(s).
 */
MODRET ls_nlst(cmd_rec *cmd) {
  char *decoded_path, *target, buf[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
  size_t targetlen = 0;
  config_rec *c = NULL;
  int res = 0, hidden = 0;
  int glob_flags = GLOB_NOSORT;
  unsigned char *tmp = NULL;

  list_nfiles.curr = list_ndirs.curr = list_ndepth.curr = 0;
  list_nfiles.logged = list_ndirs.logged = list_ndepth.logged = FALSE;

  tmp = get_param_ptr(TOPLEVEL_CONF, "ShowSymlinks", FALSE);
  if (tmp != NULL) {
    list_show_symlinks = *tmp;
  }

  decoded_path = pr_fs_decode_path2(cmd->tmp_pool, cmd->arg,
    FSIO_DECODE_FL_TELL_ERRORS);
  if (decoded_path == NULL) {
    int xerrno = errno;

    pr_log_debug(DEBUG8, "'%s' failed to decode properly: %s", cmd->arg,
      strerror(xerrno));
    pr_response_add_err(R_550, _("%s: Illegal character sequence in filename"),
      cmd->arg);

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  target = cmd->argc == 1 ? "." : decoded_path;

  c = find_config(CURRENT_CONF, CONF_PARAM, "ListOptions", FALSE);
  while (c != NULL) {
    unsigned long flags;

    pr_signals_handle();

    flags = *((unsigned long *) c->argv[5]);
    
    /* Make sure that this ListOptions can be applied to the NLST command.
     * If not, keep looking for other applicable ListOptions.
     */
    if (flags & LS_FL_LIST_ONLY) {
      pr_log_debug(DEBUG10, "%s: skipping LISTOnly ListOptions",
        (char *) cmd->argv[0]);
      c = find_config_next(c, c->next, CONF_PARAM, "ListOptions", FALSE);
      continue;
    }

    list_options = c->argv[0];
    list_strict_opts = *((unsigned char *) c->argv[1]);

    list_ndepth.max = *((unsigned int *) c->argv[2]);

    /* We add one to the configured maxdepth in order to allow it to
     * function properly: if one configures a maxdepth of 2, one should
     * allowed to list the current directory, and all subdirectories one
     * layer deeper.  For the checks to work, the maxdepth of 2 needs to
     * handled internally as a maxdepth of 3.
     */
    if (list_ndepth.max) {
      list_ndepth.max += 1;
    }

    list_nfiles.max = *((unsigned int *) c->argv[3]);
    list_ndirs.max = *((unsigned int *) c->argv[4]);
    list_flags = *((unsigned long *) c->argv[5]);

    break;
  }

  /* Clear the listing option flags. */
  opt_1 = opt_A = opt_a = opt_B = opt_C = opt_d = opt_F = opt_n = opt_r =
    opt_R = opt_S = opt_t = opt_STAT = opt_L = 0;

  if (have_options(cmd, target)) {
    if (!list_strict_opts) {
      parse_list_opts(&target, &glob_flags, FALSE);

    } else {
      char *ptr;

      /* Even if the user-given options are ignored, they still need to
       * "processed" (i.e. skip past options) in order to get to the paths.
       *
       * First, scan for options.  Any leading whitespace before options can
       * be skipped, as long as there ARE options.
       */
      ptr = target;

      while (PR_ISSPACE(*ptr)) {
        pr_signals_handle();
        ptr++;
      }

      if (*ptr == '-') {
        /* Options are found; skip past the leading whitespace. */
        target = ptr;
      }

      while (target && *target == '-') {
        /* Advance to the next whitespace */
        while (*target != '\0' && !PR_ISSPACE(*target)) {
          target++;
        }

        ptr = target;

        while (*ptr &&
               PR_ISSPACE(*ptr)) {
          pr_signals_handle();
          ptr++;
        }

        if (*ptr == '-') {
          /* Options are found; skip past the leading whitespace. */
          target = ptr;

        } else if (*target && *(target + 1) == ' ') {
          /* If the next character is a blank space, advance just one
           * character.
           */
          target++;
          break;

        } else {
          target = ptr;
          break;
        }
      }
    }
  }

  if (list_options) {
    parse_list_opts(&list_options, &glob_flags, TRUE);
  }

  /* If, after parsing out any options, the target string is empty, assume
   * the current directory (Bug#4069).
   */
  if (*target == '\0') {
    target = pstrdup(cmd->tmp_pool, ".");
  }

  /* If the target starts with '~' ... */
  if (*target == '~') {
    char pb[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
    struct passwd *pw = NULL;
    int i = 0;
    const char *p = target;

    p++;

    while (*p && *p != '/' && i < PR_TUNABLE_PATH_MAX)
      pb[i++] = *p++;
    pb[i] = '\0';

    pw = pr_auth_getpwnam(cmd->tmp_pool, i ? pb : session.user);
    if (pw != NULL) {
      pr_snprintf(pb, sizeof(pb), "%s%s", pw->pw_dir, p);
      sstrncpy(buf, pb, sizeof(buf));
      target = buf;
    }
  }

  /* If the target is a glob, get the listing of files/dirs to send. */
  if (use_globbing &&
      pr_str_is_fnmatch(target)) {
    glob_t g;
    char **path, *p;
    int globbed = FALSE;

    /* Make sure the glob_t is initialized */
    memset(&g, '\0', sizeof(glob_t));

    res = pr_fs_glob(target, glob_flags, NULL, &g);
    if (res == 0) {
      pr_log_debug(DEBUG8, "NLST: glob(3) returned %lu %s",
        (unsigned long) g.gl_pathc, g.gl_pathc != 1 ? "paths" : "path");
      globbed = TRUE;

    } else {
      if (res == GLOB_NOMATCH) {
        struct stat st;

        pr_fs_clear_cache2(target);
        if (pr_fsio_stat(target, &st) == 0) {
          pr_log_debug(DEBUG10, "NLST: glob(3) returned GLOB_NOMATCH for '%s', "
            "handling as literal path", target);

          /* Trick the following code into using the non-glob() processed path.
           */
          res = 0;
          g.gl_pathv = (char **) pcalloc(cmd->tmp_pool, 2 * sizeof(char *));
          g.gl_pathv[0] = (char *) pstrdup(cmd->tmp_pool, target);
          g.gl_pathv[1] = NULL;

        } else {
          if (list_flags & LS_FL_NO_ERROR_IF_ABSENT) {
            if (pr_data_open(NULL, "file list", PR_NETIO_IO_WR, 0) < 0) {
              int xerrno = errno;

              pr_response_add_err(R_450, "%s: %s", (char *) cmd->argv[0], 
                strerror(xerrno));

              pr_cmd_set_errno(cmd, xerrno);
              errno = xerrno;
              return PR_ERROR(cmd);
            }

            session.sf_flags |= SF_ASCII_OVERRIDE;
            pr_response_add(R_226, _("Transfer complete"));
            ls_done(cmd);

            return PR_HANDLED(cmd);
          }

          pr_response_add_err(R_450, _("No files found"));

          pr_cmd_set_errno(cmd, ENOENT);
          errno = ENOENT;
          return PR_ERROR(cmd);
        }

      } else {
        if (list_flags & LS_FL_NO_ERROR_IF_ABSENT) {
          if (pr_data_open(NULL, "file list", PR_NETIO_IO_WR, 0) < 0) {
            int xerrno = errno;

            pr_response_add_err(R_450, "%s: %s", (char *) cmd->argv[0],
              strerror(xerrno));

            pr_cmd_set_errno(cmd, xerrno);
            errno = xerrno;
            return PR_ERROR(cmd);
          }

          session.sf_flags |= SF_ASCII_OVERRIDE;
          pr_response_add(R_226, _("Transfer complete"));
          ls_done(cmd);

          return PR_HANDLED(cmd);
        }

        pr_response_add_err(R_450, _("No files found"));

        pr_cmd_set_errno(cmd, ENOENT);
        errno = ENOENT;
        return PR_ERROR(cmd);
      }
    }

    if (pr_data_open(NULL, "file list", PR_NETIO_IO_WR, 0) < 0) {
      int xerrno = errno;

      pr_response_add_err(R_450, "%s: %s", (char *) cmd->argv[0],
        strerror(xerrno));

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    session.sf_flags |= SF_ASCII_OVERRIDE;

    /* Iterate through each matching entry */
    path = g.gl_pathv;
    while (path && *path && res >= 0) {
      struct stat st;

      pr_signals_handle();

      p = *path;
      path++;

      if (*p == '.' && (!opt_A || is_dotdir(p))) {
        continue;
      }

      pr_fs_clear_cache2(p);
      if (pr_fsio_stat(p, &st) == 0) {
        /* If it's a directory... */
        if (S_ISDIR(st.st_mode)) {
          if (opt_R) {
            /* ...and we are recursing, hand off to nlstdir()...*/
            res = nlstdir(cmd, p);

          } else {
            /*...otherwise, just list the name. */
            res = nlstfile(cmd, p);
          }

        } else if (S_ISREG(st.st_mode) &&
            ls_perms(cmd->tmp_pool, cmd, p, &hidden)) {
          /* Don't display hidden files */
          if (hidden) {
            continue;
          }

          res = nlstfile(cmd, p);
        }
      }
    }

    sendline(LS_SENDLINE_FL_FLUSH, " ");
    if (globbed) {
      pr_fs_globfree(&g);
    }

  } else {
    /* A single target. If it's a directory, list the contents; if it's a
     * file, just list the file.
     */
    struct stat st;
    
    if (!is_dotdir(target)) {
      /* Clean the path. */
      if (*target != '/') {
        pr_fs_clean_path2(target, buf, sizeof(buf), 0);

      } else {
        pr_fs_clean_path(target, buf, sizeof(buf));
      }

      target = buf;

    } else {
      /* Remove any trailing separators. */
      targetlen = strlen(target);
      while (targetlen >= 1 &&
             target[targetlen-1] == '/') {
        if (strncmp(target, "/", 2) == 0) {
          break;
        }

        target[targetlen-1] = '\0';
        targetlen = strlen(target);
      }
    }

    if (!ls_perms_full(cmd->tmp_pool, cmd, target, &hidden)) {
      int xerrno = errno;

      if (xerrno == ENOENT &&
          (list_flags & LS_FL_NO_ERROR_IF_ABSENT)) {
        if (pr_data_open(NULL, "file list", PR_NETIO_IO_WR, 0) < 0) {
          xerrno = errno;

          pr_response_add_err(R_450, "%s: %s", (char *) cmd->argv[0],
            strerror(xerrno));

          pr_cmd_set_errno(cmd, xerrno);
          errno = xerrno;
          return PR_ERROR(cmd);
        }
        session.sf_flags |= SF_ASCII_OVERRIDE;
        pr_response_add(R_226, _("Transfer complete"));
        ls_done(cmd);

        return PR_HANDLED(cmd);
      }

      pr_response_add_err(R_450, "%s: %s", *cmd->arg ? cmd->arg :
        pr_fs_encode_path(cmd->tmp_pool, session.vwd), strerror(xerrno));

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    /* Don't display hidden files */
    if (hidden) {
      c = find_ls_limit(target);
      if (c) {
        unsigned char *ignore_hidden;
        int xerrno;

        ignore_hidden = get_param_ptr(c->subset, "IgnoreHidden", FALSE);
        if (ignore_hidden &&
            *ignore_hidden == TRUE) {

          if (list_flags & LS_FL_NO_ERROR_IF_ABSENT) {
            if (pr_data_open(NULL, "file list", PR_NETIO_IO_WR, 0) < 0) {
              xerrno = errno;

              pr_response_add_err(R_450, "%s: %s", (char *) cmd->argv[0],
                strerror(xerrno));

              pr_cmd_set_errno(cmd, xerrno);
              errno = xerrno;
              return PR_ERROR(cmd);
            }
            session.sf_flags |= SF_ASCII_OVERRIDE;
            pr_response_add(R_226, _("Transfer complete"));
            ls_done(cmd);

            return PR_HANDLED(cmd);
          }

          xerrno = ENOENT;

        } else {
          xerrno = EACCES;
        }

        pr_response_add_err(R_450, "%s: %s",
          pr_fs_encode_path(cmd->tmp_pool, target), strerror(xerrno));

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return PR_ERROR(cmd);
      }
    }

    /* Make sure the target is a file or directory, and that we have access
     * to it.
     */
    pr_fs_clear_cache2(target);
    if (pr_fsio_stat(target, &st) < 0) {
      int xerrno = errno;

      if (xerrno == ENOENT &&
          (list_flags & LS_FL_NO_ERROR_IF_ABSENT)) {
        if (pr_data_open(NULL, "file list", PR_NETIO_IO_WR, 0) < 0) {
          xerrno = errno;

          pr_response_add_err(R_450, "%s: %s", (char *) cmd->argv[0],
            strerror(xerrno));

          pr_cmd_set_errno(cmd, xerrno);
          errno = xerrno;
          return PR_ERROR(cmd);
        }
        session.sf_flags |= SF_ASCII_OVERRIDE;
        pr_response_add(R_226, _("Transfer complete"));
        ls_done(cmd);

        return PR_HANDLED(cmd);
      }

      pr_response_add_err(R_450, "%s: %s", cmd->arg, strerror(xerrno));

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    if (S_ISREG(st.st_mode)) {
      if (pr_data_open(NULL, "file list", PR_NETIO_IO_WR, 0) < 0) {
        int xerrno = errno;

        pr_response_add_err(R_450, "%s: %s", (char *) cmd->argv[0],
          strerror(xerrno));

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return PR_ERROR(cmd);
      }
      session.sf_flags |= SF_ASCII_OVERRIDE;

      res = nlstfile(cmd, target);

    } else if (S_ISDIR(st.st_mode)) {
      if (pr_data_open(NULL, "file list", PR_NETIO_IO_WR, 0) < 0) {
        int xerrno = errno;

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return PR_ERROR(cmd);
      }
      session.sf_flags |= SF_ASCII_OVERRIDE;

      res = nlstdir(cmd, target);

    } else {
      pr_response_add_err(R_450, _("%s: Not a regular file"), cmd->arg);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);
    }

    sendline(LS_SENDLINE_FL_FLUSH, " ");
  }

  if (XFER_ABORTED) {
    pr_data_abort(0, 0);
    res = -1;

  } else {
    /* Note that the data connection is NOT cleared here, as an error in
     * NLST still leaves data ready for another command.
     */
    ls_done(cmd);
  }

  return (res < 0 ? PR_ERROR(cmd) : PR_HANDLED(cmd));
}

/* Check for the UseGlobbing setting, if any, after the PASS command has
 * been successfully handled.
 */
MODRET ls_post_pass(cmd_rec *cmd) {
  unsigned char *globbing = NULL;

  globbing = get_param_ptr(TOPLEVEL_CONF, "UseGlobbing", FALSE);
  if (globbing != NULL &&
      *globbing == FALSE) {
    pr_log_debug(DEBUG3, "UseGlobbing: disabling globbing functionality");
    use_globbing = FALSE;
  }

  return PR_DECLINED(cmd);
}

/* Configuration handlers
 */

MODRET set_dirfakeusergroup(cmd_rec *cmd) {
  int bool = -1;
  char *as = "ftp";
  config_rec *c = NULL;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL|
    CONF_DIR|CONF_DYNDIR);

  if (cmd->argc < 2 ||
      cmd->argc > 3) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "syntax: ", (char *) cmd->argv[0],
      " on|off [<id to display>]", NULL));
  }

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
     CONF_ERROR(cmd, "expected boolean argument");
  }

  if (bool == TRUE) {
    /* Use the configured ID to display rather than the default "ftp". */
    if (cmd->argc > 2) {
      as = cmd->argv[2];
    }

    c = add_config_param_str(cmd->argv[0], 1, as);

  } else {
    /* Still need to add a config_rec to turn off the display of fake IDs. */
    c = add_config_param_str(cmd->argv[0], 0);
  }

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

MODRET set_dirfakemode(cmd_rec *cmd) {
  config_rec *c = NULL;
  char *endp = NULL;
  mode_t fake_mode;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR|
    CONF_DYNDIR);

  fake_mode = (mode_t) strtol(cmd->argv[1], &endp, 8);

  if (endp && *endp)
    CONF_ERROR(cmd, "parameter must be an octal number");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(mode_t));
  *((mode_t *) c->argv[0]) = fake_mode;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET set_listoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  unsigned long flags = 0;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR|CONF_DYNDIR);

  c = add_config_param(cmd->argv[0], 6, NULL, NULL, NULL, NULL, NULL, NULL);
  c->flags |= CF_MERGEDOWN;
  
  c->argv[0] = pstrdup(c->pool, cmd->argv[1]);

  /* The default "strict" setting. */
  c->argv[1] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[1]) = FALSE;

  /* The default "maxdepth" setting. */
  c->argv[2] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[2]) = 0;

  /* The default "maxfiles" setting. */
  c->argv[3] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[3]) = 0;

  /* The default "maxdirs" setting. */
  c->argv[4] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[4]) = 0;

  /* The default flags */
  c->argv[5] = pcalloc(c->pool, sizeof(unsigned long));
 
  /* Check for, and handle, optional arguments. */
  if (cmd->argc-1 >= 2) {
    register unsigned int i = 0;

    for (i = 2; i < cmd->argc; i++) {

      if (strcasecmp(cmd->argv[i], "strict") == 0) {
        *((unsigned int *) c->argv[1]) = TRUE;

      } else if (strcasecmp(cmd->argv[i], "maxdepth") == 0) {
        int maxdepth = atoi(cmd->argv[++i]);

        if (maxdepth < 1) {
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
            ": maxdepth must be greater than 0: '", cmd->argv[i],
            "'", NULL));
        }

        *((unsigned int *) c->argv[2]) = maxdepth;

      } else if (strcasecmp(cmd->argv[i], "maxfiles") == 0) {
        int maxfiles = atoi(cmd->argv[++i]);

        if (maxfiles < 1) {
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
            ": maxfiles must be greater than 0: '", (char *) cmd->argv[i],
            "'", NULL));
        }

        *((unsigned int *) c->argv[3]) = maxfiles;

      } else if (strcasecmp(cmd->argv[i], "maxdirs") == 0) {
        int maxdirs = atoi(cmd->argv[++i]);

        if (maxdirs < 1) {
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
            ": maxdirs must be greater than 0: '", (char *) cmd->argv[i],
            "'", NULL));
        }

        *((unsigned int *) c->argv[4]) = maxdirs;

      } else if (strcasecmp(cmd->argv[i], "LISTOnly") == 0) {
        flags |= LS_FL_LIST_ONLY;

      } else if (strcasecmp(cmd->argv[i], "NLSTOnly") == 0) {
        flags |= LS_FL_NLST_ONLY;

      } else if (strcasecmp(cmd->argv[i], "NoErrorIfAbsent") == 0) {
        flags |= LS_FL_NO_ERROR_IF_ABSENT;

      } else if (strcasecmp(cmd->argv[i], "AdjustedSymlinks") == 0) {
        flags |= LS_FL_ADJUSTED_SYMLINKS;

      } else if (strcasecmp(cmd->argv[i], "NoAdjustedSymlinks") == 0) {
        /* Ignored, for backward compatibility. */

      } else if (strcasecmp(cmd->argv[i], "SortedNLST") == 0) {
        flags |= LS_FL_SORTED_NLST;

      } else {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown keyword: '",
          (char *) cmd->argv[i], "'", NULL));
      }
    }
  }

  *((unsigned long *) c->argv[5]) = flags;
  return PR_HANDLED(cmd);
}

MODRET set_showsymlinks(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if ((bool = get_boolean(cmd, 1)) == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET set_useglobbing(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* Initialization routines
 */

static int ls_init(void) {

  /* Add the commands handled by this module to the HELP list. */
  pr_help_add(C_LIST, _("[<sp> pathname]"), TRUE);
  pr_help_add(C_NLST, _("[<sp> (pathname)]"), TRUE);
  pr_help_add(C_STAT, _("[<sp> pathname]"), TRUE);

  return 0;
}

/* Module API tables
 */

static conftable ls_conftab[] = {
  { "DirFakeUser",	set_dirfakeusergroup,			NULL },
  { "DirFakeGroup",	set_dirfakeusergroup,			NULL },
  { "DirFakeMode",	set_dirfakemode,			NULL },
  { "ListOptions",	set_listoptions,			NULL },
  { "ShowSymlinks",	set_showsymlinks,			NULL },
  { "UseGlobbing",	set_useglobbing,			NULL },
  { NULL,		NULL,					NULL }
};

static cmdtable ls_cmdtab[] = {
  { CMD,  	C_NLST,	G_DIRS,	ls_nlst,	TRUE, FALSE, CL_DIRS },
  { CMD,	C_LIST,	G_DIRS,	ls_list,	TRUE, FALSE, CL_DIRS },
  { CMD, 	C_STAT,	G_DIRS,	ls_stat,	TRUE, FALSE, CL_INFO },
  { POST_CMD,	C_PASS,	G_NONE,	ls_post_pass,	FALSE, FALSE },
  { LOG_CMD,	C_LIST,	G_NONE,	ls_log_nlst,	FALSE, FALSE },
  { LOG_CMD,	C_NLST, G_NONE,	ls_log_nlst,	FALSE, FALSE },
  { LOG_CMD_ERR,C_LIST, G_NONE, ls_err_nlst,   FALSE, FALSE },
  { LOG_CMD_ERR,C_NLST, G_NONE, ls_err_nlst,   FALSE, FALSE },
  { 0, NULL }
};

module ls_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "ls",

  /* Module configuration handler table */
  ls_conftab,

  /* Module command handler table */
  ls_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  ls_init,

  /* Session initialization */
  NULL
};
