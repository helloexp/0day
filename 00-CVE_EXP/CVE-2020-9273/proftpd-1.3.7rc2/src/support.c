/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2019 The ProFTPD Project team
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

/* Various basic support routines for ProFTPD, used by all modules
 * and not specific to one or another.
 */

#include "conf.h"

#ifdef PR_USE_OPENSSL
# include <openssl/crypto.h>
#endif /* PR_USE_OPENSSL */

/* Keep a counter of the number of times signals_block()/signals_unblock()
 * have been called, to handle nesting of calls.
 */
static unsigned int sigs_nblocked = 0;

typedef struct sched_obj {
  struct sched_obj *next, *prev;

  pool *pool;
  void (*cb)(void *, void *, void *, void *);
  int nloops;
  void *arg1, *arg2, *arg3, *arg4;
} sched_t;

static xaset_t *scheds = NULL;

/* Masks/unmasks all important signals (as opposed to blocking alarms)
 */
static void mask_signals(unsigned char block) {
  static sigset_t mask_sigset;

  if (block) {
    sigemptyset(&mask_sigset);

    sigaddset(&mask_sigset, SIGTERM);
    sigaddset(&mask_sigset, SIGCHLD);
    sigaddset(&mask_sigset, SIGUSR1);
    sigaddset(&mask_sigset, SIGINT);
    sigaddset(&mask_sigset, SIGQUIT);
    sigaddset(&mask_sigset, SIGALRM);
#ifdef SIGIO
    sigaddset(&mask_sigset, SIGIO);
#endif
#ifdef SIGBUS
    sigaddset(&mask_sigset, SIGBUS);
#endif
    sigaddset(&mask_sigset, SIGHUP);

    if (sigprocmask(SIG_BLOCK, &mask_sigset, NULL) < 0) {
      pr_log_pri(PR_LOG_NOTICE,
        "unable to block signal set: %s", strerror(errno));
    }

  } else {
    if (sigprocmask(SIG_UNBLOCK, &mask_sigset, NULL) < 0) {
      pr_log_pri(PR_LOG_NOTICE,
        "unable to unblock signal set: %s", strerror(errno));
    }
  }
}

void pr_signals_block(void) {
  if (sigs_nblocked == 0) {
    mask_signals(TRUE);
    pr_trace_msg("signal", 5, "signals blocked");

  } else {
    pr_trace_msg("signal", 9, "signals already blocked (block count = %u)",
      sigs_nblocked);
  }

  sigs_nblocked++;
}

void pr_signals_unblock(void) {
  if (sigs_nblocked == 0) {
    pr_trace_msg("signal", 5, "signals already unblocked");
    return;
  }

  if (sigs_nblocked == 1) {
    mask_signals(FALSE);
    pr_trace_msg("signal", 5, "signals unblocked");

  } else {
    pr_trace_msg("signal", 9, "signals already unblocked (block count = %u)",
      sigs_nblocked);
  }

  sigs_nblocked--;
}

void schedule(void (*cb)(void *, void *, void *, void *), int nloops,
    void *arg1, void *arg2, void *arg3, void *arg4) {
  pool *p, *sub_pool;
  sched_t *s;

  if (cb == NULL ||
      nloops < 0) {
    return;
  }

  if (scheds == NULL) {
    p = make_sub_pool(permanent_pool);
    pr_pool_tag(p, "Schedules Pool");
    scheds = xaset_create(p, NULL);

  } else {
    p = scheds->pool;
  }

  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "schedule pool");

  s = pcalloc(sub_pool, sizeof(sched_t));
  s->pool = sub_pool;
  s->cb = cb;
  s->arg1 = arg1;
  s->arg2 = arg2;
  s->arg3 = arg3;
  s->arg4 = arg4;
  s->nloops = nloops;
  xaset_insert(scheds, (xasetmember_t *) s);
}

void run_schedule(void) {
  sched_t *s, *snext;

  if (scheds == NULL ||
      scheds->xas_list == NULL) {
    return;
  }

  for (s = (sched_t *) scheds->xas_list; s; s = snext) {
    snext = s->next;

    pr_signals_handle();

    if (s->nloops-- <= 0) {
      s->cb(s->arg1, s->arg2, s->arg3, s->arg4);
      xaset_remove(scheds, (xasetmember_t *) s);
      destroy_pool(s->pool);
    }
  }
}

/* Get the maximum size of a file name (pathname component).
 * If a directory file descriptor, e.g. the d_fd DIR structure element,
 * is not available, the second argument should be 0.
 *
 * Note: a POSIX compliant system typically should NOT define NAME_MAX,
 * since the value almost certainly varies across different file system types.
 * Refer to POSIX 1003.1a, Section 2.9.5, Table 2-5.
 * Alas, current (Jul 2000) Linux systems define NAME_MAX anyway.
 * NB: NAME_MAX_GUESS is defined in support.h.
 */

static int get_fpathconf_name_max(int fd, long *name_max) {
#if defined(HAVE_FPATHCONF)
  *name_max = fpathconf(fd, _PC_NAME_MAX);
  return 0;
#else
  errno = ENOSYS;
  return -1;
#endif /* HAVE_FPATHCONF */
}

static int get_pathconf_name_max(char *dir, long *name_max) {
#if defined(HAVE_PATHCONF)
  *name_max = pathconf(dir, _PC_NAME_MAX);
  return 0;
#else
  errno = ENOSYS;
  return -1;
#endif /* HAVE_PATHCONF */
}

long get_name_max(char *dir_name, int dir_fd) {
  int res;
  long name_max = 0;

  if (dir_name == NULL &&
      dir_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  /* Try the fd first. */
  if (dir_fd >= 0) {
    res = get_fpathconf_name_max(dir_fd, &name_max);
    if (res == 0) {
      if (name_max < 0) {
        int xerrno = errno;

        pr_log_debug(DEBUG5, "fpathconf() error for fd %d: %s", dir_fd,
          strerror(xerrno));

        errno = xerrno;
        return -1;
      }

      return name_max;
    }
  }

  /* Name, then. */
  if (dir_name != NULL) {
    res = get_pathconf_name_max(dir_name, &name_max);
    if (res == 0) {
      if (name_max < 0) {
        int xerrno = errno;

        pr_log_debug(DEBUG5, "pathconf() error for name '%s': %s", dir_name,
          strerror(xerrno));

        errno = xerrno;
        return -1;
      }

      return name_max;
    }
  }

  errno = ENOSYS;
  return -1;
}

/* Interpolates a pathname, expanding ~ notation if necessary
 */
char *dir_interpolate(pool *p, const char *path) {
  struct passwd *pw;
  char *res = NULL;

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (*path == '~') {
    char *ptr, *user;

    user = pstrdup(p, path + 1);
    ptr = strchr(user, '/');
    if (ptr != NULL) {
      *ptr++ = '\0';
    }

    if (!*user) {
      user = (char *) session.user;
    }

    pw = pr_auth_getpwnam(p, user);
    if (pw == NULL) {
      errno = ENOENT;
      return NULL;
    }

    res = pdircat(p, pw->pw_dir, ptr, NULL);

  } else {
    res = pstrdup(p, path);
  }

  return res;
}

/* dir_best_path() creates the "most" fully canonicalized path possible
 * (i.e. if path components at the end don't exist, they are ignored).
 */
char *dir_best_path(pool *p, const char *path) {
  char workpath[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
  char realpath_buf[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
  char *target = NULL, *ntarget;
  int fini = 0;

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (*path == '~') {
    if (pr_fs_interpolate(path, workpath, sizeof(workpath)-1) != 1) {
      if (pr_fs_dircat(workpath, sizeof(workpath), pr_fs_getcwd(), path) < 0) {
        return NULL;
      }
    }

  } else {
    if (pr_fs_dircat(workpath, sizeof(workpath), pr_fs_getcwd(), path) < 0) {
      return NULL;
    }
  }

  pr_fs_clean_path(pstrdup(p, workpath), workpath, sizeof(workpath)-1);

  while (!fini && *workpath) {
    if (pr_fs_resolve_path(workpath, realpath_buf,
        sizeof(realpath_buf)-1, 0) != -1) {
      break;
    }

    ntarget = strrchr(workpath, '/');
    if (ntarget) {
      if (target) {
        if (pr_fs_dircat(workpath, sizeof(workpath), workpath, target) < 0) {
          return NULL;
        }
      }

      target = ntarget;
      *target++ = '\0';

    } else {
      fini++;
    }
  }

  if (!fini && *workpath) {
    if (target) {
      if (pr_fs_dircat(workpath, sizeof(workpath), realpath_buf, target) < 0) {
        return NULL;
      }

    } else {
      sstrncpy(workpath, realpath_buf, sizeof(workpath));
    }

  } else {
    if (pr_fs_dircat(workpath, sizeof(workpath), "/", target) < 0) {
      return NULL;
    }
  }

  return pstrdup(p, workpath);
}

char *dir_canonical_path(pool *p, const char *path) {
  char buf[PR_TUNABLE_PATH_MAX + 1]  = {'\0'};
  char work[PR_TUNABLE_PATH_MAX + 1] = {'\0'};

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (*path == '~') {
    if (pr_fs_interpolate(path, work, sizeof(work)-1) != 1) {
      if (pr_fs_dircat(work, sizeof(work), pr_fs_getcwd(), path) < 0) {
        return NULL;
      }
    }

  } else {
    if (pr_fs_dircat(work, sizeof(work), pr_fs_getcwd(), path) < 0) {
      return NULL;
    }
  }

  pr_fs_clean_path(work, buf, sizeof(buf)-1);
  return pstrdup(p, buf);
}

char *dir_canonical_vpath(pool *p, const char *path) {
  char buf[PR_TUNABLE_PATH_MAX + 1]  = {'\0'};
  char work[PR_TUNABLE_PATH_MAX + 1] = {'\0'};

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (*path == '~') {
    if (pr_fs_interpolate(path, work, sizeof(work)-1) != 1) {
      if (pr_fs_dircat(work, sizeof(work), pr_fs_getvwd(), path) < 0) {
        return NULL;
      }
    }

  } else {
    if (pr_fs_dircat(work, sizeof(work), pr_fs_getvwd(), path) < 0) {
      return NULL;
    }
  }

  pr_fs_clean_path(work, buf, sizeof(buf)-1);
  return pstrdup(p, buf);
}

/* Performs chroot-aware handling of symlinks. */
int dir_readlink(pool *p, const char *path, char *buf, size_t bufsz,
    int flags) {
  int is_abs_dst, clean_flags, len, res = -1;
  size_t chroot_pathlen = 0, adj_pathlen = 0;
  char *dst_path, *adj_path;
  pool *tmp_pool;

  if (p == NULL ||
      path == NULL ||
      buf == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (bufsz == 0) {
    return 0;
  }

  len = pr_fsio_readlink(path, buf, bufsz);
  if (len < 0) {
    return -1;
  }

  pr_trace_msg("fsio", 9,
    "dir_readlink() read link '%.*s' for path '%s'", (int) len, buf, path);

  if (len == 0 ||
      (size_t) len == bufsz) {
    /* If we read nothing in, OR if the given buffer was completely
     * filled WITHOUT terminating NUL, there's really nothing we can/should
     * be doing.
     */
    return len;
  }

  is_abs_dst = FALSE;
  if (*buf == '/') {
    is_abs_dst = TRUE;
  }

  if (session.chroot_path != NULL) {
    chroot_pathlen = strlen(session.chroot_path);
  }

  if (chroot_pathlen <= 1) {
    char *ptr;

    if (is_abs_dst == TRUE ||
        !(flags & PR_DIR_READLINK_FL_HANDLE_REL_PATH)) {
      return len;
    }

    /* Since we have a relative destination path, we will concat it
     * with the source path's directory, then clean up that path.
     */
    ptr = strrchr(path, '/');
    if (ptr != NULL &&
        ptr != path) {
      char *parent_dir;

      tmp_pool = make_sub_pool(p);
      pr_pool_tag(tmp_pool, "dir_readlink pool");

      parent_dir = pstrndup(tmp_pool, path, (ptr - path));
      dst_path = pdircat(tmp_pool, parent_dir, buf, NULL);

      adj_pathlen = bufsz + 1;
      adj_path = pcalloc(tmp_pool, adj_pathlen);

      res = pr_fs_clean_path2(dst_path, adj_path, adj_pathlen-1, 0);
      if (res == 0) {
        pr_trace_msg("fsio", 19,
          "cleaned symlink path '%s', yielding '%s'", dst_path, adj_path);
        dst_path = adj_path;
      }

      pr_trace_msg("fsio", 19,
        "adjusted relative symlink path '%s', yielding '%s'", buf, dst_path);

      memset(buf, '\0', bufsz);
      sstrncpy(buf, dst_path, bufsz);
      len = strlen(buf);
      destroy_pool(tmp_pool);
    }

    return len;
  }

  if (is_abs_dst == FALSE) {
    /* If we are to ignore relative destination paths, return now. */
    if (!(flags & PR_DIR_READLINK_FL_HANDLE_REL_PATH)) {
      return len;
    }
  }

  if (is_abs_dst == TRUE &&
      (size_t) len < chroot_pathlen) {
    /* If the destination path length is shorter than the chroot path,
     * AND the destination path is absolute, then by definition it CANNOT
     * point within the chroot.
     */
    return len;
  }

  tmp_pool = make_sub_pool(p);
  pr_pool_tag(tmp_pool, "dir_readlink pool");

  dst_path = pstrdup(tmp_pool, buf);
  if (is_abs_dst == FALSE) {
    char *ptr;

    /* Since we have a relative destination path, we will concat it
     * with the source path's directory, then clean up that path.
     */

    ptr = strrchr(path, '/');
    if (ptr != NULL) {
      if (ptr != path) {
        char *parent_dir;

        parent_dir = pstrndup(tmp_pool, path, (ptr - path));
        dst_path = pdircat(tmp_pool, parent_dir, dst_path, NULL);

      } else {
        dst_path = pdircat(tmp_pool, "/", dst_path, NULL);
      }
    }
  }

  adj_pathlen = bufsz + 1;
  adj_path = pcalloc(tmp_pool, adj_pathlen);

  clean_flags = PR_FSIO_CLEAN_PATH_FL_MAKE_ABS_PATH;
  res = pr_fs_clean_path2(dst_path, adj_path, adj_pathlen-1, clean_flags);
  if (res == 0) {
    pr_trace_msg("fsio", 19,
      "cleaned symlink path '%s', yielding '%s'", dst_path, adj_path);
    dst_path = adj_path;

    memset(buf, '\0', bufsz);
    sstrncpy(buf, dst_path, bufsz);
    len = strlen(dst_path);
  }

  if (strncmp(dst_path, session.chroot_path, chroot_pathlen) == 0 &&
      *(dst_path + chroot_pathlen) == '/') {
    char *ptr;

    ptr = dst_path + chroot_pathlen;

    if (is_abs_dst == FALSE &&
        res == 0) {
      /* If we originally had a relative destination path, AND we cleaned
       * that adjusted path, then we should try to re-adjust the path
       * back to being a relative path.  Within reason.
       */
      ptr = pstrcat(tmp_pool, ".", ptr, NULL);
    }

    /* Since we are making the destination path shorter, the given buffer
     * (which was big enough for the original destination path) should
     * always be large enough for this adjusted, shorter version.  Right?
     */
    pr_trace_msg("fsio", 19,
      "adjusted symlink path '%s' for chroot '%s', yielding '%s'",
      dst_path, session.chroot_path, ptr);

    memset(buf, '\0', bufsz);
    sstrncpy(buf, ptr, bufsz);
    len = strlen(buf);
  }

  destroy_pool(tmp_pool);
  return len;
}

/* dir_realpath() is needed to properly dereference symlinks (getcwd() may
 * not work if permissions cause problems somewhere up the tree).
 */
char *dir_realpath(pool *p, const char *path) {
  char buf[PR_TUNABLE_PATH_MAX + 1] = {'\0'};

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (pr_fs_resolve_partial(path, buf, sizeof(buf)-1, 0) < 0) {
    return NULL;
  }

  return pstrdup(p, buf);
}

/* Takes a directory and returns its absolute version.  ~username references
 * are appropriately interpolated.  "Absolute" includes a _full_ reference
 * based on the root directory, not upon a chrooted dir.
 */
char *dir_abs_path(pool *p, const char *path, int interpolate) {
  char *res = NULL;

  if (p == NULL ||
      path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (interpolate) {
    char buf[PR_TUNABLE_PATH_MAX+1];

    memset(buf, '\0', sizeof(buf));
    switch (pr_fs_interpolate(path, buf, sizeof(buf)-1)) {
      case -1:
        return NULL;

      case 0:
        /* Do nothing; path exists */
        break;

      case 1:
        /* Interpolation occurred; make a copy of the interpolated path. */
        path = pstrdup(p, buf);
        break;
    }
  }

  if (*path != '/') {
    if (session.chroot_path) {
      res = pdircat(p, session.chroot_path, pr_fs_getcwd(), path, NULL);

    } else {
      res = pdircat(p, pr_fs_getcwd(), path, NULL);
    }

  } else {
    if (session.chroot_path) {
      if (strncmp(path, session.chroot_path,
          strlen(session.chroot_path)) != 0) {
        res = pdircat(p, session.chroot_path, path, NULL);
 
      } else {
        res = pstrdup(p, path);
      }
 
    } else {
      res = pstrdup(p, path);
    }
  }

  return res;
}

/* Return the mode (including the file type) of the file pointed to by symlink
 * PATH, or 0 if it doesn't exist. Catch symlink loops using LAST_INODE and
 * RCOUNT.
 */
static mode_t _symlink(pool *p, const char *path, ino_t last_inode,
    int rcount) {
  char buf[PR_TUNABLE_PATH_MAX + 1];
  struct stat st;
  int i;

  if (++rcount >= PR_FSIO_MAX_LINK_COUNT) {
    errno = ELOOP;
    return 0;
  }

  memset(buf, '\0', sizeof(buf));

  if (p != NULL) {
    i = dir_readlink(p, path, buf, sizeof(buf)-1,
      PR_DIR_READLINK_FL_HANDLE_REL_PATH);
  } else {
    i = pr_fsio_readlink(path, buf, sizeof(buf)-1);
  }

  if (i < 0) {
    return (mode_t) 0;
  }
  buf[i] = '\0';

  pr_fs_clear_cache2(buf);
  if (pr_fsio_lstat(buf, &st) >= 0) {
    if (st.st_ino > 0 &&
        (ino_t) st.st_ino == last_inode) {
      errno = ELOOP;
      return 0;
    }

    if (S_ISLNK(st.st_mode)) {
      return _symlink(p, buf, (ino_t) st.st_ino, rcount);
    }

    return st.st_mode;
  }

  return 0;
}

mode_t symlink_mode2(pool *p, const char *path) {
  if (path == NULL) {
    errno = EINVAL;
    return 0;
  }

  return _symlink(p, path, (ino_t) 0, 0);
}

mode_t symlink_mode(const char *path) {
  return symlink_mode2(NULL, path);
}

mode_t file_mode2(pool *p, const char *path) {
  struct stat st;
  mode_t mode = 0;

  if (path == NULL) {
    errno = EINVAL;
    return mode;
  }

  pr_fs_clear_cache2(path);
  if (pr_fsio_lstat(path, &st) >= 0) {
    if (S_ISLNK(st.st_mode)) {
      mode = _symlink(p, path, (ino_t) 0, 0);
      if (mode == 0) {
	/* a dangling symlink, but it exists to rename or delete. */
	mode = st.st_mode;
      }

    } else {
      mode = st.st_mode;
    }
  }

  return mode;
}

mode_t file_mode(const char *path) {
  return file_mode2(NULL, path);
}

/* If flags == 1, fail unless PATH is an existing directory.
 * If flags == 0, fail unless PATH is an existing non-directory.
 * If flags == -1, fail unless PATH exists; the caller doesn't care whether
 * PATH is a file or a directory.
 */
static int _exists(pool *p, const char *path, int flags) {
  mode_t mode;

  mode = file_mode2(p, path);
  if (mode != 0) {
    switch (flags) {
      case 1:
        if (!S_ISDIR(mode)) {
          return FALSE;
        }
        break;

      case 0:
        if (S_ISDIR(mode)) {
          return FALSE;
        }
        break;

      default:
        break;
    }

    return TRUE;
  }

  return FALSE;
}

int file_exists2(pool *p, const char *path) {
  return _exists(p, path, 0);
}

int file_exists(const char *path) {
  return file_exists2(NULL, path);
}

int dir_exists2(pool *p, const char *path) {
  return _exists(p, path, 1);
}

int dir_exists(const char *path) {
  return dir_exists2(NULL, path);
}

int exists2(pool *p, const char *path) {
  return _exists(p, path, -1);
}

int exists(const char *path) {
  return exists2(NULL, path);
}

/* safe_token tokenizes a string, and increments the pointer to
 * the next non-white space character.  It's "safe" because it
 * never returns NULL, only an empty string if no token remains
 * in the source string.
 */
char *safe_token(char **s) {
  char *res = "";

  if (s == NULL ||
      !*s) {
    return res;
  }

  while (PR_ISSPACE(**s) && **s) {
    (*s)++;
  }

  if (**s) {
    res = *s;

    while (!PR_ISSPACE(**s) && **s) {
      (*s)++;
    }

    if (**s) {
      *(*s)++ = '\0';
    }

    while (PR_ISSPACE(**s) && **s) {
      (*s)++;
    }
  }

  return res;
}

/* Checks for the existence of PR_SHUTMSG_PATH.  deny and disc are
 * filled with the times to deny new connections and disconnect
 * existing ones.
 */
int check_shutmsg(const char *path, time_t *shut, time_t *deny, time_t *disc,
    char *msg, size_t msg_size) {
  FILE *fp;
  char *deny_str, *disc_str, *cp, buf[PR_TUNABLE_BUFFER_SIZE+1] = {'\0'};
  char hr[3] = {'\0'}, mn[3] = {'\0'};
  time_t now, shuttime = (time_t) 0;
  struct tm *tm;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  fp = fopen(path, "r");
  if (fp != NULL) {
    struct stat st;

    if (fstat(fileno(fp), &st) == 0) {
      if (S_ISDIR(st.st_mode)) {
        fclose(fp);
        errno = EISDIR;
        return -1;
      }
    }

    cp = fgets(buf, sizeof(buf), fp);
    if (cp != NULL) {
      buf[sizeof(buf)-1] = '\0'; CHOP(cp);

      /* We use this to fill in dst, timezone, etc */
      time(&now);
      tm = pr_localtime(NULL, &now);
      if (tm == NULL) {
        fclose(fp);
        return 0;
      }

      tm->tm_year = atoi(safe_token(&cp)) - 1900;
      tm->tm_mon = atoi(safe_token(&cp)) - 1;
      tm->tm_mday = atoi(safe_token(&cp));
      tm->tm_hour = atoi(safe_token(&cp));
      tm->tm_min = atoi(safe_token(&cp));
      tm->tm_sec = atoi(safe_token(&cp));

      deny_str = safe_token(&cp);
      disc_str = safe_token(&cp);

      shuttime = mktime(tm);
      if (shuttime == (time_t) -1) {
        fclose(fp);
        return 0;
      }

      if (deny != NULL) {
        if (strlen(deny_str) == 4) {
          sstrncpy(hr, deny_str, sizeof(hr)); hr[2] = '\0'; deny_str += 2;
          sstrncpy(mn, deny_str, sizeof(mn)); mn[2] = '\0';

          *deny = shuttime - ((atoi(hr) * 3600) + (atoi(mn) * 60));

        } else {
          *deny = shuttime;
        }
      }

      if (disc != NULL) {
        if (strlen(disc_str) == 4) {
          sstrncpy(hr, disc_str, sizeof(hr)); hr[2] = '\0'; disc_str += 2;
          sstrncpy(mn, disc_str, sizeof(mn)); mn[2] = '\0';

          *disc = shuttime - ((atoi(hr) * 3600) + (atoi(mn) * 60));

        } else {
          *disc = shuttime;
        }
      }

      if (fgets(buf, sizeof(buf), fp) && msg) {
        buf[sizeof(buf)-1] = '\0';
	CHOP(buf);
        sstrncpy(msg, buf, msg_size-1);
      }
    }

    fclose(fp);
    if (shut != NULL) {
      *shut = shuttime;
    }

    return 1;
  }

  return -1;
}

#if !defined(PR_USE_OPENSSL) || OPENSSL_VERSION_NUMBER <= 0x000907000L
/* "safe" memset() (code borrowed from OpenSSL).  This function should be
 * used to clear/scrub sensitive memory areas instead of memset() for the
 * reasons mentioned in this BugTraq thread:
 *
 *  http://online.securityfocus.com/archive/1/298598
 */

static unsigned char memscrub_ctr = 0;
#endif

void pr_memscrub(void *ptr, size_t ptrlen) {
#if defined(PR_USE_OPENSSL) && OPENSSL_VERSION_NUMBER > 0x000907000L
  if (ptr == NULL ||
      ptrlen == 0) {
    return;
  }

  /* Just use OpenSSL's function for this.  They have optimized it for
   * performance in later OpenSSL releases.
   */
  OPENSSL_cleanse(ptr, ptrlen);

#else 
  unsigned char *p;
  size_t loop;

  if (ptr == NULL ||
      ptrlen == 0) {
    return;
  }

  p = ptr;
  loop = ptrlen;

  while (loop--) {
    *(p++) = memscrub_ctr++;
    memscrub_ctr += (17 + (unsigned char)((intptr_t) p & 0xF));
  }

  if (memchr(ptr, memscrub_ctr, ptrlen)) {
    memscrub_ctr += 63;
  }
#endif
}

void pr_getopt_reset(void) {
#if defined(FREEBSD4) || defined(FREEBSD5) || defined(FREEBSD6) || \
    defined(FREEBSD7) || defined(FREEBSD8) || defined(FREEBSD9) || \
    defined(FREEBSD10) || defined(FREEBSD11) || \
    defined(DARWIN7) || defined(DARWIN8) || defined(DARWIN9) || \
    defined(DARWIN10) || defined(DARWIN11) || defined(DARWIN12) || \
    defined(DARWIN13) || defined(DARWIN14) || defined(DARWIN15) || \
    defined(DARWIN16) || defined(DARWIN17) || defined(DARWIN18)
  optreset = 1;
  opterr = 1;
  optind = 1;

#elif defined(SOLARIS2) || defined(HPUX11)
  opterr = 0;
  optind = 1;

#else
  opterr = 0;
  optind = 0;
#endif /* !FreeBSD, !Mac OSX and !Solaris2 */

  if (pr_env_get(permanent_pool, "POSIXLY_CORRECT") == NULL) {
    pr_env_set(permanent_pool, "POSIXLY_CORRECT", "1");
  }
}

struct tm *pr_gmtime(pool *p, const time_t *now) {
  struct tm *sys_tm, *dup_tm;

  if (now == NULL) {
    errno = EINVAL;
    return NULL;
  }

  sys_tm = gmtime(now);
  if (sys_tm == NULL) {
    return NULL;
  }

  /* If the caller provided a pool, make a copy of the struct tm using that
   * pool.  Otherwise, return the struct tm as is.
   */
  if (p) {
    dup_tm = pcalloc(p, sizeof(struct tm));
    memcpy(dup_tm, sys_tm, sizeof(struct tm));

  } else {
    dup_tm = sys_tm;
  }

  return dup_tm;
}

struct tm *pr_localtime(pool *p, const time_t *now) {
  struct tm *sys_tm, *dup_tm;

#ifdef HAVE_TZNAME
  char *tzname_dup[2];

  /* The localtime(3) function has a nasty habit of changing the tzname
   * global variable as a side-effect.  This can cause problems, as when
   * the process has become chrooted, and localtime(3) sets/changes
   * tzname wrong.  (For more information on the tzname global variable,
   * see the tzset(3) man page.)
   *
   * The best way to deal with this issue (which is especially prominent
   * on systems running glibc-2.3 or later, which is particularly ill-behaved
   * in a chrooted environment, as it assumes the ability to find system
   * timezone files at paths which are no longer valid within the chroot)
   * is to set the TZ environment variable explicitly, before starting
   * proftpd.  You can also use the SetEnv configuration directive within
   * the proftpd.conf to set the TZ environment variable, e.g.:
   *
   *  SetEnv TZ PST
   *
   * To try to help sites which fail to do this, the tzname global variable
   * will be copied prior to the localtime(3) call, and the copy restored
   * after the call.  (Note that calling the ctime(3) and mktime(3)
   * functions also causes a similar overwriting/setting of the tzname
   * environment variable.)
   *
   * This hack is also used in the lib/pr-syslog.c code, to work around
   * mktime(3) antics.
   */
  memcpy(&tzname_dup, tzname, sizeof(tzname_dup));
#endif /* HAVE_TZNAME */

  if (now == NULL) {
    errno = EINVAL;
    return NULL;
  }

  sys_tm = localtime(now);
  if (sys_tm == NULL) {
    return NULL;
  }

  if (p) {
    /* If the caller provided a pool, make a copy of the returned
     * struct tm, allocated out of that pool.
     */
    dup_tm = pcalloc(p, sizeof(struct tm));
    memcpy(dup_tm, sys_tm, sizeof(struct tm));

  } else {

    /* Other callers do not require pool-allocated copies, and instead
     * are happy with the struct tm as is.
     */
    dup_tm = sys_tm;
  }

#ifdef HAVE_TZNAME
  /* Restore the old tzname values prior to returning. */
  memcpy(tzname, tzname_dup, sizeof(tzname_dup));
#endif /* HAVE_TZNAME */

  return dup_tm;
}

const char *pr_strtime(time_t t) {
  return pr_strtime2(t, FALSE);
}

const char *pr_strtime2(time_t t, int use_gmtime) {
  static char buf[64];
  static char *mons[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
    "Aug", "Sep", "Oct", "Nov", "Dec" };
  static char *days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
  struct tm *tr;

  memset(buf, '\0', sizeof(buf));

  if (use_gmtime) {
    tr = pr_gmtime(NULL, &t);

  } else {
    tr = pr_localtime(NULL, &t);
  }

  if (tr != NULL) {
    pr_snprintfl(__FILE__, __LINE__, buf, sizeof(buf),
      "%s %s %02d %02d:%02d:%02d %d", days[tr->tm_wday], mons[tr->tm_mon],
      tr->tm_mday, tr->tm_hour, tr->tm_min, tr->tm_sec, tr->tm_year + 1900);
  }

  buf[sizeof(buf)-1] = '\0';
  return buf;
}

int pr_timeval2millis(struct timeval *tv, uint64_t *millis) {
  if (tv == NULL ||
      millis == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Make sure to use 64-bit multiplication to avoid overflow errors,
   * as much as we can.
   */
  *millis = (tv->tv_sec * (uint64_t) 1000) + (tv->tv_usec / (uint64_t) 1000);
  return 0;
}

int pr_gettimeofday_millis(uint64_t *millis) {
  struct timeval tv;

  if (gettimeofday(&tv, NULL) < 0) {
    return -1;
  }

  if (pr_timeval2millis(&tv, millis) < 0) {
    return -1;
  }

  return 0;
}

int pr_vsnprintfl(const char *file, int lineno, char *buf, size_t bufsz,
    const char *fmt, va_list msg) {
  int res, xerrno = 0;

  if (buf == NULL ||
      fmt == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (bufsz == 0) {
    return 0;
  }

  res = vsnprintf(buf, bufsz, fmt, msg);
  xerrno = errno;

  if (res < 0) {
    /* Unexpected error. */

#ifdef EOVERFLOW
    if (xerrno == EOVERFLOW) {
      xerrno = ENOSPC;
    }
#endif /* EOVERFLOW */

  } else if ((size_t) res >= bufsz) {
    /* Buffer too small. */
    xerrno = ENOSPC;
    res = -1;
  }

  /* We are mostly concerned with tracking down the locations of truncated
   * buffers, hence the stacktrace logging only for these conditions.
   */
  if (res < 0 &&
      xerrno == ENOSPC) {
    if (file != NULL &&
        lineno > 0) {
      pr_log_pri(PR_LOG_WARNING,
        "%s:%d: error writing format string '%s' into %lu-byte buffer: %s",
        file, lineno, fmt, (unsigned long) bufsz, strerror(xerrno));

    } else {
      pr_log_pri(PR_LOG_WARNING,
        "error writing format string '%s' into %lu-byte buffer: %s", fmt,
        (unsigned long) bufsz, strerror(xerrno));
    }

    pr_log_stacktrace(-1, NULL);
  }

  errno = xerrno;
  return res;
}

int pr_vsnprintf(char *buf, size_t bufsz, const char *fmt, va_list msg) {
  return pr_vsnprintfl(NULL, -1, buf, bufsz, fmt, msg);
}

int pr_snprintfl(const char *file, int lineno, char *buf, size_t bufsz,
    const char *fmt, ...) {
  va_list msg;
  int res;

  va_start(msg, fmt);
  res = pr_vsnprintfl(file, lineno, buf, bufsz, fmt, msg);
  va_end(msg);

  return res;
}

int pr_snprintf(char *buf, size_t bufsz, const char *fmt, ...) {
  va_list msg;
  int res;

  va_start(msg, fmt);
  res = pr_vsnprintfl(NULL, -1, buf, bufsz, fmt, msg);
  va_end(msg);

  return res;
}

/* Substitute any appearance of the %u variable in the given string with
 * the value.
 */
const char *path_subst_uservar(pool *path_pool, const char **path) {
  const char *new_path = NULL, *substr_path = NULL;
  char *substr = NULL;
  size_t user_len = 0;

  /* Sanity check. */
  if (path_pool == NULL ||
      path == NULL ||
      !*path) {
    errno = EINVAL;
    return NULL;
  }

  /* If no %u string present, do nothing. */
  if (strstr(*path, "%u") == NULL) {
    return *path;
  }

  /* Same if there is no user set yet. */
  if (session.user == NULL) {
    return *path;
  }

  user_len = strlen(session.user);

  /* First, deal with occurrences of "%u[index]" strings.  Note that
   * with this syntax, the '[' and ']' characters become invalid in paths,
   * but only if that '[' appears after a "%u" string -- certainly not
   * a common phenomenon (I hope).  This means that in the future, an escape
   * mechanism may be needed in this function.  Caveat emptor.
   */

  substr_path = *path;
  substr = substr_path ? strstr(substr_path, "%u[") : NULL;
  while (substr != NULL) {
    long i = 0;
    char *substr_end = NULL, *substr_dup = NULL, *endp = NULL;
    char ref_char[2] = {'\0', '\0'};

    pr_signals_handle();

    /* Now, find the closing ']'. If not found, it is a syntax error;
     * continue on without processing this occurrence.
     */
    substr_end = strchr(substr, ']');
    if (substr_end == NULL) {
      /* Just end here. */
      break;
    }

    /* Make a copy of the entire substring. */
    substr_dup = pstrdup(path_pool, substr);

    /* The substr_end variable (used as an index) should work here, too
     * (trying to obtain the entire substring).
     */
    substr_dup[substr_end - substr + 1] = '\0';

    /* Advance the substring pointer by three characters, so that it is
     * pointing at the character after the '['.
     */
    substr += 3;

    /* If the closing ']' is the next character after the opening '[', it
     * is a syntax error.
     */
    if (*substr == ']') {
      substr_path = *path;
      break;
    }

    /* Temporarily set the ']' to '\0', to make it easy for the string
     * scanning below.
     */
    *substr_end = '\0';

    /* Scan the index string into a number, watching for bad strings. */
    i = strtol(substr, &endp, 10);
    if (endp && *endp) {
      *substr_end = ']';
      pr_trace_msg("auth", 3,
        "invalid index number syntax found in '%s', ignoring", substr);
      return *path;
    }

    /* Make sure that index is within bounds. */
    if (i < 0 ||
        (size_t) i > user_len - 1) {

      /* Put the closing ']' back. */
      *substr_end = ']';

      if (i < 0) {
        pr_trace_msg("auth", 3,
          "out-of-bounds index number (%ld) found in '%s', ignoring", i,
          substr);

      } else {
        pr_trace_msg("auth", 3,
          "out-of-bounds index number (%ld > %lu) found in '%s', ignoring", i,
          (unsigned long) user_len-1, substr);
      }

      return *path;
    }

    ref_char[0] = session.user[i];

    /* Put the closing ']' back. */
    *substr_end = ']';

    /* Now, to substitute the whole "%u[index]" substring with the
     * referenced character/string.
     */
    substr_path = sreplace(path_pool, substr_path, substr_dup, ref_char, NULL);
    substr = substr_path ? strstr(substr_path, "%u[") : NULL;
  }

  /* Check for any bare "%u", and handle those if present. */
  if (substr_path &&
      strstr(substr_path, "%u") != NULL) {
    new_path = sreplace(path_pool, substr_path, "%u", session.user, NULL);

  } else {
    new_path = substr_path;
  }

  return new_path;
}

