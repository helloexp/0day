/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2003-2017 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Home-on-demand support */

#include "conf.h"
#include "privs.h"

static const char *trace_channel = "mkhome";

static int create_dir(const char *dir, uid_t uid, gid_t gid,
    mode_t mode) {
  mode_t prev_mask;
  struct stat st;
  int res = -1;

  pr_fs_clear_cache2(dir);
  res = pr_fsio_stat(dir, &st);

  if (res == -1 &&
      errno != ENOENT) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "error checking '%s': %s", dir,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* The directory already exists. */
  if (res == 0) {
    pr_trace_msg(trace_channel, 8, "'%s' already exists", dir);
    pr_log_debug(DEBUG3, "CreateHome: '%s' already exists", dir);
    return 0;
  }

  /* The given mode is absolute, not subject to any Umask setting. */
  prev_mask = umask(0);

  if (pr_fsio_mkdir(dir, mode) < 0) {
    int xerrno = errno;

    umask(prev_mask);
    pr_log_pri(PR_LOG_WARNING, "error creating '%s': %s", dir,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  umask(prev_mask);

  if (pr_fsio_chown(dir, uid, gid) < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "error setting ownership of '%s': %s", dir,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 8, "directory '%s' created", dir);
  pr_log_debug(DEBUG6, "CreateHome: directory '%s' created", dir);
  return 0;
}

/* Walk along a path, making sure that all directories in that path exist,
 * creating them if necessary.
 */
static int create_path(pool *p, const char *path, const char *user,
    uid_t dir_uid, gid_t dir_gid, mode_t dir_mode,
    uid_t dst_uid, gid_t dst_gid, mode_t dst_mode) {
  char *currpath = NULL, *tmppath = NULL;
  struct stat st;

  pr_fs_clear_cache2(path);
  if (pr_fsio_stat(path, &st) == 0) {
    /* Path already exists, nothing to be done. */
    errno = EEXIST;
    return -1;
  }

  /* The special-case values of -1 for dir UID/GID mean that the destination
   * UID/GID should be used for the parent directories.
   */

  if (dir_uid == (uid_t) -1) {
    dir_uid = dst_uid;
  }

  if (dir_gid == (gid_t) -1) {
    dir_gid = dst_gid;
  }

  pr_trace_msg(trace_channel, 5, "creating home directory '%s' for user '%s'",
    path, user);
  pr_log_debug(DEBUG3, "creating home directory '%s' for user '%s'", path,
    user);
  tmppath = pstrdup(p, path);

  currpath = "/";
  while (tmppath && *tmppath) {
    char *currdir = strsep(&tmppath, "/");
    currpath = pdircat(p, currpath, currdir, NULL);

    /* If tmppath is NULL, we are creating the last part of the path, so we
     * use the configured mode, and chown it to the given UID and GID.
     */
    if (tmppath == NULL ||
        (*tmppath == '\0')) {
      create_dir(currpath, dst_uid, dst_gid, dst_mode);

    } else { 
      create_dir(currpath, dir_uid, dir_gid, dir_mode);
    }

    pr_signals_handle();
  }

  pr_trace_msg(trace_channel, 5, "home directory '%s' created", path);
  pr_log_debug(DEBUG3, "home directory '%s' created", path);
  return 0;
}

static int copy_symlink(pool *p, const char *src_dir, const char *src_path,
    const char *dst_dir, const char *dst_path, uid_t uid, gid_t gid) {
  char *link_path = pcalloc(p, PR_TUNABLE_BUFFER_SIZE);
  int len;

  len = pr_fsio_readlink(src_path, link_path, PR_TUNABLE_BUFFER_SIZE-1);
  if (len < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "CreateHome: error reading link '%s': %s",
      src_path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }
  link_path[len] = '\0';

  /* If the target of the link lies within the src path, rename that portion
   * of the link to be the corresponding part of the dst path.
   */
  if (strncmp(link_path, src_dir, strlen(src_dir)) == 0) {
    link_path = pdircat(p, dst_dir, link_path + strlen(src_dir), NULL);
  }

  if (pr_fsio_symlink(link_path, dst_path) < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "CreateHome: error symlinking '%s' to '%s': %s",
      link_path, dst_path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* Make sure the new symlink has the proper ownership. */
  if (pr_fsio_chown(dst_path, uid, gid) < 0) {
    pr_log_pri(PR_LOG_WARNING, "CreateHome: error chown'ing '%s' to %s/%s: %s",
      dst_path, pr_uid2str(p, uid), pr_gid2str(p, gid), strerror(errno));
  }

  return 0; 
}

/* srcdir is to be considered a "skeleton" directory, in the manner of
 * /etc/skel, and destdir is a user's newly created home directory that needs
 * to be populated with the files in srcdir.
 */
static int copy_dir(pool *p, const char *src_dir, const char *dst_dir,
    uid_t uid, gid_t gid) {
  DIR *dh = NULL;
  struct dirent *dent = NULL;

  dh = opendir(src_dir);
  if (dh == NULL) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "CreateHome: error copying '%s' skel files: %s",
      src_dir, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  while ((dent = readdir(dh)) != NULL) {
    struct stat st;
    char *src_path, *dst_path;

    pr_signals_handle();

    /* Skip "." and ".." */
    if (strncmp(dent->d_name, ".", 2) == 0 ||
        strncmp(dent->d_name, "..", 3) == 0) {
      continue;
    }

    src_path = pdircat(p, src_dir, dent->d_name, NULL);
    dst_path = pdircat(p, dst_dir, dent->d_name, NULL);

    if (pr_fsio_lstat(src_path, &st) < 0) {
      pr_log_debug(DEBUG3, "CreateHome: unable to stat '%s' (%s), skipping",
        src_path, strerror(errno));
      continue;
    }

    /* Is this path to a directory? */
    if (S_ISDIR(st.st_mode)) {
      create_dir(dst_path, uid, gid, st.st_mode);
      copy_dir(p, src_path, dst_path, uid, gid);
      continue;

    /* Is this path to a regular file? */
    } else if (S_ISREG(st.st_mode)) {
      mode_t dst_mode = st.st_mode;

      /* Make sure to prevent S{U,G}ID permissions on target files. */

      if (dst_mode & S_ISUID) {
        dst_mode &= ~S_ISUID;
      }

      if (dst_mode & S_ISGID) {
        dst_mode &= ~S_ISGID;
      }

      (void) pr_fs_copy_file(src_path, dst_path);

      /* Make sure the destination file has the proper ownership and mode. */
      if (pr_fsio_chown(dst_path, uid, gid) < 0) {
        pr_log_pri(PR_LOG_WARNING, "CreateHome: error chown'ing '%s' "
          "to %s/%s: %s", dst_path, pr_uid2str(p, uid), pr_gid2str(p, gid),
          strerror(errno));
      }

      if (pr_fsio_chmod(dst_path, dst_mode) < 0) {
        pr_log_pri(PR_LOG_WARNING, "CreateHome: error chmod'ing '%s' to "
          "%04o: %s", dst_path, (unsigned int) dst_mode, strerror(errno));
      }

      continue;

    /* Is this path a symlink? */
    } else if (S_ISLNK(st.st_mode)) {
      copy_symlink(p, src_dir, src_path, dst_dir, dst_path, uid, gid);
      continue;

    /* All other file types are skipped */
    } else {
      pr_log_debug(DEBUG3, "CreateHome: skipping skel file '%s'", src_path);
      continue;
    }
  }

  closedir(dh);
  return 0;
}

/* Check for a CreateHome directive, and act on it if present.  If not, do
 * nothing.
 */
int create_home(pool *p, const char *home, const char *user, uid_t uid,
    gid_t gid) {
  int res;
  unsigned long flags = 0;
  config_rec *c;
  mode_t dir_mode, dst_mode;
  uid_t dir_uid, dst_uid;
  gid_t dir_gid, dst_gid, home_gid;

  c = find_config(main_server->conf, CONF_PARAM, "CreateHome", FALSE);
  if (c == NULL ||
      (c && *((unsigned char *) c->argv[0]) == FALSE)) {
    return 0;
  }

  /* Create the configured path. */

  dir_uid = *((uid_t *) c->argv[4]);
  dir_gid = *((gid_t *) c->argv[5]);
  dir_mode = *((mode_t *) c->argv[2]);
  home_gid = *((gid_t *) c->argv[6]);
  flags = *((unsigned long *) c->argv[7]);

  dst_uid = uid;
  dst_gid = (home_gid == (gid_t) -1) ? gid : home_gid;

  dst_mode = *((mode_t *) c->argv[1]);

  if (flags & PR_MKHOME_FL_USE_USER_PRIVS) {
    /* Make sure we are the actual end user here (Issue#568).  Without this,
     * we will not be using root privs, true, but we will not be creating
     * the directory as the logging-in user; we will be creating the directory
     * using the User/Group identity, which is not expected.
     */
    PRIVS_USER

  } else {
    PRIVS_ROOT
  }

  pr_event_generate("core.creating-home", user);

  res = create_path(p, home, user, dir_uid, dir_gid, dir_mode,
    dst_uid, dst_gid, dst_mode);

  if (res < 0 &&
      errno != EEXIST) {
    int xerrno = errno;

    PRIVS_RELINQUISH

    errno = xerrno;
    return -1;
  }

  if (res == 0 &&
      c->argv[3]) {
    char *skel_dir = c->argv[3];

    /* Populate the home directory with files from the configured
     * skeleton (a la /etc/skel) directory.
     */

    pr_trace_msg(trace_channel, 9, "copying skel files from '%s' into '%s'",
      skel_dir, home);
    pr_log_debug(DEBUG4, "CreateHome: copying skel files from '%s' into '%s'",
      skel_dir, home);

    pr_event_generate("core.copying-skel", user);

    if (copy_dir(p, skel_dir, home, uid, gid) < 0) {
      pr_log_debug(DEBUG4, "CreateHome: error copying skel files");

    } else {
      pr_event_generate("core.copied-skel", user);
    }
  }

  if (res == 0) {
    pr_event_generate("core.created-home", user);
  }

  PRIVS_RELINQUISH
  return 0;
}
