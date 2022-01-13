/*
 * ProFTPD - mod_sftp miscellaneous
 * Copyright (c) 2010-2017 TJ Saunders
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

#include "mod_sftp.h"
#include "misc.h"

int sftp_misc_chown_file(pool *p, pr_fh_t *fh) {
  struct stat st;
  int res, xerrno;
 
  if (fh == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* session.fsgid defaults to -1, so chown(2) won't chgrp unless specifically
   * requested via GroupOwner.
   */
  if (session.fsuid != (uid_t) -1) {
    PRIVS_ROOT
    res = pr_fsio_fchown(fh, session.fsuid, session.fsgid);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "chown(%s) as root failed: %s", fh->fh_path, strerror(xerrno));

    } else {
      if (session.fsgid != (gid_t) -1) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "root chown(%s) to UID %s, GID %s successful", fh->fh_path,
          pr_uid2str(p, session.fsuid), pr_gid2str(p, session.fsgid));

      } else {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "root chown(%s) to UID %s successful", fh->fh_path,
          pr_uid2str(NULL, session.fsuid));
      }

      if (pr_fsio_fstat(fh, &st) < 0) {
        pr_log_debug(DEBUG0,
          "'%s' fstat(2) error for root chmod: %s", fh->fh_path,
          strerror(errno));
      }

      /* The chmod happens after the chown because chown will remove the
       * S{U,G}ID bits on some files (namely, directories); the subsequent
       * chmod is used to restore those dropped bits.  This makes it necessary
       * to use root privs when doing the chmod as well (at least in the case
       * of chown'ing the file via root privs) in order to ensure that the mode
       * can be set (a file might be being "given away", and if root privs
       * aren't used, the chmod() will fail because the old owner/session user
       * doesn't have the necessary privileges to do so).
       */
      PRIVS_ROOT
      res = pr_fsio_fchmod(fh, st.st_mode);
      xerrno = errno;
      PRIVS_RELINQUISH

      if (res < 0) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "root chmod(%s) to %04o failed: %s", fh->fh_path,
          (unsigned int) st.st_mode, strerror(xerrno));

      } else {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "root chmod(%s) to %04o successful", fh->fh_path,
          (unsigned int) st.st_mode);
      }
    }

  } else if (session.fsgid != (gid_t) -1) {
    register unsigned int i;
    int use_root_privs = TRUE;

    /* Check if session.fsgid is in session.gids.  If not, use root privs. */
    for (i = 0; i < session.gids->nelts; i++) {
      gid_t *group_ids = session.gids->elts;

      if (group_ids[i] == session.fsgid) {
        use_root_privs = FALSE;
        break;
      }
    }

    if (use_root_privs) {
      PRIVS_ROOT
    }

    res = pr_fsio_fchown(fh, (uid_t) -1, session.fsgid);
    xerrno = errno;

    if (use_root_privs) {
      PRIVS_RELINQUISH
    }

    if (res < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "%schown(%s) failed: %s", use_root_privs ? "root " : "", fh->fh_path,
        strerror(xerrno));

    } else {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "%schown(%s) to GID %s successful",
        use_root_privs ? "root " : "", fh->fh_path,
        pr_gid2str(NULL, session.fsgid));

      if (pr_fsio_fstat(fh, &st) < 0) {
        pr_log_debug(DEBUG0,
          "'%s' fstat(2) error for %sfchmod: %s", fh->fh_path,
          use_root_privs ? "root " : "", strerror(errno));
      }

      if (use_root_privs) {
        PRIVS_ROOT
      }

      res = pr_fsio_fchmod(fh, st.st_mode);
      xerrno = errno;

      if (use_root_privs) {
        PRIVS_RELINQUISH
      }

      if (res < 0) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "%schmod(%s) to %04o failed: %s", use_root_privs ? "root " : "",
          fh->fh_path, (unsigned int) st.st_mode, strerror(xerrno));
      }
    }
  }

  return 0;
}

int sftp_misc_chown_path(pool *p, const char *path) {
  struct stat st;
  int res, xerrno;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* session.fsgid defaults to -1, so chown(2) won't chgrp unless specifically
   * requested via GroupOwner.
   */
  if (session.fsuid != (uid_t) -1) {

    PRIVS_ROOT
    res = pr_fsio_lchown(path, session.fsuid, session.fsgid);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "lchown(%s) as root failed: %s", path, strerror(xerrno));

    } else {
      if (session.fsgid != (gid_t) -1) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "root lchown(%s) to UID %s, GID %s successful", path,
          pr_uid2str(p, session.fsuid), pr_gid2str(p, session.fsgid));

      } else {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "root lchown(%s) to UID %s successful", path,
          pr_uid2str(NULL, session.fsuid));
      }

      pr_fs_clear_cache2(path);
      if (pr_fsio_stat(path, &st) < 0) {
        pr_log_debug(DEBUG0,
          "'%s' stat(2) error for root chmod: %s", path, strerror(errno));
      }

      /* The chmod happens after the chown because chown will remove the
       * S{U,G}ID bits on some files (namely, directories); the subsequent
       * chmod is used to restore those dropped bits.  This makes it necessary
       * to use root privs when doing the chmod as well (at least in the case
       * of chown'ing the file via root privs) in order to ensure that the mode
       * can be set (a file might be being "given away", and if root privs
       * aren't used, the chmod() will fail because the old owner/session user
       * doesn't have the necessary privileges to do so).
       */
      PRIVS_ROOT
      res = pr_fsio_chmod(path, st.st_mode);
      xerrno = errno;
      PRIVS_RELINQUISH

      if (res < 0) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "root chmod(%s) to %04o failed: %s", path,
          (unsigned int) st.st_mode, strerror(xerrno));

      } else {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "root chmod(%s) to %04o successful", path,
          (unsigned int) st.st_mode);
      }
    }

  } else if (session.fsgid != (gid_t) -1) {
    register unsigned int i;
    int use_root_privs = TRUE;

    /* Check if session.fsgid is in session.gids.  If not, use root privs. */
    for (i = 0; i < session.gids->nelts; i++) {
      gid_t *group_ids = session.gids->elts;

      if (group_ids[i] == session.fsgid) {
        use_root_privs = FALSE;
        break;
      }
    }

    if (use_root_privs) {
      PRIVS_ROOT
    }

    res = pr_fsio_lchown(path, (uid_t) -1, session.fsgid);
    xerrno = errno;

    if (use_root_privs) {
      PRIVS_RELINQUISH
    }

    if (res < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "%slchown(%s) failed: %s", use_root_privs ? "root " : "", path,
        strerror(xerrno));

    } else {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "%slchown(%s) to GID %s successful",
        use_root_privs ? "root " : "", path,
        pr_gid2str(NULL, session.fsgid));

      pr_fs_clear_cache2(path);
      if (pr_fsio_stat(path, &st) < 0) {
        pr_log_debug(DEBUG0,
          "'%s' stat(2) error for %schmod: %s", path,
          use_root_privs ? "root " : "", strerror(errno));
      }

      if (use_root_privs) {
        PRIVS_ROOT
      }

      res = pr_fsio_chmod(path, st.st_mode);
      xerrno = errno;

      if (use_root_privs) {
        PRIVS_RELINQUISH
      }

      if (res < 0) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "%schmod(%s) to %04o failed: %s", use_root_privs ? "root " : "",
          path, (unsigned int) st.st_mode, strerror(xerrno));
      }
    }
  }

  return 0;
}

const char *sftp_misc_get_chroot(pool *p) {
  return pr_table_get(session.notes, "mod_sftp.chroot-path", NULL);
}

const char *sftp_misc_namelist_shared(pool *p, const char *c2s_names,
    const char *s2c_names) {
  register unsigned int i;
  const char *name = NULL, **client_names, **server_names;
  pool *tmp_pool;
  array_header *client_list, *server_list;

  tmp_pool = make_sub_pool(p);
  pr_pool_tag(tmp_pool, "Share name pool");

  client_list = pr_str_text_to_array(tmp_pool, c2s_names, ',');
  client_names = (const char **) client_list->elts;

  server_list = pr_str_text_to_array(tmp_pool, s2c_names, ',');
  server_names = (const char **) server_list->elts;

  for (i = 0; i < client_list->nelts; i++) {
    register unsigned int j;

    if (name != NULL) {
      break;
    }

    for (j = 0; j < server_list->nelts; j++) {
      if (strcmp(client_names[i], server_names[j]) == 0) {
        name = client_names[i];
        break;
      }
    }
  }

  name = pstrdup(p, name);
  destroy_pool(tmp_pool);

  return name;
}

/* If we are chrooted, AND mod_vroot is present, then abs_path will not
 * actually point to the real absolute path on disk.  Try to account for
 * this.
 */
char *sftp_misc_vroot_abs_path(pool *p, const char *path, int interpolate) {
  const char *curr_chroot_path, *real_chroot_path;
  char *abs_path;

  curr_chroot_path = session.chroot_path;
  real_chroot_path = sftp_misc_get_chroot(p);

  if (real_chroot_path != NULL &&
      pr_module_exists("mod_vroot.c") == TRUE) {
    session.chroot_path = real_chroot_path;
  }

  abs_path = dir_abs_path(p, path, interpolate);
  session.chroot_path = curr_chroot_path;

  return abs_path;
}
