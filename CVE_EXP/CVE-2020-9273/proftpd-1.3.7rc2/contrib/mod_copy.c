/*
 * ProFTPD: mod_copy -- a module supporting copying of files on the server
 *                      without transferring the data to the client and back
 * Copyright (c) 2009-2019 TJ Saunders
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
 *
 * This is mod_copy, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"

#define MOD_COPY_VERSION	"mod_copy/0.6"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030401
# error "ProFTPD 1.3.4rc1 or later required"
#endif

extern pr_response_t *resp_list, *resp_err_list;

module copy_module;
static int copy_engine = TRUE;
static unsigned long copy_opts = 0UL;
#define COPY_OPT_NO_DELETE_ON_FAILURE	0x0001

static const char *trace_channel = "copy";

static int copy_sess_init(void);

/* These are copied largely from src/mkhome.c */

static int create_dir(const char *dir) {
  struct stat st;
  int res = -1;

  pr_fs_clear_cache2(dir);
  res = pr_fsio_stat(dir, &st);

  if (res < 0 &&
      errno != ENOENT) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, MOD_COPY_VERSION ": error checking '%s': %s",
      dir, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* The directory already exists. */
  if (res == 0) {
    pr_trace_msg(trace_channel, 9, "path '%s' already exists", dir);
    return 1;
  }

  if (pr_fsio_mkdir(dir, 0777) < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, MOD_COPY_VERSION ": error creating '%s': %s",
      dir, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  pr_log_debug(DEBUG6, MOD_COPY_VERSION ": directory '%s' created", dir);
  return 0;
}

static int create_path(pool *p, const char *path) {
  struct stat st;
  char *curr_path, *dup_path; 
 
  pr_fs_clear_cache2(path);
  if (pr_fsio_stat(path, &st) == 0) {
    return 0;
  }
 
  dup_path = pstrdup(p, path);

  curr_path = "/"; 
  while (dup_path &&
         *dup_path) {
    char *curr_dir;
    int res;
    cmd_rec *cmd;
    pool *sub_pool;

    pr_signals_handle();

    curr_dir = strsep(&dup_path, "/");
    curr_path = pdircat(p, curr_path, curr_dir, NULL);

    /* Dispatch fake C_MKD command, e.g. for mod_quotatab */
    sub_pool = pr_pool_create_sz(p, 64);
    cmd = pr_cmd_alloc(sub_pool, 2, pstrdup(sub_pool, C_MKD),
      pstrdup(sub_pool, curr_path));
    cmd->arg = pstrdup(cmd->pool, curr_path);
    cmd->cmd_class = CL_DIRS|CL_WRITE;

    pr_response_clear(&resp_list);
    pr_response_clear(&resp_err_list);

    res = pr_cmd_dispatch_phase(cmd, PRE_CMD, 0);
    if (res < 0) {
      int xerrno = errno;

      pr_log_debug(DEBUG3, MOD_COPY_VERSION
        ": creating directory '%s' blocked by MKD handler: %s", curr_path,
        strerror(xerrno));

      pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
      pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
      pr_response_clear(&resp_err_list);

      destroy_pool(sub_pool);

      errno = xerrno;
      return -1;
    }

    res = create_dir(curr_path);
    if (res < 0) {
      pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
      pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
      pr_response_clear(&resp_err_list);

      destroy_pool(sub_pool);
      return -1;
    }

    pr_cmd_dispatch_phase(cmd, POST_CMD, 0);
    pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
    pr_response_clear(&resp_list);
    destroy_pool(sub_pool);
  }

  return 0;
}

static int copy_symlink(pool *p, const char *src_path, const char *dst_path,
    int flags) {
  char *link_path = pcalloc(p, PR_TUNABLE_BUFFER_SIZE);
  int len;

  len = pr_fsio_readlink(src_path, link_path, PR_TUNABLE_BUFFER_SIZE-1);
  if (len < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, MOD_COPY_VERSION ": error reading link '%s': %s",
      src_path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }
  link_path[len] = '\0';

  if (pr_fsio_symlink(link_path, dst_path) < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, MOD_COPY_VERSION
      ": error symlinking '%s' to '%s': %s", link_path, dst_path,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

static int copy_dir(pool *p, const char *src_dir, const char *dst_dir,
    int flags) {
  DIR *dh = NULL;
  struct dirent *dent = NULL;
  int res = 0;
  pool *iter_pool = NULL;

  dh = opendir(src_dir);
  if (dh == NULL) {
    pr_log_pri(PR_LOG_WARNING, MOD_COPY_VERSION
      ": error reading directory '%s': %s", src_dir, strerror(errno));
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

    if (iter_pool != NULL) {
      destroy_pool(iter_pool);
    }

    iter_pool = pr_pool_create_sz(p, 128);
    src_path = pdircat(iter_pool, src_dir, dent->d_name, NULL);
    dst_path = pdircat(iter_pool, dst_dir, dent->d_name, NULL);

    if (pr_fsio_lstat(src_path, &st) < 0) {
      pr_log_debug(DEBUG3, MOD_COPY_VERSION
        ": unable to stat '%s' (%s), skipping", src_path, strerror(errno));
      continue;
    }

    /* Is this path to a directory? */
    if (S_ISDIR(st.st_mode)) {
      if (create_path(iter_pool, dst_path) < 0) {
        res = -1;
        break;
      }

      if (copy_dir(iter_pool, src_path, dst_path, flags) < 0) {
        res = -1;
        break;
      }
      continue;

    /* Is this path to a regular file? */
    } else if (S_ISREG(st.st_mode)) {
      cmd_rec *cmd;

      /* Dispatch fake COPY command, e.g. for mod_quotatab */
      cmd = pr_cmd_alloc(iter_pool, 4, pstrdup(iter_pool, "SITE"),
        pstrdup(iter_pool, "COPY"), pstrdup(iter_pool, src_path),
        pstrdup(iter_pool, dst_path));
      cmd->arg = pstrcat(iter_pool, "COPY ", src_path, " ", dst_path, NULL);
      cmd->cmd_class = CL_WRITE;

      pr_response_clear(&resp_list);
      pr_response_clear(&resp_err_list);

      if (pr_cmd_dispatch_phase(cmd, PRE_CMD, 0) < 0) {
        int xerrno = errno;

        pr_log_debug(DEBUG3, MOD_COPY_VERSION
          ": COPY of '%s' to '%s' blocked by COPY handler: %s", src_path,
          dst_path, strerror(xerrno));

        pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
        pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
        pr_response_clear(&resp_err_list);

        errno = xerrno;
        res = -1;
        break;

      } else {
        if (pr_fs_copy_file2(src_path, dst_path, flags, NULL) < 0) {
          int xerrno = errno;

          pr_log_debug(DEBUG7, MOD_COPY_VERSION
            ": error copying file '%s' to '%s': %s", src_path, dst_path,
            strerror(xerrno));

          pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
          pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
          pr_response_clear(&resp_err_list);

          errno = xerrno;
          res = -1;
          break;

        } else {
          char *abs_path;
          
          pr_cmd_dispatch_phase(cmd, POST_CMD, 0);
          pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
          pr_response_clear(&resp_list);

          /* Write a TransferLog entry as well. */

          pr_fs_clear_cache2(dst_path);
          pr_fsio_stat(dst_path, &st);

          abs_path = dir_abs_path(p, dst_path, TRUE);

          if (session.sf_flags & SF_ANON) {
            xferlog_write(0, session.c->remote_name, st.st_size, abs_path,
               (session.sf_flags & SF_ASCII ? 'a' : 'b'), 'd', 'a',
               session.anon_user, 'c', "_");

          } else {
            xferlog_write(0, session.c->remote_name, st.st_size, abs_path,
              (session.sf_flags & SF_ASCII ? 'a' : 'b'), 'd', 'r',
              session.user, 'c', "_");
          }
        }
      }

      continue;

    /* Is this path a symlink? */
    } else if (S_ISLNK(st.st_mode)) {
      if (copy_symlink(iter_pool, src_path, dst_path, flags) < 0) {
        res = -1;
        break;
      }
      continue;

    /* All other file types are skipped */
    } else {
      pr_log_debug(DEBUG3, MOD_COPY_VERSION ": skipping supported file '%s'",
        src_path);
      continue;
    }
  }

  if (iter_pool != NULL) {
    destroy_pool(iter_pool);
  }

  closedir(dh);
  return res;
}

static int copy_paths(pool *p, const char *from, const char *to) {
  struct stat st;
  int res, flags = 0;
  xaset_t *set;

  set = get_dir_ctxt(p, (char *) to);
  res = pr_filter_allow_path(set, to);
  switch (res) {
    case 0:
      break;

    case PR_FILTER_ERR_FAILS_ALLOW_FILTER:
      pr_log_debug(DEBUG7, MOD_COPY_VERSION
        ": path '%s' denied by PathAllowFilter", to);
      errno = EPERM;
      return -1;

    case PR_FILTER_ERR_FAILS_DENY_FILTER:
      pr_log_debug(DEBUG7, MOD_COPY_VERSION
        ": path '%s' denied by PathDenyFilter", to);
      errno = EPERM;
      return -1;
  }

  /* Check whether from is a file, a directory, a symlink, or something
   * unsupported.
   */
  res = pr_fsio_lstat(from, &st);
  if (res < 0) {
    int xerrno = errno;

    pr_log_debug(DEBUG7, MOD_COPY_VERSION ": error checking '%s': %s", from,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (copy_opts & COPY_OPT_NO_DELETE_ON_FAILURE) {
    flags |= PR_FSIO_COPY_FILE_FL_NO_DELETE_ON_FAILURE;
  }

  if (S_ISREG(st.st_mode)) { 
    char *abs_path;

    pr_fs_clear_cache2(to);
    res = pr_fsio_stat(to, &st);
    if (res == 0) {
      unsigned char *allow_overwrite;

      allow_overwrite = get_param_ptr(CURRENT_CONF, "AllowOverwrite", FALSE);
      if (allow_overwrite == NULL ||
          *allow_overwrite == FALSE) {
        pr_log_debug(DEBUG6,
          MOD_COPY_VERSION ": AllowOverwrite permission denied for '%s'", to);
        errno = EACCES;
        return -1;
      }
    }

    res = pr_fs_copy_file2(from, to, flags, NULL);
    if (res < 0) {
      int xerrno = errno;

      pr_log_debug(DEBUG7, MOD_COPY_VERSION
        ": error copying file '%s' to '%s': %s", from, to, strerror(xerrno));

      errno = xerrno;
      return -1;
    }

    pr_fs_clear_cache2(to);
    if (pr_fsio_stat(to, &st) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error stat'ing '%s': %s", to, strerror(errno));
    }

    /* Write a TransferLog entry as well. */
    abs_path = dir_abs_path(p, to, TRUE);

    if (session.sf_flags & SF_ANON) {
      xferlog_write(0, session.c->remote_name, st.st_size, abs_path,
        (session.sf_flags & SF_ASCII ? 'a' : 'b'), 'd', 'a',
        session.anon_user, 'c', "_");

    } else {
      xferlog_write(0, session.c->remote_name, st.st_size, abs_path,
        (session.sf_flags & SF_ASCII ? 'a' : 'b'), 'd', 'r',
        session.user, 'c', "_");
    }

  } else if (S_ISDIR(st.st_mode)) {
    res = create_path(p, to);
    if (res < 0) {
      int xerrno = errno;

      pr_log_debug(DEBUG7, MOD_COPY_VERSION
        ": error creating path '%s': %s", to, strerror(xerrno));

      errno = xerrno;
      return -1;
    }

    res = copy_dir(p, from, to, flags);
    if (res < 0) {
      int xerrno = errno;

      pr_log_debug(DEBUG7, MOD_COPY_VERSION
        ": error copying directory '%s' to '%s': %s", from, to,
        strerror(xerrno));

      errno = xerrno;
      return -1;
    }

  } else if (S_ISLNK(st.st_mode)) {
    pr_fs_clear_cache2(to);
    res = pr_fsio_stat(to, &st);
    if (res == 0) {
      unsigned char *allow_overwrite;

      allow_overwrite = get_param_ptr(CURRENT_CONF, "AllowOverwrite", FALSE);
      if (allow_overwrite == NULL ||
          *allow_overwrite == FALSE) {
        pr_log_debug(DEBUG6, MOD_COPY_VERSION
          ": AllowOverwrite permission denied for '%s'", to);

        errno = EACCES;
        return -1;
      }
    }

    res = copy_symlink(p, from, to, flags);
    if (res < 0) {
      int xerrno = errno;

      pr_log_debug(DEBUG7, MOD_COPY_VERSION
        ": error copying symlink '%s' to '%s': %s", from, to, strerror(xerrno));

      errno = xerrno;
      return -1;
    }

  } else {
    pr_log_debug(DEBUG7, MOD_COPY_VERSION
      ": unsupported file type for '%s'", from);

    errno = EINVAL;
    return -1;
  }

  return 0;
}

/* Configuration handlers
 */

/* usage: CopyEngine on|off */
MODRET set_copyengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: CopyOptions opt1 ... */
MODRET set_copyoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "NoDeleteOnFailure") == 0) {
      opts |= COPY_OPT_NO_DELETE_ON_FAILURE;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown CopyOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET copy_copy(cmd_rec *cmd) {
  if (copy_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (cmd->argc < 2) {
    return PR_DECLINED(cmd);
  }

  if (strncasecmp(cmd->argv[1], "COPY", 5) == 0) {
    char *cmd_name, *decoded_path, *from, *to;
    unsigned char *authenticated;

    if (cmd->argc != 4) {
      return PR_DECLINED(cmd);
    }

    authenticated = get_param_ptr(cmd->server->conf, "authenticated", FALSE);
    if (authenticated == NULL ||
        *authenticated == FALSE) {
      pr_response_add_err(R_530, _("Please login with USER and PASS"));

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);
    }

    /* XXX What about paths which contain spaces? */

    decoded_path = pr_fs_decode_path2(cmd->tmp_pool, cmd->argv[2],
      FSIO_DECODE_FL_TELL_ERRORS);
    if (decoded_path == NULL) {
      int xerrno = errno;

      pr_log_debug(DEBUG8, "'%s' failed to decode properly: %s",
        (char *) cmd->argv[2], strerror(xerrno));
      pr_response_add_err(R_550,
        _("%s: Illegal character sequence in filename"), (char *) cmd->argv[2]);

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    from = dir_canonical_vpath(cmd->tmp_pool, decoded_path);

    decoded_path = pr_fs_decode_path2(cmd->tmp_pool, cmd->argv[3],
      FSIO_DECODE_FL_TELL_ERRORS);
    if (decoded_path == NULL) {
      int xerrno = errno;

      pr_log_debug(DEBUG8, "'%s' failed to decode properly: %s",
        (char *) cmd->argv[3], strerror(xerrno));
      pr_response_add_err(R_550,
        _("%s: Illegal character sequence in filename"), (char *) cmd->argv[3]);

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    to = dir_canonical_vpath(cmd->tmp_pool, decoded_path);

    cmd_name = cmd->argv[0];
    pr_cmd_set_name(cmd, "SITE_COPY");
    if (!dir_check(cmd->tmp_pool, cmd, G_WRITE, to, NULL)) {
      int xerrno = EPERM;

      pr_cmd_set_name(cmd, cmd_name);
      pr_response_add_err(R_550, "%s: %s", (char *) cmd->argv[3],
        strerror(xerrno));

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }
    pr_cmd_set_name(cmd, cmd_name);

    if (copy_paths(cmd->tmp_pool, from, to) < 0) {
      int xerrno = errno;

      pr_log_debug(DEBUG7, MOD_COPY_VERSION
        ": error copying '%s' to '%s': %s", from, to, strerror(xerrno));

      pr_response_add_err(R_550, "%s: %s", (char *) cmd->argv[1],
        strerror(xerrno));

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    pr_response_add(R_200, _("SITE %s command successful"),
      (char *) cmd->argv[1]);
    return PR_HANDLED(cmd);
  }

  if (strncasecmp(cmd->argv[1], "HELP", 5) == 0) {
    pr_response_add(R_214, _("CPFR <sp> pathname"));
    pr_response_add(R_214, _("CPTO <sp> pathname"));
  }

  return PR_DECLINED(cmd);
}

MODRET copy_cpfr(cmd_rec *cmd) {
  register unsigned int i;
  int res;
  char *cmd_name, *path = "";
  unsigned char *authenticated = NULL;

  if (copy_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (cmd->argc < 3 ||
      strncasecmp(cmd->argv[1], "CPFR", 5) != 0) {
    return PR_DECLINED(cmd);
  }

  authenticated = get_param_ptr(cmd->server->conf, "authenticated", FALSE);
  if (authenticated == NULL ||
      *authenticated == FALSE) {
    pr_response_add_err(R_530, _("Please login with USER and PASS"));
  
    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  CHECK_CMD_MIN_ARGS(cmd, 3);

  /* Construct the target file name by concatenating all the parameters after
   * the "SITE CPFR", separating them with spaces.
   */
  for (i = 2; i <= cmd->argc-1; i++) {
    char *decoded_path;

    decoded_path = pr_fs_decode_path2(cmd->tmp_pool, cmd->argv[i],
      FSIO_DECODE_FL_TELL_ERRORS);
    if (decoded_path == NULL) {
      int xerrno = errno;

      pr_log_debug(DEBUG8, "'%s' failed to decode properly: %s",
        (char *) cmd->argv[i], strerror(xerrno));
      pr_response_add_err(R_550,
        _("%s: Illegal character sequence in filename"), cmd->arg);

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    path = pstrcat(cmd->tmp_pool, path, *path ? " " : "", decoded_path, NULL);
  }

  cmd_name = cmd->argv[0];
  pr_cmd_set_name(cmd, "SITE_CPFR");
  if (!dir_check(cmd->tmp_pool, cmd, G_READ, path, NULL)) {
    int xerrno = EPERM;

    pr_cmd_set_name(cmd, cmd_name);
    pr_response_add_err(R_550, "%s: %s", (char *) cmd->argv[3],
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }
  pr_cmd_set_name(cmd, cmd_name);

  res = pr_filter_allow_path(CURRENT_CONF, path);
  switch (res) {
    case 0:
      break;

    case PR_FILTER_ERR_FAILS_ALLOW_FILTER:
      pr_log_debug(DEBUG2, MOD_COPY_VERSION
        ": 'CPFR %s' denied by PathAllowFilter", path);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), path);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);

    case PR_FILTER_ERR_FAILS_DENY_FILTER:
      pr_log_debug(DEBUG2, MOD_COPY_VERSION
        ": 'CPFR %s' denied by PathDenyFilter", path);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), path);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);
  }

  /* Allow renaming a symlink, even a dangling one. */
  path = dir_canonical_vpath(cmd->tmp_pool, path);

  if (!path ||
      !dir_check_canon(cmd->tmp_pool, cmd, cmd->group, path, NULL) ||
      !exists2(cmd->tmp_pool, path)) {
    int xerrno = errno;

    pr_response_add_err(R_550, "%s: %s", path, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (pr_table_add(session.notes, "mod_copy.cpfr-path",
      pstrdup(session.pool, path), 0) < 0) {
    pr_trace_msg(trace_channel, 4,
      "error adding 'mod_copy.cpfr-path' note: %s", strerror(errno));
  }

  pr_response_add(R_350,
    _("File or directory exists, ready for destination name"));
  return PR_HANDLED(cmd);
}

MODRET copy_cpto(cmd_rec *cmd) {
  register unsigned int i;
  const char *from, *to = "";
  char *cmd_name;
  unsigned char *authenticated = NULL;

  if (copy_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (cmd->argc < 3 ||
      strncasecmp(cmd->argv[1], "CPTO", 5) != 0) {
    return PR_DECLINED(cmd);
  }

  authenticated = get_param_ptr(cmd->server->conf, "authenticated", FALSE);
  if (authenticated == NULL ||
      *authenticated == FALSE) {
    pr_response_add_err(R_530, _("Please login with USER and PASS"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  CHECK_CMD_MIN_ARGS(cmd, 3);

  from = pr_table_get(session.notes, "mod_copy.cpfr-path", NULL);
  if (from == NULL) {
    pr_response_add_err(R_503, _("Bad sequence of commands"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* Construct the target file name by concatenating all the parameters after
   * the "SITE CPTO", separating them with spaces.
   */
  for (i = 2; i <= cmd->argc-1; i++) {
    char *decoded_path;

    decoded_path = pr_fs_decode_path2(cmd->tmp_pool, cmd->argv[i],
      FSIO_DECODE_FL_TELL_ERRORS);
    if (decoded_path == NULL) {
      int xerrno = errno;

      pr_log_debug(DEBUG8, "'%s' failed to decode properly: %s",
        (char *) cmd->argv[i], strerror(xerrno));
      pr_response_add_err(R_550,
        _("%s: Illegal character sequence in filename"), cmd->arg);

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    to = pstrcat(cmd->tmp_pool, to, *to ? " " : "", decoded_path, NULL);
  }

  to = dir_canonical_vpath(cmd->tmp_pool, to);

  cmd_name = cmd->argv[0];
  pr_cmd_set_name(cmd, "SITE_CPTO");
  if (!dir_check(cmd->tmp_pool, cmd, G_WRITE, to, NULL)) {
    int xerrno = EPERM;

    pr_cmd_set_name(cmd, cmd_name);
    pr_response_add_err(R_550, "%s: %s", to, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }
  pr_cmd_set_name(cmd, cmd_name);

  if (copy_paths(cmd->tmp_pool, from, to) < 0) {
    int xerrno = errno;
    const char *err_code = R_550;

    pr_log_debug(DEBUG7, MOD_COPY_VERSION
      ": error copying '%s' to '%s': %s", from, to, strerror(xerrno));

    /* Check errno for EDQOUT (or the most appropriate alternative).
     * (I hate the fact that FTP has a special response code just for
     * this, and that clients actually expect it.  Special cases are
     * stupid.)
     */
    switch (xerrno) {
#if defined(EDQUOT)
      case EDQUOT:
#endif /* EDQUOT */
#if defined(EFBIG)
      case EFBIG:
#endif /* EFBIG */
#if defined(ENOSPC)
      case ENOSPC:
#endif /* ENOSPC */
        err_code = R_552;
        break;

      default:
        err_code = R_550;
        break;
    }

    pr_response_add_err(err_code, "%s: %s", (char *) cmd->argv[1],
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  pr_response_add(R_250, "%s", _("Copy successful"));
  return PR_HANDLED(cmd);
}

MODRET copy_log_site(cmd_rec *cmd) {
  if (copy_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (cmd->argc < 3 ||
      strncasecmp(cmd->argv[1], "CPTO", 5) != 0) {
    return PR_DECLINED(cmd);
  }

  /* Delete the stashed CPFR path from the session.notes table. */
  (void) pr_table_remove(session.notes, "mod_copy.cpfr-path", NULL);

  return PR_DECLINED(cmd);
}

MODRET copy_post_pass(cmd_rec *cmd) {
  config_rec *c;

  if (copy_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* The CopyEngine directive may have been changed for this user by
   * e.g. mod_ifsession, thus we check again.
   */
  c = find_config(main_server->conf, CONF_PARAM, "CopyEngine", FALSE);
  if (c != NULL) {
    copy_engine = *((int *) c->argv[0]);
  }

  if (copy_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  c = find_config(main_server->conf, CONF_PARAM, "CopyOptions", FALSE);
  while (c != NULL) {
    unsigned long opts = 0;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    copy_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "CopyOptions", FALSE);
  }

  return PR_DECLINED(cmd);
}

/* Initialization functions
 */

static int copy_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "CopyEngine", FALSE);
  if (c != NULL) {
    copy_engine = *((int *) c->argv[0]);
  }

  if (copy_engine == FALSE) {
    return 0;
  }

  /* Advertise support for the SITE command */
  pr_feat_add("SITE COPY");
  return 0;
}

/* Module API tables
 */

static conftable copy_conftab[] = {
  { "CopyEngine",	set_copyengine,		NULL },
  { "CopyOptions",	set_copyoptions,	NULL },

  { NULL }
};

static cmdtable copy_cmdtab[] = {
  { CMD, 	C_SITE, G_WRITE,	copy_copy,	FALSE,	FALSE, CL_MISC },
  { CMD, 	C_SITE, G_READ,		copy_cpfr,	FALSE,	FALSE, CL_MISC },
  { CMD, 	C_SITE, G_WRITE,	copy_cpto,	FALSE,	FALSE, CL_MISC },
  { POST_CMD,	C_PASS,	G_NONE,		copy_post_pass, FALSE,	FALSE },
  { LOG_CMD, 	C_SITE, G_NONE,		copy_log_site,	FALSE,	FALSE },
  { LOG_CMD_ERR, C_SITE, G_NONE,	copy_log_site,	FALSE,	FALSE },

  { 0, NULL }
};

module copy_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "copy",

  /* Module configuration handler table */
  copy_conftab,

  /* Module command handler table */
  copy_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  NULL,

  /* Session initialization function */
  copy_sess_init,

  /* Module version */
  MOD_COPY_VERSION
};
