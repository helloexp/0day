/*
 * ProFTPD: mod_ifsession -- a module supporting conditional
 *                            per-user/group/class configuration contexts.
 * Copyright (c) 2002-2016 TJ Saunders
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
 * This is mod_ifsession, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"

#define MOD_IFSESSION_VERSION		"mod_ifsession/1.3"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030402
# error "ProFTPD 1.3.4rc2 or later required"
#endif

#define IFSESS_CLASS_NUMBER	100
#define IFSESS_CLASS_TEXT	"<IfClass>"
#define IFSESS_GROUP_NUMBER	101
#define	IFSESS_GROUP_TEXT	"<IfGroup>"
#define IFSESS_USER_NUMBER	102
#define	IFSESS_USER_TEXT	"<IfUser>"
#define IFSESS_AUTHN_NUMBER	103
#define	IFSESS_AUTHN_TEXT	"<IfAuthenticated>"

module ifsession_module;

static int ifsess_ctx = -1;
static int ifsess_merged = FALSE;

/* For storing the home directory of user, symlinks resolved. */
static const char *ifsess_home_dir = NULL;

/* For supporting DisplayLogin files in <IfUser>/<IfGroup> sections. */
static pr_fh_t *displaylogin_fh = NULL;

static int ifsess_sess_init(void);

static const char *trace_channel = "ifsession";

/* Necessary prototypes */
static void ifsess_resolve_dirs(config_rec *);
static void ifsess_resolve_server_dirs(server_rec *);

/* Support routines
 */

static void ifsess_remove_param(xaset_t *set, int config_type,
    const char *name) {
  config_rec *c = NULL;
  int lookup_type = -1;

  if (config_type == CONF_DIR) {
    pr_trace_msg(trace_channel, 9, "removing <Directory %s> config", name);
    lookup_type = CONF_DIR;

  } else {
    pr_trace_msg(trace_channel, 9, "removing '%s' config", name);
  }

  c = find_config(set, lookup_type, name, TRUE);
  while (c != NULL) {
    xaset_t *fset;
    xasetmember_t *member;

    pr_signals_handle();

    fset = c->set;
    member = (xasetmember_t *) c;
    xaset_remove(fset, member);

    c = find_config(set, lookup_type, name, TRUE);
  }
}

static void ifsess_dup_param(pool *dst_pool, xaset_t **dst, config_rec *c,
    config_rec *parent) {
  config_rec *dup_c = NULL;

  if (c->config_type == CONF_DIR) {
    pr_trace_msg(trace_channel, 9, "adding <Directory %s> config", c->name);

  } else if (c->config_type == CONF_LIMIT) {
    pr_trace_msg(trace_channel, 9, "adding <Limit> config");

  } else {
    pr_trace_msg(trace_channel, 9, "adding '%s' config", c->name);
  }

  if (!*dst) {
    *dst = xaset_create(dst_pool, NULL);
  }

  dup_c = pr_config_add_set(dst, c->name, PR_CONFIG_FL_INSERT_HEAD);
  dup_c->config_type = c->config_type;
  dup_c->flags = c->flags;
  dup_c->parent = parent;
  dup_c->argc = c->argc;

  if (c->argc) {
    void **dst_argv = NULL, **src_argv = NULL;
    int dst_argc;

    dup_c->argv = pcalloc(dup_c->pool, (c->argc + 1) * sizeof(void *));

    src_argv = c->argv;
    dst_argv = dup_c->argv;
    dst_argc = dup_c->argc;

    while (dst_argc--) {
      *dst_argv++ = *src_argv++;
    }

    if (dst_argv) {
      *dst_argv++ = NULL;
    }
  }

  if (c->subset) {
    for (c = (config_rec *) c->subset->xas_list; c; c = c->next) {

      /* If this directive does not allow multiple instances, make sure
       * it is removed from the destination set first.  The "source"
       * directive then effectively replaces any directive there.
       *
       * Note that we only want to do this IF the config is NOT part of
       * of a <Limit> section.
       */
      if (c->parent->config_type != CONF_LIMIT &&
          c->config_type == CONF_PARAM &&
          !(c->flags & CF_MERGEDOWN_MULTI) &&
          !(c->flags & CF_MULTI)) {
          pr_trace_msg(trace_channel, 15, "removing '%s' config because "
            "c->flags does not contain MULTI or MERGEDOWN_MULTI", c->name);
        ifsess_remove_param(dup_c->subset, c->config_type, c->name);
      }

      ifsess_dup_param(dst_pool, &dup_c->subset, c, dup_c);
    }
  }
}

static void ifsess_dup_set(pool *dst_pool, xaset_t *dst, xaset_t *src) {
  config_rec *c, *next;

  for (c = (config_rec *) src->xas_list; c; c = next) {
    next = c->next;

    /* Skip the context lists. */
    if (c->config_type == IFSESS_CLASS_NUMBER ||
        c->config_type == IFSESS_GROUP_NUMBER ||
        c->config_type == IFSESS_USER_NUMBER ||
        c->config_type == IFSESS_AUTHN_NUMBER) {
      continue;
    }

    /* If this directive does not allow multiple instances, make sure
     * it is removed from the destination set first.  The "source"
     * directive then effectively replaces any directive there.
     *
     * Note that we only want to do this IF the config is NOT part of
     * of a <Limit> section.
     */
    if (c->parent->config_type != CONF_LIMIT &&
        c->config_type == CONF_PARAM &&
        !(c->flags & CF_MERGEDOWN_MULTI) &&
        !(c->flags & CF_MULTI)) {
      pr_trace_msg(trace_channel, 15, "removing '%s' config because "
        "c->flags does not contain MULTI or MERGEDOWN_MULTI", c->name);
      ifsess_remove_param(dst, c->config_type, c->name);
    }

    if (c->config_type == CONF_DIR) {
      pr_trace_msg(trace_channel, 15, "removing old <Directory %s> config "
        "because new <Directory %s> takes precedence", c->name, c->name);
      ifsess_remove_param(dst, c->config_type, c->name);
    }

    ifsess_dup_param(dst_pool, &dst, c, NULL);
  }
}

/* Similar to dir_interpolate(), except that we are cognizant of being
 * chrooted, and so try to Do The Right Thing(tm).
 */
static char *ifsess_dir_interpolate(pool *p, const char *path) {
  char *ret = (char *) path;

  if (ret == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (*ret == '~') {
    const char *user;
    char *interp_dir = NULL, *ptr;

    user = pstrdup(p, ret+1);
    ptr = strchr(user, '/');

    if (ptr != NULL) {
      *ptr++ = '\0';
    }

    if (!*user) {
      user = session.user;

      if (ifsess_home_dir != NULL) {
        /* We're chrooted; we already know the interpolated path. */
        interp_dir = (char *) ifsess_home_dir;
      }
    }

    if (interp_dir == NULL) {
      struct passwd *pw;
      struct stat st;
      size_t interp_dirlen;

      pw = pr_auth_getpwnam(p, user);
      if (pw == NULL) {
        errno = ENOENT;
        return NULL;
      }

      if (pw->pw_dir == NULL) {
        errno = EPERM;
        return NULL;
      }

      interp_dir = pstrdup(p, pw->pw_dir);
      interp_dirlen = strlen(interp_dir);

      /* If the given directory is a symlink, follow it.  Note that for
       * proper handling of such paths, we need to ensure that the path does
       * not end in a slash.
       */
      if (interp_dir[interp_dirlen] == '/') {
        interp_dir[interp_dirlen--] = '\0';
      }

      if (pr_fsio_lstat(interp_dir, &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
          char link_path[PR_TUNABLE_PATH_MAX+1];

          memset(link_path, '\0', sizeof(link_path));
          if (pr_fs_resolve_path(interp_dir, link_path, sizeof(link_path)-1,
              FSIO_DIR_CHDIR) < 0) {
            return NULL;
          }

          interp_dir = pstrdup(p, link_path);
        }
      }
    }

    ret = pdircat(p, interp_dir, ptr, NULL);
  }

  return ret;
}

/* Similar to resolve_deferred_dirs(), except that we need to recurse
 * and resolve ALL <Directory> paths.
 */
static void ifsess_resolve_dir(config_rec *c) {
  char *interp_dir = NULL, *real_dir = NULL, *orig_name = NULL;

  if (pr_trace_get_level(trace_channel) >= 11) {
    orig_name = pstrdup(c->pool, c->name);
  }

  /* Check for any expandable variables. */
  c->name = (char *) path_subst_uservar(c->pool, (const char **) &c->name);

  /* Handle any '~' interpolation. */
  interp_dir = ifsess_dir_interpolate(c->pool, c->name);
  if (interp_dir == NULL) {
    /* This can happen when the '~' is just that, and does not refer
     * to any known user.
     */
    interp_dir = c->name;
  }

  real_dir = dir_best_path(c->pool, interp_dir);
  if (real_dir) {
    c->name = real_dir;

  } else {
    real_dir = dir_canonical_path(c->pool, interp_dir);
    if (real_dir) {
      c->name = real_dir;
    }
  }

  pr_trace_msg(trace_channel, 11,
    "resolved <Directory %s> to <Directory %s>", orig_name, c->name);
}

void ifsess_resolve_dirs(config_rec *c) {
  ifsess_resolve_dir(c);

  if (c->subset != NULL) {
    config_rec *subc;

    for (subc = (config_rec *) c->subset->xas_list; subc; subc = subc->next) {
      if (subc->config_type == CONF_DIR) {
        ifsess_resolve_dirs(subc);
      }
    }
  }
}

void ifsess_resolve_server_dirs(server_rec *s) {
  config_rec *c;

  if (s == NULL ||
      s->conf == NULL) {
    return;
  }

  for (c = (config_rec *) s->conf->xas_list; c; c = c->next) {
    if (c->config_type == CONF_DIR) {
      ifsess_resolve_dirs(c);
    }
  }
}

static int ifsess_sess_merge_class(void) {
  register unsigned int i = 0;
  config_rec *c = NULL;
  pool *tmp_pool = make_sub_pool(session.pool);
  array_header *class_remove_list = make_array(tmp_pool, 1,
    sizeof(config_rec *));

  c = find_config(main_server->conf, -1, IFSESS_CLASS_TEXT, FALSE);
  while (c != NULL) {
    config_rec *list = NULL;

    pr_signals_handle();

    list = find_config(c->subset, IFSESS_CLASS_NUMBER, NULL, FALSE);
    if (list != NULL) {
      unsigned char mergein = FALSE;

#ifdef PR_USE_REGEX
      if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_REGEX) {
        pr_regex_t *pre = list->argv[2];

        if (session.conn_class != NULL) {
          pr_log_debug(DEBUG8, MOD_IFSESSION_VERSION
            ": evaluating regexp pattern '%s' against subject '%s'",
            pr_regexp_get_pattern(pre), session.conn_class->cls_name);

          if (pr_regexp_exec(pre, session.conn_class->cls_name, 0, NULL, 0, 0,
              0) == 0) {
            mergein = TRUE;
          }
        }

      } else
#endif /* regex support */

      if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_OR &&
          pr_expr_eval_class_or((char **) &list->argv[2]) == TRUE) {
        mergein = TRUE;

      } else if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_AND &&
          pr_expr_eval_class_and((char **) &list->argv[2]) == TRUE) {
        mergein = TRUE;
      }

      if (mergein) {
        pr_log_debug(DEBUG2, MOD_IFSESSION_VERSION
          ": merging <IfClass %s> directives in", (char *) list->argv[0]);
        ifsess_dup_set(session.pool, main_server->conf, c->subset);

        /* Add this config_rec pointer to the list of pointers to be
         * removed later.
         */
        *((config_rec **) push_array(class_remove_list)) = c;

        /* Do NOT call fixup_dirs() here; we need to wait until after
         * authentication to do so (in which case, mod_auth will handle the
         * call to fixup_dirs() for us).
         */

        ifsess_merged = TRUE;

      } else {
        pr_log_debug(DEBUG9, MOD_IFSESSION_VERSION
          ": <IfClass %s> not matched, skipping", (char *) list->argv[0]);
      }
    }

    c = find_config_next(c, c->next, -1, IFSESS_CLASS_TEXT, FALSE);
  }

  /* Now, remove any <IfClass> config_recs that have been merged in. */
  for (i = 0; i < class_remove_list->nelts; i++) {
    c = ((config_rec **) class_remove_list->elts)[i];
    xaset_remove(main_server->conf, (xasetmember_t *) c);
  }

  destroy_pool(tmp_pool);
  return 0;
}

/* Configuration handlers
 */

MODRET start_ifctxt(cmd_rec *cmd) {
  config_rec *c = NULL;
  int config_type = 0, eval_type = 0;
  unsigned int argc = 0;
  char *name = NULL;
  void **argv = NULL;
  array_header *acl = NULL;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = pr_parser_config_ctxt_open(cmd->argv[0]);

  /* "Inherit" the parent's context type. */
  c->config_type = (cmd->config && cmd->config->config_type != CONF_PARAM ?
    cmd->config->config_type : cmd->server->config_type ?
    cmd->server->config_type : CONF_ROOT);

  if (strcmp(cmd->argv[0], IFSESS_CLASS_TEXT) == 0) {
    name = "_IfClassList";
    ifsess_ctx = config_type = IFSESS_CLASS_NUMBER;
    eval_type = PR_EXPR_EVAL_OR;

    if (cmd->argc-1 < 1) {
      CONF_ERROR(cmd, "wrong number of parameters");
    }

  } else if (strcmp(cmd->argv[0], IFSESS_GROUP_TEXT) == 0) {
    name = "_IfGroupList";
    ifsess_ctx = config_type = IFSESS_GROUP_NUMBER;
    eval_type = PR_EXPR_EVAL_AND;

    if (cmd->argc-1 < 1) {
      CONF_ERROR(cmd, "wrong number of parameters");
    }

  } else if (strcmp(cmd->argv[0], IFSESS_USER_TEXT) == 0) {
    name = "_IfUserList";
    ifsess_ctx = config_type = IFSESS_USER_NUMBER;
    eval_type = PR_EXPR_EVAL_OR;

    if (cmd->argc-1 < 1) {
      CONF_ERROR(cmd, "wrong number of parameters");
    }

  } else if (strcmp(cmd->argv[0], IFSESS_AUTHN_TEXT) == 0) {
    name = "_IfAuthenticatedList";
    ifsess_ctx = config_type = IFSESS_AUTHN_NUMBER;
    eval_type = PR_EXPR_EVAL_OR;

    /* <IfAuthenticated> sections don't take any parameters. */
    if (cmd->argc > 1) {
      CONF_ERROR(cmd, "wrong number of parameters");
    }
  }

  /* Is this a normal expression, an explicit AND, an explicit OR, or a
   * regular expression?
   */
  if (cmd->argc-1 > 1) {
    if (strncmp(cmd->argv[1], "AND", 4) == 0) {
      eval_type = PR_EXPR_EVAL_AND;
      argc = cmd->argc-2;
      argv = cmd->argv+1;

    } else if (strncmp(cmd->argv[1], "OR", 3) == 0) {
      eval_type = PR_EXPR_EVAL_OR;
      argc = cmd->argc-2;
      argv = cmd->argv+1;

    } else if (strncmp(cmd->argv[1], "regex", 6) == 0) {
#ifdef PR_USE_REGEX
      pr_regex_t *pre = NULL;
      int res = 0;

      if (cmd->argc != 3)
        CONF_ERROR(cmd, "wrong number of parameters");

      pre = pr_regexp_alloc(&ifsession_module);

      res = pr_regexp_compile(pre, cmd->argv[2], REG_EXTENDED|REG_NOSUB);
      if (res != 0) {
        char errstr[200] = {'\0'};

        pr_regexp_error(res, pre, errstr, sizeof(errstr));
        pr_regexp_free(NULL, pre);

        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": '", cmd->argv[2], "' failed "
          "regex compilation: ", errstr, NULL));
      }

      eval_type = PR_EXPR_EVAL_REGEX;

      c = add_config_param(name, 3, NULL, NULL, NULL);
      c->config_type = config_type;
      c->argv[0] = pstrdup(c->pool, cmd->arg);
      c->argv[1] = pcalloc(c->pool, sizeof(unsigned char));
      *((unsigned char *) c->argv[1]) = eval_type;
      c->argv[2] = (void *) pre;

      return PR_HANDLED(cmd);

#else
      CONF_ERROR(cmd, "The 'regex' parameter cannot be used on this system, "
        "as you do not have POSIX compliant regex support");
#endif /* regex support */

    } else {
      argc = cmd->argc-1;
      argv = cmd->argv;
    }

  } else {
    argc = cmd->argc-1;
    argv = cmd->argv;
  }

  acl = pr_expr_create(cmd->tmp_pool, &argc, (char **) argv);
  if (acl == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error creating regex expression: ",
      strerror(errno), NULL));
  }

  c = add_config_param(name, 0);

  c->config_type = config_type;
  c->argc = acl->nelts + 2;
  c->argv = pcalloc(c->pool, (c->argc + 2) * sizeof(void *));
  c->argv[0] = pstrdup(c->pool, cmd->arg);
  c->argv[1] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[1]) = eval_type;

  argv = c->argv + 2;

  if (acl) {
    while (acl->nelts--) {
      *argv++ = pstrdup(c->pool, *((char **) acl->elts));
      acl->elts = ((char **) acl->elts) + 1;
    }
  }

  *argv = NULL;
  return PR_HANDLED(cmd);
}

MODRET end_ifctxt(cmd_rec *cmd) {
  pr_parser_config_ctxt_close(NULL);

  switch (ifsess_ctx) {
    case IFSESS_CLASS_NUMBER:
      if (strcasecmp("</IfClass>", cmd->argv[0]) == 0) {
        ifsess_ctx = -1;
      }
      break;

    case IFSESS_GROUP_NUMBER:
      if (strcasecmp("</IfGroup>", cmd->argv[0]) == 0) {
        ifsess_ctx = -1;
      }
      break;

    case IFSESS_USER_NUMBER:
      if (strcasecmp("</IfUser>", cmd->argv[0]) == 0) {
        ifsess_ctx = -1;
      }
      break;

    case IFSESS_AUTHN_NUMBER:
      if (strcasecmp("</IfAuthenticated>", cmd->argv[0]) == 0) {
        ifsess_ctx = -1;
      }
      break;
  }

  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET ifsess_pre_pass(cmd_rec *cmd) {
  config_rec *c;
  const char *user = NULL, *group = NULL, *sess_user, *sess_group;
  char *displaylogin = NULL;
  array_header *gids = NULL, *groups = NULL, *sess_groups = NULL;
  struct passwd *pw = NULL;
  struct group *gr = NULL;
  xaset_t *config_set = NULL;

  /* Look for a DisplayLogin file which has an absolute path.  If we find one,
   * open a filehandle, such that that file can be displayed even if the
   * session is chrooted.  DisplayLogin files with relative paths will be
   * handled after chroot, preserving the old behavior.
   */

  user = pr_table_get(session.notes, "mod_auth.orig-user", NULL); 
  if (user == NULL) {
    return PR_DECLINED(cmd);
  }

  pw = pr_auth_getpwnam(cmd->tmp_pool, user);
  if (pw == NULL) {
    pr_trace_msg(trace_channel, 9,
      "unable to lookup user '%s' (%s), skipping pre-PASS handling",
      user, strerror(errno));
    return PR_DECLINED(cmd);
  }
 
  gr = pr_auth_getgrgid(cmd->tmp_pool, pw->pw_gid);
  if (gr != NULL) {
    group = gr->gr_name;
  }

  (void) pr_auth_getgroups(cmd->tmp_pool, user, &gids, &groups);
 
  /* Temporarily set session.user, session.group, session.groups, for the
   * sake of the pr_eval_*() function calls.
   */
  sess_user = session.user;
  sess_group = session.group;
  sess_groups = session.groups;

  session.user = user;
  session.group = group;
  session.groups = groups;

  c = find_config(main_server->conf, -1, IFSESS_GROUP_TEXT, FALSE);
  while (c) {
    config_rec *list = NULL;

    pr_signals_handle();

    list = find_config(c->subset, IFSESS_GROUP_NUMBER, NULL, FALSE);
    if (list != NULL) {
#ifdef PR_USE_REGEX
      if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_REGEX) {
        pr_regex_t *pre = list->argv[2];

        if (session.group != NULL) {
          if (pr_regexp_exec(pre, session.group, 0, NULL, 0, 0, 0) == 0) {
            displaylogin = get_param_ptr(c->subset, "DisplayLogin", FALSE);
            if (displaylogin != NULL) {
              if (*displaylogin == '/') {
                config_set = c->subset;
              }
            }
          }
        }

        if (displaylogin == NULL &&
            session.groups != NULL) {
          register int j = 0;

          for (j = session.groups->nelts-1; j >= 0; j--) {
            char *suppl_group;

            suppl_group = *(((char **) session.groups->elts) + j);

            if (pr_regexp_exec(pre, suppl_group, 0, NULL, 0, 0, 0) == 0) {
              displaylogin = get_param_ptr(c->subset, "DisplayLogin", FALSE);
              if (displaylogin != NULL) {
                if (*displaylogin == '/') {
                  config_set = c->subset;
                }
              }

              break;
            }
          }
        }

      } else
#endif /* regex support */
   
      if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_OR &&
          pr_expr_eval_group_or((char **) &list->argv[2]) == TRUE) {
        displaylogin = get_param_ptr(c->subset, "DisplayLogin", FALSE);
        if (displaylogin != NULL) {
          if (*displaylogin == '/') {
            config_set = c->subset;
          }
        }

      } else if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_AND &&
          pr_expr_eval_group_and((char **) &list->argv[2]) == TRUE) {

        displaylogin = get_param_ptr(c->subset, "DisplayLogin", FALSE);
        if (displaylogin != NULL) {
          if (*displaylogin == '/') {
            config_set = c->subset;
          }
        }
      }
    }

    c = find_config_next(c, c->next, -1, IFSESS_GROUP_TEXT, FALSE);
  }

  c = find_config(main_server->conf, -1, IFSESS_USER_TEXT, FALSE);
  while (c) {
    config_rec *list = NULL;

    pr_signals_handle();

    list = find_config(c->subset, IFSESS_USER_NUMBER, NULL, FALSE);
    if (list != NULL) {
#ifdef PR_USE_REGEX
      if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_REGEX) {
        pr_regex_t *pre = list->argv[2];

        if (pr_regexp_exec(pre, session.user, 0, NULL, 0, 0, 0) == 0) {
          displaylogin = get_param_ptr(c->subset, "DisplayLogin", FALSE);
          if (displaylogin != NULL) {
            if (*displaylogin == '/') {
              config_set = c->subset;
            }
          }
        }

      } else
#endif /* regex support */

      if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_OR &&
          pr_expr_eval_user_or((char **) &list->argv[2]) == TRUE) {
        displaylogin = get_param_ptr(c->subset, "DisplayLogin", FALSE);
        if (displaylogin != NULL) {
          if (*displaylogin == '/') {
            config_set = c->subset;
          }
        }

      } else if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_AND &&
          pr_expr_eval_user_and((char **) &list->argv[2]) == TRUE) {
        displaylogin = get_param_ptr(c->subset, "DisplayLogin", FALSE);
        if (displaylogin != NULL) {
          if (*displaylogin == '/') {
            config_set = c->subset;
          }
        }
      }
    }

    c = find_config_next(c, c->next, -1, IFSESS_USER_TEXT, FALSE);
  }

  /* Restore the original session.user, session.group, session.groups values. */
  session.user = sess_user;
  session.group = sess_group;
  session.groups = sess_groups;

  if (displaylogin != NULL &&
      config_set != NULL) {

    displaylogin_fh = pr_fsio_open(displaylogin, O_RDONLY);
    if (displaylogin_fh == NULL) {
      pr_log_debug(DEBUG6,
        MOD_IFSESSION_VERSION ": unable to open DisplayLogin file '%s': %s",
        displaylogin, strerror(errno));

    } else {
      struct stat st;

      if (pr_fsio_fstat(displaylogin_fh, &st) < 0) {
        pr_log_debug(DEBUG6,
          MOD_IFSESSION_VERSION ": unable to stat DisplayLogin file '%s': %s",
          displaylogin, strerror(errno));
        pr_fsio_close(displaylogin_fh);
        displaylogin_fh = NULL;

      } else {
        if (S_ISDIR(st.st_mode)) {
          errno = EISDIR;
          pr_log_debug(DEBUG6,
            MOD_IFSESSION_VERSION ": unable to use DisplayLogin file '%s': %s",
            displaylogin, strerror(errno));
          pr_fsio_close(displaylogin_fh);
          displaylogin_fh = NULL;

        } else {
          /* Remove the directive from the set, since we'll be handling it. */
          remove_config(config_set, "DisplayLogin", FALSE);
        }
      }
    }
  }

  return PR_DECLINED(cmd);
}

MODRET ifsess_post_pass(cmd_rec *cmd) {
  register unsigned int i = 0;
  config_rec *c = NULL;
  int found = 0;
  pool *tmp_pool = make_sub_pool(session.pool);
  array_header *authn_remove_list = make_array(tmp_pool, 1,
    sizeof(config_rec *));
  array_header *group_remove_list = make_array(tmp_pool, 1,
    sizeof(config_rec *));
  array_header *user_remove_list = make_array(tmp_pool, 1,
    sizeof(config_rec *));

  /* Unfortunately, I can't assign my own context types for these custom
   * contexts, otherwise the existing directives would not be allowed in
   * them.  Good to know for the future, though, when developing modules that
   * want to have their own complete contexts (e.g. mod_time-3.0).
   *
   * However, I _can_ add a directive config_rec to these contexts that has
   * its own custom config_type.  And by using -1 as the context type when
   * searching via find_config(), it will match any context as long as the
   * name also matches.  Note: using a type of -1 and a name of NULL will
   * result in a scan of the whole in-memory db.  Hmm...
   */

  c = find_config(main_server->conf, -1, IFSESS_AUTHN_TEXT, FALSE);
  while (c) {
    config_rec *list = NULL;

    pr_signals_handle();

    list = find_config(c->subset, IFSESS_AUTHN_NUMBER, NULL, FALSE);
    if (list != NULL) {
      pr_log_debug(DEBUG2, MOD_IFSESSION_VERSION
        ": merging <IfAuthenticated> directives in");
      ifsess_dup_set(session.pool, main_server->conf, c->subset);

      /* Add this config_rec pointer to the list of pointers to be
       * removed later.
       */
      *((config_rec **) push_array(authn_remove_list)) = c;

      ifsess_resolve_server_dirs(main_server);
      resolve_deferred_dirs(main_server);

      /* We need to call fixup_dirs() twice: once for any added <Directory>
       * sections that use absolute paths, and again for any added <Directory>
       * sections that use deferred-resolution paths (e.g. "~").
       */
      fixup_dirs(main_server, CF_SILENT);
      fixup_dirs(main_server, CF_DEFER|CF_SILENT);

      ifsess_merged = TRUE;
    }

    c = find_config_next(c, c->next, -1, IFSESS_AUTHN_TEXT, FALSE);
  }

  /* Now, remove any <IfAuthenticated> config_recs that have been merged in. */
  for (i = 0; i < authn_remove_list->nelts; i++) {
    c = ((config_rec **) authn_remove_list->elts)[i];
    xaset_remove(main_server->conf, (xasetmember_t *) c);
  }

  c = find_config(main_server->conf, -1, IFSESS_GROUP_TEXT, FALSE);
  while (c) {
    config_rec *list = NULL;

    pr_signals_handle();

    list = find_config(c->subset, IFSESS_GROUP_NUMBER, NULL, FALSE);
    if (list != NULL) {
      unsigned char mergein = FALSE;

#ifdef PR_USE_REGEX
      if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_REGEX) {
        pr_regex_t *pre = list->argv[2];

        if (session.group != NULL) {
          pr_log_debug(DEBUG8, MOD_IFSESSION_VERSION
            ": evaluating regexp pattern '%s' against subject '%s'",
            pr_regexp_get_pattern(pre), session.group);

          if (pr_regexp_exec(pre, session.group, 0, NULL, 0, 0, 0) == 0) {
            mergein = TRUE;
          }
        }

        if (mergein == FALSE &&
            session.groups != NULL) {
          register int j = 0;

          for (j = session.groups->nelts-1; j >= 0; j--) {
            char *suppl_group;

            suppl_group = *(((char **) session.groups->elts) + j);

            pr_log_debug(DEBUG8, MOD_IFSESSION_VERSION
              ": evaluating regexp pattern '%s' against subject '%s'",
              pr_regexp_get_pattern(pre), suppl_group);

            if (pr_regexp_exec(pre, suppl_group, 0, NULL, 0, 0, 0) == 0) {
              mergein = TRUE;
              break;
            }
          }
        }

      } else
#endif /* regex support */
    
      if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_OR &&
          pr_expr_eval_group_or((char **) &list->argv[2]) == TRUE) {
        mergein = TRUE;

      } else if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_AND &&
          pr_expr_eval_group_and((char **) &list->argv[2]) == TRUE) {
        mergein = TRUE;
      }

      if (mergein) {
        pr_log_debug(DEBUG2, MOD_IFSESSION_VERSION
          ": merging <IfGroup %s> directives in", (char *) list->argv[0]);
        ifsess_dup_set(session.pool, main_server->conf, c->subset);

        /* Add this config_rec pointer to the list of pointers to be
         * removed later.
         */
        *((config_rec **) push_array(group_remove_list)) = c;

        ifsess_resolve_server_dirs(main_server);
        resolve_deferred_dirs(main_server);

        /* We need to call fixup_dirs() twice: once for any added <Directory>
         * sections that use absolute paths, and again for any added <Directory>
         * sections that use deferred-resolution paths (e.g. "~").
         */
        fixup_dirs(main_server, CF_SILENT);
        fixup_dirs(main_server, CF_DEFER|CF_SILENT);

        ifsess_merged = TRUE;

      } else {
        pr_log_debug(DEBUG9, MOD_IFSESSION_VERSION
          ": <IfGroup %s> not matched, skipping", (char *) list->argv[0]);
      }
    }

    /* Note: it would be more efficient, memory-wise, to destroy the
     * memory pool of the removed config_rec.  However, the dup'd data
     * from that config_rec may point to memory within the pool being
     * freed; and once freed, that memory becomes fair game, and thus may
     * (and probably will) be overwritten.  This means that, for now,
     * keep the removed config_rec's memory around, rather than calling
     * destroy_pool(c->pool) if removed_c is TRUE.
     */

    c = find_config_next(c, c->next, -1, IFSESS_GROUP_TEXT, FALSE);
  }

  /* Now, remove any <IfGroup> config_recs that have been merged in. */
  for (i = 0; i < group_remove_list->nelts; i++) {
    c = ((config_rec **) group_remove_list->elts)[i];
    xaset_remove(main_server->conf, (xasetmember_t *) c);
  }

  c = find_config(main_server->conf, -1, IFSESS_USER_TEXT, FALSE);
  while (c) {
    config_rec *list = NULL;

    pr_signals_handle();

    list = find_config(c->subset, IFSESS_USER_NUMBER, NULL, FALSE);
    if (list != NULL) {
      unsigned char mergein = FALSE;

#ifdef PR_USE_REGEX
      if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_REGEX) {
        pr_regex_t *pre = list->argv[2];

        pr_log_debug(DEBUG8, MOD_IFSESSION_VERSION
          ": evaluating regexp pattern '%s' against subject '%s'",
          pr_regexp_get_pattern(pre), session.user);

        if (pr_regexp_exec(pre, session.user, 0, NULL, 0, 0, 0) == 0) {
          mergein = TRUE;
        }

      } else
#endif /* regex support */

      if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_OR &&
          pr_expr_eval_user_or((char **) &list->argv[2]) == TRUE) {
        mergein = TRUE;

      } else if (*((unsigned char *) list->argv[1]) == PR_EXPR_EVAL_AND &&
          pr_expr_eval_user_and((char **) &list->argv[2]) == TRUE) {
        mergein = TRUE;
      }

      if (mergein) {
        pr_log_debug(DEBUG2, MOD_IFSESSION_VERSION
          ": merging <IfUser %s> directives in", (char *) list->argv[0]);
        ifsess_dup_set(session.pool, main_server->conf, c->subset);

        /* Add this config_rec pointer to the list of pointers to be
         * removed later.
         */
        *((config_rec **) push_array(user_remove_list)) = c;

        ifsess_resolve_server_dirs(main_server);
        resolve_deferred_dirs(main_server);

        /* We need to call fixup_dirs() twice: once for any added <Directory>
         * sections that use absolute paths, and again for any added <Directory>
         * sections that use deferred-resolution paths (e.g. "~").
         */
        fixup_dirs(main_server, CF_SILENT);
        fixup_dirs(main_server, CF_DEFER|CF_SILENT);

        ifsess_merged = TRUE;

      } else {
        pr_log_debug(DEBUG9, MOD_IFSESSION_VERSION
          ": <IfUser %s> not matched, skipping", (char *) list->argv[0]);
      }
    }

    c = find_config_next(c, c->next, -1, IFSESS_USER_TEXT, FALSE);
  }

  /* Now, remove any <IfUser> config_recs that have been merged in. */
  for (i = 0; i < user_remove_list->nelts; i++) {
    c = ((config_rec **) user_remove_list->elts)[i];
    xaset_remove(main_server->conf, (xasetmember_t *) c);
  }

  destroy_pool(tmp_pool);

  if (ifsess_merged) {
    /* Try to honor any <Limit LOGIN> sections that may have been merged in. */
    if (!login_check_limits(TOPLEVEL_CONF, FALSE, TRUE, &found)) {
      pr_log_debug(DEBUG3, MOD_IFSESSION_VERSION
        ": %s %s: Limit access denies login",
        session.anon_config ? "ANON" : C_USER, session.user);

      pr_log_auth(PR_LOG_NOTICE, "%s %s: Limit access denies login.",
        session.anon_config ? "ANON" : C_USER, session.user);
      pr_session_disconnect(&ifsession_module, PR_SESS_DISCONNECT_CONFIG_ACL,
        "Denied by <Limit LOGIN>");
    }

    /* Try to honor any DisplayLogin directives that may have been merged
     * in (Bug#3882).
     */
    if (displaylogin_fh != NULL) {
      if (pr_display_fh(displaylogin_fh, NULL, R_230, 0) < 0) {
        pr_log_debug(DEBUG6, "unable to display DisplayLogin file '%s': %s",
          displaylogin_fh->fh_path, strerror(errno));
      }

      pr_fsio_close(displaylogin_fh);
      displaylogin_fh = NULL;
    }
  }

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

static void ifsess_chroot_ev(const void *event_data, void *user_data) {
  ifsess_home_dir = (const char *) event_data;
}

#ifdef PR_SHARED_MODULE
static void ifsess_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_ifsession.c", (const char *) event_data) == 0) {
    pr_event_unregister(&ifsession_module, NULL, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

static void ifsess_postparse_ev(const void *event_data, void *user_data) {
  /* Make sure that all mod_ifsession sections have been properly closed. */

  if (ifsess_ctx == -1) {
    /* All sections properly closed; nothing to do. */
    return;
  }

  switch (ifsess_ctx) {
    case IFSESS_CLASS_NUMBER:
      pr_log_pri(PR_LOG_WARNING,
        "error: unclosed <IfClass> context in config file");
      break;

    case IFSESS_GROUP_NUMBER:
      pr_log_pri(PR_LOG_WARNING,
        "error: unclosed <IfGroup> context in config file");
      break;

    case IFSESS_USER_NUMBER:
      pr_log_pri(PR_LOG_WARNING,
        "error: unclosed <IfUser> context in config file");
      break;
  }

  pr_session_disconnect(&ifsession_module, PR_SESS_DISCONNECT_BAD_CONFIG, NULL);
  return;
}

/* Initialization routines
 */

static int ifsess_init(void) {
#ifdef PR_SHARED_MODULE
  pr_event_register(&ifsession_module, "core.module-unload",
    ifsess_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  pr_event_register(&ifsession_module, "core.chroot",
    ifsess_chroot_ev, NULL);
  pr_event_register(&ifsession_module, "core.postparse",
    ifsess_postparse_ev, NULL);

  return 0;
}

static int ifsess_sess_init(void) {
  if (ifsess_sess_merge_class() < 0) {
    return -1;
  }

  return 0;
}

/* Module API tables
 */

static conftable ifsess_conftab[] = {
  { IFSESS_AUTHN_TEXT,		start_ifctxt,	NULL },
  { "</IfAuthenticated>",	end_ifctxt,	NULL },
  { IFSESS_CLASS_TEXT,		start_ifctxt,	NULL },
  { "</IfClass>",		end_ifctxt,	NULL },
  { IFSESS_GROUP_TEXT,		start_ifctxt,	NULL },
  { "</IfGroup>",		end_ifctxt,	NULL },
  { IFSESS_USER_TEXT,		start_ifctxt,	NULL },
  { "</IfUser>",		end_ifctxt,	NULL },
  { NULL }
};

static cmdtable ifsess_cmdtab[] = {
  { PRE_CMD,	C_PASS, G_NONE, ifsess_pre_pass, FALSE, FALSE },
  { POST_CMD,	C_PASS, G_NONE, ifsess_post_pass, FALSE, FALSE },
  { 0, NULL }
};

module ifsession_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "ifsession",

  /* Module configuration handler table */
  ifsess_conftab,

  /* Module command handler table */
  ifsess_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  ifsess_init,

  /* Session initialization function */
  ifsess_sess_init,

  /* Module version */
  MOD_IFSESSION_VERSION
};
