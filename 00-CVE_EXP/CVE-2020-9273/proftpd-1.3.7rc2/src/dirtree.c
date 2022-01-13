/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2017 The ProFTPD Project team
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

/* Read configuration file(s), and manage server/configuration structures. */

#include "conf.h"

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

xaset_t *server_list = NULL;
server_rec *main_server = NULL;
int tcpBackLog = PR_TUNABLE_DEFAULT_BACKLOG;
int SocketBindTight = FALSE;
char ServerType = SERVER_STANDALONE;
unsigned long ServerMaxInstances = 0UL;
int ServerUseReverseDNS = TRUE;

/* Default TCP send/receive buffer sizes. */
static int tcp_rcvbufsz = 0;
static int tcp_sndbufsz = 0;
static int xfer_bufsz = 0;

static unsigned char _kludge_disable_umask = 0;

/* We have two different lists for Defines.  The 'perm' pool/list are
 * for "permanent" defines, i.e. those set on the command-line via the
 * -D/--define options.
 */
static pool *defines_pool = NULL;
static array_header *defines_list = NULL;

static pool *defines_perm_pool = NULL;
static array_header *defines_perm_list = NULL;

static int allow_dyn_config(const char *path) {
  config_rec *c = NULL;
  unsigned int ctxt_precedence = 0;
  unsigned char allow = TRUE, found_config = FALSE;

  c = find_config(CURRENT_CONF, CONF_PARAM, "AllowOverride", FALSE);
  while (c) {
    pr_signals_handle();

    if (*((unsigned int *) c->argv[1]) > ctxt_precedence) {

      /* Set the context precedence. */
      ctxt_precedence = *((unsigned int *) c->argv[1]);

      allow = *((int *) c->argv[0]);

      found_config = TRUE;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "AllowOverride", FALSE);
  }

  /* Print out some nice debugging information, but only if we have a real
   * path.
   */
  if (found_config &&
      *path) {
    pr_trace_msg("config", 8,
      "AllowOverride for path '%s' %s .ftpaccess files", path,
      allow ? "allows" : "denies");
  }

  return allow;
}

/* Imported this function from modules/mod_ls.c -- it belongs more with the
 * dir_* functions here, rather than the ls_* functions there.
 */

/* Return true if dir is ".", "./", "../", or "..". */
int is_dotdir(const char *dir) {
  if (strncmp(dir, ".", 2) == 0 ||
      strncmp(dir, "./", 2) == 0 ||
      strncmp(dir, "..", 3) == 0 ||
      strncmp(dir, "../", 3) == 0) {
    return TRUE;
  }

  return FALSE;
}

/* Lookup the best configuration set from which to retrieve configuration
 * values if the config_rec can appear in <Directory>.  This function
 * works around the issue caused by using the cached directory pointer
 * in session.dir_config.
 *
 * The issue with using session.dir_config is that it is assigned when
 * the client changes directories or doing other directory lookups, and so
 * dir_config may actually point to the configuration for a directory other
 * than the target directory for an uploaded, for example.  Unfortunately,
 * it is more expensive to lookup the configuration for the target directory
 * every time.  Perhaps some caching of looked up directory configurations
 * into a table, rather than a single pointer like session.dir_config,
 * might help.
 */
xaset_t *get_dir_ctxt(pool *p, char *dir_path) {
  config_rec *c = NULL;
  char *full_path = dir_path;

  if (session.chroot_path) {
    if (*dir_path != '/') {
      full_path = pdircat(p, session.chroot_path, session.cwd, dir_path, NULL);

    } else {
      full_path = pdircat(p, session.chroot_path, dir_path, NULL);
    }

  } else if (*dir_path != '/') {
    full_path = pdircat(p, session.cwd, dir_path, NULL);
  }

  c = dir_match_path(p, full_path);

  return c ? c->subset : session.anon_config ? session.anon_config->subset :
    main_server->conf;
}

/* Check for configured HideFiles directives, and check the given path (full
 * _path_, not just filename) against those regexes if configured.
 *
 * Returns FALSE if the path should be shown/listed, TRUE if it should not
 * be visible.
 */
unsigned char dir_hide_file(const char *path) {
#ifdef PR_USE_REGEX
  char *file_name = NULL, *dir_name = NULL;
  config_rec *c = NULL;
  pr_regex_t *pre = NULL;
  pool *tmp_pool;
  unsigned int ctxt_precedence = 0;
  unsigned char have_user_regex, have_group_regex, have_class_regex,
    have_all_regex, negated = FALSE;

  if (path == NULL) {
    return FALSE;
  }

  tmp_pool = make_sub_pool(session.pool);
  pr_pool_tag(tmp_pool, "dir_hide_file() tmp pool");

  have_user_regex = have_group_regex = have_class_regex = have_all_regex =
    FALSE;

  /* Separate the given path into directory and file components. */
  dir_name = pstrdup(tmp_pool, path);

  file_name = strrchr(dir_name, '/');
  if (file_name != NULL) {

    if (file_name != dir_name) {
      /* Handle paths like "/path". */
      *file_name = '\0';
      file_name++;

    } else {
      /* Handle "/". */
      dir_name = "/";

      if (strlen(file_name) > 1) {
        file_name++;

      } else {
        /* Handle "/". */
        file_name = "/";
      }
    }

  } else {
    file_name = dir_name;
  }

  /* Check for any configured HideFiles */
  c = find_config(get_dir_ctxt(tmp_pool, dir_name), CONF_PARAM, "HideFiles",
    FALSE);

  while (c) {
    pr_signals_handle();

    if (c->argc >= 4) {

      /* check for a specified "user" classifier first... */
      if (strncmp(c->argv[3], "user", 5) == 0) {
        if (pr_expr_eval_user_or((char **) &c->argv[4]) == TRUE) {

          if (*((unsigned int *) c->argv[2]) > ctxt_precedence) {
            ctxt_precedence = *((unsigned int *) c->argv[2]);

            pre = *((pr_regex_t **) c->argv[0]);
            negated = *((unsigned char *) c->argv[1]);

            have_group_regex = have_class_regex = have_all_regex = FALSE;
            have_user_regex = TRUE;
          }
        }

      /* ...then for a "group" classifier... */
      } else if (strncmp(c->argv[3], "group", 6) == 0) {
        if (pr_expr_eval_group_and((char **) &c->argv[4]) == TRUE) {
          if (*((unsigned int *) c->argv[2]) > ctxt_precedence) {
            ctxt_precedence = *((unsigned int *) c->argv[2]);

            pre = *((pr_regex_t **) c->argv[0]);
            negated = *((unsigned char *) c->argv[1]);

            have_user_regex = have_class_regex = have_all_regex = FALSE;
            have_group_regex = TRUE;
          }
        }

      /* ...finally, for a "class" classifier.  NOTE: mod_time's
       * class_expression functionality should really be added into the
       * core code at some point.  When that happens, then this code will
       * need to be updated to process class-expressions.
       */
      } else if (strncmp(c->argv[3], "class", 6) == 0) {
        if (pr_expr_eval_class_or((char **) &c->argv[4]) == TRUE) {
          if (*((unsigned int *) c->argv[2]) > ctxt_precedence) {
            ctxt_precedence = *((unsigned int *) c->argv[2]);

            pre = *((pr_regex_t **) c->argv[0]);
            negated = *((unsigned char *) c->argv[1]);

            have_user_regex = have_group_regex = have_all_regex = FALSE;
            have_class_regex = TRUE;
          }
        }
      }

    } else if (c->argc == 1) {

      /* This is the "none" HideFiles parameter. */
      destroy_pool(tmp_pool);
      return FALSE;

    } else {
      if (*((unsigned int *) c->argv[2]) > ctxt_precedence) {
        ctxt_precedence = *((unsigned int *) c->argv[2]);

        pre = *((pr_regex_t **) c->argv[0]);
        negated = *((unsigned char *) c->argv[1]);

        have_user_regex = have_group_regex = have_class_regex = FALSE;
        have_all_regex = TRUE;
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "HideFiles", FALSE);
  }

  if (have_user_regex || have_group_regex ||
      have_class_regex || have_all_regex) {

    pr_log_debug(DEBUG4, "checking %sHideFiles pattern for current %s",
      negated ? "negated " : "",
      have_user_regex ? "user" : have_group_regex ? "group" :
      have_class_regex ? "class" : "session");

    if (pre == NULL) {
      destroy_pool(tmp_pool);

      /* HideFiles none for this user/group/class */

      pr_log_debug(DEBUG9, "file '%s' did not match HideFiles pattern 'none'",
        file_name);
      return FALSE;
    }

    if (pr_regexp_exec(pre, file_name, 0, NULL, 0, 0, 0) != 0) {
      destroy_pool(tmp_pool);

      pr_log_debug(DEBUG9, "file '%s' did not match %sHideFiles pattern",
        file_name, negated ? "negated " : "");

      /* The file failed to match the HideFiles regex, which means it should
       * be treated as a "visible" file.  If the regex was negated, though,
       * switch the result.
       */
      return (negated ? TRUE : FALSE);

    } else {
      destroy_pool(tmp_pool);

      pr_log_debug(DEBUG9, "file '%s' matched %sHideFiles pattern", file_name,
        negated ? "negated " : "");

      /* The file matched the HideFiles regex, which means it should be
       * considered a "hidden" file.  If the regex was negated, though,
       * switch the result.
       */
      return (negated ? FALSE : TRUE);
    }
  }

  destroy_pool(tmp_pool);
#endif /* regex support */

  /* Return FALSE by default. */
  return FALSE;	
}

static void define_restart_ev(const void *event_data, void *user_data) {
  if (defines_pool) {
    destroy_pool(defines_pool);
    defines_pool = NULL;
    defines_list = NULL;
  }

  pr_event_unregister(NULL, "core.restart", define_restart_ev);
}

/* The 'survive_restarts' boolean indicates whether this Define is to be
 * permanent for the lifetime of the daemon (i.e. survives across restarts)
 * or whether it should be cleared when restarted.
 *
 * Right now, defines from the command-line will surive restarts, but
 * defines from the config (via the Define directive) will not.
 */
int pr_define_add(const char *definition, int survive_restarts) {

  if (definition == NULL ||
      (survive_restarts != FALSE && survive_restarts != TRUE)) {
    errno = EINVAL;
    return -1;
  }

  if (survive_restarts == FALSE) {
    if (defines_pool == NULL) {
      defines_pool = make_sub_pool(permanent_pool);
      pr_pool_tag(defines_pool, "Defines Pool");
      pr_event_register(NULL, "core.restart", define_restart_ev, NULL);
    }

    if (!defines_list) {
      defines_list = make_array(defines_pool, 0, sizeof(char *));

    }

    *((char **) push_array(defines_list)) = pstrdup(defines_pool, definition);
    return 0;
  }

  if (defines_perm_pool == NULL) {
    defines_perm_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(defines_perm_pool, "Permanent Defines Pool");
  }

  if (!defines_perm_list) {
    defines_perm_list = make_array(defines_perm_pool, 0, sizeof(char *)); 
  }

  *((char **) push_array(defines_perm_list)) =
    pstrdup(defines_perm_pool, definition);
  return 0;
}

unsigned char pr_define_exists(const char *definition) {
  if (definition == NULL) {
    errno = EINVAL;
    return FALSE;
  }

  if (defines_list) {
    char **defines = defines_list->elts;
    register unsigned int i = 0;

    for (i = 0; i < defines_list->nelts; i++) {
      if (defines[i] &&
          strcmp(defines[i], definition) == 0)
        return TRUE;
    }
  }

  if (defines_perm_list) {
    char **defines = defines_perm_list->elts;
    register unsigned int i = 0;

    for (i = 0; i < defines_perm_list->nelts; i++) {
      if (defines[i] &&
          strcmp(defines[i], definition) == 0)
        return TRUE;
    }
  }

  errno = ENOENT;
  return FALSE;
}

void kludge_disable_umask(void) {
  _kludge_disable_umask = TRUE;
}

void kludge_enable_umask(void) {
  _kludge_disable_umask = FALSE;
}

/* Per-directory configuration */

static size_t _strmatch(register char *s1, register char *s2) {
  register size_t len = 0;

  while (*s1 && *s2 && *s1++ == *s2++)
    len++;

  return len;
}

static config_rec *recur_match_path(pool *p, xaset_t *s, char *path) {
  char *suffixed_path = NULL, *tmp_path = NULL;
  config_rec *c = NULL, *res = NULL;

  if (!s) {
    errno = EINVAL;
    return NULL;
  }

  for (c = (config_rec *) s->xas_list; c; c = c->next) {
    if (c->config_type == CONF_DIR) {
      size_t path_len;

      tmp_path = c->name;

      if (c->argv[1]) {
        if (*(char *)(c->argv[1]) == '~') {
          c->argv[1] = dir_canonical_path(c->pool, (char *) c->argv[1]);
        }

        tmp_path = pdircat(p, (char *) c->argv[1], tmp_path, NULL);
      }

      /* Exact path match */
      if (strcmp(tmp_path, path) == 0) {
        pr_trace_msg("directory", 8,
          "<Directory %s> is an exact path match for '%s'", c->name, path);
        return c;
      }

      /* Bug#3146 occurred because using strstr(3) works well for paths
       * which DO NOT contain the glob sequence, i.e. we used to do:
       *
       *  if (strstr(tmp_path, slash_star) == NULL) {
       *
       * But what if they do, just not at the end of the path?
       *
       * The fix is to explicitly check the last two characters of the path
       * for '/' and '*', rather than using strstr(3).  (Again, I wish there
       * was a strrstr(3) libc function.)
       */
      path_len = strlen(tmp_path);
      if (path_len >= 2 &&
          !(tmp_path[path_len-2] == '/' && tmp_path[path_len-1] == '*')) {

        /* Trim a trailing path separator, if present. */
        if (path_len > 1 &&
            *tmp_path && 
            *(tmp_path + path_len - 1) == '/') {
          *(tmp_path + path_len - 1) = '\0';
          path_len--;

          if (strcmp(tmp_path, path) == 0) {
            pr_trace_msg("directory", 8,
              "<Directory %s> is an exact path match for '%s'", c->name, path);
            return c;
          }
        }

        suffixed_path = pdircat(p, tmp_path, "*", NULL);

      } else if (path_len == 1) {
        /* We still need to append the "*" if the path is just '/'. */
        suffixed_path = pstrcat(p, tmp_path, "*", NULL);
      }

      if (suffixed_path == NULL) {
        /* Default to treating the given path as the suffixed path */
        suffixed_path = tmp_path;
      }

      pr_trace_msg("directory", 9,
        "checking if <Directory %s> is a glob match for %s", tmp_path, path);

      /* The flags argument here needs to include PR_FNM_PATHNAME in order
       * to prevent globs from matching the '/' character.
       *
       * As per Bug#3491, we need to check if either a) the automatically
       * suffixed path (i.e. with the slash-star pattern) is a pattern match,
       * OR if b) the given path, as is, is a pattern match.
       */

      if (pr_fnmatch(suffixed_path, path, 0) == 0 ||
          (pr_str_is_fnmatch(tmp_path) &&
           pr_fnmatch(tmp_path, path, 0) == 0)) {
        pr_trace_msg("directory", 8,
          "<Directory %s> is a glob match for '%s'", tmp_path, path);

        if (c->subset) {
          /* If there's a subset config, check to see if there's a closer
           * match there.
           */
          res = recur_match_path(p, c->subset, path);
          if (res) {
            pr_trace_msg("directory", 8,
              "found closer matching <Directory %s> for '%s' in <Directory %s> "
              "sub-config", res->name, path, tmp_path);
            return res;
          }
        }

        pr_trace_msg("directory", 8, "found <Directory %s> for '%s'",
          c->name, path);
        return c;
      }
    }
  }

  errno = ENOENT;
  return NULL;
}

config_rec *dir_match_path(pool *p, char *path) {
  config_rec *res = NULL;
  char *tmp = NULL;
  size_t tmplen;

  if (p == NULL ||
      path == NULL ||
      *path == '\0') {
    errno = EINVAL;
    return NULL;
  }

  tmp = pstrdup(p, path);
  tmplen = strlen(tmp);

  if (*(tmp + tmplen - 1) == '*') {
    *(tmp + tmplen - 1) = '\0';
    tmplen = strlen(tmp);
  }

  if (*(tmp + tmplen - 1) == '/' && tmplen > 1) {
    *(tmp + tmplen - 1) = '\0';
  }

  if (session.anon_config) {
    res = recur_match_path(p, session.anon_config->subset, tmp);

    if (!res) {
      if (session.chroot_path &&
          !strncmp(session.chroot_path, tmp, strlen(session.chroot_path))) {
        return NULL;
      }
    }
  }

  if (!res) {
    res = recur_match_path(p, main_server->conf, tmp);
  }

  if (res) {
    pr_trace_msg("directory", 3, "matched <Directory %s> for path '%s'",
      res->name, tmp);

  } else {
    pr_trace_msg("directory", 3, "no matching <Directory> found for '%s': %s",
      tmp, strerror(errno));
  }

  return res;
}

/* Returns TRUE to allow, FALSE to deny. */
static int dir_check_op(pool *p, xaset_t *set, int op, const char *path,
    uid_t file_uid, gid_t file_gid, mode_t mode) {
  int res = TRUE;
  config_rec *c;

  /* Default is to allow. */
  if (!set)
    return TRUE;

  switch (op) {
    case OP_HIDE:
      c = find_config(set, CONF_PARAM, "HideUser", FALSE);
      while (c) {
        int inverted = FALSE;
        const char *hide_user = NULL;
        uid_t hide_uid = -1;

        pr_signals_handle();

        hide_user = c->argv[0];
        inverted = *((unsigned char *) c->argv[1]);

        if (strncmp(hide_user, "~", 2) == 0) {
          hide_uid = session.uid;

        } else {
          struct passwd *pw;

          pw = pr_auth_getpwnam(p, hide_user);
          if (pw == NULL) {
            pr_log_debug(DEBUG1,
              "HideUser '%s' is not a known/valid user, ignoring", hide_user);

            c = find_config_next(c, c->next, CONF_PARAM, "HideUser", FALSE);
            continue;
          }

          hide_uid = pw->pw_uid;
        }

        if (file_uid == hide_uid) {
          if (!inverted) {
            pr_trace_msg("hiding", 8,
              "hiding file '%s' because of HideUser %s", path, hide_user);
            res = FALSE;
          }
          break;

        } else {
          if (inverted) {
            pr_trace_msg("hiding", 8,
              "hiding file '%s' because of HideUser !%s", path, hide_user);
            res = FALSE;
            break;
          }
        }

        c = find_config_next(c, c->next, CONF_PARAM, "HideUser", FALSE);
      }

      /* We only need to check for HideGroup restrictions if we are not
       * already hiding the file.  I.e. if res = FALSE, then the path is to
       * be hidden, and we don't need to check for other reasons to hide it
       * (Bug#3530).
       */
      if (res == TRUE) {
        c = find_config(set, CONF_PARAM, "HideGroup", FALSE);
        while (c) {
          int inverted = FALSE;
          const char *hide_group = NULL;
          gid_t hide_gid = -1;

          pr_signals_handle();

          hide_group = c->argv[0];
          inverted = *((int *) c->argv[1]);

          if (strncmp(hide_group, "~", 2) == 0) {
            hide_gid = session.gid;

          } else {
            struct group *gr;

            gr = pr_auth_getgrnam(p, hide_group);
            if (gr == NULL) {
              pr_log_debug(DEBUG1,
                "HideGroup '%s' is not a known/valid group, ignoring",
                hide_group);

              c = find_config_next(c, c->next, CONF_PARAM, "HideGroup", FALSE);
              continue;
            }

            hide_gid = gr->gr_gid;
          }

          if (hide_gid != (gid_t) -1) {
            if (file_gid == hide_gid) {
              if (!inverted) {
                pr_trace_msg("hiding", 8,
                  "hiding file '%s' because of HideGroup %s", path, hide_group);
                res = FALSE;
              }

              break;

            } else {
              if (inverted) {
                pr_trace_msg("hiding", 8,
                  "hiding file '%s' because of HideGroup !%s", path,
                  hide_group);
                res = FALSE;
                break;
              }
            }

          } else {
            register unsigned int i;
            gid_t *group_ids = session.gids->elts;

            /* First check to see if the file GID matches the session GID. */
            if (file_gid == session.gid) {
              if (!inverted) {
                pr_trace_msg("hiding", 8,
                  "hiding file '%s' because of HideGroup %s", path, hide_group);
                res = FALSE;
              }

              break;
            }

            /* Next, scan the list of supplemental groups for this user. */
            for (i = 0; i < session.gids->nelts; i++) {
              if (file_gid == group_ids[i]) {
                if (!inverted) {
                  pr_trace_msg("hiding", 8,
                    "hiding file '%s' because of HideGroup %s", path, 
                    hide_group);
                  res = FALSE;
                }

                break;
              }
            }

            if (inverted) {
              pr_trace_msg("hiding", 8,
                "hiding file '%s' because of HideGroup !%s", path, hide_group);
              res = FALSE;
              break;
            }
          }

          c = find_config_next(c, c->next, CONF_PARAM, "HideGroup", FALSE);
        }
      }

      /* If we have already decided to hide this path (i.e. res = FALSE),
       * then we do not need to check for HideNoAccess.  Hence why we
       * only look for HideNoAccess here if res = TRUE (Bug#3530).
       */
      if (res == TRUE) {
        unsigned char *hide_no_access = NULL;

        hide_no_access = get_param_ptr(set, "HideNoAccess", FALSE);
        if (hide_no_access &&
            *hide_no_access == TRUE) {

          if (S_ISDIR(mode)) {
            /* Check to see if the mode of this directory allows the
             * current user to list its contents.
             */
            res = pr_fsio_access(path, X_OK, session.uid, session.gid,
              session.gids) == 0 ? TRUE : FALSE;
            if (res == FALSE) {
              int xerrno = errno;

              pr_trace_msg("hiding", 8,
                "hiding directory '%s' because of HideNoAccess (errno = %s)",
                path, strerror(xerrno));
              errno = xerrno;
            }

          } else {
            /* Check to see if the mode of this file allows the current
             * user to read it.
             */
            res = pr_fsio_access(path, R_OK, session.uid, session.gid,
              session.gids) == 0 ? TRUE : FALSE;
            if (res == FALSE) {
              int xerrno = errno;

              pr_trace_msg("hiding", 8,
                "hiding file '%s' because of HideNoAccess (errno = %s)", path,
                strerror(xerrno));
              errno = xerrno;
            }
          }
        }
      }
      break;

    case OP_COMMAND: {
      unsigned char *allow_all = get_param_ptr(set, "AllowAll", FALSE);
      unsigned char *deny_all = get_param_ptr(set, "DenyAll", FALSE);

      if (allow_all &&
          *allow_all == TRUE) {
        /* No-op */
        ;

      } else if (deny_all &&
                 *deny_all == TRUE) {
        pr_trace_msg("hiding", 8,
          "hiding file '%s' because of DenyAll limit for command (errno = %s)",
          path, strerror(EACCES));
        res = FALSE;
        errno = EACCES;
      }
    }

    break;
  }

  return res;
}

static int check_user_access(xaset_t *set, const char *name) {
  int res = 0;
  config_rec *c;

  /* If no user has been authenticated yet for this session, short-circuit the
   * check.
   */
  if (session.user == NULL) {
    return 0;
  }

  c = find_config(set, CONF_PARAM, name, FALSE);
  while (c) {
    pr_signals_handle();

#ifdef PR_USE_REGEX
    if (*((unsigned char *) c->argv[0]) == PR_EXPR_EVAL_REGEX) {
      pr_regex_t *pre = (pr_regex_t *) c->argv[1];

      if (pr_regexp_exec(pre, session.user, 0, NULL, 0, 0, 0) == 0) {
        res = TRUE;
        break;
      }

    } else
#endif /* regex support */

    if (*((unsigned char *) c->argv[0]) == PR_EXPR_EVAL_OR) {
      res = pr_expr_eval_user_or((char **) &c->argv[1]);
      if (res == TRUE) {
        break;
      }

    } else if (*((unsigned char *) c->argv[0]) == PR_EXPR_EVAL_AND) {
      res = pr_expr_eval_user_and((char **) &c->argv[1]);
      if (res == TRUE) {
        break;
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, name, FALSE);
  }

  return res;
}

static int check_group_access(xaset_t *set, const char *name) {
  int res = 0;
  config_rec *c;

  /* If no groups has been authenticated yet for this session, short-circuit the
   * check.
   */
  if (session.group == NULL) {
    return 0;
  }

  c = find_config(set, CONF_PARAM, name, FALSE);
  while (c) {
#ifdef PR_USE_REGEX
    if (*((unsigned char *) c->argv[0]) == PR_EXPR_EVAL_REGEX) {
      pr_regex_t *pre = (pr_regex_t *) c->argv[1];

      if (session.group &&
          pr_regexp_exec(pre, session.group, 0, NULL, 0, 0, 0) == 0) {
        res = TRUE;
        break;

      } else if (session.groups) {
        register int i = 0;

        for (i = session.groups->nelts-1; i >= 0; i--) {
          if (pr_regexp_exec(pre, *(((char **) session.groups->elts) + i), 0,
              NULL, 0, 0, 0) == 0) {
            res = TRUE;
            break;
          }
        }
      }

    } else
#endif /* regex support */

    if (*((unsigned char *) c->argv[0]) == PR_EXPR_EVAL_OR) {
      res = pr_expr_eval_group_or((char **) &c->argv[1]);
      if (res == TRUE) {
        break;
      }

    } else if (*((unsigned char *) c->argv[0]) == PR_EXPR_EVAL_AND) {
      res = pr_expr_eval_group_and((char **) &c->argv[1]);
      if (res == TRUE) {
        break;
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, name, FALSE);
  }

  return res;
}

static int check_class_access(xaset_t *set, const char *name) {
  int res = 0;
  config_rec *c;

  /* If no class was found for this session, short-circuit the check. */
  if (session.conn_class == NULL) {
    return res;
  }

  c = find_config(set, CONF_PARAM, name, FALSE);
  while (c) {
    pr_signals_handle();

#ifdef PR_USE_REGEX
    if (*((unsigned char *) c->argv[0]) == PR_EXPR_EVAL_REGEX) {
      pr_regex_t *pre = (pr_regex_t *) c->argv[1];

      if (session.conn_class &&
          pr_regexp_exec(pre, session.conn_class->cls_name, 0, NULL, 0,
            0, 0) == 0) {
        res = TRUE;
        break;
      }

    } else
#endif /* regex support */

    if (*((unsigned char *) c->argv[0]) == PR_EXPR_EVAL_OR) {
      res = pr_expr_eval_class_or((char **) &c->argv[1]);
      if (res == TRUE) {
        break;
      }

    } else if (*((unsigned char *) c->argv[0]) == PR_EXPR_EVAL_AND) {
      res = pr_expr_eval_class_and((char **) &c->argv[1]);
      if (res == TRUE) {
        break;
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, name, FALSE);
  }

  return res;
}

static int check_filter_access(xaset_t *set, const char *name, cmd_rec *cmd) {
#ifdef PR_USE_REGEX
  int res = 0;
  config_rec *c;

  if (cmd == NULL) {
    return 0;
  }

  c = find_config(set, CONF_PARAM, name, FALSE);
  while (c) {
    int matched = 0;
    pr_regex_t *pre = (pr_regex_t *) c->argv[0];

    pr_signals_handle();

    pr_trace_msg("filter", 8,
      "comparing %s argument '%s' against %s pattern '%s'",
      (char *) cmd->argv[0], cmd->arg, name, pr_regexp_get_pattern(pre));
    matched = pr_regexp_exec(pre, cmd->arg, 0, NULL, 0, 0, 0);
    pr_trace_msg("filter", 8,
      "comparing %s argument '%s' against %s pattern '%s' returned %d",
      (char *) cmd->argv[0], cmd->arg, name, pr_regexp_get_pattern(pre),
      matched);

    if (matched == 0) {
      res = TRUE;
      break;
    }

    c = find_config_next(c, c->next, CONF_PARAM, name, FALSE);
  }

  pr_trace_msg("filter", 8,
    "comparing %s argument '%s' against %s patterns returned %d",
    (char *) cmd->argv[0], cmd->arg, name, res);
  return res;
#else
  return 0;
#endif /* regex support */
}

/* As of 1.2.0rc3, a '!' character in front of the IP address
 * negates the logic (i.e. doesn't match).
 *
 * Here are our rules for matching an IP/host list:
 *
 *   (negate-cond-1 && negate-cond-2 && ... negate-cond-n) &&
 *   (cond-1 || cond-2 || ... cond-n)
 *
 * This boils down to the following two rules:
 *
 *   1. ALL negative ('!') conditions must evaluate to logically TRUE.
 *   2. One (or more) normal conditions must evaluate to logically TRUE.
 */

/* Check an ACL for negated rules and make sure all of them evaluate to TRUE.
 * Default (if none exist) is TRUE.
 */
static int check_ip_negative(const config_rec *c) {
  int aclc;
  pr_netacl_t **aclv;

  for (aclc = c->argc, aclv = (pr_netacl_t **) c->argv; aclc; aclc--, aclv++) {
    if (pr_netacl_get_negated(*aclv) == FALSE)
      continue;

    switch (pr_netacl_match(*aclv, session.c->remote_addr)) {
      case 1:
        /* This actually means we DIDN'T match, and it's ok to short circuit
         * everything (negative).
         */
        return FALSE;

      case -1:
        /* -1 signifies a NONE match, which isn't valid for negative
         * conditions.
         */
        pr_log_pri(PR_LOG_NOTICE,
          "ooops, it looks like !NONE was used in an ACL somehow");
        return FALSE;

      default:
        /* This means our match is actually true and we can continue */
        break;
    }
  }

  /* If we got this far either all conditions were TRUE or there were no
   * conditions.
   */

  return TRUE;
}

/* Check an ACL for positive conditions, short-circuiting if ANY of them are
 * TRUE.  Default return is FALSE.
 */
static int check_ip_positive(const config_rec *c) {
  int aclc;
  pr_netacl_t **aclv;

  for (aclc = c->argc, aclv = (pr_netacl_t **) c->argv; aclc; aclc--, aclv++) {
    if (pr_netacl_get_negated(*aclv) == TRUE)
      continue;

    switch (pr_netacl_match(*aclv, session.c->remote_addr)) {
      case 1:
        /* Found it! */
        return TRUE;

      case -1:
        /* Special value "NONE", meaning nothing can match, so we can
         * short-circuit on this as well.
         */
        return FALSE;

      default:
        /* No match, keep trying */
        break;
    }
  }

  /* default return value is FALSE */
  return FALSE;
}

static int check_ip_access(xaset_t *set, char *name) {
  int res = FALSE;

  config_rec *c = find_config(set, CONF_PARAM, name, FALSE);

  while (c) {
    pr_signals_handle();

    /* If the negative check failed (default is success), short-circuit and
     * return FALSE
     */
    if (check_ip_negative(c) != TRUE) {
      return FALSE;
    }

    /* Otherwise, continue on with boolean or check */
    if (check_ip_positive(c) == TRUE) {
      res = TRUE;
    }

    /* Continue on, in case there are other acls that need to be checked
     * (multiple acls are logically OR'd)
     */
    c = find_config_next(c, c->next, CONF_PARAM, name, FALSE);
  }

  return res;
}

/* 1 if allowed, 0 otherwise */

static int check_limit_allow(config_rec *c, cmd_rec *cmd) {
  unsigned char *allow_all = NULL;

  /* If session.groups is null, this means no authentication attempt has been
   * made, so we simply check for the very existence of an AllowGroup, and
   * assume (for now) it's allowed.  This works because later calls to
   * check_limit_allow() WILL have filled in the group members and we can
   * truly check group membership at that time.  Same goes for AllowUser.
   */

  if (!session.user) {
    if (find_config(c->subset, CONF_PARAM, "AllowUser", FALSE)) {
      return 1;
    }

  } else if (check_user_access(c->subset, "AllowUser")) {
    return 1;
  }

  if (!session.groups) {
    if (find_config(c->subset, CONF_PARAM, "AllowGroup", FALSE)) {
      return 1;
    }

  } else if (check_group_access(c->subset, "AllowGroup")) {
    return 1;
  }

  if (session.conn_class != NULL &&
      check_class_access(c->subset, "AllowClass")) {
    return 1;
  }

  if (check_ip_access(c->subset, "Allow")) {
    return 1;
  }

  if (check_filter_access(c->subset, "AllowFilter", cmd)) {
    return 1;
  }

  allow_all = get_param_ptr(c->subset, "AllowAll", FALSE);
  if (allow_all &&
      *allow_all == TRUE) {
    return 1;
  }

  return 0;
}

static int check_limit_deny(config_rec *c, cmd_rec *cmd) {
  unsigned char *deny_all = get_param_ptr(c->subset, "DenyAll", FALSE);

  if (deny_all &&
      *deny_all == TRUE) {
    return 1;
  }

  if (session.user &&
      check_user_access(c->subset, "DenyUser")) {
    return 1;
  }

  if (session.groups &&
      check_group_access(c->subset, "DenyGroup")) {
    return 1;
  }

  if (session.conn_class != NULL &&
      check_class_access(c->subset, "DenyClass")) {
    return 1;
  }

  if (check_ip_access(c->subset, "Deny")) {
    return 1;
  }

  if (check_filter_access(c->subset, "DenyFilter", cmd)) {
    return 1;
  }

  return 0;
}

/* check_limit returns 1 if allowed, 0 if implicitly allowed,
 * and -1 if implicitly denied and -2 if explicitly denied.
 */

static int check_limit(config_rec *c, cmd_rec *cmd) {
  int *tmp = get_param_ptr(c->subset, "Order", FALSE);
  int order = tmp ? *tmp : ORDER_ALLOWDENY;

  if (order == ORDER_DENYALLOW) {
    /* Check deny first */

    if (check_limit_deny(c, cmd)) {
      /* Explicit deny */
      errno = EPERM;
      return -2;
    }

    if (check_limit_allow(c, cmd)) {
      /* Explicit allow */
      return 1;
    }

    /* Implicit deny */
    errno = EPERM;
    return -1;
  }

  /* Check allow first */
  if (check_limit_allow(c, cmd)) {
    /* Explicit allow */
    return 1;
  }

  if (check_limit_deny(c, cmd)) {
    /* Explicit deny */
    errno = EPERM;
    return -2;
  }

  /* Implicit allow */
  return 0;
}

/* Note: if and == 1, the logic is short circuited so that the first
 * failure results in a FALSE return from the entire function, if and
 * == 0, an ORing operation is assumed and the function will return
 * TRUE if any <limit LOGIN> allows access.
 */

int login_check_limits(xaset_t *set, int recurse, int and, int *found) {
  int res = and;
  int rfound = 0;
  config_rec *c;
  int argc;
  char **argv;

  *found = 0;

  if (!set || !set->xas_list)
    return TRUE;			/* default is to allow */

  /* First check top level */
  for (c = (config_rec *) set->xas_list; c; c = c->next) {
    if (c->config_type == CONF_LIMIT) {
      for (argc = c->argc, argv = (char **) c->argv; argc; argc--, argv++) {
        if (strncasecmp(*argv, "LOGIN", 6) == 0) {
          break;
        }
      }

      if (argc) {
        if (and) {
          switch (check_limit(c, NULL)) {
            case 1:
              res = (res && TRUE);
              (*found)++;
              break;

	    case -1:
            case -2:
              res = (res && FALSE);
              (*found)++;
              break;
          }

          if (!res)
            break;

        } else {
          switch (check_limit(c, NULL)) {
            case 1:
              res = TRUE;
              (*found)++;
              break;

	    case -1:
            case -2:
              (*found)++;
              break;
          }
        }
      }
    }
  }

  if (((res && and) || (!res && !and && *found)) && recurse) {
    for (c = (config_rec *) set->xas_list; c; c = c->next) {
      if (c->config_type == CONF_ANON &&
          c->subset &&
          c->subset->xas_list) {
       if (and) {
         res = (res && login_check_limits(c->subset, recurse, and, &rfound));
         (*found) += rfound;
         if (!res)
           break;

       } else {
         int rres;

         rres = login_check_limits(c->subset, recurse, and, &rfound);
         if (rfound) {
           res = (res || rres);
         }

         (*found) += rfound;
         if (res)
           break;
       }
     }
    }
  }

  if (!*found && !and)
    return TRUE;			/* Default is to allow */

  return res;
}

/* Check limit directives.
 */
static int check_limits(xaset_t *set, cmd_rec *cmd, const char *cmd_name,
    int hidden) {
  int res = 1, ignore_hidden = -1;
  config_rec *lc = NULL;

  errno = 0;

  if (!set)
    return res;

  for (lc = (config_rec *) set->xas_list; lc && (res == 1); lc = lc->next) {
    pr_signals_handle();

    if (lc->config_type == CONF_LIMIT) {
      register unsigned int i = 0;

      for (i = 0; i < lc->argc; i++) {
        if (strcasecmp(cmd_name, (char *) lc->argv[i]) == 0) {
          break;
        }
      }
	
      if (i == lc->argc)
        continue;

      /* Found a <Limit> directive associated with the current command.
       * ignore_hidden defaults to -1, if an explicit IgnoreHidden off is seen,
       * it is set to 0 and the check will not be done again up the chain.  If
       * an explicit "IgnoreHidden on" is seen, checking short-circuits and we
       * set ENOENT.
       */

      if (hidden && ignore_hidden == -1) {
        unsigned char *ignore = get_param_ptr(lc->subset, "IgnoreHidden",
          FALSE);

        if (ignore)
          ignore_hidden = *ignore;

        if (ignore_hidden == 1) {
          res = 0;
          errno = ENOENT;
          break;
        }
      }

      switch (check_limit(lc, cmd)) {
        case 1:
          res++;
          break;
	
        case -1:
        case -2:
          res = 0;
          break;
	
        default:
          continue;
      }
    }
  }

  if (!res && !errno)
    errno = EACCES;

  return res;
}

int dir_check_limits(cmd_rec *cmd, config_rec *c, const char *cmd_name,
    int hidden) {
  int res = 1;

  for (; c && (res == 1); c = c->parent) {
    res = check_limits(c->subset, cmd, cmd_name, hidden);
  }

  if (!c && (res == 1)) {
    /* vhost or main server has been reached without an explicit permit or deny,
     * so try the current server.
     */
    res = check_limits(main_server->conf, cmd, cmd_name, hidden);
  }

  return res;
}

/* Manage .ftpaccess dynamic directory sections
 *
 * build_dyn_config() is called to check for and then handle .ftpaccess 
 * files.  It determines:
 *
 *   - whether an .ftpaccess file exists in a directory
 *   - whether an existing .ftpaccess section for that file exists
 *   - whether a new .ftpaccess section needs to be constructed
 *   - whether an existing .ftpaccess section needs rebuilding 
 *         as its corresponding .ftpaccess file has been modified   
 *   - whether an existing .ftpaccess section must now be removed
 *         as its corresponding .ftpaccess file has disappeared
 *
 * The routine must check for .ftpaccess files in each directory that is
 * a component of the path argument.  The input path may be for either a 
 * directory or file, and that may or may not already exist.  
 *
 * build_dyn_config() may be called with a path to:
 *
 *   - an existing directory        - start check in that dir
 *   - an existing file             - start check in containing dir
 *   - a proposed directory         - start check in containing dir
 *   - a proposed file              - start check in containing dir
 *
 * As in 1.3.3b code, the key is that for path "/a/b/c", one of either 
 * "/a/b/c" or "/a/b" is an existing directory, or we MUST give up as we
 * cannot even start scanning for .ftpaccess files without a valid starting
 * directory.
 */
void build_dyn_config(pool *p, const char *_path, struct stat *stp,
    unsigned char recurse) {
  struct stat st;
  config_rec *d = NULL;
  xaset_t **set = NULL;
  int isfile, removed = 0;
  char *ptr = NULL;

  /* Need three path strings: 
   *
   *  curr_dir_path: current relative directory path, for tracking our
   *                 progress as we scan upwards 
   *
   *  ftpaccess_path: current relative file path to the .ftpaccess file for
   *                  which to check.
   *
   *  ftpaccess_name: absolute directory path of the .ftpaccess file,
   *                  to be used as the name for the new config_rec.
   */
  char *curr_dir_path = NULL, *ftpaccess_path = NULL, *ftpaccess_name = NULL;

  /* Switch through each directory, from "deepest" up looking for
   * new or updated .ftpaccess files
   */

  if (!_path)
    return;

  /* Check to see whether .ftpaccess files are allowed to be parsed. */
  if (!allow_dyn_config(_path))
    return;

  /* Determine the starting directory path for the .ftpaccess file scan. */
  memcpy(&st, stp, sizeof(st));
  curr_dir_path = pstrdup(p, _path);

  if (!S_ISDIR(st.st_mode)) {

    /* If the given st is not for a directory (i.e. path is for a file),
     * then construct the path for the .ftpaccess file to check.
     *
     * strrchr(3) should always return non-NULL here, right?
     */
    ptr = strrchr(curr_dir_path, '/');
    if (ptr != NULL) {
      *ptr = '\0';
    }
  }

  while (curr_dir_path) {
    size_t curr_dir_pathlen;

    pr_signals_handle();

    curr_dir_pathlen = strlen(curr_dir_path);

    /* Remove any trailing "*" character. */
    if (curr_dir_pathlen > 1 &&
        *(curr_dir_path + curr_dir_pathlen - 1) == '*') {
      *(curr_dir_path + curr_dir_pathlen - 1) = '\0';
      curr_dir_pathlen--;
    }

    /* Trim any trailing path separator (unless it is the first AND last
     * character, e.g. "/").  For example:
     *
     *  "/a/b/" -->  "/a/b"
     *  "/a/"   -->  "/a"
     *  "/"     -->  "/"
     *
     * The check for a string length greater than 1 character skips the
     * "/" case effectively.
     */ 

    if (curr_dir_pathlen > 1 &&
      *(curr_dir_path + curr_dir_pathlen - 1) == '/') {
      *(curr_dir_path + curr_dir_pathlen - 1) = '\0';
      curr_dir_pathlen--;  
    }

    ftpaccess_path = pdircat(p, curr_dir_path, ".ftpaccess", NULL);

    /* Construct the name for the config_rec name for the .ftpaccess file
     * from curr_dir_path.
     */

    if (session.chroot_path) {
      size_t ftpaccess_namelen;

      ftpaccess_name = pdircat(p, session.chroot_path, curr_dir_path,
        NULL);

      ftpaccess_namelen = strlen(ftpaccess_name);

      if (ftpaccess_namelen > 1 &&
          *(ftpaccess_name + ftpaccess_namelen - 1) == '/') {
        *(ftpaccess_name + ftpaccess_namelen - 1) = '\0';
        ftpaccess_namelen--;
      }

    } else {
      ftpaccess_name = curr_dir_path;
    }

    if (ftpaccess_path != NULL) {
      pr_trace_msg("ftpaccess", 6, "checking for .ftpaccess file '%s'",
        ftpaccess_path);
      isfile = pr_fsio_stat(ftpaccess_path, &st);

    } else {
      isfile = -1;
    }

    d = dir_match_path(p, ftpaccess_name);

    if (!d &&
        isfile != -1 &&
        st.st_size > 0) {
      set = (session.anon_config ? &session.anon_config->subset :
        &main_server->conf);

      pr_trace_msg("ftpaccess", 6, "adding config for '%s'", ftpaccess_name);

      d = pr_config_add_set(set, ftpaccess_name, 0);
      d->config_type = CONF_DIR;
      d->argc = 1;
      d->argv = pcalloc(d->pool, 2 * sizeof (void *));

    } else if (d) {
      config_rec *newd, *dnext;

      if (isfile != -1 &&
          st.st_size > 0 &&
          strcmp(d->name, ftpaccess_name) != 0) {
        set = &d->subset;

        pr_trace_msg("ftpaccess", 6, "adding config for '%s'", ftpaccess_name);

        newd = pr_config_add_set(set, ftpaccess_name, 0);
        newd->config_type = CONF_DIR;
        newd->argc = 1;
        newd->argv = pcalloc(newd->pool, 2 * sizeof(void *));
	newd->parent = d;

        d = newd;

      } else if (strcmp(d->name, ftpaccess_name) == 0 &&
          (isfile == -1 ||
           st.st_mtime > (d->argv[0] ? *((time_t *) d->argv[0]) : 0))) {

        set = (d->parent ? &d->parent->subset : &main_server->conf);

	if (d->subset &&
            d->subset->xas_list) {

       	  /* Remove all old dynamic entries. */
          for (newd = (config_rec *) d->subset->xas_list; newd; newd = dnext) {
	    dnext = newd->next;

            if (newd->flags & CF_DYNAMIC) {
              xaset_remove(d->subset, (xasetmember_t *) newd);
              removed++;
            }
          }
	}

        if (d->subset &&
            !d->subset->xas_list) {
          destroy_pool(d->subset->pool);
          d->subset = NULL;
          d->argv[0] = NULL;

	  /* If the file has been removed and no entries exist in this
           * dynamic entry, remove it completely.
           */
          if (isfile == -1) {
            xaset_remove(*set, (xasetmember_t *) d);
          }
        }
      }
    }

    if (isfile != -1 &&
        d &&
        st.st_size > 0 &&
        st.st_mtime > (d->argv[0] ? *((time_t *) d->argv[0]) : 0)) {
      int res;

      /* File has been modified or not loaded yet */
      d->argv[0] = pcalloc(d->pool, sizeof(time_t));
      *((time_t *) d->argv[0]) = st.st_mtime;

      d->config_type = CONF_DYNDIR;

      pr_trace_msg("ftpaccess", 3, "parsing '%s'", ftpaccess_path);

      pr_parser_prepare(p, NULL);
      res = pr_parser_parse_file(p, ftpaccess_path, d,
        PR_PARSER_FL_DYNAMIC_CONFIG);
      pr_parser_cleanup();

      if (res == 0) {
        d->config_type = CONF_DIR;
        pr_config_merge_down(*set, TRUE);

        pr_trace_msg("ftpaccess", 3, "fixing up directory configs");
        fixup_dirs(main_server, CF_SILENT);

      } else {
        int xerrno = errno;

        pr_trace_msg("ftpaccess", 2, "error parsing '%s': %s", ftpaccess_path,
          strerror(xerrno));
        pr_log_debug(DEBUG0, "error parsing '%s': %s", ftpaccess_path,
          strerror(xerrno));
      }
    }

    if (isfile == -1 &&
        removed &&
        d &&
        set) {
      pr_trace_msg("ftpaccess", 6, "adding config for '%s'", ftpaccess_name);
      pr_config_merge_down(*set, FALSE);
    }

    if (!recurse)
      break;

    /* Remove the last path component of current directory path. */
    ptr = strrchr(curr_dir_path, '/');
    if (ptr != NULL) {
      /* We need to handle the case where path might be "/path".  We
       * can't just set *ptr to '\0', as that would result in the empty
       * string.  Thus check if ptr is the same value as curr_dir_path, i.e.
       * that ptr points to the start of the string.  If so, by definition
       * we know that we are dealing with the "/path" case.
       */
      if (ptr == curr_dir_path) {
        if (strncmp(curr_dir_path, "/", 2) == 0) {
          /* We've reached the top; stop scanning. */
          curr_dir_path = NULL;

        } else {
          *(ptr+1) = '\0';
        }

      } else {
        *ptr = '\0';
      }

    } else {
      curr_dir_path = NULL;
    }
  }

  return;
}

/* dir_check_full() fully recurses the path passed
 * returns 1 if operation is allowed on current path,
 * or 0 if not.
 */

/* dir_check_full() and dir_check() both take a `hidden' argument which is a
 * pointer to an integer. This is provided so that they can tell the calling
 * function if an entry should be hidden or not.  This is used by mod_ls to
 * determine if a file should be displayed.  Note that in this context, hidden
 * means "hidden by configuration" (HideUser, etc), NOT "hidden because it's a
 * .dotfile".
 */

int dir_check_full(pool *pp, cmd_rec *cmd, const char *group, const char *path,
    int *hidden) {
  char *fullpath, *owner;
  config_rec *c;
  struct stat st;
  pool *p;
  mode_t _umask = (mode_t) -1;
  int res = 1, isfile;
  int op_hidden = FALSE, regex_hidden = FALSE;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  p = make_sub_pool(pp);
  pr_pool_tag(p, "dir_check_full() subpool");

  fullpath = (char *) path;

  if (session.chroot_path) {
    fullpath = pdircat(p, session.chroot_path, fullpath, NULL);
  }

  if (*path) {
    /* Only log this debug line if we are dealing with a real path. */
    pr_log_debug(DEBUG5, "in dir_check_full(): path = '%s', fullpath = '%s'",
      path, fullpath);
  }

  /* Check and build all appropriate dynamic configuration entries */
  isfile = pr_fsio_stat(path, &st);
  if (isfile < 0) {
    memset(&st, '\0', sizeof(st));
  }

  build_dyn_config(p, path, &st, TRUE);

  /* Check to see if this path is hidden by HideFiles. */
  regex_hidden = dir_hide_file(path);

  /* Cache a pointer to the set of configuration data for this directory in
   * session.dir_config.
   */
  session.dir_config = c = dir_match_path(p, fullpath);
  if (session.dir_config) {
    pr_trace_msg("directory", 2, "matched <Directory %s> for '%s'",
      session.dir_config->name, fullpath);
  }

  if (!c && session.anon_config) {
    c = session.anon_config;
  }

  /* Make sure this cmd_rec has a cmd_id. */
  if (cmd->cmd_id == 0) {
    cmd->cmd_id = pr_cmd_get_id(cmd->argv[0]);
  }

  if (!_kludge_disable_umask) {
    /* Check for a directory Umask. */
    if (S_ISDIR(st.st_mode) ||
        pr_cmd_cmp(cmd, PR_CMD_MKD_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_XMKD_ID) == 0) {
      mode_t *dir_umask = NULL;

      dir_umask = get_param_ptr(CURRENT_CONF, "DirUmask", FALSE);
      if (dir_umask) {
        pr_trace_msg("directory", 2, "found DirUmask %04o for directory '%s'",
          *dir_umask, path);
      }

      _umask = dir_umask ? *dir_umask : (mode_t) -1;
    }

    /* It's either a file, or we had no directory Umask. */
    if (_umask == (mode_t) -1) {
      mode_t *file_umask = get_param_ptr(CURRENT_CONF, "Umask", FALSE);
      _umask = file_umask ? *file_umask : (mode_t) 0022;
    }
  }

  session.fsuid = (uid_t) -1;
  session.fsgid = (gid_t) -1;

  owner = get_param_ptr(CURRENT_CONF, "UserOwner", FALSE);
  if (owner != NULL) {
    /* Attempt chown() on all new files. */
    struct passwd *pw;

    pw = pr_auth_getpwnam(p, owner);
    if (pw != NULL) {
      session.fsuid = pw->pw_uid;
    }
  }

  owner = get_param_ptr(CURRENT_CONF, "GroupOwner", FALSE);
  if (owner != NULL) {
    /* Attempt chgrp() on all new files. */

    if (strncmp(owner, "~", 2) != 0) {
      struct group *gr;

      gr = pr_auth_getgrnam(p, owner);
      if (gr != NULL) {
        session.fsgid = gr->gr_gid;
      }

    } else {
      session.fsgid = session.gid;
    }
  }

  if (isfile != -1) {
    /* Check to see if the current config "hides" the path or not. */
    op_hidden = !dir_check_op(p, CURRENT_CONF, OP_HIDE,
      session.chroot_path ? path : fullpath, st.st_uid, st.st_gid, st.st_mode);

    res = dir_check_op(p, CURRENT_CONF, OP_COMMAND,
      session.chroot_path ? path : fullpath, st.st_uid, st.st_gid, st.st_mode);
  }

  if (res) {
    /* Note that dir_check_limits() also handles IgnoreHidden.  If it is set,
     * these return 0 (no access), and also set errno to ENOENT so it looks
     * like the file doesn't exist.
     */
    res = dir_check_limits(cmd, c, cmd->argv[0], op_hidden || regex_hidden);

    /* If specifically allowed, res will be > 1 and we don't want to
     * check the command group limit.
     */
    if (res == 1 && group) {
      res = dir_check_limits(cmd, c, group, op_hidden || regex_hidden);
    }

    /* If still == 1, no explicit allow so check lowest priority "ALL" group.
     * Note that certain commands are deliberately excluded from the
     * ALL group (i.e. EPRT, EPSV, PASV, PORT, and OPTS).
     */
    if (res == 1 &&
        pr_cmd_cmp(cmd, PR_CMD_EPRT_ID) != 0 &&
        pr_cmd_cmp(cmd, PR_CMD_EPSV_ID) != 0 &&
        pr_cmd_cmp(cmd, PR_CMD_PASV_ID) != 0 &&
        pr_cmd_cmp(cmd, PR_CMD_PORT_ID) != 0 &&
        pr_cmd_cmp(cmd, PR_CMD_PROT_ID) != 0 &&
        strncmp(cmd->argv[0], C_OPTS, 4) != 0) {
      res = dir_check_limits(cmd, c, "ALL", op_hidden || regex_hidden);
    }
  }

  if (res &&
      _umask != (mode_t) -1) {
    pr_log_debug(DEBUG5,
      "in dir_check_full(): setting umask to %04o (was %04o)",
        (unsigned int) _umask, (unsigned int) umask(_umask));
  }

  destroy_pool(p);

  if (hidden) {
    *hidden = op_hidden || regex_hidden;
  }

  return res;
}

/* dir_check() checks the current dir configuration against the path,
 * if it matches (partially), a search is done only in the subconfig,
 * otherwise handed off to dir_check_full
 */

int dir_check(pool *pp, cmd_rec *cmd, const char *group, const char *path,
    int *hidden) {
  char *fullpath, *owner;
  config_rec *c;
  struct stat st;
  pool *p;
  mode_t _umask = (mode_t) -1;
  int res = 1, isfile;
  int op_hidden = FALSE, regex_hidden = FALSE;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  p = make_sub_pool(pp);
  pr_pool_tag(p, "dir_check() subpool");

  fullpath = (char *) path;

  if (session.chroot_path) {
    fullpath = pdircat(p, session.chroot_path, fullpath, NULL);
  }

  c = (session.dir_config ? session.dir_config :
        (session.anon_config ? session.anon_config : NULL));

  if (!c || strncmp(c->name, fullpath, strlen(c->name)) != 0) {
    destroy_pool(p);
    return dir_check_full(pp, cmd, group, path, hidden);
  }

  /* Check and build all appropriate dynamic configuration entries */
  isfile = pr_fsio_stat(path, &st);
  if (isfile < 0) {
    memset(&st, 0, sizeof(st));
  }

  build_dyn_config(p, path, &st, FALSE);

  /* Check to see if this path is hidden by HideFiles. */
  regex_hidden = dir_hide_file(path);

  /* Cache a pointer to the set of configuration data for this directory in
   * session.dir_config.
   */
  session.dir_config = c = dir_match_path(p, fullpath);
  if (session.dir_config) {
    pr_trace_msg("directory", 2, "matched <Directory %s> for '%s'",
      session.dir_config->name, fullpath);
  }

  if (!c && session.anon_config) {
    c = session.anon_config;
  }

  /* Make sure this cmd_rec has a cmd_id. */
  if (cmd->cmd_id == 0) {
    cmd->cmd_id = pr_cmd_get_id(cmd->argv[0]);
  }

  if (!_kludge_disable_umask) {
    /* Check for a directory Umask. */
    if (S_ISDIR(st.st_mode) ||
        pr_cmd_cmp(cmd, PR_CMD_MKD_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_XMKD_ID) == 0) {
      mode_t *dir_umask = NULL;

      dir_umask = get_param_ptr(CURRENT_CONF, "DirUmask", FALSE);
      if (dir_umask) {
        pr_trace_msg("directory", 2, "found DirUmask %04o for directory '%s'",
          *dir_umask, path);
      }

      _umask = dir_umask ? *dir_umask : (mode_t) -1;
    }

    /* It's either a file, or we had no directory Umask. */
    if (_umask == (mode_t) -1) {
      mode_t *file_umask = get_param_ptr(CURRENT_CONF, "Umask", FALSE);
      _umask = file_umask ? *file_umask : (mode_t) 0022;
    }
  }

  session.fsuid = (uid_t) -1;
  session.fsgid = (gid_t) -1;

  owner = get_param_ptr(CURRENT_CONF, "UserOwner", FALSE);
  if (owner != NULL) {
    /* Attempt chown() on all new files. */
    struct passwd *pw;

    pw = pr_auth_getpwnam(p, owner);
    if (pw != NULL) {
      session.fsuid = pw->pw_uid;
    }
  }

  owner = get_param_ptr(CURRENT_CONF, "GroupOwner", FALSE);
  if (owner != NULL) {
    /* Attempt chgrp() on all new files. */

    if (strncmp(owner, "~", 2) != 0) {
      struct group *gr;

      gr = pr_auth_getgrnam(p, owner);
      if (gr != NULL) {
        session.fsgid = gr->gr_gid;
      }

    } else {
      session.fsgid = session.gid;
    }
  }

  if (isfile != -1) {
    /* If not already marked as hidden by its name, check to see if the path
     * is to be hidden by nature of its mode
     */
    op_hidden = !dir_check_op(p, CURRENT_CONF, OP_HIDE,
      session.chroot_path ? path : fullpath, st.st_uid, st.st_gid, st.st_mode);

    res = dir_check_op(p, CURRENT_CONF, OP_COMMAND,
      session.chroot_path ? path : fullpath, st.st_uid, st.st_gid, st.st_mode);
  }

  if (res) {
    res = dir_check_limits(cmd, c, cmd->argv[0], op_hidden || regex_hidden);

    /* If specifically allowed, res will be > 1 and we don't want to
     * check the command group limit.
     */
    if (res == 1 && group) {
      res = dir_check_limits(cmd, c, group, op_hidden || regex_hidden);
    }

    /* If still == 1, no explicit allow so check lowest priority "ALL" group.
     * Note that certain commands are deliberately excluded from the
     * ALL group (i.e. EPRT, EPSV, PASV, PORT, and OPTS).
     */
    if (res == 1 &&
        pr_cmd_cmp(cmd, PR_CMD_EPRT_ID) != 0 &&
        pr_cmd_cmp(cmd, PR_CMD_EPSV_ID) != 0 &&
        pr_cmd_cmp(cmd, PR_CMD_PASV_ID) != 0 &&
        pr_cmd_cmp(cmd, PR_CMD_PORT_ID) != 0 &&
        pr_cmd_cmp(cmd, PR_CMD_PROT_ID) != 0 &&
        strncmp(cmd->argv[0], C_OPTS, 4) != 0) {
      res = dir_check_limits(cmd, c, "ALL", op_hidden || regex_hidden);
    }
  }

  if (res &&
      _umask != (mode_t) -1) {
    pr_log_debug(DEBUG5, "in dir_check(): setting umask to %04o (was %04o)",
        (unsigned int) _umask, (unsigned int) umask(_umask));
  }

  destroy_pool(p);

  if (hidden) {
    *hidden = op_hidden || regex_hidden;
  }

  return res;
}

/* dir_check_canon() canonocalizes as much of the path as possible (which may
 * not be all of it, as the target may not yet exist) then we hand off to
 * dir_check().
 */
int dir_check_canon(pool *pp, cmd_rec *cmd, const char *group,
    const char *path, int *hidden) {
  return dir_check(pp, cmd, group, dir_best_path(pp, path), hidden);
}

/* Move all the members (i.e. a "branch") of one config set to a different
 * parent.
 */
static void reparent_all(config_rec *newparent, xaset_t *set) {
  config_rec *c, *cnext;

  if (!newparent->subset)
    newparent->subset = xaset_create(newparent->pool, NULL);

  for (c = (config_rec *) set->xas_list; c; c = cnext) {
    cnext = c->next;
    xaset_remove(set, (xasetmember_t *) c);
    xaset_insert(newparent->subset, (xasetmember_t *) c);
    c->set = newparent->subset;
    c->parent = newparent;
  }
}

/* Recursively find the most appropriate place to move a CONF_DIR
 * directive to.
 */
static config_rec *find_best_dir(xaset_t *set, char *path, size_t *matchlen) {
  config_rec *c, *res = NULL, *rres;
  size_t len, pathlen, imatchlen, tmatchlen;

  *matchlen = 0;

  if (set == NULL ||
      set->xas_list == NULL) {
    errno = EINVAL;
    return NULL;
  }

  pathlen = strlen(path);

  for (c = (config_rec *) set->xas_list; c; c = c->next) {
    if (c->config_type == CONF_DIR) {
      /* Note: this comparison of pointers, rather than of strings, is
       * intentional.  DO NOT CHANGE THIS TO A strcmp()!
       *
       * This function is only called by reorder_dirs(), and reorder_dirs()
       * always uses a c->name as the path parameter.  This means that
       * doing direct pointer/address comparisons is valid.  If ever this
       * assumption is broken, we will need to revert back to a more
       * costly (especially when there are many <Directory> config sections)
       * use of strcmp(3).
       */
      if (c->name == path) {
        continue;
      }

      len = strlen(c->name);

      /* Do NOT change the zero here to a one; the expression IS correct. */
      while (len > 0 &&
             (*(c->name+len-1) == '*' || *(c->name+len-1) == '/')) {
        len--;
      }

      /* Just a partial match on the pathname does not mean that the longer
       * path is the subdirectory of the other -- they might just be sharing
       * the last path component!
       * /var/www/.1
       * /var/www/.14
       *            ^ -- not /, not subdir
       * /var/www/.1
       * /var/www/.1/images
       *            ^ -- /, is subdir
       *
       * And then there are glob considerations, e.g.:
       *
       *   /var/www/<glob>/dir2
       *   /var/www/dir1/dir2
       *
       * In these cases, we need to make sure that the glob path appears
       * BEFORE the exact path.  Right?
       */
      if (pathlen > len &&
          path[len] != '/') {
        continue;
      }

      if (len < pathlen &&
          strncmp(c->name, path, len) == 0) {
        rres = find_best_dir(c->subset ,path, &imatchlen);
        tmatchlen = _strmatch(path, c->name);
        if (!rres &&
            tmatchlen > *matchlen) {
          res = c;
          *matchlen = tmatchlen;

        } else if (imatchlen > *matchlen) {
          res = rres;
          *matchlen = imatchlen;
        }
      }
    }
  }

  return res;
}

/* Reorder all the CONF_DIR configuration sections, so that they are
 * in directory tree order
 */

static void reorder_dirs(xaset_t *set, int flags) {
  config_rec *c = NULL, *cnext = NULL, *newparent = NULL;
  int defer = 0;
  size_t tmp;

  if (set == NULL ||
      set->xas_list == NULL) {
    return;
  }

  /* Ignore the CF_SILENT flag for purposes of reordering. */
  flags &= ~CF_SILENT;

  if (!(flags & CF_DEFER)) {
    defer = 1;
  }

  for (c = (config_rec *) set->xas_list; c; c = cnext) {
    cnext = c->next;

    pr_signals_handle();

    if (c->config_type == CONF_DIR) {
      if (flags && !(c->flags & flags))
        continue;

      if (defer && (c->flags & CF_DEFER))
        continue;

      /* If <Directory *> is used inside <Anonymous>, move all
       * the directives from '*' into the higher level.
       */
      if (c->parent &&
          c->parent->config_type == CONF_ANON &&
          strncmp(c->name, "*", 2) == 0) {

        if (c->subset)
          reparent_all(c->parent, c->subset);

        xaset_remove(c->parent->subset, (xasetmember_t *) c);

      } else {
        newparent = find_best_dir(set, c->name, &tmp);
        if (newparent) {
          if (!newparent->subset)
            newparent->subset = xaset_create(newparent->pool, NULL);

          xaset_remove(c->set, (xasetmember_t *) c);
          xaset_insert(newparent->subset, (xasetmember_t *) c);
          c->set = newparent->subset;
          c->parent = newparent;
        }
      }
    }
  }

  /* Top level is now sorted, now we recursively sort all the sublevels. */
  for (c = (config_rec *) set->xas_list; c; c = c->next) {
    if (c->config_type == CONF_DIR || c->config_type == CONF_ANON) {
      reorder_dirs(c->subset, flags);
    }
  }
}

#ifdef PR_USE_DEVEL
void pr_dirs_dump(void (*dumpf)(const char *, ...), xaset_t *s, char *indent) {
  config_rec *c;

  if (s == NULL) {
    return;
  }

  if (indent == NULL) {
    indent = " ";
  }

  for (c = (config_rec *) s->xas_list; c; c = c->next) {
    pr_signals_handle();

    if (c->config_type != CONF_DIR) {
      continue;
    }

    dumpf("%s<Directory %s>", indent, c->name);

    if (c->subset) {
      pr_dirs_dump(dumpf, c->subset, pstrcat(c->pool, indent, " ", NULL));
    }
  }

  return;
}
#endif /* PR_USE_DEVEL */

/* Iterate through <Directory> blocks inside of anonymous and
 * resolve each one.
 */
void resolve_anonymous_dirs(xaset_t *clist) {
  config_rec *c;
  char *realdir;

  if (!clist) {
    return;
  }

  for (c = (config_rec *) clist->xas_list; c; c = c->next) {
    if (c->config_type == CONF_DIR) {
      if (c->argv[1]) {
        realdir = dir_best_path(c->pool, c->argv[1]);
        if (realdir) {
          c->argv[1] = realdir;

        } else {
          realdir = dir_canonical_path(c->pool, c->argv[1]);
          if (realdir) {
            c->argv[1] = realdir;
          }
        }
      }

      if (c->subset) {
        resolve_anonymous_dirs(c->subset);
      }
    }
  }
}

/* Iterate through directory configuration items and resolve ~ references. */
void resolve_deferred_dirs(server_rec *s) {
  config_rec *c;

  if (s == NULL ||
      s->conf == NULL) {
    return;
  }

  for (c = (config_rec *) s->conf->xas_list; c; c = c->next) {
    if (c->config_type == CONF_DIR &&
        (c->flags & CF_DEFER)) {
      char *interp_dir = NULL, *real_dir = NULL, *orig_name = NULL;
      const char *trace_channel = "directory";

      if (pr_trace_get_level(trace_channel) >= 11) {
        orig_name = pstrdup(c->pool, c->name);
      }

      /* Check for any expandable variables. */
      c->name = (char *) path_subst_uservar(c->pool, (const char **) &c->name);

      /* Handle any '~' interpolation. */
      interp_dir = dir_interpolate(c->pool, c->name);
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

      /* Clear the CF_DEFER flag. */
      c->flags &= ~CF_DEFER;
    }
  }
}

static void copy_recur(xaset_t **set, pool *p, config_rec *c,
    config_rec *new_parent) {
  config_rec *newconf;
  int argc;
  void **argv, **sargv;

  if (!*set) {
    *set = xaset_create(p, NULL);
  }

  newconf = pr_config_add_set(set, c->name, 0);
  newconf->config_type = c->config_type;
  newconf->flags = c->flags;
  newconf->parent = new_parent;
  newconf->argc = c->argc;

  if (c->argc) {
    newconf->argv = pcalloc(newconf->pool, (c->argc+1) * sizeof(void *));
    argv = newconf->argv;
    sargv = c->argv;
    argc = newconf->argc;

    while (argc--) {
      *argv++ = *sargv++;
    }

    if (argv) {
      *argv++ = NULL;
    }
  }

  if (c->subset) {
    for (c = (config_rec *) c->subset->xas_list; c; c = c->next) {
      pr_signals_handle();
      copy_recur(&newconf->subset, p, c, newconf);
    }
  }
}

static void copy_global_to_all(xaset_t *set) {
  server_rec *s;
  config_rec *c;

  if (!set || !set->xas_list) {
    return;
  }

  for (c = (config_rec *) set->xas_list; c; c = c->next) {
    for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
      pr_signals_handle();
      copy_recur(&s->conf, s->pool, c, NULL);
    }
  }
}

static void fixup_globals(xaset_t *list) {
  server_rec *s = NULL, *smain = NULL;
  config_rec *c = NULL, *cnext = NULL;

  smain = (server_rec *) list->xas_list;
  for (s = smain; s; s = s->next) {
    /* Loop through each top level directive looking for a CONF_GLOBAL
     * context.
     */
    if (!s->conf ||
        !s->conf->xas_list) {
      continue;
    }

    for (c = (config_rec *) s->conf->xas_list; c; c = cnext) {
      cnext = c->next;

      if (c->config_type == CONF_GLOBAL &&
          strncmp(c->name, "<Global>", 9) == 0) {
        /* Copy the contents of the block to all other servers
         * (including this one), then pull the block "out of play".
         */
        if (c->subset &&
            c->subset->xas_list) {
          copy_global_to_all(c->subset);
        }

        xaset_remove(s->conf, (xasetmember_t *) c);

        if (!s->conf->xas_list) {
          destroy_pool(s->conf->pool);
          s->conf = NULL;
        }
      }
    }
  }
}

void fixup_dirs(server_rec *s, int flags) {
  if (s == NULL) {
    return;
  }

  if (s->conf == NULL) {
    if (!(flags & CF_SILENT)) {
      pr_log_debug(DEBUG5, "%s", "");
      pr_log_debug(DEBUG5, "Config for %s:", s->ServerName);
    }

    return;
  }
 
  reorder_dirs(s->conf, flags);

  /* Merge mergeable configuration items down. */
  pr_config_merge_down(s->conf, FALSE);

  if (!(flags & CF_SILENT)) {
    pr_log_debug(DEBUG5, "%s", "");
    pr_log_debug(DEBUG5, "Config for %s:", s->ServerName);
    pr_config_dump(NULL, s->conf, NULL);
  }

  return;
}

/* Go through each server configuration and complain if important information
 * is missing (post reading configuration files).  Otherwise, fill in defaults
 * where applicable.
 */
int fixup_servers(xaset_t *list) {
  config_rec *c = NULL;
  server_rec *s = NULL, *next_s = NULL;

  fixup_globals(list);

  s = (server_rec *) list->xas_list;
  if (s && !s->ServerName)
    s->ServerName = pstrdup(s->pool, "ProFTPD");

  for (; s; s = next_s) {
    unsigned char *default_server = NULL;

    next_s = s->next;
    if (s->ServerAddress == NULL) {
      array_header *addrs = NULL;

      s->ServerAddress = pr_netaddr_get_localaddr_str(s->pool);
      s->addr = pr_netaddr_get_addr(s->pool, s->ServerAddress, &addrs);
     
      if (addrs) {
        register unsigned int i;
        pr_netaddr_t **elts = addrs->elts;

        /* For every additional address, implicitly add a bind record. */
        for (i = 0; i < addrs->nelts; i++) {
          const char *ipstr = pr_netaddr_get_ipstr(elts[i]);

#ifdef PR_USE_IPV6
          if (pr_netaddr_use_ipv6()) {
            char *ipbuf = pcalloc(s->pool, INET6_ADDRSTRLEN + 1);
            if (pr_netaddr_get_family(elts[i]) == AF_INET) {

              /* Create the bind record using the IPv4-mapped IPv6 version of
               * this address.
               */
              pr_snprintf(ipbuf, INET6_ADDRSTRLEN, "::ffff:%s", ipstr);
              ipstr = pstrdup(s->pool, ipbuf);
            }
          }
#endif /* PR_USE_IPV6 */

          if (ipstr) {
            pr_conf_add_server_config_param_str(s, "_bind_", 1, ipstr);
          }
        }
      }
 
    } else {
      s->addr = pr_netaddr_get_addr(s->pool, s->ServerAddress, NULL);
    }

    if (s->addr == NULL) {
      pr_log_pri(PR_LOG_WARNING,
        "warning: unable to determine IP address of '%s'", s->ServerAddress);

      if (s == main_server) {
        main_server = NULL;
      }

      xaset_remove(list, (xasetmember_t *) s);
      destroy_pool(s->pool);
      s->pool = NULL;
      continue;
    }

    s->ServerFQDN = pr_netaddr_get_dnsstr(s->addr);

    if (s->ServerFQDN == NULL) {
      s->ServerFQDN = s->ServerAddress;
    }

    if (s->ServerAdmin == NULL) {
      s->ServerAdmin = pstrcat(s->pool, "root@", s->ServerFQDN, NULL);
    }

    if (s->ServerName == NULL) {
      server_rec *m = (server_rec *) list->xas_list;
      s->ServerName = pstrdup(s->pool, m->ServerName);
    }

    if (s->tcp_rcvbuf_len == 0) {
      s->tcp_rcvbuf_len = tcp_rcvbufsz;
    }

    if (s->tcp_sndbuf_len == 0) {
      s->tcp_sndbuf_len = tcp_sndbufsz;
    }

    c = find_config(s->conf, CONF_PARAM, "MasqueradeAddress", FALSE);
    if (c != NULL) {
      const char *masq_addr;

      if (c->argv[0] != NULL) {
        masq_addr = pr_netaddr_get_ipstr(c->argv[0]);

      } else {
        masq_addr = c->argv[1];
      }

      pr_log_pri(PR_LOG_INFO, "%s:%d masquerading as %s",
        pr_netaddr_get_ipstr(s->addr), s->ServerPort, masq_addr);
    }

    /* Honor the DefaultServer directive only if SocketBindTight is not
     * in effect.
     */
    default_server = get_param_ptr(s->conf, "DefaultServer", FALSE);

    if (default_server &&
        *default_server == TRUE) {

      if (SocketBindTight == FALSE) {
        pr_netaddr_set_sockaddr_any((pr_netaddr_t *) s->addr);

      } else {
        pr_log_pri(PR_LOG_NOTICE,
          "SocketBindTight in effect, ignoring DefaultServer");
      }
    }

    fixup_dirs(s, 0);
  }

  /* Make sure there actually are server_recs remaining in the list
   * before continuing.  Badly configured/resolved vhosts are rejected, and
   * it's possible to have all vhosts (even the default) rejected.
   */
  if (list->xas_list == NULL) {
    pr_log_pri(PR_LOG_WARNING, "error: no valid servers configured");
    return -1;
  }

  pr_inet_clear();
  return 0;
}

static void set_tcp_bufsz(server_rec *s) {
  int proto = -1, sockfd;
  socklen_t optlen = 0;
  struct protoent *p = NULL;

#ifdef HAVE_SETPROTOENT
  setprotoent(FALSE);
#endif

  p = getprotobyname("tcp");
  if (p != NULL) {
    proto = p->p_proto;
  }

#ifdef HAVE_ENDPROTOENT
  endprotoent();
#endif

  if (p == NULL) {
#ifndef PR_TUNABLE_RCVBUFSZ
    s->tcp_rcvbuf_len = tcp_rcvbufsz = PR_TUNABLE_DEFAULT_RCVBUFSZ;
#else
    s->tcp_rcvbuf_len = tcp_rcvbufsz = PR_TUNABLE_RCVBUFSZ;
#endif /* PR_TUNABLE_RCVBUFSZ */

#ifndef PR_TUNABLE_SNDBUFSZ
    s->tcp_sndbuf_len = tcp_sndbufsz = PR_TUNABLE_DEFAULT_SNDBUFSZ;
#else
    s->tcp_sndbuf_len = tcp_sndbufsz = PR_TUNABLE_SNDBUFSZ;
#endif /* PR_TUNABLE_SNDBUFSZ */

    pr_log_debug(DEBUG3, "getprotobyname error for 'tcp': %s", strerror(errno));
    pr_log_debug(DEBUG4, "using default TCP receive/send buffer sizes");

#ifndef PR_TUNABLE_XFER_BUFFER_SIZE
    /* Choose the smaller of the two TCP buffer sizes as the overall transfer
     * size (for use by the data transfer layer).
     */
     xfer_bufsz = tcp_sndbufsz < tcp_rcvbufsz ? tcp_sndbufsz : tcp_rcvbufsz;
#else
    xfer_bufsz = PR_TUNABLE_XFER_BUFFER_SIZE;
#endif /* PR_TUNABLE_XFER_BUFFER_SIZE */

    return;
  }

  sockfd = socket(AF_INET, SOCK_STREAM, proto);
  if (sockfd < 0) {
    s->tcp_rcvbuf_len = tcp_rcvbufsz = PR_TUNABLE_DEFAULT_RCVBUFSZ;
    s->tcp_sndbuf_len = tcp_sndbufsz = PR_TUNABLE_DEFAULT_SNDBUFSZ;

    pr_log_debug(DEBUG3, "socket error: %s", strerror(errno));
    pr_log_debug(DEBUG4, "using default TCP receive/send buffer sizes");

    return;
  }

#ifndef PR_TUNABLE_RCVBUFSZ
  /* Determine the optimal size of the TCP receive buffer. */
  optlen = sizeof(tcp_rcvbufsz);
  if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (void *) &tcp_rcvbufsz,
      &optlen) < 0) {
    s->tcp_rcvbuf_len = tcp_rcvbufsz = PR_TUNABLE_DEFAULT_RCVBUFSZ;

    pr_log_debug(DEBUG3, "getsockopt error for SO_RCVBUF: %s", strerror(errno));
    pr_log_debug(DEBUG4, "using default TCP receive buffer size of %d bytes",
      tcp_rcvbufsz);

  } else {
    pr_log_debug(DEBUG5, "using TCP receive buffer size of %d bytes",
      tcp_rcvbufsz);
    s->tcp_rcvbuf_len = tcp_rcvbufsz;
  }
#else
  optlen = -1;
  s->tcp_rcvbuf_len = tcp_rcvbufsz = PR_TUNABLE_RCVBUFSZ;
  pr_log_debug(DEBUG5, "using preset TCP receive buffer size of %d bytes",
    tcp_rcvbufsz);
#endif /* PR_TUNABLE_RCVBUFSZ */

#ifndef PR_TUNABLE_SNDBUFSZ
  /* Determine the optimal size of the TCP send buffer. */
  optlen = sizeof(tcp_sndbufsz);
  if (getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (void *) &tcp_sndbufsz,
      &optlen) < 0) {
    s->tcp_sndbuf_len = tcp_sndbufsz = PR_TUNABLE_DEFAULT_SNDBUFSZ;
    
    pr_log_debug(DEBUG3, "getsockopt error for SO_SNDBUF: %s", strerror(errno));
    pr_log_debug(DEBUG4, "using default TCP send buffer size of %d bytes",
      tcp_sndbufsz);
  
  } else {
    pr_log_debug(DEBUG5, "using TCP send buffer size of %d bytes",
      tcp_sndbufsz);
    s->tcp_sndbuf_len = tcp_sndbufsz;
  }
#else
  optlen = -1;
  s->tcp_sndbuf_len = tcp_sndbufsz = PR_TUNABLE_SNDBUFSZ;
  pr_log_debug(DEBUG5, "using preset TCP send buffer size of %d bytes",
    tcp_sndbufsz);
#endif /* PR_TUNABLE_SNDBUFSZ */

  /* Choose the smaller of the two TCP buffer sizes as the overall transfer
   * size (for use by the data transfer layer).
   */
   xfer_bufsz = tcp_sndbufsz < tcp_rcvbufsz ? tcp_sndbufsz : tcp_rcvbufsz;

  (void) close(sockfd);
}

void init_dirtree(void) {
  pool *dirtree_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(dirtree_pool, "Dirtree Pool");

  if (server_list) {
    server_rec *s, *s_next;

    /* Free the old configuration completely */
    for (s = (server_rec *) server_list->xas_list; s; s = s_next) {
      s_next = s->next;

      /* Make sure that any pointers are explicitly nulled; this does not
       * automatically happen as part of pool destruction.
       */
      s->conf = NULL;
      s->set = NULL;

      destroy_pool(s->pool);
    }

    destroy_pool(server_list->pool);
    server_list = NULL;
  }

  /* Note: xaset_create() assigns the given pool to the 'pool' member
   * of the created list, i.e. server_list->pool == conf_pool.  Hence
   * why we create yet another subpool, reusing the conf_pool pointer.
   * The pool creation below is not redundant.
   */
  server_list = xaset_create(dirtree_pool, NULL);

  dirtree_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(dirtree_pool, "main_server pool");

  main_server = (server_rec *) pcalloc(dirtree_pool, sizeof(server_rec));
  xaset_insert(server_list, (xasetmember_t *) main_server);

  main_server->pool = dirtree_pool;
  main_server->set = server_list;
  main_server->sid = 1;
  main_server->notes = pr_table_nalloc(dirtree_pool, 0, 8);

  /* TCP KeepAlive is enabled by default, with the system defaults. */
  main_server->tcp_keepalive = palloc(main_server->pool,
    sizeof(struct tcp_keepalive));
  main_server->tcp_keepalive->keepalive_enabled = TRUE;
  main_server->tcp_keepalive->keepalive_idle = -1;
  main_server->tcp_keepalive->keepalive_count = -1;
  main_server->tcp_keepalive->keepalive_intvl = -1;

  /* Default server port */
  main_server->ServerPort = pr_inet_getservport(main_server->pool,
    "ftp", "tcp");

  set_tcp_bufsz(main_server);
  return;
}

/* These functions are used by modules to help parse configuration. */

unsigned char check_context(cmd_rec *cmd, int allowed) {
  int ctxt = (cmd->config && cmd->config->config_type != CONF_PARAM ?
     cmd->config->config_type : cmd->server->config_type ?
     cmd->server->config_type : CONF_ROOT);

  if (ctxt & allowed)
    return TRUE;

  /* default */
  return FALSE;
}

char *get_context_name(cmd_rec *cmd) {
  static char cbuf[20];

  if (!cmd->config || cmd->config->config_type == CONF_PARAM) {
    if (cmd->server->config_type == CONF_VIRTUAL) {
      return "<VirtualHost>";
    }

    return "server config";
  }

  switch (cmd->config->config_type) {
    case CONF_DIR:
      return "<Directory>";

    case CONF_ANON:
      return "<Anonymous>";

    case CONF_CLASS:
      return "<Class>";

    case CONF_LIMIT:
      return "<Limit>";

    case CONF_DYNDIR:
      return ".ftpaccess";

    case CONF_GLOBAL:
      return "<Global>";

    case CONF_USERDATA:
      return "user data";

    default:
      /* XXX should dispatch to modules here, to allow them to create and
       * handle their own arbitrary configuration contexts.
       */
      memset(cbuf, '\0', sizeof(cbuf));
      pr_snprintf(cbuf, sizeof(cbuf), "%d", cmd->config->config_type);
      return cbuf;
  }
}

int get_boolean(cmd_rec *cmd, int av) {
  char *cp = cmd->argv[av];

  return pr_str_is_boolean(cp);
}

const char *get_full_cmd(cmd_rec *cmd) {
  return pr_cmd_get_displayable_str(cmd, NULL);
}

int pr_config_get_xfer_bufsz(void) {
  return xfer_bufsz;
}

int pr_config_get_xfer_bufsz2(int direction) {
  switch (direction) {
    case PR_NETIO_IO_RD:
      return tcp_rcvbufsz;

    case PR_NETIO_IO_WR:
      return tcp_sndbufsz;
  }

  return xfer_bufsz;
}

int pr_config_get_server_xfer_bufsz(int direction) {
  if (main_server != NULL) {
    switch (direction) {
      case PR_NETIO_IO_RD:
        return main_server->tcp_rcvbuf_len;

      case PR_NETIO_IO_WR:
        return main_server->tcp_sndbuf_len;
    }
  }

  return pr_config_get_xfer_bufsz2(direction);
}
