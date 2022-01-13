/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
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

/* "SITE" commands module for ProFTPD. */

#include "conf.h"

/* From mod_core.c */
extern int core_chmod(cmd_rec *cmd, const char *path, mode_t mode);
extern int core_chgrp(cmd_rec *cmd, const char *path, uid_t uid, gid_t gid);

modret_t *site_dispatch(cmd_rec *cmd);

static struct {
  char *cmd;
  char *syntax;
  int implemented;
} _help[] = {
  { "HELP",	"[<sp> site-command]",			TRUE },
  { "CHGRP",	"<sp> group <sp> pathname",		TRUE },
  { "CHMOD",	"<sp> mode <sp> pathname",		TRUE },
  { NULL,	NULL,					FALSE }
};

static char *full_cmd(cmd_rec *cmd) {
  register unsigned int i;
  char *res = "";
  size_t reslen = 0;

  for (i = 0; i < cmd->argc; i++) {
    res = pstrcat(cmd->tmp_pool, res, cmd->argv[i], " ", NULL);
  }

  reslen = strlen(res);
  while (reslen >= 1 &&
         res[reslen-1] == ' ') {
    res[reslen-1] = '\0';
    reslen--;
  }

  return res;
}

MODRET site_chgrp(cmd_rec *cmd) {
  int res;
  gid_t gid;
  char *path = NULL, *tmp = NULL, *arg = "";
  register unsigned int i = 0;
#ifdef PR_USE_REGEX
  pr_regex_t *pre;
#endif

  if (cmd->argc < 3) {
    pr_response_add_err(R_500, _("'SITE %s' not understood"), full_cmd(cmd));
    return NULL;
  }

  /* Construct the target file name by concatenating all the parameters after
   * the mode, separating them with spaces.
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
        _("SITE %s: Illegal character sequence in command"),
        (char *) cmd->argv[1]);

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    arg = pstrcat(cmd->tmp_pool, arg, *arg ? " " : "", decoded_path, NULL);
  }

#ifdef PR_USE_REGEX
  pre = get_param_ptr(CURRENT_CONF, "PathAllowFilter", FALSE);
  if (pre != NULL &&
      pr_regexp_exec(pre, arg, 0, NULL, 0, 0, 0) != 0) {
    pr_log_debug(DEBUG2, "'%s %s' denied by PathAllowFilter",
      (char *) cmd->argv[0], arg);
    pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  pre = get_param_ptr(CURRENT_CONF, "PathDenyFilter", FALSE);
  if (pre != NULL &&
      pr_regexp_exec(pre, arg, 0, NULL, 0, 0, 0) == 0) {
    pr_log_debug(DEBUG2, "'%s %s' denied by PathDenyFilter",
      (char *) cmd->argv[0], arg);
    pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }
#endif

  pr_fs_clear_cache2(arg);
  path = dir_realpath(cmd->tmp_pool, arg);
  if (path == NULL) {
    int xerrno = errno;

    pr_response_add_err(R_550, "%s: %s", arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* Map the given group argument, if a string, to a GID.  If already a
   * number, pass through as is.
   */
  gid = strtoul(cmd->argv[1], &tmp, 10);

  if (tmp && *tmp) {

    /* Try the parameter as a group name. */
    gid = pr_auth_name2gid(cmd->tmp_pool, cmd->argv[1]);
    if (gid == (gid_t) -1) {
      int xerrno = EINVAL;

      pr_log_debug(DEBUG9,
        "SITE CHGRP: Unable to resolve group name '%s' to GID",
        (char *) cmd->argv[1]);
      pr_response_add_err(R_550, "%s: %s", arg, strerror(xerrno));

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }
  }

  res = core_chgrp(cmd, path, (uid_t) -1, gid);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
      "error chown'ing '%s' to GID %s: %s", (char *) cmd->argv[0], session.user,
      pr_uid2str(cmd->tmp_pool, session.uid),
      pr_gid2str(cmd->tmp_pool, session.gid), path,
      pr_gid2str(cmd->tmp_pool, gid), strerror(xerrno));

    pr_response_add_err(R_550, "%s: %s", arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  pr_response_add(R_200, _("SITE %s command successful"),
    (char *) cmd->argv[0]);
  return PR_HANDLED(cmd);
}

MODRET site_chmod(cmd_rec *cmd) {
  int res;
  mode_t mode = 0;
  char *dir, *endp, *mode_str, *tmp, *arg = "";
  struct stat st;
  register unsigned int i = 0;
#ifdef PR_USE_REGEX
  pr_regex_t *pre;
#endif

  if (cmd->argc < 3) {
    pr_response_add_err(R_500, _("'SITE %s' not understood"), full_cmd(cmd));
    return NULL;
  }

  /* Construct the target file name by concatenating all the parameters after
   * the mode, separating them with spaces.
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
        _("SITE %s: Illegal character sequence in command"),
        (char *) cmd->argv[1]);

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    arg = pstrcat(cmd->tmp_pool, arg, *arg ? " " : "", decoded_path, NULL);
  }

#ifdef PR_USE_REGEX
  pre = get_param_ptr(CURRENT_CONF, "PathAllowFilter", FALSE);
  if (pre != NULL &&
      pr_regexp_exec(pre, arg, 0, NULL, 0, 0, 0) != 0) {
    pr_log_debug(DEBUG2, "'%s %s %s' denied by PathAllowFilter",
      (char *) cmd->argv[0], (char *) cmd->argv[1], arg);
    pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  pre = get_param_ptr(CURRENT_CONF, "PathDenyFilter", FALSE);
  if (pre != NULL &&
      pr_regexp_exec(pre, arg, 0, NULL, 0, 0, 0) == 0) {
    pr_log_debug(DEBUG2, "'%s %s %s' denied by PathDenyFilter",
      (char *) cmd->argv[0], (char *) cmd->argv[1], arg);
    pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }
#endif

  pr_fs_clear_cache2(arg);
  dir = dir_realpath(cmd->tmp_pool, arg);
  if (dir == NULL) {
    int xerrno = errno;

    pr_response_add_err(R_550, "%s: %s", arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* If the first character isn't '0', prepend it and attempt conversion.
   * This will fail if the chmod is a symbolic, but takes care of the
   * case where an octal number is sent without the leading '0'.
   */
  mode_str = cmd->argv[1];
  if (mode_str[0] != '0') {
    tmp = pstrcat(cmd->tmp_pool, "0", mode_str, NULL);

  } else {
    tmp = mode_str;
  }

  mode = strtol(tmp, &endp, 0);
  if (endp && *endp) {
    /* It's not an absolute number, try symbolic */
    char *cp = mode_str;
    int mask = 0, mode_op = 0, curr_mode = 0, curr_umask = umask(0);
    int invalid = 0;
    char *who, *how, *what;

    umask(curr_umask);
    mode = 0;

    if (pr_fsio_stat(dir, &st) != -1) {
      curr_mode = st.st_mode;
    }

    while (TRUE) {
      pr_signals_handle();

      who = pstrdup(cmd->tmp_pool, cp);

      tmp = strpbrk(who, "+-=");
      if (tmp != NULL) {
        how = pstrdup(cmd->tmp_pool, tmp);
        if (*how != '=') {
          mode = curr_mode;
        }

        *tmp = '\0';

      } else {
        invalid++;
        break;
      }

      tmp = strpbrk(how, "rwxXstugo");
      if (tmp != NULL) {
        what = pstrdup(cmd->tmp_pool, tmp);
        *tmp = '\0';

      } else {
        invalid++;
        break;
      }

      cp = what;
      while (cp) {
        switch (*who) {
          case 'u':
            mask = 0077;
            break;

          case 'g':
            mask = 0707;
            break;

          case 'o':
            mask = 0770;
            break;

          case 'a':
            mask = 0000;
            break;

          case '\0':
            mask = curr_umask;
            break;

          default:
            invalid++;
            break;
        }

        if (invalid)
          break;

        switch (*how) {
          case '+':
          case '-':
          case '=':
            break;

          default:
            invalid++;
        }

        if (invalid)
          break;

        switch (*cp) {
          case 'r':
            mode_op |= (S_IRUSR|S_IRGRP|S_IROTH);
            break;

          case 'w':
            mode_op |= (S_IWUSR|S_IWGRP|S_IWOTH);
            break;

          case 'x':
            mode_op |= (S_IXUSR|S_IXGRP|S_IXOTH);
            break;

          /* 'X' not implemented */
          case 's':
            /* setuid */
            mode_op |= S_ISUID;
            break;

          case 't':
            /* sticky */
            mode_op |= S_ISVTX;
            break;

          case 'o':
            mode_op |= (curr_mode & S_IRWXO);
            mode_op |= ((curr_mode & S_IRWXO) << 3);
            mode_op |= ((curr_mode & S_IRWXO) << 6);
            break;

          case 'g':
            mode_op |= ((curr_mode & S_IRWXG) >> 3);
            mode_op |= (curr_mode & S_IRWXG);
            mode_op |= ((curr_mode & S_IRWXG) << 3);
            break;

          case 'u':
            mode_op |= ((curr_mode & S_IRWXU) >> 6);
            mode_op |= ((curr_mode & S_IRWXU) >> 3);
            mode_op |= (curr_mode & S_IRWXU);
            break;

          case '\0':
            /* Apply the mode and move on */
            switch (*how) {
              case '+':
              case '=':
                mode |= (mode_op & ~mask);
                break;

              case '-':
                mode &= ~(mode_op & ~mask);
                break;
            }

            mode_op = 0;
            if (*who && *(who+1)) {
              who++;
              cp = what;
              continue;

            } else {
              cp = NULL;
            }
            break;

          default:
            invalid++;
        }

        if (invalid) {
          break;
        }

        if (cp) {
          cp++;
        }
      }
      break;
    }

    if (invalid) {
      pr_response_add_err(R_550, _("'%s': invalid mode"), (char *) cmd->argv[1]);

      pr_cmd_set_errno(cmd, EINVAL);
      errno = EINVAL;
      return PR_ERROR(cmd);
    }
  }

  res = core_chmod(cmd, dir, mode);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
      "error chmod'ing '%s' to %04o: %s", (char *) cmd->argv[0], session.user,
      pr_uid2str(cmd->tmp_pool, session.uid),
      pr_gid2str(cmd->tmp_pool, session.gid), dir, (unsigned int) mode,
      strerror(xerrno));

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  pr_response_add(R_200, _("SITE %s command successful"),
    (char *) cmd->argv[0]);
  return PR_HANDLED(cmd);
}

MODRET site_help(cmd_rec *cmd) {
  register unsigned int i = 0;

  /* Have to support 'HELP SITE' as well as 'SITE HELP'.  Most clients expect
   * the former (it's mentioned in RFC959), whereas the latter is more
   * syntactically correct.
   */

  if (cmd->argc == 1 || (cmd->argc == 2 &&
      ((strcasecmp(cmd->argv[0], "SITE") == 0 &&
        strcasecmp(cmd->argv[1], "HELP") == 0) ||
       (strcasecmp(cmd->argv[0], "HELP") == 0 &&
        strcasecmp(cmd->argv[1], "SITE") == 0)))) {

    for (i = 0; _help[i].cmd; i++) {
      if (_help[i].implemented) {
        pr_response_add(i != 0 ? R_DUP : R_214, "%s", _help[i].cmd);

      } else {
        pr_response_add(i != 0 ? R_DUP : R_214, "%s",
          pstrcat(cmd->pool, _help[i].cmd, "*", NULL));
      }
    }

  } else {
    char *arg, *cp = NULL;

    arg = cmd->argv[1];
    for (cp = arg; *cp; cp++) {
      *cp = toupper(*cp);
    }

    for (i = 0; _help[i].cmd; i++) {
      if (strcasecmp(arg, _help[i].cmd) == 0) {
        pr_response_add(R_214, _("Syntax: SITE %s %s"),
          (char *) cmd->argv[1], _help[i].syntax);
        return PR_HANDLED(cmd);
      }
    }

    pr_response_add_err(R_502, _("Unknown command 'SITE %s'"), cmd->arg);
    pr_cmd_set_errno(cmd, ENOSYS);
    errno = ENOSYS;
    return PR_ERROR(cmd);
  }

  return PR_HANDLED(cmd);
}

/* The site_commands table is local only, and not registered with our
 * module.
 */

static cmdtable site_commands[] = {
  { CMD, "HELP",	G_NONE,		site_help,	FALSE,	FALSE },
  { CMD, "CHGRP",	G_NONE,		site_chgrp,	TRUE,	FALSE },
  { CMD, "CHMOD",	G_NONE,		site_chmod,	TRUE,	FALSE },
  { 0, NULL }
};

modret_t *site_dispatch(cmd_rec *cmd) {
  register unsigned int i = 0;

  if (!cmd->argc) {
    pr_response_add_err(R_500, _("'SITE' requires parameters"));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  for (i = 0; site_commands[i].command; i++) {
    if (strcmp(cmd->argv[0], site_commands[i].command) == 0) {
      if (site_commands[i].requires_auth && cmd_auth_chk &&
          !cmd_auth_chk(cmd)) {
        pr_response_send(R_530, _("Please login with USER and PASS"));

        pr_cmd_set_errno(cmd, EPERM);
        errno = EPERM;
        return PR_ERROR(cmd);
      }

      return site_commands[i].handler(cmd);
    }
  }

  pr_response_add_err(R_500, _("'SITE %s' not understood"),
    (char *) cmd->argv[0]);

  pr_cmd_set_errno(cmd, EINVAL);
  errno = EINVAL;
  return PR_ERROR(cmd);
}

/* Command handlers
 */

MODRET site_pre_cmd(cmd_rec *cmd) {
  if (cmd->argc > 1 && !strcasecmp(cmd->argv[1], "help"))
    pr_response_add(R_214,
      _("The following SITE commands are recognized (* =>'s unimplemented)"));
  return PR_DECLINED(cmd);
}

MODRET site_cmd(cmd_rec *cmd) {
  char *cp = NULL;
  cmd_rec *tmpcmd = NULL;

  /* Make a copy of the cmd structure for passing to pr_module_call(). */
  tmpcmd = pcalloc(cmd->pool, sizeof(cmd_rec));
  memcpy(tmpcmd, cmd, sizeof(cmd_rec));

  tmpcmd->argc--;
  tmpcmd->argv++;

  if (tmpcmd->argc) {
    for (cp = tmpcmd->argv[0]; *cp; cp++) {
      *cp = toupper((int) *cp);
    }
  }

  tmpcmd->notes = cmd->notes;

  return site_dispatch(tmpcmd);
}

MODRET site_post_cmd(cmd_rec *cmd) {
  if (cmd->argc > 1 &&
      strcasecmp(cmd->argv[1], "help") == 0)
    pr_response_add(R_214, _("Direct comments to %s"),
      (cmd->server->ServerAdmin ? cmd->server->ServerAdmin : "ftp-admin"));

  return PR_DECLINED(cmd);
}

/* Initialization routines
 */

static int site_init(void) {

  /* Add the commands handled by this module to the HELP list. */ 
  pr_help_add(C_SITE, _("<sp> string"), TRUE);

  return 0;
}

/* Module API tables
 */

static cmdtable site_cmdtab[] = {
  { PRE_CMD,  C_SITE, G_NONE, site_pre_cmd,   FALSE,  FALSE },
  { CMD,      C_SITE, G_NONE, site_cmd,       FALSE,  FALSE,  CL_MISC },
  { POST_CMD, C_SITE, G_NONE, site_post_cmd,  FALSE,  FALSE },
  { 0, NULL }
};

module site_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "site",

  /* Module configuration table */
  NULL,

  /* Module command handler table */
  site_cmdtab,

  /* Module auth handler table */
  NULL,

  /* Module initialization function */
  site_init,

  /* Session initialization function */
  NULL
};
