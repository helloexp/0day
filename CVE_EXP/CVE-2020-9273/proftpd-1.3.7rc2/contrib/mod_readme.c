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

/* Notify the user when a given file was last changed
 *
 * Configuration:
 *   DisplayReadme <file-or-pattern>
 *
 * "DisplayReadme Readme" will tell the user when "Readme" on the current 
 * working directory was last changed.  When the current working directory is
 * changed (i.e. CWD, CDUP, etc), mod_readme will search for Readme again
 * in that directory and also display its last changing dates if found.
 */

#include "conf.h"

#define MOD_README_VERSION		"mod_readme/1.0"

static void readme_add_path(pool *p, const char *path) {
  struct stat st;
  
  if (pr_fsio_stat(path, &st) == 0) {
    int days = 0;
    time_t now;
    struct tm *now_tm = NULL;
    char time_str[32] = {'\0'};

    (void) time(&now);

    now_tm = pr_gmtime(p, &now);
    if (now_tm != NULL) {
      struct tm *mtime_tm = NULL;
      char *ptr = NULL;

      days = (int) (365.25 * now_tm->tm_year) + now_tm->tm_yday;

      mtime_tm = pr_gmtime(p, &st.st_mtime);
      if (mtime_tm != NULL) {
        days -= (int) (365.25 * mtime_tm->tm_year) + mtime_tm->tm_yday;

      } else {
        pr_log_debug(DEBUG3, MOD_README_VERSION
          ": error obtaining GMT timestamp: %s", strerror(errno));
      }

      memset(time_str, '\0', sizeof(time_str));
      pr_snprintf(time_str, sizeof(time_str)-1, "%.26s", ctime(&st.st_mtime));
    
      ptr = strchr(time_str, '\n');
      if (ptr != NULL) {
        *ptr = '\0';
      }

    } else {
      pr_log_debug(DEBUG3, MOD_README_VERSION
        ": error obtaining GMT timestamp: %s", strerror(errno));
    }

    /* As a format nicety, if we're handling the PASS command, automatically
     * add a blank line before this message, so as to separate the
     * login message that mod_auth's POST_CMD handler for PASS will add from
     * our message (see Bug#3605).
     */
    if (strcmp(session.curr_cmd, C_PASS) == 0) {
      pr_response_add(R_DUP, "%s", "");
    }

    pr_response_add(R_DUP, _("Please read the file %s"), path);
    if (now_tm != NULL) {
      pr_response_add(R_DUP, _("   it was last modified on %.26s - %i %s ago"),
        time_str, days, days == 1 ? _("day") : _("days"));
    }
  }
}

static void readme_add_pattern(pool *p, const char *pattern) {
  glob_t g;
  int a;
  char **path;
  
  a = pr_fs_glob(pattern, 0, NULL, &g);
  if (!a) {
    path = g.gl_pathv;
    while (path && *path) {
      pr_signals_handle();
      readme_add_path(p, *path);
      path++;
    }

  } else if (a == GLOB_NOSPACE) {
    pr_log_debug(DEBUG3, MOD_README_VERSION
      ": out of memory during globbing of '%s'", pattern);

  } else if (a == GLOB_ABORTED) {
    pr_log_debug(DEBUG3, MOD_README_VERSION
      ": read error during globbing of '%s'", pattern);

  } else if (a != GLOB_NOMATCH) {
    pr_log_debug(DEBUG3, MOD_README_VERSION
      ": unknown error during globbing of '%s'", pattern);
  }
 
  pr_fs_globfree(&g);
}

/* Command handlers
 */

MODRET readme_post_cmd(cmd_rec *cmd) {
  config_rec *c;
  
  c = find_config(CURRENT_CONF, CONF_PARAM, "DisplayReadme", FALSE);
  while (c) {
    char *path;

    path = c->argv[0];
    
    pr_log_debug(DEBUG5, "Checking for display pattern %s", path);
    readme_add_pattern(cmd->tmp_pool, path);
    
    c = find_config_next(c, c->next, CONF_PARAM, "DisplayReadme",FALSE);
  }

  return PR_DECLINED(cmd);
}

/* Configuration handlers
 */

/* usage: DisplayReadme path|pattern */
MODRET set_displayreadme(cmd_rec *cmd) {
  config_rec *c;
  
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);
  
  if (cmd->argc != 2) {
    CONF_ERROR(cmd, "syntax: DisplayReadme <filename-or-pattern>");
  }
  
  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;
  
  pr_log_debug(DEBUG5, "Added pattern %s to readme list",
    (char *) cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Module API tables
 */

static conftable readme_conftab[] = {
  { "DisplayReadme", set_displayreadme, NULL },
  { NULL }
};

static cmdtable readme_cmdtab[] = {
  { POST_CMD,	C_CWD,	G_NONE,	readme_post_cmd, FALSE,	FALSE },
  { POST_CMD,	C_CDUP,	G_NONE,	readme_post_cmd, FALSE,	FALSE },
  { POST_CMD,	C_XCWD,	G_NONE,	readme_post_cmd, FALSE,	FALSE },
  { POST_CMD,	C_XCUP,	G_NONE,	readme_post_cmd, FALSE,	FALSE },

  /* We specifically use a LOG_CMD handler here, so that any DisplayReadme
   * output is append after any possible DisplayLogin data (see Bug#3605).
   */
  { LOG_CMD,	C_PASS,	G_NONE, readme_post_cmd, FALSE,	FALSE },

  { 0, NULL }
};

module readme_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "readme",

  /* Module configuration directive table */
  readme_conftab,

  /* Module command handler table */
  readme_cmdtab,

  /* Module auth handler table */
  NULL,

  /* Module initialization */
  NULL,

  /* Session initialization */
  NULL,

  /* Module version */
  MOD_README_VERSION
};

