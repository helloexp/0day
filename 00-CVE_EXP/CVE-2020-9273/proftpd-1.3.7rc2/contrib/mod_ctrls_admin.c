/*
 * ProFTPD: mod_ctrls_admin -- a module implementing admin control handlers
 * Copyright (c) 2000-2017 TJ Saunders
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
 * This is mod_controls, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"
#include "mod_ctrls.h"

#define MOD_CTRLS_ADMIN_VERSION		"mod_ctrls_admin/0.9.9"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030602
# error "ProFTPD 1.3.6rc2 or later required"
#endif

#ifndef PR_USE_CTRLS
# error "Controls support required (use --enable-ctrls)"
#endif

/* Values for the stop flags */
#define CTRL_STOP_DEFAULT     (1 << 0)
#define CTRL_STOP_CLEAN       (1 << 1)
#define CTRL_STOP_FULL        (1 << 2)
#define CTRL_STOP_GRACEFUL    (1 << 3)

/* For the 'shutdown' control action */
#define CTRLS_DEFAULT_SHUTDOWN_WAIT	5

/* From src/dirtree.c */
extern xaset_t *server_list;
extern int ServerUseReverseDNS;

module ctrls_admin_module;
static ctrls_acttab_t ctrls_admin_acttab[];

/* Pool for this module's use */
static pool *ctrls_admin_pool = NULL;

static unsigned int ctrls_admin_nrestarts = 0;
static time_t ctrls_admin_start = 0;

/* Support routines
 */

#if 0
/* Will be used when scheduled shutdowns are supported.. */
static unsigned char isnumeric(char *str) {
  while (str && PR_ISSPACE(*str)) {
    str++;
  }

  if (!str || !*str)
    return FALSE;

  for (; str && *str; str++) {
    if (!PR_ISDIGIT(*str)) {
      return TRUE;
    }
  }

  return 1;
}
#endif

static int respcmp(const void *a, const void *b) {
  return strcmp(*((char **) a), *((char **) b));
}

#ifdef PR_USE_DEVEL
static pr_ctrls_t *mem_ctrl = NULL;

static void mem_printf(const char *fmt, ...) {
  char buf[PR_TUNABLE_BUFFER_SIZE];
  va_list msg;

  memset(buf, '\0', sizeof(buf)); 

  va_start(msg, fmt);
  pr_vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);
 
  buf[sizeof(buf)-1] = '\0';
 
  pr_ctrls_add_response(mem_ctrl, "pool: %s", buf);
}
#endif /* !PR_USE_DEVEL */

/* Controls handlers
 */

static server_rec *ctrls_config_find_server(pr_ctrls_t *ctrl,
    const char *name) {
  unsigned int port = 21;
  const pr_netaddr_t *addr;
  pr_ipbind_t *ipbind;
  char *name_dup, *ptr;

  name_dup = pstrdup(ctrl->ctrls_tmp_pool, name);
  if (*name_dup == '[') {
    size_t namelen;

    /* Possible IPv6 address; make sure there's a terminating bracket. */
    ptr = strchr(name_dup + 1, ']');
    if (ptr == NULL) {
      pr_ctrls_add_response(ctrl, "config: badly formatted IPv6 address: %s",
        name);
      errno = EINVAL;
      return NULL;
    }

    namelen = ptr - (name_dup + 1);
    name_dup = pstrndup(ctrl->ctrls_tmp_pool, name_dup + 1, namelen);

    if (*(ptr+1) != '\0') {
      port = atoi(ptr + 1);
    }

  } else {
    ptr = strrchr(name_dup, ':');
    if (ptr != NULL) {
      port = atoi(ptr + 1);
      *ptr = '\0';
    }
  }

  addr = pr_netaddr_get_addr(ctrl->ctrls_tmp_pool, name_dup, NULL);
  if (addr == NULL) {
    pr_ctrls_add_response(ctrl, "config: no such server: %s", name_dup);
    errno = EINVAL;
    return NULL;
  }

  ipbind = pr_ipbind_find(addr, port, TRUE);
  if (ipbind != NULL) {
    return ipbind->ib_server;
  }

  pr_ctrls_add_response(ctrl, "config: no such server: %s", name);
  errno = ENOENT;
  return NULL;
}

static int ctrls_config_dispatch_cmd(pr_ctrls_t *ctrl, cmd_rec *cmd) {
  conftable *conftab;
  char found = FALSE;

  cmd->server = pr_parser_server_ctxt_get();
  cmd->config = pr_parser_config_ctxt_get();

  conftab = pr_stash_get_symbol2(PR_SYM_CONF, cmd->argv[0], NULL,
    &cmd->stash_index, &cmd->stash_hash);
  while (conftab != NULL) {
    modret_t *mr;

    pr_signals_handle();

    cmd->argv[0] = conftab->directive;

    mr = pr_module_call(conftab->m, conftab->handler, cmd);
    if (mr != NULL) {
      if (MODRET_ISERROR(mr)) {
        pr_ctrls_add_response(ctrl, "config set: %s", MODRET_ERRMSG(mr));
        errno = EPERM;
        return -1;
      }
    }

    if (!MODRET_ISDECLINED(mr)) {
      found = TRUE;
    }

    conftab = pr_stash_get_symbol2(PR_SYM_CONF, cmd->argv[0], conftab,
      &cmd->stash_index, &cmd->stash_hash);
  }

  if (cmd->tmp_pool) {
    destroy_pool(cmd->tmp_pool);
  }

  if (found == FALSE) {
    pr_ctrls_add_response(ctrl,
      "config set: unknown configuration directive '%s'",
      (char *) cmd->argv[0]);
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int ctrls_handle_config_set(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register int i;
  int res;
  server_rec *s, *curr_main_server;
  config_rec *c;
  cmd_rec *cmd;
  const char *name, *text;
  size_t textlen;

  /* At this point, reqargv should look something like:
   *
   *  0: "127.0.0.1:2121"
   *  1: "TLSRequired"
   *  ...
   */

  if (reqargc < 3 ||
      reqargv == NULL) {
    pr_ctrls_add_response(ctrl,
      "config set: missing required parameters");
    return -1;
  }

  name = reqargv[0];
  s = ctrls_config_find_server(ctrl, name);
  if (s == NULL) {
    return -1;
  }

  res = pr_parser_prepare(ctrl->ctrls_tmp_pool, NULL);
  if (res < 0) {
    pr_ctrls_add_response(ctrl, "config set: error preparing parser: %s",
      strerror(errno));
    return -1;
  }

  res = pr_parser_server_ctxt_push(s);
  if (res < 0) {
    pr_ctrls_add_response(ctrl,
      "config set: error adding server to parser stack: %s", strerror(errno));
    (void) pr_parser_cleanup();
    return -1;
  }

  text = "";
  for (i = 1; i < reqargc; i++) {
    text = pstrcat(ctrl->ctrls_tmp_pool, text, *text ? " " : "", reqargv[i],
      NULL);
  }

  textlen = strlen(text);
  cmd = pr_parser_parse_line(ctrl->ctrls_tmp_pool, text, textlen);
  if (cmd == NULL) {
    pr_ctrls_add_response(ctrl, "config set: error parsing config data: %s",
      strerror(errno));
    (void) pr_parser_cleanup();
    return -1;
  }

  c = find_config(s->conf, CONF_PARAM, cmd->argv[0], FALSE);
  if (c != NULL) {
    /* Note that remove_config() relies on the Parser API. */
    pr_config_remove(s->conf, cmd->argv[0], PR_CONFIG_FL_PRESERVE_ENTRY, FALSE);
  }

  curr_main_server = main_server;
  res = ctrls_config_dispatch_cmd(ctrl, cmd);
  main_server = curr_main_server;

  if (res < 0) {
    if (c != NULL) {
      xaset_t *set;

      /* The config_rec "remembers" its parent set; we just need to add
       * the record back into that set.
       */
      set = c->set;
      xaset_insert_end(set, (xasetmember_t *) c);
    }

  } else {
    pr_ctrls_add_response(ctrl, "config set: %s configured",
      (char *) cmd->argv[0]);
    pr_config_merge_down(s->conf, TRUE);
  }

  (void) pr_parser_cleanup();
  return 0;
}

static int ctrls_handle_config_remove(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  int res;
  server_rec *s;
  const char *name, *directive;

  /* At this point, reqargv should look something like:
   *
   *  0: "127.0.0.1:2121"
   *  1: "TLSRequired"
   */

  if (reqargc < 2 ||
      reqargv == NULL) {
    pr_ctrls_add_response(ctrl,
      "config remove: missing required parameters");
    return -1;
  }

  if (reqargc != 2) {
    pr_ctrls_add_response(ctrl,
      "config remove: wrong number of parameters");
    return -1;
  }

  name = reqargv[0];
  s = ctrls_config_find_server(ctrl, name);
  if (s == NULL) {
    return -1;
  }

  res = pr_parser_prepare(ctrl->ctrls_tmp_pool, NULL);
  if (res < 0) {
    pr_ctrls_add_response(ctrl, "config remove: error preparing parser: %s",
      strerror(errno));
    return -1;
  }

  res = pr_parser_server_ctxt_push(s);
  if (res < 0) {
    pr_ctrls_add_response(ctrl,
      "config remove: error adding server to parser stack: %s",
      strerror(errno));
    (void) pr_parser_cleanup();
    return -1;
  }

  directive = reqargv[1];
  res = remove_config(s->conf, directive, FALSE);
  if (res == TRUE) {
    pr_ctrls_add_response(ctrl, "config remove: %s removed", directive);
    pr_config_merge_down(s->conf, TRUE);

  } else {
    pr_ctrls_add_response(ctrl, "config remove: %s not found in configuration",
      directive);
  }

  (void) pr_parser_cleanup();
  return 0;
}

static int ctrls_handle_config(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {

  /* Sanity check */
  if (reqargc == 0 ||
      reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "config: missing required parameters");
    return -1;
  }

  if (strncmp(reqargv[0], "set", 4) == 0) {
    return ctrls_handle_config_set(ctrl, --reqargc, ++reqargv);

  } else if (strncmp(reqargv[0], "remove", 7) == 0) {
    return ctrls_handle_config_remove(ctrl, --reqargc, ++reqargv);
  }

  pr_ctrls_add_response(ctrl, "config: unknown config action: '%s'",
    reqargv[0]);
  return -1;
}

static int ctrls_handle_debug(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {

  /* Check the debug ACL */
  if (!pr_ctrls_check_acl(ctrl, ctrls_admin_acttab, "debug")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */
  if (reqargc == 0 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "debug: missing required parameters");
    return -1;
  }

  /* Handle 'debug level' requests */
  if (strcmp(reqargv[0], "level") == 0) {
    int level = 0;

    if (reqargc != 1 &&
        reqargc != 2) {
      pr_ctrls_add_response(ctrl, "debug: wrong number of parameters");
      return -1;
    }

    if (reqargc == 1) {
      /* The user is requesting the current debug level.  Easy enough. */
      level = pr_log_setdebuglevel(0);
      (void) pr_log_setdebuglevel(level);

      pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "debug: level set to %d", level);
      pr_ctrls_add_response(ctrl, "debug level set to %d", level);

    } else if (reqargc == 2) {
      level = atoi(reqargv[1]);
      if (level < 0) {
        pr_ctrls_add_response(ctrl, "debug level must not be negative");
        return -1; 
      }
  
      pr_log_setdebuglevel(level);
      pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "debug: level set to %d", level);
      pr_ctrls_add_response(ctrl, "debug level set to %d", level);
    }

#ifdef PR_USE_DEVEL
  /* Handle 'debug memory' requests */
  } else if (strcmp(reqargv[0], "mem") == 0 ||
             strcmp(reqargv[0], "memory") == 0) {

    if (reqargc != 1) {
      pr_ctrls_add_response(ctrl, "debug: too many parameters");
      return -1;
    }

    mem_ctrl = ctrl;
    pr_pool_debug_memory(mem_printf);
    mem_ctrl = NULL;

    pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "debug: dumped memory info");

#endif /* PR_USE_DEVEL */

  } else {
    pr_ctrls_add_response(ctrl, "unknown debug action: '%s'", reqargv[0]);
    return -1;
  }

  return 0;
}

static int ctrls_handle_dns(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  int bool;

  /* Check the dns ACL */
  if (!pr_ctrls_check_acl(ctrl, ctrls_admin_acttab, "dns")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */
  if (reqargc == 0 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "dns: missing required parameters");
    return -1;
  }

  if (reqargc != 1 &&
      reqargc != 2) {
    pr_ctrls_add_response(ctrl, "dns: wrong number of parameters");
    return -1;
  }

  if (reqargc == 2 &&
      strcmp(reqargv[0], "cache") == 0) {
    if (strcmp(reqargv[1], "clear") != 0) {
      pr_ctrls_add_response(ctrl,
        "dns: error: expected 'clear' command: '%s'", reqargv[1]);
      return -1;
    }

    pr_netaddr_clear_cache();
    pr_ctrls_add_response(ctrl, "dns: netaddr cache cleared");
    
  } else {
    bool = pr_str_is_boolean(reqargv[0]);
    if (bool == -1) {
      pr_ctrls_add_response(ctrl,
        "dns: error: expected Boolean parameter: '%s'", reqargv[0]);
      return -1;
    }

    ServerUseReverseDNS = bool;

    pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "dns: UseReverseDNS set to '%s'",
      bool ? "on" : "off");
    pr_ctrls_add_response(ctrl, "dns: UseReverseDNS set to '%s'",
      bool ? "on" : "off");
  }

  return 0;
}

static int admin_addr_down(pr_ctrls_t *ctrl, const pr_netaddr_t *addr,
    unsigned int port) {

  pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "down: disabling %s#%u",
    pr_netaddr_get_ipstr(addr), port);

  if (pr_ipbind_close(addr, port, FALSE) < 0) {
    if (errno == ENOENT) {
      pr_ctrls_add_response(ctrl, "down: no such server: %s#%u",
        pr_netaddr_get_ipstr(addr), port);

    } else {
      pr_ctrls_add_response(ctrl, "down: %s#%u already disabled",
        pr_netaddr_get_ipstr(addr), port);
    }

  } else {
    pr_ctrls_add_response(ctrl, "down: %s#%u disabled",
      pr_netaddr_get_ipstr(addr), port);
  }

  return 0;
}

static int ctrls_handle_down(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register int i = 0;

  /* Handle scheduled downs of virtual servers in the future, and
   * cancellations of scheduled downs.
   */

  /* Check the 'down' ACL */
  if (!pr_ctrls_check_acl(ctrl, ctrls_admin_acttab, "down")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */
  if (reqargc < 1 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "down: missing required parameters");
    return -1;
  }

  for (i = 0; i < reqargc; i++) {
    unsigned int server_port = 21;
    char *server_str = reqargv[i], *tmp = NULL;
    const pr_netaddr_t *server_addr = NULL;
    array_header *addrs = NULL;

    /* Check for an argument of "all" */
    if (strcasecmp(server_str, "all") == 0) {
      pr_ipbind_close(NULL, 0, FALSE);
      pr_ctrls_add_response(ctrl, "down: all servers disabled");
      return 0;
    }

    tmp = strchr(server_str, '#');
    if (tmp != NULL) {
      server_port = atoi(tmp + 1);
      *tmp = '\0';
    }

    server_addr = pr_netaddr_get_addr(ctrl->ctrls_tmp_pool, server_str, &addrs);
    if (server_addr == NULL) {
      pr_ctrls_add_response(ctrl, "down: no such server: %s#%u",
        server_str, server_port);
      continue;
    }

    admin_addr_down(ctrl, server_addr, server_port);

    if (addrs != NULL) {
      register unsigned int j;
      pr_netaddr_t **elts = addrs->elts;

      for (j = 0; j < addrs->nelts; j++) {
        admin_addr_down(ctrl, elts[j], server_port);
      }
    }
  }

  return 0;
}

static int ctrls_handle_get(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  int res = 0;

  /* Sanity check */
  if (reqargc == 0 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "get: missing required parameters");
    return -1;
  }

  /* Handle 'get config' requests */
  if (strcmp(reqargv[0], "config") == 0) {
    if (reqargc >= 2) {
      register int i = 0;

      for (i = 1; i < reqargc; i++) {
        config_rec *c = NULL;

        /* NOTE: there are some directives that are not stored as config_recs,
         * but rather as static variables or as members of other structs.
         * Handle these exceptions as well?  These include ServerName,
         * ServerType, ServerAdmin, etc.  How to handle configs that should
         * be retrievable, but are Boolean values instead of strings.  Hmmm.
         */

        if ((c = find_config(main_server->conf, CONF_PARAM, reqargv[i],
            FALSE)) != NULL) {

#if 0
          /* Not yet supported */
          if (c->flags & CF_GCTRL)
            pr_ctrls_add_response(ctrl, "%s: %s", reqargv[i],
              (char *) c->argv[0]);
          else
#endif
            pr_ctrls_add_response(ctrl, "%s: not retrievable", reqargv[i]);

        } else
          pr_ctrls_add_response(ctrl, "%s: directive not found", reqargv[i]);
      }

    } else {
      pr_ctrls_add_response(ctrl, "%s: missing parameters", reqargv[0]);
      res = -1;
    }

  /* Handle 'get directives' requests */
  } else if (strcmp(reqargv[0], "directives") == 0) {

    if (reqargc == 1) {
      conftable *conftab;
      int stash_idx = -1;
      unsigned int stash_hash = 0;

      /* Create a list of all known configuration directives. */

      conftab = pr_stash_get_symbol2(PR_SYM_CONF, NULL, NULL, &stash_idx,
        &stash_hash);
      while (stash_idx != -1) {
        pr_signals_handle();

        if (conftab) {
          pr_ctrls_add_response(ctrl, "%s (mod_%s.c)", conftab->directive,
            conftab->m->name);

        } else {
          stash_idx++;
        }

        conftab = pr_stash_get_symbol2(PR_SYM_CONF, NULL, conftab, &stash_idx,
          &stash_hash);
      }

      /* Be nice, and sort the directives lexicographically */
      qsort(ctrl->ctrls_cb_resps->elts, ctrl->ctrls_cb_resps->nelts,
        sizeof(char *), respcmp);

    } else {
      pr_ctrls_add_response(ctrl, "%s: wrong number of parameters", reqargv[0]);
      res = -1;
    }

  } else {
    pr_ctrls_add_response(ctrl, "unknown get type requested: '%s'", reqargv[0]);
    res = -1;
  }

  return res;
}

static int ctrls_handle_kick(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  int res = 0;

  /* Check the kick ACL */
  if (!pr_ctrls_check_acl(ctrl, ctrls_admin_acttab, "kick")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */
  if (reqargc == 0 ||
      reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "missing required parameters");
    return -1;
  }

  /* Handle 'kick user' requests. */
  if (strcmp(reqargv[0], "user") == 0) {
    register int i = 0;
    int optc, kicked_count = 0, kicked_max = -1;
    const char *reqopts = "n:";
    pr_scoreboard_entry_t *score = NULL;

    pr_getopt_reset();

    while ((optc = getopt(reqargc, reqargv, reqopts)) != -1) {
      switch (optc) {
        case 'n':
          kicked_max = atoi(optarg);
          if (kicked_max < 1) {
            pr_ctrls_add_response(ctrl, "bad number: %s", optarg);
            return -1;
          }
          break;

        case '?':
          pr_ctrls_add_response(ctrl, "unsupported option: '%c'",
            (char) optopt);
          return -1;
      }
    }

    if (optind == reqargc) {
      pr_ctrls_add_response(ctrl, "kick user: missing required user name(s)");
      return -1;
    }

    /* Iterate through the scoreboard, and send a SIGTERM to each
     * pid whose name matches the given user name(s).
     */
    for (i = optind; i < reqargc; i++) {
      unsigned char kicked_user = FALSE;

      if (pr_rewind_scoreboard() < 0) {
        pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "error rewinding scoreboard: %s",
          strerror(errno));
        pr_ctrls_add_response(ctrl, "error rewinding scoreboard: %s",
          strerror(errno));
        return -1;
      }

      while ((score = pr_scoreboard_entry_read()) != NULL) {
        pr_signals_handle();

        if (kicked_max > 0 &&
            kicked_count >= kicked_max) {
          break;
        }

        if (strcmp(reqargv[i], score->sce_user) == 0) {
          int xerrno;

          res = 0;

          PRIVS_ROOT
          res = pr_scoreboard_entry_kill(score, SIGTERM);
          xerrno = errno;
          PRIVS_RELINQUISH

          if (res == 0) {
            kicked_user = TRUE;
            kicked_count++;

          } else {
            pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION,
              "error kicking user '%s': %s", reqargv[i], strerror(xerrno));
          }
        }
      }

      if (pr_restore_scoreboard() < 0) {
        pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "error restoring scoreboard: %s",
          strerror(errno));
      }

      if (kicked_user) {
        if (kicked_max > 0) {
          pr_ctrls_add_response(ctrl, "kicked user '%s' (%d clients)",
            reqargv[i], kicked_max);
          pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "kicked user '%s' (%d clients)",
            reqargv[i], kicked_max);
          pr_log_debug(DEBUG4, MOD_CTRLS_ADMIN_VERSION
            ": kicked user '%s' (%d clients)", reqargv[i], kicked_max);

        } else {
          pr_ctrls_add_response(ctrl, "kicked user '%s'", reqargv[i]);
          pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "kicked user '%s'", reqargv[i]);
          pr_log_debug(DEBUG4, MOD_CTRLS_ADMIN_VERSION ": kicked user '%s'",
            reqargv[i]);
        }

      } else {
        pr_ctrls_add_response(ctrl, "user '%s' not connected", reqargv[i]);
      }
    }

  /* Handle 'kick host' requests. */
  } else if (strcmp(reqargv[0], "host") == 0) {
    register int i = 0;
    int optc, kicked_count = 0, kicked_max = -1;
    const char *reqopts = "n:";
    pr_scoreboard_entry_t *score = NULL;

    pr_getopt_reset();

    while ((optc = getopt(reqargc, reqargv, reqopts)) != -1) {
      switch (optc) {
        case 'n':
          kicked_max = atoi(optarg);
          if (kicked_max < 1) {
            pr_ctrls_add_response(ctrl, "bad number: %s", optarg);
            return -1;
          }
          break;

        case '?':
          pr_ctrls_add_response(ctrl, "unsupported option: '%c'",
            (char) optopt);
          return -1;
      }
    }

    if (optind == reqargc) {
      pr_ctrls_add_response(ctrl, "kick host: missing required host(s)");
      return -1;
    }

    /* Iterate through the scoreboard, and send a SIGTERM to each
     * pid whose address matches the given host name (resolve to
     * stringified IP address).
     */

    for (i = optind; i < reqargc; i++) {
      unsigned char kicked_host = FALSE;
      const char *addr;
      const pr_netaddr_t *na;

      na = pr_netaddr_get_addr(ctrl->ctrls_tmp_pool, reqargv[i], NULL);
      if (na == NULL) {
        pr_ctrls_add_response(ctrl, "kick host: error resolving '%s': %s",
          reqargv[i], strerror(errno));
        continue;
      }

      addr = pr_netaddr_get_ipstr(na);

      if (pr_rewind_scoreboard() < 0) {
        pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "error rewinding scoreboard: %s",
          strerror(errno));
        pr_ctrls_add_response(ctrl, "error rewinding scoreboard: %s",
          strerror(errno));
        return -1;
      }

      while ((score = pr_scoreboard_entry_read()) != NULL) {
        pr_signals_handle();

        if (kicked_max > 0 &&
            kicked_count >= kicked_max) {
          break;
        }

        if (strcmp(score->sce_client_addr, addr) == 0) {
          PRIVS_ROOT
          if (pr_scoreboard_entry_kill(score, SIGTERM) == 0) {
            kicked_host = TRUE;
            kicked_count++;
          }
          PRIVS_RELINQUISH
        }
      }
      pr_restore_scoreboard();

      if (kicked_host) {
        if (kicked_max > 0) {
          pr_ctrls_add_response(ctrl, "kicked host '%s' (%d clients)", addr,
            kicked_max);
          pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "kicked host '%s' (%d clients)",
            addr, kicked_max);
          pr_log_debug(DEBUG4, MOD_CTRLS_ADMIN_VERSION
            ": kicked host '%s' (%d clients)", addr, kicked_max);

        } else {
          pr_ctrls_add_response(ctrl, "kicked host '%s'", addr);
          pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "kicked host '%s'", addr);
          pr_log_debug(DEBUG4, MOD_CTRLS_ADMIN_VERSION ": kicked host '%s'",
            addr);
        }

      } else {
        pr_ctrls_add_response(ctrl, "host '%s' not connected", addr);
      }
    }

  /* Handle 'kick class' requests. */
  } else if (strcmp(reqargv[0], "class") == 0) {
    register int i = 0;
    int optc, kicked_count = 0, kicked_max = -1;
    const char *reqopts = "n:";
    pr_scoreboard_entry_t *score = NULL;

    pr_getopt_reset();

    while ((optc = getopt(reqargc, reqargv, reqopts)) != -1) {
      switch (optc) {
        case 'n':
          kicked_max = atoi(optarg);
          if (kicked_max < 1) {
            pr_ctrls_add_response(ctrl, "bad client number: %s", optarg);
            return -1;
          }
          break;

        case '?':
          pr_ctrls_add_response(ctrl, "unsupported option: '%c'",
            (char) optopt);
          return -1;
      }
    }

    if (optind == reqargc) {
      pr_ctrls_add_response(ctrl, "kick class: missing required class name(s)");
      return -1;
    }

    /* Iterate through the scoreboard, and send a SIGTERM to each
     * pid whose name matches the given class name(s).
     */
    for (i = optind; i < reqargc; i++) {
      unsigned char kicked_class = FALSE;

      if (pr_rewind_scoreboard() < 0) {
        pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "error rewinding scoreboard: %s",
          strerror(errno));
        pr_ctrls_add_response(ctrl, "error rewinding scoreboard: %s",
          strerror(errno));
        return -1;
      }

      while ((score = pr_scoreboard_entry_read()) != NULL) {
        pr_signals_handle();

        if (kicked_max > 0 &&
            kicked_count >= kicked_max) {
          break;
        }

        if (strcmp(reqargv[i], score->sce_class) == 0) {
          int xerrno;

          res = 0;

          PRIVS_ROOT
          res = pr_scoreboard_entry_kill(score, SIGTERM);
          xerrno = errno;
          PRIVS_RELINQUISH

          if (res == 0) {
            kicked_class = TRUE;
            kicked_count++;

          } else {
            pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION,
              "error kicking class '%s': %s", reqargv[i], strerror(xerrno));
          }
        }
      }

      if (pr_restore_scoreboard() < 0) {
        pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "error restoring scoreboard: %s",
          strerror(errno));
      }

      if (kicked_class) {
        if (kicked_max > 0) {
          pr_ctrls_add_response(ctrl, "kicked class '%s' (%d clients)",
            reqargv[i], kicked_max);
          pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION,
            "kicked class '%s' (%d clients)", reqargv[i], kicked_max);
          pr_log_debug(DEBUG4, MOD_CTRLS_ADMIN_VERSION
            ": kicked class '%s' (%d clients)", reqargv[i], kicked_max);

        } else {
          pr_ctrls_add_response(ctrl, "kicked class '%s'", reqargv[i]);
          pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "kicked class '%s'",
            reqargv[i]);
          pr_log_debug(DEBUG4, MOD_CTRLS_ADMIN_VERSION ": kicked class '%s'",
            reqargv[i]);
        }

      } else {
        pr_ctrls_add_response(ctrl, "class '%s' not connected", reqargv[i]);
      }
    }

  } else {
    pr_ctrls_add_response(ctrl, "unknown kick type requested: '%s'",
      reqargv[0]);
    res = -1;
  }

  return res;
}

static int ctrls_handle_restart(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {

  /* Check the restart ACL */
  if (!pr_ctrls_check_acl(ctrl, ctrls_admin_acttab, "restart")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Be pedantic */
  if (reqargc > 1) {
    pr_ctrls_add_response(ctrl, "wrong number of parameters");
    return -1;
  }

  if (reqargc == 0) {
    PRIVS_ROOT
    raise(SIGHUP);
    PRIVS_RELINQUISH

    pr_ctrls_add_response(ctrl, "restarted server");

  } else if (reqargc == 1) {
    if (strcmp(reqargv[0], "count") == 0) {
      struct tm *tm;

      tm = pr_gmtime(ctrl->ctrls_tmp_pool, &ctrls_admin_start);
      if (tm != NULL) {
        pr_ctrls_add_response(ctrl,
          "server restarted %u %s since %04d-%02d-%02d %02d:%02d:%02d GMT",
          ctrls_admin_nrestarts, ctrls_admin_nrestarts != 1 ? "times" : "time",
          tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min,
          tm->tm_sec);
      } else {
        pr_ctrls_add_response(ctrl, "error obtaining GMT timestamp: %s",
          strerror(errno));
        return -1;
      }

    } else {
      pr_ctrls_add_response(ctrl, "unsupported parameter '%s'", reqargv[0]);
      return -1;
    }
  }

  return 0;
}

static int ctrls_handle_scoreboard(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {

  /* Check the scoreboard ACL. */
  if (!pr_ctrls_check_acl(ctrl, ctrls_admin_acttab, "scoreboard")) {

    /* Access denied. */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  if (reqargc != 1) {
    pr_ctrls_add_response(ctrl, "wrong number of parameters");
    return -1;
  }

  if (strcmp(reqargv[0], "clean") == 0 ||
      strcmp(reqargv[0], "scrub") == 0) {

    pr_scoreboard_scrub();
    pr_ctrls_add_response(ctrl, "scrubbed scoreboard");
    return 0;
  }

  pr_ctrls_add_response(ctrl, "unknown scoreboard action '%s'", reqargv[0]);
  return -1;
}

static int ctrls_handle_shutdown(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register int i = 0;
  int respargc = 0;
  char **respargv = NULL;

  /* Check the shutdown ACL */
  if (!pr_ctrls_check_acl(ctrl, ctrls_admin_acttab, "shutdown")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Add a response */
  pr_ctrls_add_response(ctrl, "shutting down");

  if (reqargc >= 1 &&
      strcmp(reqargv[0], "graceful") == 0) {
    unsigned long nkids = 0;
    unsigned int waiting = CTRLS_DEFAULT_SHUTDOWN_WAIT;
    unsigned int timeout = 0;
    time_t now;

    if (reqargc == 2) {
      timeout = atoi(reqargv[1]);
      time(&now);

      pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION,
        "shutdown: waiting %u seconds before shutting down", timeout);

      /* If the timeout is less than the waiting period, reduce the
       * waiting period by half.
       */
      if (timeout < waiting) {
        waiting /= 2;
      }
    }

    /* Now, simply wait for all sessions to be done.  For bonus points,
     * the admin should be able to specify a timeout, after which any
     * sessions will be summarily terminated.  And, even better, have a
     * way to indicate to the sessions that the daemon wants to shut down,
     * and the session, if it is not involved in a data transfer, should
     * end itself.
     */

    nkids = child_count();
    while (nkids > 0) {
      if (timeout &&
          time(NULL) - now > timeout) {

        pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION,
          "shutdown: %u seconds elapsed, ending %lu remaining sessions",
          timeout, nkids);

        /* End all remaining sessions at this point. */
        PRIVS_ROOT
        child_signal(SIGTERM);
        PRIVS_RELINQUISH

        break;
      }

      pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION,
        "shutdown: waiting for %lu sessions to end", nkids);
      sleep(waiting);

      child_update();
      nkids = child_count();     

      /* Always check for sent signals in a while() loop. */
      pr_signals_handle();
    }
  }

  /* This is one of the rare cases where the control handler needs to
   * flush the responses out to the client manually, rather than waiting
   * for the normal controls cycle to handle it, as this handler is
   * not going to exit the function normally.
   */

  respargc = ctrl->ctrls_cb_resps->nelts;
  respargv = ctrl->ctrls_cb_resps->elts;

  /* Manually tweak the return value, for the benefit of the client */
  ctrl->ctrls_cb_retval = 0;

  if (pr_ctrls_flush_response(ctrl) < 0) {
    pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION,
      "shutdown: error flushing response: %s", strerror(errno));
  }

  /* For logging/accounting purposes */
  pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION,
    "shutdown: flushed to %s/%s client: return value: 0",
    ctrl->ctrls_cl->cl_user, ctrl->ctrls_cl->cl_group);

  for (i = 0; i < respargc; i++) {
    pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION,
      "shutdown: flushed to %s/%s client: '%s'",
      ctrl->ctrls_cl->cl_user, ctrl->ctrls_cl->cl_group, respargv[i]);
  }

  /* Shutdown by raising SIGTERM.  Easy. */
  raise(SIGTERM);

  return 0;
}

static int admin_addr_status(pr_ctrls_t *ctrl, const pr_netaddr_t *addr,
    unsigned int port) {
  pr_ipbind_t *ipbind = NULL;

  pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "status: checking %s#%u",
    pr_netaddr_get_ipstr(addr), port);

  /* Fetch the ipbind associated with this address/port. */
  ipbind = pr_ipbind_find(addr, port, FALSE);
  if (ipbind == NULL) {
    pr_ctrls_add_response(ctrl,
      "status: no server associated with %s#%u", pr_netaddr_get_ipstr(addr),
      port);
    return -1;
  }

  pr_ctrls_add_response(ctrl, "status: %s#%u %s", pr_netaddr_get_ipstr(addr),
    port, ipbind->ib_isactive ? "UP" : "DOWN");
  return 0;
}

static int ctrls_handle_status(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register int i = 0;

  /* Check the status ACL. */
  if (!pr_ctrls_check_acl(ctrl, ctrls_admin_acttab, "status")) {

    /* Access denied. */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */ 
  if (reqargc < 1 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "status: missing required parameters");
    return -1;
  }

  for (i = 0; i < reqargc; i++) {
    unsigned int server_port = 21;
    char *server_str = reqargv[i], *tmp = NULL;
    const pr_netaddr_t *server_addr = NULL;
    array_header *addrs = NULL;

    /* Check for an argument of "all" */
    if (strcasecmp(server_str, "all") == 0) {
      pr_ipbind_t *ipbind = NULL;

      pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "status: checking all servers");

      while ((ipbind = pr_ipbind_get(ipbind)) != NULL) {
        const char *ipbind_str = pr_netaddr_get_ipstr(ipbind->ib_addr); 

        pr_ctrls_add_response(ctrl, "status: %s#%u %s", ipbind_str,
          ipbind->ib_port, ipbind->ib_isactive ? "UP" : "DOWN");
      }

      return 0;
    }

    tmp = strchr(server_str, '#');
    if (tmp != NULL) {
      server_port = atoi(tmp + 1);
      *tmp = '\0';
    }

    server_addr = pr_netaddr_get_addr(ctrl->ctrls_tmp_pool, server_str, &addrs);
    if (server_addr == NULL) {
      pr_ctrls_add_response(ctrl, "status: no such server: %s#%u",
        server_str, server_port);
      continue;
    }

    if (admin_addr_status(ctrl, server_addr, server_port) < 0) {
      continue;
    }

    if (addrs != NULL) {
      register unsigned int j;
      pr_netaddr_t **elts = addrs->elts;

      for (j = 0; j < addrs->nelts; j++) {
        admin_addr_status(ctrl, elts[j], server_port);
      }
    }
  }

  return 0;
}

static int ctrls_handle_trace(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
#ifdef PR_USE_TRACE

  /* Check the trace ACL. */
  if (!pr_ctrls_check_acl(ctrl, ctrls_admin_acttab, "trace")) {

    /* Access denied. */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */
  if (reqargc < 1 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "trace: missing required parameters");
    return -1;
  }

  if (strcmp(reqargv[0], "info") != 0) {
    register int i;

    for (i = 0; i < reqargc; i++) {
      char *channel, *tmp;
      int min_level, max_level, res;

      tmp = strchr(reqargv[i], ':');
      if (tmp == NULL) {
        pr_ctrls_add_response(ctrl, "trace: badly formatted parameter: '%s'",
          reqargv[i]);
        return -1;
      }

      channel = reqargv[i];
      *tmp = '\0';

      res = pr_trace_parse_levels(tmp + 1, &min_level, &max_level);
      if (res == 0) {
        if (pr_trace_set_levels(channel, min_level, max_level) < 0) {
          pr_ctrls_add_response(ctrl,
            "trace: error setting channel '%s' to levels %d-%d: %s", channel,
            min_level, max_level, strerror(errno));
          return -1;

        } else {
          pr_ctrls_add_response(ctrl, "trace: set channel '%s' to levels %d-%d",
            channel, min_level, max_level);
        }

      } else {
        pr_ctrls_add_response(ctrl,
          "trace: error parsing level '%s' for channel '%s': %s", tmp + 1,
          channel, strerror(errno));
        return -1;
      }
    }
 
  } else {
    pr_table_t *trace_tab;

    trace_tab = pr_trace_get_table();
    if (trace_tab != NULL) {
      const void *key = NULL, *value = NULL;

      pr_ctrls_add_response(ctrl, "%-10s %-6s", "Channel", "Level");
      pr_ctrls_add_response(ctrl, "---------- ------");

      pr_table_rewind(trace_tab);
      key = pr_table_next(trace_tab);
      while (key != NULL) {
        pr_signals_handle();

        value = pr_table_get(trace_tab, (const char *) key, NULL);
        if (value) {
          pr_ctrls_add_response(ctrl, "%10s %-6d", (const char *) key,
            *((int *) value));
        }

        key = pr_table_next(trace_tab);
      }

    } else {
      pr_ctrls_add_response(ctrl, "trace: no info available");
    }
  }
 
  return 0;
#else
  pr_ctrls_add_response(ctrl, "trace: requires trace support (--enable-trace");
  return -1;
#endif /* PR_USE_TRACE */
}

static int admin_addr_up(pr_ctrls_t *ctrl, const pr_netaddr_t *addr,
    unsigned int port) {
  pr_ipbind_t *ipbind = NULL;
  int res = 0;

  /* Fetch the ipbind associated with this address/port. */
  ipbind = pr_ipbind_find(addr, port, FALSE);
  if (ipbind == NULL) {
    pr_ctrls_add_response(ctrl,
      "up: no server associated with %s#%u", pr_netaddr_get_ipstr(addr),
      port);
    errno = ENOENT;
    return -1;
  }

  /* If this ipbind is already active, abort now. */
  if (ipbind->ib_isactive) {
    pr_ctrls_add_response(ctrl, "up: %s#%u already enabled",
      pr_netaddr_get_ipstr(addr), port);
    return 0;
  }

  /* Determine whether this server_rec needs a listening connection
   * created.  A ServerType of SERVER_STANDALONE combined with a
   * SocketBindTight means each server_rec will have its own listen
   * connection; any other combination means that all the server_recs
   * share the same listen connection.
   */
  if (ipbind->ib_server->ServerPort && !ipbind->ib_server->listen) {
    ipbind->ib_server->listen = pr_ipbind_get_listening_conn(ipbind->ib_server,
      (SocketBindTight ? ipbind->ib_server->addr : NULL),
      ipbind->ib_server->ServerPort);
  }

  pr_ctrls_log(MOD_CTRLS_ADMIN_VERSION, "up: attempting to enable %s#%u",
    pr_netaddr_get_ipstr(addr), port);

  PR_OPEN_IPBIND(ipbind->ib_server->addr, ipbind->ib_server->ServerPort,
    ipbind->ib_server->listen, FALSE, FALSE, TRUE);

  if (res < 0) {
    pr_ctrls_add_response(ctrl, "up: no server listening on %s#%u",
      pr_netaddr_get_ipstr(addr), port);

  } else {
    pr_ctrls_add_response(ctrl, "up: %s#%u enabled",
      pr_netaddr_get_ipstr(addr), port);
  }

  PR_ADD_IPBINDS(ipbind->ib_server);
  return 0;
}

static int ctrls_handle_up(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register int i = 0;

  /* Handle scheduled ups of virtual servers in the future, and
   * cancellations of scheduled ups.
   */

  /* Check the 'up' ACL */
  if (!pr_ctrls_check_acl(ctrl, ctrls_admin_acttab, "up")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */
  if (reqargc < 1 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "up: missing required parameters");
    return -1;
  }

  for (i = 0; i < reqargc; i++) {
    unsigned int server_port = 21;
    char *server_str = reqargv[i], *tmp = NULL;
    const pr_netaddr_t *server_addr = NULL;
    array_header *addrs = NULL;

    tmp = strchr(server_str, '#');
    if (tmp != NULL) {
      server_port = atoi(tmp + 1);
      *tmp = '\0';
    }

    server_addr = pr_netaddr_get_addr(ctrl->ctrls_tmp_pool, server_str, &addrs);
    if (server_addr == NULL) {
      pr_ctrls_add_response(ctrl, "up: unable to resolve address for '%s'",
        server_str);
      return -1;
    }

    if (admin_addr_up(ctrl, server_addr, server_port) < 0) {
      return -1;
    }

    if (addrs != NULL) {
      register unsigned int j;
      pr_netaddr_t **elts = addrs->elts;

      for (j = 0; j < addrs->nelts; j++) {
        if (admin_addr_up(ctrl, elts[j], server_port) < 0) {
          return -1;
        }
      }
    }
  }

  return 0;
}

/* Configuration handlers
 */

/* usage: AdminControlsACLs actions|all allow|deny user|group list */
MODRET set_adminctrlsacls(cmd_rec *cmd) {
  char *bad_action = NULL, **actions = NULL;

  CHECK_ARGS(cmd, 4);
  CHECK_CONF(cmd, CONF_ROOT);

  /* We can cheat here, and use the ctrls_parse_acl() routine to
   * separate the given string...
   */
  actions = ctrls_parse_acl(cmd->tmp_pool, cmd->argv[1]);

  /* Check the second parameter to make sure it is "allow" or "deny" */
  if (strcmp(cmd->argv[2], "allow") != 0 &&
      strcmp(cmd->argv[2], "deny") != 0)
    CONF_ERROR(cmd, "second parameter must be 'allow' or 'deny'");

  /* Check the third parameter to make sure it is "user" or "group" */
  if (strcmp(cmd->argv[3], "user") != 0 &&
      strcmp(cmd->argv[3], "group") != 0)
    CONF_ERROR(cmd, "third parameter must be 'user' or 'group'");

  bad_action = pr_ctrls_set_module_acls(ctrls_admin_acttab, ctrls_admin_pool,
    actions, cmd->argv[2], cmd->argv[3], cmd->argv[4]);
  if (bad_action != NULL)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown action: '",
      bad_action, "'", NULL));

  return PR_HANDLED(cmd);
}

/* usage: AdminControlsEngine on|off|actions */
MODRET set_adminctrlsengine(cmd_rec *cmd) {
  int bool = -1;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if ((bool = get_boolean(cmd, 1)) != -1) {
    /* If bool is TRUE, there's no need to do anything.  If FALSE,
     * then unregister all the controls of this module.
     */
    if (!bool) {
      register unsigned int i = 0;

      for (i = 0; ctrls_admin_acttab[i].act_action; i++) {
        pr_ctrls_unregister(&ctrls_admin_module,
          ctrls_admin_acttab[i].act_action);
        destroy_pool(ctrls_admin_acttab[i].act_acl->acl_pool);
      }
    }

  } else {
    char *bad_action = NULL;

    /* Parse the given string of actions into a char **.  Then iterate
     * through the acttab, checking to see if a given control is _not_ in
     * the list.  If not in the list, unregister that control.
     */

    /* We can cheat here, and use the ctrls_parse_acl() routine to
     * separate the given string...
     */
    char **actions = ctrls_parse_acl(cmd->tmp_pool, cmd->argv[1]);

    bad_action = pr_ctrls_unregister_module_actions(ctrls_admin_acttab, actions,
      &ctrls_admin_module);
    if (bad_action != NULL)
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown action: '",
          bad_action, "'", NULL));
  }

  return PR_HANDLED(cmd);
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void ctrls_admin_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_ctrls_admin.c", (const char *) event_data) == 0) {
    register unsigned int i;

    pr_event_unregister(&ctrls_admin_module, NULL, NULL);

    for (i = 0; ctrls_admin_acttab[i].act_action; i++) {
      pr_ctrls_unregister(&ctrls_admin_module,
        ctrls_admin_acttab[i].act_action);
    }

    if (ctrls_admin_pool) {
      destroy_pool(ctrls_admin_pool);
      ctrls_admin_pool = NULL;
    }
  }
}
#endif /* PR_SHARED_MODULE */

static void ctrls_admin_restart_ev(const void *event_data, void *user_data) {
  register unsigned int i;

  if (ctrls_admin_pool)
    destroy_pool(ctrls_admin_pool);

  /* Allocate the pool for this module's use */
  ctrls_admin_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(ctrls_admin_pool, MOD_CTRLS_ADMIN_VERSION);

  /* Register the control handlers */
  for (i = 0; ctrls_admin_acttab[i].act_action; i++) {

    /* Allocate and initialize the ACL for this control. */
    ctrls_admin_acttab[i].act_acl = pcalloc(ctrls_admin_pool,
      sizeof(ctrls_acl_t));
    pr_ctrls_init_acl(ctrls_admin_acttab[i].act_acl);
  }

  ctrls_admin_nrestarts++;
  return;
}

static void ctrls_admin_startup_ev(const void *event_data, void *user_data) {
  int res;

  /* Make sure the process has an fd to the scoreboard. */
  PRIVS_ROOT
  res = pr_open_scoreboard(O_RDWR);
  PRIVS_RELINQUISH

  if (res < 0) {
    switch (res) {
      case PR_SCORE_ERR_BAD_MAGIC:
        pr_log_debug(DEBUG0, "error opening scoreboard: bad/corrupted file");
        break;

      case PR_SCORE_ERR_OLDER_VERSION:
        pr_log_debug(DEBUG0, "error opening scoreboard: bad version (too old)");
        break;

      case PR_SCORE_ERR_NEWER_VERSION:
        pr_log_debug(DEBUG0, "error opening scoreboard: bad version (too new)");
        break;

      default:
        pr_log_debug(DEBUG0, "error opening scoreboard: %s", strerror(errno));
        break;
    }
  }

  return;
}

/* Initialization routines
 */

static int ctrls_admin_init(void) {
  register unsigned int i = 0;

  /* Allocate the pool for this module's use */
  ctrls_admin_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(ctrls_admin_pool, MOD_CTRLS_ADMIN_VERSION);

  /* Register the control handlers */
  for (i = 0; ctrls_admin_acttab[i].act_action; i++) {

    /* Allocate and initialize the ACL for this control. */
    ctrls_admin_acttab[i].act_acl = pcalloc(ctrls_admin_pool,
      sizeof(ctrls_acl_t));
    pr_ctrls_init_acl(ctrls_admin_acttab[i].act_acl);

    if (pr_ctrls_register(&ctrls_admin_module,
        ctrls_admin_acttab[i].act_action, ctrls_admin_acttab[i].act_desc,
        ctrls_admin_acttab[i].act_cb) < 0)
     pr_log_pri(PR_LOG_NOTICE, MOD_CTRLS_ADMIN_VERSION
        ": error registering '%s' control: %s",
        ctrls_admin_acttab[i].act_action, strerror(errno));
  }

#if defined(PR_SHARED_MODULE)
  pr_event_register(&ctrls_admin_module, "core.module-unload",
    ctrls_admin_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&ctrls_admin_module, "core.restart",
    ctrls_admin_restart_ev, NULL);
  pr_event_register(&ctrls_admin_module, "core.startup",
    ctrls_admin_startup_ev, NULL);

  time(&ctrls_admin_start);
  return 0;
}

static ctrls_acttab_t ctrls_admin_acttab[] = {
  { "config",	"set config directives",	NULL,
    ctrls_handle_config },
  { "debug",    "set debugging level",		NULL,
    ctrls_handle_debug },
  { "dns",	"set UseReverseDNS configuration",	NULL,
    ctrls_handle_dns },
  { "down",     "disable an individual virtual server", NULL,
    ctrls_handle_down },
  { "get",      "list configuration data",	NULL,
    ctrls_handle_get },
  { "kick",	"disconnect a class, host, or user",	NULL,
    ctrls_handle_kick },
  { "restart",  "restart the daemon (similar to using HUP)",	NULL,
    ctrls_handle_restart },
  { "scoreboard", "clean the ScoreboardFile", NULL,
    ctrls_handle_scoreboard },
  { "shutdown", "shutdown the daemon",	NULL,
    ctrls_handle_shutdown },
  { "status",	"display status of servers",		NULL,
    ctrls_handle_status },
  { "trace",	"set trace levels",		NULL,
    ctrls_handle_trace },
  { "up",       "enable a downed virtual server",       NULL,
    ctrls_handle_up },
  { NULL, NULL,	NULL, NULL }
};

/* Module API tables
 */

static conftable ctrls_admin_conftab[] = {
  { "AdminControlsACLs",    	set_adminctrlsacls, 		NULL },
  { "AdminControlsEngine",	set_adminctrlsengine,		NULL },
  { NULL }
};

module ctrls_admin_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "ctrls_admin",

  /* Module configuration handler table */
  ctrls_admin_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  ctrls_admin_init,

  /* Session initialization function */
  NULL,

  /* Module version */
  MOD_CTRLS_ADMIN_VERSION
};
