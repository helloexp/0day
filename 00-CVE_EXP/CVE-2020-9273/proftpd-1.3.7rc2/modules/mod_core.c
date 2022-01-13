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

/* Core FTPD module */

#include "conf.h"
#include "privs.h"
#include "error.h"

#include <ctype.h>

extern module *loaded_modules;
extern module site_module;
extern xaset_t *server_list;

/* From src/main.c */
extern unsigned long max_connects;
extern unsigned int max_connect_interval;

/* From modules/mod_site.c */
extern modret_t *site_dispatch(cmd_rec*);

/* For bytes-retrieving directives */
#define PR_BYTES_BAD_UNITS	-1
#define PR_BYTES_BAD_FORMAT	-2

/* Maximum number of parameters for OPTS commands (see Bug#3870). */
#define PR_OPTS_MAX_PARAM_COUNT		8

module core_module;
char AddressCollisionCheck = TRUE;

static int core_scrub_timer_id = -1;
static pr_fh_t *displayquit_fh = NULL;

#ifdef PR_USE_TRACE
static const char *trace_log = NULL;
#endif /* PR_USE_TRACE */

/* Necessary prototypes. */
static void core_exit_ev(const void *, void *);
static int core_sess_init(void);
static void reset_server_auth_order(void);

/* These are for handling any configured MaxCommandRate. */
static unsigned long core_cmd_count = 0UL;
static unsigned long core_max_cmds = 0UL;
static unsigned int core_max_cmd_interval = 1;
static time_t core_max_cmd_ts = 0;

static unsigned long core_exceeded_cmd_rate(cmd_rec *cmd) {
  unsigned long res = 0;
  long over = 0;
  time_t now;

  if (core_max_cmds == 0) {
    return 0;
  }

  core_cmd_count++;

  over = core_cmd_count - core_max_cmds;
  if (over > 0) {
    /* Determine the delay, in ms.
     *
     * The value for this delay must be a value which will cause the command
     * rate to not be exceeded.  For example, if the config is:
     *
     *  MaxCommandRate 200 1
     *
     * it means a maximum of 200 commands a sec.  This works out to a command
     * every 5 ms, maximum:
     *
     *  1 sec * 1000 ms / 200 cmds per sec = 5 ms
     *
     * That 5 ms, then, would be the delay to use. For each command over the
     * maximum number of commands per interval, we add this delay factor.
     * This means that the more over the limit the session is, the longer the
     * delay.
     */

    res = (unsigned long) (((core_max_cmd_interval * 1000) / core_max_cmds) * over);
  }

  now = time(NULL);
  if (core_max_cmd_ts > 0) {
    if ((now - core_max_cmd_ts) > core_max_cmd_interval) {
      /* If it's been longer than the MaxCommandRate interval, reset the
       * command counter.
       */
      core_cmd_count = 0;
      core_max_cmd_ts = now;
    }

  } else {
    core_max_cmd_ts = now;
  }

  return res;
}

static int core_idle_timeout_cb(CALLBACK_FRAME) {
  int timeout;

  timeout = pr_data_get_timeout(PR_DATA_TIMEOUT_IDLE);

  /* We don't want to quit in the middle of a transfer */
  if (session.sf_flags & SF_XFER) { 
    pr_trace_msg("timer", 4,
      "TimeoutIdle (%d %s) reached, but data transfer in progress, ignoring",
      timeout, timeout != 1 ? "seconds" : "second"); 

    /* Restart the timer. */
    return 1; 
  }
 
  pr_event_generate("core.timeout-idle", NULL);
 
  pr_response_send_async(R_421,
    _("Idle timeout (%d seconds): closing control connection"), timeout);

  pr_timer_remove(PR_TIMER_LOGIN, ANY_MODULE);
  pr_timer_remove(PR_TIMER_NOXFER, ANY_MODULE);

  pr_log_pri(PR_LOG_INFO, "%s", "Client session idle timeout, disconnected");
  pr_session_disconnect(&core_module, PR_SESS_DISCONNECT_TIMEOUT,
    "TimeoutIdle");
  return 0;
}

/* If the environment variable being set/unset is locale-related, then we need
 * to call setlocale(3) again.
 *
 * Note: We deliberately set LC_NUMERIC to "C", regardless of configuration.
 * Failure to do so will cause problems with formatting of e.g. floats in
 * SQL query strings.
 */
static void core_handle_locale_env(const char *env_name) {
#if defined(PR_USE_NLS) && defined(HAVE_LOCALE_H)
  register unsigned int i;
  const char *locale_envs[] = {
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
    "LANG",
    NULL
  };

  for (i = 0; locale_envs[i] != NULL; i++) {
    if (strcmp(env_name, locale_envs[i]) == 0) {
      if (setlocale(LC_ALL, "") != NULL) {
        setlocale(LC_NUMERIC, "C");
      }
    }
  }
#endif /* PR_USE_NLS and HAVE_LOCALE_H */
}

static int core_scrub_scoreboard_cb(CALLBACK_FRAME) {
  /* Always return 1 when leaving this function, to make sure the timer
   * gets called again.
   */
  pr_scoreboard_scrub();

  return 1;
}

MODRET start_ifdefine(cmd_rec *cmd) {
  unsigned int ifdefine_ctx_count = 1;
  unsigned char not_define = FALSE, defined = FALSE;
  char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'}, *config_line = NULL, *ptr;

  CHECK_ARGS(cmd, 1);

  ptr = cmd->argv[1];
  if (*ptr == '!') {
    not_define = TRUE;
    ptr++;
  }

  defined = pr_define_exists(ptr);

  /* Return now if we don't need to consume the <IfDefine> section
   * configuration lines.
   */
  if ((!not_define && defined) ||
      (not_define && !defined)) {
    pr_log_debug(DEBUG3, "%s: using '%s%s' section at line %u",
      (char *) cmd->argv[0], not_define ? "!" : "", (char *) cmd->argv[1],
      pr_parser_get_lineno());
    return PR_HANDLED(cmd);
  }

  pr_log_debug(DEBUG3, "%s: skipping '%s%s' section at line %u",
    (char *) cmd->argv[0], not_define ? "!" : "", (char *) cmd->argv[1],
    pr_parser_get_lineno());

  /* Rather than communicating with parse_config_file() via some global
   * variable/flag the need to skip configuration lines, if the requested
   * module condition is not TRUE, read in the lines here (effectively
   * preventing them from being parsed) up to and including the closing
   * directive.
   */
  while (ifdefine_ctx_count && (config_line = pr_parser_read_line(buf,
      sizeof(buf))) != NULL) {

    if (strncasecmp(config_line, "<IfDefine", 9) == 0) {
      ifdefine_ctx_count++;

    } else if (strcasecmp(config_line, "</IfDefine>") == 0) {
      ifdefine_ctx_count--;
    }
  }

  /* If there are still unclosed <IfDefine> sections, signal an error.
   */
  if (ifdefine_ctx_count) {
    CONF_ERROR(cmd, "unclosed <IfDefine> context");
  }

  return PR_HANDLED(cmd);
}

/* As with Apache, there is no way of cleanly checking whether an
 * <IfDefine> section is properly closed.  Extra </IfDefine> directives
 * will be silently ignored.
 */
MODRET end_ifdefine(cmd_rec *cmd) {
  return PR_HANDLED(cmd);
}

MODRET start_ifmodule(cmd_rec *cmd) {
  unsigned int ifmodule_ctx_count = 1;
  unsigned char not_module = FALSE, found_module = FALSE;
  char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'}, *config_line = NULL, *ptr;

  CHECK_ARGS(cmd, 1);

  ptr = cmd->argv[1];
  if (*ptr == '!') {
    not_module = TRUE;
    ptr++;
  }

  found_module = pr_module_exists(ptr);

  /* Return now if we don't need to consume the <IfModule> section
   * configuration lines.
   */
  if ((!not_module && found_module) ||
      (not_module && !found_module)) {
    pr_log_debug(DEBUG3, "%s: using '%s%s' section at line %u",
      (char *) cmd->argv[0], not_module ? "!" : "", (char *) cmd->argv[1],
      pr_parser_get_lineno());
    return PR_HANDLED(cmd);
  }

  pr_log_debug(DEBUG3, "%s: skipping '%s%s' section at line %u",
    (char *) cmd->argv[0], not_module ? "!" : "", (char *) cmd->argv[1],
    pr_parser_get_lineno());

  /* Rather than communicating with parse_config_file() via some global
   * variable/flag the need to skip configuration lines, if the requested
   * module condition is not TRUE, read in the lines here (effectively
   * preventing them from being parsed) up to and including the closing
   * directive.
   */
  while (ifmodule_ctx_count && (config_line = pr_parser_read_line(buf,
      sizeof(buf))) != NULL) {
    char *bufp;

    pr_signals_handle();

    /* Advance past any leading whitespace. */
    for (bufp = config_line; *bufp && PR_ISSPACE(*bufp); bufp++);

    if (strncasecmp(bufp, "<IfModule", 9) == 0) {
      ifmodule_ctx_count++;

    } else if (strcasecmp(bufp, "</IfModule>") == 0) {
      ifmodule_ctx_count--;
    }
  }

  /* If there are still unclosed <IfModule> sections, signal an error. */
  if (ifmodule_ctx_count) {
    CONF_ERROR(cmd, "unclosed <IfModule> context");
  }

  return PR_HANDLED(cmd);
}

/* As with Apache, there is no way of cleanly checking whether an
 * <IfModule> section is properly closed.  Extra </IfModule> directives
 * will be silently ignored.
 */
MODRET end_ifmodule(cmd_rec *cmd) {
  return PR_HANDLED(cmd);
}

/* Syntax: Define parameter
 *
 * Configuration file equivalent of the -D command-line option for
 * specifying an <IfDefine> value.
 *
 * It is suggested the RLimitMemory (a good idea to use anyway) be
 * used if this directive is present, to prevent Defines was being
 * used by a malicious local user in a .ftpaccess file.
 */
MODRET set_define(cmd_rec *cmd) {

  /* Make sure there's at least one parameter; any others are ignored */
  CHECK_ARGS(cmd, 1);

  /* This directive can occur in any context, so no need for the
   * CHECK_CONF macro.
   */

  pr_define_add(cmd->argv[1], FALSE);
  return PR_HANDLED(cmd);
}

/* usage: Include path|pattern */
MODRET set_include(cmd_rec *cmd) {
  int allowed_ctxs, parent_ctx, res, xerrno;

  CHECK_ARGS(cmd, 1);

  /* If we are not currently in a .ftpaccess context, then we allow Include
   * in a <Limit> section.  Otherwise, a .ftpaccess file could contain a
   * <Limit>, and that <Limit> could include e.g. itself, leading to a loop.
   */

  allowed_ctxs = CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL|CONF_DIR;

  parent_ctx = CONF_ROOT;
  if (cmd->config != NULL &&
      cmd->config->parent != NULL) {
    parent_ctx = cmd->config->parent->config_type;
  }

  if (parent_ctx != CONF_DYNDIR) {
    allowed_ctxs |= CONF_LIMIT;
  }

  CHECK_CONF(cmd, allowed_ctxs);

  /* Make sure the given path is a valid path. */

  PRIVS_ROOT
  res = pr_fs_valid_path(cmd->argv[1]);
  PRIVS_RELINQUISH

  if (res < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "unable to use path for configuration file '", cmd->argv[1], "'", NULL));
  }

  PRIVS_ROOT
  res = parse_config_path(cmd->tmp_pool, cmd->argv[1]);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (res < 0) {
    if (xerrno != EINVAL) {
      pr_log_pri(PR_LOG_WARNING, "warning: unable to include '%s': %s",
        (char *) cmd->argv[1], strerror(xerrno));

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error including '",
        (char *) cmd->argv[1], "': ", strerror(xerrno), NULL));
    }
  }

  return PR_HANDLED(cmd);
}

/* usage: IncludeOptions opt1 ... */
MODRET set_includeoptions(cmd_rec *cmd) {
  register unsigned int i;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "AllowSymlinks") == 0) {
      opts |= PR_PARSER_INCLUDE_OPT_ALLOW_SYMLINKS;

    } else if (strcmp(cmd->argv[i], "IgnoreTempFiles") == 0) {
      opts |= PR_PARSER_INCLUDE_OPT_IGNORE_TMP_FILES;

    } else if (strcmp(cmd->argv[i], "IgnoreWildcards") == 0) {
      opts |= PR_PARSER_INCLUDE_OPT_IGNORE_WILDCARDS;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown IncludeOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  (void) pr_parser_set_include_opts(opts);
  return PR_HANDLED(cmd);
}

MODRET set_debuglevel(cmd_rec *cmd) {
  config_rec *c = NULL;
  int debuglevel = -1;
  char *endp = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* Make sure the parameter is a valid number. */
  debuglevel = strtol(cmd->argv[1], &endp, 10);

  if (endp && *endp)
    CONF_ERROR(cmd, "not a valid number");

  /* Make sure the number is within the valid debug level range. */
  if (debuglevel < 0 || debuglevel > 10)
    CONF_ERROR(cmd, "invalid debug level configured");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = debuglevel;

  return PR_HANDLED(cmd);
}

MODRET set_defaultaddress(cmd_rec *cmd) {
  const char *name, *main_ipstr;
  const pr_netaddr_t *main_addr = NULL;
  array_header *addrs = NULL;
  unsigned int addr_flags = PR_NETADDR_GET_ADDR_FL_INCL_DEVICE;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT);

  name = cmd->argv[1];
  main_addr = pr_netaddr_get_addr2(main_server->pool, name, &addrs, addr_flags);
  if (main_addr == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to resolve '", name, "'",
      NULL));
  }

  /* If the given name is a DNS name, automatically add a ServerAlias
   * directive.
   */
  if (pr_netaddr_is_v4(name) == FALSE &&
      pr_netaddr_is_v6(name) == FALSE) {
    add_config_param_str("ServerAlias", 1, name);
  }

  main_server->ServerAddress = main_ipstr = pr_netaddr_get_ipstr(main_addr);
  main_server->addr = main_addr;

  if (addrs != NULL) {
    register unsigned int i;
    pr_netaddr_t **elts = addrs->elts;

    /* For every additional address, implicitly add a bind record. */
    for (i = 0; i < addrs->nelts; i++) {
      const char *ipstr;

      ipstr = pr_netaddr_get_ipstr(elts[i]);

      /* Skip duplicate addresses. */
      if (strcmp(main_ipstr, ipstr) == 0) {
        continue;
      }

#ifdef PR_USE_IPV6
      if (pr_netaddr_use_ipv6()) {
        char *ipbuf;

        ipbuf = pcalloc(cmd->tmp_pool, INET6_ADDRSTRLEN + 1);
        if (pr_netaddr_get_family(elts[i]) == AF_INET) {
          /* Create the bind record using the IPv4-mapped IPv6 version of
           * this address.
           */
          pr_snprintf(ipbuf, INET6_ADDRSTRLEN, "::ffff:%s", ipstr);
          ipstr = ipbuf;
        }
      }
#endif /* PR_USE_IPV6 */

      add_config_param_str("_bind_", 1, ipstr);
    }
  }

  /* Handle multiple addresses in a DefaultAddress directive.  We do
   * this by adding bind directives to the server_rec created for the
   * first address.
   */
  if (cmd->argc-1 > 1) {
    register unsigned int i;
    char *addrs_str = (char *) pr_netaddr_get_ipstr(main_addr);

    for (i = 2; i < cmd->argc; i++) {
      const char *addr_ipstr;
      const pr_netaddr_t *addr;
      addrs = NULL;

      addr = pr_netaddr_get_addr2(cmd->tmp_pool, cmd->argv[i], &addrs,
        addr_flags);
      if (addr == NULL) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error resolving '",
          cmd->argv[i], "': ", strerror(errno), NULL));
      }

      addr_ipstr = pr_netaddr_get_ipstr(addr);
      add_config_param_str("_bind_", 1, addr_ipstr);

      /* If the given name is a DNS name, automatically add a ServerAlias
       * directive.
       */
      if (pr_netaddr_is_v4(cmd->argv[i]) == FALSE &&
          pr_netaddr_is_v6(cmd->argv[i]) == FALSE) {
        add_config_param_str("ServerAlias", 1, cmd->argv[i]);
      }

      addrs_str = pstrcat(cmd->tmp_pool, addrs_str, ", ", addr_ipstr, NULL);

      if (addrs != NULL) {
        register unsigned int j;
        pr_netaddr_t **elts = addrs->elts;

        /* For every additional address, implicitly add a bind record. */
        for (j = 0; j < addrs->nelts; j++) {
          const char *ipstr;

          ipstr = pr_netaddr_get_ipstr(elts[j]);

          /* Skip duplicate addresses. */
          if (strcmp(addr_ipstr, ipstr) == 0) {
            continue;
          }

          add_config_param_str("_bind_", 1, ipstr);
        }
      }
    }

    pr_log_debug(DEBUG3, "setting default addresses to %s", addrs_str);

  } else {
    pr_log_debug(DEBUG3, "setting default address to %s", main_ipstr);
  }

  return PR_HANDLED(cmd);
}

MODRET set_servername(cmd_rec *cmd) {
  server_rec *s = cmd->server;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  s->ServerName = pstrdup(s->pool,cmd->argv[1]);
  return PR_HANDLED(cmd);
}

MODRET set_servertype(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (strcasecmp(cmd->argv[1], "inetd") == 0)
    ServerType = SERVER_INETD;

  else if (strcasecmp(cmd->argv[1], "standalone") == 0)
    ServerType = SERVER_STANDALONE;

  else
    CONF_ERROR(cmd,"type must be either 'inetd' or 'standalone'");

  return PR_HANDLED(cmd);
}

MODRET set_setenv(cmd_rec *cmd) {
  int ctxt_type;

  CHECK_ARGS(cmd, 2);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 2, cmd->argv[1], cmd->argv[2]);

  /* In addition, if this is the "server config" context, set the
   * environment variable now.  If there was a <Daemon> context, that would
   * be a more appropriate place for configuring parse-time environ
   * variables.
   */
  ctxt_type = (cmd->config && cmd->config->config_type != CONF_PARAM ?
     cmd->config->config_type : cmd->server->config_type ?
     cmd->server->config_type : CONF_ROOT);

  if (ctxt_type == CONF_ROOT) {
    if (pr_env_set(cmd->server->pool, cmd->argv[1], cmd->argv[2]) < 0) {
      pr_log_debug(DEBUG1, "%s: unable to set environment variable '%s': %s",
        (char *) cmd->argv[0], (char *) cmd->argv[1], strerror(errno));

    } else {
      core_handle_locale_env(cmd->argv[1]);
    }
  }

  return PR_HANDLED(cmd);
}

MODRET add_transferlog(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET set_serveradmin(cmd_rec *cmd) {
  server_rec *s = cmd->server;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  s->ServerAdmin = pstrdup(s->pool, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: UseIPv6 on|off */
MODRET set_useipv6(cmd_rec *cmd) {
#ifdef PR_USE_IPV6
  int bool = -1;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  if (bool == 0) {
    pr_log_debug(DEBUG2, "disabling runtime support for IPv6 connections");
    pr_netaddr_disable_ipv6();

  } else {
    pr_netaddr_enable_ipv6();
  }

  return PR_HANDLED(cmd);
#else
  CONF_ERROR(cmd,
    "Use of the UseIPv6 directive requires IPv6 support (--enable-ipv6)");
#endif /* PR_USE_IPV6 */
}

MODRET set_usereversedns(cmd_rec *cmd) {
  int bool = -1;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  ServerUseReverseDNS = bool;
  pr_netaddr_set_reverse_dns(bool);

  return PR_HANDLED(cmd);
}

MODRET set_satisfy(cmd_rec *cmd) {
  int satisfy = -1;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_CLASS);

  if (strcasecmp(cmd->argv[1], "any") == 0) {
    satisfy = PR_CLASS_SATISFY_ANY;

  } else if (strcasecmp(cmd->argv[1], "all") == 0) {
    satisfy = PR_CLASS_SATISFY_ALL;

  } else {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "invalid parameter: '",
      cmd->argv[1], "'", NULL));
  }

  if (pr_class_set_satisfy(satisfy) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error setting Satisfy: ",
      strerror(errno), NULL));
  }

  return PR_HANDLED(cmd);
}

/* usage: ScoreboardFile path */
MODRET set_scoreboardfile(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_set_scoreboard(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to use '", cmd->argv[1],
      "': ", strerror(errno), NULL));
  }

  return PR_HANDLED(cmd);
}

/* usage: ScoreboardMutex path */
MODRET set_scoreboardmutex(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_set_scoreboard_mutex(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to use '", cmd->argv[1],
      "': ", strerror(errno), NULL));
  }

  return PR_HANDLED(cmd);
}

/* usage: ScoreboardScrub "on"|"off"|secs */
MODRET set_scoreboardscrub(cmd_rec *cmd) {
  int bool = -1, nsecs = 0;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);
 
  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    /* If this is the case, try handling the parameter as the number of
     * seconds, as the scrub frequency.
     */
    nsecs = atoi(cmd->argv[1]);
    if (nsecs <= 0) {
      CONF_ERROR(cmd, "number must be greater than zero");
    }
  }

  if (nsecs > 0) {
    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(int));
    *((int *) c->argv[0]) = TRUE;
    c->argv[1] = pcalloc(c->pool, sizeof(int));
    *((int *) c->argv[1]) = nsecs;

  } else {
    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(int));
    *((int *) c->argv[0]) = bool;
  }

  return PR_HANDLED(cmd);
}

MODRET set_serverport(cmd_rec *cmd) {
  server_rec *s = cmd->server;
  int port;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  port = atoi(cmd->argv[1]);
  if (port < 0 ||
      port > 65535) {
    CONF_ERROR(cmd, "value must be between 0 and 65535");
  }

  s->ServerPort = port;
  return PR_HANDLED(cmd);
}

MODRET set_pidfile(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_pidfile_set(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to set PidFile '",
      cmd->argv[1], "': ", strerror(errno), NULL));
  }

  return PR_HANDLED(cmd);
}

MODRET set_sysloglevel(cmd_rec *cmd) {
  config_rec *c = NULL;
  int level = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  level = pr_log_str2sysloglevel(cmd->argv[1]);
  if (level < 0) {
    CONF_ERROR(cmd, "SyslogLevel requires level keyword: one of "
      "emerg/alert/crit/error/warn/notice/info/debug");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = level;

  return PR_HANDLED(cmd);
}

/* usage: ServerAlias hostname [hostname ...] */
MODRET set_serveralias(cmd_rec *cmd) {
  register unsigned int i;

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  for (i = 1; i < cmd->argc; i++) {
    add_config_param_str(cmd->argv[0], 1, cmd->argv[i]);
  }

  return PR_HANDLED(cmd);
}

/* usage: ServerIdent off|on [name] */
MODRET set_serverident(cmd_rec *cmd) {
  int ident_on = -1;
  config_rec *c = NULL;

  if (cmd->argc < 2 ||
      cmd->argc > 3) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  ident_on = get_boolean(cmd, 1);
  if (ident_on == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  if (ident_on == TRUE &&
      cmd->argc == 3) {
    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) c->argv[0]) = ident_on;
    c->argv[1] = pstrdup(c->pool, cmd->argv[2]);

  } else {
    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) c->argv[0]) = ident_on;
  }

  return PR_HANDLED(cmd);
}

MODRET set_defaultserver(cmd_rec *cmd) {
  int bool = -1;
  server_rec *s = NULL;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  if (!bool) {
    return PR_HANDLED(cmd);
  }

  /* DefaultServer is not allowed if already set somewhere */
  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    if (find_config(s->conf, CONF_PARAM, cmd->argv[0], FALSE)) {
      CONF_ERROR(cmd, "DefaultServer has already been set");
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

MODRET set_masqueradeaddress(cmd_rec *cmd) {
  config_rec *c = NULL;
  const char *name;
  size_t namelen;
  const pr_netaddr_t *masq_addr = NULL;
  unsigned int addr_flags = PR_NETADDR_GET_ADDR_FL_INCL_DEVICE;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* We can only masquerade as one address, so we don't need to know if the
   * given name might map to multiple addresses.
   */
  name = cmd->argv[1];
  namelen = strlen(name);
  if (namelen == 0) {
    /* Guard against empty names here. */
    CONF_ERROR(cmd, "missing required name parameter");
  }

  masq_addr = pr_netaddr_get_addr2(cmd->server->pool, name, NULL, addr_flags);
  if (masq_addr == NULL) {
    /* If the requested name cannot be resolved because it is not known AT
     * THIS TIME, then do not fail to start the server.  We will simply try
     * again later (Bug#4104).
     */
    if (errno != ENOENT) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to resolve '", name, "'",
        NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 2, (void *) masq_addr, NULL);
  c->argv[1] = pstrdup(c->pool, cmd->argv[1]);

  return PR_HANDLED(cmd);
}

MODRET set_maxinstances(cmd_rec *cmd) {
  long max_instances;
  char *endp;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (strcasecmp(cmd->argv[1], "none") == 0) {
    max_instances = 0UL;

  } else {
    max_instances = strtol(cmd->argv[1], &endp, 10);

    if ((endp && *endp) ||
        max_instances < 1) {
      CONF_ERROR(cmd, "argument must be 'none' or a number greater than 0");
    }
  }

  ServerMaxInstances = max_instances;
  return PR_HANDLED(cmd);
}

/* usage: MaxCommandRate rate [interval] */
MODRET set_maxcommandrate(cmd_rec *cmd) {
  config_rec *c;
  long cmd_max = 0L;
  unsigned int max_cmd_interval = 1;
  char *endp = NULL;

  if (cmd->argc-1 < 1 ||
      cmd->argc-1 > 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  cmd_max = strtol(cmd->argv[1], &endp, 10);

  if (endp && *endp) {
    CONF_ERROR(cmd, "invalid command rate");
  }

  if (cmd_max < 0) {
    CONF_ERROR(cmd, "command rate must be positive");
  }

  /* If the optional interval parameter is given, parse it. */
  if (cmd->argc-1 == 2) {
    max_cmd_interval = atoi(cmd->argv[2]);

    if (max_cmd_interval < 1) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "interval must be greater than zero", NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = cmd_max;
  c->argv[1] = palloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[1]) = max_cmd_interval;

  return PR_HANDLED(cmd);
}


/* usage: MaxConnectionRate rate [interval] */
MODRET set_maxconnrate(cmd_rec *cmd) {
  long conn_max = 0L;
  char *endp = NULL;

  if (cmd->argc-1 < 1 ||
      cmd->argc-1 > 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }
  CHECK_CONF(cmd, CONF_ROOT);

  conn_max = strtol(cmd->argv[1], &endp, 10);

  if (endp && *endp) {
    CONF_ERROR(cmd, "invalid connection rate");
  }

  if (conn_max < 0) {
    CONF_ERROR(cmd, "connection rate must be positive");
  }

  max_connects = conn_max;

  /* If the optional interval parameter is given, parse it. */
  if (cmd->argc-1 == 2) {
    max_connect_interval = atoi(cmd->argv[2]);

    if (max_connect_interval < 1) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "interval must be greater than zero", NULL));
    }
  }

  return PR_HANDLED(cmd);
}

MODRET set_timeoutidle(cmd_rec *cmd) {
  int timeout = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if (pr_str_get_duration(cmd->argv[1], &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      cmd->argv[1], "': ", strerror(errno), NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET set_timeoutlinger(cmd_rec *cmd) {
  int timeout = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (pr_str_get_duration(cmd->argv[1], &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      cmd->argv[1], "': ", strerror(errno), NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;

  return PR_HANDLED(cmd);
}

MODRET set_socketbindtight(cmd_rec *cmd) {
  int bool = -1;
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  SocketBindTight = bool;
  return PR_HANDLED(cmd);
}

/* NOTE: at some point in the future, SocketBindTight should be folded
 * into this SocketOptions directive handler.
 */
MODRET set_socketoptions(cmd_rec *cmd) {
  register unsigned int i = 0;

  /* Make sure we have the right number of parameters. */
  if ((cmd->argc-1) % 2 != 0)
   CONF_ERROR(cmd, "bad number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  for (i = 1; i < cmd->argc; i++) {
    int value = 0;

    if (strcasecmp(cmd->argv[i], "maxseg") == 0) {
      value = atoi(cmd->argv[++i]);

      /* As per the tcp(7) man page, sizes larger than the interface MTU
       * will be ignored, and will have no effect.
       */

      if (value < 0) {
        CONF_ERROR(cmd, "maxseg size must be greater than 0");
      }

      cmd->server->tcp_mss_len = value;

    } else if (strcasecmp(cmd->argv[i], "rcvbuf") == 0) {
      value = atoi(cmd->argv[++i]);

      if (value < 1024) {
        CONF_ERROR(cmd, "rcvbuf size must be greater than or equal to 1024");
      }

      cmd->server->tcp_rcvbuf_len = value;
      cmd->server->tcp_rcvbuf_override = TRUE;

    } else if (strcasecmp(cmd->argv[i], "sndbuf") == 0) {
      value = atoi(cmd->argv[++i]);

      if (value < 1024) {
        CONF_ERROR(cmd, "sndbuf size must be greater than or equal to 1024");
      }

      cmd->server->tcp_sndbuf_len = value;
      cmd->server->tcp_sndbuf_override = TRUE;

    /* SocketOption keepalive off
     * SocketOption keepalive on
     * SocketOption keepalive 7200:9:75
     */
    } else if (strcasecmp(cmd->argv[i], "keepalive") == 0) {
      int b;

      b = get_boolean(cmd, i+1);
      if (b == -1) {
#if defined(TCP_KEEPIDLE) || defined(TCP_KEEPCNT) || defined(TCP_KEEPINTVL)
        char *keepalive_spec, *ptr, *ptr2;
        int idle, count, intvl;

        /* Parse the given keepalive-spec */
        keepalive_spec = cmd->argv[i+1];

        ptr = strchr(keepalive_spec, ':');
        if (ptr == NULL) {
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
            "badly formatted TCP keepalive spec '", cmd->argv[i+1], "'", NULL));
        }

        *ptr = '\0';
        idle = atoi(keepalive_spec);

        keepalive_spec = ptr + 1;
        ptr2 = strchr(keepalive_spec, ':');
        if (ptr2 == NULL) {
          *ptr = ':';
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
            "badly formatted TCP keepalive spec '", cmd->argv[i+1], "'", NULL));
        }

        *ptr2 = '\0'; 
        count = atoi(keepalive_spec);

        keepalive_spec = ptr2 + 1;
        intvl = atoi(keepalive_spec);

        if (idle < 1) {
          char val_str[33];

          memset(val_str, '\0', sizeof(val_str));
          pr_snprintf(val_str, sizeof(val_str)-1, "%d", idle);

          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
            "badly formatted TCP keepalive spec: idle time '", val_str,
            "' cannot be less than 1", NULL));
        }

        if (count < 1) {
          char val_str[33];

          memset(val_str, '\0', sizeof(val_str));
          pr_snprintf(val_str, sizeof(val_str)-1, "%d", count);

          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
            "badly formatted TCP keepalive spec: count '", val_str,
            "' cannot be less than 1", NULL));
        }

        if (intvl < 1) {
          char val_str[33];

          memset(val_str, '\0', sizeof(val_str));
          pr_snprintf(val_str, sizeof(val_str)-1, "%d", intvl);

          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
            "badly formatted TCP keepalive spec: interval time '", val_str,
            "' cannot be less than 1", NULL));
        }

        cmd->server->tcp_keepalive->keepalive_enabled = TRUE;
        cmd->server->tcp_keepalive->keepalive_idle = idle;
        cmd->server->tcp_keepalive->keepalive_count = count;
        cmd->server->tcp_keepalive->keepalive_intvl = intvl;
#else
        cmd->server->tcp_keepalive->keepalive_enabled = TRUE;
        pr_log_debug(DEBUG0,
          "%s: platform does not support fine-grained TCP keepalive control, "
          "using \"keepalive on\"", (char *) cmd->argv[0]);
#endif /* No TCP_KEEPIDLE, TCP_KEEPCNT, or TCP_KEEPINTVL */

      } else {
        cmd->server->tcp_keepalive->keepalive_enabled = b;
      }

      /* Don't forget to increment the iterator. */
      i++;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown socket option: '",
        cmd->argv[i], "'", NULL));
    }
  }

  return PR_HANDLED(cmd);
}

MODRET set_multilinerfc2228(cmd_rec *cmd) {
  int bool;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;
 
  return PR_HANDLED(cmd);
}

MODRET set_tcpbacklog(cmd_rec *cmd) {
  int backlog;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  backlog = atoi(cmd->argv[1]);

  if (backlog < 1 ||
      backlog > 255) {
    CONF_ERROR(cmd, "parameter must be a number between 1 and 255");
  }

#ifdef SOMAXCONN
  if (backlog > SOMAXCONN) {
    char str[32];

    memset(str, '\0', sizeof(str));
    pr_snprintf(str, sizeof(str)-1, "%u", (unsigned int) SOMAXCONN);

    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "parameter must be less than SOMAXCONN (", str, ")", NULL));
  }
#endif

  tcpBackLog = backlog;
  return PR_HANDLED(cmd);
}

MODRET set_tcpnodelay(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

MODRET set_user(cmd_rec *cmd) {
  struct passwd *pw = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  /* 1.1.7, no longer force user/group lookup inside <Anonymous>
   * it's now deferred until authentication occurs.
   */

  if (!cmd->config || cmd->config->config_type != CONF_ANON) {
    pw = pr_auth_getpwnam(cmd->tmp_pool, cmd->argv[1]);
    if (pw == NULL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "Unknown user '",
        cmd->argv[1], "'", NULL));
    }
  }

  if (pw) {
    config_rec *c = add_config_param("UserID", 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(uid_t));
    *((uid_t *) c->argv[0]) = pw->pw_uid;
  }

  add_config_param_str("UserName", 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

MODRET add_from(cmd_rec *cmd) {
  int cargc;
  void **cargv;

  CHECK_CONF(cmd, CONF_CLASS);

  cargc = cmd->argc-1;
  cargv = cmd->argv;

  while (cargc && *(cargv + 1)) {
    if (strcasecmp("all", *(((char **) cargv) + 1)) == 0 ||
        strcasecmp("none", *(((char **) cargv) + 1)) == 0) {
      pr_netacl_t *acl = pr_netacl_create(cmd->tmp_pool,
        *(((char **) cargv) + 1));
      if (acl == NULL) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad ACL definition '",
          *(((char **) cargv) + 1), "': ", strerror(errno), NULL));
      }

      pr_trace_msg("netacl", 9, "'%s' parsed into netacl '%s'",
        *(((char **) cargv) + 1), pr_netacl_get_str(cmd->tmp_pool, acl));

      if (pr_class_add_acl(acl) < 0) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error adding rule '",
          *(((char **) cargv) + 1), "': ", strerror(errno), NULL));
      }

      cargc = 0;
    }

    break;
  }

  /* Parse each parameter into a netacl. */
  while (cargc-- && *(++cargv)) {
    char *ent = NULL, *str;

    str = pstrdup(cmd->tmp_pool, *((char **) cargv));

    while ((ent = pr_str_get_token(&str, ",")) != NULL) {
      if (*ent) {
        pr_netacl_t *acl;

        if (strcasecmp(ent, "all") == 0 ||
            strcasecmp(ent, "none") == 0) {
           cargc = 0;
           break;
         }

        acl = pr_netacl_create(cmd->tmp_pool, ent);
        if (acl == NULL) {
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad ACL definition '",
            *(((char **) cargv) + 1), "': ", strerror(errno), NULL));
        }

        pr_trace_msg("netacl", 9, "'%s' parsed into netacl '%s'", ent,
          pr_netacl_get_str(cmd->tmp_pool, acl));

        if (pr_class_add_acl(acl) < 0) {
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error adding rule '", ent,
            "': ", strerror(errno), NULL));
        }
      }
    }
  }

  return PR_HANDLED(cmd);
}

/* usage: FSCachePolicy on|off|size {count} [maxAge {age}] */
MODRET set_fscachepolicy(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;

  if (cmd->argc != 2 &&
      cmd->argc != 5) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  if (cmd->argc == 2) {
    int engine;

    engine = get_boolean(cmd, 1);
    if (engine == -1) {
      CONF_ERROR(cmd, "expected Boolean parameter");
    }

    c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);
    c->argv[0] = palloc(c->pool, sizeof(int));
    *((int *) c->argv[0]) = engine;
    c->argv[1] = palloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[1]) = PR_TUNABLE_FS_STATCACHE_SIZE;
    c->argv[2] = palloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[2]) = PR_TUNABLE_FS_STATCACHE_MAX_AGE;

    return PR_HANDLED(cmd);
  }

  c = add_config_param_str(cmd->argv[0], 3, NULL, NULL, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = TRUE;
  c->argv[1] = palloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[1]) = PR_TUNABLE_FS_STATCACHE_SIZE;
  c->argv[2] = palloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[2]) = PR_TUNABLE_FS_STATCACHE_MAX_AGE;

  for (i = 1; i < cmd->argc; i++) {
    if (strncasecmp(cmd->argv[i], "size", 5) == 0) {
      int size;

      size = atoi(cmd->argv[i++]);
      if (size < 1) {
        CONF_ERROR(cmd, "size parameter must be greater than 1");
      }

      *((unsigned int *) c->argv[1]) = size;

    } else if (strncasecmp(cmd->argv[i], "maxAge", 7) == 0) {
      int max_age;

      max_age = atoi(cmd->argv[i++]);
      if (max_age < 1) {
        CONF_ERROR(cmd, "maxAge parameter must be greater than 1");
      }

      *((unsigned int *) c->argv[2]) = max_age;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown FSCachePolicy: ",
        cmd->argv[i], NULL));
    }
  }

  return PR_HANDLED(cmd);
}

/* usage: FSOptions opt1 opt2 ... */
MODRET set_fsoptions(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;

  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "IgnoreExtendedAttributes") == 0) {
      opts |= PR_FSIO_OPT_IGNORE_XATTR;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown FSOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

MODRET set_group(cmd_rec *cmd) {
  struct group *grp = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  if (!cmd->config || cmd->config->config_type != CONF_ANON) {
    grp = pr_auth_getgrnam(cmd->tmp_pool, cmd->argv[1]);
    if (grp == NULL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "Unknown group '",
        cmd->argv[1], "'", NULL));
    }
  }

  if (grp) {
    config_rec *c = add_config_param("GroupID", 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(gid_t));
    *((gid_t *) c->argv[0]) = grp->gr_gid;
  }

  add_config_param_str("GroupName", 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: Trace ["session"] channel1:level1 ... */
MODRET set_trace(cmd_rec *cmd) {
#ifdef PR_USE_TRACE
  register unsigned int i;
  int per_session = FALSE;
  unsigned int idx = 1;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }
  CHECK_CONF(cmd, CONF_ROOT);

  /* Look for the optional "session" keyword, which will indicate that these
   * Trace settings are to be applied to a session process only.
   */
  if (strncmp(cmd->argv[1], "session", 8) == 0) {

    /* If this is the only parameter, it's a config error. */
    if (cmd->argc == 2) {
      CONF_ERROR(cmd, "wrong number of parameters");
    }

    per_session = TRUE;
    idx = 2;
  }

  if (!per_session) {
    for (i = idx; i < cmd->argc; i++) {
      char *channel, *ptr;
      int min_level, max_level, res;

      ptr = strchr(cmd->argv[i], ':');
      if (ptr == NULL) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "badly formatted parameter: '",
          cmd->argv[i], "'", NULL));
      }

      channel = cmd->argv[i];
      *ptr = '\0';

      res = pr_trace_parse_levels(ptr + 1, &min_level, &max_level);
      if (res < 0) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing level \"",
          ptr + 1, "\" for channel '", channel, "': ", strerror(errno), NULL));
      }

      if (pr_trace_set_levels(channel, min_level, max_level) < 0) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error setting level \"",
          ptr + 1, "\" for channel '", channel, "': ", strerror(errno), NULL));
      }

      *ptr = ':';
    }

  } else {
    register unsigned int j = 0;
    config_rec *c;

    /* Do a syntax check of the configured trace channels/levels, and store
     * them in a config rec for later handling.
     */

    c = add_config_param(cmd->argv[0], 0);
    c->argc = cmd->argc - 2;
    c->argv = pcalloc(c->pool, ((c->argc + 1) * sizeof(void *))); 

    for (i = idx; i < cmd->argc; i++) {
      char *ptr;

      ptr = strchr(cmd->argv[i], ':');
      if (ptr == NULL) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "badly formatted parameter: '",
          cmd->argv[i], "'", NULL));
      }

      c->argv[j++] = pstrdup(c->pool, cmd->argv[i]);
    }
  }

  return PR_HANDLED(cmd);
#else
  CONF_ERROR(cmd,
    "Use of the Trace directive requires trace support (--enable-trace)");
#endif /* PR_USE_TRACE */
}

/* usage: TraceLog path */
MODRET set_tracelog(cmd_rec *cmd) {
#ifdef PR_USE_TRACE
  if (cmd->argc-1 != 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  trace_log = pstrdup(cmd->server->pool, cmd->argv[1]);
  if (pr_trace_set_file(trace_log) < 0) {
    if (errno == EPERM) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error using TraceLog '",
        trace_log, "': directory is symlink or is world-writable", NULL));

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error using TraceLog '",
        trace_log, "': ", strerror(errno), NULL));
    }
  }

  return PR_HANDLED(cmd);
#else
  CONF_ERROR(cmd,
    "Use of the TraceLog directive requires trace support (--enable-trace)");
#endif /* PR_USE_TRACE */
}

/* usage: TraceOptions opt1 ... optN */
MODRET set_traceoptions(cmd_rec *cmd) {
#ifdef PR_USE_TRACE
  register unsigned int i;
  int ctx;
  config_rec *c;
  unsigned long trace_opts = PR_TRACE_OPT_DEFAULT;

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  for (i = 1; i < cmd->argc; i++) {
    char action, *opt;

    opt = cmd->argv[i];
    action = *opt;

    if (action != '-' &&
        action != '+') {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad TraceOption: '", opt, "'",
        NULL));
    }

    opt++;

    if (strncasecmp(opt, "ConnIPs", 8) == 0) {
      switch (action) {
        case '-':
          trace_opts &= ~PR_TRACE_OPT_LOG_CONN_IPS;
          break;

        case '+':
          trace_opts |= PR_TRACE_OPT_LOG_CONN_IPS;
          break;
      }

    } else if (strncasecmp(opt, "TimestampMillis", 16) == 0) {
      switch (action) {
        case '-':
          trace_opts &= ~PR_TRACE_OPT_USE_TIMESTAMP_MILLIS;
          break;

        case '+':
          trace_opts |= PR_TRACE_OPT_USE_TIMESTAMP_MILLIS;
          break;
      }

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown TraceOption: '",
        opt, "'", NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = trace_opts;

  ctx = (cmd->config && cmd->config->config_type != CONF_PARAM ?
    cmd->config->config_type : cmd->server->config_type ?
    cmd->server->config_type : CONF_ROOT);

  if (ctx == CONF_ROOT) {
    /* If we're the "server config" context, set the TraceOptions here,
     * too.  This will apply these TraceOptions to the daemon process.
     */
    if (pr_trace_set_options(trace_opts) < 0) {
      pr_log_debug(DEBUG6, "%s: error setting TraceOptions (%lu): %s",
        (char *) cmd->argv[0], trace_opts, strerror(errno));
    }
  }

  return PR_HANDLED(cmd);

#else
  CONF_ERROR(cmd,
    "Use of the TraceOptions directive requires trace support (--enable-trace)");
#endif /* PR_USE_TRACE */
}

MODRET set_umask(cmd_rec *cmd) {
  config_rec *c;
  char *endp;
  mode_t tmp_umask;

  CHECK_VARARGS(cmd, 1, 2);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR|CONF_DYNDIR);

  tmp_umask = (mode_t) strtol(cmd->argv[1], &endp, 8);

  if (endp && *endp) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", cmd->argv[1],
      "' is not a valid umask", NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(mode_t));
  *((mode_t *) c->argv[0]) = tmp_umask;
  c->flags |= CF_MERGEDOWN;

  /* Have we specified a directory umask as well?
   */
  if (CHECK_HASARGS(cmd, 2)) {

    /* allocate space for another mode_t.  Don't worry -- the previous
     * pointer was recorded in the Umask config_rec
     */
    tmp_umask = (mode_t) strtol(cmd->argv[2], &endp, 8);

    if (endp && *endp) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", cmd->argv[2],
        "' is not a valid umask", NULL));
    }

    c = add_config_param("DirUmask", 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(mode_t));
    *((mode_t *) c->argv[0]) = tmp_umask;
    c->flags |= CF_MERGEDOWN;
  }

  return PR_HANDLED(cmd);
}

MODRET set_unsetenv(cmd_rec *cmd) {
  int ctxt_type;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]); 

  /* In addition, if this is the "server config" context, unset the
   * environment variable now.  If there was a <Daemon> context, that would
   * be a more appropriate place for configuring parse-time environment
   * variables.
   */
  ctxt_type = (cmd->config && cmd->config->config_type != CONF_PARAM ?
    cmd->config->config_type : cmd->server->config_type ?
    cmd->server->config_type : CONF_ROOT);

  if (ctxt_type == CONF_ROOT) {
    if (pr_env_unset(cmd->server->pool, cmd->argv[1]) < 0) {
      pr_log_debug(DEBUG1, "%s: unable to unset environment variable '%s': %s",
        (char *) cmd->argv[0], (char *) cmd->argv[1], strerror(errno));

    } else {
      core_handle_locale_env(cmd->argv[1]);
    }
  }

  return PR_HANDLED(cmd);
}

/* usage: ProcessTitles "terse"|"verbose" */
MODRET set_processtitles(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (strcasecmp(cmd->argv[1], "terse") != 0 &&
      strcasecmp(cmd->argv[1], "verbose") != 0) {
    CONF_ERROR(cmd, "unknown parameter");
  }

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: Protocols protocol1 ... protocolN */
MODRET set_protocols(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  array_header *list;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);

  list = make_array(c->pool, 0, sizeof(char *));
  for (i = 1; i < cmd->argc; i++) {
    *((char **) push_array(list)) = pstrdup(c->pool, cmd->argv[i]);
  }

  c->argv[0] = list;
  c->flags |= CF_MULTI;

  return PR_HANDLED(cmd);
}

/* usage: RegexOptions [MatchLimit limit] [MatchLimitRecursion limit]
 */
MODRET set_regexoptions(cmd_rec *cmd) {
  config_rec *c;
  unsigned long match_limit = 0, match_limit_recursion = 0;
  register unsigned int i;

  if (cmd->argc < 3) {
    CONF_ERROR(cmd, "Wrong number of parameters");

  } else {
    int npairs;

    /* Make sure we have an even number of args for the key/value pairs. */
    npairs = cmd->argc - 1;
    if (npairs % 2 != 0) {
      CONF_ERROR(cmd, "Wrong number of parameters");
    }
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* XXX If more limits/options are supported, switch to using a table
   * for storing the key/value pairs.
   */

  for (i = 1; i < cmd->argc; i++) {
    if (strncmp(cmd->argv[i], "MatchLimit", 11) == 0) {
      char *ptr = NULL;

      match_limit = strtoul(cmd->argv[i+1], &ptr, 10);
      if (ptr && *ptr) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad MatchLimit value: ",
          cmd->argv[i+1], NULL));
      }

      /* Don't forget to advance i past the value. */
      i += 2;

    } else if (strncmp(cmd->argv[i], "MatchLimitRecursion", 20) == 0) {
      char *ptr = NULL;

      match_limit_recursion = strtoul(cmd->argv[i+1], &ptr, 10);
      if (ptr && *ptr) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
          "bad MatchLimitRecursion value: ", cmd->argv[i+1], NULL));
      }

      /* Don't forget to advance i past the value. */
      i += 2;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown RegexOptions option: '",
        cmd->argv[i], "'", NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = match_limit;
  c->argv[1] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[1]) = match_limit_recursion;

  return PR_HANDLED(cmd);
}

MODRET set_syslogfacility(cmd_rec *cmd) {
  int i;
  struct {
    char *name;
    int facility;
  } factable[] = {
  { "AUTH",		LOG_AUTHPRIV		},
  { "AUTHPRIV",		LOG_AUTHPRIV		},
#ifdef HAVE_LOG_FTP
  { "FTP",		LOG_FTP			},
#endif
#ifdef HAVE_LOG_CRON
  { "CRON",		LOG_CRON		},
#endif
  { "DAEMON",		LOG_DAEMON		},
  { "KERN",		LOG_KERN		},
  { "LOCAL0",		LOG_LOCAL0		},
  { "LOCAL1",		LOG_LOCAL1		},
  { "LOCAL2",		LOG_LOCAL2		},
  { "LOCAL3",		LOG_LOCAL3		},
  { "LOCAL4",		LOG_LOCAL4		},
  { "LOCAL5",		LOG_LOCAL5		},
  { "LOCAL6",		LOG_LOCAL6		},
  { "LOCAL7",		LOG_LOCAL7		},
  { "LPR",		LOG_LPR			},
  { "MAIL",		LOG_MAIL		},
  { "NEWS",		LOG_NEWS		},
  { "USER",		LOG_USER		},
  { "UUCP",		LOG_UUCP		},
  { NULL,		0			} };

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  for (i = 0; factable[i].name; i++) {
    if (strcasecmp(cmd->argv[1], factable[i].name) == 0) {
      log_closesyslog();
      log_setfacility(factable[i].facility);

      pr_signals_block();
      switch (log_opensyslog(NULL)) {
        case -1:
          pr_signals_unblock();
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to open syslog: ",
            strerror(errno), NULL));
          break;

        case PR_LOG_WRITABLE_DIR:
          pr_signals_unblock();
          CONF_ERROR(cmd,
            "you are attempting to log to a world-writable directory");
          break;

        case PR_LOG_SYMLINK:
          pr_signals_unblock();
          CONF_ERROR(cmd, "you are attempting to log to a symbolic link");
          break;

        default:
          break;
      }
      pr_signals_unblock();

      return PR_HANDLED(cmd);
    }
  }

  CONF_ERROR(cmd, "argument must be a valid syslog facility");
}

MODRET set_timesgmt(cmd_rec *cmd) {
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

MODRET set_regex(cmd_rec *cmd, char *param, char *type) {
#ifdef PR_USE_REGEX
  pr_regex_t *pre = NULL;
  config_rec *c = NULL;
  int regex_flags = REG_EXTENDED|REG_NOSUB, res = 0;

  if (cmd->argc-1 < 1 ||
      cmd->argc-1 > 2) {
    CONF_ERROR(cmd, "bad number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR|
    CONF_DYNDIR);

  /* Make sure that, if present, the flags parameter is correctly formatted. */
  if (cmd->argc-1 == 2) {
    int flags = 0;

    /* We need to parse the flags parameter here, to see if any flags which
     * affect the compilation of the regex (e.g. NC) are present.
     */

    flags = pr_filter_parse_flags(cmd->tmp_pool, cmd->argv[2]);
    if (flags < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "badly formatted flags parameter: '", cmd->argv[2], "'", NULL));
    }

    if (flags == 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "unknown filter flags '", cmd->argv[2], "'", NULL));
    }

    regex_flags |= flags;
  }

  pr_log_debug(DEBUG4, "%s: compiling %s regex '%s'", (char *) cmd->argv[0],
    type, (char *) cmd->argv[1]);
  pre = pr_regexp_alloc(&core_module);

  res = pr_regexp_compile(pre, cmd->argv[1], regex_flags);
  if (res != 0) {
    char errstr[200] = {'\0'};

    pr_regexp_error(res, pre, errstr, sizeof(errstr));
    pr_regexp_free(NULL, pre);

    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", (char *) cmd->argv[1],
      "' failed regex compilation: ", errstr, NULL));
  }

  c = add_config_param(param, 1, pre);
  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);

#else /* no regular expression support at the moment */
  CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "The ", param, " directive cannot be "
    "used on this system, as you do not have POSIX compliant regex support",
    NULL));
#endif
}

MODRET set_allowdenyfilter(cmd_rec *cmd) {
#ifdef PR_USE_REGEX
  pr_regex_t *pre = NULL;
  config_rec *c = NULL;
  int regex_flags = REG_EXTENDED|REG_NOSUB, res = 0;

  if (cmd->argc-1 < 1 ||
      cmd->argc-1 > 2) {
    CONF_ERROR(cmd, "bad number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR|
    CONF_DYNDIR|CONF_LIMIT);

  /* Make sure that, if present, the flags parameter is correctly formatted. */
  if (cmd->argc-1 == 2) {
    int flags = 0;

    /* We need to parse the flags parameter here, to see if any flags which
     * affect the compilation of the regex (e.g. NC) are present.
     */

    flags = pr_filter_parse_flags(cmd->tmp_pool, cmd->argv[2]);
    if (flags < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "badly formatted flags parameter: '", cmd->argv[2], "'", NULL));
    }

    if (flags == 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "unknown filter flags '", cmd->argv[2], "'", NULL));
    }

    regex_flags |= flags;
  }

  pr_log_debug(DEBUG4, "%s: compiling regex '%s'", (char *) cmd->argv[0],
    (char *) cmd->argv[1]);
  pre = pr_regexp_alloc(&core_module);

  res = pr_regexp_compile(pre, cmd->argv[1], regex_flags);
  if (res != 0) {
    char errstr[200] = {'\0'};

    pr_regexp_error(res, pre, errstr, sizeof(errstr));
    pr_regexp_free(NULL, pre);

    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", (char *) cmd->argv[1],
      "' failed regex compilation: ", errstr, NULL));
  }

  c = add_config_param(cmd->argv[0], 1, pre);
  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);

#else /* no regular expression support at the moment */
  CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "The ", cmd->argv[0],
    " directive cannot be used on this system, as you do not have POSIX "
    "compliant regex support", NULL));
#endif
}

MODRET set_passiveports(cmd_rec *cmd) {
  int pasv_min_port, pasv_max_port;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 2);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  pasv_min_port = atoi(cmd->argv[1]);
  pasv_max_port = atoi(cmd->argv[2]);

  /* Sanity check */
  if (pasv_min_port <= 0 ||
      pasv_min_port > 65535) {
    CONF_ERROR(cmd, "min port must be allowable port number");
  }

  if (pasv_max_port <= 0 ||
      pasv_max_port > 65535) {
    CONF_ERROR(cmd, "max port must be allowable port number");
  }

  if (pasv_min_port < 1024 ||
      pasv_max_port < 1024) {
    CONF_ERROR(cmd, "port numbers must be above 1023");
  }

  if (pasv_max_port <= pasv_min_port) {
    CONF_ERROR(cmd, "min port must be less than max port");
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = pasv_min_port;
  c->argv[1] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = pasv_max_port;

  return PR_HANDLED(cmd);
}

MODRET set_pathallowfilter(cmd_rec *cmd) {
  return set_regex(cmd, cmd->argv[0], "allow");
}

MODRET set_pathdenyfilter(cmd_rec *cmd) {
  return set_regex(cmd, cmd->argv[0], "deny");
}

/* usage: AllowForeignAddress on|off|class */
MODRET set_allowforeignaddress(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;
  char *class_name = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    /* Not a boolean?  Assume it's a <Class> name, then. */
    class_name = cmd->argv[1];
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;
  c->argv[1] = pstrdup(c->pool, class_name);

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

MODRET set_commandbuffersize(cmd_rec *cmd) {
  size_t size = 0;
  off_t nbytes = 0;
  config_rec *c = NULL;
  const char *units = NULL;

  if (cmd->argc < 2 || cmd->argc > 3) {
    CONF_ERROR(cmd, "wrong number of parameters")
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (cmd->argc == 3) {
    units = cmd->argv[2];
  }

  if (pr_str_get_nbytes(cmd->argv[1], units, &nbytes) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to parse: ",
      cmd->argv[1], " ", units ? units : "", ": ", strerror(errno), NULL));
  }

  if (nbytes > PR_TUNABLE_CMD_BUFFER_SIZE) {
    char max[1024];

    pr_snprintf(max, sizeof(max)-1, "%lu", (unsigned long)
      PR_TUNABLE_CMD_BUFFER_SIZE);
    max[sizeof(max)-1] = '\0';

    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "size ", cmd->argv[1],
      units ? units : "", "exceeds max size ", max, NULL));
  }

  /* Possible truncation here, but only for an absurdly large size. */
  size = (size_t) nbytes;

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(size_t));
  *((size_t *) c->argv[0]) = size;

  return PR_HANDLED(cmd);
}

MODRET set_cdpath(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET add_directory(cmd_rec *cmd) {
  config_rec *c;
  char *dir, *rootdir = NULL;
  int flags = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  dir = cmd->argv[1];

  if (*dir != '/' &&
      *dir != '~' &&
      (!cmd->config ||
       cmd->config->config_type != CONF_ANON)) {
    CONF_ERROR(cmd, "relative path not allowed in non-<Anonymous> sections");
  }

  /* If in anonymous mode, and path is relative, just cat anon root
   * and relative path.
   *
   * Note: This is no longer necessary, because we don't interpolate anonymous
   * directories at run-time.
   */
  if (cmd->config &&
      cmd->config->config_type == CONF_ANON &&
      *dir != '/' &&
      *dir != '~') {
    if (strncmp(dir, "*", 2) != 0) {
      dir = pdircat(cmd->tmp_pool, "/", dir, NULL);
    }
    rootdir = cmd->config->name;

  } else {
    if (pr_fs_valid_path(dir) < 0) {
      /* Not an absolute path; mark it for deferred resolution. */
      flags |= CF_DEFER;
    }
  }

  /* Check to see that there isn't already a config for this directory,
   * but only if we're not in an <Anonymous> section.  Due to the way
   * in which later <Directory> checks are done, <Directory> blocks inside
   * <Anonymous> sections are handled differently than outside, probably
   * overriding their outside counterparts (if necessary).  This is
   * probably OK, as this overriding only takes effect for the <Anonymous>
   * user.
   */

  if (!check_context(cmd, CONF_ANON) &&
      find_config(cmd->server->conf, CONF_DIR, dir, FALSE) != NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "<Directory> section already configured for '", cmd->argv[1], "'", NULL));
  }

  /* Check for any expandable variables, and mark this config_rec for
   * deferred resolution if present
   */
  if (strstr(dir, "%u")) {
    flags |= CF_DEFER;
  }

  c = pr_parser_config_ctxt_open(dir);
  c->argc = 2;
  c->argv = pcalloc(c->pool, 3 * sizeof(void *));

  /* If we do NOT have rootdir, then do NOT add anything to the argv[1] slot;
   * it is intended solely for that particular use case.
   */
  if (rootdir) {
    c->argv[1] = pstrdup(c->pool, rootdir);
  }

  c->config_type = CONF_DIR;
  c->flags |= flags;

  if (!(c->flags & CF_DEFER)) {
    pr_log_debug(DEBUG2, "<Directory %s>: adding section for resolved "
      "path '%s'", (char *) cmd->argv[1], dir);

  } else {
    pr_log_debug(DEBUG2,
      "<Directory %s>: deferring resolution of path", (char *) cmd->argv[1]);
  }

  return PR_HANDLED(cmd);
}

MODRET set_hidefiles(cmd_rec *cmd) {
#ifdef PR_USE_REGEX
  pr_regex_t *pre = NULL;
  config_rec *c = NULL;
  unsigned int precedence = 0;
  unsigned char negated = FALSE, none = FALSE;
  char *ptr;

  int ctxt = (cmd->config && cmd->config->config_type != CONF_PARAM ?
    cmd->config->config_type : cmd->server->config_type ?
    cmd->server->config_type : CONF_ROOT);

  /* This directive must have either 1, or 3, arguments */
  if (cmd->argc-1 != 1 &&
      cmd->argc-1 != 3) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_DIR|CONF_DYNDIR);

  /* Set the precedence for this config_rec based on its configuration
   * context.
   */
  if (ctxt & CONF_DIR) {
    precedence = 1;

  } else {
    precedence = 2;
  }

  /* Check for a leading '!' prefix, signifying regex negation */
  ptr = cmd->argv[1];
  if (*ptr == '!') {
    negated = TRUE;
    ptr++;

  } else {
    /* Check for a "none" argument, which is used to nullify inherited
     * HideFiles configurations from parent directories.
     */
    if (strcasecmp(ptr, "none") == 0) {
      none = TRUE;
    }
  }

  if (!none) {
    int res;

    pre = pr_regexp_alloc(&core_module);
  
    res = pr_regexp_compile(pre, ptr, REG_EXTENDED|REG_NOSUB);
    if (res != 0) {
      char errstr[200] = {'\0'};

      pr_regexp_error(res, pre, errstr, sizeof(errstr));
      pr_regexp_free(NULL, pre);

      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", ptr,
        "' failed regex compilation: ", errstr, NULL));
    }
  }

  /* If the directive was used with 3 arguments, then the optional
   * classifiers, and classifier expression, were used.  Make sure that
   * a valid classifier was used.
   */
  if (cmd->argc-1 == 3) {
    if (strncmp(cmd->argv[2], "user", 5) == 0 ||
        strncmp(cmd->argv[2], "group", 6) == 0 ||
        strncmp(cmd->argv[2], "class", 6) == 0) {

      /* no-op */

    } else {
      return PR_ERROR_MSG(cmd, NULL, pstrcat(cmd->tmp_pool, cmd->argv[0],
        "unknown classifier used: '", cmd->argv[2], "'", NULL));
    }
  }

  if (cmd->argc-1 == 1) {
    c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(pr_regex_t *));
    *((pr_regex_t **) c->argv[0]) = pre;
    c->argv[1] = pcalloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) c->argv[1]) = negated;
    c->argv[2] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[2]) = precedence;

  } else if (cmd->argc-1 == 3) {
    array_header *acl = NULL;
    unsigned int argc = cmd->argc - 3;
    void **argv;

    argv = &(cmd->argv[2]);

    acl = pr_expr_create(cmd->tmp_pool, &argc, (char **) argv);
    if (acl == NULL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error creating expression: ",
        strerror(errno), NULL));
    }

    c = add_config_param(cmd->argv[0], 0);
    c->argc = argc + 4;

    /* Add 5 to argc for the argv of the config_rec: one for the
     * regexp, one for the 'negated' value, one for the precedence,
     * one for the classifier, and one for the terminating NULL
     */
    c->argv = pcalloc(c->pool, ((argc + 5) * sizeof(void *)));

    /* Capture the config_rec's argv pointer for doing the by-hand
     * population.
     */
    argv = c->argv;

    /* Copy in the regexp. */
    *argv = pcalloc(c->pool, sizeof(pr_regex_t *));
    *((pr_regex_t **) *argv++) = pre;

    /* Copy in the 'negated' flag */
    *argv = pcalloc(c->pool, sizeof(unsigned char));
    *((unsigned char *) *argv++) = negated;

    /* Copy in the precedence. */
    *argv = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) *argv++) = precedence;

    /* Copy in the expression classifier */
    *argv++ = pstrdup(c->pool, cmd->argv[2]);

    /* now, copy in the expression arguments */
    if (argc && acl) {
      while (argc-- > 0) {
        *argv++ = pstrdup(c->pool, *((char **) acl->elts));
        acl->elts = ((char **) acl->elts) + 1;
      }
    }

    /* don't forget the terminating NULL */
    *argv = NULL;
  }

  c->flags |= CF_MERGEDOWN_MULTI;
  return PR_HANDLED(cmd);

#else /* no regular expression support at the moment */
  CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "The HideFiles directive cannot be "
    "used on this system, as you do not have POSIX compliant regex support",
    NULL));
#endif
}

MODRET set_hidenoaccess(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON|CONF_DIR);

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

MODRET set_hideuser(cmd_rec *cmd) {
  config_rec *c = NULL;
  char *user = NULL;
  int inverted = FALSE;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON|CONF_DIR);

  user = cmd->argv[1];
  if (*user == '!') {
    inverted = TRUE;
    user++;
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, user);
  c->argv[1] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = inverted;

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

MODRET set_hidegroup(cmd_rec *cmd) {
  config_rec *c = NULL;
  char *group = NULL;
  int inverted = FALSE;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON|CONF_DIR);

  group = cmd->argv[1];
  if (*group == '!') {
    inverted = TRUE;
    group++;
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, group);
  c->argv[1] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = inverted;

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

MODRET add_groupowner(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON|CONF_DIR|CONF_DYNDIR);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET add_userowner(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON|CONF_DIR);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET set_allowoverride(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;
  unsigned int precedence = 0;

  int ctxt = (cmd->config && cmd->config->config_type != CONF_PARAM ?
     cmd->config->config_type : cmd->server->config_type ?
     cmd->server->config_type : CONF_ROOT);

  /* This directive must have either 1 argument; the 3 arguments format is
   * now deprecated.
   */
  if (cmd->argc-1 == 3) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "Please use mod_ifsession for "
      "per-user/group/class conditional configuration", NULL));
  }

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  /* Set the precedence for this config_rec based on its configuration
   * context.
   */
  if (ctxt & CONF_GLOBAL) {
    precedence = 1;

  /* These will never appear simultaneously */
  } else if (ctxt & CONF_ROOT || ctxt & CONF_VIRTUAL) {
    precedence = 2;

  } else if (ctxt & CONF_ANON) {
    precedence = 3;

  } else if (ctxt & CONF_DIR) {
    precedence = 4;
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;
  c->argv[1] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[1]) = precedence;
  c->flags |= CF_MERGEDOWN_MULTI;

  return PR_HANDLED(cmd);
}

MODRET end_directory(cmd_rec *cmd) {
  int empty_ctxt = FALSE;

  if (cmd->argc > 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_DIR);

  pr_parser_config_ctxt_close(&empty_ctxt);

  if (empty_ctxt) {
    pr_log_debug(DEBUG3, "%s: ignoring empty section", (char *) cmd->argv[0]);
  }

  return PR_HANDLED(cmd);
}

MODRET add_anonymous(cmd_rec *cmd) {
  config_rec *c = NULL;
  char *dir;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  dir = cmd->argv[1];

  if (*dir != '/' && *dir != '~') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "(", dir, ") absolute pathname "
      "required", NULL));
  }

  if (strchr(dir, '*')) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "(", dir, ") wildcards not allowed "
      "in pathname", NULL));
  }

  if (strncmp(dir, "/", 2) == 0) {
    CONF_ERROR(cmd, "'/' not permitted for anonymous root directory");
  }

  if (*(dir+strlen(dir)-1) != '/') {
    dir = pstrcat(cmd->tmp_pool, dir, "/", NULL);
  }

  if (dir == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, cmd->argv[1], ": ",
      strerror(errno), NULL));
  }

  c = pr_parser_config_ctxt_open(dir);

  c->config_type = CONF_ANON;
  return PR_HANDLED(cmd);
}

MODRET end_anonymous(cmd_rec *cmd) {
  int empty_ctxt = FALSE;

  if (cmd->argc > 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ANON);

  pr_parser_config_ctxt_close(&empty_ctxt);

  if (empty_ctxt) {
    pr_log_debug(DEBUG3, "%s: ignoring empty section", (char *) cmd->argv[0]);
  }

  return PR_HANDLED(cmd);
}

MODRET add_class(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_class_open(main_server->pool, cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error creating <Class ",
      cmd->argv[1], ">: ", strerror(errno), NULL));
  }

  return PR_HANDLED(cmd);
}

MODRET end_class(cmd_rec *cmd) {
  if (cmd->argc > 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_CLASS);

  if (pr_class_close() < 0) {
    pr_log_pri(PR_LOG_WARNING, "warning: empty <Class> definition");
  }

  return PR_HANDLED(cmd);
}

MODRET add_global(cmd_rec *cmd) {
  config_rec *c = NULL;

  if (cmd->argc-1 != 0) {
    CONF_ERROR(cmd, "Too many parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  c = pr_parser_config_ctxt_open(cmd->argv[0]);
  c->config_type = CONF_GLOBAL;

  return PR_HANDLED(cmd);
}

MODRET end_global(cmd_rec *cmd) {
  int empty_ctxt = FALSE;

  if (cmd->argc > 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_GLOBAL);

  pr_parser_config_ctxt_close(&empty_ctxt);

  if (empty_ctxt) {
    pr_log_debug(DEBUG3, "%s: ignoring empty section", (char *) cmd->argv[0]);
  }

  return PR_HANDLED(cmd);
}

MODRET add_limit(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c = NULL;
  int cargc, have_cdup = FALSE, have_xcup = FALSE, have_mkd = FALSE,
    have_xmkd = FALSE, have_pwd = FALSE, have_xpwd = FALSE, have_rmd = FALSE,
    have_xrmd = FALSE;
  void **cargv, **elts;
  array_header *list;

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "directive requires one or more commands");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_DIR|CONF_ANON|CONF_DYNDIR|CONF_GLOBAL);

  c = pr_parser_config_ctxt_open("Limit");
  c->config_type = CONF_LIMIT;
  cargc = cmd->argc;
  cargv = cmd->argv;

  list = make_array(c->pool, c->argc + 1, sizeof(void *));

  while (cargc-- && *(++cargv)) {
    char *ent = NULL, *str;

    str = pstrdup(cmd->tmp_pool, *((char **) cargv));
    while ((ent = pr_str_get_token(&str, ",")) != NULL) {
      pr_signals_handle();

      if (*ent) {
        *((char **) push_array(list)) = pstrdup(c->pool, ent);
      }
    }
  }

  /* Now iterate though the list, looking for the following commands:
   *
   *  CDUP/XCUP
   *  MKD/XMKD
   *  PWD/XPWD
   *  RMD/XRMD
   *
   * If we see one of these without its counterpart, automatically add
   * the counterpart (see Bug#3077).
   */

  elts = list->elts;
  for (i = 0; i < list->nelts; i++) {
    if (strcasecmp(elts[i], C_CDUP) == 0) {
      have_cdup = TRUE;

    } else if (strcasecmp(elts[i], C_XCUP) == 0) {
      have_xcup = TRUE; 

    } else if (strcasecmp(elts[i], C_MKD) == 0) {
      have_mkd = TRUE;

    } else if (strcasecmp(elts[i], C_XMKD) == 0) {
      have_xmkd = TRUE;

    } else if (strcasecmp(elts[i], C_PWD) == 0) {
      have_pwd = TRUE;

    } else if (strcasecmp(elts[i], C_XPWD) == 0) {
      have_xpwd = TRUE;

    } else if (strcasecmp(elts[i], C_RMD) == 0) {
      have_rmd = TRUE;

    } else if (strcasecmp(elts[i], C_XRMD) == 0) {
      have_xrmd = TRUE;
    }
  }

  if (have_cdup && !have_xcup) {
    *((char **) push_array(list)) = pstrdup(c->pool, C_XCUP);
  }

  if (!have_cdup && have_xcup) {
    *((char **) push_array(list)) = pstrdup(c->pool, C_CDUP);
  }

  if (have_mkd && !have_xmkd) {
    *((char **) push_array(list)) = pstrdup(c->pool, C_XMKD);
  }

  if (!have_mkd && have_xmkd) {
    *((char **) push_array(list)) = pstrdup(c->pool, C_MKD);
  }

  if (have_pwd && !have_xpwd) {
    *((char **) push_array(list)) = pstrdup(c->pool, C_XPWD);
  }

  if (!have_pwd && have_xpwd) {
    *((char **) push_array(list)) = pstrdup(c->pool, C_PWD);
  }

  if (have_rmd && !have_xrmd) {
    *((char **) push_array(list)) = pstrdup(c->pool, C_XRMD);
  }

  if (!have_rmd && have_xrmd) {
    *((char **) push_array(list)) = pstrdup(c->pool, C_RMD);
  }

  c->argc = list->nelts;
  c->argv = list->elts;

  return PR_HANDLED(cmd);
}

MODRET set_order(cmd_rec *cmd) {
  int order = -1;
  char *arg = "";
  config_rec *c = NULL;

  if (cmd->argc != 2 &&
      cmd->argc != 3) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }
  CHECK_CONF(cmd, CONF_LIMIT);

  if (cmd->argc == 2) {
    arg = cmd->argv[1];

  } else {
    /* Concatenate our parameters. */
    arg = pstrcat(cmd->tmp_pool, arg, (char *) cmd->argv[1],
      (char *) cmd->argv[2], NULL);
  }

  if (strcasecmp(arg, "allow,deny") == 0) {
    order = ORDER_ALLOWDENY;

  } else if (strcasecmp(arg, "deny,allow") == 0) {
    order = ORDER_DENYALLOW;

  } else {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", arg, "': invalid argument",
      NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = order;

  return PR_HANDLED(cmd);
}

MODRET set_allowdenyusergroupclass(cmd_rec *cmd) {
  config_rec *c;
  void **argv;
  unsigned int argc;
  int eval_type;
  array_header *acl = NULL;
 
  CHECK_CONF(cmd, CONF_LIMIT);

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  /* For AllowClass/DenyClass and AllowUser/DenyUser, the default expression
   * type is "or".
   */
  if (strncmp(cmd->argv[0], "AllowClass", 11) == 0 ||
      strncmp(cmd->argv[0], "AllowUser", 10) == 0 ||
      strncmp(cmd->argv[0], "DenyClass", 10) == 0 ||
      strncmp(cmd->argv[0], "DenyUser", 9) == 0) {
    eval_type = PR_EXPR_EVAL_OR;

  /* For AllowGroup and DenyGroup, the default expression type is "and". */
  } else {
    eval_type = PR_EXPR_EVAL_AND;
  }

  if (cmd->argc > 2) {
    /* Check the first parameter to see if it is an evaluation modifier:
     * "and", "or", or "regex".
     */
    if (strcasecmp(cmd->argv[1], "AND") == 0) {
      eval_type = PR_EXPR_EVAL_AND;
      argc = cmd->argc-2;
      argv = cmd->argv;

    } else if (strcasecmp(cmd->argv[1], "OR") == 0) {
      eval_type = PR_EXPR_EVAL_OR;
      argc = cmd->argc-2;
      argv = cmd->argv+1;

    } else if (strcasecmp(cmd->argv[1], "regex") == 0) {
#ifdef PR_USE_REGEX
      pr_regex_t *pre;
      int res;

      if (cmd->argc != 3) {
        CONF_ERROR(cmd, "wrong number of parameters");
      }

      pre = pr_regexp_alloc(&core_module);

      res = pr_regexp_compile_posix(pre, cmd->argv[2], REG_EXTENDED|REG_NOSUB);
      if (res != 0) {
        char errstr[200] = {'\0'};

        pr_regexp_error(res, pre, errstr, sizeof(errstr));
        pr_regexp_free(NULL, pre);

        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", (char *) cmd->argv[2],
          "' failed regex compilation: ", errstr, NULL));
      }

      c = add_config_param(cmd->argv[0], 2, NULL, NULL);
      c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
      *((unsigned char *) c->argv[0]) = PR_EXPR_EVAL_REGEX;
      c->argv[1] = (void *) pre;
      c->flags |= CF_MERGEDOWN_MULTI;

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
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error creating expression: ",
      strerror(errno), NULL));
  }

  c = add_config_param(cmd->argv[0], 0);

  c->argc = acl->nelts + 1;
  c->argv = pcalloc(c->pool, (c->argc + 1) * sizeof(void *));

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = eval_type;

  argv = &(c->argv[1]);

  while (acl->nelts-- > 0) {
    pr_signals_handle();

    *argv++ = pstrdup(c->pool, *((char **) acl->elts));
    acl->elts = ((char **) acl->elts) + 1;
  }

  *argv = NULL;

  c->flags |= CF_MERGEDOWN_MULTI;
  return PR_HANDLED(cmd);
}

MODRET set_allowdeny(cmd_rec *cmd) {
  int argc;
  void **argv;
  pr_netacl_t **aclargv;
  array_header *list;
  config_rec *c;

  CHECK_CONF(cmd, CONF_LIMIT);

  /* Syntax: allow [from] [all|none]|host|network[,...] */
  list = make_array(cmd->tmp_pool, cmd->argc, sizeof(pr_netacl_t *));
  argc = cmd->argc-1;
  argv = cmd->argv;

  c = add_config_param(cmd->argv[0], 0);

  /* Skip optional "from" keyword. The '!' character is allowed in front of a
   * hostmask or IP, but NOT in front of "ALL" or "NONE".
   */

  while (argc && *(argv+1)) {
    if (strcasecmp("from", *(((char **) argv) + 1)) == 0) {
      argv++;
      argc--;
      continue;

    } else if (strcasecmp("!all", *(((char **) argv) + 1)) == 0 ||
               strcasecmp("!none", *(((char **) argv) + 1)) == 0) {
      CONF_ERROR(cmd, "the ! negation operator cannot be used with ALL/NONE");

    } else if (strcasecmp("all", *(argv+1)) == 0 ||
               strcasecmp("none", *(argv+1)) == 0) {
      *((pr_netacl_t **) push_array(list)) =
        pr_netacl_create(c->pool, *(argv+1));
      argc = 0;
    }

    break;
  }

  /* Parse any other/remaining rules. */
  while (argc-- && *(++argv)) {
    char *ent = NULL;
    char *s = pstrdup(cmd->tmp_pool, *argv);

    /* Parse the string into comma-delimited entries */
    while ((ent = pr_str_get_token(&s, ",")) != NULL) {
      if (*ent) {
        pr_netacl_t *acl;

        if (strcasecmp(ent, "all") == 0 ||
            strcasecmp(ent, "none") == 0) {
          list->nelts = 0;
          argc = 0;
          break;
        }

        acl = pr_netacl_create(c->pool, ent);
        if (acl == NULL) {
          CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad ACL definition '",
            ent, "': ", strerror(errno), NULL));     
        }

        pr_trace_msg("netacl", 9, "'%s' parsed into netacl '%s'", ent,
          pr_netacl_get_str(cmd->tmp_pool, acl));

        *((pr_netacl_t **) push_array(list)) = acl;
      }
    }
  }

  if (!list->nelts)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "syntax: ", cmd->argv[0],
      " [from] [all|none]|host|network[,...]", NULL));

  c->argc = list->nelts;
  c->argv = pcalloc(c->pool, (c->argc+1) * sizeof(pr_netacl_t *));
  aclargv = (pr_netacl_t **) c->argv;

  while (list->nelts--) {
    *aclargv++ = *((pr_netacl_t **) list->elts);
    list->elts = ((pr_netacl_t **) list->elts) + 1;
  }
  *aclargv = NULL;

  return PR_HANDLED(cmd);
}

MODRET set_denyall(cmd_rec *cmd) {
  config_rec *c = NULL;

  if (cmd->argc > 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_LIMIT|CONF_ANON|CONF_DIR|CONF_DYNDIR);

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = TRUE;

  return PR_HANDLED(cmd);
}

MODRET set_allowall(cmd_rec *cmd) {
  config_rec *c = NULL;

  if (cmd->argc > 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_LIMIT|CONF_ANON|CONF_DIR|CONF_DYNDIR);

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = TRUE;

  return PR_HANDLED(cmd);
}

MODRET set_authorder(cmd_rec *cmd) {
  register unsigned int i = 0;
  config_rec *c = NULL;
  array_header *module_list = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* Check to see if the directive has already been set */
  if (find_config(cmd->server->conf, CONF_PARAM, cmd->argv[0], FALSE)) {
    CONF_ERROR(cmd, "AuthOrder has already been configured");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  module_list = make_array(c->pool, 0, sizeof(char *));

  for (i = 1; i < cmd->argc; i++) {
    *((char **) push_array(module_list)) = pstrdup(c->pool, cmd->argv[i]);
  }
  c->argv[0] = (void *) module_list;

  return PR_HANDLED(cmd);
}

MODRET end_limit(cmd_rec *cmd) {
  int empty_ctxt = FALSE;

  if (cmd->argc > 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_LIMIT);

  pr_parser_config_ctxt_close(&empty_ctxt);

  if (empty_ctxt) {
    pr_log_debug(DEBUG3, "%s: ignoring empty section", (char *) cmd->argv[0]);
  }

  return PR_HANDLED(cmd);
}

MODRET set_ignorehidden(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_LIMIT);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: DisplayChdir path [on|off] */
MODRET set_displaychdir(cmd_rec *cmd) {
  config_rec *c = NULL;
  int bool = FALSE;

  if (cmd->argc-1 < 1 ||
      cmd->argc-1 > 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR);

  if (cmd->argc-1 == 2) {
    bool = get_boolean(cmd, 2);
    if (bool < 0) {
      CONF_ERROR(cmd, "expected Boolean parameter");
    }
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, cmd->argv[1]);
  c->argv[1] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = bool;

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

MODRET set_displayconnect(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

MODRET set_displayquit(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET add_virtualhost(cmd_rec *cmd) {
  const char *name, *addr_ipstr;
  server_rec *s = NULL;
  const pr_netaddr_t *addr = NULL;
  array_header *addrs = NULL;
  unsigned int addr_flags = PR_NETADDR_GET_ADDR_FL_INCL_DEVICE;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }
  CHECK_CONF(cmd, CONF_ROOT);

  name = cmd->argv[1];
  s = pr_parser_server_ctxt_open(name);
  if (s == NULL) {
    CONF_ERROR(cmd, "unable to create virtual server configuration");
  }

  /* It's possible for a server to have multiple IP addresses (e.g. a DNS
   * name that has both A and AAAA records).  We need to handle that case
   * here by looking up all of a server's addresses, and making sure there
   * are server_recs for each one.
   */

  addr = pr_netaddr_get_addr2(cmd->tmp_pool, name, &addrs, addr_flags);
  if (addr == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error resolving '", name, "': ",
      strerror(errno), NULL));
  }

  /* If the given name is a DNS name, automatically add a ServerAlias
   * directive.
   */
  if (pr_netaddr_is_v4(name) == FALSE &&
      pr_netaddr_is_v6(name) == FALSE) {
    add_config_param_str("ServerAlias", 1, name);
  }

  addr_ipstr = pr_netaddr_get_ipstr(addr);

  if (addrs != NULL) {
    register unsigned int i;
    pr_netaddr_t **elts = addrs->elts;

    /* For every additional address, implicitly add a bind record. */
    for (i = 0; i < addrs->nelts; i++) {
      const char *ipstr;

      ipstr = pr_netaddr_get_ipstr(elts[i]);

      /* Skip duplicate addresses. */
      if (strcmp(addr_ipstr, ipstr) == 0) {
        continue;
      }

      add_config_param_str("_bind_", 1, ipstr);
    }
  }

  /* Handle multiple addresses in a <VirtualHost> directive.  We do
   * this by adding bind directives to the server_rec created for the
   * first address.
   */
  if (cmd->argc-1 > 1) {
    register unsigned int i;

    for (i = 2; i < cmd->argc; i++) {
      addrs = NULL;

      name = cmd->argv[i];
      addr = pr_netaddr_get_addr2(cmd->tmp_pool, name, &addrs, addr_flags);
      if (addr == NULL) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error resolving '", name, "': ",
          strerror(errno), NULL));
      }

      /* If the given name is a DNS name, automatically add a ServerAlias
       * directive.
       */
      if (pr_netaddr_is_v4(name) == FALSE &&
          pr_netaddr_is_v6(name) == FALSE) {
        add_config_param_str("ServerAlias", 1, name);
      }

      addr_ipstr = pr_netaddr_get_ipstr(addr);
      add_config_param_str("_bind_", 1, addr_ipstr);

      if (addrs != NULL) {
        register unsigned int j;
        pr_netaddr_t **elts = addrs->elts;

        /* For every additional address, implicitly add a bind record. */
        for (j = 0; j < addrs->nelts; j++) {
          const char *ipstr;

          ipstr = pr_netaddr_get_ipstr(elts[j]);

          /* Skip duplicate addresses. */
          if (strcmp(addr_ipstr, ipstr) == 0) {
            continue;
          }

          add_config_param_str("_bind_", 1, ipstr);
        }
      }
    }
  }

  return PR_HANDLED(cmd);
}

MODRET end_virtualhost(cmd_rec *cmd) {
  server_rec *s = NULL, *next_s = NULL;
  const pr_netaddr_t *addr = NULL;
  const char *address = NULL;
  unsigned int addr_flags = PR_NETADDR_GET_ADDR_FL_INCL_DEVICE;

  if (cmd->argc > 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_VIRTUAL);

  if (cmd->server->ServerAddress) {
    address = cmd->server->ServerAddress;

  } else {
    address = pr_netaddr_get_localaddr_str(cmd->tmp_pool);
  }

  /* Any additional addresses associated with the configured address have
   * already been handled, so we can ignore them here.
   */
  addr = pr_netaddr_get_addr2(cmd->tmp_pool, address, NULL, addr_flags);
  if (addr == NULL) {
    /* This bad server context will be removed in fixup_servers(), after
     * the parsing has completed, so we need do nothing else here.
     */
    pr_log_pri(PR_LOG_WARNING,
      "warning: unable to determine IP address of '%s'", address);
  }

  if (AddressCollisionCheck) {
    /* Check if this server's address/port combination is already being used. */
    for (s = (server_rec *) server_list->xas_list; addr && s; s = next_s) {
      next_s = s->next;

      /* Have to resort to duplicating some of fixup_servers()'s functionality
       * here, to do this check The Right Way(tm).
       */
      if (s != cmd->server) {
        const char *serv_addrstr = NULL;
        const pr_netaddr_t *serv_addr = NULL;

        if (s->addr) {
          serv_addr = s->addr;

        } else {
          serv_addrstr = s->ServerAddress ? s->ServerAddress :
            pr_netaddr_get_localaddr_str(cmd->tmp_pool);

          serv_addr = pr_netaddr_get_addr2(cmd->tmp_pool, serv_addrstr, NULL,
            addr_flags);
        }

        if (serv_addr == NULL) {
          pr_log_pri(PR_LOG_WARNING,
            "warning: unable to determine IP address of '%s'", serv_addrstr);

        } else if (pr_netaddr_cmp(addr, serv_addr) == 0 &&
            cmd->server->ServerPort == s->ServerPort) {
          config_rec *c;

          /* If this server has a ServerAlias, it means it's a named vhost and
           * can be used for name-based virtual hosting.  Which, in turn, means
           * that this collision is expected, even wanted.
           */
          c = find_config(cmd->server->conf, CONF_PARAM, "ServerAlias", FALSE);
          if (c == NULL) {
            pr_log_pri(PR_LOG_WARNING,
              "warning: \"%s\" address/port (%s:%d) already in use by \"%s\"",
              cmd->server->ServerName ? cmd->server->ServerName : "ProFTPD",
              pr_netaddr_get_ipstr(addr), cmd->server->ServerPort,
              s->ServerName ? s->ServerName : "ProFTPD");

            if (xaset_remove(server_list, (xasetmember_t *) cmd->server) == 1) {
              destroy_pool(cmd->server->pool);
            }
          }
        }

        continue;
      }
    }
  }

  if (pr_parser_server_ctxt_close() == NULL) {
    CONF_ERROR(cmd, "must have matching <VirtualHost> directive");
  }

  return PR_HANDLED(cmd);
}

#ifdef PR_USE_REGEX
MODRET regex_filters(cmd_rec *cmd) {
  pr_regex_t *allow_regex = NULL, *deny_regex = NULL;

  /* Don't apply the filter checks to passwords (arguments to the PASS
   * command).
   */
  if (strcasecmp(cmd->argv[0], C_PASS) == 0) {
    return PR_DECLINED(cmd);
  }

  /* Check for an AllowFilter */
  allow_regex = get_param_ptr(CURRENT_CONF, "AllowFilter", FALSE);
  if (allow_regex != NULL &&
      cmd->arg != NULL &&
      pr_regexp_exec(allow_regex, cmd->arg, 0, NULL, 0, 0, 0) != 0) {
    pr_log_debug(DEBUG2, "'%s %s' denied by AllowFilter", (char *) cmd->argv[0],
      cmd->arg);
    pr_response_add_err(R_550, _("%s: Forbidden command argument"), cmd->arg);

    pr_cmd_set_errno(cmd, EACCES);
    errno = EACCES;
    return PR_ERROR(cmd);
  }

  /* Check for a DenyFilter */
  deny_regex = get_param_ptr(CURRENT_CONF, "DenyFilter", FALSE);
  if (deny_regex != NULL &&
      cmd->arg != NULL &&
      pr_regexp_exec(deny_regex, cmd->arg, 0, NULL, 0, 0, 0) == 0) {
    pr_log_debug(DEBUG2, "'%s %s' denied by DenyFilter", (char *) cmd->argv[0],
      cmd->arg);
    pr_response_add_err(R_550, _("%s: Forbidden command argument"), cmd->arg);

    pr_cmd_set_errno(cmd, EACCES);
    errno = EACCES;
    return PR_ERROR(cmd);
  }

  return PR_DECLINED(cmd);
}
#endif /* regex support */

MODRET core_pre_any(cmd_rec *cmd) {
  unsigned long cmd_delay = 0;
  const char *rnfr_path = NULL;

  /* Check for an exceeded MaxCommandRate. */
  cmd_delay = core_exceeded_cmd_rate(cmd);
  if (cmd_delay > 0) {
    struct timeval tv;

    pr_event_generate("core.max-command-rate", NULL);

    pr_log_pri(PR_LOG_NOTICE,
      "MaxCommandRate (%lu cmds/%u %s) exceeded, injecting processing delay "
      "of %lu ms", core_max_cmds, core_max_cmd_interval,
      core_max_cmd_interval == 1 ? "sec" : "secs", cmd_delay);

    pr_trace_msg("command", 8, "MaxCommandRate exceeded, delaying for %lu ms",
      cmd_delay);

    tv.tv_sec = (cmd_delay / 1000);
    tv.tv_usec = (cmd_delay - (tv.tv_sec * 1000)) * 1000;

    pr_signals_block();
    (void) select(0, NULL, NULL, NULL, &tv);
    pr_signals_unblock();
  }

  /* Make sure that any command immediately following an RNFR command which
   * is NOT the RNTO command is rejected (see Bug#3829).
   *
   * Make exception for the following commands:
   *
   *  HELP
   *  NOOP
   *  QUIT
   *  STAT
   *
   *  and RFC 2228 commands.
   */
  rnfr_path = pr_table_get(session.notes, "mod_core.rnfr-path", NULL);
  if (rnfr_path != NULL) {
    if (pr_cmd_cmp(cmd, PR_CMD_RNTO_ID) != 0 &&
        pr_cmd_cmp(cmd, PR_CMD_HELP_ID) != 0 &&
        pr_cmd_cmp(cmd, PR_CMD_NOOP_ID) != 0 &&
        pr_cmd_cmp(cmd, PR_CMD_QUIT_ID) != 0 &&
        pr_cmd_cmp(cmd, PR_CMD_STAT_ID) != 0) {
      int reject_cmd = TRUE;

      /* Perform additional checks if an RFC 2228 auth mechanism (TLS, GSSAPI)
       * has been negotiated/used.
       */
      if (session.rfc2228_mech != NULL) {
        if (pr_cmd_cmp(cmd, PR_CMD_CCC_ID) == 0 ||
            pr_cmd_cmp(cmd, PR_CMD_CONF_ID) == 0 ||
            pr_cmd_cmp(cmd, PR_CMD_ENC_ID) == 0 ||
            pr_cmd_cmp(cmd, PR_CMD_MIC_ID) == 0 ||
            pr_cmd_cmp(cmd, PR_CMD_PBSZ_ID) == 0 ||
            pr_cmd_cmp(cmd, PR_CMD_PROT_ID) == 0) {
          reject_cmd = FALSE;
        }
      }

      if (reject_cmd) {
        pr_log_debug(DEBUG3,
          "RNFR followed immediately by %s rather than RNTO, rejecting command",
          (char *) cmd->argv[0]);
        pr_response_add_err(R_501, _("Bad sequence of commands"));

        pr_cmd_set_errno(cmd, EPERM);
        errno = EPERM;
        return PR_ERROR(cmd);
      }
    }
  }

  return PR_DECLINED(cmd);
}

MODRET core_quit(cmd_rec *cmd) {
  int flags = PR_DISPLAY_FL_SEND_NOW;

  if (displayquit_fh) {
    if (pr_display_fh(displayquit_fh, NULL, R_221, flags) < 0) {
      pr_log_debug(DEBUG6, "unable to display DisplayQuit file '%s': %s",
        displayquit_fh->fh_path, strerror(errno));
    }

    pr_fsio_close(displayquit_fh);
    displayquit_fh = NULL;

  } else {
    char *display;

    display = get_param_ptr(TOPLEVEL_CONF, "DisplayQuit", FALSE);
    if (display) {
      if (pr_display_file(display, NULL, R_221, flags) < 0) {
        int xerrno = errno;

        pr_log_debug(DEBUG6, "unable to display DisplayQuit file '%s': %s",
          display, strerror(xerrno));

        if (xerrno == ENOENT) {
          /* No file found?  Send our normal fairwell, then. */
          pr_response_send(R_221, "%s", _("Goodbye."));
        }
      }

    } else {
      pr_response_send(R_221, "%s", _("Goodbye."));
    }
  }

  /* The LOG_CMD handler for QUIT is responsible for actually ending
   * the session.
   */

  return PR_HANDLED(cmd);
}

MODRET core_log_quit(cmd_rec *cmd) {

#ifndef PR_DEVEL_NO_DAEMON
  pr_session_disconnect(&core_module, PR_SESS_DISCONNECT_CLIENT_QUIT, NULL);
#endif /* PR_DEVEL_NO_DAEMON */

  /* Even though pr_session_end() does not return, this is necessary to avoid
   * compiler warnings.
   */
  return PR_HANDLED(cmd);
}

MODRET core_pwd(cmd_rec *cmd) {
  CHECK_CMD_ARGS(cmd, 1);

  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, session.vwd, NULL)) {
    int xerrno = EACCES;

    pr_response_add_err(R_550, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  pr_response_add(R_257, _("\"%s\" is the current directory"),
    quote_dir(cmd->tmp_pool, pr_fs_encode_path(cmd->tmp_pool, session.vwd)));

  return PR_HANDLED(cmd);
}

MODRET core_pasv(cmd_rec *cmd) {
  unsigned int port = 0;
  char *addrstr = NULL, *tmp = NULL;
  config_rec *c = NULL;
  const pr_netaddr_t *bind_addr;
  const char *proto;

  if (session.sf_flags & SF_EPSV_ALL) {
    pr_response_add_err(R_500, _("Illegal PASV command, EPSV ALL in effect"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  CHECK_CMD_ARGS(cmd, 1);

  /* Returning 501 is the best we can do.  It would be nicer if RFC959 allowed
   * 550 as a possible response.
   */
  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, session.cwd, NULL)) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG8, "PASV denied by <Limit> configuration");
    pr_response_add_err(R_501, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* If we already have a passive listen data connection open, kill it. */
  if (session.d) {
    pr_inet_close(session.d->pool, session.d);
    session.d = NULL;
  }

  if (pr_netaddr_get_family(session.c->local_addr) == pr_netaddr_get_family(session.c->remote_addr)) {

#ifdef PR_USE_IPV6
    if (pr_netaddr_use_ipv6()) {
      /* Make sure that the family is NOT IPv6, even though the family of the
       * local and remote ends match.  The PASV command cannot be used for
       * IPv6 addresses (Bug#3745).
       *
       * However, SOME clients and ALGs ARE able to properly handle the
       * PASV response, even for an IPv6 address.  So we relax this code
       * to merely warn about possible incompatibilities, rather than
       * rejecting the command outright.
       */
      if (pr_netaddr_get_family(session.c->local_addr) == AF_INET6) {
        pr_log_pri(PR_LOG_INFO,
          "sending a PASV response for an IPv6 address '%s'; some FTP clients "
          "may have interoperability issues with this response",
          pr_netaddr_get_ipstr(session.c->local_addr));
        pr_log_pri(PR_LOG_INFO, "%s", "please configure your FTP client "
          "to use the IPv6-compatible EPSV/EPRT commands");
      }
    }
#endif /* PR_USE_IPV6 */

    bind_addr = session.c->local_addr;

  } else {
    /* In this scenario, the server has an IPv6 socket, but the remote client
     * is an IPv4 (or IPv4-mapped IPv6) peer.
     */
    bind_addr = pr_netaddr_v6tov4(cmd->pool, session.c->local_addr);
  }

  c = find_config(main_server->conf, CONF_PARAM, "PassivePorts", FALSE);
  if (c != NULL) {
    int pasv_min_port = *((int *) c->argv[0]);
    int pasv_max_port = *((int *) c->argv[1]);

    session.d = pr_inet_create_conn_portrange(session.pool, bind_addr,
      pasv_min_port, pasv_max_port);
    if (session.d == NULL) {
      /* If not able to open a passive port in the given range, default to
       * normal behavior (using INPORT_ANY), and log the failure.  This
       * indicates a too-small range configuration.
       */
      pr_log_pri(PR_LOG_WARNING,
        "unable to find open port in PassivePorts range %d-%d: "
        "defaulting to INPORT_ANY (consider defining a larger PassivePorts "
        "range)", pasv_min_port, pasv_max_port);
    }
  }

  /* Open up the connection and pass it back. */
  if (session.d == NULL) {
    session.d = pr_inet_create_conn(session.pool, -1, bind_addr, INPORT_ANY,
      FALSE);
  }

  if (session.d == NULL) {
    pr_response_add_err(R_425,
      _("Unable to build data connection: Internal error"));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  /* Make sure that necessary socket options are set on the socket prior
   * to the call to listen(2).
   */
  pr_inet_set_proto_opts(session.pool, session.d, main_server->tcp_mss_len, 0,
    IPTOS_THROUGHPUT, 1);
  pr_inet_generate_socket_event("core.data-listen", main_server,
    session.d->local_addr, session.d->listen_fd);

  pr_inet_set_block(session.pool, session.d);
  if (pr_inet_listen(session.pool, session.d, 1, 0) < 0) {
    int xerrno = errno;

    pr_response_add_err(R_425, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  session.d->instrm = pr_netio_open(session.pool, PR_NETIO_STRM_DATA,
    session.d->listen_fd, PR_NETIO_IO_RD);

  /* Now tell the client our address/port */
  port = session.data_port = session.d->local_port;
  session.sf_flags |= SF_PASSIVE;

  addrstr = (char *) pr_netaddr_get_ipstr(session.d->local_addr);

  /* Check for a MasqueradeAddress configuration record, and return that
   * addr if appropriate.  Note that if TLSMasqueradeAddress is configured AND
   * this is an FTPS session, TLSMasqueradeAddress will take precedence;
   * see Bug#3862.
   */
  proto = pr_session_get_protocol(0);
  if (strncmp(proto, "ftps", 5) == 0) {
    c = find_config(main_server->conf, CONF_PARAM, "TLSMasqueradeAddress",
      FALSE);
    if (c != NULL) {
      addrstr = (char *) pr_netaddr_get_ipstr(c->argv[0]);

    } else {
      c = find_config(main_server->conf, CONF_PARAM, "MasqueradeAddress",
        FALSE);
      if (c != NULL) {
        if (c->argv[0] != NULL) {
          addrstr = (char *) pr_netaddr_get_ipstr(c->argv[0]);
        }
      }
    }

  } else {
    c = find_config(main_server->conf, CONF_PARAM, "MasqueradeAddress", FALSE);
    if (c != NULL) {
      if (c->argv[0] != NULL) {
        addrstr = (char *) pr_netaddr_get_ipstr(c->argv[0]);
      }
    }
  }

  /* Fixup the address string for the PASV response. */
  tmp = strrchr(addrstr, ':');
  if (tmp) {
    addrstr = tmp + 1;
  }

  for (tmp = addrstr; *tmp; tmp++) {
    if (*tmp == '.') {
      *tmp = ',';
    }
  }

  pr_log_debug(DEBUG1, "Entering Passive Mode (%s,%u,%u).", addrstr,
    (port >> 8) & 255, port & 255);

  /* Note: this response is specifically NOT localised because clients
   * assume this particular text.  Nice, huh?
   */
  pr_response_add(R_227, "Entering Passive Mode (%s,%u,%u).", addrstr,
    (port >> 8) & 255, port & 255);
 
  return PR_HANDLED(cmd);
}

MODRET core_port(cmd_rec *cmd) {
  const pr_netaddr_t *listen_addr = NULL, *port_addr = NULL;
  char *port_info;
#ifdef PR_USE_IPV6
  char buf[INET6_ADDRSTRLEN] = {'\0'};
#else
  char buf[INET_ADDRSTRLEN] = {'\0'};
#endif /* PR_USE_IPV6 */
  unsigned int h1, h2, h3, h4, p1, p2;
  unsigned short port;
  int allow_foreign_addr = FALSE, *root_revoke = NULL;
  config_rec *c;
  const char *proto;

  if (session.sf_flags & SF_EPSV_ALL) {
    pr_response_add_err(R_500, _("Illegal PORT command, EPSV ALL in effect"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  CHECK_CMD_ARGS(cmd, 2);

  /* Returning 501 is the best we can do.  It would be nicer if RFC959 allowed
   * 550 as a possible response.
   */
  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, session.cwd, NULL)) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG8, "PORT denied by <Limit> configuration");
    pr_response_add_err(R_501, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* Block active transfers (the PORT command) if RootRevoke is in effect
   * and the server's port is below 1024 (binding to the data port in this
   * case would require root privs, which will have been dropped).
   *
   * A RootRevoke value of 0 indicates 'false', 1 indicates 'true', and
   * 2 indicates 'NonCompliantActiveTransfer'.  We only block active transfers
   * for a RootRevoke value of 1.
   */
  root_revoke = get_param_ptr(TOPLEVEL_CONF, "RootRevoke", FALSE);
  if (root_revoke != NULL &&
      *root_revoke == 1 &&
      session.c->local_port < 1024) {
    pr_log_debug(DEBUG0, "RootRevoke in effect, unable to bind to local "
      "port %d for active transfer", session.c->local_port-1);
    pr_response_add_err(R_500, _("Unable to service PORT commands"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* Format is h1,h2,h3,h4,p1,p2 (ASCII in network order) */
  port_info = cmd->argv[1];
  if (sscanf(port_info, "%u,%u,%u,%u,%u,%u", &h1, &h2, &h3, &h4, &p1,
      &p2) != 6) {
    pr_log_debug(DEBUG2, "PORT '%s' is not syntactically valid", port_info);
    pr_response_add_err(R_501, _("Illegal PORT command"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  if (h1 > 255 || h2 > 255 || h3 > 255 || h4 > 255 || p1 > 255 || p2 > 255 ||
      (h1|h2|h3|h4) == 0 || (p1|p2) == 0) {
    pr_log_debug(DEBUG2, "PORT '%s' has invalid value(s)", cmd->arg);
    pr_response_add_err(R_501, _("Illegal PORT command"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }
  port = ((p1 << 8) | p2);

#ifdef PR_USE_IPV6
  if (pr_netaddr_use_ipv6()) {
    if (pr_netaddr_get_family(session.c->remote_addr) == AF_INET6) {
      pr_snprintf(buf, sizeof(buf), "::ffff:%u.%u.%u.%u", h1, h2, h3, h4);

    } else {
      pr_snprintf(buf, sizeof(buf), "%u.%u.%u.%u", h1, h2, h3, h4);
    }

  } else
#endif /* PR_USE_IPV6 */
  pr_snprintf(buf, sizeof(buf), "%u.%u.%u.%u", h1, h2, h3, h4);
  buf[sizeof(buf)-1] = '\0';

  port_addr = pr_netaddr_get_addr(cmd->tmp_pool, buf, NULL);
  if (port_addr == NULL) {
    pr_log_debug(DEBUG1, "error getting sockaddr for '%s': %s", buf,
      strerror(errno)); 
    pr_response_add_err(R_501, _("Illegal PORT command"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* If we are NOT listening on an RFC1918 address, BUT the client HAS
   * sent us an RFC1918 address in its PORT command (which we know to not be
   * routable), then ignore that address, and use the client's remote address.
   */
  listen_addr = session.c->local_addr;

  proto = pr_session_get_protocol(0);
  if (strncmp(proto, "ftps", 5) == 0) {
    c = find_config(main_server->conf, CONF_PARAM, "TLSMasqueradeAddress",
      FALSE);
    if (c != NULL) {
      listen_addr = c->argv[0];

    } else {
      c = find_config(main_server->conf, CONF_PARAM, "MasqueradeAddress",
        FALSE);
      if (c != NULL) {
        if (c->argv[0] != NULL) {
          listen_addr = c->argv[0];
        }
      }
    }

  } else {
    c = find_config(main_server->conf, CONF_PARAM, "MasqueradeAddress", FALSE);
    if (c != NULL) {
      if (c->argv[0] != NULL) {
        listen_addr = c->argv[0];
      }
    }
  }
 
  if (pr_netaddr_is_rfc1918(listen_addr) != TRUE &&
      pr_netaddr_is_rfc1918(session.c->remote_addr) != TRUE &&
      pr_netaddr_is_rfc1918(port_addr) == TRUE) {
    const char *rfc1918_ipstr;

    rfc1918_ipstr = pr_netaddr_get_ipstr(port_addr);
    port_addr = pr_netaddr_dup(cmd->tmp_pool, session.c->remote_addr);
    pr_log_debug(DEBUG1, "client sent RFC1918 address '%s' in PORT command, "
      "ignoring it and using '%s'", rfc1918_ipstr,
      pr_netaddr_get_ipstr(port_addr));
  }

  pr_netaddr_set_family(&session.data_addr, pr_netaddr_get_family(port_addr));
  pr_netaddr_set_port(&session.data_addr, htons(port));

  /* Make sure that the address specified matches the address from which
   * the control connection is coming.
   */

  c = find_config(TOPLEVEL_CONF, CONF_PARAM, "AllowForeignAddress", FALSE);
  if (c != NULL) {
    int allowed;

    allowed = *((int *) c->argv[0]);
    switch (allowed) {
      case TRUE:
        allow_foreign_addr = TRUE;
        break;

      case FALSE:
        break;

      default: {
        char *class_name;
        const pr_class_t *cls;

        class_name = c->argv[1];
        cls = pr_class_find(class_name);
        if (cls != NULL) {
          if (pr_class_satisfied(cmd->tmp_pool, cls, port_addr) == TRUE) {
            allow_foreign_addr = TRUE;

          } else {
            pr_log_debug(DEBUG8, "<Class> '%s' not satisfied by foreign "
              "address '%s'", class_name, pr_netaddr_get_ipstr(port_addr));
          }

        } else {
          pr_log_debug(DEBUG8, "<Class> '%s' not found for filtering "
            "AllowForeignAddress", class_name);
        }
      }
    }
  }

  if (allow_foreign_addr == FALSE) {
    const pr_netaddr_t *remote_addr = session.c->remote_addr;

#ifdef PR_USE_IPV6
    if (pr_netaddr_use_ipv6()) {
      /* We can only compare the PORT-given address against the remote client
       * address if the remote client address is an IPv4-mapped IPv6 address.
       */
      if (pr_netaddr_get_family(remote_addr) == AF_INET6 &&
          pr_netaddr_is_v4mappedv6(remote_addr) != TRUE) {
        pr_log_pri(PR_LOG_WARNING,
          "Refused PORT %s (IPv4/IPv6 address mismatch)", cmd->arg);
        pr_response_add_err(R_500, _("Illegal PORT command"));

        pr_cmd_set_errno(cmd, EPERM);
        errno = EPERM;
        return PR_ERROR(cmd);
      }
    }
#endif /* PR_USE_IPV6 */

    if (pr_netaddr_cmp(port_addr, remote_addr) != 0) {
      pr_log_pri(PR_LOG_WARNING, "Refused PORT %s (address mismatch)",
        cmd->arg);
      pr_response_add_err(R_500, _("Illegal PORT command"));

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);
    }
  }

  /* Additionally, make sure that the port number used is a "high numbered"
   * port, to avoid bounce attacks.  For remote Windows machines, the
   * port numbers mean little.  However, there are also quite a few Unix
   * machines out there for whom the port number matters...
   */

  if (port < 1024) {
    pr_log_pri(PR_LOG_WARNING,
      "Refused PORT %s (port %d below 1024, possible bounce attack)", cmd->arg,
      port);
    pr_response_add_err(R_500, _("Illegal PORT command"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  memcpy(&session.data_addr, port_addr, sizeof(session.data_addr));
  session.data_port = port;
  session.sf_flags &= (SF_ALL^SF_PASSIVE);

  /* If we already have a data connection open, kill it. */
  if (session.d != NULL) {
    pr_inet_close(session.d->pool, session.d);
    session.d = NULL;
  }

  session.sf_flags |= SF_PORT;
  pr_response_add(R_200, _("PORT command successful"));

  return PR_HANDLED(cmd);
}

MODRET core_eprt(cmd_rec *cmd) {
  const pr_netaddr_t *listen_addr = NULL;
  pr_netaddr_t na;
  int family = 0;
  unsigned short port = 0;
  int allow_foreign_addr = FALSE, *root_revoke = NULL;
  char delim = '\0', *argstr = pstrdup(cmd->tmp_pool, cmd->argv[1]);
  char *tmp = NULL;
  config_rec *c;
  const char *proto;

  if (session.sf_flags & SF_EPSV_ALL) {
    pr_response_add_err(R_500, _("Illegal EPRT command, EPSV ALL in effect"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  CHECK_CMD_ARGS(cmd, 2);

  /* Returning 501 is the best we can do.  It would be nicer if RFC959 allowed
   * 550 as a possible response.
   */
  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, session.cwd, NULL)) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG8, "EPRT denied by <Limit> configuration");
    pr_response_add_err(R_501, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* Initialize the netaddr. */
  pr_netaddr_clear(&na);

  /* Block active transfers (the EPRT command) if RootRevoke is in effect
   * and the server's port is below 1024 (binding to the data port in this
   * case would require root privs, which will have been dropped.
   *
   * A RootRevoke value of 0 indicates 'false', 1 indicates 'true', and
   * 2 indicates 'NonCompliantActiveTransfer'.  We only block active transfers
   * for a RootRevoke value of 1.
   */
  root_revoke = get_param_ptr(TOPLEVEL_CONF, "RootRevoke", FALSE);
  if (root_revoke != NULL &&
      *root_revoke == 1 &&
      session.c->local_port < 1024) {
    pr_log_debug(DEBUG0, "RootRevoke in effect, unable to bind to local "
      "port %d for active transfer", session.c->local_port-1);
    pr_response_add_err(R_500, _("Unable to service EPRT commands"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* Format is <d>proto<d>ip address<d>port<d> (ASCII in network order),
   * where <d> is an arbitrary delimiter character.
   */
  delim = *argstr++;

  /* atoi() will happily any trailing non-numeric characters, so feeding
   * the parameter string won't hurt.
   */
  family = atoi(argstr);

  switch (family) {
    case 1:
      break;

#ifdef PR_USE_IPV6
    case 2:
      if (pr_netaddr_use_ipv6())
        break;
#endif /* PR_USE_IPV6 */

    default:
#ifdef PR_USE_IPV6
      if (pr_netaddr_use_ipv6()) {
        pr_response_add_err(R_522,
          _("Network protocol not supported, use (1,2)"));

      } else {
        pr_response_add_err(R_522,
          _("Network protocol not supported, use (1)"));
      }
#else
      pr_response_add_err(R_522, _("Network protocol not supported, use (1)"));
#endif /* PR_USE_IPV6 */

      pr_cmd_set_errno(cmd, EINVAL);
      errno = EINVAL;
      return PR_ERROR(cmd);
  }

  /* Now, skip past those numeric characters that atoi() used. */
  while (PR_ISDIGIT(*argstr)) {
    argstr++;
  }

  /* If the next character is not the delimiter, it's a badly formatted
   * parameter.
   */
  if (*argstr == delim) {
    argstr++;

  } else {
    pr_response_add_err(R_501, _("Illegal EPRT command"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  tmp = strchr(argstr, delim);
  if (tmp == NULL) {
    pr_log_debug(DEBUG3, "badly formatted EPRT argument: '%s'",
      (char *) cmd->argv[1]);
    pr_response_add_err(R_501, _("Illegal EPRT command"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* Twiddle the string so that just the address portion will be processed
   * by pr_inet_pton().
   */
  *tmp = '\0';

  memset(&na, 0, sizeof(na));

  /* Use pr_inet_pton() to translate the address string into the address
   * value.
   */
  switch (family) {
    case 1: {
      struct sockaddr *sa = NULL;

      pr_netaddr_set_family(&na, AF_INET);
      sa = pr_netaddr_get_sockaddr(&na);
      if (sa)
        sa->sa_family = AF_INET;
      if (pr_inet_pton(AF_INET, argstr, pr_netaddr_get_inaddr(&na)) <= 0) {
        pr_log_debug(DEBUG2, "error converting IPv4 address '%s': %s",
          argstr, strerror(errno));
        pr_response_add_err(R_501, _("Illegal EPRT command"));

        pr_cmd_set_errno(cmd, EPERM);
        errno = EPERM;
        return PR_ERROR(cmd);
      }
      break;
    }

    case 2: {
      struct sockaddr *sa = NULL;

      pr_netaddr_set_family(&na, AF_INET6);
      sa = pr_netaddr_get_sockaddr(&na);
      if (sa)
        sa->sa_family = AF_INET6;
      if (pr_inet_pton(AF_INET6, argstr, pr_netaddr_get_inaddr(&na)) <= 0) {
        pr_log_debug(DEBUG2, "error converting IPv6 address '%s': %s",
          argstr, strerror(errno));
        pr_response_add_err(R_501, _("Illegal EPRT command"));

        pr_cmd_set_errno(cmd, EPERM);
        errno = EPERM;
        return PR_ERROR(cmd);
      }
      break;
    }
  }

  /* Advance past the address portion of the argument. */
  argstr = ++tmp;

  port = atoi(argstr);

  while (PR_ISDIGIT(*argstr)) {
    argstr++;
  }

  /* If the next character is not the delimiter, it's a badly formatted
   * parameter.
   */
  if (*argstr != delim) {
    pr_log_debug(DEBUG3, "badly formatted EPRT argument: '%s'",
      (char *) cmd->argv[1]);
    pr_response_add_err(R_501, _("Illegal EPRT command"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* If we are NOT listening on an RFC1918 address, BUT the client HAS
   * sent us an RFC1918 address in its PORT command (which we know to not be
   * routable), then ignore that address, and use the client's remote address.
   */
  listen_addr = session.c->local_addr;

  proto = pr_session_get_protocol(0);
  if (strncmp(proto, "ftps", 5) == 0) {
    c = find_config(main_server->conf, CONF_PARAM, "TLSMasqueradeAddress",
      FALSE);
    if (c != NULL) {
      listen_addr = c->argv[0];

    } else {
      c = find_config(main_server->conf, CONF_PARAM, "MasqueradeAddress",
        FALSE);
      if (c != NULL) {
        if (c->argv[0] != NULL) {
          listen_addr = c->argv[0];
        }
      }
    }

  } else {
    c = find_config(main_server->conf, CONF_PARAM, "MasqueradeAddress", FALSE);
    if (c != NULL) {
      if (c->argv[0] != NULL) {
        listen_addr = c->argv[0];
      }
    }
  }

  if (pr_netaddr_is_rfc1918(listen_addr) != TRUE &&
      pr_netaddr_is_rfc1918(session.c->remote_addr) != TRUE &&
      pr_netaddr_is_rfc1918(&na) == TRUE) {
    const char *rfc1918_ipstr;

    rfc1918_ipstr = pr_netaddr_get_ipstr(&na);

    pr_netaddr_clear(&na);
    pr_netaddr_set_family(&na, pr_netaddr_get_family(session.c->remote_addr));
    pr_netaddr_set_sockaddr(&na,
      pr_netaddr_get_sockaddr(session.c->remote_addr));

    pr_log_debug(DEBUG1, "client sent RFC1918 address '%s' in EPRT command, "
      "ignoring it and using '%s'", rfc1918_ipstr, pr_netaddr_get_ipstr(&na));
  }

  /* Make sure that the address specified matches the address from which
   * the control connection is coming.
   */

  c = find_config(TOPLEVEL_CONF, CONF_PARAM, "AllowForeignAddress", FALSE);
  if (c != NULL) {
    int allowed;

    allowed = *((int *) c->argv[0]);
    switch (allowed) {
      case TRUE:
        allow_foreign_addr = TRUE;
        break;

      case FALSE:
        break;

      default: {
        char *class_name;
        const pr_class_t *cls;

        class_name = c->argv[1];
        cls = pr_class_find(class_name);
        if (cls != NULL) {
          if (pr_class_satisfied(cmd->tmp_pool, cls, &na) == TRUE) {
            allow_foreign_addr = TRUE;

          } else {
            pr_log_debug(DEBUG8, "<Class> '%s' not satisfied by foreign "
              "address '%s'", class_name, pr_netaddr_get_ipstr(&na));
          }

        } else {
          pr_log_debug(DEBUG8, "<Class> '%s' not found for filtering "
            "AllowForeignAddress", class_name);
        }
      }
    }
  }

  if (allow_foreign_addr == FALSE) {
    if (pr_netaddr_cmp(&na, session.c->remote_addr) != 0 || !port) {
      pr_log_pri(PR_LOG_WARNING, "Refused EPRT %s (address mismatch)",
        cmd->arg);
      pr_response_add_err(R_500, _("Illegal EPRT command"));

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);
    }
  }

  /* Additionally, make sure that the port number used is a "high numbered"
   * port, to avoid bounce attacks.  For remote Windows machines, the
   * port numbers mean little.  However, there are also quite a few Unix
   * machines out there for whom the port number matters...
   */

  if (port < 1024) {
    pr_log_pri(PR_LOG_WARNING,
      "Refused EPRT %s (port %d below 1024, possible bounce attack)", cmd->arg,
      port);
    pr_response_add_err(R_500, _("Illegal EPRT command"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* Make sure we're using network byte order. */
  pr_netaddr_set_port(&na, htons(port));

  switch (family) {
    case 1:
      pr_netaddr_set_family(&session.data_addr, AF_INET);
      break;

    case 2:
      pr_netaddr_set_family(&session.data_addr, AF_INET6);
      break;
  }

  pr_netaddr_set_sockaddr(&session.data_addr, pr_netaddr_get_sockaddr(&na));
  pr_netaddr_set_port(&session.data_addr, pr_netaddr_get_port(&na));
  session.data_port = port;
  session.sf_flags &= (SF_ALL^SF_PASSIVE);

  /* If we already have a data connection open, kill it. */
  if (session.d) {
    pr_inet_close(session.d->pool, session.d);
    session.d = NULL;
  }

  session.sf_flags |= SF_PORT;
  pr_response_add(R_200, _("EPRT command successful"));

  return PR_HANDLED(cmd);
}

MODRET core_epsv(cmd_rec *cmd) {
  char *addrstr = "";
  char *endp = NULL, *arg = NULL;
  int family = 0;
  int epsv_min_port = 1024, epsv_max_port = 65535;
  config_rec *c = NULL;
  const pr_netaddr_t *bind_addr;

  CHECK_CMD_MIN_ARGS(cmd, 1);

  /* Returning 501 is the best we can do.  It would be nicer if RFC959 allowed
   * 550 as a possible response.
   */
  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, session.cwd, NULL)) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG8, "EPSV denied by <Limit> configuration");
    pr_response_add_err(R_501, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (cmd->argc-1 == 1) {
    arg = pstrdup(cmd->tmp_pool, cmd->argv[1]);
  }

  if (arg && strcasecmp(arg, "all") == 0) {
    session.sf_flags |= SF_EPSV_ALL;
    pr_response_add(R_200, _("EPSV ALL command successful"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_HANDLED(cmd);
  }

  /* If the optional parameter was given, determine the address family from
   * that.  If not, determine the family from the control connection address
   * family.
   */
  if (arg) {
    family = strtol(arg, &endp, 10);

    if (endp && *endp) {
      pr_response_add_err(R_501, _("%s: unknown network protocol"),
        (char *) cmd->argv[0]);

      pr_cmd_set_errno(cmd, EINVAL);
      errno = EINVAL;
      return PR_ERROR(cmd);
    }
 
  } else {

    switch (pr_netaddr_get_family(session.c->local_addr)) {
      case AF_INET:
        family = 1;
        break;

#ifdef PR_USE_IPV6
      case AF_INET6:
        if (pr_netaddr_use_ipv6()) {
          family = 2;
          break;
        }
#endif /* PR_USE_IPV6 */

      default:
        family = 0;
        break;
    }
  }

  switch (family) {
    case 1:
      break;

#ifdef PR_USE_IPV6
    case 2:
      if (pr_netaddr_use_ipv6())
        break;
#endif /* PR_USE_IPV6 */

    default:
#ifdef PR_USE_IPV6
      if (pr_netaddr_use_ipv6()) {
        pr_response_add_err(R_522,
          _("Network protocol not supported, use (1,2)"));

      } else {
        pr_response_add_err(R_522,
          _("Network protocol not supported, use (1)"));
      }
#else
      pr_response_add_err(R_522, _("Network protocol not supported, use (1)"));
#endif /* PR_USE_IPV6 */

      pr_cmd_set_errno(cmd, EINVAL);
      errno = EINVAL;
      return PR_ERROR(cmd);
  }

  /* If we already have a passive listen data connection open, kill it. */
  if (session.d) {
    pr_inet_close(session.d->pool, session.d);
    session.d = NULL;
  }

  if (pr_netaddr_get_family(session.c->local_addr) == pr_netaddr_get_family(session.c->remote_addr)) {
    bind_addr = session.c->local_addr;

  } else {
    /* In this scenario, the server has an IPv6 socket, but the remote client
     * is an IPv4 (or IPv4-mapped IPv6) peer.
     */
    bind_addr = pr_netaddr_v6tov4(cmd->pool, session.c->local_addr);
  }

  c = find_config(main_server->conf, CONF_PARAM, "PassivePorts", FALSE);
  if (c != NULL) {
    epsv_min_port = *((int *) c->argv[0]);
    epsv_max_port = *((int *) c->argv[1]);
  }

  /* We always use the portrange variant of inet_create_conn() here,
   * since it seems that some Unix kernels have issues when choosing a
   * random port number for IPv6 sockets (see Bug #2900).  By using the
   * portrange variant, proftpd, and not the kernel, will be the one
   * choosing the port number.  We really only need to do this for EPSV
   * and not PASV since only the EPSV command can be used for IPv6
   * connections; using PASV means IPv4 connections, and Unix kernels
   * have more predictable behavior for choosing random IPv4 socket ports.
   */

  session.d = pr_inet_create_conn_portrange(session.pool, bind_addr,
    epsv_min_port, epsv_max_port);
  if (session.d == NULL) {
    /* If not able to open a passive port in the given range, default to
     * normal behavior (using INPORT_ANY), and log the failure.  This
     * indicates a too-small range configuration.
     */
    pr_log_pri(PR_LOG_WARNING, "unable to find open port in PassivePorts "
      "range %d-%d: defaulting to INPORT_ANY (consider defining a larger "
      "PassivePorts range)", epsv_min_port, epsv_max_port);

    session.d = pr_inet_create_conn(session.pool, -1, bind_addr, INPORT_ANY,
      FALSE);
  }

  if (session.d == NULL) {
    pr_response_add_err(R_425,
      _("Unable to build data connection: Internal error"));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  /* Make sure that necessary socket options are set on the socket prior
   * to the call to listen(2).
   */
  pr_inet_set_proto_opts(session.pool, session.d, main_server->tcp_mss_len, 0,
    IPTOS_THROUGHPUT, 1);
  pr_inet_generate_socket_event("core.data-listen", main_server,
    session.d->local_addr, session.d->listen_fd);

  pr_inet_set_block(session.pool, session.d);
  if (pr_inet_listen(session.pool, session.d, 1, 0) < 0) {
    int xerrno = errno;

    pr_response_add_err(R_425, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  session.d->instrm = pr_netio_open(session.pool, PR_NETIO_STRM_DATA,
    session.d->listen_fd, PR_NETIO_IO_RD);

  /* Now tell the client our address/port. */
  session.data_port = session.d->local_port;
  session.sf_flags |= SF_PASSIVE;

  /* Note: what about masquerading IPv6 addresses?  It seems that RFC2428,
   * which defines the EPSV command, does not explicitly handle the
   * case where the server may wish to return a network address in its
   * EPSV response.  The assumption is that in an IPv6 environment, there
   * will be no need for NAT, and hence no need for masquerading.  This
   * may be true in an ideal world, but I think it more likely that current
   * clients will simply use EPSV, rather than PASV, in existing IPv4 networks.
   *
   * Disable the honoring of MasqueradeAddress for EPSV until this can
   * be officially determined (Bug#2369).  See also Bug#3862.
   */
#if 0
  c = find_config(main_server->conf, CONF_PARAM, "MasqueradeAddress", FALSE);
  if (c != NULL) {
   addrstr = (char *) pr_netaddr_get_ipstr(c->argv[0]);
  }
#endif

  pr_log_debug(DEBUG1, "Entering Extended Passive Mode (||%s|%u|)",
    addrstr, (unsigned int) session.data_port);
  pr_response_add(R_229, "Entering Extended Passive Mode (||%s|%u|)",
    addrstr, (unsigned int) session.data_port);

  return PR_HANDLED(cmd);
}

MODRET core_help(cmd_rec *cmd) {
  if (cmd->argc == 1) {
    pr_help_add_response(cmd, NULL);

  } else {
    char *cp;

    for (cp = cmd->argv[1]; *cp; cp++) {
      *cp = toupper(*cp);
    }

    if (strcasecmp(cmd->argv[1], C_SITE) == 0) {
      return pr_module_call(&site_module, site_dispatch, cmd);
    }

    if (pr_help_add_response(cmd, cmd->argv[1]) == 0) {
      return PR_HANDLED(cmd);
    }

    pr_response_add_err(R_502, _("Unknown command '%s'"),
      (char *) cmd->argv[1]);

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  return PR_HANDLED(cmd);
}

MODRET core_host(cmd_rec *cmd) {
  const char *local_ipstr;
  char *host;
  size_t hostlen;
  server_rec *named_server;
  int found_ipv6 = FALSE;

  if (cmd->argc != 2) {
    pr_response_add_err(R_500, _("'%s' not understood"), (char *) cmd->argv[0]);

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  if (session.user != NULL) {
    pr_log_debug(DEBUG0,
      "HOST '%s' command received after login, refusing HOST command",
      (char *) cmd->argv[1]);

    /* Per HOST spec, HOST after successful USER/PASS is not allowed. */
    pr_response_add_err(R_503, _("Bad sequence of commands"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, session.cwd, NULL)) {
    int xerrno = EACCES;

    pr_response_add_err(R_504, "%s: %s", (char *) cmd->argv[1],
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* Should there be a limit on the number of HOST commands that a client
   * can send?
   *
   * In practice, this will be limited by the TimeoutLogin time interval;
   * a client can send as many HOST commands as it wishes, as long as it
   * successfully authenticates in that time.
   */

  /* If the user has already authenticated or negotiated a RFC2228 mechanism,
   * then the HOST command is too late.
   */
  if (session.rfc2228_mech != NULL &&
      pr_table_get(session.notes, "mod_tls.sni", NULL) == NULL) {
    pr_log_debug(DEBUG0, "HOST '%s' command received after client has "
      "requested RFC2228 protection (%s), refusing HOST command",
      (char *) cmd->argv[1], session.rfc2228_mech);

    pr_response_add_err(R_503, _("Bad sequence of commands"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  host = cmd->argv[1];
  hostlen = strlen(host);

  if (host[0] == '[') {
    /* Check for any literal IPv6 hostnames. Per HOST spec, these IPv6
     * addresses MUST be enclosed within square brackets.
     */

    if (pr_netaddr_use_ipv6()) {
      if (host[hostlen-1] != ']') {
        pr_response_add_err(R_501, _("%s: Invalid IPv6 address provided"),
          host);

        pr_cmd_set_errno(cmd, EINVAL);
        errno = EINVAL;
        return PR_ERROR(cmd);
      }

      host = pstrndup(cmd->tmp_pool, host + 1, hostlen - 2);
      hostlen = hostlen - 2;

      if (pr_netaddr_is_v6(host) != TRUE) {
        pr_log_debug(DEBUG0,
          "Client-sent hostname '%s' is not a valid IPv6 address, "
          "refusing HOST command", host);

        pr_response_add_err(R_501, _("%s: Invalid IPv6 address provided"),
          (char *) cmd->argv[1]);

        pr_cmd_set_errno(cmd, EINVAL);
        errno = EINVAL;
        return PR_ERROR(cmd);
      }

      found_ipv6 = TRUE;

    } else {
      pr_response_add_err(R_501, _("%s: Invalid hostname provided"),
        host);

      pr_cmd_set_errno(cmd, EINVAL);
      errno = EINVAL;
      return PR_ERROR(cmd);
    }
  }

  local_ipstr = pr_netaddr_get_ipstr(session.c->local_addr);

  if (pr_netaddr_is_v4(host) == TRUE) {
    if (pr_netaddr_is_v4(local_ipstr) == TRUE) {
      if (strncmp(host, local_ipstr, hostlen) != 0) {
        /* The client connected to an IP address, but requested a different IP
         * address in its HOST command.  That won't work.
         */
        pr_log_debug(DEBUG0, "HOST '%s' requested, but client connected to "
          "IPv4 address '%s', refusing HOST command", host, local_ipstr);
        pr_response_add_err(R_504, _("%s: Unknown hostname provided"),
          (char *) cmd->argv[1]);

        pr_cmd_set_errno(cmd, EPERM);
        errno = EPERM;
        return PR_ERROR(cmd);
      }
    }

    (void) pr_table_remove(session.notes, "mod_core.host", NULL);
    if (pr_table_add_dup(session.notes, "mod_core.host", host, 0) < 0) {
      pr_trace_msg("command", 3,
        "error stashing 'mod_core.host' in session.notes: %s", strerror(errno));
    }

    /* No need to send the banner information again, since we didn't actually
     * change the virtual host used by the client.
     */
    pr_response_add(R_220, _("HOST command successful"));
    return PR_HANDLED(cmd);

  } else if (pr_netaddr_is_v6(host) == TRUE) {
    if (pr_netaddr_is_v6(local_ipstr) == TRUE) {

      if (found_ipv6 == FALSE) {
        /* The client sent us an IPv6 address WITHOUT the '[...]' notation,
         * which is a syntax error.
         */
        pr_log_debug(DEBUG0, "Client-sent hostname '%s' is an IPv6 address, "
          "but did not have required [] notation, refusing HOST command",
          host);

        pr_response_add_err(R_501, _("%s: Invalid IPv6 address provided"),
          host);

        pr_cmd_set_errno(cmd, EINVAL);
        errno = EINVAL;
        return PR_ERROR(cmd);
      }

      if (strncmp(host, local_ipstr, hostlen) != 0) {
        /* The client connected to an IP address, but requested a different IP
         * address in its HOST command.  That won't work.
         */
        pr_log_debug(DEBUG0, "HOST '%s' requested, but client connected to "
          "IPv6 address '%s', refusing HOST command", host, local_ipstr);
        pr_response_add_err(R_504, _("%s: Unknown hostname provided"),
          (char *) cmd->argv[1]);

        pr_cmd_set_errno(cmd, EPERM);
        errno = EPERM;
        return PR_ERROR(cmd);
      }
    }

    (void) pr_table_remove(session.notes, "mod_core.host", NULL);
    if (pr_table_add_dup(session.notes, "mod_core.host", host, 0) < 0) {
      pr_trace_msg("command", 3,
        "error stashing 'mod_core.host' in session.notes: %s", strerror(errno));
    }

    /* No need to send the banner information again, since we didn't actually
     * change the virtual host used by the client.
     */
    pr_response_add(R_220, _("HOST command successful"));
    return PR_HANDLED(cmd);
  }

  /* If we reach this point, the hostname is probably a DNS name.  See if we
   * have a matching namebind based on the current IP address/port.
   */

  if (strchr(host, ':') != NULL) {
    /* Hostnames cannot contain colon characters. */
    pr_response_add_err(R_501, _("%s: Invalid hostname provided"), host);

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  named_server = pr_namebind_get_server(host, main_server->addr,
    session.c->local_port);
  if (named_server == NULL) {
    pr_log_debug(DEBUG0, "Unknown host '%s' requested on %s#%d, "
      "refusing HOST command", host, local_ipstr, main_server->ServerPort);

    pr_response_add_err(R_504, _("%s: Unknown hostname provided"),
      (char *) cmd->argv[1]);

    pr_cmd_set_errno(cmd, ENOENT);
    errno = ENOENT;
    return PR_ERROR(cmd);
  }

  if (session.rfc2228_mech != NULL &&
      strncmp(session.rfc2228_mech, "TLS", 4) == 0) {
    const char *sni = NULL;

    /* If the TLS client used the SNI extension, ensure that the SNI name
     * matches the HOST name, per RFC 7151, Section 3.2.2.  Otherwise, we
     * reject the HOST command.
     */
    sni = pr_table_get(session.notes, "mod_tls.sni", NULL);
    if (sni != NULL) {
      if (strcasecmp(sni, host) != 0) {
        pr_log_debug(DEBUG0, "HOST '%s' requested, but client connected via "
          "TLS to SNI '%s', refusing HOST command", host, sni);
        pr_response_add_err(R_504, _("%s: Unknown hostname provided"),
          (char *) cmd->argv[1]);

        pr_cmd_set_errno(cmd, EPERM);
        errno = EPERM;
        return PR_ERROR(cmd);
      }
    }
  }

  (void) pr_table_remove(session.notes, "mod_core.host", NULL);
  if (pr_table_add_dup(session.notes, "mod_core.host", host, 0) < 0) {
    pr_trace_msg("command", 3,
      "error stashing 'mod_core.host' in session.notes: %s", strerror(errno));
  }

  if (named_server != main_server) {
    /* Set a session flag indicating that the main_server pointer changed. */
    pr_log_debug(DEBUG0,
      "Changing to server '%s' (ServerAlias %s) due to HOST command",
      named_server->ServerName, host);
    session.prev_server = main_server;
    main_server = named_server;

    pr_event_generate("core.session-reinit", named_server);
  }

  /* XXX Ultimately, if HOST is successful, we change the main_server pointer
   * to point to the named server_rec.
   *
   * Check *every single sess_init* function, since there are MANY things
   * which currently happen at sess_init, based on the main_server pointer,
   * that will need to be re-done in a HOST POST_CMD handler.  This includes
   * AuthOrder, timeouts, etc etc.  (Unfortunately, POST_CMD handlers cannot
   * fail the given command; for modules which then need to end the
   * connection, they'll need to use pr_session_disconnect().)
   *
   * Modules implementing post_host handlers:
   *   mod_core
   *
   * Modules implementing 'sess-reinit' event handlers:
   *   mod_auth
   *   mod_auth_file
   *   mod_auth_unix
   *   mod_ban
   *   mod_cap
   *   mod_copy
   *   mod_deflate
   *   mod_delay
   *   mod_dnsbl
   *   mod_exec
   *   mod_facts
   *   mod_ident
   *   mod_ldap
   *   mod_log
   *   mod_log_forensic
   *   mod_memcache
   *   mod_qos
   *   mod_quotatab
   *   mod_radius
   *   mod_rewrite
   *   mod_site_misc
   *   mod_sql
   *   mod_sql_passwd
   *   mod_tls
   *   mod_wrap
   *   mod_wrap2
   *   mod_xfer
   *
   * Modules that MIGHT need a session-reinit listener:
   *   mod_ratio
   *   mod_snmp
   *
   * Modules that DO NOT NEED a session-reinit listener:
   *   mod_auth_pam
   *   mod_ctrls_admin
   *   mod_dynmasq
   *   mod_ifsession
   *   mod_ifversion
   *   mod_load
   *   mod_readme
   *   mod_sftp (HOST command is FTP only)
   *   mod_sftp_pam
   *   mod_sftp_sql
   *   mod_shaper
   *   mod_sql_mysql
   *   mod_sql_postgres
   *   mod_sql_odbc
   *   mod_sql_sqlite
   *   mod_tls_fscache
   *   mod_tls_memcache
   *   mod_tls_shmcache
   *   mod_unique_id
   */

  /* XXX Will this function need to use pr_response_add(), rather than
   * pr_response_send(), in order to accommodate the delaying of sending the
   * response until after POST_CMD/LOG_CMD handlers have run (and thus allowing
   * module e.g. mod_tls to send an error response in the POST_CMD handler,
   * and close the connection)?
   */

  pr_session_send_banner(main_server, 0);
  return PR_HANDLED(cmd);
}

MODRET core_post_host(cmd_rec *cmd) {

  /* If the HOST command changed the main_server pointer, reinitialize
   * ourselves.
   */
  if (session.prev_server != NULL) {
    int res;
    config_rec *c;

    /* Reset the FS options */
    (void) pr_fsio_set_options(0UL);

    /* Remove the TimeoutIdle timer. */
    (void) pr_timer_remove(PR_TIMER_IDLE, ANY_MODULE);

    /* Restore the original TimeoutLinger value. */
    pr_data_set_linger(PR_TUNABLE_TIMEOUTLINGER);

    /* Restore original DebugLevel. */
    pr_log_setdebuglevel(DEBUG0);

    /* Restore the original RegexOptions values. */
    pr_regexp_set_limits(0, 0);

    /* Remove any configured SetEnvs. */
    c = find_config(session.prev_server->conf, CONF_PARAM, "SetEnv", FALSE);
    while (c) {
      pr_signals_handle();

      if (pr_env_unset(session.pool, c->argv[0]) < 0) {
        pr_log_debug(DEBUG0, "unable to unset environment variable '%s': %s",
          (char *) c->argv[0], strerror(errno));
      }

      c = find_config_next(c, c->next, CONF_PARAM, "SetEnv", FALSE);
    }

    /* Restore original AuthOrder. */
    reset_server_auth_order();

#ifdef PR_USE_TRACE
    /* XXX Restore original Trace settings. */

    /* Restore original TraceOptions settings. */
    (void) pr_trace_set_options(PR_TRACE_OPT_DEFAULT);

#endif /* PR_USE_TRACE */

    /* Remove the variables set via pr_var_set(). */
    (void) pr_var_delete("%{bytes_xfer}");
    (void) pr_var_delete("%{total_bytes_in}");
    (void) pr_var_delete("%{total_bytes_out}");
    (void) pr_var_delete("%{total_bytes_xfer}");
    (void) pr_var_delete("%{total_files_in}");
    (void) pr_var_delete("%{total_files_out}");
    (void) pr_var_delete("%{total_files_xfer}");

    /* Reset the DisplayQuit file. */
    if (displayquit_fh != NULL) {
      pr_fsio_close(displayquit_fh);
      displayquit_fh = NULL;
    }

    /* Restore the original ProcessTitles setting. */
    pr_proctitle_set_static_str(NULL);

    res = core_sess_init();
    if (res < 0) {
      pr_session_disconnect(&core_module,
        PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
    }
  }
  
  return PR_DECLINED(cmd);
}

MODRET core_clnt(cmd_rec *cmd) {
  pr_response_add(R_200, _("OK"));
  return PR_HANDLED(cmd);
}

MODRET core_syst(cmd_rec *cmd) {
  pr_response_add(R_215, "UNIX Type: L8");
  return PR_HANDLED(cmd);
}

int core_chgrp(cmd_rec *cmd, const char *path, uid_t uid, gid_t gid) {
  char *cmd_name;

  cmd_name = cmd->argv[0];
  pr_cmd_set_name(cmd, "SITE_CHGRP");
  if (!dir_check(cmd->tmp_pool, cmd, G_WRITE, path, NULL)) {
    pr_log_debug(DEBUG7, "SITE CHGRP command denied by <Limit> config");
    pr_cmd_set_name(cmd, cmd_name);

    errno = EACCES;
    return -1;
  }
  pr_cmd_set_name(cmd, cmd_name);

  return pr_fsio_lchown(path, uid, gid);
}

int core_chmod(cmd_rec *cmd, const char *path, mode_t mode) {
  char *cmd_name;

  cmd_name = cmd->argv[0];
  pr_cmd_set_name(cmd, "SITE_CHMOD");
  if (!dir_check(cmd->tmp_pool, cmd, G_WRITE, path, NULL)) {
    pr_log_debug(DEBUG7, "SITE CHMOD command denied by <Limit> config");
    pr_cmd_set_name(cmd, cmd_name);

    errno = EACCES;
    return -1;
  }
  pr_cmd_set_name(cmd, cmd_name);

  return pr_fsio_chmod(path, mode);
}

MODRET core_chdir(cmd_rec *cmd, char *ndir) {
  char *dir, *orig_dir, *cdir;
  int xerrno = 0;
  config_rec *c = NULL, *cdpath;
  unsigned char show_symlinks = TRUE, *ptr = NULL;
  struct stat st;

  orig_dir = ndir;

  ptr = get_param_ptr(TOPLEVEL_CONF, "ShowSymlinks", FALSE);
  if (ptr != NULL) {
    show_symlinks = *ptr;
  }

  if (show_symlinks) {
    int use_cdpath = FALSE;

    dir = dir_realpath(cmd->tmp_pool, ndir);
    if (dir == NULL) {
      use_cdpath = TRUE;
    }

    if (!use_cdpath) {
      int allowed_access = TRUE;

      allowed_access = dir_check_full(cmd->tmp_pool, cmd, cmd->group, dir,
        NULL);
      if (!allowed_access) {
        use_cdpath = TRUE;
      }
    }

    if (use_cdpath == FALSE &&
        pr_fsio_chdir(dir, 0) < 0) {
      xerrno = errno;
      use_cdpath = TRUE;
    }

    if (use_cdpath) {
      for (cdpath = find_config(main_server->conf, CONF_PARAM, "CDPath", TRUE);
          cdpath != NULL;
          cdpath = find_config_next(cdpath, cdpath->next, CONF_PARAM, "CDPath", TRUE)) {
        cdir = palloc(cmd->tmp_pool, strlen(cdpath->argv[0]) + strlen(ndir) + 2);
        pr_snprintf(cdir, strlen(cdpath->argv[0]) + strlen(ndir) + 2,
                 "%s%s%s", (char *) cdpath->argv[0],
                 ((char *) cdpath->argv[0])[strlen(cdpath->argv[0]) - 1] == '/' ? "" : "/",
                 ndir);
        dir = dir_realpath(cmd->tmp_pool, cdir);

        if (dir &&
            dir_check_full(cmd->tmp_pool, cmd, cmd->group, dir, NULL) &&
            pr_fsio_chdir(dir, 0) == 0) {
          break;
        }
      }

      if (cdpath == FALSE) {
        if (xerrno == 0) {
          xerrno = errno;
        }

        pr_response_add_err(R_550, "%s: %s", orig_dir, strerror(xerrno));

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return PR_ERROR(cmd);
      }
    }

  } else {
    int use_cdpath = FALSE;

    /* Virtualize the chdir */
    ndir = dir_canonical_vpath(cmd->tmp_pool, ndir);
    dir = dir_realpath(cmd->tmp_pool, ndir);

    if (!dir) {
      use_cdpath = TRUE;
    }

    if (!use_cdpath) {
      int allowed_access = TRUE;

      allowed_access = dir_check_full(cmd->tmp_pool, cmd, cmd->group, dir,
        NULL);
      if (!allowed_access)
        use_cdpath = TRUE;
    }

    if (!use_cdpath &&
        pr_fsio_chdir_canon(ndir, 1) < 0) {
      use_cdpath = TRUE;
    }            

    if (use_cdpath) {
      for (cdpath = find_config(main_server->conf, CONF_PARAM, "CDPath", TRUE);
          cdpath != NULL;
          cdpath = find_config_next(cdpath, cdpath->next, CONF_PARAM, "CDPath", TRUE)) {
        cdir = palloc(cmd->tmp_pool, strlen(cdpath->argv[0]) + strlen(ndir) + 2);
        pr_snprintf(cdir, strlen(cdpath->argv[0]) + strlen(ndir) + 2,
                 "%s%s%s", (char *) cdpath->argv[0],
                ((char *)cdpath->argv[0])[strlen(cdpath->argv[0]) - 1] == '/' ? "" : "/",
                ndir);
        ndir = dir_canonical_vpath(cmd->tmp_pool, cdir);
        dir = dir_realpath(cmd->tmp_pool, ndir);

        if (dir &&
            dir_check_full(cmd->tmp_pool, cmd, cmd->group, dir, NULL) &&
            pr_fsio_chdir_canon(ndir, 1) != -1) {
          break;
        }
      }

      if (cdpath == NULL) {
        if (xerrno == 0) {
          xerrno = errno;
        }

        pr_response_add_err(R_550, "%s: %s", orig_dir, strerror(xerrno));

        pr_cmd_set_errno(cmd, xerrno);
        errno = xerrno;
        return PR_ERROR(cmd);
      }
    }
  }

  sstrncpy(session.cwd, pr_fs_getcwd(), sizeof(session.cwd));
  sstrncpy(session.vwd, pr_fs_getvwd(), sizeof(session.vwd));

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CWD, session.cwd,
    NULL);

  if (session.dir_config) {
    c = find_config(session.dir_config->subset, CONF_PARAM, "DisplayChdir",
      FALSE);
  }

  if (c == NULL &&
      session.anon_config != NULL) {
    c = find_config(session.anon_config->subset, CONF_PARAM, "DisplayChdir",
      FALSE);
  }

  if (c == NULL) {
    c = find_config(cmd->server->conf, CONF_PARAM, "DisplayChdir", FALSE);
  }

  if (c != NULL) {
    time_t prev = 0;

    char *display = c->argv[0];
    int bool = *((int *) c->argv[1]);

    if (bool) {
   
      /* XXX Get rid of this CONF_USERDATA instance; it's the only
       * occurrence of it in the source.  Use the session.notes table instead.
       */ 
      c = find_config(cmd->server->conf, CONF_USERDATA, session.cwd, FALSE);
      if (!c) {
        time(&prev);
        c = pr_config_add_set(&cmd->server->conf, session.cwd, 0);
        c->config_type = CONF_USERDATA;
        c->argc = 1;
        c->argv = pcalloc(c->pool, sizeof(void **) * 2);
        c->argv[0] = palloc(c->pool, sizeof(time_t));
        *((time_t *) c->argv[0]) = prev;
        prev = (time_t) 0L;

      } else {
        prev = *((time_t *) c->argv[0]);

        /* Update the timestamp stored for this directory. */
        *((time_t *) c->argv[0]) = time(NULL);
      }
    }

    if (pr_fsio_stat(display, &st) != -1 &&
        !S_ISDIR(st.st_mode) &&
        (bool ? st.st_mtime > prev : TRUE)) {

      if (pr_display_file(display, session.cwd, R_250, 0) < 0) {
        pr_log_debug(DEBUG3, "error displaying '%s': %s", display,
          strerror(errno));
      }
    }
  }

  pr_response_add(R_250, _("%s command successful"), (char *) cmd->argv[0]);
  return PR_HANDLED(cmd);
}

MODRET core_rmd(cmd_rec *cmd) {
  int res;
  char *decoded_path, *dir;
  pr_error_t *err = NULL;

  CHECK_CMD_MIN_ARGS(cmd, 2);

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

  dir = decoded_path;

  res = pr_filter_allow_path(CURRENT_CONF, dir);
  switch (res) {
    case 0:
      break;

    case PR_FILTER_ERR_FAILS_ALLOW_FILTER:
      pr_log_debug(DEBUG2, "'%s %s' denied by PathAllowFilter",
        (char *) cmd->argv[0], dir);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd); 
 
    case PR_FILTER_ERR_FAILS_DENY_FILTER:
      pr_log_debug(DEBUG2, "'%s %s' denied by PathDenyFilter",
        (char *) cmd->argv[0], dir);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);
  }

  dir = dir_canonical_path(cmd->tmp_pool, dir);
  if (dir == NULL) {
    int xerrno = EINVAL;

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (!dir_check_canon(cmd->tmp_pool, cmd, cmd->group, dir, NULL)) {
    int xerrno = EACCES;

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  res = pr_fsio_rmdir_with_error(cmd->pool, dir, &err);
  if (res < 0) {
    int xerrno = errno;

    pr_error_set_where(err, &core_module, __FILE__, __LINE__ - 4);
    pr_error_set_why(err, pstrcat(cmd->pool, "remove directory '", dir, "'",
      NULL));

    (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
      "error removing directory '%s': %s", (char *) cmd->argv[0], session.user,
      pr_uid2str(cmd->tmp_pool, session.uid),
      pr_gid2str(cmd->tmp_pool, session.gid), dir, strerror(xerrno));

    if (err != NULL) {
      pr_log_debug(DEBUG9, "%s", pr_error_strerror(err, 0));
      pr_error_destroy(err);
      err = NULL;

    } else {
      pr_log_debug(DEBUG9, "error removing directory '%s': %s", dir,
        strerror(xerrno));
    }

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  pr_response_add(R_250, _("%s command successful"), (char *) cmd->argv[0]);
  return PR_HANDLED(cmd);
}

MODRET core_mkd(cmd_rec *cmd) {
  int res;
  char *decoded_path, *dir;

  CHECK_CMD_MIN_ARGS(cmd, 2);

  /* XXX Why is there a check to prevent the creation of any directory
   * name containing an asterisk?
   */
  if (strchr(cmd->arg, '*')) {
    pr_response_add_err(R_550, _("%s: Invalid directory name"), cmd->arg);

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
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

  dir = decoded_path;

  res = pr_filter_allow_path(CURRENT_CONF, dir);
  switch (res) {
    case 0:
      break;

    case PR_FILTER_ERR_FAILS_ALLOW_FILTER:
      pr_log_debug(DEBUG2, "'%s %s' denied by PathAllowFilter",
        (char *) cmd->argv[0], dir);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd); 
 
    case PR_FILTER_ERR_FAILS_DENY_FILTER:
      pr_log_debug(DEBUG2, "'%s %s' denied by PathDenyFilter",
        (char *) cmd->argv[0], dir);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);
  }

  dir = dir_canonical_path(cmd->tmp_pool, dir);
  if (dir == NULL) {
    int xerrno = EINVAL;

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (!dir_check_canon(cmd->tmp_pool, cmd, cmd->group, dir, NULL)) {
    int xerrno = EACCES;

    pr_log_debug(DEBUG8, "%s command denied by <Limit> config",
      (char *) cmd->argv[0]);
    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (pr_fsio_smkdir(cmd->tmp_pool, dir, 0777, session.fsuid,
      session.fsgid) < 0) {
    int xerrno = errno;

    (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
      "error making directory '%s': %s", (char *) cmd->argv[0], session.user,
      pr_uid2str(cmd->tmp_pool, session.uid),
      pr_gid2str(cmd->tmp_pool, session.gid), dir, strerror(xerrno));

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));
 
    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  pr_response_add(R_257, _("\"%s\" - Directory successfully created"),
    quote_dir(cmd->tmp_pool, dir));

  return PR_HANDLED(cmd);
}

MODRET core_cwd(cmd_rec *cmd) {
  char *decoded_path;
  CHECK_CMD_MIN_ARGS(cmd, 2);

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

  return core_chdir(cmd, decoded_path);
}

MODRET core_cdup(cmd_rec *cmd) {
  CHECK_CMD_ARGS(cmd, 1);
  return core_chdir(cmd, "..");
}

/* Returns the modification time of a file, as per RFC3659. */
MODRET core_mdtm(cmd_rec *cmd) {
  char *decoded_path, *path;
  struct stat st;

  CHECK_CMD_MIN_ARGS(cmd, 2);

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

  path = decoded_path;

  pr_fs_clear_cache2(path);
  path = dir_realpath(cmd->tmp_pool, decoded_path);
  if (!path ||
      !dir_check(cmd->tmp_pool, cmd, cmd->group, path, NULL) ||
      pr_fsio_stat(path, &st) == -1) {
    int xerrno = errno;

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);

  } else {
    if (!S_ISREG(st.st_mode)) {
      pr_response_add_err(R_550, _("%s: not a plain file"), cmd->arg);

      pr_cmd_set_errno(cmd, EINVAL);
      errno = EINVAL;
      return PR_ERROR(cmd);

    } else {
      char buf[16];
      struct tm *tm;

      memset(buf, '\0', sizeof(buf));

      tm = pr_gmtime(cmd->tmp_pool, &st.st_mtime);
      if (tm != NULL) {
        pr_snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02d",
          tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour,
          tm->tm_min, tm->tm_sec);

      } else {
        pr_snprintf(buf, sizeof(buf), "00000000000000");
      }

      pr_response_add(R_213, "%s", buf);
    }
  }

  return PR_HANDLED(cmd);
}

MODRET core_size(cmd_rec *cmd) {
  char *decoded_path, *path;
  struct stat st;

  CHECK_CMD_MIN_ARGS(cmd, 2);

  /* The PR_ALLOW_ASCII_MODE_SIZE macro should ONLY be defined at compile time,
   * e.g. using:
   *
   *  $ ./configure CPPFLAGS=-DPR_ALLOW_ASCII_MODE_SIZE ...
   *
   * Define this macro if you want proftpd to handle a SIZE command while in
   * ASCII mode.  Note, however, that ProFTPD will NOT properly calculate
   * CRLF sequences EVEN if this macro is defined: ProFTPD will always return
   * the number of bytes on disk for the requested file, even if the number of
   * bytes transferred when that file is downloaded is different.  Thus this
   * behavior will not comply with RFC 3659, Section 4.  Caveat emptor.
   */
#ifndef PR_ALLOW_ASCII_MODE_SIZE
  /* Refuse the command if we're in ASCII mode. */
  if (session.sf_flags & SF_ASCII) {
    pr_log_debug(DEBUG5, "%s not allowed in ASCII mode", (char *) cmd->argv[0]);
    pr_response_add_err(R_550, _("%s not allowed in ASCII mode"),
      (char *) cmd->argv[0]);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }
#endif /* PR_ALLOW_ASCII_MODE_SIZE */

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

  pr_fs_clear_cache2(decoded_path);
  path = dir_realpath(cmd->tmp_pool, decoded_path);
  if (path != NULL) {
    pr_fs_clear_cache2(path);
  }

  if (path == NULL ||
      !dir_check(cmd->tmp_pool, cmd, cmd->group, path, NULL) ||
      pr_fsio_stat(path, &st) == -1) {
    int xerrno = errno;

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);

  } else {
    if (!S_ISREG(st.st_mode)) {
      pr_response_add_err(R_550, _("%s: not a regular file"), cmd->arg);

      pr_cmd_set_errno(cmd, EINVAL);
      errno = EINVAL;
      return PR_ERROR(cmd);

    } else {
      pr_response_add(R_213, "%" PR_LU, (pr_off_t) st.st_size);
    }
  }

  return PR_HANDLED(cmd);
}

MODRET core_dele(cmd_rec *cmd) {
  int res;
  char *decoded_path, *path, *fullpath;
  struct stat st;
  pr_error_t *err = NULL;

  CHECK_CMD_MIN_ARGS(cmd, 2);

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

  path = decoded_path;

  res = pr_filter_allow_path(CURRENT_CONF, path);
  switch (res) {
    case 0:
      break;

    case PR_FILTER_ERR_FAILS_ALLOW_FILTER:
      pr_log_debug(DEBUG2, "'%s %s' denied by PathAllowFilter",
        (char *) cmd->argv[0], path);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd); 
 
    case PR_FILTER_ERR_FAILS_DENY_FILTER:
      pr_log_debug(DEBUG2, "'%s %s' denied by PathDenyFilter",
        (char *) cmd->argv[0], path);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);
  }

  /* If told to delete a symlink, don't delete the file it points to!  */
  path = dir_canonical_path(cmd->tmp_pool, path);
  if (path == NULL) {
    int xerrno = ENOENT;

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, path, NULL)) {
    int xerrno = errno;

    pr_log_debug(DEBUG7, "deleting '%s' denied by <Limit> configuration", path);
    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* Stat the path, before it is deleted, so that the size of the file
   * being deleted can be logged.  Note that unlink() doesn't follow symlinks,
   * so we need to use lstat(), not stat(), lest we log the wrong size.
   */
  memset(&st, 0, sizeof(st));
  pr_fs_clear_cache2(path);
  res = pr_fsio_lstat_with_error(cmd->tmp_pool, path, &st, &err);
  if (res < 0) {
    int xerrno = errno;

    pr_error_set_where(err, &core_module, __FILE__, __LINE__ - 4);
    pr_error_set_why(err, pstrcat(cmd->pool, "check file '", path, "'", NULL));

    if (err != NULL) {
      pr_log_debug(DEBUG3, "%s", pr_error_strerror(err, 0));
      pr_error_destroy(err);
      err = NULL;

    } else {
      pr_log_debug(DEBUG3, "unable to lstat '%s': %s", path, strerror(xerrno));
    }

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

#ifdef EISDIR
  /* If the path is a directory, try to return a good error message (e.g.
   * EISDIR).
   */
  if (S_ISDIR(st.st_mode)) {
    int xerrno = EISDIR;

    (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
      "error deleting '%s': %s", (char *) cmd->argv[0], session.user,
      pr_uid2str(cmd->tmp_pool, session.uid),
      pr_gid2str(cmd->tmp_pool, session.gid), path, strerror(xerrno));

    pr_log_debug(DEBUG3, "error deleting '%s': %s", path, strerror(xerrno));
    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }
#endif /* !EISDIR */
 
  res = pr_fsio_unlink_with_error(cmd->pool, path, &err);
  if (res < 0) {
    int xerrno = errno;

    pr_error_set_where(err, &core_module, __FILE__, __LINE__ - 4);
    pr_error_set_why(err, pstrcat(cmd->pool, "delete file '", path, "'", NULL));

    (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
      "error deleting '%s': %s", (char *) cmd->argv[0], session.user,
      pr_uid2str(cmd->tmp_pool, session.uid),
      pr_gid2str(cmd->tmp_pool, session.gid), path, strerror(xerrno));

    if (err != NULL) {
      pr_log_debug(DEBUG3, "%s", pr_error_strerror(err, 0));
      pr_error_destroy(err);
      err = NULL;

    } else {
      pr_log_debug(DEBUG3, "error deleting '%s': %s", path, strerror(xerrno));
    }

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  fullpath = dir_abs_path(cmd->tmp_pool, path, TRUE);

  if (session.sf_flags & SF_ANON) {
    xferlog_write(0, session.c->remote_name, st.st_size, fullpath,
      (session.sf_flags & SF_ASCII ? 'a' : 'b'), 'd', 'a', session.anon_user,
      'c', "_");

  } else {
    xferlog_write(0, session.c->remote_name, st.st_size, fullpath,
      (session.sf_flags & SF_ASCII ? 'a' : 'b'), 'd', 'r', session.user, 'c',
      "_");
  }

  pr_response_add(R_250, _("%s command successful"), (char *) cmd->argv[0]);
  return PR_HANDLED(cmd);
}

MODRET core_rnto(cmd_rec *cmd) {
  int res;
  char *decoded_path, *path;
  unsigned char *allow_overwrite = NULL;
  struct stat st;
  pr_error_t *err = NULL;

  CHECK_CMD_MIN_ARGS(cmd, 2);

  if (!session.xfer.path) {
    if (session.xfer.p) {
      destroy_pool(session.xfer.p);
      memset(&session.xfer, '\0', sizeof(session.xfer));
    }

    pr_response_add_err(R_503, _("Bad sequence of commands"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
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

  path = decoded_path;

  res = pr_filter_allow_path(CURRENT_CONF, path);
  switch (res) {
    case 0:
      break;

    case PR_FILTER_ERR_FAILS_ALLOW_FILTER:
      pr_log_debug(DEBUG2, "'%s %s' denied by PathAllowFilter",
        (char *) cmd->argv[0], path);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd); 
 
    case PR_FILTER_ERR_FAILS_DENY_FILTER:
      pr_log_debug(DEBUG2, "'%s %s' denied by PathDenyFilter",
        (char *) cmd->argv[0], path);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);
  }

  path = dir_canonical_path(cmd->tmp_pool, path);

  allow_overwrite = get_param_ptr(CURRENT_CONF, "AllowOverwrite", FALSE);

  /* Deny the rename if AllowOverwrites are not allowed, and the destination
   * rename file already exists.
   */
  pr_fs_clear_cache2(path);
  if ((!allow_overwrite || *allow_overwrite == FALSE) &&
      pr_fsio_stat(path, &st) == 0) {
    pr_log_debug(DEBUG6, "AllowOverwrite denied permission for %s", path);
    pr_response_add_err(R_550, _("%s: Rename permission denied"), cmd->arg);

    pr_cmd_set_errno(cmd, EACCES);
    errno = EACCES;
    return PR_ERROR(cmd);
  }

  if (!path ||
      !dir_check_canon(cmd->tmp_pool, cmd, cmd->group, path, NULL)) {
    pr_response_add_err(R_550, _("%s: %s"), cmd->arg, strerror(EPERM));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  res = pr_fsio_rename_with_error(cmd->pool, session.xfer.path, path, &err);
  if (res < 0) {
    int xerrno = errno;

    pr_error_set_where(err, &core_module, __FILE__, __LINE__ - 4);
    pr_error_set_why(err, pstrcat(cmd->pool, "rename '", session.xfer.path,
      "' to '", path, "'", NULL));

    if (xerrno == EISDIR) {
      /* In this case, the client has requested that a directory be renamed
       * across mount points.  The pr_fs_copy_file() function can't handle
       * copying directories; it only knows about files.  (This could be
       * fixed to work later, e.g. using code from the mod_copy module.)
       *
       * For now, error out now with a more informative error message to the
       * client.
       */

      (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
        "error copying '%s' to '%s': %s (previous error was '%s')",
        (char *) cmd->argv[0], session.user,
        pr_uid2str(cmd->tmp_pool, session.uid),
        pr_gid2str(cmd->tmp_pool, session.gid), session.xfer.path, path,
        strerror(xerrno), strerror(EXDEV));

      pr_log_debug(DEBUG4,
        "Cannot rename directory '%s' across a filesystem mount point",
        session.xfer.path);

      if (err != NULL) {
        pr_error_destroy(err);
        err = NULL;
      }

      /* Use EPERM, rather than EISDIR, to get slightly more informative
       * error messages.
       */
      xerrno = EPERM;

      pr_response_add_err(R_550, _("%s: %s"), cmd->arg, strerror(xerrno));

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    if (xerrno != EXDEV) {
      (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
        "error renaming '%s' to '%s': %s", (char *) cmd->argv[0], session.user,
        pr_uid2str(cmd->tmp_pool, session.uid),
        pr_gid2str(cmd->tmp_pool, session.gid), session.xfer.path, path,
        strerror(xerrno));

      if (err != NULL) {
        pr_log_debug(DEBUG9, "%s", pr_error_strerror(err, 0));
        pr_error_destroy(err);
        err = NULL;
      }

      pr_response_add_err(R_550, _("%s: %s"), cmd->arg, strerror(xerrno));

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    /* In this case, we'll need to manually copy the file from the source
     * to the destination paths.
     */
    if (pr_fs_copy_file(session.xfer.path, path) < 0) {
      xerrno = errno;

      (void) pr_trace_msg("fileperms", 1, "%s, user '%s' (UID %s, GID %s): "
        "error copying '%s' to '%s': %s", (char *) cmd->argv[0], session.user,
        pr_uid2str(cmd->tmp_pool, session.uid),
        pr_gid2str(cmd->tmp_pool, session.gid), session.xfer.path, path,
        strerror(xerrno));

      pr_response_add_err(R_550, _("Rename %s: %s"), cmd->arg,
        strerror(xerrno));

      pr_cmd_set_errno(cmd, xerrno);
      errno = xerrno;
      return PR_ERROR(cmd);
    }

    /* Once copied, unlink the original file. */
    res = pr_fsio_unlink_with_error(cmd->pool, session.xfer.path, &err);
    if (res < 0) {
      xerrno = errno;

      pr_error_set_where(err, &core_module, __FILE__, __LINE__ - 4);
      pr_error_set_why(err, pstrcat(cmd->pool, "delete file '",
        session.xfer.path, "'", NULL));

      if (err != NULL) {
        pr_log_debug(DEBUG0, "%s", pr_error_strerror(err, 0));
        pr_error_destroy(err);
        err = NULL;

      } else {
        pr_log_debug(DEBUG0, "error deleting '%s': %s", session.xfer.path,
          strerror(xerrno));
      }
    }
  }

  /* Change the xfer path to the name of the destination file, for logging. */
  session.xfer.path = pstrdup(session.xfer.p, path);

  pr_response_add(R_250, _("Rename successful"));
  return PR_HANDLED(cmd);
}

MODRET core_rnto_cleanup(cmd_rec *cmd) {
  if (session.xfer.p)
    destroy_pool(session.xfer.p);

  memset(&session.xfer, '\0', sizeof(session.xfer));

  pr_table_remove(session.notes, "mod_core.rnfr-path", NULL);
  return PR_DECLINED(cmd);
}

MODRET core_rnfr(cmd_rec *cmd) {
  int res;
  char *decoded_path, *path;

  CHECK_CMD_MIN_ARGS(cmd, 2);

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

  path = decoded_path;

  res = pr_filter_allow_path(CURRENT_CONF, path);
  switch (res) {
    case 0:
      break;

    case PR_FILTER_ERR_FAILS_ALLOW_FILTER:
      pr_log_debug(DEBUG2, "'%s %s' denied by PathAllowFilter",
        (char *) cmd->argv[0], path);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd); 
 
    case PR_FILTER_ERR_FAILS_DENY_FILTER:
      pr_log_debug(DEBUG2, "'%s %s' denied by PathDenyFilter",
        (char *) cmd->argv[0], path);
      pr_response_add_err(R_550, _("%s: Forbidden filename"), cmd->arg);

      pr_cmd_set_errno(cmd, EPERM);
      errno = EPERM;
      return PR_ERROR(cmd);
  }

  /* Allow renaming a symlink, even a dangling one. */
  path = dir_canonical_path(cmd->tmp_pool, path);

  if (path == NULL ||
      !dir_check(cmd->tmp_pool, cmd, cmd->group, path, NULL) ||
      !exists2(cmd->tmp_pool, path)) {
    int xerrno = errno;

    pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  /* We store the path in session.xfer.path */
  if (session.xfer.p) {
    destroy_pool(session.xfer.p);
    memset(&session.xfer, '\0', sizeof(session.xfer));
  }

  session.xfer.p = make_sub_pool(session.pool);
  pr_pool_tag(session.xfer.p, "session xfer pool");

  session.xfer.path = pstrdup(session.xfer.p, path);

  pr_table_add(session.notes, "mod_core.rnfr-path",
    pstrdup(session.xfer.p, session.xfer.path), 0);

  pr_response_add(R_350,
    _("File or directory exists, ready for destination name"));
  return PR_HANDLED(cmd);
}

MODRET core_noop(cmd_rec *cmd) {
  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, session.vwd, NULL)) {
    int xerrno = EPERM;

    pr_response_add_err(R_550, "%s", strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  pr_response_add(R_200, _("NOOP command successful"));
  return PR_HANDLED(cmd);
}

static int feat_cmp(const void *a, const void *b) {
  return strcasecmp(*((const char **) a), *((const char **) b));
}

MODRET core_feat(cmd_rec *cmd) {
  register unsigned int i;
  const char *feat = NULL;
  array_header *feats = NULL;

  CHECK_CMD_ARGS(cmd, 1);

  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, session.vwd, NULL)) {
    int xerrno = EPERM;

    pr_log_debug(DEBUG3, "%s command denied by <Limit> configuration",
      (char *) cmd->argv[0]);
    pr_response_add_err(R_550, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  feat = pr_feat_get();
  if (feat == NULL) {
    pr_response_add(R_211, _("No features supported"));
    return PR_HANDLED(cmd);
  }

  feats = make_array(cmd->tmp_pool, 0, sizeof(char **));

  while (feat != NULL) {
    pr_signals_handle();
    *((char **) push_array(feats)) = pstrdup(cmd->tmp_pool, feat);
    feat = pr_feat_get_next();
  }

  /* Sort the features, for a prettier output. */
  qsort(feats->elts, feats->nelts, sizeof(char *), feat_cmp);

  pr_response_add(R_211, "%s", _("Features:"));
  for (i = 0; i < feats->nelts; i++) {
    pr_response_add(R_DUP, "%s", ((const char **) feats->elts)[i]);
  }
  pr_response_add(R_DUP, _("End"));

  return PR_HANDLED(cmd);
}

MODRET core_opts(cmd_rec *cmd) {
  register unsigned int i;
  int res;
  char *arg = "";
  cmd_rec *subcmd;

  CHECK_CMD_MIN_ARGS(cmd, 2);

  /* Impose a maximum number of allowed arguments, to prevent malicious
   * clients from trying to do Bad Things(tm).  See Bug#3870.
   */
  if ((cmd->argc-1) > PR_OPTS_MAX_PARAM_COUNT) {
    int xerrno = EINVAL;

    pr_log_debug(DEBUG2,
      "OPTS command with too many parameters (%d), rejecting", cmd->argc-1);
    pr_response_add_err(R_550, "%s: %s", (char *) cmd->argv[0],
      strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  subcmd = pr_cmd_alloc(cmd->tmp_pool, cmd->argc-1, NULL);
  subcmd->argv[0] = pstrcat(cmd->tmp_pool, "OPTS_", cmd->argv[1], NULL);
  subcmd->group = cmd->group;

  if (!dir_check(cmd->tmp_pool, subcmd, subcmd->group, session.vwd, NULL)) {
    int xerrno = EACCES;

    pr_log_debug(DEBUG7, "OPTS %s denied by <Limit> configuration",
      (char *) cmd->argv[1]);
    pr_response_add_err(R_550, "%s %s: %s", (char *) cmd->argv[0],
      (char *) cmd->argv[1], strerror(xerrno));

    pr_cmd_set_errno(cmd, xerrno);
    errno = xerrno;
    return PR_ERROR(cmd);
  }

  for (i = 2; i < cmd->argc; i++) {
    subcmd->argv[i-1] = cmd->argv[i];

    arg = pstrcat(cmd->tmp_pool, arg, *arg ? " " : "", cmd->argv[i], NULL);
  }

  subcmd->arg = arg;

  res = pr_cmd_dispatch(subcmd);
  if (res < 0) {
    return PR_ERROR(cmd);
  }

  return PR_HANDLED(cmd);
}

MODRET core_post_pass(cmd_rec *cmd) {
  config_rec *c;

  c = find_config(TOPLEVEL_CONF, CONF_PARAM, "TimeoutIdle", FALSE);
  if (c != NULL) {
    int prev_timeout, timeout;

    prev_timeout = pr_data_get_timeout(PR_DATA_TIMEOUT_IDLE);
    timeout = *((int *) c->argv[0]);

    if (timeout != prev_timeout) {
      pr_data_set_timeout(PR_DATA_TIMEOUT_IDLE, timeout);

      /* Remove the old timer, and add a new one with the changed
       * timeout value.
       */
      pr_timer_remove(PR_TIMER_IDLE, &core_module);

      if (timeout > 0) {
        pr_timer_add(timeout, PR_TIMER_IDLE, &core_module, core_idle_timeout_cb,
          "TimeoutIdle");
      }
    }
  }

#ifdef PR_USE_TRACE
  /* Handle any user/group-specific Trace settings. */
  c = find_config(main_server->conf, CONF_PARAM, "Trace", FALSE);
  if (c != NULL) {
    register unsigned int i;

    for (i = 0; i < c->argc; i++) {
      char *channel, *ptr;
      int min_level, max_level, res;

      pr_signals_handle();

      channel = c->argv[i];
      ptr = strchr(channel, ':');
      if (ptr == NULL) {
        pr_log_debug(DEBUG6, "skipping badly formatted '%s' setting",
          channel);
        continue;
      }

      *ptr = '\0';

      res = pr_trace_parse_levels(ptr + 1, &min_level, &max_level);
      if (res == 0) {
        res = pr_trace_set_levels(channel, min_level, max_level);
        *ptr = ':';

        if (res < 0) {
          pr_log_debug(DEBUG6, "%s: error setting levels %d-%d for "
            "channel '%s': %s", c->name, min_level, max_level, channel,
            strerror(errno));
        }

      } else {
        pr_log_debug(DEBUG6, "%s: error parsing level '%s' for channel '%s': "
          "%s", c->name, ptr + 1, channel, strerror(errno));
      }
    }
  }

  /* Handle any user/group-specific TraceOptions settings. */
  c = find_config(main_server->conf, CONF_PARAM, "TraceOptions", FALSE);
  if (c != NULL) {
    unsigned long trace_opts;

    trace_opts = *((unsigned long *) c->argv[0]);
    if (pr_trace_set_options(trace_opts) < 0) {
      pr_log_debug(DEBUG6, "%s: error setting TraceOptions (%lu): %s",
        c->name, trace_opts, strerror(errno));
    }
  }
#endif /* PR_USE_TRACE */

  /* Look for a configured MaxCommandRate. */
  c = find_config(main_server->conf, CONF_PARAM, "MaxCommandRate", FALSE);
  if (c) {
    core_cmd_count = 0UL;
    core_max_cmds = *((unsigned long *) c->argv[0]);
    core_max_cmd_interval = *((unsigned int *) c->argv[1]);
    core_max_cmd_ts = 0;
  }

  /* Configure the statcache to start caching for the authenticated session. */
  pr_fs_statcache_reset();
  c = find_config(main_server->conf, CONF_PARAM, "FSCachePolicy", FALSE);
  if (c != NULL) {
    int engine;
    unsigned int size, max_age;

    engine = *((int *) c->argv[0]);
    size = *((unsigned int *) c->argv[1]);
    max_age = *((unsigned int *) c->argv[2]);

    if (engine) {
      pr_fs_statcache_set_policy(size, max_age, 0);

    } else {
      pr_fs_statcache_set_policy(0, 0, 0);
    }

  } else {
    /* Set the default statcache policy. */
    pr_fs_statcache_set_policy(PR_TUNABLE_FS_STATCACHE_SIZE,
      PR_TUNABLE_FS_STATCACHE_MAX_AGE, 0);
  }

  /* Register an exit handler here, for clearing the statcache. */
  pr_event_register(&core_module, "core.exit", core_exit_ev, NULL);

  /* Note: we MUST return HANDLED here, not DECLINED, to indicate that at
   * least one POST_CMD handler of the PASS command succeeded.  Since
   * mod_core is always the last module to which commands are dispatched,
   * we can rest assured that we are not causing problems for any other
   * PASS POST_CMD handlers by returning HANDLED here.
   */
  return PR_HANDLED(cmd);
}

/* Configuration directive handlers
 */

MODRET set_deferwelcome(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* Variable handlers
 */

static const char *core_get_sess_bytes_str(void *data, size_t datasz) {
  char buf[256];
  off_t bytes = *((off_t *) data);

  memset(buf, '\0', sizeof(buf));
  pr_snprintf(buf, sizeof(buf)-1, "%" PR_LU, (pr_off_t) bytes);

  return pstrdup(session.pool, buf);
}

static const char *core_get_sess_files_str(void *data, size_t datasz) {
  char buf[256];
  unsigned int files = *((unsigned int *) data);

  memset(buf, '\0', sizeof(buf));
  pr_snprintf(buf, sizeof(buf)-1, "%u", files);

  return pstrdup(session.pool, buf);
}

static const char *core_get_xfer_bytes_str(void *data, size_t datasz) {
  char buf[256];
  off_t bytes = *((off_t *) data);

  memset(buf, '\0', sizeof(buf));
  pr_snprintf(buf, sizeof(buf)-1, "%" PR_LU, (pr_off_t) bytes);

  return pstrdup(session.pool, buf);
}

/* Event handlers
 */

static void core_exit_ev(const void *event_data, void *user_data) {
  pr_fs_statcache_free();
}

static void core_restart_ev(const void *event_data, void *user_data) {
  pr_fs_statcache_reset();
  pr_scoreboard_scrub();

#ifdef PR_USE_TRACE
  if (trace_log) {
    (void) pr_trace_set_levels(PR_TRACE_DEFAULT_CHANNEL, -1, -1);
    pr_trace_set_file(NULL);
    trace_log = NULL;
  }
#endif /* PR_USE_TRACE */
}

static void core_startup_ev(const void *event_data, void *user_data) {

  /* Add a scoreboard-scrubbing timer.
   *
   * Note that we do this only for standalone proftpd daemons, not for
   * inetd-run daemons.  There is no "master"/"daemon" process for
   * inetd-run proftpd processes, which means that _all_ processes scrub
   * the scoreboard (which greatly increases lock contention, particularly
   * under high numbers of simultaneous connections), or that _no_
   * processes scrub the scoreboard (which increases the chance of stale/bad
   * scoreboard data).
   */
  if (ServerType == SERVER_STANDALONE) {
    int scrub_scoreboard = TRUE;
    int scrub_interval = PR_TUNABLE_SCOREBOARD_SCRUB_TIMER;
    config_rec *c;

    c = find_config(main_server->conf, CONF_PARAM, "ScoreboardScrub", FALSE);
    if (c) {
      scrub_scoreboard = *((int *) c->argv[0]);

      if (c->argc == 2) {
        scrub_interval = *((int *) c->argv[1]);
      }
    }

    if (scrub_scoreboard) {
      core_scrub_timer_id = pr_timer_add(scrub_interval, -1,
        &core_module, core_scrub_scoreboard_cb, "scoreboard scrubbing");
    }
  }
}

/* Initialization/finalization routines
 */

static int core_init(void) {
  /* Set the default (i.e. FTP) command handler. */
  pr_cmd_set_handler(NULL);

  /* Add the commands handled by this module to the HELP list. */
  pr_help_add(C_CWD,  _("<sp> pathname"), TRUE);
  pr_help_add(C_XCWD, _("<sp> pathname"), TRUE);
  pr_help_add(C_CDUP, _("(up one directory)"), TRUE);
  pr_help_add(C_XCUP, _("(up one directory)"), TRUE);
  pr_help_add(C_SMNT, _("is not implemented"), FALSE);
  pr_help_add(C_QUIT, _("(close control connection)"), TRUE);
  pr_help_add(C_PORT, _("<sp> h1,h2,h3,h4,p1,p2"), TRUE);
  pr_help_add(C_PASV, _("(returns address/port)"), TRUE);
  pr_help_add(C_EPRT, _("<sp> |proto|addr|port|"), TRUE);
  pr_help_add(C_EPSV, _("(returns port |||port|)"), TRUE);
  pr_help_add(C_ALLO, _("<sp> size"), TRUE);
  pr_help_add(C_RNFR, _("<sp> pathname"), TRUE);
  pr_help_add(C_RNTO, _("<sp> pathname"), TRUE);
  pr_help_add(C_DELE, _("<sp> pathname"), TRUE);
  pr_help_add(C_MDTM, _("<sp> pathname"), TRUE);
  pr_help_add(C_RMD, _("<sp> pathname"), TRUE);
  pr_help_add(C_XRMD, _("<sp> pathname"), TRUE);
  pr_help_add(C_MKD, _("<sp> pathname"), TRUE);
  pr_help_add(C_XMKD, _("<sp> pathname"), TRUE);
  pr_help_add(C_PWD, _("(returns current working directory)"), TRUE);
  pr_help_add(C_XPWD, _("(returns current working directory)"), TRUE);
  pr_help_add(C_SIZE, _("<sp> pathname"), TRUE);
  pr_help_add(C_SYST, _("(returns system type)"), TRUE);
  pr_help_add(C_HELP, _("[<sp> command]"), TRUE);
  pr_help_add(C_NOOP, _("(no operation)"), TRUE);
  pr_help_add(C_FEAT, _("(returns feature list)"), TRUE);
  pr_help_add(C_OPTS, _("<sp> command [<sp> options]"), TRUE);
  pr_help_add(C_HOST, _("<cp> hostname"), TRUE);
  pr_help_add(C_CLNT, _("<cp> client-info"), TRUE);
  pr_help_add(C_AUTH, _("<sp> base64-data"), FALSE);
  pr_help_add(C_CCC, _("(clears protection level)"), FALSE);
  pr_help_add(C_CONF, _("<sp> base64-data"), FALSE);
  pr_help_add(C_ENC, _("<sp> base64-data"), FALSE);
  pr_help_add(C_MIC, _("<sp> base64-data"), FALSE);
  pr_help_add(C_PBSZ, _("<sp> protection buffer size"), FALSE);
  pr_help_add(C_PROT, _("<sp> protection code"), FALSE);

  /* Add the additional features implemented by this module into the
   * list, to be displayed in response to a FEAT command.
   */
  pr_feat_add(C_CLNT);
  pr_feat_add(C_EPRT);
  pr_feat_add(C_EPSV);
  pr_feat_add(C_MDTM);
  pr_feat_add("REST STREAM");
  pr_feat_add(C_SIZE);
  pr_feat_add(C_HOST);

  pr_event_register(&core_module, "core.restart", core_restart_ev, NULL);
  pr_event_register(&core_module, "core.startup", core_startup_ev, NULL);

  return 0;
}

static const char *auth_syms[] = {
  "setpwent", "endpwent", "setgrent", "endgrent", "getpwent", "getgrent",
  "getpwnam", "getgrnam", "getpwuid", "getgrgid", "auth", "check",
  "uid2name", "gid2name", "name2uid", "name2gid", "getgroups", NULL
};

static void reset_server_auth_order(void) {
  config_rec *c = NULL;

  c = find_config(session.prev_server->conf, CONF_PARAM, "AuthOrder", FALSE);
  if (c != NULL) {
    register unsigned int i;
    unsigned int module_pri = 0;
    module *m;

    /* There was an AuthOrder applying to the previous server_rec, which
     * means we need to reset the default AuthOrder symbols.
     */

    /* Delete all auth syms. */
    for (i = 0; auth_syms[i] != NULL; i++) {
      pr_stash_remove_symbol(PR_SYM_AUTH, auth_syms[i], NULL);
    }

    /* Reload all modules' auth syms. Be sure to reset the module
     * priority while doing so.
     */
    for (m = loaded_modules; m; m = m->next) {
      if (pr_module_load_authtab(m) < 0) {
        pr_log_debug(DEBUG0,
          "error reloading auth symbols for module 'mod_%s.c': %s", m->name,
          strerror(errno));
      }

      m->priority = module_pri++;
    }
  }
}

static void set_server_auth_order(void) {
  config_rec *c = NULL;

  c = find_config(main_server->conf, CONF_PARAM, "AuthOrder", FALSE);
  if (c != NULL) {
    array_header *module_list = (array_header *) c->argv[0];
    unsigned int modulec = 0;
    char **modulev = NULL;
    register unsigned int i = 0;

    pr_log_debug(DEBUG3, "AuthOrder in effect, resetting auth module order");

    modulec = module_list->nelts;
    modulev = (char **) module_list->elts;

    /* First, delete all auth symbols. */
    for (i = 0; auth_syms[i] != NULL; i++) {
      pr_stash_remove_symbol(PR_SYM_AUTH, auth_syms[i], NULL);
    }

    /* Now, cycle through the list of configured modules, re-adding their
     * auth symbols, in the order in which they appear.
     */

    for (i = 0; i < modulec; i++) {
      module *m;
      int required = FALSE;

      /* Check for the trailing '*', indicating a required auth module. */
      if (modulev[i][strlen(modulev[i])-1] == '*') {
        required = TRUE;
        modulev[i][strlen(modulev[i])-1] = '\0';
      }

      m = pr_module_get(modulev[i]);

      if (m) {
        if (m->authtable) {
          authtable *authtab;

          /* Twiddle the module's priority field before insertion into the
           * symbol table, as the insertion operation does so based on that
           * priority.  This has no effect other than during symbol
           * insertion.
           */
          m->priority = modulec - i;

          for (authtab = m->authtable; authtab->name; authtab++) {
            authtab->m = m;

            if (required) {
              authtab->auth_flags |= PR_AUTH_FL_REQUIRED;
            }

            pr_stash_add_symbol(PR_SYM_AUTH, authtab);
          }

        } else {
          pr_log_debug(DEBUG0, "AuthOrder: warning: module '%s' is not a valid "
            "auth module (no auth handlers), authentication may fail",
            modulev[i]);
        }

      } else {
        pr_log_debug(DEBUG0, "AuthOrder: warning: module '%s' not loaded",
          modulev[i]);
      }
    }

    /* NOTE: the master conf/cmd/auth tables/arrays should ideally be
     * rebuilt after this symbol shuffling, but it's not necessary at this
     * point.
     */
  }
}

static int core_sess_init(void) {
  int timeout_idle;
  char *displayquit = NULL;
  config_rec *c = NULL;
  unsigned int *debug_level = NULL;
  unsigned long fs_opts = 0UL;

  init_auth();

  c = find_config(main_server->conf, CONF_PARAM, "MultilineRFC2228", FALSE);
  if (c != NULL) {
    session.multiline_rfc2228 = *((int *) c->argv[0]);
  }

  /* Start the idle timer. */

  c = find_config(main_server->conf, CONF_PARAM, "TimeoutIdle", FALSE);
  if (c != NULL) {
    int timeout = *((int *) c->argv[0]);
    pr_data_set_timeout(PR_DATA_TIMEOUT_IDLE, timeout);
  }

  timeout_idle = pr_data_get_timeout(PR_DATA_TIMEOUT_IDLE);
  if (timeout_idle) {
    pr_timer_add(timeout_idle, PR_TIMER_IDLE, &core_module,
      core_idle_timeout_cb, "TimeoutIdle");
  }

  /* Check for a server-specific TimeoutLinger */
  c = find_config(main_server->conf, CONF_PARAM, "TimeoutLinger", FALSE);
  if (c != NULL) {
    long timeout;

    timeout = (long) *((int *) c->argv[0]);
    pr_data_set_linger(timeout);
  }
 
  /* Check for a configured DebugLevel. */
  debug_level = get_param_ptr(main_server->conf, "DebugLevel", FALSE);
  if (debug_level != NULL) {
    pr_log_setdebuglevel(*debug_level);
  }

  c = find_config(main_server->conf, CONF_PARAM, "FSOptions", FALSE);
  while (c != NULL) {
    unsigned long opts = 0;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    fs_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "FSOptions", FALSE);
  }

  (void) pr_fsio_set_options(fs_opts);

  /* Check for any server-specific RegexOptions */
  c = find_config(main_server->conf, CONF_PARAM, "RegexOptions", FALSE);
  if (c != NULL) {
    unsigned long match_limit, match_limit_recursion;

    match_limit = *((unsigned long *) c->argv[0]);
    match_limit_recursion = *((unsigned long *) c->argv[1]);

    pr_trace_msg("regexp", 4,
      "using regex options: match limit = %lu, match limit recursion = %lu",
      match_limit, match_limit_recursion);

    pr_regexp_set_limits(match_limit, match_limit_recursion);
  }

  /* Check for configured SetEnvs. */
  c = find_config(main_server->conf, CONF_PARAM, "SetEnv", FALSE);

  while (c) {
    if (pr_env_set(session.pool, c->argv[0], c->argv[1]) < 0) {
      pr_log_debug(DEBUG1, "unable to set environment variable '%s': %s",
        (char *) c->argv[0], strerror(errno));

    } else {
      core_handle_locale_env(c->argv[0]);
    }

    c = find_config_next(c, c->next, CONF_PARAM, "SetEnv", FALSE);
  }

  /* Check for configured UnsetEnvs. */
  c = find_config(main_server->conf, CONF_PARAM, "UnsetEnv", FALSE);

  while (c) {
    if (pr_env_unset(session.pool, c->argv[0]) < 0) {
      pr_log_debug(DEBUG1, "unable to unset environment variable '%s': %s",
        (char *) c->argv[0], strerror(errno));

    } else {
      core_handle_locale_env(c->argv[0]);
    }

    c = find_config_next(c, c->next, CONF_PARAM, "UnsetEnv", FALSE);
  }

  set_server_auth_order();

#ifdef PR_USE_TRACE
  /* Handle any session-specific Trace settings. */
  c = find_config(main_server->conf, CONF_PARAM, "Trace", FALSE);
  if (c != NULL) {
    register unsigned int i;

    for (i = 0; i < c->argc; i++) {
      char *channel, *ptr;
      int min_level, max_level, res;

      pr_signals_handle();

      channel = c->argv[i];

      ptr = strchr(channel, ':');
      if (ptr == NULL) {
        pr_log_debug(DEBUG6, "skipping badly formatted '%s' setting",
          channel);
        continue;
      }

      *ptr = '\0';

      res = pr_trace_parse_levels(ptr + 1, &min_level, &max_level);
      if (res == 0) {
        res = pr_trace_set_levels(channel, min_level, max_level);
        *ptr = ':';

        if (res < 0) {
          pr_log_debug(DEBUG6, "%s: error setting levels %d-%d for "
            "channel '%s': %s", c->name, min_level, max_level, channel,
            strerror(errno));
        }

      } else {
        pr_log_debug(DEBUG6, "%s: error parsing level '%s' for channel '%s': "
          "%s", c->name, ptr + 1, channel, strerror(errno));
      }
    }
  }

  /* Handle any session-specific TraceOptions settings. */
  c = find_config(main_server->conf, CONF_PARAM, "TraceOptions", FALSE);
  if (c != NULL) {
    unsigned long trace_opts;

    trace_opts = *((unsigned long *) c->argv[0]);
    if (pr_trace_set_options(trace_opts) < 0) {
      pr_log_debug(DEBUG6, "%s: error setting TraceOptions (%lu): %s",
        c->name, trace_opts, strerror(errno));
    }
  }
#endif /* PR_USE_TRACE */

  if (ServerType == SERVER_STANDALONE) {
    pr_timer_remove(core_scrub_timer_id, &core_module);

  } else if (ServerType == SERVER_INETD) {

    /* If we're running as 'ServerType inetd', scrub the scoreboard here.
     * For standalone ServerTypes, the scoreboard scrubber will handle
     * things itself.
     */

    c = find_config(main_server->conf, CONF_PARAM, "ScoreboardScrub", FALSE);
    if (c) {
      if (*((int *) c->argv[0]) == TRUE) {
        pr_scoreboard_scrub();
      }
    }
  }

  /* Set some Variable entries for Display files. */

  if (pr_var_set(session.pool, "%{bytes_xfer}", 
      "Number of bytes transferred in this transfer", PR_VAR_TYPE_FUNC,
      (void *) core_get_xfer_bytes_str, &session.xfer.total_bytes,
      sizeof(off_t *)) < 0) {
    pr_log_debug(DEBUG6, "error setting %%{bytes_fer} variable: %s",
      strerror(errno));
  }

  if (pr_var_set(session.pool, "%{total_bytes_in}",
      "Number of bytes uploaded during a session", PR_VAR_TYPE_FUNC,
      (void *) core_get_sess_bytes_str, &session.total_bytes_in,
      sizeof(off_t *)) < 0) {
    pr_log_debug(DEBUG6, "error setting %%{total_bytes_in} variable: %s",
      strerror(errno));
  }

  if (pr_var_set(session.pool, "%{total_bytes_out}", 
      "Number of bytes downloaded during a session", PR_VAR_TYPE_FUNC,
      (void *) core_get_sess_bytes_str, &session.total_bytes_out,
      sizeof(off_t *)) < 0) {
    pr_log_debug(DEBUG6, "error setting %%{total_bytes_out} variable: %s",
      strerror(errno));
  }

  if (pr_var_set(session.pool, "%{total_bytes_xfer}", 
      "Number of bytes transferred during a session", PR_VAR_TYPE_FUNC,
      (void *) core_get_sess_bytes_str, &session.total_bytes,
      sizeof(off_t *)) < 0) {
    pr_log_debug(DEBUG6, "error setting %%{total_bytes_fer} variable: %s",
      strerror(errno));
  }

  if (pr_var_set(session.pool, "%{total_files_in}", 
      "Number of files uploaded during a session", PR_VAR_TYPE_FUNC,
      (void *) core_get_sess_files_str, &session.total_files_in,
      sizeof(unsigned int *)) < 0) {
    pr_log_debug(DEBUG6, "error setting %%{total_files_in} variable: %s",
      strerror(errno));
  }

  if (pr_var_set(session.pool, "%{total_files_out}", 
      "Number of files downloaded during a session", PR_VAR_TYPE_FUNC,
      (void *) core_get_sess_files_str, &session.total_files_out,
      sizeof(unsigned int *)) < 0) {
    pr_log_debug(DEBUG6, "error setting %%{total_files_out} variable: %s",
      strerror(errno));
  }

  if (pr_var_set(session.pool, "%{total_files_xfer}", 
      "Number of files transferred during a session", PR_VAR_TYPE_FUNC,
      (void *) core_get_sess_files_str, &session.total_files_xfer,
      sizeof(unsigned int *)) < 0) {
    pr_log_debug(DEBUG6, "error setting %%{total_files_xfer} variable: %s",
      strerror(errno));
  }

  /* Look for a DisplayQuit file which has an absolute path.  If we
   * find one, open a filehandle, such that that file can be displayed
   * even if the session is chrooted.  DisplayQuit files with
   * relative paths will be handled after chroot, preserving the old
   * behavior.
   */
  displayquit = get_param_ptr(TOPLEVEL_CONF, "DisplayQuit", FALSE);
  if (displayquit &&
      *displayquit == '/') {
    struct stat st;

    displayquit_fh = pr_fsio_open(displayquit, O_RDONLY);
    if (displayquit_fh == NULL) {
      pr_log_debug(DEBUG6, "unable to open DisplayQuit file '%s': %s",
        displayquit, strerror(errno));

    } else {
      if (pr_fsio_fstat(displayquit_fh, &st) < 0) {
        pr_log_debug(DEBUG6, "unable to stat DisplayQuit file '%s': %s",
          displayquit, strerror(errno));
        pr_fsio_close(displayquit_fh);
        displayquit_fh = NULL;

      } else {
        if (S_ISDIR(st.st_mode)) {
          errno = EISDIR;
          pr_log_debug(DEBUG6, "unable to use DisplayQuit file '%s': %s",
            displayquit, strerror(errno));
          pr_fsio_close(displayquit_fh);
          displayquit_fh = NULL;
        }
      }
    }
  }

  /* Check for any ProcessTitles setting. */
  c = find_config(main_server->conf, CONF_PARAM, "ProcessTitles", FALSE);
  if (c) {
    char *verbosity;
 
    verbosity = c->argv[0];
    if (strcasecmp(verbosity, "terse") == 0) {
      pr_proctitle_set_static_str("proftpd: processing connection");
    }
  }

  return 0;
}

/* Module API tables
 */

static conftable core_conftab[] = {
  { "<Anonymous>",		add_anonymous,			NULL },
  { "</Anonymous>",		end_anonymous,			NULL },
  { "<Class>",			add_class,			NULL },
  { "</Class>",			end_class,			NULL },
  { "<Directory>",		add_directory,			NULL },
  { "</Directory>",		end_directory,			NULL },
  { "<Global>",			add_global,			NULL },
  { "</Global>",		end_global,			NULL },
  { "<IfDefine>",		start_ifdefine,			NULL },
  { "</IfDefine>",		end_ifdefine,			NULL },
  { "<IfModule>",		start_ifmodule,			NULL },
  { "</IfModule>",		end_ifmodule,			NULL },
  { "<Limit>",			add_limit,			NULL },
  { "</Limit>", 		end_limit, 			NULL },
  { "<VirtualHost>",		add_virtualhost,		NULL },
  { "</VirtualHost>",		end_virtualhost,		NULL },
  { "Allow",			set_allowdeny,			NULL },
  { "AllowAll",			set_allowall,			NULL },
  { "AllowClass",		set_allowdenyusergroupclass,	NULL },
  { "AllowFilter",		set_allowdenyfilter,		NULL },
  { "AllowForeignAddress",	set_allowforeignaddress,	NULL },
  { "AllowGroup",		set_allowdenyusergroupclass,	NULL },
  { "AllowOverride",		set_allowoverride,		NULL },
  { "AllowUser",		set_allowdenyusergroupclass,	NULL },
  { "AuthOrder",		set_authorder,			NULL },
  { "CDPath",			set_cdpath,			NULL },
  { "CommandBufferSize",	set_commandbuffersize,		NULL },
  { "DebugLevel",		set_debuglevel,			NULL },
  { "DefaultAddress",		set_defaultaddress,		NULL },
  { "DefaultServer",		set_defaultserver,		NULL },
  { "DeferWelcome",		set_deferwelcome,		NULL },
  { "Define",			set_define,			NULL },
  { "Deny",			set_allowdeny,			NULL },
  { "DenyAll",			set_denyall,			NULL },
  { "DenyClass",		set_allowdenyusergroupclass,	NULL },
  { "DenyFilter",		set_allowdenyfilter,		NULL },
  { "DenyGroup",		set_allowdenyusergroupclass,	NULL },
  { "DenyUser",			set_allowdenyusergroupclass,	NULL },
  { "DisplayChdir",		set_displaychdir,		NULL },
  { "DisplayConnect",		set_displayconnect,		NULL },
  { "DisplayQuit",		set_displayquit,		NULL },
  { "From",			add_from,			NULL },
  { "FSCachePolicy",		set_fscachepolicy,		NULL },
  { "FSOptions",		set_fsoptions,			NULL },
  { "Group",			set_group, 			NULL },
  { "GroupOwner",		add_groupowner,			NULL },
  { "HideFiles",		set_hidefiles,			NULL },
  { "HideGroup",		set_hidegroup,			NULL },
  { "HideNoAccess",		set_hidenoaccess,		NULL },
  { "HideUser",			set_hideuser,			NULL },
  { "IgnoreHidden",		set_ignorehidden,		NULL },
  { "Include",			set_include,	 		NULL },
  { "IncludeOptions",		set_includeoptions, 		NULL },
  { "MasqueradeAddress",	set_masqueradeaddress,		NULL },
  { "MaxCommandRate",		set_maxcommandrate,		NULL },
  { "MaxConnectionRate",	set_maxconnrate,		NULL },
  { "MaxInstances",		set_maxinstances,		NULL },
  { "MultilineRFC2228",		set_multilinerfc2228,		NULL },
  { "Order",			set_order,			NULL },
  { "PassivePorts",		set_passiveports,		NULL },
  { "PathAllowFilter",		set_pathallowfilter,		NULL },
  { "PathDenyFilter",		set_pathdenyfilter,		NULL },
  { "PidFile",			set_pidfile,	 		NULL },
  { "Port",			set_serverport, 		NULL },
  { "ProcessTitles",		set_processtitles,		NULL },
  { "Protocols",		set_protocols,			NULL },
  { "RegexOptions",		set_regexoptions,		NULL },
  { "Satisfy",			set_satisfy,			NULL },
  { "ScoreboardFile",		set_scoreboardfile,		NULL },
  { "ScoreboardMutex",		set_scoreboardmutex,		NULL },
  { "ScoreboardScrub",		set_scoreboardscrub,		NULL },
  { "ServerAdmin",		set_serveradmin,		NULL },
  { "ServerAlias",		set_serveralias,		NULL },
  { "ServerIdent",		set_serverident,		NULL },
  { "ServerName",		set_servername, 		NULL },
  { "ServerType",		set_servertype,			NULL },
  { "SetEnv",			set_setenv,			NULL },
  { "SocketBindTight",		set_socketbindtight,		NULL },
  { "SocketOptions",		set_socketoptions,		NULL },
  { "SyslogFacility",		set_syslogfacility,		NULL },
  { "SyslogLevel",		set_sysloglevel,		NULL },
  { "TimeoutIdle",		set_timeoutidle,		NULL },
  { "TimeoutLinger",		set_timeoutlinger,		NULL },
  { "TimesGMT",			set_timesgmt,			NULL },
  { "Trace",			set_trace,			NULL },
  { "TraceLog",			set_tracelog,			NULL },
  { "TraceOptions",		set_traceoptions,		NULL },
  { "TransferLog",		add_transferlog,		NULL },
  { "Umask",			set_umask,			NULL },
  { "UnsetEnv",			set_unsetenv,			NULL },
  { "UseIPv6",			set_useipv6,			NULL },
  { "UseReverseDNS",		set_usereversedns,		NULL },
  { "User",			set_user,			NULL },
  { "UserOwner",		add_userowner,			NULL },
  { "TCPBackLog",		set_tcpbacklog,			NULL },
  { "TCPNoDelay",		set_tcpnodelay,			NULL },

  { NULL, NULL, NULL }
};

static cmdtable core_cmdtab[] = {
#ifdef PR_USE_REGEX
  { PRE_CMD, C_ANY, G_NONE,  regex_filters, FALSE, FALSE, CL_NONE },
#endif
  { PRE_CMD, C_ANY, G_NONE, core_pre_any,FALSE, FALSE, CL_NONE },
  { CMD, C_HELP, G_NONE,  core_help,	FALSE,	FALSE, CL_INFO },
  { CMD, C_PORT, G_NONE,  core_port,	TRUE,	FALSE, CL_MISC },
  { CMD, C_PASV, G_NONE,  core_pasv,	TRUE,	FALSE, CL_MISC },
  { CMD, C_EPRT, G_NONE,  core_eprt,    TRUE,	FALSE, CL_MISC },
  { CMD, C_EPSV, G_NONE,  core_epsv,	TRUE,	FALSE, CL_MISC },
  { CMD, C_SYST, G_NONE,  core_syst,	FALSE,	FALSE, CL_INFO },
  { CMD, C_PWD,	 G_DIRS,  core_pwd,	TRUE,	FALSE, CL_INFO|CL_DIRS },
  { CMD, C_XPWD, G_DIRS,  core_pwd,	TRUE,	FALSE, CL_INFO|CL_DIRS },
  { CMD, C_CWD,	 G_DIRS,  core_cwd,	TRUE,	FALSE, CL_DIRS },
  { CMD, C_XCWD, G_DIRS,  core_cwd,	TRUE,	FALSE, CL_DIRS },
  { CMD, C_MKD,	 G_WRITE, core_mkd,	TRUE,	FALSE, CL_DIRS|CL_WRITE },
  { CMD, C_XMKD, G_WRITE, core_mkd,	TRUE,	FALSE, CL_DIRS|CL_WRITE },
  { CMD, C_RMD,	 G_WRITE, core_rmd,	TRUE,	FALSE, CL_DIRS|CL_WRITE },
  { CMD, C_XRMD, G_WRITE, core_rmd,	TRUE,	FALSE, CL_DIRS|CL_WRITE },
  { CMD, C_CDUP, G_DIRS,  core_cdup,	TRUE,	FALSE, CL_DIRS },
  { CMD, C_XCUP, G_DIRS,  core_cdup,	TRUE,	FALSE, CL_DIRS },
  { CMD, C_DELE, G_WRITE, core_dele,	TRUE,	FALSE, CL_WRITE },
  { CMD, C_MDTM, G_DIRS,  core_mdtm,	TRUE,	FALSE, CL_INFO|CL_DIRS },
  { CMD, C_RNFR, G_WRITE, core_rnfr,	TRUE,	FALSE, CL_MISC|CL_WRITE },
  { CMD, C_RNTO, G_WRITE, core_rnto,	TRUE,	FALSE, CL_MISC|CL_WRITE },
  { LOG_CMD,     C_RNTO, G_NONE, core_rnto_cleanup, TRUE, FALSE, CL_NONE },
  { LOG_CMD_ERR, C_RNTO, G_NONE, core_rnto_cleanup, TRUE, FALSE, CL_NONE },
  { CMD, C_SIZE, G_READ,  core_size,	TRUE,	FALSE, CL_INFO },
  { CMD, C_QUIT, G_NONE,  core_quit,	FALSE,	FALSE,  CL_INFO },
  { LOG_CMD, 	 C_QUIT, G_NONE, core_log_quit, FALSE, FALSE },
  { LOG_CMD_ERR, C_QUIT, G_NONE, core_log_quit, FALSE, FALSE },
  { CMD, C_NOOP, G_NONE,  core_noop,	FALSE,	FALSE,  CL_MISC },
  { CMD, C_FEAT, G_NONE,  core_feat,	FALSE,	FALSE,  CL_INFO },
  { CMD, C_OPTS, G_NONE,  core_opts,    FALSE,	FALSE,	CL_MISC },
  { CMD, C_HOST, G_NONE,  core_host,    FALSE,	FALSE,	CL_MISC },
  { POST_CMD, C_PASS, G_NONE, core_post_pass, FALSE, FALSE },
  { CMD, C_HOST, G_NONE,  core_host,	FALSE,	FALSE,	CL_AUTH },
  { POST_CMD, C_HOST, G_NONE, core_post_host, FALSE, FALSE },
  { CMD, C_CLNT, G_NONE,  core_clnt,	FALSE,	FALSE,	CL_INFO },

  { 0, NULL }
};

module core_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "core",

  /* Module configuration directive table */
  core_conftab,

  /* Module command handler table */
  core_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  core_init,

  /* Session initialization function */
  core_sess_init
};
