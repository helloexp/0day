/*
 * ProFTPD: mod_memcache -- a module for managing memcache data
 * Copyright (c) 2010-2016 The ProFTPD Project
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
 * $Libraries: -lmemcached -lmemcachedutil$
 */

#include "conf.h"
#include "privs.h"
#include <libmemcached/memcached.h>

#define MOD_MEMCACHE_VERSION		"mod_memcache/0.1"

#if PROFTPD_VERSION_NUMBER < 0x0001030401
# error "ProFTPD 1.3.4rc1 or later required"
#endif

extern xaset_t *server_list;

module memcache_module;

static int memcache_logfd = -1;
static pool *memcache_pool = NULL;
static array_header *memcache_server_lists = NULL;

static void mcache_exit_ev(const void *, void *);
static int mcache_sess_init(void);

/* Configuration handlers
 */

/* usage: MemcacheConnectFailures count */
MODRET set_memcacheconnectfailures(cmd_rec *cmd) {
  char *ptr = NULL;
  config_rec *c;
  uint64_t count = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

#ifdef HAVE_STRTOULL
  count = strtoull(cmd->argv[1], &ptr, 10);
#else
  count = strtoul(cmd->argv[1], &ptr, 10);
#endif /* HAVE_STRTOULL */

  if (ptr &&
      *ptr) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad connect failures parameter: ",
      cmd->argv[1], NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(uint64_t));
  *((uint64_t *) c->argv[0]) = count;

  return PR_HANDLED(cmd);
}

/* usage: MemcacheEngine on|off */
MODRET set_memcacheengine(cmd_rec *cmd) {
  int b = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  b = get_boolean(cmd, 1);
  if (b == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = b;

  return PR_HANDLED(cmd);
}

/* usage: MemcacheLog path|"none" */
MODRET set_memcachelog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "none") != 0 &&
      pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: MemcacheOptions opt1 opt2 ... */
MODRET set_memcacheoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "NoBinaryProtocol") == 0) {
      opts |= PR_MEMCACHE_FL_NO_BINARY_PROTOCOL;

    } else if (strcmp(cmd->argv[i], "NoRandomReplicaReads") == 0) {
      opts |= PR_MEMCACHE_FL_NO_RANDOM_REPLICA_READ;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown MemcacheOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: MemcacheReplicas count */
MODRET set_memcachereplicas(cmd_rec *cmd) {
  char *ptr = NULL;
  config_rec *c;
  uint64_t count = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

#ifdef HAVE_STRTOULL
  count = strtoull(cmd->argv[1], &ptr, 10);
#else
  count = strtoul(cmd->argv[1], &ptr, 10);
#endif /* HAVE_STRTOULL */

  if (ptr &&
      *ptr) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad replica parameter: ",
      cmd->argv[1], NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(uint64_t));
  *((uint64_t *) c->argv[0]) = count;

  return PR_HANDLED(cmd);
}

/* usage: MemcacheServers host1[:port1] ... */
MODRET set_memcacheservers(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  char *str = "";
  int ctxt;
  memcached_server_st *memcache_servers = NULL;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);
  for (i = 1; i < cmd->argc; i++) {
    str = pstrcat(cmd->pool, str, *str ? ", " : "", cmd->argv[i], NULL);
  }

  memcache_servers = memcached_servers_parse(str);
  if (memcache_servers == NULL) {
    CONF_ERROR(cmd, "unable to parse server parameters");
  }

  ctxt = (cmd->config && cmd->config->config_type != CONF_PARAM ?
    cmd->config->config_type : cmd->server->config_type ?
    cmd->server->config_type : CONF_ROOT);

  if (ctxt == CONF_ROOT) {
    /* If we're the "server config" context, set the server list now.  This
     * would let mod_memcache talk to those servers for e.g. ftpdctl actions.
     */
    memcache_set_servers(memcache_servers);
  }

  c->argv[0] = memcache_servers;

  /* Add the libmemcached-allocated pointer to a list, for later freeing. */
  *((memcached_server_st **) push_array(memcache_server_lists)) = memcache_servers;
  return PR_HANDLED(cmd);
}

/* usage: MemcacheTimeouts conn-timeout read-timeout write-timeout
 *                         [ejected-timeout]
 */
MODRET set_memcachetimeouts(cmd_rec *cmd) {
  config_rec *c;
  unsigned long conn_millis, read_millis, write_millis, ejected_sec = 0;
  char *ptr = NULL;

  if (cmd->argc-1 < 3 ||
      cmd->argc-1 > 4) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  conn_millis = strtoul(cmd->argv[1], &ptr, 10);
  if (ptr && *ptr) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "badly formatted connect timeout value: ", cmd->argv[1], NULL));
  }

  ptr = NULL;
  read_millis = strtoul(cmd->argv[2], &ptr, 10);
  if (ptr && *ptr) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "badly formatted read timeout value: ", cmd->argv[2], NULL));
  }

  ptr = NULL;
  write_millis = strtoul(cmd->argv[3], &ptr, 10);
  if (ptr && *ptr) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "badly formatted write timeout value: ", cmd->argv[3], NULL));
  }

  if (cmd->argc-1 == 4) {
    ptr = NULL;
    ejected_sec = strtoul(cmd->argv[4], &ptr, 10);
    if (ptr && *ptr) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "badly formatted retry timeout value: ", cmd->argv[4], NULL));
    }
  }

#if 0
  /* XXX If we're the "server config" context, set the timeouts now.
   * This would let mod_memcache talk to those servers for e.g. ftpdctl
   * actions.
   */
  memcache_set_timeouts(conn_timeout, read_timeout, write_timeout,
    ejected_sec);
#endif

  c = add_config_param(cmd->argv[0], 4, NULL, NULL, NULL, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = conn_millis;
  c->argv[1] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[1]) = read_millis;
  c->argv[2] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[2]) = write_millis;
  c->argv[3] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[3]) = ejected_sec;

  return PR_HANDLED(cmd);
}

/* Event handlers
 */

static void mcache_exit_ev(const void *event_data, void *user_data) {
  memcache_clear();
}

static void mcache_restart_ev(const void *event_data, void *user_data) {
  register unsigned int i;
  memcached_server_st **mcache_servers = NULL;

  mcache_servers = memcache_server_lists->elts;
  for (i = 0; i < memcache_server_lists->nelts; i++) {
    memcached_server_list_free(mcache_servers[i]);
  }

  /* Make sure to clear the pointer in the Memcache API as well, to prevent
   * a dangling pointer situation.
   */
  memcache_set_servers(NULL);

  /* Now we can recycle the mod_memcache pool and its associated resources. */
  destroy_pool(memcache_pool);

  memcache_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(memcache_pool, MOD_MEMCACHE_VERSION);

  memcache_server_lists = make_array(memcache_pool, 2,
    sizeof(memcached_server_st **));
}

static void mcache_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;
  config_rec *c;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&memcache_module, "core.exit", mcache_exit_ev);
  pr_event_unregister(&memcache_module, "core.session-reinit",
    mcache_sess_reinit_ev);

  (void) close(memcache_logfd);
  memcache_logfd = -1;

  c = find_config(session.prev_server->conf, CONF_PARAM, "MemcacheServers",
    FALSE);
  if (c != NULL) {
    memcached_server_st *memcache_servers;

    memcache_servers = c->argv[0];
    memcache_set_servers(memcache_servers);
  }

  /* XXX Restore other memcache settings? */
  /* reset MemcacheOptions */
  /* reset MemcacheReplicas */
  /* reset MemcacheTimeout */

  res = mcache_sess_init();
  if (res < 0) {
    pr_session_disconnect(&memcache_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Initialization functions
 */

static int mcache_init(void) {
  const char *version;

  memcache_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(memcache_pool, MOD_MEMCACHE_VERSION);

  memcache_server_lists = make_array(memcache_pool, 2,
    sizeof(memcached_server_st **));

  memcache_init();

  pr_event_register(&memcache_module, "core.restart", mcache_restart_ev, NULL);

  version = memcached_lib_version();
  if (strcmp(version, LIBMEMCACHED_VERSION_STRING) != 0) {
    pr_log_pri(PR_LOG_INFO, MOD_MEMCACHE_VERSION
      ": compiled using libmemcached-%s headers, but linked to "
      "libmemcached-%s library", LIBMEMCACHED_VERSION_STRING, version);

  } else {
    pr_log_debug(DEBUG2, MOD_MEMCACHE_VERSION ": using libmemcached-%s",
      version);
  }

  return 0;
}

static int mcache_sess_init(void) {
  config_rec *c;

  pr_event_register(&memcache_module, "core.session-reinit",
    mcache_sess_reinit_ev, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "MemcacheEngine", FALSE);
  if (c) {
    int engine;

    engine = *((int *) c->argv[0]);
    if (engine == FALSE) {
      /* Explicitly disable memcache support for this session */
      memcache_set_servers(NULL);
      return 0;
    }
  }

  pr_event_register(&memcache_module, "core.exit", mcache_exit_ev, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "MemcacheLog", FALSE);
  if (c) {
    const char *path;

    path = c->argv[0];
    if (strcasecmp(path, "none") != 0) {
      int res, xerrno;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(path, &memcache_logfd, PR_LOG_SYSTEM_MODE);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      switch (res) {
        case 0:
          break;

        case -1:
          pr_log_pri(PR_LOG_NOTICE, MOD_MEMCACHE_VERSION
            ": notice: unable to open MemcacheLog '%s': %s", path,
            strerror(xerrno));
          break;

        case PR_LOG_WRITABLE_DIR:
          pr_log_pri(PR_LOG_WARNING, MOD_MEMCACHE_VERSION
            ": notice: unable to use MemcacheLog '%s': parent directory is "
              "world-writable", path);
          break;

        case PR_LOG_SYMLINK:
          pr_log_pri(PR_LOG_WARNING, MOD_MEMCACHE_VERSION
            ": notice: unable to use MemcacheLog '%s': cannot log to a symlink",
            path);
          break;
      }
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "MemcacheServers", FALSE);
  if (c) {
    memcached_server_st *memcache_servers;

    memcache_servers = c->argv[0]; 
    memcache_set_servers(memcache_servers);
  }

  c = find_config(main_server->conf, CONF_PARAM, "MemcacheOptions", FALSE);
  if (c) {
    unsigned long flags;

    flags = *((unsigned long *) c->argv[0]);

    if (memcache_set_sess_flags(flags) < 0) {
      (void) pr_log_writefile(memcache_logfd, MOD_MEMCACHE_VERSION,
        "error setting memcache flags: %s", strerror(errno));
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "MemcacheReplicas", FALSE);
  if (c) {
    uint64_t count;

    count = *((uint64_t *) c->argv[0]);

    if (memcache_set_sess_replicas(count) < 0) {
      (void) pr_log_writefile(memcache_logfd, MOD_MEMCACHE_VERSION,
        "error setting memcache replicas: %s", strerror(errno));
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "MemcacheTimeouts", FALSE);
  if (c) {
    unsigned long conn_millis, read_millis, write_millis, retry_sec;

    conn_millis = *((unsigned long *) c->argv[0]);
    read_millis = *((unsigned long *) c->argv[1]);
    write_millis = *((unsigned long *) c->argv[2]);
    retry_sec = *((unsigned long *) c->argv[3]);

    if (memcache_set_timeouts(conn_millis, read_millis, write_millis,
        retry_sec) < 0) {
      (void) pr_log_writefile(memcache_logfd, MOD_MEMCACHE_VERSION,
        "error setting memcache timeouts: %s", strerror(errno));
    }
  }

  return 0;
}

/* Module API tables
 */

static conftable memcache_conftab[] = {
  { "MemcacheConnectFailures",	set_memcacheconnectfailures,	NULL },
  { "MemcacheEngine",		set_memcacheengine,		NULL },
  { "MemcacheLog",		set_memcachelog,		NULL },
  { "MemcacheOptions",		set_memcacheoptions,		NULL },
  { "MemcacheReplicas",		set_memcachereplicas,		NULL },
  { "MemcacheServers",		set_memcacheservers,		NULL },
  { "MemcacheTimeouts",		set_memcachetimeouts,		NULL },
 
  { NULL }
};

module memcache_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "memcache",

  /* Module configuration handler table */
  memcache_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  mcache_init,

  /* Session initialization function */
  mcache_sess_init,

  /* Module version */
  MOD_MEMCACHE_VERSION
};
