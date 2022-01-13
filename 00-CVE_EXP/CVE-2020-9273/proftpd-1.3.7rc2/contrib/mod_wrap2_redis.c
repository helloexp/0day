/*
 * ProFTPD: mod_wrap2_redis -- a mod_wrap2 sub-module for supplying IP-based
 *                             access control data via Redis
 * Copyright (c) 2017 TJ Saunders
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
 * As a special exemption, TJ Saunders gives permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

#include "mod_wrap2.h"
#include "redis.h"

#define MOD_WRAP2_REDIS_VERSION		"mod_wrap2_redis/0.1"

#define WRAP2_REDIS_NKEYS		2
#define WRAP2_REDIS_CLIENT_KEY_IDX	0
#define WRAP2_REDIS_OPTION_KEY_IDX	1

module wrap2_redis_module;

static char *get_named_key(pool *p, char *key, const char *name) {
  if (name == NULL) {
    return key;
  }

  if (strstr(key, "%{name}") != NULL) {
    key = (char *) sreplace(p, key, "%{name}", name, NULL);
  }

  return key;
}

static int redistab_close_cb(wrap2_table_t *redistab) {
  pr_redis_t *redis;

  redis = redistab->tab_handle;

  (void) pr_redis_conn_close(redis);
  redistab->tab_handle = NULL;
  return 0;
}

static array_header *redistab_fetch_clients_cb(wrap2_table_t *redistab,
    const char *name) {
  register unsigned int i;
  pool *tmp_pool = NULL;
  pr_redis_t *redis;
  char *key = NULL, **vals = NULL;
  array_header *items = NULL, *itemszs = NULL, *clients = NULL;
  int res, xerrno = 0, use_list = TRUE;

  /* Allocate a temporary pool for the duration of this read. */
  tmp_pool = make_sub_pool(redistab->tab_pool);

  key = ((char **) redistab->tab_data)[WRAP2_REDIS_CLIENT_KEY_IDX];

  if (strncasecmp(key, "list:", 5) == 0) {
    key += 5;

  } else if (strncasecmp(key, "set:", 4) == 0) {
    use_list = FALSE;
    key += 4;
  }

  key = get_named_key(tmp_pool, key, name);
  redis = redistab->tab_handle;

  if (use_list == TRUE) {
    res = pr_redis_list_getall(tmp_pool, redis, &wrap2_redis_module, key,
      &items, &itemszs);
    xerrno = errno;

  } else {
    res = pr_redis_set_getall(tmp_pool, redis, &wrap2_redis_module, key,
      &items, &itemszs);
    xerrno = errno;
  }

  /* Check the results. */
  if (res < 0) {
    if (use_list == TRUE) {
      wrap2_log("error obtaining clients from Redis using list '%s': %s",
        key, strerror(xerrno));

    } else {
      wrap2_log("error obtaining clients from Redis using set '%s': %s",
        key, strerror(xerrno));
    }

    destroy_pool(tmp_pool);
    errno = xerrno;
    return NULL;
  }

  if (items->nelts < 1) {
    if (use_list == TRUE) {
      wrap2_log("no clients found in Redis using list '%s'", key);

    } else {
      wrap2_log("no clients found in Redis using set '%s'", key);
    }

    destroy_pool(tmp_pool);
    errno = ENOENT;
    return NULL;
  }

  clients = make_array(redistab->tab_pool, items->nelts, sizeof(char *));

  /* Iterate through each returned row.  If there are commas or whitespace
   * in the row, parse them as separate client names.  Otherwise, a comma-
   * or space-delimited list of names will be treated as a single name, and
   * violate the principle of least surprise for the site admin.
   */

  vals = (char **) items->elts;

  for (i = 0; i < items->nelts; i++) {
    char *ptr, *val;

    if (vals[i] == NULL) {
      continue;
    }

    val = vals[i];

    /* Values in Redis are NOT NUL-terminated. */
    val = pstrndup(tmp_pool, val, ((size_t *) itemszs->elts)[i]);

    ptr = strpbrk(val, ", \t");
    if (ptr != NULL) {
      char *dup_opts, *word;

      dup_opts = pstrdup(redistab->tab_pool, val);
      while ((word = pr_str_get_token(&dup_opts, ", \t")) != NULL) {
        size_t wordlen;

        pr_signals_handle();

        wordlen = strlen(word);
        if (wordlen == 0) {
          continue;
        }

        /* Remove any trailing comma */
        if (word[wordlen-1] == ',') {
          word[wordlen-1] = '\0';
          wordlen--;
        }

        *((char **) push_array(clients)) = word;

        /* Skip redundant whitespaces */
        while (*dup_opts == ' ' ||
               *dup_opts == '\t') {
          pr_signals_handle();
          dup_opts++;
        }
      }

    } else {
      *((char **) push_array(clients)) = pstrdup(redistab->tab_pool, val);
    }
  }

  destroy_pool(tmp_pool);
  return clients;
}

static array_header *redistab_fetch_daemons_cb(wrap2_table_t *redistab,
    const char *name) {
  array_header *daemons_list;

  /* Simply return the service name we're given. */
  daemons_list = make_array(redistab->tab_pool, 1, sizeof(char *));
  *((char **) push_array(daemons_list)) = pstrdup(redistab->tab_pool, name);

  return daemons_list;
}

static array_header *redistab_fetch_options_cb(wrap2_table_t *redistab,
    const char *name) {
  register unsigned int i;
  pool *tmp_pool = NULL;
  pr_redis_t *redis;
  char *key = NULL, **vals = NULL;
  array_header *items = NULL, *itemszs = NULL, *options = NULL;
  int res, xerrno = 0, use_list = TRUE;

  /* Allocate a temporary pool for the duration of this read. */
  tmp_pool = make_sub_pool(redistab->tab_pool);

  key = ((char **) redistab->tab_data)[WRAP2_REDIS_OPTION_KEY_IDX];

  /* The options key is not necessary.  Skip if not present. */
  if (key == NULL) {
    destroy_pool(tmp_pool);
    return NULL;
  }

  if (strncasecmp(key, "list:", 5) == 0) {
    key += 5;

  } else if (strncasecmp(key, "set:", 4) == 0) {
    use_list = FALSE;
    key += 4;
  }

  key = get_named_key(tmp_pool, key, name);
  redis = redistab->tab_handle;

  if (use_list == TRUE) {
    res = pr_redis_list_getall(tmp_pool, redis, &wrap2_redis_module, key,
      &items, &itemszs);
    xerrno = errno;

  } else {
    res = pr_redis_set_getall(tmp_pool, redis, &wrap2_redis_module, key,
      &items, &itemszs);
    xerrno = errno;
  }

  /* Check the results. */
  if (res < 0) {
    if (use_list == TRUE) {
      wrap2_log("error obtaining options from Redis using list '%s': %s",
        key, strerror(xerrno));

    } else {
      wrap2_log("error obtaining options from Redis using set '%s': %s",
        key, strerror(xerrno));
    }

    destroy_pool(tmp_pool);
    errno = xerrno;
    return NULL;
  }

  if (items->nelts < 1) {
    if (use_list == TRUE) {
      wrap2_log("no options found in Redis using list '%s'", key);

    } else {
      wrap2_log("no options found in Redis using set '%s'", key);
    }

    destroy_pool(tmp_pool);
    errno = ENOENT;
    return NULL;
  }

  options = make_array(redistab->tab_pool, items->nelts, sizeof(char *));

  vals = (char **) items->elts;

  for (i = 0; i < items->nelts; i++) {
    char *val;

    if (vals[i] == NULL) {
      continue;
    }

    /* Values in Redis are NOT NUL-terminated. */
    val = pstrndup(tmp_pool, vals[i], ((size_t *) itemszs->elts)[i]);

    *((char **) push_array(options)) = pstrdup(redistab->tab_pool, val);
  }

  destroy_pool(tmp_pool);
  return options;
}

static wrap2_table_t *redistab_open_cb(pool *parent_pool, const char *srcinfo) {
  wrap2_table_t *tab = NULL;
  pool *tab_pool = make_sub_pool(parent_pool),
    *tmp_pool = make_sub_pool(parent_pool);
  char *start = NULL, *finish = NULL, *info;
  char *client_key = NULL, *option_key = NULL;
  pr_redis_t *redis;

  tab = (wrap2_table_t *) pcalloc(tab_pool, sizeof(wrap2_table_t));
  tab->tab_pool = tab_pool;

  /* The srcinfo string for this case should look like:
   *  "/list|set:<client-key>[/list|set:<options-key>]"
   */

  info = pstrdup(tmp_pool, srcinfo);
  start = strchr(info, '/');
  if (start == NULL) {
    wrap2_log("error: badly formatted source info '%s'", srcinfo);
    destroy_pool(tab_pool);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return NULL;
  }

  /* Find the next slash. */
  finish = strchr(++start, '/');
  if (finish != NULL) {
    *finish = '\0';
  }

  client_key = pstrdup(tab->tab_pool, start);

  /* Handle the options list, if present. */
  if (finish != NULL) {
    option_key = pstrdup(tab->tab_pool, ++finish);
  }

  if (strncasecmp(client_key, "list:", 5) != 0 &&
      strncasecmp(client_key, "set:", 4) != 0) {
    wrap2_log("error: client key '%s' lacks required 'list:' or 'set:' prefix",
      client_key);
    destroy_pool(tab_pool);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return NULL;
  }

  if (option_key != NULL) {
    if (strncasecmp(option_key, "list:", 5) != 0 &&
        strncasecmp(option_key, "set:", 4) != 0) {
      wrap2_log("error: option key '%s' lacks required 'list:' or 'set:' "
        "prefix", option_key);
      destroy_pool(tab_pool);
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return NULL;
    }
  }

  redis = pr_redis_conn_new(tab->tab_pool, &wrap2_redis_module, 0);
  if (redis == NULL) {
    int xerrno = errno;

    wrap2_log("error: unable to open Redis connection: %s", strerror(xerrno));
    destroy_pool(tab_pool);
    destroy_pool(tmp_pool);
    errno = xerrno;
    return NULL;
  }

  tab->tab_handle = redis;
  tab->tab_name = pstrcat(tab->tab_pool, "Redis(", info, ")", NULL);

  tab->tab_data = pcalloc(tab->tab_pool, WRAP2_REDIS_NKEYS * sizeof(char *));
  ((char **) tab->tab_data)[WRAP2_REDIS_CLIENT_KEY_IDX] =
    pstrdup(tab->tab_pool, client_key);

  ((char **) tab->tab_data)[WRAP2_REDIS_OPTION_KEY_IDX] =
    pstrdup(tab->tab_pool, option_key);

  /* Set the necessary callbacks. */
  tab->tab_close = redistab_close_cb;
  tab->tab_fetch_clients = redistab_fetch_clients_cb;
  tab->tab_fetch_daemons = redistab_fetch_daemons_cb;
  tab->tab_fetch_options = redistab_fetch_options_cb;

  destroy_pool(tmp_pool);
  return tab;
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void redistab_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_wrap2_redis.c", (const char *) event_data) == 0) {
    pr_event_unregister(&wrap2_redis_module, NULL, NULL);
    wrap2_unregister("redis");
  }
}
#endif /* PR_SHARED_MODULE */

/* Initialization routines
 */

static int redistab_init(void) {

  /* Initialize the wrap source objects for type "redis".  */
  wrap2_register("redis", redistab_open_cb);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&wrap2_redis_module, "core.module-unload",
    redistab_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  return 0;
}

static int redistab_sess_init(void) {
  config_rec *c;
  int engine;

  c = find_config(main_server->conf, CONF_PARAM, "RedisEngine", FALSE);
  if (c == NULL) {
    return 0;
  }

  engine = *((int *) c->argv[0]);
  if (engine == FALSE) {
    return 0;
  }

  /* Note: These lookups duplicate what mod_redis does.  But we do it here
   * due to module load ordering; we want to make sure that Redis-based
   * ACLs work properly with minimal fuss with regard to the module load
   * order.
   */

  c = find_config(main_server->conf, CONF_PARAM, "RedisSentinel", FALSE);
  if (c != NULL) {
    array_header *sentinels;
    const char *name;

    sentinels = c->argv[0];
    name = c->argv[1];

    (void) redis_set_sentinels(sentinels, name);
  }

  c = find_config(main_server->conf, CONF_PARAM, "RedisServer", FALSE);
  if (c != NULL) {
    const char *server, *password, *db_idx;
    int port;

    server = c->argv[0];
    port = *((int *) c->argv[1]);
    password = c->argv[2];
    db_idx = c->argv[3];

    (void) redis_set_server(server, port, 0UL, password, db_idx);
  }

  c = find_config(main_server->conf, CONF_PARAM, "RedisTimeouts", FALSE);
  if (c) {
    unsigned long connect_millis, io_millis;

    connect_millis = *((unsigned long *) c->argv[0]);
    io_millis = *((unsigned long *) c->argv[1]);

    (void) redis_set_timeouts(connect_millis, io_millis);
  }

  return 0;
}

/* Module API tables
 */

module wrap2_redis_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "wrap2_redis",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  redistab_init,

  /* Session initialization function */
  redistab_sess_init,

  /* Module version */
  MOD_WRAP2_REDIS_VERSION
};
