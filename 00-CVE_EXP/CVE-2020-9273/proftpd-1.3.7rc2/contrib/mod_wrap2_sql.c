/*
 * ProFTPD: mod_wrap2_sql -- a mod_wrap2 sub-module for supplying IP-based
 *                           access control data via SQL tables
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
 * As a special exemption, TJ Saunders gives permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

#include "mod_wrap2.h"
#include "mod_sql.h"

#define MOD_WRAP2_SQL_VERSION		"mod_wrap2_sql/1.0"

#define WRAP2_SQL_NSLOTS		2
#define WRAP2_SQL_CLIENT_QUERY_IDX	0
#define WRAP2_SQL_OPTION_QUERY_IDX	1

module wrap2_sql_module;

static cmd_rec *sql_cmd_create(pool *parent_pool, unsigned int argc, ...) {
  register unsigned int i = 0;
  pool *cmd_pool = NULL;
  cmd_rec *cmd = NULL;
  va_list argp;

  cmd_pool = make_sub_pool(parent_pool);
  cmd = (cmd_rec *) pcalloc(cmd_pool, sizeof(cmd_rec));
  cmd->pool = cmd_pool;

  cmd->argc = argc;
  cmd->argv = pcalloc(cmd->pool, argc * sizeof(void *));

  /* Hmmm... */
  cmd->tmp_pool = cmd->pool;

  va_start(argp, argc);
  for (i = 0; i < argc; i++) {
    cmd->argv[i] = va_arg(argp, char *);
  }
  va_end(argp);

  return cmd;
}

static int sqltab_close_cb(wrap2_table_t *sqltab) {
  return 0;
}

static array_header *sqltab_fetch_clients_cb(wrap2_table_t *sqltab,
    const char *name) {
  register unsigned int i;
  pool *tmp_pool = NULL;
  cmdtable *sql_cmdtab = NULL;
  cmd_rec *sql_cmd = NULL;
  modret_t *sql_res = NULL;
  array_header *sql_data = NULL;
  char *query = NULL, **vals = NULL;
  array_header *clients_list = NULL;

  /* Allocate a temporary pool for the duration of this read. */
  tmp_pool = make_sub_pool(sqltab->tab_pool);

  query = ((char **) sqltab->tab_data)[WRAP2_SQL_CLIENT_QUERY_IDX];

  /* Find the cmdtable for the sql_lookup command. */
  sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_lookup", NULL, NULL,
    NULL);
  if (sql_cmdtab == NULL) {
    wrap2_log("error: unable to find SQL hook symbol 'sql_lookup': "
      "perhaps your proftpd.conf needs 'LoadModule mod_sql.c'?");
    destroy_pool(tmp_pool);
    return NULL;
  }

  /* Prepare the SELECT query. */
  sql_cmd = sql_cmd_create(tmp_pool, 3, "sql_lookup", query, name);

  /* Call the handler. */
  sql_res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, sql_cmd);

  /* Check the results. */
  if (sql_res == NULL) {
    wrap2_log("SQLNamedQuery '%s' returned no data; "
      "see the mod_sql.c SQLLogFile for more details", query);
    destroy_pool(tmp_pool);
    return NULL;
  }

  if (MODRET_ISERROR(sql_res)) {
    wrap2_log("error processing SQLNamedQuery '%s': "
      "check the mod_sql.c SQLLogFile for more details", query);
    destroy_pool(tmp_pool);
    return NULL;
  }

  sql_data = (array_header *) sql_res->data;
  vals = (char **) sql_data->elts;

  if (sql_data->nelts < 1) {
    wrap2_log("SQLNamedQuery '%s' returned no data; "
      "see the mod_sql.c SQLLogFile for more details", query);
    destroy_pool(tmp_pool);
    return NULL;
  }

  clients_list = make_array(sqltab->tab_pool, sql_data->nelts, sizeof(char *));

  /* Iterate through each returned row.  If there are commas or whitespace
   * in the row, parse them as separate client names.  Otherwise, a comma-
   * or space-delimited list of names will be treated as a single name, and
   * violate the principle of least surprise for the site admin.
   */

  for (i = 0; i < sql_data->nelts; i++) {
    char *ptr;

    if (vals[i] == NULL) {
      continue;
    }

    ptr = strpbrk(vals[i], ", \t");
    if (ptr != NULL) {
      char *dup_opts, *word;

      dup_opts = pstrdup(sqltab->tab_pool, vals[i]);
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

        *((char **) push_array(clients_list)) = word;

        /* Skip redundant whitespaces */
        while (*dup_opts == ' ' ||
               *dup_opts == '\t') {
          pr_signals_handle();
          dup_opts++;
        }
      }

    } else {
      *((char **) push_array(clients_list)) = pstrdup(sqltab->tab_pool,
        vals[i]);
    }
  }

  destroy_pool(tmp_pool);
  return clients_list;
}

static array_header *sqltab_fetch_daemons_cb(wrap2_table_t *sqltab,
    const char *name) {
  array_header *daemons_list = make_array(sqltab->tab_pool, 1, sizeof(char *));

  /* Simply return the service name we're given. */
  *((char **) push_array(daemons_list)) = pstrdup(sqltab->tab_pool, name);

  return daemons_list;
}

static array_header *sqltab_fetch_options_cb(wrap2_table_t *sqltab,
    const char *name) {
  pool *tmp_pool = NULL;
  cmdtable *sql_cmdtab = NULL;
  cmd_rec *sql_cmd = NULL;
  modret_t *sql_res = NULL;
  array_header *sql_data = NULL;
  char *query = NULL, **vals = NULL;
  array_header *options_list = NULL;

  /* Allocate a temporary pool for the duration of this read. */
  tmp_pool = make_sub_pool(sqltab->tab_pool);

  query = ((char **) sqltab->tab_data)[WRAP2_SQL_OPTION_QUERY_IDX];

  /* The options-query is not necessary.  Skip if not present. */
  if (!query) {
    destroy_pool(tmp_pool);
    return NULL;
  }

  /* Find the cmdtable for the sql_lookup command. */
  sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_lookup", NULL, NULL,
    NULL);
  if (sql_cmdtab == NULL) {
    wrap2_log("error: unable to find SQL hook symbol 'sql_lookup': "
      "perhaps your proftpd.conf needs 'LoadModule mod_sql.c'?");
    destroy_pool(tmp_pool);
    return NULL;
  }

  /* Prepare the SELECT query. */
  sql_cmd = sql_cmd_create(tmp_pool, 3, "sql_lookup", query, name);

  /* Call the handler. */
  sql_res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, sql_cmd);

  /* Check the results. */
  if (!sql_res) {
    wrap2_log("SQLNamedQuery '%s' returned no data; "
      "see the mod_sql.c SQLLogFile for more details", query);
    destroy_pool(tmp_pool);
    return NULL;
  }

  if (MODRET_ISERROR(sql_res)) {
    wrap2_log("error processing SQLNamedQuery '%s': "
      "check the mod_sql.c SQLLogFile for more details", query);
    destroy_pool(tmp_pool);
    return NULL;
  }

  /* Construct a single string, concatenating the returned client tokens
   * together.
   */
  sql_data = (array_header *) sql_res->data;
  vals = (char **) sql_data->elts;

  if (sql_data->nelts < 1) {
    wrap2_log("SQLNamedQuery '%s' returned no data; "
      "see the mod_sql.c SQLLogFile for more details", query);
    destroy_pool(tmp_pool);
    return NULL;
  }

  options_list = make_array(sqltab->tab_pool, sql_data->nelts, sizeof(char *));
  *((char **) push_array(options_list)) = pstrdup(sqltab->tab_pool, vals[0]);

  if (sql_data->nelts > 1) {
    register unsigned int i = 0;

    for (i = 1; i < sql_data->nelts; i++) {
      if (vals[i] == NULL) {
        continue;
      }

      *((char **) push_array(options_list)) = pstrdup(sqltab->tab_pool,
        vals[i]);
    }
  }

  destroy_pool(tmp_pool);
  return options_list;
}

static wrap2_table_t *sqltab_open_cb(pool *parent_pool, const char *srcinfo) {
  wrap2_table_t *tab = NULL;
  pool *tab_pool = make_sub_pool(parent_pool),
    *tmp_pool = make_sub_pool(parent_pool);
  config_rec *c = NULL;
  char *start = NULL, *finish = NULL, *query = NULL, *clients_query = NULL,
    *options_query = NULL, *info;

  tab = (wrap2_table_t *) pcalloc(tab_pool, sizeof(wrap2_table_t));
  tab->tab_pool = tab_pool;

  /* Parse the SELECT query name out of the srcinfo string.  Lookup and
   * store the query in the tab_data area, so that it need not be looked
   * up later.
   *
   * The srcinfo string for this case should look like:
   *  "/<clients-named-query>[/<options-named-query>]"
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

  clients_query = pstrdup(tab->tab_pool, start);

  /* Verify that the named query has indeed been defined.  This is
   * base on how mod_sql creates its config_rec names.
   */
  query = pstrcat(tmp_pool, "SQLNamedQuery_", clients_query, NULL);

  c = find_config(main_server->conf, CONF_PARAM, query, FALSE);
  if (c == NULL) {
    wrap2_log("error: unable to resolve SQLNamedQuery name '%s'",
      clients_query);
    pr_log_pri(PR_LOG_WARNING, MOD_WRAP2_SQL_VERSION
      ": no such SQLNamedQuery '%s' found, allowing connection", clients_query);

    destroy_pool(tab_pool);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return NULL;
  }

  /* Handle the options-query, if present. */
  if (finish != NULL) {
    options_query = pstrdup(tab->tab_pool, ++finish);

    query = pstrcat(tmp_pool, "SQLNamedQuery_", options_query, NULL);

    c = find_config(main_server->conf, CONF_PARAM, query, FALSE);
    if (c == NULL) {
      wrap2_log("error: unable to resolve SQLNamedQuery name '%s'",
        options_query);
      destroy_pool(tab_pool);
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return NULL;
    }
  }

  tab->tab_name = pstrcat(tab->tab_pool, "SQL(", info, ")", NULL);

  tab->tab_data = pcalloc(tab->tab_pool, WRAP2_SQL_NSLOTS * sizeof(char *));
  ((char **) tab->tab_data)[WRAP2_SQL_CLIENT_QUERY_IDX] =
    pstrdup(tab->tab_pool, clients_query);

  ((char **) tab->tab_data)[WRAP2_SQL_OPTION_QUERY_IDX] =
    (options_query ? pstrdup(tab->tab_pool, options_query) : NULL);

  /* Set the necessary callbacks. */
  tab->tab_close = sqltab_close_cb;
  tab->tab_fetch_clients = sqltab_fetch_clients_cb;
  tab->tab_fetch_daemons = sqltab_fetch_daemons_cb;
  tab->tab_fetch_options = sqltab_fetch_options_cb;

  destroy_pool(tmp_pool);
  return tab;
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void sqltab_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_wrap2_sql.c", (const char *) event_data) == 0) {
    pr_event_unregister(&wrap2_sql_module, NULL, NULL);
    wrap2_unregister("sql");
  }
}
#endif /* PR_SHARED_MODULE */

/* Initialization routines
 */

static int sqltab_init(void) {

  /* Initialize the wrap source objects for type "sql".  */
  wrap2_register("sql", sqltab_open_cb);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&wrap2_sql_module, "core.module-unload",
    sqltab_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  return 0;
}

module wrap2_sql_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "wrap2_sql",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  sqltab_init,

  /* Session initialization function */
  NULL,

  /* Module version */
  MOD_WRAP2_SQL_VERSION
};
