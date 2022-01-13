/*
 * ProFTPD: mod_quotatab_sql -- a mod_quotatab sub-module for managing quota
 *                              data via SQL-based tables
 * Copyright (c) 2002-2017 TJ Saunders
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

#include "mod_quotatab.h"
#include "mod_sql.h"

#define QUOTATAB_SQL_VALUE_BUFSZ	20

module quotatab_sql_module;

static cmd_rec *sqltab_cmd_create(pool *parent_pool, unsigned int argc, ...) {
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

static char *sqltab_get_name(pool *p, char *name) {
  cmdtable *cmdtab;
  cmd_rec *cmd;
  modret_t *res;

  /* Find the cmdtable for the sql_escapestr command. */
  cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_escapestr", NULL, NULL, NULL);
  if (cmdtab == NULL) {
    quotatab_log("error: unable to find SQL hook symbol 'sql_escapestr'");
    return name;
  }

  if (strlen(name) == 0) {
    return name;
  }

  cmd = sqltab_cmd_create(p, 1, pr_str_strip(p, name));

  /* Call the handler. */
  res = pr_module_call(cmdtab->m, cmdtab->handler, cmd);

  /* Check the results. */
  if (MODRET_ISDECLINED(res) ||
      MODRET_ISERROR(res)) {
    quotatab_log("error executing 'sql_escapestring'");
    return name;
  }

  return res->data;
}

static int sqltab_close(quota_table_t *sqltab) {

  /* Is there really anything that needs to be done here? */
  return 0;
}

static int sqltab_create(quota_table_t *sqltab, void *ptr) {
  pool *tmp_pool = NULL;
  cmdtable *sql_cmdtab = NULL;
  cmd_rec *sql_cmd = NULL;
  modret_t *sql_res = NULL;
  char *insert_query = NULL, *tally_quota_name = NULL, *tally_quota_type = NULL,
    *tally_bytes_in = NULL, *tally_bytes_out = NULL, *tally_bytes_xfer = NULL,
    *tally_files_in = NULL, *tally_files_out = NULL, *tally_files_xfer = NULL;
  quota_tally_t *tally = ptr;

  /* Allocate a sub pool for use by this function. */
  tmp_pool = make_sub_pool(sqltab->tab_pool);

  /* Allocate small buffers for stringifying most of the tally struct
   * members: quota_type, bytes_in_used, bytes_out_used, bytes_xfer_used,
   * files_in_used, files_out_used, files_xfer_used.
   */
  tally_quota_name = pcalloc(tmp_pool, 83 * sizeof(char));
  tally_quota_type = pcalloc(tmp_pool, QUOTATAB_SQL_VALUE_BUFSZ * sizeof(char));
  tally_bytes_in = pcalloc(tmp_pool, QUOTATAB_SQL_VALUE_BUFSZ * sizeof(char));
  tally_bytes_out = pcalloc(tmp_pool, QUOTATAB_SQL_VALUE_BUFSZ * sizeof(char));
  tally_bytes_xfer = pcalloc(tmp_pool, QUOTATAB_SQL_VALUE_BUFSZ * sizeof(char));
  tally_files_in = pcalloc(tmp_pool, QUOTATAB_SQL_VALUE_BUFSZ * sizeof(char));
  tally_files_out = pcalloc(tmp_pool, QUOTATAB_SQL_VALUE_BUFSZ * sizeof(char));
  tally_files_xfer = pcalloc(tmp_pool, QUOTATAB_SQL_VALUE_BUFSZ * sizeof(char));

  /* Execute the INSERT NamedQuery */
  insert_query = ((char **) sqltab->tab_data)[2];

  /* Populate the INSERT query with the necessary data from the current
   * limit record.  Need to stringify most of the tally struct members:
   * quota_type, bytes_in_used, bytes_out_used, bytes_xfer_used,
   * files_in_used, files_out_used, files_xfer_used.
   */

  pr_snprintf(tally_quota_name, 83, "'%s'",
    sqltab_get_name(tmp_pool, tally->name));
  tally_quota_name[82] = '\0';

  if (tally->quota_type == USER_QUOTA) {
    pr_snprintf(tally_quota_type, QUOTATAB_SQL_VALUE_BUFSZ, "'%s'", "user");

  } else if (tally->quota_type == GROUP_QUOTA) {
    pr_snprintf(tally_quota_type, QUOTATAB_SQL_VALUE_BUFSZ, "'%s'", "group");

  } else if (tally->quota_type == CLASS_QUOTA) {
    pr_snprintf(tally_quota_type, QUOTATAB_SQL_VALUE_BUFSZ, "'%s'", "class");

  } else if (tally->quota_type == ALL_QUOTA) {
    pr_snprintf(tally_quota_type, QUOTATAB_SQL_VALUE_BUFSZ, "'%s'", "all");
  }

  tally_quota_type[QUOTATAB_SQL_VALUE_BUFSZ-1] = '\0';

  pr_snprintf(tally_bytes_in, QUOTATAB_SQL_VALUE_BUFSZ, "%f",
    tally->bytes_in_used);
  tally_bytes_in[QUOTATAB_SQL_VALUE_BUFSZ-1] = '\0';

  pr_snprintf(tally_bytes_out, QUOTATAB_SQL_VALUE_BUFSZ, "%f",
    tally->bytes_out_used);
  tally_bytes_out[QUOTATAB_SQL_VALUE_BUFSZ-1] = '\0';

  pr_snprintf(tally_bytes_xfer, QUOTATAB_SQL_VALUE_BUFSZ, "%f",
    tally->bytes_xfer_used);
  tally_bytes_xfer[QUOTATAB_SQL_VALUE_BUFSZ-1] = '\0';

  pr_snprintf(tally_files_in, QUOTATAB_SQL_VALUE_BUFSZ, "%u",
    tally->files_in_used);
  tally_files_in[QUOTATAB_SQL_VALUE_BUFSZ-1] = '\0';

  pr_snprintf(tally_files_out, QUOTATAB_SQL_VALUE_BUFSZ, "%u",
    tally->files_out_used);
  tally_files_out[QUOTATAB_SQL_VALUE_BUFSZ-1] = '\0';

  pr_snprintf(tally_files_xfer, QUOTATAB_SQL_VALUE_BUFSZ, "%u",
    tally->files_xfer_used);
  tally_files_xfer[QUOTATAB_SQL_VALUE_BUFSZ-1] = '\0';

  sql_cmd = sqltab_cmd_create(tmp_pool, 10, "sql_change", insert_query,
    tally_quota_name, tally_quota_type,
    tally_bytes_in, tally_bytes_out, tally_bytes_xfer,
    tally_files_in, tally_files_out, tally_files_xfer);

  /* Find the cmdtable for the sql_change command. */
  sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_change", NULL, NULL,
    NULL);
  if (sql_cmdtab == NULL) {
    quotatab_log("error: unable to find SQL hook symbol 'sql_change'");
    destroy_pool(tmp_pool);
    return -1;
  }

  /* Call the handler. */
  sql_res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, sql_cmd);

  /* Check the results. */
  if (MODRET_ISERROR(sql_res)) {
    quotatab_log("error executing NamedQuery '%s': %s", insert_query,
      strerror(errno));
    destroy_pool(tmp_pool);
    return -1;
  } 

  destroy_pool(tmp_pool);
  return 0;
}

static unsigned char sqltab_lookup(quota_table_t *sqltab, void *ptr,
    const char *name, quota_type_t quota_type) {
  pool *tmp_pool = NULL;
  cmdtable *sql_cmdtab = NULL;
  cmd_rec *sql_cmd = NULL;
  modret_t *sql_res = NULL;
  array_header *sql_data = NULL;
  char *select_query = NULL;

  /* Allocate a temporary pool for the duration of this lookup. */
  tmp_pool = make_sub_pool(sqltab->tab_pool);

  /* Handle tally and limit tables differently... */
  if (sqltab->tab_type == TYPE_TALLY) {
    select_query = ((char **) sqltab->tab_data)[0];

  } else if (sqltab->tab_type == TYPE_LIMIT) {
    select_query = (char *) sqltab->tab_data;
  }

  /* Find the cmdtable for the sql_lookup command. */
  sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_lookup", NULL, NULL,
    NULL);
  if (sql_cmdtab == NULL) {
    quotatab_log("error: unable to find SQL hook symbol 'sql_lookup'");
    destroy_pool(tmp_pool);
    return FALSE;
  }

  /* Prepare the SELECT query. */
  sql_cmd = sqltab_cmd_create(tmp_pool, 4, "sql_lookup", select_query,
    name ? sqltab_get_name(tmp_pool, (char *) name) : "",
    quota_type == USER_QUOTA ? "user" : quota_type == GROUP_QUOTA ? "group" :
    quota_type == CLASS_QUOTA ? "class" : "all");

  /* Call the handler. */
  sql_res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, sql_cmd);

  /* Check the results. */
  if (!sql_res || MODRET_ISERROR(sql_res)) {
    quotatab_log("error processing NamedQuery '%s'", select_query);
    destroy_pool(tmp_pool);
    return FALSE;
  }

  sql_data = (array_header *) sql_res->data;

  if (sqltab->tab_type == TYPE_TALLY) {
    quota_tally_t *tally = ptr;
    char **values = (char **) sql_data->elts;

    /* Update the tally record with the 8 values:
     *  name
     *  quota_type
     *  bytes_{in,out,xfer}_used
     *  files_{in,out,xfer}_used
     */

    if (sql_data->nelts < 8) {
      if (sql_data->nelts > 0) {
        quotatab_log("error: SQLNamedQuery '%s' returned incorrect number of "
          "values (%d)", select_query, sql_data->nelts);
      }

      destroy_pool(tmp_pool);
      return FALSE;
    }

    /* Process each element returned. */
    memmove(tally->name, values[0], sizeof(tally->name));

    if (strcasecmp(values[1], "user") == 0) {
      tally->quota_type = USER_QUOTA;

    } else if (strcasecmp(values[1], "group") == 0) {
      tally->quota_type = GROUP_QUOTA;

    } else if (strcasecmp(values[1], "class") == 0) {
      tally->quota_type = CLASS_QUOTA;

    } else if (strcasecmp(values[1], "all") == 0) {
      tally->quota_type = ALL_QUOTA;
    }

    /* Check if this is the requested record, now that enough information
     * is in place.
     */
    if (quota_type != tally->quota_type) {
      destroy_pool(tmp_pool);
      return FALSE;
    }

    /* Match names if need be */
    if (quota_type != ALL_QUOTA &&
        values[0] &&
        strlen(values[0]) > 0 &&
        strcmp(name, tally->name) != 0) {
      destroy_pool(tmp_pool);
      return FALSE;
    }

    tally->bytes_in_used = -1.0;
    if (values[2])
      tally->bytes_in_used = atof(values[2]);

    tally->bytes_out_used = -1.0;
    if (values[3])
      tally->bytes_out_used = atof(values[3]);

    tally->bytes_xfer_used = -1.0;
    if (values[4])
      tally->bytes_xfer_used = atof(values[4]);

    tally->files_in_used = 0;
    if (values[5])
      tally->files_in_used = atol(values[5]);

    tally->files_out_used = 0;
    if (values[6])
      tally->files_out_used = atol(values[6]);

    tally->files_xfer_used = 0;
    if (values[7])
      tally->files_xfer_used = atol(values[7]);

    destroy_pool(tmp_pool);
    return TRUE;

  } else if (sqltab->tab_type == TYPE_LIMIT) {
    quota_limit_t *limit = ptr;
    char **values = (char **) sql_data->elts;

    /* Update the limit record with the 10 values:
     *  name
     *  quota_type
     *  per_session
     *  limit_type
     *  bytes_{in,out,xfer}_avail
     *  files_{in,out,xfer}_avail
     */

    if (sql_data->nelts < 10) {
      if (sql_data->nelts > 0) {
        quotatab_log("error: SQLNamedQuery '%s' returned incorrect number of "
          "values (%d)", select_query, sql_data->nelts);
      }

      destroy_pool(tmp_pool);
      return FALSE;
    }

    /* Process each element returned. */
    memmove(limit->name, values[0], sizeof(limit->name));

    if (strcasecmp(values[1], "user") == 0) {
      limit->quota_type = USER_QUOTA;

    } else if (strcasecmp(values[1], "group") == 0) {
      limit->quota_type = GROUP_QUOTA;

    } else if (strcasecmp(values[1], "class") == 0) {
      limit->quota_type = CLASS_QUOTA;

    } else if (strcasecmp(values[1], "all") == 0) {
      limit->quota_type = ALL_QUOTA;
    }

    /* Check if this is the requested record, now that enough information
     * is in place.
     */
    if (quota_type != limit->quota_type) {
      destroy_pool(tmp_pool);
      return FALSE;
    }

    /* Match names if need be */
    if (quota_type != ALL_QUOTA &&
        values[0] &&
        strlen(values[0]) > 0 &&
        strcmp(name, limit->name) != 0) {
      destroy_pool(tmp_pool);
      return FALSE;
    }

    if (strcasecmp(values[2], "false") == 0) {
      limit->quota_per_session = FALSE;

    } else if (strcasecmp(values[2], "true") == 0) {
      limit->quota_per_session = TRUE;
    }

    if (strcasecmp(values[3], "soft") == 0) {
      limit->quota_limit_type = SOFT_LIMIT;

    } else if (strcasecmp(values[3], "hard") == 0) {
      limit->quota_limit_type = HARD_LIMIT;
    }

    limit->bytes_in_avail = -1.0;
    if (values[4])
      limit->bytes_in_avail = atof(values[4]);

    limit->bytes_out_avail = -1.0;
    if (values[5])
      limit->bytes_out_avail = atof(values[5]);

    limit->bytes_xfer_avail = -1.0;
    if (values[6])
      limit->bytes_xfer_avail = atof(values[6]);

    limit->files_in_avail = 0;
    if (values[7])
      limit->files_in_avail = atol(values[7]);

    limit->files_out_avail = 0;
    if (values[8])
      limit->files_out_avail = atol(values[8]);

    limit->files_xfer_avail = 0;
    if (values[9])
      limit->files_xfer_avail = atol(values[9]);

    destroy_pool(tmp_pool);
    return TRUE;
  }

  destroy_pool(tmp_pool);

  /* default */
  return FALSE;
}

static int sqltab_read(quota_table_t *sqltab, void *ptr) {
  quota_tally_t *tally = ptr;

  return sqltab_lookup(sqltab, ptr, tally->name, tally->quota_type);
}

static unsigned char sqltab_verify(quota_table_t *sqltab) {

  /* Always TRUE. */
  return TRUE;
}

static int sqltab_write(quota_table_t *sqltab, void *ptr) {
  pool *tmp_pool = NULL;
  cmdtable *sql_cmdtab = NULL;
  cmd_rec *sql_cmd = NULL;
  modret_t *sql_res = NULL;
  char *update_query = NULL, *tally_quota_type = NULL,
    *tally_bytes_in = NULL, *tally_bytes_out = NULL, *tally_bytes_xfer = NULL,
    *tally_files_in = NULL, *tally_files_out = NULL, *tally_files_xfer = NULL;
  quota_tally_t *tally = ptr;

  /* Allocate a sub pool for use by this function. */
  tmp_pool = make_sub_pool(sqltab->tab_pool);

  /* Allocate small buffers for stringifying most of the tally struct
   * members: quota_type, bytes_in_used, bytes_out_used, bytes_xfer_used,
   * files_in_used, files_out_used, files_xfer_used.
   */
  tally_quota_type = pcalloc(tmp_pool, QUOTATAB_SQL_VALUE_BUFSZ * sizeof(char));
  tally_bytes_in = pcalloc(tmp_pool, QUOTATAB_SQL_VALUE_BUFSZ * sizeof(char));
  tally_bytes_out = pcalloc(tmp_pool, QUOTATAB_SQL_VALUE_BUFSZ * sizeof(char));
  tally_bytes_xfer = pcalloc(tmp_pool, QUOTATAB_SQL_VALUE_BUFSZ * sizeof(char));
  tally_files_in = pcalloc(tmp_pool, QUOTATAB_SQL_VALUE_BUFSZ * sizeof(char));
  tally_files_out = pcalloc(tmp_pool, QUOTATAB_SQL_VALUE_BUFSZ * sizeof(char));
  tally_files_xfer = pcalloc(tmp_pool, QUOTATAB_SQL_VALUE_BUFSZ * sizeof(char));

  /* Retrieve the UPDATE NamedQuery */
  update_query = ((char **) sqltab->tab_data)[1];

  /* Populate the UPDATE query with the necessary data from the current
   * limit record.  Need to stringify most of the tally struct members:
   * quota_type, bytes_in_used, bytes_out_used, bytes_xfer_used,
   * files_in_used, files_out_used, files_xfer_used.
   */

  if (tally->quota_type == USER_QUOTA) {
    pr_snprintf(tally_quota_type, QUOTATAB_SQL_VALUE_BUFSZ, "%s", "user");

  } else if (tally->quota_type == GROUP_QUOTA) {
    pr_snprintf(tally_quota_type, QUOTATAB_SQL_VALUE_BUFSZ, "%s", "group");

  } else if (tally->quota_type == CLASS_QUOTA) {
    pr_snprintf(tally_quota_type, QUOTATAB_SQL_VALUE_BUFSZ, "%s", "class");

  } else if (tally->quota_type == ALL_QUOTA) {
    pr_snprintf(tally_quota_type, QUOTATAB_SQL_VALUE_BUFSZ, "%s", "all");
  }

  tally_quota_type[QUOTATAB_SQL_VALUE_BUFSZ-1] = '\0';

  /* Note: use the deltas data, not the tally members, so that the
   * UPDATE can do an "atomic" read+update all in one shot.
   */
  pr_snprintf(tally_bytes_in, QUOTATAB_SQL_VALUE_BUFSZ, "%f",
    quotatab_deltas.bytes_in_delta);
  tally_bytes_in[QUOTATAB_SQL_VALUE_BUFSZ-1] = '\0';

  pr_snprintf(tally_bytes_out, QUOTATAB_SQL_VALUE_BUFSZ, "%f",
    quotatab_deltas.bytes_out_delta);
  tally_bytes_out[QUOTATAB_SQL_VALUE_BUFSZ-1] = '\0';

  pr_snprintf(tally_bytes_xfer, QUOTATAB_SQL_VALUE_BUFSZ, "%f",
    quotatab_deltas.bytes_xfer_delta);
  tally_bytes_xfer[QUOTATAB_SQL_VALUE_BUFSZ-1] = '\0';

  /* Don't try to prevent underflows here; mod_quotatab already makes
   * these checks.
   */
  pr_snprintf(tally_files_in, QUOTATAB_SQL_VALUE_BUFSZ, "%d",
    quotatab_deltas.files_in_delta);
  tally_files_in[QUOTATAB_SQL_VALUE_BUFSZ-1] = '\0';

  pr_snprintf(tally_files_out, QUOTATAB_SQL_VALUE_BUFSZ, "%d",
    quotatab_deltas.files_out_delta);
  tally_files_out[QUOTATAB_SQL_VALUE_BUFSZ-1] = '\0';

  pr_snprintf(tally_files_xfer, QUOTATAB_SQL_VALUE_BUFSZ, "%d",
    quotatab_deltas.files_xfer_delta);
  tally_files_xfer[QUOTATAB_SQL_VALUE_BUFSZ-1] = '\0';

  sql_cmd = sqltab_cmd_create(tmp_pool, 10, "sql_change", update_query,
    tally_bytes_in, tally_bytes_out, tally_bytes_xfer,
    tally_files_in, tally_files_out, tally_files_xfer,
    sqltab_get_name(tmp_pool, tally->name), tally_quota_type);

  /* Find the cmdtable for the sql_change command. */
  sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_change", NULL, NULL,
    NULL);
  if (sql_cmdtab == NULL) {
    quotatab_log("error: unable to find SQL hook symbol 'sql_change'");
    destroy_pool(tmp_pool);
    return -1;
  }

  /* Call the handler. */
  sql_res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, sql_cmd);

  /* Check the results. */
  if (MODRET_ISERROR(sql_res)) {
    quotatab_log("error executing NamedQuery '%s': %s", update_query,
      strerror(errno));
    destroy_pool(tmp_pool);
    return -1;
  }

  destroy_pool(tmp_pool);
  return 0;
}

static int sqltab_rlock(quota_table_t *sqltab) {

  /* Check for a configured lock file. */
  if (sqltab->tab_lockfd > 0) {
    sqltab->tab_lock.l_type = F_RDLCK;
    return fcntl(sqltab->tab_lockfd, F_SETLK, &sqltab->tab_lock);
  }

  return 0;
}

static int sqltab_unlock(quota_table_t *sqltab) {

  /* Check for a configured lock file. */
  if (sqltab->tab_lockfd > 0) {
    sqltab->tab_lock.l_type = F_UNLCK;
    return fcntl(sqltab->tab_lockfd, F_SETLK, &sqltab->tab_lock);
  }

  return 0;
}

static int sqltab_wlock(quota_table_t *sqltab) {

  /* Check for a configured lock file. */
  if (sqltab->tab_lockfd > 0) {
    sqltab->tab_lock.l_type = F_WRLCK;
    return fcntl(sqltab->tab_lockfd, F_SETLK, &sqltab->tab_lock);
  }

  return 0;
}

static quota_table_t *sqltab_open(pool *parent_pool, quota_tabtype_t tab_type,
    const char *srcinfo) {

  quota_table_t *tab = NULL;
  pool *tab_pool = make_sub_pool(parent_pool),
    *tmp_pool = make_sub_pool(parent_pool);
  config_rec *c = NULL;
  char *named_query = NULL;

  tab = (quota_table_t *) pcalloc(tab_pool, sizeof(quota_table_t));
  tab->tab_pool = tab_pool;
  tab->tab_type = tab_type;

  if (tab->tab_type == TYPE_TALLY) {
    char *start = NULL, *finish = NULL;
    char *select_query = NULL, *update_query = NULL, *insert_query = NULL;

    /* Parse the SELECT, UPDATE, and INSERT query names out of the srcinfo
     * string.  Lookup and store the queries in the tab_data area, so that
     * they need not be looked up later.
     *
     * The srcinfo string for this case should look like:
     *  "/<select-named-query>/<update-named-query>/<insert-named-query>/"
     */

    start = strchr(srcinfo, '/');
    if (start == NULL) {
      quotatab_log("error: badly formatted source info '%s'", srcinfo);
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return NULL;
    }

    /* Find the next slash. */
    finish = strchr(++start, '/');
    if (finish == NULL) {
      quotatab_log("error: badly formatted source info '%s'", srcinfo);
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return NULL;
    }

    *finish = '\0';
    select_query = pstrdup(tab->tab_pool, start);

    /* Verify that the named query has indeed been defined. This is
     * based on how mod_sql creates its config_rec names.
     */
    named_query = pstrcat(tmp_pool, "SQLNamedQuery_", select_query, NULL);

    c = find_config(main_server->conf, CONF_PARAM, named_query, FALSE);
    if (c == NULL) {
      quotatab_log("error: unable to resolve SQLNamedQuery name '%s'",
        select_query);
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return NULL;
    }

    /* Now, find the next slash. */
    start = finish;
    finish = strchr(++start, '/');
    if (finish == NULL) {
      quotatab_log("error: badly formatted source info '%s'", srcinfo);
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return NULL;
    }

    *finish = '\0';
    update_query = pstrdup(tab->tab_pool, start);

    /* Verify that the named query has indeed been defined. This is
     * based on how mod_sql creates its config_rec names.
     */
    named_query = pstrcat(tmp_pool, "SQLNamedQuery_", update_query, NULL);

    c = find_config(main_server->conf, CONF_PARAM, named_query, FALSE);
    if (c == NULL) {
      quotatab_log("error: unable to resolve SQLNamedQuery name '%s'",
        update_query);
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return NULL;
    }

    /* Assume the rest of the srcinfo string is the INSERT query (assuming
     * there *is* a "rest of the string").
     */
    if (*(++finish) != '\0') {
      insert_query = pstrdup(tab->tab_pool, finish);

    } else {
      quotatab_log("error: badly formatted source info '%s'", srcinfo);
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return NULL;
    }

    /* Verify that the named query has indeed been defined. This is
     * based on how mod_sql creates its config_rec names.
     */
    named_query = pstrcat(tmp_pool, "SQLNamedQuery_", insert_query, NULL);

    c = find_config(main_server->conf, CONF_PARAM, named_query, FALSE);
    if (c == NULL) {
      quotatab_log("error: unable to resolve SQLNamedQuery name '%s'",
        insert_query);
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return NULL;
    }

    tab->tab_data = (char **) pcalloc(tab->tab_pool, 3 * sizeof(char *));
    ((char **) tab->tab_data)[0] = pstrdup(tab->tab_pool, select_query);
    ((char **) tab->tab_data)[1] = pstrdup(tab->tab_pool, update_query);
    ((char **) tab->tab_data)[2] = pstrdup(tab->tab_pool, insert_query);

  } else if (tab->tab_type == TYPE_LIMIT) {
    char *start = NULL, *select_query = NULL;

    /* Parse the SELECT query name out of the srcinfo string.  Lookup and
     * store the queries in the tab_data area, so that it need not be looked
     * up later.
     *
     * The srcinfo string for this case should look like:
     *  "/<select-named-query>"
     */

    start = strchr(srcinfo, '/');
    if (start == NULL) {
      quotatab_log("error: badly formatted source info '%s'", srcinfo);
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return NULL;
    }
    select_query = ++start;

    /* Verify that the named query has indeed been defined. This is
     * based on how mod_sql creates its config_rec names.
     */
    named_query = pstrcat(tmp_pool, "SQLNamedQuery_", select_query, NULL);

    c = find_config(main_server->conf, CONF_PARAM, named_query, FALSE);
    if (c == NULL) {
      quotatab_log("error: unable to resolve SQLNamedQuery name '%s'",
        select_query);
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return NULL;
    }

    tab->tab_data = (void *) pstrdup(tab->tab_pool, select_query);
  }

  /* Set all the necessary function pointers. */
  tab->tab_close = sqltab_close;
  tab->tab_create = sqltab_create;
  tab->tab_lookup = sqltab_lookup;
  tab->tab_read = sqltab_read;
  tab->tab_verify = sqltab_verify;
  tab->tab_write = sqltab_write;

  tab->tab_rlock = sqltab_rlock;
  tab->tab_unlock = sqltab_unlock;
  tab->tab_wlock = sqltab_wlock;

  /* Prepare the lock structure. */
  tab->tab_lock.l_whence = SEEK_CUR;
  tab->tab_lock.l_start = 0;
  tab->tab_lock.l_len = 0;

  destroy_pool(tmp_pool);
  return tab;
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void sqltab_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_quotatab_sql.c", (const char *) event_data) == 0) {
    pr_event_unregister(&quotatab_sql_module, NULL, NULL);
    quotatab_unregister_backend("sql", QUOTATAB_LIMIT_SRC|QUOTATAB_TALLY_SRC);
  }
}
#endif /* PR_SHARED_MODULE */

/* Initialization routines
 */

static int sqltab_init(void) {

  /* Initialize the quota source objects for type "sql". */
  quotatab_register_backend("sql", sqltab_open,
    QUOTATAB_LIMIT_SRC|QUOTATAB_TALLY_SRC);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&quotatab_sql_module, "core.module-unload",
    sqltab_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  return 0;
}

module quotatab_sql_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "quotatab_sql",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  sqltab_init,

  /* Session initialization */
  NULL
};
