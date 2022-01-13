/*
 * ProFTPD: mod_sql_sqlite -- Support for connecting to SQLite databases
 * Copyright (c) 2004-2017 TJ Saunders
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
 *
 * $Libraries: -lsqlite3$
 */

#define MOD_SQL_SQLITE_VERSION		"mod_sql_sqlite/0.4"

#include "conf.h"
#include "privs.h"
#include "mod_sql.h"

#include <sqlite3.h>

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030602
# error "ProFTPD 1.3.6rc2 or later required"
#endif

module sql_sqlite_module;

#define SQL_SQLITE_START_FL_NOW		1
#define SQL_SQLITE_START_FL_EXCL	2

typedef struct db_conn_struct {
  char *dsn;
  char *user;
  char *pass;

  sqlite3 *dbh;

} db_conn_t;

typedef struct conn_entry_struct {
  char *name;
  void *data;

  /* Timer handling */
  int timer;
  int ttl;

  /* Connection handling */
  unsigned int nconn;

} conn_entry_t;

#define DEF_CONN_POOL_SIZE	10

static pool *conn_pool = NULL;
static array_header *conn_cache = NULL;

#define SQLITE_TRACE_LEVEL	12
static const char *trace_channel = "sql.sqlite";

MODRET sql_sqlite_close(cmd_rec *);

static void db_err(void *user_data, int err_code, const char *err_msg) {
  pr_trace_msg(trace_channel, 1, "(sqlite3): [error %d] %s", err_code, err_msg);
}

static void db_trace(void *user_data, const char *trace_msg) {
  pr_trace_msg(trace_channel, SQLITE_TRACE_LEVEL, "(sqlite3): %s", trace_msg);
}

static conn_entry_t *sql_sqlite_get_conn(char *name) {
  register unsigned int i = 0;

  if (name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  for (i = 0; i < conn_cache->nelts; i++) {
    conn_entry_t *entry = ((conn_entry_t **) conn_cache->elts)[i];

    if (strcmp(name, entry->name) == 0) {
      return entry;
    }
  }

  errno = ENOENT;
  return NULL;
}

static void *sql_sqlite_add_conn(pool *p, char *name, db_conn_t *conn) {
  conn_entry_t *entry = NULL;

  if (!name || !conn || !p)
    return NULL;
  
  if (sql_sqlite_get_conn(name))
    return NULL;

  entry = (conn_entry_t *) pcalloc(p, sizeof(conn_entry_t));
  entry->name = name;
  entry->data = conn;

  *((conn_entry_t **) push_array(conn_cache)) = entry;

  return entry;
}

static int sql_sqlite_timer_cb(CALLBACK_FRAME) {
  register unsigned int i = 0;
 
  for (i = 0; i < conn_cache->nelts; i++) {
    conn_entry_t *entry;

    entry = ((conn_entry_t **) conn_cache->elts)[i];
    if ((unsigned long) entry->timer == p2) {
      cmd_rec *cmd = NULL;

      sql_log(DEBUG_INFO, "timer expired for connection '%s'", entry->name);

      cmd = pr_cmd_alloc(conn_pool, 2, entry->name, "1");
      sql_sqlite_close(cmd);
      destroy_pool(cmd->pool);

      entry->timer = 0;
    }
  }

  return 0;
}

/* The result set from handling SQLite queries is built up by the callback
 * function exec_cb(), and stored here.
 */
static int result_ncols = 0;
static array_header *result_list = NULL;

static int exec_cb(void *n, int ncols, char **cols,
    char **colnames) {
  register int i;
  char ***row;
  cmd_rec *cmd = n;

  if (result_list == NULL) {
    result_ncols = ncols;
    result_list = make_array(cmd->tmp_pool, ncols, sizeof(char **));
  }

  row = push_array(result_list);
  *row = pcalloc(cmd->tmp_pool, sizeof(char *) * ncols);

  for (i = 0; i < ncols; i++) {
    char *val = cols[i];
    (*row)[i] = pstrdup(cmd->tmp_pool, val ? val : "NULL");
  }

  return 0;
}

static int exec_stmt(cmd_rec *cmd, db_conn_t *conn, char *stmt, char **errstr) {
  int res;
  char *ptr = NULL;
  unsigned int nretries = 0;

  PRIVS_ROOT
  res = sqlite3_exec(conn->dbh, stmt, exec_cb, cmd, &ptr);
  PRIVS_RELINQUISH

  while (res != SQLITE_OK) {
    if (res == SQLITE_BUSY) {
      struct timeval tv;

      sqlite3_free(ptr);

      nretries++;
      sql_log(DEBUG_FUNC, "attempt #%u, database busy, trying '%s' again",
        nretries, stmt);

      /* Sleep for short bit, then try again. */
      tv.tv_sec = 0;
      tv.tv_usec = 500000L;

      if (select(0, NULL, NULL, NULL, &tv) < 0) {
        if (errno == EINTR) {
          pr_signals_handle();
        }
      }

      PRIVS_ROOT
      res = sqlite3_exec(conn->dbh, stmt, exec_cb, cmd, &ptr);
      PRIVS_RELINQUISH

      continue;
    }

    *errstr = pstrdup(cmd->pool, ptr);
    sqlite3_free(ptr);

    sql_log(DEBUG_FUNC, "error executing '%s': (%d) %s", stmt, res, *errstr);
    return -1;
  }

  if (ptr)
    sqlite3_free(ptr);

  return 0;
}

static int query_start(cmd_rec *cmd, db_conn_t *conn, int flags,
    char **errstr) {
  char *start_txn = NULL;

  switch (flags) {
    case SQL_SQLITE_START_FL_NOW:
      start_txn = pstrdup(cmd->tmp_pool, "BEGIN IMMEDIATE");
      break;

    case SQL_SQLITE_START_FL_EXCL:
      start_txn = pstrdup(cmd->tmp_pool, "BEGIN EXCLUSIVE");
      break;

    default:
      start_txn = pstrdup(cmd->tmp_pool, "BEGIN");
      break;
  }

  return exec_stmt(cmd, conn, start_txn, errstr);
}

static int query_run(cmd_rec *cmd, db_conn_t *conn, char *query,
    char **errstr) {
  return exec_stmt(cmd, conn, query, errstr);
}

static int query_finish(cmd_rec *cmd, db_conn_t *conn, char **errstr) {
  return exec_stmt(cmd, conn, pstrdup(cmd->tmp_pool, "COMMIT"), errstr);
}

static modret_t *sql_sqlite_get_data(cmd_rec *cmd) {
  register unsigned int i;
  unsigned int count, k = 0;
  char **data;
  sql_data_t *sd = pcalloc(cmd->tmp_pool, sizeof(sql_data_t));

  if (result_list == NULL) {
    return mod_create_data(cmd, sd);
  }

  sd->rnum = result_list->nelts;
  sd->fnum = result_ncols;
  count = sd->rnum * sd->fnum;
  data = pcalloc(cmd->tmp_pool, sizeof(char *) * (count + 1));

  for (i = 0; i < result_list->nelts; i++) {
    register int j;
    char **row;

    row = ((char ***) result_list->elts)[i];
    for (j = 0; j < result_ncols; j++) {
      data[k++] = pstrdup(cmd->tmp_pool, row[j]);
    }
  }

  data[k] = NULL;
  sd->data = data;

  /* Reset these variables.  The memory in them is allocated from this
   * same cmd_rec, and will be recovered when the cmd_rec is destroyed.
   */
  result_ncols = 0;
  result_list = NULL;

  return mod_create_data(cmd, sd);
}

MODRET sql_sqlite_open(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  const char *stmt = NULL;
  int res, xerrno = 0;
  unsigned int nretries = 0;

  sql_log(DEBUG_FUNC, "%s", "entering \tsqlite cmd_open");

  if (cmd->argc < 1) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_open");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, "badly formed request");
  }    

  /* Get the named connection. */
  entry = sql_sqlite_get_conn(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_open");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  } 

  conn = (db_conn_t *) entry->data;

  /* If we're already open (nconn > 0), increment the number of connections.
   * Reset our timer if we have one, and return HANDLED.
   */
  if (entry->nconn > 0) {
    entry->nconn++;

    if (entry->timer) {
      pr_timer_reset(entry->timer, &sql_sqlite_module);
    }

    sql_log(DEBUG_INFO, "'%s' connection count is now %u", entry->name,
      entry->nconn);
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_open");
    return PR_HANDLED(cmd);
  }

  /* Note that we do NOT automatically create the database if it does not
   * exist; we do not know the schema a database should have a priori.
   */
  PRIVS_ROOT
  res = sqlite3_open_v2(conn->dsn, &(conn->dbh), SQLITE_OPEN_READWRITE, NULL);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (res != SQLITE_OK) {
    char *errstr;

    errstr = pstrcat(cmd->pool, sqlite3_errmsg(conn->dbh),
      " (", strerror(xerrno), ")", NULL);
    sql_log(DEBUG_FUNC, "error opening SQLite database '%s': %s", conn->dsn,
      errstr);

    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_open");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, errstr);
  }

  if (pr_trace_get_level(trace_channel) >= SQLITE_TRACE_LEVEL) {
    sqlite3_trace(conn->dbh, db_trace, NULL);
  }

  /* Tell SQLite to only use in-memory journals.  This is necessary for
   * mod_sql_sqlite to work properly, for SQLLog statements, when a chroot
   * is used.  Note that the MEMORY journal mode of SQLite is supported
   * only for SQLite-3.6.5 and later.
   */
  stmt = "PRAGMA journal_mode = MEMORY;";
  res = sqlite3_exec(conn->dbh, stmt, NULL, NULL, NULL);

  /* Make sure we handle contention here, just like any other statement
   * (Issue#385).
   */
  while (res != SQLITE_OK) {
    if (res == SQLITE_BUSY) {
      struct timeval tv;

      nretries++;
      sql_log(DEBUG_FUNC, "attempt #%u, database busy, trying '%s' again",
        nretries, stmt);

      /* Sleep for short bit, then try again. */
      tv.tv_sec = 0;
      tv.tv_usec = 500000L;

      if (select(0, NULL, NULL, NULL, &tv) < 0) {
        if (errno == EINTR) {
          pr_signals_handle();
        }
      }

      res = sqlite3_exec(conn->dbh, stmt, NULL, NULL, NULL);
    }
  }

  if (res != SQLITE_OK) {
    sql_log(DEBUG_FUNC, "error setting MEMORY journal mode: %s",
      sqlite3_errmsg(conn->dbh));
  }

  /* Add some SQLite information to the logs. */
  sql_log(DEBUG_INFO, MOD_SQL_SQLITE_VERSION ": SQLite version: %s",
    sqlite3_libversion());

  entry->nconn++;

  if (pr_sql_conn_policy == SQL_CONN_POLICY_PERSESSION) {
    /* If the connection policy is PERSESSION... */
    if (entry->nconn == 1) {
      /* ...and we are actually opening the first connection to the database;
       * we want to make sure this connection stays open, after this first use
       * (as per Bug#3290).  To do this, we re-bump the connection count.
       */
      entry->nconn++;
    }

  } else if (entry->ttl > 0) {
    /* Set up our timer, if necessary. */
    entry->timer = pr_timer_add(entry->ttl, -1, &sql_sqlite_module,
      sql_sqlite_timer_cb, "sqlite connection ttl");

    sql_log(DEBUG_INFO, "'%s' connection: %d second timer started",
      entry->name, entry->ttl);

    /* Timed connections get re-bumped so they don't go away when
     * sql_sqlite_close() is called.
     */
    entry->nconn++;
  }

  sql_log(DEBUG_INFO, "'%s' connection opened", entry->name);
  sql_log(DEBUG_INFO, "'%s' connection count is now %u", entry->name,
    entry->nconn);
  pr_event_generate("mod_sql.db.connection-opened", &sql_sqlite_module);

  sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_open");
  return PR_HANDLED(cmd);
}

MODRET sql_sqlite_close(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;

  sql_log(DEBUG_FUNC, "%s", "entering \tsqlite cmd_close");

  if (cmd->argc < 1 || cmd->argc > 2) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_close");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, "badly formed request");
  }

  /* Get the named connection. */
  entry = sql_sqlite_get_conn(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_close");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  conn = (db_conn_t *) entry->data;

  /* If we're closed already (nconn == 0), return HANDLED. */
  if (entry->nconn == 0) {
    sql_log(DEBUG_INFO, "'%s' connection count is now %u", entry->name,
      entry->nconn);
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_close");
    return PR_HANDLED(cmd);
  }

  /* Decrement nconn. If our count is 0 or we received a second arg, close
   * the connection, explicitly set the counter to 0, and remove any timers.
   */
  if ((--entry->nconn) == 0 ||
      (cmd->argc == 2 && cmd->argv[1])) {

    if (conn->dbh) {
      if (sqlite3_close(conn->dbh) != SQLITE_OK) {
        sql_log(DEBUG_FUNC, "error closing SQLite database: %s",
          sqlite3_errmsg(conn->dbh));
      }

      conn->dbh = NULL;
    }

    entry->nconn = 0;

    if (entry->timer) {
      pr_timer_remove(entry->timer, &sql_sqlite_module);
      entry->timer = 0;
      sql_log(DEBUG_INFO, "'%s' connection timer stopped", entry->name);
    }

    sql_log(DEBUG_INFO, "'%s' connection closed", entry->name);
    pr_event_generate("mod_sql.db.connection-closed", &sql_sqlite_module);
  }

  sql_log(DEBUG_INFO, "'%s' connection count is now %u", entry->name,
    entry->nconn);
  sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_close");
  
  return PR_HANDLED(cmd);
}

MODRET sql_sqlite_cleanup(cmd_rec *cmd) {
  destroy_pool(conn_pool);
  conn_pool = NULL;
  conn_cache = NULL;

  return mod_create_data(cmd, NULL);
}

MODRET sql_sqlite_def_conn(cmd_rec *cmd) {
  char *name = NULL;
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL; 

  sql_log(DEBUG_FUNC, "%s", "entering \tsqlite cmd_defineconnection");

  if (cmd->argc < 4 ||
      cmd->argc > 10 ||
      !cmd->argv[0]) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_defineconnection");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, "badly formed request");
  }

  if (conn_pool == NULL) {
    pr_log_pri(PR_LOG_WARNING, "WARNING: the mod_sql_sqlite module has not "
      "been properly initialized.  Please make sure your --with-modules "
      "configure option lists mod_sql *before* mod_sql_sqlite, and recompile.");

    sql_log(DEBUG_FUNC, "%s", "The mod_sql_sqlite module has not been properly "
      "initialized.  Please make sure your --with-modules configure option "
      "lists mod_sql *before* mod_sql_sqlite, and recompile.");
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_defineconnection");

    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, "uninitialized module");
  }

  conn = (db_conn_t *) palloc(conn_pool, sizeof(db_conn_t));

  name = pstrdup(conn_pool, cmd->argv[0]);
  conn->user = pstrdup(conn_pool, cmd->argv[1]);
  conn->pass = pstrdup(conn_pool, cmd->argv[2]);
  conn->dsn = pstrdup(conn_pool, cmd->argv[3]);

  /* Insert the new conn_info into the connection hash */
  entry = sql_sqlite_add_conn(conn_pool, name, (void *) conn);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_defineconnection");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION,
      "named connection already exists");
  }

  if (cmd->argc >= 5) {
    entry->ttl = (int) strtol(cmd->argv[4], (char **) NULL, 10);
    if (entry->ttl >= 1) {
      pr_sql_conn_policy = SQL_CONN_POLICY_TIMER;

    } else {
      entry->ttl = 0;
    }
  }

  entry->timer = 0;
  entry->nconn = 0;

  sql_log(DEBUG_INFO, " name: '%s'", entry->name);
  sql_log(DEBUG_INFO, "  dsn: '%s'", conn->dsn);
  sql_log(DEBUG_INFO, "  ttl: '%d'", entry->ttl);

  sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_defineconnection");
  return PR_HANDLED(cmd);
}

MODRET sql_sqlite_exit(cmd_rec *cmd) {
  register unsigned int i = 0;

  sql_log(DEBUG_FUNC, "%s", "entering \tsqlite cmd_exit");

  for (i = 0; i < conn_cache->nelts; i++) {
    conn_entry_t *entry = ((conn_entry_t **) conn_cache->elts)[i];

    if (entry->nconn > 0) {
      cmd_rec *tmp = pr_cmd_alloc(conn_pool, 2, entry->name, "1");
      sql_sqlite_close(tmp);
      destroy_pool(tmp->pool);
    }
  }

  sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_exit");

  return PR_HANDLED(cmd);
}

MODRET sql_sqlite_select(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  modret_t *mr = NULL;
  char *errstr = NULL, *query = NULL;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \tsqlite cmd_select");

  if (cmd->argc < 2) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_select");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, "badly formed request");
  }

  /* Get the named connection. */
  entry = sql_sqlite_get_conn(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_select");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }
 
  conn = (db_conn_t *) entry->data;

  mr = sql_sqlite_open(cmd);
  if (MODRET_ERROR(mr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_select");
    return mr;
  }

  /* Construct the query string. */
  if (cmd->argc == 2) {
    query = pstrcat(cmd->tmp_pool, "SELECT ", cmd->argv[1], NULL);

  } else {
    query = pstrcat(cmd->tmp_pool, cmd->argv[2], " FROM ", cmd->argv[1], NULL);

    if (cmd->argc > 3 && cmd->argv[3])
      query = pstrcat(cmd->tmp_pool, query, " WHERE ", cmd->argv[3], NULL);

    if (cmd->argc > 4 && cmd->argv[4])
      query = pstrcat(cmd->tmp_pool, query, " LIMIT ", cmd->argv[4], NULL);

    if (cmd->argc > 5) {
      register unsigned int i = 0;

      /* Handle the optional arguments -- they're rare, so in this case
       * we'll play with the already constructed query string, but in 
       * general we should probably take optional arguments into account 
       * and put the query string together later once we know what they are.
       */
    
      for (i = 5; i < cmd->argc; i++) {
	if (cmd->argv[i] &&
            strcasecmp("DISTINCT", cmd->argv[i]) == 0)
	  query = pstrcat(cmd->tmp_pool, "DISTINCT ", query, NULL);
      }
    }

    query = pstrcat(cmd->tmp_pool, "SELECT ", query, NULL);
  }

  /* Log the query string */
  sql_log(DEBUG_INFO, "query \"%s\"", query);

  /* Perform the query.  If it doesn't work, log the error, close the
   * connection, then return the error from the query processing.
   */

  if (query_start(cmd, conn, 0, &errstr) < 0) {
    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sql_sqlite_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_select");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, errstr);
  }

  if (query_run(cmd, conn, query, &errstr) < 0) {
    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sql_sqlite_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_select");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, errstr);
  }

  if (query_finish(cmd, conn, &errstr) < 0) {
    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sql_sqlite_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_select");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, errstr);
  }

  mr = sql_sqlite_get_data(cmd);
  
  /* Close the connection, return the data. */
  close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
  sql_sqlite_close(close_cmd);
  destroy_pool(close_cmd->pool);

  sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_select");
  return mr;
}

MODRET sql_sqlite_insert(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  modret_t *mr = NULL;
  char *errstr = NULL, *query = NULL;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \tsqlite cmd_insert");

  if (cmd->argc != 2 &&
      cmd->argc != 4) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_insert");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, "badly formed request");
  }

  /* Get the named connection. */
  entry = sql_sqlite_get_conn(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_insert");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  conn = (db_conn_t *) entry->data;

  mr = sql_sqlite_open(cmd);
  if (MODRET_ERROR(mr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_insert");
    return mr;
  }

  /* Construct the query string. */
  if (cmd->argc == 2) {
    query = pstrcat(cmd->tmp_pool, "INSERT ", cmd->argv[1], NULL);

  } else {
    query = pstrcat(cmd->tmp_pool, "INSERT INTO ", cmd->argv[1],
      " (", cmd->argv[2], ") VALUES (", cmd->argv[3], ")", NULL);
  }

  /* Log the query string */
  sql_log(DEBUG_INFO, "query \"%s\"", query);

  /* Perform the query.  If it doesn't work, log the error, close the
   * connection (and log any errors there, too) then return the error
   * from the query processing.
   */

  if (query_start(cmd, conn, SQL_SQLITE_START_FL_NOW, &errstr) < 0) {
    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sql_sqlite_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_insert");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, errstr);
  }

  if (query_run(cmd, conn, query, &errstr) < 0) {
    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sql_sqlite_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_insert");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, errstr);
  }

  if (query_finish(cmd, conn, &errstr) < 0) {
    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sql_sqlite_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_insert");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, errstr);
  }

  /* Reset these variables.  The memory in them is allocated from this
   * same cmd_rec, and will be recovered when the cmd_rec is destroyed.
   */
  result_ncols = 0;
  result_list = NULL;

  /* Close the connection and return HANDLED. */
  close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
  sql_sqlite_close(close_cmd);
  destroy_pool(close_cmd->pool);

  sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_insert");
  return PR_HANDLED(cmd);
}

MODRET sql_sqlite_update(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  modret_t *mr = NULL;
  char *errstr = NULL, *query = NULL;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \tsqlite cmd_update");

  if (cmd->argc < 2 || cmd->argc > 4) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_update");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, "badly formed request");
  }

  /* Get the named connection. */
  entry = sql_sqlite_get_conn(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_update");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  conn = (db_conn_t *) entry->data;

  mr = sql_sqlite_open(cmd);
  if (MODRET_ERROR(mr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_update");
    return mr;
  }

  /* Construct the query string. */
  if (cmd->argc == 2) {
    query = pstrcat(cmd->tmp_pool, "UPDATE ", cmd->argv[1], NULL);

  } else {
    query = pstrcat(cmd->tmp_pool, "UPDATE ", cmd->argv[1], " SET ",
      cmd->argv[2], NULL);

    if (cmd->argc > 3 &&
        cmd->argv[3]) {
      query = pstrcat(cmd->tmp_pool, query, " WHERE ", cmd->argv[3], NULL);
    }
  }

  /* Log the query string. */
  sql_log(DEBUG_INFO, "query \"%s\"", query);

  /* Perform the query.  If it doesn't work close the connection, then
   * return the error from the query processing.
   */

  if (query_start(cmd, conn, SQL_SQLITE_START_FL_NOW, &errstr) < 0) {
    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sql_sqlite_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_update");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, errstr);
  }

  if (query_run(cmd, conn, query, &errstr) < 0) {
    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sql_sqlite_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_update");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, errstr);
  }

  if (query_finish(cmd, conn, &errstr) < 0) {
    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sql_sqlite_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_update");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, errstr);
  }

  /* Reset these variables.  The memory in them is allocated from this
   * same cmd_rec, and will be recovered when the cmd_rec is destroyed.
   */
  result_ncols = 0;
  result_list = NULL;

  /* Close the connection, return HANDLED.  */
  close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
  sql_sqlite_close(close_cmd);
  destroy_pool(close_cmd->pool);

  sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_update");
  return PR_HANDLED(cmd);
}

MODRET sql_sqlite_prepare(cmd_rec *cmd) {
  if (cmd->argc != 1) {
    return PR_ERROR(cmd);
  }

  conn_pool = (pool *) cmd->argv[0];

  if (conn_cache == NULL) {
    conn_cache = make_array(conn_pool, DEF_CONN_POOL_SIZE,
      sizeof(conn_entry_t *));
  }

  return mod_create_data(cmd, NULL);
}

MODRET sql_sqlite_procedure(cmd_rec *cmd) {
  sql_log(DEBUG_FUNC, "%s", "entering \tsqlite cmd_procedure");

  if (cmd->argc != 3) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_procedure");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, "badly formed request");
  }

  sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_procedure");
  return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION,
    "backend does not support procedures");
}

MODRET sql_sqlite_query(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  modret_t *mr = NULL;
  char *errstr = NULL, *query = NULL;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \tsqlite cmd_query");

  if (cmd->argc != 2) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_query");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, "badly formed request");
  }

  /* Get the named connection. */
  entry = sql_sqlite_get_conn(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_query");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  conn = (db_conn_t *) entry->data;

  mr = sql_sqlite_open(cmd);
  if (MODRET_ERROR(mr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_query");
    return mr;
  }

  query = pstrdup(cmd->tmp_pool, cmd->argv[1]);

  /* Log the query string */
  sql_log(DEBUG_INFO, "query \"%s\"", query);

  /* Perform the query.  If it doesn't work close the connection, then
   * return the error from the query processing.
   */

  if (query_start(cmd, conn, 0, &errstr) < 0) {
    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sql_sqlite_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_query");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, errstr);
  }

  if (query_run(cmd, conn, query, &errstr) < 0) {
    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sql_sqlite_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_query");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, errstr);
  }

  if (query_finish(cmd, conn, &errstr) < 0) {
    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sql_sqlite_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_query");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, errstr);
  }

  mr = sql_sqlite_get_data(cmd);
  
  /* Close the connection, return the data. */
  close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
  sql_sqlite_close(close_cmd);
  destroy_pool(close_cmd->pool);

  sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_query");
  return mr;
}

MODRET sql_sqlite_quote(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  modret_t *mr = NULL;
  char *unescaped = NULL, *escaped = NULL, *ptr = NULL;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \tsqlite cmd_escapestring");

  if (cmd->argc != 2) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_escapestring");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION, "badly formed request");
  }

  /* Get the named connection. */
  entry = sql_sqlite_get_conn(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_escapestring");
    return PR_ERROR_MSG(cmd, MOD_SQL_SQLITE_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  /* Make sure the connection is open. */
  mr = sql_sqlite_open(cmd);
  if (MODRET_ERROR(mr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_escapestring");
    return mr;
  }

  unescaped = cmd->argv[1];
  ptr = sqlite3_mprintf("%q", unescaped);
  escaped = pstrdup(cmd->pool, ptr);
  pr_trace_msg(trace_channel, 17, "quoted '%s' to '%s'", unescaped, escaped);
  sqlite3_free(ptr);

  close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
  sql_sqlite_close(close_cmd);
  destroy_pool(close_cmd->pool);

  sql_log(DEBUG_FUNC, "%s", "exiting \tsqlite cmd_escapestring");
  return mod_create_data(cmd, escaped);
}

MODRET sql_sqlite_identify(cmd_rec *cmd) {
  sql_data_t *sd = NULL;

  sd = (sql_data_t *) pcalloc(cmd->tmp_pool, sizeof(sql_data_t));
  sd->data = (char **) pcalloc(cmd->tmp_pool, sizeof(char *) * 2);

  sd->rnum = 1;
  sd->fnum = 2;

  sd->data[0] = MOD_SQL_SQLITE_VERSION;
  sd->data[1] = MOD_SQL_API_V1;

  return mod_create_data(cmd, (void *) sd);
}  

static cmdtable sql_sqlite_cmdtable[] = {
  { CMD, "sql_close",		G_NONE, sql_sqlite_close,	FALSE, FALSE },
  { CMD, "sql_cleanup",		G_NONE, sql_sqlite_cleanup,	FALSE, FALSE },
  { CMD, "sql_defineconnection",G_NONE, sql_sqlite_def_conn,	FALSE, FALSE },
  { CMD, "sql_escapestring",	G_NONE, sql_sqlite_quote,	FALSE, FALSE },
  { CMD, "sql_exit",		G_NONE,	sql_sqlite_exit,	FALSE, FALSE },
  { CMD, "sql_identify",	G_NONE, sql_sqlite_identify,	FALSE, FALSE },
  { CMD, "sql_insert",		G_NONE, sql_sqlite_insert,	FALSE, FALSE },
  { CMD, "sql_open",		G_NONE,	sql_sqlite_open,	FALSE, FALSE },
  { CMD, "sql_prepare",		G_NONE, sql_sqlite_prepare,	FALSE, FALSE },
  { CMD, "sql_procedure",	G_NONE, sql_sqlite_procedure,	FALSE, FALSE },
  { CMD, "sql_query",		G_NONE, sql_sqlite_query,	FALSE, FALSE },
  { CMD, "sql_select",		G_NONE, sql_sqlite_select,	FALSE, FALSE },
  { CMD, "sql_update",		G_NONE, sql_sqlite_update,	FALSE, FALSE },
  { 0, NULL }
};

/* Event handlers
 */

static void sql_sqlite_mod_load_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_sql_sqlite.c", (const char *) event_data) == 0) {
    /* Register ourselves with mod_sql. */
    if (sql_register_backend("sqlite3", sql_sqlite_cmdtable) < 0) {
      pr_log_pri(PR_LOG_NOTICE, MOD_SQL_SQLITE_VERSION
        ": notice: error registering backend: %s", strerror(errno));
      pr_session_end(0);
    }
  }
}

static void sql_sqlite_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_sql_sqlite.c", (const char *) event_data) == 0) {
    /* Unegister ourselves with mod_sql. */
    if (sql_unregister_backend("sqlite3") < 0) {
      pr_log_pri(PR_LOG_NOTICE, MOD_SQL_SQLITE_VERSION
        ": notice: error unregistering backend: %s", strerror(errno));
      pr_session_end(0);
    }

    pr_event_unregister(&sql_sqlite_module, NULL, NULL);

    /* Note that we do NOT call sqlite3_shutdown() here, as SQLite may
     * also be being used by other modules.
     */
  }
}

/* Initialization routines
 */

static int sql_sqlite_init(void) {

  /* Register listeners for the load and unload events. */
  pr_event_register(&sql_sqlite_module, "core.module-load",
    sql_sqlite_mod_load_ev, NULL);
  pr_event_register(&sql_sqlite_module, "core.module-unload",
    sql_sqlite_mod_unload_ev, NULL);

#if defined(SQLITE_CONFIG_LOG)
  sqlite3_config(SQLITE_CONFIG_LOG, db_err, NULL);
#endif /* SQLite_CONFIG_LOG */

  /* Check that the SQLite headers used match the version of the SQLite
   * library used.
   *
   * For now, we only log if there is a difference.
   */
  if (strcmp(sqlite3_libversion(), SQLITE_VERSION) != 0) {
    pr_log_pri(PR_LOG_INFO, MOD_SQL_SQLITE_VERSION
      ": compiled using SQLite version '%s' headers, but linked to "
      "SQLite version '%s' library", SQLITE_VERSION, sqlite3_libversion());
  }

  pr_log_debug(DEBUG3, MOD_SQL_SQLITE_VERSION ": using SQLite %s",
    sqlite3_libversion());

  return 0;
}

static int sql_sqlite_sess_init(void) {
  if (conn_pool == NULL) {
    conn_pool = make_sub_pool(session.pool);
    pr_pool_tag(conn_pool, "SQLite connection pool");
  }

  if (conn_cache == NULL) {
    conn_cache = make_array(make_sub_pool(session.pool), DEF_CONN_POOL_SIZE,
      sizeof(conn_entry_t *));
  }

  return 0;
}

/* Module API tables
 */

module sql_sqlite_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "sql_sqlite",

  /* Module configuration directive table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  sql_sqlite_init,

  /* Session initialization */
  sql_sqlite_sess_init,

  /* Module version */
  MOD_SQL_SQLITE_VERSION
};
