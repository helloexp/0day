/*
 * ProFTPD: mod_sql_mysql -- Support for connecting to MySQL databases.
 * Copyright (c) 2001 Andrew Houghton
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
 * As a special exemption, Andrew Houghton and other respective copyright
 * holders give permission to link this program with OpenSSL, and distribute
 * the resulting executable, without including the source code for OpenSSL in
 * the source distribution.
 *
 * -----DO NOT EDIT-----
 * $Libraries: -lm -lmysqlclient -lz$
 */

/* INTRO:
 *
 * mod_sql_mysql is the reference backend module for mod_sql. As such,
 * it's very, very over-commented.
 *
 * COPYRIGHT NOTICE:  
 * 
 * The section of the copyright notice above that refers to OpenSSL *must* 
 * be present in every backend module.  Without that exemption the backend 
 * module cannot legally be compiled into ProFTPD, even if the backend 
 * module makes no use of OpenSSL.
 *
 * FUNCTIONS IN THIS CODE:
 *
 * Backend modules are only called into via the functions listed in
 * sql_cmdtable (see the end of this file).  All other functions are 
 * internal.
 *
 * For stylistic reasons, it's requested that backend authors maintain the
 * following conventions:
 *  1) when returning data in a modret_t, use the standard ProFTPD macros
 *     whenever possible (ERR_MSG, HANDLED, etc.)
 *  2) although 'static modret_t *' and 'MODRET' are equivalent, please
 *     use MODRET only for those functions listed in sql_cmdtable.
 *
 * NAMED CONNECTIONS:
 *
 * Backend modules need to handle named connections.  A named connection
 * is the complete specification of how to access a database coupled with
 * a unique (to the session) descriptive name.  Every call mod_sql makes 
 * into a backend is directed at a particular named connection.  
 * mod_sql_mysql includes a set of simplistic cache functions to keep an 
 * internal map of names to connections -- other backends should feel free 
 * to handle this however they want.
 *
 * OPEN/CLOSE SEMANTICS & CONNECTION COUNTING:
 *
 * Administrators using mod_sql decide on one of three connection policies:
 *  1) open a connection to the database and hold it open for the life of
 *     the client process
 *  2) open a connection to the database and hold it open for the life of
 *     each call
 *  3) open a connection to the database and hold it open until a specified
 *     period of time has elapsed with no activity
 *
 * mod_sql enforces this choice by requiring that backends:
 *  1) wrap each call in an open/close bracket (so if a connection isn't 
 *     currently open, it will be opened for the call and closed afterwards)
 *  2) properly do connection counting to ensure that a connection is not
 *     re-opened unnecessarily, and not closed too early.
 *
 * In simple terms: if an administrator chooses the "one connection for the
 * life of the process" policy, mod_sql will send an initial cmd_open call
 * for that connection at the start of the client session, and a final 
 * cmd_close call when the session ends.  If an administrator chooses the
 * "per-call" connection policy, the initial cmd_open and final cmd_close
 * calls will not be made.  If an administrator chooses the "timeout"
 * connection policy, connections may be closed at any time and may need
 * to be reopened for any call.
 *
 * CONNECTION TIMERS
 *
 * Backends are required to handle connection timers; when a connection is 
 * defined via cmd_defineconnection, a time value (in seconds) will be sent
 * with the definition.  Given the complexity of the semantics, it's
 * recommended that backend authors simply copy the timer handling code from
 * this module.  Timer handling code exists in nearly every function in this
 * module; read the code for more information.
 *
 * ERROR HANDLING AND LOGGING:
 * 
 * Proper error handling is required of backend modules -- the modret_t 
 * structure passed back to mod_sql should have the error fields correctly
 * filled.  mod_sql handles backend errors by logging them then closing the
 * connection and the session.  Therefore, it's not necessary for backends
 * to log errors which will be passed back to mod_sql, but they should log
 * any errors or useful information which will not be returned in the 
 * modret_t.  If an error is transient -- if there's any way for the backend
 * module to handle an error intelligently -- it should do so.  mod_sql
 * will always handle backend errors by ending the client session.
 * 
 * Good debug logging is encouraged -- major functions (the functions that
 * mod_sql calls directly) should be wrapped in 'entering' and 'exiting' 
 * DEBUG_FUNC level output, the text of SQL queries should be visible with
 * DEBUG_INFO level output, and any errors should be visible with DEBUG_WARN
 * level output.  
 *
 * Check the code if this makes no sense.
 *
 * COMMENTS / QUESTIONS:
 * 
 * Backend module writers are encouraged to read through all comments in this
 * file.  If anything is unclear, please contact the author.  
 */

/* Internal define used for debug and logging.  All backends are encouraged
 * to use the same format.
 */
#define MOD_SQL_MYSQL_VERSION		"mod_sql_mysql/4.0.9"

#define _MYSQL_PORT "3306"

#include "conf.h"
#include "../contrib/mod_sql.h"

#include <mysql.h>
#include <stdbool.h>

/* The my_make_scrambled_password{,_323} functions are not part of the public
 * MySQL API and are not declared in any of the MySQL header files. But the
 * use of these functions are required for implementing the "Backend"
 * SQLAuthType for MySQL. Thus these functions are declared here (Bug#3908).
 */
#if defined(HAVE_MYSQL_MY_MAKE_SCRAMBLED_PASSWORD)
void my_make_scrambled_password(char *to, const char *from, size_t fromlen);
#endif

#if defined(HAVE_MYSQL_MY_MAKE_SCRAMBLED_PASSWORD_323)
void my_make_scrambled_password_323(char *to, const char *from, size_t fromlen);
#endif

/* Timer-handling code adds the need for a couple of forward declarations. */
MODRET cmd_close(cmd_rec *cmd);
module sql_mysql_module;

/* 
 * db_conn_struct: an internal struct to hold connection information. This 
 *  connection information is backend-specific; the members here reflect 
 *  the information MySQL needs for connections.  
 *
 *  Other backends are expected to make whatever changes are necessary.
 */
struct db_conn_struct {

  /* MySQL-specific members */
  const char *host;
  const char *user;
  const char *pass;
  const char *db;
  const char *port;
  const char *unix_sock;

  /* For configuring the SSL/TLS session to the MySQL server. */
  const char *ssl_cert_file;
  const char *ssl_key_file;
  const char *ssl_ca_file;
  const char *ssl_ca_dir;
  const char *ssl_ciphers;

  MYSQL *mysql;
};

typedef struct db_conn_struct db_conn_t;

/*
 * This struct is a wrapper for whatever backend data is needed to access 
 * the database, and supports named connections, connection counting, and 
 * timer handling.  In most cases it should be enough for backend authors 
 * to change db_conn_t and leave this struct alone.
 */

struct conn_entry_struct {
  const char *name;
  void *data;

  /* Timer handling */
  int timer;
  int ttl;

  /* Connection handling */
  unsigned int connections;
};

typedef struct conn_entry_struct conn_entry_t;

#define DEF_CONN_POOL_SIZE 10

static pool *conn_pool = NULL;
static array_header *conn_cache = NULL;

static const char *trace_channel = "sql.mysql";

/*  sql_get_connection: walks the connection cache looking for the named
 *   connection.  Returns NULL if unsuccessful, a pointer to the conn_entry_t
 *   if successful.
 */
static conn_entry_t *sql_get_connection(const char *conn_name) {
  register unsigned int i;

  if (conn_name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* walk the array looking for our entry */
  for (i = 0; i < conn_cache->nelts; i++) {
    conn_entry_t *entry;

    entry = ((conn_entry_t **) conn_cache->elts)[i];
    if (strcmp(conn_name, entry->name) == 0) {
      return entry;
    }
  }

  errno = ENOENT;
  return NULL;
}

/* sql_add_connection: internal helper function to maintain a cache of
 *  connections.  Since we expect the number of named connections to be small,
 *  simply use an array header to hold them.  We don't allow duplicate
 *  connection names.
 *
 * Returns: NULL if the insertion was unsuccessful, a pointer to the 
 *  conn_entry_t that was created if successful.
 */
static void *sql_add_connection(pool *p, const char *name, db_conn_t *conn) {
  conn_entry_t *entry = NULL;

  if (name == NULL ||
      conn == NULL ||
      p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (sql_get_connection(name) != NULL) {
    errno = EEXIST;
    return NULL;
  }

  entry = (conn_entry_t *) pcalloc(p, sizeof(conn_entry_t));
  entry->name = pstrdup(p, name);
  entry->data = conn;

  *((conn_entry_t **) push_array(conn_cache)) = entry;
  return entry;
}

/* sql_check_cmd: tests to make sure the cmd_rec is valid and is properly
 *  filled in.  If not, it's grounds for the daemon to shutdown.
 */
static void sql_check_cmd(cmd_rec *cmd, char *msg) {
  if (cmd == NULL ||
      cmd->tmp_pool == NULL) {
    pr_log_pri(PR_LOG_ERR, MOD_SQL_MYSQL_VERSION
      ": '%s' was passed an invalid cmd_rec (internal bug); shutting down",
      msg);
    sql_log(DEBUG_WARN, "'%s' was passed an invalid cmd_rec (internal bug); "
      "shutting down", msg);
    pr_session_end(0);
  }    

  return;
}

/* sql_timer_cb: when a timer goes off, this is the function that gets called.
 * This function makes assumptions about the db_conn_t members.
 */
static int sql_timer_cb(CALLBACK_FRAME) {
  register unsigned int i;
 
  for (i = 0; i < conn_cache->nelts; i++) {
    conn_entry_t *entry = NULL;

    entry = ((conn_entry_t **) conn_cache->elts)[i];
    if ((unsigned long) entry->timer == p2) {
      cmd_rec *cmd = NULL;

      sql_log(DEBUG_INFO, "timer expired for connection '%s'", entry->name);
      cmd = sql_make_cmd(conn_pool, 2, entry->name, "1");
      cmd_close(cmd);
      SQL_FREE_CMD(cmd);
      entry->timer = 0;
    }
  }

  return 0;
}

/* build_error: constructs a modret_t filled with error information;
 *  mod_sql_mysql calls this function and returns the resulting mod_ret_t
 *  whenever a call to the database results in an error.  Other backends
 *  may want to use a different method to return error information.
 */
static modret_t *build_error(cmd_rec *cmd, db_conn_t *conn) {
  char num[20] = {'\0'};

  if (conn == NULL) {
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION, "badly formed request");
  }

  pr_snprintf(num, 20, "%u", mysql_errno(conn->mysql));
  return PR_ERROR_MSG(cmd, pstrdup(cmd->pool, num),
    pstrdup(cmd->pool, (char *) mysql_error(conn->mysql)));
}

/* build_data: both cmd_select and cmd_procedure potentially
 *  return data to mod_sql; this function builds a modret to return
 *  that data.  This is MySQL specific; other backends may choose 
 *  to do things differently.
 */
static modret_t *build_data(cmd_rec *cmd, db_conn_t *conn) {
  modret_t *mr = NULL;
  MYSQL *mysql = NULL;
  MYSQL_RES *result = NULL;
  MYSQL_ROW row;
  sql_data_t *sd = NULL;
  char **data = NULL;
  unsigned long cnt = 0;
  unsigned long i = 0;

  if (conn == NULL) {
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION, "badly formed request");
  }

  mysql = conn->mysql;

  /* Would much rather use mysql_use_result here but without knowing
   * the number of rows returned we can't presize the data[] array.
   */

  result = mysql_store_result(mysql);
  if (!result) {
    return build_error(cmd, conn);
  }
  
  sd = (sql_data_t *) pcalloc(cmd->tmp_pool, sizeof(sql_data_t));
  sd->rnum = (unsigned long) mysql_num_rows(result);
  sd->fnum = (unsigned long) mysql_num_fields(result);
  cnt = sd->rnum * sd->fnum;

  data = (char **) pcalloc(cmd->tmp_pool, sizeof(char *) * (cnt + 1));
  
  while ((row = mysql_fetch_row(result))) {
    for (cnt = 0; cnt < sd->fnum; cnt++)
      data[i++] = pstrdup(cmd->tmp_pool, row[cnt]);
  }
  
  /* At this point either we finished correctly or an error occurred in the
   * fetch.  Do the right thing.
   */
  if (mysql_errno(mysql) != 0) {
    mr = build_error(cmd, conn);
    mysql_free_result(result);
    return mr;
  }

  mysql_free_result(result);
  data[i] = NULL;
  sd->data = data;

#ifdef CLIENT_MULTI_RESULTS
  /* We might be dealing with multiple result sets here, as when a stored
   * procedure was called which produced more results than we expect.
   *
   * We only want the first result set, so simply iterate through and free
   * up any remaining result sets.
   */
  while (mysql_next_result(mysql) == 0) {
    pr_signals_handle();
    result = mysql_store_result(mysql);
    mysql_free_result(result);
  }
#endif

  return mod_create_data(cmd, (void *) sd);
}

/*
 * cmd_open: attempts to open a named connection to the database.
 *
 * Inputs:
 *  cmd->argv[0]: connection name
 *
 * Returns:
 *  either a properly filled error modret_t if a connection could not be
 *  opened, or a simple non-error modret_t.
 *
 * Notes:
 *  mod_sql depends on these semantics -- a backend should not open
 *  a connection unless mod_sql requests it, nor close one unless 
 *  mod_sql requests it.  Connection counting is *REQUIRED* for complete
 *  compatibility; a connection should not be closed unless the count
 *  reaches 0, and ideally will not need to be re-opened for counts > 1.
 */
MODRET cmd_open(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  unsigned long client_flags = CLIENT_INTERACTIVE;
#ifdef PR_USE_NLS
  const char *encoding = NULL;
#endif
#ifdef HAVE_MYSQL_MYSQL_GET_SSL_CIPHER
  const char *ssl_cipher = NULL;
#endif

  sql_log(DEBUG_FUNC, "%s", "entering \tmysql cmd_open");

  sql_check_cmd(cmd, "cmd_open");

  if (cmd->argc < 1) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_open");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION, "badly formed request");
  }    

  entry = sql_get_connection(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_open");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  } 

  conn = (db_conn_t *) entry->data;

  /* If we're already open (connections > 0), AND our connection to MySQL
   * is still alive, increment the connection counter, reset our timer (if
   * we have one), and return HANDLED.
   */
  if (entry->connections > 0) {
    if (mysql_ping(conn->mysql) == 0) {
      entry->connections++;

      if (entry->timer) {
        pr_timer_reset(entry->timer, &sql_mysql_module);
      }

      sql_log(DEBUG_INFO, "connection '%s' count is now %d", entry->name,
        entry->connections);
      sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_open");
      return PR_HANDLED(cmd);

    } else {
      sql_log(DEBUG_INFO, "lost connection to database: %s",
        mysql_error(conn->mysql));

      entry->connections = 0;
      if (entry->timer) {
        pr_timer_remove(entry->timer, &sql_mysql_module);
        entry->timer = 0;
      }

      sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_open");
      return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION,
        "lost connection to database");
    }
  }

  /* Make sure we have a new conn struct */
  conn->mysql = mysql_init(NULL);
  if (conn->mysql == NULL) {
    pr_log_pri(PR_LOG_ALERT, MOD_SQL_MYSQL_VERSION
      ": failed to allocate memory for MYSQL structure; shutting down");
    sql_log(DEBUG_WARN, "%s", "failed to allocate memory for MYSQL structure; "
      "shutting down");
    pr_session_end(0);
  }

  if (!(pr_sql_opts & SQL_OPT_IGNORE_CONFIG_FILE)) {
    /* Make sure the MySQL config files are read in.  This will read in
     * options from group "client" in the MySQL .cnf files.
     */
    mysql_options(conn->mysql, MYSQL_READ_DEFAULT_GROUP, "client");
  }

#if MYSQL_VERSION_ID >= 50013
  /* The MYSQL_OPT_RECONNECT option appeared in MySQL 5.0.13, according to
   *
   *  http://dev.mysql.com/doc/refman/5.0/en/auto-reconnect.html
   */
  if (!(pr_sql_opts & SQL_OPT_NO_RECONNECT)) {
#if MYSQL_VERSION_ID >= 80000
    bool reconnect = true;
#else
    my_bool reconnect = TRUE;
#endif
    mysql_options(conn->mysql, MYSQL_OPT_RECONNECT, &reconnect);
  }
#endif

#ifdef CLIENT_MULTI_RESULTS
  /* Enable mod_sql_mysql to deal with multiple result sets which may be
   * returned from calling stored procedures.
   */
  client_flags |= CLIENT_MULTI_RESULTS;
#endif

#if defined(HAVE_MYSQL_MYSQL_SSL_SET)
  /* Per the MySQL docs, this function always returns success.  Errors are
   * reported when we actually attempt to connect.
   *
   * Note: There are some other TLS-related options, in newer versions of
   * MySQL, which might be interest (although they require the use of the
   * mysql_options() function, not mysql_ssl_set()):
   *
   *  MYSQL_OPT_SSL_ENFORCE (boolean, defaults to 'false')
   *  MYSQL_OPT_SSL_VERIFY_SERVER_CERT (boolean, defaults to 'false')
   *  MYSQL_OPT_TLS_VERSION (char *, for configuring the protocol versions)
   */
  (void) mysql_ssl_set(conn->mysql, conn->ssl_key_file, conn->ssl_cert_file,
    conn->ssl_ca_file, conn->ssl_ca_dir, conn->ssl_ciphers);
#endif

  if (!mysql_real_connect(conn->mysql, conn->host, conn->user, conn->pass,
      conn->db, (int) strtol(conn->port, (char **) NULL, 10),
      conn->unix_sock, client_flags)) {
    modret_t *mr = NULL;

    /* If it didn't work, return an error. */
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_open");
    mr = build_error(cmd, conn);

    /* Since we failed to connect here, avoid a memory leak by freeing up the
     * mysql conn struct.
     */
    mysql_close(conn->mysql);
    conn->mysql = NULL;

    return mr;
  }

  sql_log(DEBUG_FUNC, "MySQL client version: %s", mysql_get_client_info());
  sql_log(DEBUG_FUNC, "MySQL server version: %s",
    mysql_get_server_info(conn->mysql));

# if MYSQL_VERSION_ID >= 50703 && defined(HAVE_MYSQL_GET_OPTION)
  /* Log the configured authentication plugin, if any.  For example, it
   * might be set in the my.cnf file using:
   *
   *   [client]
   *   default-auth = mysql_native_password
   *
   * Note: the mysql_get_option() function appeared in MySQL 5.7.3, as per:
   *
   *  https://dev.mysql.com/doc/refman/5.7/en/mysql-get-option.html
   *
   * The MYSQL_DEFAULT_AUTH value is an enum, not a #define, so we cannot
   * use a simple #ifdef here.
   */
  {
    const char *auth_plugin = NULL;

    if (mysql_get_option(conn->mysql, MYSQL_DEFAULT_AUTH, &auth_plugin) == 0) {
      /* There may not have been a default auth plugin explicitly configured,
       * and the MySQL internals themselves may not set one.  So it is not
       * surprising if the pointer remains null.
       */
      if (auth_plugin != NULL) {
        sql_log(DEBUG_FUNC, "MySQL client default authentication plugin: %s",
          auth_plugin);
      }
    }
  }
#endif /* MySQL 5.7.3 and later */

#if defined(HAVE_MYSQL_MYSQL_GET_SSL_CIPHER)
  ssl_cipher = mysql_get_ssl_cipher(conn->mysql);
  /* XXX Should we fail the connection here, if we expect an SSL session to
   * have been successfully completed/required?
   */
  if (ssl_cipher != NULL) {
    sql_log(DEBUG_FUNC, "%s", "MySQL SSL connection: true");
    sql_log(DEBUG_FUNC, "MySQL SSL cipher: %s", ssl_cipher);

  } else {
    sql_log(DEBUG_FUNC, "%s", "MySQL SSL connection: false");
  }
#endif

#if defined(PR_USE_NLS)
  encoding = pr_encode_get_encoding();
  if (encoding != NULL) {

# if MYSQL_VERSION_ID >= 50007
    /* Configure the connection for the current local character set.
     *
     * Note: the mysql_set_character_set() function appeared in MySQL 5.0.7,
     * as per:
     *
     *  http://dev.mysql.com/doc/refman/5.0/en/mysql-set-character-set.html
     *
     * Yes, even though the variable names say "charset", we (and MySQL,
     * though their documentation says otherwise) actually mean "encoding".
     */

     if (strcasecmp(encoding, "UTF-8") == 0) {
#  if MYSQL_VERSION_ID >= 50503
       /* MySQL prefers the name "utf8mb4", not "UTF-8" */
       encoding = pstrdup(cmd->tmp_pool, "utf8mb4");
#  else
       /* MySQL prefers the name "utf8", not "UTF-8" */
       encoding = pstrdup(cmd->tmp_pool, "utf8");
#  endif /* MySQL before 5.5.3 */
     }

    if (mysql_set_character_set(conn->mysql, encoding) != 0) {
      /* Failing to set the character set should NOT be a fatal error.
       * There are situations where, due to client/server mismatch, the
       * requested character set may not be available.  Thus for now,
       * we simply log the failure.
       *
       * A future improvement might be to implement fallback behavior,
       * trying to set "older" character sets as needed.
       */
      sql_log(DEBUG_FUNC, MOD_SQL_MYSQL_VERSION
        ": failed to set character set '%s': %s (%u)", encoding,
        mysql_error(conn->mysql), mysql_errno(conn->mysql));
    }

    sql_log(DEBUG_FUNC, "MySQL connection character set now '%s' (from '%s')",
      mysql_character_set_name(conn->mysql), pr_encode_get_encoding());

# else
    /* No mysql_set_character_set() API available.  But
     * mysql_character_set_name() has been around for a while; we can use it
     * to at least see whether there might be a character set discrepancy.
     */

    const char *local_charset = pr_encode_get_encoding();
    const char *mysql_charset = mysql_character_set_name(conn->mysql);

    if (strcasecmp(mysql_charset, "utf8") == 0) {
      mysql_charset = pstrdup(cmd->tmp_pool, "UTF-8");
    }

    if (local_charset &&
        mysql_charset &&
        strcasecmp(local_charset, mysql_charset) != 0) {
      pr_log_pri(PR_LOG_ERR, MOD_SQL_MYSQL_VERSION
        ": local character set '%s' does not match MySQL character set '%s', "
        "SQL injection possible, shutting down", local_charset, mysql_charset);
      sql_log(DEBUG_WARN, "local character set '%s' does not match MySQL "
        "character set '%s', SQL injection possible, shutting down",
        local_charset, mysql_charset);
      pr_session_end(0);
    }
# endif /* older MySQL */
  }
#endif /* !PR_USE_NLS */

  /* bump connections */
  entry->connections++;

  if (pr_sql_conn_policy == SQL_CONN_POLICY_PERSESSION) {
    /* If the connection policy is PERSESSION... */
    if (entry->connections == 1) {
      /* ...and we are actually opening the first connection to the database;
       * we want to make sure this connection stays open, after this first use
       * (as per Bug#3290).  To do this, we re-bump the connection count.
       */
      entry->connections++;
    } 
 
  } else if (entry->ttl > 0) { 
    /* Set up our timer if necessary */

    entry->timer = pr_timer_add(entry->ttl, -1, &sql_mysql_module,
      sql_timer_cb, "mysql connection ttl");
    sql_log(DEBUG_INFO, "connection '%s' - %d second timer started",
      entry->name, entry->ttl);

    /* timed connections get re-bumped so they don't go away when cmd_close
     * is called.
     */
    entry->connections++;
  }

  /* return HANDLED */
  sql_log(DEBUG_INFO, "connection '%s' opened", entry->name);
  sql_log(DEBUG_INFO, "connection '%s' count is now %d", entry->name,
    entry->connections);
  pr_event_generate("mod_sql.db.connection-opened", &sql_mysql_module);

  sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_open");
  return PR_HANDLED(cmd);
}

/*
 * cmd_close: attempts to close the named connection.
 *
 * Inputs:
 *  cmd->argv[0]: connection name
 * Optional:
 *  cmd->argv[1]: close immediately
 *
 * Returns:
 *  either a properly filled error modret_t if a connection could not be
 *  closed, or a simple non-error modret_t.  For the case of mod_sql_mysql,
 *  there are no error codes returned by the close call; other backends
 *  may be able to return a useful error message.
 *
 * Notes:
 *  mod_sql depends on these semantics -- a backend should not open
 *  a connection unless mod_sql requests it, nor close one unless 
 *  mod_sql requests it.  Connection counting is *REQUIRED* for complete
 *  compatibility; a connection should not be closed unless the count
 *  reaches 0, and should not need to be re-opened for counts > 1.
 * 
 *  If argv[1] exists and is not NULL, the connection should be immediately
 *  closed and the connection count should be reset to 0.
 */
MODRET cmd_close(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;

  sql_log(DEBUG_FUNC, "%s", "entering \tmysql cmd_close");

  sql_check_cmd(cmd, "cmd_close");

  if ((cmd->argc < 1) || (cmd->argc > 2)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_close");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION, "badly formed request");
  }

  entry = sql_get_connection(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_close");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  conn = (db_conn_t *) entry->data;

  /* if we're closed already (connections == 0) return HANDLED */
  if (entry->connections == 0) {
    sql_log(DEBUG_INFO, "connection '%s' count is now %d", entry->name,
      entry->connections);

    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_close");
    return PR_HANDLED(cmd);
  }

  /* decrement connections. If our count is 0 or we received a second arg
   * close the connection, explicitly set the counter to 0, and remove any
   * timers.
   */
  if (((--entry->connections) == 0) || ((cmd->argc == 2) && (cmd->argv[1]))) {
    if (conn->mysql != NULL) {
      mysql_close(conn->mysql);
      conn->mysql = NULL;
    }
    entry->connections = 0;

    if (entry->timer) {
      pr_timer_remove(entry->timer, &sql_mysql_module);
      entry->timer = 0;
      sql_log(DEBUG_INFO, "connection '%s' - timer stopped", entry->name);
    }

    sql_log(DEBUG_INFO, "connection '%s' closed", entry->name);
    pr_event_generate("mod_sql.db.connection-closed", &sql_mysql_module);
  }

  sql_log(DEBUG_INFO, "connection '%s' count is now %d", entry->name,
    entry->connections);
  sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_close");
  
  return PR_HANDLED(cmd);
}

/* cmd_defineconnection: takes all information about a database
 *  connection and stores it for later use.
 *
 * Inputs:
 *  cmd->argv[0]: connection name
 *  cmd->argv[1]: username portion of the SQLConnectInfo directive
 *  cmd->argv[2]: password portion of the SQLConnectInfo directive
 *  cmd->argv[3]: info portion of the SQLConnectInfo directive
 *
 * Optional:
 *  cmd->argv[4]: time-to-live in seconds
 *  cmd->argv[5]: SSL client cert file
 *  cmd->argv[6]: SSL client key file
 *  cmd->argv[7]: SSL CA file
 *  cmd->argv[8]: SSL CA directory
 *  cmd->argv[9]: SSL ciphers
 *
 * Returns:
 *  either a properly filled error modret_t if the connection could not
 *  defined, or a simple non-error modret_t.
 *
 * Notes:
 *  time-to-live is the length of time to allow a connection to remain unused;
 *  once that amount of time has passed, a connection should be closed and 
 *  it's connection count should be reduced to 0.  If ttl is 0, or ttl is not 
 *  a number or ttl is negative, the connection will be assumed to have no
 *  associated timer.
 */
MODRET cmd_defineconnection(cmd_rec *cmd) {
  char *have_host = NULL, *have_port = NULL, *info = NULL, *name = NULL;
  const char *db = NULL, *host = NULL, *port = NULL;
  const char *ssl_cert_file = NULL, *ssl_key_file = NULL, *ssl_ca_file = NULL;
  const char *ssl_ca_dir = NULL, *ssl_ciphers = NULL;
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL; 

  sql_log(DEBUG_FUNC, "%s", "entering \tmysql cmd_defineconnection");

  sql_check_cmd(cmd, "cmd_defineconnection");

  if (cmd->argc < 4 ||
      cmd->argc > 10 ||
      !cmd->argv[0]) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_defineconnection");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION, "badly formed request");
  }

  if (conn_pool == NULL) {
    pr_log_pri(PR_LOG_WARNING, "WARNING: the mod_sql_mysql module has not been "
      "properly initialized.  Please make sure your --with-modules configure "
      "option lists mod_sql *before* mod_sql_mysql, and recompile.");

    sql_log(DEBUG_FUNC, "%s", "The mod_sql_mysql module has not been properly "
      "initialized.  Please make sure your --with-modules configure option "
      "lists mod_sql *before* mod_sql_mysql, and recompile.");
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_defineconnection");

    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION, "uninitialized module");
  }

  conn = (db_conn_t *) pcalloc(conn_pool, sizeof(db_conn_t));

  name = pstrdup(conn_pool, cmd->argv[0]);
  conn->user = pstrdup(conn_pool, cmd->argv[1]);
  conn->pass = pstrdup(conn_pool, cmd->argv[2]);

  info = cmd->argv[3];

  db = pstrdup(cmd->tmp_pool, info);

  have_host = strchr(db, '@');
  have_port = strchr(db, ':');

  /* If have_port, parse it, otherwise default it.
   * If have_port, set it to '\0'.
   *
   * If have_host, parse it, otherwise default it.
   * If have_host, set it to '\0'.
   */

  if (have_port != NULL) {
    port = have_port + 1;
    *have_port = '\0';

  } else {
    port = _MYSQL_PORT;
  }

  if (have_host != NULL) {
    host = have_host + 1;
    *have_host = '\0';

  } else {
    host = "localhost";
  }

  /* Hack to support ability to configure path to Unix domain socket
   * for MySQL: if the host string starts with a '/', assume it's
   * a path to the Unix domain socket to use.
   */
  if (*host == '/') {
    conn->unix_sock = pstrdup(conn_pool, host);

  } else {
    conn->host = pstrdup(conn_pool, host);
  }

  conn->db = pstrdup(conn_pool, db);
  conn->port = pstrdup(conn_pool, port);

  /* SSL parameters, if configured. */
  if (cmd->argc >= 6) {
    ssl_cert_file = cmd->argv[5];
    if (ssl_cert_file != NULL) {
      conn->ssl_cert_file = pstrdup(conn_pool, ssl_cert_file);
    }
  }

  if (cmd->argc >= 7) {
    ssl_key_file = cmd->argv[6];
    if (ssl_key_file != NULL) {
      conn->ssl_key_file = pstrdup(conn_pool, ssl_key_file);
    }
  }

  if (cmd->argc >= 8) {
    ssl_ca_file = cmd->argv[7];
    if (ssl_ca_file != NULL) {
      conn->ssl_ca_file = pstrdup(conn_pool, ssl_ca_file);
    }
  }

  if (cmd->argc >= 9) {
    ssl_ca_dir = cmd->argv[8];
    if (ssl_ca_dir != NULL) {
      conn->ssl_ca_dir = pstrdup(conn_pool, ssl_ca_dir);
    }
  }

  if (cmd->argc >= 10) {
    ssl_ciphers = cmd->argv[9];
    if (ssl_ciphers != NULL) {
      conn->ssl_ciphers = pstrdup(conn_pool, ssl_ciphers);
    }
  }

  entry = sql_add_connection(conn_pool, name, (void *) conn);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_defineconnection");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION,
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
  entry->connections = 0;

  sql_log(DEBUG_INFO, "  name: '%s'", entry->name);
  sql_log(DEBUG_INFO, "  user: '%s'", conn->user);

  if (conn->host != NULL) {
    sql_log(DEBUG_INFO, "  host: '%s'", conn->host);

  } else if (conn->unix_sock != NULL) {
    sql_log(DEBUG_INFO, "socket: '%s'", conn->unix_sock);
  }

  sql_log(DEBUG_INFO, "    db: '%s'", conn->db);
  sql_log(DEBUG_INFO, "  port: '%s'", conn->port);
  sql_log(DEBUG_INFO, "   ttl: '%d'", entry->ttl);

  if (conn->ssl_cert_file != NULL) {
    sql_log(DEBUG_INFO, "   ssl: client cert = '%s'", conn->ssl_cert_file);
  }

  if (conn->ssl_key_file != NULL) {
    sql_log(DEBUG_INFO, "   ssl: client key = '%s'", conn->ssl_key_file);
  }

  if (conn->ssl_ca_file != NULL) {
    sql_log(DEBUG_INFO, "   ssl: CA file = '%s'", conn->ssl_ca_file);
  }

  if (conn->ssl_ca_dir != NULL) {
    sql_log(DEBUG_INFO, "   ssl: CA dir = '%s'", conn->ssl_ca_dir);
  }

  if (conn->ssl_ciphers != NULL) {
    sql_log(DEBUG_INFO, "   ssl: ciphers = '%s'", conn->ssl_ciphers);
  }

  sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_defineconnection");
  return PR_HANDLED(cmd);
}

/*
 * cmd_exit: closes all open connections.
 *
 * Inputs:
 *  None
 *
 * Returns:
 *  A simple non-error modret_t.
 */
static modret_t *cmd_exit(cmd_rec *cmd) {
  register unsigned int i = 0;

  sql_log(DEBUG_FUNC, "%s", "entering \tmysql cmd_exit");

  for (i = 0; i < conn_cache->nelts; i++) {
    conn_entry_t *entry;

    entry = ((conn_entry_t **) conn_cache->elts)[i];
    if (entry->connections > 0) {
      cmd_rec *close_cmd;

      close_cmd = sql_make_cmd(conn_pool, 2, entry->name, "1");
      cmd_close(close_cmd);
      destroy_pool(close_cmd->pool);
    }
  }

  sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_exit");
  return PR_HANDLED(cmd);
}

/*
 * cmd_select: executes a SELECT query. properly constructing the query
 *  based on the inputs.  See mod_sql.h for the definition of the _sql_data
 *  structure which is used to return the result data.
 *
 * cmd_select takes either exactly two inputs, or more than two.  If only
 *  two inputs are given, the second is a monolithic query string.  See 
 *  the examples below.
 *
 * Inputs:
 *  cmd->argv[0]: connection name
 *  cmd->argv[1]: table 
 *  cmd->argv[2]: select string
 * Optional:
 *  cmd->argv[3]: where clause 
 *  cmd->argv[4]: requested number of return rows (LIMIT)
 *  
 *  etc.        : other options, such as "GROUP BY", "ORDER BY",
 *                and "DISTINCT" will start at cmd->arg[5].  All 
 *                backends MUST support 'DISTINCT', the other
 *                arguments are optional (but encouraged).         
 *
 * Returns:
 *  either a properly filled error modret_t if the select failed, or a 
 *  modret_t with the result data filled in.
 *
 * Example:
 *  These are example queries that would be executed for MySQL; other
 *  backends will have different SQL syntax.
 *  
 *  argv[] = "default","user","userid, count", "userid='aah'","2"
 *  query  = "SELECT userid, count FROM user WHERE userid='aah' LIMIT 2"
 *
 *  argv[] = "default","usr1, usr2","usr1.foo, usr2.bar"
 *  query  = "SELECT usr1.foo, usr2.bar FROM usr1, usr2"
 *
 *  argv[] = "default","usr1","foo",,,"DISTINCT"
 *  query  = "SELECT DISTINCT foo FROM usr1"
 *
 *  argv[] = "default","bar FROM usr1 WHERE tmp=1 ORDER BY bar"
 *  query  = "SELECT bar FROM usr1 WHERE tmp=1 ORDER BY bar"
 *
 * Notes:
 *  certain selects could return huge amounts of data.  do whatever is
 *  possible to minimize the amount of data copying here.
 */
MODRET cmd_select(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  modret_t *cmr = NULL;
  modret_t *dmr = NULL;
  char *query = NULL;
  unsigned long cnt = 0;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \tmysql cmd_select");

  sql_check_cmd(cmd, "cmd_select");

  if (cmd->argc < 2) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_select");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION, "badly formed request");
  }

  entry = sql_get_connection(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_select");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }
 
  conn = (db_conn_t *) entry->data;

  cmr = cmd_open(cmd);
  if (MODRET_ERROR(cmr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_select");
    return cmr;
  }

  /* construct the query string */
  if (cmd->argc == 2) {
    query = pstrcat(cmd->tmp_pool, "SELECT ", cmd->argv[1], NULL);

  } else {
    query = pstrcat(cmd->tmp_pool, cmd->argv[2], " FROM ", cmd->argv[1], NULL);

    if (cmd->argc > 3 &&
        cmd->argv[3]) {
      query = pstrcat(cmd->tmp_pool, query, " WHERE ", cmd->argv[3], NULL);
    }

    if (cmd->argc > 4 &&
        cmd->argv[4]) {
      query = pstrcat(cmd->tmp_pool, query, " LIMIT ", cmd->argv[4], NULL);
    }

    if (cmd->argc > 5) {
      /* Handle the optional arguments -- they're rare, so in this case
       * we'll play with the already constructed query string, but in 
       * general we should probably take optional arguments into account 
       * and put the query string together later once we know what they are.
       */
      for (cnt = 5; cnt < cmd->argc; cnt++) {
	if (cmd->argv[cnt] &&
            strcasecmp("DISTINCT", cmd->argv[cnt]) == 0) {
	  query = pstrcat(cmd->tmp_pool, "DISTINCT ", query, NULL);
	}
      }
    }

    query = pstrcat(cmd->tmp_pool, "SELECT ", query, NULL);
  }

  /* Log the query string */
  sql_log(DEBUG_INFO, "query \"%s\"", query);

  /* Perform the query.  if it doesn't work, log the error, close the
   * connection then return the error from the query processing.
   */
  if (mysql_real_query(conn->mysql, query, strlen(query)) != 0) {
    dmr = build_error(cmd, conn);

    close_cmd = sql_make_cmd(cmd->tmp_pool, 1, entry->name);
    cmd_close(close_cmd);
    SQL_FREE_CMD(close_cmd);

    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_select");
    return dmr;
  }

  /* Get the data. if it doesn't work, log the error, close the
   * connection then return the error from the data processing.
   */
  dmr = build_data(cmd, conn);
  if (MODRET_ERROR(dmr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_select");

    close_cmd = sql_make_cmd(cmd->tmp_pool, 1, entry->name);
    cmd_close(close_cmd);
    SQL_FREE_CMD(close_cmd);

    return dmr;
  }

  /* close the connection, return the data. */
  close_cmd = sql_make_cmd(cmd->tmp_pool, 1, entry->name);
  cmd_close(close_cmd);
  SQL_FREE_CMD(close_cmd);
 
  sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_select");
  return dmr;
}

/*
 * cmd_insert: executes an INSERT query, properly constructing the query
 *  based on the inputs.
 *
 * cmd_insert takes either exactly two inputs, or exactly four.  If only
 *  two inputs are given, the second is a monolithic query string.  See 
 *  the examples below.
 *
 * Inputs:
 *  cmd->argv[0]: connection name
 *  cmd->argv[1]: table
 *  cmd->argv[2]: field string
 *  cmd->argv[3]: value string
 *
 * Returns:
 *  either a properly filled error modret_t if the insert failed, or a 
 *  simple non-error modret_t.
 *
 * Example:
 *  These are example queries that would be executed for MySQL; other
 *  backends will have different SQL syntax.
 *  
 *  argv[] = "default","log","userid, date, count", "'aah', now(), 2"
 *  query  = "INSERT INTO log (userid, date, count) VALUES ('aah', now(), 2)"
 *
 *  argv[] = "default"," INTO foo VALUES ('do','re','mi','fa')"
 *  query  = "INSERT INTO foo VALUES ('do','re','mi','fa')"
 *
 * Notes:
 *  none
 */
MODRET cmd_insert(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  modret_t *cmr = NULL;
  modret_t *dmr = NULL;
  char *query = NULL;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \tmysql cmd_insert");

  sql_check_cmd(cmd, "cmd_insert");

  if ((cmd->argc != 2) && (cmd->argc != 4)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_insert");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION, "badly formed request");
  }

  entry = sql_get_connection(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_insert");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  conn = (db_conn_t *) entry->data;

  cmr = cmd_open(cmd);
  if (MODRET_ERROR(cmr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_insert");
    return cmr;
  }

  /* construct the query string */
  if (cmd->argc == 2) {
    query = pstrcat(cmd->tmp_pool, "INSERT ", cmd->argv[1], NULL);

  } else {
    query = pstrcat(cmd->tmp_pool, "INSERT INTO ", cmd->argv[1], " (",
      cmd->argv[2], ") VALUES (", cmd->argv[3], ")", NULL);
  }

  sql_log(DEBUG_INFO, "query \"%s\"", query);

  /* perform the query.  if it doesn't work, log the error, close the
   * connection (and log any errors there, too) then return the error
   * from the query processing.
   */
  if (mysql_real_query(conn->mysql, query, strlen(query)) != 0) {
    dmr = build_error(cmd, conn);

    close_cmd = sql_make_cmd(cmd->tmp_pool, 1, entry->name);
    cmd_close(close_cmd);
    SQL_FREE_CMD(close_cmd);

    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_insert");
    return dmr;
  }

  /* close the connection and return HANDLED. */
  close_cmd = sql_make_cmd(cmd->tmp_pool, 1, entry->name);
  cmd_close(close_cmd);
  SQL_FREE_CMD(close_cmd);

  sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_insert");
  return PR_HANDLED(cmd);
}

/*
 * cmd_update: executes an UPDATE query, properly constructing the query
 *  based on the inputs.
 *
 * cmd_update takes either exactly two, three, or four inputs.  If only
 *  two inputs are given, the second is a monolithic query string.  See 
 *  the examples below.
 *
 * Inputs:
 *  cmd->argv[0]: connection name
 *  cmd->argv[1]: table
 *  cmd->argv[2]: update string
 * Optional:
 *  cmd->argv[3]: where string
 *
 * Returns:
 *  either a properly filled error modret_t if the update failed, or a 
 *  simple non-error modret_t. *  
 *
 * Example:
 *  These are example queries that would be executed for MySQL; other
 *  backends will have different SQL syntax.
 *  
 *  argv[] = "default","user","count=count+1", "userid='joesmith'"
 *  query  = "UPDATE user SET count=count+1 WHERE userid='joesmith'"
 *
 * Notes:
 *  argv[3] is optional -- it may be NULL, or it may not exist at all.  
 *  make sure this is handled correctly. 
 */
MODRET cmd_update(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  modret_t *cmr = NULL;
  modret_t *dmr = NULL;
  char *query = NULL;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \tmysql cmd_update");

  sql_check_cmd(cmd, "cmd_update");

  if ((cmd->argc < 2) || (cmd->argc > 4)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_update");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION, "badly formed request");
  }

  entry = sql_get_connection(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_update");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  conn = (db_conn_t *) entry->data;

  cmr = cmd_open(cmd);
  if (MODRET_ERROR(cmr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_update");
    return cmr;
  }

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

  /* Log the query string */
  sql_log(DEBUG_INFO, "query \"%s\"", query);

  /* Perform the query.  if it doesn't work close the connection, then
   * return the error from the query processing.
   */
  if (mysql_real_query(conn->mysql, query, strlen(query)) != 0) {
    dmr = build_error(cmd, conn);

    close_cmd = sql_make_cmd(cmd->tmp_pool, 1, entry->name);
    cmd_close(close_cmd);
    SQL_FREE_CMD(close_cmd);

    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_update");
    return dmr;
  }

  /* Close the connection, return HANDLED.  */
  close_cmd = sql_make_cmd(cmd->tmp_pool, 1, entry->name);
  cmd_close(close_cmd);
  SQL_FREE_CMD(close_cmd);

  sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_update");
  return PR_HANDLED(cmd);
}

/*
 * cmd_procedure: executes a stored procedure.
 *
 * Inputs:
 *  cmd->argv[0]: connection name
 *  cmd->argv[1]: procedure name
 *  cmd->argv[2]: procedure string
 *
 * Returns:
 *  either a properly filled error modret_t if the procedure failed in
 *  some way, or a modret_t with the result data.  If a procedure
 *  returns data, it should be returned in the same way as cmd_select.
 *
 * Notes:
 *  not every backend will support stored procedures.  Backends which do
 *  not support stored procedures should return an error with a descriptive
 *  error message (something like 'backend does not support procedures').
 */
MODRET cmd_procedure(cmd_rec *cmd) {
  sql_log(DEBUG_FUNC, "%s", "entering \tmysql cmd_procedure");

  sql_check_cmd(cmd, "cmd_procedure");

  if (cmd->argc != 3) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_procedure");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION, "badly formed request");
  }

  /* MySQL does not support procedures.  Nothing to do. */

  sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_procedure");

  return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION,
    "backend does not support procedures");
}

/*
 * cmd_query: executes a freeform query string, with no syntax checking.
 *
 * cmd_query takes exactly two inputs, the connection and the query string.
 *
 * Inputs:
 *  cmd->argv[0]: connection name
 *  cmd->argv[1]: query string
 *
 * Returns:
 *  depending on the query type, returns a modret_t with data, a non-error
 *  modret_t, or a properly filled error modret_t if the query failed.
 *
 * Example:
 *  None.  The query should be passed directly to the backend database.
 *  
 * Notes:
 *  None.
 */
MODRET cmd_query(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  modret_t *cmr = NULL;
  modret_t *dmr = NULL;
  char *query = NULL;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \tmysql cmd_query");

  sql_check_cmd(cmd, "cmd_query");

  if (cmd->argc != 2) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_query");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION, "badly formed request");
  }

  entry = sql_get_connection(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_query");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  conn = (db_conn_t *) entry->data;

  cmr = cmd_open(cmd);
  if (MODRET_ERROR(cmr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_query");
    return cmr;
  }

  query = pstrcat(cmd->tmp_pool, cmd->argv[1], NULL);

  /* Log the query string */
  sql_log(DEBUG_INFO, "query \"%s\"", query);

  /* Perform the query.  if it doesn't work close the connection, then
   * return the error from the query processing.
   */
  if (mysql_real_query(conn->mysql, query, strlen(query)) != 0) {
    dmr = build_error(cmd, conn);
    
    close_cmd = sql_make_cmd(cmd->tmp_pool, 1, entry->name);
    cmd_close(close_cmd);
    SQL_FREE_CMD(close_cmd);
    
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_query");
    return dmr;
  }

  /* Get data if necessary. if it doesn't work, log the error, close the
   * connection then return the error from the data processing.
   */

  if (mysql_field_count(conn->mysql) > 0) {
    dmr = build_data(cmd, conn);
    if (MODRET_ERROR(dmr)) {
      sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_query");
    }

  } else {
    dmr = PR_HANDLED(cmd);
  }
  
  /* close the connection, return the data. */
  close_cmd = sql_make_cmd(cmd->tmp_pool, 1, entry->name);
  cmd_close(close_cmd);
  SQL_FREE_CMD(close_cmd);

  sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_query");
  return dmr;
}

/*
 * cmd_escapestring: certain strings sent to a database should be properly
 *  escaped -- for instance, quotes need to be escaped to insure that 
 *  a query string is properly formatted.  cmd_escapestring does whatever
 *  is necessary to escape the special characters in a string. 
 *
 * Inputs:
 *  cmd->argv[0]: connection name
 *  cmd->argv[1]: string to escape
 *
 * Returns:
 *  this command CANNOT fail.  The return string is null-terminated and 
 *  stored in the data field of the modret_t structure.
 *
 * Notes:
 *  Different languages may escape different characters in different ways.
 *  A backend should handle this correctly, where possible.  If there is
 *  no client library function to do the string conversion, it is strongly
 *  recommended that the backend module writer do whatever is necessry (read
 *  the database documentation and figure it out) to do the conversion
 *  themselves in this function.
 *
 *  A backend MUST supply a working escapestring implementation.  Simply
 *  copying the data from argv[0] into the data field of the modret allows
 *  for possible SQL injection attacks when this backend is used.
 */
MODRET cmd_escapestring(cmd_rec * cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  modret_t *cmr = NULL;
  char *unescaped = NULL;
  char *escaped = NULL;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \tmysql cmd_escapestring");

  sql_check_cmd(cmd, "cmd_escapestring");

  if (cmd->argc != 2) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_escapestring");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION, "badly formed request");
  }

  entry = sql_get_connection(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_escapestring");
    return PR_ERROR_MSG(cmd, MOD_SQL_MYSQL_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  conn = (db_conn_t *) entry->data;

  /* Make sure the connection is open. */
  cmr = cmd_open(cmd);
  if (MODRET_ERROR(cmr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_escapestring");
    return cmr;
  }

  unescaped = cmd->argv[1];
  escaped = (char *) pcalloc(cmd->tmp_pool, sizeof(char) *
    (strlen(unescaped) * 2) + 1);

  /* Note: the mysql_real_escape_string() function appeared in the C API
   * as of MySQL 3.23.14; this macro allows functioning with older mysql
   * installations.
   */
#if MYSQL_VERSION_ID >= 32314
  mysql_real_escape_string(conn->mysql, escaped, unescaped, strlen(unescaped));
#else
  mysql_escape_string(escaped, unescaped, strlen(unescaped));
#endif

  close_cmd = sql_make_cmd(cmd->tmp_pool, 1, entry->name);
  cmd_close(close_cmd);
  SQL_FREE_CMD(close_cmd);

  sql_log(DEBUG_FUNC, "%s", "exiting \tmysql cmd_escapestring");
  return mod_create_data(cmd, (void *) escaped);
}

/* Per the MySQL docs for the PASSWORD function, MySQL pre-4.1 passwords
 * are always 16 bytes; MySQL 4.1 passwords are 41 bytes AND start with '*'.
 * See:
 *   http://dev.mysql.com/doc/refman/5.7/en/encryption-functions.html#function_password
 */

#define MYSQL_PASSWD_FMT_UNKNOWN	-1
#define MYSQL_PASSWD_FMT_PRE41		1
#define MYSQL_PASSWD_FMT_41		2
#define MYSQL_PASSWD_FMT_SHA256		3

static int get_mysql_passwd_fmt(const char *txt, size_t txt_len) {
  if (txt_len == 16) {
    return MYSQL_PASSWD_FMT_PRE41;
  }

  if (txt_len == 41 &&
      txt[0] == '*') {
    return MYSQL_PASSWD_FMT_41;
  }

  if (txt_len > 3 &&
      txt[0] == '$' &&
      txt[1] == '5' &&
      txt[2] == '$') {
    return MYSQL_PASSWD_FMT_SHA256;
  }

  return MYSQL_PASSWD_FMT_UNKNOWN;
}

static int match_mysql_passwds(const char *hashed, size_t hashed_len,
    const char *scrambled, size_t scrambled_len, const char *scramble_func) {
  int hashed_fmt = 0, scrambled_fmt = 0, matched = FALSE;

  if (pr_trace_get_level(trace_channel) >= 7) {
    const char *hashed_fmt_name, *scrambled_fmt_name;

    hashed_fmt = get_mysql_passwd_fmt(hashed, hashed_len);
    scrambled_fmt = get_mysql_passwd_fmt(scrambled, scrambled_len);

    switch (hashed_fmt) {
      case MYSQL_PASSWD_FMT_PRE41:
        hashed_fmt_name = "pre-4.1";
        break;

      case MYSQL_PASSWD_FMT_41:
        hashed_fmt_name = "4.1";
        break;

      case MYSQL_PASSWD_FMT_SHA256:
        hashed_fmt_name = "SHA256";
        break;

      default:
        hashed_fmt_name = "unknown";
        break;
    }

    switch (scrambled_fmt) {
      case MYSQL_PASSWD_FMT_PRE41:
        scrambled_fmt_name = "pre-4.1";
        break;

      case MYSQL_PASSWD_FMT_41:
        scrambled_fmt_name = "4.1";
        break;

      case MYSQL_PASSWD_FMT_SHA256:
        scrambled_fmt_name = "SHA256";
        break;

      default:
        scrambled_fmt_name = "unknown";
        break;
    }

    pr_trace_msg(trace_channel, 7,
      "SQLAuthType Backend: database password format = %s, "
      "client library password format = %s (using %s())", hashed_fmt_name,
      scrambled_fmt_name, scramble_func);
  }

  /* Note here that if the scrambled value has a different length than our
   * expected hash, it might be a completely different format (i.e. not the
   * 4.1 or whatever format provided by the db).  Log if this the case!
   *
   * Consider that using PASSWORD() on the server might make a 4.1 format
   * value, but the client lib might make a SHA256 format value.  Or
   * vice versa.
   */
  if (scrambled_len == hashed_len) {
    matched = (strncmp(scrambled, hashed, hashed_len) == 0);
  }

  if (matched == FALSE) {
    if (hashed_fmt == 0) {
      hashed_fmt = get_mysql_passwd_fmt(hashed, hashed_len);
    }

    if (scrambled_fmt == 0) {
      scrambled_fmt = get_mysql_passwd_fmt(scrambled, scrambled_len);
    }

    if (hashed_fmt != scrambled_fmt) {
      if (scrambled_fmt == MYSQL_PASSWD_FMT_SHA256) {
        sql_log(DEBUG_FUNC, "MySQL client library used MySQL SHA256 password format, and Backend SQLAuthType cannot succeed; consider using MD5/SHA1/SHA256 SQLAuthType using mod_sql_passwd");
        switch (hashed_fmt) {
          case MYSQL_PASSWD_FMT_PRE41:
            sql_log(DEBUG_FUNC, "MySQL server used MySQL pre-4.1 password format for PASSWORD() value");
            break;

          case MYSQL_PASSWD_FMT_41:
            sql_log(DEBUG_FUNC, "MySQL server used MySQL 4.1 password format for PASSWORD() value");
            break;

          default:
            pr_trace_msg(trace_channel, 19,
              "unknown MySQL PASSWORD() format used on server");
            break;
        }
      }
    }

    pr_trace_msg(trace_channel, 9,
      "expected '%.*s' (%lu), got '%.*s' (%lu) using MySQL %s()",
      (int) hashed_len, hashed, (unsigned long) hashed_len,
      (int) scrambled_len, scrambled, (unsigned long) scrambled_len,
      scramble_func);
  }

  return matched;
}

static modret_t *sql_mysql_password(cmd_rec *cmd, const char *plaintext,
    const char *ciphertext) {
  char scrambled[256] = {'\0'};
  size_t plaintext_len = 0, ciphertext_len = 0, scrambled_len = 0;
  int success = 0;

  plaintext_len = strlen(plaintext);
  ciphertext_len = strlen(ciphertext);

  /* Checking order (damn MySQL API changes):
   *
   *  my_make_scrambled_password (if available)
   *  my_make_scrambled_password_323 (if available)
   *  make_scrambled_password (if available)
   *  make_scrammbed_password_323 (if available)
   */

#if defined(HAVE_MYSQL_MY_MAKE_SCRAMBLED_PASSWORD)
  if (success == FALSE) {
    memset(scrambled, '\0', sizeof(scrambled));

    my_make_scrambled_password(scrambled, plaintext, plaintext_len);
    scrambled_len = strlen(scrambled);

    success = match_mysql_passwds(ciphertext, ciphertext_len, scrambled,
      scrambled_len, "my_make_scrambled_password");
  }
#endif /* HAVE_MYSQL_MY_MAKE_SCRAMBLED_PASSWORD */

#if defined(HAVE_MYSQL_MY_MAKE_SCRAMBLED_PASSWORD_323)
  if (success == FALSE) {
    memset(scrambled, '\0', sizeof(scrambled));

    sql_log(DEBUG_FUNC, "%s",
      "checking again using deprecated legacy MySQL password algorithm (my_make_scrambled_password_323 function)");
    sql_log(DEBUG_FUNC, "%s",
      "warning: support for this legacy MySQ-3.xL password algorithm will be dropped from MySQL in the future");

    my_make_scrambled_password_323(scrambled, plaintext, plaintext_len);
    scrambled_len = strlen(scrambled);

    success = match_mysql_passwds(ciphertext, ciphertext_len, scrambled,
      scrambled_len, "my_make_scrambled_password_323");
  }
#endif /* HAVE_MYSQL_MY_MAKE_SCRAMBLED_PASSWORD_323 */

#if defined(HAVE_MYSQL_MAKE_SCRAMBLED_PASSWORD)
  if (success == FALSE) {
    memset(scrambled, '\0', sizeof(scrambled));

# if MYSQL_VERSION_ID >= 40100 && MYSQL_VERSION_ID < 40101
    make_scrambled_password(scrambled, plaintext, 1, NULL);
# else
    make_scrambled_password(scrambled, plaintext);
# endif
    scrambled_len = strlen(scrambled);

    success = match_mysql_passwds(ciphertext, ciphertext_len, scrambled,
      scrambled_len, "make_scrambled_password");
  }
#endif /* HAVE_MYSQL_MAKE_SCRAMBLED_PASSWORD */

#if defined(HAVE_MYSQL_MAKE_SCRAMBLED_PASSWORD_323)
  if (success == FALSE) {
    memset(scrambled, '\0', sizeof(scrambled));
 
    sql_log(DEBUG_FUNC, "%s",
      "checking again using deprecated legacy MySQL password algorithm (make_scrambled_password_323 function)");
    sql_log(DEBUG_FUNC, "%s",
      "warning: support for this legacy MySQ-3.xL password algorithm will be dropped from MySQL in the future");

    make_scrambled_password_323(scrambled, plaintext);
    scrambled_len = strlen(scrambled);

    success = match_mysql_passwds(ciphertext, ciphertext_len, scrambled,
      scrambled_len, "make_scrambled_password_323");
  }
#endif /* HAVE_MYSQL_MAKE_SCRAMBLED_PASSWORD_323 */

  if (success == FALSE) {
    sql_log(DEBUG_FUNC, "%s", "password mismatch");
  }

  return success ? PR_HANDLED(cmd) : PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
}

/*
 * cmd_identify: returns API information and an identification string for 
 *  the backend handler.  mod_sql will call this at initialization and 
 *  display the identification string.  The API version information is 
 *  used by mod_sql to identify available command handlers.
 *
 * Inputs:
 *  None.  The cmd->tmp_pool can be used to construct the return data, but
 *  do not depend on any other portion of the cmd_rec to be useful in any way.
 *
 * Returns:
 *  A sql_data_t of *exactly* this form:
 *   sql_data_t->rnum    = 1;
 *   sql_data_t->fnum    = 2;
 *   sql_data_t->data[0] = "identification string"
 *   sql_data_t->data[0] = "API version"
 *
 * Notes:
 *  See mod_sql.h for currently accepted APIs.
 */
MODRET cmd_identify(cmd_rec * cmd) {
  sql_data_t *sd = NULL;

  sql_check_cmd(cmd, "cmd_identify");

  sd = (sql_data_t *) pcalloc(cmd->tmp_pool, sizeof(sql_data_t));
  sd->data = (char **) pcalloc(cmd->tmp_pool, sizeof(char *) * 2);

  sd->rnum = 1;
  sd->fnum = 2;

  sd->data[0] = MOD_SQL_MYSQL_VERSION;
  sd->data[1] = MOD_SQL_API_V1;

  return mod_create_data(cmd, (void *) sd);
}  

/*
 * cmd_prepare: prepares this mod_sql_mysql module for running.
 *
 * Inputs:
 *  cmd->argv[0]:  A pool to be used for any necessary preparations.
 *
 * Returns:
 *  Success.
 */
MODRET cmd_prepare(cmd_rec *cmd) {
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

/*
 * cmd_cleanup: cleans up any initialisations made during module preparations
 *  (see cmd_prepre).
 *
 * Inputs:
 *  None.
 *
 * Returns:
 *  Success.
 */
MODRET cmd_cleanup(cmd_rec *cmd) {
  destroy_pool(conn_pool);
  conn_pool = NULL;
  conn_cache = NULL;

  return mod_create_data(cmd, NULL);
}

/* SQL cmdtable: mod_sql requires each backend module to define a cmdtable
 *  with this exact name. ALL these functions must be defined; mod_sql checks
 *  that they all exist on startup and ProFTPD will refuse to start if they
 *  aren't defined.
 */
static cmdtable sql_mysql_cmdtable[] = {
  { CMD, "sql_close",            G_NONE, cmd_close,            FALSE, FALSE },
  { CMD, "sql_cleanup",          G_NONE, cmd_cleanup,          FALSE, FALSE },
  { CMD, "sql_defineconnection", G_NONE, cmd_defineconnection, FALSE, FALSE },
  { CMD, "sql_escapestring",     G_NONE, cmd_escapestring,     FALSE, FALSE },
  { CMD, "sql_exit",             G_NONE, cmd_exit,             FALSE, FALSE },
  { CMD, "sql_identify",         G_NONE, cmd_identify,         FALSE, FALSE },
  { CMD, "sql_insert",           G_NONE, cmd_insert,           FALSE, FALSE },
  { CMD, "sql_open",             G_NONE, cmd_open,             FALSE, FALSE },
  { CMD, "sql_prepare",          G_NONE, cmd_prepare,          FALSE, FALSE },
  { CMD, "sql_procedure",        G_NONE, cmd_procedure,        FALSE, FALSE },
  { CMD, "sql_query",            G_NONE, cmd_query,            FALSE, FALSE },
  { CMD, "sql_select",           G_NONE, cmd_select,           FALSE, FALSE },
  { CMD, "sql_update",           G_NONE, cmd_update,           FALSE, FALSE },

  { 0, NULL }
};

/* Configuration handlers
 */

MODRET set_sqlauthtypes(cmd_rec *cmd) {
#if MYSQL_VERSION_ID >= 50600 && \
    !defined(HAVE_MYSQL_MAKE_SCRAMBLED_PASSWORD) && \
    !defined(HAVE_MYSQL_MAKE_SCRAMBLED_PASSWORD_323) && \
    !defined(HAVE_MYSQL_MY_MAKE_SCRAMBLED_PASSWORD_323)
  register unsigned int i;

  /* If we are using MySQL 5.6.x or later, AND we only have the
   * my_make_scrambled_password() MySQL function available, AND the Backend
   * SQLAuthType is used, then we must fail the directive; see Bug#4281.
   */

  for (i = 1; i < cmd->argc; i++) {
    const char *auth_type;

    auth_type = cmd->argv[i];
    if (strcasecmp(auth_type, "Backend") == 0) {
      pr_log_pri(PR_LOG_NOTICE, "%s: WARNING: MySQL client library uses MySQL SHA256 password format, and Backend SQLAuthType cannot succeed; consider using MD5/SHA1/SHA256 SQLAuthType using mod_sql_passwd", (char *) cmd->argv[0]);
      break;
    }
  }
#endif

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

static void sql_mysql_mod_load_ev(const void *event_data, void *user_data) {

  if (strcmp("mod_sql_mysql.c", (const char *) event_data) == 0) {
    /* Register ourselves with mod_sql. */
    if (sql_register_backend("mysql", sql_mysql_cmdtable) < 0) {
      pr_log_pri(PR_LOG_NOTICE, MOD_SQL_MYSQL_VERSION
        ": notice: error registering backend: %s", strerror(errno));
      pr_session_end(0);
    }
  }
}

static void sql_mysql_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_sql_mysql.c", (const char *) event_data) == 0) {
    /* Unregister ourselves from all events. */
    pr_event_unregister(&sql_mysql_module, NULL, NULL);

    /* Unegister ourselves with mod_sql. */
    (void) sql_unregister_authtype("Backend");

    if (sql_unregister_backend("mysql") < 0) {
      pr_log_pri(PR_LOG_NOTICE, MOD_SQL_MYSQL_VERSION
        ": notice: error unregistering backend: %s", strerror(errno));
      pr_session_end(0);
    }
  }
}

/* Initialization routines
 */

static int sql_mysql_init(void) {

  /* Register listeners for the load and unload events. */
  pr_event_register(&sql_mysql_module, "core.module-load",
    sql_mysql_mod_load_ev, NULL);
  pr_event_register(&sql_mysql_module, "core.module-unload",
    sql_mysql_mod_unload_ev, NULL);

  /* Register our auth handler. */
  (void) sql_register_authtype("Backend", sql_mysql_password);
  return 0;
}

static int sql_mysql_sess_init(void) {
  if (conn_pool == NULL) {
    conn_pool = make_sub_pool(session.pool);
    pr_pool_tag(conn_pool, "MySQL connection pool");
  }

  if (conn_cache == NULL) {
    conn_cache = make_array(make_sub_pool(session.pool), DEF_CONN_POOL_SIZE,
      sizeof(conn_entry_t *));
  }

  return 0;
}

static conftable sql_mysql_conftab[] = {
  { "SQLAuthTypes",	set_sqlauthtypes,	NULL },

  { NULL, NULL, NULL }
};

/* sql_mysql_module: The standard module struct for all ProFTPD modules.
 *  We use the pre-fork handler to initialize the conn_cache array header.
 *  Other backend modules may not need any init functions, or may need
 *  to extend the init functions to initialize other internal variables.
 */
module sql_mysql_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "sql_mysql",

  /* Module configuration directive handlers */
  sql_mysql_conftab,

  /* Module command handlers */
  NULL,

  /* Module authentication handlers */
  NULL,

  /* Module initialization */
  sql_mysql_init,

  /* Session initialization */
  sql_mysql_sess_init,

  /* Module version */
  MOD_SQL_MYSQL_VERSION
};
