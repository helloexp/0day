/*
 * ProFTPD: mod_sql_odbc -- Support for connecting to databases via ODBC
 * Copyright (c) 2003-2017 TJ Saunders
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

#include "conf.h"
#include "mod_sql.h"

#define MOD_SQL_ODBC_VERSION    "mod_sql_odbc/0.3.4"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030602
# error "ProFTPD 1.3.6rc2 or later required"
#endif

#include "sql.h"
#include "sqlext.h"

module sql_odbc_module;

typedef struct db_conn_struct {
  char *dsn;
  char *user;
  char *pass;

  HENV envh;
  HDBC dbh;
  HSTMT sth;

  unsigned int state;

} db_conn_t;

#define SQLODBC_HAVE_ENV_HANDLE         0x0001
#define SQLODBC_HAVE_DBC_HANDLE         0x0002
#define SQLODBC_HAVE_STMT_HANDLE        0x0004
#define SQLODBC_HAVE_INFO		0x0010

typedef struct conn_entry_struct {
  char *name;
  void *data;

  /* Timer handling */
  int timer;
  int ttl;

  /* Connection handling */
  unsigned int nconn;

} conn_entry_t;

#define DEF_CONN_POOL_SIZE 10

static pool *conn_pool = NULL;
static array_header *conn_cache = NULL;
static int odbc_version = SQL_OV_ODBC3;
static const char *odbc_version_str = "ODBCv3";

/* Default to using the LIMIT clause.  Some database drivers prefer
 * ROWNUM (e.g. Oracle), and others prefer TOP (e.g. TDS).
 */
static int use_limit_clause = TRUE;
static int use_rownum_clause = FALSE;
static int use_top_clause = FALSE;

MODRET sqlodbc_close(cmd_rec *);

static conn_entry_t *sqlodbc_get_conn(char *name) {
  register unsigned int i = 0;

  if (!name)
    return NULL;

  for (i = 0; i < conn_cache->nelts; i++) {
    conn_entry_t *entry = ((conn_entry_t **) conn_cache->elts)[i];

    if (strcmp(name, entry->name) == 0)
      return entry;
  }

  return NULL;
}

static void *sqlodbc_add_conn(pool *p, char *name, db_conn_t *conn) {
  conn_entry_t *entry = NULL;

  if (!name || !conn || !p)
    return NULL;
  
  if (sqlodbc_get_conn(name))
    return NULL;

  entry = (conn_entry_t *) pcalloc(p, sizeof(conn_entry_t));
  entry->name = name;
  entry->data = conn;

  *((conn_entry_t **) push_array(conn_cache)) = entry;

  return entry;
}

static int sqlodbc_timer_cb(CALLBACK_FRAME) {
  register unsigned int i = 0;
 
  for (i = 0; i < conn_cache->nelts; i++) {
    conn_entry_t *entry = ((conn_entry_t **) conn_cache->elts)[i];

    if (entry->timer == p2) {
      cmd_rec *cmd = NULL;

      sql_log(DEBUG_INFO, "timer expired for connection '%s'", entry->name);

      cmd = pr_cmd_alloc(conn_pool, 2, entry->name, "1");
      sqlodbc_close(cmd);
      destroy_pool(cmd->pool);

      entry->timer = 0;
    }
  }

  return 0;
}

static SQLCHAR odbc_state[6];
static SQLCHAR odbc_errstr[SQL_MAX_MESSAGE_LENGTH];

static const char *sqlodbc_errstr(SQLSMALLINT handle_type, SQLHANDLE handle,
    SQLCHAR **statep) {
  SQLSMALLINT odbc_errlen = 0;
  SQLINTEGER odbc_errno;
  SQLRETURN res;

  memset(odbc_state, '\0', sizeof(odbc_state));
  memset(odbc_errstr, '\0', sizeof(odbc_errstr));

  /* Ideally, we'd keep calling SQLGetDiagRec() until it returned SQL_NO_DATA,
   * in order to capture the entire error message stack.
   */

  res = SQLGetDiagRec(handle_type, handle, 1, odbc_state, &odbc_errno,
    odbc_errstr, sizeof(odbc_errstr), &odbc_errlen);

  if (res != SQL_NO_DATA) {
    if (statep)
      *statep = odbc_state;

    return (const char *) odbc_errstr;
  }

  return "(no data)";
}

/* Liberally borrowed from MySQL-3.23.55's libmysql.c file,
 * mysql_odbc_escape_string() function.
 */
static void sqlodbc_escape_string(char *to, const char *from, size_t fromlen) {
  const char *end;

  for (end = from + fromlen; from != end; from++) {
    switch (*from) {
      case 0:
        *to++ = '\\';
        *to++ = '0';
        break;

      case '\n':
        *to++ = '\\';
        *to++ = 'n';
        break;

      case '\r':
        *to++ = '\\';
        *to++ = 'r';
        break;

      case '\\':
        *to++ = '\\';
        *to++ = '\\';
        break;

      case '\'':
        *to++ = '\'';
        *to++ = '\'';
        break;

      case '"':
        *to++ = '\\';
        *to++ = '"';
        break;

      case '\032':
        *to++ = '\\';
        *to++ = 'Z';
        break;

       default:
         *to++ = *from;
    }
  }
}

static const char *sqlodbc_typestr(SQLSMALLINT type) {
  switch (type) {
    case SQL_CHAR:
      return "SQL_CHAR";

    case SQL_VARCHAR:
      return "SQL_VARCHAR";

    case SQL_LONGVARCHAR:
      return "SQL_LONGVARCHAR";

#ifdef SQL_WCHAR
    case SQL_WCHAR:
      return "SQL_WCHAR";
#endif

#ifdef SQL_WVARCHAR
    case SQL_WVARCHAR:
      return "SQL_WVARCHAR";
#endif

#ifdef SQL_WLONGVARCHAR
    case SQL_WLONGVARCHAR:
      return "SQL_WLONGVARCHAR";
#endif

    case SQL_DECIMAL:
      return "SQL_DECIMAL";

    case SQL_NUMERIC:
      return "SQL_NUMERIC";

    case SQL_BIT:
      return "SQL_BIT";

    case SQL_TINYINT:
      return "SQL_TINYINT";

    case SQL_SMALLINT:
      return "SQL_SMALLINT";

    case SQL_INTEGER:
      return "SQL_INTEGER";

    case SQL_BIGINT:
      return "SQL_BIGINT";

    case SQL_REAL:
      return "SQL_REAL";

    case SQL_FLOAT:
      return "SQL_FLOAT";

    case SQL_DOUBLE:
      return "SQL_DOUBLE";

    case SQL_BINARY:
      return "SQL_BINARY";

    case SQL_VARBINARY:
      return "SQL_VARBINARY";

    case SQL_LONGVARBINARY:
      return "SQL_LONGVARBINARY";

    case SQL_TYPE_DATE:
      return "SQL_TYPE_DATE";

    case SQL_TYPE_TIME:
      return "SQL_TYPE_TIME";

    case SQL_TYPE_TIMESTAMP:
      return "SQL_TYPE_TIMESTAMP";

    case SQL_GUID:
      return "SQL_GUID";
  }

  return "[unknown]";
}

static const char *sqlodbc_strerror(SQLSMALLINT odbc_error) {
  switch (odbc_error) {
    case SQL_SUCCESS:
      return "Success";

    case SQL_SUCCESS_WITH_INFO:
      return "Success with info";

#ifdef SQL_NO_DATA
    case SQL_NO_DATA:
      return "No data";
#endif

    case SQL_ERROR:
      return "Error";

    case SQL_INVALID_HANDLE:
      return "Invalid handle";

    case SQL_STILL_EXECUTING:
      return "Still executing";

    case SQL_NEED_DATA:
      return "Need data";
  }

  return "(unknown)";
}

static modret_t *sqlodbc_get_error(cmd_rec *cmd, SQLSMALLINT handle_type,
    SQLHANDLE handle) {
  SQLCHAR state[6], errstr[SQL_MAX_MESSAGE_LENGTH];
  SQLSMALLINT errlen;
  SQLINTEGER odbc_errno = 0;
  SQLRETURN res;
  unsigned int recno = 1;
  char numstr[20];

  memset(errstr, '\0', sizeof(errstr));
  pr_snprintf((char *) errstr, sizeof(errstr)-1, "%s", "(no data)");

  res = SQLGetDiagRec(handle_type, handle, recno++, state, &odbc_errno,
    errstr, sizeof(errstr), &errlen);
  while (res != SQL_NO_DATA
#ifdef SQL_ERROR
         && res != SQL_ERROR
#endif /* SQL_ERROR */
#ifdef SQL_INVALID_HANDLE
         && res != SQL_INVALID_HANDLE
#endif /* SQL_INVALID_HANDLE */
        ) {
    pr_signals_handle();

    sql_log(DEBUG_FUNC, "odbc error: [%d] %s", odbc_errno, errstr);
    
    res = SQLGetDiagRec(handle_type, handle, recno++, state, &odbc_errno,
      errstr, sizeof(errstr), &errlen);
  }

  /* This will return the last error retrieved.  This is OK, since we
   * have logged all the previous errors.
   */
  memset(numstr, '\0', sizeof(numstr));
  pr_snprintf(numstr, 20, "%d", (int) odbc_errno);

  return PR_ERROR_MSG(cmd, numstr, (char *) errstr);
}

static modret_t *sqlodbc_get_data(cmd_rec *cmd, db_conn_t *conn) {
  sql_data_t *sd = NULL;
  array_header *dh = NULL;
  SQLSMALLINT ncols;
  SQLRETURN res;

  if (!conn) 
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION, "badly formed request");

  sd = (sql_data_t *) pcalloc(cmd->tmp_pool, sizeof(sql_data_t));

  res = SQLNumResultCols(conn->sth, &ncols);
  if (res != SQL_SUCCESS &&
      res != SQL_SUCCESS_WITH_INFO) {
    char *err;
    SQLCHAR *state = NULL;

    err = (char *) sqlodbc_errstr(SQL_HANDLE_STMT, conn->sth, &state);

    sql_log(DEBUG_WARN, "error getting column count: %s", err);
    return PR_ERROR_MSG(cmd, state ? (char *) state : "0", err);
  }
  sd->fnum = (unsigned long) ncols;
  sd->rnum = 0;

  dh = (array_header *) make_array(cmd->tmp_pool, sd->fnum, sizeof(char *));

  /* NOTE: this could be optimised, caching the SQLDescribeCol() results
   * (used mainly to get the column datatype) so that that call is not
   * needed for subsequent rows, just the first row.
   */
  while (TRUE) {
    int done_fetching = FALSE;
    register unsigned int i;

    pr_signals_handle();

    res = SQLFetch(conn->sth);

    switch (res) {
      case SQL_ERROR:
        sql_log(DEBUG_WARN, "error fetching row %u: %s", sd->rnum + 1,
          sqlodbc_errstr(SQL_HANDLE_STMT, conn->sth, NULL));
        return PR_ERROR(cmd);

      case SQL_NO_DATA:
        done_fetching = TRUE;
        break;

      case SQL_SUCCESS_WITH_INFO:
        /* Note: this deliberately falls through to the SQL_SUCCESS case. */
        sql_log(DEBUG_WARN, "fetching row %u: %s", sd->rnum + 1,
          sqlodbc_errstr(SQL_HANDLE_STMT, conn->sth, NULL));

      case SQL_SUCCESS:
        sd->rnum++;

        for (i = 1; i <= sd->fnum; i++) {
          SQLCHAR col_name[80];
          SQLSMALLINT col_namelen, col_type, col_digits, col_nullable;
          SQLULEN col_size;

          if (SQLDescribeCol(conn->sth, i, col_name, sizeof(col_name),
              &col_namelen, &col_type, &col_size, &col_digits,
              &col_nullable) == SQL_SUCCESS) {
            SQLSMALLINT col_ctype; 

            /* mod_sql expects to handle all returned data elements as strings
             * (even though it converts some to numbers), so we need to
             * stringify any numeric datatypes returned.
             */
            switch (col_type) {
              case SQL_CHAR:
              case SQL_LONGVARCHAR:
              case SQL_VARCHAR:
#ifdef SQL_WVARCHAR
              case SQL_WVARCHAR:
#endif
                col_ctype = SQL_C_CHAR;

                if (col_size) {
                  SQLLEN buflen;
                  SQLCHAR *buf = pcalloc(cmd->tmp_pool, ++col_size);

                  if (SQLGetData(conn->sth, i, col_ctype, buf, col_size,
                      &buflen) != SQL_SUCCESS) {
                    sql_log(DEBUG_WARN, "error getting %s data for column %u, "
                      "row %u: %s", sqlodbc_typestr(col_ctype), i,
                      sd->rnum + 1, sqlodbc_errstr(SQL_HANDLE_STMT, conn->sth,
                        NULL));
                    *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                    continue;
                  }

                  if (buflen == SQL_NO_TOTAL) {
                    sql_log(DEBUG_WARN, "notice: unable to determine total "
                      "number of bytes remaining for %s column %u, row %u",
                      sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                    *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                    break;

                  } else if (buflen == SQL_NULL_DATA) {
                    sql_log(DEBUG_WARN, "notice: data is NULL for %s column "
                      "%u, row %u", sqlodbc_typestr(col_ctype), i,
                      sd->rnum + 1);
                    *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                    break;
                  }

                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool,
                    (char *) buf);

                } else {
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                }

                break;

              /* Note: ODBC doesn't seem to provide a way of knowing whether
               * the value in the column is supposed to be signed or unsigned.
               * Could cause problems later on.
               */

              case SQL_TINYINT: {
                char buf[64];
                short col_cval;
                SQLLEN ind;

                col_ctype = SQL_C_TINYINT;

                if (SQLGetData(conn->sth, i, col_ctype,
                    (SQLPOINTER) &col_cval, 0, &ind) != SQL_SUCCESS) {
                  sql_log(DEBUG_WARN, "error getting %s data for column %u, "
                    "row %u: %s", sqlodbc_typestr(col_ctype), i,
                    sd->rnum + 1, sqlodbc_errstr(SQL_HANDLE_STMT, conn->sth,
                      NULL));
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;
                }

                if (ind == SQL_NO_TOTAL) {
                  sql_log(DEBUG_WARN, "notice: unable to determine total "
                    "number of bytes remaining for %s column %u, row %u",
                    sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;

                } else if (ind == SQL_NULL_DATA) {
                  sql_log(DEBUG_WARN, "notice: data is NULL for %s column %u, "
                    "row %u", sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;
                }

                pr_snprintf(buf, sizeof(buf), "%hd", col_cval);
                buf[sizeof(buf)-1] = '\0';

                *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, buf);
                break;
              }
 
              case SQL_SMALLINT: {
                char buf[64];
                short col_cval;
                SQLLEN ind;

                col_ctype = SQL_C_SHORT;

                if (SQLGetData(conn->sth, i, col_ctype,
                    (SQLPOINTER) &col_cval, 0, &ind) != SQL_SUCCESS) {
                  sql_log(DEBUG_WARN, "error getting %s data for column %u, "
                    "row %u: %s", sqlodbc_typestr(col_ctype), i,
                    sd->rnum + 1, sqlodbc_errstr(SQL_HANDLE_STMT, conn->sth,
                      NULL));
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;
                }

                if (ind == SQL_NO_TOTAL) {
                  sql_log(DEBUG_WARN, "notice: unable to determine total "
                    "number of bytes remaining for %s column %u, row %u",
                    sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;

                } else if (ind == SQL_NULL_DATA) {
                  sql_log(DEBUG_WARN, "notice: data is NULL for %s column %u, "
                    "row %u", sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;
                }

                pr_snprintf(buf, sizeof(buf), "%hd", col_cval);
                buf[sizeof(buf)-1] = '\0';

                *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, buf);
                break;
              }

              case SQL_INTEGER: {
                char buf[64];
                int col_cval;
                SQLLEN ind;

                col_ctype = SQL_INTEGER;

                if (SQLGetData(conn->sth, i, col_ctype,
                    (SQLPOINTER) &col_cval, 0, &ind) != SQL_SUCCESS) {
                  sql_log(DEBUG_WARN, "error getting %s data for column %u, "
                    "row %u: %s", sqlodbc_typestr(col_ctype), i,
                    sd->rnum + 1, sqlodbc_errstr(SQL_HANDLE_STMT, conn->sth,
                      NULL));
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;
                }

                if (ind == SQL_NO_TOTAL) {
                  sql_log(DEBUG_WARN, "notice: unable to determine total "
                    "number of bytes remaining for %s column %u, row %u",
                    sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;

                } else if (ind == SQL_NULL_DATA) {
                  sql_log(DEBUG_WARN, "notice: data is NULL for %s column %u, "
                    "row %u", sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;
                }

                pr_snprintf(buf, sizeof(buf), "%d", col_cval);
                buf[sizeof(buf)-1] = '\0';

                *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, buf);
                break;
              }

              case SQL_BIGINT: {
                char buf[64];
                long col_cval;
                SQLLEN ind;

                col_ctype = SQL_C_LONG;

                if (SQLGetData(conn->sth, i, col_ctype,
                    (SQLPOINTER) &col_cval, 0, &ind) != SQL_SUCCESS) {
                  sql_log(DEBUG_WARN, "error getting %s data for column %u, "
                    "row %u: %s", sqlodbc_typestr(col_ctype), i,
                    sd->rnum + 1, sqlodbc_errstr(SQL_HANDLE_STMT, conn->sth,
                      NULL));
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;
                }

                if (ind == SQL_NO_TOTAL) {
                  sql_log(DEBUG_WARN, "notice: unable to determine total "
                    "number of bytes remaining for %s column %u, row %u",
                    sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;

                } else if (ind == SQL_NULL_DATA) {
                  sql_log(DEBUG_WARN, "notice: data is NULL for %s column %u, "
                    "row %u", sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;
                }

                pr_snprintf(buf, sizeof(buf), "%ld", col_cval);
                buf[sizeof(buf)-1] = '\0';

                *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, buf);
                break;
              }

              case SQL_REAL: {
                char buf[64];
                long col_cval;
                SQLLEN ind;

                col_ctype = SQL_C_LONG;

                if (SQLGetData(conn->sth, i, col_ctype,
                    (SQLPOINTER) &col_cval, 0, &ind) != SQL_SUCCESS) {
                  sql_log(DEBUG_WARN, "error getting %s data for column %u, "
                    "row %u: %s", sqlodbc_typestr(col_ctype), i,
                    sd->rnum + 1, sqlodbc_errstr(SQL_HANDLE_STMT, conn->sth,
                      NULL));
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;
                }

                if (ind == SQL_NO_TOTAL) {
                  sql_log(DEBUG_WARN, "notice: unable to determine total "
                    "number of bytes remaining for %s column %u, row %u",
                    sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;

                } else if (ind == SQL_NULL_DATA) {
                  sql_log(DEBUG_WARN, "notice: data is NULL for %s column %u, "
                    "row %u", sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;
                }

                pr_snprintf(buf, sizeof(buf), "%ld", col_cval);
                buf[sizeof(buf)-1] = '\0';

                *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, buf);
                break;
              }

              case SQL_FLOAT: {
                char buf[64];
                float col_cval;
                SQLLEN ind;

                col_ctype = SQL_C_FLOAT;

                if (SQLGetData(conn->sth, i, col_ctype,
                    (SQLPOINTER) &col_cval, 0, &ind) != SQL_SUCCESS) {
                  sql_log(DEBUG_WARN, "error getting %s data for column %u, "
                    "row %u: %s", sqlodbc_typestr(col_ctype), i,
                    sd->rnum + 1, sqlodbc_errstr(SQL_HANDLE_STMT, conn->sth,
                      NULL));
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;
                }

                if (ind == SQL_NO_TOTAL) {
                  sql_log(DEBUG_WARN, "notice: unable to determine total "
                    "number of bytes remaining for %s column %u, row %u",
                    sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;

                } else if (ind == SQL_NULL_DATA) {
                  sql_log(DEBUG_WARN, "notice: data is NULL for %s column %u, "
                    "row %u", sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;
                }

                pr_snprintf(buf, sizeof(buf), "%f", col_cval);
                buf[sizeof(buf)-1] = '\0';

                *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, buf);
                break;
              }

              case SQL_DOUBLE: {
                char buf[64];
                double col_cval;
                SQLLEN ind;

                col_ctype = SQL_C_DOUBLE;

                if (SQLGetData(conn->sth, i, col_ctype,
                    (SQLPOINTER) &col_cval, 0, &ind) != SQL_SUCCESS) {
                  sql_log(DEBUG_WARN, "error getting %s data for column %u, "
                    "row %u: %s", sqlodbc_typestr(col_ctype), i,
                    sd->rnum + 1, sqlodbc_errstr(SQL_HANDLE_STMT, conn->sth,
                      NULL));
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;
                }

                if (ind == SQL_NO_TOTAL) {
                  sql_log(DEBUG_WARN, "notice: unable to determine total "
                    "number of bytes remaining for %s column %u, row %u",
                    sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;

                } else if (ind == SQL_NULL_DATA) {
                  sql_log(DEBUG_WARN, "notice: data is NULL for %s column %u, "
                    "row %u", sqlodbc_typestr(col_ctype), i, sd->rnum + 1);
                  *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, "");
                  break;
                }

                pr_snprintf(buf, sizeof(buf), "%f", col_cval);
                buf[sizeof(buf)-1] = '\0';

                *((char **) push_array(dh)) = pstrdup(cmd->tmp_pool, buf);
                break;
              }

              default:
                sql_log(DEBUG_WARN, "data type (%s) of column %u not handled",
                  sqlodbc_typestr(col_type), i);
            }

          } else {
            sql_log(DEBUG_WARN, "error describing column %u: %s", i,
              sqlodbc_errstr(SQL_HANDLE_STMT, conn->sth, NULL));
          }
        }
        break;

      default:
        sql_log(DEBUG_WARN, "SQLFetch returned unhandled result: %d", res);
        break;
    }

    if (done_fetching)
      break;
  }

  SQLFreeHandle(SQL_HANDLE_STMT, conn->sth);
  conn->state &= ~SQLODBC_HAVE_STMT_HANDLE;

  /* We allocate an extra char *, for a terminating NULL. */
  *((char **) push_array(dh)) = NULL;
  sd->data = (char **) dh->elts;

  return mod_create_data(cmd, (void *) sd);
}

MODRET sqlodbc_open(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  SQLSMALLINT res;

  sql_log(DEBUG_FUNC, "%s", "entering \todbc cmd_open");

  if (cmd->argc < 1) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_open");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION, "badly formed request");
  }    

  /* Get the named connection. */
  entry = sqlodbc_get_conn(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_open");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  } 

  conn = (db_conn_t *) entry->data;

  /* If we're already open (nconn > 0), increment the number of connections.
   * Reset our timer if we have one, and return HANDLED.
   */
  if (entry->nconn > 0) {
    entry->nconn++;

    if (entry->timer)
      pr_timer_reset(entry->timer, &sql_odbc_module);

    sql_log(DEBUG_INFO, "'%s' connection count is now %u", entry->name,
      entry->nconn);
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_open");
    return PR_HANDLED(cmd);
  }

  if (!(conn->state & SQLODBC_HAVE_ENV_HANDLE)) {
    res = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &conn->envh);
    if (res != SQL_SUCCESS) {
      sql_log(DEBUG_WARN, "error allocating environment handle: %s",
        sqlodbc_strerror(res));
      sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_open");
      return sqlodbc_get_error(cmd, SQL_HANDLE_ENV, conn->envh);
    }

    res = SQLSetEnvAttr(conn->envh, SQL_ATTR_ODBC_VERSION,
      (SQLPOINTER) odbc_version, 0);
    if (res != SQL_SUCCESS) {
      sql_log(DEBUG_WARN, "error setting SQL_ATTR_ODBC_VERSION %s: %s",
        odbc_version_str, sqlodbc_strerror(res));
      sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_open");
      return sqlodbc_get_error(cmd, SQL_HANDLE_ENV, conn->envh);
    }

    conn->state |= SQLODBC_HAVE_ENV_HANDLE;
  }

  if (!(conn->state & SQLODBC_HAVE_DBC_HANDLE)) {
    res = SQLAllocHandle(SQL_HANDLE_DBC, conn->envh, &conn->dbh);
    if (res != SQL_SUCCESS) {
      sql_log(DEBUG_WARN, "error allocating database handle: %s",
        sqlodbc_strerror(res));
      sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_open");
      return sqlodbc_get_error(cmd, SQL_HANDLE_DBC, conn->dbh);
    }

    conn->state |= SQLODBC_HAVE_DBC_HANDLE;
  }

  res = SQLConnect(conn->dbh, (SQLCHAR *) conn->dsn, SQL_NTS,
    (SQLCHAR *) conn->user, SQL_NTS, (SQLCHAR *) conn->pass, SQL_NTS);
  if (res != SQL_SUCCESS &&
      res != SQL_SUCCESS_WITH_INFO) {
    sql_log(DEBUG_FUNC, "error connecting to dsn '%s': %s", conn->dsn,
      sqlodbc_strerror(res));
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_open");
    return sqlodbc_get_error(cmd, SQL_HANDLE_DBC, conn->dbh);
  }

  /* Add some DriverManager and Driver information to the logs via
   * SQLGetInfo().
   */
  if (!(conn->state & SQLODBC_HAVE_INFO)) {
    SQLCHAR info[SQL_MAX_MESSAGE_LENGTH];
    SQLSMALLINT infolen;

    res = SQLGetInfo(conn->dbh, SQL_DBMS_NAME, info, sizeof(info), &infolen);
    if (res == SQL_SUCCESS) {
      info[infolen] = '\0';
      sql_log(DEBUG_INFO, MOD_SQL_ODBC_VERSION ": Product name: %s", info);

      /* Oracle does not like use of the LIMIT, and prefers ROWNUM instead.
       * Thus we need to check to see if this driver is for Oracle.
       */
      if (strcasecmp((char *) info, "Oracle") == 0) {
        sql_log(DEBUG_INFO, MOD_SQL_ODBC_VERSION
          ": %s does not support LIMIT, using ROWNUM instead", info);
        use_limit_clause = FALSE;
        use_rownum_clause = TRUE;
        use_top_clause = FALSE;
      }

      /* FreeTDS (and SQL Server) does not like either LIMIT or ROWNUM, and
       * prefers TOP. So we need to check for this as well.
       */
      if (strcasecmp((char *) info, "FreeTDS") == 0 ||
          strstr((char *) info, "SQL Server") != NULL) {
        sql_log(DEBUG_INFO, MOD_SQL_ODBC_VERSION
          ": %s does not support LIMIT, using TOP instead", info);
        use_limit_clause = FALSE;
        use_rownum_clause = FALSE;
        use_top_clause = TRUE;
      }

    } else {
      sql_log(DEBUG_INFO, MOD_SQL_ODBC_VERSION
        ": Product name: (unavailable)");
    }

    res = SQLGetInfo(conn->dbh, SQL_DBMS_VER, info, sizeof(info), &infolen);
    if (res == SQL_SUCCESS) {
      info[infolen] = '\0';
      sql_log(DEBUG_INFO, MOD_SQL_ODBC_VERSION ": Product version: %s", info);

    } else {
      sql_log(DEBUG_INFO, MOD_SQL_ODBC_VERSION
        ": Product version: (unavailable)");
    }

    res = SQLGetInfo(conn->dbh, SQL_DM_VER, info, sizeof(info), &infolen);
    if (res == SQL_SUCCESS) {
      info[infolen] = '\0';
      sql_log(DEBUG_INFO, MOD_SQL_ODBC_VERSION ": Driver Manager version: %s",
        info);

    } else {
      sql_log(DEBUG_INFO, MOD_SQL_ODBC_VERSION
        ": Driver Manager version: (unavailable)");
    }

    res = SQLGetInfo(conn->dbh, SQL_DRIVER_NAME, info, sizeof(info), &infolen);
    if (res == SQL_SUCCESS) {
      info[infolen] = '\0';
      sql_log(DEBUG_INFO, MOD_SQL_ODBC_VERSION ": Driver name: %s", info);

    } else {
      sql_log(DEBUG_INFO, MOD_SQL_ODBC_VERSION ": Driver name: (unavailable)");
    }

    res = SQLGetInfo(conn->dbh, SQL_DRIVER_VER, info, sizeof(info), &infolen);
    if (res == SQL_SUCCESS) {
      info[infolen] = '\0';
      sql_log(DEBUG_INFO, MOD_SQL_ODBC_VERSION ": Driver version: %s", info);

    } else {
      sql_log(DEBUG_INFO, MOD_SQL_ODBC_VERSION
        ": Driver version: (unavailable)");
    }

    res = SQLGetInfo(conn->dbh, SQL_DRIVER_ODBC_VER, info, sizeof(info),
      &infolen);
    if (res == SQL_SUCCESS) {
      info[infolen] = '\0';
      sql_log(DEBUG_INFO, MOD_SQL_ODBC_VERSION ": Driver ODBC version: %s",
        info);

    } else {
      sql_log(DEBUG_INFO, MOD_SQL_ODBC_VERSION
        ": Driver ODBC version: (unavailable)");
    }

    conn->state |= SQLODBC_HAVE_INFO;
  }

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

    entry->timer = pr_timer_add(entry->ttl, -1, &sql_odbc_module,
      sqlodbc_timer_cb, "odbc connection ttl");

    sql_log(DEBUG_INFO, "'%s' connection: %d second timer started",
      entry->name, entry->ttl);

    /* Timed connections get re-bumped so they don't go away when
     * sqlodbc_close() is called.
     */
    entry->nconn++;
  }

  sql_log(DEBUG_INFO, "'%s' connection opened", entry->name);
  sql_log(DEBUG_INFO, "'%s' connection count is now %u", entry->name,
    entry->nconn);
  pr_event_generate("mod_sql.db.connection-opened", &sql_odbc_module);

  sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_open");
  return PR_HANDLED(cmd);
}

MODRET sqlodbc_close(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;

  sql_log(DEBUG_FUNC, "%s", "entering \todbc cmd_close");

  if (cmd->argc < 1 || cmd->argc > 2) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_close");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION, "badly formed request");
  }

  /* Get the named connection. */
  entry = sqlodbc_get_conn(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_close");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  conn = (db_conn_t *) entry->data;

  /* If we're closed already (nconn == 0), return HANDLED. */
  if (entry->nconn == 0) {
    sql_log(DEBUG_INFO, "'%s' connection count is now %u", entry->name,
      entry->nconn);
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_close");
    return PR_HANDLED(cmd);
  }

  /* Decrement nconn. If our count is 0 or we received a second arg, close
   * the connection, explicitly set the counter to 0, and remove any timers.
   */
  if ((--entry->nconn) == 0 ||
      (cmd->argc == 2 && cmd->argv[1])) {

    if (conn->state & SQLODBC_HAVE_STMT_HANDLE) {
      SQLFreeHandle(SQL_HANDLE_STMT, conn->sth);
      conn->sth = NULL;

      conn->state &= ~SQLODBC_HAVE_STMT_HANDLE;
    }

    if (conn->state & SQLODBC_HAVE_DBC_HANDLE) {
      SQLDisconnect(conn->dbh);
      SQLFreeHandle(SQL_HANDLE_DBC, conn->dbh);
      conn->dbh = NULL;

      conn->state &= ~SQLODBC_HAVE_DBC_HANDLE;
    }

    if (conn->state & SQLODBC_HAVE_ENV_HANDLE) {
      SQLFreeHandle(SQL_HANDLE_ENV, conn->envh);
      conn->envh = NULL;

      conn->state &= ~SQLODBC_HAVE_ENV_HANDLE;
    }

    entry->nconn = 0;

    if (entry->timer) {
      pr_timer_remove(entry->timer, &sql_odbc_module);
      entry->timer = 0;
      sql_log(DEBUG_INFO, "'%s' connection timer stopped", entry->name);
    }

    sql_log(DEBUG_INFO, "'%s' connection closed", entry->name);
    pr_event_generate("mod_sql.db.connection-closed", &sql_odbc_module);
  }

  sql_log(DEBUG_INFO, "'%s' connection count is now %u", entry->name,
    entry->nconn);
  sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_close");
  
  return PR_HANDLED(cmd);
}

MODRET sqlodbc_def_conn(cmd_rec *cmd) {
  char *name = NULL;
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL; 

  sql_log(DEBUG_FUNC, "%s", "entering \todbc cmd_defineconnection");

  if (cmd->argc < 4 ||
      cmd->argc > 10 ||
      !cmd->argv[0]) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_defineconnection");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION, "badly formed request");
  }

  conn = (db_conn_t *) pcalloc(conn_pool, sizeof(db_conn_t));

  name = pstrdup(conn_pool, cmd->argv[0]);
  conn->user = pstrdup(conn_pool, cmd->argv[1]);
  conn->pass = pstrdup(conn_pool, cmd->argv[2]);
  conn->dsn = pstrdup(conn_pool, cmd->argv[3]);

  /* Insert the new conn_info into the connection hash */
  entry = sqlodbc_add_conn(conn_pool, name, (void *) conn);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_defineconnection");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION,
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
  sql_log(DEBUG_INFO, " user: '%s'", conn->user);
  sql_log(DEBUG_INFO, "  dsn: '%s'", conn->dsn);

  sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_defineconnection");
  return PR_HANDLED(cmd);
}

MODRET sqlodbc_select(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  modret_t *mr = NULL;
  char *query = NULL;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \todbc cmd_select");

  if (cmd->argc < 2) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_select");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION, "badly formed request");
  }

  /* Get the named connection. */
  entry = sqlodbc_get_conn(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_select");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }
 
  conn = (db_conn_t *) entry->data;

  mr = sqlodbc_open(cmd);
  if (MODRET_ERROR(mr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_select");
    return mr;
  }

  /* Construct the query string. */
  if (cmd->argc == 2) {
    query = pstrcat(cmd->tmp_pool, "SELECT ", cmd->argv[1], NULL);

  } else {
    query = pstrcat(cmd->tmp_pool, cmd->argv[2], " FROM ", cmd->argv[1], NULL);

    if (cmd->argc > 3 &&
        cmd->argv[3])
      query = pstrcat(cmd->tmp_pool, query, " WHERE ", cmd->argv[3], NULL);

    if (cmd->argc > 4 &&
        cmd->argv[4]) {

      if (use_limit_clause) {
        query = pstrcat(cmd->tmp_pool, query, " LIMIT ", cmd->argv[4], NULL);

      } else if (use_rownum_clause) {
        query = pstrcat(cmd->tmp_pool, query, " AND ROWNUM = ", cmd->argv[4],
          NULL);

      } else if (use_top_clause) {
        /* Note that the TOP clause must be at the start of the query, not
         * the end.
         */
        query = pstrcat(cmd->tmp_pool, "TOP ", cmd->argv[4], " ", query, NULL);
      }
    }

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

  if (!(conn->state & SQLODBC_HAVE_STMT_HANDLE)) {
    if (SQLAllocHandle(SQL_HANDLE_STMT, conn->dbh, &conn->sth) !=
        SQL_SUCCESS) {
      sql_log(DEBUG_WARN, "%s", "error allocating statement handle");
      sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_select");
      return sqlodbc_get_error(cmd, SQL_HANDLE_STMT, conn->sth);
    }

    conn->state |= SQLODBC_HAVE_STMT_HANDLE;
  }

  /* Perform the query.  If it doesn't work, log the error, close the
   * connection, then return the error from the query processing.
   */
  switch (SQLPrepare(conn->sth, (SQLCHAR *) query, strlen(query))) {
    case SQL_SUCCESS:
    case SQL_SUCCESS_WITH_INFO:
      break;

    default:
      mr = sqlodbc_get_error(cmd, SQL_HANDLE_STMT, conn->sth);

      close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
      sqlodbc_close(close_cmd);
      destroy_pool(close_cmd->pool);

      sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_select");
      return mr;
  }

  switch (SQLExecute(conn->sth)) {
    case SQL_SUCCESS:
    case SQL_SUCCESS_WITH_INFO:
      break;

    default:
      mr = sqlodbc_get_error(cmd, SQL_HANDLE_STMT, conn->sth);

      close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
      sqlodbc_close(close_cmd);
      destroy_pool(close_cmd->pool);

      sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_select");
      return mr;
  }

  /* Get the data. If it doesn't work, log the error, close the connection,
   * then return the error from the data processing.
   */

  mr = sqlodbc_get_data(cmd, conn);
  if (MODRET_ERROR(mr)) {
    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sqlodbc_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_select");
    return mr;
  }    

  /* Close the connection, return the data. */
  close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
  sqlodbc_close(close_cmd);
  destroy_pool(close_cmd->pool);

  sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_select");
  return mr;
}

MODRET sqlodbc_insert(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  modret_t *mr = NULL;
  char *query = NULL;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \todbc cmd_insert");

  if (cmd->argc != 2 && cmd->argc != 4) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_insert");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION, "badly formed request");
  }

  /* Get the named connection. */
  entry = sqlodbc_get_conn(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_insert");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  conn = (db_conn_t *) entry->data;

  mr = sqlodbc_open(cmd);
  if (MODRET_ERROR(mr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_insert");
    return mr;
  }

  /* Construct the query string */
  if (cmd->argc == 2)
    query = pstrcat(cmd->tmp_pool, "INSERT ", cmd->argv[1], NULL);

  else
    query = pstrcat(cmd->tmp_pool, "INSERT INTO ", cmd->argv[1], " (",
      cmd->argv[2], ") VALUES (", cmd->argv[3], ")", NULL);

  /* Log the query string */
  sql_log(DEBUG_INFO, "query \"%s\"", query);

  if (!(conn->state & SQLODBC_HAVE_STMT_HANDLE)) {
    if (SQLAllocHandle(SQL_HANDLE_STMT, conn->dbh, &conn->sth) !=
        SQL_SUCCESS) {
      sql_log(DEBUG_WARN, "%s", "error allocating statement handle");
      sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_insert");
      return sqlodbc_get_error(cmd, SQL_HANDLE_STMT, conn->sth);
    }

    conn->state |= SQLODBC_HAVE_STMT_HANDLE;
  }

  /* Perform the query.  If it doesn't work, log the error, close the
   * connection (and log any errors there, too) then return the error
   * from the query processing.
   */
  if (SQLPrepare(conn->sth, (SQLCHAR *) query, strlen(query)) != SQL_SUCCESS) {
    mr = sqlodbc_get_error(cmd, SQL_HANDLE_STMT, conn->sth);

    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sqlodbc_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_insert");
    return mr;
  }

  switch (SQLExecute(conn->sth)) {
    case SQL_SUCCESS:
    case SQL_SUCCESS_WITH_INFO:
      break;

    default:
      mr = sqlodbc_get_error(cmd, SQL_HANDLE_STMT, conn->sth);

      close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
      sqlodbc_close(close_cmd);
      destroy_pool(close_cmd->pool);

      sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_insert");
      return mr;
  }

  /* Close the connection and return HANDLED. */
  close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
  sqlodbc_close(close_cmd);
  destroy_pool(close_cmd->pool);

  sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_insert");
  return PR_HANDLED(cmd);
}

MODRET sqlodbc_update(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  modret_t *mr = NULL;
  char *query = NULL;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \todbc cmd_update");

  if (cmd->argc < 2 || cmd->argc > 4) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_update");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION, "badly formed request");
  }

  /* Get the named connection. */
  entry = sqlodbc_get_conn(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_update");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  conn = (db_conn_t *) entry->data;

  mr = sqlodbc_open(cmd);
  if (MODRET_ERROR(mr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_update");
    return mr;
  }

  if (cmd->argc == 2) {
    query = pstrcat(cmd->tmp_pool, "UPDATE ", cmd->argv[1], NULL);

  } else {
    /* Construct the query string */
    query = pstrcat(cmd->tmp_pool, "UPDATE ", cmd->argv[1], " SET ",
      cmd->argv[2], NULL);

    if (cmd->argc > 3 && cmd->argv[3])
      query = pstrcat(cmd->tmp_pool, query, " WHERE ", cmd->argv[3], NULL);
  }

  /* Log the query string. */
  sql_log(DEBUG_INFO, "query \"%s\"", query);

  if (!(conn->state & SQLODBC_HAVE_STMT_HANDLE)) {
    if (SQLAllocHandle(SQL_HANDLE_STMT, conn->dbh, &conn->sth) !=
        SQL_SUCCESS) {
      sql_log(DEBUG_WARN, "%s", "error allocating statement handle");
      sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_update");
      return sqlodbc_get_error(cmd, SQL_HANDLE_STMT, conn->sth);
    }

    conn->state |= SQLODBC_HAVE_STMT_HANDLE;
  }

  /* Perform the query.  If it doesn't work close the connection, then
   * return the error from the query processing.
   */
  if (SQLPrepare(conn->sth, (SQLCHAR *) query, strlen(query)) != SQL_SUCCESS) {
    mr = sqlodbc_get_error(cmd, SQL_HANDLE_STMT, conn->sth);

    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sqlodbc_close(close_cmd);
    destroy_pool(close_cmd->pool);

    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_update");
    return mr;
  }

  switch (SQLExecute(conn->sth)) {
    case SQL_SUCCESS:
    case SQL_SUCCESS_WITH_INFO:
      break;

    default:
      mr = sqlodbc_get_error(cmd, SQL_HANDLE_STMT, conn->sth);

      close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
      sqlodbc_close(close_cmd);
      destroy_pool(close_cmd->pool);

      sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_update");
      return mr;
  }

  /* Close the connection, return HANDLED.  */
  close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
  sqlodbc_close(close_cmd);
  destroy_pool(close_cmd->pool);

  sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_update");
  return PR_HANDLED(cmd);
}

MODRET sqlodbc_procedure(cmd_rec *cmd) {
  sql_log(DEBUG_FUNC, "%s", "entering \todbc cmd_procedure");

  if (cmd->argc != 3) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_procedure");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION, "badly formed request");
  }

  sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_procedure");
  return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION,
    "backend does not support procedures");
}

MODRET sqlodbc_query(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  db_conn_t *conn = NULL;
  modret_t *mr = NULL;
  char *query = NULL;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \todbc cmd_query");

  if (cmd->argc != 2) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_query");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION, "badly formed request");
  }

  /* Get the named connection. */
  entry = sqlodbc_get_conn(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_query");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  conn = (db_conn_t *) entry->data;

  mr = sqlodbc_open(cmd);
  if (MODRET_ERROR(mr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_query");
    return mr;
  }

  query = pstrcat(cmd->tmp_pool, cmd->argv[1], NULL);

  /* Log the query string */
  sql_log(DEBUG_INFO, "query \"%s\"", query);

  if (!(conn->state & SQLODBC_HAVE_STMT_HANDLE)) {
    if (SQLAllocHandle(SQL_HANDLE_STMT, conn->dbh, &conn->sth) !=
        SQL_SUCCESS) {
      sql_log(DEBUG_WARN, "%s", "error allocating statement handle");
      sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_query");
      return sqlodbc_get_error(cmd, SQL_HANDLE_STMT, conn->sth);
    }

    conn->state |= SQLODBC_HAVE_STMT_HANDLE;
  }

  /* Perform the query.  If it doesn't work close the connection, then
   * return the error from the query processing.
   */
  if (SQLPrepare(conn->sth, (SQLCHAR *) query, strlen(query)) != SQL_SUCCESS) {
    mr = sqlodbc_get_error(cmd, SQL_HANDLE_STMT, conn->sth);
    
    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sqlodbc_close(close_cmd);
    destroy_pool(close_cmd->pool);
  
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_query");
    return mr;
  }
    
  switch (SQLExecute(conn->sth)) {
    case SQL_SUCCESS:
    case SQL_SUCCESS_WITH_INFO:
      break;

    default: 
      mr = sqlodbc_get_error(cmd, SQL_HANDLE_STMT, conn->sth);

      close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name); 
      sqlodbc_close(close_cmd);
      destroy_pool(close_cmd->pool);
  
      sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_query");
      return mr;
  }

  /* Get data if necessary. If it doesn't work, log the error, close the
   * connection then return the error from the data processing.
   */

  mr = sqlodbc_get_data(cmd, conn);
  if (MODRET_ERROR(mr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_query");

    close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
    sqlodbc_close(close_cmd);
    destroy_pool(close_cmd->pool);

    return mr;
  }   
  
  /* Close the connection, return the data. */
  close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
  sqlodbc_close(close_cmd);
  destroy_pool(close_cmd->pool);

  sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_query");
  return mr;
}

/* XXX need to provide an escapestring implementation, probably borrowed
 * from MySQL.  Make sure it's standards-compliant.
 */

MODRET sqlodbc_quote(cmd_rec *cmd) {
  conn_entry_t *entry = NULL;
  modret_t *mr = NULL;
  char *unescaped = NULL;
  char *escaped = NULL;
  cmd_rec *close_cmd;

  sql_log(DEBUG_FUNC, "%s", "entering \todbc cmd_escapestring");

  if (cmd->argc != 2) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_escapestring");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION, "badly formed request");
  }

  /* Get the named connection. */
  entry = sqlodbc_get_conn(cmd->argv[0]);
  if (entry == NULL) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_escapestring");
    return PR_ERROR_MSG(cmd, MOD_SQL_ODBC_VERSION,
      pstrcat(cmd->tmp_pool, "unknown named connection: ", cmd->argv[0], NULL));
  }

  /* Make sure the connection is open. */
  mr = sqlodbc_open(cmd);
  if (MODRET_ERROR(mr)) {
    sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_escapestring");
    return mr;
  }

  unescaped = cmd->argv[1];
  escaped = (char *) pcalloc(cmd->tmp_pool, sizeof(char) * 
			      (strlen(unescaped) * 2) + 1);

  sqlodbc_escape_string(escaped, unescaped, strlen(unescaped));

  close_cmd = pr_cmd_alloc(cmd->tmp_pool, 1, entry->name);
  sqlodbc_close(close_cmd);
  destroy_pool(close_cmd->pool);

  sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_escapestring");
  return mod_create_data(cmd, (void *) escaped);
}

MODRET sqlodbc_exit(cmd_rec *cmd) {
  register unsigned int i = 0;

  sql_log(DEBUG_FUNC, "%s", "entering \todbc cmd_exit");

  for (i = 0; i < conn_cache->nelts; i++) {
    conn_entry_t *entry = ((conn_entry_t **) conn_cache->elts)[i];

    if (entry->nconn > 0) {
      cmd_rec *close_cmd = pr_cmd_alloc(conn_pool, 2, entry->name, "1");
      sqlodbc_close(close_cmd);
      destroy_pool(close_cmd->pool);
    }
  }

  sql_log(DEBUG_FUNC, "%s", "exiting \todbc cmd_exit");
  return PR_HANDLED(cmd);
}

MODRET sqlodbc_identify(cmd_rec *cmd) {
  sql_data_t *sd = NULL;

  sd = (sql_data_t *) pcalloc(cmd->tmp_pool, sizeof(sql_data_t));
  sd->data = (char **) pcalloc(cmd->tmp_pool, sizeof(char *) * 2);

  sd->rnum = 1;
  sd->fnum = 2;

  sd->data[0] = MOD_SQL_ODBC_VERSION;
  sd->data[1] = MOD_SQL_API_V1;

  return mod_create_data(cmd, (void *) sd);
}  

/* mod_sql-specific command dispatch/handler table */
static cmdtable sqlodbc_cmdtable[] = {
  { CMD, "sql_open",		G_NONE,	sqlodbc_open,	FALSE, FALSE },
  { CMD, "sql_close",		G_NONE, sqlodbc_close,	FALSE, FALSE },
  { CMD, "sql_defineconnection",G_NONE, sqlodbc_def_conn, FALSE, FALSE },
  { CMD, "sql_select",		G_NONE, sqlodbc_select,	FALSE, FALSE },
  { CMD, "sql_insert",		G_NONE, sqlodbc_insert,	FALSE, FALSE },
  { CMD, "sql_update",		G_NONE, sqlodbc_update,	FALSE, FALSE },
  { CMD, "sql_procedure",	G_NONE, sqlodbc_procedure, FALSE, FALSE },
  { CMD, "sql_query",		G_NONE, sqlodbc_query,	FALSE, FALSE },
  { CMD, "sql_escapestring",	G_NONE, sqlodbc_quote,	FALSE, FALSE },
  { CMD, "sql_exit",		G_NONE, sqlodbc_exit,	FALSE, FALSE },
  { CMD, "sql_identify",	G_NONE, sqlodbc_identify, FALSE, FALSE },

  { 0, NULL }
};

/* Configuration handlers
 */

/* usage: SQLODBCVersion version */
MODRET set_sqlodbcversion(cmd_rec *cmd) {
  int version = -1;
  const char *version_str;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_VIRTUAL);

  if (strcasecmp(cmd->argv[1], "2") == 0 ||
      strcasecmp(cmd->argv[1], "odbcv2") == 0) {
#if defined(SQL_OV_ODBC2)
    version = SQL_OV_ODBC2;
    version_str = "ODBCv2";
#endif /* ODBCv2 */

  } else if (strcasecmp(cmd->argv[1], "3") == 0 ||
             strcasecmp(cmd->argv[1], "odbcv3") == 0) {
#if defined(SQL_OV_ODBC3)
    version = SQL_OV_ODBC3;
    version_str = "ODBCv3";
#endif /* ODBCv3 */

  } else if (strcasecmp(cmd->argv[1], "3.80") == 0 ||
             strcasecmp(cmd->argv[1], "odbcv3.80") == 0) {
#if defined(SQL_OV_ODBC3_80)
    version = SQL_OV_ODBC3_80;
    version_str = "ODBCv3.80";
#endif /* ODBCv3.80 */
  }

  if (version < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "unknown/supported ODBC API version: ", cmd->argv[1], NULL));
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = version;
  c->argv[1] = pstrdup(c->pool, version_str);

  return PR_HANDLED(cmd);
}

/* Event handlers
 */

static void sqlodbc_mod_unload_ev(const void *event_data, void *user_data) {

  if (strcmp("mod_sql_odbc.c", (const char *) event_data) == 0) {
    /* Unegister ourselves with mod_sql. */
    if (sql_unregister_backend("odbc") < 0) {
      pr_log_pri(PR_LOG_NOTICE, MOD_SQL_ODBC_VERSION
        ": notice: error unregistering backend: %s", strerror(errno));
      pr_session_end(0);
    }

    /* Unregister ourselves from all events. */
    pr_event_unregister(&sql_odbc_module, NULL, NULL);
  }
}

/* Module initialization routines
 */

static int sqlodbc_init(void) {

  /* Register ourselves with mod_sql. */
  if (sql_register_backend("odbc", sqlodbc_cmdtable) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_SQL_ODBC_VERSION
      ": notice: error registering backend: %s", strerror(errno));
    errno = EPERM;
    return -1;
  }

  /* Register listeners for the unload event. */
  pr_event_register(&sql_odbc_module, "core.module-unload",
    sqlodbc_mod_unload_ev, NULL);

  return 0;
}

static int sqlodbc_sess_init(void) {
  config_rec *c;

  if (conn_pool == NULL) {
    conn_pool = make_sub_pool(session.pool);
    pr_pool_tag(conn_pool, "ODBC connection pool");
  }

  if (conn_cache == NULL) {
    conn_cache = make_array(make_sub_pool(session.pool), DEF_CONN_POOL_SIZE,
      sizeof(conn_entry_t *));
  }

  /* There is a very specific reason for using square brackets, rather than
   * parentheses, here.
   *
   * Users of the mod_sql_odbc module for talking to an Oracle database
   * via ODBC encountered a bug in the Oracle client library, where the Oracle
   * client library tries to find the name of the process calling the client,
   * and adds that name to the connection string used.  However, that process
   * name parsing will fail if the process name uses parentheses.  The
   * workaround, then, is to use square brackets.
   *
   * For those curious, this is Oracle Bug 3807408.  More discussions on
   * problem can be found at:
   *
   *  http://forums.oracle.com/forums/thread.jspa?threadID=296725
   *
   * The following comment indicates that more recent versions of Oracle
   * have this issue fixed; there is also a patch available:
   *
   *  "This issue is Oracle bug 3807408 and can be fixed by applying 10.2.0.1
   *   Patch 6. This can be downloaded from MetaLink if you have an account:
   *
   *   http://updates.oracle.com/ARULink/PatchDetails/process_form?patch_num=5059238"
   * This comment was found at:
   *
   *  http://www.topxml.com/forum/Database_Adapter_for_Oracle_on_64bit_Windows/m_3448/tm.htm
   */

  pr_proctitle_set("[accepting connections]");

  c = find_config(main_server->conf, CONF_PARAM, "SQLODBCVersion", FALSE);
  if (c != NULL) {
    odbc_version = *((int *) c->argv[0]);
    odbc_version_str = c->argv[1];
  }

  return 0;
}

/* Module API tables
 */

static conftable sqlodbc_conftab[] = {
  { "SQLODBCVersion",	set_sqlodbcversion,	NULL },
  { NULL, NULL, NULL }
};

module sql_odbc_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "sql_odbc",

  /* Module configuration directive table */
  sqlodbc_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  sqlodbc_init,

  /* Session initialization */
  sqlodbc_sess_init,

  /* Module version */
  MOD_SQL_ODBC_VERSION
};
