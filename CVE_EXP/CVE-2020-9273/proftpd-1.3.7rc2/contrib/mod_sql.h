/*
 * ProFTPD: mod_sql.h -- header file for mod_sql and backends
 * Time-stamp: <1999-10-04 03:21:21 root>
 * Copyright (c) 1998-1999 Johnie Ingram.
 * Copyright (c) 2001 Andrew Houghton
 * Copyright (c) 2002-2015 The ProFTPD Project
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
 */

#ifndef MOD_SQL_H
#define MOD_SQL_H

/* mod_sql helper functions */
int sql_log(int, const char *, ...);
cmd_rec *sql_make_cmd(pool *p, int argc, ...);
int sql_register_backend(const char *, cmdtable *);
int sql_unregister_backend(const char *);

/* Custom SQLAuthType registration. */
int sql_register_authtype(const char *name,
  modret_t *(*callback)(cmd_rec *, const char *, const char *));
int sql_unregister_authtype(const char *name);

/* data passing structure */
struct sql_data_struct {
  unsigned long rnum;     /* number of rows of data    */
  unsigned long fnum;     /* number of fields per row  */
  char **data;            /* data[][]                  */
};

typedef struct sql_data_struct sql_data_t;

/* on the assumption that logging will turn into a bitmask later */
#define DEBUG_FUNC DEBUG5
#define DEBUG_AUTH DEBUG4
#define DEBUG_INFO DEBUG3
#define DEBUG_WARN DEBUG2

#define SQL_FREE_CMD(c)       destroy_pool((c)->pool)

/* 
 * These macros are for backends to create basic internal error messages
 */

#define PR_ERR_SQL_REDEF(cmd)        mod_create_ret((cmd), 1, _MOD_VERSION, \
                                     "named connection already exists")
#define PR_ERR_SQL_UNDEF(cmd)        mod_create_ret((cmd), 1, _MOD_VERSION, \
                                     "unknown named connection")
#define PR_ERR_SQL_UNKNOWN(cmd)      mod_create_ret((cmd), 1, _MOD_VERSION, \
                                     "unknown backend error")
#define PR_ERR_SQL_BADCMD(cmd)       mod_create_ret((cmd), 1, _MOD_VERSION, \
                                     "badly formed request")

/* API versions */

/* MOD_SQL_API_V1: guarantees to correctly implement cmd_open, cmd_close,
 *  cmd_defineconnection, cmd_select, cmd_insert, cmd_update, cmd_escapestring,
 *  cmd_query, cmd_checkauth, and cmd_identify.  Also guarantees to
 *  perform proper registration of the cmdtable.
 */
#define MOD_SQL_API_V1 "mod_sql_api_v1"

/* MOD_SQL_API_V2: MOD_SQL_API_V1 && guarantees to correctly implement 
 *  cmd_procedure.
 */
#define MOD_SQL_API_V2 "mod_sql_api_v2"

/* SQLOption values */
extern unsigned long pr_sql_opts;

#define SQL_OPT_NO_DISCONNECT_ON_ERROR          0x0001
#define SQL_OPT_USE_NORMALIZED_GROUP_SCHEMA     0x0002
#define SQL_OPT_NO_RECONNECT                    0x0004
#define SQL_OPT_IGNORE_CONFIG_FILE		0x0008

/* SQL connection policy */
extern unsigned int pr_sql_conn_policy;

#define SQL_CONN_POLICY_PERSESSION	1
#define SQL_CONN_POLICY_TIMER		2
#define SQL_CONN_POLICY_PERCALL		3
#define SQL_CONN_POLICY_PERCONN		4

#endif /* MOD_SQL_H */
