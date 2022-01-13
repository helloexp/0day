/*
 * ProFTPD - mod_auth_otp database storage
 * Copyright (c) 2015-2017 TJ Saunders
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
 */

#include "mod_auth_otp.h"
#include "mod_sql.h"
#include "base32.h"
#include "db.h"

#define AUTH_OTP_SQL_VALUE_BUFSZ	32

/* Max number of attempts for lock requests */
#define AUTH_OTP_MAX_LOCK_ATTEMPTS	10

static const char *trace_channel = "auth_otp";

static char *db_get_name(pool *p, const char *name) {
  cmdtable *cmdtab;
  cmd_rec *cmd;
  modret_t *res;

  /* Find the cmdtable for the sql_escapestr command. */
  cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_escapestr", NULL, NULL, NULL);
  if (cmdtab == NULL) {
    pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "error: unable to find SQL hook symbol 'sql_escapestr'");
    return pstrdup(p, name);
  }

  if (strlen(name) == 0) {
    return pstrdup(p, "");
  }

  cmd = pr_cmd_alloc(p, 1, pr_str_strip(p, (char *) name));

  /* Call the handler. */
  res = pr_module_call(cmdtab->m, cmdtab->handler, cmd);

  /* Check the results. */
  if (MODRET_ISDECLINED(res) ||
      MODRET_ISERROR(res)) {
    pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "error executing 'sql_escapestring'");
    return pstrdup(p, name);
  }

  return res->data;
}

int auth_otp_db_close(struct auth_otp_db *dbh) {
  if (dbh->db_lockfd > 0) {
    (void) close(dbh->db_lockfd);
    dbh->db_lockfd = -1;
  }

  destroy_pool(dbh->pool);
  return 0;
}

struct auth_otp_db *auth_otp_db_open(pool *p, const char *tabinfo) {
  struct auth_otp_db *dbh = NULL;
  pool *db_pool = NULL, *tmp_pool = NULL;
  char *ptr, *ptr2, *named_query, *select_query = NULL, *update_query = NULL;
  config_rec *c;

  /* The tabinfo should look like:
   *  "/<select-named-query>/<update-named-query>"
   *
   * Parse the named queries out of the string, and store them in the db
   * handle.
   */

  ptr = strchr(tabinfo, '/');
  if (ptr == NULL) {
    pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "error: badly formatted table info '%s'", tabinfo);
    errno = EINVAL;
    return NULL;
  }

  ptr2 = strchr(ptr + 1, '/');
  if (ptr2 == NULL) {
    pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "error: badly formatted table info '%s'", tabinfo);
    errno = EINVAL;
    return NULL;
  }

  db_pool = make_sub_pool(p);
  pr_pool_tag(db_pool, "Auth OTP Table Pool");
  dbh = pcalloc(db_pool, sizeof(struct auth_otp_db));
  dbh->pool = db_pool;

  tmp_pool = make_sub_pool(p);

  *ptr2 = '\0';
  select_query = pstrdup(dbh->pool, ptr + 1);

  /* Verify that the named query has indeed been defined. This is based on how
   * mod_sql creates its config_rec names.
   */
  named_query = pstrcat(tmp_pool, "SQLNamedQuery_", select_query, NULL);
  c = find_config(main_server->conf, CONF_PARAM, named_query, FALSE);
  if (c == NULL) {
    pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "error: unable to resolve SQLNamedQuery name '%s'", select_query);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return NULL;
  }

  *ptr = *ptr2 = '/';

  ptr = ptr2;
  ptr2 = strchr(ptr + 1, '/');
  if (ptr2 != NULL) {
    *ptr2 = '\0';
  }

  update_query = pstrdup(dbh->pool, ptr + 1);

  if (ptr2 != NULL) {
    *ptr2 = '/';
  }

  named_query = pstrcat(tmp_pool, "SQLNamedQuery_", update_query, NULL);
  c = find_config(main_server->conf, CONF_PARAM, named_query, FALSE);
  if (c == NULL) {
    pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "error: unable to resolve SQLNamedQuery name '%s'", update_query);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return NULL;
  }

  destroy_pool(tmp_pool);

  dbh->select_query = select_query;
  dbh->update_query = update_query;

  /* Prepare the lock structure. */
  dbh->db_lock.l_whence = SEEK_CUR;
  dbh->db_lock.l_start = 0;
  dbh->db_lock.l_len = 0;

  return dbh;
}

int auth_otp_db_get_user_info(pool *p, struct auth_otp_db *dbh,
    const char *user, const unsigned char **secret, size_t *secret_len,
    unsigned long *counter) {
  int res;
  pool *tmp_pool = NULL;
  cmdtable *sql_cmdtab = NULL;
  cmd_rec *sql_cmd = NULL;
  modret_t *sql_res = NULL;
  array_header *sql_data = NULL;
  const char *select_query = NULL;
  char *encoded, **values = NULL;
  size_t encoded_len;
  unsigned int nvalues = 0;

  if (dbh == NULL ||
      user == NULL ||
      secret == NULL ||
      secret_len == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Allocate a temporary pool for the duration of this lookup. */
  tmp_pool = make_sub_pool(p);

  /* Find the cmdtable for the sql_lookup command. */
  sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_lookup", NULL, NULL,
    NULL);
  if (sql_cmdtab == NULL) {
    pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "error: unable to find SQL hook symbol 'sql_lookup'");
    destroy_pool(tmp_pool);
    errno = EPERM;
    return -1;
  }

  /* Prepare the SELECT query. */
  select_query = dbh->select_query;
  sql_cmd = pr_cmd_alloc(tmp_pool, 3, "sql_lookup", select_query,
    db_get_name(tmp_pool, user));

  /* Call the handler. */
  sql_res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, sql_cmd);

  /* Check the results. */
  if (sql_res == NULL ||
      MODRET_ISERROR(sql_res)) {
    pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "error processing SQLNamedQuery '%s'", select_query);
    destroy_pool(tmp_pool);
    errno = EPERM;
    return -1;
  }

  sql_data = (array_header *) sql_res->data;

  /* The expected number of items in the result set depends on whether we
   * want/need the HOTP counter.  If not, then it's only 1 (for the secret),
   * otherwise 2 (secret and current counter).
   */
  nvalues = (counter ? 2 : 1);

  if (sql_data->nelts < nvalues) {
    if (sql_data->nelts > 0) {
      pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
        "error: SQLNamedQuery '%s' returned incorrect number of values (%d)",
        select_query, sql_data->nelts);
    }

    destroy_pool(tmp_pool);

    errno = (sql_data->nelts == 0) ? ENOENT : EINVAL;
    return -1;
  }

  values = sql_data->elts;

  /* Don't forget to base32-decode the value from the database. */
  encoded = values[0];
  encoded_len = strlen(encoded);

  res = auth_otp_base32_decode(p, (const unsigned char *) encoded, encoded_len,
    secret, secret_len);
  if (res < 0) {
    (void) pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "error base32-decoding value from database: %s", strerror(errno));
    errno = EPERM;
    return -1;
  }

  pr_memscrub(values[0], *secret_len);

  if (counter != NULL) {
    *counter = (unsigned long) atol(values[1]);
  }

  destroy_pool(tmp_pool);
  return 0;
}

int auth_otp_db_have_user_info(pool *p, struct auth_otp_db *dbh,
    const char *user) {
  int res, xerrno = 0;
  const unsigned char *secret = NULL;
  size_t secret_len = 0;

  res = auth_otp_db_get_user_info(p, dbh, user, &secret, &secret_len, NULL);
  xerrno = errno;

  if (res == 0) {
    pr_memscrub((void *) secret, secret_len);
  }

  errno = xerrno;
  return res;
}

int auth_otp_db_update_counter(struct auth_otp_db *dbh, const char *user,
    unsigned long counter) {
  pool *tmp_pool = NULL;
  cmdtable *sql_cmdtab = NULL;
  cmd_rec *sql_cmd = NULL;
  modret_t *sql_res = NULL;
  const char *update_query = NULL;
  char *counter_str = NULL;
  size_t counter_len = 0;

  if (dbh == NULL ||
      user == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Allocate a temporary pool for the duration of this change. */
  tmp_pool = make_sub_pool(dbh->pool);

  /* Find the cmdtable for the sql_change command. */
  sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_change", NULL, NULL,
    NULL);
  if (sql_cmdtab == NULL) {
    pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "error: unable to find SQL hook symbol 'sql_change'");
    destroy_pool(tmp_pool);
    return -1;
  }

  update_query = dbh->update_query;
  counter_len = AUTH_OTP_SQL_VALUE_BUFSZ * sizeof(char);
  counter_str = pcalloc(tmp_pool, counter_len);
  pr_snprintf(counter_str, counter_len-1, "%lu", counter);

  sql_cmd = pr_cmd_alloc(tmp_pool, 4, "sql_change", update_query,
    db_get_name(tmp_pool, user), counter_str);

  /* Call the handler. */
  sql_res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, sql_cmd);

  /* Check the results. */
  if (sql_res == NULL ||
      MODRET_ISERROR(sql_res)) {
    pr_log_writefile(auth_otp_logfd, MOD_AUTH_OTP_VERSION,
      "error processing SQLNamedQuery '%s'", update_query);
    destroy_pool(tmp_pool);
    errno = EPERM;
    return -1;
  }

  destroy_pool(tmp_pool);
  return 0;
}

/* Locking routines */

static const char *get_lock_type(struct flock *lock) {
  const char *lock_type;

  switch (lock->l_type) {
    case F_RDLCK:
      lock_type = "read-lock";
      break;

    case F_WRLCK:
      lock_type = "write-lock";
      break;

    case F_UNLCK:
      lock_type = "unlock";
      break;

    default:
      lock_type = "[unknown]";
  }

  return lock_type;
}

static int do_lock(int fd, struct flock *lock) {
  unsigned int nattempts = 1;
  const char *lock_type;

  lock_type = get_lock_type(lock);

  pr_trace_msg(trace_channel, 9,
    "attempt #%u to %s AuthOTPTableLock fd %d", nattempts, lock_type, fd);

  while (fcntl(fd, F_SETLK, lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg(trace_channel, 3,
      "%s (attempt #%u) of AuthOTPTableLock fd %d failed: %s", lock_type,
      nattempts, fd, strerror(xerrno));
    if (xerrno == EACCES) {
      struct flock locker;

      /* Get the PID of the process blocking this lock. */
      if (fcntl(fd, F_GETLK, &locker) == 0) {
        pr_trace_msg(trace_channel, 3, "process ID %lu has blocking %s lock on "
          "AuthOTPTableLock fd %d", (unsigned long) locker.l_pid,
          get_lock_type(&locker), fd);
      }
    }

    if (xerrno == EAGAIN ||
        xerrno == EACCES) {
      /* Treat this as an interrupted call, call pr_signals_handle() (which
       * will delay for a few msecs because of EINTR), and try again.
       * After MAX_LOCK_ATTEMPTS attempts, give up altogether.
       */

      nattempts++;
      if (nattempts <= AUTH_OTP_MAX_LOCK_ATTEMPTS) {
        errno = EINTR;

        pr_signals_handle();

        errno = 0;
        pr_trace_msg(trace_channel, 9,
          "attempt #%u to %s AuthOTPTableLock fd %d", nattempts, lock_type, fd);
        continue;
      }

      pr_trace_msg(trace_channel, 9, "unable to acquire %s on "
        "AuthOTPTableLock fd %d after %u attempts: %s", lock_type, fd,
        nattempts, strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 9,
    "%s of AuthOTPTableLock fd %d successful after %u %s", lock_type, fd,
    nattempts, nattempts != 1 ? "attempts" : "attempt");
  return 0;
}

int auth_otp_db_rlock(struct auth_otp_db *dbh) {
  int res = 0;

  if (dbh->db_lockfd > 0) {
    dbh->db_lock.l_type = F_RDLCK;
    res = do_lock(dbh->db_lockfd, &dbh->db_lock);
  }

  return res;
}

int auth_otp_db_wlock(struct auth_otp_db *dbh) {
  int res = 0;

  if (dbh->db_lockfd > 0) {
    dbh->db_lock.l_type = F_WRLCK;
    res = do_lock(dbh->db_lockfd, &dbh->db_lock);
  }

  return res;
}

int auth_otp_db_unlock(struct auth_otp_db *dbh) {
  int res = 0;

  if (dbh->db_lockfd > 0) {
    dbh->db_lock.l_type = F_UNLCK;
    res = do_lock(dbh->db_lockfd, &dbh->db_lock);
  }

  return res;
}
