/*
 * ProFTPD: mod_sftp_sql -- SQL backend module for retrieving authorized keys
 * Copyright (c) 2008-2016 TJ Saunders
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
 * This is mod_sftp_sql, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"
#include "mod_sftp.h"
#include "mod_sql.h"

#define MOD_SFTP_SQL_VERSION		"mod_sftp_sql/0.4"

module sftp_sql_module;

#define SFTP_SQL_BUFSZ			1024

struct sqlstore_key {
  const char *subject;

  /* Key data */
  unsigned char *key_data;
  uint32_t key_datalen;
};

struct sqlstore_data {
  const char *select_query;
};

static const char *trace_channel = "ssh2";

static cmd_rec *sqlstore_cmd_create(pool *parent_pool, unsigned int argc, ...) {
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

/* Given a blob of bytes retrieved from a single row, read that blob as if
 * it were text, line by line.
 */
static char *sqlstore_getline(pool *p, char **blob, size_t *bloblen) {
  char linebuf[SFTP_SQL_BUFSZ], *line = "", *data;
  size_t datalen;

  data = *blob;
  datalen = *bloblen;

  if (data == NULL ||
      datalen == 0) {
    errno = EOF;
    return NULL;
  }

  while (data != NULL && datalen > 0) {
    char *ptr;
    size_t delimlen, linelen;
    int have_line_continuation = FALSE;

    pr_signals_handle();

    if (datalen <= 2) {
      line = pstrcat(p, line, data, NULL);

      *blob = NULL;
      *bloblen = 0;

      return line;
    }

    /* Find the CRLF markers in the data. */
    ptr = strstr(data, "\r\n");
    if (ptr != NULL) {
      delimlen = 1;

    } else {
      ptr = strstr(data, "\n");
      if (ptr != NULL) {
        delimlen = 0;
      }
    }

    if (ptr == NULL) {
      /* Just return the rest of the data. */
      line = pstrcat(p, line, data, NULL);

      *blob = NULL;
      *bloblen = 0;

      return line;
    }

    linelen = (ptr - data + 1);

    if (linelen == 1) {
      data += (delimlen + 1);
      datalen -= (delimlen + 1);

      continue;
    }

    /* Watch out for lines larger than our buffer. */
    if (linelen > sizeof(linebuf)) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
        "line of key data (%lu bytes) exceeds buffer size, truncating; "
        "this WILL cause authentication failures", (unsigned long) linelen);
      linelen = sizeof(linebuf);
    }

    memcpy(linebuf, data, linelen);
    linebuf[linelen-1] = '\0';

    data += (linelen + delimlen);
    datalen -= (linelen + delimlen);

    /* Check for continued lines. */
    if (linelen >= 2 &&
        linebuf[linelen-2] == '\\') {
      linebuf[linelen-2] = '\0';
      have_line_continuation = TRUE;
    }

    line = pstrcat(p, line, linebuf, NULL);
    linelen = strlen(line);

    if (have_line_continuation) {
      continue;
    }

    ptr = strchr(line, ':');
    if (ptr != NULL) {
      unsigned int header_taglen, header_valuelen;

      /* We have a header.  Make sure the header tag is not longer than
       * the specified length of 64 bytes, and that the header value is
       * not longer than 1024 bytes.
       */
      header_taglen = ptr - line;
      if (header_taglen > 64) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
          "header tag too long (%u) in retrieved SQL data", header_taglen);
        errno = EINVAL;
        return NULL;
      }

      /* Header value starts at 2 after the ':' (one for the mandatory
       * space character.
       */
      header_valuelen = linelen - (header_taglen + 2);
      if (header_valuelen > 1024) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
          "header value too long (%u) in retrieved SQL data", header_valuelen);
        errno = EINVAL;
        return NULL;
      }
    }

    *blob = data;
    *bloblen = datalen;

    return line;
  }

  return NULL;
}

static struct sqlstore_key *sqlstore_get_key_raw(pool *p, char **blob,
    size_t *bloblen) {
  char chunk[SFTP_SQL_BUFSZ], *data = NULL;
  BIO *bio = NULL, *b64 = NULL, *bmem = NULL;
  int chunklen;
  long datalen = 0;
  struct sqlstore_key *key = NULL;

  bio = BIO_new(BIO_s_mem());

  if (BIO_write(bio, (void *) *blob, *bloblen) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "error buffering base64 data");
  }

  /* Add a base64 filter BIO, and read the data out, thus base64-decoding
   * the key.  Write the decoded data into another memory BIO.
   */
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bio = BIO_push(b64, bio);

  bmem = BIO_new(BIO_s_mem());

  memset(chunk, '\0', sizeof(chunk));
  chunklen = BIO_read(bio, (void *) chunk, sizeof(chunk));

  if (chunklen < 0 &&
      !BIO_should_retry(bio)) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "unable to base64-decode raw key data from database: %s",
      sftp_crypto_get_errors());
    BIO_free_all(bio);
    BIO_free_all(bmem);

    errno = EPERM;
    return NULL;
  }

  while (chunklen > 0) {
    pr_signals_handle();

    if (BIO_write(bmem, (void *) chunk, chunklen) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
        "error writing to memory BIO: %s", sftp_crypto_get_errors());
      BIO_free_all(bio);
      BIO_free_all(bmem);

      errno = EPERM;
      return NULL;
    }

    memset(chunk, '\0', sizeof(chunk));
    chunklen = BIO_read(bio, (void *) chunk, sizeof(chunk));
  }

  datalen = BIO_get_mem_data(bmem, &data);

  if (data != NULL &&
      datalen > 0) {
    key = pcalloc(p, sizeof(struct sqlstore_key));
    key->key_data = pcalloc(p, datalen + 1);
    key->key_datalen = datalen;
    memcpy(key->key_data, data, datalen);

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "error base64-decoding raw key data from database");
  }

  BIO_free_all(bio);
  bio = NULL;

  BIO_free_all(bmem);
  return key;
}

static struct sqlstore_key *sqlstore_get_key_rfc4716(pool *p, char **blob,
    size_t *bloblen) {
  char *line;
  BIO *bio = NULL;
  struct sqlstore_key *key = NULL;
  size_t begin_markerlen = 0, end_markerlen = 0;

  line = sqlstore_getline(p, blob, bloblen);
  while (line == NULL &&
         errno == EINVAL) {
    pr_signals_handle();
    line = sqlstore_getline(p, blob, bloblen);
  }

  if (line == NULL) {
    return NULL;
  }

  begin_markerlen = strlen(SFTP_SSH2_PUBKEY_BEGIN_MARKER);
  end_markerlen = strlen(SFTP_SSH2_PUBKEY_END_MARKER);

  while (line != NULL) {
    pr_signals_handle();

    if (key == NULL &&
        strncmp(line, SFTP_SSH2_PUBKEY_BEGIN_MARKER, begin_markerlen) == 0) {
      key = pcalloc(p, sizeof(struct sqlstore_key));
      bio = BIO_new(BIO_s_mem());

    } else if (key != NULL &&
               strncmp(line, SFTP_SSH2_PUBKEY_END_MARKER, end_markerlen) == 0) {
      if (bio != NULL) {
        char chunk[SFTP_SQL_BUFSZ], *data = NULL;
        BIO *b64 = NULL, *bmem = NULL;
        int chunklen;
        long datalen = 0;

        /* Add a base64 filter BIO, and read the data out, thus base64-decoding
         * the key.  Write the decoded data into another memory BIO.
         */
        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);

        bmem = BIO_new(BIO_s_mem());

        memset(chunk, '\0', sizeof(chunk));
        chunklen = BIO_read(bio, (void *) chunk, sizeof(chunk));

        if (chunklen < 0 &&
            !BIO_should_retry(bio)) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
            "unable to base64-decode RFC4716 key data from database: %s",
          sftp_crypto_get_errors());
          BIO_free_all(bio);
          BIO_free_all(bmem);

          errno = EPERM;
          return NULL;
        }

        while (chunklen > 0) {
          pr_signals_handle();

          if (BIO_write(bmem, (void *) chunk, chunklen) < 0) {
            (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
              "error writing to memory BIO: %s", sftp_crypto_get_errors());
            BIO_free_all(bio);
            BIO_free_all(bmem);

            errno = EPERM;
            return NULL;
          }

          memset(chunk, '\0', sizeof(chunk));
          chunklen = BIO_read(bio, (void *) chunk, sizeof(chunk));
        }

        datalen = BIO_get_mem_data(bmem, &data);

        if (data != NULL &&
            datalen > 0) {
          key = pcalloc(p, sizeof(struct sqlstore_key));
          key->key_data = pcalloc(p, datalen + 1);
          key->key_datalen = datalen;
          memcpy(key->key_data, data, datalen);

        } else {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
            "error base64-decoding RFC4716 key data from database");
        }

        BIO_free_all(bio);
        bio = NULL;

        BIO_free_all(bmem);
      }

      break;

    } else {
      if (key) {
        if (strstr(line, ": ") != NULL) {
          if (strncasecmp(line, "Subject: ", 9) == 0) {
            key->subject = pstrdup(p, line + 9);
          }

        } else {
          if (BIO_write(bio, line, strlen(line)) < 0) {
            (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
              "error buffering base64 data");
          }
        }
      }
    }

    line = sqlstore_getline(p, blob, bloblen);
    while (line == NULL &&
           errno == EINVAL) {
      pr_signals_handle();
      line = sqlstore_getline(p, blob, bloblen);
    }
  }

  return key;
}

static char *sqlstore_get_str(pool *p, char *str) {
  cmdtable *cmdtab;
  cmd_rec *cmd;
  modret_t *res;

  if (strlen(str) == 0)
    return str;

  /* Find the cmdtable for the sql_escapestr command. */
  cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_escapestr", NULL, NULL, NULL);
  if (cmdtab == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "unable to find SQL hook symbol 'sql_escapestr'");
    return str;
  }

  cmd = sqlstore_cmd_create(p, 1, pr_str_strip(p, str));

  /* Call the handler. */
  res = pr_module_call(cmdtab->m, cmdtab->handler, cmd);

  /* Check the results. */
  if (MODRET_ISERROR(res)) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "error executing 'sql_escapestring'");
    return str;
  }

  return res->data;
}

static int sqlstore_verify_key_raw(pool *p, struct sqlstore_data *store_data,
    int nrow, char *col_data, size_t col_datalen, unsigned char *key_data,
    uint32_t key_datalen) {
  struct sqlstore_key *key;
  int res;

  key = sqlstore_get_key_raw(p, &col_data, &col_datalen);
  if (key == NULL) {
    pr_trace_msg(trace_channel, 10,
      "unable to parse data (row %u) as raw data", nrow+1);
    return -1;
  }

  res = sftp_keys_compare_keys(p, key_data, key_datalen, key->key_data,
    key->key_datalen);
  if (res < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "error comparing client-sent host key with SQL data (row %u) from "
      "SQLNamedQuery '%s': %s", nrow+1, store_data->select_query,
      strerror(errno));

  } else if (res == FALSE) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "client-sent host key does not match SQL data (row %u) from "
      "SQLNamedQuery '%s'", nrow+1, store_data->select_query);
    res = -1;

  } else {
    res = 0;
  }

  return res;
}

static int sqlstore_verify_key_rfc4716(pool *p,
    struct sqlstore_data *store_data, int nrow, char *col_data,
    size_t col_datalen, unsigned char *key_data, uint32_t key_datalen) {
  struct sqlstore_key *key;
  int res;

  key = sqlstore_get_key_rfc4716(p, &col_data, &col_datalen);
  while (key != NULL) {
    pr_signals_handle();

    res = sftp_keys_compare_keys(p, key_data, key_datalen, key->key_data,
      key->key_datalen);
    if (res < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
        "error comparing client-sent key with SQL data (row %u) from "
        "SQLNamedQuery '%s': %s", nrow+1, store_data->select_query,
        strerror(errno));
      key = sqlstore_get_key_rfc4716(p, &col_data, &col_datalen);
      continue;

    } else if (res == FALSE) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
        "client-sent key does not match SQL data (row %u) from "
        "SQLNamedQuery '%s'", nrow+1, store_data->select_query);
      key = sqlstore_get_key_rfc4716(p, &col_data, &col_datalen);
      continue;
    }

    return 0;
  }

  return -1;
}

static int sqlstore_verify_host_key(sftp_keystore_t *store, pool *p,
    const char *user, const char *host_fqdn, const char *host_user,
    unsigned char *key_data, uint32_t key_datalen) {
  register unsigned int i;
  struct sqlstore_data *store_data;
  pool *tmp_pool;
  cmdtable *sql_cmdtab;
  cmd_rec *sql_cmd;
  modret_t *sql_res;
  array_header *sql_data;
  char **values;
  int res;

  store_data = store->keystore_data;

  /* Find the cmdtable for the sql_lookup command. */
  sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_lookup", NULL, NULL,
    NULL);
  if (sql_cmdtab == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "unable to find SQL hook symbol 'sql_lookup'");
    errno = EPERM;
    return -1;
  }

  tmp_pool = make_sub_pool(store->keystore_pool);

  /* Prepare the SELECT query. */
  sql_cmd = sqlstore_cmd_create(tmp_pool, 3, "sql_lookup",
    store_data->select_query, sqlstore_get_str(tmp_pool, (char *) host_fqdn));

  /* Call the handler. */
  sql_res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, sql_cmd);
  if (sql_res == NULL ||
      MODRET_ISERROR(sql_res)) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "error processing SQLNamedQuery '%s'", store_data->select_query);
    destroy_pool(tmp_pool);

    errno = EPERM;
    return -1;
  }

  sql_data = (array_header *) sql_res->data;

  if (sql_data->nelts == 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "SQLNamedQuery '%s' returned zero results", store_data->select_query);
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return -1;

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "SQLNamedQuery '%s' returned %d %s", store_data->select_query,
      sql_data->nelts, sql_data->nelts != 1 ? "rows" : "row");
  }

  values = (char **) sql_data->elts;
  for (i = 0; i < sql_data->nelts; i++) {
    char *col_data;
    size_t col_datalen;

    pr_signals_handle();

    col_data = values[i];
    col_datalen = strlen(values[i]);

    res = sqlstore_verify_key_rfc4716(p, store_data, i, col_data, col_datalen,
      key_data, key_datalen);
    if (res == 0) {
      pr_trace_msg(trace_channel, 10, "found matching RFC4716 public key "
        "(row %u) for host '%s' using SQLNamedQuery '%s'", i+1, host_fqdn,
        store_data->select_query);
      destroy_pool(tmp_pool);
      return 0;
    }

    res = sqlstore_verify_key_raw(p, store_data, i, col_data, col_datalen,
      key_data, key_datalen);
    if (res == 0) {
      pr_trace_msg(trace_channel, 10, "found matching public key (row %u) for "
        "host '%s' using SQLNamedQuery '%s'", i+1, host_fqdn,
        store_data->select_query);
      destroy_pool(tmp_pool);
      return 0;
    }
  }

  destroy_pool(tmp_pool);
  errno = ENOENT;
  return -1;
}

static int sqlstore_verify_user_key(sftp_keystore_t *store, pool *p,
    const char *user, unsigned char *key_data, uint32_t key_datalen) {
  register unsigned int i;
  struct sqlstore_data *store_data;
  pool *tmp_pool;
  cmdtable *sql_cmdtab;
  cmd_rec *sql_cmd;
  modret_t *sql_res;
  array_header *sql_data;
  char **values;
  int res;

  store_data = store->keystore_data;

  /* Find the cmdtable for the sql_lookup command. */
  sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_lookup", NULL, NULL,
    NULL);
  if (sql_cmdtab == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "unable to find SQL hook symbol 'sql_lookup'");
    errno = EPERM;
    return -1;
  }

  tmp_pool = make_sub_pool(store->keystore_pool);

  /* Prepare the SELECT query. */
  sql_cmd = sqlstore_cmd_create(tmp_pool, 3, "sql_lookup",
    store_data->select_query, sqlstore_get_str(tmp_pool, (char *) user));

  /* Call the handler. */
  sql_res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, sql_cmd);
  if (sql_res == NULL ||
      MODRET_ISERROR(sql_res)) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "error processing SQLNamedQuery '%s'", store_data->select_query);
    destroy_pool(tmp_pool);

    errno = EPERM;
    return -1;
  }

  sql_data = (array_header *) sql_res->data;

  if (sql_data->nelts == 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "SQLNamedQuery '%s' returned zero results", store_data->select_query);
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return -1;

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "SQLNamedQuery '%s' returned %d %s", store_data->select_query,
      sql_data->nelts, sql_data->nelts != 1 ? "rows" : "row");
  }

  values = (char **) sql_data->elts;
  for (i = 0; i < sql_data->nelts; i++) {
    char *col_data;
    size_t col_datalen;

    pr_signals_handle();

    col_data = values[i];
    col_datalen = strlen(values[i]);

    res = sqlstore_verify_key_rfc4716(p, store_data, i, col_data, col_datalen,
      key_data, key_datalen);
    if (res == 0) {
      pr_trace_msg(trace_channel, 10, "found matching RFC4716 public key "
        "(row %u) for user '%s' using SQLNamedQuery '%s'", i+1, user,
        store_data->select_query);
      destroy_pool(tmp_pool);
      return 0;
    }

    res = sqlstore_verify_key_raw(p, store_data, i, col_data, col_datalen,
      key_data, key_datalen);
    if (res == 0) {
      pr_trace_msg(trace_channel, 10, "found matching public key (row %u) for "
        "user '%s' using SQLNamedQuery '%s'", i+1, user,
        store_data->select_query);
      destroy_pool(tmp_pool);
      return 0;
    }
  }

  destroy_pool(tmp_pool);
  errno = ENOENT;
  return -1;
}

static int sqlstore_close(sftp_keystore_t *store) {
  /* Nothing really to do here. */
  return 0;
}

static sftp_keystore_t *sqlstore_open(pool *parent_pool,
    int requested_key_type, const char *store_info, const char *user) {
  sftp_keystore_t *store;
  pool *sqlstore_pool, *tmp_pool;
  struct sqlstore_data *store_data;
  char *named_query, *select_query, *ptr;
  config_rec *c;

  tmp_pool = make_sub_pool(parent_pool);

  sqlstore_pool = make_sub_pool(parent_pool);
  pr_pool_tag(sqlstore_pool, "SFTP SQL-based Keystore Pool");

  store = pcalloc(sqlstore_pool, sizeof(sftp_keystore_t));
  store->keystore_pool = sqlstore_pool;
  store->store_ktypes = requested_key_type;

  switch (requested_key_type) {
    case SFTP_SSH2_HOST_KEY_STORE:
      store->verify_host_key = sqlstore_verify_host_key;
      break;

    case SFTP_SSH2_USER_KEY_STORE:
      store->verify_user_key = sqlstore_verify_user_key;
      break;
  }

  store->store_close = sqlstore_close;

  /* Parse the SELECT query name out of the store_info string:
   *
   *  "/<select-named-query"
   */
  ptr = strchr(store_info, '/');
  if (ptr == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_SQL_VERSION,
      "badly formatted store info '%s'", store_info);
    destroy_pool(tmp_pool);

    errno = EINVAL;
    return NULL;
  }

  ptr++;
  select_query = pstrdup(sqlstore_pool, ptr);

  /* Verify that the named query has indeed been configured.  This is based
   * on how mod_sql creates its config_rec names.
   */
  named_query = pstrcat(tmp_pool, "SQLNamedQuery_", select_query, NULL);

  c = find_config(main_server->conf, CONF_PARAM, named_query, FALSE);
  if (c == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unable to resolve SQLNamedQuery '%s'", select_query);
    destroy_pool(tmp_pool);

    errno = EINVAL;
    return NULL;
  }

  store_data = pcalloc(sqlstore_pool, sizeof(struct sqlstore_data));
  store->keystore_data = store_data;
  store_data->select_query = pstrdup(sqlstore_pool, select_query);

  destroy_pool(tmp_pool);
  return store;
}

/* Event Handlers
 */

#if defined(PR_SHARED_MODULE)
static void sftpsql_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_sftp_sql.c", (const char *) event_data) == 0) {
    /* XXX any further cleanup here */

    sftp_keystore_unregister_store("sql",
      SFTP_SSH2_HOST_KEY_STORE|SFTP_SSH2_USER_KEY_STORE);
    pr_event_unregister(&sftp_sql_module, NULL, NULL);
  }
}
#endif /* !PR_SHARED_MODULE */

/* Initialization functions
 */

static int sftpsql_init(void) {

  sftp_keystore_register_store("sql", sqlstore_open,
    SFTP_SSH2_HOST_KEY_STORE|SFTP_SSH2_USER_KEY_STORE);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&sftp_sql_module, "core.module-unload",
    sftpsql_mod_unload_ev, NULL);
#endif /* !PR_SHARED_MODULE */

  return 0;
}

module sftp_sql_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "sftp_sql",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  sftpsql_init,

  /* Session initialization function */
  NULL,

  /* Module version */
  MOD_SFTP_SQL_VERSION
};
