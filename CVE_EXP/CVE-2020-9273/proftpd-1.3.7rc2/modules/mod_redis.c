/*
 * ProFTPD: mod_redis -- a module for managing Redis data
 * Copyright (c) 2017 The ProFTPD Project
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
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Libraries: -lhiredis$
 */

#include "conf.h"
#include "privs.h"
#include "logfmt.h"
#include "json.h"
#include "jot.h"

#define MOD_REDIS_VERSION		"mod_redis/0.2.2"

#if PROFTPD_VERSION_NUMBER < 0x0001030605
# error "ProFTPD 1.3.6rc5 or later required"
#endif

#include <hiredis/hiredis.h>

extern xaset_t *server_list;

module redis_module;

#define REDIS_SERVER_DEFAULT_PORT		6379
#define REDIS_SENTINEL_DEFAULT_PORT		26379

static int redis_engine = FALSE;
static int redis_logfd = -1;
static unsigned long redis_opts = 0UL;
static pool *redis_pool = NULL;

static int redis_sess_init(void);

static pr_table_t *jot_logfmt2json = NULL;
static const char *trace_channel = "redis";

/* TODO: Refactor this into a pr_jot_resolved_t structure, with shared/common
 * resolver callbacks, similar to the shared parser callbacks.
 */

struct redis_buffer {
  char *ptr, *buf;
  size_t bufsz, buflen;
};

static void redis_buffer_append_text(struct redis_buffer *log, const char *text,
    size_t text_len) {
  if (text == NULL ||
      text_len == 0) {
    return;
  }

  if (text_len > log->buflen) {
    text_len = log->buflen;
  }

  pr_trace_msg(trace_channel, 19, "appending text '%.*s' (%lu) to buffer",
    (int) text_len, text, (unsigned long) text_len);
  memcpy(log->buf, text, text_len);
  log->buf += text_len;
  log->buflen -= text_len;
}

static int resolve_on_meta(pool *p, pr_jot_ctx_t *jot_ctx,
    unsigned char logfmt_id, const char *jot_hint, const void *val) {
  struct redis_buffer *log;

  log = jot_ctx->log;
  if (log->buflen > 0) {
    const char *text = NULL;
    size_t text_len = 0;
    char buf[1024];

    switch (logfmt_id) {
      case LOGFMT_META_MICROSECS: {
        unsigned long num;

        num = *((double *) val);
        text_len = pr_snprintf(buf, sizeof(buf)-1, "%06lu", num);
        buf[text_len] = '\0';
        text = buf;
        break;
      }

      case LOGFMT_META_MILLISECS: {
        unsigned long num;

        num = *((double *) val);
        text_len = pr_snprintf(buf, sizeof(buf)-1, "%03lu", num);
        buf[text_len] = '\0';
        text = buf;
        break;
      }

      case LOGFMT_META_LOCAL_PORT:
      case LOGFMT_META_REMOTE_PORT:
      case LOGFMT_META_RESPONSE_CODE: {
        int num;

        num = *((double *) val);
        text_len = pr_snprintf(buf, sizeof(buf)-1, "%d", num);
        buf[text_len] = '\0';
        text = buf;
        break;
      }

      case LOGFMT_META_UID: {
        uid_t uid;

        uid = *((double *) val);
        text = pr_uid2str(p, uid);
        break;
      }

      case LOGFMT_META_GID: {
        gid_t gid;

        gid = *((double *) val);
        text = pr_gid2str(p, gid);
        break;
      }

      case LOGFMT_META_BYTES_SENT:
      case LOGFMT_META_FILE_OFFSET:
      case LOGFMT_META_FILE_SIZE:
      case LOGFMT_META_RAW_BYTES_IN:
      case LOGFMT_META_RAW_BYTES_OUT:
      case LOGFMT_META_RESPONSE_MS:
      case LOGFMT_META_XFER_MS: {
        off_t num;

        num = *((double *) val);
        text_len = pr_snprintf(buf, sizeof(buf)-1, "%" PR_LU, (pr_off_t) num);
        buf[text_len] = '\0';
        text = buf;
        break;
      }

      case LOGFMT_META_EPOCH:
      case LOGFMT_META_PID: {
        unsigned long num;

        num = *((double *) val);
        text_len = pr_snprintf(buf, sizeof(buf)-1, "%lu", num);
        buf[text_len] = '\0';
        text = buf;
        break;
      }

      case LOGFMT_META_FILE_MODIFIED: {
        int truth;

        truth = *((int *) val);
        text = truth ? "true" : "false";
        break;
      }

      case LOGFMT_META_SECONDS: {
        float num;

        num = *((double *) val);
        text_len = pr_snprintf(buf, sizeof(buf)-1, "%0.3f", num);
        buf[text_len] = '\0';
        text = buf;
        break;
      }

      case LOGFMT_META_ANON_PASS:
      case LOGFMT_META_BASENAME:
      case LOGFMT_META_CLASS:
      case LOGFMT_META_CMD_PARAMS:
      case LOGFMT_META_COMMAND:
      case LOGFMT_META_DIR_NAME:
      case LOGFMT_META_DIR_PATH:
      case LOGFMT_META_ENV_VAR:
      case LOGFMT_META_EOS_REASON:
      case LOGFMT_META_FILENAME:
      case LOGFMT_META_GROUP:
      case LOGFMT_META_IDENT_USER:
      case LOGFMT_META_ISO8601:
      case LOGFMT_META_LOCAL_FQDN:
      case LOGFMT_META_LOCAL_IP:
      case LOGFMT_META_LOCAL_NAME:
      case LOGFMT_META_METHOD:
      case LOGFMT_META_NOTE_VAR:
      case LOGFMT_META_ORIGINAL_USER:
      case LOGFMT_META_PROTOCOL:
      case LOGFMT_META_REMOTE_HOST:
      case LOGFMT_META_REMOTE_IP:
      case LOGFMT_META_RENAME_FROM:
      case LOGFMT_META_RESPONSE_STR:
      case LOGFMT_META_TIME:
      case LOGFMT_META_USER:
      case LOGFMT_META_VERSION:
      case LOGFMT_META_VHOST_IP:
      case LOGFMT_META_XFER_FAILURE:
      case LOGFMT_META_XFER_PATH:
      case LOGFMT_META_XFER_STATUS:
      case LOGFMT_META_XFER_TYPE:
      default:
        text = val;
    }

    if (text != NULL &&
        text_len == 0) {
      text_len = strlen(text);
    }

    redis_buffer_append_text(log, text, text_len);
  }

  return 0;
}

static int resolve_on_other(pool *p, pr_jot_ctx_t *jot_ctx, unsigned char *text,
    size_t text_len) {
  struct redis_buffer *log;

  log = jot_ctx->log;
  redis_buffer_append_text(log, (const char *) text, text_len);
  return 0;
}

static void log_event(pr_redis_t *redis, config_rec *c, cmd_rec *cmd) {
  pool *tmp_pool;
  int res;
  pr_jot_ctx_t *jot_ctx;
  pr_jot_filters_t *jot_filters;
  pr_json_object_t *json;
  const char *fmt_name = NULL;
  char *payload = NULL;
  size_t payload_len = 0;
  unsigned char *log_fmt, *key_fmt;

  jot_filters = c->argv[0];
  fmt_name = c->argv[1];
  log_fmt = c->argv[2];
  key_fmt = c->argv[3];

  if (jot_filters == NULL ||
      fmt_name == NULL ||
      log_fmt == NULL) {
    return;
  }

  tmp_pool = make_sub_pool(cmd->tmp_pool);
  jot_ctx = pcalloc(tmp_pool, sizeof(pr_jot_ctx_t));
  json = pr_json_object_alloc(tmp_pool);
  jot_ctx->log = json;
  jot_ctx->user_data = jot_logfmt2json;

  res = pr_jot_resolve_logfmt(tmp_pool, cmd, jot_filters, log_fmt, jot_ctx,
    pr_jot_on_json, NULL, NULL);
  if (res == 0) {
    payload = pr_json_object_to_text(tmp_pool, json, "");
    payload_len = strlen(payload);
    pr_trace_msg(trace_channel, 8, "generated JSON payload for %s: %.*s",
      (char *) cmd->argv[0], (int) payload_len, payload);

  } else {
    /* EPERM indicates that the message was filtered. */
    if (errno != EPERM) {
      (void) pr_log_writefile(redis_logfd, MOD_REDIS_VERSION,
        "error generating JSON formatted log message: %s", strerror(errno));
    }

    payload = NULL;
    payload_len = 0;
  }

  pr_json_object_free(json);

  if (payload_len > 0) {
    const char *key;

    if (key_fmt != NULL) {
      struct redis_buffer *rb;
      char key_buf[1024];

      rb = pcalloc(tmp_pool, sizeof(struct redis_buffer));
      rb->bufsz = rb->buflen = sizeof(key_buf)-1;
      rb->ptr = rb->buf = key_buf;

      jot_ctx->log = rb;

      res = pr_jot_resolve_logfmt(tmp_pool, cmd, NULL, key_fmt, jot_ctx,
        resolve_on_meta, NULL, resolve_on_other);
      if (res == 0) {
        size_t key_buflen;

        key_buflen = rb->bufsz - rb->buflen;
        key = pstrndup(tmp_pool, key_buf, key_buflen);

      } else {
        (void) pr_log_writefile(redis_logfd, MOD_REDIS_VERSION,
          "error resolving Redis key format: %s", strerror(errno));
        key = fmt_name;
      }

    } else {
      key = fmt_name;
    }

    res = pr_redis_list_append(redis, &redis_module, key, payload,
      payload_len);
    if (res < 0) {
      (void) pr_log_writefile(redis_logfd, MOD_REDIS_VERSION,
        "error appending log message to '%s': %s", key, strerror(errno));

    } else {
      pr_trace_msg(trace_channel, 17, "appended log message to '%s'", key);
    }
  }

  destroy_pool(tmp_pool);
}

static void log_events(cmd_rec *cmd) {
  pr_redis_t *redis;
  config_rec *c;

  redis = pr_redis_conn_get(session.pool, redis_opts);
  if (redis == NULL) {
    (void) pr_log_writefile(redis_logfd, MOD_REDIS_VERSION,
      "error connecting to Redis: %s", strerror(errno));
    return;
  }

  c = find_config(CURRENT_CONF, CONF_PARAM, "RedisLogOnCommand", FALSE);
  while (c != NULL) {
    pr_signals_handle();

    log_event(redis, c, cmd);
    c = find_config_next(c, c->next, CONF_PARAM, "RedisLogOnCommand", FALSE);
  }

  c = find_config(CURRENT_CONF, CONF_PARAM, "RedisLogOnEvent", FALSE);
  while (c != NULL) {
    pr_signals_handle();

    log_event(redis, c, cmd);
    c = find_config_next(c, c->next, CONF_PARAM, "RedisLogOnEvent", FALSE);
  }
}

/* Configuration handlers
 */

/* usage: RedisEngine on|off */
MODRET set_redisengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: RedisLog path|"none" */
MODRET set_redislog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "none") != 0 &&
      pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: RedisLogOnCommand "none"|commands log-fmt [key] */
MODRET set_redislogoncommand(cmd_rec *cmd) {
  config_rec *c, *logfmt_config;
  const char *fmt_name, *rules;
  unsigned char *log_fmt = NULL, *key_fmt = NULL;
  pr_jot_filters_t *jot_filters;

  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_VIRTUAL|CONF_ANON|CONF_DIR);

  if (cmd->argc < 3 ||
      cmd->argc > 4) {

    if (cmd->argc == 2 &&
        strcasecmp(cmd->argv[1], "none") == 0) {
       c = add_config_param(cmd->argv[0], 4, NULL, NULL, NULL, NULL);
       c->flags |= CF_MERGEDOWN;
       return PR_HANDLED(cmd);
    }

    CONF_ERROR(cmd, "wrong number of parameters");
  }

  c = add_config_param(cmd->argv[0], 4, NULL, NULL, NULL, NULL);

  rules = cmd->argv[1];
  jot_filters = pr_jot_filters_create(c->pool, rules,
    PR_JOT_FILTER_TYPE_COMMANDS, 0);
  if (jot_filters == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to use commands '", rules,
      "': ", strerror(errno), NULL));
  }

  fmt_name = cmd->argv[2];

  /* Make sure that the given LogFormat name is known. */
  logfmt_config = find_config(cmd->server->conf, CONF_PARAM, "LogFormat",
    FALSE);
  while (logfmt_config != NULL) {
    pr_signals_handle();

    if (strcmp(fmt_name, logfmt_config->argv[0]) == 0) {
      log_fmt = logfmt_config->argv[1];
      break;
    }

    logfmt_config = find_config_next(logfmt_config, logfmt_config->next,
      CONF_PARAM, "LogFormat", FALSE);
  }

  if (log_fmt == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "no LogFormat '", fmt_name,
      "' configured", NULL));
  }

  if (cmd->argc == 4) {
    int res;
    pool *tmp_pool;
    pr_jot_ctx_t *jot_ctx;
    pr_jot_parsed_t *jot_parsed;
    char *key_text;
    unsigned char key_fmtbuf[1024];
    size_t key_fmtlen;

    tmp_pool = make_sub_pool(cmd->tmp_pool);
    jot_ctx = pcalloc(tmp_pool, sizeof(pr_jot_ctx_t));
    jot_parsed = pcalloc(tmp_pool, sizeof(pr_jot_parsed_t));
    jot_parsed->bufsz = jot_parsed->buflen = sizeof(key_fmtbuf)-1;
    jot_parsed->ptr = jot_parsed->buf = key_fmtbuf;

    jot_ctx->log = jot_parsed;

    key_text = cmd->argv[3];
    res = pr_jot_parse_logfmt(tmp_pool, key_text, jot_ctx,
      pr_jot_parse_on_meta, pr_jot_parse_on_unknown, pr_jot_parse_on_other, 0);
    if (res < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing Redis key '",
        key_text, "': ", strerror(errno), NULL));
    }

    destroy_pool(tmp_pool);

    key_fmtlen = jot_parsed->bufsz - jot_parsed->buflen;
    key_fmtbuf[key_fmtlen] = '\0';
    key_fmt = (unsigned char *) pstrndup(c->pool, (char *) key_fmtbuf,
      key_fmtlen);
  }

  c->argv[0] = jot_filters;
  c->argv[1] = pstrdup(c->pool, fmt_name);
  c->argv[2] = log_fmt;
  c->argv[3] = key_fmt;

  c->flags |= CF_MERGEDOWN_MULTI;
  return PR_HANDLED(cmd);
}

/* usage: RedisLogOnEvent "none"|events log-fmt [key] */
MODRET set_redislogonevent(cmd_rec *cmd) {
  config_rec *c, *logfmt_config;
  const char *fmt_name, *rules;
  unsigned char *log_fmt = NULL, *key_fmt = NULL;
  pr_jot_filters_t *jot_filters;

  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_VIRTUAL|CONF_ANON|CONF_DIR);

  if (cmd->argc < 3 ||
      cmd->argc > 4) {

    if (cmd->argc == 2 &&
        strcasecmp(cmd->argv[1], "none") == 0) {
       c = add_config_param(cmd->argv[0], 4, NULL, NULL, NULL, NULL);
       c->flags |= CF_MERGEDOWN;
       return PR_HANDLED(cmd);
    }

    CONF_ERROR(cmd, "wrong number of parameters");
  }

  c = add_config_param(cmd->argv[0], 4, NULL, NULL, NULL, NULL);

  rules = cmd->argv[1];
  jot_filters = pr_jot_filters_create(c->pool, rules,
    PR_JOT_FILTER_TYPE_COMMANDS_WITH_CLASSES,
    PR_JOT_FILTER_FL_ALL_INCL_ALL);
  if (jot_filters == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to use events '", rules,
      "': ", strerror(errno), NULL));
  }

  fmt_name = cmd->argv[2];

  /* Make sure that the given LogFormat name is known. */
  logfmt_config = find_config(cmd->server->conf, CONF_PARAM, "LogFormat",
    FALSE);
  while (logfmt_config != NULL) {
    pr_signals_handle();

    if (strcmp(fmt_name, logfmt_config->argv[0]) == 0) {
      log_fmt = logfmt_config->argv[1];
      break;
    }

    logfmt_config = find_config_next(logfmt_config, logfmt_config->next,
      CONF_PARAM, "LogFormat", FALSE);
  }

  if (log_fmt == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "no LogFormat '", fmt_name,
      "' configured", NULL));
  }

  if (cmd->argc == 4) {
    int res;
    pool *tmp_pool;
    pr_jot_ctx_t *jot_ctx;
    pr_jot_parsed_t *jot_parsed;
    char *key_text;
    unsigned char key_fmtbuf[1024];
    size_t key_fmtlen;

    tmp_pool = make_sub_pool(cmd->tmp_pool);
    jot_ctx = pcalloc(tmp_pool, sizeof(pr_jot_ctx_t));
    jot_parsed = pcalloc(tmp_pool, sizeof(pr_jot_parsed_t));
    jot_parsed->bufsz = jot_parsed->buflen = sizeof(key_fmtbuf)-1;
    jot_parsed->ptr = jot_parsed->buf = key_fmtbuf;

    jot_ctx->log = jot_parsed;

    key_text = cmd->argv[3];
    res = pr_jot_parse_logfmt(tmp_pool, key_text, jot_ctx,
      pr_jot_parse_on_meta, pr_jot_parse_on_unknown, pr_jot_parse_on_other, 0);
    if (res < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing Redis key '",
        key_text, "': ", strerror(errno), NULL));
    }

    destroy_pool(tmp_pool);

    key_fmtlen = jot_parsed->bufsz - jot_parsed->buflen;
    key_fmtbuf[key_fmtlen] = '\0';
    key_fmt = (unsigned char *) pstrndup(c->pool, (char *) key_fmtbuf,
      key_fmtlen);
  }

  c->argv[0] = jot_filters;
  c->argv[1] = pstrdup(c->pool, fmt_name);
  c->argv[2] = log_fmt;
  c->argv[3] = key_fmt;

  c->flags |= CF_MERGEDOWN_MULTI;
  return PR_HANDLED(cmd);
}

/* usage: RedisOptions opt1 opt2 ... */
MODRET set_redisoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "NoReconnect") == 0) {
      opts |= PR_REDIS_CONN_FL_NO_RECONNECT;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown RedisOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: RedisSentinel host[:port] ... [master name] */
MODRET set_redissentinel(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  array_header *sentinels;
  char *master_name = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (cmd->argc >= 4) {
    /* Has the name of a master been explicitly provided? */
    if (strcasecmp(cmd->argv[cmd->argc-2], "master") == 0) {
      master_name = cmd->argv[cmd->argc-1];

      cmd->argc -= 2;
    }
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  sentinels = make_array(c->pool, 0, sizeof(pr_netaddr_t *));

  for (i = 1; i < cmd->argc; i++) {
    char *sentinel, *ptr;
    size_t sentinel_len;
    int port = REDIS_SENTINEL_DEFAULT_PORT;
    pr_netaddr_t *sentinel_addr;

    sentinel = pstrdup(cmd->tmp_pool, cmd->argv[i]);
    sentinel_len = strlen(sentinel);

    ptr = strrchr(sentinel, ':');
    if (ptr != NULL) {
      /* We also need to check for IPv6 addresses, e.g. "[::1]" or
       * "[::1]:26379", before assuming that the text following our discovered
       * ':' is indeed a port number.
       */
      if (*sentinel == '[') {
        if (*(ptr-1) == ']') {
          /* We have an IPv6 address with an explicit port number. */
          sentinel = pstrndup(cmd->tmp_pool, sentinel + 1,
            (ptr - 1) - (sentinel + 1));
          *ptr = '\0';
          port = atoi(ptr + 1);

        } else if (sentinel[sentinel_len-1] == ']') {
          /* We have an IPv6 address without an explicit port number. */
          sentinel = pstrndup(cmd->tmp_pool, sentinel + 1, sentinel_len - 2);
          port = REDIS_SENTINEL_DEFAULT_PORT;
        }

      } else {
        *ptr = '\0';
        port = atoi(ptr + 1);
      }
    }

    sentinel_addr = (pr_netaddr_t *) pr_netaddr_get_addr(c->pool, sentinel,
      NULL);
    if (sentinel_addr != NULL) {
      pr_netaddr_set_port2(sentinel_addr, port);
      *((pr_netaddr_t **) push_array(sentinels)) = sentinel_addr;

    } else {
      pr_log_debug(DEBUG0, "%s: unable to resolve '%s' (%s), ignoring",
        (char *) cmd->argv[0], sentinel, strerror(errno));
    }
  }

  c->argv[0] = sentinels;
  c->argv[1] = pstrdup(c->pool, master_name);

  return PR_HANDLED(cmd);
}

/* usage: RedisServer host[:port] [password] [db-index] */
MODRET set_redisserver(cmd_rec *cmd) {
  config_rec *c;
  char *server, *password = NULL, *db_idx = NULL, *ptr;
  size_t server_len;
  int ctx, port = REDIS_SERVER_DEFAULT_PORT;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  server = pstrdup(cmd->tmp_pool, cmd->argv[1]);
  server_len = strlen(server);

  ptr = strrchr(server, ':');
  if (ptr != NULL) {
    /* We also need to check for IPv6 addresses, e.g. "[::1]" or "[::1]:6379",
     * before assuming that the text following our discovered ':' is indeed
     * a port number.
     */

    if (*server == '[') {
      if (*(ptr-1) == ']') {
        /* We have an IPv6 address with an explicit port number. */
        server = pstrndup(cmd->tmp_pool, server + 1, (ptr - 1) - (server + 1));
        *ptr = '\0';
        port = atoi(ptr + 1);

      } else if (server[server_len-1] == ']') {
        /* We have an IPv6 address without an explicit port number. */
        server = pstrndup(cmd->tmp_pool, server + 1, server_len - 2);
        port = REDIS_SERVER_DEFAULT_PORT;
      }

    } else {
      *ptr = '\0';
      port = atoi(ptr + 1);
    }
  }

  if (cmd->argc == 3) {
    password = cmd->argv[2];
    if (strcmp(password, "") == 0) {
      password = NULL;
    }
  }

  if (cmd->argc == 4) {
    db_idx = cmd->argv[3];
    if (strcmp(db_idx, "") == 0) {
      db_idx = NULL;
    }
  }

  c = add_config_param(cmd->argv[0], 4, NULL, NULL, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, server);
  c->argv[1] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = port;
  c->argv[2] = pstrdup(c->pool, password);
  c->argv[3] = pstrdup(c->pool, db_idx);

  ctx = (cmd->config && cmd->config->config_type != CONF_PARAM ?
    cmd->config->config_type : cmd->server->config_type ?
    cmd->server->config_type : CONF_ROOT);

  if (ctx == CONF_ROOT) {
    /* If we're the "server config" context, set the server now.  This
     * would let mod_redis talk to those servers for e.g. ftpdctl actions.
     */
    (void) redis_set_server(c->argv[0], port, 0UL, c->argv[2], c->argv[3]);
  }

  return PR_HANDLED(cmd);
}

/* usage: RedisTimeouts conn-timeout io-timeout */
MODRET set_redistimeouts(cmd_rec *cmd) {
  config_rec *c;
  unsigned long connect_millis, io_millis;
  char *ptr = NULL;

  CHECK_ARGS(cmd, 2);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  connect_millis = strtoul(cmd->argv[1], &ptr, 10);
  if (ptr && *ptr) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "badly formatted connect timeout value: ", cmd->argv[1], NULL));
  }

  ptr = NULL;
  io_millis = strtoul(cmd->argv[2], &ptr, 10);
  if (ptr && *ptr) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "badly formatted IO timeout value: ", cmd->argv[2], NULL));
  }

#if 0
  /* XXX If we're the "server config" context, set the timeouts now.
   * This would let mod_redis talk to those servers for e.g. ftpdctl
   * actions.
   */
  redis_set_timeouts(conn_timeout, io_timeout);
#endif

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = connect_millis;
  c->argv[1] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[1]) = io_millis;

  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET redis_log_any(cmd_rec *cmd) {
  if (redis_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  log_events(cmd);
  return PR_DECLINED(cmd);
}

static int is_redis_log_config(config_rec *c, const char *name, size_t namelen,
    unsigned int config_id) {
  int matched = FALSE;

  if (c->config_type == CONF_PARAM &&
      c->argc == 4 &&
      c->config_id == config_id &&
      strncmp(name, c->name, namelen + 1) == 0) {
    matched = TRUE;
  }

  return matched;
}

static int prune_redis_log_config(pool *p, xaset_t *set, const char *name,
    size_t namelen, unsigned int config_id) {
  config_rec *c;
  int needs_pruning = FALSE, pruned = FALSE;

  /* Bottom up pruning; handle subsets first. */
  for (c = (config_rec *) set->xas_list; c; c = c->next) {
    pr_signals_handle();

    if (c->subset == NULL) {
      continue;
    }

    if (prune_redis_log_config(p, c->subset, name, namelen,
        config_id) == TRUE) {
      pruned = TRUE;
    }
  }

  /* Look for the named directive, specifically looking for any "none"
   * configurations.
   */
  for (c = (config_rec *) set->xas_list; c; c = c->next) {
    pr_signals_handle();

    if (is_redis_log_config(c, name, namelen, config_id) == TRUE) {
      if (c->argv[0] == NULL ||
          c->argv[1] == NULL ||
          c->argv[2] == NULL) {
        needs_pruning = TRUE;
        break;
      }
    }
  }

  if (needs_pruning) {
    pr_config_remove(set, name, 0, FALSE);
    pruned = TRUE;
  }

  return pruned;
}

MODRET redis_post_pass(cmd_rec *cmd) {
  const char *name;
  int pruned = FALSE;

  if (redis_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (main_server->conf == NULL ||
      main_server->conf->xas_list == NULL) {
    return PR_DECLINED(cmd);
  }

  /* Process the config tree for RedisLogOnCommand/Event "none" directives,
   * so that they work as expected.
   *
   * Since RedisLogOnCommand/Event allow for multiple simultaneous occurrences
   * (via CF_MERGEDOWN_MULTI), due to multiple possible filters/formats, we
   * cannot simply assume that the CF_MERGEDOWN flag for the "none" case will
   * do as we want.  Instead, we have manually prune any competing
   * RedisLogOnCommand/Event directives, for a given directory level, whenever
   * we encounter a "none" directive.
   */

  name = "RedisLogOnCommand";
  if (find_config(main_server->conf, CONF_PARAM, name, TRUE) != NULL) {
    size_t namelen;
    unsigned int config_id;

    namelen = strlen(name);
    config_id = pr_config_get_id(name);
    if (prune_redis_log_config(cmd->tmp_pool, main_server->conf, name, namelen,
        config_id) == TRUE) {
      pruned = TRUE;
    }
  }

  name = "RedisLogOnEvent";
  if (find_config(main_server->conf, CONF_PARAM, name, TRUE) != NULL) {
    size_t namelen;
    unsigned int config_id;

    namelen = strlen(name);
    config_id = pr_config_get_id(name);
    if (prune_redis_log_config(cmd->tmp_pool, main_server->conf, name, namelen,
        config_id) == TRUE) {
      pruned = TRUE;
    }
  }

  if (pruned) {
    pr_log_debug(DEBUG9, MOD_REDIS_VERSION
      ": Pruned configuration for Redis logging");
    pr_config_dump(NULL, main_server->conf, NULL);
  }

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

static void redis_restart_ev(const void *event_data, void *user_data) {
  destroy_pool(redis_pool);
  redis_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(redis_pool, MOD_REDIS_VERSION);

  jot_logfmt2json = pr_jot_get_logfmt2json(redis_pool);
}

static void redis_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&redis_module, "core.session-reinit",
    redis_sess_reinit_ev);

  (void) close(redis_logfd);
  redis_logfd = -1;

  /* XXX Restore other Redis settings? */
  /* reset RedisTimeouts */

  res = redis_sess_init();
  if (res < 0) {
    pr_session_disconnect(&redis_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

static void redis_shutdown_ev(const void *event_data, void *user_data) {
  destroy_pool(redis_pool);
  jot_logfmt2json = NULL;
}

/* Initialization functions
 */

static int redis_module_init(void) {
  redis_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(redis_pool, MOD_REDIS_VERSION);

  redis_init();
  pr_event_register(&redis_module, "core.restart", redis_restart_ev, NULL);
  pr_event_register(&redis_module, "core.shutdown", redis_shutdown_ev, NULL);

  pr_log_debug(DEBUG2, MOD_REDIS_VERSION ": using hiredis-%d.%d.%d",
    HIREDIS_MAJOR, HIREDIS_MINOR, HIREDIS_PATCH);

  jot_logfmt2json = pr_jot_get_logfmt2json(redis_pool);
  if (jot_logfmt2json == NULL) {
    return -1;
  }

  return 0;
}

static int redis_sess_init(void) {
  config_rec *c;

  pr_event_register(&redis_module, "core.session-reinit",
    redis_sess_reinit_ev, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "RedisEngine", FALSE);
  if (c != NULL) {
    int engine;

    engine = *((int *) c->argv[0]);
    if (engine == FALSE) {
      return 0;
    }

    redis_engine = engine;
  }

  c = find_config(main_server->conf, CONF_PARAM, "RedisLog", FALSE);
  if (c != NULL) {
    const char *path;

    path = c->argv[0];
    if (strcasecmp(path, "none") != 0) {
      int res, xerrno;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(path, &redis_logfd, PR_LOG_SYSTEM_MODE);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      switch (res) {
        case 0:
          break;

        case -1:
          pr_log_pri(PR_LOG_NOTICE, MOD_REDIS_VERSION
            ": notice: unable to open RedisLog '%s': %s", path,
            strerror(xerrno));
          break;

        case PR_LOG_WRITABLE_DIR:
          pr_log_pri(PR_LOG_WARNING, MOD_REDIS_VERSION
            ": notice: unable to use RedisLog '%s': parent directory is "
              "world-writable", path);
          break;

        case PR_LOG_SYMLINK:
          pr_log_pri(PR_LOG_WARNING, MOD_REDIS_VERSION
            ": notice: unable to use RedisLog '%s': cannot log to a symlink",
            path);
          break;
      }
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "RedisOptions", FALSE);
  while (c != NULL) {
    unsigned long opts = 0;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    redis_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "RedisOptions", FALSE);
  }

  c = find_config(main_server->conf, CONF_PARAM, "RedisSentinel", FALSE);
  if (c != NULL) {
    array_header *sentinels;
    const char *master;

    sentinels = c->argv[0];
    master = c->argv[1];

    (void) redis_set_sentinels(sentinels, master);
  }

  c = find_config(main_server->conf, CONF_PARAM, "RedisServer", FALSE);
  if (c != NULL) {
    const char *server, *password, *db_idx;
    int port;

    server = c->argv[0];
    port = *((int *) c->argv[1]);
    password = c->argv[2];
    db_idx = c->argv[3];

    (void) redis_set_server(server, port, redis_opts, password, db_idx);
  }

  c = find_config(main_server->conf, CONF_PARAM, "RedisTimeouts", FALSE);
  if (c != NULL) {
    unsigned long connect_millis, io_millis;

    connect_millis = *((unsigned long *) c->argv[0]);
    io_millis = *((unsigned long *) c->argv[1]);

    if (redis_set_timeouts(connect_millis, io_millis) < 0) {
      (void) pr_log_writefile(redis_logfd, MOD_REDIS_VERSION,
        "error setting Redis timeouts: %s", strerror(errno));
    }
  }

  return 0;
}

/* Module API tables
 */

static conftable redis_conftab[] = {
  { "RedisEngine",		set_redisengine,	NULL },
  { "RedisLog",			set_redislog,		NULL },
  { "RedisLogOnCommand",	set_redislogoncommand,	NULL },
  { "RedisLogOnEvent",		set_redislogonevent,	NULL },
  { "RedisOptions",		set_redisoptions,	NULL },
  { "RedisSentinel",		set_redissentinel,	NULL },
  { "RedisServer",		set_redisserver,	NULL },
  { "RedisTimeouts",		set_redistimeouts,	NULL },
 
  { NULL }
};

static cmdtable redis_cmdtab[] = {
  { POST_CMD,		C_PASS,	G_NONE,	redis_post_pass, FALSE,	FALSE },
  { LOG_CMD,		C_ANY,	G_NONE,	redis_log_any,	 FALSE,	FALSE },
  { LOG_CMD_ERR,	C_ANY,	G_NONE,	redis_log_any,	 FALSE,	FALSE },

  { 0, NULL }
};

module redis_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "redis",

  /* Module configuration handler table */
  redis_conftab,

  /* Module command handler table */
  redis_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  redis_module_init,

  /* Session initialization function */
  redis_sess_init,

  /* Module version */
  MOD_REDIS_VERSION
};
