/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2017 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Redis management */

#include "conf.h"

#ifdef PR_USE_REDIS

#include <hiredis/hiredis.h>

#ifndef REDIS_CONNECT_RETRIES
# define REDIS_CONNECT_RETRIES	10
#endif /* REDIS_CONNECT_RETRIES */

/* When scanning for keys/lists, how many items to request per command? */
#define PR_REDIS_SCAN_SIZE	100

struct redis_rec {
  pool *pool;
  module *owner;
  redisContext *ctx;
  unsigned long flags;

  /* For tracking the number of "opens"/"closes" on a shared redis_rec,
   * as the same struct might be used by multiple modules in the same
   * session, each module doing a conn_get()/conn_close().
   */
  unsigned int refcount;

  /* Table mapping modules to their namespaces */
  pr_table_t *namespace_tab;
};

static array_header *redis_sentinels = NULL;
static const char *redis_sentinel_master = NULL;

static const char *redis_server = NULL;
static int redis_port = -1;
static unsigned long redis_flags = 0UL;
static const char *redis_password = NULL;
static const char *redis_db_idx = NULL;

static pr_redis_t *sess_redis = NULL;

static unsigned long redis_connect_millis = 500;
static unsigned long redis_io_millis = 500;

static const char *trace_channel = "redis";

static void millis2timeval(struct timeval *tv, unsigned long millis) {
  tv->tv_sec = (millis / 1000);
  tv->tv_usec = (millis - (tv->tv_sec * 1000)) * 1000;
}

static const char *redis_strerror(pool *p, pr_redis_t *redis, int rerrno) {
  const char *err;

  switch (redis->ctx->err) {
    case REDIS_ERR_IO:
      err = pstrcat(p, "[io] ", strerror(rerrno), NULL);
      break;

    case REDIS_ERR_EOF:
      err = pstrcat(p, "[eof] ", redis->ctx->errstr, NULL);
      break;

    case REDIS_ERR_PROTOCOL:
      err = pstrcat(p, "[protocol] ", redis->ctx->errstr, NULL);
      break;

    case REDIS_ERR_OOM:
      err = pstrcat(p, "[oom] ", redis->ctx->errstr, NULL);
      break;

    case REDIS_ERR_OTHER:
      err = pstrcat(p, "[other] ", redis->ctx->errstr, NULL);
      break;

    case REDIS_OK:
    default:
      err = "OK";
      break;
  }

  return err;
}

static int conn_reconnect(pool *p, pr_redis_t *redis) {
  int xerrno = 0;
#ifdef HAVE_HIREDIS_REDISRECONNECT
  register unsigned int i;

  if (redis->flags & PR_REDIS_CONN_FL_NO_RECONNECT) {
    errno = EPERM;
    return -1;
  }

  /* Use the already-provided REDIS_CONNECT_RETRIES from <hiredis/hiredis.h>
   * rather than defining our own.
   *
   * Currently that is a rather low number (3), so I do not feel the need
   * for retry delays or exponential backoff at this time.
   */
  for (i = 0; i < REDIS_CONNECT_RETRIES; i++) {
    int res;

    pr_trace_msg(trace_channel, 9, "attempt #%u to reconnect", i+1);

    res = redisReconnect(redis->ctx);
    xerrno = errno;
    if (res == REDIS_OK) {
      pr_trace_msg(trace_channel, 9, "attempt #%u to reconnect succeeded", i+1);
      return 0;
    }

    pr_trace_msg(trace_channel, 9, "attempt #%u to reconnect failed: %s",
      i+ 1, redis_strerror(p, redis, xerrno));
  }
#else
  xerrno = ENOSYS;
#endif /* No redisReconnect() */

  errno = xerrno;
  return -1;
}

static redisReply *handle_reply(pr_redis_t *redis, const char *cmd,
    redisReply *reply) {
  int xerrno;
  pool *tmp_pool;

  if (reply != NULL) {
    return reply;
  }

  xerrno = errno;
  tmp_pool = make_sub_pool(redis->pool);
  pr_trace_msg(trace_channel, 2, "error executing %s command: %s", cmd,
    redis_strerror(tmp_pool, redis, xerrno));

  if (redis->ctx->err == REDIS_ERR_IO ||
      redis->ctx->err == REDIS_ERR_EOF) {
    int res;

    res = conn_reconnect(tmp_pool, redis);
    if (res < 0) {
      pr_trace_msg(trace_channel, 9, "failed to reconnect: %s",
        strerror(errno));
    }
  }

  destroy_pool(tmp_pool);
  errno = xerrno;
  return NULL;
}

static int ping_server(pr_redis_t *redis) {
  const char *cmd;
  redisReply *reply;

  cmd = "PING";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s", cmd);
  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    return -1;
  }

  /* We COULD assert a "PONG" response here, but really, anything is OK. */
  pr_trace_msg(trace_channel, 7, "%s reply: %s", cmd, reply->str);
  freeReplyObject(reply);
  return 0;
}

static int stat_server(pr_redis_t *redis, const char *section) {
  const char *cmd;
  redisReply *reply;

  cmd = "INFO";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %s", cmd, section);
  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    return -1;
  }

  if (pr_trace_get_level(trace_channel) >= 25) {
    pr_trace_msg(trace_channel, 25, "%s reply: %s", cmd, reply->str);

  } else {
    pr_trace_msg(trace_channel, 7, "%s reply: (text, %lu bytes)", cmd,
      (unsigned long) reply->len);
  }

  freeReplyObject(reply);
  return 0;
}

pr_redis_t *pr_redis_conn_get(pool *p, unsigned long flags) {
  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (sess_redis != NULL) {
    sess_redis->refcount++;
    return sess_redis;
  }

  return pr_redis_conn_new(p, NULL, flags);
}

static int set_conn_options(pr_redis_t *redis) {
  int res, xerrno;
  struct timeval tv;
  pool *tmp_pool;

  tmp_pool = make_sub_pool(redis->pool);

  millis2timeval(&tv, redis_io_millis);
  res = redisSetTimeout(redis->ctx, tv);
  xerrno = errno;

  if (res == REDIS_ERR) {
    pr_trace_msg(trace_channel, 4,
      "error setting %lu ms timeout: %s", redis_io_millis,
      redis_strerror(tmp_pool, redis, xerrno));
  }

#if HIREDIS_MAJOR >= 0 && \
    HIREDIS_MINOR >= 12
  res = redisEnableKeepAlive(redis->ctx);
  xerrno = errno;

  if (res == REDIS_ERR) {
    pr_trace_msg(trace_channel, 4,
      "error setting keepalive: %s", redis_strerror(tmp_pool, redis, xerrno));
  }
#endif /* HiRedis 0.12.0 and later */

  destroy_pool(tmp_pool);
  return 0;
}

static void sess_redis_cleanup(void *data) {
  sess_redis = NULL;
}

static pr_redis_t *make_redis_conn(pool *p, const char *host, int port) {
  int uses_ip = TRUE, xerrno;
  pr_redis_t *redis;
  pool *sub_pool;
  redisContext *ctx;
  struct timeval tv;

  millis2timeval(&tv, redis_connect_millis); 

  /* If the given redis "server" string starts with a '/' character, assume
   * that it is a Unix socket path.
   */
  if (*host == '/') {
    uses_ip = FALSE;
    ctx = redisConnectUnixWithTimeout(host, tv);

  } else {
    ctx = redisConnectWithTimeout(host, port, tv);
  }

  xerrno = errno;

  if (ctx == NULL) {
    errno = ENOMEM;
    return NULL;
  }

  if (ctx->err != 0) {
    const char *err_type, *err_msg;

    switch (ctx->err) {
      case REDIS_ERR_IO:
        err_type = "io";
        err_msg = strerror(xerrno);
        break;

      case REDIS_ERR_EOF:
        err_type = "eof";
        err_msg = ctx->errstr;
        break;

      case REDIS_ERR_PROTOCOL:
        err_type = "protocol";
        err_msg = ctx->errstr;
        break;

      case REDIS_ERR_OOM:
        err_type = "oom";
        err_msg = ctx->errstr;
        break;

      case REDIS_ERR_OTHER:
        err_type = "other";
        err_msg = ctx->errstr;
        break;

      default:
        err_type = "unknown";
        err_msg = ctx->errstr;
        break;
    }

    if (uses_ip == TRUE) {
      pr_trace_msg(trace_channel, 3,
        "error connecting to %s#%d: [%s] %s", host, port, err_type, err_msg);

    } else {
      pr_trace_msg(trace_channel, 3,
        "error connecting to '%s': [%s] %s", host, err_type, err_msg);
    }

    redisFree(ctx);
    errno = EIO;
    return NULL;
  }

  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "Redis connection pool");

  redis = pcalloc(sub_pool, sizeof(pr_redis_t));
  redis->pool = sub_pool;
  redis->ctx = ctx;

  return redis;
}

static int discover_redis_master(pool *p, const char *host, int port,
    const char *master) {
  int res = 0, xerrno = 0;
  pool *tmp_pool;
  pr_redis_t *redis;
  pr_netaddr_t *addr = NULL;

  tmp_pool = make_sub_pool(p);

  redis = make_redis_conn(tmp_pool, host, port);
  xerrno = errno;

  if (redis == NULL) {
    destroy_pool(tmp_pool);

    errno = xerrno;
    return -1;
  }

  if (master == NULL) {
    array_header *masters = NULL;

    res = pr_redis_sentinel_get_masters(tmp_pool, redis, &masters);
    if (res < 0) {
      pr_trace_msg(trace_channel, 14, "error getting masters from Sentinel: %s",
        strerror(errno));

    } else {
      master = ((char **) masters->elts)[0];
      pr_trace_msg(trace_channel, 17, "discovered master '%s'", master);
    }
  }

  res = pr_redis_sentinel_get_master_addr(tmp_pool, redis, master, &addr);
  xerrno = errno;

  if (res < 0) {
    pr_redis_conn_destroy(redis);
    destroy_pool(tmp_pool);

    errno = xerrno;
    return -1;
  }

  redis_server = pstrdup(p, pr_netaddr_get_ipstr(addr));
  redis_port = ntohs(pr_netaddr_get_port(addr));

  pr_redis_conn_destroy(redis);
  destroy_pool(tmp_pool);

  errno = xerrno;
  return res;
}

pr_redis_t *pr_redis_conn_new(pool *p, module *m, unsigned long flags) {
  int default_port, res, xerrno;
  pr_redis_t *redis;
  const char *default_host;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  default_host = redis_server;
  default_port = redis_port;

  /* Do we have a list of Sentinels configured?  If so, try those first. */
  if (redis_sentinels != NULL) {
    register unsigned int i;

    pr_trace_msg(trace_channel, 17,
      "querying Sentinels (%u count) for Redis server",
      redis_sentinels->nelts);

    for (i = 0; i < redis_sentinels->nelts; i++) {
      pr_netaddr_t *addr;
      const char *sentinel;
      int port;

      addr = ((pr_netaddr_t **) redis_sentinels->elts)[i];
      sentinel = pr_netaddr_get_ipstr(addr);
      port = ntohs(pr_netaddr_get_port(addr));

      if (discover_redis_master(p, sentinel, port,
          redis_sentinel_master) == 0) {
        pr_trace_msg(trace_channel, 17,
          "discovered Redis server %s:%d using Sentinel #%u (%s:%d)",
          redis_server, redis_port, i+1, sentinel, port);
      }
    }
  }

  /* If the Sentinels failed to provide a usable host, fall back to the
   * default.
   */
  if (redis_server == NULL) {
    redis_server = default_host;
    redis_port = default_port;
  }

  if (redis_server == NULL) {
    pr_trace_msg(trace_channel, 9, "%s",
      "unable to create new Redis connection: No server configured");
    errno = EPERM;
    return NULL;
  }

  redis = make_redis_conn(p, redis_server, redis_port);
  if (redis == NULL) {
    return NULL;
  }

  redis->owner = m;
  redis->refcount = 1;
  redis->flags = flags;

  /* The namespace table is null; it will be created if/when callers
   * configure namespace prefixes.
   */
  redis->namespace_tab = NULL;

  /* Set some of the desired behavior flags on the connection */
  res = set_conn_options(redis);
  if (res < 0) {
    xerrno = errno;

    pr_redis_conn_destroy(redis);
    errno = xerrno;
    return NULL;    
  }

  res = ping_server(redis);
  if (res < 0) {
    xerrno = errno;

    pr_redis_conn_destroy(redis);
    errno = xerrno;
    return NULL;
  }

  /* Make sure we are connected to the configured server by querying
   * some stats/info from it.
   */
  res = stat_server(redis, "server");
  if (res < 0) {
    xerrno = errno;

    pr_redis_conn_destroy(redis);
    errno = xerrno;
    return NULL;    
  }

  if (redis_password != NULL) {
    res = pr_redis_auth(redis, redis_password);
    if (res < 0) {
      xerrno = errno;

      pr_redis_conn_destroy(redis);
      errno = xerrno;
      return NULL;
    }
  }

  if (redis_db_idx != NULL) {
    res = pr_redis_select(redis, redis_db_idx);
    if (res < 0) {
      xerrno = errno;

      pr_redis_conn_destroy(redis);
      errno = xerrno;
      return NULL;
    }
  }

  if (sess_redis == NULL) {
    sess_redis = redis;

    /* Register a cleanup on this redis, so that when it is destroyed, we
     * clear this sess_redis pointer, lest it remaining dangling.
     */
    register_cleanup(redis->pool, NULL, sess_redis_cleanup, NULL);
  }

  return redis;
}

/* Return TRUE if we actually closed the connection, FALSE if we simply
 * decremented the refcount.
 */
int pr_redis_conn_close(pr_redis_t *redis) {
  int closed = FALSE;

  if (redis == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (redis->refcount > 0) {
    redis->refcount--;
  }

  if (redis->refcount == 0) {
    if (redis->ctx != NULL) {
      const char *cmd = NULL;
      redisReply *reply;

      cmd = "QUIT";
      pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
      reply = redisCommand(redis->ctx, "%s", cmd);
      if (reply != NULL) {
        freeReplyObject(reply);
      }

      redisFree(redis->ctx);
      redis->ctx = NULL;
    }

    if (redis->namespace_tab != NULL) {
      (void) pr_table_empty(redis->namespace_tab);
      (void) pr_table_free(redis->namespace_tab);
      redis->namespace_tab = NULL;
    }

    closed = TRUE;
  }

  return closed;
}

/* Return TRUE if we actually closed the connection, FALSE if we simply
 * decremented the refcount.
 */
int pr_redis_conn_destroy(pr_redis_t *redis) {
  int closed, destroyed = FALSE;

  if (redis == NULL) {
    errno = EINVAL;
    return -1;
  }

  closed = pr_redis_conn_close(redis);
  if (closed < 0) {
    return -1;
  }

  if (closed == TRUE) {
    if (redis == sess_redis) {
      sess_redis = NULL;
    }

    destroy_pool(redis->pool);
    destroyed = TRUE;
  }

  return destroyed;
}

static int modptr_cmp_cb(const void *k1, size_t ksz1, const void *k2,
    size_t ksz2) {

  /* Return zero to indicate a match, non-zero otherwise. */
  return (((module *) k1) == ((module *) k2) ? 0 : 1);
}

static unsigned int modptr_hash_cb(const void *k, size_t ksz) {
  unsigned int key = 0;

  /* XXX Yes, this is a bit hacky for "hashing" a pointer value. */

  memcpy(&key, k, sizeof(key));
  key ^= (key >> 16);

  return key;
}

int pr_redis_conn_set_namespace(pr_redis_t *redis, module *m,
    const void *prefix, size_t prefixsz) {

  if (redis == NULL ||
      m == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (prefix != NULL &&
      prefixsz == 0) {
    errno = EINVAL;
    return -1;
  }

  if (redis->namespace_tab == NULL) {
    pr_table_t *tab;

    tab = pr_table_alloc(redis->pool, 0);

    (void) pr_table_ctl(tab, PR_TABLE_CTL_SET_KEY_CMP, modptr_cmp_cb);
    (void) pr_table_ctl(tab, PR_TABLE_CTL_SET_KEY_HASH, modptr_hash_cb);
    redis->namespace_tab = tab;
  }

  if (prefix != NULL) {
    int count;
    void *val;
    size_t valsz;

    valsz = prefixsz;
    val = palloc(redis->pool, valsz);
    memcpy(val, prefix, prefixsz);

    count = pr_table_kexists(redis->namespace_tab, m, sizeof(module *));
    if (count <= 0) {
      (void) pr_table_kadd(redis->namespace_tab, m, sizeof(module *), val,
        valsz);

    } else {
      (void) pr_table_kset(redis->namespace_tab, m, sizeof(module *), val,
        valsz);
    }

  } else {
    /* A NULL prefix means the caller is removing their namespace mapping. */
    (void) pr_table_kremove(redis->namespace_tab, m, sizeof(module *), NULL);
  }

  return 0;
}

int pr_redis_add(pr_redis_t *redis, module *m, const char *key, void *value,
    size_t valuesz, time_t expires) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_kadd(redis, m, key, strlen(key), value, valuesz, expires);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error adding key '%s', value (%lu bytes): %s", key,
      (unsigned long) valuesz, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_decr(pr_redis_t *redis, module *m, const char *key, uint32_t decr,
    uint64_t *value) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_kdecr(redis, m, key, strlen(key), decr, value);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error decrementing key '%s' by %lu: %s", key,
      (unsigned long) decr, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

void *pr_redis_get(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t *valuesz) {
  void *ptr = NULL;

  if (key == NULL) {
    errno = EINVAL;
    return NULL;
  }

  ptr = pr_redis_kget(p, redis, m, key, strlen(key), valuesz);
  if (ptr == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error getting data for key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  return ptr;
}

char *pr_redis_get_str(pool *p, pr_redis_t *redis, module *m, const char *key) {
  char *ptr = NULL;

  if (key == NULL) {
    errno = EINVAL;
    return NULL;
  }

  ptr = pr_redis_kget_str(p, redis, m, key, strlen(key));
  if (ptr == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error getting data for key '%s': %s", key, strerror(xerrno));

    errno = xerrno; 
    return NULL;
  }

  return ptr;
}

int pr_redis_incr(pr_redis_t *redis, module *m, const char *key, uint32_t incr,
    uint64_t *value) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_kincr(redis, m, key, strlen(key), incr, value);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error incrementing key '%s' by %lu: %s", key,
      (unsigned long) incr, strerror(xerrno));
 
    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_remove(pr_redis_t *redis, module *m, const char *key) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_kremove(redis, m, key, strlen(key));
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error removing key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_rename(pr_redis_t *redis, module *m, const char *from,
    const char *to) {
  int res;

  if (from == NULL ||
      to == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_krename(redis, m, from, strlen(from), to, strlen(to));
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error renaming key '%s' to '%s': %s", from, to, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_set(pr_redis_t *redis, module *m, const char *key, void *value,
    size_t valuesz, time_t expires) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_kset(redis, m, key, strlen(key), value, valuesz, expires);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error setting key '%s', value (%lu bytes): %s", key,
      (unsigned long) valuesz, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

/* Hash operations */
int pr_redis_hash_count(pr_redis_t *redis, module *m, const char *key,
    uint64_t *count) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_hash_kcount(redis, m, key, strlen(key), count);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error counting hash using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_hash_delete(pr_redis_t *redis, module *m, const char *key,
    const char *field) {
  int res;

  if (key == NULL ||
      field == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_hash_kdelete(redis, m, key, strlen(key), field, strlen(field));
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error deleting field from hash using key '%s', field '%s': %s", key,
      field, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_hash_exists(pr_redis_t *redis, module *m, const char *key,
    const char *field) {
  int res;

  if (key == NULL ||
      field == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_hash_kexists(redis, m, key, strlen(key), field, strlen(field));
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error checking existence of hash using key '%s', field '%s': %s", key,
      field, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return res;
}

int pr_redis_hash_get(pool *p, pr_redis_t *redis, module *m, const char *key,
    const char *field, void **value, size_t *valuesz) {
  int res;

  if (key == NULL ||
      field == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_hash_kget(p, redis, m, key, strlen(key), field, strlen(field),
    value, valuesz);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error getting field from hash using key '%s', field '%s': %s", key,
      field, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_hash_getall(pool *p, pr_redis_t *redis, module *m,
    const char *key, pr_table_t **hash) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_hash_kgetall(p, redis, m, key, strlen(key), hash);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error entire hash using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_hash_incr(pr_redis_t *redis, module *m, const char *key,
    const char *field, int32_t incr, int64_t *value) {
  int res;

  if (key == NULL ||
      field == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_hash_kincr(redis, m, key, strlen(key), field, strlen(field),
    incr, value);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error incrementing field in hash using key '%s', field '%s': %s", key,
      field, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_hash_keys(pool *p, pr_redis_t *redis, module *m, const char *key,
    array_header **fields) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_hash_kkeys(p, redis, m, key, strlen(key), fields);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error obtaining keys from hash using key '%s': %s", key,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_hash_remove(pr_redis_t *redis, module *m, const char *key) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_hash_kremove(redis, m, key, strlen(key));
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error removing hash using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_hash_set(pr_redis_t *redis, module *m, const char *key,
    const char *field, void *value, size_t valuesz) {
  int res;

  if (key == NULL ||
      field == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_hash_kset(redis, m, key, strlen(key), field, strlen(field),
    value, valuesz);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error setting field in hash using key '%s', field '%s': %s", key, field,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_hash_setall(pr_redis_t *redis, module *m, const char *key,
    pr_table_t *hash) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_hash_ksetall(redis, m, key, strlen(key), hash);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error setting hash using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_hash_values(pool *p, pr_redis_t *redis, module *m,
    const char *key, array_header **values) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_hash_kvalues(p, redis, m, key, strlen(key), values);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error getting values of hash using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

/* List operations */
int pr_redis_list_append(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_list_kappend(redis, m, key, strlen(key), value, valuesz);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error appending to list using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_list_count(pr_redis_t *redis, module *m, const char *key,
    uint64_t *count) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_list_kcount(redis, m, key, strlen(key), count);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error counting list using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_list_delete(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz) {
  int res;

  if (value == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_list_kdelete(redis, m, key, strlen(key), value, valuesz);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error deleting item from list using key '%s': %s", key,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_list_exists(pr_redis_t *redis, module *m, const char *key,
    unsigned int idx) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_list_kexists(redis, m, key, strlen(key), idx);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error checking item at index %u in list using key '%s': %s", idx, key,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return res;
}

int pr_redis_list_get(pool *p, pr_redis_t *redis, module *m, const char *key,
    unsigned int idx, void **value, size_t *valuesz) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_list_kget(p, redis, m, key, strlen(key), idx, value, valuesz);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error getting item at index %u in list using key '%s': %s", idx, key,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return res;
}

int pr_redis_list_getall(pool *p, pr_redis_t *redis, module *m, const char *key,
    array_header **values, array_header **valueszs) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_list_kgetall(p, redis, m, key, strlen(key), values, valueszs);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error getting items in list using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return res;
}

int pr_redis_list_pop(pool *p, pr_redis_t *redis, module *m, const char *key,
    void **value, size_t *valuesz, int flags) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_list_kpop(p, redis, m, key, strlen(key), value, valuesz,
    flags);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error popping item from list using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return res;
}

int pr_redis_list_push(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz, int flags) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_list_kpush(redis, m, key, strlen(key), value, valuesz, flags);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error pushing item into list using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_list_remove(pr_redis_t *redis, module *m, const char *key) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_list_kremove(redis, m, key, strlen(key));
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error removing list using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_list_rotate(pool *p, pr_redis_t *redis, module *m,
    const char *key, void **value, size_t *valuesz) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_list_krotate(p, redis, m, key, strlen(key), value, valuesz);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error rotating list using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_list_set(pr_redis_t *redis, module *m, const char *key,
    unsigned int idx, void *value, size_t valuesz) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_list_kset(redis, m, key, strlen(key), idx, value, valuesz);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error setting item in list using key '%s', index %u: %s", key, idx,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_list_setall(pr_redis_t *redis, module *m, const char *key,
    array_header *values, array_header *valueszs) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_list_ksetall(redis, m, key, strlen(key), values, valueszs);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error setting items in list using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

/* Set operations */
int pr_redis_set_add(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_set_kadd(redis, m, key, strlen(key), value, valuesz);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error adding item to set using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_set_count(pr_redis_t *redis, module *m, const char *key,
    uint64_t *count) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_set_kcount(redis, m, key, strlen(key), count);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error counting set using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_set_delete(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_set_kdelete(redis, m, key, strlen(key), value, valuesz);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error deleting item from set using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_set_exists(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_set_kexists(redis, m, key, strlen(key), value, valuesz);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error checking item in set using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return res;
}

int pr_redis_set_getall(pool *p, pr_redis_t *redis, module *m, const char *key,
    array_header **values, array_header **valueszs) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_set_kgetall(p, redis, m, key, strlen(key), values, valueszs);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error getting items in set using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return res;
}

int pr_redis_set_remove(pr_redis_t *redis, module *m, const char *key) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_set_kremove(redis, m, key, strlen(key));
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error removing set using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_set_setall(pr_redis_t *redis, module *m, const char *key,
    array_header *values, array_header *valueszs) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_set_ksetall(redis, m, key, strlen(key), values, valueszs);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error setting items in set using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

/* Sorted Set operations */
int pr_redis_sorted_set_add(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz, float score) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_sorted_set_kadd(redis, m, key, strlen(key), value, valuesz,
    score);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error adding item with score %0.3f to sorted set using key '%s': %s",
      score, key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_sorted_set_count(pr_redis_t *redis, module *m, const char *key,
    uint64_t *count) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_sorted_set_kcount(redis, m, key, strlen(key), count);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error counting sorted set using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_sorted_set_delete(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_sorted_set_kdelete(redis, m, key, strlen(key), value, valuesz);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error deleting item from sorted set using key '%s': %s", key,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_sorted_set_exists(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_sorted_set_kexists(redis, m, key, strlen(key), value, valuesz);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error checking item in sorted set using key '%s': %s", key,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return res;
}

int pr_redis_sorted_set_getn(pool *p, pr_redis_t *redis, module *m,
    const char *key, unsigned int offset, unsigned int len,
    array_header **values, array_header **valueszs, int flags) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_sorted_set_kgetn(p, redis, m, key, strlen(key), offset, len,
    values, valueszs, flags);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error getting %u %s from sorted set using key '%s': %s", len,
      len != 1 ? "items" : "item", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return res;
}

int pr_redis_sorted_set_incr(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz, float incr, float *score) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_sorted_set_kincr(redis, m, key, strlen(key), value, valuesz,
    incr, score);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error incrementing item by %0.3f in sorted set using key '%s': %s",
      incr, key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return res;
}

int pr_redis_sorted_set_remove(pr_redis_t *redis, module *m, const char *key) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_sorted_set_kremove(redis, m, key, strlen(key));
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error removing sorted set using key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_sorted_set_score(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz, float *score) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_sorted_set_kscore(redis, m, key, strlen(key), value, valuesz,
    score);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error getting score for item in sorted set using key '%s': %s", key,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return res;
}

int pr_redis_sorted_set_set(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz, float score) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_sorted_set_kset(redis, m, key, strlen(key), value, valuesz,
    score);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error setting item to score %0.3f in sorted set using key '%s': %s",
      score, key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_redis_sorted_set_setall(pr_redis_t *redis, module *m, const char *key,
    array_header *values, array_header *valueszs, array_header *scores) {
  int res;

  if (key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_redis_sorted_set_ksetall(redis, m, key, strlen(key), values,
    valueszs, scores);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error setting items in sorted set using key '%s': %s", key,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

static const char *get_namespace_key(pool *p, pr_redis_t *redis, module *m,
    const char *key, size_t *keysz) {

  if (m != NULL &&
      redis->namespace_tab != NULL) {
    const char *prefix = NULL;
    size_t prefixsz = 0;

    prefix = pr_table_kget(redis->namespace_tab, m, sizeof(module *),
      &prefixsz);
    if (prefix != NULL) {
      char *new_key;
      size_t new_keysz;

      pr_trace_msg(trace_channel, 25,
        "using namespace prefix '%s' for module 'mod_%s.c'", prefix, m->name);

      /* Since the given key may not be text, we cannot simply use pstrcat()
       * to prepend our namespace value.
       */
      new_keysz = prefixsz + *keysz;
      new_key = palloc(p, new_keysz);
      memcpy(new_key, prefix, prefixsz);
      memcpy(new_key + prefixsz, key, *keysz);

      key = new_key;
      *keysz = new_keysz;
    }
  }

  return key;
}

static const char *get_reply_type(int reply_type) {
  const char *type_name;

  switch (reply_type) {
    case REDIS_REPLY_STRING:
      type_name = "STRING";
      break;

    case REDIS_REPLY_ARRAY:
      type_name = "ARRAY";
      break;

    case REDIS_REPLY_INTEGER:
      type_name = "INTEGER";
      break;

    case REDIS_REPLY_NIL:
      type_name = "NIL";
      break;

    case REDIS_REPLY_STATUS:
      type_name = "STATUS";
      break;

    case REDIS_REPLY_ERROR:
      type_name = "ERROR";
      break;

    default:
      type_name = "unknown";
  }

  return type_name;
}

int pr_redis_command(pr_redis_t *redis, const array_header *args,
    int reply_type) {
  register unsigned int i;
  pool *tmp_pool = NULL;
  array_header *arglens;
  const char *cmd = NULL;
  redisReply *reply;
  int redis_reply_type;

  if (redis == NULL ||
      args == NULL ||
      args->nelts == 0) {
    errno = EINVAL;
    return -1;
  }

  switch (reply_type) {
    case PR_REDIS_REPLY_TYPE_STRING:
      redis_reply_type = REDIS_REPLY_STRING;
      break;

    case PR_REDIS_REPLY_TYPE_INTEGER:
      redis_reply_type = REDIS_REPLY_INTEGER;
      break;

    case PR_REDIS_REPLY_TYPE_NIL:
      redis_reply_type = REDIS_REPLY_NIL;
      break;

    case PR_REDIS_REPLY_TYPE_ARRAY:
      redis_reply_type = REDIS_REPLY_ARRAY;
      break;

    case PR_REDIS_REPLY_TYPE_STATUS:
      redis_reply_type = REDIS_REPLY_STATUS;
      break;

    case PR_REDIS_REPLY_TYPE_ERROR:
      redis_reply_type = REDIS_REPLY_ERROR;
      break;

    default:
      errno = EINVAL;
      return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis Command pool");

  arglens = make_array(tmp_pool, args->nelts, sizeof(size_t));
  for (i = 0; i < args->nelts; i++) {
    pr_signals_handle();
    *((size_t *) push_array(arglens)) = strlen(((char **) args->elts)[i]);
  }

  cmd = ((char **) args->elts)[0];
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommandArgv(redis->ctx, args->nelts, args->elts, arglens->elts);
  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    destroy_pool(tmp_pool);
    errno = EIO;
    return -1;
  }

  if (reply->type != redis_reply_type) {
    pr_trace_msg(trace_channel, 2,
      "expected %s reply for %s, got %s", get_reply_type(redis_reply_type), cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  switch (reply->type) {
    case REDIS_REPLY_STRING:
    case REDIS_REPLY_STATUS:
    case REDIS_REPLY_ERROR:
      pr_trace_msg(trace_channel, 7, "%s %s reply: %.*s", cmd,
        get_reply_type(reply->type), (int) reply->len, reply->str);
      break;

    case REDIS_REPLY_INTEGER:
      pr_trace_msg(trace_channel, 7, "%s INTEGER reply: %lld", cmd,
        reply->integer);
      break;

    case REDIS_REPLY_NIL:
      pr_trace_msg(trace_channel, 7, "%s NIL reply", cmd);
      break;

    case REDIS_REPLY_ARRAY:
      pr_trace_msg(trace_channel, 7, "%s ARRAY reply: (%lu %s)", cmd,
        (unsigned long) reply->elements,
        reply->elements != 1 ? "elements" : "element");
      break;

    default:
      break;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_auth(pr_redis_t *redis, const char *password) {
  const char *cmd;
  pool *tmp_pool;
  redisReply *reply;

  if (redis == NULL ||
      password == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis AUTH pool");

  cmd = "AUTH";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %s", cmd, password);
  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error authenticating client: %s", strerror(errno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return -1;
  }

  if (reply->type != REDIS_REPLY_STRING &&
      reply->type != REDIS_REPLY_STATUS) {
    pr_trace_msg(trace_channel, 2,
      "expected STRING or STATUS reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %.*s", cmd, (int) reply->len,
    reply->str);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_select(pr_redis_t *redis, const char *db_idx) {
  const char *cmd;
  pool *tmp_pool;
  redisReply *reply;

  if (redis == NULL ||
      db_idx == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis SELECT pool");

  cmd = "SELECT";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %s", cmd, db_idx);
  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error selecting database '%s': %s", db_idx, strerror(errno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return -1;
  }

  if (reply->type != REDIS_REPLY_STRING &&
      reply->type != REDIS_REPLY_STATUS) {
    pr_trace_msg(trace_channel, 2,
      "expected STRING or STATUS reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %.*s", cmd, (int) reply->len,
    reply->str);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_kadd(pr_redis_t *redis, module *m, const char *key, size_t keysz,
    void *value, size_t valuesz, time_t expires) {
  return pr_redis_kset(redis, m, key, keysz, value, valuesz, expires);
}

int pr_redis_kdecr(pr_redis_t *redis, module *m, const char *key, size_t keysz,
    uint32_t decr, uint64_t *value) {
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      decr == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis DECRBY pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "DECRBY";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %lu", cmd, key, keysz,
    (unsigned long) decr);
  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error decrementing key (%lu bytes) by %lu using %s: %s",
      (unsigned long) keysz, (unsigned long) decr, cmd, strerror(errno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  /* Note: DECRBY will automatically set the key value to zero if it does
   * not already exist.  To detect a nonexistent key, then, we look to
   * see if the return value is exactly our requested decrement.  If so,
   * REMOVE the auto-created key, and return ENOENT.
   */
  if ((decr * -1) == (uint32_t) reply->integer) {
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    (void) pr_redis_kremove(redis, m, key, keysz);
    errno = ENOENT;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);

  if (value != NULL) {
    *value = (uint64_t) reply->integer;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

void *pr_redis_kget(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz, size_t *valuesz) {
  const char *cmd;
  pool *tmp_pool;
  redisReply *reply;
  char *data = NULL;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL ||
      valuesz == NULL) {
    errno = EINVAL;
    return NULL;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis GET pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "GET";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b", cmd, key, keysz);
  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting data for key (%lu bytes) using %s: %s",
      (unsigned long) keysz, cmd, strerror(errno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return NULL;
  }

  if (reply->type == REDIS_REPLY_NIL) {
    pr_trace_msg(trace_channel, 7, "%s reply: nil", cmd);
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return NULL;
  }

  if (reply->type != REDIS_REPLY_STRING) {
    pr_trace_msg(trace_channel, 2,
      "expected STRING reply for %s, got %s", cmd, get_reply_type(reply->type));
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return NULL;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %.*s", cmd, (int) reply->len,
    reply->str);

  if (valuesz != NULL) {
    *valuesz = (uint64_t) reply->len;
  }

  data = palloc(p, reply->len);
  memcpy(data, reply->str, reply->len);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return data;
}

char *pr_redis_kget_str(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {
  const char *cmd;
  pool *tmp_pool;
  redisReply *reply;
  char *data = NULL;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL) {
    errno = EINVAL;
    return NULL;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis GET pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "GET";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b", cmd, key, keysz);
  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting data for key (%lu bytes) using %s: %s",
      (unsigned long) keysz, cmd, strerror(errno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return NULL;
  }

  if (reply->type == REDIS_REPLY_NIL) {
    pr_trace_msg(trace_channel, 7, "%s reply: nil", cmd);
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return NULL;
  }

  if (reply->type != REDIS_REPLY_STRING) {
    pr_trace_msg(trace_channel, 2,
      "expected STRING reply for %s, got %s", cmd, get_reply_type(reply->type));
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return NULL;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %.*s", cmd, (int) reply->len,
    reply->str);

  data = pstrndup(p, reply->str, reply->len);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return data;
}

int pr_redis_kincr(pr_redis_t *redis, module *m, const char *key, size_t keysz,
    uint32_t incr, uint64_t *value) {
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      incr == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis INCRBY pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "INCRBY";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %lu", cmd, key, keysz,
    (unsigned long) incr);
  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error incrementing key (%lu bytes) by %lu using %s: %s",
      (unsigned long) keysz, (unsigned long) incr, cmd, strerror(errno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  /* Note: INCRBY will automatically set the key value to zero if it does
   * not already exist.  To detect a nonexistent key, then, we look to
   * see if the return value is exactly our requested increment.  If so,
   * REMOVE the auto-created key, and return ENOENT.
   */
  if (incr == (uint32_t) reply->integer) {
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    (void) pr_redis_kremove(redis, m, key, keysz);
    errno = ENOENT;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);

  if (value != NULL) {
    *value = (uint64_t) reply->integer;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_kremove(pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {
  int xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;
  long long count;

  if (redis == NULL ||
      m == NULL ||
      key == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis DEL pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "DEL";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b", cmd, key, keysz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error removing key (%lu bytes): %s", (unsigned long) keysz,
      strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);
  count = reply->integer;

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  if (count == 0) {
    /* No keys removed. */
    errno = ENOENT;
    return -1;
  }

  return 0;
}

int pr_redis_krename(pr_redis_t *redis, module *m, const char *from,
    size_t fromsz, const char *to, size_t tosz) {
  int xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      from == NULL ||
      fromsz == 0 ||
      to == NULL ||
      tosz == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis RENAME pool");

  from = get_namespace_key(tmp_pool, redis, m, from, &fromsz);
  to = get_namespace_key(tmp_pool, redis, m, to, &tosz);

  cmd = "RENAME";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %b", cmd, from, fromsz, to, tosz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error renaming key (from %lu bytes, to %lu bytes): %s",
      (unsigned long) fromsz, (unsigned long) tosz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_STRING &&
      reply->type != REDIS_REPLY_STATUS) {
    xerrno = EINVAL;

    pr_trace_msg(trace_channel, 2,
      "expected STRING or STATUS reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);

      /* Note: In order to provide ENOENT semantics here, we have to be
       * naughty, and assume the contents of this error message.
       */
      if (strstr(reply->str, "no such key") != NULL) {
        xerrno = ENOENT;
      }
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %.*s", cmd, (int) reply->len,
    reply->str);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_kset(pr_redis_t *redis, module *m, const char *key, size_t keysz,
    void *value, size_t valuesz, time_t expires) {
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      value == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis SET pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  if (expires > 0) {
    cmd = "SETEX";
    pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
    reply = redisCommand(redis->ctx, "%s %b %lu %b", cmd, key, keysz,
      (unsigned long) expires, value, valuesz);

  } else {
    cmd = "SET";
    pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
    reply = redisCommand(redis->ctx, "%s %b %b", cmd, key, keysz, value,
      valuesz);
  }

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error adding key (%lu bytes), value (%lu bytes) using %s: %s",
      (unsigned long) keysz, (unsigned long) valuesz, cmd, strerror(errno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %s", cmd, reply->str);
  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_hash_kcount(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, uint64_t *count) {
  int xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      count == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis HLEN pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "HLEN";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b", cmd, key, keysz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting count of hash using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);
  *count = reply->integer;

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_hash_kdelete(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, const char *field, size_t fieldsz) {
  int xerrno = 0, exists = FALSE;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      field == NULL ||
      fieldsz == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis HDEL pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "HDEL";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %b", cmd, key, keysz, field, fieldsz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting count of hash using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);
  exists = reply->integer ? TRUE : FALSE;

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  if (exists == FALSE) {
    errno = ENOENT;
    return -1;
  }

  return 0;
}

int pr_redis_hash_kexists(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, const char *field, size_t fieldsz) {
  int xerrno = 0, exists = FALSE;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      field == NULL ||
      fieldsz == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis HEXISTS pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "HEXISTS";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %b", cmd, key, keysz, field, fieldsz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting count of hash using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);
  exists = reply->integer ? TRUE : FALSE;

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return exists;
}

int pr_redis_hash_kget(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz, const char *field, size_t fieldsz, void **value,
    size_t *valuesz) {
  int xerrno = 0, exists = FALSE;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      field == NULL ||
      fieldsz == 0 ||
      value == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis HGET pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "HGET";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %b", cmd, key, keysz, field, fieldsz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting item for field in hash using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_STRING &&
      reply->type != REDIS_REPLY_NIL) {
    pr_trace_msg(trace_channel, 2,
      "expected STRING or NIL reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  if (reply->type == REDIS_REPLY_STRING) {
    pr_trace_msg(trace_channel, 7, "%s reply: (%lu bytes)", cmd,
      (unsigned long) reply->len);

    *value = palloc(p, reply->len);
    memcpy(*value, reply->str, reply->len);

    if (valuesz != NULL) {
      *valuesz = reply->len;
    }

    exists = TRUE;

  } else {
    pr_trace_msg(trace_channel, 7, "%s reply: nil", cmd);
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  if (exists == FALSE) {
    errno = ENOENT;
    return -1;
  }

  return 0;
}

int pr_redis_hash_kgetall(pool *p, pr_redis_t *redis, module *m,
    const char *key, size_t keysz, pr_table_t **hash) {
  int res, xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      hash == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis HGETALL pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "HGETALL";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b", cmd, key, keysz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting hash using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_ARRAY) {
    pr_trace_msg(trace_channel, 2,
      "expected ARRAY reply for %s, got %s", cmd, get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  if (reply->elements > 0) {
    register unsigned int i;

    pr_trace_msg(trace_channel, 7, "%s reply: %lu %s", cmd,
      (unsigned long) reply->elements,
      reply->elements != 1 ? "elements" : "element");

    *hash = pr_table_alloc(p, 0);

    for (i = 0; i < reply->elements; i += 2) {
      redisReply *key_elt, *value_elt;
      void *key_data = NULL, *value_data = NULL;
      size_t key_datasz = 0, value_datasz = 0;

      key_elt = reply->element[i];
      if (key_elt->type == REDIS_REPLY_STRING) {
        key_datasz = key_elt->len;
        key_data = palloc(p, key_datasz);
        memcpy(key_data, key_elt->str, key_datasz);

      } else {
        pr_trace_msg(trace_channel, 2,
          "expected STRING element at index %u, got %s", i,
          get_reply_type(key_elt->type));
      }

      value_elt = reply->element[i+1];
      if (value_elt->type == REDIS_REPLY_STRING) {
        value_datasz = value_elt->len;
        value_data = palloc(p, value_datasz);
        memcpy(value_data, value_elt->str, value_datasz);

      } else {
        pr_trace_msg(trace_channel, 2,
          "expected STRING element at index %u, got %s", i + 2,
          get_reply_type(value_elt->type));
      }

      if (key_data != NULL &&
          value_data != NULL) {
        if (pr_table_kadd(*hash, key_data, key_datasz, value_data,
            value_datasz) < 0) {
          pr_trace_msg(trace_channel, 2,
            "error adding key (%lu bytes), value (%lu bytes) to hash: %s",
            (unsigned long) key_datasz, (unsigned long) value_datasz,
            strerror(errno));
        }
      }
    }

    res = 0;

  } else {
    xerrno = ENOENT;
    res = -1;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  errno = xerrno;
  return res;
}

int pr_redis_hash_kincr(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, const char *field, size_t fieldsz, int32_t incr,
    int64_t *value) {
  int xerrno = 0, exists = FALSE;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      field == NULL ||
      fieldsz == 0) {
    errno = EINVAL;
    return -1;
  }

  exists = pr_redis_hash_kexists(redis, m, key, keysz, field, fieldsz);
  if (exists == FALSE) {
    errno = ENOENT;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis HINCRBY pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "HINCRBY";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %b %d", cmd, key, keysz, field,
    fieldsz, incr);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error incrementing field in hash using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);
  if (value != NULL) {
    *value = (int64_t) reply->integer;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

static int hash_scan(pool *p, pr_redis_t *redis, const char *key,
    size_t keysz, array_header *fields, char **cursor, int count) {
  int res = 0, xerrno = 0;
  const char *cmd = NULL;
  redisReply *reply;

  cmd = "HSCAN";
  pr_trace_msg(trace_channel, 7, "sending command: %s %s", cmd, *cursor);
  reply = redisCommand(redis->ctx, "%s %b %s COUNT %d", cmd, key, keysz,
    *cursor, count);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting fields of hash using key (%lu bytes), cursor '%s': %s",
      (unsigned long) keysz, *cursor, strerror(errno));
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_ARRAY) {
    pr_trace_msg(trace_channel, 2,
      "expected ARRAY reply for %s, got %s", cmd, get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    errno = EINVAL;
    return -1;
  }

  if (reply->elements == 2) {
    redisReply *elt;

    elt = reply->element[0];
    if (elt->type == REDIS_REPLY_STRING) {
      *cursor = pstrndup(p, elt->str, elt->len);

    } else {
      pr_trace_msg(trace_channel, 2,
        "expected STRING element at index 0, got %s",
        get_reply_type(elt->type));

      xerrno = EINVAL;
      res = -1;
    }

    if (res == 0) {
      elt = reply->element[1];
      if (elt->type == REDIS_REPLY_ARRAY) {
        register unsigned int i;

        pr_trace_msg(trace_channel, 7, "%s reply: %s %lu %s", cmd, *cursor,
          (unsigned long) elt->elements,
          elt->elements != 1 ? "elements" : "element");

        /* When using HSCAN, we iterate over ALL the fields of the hash,
         * key AND value.  Thus to get just the keys, we need every other
         * item.
         */
        for (i = 1; i < elt->elements; i += 2) {
          redisReply *item;

          item = elt->element[i];
          if (item->type == REDIS_REPLY_STRING) {
            char *field;

            field = pstrndup(p, item->str, item->len);
            *((char **) push_array(fields)) = field;

          } else {
            pr_trace_msg(trace_channel, 2,
              "expected STRING element at index %u, got %s", i,
              get_reply_type(elt->type));
          }
        }

        if (strcmp(*cursor, "0") == 0) {
          /* Set the cursor to NULL, to indicate to the caller the end
           * of the iteration.
           */
          *cursor = NULL;
        }

      } else {
        pr_trace_msg(trace_channel, 2,
          "expected ARRAY element at index 1, got %s",
          get_reply_type(elt->type));

        xerrno = EINVAL;
        res = -1;
      }
    }

  } else {
    xerrno = ENOENT;
    res = -1;
  }

  freeReplyObject(reply);
  errno = xerrno;
  return res;
}

int pr_redis_hash_kkeys(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz, array_header **fields) {
  int res = 0, xerrno = 0;
  pool *tmp_pool = NULL;
  char *cursor;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      fields == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis HSCAN pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cursor = "0";
  res = 0;
  *fields = make_array(p, 0, sizeof(char *));

  while (res == 0 &&
         cursor != NULL) {
    pr_signals_handle();

    res = hash_scan(tmp_pool, redis, key, keysz, *fields, &cursor,
      PR_REDIS_SCAN_SIZE);
    xerrno = errno;

    if (res < 0) {
      destroy_pool(tmp_pool);

      errno = xerrno;
      return -1;
    }
  }

  if ((*fields)->nelts == 0) {
    *fields = NULL;
    xerrno = ENOENT;
    res = -1;
  }

  destroy_pool(tmp_pool);
  errno = xerrno;
  return res;
}

int pr_redis_hash_kremove(pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {

  /* Note: We can actually use just DEL here. */
  return pr_redis_kremove(redis, m, key, keysz);
}

int pr_redis_hash_kset(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, const char *field, size_t fieldsz, void *value,
    size_t valuesz) {
  int xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      field == NULL ||
      fieldsz == 0 ||
      value == NULL ||
      valuesz == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis HSET pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "HSET";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %b %b", cmd, key, keysz, field,
    fieldsz, value, valuesz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error setting item for field in hash using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_hash_ksetall(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, pr_table_t *hash) {
  int count, xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  array_header *args, *arglens;
  redisReply *reply;
  const void *key_data;
  size_t key_datasz;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      hash == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Skip any empty hashes. */
  count = pr_table_count(hash);
  if (count <= 0) {
    pr_trace_msg(trace_channel, 9, "skipping empty table");
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis HMSET pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "HMSET";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);

  args = make_array(tmp_pool, count + 1, sizeof(char *));
  arglens = make_array(tmp_pool, count + 1, sizeof(size_t));

  *((char **) push_array(args)) = pstrdup(tmp_pool, cmd);
  *((size_t *) push_array(arglens)) = strlen(cmd);

  *((char **) push_array(args)) = (char *) key;
  *((size_t *) push_array(arglens)) = keysz;

  pr_table_rewind(hash);
  key_data = pr_table_knext(hash, &key_datasz);
  while (key_data != NULL) {
    const void *value_data;
    size_t value_datasz;

    pr_signals_handle();

    value_data = pr_table_kget(hash, key_data, key_datasz, &value_datasz);
    if (value_data != NULL) {
      char *key_dup, *value_dup;

      key_dup = palloc(tmp_pool, key_datasz);
      memcpy(key_dup, key_data, key_datasz);
      *((char **) push_array(args)) = key_dup;
      *((size_t *) push_array(arglens)) = key_datasz;

      value_dup = palloc(tmp_pool, value_datasz);
      memcpy(value_dup, value_data, value_datasz);
      *((char **) push_array(args)) = value_dup;
      *((size_t *) push_array(arglens)) = value_datasz;
    }

    key_data = pr_table_knext(hash, &key_datasz);
  }

  reply = redisCommandArgv(redis->ctx, args->nelts, args->elts, arglens->elts);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error setting hash using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_STRING &&
      reply->type != REDIS_REPLY_STATUS) {
    pr_trace_msg(trace_channel, 2,
      "expected STRING or STATUS reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %.*s", cmd, (int) reply->len,
    reply->str);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_hash_kvalues(pool *p, pr_redis_t *redis, module *m,
    const char *key, size_t keysz, array_header **values) {
  int res, xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      values == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis HVALS pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "HVALS";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b", cmd, key, keysz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting values of hash using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_ARRAY) {
    pr_trace_msg(trace_channel, 2,
      "expected ARRAY reply for %s, got %s", cmd, get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  if (reply->elements > 0) {
    register unsigned int i;

    pr_trace_msg(trace_channel, 7, "%s reply: %lu %s", cmd,
      (unsigned long) reply->elements,
      reply->elements != 1 ? "elements" : "element");

    *values = make_array(p, reply->elements, sizeof(char *));
    for (i = 0; i < reply->elements; i++) {
      redisReply *elt;

      elt = reply->element[i];
      if (elt->type == REDIS_REPLY_STRING) {
        char *value;

        value = pcalloc(p, reply->len + 1);
        memcpy(value, reply->str, reply->len);
        *((char **) push_array(*values)) = value;

      } else {
        pr_trace_msg(trace_channel, 2,
          "expected STRING element at index %u, got %s", i,
          get_reply_type(elt->type));
      }
    }

    res = 0;

  } else {
    xerrno = ENOENT;
    res = -1;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  errno = xerrno;
  return res;
}

int pr_redis_list_kappend(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz) {
  return pr_redis_list_kpush(redis, m, key, keysz, value, valuesz,
    PR_REDIS_LIST_FL_RIGHT);
}

int pr_redis_list_kcount(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, uint64_t *count) {
  int xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      count == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis LLEN pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "LLEN";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b", cmd, key, keysz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting count of list using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);
  *count = (uint64_t) reply->integer;

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_list_kdelete(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz) {
  int xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;
  long long count = 0;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis LREM pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "LREM";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b 0 %b", cmd, key, keysz, value,
    valuesz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error deleting item from set using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);
  count = reply->integer;

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  if (count == 0) {
    /* No items removed. */
    errno = ENOENT;
    return -1;
  }

  return 0;
}

int pr_redis_list_kexists(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, unsigned int idx) {
  pool *tmp_pool;
  int res, xerrno = 0;
  void *val = NULL;
  size_t valsz = 0;

  tmp_pool = make_sub_pool(NULL);
  res = pr_redis_list_kget(tmp_pool, redis, m, key, keysz, idx, &val, &valsz);
  xerrno = errno;
  destroy_pool(tmp_pool);

  if (res < 0) {
    if (xerrno != ENOENT) {
      errno = xerrno;
      return -1;
    }

    return FALSE;
  }

  return TRUE;
}

int pr_redis_list_kget(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz, unsigned int idx, void **value, size_t *valuesz) {
  int res, xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;
  uint64_t count;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (pr_redis_list_kcount(redis, m, key, keysz, &count) == 0) {
    if (count > 0 &&
        idx > 0 &&
        idx >= count) {
      pr_trace_msg(trace_channel, 14,
        "requested index %u exceeds list length %lu", idx,
        (unsigned long) count);
      errno = ERANGE;
      return -1;
    }
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis LINDEX pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "LINDEX";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %u", cmd, key, keysz, idx);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting item at index %u of list using key (%lu bytes): %s", idx,
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_STRING &&
      reply->type != REDIS_REPLY_NIL) {
    pr_trace_msg(trace_channel, 2,
      "expected STRING or NIL reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  if (reply->type == REDIS_REPLY_STRING) {
    pr_trace_msg(trace_channel, 7, "%s reply: %.*s", cmd, (int) reply->len,
      reply->str);
    *valuesz = reply->len;
    *value = palloc(p, reply->len);
    memcpy(*value, reply->str, reply->len);
    res = 0;

  } else {
    pr_trace_msg(trace_channel, 7, "%s reply: nil", cmd);
    xerrno = ENOENT;
    res = -1;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  errno = xerrno;
  return res;
}

static int list_scan(pool *p, pr_redis_t *redis, const char *key, size_t keysz,
    array_header *values, array_header *valueszs, int *cursor, int count) {
  int res = 0, xerrno = 0, range;
  const char *cmd = NULL;
  redisReply *reply;

  cmd = "LRANGE";

  /* Note: We use one less than the count to preserve [...) semantics of the
   * requested range, rather than Redis' [...] inclusive semantics.
   */
  range = *cursor + count - 1;
  pr_trace_msg(trace_channel, 7, "sending command: %s %d %d", cmd, *cursor,
    range);
  reply = redisCommand(redis->ctx, "%s %b %d %d", cmd, key, keysz,
    *cursor, range);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting items in list using key (%lu bytes), cursor %d: %s",
      (unsigned long) keysz, *cursor, strerror(errno));
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_ARRAY) {
    pr_trace_msg(trace_channel, 2,
      "expected ARRAY reply for %s, got %s", cmd, get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    errno = EINVAL;
    return -1;
  }

  if (reply->elements > 0) {
    register unsigned int i;

    pr_trace_msg(trace_channel, 7, "%s reply: %lu %s", cmd,
      (unsigned long) reply->elements,
      reply->elements != 1 ? "elements" : "element");

    for (i = 0; i < reply->elements; i++) {
      redisReply *value_elt;
      void *value_data = NULL;
      size_t value_datasz = 0;

      value_elt = reply->element[i];
      if (value_elt->type == REDIS_REPLY_STRING) {
        value_datasz = value_elt->len;
        value_data = palloc(p, value_datasz);
        memcpy(value_data, value_elt->str, value_datasz);

      } else {
        pr_trace_msg(trace_channel, 2,
          "expected STRING element at index %u, got %s", i+1,
          get_reply_type(value_elt->type));
      }

      if (value_data != NULL) {
        *((void **) push_array(values)) = value_data;
        *((size_t *) push_array(valueszs)) = value_datasz;
      }
    }

    if (reply->elements == 0) {
      /* Set the cursor to -1, to indicate to the caller the end of the
       * iteration.
       */
      *cursor = -1;

    } else {
      (*cursor) += reply->elements;
    }

    res = 0;

  } else {
    if (*cursor > 0) {
      /* If cursor is greater than zero, then we have found some elements,
       * and have reached the end of the iteration.
       */
      *cursor = -1;
      res = 0;

    } else {
      xerrno = ENOENT;
      res = -1;
    }
  }

  freeReplyObject(reply);
  errno = xerrno;
  return res;
}

int pr_redis_list_kgetall(pool *p, pr_redis_t *redis, module *m,
    const char *key, size_t keysz, array_header **values,
    array_header **valueszs) {
  int cursor, res = 0, xerrno = 0;
  pool *tmp_pool = NULL;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      values == NULL ||
      valueszs == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis LRANGE pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cursor = 0;
  res = 0;
  *values = make_array(p, 0, sizeof(void *));
  *valueszs = make_array(p, 0, sizeof(size_t));

  while (res == 0 &&
         cursor != -1) {
    pr_signals_handle();

    res = list_scan(tmp_pool, redis, key, keysz, *values, *valueszs, &cursor,
      PR_REDIS_SCAN_SIZE);
    xerrno = errno;

    if (res < 0) {
      destroy_pool(tmp_pool);

      errno = xerrno;
      return -1;
    }
  }

  if ((*values)->nelts == 0) {
    *values = *valueszs = NULL;
    xerrno = ENOENT;
    res = -1;
  }

  destroy_pool(tmp_pool);
  errno = xerrno;
  return res;
}

int pr_redis_list_kpop(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void **value, size_t *valuesz, int flags) {
  int res, xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);

  switch (flags) {
    case PR_REDIS_LIST_FL_RIGHT:
      pr_pool_tag(tmp_pool, "Redis RPOP pool");
      cmd = "RPOP";
      break;

    case PR_REDIS_LIST_FL_LEFT:
      pr_pool_tag(tmp_pool, "Redis LPOP pool");
      cmd = "LPOP";
      break;

    default:
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return -1;
  }

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b", cmd, key, keysz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error popping item from list using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_STRING &&
      reply->type != REDIS_REPLY_NIL) {
    pr_trace_msg(trace_channel, 2,
      "expected STRING or NIL reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  if (reply->type == REDIS_REPLY_STRING) {
    pr_trace_msg(trace_channel, 7, "%s reply: %.*s", cmd, (int) reply->len,
      reply->str);
    *valuesz = reply->len;
    *value = palloc(p, reply->len);
    memcpy(*value, reply->str, reply->len);
    res = 0;

  } else {
    pr_trace_msg(trace_channel, 7, "%s reply: nil", cmd);
    xerrno = ENOENT;
    res = -1;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  errno = xerrno;
  return res;
}

int pr_redis_list_kpush(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz, int flags) {
  int xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);

  switch (flags) {
    case PR_REDIS_LIST_FL_RIGHT:
      pr_pool_tag(tmp_pool, "Redis RPUSH pool");
      cmd = "RPUSH";
      break;

    case PR_REDIS_LIST_FL_LEFT:
      pr_pool_tag(tmp_pool, "Redis LPUSH pool");
      cmd = "LPUSH";
      break;

    default:
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return -1;
  }

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %b", cmd, key, keysz, value, valuesz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error pushing to list using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_list_kremove(pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {

  /* Note: We can actually use just DEL here. */
  return pr_redis_kremove(redis, m, key, keysz);
}

int pr_redis_list_krotate(pool *p, pr_redis_t *redis, module *m,
    const char *key, size_t keysz, void **value, size_t *valuesz) {
  int res = 0, xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis RPOPLPUSH pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "RPOPLPUSH";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %b", cmd, key, keysz, key, keysz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error rotating list using key (%lu bytes): %s", (unsigned long) keysz,
      strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_STRING &&
      reply->type != REDIS_REPLY_NIL) {
    pr_trace_msg(trace_channel, 2,
      "expected STRING or NIL reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  if (reply->type == REDIS_REPLY_STRING) {
    pr_trace_msg(trace_channel, 7, "%s reply: %.*s", cmd, (int) reply->len,
      reply->str);
    *valuesz = reply->len;
    *value = palloc(p, reply->len);
    memcpy(*value, reply->str, reply->len);
    res = 0;

  } else {
    pr_trace_msg(trace_channel, 7, "%s reply: nil", cmd);
    xerrno = ENOENT;
    res = -1;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  errno = xerrno;
  return res;
}

int pr_redis_list_kset(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, unsigned int idx, void *value, size_t valuesz) {
  int xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis LSET pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "LSET";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %u %b", cmd, key, keysz, idx, value,
    valuesz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error setting item at index %u in list using key (%lu bytes): %s", idx,
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_STRING &&
      reply->type != REDIS_REPLY_STATUS) {
    pr_trace_msg(trace_channel, 2,
      "expected STRING or STATUS reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %.*s", cmd, (int) reply->len,
    reply->str);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_list_ksetall(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, array_header *values, array_header *valueszs) {
  register unsigned int i;
  int res, xerrno = 0;
  pool *tmp_pool = NULL;
  array_header *args, *arglens;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      values == NULL ||
      values->nelts == 0 ||
      valueszs == NULL ||
      valueszs->nelts == 0 ||
      values->nelts != valueszs->nelts) {
    errno = EINVAL;
    return -1;
  }

  /* First, delete any existing list at this key; a set operation, in my mind,
   * is a complete overwrite.
   */
  res = pr_redis_list_kremove(redis, m, key, keysz);
  if (res < 0 &&
      errno != ENOENT) {
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis RPUSH pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "RPUSH";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);

  args = make_array(tmp_pool, 0, sizeof(char *));
  arglens = make_array(tmp_pool, 0, sizeof(size_t));

  *((char **) push_array(args)) = pstrdup(tmp_pool, cmd);
  *((size_t *) push_array(arglens)) = strlen(cmd);

  *((char **) push_array(args)) = (char *) key;
  *((size_t *) push_array(arglens)) = keysz;

  for (i = 0; i < values->nelts; i++) {
    pr_signals_handle();

    *((char **) push_array(args)) = ((char **) values->elts)[i];
    *((size_t *) push_array(arglens)) = ((size_t *) valueszs->elts)[i];
  }

  reply = redisCommandArgv(redis->ctx, args->nelts, args->elts, arglens->elts);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error setting items in list using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_set_kadd(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz) {
  int xerrno = 0, exists = FALSE;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == 0) {
    errno = EINVAL;
    return -1;
  }

  exists = pr_redis_set_kexists(redis, m, key, keysz, value, valuesz);
  if (exists == TRUE) {
    errno = EEXIST;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis SADD pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "SADD";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %b", cmd, key, keysz, value, valuesz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error adding to set using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_set_kcount(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, uint64_t *count) {
  int xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      count == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis SCARD pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "SCARD";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b", cmd, key, keysz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting count of set using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);
  *count = (uint64_t) reply->integer;

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_set_kdelete(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz) {
  int xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;
  long long count = 0;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis SREM pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "SREM";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %b", cmd, key, keysz, value, valuesz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error deleting item from set using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);
  count = reply->integer;

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  if (count == 0) {
    /* No items removed. */
    errno = ENOENT;
    return -1;
  }

  return 0;
}

int pr_redis_set_kexists(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz) {
  int xerrno = 0, exists = FALSE;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis SISMEMBER pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "SISMEMBER";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %b", cmd, key, keysz, value, valuesz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error checking item in set using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);
  exists = reply->integer ? TRUE : FALSE;

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return exists;
}

int pr_redis_set_kgetall(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz, array_header **values, array_header **valueszs) {
  int res = 0, xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      values == NULL ||
      valueszs == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis SMEMBERS pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "SMEMBERS";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b", cmd, key, keysz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting items in set using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_ARRAY) {
    pr_trace_msg(trace_channel, 2,
      "expected ARRAY reply for %s, got %s", cmd, get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  if (reply->elements > 0) {
    register unsigned int i;

    pr_trace_msg(trace_channel, 7, "%s reply: %lu %s", cmd,
      (unsigned long) reply->elements,
      reply->elements != 1 ? "elements" : "element");

    *values = make_array(p, 0, sizeof(void *));
    *valueszs = make_array(p, 0, sizeof(size_t));

    for (i = 0; i < reply->elements; i++) {
      redisReply *value_elt;
      void *value_data = NULL;
      size_t value_datasz = 0;

      value_elt = reply->element[i];
      if (value_elt->type == REDIS_REPLY_STRING) {
        value_datasz = value_elt->len;
        value_data = palloc(p, value_datasz);
        memcpy(value_data, value_elt->str, value_datasz);

      } else {
        pr_trace_msg(trace_channel, 2,
          "expected STRING element at index %u, got %s", i + 1,
          get_reply_type(value_elt->type));
      }

      if (value_data != NULL) {
        *((void **) push_array(*values)) = value_data;
        *((size_t *) push_array(*valueszs)) = value_datasz;
      }
    }

    res = 0;

  } else {
    xerrno = ENOENT;
    res = -1;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  errno = xerrno;
  return res;
}

int pr_redis_set_kremove(pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {

  /* Note: We can actually use just DEL here. */
  return pr_redis_kremove(redis, m, key, keysz);
}

int pr_redis_set_ksetall(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, array_header *values, array_header *valueszs) {
  register unsigned int i;
  int res, xerrno = 0;
  pool *tmp_pool = NULL;
  array_header *args, *arglens;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      values == NULL ||
      values->nelts == 0 ||
      valueszs == NULL ||
      valueszs->nelts == 0 ||
      values->nelts != valueszs->nelts) {
    errno = EINVAL;
    return -1;
  }

  /* First, delete any existing set at this key; a set operation, in my mind,
   * is a complete overwrite.
   */
  res = pr_redis_set_kremove(redis, m, key, keysz);
  if (res < 0 &&
      errno != ENOENT) {
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis SADD pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "SADD";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);

  args = make_array(tmp_pool, 0, sizeof(char *));
  arglens = make_array(tmp_pool, 0, sizeof(size_t));

  *((char **) push_array(args)) = pstrdup(tmp_pool, cmd);
  *((size_t *) push_array(arglens)) = strlen(cmd);

  *((char **) push_array(args)) = (char *) key;
  *((size_t *) push_array(arglens)) = keysz;

  for (i = 0; i < values->nelts; i++) {
    pr_signals_handle();

    *((char **) push_array(args)) = ((char **) values->elts)[i];
    *((size_t *) push_array(arglens)) = ((size_t *) valueszs->elts)[i];
  }

  reply = redisCommandArgv(redis->ctx, args->nelts, args->elts, arglens->elts);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error setting items in set using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_sorted_set_kadd(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz, float score) {
  int xerrno = 0, exists = FALSE;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == 0) {
    errno = EINVAL;
    return -1;
  }

  /* Note: We should probably detect the server version, and instead of using
   * a separate existence check, if server >= 3.0.2, use the NX/XX flags of
   * the ZADD command.
   */
  exists = pr_redis_sorted_set_kexists(redis, m, key, keysz, value, valuesz);
  if (exists == TRUE) {
    errno = EEXIST;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis ZADD pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "ZADD";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %f %b", cmd, key, keysz, score,
    value, valuesz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error adding to sorted set using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_sorted_set_kcount(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, uint64_t *count) {
  int xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      count == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis ZCARD pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "ZCARD";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b", cmd, key, keysz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting count of sorted set using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);
  *count = (uint64_t) reply->integer;

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_sorted_set_kdelete(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz) {
  int xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;
  long long count = 0;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis ZREM pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "ZREM";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %b", cmd, key, keysz, value, valuesz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error deleting item from sorted set using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);
  count = reply->integer;

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  if (count == 0) {
    /* No items removed. */
    errno = ENOENT;
    return -1;
  }

  return 0;
}

int pr_redis_sorted_set_kexists(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz) {
  int xerrno = 0, exists = FALSE;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == 0) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis ZRANK pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "ZRANK";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %b", cmd, key, keysz, value, valuesz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error checking item in sorted set using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER &&
      reply->type != REDIS_REPLY_NIL) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER or NIL reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  if (reply->type == REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);
    exists = TRUE;

  } else {
    pr_trace_msg(trace_channel, 7, "%s reply: nil", cmd);
    exists = FALSE;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return exists;
}

int pr_redis_sorted_set_kgetn(pool *p, pr_redis_t *redis, module *m,
    const char *key, size_t keysz, unsigned int offset, unsigned int len,
    array_header **values, array_header **valueszs, int flags) {
  int res = 0, xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (p == NULL ||
      redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      values == NULL ||
      valueszs == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);

  switch (flags) {
    case PR_REDIS_SORTED_SET_FL_ASC:
      pr_pool_tag(tmp_pool, "Redis ZRANGE pool");
      cmd = "ZRANGE";
      break;

    case PR_REDIS_SORTED_SET_FL_DESC:
      pr_pool_tag(tmp_pool, "Redis ZREVRANGE pool");
      cmd = "ZREVRANGE";
      break;

    default:
      errno = EINVAL;
      return -1;
  }

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);

  /* Since the the range is [start, stop] inclusive, and the function takes
   * a length, we need to subtract one for whose items these are.  Consider
   * an offset of 0, and a len of 1 -- to get just one item.  In that case,
   * stop would be 0 as well.
   */
  reply = redisCommand(redis->ctx, "%s %b %u %u", cmd, key, keysz, offset,
    offset + len - 1);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting %u %s in sorted set using key (%lu bytes): %s", len,
      len != 1 ? "items" : "item", (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_ARRAY) {
    pr_trace_msg(trace_channel, 2,
      "expected ARRAY reply for %s, got %s", cmd, get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  if (reply->elements > 0) {
    register unsigned int i;

    pr_trace_msg(trace_channel, 7, "%s reply: %lu %s", cmd,
      (unsigned long) reply->elements,
      reply->elements != 1 ? "elements" : "element");

    *values = make_array(p, 0, sizeof(void *));
    *valueszs = make_array(p, 0, sizeof(size_t));

    for (i = 0; i < reply->elements; i++) {
      redisReply *value_elt;
      void *value_data = NULL;
      size_t value_datasz = 0;

      value_elt = reply->element[i];
      if (value_elt->type == REDIS_REPLY_STRING) {
        value_datasz = value_elt->len;
        value_data = palloc(p, value_datasz);
        memcpy(value_data, value_elt->str, value_datasz);

      } else {
        pr_trace_msg(trace_channel, 2,
          "expected STRING element at index %u, got %s", i + 1,
          get_reply_type(value_elt->type));
      }

      if (value_data != NULL) {
        *((void **) push_array(*values)) = value_data;
        *((size_t *) push_array(*valueszs)) = value_datasz;
      }
    }

    res = 0;

  } else {
    xerrno = ENOENT;
    res = -1;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  errno = xerrno;
  return res;
}

int pr_redis_sorted_set_kincr(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz, float incr, float *score) {
  int res, xerrno, exists;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == 0 ||
      score == NULL) {
    errno = EINVAL;
    return -1;
  }

  exists = pr_redis_sorted_set_kexists(redis, m, key, keysz, value, valuesz);
  if (exists == FALSE) {
    errno = ENOENT;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis ZINCRBY pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "ZINCRBY";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %f %b", cmd, key, keysz, incr,
    value, valuesz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error incrementing key (%lu bytes) by %0.3f in sorted set using %s: %s",
      (unsigned long) keysz, incr, cmd, strerror(errno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return -1;
  }

  if (reply->type != REDIS_REPLY_STRING) {
    pr_trace_msg(trace_channel, 2,
      "expected STRING reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %.*s", cmd, (int) reply->len,
    reply->str);

  res = sscanf(reply->str, "%f", score);
  if (res != 1) {
    pr_trace_msg(trace_channel, 3, "error parsing '%.*s' as float",
      (int) reply->len, reply->str);
    xerrno = EINVAL;
    res = -1;

  } else {
    res = 0;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  errno = xerrno;
  return res;
}

int pr_redis_sorted_set_kremove(pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {

  /* Note: We can actually use just DEL here. */
  return pr_redis_kremove(redis, m, key, keysz);
}

int pr_redis_sorted_set_kscore(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz, float *score) {
  int res, xerrno;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == 0 ||
      score == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis ZSCORE pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "ZSCORE";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %b", cmd, key, keysz, value, valuesz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error gettin score for key (%lu bytes) using %s: %s",
      (unsigned long) keysz, cmd, strerror(errno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return -1;
  }

  if (reply->type != REDIS_REPLY_STRING &&
      reply->type != REDIS_REPLY_NIL) {
    pr_trace_msg(trace_channel, 2,
      "expected STRING or NIL reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  if (reply->type == REDIS_REPLY_STRING) {
    pr_trace_msg(trace_channel, 7, "%s reply: %.*s", cmd, (int) reply->len,
      reply->str);

    res = sscanf(reply->str, "%f", score);
    if (res != 1) {
      pr_trace_msg(trace_channel, 3, "error parsing '%.*s' as float",
        (int) reply->len, reply->str);
      xerrno = EINVAL;
      res = -1;

    } else {
      res = 0;
    }

  } else {
    pr_trace_msg(trace_channel, 7, "%s reply: nil", cmd);
    xerrno = ENOENT;
    res = -1;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  errno = xerrno;
  return res;
}

int pr_redis_sorted_set_kset(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz, float score) {
  int xerrno = 0, exists = FALSE;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      value == NULL ||
      valuesz == 0) {
    errno = EINVAL;
    return -1;
  }

  /* Note: We should probably detect the server version, and instead of using
   * a separate existence check, if server >= 3.0.2, use the NX/XX flags of
   * the ZADD command.
   */
  exists = pr_redis_sorted_set_kexists(redis, m, key, keysz, value, valuesz);
  if (exists == FALSE) {
    errno = ENOENT;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis ZADD pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "ZADD";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s %b %f %b", cmd, key, keysz, score,
    value, valuesz);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error setting item in sorted set using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

static char *f2s(pool *p, float num, size_t *len) {
  int res;
  char *s;
  size_t sz;

  sz = 32;
  s = pcalloc(p, sz + 1);
  res = pr_snprintf(s, sz, "%0.3f", num);

  *len = res;
  return s;
}

int pr_redis_sorted_set_ksetall(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, array_header *values, array_header *valueszs,
    array_header *scores) {
  register unsigned int i;
  int res, xerrno = 0;
  pool *tmp_pool = NULL;
  array_header *args, *arglens;
  const char *cmd = NULL;
  redisReply *reply;

  if (redis == NULL ||
      m == NULL ||
      key == NULL ||
      keysz == 0 ||
      values == NULL ||
      values->nelts == 0 ||
      valueszs == NULL ||
      valueszs->nelts == 0 ||
      scores == NULL ||
      scores->nelts == 0) {
    errno = EINVAL;
    return -1;
  }

  if (values->nelts != valueszs->nelts ||
      values->nelts != scores->nelts) {
    errno = EINVAL;
    return -1;
  }

  /* First, delete any existing sorted set at this key; a set operation,
   * in my mind, is a complete overwrite.
   */
  res = pr_redis_sorted_set_kremove(redis, m, key, keysz);
  if (res < 0 &&
      errno != ENOENT) {
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis ZADD pool");

  key = get_namespace_key(tmp_pool, redis, m, key, &keysz);

  cmd = "ZADD";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);

  args = make_array(tmp_pool, 0, sizeof(char *));
  arglens = make_array(tmp_pool, 0, sizeof(size_t));

  *((char **) push_array(args)) = pstrdup(tmp_pool, cmd);
  *((size_t *) push_array(arglens)) = strlen(cmd);

  *((char **) push_array(args)) = (char *) key;
  *((size_t *) push_array(arglens)) = keysz;

  for (i = 0; i < values->nelts; i++) {
    size_t scoresz = 0;

    pr_signals_handle();

    *((char **) push_array(args)) = f2s(tmp_pool, ((float *) scores->elts)[i],
      &scoresz);
    *((size_t *) push_array(arglens)) = scoresz;

    *((char **) push_array(args)) = ((char **) values->elts)[i];
    *((size_t *) push_array(arglens)) = ((size_t *) valueszs->elts)[i];
  }

  reply = redisCommandArgv(redis->ctx, args->nelts, args->elts, arglens->elts);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error setting items in sorted set using key (%lu bytes): %s",
      (unsigned long) keysz, strerror(errno));
    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (reply->type != REDIS_REPLY_INTEGER) {
    pr_trace_msg(trace_channel, 2,
      "expected INTEGER reply for %s, got %s", cmd,
      get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }
    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "%s reply: %lld", cmd, reply->integer);

  freeReplyObject(reply);
  destroy_pool(tmp_pool);
  return 0;
}

int pr_redis_sentinel_get_master_addr(pool *p, pr_redis_t *redis,
    const char *name, pr_netaddr_t **addr) {
  int res = 0, xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (p == NULL ||
      redis == NULL ||
      name == NULL ||
      addr == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis SENTINEL pool");

  cmd = "SENTINEL";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s get-master-addr-by-name %s", cmd, name);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting address for master '%s': %s", name, strerror(errno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return -1;
  }

  if (reply->type == REDIS_REPLY_NIL) {
    pr_trace_msg(trace_channel, 7, "%s reply: nil", cmd);
    freeReplyObject(reply);
    destroy_pool(tmp_pool);

    errno = ENOENT;
    return -1;
  }

  if (reply->type != REDIS_REPLY_ARRAY) {
    pr_trace_msg(trace_channel, 2,
      "expected ARRAY reply for %s, got %s", cmd, get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  if (reply->elements > 0) {
    redisReply *elt;
    char *host = NULL;
    int port = -1;

    pr_trace_msg(trace_channel, 7, "%s reply: %lu %s", cmd,
      (unsigned long) reply->elements,
      reply->elements != 1 ? "elements" : "element");

    elt = reply->element[0];
    if (elt->type == REDIS_REPLY_STRING) {
      host = pstrndup(tmp_pool, elt->str, elt->len);

    } else {
      pr_trace_msg(trace_channel, 2,
        "expected STRING element at index 0, got %s",
        get_reply_type(elt->type));
    }

    elt = reply->element[1];
    if (elt->type == REDIS_REPLY_STRING) {
      char *port_str;

      port_str = pstrndup(tmp_pool, elt->str, elt->len);
      port = atoi(port_str);

    } else {
      pr_trace_msg(trace_channel, 2,
        "expected STRING element at index 1, got %s",
        get_reply_type(elt->type));
    }

    if (host != NULL &&
        port != -1) {
      *addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, host, NULL);
      if (*addr != NULL) {
        pr_netaddr_set_port2(*addr, port);

      } else {
        xerrno = errno;
        res = -1;
      }

    } else {
      xerrno = ENOENT;
      res = -1;
    }

  } else {
    xerrno = ENOENT;
    res = -1;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  errno = xerrno;
  return res;
}

int pr_redis_sentinel_get_masters(pool *p, pr_redis_t *redis,
    array_header **masters) {
  int res = 0, xerrno = 0;
  pool *tmp_pool = NULL;
  const char *cmd = NULL;
  redisReply *reply;

  if (p == NULL ||
      redis == NULL ||
      masters == NULL) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(redis->pool);
  pr_pool_tag(tmp_pool, "Redis SENTINEL pool");

  cmd = "SENTINEL";
  pr_trace_msg(trace_channel, 7, "sending command: %s", cmd);
  reply = redisCommand(redis->ctx, "%s masters", cmd);
  xerrno = errno;

  reply = handle_reply(redis, cmd, reply);
  if (reply == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error getting masters: %s", strerror(errno));
    destroy_pool(tmp_pool);
    errno = EIO;
    return -1;
  }

  if (reply->type == REDIS_REPLY_NIL) {
    pr_trace_msg(trace_channel, 7, "%s reply: nil", cmd);
    freeReplyObject(reply);
    destroy_pool(tmp_pool);

    errno = ENOENT;
    return -1;
  }

  if (reply->type != REDIS_REPLY_ARRAY) {
    pr_trace_msg(trace_channel, 2,
      "expected ARRAY reply for %s, got %s", cmd, get_reply_type(reply->type));

    if (reply->type == REDIS_REPLY_ERROR) {
      pr_trace_msg(trace_channel, 2, "%s error: %s", cmd, reply->str);
    }

    freeReplyObject(reply);
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  if (reply->elements > 0) {
    register unsigned int i;

    pr_trace_msg(trace_channel, 7, "%s reply: %lu %s", cmd,
      (unsigned long) reply->elements,
      reply->elements != 1 ? "elements" : "element");

    *masters = make_array(p, reply->elements, sizeof(char *));

    for (i = 0; i < reply->elements; i++) {
      redisReply *elt;

      elt = reply->element[i];
      if (elt->type == REDIS_REPLY_ARRAY) {
        redisReply *info;

        info = elt->element[1];
        *((char **) push_array(*masters)) = pstrndup(p, info->str, info->len);

      } else {
        pr_trace_msg(trace_channel, 2,
          "expected ARRAY element at index %u, got %s", i,
          get_reply_type(elt->type));
      }
    }

  } else {
    xerrno = ENOENT;
    res = -1;
  }

  freeReplyObject(reply);
  destroy_pool(tmp_pool);

  errno = xerrno;
  return res;
}

int redis_set_server(const char *server, int port, unsigned long flags,
    const char *password, const char *db_idx) {

  if (server == NULL) {
    /* By using a port of -2 specifically, we can use this function to
     * clear the server/port, for testing purposes ONLY.
     */
    if (port < 1 &&
        port != -2) {
      errno = EINVAL;
      return -1;
    }
  }

  redis_server = server;
  redis_port = port;
  redis_flags = flags;
  redis_password = password;
  redis_db_idx = db_idx;

  return 0;
}

int redis_set_sentinels(array_header *sentinels, const char *name) {

  if (sentinels != NULL &&
      sentinels->nelts == 0) {
    errno = EINVAL;
    return -1;
  }

  redis_sentinels = sentinels;
  redis_sentinel_master = name;

  return 0;
}

int redis_set_timeouts(unsigned long connect_millis, unsigned long io_millis) {
  redis_connect_millis = connect_millis;
  redis_io_millis = io_millis;

  return 0;
}

int redis_clear(void) {
  if (sess_redis != NULL) {
    pr_redis_conn_destroy(sess_redis);
    sess_redis = NULL;
  }

  return 0;
}

int redis_init(void) {
  return 0;
}

#else

pr_redis_t *pr_redis_conn_get(pool *p, unsigned long flags) {
  errno = ENOSYS;
  return NULL;
}

pr_redis_t *pr_redis_conn_new(pool *p, module *m, unsigned long flags) {
  errno = ENOSYS;
  return NULL;
}

int pr_redis_conn_close(pr_redis_t *redis) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_conn_destroy(pr_redis_t *redis) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_conn_set_namespace(pr_redis_t *redis, module *m,
    const void *prefix, size_t prefixsz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_auth(pr_redis_t *redis, const char *password) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_select(pr_redis_t *redis, const char *db_idx) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_command(pr_redis_t *redis, const array_header *args,
    int reply_type) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_add(pr_redis_t *redis, module *m, const char *key, void *value,
    size_t valuesz, time_t expires) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_decr(pr_redis_t *redis, module *m, const char *key, uint32_t decr,
    uint64_t *value) {
  errno = ENOSYS;
  return -1;
}

void *pr_redis_get(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t *valuesz) {
  errno = ENOSYS;
  return NULL;
}

char *pr_redis_get_str(pool *p, pr_redis_t *redis, module *m, const char *key) {
  errno = ENOSYS;
  return NULL;
}

int pr_redis_incr(pr_redis_t *redis, module *m, const char *key, uint32_t incr,
    uint64_t *value) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_remove(pr_redis_t *redis, module *m, const char *key) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_rename(pr_redis_t *redis, module *m, const char *from,
    const char *to) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set(pr_redis_t *redis, module *m, const char *key, void *value,
    size_t valuesz, time_t expires) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_count(pr_redis_t *redis, module *m, const char *key,
    uint64_t *count) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_delete(pr_redis_t *redis, module *m, const char *key,
    const char *field) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_exists(pr_redis_t *redis, module *m, const char *key,
    const char *field) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_get(pool *p, pr_redis_t *redis, module *m, const char *key,
    const char *field, void **value, size_t *valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_getall(pool *p, pr_redis_t *redis, module *m,
    const char *key, pr_table_t **hash) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_incr(pr_redis_t *redis, module *m, const char *key,
    const char *field, int32_t incr, int64_t *value) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_keys(pool *p, pr_redis_t *redis, module *m, const char *key,
    array_header **fields) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_remove(pr_redis_t *redis, module *m, const char *key) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_set(pr_redis_t *redis, module *m, const char *key,
    const char *field, void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_setall(pr_redis_t *redis, module *m, const char *key,
    pr_table_t *hash) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_values(pool *p, pr_redis_t *redis, module *m,
    const char *key, array_header **values) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_append(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_count(pr_redis_t *redis, module *m, const char *key,
    uint64_t *count) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_delete(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_exists(pr_redis_t *redis, module *m, const char *key,
    unsigned int idx) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_get(pool *p, pr_redis_t *redis, module *m, const char *key,
    unsigned int idx, void **value, size_t *valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_getall(pool *p, pr_redis_t *redis, module *m, const char *key,
    array_header **values, array_header **valueszs) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_pop(pool *p, pr_redis_t *redis, module *m, const char *key,
    void **value, size_t *valuesz, int flags) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_push(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz, int flags) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_remove(pr_redis_t *redis, module *m, const char *key) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_rotate(pool *p, pr_redis_t *redis, module *m,
    const char *key, void **value, size_t *valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_set(pr_redis_t *redis, module *m, const char *key,
    unsigned int idx, void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_setall(pr_redis_t *redis, module *m, const char *key,
    array_header *values, array_header *valueszs) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set_add(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set_count(pr_redis_t *redis, module *m, const char *key,
    uint64_t *count) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set_delete(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set_exists(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set_getall(pool *p, pr_redis_t *redis, module *m, const char *key,
    array_header **values, array_header **valueszs) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set_remove(pr_redis_t *redis, module *m, const char *key) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set_setall(pr_redis_t *redis, module *m, const char *key,
    array_header *values, array_header *valueszs) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_add(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz, float score) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_count(pr_redis_t *redis, module *m, const char *key,
    uint64_t *count) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_delete(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_exists(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_getn(pool *p, pr_redis_t *redis, module *m,
    const char *key, unsigned int offset, unsigned int len,
    array_header **values, array_header **valueszs, int flags) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_incr(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz, float incr, float *score) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_remove(pr_redis_t *redis, module *m, const char *key) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_score(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz, float *score) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_set(pr_redis_t *redis, module *m, const char *key,
    void *value, size_t valuesz, float score) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_setall(pr_redis_t *redis, module *m, const char *key,
    array_header *values, array_header *valueszs, array_header *scores) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_kadd(pr_redis_t *redis, module *m, const char *key, size_t keysz,
    void *value, size_t valuesz, time_t expires) {
  errno = ENOSYS;
  return -1;
}

void *pr_redis_kget(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz, size_t *valuesz) {
  errno = ENOSYS;
  return NULL;
}

char *pr_redis_kget_str(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {
  errno = ENOSYS;
  return NULL;
}

int pr_redis_kremove(pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_krename(pr_redis_t *redis, module *m, const char *from,
    size_t fromsz, const char *to, size_t tosz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_kset(pr_redis_t *redis, module *m, const char *key, size_t keysz,
    void *value, size_t valuesz, time_t expires) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_kcount(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, uint64_t *count) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_kdelete(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, const char *field, size_t fieldsz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_kexists(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, const char *field, size_t fieldsz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_kget(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz, const char *field, size_t fieldsz, void **value,
    size_t *valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_kgetall(pool *p, pr_redis_t *redis, module *m,
    const char *key, size_t keysz, pr_table_t **hash) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_kincr(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, const char *field, size_t fieldsz, int32_t incr,
    int64_t *value) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_kkeys(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz, array_header **fields) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_kremove(pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_kset(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, const char *field, size_t fieldsz, void *value,
    size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_ksetall(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, pr_table_t *hash) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_hash_kvalues(pool *p, pr_redis_t *redis, module *m,
    const char *key, size_t keysz, array_header **values) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_kappend(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_kcount(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, uint64_t *count) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_kdelete(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_kexists(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, unsigned int idx) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_kget(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz, unsigned int idx, void **value, size_t *valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_kgetall(pool *p, pr_redis_t *redis, module *m,
    const char *key, size_t keysz, array_header **values,
    array_header **valueszs) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_kpop(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void **value, size_t *valuesz, int flags) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_kpush(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz, int flags) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_kremove(pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_krotate(pool *p, pr_redis_t *redis, module *m,
    const char *key, size_t keysz, void **value, size_t *valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_kset(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, unsigned int idx, void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_list_ksetall(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, array_header *values, array_header *valueszs) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set_kadd(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set_kcount(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, uint64_t *count) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set_kdelete(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set_kexists(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set_kgetall(pool *p, pr_redis_t *redis, module *m, const char *key,
    size_t keysz, array_header **values, array_header **valueszs) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set_kremove(pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_set_ksetall(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, array_header *values, array_header *valueszs) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_kadd(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz, float score) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_kcount(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, uint64_t *count) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_kdelete(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_kexists(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_kgetn(pool *p, pr_redis_t *redis, module *m,
    const char *key, size_t keysz, unsigned int offset, unsigned int len,
    array_header **values, array_header **valueszs, int flags) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_kincr(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz, float incr, float *score) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_kremove(pr_redis_t *redis, module *m, const char *key,
    size_t keysz) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_kscore(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz, float *score) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_kset(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz, float score) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sorted_set_ksetall(pr_redis_t *redis, module *m, const char *key,
    size_t keysz, array_header *values, array_header *valueszs,
    array_header *scores) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sentinel_get_master_addr(pool *p, pr_redis_t *redis,
    const char *name, pr_netaddr_t **addr) {
  errno = ENOSYS;
  return -1;
}

int pr_redis_sentinel_get_masters(pool *p, pr_redis_t *redis,
    array_header **masters) {
  errno = ENOSYS;
  return -1;
}

int redis_set_server(const char *server, int port, unsigned long flags,
    const char *password, const char *db_idx) {
  errno = ENOSYS;
  return -1;
}

int redis_set_sentinels(array_header *sentinels, const char *name) {
  errno = ENOSYS;
  return -1;
}

int redis_set_timeouts(unsigned long conn_millis, unsigned long io_millis) {
  errno = ENOSYS;
  return -1;
}

int redis_clear(void) {
  errno = ENOSYS;
  return -1;
}

int redis_init(void) {
  errno = ENOSYS;
  return -1;
}

#endif /* PR_USE_REDIS */
