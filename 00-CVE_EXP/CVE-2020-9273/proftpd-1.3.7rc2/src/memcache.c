/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2010-2016 The ProFTPD Project team
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

/* Memcache management */

#include "conf.h"

#ifdef PR_USE_MEMCACHE

#include "hanson-tpl.h"
#include <libmemcached/memcached.h>

#if defined(LIBMEMCACHED_VERSION_HEX)
# if LIBMEMCACHED_VERSION_HEX < 0x00041000
#  error "libmemcached-0.41 or later required"
# endif /* LIBMEMCACHED_VERSION_HEX too old */
#else
# error "Unable to determine libmemcached version"
#endif /* LIBMEMCACHED_VERSION_HEX */

/* libmemcached-0.41 and later included this header file. */
#include <libmemcached/util.h>

extern tpl_hook_t tpl_hook;

struct mcache_rec {
  pool *pool;
  module *owner;
  memcached_st *mc;

  /* For tracking the number of "opens"/"closes" on a shared mcache_rec,
   * as the same struct might be used by multiple modules in the same
   * session, each module doing a conn_get()/conn_close().
   */
  unsigned int refcount;

  /* Table mapping modules to their namespaces */
  pr_table_t *namespace_tab;
};

static memcached_server_st *configured_server_list = NULL;
static pr_memcache_t *sess_mcache = NULL;

static uint64_t memcache_sess_conn_failures = 0;
static unsigned long memcache_sess_flags = 0;
static uint64_t memcache_sess_nreplicas = 0;

static unsigned long memcache_conn_millis = 500;
static unsigned long memcache_rcv_millis = 500;
static unsigned long memcache_snd_millis = 500;
static unsigned long memcache_ejected_sec = 0;

#if 0
/* XXX Unused, for now. */
static unsigned long memcache_ping_interval = 0;
#endif

static const char *trace_channel = "memcache";

static int mcache_set_options(pr_memcache_t *mcache, unsigned long flags,
    uint64_t nreplicas) {
  memcached_return res;
  uint64_t val;

  val = memcached_behavior_get(mcache->mc, MEMCACHED_BEHAVIOR_TCP_NODELAY);
  if (val != 1) {
    res = memcached_behavior_set(mcache->mc, MEMCACHED_BEHAVIOR_TCP_NODELAY, 1);
    if (res != MEMCACHED_SUCCESS) {
      pr_trace_msg(trace_channel, 4,
        "error setting TCP_NODELAY behavior on connection: %s",
        memcached_strerror(mcache->mc, res));
    }
  }

  /* Enable caching of DNS lookups. */
  val = memcached_behavior_get(mcache->mc, MEMCACHED_BEHAVIOR_CACHE_LOOKUPS);
  if (val != 1) {
    res = memcached_behavior_set(mcache->mc, MEMCACHED_BEHAVIOR_CACHE_LOOKUPS,
      1);
    if (res != MEMCACHED_SUCCESS) {
      pr_trace_msg(trace_channel, 4,
        "error setting CACHE_LOOKUPS behavior on connection: %s",
        memcached_strerror(mcache->mc, res));
    }
  }

  /* Verify that all keys are correct. */
  val = memcached_behavior_get(mcache->mc, MEMCACHED_BEHAVIOR_VERIFY_KEY);
  if (val != 1) {
    res = memcached_behavior_set(mcache->mc, MEMCACHED_BEHAVIOR_VERIFY_KEY, 1);
    if (res != MEMCACHED_SUCCESS) {
      pr_trace_msg(trace_channel, 4,
        "error setting VERIFY_KEY behavior on connection: %s",
        memcached_strerror(mcache->mc, res));
    }
  }

  /* We always want consistent hashing, to minimize cache churn when
   * servers are added/removed from the list.
   */
  val = memcached_behavior_get(mcache->mc, MEMCACHED_BEHAVIOR_DISTRIBUTION);
  if (val != MEMCACHED_DISTRIBUTION_CONSISTENT) {
    res = memcached_behavior_set(mcache->mc, MEMCACHED_BEHAVIOR_DISTRIBUTION,
      MEMCACHED_DISTRIBUTION_CONSISTENT);
    if (res != MEMCACHED_SUCCESS) {
      pr_trace_msg(trace_channel, 4,
        "error setting DISTRIBUTION_CONSISTENT behavior on connection: %s",
        memcached_strerror(mcache->mc, res));
    }
  }

  /* Use blocking IO */
  val = memcached_behavior_get(mcache->mc, MEMCACHED_BEHAVIOR_NO_BLOCK);
  if (val != 0) {
    res = memcached_behavior_set(mcache->mc, MEMCACHED_BEHAVIOR_NO_BLOCK, 0);
    if (res != MEMCACHED_SUCCESS) {
      pr_trace_msg(trace_channel, 4,
        "error setting NO_BLOCK behavior on connection: %s",
        memcached_strerror(mcache->mc, res));
    }
  }

  val = memcached_behavior_get(mcache->mc,
    MEMCACHED_BEHAVIOR_SERVER_FAILURE_LIMIT);
  if (memcache_sess_conn_failures > 0) {
    res = memcached_behavior_set(mcache->mc,
      MEMCACHED_BEHAVIOR_SERVER_FAILURE_LIMIT, memcache_sess_conn_failures);

    if (res != MEMCACHED_SUCCESS) {
      pr_trace_msg(trace_channel, 4,
        "error setting SERVER_FAILURE_LIMIT behavior on connection: %s",
        memcached_strerror(mcache->mc, res));

    } else {
      /* Automatically eject hosts which have reached this failure limit;
       * keeping them around in the memcached_st struct only causes
       * confusion.  Note that this requires that an ejected timeout value
       * be configured.
       */

      if (memcache_ejected_sec > 0) {
        res = memcached_behavior_set(mcache->mc,
          MEMCACHED_BEHAVIOR_RETRY_TIMEOUT, memcache_ejected_sec);
        if (res != MEMCACHED_SUCCESS) {
          pr_trace_msg(trace_channel, 4,
            "error setting RETRY_TIMEOUT behavior on connection to %lu ms: %s",
            memcache_ejected_sec, memcached_strerror(mcache->mc, res));
        }

        res = memcached_behavior_set(mcache->mc,
          MEMCACHED_BEHAVIOR_AUTO_EJECT_HOSTS, 1);
        if (res != MEMCACHED_SUCCESS) {
          pr_trace_msg(trace_channel, 4,
            "error setting AUTO_EJECT_HOSTS behavior on connection: %s",
            memcached_strerror(mcache->mc, res));
        }
      }
    }
  }

  /* Use the binary protocol by default, unless explicitly requested not to. */
  val = memcached_behavior_get(mcache->mc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL);
  pr_trace_msg(trace_channel, 16,
    "found BINARY_PROTOCOL=%s default behavior (val %lu) for connection",
    val != 1 ? "false" : "true", (unsigned long) val);

  if (val != 1) {
    if (!(flags & PR_MEMCACHE_FL_NO_BINARY_PROTOCOL)) {
      res = memcached_behavior_set(mcache->mc,
        MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);
      if (res != MEMCACHED_SUCCESS) {
        pr_trace_msg(trace_channel, 4,
          "error setting BINARY_PROTOCOL=true behavior on connection: %s",
          memcached_strerror(mcache->mc, res));

      } else {
        pr_trace_msg(trace_channel, 16, "%s",
          "set BINARY_PROTOCOL=true for connection");
      }
    }

  } else {
    if (flags & PR_MEMCACHE_FL_NO_BINARY_PROTOCOL) {
      res = memcached_behavior_set(mcache->mc,
        MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 0);
      if (res != MEMCACHED_SUCCESS) {
        pr_trace_msg(trace_channel, 4,
          "error setting BINARY_PROTOCOL=false behavior on connection: %s",
          memcached_strerror(mcache->mc, res));

      } else {
        pr_trace_msg(trace_channel, 16, "%s",
          "set BINARY_PROTOCOL=false for connection");
      }
    }
  }

  /* Configure the timeouts. */
  res = memcached_behavior_set(mcache->mc, MEMCACHED_BEHAVIOR_CONNECT_TIMEOUT,
    memcache_conn_millis);
  if (res != MEMCACHED_SUCCESS) {
    pr_trace_msg(trace_channel, 4,
      "error setting CONNECT_TIMEOUT behavior on connection to %lu ms: %s",
      memcache_conn_millis, memcached_strerror(mcache->mc, res));
  }

  res = memcached_behavior_set(mcache->mc, MEMCACHED_BEHAVIOR_RCV_TIMEOUT,
    memcache_rcv_millis);
  if (res != MEMCACHED_SUCCESS) {
    pr_trace_msg(trace_channel, 4,
      "error setting RCV_TIMEOUT behavior on connection to %lu ms: %s",
      memcache_rcv_millis, memcached_strerror(mcache->mc, res));
  }

  res = memcached_behavior_set(mcache->mc, MEMCACHED_BEHAVIOR_SND_TIMEOUT,
    memcache_snd_millis);
  if (res != MEMCACHED_SUCCESS) {
    pr_trace_msg(trace_channel, 4,
      "error setting SND_TIMEOUT behavior on connection to %lu ms: %s",
      memcache_snd_millis, memcached_strerror(mcache->mc, res));
  }

  /* Make sure that the requested number of replicas does not exceed the
   * server count.
   */
  if (nreplicas > memcached_server_count(mcache->mc)) {
    nreplicas = memcached_server_count(mcache->mc);
  }

  /* XXX Some caveats about libmemcached replication:
   *
   *  1.  Replication is enabled only if the binary protocol is used.
   *  2.  Replication occurs only for 'delete', 'get, 'set' operations, NOT
   *      'add', 'cas', 'incr', 'decr', etc.
   */

  if (nreplicas > 0 &&
      !(flags & PR_MEMCACHE_FL_NO_BINARY_PROTOCOL)) {

    res = memcached_behavior_set(mcache->mc,
      MEMCACHED_BEHAVIOR_NUMBER_OF_REPLICAS, nreplicas);
    if (res != MEMCACHED_SUCCESS) {
      pr_trace_msg(trace_channel, 4,
        "error setting NUMBER_OF_REPLICAS behavior on connection: %s",
        memcached_strerror(mcache->mc, res));

    } else {
      pr_trace_msg(trace_channel, 9, "storing %lu %s",
        (unsigned long) nreplicas, nreplicas != 1 ? "replicas" : "replica");
    }
  }

  /* Use randomized reads from replicas by default, unless explicitly
   * requested not to.
   */
  val = memcached_behavior_get(mcache->mc,
    MEMCACHED_BEHAVIOR_RANDOMIZE_REPLICA_READ);
  if (val != 1) {
    if (!(flags & PR_MEMCACHE_FL_NO_RANDOM_REPLICA_READ)) {
      res = memcached_behavior_set(mcache->mc,
        MEMCACHED_BEHAVIOR_RANDOMIZE_REPLICA_READ, 1);

      if (res != MEMCACHED_SUCCESS) {
        pr_trace_msg(trace_channel, 4,
          "error setting RANDOMIZE_REPLICA_READ behavior on connection: %s",
          memcached_strerror(mcache->mc, res));
      }
    }
  }

  return 0;
}

static int mcache_ping_servers(pr_memcache_t *mcache) {
  memcached_server_st *alive_server_list;
  memcached_return res;
  memcached_st *clone;
  uint32_t server_count;
  register unsigned int i;

  /* We always start with the configured list of servers. */
  clone = memcached_clone(NULL, mcache->mc);
  if (clone == NULL) {
    errno = ENOMEM;
    return -1;
  }

  memcached_servers_reset(clone);

  /* Bug#4242: Don't use memcached_server_push() if we're using
   * libmemcached-1.0.18 or earlier.  Doing so leads to a segfault, due to
   * this libmemcached bug:
   *
   *  https://bugs.launchpad.net/libmemcached/+bug/1154159
   */
#if LIBMEMCACHED_VERSION_HEX > 0x01000018
  memcached_server_push(clone, configured_server_list);
#endif

  server_count = memcached_server_count(clone);
  pr_trace_msg(trace_channel, 16,
    "pinging %lu memcached %s", (unsigned long) server_count,
    server_count != 1 ? "servers" : "server");

  alive_server_list = NULL;
  for (i = 0; i < server_count; i++) {
    memcached_server_instance_st server;

    server = memcached_server_instance_by_position(clone, i);

    pr_trace_msg(trace_channel, 17, "pinging server %s:%d",
      memcached_server_name(server), memcached_server_port(server));

    if (libmemcached_util_ping(memcached_server_name(server),
        memcached_server_port(server), &res) == FALSE) {
      pr_trace_msg(trace_channel, 4,
        "error pinging %s:%d: %s", memcached_server_name(server),
        memcached_server_port(server), memcached_strerror(clone, res));

    } else {
      pr_trace_msg(trace_channel, 17, "server %s:%d is alive",
        memcached_server_name(server), memcached_server_port(server));

       alive_server_list = memcached_server_list_append(alive_server_list,    
         memcached_server_name(server), memcached_server_port(server), &res);
       if (alive_server_list == NULL) {
         pr_trace_msg(trace_channel, 1,
           "error appending server %s:%d to list: %s",
           memcached_server_name(server), memcached_server_port(server),
           memcached_strerror(clone, res));

         memcached_free(clone);
         errno = EPERM;
         return -1;
       }
    }
  }

  if (alive_server_list != NULL) {
    memcached_servers_reset(mcache->mc);
    res = memcached_server_push(mcache->mc, alive_server_list);
    if (res != MEMCACHED_SUCCESS) {
      unsigned int count;

      count = memcached_server_list_count(alive_server_list);
      pr_trace_msg(trace_channel, 2,
        "error adding %u alive memcached %s to connection: %s",
        count, count != 1 ? "servers" : "server",
        memcached_strerror(mcache->mc, res));
      memcached_free(clone);
 
      errno = EPERM;
      return -1;

    } else {
      unsigned int count;

      count = memcached_server_list_count(alive_server_list);
      pr_trace_msg(trace_channel, 9,
        "now using %d alive memcached %s", count,
        count != 1 ? "servers" : "server");

      memcached_server_list_free(alive_server_list);
    }
  }

  memcached_free(clone);
  return 0;
}

static int mcache_stat_servers(pr_memcache_t *mcache) {
  memcached_stat_st *mst;
  memcached_return res;

  mst = memcached_stat(mcache->mc, NULL, &res);
  if (mst != NULL) {
    if (res == MEMCACHED_SUCCESS) {
      register unsigned int i;
      const char *stat_keys[] = {
        "version",
        "uptime",
        "curr_connections",
        "curr_items",
        "bytes",
        "limit_maxbytes",
        NULL
      };

      /* Log some of the stats about the memcached servers to which we just
       * connected.
       */  

      for (i = 0; stat_keys[i] != NULL; i++) {
        char *info;

        info = memcached_stat_get_value(mcache->mc, mst, stat_keys[i], &res);
        if (info != NULL) {
          pr_trace_msg(trace_channel, 9,
            "memcached server stats: %s = %s", stat_keys[i], info);
          free(info);

        } else {
          pr_trace_msg(trace_channel, 6,
            "unable to obtain '%s' stat: %s", stat_keys[i],
            memcached_strerror(mcache->mc, res));
        }
      }

    } else {
      switch (res) {
        case MEMCACHED_ERRNO:
          if (errno != EINPROGRESS) {
            pr_trace_msg(trace_channel, 3,
              "error requesting memcached stats: system error: %s",
              strerror(errno));

          } else {
            /* We know that we're not using nonblocking IO; this value usually
             * means that libmemcached could not connect to the configured
             * memcached servers.  So set the value to something more
             * indicative, and fall through.
             */
            res = MEMCACHED_CONNECTION_FAILURE;
          }
          break;

          case MEMCACHED_SOME_ERRORS:
          case MEMCACHED_SERVER_MARKED_DEAD:
          case MEMCACHED_CONNECTION_FAILURE: {
            memcached_server_instance_st server;

            server = memcached_server_get_last_disconnect(mcache->mc);
            if (server != NULL) {
              pr_trace_msg(trace_channel, 3,
                "unable to connect to %s:%d", memcached_server_name(server),
                memcached_server_port(server));
            }

            break;
          }

        default:
          pr_trace_msg(trace_channel, 6,
            "error requesting memcached stats: %s",
            memcached_strerror(mcache->mc, res));
          break;
      }
    }

    memcached_stat_free(mcache->mc, mst);
  }

  return 0;
}

pr_memcache_t *pr_memcache_conn_get(void) {
  if (sess_mcache != NULL) {
    sess_mcache->refcount++;
    return sess_mcache;
  }

  return pr_memcache_conn_new(session.pool, NULL, memcache_sess_flags,
    memcache_sess_nreplicas);
}

pr_memcache_t *pr_memcache_conn_new(pool *p, module *m, unsigned long flags,
    uint64_t nreplicas) {
  pr_memcache_t *mcache;
  pool *sub_pool;
  memcached_st *mc;
  memcached_return res;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (configured_server_list == NULL) {
    pr_trace_msg(trace_channel, 9, "%s",
      "unable to create new memcache connection: No servers configured");
    errno = EPERM;
    return NULL;
  }

  mc = memcached_create(NULL);
  if (mc == NULL) {
    errno = ENOMEM;
    return NULL;
  }

  res = memcached_server_push(mc, configured_server_list); 
  if (res != MEMCACHED_SUCCESS) {
    unsigned int count;

    count = memcached_server_list_count(configured_server_list);
    pr_trace_msg(trace_channel, 2,
      "error adding %u memcached %s to connection: %s",
      count, count != 1 ? "servers" : "server", memcached_strerror(mc, res));
    memcached_free(mc);

    errno = EPERM;
    return NULL;
  }

  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "Memcache connection pool");

  mcache = pcalloc(sub_pool, sizeof(pr_memcache_t));
  mcache->pool = sub_pool;
  mcache->owner = m;
  mcache->mc = mc;
  mcache->refcount = 1;

  /* The namespace table is null; it will be created if/when callers
   * configure namespace prefixes.
   */
  mcache->namespace_tab = NULL;

  /* Set some of the desired behavior flags on the connection */
  if (mcache_set_options(mcache, flags, nreplicas) < 0) {
    int xerrno = errno;

    pr_memcache_conn_close(mcache);
    destroy_pool(mcache->pool);

    errno = xerrno;
    return NULL;    
  }

  /* Check that all of the configured servers are alive and usable. */
  if (mcache_ping_servers(mcache) < 0) {
    int xerrno = errno;

    pr_memcache_conn_close(mcache);
    destroy_pool(mcache->pool);

    errno = xerrno;
    return NULL;    
  }

  /* Make sure we are connected to the configured servers by querying
   * some stats/info from them.
   */
  if (mcache_stat_servers(mcache) < 0) {
    int xerrno = errno;

    pr_memcache_conn_close(mcache);
    destroy_pool(mcache->pool);

    errno = xerrno;
    return NULL;    
  }

  if (sess_mcache == NULL) {
    sess_mcache = mcache;
  }

  return mcache;
}

int pr_memcache_conn_close(pr_memcache_t *mcache) {
  if (mcache == NULL) {
    errno = EINVAL;
    return -1;
  }

  mcache->refcount--;

  if (mcache->refcount == 0) {
    memcached_free(mcache->mc);

    if (mcache->namespace_tab != NULL) {
      (void) pr_table_empty(mcache->namespace_tab);
      (void) pr_table_free(mcache->namespace_tab);
      mcache->namespace_tab = NULL;
    }
  }

  return 0;
}

int pr_memcache_conn_clone(pool *p, pr_memcache_t *mcache) {
  memcached_st *old_mc = NULL, *new_mc = NULL;

  if (p == NULL ||
      mcache == NULL) {
    errno = EINVAL;
    return -1;
  }

  memcached_quit(mcache->mc);
  old_mc = mcache->mc;

  new_mc = memcached_clone(NULL, old_mc);
  if (new_mc == NULL) {
    errno = ENOMEM;
    return -1;
  }

  /* Now free up the previous context; we don't need it anymore. */
  memcached_free(old_mc);

  mcache->mc = new_mc;
  return 0;
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

int pr_memcache_conn_set_namespace(pr_memcache_t *mcache, module *m,
    const char *prefix) {

  if (mcache == NULL ||
      m == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (mcache->namespace_tab == NULL) {
    pr_table_t *tab;

    tab = pr_table_alloc(mcache->pool, 0);

    if (pr_table_ctl(tab, PR_TABLE_CTL_SET_KEY_CMP, modptr_cmp_cb) < 0) {
      pr_trace_msg(trace_channel, 4,
        "error setting key comparison callback for namespace table: %s",
        strerror(errno));
    }

    if (pr_table_ctl(tab, PR_TABLE_CTL_SET_KEY_HASH, modptr_hash_cb) < 0) {
      pr_trace_msg(trace_channel, 4,
        "error setting key hash callback for namespace table: %s",
        strerror(errno));
    }

    mcache->namespace_tab = tab;
  }

  if (prefix != NULL) {
    int count;
    size_t prefix_len;

    prefix_len = strlen(prefix);

    count = pr_table_kexists(mcache->namespace_tab, m, sizeof(module *));
    if (count <= 0) {
      if (pr_table_kadd(mcache->namespace_tab, m, sizeof(module *),
          pstrndup(mcache->pool, prefix, prefix_len), prefix_len) < 0) {
        pr_trace_msg(trace_channel, 7,
          "error adding namespace prefix '%s' for module 'mod_%s.c': %s",
          prefix, m->name, strerror(errno));
      }

    } else {
      if (pr_table_kset(mcache->namespace_tab, m, sizeof(module *),
          pstrndup(mcache->pool, prefix, prefix_len), prefix_len) < 0) {
        pr_trace_msg(trace_channel, 7,
          "error setting namespace prefix '%s' for module 'mod_%s.c': %s",
          prefix, m->name, strerror(errno));
      }
    }

  } else {
    /* A NULL prefix means the caller is removing their namespace mapping. */
    (void) pr_table_kremove(mcache->namespace_tab, m, sizeof(module *), NULL);
  }

  return 0;
}

int pr_memcache_add(pr_memcache_t *mcache, module *m, const char *key,
    void *value, size_t valuesz, time_t expires, uint32_t flags) {
  int res;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (mcache == NULL ||
      m == NULL ||
      key == NULL ||
      value == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_memcache_kadd(mcache, m, key, strlen(key), value, valuesz, expires,
    flags); 
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

int pr_memcache_decr(pr_memcache_t *mcache, module *m, const char *key,
    uint32_t decr, uint64_t *value) {
  int res;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (mcache == NULL ||
      m == NULL ||
      key == NULL ||
      decr == 0) {
    errno = EINVAL;
    return -1;
  }

  res = pr_memcache_kdecr(mcache, m, key, strlen(key), decr, value);
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

void *pr_memcache_get(pr_memcache_t *mcache, module *m, const char *key,
    size_t *valuesz, uint32_t *flags) {
  void *ptr = NULL;

  if (mcache == NULL ||
      m == NULL ||
      key == NULL ||
      valuesz == NULL ||
      flags == NULL) {
    errno = EINVAL;
    return NULL;
  }

  ptr = pr_memcache_kget(mcache, m, key, strlen(key), valuesz, flags);
  if (ptr == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error getting data for key '%s': %s", key, strerror(xerrno));

    xerrno = errno;
    return NULL;
  }

  return ptr;
}

char *pr_memcache_get_str(pr_memcache_t *mcache, module *m, const char *key,
    uint32_t *flags) {
  char *ptr = NULL;

  if (mcache == NULL ||
      m == NULL ||
      key == NULL ||
      flags == NULL) {
    errno = EINVAL;
    return NULL;
  }

  ptr = pr_memcache_kget_str(mcache, m, key, strlen(key), flags);
  if (ptr == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error getting data for key '%s': %s", key, strerror(xerrno));

    errno = xerrno; 
    return NULL;
  }

  return ptr;
}

int pr_memcache_incr(pr_memcache_t *mcache, module *m, const char *key,
    uint32_t incr, uint64_t *value) {
  int res;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (mcache == NULL ||
      m == NULL ||
      key == NULL ||
      incr == 0) {
    errno = EINVAL;
    return -1;
  }

  res = pr_memcache_kincr(mcache, m, key, strlen(key), incr, value);
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

int pr_memcache_remove(pr_memcache_t *mcache, module *m, const char *key,
    time_t expires) {
  int res;

  if (mcache == NULL ||
      m == NULL ||
      key == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_memcache_kremove(mcache, m, key, strlen(key), expires);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error removing key '%s': %s", key, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

int pr_memcache_set(pr_memcache_t *mcache, module *m, const char *key,
    void *value, size_t valuesz, time_t expires, uint32_t flags) {
  int res;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (mcache == NULL ||
      m == NULL ||
      key == NULL ||
      value == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_memcache_kset(mcache, m, key, strlen(key), value, valuesz, expires,
    flags);
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

static void mcache_set_module_namespace(pr_memcache_t *mcache, module *m) {
  memcached_return res = MEMCACHED_SUCCESS;

  if (m == NULL) {
    res = memcached_callback_set(mcache->mc, MEMCACHED_CALLBACK_PREFIX_KEY,
      NULL);

  } else {
    if (mcache->namespace_tab != NULL) {
      const char *v;

      v = pr_table_kget(mcache->namespace_tab, m, sizeof(module *), NULL);
      if (v != NULL) {
        pr_trace_msg(trace_channel, 25,
          "using namespace prefix '%s' for module 'mod_%s.c'", v, m->name);

        res = memcached_callback_set(mcache->mc, MEMCACHED_CALLBACK_PREFIX_KEY,
          (void *) v);
      }

    } else {
      res = MEMCACHED_SUCCESS;
    }
  }

  if (res != MEMCACHED_SUCCESS) {
    if (m != NULL) {
      pr_trace_msg(trace_channel, 9,
        "unable to set MEMCACHED_CALLBACK_PREFIX_KEY for module 'mod_%s.c': %s",
        m->name, memcached_strerror(mcache->mc, res));

    } else {
      pr_trace_msg(trace_channel, 9,
        "unable to clear MEMCACHED_CALLBACK_PREFIX_KEY: %s",
        memcached_strerror(mcache->mc, res));
    }
  }
}

int pr_memcache_kadd(pr_memcache_t *mcache, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz, time_t expires, uint32_t flags) {
  memcached_return res;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (mcache == NULL ||
      m == NULL ||
      key == NULL ||
      value == NULL) {
    errno = EINVAL;
    return -1;
  }

  mcache_set_module_namespace(mcache, m);
  res = memcached_add(mcache->mc, key, keysz, value, valuesz, expires, flags); 
  mcache_set_module_namespace(mcache, NULL);

  switch (res) {
    case MEMCACHED_SUCCESS:
      return 0;

    case MEMCACHED_ERRNO:
      if (errno != EINPROGRESS) {
        int xerrno = errno;

        pr_trace_msg(trace_channel, 3,
          "error adding key (%lu bytes), value (%lu bytes): system error: %s",
          (unsigned long) keysz, (unsigned long) valuesz, strerror(xerrno));

        errno = xerrno;

      } else {
        /* We know that we're not using nonblocking IO; this value usually
         * means that libmemcached could not connect to the configured
         * memcached servers.  So set the value to something more
         * indicative, and fall through.
         */
        res = MEMCACHED_CONNECTION_FAILURE;
      }
      break;

    case MEMCACHED_SERVER_MARKED_DEAD:
    case MEMCACHED_CONNECTION_FAILURE: {
      memcached_server_instance_st server;

      server = memcached_server_get_last_disconnect(mcache->mc);
      if (server != NULL) {
        pr_trace_msg(trace_channel, 3,
          "unable to connect to %s:%d", memcached_server_name(server),
          memcached_server_port(server));
      }

      break;
    }

    default:
      pr_trace_msg(trace_channel, 2,
        "error adding key (%lu bytes), value (%lu bytes): %s",
        (unsigned long) keysz, (unsigned long) valuesz,
        memcached_strerror(mcache->mc, res));
      errno = EPERM;
      break;
  }

  return -1;
}

int pr_memcache_kdecr(pr_memcache_t *mcache, module *m, const char *key,
    size_t keysz, uint32_t decr, uint64_t *value) {
  memcached_return res;

  if (mcache == NULL ||
      m == NULL ||
      key == NULL ||
      decr == 0) {
    errno = EINVAL;
    return -1;
  }

  /* Note: libmemcached automatically handles the case where value might be
   * NULL.
   */

  mcache_set_module_namespace(mcache, m);
  res = memcached_decrement(mcache->mc, key, keysz, decr, value);
  mcache_set_module_namespace(mcache, NULL);

  switch (res) {
    case MEMCACHED_SUCCESS:
      return 0;

    case MEMCACHED_ERRNO:
      if (errno != EINPROGRESS) {
        int xerrno = errno;

        pr_trace_msg(trace_channel, 3,
          "error decrementing key (%lu bytes) by %lu: system error: %s",
          (unsigned long) keysz, (unsigned long) decr, strerror(xerrno));

        errno = xerrno;

      } else {
        /* We know that we're not using nonblocking IO; this value usually
         * means that libmemcached could not connect to the configured
         * memcached servers.  So set the value to something more
         * indicative, and fall through.
         */
        res = MEMCACHED_CONNECTION_FAILURE;
      }
      break;

    case MEMCACHED_SERVER_MARKED_DEAD:
    case MEMCACHED_CONNECTION_FAILURE: {
      memcached_server_instance_st server;

      server = memcached_server_get_last_disconnect(mcache->mc);
      if (server != NULL) {
        pr_trace_msg(trace_channel, 3,
          "unable to connect to %s:%d", memcached_server_name(server),
          memcached_server_port(server));
      }

      break;
    }

    default:
      pr_trace_msg(trace_channel, 2,
        "error decrementing key (%lu bytes) by %lu: %s",
        (unsigned long) keysz, (unsigned long) decr,
        memcached_strerror(mcache->mc, res));
      errno = EPERM;
      break;
  }

  return -1;
}

void *pr_memcache_kget(pr_memcache_t *mcache, module *m, const char *key,
    size_t keysz, size_t *valuesz, uint32_t *flags) {
  char *data = NULL;
  void *ptr = NULL;
  memcached_return res;
  int xerrno = 0;

  if (mcache == NULL ||
      m == NULL ||
      key == NULL ||
      valuesz == NULL ||
      flags == NULL) {
    errno = EINVAL;
    return NULL;
  }

  mcache_set_module_namespace(mcache, m);
  data = memcached_get(mcache->mc, key, keysz, valuesz, flags, &res);
  xerrno = errno;
  mcache_set_module_namespace(mcache, NULL);

  if (data == NULL) {
    switch (res) {
      case MEMCACHED_NOTFOUND:
        pr_trace_msg(trace_channel, 8,
          "no data found for key (%lu bytes)", (unsigned long) keysz);
        errno = ENOENT;
        break;

      case MEMCACHED_ERRNO:
        if (errno != EINPROGRESS) {
          pr_trace_msg(trace_channel, 3,
            "no data found for key (%lu bytes): system error: %s",
            (unsigned long) keysz, strerror(xerrno));

          errno = xerrno;

        } else {
          /* We know that we're not using nonblocking IO; this value usually
           * means that libmemcached could not connect to the configured
           * memcached servers.  So set the value to something more
           * indicative, and fall through.
           */
          res = MEMCACHED_CONNECTION_FAILURE;
        }
        break;

      case MEMCACHED_SERVER_MARKED_DEAD:
      case MEMCACHED_CONNECTION_FAILURE: {
        memcached_server_instance_st server;

        server = memcached_server_get_last_disconnect(mcache->mc);
        if (server != NULL) {
          pr_trace_msg(trace_channel, 3,
            "unable to connect to %s:%d", memcached_server_name(server),
            memcached_server_port(server));
        }

        break;
      }

      default:
        pr_trace_msg(trace_channel, 6,
          "error getting data for key (%lu bytes): [%d] %s",
          (unsigned long) keysz, res, memcached_strerror(mcache->mc, res));
        errno = EPERM;
        break;
    }

    return NULL;
  }

  /* Create a duplicate of the returned data from the mcache's pool, so that
   * we can call free(3) on the data returned by libmemcached.
   */

  ptr = palloc(mcache->pool, *valuesz);
  memcpy(ptr, data, *valuesz);
  free(data);

  return ptr;
}

char *pr_memcache_kget_str(pr_memcache_t *mcache, module *m, const char *key,
    size_t keysz, uint32_t *flags) {
  char *data = NULL, *ptr = NULL;
  size_t valuesz = 0;
  memcached_return res;
  int xerrno = 0;

  if (mcache == NULL ||
      m == NULL ||
      key == NULL ||
      flags == NULL) {
    errno = EINVAL;
    return NULL;
  }

  mcache_set_module_namespace(mcache, m);
  data = memcached_get(mcache->mc, key, keysz, &valuesz, flags, &res);
  xerrno = errno;
  mcache_set_module_namespace(mcache, NULL);

  if (data == NULL) {
    switch (res) {
      case MEMCACHED_NOTFOUND:
        pr_trace_msg(trace_channel, 8,
          "no data found for key (%lu bytes)", (unsigned long) keysz);
        errno = ENOENT;
        break;

      case MEMCACHED_ERRNO:
        if (errno != EINPROGRESS) {
          pr_trace_msg(trace_channel, 3,
            "no data found for key (%lu bytes): system error: %s",
            (unsigned long) keysz, strerror(xerrno));

          errno = xerrno;

        } else {
          /* We know that we're not using nonblocking IO; this value usually
           * means that libmemcached could not connect to the configured
           * memcached servers.  So set the value to something more
           * indicative, and fall through.
           */
          res = MEMCACHED_CONNECTION_FAILURE;
        }
        break;

      case MEMCACHED_SERVER_MARKED_DEAD:
      case MEMCACHED_CONNECTION_FAILURE: {
        memcached_server_instance_st server;

        server = memcached_server_get_last_disconnect(mcache->mc);
        if (server != NULL) {
          pr_trace_msg(trace_channel, 3,
            "unable to connect to %s:%d", memcached_server_name(server),
            memcached_server_port(server));
        }

        break;
      }

      default:
        pr_trace_msg(trace_channel, 6,
          "error getting data for key (%lu bytes): [%d] %s",
          (unsigned long) keysz, res, memcached_strerror(mcache->mc, res));
        errno = EPERM;
        break;
    }

    return NULL;
  }

  /* Create a duplicate of the returned data from the mcache's pool, so that
   * we can call free(3) on the data returned by libmemcached.
   */

  ptr = pcalloc(mcache->pool, valuesz + 1);
  memcpy(ptr, data, valuesz);
  free(data);

  return ptr;
}

int pr_memcache_kincr(pr_memcache_t *mcache, module *m, const char *key,
    size_t keysz, uint32_t incr, uint64_t *value) {
  memcached_return res;

  if (mcache == NULL ||
      m == NULL ||
      key == NULL ||
      incr == 0) {
    errno = EINVAL;
    return -1;
  }

  /* Note: libmemcached automatically handles the case where value might be
   * NULL.
   */

  mcache_set_module_namespace(mcache, m);
  res = memcached_increment(mcache->mc, key, keysz, incr, value);
  mcache_set_module_namespace(mcache, NULL);

  if (res == MEMCACHED_NOTFOUND) {
    /* Automatically create a value for this key, with the given increment. */

    pr_trace_msg(trace_channel, 18,
      "unable to increment nonexistent key (%lu bytes), automatically "
      "creating one", (unsigned long) keysz);
    return pr_memcache_kset(mcache, m, key, keysz, &incr, sizeof(uint32_t),
      0, 0);
  }

  switch (res) {
    case MEMCACHED_SUCCESS:
      return 0;

    case MEMCACHED_ERRNO:
      if (errno != EINPROGRESS) {
        int xerrno = errno;

        pr_trace_msg(trace_channel, 3,
          "error incrementing key (%lu bytes) by %lu: system error: %s",
          (unsigned long) keysz, (unsigned long) incr, strerror(xerrno));

        errno = xerrno;

      } else {
        /* We know that we're not using nonblocking IO; this value usually
         * means that libmemcached could not connect to the configured
         * memcached servers.  So set the value to something more
         * indicative, and fall through.
         */
        res = MEMCACHED_CONNECTION_FAILURE;
      }
      break;

    case MEMCACHED_SERVER_MARKED_DEAD:
    case MEMCACHED_CONNECTION_FAILURE: {
      memcached_server_instance_st server;

      server = memcached_server_get_last_disconnect(mcache->mc);
      if (server != NULL) {
        pr_trace_msg(trace_channel, 3,
          "unable to connect to %s:%d", memcached_server_name(server),
          memcached_server_port(server));
      }

      break;
    }

    default:
      pr_trace_msg(trace_channel, 2,
        "error incrementing key (%lu bytes) by %lu: %s",
        (unsigned long) keysz, (unsigned long) incr,
        memcached_strerror(mcache->mc, res));
      errno = EPERM;
      break;
  }

  return -1;
}

int pr_memcache_kremove(pr_memcache_t *mcache, module *m, const char *key,
    size_t keysz, time_t expires) {
  memcached_return res;

  if (mcache == NULL ||
      m == NULL ||
      key == NULL) {
    errno = EINVAL;
    return -1;
  }

  mcache_set_module_namespace(mcache, m);
  res = memcached_delete(mcache->mc, key, keysz, expires);
  mcache_set_module_namespace(mcache, NULL);

  switch (res) {
    case MEMCACHED_SUCCESS:
      return 0;

    case MEMCACHED_ERRNO:
      if (errno != EINPROGRESS) {
        int xerrno = errno;

        pr_trace_msg(trace_channel, 3,
          "error removing key (%lu bytes): system error: %s",
          (unsigned long) keysz, strerror(xerrno));

        errno = xerrno;

      } else {
        /* We know that we're not using nonblocking IO; this value usually
         * means that libmemcached could not connect to the configured
         * memcached servers.  So set the value to something more
         * indicative, and fall through.
         */
        res = MEMCACHED_CONNECTION_FAILURE;
      }
      break;

    case MEMCACHED_SERVER_MARKED_DEAD:
    case MEMCACHED_CONNECTION_FAILURE: {
      memcached_server_instance_st server;

      server = memcached_server_get_last_disconnect(mcache->mc);
      if (server != NULL) {
        pr_trace_msg(trace_channel, 3,
          "unable to connect to %s:%d", memcached_server_name(server),
          memcached_server_port(server));
      }

      break;
    }

    default:
      pr_trace_msg(trace_channel, 2,
        "error removing key (%lu bytes): %s", (unsigned long) keysz,
        memcached_strerror(mcache->mc, res));
      errno = EPERM;
      break;
  }

  return -1;
}

int pr_memcache_kset(pr_memcache_t *mcache, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz, time_t expires, uint32_t flags) {
  memcached_return res;

  /* XXX Should we allow null values to be added, thus allowing use of keys
   * as sentinels?
   */
  if (mcache == NULL ||
      m == NULL ||
      key == NULL ||
      value == NULL) {
    errno = EINVAL;
    return -1;
  }

  mcache_set_module_namespace(mcache, m);
  res = memcached_set(mcache->mc, key, keysz, (const char *) value, valuesz,
    expires, flags);
  mcache_set_module_namespace(mcache, NULL);

  switch (res) {
    case MEMCACHED_SUCCESS:
      return 0;

    case MEMCACHED_ERRNO:
      if (errno != EINPROGRESS) {
        int xerrno = errno;

        pr_trace_msg(trace_channel, 3,
          "error setting key (%lu bytes), value (%lu bytes): system error: %s",
          (unsigned long) keysz, (unsigned long) valuesz, strerror(xerrno));

        errno = xerrno;

      } else {
        /* We know that we're not using nonblocking IO; this value usually
         * means that libmemcached could not connect to the configured
         * memcached servers.  So set the value to something more
         * indicative, and fall through.
         */
        res = MEMCACHED_CONNECTION_FAILURE;
      }
      break;

    case MEMCACHED_SERVER_MARKED_DEAD:
    case MEMCACHED_CONNECTION_FAILURE: {
      memcached_server_instance_st server;

      server = memcached_server_get_last_disconnect(mcache->mc);
      if (server != NULL) {
        pr_trace_msg(trace_channel, 3,
          "unable to connect to %s:%d", memcached_server_name(server),
          memcached_server_port(server));
      }

      break;
    }

    default:
      pr_trace_msg(trace_channel, 2,
        "error setting key (%lu bytes), value (%lu bytes): %s",
        (unsigned long) keysz, (unsigned long) valuesz,
        memcached_strerror(mcache->mc, res));
      errno = EPERM;
      break;
  }

  return -1;
}

unsigned long memcache_get_sess_flags(void) {
  return memcache_sess_flags;
}

int memcache_set_sess_connect_failures(uint64_t count) {
  memcache_sess_conn_failures = count;
  return 0;
}

int memcache_set_sess_flags(unsigned long flags) {
  memcache_sess_flags = flags;
  return 0;
}

int memcache_set_sess_replicas(uint64_t count) {
  if (count < 1) {
    errno = EINVAL;
    return -1;
  }

  memcache_sess_nreplicas = count;
  return 0;
}

int memcache_set_servers(void *server_list) {
  if (server_list == NULL) {
    errno = EINVAL;
    return -1;
  }

  configured_server_list = server_list;
  return 0;
}

int memcache_set_timeouts(unsigned long conn_millis, unsigned long read_millis,
    unsigned long write_millis, unsigned long ejected_sec) {
  memcache_conn_millis = conn_millis;
  memcache_rcv_millis = read_millis;
  memcache_snd_millis = write_millis;
  memcache_ejected_sec = ejected_sec;

  return 0;
}

static int memcache_tpl_oops(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  pr_trace_vmsg(trace_channel, 1, fmt, ap);
  va_end(ap);

  /* XXX Does tpl check the return value of its oops() hook? */
  return 0;
}

static void memcache_tpl_fatal(char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  pr_trace_vmsg(trace_channel, 1, fmt, ap);
  va_end(ap);

  _exit(1);
}

int memcache_clear(void) {
  if (sess_mcache != NULL) {
    pr_memcache_conn_close(sess_mcache);
    sess_mcache = NULL;
  }

  return 0;
}

int memcache_init(void) {

  /* Set the tpl callbacks */
  tpl_hook.oops = memcache_tpl_oops;
  tpl_hook.fatal = memcache_tpl_fatal;

  return 0;
}

#else

pr_memcache_t *pr_memcache_conn_get(void) {
  errno = ENOSYS;
  return NULL;
}

pr_memcache_t *pr_memcache_conn_new(pool *p, module *m, unsigned long flags,
    uint64_t nreplicas) {
  errno = ENOSYS;
  return NULL;
}

int pr_memcache_conn_close(pr_memcache_t *mcache) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_conn_clone(pool *p, pr_memcache_t *mcache) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_conn_set_namespace(pr_memcache_t *mcache, module *m,
    const char *prefix) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_add(pr_memcache_t *mcache, module *m, const char *key,
    void *value, size_t valuesz, time_t expires, uint32_t flags) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_decr(pr_memcache_t *mcache, module *m, const char *key,
    uint32_t decr, uint64_t *value) {
  errno = ENOSYS;
  return -1;
}

void *pr_memcache_get(pr_memcache_t *mcache, module *m, const char *key,
    size_t *valuesz, uint32_t *flags) {
  errno = ENOSYS;
  return NULL;
}

char *pr_memcache_get_str(pr_memcache_t *mcache, module *m, const char *key,
    uint32_t *flags) {
  errno = ENOSYS;
  return NULL;
}

int pr_memcache_incr(pr_memcache_t *mcache, module *m, const char *key,
    uint32_t incr, uint64_t *value) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_remove(pr_memcache_t *mcache, module *m, const char *key,
    time_t expires) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_set(pr_memcache_t *mcache, module *m, const char *key,
    void *value, size_t valuesz, time_t expires, uint32_t flags) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_kadd(pr_memcache_t *mcache, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz, time_t expires, uint32_t flags) {
  errno = ENOSYS;
  return -1;
}

void *pr_memcache_kget(pr_memcache_t *mcache, module *m, const char *key,
    size_t keysz, size_t *valuesz, uint32_t *flags) {
  errno = ENOSYS;
  return NULL;
}

char *pr_memcache_kget_str(pr_memcache_t *mcache, module *m, const char *key,
    size_t keysz, uint32_t *flags) {
  errno = ENOSYS;
  return NULL;
}

int pr_memcache_kremove(pr_memcache_t *mcache, module *m, const char *key,
    size_t keysz, time_t expires) {
  errno = ENOSYS;
  return -1;
}

int pr_memcache_kset(pr_memcache_t *mcache, module *m, const char *key,
    size_t keysz, void *value, size_t valuesz, time_t expires, uint32_t flags) {
  errno = ENOSYS;
  return -1;
}

unsigned long memcache_get_sess_flags(void) {
  return 0;
}

int memcache_set_sess_connect_failures(uint64_t count) {
  errno = ENOSYS;
  return -1;
}

int memcache_set_sess_flags(unsigned long flags) {
  errno = ENOSYS;
  return -1;
}

int memcache_set_sess_replicas(uint64_t count) {
  errno = ENOSYS;
  return -1;
}

int memcache_set_servers(void *server_list) {
  errno = ENOSYS;
  return -1;
}

int memcache_set_timeouts(unsigned long conn_millis, unsigned long read_millis,
    unsigned long write_millis, unsigned long ejected_sec) {
  errno = ENOSYS;
  return -1;
}

int memcache_clear(void) {
  errno = ENOSYS;
  return -1;
}

int memcache_init(void) {
  errno = ENOSYS;
  return -1;
}

#endif /* PR_USE_MEMCACHE */

