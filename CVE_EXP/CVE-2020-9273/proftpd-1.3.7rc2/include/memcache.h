/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2010-2015 The ProFTPD Project team
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

/* Memcache support */

#ifndef PR_MEMCACHE_H
#define PR_MEMCACHE_H

#include "conf.h"

typedef struct mcache_rec pr_memcache_t;

/* Core API for use by modules et al */

/* This function returns the pr_memcache_t for the current session; if one
 * does not exist, it will be allocated.
 */
pr_memcache_t *pr_memcache_conn_get(void);
pr_memcache_t *pr_memcache_conn_new(pool *p, module *owner,
  unsigned long flags, uint64_t nreplicas);
int pr_memcache_conn_close(pr_memcache_t *mcache);

/* Given an existing handle, quit that handle, and clone the internal
 * structures.  This is to be used by modules which need to get their own
 * process-specific handle, using a handle inherited from their parent process.
 */
int pr_memcache_conn_clone(pool *p, pr_memcache_t *mcache);

/* Set a namespace key prefix, to be used by this connection for all of the
 * operations involving items.  In practice, the key prefix should always
 * be a string which does contain any space characters.
 *
 * Different modules can use different namespace prefixes for their keys.
 * Setting NULL for the namespace prefix clears it.
 */
int pr_memcache_conn_set_namespace(pr_memcache_t *mcache, module *m,
  const char *prefix);

int pr_memcache_add(pr_memcache_t *mcache, module *m, const char *key,
  void *value, size_t valuesz, time_t expires, uint32_t flags);
int pr_memcache_decr(pr_memcache_t *mcache, module *m, const char *key,
  uint32_t decr, uint64_t *value);
void *pr_memcache_get(pr_memcache_t *mcache, module *m, const char *key,
  size_t *valuesz, uint32_t *flags);
char *pr_memcache_get_str(pr_memcache_t *mcache, module *m, const char *key,
  uint32_t *flags);
int pr_memcache_incr(pr_memcache_t *mcache, module *m, const char *key,
  uint32_t incr, uint64_t *value);
int pr_memcache_remove(pr_memcache_t *mcache, module *m, const char *key,
  time_t expires);
int pr_memcache_set(pr_memcache_t *mcache, module *m, const char *key,
  void *value, size_t valuesz, time_t expires, uint32_t flags);

/* Variants of the above, where the key values are arbitrary bits rather
 * than being assumed to be strings.
 */
int pr_memcache_kadd(pr_memcache_t *mcache, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz, time_t expires, uint32_t flags);
int pr_memcache_kdecr(pr_memcache_t *mcache, module *m, const char *key,
  size_t keysz, uint32_t decr, uint64_t *value);
void *pr_memcache_kget(pr_memcache_t *mcache, module *m, const char *key,
  size_t keysz, size_t *valuesz, uint32_t *flags);
char *pr_memcache_kget_str(pr_memcache_t *mcache, module *m, const char *key,
  size_t keysz, uint32_t *flags);
int pr_memcache_kincr(pr_memcache_t *mcache, module *m, const char *key,
  size_t keysz, uint32_t incr, uint64_t *value);
int pr_memcache_kremove(pr_memcache_t *mcache, module *m, const char *key,
  size_t keysz, time_t expires);
int pr_memcache_kset(pr_memcache_t *mcache, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz, time_t expires, uint32_t flags);

/* For internal use only */

unsigned long memcache_get_sess_flags(void);
#define PR_MEMCACHE_FL_NO_BINARY_PROTOCOL	0x001
#define PR_MEMCACHE_FL_NO_RANDOM_REPLICA_READ	0x002

int memcache_set_sess_connect_failures(uint64_t count);
int memcache_set_sess_flags(unsigned long flags);
int memcache_set_sess_replicas(uint64_t count);
int memcache_set_servers(void *server_list);

/* Configure the timeouts in millisecs.
 *
 * The last timeout argument is timeout in seconds.  When a server is marked
 * as "dead", that server will be automatically ejected from the pool of servers
 * used for storage/retrieval.  This "ejected timeout" argument configures the
 * number of seconds that an ejected server will be out of the pool, before
 * being added back in.
 */
int memcache_set_timeouts(unsigned long conn_millis, unsigned long read_millis,
  unsigned long write_millis, unsigned long ejected_sec);

int memcache_clear(void);
int memcache_init(void);

#endif /* PR_MEMCACHE_H */
