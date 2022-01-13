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

/* Redis support */

#ifndef PR_REDIS_H
#define PR_REDIS_H

#include "conf.h"

typedef struct redis_rec pr_redis_t;

/* Core API for use by modules et al */

/* This function returns the pr_redis_t for the current session; if one
 * does not exist, it will be allocated.
 */
pr_redis_t *pr_redis_conn_get(pool *p, unsigned long flags);
pr_redis_t *pr_redis_conn_new(pool *p, module *owner, unsigned long flags);

/* These flags are used for tweaking connection behaviors. */
#define PR_REDIS_CONN_FL_NO_RECONNECT		0x0001

int pr_redis_conn_close(pr_redis_t *redis);
int pr_redis_conn_destroy(pr_redis_t *redis);

/* Set a namespace key prefix, to be used by this connection for all of the
 * operations involving items.  In practice, the key prefix should always
 * be a string which does contain any space characters.
 *
 * Different modules can use different namespace prefixes for their keys.
 * Setting NULL for the namespace prefix clears it.
 */
int pr_redis_conn_set_namespace(pr_redis_t *redis, module *m,
  const void *prefix, size_t prefixsz);

/* Authenticate to a password-protected Redis server. */
int pr_redis_auth(pr_redis_t *redis, const char *password);

/* Select the database used by the Redis server. */
int pr_redis_select(pr_redis_t *redis, const char *db_idx);

/* Issue a custom command to the Redis server; the reply type MUST match the
 * one specified.  Mostly this is used for testing.
 */
int pr_redis_command(pr_redis_t *redis, const array_header *args,
  int reply_type);
#define PR_REDIS_REPLY_TYPE_STRING		1
#define PR_REDIS_REPLY_TYPE_INTEGER		2
#define PR_REDIS_REPLY_TYPE_NIL			3
#define PR_REDIS_REPLY_TYPE_ARRAY		4
#define PR_REDIS_REPLY_TYPE_STATUS		5
#define PR_REDIS_REPLY_TYPE_ERROR		6

int pr_redis_add(pr_redis_t *redis, module *m, const char *key, void *value,
  size_t valuesz, time_t expires);
int pr_redis_decr(pr_redis_t *redis, module *m, const char *key, uint32_t decr,
  uint64_t *value);
void *pr_redis_get(pool *p, pr_redis_t *redis, module *m, const char *key,
  size_t *valuesz);
char *pr_redis_get_str(pool *p, pr_redis_t *redis, module *m, const char *key);
int pr_redis_incr(pr_redis_t *redis, module *m, const char *key, uint32_t incr,
  uint64_t *value);
int pr_redis_remove(pr_redis_t *redis, module *m, const char *key);
int pr_redis_rename(pr_redis_t *redis, module *m, const char *from,
  const char *to);
int pr_redis_set(pr_redis_t *redis, module *m, const char *key, void *value,
  size_t valuesz, time_t expires);

/* Hash operations */
int pr_redis_hash_count(pr_redis_t *redis, module *m, const char *key,
  uint64_t *count);
int pr_redis_hash_delete(pr_redis_t *redis, module *m, const char *key,
  const char *field);
int pr_redis_hash_exists(pr_redis_t *redis, module *m, const char *key,
  const char *field);
int pr_redis_hash_get(pool *p, pr_redis_t *redis, module *m, const char *key,
  const char *field, void **value, size_t *valuesz);
int pr_redis_hash_getall(pool *p, pr_redis_t *redis, module *m,
  const char *key, pr_table_t **hash);
int pr_redis_hash_incr(pr_redis_t *redis, module *m, const char *key,
  const char *field, int32_t incr, int64_t *value);
int pr_redis_hash_keys(pool *p, pr_redis_t *redis, module *m, const char *key,
  array_header **fields);
int pr_redis_hash_remove(pr_redis_t *redis, module *m, const char *key);
int pr_redis_hash_set(pr_redis_t *redis, module *m, const char *key,
  const char *field, void *value, size_t valuesz);
int pr_redis_hash_setall(pr_redis_t *redis, module *m, const char *key,
  pr_table_t *hash);
int pr_redis_hash_values(pool *p, pr_redis_t *redis, module *m,
  const char *key, array_header **values);

/* List operations */
int pr_redis_list_append(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz);
int pr_redis_list_count(pr_redis_t *redis, module *m, const char *key,
  uint64_t *count);
int pr_redis_list_delete(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz);
int pr_redis_list_exists(pr_redis_t *redis, module *m, const char *key,
  unsigned int idx);
int pr_redis_list_get(pool *p, pr_redis_t *redis, module *m, const char *key,
  unsigned int idx, void **value, size_t *valuesz);
int pr_redis_list_getall(pool *p, pr_redis_t *redis, module *m,
  const char *key, array_header **values, array_header **valueszs);
int pr_redis_list_pop(pool *p, pr_redis_t *redis, module *m, const char *key,
  void **value, size_t *valuesz, int flags);
int pr_redis_list_push(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz, int flags);
int pr_redis_list_remove(pr_redis_t *redis, module *m, const char *key);
int pr_redis_list_rotate(pool *p, pr_redis_t *redis, module *m, const char *key,
  void **value, size_t *valuesz);
int pr_redis_list_set(pr_redis_t *redis, module *m, const char *key,
  unsigned int idx, void *value, size_t valuesz);
int pr_redis_list_setall(pr_redis_t *redis, module *m, const char *key,
  array_header *values, array_header *valueszs);

/* These flags are used for determining whether the list operation occurs
 * to the LEFT or the RIGHT side of the list, e.g. LPUSH vs RPUSH.
 */
#define PR_REDIS_LIST_FL_LEFT		1
#define PR_REDIS_LIST_FL_RIGHT		2

/* Set operations */
int pr_redis_set_add(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz);
int pr_redis_set_count(pr_redis_t *redis, module *m, const char *key,
  uint64_t *count);
int pr_redis_set_delete(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz);
int pr_redis_set_exists(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz);
int pr_redis_set_getall(pool *p, pr_redis_t *redis, module *m, const char *key,
  array_header **values, array_header **valueszs);
int pr_redis_set_remove(pr_redis_t *redis, module *m, const char *key);
int pr_redis_set_setall(pr_redis_t *redis, module *m, const char *key,
  array_header *values, array_header *valueszs);

/* Sorted Set operations */
int pr_redis_sorted_set_add(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz, float score);
int pr_redis_sorted_set_count(pr_redis_t *redis, module *m, const char *key,
  uint64_t *count);
int pr_redis_sorted_set_delete(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz);
int pr_redis_sorted_set_exists(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz);
int pr_redis_sorted_set_getn(pool *p, pr_redis_t *redis, module *m,
  const char *key, unsigned int offset, unsigned int len,
  array_header **values, array_header **valueszs, int flags);

/* These flags are used for determining whether the sorted set items are
 * obtained in ascending (ASC) or descending (DESC) order.
 */
#define PR_REDIS_SORTED_SET_FL_ASC		1
#define PR_REDIS_SORTED_SET_FL_DESC		2

int pr_redis_sorted_set_incr(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz, float incr, float *score);
int pr_redis_sorted_set_remove(pr_redis_t *redis, module *m, const char *key);
int pr_redis_sorted_set_score(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz, float *score);
int pr_redis_sorted_set_set(pr_redis_t *redis, module *m, const char *key,
  void *value, size_t valuesz, float score);
int pr_redis_sorted_set_setall(pr_redis_t *redis, module *m, const char *key,
  array_header *values, array_header *valueszs, array_header *scores);

/* Variants of the above, where the key values are arbitrary bits rather than
 * being assumed to be strings.
 */
int pr_redis_kadd(pr_redis_t *redis, module *m, const char *key, size_t keysz,
  void *value, size_t valuesz, time_t expires);
int pr_redis_kdecr(pr_redis_t *redis, module *m, const char *key, size_t keysz,
  uint32_t decr, uint64_t *value);
void *pr_redis_kget(pool *p, pr_redis_t *redis, module *m, const char *key,
  size_t keysz, size_t *valuesz);
char *pr_redis_kget_str(pool *p, pr_redis_t *redis, module *m, const char *key,
  size_t keysz);
int pr_redis_kincr(pr_redis_t *redis, module *m, const char *key, size_t keysz,
  uint32_t incr, uint64_t *value);
int pr_redis_kremove(pr_redis_t *redis, module *m, const char *key,
  size_t keysz);
int pr_redis_krename(pr_redis_t *redis, module *m, const char *from,
  size_t fromsz, const char *to, size_t tosz);
int pr_redis_kset(pr_redis_t *redis, module *m, const char *key, size_t keysz,
  void *value, size_t valuesz, time_t expires);

int pr_redis_hash_kcount(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, uint64_t *count);
int pr_redis_hash_kdelete(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, const char *field, size_t fieldsz);
int pr_redis_hash_kexists(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, const char *field, size_t fieldsz);
int pr_redis_hash_kget(pool *p, pr_redis_t *redis, module *m, const char *key,
  size_t keysz, const char *field, size_t fieldsz, void **value,
  size_t *valuesz);
int pr_redis_hash_kgetall(pool *p, pr_redis_t *redis, module *m,
  const char *key, size_t keysz, pr_table_t **hash);
int pr_redis_hash_kincr(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, const char *field, size_t fieldsz, int32_t incr,
  int64_t *value);
int pr_redis_hash_kkeys(pool *p, pr_redis_t *redis, module *m, const char *key,
  size_t keysz, array_header **fields);
int pr_redis_hash_kremove(pr_redis_t *redis, module *m, const char *key,
  size_t keysz);
int pr_redis_hash_kset(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, const char *field, size_t fieldsz, void *value, size_t valuesz);
int pr_redis_hash_ksetall(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, pr_table_t *hash);
int pr_redis_hash_kvalues(pool *p, pr_redis_t *redis, module *m,
  const char *key, size_t keysz, array_header **values);

int pr_redis_list_kappend(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz);
int pr_redis_list_kcount(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, uint64_t *count);
int pr_redis_list_kdelete(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz);
int pr_redis_list_kexists(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, unsigned int idx);
int pr_redis_list_kget(pool *p, pr_redis_t *redis, module *m, const char *key,
  size_t keysz, unsigned int idx, void **value, size_t *valuesz);
int pr_redis_list_kgetall(pool *p, pr_redis_t *redis, module *m,
  const char *key, size_t keysz, array_header **values,
  array_header **valueszs);
int pr_redis_list_kpop(pool *p, pr_redis_t *redis, module *m,
  const char *key, size_t keysz, void **value, size_t *valuesz, int flags);
int pr_redis_list_kpush(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz, int flags);
int pr_redis_list_kremove(pr_redis_t *redis, module *m, const char *key,
  size_t keysz);
int pr_redis_list_krotate(pool *p, pr_redis_t *redis, module *m,
  const char *key, size_t keysz, void **value, size_t *valuesz);
int pr_redis_list_kset(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, unsigned int idx, void *value, size_t valuesz);
int pr_redis_list_ksetall(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, array_header *values, array_header *valueszs);

int pr_redis_set_kadd(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz);
int pr_redis_set_kcount(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, uint64_t *count);
int pr_redis_set_kdelete(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz);
int pr_redis_set_kexists(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz);
int pr_redis_set_kgetall(pool *p, pr_redis_t *redis, module *m, const char *key,
  size_t keysz, array_header **values, array_header **valueszs);
int pr_redis_set_kremove(pr_redis_t *redis, module *m, const char *key,
  size_t keysz);
int pr_redis_set_ksetall(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, array_header *values, array_header *valueszs);

int pr_redis_sorted_set_kadd(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz, float score);
int pr_redis_sorted_set_kcount(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, uint64_t *count);
int pr_redis_sorted_set_kdelete(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz);
int pr_redis_sorted_set_kexists(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz);
int pr_redis_sorted_set_kgetn(pool *p, pr_redis_t *redis, module *m,
  const char *key, size_t keysz, unsigned int offset, unsigned int len,
  array_header **values, array_header **valueszs, int flags);
int pr_redis_sorted_set_kincr(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz, float incr, float *score);
int pr_redis_sorted_set_kremove(pr_redis_t *redis, module *m, const char *key,
  size_t keysz);
int pr_redis_sorted_set_kscore(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz, float *score);
int pr_redis_sorted_set_kset(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, void *value, size_t valuesz, float score);
int pr_redis_sorted_set_ksetall(pr_redis_t *redis, module *m, const char *key,
  size_t keysz, array_header *values, array_header *valueszs,
  array_header *scores);

/* Sentinel operations */
int pr_redis_sentinel_get_master_addr(pool *p, pr_redis_t *redis,
  const char *name, pr_netaddr_t **addr);
int pr_redis_sentinel_get_masters(pool *p, pr_redis_t *redis,
  array_header **masters);

/* For internal use only */
int redis_set_server(const char *server, int port, unsigned long flags,
  const char *password, const char *db_idx);
int redis_set_sentinels(array_header *sentinels, const char *name);
int redis_set_timeouts(unsigned long connect_millis, unsigned long io_millis);

int redis_clear(void);
int redis_init(void);

#endif /* PR_REDIS_H */
