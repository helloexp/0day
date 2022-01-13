/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2004-2017 The ProFTPD Project team
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

/* Table management */

#ifndef PR_TABLE_H
#define PR_TABLE_H

#include "os.h"
#include "pool.h"

typedef struct tab_key {
  struct tab_key *next;
  const void *key_data;
  size_t key_datasz;
  unsigned int hash;
  unsigned nents;

} pr_table_key_t;

typedef struct tab_entry {
  struct tab_entry *next, *prev;
  unsigned int idx;
  pr_table_key_t *key;
  const void *value_data;
  size_t value_datasz;

} pr_table_entry_t;

typedef struct table_rec pr_table_t;

/* Add an entry in the table under the given key.  The char * pointer
 * is stored directly, NOT a copy of the memory to which it points.
 * If value_datasz is 0, value_data is assumed to be a NUL-terminated string
 * and strlen() is called on it.
 */
int pr_table_add(pr_table_t *tab, const char *key_data, const void *value_data,
  size_t value_datasz);

/* Add an entry in the table under the given key, making a duplicate of
 * the given value from the table's pool.  If value_datasz is 0, value_data
 * is assumed to be a NUL-terminated string and strlen() is called on it.
 */
int pr_table_add_dup(pr_table_t *tab, const char *key_data,
  const void *value_data, size_t value_datasz);

/* Allocates a new table from the given pool.  flags can be used to
 * determine the table behavior, e.g. will it allow multiple entries under
 * the same key (PR_TABLE_FL_MULTI_VALUE).
 */
pr_table_t *pr_table_alloc(pool *p, int flags);
#define PR_TABLE_FL_MULTI_VALUE		0x0001
#define PR_TABLE_FL_USE_CACHE		0x0002

/* Returns the number of entries stored in the table.
 */
int pr_table_count(pr_table_t *tab);

/* Similar to Perl's map() function, this function executes the given
 * callback on every entry in the table, passing in the key/value stored and a
 * pointer to user-provided data.  DO NOT ALTER the table inside the callback
 * function by adding or removing entries; it will alter the iterator state,
 * possibly causing entries to be skipped.
 *
 * This function is useful for when completely freeing an entire table and
 * everything in it: do() a free() function on the items, then free the table.
 *
 * The flags argument alters how the calling is done: a callback can return -1
 * to halt the iteration, unless PR_TABLE_DO_FL_ALL is used.
 */
int pr_table_do(pr_table_t *tab, int cb(const void *key_data,
  size_t key_datasz, const void *value_data, size_t value_datasz,
  void *user_data), void *user_data, int flags);
#define PR_TABLE_DO_FL_ALL			0x0010

/* Remove all entries from the table, emptying it.
 */
int pr_table_empty(pr_table_t *tab);

/* Returns a count of the number of entries stored under that key.  This
 * means that these tables allow multiple entries under the same key; it is
 * up to higher-level APIs to impose restrictions such as avoiding duplicates.
 */
int pr_table_exists(pr_table_t *tab, const char *key_data);

/* Free the given empty table.  If the table is not empty, -1 will be
 * returned, and errno set to EPERM.
 */
int pr_table_free(pr_table_t *tab);

/* Returns the value stored under the given key, or NULL if there is no
 * entry in the table for the given key.  If value_datasz is not NULL,
 * the size of the returned value will be stored in it.
 */
const void *pr_table_get(pr_table_t *tab, const char *key_data,
  size_t *value_datasz);

/* Retrieve the next key, for iterating over the entire table.  Returns
 * NULL when the end of the table has been reached.
 */
const void *pr_table_next(pr_table_t *tab);

/* Returns the value stored under the given key, and removes that entry from
 * the table.  If value_datasz is not NULL, the size of the returned value
 * will be stored in it.
 */
const void *pr_table_remove(pr_table_t *tab, const char *key_data,
  size_t *value_datasz);

/* Rewind to the start of the table before iterating using pr_table_next().
 */
int pr_table_rewind(pr_table_t *tab);

/* Changes the value stored under the given key to the provided value.
 * Returns -1 if no such key is in the table.  Note that only the first
 * encountered value under the key is set; this may be need to be called
 * multiple times in order to set all entries under that key; call
 * pr_table_exists() to find the number of entries to change.
 */
int pr_table_set(pr_table_t *tab, const char *key_data,
  const void *value_data, size_t value_datasz);

/* Change some of the characteristics of an allocated table tab via
 * the control cmd.  pr_table_ctl() can only be called on an empty table.
 * Returns 0 on success, -1 on failure (with errno set appropriately).
 *
 * cmd may have one of the following values:
 *
 *  PR_TABLE_CTL_SET_ENT_INSERT
 *    Sets a callback that handles inserting a table entry into its chain.
 *    The default insertor inserts new entries at the start of the chain;
 *    some tables may require that new entries be inserted at the end of
 *    of the chain.
 *
 *    The arg parameter must be a pointer to a function with the following
 *    signature:
 *
 *      void (*func)(pr_table_entry_t **head, pr_table_entry_t *ent)
 *
 *    The function will be called with head as a pointer to the head of
 *    the chain into which ent will be inserted.
 *
 *    If arg is NULL, the default insertor will be used.
 *
 *  PR_TABLE_CTL_SET_ENT_REMOVE
 *    Sets a callback that handles removing a table entry for its chain.
 *   
 *    The arg parameter must be a pointer to a function with the following
 *    signature:
 *
 *      void (*func)(pr_table_entry_t **head, pr_table_entry_t *ent)
 *
 *    The function will be called with head as a pointer to the head of
 *    the chain from which ent will be removed.
 *
 *    If arg is NULL, the default remover will be used.
 *
 *  PR_TABLE_CTL_SET_FLAGS
 *    Sets the flags on the given table.  These flags have the same
 *    values as the flags used in pr_table_alloc().
 *
 *  PR_TABLE_CTL_SET_KEY_CMP
 *    Sets a callback for handling key comparisons.  The default comparator
 *    uses strcmp() on the key data; some tables may require other
 *    comparators, especially if the key data are not strings.
 *
 *    The arg parameter must be a pointer to a function with the following
 *    signature:
 *
 *      int (*func)(const void *key1, size_t keysz1, const void *key2,
 *        size_t keysz2)
 *
 *    If arg is NULL, the default comparator will be used.
 *
 *  PR_TABLE_CTL_SET_KEY_HASH
 *    Sets a callback for handling the calculation of a hash value for
 *    given key data.  The default hash algorithm is the same used in Perl.
 *
 *    The arg parameter must be a pointer to a function with the following
 *    signature:
 *
 *      unsigned int (*func)(const void *key, size_t keysz)
 *
 *    If arg is NULL, the default hash function will be used.
 *
 *  PR_TABLE_CTL_SET_NCHAINS
 *    Sets the number of chains in a table.  New entries are hashed, then
 *    distributed among the chains in a manner that hopefully provides
 *    minimum lookup times.  If a table will be holding a large number of
 *    entries, a larger number of chains will ensure a better distribution.
 *    The default number of chains is 256.
 *
 *  PR_TABLE_CTL_SET_MAX_ENTS
 *    Sets the maximum number of entries the table can hold.  Attempts to
 *    insert entries above this maximum result in an ENOSPC error value.
 *    The default maximum number of entries is currently 8192.
 */
int pr_table_ctl(pr_table_t *tab, int cmd, void *arg);
#define PR_TABLE_CTL_SET_ENT_INSERT	1
#define PR_TABLE_CTL_SET_ENT_REMOVE	2
#define PR_TABLE_CTL_SET_FLAGS		3
#define PR_TABLE_CTL_SET_KEY_CMP	4
#define PR_TABLE_CTL_SET_KEY_HASH	5
#define PR_TABLE_CTL_SET_NCHAINS	6
#define PR_TABLE_CTL_SET_MAX_ENTS	7

/* Returns the table "load", which is the ratio between the number of
 * entries in the table (e.g. via pr_table_count()) and the number of chains
 * among which the entries are distributed.  Note that a negative return value
 * indicates an error of some sort; check the errno value in such cases.
 *
 * The load factor can be used, in combination with tests surrounding entry
 * lookup time, to determine how well the key hashing function performs with
 * regard to collision avoidance, especially as the number of entries increases.
 */
float pr_table_load(pr_table_t *tab);

/* Dump table information. */
void pr_table_dump(void (*)(const char *, ...), pr_table_t *tab);

/* Same as pr_table_add(), except that the key data to use is treated as
 * an opaque memory region of size key_datasz.  This function should be
 * used if the lookup key is not a string.
 *
 * Unlike pr_table_add(), though, if value_datasz is zero, it is not
 * assumed that value_data is a NUL-terminated string.  Callers of this
 * function must provide the size of the given value_data.
 */
int pr_table_kadd(pr_table_t *tab, const void *key_data, size_t key_datasz,
  const void *value_data, size_t value_datasz);

/* Same as pr_table_exists(), except that the key data to use is treated as
 * an opaque memory region of size key_datasz.  This function should be
 * used if the lookup key is not a string.
 */
int pr_table_kexists(pr_table_t *tab, const void *key_data, size_t key_datasz);

/* Same as pr_table_next(), except that the size of the key is also provided.
 * This function should be used if the lookup key is not a string.
 */
const void *pr_table_knext(pr_table_t *tab, size_t *key_datasz);

/* Same as pr_table_get(), except that the key data to use is treated as
 * an opaque memory region of size key_datasz.  This function should be
 * used if the lookup key is not a string.
 */
const void *pr_table_kget(pr_table_t *tab, const void *key_data,
  size_t key_datasz, size_t *value_datasz);

/* Same as pr_table_remove(), except that the key data to use is treated as
 * an opaque memory region of size key_datasz.  This function should be
 * used if the lookup key is not a string.
 */
const void *pr_table_kremove(pr_table_t *tab, const void *key_data,
  size_t key_datasz, size_t *value_datasz);

/* Same as pr_table_set(), except that the key data to use is treated as
 * an opaque memory region of size key_datasz.  This function should be
 * used if the lookup key is not a string.
 */
int pr_table_kset(pr_table_t *tab, const void *key_data, size_t key_datasz,
  const void *value_data, size_t value_datasz);

/* Similar to pr_table_alloc(), except that the number of chains can
 * be explicitly configured.
 */
pr_table_t *pr_table_nalloc(pool *p, int flags, unsigned int nchains);

/* Similar to pcalloc(), except that the requested memory is allocated
 * from the table's pool.
 */
void *pr_table_pcalloc(pr_table_t *tab, size_t sz);

/* Internal use only. */
int table_handling_signal(int);

#endif /* PR_TABLE_H */
