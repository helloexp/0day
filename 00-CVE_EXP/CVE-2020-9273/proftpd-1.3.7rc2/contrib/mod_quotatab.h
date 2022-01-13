/*
 * ProFTPD: mod_quotatab -- a module for managing FTP byte/file quotas via
 *                          centralized tables
 *
 * Copyright (c) 2001-2016 TJ Saunders
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
 * This is mod_quotatab, contrib software for proftpd 1.2/1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.  It is based
 * the ideas in Eric Estabrook's mod_quota, available from
 * ftp://pooh.urbanrage.com/pub/c/.  This module, however, has been written
 * from scratch to implement quotas in a different way.
 */

#ifndef MOD_QUOTATAB_H
#define MOD_QUOTATAB_H

#include "conf.h"
#include "privs.h"

#define MOD_QUOTATAB_VERSION "mod_quotatab/1.3.1"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030001
# error "ProFTPD 1.3.0rc1 or later required"
#endif

/* Quota types */
typedef enum {
  ALL_QUOTA = 10,
  USER_QUOTA = 20,
  GROUP_QUOTA = 30,
  CLASS_QUOTA = 40
} quota_type_t;

/* Bytes quota limit types */
typedef enum {
  HARD_LIMIT = 1,
  SOFT_LIMIT = 2
} quota_limit_type_t;

/* Quota objects */
typedef struct {
  char name[81];

  /* name refers to user, group, or class */
  quota_type_t quota_type;

  /* are quotas enforced per session or not? */
  unsigned char quota_per_session;

  /* are byte quotas hard or soft? */
  quota_limit_type_t quota_limit_type;

  /* Configured bytes limits. */
  double bytes_in_avail;
  double bytes_out_avail;
  double bytes_xfer_avail;

  /* Configured files limits.  These have no "limit type", as they are
   * always hard.
   */
  unsigned int files_in_avail;
  unsigned int files_out_avail;
  unsigned int files_xfer_avail;

} quota_limit_t;

typedef struct {
  char name[81];

  quota_type_t quota_type;

  /* Current bytes tallies. */
  double bytes_in_used;
  double bytes_out_used;
  double bytes_xfer_used;

  /* Current files tallies. */
  unsigned int files_in_used;
  unsigned int files_out_used;
  unsigned int files_xfer_used;

} quota_tally_t;

/* Quota table type (ie limit or tally) */
typedef enum {
  TYPE_LIMIT = 100,
  TYPE_TALLY

} quota_tabtype_t;

/* Quota display units */
typedef enum {
  BYTE = 10,
  KILO,
  MEGA,
  GIGA

} quota_units_t;

typedef enum {
  IN = 100,
  OUT,
  XFER,

} quota_xfer_t;

/* Quota deltas -- used to mark the changes in tallies per-operation.
 * This structure is useful for submodules (eg mod_quotatab_sql) that are
 * more interested in the deltas, rather than in the current tallies.
 */
typedef struct {
 
  /* Deltas of bytes tallies. */
  double bytes_in_delta;
  double bytes_out_delta;
  double bytes_xfer_delta;

  /* Deltas of files tallies. */
  int files_in_delta;
  int files_out_delta;
  int files_xfer_delta;
 
} quota_deltas_t;

typedef struct table_obj {

  /* Memory pool for this object */
  pool *tab_pool;

  /* Table type, limit or tally */
  quota_tabtype_t tab_type;

  /* Table handle */
  int tab_handle;

  /* Table "magic" number */
  unsigned int tab_magic;

  /* Table record length */
  unsigned int tab_quotalen;

  /* Arbitrary data pointer */
  void *tab_data;

  /* Table I/O routines */
  int (*tab_close)(struct table_obj *);
  int (*tab_create)(struct table_obj *, void *);
  unsigned char (*tab_lookup)(struct table_obj *, void *, const char *,
    quota_type_t);
  int (*tab_read)(struct table_obj *, void *);
  unsigned char (*tab_verify)(struct table_obj *);
  int (*tab_write)(struct table_obj *, void *);

  /* Table locking routines */
  struct flock tab_lock;
  int tab_lockfd;
  int (*tab_rlock)(struct table_obj *);
  int (*tab_unlock)(struct table_obj *);
  int (*tab_wlock)(struct table_obj *);

  /* Table locking counters */
  unsigned int rlock_count;
  unsigned int wlock_count;

} quota_table_t;

#define QUOTATAB_LIMIT_SRC      0x0001
#define QUOTATAB_TALLY_SRC      0x0002

/* Quota objects for the current session. */
quota_deltas_t quotatab_deltas;

/* Function prototypes necessary for quotatab sub-modules */
int quotatab_log(const char *, ...)
#ifdef __GNUC__
       __attribute__ ((format (printf, 1, 2)));
#else
       ;
#endif

int quotatab_openlog(void);
int quotatab_register_backend(const char *,
  quota_table_t *(*tab_open)(pool *, quota_tabtype_t, const char *),
  unsigned int);
int quotatab_unregister_backend(const char *, unsigned int);

/* Function prototypes necessary for consumers of quotatab data. */

/* Note: this function will only find the first occurrence of the given
 *  name and type in the table.  This means that if there is a malformed
 *  quota table, with duplicate name/type pairs, the duplicates will be
 *  ignored.  Returns TRUE if found, FALSE otherwise.
 */
unsigned char quotatab_lookup(quota_tabtype_t, void *, const char *,
  quota_type_t);

unsigned char quotatab_lookup_default(quota_tabtype_t, void *, const char *,
  quota_type_t);

/* Reads via this function are only ever done on tally tables.  Limit tables
 * are read via the quotatab_lookup function.  Returns 0 on success,
 * -1 on failure (with errno set appropriately).
 */
int quotatab_read(quota_tally_t *);

/* Writes via this function are only ever done on tally tables.  Returns 0
 * on success, -1 on failure (with errno set appropriately).
 */
int quotatab_write(quota_tally_t *, double, double, double, int, int, int);

#endif /* no MOD_QUOTATAB_H */
