/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2015 The ProFTPD Project team
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
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* Memory allocation/anti-leak system.  Yes, this *IS* stolen from Apache
 * also.  What can I say?  It makes sense, and it's safe (more overhead
 * though)
 */

#ifndef PR_POOL_H
#define PR_POOL_H

typedef struct pool_rec pool;

extern pool *permanent_pool;

void init_pools(void);
void free_pools(void);
pool *make_sub_pool(pool *);	/* All pools are sub-pools of perm */
pool *pr_pool_create_sz(pool *parent_pool, size_t sz);

/* Clears out _everything_ in a pool, destroying any sub-pools */
void destroy_pool(struct pool_rec *);

/* Allocate memory from a pool */
void *palloc(struct pool_rec *, size_t);
void *pallocsz(struct pool_rec *, size_t);
void *pcalloc(struct pool_rec *, size_t);
void *pcallocsz(struct pool_rec *, size_t);
void pr_pool_tag(struct pool_rec *, const char *);

#ifdef PR_USE_DEVEL
void pr_pool_debug_memory(void (*)(const char *, ...));

int pr_pool_debug_set_flags(int);
#define PR_POOL_DEBUG_FL_OOM_DUMP_POOLS	0x001

#endif /* PR_USE_DEVEL */

/* Array management */

typedef struct {
  struct pool_rec *pool;
  size_t elt_size;
  unsigned int nelts;
  unsigned int nalloc;
  void *elts;
} array_header;

array_header *make_array(pool *, unsigned int, size_t);
void clear_array(array_header *);
void *push_array(array_header *);

/* Concatenate two array_headers together. */
void array_cat(array_header *dst, const array_header *src);

/* Similar to array_cat(), except that it provides a return value. */
int array_cat2(array_header *dst, const array_header *src);

array_header *append_arrays(pool *, const array_header *, const array_header *);
array_header *copy_array(pool *, const array_header *);
array_header *copy_array_str(pool *, const array_header *);
array_header *copy_array_hdr(pool *, const array_header *);

/* Alarm signals can easily interfere with the pooled memory operations, thus
 * pr_alarms_block() and pr_alarms_unblock() provide for re-entrant security.
 */
extern void pr_alarms_block(void);
extern void pr_alarms_unblock(void);

void register_cleanup(pool *, void *, void (*)(void *), void (*)(void *));
void unregister_cleanup(pool *, void *, void (*)(void *));

/* minimum free bytes in a new block pool */
#define BLOCK_MINFREE		PR_TUNABLE_NEW_POOL_SIZE

#endif /* PR_POOL_H */
