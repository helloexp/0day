/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2016 The ProFTPD Project team
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

#ifndef PR_SETS_H
#define PR_SETS_H

#include "pool.h"

typedef struct XAsetmember xasetmember_t;
typedef struct XAset xaset_t;
typedef int (*XASET_COMPARE)(xasetmember_t *v1, xasetmember_t *v2);
typedef xasetmember_t* (*XASET_MCOPY)(xasetmember_t *mem);

struct XAsetmember {
  xasetmember_t	*next, *prev;
};

struct XAset {
  xasetmember_t *xas_list;
  struct pool_rec *pool;
  XASET_COMPARE xas_compare;
};

/* Prototypes */
xaset_t *xaset_create(pool *, XASET_COMPARE);
xaset_t *xaset_copy(pool *, xaset_t *, size_t, XASET_MCOPY);
int xaset_insert(xaset_t *, xasetmember_t *);
int xaset_insert_end(xaset_t *, xasetmember_t *);
int xaset_insert_sort(xaset_t *, xasetmember_t *, int);
int xaset_remove(xaset_t *, xasetmember_t *);

#endif /* PR_SETS_H */
