/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
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

/* Generic set manipulation */

#include "conf.h"

/* Create a new set, cmpfunc is a pointer to the function used to to compare
 * members of the set ... it should return 1, 0, or -1 after the fashion of
 * strcmp.  Returns NULL if memory allocation fails.
 */

xaset_t *xaset_create(pool *p, XASET_COMPARE cmpfunc) {
  xaset_t *new_set;

  if (p == NULL &&
      permanent_pool == NULL) {
    errno = EPERM;
    return NULL;
  }

  p = p ? p : permanent_pool;

  new_set = palloc(p, sizeof(xaset_t));

  if (!new_set)
    return NULL;

  new_set->xas_list = NULL;
  new_set->pool = p;
  new_set->xas_compare = cmpfunc;

  return new_set;
}

/* Inserts a new member into an existing set.  The member is inserted
 * at the beginning of the set.  Returns 0 if successful, -1 otherwise (with
 * errno set appropriately).
 */
int xaset_insert(xaset_t *set, xasetmember_t *member) {

  if (set == NULL ||
      member == NULL) {
    errno = EINVAL;
    return -1;
  }

  member->next = set->xas_list;

  if (set->xas_list)
    set->xas_list->prev = member;

  set->xas_list = member;
  return 0;
}

/* Inserts a new member into an existing set at the end of the list.
 */
int xaset_insert_end(xaset_t *set, xasetmember_t *member) {
  xasetmember_t **tmp, *prev = NULL;

  if (set == NULL ||
      member == NULL) {
    errno = EINVAL;
    return -1;
  }

  for (tmp = &set->xas_list; *tmp; prev = *tmp, tmp = &(*tmp)->next)
    ;

  *tmp = member;
  member->prev = prev;
  member->next = NULL;

  if (prev)
    prev->next = member;

  return 0;
}

/* Inserts a new member into an existing set, sorted using the set's compare
 * callback.  If dups_allowed is non-0, returns 0 and the member is not added
 * to the set.  Otherwise, it is added immediately before the first duplicate.
 * If the set is not empty and not pre-sorted, results are undefined.
 * Returns 0 if successful, -1 otherwise (with errno set appropriately).
 */
int xaset_insert_sort(xaset_t *set, xasetmember_t *member, int dups_allowed) {
  xasetmember_t **setp = NULL, *mprev = NULL;

  if (!set || !member || !set->xas_compare) {
    errno = EINVAL;
    return -1;
  }

  for (setp = &set->xas_list; *setp; setp = &(*setp)->next) {
    int res;

    res = set->xas_compare(member, *setp);
    if (res <= 0) {
      if (res == 0 &&
          !dups_allowed)
        return 0;
      break;
    }

    mprev = *setp;
  }

  if (*setp)
    (*setp)->prev = member;

  member->prev = mprev;
  member->next = *setp;
  *setp = member;

  return 0;
}

/* Remove a member from a set.  The set need not be sorted.  Note that this
 * does NOT free the memory used by the member.  Returns 0 if successful,
 * and -1 if there was a problem (with errno set appropriately).
 */
int xaset_remove(xaset_t *set, xasetmember_t *member) {
  xasetmember_t *m = NULL;

  if (set == NULL ||
      member == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Check if member is actually a member of set. */
  for (m = set->xas_list; m; m = m->next) {
    if (m == member)
      break;
  }

  if (m == NULL) {
    errno = ENOENT;
    return -1;  
  }

  if (member->prev)
    member->prev->next = member->next;

  else /* assume that member is first in the list */
    set->xas_list = member->next;

  if (member->next)
    member->next->prev = member->prev;

  member->next = member->prev = NULL;
  return 0;
}

/* Perform an exact copy of the entire set, returning the new set.  msize
 * specifies the size of each member.  If copyfunc is non-NULL, it is called
 * instead to copy each member.  Returns NULL if out of memory condition
 * occurs.
 */
xaset_t *xaset_copy(pool *p, xaset_t *set, size_t msize, XASET_MCOPY copyfunc) {
  xaset_t *new_set;
  xasetmember_t *n, *m, **pos;

  if (set == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (!copyfunc && !msize) {
    errno = EINVAL;
    return NULL;
  }

  p = (p ? p : set->pool);

  new_set = xaset_create(p, set->xas_compare);
  if (new_set == NULL)
    return NULL;

  pos = &new_set->xas_list;

  /* NOTE: xaset_insert_sort is not used here for performance reasons. */

  for (m = set->xas_list; m; m = m->next) {
    n = copyfunc ? copyfunc(m) : (xasetmember_t *) palloc(p, msize);
    if (!n)
      return NULL;			/* Could clean up here */

    if (!copyfunc)
      memcpy(n, m, msize);

    /* Create links */
    n->prev = *pos;
    n->next = NULL;
    if (*pos)
      pos = &(*pos)->next;
    *pos = n;
  }

  return new_set;
}
