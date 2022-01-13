/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2003-2017 The ProFTPD Project team
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
 * As a special exemption, the ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Class definitions */

#ifndef PR_CLASS_H
#define PR_CLASS_H

#include "table.h"
#include "netaddr.h"
#include "netacl.h"

typedef struct class_struc {
  pool *cls_pool;
  char *cls_name;
  unsigned int cls_satisfy;
  array_header *cls_acls;
  pr_table_t *cls_notes;

  struct class_struc *cls_next;
} pr_class_t;

#define PR_CLASS_SATISFY_ANY	0
#define PR_CLASS_SATISFY_ALL	1

/* Returns the class object associated with the given name, or NULL if
 * there is no matching class object.
 */
const pr_class_t *pr_class_find(const char *name);

/* Iterate through the Class list, returning the next class.  Returns NULL
 * once the end of the list is reached.  If prev is NULL, the iterator
 * restarts at the beginning of the list.
 */
const pr_class_t *pr_class_get(const pr_class_t *prev);

/* Returns TRUE if the given class object rules are satisfied/fulfilled by
 * the provided address, FALSE if not, and -1 on error.
 */
int pr_class_satisfied(pool *p, const pr_class_t *cls,
  const pr_netaddr_t *addr);

/* Returns the class object for which the given address matches every rule.
 * If multiple classes exist that might match the given address, the first
 * defined class matches.
 */
const pr_class_t *pr_class_match_addr(const pr_netaddr_t *addr);

/* Start a new class object, allocated from the given pool, with the given
 * name.
 */
int pr_class_open(pool *p, const char *name);

/* Close the current class object.
 *
 * Note that -1 may be returned.  This can happen, for example, if the
 * current class object has no associated rules, i.e. is empty.
 */
int pr_class_close(void);

/* Add the given ACL object to the currently opened class object. */
int pr_class_add_acl(const pr_netacl_t *acl);

/* Set the Satisfy flag on the currently opened class object. */
int pr_class_set_satisfy(int flags);

/* Set a note on the currently opened class object. */
int pr_class_add_note(const char *key, void *val, size_t valsz);

/* For internal use only. */
void init_class(void);

#endif /* PR_CLASS_H */
