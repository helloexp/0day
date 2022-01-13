/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2003-2016 The ProFTPD Project team
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

/* Network ACL definitions */

#ifndef PR_NETACL_H
#define PR_NETACL_H

typedef struct pr_netacl_t pr_netacl_t;

typedef enum {
  PR_NETACL_TYPE_ALL,
  PR_NETACL_TYPE_NONE,
  PR_NETACL_TYPE_IPMASK,
  PR_NETACL_TYPE_IPMATCH,
  PR_NETACL_TYPE_DNSMATCH,
  PR_NETACL_TYPE_IPGLOB,
  PR_NETACL_TYPE_DNSGLOB

} pr_netacl_type_t;

/* Parses the given string into a network ACL ('netacl') object allocated
 * from the given pool.  NULL is returned if there is an error during
 * the parsing; errno will be set appropriately.
 */
pr_netacl_t *pr_netacl_create(pool *, char *);

/* Returns a duplicate of the given netacl allocated from the pool. */
pr_netacl_t *pr_netacl_dup(pool *, const pr_netacl_t *);

/* Returns 1 if the given netaddr explicitly matches the ACL, -1 if the
 * netaddr explicitly does not match the ACL (e.g. "none"), and 0 if there is
 * no match.
 */
int pr_netacl_match(const pr_netacl_t *, const pr_netaddr_t *);

/* Returns TRUE if the given netacl is negated, FALSE if it is not negated,
 * and -1 if there was an error.  If -1 is returned, errno will be set
 * appropriately.
 */
int pr_netacl_get_negated(const pr_netacl_t *);

/* Returns the ACL type. */
pr_netacl_type_t pr_netacl_get_type(const pr_netacl_t *);

/* Returns a string describing the given NetACL. */
const char *pr_netacl_get_str(pool *p, const pr_netacl_t *acl);
const char *pr_netacl_get_str2(pool *p, const pr_netacl_t *acl, int flags);
#define PR_NETACL_FL_STR_NO_DESC	0x0001

#endif /* PR_NETACL_H */
