/*
 * ProFTPD - mod_snmp notification types
 * Copyright (c) 2012-2016 TJ Saunders
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
 */

#ifndef MOD_SNMP_NOTIFY_H
#define MOD_SNMP_NOTIFY_H

#include "mod_snmp.h"
#include "asn1.h"

/* ftp.notifications */
#define SNMP_NOTIFY_DAEMON_MAX_INSTANCES	100
#define SNMP_NOTIFY_FTP_BAD_PASSWD		1000
#define SNMP_NOTIFY_FTP_BAD_USER		1001

int snmp_notify_generate(pool *p, int sockfd, const char *community,
  const pr_netaddr_t *src_addr, const pr_netaddr_t *dst_addr,
  unsigned int notify_id);
long snmp_notify_get_request_id(void);
void snmp_notify_poll_cond(void);

#endif /* MOD_SNMP_NOTIFY */
