/*
 * ProFTPD - mod_snmp message routines
 * Copyright (c) 2008-2016 TJ Saunders
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

#ifndef MOD_SNMP_MSG_H
#define MOD_SNMP_MSG_H

#include "mod_snmp.h"
#include "pdu.h"

const char *snmp_msg_get_versionstr(long snmp_version);

int snmp_msg_read(pool *p, unsigned char **buf, size_t *buflen,
  char **community, unsigned int *community_len, long *snmp_version,
  struct snmp_pdu **pdu);
int snmp_msg_write(pool *p, unsigned char **buf, size_t *buflen,
  char *community, unsigned int community_len, long snmp_version,
  struct snmp_pdu *pdu);

#endif /* MOD_SNMP_MSG_H */
