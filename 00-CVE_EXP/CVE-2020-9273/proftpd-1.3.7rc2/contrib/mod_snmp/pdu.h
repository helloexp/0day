/*
 * ProFTPD - mod_snmp PDU routines
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

#ifndef MOD_SNMP_PDU_H
#define MOD_SNMP_PDU_H

#include "mod_snmp.h"
#include "asn1.h"
#include "smi.h"

/* RFC1905 SNMPv2 ResponsePDU error status codes */
#define SNMP_ERR_NO_ERROR		0
#define SNMP_ERR_TOO_BIG		1
#define SNMP_ERR_NO_SUCH_NAME		2
#define SNMP_ERR_BAD_VALUE		3
#define SNMP_ERR_READ_ONLY		4
#define SNMP_ERR_GENERIC		5
#define SNMP_ERR_NO_ACCESS		6
#define SNMP_ERR_WRONG_TYPE		7
#define SNMP_ERR_WRONG_LEN		8
#define SNMP_ERR_WRONG_ENCODING		9
#define SNMP_ERR_WRONG_VALUE		10
#define SNMP_ERR_NO_CREATE		11
#define SNMP_ERR_INCONSISTENT_VALUE	12
#define SNMP_ERR_RSRC_UNAVAIL		13
#define SNMP_ERR_COMMIT_FAILED		14
#define SNMP_ERR_UNDO_FAILED		15
#define SNMP_ERR_AUTHZ_FAILED		16
#define SNMP_ERR_CANT_WRITE		17
#define SNMP_ERR_INCONSISTENT_NAME	18

/* RFC1907 SNMPv2 Trap types */
#define SNMP_TRAP_TYPE_COLDSTART		0
#define SNMP_TRAP_TYPE_WARMSTART		1
#define SNMP_TRAP_TYPE_LINKDOWN			2
#define SNMP_TRAP_TYPE_LINKUP			3
#define SNMP_TRAP_TYPE_AUTH_FAILED		4
#define SNMP_TRAP_TYPE_EGP_NEIGHBOR_LOSS	5
#define SNMP_TRAP_TYPE_SPECIFIC			6

/* RFC1905 defines the operations for SNMPv2 requests.
 *
 * Note that 0x04 is obsolete and no longer used.
 */
#define SNMP_PDU_GET		(SNMP_ASN1_CLASS_CONTEXT|SNMP_ASN1_CONSTRUCT|0x0)
#define SNMP_PDU_GETNEXT	(SNMP_ASN1_CLASS_CONTEXT|SNMP_ASN1_CONSTRUCT|0x1)
#define SNMP_PDU_RESPONSE	(SNMP_ASN1_CLASS_CONTEXT|SNMP_ASN1_CONSTRUCT|0x2)
#define SNMP_PDU_SET		(SNMP_ASN1_CLASS_CONTEXT|SNMP_ASN1_CONSTRUCT|0x3)
#define SNMP_PDU_TRAP_V1	(SNMP_ASN1_CLASS_CONTEXT|SNMP_ASN1_CONSTRUCT|0x4)
#define SNMP_PDU_GETBULK	(SNMP_ASN1_CLASS_CONTEXT|SNMP_ASN1_CONSTRUCT|0x5)
#define SNMP_PDU_INFORM		(SNMP_ASN1_CLASS_CONTEXT|SNMP_ASN1_CONSTRUCT|0x6)
#define SNMP_PDU_TRAP_V2	(SNMP_ASN1_CLASS_CONTEXT|SNMP_ASN1_CONSTRUCT|0x7)
#define SNMP_PDU_REPORT		(SNMP_ASN1_CLASS_CONTEXT|SNMP_ASN1_CONSTRUCT|0x8)

#define SNMP_PDU_MAX_BINDINGS	2147483647

/* Used to hold both requests and response. */
struct snmp_pdu {
  pool *pool;
  pr_netaddr_t *peer_addr;

  unsigned char request_type;
  long request_id;

  long err_code;
  long err_idx;

  /* For SNMPv2 bulk requests.  RFC1905 says that these values can be
   * negative (but if so, they are set to/treated as zero).
   */
  long non_repeaters;
  long max_repetitions;

  /* For responses. */
  struct snmp_var *varlist;
  unsigned int varlistlen;

  /* For traps. */
  oid_t *trap_oid;
  unsigned int trap_oidlen;
  pr_netaddr_t *trap_cause;
  int trap_type;
  unsigned int trap_systime;
};

const char *snmp_pdu_get_request_type_desc(unsigned char request_type);
struct snmp_pdu *snmp_pdu_create(pool *p, unsigned char request_type);
struct snmp_pdu *snmp_pdu_dup(pool *p, struct snmp_pdu *pdu);

/* XXX functions for fixing up a PDU, based on whether there was an err_code/
 * err_idx value, etc.
 */

int snmp_pdu_read(pool *p, unsigned char **buf, size_t *buflen,
    struct snmp_pdu **pdu, long snmp_version);
int snmp_pdu_write(pool *p, unsigned char **buf, size_t *buflen,
    struct snmp_pdu *pdu, long snmp_version);

#endif /* MOD_SNMP_PDU_H */
