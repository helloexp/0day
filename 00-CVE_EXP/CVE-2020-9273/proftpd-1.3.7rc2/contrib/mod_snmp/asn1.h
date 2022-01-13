/*
 * ProFTPD - mod_snmp ASN.1 support
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

#ifndef MOD_SNMP_ASN1_H
#define MOD_SNMP_ASN1_H

#include "mod_snmp.h"

typedef uint32_t oid_t;

/* ASN.1 OIDs */

/* Per RFC 1905, Section 4.1, an SNMP OID can have a maximum of 128
 * sub-identifiers.
 */
#define SNMP_ASN1_OID_MAX_LEN		128
#define SNMP_ASN1_OID_MAX_ID		0xffff

/* ASN.1 Tag Types (RFC1155, Section 3.2.1) */
#define SNMP_ASN1_TYPE_BOOLEAN		0x01
#define SNMP_ASN1_TYPE_INTEGER		0x02
#define SNMP_ASN1_TYPE_BITSTRING	0x03
#define SNMP_ASN1_TYPE_OCTETSTRING	0x04
#define SNMP_ASN1_TYPE_NULL		0x05
#define SNMP_ASN1_TYPE_OID		0x06
#define SNMP_ASN1_TYPE_SEQUENCE		0x10
#define SNMP_ASN1_TYPE_SET		0x11

/* ASN.1 Tag Class values */
#define SNMP_ASN1_CLASS_UNIVERSAL	0x00    
#define SNMP_ASN1_CLASS_APPLICATION	0x40
#define SNMP_ASN1_CLASS_CONTEXT		0x80
#define SNMP_ASN1_CLASS_PRIVATE		0xc0

/* ASN.1 Tag Primitive/Construct values */
#define SNMP_ASN1_PRIMITIVE		0x00
#define SNMP_ASN1_CONSTRUCT		0x20

/* ASN.1 Tag Length values */
#define SNMP_ASN1_LEN_LONG		0x80
#define SNMP_ASN1_LEN_EXTENSION		0xff
#define SNMP_ASN1_LEN_INDEFINITE	0x80

const char *snmp_asn1_get_oidstr(pool *p, oid_t *asn1_oid,
  unsigned int asn1_oidlen);
const char *snmp_asn1_get_tagstr(pool *p, unsigned char asn1_type);

/* API flags */
#define SNMP_ASN1_FL_KNOWN_LEN		0x01
#define SNMP_ASN1_FL_NO_TRACE_TYPESTR	0x02
#define SNMP_ASN1_FL_UNSIGNED		0x04

int snmp_asn1_read_header(pool *p, unsigned char **buf, size_t *buflen,
  unsigned char *asn1_type, unsigned int *asn1_len, int flags);
int snmp_asn1_read_int(pool *p, unsigned char **buf, size_t *buflen,
  unsigned char *asn1_type, long *asn1_int, int flags);
int snmp_asn1_read_uint(pool *p, unsigned char **buf, size_t *buflen,
  unsigned char *asn1_type, unsigned long *asn1_uint);
int snmp_asn1_read_null(pool *p, unsigned char **buf, size_t *buflen,
  unsigned char *asn1_type);
int snmp_asn1_read_oid(pool *p, unsigned char **buf, size_t *buflen,
  unsigned char *asn1_type, oid_t *asn1_oid, unsigned int *asn1_oidlen);

/* XXX Need a matching snmp_asn1_read_bitstring() function? */
int snmp_asn1_read_string(pool *p, unsigned char **buf, size_t *buflen,
  unsigned char *asn1_type, char **asn_1str, unsigned int *asn1_strlen);

/* XXX Need an snmp_asn1_read_sequence() function? */

int snmp_asn1_write_header(pool *p, unsigned char **buf, size_t *buflen,
  unsigned char asn1_type, unsigned int asn1_len, int flags);
int snmp_asn1_write_int(pool *p, unsigned char **buf, size_t *buflen,
  unsigned char asn1_type, long asn1_int, int flags);
int snmp_asn1_write_uint(pool *p, unsigned char **buf, size_t *buflen,
  unsigned char asn1_type, unsigned long asn1_uint);
int snmp_asn1_write_null(pool *p, unsigned char **buf, size_t *buflen,
  unsigned char asn1_type);
int snmp_asn1_write_oid(pool *p, unsigned char **buf, size_t *buflen,
  unsigned char asn1_type, oid_t *asn1_oid, unsigned int asn1_oidlen);

/* XXX Need a matching snmp_asn1_write_bitstring() function? */
int snmp_asn1_write_string(pool *p, unsigned char **buf, size_t *buflen,
  unsigned char asn1_type, const char *asn1_str, unsigned int asn1_strlen);

/* The asn1_ex argument should be an enum, for the different exception
 * identifiers:
 *
 *  noSuchObject(0)
 *  noSuchInstance(1)
 *  endOfMibView(2)
 *
 *
 * XXX Need a corresponding snmp_asn1_read_exception() function.
 */
int snmp_asn1_write_exception(pool *p, unsigned char **buf, size_t *buflen,
  unsigned char asn1_type, unsigned char asn1_ex);

/* XXX Need an snmp_asn1_write_sequence() function? */

#endif /* MOD_SNMP_ASN1_H */
