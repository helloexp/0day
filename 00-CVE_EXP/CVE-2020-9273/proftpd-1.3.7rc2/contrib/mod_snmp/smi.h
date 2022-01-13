/*
 * ProFTPD - mod_snmp SMI routines
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

#ifndef MOD_SNMP_SMI_H
#define MOD_SNMP_SMI_H

#include "mod_snmp.h"
#include "asn1.h"

/* RFC1902 Structure of Management Information (SMI) for SNMPv2 */
#define SNMP_SMI_INTEGER	SNMP_ASN1_TYPE_INTEGER
#define SNMP_SMI_STRING		SNMP_ASN1_TYPE_OCTETSTRING
#define SNMP_SMI_OID		SNMP_ASN1_TYPE_OID
#define SNMP_SMI_NULL		SNMP_ASN1_TYPE_NULL

/* OCTET_STRING, network byte order */
#define SNMP_SMI_IPADDR		(SNMP_ASN1_CLASS_APPLICATION|0)

/* INTEGER */
#define SNMP_SMI_COUNTER32	(SNMP_ASN1_CLASS_APPLICATION|1)

/* INTEGER */
#define SNMP_SMI_GAUGE32	(SNMP_ASN1_CLASS_APPLICATION|2)

/* INTEGER */
#define SNMP_SMI_TIMETICKS	(SNMP_ASN1_CLASS_APPLICATION|3)

/* OCTET_STRING */
#define SNMP_SMI_OPAQUE		(SNMP_ASN1_CLASS_APPLICATION|4)

/* INTEGER */
#define SNMP_SMI_COUNTER64	(SNMP_ASN1_CLASS_APPLICATION|6)

#define SNMP_SMI_NO_SUCH_OBJECT \
  (SNMP_ASN1_CLASS_CONTEXT|SNMP_ASN1_PRIMITIVE|0x0)

#define SNMP_SMI_NO_SUCH_INSTANCE \
  (SNMP_ASN1_CLASS_CONTEXT|SNMP_ASN1_PRIMITIVE|0x1)

#define SNMP_SMI_END_OF_MIB_VIEW \
  (SNMP_ASN1_CLASS_CONTEXT|SNMP_ASN1_PRIMITIVE|0x2)

/* Maximum length/number of sub-identifiers in an OID that we will accept. */
#define SNMP_SMI_MAX_NAMELEN	64

struct snmp_var {
  pool *pool;

  struct snmp_var *next;

  /* OID identifier of this variable */
  oid_t *name;
  unsigned int namelen;

  /* SMI/ASN.1 type of this variable */
  unsigned char smi_type;

  union {
    long *integer;
    char *string;
    oid_t *oid;
  } value;

  unsigned int valuelen;
};

const char *snmp_smi_get_varstr(pool *p, unsigned char var_type);

struct snmp_var *snmp_smi_alloc_var(pool *p, oid_t *name, unsigned int namelen);
struct snmp_var *snmp_smi_create_var(pool *p, oid_t *name,
  unsigned int namelen, unsigned char smi_type, int32_t int_value,
  char *str_value, size_t str_valuelen);
struct snmp_var *snmp_smi_create_int(pool *p, oid_t *name, unsigned int namelen,
  unsigned char smi_type, int32_t value);
struct snmp_var *snmp_smi_create_string(pool *p, oid_t *name,
  unsigned int namelen, unsigned char smi_type, char *value, size_t valuelen);
struct snmp_var *snmp_smi_create_oid(pool *p, oid_t *name,
  unsigned int namelen, unsigned char smi_type, oid_t *value,
  unsigned int valuelen);
struct snmp_var *snmp_smi_create_exception(pool *p, oid_t *name,
  unsigned int namelen, unsigned char smi_type);
struct snmp_var *snmp_smi_dup_var(pool *p, struct snmp_var *var);

int snmp_smi_read_vars(pool *p, unsigned char **buf, size_t *buflen,
    struct snmp_var **varlist, int snmp_version);
int snmp_smi_write_vars(pool *p, unsigned char **buf, size_t *buflen,
    struct snmp_var *varlist, int snmp_version);

unsigned int snmp_smi_util_add_list_var(struct snmp_var **head,
  struct snmp_var **tail, struct snmp_var *var);

#endif /* MOD_SNMP_SMI_H */
