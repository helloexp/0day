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

#include "mod_snmp.h"
#include "msg.h"
#include "pdu.h"
#include "smi.h"
#include "asn1.h"
#include "packet.h"
#include "db.h"

static const char *trace_channel = "snmp.msg";

const char *snmp_msg_get_versionstr(long snmp_version) {
  const char *versionstr = "unknown";

  switch (snmp_version) {
    case SNMP_PROTOCOL_VERSION_1:
      versionstr = "SNMPv1";
      break;

    case SNMP_PROTOCOL_VERSION_2:
      versionstr = "SNMPv2";
      break;

    case SNMP_PROTOCOL_VERSION_3:
      versionstr = "SNMPv3";
      break;
  }

  return versionstr;
}

/* RFC 1901: Introduction to Community-based SNMPv2:
 *
 *  Message ::=
 *    SEQUENCE {
 *      version   INTEGER
 *      community OCTET STRING
 *      data
 *    }
 *
 * and, before that: RFC 1157: A Simple Network Management Protocol (SNMP):
 *
 *  Message ::=
 *    SEQUENCE {
 *      version   INTEGER
 *      community OCTET STRING
 *      data
 *    }
 */

int snmp_msg_read(pool *p, unsigned char **buf, size_t *buflen,
    char **community, unsigned int *community_len, long *snmp_version,
    struct snmp_pdu **pdu) {
  unsigned char asn1_type;
  unsigned int asn1_len;
  int res;

  res = snmp_asn1_read_header(p, buf, buflen, &asn1_type, &asn1_len, 0);
  if (res < 0) {
    return -1;
  }

  if (asn1_type != (SNMP_ASN1_TYPE_SEQUENCE|SNMP_ASN1_CONSTRUCT)) {
    pr_trace_msg(trace_channel, 3,
      "unable to read SNMP message (tag '%s')",
      snmp_asn1_get_tagstr(p, asn1_type));

    errno = EINVAL;
    return -1;
  }

  res = snmp_asn1_read_int(p, buf, buflen, &asn1_type, snmp_version, 0);
  if (res < 0) {
    return -1;
  }

  pr_trace_msg(trace_channel, 17,
    "read SNMP message for %s", snmp_msg_get_versionstr(*snmp_version));

  /* XXX Don't support SNMPv3 yet. */

  if (*snmp_version != SNMP_PROTOCOL_VERSION_1 &&
      *snmp_version != SNMP_PROTOCOL_VERSION_2) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "%s messages not currently supported, dropping packet",
      snmp_msg_get_versionstr(*snmp_version));

    res = snmp_db_incr_value(p, SNMP_DB_SNMP_F_PKTS_DROPPED_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing snmp.packetsDroppedTotal: %s", strerror(errno));
    }

    errno = ENOSYS;
    return -1;
  }

  res = snmp_asn1_read_string(p, buf, buflen, &asn1_type, community,
    community_len);
  if (res < 0) {
    return -1;
  }

  /* Check that asn1_type is a UNIVERSAL/PRIMITIVE/OCTETSTRING. */
  if (!(asn1_type == (SNMP_ASN1_CLASS_UNIVERSAL|SNMP_ASN1_PRIMITIVE|SNMP_ASN1_TYPE_OCTETSTRING))) {
    pr_trace_msg(trace_channel, 3,
      "unable to read OCTET_STRING (received type '%s')",
      snmp_asn1_get_tagstr(p, asn1_type));
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 17,
    "read %s message: community = '%s'",
    snmp_msg_get_versionstr(*snmp_version), *community);

  res = snmp_pdu_read(p, buf, buflen, pdu, *snmp_version);
  if (res < 0) {
    return -1;
  }

  return 0;
}

int snmp_msg_write(pool *p, unsigned char **buf, size_t *buflen,
    char *community, unsigned int community_len, long snmp_version,
    struct snmp_pdu *pdu) {
  unsigned char asn1_type;
  unsigned int asn1_len;
  unsigned char *msg_ptr, *msg_hdr_start, *msg_hdr_end;
  size_t msg_hdr_startlen, msg_len;
  int res;

  if (p == NULL ||
      buf == NULL ||
      buflen == NULL ||
      community == NULL ||
      pdu == NULL) {
    errno = EINVAL;
    return -1;
  }

  msg_ptr = msg_hdr_start = *buf;
  msg_hdr_startlen = *buflen;

  asn1_type = (SNMP_ASN1_TYPE_SEQUENCE|SNMP_ASN1_CONSTRUCT);
  asn1_len = 0;

  res = snmp_asn1_write_header(p, buf, buflen, asn1_type, asn1_len, 0);
  if (res < 0) {
    return -1;
  }

  msg_hdr_end = *buf;

  asn1_type = (SNMP_ASN1_CLASS_UNIVERSAL|SNMP_ASN1_PRIMITIVE|SNMP_ASN1_TYPE_INTEGER);
  res = snmp_asn1_write_int(p, buf, buflen, asn1_type, snmp_version, 0);
  if (res < 0) {
    return -1;
  }

  asn1_type = (SNMP_ASN1_CLASS_UNIVERSAL|SNMP_ASN1_PRIMITIVE|SNMP_ASN1_TYPE_OCTETSTRING);
  res = snmp_asn1_write_string(p, buf, buflen, asn1_type, community,
    community_len);
  if (res < 0) {
    return -1;
  }

  if (pdu != NULL) {
    res = snmp_pdu_write(p, buf, buflen, pdu, snmp_version);
    if (res < 0) {
      return -1;
    }
  }

  /* Calculate the full message length, for use later. */
  msg_len = (*buf - msg_hdr_start);

  /* Having written out the entire message now, we can go back and fill
   * in the appropriate length in the header.
   */

  asn1_type = (SNMP_ASN1_TYPE_SEQUENCE|SNMP_ASN1_CONSTRUCT);
  asn1_len = (*buf - msg_hdr_end);
  
  pr_trace_msg(trace_channel, 18,
    "updating SNMP message header to have length %u", asn1_len);

  res = snmp_asn1_write_header(p, &msg_hdr_start, &msg_hdr_startlen,
    asn1_type, asn1_len, 0);
  if (res < 0) {
    return -1;
  }

  /* XXX This is a bit of a hack here.  We started with a buflen, and steadily
   * decremented that value as we wrote data into the buffer.
   *
   * However, buflen needs to the amount of data IN the buffer once we return
   * the caller, NOT the amount of data REMAINING in the buffer.  So we
   * cheat here.
   *
   * We also cheat by resetting buf to point to the start of the message.
   */

  *buflen = msg_len;
  *buf = msg_ptr;

  return 0;
}
