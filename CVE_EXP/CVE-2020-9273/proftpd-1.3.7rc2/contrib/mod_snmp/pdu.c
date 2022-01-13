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

#include "mod_snmp.h"
#include "msg.h"
#include "pdu.h"
#include "smi.h"
#include "asn1.h"

static const char *trace_channel = "snmp.pdu";

const char *snmp_pdu_get_request_type_desc(unsigned char request_type) {
  const char *desc;

  switch (request_type) {
    case SNMP_PDU_GET:
      desc = "GetRequest-PDU";
      break;

    case SNMP_PDU_GETNEXT:
      desc = "GetNextRequest-PDU";
      break;

    case SNMP_PDU_RESPONSE:
      desc = "GetResponse-PDU";
      break;

    case SNMP_PDU_SET:
      desc = "SetRequest-PDU";
      break;

    case SNMP_PDU_TRAP_V1:
      desc = "Trap-PDU";
      break;

    case SNMP_PDU_GETBULK:
      desc = "GetBulkRequest-PDU";
      break;

    case SNMP_PDU_INFORM:
      desc = "InformRequest-PDU";
      break;

    case SNMP_PDU_TRAP_V2:
      desc = "TrapV2-PDU";
      break;

    case SNMP_PDU_REPORT:
      desc = "Report-PDU";
      break;

    default:
      desc = "Unknown";
      break;
  }

  return desc;
}

struct snmp_pdu *snmp_pdu_create(pool *p, unsigned char request_type) {
  pool *sub_pool;
  struct snmp_pdu *pdu;

  sub_pool = pr_pool_create_sz(p, 64);
  pdu = pcalloc(sub_pool, sizeof(struct snmp_pdu));
  pdu->pool = sub_pool;
  pdu->request_type = request_type;

  pr_trace_msg(trace_channel, 19,
    "created PDU of type '%s'", snmp_pdu_get_request_type_desc(request_type));
  return pdu;
}

/* Note: This makes a *shallow* copy of the given PDU, not a deep copy! */
struct snmp_pdu *snmp_pdu_dup(pool *p, struct snmp_pdu *src_pdu) {
  struct snmp_pdu *dst_pdu;

  dst_pdu = snmp_pdu_create(p, src_pdu->request_type);

  dst_pdu->request_id = src_pdu->request_id;
  dst_pdu->err_code = src_pdu->err_code;
  dst_pdu->err_idx = src_pdu->err_idx;

  dst_pdu->non_repeaters = src_pdu->non_repeaters;
  dst_pdu->max_repetitions = src_pdu->max_repetitions;

  /* XXX I'm not sure this is a good idea; once the source PDU is destroyed,
   * this becomes a dangling pointer.  Perhaps this should be a deep copy
   * of the varlist, too?
   */
  dst_pdu->varlist = src_pdu->varlist;

  dst_pdu->trap_oid = src_pdu->trap_oid;
  dst_pdu->trap_oidlen = src_pdu->trap_oidlen;
  dst_pdu->trap_cause = src_pdu->trap_cause;
  dst_pdu->trap_type = src_pdu->trap_type;
  dst_pdu->trap_systime = src_pdu->trap_systime;

  return dst_pdu;
}

/* Write this PDU into a buffer.
 *
 * RFC 1157: A Simple Network Management Protocol (SNMP)
 *
 *   PDU ::=
 *     SEQUENCE {
 *       request-id   INTEGER
 *       error-status INTEGER
 *       error-index  INTEGER
 *       Variable Bindings
 *     }
 *
 *   TrapPDU ::=
 *     SEQUENCE {
 *       enterprise    NetworkAddress
 *       generic-trap  INTEGER
 *       specific-trap INTEGER
 *       time-stamp    TIMETICKS
 *       Variable Bindings
 *     }
 *
 *
 * RFC 1902: Structure of Management Information for SNMPv2
 *
 *   PDU ::=
 *     SEQUENCE {
 *       request-id   INTEGER32
 *       error-status INTEGER
 *       error-index  INTEGER
 *       Variable Bindings
 *     }
 *
 *   BulkPDU ::=
 *     SEQUENCE {
 *       request-id      INTEGER32
 *       non-repeaters   INTEGER
 *       max-repetitions INTEGER
 *       Variable Bindings
 *     }
 */

int snmp_pdu_read(pool *p, unsigned char **buf, size_t *buflen,
    struct snmp_pdu **pdu, long snmp_version) {
  unsigned char asn1_type;
  unsigned int asn1_len;
  int flags, res;

  /* Since the "type" in this header is the PDU request type, the trace logging
   * of the ASN.1 type will be wrong.  That being the case, simply tell the
   * readers to not trace log that wrong invalid ASN.1 type.  Makes the
   * trace logging confusing and incorrect.
   */
  flags = SNMP_ASN1_FL_NO_TRACE_TYPESTR;

  res = snmp_asn1_read_header(p, buf, buflen, &asn1_type, &asn1_len, flags);
  if (res < 0) {
    return -1;
  }

  pr_trace_msg(trace_channel, 19,
    "read in PDU (0x%02x), length %u bytes", asn1_type, asn1_len);

  *pdu = snmp_pdu_create(p, asn1_type);

  switch (asn1_type) {
    case SNMP_PDU_RESPONSE:
    case SNMP_PDU_TRAP_V1:
    case SNMP_PDU_TRAP_V2:
    case SNMP_PDU_INFORM:
    case SNMP_PDU_REPORT:
      pr_trace_msg(trace_channel, 1,
        "handling '%s' PDU not currently supported",
        snmp_pdu_get_request_type_desc((*pdu)->request_type));
      errno = ENOSYS;
      return -1;

    case SNMP_PDU_GETBULK:
      /* Request ID */
      res = snmp_asn1_read_int(p, buf, buflen, &asn1_type,
        &((*pdu)->request_id), 0);
      if (res < 0) {
        return -1;
      }
      pr_trace_msg(trace_channel, 19,
        "read PDU request ID: %ld", (*pdu)->request_id);

      /* Non-repeaters */
      res = snmp_asn1_read_int(p, buf, buflen, &asn1_type,
        &((*pdu)->non_repeaters), 0);
      if (res < 0) {
        return -1;
      }
      pr_trace_msg(trace_channel, 19,
        "read PDU non-repeaters: %ld", (*pdu)->non_repeaters);

      /* As per RFC1905, if non_repeaters is negative, it is set to zero. */
      if ((*pdu)->non_repeaters < 0) {
        (*pdu)->non_repeaters = 0;
      }

      /* Max-repetitions */
      res = snmp_asn1_read_int(p, buf, buflen, &asn1_type,
        &((*pdu)->max_repetitions), 0);
      if (res < 0) {
        return -1;
      }
      pr_trace_msg(trace_channel, 19,
        "read PDU max-repetitions: %ld", (*pdu)->max_repetitions);

      /* As per RFC1905, if max_repetitions is negative, it is set to zero. */
      if ((*pdu)->max_repetitions < 0) {
        (*pdu)->max_repetitions = 0;
      }

      break;

    default:
      /* Request ID */
      res = snmp_asn1_read_int(p, buf, buflen, &asn1_type,
        &((*pdu)->request_id), 0);
      if (res < 0) {
        return -1;
      }
      pr_trace_msg(trace_channel, 19,
        "read PDU request ID: %ld", (*pdu)->request_id);

      /* Error Status/Code */
      res = snmp_asn1_read_int(p, buf, buflen, &asn1_type,
        &((*pdu)->err_code), 0);
      if (res < 0) {
        return -1;
      }
      pr_trace_msg(trace_channel, 19,
        "read PDU error status/code: %ld", (*pdu)->err_code);

      /* XXX What if err_code is non-zero? */

      /* Error Index */
      res = snmp_asn1_read_int(p, buf, buflen, &asn1_type,
        &((*pdu)->err_idx), 0);
      if (res < 0) {
        return -1;
      }
      pr_trace_msg(trace_channel, 19,
        "read PDU error index: %ld", (*pdu)->err_idx);

      /* XXX What if err_idx is non-zero? */

      break;
  }

  res = snmp_smi_read_vars(p, buf, buflen, &((*pdu)->varlist), snmp_version);
  if (res < 0) {
    return -1;
  }

  (*pdu)->varlistlen = res;

  pr_trace_msg(trace_channel, 17,
    "read %d %s from %s message", res,
    res != 1 ? "variables" : "variable",
    snmp_msg_get_versionstr(snmp_version));

  return 0;
}

int snmp_pdu_write(pool *p, unsigned char **buf, size_t *buflen,
    struct snmp_pdu *pdu, long snmp_version) {
  unsigned char asn1_type, *pdu_hdr_start, *pdu_hdr_end;
  size_t pdu_hdr_startlen;
  unsigned int asn1_len;
  int flags, res;

  pr_trace_msg(trace_channel, 19,
    "writing %s PDU (0x%02x)",
    snmp_pdu_get_request_type_desc(pdu->request_type), pdu->request_type);

  /* Since the "type" in this header is the PDU request type, the trace logging
   * of the ASN.1 type will be wrong.  That being the case, simply tell the
   * writers to not trace log that wrong invalid ASN.1 type.  Makes the
   * trace logging confusing and incorrect.
   */
  flags = SNMP_ASN1_FL_NO_TRACE_TYPESTR;

  asn1_type = pdu->request_type;
  asn1_len = 0;

  pdu_hdr_start = *buf;
  pdu_hdr_startlen = *buflen;

  res = snmp_asn1_write_header(p, buf, buflen, asn1_type, asn1_len, flags);
  if (res < 0) {
    return -1;
  }

  pdu_hdr_end = *buf;

  switch (pdu->request_type) {
    case SNMP_PDU_GETBULK:
      asn1_type = (SNMP_ASN1_CLASS_UNIVERSAL|SNMP_ASN1_PRIMITIVE|SNMP_ASN1_TYPE_INTEGER);

      /* Request ID */
      pr_trace_msg(trace_channel, 19,
        "writing PDU request ID: %ld", pdu->request_id);
      res = snmp_asn1_write_int(p, buf, buflen, asn1_type, pdu->request_id, 0);
      if (res < 0) {
        return -1;
      }

      /* Non-repeaters */
      pr_trace_msg(trace_channel, 19,
        "writing PDU non-repeaters: %ld", pdu->non_repeaters);
      res = snmp_asn1_write_int(p, buf, buflen, asn1_type,
        pdu->non_repeaters, 0);
      if (res < 0) {
        return -1;
      }

      /* Max-repetitions */
      pr_trace_msg(trace_channel, 19,
        "writing PDU max-repetitions: %ld", pdu->max_repetitions);
      res = snmp_asn1_write_int(p, buf, buflen, asn1_type,
        pdu->max_repetitions, 0);
      if (res < 0) {
        return -1;
      }

      /* XXX write varlist? */

      break;

    default:
      /* "Normal" PDU formatting. */

      asn1_type = (SNMP_ASN1_CLASS_UNIVERSAL|SNMP_ASN1_PRIMITIVE|SNMP_ASN1_TYPE_INTEGER);

      /* Request ID */
      pr_trace_msg(trace_channel, 19,
        "writing PDU request ID: %ld", pdu->request_id);
      res = snmp_asn1_write_int(p, buf, buflen, asn1_type, pdu->request_id, 0);
      if (res < 0) {
        return -1;
      }

      /* Error Status/Code */
      pr_trace_msg(trace_channel, 19,
        "writing PDU error status/code: %ld", pdu->err_code);
      res = snmp_asn1_write_int(p, buf, buflen, asn1_type, pdu->err_code, 0);
      if (res < 0) {
        return -1;
      }

      /* Error Index */
      pr_trace_msg(trace_channel, 19,
        "writing PDU error index: %ld", pdu->err_idx);
      res = snmp_asn1_write_int(p, buf, buflen, asn1_type, pdu->err_idx, 0);
      if (res < 0) {
        return -1;
      }

      /* Variable bindings list */
      pr_trace_msg(trace_channel, 19,
        "writing PDU variable binding list: (%u %s)", pdu->varlistlen,
        pdu->varlistlen != 1 ? "variables" : "variable");
      res = snmp_smi_write_vars(p, buf, buflen, pdu->varlist, snmp_version);
      if (res < 0) {
        return -1;
      }

      break;
  }

  /* Rewrite the PDU header, this time with the length of the entire PDU. */

  asn1_type = pdu->request_type;
  asn1_len = (*buf - pdu_hdr_end);

  pr_trace_msg(trace_channel, 18,
    "updating PDU header to have length %u", asn1_len);
  res = snmp_asn1_write_header(p, &pdu_hdr_start, &pdu_hdr_startlen, asn1_type,
    asn1_len, flags);
  if (res < 0) {
    return -1;
  }

  return 0;
}
