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

#include "mod_snmp.h"
#include "asn1.h"
#include "smi.h"
#include "mib.h"
#include "msg.h"

static const char *trace_channel = "snmp.smi";

const char *snmp_smi_get_varstr(pool *p, unsigned char var_type) {
  const char *varstr = "unknown";

  switch (var_type) {
    case SNMP_SMI_INTEGER:
      varstr = "INTEGER";
      break;

    case SNMP_SMI_STRING:
      varstr = "STRING";
      break;

    case SNMP_SMI_OID:
      varstr = "OID";
      break;
 
    case SNMP_SMI_NULL:
      varstr = "NULL";
      break; 

    case SNMP_SMI_IPADDR:
      varstr = "IPADDR";
      break; 

    case SNMP_SMI_COUNTER32:
      varstr = "COUNTER32";
      break;

    case SNMP_SMI_GAUGE32:
      varstr = "GAUGE32";
      break;

    case SNMP_SMI_TIMETICKS:
      varstr = "TIMETICKS";
      break;

    case SNMP_SMI_OPAQUE:
      varstr = "OPAQUE";
      break;

    case SNMP_SMI_COUNTER64:
      varstr = "COUNTER64";
      break;

    case SNMP_SMI_NO_SUCH_OBJECT:
      varstr = "NO_SUCH_OBJECT";
      break;

    case SNMP_SMI_NO_SUCH_INSTANCE:
      varstr = "NO_SUCH_INSTANCE";
      break;

    case SNMP_SMI_END_OF_MIB_VIEW:
      varstr = "END_OF_MIB_VIEW";
      break;
  }

  return varstr;
}

struct snmp_var *snmp_smi_alloc_var(pool *p, oid_t *name,
    unsigned int namelen) {
  pool *sub_pool;
  struct snmp_var *var;

  sub_pool = pr_pool_create_sz(p, 64);
  var = pcalloc(sub_pool, sizeof(struct snmp_var));
  var->pool = sub_pool;
  var->next = NULL;

  /* Default type for newly-allocated variables. */
  var->smi_type = SNMP_SMI_NULL;

  var->namelen = namelen;

  if (var->namelen == 0) {
    /* Not sure why a caller would do this, but... */
    return var;
  }

  /* Even though the name argument may be NULL, we still allocate the space.
   * Why?  Because when reading off variables from a message, we may not
   * know the name when we are allocating the struct, but we will know at
   * some point after that.
   */
  var->name = pcalloc(var->pool, sizeof(oid_t) * var->namelen);

  if (name != NULL) {
    memmove(var->name, name, sizeof(oid_t) * var->namelen);
  }

  return var;
}

struct snmp_var *snmp_smi_create_var(pool *p, oid_t *name, unsigned int namelen,
    unsigned char smi_type, int32_t int_value, char *str_value,
    size_t str_valuelen) {
  struct snmp_var *var = NULL;

  switch (smi_type) {
    case SNMP_SMI_INTEGER:  
    case SNMP_SMI_COUNTER32:
    case SNMP_SMI_GAUGE32:
    case SNMP_SMI_TIMETICKS:
      var = snmp_smi_create_int(p, name, namelen, smi_type, int_value);
      break;

    case SNMP_SMI_STRING:
    case SNMP_SMI_IPADDR:
      var = snmp_smi_create_string(p, name, namelen, smi_type, str_value,
        str_valuelen);
      break;

    default:
      pr_trace_msg(trace_channel, 16,
        "unable to create variable for SMI type %s",
      snmp_smi_get_varstr(p, smi_type));
      errno = ENOENT;
      break;
  }

  return var;
}

struct snmp_var *snmp_smi_create_int(pool *p, oid_t *name, unsigned int namelen,
    unsigned char smi_type, int32_t value) {
  struct snmp_var *var;

  var = snmp_smi_alloc_var(p, name, namelen);
  var->valuelen = sizeof(value);
  var->value.integer = palloc(var->pool, var->valuelen);
  *(var->value.integer) = value;
  var->smi_type = smi_type;

  pr_trace_msg(trace_channel, 19,
    "created SMI variable %s, value %d", snmp_smi_get_varstr(p, smi_type),
    value);
  return var;
}

struct snmp_var *snmp_smi_create_string(pool *p, oid_t *name,
    unsigned int namelen, unsigned char smi_type, char *value,
    size_t valuelen) {
  struct snmp_var *var;

  if (value == NULL) {
    errno = EINVAL;
    return NULL;
  }

  var = snmp_smi_alloc_var(p, name, namelen);
  var->valuelen = valuelen;
  var->value.string = pstrndup(var->pool, value, var->valuelen);
  var->smi_type = smi_type;

  pr_trace_msg(trace_channel, 19,
    "created SMI variable %s, value '%s'", snmp_smi_get_varstr(p, smi_type),
    value);
  return var;
}

struct snmp_var *snmp_smi_create_oid(pool *p, oid_t *name,
    unsigned int namelen, unsigned char smi_type, oid_t *value,
    unsigned int valuelen) {
  struct snmp_var *var;

  if (value == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (smi_type != SNMP_SMI_OID) {
    errno = EINVAL;
    return NULL;
  }

  var = snmp_smi_alloc_var(p, name, namelen);

  /* The valuelen argument is the number of sub-ids, NOT the number of bytes,
   * for an OID.
   */
  var->valuelen = valuelen;
  var->value.oid = palloc(var->pool, sizeof(oid_t) * var->valuelen);
  memmove(var->value.oid, value, sizeof(oid_t) * var->valuelen);
  var->smi_type = smi_type;

  pr_trace_msg(trace_channel, 19,
    "created SMI variable %s, value %s", snmp_smi_get_varstr(p, smi_type),
    snmp_asn1_get_oidstr(p, value, valuelen));
  return var;
}

struct snmp_var *snmp_smi_create_exception(pool *p, oid_t *name,
    unsigned int namelen, unsigned char smi_type) {
  struct snmp_var *var;

  /* Check that the SMI type is one of the allowed "exceptions"
   * (terminology from RFC 1905).
   */
  switch (smi_type) {
    case SNMP_SMI_NO_SUCH_OBJECT:
    case SNMP_SMI_NO_SUCH_INSTANCE:
    case SNMP_SMI_END_OF_MIB_VIEW:
      break;

    default:
      errno = EINVAL;
      return NULL;
  }

  var = snmp_smi_alloc_var(p, name, namelen);
  var->valuelen = 0;
  var->smi_type = smi_type;

  pr_trace_msg(trace_channel, 19,
    "created SMI variable %s", snmp_smi_get_varstr(p, smi_type));
  return var;
}

/* Note: This will duplicate the entire varlist represented by the head
 * variable.
 */
struct snmp_var *snmp_smi_dup_var(pool *p, struct snmp_var *src_var) {
  struct snmp_var *head_var = NULL, *iter_var = NULL, *tail_var = NULL;
  unsigned int var_count = 0;

  for (iter_var = src_var; iter_var; iter_var = iter_var->next) {
    struct snmp_var *var;

    pr_signals_handle();

    var = snmp_smi_alloc_var(p, iter_var->name, iter_var->namelen);
    var->smi_type = iter_var->smi_type;
    var->valuelen = iter_var->valuelen;

    if (var->valuelen > 0) {
      switch (var->smi_type) {
        case SNMP_SMI_INTEGER:
          var->value.integer = palloc(var->pool, var->valuelen);
          memmove(var->value.integer, iter_var->value.integer, var->valuelen);
          break;

        case SNMP_SMI_STRING:
          var->value.string = pcalloc(var->pool, var->valuelen);
          memmove(var->value.string, iter_var->value.string, var->valuelen);
          break;

        case SNMP_SMI_OID:
          var->value.oid = palloc(var->pool, var->valuelen);
          memmove(var->value.oid, iter_var->value.oid, var->valuelen);
          break;

        default:
          pr_trace_msg(trace_channel, 1,
            "unable to dup variable '%s': unsupported",
            snmp_asn1_get_tagstr(p, var->smi_type));

          /* XXX Destroy the entire chain? */
          destroy_pool(var->pool);
          pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
          errno = EINVAL;
          return NULL;
      }
    }

    if (head_var == NULL) {
      head_var = var;
    }

    if (tail_var != NULL) {
      tail_var->next = var;
    }

    tail_var = var;
    var_count++;

    pr_trace_msg(trace_channel, 19,
      "cloned SMI variable %s", snmp_smi_get_varstr(p, iter_var->smi_type));
  }

  pr_trace_msg(trace_channel, 19, "cloned %u SMI %s", var_count,
    var_count != 1 ? "variables" : "variable");
  return head_var;
}

/* Decode a list of SNMPv2 variable bindings. */
int snmp_smi_read_vars(pool *p, unsigned char **buf, size_t *buflen,
    struct snmp_var **varlist, int snmp_version) {
  struct snmp_var *var = NULL, *head = NULL, *tail = NULL;
  unsigned char asn1_type;
  unsigned int total_varlen = 0;
  int res, var_count = 0;

  res = snmp_asn1_read_header(p, buf, buflen, &asn1_type, &total_varlen, 0);
  if (res < 0) {
    return -1;
  }

  /* If this isn't a constructed sequence, error out. */
  if (asn1_type != (SNMP_ASN1_TYPE_SEQUENCE|SNMP_ASN1_CONSTRUCT)) {
    pr_trace_msg(trace_channel, 1,
      "unable to parse tag (%s) as list of variables",
      snmp_asn1_get_tagstr(p, asn1_type));
    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 17, "reading %s variables (%u bytes)",
    snmp_msg_get_versionstr(snmp_version), total_varlen);

  while (*buflen > 0) {
    unsigned int varlen;
    unsigned char *obj_start = NULL;
    size_t obj_startlen = 0;

    pr_signals_handle();

    res = snmp_asn1_read_header(p, buf, buflen, &asn1_type, &varlen, 0);
    if (res < 0) {
      return -1;
    }

    /* If this isn't a constructed sequence, error out. */
    if (asn1_type != (SNMP_ASN1_TYPE_SEQUENCE|SNMP_ASN1_CONSTRUCT)) {
      pr_trace_msg(trace_channel, 1,
        "unable to parse tag (%s) as variable binding",
        snmp_asn1_get_tagstr(p, asn1_type));
      pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
      errno = EINVAL;
      return -1;
    }

    /* We don't know the name of this variable yet. */
    var = snmp_smi_alloc_var(p, NULL, SNMP_SMI_MAX_NAMELEN);

    /* Read the variable name/OID. */
    res = snmp_asn1_read_oid(p, buf, buflen, &asn1_type, var->name,
      &(var->namelen));
    if (res < 0) {
      destroy_pool(var->pool);
      return -1;
    }

    if (asn1_type != (SNMP_ASN1_CLASS_UNIVERSAL|SNMP_ASN1_PRIMITIVE|SNMP_ASN1_TYPE_OID)) {
      pr_trace_msg(trace_channel, 1,
        "expected OID tag, read tag (%s) from variable list",
        snmp_asn1_get_tagstr(p, asn1_type));

      destroy_pool(var->pool);
      pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
      errno = EINVAL;
      return -1;
    }

    if (pr_trace_get_level(trace_channel) >= 19) {
      struct snmp_mib *mib;
      int lacks_instance_id = FALSE;

      mib = snmp_mib_get_by_oid(var->name, var->namelen, &lacks_instance_id);
      if (mib != NULL) {
        pr_trace_msg(trace_channel, 19,
          "read variable OID %s (%u sub-ids, name %s)",
          snmp_asn1_get_oidstr(p, var->name, var->namelen), var->namelen,
          mib->instance_name);

      } else {
        pr_trace_msg(trace_channel, 19,
          "read variable OID %s (%u sub-ids)",
          snmp_asn1_get_oidstr(p, var->name, var->namelen), var->namelen);
      }
    }

    obj_start = *buf;
    obj_startlen = *buflen;

    /* Now that we know the name/OID of the variable, let's find out what
     * type of variable it is.
     *
     * This is effectively a peek, since the following reader functions
     * will also want to read the tag/length header values.
     */
    res = snmp_asn1_read_header(p, &obj_start, &obj_startlen, &(var->smi_type),
      &(var->valuelen), 0);
    if (res < 0) {
      destroy_pool(var->pool);
      return -1;
    }

    pr_trace_msg(trace_channel, 19,
      "read SMI variable %s, data len %u bytes",
      snmp_smi_get_varstr(p, var->smi_type), var->valuelen);

    /* Now read in the value */
    switch (var->smi_type) {
      case SNMP_SMI_INTEGER:
        res = snmp_asn1_read_int(p, buf, buflen,
          &(var->smi_type), var->value.integer, 0);
        if (res == 0) {
          pr_trace_msg(trace_channel, 19,
            "read INTEGER variable (value %d)", *((int *) var->value.integer));
        }
        break;

      case SNMP_SMI_COUNTER32:
      case SNMP_SMI_GAUGE32:
      case SNMP_SMI_TIMETICKS:
        res = snmp_asn1_read_uint(p, buf, buflen,
          &(var->smi_type), (unsigned long *) var->value.integer);
        if (res == 0) {
          pr_trace_msg(trace_channel, 19,
            "read %s variable (value %u)",
            snmp_smi_get_varstr(p, var->smi_type),
            *((unsigned int *) var->value.integer));
        }
        break;

      case SNMP_SMI_STRING:
      case SNMP_SMI_IPADDR:
      case SNMP_SMI_OPAQUE:
        res = snmp_asn1_read_string(p, buf, buflen,
          &(var->smi_type), &(var->value.string), &(var->valuelen));
        if (res == 0) {
          pr_trace_msg(trace_channel, 19,
            "read %s variable (value '%.*s')",
            snmp_smi_get_varstr(p, var->smi_type),
            var->valuelen, var->value.string);
        }
        break;

      case SNMP_SMI_OID:
        res = snmp_asn1_read_oid(p, buf, buflen,
          &(var->smi_type), var->value.oid, &(var->valuelen));
        if (res == 0) {
          pr_trace_msg(trace_channel, 19,
            "read %s variable (%u sub-ids, value %s)",
            snmp_smi_get_varstr(p, var->smi_type), var->valuelen,
            snmp_asn1_get_oidstr(p, var->value.oid, var->valuelen));
        }
        break;

      case SNMP_SMI_NULL:
        res = snmp_asn1_read_null(p, buf, buflen, &(var->smi_type));
        if (res == 0) {
          pr_trace_msg(trace_channel, 19, "read %s variable",
            snmp_smi_get_varstr(p, var->smi_type));
        }
        break;

      case SNMP_SMI_NO_SUCH_OBJECT:
      case SNMP_SMI_NO_SUCH_INSTANCE:
      case SNMP_SMI_END_OF_MIB_VIEW:
        pr_trace_msg(trace_channel, 19, "read %s variable",
          snmp_smi_get_varstr(p, var->smi_type));
        break;

      case SNMP_SMI_COUNTER64:
        pr_trace_msg(trace_channel, 1,
          "unable to handle COUNTER64 variable (%x)", var->smi_type);
        /* fallthrough */

      default:
        pr_trace_msg(trace_channel, 1,
          "unable to read variable type %x", var->smi_type);
        destroy_pool(var->pool);
        pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
        errno = EINVAL;
        return -1;
    }

    if (res < 0) {
      return -1;
    }

    /* Add the variable to the end of the list. */
    if (tail != NULL) {
      tail->next = var;
      tail = var;

    } else {
      head = tail = var;
    }

    var_count++;
  }

  *varlist = head;
  return var_count;
}

/* Encode an SNMPv2 variable binding.
 *
 * As per RFC 1905 Protocol Operations for SNMPv2:
 *
 * VarBind ::=
 *   SEQUENCE {
 *     name ObjectName
 *     CHOICE {
 *       value ObjectSyntax
 *       unSpecified NULL
 *       noSuchObject[0] NULL
 *       noSuchInstance[1] NULL
 *       endOfMibView[2] NULL
 *     }
 *   }
 */
int snmp_smi_write_vars(pool *p, unsigned char **buf, size_t *buflen,
    struct snmp_var *varlist, int snmp_version) {
  struct snmp_var *iter;
  unsigned char asn1_type, *list_hdr_start, *list_hdr_end;
  size_t list_hdr_startlen;
  unsigned int asn1_len;
  int res;

  /* Write the header for the varlist. */
  asn1_type = (SNMP_ASN1_TYPE_SEQUENCE|SNMP_ASN1_CONSTRUCT);
  asn1_len = 0;

  list_hdr_start = *buf;
  list_hdr_startlen = *buflen;

  res = snmp_asn1_write_header(p, buf, buflen, asn1_type, asn1_len, 0);
  if (res < 0) {
    return -1;
  }

  list_hdr_end = *buf;

  for (iter = varlist; iter; iter = iter->next) {
    unsigned char *var_hdr_start = NULL, *var_hdr_end = NULL;
    size_t var_hdr_startlen;

    pr_signals_handle();

    /* Write the header for this variable. */
    asn1_type = (SNMP_ASN1_TYPE_SEQUENCE|SNMP_ASN1_CONSTRUCT);
    asn1_len = 0;

    var_hdr_start = *buf;
    var_hdr_startlen = *buflen;

    res = snmp_asn1_write_header(p, buf, buflen, asn1_type, asn1_len, 0);
    if (res < 0) {
      return -1;
    }

    var_hdr_end = *buf;

    asn1_type = (SNMP_ASN1_CLASS_UNIVERSAL|SNMP_ASN1_PRIMITIVE|SNMP_ASN1_TYPE_OID);
    res = snmp_asn1_write_oid(p, buf, buflen, asn1_type, iter->name,
      iter->namelen);
    if (res < 0) {
      return -1;
    }

    switch (iter->smi_type) {
      case SNMP_SMI_INTEGER:
        res = snmp_asn1_write_int(p, buf, buflen, iter->smi_type,
          *((long *) iter->value.integer), 0);
        break;

      case SNMP_SMI_COUNTER32:
      case SNMP_SMI_GAUGE32:
      case SNMP_SMI_TIMETICKS:
        res = snmp_asn1_write_uint(p, buf, buflen, iter->smi_type,
          *((unsigned long *) iter->value.integer));
        break;

      case SNMP_SMI_STRING:
      case SNMP_SMI_IPADDR:
      case SNMP_SMI_OPAQUE:
        res = snmp_asn1_write_string(p, buf, buflen, iter->smi_type,
          iter->value.string, iter->valuelen);
        break;

      case SNMP_SMI_OID:
        res = snmp_asn1_write_oid(p, buf, buflen, iter->smi_type,
          iter->value.oid, iter->valuelen);
        break;

      case SNMP_SMI_NO_SUCH_OBJECT:
      case SNMP_SMI_NO_SUCH_INSTANCE:
      case SNMP_SMI_END_OF_MIB_VIEW:
        if (snmp_version == SNMP_PROTOCOL_VERSION_1) {
          /* SNMPv1 does not support the other error codes. */
          res = snmp_asn1_write_null(p, buf, buflen, SNMP_SMI_NO_SUCH_OBJECT);

        } else {
          res = snmp_asn1_write_exception(p, buf, buflen, iter->smi_type, 0);
        }

        break;

      case SNMP_SMI_NULL:
        res = snmp_asn1_write_null(p, buf, buflen, iter->smi_type);
        break;

      case SNMP_SMI_COUNTER64:
        pr_trace_msg(trace_channel, 1, "%s",
          "unable to encode COUNTER64 SMI variable");
        /* fall through */

      default:
        /* Unsupported type */
        pr_trace_msg(trace_channel, 1, "%s",
          "unable to encode unsupported SMI variable type");
        pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
        errno = ENOSYS;
        return -1;
    }

    if (res < 0) {
      return -1;
    }

    /* Rewrite the header, this time with the appropriate length. */
    asn1_type = (SNMP_ASN1_TYPE_SEQUENCE|SNMP_ASN1_CONSTRUCT);
    asn1_len = (*buf - var_hdr_end);

    pr_trace_msg(trace_channel, 18,
      "updating variable header to have length %u", asn1_len);
    res = snmp_asn1_write_header(p, &var_hdr_start, &var_hdr_startlen,
      asn1_type, asn1_len, 0);
    if (res < 0) {
      return -1;
    }
  }

  /* Rewrite the varlist header, this time with the length of all of the
   * variables.
   */

  asn1_type = (SNMP_ASN1_TYPE_SEQUENCE|SNMP_ASN1_CONSTRUCT);
  asn1_len = (*buf - list_hdr_end);

  pr_trace_msg(trace_channel, 18,
    "updating variable bindings list header to have length %u", asn1_len);
  res = snmp_asn1_write_header(p, &list_hdr_start, &list_hdr_startlen,
    asn1_type, asn1_len, 0);
  if (res < 0) {
    return -1;
  }

  return 0;
}

unsigned int snmp_smi_util_add_list_var(struct snmp_var **head,
    struct snmp_var **tail, struct snmp_var *var) {
  unsigned int count = 0;
  struct snmp_var *iter_var;

  if (*head == NULL) {
    *head = var;
  }

  if (*tail != NULL) {
    (*tail)->next = var;
  }

  (*tail) = var;

  for (iter_var = *head; iter_var; iter_var = iter_var->next) {
    count++;
  }

  return count;
}

