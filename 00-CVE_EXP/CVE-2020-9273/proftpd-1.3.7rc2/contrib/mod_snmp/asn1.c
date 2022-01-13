/*
 * ProFTPD - mod_snmp ASN.1 support
 * Copyright (c) 2008-2017 TJ Saunders
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
#include "mib.h"

static const char *trace_channel = "snmp.asn1";

/* Set an arbitrary max limit of 512K on ASN.1 objects */
#define SNMP_ASN1_MAX_OBJECT_LEN	(512 * 1024)

static const char *asn1_typestr(unsigned char byte) {
  unsigned char asn1_type;
  const char *typestr = "(unknown)";

  asn1_type = byte;

  /* Clear any Class and P/C bits */
  asn1_type &= ~(SNMP_ASN1_CLASS_APPLICATION|SNMP_ASN1_CLASS_CONTEXT|SNMP_ASN1_CLASS_PRIVATE);
  asn1_type &= ~(SNMP_ASN1_CONSTRUCT);

  switch (asn1_type) {
    case SNMP_ASN1_TYPE_BOOLEAN:
      typestr = "BOOLEAN";
      break;

    case SNMP_ASN1_TYPE_INTEGER:
      typestr = "INTEGER";
      break;

    case SNMP_ASN1_TYPE_BITSTRING:
      typestr = "BITSTRING";
      break;

    case SNMP_ASN1_TYPE_OCTETSTRING:
      typestr = "OCTETSTRING";
      break;

    case SNMP_ASN1_TYPE_NULL:
      typestr = "NULL";
      break;

    case SNMP_ASN1_TYPE_OID:
      typestr = "OID";
      break;

    case SNMP_ASN1_TYPE_SEQUENCE:
      typestr = "SEQUENCE";
      break;

    case SNMP_ASN1_TYPE_SET:
      typestr = "SET";
      break;
  }

  return typestr;
}

static const char *asn1_classstr(unsigned char asn1_type) {
  const char *class_str = "Universal";

  if (asn1_type & SNMP_ASN1_CLASS_APPLICATION) {
    class_str = "Application";

  } else if (asn1_type & SNMP_ASN1_CLASS_CONTEXT) {
    class_str = "Context";

  } else if (asn1_type & SNMP_ASN1_CLASS_PRIVATE) {
    class_str = "Private";
  }

  return class_str;
}

static const char *asn1_pcstr(unsigned char asn1_type) {
  const char *pcstr = "Primitive";

  if (asn1_type & SNMP_ASN1_CONSTRUCT) {
    pcstr = "Construct";
  }

  return pcstr;
}

const char *snmp_asn1_get_oidstr(pool *p, oid_t *asn1_oid,
    unsigned int asn1_oidlen) {
  register unsigned int i;
  char *oidstr = "";

  if (asn1_oidlen == 0) {
    return oidstr;
  }

  for (i = 0; i < asn1_oidlen; i++) {
    char buf[16];

    memset(buf, '\0', sizeof(buf));
    pr_snprintf(buf, sizeof(buf)-1, "%lu", (unsigned long) asn1_oid[i]);

    oidstr = pstrcat(p, oidstr, buf, NULL);

    /* Skip the trailing '.' in the OID string. */
    if (i != (asn1_oidlen-1)) {
      oidstr = pstrcat(p, oidstr, ".", NULL);
    }
  }

  return oidstr;
}

const char *snmp_asn1_get_tagstr(pool *p, unsigned char asn1_type) {
  const char *tagstr;

  tagstr = pstrcat(p, "type '", asn1_typestr(asn1_type), "', class '",
    asn1_classstr(asn1_type), "', ", asn1_pcstr(asn1_type), NULL);
  return tagstr;
}

static int asn1_read_byte(pool *p, unsigned char **buf, size_t *buflen,
    unsigned char *byte) {

  if (*buflen < sizeof(unsigned char)) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "ASN.1 format error: unable to read type (buflen = %lu)",
      (unsigned long) *buflen);
    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;
  }

  memmove(byte, *buf, sizeof(unsigned char));
  (*buf) += sizeof(unsigned char);
  (*buflen) -= sizeof(unsigned char);

  return 0;
}

static int asn1_read_type(pool *p, unsigned char **buf, size_t *buflen,
    unsigned char *asn1_type, int flags) {
  unsigned char byte;
  int res;

  res = asn1_read_byte(p, buf, buflen, &byte);
  if (res < 0) {
    return -1;
  }

  *asn1_type = byte;

  if (!(flags & SNMP_ASN1_FL_NO_TRACE_TYPESTR)) {
    pr_trace_msg(trace_channel, 18,
      "read ASN.1 type 0x%02x (%s)", *asn1_type, asn1_typestr(*asn1_type));

  } else {
    pr_trace_msg(trace_channel, 18, "read byte 0x%02x", *asn1_type);
  }

  return 0;
}

static int asn1_read_len(pool *p, unsigned char **buf, size_t *buflen,
    unsigned int *asn1_len) {
  unsigned char byte;

  if (*buflen < sizeof(unsigned char)) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "ASN.1 format error: unable to read length (buflen = %lu)",
      (unsigned long) *buflen);
    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;
  }

  /* First we check the first byte in the buffer, the 'length' byte. */
  memmove(&byte, *buf, sizeof(unsigned char));
  (*buf) += sizeof(unsigned char);
  (*buflen) -= sizeof(unsigned char);

  if (byte & SNMP_ASN1_LEN_LONG) {
    byte &= ~SNMP_ASN1_LEN_LONG;

    /* The high bit was set, indicating a "long" length value, spread
     * out over the next bytes.
     */
    if (byte == 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "ASN.1 format error: invalid ASN1 length value %c", byte);
      pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
      errno = EINVAL;
      return -1;
    }

    if (byte > sizeof(unsigned int)) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "ASN.1 format error: invalid ASN1 length value %c (> %lu)", byte,
        (unsigned long) sizeof(unsigned int));
      pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
      errno = EINVAL;
      return -1;
    }

    *asn1_len = 0;
    memmove(asn1_len, *buf, (size_t) byte);
    (*buf) += byte;
    (*buflen) -= byte;

    *asn1_len = ntohl(*asn1_len);
    *asn1_len >>= (8 * ((sizeof(unsigned int)) - byte));

  } else {
    *asn1_len = (unsigned int) byte;
  }

  pr_trace_msg(trace_channel, 18, "read ASN.1 length %u", *asn1_len);
  return 0;
}

int snmp_asn1_read_header(pool *p, unsigned char **buf, size_t *buflen,
    unsigned char *asn1_type, unsigned int *asn1_len, int flags) {
  unsigned int objlen;
  int res;

  /* XXX Currently don't support extension octets.  We check this by looking
   * at the first byte of data to see if extension length bit is set.
   */
  if ((*buf)[0] == SNMP_ASN1_LEN_EXTENSION) {
    pr_trace_msg(trace_channel, 3,
      "failed reading object header: extension length bit set (%c)", (*buf)[0]);

    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EPERM;
    return -1;
  }

  /* Type */
  res = asn1_read_type(p, buf, buflen, asn1_type, flags);
  if (res < 0) {
    return -1;
  }

  /* Length */
  res = asn1_read_len(p, buf, buflen, &objlen);
  if (res < 0) {
    return -1;
  }

  /* Sanity check on the object length, to make sure it is not absurd. */
  if (objlen > SNMP_ASN1_MAX_OBJECT_LEN) {
    pr_trace_msg(trace_channel, 3,
      "failed reading object header: object length (%u bytes) is greater "
      "than max object length (%u bytes)", objlen, SNMP_ASN1_MAX_OBJECT_LEN);
    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;
  }

  if (objlen > *buflen) {
    pr_trace_msg(trace_channel, 3,
      "failed reading object header: object length (%u bytes) is greater "
      "than remaining data (%lu bytes)", objlen, (unsigned long) (*buflen));

    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;
  }

  *asn1_len = objlen;
  return 0;
}

/* ASN.1 integer ::= 0x02 objlen byte {byte}* */
int snmp_asn1_read_int(pool *p, unsigned char **buf, size_t *buflen,
    unsigned char *asn1_type, long *asn1_int, int flags) {
  unsigned int objlen = 0;
  long objval = 0;
  int res;

  /* Type */
  res = asn1_read_type(p, buf, buflen, asn1_type, 0);
  if (res < 0) {
    return -1;
  }

  /*  Check that we actually read an INTEGER as expected. */
  if (!(*asn1_type & SNMP_ASN1_TYPE_INTEGER)) {
    pr_trace_msg(trace_channel, 3,
      "unable to read INTEGER (received type '%s')",
      snmp_asn1_get_tagstr(p, *asn1_type));
    errno = EINVAL;
    return -1;
  }

  /* Length */
  res = asn1_read_len(p, buf, buflen, &objlen);
  if (res < 0) {
    return -1;
  }

  /* Make sure there'e enough remaining data for the object. */
  if (objlen > *buflen) {
    pr_trace_msg(trace_channel, 3,
      "failed reading object header: object length (%u bytes) is greater "
      "than remaining data (%lu bytes)", objlen, (unsigned long) (*buflen));

    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;
  }

  if ((*buf)[0] & 0x80) {
    /* The integer is negative; the negative sign bit is set. */

    if (flags & SNMP_ASN1_FL_UNSIGNED) {
      objval = ~objval;

    } else {
      objval = -1;
    }
  }

  /* Pull objlen bytes out of the buffer, building up the value. */
  while (objlen--) {
    unsigned char byte;

    pr_signals_handle();

    res = asn1_read_byte(p, buf, buflen, &byte);
    if (res < 0) {
      return -1;
    }

    objval = (objval << 8) | byte;
  }

  *asn1_int = objval;
  return 0;
}

int snmp_asn1_read_uint(pool *p, unsigned char **buf, size_t *buflen,
    unsigned char *asn1_type, unsigned long *asn1_uint) {
  long asn1_int;
  int flags, res;

  flags = SNMP_ASN1_FL_UNSIGNED;

  res = snmp_asn1_read_int(p, buf, buflen, asn1_type, &asn1_int, flags);
  if (res < 0) {
    return -1;
  }

  /* Check that the actual integer value read in is unsigned/not negative.
   * If it's negative, log a warning -- but proceed, and simply handle the
   * value as if it's unsigned, as the caller requested.
   */
  if (asn1_int < 0) {
    pr_trace_msg(trace_channel, 1,
      "ASN.1 integer value (%ld) is not unsigned as expected", asn1_int);
  }

  *asn1_uint = (unsigned int) asn1_int;
  return 0;
}

/* ASN.1 null ::= 0x05 0x00 */
int snmp_asn1_read_null(pool *p, unsigned char **buf, size_t *buflen,
    unsigned char *asn1_type) {
  unsigned int objlen;
  int res;

  /* Type */
  res = asn1_read_type(p, buf, buflen, asn1_type, 0);
  if (res < 0) {
    return -1;
  }

  /* Check that the type is actually a NULL, as expected. */
  if (!(*asn1_type & SNMP_ASN1_TYPE_NULL)) {
    pr_trace_msg(trace_channel, 3,
      "unable to read NULL (received type '%s')",
      snmp_asn1_get_tagstr(p, *asn1_type));
    errno = EINVAL;
    return -1;
  }

  res = asn1_read_len(p, buf, buflen, &objlen);
  if (res < 0) {
    return -1;
  }

  /* Check that the object len is zero, as expected. */
  if (objlen != 0) {
    pr_trace_msg(trace_channel, 3,
      "failed reading NULL object: object length (%u bytes) is not zero, "
      "as expected", objlen);

    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;
  }

  return 0;
}

/* ASN.1 OID ::= 0x06 asnlength subidentifier {subidentifier}*
 * subidentifier ::= {leadingbyte}* lastbyte
 * leadingbyte ::= 1 7bitvalue
 * lastbyte ::= 0 7bitvalue
 */
int snmp_asn1_read_oid(pool *p, unsigned char **buf, size_t *buflen,
    unsigned char *asn1_type, oid_t *asn1_oid, unsigned int *asn1_oidlen) {

  /* We leave room at the start of the OID memory for expansion into two
   * bytes from the first byte of buffer data.
   */
  oid_t *oid_ptr = asn1_oid + 1;

  unsigned int objlen, len, sub_id;
  int res;

  /* Type */
  res = asn1_read_type(p, buf, buflen, asn1_type, 0);
  if (res < 0) {
    return -1;
  }

  /* Check that asn1_type is actually for an OID, as expected. */
  if (!(*asn1_type & SNMP_ASN1_TYPE_OID)) {
    pr_trace_msg(trace_channel, 3,
      "unable to read OID (received type '%s')",
      snmp_asn1_get_tagstr(p, *asn1_type));
    errno = EINVAL;
    return -1;
  }

  /* Length */
  res = asn1_read_len(p, buf, buflen, &objlen);
  if (res < 0) {
    return -1;
  }

  /* Is there enough data remaining in the buffer for the indicated object? */
  if (objlen > *buflen) {
    pr_trace_msg(trace_channel, 3,
      "failed reading OID object: object length (%u bytes) is greater "
      "than remaining data (%lu bytes)", objlen, (unsigned long) (*buflen));

    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;
  }

  /* Handle invalid OID encodings of the form 06 00 robustly. */
  if (objlen == 0) {
    memset(asn1_oid, 0, sizeof(oid_t));
  }

  /* XXX Not sure I like this section; it presumes that the value in
   * *asn1_oidlen is already initialized to something sane.  Is that a valid
   * assumption?
   */

  len = objlen;
  (*asn1_oidlen)--;		/* account for expansion of first byte */
  while (len > 0 && (*asn1_oidlen)-- > 0) {
    unsigned char byte;

    pr_signals_handle();

    sub_id = 0;

    do {
      res = asn1_read_byte(p, buf, buflen, &byte);
      if (res < 0) {
        return -1;
      }

      /* Shift and add in the low order 7 bits */
      sub_id = (sub_id << 7) + (byte & ~0x80);
      len--;

    } while (byte & 0x80);

    if (sub_id > SNMP_ASN1_OID_MAX_ID) {
      pr_trace_msg(trace_channel, 3,
        "failed reading OID object: sub-identifer (%u is greater "
        "than maximum allowed OID value (%u)", sub_id, SNMP_ASN1_OID_MAX_ID);

      pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
      errno = EINVAL;
      return -1;
    }

    *oid_ptr++ = (oid_t) sub_id;
  }

  /* The first two subidentifiers are encoded into the first component with
   * the value (X * 40) + Y, where:
   *
   *  X is the value of the first subidentifier.
   *  Y is the value of the second subidentifier.
   */
  sub_id = (unsigned int) asn1_oid[1];
  if (sub_id == 0x2b) {
    asn1_oid[0] = 1;
    asn1_oid[1] = 3;

  } else {
    asn1_oid[1] = (unsigned char) (sub_id % 40);
    asn1_oid[0] = (unsigned char) ((sub_id - asn1_oid[1]) / 40);
  }

  *asn1_oidlen = (unsigned int) (oid_ptr - asn1_oid);
  return 0;
}

/* ASN.1 octet string ::= primitive-string | compound-string
 * primitive-string ::= 0x04 asnlength byte {byte}*
 * compound-string ::= 0x24 asnlength string {string}*
 */
int snmp_asn1_read_string(pool *p, unsigned char **buf, size_t *buflen,
    unsigned char *asn1_type, char **asn1_str, unsigned int *asn1_strlen) {
  unsigned int objlen;
  int res;

  /* Type */
  res = asn1_read_type(p, buf, buflen, asn1_type, 0);
  if (res < 0) {
    return -1;
  }

  /* Check the type to see if it actually is OCTET_STRING, as expected.
   * XXX What about compound strings, bitstrings?
   */
  if (!(*asn1_type & SNMP_ASN1_TYPE_OCTETSTRING)) {
    pr_trace_msg(trace_channel, 3,
      "unable to read OCTET_STRING (received type '%s')",
      snmp_asn1_get_tagstr(p, *asn1_type));
    errno = EINVAL;
    return -1;
  }

  /* Length */
  res = asn1_read_len(p, buf, buflen, &objlen);
  if (res < 0) {
    return -1;
  }

  /* Is there enough data remaining in the buffer for the indicated object? */
  if (objlen > *buflen) {
    pr_trace_msg(trace_channel, 3,
      "failed reading OCTET_STRING object: object length (%u bytes) is greater "
      "than remaining data (%lu bytes)", objlen, (unsigned long) (*buflen));

    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;
  }

  *asn1_strlen = objlen;
  *asn1_str = pstrndup(p, (char *) *buf, objlen);
  (*buf) += objlen;
  (*buflen) -= objlen;

  return 0;
}

static int asn1_write_byte(unsigned char **buf, size_t *buflen,
    unsigned char byte) {

  if (*buflen < sizeof(unsigned char)) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "ASN.1 format error: unable to write byte %c (buflen = %lu)", byte,
      (unsigned long) *buflen);
    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;
  }

  memmove(*buf, &byte, sizeof(unsigned char));
  (*buf) += sizeof(unsigned char);
  (*buflen) -= sizeof(unsigned char);

  return 0;
}

static int asn1_write_type(unsigned char **buf, size_t *buflen,
    unsigned char asn1_type, int flags) {
  int res;

  res = asn1_write_byte(buf, buflen, asn1_type);
  if (res < 0) {
    return -1;
  }

  if (!(flags & SNMP_ASN1_FL_NO_TRACE_TYPESTR)) {
    pr_trace_msg(trace_channel, 18,
      "wrote ASN.1 type 0x%02x (%s)", asn1_type, asn1_typestr(asn1_type));

  } else {
    pr_trace_msg(trace_channel, 18, "wrote byte 0x%02x", asn1_type);
  }

  return 0;
}

static int asn1_write_len(unsigned char **buf, size_t *buflen,
    unsigned int asn1_len, int flags) {
  int res;

  if (flags & SNMP_ASN1_FL_KNOWN_LEN) {
    pr_trace_msg(trace_channel, 19, "writing ASN.1 known length %u", asn1_len);

    /* No indefinite lengths sent. */
    if (asn1_len < SNMP_ASN1_LEN_LONG) {

      /* For this length, we only need one byte. */
      if (*buflen < sizeof(unsigned char)) {
        pr_trace_msg(trace_channel, 1,
          "ASN.1 format error: unable to write length %u (buflen = %lu)",
          asn1_len, (unsigned long) *buflen);

        pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
        errno = EINVAL;
        return -1;
      }

      res = asn1_write_byte(buf, buflen, (unsigned char) asn1_len);
      if (res < 0) {
        return -1;
      }

    } else if (asn1_len <= 0xff) {
      unsigned char first_byte, last_byte;

      /* For this length, we need two bytes. */
      if (*buflen < (2 * sizeof(unsigned char))) {
        pr_trace_msg(trace_channel, 1,
          "ASN.1 format error: unable to write length %u (buflen = %lu)",
          asn1_len, (unsigned long) *buflen);

        pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
        errno = EINVAL;
        return -1;
      }

      first_byte = (unsigned char) (0x01|SNMP_ASN1_LEN_LONG);
      res = asn1_write_byte(buf, buflen, first_byte);
      if (res < 0) {
        return -1;
      }

      last_byte = (unsigned char) asn1_len;
      res = asn1_write_byte(buf, buflen, last_byte);
      if (res < 0) {
        return -1;
      }

    } else {
      unsigned char first_byte;
      unsigned short len;

      /* Length is 0xff (255) < asn1_len <= 0xffff (65535) */

      /* For this length, we need three bytes. */
      if (*buflen < (3 * sizeof(unsigned char))) {
        pr_trace_msg(trace_channel, 1,
          "ASN.1 format error: unable to write length %u (buflen = %lu)",
          asn1_len, (unsigned long) *buflen);

        pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
        errno = EINVAL;
        return -1;
      }

      first_byte = (unsigned char) (0x02|SNMP_ASN1_LEN_LONG);
      res = asn1_write_byte(buf, buflen, first_byte);
      if (res < 0) {
        return -1;
      }

      len = (unsigned short) asn1_len;
      len = htons(len);

      memmove(*buf, &len, sizeof(unsigned short));
      (*buf) += sizeof(unsigned short);
      (*buflen) -= sizeof(unsigned short);
    }

  } else {
    unsigned char first_byte;
    unsigned short len;

    pr_trace_msg(trace_channel, 19, "writing ASN.1 unknown length %u",
      asn1_len);

    /* We don't know if this is the true length.  Make sure it's large
     * enough (i.e. three bytes) for later.
     */
    if (*buflen < (3 * sizeof(unsigned char))) {
      pr_trace_msg(trace_channel, 1,
        "ASN.1 format error: unable to write length %u (buflen = %lu)",
        asn1_len, (unsigned long) *buflen);

      pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
      errno = EINVAL;
      return -1;
    }

    first_byte = (unsigned char) (0x02|SNMP_ASN1_LEN_LONG);
    res = asn1_write_byte(buf, buflen, first_byte);
    if (res < 0) {
      return -1;
    }

    len = (unsigned short) asn1_len;
    len = htons(len);

    memmove(*buf, &len, sizeof(unsigned short));
    (*buf) += sizeof(unsigned short);
    (*buflen) -= sizeof(unsigned short);
  }

  pr_trace_msg(trace_channel, 18, "wrote ASN.1 length %u", asn1_len);
  return 0;
}

int snmp_asn1_write_header(pool *p, unsigned char **buf, size_t *buflen,
    unsigned char asn1_type, unsigned int asn1_len, int flags) {
  int res;

  res = asn1_write_type(buf, buflen, asn1_type, flags);
  if (res < 0) {
    return -1;
  }

  res = asn1_write_len(buf, buflen, asn1_len, flags);
  return res;
}

/* Why does the caller have to provide the ASN.1 type, if we know that they
 * want to write an INTEGER?
 *
 * Answer: Callers need to include the Class and Primitive/Constructed bits
 * in the ASN.1 type value as well, e.g.:
 *
 *  asn1_type = SNMP_ASN1_TYPE_INTEGER;
 *  asn1_type |= SNMP_ASN1_PRIMITIVE;
 *  asn1_type |= SNMP_ASN1_CLASS_UNIVERSAL;
 *
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */
int snmp_asn1_write_int(pool *p, unsigned char **buf, size_t *buflen,
    unsigned char asn1_type, long asn1_int, int flags) {
  unsigned int asn1_intsz;
  unsigned long bitmask;
  long objval;
  int res;

  /* XXX Check that asn1_type is INTEGER, as expected? */

  asn1_intsz = (unsigned int) sizeof(long);
  flags |= SNMP_ASN1_FL_KNOWN_LEN;

  /* Truncate "unnecessary" bytes off of the most significant end of this
   * 2's complement integer.  There should be no sequence of 9 consecutive 1's
   * or 0's at the most significant end of the integer.
   *
   * bitmask is 0xff800000 on a big-endian machine.
   */

  objval = asn1_int;
  bitmask = (unsigned long) 0x1ff << ((8 * (sizeof(long) - 1)) - 1);

  while (((objval & bitmask) == 0 ||
          (objval & bitmask) == bitmask) &&
         asn1_intsz > 1) {
    pr_signals_handle();

    asn1_intsz--;
    objval <<= 8;
  }

  res = snmp_asn1_write_header(p, buf, buflen, asn1_type, asn1_intsz, flags);
  if (res < 0) {
    return -1;
  }

  /* Is there enough room remaining in the buffer for the object? */
  if (*buflen < asn1_intsz) {
    pr_trace_msg(trace_channel, 3,
      "failed writing INTEGER object: object length (%u bytes) is greater "
      "than remaining buffer (%lu bytes)", asn1_intsz,
      (unsigned long) (*buflen));

    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;
  }

  /* At this point, bitmask is 0xff000000 on a big-endian machine. */
  bitmask = (unsigned long) 0xff << (8 * (sizeof(long) - 1));

  while (asn1_intsz--) {
    unsigned char byte;

    pr_signals_handle();

    byte = (unsigned char) ((objval & bitmask) >> (8 * (sizeof(long) - 1)));
    res = asn1_write_byte(buf, buflen, byte);
    if (res < 0) {
      return -1;
    }

    objval <<= 8;
  }

  pr_trace_msg(trace_channel, 18, "wrote ASN.1 value %ld", asn1_int);
  return 0;
}

/* ASN.1 integer ::= 0x02 asnlength byte {byte}* */
int snmp_asn1_write_uint(pool *p, unsigned char **buf, size_t *buflen,
    unsigned char asn1_type, unsigned long asn1_uint) {
  unsigned int asn1_uintsz, bitmask;
  int add_null_byte = FALSE, flags, res;

  /* XXX Check that asn1_type is INTEGER, as expected? */

  asn1_uintsz = (unsigned int) sizeof(unsigned int);
  flags = SNMP_ASN1_FL_KNOWN_LEN;

  /* Truncate "unnecessary" bytes off of the most significant end of this
   * 2's complement integer. 
   *
   * There should be no sequence of 9 consecutive 1's or 0's at the most
   * significant end of the integer.  The 1's case is taken care of below by
   * adding a null byte.
   *
   * bitmask is 0x80000000 on a big-endian machine
   */
  bitmask = (unsigned int) 0x80 << (8 * (sizeof(unsigned int) - 1));

  if ((asn1_uint & bitmask) != 0) {
    /* Add a null byte if MSB is set, to prevent sign extension. */
    add_null_byte = TRUE;
    asn1_uintsz++;
  }

  /* bitmask is 0xff800000 on a big-endian machine */
  bitmask = (unsigned int) 0x1ff << ((8 * (sizeof(unsigned int) - 1)) - 1);

  while ((asn1_uint & bitmask) == 0 &&
         asn1_uintsz > 1) {
    pr_signals_handle();

    asn1_uintsz--;
    asn1_uint <<= 8;
  }

  res = snmp_asn1_write_header(p, buf, buflen, asn1_type, asn1_uintsz, flags);
  if (res < 0) {
    return -1;
  }

  /* Is there enough room remaining in the buffer for the object? */
  if (*buflen < asn1_uintsz) {
    pr_trace_msg(trace_channel, 3,
      "failed writing INTEGER object: object length (%u bytes) is greater "
      "than remaining buffer (%lu bytes)", asn1_uintsz,
      (unsigned long) (*buflen));

    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;
  }

  if (add_null_byte) {
    res = asn1_write_byte(buf, buflen, 0);
    if (res < 0) {
      return -1;
    }

    asn1_uintsz--;
  }

  /* At this point, bitmask is 0xff000000 on a big-endian machine. */
  bitmask = (unsigned int) 0xff << (8 * (sizeof(unsigned int) - 1));
  while (asn1_uintsz--) {
    unsigned char byte;

    pr_signals_handle();

    byte = (unsigned char) ((asn1_uint & bitmask) >> (8 * (sizeof(unsigned int) - 1)));
    res = asn1_write_byte(buf, buflen, byte);
    if (res < 0) {
      return -1;
    }

    asn1_uint <<= 8;
  }

  pr_trace_msg(trace_channel, 18, "wrote ASN.1 value %lu", asn1_uint);
  return 0;
}

/* ASN.1 null ::= 0x05 0x00 */
int snmp_asn1_write_null(pool *p, unsigned char **buf, size_t *buflen,
  unsigned char asn1_type) {
  int flags, res;

  flags = SNMP_ASN1_FL_KNOWN_LEN;

  /* XXX Check that asn1_type is NULL, as expected? */

  res = snmp_asn1_write_header(p, buf, buflen, asn1_type, 0, flags);
  if (res < 0) {
    return -1;
  }

  pr_trace_msg(trace_channel, 18, "%s", "wrote ASN.1 value null");
  return res;
}

/* ASN.1 objid ::= 0x06 asnlength subidentifier {subidentifier}*
 * subidentifier ::= {leadingbyte}* lastbyte
 * leadingbyte ::= 1 7bitvalue
 * lastbyte ::= 0 7bitvalue
 */
int snmp_asn1_write_oid(pool *p, unsigned char **buf, size_t *buflen,
    unsigned char asn1_type, oid_t *asn1_oid, unsigned int asn1_oidlen) {
  register unsigned int i;
  unsigned char oid_lens[SNMP_ASN1_OID_MAX_LEN];
  unsigned int asn1_len;
  oid_t *oid_ptr = asn1_oid, sub_id, first_sub_id;
  int flags, res;

  flags = SNMP_ASN1_FL_KNOWN_LEN;

  /* XXX Check that asn1_type is OID, as expected? */

  /* ISO/IEC 8825 - Specification of Basic Encoding Rules for Abstract Syntax
   * Notation One (ASN.1) dictates that the first two sub-identifiers are
   * encoded into the first identifier using the the equation:
   *
   *  subid = ((first * 40) + second)
   *
   * Pad the OBJECT IDENTIFIER to at least two sub-identifiers.
   */

  /* Make sure that there are at least 2 sub-identifiers. */
  if (asn1_oidlen == 0) {
    /* If not, make the OID have two sub-identifiers, both valued zero. */
    sub_id = 0;
    asn1_oidlen = 0;

  } else if (asn1_oid[0] > 2) {
    /* Bad first sub-identifier value.
     *
     * The first sub-identifiers are limited to ccitt(0), iso(1), and
     * joint-iso-ccitt(2) as per RFC 2578.
     */
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "invalid first sub-identifier (%lu) in OID", (unsigned long) asn1_oid[0]);
    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;

  } else if (asn1_oidlen > SNMP_MIB_MAX_OIDLEN) {
    /* OID is too long for us. */
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "OID sub-identifier count (%u) exceeds max supported (%u)", asn1_oidlen,
      SNMP_MIB_MAX_OIDLEN);
    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;

  } else if (asn1_oidlen == 1) {
    /* Encode the first sub-identifier. */

    sub_id = (oid_ptr[0] * 40);
    asn1_oidlen = 2;
    oid_ptr++;
    
  } else {
    /* Combine the first two values. */

    sub_id = ((oid_ptr[0] * 40) + oid_ptr[1]);
    oid_ptr += 2;
  }

  first_sub_id = sub_id;

  /* Determine how many bytes are needed for the encoded value. */
  for (i = 1, asn1_len = 0;;) {
    pr_signals_handle();

    if (sub_id < (unsigned int) 0x80) {
      oid_lens[i] = 1;
      asn1_len += 1;

    } else if (sub_id < (unsigned int) 0x4000) {
      oid_lens[i] = 2;
      asn1_len += 2;

    } else if (sub_id < (unsigned int) 0x200000) {
      oid_lens[i] = 3;
      asn1_len += 3;

    } else if (sub_id < (unsigned int) 0x10000000) {
      oid_lens[i] = 4;
      asn1_len += 4;

    } else {
      oid_lens[i] = 5;
      asn1_len += 5;
    }

    i++;

    if (i >= asn1_oidlen) {
      break;
    }

    sub_id = *oid_ptr++;
  }

  res = snmp_asn1_write_header(p, buf, buflen, asn1_type, asn1_len, flags);
  if (res < 0) {
    return -1;
  }

  /* Is there enough room remaining in the buffer for the object? */
  if (*buflen < asn1_len) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "failed writing OID object: object length (%u bytes) is greater "
      "than remaining buffer (%lu bytes)", asn1_len, (unsigned long) (*buflen));

    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;
  }

  /* Write in the encoded OID value. */
  for (i = 1, sub_id = first_sub_id, oid_ptr = asn1_oid + 2;
       i < asn1_oidlen; i++) {
    unsigned char byte;

    if (i != 1) {
      sub_id = *oid_ptr++;

#if SIZEOF_LONG != 4
      if (sub_id > 0xffffffff) {
        sub_id &= 0xffffffff;
      }
#endif
    }

    switch (oid_lens[i]) {
      case 1:
        byte = (unsigned char) sub_id;
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        break;

      case 2:
        byte = (unsigned char) ((sub_id >> 7) | 0x80);
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        byte = (unsigned char) (sub_id & 0x07f);
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        break;

      case 3:
        byte = (unsigned char) ((sub_id >> 14) | 0x80);
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        byte = (unsigned char) ((sub_id >> 7 & 0x07f) | 0x80);
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        byte = (unsigned char) (sub_id & 0x07f);
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        break;

      case 4:
        byte = (unsigned char) ((sub_id >> 21) | 0x80);
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        byte = (unsigned char) ((sub_id >> 14 & 0x07f) | 0x80);
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        byte = (unsigned char) ((sub_id >> 7 & 0x07f) | 0x80);
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        byte = (unsigned char) (sub_id & 0x07f);
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        break;

      case 5:
        byte = (unsigned char) ((sub_id >> 28) | 0x80);
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        byte = (unsigned char) ((sub_id >> 21 & 0x07f) | 0x80);
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        byte = (unsigned char) ((sub_id >> 14 & 0x07f) | 0x80);
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        byte = (unsigned char) ((sub_id >> 7 & 0x07f) | 0x80);
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        byte = (unsigned char) (sub_id & 0x07f);
        res = asn1_write_byte(buf, buflen, byte);
        if (res < 0) {
          return -1;
        }

        break;
    }
  }

  pr_trace_msg(trace_channel, 18, "wrote ASN.1 value %s (%u bytes)",
    snmp_asn1_get_oidstr(p, asn1_oid, asn1_oidlen), asn1_len);
  return 0;
}

/* ASN.1 octet string ::= primitive-string | compound-string
 * primitive-string ::= 0x04 asnlength byte {byte}*
 * compound-string ::= 0x24 asnlength string {string}*
 *
 * Note: this code will never send a compound string.
 */
int snmp_asn1_write_string(pool *p, unsigned char **buf, size_t *buflen,
    unsigned char asn1_type, const char *asn1_str, unsigned int asn1_strlen) {
  int flags, res;

  flags = SNMP_ASN1_FL_KNOWN_LEN;

  /* XXX Check that asn1_type is OCTET_STRING, as expected? */

  res = snmp_asn1_write_header(p, buf, buflen, asn1_type, asn1_strlen, flags);
  if (res < 0) {
    return -1;
  }

  /* Is there enough room remaining in the buffer for the object? */
  if (*buflen < asn1_strlen) {
    pr_trace_msg(trace_channel, 3,
      "failed writing STRING object: object length (%lu bytes) is greater "
      "than remaining buffer (%lu bytes)", (unsigned long) asn1_strlen,
      (unsigned long) (*buflen));

    pr_log_stacktrace(snmp_logfd, MOD_SNMP_VERSION);
    errno = EINVAL;
    return -1;
  }

  memmove(*buf, asn1_str, asn1_strlen);
  (*buf) += asn1_strlen;
  (*buflen) -= asn1_strlen;

  pr_trace_msg(trace_channel, 18, "wrote ASN.1 value '%.*s' (%u bytes)",
    (int) asn1_strlen, asn1_str, asn1_strlen);
  return 0;
}

/* ASN.1 variable exception ::= 0x8i 0x00, where i the exception identifier:
 * noSuchObject(0), noSuchInstance(1), endOfMibView(2).
 */
int snmp_asn1_write_exception(pool *p, unsigned char **buf, size_t *buflen,
    unsigned char asn1_type, unsigned char asn1_ex) {
  int flags, res;

  flags = SNMP_ASN1_FL_KNOWN_LEN;

  /* XXX Check that asn1_type is EXCEPTION, as expected? */

  res = snmp_asn1_write_header(p, buf, buflen, asn1_type, asn1_ex, flags);
  if (res < 0) {
    return -1;
  }

  pr_trace_msg(trace_channel, 18, "wrote ASN.1 value %u", asn1_ex);
  return res;
}
