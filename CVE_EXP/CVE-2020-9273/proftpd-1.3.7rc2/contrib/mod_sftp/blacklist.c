/*
 * Support for RSA/DSA key blacklisting based on partial fingerprints,
 * developed under Openwall Project for Owl - http://www.openwall.com/Owl/
 *
 * Copyright (c) 2008 Dmitry V. Levin <ldv at cvs.openwall.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * The blacklist encoding was designed by Solar Designer and Dmitry V. Levin.
 * No intellectual property rights to the encoding scheme are claimed.
 *
 * This effort was supported by CivicActions - http://www.civicactions.com
 *
 * The file size to encode 294,903 of 48-bit fingerprints is just 1.3 MB,
 * which corresponds to less than 4.5 bytes per fingerprint.
 */

#include "mod_sftp.h"
#include "blacklist.h"
#include "keys.h"

struct blacklist_header {
  /* format version identifier */
  char version[8];

  /* index size, in bits */
  uint8_t index_size;

  /* offset size, in bits */
  uint8_t offset_size;

  /* record size, in bits */
  uint8_t record_bits;

  /* number of records */
  uint8_t records[3];

  /* offset shift */
  uint8_t shift[2];

};

/* Set a maximum number of records we expect to find in the blacklist file.
 * The blacklist.dat file shipped with mod_sftp contains 294903 records.
 */
#define SFTP_BLACKLIST_MAX_RECORDS	300000

static const char *blacklist_path = PR_CONFIG_DIR "/blacklist.dat";

static const char *trace_channel = "ssh2";

static unsigned c2u(uint8_t c) {
  return (c >= 'a') ? (c - 'a' + 10) : (c - '0');
}

static int validate_blacklist(int fd, unsigned int *bytes,
    unsigned int *records, unsigned int *shift) {

  size_t expected;
  struct stat st;
  struct blacklist_header hdr;

  if (fstat(fd, &st)) {
    pr_trace_msg(trace_channel, 3, "error checking SFTPKeyBlacklist '%s': %s",
      blacklist_path, strerror(errno));
    return -1;
  }

  if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
    pr_trace_msg(trace_channel, 3,
      "error reading header of SFTPKeyBlacklist '%s': %s", blacklist_path,
      strerror(errno));
    return -1;
  }

  /* Check the header format and version */
  if (memcmp(hdr.version, "SSH-FP", 6) != 0) {
    pr_trace_msg(trace_channel, 2,
      "SFTPKeyBlacklist '%s' has unknown format", blacklist_path);
    return -1;
  }

  if (hdr.index_size != 16 ||
      hdr.offset_size != 16 ||
      memcmp(hdr.version, "SSH-FP00", 8) != 0) {
    pr_trace_msg(trace_channel, 2,
      "SFTPKeyBlacklist '%s' has unsupported format", blacklist_path);
    return -1;
  }

  *bytes = (hdr.record_bits >> 3) - 2;

  *records = (((hdr.records[0] << 8) + hdr.records[1]) << 8) + hdr.records[2];
  if (*records > SFTP_BLACKLIST_MAX_RECORDS) {
    pr_trace_msg(trace_channel, 2,
      "SFTPKeyBlacklist '%s' contains %u records > max %u records",
      blacklist_path, *records, (unsigned int) SFTP_BLACKLIST_MAX_RECORDS);
    *records = SFTP_BLACKLIST_MAX_RECORDS;
  }

  *shift = (hdr.shift[0] << 8) + hdr.shift[1];

  expected = sizeof(hdr) + 0x20000 + (*records) * (*bytes);
  if (st.st_size != (off_t) expected) {
    pr_trace_msg(trace_channel, 4,
      "unexpected SFTPKeyBlacklist '%s' file size: expected %lu, found %lu",
      blacklist_path, (unsigned long) expected, (unsigned long) st.st_size);
    return -1;
  }

  return 0;
}

static int expected_offset(uint16_t idx, uint16_t shift,
    unsigned int records) {
  return (int) (((idx * (long long) records) >> 16) - shift);
}

/* Returns -1 if there was an error, 1 if the fingerprint was found, and
 * 0 otherwise.
 */
static int check_fp(int fd, const char *fp_str) {
  register unsigned int i;
  unsigned int bytes, num, records, shift;
  off_t offset;
  int off_start, off_end, res;
  uint16_t idx;

  /* Max number of bytes stored in record_bits, minus two bytes used for
   * index.
   */
  uint8_t buf[(0xff >> 3) - 2];

  res = validate_blacklist(fd, &bytes, &records, &shift);
  if (res < 0)
    return res;

  idx = (((((c2u(fp_str[0]) << 4) | c2u(fp_str[1])) << 4) |
    c2u(fp_str[2])) << 4) | c2u(fp_str[3]);

  offset = sizeof(struct blacklist_header) + (idx * 2);
  if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
    pr_trace_msg(trace_channel, 3, "error seeking to offset %" PR_LU
      " in SFTPKeyBlacklist '%s': %s", (pr_off_t) offset, blacklist_path,
      strerror(errno));
    return -1;
  }

  if (read(fd, buf, 4) != 4) {
    pr_trace_msg(trace_channel, 3, "error reading SFTPKeyBlacklist '%s': %s",
      blacklist_path, strerror(errno));
    return -1;
  }

  off_start = (buf[0] << 8) + buf[1] + expected_offset(idx, shift, records);

  if (off_start < 0 ||
      (unsigned int) off_start > records) {
    pr_trace_msg(trace_channel, 4,
      "SFTPKeyBlacklist '%s' has offset start overflow [%d] for index %#x",
      blacklist_path, off_start, idx);
    return -1;
  }

  if (idx < 0xffff) {
    off_end = (buf[2] << 8) + buf[3] +
      expected_offset(idx + 1, shift, records);

    if (off_end < off_start ||
        (unsigned int) off_end > records) {
      pr_trace_msg(trace_channel, 4,
        "SFTPKeyBlacklist '%s' has offset end overflow [%d] for index %#x",
        blacklist_path, off_start, idx);
      return -1;
    }

  } else {
    off_end = records;
  }

  offset = sizeof(struct blacklist_header) + 0x20000 + (off_start * bytes);
  if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
    pr_trace_msg(trace_channel, 3, "error seeking to offset %" PR_LU
      " in SFTPKeyBlacklist '%s': %s", (pr_off_t) offset, blacklist_path,
      strerror(errno));
    return -1;
  }

  num = off_end - off_start;

  for (i = 0; i < num; ++i) {
    register unsigned int j;

    if (read(fd, buf, bytes) != bytes) {
      pr_trace_msg(trace_channel, 2, "error reading SFTPKeyBlacklist '%s': %s",
        blacklist_path, strerror(errno));
      return -1;
    }

    for (j = 0; j < bytes; ++j) {
      if (((c2u(fp_str[4 + j * 2]) << 4) | c2u(fp_str[5 + j * 2])) != buf[j])
        break;
    }

    if (j >= bytes) {
      pr_trace_msg(trace_channel, 6,
        "fingerprint '%s' blacklisted (offset %u, number %u)", fp_str,
        off_start, i);
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "public key is blacklisted");
      return 1;
    }
  }

  pr_trace_msg(trace_channel, 12,
    "fingerprint '%s' not blacklisted (offset %u, number %u)", fp_str,
    off_start, num);
  return 0;
}

int sftp_blacklist_reject_key(pool *p, unsigned char *key_data,
    uint32_t key_datalen) {
  int fd, res;
  const char *fp;
  char *digest_name = "none", *hex, *ptr;
  size_t hex_len, hex_maxlen;

  if (key_data == NULL ||
      key_datalen == 0) {
    return FALSE;
  }

  if (blacklist_path == NULL) {
    /* No key blacklist configured, nothing to do. */
    return FALSE;
  }

#ifdef OPENSSL_FIPS
  if (FIPS_mode()) {
    /* Use SHA1 fingerprints when in FIPS mode, since FIPS does not allow the
     * MD5 algorithm.
     */
    digest_name = "SHA1";
    fp = sftp_keys_get_fingerprint(p, key_data, key_datalen,
      SFTP_KEYS_FP_DIGEST_SHA1);

    /* SHA1 digests are 20 bytes (40 bytes when hex-encoded). */
    hex_maxlen = 40;

  } else { 
#endif /* OPENSSL_FIPS */
    digest_name = "MD5";
    fp = sftp_keys_get_fingerprint(p, key_data, key_datalen,
      SFTP_KEYS_FP_DIGEST_MD5);

    /* MD5 digests are 16 bytes (32 bytes when hex-encoded). */
    hex_maxlen = 32;
#ifdef OPENSSL_FIPS
  }
#endif /* OPENSSL_FIPS */

  /* If we can't obtain a fingerprint for any reason, assume the key is OK. */
  if (fp == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unable to obtain %s fingerprint for checking against blacklist: %s",
      digest_name, strerror(errno));
    return FALSE;
  }

  pr_trace_msg(trace_channel, 5,
    "checking key %s fingerprint against SFTPKeyBlacklist '%s'",
    digest_name, blacklist_path);

  /* Get a version of the fingerprint sans the colon delimiters. */
  hex = pstrdup(p, fp);
  for (ptr = hex; *fp; ++fp) {
    pr_signals_handle();

    if (*fp != ':')
      *ptr++ = *fp;
  }
  *ptr = '\0';

  hex_len = strlen(hex);
  if (hex_len != hex_maxlen ||
      hex_len != strspn(hex, "0123456789abcdef")) {
    pr_trace_msg(trace_channel, 3, "invalid %s fingerprint: '%s'", digest_name,
      hex);
    return FALSE;
  }

  /* XXX Will this fd need to be cached, for handling keys after the
   * process has chrooted?
   */
  fd = open(blacklist_path, O_RDONLY);
  if (fd < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unable to open SFTPKeyBlacklist '%s': %s", blacklist_path,
      strerror(errno));
    return FALSE;
  }

  res = check_fp(fd, hex);
  close(fd);

  if (res == 1)
    return TRUE;

  return FALSE;  
}

int sftp_blacklist_set_file(const char *path) {
  if (path == NULL) {
    blacklist_path = NULL;
  }

  blacklist_path = pstrdup(sftp_pool, path);
  return 0;
}
