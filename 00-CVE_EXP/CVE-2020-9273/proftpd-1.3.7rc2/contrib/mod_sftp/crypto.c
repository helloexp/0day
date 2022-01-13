/*
 * ProFTPD - mod_sftp OpenSSL interface
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

#include "mod_sftp.h"
#include "crypto.h"
#include "umac.h"

/* In OpenSSL 0.9.7, all des_ functions were renamed to DES_ to avoid 
 * clashes with older versions of libdes. 
 */ 
#if OPENSSL_VERSION_NUMBER < 0x000907000L 
# define DES_key_schedule des_key_schedule 
# define DES_cblock des_cblock 
# define DES_encrypt3 des_encrypt3 
# define DES_set_key_unchecked des_set_key_unchecked 
#endif

#if OPENSSL_VERSION_NUMBER > 0x000907000L
static const char *crypto_engine = NULL;
#endif

struct sftp_cipher {
  const char *name;
  const char *openssl_name;

  /* Used mostly for the RC4/ArcFour algorithms, for mitigating attacks
   * based on the first N bytes of the keystream.
   */
  size_t discard_len;

#if OPENSSL_VERSION_NUMBER > 0x000907000L
  const EVP_CIPHER *(*get_type)(void);
#else
  EVP_CIPHER *(*get_type)(void);
#endif

  /* Is this cipher enabled by default?  If FALSE, then this cipher must
   * be explicitly requested via SFTPCiphers.
   */
  int enabled;

  /* Is this cipher usable when FIPS is enabled?  If FALSE, then this
   * cipher must NOT be advertised to clients in the KEXINIT.
   */
  int fips_allowed;
};

/* Currently, OpenSSL does NOT support AES CTR modes (not sure why).
 * Until then, we have to provide our own CTR code, for some of the ciphers
 * recommended by RFC4344.
 *
 * And according to:
 *
 *   http://www.cpni.gov.uk/Docs/Vulnerability_Advisory_SSH.txt
 *
 * it is highly recommended to use CTR mode ciphers, rather than CBC mode,
 * in order to avoid leaking plaintext.
 */

static struct sftp_cipher ciphers[] = {
  /* The handling of NULL openssl_name and get_type fields is done in
   * sftp_crypto_get_cipher(), as special cases.
   */
#if OPENSSL_VERSION_NUMBER > 0x000907000L
  { "aes256-ctr",	NULL,		0,	NULL,	TRUE, TRUE },
  { "aes192-ctr",	NULL,		0,	NULL,	TRUE, TRUE },
  { "aes128-ctr",	NULL,		0,	NULL,	TRUE, TRUE },

# ifndef HAVE_AES_CRIPPLED_OPENSSL
  { "aes256-cbc",	"aes-256-cbc",	0,	EVP_aes_256_cbc, TRUE, TRUE },
  { "aes192-cbc",	"aes-192-cbc",	0,	EVP_aes_192_cbc, TRUE, TRUE },
# endif /* !HAVE_AES_CRIPPLED_OPENSSL */

  { "aes128-cbc",	"aes-128-cbc",	0,	EVP_aes_128_cbc, TRUE, TRUE },
#endif

#if !defined(OPENSSL_NO_BF)
  { "blowfish-ctr",	NULL,		0,	NULL,	FALSE, FALSE },
  { "blowfish-cbc",	"bf-cbc",	0,	EVP_bf_cbc, FALSE, FALSE },
#endif /* !OPENSSL_NO_BF */

#if !defined(OPENSSL_NO_CAST)
  { "cast128-cbc",	"cast5-cbc",	0,	EVP_cast5_cbc, TRUE, FALSE },
#endif /* !OPENSSL_NO_CAST */

#if !defined(OPENSSL_NO_RC4)
  { "arcfour256",	"rc4",		1536,	EVP_rc4, FALSE, FALSE },
  { "arcfour128",	"rc4",		1536,	EVP_rc4, FALSE, FALSE },
#endif /* !OPENSSL_NO_RC4 */

#if 0
  /* This cipher is explicitly NOT supported because it does not discard
   * the first N bytes of the keystream, unlike the other RC4 ciphers.
   *
   * If there is a hue and cry, I might add this to the code BUT it would
   * require explicit configuration via SFTPCiphers, and would generate
   * warnings about its unsafe use.
   */
  { "arcfour",		"rc4",		0,	EVP_rc4, FALSE, FALSE },
#endif

#if !defined(OPENSSL_NO_DES)
  { "3des-ctr",		NULL,		0,	NULL, TRUE, TRUE },
  { "3des-cbc",		"des-ede3-cbc",	0,	EVP_des_ede3_cbc, TRUE, TRUE },
#endif /* !OPENSSL_NO_DES */

  { "none",		"null",		0,	EVP_enc_null, FALSE, TRUE },
  { NULL, NULL, 0, NULL, FALSE, FALSE }
};

struct sftp_digest {
  const char *name;
  const char *openssl_name;

#if OPENSSL_VERSION_NUMBER > 0x000907000L
  const EVP_MD *(*get_type)(void);
#else
  EVP_MD *(*get_type)(void);
#endif

  uint32_t mac_len;

  /* Is this MAC enabled by default?  If FALSE, then this MAC must be
   * explicitly requested via SFTPDigests.
   */
  int enabled;

  /* Is this MAC usable when FIPS is enabled?  If FALSE, then this digest must
   * NOT be advertised to clients in the KEXINIT.
   */
  int fips_allowed;
};

static struct sftp_digest digests[] = {
  /* The handling of NULL openssl_name and get_type fields is done in
   * sftp_crypto_get_digest(), as special cases.
   */
#ifdef HAVE_SHA256_OPENSSL
  { "hmac-sha2-256",	"sha256",		EVP_sha256,	0, TRUE, TRUE },
#endif /* SHA256 support in OpenSSL */
#ifdef HAVE_SHA512_OPENSSL
  { "hmac-sha2-512",	"sha512",		EVP_sha512,	0, TRUE, TRUE },
#endif /* SHA512 support in OpenSSL */
  { "hmac-sha1",	"sha1",		EVP_sha1,	0, 	TRUE, TRUE },
  { "hmac-sha1-96",	"sha1",		EVP_sha1,	12,	TRUE, TRUE },
  { "hmac-md5",		"md5",		EVP_md5,	0,	FALSE, FALSE },
  { "hmac-md5-96",	"md5",		EVP_md5,	12,	FALSE, FALSE },
#if !defined(OPENSSL_NO_RIPEMD)
  { "hmac-ripemd160",	"rmd160",	EVP_ripemd160,	0,	FALSE, FALSE },
#endif /* !OPENSSL_NO_RIPEMD */
#if OPENSSL_VERSION_NUMBER > 0x000907000L
  { "umac-64@openssh.com", NULL,	NULL,		8,	TRUE, FALSE },
  { "umac-128@openssh.com", NULL,	NULL,		16,	TRUE, FALSE },
#endif /* OpenSSL-0.9.7 or later */
  { "none",		"null",		EVP_md_null,	0,	FALSE, TRUE },
  { NULL, NULL, NULL, 0, FALSE, FALSE }
};

static const char *trace_channel = "ssh2";

static void ctr_incr(unsigned char *ctr, size_t len) {
  register int i;

  if (len == 0) {
    return;
  }

  for (i = len - 1; i >= 0; i--) {
    /* If we haven't overflowed, we're done. */
    if (++ctr[i]) {
      return;
    }
  }
}

#if !defined(OPENSSL_NO_BF)
/* Blowfish CTR mode implementation */

struct bf_ctr_ex {
  BF_KEY key;
  unsigned char counter[BF_BLOCK];
};

static int init_bf_ctr(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc) {
  struct bf_ctr_ex *bce;

  bce = EVP_CIPHER_CTX_get_app_data(ctx);
  if (bce == NULL) {

    /* Allocate our data structure. */
    bce = calloc(1, sizeof(struct bf_ctr_ex));
    if (bce == NULL) {
      pr_log_pri(PR_LOG_ALERT, MOD_SFTP_VERSION ": Out of memory!");
      _exit(1);
    }

    EVP_CIPHER_CTX_set_app_data(ctx, bce);
  }

  if (key != NULL) {
    int key_len;

# if OPENSSL_VERSION_NUMBER == 0x0090805fL
    /* OpenSSL 0.9.8e had a bug where EVP_CIPHER_CTX_key_length() returned
     * the cipher key length rather than the context key length.
     */
    key_len = ctx->key_len;
# else
    key_len = EVP_CIPHER_CTX_key_length(ctx);
# endif

    BF_set_key(&(bce->key), key_len, key);
  }

  if (iv != NULL) {
    memcpy(bce->counter, iv, BF_BLOCK);
  }

  return 1;
}

static int cleanup_bf_ctr(EVP_CIPHER_CTX *ctx) {
  struct bf_ctr_ex *bce;

  bce = EVP_CIPHER_CTX_get_app_data(ctx);
  if (bce != NULL) {
    pr_memscrub(bce, sizeof(struct bf_ctr_ex));
    free(bce);
    EVP_CIPHER_CTX_set_app_data(ctx, NULL);
  }

  return 1;
}

static int do_bf_ctr(EVP_CIPHER_CTX *ctx, unsigned char *dst,
    const unsigned char *src, size_t len) {
  struct bf_ctr_ex *bce;
  unsigned int n;
  unsigned char buf[BF_BLOCK];

  if (len == 0)
    return 1;

  bce = EVP_CIPHER_CTX_get_app_data(ctx);
  if (bce == NULL)
    return 0;

  n = 0;

  while ((len--) > 0) {
    pr_signals_handle();

    if (n == 0) {
      BF_LONG ctr[2];

      /* Ideally, we would not be using htonl/ntohl here, and the following
       * code would be as simple as:
       *
       *  memcpy(buf, bce->counter, BF_BLOCK);
       *  BF_encrypt((BF_LONG *) buf, &(bce->key));
       *
       * However, the above is susceptible to endianness issues.  The only
       * client that I could find which implements the blowfish-ctr cipher,
       * PuTTy, uses its own big-endian Blowfish implementation.  So the
       * above code will work with PuTTy, but only on big-endian machines.
       * For little-endian machines, we need to handle the endianness
       * ourselves.  Whee.
       */

      memcpy(&(ctr[0]), bce->counter, sizeof(BF_LONG));
      memcpy(&(ctr[1]), bce->counter + sizeof(BF_LONG), sizeof(BF_LONG));

      /* Convert to big-endian values before encrypting the counter... */
      ctr[0] = htonl(ctr[0]);
      ctr[1] = htonl(ctr[1]);

      BF_encrypt(ctr, &(bce->key));

      /* ...and convert back to little-endian before XOR'ing the counter in. */
      ctr[0] = ntohl(ctr[0]);
      ctr[1] = ntohl(ctr[1]);

      memcpy(buf, ctr, BF_BLOCK);

      ctr_incr(bce->counter, BF_BLOCK);
    }

    *(dst++) = *(src++) ^ buf[n];
    n = (n + 1) % BF_BLOCK;
  }

  return 1;
}

static const EVP_CIPHER *get_bf_ctr_cipher(void) {
  EVP_CIPHER *cipher;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  /* XXX TODO: At some point, we also need to call EVP_CIPHER_meth_free() on
   * this, to avoid a resource leak.
   */
  cipher = EVP_CIPHER_meth_new(NID_bf_cbc, BF_BLOCK, 32);
  EVP_CIPHER_meth_set_iv_length(cipher, BF_BLOCK);
  EVP_CIPHER_meth_set_init(cipher, init_bf_ctr);
  EVP_CIPHER_meth_set_cleanup(cipher, cleanup_bf_ctr);
  EVP_CIPHER_meth_set_do_cipher(cipher, do_bf_ctr);
  EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_CBC_MODE|EVP_CIPH_VARIABLE_LENGTH|EVP_CIPH_ALWAYS_CALL_INIT|EVP_CIPH_CUSTOM_IV);

#else
  static EVP_CIPHER bf_ctr_cipher;

  memset(&bf_ctr_cipher, 0, sizeof(EVP_CIPHER));

  bf_ctr_cipher.nid = NID_bf_cbc;
  bf_ctr_cipher.block_size = BF_BLOCK;
  bf_ctr_cipher.iv_len = BF_BLOCK;
  bf_ctr_cipher.key_len = 32;
  bf_ctr_cipher.init = init_bf_ctr;
  bf_ctr_cipher.cleanup = cleanup_bf_ctr;
  bf_ctr_cipher.do_cipher = do_bf_ctr;

  bf_ctr_cipher.flags = EVP_CIPH_CBC_MODE|EVP_CIPH_VARIABLE_LENGTH|EVP_CIPH_ALWAYS_CALL_INIT|EVP_CIPH_CUSTOM_IV;

  cipher = &bf_ctr_cipher;
#endif /* prior to OpenSSL-1.1.0 */

  return cipher;
}
#endif /* !OPENSSL_NO_BF */

#if OPENSSL_VERSION_NUMBER > 0x000907000L

# if !defined(OPENSSL_NO_DES)
/* 3DES CTR mode implementation */

struct des3_ctr_ex {
  DES_key_schedule sched[3];
  unsigned char counter[8];
  int big_endian;
};

static uint32_t byteswap32(uint32_t in) {
  uint32_t out;

  out = (((in & 0x000000ff) << 24) |
         ((in & 0x0000ff00) << 8) |
         ((in & 0x00ff0000) >> 8) |
         ((in & 0xff000000) >> 24));

  return out;
}

static int init_des3_ctr(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc) {
  struct des3_ctr_ex *dce;

  dce = EVP_CIPHER_CTX_get_app_data(ctx);
  if (dce == NULL) {

    /* Allocate our data structure. */
    dce = calloc(1, sizeof(struct des3_ctr_ex));
    if (dce == NULL) {
      pr_log_pri(PR_LOG_ALERT, MOD_SFTP_VERSION ": Out of memory!");
      _exit(1);
    }

    /* Simple test to see if we're on a big- or little-endian machine:
     * on big-endian machines, the ntohl() et al will be no-ops.
     */
    dce->big_endian = (ntohl(1234) == 1234);

    EVP_CIPHER_CTX_set_app_data(ctx, dce);
  }

  if (key != NULL) {
    register unsigned int i;
    unsigned char *ptr;

    ptr = (unsigned char *) key;

    for (i = 0; i < 3; i++) {
      DES_cblock material[8];
      memcpy(material, ptr, 8);
      ptr += 8;

      DES_set_key_unchecked(material, &(dce->sched[i]));
    }
  }

  if (iv != NULL) {
    memcpy(dce->counter, iv, 8);
  }

  return 1;
}

static int cleanup_des3_ctr(EVP_CIPHER_CTX *ctx) {
  struct des3_ctr_ex *dce;

  dce = EVP_CIPHER_CTX_get_app_data(ctx);
  if (dce != NULL) {
    pr_memscrub(dce, sizeof(struct des3_ctr_ex));
    free(dce);
    EVP_CIPHER_CTX_set_app_data(ctx, NULL);
  }

  return 1;
}

static int do_des3_ctr(EVP_CIPHER_CTX *ctx, unsigned char *dst,
    const unsigned char *src, size_t len) {
  struct des3_ctr_ex *dce;
  unsigned int n;
  unsigned char buf[8];

  if (len == 0)
    return 1;

  dce = EVP_CIPHER_CTX_get_app_data(ctx);
  if (dce == NULL)
    return 0;

  n = 0;

  while ((len--) > 0) {
    pr_signals_handle();

    if (n == 0) {
      DES_LONG ctr[2];

      memcpy(&(ctr[0]), dce->counter, sizeof(DES_LONG));
      memcpy(&(ctr[1]), dce->counter + sizeof(DES_LONG), sizeof(DES_LONG));

      if (dce->big_endian) {
        /* If we are on a big-endian machine, we need to initialize the counter
         * using little-endian values, since that is what OpenSSL's
         * DES_encryptX() functions expect.
         */

        ctr[0] = byteswap32(ctr[0]);
        ctr[1] = byteswap32(ctr[1]);
      }

      DES_encrypt3(ctr, &(dce->sched[0]), &(dce->sched[1]), &(dce->sched[2]));

      if (dce->big_endian) {
        ctr[0] = byteswap32(ctr[0]);
        ctr[1] = byteswap32(ctr[1]);
      }

      memcpy(buf, ctr, 8);

      ctr_incr(dce->counter, 8);
    }

    *(dst++) = *(src++) ^ buf[n];
    n = (n + 1) % 8;
  }

  return 1;
}

static const EVP_CIPHER *get_des3_ctr_cipher(void) {
  EVP_CIPHER *cipher;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  unsigned long flags;

  /* XXX TODO: At some point, we also need to call EVP_CIPHER_meth_free() on
   * this, to avoid a resource leak.
   */
  cipher = EVP_CIPHER_meth_new(NID_des_ede3_ecb, 8, 24);
  EVP_CIPHER_meth_set_iv_length(cipher, 8);
  EVP_CIPHER_meth_set_init(cipher, init_des3_ctr);
  EVP_CIPHER_meth_set_cleanup(cipher, cleanup_des3_ctr);
  EVP_CIPHER_meth_set_do_cipher(cipher, do_des3_ctr);

  flags = EVP_CIPH_CBC_MODE|EVP_CIPH_VARIABLE_LENGTH|EVP_CIPH_ALWAYS_CALL_INIT|EVP_CIPH_CUSTOM_IV;
#ifdef OPENSSL_FIPS
  flags |= EVP_CIPH_FLAG_FIPS;
#endif /* OPENSSL_FIPS */

  EVP_CIPHER_meth_set_flags(cipher, flags);

#else
  static EVP_CIPHER des3_ctr_cipher;

  memset(&des3_ctr_cipher, 0, sizeof(EVP_CIPHER));

  des3_ctr_cipher.nid = NID_des_ede3_ecb;
  des3_ctr_cipher.block_size = 8;
  des3_ctr_cipher.iv_len = 8;
  des3_ctr_cipher.key_len = 24;
  des3_ctr_cipher.init = init_des3_ctr;
  des3_ctr_cipher.cleanup = cleanup_des3_ctr;
  des3_ctr_cipher.do_cipher = do_des3_ctr;

  des3_ctr_cipher.flags = EVP_CIPH_CBC_MODE|EVP_CIPH_VARIABLE_LENGTH|EVP_CIPH_ALWAYS_CALL_INIT|EVP_CIPH_CUSTOM_IV;
#ifdef OPENSSL_FIPS
  des3_ctr_cipher.flags |= EVP_CIPH_FLAG_FIPS;
#endif /* OPENSSL_FIPS */

  cipher = &des3_ctr_cipher;
#endif /* prior to OpenSSL-1.1.0 */

  return cipher;
}
# endif /* !OPENSSL_NO_DES */

/* AES CTR mode implementation */
struct aes_ctr_ex {
  AES_KEY key;
  unsigned char counter[AES_BLOCK_SIZE];
  unsigned char enc_counter[AES_BLOCK_SIZE];
  unsigned int num;
};

static int init_aes_ctr(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc) {
  struct aes_ctr_ex *ace;

  ace = EVP_CIPHER_CTX_get_app_data(ctx);
  if (ace == NULL) {

    /* Allocate our data structure. */
    ace = calloc(1, sizeof(struct aes_ctr_ex));
    if (ace == NULL) {
      pr_log_pri(PR_LOG_ALERT, MOD_SFTP_VERSION ": Out of memory!");
      _exit(1);
    }

    EVP_CIPHER_CTX_set_app_data(ctx, ace);
  }

  if (key != NULL) {
    int nbits;

# if OPENSSL_VERSION_NUMBER == 0x0090805fL
    /* OpenSSL 0.9.8e had a bug where EVP_CIPHER_CTX_key_length() returned
     * the cipher key length rather than the context key length.
     */
    nbits = ctx->key_len * 8;
# else
    nbits = EVP_CIPHER_CTX_key_length(ctx) * 8;
# endif

    AES_set_encrypt_key(key, nbits, &(ace->key));
  }

  if (iv != NULL) {
    memcpy(ace->counter, iv, AES_BLOCK_SIZE);
  }

  return 1;
}

static int cleanup_aes_ctr(EVP_CIPHER_CTX *ctx) {
  struct aes_ctr_ex *ace;

  ace = EVP_CIPHER_CTX_get_app_data(ctx);
  if (ace != NULL) {
    pr_memscrub(ace, sizeof(struct aes_ctr_ex));
    free(ace);
    EVP_CIPHER_CTX_set_app_data(ctx, NULL);
  }

  return 1;
}

static int do_aes_ctr(EVP_CIPHER_CTX *ctx, unsigned char *dst,
    const unsigned char *src, size_t len) {
  struct aes_ctr_ex *ace;
# if OPENSSL_VERSION_NUMBER <= 0x0090704fL || \
     OPENSSL_VERSION_NUMBER >= 0x10100000L
  unsigned int n;
  unsigned char buf[AES_BLOCK_SIZE];
# endif

  if (len == 0)
    return 1;

  ace = EVP_CIPHER_CTX_get_app_data(ctx);
  if (ace == NULL)
    return 0;

# if OPENSSL_VERSION_NUMBER <= 0x0090704fL || \
     OPENSSL_VERSION_NUMBER >= 0x10100000L
  /* In OpenSSL-0.9.7d and earlier, the AES CTR code did not properly handle
   * the IV as big-endian; this would cause the dreaded "Incorrect MAC
   * received on packet" error when using clients e.g. PuTTy.  To see
   * the difference in OpenSSL, you have do manually do:
   *
   *  diff -u openssl-0.9.7d/crypto/aes/aes_ctr.c \
   *    openssl-0.9.7e/crypto/aes/aes_ctr.c
   *
   * This change is not documented in OpenSSL's CHANGES file.  Sigh.
   *
   * And in OpenSSL-1.1.0 and later, the AES CTR code was removed entirely.
   *
   * Thus for these versions, we have to use our own AES CTR code.
   */

  n = 0;

  while ((len--) > 0) {
    pr_signals_handle();

    if (n == 0) {
      AES_encrypt(ace->counter, buf, &(ace->key));
      ctr_incr(ace->counter, AES_BLOCK_SIZE);
    }

    *(dst++) = *(src++) ^ buf[n];
    n = (n + 1) % AES_BLOCK_SIZE;
  }

  return 1;
# else
  /* Thin wrapper around AES_ctr128_encrypt(). */
  AES_ctr128_encrypt(src, dst, len, &(ace->key), ace->counter, ace->enc_counter,
    &(ace->num));
# endif

  return 1;
}

static int get_aes_ctr_cipher_nid(int key_len) {
  int nid;

#ifdef OPENSSL_FIPS
  /* Set the NID depending on the key len. */
  switch (key_len) {
    case 16:
      nid = NID_aes_128_cbc;
      break;

    case 24:
      nid = NID_aes_192_cbc;
      break;

    case 32:
      nid = NID_aes_256_cbc;
      break;

    default:
      nid = NID_undef;
      break;
  }

#else
  /* Setting this nid member to something other than NID_undef causes
   * interesting problems on an OpenSolaris system, using the provided
   * OpenSSL installation's pkcs11 engine via:
   *
   *  SFTPCryptoDevice pkcs11
   *
   * for the mod_sftp config.  I'm not sure why; I need to look into this
   * issue more.
   *
   * For posterity, the issues seen when using the above config are
   * described below.  After sending the NEWKEYS request, mod_sftp
   * would log the following, upon receiving the next message from sftp(1):
   *
   *  <ssh2:20>: SSH2 packet len = 1500737511 bytes
   *  <ssh2:20>: SSH2 packet padding len = 95 bytes
   *  <ssh2:20>: SSH2 packet payload len = 1500737415 bytes
   *  <ssh2:20>: payload len (1500737415 bytes) exceeds max payload len (262144), ignoring payload
   *  client sent buggy/malicious packet payload length, ignoring
   *
   * and sftp(1), for its side, would report:
   *
   *  debug1: send SSH2_MSG_SERVICE_REQUEST
   *  Disconnecting: Bad packet length.
   *  debug1: Calling cleanup 0x807cc14(0x0)
   *  Couldn't read packet: Error 0
   */
  nid = NID_undef;
#endif /* OPENSSL_FIPS */

  return nid;
}

static const EVP_CIPHER *get_aes_ctr_cipher(int key_len) {
  EVP_CIPHER *cipher;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  unsigned long flags;

  /* XXX TODO: At some point, we also need to call EVP_CIPHER_meth_free() on
   * this, to avoid a resource leak.
   */
  cipher = EVP_CIPHER_meth_new(get_aes_ctr_cipher_nid(key_len), AES_BLOCK_SIZE,
    key_len);
  EVP_CIPHER_meth_set_iv_length(cipher, AES_BLOCK_SIZE);
  EVP_CIPHER_meth_set_init(cipher, init_aes_ctr);
  EVP_CIPHER_meth_set_cleanup(cipher, cleanup_aes_ctr);
  EVP_CIPHER_meth_set_do_cipher(cipher, do_aes_ctr);

  flags = EVP_CIPH_CBC_MODE|EVP_CIPH_VARIABLE_LENGTH|EVP_CIPH_ALWAYS_CALL_INIT|EVP_CIPH_CUSTOM_IV;
#ifdef OPENSSL_FIPS
  flags |= EVP_CIPH_FLAG_FIPS;
#endif /* OPENSSL_FIPS */

  EVP_CIPHER_meth_set_flags(cipher, flags);

#else
  static EVP_CIPHER aes_ctr_cipher;

  memset(&aes_ctr_cipher, 0, sizeof(EVP_CIPHER));

  aes_ctr_cipher.nid = get_aes_ctr_cipher_nid(key_len);
  aes_ctr_cipher.block_size = AES_BLOCK_SIZE;
  aes_ctr_cipher.iv_len = AES_BLOCK_SIZE;
  aes_ctr_cipher.key_len = key_len;
  aes_ctr_cipher.init = init_aes_ctr;
  aes_ctr_cipher.cleanup = cleanup_aes_ctr;
  aes_ctr_cipher.do_cipher = do_aes_ctr;

  aes_ctr_cipher.flags = EVP_CIPH_CBC_MODE|EVP_CIPH_VARIABLE_LENGTH|EVP_CIPH_ALWAYS_CALL_INIT|EVP_CIPH_CUSTOM_IV;
# ifdef OPENSSL_FIPS
  aes_ctr_cipher.flags |= EVP_CIPH_FLAG_FIPS;
# endif /* OPENSSL_FIPS */

  cipher = &aes_ctr_cipher;
#endif /* prior to OpenSSL-1.1.0 */

  return cipher;
}

static int update_umac64(EVP_MD_CTX *ctx, const void *data, size_t len) {
  int res;
  void *md_data;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  md_data = EVP_MD_CTX_md_data(ctx);
#else
  md_data = ctx->md_data;
#endif /* prior to OpenSSL-1.1.0 */
  if (md_data == NULL) {
    struct umac_ctx *umac;
    void **ptr;

    umac = umac_new((unsigned char *) data);
    if (umac == NULL) {
      return 0;
    }

    ptr = &md_data;
    *ptr = umac;
    return 1;
  }

  res = umac_update(md_data, (unsigned char *) data, (long) len);
  return res;
}

static int update_umac128(EVP_MD_CTX *ctx, const void *data, size_t len) {
  int res;
  void *md_data;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  md_data = EVP_MD_CTX_md_data(ctx);
#else
  md_data = ctx->md_data;
#endif /* prior to OpenSSL-1.1.0 */

  if (md_data == NULL) {
    struct umac_ctx *umac;
    void **ptr;

    umac = umac128_new((unsigned char *) data);
    if (umac == NULL) {
      return 0;
    }

    ptr = &md_data;
    *ptr = umac;
    return 1;
  }

  res = umac128_update(md_data, (unsigned char *) data, (long) len);
  return res;
}

static int final_umac64(EVP_MD_CTX *ctx, unsigned char *md) {
  unsigned char nonce[8];
  int res;
  void *md_data;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  md_data = EVP_MD_CTX_md_data(ctx);
#else
  md_data = ctx->md_data;
#endif /* prior to OpenSSL-1.1.0 */

  res = umac_final(md_data, md, nonce);
  return res;
}

static int final_umac128(EVP_MD_CTX *ctx, unsigned char *md) {
  unsigned char nonce[8];
  int res;
  void *md_data;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  md_data = EVP_MD_CTX_md_data(ctx);
#else
  md_data = ctx->md_data;
#endif /* prior to OpenSSL-1.1.0 */

  res = umac128_final(md_data, md, nonce);
  return res;
}

static int delete_umac64(EVP_MD_CTX *ctx) {
  struct umac_ctx *umac;
  void *md_data, **ptr;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  md_data = EVP_MD_CTX_md_data(ctx);
#else
  md_data = ctx->md_data;
#endif /* prior to OpenSSL-1.1.0 */

  umac = md_data;
  umac_delete(umac);

  ptr = &md_data;
  *ptr = NULL;

  return 1;
}

static int delete_umac128(EVP_MD_CTX *ctx) {
  struct umac_ctx *umac;
  void *md_data, **ptr;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  md_data = EVP_MD_CTX_md_data(ctx);
#else
  md_data = ctx->md_data;
#endif /* prior to OpenSSL-1.1.0 */

  umac = md_data;
  umac128_delete(umac);

  ptr = &md_data;
  *ptr = NULL;

  return 1;
}

static const EVP_MD *get_umac64_digest(void) {
  EVP_MD *md;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  /* XXX TODO: At some point, we also need to call EVP_MD_meth_free() on
   * this, to avoid a resource leak.
   */
  md = EVP_MD_meth_new(NID_undef, NID_undef);
  EVP_MD_meth_set_input_blocksize(md, 32);
  EVP_MD_meth_set_result_size(md, 8);
  EVP_MD_meth_set_flags(md, 0UL);
  EVP_MD_meth_set_update(md, update_umac64);
  EVP_MD_meth_set_final(md, final_umac64);
  EVP_MD_meth_set_cleanup(md, delete_umac64);
#else
  static EVP_MD umac64_digest;

  memset(&umac64_digest, 0, sizeof(EVP_MD));

  umac64_digest.type = NID_undef;
  umac64_digest.pkey_type = NID_undef;
  umac64_digest.md_size = 8;
  umac64_digest.flags = 0UL;
  umac64_digest.update = update_umac64;
  umac64_digest.final = final_umac64;
  umac64_digest.cleanup = delete_umac64;
  umac64_digest.block_size = 32;

  md = &umac64_digest;
#endif /* prior to OpenSSL-1.1.0 */

  return md;
}

static const EVP_MD *get_umac128_digest(void) {
  EVP_MD *md;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  /* XXX TODO: At some point, we also need to call EVP_MD_meth_free() on
   * this, to avoid a resource leak.
   */
  md = EVP_MD_meth_new(NID_undef, NID_undef);
  EVP_MD_meth_set_input_blocksize(md, 64);
  EVP_MD_meth_set_result_size(md, 16);
  EVP_MD_meth_set_flags(md, 0UL);
  EVP_MD_meth_set_update(md, update_umac128);
  EVP_MD_meth_set_final(md, final_umac128);
  EVP_MD_meth_set_cleanup(md, delete_umac128);

#else
  static EVP_MD umac128_digest;

  memset(&umac128_digest, 0, sizeof(EVP_MD));

  umac128_digest.type = NID_undef;
  umac128_digest.pkey_type = NID_undef;
  umac128_digest.md_size = 16;
  umac128_digest.flags = 0UL;
  umac128_digest.update = update_umac128;
  umac128_digest.final = final_umac128;
  umac128_digest.cleanup = delete_umac128;
  umac128_digest.block_size = 64;

  md = &umac128_digest;
#endif /* prior to OpenSSL-1.1.0 */

  return md;
}
#endif /* OpenSSL older than 0.9.7 */

const EVP_CIPHER *sftp_crypto_get_cipher(const char *name, size_t *key_len,
    size_t *discard_len) {
  register unsigned int i;

  for (i = 0; ciphers[i].name; i++) {
    if (strcmp(ciphers[i].name, name) == 0) {
      const EVP_CIPHER *cipher;

      if (strncmp(name, "blowfish-ctr", 13) == 0) {
#if !defined(OPENSSL_NO_BF)
        cipher = get_bf_ctr_cipher();
#else
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "'%s' cipher unsupported", name);
        errno = ENOENT;
        return NULL;
#endif /* !OPENSSL_NO_BF */

#if OPENSSL_VERSION_NUMBER > 0x000907000L
      } else if (strncmp(name, "3des-ctr", 9) == 0) {
# if !defined(OPENSSL_NO_DES)
        cipher = get_des3_ctr_cipher();
# else
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "'%s' cipher unsupported", name);
        errno = ENOENT;
        return NULL;
# endif /* !OPENSSL_NO_DES */

      } else if (strncmp(name, "aes256-ctr", 11) == 0) {
        cipher = get_aes_ctr_cipher(32);

      } else if (strncmp(name, "aes192-ctr", 11) == 0) {
        cipher = get_aes_ctr_cipher(24);

      } else if (strncmp(name, "aes128-ctr", 11) == 0) {
        cipher = get_aes_ctr_cipher(16);
#endif /* OpenSSL older than 0.9.7 */

      } else {
        cipher = ciphers[i].get_type();
      }

      if (key_len) {
        if (strncmp(name, "arcfour256", 11) != 0) {
          *key_len = 0;

        } else {
          /* The arcfour256 cipher is special-cased here in order to use
           * a longer key (32 bytes), rather than the normal 16 bytes for the
           * RC4 cipher.
           */
          *key_len = 32;
        }
      }

      if (discard_len) {
        *discard_len = ciphers[i].discard_len;
      }

      return cipher;
    }
  }

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "no cipher matching '%s' found", name);
  errno = ENOENT;
  return NULL;
}

const EVP_MD *sftp_crypto_get_digest(const char *name, uint32_t *mac_len) {
  register unsigned int i;

  for (i = 0; digests[i].name; i++) {
    if (strcmp(digests[i].name, name) == 0) {
      const EVP_MD *digest = NULL;

#if OPENSSL_VERSION_NUMBER > 0x000907000L
      if (strncmp(name, "umac-64@openssh.com", 12) == 0) {
        digest = get_umac64_digest();

      } else if (strncmp(name, "umac-128@openssh.com", 13) == 0) {
        digest = get_umac128_digest();
#else
      if (FALSE) {
#endif /* OpenSSL older than 0.9.7 */

      } else {
        digest = digests[i].get_type();
      }

      if (mac_len) {
        *mac_len = digests[i].mac_len;
      }

      return digest;
    }
  }

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "no digest matching '%s' found", name);
  return NULL;
}

const char *sftp_crypto_get_kexinit_cipher_list(pool *p) {
  char *res = "";
  config_rec *c;

  /* Make sure that OpenSSL can use these ciphers.  For example, in FIPS mode,
   * some ciphers cannot be used.  So we should not advertise ciphers that we
   * know we cannot use.
   */

  c = find_config(main_server->conf, CONF_PARAM, "SFTPCiphers", FALSE);
  if (c) {
    register unsigned int i;

    for (i = 0; i < c->argc; i++) {
      register unsigned int j;

      for (j = 0; ciphers[j].name; j++) {
        if (strcmp(c->argv[i], ciphers[j].name) == 0) {
#ifdef OPENSSL_FIPS
          if (FIPS_mode()) {
            /* If FIPS mode is enabled, check whether the cipher is allowed
             * for use.
             */
            if (ciphers[j].fips_allowed == FALSE) {
              pr_trace_msg(trace_channel, 5,
                "cipher '%s' is disabled in FIPS mode, skipping",
                ciphers[j].name);
              continue;
            }
          }
#endif /* OPENSSL_FIPS */
          if (strncmp(c->argv[i], "none", 5) != 0) {
            if (EVP_get_cipherbyname(ciphers[j].openssl_name) != NULL) {
              res = pstrcat(p, res, *res ? "," : "",
                pstrdup(p, ciphers[j].name), NULL);

            } else {
              /* The CTR modes are special cases. */

              if (strncmp(ciphers[j].name, "blowfish-ctr", 13) == 0 ||
                  strncmp(ciphers[j].name, "3des-ctr", 9) == 0
#if OPENSSL_VERSION_NUMBER > 0x000907000L
                  || strncmp(ciphers[j].name, "aes256-ctr", 11) == 0 ||
                  strncmp(ciphers[j].name, "aes192-ctr", 11) == 0 ||
                  strncmp(ciphers[j].name, "aes128-ctr", 11) == 0
#endif
                  ) {
                res = pstrcat(p, res, *res ? "," : "",
                  pstrdup(p, ciphers[j].name), NULL);
       
              } else {
                pr_trace_msg(trace_channel, 3,
                  "unable to use '%s' cipher: Unsupported by OpenSSL",
                  ciphers[j].name);
              }
            }

          } else {
            res = pstrcat(p, res, *res ? "," : "",
              pstrdup(p, ciphers[j].name), NULL);
          }
        }
      }
    }

  } else {
    register unsigned int i;

    for (i = 0; ciphers[i].name; i++) {
      if (ciphers[i].enabled) {
#ifdef OPENSSL_FIPS
          if (FIPS_mode()) {
            /* If FIPS mode is enabled, check whether the cipher is allowed
             * for use.
             */
            if (ciphers[i].fips_allowed == FALSE) {
              pr_trace_msg(trace_channel, 5,
                "cipher '%s' is disabled in FIPS mode, skipping",
                ciphers[i].name);
              continue;
            }
          }
#endif /* OPENSSL_FIPS */

        if (strncmp(ciphers[i].name, "none", 5) != 0) {
          if (EVP_get_cipherbyname(ciphers[i].openssl_name) != NULL) {
            res = pstrcat(p, res, *res ? "," : "",
              pstrdup(p, ciphers[i].name), NULL);

          } else {
            /* The CTR modes are special cases. */

            if (strncmp(ciphers[i].name, "blowfish-ctr", 13) == 0 ||
                strncmp(ciphers[i].name, "3des-ctr", 9) == 0
#if OPENSSL_VERSION_NUMBER > 0x000907000L
                || strncmp(ciphers[i].name, "aes256-ctr", 11) == 0 ||
                strncmp(ciphers[i].name, "aes192-ctr", 11) == 0 ||
                strncmp(ciphers[i].name, "aes128-ctr", 11) == 0
#endif
                ) {
              res = pstrcat(p, res, *res ? "," : "",
                pstrdup(p, ciphers[i].name), NULL);

            } else {       
              pr_trace_msg(trace_channel, 3,
                "unable to use '%s' cipher: Unsupported by OpenSSL",
                ciphers[i].name);
            }
          }

        } else {
          res = pstrcat(p, res, *res ? "," : "",
            pstrdup(p, ciphers[i].name), NULL);
        }

      } else {
        pr_trace_msg(trace_channel, 3, "unable to use '%s' cipher: "
          "Must be explicitly requested via SFTPCiphers", ciphers[i].name);
      }
    }
  }

  return res;
}

const char *sftp_crypto_get_kexinit_digest_list(pool *p) {
  char *res = "";
  config_rec *c;

  /* Make sure that OpenSSL can use these digests.  For example, in FIPS
   * mode, some digests cannot be used.  So we should not advertise digests
   * that we know we cannot use.
   */

  c = find_config(main_server->conf, CONF_PARAM, "SFTPDigests", FALSE);
  if (c != NULL) {
    register unsigned int i;

    for (i = 0; i < c->argc; i++) {
      register unsigned int j;

      for (j = 0; digests[j].name; j++) {
        if (strcmp(c->argv[i], digests[j].name) == 0) {
#ifdef OPENSSL_FIPS
          if (FIPS_mode()) {
            /* If FIPS mode is enabled, check whether the MAC is allowed
             * for use.
             */
            if (digests[j].fips_allowed == FALSE) {
              pr_trace_msg(trace_channel, 5,
                "digest '%s' is disabled in FIPS mode, skipping",
                digests[j].name);
              continue;
            }
          }
#endif /* OPENSSL_FIPS */

          if (strncmp(c->argv[i], "none", 5) != 0) {
            if (digests[j].openssl_name != NULL &&
                EVP_get_digestbyname(digests[j].openssl_name) != NULL) {
              res = pstrcat(p, res, *res ? "," : "",
                pstrdup(p, digests[j].name), NULL);

            } else {
              /* The umac-64/umac-128 digests are special cases. */
              if (strncmp(digests[j].name, "umac-64@openssh.com", 12) == 0 ||
                  strncmp(digests[j].name, "umac-128@openssh.com", 13) == 0) {
                res = pstrcat(p, res, *res ? "," : "",
                  pstrdup(p, digests[j].name), NULL);

              } else {
                pr_trace_msg(trace_channel, 3,
                  "unable to use '%s' digest: Unsupported by OpenSSL",
                  digests[j].name);
              }
            }

          } else {
            res = pstrcat(p, res, *res ? "," : "",
              pstrdup(p, digests[j].name), NULL);
          }
        }
      }
    }

  } else {
    register unsigned int i;

    for (i = 0; digests[i].name; i++) {
      if (digests[i].enabled) {
#ifdef OPENSSL_FIPS
          if (FIPS_mode()) {
            /* If FIPS mode is enabled, check whether the digest is allowed
             * for use.
             */
            if (digests[i].fips_allowed == FALSE) {
              pr_trace_msg(trace_channel, 5,
                "digest '%s' is disabled in FIPS mode, skipping",
                digests[i].name);
              continue;
            }
          }
#endif /* OPENSSL_FIPS */

        if (strncmp(digests[i].name, "none", 5) != 0) {
          if (digests[i].openssl_name != NULL &&
              EVP_get_digestbyname(digests[i].openssl_name) != NULL) {
            res = pstrcat(p, res, *res ? "," : "",
              pstrdup(p, digests[i].name), NULL);

          } else {
            /* The umac-64/umac-128 digests are special cases. */
            if (strncmp(digests[i].name, "umac-64@openssh.com", 12) == 0 ||
                strncmp(digests[i].name, "umac-128@openssh.com", 13) == 0) {
              res = pstrcat(p, res, *res ? "," : "",
                pstrdup(p, digests[i].name), NULL);

            } else {
              pr_trace_msg(trace_channel, 3,
                "unable to use '%s' digest: Unsupported by OpenSSL",
                digests[i].name);
            }
          }

        } else {
          res = pstrcat(p, res, *res ? "," : "",
            pstrdup(p, digests[i].name), NULL);
        }

      } else {
        pr_trace_msg(trace_channel, 3, "unable to use '%s' digest: "
          "Must be explicitly requested via SFTPDigests", digests[i].name);
      }
    }
  }

  return res;
}

const char *sftp_crypto_get_errors(void) {
  unsigned int count = 0;
  unsigned long error_code;
  BIO *bio = NULL;
  char *data = NULL;
  long datalen;
  const char *error_data = NULL, *str = "(unknown)";
  int error_flags = 0;

  /* Use ERR_print_errors() and a memory BIO to build up a string with
   * all of the error messages from the error queue.
   */

  error_code = ERR_get_error_line_data(NULL, NULL, &error_data, &error_flags);
  if (error_code) {
    bio = BIO_new(BIO_s_mem());
  }

  while (error_code) {
    if (error_flags & ERR_TXT_STRING) {
      BIO_printf(bio, "\n  (%u) %s [%s]", ++count,
        ERR_error_string(error_code, NULL), error_data);

    } else {
      BIO_printf(bio, "\n  (%u) %s", ++count,
        ERR_error_string(error_code, NULL));
    }

    error_data = NULL;
    error_flags = 0;
    error_code = ERR_get_error_line_data(NULL, NULL, &error_data, &error_flags);
  }

  datalen = BIO_get_mem_data(bio, &data);
  if (data != NULL) {
    data[datalen] = '\0';
    str = pstrdup(sftp_pool, data);
  }

  if (bio) {
    BIO_free(bio);
  }

  return str;
}

/* Try to find the best multiple/block size which accommodates the two given
 * sizes by rounding up.
 */
size_t sftp_crypto_get_size(size_t first, size_t second) {
#ifdef roundup
  return roundup(first, second);
#else
  return (((first + (second - 1)) / second) * second);
#endif /* !roundup */
}

void sftp_crypto_free(int flags) {

  /* Only call EVP_cleanup() et al if other OpenSSL-using modules are not
   * present.  If we called EVP_cleanup() here during a restart,
   * and other modules want to use OpenSSL, we may be depriving those modules
   * of OpenSSL functionality.
   *
   * At the moment, the modules known to use OpenSSL are mod_ldap, mod_radius,
   * mod_sftp, mod_sql, and mod_sql_passwd, and mod_tls.
   */
  if (pr_module_get("mod_auth_otp.c") == NULL &&
      pr_module_get("mod_digest.c") == NULL &&
      pr_module_get("mod_ldap.c") == NULL &&
      pr_module_get("mod_radius.c") == NULL &&
      pr_module_get("mod_sql.c") == NULL &&
      pr_module_get("mod_sql_passwd.c") == NULL &&
      pr_module_get("mod_tls.c") == NULL) {

#if OPENSSL_VERSION_NUMBER > 0x000907000L
    if (crypto_engine) {
      ENGINE_cleanup();
      crypto_engine = NULL;
    }
#endif

    ERR_free_strings();

#if OPENSSL_VERSION_NUMBER >= 0x10000001L
    /* The ERR_remove_state(0) usage is deprecated due to thread ID
     * differences among platforms; see the OpenSSL-1.0.0c CHANGES file
     * for details.  So for new enough OpenSSL installations, use the
     * proper way to clear the error queue state.
     */
    ERR_remove_thread_state(NULL);
#else
    ERR_remove_state(0);
#endif /* OpenSSL prior to 1.0.0-beta1 */

    EVP_cleanup();
    RAND_cleanup();
  }
}

int sftp_crypto_set_driver(const char *driver) {
#if OPENSSL_VERSION_NUMBER > 0x000907000L
  if (driver == NULL) {
    errno = EINVAL;
    return -1;
  }

  crypto_engine = driver;

  if (strncasecmp(driver, "ALL", 4) == 0) {
    /* Load all ENGINE implementations bundled with OpenSSL. */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "enabled all builtin crypto devices");

  } else {
    ENGINE *e;

    /* Load all ENGINE implementations bundled with OpenSSL. */
    ENGINE_load_builtin_engines();

    e = ENGINE_by_id(driver);
    if (e) {
      if (ENGINE_init(e)) {
        if (ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
          ENGINE_finish(e);
          ENGINE_free(e);

          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "using SFTPCryptoDevice '%s'", driver);

        } else {
          /* The requested driver could not be used as the default for
           * some odd reason.
           */
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "unable to register SFTPCryptoDevice '%s' as the default: %s",
            driver, sftp_crypto_get_errors());

          ENGINE_finish(e);
          ENGINE_free(e);
          e = NULL;
          crypto_engine = NULL;

          errno = EPERM;
          return -1;
        }

      } else {
        /* The requested driver could not be initialized. */
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "unable to initialize SFTPCryptoDevice '%s': %s", driver,
          sftp_crypto_get_errors());

        ENGINE_free(e);
        e = NULL;
        crypto_engine = NULL;

        errno = EPERM;
        return -1;
      }

    } else {
      /* The requested driver is not available. */
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "SFTPCryptoDevice '%s' is not available", driver);

      crypto_engine = NULL;

      errno = EPERM;
      return -1;
    }
  }

  return 0;
#else
  errno = ENOSYS;
  return -1;
#endif
}

