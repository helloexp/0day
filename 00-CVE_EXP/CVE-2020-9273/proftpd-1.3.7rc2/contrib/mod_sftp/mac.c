/*
 * ProFTPD - mod_sftp MACs
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
#include "ssh2.h"
#include "msg.h"
#include "packet.h"
#include "crypto.h"
#include "mac.h"
#include "session.h"
#include "disconnect.h"
#include "interop.h"
#include "umac.h"

struct sftp_mac {
  const char *algo;
  int algo_type;

  const EVP_MD *digest;

  unsigned char *key;

  /* The keysz and key_len are usually the same; they can differ if, for
   * example, the client always truncates the MAC key len to 16 bits.
   */
  size_t keysz;
  uint32_t key_len;

  uint32_t mac_len;
};

#define SFTP_MAC_ALGO_TYPE_HMAC		1
#define SFTP_MAC_ALGO_TYPE_UMAC64	2
#define SFTP_MAC_ALGO_TYPE_UMAC128	3

#define SFTP_MAC_FL_READ_MAC	1
#define SFTP_MAC_FL_WRITE_MAC	2

/* We need to keep the old MACs around, so that we can handle N arbitrary
 * packets to/from the client using the old keys, as during rekeying.
 * Thus we have two read MAC contexts, two write MAC contexts.
 * The cipher idx variable indicates which of the MACs is currently in use.
 */

static struct sftp_mac read_macs[] = {
  { NULL, 0, NULL, NULL, 0 },
  { NULL, 0, NULL, NULL, 0 }
};
static HMAC_CTX *hmac_read_ctxs[2];
static struct umac_ctx *umac_read_ctxs[2];

static struct sftp_mac write_macs[] = {
  { NULL, 0, NULL, NULL, 0 },
  { NULL, 0, NULL, NULL, 0 }
};
static HMAC_CTX *hmac_write_ctxs[2];
static struct umac_ctx *umac_write_ctxs[2];

static size_t mac_blockszs[2] = { 0, 0 };

/* Buffer size for reading/writing keys */
#define SFTP_MAC_BUFSZ				4096

static unsigned int read_mac_idx = 0;
static unsigned int write_mac_idx = 0;

static void clear_mac(struct sftp_mac *);

static unsigned int get_next_read_index(void) {
  if (read_mac_idx == 1) {
    return 0;
  }

  return 1;
}

static unsigned int get_next_write_index(void) {
  if (write_mac_idx == 1) {
    return 0;
  }

  return 1;
}

static void switch_read_mac(void) {
  /* First we can clear the read MAC, kept from rekeying. */
  if (read_macs[read_mac_idx].key) {
    clear_mac(&(read_macs[read_mac_idx]));
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
    HMAC_CTX_reset(hmac_read_ctxs[read_mac_idx]);
#elif OPENSSL_VERSION_NUMBER > 0x000907000L
    HMAC_CTX_cleanup(hmac_read_ctxs[read_mac_idx]);
#else
    HMAC_cleanup(hmac_read_ctxs[read_mac_idx]);
#endif
    if (read_macs[read_mac_idx].algo_type == SFTP_MAC_ALGO_TYPE_UMAC64) {
      umac_reset(umac_read_ctxs[read_mac_idx]);

    } else if (read_macs[read_mac_idx].algo_type == SFTP_MAC_ALGO_TYPE_UMAC128) {
      umac128_reset(umac_read_ctxs[read_mac_idx]);
    }

    mac_blockszs[read_mac_idx] = 0; 

    /* Now we can switch the index. */
    if (read_mac_idx == 1) {
      read_mac_idx = 0;
      return;
    }

    read_mac_idx = 1;
  }
}

static void switch_write_mac(void) {
  /* First we can clear the write MAC, kept from rekeying. */
  if (write_macs[write_mac_idx].key) {
    clear_mac(&(write_macs[write_mac_idx]));
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
    HMAC_CTX_reset(hmac_write_ctxs[write_mac_idx]);
#elif OPENSSL_VERSION_NUMBER > 0x000907000L
    HMAC_CTX_cleanup(hmac_write_ctxs[write_mac_idx]);
#else
    HMAC_cleanup(hmac_write_ctxs[write_mac_idx]);
#endif
    if (write_macs[write_mac_idx].algo_type == SFTP_MAC_ALGO_TYPE_UMAC64) {
      umac_reset(umac_write_ctxs[write_mac_idx]);

    } else if (write_macs[write_mac_idx].algo_type == SFTP_MAC_ALGO_TYPE_UMAC128) {
      umac128_reset(umac_write_ctxs[write_mac_idx]);
    }

    /* Now we can switch the index. */
    if (write_mac_idx == 1) {
      write_mac_idx = 0;
      return;
    }

    write_mac_idx = 1;
  }
}

static void clear_mac(struct sftp_mac *mac) {
  if (mac->key) {
    pr_memscrub(mac->key, mac->keysz);
    free(mac->key);
    mac->key = NULL;
    mac->keysz = 0;
    mac->key_len = 0;
  }

  mac->digest = NULL;
  mac->algo = NULL;
}

static int init_mac(pool *p, struct sftp_mac *mac, HMAC_CTX *hmac_ctx,
    struct umac_ctx *umac_ctx) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  HMAC_CTX_reset(hmac_ctx);
#elif OPENSSL_VERSION_NUMBER > 0x000907000L
  HMAC_CTX_init(hmac_ctx);
#else
  /* Reset the HMAC context. */
  HMAC_Init(hmac_ctx, NULL, 0, NULL);
#endif

  if (mac->algo_type == SFTP_MAC_ALGO_TYPE_HMAC) {
#if OPENSSL_VERSION_NUMBER > 0x000907000L
# if OPENSSL_VERSION_NUMBER >= 0x10000001L
    if (HMAC_Init_ex(hmac_ctx, mac->key, mac->key_len, mac->digest,
        NULL) != 1) {
      pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error initializing HMAC: %s", sftp_crypto_get_errors());
      errno = EPERM;
      return -1;
    }

# else
    HMAC_Init_ex(hmac_ctx, mac->key, mac->key_len, mac->digest, NULL);
# endif /* OpenSSL-1.0.0 and later */

#else
    HMAC_Init(hmac_ctx, mac->key, mac->key_len, mac->digest);
#endif

  } else if (mac->algo_type == SFTP_MAC_ALGO_TYPE_UMAC64) {
    umac_reset(umac_ctx);
    umac_init(umac_ctx, mac->key);

  } else if (mac->algo_type == SFTP_MAC_ALGO_TYPE_UMAC128) {
    umac128_reset(umac_ctx);
    umac128_init(umac_ctx, mac->key);
  }

  return 0;
}

static int get_mac(struct ssh2_packet *pkt, struct sftp_mac *mac,
    HMAC_CTX *hmac_ctx, struct umac_ctx *umac_ctx, int flags) {
  unsigned char *mac_data;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz = 0, mac_len = 0;

  if (mac->algo_type == SFTP_MAC_ALGO_TYPE_HMAC) {
    bufsz = (sizeof(uint32_t) * 2) + pkt->packet_len;
    mac_data = pcalloc(pkt->pool, EVP_MAX_MD_SIZE);

    buflen = bufsz;
    ptr = buf = sftp_msg_getbuf(pkt->pool, bufsz);

    sftp_msg_write_int(&buf, &buflen, pkt->seqno);
    sftp_msg_write_int(&buf, &buflen, pkt->packet_len);
    sftp_msg_write_byte(&buf, &buflen, pkt->padding_len);
    sftp_msg_write_data(&buf, &buflen, pkt->payload, pkt->payload_len, FALSE);
    sftp_msg_write_data(&buf, &buflen, pkt->padding, pkt->padding_len, FALSE);

#if OPENSSL_VERSION_NUMBER > 0x000907000L
# if OPENSSL_VERSION_NUMBER >= 0x10000001L
    if (HMAC_Init_ex(hmac_ctx, NULL, 0, NULL, NULL) != 1) {
      pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error resetting HMAC context: %s", sftp_crypto_get_errors());
      errno = EPERM;
      return -1;
    }
# else
    HMAC_Init_ex(hmac_ctx, NULL, 0, NULL, NULL);
# endif /* OpenSSL-1.0.0 and later */

#else
    HMAC_Init(hmac_ctx, NULL, 0, NULL);
#endif /* OpenSSL-0.9.7 and later */

#if OPENSSL_VERSION_NUMBER >= 0x10000001L
    if (HMAC_Update(hmac_ctx, ptr, (bufsz - buflen)) != 1) {
      pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error adding %lu bytes of data to  HMAC context: %s",
        (unsigned long) (bufsz - buflen), sftp_crypto_get_errors());
      errno = EPERM;
      return -1;
    }

    if (HMAC_Final(hmac_ctx, mac_data, &mac_len) != 1) {
      pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error finalizing HMAC context: %s", sftp_crypto_get_errors());
      errno = EPERM;
      return -1;
    }
#else
    HMAC_Update(hmac_ctx, ptr, (bufsz - buflen));
    HMAC_Final(hmac_ctx, mac_data, &mac_len);
#endif /* OpenSSL-1.0.0 and later */

  } else if (mac->algo_type == SFTP_MAC_ALGO_TYPE_UMAC64 ||
             mac->algo_type == SFTP_MAC_ALGO_TYPE_UMAC128) {
    unsigned char nonce[8], *nonce_ptr;
    uint32_t nonce_len = 0;

    bufsz = sizeof(uint32_t) + pkt->packet_len;
    mac_data = pcalloc(pkt->pool, EVP_MAX_MD_SIZE);

    buflen = bufsz;
    ptr = buf = sftp_msg_getbuf(pkt->pool, bufsz);

    sftp_msg_write_int(&buf, &buflen, pkt->packet_len);
    sftp_msg_write_byte(&buf, &buflen, pkt->padding_len);
    sftp_msg_write_data(&buf, &buflen, pkt->payload, pkt->payload_len, FALSE);
    sftp_msg_write_data(&buf, &buflen, pkt->padding, pkt->padding_len, FALSE);

    nonce_ptr = nonce;
    nonce_len = sizeof(nonce);
    sftp_msg_write_long(&nonce_ptr, &nonce_len, pkt->seqno);

    if (mac->algo_type == SFTP_MAC_ALGO_TYPE_UMAC64) {
      umac_reset(umac_ctx);
      umac_update(umac_ctx, ptr, (bufsz - buflen));
      umac_final(umac_ctx, mac_data, nonce);
      mac_len = 8;

    } else if (mac->algo_type == SFTP_MAC_ALGO_TYPE_UMAC128) {
      umac128_reset(umac_ctx);
      umac128_update(umac_ctx, ptr, (bufsz - buflen));
      umac128_final(umac_ctx, mac_data, nonce);
      mac_len = 16;
    }
  }

  if (mac_len == 0) {
    pkt->mac = NULL;
    pkt->mac_len = 0;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error computing MAC using %s: %s", mac->algo,
      sftp_crypto_get_errors());

    errno = EIO;
    return -1;
  }

  if (mac->mac_len != 0) {
    mac_len = mac->mac_len;
  }

  if (flags & SFTP_MAC_FL_READ_MAC) {
    if (memcmp(mac_data, pkt->mac, mac_len) != 0) {
      unsigned int i = 0;

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "MAC from client differs from expected MAC using %s", mac->algo);

#ifdef SFTP_DEBUG_PACKET
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "client MAC (len %lu):", (unsigned long) pkt->mac_len);
      for (i = 0; i < mac_len;) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "  %02x%02x %02x%02x %02x%02x %02x%02x",
          ((unsigned char *) pkt->mac)[i], ((unsigned char *) pkt->mac)[i+1],
          ((unsigned char *) pkt->mac)[i+2], ((unsigned char *) pkt->mac)[i+3],
          ((unsigned char *) pkt->mac)[i+4], ((unsigned char *) pkt->mac)[i+5],
          ((unsigned char *) pkt->mac)[i+6], ((unsigned char *) pkt->mac)[i+7]);
        i += 8;
      }

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "server MAC (len %lu):", (unsigned long) mac_len);
      for (i = 0; i < mac_len;) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "  %02x%02x %02x%02x %02x%02x %02x%02x",
          ((unsigned char *) mac)[i], ((unsigned char *) mac)[i+1],
          ((unsigned char *) mac)[i+2], ((unsigned char *) mac)[i+3],
          ((unsigned char *) mac)[i+4], ((unsigned char *) mac)[i+5],
          ((unsigned char *) mac)[i+6], ((unsigned char *) mac)[i+7]);
        i += 8;
      }
#else
      /* Avoid compiler warning. */
      (void) i;
#endif

      errno = EINVAL;
      return -1;
    }

  } else if (flags & SFTP_MAC_FL_WRITE_MAC) {
    unsigned int i = 0;
#ifdef SFTP_DEBUG_PACKET

    if (pkt->mac_len > 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "server MAC (len %lu, seqno %lu):",
        (unsigned long) pkt->mac_len, (unsigned long) pkt->seqno);
      for (i = 0; i < mac_len;) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "  %02x%02x %02x%02x %02x%02x %02x%02x",
          ((unsigned char *) pkt->mac)[i], ((unsigned char *) pkt->mac)[i+1],
          ((unsigned char *) pkt->mac)[i+2], ((unsigned char *) pkt->mac)[i+3],
          ((unsigned char *) pkt->mac)[i+4], ((unsigned char *) pkt->mac)[i+5],
          ((unsigned char *) pkt->mac)[i+6], ((unsigned char *) pkt->mac)[i+7]);
        i += 8;
      }
    }
#else
    /* Avoid compiler warning. */
    (void) i;
#endif
  }

  pkt->mac_len = mac_len;
  pkt->mac = pcalloc(pkt->pool, pkt->mac_len);
  memcpy(pkt->mac, mac_data, mac_len);

  return 0;
}

static int set_mac_key(struct sftp_mac *mac, const EVP_MD *hash,
    const unsigned char *k, uint32_t klen, const char *h, uint32_t hlen,
    char *letter, const unsigned char *id, uint32_t id_len) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
  EVP_MD_CTX ctx;
#endif /* prior to OpenSSL-1.1.0 */
  EVP_MD_CTX *pctx;
  unsigned char *key = NULL;
  size_t key_sz;
  uint32_t key_len = 0;

  key_sz = sftp_crypto_get_size(EVP_MD_block_size(mac->digest),
    EVP_MD_size(hash)); 
  if (key_sz == 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unable to determine key length for MAC '%s'", mac->algo);
    errno = EINVAL;
    return -1;
  }

  key = malloc(key_sz);
  if (key == NULL) {
    pr_log_pri(PR_LOG_ALERT, MOD_SFTP_VERSION ": Out of memory!");
    _exit(1);
  }

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
  pctx = &ctx;
#else
  pctx = EVP_MD_CTX_new();
#endif /* prior to OpenSSL-1.1.0 */

  /* In OpenSSL 0.9.6, many of the EVP_Digest* functions returned void, not
   * int.  Without these ugly OpenSSL version preprocessor checks, the
   * compiler will error out with "void value not ignored as it ought to be".
   */

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestInit(pctx, hash) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error initializing message digest: %s", sftp_crypto_get_errors());
    free(key);
# if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return -1;
  }
#else
  EVP_DigestInit(pctx, hash);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestUpdate(pctx, k, klen) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error updating message digest with K: %s", sftp_crypto_get_errors());
    free(key);
# if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return -1;
  }
#else
  EVP_DigestUpdate(pctx, k, klen);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestUpdate(pctx, h, hlen) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error updating message digest with H: %s", sftp_crypto_get_errors());
    free(key);
# if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return -1;
  }
#else
  EVP_DigestUpdate(pctx, h, hlen);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestUpdate(pctx, letter, sizeof(char)) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error updating message digest with '%c': %s", *letter,
      sftp_crypto_get_errors());
    free(key);
# if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return -1;
  }
#else
  EVP_DigestUpdate(pctx, letter, sizeof(char));
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestUpdate(pctx, (char *) id, id_len) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error updating message digest with ID: %s", sftp_crypto_get_errors());
    free(key);
# if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return -1;
  }
#else
  EVP_DigestUpdate(pctx, (char *) id, id_len);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestFinal(pctx, key, &key_len) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error finalizing message digest: %s", sftp_crypto_get_errors());
    pr_memscrub(key, key_sz);
    free(key);
# if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return -1;
  }
#else
  EVP_DigestFinal(pctx, key, &key_len);
#endif

  /* If we need more, keep hashing, as per RFC, until we have enough
   * material.
   */

  while (key_sz > key_len) {
    uint32_t len = key_len;

    pr_signals_handle();

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
    if (EVP_DigestInit(pctx, hash) != 1) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error initializing message digest: %s", sftp_crypto_get_errors());
      pr_memscrub(key, key_sz);
      free(key);
# if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
     !defined(HAVE_LIBRESSL)
      EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
      return -1;
    }
#else
    EVP_DigestInit(pctx, hash);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
    if (EVP_DigestUpdate(pctx, k, klen) != 1) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error updating message digest with K: %s", sftp_crypto_get_errors());
      pr_memscrub(key, key_sz);
      free(key);
# if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
     !defined(HAVE_LIBRESSL)
      EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
      return -1;
    }
#else
    EVP_DigestUpdate(pctx, k, klen);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
    if (EVP_DigestUpdate(pctx, h, hlen) != 1) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error updating message digest with H: %s", sftp_crypto_get_errors());
      pr_memscrub(key, key_sz);
      free(key);
# if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
     !defined(HAVE_LIBRESSL)
      EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
      return -1;
    }
#else
    EVP_DigestUpdate(pctx, h, hlen);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
    if (EVP_DigestUpdate(pctx, key, len) != 1) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error updating message digest with data: %s",
        sftp_crypto_get_errors());
      pr_memscrub(key, key_sz);
      free(key);
# if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
     !defined(HAVE_LIBRESSL)
      EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
      return -1;
    }
#else
    EVP_DigestUpdate(pctx, key, len);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
    if (EVP_DigestFinal(pctx, key + len, &len) != 1) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error finalizing message digest: %s", sftp_crypto_get_errors());
      pr_memscrub(key, key_sz);
      free(key);
# if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
     !defined(HAVE_LIBRESSL)
      EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
      return -1;
    }
#else
    EVP_DigestFinal(pctx, key + len, &len);
#endif

    key_len += len;
  }

  mac->key = key;
  mac->keysz = key_sz;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  EVP_MD_CTX_free(pctx);
#endif /* OpenSSL-1.1.0 and later */

  if (mac->algo_type == SFTP_MAC_ALGO_TYPE_HMAC) {
    mac->key_len = EVP_MD_size(mac->digest);

  } else if (mac->algo_type == SFTP_MAC_ALGO_TYPE_UMAC64 ||
             mac->algo_type == SFTP_MAC_ALGO_TYPE_UMAC128) {
    mac->key_len = EVP_MD_block_size(mac->digest);
  }

  if (!sftp_interop_supports_feature(SFTP_SSH2_FEAT_MAC_LEN)) {
    mac->key_len = 16;
  }

  return 0;
}

size_t sftp_mac_get_block_size(void) {
  return mac_blockszs[read_mac_idx];
}

void sftp_mac_set_block_size(size_t blocksz) {
  if (blocksz > mac_blockszs[read_mac_idx]) {
    mac_blockszs[read_mac_idx] = blocksz;
  }
}

const char *sftp_mac_get_read_algo(void) {
  if (read_macs[read_mac_idx].key) {
    return read_macs[read_mac_idx].algo;
  }

  return NULL;
}

int sftp_mac_set_read_algo(const char *algo) {
  uint32_t mac_len;
  unsigned int idx = read_mac_idx;

  if (read_macs[idx].key) {
    /* If we have an existing key, it means that we are currently rekeying. */
    idx = get_next_read_index();
  }

  /* Clear any potential UMAC contexts at this index. */
  if (umac_read_ctxs[idx] != NULL) {
    switch (read_macs[idx].algo_type) {
      case SFTP_MAC_ALGO_TYPE_UMAC64:
        umac_delete(umac_read_ctxs[idx]);
        umac_read_ctxs[idx] = NULL;
        break;

      case SFTP_MAC_ALGO_TYPE_UMAC128:
        umac128_delete(umac_read_ctxs[idx]);
        umac_read_ctxs[idx] = NULL;
        break;
    }
  }

  read_macs[idx].digest = sftp_crypto_get_digest(algo, &mac_len);
  if (read_macs[idx].digest == NULL) {
    return -1;
  }

  read_macs[idx].algo = algo;
  if (strncmp(read_macs[idx].algo, "umac-64@openssh.com", 12) == 0) {
    read_macs[idx].algo_type = SFTP_MAC_ALGO_TYPE_UMAC64;
    umac_read_ctxs[idx] = umac_alloc();

  } else if (strncmp(read_macs[idx].algo, "umac-128@openssh.com", 13) == 0) {
    read_macs[idx].algo_type = SFTP_MAC_ALGO_TYPE_UMAC128;
    umac_read_ctxs[idx] = umac128_alloc();

  } else {
    read_macs[idx].algo_type = SFTP_MAC_ALGO_TYPE_HMAC;
  }

  read_macs[idx].mac_len = mac_len;
  return 0;
}

int sftp_mac_set_read_key(pool *p, const EVP_MD *hash, const BIGNUM *k,
    const char *h, uint32_t hlen, int role) {
  const unsigned char *id = NULL;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, id_len;
  char letter;
  size_t blocksz;
  struct sftp_mac *mac;
  HMAC_CTX *hmac_ctx;
  struct umac_ctx *umac_ctx;

  switch_read_mac();

  mac = &(read_macs[read_mac_idx]);
  hmac_ctx = hmac_read_ctxs[read_mac_idx];
  umac_ctx = umac_read_ctxs[read_mac_idx];

  bufsz = buflen = SFTP_MAC_BUFSZ;
  ptr = buf = sftp_msg_getbuf(p, bufsz);

  /* Need to use SSH2-style format of K for the key. */
  sftp_msg_write_mpint(&buf, &buflen, k);

  id_len = sftp_session_get_id(&id);

  /* The letters used depend on the role; see:
   *  https://tools.ietf.org/html/rfc4253#section-7.2
   *
   * If we are the SERVER, then we use the letters for the "client to server"
   * flows, since we are READING from the client.
   */

  /* client-to-server HASH(K || H || "E" || session_id)
   * server-to-client HASH(K || H || "F" || session_id)
   */
  letter = (role == SFTP_ROLE_SERVER ? 'E' : 'F');
  set_mac_key(mac, hash, ptr, (bufsz - buflen), h, hlen, &letter, id, id_len);

  if (init_mac(p, mac, hmac_ctx, umac_ctx) < 0) {
    return -1;
  }

  if (mac->mac_len == 0) {
    blocksz = EVP_MD_size(mac->digest);

  } else {
    blocksz = mac->mac_len;
  }

  pr_memscrub(ptr, bufsz);
  sftp_mac_set_block_size(blocksz);
  return 0;
}

int sftp_mac_read_data(struct ssh2_packet *pkt) {
  struct sftp_mac *mac;
  HMAC_CTX *hmac_ctx;
  struct umac_ctx *umac_ctx;
  int res;

  mac = &(read_macs[read_mac_idx]);
  hmac_ctx = hmac_read_ctxs[read_mac_idx];
  umac_ctx = umac_read_ctxs[read_mac_idx];

  if (mac->key == NULL) {
    pkt->mac = NULL;
    pkt->mac_len = 0;

    return 0;
  }

  res = get_mac(pkt, mac, hmac_ctx, umac_ctx, SFTP_MAC_FL_READ_MAC);
  if (res < 0) {
    return -1;
  }

  return 0;
}

const char *sftp_mac_get_write_algo(void) {
  if (write_macs[write_mac_idx].key) {
    return write_macs[write_mac_idx].algo;
  }

  return NULL;
}

int sftp_mac_set_write_algo(const char *algo) {
  uint32_t mac_len;
  unsigned int idx = write_mac_idx;

  if (write_macs[idx].key) {
    /* If we have an existing key, it means that we are currently rekeying. */
    idx = get_next_write_index();
  }

  /* Clear any potential UMAC contexts at this index. */
  if (umac_write_ctxs[idx] != NULL) {
    switch (write_macs[idx].algo_type) {
      case SFTP_MAC_ALGO_TYPE_UMAC64:
        umac_delete(umac_write_ctxs[idx]);
        umac_write_ctxs[idx] = NULL;
        break;

      case SFTP_MAC_ALGO_TYPE_UMAC128:
        umac128_delete(umac_write_ctxs[idx]);
        umac_write_ctxs[idx] = NULL;
        break;
    }
  }

  write_macs[idx].digest = sftp_crypto_get_digest(algo, &mac_len);
  if (write_macs[idx].digest == NULL) {
    return -1;
  }

  write_macs[idx].algo = algo;
  if (strncmp(write_macs[idx].algo, "umac-64@openssh.com", 12) == 0) {
    write_macs[idx].algo_type = SFTP_MAC_ALGO_TYPE_UMAC64;
    umac_write_ctxs[idx] = umac_alloc();

  } else if (strncmp(write_macs[idx].algo, "umac-128@openssh.com", 13) == 0) {
    write_macs[idx].algo_type = SFTP_MAC_ALGO_TYPE_UMAC128;
    umac_write_ctxs[idx] = umac128_alloc();

  } else {
    write_macs[idx].algo_type = SFTP_MAC_ALGO_TYPE_HMAC;
  }

  write_macs[idx].mac_len = mac_len;
  return 0;
}

int sftp_mac_set_write_key(pool *p, const EVP_MD *hash, const BIGNUM *k,
    const char *h, uint32_t hlen, int role) {
  const unsigned char *id = NULL;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, id_len;
  char letter;
  struct sftp_mac *mac;
  HMAC_CTX *hmac_ctx;
  struct umac_ctx *umac_ctx;

  switch_write_mac();

  mac = &(write_macs[write_mac_idx]);
  hmac_ctx = hmac_write_ctxs[write_mac_idx];
  umac_ctx = umac_write_ctxs[write_mac_idx];

  bufsz = buflen = SFTP_MAC_BUFSZ;
  ptr = buf = sftp_msg_getbuf(p, bufsz);

  /* Need to use SSH2-style format of K for the key. */
  sftp_msg_write_mpint(&buf, &buflen, k);

  id_len = sftp_session_get_id(&id);

  /* The letters used depend on the role; see:
   *  https://tools.ietf.org/html/rfc4253#section-7.2
   *
   * If we are the SERVER, then we use the letters for the "server to client"
   * flows, since we are WRITING to the client.
   */

  /* client-to-server HASH(K || H || "E" || session_id)
   * server-to-client HASH(K || H || "F" || session_id)
   */
  letter = (role == SFTP_ROLE_SERVER ? 'F' : 'E');
  set_mac_key(mac, hash, ptr, (bufsz - buflen), h, hlen, &letter, id, id_len);

  if (init_mac(p, mac, hmac_ctx, umac_ctx) < 0) {
    return -1;
  }

  pr_memscrub(ptr, bufsz);
  return 0;
}

int sftp_mac_write_data(struct ssh2_packet *pkt) {
  struct sftp_mac *mac;
  HMAC_CTX *hmac_ctx;
  struct umac_ctx *umac_ctx;
  int res;

  mac = &(write_macs[write_mac_idx]);
  hmac_ctx = hmac_write_ctxs[write_mac_idx];
  umac_ctx = umac_write_ctxs[write_mac_idx];

  if (mac->key == NULL) {
    pkt->mac = NULL;
    pkt->mac_len = 0;

    return 0;
  }

  res = get_mac(pkt, mac, hmac_ctx, umac_ctx, SFTP_MAC_FL_WRITE_MAC);
  if (res < 0) {
    return -1;
  }

  return 0;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
/* In older versions of OpenSSL, there was not a way to dynamically allocate
 * an HMAC_CTX object.  Thus we have these static objects for those
 * older versions.
 */
static HMAC_CTX read_ctx1, read_ctx2;
static HMAC_CTX write_ctx1, write_ctx2;
#endif /* prior to OpenSSL-1.1.0 */

int sftp_mac_init(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
  hmac_read_ctxs[0] = &read_ctx1;
  hmac_read_ctxs[1] = &read_ctx2;
  hmac_write_ctxs[0] = &write_ctx1;
  hmac_write_ctxs[1] = &write_ctx2;
#else
  hmac_read_ctxs[0] = HMAC_CTX_new();
  hmac_read_ctxs[1] = HMAC_CTX_new();
  hmac_write_ctxs[0] = HMAC_CTX_new();
  hmac_write_ctxs[1] = HMAC_CTX_new();
#endif /* OpenSSL-1.1.0 and later */

  umac_read_ctxs[0] = NULL;
  umac_read_ctxs[1] = NULL;
  umac_write_ctxs[0] = NULL;
  umac_write_ctxs[1] = NULL;

  return 0;
}

int sftp_mac_free(void) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  HMAC_CTX_free(hmac_read_ctxs[0]);
  HMAC_CTX_free(hmac_read_ctxs[1]);
  HMAC_CTX_free(hmac_write_ctxs[0]);
  HMAC_CTX_free(hmac_write_ctxs[1]);
#endif /* OpenSSL-1.1.0 and later */
  return 0;
}
