/*
 * ProFTPD - mod_sftp key exchange (kex)
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
#include "session.h"
#include "cipher.h"
#include "mac.h"
#include "compress.h"
#include "kex.h"
#include "keys.h"
#include "crypto.h"
#include "disconnect.h"
#include "interop.h"
#include "tap.h"
#include "misc.h"

#ifdef PR_USE_SODIUM
# include <sodium.h>
# define CURVE25519_SIZE	32
#endif /* PR_USE_SODIUM */

/* Define the minimum DH group length we allow (unless the AllowWeakDH
 * SFTPOption is used).
 */
#define SFTP_DH_MIN_LEN			2048

extern pr_response_t *resp_list, *resp_err_list;
extern module sftp_module;

/* For managing the kexinit process */
static pool *kex_pool = NULL;

static int kex_rekey_interval = 0;
static int kex_rekey_timeout = 0;
static int kex_rekey_timerno = -1;
static int kex_rekey_timeout_timerno = -1;

struct sftp_kex_names {
  const char *kex_algo;
  const char *server_hostkey_algo;
  const char *c2s_encrypt_algo;
  const char *s2c_encrypt_algo;
  const char *c2s_mac_algo;
  const char *s2c_mac_algo;
  const char *c2s_comp_algo;
  const char *s2c_comp_algo;
  const char *c2s_lang;
  const char *s2c_lang;
};

struct sftp_kex {
  pool *pool;

  /* Versions */
  const char *client_version;
  const char *server_version;

  /* KEXINIT lists from client */
  struct sftp_kex_names *client_names;

  /* KEXINIT lists from server. */
  struct sftp_kex_names *server_names;

  /* Session algorithms */
  struct sftp_kex_names *session_names;

  /* For constructing the session ID/hash */
  unsigned char *client_kexinit_payload;
  size_t client_kexinit_payload_len;

  unsigned char *server_kexinit_payload;
  size_t server_kexinit_payload_len;

  int first_kex_follows;

  /* Client-preferred hostkey type, based on algorithm:
   *
   *  "ssh-dss"      --> KEX_HOSTKEY_DSA
   *  "ssh-rsa"      --> KEX_HOSTKEY_RSA
   *  "ecdsa-sha2-*" --> KEX_HOSTKEY_ECDSA_*
   */
  enum sftp_key_type_e use_hostkey_type;

  /* Using DH group-exchange? */
  int use_gex;

  /* Using RSA key exchange? */
  int use_kexrsa;

  /* Using ECDH? */
  int use_ecdh;

  /* Using Curve25519? */
  int use_curve25519;

  /* For generating the session ID */
  DH *dh;
  BIGNUM *e;
  const EVP_MD *hash;

  BIGNUM *k;
  const char *h;
  uint32_t hlen;

  RSA *rsa;
  unsigned char *rsa_encrypted;
  uint32_t rsa_encrypted_len;

#ifdef PR_USE_OPENSSL_ECC
  EC_KEY *ec;
  EC_POINT *client_point;
#endif /* PR_USE_OPENSSL_ECC */
#if defined(PR_USE_SODIUM) && defined(HAVE_SHA256_OPENSSL)
  unsigned char *client_curve25519;
#endif /* PR_USE_SODIUM and HAVE_SHA256_OPENSSL */
};

static struct sftp_kex *kex_first_kex = NULL;
static struct sftp_kex *kex_rekey_kex = NULL;
static int kex_sent_kexinit = FALSE;

/* Diffie-Hellman group moduli */

static const char *dh_group1_str =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

static const char *dh_group14_str = 
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
  "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
  "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
  "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

static const char *dh_group16_str =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
  "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
  "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
  "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
  "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
  "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
  "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
  "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
  "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
  "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
  "FFFFFFFFFFFFFFFF";

static const char *dh_group18_str =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
  "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
  "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
  "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
  "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
  "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
  "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
  "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
  "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
  "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
  "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
  "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
  "179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
  "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
  "5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
  "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
  "23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
  "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
  "06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
  "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
  "12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"
  "38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300"
  "741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568"
  "3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
  "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"
  "4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A"
  "062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36"
  "4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1"
  "B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"
  "4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47"
  "9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
  "60C980DD98EDD3DFFFFFFFFFFFFFFFFF";


#define SFTP_DH_GROUP1_SHA1		1
#define SFTP_DH_GROUP14_SHA1		2
#define SFTP_DH_GEX_SHA1		3
#define SFTP_DH_GEX_SHA256		4
#define SFTP_KEXRSA_SHA1		5
#define SFTP_KEXRSA_SHA256		6
#define SFTP_ECDH_SHA256		7
#define SFTP_ECDH_SHA384		8
#define SFTP_ECDH_SHA512		9
#define SFTP_DH_GROUP14_SHA256		10
#define SFTP_DH_GROUP16_SHA512		11
#define SFTP_DH_GROUP18_SHA512		12

#define SFTP_KEXRSA_SHA1_SIZE		2048
#define SFTP_KEXRSA_SHA256_SIZE		3072

static const char *kex_client_version = NULL;
static const char *kex_server_version = NULL;
static unsigned char kex_digest_buf[EVP_MAX_MD_SIZE];

/* Used for access to a SFTPDHParamsFile during rekeys, even if the process
 * has chrooted itself.
 */
static FILE *kex_dhparams_fp = NULL;

/* Necessary prototypes. */
static struct ssh2_packet *read_kex_packet(pool *, struct sftp_kex *, int,
  char *, unsigned int, ...);

static const char *trace_channel = "ssh2";

static int kex_rekey_timeout_cb(CALLBACK_FRAME) {
  pr_trace_msg(trace_channel, 5,
    "Failed to rekey before %d %s timeout, disconnecting client",
    kex_rekey_timeout, kex_rekey_timeout != 1 ? "seconds" : "second");
  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "Failed to rekey before %d %s timeout, disconnecting client",
    kex_rekey_timeout, kex_rekey_timeout != 1 ? "seconds" : "second");
  SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  return 0;
}

static int kex_rekey_timer_cb(CALLBACK_FRAME) {
  pr_trace_msg(trace_channel, 17,
    "SFTPRekey timer (%d %s) expired, requesting rekey", kex_rekey_interval,
    kex_rekey_interval != 1 ? "secs" : "sec");
  sftp_kex_rekey();
  return 0;
}

static const unsigned char *calculate_h(struct sftp_kex *kex,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen,
    const BIGNUM *k, uint32_t *hlen) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
  EVP_MD_CTX ctx;
#endif /* prior to OpenSSL-1.1.0 */
  EVP_MD_CTX *pctx;
  const BIGNUM *dh_pub_key = NULL;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;

  bufsz = buflen = 8192;

  /* XXX Is this buffer large enough? Too large? */
  ptr = buf = sftp_msg_getbuf(kex_pool, bufsz);

  /* Write all of the data into the buffer in the SSH2 format, and hash it. */

  /* First, the version strings */
  sftp_msg_write_string(&buf, &buflen, kex->client_version);
  sftp_msg_write_string(&buf, &buflen, kex->server_version);

  /* Client's KEXINIT */
  sftp_msg_write_int(&buf, &buflen, kex->client_kexinit_payload_len + 1);
  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEXINIT);
  sftp_msg_write_data(&buf, &buflen, kex->client_kexinit_payload,
    kex->client_kexinit_payload_len, FALSE);

  /* Server's KEXINIT */
  sftp_msg_write_int(&buf, &buflen, kex->server_kexinit_payload_len + 1);
  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEXINIT);
  sftp_msg_write_data(&buf, &buflen, kex->server_kexinit_payload,
    kex->server_kexinit_payload_len, FALSE);

  /* Hostkey data */
  sftp_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen, TRUE);

  /* Client's key */
  sftp_msg_write_mpint(&buf, &buflen, kex->e);

  /* Server's key */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  DH_get0_key(kex->dh, &dh_pub_key, NULL);
#else
  dh_pub_key = kex->dh->pub_key;
#endif /* prior to OpenSSL-1.1.0 */
  sftp_msg_write_mpint(&buf, &buflen, dh_pub_key);

  /* Shared secret */
  sftp_msg_write_mpint(&buf, &buflen, k);

#if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
    !defined(HAVE_LIBRESSL)
  pctx = EVP_MD_CTX_new();
#else
  pctx = &ctx;
#endif /* OpenSSL-1.1.0 and later */

  /* In OpenSSL 0.9.6, many of the EVP_Digest* functions returned void, not
   * int.  Without these ugly OpenSSL version preprocessor checks, the
   * compiler will error out with "void value not ignored as it ought to be".
   */

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestInit(pctx, kex->hash) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error initializing message digest: %s", sftp_crypto_get_errors());
    BN_clear_free(kex->e);
    kex->e = NULL;
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestInit(pctx, kex->hash);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestUpdate(pctx, ptr, (bufsz - buflen)) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error updating message digest: %s", sftp_crypto_get_errors());
    BN_clear_free(kex->e);
    kex->e = NULL;
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestUpdate(pctx, ptr, (bufsz - buflen));
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestFinal(pctx, kex_digest_buf, hlen) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error finalizing message digest: %s", sftp_crypto_get_errors());
    BN_clear_free(kex->e);
    kex->e = NULL;
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestFinal(pctx, kex_digest_buf, hlen);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
    !defined(HAVE_LIBRESSL)
  EVP_MD_CTX_free(pctx);
#endif /* OpenSSL-1.1.0 and later */

  BN_clear_free(kex->e);
  kex->e = NULL;

  pr_memscrub(ptr, bufsz);
  return kex_digest_buf;
}

static const unsigned char *calculate_gex_h(struct sftp_kex *kex,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen,
    const BIGNUM *k, uint32_t min, uint32_t pref, uint32_t max,
    uint32_t *hlen) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
  EVP_MD_CTX ctx;
#endif /* prior to OpenSSL-1.1.0 */
  EVP_MD_CTX *pctx;
  const BIGNUM *dh_p = NULL, *dh_g = NULL, *dh_pub_key = NULL;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;

  bufsz = buflen = 8192;

  /* XXX Is this buffer large enough? Too large? */
  ptr = buf = sftp_msg_getbuf(kex_pool, bufsz);

  /* Write all of the data into the buffer in the SSH2 format, and hash it.
   * The ordering of these fields is described in RFC4419.
   */

  /* First, the version strings */
  sftp_msg_write_string(&buf, &buflen, kex->client_version);
  sftp_msg_write_string(&buf, &buflen, kex->server_version);

  /* Client's KEXINIT */
  sftp_msg_write_int(&buf, &buflen, kex->client_kexinit_payload_len + 1);
  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEXINIT);
  sftp_msg_write_data(&buf, &buflen, kex->client_kexinit_payload,
    kex->client_kexinit_payload_len, FALSE);

  /* Server's KEXINIT */
  sftp_msg_write_int(&buf, &buflen, kex->server_kexinit_payload_len + 1);
  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEXINIT);
  sftp_msg_write_data(&buf, &buflen, kex->server_kexinit_payload,
    kex->server_kexinit_payload_len, FALSE);

  /* Hostkey data */
  sftp_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen, TRUE);

  if (min == 0 ||
      max == 0) {
    sftp_msg_write_int(&buf, &buflen, pref);

  } else {
    sftp_msg_write_int(&buf, &buflen, min);
    sftp_msg_write_int(&buf, &buflen, pref);
    sftp_msg_write_int(&buf, &buflen, max);
  }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  DH_get0_pqg(kex->dh, &dh_p, NULL, &dh_g);
#else
  dh_p = kex->dh->p;
  dh_g = kex->dh->g;
#endif /* prior to OpenSSL-1.1.0 */
  sftp_msg_write_mpint(&buf, &buflen, dh_p);
  sftp_msg_write_mpint(&buf, &buflen, dh_g);

  /* Client's key */
  sftp_msg_write_mpint(&buf, &buflen, kex->e);

  /* Server's key */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  DH_get0_key(kex->dh, &dh_pub_key, NULL);
#else
  dh_pub_key = kex->dh->pub_key;
#endif /* prior to OpenSSL-1.1.0 */
  sftp_msg_write_mpint(&buf, &buflen, dh_pub_key);

  /* Shared secret */
  sftp_msg_write_mpint(&buf, &buflen, k);

#if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
    !defined(HAVE_LIBRESSL)
  pctx = EVP_MD_CTX_new();
#else
  pctx = &ctx;
#endif /* OpenSSL-1.1.0 and later */

  /* In OpenSSL 0.9.6, many of the EVP_Digest* functions returned void, not
   * int.  Without these ugly OpenSSL version preprocessor checks, the
   * compiler will error out with "void value not ignored as it ought to be".
   */

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestInit(pctx, kex->hash) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error initializing message digest: %s", sftp_crypto_get_errors());
    BN_clear_free(kex->e);
    kex->e = NULL;
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestInit(pctx, kex->hash);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestUpdate(pctx, ptr, (bufsz - buflen)) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error updating message digest: %s", sftp_crypto_get_errors());
    BN_clear_free(kex->e);
    kex->e = NULL;
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestUpdate(pctx, ptr, (bufsz - buflen));
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestFinal(pctx, kex_digest_buf, hlen) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error finalizing message digest: %s", sftp_crypto_get_errors());
    BN_clear_free(kex->e);
    kex->e = NULL;
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestFinal(pctx, kex_digest_buf, hlen);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
    !defined(HAVE_LIBRESSL)
  EVP_MD_CTX_free(pctx);
#endif /* OpenSSL-1.1.0 and later */
  BN_clear_free(kex->e);
  kex->e = NULL;
  pr_memscrub(ptr, bufsz);

  return kex_digest_buf;
}

static const unsigned char *calculate_kexrsa_h(struct sftp_kex *kex,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen,
    const BIGNUM *k, unsigned char *rsa_key, uint32_t rsa_keylen,
    uint32_t *hlen) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
  EVP_MD_CTX ctx;
#endif /* prior to OpenSSL-1.1.0 */
  EVP_MD_CTX *pctx;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;

  bufsz = buflen = 4096;

  /* XXX Is this buffer large enough? Too large? */
  ptr = buf = sftp_msg_getbuf(kex_pool, bufsz);

  /* Write all of the data into the buffer in the SSH2 format, and hash it. */

  /* First, the version strings */
  sftp_msg_write_string(&buf, &buflen, kex->client_version);
  sftp_msg_write_string(&buf, &buflen, kex->server_version);

  /* Client's KEXINIT */
  sftp_msg_write_int(&buf, &buflen, kex->client_kexinit_payload_len + 1);
  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEXINIT);
  sftp_msg_write_data(&buf, &buflen, kex->client_kexinit_payload,
    kex->client_kexinit_payload_len, FALSE);

  /* Server's KEXINIT */
  sftp_msg_write_int(&buf, &buflen, kex->server_kexinit_payload_len + 1);
  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEXINIT);
  sftp_msg_write_data(&buf, &buflen, kex->server_kexinit_payload,
    kex->server_kexinit_payload_len, FALSE);

  /* Hostkey data */
  sftp_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen, TRUE);

  /* Transient RSA public key */
  sftp_msg_write_data(&buf, &buflen, rsa_key, rsa_keylen, TRUE);

  /* RSA-encrypted secret */
  sftp_msg_write_data(&buf, &buflen, kex->rsa_encrypted, kex->rsa_encrypted_len,
    TRUE);

  /* Shared secret. */
  sftp_msg_write_mpint(&buf, &buflen, k);

#if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
    !defined(HAVE_LIBRESSL)
  pctx = EVP_MD_CTX_new();
#else
  pctx = &ctx;
#endif /* OpenSSL-1.1.0 and later */

  /* In OpenSSL 0.9.6, many of the EVP_Digest* functions returned void, not
   * int.  Without these ugly OpenSSL version preprocessor checks, the
   * compiler will error out with "void value not ignored as it ought to be".
   */

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestInit(pctx, kex->hash) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error initializing message digest: %s", sftp_crypto_get_errors());
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestInit(pctx, kex->hash);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestUpdate(pctx, ptr, (bufsz - buflen)) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error updating message digest: %s", sftp_crypto_get_errors());
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestUpdate(pctx, ptr, (bufsz - buflen));
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestFinal(pctx, kex_digest_buf, hlen) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error finalizing message digest: %s", sftp_crypto_get_errors());
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestFinal(pctx, kex_digest_buf, hlen);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
    !defined(HAVE_LIBRESSL)
  EVP_MD_CTX_free(pctx);
#endif /* OpenSSL-1.1.0 and later */
  pr_memscrub(ptr, bufsz);

  return kex_digest_buf;
}

#ifdef PR_USE_OPENSSL_ECC
static const unsigned char *calculate_ecdh_h(struct sftp_kex *kex,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen,
    const BIGNUM *k, uint32_t *hlen) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
  EVP_MD_CTX ctx;
#endif /* prior to OpenSSL-1.1.0 */
  EVP_MD_CTX *pctx;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;

  bufsz = buflen = 4096;

  /* XXX Is this buffer large enough? Too large? */
  ptr = buf = sftp_msg_getbuf(kex_pool, bufsz);

  /* Write all of the data into the buffer in the SSH2 format, and hash it.
   * The ordering of these fields is described in RFC5656.
   */

  /* First, the version strings */
  sftp_msg_write_string(&buf, &buflen, kex->client_version);
  sftp_msg_write_string(&buf, &buflen, kex->server_version);

  /* Client's KEXINIT */
  sftp_msg_write_int(&buf, &buflen, kex->client_kexinit_payload_len + 1);
  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEXINIT);
  sftp_msg_write_data(&buf, &buflen, kex->client_kexinit_payload,
    kex->client_kexinit_payload_len, FALSE);

  /* Server's KEXINIT */
  sftp_msg_write_int(&buf, &buflen, kex->server_kexinit_payload_len + 1);
  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEXINIT);
  sftp_msg_write_data(&buf, &buflen, kex->server_kexinit_payload,
    kex->server_kexinit_payload_len, FALSE);

  /* Hostkey data */
  sftp_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen, TRUE);

  /* Client's key */
  sftp_msg_write_ecpoint(&buf, &buflen, EC_KEY_get0_group(kex->ec),
    kex->client_point);

  /* Server's key */
  sftp_msg_write_ecpoint(&buf, &buflen, EC_KEY_get0_group(kex->ec),
    EC_KEY_get0_public_key(kex->ec));

  /* Shared secret */
  sftp_msg_write_mpint(&buf, &buflen, k);

#if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
    !defined(HAVE_LIBRESSL)
  pctx = EVP_MD_CTX_new();
#else
  pctx = &ctx;
#endif /* OpenSSL-1.1.0 and later */

  /* In OpenSSL 0.9.6, many of the EVP_Digest* functions returned void, not
   * int.  Without these ugly OpenSSL version preprocessor checks, the
   * compiler will error out with "void value not ignored as it ought to be".
   */

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestInit(pctx, kex->hash) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error initializing message digest: %s", sftp_crypto_get_errors());
    BN_clear_free(kex->e);
    kex->e = NULL;
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestInit(pctx, kex->hash);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestUpdate(pctx, ptr, (bufsz - buflen)) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error updating message digest: %s", sftp_crypto_get_errors());
    BN_clear_free(kex->e);
    kex->e = NULL;
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestUpdate(pctx, ptr, (bufsz - buflen));
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestFinal(pctx, kex_digest_buf, hlen) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error finalizing message digest: %s", sftp_crypto_get_errors());
    BN_clear_free(kex->e);
    kex->e = NULL;
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
     !defined(HAVE_LIBRESSL)
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestFinal(pctx, kex_digest_buf, hlen);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000LL && \
    !defined(HAVE_LIBRESSL)
  EVP_MD_CTX_free(pctx);
#endif /* OpenSSL-1.1.0 and later */
  BN_clear_free(kex->e);
  kex->e = NULL;
  pr_memscrub(ptr, bufsz);

  return kex_digest_buf;
}
#endif /* PR_USE_OPENSSL_ECC */

/* Make sure that the DH key we're generating is good enough. */
static int have_good_dh(DH *dh, BIGNUM *pub_key) {
  register int i;
  unsigned int nbits = 0;
  const BIGNUM *dh_p = NULL;
  BIGNUM *tmp;

#if OPENSSL_VERSION_NUMBER >= 0x0090801fL
  if (BN_is_negative(pub_key)) {
    pr_trace_msg(trace_channel, 10,
      "DH public keys cannot have negative numbers");
    errno = EINVAL;
    return -1;
  }
#endif /* OpenSSL-0.9.8a or later */

  if (BN_cmp(pub_key, BN_value_one()) != 1) {
    pr_trace_msg(trace_channel, 10, "bad DH public key exponent (<= 1)");
    errno = EINVAL;
    return -1;
  }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  DH_get0_pqg(dh, &dh_p, NULL, NULL);
#else
  dh_p = dh->p;
#endif /* prior to OpenSSL-1.1.0 */

  tmp = BN_new();
  if (!BN_sub(tmp, dh_p, BN_value_one()) ||
      BN_cmp(pub_key, tmp) != -1) {
    BN_clear_free(tmp);
    pr_trace_msg(trace_channel, 10, "bad DH public key (>= p-1)");
    errno = EINVAL;
    return -1;
  }

  BN_clear_free(tmp);

  for (i = 0; i <= BN_num_bits(pub_key); i++) {
    if (BN_is_bit_set(pub_key, i)) {
      nbits++;
    }
  }

  /* The number of bits set in the public key must be greater than one.
   * Otherwise, the public key will not hold up under scrutiny, not for
   * our needs.  (The OpenSSH client is picky about the DH public keys it
   * will accept as well, so this is necessary to pass OpenSSH's requirements).
   */
  if (nbits <= 1) {
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 10, "good DH public key: %u bits set", nbits);
  return 0;
}

static int get_dh_nbits(struct sftp_kex *kex) {
  int dh_nbits = 0, dh_size = 0;
  const char *algo;
  const EVP_CIPHER *cipher;
  const EVP_MD *digest;

  algo = kex->session_names->c2s_encrypt_algo;
  cipher = sftp_crypto_get_cipher(algo, NULL, NULL);
  if (cipher != NULL) {
    int block_size, key_len;

    key_len = EVP_CIPHER_key_length(cipher);
    if (dh_size < key_len) {
      dh_size = key_len;
      pr_trace_msg(trace_channel, 19,
        "set DH size to %d bytes, matching client-to-server '%s' cipher "
        "key length", dh_size, algo);
    }

    block_size = EVP_CIPHER_block_size(cipher);
    if (dh_size < block_size) {
      dh_size = block_size;
      pr_trace_msg(trace_channel, 19,
        "set DH size to %d bytes, matching client-to-server '%s' cipher "
        "block size", dh_size, algo);
    }
  }

  algo = kex->session_names->s2c_encrypt_algo;
  cipher = sftp_crypto_get_cipher(algo, NULL, NULL);
  if (cipher != NULL) {
    int block_size, key_len;

    key_len = EVP_CIPHER_key_length(cipher);
    if (dh_size < key_len) {
      dh_size = key_len;
      pr_trace_msg(trace_channel, 19,
        "set DH size to %d bytes, matching server-to-client '%s' cipher "
        "key length", dh_size, algo);
    }

    block_size = EVP_CIPHER_block_size(cipher);
    if (dh_size < block_size) {
      dh_size = block_size;
      pr_trace_msg(trace_channel, 19,
        "set DH size to %d bytes, matching server-to-client '%s' cipher "
        "block size", dh_size, algo);
    }
  }

  algo = kex->session_names->c2s_mac_algo;
  digest = sftp_crypto_get_digest(algo, NULL);
  if (digest != NULL) {
    int mac_len;

    mac_len = EVP_MD_size(digest);
    if (dh_size < mac_len) {
      dh_size = mac_len;
      pr_trace_msg(trace_channel, 19,
        "set DH size to %d bytes, matching client-to-server '%s' digest size",
        dh_size, algo);
    }
  }

  algo = kex->session_names->s2c_mac_algo;
  digest = sftp_crypto_get_digest(algo, NULL);
  if (digest != NULL) {
    int mac_len;

    mac_len = EVP_MD_size(digest);
    if (dh_size < mac_len) {
      dh_size = mac_len;
      pr_trace_msg(trace_channel, 19,
        "set DH size to %d bytes, matching server-to-client '%s' digest size",
        dh_size, algo);
    }
  }

  /* We want to return bits, not bytes. */
  dh_nbits = dh_size * 8;

  pr_trace_msg(trace_channel, 8, "requesting DH size of %d bits", dh_nbits);
  return dh_nbits;
}

static int create_dh(struct sftp_kex *kex, int type) {
  unsigned int attempts = 0;
  int dh_nbits;
  DH *dh;

  if (type != SFTP_DH_GROUP1_SHA1 &&
      type != SFTP_DH_GROUP14_SHA1 &&
      type != SFTP_DH_GROUP14_SHA256 &&
      type != SFTP_DH_GROUP16_SHA512 &&
      type != SFTP_DH_GROUP18_SHA512) {
    errno = EINVAL;
    return -1;
  }

  if (kex->dh) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (kex->dh->p) {
      BN_clear_free(kex->dh->p);
      kex->dh->p = NULL;
    }

    if (kex->dh->g) {
      BN_clear_free(kex->dh->g);
      kex->dh->g = NULL;
    }

    if (kex->dh->priv_key) {
      BN_clear_free(kex->dh->priv_key);
      kex->dh->priv_key = NULL;
    }

    if (kex->dh->pub_key) {
      BN_clear_free(kex->dh->pub_key);
      kex->dh->pub_key = NULL;
    }
#endif /* prior to OpenSSL-1.1.0 */

    DH_free(kex->dh);
    kex->dh = NULL;
  }

  dh_nbits = get_dh_nbits(kex);

  /* We have 10 attempts to make a DH key which passes muster. */
  while (attempts <= 10) {
    BIGNUM *dh_p, *dh_g, *dh_pub_key = NULL, *dh_priv_key = NULL;

    pr_signals_handle();

    attempts++;
    pr_trace_msg(trace_channel, 9, "attempt #%u to create a good DH key",
      attempts);

    dh = DH_new();
    if (dh == NULL) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error creating DH: %s", sftp_crypto_get_errors());
      return -1;
    }

    dh_p = BN_new();

    switch (type) {
      case SFTP_DH_GROUP18_SHA512:
        if (BN_hex2bn(&dh_p, dh_group18_str) == 0) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error setting DH (group18) P: %s", sftp_crypto_get_errors());
          BN_clear_free(dh_p);
          DH_free(dh);
          return -1;
        }
        break;

      case SFTP_DH_GROUP16_SHA512:
        if (BN_hex2bn(&dh_p, dh_group16_str) == 0) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error setting DH (group16) P: %s", sftp_crypto_get_errors());
          BN_clear_free(dh_p);
          DH_free(dh);
          return -1;
        }
        break;

      case SFTP_DH_GROUP14_SHA1:
      case SFTP_DH_GROUP14_SHA256:
        if (BN_hex2bn(&dh_p, dh_group14_str) == 0) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error setting DH (group14) P: %s", sftp_crypto_get_errors());
          BN_clear_free(dh_p);
          DH_free(dh);
          return -1;
        }
        break;

      default:
        if (BN_hex2bn(&dh_p, dh_group1_str) == 0) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error setting DH (group1) P: %s", sftp_crypto_get_errors());
          BN_clear_free(dh_p);
          DH_free(dh);
          return -1;
        }
        break;
    }

    dh_g = BN_new();

    if (BN_hex2bn(&dh_g, "2") == 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error setting DH G: %s", sftp_crypto_get_errors());
      BN_clear_free(dh_p);
      BN_clear_free(dh_g);
      DH_free(dh);
      return -1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
    DH_set0_pqg(dh, dh_p, NULL, dh_g);
#else
    dh->p = dh_p;
    dh->g = dh_g;
#endif /* prior to OpenSSL-1.1.0 */

    dh_priv_key = BN_new();

    /* Generate a random private exponent of the desired size, in bits. */
    if (!BN_rand(dh_priv_key, dh_nbits, 0, 0)) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error generating DH random key (%d bits): %s", dh_nbits,
        sftp_crypto_get_errors());
      BN_clear_free(dh_priv_key);
      DH_free(dh);
      return -1;
    }

    dh_pub_key = BN_new();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
    DH_set0_key(dh, dh_pub_key, dh_priv_key);
#else
    dh->pub_key = dh_pub_key;
    dh->priv_key = dh_priv_key;
#endif /* prior to OpenSSL-1.1.0 */

    pr_trace_msg(trace_channel, 12, "generating DH key");
    if (DH_generate_key(dh) != 1) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error generating DH key: %s", sftp_crypto_get_errors());
      DH_free(dh);
      return -1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
    DH_get0_key(dh, &dh_pub_key, NULL);
#else
    dh_pub_key = dh->pub_key;
#endif /* prior to OpenSSL-1.1.0 */

    if (have_good_dh(dh, dh_pub_key) < 0) {
      DH_free(dh);
      continue;
    }

    kex->dh = dh;

    switch (type) {
#ifdef HAVE_SHA512_OPENSSL
      case SFTP_DH_GROUP16_SHA512:
      case SFTP_DH_GROUP18_SHA512:
        kex->hash = EVP_sha512();
        break;
#endif /* HAVE_SHA512_OPENSSL */

#ifdef HAVE_SHA256_OPENSSL
      case SFTP_DH_GROUP14_SHA256:
        kex->hash = EVP_sha256();
        break;
#endif /* HAVE_SHA256_OPENSSL */

      default:
        kex->hash = EVP_sha1();
    }

    return 0;
  }

  errno = EPERM;
  return -1;
}

static int prepare_dh(struct sftp_kex *kex, int type) {
  DH *dh;

  if (type != SFTP_DH_GEX_SHA1 &&
      type != SFTP_DH_GEX_SHA256) {
    errno = EINVAL;
    return -1;
  }

  if (kex->dh) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (kex->dh->p) {
      BN_clear_free(kex->dh->p);
      kex->dh->p = NULL;
    }

    if (kex->dh->g) {
      BN_clear_free(kex->dh->g);
      kex->dh->g = NULL;
    }

    if (kex->dh->priv_key) {
      BN_clear_free(kex->dh->priv_key);
      kex->dh->priv_key = NULL;
    }

    if (kex->dh->pub_key) {
      BN_clear_free(kex->dh->pub_key);
      kex->dh->pub_key = NULL;
    }
#endif /* prior to OpenSSL-1.1.0 */

    DH_free(kex->dh);
    kex->dh = NULL;
  }

  dh = DH_new();
  if (!dh) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error creating DH: %s", sftp_crypto_get_errors());
    return -1;
  }

  kex->dh = dh;

  if (type == SFTP_DH_GEX_SHA1) {
    kex->hash = EVP_sha1();

#if ((OPENSSL_VERSION_NUMBER > 0x000907000L && defined(OPENSSL_FIPS)) || \
     (OPENSSL_VERSION_NUMBER > 0x000908000L)) && \
     defined(HAVE_SHA256_OPENSSL)
  } else if (type == SFTP_DH_GEX_SHA256) {
    kex->hash = EVP_sha256();
#endif
  }

  return 0;
}

static int finish_dh(struct sftp_kex *kex) {
  unsigned int attempts = 0;
  int dh_nbits;
  BIGNUM *dh_pub_key, *dh_priv_key;

  dh_nbits = get_dh_nbits(kex);

  /* We have 10 attempts to make a DH key which passes muster. */
  while (attempts <= 10) {
    pr_signals_handle();

    attempts++;
    pr_trace_msg(trace_channel, 9, "attempt #%u to create a good DH key",
      attempts);

    dh_priv_key = BN_new();
  
    /* Generate a random private exponent of the desired size, in bits. */
    if (!BN_rand(dh_priv_key, dh_nbits, 0, 0)) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error generating DH random key (%d bits): %s", dh_nbits,
        sftp_crypto_get_errors());
      BN_clear_free(dh_priv_key);
      return -1;
    }

    dh_pub_key = BN_new();

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
    DH_set0_key(kex->dh, dh_pub_key, dh_priv_key);
#else
    kex->dh->pub_key = dh_pub_key;
    kex->dh->priv_key = dh_priv_key;
#endif /* prior to OpenSSL-1.1.0 */

    pr_trace_msg(trace_channel, 12, "generating DH key");
    if (DH_generate_key(kex->dh) != 1) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error generating DH key: %s", sftp_crypto_get_errors());
      return -1;
    }

    if (have_good_dh(kex->dh, kex->e) < 0) {
      dh_pub_key = NULL;
      dh_priv_key = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
      DH_get0_key(kex->dh, &dh_pub_key, &dh_priv_key);
#else
      dh_pub_key = kex->dh->pub_key;
      dh_priv_key = kex->dh->priv_key;
#endif /* prior to OpenSSL-1.1.0 */

      if (dh_priv_key != NULL) {
        BN_clear_free(dh_priv_key);
      }

      if (dh_pub_key != NULL) {
        BN_clear_free(dh_pub_key);
      }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      /* Per the docs, this is a no-no -- but its the only way to actually
       * set the public DH key to null.
       */
      dh_pub_key = dh_priv_key = NULL;
#else
      kex->dh->pub_key = kex->dh->priv_key = NULL;
#endif /* prior to OpenSSL-1.1.0 */

      continue;
    }

    return 0;
  }

  errno = EPERM;
  return -1;
}

static int create_kexrsa(struct sftp_kex *kex, int type) {
  RSA *rsa = NULL;

  if (type != SFTP_KEXRSA_SHA1 &&
      type != SFTP_KEXRSA_SHA256) {
    errno = EINVAL;
    return -1;
  }

  if (kex->rsa) {
    RSA_free(kex->rsa);
    kex->rsa = NULL;
  }

  if (kex->rsa_encrypted) {
    pr_memscrub(kex->rsa_encrypted, kex->rsa_encrypted_len);
    kex->rsa_encrypted = NULL;
    kex->rsa_encrypted_len = 0;
  }

  if (type == SFTP_KEXRSA_SHA1) {
    BIGNUM *e = NULL;

#if OPENSSL_VERSION_NUMBER > 0x000908000L
    e = BN_new();
    if (e == NULL) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error allocated BIGNUM: %s", sftp_crypto_get_errors());
      return -1;
    }

    if (BN_set_word(e, 17) != 1) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error setting BIGNUM word: %s", sftp_crypto_get_errors());
      BN_free(e);
      return -1;
    }

    if (RSA_generate_key_ex(rsa, SFTP_KEXRSA_SHA1_SIZE, e, NULL) != 1) {
#else
    rsa = RSA_generate_key(SFTP_KEXRSA_SHA1_SIZE, 17, NULL, NULL);
    if (rsa == NULL) {
#endif /* OpenSSL version 0.9.8 and later */
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error generating %u-bit RSA key: %s", SFTP_KEXRSA_SHA1_SIZE,
        sftp_crypto_get_errors());

      if (e != NULL) {
        BN_free(e);
      }

      return -1;
    }

    kex->hash = EVP_sha1();

#if ((OPENSSL_VERSION_NUMBER > 0x000907000L && defined(OPENSSL_FIPS)) || \
     (OPENSSL_VERSION_NUMBER > 0x000908000L)) && \
     defined(HAVE_SHA256_OPENSSL)
  } else if (type == SFTP_KEXRSA_SHA256) {
    BIGNUM *e = NULL;

# if OPENSSL_VERSION_NUMBER > 0x000908000L
    e = BN_new();
    if (e == NULL) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error allocated BIGNUM: %s", sftp_crypto_get_errors());
      return -1;
    }

    if (BN_set_word(e, 65537) != 1) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error setting BIGNUM word: %s", sftp_crypto_get_errors());
      BN_free(e);
      return -1;
    }

    if (RSA_generate_key_ex(rsa, SFTP_KEXRSA_SHA256_SIZE, e, NULL) != 1) {
# else
    rsa = RSA_generate_key(SFTP_KEXRSA_SHA256_SIZE, 65537, NULL, NULL);
    if (rsa == NULL) {
# endif /* OpenSSL version 0.9.8 and later */
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error generating %u-bit RSA key: %s", SFTP_KEXRSA_SHA256_SIZE,
        sftp_crypto_get_errors());

      if (e != NULL) {
        BN_free(e);
      }

      return -1;
    }

    kex->hash = EVP_sha256();
#endif
  }

#if OPENSSL_VERSION_NUMBER < 0x0090702fL
  /* In OpenSSL-0.9.7a and later, RSA blinding is turned on by default.  Thus
   * if our OpenSSL is older than that, manually enable RSA blinding.
   */
  if (RSA_blinding_on(rsa, NULL) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error enabling RSA blinding for generated key: %s",
      sftp_crypto_get_errors());

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RSA blinding enabled for generated key");
  }
#endif

  kex->rsa = rsa;
  return 0;
}

#ifdef PR_USE_OPENSSL_ECC
static int create_ecdh(struct sftp_kex *kex, int type) {
  EC_KEY *ec;
  int curve_nid = -1;
  char *curve_name = NULL;

  switch (type) {
    case SFTP_ECDH_SHA256:
      curve_name = "NID_X9_62_prime256v1";
# if defined(HAVE_SHA256_OPENSSL)
      curve_nid = NID_X9_62_prime256v1;
      kex->hash = EVP_sha256();
# else
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "unable to generate EC key using '%s': OpenSSL lacks SHA256 support",
        curve_name);
      errno = ENOSYS;
      return -1;
# endif /* HAVE_SHA256_OPENSSL */
      break;

    case SFTP_ECDH_SHA384:
      curve_name = "NID_secp384r1";
# if defined(HAVE_SHA256_OPENSSL)
      curve_nid = NID_secp384r1;
      kex->hash = EVP_sha384();
# else
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "unable to generate EC key using '%s': OpenSSL lacks SHA256 support",
        curve_name);
      errno = ENOSYS;
      return -1;
# endif /* HAVE_SHA256_OPENSSL */
      break;

    case SFTP_ECDH_SHA512:
      curve_name = "NID_secp521r1";
# if defined(HAVE_SHA512_OPENSSL)
      curve_nid = NID_secp521r1;
      kex->hash = EVP_sha512();
# else
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "unable to generate EC key using '%s': OpenSSL lacks SHA512 support",
        curve_name);
      errno = ENOSYS;
      return -1;
# endif /* HAVE_SHA512_OPENSSL */
      break;

    default:
      errno = EINVAL;
      return -1;
  }

  ec = EC_KEY_new_by_curve_name(curve_nid);
  if (ec == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error generating new EC key using '%s': %s", curve_name,
      sftp_crypto_get_errors());
    return -1;
  }

  if (EC_KEY_generate_key(ec) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error generating new EC key: %s", sftp_crypto_get_errors());
    EC_KEY_free(ec);
    return -1;
  }

  kex->ec = ec;
  return 0;
}

static int finish_ecdh(struct sftp_kex *kex) {
  if (kex->ec) {
    EC_KEY_free(kex->ec); 
    kex->ec = NULL;
  }

  if (kex->client_point) {
    EC_POINT_clear_free(kex->client_point);
    kex->client_point = NULL;
  }

  return 0;
}
#endif /* PR_USE_OPENSSL_ECC */

/* Given a name-list, return the first (i.e. preferred) name in the list. */
static const char *get_preferred_name(pool *p, const char *names) {
  register unsigned int i;

  /* Advance to the first comma, or NUL. */
  for (i = 0; names[i] && names[i] != ','; i++);
  
  if (names[i] == ',' ||
      names[i] == '\0') {
    char *pref;

    pref = pcalloc(p, i + 1);
    memcpy(pref, names, i);

    return pref;
  }

  /* This should never happen. */
  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "unable to find preferred name in '%s'", names);
  return NULL;
}

/* Note that in this default list of key exchange algorithms, one of the
 * REQUIRED algorithms is conspicuously absent:
 *
 *   diffie-hellman-group1-sha1
 *
 * This exchange has a weak hardcoded DH group, and will thus only be used
 * if explicitly requested via SFTPKeyExchanges, or if the AllowWeakDH
 * SFTPOption is used.
 */
static const char *kex_exchanges[] = {
#if defined(PR_USE_SODIUM) && defined(HAVE_SHA256_OPENSSL)
  "curve25519-sha256@libssh.org",
#endif /* PR_USE_SODIUM and HAVE_SHA256_OPENSSL */
#ifdef PR_USE_OPENSSL_ECC
  "ecdh-sha2-nistp521",
  "ecdh-sha2-nistp384",
  "ecdh-sha2-nistp256",
#endif /* PR_USE_OPENSSL_ECC */

#if (OPENSSL_VERSION_NUMBER > 0x000907000L && defined(OPENSSL_FIPS)) || \
    (OPENSSL_VERSION_NUMBER > 0x000908000L)
# if defined(HAVE_SHA512_OPENSSL)
  "diffie-hellman-group18-sha512",
  "diffie-hellman-group16-sha512",
# endif /* HAVE_SHA512_OPENSSL */
# if defined(HAVE_SHA256_OPENSSL)
  "diffie-hellman-group14-sha256",
  "diffie-hellman-group-exchange-sha256",
# endif /* HAVE_SHA256_OPENSSL */
#endif
  "diffie-hellman-group-exchange-sha1",
  "diffie-hellman-group14-sha1",

#if 0
/* We cannot currently support rsa2048-sha256, since it requires support
 * for PKCS#1 v2.1 (RFC3447).  OpenSSL only supports PKCS#1 v2.0 (RFC2437)
 * at present, which only allows EME-OAEP using SHA1.  v2.1 allows for
 * using other message digests, e.g. SHA256, for EME-OAEP.
 */
#if ((OPENSSL_VERSION_NUMBER > 0x000907000L && defined(OPENSSL_FIPS)) || \
     (OPENSSL_VERSION_NUMBER > 0x000908000L)) && \
     defined(HAVE_SHA256_OPENSSL)
  "rsa2048-sha256",
#endif
#endif

  "rsa1024-sha1",
  NULL,
};

static const char *get_kexinit_exchange_list(pool *p) {
  char *res = "";
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "SFTPKeyExchanges", FALSE);
  if (c != NULL) {
    res = pstrdup(p, c->argv[0]);

  } else {
    register unsigned int i;

    for (i = 0; kex_exchanges[i]; i++) {
      res = pstrcat(p, res, *res ? "," : "", pstrdup(p, kex_exchanges[i]),
        NULL);
    }

    if (sftp_opts & SFTP_OPT_ALLOW_WEAK_DH) {
      /* The hardcoded group for this exchange is rather weak in the face of
       * the "Logjam" vulnerability (see https://weakdh.org).  Thus it is
       * only appended to the end of the default exchanges if the AllowWeakDH
       * SFTPOption is in effect.
       */
      res = pstrcat(p, res, ",", pstrdup(p, "diffie-hellman-group1-sha1"),
        NULL);
    }
  }

  return res;
}

static const char *get_kexinit_hostkey_algo_list(pool *p) {
#ifdef PR_USE_OPENSSL_ECC
  int *nids = NULL, res;
#endif /* PR_USE_OPENSSL_ECC */
  char *list = "";

  /* Our list of supported hostkey algorithms depends on the hostkeys
   * that have been configured.  Show a preference for RSA over DSA,
   * and ECDSA over both RSA and DSA.
   *
   * XXX Should this be configurable later?
   */

#ifdef PR_USE_OPENSSL_ECC
  res = sftp_keys_have_ecdsa_hostkey(p, &nids);
  if (res > 0) {
    register int i;

    for (i = 0; i < res; i++) {
      char *algo_name = NULL;

      switch (nids[i]) {
        case NID_X9_62_prime256v1:
          algo_name = "ecdsa-sha2-nistp256";
          break;

        case NID_secp384r1:
          algo_name = "ecdsa-sha2-nistp384";
          break;

        case NID_secp521r1:
          algo_name = "ecdsa-sha2-nistp521";
          break;

        default:
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "unknown/unsupported ECDSA NID %d, skipping", nids[i]);
          break;
      }

      if (algo_name != NULL) {
        list = pstrcat(p, list, *list ? "," : "", algo_name, NULL);
      }
    }
  }
#endif /* PR_USE_OPENSSL_ECC */

  if (sftp_keys_have_rsa_hostkey() == 0) {
    list = pstrcat(p, list, *list ? "," : "", "ssh-rsa", NULL);
  }

  if (sftp_keys_have_dsa_hostkey() == 0) {
    list = pstrcat(p, list, *list ? "," : "", "ssh-dss", NULL);
  } 

  return list;
}

static struct sftp_kex *create_kex(pool *p) {
  struct sftp_kex *kex;
  const char *list;
  config_rec *c;
  pool *tmp_pool;

  tmp_pool = make_sub_pool(p);
  pr_pool_tag(tmp_pool, "Kex KEXINIT Pool");

  kex = pcalloc(tmp_pool, sizeof(struct sftp_kex));
  kex->pool = tmp_pool;
  kex->client_version = kex_client_version;
  kex->server_version = kex_server_version;
  kex->client_names = pcalloc(kex->pool, sizeof(struct sftp_kex_names));
  kex->server_names = pcalloc(kex->pool, sizeof(struct sftp_kex_names));
  kex->session_names = pcalloc(kex->pool, sizeof(struct sftp_kex_names));
  kex->use_hostkey_type = SFTP_KEY_UNKNOWN;
  kex->dh = NULL;
  kex->e = NULL;
  kex->hash = NULL;
  kex->k = NULL;
  kex->h = NULL;
  kex->hlen = 0;
  kex->rsa = NULL;
  kex->rsa_encrypted = NULL;
  kex->rsa_encrypted_len = 0;

  list = get_kexinit_exchange_list(kex->pool);
  kex->server_names->kex_algo = list;

  list = get_kexinit_hostkey_algo_list(kex->pool);
  kex->server_names->server_hostkey_algo = list;

  list = sftp_crypto_get_kexinit_cipher_list(kex->pool);
  kex->server_names->c2s_encrypt_algo = list;
  kex->server_names->s2c_encrypt_algo = list;

  list = sftp_crypto_get_kexinit_digest_list(kex->pool);
  kex->server_names->c2s_mac_algo = list;
  kex->server_names->s2c_mac_algo = list;

  c = find_config(main_server->conf, CONF_PARAM, "SFTPCompression", FALSE);
  if (c) {
    int comp_mode;

    comp_mode = *((int *) c->argv[0]);

    switch (comp_mode) {
      case 2:
        /* Advertise that we support OpenSSH's "delayed" compression mode. */
        kex->server_names->c2s_comp_algo = "zlib@openssh.com,zlib,none";
        kex->server_names->s2c_comp_algo = "zlib@openssh.com,zlib,none";
        break;

      case 1:
        kex->server_names->c2s_comp_algo = "zlib,none";
        kex->server_names->s2c_comp_algo = "zlib,none";
        break;

      default:
        kex->server_names->c2s_comp_algo = "none";
        kex->server_names->s2c_comp_algo = "none";
        break;
    }

  } else {
    kex->server_names->c2s_comp_algo = "none";
    kex->server_names->s2c_comp_algo = "none";
  }

#ifdef PR_USE_NLS
  c = find_config(main_server->conf, CONF_PARAM, "SFTPLanguages", FALSE);
  if (c) {
    /* XXX Need to implement functionality here. */

  } else {
    kex->server_names->c2s_lang = "en_US";
    kex->server_names->s2c_lang = "en_US";
  }
#else
  kex->server_names->c2s_lang = "";
  kex->server_names->s2c_lang = "";
#endif /* !PR_USE_NLS */

  return kex;
}

static void destroy_kex(struct sftp_kex *kex) {
  if (kex) {
    if (kex->dh) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
      if (kex->dh->p) {
        BN_clear_free(kex->dh->p);
        kex->dh->p = NULL;
      }

      if (kex->dh->g) {
        BN_clear_free(kex->dh->g);
        kex->dh->g = NULL;
      }
#endif /* prior to OpenSSL-1.1.0 */

      DH_free(kex->dh);
      kex->dh = NULL;
    }

    if (kex->rsa) {
      RSA_free(kex->rsa);
      kex->rsa = NULL;
    }

    if (kex->rsa_encrypted) {
      pr_memscrub(kex->rsa_encrypted, kex->rsa_encrypted_len);
      kex->rsa_encrypted = NULL;
      kex->rsa_encrypted_len = 0;
    }

    if (kex->e) {
      BN_clear_free(kex->e);
      kex->e = NULL;
    }

    if (kex->k) {
      BN_clear_free(kex->k);
      kex->k = NULL;
    }

    if (kex->hlen > 0) {
      pr_memscrub((char *) kex->h, kex->hlen);
      kex->hlen = 0;
    }

    if (kex->pool) {
      destroy_pool(kex->pool);
      kex->pool = NULL;
    }
  }

  kex_first_kex = kex_rekey_kex = NULL;
}

static int setup_kex_algo(struct sftp_kex *kex, const char *algo) {

  if (strncmp(algo, "diffie-hellman-group1-sha1", 27) == 0) {
    if (create_dh(kex, SFTP_DH_GROUP1_SHA1) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    return 0;

  } else if (strncmp(algo, "diffie-hellman-group14-sha1", 28) == 0) {
    if (create_dh(kex, SFTP_DH_GROUP14_SHA1) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    return 0;

  } else if (strncmp(algo, "diffie-hellman-group14-sha256", 30) == 0) {
    if (create_dh(kex, SFTP_DH_GROUP14_SHA256) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    return 0;

  } else if (strncmp(algo, "diffie-hellman-group16-sha512", 30) == 0) {
    if (create_dh(kex, SFTP_DH_GROUP16_SHA512) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    return 0;

  } else if (strncmp(algo, "diffie-hellman-group18-sha512", 30) == 0) {
    if (create_dh(kex, SFTP_DH_GROUP18_SHA512) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    return 0;

  } else if (strncmp(algo, "diffie-hellman-group-exchange-sha1", 35) == 0) {
    if (prepare_dh(kex, SFTP_DH_GEX_SHA1) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    kex->use_gex = TRUE;
    return 0;

  } else if (strncmp(algo, "rsa1024-sha1", 13) == 0) {
    if (create_kexrsa(kex, SFTP_KEXRSA_SHA1) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    kex->use_kexrsa = TRUE;
    return 0;

#if ((OPENSSL_VERSION_NUMBER > 0x000907000L && defined(OPENSSL_FIPS)) || \
     (OPENSSL_VERSION_NUMBER > 0x000908000L)) && \
     defined(HAVE_SHA256_OPENSSL)
  } else if (strncmp(algo, "diffie-hellman-group-exchange-sha256", 37) == 0) {
    if (prepare_dh(kex, SFTP_DH_GEX_SHA256) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    kex->use_gex = TRUE;
    return 0;

  } else if (strncmp(algo, "rsa2048-sha256", 15) == 0) {
    if (create_kexrsa(kex, SFTP_KEXRSA_SHA256) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    kex->use_kexrsa = TRUE;
    return 0;
#endif

#ifdef PR_USE_OPENSSL_ECC
  } else if (strncmp(algo, "ecdh-sha2-nistp256", 19) == 0) {
    if (create_ecdh(kex, SFTP_ECDH_SHA256) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    kex->use_ecdh = TRUE;
    return 0;

  } else if (strncmp(algo, "ecdh-sha2-nistp384", 19) == 0) {
    if (create_ecdh(kex, SFTP_ECDH_SHA384) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    kex->use_ecdh = TRUE;
    return 0;

  } else if (strncmp(algo, "ecdh-sha2-nistp521", 19) == 0) {
    if (create_ecdh(kex, SFTP_ECDH_SHA512) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error using '%s' as the key exchange algorithm: %s", algo,
        strerror(errno));
      return -1;
    }

    kex->session_names->kex_algo = algo;
    kex->use_ecdh = TRUE;
    return 0;
#endif /* PR_USE_OPENSSL_ECC */

#if defined(PR_USE_SODIUM) && defined(HAVE_SHA256_OPENSSL)
  } else if (strncmp(algo, "curve25519-sha256@libssh.org", 22) == 0) {
    kex->hash = EVP_sha256();
    kex->session_names->kex_algo = algo;
    kex->use_curve25519 = TRUE;
    return 0;
#endif /* PR_USE_SODIUM and HAVE_SHA256_OPENSSL */
  }

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "unsupported key exchange algorithm '%s'", algo);
  errno = EINVAL;
  return -1;
}

static int setup_hostkey_algo(struct sftp_kex *kex, const char *algo) {
  kex->session_names->server_hostkey_algo = (char *) algo;

  if (strncmp(algo, "ssh-dss", 8) == 0) {
    kex->use_hostkey_type = SFTP_KEY_DSA;
    return 0;
  }

  if (strncmp(algo, "ssh-rsa", 8) == 0) {
    kex->use_hostkey_type = SFTP_KEY_RSA;
    return 0;
  }

#ifdef PR_USE_OPENSSL_ECC
  if (strncmp(algo, "ecdsa-sha2-nistp256", 20) == 0) {
    kex->use_hostkey_type = SFTP_KEY_ECDSA_256;
    return 0;
  }

  if (strncmp(algo, "ecdsa-sha2-nistp384", 20) == 0) {
    kex->use_hostkey_type = SFTP_KEY_ECDSA_384;
    return 0;
  }

  if (strncmp(algo, "ecdsa-sha2-nistp521", 20) == 0) {
    kex->use_hostkey_type = SFTP_KEY_ECDSA_521;
    return 0;
  }
#endif /* PR_USE_OPENSSL_ECC */

  /* XXX Need to handle "x509v3-ssh-dss", "x509v3-ssh-rsa", "x509v3-sign"
   * algorithms here.
   */

  errno = EINVAL;
  return -1;
}

static int setup_c2s_encrypt_algo(struct sftp_kex *kex, const char *algo) {
  if (sftp_cipher_set_read_algo(algo) < 0) {
    return -1;
  }

  kex->session_names->c2s_encrypt_algo = algo;
  return 0;
}

static int setup_s2c_encrypt_algo(struct sftp_kex *kex, const char *algo) {
  if (sftp_cipher_set_write_algo(algo) < 0) {
    return -1;
  }

  kex->session_names->s2c_encrypt_algo = algo;
  return 0;
}

static int setup_c2s_mac_algo(struct sftp_kex *kex, const char *algo) {
  if (sftp_mac_set_read_algo(algo) < 0) {
    return -1;
  }

  kex->session_names->c2s_mac_algo = algo;
  return 0;
}

static int setup_s2c_mac_algo(struct sftp_kex *kex, const char *algo) {
  if (sftp_mac_set_write_algo(algo) < 0) {
    return -1;
  }

  kex->session_names->s2c_mac_algo = algo;
  return 0;
}

static int setup_c2s_comp_algo(struct sftp_kex *kex, const char *algo) {
  if (sftp_compress_set_read_algo(algo) < 0) {
    return -1;
  }

  kex->session_names->c2s_comp_algo = algo;
  return 0;
}

static int setup_s2c_comp_algo(struct sftp_kex *kex, const char *algo) {
  if (sftp_compress_set_write_algo(algo) < 0) {
    return -1;
  }

  kex->session_names->s2c_comp_algo = algo;
  return 0;
}

static int setup_c2s_lang(struct sftp_kex *kex, const char *lang) {
  /* XXX Need to implement the functionality here. */
  kex->session_names->c2s_lang = lang;
  return 0;
}

static int setup_s2c_lang(struct sftp_kex *kex, const char *lang) {
  /* XXX Need to implement the functionality here. */
  kex->session_names->s2c_lang = lang;
  return 0;
}

static int get_session_names(struct sftp_kex *kex, int *correct_guess) {
  const char *kex_algo, *shared, *client_list, *server_list;
  const char *client_pref, *server_pref;
  pool *tmp_pool;

  tmp_pool = make_sub_pool(kex->pool);
  pr_pool_tag(tmp_pool, "SSH2 session shared name pool");

  client_list = kex->client_names->kex_algo;
  server_list = kex->server_names->kex_algo;

  pr_trace_msg(trace_channel, 8, "client-sent key exchange algorithms: %s",
    client_list);
  pr_trace_msg(trace_channel, 8, "server-sent key exchange algorithms: %s",
    server_list);

  client_pref = get_preferred_name(tmp_pool, client_list);
  server_pref = get_preferred_name(tmp_pool, server_list);

  /* Did the client correctly guess at the key exchange algorithm that
   * we would list first in our server list, if it says it sent
   * a guess KEX packet?
   */

  if (kex->first_kex_follows == TRUE &&
      *correct_guess == TRUE &&
      client_pref != NULL &&
      server_pref != NULL) {

    if (strcmp(client_pref, server_pref) != 0) {
      *correct_guess = FALSE;

      pr_trace_msg(trace_channel, 7,
        "client incorrectly guessed key exchange algorithm '%s'", client_pref);

    } else {
      pr_trace_msg(trace_channel, 7,
        "client correctly guessed key exchange algorithm '%s'", server_pref);
    }
  }

  kex_algo = sftp_misc_namelist_shared(kex->pool, client_list, server_list);
  if (kex_algo != NULL) {
    /* Unlike the following algorithms, we wait to setup the chosen kex algo
     * until the end.  Why?  The kex algo setup may require knowledge of the
     * ciphers chosen for encryption, MAC, etc (Bug#4097).
     */
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      " + Session key exchange: %s", kex_algo);
    pr_trace_msg(trace_channel, 20, "session key exchange algorithm: %s",
      kex_algo);

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no shared key exchange algorithm found (client sent '%s', server sent "
      "'%s')", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
  }

  client_list = kex->client_names->server_hostkey_algo;
  server_list = kex->server_names->server_hostkey_algo;

  pr_trace_msg(trace_channel, 8,
    "client-sent host key algorithms: %s", client_list);
  pr_trace_msg(trace_channel, 8,
    "server-sent host key algorithms: %s", server_list);

  shared = sftp_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared) {
    if (setup_hostkey_algo(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      " + Session server hostkey: %s", shared);
    pr_trace_msg(trace_channel, 20, "session server hostkey algorithm: %s",
      shared);

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no shared server hostkey algorithm found (client sent '%s', server sent "
      "'%s'", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
  }

  client_list = kex->client_names->c2s_encrypt_algo;
  server_list = kex->server_names->c2s_encrypt_algo;

  pr_trace_msg(trace_channel, 8, "client-sent client encryption algorithms: %s",
    client_list);
  pr_trace_msg(trace_channel, 8, "server-sent client encryption algorithms: %s",
    server_list);

  shared = sftp_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared) {
    if (setup_c2s_encrypt_algo(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      " + Session client-to-server encryption: %s", shared);
    pr_trace_msg(trace_channel, 20,
      "session client-to-server encryption algorithm: %s", shared);

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no shared client-to-server encryption algorithm found (client sent '%s',"
      " server sent '%s')", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
  }

  client_list = kex->client_names->s2c_encrypt_algo;
  server_list = kex->server_names->s2c_encrypt_algo;

  pr_trace_msg(trace_channel, 8, "client-sent server encryption algorithms: %s",
    client_list);
  pr_trace_msg(trace_channel, 8, "server-sent server encryption algorithms: %s",
    server_list);

  shared = sftp_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared) {
    if (setup_s2c_encrypt_algo(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      " + Session server-to-client encryption: %s", shared);
    pr_trace_msg(trace_channel, 20,
      "session server-to-client encryption algorithm: %s", shared);

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no shared server-to-client encryption algorithm found (client sent '%s',"
      " server sent '%s')", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
  }

  client_list = kex->client_names->c2s_mac_algo;
  server_list = kex->server_names->c2s_mac_algo;

  pr_trace_msg(trace_channel, 8, "client-sent client MAC algorithms: %s",
    client_list);
  pr_trace_msg(trace_channel, 8, "server-sent client MAC algorithms: %s",
    server_list);

  shared = sftp_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared) {
    if (setup_c2s_mac_algo(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      " + Session client-to-server MAC: %s", shared);
    pr_trace_msg(trace_channel, 20,
      "session client-to-server MAC algorithm: %s", shared);

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no shared client-to-server MAC algorithm found (client sent '%s', "
      "server sent '%s')", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
  }

  client_list = kex->client_names->s2c_mac_algo;
  server_list = kex->server_names->s2c_mac_algo;

  pr_trace_msg(trace_channel, 8, "client-sent server MAC algorithms: %s",
    client_list);
  pr_trace_msg(trace_channel, 8, "server-sent server MAC algorithms: %s",
    server_list);

  shared = sftp_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared) {
    if (setup_s2c_mac_algo(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      " + Session server-to-client MAC: %s", shared);
    pr_trace_msg(trace_channel, 20,
      "session server-to-client MAC algorithm: %s", shared);

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no shared server-to-client MAC algorithm found (client sent '%s', "
      "server sent '%s')", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
  }

  client_list = kex->client_names->c2s_comp_algo;
  server_list = kex->server_names->c2s_comp_algo;

  pr_trace_msg(trace_channel, 8,
    "client-sent client compression algorithms: %s", client_list);
  pr_trace_msg(trace_channel, 8,
    "server-sent client compression algorithms: %s", server_list);

  shared = sftp_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared) {
    if (setup_c2s_comp_algo(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      " + Session client-to-server compression: %s", shared);
    pr_trace_msg(trace_channel, 20,
      "session client-to-server compression algorithm: %s", shared);

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no shared client-to-server compression algorithm found (client sent "
      "'%s', server sent '%s'", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
  }

  client_list = kex->client_names->s2c_comp_algo;
  server_list = kex->server_names->s2c_comp_algo;

  pr_trace_msg(trace_channel, 8,
    "client-sent server compression algorithms: %s", client_list);
  pr_trace_msg(trace_channel, 8,
    "server-sent server compression algorithms: %s", server_list);

  shared = sftp_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared) {
    if (setup_s2c_comp_algo(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      " + Session server-to-client compression: %s", shared);
    pr_trace_msg(trace_channel, 20,
      "session server-to-client compression algorithm: %s", shared);

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no shared server-to-client compression algorithm found (client sent "
      "'%s', server sent '%s'", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
  }

  client_list = kex->client_names->c2s_lang;
  server_list = kex->server_names->c2s_lang;

  pr_trace_msg(trace_channel, 8,
    "client-sent client languages: %s", client_list);
  pr_trace_msg(trace_channel, 8,
    "server-sent client languages: %s", client_list);

  shared = sftp_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared) {
    if (setup_c2s_lang(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      " + Session client-to-server language: %s", shared);
    pr_trace_msg(trace_channel, 20,
      "session client-to-server language: %s", shared);

/* XXX Do not error out if there are no shared languages yet. */
#if 0
  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no shared client-to-server language found (client sent '%s', server "
      "sent '%s'", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
#endif
  }

  client_list = kex->client_names->s2c_lang;
  server_list = kex->server_names->s2c_lang;

  pr_trace_msg(trace_channel, 8,
    "client-sent server languages: %s", client_list);
  pr_trace_msg(trace_channel, 8,
    "server-sent server languages: %s", client_list);

  shared = sftp_misc_namelist_shared(kex->pool, client_list, server_list);
  if (shared) {
    if (setup_s2c_lang(kex, shared) < 0) {
      destroy_pool(tmp_pool);
      return -1;
    }

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      " + Session server-to-client language: %s", shared);
    pr_trace_msg(trace_channel, 20,
      "session server-to-client language: %s", shared);

/* XXX Do not error out if there are no shared languages yet. */
#if 0
  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no shared server-to-client language found (client sent '%s', server "
      "sent '%s'", client_list, server_list);
    destroy_pool(tmp_pool);
    return -1;
#endif
  }

  /* Now that we've finished setting up the other bits, we can set up the
   * kex algo.
   */
  if (setup_kex_algo(kex, kex_algo) < 0) {
    destroy_pool(tmp_pool);
    return -1;
  }

  destroy_pool(tmp_pool);
  return 0;
}

static int read_kexinit(struct ssh2_packet *pkt, struct sftp_kex *kex) {
  unsigned char *buf;
  char *list;
  uint32_t buflen;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* Make a copy of the payload for later. */
  kex->client_kexinit_payload = palloc(kex->pool, pkt->payload_len);
  kex->client_kexinit_payload_len = pkt->payload_len;
  memcpy(kex->client_kexinit_payload, pkt->payload, pkt->payload_len);

  /* Read the cookie, which is a mandated length of 16 bytes. */
  (void) sftp_msg_read_data(pkt->pool, &buf, &buflen, 16);

  list = sftp_msg_read_string(kex->pool, &buf, &buflen);
  kex->client_names->kex_algo = list;

  list = sftp_msg_read_string(kex->pool, &buf, &buflen);
  kex->client_names->server_hostkey_algo = list;

  list = sftp_msg_read_string(kex->pool, &buf, &buflen);
  kex->client_names->c2s_encrypt_algo = list;

  list = sftp_msg_read_string(kex->pool, &buf, &buflen);
  kex->client_names->s2c_encrypt_algo = list;

  list = sftp_msg_read_string(kex->pool, &buf, &buflen);
  kex->client_names->c2s_mac_algo = list;

  list = sftp_msg_read_string(kex->pool, &buf, &buflen);
  kex->client_names->s2c_mac_algo = list;

  list = sftp_msg_read_string(kex->pool, &buf, &buflen);
  kex->client_names->c2s_comp_algo = list;

  list = sftp_msg_read_string(kex->pool, &buf, &buflen);
  kex->client_names->s2c_comp_algo = list;

  /* Client-to-server languages */
  list = sftp_msg_read_string(kex->pool, &buf, &buflen);
  kex->client_names->c2s_lang = list;

  /* Server-to-client languages */
  list = sftp_msg_read_string(kex->pool, &buf, &buflen);
  kex->client_names->s2c_lang = list;

  /* Read the "first kex packet follows" byte */
  kex->first_kex_follows = sftp_msg_read_bool(pkt->pool, &buf, &buflen);

  pr_trace_msg(trace_channel, 3, "first kex packet follows = %s",
    kex->first_kex_follows ? "true" : "false");

  /* Reserved flags */
  (void) sftp_msg_read_int(pkt->pool, &buf, &buflen);

  return 0;
}

static int write_kexinit(struct ssh2_packet *pkt, struct sftp_kex *kex) {
  unsigned char cookie[16];
  unsigned char *buf, *ptr;
  const char *list;
  uint32_t bufsz, buflen;

  /* XXX Always have empty language lists; we really don't care. */
  const char *langs = "";

  bufsz = buflen = sizeof(char) +
    sizeof(cookie) +
    sizeof(uint32_t) + strlen(kex->server_names->kex_algo) +
    sizeof(uint32_t) + strlen(kex->server_names->server_hostkey_algo) +
    sizeof(uint32_t) + strlen(kex->server_names->c2s_encrypt_algo) +
    sizeof(uint32_t) + strlen(kex->server_names->s2c_encrypt_algo) +
    sizeof(uint32_t) + strlen(kex->server_names->c2s_mac_algo) +
    sizeof(uint32_t) + strlen(kex->server_names->s2c_mac_algo) +
    sizeof(uint32_t) + strlen(kex->server_names->c2s_comp_algo) +
    sizeof(uint32_t) + strlen(kex->server_names->s2c_comp_algo) +
    sizeof(uint32_t) + strlen(langs) +
    sizeof(uint32_t) + strlen(langs) +
    sizeof(char) +
    sizeof(uint32_t);

  ptr = buf = pcalloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEXINIT);

  /* Try first to use cryptographically secure bytes for the cookie.
   * If that fails (e.g. if the PRNG hasn't been seeded well), use
   * pseudo-cryptographically secure bytes.
   */
  memset(cookie, 0, sizeof(cookie));
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  RAND_bytes(cookie, sizeof(cookie));
#else
  if (RAND_bytes(cookie, sizeof(cookie)) != 1) {
    RAND_pseudo_bytes(cookie, sizeof(cookie));
  }
#endif /* prior to OpenSSL-1.1.0 */

  sftp_msg_write_data(&buf, &buflen, cookie, sizeof(cookie), FALSE);

  list = kex->server_names->kex_algo;
  sftp_msg_write_string(&buf, &buflen, list);

  list = kex->server_names->server_hostkey_algo;
  sftp_msg_write_string(&buf, &buflen, list);

  list = kex->server_names->c2s_encrypt_algo;
  sftp_msg_write_string(&buf, &buflen, list);

  list = kex->server_names->s2c_encrypt_algo;
  sftp_msg_write_string(&buf, &buflen, list);

  list = kex->server_names->c2s_mac_algo;
  sftp_msg_write_string(&buf, &buflen, list);

  list = kex->server_names->s2c_mac_algo;
  sftp_msg_write_string(&buf, &buflen, list);

  list = kex->server_names->c2s_comp_algo;
  sftp_msg_write_string(&buf, &buflen, list);

  list = kex->server_names->s2c_comp_algo;
  sftp_msg_write_string(&buf, &buflen, list);

  /* XXX Need to support langs here. */
  sftp_msg_write_string(&buf, &buflen, langs);
  sftp_msg_write_string(&buf, &buflen, langs);

  /* We don't try to optimistically guess what algorithms the client would
   * use and send a preemptive kex packet.
   */
  sftp_msg_write_bool(&buf, &buflen, FALSE);
  sftp_msg_write_int(&buf, &buflen, 0);

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  /* Make a copy of the payload for later. Skip past the first byte, which
   * is the KEXINIT identifier.
   */
  kex->server_kexinit_payload_len = pkt->payload_len - 1;
  kex->server_kexinit_payload = palloc(kex->pool, pkt->payload_len - 1);
  memcpy(kex->server_kexinit_payload, pkt->payload + 1, pkt->payload_len - 1);

  return 0;
}

static int read_dh_init(struct ssh2_packet *pkt, struct sftp_kex *kex) {
  unsigned char *buf;
  uint32_t buflen;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* Read in 'e' */
  kex->e = sftp_msg_read_mpint(pkt->pool, &buf, &buflen);
  if (kex->e == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading DH_INIT: %s", strerror(errno));
    return -1;
  }

  return 0;
}

/* Only set the given environment variable/value IFF it is not already
 * present.
 */
static void set_env_var(pool *p, const char *k, const char *v) {
  const char *val;
  int have_val = FALSE;

  val = pr_env_get(p, k);
  if (val != NULL) {
    if (strcmp(val, v) == 0) {
      have_val = TRUE;
    }
  }

  if (have_val == FALSE) {
    k = pstrdup(p, k);
    v = pstrdup(p, v);
    pr_env_unset(p, k);
    pr_env_set(p, k, v);
  }
}

static int set_session_keys(struct sftp_kex *kex) {
  const char *k;
  int comp_read_flags, comp_write_flags;

  if (sftp_cipher_set_read_key(kex_pool, kex->hash, kex->k, kex->h,
      kex->hlen, SFTP_ROLE_SERVER) < 0) {
    return -1;
  }

  if (sftp_cipher_set_write_key(kex_pool, kex->hash, kex->k, kex->h,
      kex->hlen, SFTP_ROLE_SERVER) < 0) {
    return -1;
  }

  if (sftp_mac_set_read_key(kex_pool, kex->hash, kex->k, kex->h,
      kex->hlen, SFTP_ROLE_SERVER) < 0) {
    return -1;
  }

  if (sftp_mac_set_write_key(kex_pool, kex->hash, kex->k, kex->h,
      kex->hlen, SFTP_ROLE_SERVER) < 0) {
    return -1;
  }

  comp_read_flags = comp_write_flags = SFTP_COMPRESS_FL_NEW_KEY;

  /* If we are rekeying, AND the existing compression is "delayed", then
   * we need to use slightly different compression flags.
   */
  if (kex_rekey_kex) {
    const char *algo;

    algo = sftp_compress_get_read_algo();
    if (strncmp(algo, "zlib@openssh.com", 17) == 0) {
      comp_read_flags = SFTP_COMPRESS_FL_AUTHENTICATED;
    }

    algo = sftp_compress_get_write_algo();
    if (strncmp(algo, "zlib@openssh.com", 17) == 0) {
      comp_write_flags = SFTP_COMPRESS_FL_AUTHENTICATED;
    }
  }

  if (sftp_compress_init_read(comp_read_flags) < 0) {
    return -1;
  }

  if (sftp_compress_init_write(comp_write_flags) < 0) {
    return -1;
  }

  set_env_var(session.pool, "SFTP_CLIENT_CIPHER_ALGO",
    sftp_cipher_get_read_algo());
  set_env_var(session.pool, "SFTP_SERVER_CIPHER_ALGO",
    sftp_cipher_get_write_algo());
  set_env_var(session.pool, "SFTP_CLIENT_MAC_ALGO",
    sftp_mac_get_read_algo());
  set_env_var(session.pool, "SFTP_SERVER_MAC_ALGO",
    sftp_mac_get_write_algo());
  set_env_var(session.pool, "SFTP_CLIENT_COMPRESSION_ALGO",
    sftp_compress_get_read_algo());
  set_env_var(session.pool, "SFTP_SERVER_COMPRESSION_ALGO",
    sftp_compress_get_write_algo());
  set_env_var(session.pool, "SFTP_KEX_ALGO",
    kex->session_names->kex_algo);

  if (kex_rekey_interval > 0 &&
      kex_rekey_timerno == -1) {
    /* Register the rekey timer. */
    kex_rekey_timerno = pr_timer_add(kex_rekey_interval, -1,
      &sftp_module, kex_rekey_timer_cb, "SFTP KEX Rekey timer");
  }

  if (kex_rekey_timeout > 0 &&
      kex_rekey_timeout_timerno > 0) {
    pr_timer_remove(kex_rekey_timeout_timerno, &sftp_module);
    kex_rekey_timeout_timerno = -1;
  }

  if (kex_rekey_kex != NULL) {
    pr_trace_msg("ssh2", 3, "rekey KEX completed");
  }

  sftp_ssh2_packet_rekey_reset();
  kex_rekey_kex = NULL;

  /* If any CBC mode ciphers have been negotiated for the server-to-client
   * stream, then we need to use the 'rogaway' TAP policy.
   */
  k = sftp_cipher_get_write_algo();
  if (strncmp(k + strlen(k) - 4, "-cbc", 4) == 0) {
    const char *policy = "rogaway";

    pr_trace_msg("ssh2", 4, "CBC mode cipher chosen for server-to-client "
      "messages, automatically enabling '%s' TAP policy", policy);

    if (sftp_tap_set_policy(policy) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error setting TrafficPolicy '%s': %s", policy, strerror(errno));
    }
  }
 
  return 0;
}

static int write_dh_reply(struct ssh2_packet *pkt, struct sftp_kex *kex) {
  const unsigned char *h;
  const unsigned char *hostkey_data, *hsig;
  unsigned char *buf, *ptr;
  uint32_t bufsz, buflen, hlen = 0, hostkey_datalen = 0;
  size_t dhlen, hsiglen;
  BIGNUM *k = NULL, *dh_pub_key = NULL;
  int res;

  /* Compute the shared secret */
  dhlen = DH_size(kex->dh);
  buf = palloc(pkt->pool, dhlen);

  pr_trace_msg(trace_channel, 12, "computing DH key");
  res = DH_compute_key((unsigned char *) buf, kex->e, kex->dh);
  if (res < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error computing DH shared secret: %s", sftp_crypto_get_errors());
    return -1;
  }

  k = BN_new();
  if (BN_bin2bn((unsigned char *) buf, res, k) == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error converting DH shared secret to BN: %s", sftp_crypto_get_errors());

    pr_memscrub(buf, res);
    return -1;
  }

  pr_memscrub(buf, res);
  kex->k = k;

  /* Get the hostkey data; it will be part of the data we hash in order
   * to create the session key.
   */
  hostkey_data = sftp_keys_get_hostkey_data(pkt->pool, kex->use_hostkey_type,
    &hostkey_datalen);
  if (hostkey_data == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error converting hostkey for signing: %s", strerror(errno));

    BN_clear_free(kex->k);
    kex->k = NULL;
    return -1;
  }

  /* Calculate H */
  h = calculate_h(kex, hostkey_data, hostkey_datalen, k, &hlen);
  if (h == NULL) {
    pr_memscrub((char *) hostkey_data, hostkey_datalen);
    BN_clear_free(kex->k);
    kex->k = NULL;
    return -1;
  }

  kex->h = palloc(pkt->pool, hlen);
  kex->hlen = hlen;
  memcpy((char *) kex->h, h, kex->hlen);

  /* Save H as the session ID */
  sftp_session_set_id(h, hlen);

  /* Sign H with our hostkey */
  hsig = sftp_keys_sign_data(pkt->pool, kex->use_hostkey_type, h, hlen,
    &hsiglen);
  if (hsig == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION, "error signing H");
    pr_memscrub((char *) hostkey_data, hostkey_datalen);
    BN_clear_free(kex->k);
    kex->k = NULL;
    return -1;
  }

  /* XXX Is this large enough?  Too large? */
  buflen = bufsz = 8192;
  ptr = buf = palloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEX_DH_REPLY);
  sftp_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen, TRUE);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  DH_get0_key(kex->dh, &dh_pub_key, NULL);
#else
  dh_pub_key = kex->dh->pub_key;
#endif /* prior to OpenSSL-1.1.0 */
  sftp_msg_write_mpint(&buf, &buflen, dh_pub_key);

  sftp_msg_write_data(&buf, &buflen, hsig, hsiglen, TRUE);

  /* Scrub any sensitive data when done */
  pr_memscrub((char *) hostkey_data, hostkey_datalen);
  pr_memscrub((char *) hsig, hsiglen);

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  return 0;
}

static int write_newkeys_reply(struct ssh2_packet *pkt) {
  unsigned char *buf, *ptr;
  uint32_t bufsz, buflen;

  /* Write out the NEWKEYS message. */
  bufsz = buflen = 1;
  ptr = buf = palloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_NEWKEYS);

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  return 0;
}

static int handle_kex_dh(struct ssh2_packet *pkt, struct sftp_kex *kex) {
  int res;
  cmd_rec *cmd;

  cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, "DH_INIT"));
  cmd->arg = "(data)";
  cmd->cmd_class = CL_AUTH|CL_SSH;

  pr_trace_msg(trace_channel, 9, "reading DH_INIT message from client");

  res = read_dh_init(pkt, kex);
  if (res < 0) {
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  destroy_pool(pkt->pool);

  pr_trace_msg(trace_channel, 9, "writing DH_INIT message to client");

  /* Send our key exchange reply. */
  pkt = sftp_ssh2_packet_create(kex_pool);
  res = write_dh_reply(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);
  return 0;
}

static int read_dh_gex(struct ssh2_packet *pkt, uint32_t *min, uint32_t *pref,
    uint32_t *max, int old_request) {
  unsigned char *buf;
  uint32_t buflen;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  if (!old_request) {
    *min = sftp_msg_read_int(pkt->pool, &buf, &buflen);
    if (*min < SFTP_KEX_DH_GROUP_MIN) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "DH_GEX_REQUEST min value (%lu) too small (< %lu)",
        (unsigned long) *min, (unsigned long) SFTP_KEX_DH_GROUP_MIN);
      return -1;
    }

    *pref = sftp_msg_read_int(pkt->pool, &buf, &buflen);

    *max = sftp_msg_read_int(pkt->pool, &buf, &buflen);
    if (*max > SFTP_KEX_DH_GROUP_MAX) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "DH_GEX_REQUEST max value (%lu) too large (> %lu)",
        (unsigned long) *max, (unsigned long) SFTP_KEX_DH_GROUP_MAX);
      return -1;
    }

  } else {
    *min = SFTP_KEX_DH_GROUP_MIN;
    *pref = sftp_msg_read_int(pkt->pool, &buf, &buflen);
    *max = SFTP_KEX_DH_GROUP_MAX;
  }

  if (*max < *min ||
      *pref < *min ||
      *pref > *max) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "bad DH_GEX_REQUEST parameters: min = %lu, pref = %lu, max = %lu",
      (unsigned long) *min, (unsigned long) *pref, (unsigned long) *max);
    return -1;
  }

  return 0;
}

static int get_dh_gex_group(struct sftp_kex *kex, uint32_t min,
    uint32_t pref, uint32_t max) {
  const char *dhparam_path;
  config_rec *c;
  int use_fixed_modulus = FALSE;

  dhparam_path = PR_CONFIG_DIR "/dhparams.pem";
  c = find_config(main_server->conf, CONF_PARAM, "SFTPDHParamFile", FALSE);
  if (c != NULL) {
    dhparam_path = c->argv[0];
  }

  /* If the preferred DH is less than SFTP_DH_MIN_LEN, AND the AllowWeakDH
   * SFTPOption is not used, then use a pref of SFTP_DH_MIN_LEN (Bug#4184).
   */
  if (pref < SFTP_DH_MIN_LEN) {
    if (!(sftp_opts & SFTP_OPT_ALLOW_WEAK_DH)) {
      pref = SFTP_DH_MIN_LEN;

    } else {
      pr_trace_msg(trace_channel, 14,
       "client prefers relatively weak DH group size (%lu) but AllowWeakDH "
       "SFTPOption in effect", (unsigned long) pref);
    }
  }

  if (dhparam_path) {
    if (kex_dhparams_fp != NULL) {
      /* Rewind to the start of the file. */
      fseek(kex_dhparams_fp, 0, SEEK_SET);

    } else {
      kex_dhparams_fp = fopen(dhparam_path, "r");
    }

    if (kex_dhparams_fp) {
      register unsigned int i;
      pool *tmp_pool;
      array_header *smaller_dhs, *pref_dhs, *larger_dhs;
      DH *chosen_dh, **dhs;
      uint32_t smaller_dh_nbits = 0, larger_dh_nbits = 0;

      pr_trace_msg(trace_channel, 15,
        "using DH parameters from SFTPDHParamFile '%s' for group exchange",
        dhparam_path);

      tmp_pool = make_sub_pool(kex->pool);
      pr_pool_tag(tmp_pool, "Kex DHparams selection pool");

      smaller_dhs = make_array(tmp_pool, 1, sizeof(DH *)); 
      pref_dhs = make_array(tmp_pool, 1, sizeof(DH *)); 
      larger_dhs = make_array(tmp_pool, 1, sizeof(DH *)); 

      /* From Section 3 of RFC4419:
       *
       *  "The server should return the smallest group it knows that is larger
       *   than the size the client requested.  If the server does not know a
       *   group that is larger than the client request, then it SHOULD return
       *   the largest group it knows.  In all cases, the size of the returned
       *   group SHOULD be at least 1024 bits."
       *
       * Make lists of DHs in the param file whose size falls within the
       * bit lengths requested by the client.  Note that DH_size() returns
       * the sizes _in bytes_, not bits.  We have three lists: one for DHs
       * which match the client-requested preferred size, one for DHs which
       * are smaller than the preferred size, and one for DHs which are larger
       * than the preferred size.  DHs in these last two lists will be of the
       * same size.  Once the lists are populated, we will randomly choose one
       * from the preferred DH list (if available), else one from the larger
       * DH list (if available), else one from the smaller DH list.
       */

      while (TRUE) {
        uint32_t nbits;

        pr_signals_handle();

        chosen_dh = PEM_read_DHparams(kex_dhparams_fp, NULL, NULL, NULL);
        if (chosen_dh == NULL) {
          if (!feof(kex_dhparams_fp)) {
            pr_trace_msg(trace_channel, 5, "error reading DH params from "
              "SFTPDHParamFile '%s': %s", dhparam_path,
              sftp_crypto_get_errors());
          }

          break;
        }

        nbits = DH_size(chosen_dh) * 8;

        if (nbits < min ||
            nbits > max) {
          pr_trace_msg(trace_channel, 17,
            "skipping %lu-bit DH from %s (exceeds min %lu, max %lu bits)",
            (unsigned long) nbits, dhparam_path, (unsigned long) min,
            (unsigned long) max);
          DH_free(chosen_dh);
          continue;
        }

        if (nbits == pref) {
          *((DH **) push_array(pref_dhs)) = chosen_dh;

        } else if (nbits < pref) {
          if (nbits > smaller_dh_nbits) {
            if (smaller_dhs->nelts > 0) {
              dhs = smaller_dhs->elts;
              for (i = 0; i < smaller_dhs->nelts; i++) {
                DH_free(dhs[i]);
              }

              clear_array(smaller_dhs);
            }

            smaller_dh_nbits = nbits;
            *((DH **) push_array(smaller_dhs)) = chosen_dh;

          } else if (nbits == smaller_dh_nbits) {
            *((DH **) push_array(smaller_dhs)) = chosen_dh;

          } else {
            DH_free(chosen_dh);
          }

        } else {
          /* By process of elimination, nbits here MUST be > pref. */

          if (nbits < larger_dh_nbits) {
            if (larger_dhs->nelts > 0) {
              dhs = larger_dhs->elts;
              for (i = 0; i < larger_dhs->nelts; i++) {
                DH_free(dhs[i]);
              }

              clear_array(larger_dhs);
            }

            larger_dh_nbits = nbits;
            *((DH **) push_array(larger_dhs)) = chosen_dh;

          } else if (nbits == larger_dh_nbits) {
            *((DH **) push_array(larger_dhs)) = chosen_dh;

          } else {
            DH_free(chosen_dh);
          }
        }
      }

      chosen_dh = NULL;

      /* The use of rand(3) below is NOT intended to be perfect, or even
       * uniformly distributed.  It simply needs to be good enough to pick
       * a single item from a small list, where all items are equally
       * usable and valid.
       *
       * Ideally we want to find a preferred DH first.  Failing that, a larger
       * DH is better; if none found there, then we settle for a smaller DH.
       */

      if (pref_dhs->nelts > 0) {
        int r = (int) (rand() / (RAND_MAX / pref_dhs->nelts + 1));

        pr_trace_msg(trace_channel, 17,
          "%s DH selection: preferred DHs (count %u, idx %d)", dhparam_path,
          pref_dhs->nelts, r);
        dhs = pref_dhs->elts;
        chosen_dh = dhs[r];

      } else if (larger_dhs->nelts > 0) {
        int r = (int) (rand() / (RAND_MAX / larger_dhs->nelts + 1));

        pr_trace_msg(trace_channel, 17,
          "%s DH selection: larger DHs (count %u, idx %d)", dhparam_path,
          larger_dhs->nelts, r);
        dhs = larger_dhs->elts;
        chosen_dh = dhs[r];

      } else if (smaller_dhs->nelts > 0) {
        int r = (int) (rand() / (RAND_MAX / smaller_dhs->nelts + 1));

        pr_trace_msg(trace_channel, 17,
          "%s DH selection: smaller DHs (count %u, idx %d)", dhparam_path,
          smaller_dhs->nelts, r);
        dhs = smaller_dhs->elts;
        chosen_dh = dhs[r];

      } else {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "unable to find suitable DH in SFTPDHParamFile '%s' for %lu-%lu "
          "bit sizes", dhparam_path, (unsigned long) min, (unsigned long) max);
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "WARNING: using fixed modulus for DH group exchange");
        use_fixed_modulus = TRUE;
      }

      if (chosen_dh != NULL) {
        BIGNUM *dh_p = NULL, *dh_g = NULL, *dup_p, *dup_g;

        pr_trace_msg(trace_channel, 20, "client requested min %lu, pref %lu, "
          "max %lu sizes for DH group exchange, selected DH of %lu bits",
          (unsigned long) min, (unsigned long) pref, (unsigned long) max,
          (unsigned long) DH_size(chosen_dh) * 8);

        /* Get the P, G parameters of the chosen DH group, and make copies
         * of them for our KEX DH.
         */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
        DH_get0_pqg(chosen_dh, &dh_p, NULL, &dh_g);
#else
        dh_p = chosen_dh->p;
        dh_g = chosen_dh->g;
#endif /* prior to OpenSSL-1.1.0 */

        dup_p = BN_dup(dh_p);
        if (dup_p == NULL) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error copying selected DH P: %s", sftp_crypto_get_errors());
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "WARNING: using fixed modulus for DH group exchange");
          use_fixed_modulus = TRUE;

        } else {
          dup_g = BN_dup(dh_g);
          if (dup_g == NULL) {
            (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
              "error copying selected DH G: %s", sftp_crypto_get_errors());
            (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
              "WARNING: using fixed modulus for DH group exchange");
            BN_clear_free(dup_p);
            use_fixed_modulus = TRUE;

          } else {
            /* Now set those P, G copies into our KEX DH. */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
            DH_set0_pqg(kex->dh, dup_p, NULL, dup_g);
#else
            kex->dh->p = dup_p;
            kex->dh->g = dup_g;
#endif /* prior to OpenSSL-1.1.0 */
          }
        }
      }

      /* Don't forget to clean up all of the allocated DHs. */
      dhs = (DH **) smaller_dhs->elts;
      for (i = 0; i < smaller_dhs->nelts; i++) {
        pr_signals_handle();
        DH_free(dhs[i]);
      }

      dhs = (DH **) pref_dhs->elts;
      for (i = 0; i < pref_dhs->nelts; i++) {
        pr_signals_handle();
        DH_free(dhs[i]);
      }

      dhs = (DH **) larger_dhs->elts;
      for (i = 0; i < larger_dhs->nelts; i++) {
        pr_signals_handle();
        DH_free(dhs[i]);
      }

      destroy_pool(tmp_pool);

    } else {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "WARNING: unable to read SFTPDHParamFile '%s': %s", dhparam_path,
        strerror(errno));
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "WARNING: using fixed modulus for DH group exchange");
      use_fixed_modulus = TRUE;
    }
  }

  if (use_fixed_modulus) {
    BIGNUM *dh_p, *dh_g;

    dh_p = BN_new();

    /* Note: Consider using a stronger fixed DH group here! */
    if (BN_hex2bn(&dh_p, dh_group14_str) == 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error setting DH P: %s", sftp_crypto_get_errors());
      BN_clear_free(dh_p);
      errno = EACCES;
      return -1;
    }

    dh_g = BN_new();
    if (BN_hex2bn(&dh_g, "2") == 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error setting DH G: %s", sftp_crypto_get_errors());
      BN_clear_free(dh_p);
      BN_clear_free(dh_g);
      errno = EACCES;
      return -1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
    DH_set0_pqg(kex->dh, dh_p, NULL, dh_g);
#else
    kex->dh->p = dh_p;
    kex->dh->g = dh_g;
#endif /* prior to OpenSSL-1.1.0 */
  }

  return 0;
}

static int write_dh_gex_group(struct ssh2_packet *pkt, struct sftp_kex *kex,
    uint32_t min, uint32_t pref, uint32_t max) {
  BIGNUM *dh_p = NULL, *dh_g = NULL;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;

  if (get_dh_gex_group(kex, min, pref, max) < 0) {
    return -1;
  }

  /* XXX Is this large enough?  Too large? */
  buflen = bufsz = 4096;
  ptr = buf = palloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEX_DH_GEX_GROUP);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  DH_get0_pqg(kex->dh, &dh_p, NULL, &dh_g);
#else
  dh_p = kex->dh->p;
  dh_g = kex->dh->g;
#endif /* prior to OpenSSL-1.1.0 */
  sftp_msg_write_mpint(&buf, &buflen, dh_p);
  sftp_msg_write_mpint(&buf, &buflen, dh_g);

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  return 0;
}

static int read_dh_gex_init(struct ssh2_packet *pkt, struct sftp_kex *kex) {
  unsigned char *buf;
  uint32_t buflen;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  /* Read in 'e' */
  kex->e = sftp_msg_read_mpint(pkt->pool, &buf, &buflen);
  if (kex->e == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading DH_GEX_INIT: %s", strerror(errno));
    return -1;
  }

  return 0;
}

static int write_dh_gex_reply(struct ssh2_packet *pkt, struct sftp_kex *kex,
    uint32_t min, uint32_t pref, uint32_t max, int old_request) {
  const unsigned char *h, *hostkey_data, *hsig;
  unsigned char *buf, *ptr;
  uint32_t bufsz, buflen, hlen = 0, hostkey_datalen = 0;
  size_t dhlen, hsiglen = 0;
  BIGNUM *k = NULL, *dh_pub_key = NULL;
  int res;

  /* Compute the shared secret. */
  dhlen = DH_size(kex->dh);
  buf = palloc(kex_pool, dhlen);

  pr_trace_msg(trace_channel, 12, "computing DH key");
  res = DH_compute_key(buf, kex->e, kex->dh);
  if (res < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error computing DH shared secret: %s", sftp_crypto_get_errors());
    return -1;
  }

  k = BN_new();
  if (BN_bin2bn(buf, res, k) == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error converting DH shared secret to BN: %s", sftp_crypto_get_errors());

    pr_memscrub(buf, res);
    BN_clear_free(k);
    return -1;
  }

  pr_memscrub(buf, res);
  kex->k = k;

  /* Get the hostkey data; it will be part of the data we hash in order
   * to create the session key.
   */
  hostkey_data = sftp_keys_get_hostkey_data(pkt->pool, kex->use_hostkey_type,
    &hostkey_datalen);
  if (hostkey_data == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error converting hostkey for signing: %s", strerror(errno));

    BN_clear_free(kex->k);
    kex->k = NULL;
    return -1;
  }

  if (old_request) {
    max = min = 0;
  }

  /* Calculate H */
  h = calculate_gex_h(kex, hostkey_data, hostkey_datalen, k, min, pref, max,
    &hlen);
  if (h == NULL) {
    pr_memscrub((char *) hostkey_data, hostkey_datalen);
    BN_clear_free(kex->k);
    kex->k = NULL;
    return -1;
  } 

  kex->h = palloc(pkt->pool, hlen);
  kex->hlen = hlen;
  memcpy((char *) kex->h, h, kex->hlen);

  /* Save H as the session ID */
  sftp_session_set_id(h, hlen);

  /* Sign H with our hostkey */
  hsig = sftp_keys_sign_data(pkt->pool, kex->use_hostkey_type, h, hlen,
    &hsiglen);
  if (hsig == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION, "error signing H");
    pr_memscrub((char *) hostkey_data, hostkey_datalen);
    BN_clear_free(kex->k);
    kex->k = NULL;
    return -1;
  }

  /* XXX Is this large enough?  Too large? */
  buflen = bufsz = 8192;
  ptr = buf = palloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEX_DH_GEX_REPLY);
  sftp_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen, TRUE);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  DH_get0_key(kex->dh, &dh_pub_key, NULL);
#else
  dh_pub_key = kex->dh->pub_key;
#endif /* prior to OpenSSL-1.1.0 */
  sftp_msg_write_mpint(&buf, &buflen, dh_pub_key);

  sftp_msg_write_data(&buf, &buflen, hsig, hsiglen, TRUE);

  /* Scrub any sensitive data when done */
  pr_memscrub((char *) hostkey_data, hostkey_datalen);
  pr_memscrub((char *) hsig, hsiglen);

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  return 0;
}

static int handle_kex_dh_gex(struct ssh2_packet *pkt, struct sftp_kex *kex,
    int old_request) {
  int res;
  uint32_t min = 0, pref = 0, max = 0;
  cmd_rec *cmd;

  if (!old_request) {
    pr_trace_msg(trace_channel, 9,
      "reading DH_GEX_REQUEST message from client");

    cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, "DH_GEX_REQUEST"));
    cmd->arg = "(data)";
    cmd->cmd_class = CL_AUTH|CL_SSH;

  } else {
    pr_trace_msg(trace_channel, 9,
      "reading DH_GEX_REQUEST_OLD message from client");

    cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, "DH_GEX_REQUEST_OLD"));
    cmd->arg = "(data)";
    cmd->cmd_class = CL_AUTH|CL_SSH;
  }

  res = read_dh_gex(pkt, &min, &pref, &max, old_request);
  if (res < 0) {
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  destroy_pool(pkt->pool);

  pkt = sftp_ssh2_packet_create(kex_pool);
  res = write_dh_gex_group(pkt, kex, min, pref, max);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  pr_trace_msg(trace_channel, 9, "writing DH_GEX_GROUP message to client");

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);

  pkt = read_kex_packet(kex_pool, kex, SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
    NULL, 1, SFTP_SSH2_MSG_KEX_DH_GEX_INIT);

  cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, "DH_GEX_INIT"));
  cmd->arg = "(data)";
  cmd->cmd_class = CL_AUTH|CL_SSH;

  pr_trace_msg(trace_channel, 9, "reading DH_GEX_INIT message from client");

  res = read_dh_gex_init(pkt, kex);
  if (res < 0) {
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

    destroy_pool(pkt->pool);
    return -1;
  }

  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  destroy_pool(pkt->pool);

  if (finish_dh(kex) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error finishing DH key for group exchange: %s", strerror(errno));
    return -1;
  }

  pkt = sftp_ssh2_packet_create(kex_pool);
  res = write_dh_gex_reply(pkt, kex, min, pref, max, old_request);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  pr_trace_msg(trace_channel, 9, "writing DH_GEX_REPLY message to client");

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);
  return 0;
}

static int read_kexrsa_secret(struct ssh2_packet *pkt, struct sftp_kex *kex) {
  unsigned char *buf, *encrypted, *decrypted;
  uint32_t buflen, encrypted_len;
  BIGNUM *k = NULL;
  int res;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  encrypted_len = sftp_msg_read_int(pkt->pool, &buf, &buflen);
  encrypted = (unsigned char *) sftp_msg_read_data(pkt->pool, &buf, &buflen,
    encrypted_len);

  /* Save the encrypted secret for calculating H. */
  kex->rsa_encrypted_len = encrypted_len;
  kex->rsa_encrypted = palloc(kex_pool, encrypted_len);
  memcpy(kex->rsa_encrypted, encrypted, encrypted_len);

  pr_trace_msg(trace_channel, 12, "decrypting RSA shared secret");

  decrypted = palloc(pkt->pool, RSA_size(kex->rsa));

  res = RSA_private_decrypt((int) encrypted_len, encrypted, decrypted,
    kex->rsa, RSA_PKCS1_OAEP_PADDING);
  if (res == -1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error decrypting RSA shared secret: %s", sftp_crypto_get_errors());
    RSA_free(kex->rsa);
    kex->rsa = NULL;
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  /* When converting the decrypted secret into an mpint, watch out for any
   * leading padding (as required per SSH RFCs).
   */

  k = BN_new();
  if (BN_mpi2bn(decrypted, res, k) == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error converting RSA shared secret to BN: %s", sftp_crypto_get_errors());

    pr_memscrub(decrypted, res);
    RSA_free(kex->rsa);
    kex->rsa = NULL;
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  pr_memscrub(decrypted, res);

  kex->k = k;
  return 0;
}

static int write_kexrsa_pubkey(struct ssh2_packet *pkt, struct sftp_kex *kex) {
  BIGNUM *rsa_n = NULL, *rsa_e = NULL;
  unsigned char *buf, *ptr, *buf2, *ptr2;
  const unsigned char *hostkey_data;
  uint32_t buflen, bufsz, buflen2, bufsz2, hostkey_datalen;

  hostkey_data = sftp_keys_get_hostkey_data(pkt->pool, kex->use_hostkey_type,
    &hostkey_datalen);
  if (hostkey_data == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error obtaining hostkey for KEXRSA key exchange: %s", strerror(errno));
    RSA_free(kex->rsa);
    kex->rsa = NULL;
    return -1;
  }

  /* XXX Is this buffer large enough?  Too large? */
  bufsz = buflen = 2048;
  ptr = buf = palloc(kex_pool, bufsz);

  /* Write the transient RSA public key into its own buffer, to then be
   * written in its entirety as an SSH2 string.
   */
  sftp_msg_write_string(&buf, &buflen, "ssh-rsa");

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  RSA_get0_key(kex->rsa, &rsa_n, &rsa_e, NULL);
#else
  rsa_e = kex->rsa->e;
  rsa_n = kex->rsa->n;
#endif /* prior to OpenSSL-1.1.0 */
  sftp_msg_write_mpint(&buf, &buflen, rsa_e);
  sftp_msg_write_mpint(&buf, &buflen, rsa_n);

  /* XXX Is this buffer large enough?  Too large? */
  bufsz2 = buflen2 = 4096;
  ptr2 = buf2 = palloc(pkt->pool, bufsz2);

  sftp_msg_write_byte(&buf2, &buflen2, SFTP_SSH2_MSG_KEXRSA_PUBKEY);
  sftp_msg_write_data(&buf2, &buflen2, hostkey_data, hostkey_datalen, TRUE);
  sftp_msg_write_data(&buf2, &buflen2, ptr, (bufsz - buflen), TRUE);

  pr_memscrub((char *) hostkey_data, hostkey_datalen);

  pkt->payload = ptr2;
  pkt->payload_len = (bufsz2 - buflen2);

  return 0;
}

static int write_kexrsa_done(struct ssh2_packet *pkt, struct sftp_kex *kex) {
  BIGNUM *rsa_e = NULL, *rsa_n = NULL;
  unsigned char *buf, *ptr, *buf2, *ptr2;
  const unsigned char *h, *hostkey_data, *hsig;
  uint32_t buflen, bufsz, buflen2, bufsz2, hlen, hostkey_datalen = 0;
  size_t hsiglen;

  hostkey_data = sftp_keys_get_hostkey_data(pkt->pool, kex->use_hostkey_type,
    &hostkey_datalen);
  if (hostkey_data == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error obtaining hostkey for KEXRSA key exchange: %s", strerror(errno));

    RSA_free(kex->rsa);
    kex->rsa = NULL;
    BN_clear_free(kex->k);
    kex->k = NULL;
    pr_memscrub(kex->rsa_encrypted, kex->rsa_encrypted_len);
    kex->rsa_encrypted = NULL;
    kex->rsa_encrypted_len = 0;

    return -1;
  }

  /* XXX Is this buffer large enough?  Too large? */
  bufsz2 = buflen2 = 4096;
  ptr2 = buf2 = palloc(kex_pool, bufsz2);

  /* Write the transient RSA public key into its own buffer, to then be
   * written in its entirety as an SSH2 string.
   */
  sftp_msg_write_string(&buf2, &buflen2, "ssh-rsa");

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && \
    !defined(HAVE_LIBRESSL)
  RSA_get0_key(kex->rsa, &rsa_n, &rsa_e, NULL);
#else
  rsa_e = kex->rsa->e;
  rsa_n = kex->rsa->n;
#endif /* prior to OpenSSL-1.1.0 */
  sftp_msg_write_mpint(&buf2, &buflen2, rsa_e);
  sftp_msg_write_mpint(&buf2, &buflen2, rsa_n);

  /* Calculate H */
  h = calculate_kexrsa_h(kex, hostkey_data, hostkey_datalen, kex->k,
    ptr2, (bufsz2 - buflen2), &hlen);
  if (h == NULL) {
    pr_memscrub((char *) hostkey_data, hostkey_datalen);
    RSA_free(kex->rsa);
    kex->rsa = NULL;
    BN_clear_free(kex->k);
    kex->k = NULL;
    pr_memscrub(kex->rsa_encrypted, kex->rsa_encrypted_len);
    kex->rsa_encrypted = NULL;
    kex->rsa_encrypted_len = 0;

    return -1;
  } 

  kex->h = palloc(pkt->pool, hlen);
  kex->hlen = hlen;
  memcpy((char *) kex->h, h, kex->hlen);

  /* Save H as the session ID */
  sftp_session_set_id(h, hlen);

  /* Sign H with our host key */
  hsig = sftp_keys_sign_data(pkt->pool, kex->use_hostkey_type, h, hlen,
    &hsiglen);
  if (hsig == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION, "error signing H");

    pr_memscrub((char *) hostkey_data, hostkey_datalen);
    RSA_free(kex->rsa);
    kex->rsa = NULL;
    BN_clear_free(kex->k);
    kex->k = NULL;
    pr_memscrub(kex->rsa_encrypted, kex->rsa_encrypted_len);
    kex->rsa_encrypted = NULL;
    kex->rsa_encrypted_len = 0;

    return -1;
  }

  /* XXX Is this buffer large enough?  Too large? */
  bufsz = buflen = 4096;
  ptr = buf = palloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEXRSA_DONE);
  sftp_msg_write_data(&buf, &buflen, hsig, hsiglen, TRUE);

  pr_memscrub((char *) hostkey_data, hostkey_datalen);
  pr_memscrub((char *) h, hlen);
  pr_memscrub((char *) hsig, hsiglen);

  pr_memscrub(kex->rsa_encrypted, kex->rsa_encrypted_len);
  kex->rsa_encrypted = NULL;
  kex->rsa_encrypted_len = 0;

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  return 0;
}

static int handle_kex_rsa(struct sftp_kex *kex) {
  struct ssh2_packet *pkt;
  int res;
  cmd_rec *cmd;

  pkt = sftp_ssh2_packet_create(kex_pool);
  res = write_kexrsa_pubkey(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  pr_trace_msg(trace_channel, 9, "writing KEXRSA_PUBKEY message to client");

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);

  pkt = read_kex_packet(kex_pool, kex, SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
    NULL, 1, SFTP_SSH2_MSG_KEXRSA_SECRET);

  cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, "KEXRSA_SECRET"));
  cmd->arg = "(data)";
  cmd->cmd_class = CL_AUTH|CL_SSH;

  pr_trace_msg(trace_channel, 9, "reading KEXRSA_SECRET message from client");

  res = read_kexrsa_secret(pkt, kex);
  if (res < 0) {
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  destroy_pool(pkt->pool);

  pkt = sftp_ssh2_packet_create(kex_pool);
  res = write_kexrsa_done(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  pr_trace_msg(trace_channel, 9, "writing KEXRSA_DONE message to client");

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);
  return 0;
}

#if defined(PR_USE_SODIUM) && defined(HAVE_SHA256_OPENSSL)
static int generate_curve25519_keys(unsigned char *priv_key,
    unsigned char *pub_key) {
  static const unsigned char basepoint[CURVE25519_SIZE] = {9};
  unsigned char zero_curve25519[CURVE25519_SIZE];
  int res;

  randombytes_buf(priv_key, CURVE25519_SIZE);
  res = crypto_scalarmult_curve25519(pub_key, priv_key, basepoint);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3,
      "error performing Curve25519 scalar multiplication");
    errno = EINVAL;
    return -1;
  }

  /* Check for all-zero public keys. */
  sodium_memzero(zero_curve25519, CURVE25519_SIZE);
  if (sodium_memcmp(pub_key, zero_curve25519, CURVE25519_SIZE) == 0) {
    pr_trace_msg(trace_channel, 12,
      "generated all-zero Curve25519 public key, trying again");
    return generate_curve25519_keys(priv_key, pub_key);
  }

  return 0;
}

static int read_curve25519_init(struct ssh2_packet *pkt, struct sftp_kex *kex) {
  unsigned char zero_curve25519[CURVE25519_SIZE];
  unsigned char *client_curve25519;
  unsigned char *buf;
  uint32_t buflen, data_len;
  char *data;

  buf = pkt->payload;
  buflen = data_len = pkt->payload_len;

  data = sftp_msg_read_string(pkt->pool, &buf, &buflen);

  /* The "string" we read MIGHT contain NULs, thus using strlen(3) to determine
   * the length of data is a Bad Idea (Issue #556).  Thus instead, we track
   * the packet payload length remaining after the read; the data length is
   * the difference, including the length value prefix of 4 bytes.
   */
  data_len -= (buflen + sizeof(uint32_t));

  if (data_len != CURVE25519_SIZE) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "rejecting invalid length (%lu %s, wanted %d) client Curve25519 key",
      (unsigned long) data_len, data_len != 1 ? "bytes" : "byte",
      CURVE25519_SIZE);
    errno = EINVAL;
    return -1;
  }

  client_curve25519 = (unsigned char *) data;

  /* Watch for all-zero public keys, and reject them. */
  sodium_memzero(zero_curve25519, CURVE25519_SIZE);
  if (sodium_memcmp(client_curve25519, zero_curve25519, CURVE25519_SIZE) == 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "rejecting invalid (all-zero) client Curve25519 key");
    errno = EINVAL;
    return -1;
  }

  kex->client_curve25519 = client_curve25519;
  return 0;
}

static int get_curve25519_shared_key(unsigned char *shared_key,
    unsigned char *client_curve25519, unsigned char *server_key) {
  int res;

  res = crypto_scalarmult_curve25519(shared_key, server_key, client_curve25519);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3,
      "error performing Curve25519 scalar multiplication");
    errno = EINVAL;
    return -1;
  }

  return CURVE25519_SIZE;
}

static const unsigned char *calculate_curve25519_h(struct sftp_kex *kex,
    const unsigned char *hostkey_data, uint32_t hostkey_datalen,
    const BIGNUM *k, unsigned char *client_curve25519,
    unsigned char *server_curve25519, uint32_t *hlen) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  EVP_MD_CTX ctx;
#endif /* prior to OpenSSL-1.1.0 */
  EVP_MD_CTX *pctx;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;

  bufsz = buflen = 4096;

  /* XXX Is this buffer large enough? Too large? */
  ptr = buf = sftp_msg_getbuf(kex_pool, bufsz);

  /* Write all of the data into the buffer in the SSH2 format, and hash it.
   * The ordering of these fields is described in RFC5656.
   */

  /* First, the version strings */
  sftp_msg_write_string(&buf, &buflen, kex->client_version);
  sftp_msg_write_string(&buf, &buflen, kex->server_version);

  /* Client's KEXINIT */
  sftp_msg_write_int(&buf, &buflen, kex->client_kexinit_payload_len + 1);
  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEXINIT);
  sftp_msg_write_data(&buf, &buflen, kex->client_kexinit_payload,
    kex->client_kexinit_payload_len, FALSE);

  /* Server's KEXINIT */
  sftp_msg_write_int(&buf, &buflen, kex->server_kexinit_payload_len + 1);
  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEXINIT);
  sftp_msg_write_data(&buf, &buflen, kex->server_kexinit_payload,
    kex->server_kexinit_payload_len, FALSE);

  /* Hostkey data */
  sftp_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen, TRUE);

  /* Client's key */
  sftp_msg_write_data(&buf, &buflen, client_curve25519, CURVE25519_SIZE, TRUE);

  /* Server's key */
  sftp_msg_write_data(&buf, &buflen, server_curve25519, CURVE25519_SIZE, TRUE);

  /* Shared secret */
  sftp_msg_write_mpint(&buf, &buflen, k);

#if OPENSSL_VERSION_NUMBER >= 0x10100000LL
    pctx = EVP_MD_CTX_new();
#else
    pctx = &ctx;
#endif /* OpenSSL-1.1.0 and later */

  /* In OpenSSL 0.9.6, many of the EVP_Digest* functions returned void, not
   * int.  Without these ugly OpenSSL version preprocessor checks, the
   * compiler will error out with "void value not ignored as it ought to be".
   */

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestInit(pctx, kex->hash) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error initializing message digest: %s", sftp_crypto_get_errors());
    BN_clear_free(kex->e);
    kex->e = NULL;
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestInit(pctx, kex->hash);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestUpdate(pctx, ptr, (bufsz - buflen)) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error updating message digest: %s", sftp_crypto_get_errors());
    BN_clear_free(kex->e);
    kex->e = NULL;
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestUpdate(pctx, ptr, (bufsz - buflen));
#endif

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestFinal(pctx, kex_digest_buf, hlen) != 1) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error finalizing message digest: %s", sftp_crypto_get_errors());
    BN_clear_free(kex->e);
    kex->e = NULL;
    pr_memscrub(ptr, bufsz);
# if OPENSSL_VERSION_NUMBER >= 0x10100000LL
    EVP_MD_CTX_free(pctx);
# endif /* OpenSSL-1.1.0 and later */
    return NULL;
  }
#else
  EVP_DigestFinal(pctx, kex_digest_buf, hlen);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000LL
  EVP_MD_CTX_free(pctx);
#endif /* OpenSSL-1.1.0 and later */
  BN_clear_free(kex->e);
  kex->e = NULL;
  pr_memscrub(ptr, bufsz);

  return kex_digest_buf;
}

static int write_curve25519_reply(struct ssh2_packet *pkt,
    struct sftp_kex *kex) {
  const unsigned char *h, *hostkey_data, *hsig;
  unsigned char *buf, *ptr;
  unsigned char server_curve25519[CURVE25519_SIZE];
  unsigned char server_key[CURVE25519_SIZE];
  uint32_t bufsz, buflen, hlen = 0, hostkey_datalen = 0;
  size_t hsiglen;
  BIGNUM *k = NULL;
  int res;

  if (generate_curve25519_keys(server_key, server_curve25519) < 0) {
    return -1;
  }

  /* Compute the shared secret. */
  buf = palloc(kex_pool, CURVE25519_SIZE);

  pr_trace_msg(trace_channel, 12, "computing Curve25519 key");
  res = get_curve25519_shared_key((unsigned char *) buf, kex->client_curve25519,
    server_key);
  if (res < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error computing Curve25519 shared secret: %s", strerror(errno));
    return -1;
  }

  k = BN_new();
  if (k == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error allocating new BIGNUM: %s", sftp_crypto_get_errors());
    pr_memscrub(buf, res);
    return -1;
  }

  if (BN_bin2bn((unsigned char *) buf, res, k) == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error converting Curve25519 shared secret to BN: %s",
      sftp_crypto_get_errors());
    pr_memscrub(buf, res);
    return -1;
  }

  pr_memscrub(buf, res);
  kex->k = k;

  /* Get the hostkey data; it will be part of the data we hash in order
   * to create the session key.
   */
  hostkey_data = sftp_keys_get_hostkey_data(pkt->pool, kex->use_hostkey_type,
    &hostkey_datalen);
  if (hostkey_data == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error converting hostkey for signing: %s", strerror(errno));

    BN_clear_free(kex->k);
    kex->k = NULL;
    return -1;
  }

  /* Calculate H */
  h = calculate_curve25519_h(kex, hostkey_data, hostkey_datalen, k,
    kex->client_curve25519, server_curve25519, &hlen);
  if (h == NULL) {
    pr_memscrub((char *) hostkey_data, hostkey_datalen);
    BN_clear_free(kex->k);
    kex->k = NULL;
    return -1;
  }

  kex->h = palloc(pkt->pool, hlen);
  kex->hlen = hlen;
  memcpy((char *) kex->h, h, kex->hlen);

  /* Save H as the session ID */
  sftp_session_set_id(h, hlen);

  /* Sign H with our hostkey */
  hsig = sftp_keys_sign_data(pkt->pool, kex->use_hostkey_type, h, hlen,
    &hsiglen);
  if (hsig == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION, "error signing H");
    pr_memscrub((char *) hostkey_data, hostkey_datalen);
    BN_clear_free(kex->k);
    kex->k = NULL;
    return -1;
  }

  /* XXX Is this large enough?  Too large? */
  buflen = bufsz = 4096;
  ptr = buf = palloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEX_ECDH_REPLY);
  sftp_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen, TRUE);
  sftp_msg_write_data(&buf, &buflen, server_curve25519, CURVE25519_SIZE, TRUE);
  sftp_msg_write_data(&buf, &buflen, hsig, hsiglen, TRUE);

  /* Scrub any sensitive data when done */
  pr_memscrub((char *) server_key, CURVE25519_SIZE);
  pr_memscrub((char *) hostkey_data, hostkey_datalen);
  pr_memscrub((char *) hsig, hsiglen);

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  return 0;
}

static int handle_kex_curve25519(struct ssh2_packet *pkt,
    struct sftp_kex *kex) {
  int res;
  cmd_rec *cmd;
  const char *req;

  req = "ECDH_INIT";
  cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, req));
  cmd->arg = "(data)";
  cmd->cmd_class = CL_AUTH|CL_SSH;

  pr_trace_msg(trace_channel, 9, "reading %s message from client", req);

  res = read_curve25519_init(pkt, kex);
  if (res < 0) {
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  destroy_pool(pkt->pool);

  /* Send our key exchange reply. */
  pkt = sftp_ssh2_packet_create(kex_pool);
  res = write_curve25519_reply(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  pr_trace_msg(trace_channel, 9, "writing %s message to client", req);

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);
  return 0;
}
#endif /* PR_USE_SODIUM and HAVE_SHA256_OPENSSL */

#ifdef PR_USE_OPENSSL_ECC
static int read_ecdh_init(struct ssh2_packet *pkt, struct sftp_kex *kex) {
  unsigned char *buf;
  uint32_t buflen;
  const EC_GROUP *curve;
  EC_POINT *point;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  curve = EC_KEY_get0_group(kex->ec);

  point = EC_POINT_new(curve);
  if (point == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error allocating EC_POINT: %s", sftp_crypto_get_errors());
    return -1;
  }

  /* Read in the client's EC point (i.e. their ECC "public key"). */
  kex->client_point = sftp_msg_read_ecpoint(pkt->pool, &buf, &buflen, curve,
    point);
  if (kex->client_point == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error reading ECDH_INIT: %s", strerror(errno));
    EC_POINT_clear_free(point);
    kex->client_point = NULL;
    return -1;
  }

  if (sftp_keys_validate_ecdsa_params(curve, kex->client_point) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "invalid client ECDH public key (EC point): %s", strerror(errno));
    EC_POINT_clear_free(kex->client_point);
    kex->client_point = NULL;
    return -1;
  }

  return 0;
}

static int write_ecdh_reply(struct ssh2_packet *pkt, struct sftp_kex *kex) {
  const unsigned char *h;
  const unsigned char *hostkey_data, *hsig;
  unsigned char *buf, *ptr;
  uint32_t bufsz, buflen, hlen = 0, hostkey_datalen = 0;
  size_t ecdhlen, hsiglen;
  BIGNUM *k = NULL;
  int res;

  /* Compute the shared secret */
  ecdhlen = ((EC_GROUP_get_degree(EC_KEY_get0_group(kex->ec)) + 7) / 8);
  buf = palloc(kex_pool, ecdhlen);

  pr_trace_msg(trace_channel, 12, "computing ECDH key");
  res = ECDH_compute_key((unsigned char *) buf, ecdhlen, kex->client_point,
    kex->ec, NULL);
  if (res <= 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error computing ECDH shared secret: %s", sftp_crypto_get_errors());
    return -1;
  }

  if ((size_t) res != ecdhlen) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "computed ECDH shared secret length (%d) does not match needed length "
      "(%lu), rejecting", res, (unsigned long) ecdhlen);
    return -1;
  }

  k = BN_new();
  if (k == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error allocating new BIGNUM: %s", sftp_crypto_get_errors());
    pr_memscrub(buf, res);
    return -1;
  }

  if (BN_bin2bn((unsigned char *) buf, res, k) == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error converting ECDH shared secret to BN: %s",
      sftp_crypto_get_errors());

    pr_memscrub(buf, res);
    return -1;
  }

  pr_memscrub(buf, res);
  kex->k = k;

  /* Get the hostkey data; it will be part of the data we hash in order
   * to create the session key.
   */
  hostkey_data = sftp_keys_get_hostkey_data(pkt->pool, kex->use_hostkey_type,
    &hostkey_datalen);
  if (hostkey_data == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error converting hostkey for signing: %s", strerror(errno));

    BN_clear_free(kex->k);
    kex->k = NULL;
    return -1;
  }

  /* Calculate H */
  h = calculate_ecdh_h(kex, hostkey_data, hostkey_datalen, k, &hlen);
  if (h == NULL) {
    pr_memscrub((char *) hostkey_data, hostkey_datalen);
    BN_clear_free(kex->k);
    kex->k = NULL;
    return -1;
  }

  kex->h = palloc(pkt->pool, hlen);
  kex->hlen = hlen;
  memcpy((char *) kex->h, h, kex->hlen);

  /* Save H as the session ID */
  sftp_session_set_id(h, hlen);

  /* Sign H with our hostkey */
  hsig = sftp_keys_sign_data(pkt->pool, kex->use_hostkey_type, h, hlen,
    &hsiglen);
  if (hsig == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION, "error signing H");
    pr_memscrub((char *) hostkey_data, hostkey_datalen);
    BN_clear_free(kex->k);
    kex->k = NULL;
    return -1;
  }

  /* XXX Is this large enough?  Too large? */
  buflen = bufsz = 4096;
  ptr = buf = palloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_KEX_ECDH_REPLY);
  sftp_msg_write_data(&buf, &buflen, hostkey_data, hostkey_datalen, TRUE);
  sftp_msg_write_ecpoint(&buf, &buflen, EC_KEY_get0_group(kex->ec),
    EC_KEY_get0_public_key(kex->ec));
  sftp_msg_write_data(&buf, &buflen, hsig, hsiglen, TRUE);

  /* Scrub any sensitive data when done */
  pr_memscrub((char *) hostkey_data, hostkey_datalen);
  pr_memscrub((char *) hsig, hsiglen);

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  return 0;
}

static int handle_kex_ecdh(struct ssh2_packet *pkt, struct sftp_kex *kex) {
  int res;
  cmd_rec *cmd;
  const char *req;

  req = "ECDH_INIT";
  cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, req));
  cmd->arg = "(data)";
  cmd->cmd_class = CL_AUTH|CL_SSH;

  pr_trace_msg(trace_channel, 9, "reading %s message from client", req);

  res = read_ecdh_init(pkt, kex);
  if (res < 0) {
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  destroy_pool(pkt->pool);

  /* Send our key exchange reply. */
  pkt = sftp_ssh2_packet_create(kex_pool);
  res = write_ecdh_reply(pkt, kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  /* Don't clean up the EC key in the kex struct until after we've
   * written out a reply.
   */
  if (finish_ecdh(kex) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error finishing ECDH key: %s", strerror(errno));
    destroy_pool(pkt->pool);
    return -1;
  }

  pr_trace_msg(trace_channel, 9, "writing %s message to client", req);

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);
  return 0;
}

#endif /* PR_USE_OPENSSL_ECC */

static struct ssh2_packet *read_kex_packet(pool *p, struct sftp_kex *kex,
    int disconn_code, char *found_mesg_type, unsigned int ntypes, ...) {
  register unsigned int i;
  va_list ap;
  struct ssh2_packet *pkt = NULL;
  array_header *allowed_types;

  pr_trace_msg(trace_channel, 9, "waiting for a message of %d %s from client",
    ntypes, ntypes != 1 ? "types" : "type");

  allowed_types = make_array(p, 1, sizeof(char));
 
  va_start(ap, ntypes);  

  while (ntypes-- > 0) {
    *((char *) push_array(allowed_types)) = va_arg(ap, int);
  }

  va_end(ap);

  /* Keep looping until we get the desired message, or we time out (hopefully
   * via TimeoutLogin or somesuch).
   */
  while (pkt == NULL) {
    int found = FALSE, res;
    char mesg_type;

    pr_signals_handle();

    pkt = sftp_ssh2_packet_create(p);
    res = sftp_ssh2_packet_read(sftp_conn->rfd, pkt);
    if (res < 0) {
      int xerrno = errno;

      destroy_kex(kex);
      destroy_pool(pkt->pool);

      errno = xerrno;
      return NULL;
    }

    pr_response_clear(&resp_list);
    pr_response_clear(&resp_err_list);
    pr_response_set_pool(pkt->pool);

    /* Per RFC 4253, Section 11, DEBUG, DISCONNECT, IGNORE, and UNIMPLEMENTED
     * messages can occur at any time, even during KEX.  We have to be prepared
     * for this, and Do The Right Thing(tm).
     */

    mesg_type = sftp_ssh2_packet_get_mesg_type(pkt);

    for (i = 0; i < allowed_types->nelts; i++) {
      if (mesg_type == ((unsigned char *) allowed_types->elts)[i]) {
        /* Exactly what we were looking for.  Excellent. */
        pr_trace_msg(trace_channel, 13,
          "received expected %s message",
          sftp_ssh2_packet_get_mesg_type_desc(mesg_type));

        if (found_mesg_type != NULL) {
          /* The caller wants to know the type of message we're returning;
           * packet_get_mesg_type() performs a destructive read.
           */
          *found_mesg_type = mesg_type;
        }

        found = TRUE;
        break;
      }
    }

    if (found == TRUE) {
      break;
    }

    switch (mesg_type) {
      case SFTP_SSH2_MSG_DEBUG:
        sftp_ssh2_packet_handle_debug(pkt);
        pr_response_set_pool(NULL);
        pkt = NULL;
        break;

      case SFTP_SSH2_MSG_DISCONNECT:
        sftp_ssh2_packet_handle_disconnect(pkt);
        pr_response_set_pool(NULL);
        pkt = NULL;
        break;

      case SFTP_SSH2_MSG_IGNORE:
        sftp_ssh2_packet_handle_ignore(pkt);
        pr_response_set_pool(NULL);
        pkt = NULL;
        break;

      case SFTP_SSH2_MSG_UNIMPLEMENTED:
        sftp_ssh2_packet_handle_unimplemented(pkt);
        pr_response_set_pool(NULL);
        pkt = NULL;
        break;

      default:
        /* For any other message type, it's considered a protocol error. */
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "received %s (%d) unexpectedly, disconnecting",
          sftp_ssh2_packet_get_mesg_type_desc(mesg_type), mesg_type);
        pr_response_set_pool(NULL);
        destroy_kex(kex);
        destroy_pool(pkt->pool);
        SFTP_DISCONNECT_CONN(disconn_code, NULL);
    }
  }

  return pkt;
}

int sftp_kex_handle(struct ssh2_packet *pkt) {
  int correct_guess = TRUE, res, sent_newkeys = FALSE;
  char mesg_type;
  struct sftp_kex *kex;
  cmd_rec *cmd;

  /* We may already have a kex structure, either from the client
   * initial connect (kex_first_kex not null), or because we
   * are in a server-initiated rekeying (kex_rekey_kex not null).
   */
  if (kex_first_kex) {
    kex = kex_first_kex;

    /* We need to assign the client/server versions, which this struct
     * will not have.
     */
    kex->client_version = kex_client_version;
    kex->server_version = kex_server_version;

  } else if (kex_rekey_kex) {
    kex = kex_rekey_kex;

  } else {
    kex = create_kex(kex_pool);
  }

  /* The packet we are given is guaranteed to be a KEXINIT packet. */

  cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, "KEXINIT"));
  cmd->arg = "(data)";
  cmd->cmd_class = CL_AUTH|CL_SSH;

  pr_trace_msg(trace_channel, 9, "reading KEXINIT message from client");

  res = read_kexinit(pkt, kex);
  if (res < 0) {
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);

    destroy_kex(kex);
    destroy_pool(pkt->pool);
    return -1;
  }

  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  destroy_pool(pkt->pool);
  cmd = NULL;

  pr_trace_msg(trace_channel, 9,
    "determining shared algorithms for SSH session");

  if (get_session_names(kex, &correct_guess) < 0) {
    destroy_kex(kex);
    return -1;
  }

  /* Once we have received the client KEXINIT message, we can compare what we
   * want to send against what we already received from the client.
   *
   * If the client said that it was going to send a "guess" KEX packet,
   * and we determine that its key exchange guess matches what we would have
   * sent in our KEXINIT, then we proceed on with reading and handling that
   * guess packet.  If not, we ignore that packet, and proceed.
   */

  if (!kex->first_kex_follows) {
    /* No guess packet sent; send our KEXINIT as normal (as long as we are
     * not in a server-initiated rekeying).
     */

    if (!kex_sent_kexinit) {
      pkt = sftp_ssh2_packet_create(kex_pool);
      res = write_kexinit(pkt, kex);
      if (res < 0) {
        destroy_kex(kex);
        destroy_pool(pkt->pool);
        return -1;
      }

      pr_trace_msg(trace_channel, 9, "sending KEXINIT message to client");

      res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
      if (res < 0) {
        destroy_kex(kex);
        destroy_pool(pkt->pool);
        return res;
      }

      kex_sent_kexinit = TRUE;
      destroy_pool(pkt->pool);
    }

  } else {

    /* If the client sent a guess kex packet, but that guess was incorrect,
     * then we need to consume and silently ignore that packet, and proceed
     * as normal.
     */
    if (correct_guess == FALSE) {
      pr_trace_msg(trace_channel, 3, "client sent incorrect key exchange "
        "guess, ignoring guess packet");

      pkt = read_kex_packet(kex_pool, kex,
        SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, &mesg_type, 3,
        SFTP_SSH2_MSG_KEX_DH_INIT,
        SFTP_SSH2_MSG_KEX_DH_GEX_INIT,
        SFTP_SSH2_MSG_KEX_ECDH_INIT);

      pr_trace_msg(trace_channel, 3,
        "ignored %s (%d) guess message sent by client",
        sftp_ssh2_packet_get_mesg_type_desc(mesg_type), mesg_type);

      destroy_pool(pkt->pool);

      if (!kex_sent_kexinit) {
        pkt = sftp_ssh2_packet_create(kex_pool);
        res = write_kexinit(pkt, kex);
        if (res < 0) {
          destroy_kex(kex);
          destroy_pool(pkt->pool);
          return -1;
        }

        pr_trace_msg(trace_channel, 9, "sending KEXINIT message to client");

        res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
        if (res < 0) {
          destroy_kex(kex);
          destroy_pool(pkt->pool);
          return res;
        }

        kex_sent_kexinit = TRUE;
        destroy_pool(pkt->pool);
      }
    }

    if (!kex_sent_kexinit) {
      pkt = sftp_ssh2_packet_create(kex_pool);
      res = write_kexinit(pkt, kex);
      if (res < 0) {
        destroy_kex(kex);
        destroy_pool(pkt->pool);
        return -1;
      }

      pr_trace_msg(trace_channel, 9, "sending KEXINIT message to client");

      res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
      if (res < 0) {
        destroy_kex(kex);
        destroy_pool(pkt->pool);
        return res;
      }

      kex_sent_kexinit = TRUE;
      destroy_pool(pkt->pool);
    }
  }

  if (!kex->use_kexrsa) {
    /* Read the client key exchange mesg. */
    pkt = read_kex_packet(kex_pool, kex,
      SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, &mesg_type, 3,
      SFTP_SSH2_MSG_KEX_DH_INIT,
      SFTP_SSH2_MSG_KEX_DH_GEX_REQUEST,
      SFTP_SSH2_MSG_KEX_ECDH_INIT);

    switch (mesg_type) {
      case SFTP_SSH2_MSG_KEX_DH_INIT:
        /* This handles the case of SFTP_SSH2_MSG_KEX_DH_GEX_REQUEST_OLD as
         * well; that ID has the same value as the KEX_DH_INIT ID.
         */
#if defined(PR_USE_SODIUM) && defined(HAVE_SHA256_OPENSSL)
        if (kex->use_curve25519) {
          res = handle_kex_curve25519(pkt, kex);

        } else
#endif /* PR_USE_SODIUM and HAVE_SHA256_OPENSSL */
#ifdef PR_USE_OPENSSL_ECC
        if (kex->use_ecdh) {
          res = handle_kex_ecdh(pkt, kex);

        } else
#endif /* PR_USE_OPENSSL_ECC */

        if (kex->use_gex) {
          res = handle_kex_dh_gex(pkt, kex, TRUE);

        } else {
          res = handle_kex_dh(pkt, kex);
        }

        if (res < 0) {
          destroy_kex(kex);
          destroy_pool(pkt->pool);
          return -1;
        }
        break;

      case SFTP_SSH2_MSG_KEX_DH_GEX_REQUEST:
        res = handle_kex_dh_gex(pkt, kex, FALSE);
        if (res < 0) {
          destroy_kex(kex);
          destroy_pool(pkt->pool);
          return -1;
        }
        break;

      default:
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
#ifdef PR_USE_OPENSSL_ECC
          "expecting KEX_DH_INIT, KEX_ECDH_INIT or KEX_DH_GEX_GROUP message, "
#else
          "expecting KEX_DH_INIT or KEX_DH_GEX_GROUP message, "
#endif /* PR_USE_OPENSSL_ECC */
          "received %s (%d), disconnecting",
          sftp_ssh2_packet_get_mesg_type_desc(mesg_type), mesg_type);
        destroy_kex(kex);
        destroy_pool(pkt->pool);
        SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_PROTOCOL_ERROR, NULL);
    }

    /* Note: All of the above handle_kex_*() functions are REQUIRED to have
     * destroyed the pkt->pool themselves, thus we do NOT need to do it here.
     */

  } else {
    res = handle_kex_rsa(kex);
    if (res < 0) {
      destroy_kex(kex);
      return -1;
    }
  }

  if (!sftp_interop_supports_feature(SFTP_SSH2_FEAT_PESSIMISTIC_NEWKEYS)) {
    pr_trace_msg(trace_channel, 9, "sending NEWKEYS message to client");

    /* Send our NEWKEYS reply. */
    pkt = sftp_ssh2_packet_create(kex_pool);
    res = write_newkeys_reply(pkt);
    if (res < 0) {
      destroy_kex(kex);
      destroy_pool(pkt->pool);
      return -1;
    }

    res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
    if (res < 0) {
      destroy_kex(kex);
      destroy_pool(pkt->pool);
      return -1;
    }

    destroy_pool(pkt->pool);
    sent_newkeys = TRUE;
  }

  pkt = read_kex_packet(kex_pool, kex, SFTP_SSH2_DISCONNECT_PROTOCOL_ERROR,
    NULL, 1, SFTP_SSH2_MSG_NEWKEYS);

  /* If we didn't send our NEWKEYS message earlier, do it now. */
  if (!sent_newkeys) {
    struct ssh2_packet *pkt2;

    pr_trace_msg(trace_channel, 9, "sending NEWKEYS message to client");

    /* Send our NEWKEYS reply. */
    pkt2 = sftp_ssh2_packet_create(kex_pool);
    res = write_newkeys_reply(pkt2);
    if (res < 0) {
      destroy_kex(kex);
      destroy_pool(pkt2->pool);
      return -1;
    }

    res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt2);
    if (res < 0) {
      destroy_kex(kex);
      destroy_pool(pkt2->pool);
      return -1;
    }

    destroy_pool(pkt2->pool);
  }

  /* Last but certainly not least, set up the keys for encryption and
   * authentication, based on H and K.
   */
  pr_trace_msg(trace_channel, 9, "setting session keys");
  if (set_session_keys(kex) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error setting session keys, disconnecting");
    destroy_kex(kex);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_BY_APPLICATION, NULL);
  }

  cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, "NEWKEYS"));
  cmd->arg = "";
  cmd->cmd_class = CL_AUTH|CL_SSH;

  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  destroy_pool(pkt->pool);
  cmd = NULL;

  /* Reset this flag for the next time through. */
  kex_sent_kexinit = FALSE;

  destroy_kex(kex);
  return 0;
}

int sftp_kex_free(void) {
  struct sftp_kex *first_kex, *rekey_kex;

  if (kex_dhparams_fp != NULL) {
    (void) fclose(kex_dhparams_fp);
    kex_dhparams_fp = NULL;
  }

  /* destroy_kex() will set the kex_first_kex AND kex_rekey_kex pointers to
   * null, so we need to keep our own copies of those pointers here.
   */
  first_kex = kex_first_kex;
  rekey_kex = kex_rekey_kex;

  if (first_kex != NULL) {
    destroy_kex(first_kex);
  }

  if (rekey_kex != NULL) {
    destroy_kex(rekey_kex);
  }

  if (kex_pool) {
    destroy_pool(kex_pool);
    kex_pool = NULL;
  }

  return 0;
}

int sftp_kex_init(const char *client_version, const char *server_version) {
  /* If we are called with client_version and server_version both NULL,
   * then we're setting up for a rekey.  We can destroy/create the Kex
   * pool in that case.  But not otherwise.
   */
  if (client_version == NULL &&
      server_version == NULL) {
    if (kex_pool) {
      destroy_pool(kex_pool);
      kex_pool = NULL;
    }
  }

  if (!kex_pool) {
    kex_pool = make_sub_pool(sftp_pool);
    pr_pool_tag(kex_pool, "Kex Pool");
  }

  /* Save the client and server versions, the first time through.  They
   * will be used for any future rekey KEXINIT exchanges.
   */

  if (client_version != NULL &&
      kex_client_version == NULL) {
    kex_client_version = pstrdup(sftp_pool, client_version);
  }

  if (server_version != NULL &&
      kex_server_version == NULL) {
    kex_server_version = pstrdup(sftp_pool, server_version);
  }

  return 0;
}

int sftp_kex_rekey(void) {
  int res;
  struct ssh2_packet *pkt;

  /* We cannot perform a rekey if we have not even finished the first kex. */ 
  if (!(sftp_sess_state & SFTP_SESS_STATE_HAVE_KEX)) {
    pr_trace_msg(trace_channel, 3,
      "unable to request rekey: KEX not completed");

    /* If this was triggered by a rekey timer, register a new timer and
     * try the rekey request in another 5 seconds.
     */
    if (kex_rekey_interval > 0 &&
        kex_rekey_timerno == -1) {
      pr_trace_msg(trace_channel, 3,
        "trying rekey request in another 5 seconds");
      kex_rekey_timerno = pr_timer_add(5, -1, &sftp_module, kex_rekey_timer_cb,
        "SFTP KEX Rekey timer");
    }

    return 0;
  }

  if (!sftp_interop_supports_feature(SFTP_SSH2_FEAT_REKEYING)) {
    pr_trace_msg(trace_channel, 3,
      "unable to request rekeying: Not supported by client");
    sftp_ssh2_packet_rekey_reset();
    return 0;
  }
 
  /* If already rekeying, return now. */
  if (sftp_sess_state & SFTP_SESS_STATE_REKEYING) {
    pr_trace_msg(trace_channel, 17,
      "rekeying already in effect, ignoring rekey request");
    return 0;
  }

  /* If the client has NOT authenticated by this point in time, try again
   * later.  Some clients do not deal well with having their authentication
   * processes interrupted by a rekey (Bug#4254).
   */
  if (!(sftp_sess_state & SFTP_SESS_STATE_HAVE_AUTH)) {
    pr_trace_msg(trace_channel, 17,
      "authentication not completed, delaying rekey request");

    /* If the rekey interval is so short as to interfere the client before
     * it has authenticated, assume the rekey interval is short enough to
     * fire again soon, such that we do not need to change its schedule.
     */
    return 1;
  }

  /* Make sure that any rekey timer will try not to interfere while the
   * rekeying is happening.
   */
  if (kex_rekey_timerno != -1) {
    pr_timer_remove(kex_rekey_timerno, &sftp_module);
    kex_rekey_timerno = -1;
  }

  pr_trace_msg(trace_channel, 17, "sending rekey KEXINIT");

  /* Some SSH2 clients are very particular about rekeying, and do NOT want
   * other data while they are rekeying.  Other clients are more forgiving.
   * For the strict clients, we set the REKEYING flag here, such that the
   * Channel API will buffer up its responses until the rekeying completes.
   */
  if (sftp_interop_supports_feature(SFTP_SSH2_FEAT_NO_DATA_WHILE_REKEYING)) {
    sftp_sess_state |= SFTP_SESS_STATE_REKEYING;
  }

  sftp_kex_init(NULL, NULL);

  kex_rekey_kex = create_kex(kex_pool);

  pr_trace_msg(trace_channel, 9, "writing KEXINIT message to client");

  /* Sent our KEXINIT mesg. */
  pkt = sftp_ssh2_packet_create(kex_pool);
  res = write_kexinit(pkt, kex_rekey_kex);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED, NULL);
  }

  destroy_pool(pkt->pool);

  kex_sent_kexinit = TRUE;

  if (kex_rekey_timeout > 0) {
    pr_trace_msg(trace_channel, 17, "client has %d %s to rekey",
      kex_rekey_timeout, kex_rekey_timeout != 1 ? "secs" : "sec");
    kex_rekey_timeout_timerno = pr_timer_add(kex_rekey_timeout, -1,
      &sftp_module, kex_rekey_timeout_cb, "SFTP KEX Rekey Timeout timer");
  }

  return 0;
}

int sftp_kex_rekey_set_interval(int rekey_interval) {
  if (rekey_interval < 0) {
    errno = EINVAL;
    return -1;
  }

  kex_rekey_interval = rekey_interval;
  return 0;
}

int sftp_kex_rekey_set_timeout(int timeout) {
  if (timeout < 0) {
    errno = EINVAL;
    return -1;
  }

  kex_rekey_timeout = timeout;
  return 0;
}

int sftp_kex_send_first_kexinit(void) {
  struct ssh2_packet *pkt;
  int res;

  if (!kex_pool) {
    kex_pool = make_sub_pool(sftp_pool);
    pr_pool_tag(kex_pool, "Kex Pool");
  }

  /* The client has just connected to us.  We want to send our version
   * ID string _and_ the KEXINIT in the same TCP packet, and save a 
   * TCP round trip (one TCP ACK for both messages, rather than one ACK
   * per message).  The packet API will automatically send the version
   * ID string along with the first packet we send; we just have to
   * send a packet, and the KEXINIT is the first one in the protocol.
   */
  kex_first_kex = create_kex(kex_pool);

  pkt = sftp_ssh2_packet_create(kex_pool); 
  res = write_kexinit(pkt, kex_first_kex);
  if (res < 0) {
    destroy_kex(kex_first_kex);
    destroy_pool(pkt->pool);
    return -1;
  }

  pr_trace_msg(trace_channel, 9, "sending KEXINIT message to client");

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_kex(kex_first_kex);
    destroy_pool(pkt->pool);
    return -1;
  }
  kex_sent_kexinit = TRUE;

  destroy_pool(pkt->pool);
  return 0;
}

