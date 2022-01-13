/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Copyright (C) 1995 - 2018  Exim maintainers
 *
 *  RSA signing/verification interface
 */

#include "../exim.h"

#ifndef DISABLE_DKIM	/* entire file */

#include "crypt_ver.h"

#ifdef SIGN_OPENSSL
# include <openssl/rsa.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
#elif defined(SIGN_GNUTLS)
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
# include <gnutls/abstract.h>
#elif defined(SIGN_GCRYPT)
# include <gcrypt.h>
# include <libtasn1.h>
#endif

#include "../blob.h"

typedef enum {
  KEYTYPE_RSA,
  KEYTYPE_ED25519
} keytype;

typedef enum {
  KEYFMT_DER,		/* an asn.1 structure */
  KEYFMT_ED25519_BARE	/* just the key */
} keyformat;


#ifdef SIGN_OPENSSL

typedef struct {
  keytype	keytype;
  EVP_PKEY *	key;
} es_ctx;

typedef struct {
  keytype	keytype;
  EVP_PKEY *	key;
} ev_ctx;

#elif defined(SIGN_GNUTLS)

typedef struct {
  keytype	keytype;
  gnutls_privkey_t key;
} es_ctx;

typedef struct {
  keytype	keytype;
  gnutls_pubkey_t key;
} ev_ctx;

#elif defined(SIGN_GCRYPT)

typedef struct {
  keytype	keytype;
  gcry_mpi_t n;
  gcry_mpi_t e;
  gcry_mpi_t d;
  gcry_mpi_t p;
  gcry_mpi_t q;
  gcry_mpi_t dp;
  gcry_mpi_t dq;
  gcry_mpi_t qp;
} es_ctx;

typedef struct {
  keytype	keytype;
  gcry_mpi_t n;
  gcry_mpi_t e;
} ev_ctx;

#endif


extern void exim_dkim_init(void);
extern gstring * exim_dkim_data_append(gstring *, uschar *);

extern const uschar * exim_dkim_signing_init(const uschar *, es_ctx *);
extern const uschar * exim_dkim_sign(es_ctx *, hashmethod, blob *, blob *);
extern const uschar * exim_dkim_verify_init(blob *, keyformat, ev_ctx *);
extern const uschar * exim_dkim_verify(ev_ctx *, hashmethod, blob *, blob *);

#endif	/*DISABLE_DKIM*/
/* End of File */
