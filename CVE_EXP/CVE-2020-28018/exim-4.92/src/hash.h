/*
 *  Exim - an Internet mail transport agent
 *
 *  Copyright (C) 1995 - 2018  Exim maintainers
 *
 *  Hash interface functions
 */

#include "exim.h"

#if !defined(HASH_H)	/* entire file */
#define HASH_H

#include "sha_ver.h"

#ifdef SHA_OPENSSL
# include <openssl/sha.h>
#elif defined SHA_GNUTLS
# include <gnutls/crypto.h>
#elif defined(SHA_GCRYPT)
# include <gcrypt.h>
#elif defined(SHA_POLARSSL)
# include "pdkim/pdkim.h"		/*XXX ugly */
# include "pdkim/polarssl/sha1.h"
# include "pdkim/polarssl/sha2.h"
#endif


/* Hash context for the exim_sha_* routines */

typedef enum hashmethod {
  HASH_BADTYPE,
  HASH_NULL,
  HASH_SHA1,

  HASH_SHA2_256,
  HASH_SHA2_384,
  HASH_SHA2_512,

  HASH_SHA3_224,
  HASH_SHA3_256,
  HASH_SHA3_384,
  HASH_SHA3_512,
} hashmethod;

typedef struct {
  hashmethod	method;
  int		hashlen;

#ifdef SHA_OPENSSL
  union {
    SHA_CTX      sha1;       /* SHA1 block                                */
    SHA256_CTX   sha2_256;   /* SHA256 or 224 block                       */
    SHA512_CTX   sha2_512;   /* SHA512 or 384 block                       */
#ifdef EXIM_HAVE_SHA3
    EVP_MD_CTX * mctx;	     /* SHA3 block				  */
#endif
  } u;

#elif defined(SHA_GNUTLS)
  gnutls_hash_hd_t sha;      /* Either SHA1 or SHA256 block               */

#elif defined(SHA_GCRYPT)
  gcry_md_hd_t sha;          /* Either SHA1 or SHA256 block               */

#elif defined(SHA_POLARSSL)
  union {
    sha1_context sha1;       /* SHA1 block                                */
    sha2_context sha2;       /* SHA256 block                              */
  } u;

#elif defined(SHA_NATIVE)
  sha1 sha1;
#endif

} hctx;

extern BOOL     exim_sha_init(hctx *, hashmethod);
extern void     exim_sha_update(hctx *, const uschar *a, int);
extern void     exim_sha_finish(hctx *, blob *);

#endif
/* End of File */
