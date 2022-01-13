/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Copyright (C) 1995 - 2018  Exim maintainers
 *
 *  signing/verification interface
 */

#include "../exim.h"
#include "crypt_ver.h"
#include "signing.h"


#ifdef MACRO_PREDEF
# include "../macro_predef.h"

void
features_crypto(void)
{
# ifdef SIGN_HAVE_ED25519
  builtin_macro_create(US"_CRYPTO_SIGN_ED25519");
# endif
# ifdef EXIM_HAVE_SHA3
  builtin_macro_create(US"_CRYPTO_HASH_SHA3");
# endif
}
#else

#ifndef DISABLE_DKIM	/* rest of file */

#ifndef SUPPORT_TLS
# error Need SUPPORT_TLS for DKIM
#endif


/******************************************************************************/
#ifdef SIGN_GNUTLS
# define EXIM_GNUTLS_LIBRARY_LOG_LEVEL 3


/* Logging function which can be registered with
 *   gnutls_global_set_log_function()
 *   gnutls_global_set_log_level() 0..9
 */
#if EXIM_GNUTLS_LIBRARY_LOG_LEVEL >= 0
static void
exim_gnutls_logger_cb(int level, const char *message)
{
size_t len = strlen(message);
if (len < 1)
  {
  DEBUG(D_tls) debug_printf("GnuTLS<%d> empty debug message\n", level);
  return;
  }
DEBUG(D_tls) debug_printf("GnuTLS<%d>: %s%s", level, message,
    message[len-1] == '\n' ? "" : "\n");
}
#endif



void
exim_dkim_init(void)
{
#if EXIM_GNUTLS_LIBRARY_LOG_LEVEL >= 0
DEBUG(D_tls)
  {
  gnutls_global_set_log_function(exim_gnutls_logger_cb);
  /* arbitrarily chosen level; bump upto 9 for more */
  gnutls_global_set_log_level(EXIM_GNUTLS_LIBRARY_LOG_LEVEL);
  }
#endif
}


/* accumulate data (gnutls-only).  String to be appended must be nul-terminated. */
gstring *
exim_dkim_data_append(gstring * g, uschar * s)
{
return string_cat(g, s);
}



/* import private key from PEM string in memory.
Return: NULL for success, or an error string */

const uschar *
exim_dkim_signing_init(const uschar * privkey_pem, es_ctx * sign_ctx)
{
gnutls_datum_t k = { .data = (void *)privkey_pem, .size = Ustrlen(privkey_pem) };
gnutls_x509_privkey_t x509_key;
const uschar * where;
int rc;

if (  (where = US"internal init", rc = gnutls_x509_privkey_init(&x509_key))
   || (rc = gnutls_privkey_init(&sign_ctx->key))
   || (where = US"privkey PEM-block import",
       rc = gnutls_x509_privkey_import(x509_key, &k, GNUTLS_X509_FMT_PEM))
   || (where = US"internal privkey transfer",
       rc = gnutls_privkey_import_x509(sign_ctx->key, x509_key, 0))
   )
  return string_sprintf("%s: %s", where, gnutls_strerror(rc));

switch (rc = gnutls_privkey_get_pk_algorithm(sign_ctx->key, NULL))
  {
  case GNUTLS_PK_RSA:		sign_ctx->keytype = KEYTYPE_RSA;     break;
#ifdef SIGN_HAVE_ED25519
  case GNUTLS_PK_EDDSA_ED25519:	sign_ctx->keytype = KEYTYPE_ED25519; break;
#endif
  default: return rc < 0
    ? CUS gnutls_strerror(rc)
    : string_sprintf("Unhandled key type: %d '%s'", rc, gnutls_pk_get_name(rc));
  }

return NULL;
}



/* allocate mem for signature (when signing) */
/* hash & sign data.   No way to do incremental.

Return: NULL for success, or an error string */

const uschar *
exim_dkim_sign(es_ctx * sign_ctx, hashmethod hash, blob * data, blob * sig)
{
gnutls_datum_t k_data = { .data = data->data, .size = data->len };
gnutls_digest_algorithm_t dig;
gnutls_datum_t k_sig;
int rc;

switch (hash)
  {
  case HASH_SHA1:	dig = GNUTLS_DIG_SHA1; break;
  case HASH_SHA2_256:	dig = GNUTLS_DIG_SHA256; break;
  case HASH_SHA2_512:	dig = GNUTLS_DIG_SHA512; break;
  default:		return US"nonhandled hash type";
  }

if ((rc = gnutls_privkey_sign_data(sign_ctx->key, dig, 0, &k_data, &k_sig)))
  return CUS gnutls_strerror(rc);

/* Don't care about deinit for the key; shortlived process */

sig->data = k_sig.data;
sig->len = k_sig.size;
return NULL;
}



/* import public key (from blob in memory)
Return: NULL for success, or an error string */

const uschar *
exim_dkim_verify_init(blob * pubkey, keyformat fmt, ev_ctx * verify_ctx)
{
gnutls_datum_t k;
int rc;
const uschar * ret = NULL;

gnutls_pubkey_init(&verify_ctx->key);
k.data = pubkey->data;
k.size = pubkey->len;

switch(fmt)
  {
  case KEYFMT_DER:
    if ((rc = gnutls_pubkey_import(verify_ctx->key, &k, GNUTLS_X509_FMT_DER)))
      ret = US gnutls_strerror(rc);
    break;
#ifdef SIGN_HAVE_ED25519
  case KEYFMT_ED25519_BARE:
    if ((rc = gnutls_pubkey_import_ecc_raw(verify_ctx->key,
					  GNUTLS_ECC_CURVE_ED25519, &k, NULL)))
      ret = US gnutls_strerror(rc);
    break;
#endif
  default:
    ret = US"pubkey format not handled";
    break;
  }
return ret;
}


/* verify signature (of hash if RSA sig, of data if EC sig.  No way to do incremental)
(given pubkey & alleged sig)
Return: NULL for success, or an error string */

const uschar *
exim_dkim_verify(ev_ctx * verify_ctx, hashmethod hash, blob * data_hash, blob * sig)
{
gnutls_datum_t k = { .data = data_hash->data, .size = data_hash->len };
gnutls_datum_t s = { .data = sig->data,       .size = sig->len };
int rc;
const uschar * ret = NULL;

#ifdef SIGN_HAVE_ED25519
if (verify_ctx->keytype == KEYTYPE_ED25519)
  {
  if ((rc = gnutls_pubkey_verify_data2(verify_ctx->key,
				      GNUTLS_SIGN_EDDSA_ED25519, 0, &k, &s)) < 0)
    ret = US gnutls_strerror(rc);
  }
else
#endif
  {
  gnutls_sign_algorithm_t algo;
  switch (hash)
    {
    case HASH_SHA1:	algo = GNUTLS_SIGN_RSA_SHA1;   break;
    case HASH_SHA2_256:	algo = GNUTLS_SIGN_RSA_SHA256; break;
    case HASH_SHA2_512:	algo = GNUTLS_SIGN_RSA_SHA512; break;
    default:		return US"nonhandled hash type";
    }

  if ((rc = gnutls_pubkey_verify_hash2(verify_ctx->key, algo, 0, &k, &s)) < 0)
    ret = US gnutls_strerror(rc);
  }

gnutls_pubkey_deinit(verify_ctx->key);
return ret;
}




#elif defined(SIGN_GCRYPT)
/******************************************************************************/
/* This variant is used under pre-3.0.0 GnuTLS.  Only rsa-sha1 and rsa-sha256 */


/* Internal service routine:
Read and move past an asn.1 header, checking class & tag,
optionally returning the data-length */

static int
as_tag(blob * der, uschar req_cls, long req_tag, long * alen)
{
int rc;
uschar tag_class;
int taglen;
long tag, len;

debug_printf_indent("as_tag: %02x %02x %02x %02x\n",
	der->data[0], der->data[1], der->data[2], der->data[3]);

if ((rc = asn1_get_tag_der(der->data++, der->len--, &tag_class, &taglen, &tag))
    != ASN1_SUCCESS)
  return rc;

if (tag_class != req_cls || tag != req_tag) return ASN1_ELEMENT_NOT_FOUND;

if ((len = asn1_get_length_der(der->data, der->len, &taglen)) < 0)
  return ASN1_DER_ERROR;
if (alen) *alen = len;

/* debug_printf_indent("as_tag:  tlen %d dlen %d\n", taglen, (int)len); */

der->data += taglen;
der->len -= taglen;
return rc;
}

/* Internal service routine:
Read and move over an asn.1 integer, setting an MPI to the value
*/

static uschar *
as_mpi(blob * der, gcry_mpi_t * mpi)
{
long alen;
int rc;
gcry_error_t gerr;

debug_printf_indent("%s\n", __FUNCTION__);

/* integer; move past the header */
if ((rc = as_tag(der, 0, ASN1_TAG_INTEGER, &alen)) != ASN1_SUCCESS)
  return US asn1_strerror(rc);

/* read to an MPI */
if ((gerr = gcry_mpi_scan(mpi, GCRYMPI_FMT_STD, der->data, alen, NULL)))
  return US gcry_strerror(gerr);

/* move over the data */
der->data += alen; der->len -= alen;
return NULL;
}



void
exim_dkim_init(void)
{
/* Version check should be the very first call because it
makes sure that important subsystems are initialized. */
if (!gcry_check_version (GCRYPT_VERSION))
  {
  fputs ("libgcrypt version mismatch\n", stderr);
  exit (2);
  }

/* We don't want to see any warnings, e.g. because we have not yet
parsed program options which might be used to suppress such
warnings. */
gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

/* ... If required, other initialization goes here.  Note that the
process might still be running with increased privileges and that
the secure memory has not been initialized.  */

/* Allocate a pool of 16k secure memory.  This make the secure memory
available and also drops privileges where needed.  */
gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

/* It is now okay to let Libgcrypt complain when there was/is
a problem with the secure memory. */
gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

/* ... If required, other initialization goes here.  */

/* Tell Libgcrypt that initialization has completed. */
gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

return;
}




/* Accumulate data (gnutls-only).
String to be appended must be nul-terminated. */

gstring *
exim_dkim_data_append(gstring * g, uschar * s)
{
return g;	/*dummy*/
}



/* import private key from PEM string in memory.
Only handles RSA keys.
Return: NULL for success, or an error string */

const uschar *
exim_dkim_signing_init(const uschar * privkey_pem, es_ctx * sign_ctx)
{
uschar * s1, * s2;
blob der;
long alen;
int rc;

/*XXX will need extension to _spot_ as well as handle a
non-RSA key?  I think...
So... this is not a PrivateKeyInfo - which would have a field
identifying the keytype - PrivateKeyAlgorithmIdentifier -
but a plain RSAPrivateKey (wrapped in PEM-headers.  Can we
use those as a type tag?  What forms are there?  "BEGIN EC PRIVATE KEY" (cf. ec(1ssl))

How does OpenSSL PEM_read_bio_PrivateKey() deal with it?
gnutls_x509_privkey_import() ?
*/

/*
 *  RSAPrivateKey ::= SEQUENCE
 *      version           Version,
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER,  -- e
 *      privateExponent   INTEGER,  -- d
 *      prime1            INTEGER,  -- p
 *      prime2            INTEGER,  -- q
 *      exponent1         INTEGER,  -- d mod (p-1)
 *      exponent2         INTEGER,  -- d mod (q-1)
 *      coefficient       INTEGER,  -- (inverse of q) mod p
 *      otherPrimeInfos   OtherPrimeInfos OPTIONAL

 * ECPrivateKey ::= SEQUENCE {
 *     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *     privateKey     OCTET STRING,
 *     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *     publicKey  [1] BIT STRING OPTIONAL
 *   }
 * Hmm, only 1 useful item, and not even an integer?  Wonder how we might use it...

- actually, gnutls_x509_privkey_import() appears to require a curve name parameter
	value for that is an OID? a local-only integer (it's an enum in GnuTLS)?


Useful cmds:
  ssh-keygen -t ecdsa -f foo.privkey
  ssh-keygen -t ecdsa -b384 -f foo.privkey
  ssh-keygen -t ecdsa -b521 -f foo.privkey
  ssh-keygen -t ed25519 -f foo.privkey

  < foo openssl pkcs8 -in /dev/stdin -inform PEM -nocrypt -topk8 -outform DER | od -x

  openssl asn1parse -in foo -inform PEM -dump
  openssl asn1parse -in foo -inform PEM -dump -stroffset 24    (??)
(not good for ed25519)

 */

if (  !(s1 = Ustrstr(CS privkey_pem, "-----BEGIN RSA PRIVATE KEY-----"))
   || !(s2 = Ustrstr(CS (s1+=31),    "-----END RSA PRIVATE KEY-----" ))
   )
  return US"Bad PEM wrapper";

*s2 = '\0';

if ((der.len = b64decode(s1, &der.data)) < 0)
  return US"Bad PEM-DER b64 decode";

/* untangle asn.1 */

/* sequence; just move past the header */
if ((rc = as_tag(&der, ASN1_CLASS_STRUCTURED, ASN1_TAG_SEQUENCE, NULL))
   != ASN1_SUCCESS) goto asn_err;

/* integer version; move past the header, check is zero */
if ((rc = as_tag(&der, 0, ASN1_TAG_INTEGER, &alen)) != ASN1_SUCCESS)
  goto asn_err;
if (alen != 1 || *der.data != 0)
  return US"Bad version number";
der.data++; der.len--;

if (  (s1 = as_mpi(&der, &sign_ctx->n))
   || (s1 = as_mpi(&der, &sign_ctx->e))
   || (s1 = as_mpi(&der, &sign_ctx->d))
   || (s1 = as_mpi(&der, &sign_ctx->p))
   || (s1 = as_mpi(&der, &sign_ctx->q))
   || (s1 = as_mpi(&der, &sign_ctx->dp))
   || (s1 = as_mpi(&der, &sign_ctx->dq))
   || (s1 = as_mpi(&der, &sign_ctx->qp))
   )
  return s1;

#ifdef extreme_debug
DEBUG(D_acl) debug_printf_indent("rsa_signing_init:\n");
  {
  uschar * s;
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->n);
  debug_printf_indent(" N : %s\n", s);
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->e);
  debug_printf_indent(" E : %s\n", s);
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->d);
  debug_printf_indent(" D : %s\n", s);
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->p);
  debug_printf_indent(" P : %s\n", s);
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->q);
  debug_printf_indent(" Q : %s\n", s);
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->dp);
  debug_printf_indent(" DP: %s\n", s);
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->dq);
  debug_printf_indent(" DQ: %s\n", s);
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, sign_ctx->qp);
  debug_printf_indent(" QP: %s\n", s);
  }
#endif

sign_ctx->keytype = KEYTYPE_RSA;
return NULL;

asn_err: return US asn1_strerror(rc);
}



/* allocate mem for signature (when signing) */
/* sign already-hashed data.

Return: NULL for success, or an error string */

const uschar *
exim_dkim_sign(es_ctx * sign_ctx, hashmethod hash, blob * data, blob * sig)
{
char * sexp_hash;
gcry_sexp_t s_hash = NULL, s_key = NULL, s_sig = NULL;
gcry_mpi_t m_sig;
uschar * errstr;
gcry_error_t gerr;

/*XXX will need extension for hash types (though, possibly, should
be re-specced to not rehash but take an already-hashed value? Actually
current impl looks WRONG - it _is_ given a hash so should not be
re-hashing.  Has this been tested?

Will need extension for non-RSA sugning algos. */

switch (hash)
  {
  case HASH_SHA1:	sexp_hash = "(data(flags pkcs1)(hash sha1 %b))"; break;
  case HASH_SHA2_256:	sexp_hash = "(data(flags pkcs1)(hash sha256 %b))"; break;
  default:		return US"nonhandled hash type";
  }

#define SIGSPACE 128
sig->data = store_get(SIGSPACE);

if (gcry_mpi_cmp (sign_ctx->p, sign_ctx->q) > 0)
  {
  gcry_mpi_swap (sign_ctx->p, sign_ctx->q);
  gcry_mpi_invm (sign_ctx->qp, sign_ctx->p, sign_ctx->q);
  }

if (  (gerr = gcry_sexp_build (&s_key, NULL,
		"(private-key (rsa (n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))",
		sign_ctx->n, sign_ctx->e,
		sign_ctx->d, sign_ctx->p,
		sign_ctx->q, sign_ctx->qp))
   || (gerr = gcry_sexp_build (&s_hash, NULL, sexp_hash,
		(int) data->len, CS data->data))
   ||  (gerr = gcry_pk_sign (&s_sig, s_hash, s_key))
   )
  return US gcry_strerror(gerr);

/* gcry_sexp_dump(s_sig); */

if (  !(s_sig = gcry_sexp_find_token(s_sig, "s", 0))
   )
  return US"no sig result";

m_sig = gcry_sexp_nth_mpi(s_sig, 1, GCRYMPI_FMT_USG);

#ifdef extreme_debug
DEBUG(D_acl)
  {
  uschar * s;
  gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, m_sig);
  debug_printf_indent(" SG: %s\n", s);
  }
#endif

gerr = gcry_mpi_print(GCRYMPI_FMT_USG, sig->data, SIGSPACE, &sig->len, m_sig);
if (gerr)
  {
  debug_printf_indent("signature conversion from MPI to buffer failed\n");
  return US gcry_strerror(gerr);
  }
#undef SIGSPACE

return NULL;
}


/* import public key (from blob in memory)
Return: NULL for success, or an error string */

const uschar *
exim_dkim_verify_init(blob * pubkey, keyformat fmt, ev_ctx * verify_ctx)
{
/*
in code sequence per b81207d2bfa92 rsa_parse_public_key() and asn1_get_mpi()
*/
uschar tag_class;
int taglen;
long alen;
int rc;
uschar * errstr;
gcry_error_t gerr;
uschar * stage = US"S1";

if (fmt != KEYFMT_DER) return US"pubkey format not handled";

/*
sequence
 sequence
  OBJECT:rsaEncryption
  NULL
 BIT STRING:RSAPublicKey
  sequence
   INTEGER:Public modulus
   INTEGER:Public exponent

openssl rsa -in aux-fixed/dkim/dkim.private -pubout -outform DER | od -t x1 | head;
openssl rsa -in aux-fixed/dkim/dkim.private -pubout | openssl asn1parse -dump;
openssl rsa -in aux-fixed/dkim/dkim.private -pubout | openssl asn1parse -dump -offset 22;
*/

/* sequence; just move past the header */
if ((rc = as_tag(pubkey, ASN1_CLASS_STRUCTURED, ASN1_TAG_SEQUENCE, NULL))
   != ASN1_SUCCESS) goto asn_err;

/* sequence; skip the entire thing */
DEBUG(D_acl) stage = US"S2";
if ((rc = as_tag(pubkey, ASN1_CLASS_STRUCTURED, ASN1_TAG_SEQUENCE, &alen))
   != ASN1_SUCCESS) goto asn_err;
pubkey->data += alen; pubkey->len -= alen;


/* bitstring: limit range to size of bitstring;
move over header + content wrapper */
DEBUG(D_acl) stage = US"BS";
if ((rc = as_tag(pubkey, 0, ASN1_TAG_BIT_STRING, &alen)) != ASN1_SUCCESS)
  goto asn_err;
pubkey->len = alen;
pubkey->data++; pubkey->len--;

/* sequence; just move past the header */
DEBUG(D_acl) stage = US"S3";
if ((rc = as_tag(pubkey, ASN1_CLASS_STRUCTURED, ASN1_TAG_SEQUENCE, NULL))
   != ASN1_SUCCESS) goto asn_err;

/* read two integers */
DEBUG(D_acl) stage = US"MPI";
if (  (errstr = as_mpi(pubkey, &verify_ctx->n))
   || (errstr = as_mpi(pubkey, &verify_ctx->e))
   )
  return errstr;

#ifdef extreme_debug
DEBUG(D_acl) debug_printf_indent("rsa_verify_init:\n");
	{
	uschar * s;
	gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, verify_ctx->n);
	debug_printf_indent(" N : %s\n", s);
	gcry_mpi_aprint (GCRYMPI_FMT_HEX, &s, NULL, verify_ctx->e);
	debug_printf_indent(" E : %s\n", s);
	}

#endif
return NULL;

asn_err:
DEBUG(D_acl) return string_sprintf("%s: %s", stage, asn1_strerror(rc));
	     return US asn1_strerror(rc);
}


/* verify signature (of hash)
XXX though we appear to be doing a hash, too!
(given pubkey & alleged sig)
Return: NULL for success, or an error string */

const uschar *
exim_dkim_verify(ev_ctx * verify_ctx, hashmethod hash, blob * data_hash, blob * sig)
{
/*
cf. libgnutls 2.8.5 _wrap_gcry_pk_verify()
*/
char * sexp_hash;
gcry_mpi_t m_sig;
gcry_sexp_t s_sig = NULL, s_hash = NULL, s_pkey = NULL;
gcry_error_t gerr;
uschar * stage;

/*XXX needs extension for SHA512 */
switch (hash)
  {
  case HASH_SHA1:     sexp_hash = "(data(flags pkcs1)(hash sha1 %b))"; break;
  case HASH_SHA2_256: sexp_hash = "(data(flags pkcs1)(hash sha256 %b))"; break;
  default:	      return US"nonhandled hash type";
  }

if (  (stage = US"pkey sexp build",
       gerr = gcry_sexp_build (&s_pkey, NULL, "(public-key(rsa(n%m)(e%m)))",
		        verify_ctx->n, verify_ctx->e))
   || (stage = US"data sexp build",
       gerr = gcry_sexp_build (&s_hash, NULL, sexp_hash,
		(int) data_hash->len, CS data_hash->data))
   || (stage = US"sig mpi scan",
       gerr = gcry_mpi_scan(&m_sig, GCRYMPI_FMT_USG, sig->data, sig->len, NULL))
   || (stage = US"sig sexp build",
       gerr = gcry_sexp_build (&s_sig, NULL, "(sig-val(rsa(s%m)))", m_sig))
   || (stage = US"verify",
       gerr = gcry_pk_verify (s_sig, s_hash, s_pkey))
   )
  {
  DEBUG(D_acl) debug_printf_indent("verify: error in stage '%s'\n", stage);
  return US gcry_strerror(gerr);
  }

if (s_sig) gcry_sexp_release (s_sig);
if (s_hash) gcry_sexp_release (s_hash);
if (s_pkey) gcry_sexp_release (s_pkey);
gcry_mpi_release (m_sig);
gcry_mpi_release (verify_ctx->n);
gcry_mpi_release (verify_ctx->e);

return NULL;
}




#elif defined(SIGN_OPENSSL)
/******************************************************************************/

void
exim_dkim_init(void)
{
ERR_load_crypto_strings();
}


/* accumulate data (was gnutls-only but now needed for OpenSSL non-EC too
because now using hash-and-sign interface) */
gstring *
exim_dkim_data_append(gstring * g, uschar * s)
{
return string_cat(g, s);
}


/* import private key from PEM string in memory.
Return: NULL for success, or an error string */

const uschar *
exim_dkim_signing_init(const uschar * privkey_pem, es_ctx * sign_ctx)
{
BIO * bp = BIO_new_mem_buf(privkey_pem, -1);

if (!(sign_ctx->key = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL)))
  return string_sprintf("privkey PEM-block import: %s",
		       	ERR_error_string(ERR_get_error(), NULL));

sign_ctx->keytype =
#ifdef SIGN_HAVE_ED25519
	EVP_PKEY_type(EVP_PKEY_id(sign_ctx->key)) == EVP_PKEY_ED25519
	  ? KEYTYPE_ED25519 : KEYTYPE_RSA;
#else
	KEYTYPE_RSA;
#endif
return NULL;
}



/* allocate mem for signature (when signing) */
/* hash & sign data.  Incremental not supported.

Return: NULL for success with the signaature in the sig blob, or an error string */

const uschar *
exim_dkim_sign(es_ctx * sign_ctx, hashmethod hash, blob * data, blob * sig)
{
const EVP_MD * md;
EVP_MD_CTX * ctx;
size_t siglen;

switch (hash)
  {
  case HASH_NULL:	md = NULL;	   break;	/* Ed25519 signing */
  case HASH_SHA1:	md = EVP_sha1();   break;
  case HASH_SHA2_256:	md = EVP_sha256(); break;
  case HASH_SHA2_512:	md = EVP_sha512(); break;
  default:		return US"nonhandled hash type";
  }

#ifdef SIGN_HAVE_ED25519
if (  (ctx = EVP_MD_CTX_new())
   && EVP_DigestSignInit(ctx, NULL, md, NULL, sign_ctx->key) > 0
   && EVP_DigestSign(ctx, NULL, &siglen, NULL, 0) > 0
   && (sig->data = store_get(siglen))

   /* Obtain the signature (slen could change here!) */
   && EVP_DigestSign(ctx, sig->data, &siglen, data->data, data->len) > 0
   )
  {
  EVP_MD_CTX_destroy(ctx);
  sig->len = siglen;
  return NULL;
  }
#else
/*XXX renamed to EVP_MD_CTX_new() in 1.1.0 */
if (  (ctx = EVP_MD_CTX_create())
   && EVP_DigestSignInit(ctx, NULL, md, NULL, sign_ctx->key) > 0
   && EVP_DigestSignUpdate(ctx, data->data, data->len) > 0
   && EVP_DigestSignFinal(ctx, NULL, &siglen) > 0
   && (sig->data = store_get(siglen))
 
   /* Obtain the signature (slen could change here!) */
   && EVP_DigestSignFinal(ctx, sig->data, &siglen) > 0
   )
  {
  EVP_MD_CTX_destroy(ctx);
  sig->len = siglen;
  return NULL;
  }
#endif

if (ctx) EVP_MD_CTX_destroy(ctx);
return US ERR_error_string(ERR_get_error(), NULL);
}



/* import public key (from blob in memory)
Return: NULL for success, or an error string */

const uschar *
exim_dkim_verify_init(blob * pubkey, keyformat fmt, ev_ctx * verify_ctx)
{
const uschar * s = pubkey->data;
uschar * ret = NULL;

switch(fmt)
  {
  case KEYFMT_DER:
    /*XXX hmm, we never free this */
    if (!(verify_ctx->key = d2i_PUBKEY(NULL, &s, pubkey->len)))
      ret = US ERR_error_string(ERR_get_error(), NULL);
    break;
#ifdef SIGN_HAVE_ED25519
  case KEYFMT_ED25519_BARE:
    if (!(verify_ctx->key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
							s, pubkey->len)))
      ret = US ERR_error_string(ERR_get_error(), NULL);
    break;
#endif
  default:
    ret = US"pubkey format not handled";
    break;
  }

return ret;
}




/* verify signature (of hash, except Ed25519 where of-data)
(given pubkey & alleged sig)
Return: NULL for success, or an error string */

const uschar *
exim_dkim_verify(ev_ctx * verify_ctx, hashmethod hash, blob * data, blob * sig)
{
const EVP_MD * md;

switch (hash)
  {
  case HASH_NULL:	md = NULL;	   break;
  case HASH_SHA1:	md = EVP_sha1();   break;
  case HASH_SHA2_256:	md = EVP_sha256(); break;
  case HASH_SHA2_512:	md = EVP_sha512(); break;
  default:		return US"nonhandled hash type";
  }

#ifdef SIGN_HAVE_ED25519
if (!md)
  {
  EVP_MD_CTX * ctx;

  if ((ctx = EVP_MD_CTX_new()))
    {
    if (  EVP_DigestVerifyInit(ctx, NULL, md, NULL, verify_ctx->key) > 0
       && EVP_DigestVerify(ctx, sig->data, sig->len, data->data, data->len) > 0
       )
      { EVP_MD_CTX_free(ctx); return NULL; }
    EVP_MD_CTX_free(ctx);
    }
  }
else
#endif
  {
  EVP_PKEY_CTX * ctx;

  if ((ctx = EVP_PKEY_CTX_new(verify_ctx->key, NULL)))
    {
    if (  EVP_PKEY_verify_init(ctx) > 0
       && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0
       && EVP_PKEY_CTX_set_signature_md(ctx, md) > 0
       && EVP_PKEY_verify(ctx, sig->data, sig->len,
				      data->data, data->len) == 1
       )
      { EVP_PKEY_CTX_free(ctx); return NULL; }
    EVP_PKEY_CTX_free(ctx);

    DEBUG(D_tls)
      if (Ustrcmp(ERR_reason_error_string(ERR_peek_error()), "wrong signature length") == 0)
	debug_printf("sig len (from msg hdr): %d, expected (from dns pubkey) %d\n",
	 (int) sig->len, EVP_PKEY_size(verify_ctx->key));
    }
  }

return US ERR_error_string(ERR_get_error(), NULL);
}



#endif
/******************************************************************************/

#endif	/*DISABLE_DKIM*/
#endif	/*MACRO_PREDEF*/
/* End of File */
