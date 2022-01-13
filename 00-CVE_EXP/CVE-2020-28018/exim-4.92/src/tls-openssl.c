/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Portions Copyright (c) The OpenSSL Project 1999 */

/* This module provides the TLS (aka SSL) support for Exim using the OpenSSL
library. It is #included into the tls.c file when that library is used. The
code herein is based on a patch that was originally contributed by Steve
Haslam. It was adapted from stunnel, a GPL program by Michal Trojnara.

No cryptographic code is included in Exim. All this module does is to call
functions from the OpenSSL library. */


/* Heading stuff */

#include <openssl/lhash.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_ECDH
# include <openssl/ec.h>
#endif
#ifndef DISABLE_OCSP
# include <openssl/ocsp.h>
#endif
#ifdef SUPPORT_DANE
# include "danessl.h"
#endif


#ifndef DISABLE_OCSP
# define EXIM_OCSP_SKEW_SECONDS (300L)
# define EXIM_OCSP_MAX_AGE (-1L)
#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
# define EXIM_HAVE_OPENSSL_TLSEXT
#endif
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
# define EXIM_HAVE_RSA_GENKEY_EX
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
# define EXIM_HAVE_OCSP_RESP_COUNT
#else
# define EXIM_HAVE_EPHEM_RSA_KEX
# define EXIM_HAVE_RAND_PSEUDO
#endif
#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL) && !defined(OPENSSL_NO_SHA256)
# define EXIM_HAVE_SHA256
#endif

/*
 * X509_check_host provides sane certificate hostname checking, but was added
 * to OpenSSL late, after other projects forked off the code-base.  So in
 * addition to guarding against the base version number, beware that LibreSSL
 * does not (at this time) support this function.
 *
 * If LibreSSL gains a different API, perhaps via libtls, then we'll probably
 * opt to disentangle and ask a LibreSSL user to provide glue for a third
 * crypto provider for libtls instead of continuing to tie the OpenSSL glue
 * into even twistier knots.  If LibreSSL gains the same API, we can just
 * change this guard and punt the issue for a while longer.
 */
#ifndef LIBRESSL_VERSION_NUMBER
# if OPENSSL_VERSION_NUMBER >= 0x010100000L
#  define EXIM_HAVE_OPENSSL_CHECKHOST
#  define EXIM_HAVE_OPENSSL_DH_BITS
#  define EXIM_HAVE_OPENSSL_TLS_METHOD
# else
#  define EXIM_NEED_OPENSSL_INIT
# endif
# if OPENSSL_VERSION_NUMBER >= 0x010000000L \
    && (OPENSSL_VERSION_NUMBER & 0x0000ff000L) >= 0x000002000L
#  define EXIM_HAVE_OPENSSL_CHECKHOST
# endif
#endif

#if !defined(LIBRESSL_VERSION_NUMBER) \
    || LIBRESSL_VERSION_NUMBER >= 0x20010000L
# if !defined(OPENSSL_NO_ECDH)
#  if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#   define EXIM_HAVE_ECDH
#  endif
#  if OPENSSL_VERSION_NUMBER >= 0x10002000L
#   define EXIM_HAVE_OPENSSL_EC_NIST2NID
#  endif
# endif
#endif

#if !defined(EXIM_HAVE_OPENSSL_TLSEXT) && !defined(DISABLE_OCSP)
# warning "OpenSSL library version too old; define DISABLE_OCSP in Makefile"
# define DISABLE_OCSP
#endif

#ifdef EXIM_HAVE_OPENSSL_CHECKHOST
# include <openssl/x509v3.h>
#endif

/*************************************************
*        OpenSSL option parse                    *
*************************************************/

typedef struct exim_openssl_option {
  uschar *name;
  long    value;
} exim_openssl_option;
/* We could use a macro to expand, but we need the ifdef and not all the
options document which version they were introduced in.  Policylet: include
all options unless explicitly for DTLS, let the administrator choose which
to apply.

This list is current as of:
  ==>  1.0.1b  <==
Plus SSL_OP_SAFARI_ECDHE_ECDSA_BUG from 2013-June patch/discussion on openssl-dev
Plus SSL_OP_NO_TLSv1_3 for 1.1.2-dev
*/
static exim_openssl_option exim_openssl_options[] = {
/* KEEP SORTED ALPHABETICALLY! */
#ifdef SSL_OP_ALL
  { US"all", SSL_OP_ALL },
#endif
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
  { US"allow_unsafe_legacy_renegotiation", SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION },
#endif
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
  { US"cipher_server_preference", SSL_OP_CIPHER_SERVER_PREFERENCE },
#endif
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
  { US"dont_insert_empty_fragments", SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS },
#endif
#ifdef SSL_OP_EPHEMERAL_RSA
  { US"ephemeral_rsa", SSL_OP_EPHEMERAL_RSA },
#endif
#ifdef SSL_OP_LEGACY_SERVER_CONNECT
  { US"legacy_server_connect", SSL_OP_LEGACY_SERVER_CONNECT },
#endif
#ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
  { US"microsoft_big_sslv3_buffer", SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER },
#endif
#ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
  { US"microsoft_sess_id_bug", SSL_OP_MICROSOFT_SESS_ID_BUG },
#endif
#ifdef SSL_OP_MSIE_SSLV2_RSA_PADDING
  { US"msie_sslv2_rsa_padding", SSL_OP_MSIE_SSLV2_RSA_PADDING },
#endif
#ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
  { US"netscape_challenge_bug", SSL_OP_NETSCAPE_CHALLENGE_BUG },
#endif
#ifdef SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
  { US"netscape_reuse_cipher_change_bug", SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG },
#endif
#ifdef SSL_OP_NO_COMPRESSION
  { US"no_compression", SSL_OP_NO_COMPRESSION },
#endif
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
  { US"no_session_resumption_on_renegotiation", SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION },
#endif
#ifdef SSL_OP_NO_SSLv2
  { US"no_sslv2", SSL_OP_NO_SSLv2 },
#endif
#ifdef SSL_OP_NO_SSLv3
  { US"no_sslv3", SSL_OP_NO_SSLv3 },
#endif
#ifdef SSL_OP_NO_TICKET
  { US"no_ticket", SSL_OP_NO_TICKET },
#endif
#ifdef SSL_OP_NO_TLSv1
  { US"no_tlsv1", SSL_OP_NO_TLSv1 },
#endif
#ifdef SSL_OP_NO_TLSv1_1
#if SSL_OP_NO_TLSv1_1 == 0x00000400L
  /* Error in chosen value in 1.0.1a; see first item in CHANGES for 1.0.1b */
#warning OpenSSL 1.0.1a uses a bad value for SSL_OP_NO_TLSv1_1, ignoring
#else
  { US"no_tlsv1_1", SSL_OP_NO_TLSv1_1 },
#endif
#endif
#ifdef SSL_OP_NO_TLSv1_2
  { US"no_tlsv1_2", SSL_OP_NO_TLSv1_2 },
#endif
#ifdef SSL_OP_NO_TLSv1_3
  { US"no_tlsv1_3", SSL_OP_NO_TLSv1_3 },
#endif
#ifdef SSL_OP_SAFARI_ECDHE_ECDSA_BUG
  { US"safari_ecdhe_ecdsa_bug", SSL_OP_SAFARI_ECDHE_ECDSA_BUG },
#endif
#ifdef SSL_OP_SINGLE_DH_USE
  { US"single_dh_use", SSL_OP_SINGLE_DH_USE },
#endif
#ifdef SSL_OP_SINGLE_ECDH_USE
  { US"single_ecdh_use", SSL_OP_SINGLE_ECDH_USE },
#endif
#ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
  { US"ssleay_080_client_dh_bug", SSL_OP_SSLEAY_080_CLIENT_DH_BUG },
#endif
#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
  { US"sslref2_reuse_cert_type_bug", SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG },
#endif
#ifdef SSL_OP_TLS_BLOCK_PADDING_BUG
  { US"tls_block_padding_bug", SSL_OP_TLS_BLOCK_PADDING_BUG },
#endif
#ifdef SSL_OP_TLS_D5_BUG
  { US"tls_d5_bug", SSL_OP_TLS_D5_BUG },
#endif
#ifdef SSL_OP_TLS_ROLLBACK_BUG
  { US"tls_rollback_bug", SSL_OP_TLS_ROLLBACK_BUG },
#endif
};

#ifndef MACRO_PREDEF
static int exim_openssl_options_size = nelem(exim_openssl_options);
#endif

#ifdef MACRO_PREDEF
void
options_tls(void)
{
struct exim_openssl_option * o;
uschar buf[64];

for (o = exim_openssl_options;
     o < exim_openssl_options + nelem(exim_openssl_options); o++)
  {
  /* Trailing X is workaround for problem with _OPT_OPENSSL_NO_TLSV1
  being a ".ifdef _OPT_OPENSSL_NO_TLSV1_3" match */

  spf(buf, sizeof(buf), US"_OPT_OPENSSL_%T_X", o->name);
  builtin_macro_create(buf);
  }
}
#else

/******************************************************************************/

/* Structure for collecting random data for seeding. */

typedef struct randstuff {
  struct timeval tv;
  pid_t          p;
} randstuff;

/* Local static variables */

static BOOL client_verify_callback_called = FALSE;
static BOOL server_verify_callback_called = FALSE;
static const uschar *sid_ctx = US"exim";

/* We have three different contexts to care about.

Simple case: client, `client_ctx`
 As a client, we can be doing a callout or cut-through delivery while receiving
 a message.  So we have a client context, which should have options initialised
 from the SMTP Transport.  We may also concurrently want to make TLS connections
 to utility daemons, so client-contexts are allocated and passed around in call
 args rather than using a gobal.

Server:
 There are two cases: with and without ServerNameIndication from the client.
 Given TLS SNI, we can be using different keys, certs and various other
 configuration settings, because they're re-expanded with $tls_sni set.  This
 allows vhosting with TLS.  This SNI is sent in the handshake.
 A client might not send SNI, so we need a fallback, and an initial setup too.
 So as a server, we start out using `server_ctx`.
 If SNI is sent by the client, then we as server, mid-negotiation, try to clone
 `server_sni` from `server_ctx` and then initialise settings by re-expanding
 configuration.
*/

typedef struct {
  SSL_CTX *	ctx;
  SSL *		ssl;
} exim_openssl_client_tls_ctx;

static SSL_CTX *server_ctx = NULL;
static SSL     *server_ssl = NULL;

#ifdef EXIM_HAVE_OPENSSL_TLSEXT
static SSL_CTX *server_sni = NULL;
#endif

static char ssl_errstring[256];

static int  ssl_session_timeout = 200;
static BOOL client_verify_optional = FALSE;
static BOOL server_verify_optional = FALSE;

static BOOL reexpand_tls_files_for_sni = FALSE;


typedef struct tls_ext_ctx_cb {
  uschar *certificate;
  uschar *privatekey;
  BOOL is_server;
#ifndef DISABLE_OCSP
  STACK_OF(X509) *verify_stack;		/* chain for verifying the proof */
  union {
    struct {
      uschar        *file;
      uschar        *file_expanded;
      OCSP_RESPONSE *response;
    } server;
    struct {
      X509_STORE    *verify_store;	/* non-null if status requested */
      BOOL	    verify_required;
    } client;
  } u_ocsp;
#endif
  uschar *dhparam;
  /* these are cached from first expand */
  uschar *server_cipher_list;
  /* only passed down to tls_error: */
  host_item *host;
  const uschar * verify_cert_hostnames;
#ifndef DISABLE_EVENT
  uschar * event_action;
#endif
} tls_ext_ctx_cb;

/* should figure out a cleanup of API to handle state preserved per
implementation, for various reasons, which can be void * in the APIs.
For now, we hack around it. */
tls_ext_ctx_cb *client_static_cbinfo = NULL;
tls_ext_ctx_cb *server_static_cbinfo = NULL;

static int
setup_certs(SSL_CTX *sctx, uschar *certs, uschar *crl, host_item *host, BOOL optional,
    int (*cert_vfy_cb)(int, X509_STORE_CTX *), uschar ** errstr );

/* Callbacks */
#ifdef EXIM_HAVE_OPENSSL_TLSEXT
static int tls_servername_cb(SSL *s, int *ad ARG_UNUSED, void *arg);
#endif
#ifndef DISABLE_OCSP
static int tls_server_stapling_cb(SSL *s, void *arg);
#endif


/*************************************************
*               Handle TLS error                 *
*************************************************/

/* Called from lots of places when errors occur before actually starting to do
the TLS handshake, that is, while the session is still in clear. Always returns
DEFER for a server and FAIL for a client so that most calls can use "return
tls_error(...)" to do this processing and then give an appropriate return. A
single function is used for both server and client, because it is called from
some shared functions.

Argument:
  prefix    text to include in the logged error
  host      NULL if setting up a server;
            the connected host if setting up a client
  msg       error message or NULL if we should ask OpenSSL
  errstr    pointer to output error message

Returns:    OK/DEFER/FAIL
*/

static int
tls_error(uschar * prefix, const host_item * host, uschar * msg, uschar ** errstr)
{
if (!msg)
  {
  ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
  msg = US ssl_errstring;
  }

msg = string_sprintf("(%s): %s", prefix, msg);
DEBUG(D_tls) debug_printf("TLS error '%s'\n", msg);
if (errstr) *errstr = msg;
return host ? FAIL : DEFER;
}



/*************************************************
*        Callback to generate RSA key            *
*************************************************/

/*
Arguments:
  s          SSL connection (not used)
  export     not used
  keylength  keylength

Returns:     pointer to generated key
*/

static RSA *
rsa_callback(SSL *s, int export, int keylength)
{
RSA *rsa_key;
#ifdef EXIM_HAVE_RSA_GENKEY_EX
BIGNUM *bn = BN_new();
#endif

export = export;     /* Shut picky compilers up */
DEBUG(D_tls) debug_printf("Generating %d bit RSA key...\n", keylength);

#ifdef EXIM_HAVE_RSA_GENKEY_EX
if (  !BN_set_word(bn, (unsigned long)RSA_F4)
   || !(rsa_key = RSA_new())
   || !RSA_generate_key_ex(rsa_key, keylength, bn, NULL)
   )
#else
if (!(rsa_key = RSA_generate_key(keylength, RSA_F4, NULL, NULL)))
#endif

  {
  ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
  log_write(0, LOG_MAIN|LOG_PANIC, "TLS error (RSA_generate_key): %s",
    ssl_errstring);
  return NULL;
  }
return rsa_key;
}



/* Extreme debug
#ifndef DISABLE_OCSP
void
x509_store_dump_cert_s_names(X509_STORE * store)
{
STACK_OF(X509_OBJECT) * roots= store->objs;
int i;
static uschar name[256];

for(i= 0; i<sk_X509_OBJECT_num(roots); i++)
  {
  X509_OBJECT * tmp_obj= sk_X509_OBJECT_value(roots, i);
  if(tmp_obj->type == X509_LU_X509)
    {
    X509_NAME * sn = X509_get_subject_name(tmp_obj->data.x509);
    if (X509_NAME_oneline(sn, CS name, sizeof(name)))
      {
      name[sizeof(name)-1] = '\0';
      debug_printf(" %s\n", name);
      }
    }
  }
}
#endif
*/


#ifndef DISABLE_EVENT
static int
verify_event(tls_support * tlsp, X509 * cert, int depth, const uschar * dn,
  BOOL *calledp, const BOOL *optionalp, const uschar * what)
{
uschar * ev;
uschar * yield;
X509 * old_cert;

ev = tlsp == &tls_out ? client_static_cbinfo->event_action : event_action;
if (ev)
  {
  DEBUG(D_tls) debug_printf("verify_event: %s %d\n", what, depth);
  old_cert = tlsp->peercert;
  tlsp->peercert = X509_dup(cert);
  /* NB we do not bother setting peerdn */
  if ((yield = event_raise(ev, US"tls:cert", string_sprintf("%d", depth))))
    {
    log_write(0, LOG_MAIN, "[%s] %s verify denied by event-action: "
		"depth=%d cert=%s: %s",
	      tlsp == &tls_out ? deliver_host_address : sender_host_address,
	      what, depth, dn, yield);
    *calledp = TRUE;
    if (!*optionalp)
      {
      if (old_cert) tlsp->peercert = old_cert;	/* restore 1st failing cert */
      return 1;			    /* reject (leaving peercert set) */
      }
    DEBUG(D_tls) debug_printf("Event-action verify failure overridden "
      "(host in tls_try_verify_hosts)\n");
    }
  X509_free(tlsp->peercert);
  tlsp->peercert = old_cert;
  }
return 0;
}
#endif

/*************************************************
*        Callback for verification               *
*************************************************/

/* The SSL library does certificate verification if set up to do so. This
callback has the current yes/no state is in "state". If verification succeeded,
we set the certificate-verified flag. If verification failed, what happens
depends on whether the client is required to present a verifiable certificate
or not.

If verification is optional, we change the state to yes, but still log the
verification error. For some reason (it really would help to have proper
documentation of OpenSSL), this callback function then gets called again, this
time with state = 1.  We must take care not to set the private verified flag on
the second time through.

Note: this function is not called if the client fails to present a certificate
when asked. We get here only if a certificate has been received. Handling of
optional verification for this case is done when requesting SSL to verify, by
setting SSL_VERIFY_FAIL_IF_NO_PEER_CERT in the non-optional case.

May be called multiple times for different issues with a certificate, even
for a given "depth" in the certificate chain.

Arguments:
  preverify_ok current yes/no state as 1/0
  x509ctx      certificate information.
  tlsp         per-direction (client vs. server) support data
  calledp      has-been-called flag
  optionalp    verification-is-optional flag

Returns:     0 if verification should fail, otherwise 1
*/

static int
verify_callback(int preverify_ok, X509_STORE_CTX * x509ctx,
  tls_support * tlsp, BOOL * calledp, BOOL * optionalp)
{
X509 * cert = X509_STORE_CTX_get_current_cert(x509ctx);
int depth = X509_STORE_CTX_get_error_depth(x509ctx);
uschar dn[256];

if (!X509_NAME_oneline(X509_get_subject_name(cert), CS dn, sizeof(dn)))
  {
  DEBUG(D_tls) debug_printf("X509_NAME_oneline() error\n");
  log_write(0, LOG_MAIN, "[%s] SSL verify error: internal error",
    tlsp == &tls_out ? deliver_host_address : sender_host_address);
  return 0;
  }
dn[sizeof(dn)-1] = '\0';

if (preverify_ok == 0)
  {
  uschar * extra = verify_mode ? string_sprintf(" (during %c-verify for [%s])",
      *verify_mode, sender_host_address)
    : US"";
  log_write(0, LOG_MAIN, "[%s] SSL verify error%s: depth=%d error=%s cert=%s",
    tlsp == &tls_out ? deliver_host_address : sender_host_address,
    extra, depth,
    X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509ctx)), dn);
  *calledp = TRUE;
  if (!*optionalp)
    {
    if (!tlsp->peercert)
      tlsp->peercert = X509_dup(cert);	/* record failing cert */
    return 0;				/* reject */
    }
  DEBUG(D_tls) debug_printf("SSL verify failure overridden (host in "
    "tls_try_verify_hosts)\n");
  }

else if (depth != 0)
  {
  DEBUG(D_tls) debug_printf("SSL verify ok: depth=%d SN=%s\n", depth, dn);
#ifndef DISABLE_OCSP
  if (tlsp == &tls_out && client_static_cbinfo->u_ocsp.client.verify_store)
    {	/* client, wanting stapling  */
    /* Add the server cert's signing chain as the one
    for the verification of the OCSP stapled information. */

    if (!X509_STORE_add_cert(client_static_cbinfo->u_ocsp.client.verify_store,
                             cert))
      ERR_clear_error();
    sk_X509_push(client_static_cbinfo->verify_stack, cert);
    }
#endif
#ifndef DISABLE_EVENT
    if (verify_event(tlsp, cert, depth, dn, calledp, optionalp, US"SSL"))
      return 0;				/* reject, with peercert set */
#endif
  }
else
  {
  const uschar * verify_cert_hostnames;

  if (  tlsp == &tls_out
     && ((verify_cert_hostnames = client_static_cbinfo->verify_cert_hostnames)))
	/* client, wanting hostname check */
    {

#ifdef EXIM_HAVE_OPENSSL_CHECKHOST
# ifndef X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
#  define X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS 0
# endif
# ifndef X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS
#  define X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS 0
# endif
    int sep = 0;
    const uschar * list = verify_cert_hostnames;
    uschar * name;
    int rc;
    while ((name = string_nextinlist(&list, &sep, NULL, 0)))
      if ((rc = X509_check_host(cert, CCS name, 0,
		  X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
		  | X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS,
		  NULL)))
	{
	if (rc < 0)
	  {
	  log_write(0, LOG_MAIN, "[%s] SSL verify error: internal error",
	    tlsp == &tls_out ? deliver_host_address : sender_host_address);
	  name = NULL;
	  }
	break;
	}
    if (!name)
#else
    if (!tls_is_name_for_cert(verify_cert_hostnames, cert))
#endif
      {
      uschar * extra = verify_mode
        ? string_sprintf(" (during %c-verify for [%s])",
	  *verify_mode, sender_host_address)
	: US"";
      log_write(0, LOG_MAIN,
	"[%s] SSL verify error%s: certificate name mismatch: DN=\"%s\" H=\"%s\"",
	tlsp == &tls_out ? deliver_host_address : sender_host_address,
	extra, dn, verify_cert_hostnames);
      *calledp = TRUE;
      if (!*optionalp)
	{
	if (!tlsp->peercert)
	  tlsp->peercert = X509_dup(cert);	/* record failing cert */
	return 0;				/* reject */
	}
      DEBUG(D_tls) debug_printf("SSL verify failure overridden (host in "
	"tls_try_verify_hosts)\n");
      }
    }

#ifndef DISABLE_EVENT
  if (verify_event(tlsp, cert, depth, dn, calledp, optionalp, US"SSL"))
    return 0;				/* reject, with peercert set */
#endif

  DEBUG(D_tls) debug_printf("SSL%s verify ok: depth=0 SN=%s\n",
    *calledp ? "" : " authenticated", dn);
  if (!*calledp) tlsp->certificate_verified = TRUE;
  *calledp = TRUE;
  }

return 1;   /* accept, at least for this level */
}

static int
verify_callback_client(int preverify_ok, X509_STORE_CTX *x509ctx)
{
return verify_callback(preverify_ok, x509ctx, &tls_out,
  &client_verify_callback_called, &client_verify_optional);
}

static int
verify_callback_server(int preverify_ok, X509_STORE_CTX *x509ctx)
{
return verify_callback(preverify_ok, x509ctx, &tls_in,
  &server_verify_callback_called, &server_verify_optional);
}


#ifdef SUPPORT_DANE

/* This gets called *by* the dane library verify callback, which interposes
itself.
*/
static int
verify_callback_client_dane(int preverify_ok, X509_STORE_CTX * x509ctx)
{
X509 * cert = X509_STORE_CTX_get_current_cert(x509ctx);
uschar dn[256];
int depth = X509_STORE_CTX_get_error_depth(x509ctx);
#ifndef DISABLE_EVENT
BOOL dummy_called, optional = FALSE;
#endif

if (!X509_NAME_oneline(X509_get_subject_name(cert), CS dn, sizeof(dn)))
  {
  DEBUG(D_tls) debug_printf("X509_NAME_oneline() error\n");
  log_write(0, LOG_MAIN, "[%s] SSL verify error: internal error",
    deliver_host_address);
  return 0;
  }
dn[sizeof(dn)-1] = '\0';

DEBUG(D_tls) debug_printf("verify_callback_client_dane: %s depth %d %s\n",
  preverify_ok ? "ok":"BAD", depth, dn);

#ifndef DISABLE_EVENT
  if (verify_event(&tls_out, cert, depth, dn,
	  &dummy_called, &optional, US"DANE"))
    return 0;				/* reject, with peercert set */
#endif

if (preverify_ok == 1)
  {
  tls_out.dane_verified = tls_out.certificate_verified = TRUE;
#ifndef DISABLE_OCSP
  if (client_static_cbinfo->u_ocsp.client.verify_store)
    {	/* client, wanting stapling  */
    /* Add the server cert's signing chain as the one
    for the verification of the OCSP stapled information. */

    if (!X509_STORE_add_cert(client_static_cbinfo->u_ocsp.client.verify_store,
                             cert))
      ERR_clear_error();
    sk_X509_push(client_static_cbinfo->verify_stack, cert);
    }
#endif
  }
else
  {
  int err = X509_STORE_CTX_get_error(x509ctx);
  DEBUG(D_tls)
    debug_printf(" - err %d '%s'\n", err, X509_verify_cert_error_string(err));
  if (err == X509_V_ERR_APPLICATION_VERIFICATION)
    preverify_ok = 1;
  }
return preverify_ok;
}

#endif	/*SUPPORT_DANE*/


/*************************************************
*           Information callback                 *
*************************************************/

/* The SSL library functions call this from time to time to indicate what they
are doing. We copy the string to the debugging output when TLS debugging has
been requested.

Arguments:
  s         the SSL connection
  where
  ret

Returns:    nothing
*/

static void
info_callback(SSL *s, int where, int ret)
{
DEBUG(D_tls)
  {
  const uschar * str;

  if (where & SSL_ST_CONNECT)
     str = US"SSL_connect";
  else if (where & SSL_ST_ACCEPT)
     str = US"SSL_accept";
  else
     str = US"SSL info (undefined)";

  if (where & SSL_CB_LOOP)
     debug_printf("%s: %s\n", str, SSL_state_string_long(s));
  else if (where & SSL_CB_ALERT)
    debug_printf("SSL3 alert %s:%s:%s\n",
	  str = where & SSL_CB_READ ? US"read" : US"write",
	  SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
  else if (where & SSL_CB_EXIT)
     if (ret == 0)
	debug_printf("%s: failed in %s\n", str, SSL_state_string_long(s));
     else if (ret < 0)
	debug_printf("%s: error in %s\n", str, SSL_state_string_long(s));
  else if (where & SSL_CB_HANDSHAKE_START)
     debug_printf("%s: hshake start: %s\n", str, SSL_state_string_long(s));
  else if (where & SSL_CB_HANDSHAKE_DONE)
     debug_printf("%s: hshake done: %s\n", str, SSL_state_string_long(s));
  }
}



/*************************************************
*                Initialize for DH               *
*************************************************/

/* If dhparam is set, expand it, and load up the parameters for DH encryption.

Arguments:
  sctx      The current SSL CTX (inbound or outbound)
  dhparam   DH parameter file or fixed parameter identity string
  host      connected host, if client; NULL if server
  errstr    error string pointer

Returns:    TRUE if OK (nothing to set up, or setup worked)
*/

static BOOL
init_dh(SSL_CTX *sctx, uschar *dhparam, const host_item *host, uschar ** errstr)
{
BIO *bio;
DH *dh;
uschar *dhexpanded;
const char *pem;
int dh_bitsize;

if (!expand_check(dhparam, US"tls_dhparam", &dhexpanded, errstr))
  return FALSE;

if (!dhexpanded || !*dhexpanded)
  bio = BIO_new_mem_buf(CS std_dh_prime_default(), -1);
else if (dhexpanded[0] == '/')
  {
  if (!(bio = BIO_new_file(CS dhexpanded, "r")))
    {
    tls_error(string_sprintf("could not read dhparams file %s", dhexpanded),
          host, US strerror(errno), errstr);
    return FALSE;
    }
  }
else
  {
  if (Ustrcmp(dhexpanded, "none") == 0)
    {
    DEBUG(D_tls) debug_printf("Requested no DH parameters.\n");
    return TRUE;
    }

  if (!(pem = std_dh_prime_named(dhexpanded)))
    {
    tls_error(string_sprintf("Unknown standard DH prime \"%s\"", dhexpanded),
        host, US strerror(errno), errstr);
    return FALSE;
    }
  bio = BIO_new_mem_buf(CS pem, -1);
  }

if (!(dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL)))
  {
  BIO_free(bio);
  tls_error(string_sprintf("Could not read tls_dhparams \"%s\"", dhexpanded),
      host, NULL, errstr);
  return FALSE;
  }

/* note: our default limit of 2236 is not a multiple of 8; the limit comes from
 * an NSS limit, and the GnuTLS APIs handle bit-sizes fine, so we went with
 * 2236.  But older OpenSSL can only report in bytes (octets), not bits.
 * If someone wants to dance at the edge, then they can raise the limit or use
 * current libraries. */
#ifdef EXIM_HAVE_OPENSSL_DH_BITS
/* Added in commit 26c79d5641d; `git describe --contains` says OpenSSL_1_1_0-pre1~1022
 * This predates OpenSSL_1_1_0 (before a, b, ...) so is in all 1.1.0 */
dh_bitsize = DH_bits(dh);
#else
dh_bitsize = 8 * DH_size(dh);
#endif

/* Even if it is larger, we silently return success rather than cause things
 * to fail out, so that a too-large DH will not knock out all TLS; it's a
 * debatable choice. */
if (dh_bitsize > tls_dh_max_bits)
  {
  DEBUG(D_tls)
    debug_printf("dhparams file %d bits, is > tls_dh_max_bits limit of %d\n",
        dh_bitsize, tls_dh_max_bits);
  }
else
  {
  SSL_CTX_set_tmp_dh(sctx, dh);
  DEBUG(D_tls)
    debug_printf("Diffie-Hellman initialized from %s with %d-bit prime\n",
      dhexpanded ? dhexpanded : US"default", dh_bitsize);
  }

DH_free(dh);
BIO_free(bio);

return TRUE;
}




/*************************************************
*               Initialize for ECDH              *
*************************************************/

/* Load parameters for ECDH encryption.

For now, we stick to NIST P-256 because: it's simple and easy to configure;
it avoids any patent issues that might bite redistributors; despite events in
the news and concerns over curve choices, we're not cryptographers, we're not
pretending to be, and this is "good enough" to be better than no support,
protecting against most adversaries.  Given another year or two, there might
be sufficient clarity about a "right" way forward to let us make an informed
decision, instead of a knee-jerk reaction.

Longer-term, we should look at supporting both various named curves and
external files generated with "openssl ecparam", much as we do for init_dh().
We should also support "none" as a value, to explicitly avoid initialisation.

Patches welcome.

Arguments:
  sctx      The current SSL CTX (inbound or outbound)
  host      connected host, if client; NULL if server
  errstr    error string pointer

Returns:    TRUE if OK (nothing to set up, or setup worked)
*/

static BOOL
init_ecdh(SSL_CTX * sctx, host_item * host, uschar ** errstr)
{
#ifdef OPENSSL_NO_ECDH
return TRUE;
#else

EC_KEY * ecdh;
uschar * exp_curve;
int nid;
BOOL rv;

if (host)	/* No ECDH setup for clients, only for servers */
  return TRUE;

# ifndef EXIM_HAVE_ECDH
DEBUG(D_tls)
  debug_printf("No OpenSSL API to define ECDH parameters, skipping\n");
return TRUE;
# else

if (!expand_check(tls_eccurve, US"tls_eccurve", &exp_curve, errstr))
  return FALSE;
if (!exp_curve || !*exp_curve)
  return TRUE;

/* "auto" needs to be handled carefully.
 * OpenSSL <  1.0.2: we do not select anything, but fallback to prime256v1
 * OpenSSL <  1.1.0: we have to call SSL_CTX_set_ecdh_auto
 *                   (openssl/ssl.h defines SSL_CTRL_SET_ECDH_AUTO)
 * OpenSSL >= 1.1.0: we do not set anything, the libray does autoselection
 *                   https://github.com/openssl/openssl/commit/fe6ef2472db933f01b59cad82aa925736935984b
 */
if (Ustrcmp(exp_curve, "auto") == 0)
  {
#if OPENSSL_VERSION_NUMBER < 0x10002000L
  DEBUG(D_tls) debug_printf(
    "ECDH OpenSSL < 1.0.2: temp key parameter settings: overriding \"auto\" with \"prime256v1\"\n");
  exp_curve = US"prime256v1";
#else
# if defined SSL_CTRL_SET_ECDH_AUTO
  DEBUG(D_tls) debug_printf(
    "ECDH OpenSSL 1.0.2+ temp key parameter settings: autoselection\n");
  SSL_CTX_set_ecdh_auto(sctx, 1);
  return TRUE;
# else
  DEBUG(D_tls) debug_printf(
    "ECDH OpenSSL 1.1.0+ temp key parameter settings: default selection\n");
  return TRUE;
# endif
#endif
  }

DEBUG(D_tls) debug_printf("ECDH: curve '%s'\n", exp_curve);
if (  (nid = OBJ_sn2nid       (CCS exp_curve)) == NID_undef
#   ifdef EXIM_HAVE_OPENSSL_EC_NIST2NID
   && (nid = EC_curve_nist2nid(CCS exp_curve)) == NID_undef
#   endif
   )
  {
  tls_error(string_sprintf("Unknown curve name tls_eccurve '%s'", exp_curve),
    host, NULL, errstr);
  return FALSE;
  }

if (!(ecdh = EC_KEY_new_by_curve_name(nid)))
  {
  tls_error(US"Unable to create ec curve", host, NULL, errstr);
  return FALSE;
  }

/* The "tmp" in the name here refers to setting a temporary key
not to the stability of the interface. */

if ((rv = SSL_CTX_set_tmp_ecdh(sctx, ecdh) == 0))
  tls_error(string_sprintf("Error enabling '%s' curve", exp_curve), host, NULL, errstr);
else
  DEBUG(D_tls) debug_printf("ECDH: enabled '%s' curve\n", exp_curve);

EC_KEY_free(ecdh);
return !rv;

# endif	/*EXIM_HAVE_ECDH*/
#endif /*OPENSSL_NO_ECDH*/
}




#ifndef DISABLE_OCSP
/*************************************************
*       Load OCSP information into state         *
*************************************************/
/* Called to load the server OCSP response from the given file into memory, once
caller has determined this is needed.  Checks validity.  Debugs a message
if invalid.

ASSUMES: single response, for single cert.

Arguments:
  sctx            the SSL_CTX* to update
  cbinfo          various parts of session state
  expanded        the filename putatively holding an OCSP response

*/

static void
ocsp_load_response(SSL_CTX *sctx, tls_ext_ctx_cb *cbinfo, const uschar *expanded)
{
BIO * bio;
OCSP_RESPONSE * resp;
OCSP_BASICRESP * basic_response;
OCSP_SINGLERESP * single_response;
ASN1_GENERALIZEDTIME * rev, * thisupd, * nextupd;
STACK_OF(X509) * sk;
unsigned long verify_flags;
int status, reason, i;

cbinfo->u_ocsp.server.file_expanded = string_copy(expanded);
if (cbinfo->u_ocsp.server.response)
  {
  OCSP_RESPONSE_free(cbinfo->u_ocsp.server.response);
  cbinfo->u_ocsp.server.response = NULL;
  }

if (!(bio = BIO_new_file(CS cbinfo->u_ocsp.server.file_expanded, "rb")))
  {
  DEBUG(D_tls) debug_printf("Failed to open OCSP response file \"%s\"\n",
      cbinfo->u_ocsp.server.file_expanded);
  return;
  }

resp = d2i_OCSP_RESPONSE_bio(bio, NULL);
BIO_free(bio);
if (!resp)
  {
  DEBUG(D_tls) debug_printf("Error reading OCSP response.\n");
  return;
  }

if ((status = OCSP_response_status(resp)) != OCSP_RESPONSE_STATUS_SUCCESSFUL)
  {
  DEBUG(D_tls) debug_printf("OCSP response not valid: %s (%d)\n",
      OCSP_response_status_str(status), status);
  goto bad;
  }

if (!(basic_response = OCSP_response_get1_basic(resp)))
  {
  DEBUG(D_tls)
    debug_printf("OCSP response parse error: unable to extract basic response.\n");
  goto bad;
  }

sk = cbinfo->verify_stack;
verify_flags = OCSP_NOVERIFY; /* check sigs, but not purpose */

/* May need to expose ability to adjust those flags?
OCSP_NOSIGS OCSP_NOVERIFY OCSP_NOCHAIN OCSP_NOCHECKS OCSP_NOEXPLICIT
OCSP_TRUSTOTHER OCSP_NOINTERN */

/* This does a full verify on the OCSP proof before we load it for serving
up; possibly overkill - just date-checks might be nice enough.

OCSP_basic_verify takes a "store" arg, but does not
use it for the chain verification, which is all we do
when OCSP_NOVERIFY is set.  The content from the wire
"basic_response" and a cert-stack "sk" are all that is used.

We have a stack, loaded in setup_certs() if tls_verify_certificates
was a file (not a directory, or "system").  It is unfortunate we
cannot used the connection context store, as that would neatly
handle the "system" case too, but there seems to be no library
function for getting a stack from a store.
[ In OpenSSL 1.1 - ?  X509_STORE_CTX_get0_chain(ctx) ? ]
We do not free the stack since it could be needed a second time for
SNI handling.

Separately we might try to replace using OCSP_basic_verify() - which seems to not
be a public interface into the OpenSSL library (there's no manual entry) -
But what with?  We also use OCSP_basic_verify in the client stapling callback.
And there we NEED it; we must verify that status... unless the
library does it for us anyway?  */

if ((i = OCSP_basic_verify(basic_response, sk, NULL, verify_flags)) < 0)
  {
  DEBUG(D_tls)
    {
    ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
    debug_printf("OCSP response verify failure: %s\n", US ssl_errstring);
    }
  goto bad;
  }

/* Here's the simplifying assumption: there's only one response, for the
one certificate we use, and nothing for anything else in a chain.  If this
proves false, we need to extract a cert id from our issued cert
(tls_certificate) and use that for OCSP_resp_find_status() (which finds the
right cert in the stack and then calls OCSP_single_get0_status()).

I'm hoping to avoid reworking a bunch more of how we handle state here. */

if (!(single_response = OCSP_resp_get0(basic_response, 0)))
  {
  DEBUG(D_tls)
    debug_printf("Unable to get first response from OCSP basic response.\n");
  goto bad;
  }

status = OCSP_single_get0_status(single_response, &reason, &rev, &thisupd, &nextupd);
if (status != V_OCSP_CERTSTATUS_GOOD)
  {
  DEBUG(D_tls) debug_printf("OCSP response bad cert status: %s (%d) %s (%d)\n",
      OCSP_cert_status_str(status), status,
      OCSP_crl_reason_str(reason), reason);
  goto bad;
  }

if (!OCSP_check_validity(thisupd, nextupd, EXIM_OCSP_SKEW_SECONDS, EXIM_OCSP_MAX_AGE))
  {
  DEBUG(D_tls) debug_printf("OCSP status invalid times.\n");
  goto bad;
  }

supply_response:
  cbinfo->u_ocsp.server.response = resp;	/*XXX stack?*/
return;

bad:
  if (f.running_in_test_harness)
    {
    extern char ** environ;
    uschar ** p;
    if (environ) for (p = USS environ; *p; p++)
      if (Ustrncmp(*p, "EXIM_TESTHARNESS_DISABLE_OCSPVALIDITYCHECK", 42) == 0)
	{
	DEBUG(D_tls) debug_printf("Supplying known bad OCSP response\n");
	goto supply_response;
	}
    }
return;
}
#endif	/*!DISABLE_OCSP*/




/* Create and install a selfsigned certificate, for use in server mode */

static int
tls_install_selfsign(SSL_CTX * sctx, uschar ** errstr)
{
X509 * x509 = NULL;
EVP_PKEY * pkey;
RSA * rsa;
X509_NAME * name;
uschar * where;

where = US"allocating pkey";
if (!(pkey = EVP_PKEY_new()))
  goto err;

where = US"allocating cert";
if (!(x509 = X509_new()))
  goto err;

where = US"generating pkey";
if (!(rsa = rsa_callback(NULL, 0, 2048)))
  goto err;

where = US"assigning pkey";
if (!EVP_PKEY_assign_RSA(pkey, rsa))
  goto err;

X509_set_version(x509, 2);				/* N+1 - version 3 */
ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
X509_gmtime_adj(X509_get_notBefore(x509), 0);
X509_gmtime_adj(X509_get_notAfter(x509), (long)60 * 60);	/* 1 hour */
X509_set_pubkey(x509, pkey);

name = X509_get_subject_name(x509);
X509_NAME_add_entry_by_txt(name, "C",
			  MBSTRING_ASC, CUS "UK", -1, -1, 0);
X509_NAME_add_entry_by_txt(name, "O",
			  MBSTRING_ASC, CUS "Exim Developers", -1, -1, 0);
X509_NAME_add_entry_by_txt(name, "CN",
			  MBSTRING_ASC, CUS smtp_active_hostname, -1, -1, 0);
X509_set_issuer_name(x509, name);

where = US"signing cert";
if (!X509_sign(x509, pkey, EVP_md5()))
  goto err;

where = US"installing selfsign cert";
if (!SSL_CTX_use_certificate(sctx, x509))
  goto err;

where = US"installing selfsign key";
if (!SSL_CTX_use_PrivateKey(sctx, pkey))
  goto err;

return OK;

err:
  (void) tls_error(where, NULL, NULL, errstr);
  if (x509) X509_free(x509);
  if (pkey) EVP_PKEY_free(pkey);
  return DEFER;
}




static int
tls_add_certfile(SSL_CTX * sctx, tls_ext_ctx_cb * cbinfo, uschar * file,
  uschar ** errstr)
{
DEBUG(D_tls) debug_printf("tls_certificate file %s\n", file);
if (!SSL_CTX_use_certificate_chain_file(sctx, CS file))
  return tls_error(string_sprintf(
    "SSL_CTX_use_certificate_chain_file file=%s", file),
      cbinfo->host, NULL, errstr);
return 0;
}

static int
tls_add_pkeyfile(SSL_CTX * sctx, tls_ext_ctx_cb * cbinfo, uschar * file,
  uschar ** errstr)
{
DEBUG(D_tls) debug_printf("tls_privatekey file %s\n", file);
if (!SSL_CTX_use_PrivateKey_file(sctx, CS file, SSL_FILETYPE_PEM))
  return tls_error(string_sprintf(
    "SSL_CTX_use_PrivateKey_file file=%s", file), cbinfo->host, NULL, errstr);
return 0;
}


/*************************************************
*        Expand key and cert file specs          *
*************************************************/

/* Called once during tls_init and possibly again during TLS setup, for a
new context, if Server Name Indication was used and tls_sni was seen in
the certificate string.

Arguments:
  sctx            the SSL_CTX* to update
  cbinfo          various parts of session state
  errstr	  error string pointer

Returns:          OK/DEFER/FAIL
*/

static int
tls_expand_session_files(SSL_CTX *sctx, tls_ext_ctx_cb *cbinfo,
  uschar ** errstr)
{
uschar *expanded;

if (!cbinfo->certificate)
  {
  if (!cbinfo->is_server)		/* client */
    return OK;
					/* server */
  if (tls_install_selfsign(sctx, errstr) != OK)
    return DEFER;
  }
else
  {
  int err;

  if (Ustrstr(cbinfo->certificate, US"tls_sni") ||
      Ustrstr(cbinfo->certificate, US"tls_in_sni") ||
      Ustrstr(cbinfo->certificate, US"tls_out_sni")
     )
    reexpand_tls_files_for_sni = TRUE;

  if (!expand_check(cbinfo->certificate, US"tls_certificate", &expanded, errstr))
    return DEFER;

  if (expanded)
    if (cbinfo->is_server)
      {
      const uschar * file_list = expanded;
      int sep = 0;
      uschar * file;

      while (file = string_nextinlist(&file_list, &sep, NULL, 0))
	if ((err = tls_add_certfile(sctx, cbinfo, file, errstr)))
	  return err;
      }
    else	/* would there ever be a need for multiple client certs? */
      if ((err = tls_add_certfile(sctx, cbinfo, expanded, errstr)))
	return err;

  if (  cbinfo->privatekey
     && !expand_check(cbinfo->privatekey, US"tls_privatekey", &expanded, errstr))
    return DEFER;

  /* If expansion was forced to fail, key_expanded will be NULL. If the result
  of the expansion is an empty string, ignore it also, and assume the private
  key is in the same file as the certificate. */

  if (expanded && *expanded)
    if (cbinfo->is_server)
      {
      const uschar * file_list = expanded;
      int sep = 0;
      uschar * file;

      while (file = string_nextinlist(&file_list, &sep, NULL, 0))
	if ((err = tls_add_pkeyfile(sctx, cbinfo, file, errstr)))
	  return err;
      }
    else	/* would there ever be a need for multiple client certs? */
      if ((err = tls_add_pkeyfile(sctx, cbinfo, expanded, errstr)))
	return err;
  }

#ifndef DISABLE_OCSP
if (cbinfo->is_server && cbinfo->u_ocsp.server.file)
  {
  /*XXX stack*/
  if (!expand_check(cbinfo->u_ocsp.server.file, US"tls_ocsp_file", &expanded, errstr))
    return DEFER;

  if (expanded && *expanded)
    {
    DEBUG(D_tls) debug_printf("tls_ocsp_file %s\n", expanded);
    if (  cbinfo->u_ocsp.server.file_expanded
       && (Ustrcmp(expanded, cbinfo->u_ocsp.server.file_expanded) == 0))
      {
      DEBUG(D_tls) debug_printf(" - value unchanged, using existing values\n");
      }
    else
      ocsp_load_response(sctx, cbinfo, expanded);
    }
  }
#endif

return OK;
}




/*************************************************
*            Callback to handle SNI              *
*************************************************/

/* Called when acting as server during the TLS session setup if a Server Name
Indication extension was sent by the client.

API documentation is OpenSSL s_server.c implementation.

Arguments:
  s               SSL* of the current session
  ad              unknown (part of OpenSSL API) (unused)
  arg             Callback of "our" registered data

Returns:          SSL_TLSEXT_ERR_{OK,ALERT_WARNING,ALERT_FATAL,NOACK}
*/

#ifdef EXIM_HAVE_OPENSSL_TLSEXT
static int
tls_servername_cb(SSL *s, int *ad ARG_UNUSED, void *arg)
{
const char *servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
tls_ext_ctx_cb *cbinfo = (tls_ext_ctx_cb *) arg;
int rc;
int old_pool = store_pool;
uschar * dummy_errstr;

if (!servername)
  return SSL_TLSEXT_ERR_OK;

DEBUG(D_tls) debug_printf("Received TLS SNI \"%s\"%s\n", servername,
    reexpand_tls_files_for_sni ? "" : " (unused for certificate selection)");

/* Make the extension value available for expansion */
store_pool = POOL_PERM;
tls_in.sni = string_copy(US servername);
store_pool = old_pool;

if (!reexpand_tls_files_for_sni)
  return SSL_TLSEXT_ERR_OK;

/* Can't find an SSL_CTX_clone() or equivalent, so we do it manually;
not confident that memcpy wouldn't break some internal reference counting.
Especially since there's a references struct member, which would be off. */

#ifdef EXIM_HAVE_OPENSSL_TLS_METHOD
if (!(server_sni = SSL_CTX_new(TLS_server_method())))
#else
if (!(server_sni = SSL_CTX_new(SSLv23_server_method())))
#endif
  {
  ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
  DEBUG(D_tls) debug_printf("SSL_CTX_new() failed: %s\n", ssl_errstring);
  goto bad;
  }

/* Not sure how many of these are actually needed, since SSL object
already exists.  Might even need this selfsame callback, for reneg? */

SSL_CTX_set_info_callback(server_sni, SSL_CTX_get_info_callback(server_ctx));
SSL_CTX_set_mode(server_sni, SSL_CTX_get_mode(server_ctx));
SSL_CTX_set_options(server_sni, SSL_CTX_get_options(server_ctx));
SSL_CTX_set_timeout(server_sni, SSL_CTX_get_timeout(server_ctx));
SSL_CTX_set_tlsext_servername_callback(server_sni, tls_servername_cb);
SSL_CTX_set_tlsext_servername_arg(server_sni, cbinfo);

if (  !init_dh(server_sni, cbinfo->dhparam, NULL, &dummy_errstr)
   || !init_ecdh(server_sni, NULL, &dummy_errstr)
   )
  goto bad;

if (  cbinfo->server_cipher_list
   && !SSL_CTX_set_cipher_list(server_sni, CS cbinfo->server_cipher_list))
  goto bad;

#ifndef DISABLE_OCSP
if (cbinfo->u_ocsp.server.file)
  {
  SSL_CTX_set_tlsext_status_cb(server_sni, tls_server_stapling_cb);
  SSL_CTX_set_tlsext_status_arg(server_sni, cbinfo);
  }
#endif

if ((rc = setup_certs(server_sni, tls_verify_certificates, tls_crl, NULL, FALSE,
		      verify_callback_server, &dummy_errstr)) != OK)
  goto bad;

/* do this after setup_certs, because this can require the certs for verifying
OCSP information. */
if ((rc = tls_expand_session_files(server_sni, cbinfo, &dummy_errstr)) != OK)
  goto bad;

DEBUG(D_tls) debug_printf("Switching SSL context.\n");
SSL_set_SSL_CTX(s, server_sni);
return SSL_TLSEXT_ERR_OK;

bad: return SSL_TLSEXT_ERR_ALERT_FATAL;
}
#endif /* EXIM_HAVE_OPENSSL_TLSEXT */




#ifndef DISABLE_OCSP

/*************************************************
*        Callback to handle OCSP Stapling        *
*************************************************/

/* Called when acting as server during the TLS session setup if the client
requests OCSP information with a Certificate Status Request.

Documentation via openssl s_server.c and the Apache patch from the OpenSSL
project.

*/

static int
tls_server_stapling_cb(SSL *s, void *arg)
{
const tls_ext_ctx_cb *cbinfo = (tls_ext_ctx_cb *) arg;
uschar *response_der;	/*XXX blob */
int response_der_len;

/*XXX stack: use SSL_get_certificate() to see which cert; from that work
out which ocsp blob to send.  Unfortunately, SSL_get_certificate is known
buggy in current OpenSSL; it returns the last cert loaded always rather than
the one actually presented.  So we can't support a stack of OCSP proofs at
this time. */

DEBUG(D_tls)
  debug_printf("Received TLS status request (OCSP stapling); %s response\n",
    cbinfo->u_ocsp.server.response ? "have" : "lack");

tls_in.ocsp = OCSP_NOT_RESP;
if (!cbinfo->u_ocsp.server.response)
  return SSL_TLSEXT_ERR_NOACK;

response_der = NULL;
response_der_len = i2d_OCSP_RESPONSE(cbinfo->u_ocsp.server.response,	/*XXX stack*/
		      &response_der);
if (response_der_len <= 0)
  return SSL_TLSEXT_ERR_NOACK;

SSL_set_tlsext_status_ocsp_resp(server_ssl, response_der, response_der_len);
tls_in.ocsp = OCSP_VFIED;
return SSL_TLSEXT_ERR_OK;
}


static void
time_print(BIO * bp, const char * str, ASN1_GENERALIZEDTIME * time)
{
BIO_printf(bp, "\t%s: ", str);
ASN1_GENERALIZEDTIME_print(bp, time);
BIO_puts(bp, "\n");
}

static int
tls_client_stapling_cb(SSL *s, void *arg)
{
tls_ext_ctx_cb * cbinfo = arg;
const unsigned char * p;
int len;
OCSP_RESPONSE * rsp;
OCSP_BASICRESP * bs;
int i;

DEBUG(D_tls) debug_printf("Received TLS status response (OCSP stapling):");
len = SSL_get_tlsext_status_ocsp_resp(s, &p);
if(!p)
 {
  /* Expect this when we requested ocsp but got none */
  if (cbinfo->u_ocsp.client.verify_required && LOGGING(tls_cipher))
    log_write(0, LOG_MAIN, "Received TLS status callback, null content");
  else
    DEBUG(D_tls) debug_printf(" null\n");
  return cbinfo->u_ocsp.client.verify_required ? 0 : 1;
 }

if(!(rsp = d2i_OCSP_RESPONSE(NULL, &p, len)))
 {
  tls_out.ocsp = OCSP_FAILED;
  if (LOGGING(tls_cipher))
    log_write(0, LOG_MAIN, "Received TLS cert status response, parse error");
  else
    DEBUG(D_tls) debug_printf(" parse error\n");
  return 0;
 }

if(!(bs = OCSP_response_get1_basic(rsp)))
  {
  tls_out.ocsp = OCSP_FAILED;
  if (LOGGING(tls_cipher))
    log_write(0, LOG_MAIN, "Received TLS cert status response, error parsing response");
  else
    DEBUG(D_tls) debug_printf(" error parsing response\n");
  OCSP_RESPONSE_free(rsp);
  return 0;
  }

/* We'd check the nonce here if we'd put one in the request. */
/* However that would defeat cacheability on the server so we don't. */

/* This section of code reworked from OpenSSL apps source;
   The OpenSSL Project retains copyright:
   Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
*/
  {
    BIO * bp = NULL;
    int status, reason;
    ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;

    DEBUG(D_tls) bp = BIO_new_fp(debug_file, BIO_NOCLOSE);

    /*OCSP_RESPONSE_print(bp, rsp, 0);   extreme debug: stapling content */

    /* Use the chain that verified the server cert to verify the stapled info */
    /* DEBUG(D_tls) x509_store_dump_cert_s_names(cbinfo->u_ocsp.client.verify_store); */

    if ((i = OCSP_basic_verify(bs, cbinfo->verify_stack,
	      cbinfo->u_ocsp.client.verify_store, 0)) <= 0)
      {
      tls_out.ocsp = OCSP_FAILED;
      if (LOGGING(tls_cipher)) log_write(0, LOG_MAIN,
	      "Received TLS cert status response, itself unverifiable: %s",
	      ERR_reason_error_string(ERR_peek_error()));
      BIO_printf(bp, "OCSP response verify failure\n");
      ERR_print_errors(bp);
      OCSP_RESPONSE_print(bp, rsp, 0);
      goto failed;
      }

    BIO_printf(bp, "OCSP response well-formed and signed OK\n");

    /*XXX So we have a good stapled OCSP status.  How do we know
    it is for the cert of interest?  OpenSSL 1.1.0 has a routine
    OCSP_resp_find_status() which matches on a cert id, which presumably
    we should use. Making an id needs OCSP_cert_id_new(), which takes
    issuerName, issuerKey, serialNumber.  Are they all in the cert?

    For now, carry on blindly accepting the resp. */

      {
      OCSP_SINGLERESP * single;

#ifdef EXIM_HAVE_OCSP_RESP_COUNT
      if (OCSP_resp_count(bs) != 1)
#else
      STACK_OF(OCSP_SINGLERESP) * sresp = bs->tbsResponseData->responses;
      if (sk_OCSP_SINGLERESP_num(sresp) != 1)
#endif
        {
	tls_out.ocsp = OCSP_FAILED;
        log_write(0, LOG_MAIN, "OCSP stapling "
	    "with multiple responses not handled");
        goto failed;
        }
      single = OCSP_resp_get0(bs, 0);
      status = OCSP_single_get0_status(single, &reason, &rev,
		  &thisupd, &nextupd);
      }

    DEBUG(D_tls) time_print(bp, "This OCSP Update", thisupd);
    DEBUG(D_tls) if(nextupd) time_print(bp, "Next OCSP Update", nextupd);
    if (!OCSP_check_validity(thisupd, nextupd,
	  EXIM_OCSP_SKEW_SECONDS, EXIM_OCSP_MAX_AGE))
      {
      tls_out.ocsp = OCSP_FAILED;
      DEBUG(D_tls) ERR_print_errors(bp);
      log_write(0, LOG_MAIN, "Server OSCP dates invalid");
      }
    else
      {
      DEBUG(D_tls) BIO_printf(bp, "Certificate status: %s\n",
		    OCSP_cert_status_str(status));
      switch(status)
	{
	case V_OCSP_CERTSTATUS_GOOD:
	  tls_out.ocsp = OCSP_VFIED;
	  i = 1;
	  goto good;
	case V_OCSP_CERTSTATUS_REVOKED:
	  tls_out.ocsp = OCSP_FAILED;
	  log_write(0, LOG_MAIN, "Server certificate revoked%s%s",
	      reason != -1 ? "; reason: " : "",
	      reason != -1 ? OCSP_crl_reason_str(reason) : "");
	  DEBUG(D_tls) time_print(bp, "Revocation Time", rev);
	  break;
	default:
	  tls_out.ocsp = OCSP_FAILED;
	  log_write(0, LOG_MAIN,
	      "Server certificate status unknown, in OCSP stapling");
	  break;
	}
      }
  failed:
    i = cbinfo->u_ocsp.client.verify_required ? 0 : 1;
  good:
    BIO_free(bp);
  }

OCSP_RESPONSE_free(rsp);
return i;
}
#endif	/*!DISABLE_OCSP*/


/*************************************************
*            Initialize for TLS                  *
*************************************************/

/* Called from both server and client code, to do preliminary initialization
of the library.  We allocate and return a context structure.

Arguments:
  ctxp            returned SSL context
  host            connected host, if client; NULL if server
  dhparam         DH parameter file
  certificate     certificate file
  privatekey      private key
  ocsp_file       file of stapling info (server); flag for require ocsp (client)
  addr            address if client; NULL if server (for some randomness)
  cbp             place to put allocated callback context
  errstr	  error string pointer

Returns:          OK/DEFER/FAIL
*/

static int
tls_init(SSL_CTX **ctxp, host_item *host, uschar *dhparam, uschar *certificate,
  uschar *privatekey,
#ifndef DISABLE_OCSP
  uschar *ocsp_file,	/*XXX stack, in server*/
#endif
  address_item *addr, tls_ext_ctx_cb ** cbp, uschar ** errstr)
{
SSL_CTX * ctx;
long init_options;
int rc;
tls_ext_ctx_cb * cbinfo;

cbinfo = store_malloc(sizeof(tls_ext_ctx_cb));
cbinfo->certificate = certificate;
cbinfo->privatekey = privatekey;
cbinfo->is_server = host==NULL;
#ifndef DISABLE_OCSP
cbinfo->verify_stack = NULL;
if (!host)
  {
  cbinfo->u_ocsp.server.file = ocsp_file;
  cbinfo->u_ocsp.server.file_expanded = NULL;
  cbinfo->u_ocsp.server.response = NULL;
  }
else
  cbinfo->u_ocsp.client.verify_store = NULL;
#endif
cbinfo->dhparam = dhparam;
cbinfo->server_cipher_list = NULL;
cbinfo->host = host;
#ifndef DISABLE_EVENT
cbinfo->event_action = NULL;
#endif

#ifdef EXIM_NEED_OPENSSL_INIT
SSL_load_error_strings();          /* basic set up */
OpenSSL_add_ssl_algorithms();
#endif

#ifdef EXIM_HAVE_SHA256
/* SHA256 is becoming ever more popular. This makes sure it gets added to the
list of available digests. */
EVP_add_digest(EVP_sha256());
#endif

/* Create a context.
The OpenSSL docs in 1.0.1b have not been updated to clarify TLS variant
negotiation in the different methods; as far as I can tell, the only
*_{server,client}_method which allows negotiation is SSLv23, which exists even
when OpenSSL is built without SSLv2 support.
By disabling with openssl_options, we can let admins re-enable with the
existing knob. */

#ifdef EXIM_HAVE_OPENSSL_TLS_METHOD
if (!(ctx = SSL_CTX_new(host ? TLS_client_method() : TLS_server_method())))
#else
if (!(ctx = SSL_CTX_new(host ? SSLv23_client_method() : SSLv23_server_method())))
#endif
  return tls_error(US"SSL_CTX_new", host, NULL, errstr);

/* It turns out that we need to seed the random number generator this early in
order to get the full complement of ciphers to work. It took me roughly a day
of work to discover this by experiment.

On systems that have /dev/urandom, SSL may automatically seed itself from
there. Otherwise, we have to make something up as best we can. Double check
afterwards. */

if (!RAND_status())
  {
  randstuff r;
  gettimeofday(&r.tv, NULL);
  r.p = getpid();

  RAND_seed(US (&r), sizeof(r));
  RAND_seed(US big_buffer, big_buffer_size);
  if (addr != NULL) RAND_seed(US addr, sizeof(addr));

  if (!RAND_status())
    return tls_error(US"RAND_status", host,
      US"unable to seed random number generator", errstr);
  }

/* Set up the information callback, which outputs if debugging is at a suitable
level. */

DEBUG(D_tls) SSL_CTX_set_info_callback(ctx, (void (*)())info_callback);

/* Automatically re-try reads/writes after renegotiation. */
(void) SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

/* Apply administrator-supplied work-arounds.
Historically we applied just one requested option,
SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS, but when bug 994 requested a second, we
moved to an administrator-controlled list of options to specify and
grandfathered in the first one as the default value for "openssl_options".

No OpenSSL version number checks: the options we accept depend upon the
availability of the option value macros from OpenSSL.  */

if (!tls_openssl_options_parse(openssl_options, &init_options))
  return tls_error(US"openssl_options parsing failed", host, NULL, errstr);

if (init_options)
  {
  DEBUG(D_tls) debug_printf("setting SSL CTX options: %#lx\n", init_options);
  if (!(SSL_CTX_set_options(ctx, init_options)))
    return tls_error(string_sprintf(
          "SSL_CTX_set_option(%#lx)", init_options), host, NULL, errstr);
  }
else
  DEBUG(D_tls) debug_printf("no SSL CTX options to set\n");

/* We'd like to disable session cache unconditionally, but foolish Outlook
Express clients then give up the first TLS connection and make a second one
(which works).  Only when there is an IMAP service on the same machine.
Presumably OE is trying to use the cache for A on B.  Leave it enabled for
now, until we work out a decent way of presenting control to the config.  It
will never be used because we use a new context every time. */
#ifdef notdef
(void) SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
#endif

/* Initialize with DH parameters if supplied */
/* Initialize ECDH temp key parameter selection */

if (  !init_dh(ctx, dhparam, host, errstr)
   || !init_ecdh(ctx, host, errstr)
   )
  return DEFER;

/* Set up certificate and key (and perhaps OCSP info) */

if ((rc = tls_expand_session_files(ctx, cbinfo, errstr)) != OK)
  return rc;

/* If we need to handle SNI or OCSP, do so */

#ifdef EXIM_HAVE_OPENSSL_TLSEXT
# ifndef DISABLE_OCSP
  if (!(cbinfo->verify_stack = sk_X509_new_null()))
    {
    DEBUG(D_tls) debug_printf("failed to create stack for stapling verify\n");
    return FAIL;
    }
# endif

if (!host)		/* server */
  {
# ifndef DISABLE_OCSP
  /* We check u_ocsp.server.file, not server.response, because we care about if
  the option exists, not what the current expansion might be, as SNI might
  change the certificate and OCSP file in use between now and the time the
  callback is invoked. */
  if (cbinfo->u_ocsp.server.file)
    {
    SSL_CTX_set_tlsext_status_cb(ctx, tls_server_stapling_cb);
    SSL_CTX_set_tlsext_status_arg(ctx, cbinfo);
    }
# endif
  /* We always do this, so that $tls_sni is available even if not used in
  tls_certificate */
  SSL_CTX_set_tlsext_servername_callback(ctx, tls_servername_cb);
  SSL_CTX_set_tlsext_servername_arg(ctx, cbinfo);
  }
# ifndef DISABLE_OCSP
else			/* client */
  if(ocsp_file)		/* wanting stapling */
    {
    if (!(cbinfo->u_ocsp.client.verify_store = X509_STORE_new()))
      {
      DEBUG(D_tls) debug_printf("failed to create store for stapling verify\n");
      return FAIL;
      }
    SSL_CTX_set_tlsext_status_cb(ctx, tls_client_stapling_cb);
    SSL_CTX_set_tlsext_status_arg(ctx, cbinfo);
    }
# endif
#endif

cbinfo->verify_cert_hostnames = NULL;

#ifdef EXIM_HAVE_EPHEM_RSA_KEX
/* Set up the RSA callback */
SSL_CTX_set_tmp_rsa_callback(ctx, rsa_callback);
#endif

/* Finally, set the timeout, and we are done */

SSL_CTX_set_timeout(ctx, ssl_session_timeout);
DEBUG(D_tls) debug_printf("Initialized TLS\n");

*cbp = cbinfo;
*ctxp = ctx;

return OK;
}




/*************************************************
*           Get name of cipher in use            *
*************************************************/

/*
Argument:   pointer to an SSL structure for the connection
            buffer to use for answer
            size of buffer
	    pointer to number of bits for cipher
Returns:    nothing
*/

static void
construct_cipher_name(SSL *ssl, uschar *cipherbuf, int bsize, int *bits)
{
/* With OpenSSL 1.0.0a, 'c' needs to be const but the documentation doesn't
yet reflect that.  It should be a safe change anyway, even 0.9.8 versions have
the accessor functions use const in the prototype. */

const uschar * ver = CUS SSL_get_version(ssl);
const SSL_CIPHER * c = (const SSL_CIPHER *) SSL_get_current_cipher(ssl);

SSL_CIPHER_get_bits(c, bits);

string_format(cipherbuf, bsize, "%s:%s:%u", ver,
  SSL_CIPHER_get_name(c), *bits);

DEBUG(D_tls) debug_printf("Cipher: %s\n", cipherbuf);
}


static void
peer_cert(SSL * ssl, tls_support * tlsp, uschar * peerdn, unsigned siz)
{
/*XXX we might consider a list-of-certs variable for the cert chain.
SSL_get_peer_cert_chain(SSL*).  We'd need a new variable type and support
in list-handling functions, also consider the difference between the entire
chain and the elements sent by the peer. */

tlsp->peerdn = NULL;

/* Will have already noted peercert on a verify fail; possibly not the leaf */
if (!tlsp->peercert)
  tlsp->peercert = SSL_get_peer_certificate(ssl);
/* Beware anonymous ciphers which lead to server_cert being NULL */
if (tlsp->peercert)
  if (!X509_NAME_oneline(X509_get_subject_name(tlsp->peercert), CS peerdn, siz))
    { DEBUG(D_tls) debug_printf("X509_NAME_oneline() error\n"); }
  else
    {
    peerdn[siz-1] = '\0';
    tlsp->peerdn = peerdn;		/*XXX a static buffer... */
    }
}





/*************************************************
*        Set up for verifying certificates       *
*************************************************/

#ifndef DISABLE_OCSP
/* Load certs from file, return TRUE on success */

static BOOL
chain_from_pem_file(const uschar * file, STACK_OF(X509) * verify_stack)
{
BIO * bp;
X509 * x;

while (sk_X509_num(verify_stack) > 0)
  X509_free(sk_X509_pop(verify_stack));

if (!(bp = BIO_new_file(CS file, "r"))) return FALSE;
while ((x = PEM_read_bio_X509(bp, NULL, 0, NULL)))
  sk_X509_push(verify_stack, x);
BIO_free(bp);
return TRUE;
}
#endif



/* Called by both client and server startup; on the server possibly
repeated after a Server Name Indication.

Arguments:
  sctx          SSL_CTX* to initialise
  certs         certs file or NULL
  crl           CRL file or NULL
  host          NULL in a server; the remote host in a client
  optional      TRUE if called from a server for a host in tls_try_verify_hosts;
                otherwise passed as FALSE
  cert_vfy_cb	Callback function for certificate verification
  errstr	error string pointer

Returns:        OK/DEFER/FAIL
*/

static int
setup_certs(SSL_CTX *sctx, uschar *certs, uschar *crl, host_item *host, BOOL optional,
    int (*cert_vfy_cb)(int, X509_STORE_CTX *), uschar ** errstr)
{
uschar *expcerts, *expcrl;

if (!expand_check(certs, US"tls_verify_certificates", &expcerts, errstr))
  return DEFER;
DEBUG(D_tls) debug_printf("tls_verify_certificates: %s\n", expcerts);

if (expcerts && *expcerts)
  {
  /* Tell the library to use its compiled-in location for the system default
  CA bundle. Then add the ones specified in the config, if any. */

  if (!SSL_CTX_set_default_verify_paths(sctx))
    return tls_error(US"SSL_CTX_set_default_verify_paths", host, NULL, errstr);

  if (Ustrcmp(expcerts, "system") != 0)
    {
    struct stat statbuf;

    if (Ustat(expcerts, &statbuf) < 0)
      {
      log_write(0, LOG_MAIN|LOG_PANIC,
	"failed to stat %s for certificates", expcerts);
      return DEFER;
      }
    else
      {
      uschar *file, *dir;
      if ((statbuf.st_mode & S_IFMT) == S_IFDIR)
	{ file = NULL; dir = expcerts; }
      else
	{
	file = expcerts; dir = NULL;
#ifndef DISABLE_OCSP
	/* In the server if we will be offering an OCSP proof, load chain from
	file for verifying the OCSP proof at load time. */

	if (  !host
	   && statbuf.st_size > 0
	   && server_static_cbinfo->u_ocsp.server.file
	   && !chain_from_pem_file(file, server_static_cbinfo->verify_stack)
	   )
	  {
	  log_write(0, LOG_MAIN|LOG_PANIC,
	    "failed to load cert chain from %s", file);
	  return DEFER;
	  }
#endif
	}

      /* If a certificate file is empty, the next function fails with an
      unhelpful error message. If we skip it, we get the correct behaviour (no
      certificates are recognized, but the error message is still misleading (it
      says no certificate was supplied).  But this is better. */

      if (  (!file || statbuf.st_size > 0)
         && !SSL_CTX_load_verify_locations(sctx, CS file, CS dir))
	return tls_error(US"SSL_CTX_load_verify_locations", host, NULL, errstr);

      /* Load the list of CAs for which we will accept certs, for sending
      to the client.  This is only for the one-file tls_verify_certificates
      variant.
      If a list isn't loaded into the server, but
      some verify locations are set, the server end appears to make
      a wildcard request for client certs.
      Meanwhile, the client library as default behaviour *ignores* the list
      we send over the wire - see man SSL_CTX_set_client_cert_cb.
      Because of this, and that the dir variant is likely only used for
      the public-CA bundle (not for a private CA), not worth fixing.
      */
      if (file)
	{
	STACK_OF(X509_NAME) * names = SSL_load_client_CA_file(CS file);

	SSL_CTX_set_client_CA_list(sctx, names);
	DEBUG(D_tls) debug_printf("Added %d certificate authorities.\n",
				    sk_X509_NAME_num(names));
	}
      }
    }

  /* Handle a certificate revocation list. */

#if OPENSSL_VERSION_NUMBER > 0x00907000L

  /* This bit of code is now the version supplied by Lars Mainka. (I have
  merely reformatted it into the Exim code style.)

  "From here I changed the code to add support for multiple crl's
  in pem format in one file or to support hashed directory entries in
  pem format instead of a file. This method now uses the library function
  X509_STORE_load_locations to add the CRL location to the SSL context.
  OpenSSL will then handle the verify against CA certs and CRLs by
  itself in the verify callback." */

  if (!expand_check(crl, US"tls_crl", &expcrl, errstr)) return DEFER;
  if (expcrl && *expcrl)
    {
    struct stat statbufcrl;
    if (Ustat(expcrl, &statbufcrl) < 0)
      {
      log_write(0, LOG_MAIN|LOG_PANIC,
        "failed to stat %s for certificates revocation lists", expcrl);
      return DEFER;
      }
    else
      {
      /* is it a file or directory? */
      uschar *file, *dir;
      X509_STORE *cvstore = SSL_CTX_get_cert_store(sctx);
      if ((statbufcrl.st_mode & S_IFMT) == S_IFDIR)
        {
        file = NULL;
        dir = expcrl;
        DEBUG(D_tls) debug_printf("SSL CRL value is a directory %s\n", dir);
        }
      else
        {
        file = expcrl;
        dir = NULL;
        DEBUG(D_tls) debug_printf("SSL CRL value is a file %s\n", file);
        }
      if (X509_STORE_load_locations(cvstore, CS file, CS dir) == 0)
        return tls_error(US"X509_STORE_load_locations", host, NULL, errstr);

      /* setting the flags to check against the complete crl chain */

      X509_STORE_set_flags(cvstore,
        X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
      }
    }

#endif  /* OPENSSL_VERSION_NUMBER > 0x00907000L */

  /* If verification is optional, don't fail if no certificate */

  SSL_CTX_set_verify(sctx,
    SSL_VERIFY_PEER | (optional ? 0 : SSL_VERIFY_FAIL_IF_NO_PEER_CERT),
    cert_vfy_cb);
  }

return OK;
}



/*************************************************
*       Start a TLS session in a server          *
*************************************************/

/* This is called when Exim is running as a server, after having received
the STARTTLS command. It must respond to that command, and then negotiate
a TLS session.

Arguments:
  require_ciphers   allowed ciphers
  errstr	    pointer to error message

Returns:            OK on success
                    DEFER for errors before the start of the negotiation
                    FAIL for errors during the negotiation; the server can't
                      continue running.
*/

int
tls_server_start(const uschar * require_ciphers, uschar ** errstr)
{
int rc;
uschar * expciphers;
tls_ext_ctx_cb * cbinfo;
static uschar peerdn[256];
static uschar cipherbuf[256];

/* Check for previous activation */

if (tls_in.active.sock >= 0)
  {
  tls_error(US"STARTTLS received after TLS started", NULL, US"", errstr);
  smtp_printf("554 Already in TLS\r\n", FALSE);
  return FAIL;
  }

/* Initialize the SSL library. If it fails, it will already have logged
the error. */

rc = tls_init(&server_ctx, NULL, tls_dhparam, tls_certificate, tls_privatekey,
#ifndef DISABLE_OCSP
    tls_ocsp_file,	/*XXX stack*/
#endif
    NULL, &server_static_cbinfo, errstr);
if (rc != OK) return rc;
cbinfo = server_static_cbinfo;

if (!expand_check(require_ciphers, US"tls_require_ciphers", &expciphers, errstr))
  return FAIL;

/* In OpenSSL, cipher components are separated by hyphens. In GnuTLS, they
were historically separated by underscores. So that I can use either form in my
tests, and also for general convenience, we turn underscores into hyphens here.

XXX SSL_CTX_set_cipher_list() is replaced by SSL_CTX_set_ciphersuites()
for TLS 1.3 .  Since we do not call it at present we get the default list:
TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
*/

if (expciphers)
  {
  uschar * s = expciphers;
  while (*s != 0) { if (*s == '_') *s = '-'; s++; }
  DEBUG(D_tls) debug_printf("required ciphers: %s\n", expciphers);
  if (!SSL_CTX_set_cipher_list(server_ctx, CS expciphers))
    return tls_error(US"SSL_CTX_set_cipher_list", NULL, NULL, errstr);
  cbinfo->server_cipher_list = expciphers;
  }

/* If this is a host for which certificate verification is mandatory or
optional, set up appropriately. */

tls_in.certificate_verified = FALSE;
#ifdef SUPPORT_DANE
tls_in.dane_verified = FALSE;
#endif
server_verify_callback_called = FALSE;

if (verify_check_host(&tls_verify_hosts) == OK)
  {
  rc = setup_certs(server_ctx, tls_verify_certificates, tls_crl, NULL,
			FALSE, verify_callback_server, errstr);
  if (rc != OK) return rc;
  server_verify_optional = FALSE;
  }
else if (verify_check_host(&tls_try_verify_hosts) == OK)
  {
  rc = setup_certs(server_ctx, tls_verify_certificates, tls_crl, NULL,
			TRUE, verify_callback_server, errstr);
  if (rc != OK) return rc;
  server_verify_optional = TRUE;
  }

/* Prepare for new connection */

if (!(server_ssl = SSL_new(server_ctx)))
  return tls_error(US"SSL_new", NULL, NULL, errstr);

/* Warning: we used to SSL_clear(ssl) here, it was removed.
 *
 * With the SSL_clear(), we get strange interoperability bugs with
 * OpenSSL 1.0.1b and TLS1.1/1.2.  It looks as though this may be a bug in
 * OpenSSL itself, as a clear should not lead to inability to follow protocols.
 *
 * The SSL_clear() call is to let an existing SSL* be reused, typically after
 * session shutdown.  In this case, we have a brand new object and there's no
 * obvious reason to immediately clear it.  I'm guessing that this was
 * originally added because of incomplete initialisation which the clear fixed,
 * in some historic release.
 */

/* Set context and tell client to go ahead, except in the case of TLS startup
on connection, where outputting anything now upsets the clients and tends to
make them disconnect. We need to have an explicit fflush() here, to force out
the response. Other smtp_printf() calls do not need it, because in non-TLS
mode, the fflush() happens when smtp_getc() is called. */

SSL_set_session_id_context(server_ssl, sid_ctx, Ustrlen(sid_ctx));
if (!tls_in.on_connect)
  {
  smtp_printf("220 TLS go ahead\r\n", FALSE);
  fflush(smtp_out);
  }

/* Now negotiate the TLS session. We put our own timer on it, since it seems
that the OpenSSL library doesn't. */

SSL_set_wfd(server_ssl, fileno(smtp_out));
SSL_set_rfd(server_ssl, fileno(smtp_in));
SSL_set_accept_state(server_ssl);

DEBUG(D_tls) debug_printf("Calling SSL_accept\n");

sigalrm_seen = FALSE;
if (smtp_receive_timeout > 0) ALARM(smtp_receive_timeout);
rc = SSL_accept(server_ssl);
ALARM_CLR(0);

if (rc <= 0)
  {
  (void) tls_error(US"SSL_accept", NULL, sigalrm_seen ? US"timed out" : NULL, errstr);
  return FAIL;
  }

DEBUG(D_tls) debug_printf("SSL_accept was successful\n");
ERR_clear_error();	/* Even success can leave errors in the stack. Seen with
			anon-authentication ciphersuite negociated. */

/* TLS has been set up. Adjust the input functions to read via TLS,
and initialize things. */

peer_cert(server_ssl, &tls_in, peerdn, sizeof(peerdn));

construct_cipher_name(server_ssl, cipherbuf, sizeof(cipherbuf), &tls_in.bits);
tls_in.cipher = cipherbuf;

DEBUG(D_tls)
  {
  uschar buf[2048];
  if (SSL_get_shared_ciphers(server_ssl, CS buf, sizeof(buf)) != NULL)
    debug_printf("Shared ciphers: %s\n", buf);
  }

/* Record the certificate we presented */
  {
  X509 * crt = SSL_get_certificate(server_ssl);
  tls_in.ourcert = crt ? X509_dup(crt) : NULL;
  }

/* Only used by the server-side tls (tls_in), including tls_getc.
   Client-side (tls_out) reads (seem to?) go via
   smtp_read_response()/ip_recv().
   Hence no need to duplicate for _in and _out.
 */
if (!ssl_xfer_buffer) ssl_xfer_buffer = store_malloc(ssl_xfer_buffer_size);
ssl_xfer_buffer_lwm = ssl_xfer_buffer_hwm = 0;
ssl_xfer_eof = ssl_xfer_error = FALSE;

receive_getc = tls_getc;
receive_getbuf = tls_getbuf;
receive_get_cache = tls_get_cache;
receive_ungetc = tls_ungetc;
receive_feof = tls_feof;
receive_ferror = tls_ferror;
receive_smtp_buffered = tls_smtp_buffered;

tls_in.active.sock = fileno(smtp_out);
tls_in.active.tls_ctx = NULL;	/* not using explicit ctx for server-side */
return OK;
}




static int
tls_client_basic_ctx_init(SSL_CTX * ctx,
    host_item * host, smtp_transport_options_block * ob, tls_ext_ctx_cb * cbinfo,
    uschar ** errstr)
{
int rc;
/* stick to the old behaviour for compatibility if tls_verify_certificates is
   set but both tls_verify_hosts and tls_try_verify_hosts is not set. Check only
   the specified host patterns if one of them is defined */

if (  (  !ob->tls_verify_hosts
      && (!ob->tls_try_verify_hosts || !*ob->tls_try_verify_hosts)
      )
   || verify_check_given_host(CUSS &ob->tls_verify_hosts, host) == OK
   )
  client_verify_optional = FALSE;
else if (verify_check_given_host(CUSS &ob->tls_try_verify_hosts, host) == OK)
  client_verify_optional = TRUE;
else
  return OK;

if ((rc = setup_certs(ctx, ob->tls_verify_certificates,
      ob->tls_crl, host, client_verify_optional, verify_callback_client,
      errstr)) != OK)
  return rc;

if (verify_check_given_host(CUSS &ob->tls_verify_cert_hostnames, host) == OK)
  {
  cbinfo->verify_cert_hostnames =
#ifdef SUPPORT_I18N
    string_domain_utf8_to_alabel(host->name, NULL);
#else
    host->name;
#endif
  DEBUG(D_tls) debug_printf("Cert hostname to check: \"%s\"\n",
		    cbinfo->verify_cert_hostnames);
  }
return OK;
}


#ifdef SUPPORT_DANE
static int
dane_tlsa_load(SSL * ssl, host_item * host, dns_answer * dnsa, uschar ** errstr)
{
dns_record * rr;
dns_scan dnss;
const char * hostnames[2] = { CS host->name, NULL };
int found = 0;

if (DANESSL_init(ssl, NULL, hostnames) != 1)
  return tls_error(US"hostnames load", host, NULL, errstr);

for (rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS);
     rr;
     rr = dns_next_rr(dnsa, &dnss, RESET_NEXT)
    ) if (rr->type == T_TLSA && rr->size > 3)
  {
  const uschar * p = rr->data;
  uint8_t usage, selector, mtype;
  const char * mdname;

  usage = *p++;

  /* Only DANE-TA(2) and DANE-EE(3) are supported */
  if (usage != 2 && usage != 3) continue;

  selector = *p++;
  mtype = *p++;

  switch (mtype)
    {
    default: continue;	/* Only match-types 0, 1, 2 are supported */
    case 0:  mdname = NULL; break;
    case 1:  mdname = "sha256"; break;
    case 2:  mdname = "sha512"; break;
    }

  found++;
  switch (DANESSL_add_tlsa(ssl, usage, selector, mdname, p, rr->size - 3))
    {
    default:
      return tls_error(US"tlsa load", host, NULL, errstr);
    case 0:	/* action not taken */
    case 1:	break;
    }

  tls_out.tlsa_usage |= 1<<usage;
  }

if (found)
  return OK;

log_write(0, LOG_MAIN, "DANE error: No usable TLSA records");
return DEFER;
}
#endif	/*SUPPORT_DANE*/



/*************************************************
*    Start a TLS session in a client             *
*************************************************/

/* Called from the smtp transport after STARTTLS has been accepted.

Argument:
  fd               the fd of the connection
  host             connected host (for messages and option-tests)
  addr             the first address (for some randomness; can be NULL)
  tb               transport (always smtp)
  tlsa_dnsa        tlsa lookup, if DANE, else null
  tlsp		   record details of channel configuration here; must be non-NULL
  errstr	   error string pointer

Returns:           Pointer to TLS session context, or NULL on error
*/

void *
tls_client_start(int fd, host_item *host, address_item *addr,
  transport_instance * tb,
#ifdef SUPPORT_DANE
  dns_answer * tlsa_dnsa,
#endif
  tls_support * tlsp, uschar ** errstr)
{
smtp_transport_options_block * ob = tb
  ? (smtp_transport_options_block *)tb->options_block
  : &smtp_transport_option_defaults;
exim_openssl_client_tls_ctx * exim_client_ctx;
static uschar peerdn[256];
uschar * expciphers;
int rc;
static uschar cipherbuf[256];

#ifndef DISABLE_OCSP
BOOL request_ocsp = FALSE;
BOOL require_ocsp = FALSE;
#endif

rc = store_pool;
store_pool = POOL_PERM;
exim_client_ctx = store_get(sizeof(exim_openssl_client_tls_ctx));
store_pool = rc;

#ifdef SUPPORT_DANE
tlsp->tlsa_usage = 0;
#endif

#ifndef DISABLE_OCSP
  {
# ifdef SUPPORT_DANE
  if (  tlsa_dnsa
     && ob->hosts_request_ocsp[0] == '*'
     && ob->hosts_request_ocsp[1] == '\0'
     )
    {
    /* Unchanged from default.  Use a safer one under DANE */
    request_ocsp = TRUE;
    ob->hosts_request_ocsp = US"${if or { {= {0}{$tls_out_tlsa_usage}} "
				      "   {= {4}{$tls_out_tlsa_usage}} } "
				 " {*}{}}";
    }
# endif

  if ((require_ocsp =
	verify_check_given_host(CUSS &ob->hosts_require_ocsp, host) == OK))
    request_ocsp = TRUE;
  else
# ifdef SUPPORT_DANE
    if (!request_ocsp)
# endif
      request_ocsp =
	verify_check_given_host(CUSS &ob->hosts_request_ocsp, host) == OK;
  }
#endif

rc = tls_init(&exim_client_ctx->ctx, host, NULL,
    ob->tls_certificate, ob->tls_privatekey,
#ifndef DISABLE_OCSP
    (void *)(long)request_ocsp,
#endif
    addr, &client_static_cbinfo, errstr);
if (rc != OK) return NULL;

tlsp->certificate_verified = FALSE;
client_verify_callback_called = FALSE;

expciphers = NULL;
#ifdef SUPPORT_DANE
if (tlsa_dnsa)
  {
  /* We fall back to tls_require_ciphers if unset, empty or forced failure, but
  other failures should be treated as problems. */
  if (ob->dane_require_tls_ciphers &&
      !expand_check(ob->dane_require_tls_ciphers, US"dane_require_tls_ciphers",
        &expciphers, errstr))
    return NULL;
  if (expciphers && *expciphers == '\0')
    expciphers = NULL;
  }
#endif
if (!expciphers &&
    !expand_check(ob->tls_require_ciphers, US"tls_require_ciphers",
      &expciphers, errstr))
  return NULL;

/* In OpenSSL, cipher components are separated by hyphens. In GnuTLS, they
are separated by underscores. So that I can use either form in my tests, and
also for general convenience, we turn underscores into hyphens here. */

if (expciphers)
  {
  uschar *s = expciphers;
  while (*s) { if (*s == '_') *s = '-'; s++; }
  DEBUG(D_tls) debug_printf("required ciphers: %s\n", expciphers);
  if (!SSL_CTX_set_cipher_list(exim_client_ctx->ctx, CS expciphers))
    {
    tls_error(US"SSL_CTX_set_cipher_list", host, NULL, errstr);
    return NULL;
    }
  }

#ifdef SUPPORT_DANE
if (tlsa_dnsa)
  {
  SSL_CTX_set_verify(exim_client_ctx->ctx,
    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
    verify_callback_client_dane);

  if (!DANESSL_library_init())
    {
    tls_error(US"library init", host, NULL, errstr);
    return NULL;
    }
  if (DANESSL_CTX_init(exim_client_ctx->ctx) <= 0)
    {
    tls_error(US"context init", host, NULL, errstr);
    return NULL;
    }
  }
else

#endif

  if (tls_client_basic_ctx_init(exim_client_ctx->ctx, host, ob,
	client_static_cbinfo, errstr) != OK)
    return NULL;

if (!(exim_client_ctx->ssl = SSL_new(exim_client_ctx->ctx)))
  {
  tls_error(US"SSL_new", host, NULL, errstr);
  return NULL;
  }
SSL_set_session_id_context(exim_client_ctx->ssl, sid_ctx, Ustrlen(sid_ctx));
SSL_set_fd(exim_client_ctx->ssl, fd);
SSL_set_connect_state(exim_client_ctx->ssl);

if (ob->tls_sni)
  {
  if (!expand_check(ob->tls_sni, US"tls_sni", &tlsp->sni, errstr))
    return NULL;
  if (!tlsp->sni)
    {
    DEBUG(D_tls) debug_printf("Setting TLS SNI forced to fail, not sending\n");
    }
  else if (!Ustrlen(tlsp->sni))
    tlsp->sni = NULL;
  else
    {
#ifdef EXIM_HAVE_OPENSSL_TLSEXT
    DEBUG(D_tls) debug_printf("Setting TLS SNI \"%s\"\n", tlsp->sni);
    SSL_set_tlsext_host_name(exim_client_ctx->ssl, tlsp->sni);
#else
    log_write(0, LOG_MAIN, "SNI unusable with this OpenSSL library version; ignoring \"%s\"\n",
          tlsp->sni);
#endif
    }
  }

#ifdef SUPPORT_DANE
if (tlsa_dnsa)
  if (dane_tlsa_load(exim_client_ctx->ssl, host, tlsa_dnsa, errstr) != OK)
    return NULL;
#endif

#ifndef DISABLE_OCSP
/* Request certificate status at connection-time.  If the server
does OCSP stapling we will get the callback (set in tls_init()) */
# ifdef SUPPORT_DANE
if (request_ocsp)
  {
  const uschar * s;
  if (  ((s = ob->hosts_require_ocsp) && Ustrstr(s, US"tls_out_tlsa_usage"))
     || ((s = ob->hosts_request_ocsp) && Ustrstr(s, US"tls_out_tlsa_usage"))
     )
    {	/* Re-eval now $tls_out_tlsa_usage is populated.  If
    	this means we avoid the OCSP request, we wasted the setup
	cost in tls_init(). */
    require_ocsp = verify_check_given_host(CUSS &ob->hosts_require_ocsp, host) == OK;
    request_ocsp = require_ocsp
      || verify_check_given_host(CUSS &ob->hosts_request_ocsp, host) == OK;
    }
  }
# endif

if (request_ocsp)
  {
  SSL_set_tlsext_status_type(exim_client_ctx->ssl, TLSEXT_STATUSTYPE_ocsp);
  client_static_cbinfo->u_ocsp.client.verify_required = require_ocsp;
  tlsp->ocsp = OCSP_NOT_RESP;
  }
#endif

#ifndef DISABLE_EVENT
client_static_cbinfo->event_action = tb ? tb->event_action : NULL;
#endif

/* There doesn't seem to be a built-in timeout on connection. */

DEBUG(D_tls) debug_printf("Calling SSL_connect\n");
sigalrm_seen = FALSE;
ALARM(ob->command_timeout);
rc = SSL_connect(exim_client_ctx->ssl);
ALARM_CLR(0);

#ifdef SUPPORT_DANE
if (tlsa_dnsa)
  DANESSL_cleanup(exim_client_ctx->ssl);
#endif

if (rc <= 0)
  {
  tls_error(US"SSL_connect", host, sigalrm_seen ? US"timed out" : NULL, errstr);
  return NULL;
  }

DEBUG(D_tls) debug_printf("SSL_connect succeeded\n");

peer_cert(exim_client_ctx->ssl, tlsp, peerdn, sizeof(peerdn));

construct_cipher_name(exim_client_ctx->ssl, cipherbuf, sizeof(cipherbuf), &tlsp->bits);
tlsp->cipher = cipherbuf;

/* Record the certificate we presented */
  {
  X509 * crt = SSL_get_certificate(exim_client_ctx->ssl);
  tlsp->ourcert = crt ? X509_dup(crt) : NULL;
  }

tlsp->active.sock = fd;
tlsp->active.tls_ctx = exim_client_ctx;
return exim_client_ctx;
}





static BOOL
tls_refill(unsigned lim)
{
int error;
int inbytes;

DEBUG(D_tls) debug_printf("Calling SSL_read(%p, %p, %u)\n", server_ssl,
  ssl_xfer_buffer, ssl_xfer_buffer_size);

if (smtp_receive_timeout > 0) ALARM(smtp_receive_timeout);
inbytes = SSL_read(server_ssl, CS ssl_xfer_buffer,
		  MIN(ssl_xfer_buffer_size, lim));
error = SSL_get_error(server_ssl, inbytes);
if (smtp_receive_timeout > 0) ALARM_CLR(0);

if (had_command_timeout)		/* set by signal handler */
  smtp_command_timeout_exit();		/* does not return */
if (had_command_sigterm)
  smtp_command_sigterm_exit();
if (had_data_timeout)
  smtp_data_timeout_exit();
if (had_data_sigint)
  smtp_data_sigint_exit();

/* SSL_ERROR_ZERO_RETURN appears to mean that the SSL session has been
closed down, not that the socket itself has been closed down. Revert to
non-SSL handling. */

switch(error)
  {
  case SSL_ERROR_NONE:
    break;

  case SSL_ERROR_ZERO_RETURN:
    DEBUG(D_tls) debug_printf("Got SSL_ERROR_ZERO_RETURN\n");

    receive_getc = smtp_getc;
    receive_getbuf = smtp_getbuf;
    receive_get_cache = smtp_get_cache;
    receive_ungetc = smtp_ungetc;
    receive_feof = smtp_feof;
    receive_ferror = smtp_ferror;
    receive_smtp_buffered = smtp_buffered;

    if (SSL_get_shutdown(server_ssl) == SSL_RECEIVED_SHUTDOWN)
	  SSL_shutdown(server_ssl);

#ifndef DISABLE_OCSP
    sk_X509_pop_free(server_static_cbinfo->verify_stack, X509_free);
    server_static_cbinfo->verify_stack = NULL;
#endif
    SSL_free(server_ssl);
    SSL_CTX_free(server_ctx);
    server_ctx = NULL;
    server_ssl = NULL;
    tls_in.active.sock = -1;
    tls_in.active.tls_ctx = NULL;
    tls_in.bits = 0;
    tls_in.cipher = NULL;
    tls_in.peerdn = NULL;
    tls_in.sni = NULL;

    return FALSE;

  /* Handle genuine errors */
  case SSL_ERROR_SSL:
    ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
    log_write(0, LOG_MAIN, "TLS error (SSL_read): %s", ssl_errstring);
    ssl_xfer_error = TRUE;
    return FALSE;

  default:
    DEBUG(D_tls) debug_printf("Got SSL error %d\n", error);
    DEBUG(D_tls) if (error == SSL_ERROR_SYSCALL)
      debug_printf(" - syscall %s\n", strerror(errno));
    ssl_xfer_error = TRUE;
    return FALSE;
  }

#ifndef DISABLE_DKIM
dkim_exim_verify_feed(ssl_xfer_buffer, inbytes);
#endif
ssl_xfer_buffer_hwm = inbytes;
ssl_xfer_buffer_lwm = 0;
return TRUE;
}


/*************************************************
*            TLS version of getc                 *
*************************************************/

/* This gets the next byte from the TLS input buffer. If the buffer is empty,
it refills the buffer via the SSL reading function.

Arguments:  lim		Maximum amount to read/buffer
Returns:    the next character or EOF

Only used by the server-side TLS.
*/

int
tls_getc(unsigned lim)
{
if (ssl_xfer_buffer_lwm >= ssl_xfer_buffer_hwm)
  if (!tls_refill(lim))
    return ssl_xfer_error ? EOF : smtp_getc(lim);

/* Something in the buffer; return next uschar */

return ssl_xfer_buffer[ssl_xfer_buffer_lwm++];
}

uschar *
tls_getbuf(unsigned * len)
{
unsigned size;
uschar * buf;

if (ssl_xfer_buffer_lwm >= ssl_xfer_buffer_hwm)
  if (!tls_refill(*len))
    {
    if (!ssl_xfer_error) return smtp_getbuf(len);
    *len = 0;
    return NULL;
    }

if ((size = ssl_xfer_buffer_hwm - ssl_xfer_buffer_lwm) > *len)
  size = *len;
buf = &ssl_xfer_buffer[ssl_xfer_buffer_lwm];
ssl_xfer_buffer_lwm += size;
*len = size;
return buf;
}


void
tls_get_cache()
{
#ifndef DISABLE_DKIM
int n = ssl_xfer_buffer_hwm - ssl_xfer_buffer_lwm;
if (n > 0)
  dkim_exim_verify_feed(ssl_xfer_buffer+ssl_xfer_buffer_lwm, n);
#endif
}


BOOL
tls_could_read(void)
{
return ssl_xfer_buffer_lwm < ssl_xfer_buffer_hwm || SSL_pending(server_ssl) > 0;
}


/*************************************************
*          Read bytes from TLS channel           *
*************************************************/

/*
Arguments:
  ct_ctx    client context pointer, or NULL for the one global server context
  buff      buffer of data
  len       size of buffer

Returns:    the number of bytes read
            -1 after a failed read, including EOF

Only used by the client-side TLS.
*/

int
tls_read(void * ct_ctx, uschar *buff, size_t len)
{
SSL * ssl = ct_ctx ? ((exim_openssl_client_tls_ctx *)ct_ctx)->ssl : server_ssl;
int inbytes;
int error;

DEBUG(D_tls) debug_printf("Calling SSL_read(%p, %p, %u)\n", ssl,
  buff, (unsigned int)len);

inbytes = SSL_read(ssl, CS buff, len);
error = SSL_get_error(ssl, inbytes);

if (error == SSL_ERROR_ZERO_RETURN)
  {
  DEBUG(D_tls) debug_printf("Got SSL_ERROR_ZERO_RETURN\n");
  return -1;
  }
else if (error != SSL_ERROR_NONE)
  return -1;

return inbytes;
}





/*************************************************
*         Write bytes down TLS channel           *
*************************************************/

/*
Arguments:
  ct_ctx    client context pointer, or NULL for the one global server context
  buff      buffer of data
  len       number of bytes
  more	    further data expected soon

Returns:    the number of bytes after a successful write,
            -1 after a failed write

Used by both server-side and client-side TLS.
*/

int
tls_write(void * ct_ctx, const uschar *buff, size_t len, BOOL more)
{
int outbytes, error, left;
SSL * ssl = ct_ctx ? ((exim_openssl_client_tls_ctx *)ct_ctx)->ssl : server_ssl;
static gstring * corked = NULL;

DEBUG(D_tls) debug_printf("%s(%p, %lu%s)\n", __FUNCTION__,
  buff, (unsigned long)len, more ? ", more" : "");

/* Lacking a CORK or MSG_MORE facility (such as GnuTLS has) we copy data when
"more" is notified.  This hack is only ok if small amounts are involved AND only
one stream does it, in one context (i.e. no store reset).  Currently it is used
for the responses to the received SMTP MAIL , RCPT, DATA sequence, only. */
/*XXX + if PIPE_COMMAND, banner & ehlo-resp for smmtp-on-connect. Suspect there's
a store reset there. */

if (!ct_ctx && (more || corked))
  {
#ifdef EXPERIMENTAL_PIPE_CONNECT
  int save_pool = store_pool;
  store_pool = POOL_PERM;
#endif

  corked = string_catn(corked, buff, len);

#ifdef EXPERIMENTAL_PIPE_CONNECT
  store_pool = save_pool;
#endif

  if (more)
    return len;
  buff = CUS corked->s;
  len = corked->ptr;
  corked = NULL;
  }

for (left = len; left > 0;)
  {
  DEBUG(D_tls) debug_printf("SSL_write(%p, %p, %d)\n", ssl, buff, left);
  outbytes = SSL_write(ssl, CS buff, left);
  error = SSL_get_error(ssl, outbytes);
  DEBUG(D_tls) debug_printf("outbytes=%d error=%d\n", outbytes, error);
  switch (error)
    {
    case SSL_ERROR_SSL:
      ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
      log_write(0, LOG_MAIN, "TLS error (SSL_write): %s", ssl_errstring);
      return -1;

    case SSL_ERROR_NONE:
      left -= outbytes;
      buff += outbytes;
      break;

    case SSL_ERROR_ZERO_RETURN:
      log_write(0, LOG_MAIN, "SSL channel closed on write");
      return -1;

    case SSL_ERROR_SYSCALL:
      log_write(0, LOG_MAIN, "SSL_write: (from %s) syscall: %s",
	sender_fullhost ? sender_fullhost : US"<unknown>",
	strerror(errno));
      return -1;

    default:
      log_write(0, LOG_MAIN, "SSL_write error %d", error);
      return -1;
    }
  }
return len;
}



/*************************************************
*         Close down a TLS session               *
*************************************************/

/* This is also called from within a delivery subprocess forked from the
daemon, to shut down the TLS library, without actually doing a shutdown (which
would tamper with the SSL session in the parent process).

Arguments:
  ct_ctx	client TLS context pointer, or NULL for the one global server context
  shutdown	1 if TLS close-alert is to be sent,
 		2 if also response to be waited for

Returns:     nothing

Used by both server-side and client-side TLS.
*/

void
tls_close(void * ct_ctx, int shutdown)
{
exim_openssl_client_tls_ctx * o_ctx = ct_ctx;
SSL_CTX **ctxp = o_ctx ? &o_ctx->ctx : &server_ctx;
SSL **sslp =     o_ctx ? &o_ctx->ssl : &server_ssl;
int *fdp = o_ctx ? &tls_out.active.sock : &tls_in.active.sock;

if (*fdp < 0) return;  /* TLS was not active */

if (shutdown)
  {
  int rc;
  DEBUG(D_tls) debug_printf("tls_close(): shutting down TLS%s\n",
    shutdown > 1 ? " (with response-wait)" : "");

  if (  (rc = SSL_shutdown(*sslp)) == 0	/* send "close notify" alert */
     && shutdown > 1)
    {
    ALARM(2);
    rc = SSL_shutdown(*sslp);		/* wait for response */
    ALARM_CLR(0);
    }

  if (rc < 0) DEBUG(D_tls)
    {
    ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
    debug_printf("SSL_shutdown: %s\n", ssl_errstring);
    }
  }

#ifndef DISABLE_OCSP
if (!o_ctx)		/* server side */
  {
  sk_X509_pop_free(server_static_cbinfo->verify_stack, X509_free);
  server_static_cbinfo->verify_stack = NULL;
  }
#endif

SSL_CTX_free(*ctxp);
SSL_free(*sslp);
*ctxp = NULL;
*sslp = NULL;
*fdp = -1;
}




/*************************************************
*  Let tls_require_ciphers be checked at startup *
*************************************************/

/* The tls_require_ciphers option, if set, must be something which the
library can parse.

Returns:     NULL on success, or error message
*/

uschar *
tls_validate_require_cipher(void)
{
SSL_CTX *ctx;
uschar *s, *expciphers, *err;

/* this duplicates from tls_init(), we need a better "init just global
state, for no specific purpose" singleton function of our own */

#ifdef EXIM_NEED_OPENSSL_INIT
SSL_load_error_strings();
OpenSSL_add_ssl_algorithms();
#endif
#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL) && !defined(OPENSSL_NO_SHA256)
/* SHA256 is becoming ever more popular. This makes sure it gets added to the
list of available digests. */
EVP_add_digest(EVP_sha256());
#endif

if (!(tls_require_ciphers && *tls_require_ciphers))
  return NULL;

if (!expand_check(tls_require_ciphers, US"tls_require_ciphers", &expciphers,
		  &err))
  return US"failed to expand tls_require_ciphers";

if (!(expciphers && *expciphers))
  return NULL;

/* normalisation ripped from above */
s = expciphers;
while (*s != 0) { if (*s == '_') *s = '-'; s++; }

err = NULL;

#ifdef EXIM_HAVE_OPENSSL_TLS_METHOD
if (!(ctx = SSL_CTX_new(TLS_server_method())))
#else
if (!(ctx = SSL_CTX_new(SSLv23_server_method())))
#endif
  {
  ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
  return string_sprintf("SSL_CTX_new() failed: %s", ssl_errstring);
  }

DEBUG(D_tls)
  debug_printf("tls_require_ciphers expands to \"%s\"\n", expciphers);

if (!SSL_CTX_set_cipher_list(ctx, CS expciphers))
  {
  ERR_error_string_n(ERR_get_error(), ssl_errstring, sizeof(ssl_errstring));
  err = string_sprintf("SSL_CTX_set_cipher_list(%s) failed: %s",
		      expciphers, ssl_errstring);
  }

SSL_CTX_free(ctx);

return err;
}




/*************************************************
*         Report the library versions.           *
*************************************************/

/* There have historically been some issues with binary compatibility in
OpenSSL libraries; if Exim (like many other applications) is built against
one version of OpenSSL but the run-time linker picks up another version,
it can result in serious failures, including crashing with a SIGSEGV.  So
report the version found by the compiler and the run-time version.

Note: some OS vendors backport security fixes without changing the version
number/string, and the version date remains unchanged.  The _build_ date
will change, so we can more usefully assist with version diagnosis by also
reporting the build date.

Arguments:   a FILE* to print the results to
Returns:     nothing
*/

void
tls_version_report(FILE *f)
{
fprintf(f, "Library version: OpenSSL: Compile: %s\n"
           "                          Runtime: %s\n"
           "                                 : %s\n",
           OPENSSL_VERSION_TEXT,
           SSLeay_version(SSLEAY_VERSION),
           SSLeay_version(SSLEAY_BUILT_ON));
/* third line is 38 characters for the %s and the line is 73 chars long;
the OpenSSL output includes a "built on: " prefix already. */
}




/*************************************************
*            Random number generation            *
*************************************************/

/* Pseudo-random number generation.  The result is not expected to be
cryptographically strong but not so weak that someone will shoot themselves
in the foot using it as a nonce in input in some email header scheme or
whatever weirdness they'll twist this into.  The result should handle fork()
and avoid repeating sequences.  OpenSSL handles that for us.

Arguments:
  max       range maximum
Returns     a random number in range [0, max-1]
*/

int
vaguely_random_number(int max)
{
unsigned int r;
int i, needed_len;
static pid_t pidlast = 0;
pid_t pidnow;
uschar *p;
uschar smallbuf[sizeof(r)];

if (max <= 1)
  return 0;

pidnow = getpid();
if (pidnow != pidlast)
  {
  /* Although OpenSSL documents that "OpenSSL makes sure that the PRNG state
  is unique for each thread", this doesn't apparently apply across processes,
  so our own warning from vaguely_random_number_fallback() applies here too.
  Fix per PostgreSQL. */
  if (pidlast != 0)
    RAND_cleanup();
  pidlast = pidnow;
  }

/* OpenSSL auto-seeds from /dev/random, etc, but this a double-check. */
if (!RAND_status())
  {
  randstuff r;
  gettimeofday(&r.tv, NULL);
  r.p = getpid();

  RAND_seed(US (&r), sizeof(r));
  }
/* We're after pseudo-random, not random; if we still don't have enough data
in the internal PRNG then our options are limited.  We could sleep and hope
for entropy to come along (prayer technique) but if the system is so depleted
in the first place then something is likely to just keep taking it.  Instead,
we'll just take whatever little bit of pseudo-random we can still manage to
get. */

needed_len = sizeof(r);
/* Don't take 8 times more entropy than needed if int is 8 octets and we were
asked for a number less than 10. */
for (r = max, i = 0; r; ++i)
  r >>= 1;
i = (i + 7) / 8;
if (i < needed_len)
  needed_len = i;

#ifdef EXIM_HAVE_RAND_PSEUDO
/* We do not care if crypto-strong */
i = RAND_pseudo_bytes(smallbuf, needed_len);
#else
i = RAND_bytes(smallbuf, needed_len);
#endif

if (i < 0)
  {
  DEBUG(D_all)
    debug_printf("OpenSSL RAND_pseudo_bytes() not supported by RAND method, using fallback.\n");
  return vaguely_random_number_fallback(max);
  }

r = 0;
for (p = smallbuf; needed_len; --needed_len, ++p)
  {
  r *= 256;
  r += *p;
  }

/* We don't particularly care about weighted results; if someone wants
smooth distribution and cares enough then they should submit a patch then. */
return r % max;
}




/*************************************************
*        OpenSSL option parse                    *
*************************************************/

/* Parse one option for tls_openssl_options_parse below

Arguments:
  name    one option name
  value   place to store a value for it
Returns   success or failure in parsing
*/



static BOOL
tls_openssl_one_option_parse(uschar *name, long *value)
{
int first = 0;
int last = exim_openssl_options_size;
while (last > first)
  {
  int middle = (first + last)/2;
  int c = Ustrcmp(name, exim_openssl_options[middle].name);
  if (c == 0)
    {
    *value = exim_openssl_options[middle].value;
    return TRUE;
    }
  else if (c > 0)
    first = middle + 1;
  else
    last = middle;
  }
return FALSE;
}




/*************************************************
*        OpenSSL option parsing logic            *
*************************************************/

/* OpenSSL has a number of compatibility options which an administrator might
reasonably wish to set.  Interpret a list similarly to decode_bits(), so that
we look like log_selector.

Arguments:
  option_spec  the administrator-supplied string of options
  results      ptr to long storage for the options bitmap
Returns        success or failure
*/

BOOL
tls_openssl_options_parse(uschar *option_spec, long *results)
{
long result, item;
uschar *s, *end;
uschar keep_c;
BOOL adding, item_parsed;

result = SSL_OP_NO_TICKET;
/* Prior to 4.80 we or'd in SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS; removed
 * from default because it increases BEAST susceptibility. */
#ifdef SSL_OP_NO_SSLv2
result |= SSL_OP_NO_SSLv2;
#endif
#ifdef SSL_OP_SINGLE_DH_USE
result |= SSL_OP_SINGLE_DH_USE;
#endif

if (!option_spec)
  {
  *results = result;
  return TRUE;
  }

for (s=option_spec; *s != '\0'; /**/)
  {
  while (isspace(*s)) ++s;
  if (*s == '\0')
    break;
  if (*s != '+' && *s != '-')
    {
    DEBUG(D_tls) debug_printf("malformed openssl option setting: "
        "+ or - expected but found \"%s\"\n", s);
    return FALSE;
    }
  adding = *s++ == '+';
  for (end = s; (*end != '\0') && !isspace(*end); ++end) /**/ ;
  keep_c = *end;
  *end = '\0';
  item_parsed = tls_openssl_one_option_parse(s, &item);
  *end = keep_c;
  if (!item_parsed)
    {
    DEBUG(D_tls) debug_printf("openssl option setting unrecognised: \"%s\"\n", s);
    return FALSE;
    }
  DEBUG(D_tls) debug_printf("openssl option, %s from %lx: %lx (%s)\n",
      adding ? "adding" : "removing", result, item, s);
  if (adding)
    result |= item;
  else
    result &= ~item;
  s = end;
  }

*results = result;
return TRUE;
}

#endif	/*!MACRO_PREDEF*/
/* vi: aw ai sw=2
*/
/* End of tls-openssl.c */
