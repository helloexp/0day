/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Copyright (c) Phil Pennock 2012 */

/* This file provides TLS/SSL support for Exim using the GnuTLS library,
one of the available supported implementations.  This file is #included into
tls.c when USE_GNUTLS has been set.

The code herein is a revamp of GnuTLS integration using the current APIs; the
original tls-gnu.c was based on a patch which was contributed by Nikos
Mavrogiannopoulos.  The revamp is partially a rewrite, partially cut&paste as
appropriate.

APIs current as of GnuTLS 2.12.18; note that the GnuTLS manual is for GnuTLS 3,
which is not widely deployed by OS vendors.  Will note issues below, which may
assist in updating the code in the future.  Another sources of hints is
mod_gnutls for Apache (SNI callback registration and handling).

Keeping client and server variables more split than before and is currently
the norm, in anticipation of TLS in ACL callouts.

I wanted to switch to gnutls_certificate_set_verify_function() so that
certificate rejection could happen during handshake where it belongs, rather
than being dropped afterwards, but that was introduced in 2.10.0 and Debian
(6.0.5) is still on 2.8.6.  So for now we have to stick with sub-par behaviour.

(I wasn't looking for libraries quite that old, when updating to get rid of
compiler warnings of deprecated APIs.  If it turns out that a lot of the rest
require current GnuTLS, then we'll drop support for the ancient libraries).
*/

#include <gnutls/gnutls.h>
/* needed for cert checks in verification and DN extraction: */
#include <gnutls/x509.h>
/* man-page is incorrect, gnutls_rnd() is not in gnutls.h: */
#include <gnutls/crypto.h>

/* needed to disable PKCS11 autoload unless requested */
#if GNUTLS_VERSION_NUMBER >= 0x020c00
# include <gnutls/pkcs11.h>
# define SUPPORT_PARAM_TO_PK_BITS
#endif
#if GNUTLS_VERSION_NUMBER < 0x030103 && !defined(DISABLE_OCSP)
# warning "GnuTLS library version too old; define DISABLE_OCSP in Makefile"
# define DISABLE_OCSP
#endif
#if GNUTLS_VERSION_NUMBER < 0x020a00 && !defined(DISABLE_EVENT)
# warning "GnuTLS library version too old; tls:cert event unsupported"
# define DISABLE_EVENT
#endif
#if GNUTLS_VERSION_NUMBER >= 0x030306
# define SUPPORT_CA_DIR
#else
# undef  SUPPORT_CA_DIR
#endif
#if GNUTLS_VERSION_NUMBER >= 0x030014
# define SUPPORT_SYSDEFAULT_CABUNDLE
#endif
#if GNUTLS_VERSION_NUMBER >= 0x030104
# define GNUTLS_CERT_VFY_STATUS_PRINT
#endif
#if GNUTLS_VERSION_NUMBER >= 0x030109
# define SUPPORT_CORK
#endif
#if GNUTLS_VERSION_NUMBER >= 0x030506 && !defined(DISABLE_OCSP)
# define SUPPORT_SRV_OCSP_STACK
#endif

#ifdef SUPPORT_DANE
# if GNUTLS_VERSION_NUMBER >= 0x030000
#  define DANESSL_USAGE_DANE_TA 2
#  define DANESSL_USAGE_DANE_EE 3
# else
#  error GnuTLS version too early for DANE
# endif
# if GNUTLS_VERSION_NUMBER < 0x999999
#  define GNUTLS_BROKEN_DANE_VALIDATION
# endif
#endif

#ifndef DISABLE_OCSP
# include <gnutls/ocsp.h>
#endif
#ifdef SUPPORT_DANE
# include <gnutls/dane.h>
#endif

/* GnuTLS 2 vs 3

GnuTLS 3 only:
  gnutls_global_set_audit_log_function()

Changes:
  gnutls_certificate_verify_peers2(): is new, drop the 2 for old version
*/

/* Local static variables for GnuTLS */

/* Values for verify_requirement */

enum peer_verify_requirement
  { VERIFY_NONE, VERIFY_OPTIONAL, VERIFY_REQUIRED, VERIFY_DANE };

/* This holds most state for server or client; with this, we can set up an
outbound TLS-enabled connection in an ACL callout, while not stomping all
over the TLS variables available for expansion.

Some of these correspond to variables in globals.c; those variables will
be set to point to content in one of these instances, as appropriate for
the stage of the process lifetime.

Not handled here: global tls_channelbinding_b64.
*/

typedef struct exim_gnutls_state {
  gnutls_session_t	session;
  gnutls_certificate_credentials_t x509_cred;
  gnutls_priority_t	priority_cache;
  enum peer_verify_requirement verify_requirement;
  int			fd_in;
  int			fd_out;
  BOOL			peer_cert_verified;
  BOOL			peer_dane_verified;
  BOOL			trigger_sni_changes;
  BOOL			have_set_peerdn;
  const struct host_item *host;		/* NULL if server */
  gnutls_x509_crt_t	peercert;
  uschar		*peerdn;
  uschar		*ciphersuite;
  uschar		*received_sni;

  const uschar *tls_certificate;
  const uschar *tls_privatekey;
  const uschar *tls_sni; /* client send only, not received */
  const uschar *tls_verify_certificates;
  const uschar *tls_crl;
  const uschar *tls_require_ciphers;

  uschar *exp_tls_certificate;
  uschar *exp_tls_privatekey;
  uschar *exp_tls_verify_certificates;
  uschar *exp_tls_crl;
  uschar *exp_tls_require_ciphers;
  const uschar *exp_tls_verify_cert_hostnames;
#ifndef DISABLE_EVENT
  uschar *event_action;
#endif
#ifdef SUPPORT_DANE
  char * const *	dane_data;
  const int *		dane_data_len;
#endif

  tls_support *tlsp;	/* set in tls_init() */

  uschar *xfer_buffer;
  int xfer_buffer_lwm;
  int xfer_buffer_hwm;
  BOOL xfer_eof;	/*XXX never gets set! */
  BOOL xfer_error;
} exim_gnutls_state_st;

static const exim_gnutls_state_st exim_gnutls_state_init = {
  .session =		NULL,
  .x509_cred =		NULL,
  .priority_cache =	NULL,
  .verify_requirement =	VERIFY_NONE,
  .fd_in =		-1,
  .fd_out =		-1,
  .peer_cert_verified =	FALSE,
  .peer_dane_verified =	FALSE,
  .trigger_sni_changes =FALSE,
  .have_set_peerdn =	FALSE,
  .host =		NULL,
  .peercert =		NULL,
  .peerdn =		NULL,
  .ciphersuite =	NULL,
  .received_sni =	NULL,

  .tls_certificate =	NULL,
  .tls_privatekey =	NULL,
  .tls_sni =		NULL,
  .tls_verify_certificates = NULL,
  .tls_crl =		NULL,
  .tls_require_ciphers =NULL,

  .exp_tls_certificate = NULL,
  .exp_tls_privatekey =	NULL,
  .exp_tls_verify_certificates = NULL,
  .exp_tls_crl =	NULL,
  .exp_tls_require_ciphers = NULL,
  .exp_tls_verify_cert_hostnames = NULL,
#ifndef DISABLE_EVENT
  .event_action =	NULL,
#endif
  .tlsp =		NULL,

  .xfer_buffer =	NULL,
  .xfer_buffer_lwm =	0,
  .xfer_buffer_hwm =	0,
  .xfer_eof =		FALSE,
  .xfer_error =		FALSE,
};

/* Not only do we have our own APIs which don't pass around state, assuming
it's held in globals, GnuTLS doesn't appear to let us register callback data
for callbacks, or as part of the session, so we have to keep a "this is the
context we're currently dealing with" pointer and rely upon being
single-threaded to keep from processing data on an inbound TLS connection while
talking to another TLS connection for an outbound check.  This does mean that
there's no way for heart-beats to be responded to, for the duration of the
second connection.
XXX But see gnutls_session_get_ptr()
*/

static exim_gnutls_state_st state_server;

/* dh_params are initialised once within the lifetime of a process using TLS;
if we used TLS in a long-lived daemon, we'd have to reconsider this.  But we
don't want to repeat this. */

static gnutls_dh_params_t dh_server_params = NULL;

/* No idea how this value was chosen; preserving it.  Default is 3600. */

static const int ssl_session_timeout = 200;

static const char * const exim_default_gnutls_priority = "NORMAL";

/* Guard library core initialisation */

static BOOL exim_gnutls_base_init_done = FALSE;

#ifndef DISABLE_OCSP
static BOOL gnutls_buggy_ocsp = FALSE;
#endif


/* ------------------------------------------------------------------------ */
/* macros */

#define MAX_HOST_LEN 255

/* Set this to control gnutls_global_set_log_level(); values 0 to 9 will setup
the library logging; a value less than 0 disables the calls to set up logging
callbacks.  Possibly GNuTLS also looks for an environment variable
"GNUTLS_DEBUG_LEVEL". */
#ifndef EXIM_GNUTLS_LIBRARY_LOG_LEVEL
# define EXIM_GNUTLS_LIBRARY_LOG_LEVEL -1
#endif

#ifndef EXIM_CLIENT_DH_MIN_BITS
# define EXIM_CLIENT_DH_MIN_BITS 1024
#endif

/* With GnuTLS 2.12.x+ we have gnutls_sec_param_to_pk_bits() with which we
can ask for a bit-strength.  Without that, we stick to the constant we had
before, for now. */
#ifndef EXIM_SERVER_DH_BITS_PRE2_12
# define EXIM_SERVER_DH_BITS_PRE2_12 1024
#endif

#define exim_gnutls_err_check(rc, Label) do { \
  if ((rc) != GNUTLS_E_SUCCESS) \
    return tls_error((Label), US gnutls_strerror(rc), host, errstr); \
  } while (0)

#define expand_check_tlsvar(Varname, errstr) \
  expand_check(state->Varname, US #Varname, &state->exp_##Varname, errstr)

#if GNUTLS_VERSION_NUMBER >= 0x020c00
# define HAVE_GNUTLS_SESSION_CHANNEL_BINDING
# define HAVE_GNUTLS_SEC_PARAM_CONSTANTS
# define HAVE_GNUTLS_RND
/* The security fix we provide with the gnutls_allow_auto_pkcs11 option
 * (4.82 PP/09) introduces a compatibility regression. The symbol simply
 * isn't available sometimes, so this needs to become a conditional
 * compilation; the sanest way to deal with this being a problem on
 * older OSes is to block it in the Local/Makefile with this compiler
 * definition  */
# ifndef AVOID_GNUTLS_PKCS11
#  define HAVE_GNUTLS_PKCS11
# endif /* AVOID_GNUTLS_PKCS11 */
#endif




/* ------------------------------------------------------------------------ */
/* Callback declarations */

#if EXIM_GNUTLS_LIBRARY_LOG_LEVEL >= 0
static void exim_gnutls_logger_cb(int level, const char *message);
#endif

static int exim_sni_handling_cb(gnutls_session_t session);

#ifndef DISABLE_OCSP
static int server_ocsp_stapling_cb(gnutls_session_t session, void * ptr,
  gnutls_datum_t * ocsp_response);
#endif



/* ------------------------------------------------------------------------ */
/* Static functions */

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
  msg       additional error string (may be NULL)
            usually obtained from gnutls_strerror()
  host      NULL if setting up a server;
            the connected host if setting up a client
  errstr    pointer to returned error string

Returns:    OK/DEFER/FAIL
*/

static int
tls_error(const uschar *prefix, const uschar *msg, const host_item *host,
  uschar ** errstr)
{
if (errstr)
  *errstr = string_sprintf("(%s)%s%s", prefix, msg ? ": " : "", msg ? msg : US"");
return host ? FAIL : DEFER;
}




/*************************************************
*    Deal with logging errors during I/O         *
*************************************************/

/* We have to get the identity of the peer from saved data.

Argument:
  state    the current GnuTLS exim state container
  rc       the GnuTLS error code, or 0 if it's a local error
  when     text identifying read or write
  text     local error text when ec is 0

Returns:   nothing
*/

static void
record_io_error(exim_gnutls_state_st *state, int rc, uschar *when, uschar *text)
{
const uschar * msg;
uschar * errstr;

if (rc == GNUTLS_E_FATAL_ALERT_RECEIVED)
  msg = string_sprintf("%s: %s", US gnutls_strerror(rc),
    US gnutls_alert_get_name(gnutls_alert_get(state->session)));
else
  msg = US gnutls_strerror(rc);

(void) tls_error(when, msg, state->host, &errstr);

if (state->host)
  log_write(0, LOG_MAIN, "H=%s [%s] TLS error on connection %s",
    state->host->name, state->host->address, errstr);
else
  {
  uschar * conn_info = smtp_get_connection_info();
  if (Ustrncmp(conn_info, US"SMTP ", 5) == 0) conn_info += 5;
  /* I'd like to get separated H= here, but too hard for now */
  log_write(0, LOG_MAIN, "TLS error on %s %s", conn_info, errstr);
  }
}




/*************************************************
*        Set various Exim expansion vars         *
*************************************************/

#define exim_gnutls_cert_err(Label) \
  do \
    { \
    if (rc != GNUTLS_E_SUCCESS) \
      { \
      DEBUG(D_tls) debug_printf("TLS: cert problem: %s: %s\n", \
	(Label), gnutls_strerror(rc)); \
      return rc; \
      } \
    } while (0)

static int
import_cert(const gnutls_datum_t * cert, gnutls_x509_crt_t * crtp)
{
int rc;

rc = gnutls_x509_crt_init(crtp);
exim_gnutls_cert_err(US"gnutls_x509_crt_init (crt)");

rc = gnutls_x509_crt_import(*crtp, cert, GNUTLS_X509_FMT_DER);
exim_gnutls_cert_err(US"failed to import certificate [gnutls_x509_crt_import(cert)]");

return rc;
}

#undef exim_gnutls_cert_err


/* We set various Exim global variables from the state, once a session has
been established.  With TLS callouts, may need to change this to stack
variables, or just re-call it with the server state after client callout
has finished.

Make sure anything set here is unset in tls_getc().

Sets:
  tls_active                fd
  tls_bits                  strength indicator
  tls_certificate_verified  bool indicator
  tls_channelbinding_b64    for some SASL mechanisms
  tls_cipher                a string
  tls_peercert              pointer to library internal
  tls_peerdn                a string
  tls_sni                   a (UTF-8) string
  tls_ourcert               pointer to library internal

Argument:
  state      the relevant exim_gnutls_state_st *
*/

static void
extract_exim_vars_from_tls_state(exim_gnutls_state_st * state)
{
gnutls_cipher_algorithm_t cipher;
#ifdef HAVE_GNUTLS_SESSION_CHANNEL_BINDING
int old_pool;
int rc;
gnutls_datum_t channel;
#endif
tls_support * tlsp = state->tlsp;

tlsp->active.sock = state->fd_out;
tlsp->active.tls_ctx = state;

cipher = gnutls_cipher_get(state->session);
/* returns size in "bytes" */
tlsp->bits = gnutls_cipher_get_key_size(cipher) * 8;

tlsp->cipher = state->ciphersuite;

DEBUG(D_tls) debug_printf("cipher: %s\n", state->ciphersuite);

tlsp->certificate_verified = state->peer_cert_verified;
#ifdef SUPPORT_DANE
tlsp->dane_verified = state->peer_dane_verified;
#endif

/* note that tls_channelbinding_b64 is not saved to the spool file, since it's
only available for use for authenticators while this TLS session is running. */

tls_channelbinding_b64 = NULL;
#ifdef HAVE_GNUTLS_SESSION_CHANNEL_BINDING
channel.data = NULL;
channel.size = 0;
rc = gnutls_session_channel_binding(state->session, GNUTLS_CB_TLS_UNIQUE, &channel);
if (rc) {
  DEBUG(D_tls) debug_printf("Channel binding error: %s\n", gnutls_strerror(rc));
} else {
  old_pool = store_pool;
  store_pool = POOL_PERM;
  tls_channelbinding_b64 = b64encode(channel.data, (int)channel.size);
  store_pool = old_pool;
  DEBUG(D_tls) debug_printf("Have channel bindings cached for possible auth usage.\n");
}
#endif

/* peercert is set in peer_status() */
tlsp->peerdn = state->peerdn;
tlsp->sni =    state->received_sni;

/* record our certificate */
  {
  const gnutls_datum_t * cert = gnutls_certificate_get_ours(state->session);
  gnutls_x509_crt_t crt;

  tlsp->ourcert = cert && import_cert(cert, &crt)==0 ? crt : NULL;
  }
}




/*************************************************
*            Setup up DH parameters              *
*************************************************/

/* Generating the D-H parameters may take a long time. They only need to
be re-generated every so often, depending on security policy. What we do is to
keep these parameters in a file in the spool directory. If the file does not
exist, we generate them. This means that it is easy to cause a regeneration.

The new file is written as a temporary file and renamed, so that an incomplete
file is never present. If two processes both compute some new parameters, you
waste a bit of effort, but it doesn't seem worth messing around with locking to
prevent this.

Returns:     OK/DEFER/FAIL
*/

static int
init_server_dh(uschar ** errstr)
{
int fd, rc;
unsigned int dh_bits;
gnutls_datum_t m;
uschar filename_buf[PATH_MAX];
uschar *filename = NULL;
size_t sz;
uschar *exp_tls_dhparam;
BOOL use_file_in_spool = FALSE;
BOOL use_fixed_file = FALSE;
host_item *host = NULL; /* dummy for macros */

DEBUG(D_tls) debug_printf("Initialising GnuTLS server params.\n");

rc = gnutls_dh_params_init(&dh_server_params);
exim_gnutls_err_check(rc, US"gnutls_dh_params_init");

m.data = NULL;
m.size = 0;

if (!expand_check(tls_dhparam, US"tls_dhparam", &exp_tls_dhparam, errstr))
  return DEFER;

if (!exp_tls_dhparam)
  {
  DEBUG(D_tls) debug_printf("Loading default hard-coded DH params\n");
  m.data = US std_dh_prime_default();
  m.size = Ustrlen(m.data);
  }
else if (Ustrcmp(exp_tls_dhparam, "historic") == 0)
  use_file_in_spool = TRUE;
else if (Ustrcmp(exp_tls_dhparam, "none") == 0)
  {
  DEBUG(D_tls) debug_printf("Requested no DH parameters.\n");
  return OK;
  }
else if (exp_tls_dhparam[0] != '/')
  {
  if (!(m.data = US std_dh_prime_named(exp_tls_dhparam)))
    return tls_error(US"No standard prime named", exp_tls_dhparam, NULL, errstr);
  m.size = Ustrlen(m.data);
  }
else
  {
  use_fixed_file = TRUE;
  filename = exp_tls_dhparam;
  }

if (m.data)
  {
  rc = gnutls_dh_params_import_pkcs3(dh_server_params, &m, GNUTLS_X509_FMT_PEM);
  exim_gnutls_err_check(rc, US"gnutls_dh_params_import_pkcs3");
  DEBUG(D_tls) debug_printf("Loaded fixed standard D-H parameters\n");
  return OK;
  }

#ifdef HAVE_GNUTLS_SEC_PARAM_CONSTANTS
/* If you change this constant, also change dh_param_fn_ext so that we can use a
different filename and ensure we have sufficient bits. */
dh_bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, GNUTLS_SEC_PARAM_NORMAL);
if (!dh_bits)
  return tls_error(US"gnutls_sec_param_to_pk_bits() failed", NULL, NULL, errstr);
DEBUG(D_tls)
  debug_printf("GnuTLS tells us that for D-H PK, NORMAL is %d bits.\n",
      dh_bits);
#else
dh_bits = EXIM_SERVER_DH_BITS_PRE2_12;
DEBUG(D_tls)
  debug_printf("GnuTLS lacks gnutls_sec_param_to_pk_bits(), using %d bits.\n",
      dh_bits);
#endif

/* Some clients have hard-coded limits. */
if (dh_bits > tls_dh_max_bits)
  {
  DEBUG(D_tls)
    debug_printf("tls_dh_max_bits clamping override, using %d bits instead.\n",
        tls_dh_max_bits);
  dh_bits = tls_dh_max_bits;
  }

if (use_file_in_spool)
  {
  if (!string_format(filename_buf, sizeof(filename_buf),
        "%s/gnutls-params-%d", spool_directory, dh_bits))
    return tls_error(US"overlong filename", NULL, NULL, errstr);
  filename = filename_buf;
  }

/* Open the cache file for reading and if successful, read it and set up the
parameters. */

if ((fd = Uopen(filename, O_RDONLY, 0)) >= 0)
  {
  struct stat statbuf;
  FILE *fp;
  int saved_errno;

  if (fstat(fd, &statbuf) < 0)  /* EIO */
    {
    saved_errno = errno;
    (void)close(fd);
    return tls_error(US"TLS cache stat failed", US strerror(saved_errno), NULL, errstr);
    }
  if (!S_ISREG(statbuf.st_mode))
    {
    (void)close(fd);
    return tls_error(US"TLS cache not a file", NULL, NULL, errstr);
    }
  if (!(fp = fdopen(fd, "rb")))
    {
    saved_errno = errno;
    (void)close(fd);
    return tls_error(US"fdopen(TLS cache stat fd) failed",
        US strerror(saved_errno), NULL, errstr);
    }

  m.size = statbuf.st_size;
  if (!(m.data = malloc(m.size)))
    {
    fclose(fp);
    return tls_error(US"malloc failed", US strerror(errno), NULL, errstr);
    }
  if (!(sz = fread(m.data, m.size, 1, fp)))
    {
    saved_errno = errno;
    fclose(fp);
    free(m.data);
    return tls_error(US"fread failed", US strerror(saved_errno), NULL, errstr);
    }
  fclose(fp);

  rc = gnutls_dh_params_import_pkcs3(dh_server_params, &m, GNUTLS_X509_FMT_PEM);
  free(m.data);
  exim_gnutls_err_check(rc, US"gnutls_dh_params_import_pkcs3");
  DEBUG(D_tls) debug_printf("read D-H parameters from file \"%s\"\n", filename);
  }

/* If the file does not exist, fall through to compute new data and cache it.
If there was any other opening error, it is serious. */

else if (errno == ENOENT)
  {
  rc = -1;
  DEBUG(D_tls)
    debug_printf("D-H parameter cache file \"%s\" does not exist\n", filename);
  }
else
  return tls_error(string_open_failed(errno, "\"%s\" for reading", filename),
      NULL, NULL, errstr);

/* If ret < 0, either the cache file does not exist, or the data it contains
is not useful. One particular case of this is when upgrading from an older
release of Exim in which the data was stored in a different format. We don't
try to be clever and support both formats; we just regenerate new data in this
case. */

if (rc < 0)
  {
  uschar *temp_fn;
  unsigned int dh_bits_gen = dh_bits;

  if ((PATH_MAX - Ustrlen(filename)) < 10)
    return tls_error(US"Filename too long to generate replacement",
        filename, NULL, errstr);

  temp_fn = string_copy(US"%s.XXXXXXX");
  if ((fd = mkstemp(CS temp_fn)) < 0)	/* modifies temp_fn */
    return tls_error(US"Unable to open temp file", US strerror(errno), NULL, errstr);
  (void)fchown(fd, exim_uid, exim_gid);   /* Probably not necessary */

  /* GnuTLS overshoots!
   * If we ask for 2236, we might get 2237 or more.
   * But there's no way to ask GnuTLS how many bits there really are.
   * We can ask how many bits were used in a TLS session, but that's it!
   * The prime itself is hidden behind too much abstraction.
   * So we ask for less, and proceed on a wing and a prayer.
   * First attempt, subtracted 3 for 2233 and got 2240.
   */
  if (dh_bits >= EXIM_CLIENT_DH_MIN_BITS + 10)
    {
    dh_bits_gen = dh_bits - 10;
    DEBUG(D_tls)
      debug_printf("being paranoid about DH generation, make it '%d' bits'\n",
          dh_bits_gen);
    }

  DEBUG(D_tls)
    debug_printf("requesting generation of %d bit Diffie-Hellman prime ...\n",
        dh_bits_gen);
  rc = gnutls_dh_params_generate2(dh_server_params, dh_bits_gen);
  exim_gnutls_err_check(rc, US"gnutls_dh_params_generate2");

  /* gnutls_dh_params_export_pkcs3() will tell us the exact size, every time,
  and I confirmed that a NULL call to get the size first is how the GnuTLS
  sample apps handle this. */

  sz = 0;
  m.data = NULL;
  rc = gnutls_dh_params_export_pkcs3(dh_server_params, GNUTLS_X509_FMT_PEM,
      m.data, &sz);
  if (rc != GNUTLS_E_SHORT_MEMORY_BUFFER)
    exim_gnutls_err_check(rc, US"gnutls_dh_params_export_pkcs3(NULL) sizing");
  m.size = sz;
  if (!(m.data = malloc(m.size)))
    return tls_error(US"memory allocation failed", US strerror(errno), NULL, errstr);

  /* this will return a size 1 less than the allocation size above */
  rc = gnutls_dh_params_export_pkcs3(dh_server_params, GNUTLS_X509_FMT_PEM,
      m.data, &sz);
  if (rc != GNUTLS_E_SUCCESS)
    {
    free(m.data);
    exim_gnutls_err_check(rc, US"gnutls_dh_params_export_pkcs3() real");
    }
  m.size = sz; /* shrink by 1, probably */

  if ((sz = write_to_fd_buf(fd, m.data, (size_t) m.size)) != m.size)
    {
    free(m.data);
    return tls_error(US"TLS cache write D-H params failed",
        US strerror(errno), NULL, errstr);
    }
  free(m.data);
  if ((sz = write_to_fd_buf(fd, US"\n", 1)) != 1)
    return tls_error(US"TLS cache write D-H params final newline failed",
        US strerror(errno), NULL, errstr);

  if ((rc = close(fd)))
    return tls_error(US"TLS cache write close() failed", US strerror(errno), NULL, errstr);

  if (Urename(temp_fn, filename) < 0)
    return tls_error(string_sprintf("failed to rename \"%s\" as \"%s\"",
          temp_fn, filename), US strerror(errno), NULL, errstr);

  DEBUG(D_tls) debug_printf("wrote D-H parameters to file \"%s\"\n", filename);
  }

DEBUG(D_tls) debug_printf("initialized server D-H parameters\n");
return OK;
}




/* Create and install a selfsigned certificate, for use in server mode */

static int
tls_install_selfsign(exim_gnutls_state_st * state, uschar ** errstr)
{
gnutls_x509_crt_t cert = NULL;
time_t now;
gnutls_x509_privkey_t pkey = NULL;
const uschar * where;
int rc;

where = US"initialising pkey";
if ((rc = gnutls_x509_privkey_init(&pkey))) goto err;

where = US"initialising cert";
if ((rc = gnutls_x509_crt_init(&cert))) goto err;

where = US"generating pkey";
if ((rc = gnutls_x509_privkey_generate(pkey, GNUTLS_PK_RSA,
#ifdef SUPPORT_PARAM_TO_PK_BITS
# ifndef GNUTLS_SEC_PARAM_MEDIUM
#  define GNUTLS_SEC_PARAM_MEDIUM GNUTLS_SEC_PARAM_HIGH
# endif
	    gnutls_sec_param_to_pk_bits(GNUTLS_PK_RSA, GNUTLS_SEC_PARAM_MEDIUM),
#else
	    2048,
#endif
	    0)))
  goto err;

where = US"configuring cert";
now = 1;
if (  (rc = gnutls_x509_crt_set_version(cert, 3))
   || (rc = gnutls_x509_crt_set_serial(cert, &now, sizeof(now)))
   || (rc = gnutls_x509_crt_set_activation_time(cert, now = time(NULL)))
   || (rc = gnutls_x509_crt_set_expiration_time(cert, now + 60 * 60)) /* 1 hr */
   || (rc = gnutls_x509_crt_set_key(cert, pkey))

   || (rc = gnutls_x509_crt_set_dn_by_oid(cert,
	      GNUTLS_OID_X520_COUNTRY_NAME, 0, "UK", 2))
   || (rc = gnutls_x509_crt_set_dn_by_oid(cert,
	      GNUTLS_OID_X520_ORGANIZATION_NAME, 0, "Exim Developers", 15))
   || (rc = gnutls_x509_crt_set_dn_by_oid(cert,
	      GNUTLS_OID_X520_COMMON_NAME, 0,
	      smtp_active_hostname, Ustrlen(smtp_active_hostname)))
   )
  goto err;

where = US"signing cert";
if ((rc = gnutls_x509_crt_sign(cert, cert, pkey))) goto err;

where = US"installing selfsign cert";
					/* Since: 2.4.0 */
if ((rc = gnutls_certificate_set_x509_key(state->x509_cred, &cert, 1, pkey)))
  goto err;

rc = OK;

out:
  if (cert) gnutls_x509_crt_deinit(cert);
  if (pkey) gnutls_x509_privkey_deinit(pkey);
  return rc;

err:
  rc = tls_error(where, US gnutls_strerror(rc), NULL, errstr);
  goto out;
}




/* Add certificate and key, from files.

Return:
  Zero or negative: good.  Negate value for certificate index if < 0.
  Greater than zero: FAIL or DEFER code.
*/

static int
tls_add_certfile(exim_gnutls_state_st * state, const host_item * host,
  uschar * certfile, uschar * keyfile, uschar ** errstr)
{
int rc = gnutls_certificate_set_x509_key_file(state->x509_cred,
    CS certfile, CS keyfile, GNUTLS_X509_FMT_PEM);
if (rc < 0)
  return tls_error(
    string_sprintf("cert/key setup: cert=%s key=%s", certfile, keyfile),
    US gnutls_strerror(rc), host, errstr);
return -rc;
}


/*************************************************
*       Variables re-expanded post-SNI           *
*************************************************/

/* Called from both server and client code, via tls_init(), and also from
the SNI callback after receiving an SNI, if tls_certificate includes "tls_sni".

We can tell the two apart by state->received_sni being non-NULL in callback.

The callback should not call us unless state->trigger_sni_changes is true,
which we are responsible for setting on the first pass through.

Arguments:
  state           exim_gnutls_state_st *
  errstr	  error string pointer

Returns:          OK/DEFER/FAIL
*/

static int
tls_expand_session_files(exim_gnutls_state_st * state, uschar ** errstr)
{
struct stat statbuf;
int rc;
const host_item *host = state->host;  /* macro should be reconsidered? */
uschar *saved_tls_certificate = NULL;
uschar *saved_tls_privatekey = NULL;
uschar *saved_tls_verify_certificates = NULL;
uschar *saved_tls_crl = NULL;
int cert_count;

/* We check for tls_sni *before* expansion. */
if (!host)	/* server */
  if (!state->received_sni)
    {
    if (  state->tls_certificate
       && (  Ustrstr(state->tls_certificate, US"tls_sni")
	  || Ustrstr(state->tls_certificate, US"tls_in_sni")
	  || Ustrstr(state->tls_certificate, US"tls_out_sni")
       )  )
      {
      DEBUG(D_tls) debug_printf("We will re-expand TLS session files if we receive SNI.\n");
      state->trigger_sni_changes = TRUE;
      }
    }
  else
    {
    /* useful for debugging */
    saved_tls_certificate = state->exp_tls_certificate;
    saved_tls_privatekey = state->exp_tls_privatekey;
    saved_tls_verify_certificates = state->exp_tls_verify_certificates;
    saved_tls_crl = state->exp_tls_crl;
    }

rc = gnutls_certificate_allocate_credentials(&state->x509_cred);
exim_gnutls_err_check(rc, US"gnutls_certificate_allocate_credentials");

#ifdef SUPPORT_SRV_OCSP_STACK
gnutls_certificate_set_flags(state->x509_cred, GNUTLS_CERTIFICATE_API_V2);
#endif

/* remember: expand_check_tlsvar() is expand_check() but fiddling with
state members, assuming consistent naming; and expand_check() returns
false if expansion failed, unless expansion was forced to fail. */

/* check if we at least have a certificate, before doing expensive
D-H generation. */

if (!expand_check_tlsvar(tls_certificate, errstr))
  return DEFER;

/* certificate is mandatory in server, optional in client */

if (  !state->exp_tls_certificate
   || !*state->exp_tls_certificate
   )
  if (!host)
    return tls_install_selfsign(state, errstr);
  else
    DEBUG(D_tls) debug_printf("TLS: no client certificate specified; okay\n");

if (state->tls_privatekey && !expand_check_tlsvar(tls_privatekey, errstr))
  return DEFER;

/* tls_privatekey is optional, defaulting to same file as certificate */

if (state->tls_privatekey == NULL || *state->tls_privatekey == '\0')
  {
  state->tls_privatekey = state->tls_certificate;
  state->exp_tls_privatekey = state->exp_tls_certificate;
  }


if (state->exp_tls_certificate && *state->exp_tls_certificate)
  {
  DEBUG(D_tls) debug_printf("certificate file = %s\nkey file = %s\n",
      state->exp_tls_certificate, state->exp_tls_privatekey);

  if (state->received_sni)
    if (  Ustrcmp(state->exp_tls_certificate, saved_tls_certificate) == 0
       && Ustrcmp(state->exp_tls_privatekey,  saved_tls_privatekey)  == 0
       )
      {
      DEBUG(D_tls) debug_printf("TLS SNI: cert and key unchanged\n");
      }
    else
      {
      DEBUG(D_tls) debug_printf("TLS SNI: have a changed cert/key pair.\n");
      }

  if (!host)	/* server */
    {
    const uschar * clist = state->exp_tls_certificate;
    const uschar * klist = state->exp_tls_privatekey;
    const uschar * olist;
    int csep = 0, ksep = 0, osep = 0, cnt = 0;
    uschar * cfile, * kfile, * ofile;

#ifndef DISABLE_OCSP
    if (!expand_check(tls_ocsp_file, US"tls_ocsp_file", &ofile, errstr))
      return DEFER;
    olist = ofile;
#endif

    while (cfile = string_nextinlist(&clist, &csep, NULL, 0))

      if (!(kfile = string_nextinlist(&klist, &ksep, NULL, 0)))
	return tls_error(US"cert/key setup: out of keys", NULL, host, errstr);
      else if (0 < (rc = tls_add_certfile(state, host, cfile, kfile, errstr)))
	return rc;
      else
	{
	int gnutls_cert_index = -rc;
	DEBUG(D_tls) debug_printf("TLS: cert/key %s registered\n", cfile);

	/* Set the OCSP stapling server info */

#ifndef DISABLE_OCSP
	if (tls_ocsp_file)
	  if (gnutls_buggy_ocsp)
	    {
	    DEBUG(D_tls)
	      debug_printf("GnuTLS library is buggy for OCSP; avoiding\n");
	    }
	  else if ((ofile = string_nextinlist(&olist, &osep, NULL, 0)))
	    {
	    /* Use the full callback method for stapling just to get
	    observability.  More efficient would be to read the file once only,
	    if it never changed (due to SNI). Would need restart on file update,
	    or watch datestamp.  */

# ifdef SUPPORT_SRV_OCSP_STACK
	    rc = gnutls_certificate_set_ocsp_status_request_function2(
	      state->x509_cred, gnutls_cert_index,
	      server_ocsp_stapling_cb, ofile);

	    exim_gnutls_err_check(rc,
	      US"gnutls_certificate_set_ocsp_status_request_function2");
# else
	    if (cnt++ > 0)
	      {
	      DEBUG(D_tls)
		debug_printf("oops; multiple OCSP files not supported\n");
	      break;
	      }
	      gnutls_certificate_set_ocsp_status_request_function(
		state->x509_cred, server_ocsp_stapling_cb, ofile);
# endif

	    DEBUG(D_tls) debug_printf("OCSP response file = %s\n", ofile);
	    }
	  else
	    DEBUG(D_tls) debug_printf("ran out of OCSP response files in list\n");
#endif
	}
    }
  else
    {
    if (0 < (rc = tls_add_certfile(state, host,
		state->exp_tls_certificate, state->exp_tls_privatekey, errstr)))
      return rc;
    DEBUG(D_tls) debug_printf("TLS: cert/key registered\n");
    }

  } /* tls_certificate */


/* Set the trusted CAs file if one is provided, and then add the CRL if one is
provided. Experiment shows that, if the certificate file is empty, an unhelpful
error message is provided. However, if we just refrain from setting anything up
in that case, certificate verification fails, which seems to be the correct
behaviour. */

if (state->tls_verify_certificates && *state->tls_verify_certificates)
  {
  if (!expand_check_tlsvar(tls_verify_certificates, errstr))
    return DEFER;
#ifndef SUPPORT_SYSDEFAULT_CABUNDLE
  if (Ustrcmp(state->exp_tls_verify_certificates, "system") == 0)
    state->exp_tls_verify_certificates = NULL;
#endif
  if (state->tls_crl && *state->tls_crl)
    if (!expand_check_tlsvar(tls_crl, errstr))
      return DEFER;

  if (!(state->exp_tls_verify_certificates &&
        *state->exp_tls_verify_certificates))
    {
    DEBUG(D_tls)
      debug_printf("TLS: tls_verify_certificates expanded empty, ignoring\n");
    /* With no tls_verify_certificates, we ignore tls_crl too */
    return OK;
    }
  }
else
  {
  DEBUG(D_tls)
    debug_printf("TLS: tls_verify_certificates not set or empty, ignoring\n");
  return OK;
  }

#ifdef SUPPORT_SYSDEFAULT_CABUNDLE
if (Ustrcmp(state->exp_tls_verify_certificates, "system") == 0)
  cert_count = gnutls_certificate_set_x509_system_trust(state->x509_cred);
else
#endif
  {
  if (Ustat(state->exp_tls_verify_certificates, &statbuf) < 0)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "could not stat %s "
	"(tls_verify_certificates): %s", state->exp_tls_verify_certificates,
	strerror(errno));
    return DEFER;
    }

#ifndef SUPPORT_CA_DIR
  /* The test suite passes in /dev/null; we could check for that path explicitly,
  but who knows if someone has some weird FIFO which always dumps some certs, or
  other weirdness.  The thing we really want to check is that it's not a
  directory, since while OpenSSL supports that, GnuTLS does not.
  So s/!S_ISREG/S_ISDIR/ and change some messaging ... */
  if (S_ISDIR(statbuf.st_mode))
    {
    DEBUG(D_tls)
      debug_printf("verify certificates path is a dir: \"%s\"\n",
	  state->exp_tls_verify_certificates);
    log_write(0, LOG_MAIN|LOG_PANIC,
	"tls_verify_certificates \"%s\" is a directory",
	state->exp_tls_verify_certificates);
    return DEFER;
    }
#endif

  DEBUG(D_tls) debug_printf("verify certificates = %s size=" OFF_T_FMT "\n",
	  state->exp_tls_verify_certificates, statbuf.st_size);

  if (statbuf.st_size == 0)
    {
    DEBUG(D_tls)
      debug_printf("cert file empty, no certs, no verification, ignoring any CRL\n");
    return OK;
    }

  cert_count =

#ifdef SUPPORT_CA_DIR
    (statbuf.st_mode & S_IFMT) == S_IFDIR
    ?
    gnutls_certificate_set_x509_trust_dir(state->x509_cred,
      CS state->exp_tls_verify_certificates, GNUTLS_X509_FMT_PEM)
    :
#endif
    gnutls_certificate_set_x509_trust_file(state->x509_cred,
      CS state->exp_tls_verify_certificates, GNUTLS_X509_FMT_PEM);
  }

if (cert_count < 0)
  {
  rc = cert_count;
  exim_gnutls_err_check(rc, US"setting certificate trust");
  }
DEBUG(D_tls) debug_printf("Added %d certificate authorities.\n", cert_count);

if (state->tls_crl && *state->tls_crl &&
    state->exp_tls_crl && *state->exp_tls_crl)
  {
  DEBUG(D_tls) debug_printf("loading CRL file = %s\n", state->exp_tls_crl);
  cert_count = gnutls_certificate_set_x509_crl_file(state->x509_cred,
      CS state->exp_tls_crl, GNUTLS_X509_FMT_PEM);
  if (cert_count < 0)
    {
    rc = cert_count;
    exim_gnutls_err_check(rc, US"gnutls_certificate_set_x509_crl_file");
    }
  DEBUG(D_tls) debug_printf("Processed %d CRLs.\n", cert_count);
  }

return OK;
}




/*************************************************
*          Set X.509 state variables             *
*************************************************/

/* In GnuTLS, the registered cert/key are not replaced by a later
set of a cert/key, so for SNI support we need a whole new x509_cred
structure.  Which means various other non-re-expanded pieces of state
need to be re-set in the new struct, so the setting logic is pulled
out to this.

Arguments:
  state           exim_gnutls_state_st *
  errstr	  error string pointer

Returns:          OK/DEFER/FAIL
*/

static int
tls_set_remaining_x509(exim_gnutls_state_st *state, uschar ** errstr)
{
int rc;
const host_item *host = state->host;  /* macro should be reconsidered? */

/* Create D-H parameters, or read them from the cache file. This function does
its own SMTP error messaging. This only happens for the server, TLS D-H ignores
client-side params. */

if (!state->host)
  {
  if (!dh_server_params)
    {
    rc = init_server_dh(errstr);
    if (rc != OK) return rc;
    }
  gnutls_certificate_set_dh_params(state->x509_cred, dh_server_params);
  }

/* Link the credentials to the session. */

rc = gnutls_credentials_set(state->session, GNUTLS_CRD_CERTIFICATE, state->x509_cred);
exim_gnutls_err_check(rc, US"gnutls_credentials_set");

return OK;
}

/*************************************************
*            Initialize for GnuTLS               *
*************************************************/


#ifndef DISABLE_OCSP

static BOOL
tls_is_buggy_ocsp(void)
{
const uschar * s;
uschar maj, mid, mic;

s = CUS gnutls_check_version(NULL);
maj = atoi(CCS s);
if (maj == 3)
  {
  while (*s && *s != '.') s++;
  mid = atoi(CCS ++s);
  if (mid <= 2)
    return TRUE;
  else if (mid >= 5)
    return FALSE;
  else
    {
    while (*s && *s != '.') s++;
    mic = atoi(CCS ++s);
    return mic <= (mid == 3 ? 16 : 3);
    }
  }
return FALSE;
}

#endif


/* Called from both server and client code. In the case of a server, errors
before actual TLS negotiation return DEFER.

Arguments:
  host            connected host, if client; NULL if server
  certificate     certificate file
  privatekey      private key file
  sni             TLS SNI to send, sometimes when client; else NULL
  cas             CA certs file
  crl             CRL file
  require_ciphers tls_require_ciphers setting
  caller_state    returned state-info structure
  errstr	  error string pointer

Returns:          OK/DEFER/FAIL
*/

static int
tls_init(
    const host_item *host,
    const uschar *certificate,
    const uschar *privatekey,
    const uschar *sni,
    const uschar *cas,
    const uschar *crl,
    const uschar *require_ciphers,
    exim_gnutls_state_st **caller_state,
    tls_support * tlsp,
    uschar ** errstr)
{
exim_gnutls_state_st *state;
int rc;
size_t sz;
const char *errpos;
uschar *p;
BOOL want_default_priorities;

if (!exim_gnutls_base_init_done)
  {
  DEBUG(D_tls) debug_printf("GnuTLS global init required.\n");

#ifdef HAVE_GNUTLS_PKCS11
  /* By default, gnutls_global_init will init PKCS11 support in auto mode,
  which loads modules from a config file, which sounds good and may be wanted
  by some sysadmin, but also means in common configurations that GNOME keyring
  environment variables are used and so breaks for users calling mailq.
  To prevent this, we init PKCS11 first, which is the documented approach. */
  if (!gnutls_allow_auto_pkcs11)
    {
    rc = gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL);
    exim_gnutls_err_check(rc, US"gnutls_pkcs11_init");
    }
#endif

  rc = gnutls_global_init();
  exim_gnutls_err_check(rc, US"gnutls_global_init");

#if EXIM_GNUTLS_LIBRARY_LOG_LEVEL >= 0
  DEBUG(D_tls)
    {
    gnutls_global_set_log_function(exim_gnutls_logger_cb);
    /* arbitrarily chosen level; bump up to 9 for more */
    gnutls_global_set_log_level(EXIM_GNUTLS_LIBRARY_LOG_LEVEL);
    }
#endif

#ifndef DISABLE_OCSP
  if (tls_ocsp_file && (gnutls_buggy_ocsp = tls_is_buggy_ocsp()))
    log_write(0, LOG_MAIN, "OCSP unusable with this GnuTLS library version");
#endif

  exim_gnutls_base_init_done = TRUE;
  }

if (host)
  {
  /* For client-side sessions we allocate a context. This lets us run
  several in parallel. */
  int old_pool = store_pool;
  store_pool = POOL_PERM;
  state = store_get(sizeof(exim_gnutls_state_st));
  store_pool = old_pool;

  memcpy(state, &exim_gnutls_state_init, sizeof(exim_gnutls_state_init));
  state->tlsp = tlsp;
  DEBUG(D_tls) debug_printf("initialising GnuTLS client session\n");
  rc = gnutls_init(&state->session, GNUTLS_CLIENT);
  }
else
  {
  state = &state_server;
  memcpy(state, &exim_gnutls_state_init, sizeof(exim_gnutls_state_init));
  state->tlsp = tlsp;
  DEBUG(D_tls) debug_printf("initialising GnuTLS server session\n");
  rc = gnutls_init(&state->session, GNUTLS_SERVER);
  }
exim_gnutls_err_check(rc, US"gnutls_init");

state->host = host;

state->tls_certificate = certificate;
state->tls_privatekey = privatekey;
state->tls_require_ciphers = require_ciphers;
state->tls_sni = sni;
state->tls_verify_certificates = cas;
state->tls_crl = crl;

/* This handles the variables that might get re-expanded after TLS SNI;
that's tls_certificate, tls_privatekey, tls_verify_certificates, tls_crl */

DEBUG(D_tls)
  debug_printf("Expanding various TLS configuration options for session credentials.\n");
if ((rc = tls_expand_session_files(state, errstr)) != OK) return rc;

/* These are all other parts of the x509_cred handling, since SNI in GnuTLS
requires a new structure afterwards. */

if ((rc = tls_set_remaining_x509(state, errstr)) != OK) return rc;

/* set SNI in client, only */
if (host)
  {
  if (!expand_check(sni, US"tls_out_sni", &state->tlsp->sni, errstr))
    return DEFER;
  if (state->tlsp->sni && *state->tlsp->sni)
    {
    DEBUG(D_tls)
      debug_printf("Setting TLS client SNI to \"%s\"\n", state->tlsp->sni);
    sz = Ustrlen(state->tlsp->sni);
    rc = gnutls_server_name_set(state->session,
        GNUTLS_NAME_DNS, state->tlsp->sni, sz);
    exim_gnutls_err_check(rc, US"gnutls_server_name_set");
    }
  }
else if (state->tls_sni)
  DEBUG(D_tls) debug_printf("*** PROBABLY A BUG *** " \
      "have an SNI set for a server [%s]\n", state->tls_sni);

/* This is the priority string support,
http://www.gnutls.org/manual/html_node/Priority-Strings.html
and replaces gnutls_require_kx, gnutls_require_mac & gnutls_require_protocols.
This was backwards incompatible, but means Exim no longer needs to track
all algorithms and provide string forms for them. */

want_default_priorities = TRUE;

if (state->tls_require_ciphers && *state->tls_require_ciphers)
  {
  if (!expand_check_tlsvar(tls_require_ciphers, errstr))
    return DEFER;
  if (state->exp_tls_require_ciphers && *state->exp_tls_require_ciphers)
    {
    DEBUG(D_tls) debug_printf("GnuTLS session cipher/priority \"%s\"\n",
        state->exp_tls_require_ciphers);

    rc = gnutls_priority_init(&state->priority_cache,
        CS state->exp_tls_require_ciphers, &errpos);
    want_default_priorities = FALSE;
    p = state->exp_tls_require_ciphers;
    }
  }
if (want_default_priorities)
  {
  DEBUG(D_tls)
    debug_printf("GnuTLS using default session cipher/priority \"%s\"\n",
        exim_default_gnutls_priority);
  rc = gnutls_priority_init(&state->priority_cache,
      exim_default_gnutls_priority, &errpos);
  p = US exim_default_gnutls_priority;
  }

exim_gnutls_err_check(rc, string_sprintf(
      "gnutls_priority_init(%s) failed at offset %ld, \"%.6s..\"",
      p, errpos - CS p, errpos));

rc = gnutls_priority_set(state->session, state->priority_cache);
exim_gnutls_err_check(rc, US"gnutls_priority_set");

gnutls_db_set_cache_expiration(state->session, ssl_session_timeout);

/* Reduce security in favour of increased compatibility, if the admin
decides to make that trade-off. */
if (gnutls_compat_mode)
  {
#if LIBGNUTLS_VERSION_NUMBER >= 0x020104
  DEBUG(D_tls) debug_printf("lowering GnuTLS security, compatibility mode\n");
  gnutls_session_enable_compatibility_mode(state->session);
#else
  DEBUG(D_tls) debug_printf("Unable to set gnutls_compat_mode - GnuTLS version too old\n");
#endif
  }

*caller_state = state;
return OK;
}



/*************************************************
*            Extract peer information            *
*************************************************/

/* Called from both server and client code.
Only this is allowed to set state->peerdn and state->have_set_peerdn
and we use that to detect double-calls.

NOTE: the state blocks last while the TLS connection is up, which is fine
for logging in the server side, but for the client side, we log after teardown
in src/deliver.c.  While the session is up, we can twist about states and
repoint tls_* globals, but those variables used for logging or other variable
expansion that happens _after_ delivery need to have a longer life-time.

So for those, we get the data from POOL_PERM; the re-invoke guard keeps us from
doing this more than once per generation of a state context.  We set them in
the state context, and repoint tls_* to them.  After the state goes away, the
tls_* copies of the pointers remain valid and client delivery logging is happy.

tls_certificate_verified is a BOOL, so the tls_peerdn and tls_cipher issues
don't apply.

Arguments:
  state           exim_gnutls_state_st *
  errstr	  pointer to error string

Returns:          OK/DEFER/FAIL
*/

static int
peer_status(exim_gnutls_state_st *state, uschar ** errstr)
{
uschar cipherbuf[256];
const gnutls_datum_t *cert_list;
int old_pool, rc;
unsigned int cert_list_size = 0;
gnutls_protocol_t protocol;
gnutls_cipher_algorithm_t cipher;
gnutls_kx_algorithm_t kx;
gnutls_mac_algorithm_t mac;
gnutls_certificate_type_t ct;
gnutls_x509_crt_t crt;
uschar *p, *dn_buf;
size_t sz;

if (state->have_set_peerdn)
  return OK;
state->have_set_peerdn = TRUE;

state->peerdn = NULL;

/* tls_cipher */
cipher = gnutls_cipher_get(state->session);
protocol = gnutls_protocol_get_version(state->session);
mac = gnutls_mac_get(state->session);
kx = gnutls_kx_get(state->session);

string_format(cipherbuf, sizeof(cipherbuf),
    "%s:%s:%d",
    gnutls_protocol_get_name(protocol),
    gnutls_cipher_suite_get_name(kx, cipher, mac),
    (int) gnutls_cipher_get_key_size(cipher) * 8);

/* I don't see a way that spaces could occur, in the current GnuTLS
code base, but it was a concern in the old code and perhaps older GnuTLS
releases did return "TLS 1.0"; play it safe, just in case. */
for (p = cipherbuf; *p != '\0'; ++p)
  if (isspace(*p))
    *p = '-';
old_pool = store_pool;
store_pool = POOL_PERM;
state->ciphersuite = string_copy(cipherbuf);
store_pool = old_pool;
state->tlsp->cipher = state->ciphersuite;

/* tls_peerdn */
cert_list = gnutls_certificate_get_peers(state->session, &cert_list_size);

if (cert_list == NULL || cert_list_size == 0)
  {
  DEBUG(D_tls) debug_printf("TLS: no certificate from peer (%p & %d)\n",
      cert_list, cert_list_size);
  if (state->verify_requirement >= VERIFY_REQUIRED)
    return tls_error(US"certificate verification failed",
        US"no certificate received from peer", state->host, errstr);
  return OK;
  }

ct = gnutls_certificate_type_get(state->session);
if (ct != GNUTLS_CRT_X509)
  {
  const uschar *ctn = US gnutls_certificate_type_get_name(ct);
  DEBUG(D_tls)
    debug_printf("TLS: peer cert not X.509 but instead \"%s\"\n", ctn);
  if (state->verify_requirement >= VERIFY_REQUIRED)
    return tls_error(US"certificate verification not possible, unhandled type",
        ctn, state->host, errstr);
  return OK;
  }

#define exim_gnutls_peer_err(Label) \
  do { \
    if (rc != GNUTLS_E_SUCCESS) \
      { \
      DEBUG(D_tls) debug_printf("TLS: peer cert problem: %s: %s\n", \
	(Label), gnutls_strerror(rc)); \
      if (state->verify_requirement >= VERIFY_REQUIRED) \
	return tls_error((Label), US gnutls_strerror(rc), state->host, errstr); \
      return OK; \
      } \
    } while (0)

rc = import_cert(&cert_list[0], &crt);
exim_gnutls_peer_err(US"cert 0");

state->tlsp->peercert = state->peercert = crt;

sz = 0;
rc = gnutls_x509_crt_get_dn(crt, NULL, &sz);
if (rc != GNUTLS_E_SHORT_MEMORY_BUFFER)
  {
  exim_gnutls_peer_err(US"getting size for cert DN failed");
  return FAIL; /* should not happen */
  }
dn_buf = store_get_perm(sz);
rc = gnutls_x509_crt_get_dn(crt, CS dn_buf, &sz);
exim_gnutls_peer_err(US"failed to extract certificate DN [gnutls_x509_crt_get_dn(cert 0)]");

state->peerdn = dn_buf;

return OK;
#undef exim_gnutls_peer_err
}




/*************************************************
*            Verify peer certificate             *
*************************************************/

/* Called from both server and client code.
*Should* be using a callback registered with
gnutls_certificate_set_verify_function() to fail the handshake if we dislike
the peer information, but that's too new for some OSes.

Arguments:
  state		exim_gnutls_state_st *
  errstr	where to put an error message

Returns:
  FALSE     if the session should be rejected
  TRUE      if the cert is okay or we just don't care
*/

static BOOL
verify_certificate(exim_gnutls_state_st * state, uschar ** errstr)
{
int rc;
uint verify;

if (state->verify_requirement == VERIFY_NONE)
  return TRUE;

DEBUG(D_tls) debug_printf("TLS: checking peer certificate\n");
*errstr = NULL;

if ((rc = peer_status(state, errstr)) != OK)
  {
  verify = GNUTLS_CERT_INVALID;
  *errstr = US"certificate not supplied";
  }
else

  {
#ifdef SUPPORT_DANE
  if (state->verify_requirement == VERIFY_DANE && state->host)
    {
    /* Using dane_verify_session_crt() would be easy, as it does it all for us
    including talking to a DNS resolver.  But we want to do that bit ourselves
    as the testsuite intercepts and fakes its own DNS environment. */

    dane_state_t s;
    dane_query_t r;
    uint lsize;
    const gnutls_datum_t * certlist =
      gnutls_certificate_get_peers(state->session, &lsize);
    int usage = tls_out.tlsa_usage;

# ifdef GNUTLS_BROKEN_DANE_VALIDATION
    /* Split the TLSA records into two sets, TA and EE selectors.  Run the
    dane-verification separately so that we know which selector verified;
    then we know whether to do name-verification (needed for TA but not EE). */

    if (usage == ((1<<DANESSL_USAGE_DANE_TA) | (1<<DANESSL_USAGE_DANE_EE)))
      {						/* a mixed-usage bundle */
      int i, j, nrec;
      const char ** dd;
      int * ddl;

      for(nrec = 0; state->dane_data_len[nrec]; ) nrec++;
      nrec++;

      dd = store_get(nrec * sizeof(uschar *));
      ddl = store_get(nrec * sizeof(int));
      nrec--;

      if ((rc = dane_state_init(&s, 0)))
	goto tlsa_prob;

      for (usage = DANESSL_USAGE_DANE_EE;
	   usage >= DANESSL_USAGE_DANE_TA; usage--)
	{				/* take records with this usage */
	for (j = i = 0; i < nrec; i++)
	  if (state->dane_data[i][0] == usage)
	    {
	    dd[j] = state->dane_data[i];
	    ddl[j++] = state->dane_data_len[i];
	    }
	if (j)
	  {
	  dd[j] = NULL;
	  ddl[j] = 0;

	  if ((rc = dane_raw_tlsa(s, &r, (char * const *)dd, ddl, 1, 0)))
	    goto tlsa_prob;

	  if ((rc = dane_verify_crt_raw(s, certlist, lsize,
			    gnutls_certificate_type_get(state->session),
			    r, 0,
			    usage == DANESSL_USAGE_DANE_EE
			    ? DANE_VFLAG_ONLY_CHECK_EE_USAGE : 0,
			    &verify)))
	    {
	    DEBUG(D_tls)
	      debug_printf("TLSA record problem: %s\n", dane_strerror(rc));
	    }
	  else if (verify == 0)	/* verification passed */
	    {
	    usage = 1 << usage;
	    break;
	    }
	  }
	}

	if (rc) goto tlsa_prob;
      }
    else
# endif
      {
      if (  (rc = dane_state_init(&s, 0))
	 || (rc = dane_raw_tlsa(s, &r, state->dane_data, state->dane_data_len,
			1, 0))
	 || (rc = dane_verify_crt_raw(s, certlist, lsize,
			gnutls_certificate_type_get(state->session),
			r, 0,
# ifdef GNUTLS_BROKEN_DANE_VALIDATION
			usage == (1 << DANESSL_USAGE_DANE_EE)
			? DANE_VFLAG_ONLY_CHECK_EE_USAGE : 0,
# else
			0,
# endif
			&verify))
	 )
	goto tlsa_prob;
      }

    if (verify != 0)		/* verification failed */
      {
      gnutls_datum_t str;
      (void) dane_verification_status_print(verify, &str, 0);
      *errstr = US str.data;	/* don't bother to free */
      goto badcert;
      }

# ifdef GNUTLS_BROKEN_DANE_VALIDATION
    /* If a TA-mode TLSA record was used for verification we must additionally
    verify the cert name (but not the CA chain).  For EE-mode, skip it. */

    if (usage & (1 << DANESSL_USAGE_DANE_EE))
# endif
      {
      state->peer_dane_verified = state->peer_cert_verified = TRUE;
      goto goodcert;
      }
# ifdef GNUTLS_BROKEN_DANE_VALIDATION
    /* Assume that the name on the A-record is the one that should be matching
    the cert.  An alternate view is that the domain part of the email address
    is also permissible. */

    if (gnutls_x509_crt_check_hostname(state->tlsp->peercert,
	  CS state->host->name))
      {
      state->peer_dane_verified = state->peer_cert_verified = TRUE;
      goto goodcert;
      }
# endif
    }
#endif	/*SUPPORT_DANE*/

  rc = gnutls_certificate_verify_peers2(state->session, &verify);
  }

/* Handle the result of verification. INVALID is set if any others are. */

if (rc < 0 || verify & (GNUTLS_CERT_INVALID|GNUTLS_CERT_REVOKED))
  {
  state->peer_cert_verified = FALSE;
  if (!*errstr)
    {
#ifdef GNUTLS_CERT_VFY_STATUS_PRINT
    DEBUG(D_tls)
      {
      gnutls_datum_t txt;

      if (gnutls_certificate_verification_status_print(verify,
	    gnutls_certificate_type_get(state->session), &txt, 0)
	  == GNUTLS_E_SUCCESS)
	{
	debug_printf("%s\n", txt.data);
	gnutls_free(txt.data);
	}
      }
#endif
    *errstr = verify & GNUTLS_CERT_REVOKED
      ? US"certificate revoked" : US"certificate invalid";
    }

  DEBUG(D_tls)
    debug_printf("TLS certificate verification failed (%s): peerdn=\"%s\"\n",
        *errstr, state->peerdn ? state->peerdn : US"<unset>");

  if (state->verify_requirement >= VERIFY_REQUIRED)
    goto badcert;
  DEBUG(D_tls)
    debug_printf("TLS verify failure overridden (host in tls_try_verify_hosts)\n");
  }

else
  {
  /* Client side, check the server's certificate name versus the name on the
  A-record for the connection we made.  What to do for server side - what name
  to use for client?  We document that there is no such checking for server
  side. */

  if (  state->exp_tls_verify_cert_hostnames
     && !gnutls_x509_crt_check_hostname(state->tlsp->peercert,
		CS state->exp_tls_verify_cert_hostnames)
     )
    {
    DEBUG(D_tls)
      debug_printf("TLS certificate verification failed: cert name mismatch\n");
    if (state->verify_requirement >= VERIFY_REQUIRED)
      goto badcert;
    return TRUE;
    }

  state->peer_cert_verified = TRUE;
  DEBUG(D_tls) debug_printf("TLS certificate verified: peerdn=\"%s\"\n",
      state->peerdn ? state->peerdn : US"<unset>");
  }

goodcert:
  state->tlsp->peerdn = state->peerdn;
  return TRUE;

#ifdef SUPPORT_DANE
tlsa_prob:
  *errstr = string_sprintf("TLSA record problem: %s",
    rc == DANE_E_REQUESTED_DATA_NOT_AVAILABLE ? "none usable" : dane_strerror(rc));
#endif

badcert:
  gnutls_alert_send(state->session, GNUTLS_AL_FATAL, GNUTLS_A_BAD_CERTIFICATE);
  return FALSE;
}




/* ------------------------------------------------------------------------ */
/* Callbacks */

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


/* Called after client hello, should handle SNI work.
This will always set tls_sni (state->received_sni) if available,
and may trigger presenting different certificates,
if state->trigger_sni_changes is TRUE.

Should be registered with
  gnutls_handshake_set_post_client_hello_function()

"This callback must return 0 on success or a gnutls error code to terminate the
handshake.".

For inability to get SNI information, we return 0.
We only return non-zero if re-setup failed.
Only used for server-side TLS.
*/

static int
exim_sni_handling_cb(gnutls_session_t session)
{
char sni_name[MAX_HOST_LEN];
size_t data_len = MAX_HOST_LEN;
exim_gnutls_state_st *state = &state_server;
unsigned int sni_type;
int rc, old_pool;
uschar * dummy_errstr;

rc = gnutls_server_name_get(session, sni_name, &data_len, &sni_type, 0);
if (rc != GNUTLS_E_SUCCESS)
  {
  DEBUG(D_tls) {
    if (rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
      debug_printf("TLS: no SNI presented in handshake.\n");
    else
      debug_printf("TLS failure: gnutls_server_name_get(): %s [%d]\n",
        gnutls_strerror(rc), rc);
    }
  return 0;
  }

if (sni_type != GNUTLS_NAME_DNS)
  {
  DEBUG(D_tls) debug_printf("TLS: ignoring SNI of unhandled type %u\n", sni_type);
  return 0;
  }

/* We now have a UTF-8 string in sni_name */
old_pool = store_pool;
store_pool = POOL_PERM;
state->received_sni = string_copyn(US sni_name, data_len);
store_pool = old_pool;

/* We set this one now so that variable expansions below will work */
state->tlsp->sni = state->received_sni;

DEBUG(D_tls) debug_printf("Received TLS SNI \"%s\"%s\n", sni_name,
    state->trigger_sni_changes ? "" : " (unused for certificate selection)");

if (!state->trigger_sni_changes)
  return 0;

if ((rc = tls_expand_session_files(state, &dummy_errstr)) != OK)
  {
  /* If the setup of certs/etc failed before handshake, TLS would not have
  been offered.  The best we can do now is abort. */
  return GNUTLS_E_APPLICATION_ERROR_MIN;
  }

rc = tls_set_remaining_x509(state, &dummy_errstr);
if (rc != OK) return GNUTLS_E_APPLICATION_ERROR_MIN;

return 0;
}



#ifndef DISABLE_OCSP

static int
server_ocsp_stapling_cb(gnutls_session_t session, void * ptr,
  gnutls_datum_t * ocsp_response)
{
int ret;
DEBUG(D_tls) debug_printf("OCSP stapling callback: %s\n", US ptr);

if ((ret = gnutls_load_file(ptr, ocsp_response)) < 0)
  {
  DEBUG(D_tls) debug_printf("Failed to load ocsp stapling file %s\n",
			      CS ptr);
  tls_in.ocsp = OCSP_NOT_RESP;
  return GNUTLS_E_NO_CERTIFICATE_STATUS;
  }

tls_in.ocsp = OCSP_VFY_NOT_TRIED;
return 0;
}

#endif


#ifndef DISABLE_EVENT
/*
We use this callback to get observability and detail-level control
for an exim TLS connection (either direction), raising a tls:cert event
for each cert in the chain presented by the peer.  Any event
can deny verification.

Return 0 for the handshake to continue or non-zero to terminate.
*/

static int
verify_cb(gnutls_session_t session)
{
const gnutls_datum_t * cert_list;
unsigned int cert_list_size = 0;
gnutls_x509_crt_t crt;
int rc;
uschar * yield;
exim_gnutls_state_st * state = gnutls_session_get_ptr(session);

if ((cert_list = gnutls_certificate_get_peers(session, &cert_list_size)))
  while (cert_list_size--)
  {
  if ((rc = import_cert(&cert_list[cert_list_size], &crt)) != GNUTLS_E_SUCCESS)
    {
    DEBUG(D_tls) debug_printf("TLS: peer cert problem: depth %d: %s\n",
      cert_list_size, gnutls_strerror(rc));
    break;
    }

  state->tlsp->peercert = crt;
  if ((yield = event_raise(state->event_action,
	      US"tls:cert", string_sprintf("%d", cert_list_size))))
    {
    log_write(0, LOG_MAIN,
	      "SSL verify denied by event-action: depth=%d: %s",
	      cert_list_size, yield);
    return 1;                     /* reject */
    }
  state->tlsp->peercert = NULL;
  }

return 0;
}

#endif



/* ------------------------------------------------------------------------ */
/* Exported functions */




/*************************************************
*       Start a TLS session in a server          *
*************************************************/

/* This is called when Exim is running as a server, after having received
the STARTTLS command. It must respond to that command, and then negotiate
a TLS session.

Arguments:
  require_ciphers  list of allowed ciphers or NULL
  errstr	   pointer to error string

Returns:           OK on success
                   DEFER for errors before the start of the negotiation
                   FAIL for errors during the negotiation; the server can't
                     continue running.
*/

int
tls_server_start(const uschar * require_ciphers, uschar ** errstr)
{
int rc;
exim_gnutls_state_st * state = NULL;

/* Check for previous activation */
if (tls_in.active.sock >= 0)
  {
  tls_error(US"STARTTLS received after TLS started", US "", NULL, errstr);
  smtp_printf("554 Already in TLS\r\n", FALSE);
  return FAIL;
  }

/* Initialize the library. If it fails, it will already have logged the error
and sent an SMTP response. */

DEBUG(D_tls) debug_printf("initialising GnuTLS as a server\n");

if ((rc = tls_init(NULL, tls_certificate, tls_privatekey,
    NULL, tls_verify_certificates, tls_crl,
    require_ciphers, &state, &tls_in, errstr)) != OK) return rc;

/* If this is a host for which certificate verification is mandatory or
optional, set up appropriately. */

if (verify_check_host(&tls_verify_hosts) == OK)
  {
  DEBUG(D_tls)
    debug_printf("TLS: a client certificate will be required.\n");
  state->verify_requirement = VERIFY_REQUIRED;
  gnutls_certificate_server_set_request(state->session, GNUTLS_CERT_REQUIRE);
  }
else if (verify_check_host(&tls_try_verify_hosts) == OK)
  {
  DEBUG(D_tls)
    debug_printf("TLS: a client certificate will be requested but not required.\n");
  state->verify_requirement = VERIFY_OPTIONAL;
  gnutls_certificate_server_set_request(state->session, GNUTLS_CERT_REQUEST);
  }
else
  {
  DEBUG(D_tls)
    debug_printf("TLS: a client certificate will not be requested.\n");
  state->verify_requirement = VERIFY_NONE;
  gnutls_certificate_server_set_request(state->session, GNUTLS_CERT_IGNORE);
  }

#ifndef DISABLE_EVENT
if (event_action)
  {
  state->event_action = event_action;
  gnutls_session_set_ptr(state->session, state);
  gnutls_certificate_set_verify_function(state->x509_cred, verify_cb);
  }
#endif

/* Register SNI handling; always, even if not in tls_certificate, so that the
expansion variable $tls_sni is always available. */

gnutls_handshake_set_post_client_hello_function(state->session,
    exim_sni_handling_cb);

/* Set context and tell client to go ahead, except in the case of TLS startup
on connection, where outputting anything now upsets the clients and tends to
make them disconnect. We need to have an explicit fflush() here, to force out
the response. Other smtp_printf() calls do not need it, because in non-TLS
mode, the fflush() happens when smtp_getc() is called. */

if (!state->tlsp->on_connect)
  {
  smtp_printf("220 TLS go ahead\r\n", FALSE);
  fflush(smtp_out);
  }

/* Now negotiate the TLS session. We put our own timer on it, since it seems
that the GnuTLS library doesn't.
From 3.1.0 there is gnutls_handshake_set_timeout() - but it requires you
to set (and clear down afterwards) up a pull-timeout callback function that does
a select, so we're no better off unless avoiding signals becomes an issue. */

gnutls_transport_set_ptr2(state->session,
    (gnutls_transport_ptr_t)(long) fileno(smtp_in),
    (gnutls_transport_ptr_t)(long) fileno(smtp_out));
state->fd_in = fileno(smtp_in);
state->fd_out = fileno(smtp_out);

sigalrm_seen = FALSE;
if (smtp_receive_timeout > 0) ALARM(smtp_receive_timeout);
do
  rc = gnutls_handshake(state->session);
while (rc == GNUTLS_E_AGAIN ||  rc == GNUTLS_E_INTERRUPTED && !sigalrm_seen);
ALARM_CLR(0);

if (rc != GNUTLS_E_SUCCESS)
  {
  /* It seems that, except in the case of a timeout, we have to close the
  connection right here; otherwise if the other end is running OpenSSL it hangs
  until the server times out. */

  if (sigalrm_seen)
    {
    tls_error(US"gnutls_handshake", US"timed out", NULL, errstr);
    gnutls_db_remove_session(state->session);
    }
  else
    {
    tls_error(US"gnutls_handshake", US gnutls_strerror(rc), NULL, errstr);
    (void) gnutls_alert_send_appropriate(state->session, rc);
    gnutls_deinit(state->session);
    gnutls_certificate_free_credentials(state->x509_cred);
    millisleep(500);
    shutdown(state->fd_out, SHUT_WR);
    for (rc = 1024; fgetc(smtp_in) != EOF && rc > 0; ) rc--;	/* drain skt */
    (void)fclose(smtp_out);
    (void)fclose(smtp_in);
    smtp_out = smtp_in = NULL;
    }

  return FAIL;
  }

DEBUG(D_tls) debug_printf("gnutls_handshake was successful\n");

/* Verify after the fact */

if (!verify_certificate(state, errstr))
  {
  if (state->verify_requirement != VERIFY_OPTIONAL)
    {
    (void) tls_error(US"certificate verification failed", *errstr, NULL, errstr);
    return FAIL;
    }
  DEBUG(D_tls)
    debug_printf("TLS: continuing on only because verification was optional, after: %s\n",
	*errstr);
  }

/* Figure out peer DN, and if authenticated, etc. */

if ((rc = peer_status(state, NULL)) != OK) return rc;

/* Sets various Exim expansion variables; always safe within server */

extract_exim_vars_from_tls_state(state);

/* TLS has been set up. Adjust the input functions to read via TLS,
and initialize appropriately. */

state->xfer_buffer = store_malloc(ssl_xfer_buffer_size);

receive_getc = tls_getc;
receive_getbuf = tls_getbuf;
receive_get_cache = tls_get_cache;
receive_ungetc = tls_ungetc;
receive_feof = tls_feof;
receive_ferror = tls_ferror;
receive_smtp_buffered = tls_smtp_buffered;

return OK;
}




static void
tls_client_setup_hostname_checks(host_item * host, exim_gnutls_state_st * state,
  smtp_transport_options_block * ob)
{
if (verify_check_given_host(CUSS &ob->tls_verify_cert_hostnames, host) == OK)
  {
  state->exp_tls_verify_cert_hostnames =
#ifdef SUPPORT_I18N
    string_domain_utf8_to_alabel(host->name, NULL);
#else
    host->name;
#endif
  DEBUG(D_tls)
    debug_printf("TLS: server cert verification includes hostname: \"%s\".\n",
		    state->exp_tls_verify_cert_hostnames);
  }
}




#ifdef SUPPORT_DANE
/* Given our list of RRs from the TLSA lookup, build a lookup block in
GnuTLS-DANE's preferred format.  Hang it on the state str for later
use in DANE verification.

We point at the dnsa data not copy it, so it must remain valid until
after verification is done.*/

static BOOL
dane_tlsa_load(exim_gnutls_state_st * state, dns_answer * dnsa)
{
dns_record * rr;
dns_scan dnss;
int i;
const char **	dane_data;
int *		dane_data_len;

for (rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS), i = 1;
     rr;
     rr = dns_next_rr(dnsa, &dnss, RESET_NEXT)
    ) if (rr->type == T_TLSA) i++;

dane_data = store_get(i * sizeof(uschar *));
dane_data_len = store_get(i * sizeof(int));

for (rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS), i = 0;
     rr;
     rr = dns_next_rr(dnsa, &dnss, RESET_NEXT)
    ) if (rr->type == T_TLSA && rr->size > 3)
  {
  const uschar * p = rr->data;
  uint8_t usage = p[0], sel = p[1], type = p[2];

  DEBUG(D_tls)
    debug_printf("TLSA: %d %d %d size %d\n", usage, sel, type, rr->size);

  if (  (usage != DANESSL_USAGE_DANE_TA && usage != DANESSL_USAGE_DANE_EE)
     || (sel != 0 && sel != 1)
     )
    continue;
  switch(type)
    {
    case 0:	/* Full: cannot check at present */
		break;
    case 1:	if (rr->size != 3 + 256/8) continue;	/* sha2-256 */
		break;
    case 2:	if (rr->size != 3 + 512/8) continue;	/* sha2-512 */
		break;
    default:	continue;
    }

  tls_out.tlsa_usage |= 1<<usage;
  dane_data[i] = CS p;
  dane_data_len[i++] = rr->size;
  }

if (!i) return FALSE;

dane_data[i] = NULL;
dane_data_len[i] = 0;

state->dane_data = (char * const *)dane_data;
state->dane_data_len = dane_data_len;
return TRUE;
}
#endif



/*************************************************
*    Start a TLS session in a client             *
*************************************************/

/* Called from the smtp transport after STARTTLS has been accepted.

Arguments:
  fd                the fd of the connection
  host              connected host (for messages and option-tests)
  addr              the first address (not used)
  tb                transport (always smtp)
  tlsa_dnsa	    non-NULL, either request or require dane for this host, and
		    a TLSA record found.  Therefore, dane verify required.
		    Which implies cert must be requested and supplied, dane
		    verify must pass, and cert verify irrelevant (incl.
		    hostnames), and (caller handled) require_tls
  tlsp		    record details of channel configuration
  errstr	    error string pointer

Returns:            Pointer to TLS session context, or NULL on error
*/

void *
tls_client_start(int fd, host_item *host,
    address_item *addr ARG_UNUSED,
    transport_instance * tb,
#ifdef SUPPORT_DANE
    dns_answer * tlsa_dnsa,
#endif
    tls_support * tlsp, uschar ** errstr)
{
smtp_transport_options_block *ob = tb
  ? (smtp_transport_options_block *)tb->options_block
  : &smtp_transport_option_defaults;
int rc;
exim_gnutls_state_st * state = NULL;
uschar *cipher_list = NULL;

#ifndef DISABLE_OCSP
BOOL require_ocsp =
  verify_check_given_host(CUSS &ob->hosts_require_ocsp, host) == OK;
BOOL request_ocsp = require_ocsp ? TRUE
  : verify_check_given_host(CUSS &ob->hosts_request_ocsp, host) == OK;
#endif

DEBUG(D_tls) debug_printf("initialising GnuTLS as a client on fd %d\n", fd);

#ifdef SUPPORT_DANE
if (tlsa_dnsa && ob->dane_require_tls_ciphers)
  {
  /* not using expand_check_tlsvar because not yet in state */
  if (!expand_check(ob->dane_require_tls_ciphers, US"dane_require_tls_ciphers",
      &cipher_list, errstr))
    return NULL;
  cipher_list = cipher_list && *cipher_list
    ? ob->dane_require_tls_ciphers : ob->tls_require_ciphers;
  }
#endif

if (!cipher_list)
  cipher_list = ob->tls_require_ciphers;

if (tls_init(host, ob->tls_certificate, ob->tls_privatekey,
    ob->tls_sni, ob->tls_verify_certificates, ob->tls_crl,
    cipher_list, &state, tlsp, errstr) != OK)
  return NULL;

  {
  int dh_min_bits = ob->tls_dh_min_bits;
  if (dh_min_bits < EXIM_CLIENT_DH_MIN_MIN_BITS)
    {
    DEBUG(D_tls)
      debug_printf("WARNING: tls_dh_min_bits far too low,"
		    " clamping %d up to %d\n",
	  dh_min_bits, EXIM_CLIENT_DH_MIN_MIN_BITS);
    dh_min_bits = EXIM_CLIENT_DH_MIN_MIN_BITS;
    }

  DEBUG(D_tls) debug_printf("Setting D-H prime minimum"
		    " acceptable bits to %d\n",
      dh_min_bits);
  gnutls_dh_set_prime_bits(state->session, dh_min_bits);
  }

/* Stick to the old behaviour for compatibility if tls_verify_certificates is
set but both tls_verify_hosts and tls_try_verify_hosts are unset. Check only
the specified host patterns if one of them is defined */

#ifdef SUPPORT_DANE
if (tlsa_dnsa && dane_tlsa_load(state, tlsa_dnsa))
  {
  DEBUG(D_tls)
    debug_printf("TLS: server certificate DANE required.\n");
  state->verify_requirement = VERIFY_DANE;
  gnutls_certificate_server_set_request(state->session, GNUTLS_CERT_REQUIRE);
  }
else
#endif
    if (  (  state->exp_tls_verify_certificates
	  && !ob->tls_verify_hosts
	  && (!ob->tls_try_verify_hosts || !*ob->tls_try_verify_hosts)
	  )
	|| verify_check_given_host(CUSS &ob->tls_verify_hosts, host) == OK
       )
  {
  tls_client_setup_hostname_checks(host, state, ob);
  DEBUG(D_tls)
    debug_printf("TLS: server certificate verification required.\n");
  state->verify_requirement = VERIFY_REQUIRED;
  gnutls_certificate_server_set_request(state->session, GNUTLS_CERT_REQUIRE);
  }
else if (verify_check_given_host(CUSS &ob->tls_try_verify_hosts, host) == OK)
  {
  tls_client_setup_hostname_checks(host, state, ob);
  DEBUG(D_tls)
    debug_printf("TLS: server certificate verification optional.\n");
  state->verify_requirement = VERIFY_OPTIONAL;
  gnutls_certificate_server_set_request(state->session, GNUTLS_CERT_REQUEST);
  }
else
  {
  DEBUG(D_tls)
    debug_printf("TLS: server certificate verification not required.\n");
  state->verify_requirement = VERIFY_NONE;
  gnutls_certificate_server_set_request(state->session, GNUTLS_CERT_IGNORE);
  }

#ifndef DISABLE_OCSP
			/* supported since GnuTLS 3.1.3 */
if (request_ocsp)
  {
  DEBUG(D_tls) debug_printf("TLS: will request OCSP stapling\n");
  if ((rc = gnutls_ocsp_status_request_enable_client(state->session,
		    NULL, 0, NULL)) != OK)
    {
    tls_error(US"cert-status-req", US gnutls_strerror(rc), state->host, errstr);
    return NULL;
    }
  tlsp->ocsp = OCSP_NOT_RESP;
  }
#endif

#ifndef DISABLE_EVENT
if (tb && tb->event_action)
  {
  state->event_action = tb->event_action;
  gnutls_session_set_ptr(state->session, state);
  gnutls_certificate_set_verify_function(state->x509_cred, verify_cb);
  }
#endif

gnutls_transport_set_ptr(state->session, (gnutls_transport_ptr_t)(long) fd);
state->fd_in = fd;
state->fd_out = fd;

DEBUG(D_tls) debug_printf("about to gnutls_handshake\n");
/* There doesn't seem to be a built-in timeout on connection. */

sigalrm_seen = FALSE;
ALARM(ob->command_timeout);
do
  rc = gnutls_handshake(state->session);
while (rc == GNUTLS_E_AGAIN || rc == GNUTLS_E_INTERRUPTED && !sigalrm_seen);
ALARM_CLR(0);

if (rc != GNUTLS_E_SUCCESS)
  {
  if (sigalrm_seen)
    {
    gnutls_alert_send(state->session, GNUTLS_AL_FATAL, GNUTLS_A_USER_CANCELED);
    tls_error(US"gnutls_handshake", US"timed out", state->host, errstr);
    }
  else
    tls_error(US"gnutls_handshake", US gnutls_strerror(rc), state->host, errstr);
  return NULL;
  }

DEBUG(D_tls) debug_printf("gnutls_handshake was successful\n");

/* Verify late */

if (!verify_certificate(state, errstr))
  {
  tls_error(US"certificate verification failed", *errstr, state->host, errstr);
  return NULL;
  }

#ifndef DISABLE_OCSP
if (require_ocsp)
  {
  DEBUG(D_tls)
    {
    gnutls_datum_t stapling;
    gnutls_ocsp_resp_t resp;
    gnutls_datum_t printed;
    if (  (rc= gnutls_ocsp_status_request_get(state->session, &stapling)) == 0
       && (rc= gnutls_ocsp_resp_init(&resp)) == 0
       && (rc= gnutls_ocsp_resp_import(resp, &stapling)) == 0
       && (rc= gnutls_ocsp_resp_print(resp, GNUTLS_OCSP_PRINT_FULL, &printed)) == 0
       )
      {
      debug_printf("%.4096s", printed.data);
      gnutls_free(printed.data);
      }
    else
      (void) tls_error(US"ocsp decode", US gnutls_strerror(rc), state->host, errstr);
    }

  if (gnutls_ocsp_status_request_is_checked(state->session, 0) == 0)
    {
    tlsp->ocsp = OCSP_FAILED;
    tls_error(US"certificate status check failed", NULL, state->host, errstr);
    return NULL;
    }
  DEBUG(D_tls) debug_printf("Passed OCSP checking\n");
  tlsp->ocsp = OCSP_VFIED;
  }
#endif

/* Figure out peer DN, and if authenticated, etc. */

if (peer_status(state, errstr) != OK)
  return NULL;

/* Sets various Exim expansion variables; may need to adjust for ACL callouts */

extract_exim_vars_from_tls_state(state);

return state;
}




/*************************************************
*         Close down a TLS session               *
*************************************************/

/* This is also called from within a delivery subprocess forked from the
daemon, to shut down the TLS library, without actually doing a shutdown (which
would tamper with the TLS session in the parent process).

Arguments:
  ct_ctx	client context pointer, or NULL for the one global server context
  shutdown	1 if TLS close-alert is to be sent,
		2 if also response to be waited for

Returns:     nothing
*/

void
tls_close(void * ct_ctx, int shutdown)
{
exim_gnutls_state_st * state = ct_ctx ? ct_ctx : &state_server;

if (!state->tlsp || state->tlsp->active.sock < 0) return;  /* TLS was not active */

if (shutdown)
  {
  DEBUG(D_tls) debug_printf("tls_close(): shutting down TLS%s\n",
    shutdown > 1 ? " (with response-wait)" : "");

  ALARM(2);
  gnutls_bye(state->session, shutdown > 1 ? GNUTLS_SHUT_RDWR : GNUTLS_SHUT_WR);
  ALARM_CLR(0);
  }

gnutls_deinit(state->session);
gnutls_certificate_free_credentials(state->x509_cred);


state->tlsp->active.sock = -1;
state->tlsp->active.tls_ctx = NULL;
if (state->xfer_buffer) store_free(state->xfer_buffer);
memcpy(state, &exim_gnutls_state_init, sizeof(exim_gnutls_state_init));
}




static BOOL
tls_refill(unsigned lim)
{
exim_gnutls_state_st * state = &state_server;
ssize_t inbytes;

DEBUG(D_tls) debug_printf("Calling gnutls_record_recv(%p, %p, %u)\n",
  state->session, state->xfer_buffer, ssl_xfer_buffer_size);

sigalrm_seen = FALSE;
if (smtp_receive_timeout > 0) ALARM(smtp_receive_timeout);

do
  inbytes = gnutls_record_recv(state->session, state->xfer_buffer,
    MIN(ssl_xfer_buffer_size, lim));
while (inbytes == GNUTLS_E_AGAIN);

if (smtp_receive_timeout > 0) ALARM_CLR(0);

if (had_command_timeout)		/* set by signal handler */
  smtp_command_timeout_exit();		/* does not return */
if (had_command_sigterm)
  smtp_command_sigterm_exit();
if (had_data_timeout)
  smtp_data_timeout_exit();
if (had_data_sigint)
  smtp_data_sigint_exit();

/* Timeouts do not get this far.  A zero-byte return appears to mean that the
TLS session has been closed down, not that the socket itself has been closed
down. Revert to non-TLS handling. */

if (sigalrm_seen)
  {
  DEBUG(D_tls) debug_printf("Got tls read timeout\n");
  state->xfer_error = TRUE;
  return FALSE;
  }

else if (inbytes == 0)
  {
  DEBUG(D_tls) debug_printf("Got TLS_EOF\n");

  receive_getc = smtp_getc;
  receive_getbuf = smtp_getbuf;
  receive_get_cache = smtp_get_cache;
  receive_ungetc = smtp_ungetc;
  receive_feof = smtp_feof;
  receive_ferror = smtp_ferror;
  receive_smtp_buffered = smtp_buffered;

  gnutls_deinit(state->session);
  gnutls_certificate_free_credentials(state->x509_cred);

  state->session = NULL;
  state->tlsp->active.sock = -1;
  state->tlsp->active.tls_ctx = NULL;
  state->tlsp->bits = 0;
  state->tlsp->certificate_verified = FALSE;
  tls_channelbinding_b64 = NULL;
  state->tlsp->cipher = NULL;
  state->tlsp->peercert = NULL;
  state->tlsp->peerdn = NULL;

  return FALSE;
  }

/* Handle genuine errors */

else if (inbytes < 0)
  {
  DEBUG(D_tls) debug_printf("%s: err from gnutls_record_recv(\n", __FUNCTION__);
  record_io_error(state, (int) inbytes, US"recv", NULL);
  state->xfer_error = TRUE;
  return FALSE;
  }
#ifndef DISABLE_DKIM
dkim_exim_verify_feed(state->xfer_buffer, inbytes);
#endif
state->xfer_buffer_hwm = (int) inbytes;
state->xfer_buffer_lwm = 0;
return TRUE;
}

/*************************************************
*            TLS version of getc                 *
*************************************************/

/* This gets the next byte from the TLS input buffer. If the buffer is empty,
it refills the buffer via the GnuTLS reading function.
Only used by the server-side TLS.

This feeds DKIM and should be used for all message-body reads.

Arguments:  lim		Maximum amount to read/buffer
Returns:    the next character or EOF
*/

int
tls_getc(unsigned lim)
{
exim_gnutls_state_st * state = &state_server;

if (state->xfer_buffer_lwm >= state->xfer_buffer_hwm)
  if (!tls_refill(lim))
    return state->xfer_error ? EOF : smtp_getc(lim);

/* Something in the buffer; return next uschar */

return state->xfer_buffer[state->xfer_buffer_lwm++];
}

uschar *
tls_getbuf(unsigned * len)
{
exim_gnutls_state_st * state = &state_server;
unsigned size;
uschar * buf;

if (state->xfer_buffer_lwm >= state->xfer_buffer_hwm)
  if (!tls_refill(*len))
    {
    if (!state->xfer_error) return smtp_getbuf(len);
    *len = 0;
    return NULL;
    }

if ((size = state->xfer_buffer_hwm - state->xfer_buffer_lwm) > *len)
  size = *len;
buf = &state->xfer_buffer[state->xfer_buffer_lwm];
state->xfer_buffer_lwm += size;
*len = size;
return buf;
}


void
tls_get_cache()
{
#ifndef DISABLE_DKIM
exim_gnutls_state_st * state = &state_server;
int n = state->xfer_buffer_hwm - state->xfer_buffer_lwm;
if (n > 0)
  dkim_exim_verify_feed(state->xfer_buffer+state->xfer_buffer_lwm, n);
#endif
}


BOOL
tls_could_read(void)
{
return state_server.xfer_buffer_lwm < state_server.xfer_buffer_hwm
 || gnutls_record_check_pending(state_server.session) > 0;
}




/*************************************************
*          Read bytes from TLS channel           *
*************************************************/

/* This does not feed DKIM, so if the caller uses this for reading message body,
then the caller must feed DKIM.

Arguments:
  ct_ctx    client context pointer, or NULL for the one global server context
  buff      buffer of data
  len       size of buffer

Returns:    the number of bytes read
            -1 after a failed read, including EOF
*/

int
tls_read(void * ct_ctx, uschar *buff, size_t len)
{
exim_gnutls_state_st * state = ct_ctx ? ct_ctx : &state_server;
ssize_t inbytes;

if (len > INT_MAX)
  len = INT_MAX;

if (state->xfer_buffer_lwm < state->xfer_buffer_hwm)
  DEBUG(D_tls)
    debug_printf("*** PROBABLY A BUG *** " \
        "tls_read() called with data in the tls_getc() buffer, %d ignored\n",
        state->xfer_buffer_hwm - state->xfer_buffer_lwm);

DEBUG(D_tls)
  debug_printf("Calling gnutls_record_recv(%p, %p, " SIZE_T_FMT ")\n",
      state->session, buff, len);

do
  inbytes = gnutls_record_recv(state->session, buff, len);
while (inbytes == GNUTLS_E_AGAIN);

if (inbytes > 0) return inbytes;
if (inbytes == 0)
  {
  DEBUG(D_tls) debug_printf("Got TLS_EOF\n");
  }
else
  {
  DEBUG(D_tls) debug_printf("%s: err from gnutls_record_recv(\n", __FUNCTION__);
  record_io_error(state, (int)inbytes, US"recv", NULL);
  }

return -1;
}




/*************************************************
*         Write bytes down TLS channel           *
*************************************************/

/*
Arguments:
  ct_ctx    client context pointer, or NULL for the one global server context
  buff      buffer of data
  len       number of bytes
  more	    more data expected soon

Returns:    the number of bytes after a successful write,
            -1 after a failed write
*/

int
tls_write(void * ct_ctx, const uschar * buff, size_t len, BOOL more)
{
ssize_t outbytes;
size_t left = len;
exim_gnutls_state_st * state = ct_ctx ? ct_ctx : &state_server;
#ifdef SUPPORT_CORK
static BOOL corked = FALSE;

if (more && !corked) gnutls_record_cork(state->session);
#endif

DEBUG(D_tls) debug_printf("%s(%p, " SIZE_T_FMT "%s)\n", __FUNCTION__,
  buff, left, more ? ", more" : "");

while (left > 0)
  {
  DEBUG(D_tls) debug_printf("gnutls_record_send(SSL, %p, " SIZE_T_FMT ")\n",
      buff, left);

  do
    outbytes = gnutls_record_send(state->session, buff, left);
  while (outbytes == GNUTLS_E_AGAIN);

  DEBUG(D_tls) debug_printf("outbytes=" SSIZE_T_FMT "\n", outbytes);
  if (outbytes < 0)
    {
    DEBUG(D_tls) debug_printf("%s: gnutls_record_send err\n", __FUNCTION__);
    record_io_error(state, outbytes, US"send", NULL);
    return -1;
    }
  if (outbytes == 0)
    {
    record_io_error(state, 0, US"send", US"TLS channel closed on write");
    return -1;
    }

  left -= outbytes;
  buff += outbytes;
  }

if (len > INT_MAX)
  {
  DEBUG(D_tls)
    debug_printf("Whoops!  Wrote more bytes (" SIZE_T_FMT ") than INT_MAX\n",
        len);
  len = INT_MAX;
  }

#ifdef SUPPORT_CORK
if (more != corked)
  {
  if (!more) (void) gnutls_record_uncork(state->session, 0);
  corked = more;
  }
#endif

return (int) len;
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

#ifdef HAVE_GNUTLS_RND
int
vaguely_random_number(int max)
{
unsigned int r;
int i, needed_len;
uschar *p;
uschar smallbuf[sizeof(r)];

if (max <= 1)
  return 0;

needed_len = sizeof(r);
/* Don't take 8 times more entropy than needed if int is 8 octets and we were
 * asked for a number less than 10. */
for (r = max, i = 0; r; ++i)
  r >>= 1;
i = (i + 7) / 8;
if (i < needed_len)
  needed_len = i;

i = gnutls_rnd(GNUTLS_RND_NONCE, smallbuf, needed_len);
if (i < 0)
  {
  DEBUG(D_all) debug_printf("gnutls_rnd() failed, using fallback.\n");
  return vaguely_random_number_fallback(max);
  }
r = 0;
for (p = smallbuf; needed_len; --needed_len, ++p)
  {
  r *= 256;
  r += *p;
  }

/* We don't particularly care about weighted results; if someone wants
 * smooth distribution and cares enough then they should submit a patch then. */
return r % max;
}
#else /* HAVE_GNUTLS_RND */
int
vaguely_random_number(int max)
{
  return vaguely_random_number_fallback(max);
}
#endif /* HAVE_GNUTLS_RND */




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
int rc;
uschar *expciphers = NULL;
gnutls_priority_t priority_cache;
const char *errpos;
uschar * dummy_errstr;

#define validate_check_rc(Label) do { \
  if (rc != GNUTLS_E_SUCCESS) { if (exim_gnutls_base_init_done) gnutls_global_deinit(); \
  return string_sprintf("%s failed: %s", (Label), gnutls_strerror(rc)); } } while (0)
#define return_deinit(Label) do { gnutls_global_deinit(); return (Label); } while (0)

if (exim_gnutls_base_init_done)
  log_write(0, LOG_MAIN|LOG_PANIC,
      "already initialised GnuTLS, Exim developer bug");

#ifdef HAVE_GNUTLS_PKCS11
if (!gnutls_allow_auto_pkcs11)
  {
  rc = gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL);
  validate_check_rc(US"gnutls_pkcs11_init");
  }
#endif
rc = gnutls_global_init();
validate_check_rc(US"gnutls_global_init()");
exim_gnutls_base_init_done = TRUE;

if (!(tls_require_ciphers && *tls_require_ciphers))
  return_deinit(NULL);

if (!expand_check(tls_require_ciphers, US"tls_require_ciphers", &expciphers,
		  &dummy_errstr))
  return_deinit(US"failed to expand tls_require_ciphers");

if (!(expciphers && *expciphers))
  return_deinit(NULL);

DEBUG(D_tls)
  debug_printf("tls_require_ciphers expands to \"%s\"\n", expciphers);

rc = gnutls_priority_init(&priority_cache, CS expciphers, &errpos);
validate_check_rc(string_sprintf(
      "gnutls_priority_init(%s) failed at offset %ld, \"%.8s..\"",
      expciphers, errpos - CS expciphers, errpos));

#undef return_deinit
#undef validate_check_rc
gnutls_global_deinit();

return NULL;
}




/*************************************************
*         Report the library versions.           *
*************************************************/

/* See a description in tls-openssl.c for an explanation of why this exists.

Arguments:   a FILE* to print the results to
Returns:     nothing
*/

void
tls_version_report(FILE *f)
{
fprintf(f, "Library version: GnuTLS: Compile: %s\n"
           "                         Runtime: %s\n",
           LIBGNUTLS_VERSION,
           gnutls_check_version(NULL));
}

/* vi: aw ai sw=2
*/
/* End of tls-gnu.c */
