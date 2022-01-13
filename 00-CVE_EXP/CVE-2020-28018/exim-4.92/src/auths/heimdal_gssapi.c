/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Copyright (c) Twitter Inc 2012
   Author: Phil Pennock <pdp@exim.org> */
/* Copyright (c) Phil Pennock 2012 */

/* Interface to Heimdal library for GSSAPI authentication. */

/* Naming and rationale

Sensibly, this integration would be deferred to a SASL library, but none
of them appear to offer keytab file selection interfaces in their APIs.  It
might be that this driver only requires minor modification to work with MIT
Kerberos.

Heimdal provides a number of interfaces for various forms of authentication.
As GS2 does not appear to provide keytab control interfaces either, we may
end up supporting that too.  It's possible that we could trivially expand to
support NTLM support via Heimdal, etc.  Rather than try to be too generic
immediately, this driver is directly only supporting GSSAPI.

Without rename, we could add an option for GS2 support in the future.
*/

/* Sources

* mailcheck-imap (Perl, client-side, written by me years ago)
* gsasl driver (GPL, server-side)
* heimdal sources and man-pages, plus http://www.h5l.org/manual/
* FreeBSD man-pages (very informative!)
* http://www.ggf.org/documents/GFD.24.pdf confirming GSS_KRB5_REGISTER_ACCEPTOR_IDENTITY_X
  semantics, that found by browsing Heimdal source to find how to set the keytab; however,
  after multiple attempts I failed to get that to work and instead switched to
  gsskrb5_register_acceptor_identity().
*/

#include "../exim.h"

#ifndef AUTH_HEIMDAL_GSSAPI
/* dummy function to satisfy compilers when we link in an "empty" file. */
static void dummy(int x);
static void dummy2(int x) { dummy(x-1); }
static void dummy(int x) { dummy2(x-1); }
#else

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

/* for the _init debugging */
#include <krb5.h>

#include "heimdal_gssapi.h"

/* Authenticator-specific options. */
optionlist auth_heimdal_gssapi_options[] = {
  { "server_hostname",      opt_stringptr,
      (void *)(offsetof(auth_heimdal_gssapi_options_block, server_hostname)) },
  { "server_keytab",        opt_stringptr,
      (void *)(offsetof(auth_heimdal_gssapi_options_block, server_keytab)) },
  { "server_service",       opt_stringptr,
      (void *)(offsetof(auth_heimdal_gssapi_options_block, server_service)) }
};

int auth_heimdal_gssapi_options_count =
  sizeof(auth_heimdal_gssapi_options)/sizeof(optionlist);

/* Defaults for the authenticator-specific options. */
auth_heimdal_gssapi_options_block auth_heimdal_gssapi_option_defaults = {
  US"$primary_hostname",    /* server_hostname */
  NULL,                     /* server_keytab */
  US"smtp",                 /* server_service */
};


#ifdef MACRO_PREDEF

/* Dummy values */
void auth_heimdal_gssapi_init(auth_instance *ablock) {}
int auth_heimdal_gssapi_server(auth_instance *ablock, uschar *data) {return 0;}
int auth_heimdal_gssapi_client(auth_instance *ablock, void * sx,
  int timeout, uschar *buffer, int buffsize) {return 0;}
void auth_heimdal_gssapi_version_report(FILE *f) {}

#else   /*!MACRO_PREDEF*/



/* "Globals" for managing the heimdal_gssapi interface. */

/* Utility functions */
static void
  exim_heimdal_error_debug(const char *, krb5_context, krb5_error_code);
static int
  exim_gssapi_error_defer(uschar *, OM_uint32, OM_uint32, const char *, ...)
    PRINTF_FUNCTION(4, 5);

#define EmptyBuf(buf) do { buf.value = NULL; buf.length = 0; } while (0)


/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */

/* Heimdal provides a GSSAPI extension method for setting the keytab;
in the init, we mostly just use raw krb5 methods so that we can report
the keytab contents, for -D+auth debugging. */

void
auth_heimdal_gssapi_init(auth_instance *ablock)
{
  krb5_context context;
  krb5_keytab keytab;
  krb5_kt_cursor cursor;
  krb5_keytab_entry entry;
  krb5_error_code krc;
  char *principal, *enctype_s;
  const char *k_keytab_typed_name = NULL;
  auth_heimdal_gssapi_options_block *ob =
    (auth_heimdal_gssapi_options_block *)(ablock->options_block);

  ablock->server = FALSE;
  ablock->client = FALSE;

  if (!ob->server_service || !*ob->server_service) {
    HDEBUG(D_auth) debug_printf("heimdal: missing server_service\n");
    return;
  }

  krc = krb5_init_context(&context);
  if (krc != 0) {
    int kerr = errno;
    HDEBUG(D_auth) debug_printf("heimdal: failed to initialise krb5 context: %s\n",
        strerror(kerr));
    return;
  }

  if (ob->server_keytab) {
    k_keytab_typed_name = CCS string_sprintf("file:%s", expand_string(ob->server_keytab));
    HDEBUG(D_auth) debug_printf("heimdal: using keytab %s\n", k_keytab_typed_name);
    krc = krb5_kt_resolve(context, k_keytab_typed_name, &keytab);
    if (krc) {
      HDEBUG(D_auth) exim_heimdal_error_debug("krb5_kt_resolve", context, krc);
      return;
    }
  } else {
    HDEBUG(D_auth) debug_printf("heimdal: using system default keytab\n");
    krc = krb5_kt_default(context, &keytab);
    if (krc) {
      HDEBUG(D_auth) exim_heimdal_error_debug("krb5_kt_default", context, krc);
      return;
    }
  }

  HDEBUG(D_auth) {
    /* http://www.h5l.org/manual/HEAD/krb5/krb5_keytab_intro.html */
    krc = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (krc)
      exim_heimdal_error_debug("krb5_kt_start_seq_get", context, krc);
    else {
      while ((krc = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0) {
        principal = enctype_s = NULL;
        krb5_unparse_name(context, entry.principal, &principal);
        krb5_enctype_to_string(context, entry.keyblock.keytype, &enctype_s);
        debug_printf("heimdal: keytab principal: %s  vno=%d  type=%s\n",
            principal ? principal : "??",
            entry.vno,
            enctype_s ? enctype_s : "??");
        free(principal);
        free(enctype_s);
        krb5_kt_free_entry(context, &entry);
      }
      krc = krb5_kt_end_seq_get(context, keytab, &cursor);
      if (krc)
        exim_heimdal_error_debug("krb5_kt_end_seq_get", context, krc);
    }
  }

  krc = krb5_kt_close(context, keytab);
  if (krc)
    HDEBUG(D_auth) exim_heimdal_error_debug("krb5_kt_close", context, krc);

  krb5_free_context(context);

  /* RFC 4121 section 5.2, SHOULD support 64K input buffers */
  if (big_buffer_size < (64 * 1024)) {
    uschar *newbuf;
    big_buffer_size = 64 * 1024;
    newbuf = store_malloc(big_buffer_size);
    store_free(big_buffer);
    big_buffer = newbuf;
  }

  ablock->server = TRUE;
}


static void
exim_heimdal_error_debug(const char *label,
    krb5_context context, krb5_error_code err)
{
  const char *kerrsc;
  kerrsc = krb5_get_error_message(context, err);
  debug_printf("heimdal %s: %s\n", label, kerrsc ? kerrsc : "unknown error");
  krb5_free_error_message(context, kerrsc);
}

/*************************************************
*             Server entry point                 *
*************************************************/

/* For interface, see auths/README */

/* GSSAPI notes:
OM_uint32: portable type for unsigned int32
gss_buffer_desc / *gss_buffer_t: hold/point-to size_t .length & void *value
  -- all strings/etc passed in should go through one of these
  -- when allocated by gssapi, release with gss_release_buffer()
*/

int
auth_heimdal_gssapi_server(auth_instance *ablock, uschar *initial_data)
{
  gss_name_t gclient = GSS_C_NO_NAME;
  gss_name_t gserver = GSS_C_NO_NAME;
  gss_cred_id_t gcred = GSS_C_NO_CREDENTIAL;
  gss_ctx_id_t gcontext = GSS_C_NO_CONTEXT;
  uschar *ex_server_str;
  gss_buffer_desc gbufdesc = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc gbufdesc_in = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc gbufdesc_out = GSS_C_EMPTY_BUFFER;
  gss_OID mech_type;
  OM_uint32 maj_stat, min_stat;
  int step, error_out, i;
  uschar *tmp1, *tmp2, *from_client;
  auth_heimdal_gssapi_options_block *ob =
    (auth_heimdal_gssapi_options_block *)(ablock->options_block);
  BOOL handled_empty_ir;
  uschar *store_reset_point;
  uschar *keytab;
  uschar sasl_config[4];
  uschar requested_qop;

  store_reset_point = store_get(0);

  HDEBUG(D_auth)
    debug_printf("heimdal: initialising auth context for %s\n", ablock->name);

  /* Construct our gss_name_t gserver describing ourselves */
  tmp1 = expand_string(ob->server_service);
  tmp2 = expand_string(ob->server_hostname);
  ex_server_str = string_sprintf("%s@%s", tmp1, tmp2);
  gbufdesc.value = (void *) ex_server_str;
  gbufdesc.length = Ustrlen(ex_server_str);
  maj_stat = gss_import_name(&min_stat,
      &gbufdesc, GSS_C_NT_HOSTBASED_SERVICE, &gserver);
  if (GSS_ERROR(maj_stat))
    return exim_gssapi_error_defer(store_reset_point, maj_stat, min_stat,
        "gss_import_name(%s)", CS gbufdesc.value);

  /* Use a specific keytab, if specified */
  if (ob->server_keytab) {
    keytab = expand_string(ob->server_keytab);
    maj_stat = gsskrb5_register_acceptor_identity(CCS keytab);
    if (GSS_ERROR(maj_stat))
      return exim_gssapi_error_defer(store_reset_point, maj_stat, min_stat,
          "registering keytab \"%s\"", keytab);
    HDEBUG(D_auth)
      debug_printf("heimdal: using keytab \"%s\"\n", keytab);
  }

  /* Acquire our credentials */
  maj_stat = gss_acquire_cred(&min_stat,
      gserver,             /* desired name */
      0,                   /* time */
      GSS_C_NULL_OID_SET,  /* desired mechs */
      GSS_C_ACCEPT,        /* cred usage */
      &gcred,              /* handle */
      NULL                 /* actual mechs */,
      NULL                 /* time rec */);
  if (GSS_ERROR(maj_stat))
    return exim_gssapi_error_defer(store_reset_point, maj_stat, min_stat,
        "gss_acquire_cred(%s)", ex_server_str);

  maj_stat = gss_release_name(&min_stat, &gserver);

  HDEBUG(D_auth) debug_printf("heimdal: have server credentials.\n");

  /* Loop talking to client */
  step = 0;
  from_client = initial_data;
  handled_empty_ir = FALSE;
  error_out = OK;

  /* buffer sizes: auth_get_data() uses big_buffer, which we grow per
  GSSAPI RFC in _init, if needed, to meet the SHOULD size of 64KB.
  (big_buffer starts life at the MUST size of 16KB). */

  /* step values
  0: getting initial data from client to feed into GSSAPI
  1: iterating for as long as GSS_S_CONTINUE_NEEDED
  2: GSS_S_COMPLETE, SASL wrapping for authz and qop to send to client
  3: unpick final auth message from client
  4: break/finish (non-step)
  */
  while (step < 4) {
    switch (step) {
      case 0:
        if (!from_client || *from_client == '\0') {
          if (handled_empty_ir) {
            HDEBUG(D_auth) debug_printf("gssapi: repeated empty input, grr.\n");
            error_out = BAD64;
            goto ERROR_OUT;
          } else {
            HDEBUG(D_auth) debug_printf("gssapi: missing initial response, nudging.\n");
            error_out = auth_get_data(&from_client, US"", 0);
            if (error_out != OK)
              goto ERROR_OUT;
            handled_empty_ir = TRUE;
            continue;
          }
        }
        /* We should now have the opening data from the client, base64-encoded. */
        step += 1;
        HDEBUG(D_auth) debug_printf("heimdal: have initial client data\n");
        break;

      case 1:
        gbufdesc_in.length = b64decode(from_client, USS &gbufdesc_in.value);
        if (gclient) {
          maj_stat = gss_release_name(&min_stat, &gclient);
          gclient = GSS_C_NO_NAME;
        }
        maj_stat = gss_accept_sec_context(&min_stat,
            &gcontext,          /* context handle */
            gcred,              /* acceptor cred handle */
            &gbufdesc_in,       /* input from client */
            GSS_C_NO_CHANNEL_BINDINGS,  /* XXX fixme: use the channel bindings from GnuTLS */
            &gclient,           /* client identifier */
            &mech_type,         /* mechanism in use */
            &gbufdesc_out,      /* output to send to client */
            NULL,               /* return flags */
            NULL,               /* time rec */
            NULL                /* delegated cred_handle */
            );
        if (GSS_ERROR(maj_stat)) {
          exim_gssapi_error_defer(NULL, maj_stat, min_stat,
              "gss_accept_sec_context()");
          error_out = FAIL;
          goto ERROR_OUT;
        }
        if (gbufdesc_out.length != 0) {
          error_out = auth_get_data(&from_client,
              gbufdesc_out.value, gbufdesc_out.length);
          if (error_out != OK)
            goto ERROR_OUT;

          gss_release_buffer(&min_stat, &gbufdesc_out);
          EmptyBuf(gbufdesc_out);
        }
        if (maj_stat == GSS_S_COMPLETE) {
          step += 1;
          HDEBUG(D_auth) debug_printf("heimdal: GSS complete\n");
        } else {
          HDEBUG(D_auth) debug_printf("heimdal: need more data\n");
        }
        break;

      case 2:
        memset(sasl_config, 0xFF, 4);
        /* draft-ietf-sasl-gssapi-06.txt defines bitmasks for first octet
        0x01 No security layer
        0x02 Integrity protection
        0x04 Confidentiality protection

        The remaining three octets are the maximum buffer size for wrapped
        content. */
        sasl_config[0] = 0x01;  /* Exim does not wrap/unwrap SASL layers after auth */
        gbufdesc.value = (void *) sasl_config;
        gbufdesc.length = 4;
        maj_stat = gss_wrap(&min_stat,
            gcontext,
            0,                    /* conf_req_flag: integrity only */
            GSS_C_QOP_DEFAULT,    /* qop requested */
            &gbufdesc,            /* message to protect */
            NULL,                 /* conf_state: no confidentiality applied */
            &gbufdesc_out         /* output buffer */
            );
        if (GSS_ERROR(maj_stat)) {
          exim_gssapi_error_defer(NULL, maj_stat, min_stat,
              "gss_wrap(SASL state after auth)");
          error_out = FAIL;
          goto ERROR_OUT;
        }

        HDEBUG(D_auth) debug_printf("heimdal SASL: requesting QOP with no security layers\n");

        error_out = auth_get_data(&from_client,
            gbufdesc_out.value, gbufdesc_out.length);
        if (error_out != OK)
          goto ERROR_OUT;

        gss_release_buffer(&min_stat, &gbufdesc_out);
        EmptyBuf(gbufdesc_out);
        step += 1;
        break;

      case 3:
        gbufdesc_in.length = b64decode(from_client, USS &gbufdesc_in.value);
        maj_stat = gss_unwrap(&min_stat,
            gcontext,
            &gbufdesc_in,       /* data from client */
            &gbufdesc_out,      /* results */
            NULL,               /* conf state */
            NULL                /* qop state */
            );
        if (GSS_ERROR(maj_stat)) {
          exim_gssapi_error_defer(NULL, maj_stat, min_stat,
              "gss_unwrap(final SASL message from client)");
          error_out = FAIL;
          goto ERROR_OUT;
        }
        if (gbufdesc_out.length < 4) {
          HDEBUG(D_auth)
            debug_printf("gssapi: final message too short; "
                "need flags, buf sizes and optional authzid\n");
          error_out = FAIL;
          goto ERROR_OUT;
        }

        requested_qop = (CS gbufdesc_out.value)[0];
        if ((requested_qop & 0x01) == 0) {
          HDEBUG(D_auth)
            debug_printf("gssapi: client requested security layers (%x)\n",
                (unsigned int) requested_qop);
          error_out = FAIL;
          goto ERROR_OUT;
        }

        for (i = 0; i < AUTH_VARS; i++) auth_vars[i] = NULL;
        expand_nmax = 0;

        /* Identifiers:
        The SASL provided identifier is an unverified authzid.
        GSSAPI provides us with a verified identifier, but it might be empty
        for some clients.
        */

        /* $auth2 is authzid requested at SASL layer */
        if (gbufdesc_out.length > 4) {
          expand_nlength[2] = gbufdesc_out.length - 4;
          auth_vars[1] = expand_nstring[2] =
            string_copyn((US gbufdesc_out.value) + 4, expand_nlength[2]);
          expand_nmax = 2;
        }

        gss_release_buffer(&min_stat, &gbufdesc_out);
        EmptyBuf(gbufdesc_out);

        /* $auth1 is GSSAPI display name */
        maj_stat = gss_display_name(&min_stat,
            gclient,
            &gbufdesc_out,
            &mech_type);
        if (GSS_ERROR(maj_stat)) {
          auth_vars[1] = expand_nstring[2] = NULL;
          expand_nmax = 0;
          exim_gssapi_error_defer(NULL, maj_stat, min_stat,
              "gss_display_name(client identifier)");
          error_out = FAIL;
          goto ERROR_OUT;
        }

        expand_nlength[1] = gbufdesc_out.length;
        auth_vars[0] = expand_nstring[1] =
          string_copyn(gbufdesc_out.value, gbufdesc_out.length);

        if (expand_nmax == 0) { /* should be: authzid was empty */
          expand_nmax = 2;
          expand_nlength[2] = expand_nlength[1];
          auth_vars[1] = expand_nstring[2] = string_copyn(expand_nstring[1], expand_nlength[1]);
          HDEBUG(D_auth)
            debug_printf("heimdal SASL: empty authzid, set to dup of GSSAPI display name\n");
        }

        HDEBUG(D_auth)
          debug_printf("heimdal SASL: happy with client request\n"
             "  auth1 (verified GSSAPI display-name): \"%s\"\n"
             "  auth2 (unverified SASL requested authzid): \"%s\"\n",
             auth_vars[0], auth_vars[1]);

        step += 1;
        break;

    } /* switch */
  } /* while step */


ERROR_OUT:
  maj_stat = gss_release_cred(&min_stat, &gcred);
  if (gclient) {
    gss_release_name(&min_stat, &gclient);
    gclient = GSS_C_NO_NAME;
  }
  if (gbufdesc_out.length) {
    gss_release_buffer(&min_stat, &gbufdesc_out);
    EmptyBuf(gbufdesc_out);
  }
  if (gcontext != GSS_C_NO_CONTEXT) {
    gss_delete_sec_context(&min_stat, &gcontext, GSS_C_NO_BUFFER);
  }

  store_reset(store_reset_point);

  if (error_out != OK)
    return error_out;

  /* Auth succeeded, check server_condition */
  return auth_check_serv_cond(ablock);
}


static int
exim_gssapi_error_defer(uschar *store_reset_point,
    OM_uint32 major, OM_uint32 minor,
    const char *format, ...)
{
  va_list ap;
  OM_uint32 maj_stat, min_stat;
  OM_uint32 msgcontext = 0;
  gss_buffer_desc status_string;
  gstring * g;

  HDEBUG(D_auth)
    {
    va_start(ap, format);
    g = string_vformat(NULL, TRUE, format, ap);
    va_end(ap);
    }

  auth_defer_msg = NULL;

  do {
    maj_stat = gss_display_status(&min_stat,
        major, GSS_C_GSS_CODE, GSS_C_NO_OID, &msgcontext, &status_string);

    if (!auth_defer_msg)
      auth_defer_msg = string_copy(US status_string.value);

    HDEBUG(D_auth) debug_printf("heimdal %s: %.*s\n",
        string_from_gstring(g), (int)status_string.length,
	CS status_string.value);
    gss_release_buffer(&min_stat, &status_string);

  } while (msgcontext != 0);

  if (store_reset_point)
    store_reset(store_reset_point);
  return DEFER;
}


/*************************************************
*              Client entry point                *
*************************************************/

/* For interface, see auths/README */

int
auth_heimdal_gssapi_client(
  auth_instance *ablock,                 /* authenticator block */
  void * sx,				 /* connection */
  int timeout,                           /* command timeout */
  uschar *buffer,                        /* buffer for reading response */
  int buffsize)                          /* size of buffer */
{
  HDEBUG(D_auth)
    debug_printf("Client side NOT IMPLEMENTED: you should not see this!\n");
  /* NOT IMPLEMENTED */
  return FAIL;
}

/*************************************************
*                Diagnostic API                  *
*************************************************/

void
auth_heimdal_gssapi_version_report(FILE *f)
{
  /* No build-time constants available unless we link against libraries at
  build-time and export the result as a string into a header ourselves. */
  fprintf(f, "Library version: Heimdal: Runtime: %s\n"
             " Build Info: %s\n",
          heimdal_version, heimdal_long_version);
}

#endif   /*!MACRO_PREDEF*/
#endif  /* AUTH_HEIMDAL_GSSAPI */

/* End of heimdal_gssapi.c */
