/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Many thanks to Stuart Lynne for contributing the original code for this
driver. Further contributions from Michael Haardt, Brian Candler, Barry
Pederson, Peter Savitch and Christian Kellner. Particular thanks to Brian for
researching how to handle the different kinds of error. */


#include "../exim.h"
#include "lf_functions.h"


/* Include LDAP headers. The code below uses some "old" LDAP interfaces that
are deprecated in OpenLDAP. I don't know their status in other LDAP
implementations. LDAP_DEPRECATED causes their prototypes to be defined in
ldap.h. */

#define LDAP_DEPRECATED 1

#include <lber.h>
#include <ldap.h>


/* Annoyingly, the different LDAP libraries handle errors in different ways,
and some other things too. There doesn't seem to be an automatic way of
distinguishing between them. Local/Makefile should contain a setting of
LDAP_LIB_TYPE, which in turn causes appropriate macros to be defined for the
different kinds. Those that matter are:

LDAP_LIB_NETSCAPE
LDAP_LIB_SOLARIS   with synonym LDAP_LIB_SOLARIS7
LDAP_LIB_OPENLDAP2

These others may be defined, but are in fact the default, so are not tested:

LDAP_LIB_UMICHIGAN
LDAP_LIB_OPENLDAP1
*/

#if defined(LDAP_LIB_SOLARIS7) && ! defined(LDAP_LIB_SOLARIS)
#define LDAP_LIB_SOLARIS
#endif


/* Just in case LDAP_NO_LIMIT is not defined by some of these libraries. */

#ifndef LDAP_NO_LIMIT
#define LDAP_NO_LIMIT 0
#endif


/* Just in case LDAP_DEREF_NEVER is not defined */

#ifndef LDAP_DEREF_NEVER
#define LDAP_DEREF_NEVER 0
#endif


/* Four types of LDAP search are implemented */

#define SEARCH_LDAP_MULTIPLE 0       /* Get attributes from multiple entries */
#define SEARCH_LDAP_SINGLE 1         /* Get attributes from one entry only */
#define SEARCH_LDAP_DN 2             /* Get just the DN from one entry */
#define SEARCH_LDAP_AUTH 3           /* Just checking for authentication */

/* In all 4 cases, the DN is left in $ldap_dn (which post-dates the
SEARCH_LDAP_DN lookup). */


/* Structure and anchor for caching connections. */

typedef struct ldap_connection {
  struct ldap_connection *next;
  uschar *host;
  uschar *user;
  uschar *password;
  BOOL  bound;
  int   port;
  BOOL  is_start_tls_called;
  LDAP *ld;
} LDAP_CONNECTION;

static LDAP_CONNECTION *ldap_connections = NULL;



/*************************************************
*         Internal search function               *
*************************************************/

/* This is the function that actually does the work. It is called (indirectly
via control_ldap_search) from eldap_find(), eldapauth_find(), eldapdn_find(),
and eldapm_find(), with a difference in the "search_type" argument.

The case of eldapauth_find() is special in that all it does is do
authentication, returning OK or FAIL as appropriate. This isn't used as a
lookup. Instead, it is called from expand.c as an expansion condition test.

The DN from a successful lookup is placed in $ldap_dn. This feature postdates
the provision of the SEARCH_LDAP_DN facility for returning just the DN as the
data.

Arguments:
  ldap_url      the URL to be looked up
  server        server host name, when URL contains none
  s_port        server port, used when URL contains no name
  search_type   SEARCH_LDAP_MULTIPLE allows values from multiple entries
                SEARCH_LDAP_SINGLE allows values from one entry only
                SEARCH_LDAP_DN gets the DN from one entry
  res           set to point at the result (not used for ldapauth)
  errmsg        set to point a message if result is not OK
  defer_break   set TRUE if no more servers to be tried after a DEFER
  user          user name for authentication, or NULL
  password      password for authentication, or NULL
  sizelimit     max number of entries returned, or 0 for no limit
  timelimit     max time to wait, or 0 for no limit
  tcplimit      max time for network activity, e.g. connect, or 0 for OS default
  deference     the dereference option, which is one of
                  LDAP_DEREF_{NEVER,SEARCHING,FINDING,ALWAYS}
  referrals     the referral option, which is LDAP_OPT_ON or LDAP_OPT_OFF

Returns:        OK or FAIL or DEFER
                FAIL is given only if a lookup was performed successfully, but
                returned no data.
*/

static int
perform_ldap_search(const uschar *ldap_url, uschar *server, int s_port,
  int search_type, uschar **res, uschar **errmsg, BOOL *defer_break,
  uschar *user, uschar *password, int sizelimit, int timelimit, int tcplimit,
  int dereference, void *referrals)
{
LDAPURLDesc     *ludp = NULL;
LDAPMessage     *result = NULL;
BerElement      *ber;
LDAP_CONNECTION *lcp;

struct timeval timeout;
struct timeval *timeoutptr = NULL;

uschar *attr;
uschar **attrp;
gstring * data = NULL;
uschar *dn = NULL;
uschar *host;
uschar **values;
uschar **firstval;
uschar porttext[16];

uschar *error1 = NULL;   /* string representation of errcode (static) */
uschar *error2 = NULL;   /* error message from the server */
uschar *matched = NULL;  /* partially matched DN */

int    attrs_requested = 0;
int    error_yield = DEFER;
int    msgid;
int    rc, ldap_rc, ldap_parse_rc;
int    port;
int    rescount = 0;
BOOL   attribute_found = FALSE;
BOOL   ldapi = FALSE;

DEBUG(D_lookup)
  debug_printf("perform_ldap_search: ldap%s URL = \"%s\" server=%s port=%d "
    "sizelimit=%d timelimit=%d tcplimit=%d\n",
    search_type == SEARCH_LDAP_MULTIPLE ? "m" :
    search_type == SEARCH_LDAP_DN       ? "dn" :
    search_type == SEARCH_LDAP_AUTH     ? "auth" : "",
    ldap_url, server, s_port, sizelimit, timelimit, tcplimit);

/* Check if LDAP thinks the URL is a valid LDAP URL. We assume that if the LDAP
library that is in use doesn't recognize, say, "ldapi", it will barf here. */

if (!ldap_is_ldap_url(CS ldap_url))
  {
  *errmsg = string_sprintf("ldap_is_ldap_url: not an LDAP url \"%s\"\n",
    ldap_url);
  goto RETURN_ERROR_BREAK;
  }

/* Parse the URL */

if ((rc = ldap_url_parse(CS ldap_url, &ludp)) != 0)
  {
  *errmsg = string_sprintf("ldap_url_parse: (error %d) parsing \"%s\"\n", rc,
    ldap_url);
  goto RETURN_ERROR_BREAK;
  }

/* If the host name is empty, take it from the separate argument, if one is
given. OpenLDAP 2.0.6 sets an unset hostname to "" rather than empty, but
expects NULL later in ldap_init() to mean "default", annoyingly. In OpenLDAP
2.0.11 this has changed (it uses NULL). */

if ((!ludp->lud_host || !ludp->lud_host[0]) && server)
  {
  host = server;
  port = s_port;
  }
else
  {
  host = US ludp->lud_host;
  if (host && !host[0]) host = NULL;
  port = ludp->lud_port;
  }

DEBUG(D_lookup) debug_printf("after ldap_url_parse: host=%s port=%d\n",
  host, port);

if (port == 0) port = LDAP_PORT;      /* Default if none given */
sprintf(CS porttext, ":%d", port);    /* For messages */

/* If the "host name" is actually a path, we are going to connect using a Unix
socket, regardless of whether "ldapi" was actually specified or not. This means
that a Unix socket can be declared in eldap_default_servers, and "traditional"
LDAP queries using just "ldap" can be used ("ldaps" is similarly overridden).
The path may start with "/" or it may already be escaped as "%2F" if it was
actually declared that way in eldap_default_servers. (I did it that way the
first time.) If the host name is not a path, the use of "ldapi" causes an
error, except in the default case. (But lud_scheme doesn't seem to exist in
older libraries.) */

if (host)
  {
  if ((host[0] == '/' || Ustrncmp(host, "%2F", 3) == 0))
    {
    ldapi = TRUE;
    porttext[0] = 0;    /* Remove port from messages */
    }

#if defined LDAP_LIB_OPENLDAP2
  else if (strncmp(ludp->lud_scheme, "ldapi", 5) == 0)
    {
    *errmsg = string_sprintf("ldapi requires an absolute path (\"%s\" given)",
      host);
    goto RETURN_ERROR;
    }
#endif
  }

/* Count the attributes; we need this later to tell us how to format results */

for (attrp = USS ludp->lud_attrs; attrp && *attrp; attrp++)
  attrs_requested++;

/* See if we can find a cached connection to this host. The port is not
relevant for ldapi. The host name pointer is set to NULL if no host was given
(implying the library default), rather than to the empty string. Note that in
this case, there is no difference between ldap and ldapi. */

for (lcp = ldap_connections; lcp; lcp = lcp->next)
  {
  if ((host == NULL) != (lcp->host == NULL) ||
      (host != NULL && strcmpic(lcp->host, host) != 0))
    continue;
  if (ldapi || port == lcp->port) break;
  }

/* Use this network timeout in any requests. */

if (tcplimit > 0)
  {
  timeout.tv_sec = tcplimit;
  timeout.tv_usec = 0;
  timeoutptr = &timeout;
  }

/* If no cached connection found, we must open a connection to the server. If
the server name is actually an absolute path, we set ldapi=TRUE above. This
requests connection via a Unix socket. However, as far as I know, only OpenLDAP
supports the use of sockets, and the use of ldap_initialize(). */

if (!lcp)
  {
  LDAP *ld;

#ifdef LDAP_OPT_X_TLS_NEWCTX
  int  am_server = 0;
  LDAP *ldsetctx;
#else
  LDAP *ldsetctx = NULL;
#endif


  /* --------------------------- OpenLDAP ------------------------ */

  /* There seems to be a preference under OpenLDAP for ldap_initialize()
  instead of ldap_init(), though I have as yet been unable to find
  documentation that says this. (OpenLDAP documentation is sparse to
  non-existent). So we handle OpenLDAP differently here. Also, support for
  ldapi seems to be OpenLDAP-only at present. */

#ifdef LDAP_LIB_OPENLDAP2

  /* We now need an empty string for the default host. Get some store in which
  to build a URL for ldap_initialize(). In the ldapi case, it can't be bigger
  than (9 + 3*Ustrlen(shost)), whereas in the other cases it can't be bigger
  than the host name + "ldaps:///" plus : and a port number, say 20 + the
  length of the host name. What we get should accommodate both, easily. */

  uschar *shost = (host == NULL)? US"" : host;
  uschar *init_url = store_get(20 + 3 * Ustrlen(shost));
  uschar *init_ptr;

  /* Handle connection via Unix socket ("ldapi"). We build a basic LDAP URI to
  contain the path name, with slashes escaped as %2F. */

  if (ldapi)
    {
    int ch;
    init_ptr = init_url + 8;
    Ustrcpy(init_url, "ldapi://");
    while ((ch = *shost++))
      if (ch == '/')
	{ Ustrncpy(init_ptr, "%2F", 3); init_ptr += 3; }
      else
	*init_ptr++ = ch;
    *init_ptr = 0;
    }

  /* This is not an ldapi call. Just build a URI with the protocol type, host
  name, and port. */

  else
    {
    init_ptr = Ustrchr(ldap_url, '/');
    Ustrncpy(init_url, ldap_url, init_ptr - ldap_url);
    init_ptr = init_url + (init_ptr - ldap_url);
    sprintf(CS init_ptr, "//%s:%d/", shost, port);
    }

  /* Call ldap_initialize() and check the result */

  DEBUG(D_lookup) debug_printf("ldap_initialize with URL %s\n", init_url);
  if ((rc = ldap_initialize(&ld, CS init_url)) != LDAP_SUCCESS)
    {
    *errmsg = string_sprintf("ldap_initialize: (error %d) URL \"%s\"\n",
      rc, init_url);
    goto RETURN_ERROR;
    }
  store_reset(init_url);   /* Might as well save memory when we can */


  /* ------------------------- Not OpenLDAP ---------------------- */

  /* For libraries other than OpenLDAP, use ldap_init(). */

#else   /* LDAP_LIB_OPENLDAP2 */
  ld = ldap_init(CS host, port);
#endif  /* LDAP_LIB_OPENLDAP2 */

  /* -------------------------------------------------------------- */


  /* Handle failure to initialize */

  if (!ld)
    {
    *errmsg = string_sprintf("failed to initialize for LDAP server %s%s - %s",
      host, porttext, strerror(errno));
    goto RETURN_ERROR;
    }

#ifdef LDAP_OPT_X_TLS_NEWCTX
  ldsetctx = ld;
#endif

  /* Set the TCP connect time limit if available. This is something that is
  in Netscape SDK v4.1; I don't know about other libraries. */

#ifdef LDAP_X_OPT_CONNECT_TIMEOUT
  if (tcplimit > 0)
    {
    int timeout1000 = tcplimit*1000;
    ldap_set_option(ld, LDAP_X_OPT_CONNECT_TIMEOUT, (void *)&timeout1000);
    }
  else
    {
    int notimeout = LDAP_X_IO_TIMEOUT_NO_TIMEOUT;
    ldap_set_option(ld, LDAP_X_OPT_CONNECT_TIMEOUT, (void *)&notimeout);
    }
#endif

  /* Set the TCP connect timeout. This works with OpenLDAP 2.2.14. */

#ifdef LDAP_OPT_NETWORK_TIMEOUT
  if (tcplimit > 0)
    ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, (void *)timeoutptr);
#endif

  /* I could not get TLS to work until I set the version to 3. That version
  seems to be the default nowadays. The RFC is dated 1997, so I would hope
  that all the LDAP libraries support it. Therefore, if eldap_version hasn't
  been set, go for v3 if we can. */

  if (eldap_version < 0)
    {
#ifdef LDAP_VERSION3
    eldap_version = LDAP_VERSION3;
#else
    eldap_version = 2;
#endif
    }

#ifdef LDAP_OPT_PROTOCOL_VERSION
  ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, (void *)&eldap_version);
#endif

  DEBUG(D_lookup) debug_printf("initialized for LDAP (v%d) server %s%s\n",
    eldap_version, host, porttext);

  /* If not using ldapi and TLS is available, set appropriate TLS options: hard
  for "ldaps" and soft otherwise. */

#ifdef LDAP_OPT_X_TLS
  if (!ldapi)
    {
    int tls_option;
# ifdef LDAP_OPT_X_TLS_REQUIRE_CERT
    if (eldap_require_cert)
      {
      tls_option =
	Ustrcmp(eldap_require_cert, "hard")     == 0 ? LDAP_OPT_X_TLS_HARD
	: Ustrcmp(eldap_require_cert, "demand") == 0 ? LDAP_OPT_X_TLS_DEMAND
	: Ustrcmp(eldap_require_cert, "allow")  == 0 ? LDAP_OPT_X_TLS_ALLOW
	: Ustrcmp(eldap_require_cert, "try")    == 0 ? LDAP_OPT_X_TLS_TRY
	: LDAP_OPT_X_TLS_NEVER;

      DEBUG(D_lookup)
        debug_printf("Require certificate overrides LDAP_OPT_X_TLS option (%d)\n",
                     tls_option);
      }
    else
# endif  /* LDAP_OPT_X_TLS_REQUIRE_CERT */
    if (strncmp(ludp->lud_scheme, "ldaps", 5) == 0)
      {
      tls_option = LDAP_OPT_X_TLS_HARD;
      DEBUG(D_lookup)
        debug_printf("LDAP_OPT_X_TLS_HARD set due to ldaps:// URI\n");
      }
    else
      {
      tls_option = LDAP_OPT_X_TLS_TRY;
      DEBUG(D_lookup)
        debug_printf("LDAP_OPT_X_TLS_TRY set due to ldap:// URI\n");
      }
    ldap_set_option(ld, LDAP_OPT_X_TLS, (void *)&tls_option);
    }
#endif  /* LDAP_OPT_X_TLS */

#ifdef LDAP_OPT_X_TLS_CACERTFILE
  if (eldap_ca_cert_file)
    ldap_set_option(ldsetctx, LDAP_OPT_X_TLS_CACERTFILE, eldap_ca_cert_file);
#endif
#ifdef LDAP_OPT_X_TLS_CACERTDIR
  if (eldap_ca_cert_dir)
    ldap_set_option(ldsetctx, LDAP_OPT_X_TLS_CACERTDIR, eldap_ca_cert_dir);
#endif
#ifdef LDAP_OPT_X_TLS_CERTFILE
  if (eldap_cert_file)
    ldap_set_option(ldsetctx, LDAP_OPT_X_TLS_CERTFILE, eldap_cert_file);
#endif
#ifdef LDAP_OPT_X_TLS_KEYFILE
  if (eldap_cert_key)
    ldap_set_option(ldsetctx, LDAP_OPT_X_TLS_KEYFILE, eldap_cert_key);
#endif
#ifdef LDAP_OPT_X_TLS_CIPHER_SUITE
  if (eldap_cipher_suite)
    ldap_set_option(ldsetctx, LDAP_OPT_X_TLS_CIPHER_SUITE, eldap_cipher_suite);
#endif
#ifdef LDAP_OPT_X_TLS_REQUIRE_CERT
  if (eldap_require_cert)
    {
    int cert_option =
      Ustrcmp(eldap_require_cert, "hard")     == 0 ? LDAP_OPT_X_TLS_HARD
      : Ustrcmp(eldap_require_cert, "demand") == 0 ? LDAP_OPT_X_TLS_DEMAND
      : Ustrcmp(eldap_require_cert, "allow")  == 0 ? LDAP_OPT_X_TLS_ALLOW
      : Ustrcmp(eldap_require_cert, "try")    == 0 ? LDAP_OPT_X_TLS_TRY
      : LDAP_OPT_X_TLS_NEVER;

    /* This ldap handle is set at compile time based on client libs. Older
     * versions want it to be global and newer versions can force a reload
     * of the TLS context (to reload these settings we are changing from the
     * default that loaded at instantiation). */
    rc = ldap_set_option(ldsetctx, LDAP_OPT_X_TLS_REQUIRE_CERT, &cert_option);
    if (rc)
      DEBUG(D_lookup)
        debug_printf("Unable to set TLS require cert_option(%d) globally: %s\n",
          cert_option, ldap_err2string(rc));
    }
#endif
#ifdef LDAP_OPT_X_TLS_NEWCTX
  if ((rc = ldap_set_option(ldsetctx, LDAP_OPT_X_TLS_NEWCTX, &am_server)))
    DEBUG(D_lookup)
      debug_printf("Unable to reload TLS context %d: %s\n",
                   rc, ldap_err2string(rc));
  #endif

  /* Now add this connection to the chain of cached connections */

  lcp = store_get(sizeof(LDAP_CONNECTION));
  lcp->host = (host == NULL)? NULL : string_copy(host);
  lcp->bound = FALSE;
  lcp->user = NULL;
  lcp->password = NULL;
  lcp->port = port;
  lcp->ld = ld;
  lcp->next = ldap_connections;
  lcp->is_start_tls_called = FALSE;
  ldap_connections = lcp;
  }

/* Found cached connection */

else
  DEBUG(D_lookup)
    debug_printf("re-using cached connection to LDAP server %s%s\n",
      host, porttext);

/* Bind with the user/password supplied, or an anonymous bind if these values
are NULL, unless a cached connection is already bound with the same values. */

if (  !lcp->bound
   || !lcp->user && user
   || lcp->user && !user
   || lcp->user && user && Ustrcmp(lcp->user, user) != 0
   || !lcp->password && password
   || lcp->password && !password
   || lcp->password && password && Ustrcmp(lcp->password, password) != 0
   )
  {
  DEBUG(D_lookup) debug_printf("%sbinding with user=%s password=%s\n",
    lcp->bound ? "re-" : "", user, password);

  if (eldap_start_tls && !lcp->is_start_tls_called && !ldapi)
    {
#if defined(LDAP_OPT_X_TLS) && !defined(LDAP_LIB_SOLARIS)
    /* The Oracle LDAP libraries (LDAP_LIB_TYPE=SOLARIS) don't support this.
     * Note: moreover, they appear to now define LDAP_OPT_X_TLS and still not
     *       export an ldap_start_tls_s symbol.
     */
    if ( (rc = ldap_start_tls_s(lcp->ld, NULL, NULL)) != LDAP_SUCCESS)
      {
      *errmsg = string_sprintf("failed to initiate TLS processing on an "
          "LDAP session to server %s%s - ldap_start_tls_s() returned %d:"
          " %s", host, porttext, rc, ldap_err2string(rc));
      goto RETURN_ERROR;
      }
    lcp->is_start_tls_called = TRUE;
#else
    DEBUG(D_lookup) debug_printf("TLS initiation not supported with this Exim"
      " and your LDAP library.\n");
#endif
    }
  if ((msgid = ldap_bind(lcp->ld, CS user, CS password, LDAP_AUTH_SIMPLE))
       == -1)
    {
    *errmsg = string_sprintf("failed to bind the LDAP connection to server "
      "%s%s - ldap_bind() returned -1", host, porttext);
    goto RETURN_ERROR;
    }

  if ((rc = ldap_result(lcp->ld, msgid, 1, timeoutptr, &result)) <= 0)
    {
    *errmsg = string_sprintf("failed to bind the LDAP connection to server "
      "%s%s - LDAP error: %s", host, porttext,
      rc == -1 ? "result retrieval failed" : "timeout" );
    result = NULL;
    goto RETURN_ERROR;
    }

  rc = ldap_result2error(lcp->ld, result, 0);

  /* Invalid credentials when just checking credentials returns FAIL. This
  stops any further servers being tried. */

  if (search_type == SEARCH_LDAP_AUTH && rc == LDAP_INVALID_CREDENTIALS)
    {
    DEBUG(D_lookup)
      debug_printf("Invalid credentials: ldapauth returns FAIL\n");
    error_yield = FAIL;
    goto RETURN_ERROR_NOMSG;
    }

  /* Otherwise we have a problem that doesn't stop further servers from being
  tried. */

  if (rc != LDAP_SUCCESS)
    {
    *errmsg = string_sprintf("failed to bind the LDAP connection to server "
      "%s%s - LDAP error %d: %s", host, porttext, rc, ldap_err2string(rc));
    goto RETURN_ERROR;
    }

  /* Successful bind */

  lcp->bound = TRUE;
  lcp->user = !user ? NULL : string_copy(user);
  lcp->password = !password ? NULL : string_copy(password);

  ldap_msgfree(result);
  result = NULL;
  }

/* If we are just checking credentials, return OK. */

if (search_type == SEARCH_LDAP_AUTH)
  {
  DEBUG(D_lookup) debug_printf("Bind succeeded: ldapauth returns OK\n");
  goto RETURN_OK;
  }

/* Before doing the search, set the time and size limits (if given). Here again
the different implementations of LDAP have chosen to do things differently. */

#if defined(LDAP_OPT_SIZELIMIT)
ldap_set_option(lcp->ld, LDAP_OPT_SIZELIMIT, (void *)&sizelimit);
ldap_set_option(lcp->ld, LDAP_OPT_TIMELIMIT, (void *)&timelimit);
#else
lcp->ld->ld_sizelimit = sizelimit;
lcp->ld->ld_timelimit = timelimit;
#endif

/* Similarly for dereferencing aliases. Don't know if this is possible on
an LDAP library without LDAP_OPT_DEREF. */

#if defined(LDAP_OPT_DEREF)
ldap_set_option(lcp->ld, LDAP_OPT_DEREF, (void *)&dereference);
#endif

/* Similarly for the referral setting; should the library follow referrals that
the LDAP server returns? The conditional is just in case someone uses a library
without it. */

#if defined(LDAP_OPT_REFERRALS)
ldap_set_option(lcp->ld, LDAP_OPT_REFERRALS, referrals);
#endif

/* Start the search on the server. */

DEBUG(D_lookup) debug_printf("Start search\n");

msgid = ldap_search(lcp->ld, ludp->lud_dn, ludp->lud_scope, ludp->lud_filter,
  ludp->lud_attrs, 0);

if (msgid == -1)
  {
#if defined LDAP_LIB_SOLARIS || defined LDAP_LIB_OPENLDAP2
  int err;
  ldap_get_option(lcp->ld, LDAP_OPT_ERROR_NUMBER, &err);
  *errmsg = string_sprintf("ldap_search failed: %d, %s", err,
    ldap_err2string(err));
#else
  *errmsg = string_sprintf("ldap_search failed");
#endif

  goto RETURN_ERROR;
  }

/* Loop to pick up results as they come in, setting a timeout if one was
given. */

while ((rc = ldap_result(lcp->ld, msgid, 0, timeoutptr, &result)) ==
        LDAP_RES_SEARCH_ENTRY)
  {
  LDAPMessage  *e;
  int valuecount;   /* We can see an attr spread across several
                    entries. If B is derived from A and we request
                    A and the directory contains both, A and B,
                    then we get two entries, one for A and one for B.
                    Here we just count the values per entry */

  DEBUG(D_lookup) debug_printf("LDAP result loop\n");

  for(e = ldap_first_entry(lcp->ld, result), valuecount = 0;
      e;
      e = ldap_next_entry(lcp->ld, e))
    {
    uschar *new_dn;
    BOOL insert_space = FALSE;

    DEBUG(D_lookup) debug_printf("LDAP entry loop\n");

    rescount++;   /* Count results */

    /* Results for multiple entries values are separated by newlines. */

    if (data) data = string_catn(data, US"\n", 1);

    /* Get the DN from the last result. */

    if ((new_dn = US ldap_get_dn(lcp->ld, e)))
      {
      if (dn)
        {
#if defined LDAP_LIB_NETSCAPE || defined LDAP_LIB_OPENLDAP2
        ldap_memfree(dn);
#else   /* OPENLDAP 1, UMich, Solaris */
        free(dn);
#endif
        }
      /* Save for later */
      dn = new_dn;
      }

    /* If the data we want is actually the DN rather than any attribute values,
    (an "ldapdn" search) add it to the data string. If there are multiple
    entries, the DNs will be concatenated, but we test for this case below, as
    for SEARCH_LDAP_SINGLE, and give an error. */

    if (search_type == SEARCH_LDAP_DN)	/* Do not amalgamate these into one */
      {					/* condition, because of the else */
      if (new_dn)			/* below, that's for the first only */
        {
        data = string_cat(data, new_dn);
	(void) string_from_gstring(data);
        attribute_found = TRUE;
        }
      }

    /* Otherwise, loop through the entry, grabbing attribute values. If there's
    only one attribute being retrieved, no attribute name is given, and the
    result is not quoted. Multiple values are separated by (comma).
    If more than one attribute is being retrieved, the data is given as a
    sequence of name=value pairs, separated by (space), with the value always in quotes.
    If there are multiple values, they are given within the quotes, comma separated. */

    else for (attr = US ldap_first_attribute(lcp->ld, e, &ber);
              attr; attr = US ldap_next_attribute(lcp->ld, e, ber))
      {
      DEBUG(D_lookup) debug_printf("LDAP attr loop\n");

      /* In case of attrs_requested == 1 we just count the values, in all other cases
      (0, >1) we count the values per attribute */
      if (attrs_requested != 1) valuecount = 0;

      if (attr[0] != 0)
        {
        /* Get array of values for this attribute. */

        if ((firstval = values = USS ldap_get_values(lcp->ld, e, CS attr)))
          {
          if (attrs_requested != 1)
            {
            if (insert_space)
              data = string_catn(data, US" ", 1);
            else
              insert_space = TRUE;
            data = string_cat(data, attr);
            data = string_catn(data, US"=\"", 2);
            }

          while (*values)
            {
            uschar *value = *values;
            int len = Ustrlen(value);
            ++valuecount;

            DEBUG(D_lookup) debug_printf("LDAP value loop %s:%s\n", attr, value);

            /* In case we requested one attribute only but got several times
            into that attr loop, we need to append the additional values.
            (This may happen if you derive attributeTypes B and C from A and
            then query for A.) In all other cases we detect the different
            attribute and append only every non first value. */

            if (data && valuecount > 1)
              data = string_catn(data, US",", 1);

            /* For multiple attributes, the data is in quotes. We must escape
            internal quotes, backslashes, newlines, and must double commas. */

            if (attrs_requested != 1)
              {
              int j;
              for (j = 0; j < len; j++)
                {
                if (value[j] == '\n')
                  data = string_catn(data, US"\\n", 2);
                else if (value[j] == ',')
                  data = string_catn(data, US",,", 2);
                else
                  {
                  if (value[j] == '\"' || value[j] == '\\')
                    data = string_catn(data, US"\\", 1);
                  data = string_catn(data, value+j, 1);
                  }
                }
              }

            /* For single attributes, just double commas */

	    else
	      {
	      int j;
	      for (j = 0; j < len; j++)
	        if (value[j] == ',')
	          data = string_catn(data, US",,", 2);
	        else
	          data = string_catn(data, value+j, 1);
	      }


            /* Move on to the next value */

            values++;
            attribute_found = TRUE;
            }

          /* Closing quote at the end of the data for a named attribute. */

          if (attrs_requested != 1)
            data = string_catn(data, US"\"", 1);

          /* Free the values */

          ldap_value_free(CSS firstval);
          }
        }

#if defined LDAP_LIB_NETSCAPE || defined LDAP_LIB_OPENLDAP2

      /* Netscape and OpenLDAP2 LDAP's attrs are dynamically allocated and need
      to be freed. UMich LDAP stores them in static storage and does not require
      this. */

      ldap_memfree(attr);
#endif
      }        /* End "for" loop for extracting attributes from an entry */
    }          /* End "for" loop for extracting entries from a result */

  /* Free the result */

  ldap_msgfree(result);
  result = NULL;
  }            /* End "while" loop for multiple results */

/* Terminate the dynamic string that we have built and reclaim unused store.
In the odd case of a single attribute with zero-length value, allocate
an empty string. */

if (!data) data = string_get(1);
(void) string_from_gstring(data);
gstring_reset_unused(data);

/* Copy the last dn into eldap_dn */

if (dn)
  {
  eldap_dn = string_copy(dn);
#if defined LDAP_LIB_NETSCAPE || defined LDAP_LIB_OPENLDAP2
  ldap_memfree(dn);
#else   /* OPENLDAP 1, UMich, Solaris */
  free(dn);
#endif
  }

DEBUG(D_lookup) debug_printf("search ended by ldap_result yielding %d\n",rc);

if (rc == 0)
  {
  *errmsg = US"ldap_result timed out";
  goto RETURN_ERROR;
  }

/* A return code of -1 seems to mean "ldap_result failed internally or couldn't
provide you with a message". Other error states seem to exist where
ldap_result() didn't give us any message from the server at all, leaving result
set to NULL. Apparently, "the error parameters of the LDAP session handle will
be set accordingly". That's the best we can do to retrieve an error status; we
can't use functions like ldap_result2error because they parse a message from
the server, which we didn't get.

Annoyingly, the different implementations of LDAP have gone for different
methods of handling error codes and generating error messages. */

if (rc == -1 || !result)
  {
  int err;
  DEBUG(D_lookup) debug_printf("ldap_result failed\n");

#if defined LDAP_LIB_SOLARIS || defined LDAP_LIB_OPENLDAP2
    ldap_get_option(lcp->ld, LDAP_OPT_ERROR_NUMBER, &err);
    *errmsg = string_sprintf("ldap_result failed: %d, %s",
      err, ldap_err2string(err));

#elif defined LDAP_LIB_NETSCAPE
    /* Dubious (surely 'matched' is spurious here?) */
    (void)ldap_get_lderrno(lcp->ld, &matched, &error1);
    *errmsg = string_sprintf("ldap_result failed: %s (%s)", error1, matched);

#else                             /* UMich LDAP aka OpenLDAP 1.x */
    *errmsg = string_sprintf("ldap_result failed: %d, %s",
      lcp->ld->ld_errno, ldap_err2string(lcp->ld->ld_errno));
#endif

  goto RETURN_ERROR;
  }

/* A return code that isn't -1 doesn't necessarily mean there were no problems
with the search. The message must be an LDAP_RES_SEARCH_RESULT or
LDAP_RES_SEARCH_REFERENCE or else it's something we can't handle. Some versions
of LDAP do not define LDAP_RES_SEARCH_REFERENCE (LDAP v1 is one, it seems). So
we don't provide that functionality when we can't. :-) */

if (rc != LDAP_RES_SEARCH_RESULT
#ifdef LDAP_RES_SEARCH_REFERENCE
    && rc != LDAP_RES_SEARCH_REFERENCE
#endif
   )
  {
  *errmsg = string_sprintf("ldap_result returned unexpected code %d", rc);
  goto RETURN_ERROR;
  }

/* We have a result message from the server. This doesn't yet mean all is well.
We need to parse the message to find out exactly what's happened. */

#if defined LDAP_LIB_SOLARIS || defined LDAP_LIB_OPENLDAP2
  ldap_rc = rc;
  ldap_parse_rc = ldap_parse_result(lcp->ld, result, &rc, CSS &matched,
    CSS &error2, NULL, NULL, 0);
  DEBUG(D_lookup) debug_printf("ldap_parse_result: %d\n", ldap_parse_rc);
  if (ldap_parse_rc < 0 &&
      (ldap_parse_rc != LDAP_NO_RESULTS_RETURNED
      #ifdef LDAP_RES_SEARCH_REFERENCE
      || ldap_rc != LDAP_RES_SEARCH_REFERENCE
      #endif
     ))
    {
    *errmsg = string_sprintf("ldap_parse_result failed %d", ldap_parse_rc);
    goto RETURN_ERROR;
    }
  error1 = US ldap_err2string(rc);

#elif defined LDAP_LIB_NETSCAPE
  /* Dubious (it doesn't reference 'result' at all!) */
  rc = ldap_get_lderrno(lcp->ld, &matched, &error1);

#else                             /* UMich LDAP aka OpenLDAP 1.x */
  rc = ldap_result2error(lcp->ld, result, 0);
  error1 = ldap_err2string(rc);
  error2 = lcp->ld->ld_error;
  matched = lcp->ld->ld_matched;
#endif

/* Process the status as follows:

  (1) If we get LDAP_SIZELIMIT_EXCEEDED, just carry on, to return the
      truncated result list.

  (2) If we get LDAP_RES_SEARCH_REFERENCE, also just carry on. This was a
      submitted patch that is reported to "do the right thing" with Solaris
      LDAP libraries. (The problem it addresses apparently does not occur with
      Open LDAP.)

  (3) The range of errors defined by LDAP_NAME_ERROR generally mean "that
      object does not, or cannot, exist in the database". For those cases we
      fail the lookup.

  (4) All other non-successes here are treated as some kind of problem with
      the lookup, so return DEFER (which is the default in error_yield).
*/

DEBUG(D_lookup) debug_printf("ldap_parse_result yielded %d: %s\n",
  rc, ldap_err2string(rc));

if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED
    #ifdef LDAP_RES_SEARCH_REFERENCE
    && rc != LDAP_RES_SEARCH_REFERENCE
    #endif
    )
  {
  *errmsg = string_sprintf("LDAP search failed - error %d: %s%s%s%s%s",
    rc,
    error1 ?                  error1  : US"",
    error2 && error2[0] ?     US"/"   : US"",
    error2 ?                  error2  : US"",
    matched && matched[0] ?   US"/"   : US"",
    matched ?                 matched : US"");

#if defined LDAP_NAME_ERROR
  if (LDAP_NAME_ERROR(rc))
#elif defined NAME_ERROR    /* OPENLDAP1 calls it this */
  if (NAME_ERROR(rc))
#else
  if (rc == LDAP_NO_SUCH_OBJECT)
#endif

    {
    DEBUG(D_lookup) debug_printf("lookup failure forced\n");
    error_yield = FAIL;
    }
  goto RETURN_ERROR;
  }

/* The search succeeded. Check if we have too many results */

if (search_type != SEARCH_LDAP_MULTIPLE && rescount > 1)
  {
  *errmsg = string_sprintf("LDAP search: more than one entry (%d) was returned "
    "(filter not specific enough?)", rescount);
  goto RETURN_ERROR_BREAK;
  }

/* Check if we have too few (zero) entries */

if (rescount < 1)
  {
  *errmsg = string_sprintf("LDAP search: no results");
  error_yield = FAIL;
  goto RETURN_ERROR_BREAK;
  }

/* If an entry was found, but it had no attributes, we behave as if no entries
were found, that is, the lookup failed. */

if (!attribute_found)
  {
  *errmsg = US"LDAP search: found no attributes";
  error_yield = FAIL;
  goto RETURN_ERROR;
  }

/* Otherwise, it's all worked */

DEBUG(D_lookup) debug_printf("LDAP search: returning: %s\n", data->s);
*res = data->s;

RETURN_OK:
if (result) ldap_msgfree(result);
ldap_free_urldesc(ludp);
return OK;

/* Error returns */

RETURN_ERROR_BREAK:
*defer_break = TRUE;

RETURN_ERROR:
DEBUG(D_lookup) debug_printf("%s\n", *errmsg);

RETURN_ERROR_NOMSG:
if (result) ldap_msgfree(result);
if (ludp) ldap_free_urldesc(ludp);

#if defined LDAP_LIB_OPENLDAP2
  if (error2)  ldap_memfree(error2);
  if (matched) ldap_memfree(matched);
#endif

return error_yield;
}



/*************************************************
*        Internal search control function        *
*************************************************/

/* This function is called from eldap_find(), eldapauth_find(), eldapdn_find(),
and eldapm_find() with a difference in the "search_type" argument. It controls
calls to perform_ldap_search() which actually does the work. We call that
repeatedly for certain types of defer in the case when the URL contains no host
name and eldap_default_servers is set to a list of servers to try. This gives
more control than just passing over a list of hosts to ldap_open() because it
handles other kinds of defer as well as just a failure to open. Note that the
URL is defined to contain either zero or one "hostport" only.

Parameter data in addition to the URL can be passed as preceding text in the
string, as items of the form XXX=yyy. The URL itself can be detected because it
must begin "ldapx://", where x is empty, s, or i.

Arguments:
  ldap_url      the URL to be looked up, optionally preceded by other parameter
                settings
  search_type   SEARCH_LDAP_MULTIPLE allows values from multiple entries
                SEARCH_LDAP_SINGLE allows values from one entry only
                SEARCH_LDAP_DN gets the DN from one entry
  res           set to point at the result
  errmsg        set to point a message if result is not OK

Returns:        OK or FAIL or DEFER
*/

static int
control_ldap_search(const uschar *ldap_url, int search_type, uschar **res,
  uschar **errmsg)
{
BOOL defer_break = FALSE;
int timelimit = LDAP_NO_LIMIT;
int sizelimit = LDAP_NO_LIMIT;
int tcplimit = 0;
int sep = 0;
int dereference = LDAP_DEREF_NEVER;
void* referrals = LDAP_OPT_ON;
const uschar *url = ldap_url;
const uschar *p;
uschar *user = NULL;
uschar *password = NULL;
uschar *local_servers = NULL;
uschar *server;
const uschar *list;
uschar buffer[512];

while (isspace(*url)) url++;

/* Until the string begins "ldap", search for the other parameter settings that
are recognized. They are of the form NAME=VALUE, with the value being
optionally double-quoted. There must still be a space after it, however. No
NAME has the value "ldap". */

while (strncmpic(url, US"ldap", 4) != 0)
  {
  const uschar *name = url;
  while (*url != 0 && *url != '=') url++;
  if (*url == '=')
    {
    int namelen;
    uschar *value;
    namelen = ++url - name;
    value = string_dequote(&url);
    if (isspace(*url))
      {
      if (strncmpic(name, US"USER=", namelen) == 0) user = value;
      else if (strncmpic(name, US"PASS=", namelen) == 0) password = value;
      else if (strncmpic(name, US"SIZE=", namelen) == 0) sizelimit = Uatoi(value);
      else if (strncmpic(name, US"TIME=", namelen) == 0) timelimit = Uatoi(value);
      else if (strncmpic(name, US"CONNECT=", namelen) == 0) tcplimit = Uatoi(value);
      else if (strncmpic(name, US"NETTIME=", namelen) == 0) tcplimit = Uatoi(value);
      else if (strncmpic(name, US"SERVERS=", namelen) == 0) local_servers = value;

      /* Don't know if all LDAP libraries have LDAP_OPT_DEREF */

      #ifdef LDAP_OPT_DEREF
      else if (strncmpic(name, US"DEREFERENCE=", namelen) == 0)
        {
        if (strcmpic(value, US"never") == 0) dereference = LDAP_DEREF_NEVER;
        else if (strcmpic(value, US"searching") == 0)
          dereference = LDAP_DEREF_SEARCHING;
        else if (strcmpic(value, US"finding") == 0)
          dereference = LDAP_DEREF_FINDING;
        if (strcmpic(value, US"always") == 0) dereference = LDAP_DEREF_ALWAYS;
        }
      #else
      else if (strncmpic(name, US"DEREFERENCE=", namelen) == 0)
        {
        *errmsg = string_sprintf("LDAP_OP_DEREF not defined in this LDAP "
          "library - cannot use \"dereference\"");
        DEBUG(D_lookup) debug_printf("%s\n", *errmsg);
        return DEFER;
        }
      #endif

      #ifdef LDAP_OPT_REFERRALS
      else if (strncmpic(name, US"REFERRALS=", namelen) == 0)
        {
        if (strcmpic(value, US"follow") == 0) referrals = LDAP_OPT_ON;
        else if (strcmpic(value, US"nofollow") == 0) referrals = LDAP_OPT_OFF;
        else
          {
          *errmsg = string_sprintf("LDAP option REFERRALS is not \"follow\" "
            "or \"nofollow\"");
          DEBUG(D_lookup) debug_printf("%s\n", *errmsg);
          return DEFER;
          }
        }
      #else
      else if (strncmpic(name, US"REFERRALS=", namelen) == 0)
        {
        *errmsg = string_sprintf("LDAP_OP_REFERRALS not defined in this LDAP "
          "library - cannot use \"referrals\"");
        DEBUG(D_lookup) debug_printf("%s\n", *errmsg);
        return DEFER;
        }
      #endif

      else
        {
        *errmsg =
          string_sprintf("unknown parameter \"%.*s\" precedes LDAP URL",
            namelen, name);
        DEBUG(D_lookup) debug_printf("LDAP query error: %s\n", *errmsg);
        return DEFER;
        }
      while (isspace(*url)) url++;
      continue;
      }
    }
  *errmsg = US"malformed parameter setting precedes LDAP URL";
  DEBUG(D_lookup) debug_printf("LDAP query error: %s\n", *errmsg);
  return DEFER;
  }

/* If user is set, de-URL-quote it. Some LDAP libraries do this for themselves,
but it seems that not all behave like this. The DN for the user is often the
result of ${quote_ldap_dn:...} quoting, which does apply URL quoting, because
that is needed when the DN is used as a base DN in a query. Sigh. This is all
far too complicated. */

if (user != NULL)
  {
  uschar *s;
  uschar *t = user;
  for (s = user; *s != 0; s++)
    {
    int c, d;
    if (*s == '%' && isxdigit(c=s[1]) && isxdigit(d=s[2]))
      {
      c = tolower(c);
      d = tolower(d);
      *t++ =
        (((c >= 'a')? (10 + c - 'a') : c - '0') << 4) |
         ((d >= 'a')? (10 + d - 'a') : d - '0');
      s += 2;
      }
    else *t++ = *s;
    }
  *t = 0;
  }

DEBUG(D_lookup)
  debug_printf("LDAP parameters: user=%s pass=%s size=%d time=%d connect=%d "
    "dereference=%d referrals=%s\n", user, password, sizelimit, timelimit,
    tcplimit, dereference, (referrals == LDAP_OPT_ON)? "on" : "off");

/* If the request is just to check authentication, some credentials must
be given. The password must not be empty because LDAP binds with an empty
password are considered anonymous, and will succeed on most installations. */

if (search_type == SEARCH_LDAP_AUTH)
  {
  if (user == NULL || password == NULL)
    {
    *errmsg = US"ldapauth lookups must specify the username and password";
    return DEFER;
    }
  if (password[0] == 0)
    {
    DEBUG(D_lookup) debug_printf("Empty password: ldapauth returns FAIL\n");
    return FAIL;
    }
  }

/* Check for valid ldap url starters */

p = url + 4;
if (tolower(*p) == 's' || tolower(*p) == 'i') p++;
if (Ustrncmp(p, "://", 3) != 0)
  {
  *errmsg = string_sprintf("LDAP URL does not start with \"ldap://\", "
    "\"ldaps://\", or \"ldapi://\" (it starts with \"%.16s...\")", url);
  DEBUG(D_lookup) debug_printf("LDAP query error: %s\n", *errmsg);
  return DEFER;
  }

/* No default servers, or URL contains a server name: just one attempt */

if ((eldap_default_servers == NULL && local_servers == NULL) || p[3] != '/')
  {
  return perform_ldap_search(url, NULL, 0, search_type, res, errmsg,
    &defer_break, user, password, sizelimit, timelimit, tcplimit, dereference,
    referrals);
  }

/* Loop through the default servers until OK or FAIL. Use local_servers list
 * if defined in the lookup, otherwise use the global default list */
list = (local_servers == NULL) ? eldap_default_servers : local_servers;
while ((server = string_nextinlist(&list, &sep, buffer, sizeof(buffer))) != NULL)
  {
  int rc;
  int port = 0;
  uschar *colon = Ustrchr(server, ':');
  if (colon != NULL)
    {
    *colon = 0;
    port = Uatoi(colon+1);
    }
  rc = perform_ldap_search(url, server, port, search_type, res, errmsg,
    &defer_break, user, password, sizelimit, timelimit, tcplimit, dereference,
    referrals);
  if (rc != DEFER || defer_break) return rc;
  }

return DEFER;
}



/*************************************************
*               Find entry point                 *
*************************************************/

/* See local README for interface description. The different kinds of search
are handled by a common function, with a flag to differentiate between them.
The handle and filename arguments are not used. */

static int
eldap_find(void *handle, uschar *filename, const uschar *ldap_url, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
/* Keep picky compilers happy */
do_cache = do_cache;
return(control_ldap_search(ldap_url, SEARCH_LDAP_SINGLE, result, errmsg));
}

static int
eldapm_find(void *handle, uschar *filename, const uschar *ldap_url, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
/* Keep picky compilers happy */
do_cache = do_cache;
return(control_ldap_search(ldap_url, SEARCH_LDAP_MULTIPLE, result, errmsg));
}

static int
eldapdn_find(void *handle, uschar *filename, const uschar *ldap_url, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
/* Keep picky compilers happy */
do_cache = do_cache;
return(control_ldap_search(ldap_url, SEARCH_LDAP_DN, result, errmsg));
}

int
eldapauth_find(void *handle, uschar *filename, const uschar *ldap_url, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
/* Keep picky compilers happy */
do_cache = do_cache;
return(control_ldap_search(ldap_url, SEARCH_LDAP_AUTH, result, errmsg));
}



/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

static void *
eldap_open(uschar *filename, uschar **errmsg)
{
return (void *)(1);    /* Just return something non-null */
}



/*************************************************
*               Tidy entry point                 *
*************************************************/

/* See local README for interface description.
Make sure that eldap_dn does not refer to reclaimed or worse, freed store */

static void
eldap_tidy(void)
{
LDAP_CONNECTION *lcp = NULL;
eldap_dn = NULL;

while ((lcp = ldap_connections) != NULL)
  {
  DEBUG(D_lookup) debug_printf("unbind LDAP connection to %s:%d\n", lcp->host,
    lcp->port);
  if(lcp->bound == TRUE)
    ldap_unbind(lcp->ld);
  ldap_connections = lcp->next;
  }
}



/*************************************************
*               Quote entry point                *
*************************************************/

/* LDAP quoting is unbelievably messy. For a start, two different levels of
quoting have to be done: LDAP quoting, and URL quoting. The current
specification is the result of a suggestion by Brian Candler. It recognizes
two separate cases:

(1) For text that appears in a search filter, the following escapes are
    required (see RFC 2254):

      *    ->   \2A
      (    ->   \28
      )    ->   \29
      \    ->   \5C
     NULL  ->   \00

    Then the entire filter text must be URL-escaped. This kind of quoting is
    implemented by ${quote_ldap:....}. Note that we can never have a NULL
    in the input string, because that's a terminator.

(2) For a DN that is part of a URL (i.e. the base DN), the characters

      , + " \ < > ;

    must be quoted by backslashing. See RFC 2253. Leading and trailing spaces
    must be escaped, as must a leading #. Then the string must be URL-quoted.
    This type of quoting is implemented by ${quote_ldap_dn:....}.

For URL quoting, the only characters that need not be quoted are the
alphamerics and

  ! $ ' ( ) * + - . _

All the others must be hexified and preceded by %. This includes the
backslashes used for LDAP quoting.

For a DN that is given in the USER parameter for authentication, we need the
same initial quoting as (2) but in this case, the result must NOT be
URL-escaped, because it isn't a URL. The way this is handled is by
de-URL-quoting the text when processing the USER parameter in
control_ldap_search() above. That means that the same quote operator can be
used. This has the additional advantage that spaces in the DN won't cause
parsing problems. For example:

  USER=cn=${quote_ldap_dn:$1},%20dc=example,%20dc=com

should be safe if there are spaces in $1.


Arguments:
  s          the string to be quoted
  opt        additional option text or NULL if none
             only "dn" is recognized

Returns:     the processed string or NULL for a bad option
*/



/* The characters in this string, together with alphanumerics, never need
quoting in any way. */

#define ALWAYS_LITERAL  "!$'-._"

/* The special characters in this string do not need to be URL-quoted. The set
is a bit larger than the general literals. */

#define URL_NONQUOTE    ALWAYS_LITERAL "()*+"

/* The following macros define the characters that are quoted by quote_ldap and
quote_ldap_dn, respectively. */

#define LDAP_QUOTE      "*()\\"
#define LDAP_DN_QUOTE   ",+\"\\<>;"



static uschar *
eldap_quote(uschar *s, uschar *opt)
{
register int c;
int count = 0;
int len = 0;
BOOL dn = FALSE;
uschar *t = s;
uschar *quoted;

/* Test for a DN quotation. */

if (opt != NULL)
  {
  if (Ustrcmp(opt, "dn") != 0) return NULL;    /* No others recognized */
  dn = TRUE;
  }

/* Compute how much extra store we need for the string. This doesn't have to be
exact as long as it isn't an underestimate. The worst case is the addition of 5
extra bytes for a single character. This occurs for certain characters in DNs,
where, for example, < turns into %5C%3C. For simplicity, we just add 5 for each
possibly escaped character. The really fast way would be just to test for
non-alphanumerics, but it is probably better to spot a few others that are
never escaped, because if there are no specials at all, we can avoid copying
the string. */

while ((c = *t++) != 0)
  {
  len++;
  if (!isalnum(c) && Ustrchr(ALWAYS_LITERAL, c) == NULL) count += 5;
  }
if (count == 0) return s;

/* Get sufficient store to hold the quoted string */

t = quoted = store_get(len + count + 1);

/* Handle plain quote_ldap */

if (!dn)
  {
  while ((c = *s++) != 0)
    {
    if (!isalnum(c))
      {
      if (Ustrchr(LDAP_QUOTE, c) != NULL)
        {
        sprintf(CS t, "%%5C%02X", c);        /* e.g. * => %5C2A */
        t += 5;
        continue;
        }
      if (Ustrchr(URL_NONQUOTE, c) == NULL)  /* e.g. ] => %5D */
        {
        sprintf(CS t, "%%%02X", c);
        t += 3;
        continue;
        }
      }
    *t++ = c;                                /* unquoted character */
    }
  }

/* Handle quote_ldap_dn */

else
  {
  uschar *ss = s + len;

  /* Find the last char before any trailing spaces */

  while (ss > s && ss[-1] == ' ') ss--;

  /* Quote leading spaces and sharps */

  for (; s < ss; s++)
    {
    if (*s != ' ' && *s != '#') break;
    sprintf(CS t, "%%5C%%%02X", *s);
    t += 6;
    }

  /* Handle the rest of the string, up to the trailing spaces */

  while (s < ss)
    {
    c = *s++;
    if (!isalnum(c))
      {
      if (Ustrchr(LDAP_DN_QUOTE, c) != NULL)
        {
        Ustrncpy(t, "%5C", 3);               /* insert \ where needed */
        t += 3;                              /* fall through to check URL */
        }
      if (Ustrchr(URL_NONQUOTE, c) == NULL)  /* e.g. ] => %5D */
        {
        sprintf(CS t, "%%%02X", c);
        t += 3;
        continue;
        }
      }
    *t++ = c;    /* unquoted character, or non-URL quoted after %5C */
    }

  /* Handle the trailing spaces */

  while (*ss++ != 0)
    {
    Ustrncpy(t, "%5C%20", 6);
    t += 6;
    }
  }

/* Terminate the new string and return */

*t = 0;
return quoted;
}



/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
ldap_version_report(FILE *f)
{
#ifdef DYNLOOKUP
fprintf(f, "Library version: LDAP: Exim version %s\n", EXIM_VERSION_STR);
#endif
}


static lookup_info ldap_lookup_info = {
  US"ldap",                      /* lookup name */
  lookup_querystyle,             /* query-style lookup */
  eldap_open,                    /* open function */
  NULL,                          /* check function */
  eldap_find,                    /* find function */
  NULL,                          /* no close function */
  eldap_tidy,                    /* tidy function */
  eldap_quote,                   /* quoting function */
  ldap_version_report            /* version reporting */
};

static lookup_info ldapdn_lookup_info = {
  US"ldapdn",                     /* lookup name */
  lookup_querystyle,             /* query-style lookup */
  eldap_open,       /* sic */    /* open function */
  NULL,                          /* check function */
  eldapdn_find,                  /* find function */
  NULL,                          /* no close function */
  eldap_tidy,       /* sic */    /* tidy function */
  eldap_quote,      /* sic */    /* quoting function */
  NULL                           /* no version reporting (redundant) */
};

static lookup_info ldapm_lookup_info = {
  US"ldapm",                     /* lookup name */
  lookup_querystyle,             /* query-style lookup */
  eldap_open,       /* sic */    /* open function */
  NULL,                          /* check function */
  eldapm_find,                   /* find function */
  NULL,                          /* no close function */
  eldap_tidy,       /* sic */    /* tidy function */
  eldap_quote,      /* sic */    /* quoting function */
  NULL                           /* no version reporting (redundant) */
};

#ifdef DYNLOOKUP
#define ldap_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &ldap_lookup_info, &ldapdn_lookup_info, &ldapm_lookup_info };
lookup_module_info ldap_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 3 };

/* End of lookups/ldap.c */
