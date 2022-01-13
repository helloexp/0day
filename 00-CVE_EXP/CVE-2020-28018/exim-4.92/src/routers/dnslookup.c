/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "rf_functions.h"
#include "dnslookup.h"



/* Options specific to the dnslookup router. */

optionlist dnslookup_router_options[] = {
  { "check_secondary_mx", opt_bool,
      (void *)(offsetof(dnslookup_router_options_block, check_secondary_mx)) },
  { "check_srv",          opt_stringptr,
      (void *)(offsetof(dnslookup_router_options_block, check_srv)) },
  { "fail_defer_domains", opt_stringptr,
      (void *)(offsetof(dnslookup_router_options_block, fail_defer_domains)) },
  { "ipv4_only",          opt_stringptr,
      (void *)(offsetof(dnslookup_router_options_block, ipv4_only)) },
  { "ipv4_prefer",        opt_stringptr,
      (void *)(offsetof(dnslookup_router_options_block, ipv4_prefer)) },
  { "mx_domains",         opt_stringptr,
      (void *)(offsetof(dnslookup_router_options_block, mx_domains)) },
  { "mx_fail_domains",    opt_stringptr,
      (void *)(offsetof(dnslookup_router_options_block, mx_fail_domains)) },
  { "qualify_single",     opt_bool,
      (void *)(offsetof(dnslookup_router_options_block, qualify_single)) },
  { "rewrite_headers",    opt_bool,
      (void *)(offsetof(dnslookup_router_options_block, rewrite_headers)) },
  { "same_domain_copy_routing", opt_bool|opt_public,
      (void *)(offsetof(router_instance, same_domain_copy_routing)) },
  { "search_parents",     opt_bool,
      (void *)(offsetof(dnslookup_router_options_block, search_parents)) },
  { "srv_fail_domains",   opt_stringptr,
      (void *)(offsetof(dnslookup_router_options_block, srv_fail_domains)) },
  { "widen_domains",      opt_stringptr,
      (void *)(offsetof(dnslookup_router_options_block, widen_domains)) }
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int dnslookup_router_options_count =
  sizeof(dnslookup_router_options)/sizeof(optionlist);


#ifdef MACRO_PREDEF

/* Dummy entries */
dnslookup_router_options_block dnslookup_router_option_defaults = {0};
void dnslookup_router_init(router_instance *rblock) {}
int dnslookup_router_entry(router_instance *rblock, address_item *addr,
  struct passwd *pw, int verify, address_item **addr_local,
  address_item **addr_remote, address_item **addr_new,
  address_item **addr_succeed) {return 0;}

#else   /*!MACRO_PREDEF*/




/* Default private options block for the dnslookup router. */

dnslookup_router_options_block dnslookup_router_option_defaults = {
  .check_secondary_mx =	FALSE,
  .qualify_single =	TRUE,
  .search_parents =	FALSE,
  .rewrite_headers =	TRUE,
  .widen_domains =	NULL,
  .mx_domains =		NULL,
  .mx_fail_domains =	NULL,
  .srv_fail_domains =	NULL,
  .check_srv =		NULL,
  .fail_defer_domains =	NULL,
  .ipv4_only =		NULL,
  .ipv4_prefer =	NULL,
};



/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to enable
consistency checks to be done, or anything else that needs to be set up. */

void
dnslookup_router_init(router_instance *rblock)
{
/*
dnslookup_router_options_block *ob =
  (dnslookup_router_options_block *)(rblock->options_block);
*/
rblock = rblock;
}



/*************************************************
*              Main entry point                  *
*************************************************/

/* See local README for interface details. This router returns:

DECLINE
  . the domain does not exist in the DNS
  . MX records point to non-existent hosts (including RHS = IP address)
  . a single SRV record has a host name of "." (=> no service)
  . syntactically invalid mail domain
  . check_secondary_mx set, and local host not in host list

DEFER
  . lookup defer for mx_domains
  . timeout etc on DNS lookup
  . verifying the errors address caused a deferment or a big disaster such
      as an expansion failure (rf_get_errors_address)
  . expanding a headers_{add,remove} string caused a deferment or another
      expansion error (rf_get_munge_headers)
  . a problem in rf_get_transport: no transport when one is needed;
      failed to expand dynamic transport; failed to find dynamic transport
  . failure to expand or find a uid/gid (rf_get_ugid via rf_queue_add)
  . self = "freeze", self = "defer"

PASS
  . timeout etc on DNS lookup and pass_on_timeout set
  . self = "pass"

REROUTED
  . routed to local host, but name was expanded by DNS lookup, so a
      re-routing should take place
  . self = "reroute"

  In both cases the new address will have been set up as a child

FAIL
  . self = "fail"

OK
  added address to addr_local or addr_remote, as appropriate for the
  type of transport; this includes the self="send" case.
*/

int
dnslookup_router_entry(
  router_instance *rblock,        /* data for this instantiation */
  address_item *addr,             /* address we are working on */
  struct passwd *pw,              /* passwd entry after check_local_user */
  int verify,                     /* v_none/v_recipient/v_sender/v_expn */
  address_item **addr_local,      /* add it to this if it's local */
  address_item **addr_remote,     /* add it to this if it's remote */
  address_item **addr_new,        /* put new addresses on here */
  address_item **addr_succeed)    /* put old address here on success */
{
host_item h;
int rc;
int widen_sep = 0;
int whichrrs = HOST_FIND_BY_MX | HOST_FIND_BY_A | HOST_FIND_BY_AAAA;
dnslookup_router_options_block *ob =
  (dnslookup_router_options_block *)(rblock->options_block);
uschar *srv_service = NULL;
uschar *widen = NULL;
const uschar *pre_widen = addr->domain;
const uschar *post_widen = NULL;
const uschar *fully_qualified_name;
const uschar *listptr;
uschar widen_buffer[256];

addr_new = addr_new;          /* Keep picky compilers happy */
addr_succeed = addr_succeed;

DEBUG(D_route)
  debug_printf("%s router called for %s\n  domain = %s\n",
    rblock->name, addr->address, addr->domain);

/* If an SRV check is required, expand the service name */

if (ob->check_srv)
  {
  if (  !(srv_service = expand_string(ob->check_srv))
     && !f.expand_string_forcedfail)
    {
    addr->message = string_sprintf("%s router: failed to expand \"%s\": %s",
      rblock->name, ob->check_srv, expand_string_message);
    return DEFER;
    }
  else whichrrs |= HOST_FIND_BY_SRV;
  }

/* Set up the first of any widening domains. The code further down copes with
either pre- or post-widening, but at present there is no way to turn on
pre-widening, as actually doing so seems like a rather bad idea, and nobody has
requested it. Pre-widening would cause local abbreviated names to take
precedence over global names. For example, if the domain is "xxx.ch" it might
be something in the "ch" toplevel domain, but it also might be xxx.ch.xyz.com.
The choice of pre- or post-widening affects which takes precedence. If ever
somebody comes up with some kind of requirement for pre-widening, presumably
with some conditions under which it is done, it can be selected here.

The rewrite_headers option works only when routing an address at transport
time, because the alterations to the headers are not persistent so must be
worked out immediately before they are used. Sender addresses are routed for
verification purposes, but never at transport time, so any header changes that
you might expect as a result of sender domain widening do not occur. Therefore
we do not perform widening when verifying sender addresses; however, widening
sender addresses is OK if we do not have to rewrite the headers. A corollary
of this is that if the current address is not the original address, then it
does not appear in the message header so it is also OK to widen. The
suppression of widening for sender addresses is silent because it is the
normal desirable behaviour. */

if (  ob->widen_domains
   && (verify != v_sender || !ob->rewrite_headers || addr->parent))
  {
  listptr = ob->widen_domains;
  widen = string_nextinlist(&listptr, &widen_sep, widen_buffer,
    sizeof(widen_buffer));

/****
  if (some condition requiring pre-widening)
    {
    post_widen = pre_widen;
    pre_widen = NULL;
    }
****/
  }

/* Loop to cope with explicit widening of domains as configured. This code
copes with widening that may happen before or after the original name. The
decision as to which is taken above. */

for (;;)
  {
  int flags = whichrrs;
  BOOL removed = FALSE;

  if (pre_widen)
    {
    h.name = pre_widen;
    pre_widen = NULL;
    }
  else if (widen)
    {
    h.name = string_sprintf("%s.%s", addr->domain, widen);
    widen = string_nextinlist(&listptr, &widen_sep, widen_buffer,
      sizeof(widen_buffer));
    DEBUG(D_route) debug_printf("%s router widened %s to %s\n", rblock->name,
      addr->domain, h.name);
    }
  else if (post_widen)
    {
    h.name = post_widen;
    post_widen = NULL;
    DEBUG(D_route) debug_printf("%s router trying %s after widening failed\n",
      rblock->name, h.name);
    }
  else return DECLINE;

  /* Check if we must request only. or prefer, ipv4 */

  if (  ob->ipv4_only
     && expand_check_condition(ob->ipv4_only, rblock->name, US"router"))
    flags = flags & ~HOST_FIND_BY_AAAA | HOST_FIND_IPV4_ONLY;
  else if (f.search_find_defer)
    return DEFER;
  if (  ob->ipv4_prefer
     && expand_check_condition(ob->ipv4_prefer, rblock->name, US"router"))
    flags |= HOST_FIND_IPV4_FIRST;
  else if (f.search_find_defer)
    return DEFER;

  /* Set up the rest of the initial host item. Others may get chained on if
  there is more than one IP address. We set it up here instead of outside the
  loop so as to re-initialize if a previous try succeeded but was rejected
  because of not having an MX record. */

  h.next = NULL;
  h.address = NULL;
  h.port = PORT_NONE;
  h.mx = MX_NONE;
  h.status = hstatus_unknown;
  h.why = hwhy_unknown;
  h.last_try = 0;

  /* Unfortunately, we cannot set the mx_only option in advance, because the
  DNS lookup may extend an unqualified name. Therefore, we must do the test
  stoubsequently. We use the same logic as that for widen_domains above to avoid
  requesting a header rewrite that cannot work. */

  if (verify != v_sender || !ob->rewrite_headers || addr->parent)
    {
    if (ob->qualify_single) flags |= HOST_FIND_QUALIFY_SINGLE;
    if (ob->search_parents) flags |= HOST_FIND_SEARCH_PARENTS;
    }

  rc = host_find_bydns(&h, CUS rblock->ignore_target_hosts, flags,
    srv_service, ob->srv_fail_domains, ob->mx_fail_domains,
    &rblock->dnssec,
    &fully_qualified_name, &removed);

  if (removed) setflag(addr, af_local_host_removed);

  /* If host found with only address records, test for the domain's being in
  the mx_domains list. Note that this applies also to SRV records; the name of
  the option is historical. */

  if ((rc == HOST_FOUND || rc == HOST_FOUND_LOCAL) && h.mx < 0 &&
       ob->mx_domains)
    switch(match_isinlist(fully_qualified_name,
          CUSS &(ob->mx_domains), 0,
          &domainlist_anchor, addr->domain_cache, MCL_DOMAIN, TRUE, NULL))
      {
      case DEFER:
      addr->message = US"lookup defer for mx_domains";
      return DEFER;

      case OK:
      DEBUG(D_route) debug_printf("%s router rejected %s: no MX record(s)\n",
        rblock->name, fully_qualified_name);
      continue;
      }

  /* Deferral returns forthwith, and anything other than failure breaks the
  loop. */

  if (rc == HOST_FIND_SECURITY)
    {
    addr->message = US"host lookup done insecurely";
    return DEFER;
    }
  if (rc == HOST_FIND_AGAIN)
    {
    if (rblock->pass_on_timeout)
      {
      DEBUG(D_route) debug_printf("%s router timed out, and pass_on_timeout is set\n",
        rblock->name);
      return PASS;
      }
    addr->message = US"host lookup did not complete";
    return DEFER;
    }

  if (rc != HOST_FIND_FAILED) break;

  if (ob->fail_defer_domains)
    switch(match_isinlist(fully_qualified_name,
	  CUSS &ob->fail_defer_domains, 0,
	  &domainlist_anchor, addr->domain_cache, MCL_DOMAIN, TRUE, NULL))
      {
      case DEFER:
	addr->message = US"lookup defer for fail_defer_domains option";
	return DEFER;

      case OK:
	DEBUG(D_route) debug_printf("%s router: matched fail_defer_domains\n",
	  rblock->name);
	addr->message = US"missing MX, or all MXs point to missing A records,"
	  " and defer requested";
	return DEFER;
      }
  /* Check to see if the failure is the result of MX records pointing to
  non-existent domains, and if so, set an appropriate error message; the case
  of an MX or SRV record pointing to "." is another special case that we can
  detect. Otherwise "unknown mail domain" is used, which is confusing. Also, in
  this case don't do the widening. We need check only the first host to see if
  its MX has been filled in, but there is no address, because if there were any
  usable addresses returned, we would not have had HOST_FIND_FAILED.

  As a common cause of this problem is MX records with IP addresses on the
  RHS, give a special message in this case. */

  if (h.mx >= 0 && h.address == NULL)
    {
    setflag(addr, af_pass_message);   /* This is not a security risk */
    if (h.name[0] == 0)
      addr->message = US"an MX or SRV record indicated no SMTP service";
    else
      {
      addr->basic_errno = ERRNO_UNKNOWNHOST;
      addr->message = US"all relevant MX records point to non-existent hosts";
      if (!allow_mx_to_ip && string_is_ip_address(h.name, NULL) != 0)
        {
        addr->user_message =
          string_sprintf("It appears that the DNS operator for %s\n"
            "has installed an invalid MX record with an IP address\n"
            "instead of a domain name on the right hand side.", addr->domain);
        addr->message = string_sprintf("%s or (invalidly) to IP addresses",
          addr->message);
        }
      }
    return DECLINE;
    }

  /* If there's a syntax error, do not continue with any widening, and note
  the error. */

  if (f.host_find_failed_syntax)
    {
    addr->message = string_sprintf("mail domain \"%s\" is syntactically "
      "invalid", h.name);
    return DECLINE;
    }
  }

/* If the original domain name has been changed as a result of the host lookup,
set up a child address for rerouting and request header rewrites if so
configured. Then yield REROUTED. However, if the only change is a change of
case in the domain name, which some resolvers yield (others don't), just change
the domain name in the original address so that the official version is used in
RCPT commands. */

if (Ustrcmp(addr->domain, fully_qualified_name) != 0)
  {
  if (strcmpic(addr->domain, fully_qualified_name) == 0)
    {
    uschar *at = Ustrrchr(addr->address, '@');
    memcpy(at+1, fully_qualified_name, Ustrlen(at+1));
    }
  else
    {
    rf_change_domain(addr, fully_qualified_name, ob->rewrite_headers, addr_new);
    return REROUTED;
    }
  }

/* If the yield is HOST_FOUND_LOCAL, the remote domain name either found MX
records with the lowest numbered one pointing to a host with an IP address that
is set on one of the interfaces of this machine, or found A records or got
addresses from gethostbyname() that contain one for this machine. This can
happen quite legitimately if the original name was a shortened form of a
domain, but we will have picked that up already via the name change test above.

Otherwise, the action to be taken can be configured by the self option, the
handling of which is in a separate function, as it is also required for other
routers. */

if (rc == HOST_FOUND_LOCAL)
  {
  rc = rf_self_action(addr, &h, rblock->self_code, rblock->self_rewrite,
    rblock->self, addr_new);
  if (rc != OK) return rc;
  }

/* Otherwise, insist on being a secondary MX if so configured */

else if (ob->check_secondary_mx && !testflag(addr, af_local_host_removed))
  {
  DEBUG(D_route) debug_printf("check_secondary_mx set and local host not secondary\n");
  return DECLINE;
  }

/* Set up the errors address, if any. */

rc = rf_get_errors_address(addr, rblock, verify, &addr->prop.errors_address);
if (rc != OK) return rc;

/* Set up the additional and removable headers for this address. */

rc = rf_get_munge_headers(addr, rblock, &addr->prop.extra_headers,
  &addr->prop.remove_headers);
if (rc != OK) return rc;

/* Get store in which to preserve the original host item, chained on
to the address. */

addr->host_list = store_get(sizeof(host_item));
addr->host_list[0] = h;

/* Fill in the transport and queue the address for delivery. */

if (!rf_get_transport(rblock->transport_name, &(rblock->transport),
      addr, rblock->name, NULL))
  return DEFER;

addr->transport = rblock->transport;

return rf_queue_add(addr, addr_local, addr_remote, rblock, pw)?
  OK : DEFER;
}

#endif   /*!MACRO_PREDEF*/
/* End of routers/dnslookup.c */
/* vi: aw ai sw=2
*/
