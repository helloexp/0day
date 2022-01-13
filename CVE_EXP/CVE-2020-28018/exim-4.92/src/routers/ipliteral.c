/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "rf_functions.h"
#include "ipliteral.h"


/* Options specific to the ipliteral router. Because some compilers do not like
empty declarations ("undefined" in the Standard) we put in a dummy value. */

optionlist ipliteral_router_options[] = {
  { "", opt_hidden, NULL }
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int ipliteral_router_options_count =
  sizeof(ipliteral_router_options)/sizeof(optionlist);

/* Default private options block for the ipliteral router. Again, a dummy
value is present to keep some compilers happy. */

ipliteral_router_options_block ipliteral_router_option_defaults = { 0 };


#ifdef MACRO_PREDEF

/* Dummy entries */
void ipliteral_router_init(router_instance *rblock) {}
int ipliteral_router_entry(router_instance *rblock, address_item *addr,
  struct passwd *pw, int verify, address_item **addr_local,
  address_item **addr_remote, address_item **addr_new,
  address_item **addr_succeed) {return 0;}

#else   /*!MACRO_PREDEF*/


/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to enable
consistency checks to be done, or anything else that needs to be set up. */

void
ipliteral_router_init(router_instance *rblock)
{
/*
ipliteral_router_options_block *ob =
  (ipliteral_router_options_block *)(rblock->options_block);
*/
rblock = rblock;
}



/*************************************************
*              Main entry point                  *
*************************************************/

/* See local README for interface details. This router returns:

DECLINE
  . the domain is not in the form of an IP literal

DEFER
  . verifying the errors address caused a deferment or a big disaster such
      as an expansion failure (rf_get_errors_address)
  . expanding a headers_{add,remove} string caused a deferment or another
      expansion error (rf_get_munge_headers)
  . a problem in rf_get_transport: no transport when one is needed;
      failed to expand dynamic transport; failed to find dynamic transport
  . failure to expand or find a uid/gid (rf_get_ugid via rf_queue_add)
  . self = "freeze", self = "defer"

PASS
  . self = "pass"

REROUTED
  . self = "reroute"

FAIL
  . self = "fail"

OK
  added address to addr_local or addr_remote, as appropriate for the
  type of transport; this includes the self="send" case.
*/

int
ipliteral_router_entry(
  router_instance *rblock,        /* data for this instantiation */
  address_item *addr,             /* address we are working on */
  struct passwd *pw,              /* passwd entry after check_local_user */
  int verify,                     /* v_none/v_recipient/v_sender/v_expn */
  address_item **addr_local,      /* add it to this if it's local */
  address_item **addr_remote,     /* add it to this if it's remote */
  address_item **addr_new,        /* put new addresses on here */
  address_item **addr_succeed)    /* put old address here on success */
{
/*
ipliteral_router_options_block *ob =
  (ipliteral_router_options_block *)(rblock->options_block);
*/
host_item *h;
const uschar *domain = addr->domain;
const uschar *ip;
int len = Ustrlen(domain);
int rc, ipv;

addr_new = addr_new;         /* Keep picky compilers happy */
addr_succeed = addr_succeed;

DEBUG(D_route) debug_printf("%s router called for %s: domain = %s\n",
  rblock->name, addr->address, addr->domain);

/* Check that the domain is an IP address enclosed in square brackets. Remember
to allow for the "official" form of IPv6 addresses. If not, the router
declines. Otherwise route to the single IP address, setting the host name to
"(unnamed)". */

if (domain[0] != '[' || domain[len-1] != ']') return DECLINE;
ip = string_copyn(domain+1, len-2);
if (strncmpic(ip, US"IPV6:", 5) == 0 || strncmpic(ip, US"IPV4:", 5) == 0)
  ip += 5;

ipv = string_is_ip_address(ip, NULL);
if (ipv == 0 || (disable_ipv6 && ipv == 6))
  return DECLINE;

/* It seems unlikely that ignore_target_hosts will be used with this router,
but if it is set, it should probably work. */

if (verify_check_this_host(CUSS&rblock->ignore_target_hosts,
       	NULL, domain, ip, NULL) == OK)
  {
  DEBUG(D_route)
      debug_printf("%s is in ignore_target_hosts\n", ip);
  addr->message = US"IP literal host explicitly ignored";
  return DECLINE;
  }

/* Set up a host item */

h = store_get(sizeof(host_item));

h->next = NULL;
h->address = string_copy(ip);
h->port = PORT_NONE;
h->name = domain;
h->mx = MX_NONE;
h->status = hstatus_unknown;
h->why = hwhy_unknown;
h->last_try = 0;

/* Determine whether the host is the local host, and if so, take action
according to the configuration. */

if (host_scan_for_local_hosts(h, &h, NULL) == HOST_FOUND_LOCAL)
  {
  int rc = rf_self_action(addr, h, rblock->self_code, rblock->self_rewrite,
    rblock->self, addr_new);
  if (rc != OK) return rc;
  }

/* Address is routed to this host */

addr->host_list = h;

/* Set up the errors address, if any. */

rc = rf_get_errors_address(addr, rblock, verify, &addr->prop.errors_address);
if (rc != OK) return rc;

/* Set up the additional and removable headers for this address. */

rc = rf_get_munge_headers(addr, rblock, &addr->prop.extra_headers,
  &addr->prop.remove_headers);
if (rc != OK) return rc;

/* Fill in the transport, queue the address for local or remote delivery, and
yield success. For local delivery, of course, the IP address won't be used. If
just verifying, there need not be a transport, in which case it doesn't matter
which queue we put the address on. This is all now handled by the route_queue()
function. */

if (!rf_get_transport(rblock->transport_name, &(rblock->transport),
      addr, rblock->name, NULL))
  return DEFER;

addr->transport = rblock->transport;

return rf_queue_add(addr, addr_local, addr_remote, rblock, pw)?
  OK : DEFER;
}

#endif   /*!MACRO_PREDEF*/
/* End of routers/ipliteral.c */
