/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "rf_functions.h"



/*************************************************
*     Look up IP addresses for a set of hosts    *
*************************************************/

/* This function is called by a router to fill in the IP addresses for a set of
hosts that are attached to an address. Each host has its name and MX value set;
and those that need processing have their address fields set NULL. Multihomed
hosts cause additional blocks to be inserted into the chain.

This function also supports pseudo-hosts whose names end with "/MX". In this
case, MX records are looked up for the name, and the list of hosts obtained
replaces the incoming "host". In other words, "x/MX" is shorthand for "those
hosts pointed to by x's MX records".

It is also possible for a port to be specified along with the host name or IP
address. The syntax is to add ":port" on to the end. This doesn't work with
IPv6 addresses, so we allow IP addresses to be enclosed in [] in order to make
this work. The specification of the port must come last, that is, after "/MX"
if that is present.

Arguments:
  rblock               the router block
  addr                 the address being routed
  ignore_target_hosts  list of hosts to ignore
  lookup_type          LK_DEFAULT or LK_BYNAME or LK_BYDNS,
		       plus LK_IPV4_{ONLY,PREFER}
  hff_code             what to do for host find failed
  addr_new             passed to rf_self_action for self=reroute

Returns:               OK
                       DEFER host lookup defer
                       PASS  timeout etc and pass_on_timeout set
                       self_action: PASS, DECLINE, DEFER, FAIL, FREEZE
                       hff_code after host find failed
*/

int
rf_lookup_hostlist(router_instance *rblock, address_item *addr,
  uschar *ignore_target_hosts, int lookup_type, int hff_code,
  address_item **addr_new)
{
BOOL self_send = FALSE;
host_item *h, *next_h, *prev;

/* Look up each host address. A lookup may add additional items into the chain
if there are multiple addresses. Hence the use of next_h to start each cycle of
the loop at the next original host. If any host is identified as being the local
host, omit it and any subsequent hosts - i.e. treat the list like an ordered
list of MX hosts. If the first host is the local host, act according to the
"self" option in the configuration. */

for (prev = NULL, h = addr->host_list; h; h = next_h)
  {
  const uschar *canonical_name;
  int rc, len, port, mx, sort_key;

  next_h = h->next;
  if (h->address) { prev = h; continue; }

  DEBUG(D_route|D_host_lookup)
    debug_printf("finding IP address for %s\n", h->name);

  /* Handle any port setting that may be on the name; it will be removed
  from the end of the name. */

  port = host_item_get_port(h);

  /* Store the previous mx and sort_key values, which were assigned in
  host_build_hostlist and will be overwritten by host_find_bydns. */

  mx = h->mx;
  sort_key = h->sort_key;

  /* If the name ends with "/MX", we interpret it to mean "the list of hosts
  pointed to by MX records with this name", and the MX record values override
  the ordering from host_build_hostlist. */

  len = Ustrlen(h->name);
  if (len > 3 && strcmpic(h->name + len - 3, US"/mx") == 0)
    {
    int whichrrs = lookup_type & LK_IPV4_ONLY
      ? HOST_FIND_BY_MX | HOST_FIND_IPV4_ONLY
      : lookup_type & LK_IPV4_PREFER
      ? HOST_FIND_BY_MX | HOST_FIND_IPV4_FIRST
      : HOST_FIND_BY_MX;

    DEBUG(D_route|D_host_lookup)
      debug_printf("doing DNS MX lookup for %s\n", h->name);

    mx = MX_NONE;
    h->name = string_copyn(h->name, len - 3);
    rc = host_find_bydns(h,
        ignore_target_hosts,
        whichrrs,			/* look only for MX records */
        NULL,				/* SRV service not relevant */
        NULL,				/* failing srv domains not relevant */
        NULL,				/* no special mx failing domains */
        &rblock->dnssec,		/* dnssec request/require */
        NULL,				/* fully_qualified_name */
        NULL);				/* indicate local host removed */
    }

  /* If explicitly configured to look up by name, or if the "host name" is
  actually an IP address, do a byname lookup. */

  else if (lookup_type & LK_BYNAME || string_is_ip_address(h->name, NULL) != 0)
    {
    DEBUG(D_route|D_host_lookup) debug_printf("calling host_find_byname\n");
    rc = host_find_byname(h, ignore_target_hosts, HOST_FIND_QUALIFY_SINGLE,
      &canonical_name, TRUE);
    }

  /* Otherwise, do a DNS lookup. If that yields "host not found", and the
  lookup type is the default (i.e. "bydns" is not explicitly configured),
  follow up with a byname lookup, just in case. */

  else
    {
    BOOL removed;
    int whichrrs = lookup_type & LK_IPV4_ONLY
      ? HOST_FIND_BY_A
      : lookup_type & LK_IPV4_PREFER
      ? HOST_FIND_BY_A | HOST_FIND_BY_AAAA | HOST_FIND_IPV4_FIRST
      : HOST_FIND_BY_A | HOST_FIND_BY_AAAA;

    DEBUG(D_route|D_host_lookup) debug_printf("doing DNS lookup\n");
    switch (rc = host_find_bydns(h, ignore_target_hosts, whichrrs, NULL,
	NULL, NULL,
	&rblock->dnssec,			/* domains for request/require */
	&canonical_name, &removed))
      {
      case HOST_FOUND:
        if (removed) setflag(addr, af_local_host_removed);
	break;
      case HOST_FIND_FAILED:
	if (lookup_type & LK_DEFAULT)
	  {
	  DEBUG(D_route|D_host_lookup)
	    debug_printf("DNS lookup failed: trying getipnodebyname\n");
	  rc = host_find_byname(h, ignore_target_hosts, HOST_FIND_QUALIFY_SINGLE,
	    &canonical_name, TRUE);
	  }
	break;
      }
    }

  /* Temporary failure defers, unless pass_on_timeout is set */

  if (rc == HOST_FIND_SECURITY)
    {
    addr->message = string_sprintf("host lookup for %s done insecurely" , h->name);
    addr->basic_errno = ERRNO_DNSDEFER;
    return DEFER;
    }
  if (rc == HOST_FIND_AGAIN)
    {
    if (rblock->pass_on_timeout)
      {
      DEBUG(D_route)
        debug_printf("%s router timed out and pass_on_timeout set\n",
          rblock->name);
      return PASS;
      }
    addr->message = string_sprintf("host lookup for %s did not complete "
      "(DNS timeout?)", h->name);
    addr->basic_errno = ERRNO_DNSDEFER;
    return DEFER;
    }

  /* Permanent failure is controlled by host_find_failed */

  if (rc == HOST_FIND_FAILED)
    {
    if (hff_code == hff_ignore)
      {
      if (prev == NULL) addr->host_list = next_h; else prev->next = next_h;
      continue;   /* With the next host, leave prev unchanged */
      }

    if (hff_code == hff_pass) return PASS;
    if (hff_code == hff_decline) return DECLINE;

    addr->basic_errno = ERRNO_UNKNOWNHOST;
    addr->message =
      string_sprintf("lookup of host \"%s\" failed in %s router%s",
        h->name, rblock->name,
        f.host_find_failed_syntax? ": syntax error in name" : "");

    if (hff_code == hff_defer) return DEFER;
    if (hff_code == hff_fail) return FAIL;

    addr->special_action = SPECIAL_FREEZE;
    return DEFER;
    }

  /* Deal with the settings that were previously cleared:
  port, mx and sort_key. */

  if (port != PORT_NONE)
    {
    host_item *hh;
    for (hh = h; hh != next_h; hh = hh->next) hh->port = port;
    }

  if (mx != MX_NONE)
    {
    host_item *hh;
    for (hh = h; hh != next_h; hh = hh->next)
      {
      hh->mx = mx;
      hh->sort_key = sort_key;
      }
    }

  /* A local host gets chopped, with its successors, if there are previous
  hosts. Otherwise the self option is used. If it is set to "send", any
  subsequent hosts that are also the local host do NOT get chopped. */

  if (rc == HOST_FOUND_LOCAL && !self_send)
    {
    if (prev)
      {
      DEBUG(D_route)
        {
        debug_printf("Removed from host list:\n");
        for (; h != NULL; h = h->next) debug_printf("  %s\n", h->name);
        }
      prev->next = NULL;
      setflag(addr, af_local_host_removed);
      break;
      }
    rc = rf_self_action(addr, h, rblock->self_code, rblock->self_rewrite,
      rblock->self, addr_new);
    if (rc != OK)
      {
      addr->host_list = NULL;   /* Kill the host list for */
      return rc;                /* anything other than "send" */
      }
    self_send = TRUE;
    }

  /* Ensure that prev is the host before next_h; this will not be h if a lookup
  found multiple addresses or multiple MX records. */

  prev = h;
  while (prev->next != next_h) prev = prev->next;
  }

return OK;
}

/* End of rf_lookup_hostlist.c */
