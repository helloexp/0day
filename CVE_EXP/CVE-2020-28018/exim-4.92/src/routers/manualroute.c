/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "rf_functions.h"
#include "manualroute.h"


/* Options specific to the manualroute router. */

optionlist manualroute_router_options[] = {
  { "host_all_ignored", opt_stringptr,
      (void *)(offsetof(manualroute_router_options_block, host_all_ignored)) },
  { "host_find_failed", opt_stringptr,
      (void *)(offsetof(manualroute_router_options_block, host_find_failed)) },
  { "hosts_randomize",  opt_bool,
      (void *)(offsetof(manualroute_router_options_block, hosts_randomize)) },
  { "route_data",       opt_stringptr,
      (void *)(offsetof(manualroute_router_options_block, route_data)) },
  { "route_list",       opt_stringptr,
      (void *)(offsetof(manualroute_router_options_block, route_list)) },
  { "same_domain_copy_routing", opt_bool|opt_public,
      (void *)(offsetof(router_instance, same_domain_copy_routing)) }
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int manualroute_router_options_count =
  sizeof(manualroute_router_options)/sizeof(optionlist);


#ifdef MACRO_PREDEF

/* Dummy entries */
manualroute_router_options_block manualroute_router_option_defaults = {0};
void manualroute_router_init(router_instance *rblock) {}
int manualroute_router_entry(router_instance *rblock, address_item *addr,
  struct passwd *pw, int verify, address_item **addr_local,
  address_item **addr_remote, address_item **addr_new,
  address_item **addr_succeed) {return 0;}

#else   /*!MACRO_PREDEF*/



/* Default private options block for the manualroute router. */

manualroute_router_options_block manualroute_router_option_defaults = {
  -1,           /* host_all_ignored code (unset) */
  -1,           /* host_find_failed code (unset) */
  FALSE,        /* hosts_randomize */
  US"defer",    /* host_all_ignored */
  US"freeze",   /* host_find_failed */
  NULL,         /* route_data */
  NULL          /* route_list */
};


/* Names and values for host_find_failed and host_all_ignored.  */

static uschar *hff_names[] = {
  US"ignore",  /* MUST be first - not valid for host_all_ignored */
  US"decline",
  US"defer",
  US"fail",
  US"freeze",
  US"pass" };

static int hff_codes[] = { hff_ignore, hff_decline, hff_defer, hff_fail,
  hff_freeze, hff_pass };

static int hff_count= sizeof(hff_codes)/sizeof(int);



/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to enable
consistency checks to be done, or anything else that needs to be set up. */

void
manualroute_router_init(router_instance *rblock)
{
manualroute_router_options_block *ob =
  (manualroute_router_options_block *)(rblock->options_block);
int i;

/* Host_find_failed must be a recognized word */

for (i = 0; i < hff_count; i++)
  {
  if (Ustrcmp(ob->host_find_failed, hff_names[i]) == 0)
    {
    ob->hff_code = hff_codes[i];
    break;
    }
  }
if (ob->hff_code < 0)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s router:\n  "
    "unrecognized setting for host_find_failed option", rblock->name);

for (i = 1; i < hff_count; i++)   /* NB starts at 1 to skip "ignore" */
  {
  if (Ustrcmp(ob->host_all_ignored, hff_names[i]) == 0)
    {
    ob->hai_code = hff_codes[i];
    break;
    }
  }
if (ob->hai_code < 0)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s router:\n  "
    "unrecognized setting for host_all_ignored option", rblock->name);

/* One of route_list or route_data must be specified */

if ((ob->route_list == NULL && ob->route_data == NULL) ||
    (ob->route_list != NULL && ob->route_data != NULL))
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s router:\n  "
    "route_list or route_data (but not both) must be specified",
    rblock->name);
}




/*************************************************
*               Parse a route item               *
*************************************************/

/* The format of a route list item is:

  <domain> [<host[list]> [<options>]]

if obtained from route_list. The domain is absent if the string came from
route_data, in which case domain==NULL. The domain and the host list may be
enclosed in quotes.

Arguments:
  s         pointer to route list item
  domain    if not NULL, where to put the domain pointer
  hostlist  where to put the host[list] pointer
  options   where to put the options pointer

Returns:    FALSE if domain expected and string is empty;
            TRUE otherwise
*/

static BOOL
parse_route_item(const uschar *s, const uschar **domain, const uschar **hostlist,
  const uschar **options)
{
while (*s != 0 && isspace(*s)) s++;

if (domain)
  {
  if (!*s) return FALSE;            /* missing data */
  *domain = string_dequote(&s);
  while (*s && isspace(*s)) s++;
  }

*hostlist = string_dequote(&s);
while (*s && isspace(*s)) s++;
*options = s;
return TRUE;
}



/*************************************************
*              Main entry point                  *
*************************************************/

/* The manualroute router provides a manual routing facility (surprise,
surprise). The data that defines the routing can either be set in route_data
(which means it can be found by, for example, looking up the domain in a file),
or a list of domain patterns and their corresponding data can be provided in
route_list. */

/* See local README for interface details. This router returns:

DECLINE
  . no pattern in route_list matched (route_data not set)
  . route_data was an empty string (route_list not set)
  . forced expansion failure in route_data (rf_expand_data)
  . forced expansion of host list
  . host_find_failed = decline

DEFER
  . transport not defined when needed
  . lookup defer in route_list when matching domain pattern
  . non-forced expansion failure in route_data
  . non-forced expansion failure in host list
  . unknown routing option
  . host list missing for remote transport (not verifying)
  . timeout etc on host lookup (pass_on_timeout not set)
  . verifying the errors address caused a deferment or a big disaster such
      as an expansion failure (rf_get_errors_address)
  . expanding a headers_{add,remove} string caused a deferment or another
      expansion error (rf_get_munge_headers)
  . a problem in rf_get_transport: no transport when one is needed;
      failed to expand dynamic transport; failed to find dynamic transport
  . failure to expand or find a uid/gid (rf_get_ugid via rf_queue_add)
  . host_find_failed = freeze or defer
  . self = freeze or defer

PASS
  . timeout etc on host lookup (pass_on_timeout set)
  . host_find_failed = pass
  . self = pass

REROUTED
  . self = reroute

FAIL
  . host_find_failed = fail
  . self = fail

OK
  . added address to addr_local or addr_remote, as appropriate for the
    type of transport; this includes the self="send" case.
*/

int
manualroute_router_entry(
  router_instance *rblock,        /* data for this instantiation */
  address_item *addr,             /* address we are working on */
  struct passwd *pw,              /* passwd entry after check_local_user */
  int verify,                     /* v_none/v_recipient/v_sender/v_expn */
  address_item **addr_local,      /* add it to this if it's local */
  address_item **addr_remote,     /* add it to this if it's remote */
  address_item **addr_new,        /* put new addresses on here */
  address_item **addr_succeed)    /* put old address here on success */
{
int rc, lookup_type;
uschar *route_item = NULL;
const uschar *options = NULL;
const uschar *hostlist = NULL;
const uschar *domain;
uschar *newhostlist;
const uschar *listptr;
manualroute_router_options_block *ob =
  (manualroute_router_options_block *)(rblock->options_block);
transport_instance *transport = NULL;
BOOL individual_transport_set = FALSE;
BOOL randomize = ob->hosts_randomize;

addr_new = addr_new;           /* Keep picky compilers happy */
addr_succeed = addr_succeed;

DEBUG(D_route) debug_printf("%s router called for %s\n  domain = %s\n",
  rblock->name, addr->address, addr->domain);

/* The initialization check ensures that either route_list or route_data is
set. */

if (ob->route_list)
  {
  int sep = -(';');             /* Default is semicolon */
  listptr = ob->route_list;

  while ((route_item = string_nextinlist(&listptr, &sep, NULL, 0)) != NULL)
    {
    int rc;

    DEBUG(D_route) debug_printf("route_item = %s\n", route_item);
    if (!parse_route_item(route_item, &domain, &hostlist, &options))
      continue;     /* Ignore blank items */

    /* Check the current domain; if it matches, break the loop */

    if ((rc = match_isinlist(addr->domain, &domain, UCHAR_MAX+1,
           &domainlist_anchor, NULL, MCL_DOMAIN, TRUE, CUSS &lookup_value)) == OK)
      break;

    /* If there was a problem doing the check, defer */

    if (rc == DEFER)
      {
      addr->message = US"lookup defer in route_list";
      return DEFER;
      }
    }

  if (!route_item) return DECLINE;  /* No pattern in the list matched */
  }

/* Handle a single routing item in route_data. If it expands to an empty
string, decline. */

else
  {
  if (!(route_item = rf_expand_data(addr, ob->route_data, &rc)))
    return rc;
  (void) parse_route_item(route_item, NULL, &hostlist, &options);
  if (!hostlist[0]) return DECLINE;
  }

/* Expand the hostlist item. It may then pointing to an empty string, or to a
single host or a list of hosts; options is pointing to the rest of the
routelist item, which is either empty or contains various option words. */

DEBUG(D_route) debug_printf("original list of hosts = '%s' options = '%s'\n",
  hostlist, options);

newhostlist = expand_string_copy(hostlist);
lookup_value = NULL;                        /* Finished with */
expand_nmax = -1;

/* If the expansion was forced to fail, just decline. Otherwise there is a
configuration problem. */

if (!newhostlist)
  {
  if (f.expand_string_forcedfail) return DECLINE;
  addr->message = string_sprintf("%s router: failed to expand \"%s\": %s",
    rblock->name, hostlist, expand_string_message);
  return DEFER;
  }
else hostlist = newhostlist;

DEBUG(D_route) debug_printf("expanded list of hosts = '%s' options = '%s'\n",
  hostlist, options);

/* Set default lookup type and scan the options */

lookup_type = LK_DEFAULT;

while (*options)
  {
  unsigned n;
  const uschar *s = options;
  while (*options != 0 && !isspace(*options)) options++;
  n = options-s;

  if (Ustrncmp(s, "randomize", n) == 0) randomize = TRUE;
  else if (Ustrncmp(s, "no_randomize", n) == 0) randomize = FALSE;
  else if (Ustrncmp(s, "byname", n) == 0)
    lookup_type = lookup_type & ~(LK_DEFAULT | LK_BYDNS) | LK_BYNAME;
  else if (Ustrncmp(s, "bydns", n) == 0)
    lookup_type = lookup_type & ~(LK_DEFAULT | LK_BYNAME) & LK_BYDNS;
  else if (Ustrncmp(s, "ipv4_prefer", n) == 0) lookup_type |= LK_IPV4_PREFER;
  else if (Ustrncmp(s, "ipv4_only",   n) == 0) lookup_type |= LK_IPV4_ONLY;
  else
    {
    transport_instance *t;
    for (t = transports; t; t = t->next)
      if (Ustrncmp(t->name, s, n) == 0)
        {
        transport = t;
        individual_transport_set = TRUE;
        break;
        }

    if (!t)
      {
      s = string_sprintf("unknown routing option or transport name \"%s\"", s);
      log_write(0, LOG_MAIN, "Error in %s router: %s", rblock->name, s);
      addr->message = string_sprintf("error in router: %s", s);
      return DEFER;
      }
    }

  if (*options)
    {
    options++;
    while (*options != 0 && isspace(*options)) options++;
    }
  }

/* Set up the errors address, if any. */

rc = rf_get_errors_address(addr, rblock, verify, &addr->prop.errors_address);
if (rc != OK) return rc;

/* Set up the additional and removable headers for this address. */

rc = rf_get_munge_headers(addr, rblock, &addr->prop.extra_headers,
  &addr->prop.remove_headers);
if (rc != OK) return rc;

/* If an individual transport is not set, get the transport for this router, if
any. It might be expanded, or it might be unset if this router has verify_only
set. */

if (!individual_transport_set)
  {
  if (!rf_get_transport(rblock->transport_name, &(rblock->transport), addr,
      rblock->name, NULL))
    return DEFER;
  transport = rblock->transport;
  }

/* Deal with the case of a local transport. The host list is passed over as a
single text string that ends up in $host. */

if (transport && transport->info->local)
  {
  if (hostlist[0])
    {
    host_item *h;
    addr->host_list = h = store_get(sizeof(host_item));
    h->name = string_copy(hostlist);
    h->address = NULL;
    h->port = PORT_NONE;
    h->mx = MX_NONE;
    h->status = hstatus_unknown;
    h->why = hwhy_unknown;
    h->last_try = 0;
    h->next = NULL;
    }

  /* There is nothing more to do other than to queue the address for the
  local transport, filling in any uid/gid. This can be done by the common
  rf_queue_add() function. */

  addr->transport = transport;
  return rf_queue_add(addr, addr_local, addr_remote, rblock, pw)?
    OK : DEFER;
  }

/* There is either no transport (verify_only) or a remote transport. A host
list is mandatory in either case, except when verifying, in which case the
address is just accepted. */

if (!hostlist[0])
  {
  if (verify != v_none) goto ROUTED;
  addr->message = string_sprintf("error in %s router: no host(s) specified "
    "for domain %s", rblock->name, addr->domain);
  log_write(0, LOG_MAIN, "%s", addr->message);
  return DEFER;
  }

/* Otherwise we finish the routing here by building a chain of host items
for the list of configured hosts, and then finding their addresses. */

host_build_hostlist(&addr->host_list, hostlist, randomize);
rc = rf_lookup_hostlist(rblock, addr, rblock->ignore_target_hosts, lookup_type,
  ob->hff_code, addr_new);
if (rc != OK) return rc;

/* If host_find_failed is set to "ignore", it is possible for all the hosts to
be ignored, in which case we will end up with an empty host list. What happens
is controlled by host_all_ignored. */

if (!addr->host_list)
  {
  int i;
  DEBUG(D_route) debug_printf("host_find_failed ignored every host\n");
  if (ob->hai_code == hff_decline) return DECLINE;
  if (ob->hai_code == hff_pass) return PASS;

  for (i = 0; i < hff_count; i++)
    if (ob->hai_code == hff_codes[i]) break;

  addr->message = string_sprintf("lookup failed for all hosts in %s router: "
    "host_find_failed=ignore host_all_ignored=%s", rblock->name, hff_names[i]);

  if (ob->hai_code == hff_defer) return DEFER;
  if (ob->hai_code == hff_fail) return FAIL;

  addr->special_action = SPECIAL_FREEZE;
  return DEFER;
  }

/* Finally, since we have done all the routing here, there must be a transport
defined for these hosts. It will be a remote one, as a local transport is
dealt with above. However, we don't need one if verifying only. */

if (transport == NULL && verify == v_none)
    {
    log_write(0, LOG_MAIN, "Error in %s router: no transport defined",
      rblock->name);
    addr->message = US"error in router: transport missing";
    return DEFER;
    }

/* Fill in the transport, queue for remote delivery. The yield of
rf_queue_add() is always TRUE for a remote transport. */

ROUTED:

addr->transport = transport;
(void)rf_queue_add(addr, addr_local, addr_remote, rblock, NULL);
return OK;
}

#endif   /*!MACRO_PREDEF*/
/* End of routers/manualroute.c */
