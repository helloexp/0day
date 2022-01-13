/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "rf_functions.h"


/*************************************************
*        Queue address for transport             *
*************************************************/

/* This function is called to put an address onto the local or remote transport
queue, as appropriate. When the driver is for verifying only, a transport need
not be set, in which case it doesn't actually matter which queue the address
gets put on.

The generic uid/gid options are inspected and put into the address if they are
set. For a remote transport, if there are fallback hosts, they are added to the
address.

Arguments:
  addr          the address, with the transport field set (if not verify only)
  paddr_local   pointer to the anchor of the local transport chain
  paddr_remote  pointer to the anchor of the remote transport chain
  rblock        the router block
  pw            password entry if check_local_user was set, or NULL

Returns:        FALSE on error; the only case is failing to get a uid/gid
*/

BOOL
rf_queue_add(address_item *addr, address_item **paddr_local,
  address_item **paddr_remote, router_instance *rblock, struct passwd *pw)
{
addr->prop.domain_data = deliver_domain_data;         /* Save these values for */
addr->prop.localpart_data = deliver_localpart_data;   /* use in the transport */

/* Handle a local transport */

if (addr->transport && addr->transport->info->local)
  {
  ugid_block ugid;

  /* Default uid/gid and transport-time home directory are from the passwd file
  when check_local_user is set, but can be overridden by explicit settings.
  When getting the home directory out of the password information, set the
  flag that prevents expansion later. */

  if (pw)
    {
    addr->uid = pw->pw_uid;
    addr->gid = pw->pw_gid;
    setflag(addr, af_uid_set);
    setflag(addr, af_gid_set);
    setflag(addr, af_home_expanded);
    addr->home_dir = string_copy(US pw->pw_dir);
    }

  if (!rf_get_ugid(rblock, addr, &ugid)) return FALSE;
  rf_set_ugid(addr, &ugid);

  /* transport_home_directory (in rblock->home_directory) takes priority;
  otherwise use the expanded value of router_home_directory. The flag also
  tells the transport not to re-expand it. */

  if (rblock->home_directory)
    {
    addr->home_dir = rblock->home_directory;
    clearflag(addr, af_home_expanded);
    }
  else if (!addr->home_dir && testflag(addr, af_home_expanded))
    addr->home_dir = deliver_home;

  addr->current_dir = rblock->current_directory;

  addr->next = *paddr_local;
  *paddr_local = addr;
  }

/* For a remote transport, set up the fallback host list, and keep a count of
the total number of addresses routed to remote transports. */

else
  {
  addr->fallback_hosts = rblock->fallback_hostlist;
  addr->next = *paddr_remote;
  *paddr_remote = addr;
  remote_delivery_count++;
  }

DEBUG(D_route)
  {
  debug_printf("queued for %s transport: local_part = %s\ndomain = %s\n"
    "  errors_to=%s\n",
    (addr->transport == NULL)? US"<unset>" : addr->transport->name,
    addr->local_part, addr->domain, addr->prop.errors_address);
  debug_printf("  domain_data=%s localpart_data=%s\n", addr->prop.domain_data,
    addr->prop.localpart_data);
  }

return TRUE;
}

/* End of rf_queue_add.c */
