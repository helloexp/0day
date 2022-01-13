/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "rf_functions.h"


/*************************************************
*            Get uid/gid for a router            *
*************************************************/

/* This function is called by routers to sort out the uid/gid values which are
passed with an address for use by local transports.

Arguments:
  rblock       the router block
  addr         the address being worked on
  ugid         pointer to a ugid block to fill in

Returns:       TRUE if all goes well, else FALSE
*/

BOOL
rf_get_ugid(router_instance *rblock, address_item *addr, ugid_block *ugid)
{
struct passwd *upw = NULL;

/* Initialize from fixed values */

ugid->uid = rblock->uid;
ugid->gid = rblock->gid;
ugid->uid_set = rblock->uid_set;
ugid->gid_set = rblock->gid_set;
ugid->initgroups = rblock->initgroups;

/* If there is no fixed uid set, see if there's a dynamic one that can
be expanded and possibly looked up. */

if (!ugid->uid_set && rblock->expand_uid != NULL)
  {
  if (route_find_expanded_user(rblock->expand_uid, rblock->name, US"router",
    &upw, &(ugid->uid), &(addr->message))) ugid->uid_set = TRUE;
  else return FALSE;
  }

/* Likewise for the gid */

if (!ugid->gid_set && rblock->expand_gid != NULL)
  {
  if (route_find_expanded_group(rblock->expand_gid, rblock->name, US"router",
    &(ugid->gid), &(addr->message))) ugid->gid_set = TRUE;
  else return FALSE;
  }

/* If a uid is set, then a gid must also be available; use one from the passwd
lookup if it happened. */

if (ugid->uid_set && !ugid->gid_set)
  {
  if (upw != NULL)
    {
    ugid->gid = upw->pw_gid;
    ugid->gid_set = TRUE;
    }
  else
    {
    addr->message = string_sprintf("user set without group for %s router",
      rblock->name);
    return FALSE;
    }
  }

return TRUE;
}

/* End of rf_get_ugid.c */
