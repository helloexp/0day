/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "rf_functions.h"


/*************************************************
*      Set uid/gid from block into address       *
*************************************************/

/* This function copies any set uid or gid from a ugid block into an
address.

Arguments:
  addr        the address
  ugid        the ugid block

Returns:      nothing
*/

void
rf_set_ugid(address_item *addr, ugid_block *ugid)
{
if (ugid->uid_set)
  {
  addr->uid = ugid->uid;
  setflag(addr, af_uid_set);
  }

if (ugid->gid_set)
  {
  addr->gid = ugid->gid;
  setflag(addr, af_gid_set);
  }

if (ugid->initgroups) setflag(addr, af_initgroups);
}

/* End of rf_set_ugid.c */
