/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "rf_functions.h"



/*************************************************
*          Change domain in an address           *
*************************************************/

/* When a router wants to change the address that is being routed, it is like a
redirection. We insert a new parent of the current address to hold the original
information, and change the data in the original address, which is now the
child. The child address is put onto the addr_new chain. Pick up the local part
from the "address" field so as to get it in external form - caseful, and with
any quoting retained.

Arguments:
  addr        the address block
  domain      the new domain
  rewrite     TRUE if headers lines are to be rewritten
  addr_new    the new address chain

Returns:      nothing
*/

void
rf_change_domain(address_item *addr, const uschar *domain, BOOL rewrite,
  address_item **addr_new)
{
address_item *parent = store_get(sizeof(address_item));
uschar *at = Ustrrchr(addr->address, '@');
uschar *address = string_sprintf("%.*s@%s",
  (int)(at - addr->address), addr->address, domain);

DEBUG(D_route) debug_printf("domain changed to %s\n", domain);

/* The current address item is made into the parent, and a new address is set
up in the old space. */

*parent = *addr;

/* First copy in initializing values, to wipe out stuff such as the named
domain cache. Then copy over the propagating fields from the parent. Then set
up the new fields. */

*addr = address_defaults;
addr->prop = parent->prop;

addr->address = address;
addr->unique = string_copy(address);
addr->parent = parent;
parent->child_count = 1;

addr->next = *addr_new;
*addr_new = addr;

/* Rewrite header lines if requested */

if (rewrite)
  {
  header_line *h;
  DEBUG(D_route|D_rewrite) debug_printf("rewriting header lines\n");
  for (h = header_list; h != NULL; h = h->next)
    {
    header_line *newh =
      rewrite_header(h, parent->domain, domain,
        global_rewrite_rules, rewrite_existflags, TRUE);
    if (newh != NULL)
      {
      h = newh;
      f.header_rewritten = TRUE;
      }
    }
  }
}

/* End of rf_change_domain.c */
