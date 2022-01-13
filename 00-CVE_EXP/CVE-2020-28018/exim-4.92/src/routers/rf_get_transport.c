/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "rf_functions.h"


/*************************************************
*       Get transport for a router               *
*************************************************/

/* If transport_name contains $, it must be expanded each time and used as a
transport name. Otherwise, look up the transport only if the destination is not
already set.

Some routers (e.g. accept) insist that their transport option is set at
initialization time. However, for some (e.g. file_transport in redirect), there
is no such check, because the transport may not be required. Calls to this
function from the former type of router have require_name = NULL, because it
will never be used. NULL is also used in verify_only cases, where a transport
is not required.

Arguments:
  tpname        the text of the transport name
  tpptr         where to put the transport
  addr          the address being processed
  router_name   for error messages
  require_name  used in the error message if transport is unset

Returns:        TRUE if *tpptr is already set and tpname has no '$' in it;
                TRUE if a transport has been placed in tpptr;
                FALSE if there's a problem, in which case
                addr->message contains a message, and addr->basic_errno has
                ERRNO_BADTRANSPORT set in it.
*/

BOOL
rf_get_transport(uschar *tpname, transport_instance **tpptr, address_item *addr,
  uschar *router_name, uschar *require_name)
{
uschar *ss;
BOOL expandable;
transport_instance *tp;

if (tpname == NULL)
  {
  if (require_name == NULL) return TRUE;
  addr->basic_errno = ERRNO_BADTRANSPORT;
  addr->message = string_sprintf("%s unset in %s router", require_name,
    router_name);
  return FALSE;
  }

expandable = Ustrchr(tpname, '$') != NULL;
if (*tpptr != NULL && !expandable) return TRUE;

if (expandable)
  {
  ss = expand_string(tpname);
  if (ss == NULL)
    {
    addr->basic_errno = ERRNO_BADTRANSPORT;
    addr->message = string_sprintf("failed to expand transport "
      "\"%s\" in %s router: %s", tpname, router_name, expand_string_message);
    return FALSE;
    }
  }
else ss = tpname;

for (tp = transports; tp != NULL; tp = tp->next)
  {
  if (Ustrcmp(tp->name, ss) == 0)
    {
    DEBUG(D_route) debug_printf("set transport %s\n", ss);
    *tpptr = tp;
    return TRUE;
    }
  }

addr->basic_errno = ERRNO_BADTRANSPORT;
addr->message = string_sprintf("transport \"%s\" not found in %s router", ss,
  router_name);
return FALSE;
}

/* End of rf_get_transport.c */
