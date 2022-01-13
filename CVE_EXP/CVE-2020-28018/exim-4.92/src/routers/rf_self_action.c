/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "rf_functions.h"



/*************************************************
*        Decode actions for self reference       *
*************************************************/

/* This function is called from a number of routers on receiving
HOST_FOUND_LOCAL when looking up a supposedly remote host. The action is
controlled by a generic configuration option called "self" on each router,
which can be one of:

   . freeze:                       Log the incident, freeze, and return DEFER

   . defer:                        Log the incident and return DEFER

   . fail:                         Fail the address

   . send:                         Carry on with the delivery regardless -
                                   this makes sense only if the SMTP
                                   listener on this machine is a differently
                                   configured MTA

   . pass:                         The router passes; the address
                                   gets passed to the next router, overriding
                                   the setting of no_more

   . reroute:<new-domain>          Change the domain to the given domain
                                   and return REROUTE so it gets passed back
                                   to the routers.

   . reroute:rewrite:<new-domain>  The same, but headers containing the
                                   old domain get rewritten.

These string values are interpreted earlier on, and passed into this function
as the values of "code" and "rewrite".

Arguments:
  addr       the address being routed
  host       the host that is local, with MX set (or -1 if MX not used)
  code       the action to be taken (one of the self_xxx enums)
  rewrite    TRUE if rewriting headers required for REROUTED
  new        new domain to be used for REROUTED
  addr_new   child chain for REROUTEED

Returns:   DEFER, REROUTED, PASS, FAIL, or OK, according to the value of code.
*/

int
rf_self_action(address_item *addr, host_item *host, int code, BOOL rewrite,
  uschar *new, address_item **addr_new)
{
uschar * msg = host->mx >= 0
  ? US"lowest numbered MX record points to local host"
  : US"remote host address is the local host";

switch (code)
  {
  case self_freeze:

    /* If there is no message id, this is happening during an address
    verification, so give information about the address that is being verified,
    and where it has come from. Otherwise, during message delivery, the normal
    logging for the address will be sufficient. */

    if (message_id[0] == 0)
      if (sender_fullhost)
	log_write(0, LOG_MAIN, "%s: %s (while verifying <%s> from host %s)",
	  msg, addr->domain, addr->address, sender_fullhost);
      else
	log_write(0, LOG_MAIN, "%s: %s (while routing <%s>)", msg,
	  addr->domain, addr->address);
    else
      log_write(0, LOG_MAIN, "%s: %s", msg, addr->domain);

    addr->message = msg;
    addr->special_action = SPECIAL_FREEZE;
    return DEFER;

  case self_defer:
    addr->message = msg;
    return DEFER;

  case self_reroute:
    DEBUG(D_route)
      debug_printf("%s: %s: domain changed to %s\n", msg, addr->domain, new);
    rf_change_domain(addr, new, rewrite, addr_new);
    return REROUTED;

  case self_send:
    DEBUG(D_route)
      debug_printf("%s: %s: configured to try delivery anyway\n", msg, addr->domain);
    return OK;

  case self_pass:    /* This is soft failure; pass to next router */
    DEBUG(D_route)
      debug_printf("%s: %s: passed to next router (self = pass)\n", msg, addr->domain);
    addr->message = msg;
    addr->self_hostname = string_copy(host->name);
    return PASS;

  case self_fail:
    DEBUG(D_route)
      debug_printf("%s: %s: address failed (self = fail)\n", msg, addr->domain);
    addr->message = msg;
    setflag(addr, af_pass_message);
    return FAIL;
  }

return DEFER;   /* paranoia */
}

/* End of rf_self_action.c */
