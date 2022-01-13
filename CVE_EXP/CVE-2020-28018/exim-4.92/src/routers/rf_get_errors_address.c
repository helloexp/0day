/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "rf_functions.h"


/*************************************************
*        Get errors address for a router         *
*************************************************/

/* This function is called by routers to sort out the errors address for a
particular address. If there is a setting in the router block, then expand and
verify it, and if it works, use it. Otherwise use any setting that is in the
address itself. This might be NULL, meaning unset (the message's sender is then
used). Verification isn't done when the original address is just being
verified, as otherwise there might be routing loops if someone sets up a silly
configuration.

Arguments:
  addr         the input address
  rblock       the router instance
  verify       v_none / v_recipient / v_sender / v_expn
  errors_to    point the errors address here

Returns:       OK if no problem
               DEFER if verifying the address caused a deferment
                 or a big disaster (e.g. expansion failure)
*/

int
rf_get_errors_address(address_item *addr, router_instance *rblock,
  int verify, uschar **errors_to)
{
uschar *s;

*errors_to = addr->prop.errors_address;
if (rblock->errors_to == NULL) return OK;

s = expand_string(rblock->errors_to);

if (s == NULL)
  {
  if (f.expand_string_forcedfail)
    {
    DEBUG(D_route)
      debug_printf("forced expansion failure - ignoring errors_to\n");
    return OK;
    }
  addr->message = string_sprintf("%s router failed to expand \"%s\": %s",
    rblock->name, rblock->errors_to, expand_string_message);
  return DEFER;
  }

/* If the errors_to address is empty, it means "ignore errors" */

if (*s == 0)
  {
  addr->prop.ignore_error = TRUE;   /* For locally detected errors */
  *errors_to = US"";                   /* Return path for SMTP */
  return OK;
  }

/* If we are already verifying, do not check the errors address, in order to
save effort (but we do verify when testing an address). When we do verify, set
the sender address to null, because that's what it will be when sending an
error message, and there are now configuration options that control the running
of routers by checking the sender address. When testing an address, there may
not be a sender address. We also need to save and restore the expansion values
associated with an address. */

if (verify != v_none)
  {
  *errors_to = s;
  DEBUG(D_route)
    debug_printf("skipped verify errors_to address: already verifying\n");
  }
else
  {
  BOOL save_address_test_mode = f.address_test_mode;
  int save1 = 0;
  int i;
  const uschar ***p;
  const uschar *address_expansions_save[ADDRESS_EXPANSIONS_COUNT];
  address_item *snew = deliver_make_addr(s, FALSE);

  if (sender_address != NULL)
    {
    save1 = sender_address[0];
    sender_address[0] = 0;
    }

  for (i = 0, p = address_expansions; *p != NULL;)
    address_expansions_save[i++] = **p++;
  f.address_test_mode = FALSE;

  /* NOTE: the address is verified as a recipient, not a sender. This is
  perhaps confusing. It isn't immediately obvious what to do: we want to have
  some confidence that we can deliver to the address, in which case it will be
  a recipient, but on the other hand, it will be passed on in SMTP deliveries
  as a sender. However, I think on balance recipient is right because sender
  verification is really about the *incoming* sender of the message.

  If this code is changed, note that you must set vopt_fake_sender instead of
  vopt_is_recipient, as otherwise sender_address may be altered because
  verify_address() thinks it is dealing with *the* sender of the message. */

  DEBUG(D_route|D_verify)
    debug_printf("------ Verifying errors address %s ------\n", s);
  if (verify_address(snew, NULL,
      vopt_is_recipient /* vopt_fake_sender is the alternative */
      | vopt_qualify, -1, -1, -1, NULL, NULL, NULL) == OK)
    *errors_to = snew->address;
  DEBUG(D_route|D_verify)
    debug_printf("------ End verifying errors address %s ------\n", s);

  f.address_test_mode = save_address_test_mode;
  for (i = 0, p = address_expansions; *p != NULL;)
    **p++ = address_expansions_save[i++];

  if (sender_address != NULL) sender_address[0] = save1;
  }

return OK;
}

/* End of rf_get_errors_address.c */
