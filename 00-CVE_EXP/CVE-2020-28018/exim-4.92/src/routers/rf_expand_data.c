/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "rf_functions.h"


/*************************************************
*       Expand data string and handle errors     *
*************************************************/

/* This little function is used by a couple of routers for expanding things. It
just saves repeating this code too many times. It does an expansion, and
chooses a suitable return code on error.

Arguments:
  addr       the address that's being routed
  s          the string to be expanded
  prc        pointer to where to put the return code on failure

Returns:     the expanded string, or NULL (with prc set) on failure
*/

uschar *
rf_expand_data(address_item *addr, uschar *s, int *prc)
{
uschar *yield = expand_string(s);
if (yield != NULL) return yield;
if (f.expand_string_forcedfail)
  {
  DEBUG(D_route) debug_printf("forced failure for expansion of \"%s\"\n", s);
  *prc = DECLINE;
  }
else
  {
  addr->message = string_sprintf("failed to expand \"%s\": %s", s,
    expand_string_message);
  *prc = DEFER;
  }
return NULL;
}

/* End of routers/rf_expand_data.c */
