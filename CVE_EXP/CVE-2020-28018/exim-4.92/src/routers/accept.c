/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "rf_functions.h"
#include "accept.h"


/* Options specific to the accept router. Because some compilers do not like
empty declarations ("undefined" in the Standard) we put in a dummy value. */

optionlist accept_router_options[] = {
  { "", opt_hidden, NULL }
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int accept_router_options_count =
  sizeof(accept_router_options)/sizeof(optionlist);

/* Default private options block for the accept router. Again, a dummy
value is used. */

accept_router_options_block accept_router_option_defaults = {
  NULL        /* dummy */
};


#ifdef MACRO_PREDEF

/* Dummy entries */
void accept_router_init(router_instance *rblock) {}
int accept_router_entry(router_instance *rblock, address_item *addr,
  struct passwd *pw, int verify, address_item **addr_local,
  address_item **addr_remote, address_item **addr_new,
  address_item **addr_succeed) {return 0;}

#else	/*!MACRO_PREDEF*/



/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to enable
consistency checks to be done, or anything else that needs to be set up. */

void accept_router_init(router_instance *rblock)
{
/*
accept_router_options_block *ob =
  (accept_router_options_block *)(rblock->options_block);
*/

/* By default, log deliveries via this router as local deliveries. We can't
just leave it as TRUE_UNSET, because the global default is FALSE. */

if (rblock->log_as_local == TRUE_UNSET) rblock->log_as_local = TRUE;
}



/*************************************************
*              Main entry point                  *
*************************************************/

/* See local README for interface description. This router returns:

DEFER
  . verifying the errors address caused a deferment or a big disaster such
      as an expansion failure (rf_get_errors_address)
  . expanding a headers_{add,remove} string caused a deferment or another
      expansion error (rf_get_munge_headers)
  . a problem in rf_get_transport: no transport when one is needed;
    failed to expand dynamic transport; failed to find dynamic transport
  . failure to expand or find a uid/gid (rf_get_ugid via rf_queue_add)

OK
  added address to addr_local or addr_remote, as appropriate for the
  type of transport
*/

int accept_router_entry(
  router_instance *rblock,        /* data for this instantiation */
  address_item *addr,             /* address we are working on */
  struct passwd *pw,              /* passwd entry after check_local_user */
  int verify,                     /* v_none/v_recipient/v_sender/v_expn */
  address_item **addr_local,      /* add it to this if it's local */
  address_item **addr_remote,     /* add it to this if it's remote */
  address_item **addr_new,        /* put new addresses on here */
  address_item **addr_succeed)    /* put old address here on success */
{
/*
accept_router_options_block *ob =
  (accept_router_options_block *)(rblock->options_block);
*/
int rc;
uschar *errors_to;
uschar *remove_headers;
header_line *extra_headers;

addr_new = addr_new;  /* Keep picky compilers happy */
addr_succeed = addr_succeed;

DEBUG(D_route) debug_printf("%s router called for %s\n  domain = %s\n",
  rblock->name, addr->address, addr->domain);

/* Set up the errors address, if any. */

rc = rf_get_errors_address(addr, rblock, verify, &errors_to);
if (rc != OK) return rc;

/* Set up the additional and removable headers for the address. */

rc = rf_get_munge_headers(addr, rblock, &extra_headers, &remove_headers);
if (rc != OK) return rc;

/* Set the transport and accept the address; update its errors address and
header munging. Initialization ensures that there is a transport except when
verifying. */

if (!rf_get_transport(rblock->transport_name, &(rblock->transport),
  addr, rblock->name, NULL)) return DEFER;

addr->transport = rblock->transport;
addr->prop.errors_address = errors_to;
addr->prop.extra_headers = extra_headers;
addr->prop.remove_headers = remove_headers;

return rf_queue_add(addr, addr_local, addr_remote, rblock, pw)? OK : DEFER;
}

#endif	/*!MACRO_PREDEF*/
/* End of routers/accept.c */
