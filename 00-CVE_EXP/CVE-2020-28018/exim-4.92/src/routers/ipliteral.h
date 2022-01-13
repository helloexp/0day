/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */


/* Private structure for the private options. Some compilers do not like empty
structures - the Standard, alas, says "undefined behaviour" for an empty
structure - so we have to put in a dummy value. */

typedef struct {
  int dummy;
} ipliteral_router_options_block;

/* Data for reading the private options. */

extern optionlist ipliteral_router_options[];
extern int ipliteral_router_options_count;

/* Block containing default values. */

extern ipliteral_router_options_block ipliteral_router_option_defaults;

/* The main and initialization entry points for the router */

extern int ipliteral_router_entry(router_instance *, address_item *,
  struct passwd *, int, address_item **, address_item **,
  address_item **, address_item **);

extern void ipliteral_router_init(router_instance *);

/* End of routers/ipliteral.h */
