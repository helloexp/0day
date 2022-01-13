/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */


/* Private structure for the private options. */

typedef struct {
  int   port;
  int   protocol;
  int   timeout;
  uschar *protocol_name;
  uschar *hosts;
  uschar *query;
  uschar *response_pattern;
  uschar *reroute;
  const pcre *re_response_pattern;
  BOOL  optional;
} iplookup_router_options_block;

/* Data for reading the private options. */

extern optionlist iplookup_router_options[];
extern int iplookup_router_options_count;

/* Block containing default values. */

extern iplookup_router_options_block iplookup_router_option_defaults;

/* The main and initialization entry points for the router */

extern int iplookup_router_entry(router_instance *, address_item *,
  struct passwd *, int, address_item **, address_item **,
  address_item **, address_item **);

extern void iplookup_router_init(router_instance *);

/* End of routers/iplookup.h */
