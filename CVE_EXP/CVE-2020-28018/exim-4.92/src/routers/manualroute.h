/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the manualroute router */

/* Structure for the private options. */

typedef struct {
  int   hai_code;
  int   hff_code;
  BOOL  hosts_randomize;
  uschar *host_all_ignored;
  uschar *host_find_failed;
  uschar *route_data;
  uschar *route_list;
} manualroute_router_options_block;

/* Data for reading the private options. */

extern optionlist manualroute_router_options[];
extern int manualroute_router_options_count;

/* Block containing default values. */

extern manualroute_router_options_block manualroute_router_option_defaults;

/* The main and initialization entry points for the router */

extern int manualroute_router_entry(router_instance *, address_item *,
  struct passwd *, int, address_item **, address_item **,
  address_item **, address_item **);

extern void manualroute_router_init(router_instance *);

/* End of routers/manualroute.h */
