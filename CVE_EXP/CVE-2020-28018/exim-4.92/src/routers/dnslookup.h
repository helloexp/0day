/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Private structure for the private options. */

typedef struct {
  BOOL check_secondary_mx;
  BOOL qualify_single;
  BOOL search_parents;
  BOOL rewrite_headers;
  uschar *widen_domains;
  uschar *mx_domains;
  uschar *mx_fail_domains;
  uschar *srv_fail_domains;
  uschar *check_srv;
  uschar *fail_defer_domains;
  uschar *ipv4_only;
  uschar *ipv4_prefer;
} dnslookup_router_options_block;

/* Data for reading the private options. */

extern optionlist dnslookup_router_options[];
extern int dnslookup_router_options_count;

/* Block containing default values. */

extern dnslookup_router_options_block dnslookup_router_option_defaults;

/* The main and initialization entry points for the router */

extern int dnslookup_router_entry(router_instance *, address_item *,
  struct passwd *, int, address_item **, address_item **,
  address_item **, address_item **);

extern void dnslookup_router_init(router_instance *);

/* End of routers/dnslookup.h */
