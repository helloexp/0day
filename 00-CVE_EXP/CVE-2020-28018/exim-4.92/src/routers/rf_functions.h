/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the functions that are shared by the routers */


extern void rf_add_generated(router_instance *, address_item **,
              address_item *, address_item *, uschar *, header_line *,
              uschar *, ugid_block *, struct passwd *);
extern void rf_change_domain(address_item *, const uschar *, BOOL, address_item **);
extern uschar *rf_expand_data(address_item *, uschar *, int *);
extern int  rf_get_errors_address(address_item *, router_instance *,
              int, uschar **);
extern int  rf_get_munge_headers(address_item *, router_instance *,
              header_line **, uschar **);
extern BOOL rf_get_transport(uschar *, transport_instance **,  address_item *,
              uschar *, uschar *);
extern BOOL rf_get_ugid(router_instance *, address_item *, ugid_block *);
extern int  rf_lookup_hostlist(router_instance *, address_item *, uschar *,
              int, int, address_item **);
extern BOOL rf_queue_add(address_item *, address_item **, address_item **,
              router_instance *, struct passwd *);
extern int  rf_self_action(address_item *, host_item *, int, BOOL, uschar *,
              address_item **);
extern void rf_set_ugid(address_item *, ugid_block *);

/* End of rf_functions.h */
