/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2012 */
/* See the file NOTICE for conditions of use and distribution. */

/* Copyright (c) A L Digital Ltd 2004 */

/* Private structure for the private options. */

typedef struct {
  uschar *server_service;
  uschar *server_hostname;
  uschar *server_realm;
  uschar *server_mech;
} auth_cyrus_sasl_options_block;

/* Data for reading the private options. */

extern optionlist auth_cyrus_sasl_options[];
extern int auth_cyrus_sasl_options_count;

/* Block containing default values. */

extern auth_cyrus_sasl_options_block auth_cyrus_sasl_option_defaults;

/* The entry points for the mechanism */

extern void auth_cyrus_sasl_init(auth_instance *);
extern int auth_cyrus_sasl_server(auth_instance *, uschar *);
extern int auth_cyrus_sasl_client(auth_instance *, void *, int, uschar *, int);
extern void auth_cyrus_sasl_version_report(FILE *f);

/* End of cyrus_sasl.h */
