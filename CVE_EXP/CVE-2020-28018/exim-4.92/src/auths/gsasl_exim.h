/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2012 */
/* See the file NOTICE for conditions of use and distribution. */

/* Copyright (c) Twitter Inc 2012 */

/* Interface to GNU SASL library for generic authentication. */

/* Authenticator-specific options. */

typedef struct {
  uschar *server_service;
  uschar *server_hostname;
  uschar *server_realm;
  uschar *server_mech;
  uschar *server_password;
  uschar *server_scram_iter;
  uschar *server_scram_salt;
  BOOL    server_channelbinding;
} auth_gsasl_options_block;

/* Data for reading the authenticator-specific options. */

extern optionlist auth_gsasl_options[];
extern int auth_gsasl_options_count;

/* Defaults for the authenticator-specific options. */

extern auth_gsasl_options_block auth_gsasl_option_defaults;

/* The entry points for the mechanism */

extern void auth_gsasl_init(auth_instance *);
extern int auth_gsasl_server(auth_instance *, uschar *);
extern int auth_gsasl_client(auth_instance *, smtp_inblock *,
				int, uschar *, int);
extern void auth_gsasl_version_report(FILE *f);

/* End of gsasl_exim.h */
