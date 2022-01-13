/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

/* Private structure for the private options. */

typedef struct {
  uschar *server_secret;
  uschar *client_secret;
  uschar *client_name;
} auth_cram_md5_options_block;

/* Data for reading the private options. */

extern optionlist auth_cram_md5_options[];
extern int auth_cram_md5_options_count;

/* Block containing default values. */

extern auth_cram_md5_options_block auth_cram_md5_option_defaults;

/* The entry points for the mechanism */

extern void auth_cram_md5_init(auth_instance *);
extern int auth_cram_md5_server(auth_instance *, uschar *);
extern int auth_cram_md5_client(auth_instance *, void *, int, uschar *, int);

/* End of cram_md5.h */
