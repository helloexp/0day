/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

/* This file, which provides support for Microsoft's Secure Password
Authentication, was contributed by Marc Prud'hommeaux. */


#include "auth-spa.h"

/* Private structure for the private options. */

typedef struct {
  uschar *spa_username;
  uschar *spa_password;
  uschar *spa_domain;
  uschar *spa_serverpassword;
} auth_spa_options_block;

/* Data for reading the private options. */

extern optionlist auth_spa_options[];
extern int auth_spa_options_count;

/* Block containing default values. */

extern auth_spa_options_block auth_spa_option_defaults;

/* The entry points for the mechanism */

extern void auth_spa_init(auth_instance *);
extern int auth_spa_server(auth_instance *, uschar *);
extern int auth_spa_client(auth_instance *, void *, int, uschar *, int);

/* End of spa.h */
