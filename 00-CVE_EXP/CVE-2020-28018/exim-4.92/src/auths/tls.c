/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* This file provides an Exim authenticator driver for
a server to verify a client SSL certificate
*/


#include "../exim.h"
#include "tls.h"

/* Options specific to the tls authentication mechanism. */

optionlist auth_tls_options[] = {
  { "server_param",     opt_stringptr,
      (void *)(offsetof(auth_tls_options_block, server_param1)) },
  { "server_param1",    opt_stringptr,
      (void *)(offsetof(auth_tls_options_block, server_param1)) },
  { "server_param2",    opt_stringptr,
      (void *)(offsetof(auth_tls_options_block, server_param2)) },
  { "server_param3",    opt_stringptr,
      (void *)(offsetof(auth_tls_options_block, server_param3)) },
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int auth_tls_options_count = nelem(auth_tls_options);

/* Default private options block for the authentication method. */

auth_tls_options_block auth_tls_option_defaults = {
    NULL,	/* server_param1 */
    NULL,	/* server_param2 */
    NULL,	/* server_param3 */
};


#ifdef MACRO_PREDEF

/* Dummy values */
void auth_tls_init(auth_instance *ablock) {}
int auth_tls_server(auth_instance *ablock, uschar *data) {return 0;}
int auth_tls_client(auth_instance *ablock, void * sx,
  int timeout, uschar *buffer, int buffsize) {return 0;}

#else   /*!MACRO_PREDEF*/




/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */

void
auth_tls_init(auth_instance *ablock)
{
ablock->public_name = ablock->name;	/* needed for core code */
}



/*************************************************
*             Server entry point                 *
*************************************************/

/* For interface, see auths/README */

int
auth_tls_server(auth_instance *ablock, uschar *data)
{
auth_tls_options_block * ob = (auth_tls_options_block *)ablock->options_block;

if (ob->server_param1)
  auth_vars[expand_nmax++] = expand_string(ob->server_param1);
if (ob->server_param2)
  auth_vars[expand_nmax++] = expand_string(ob->server_param2);
if (ob->server_param3)
  auth_vars[expand_nmax++] = expand_string(ob->server_param3);
return auth_check_serv_cond(ablock);
}


#endif   /*!MACRO_PREDEF*/
/* End of tls.c */
