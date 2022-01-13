/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* This module contains interface functions to the two Cyrus authentication
daemons. The original one was "pwcheck", which gives its name to the source
file. This is now deprecated in favour of "saslauthd". */


#include "../exim.h"
#include "pwcheck.h"


/*************************************************
*      External entry point for pwcheck          *
*************************************************/

/* This function calls the now-deprecated "pwcheck" Cyrus-SASL authentication
daemon, passing over a colon-separated user name and password. As this is
called from the string expander, the string will always be in dynamic store and
can be overwritten.

Arguments:
  s        a colon-separated username:password string
  errptr   where to point an error message

Returns:   OK if authentication succeeded
           FAIL if authentication failed
           ERROR some other error condition
*/

int
auth_call_pwcheck(uschar *s, uschar **errptr)
{
uschar *reply = NULL;
uschar *pw = Ustrrchr(s, ':');

if (pw == NULL)
  {
  *errptr = US"pwcheck: malformed input - missing colon";
  return ERROR;
  }

*pw++ = 0;   /* Separate user and password */

DEBUG(D_auth)
  debug_printf("Running pwcheck authentication for user \"%s\"\n", s);

switch (pwcheck_verify_password(CS s, CS pw, (const char **)(&reply)))
  {
  case PWCHECK_OK:
  DEBUG(D_auth) debug_printf("pwcheck: success (%s)\n", reply);
  return OK;

  case PWCHECK_NO:
  DEBUG(D_auth) debug_printf("pwcheck: access denied (%s)\n", reply);
  return FAIL;

  default:
  DEBUG(D_auth) debug_printf("pwcheck: query failed (%s)\n", reply);
  *errptr = reply;
  return ERROR;
  }
}


/*************************************************
*       External entry point for pwauthd         *
*************************************************/

/* This function calls the "saslauthd" Cyrus-SASL authentication daemon,
saslauthd, As this is called from the string expander, all the strings will
always be in dynamic store and can be overwritten.

Arguments:
  username        username
  password        password
  service         optional service
  realm           optional realm
  errptr          where to point an error message

Returns:   OK if authentication succeeded
           FAIL if authentication failed
           ERROR some other error condition
*/

int
auth_call_saslauthd(const uschar *username, const uschar *password,
  const uschar *service, const uschar *realm, uschar **errptr)
{
uschar *reply = NULL;

if (service == NULL) service = US"";
if (realm == NULL) realm = US"";

DEBUG(D_auth)
  debug_printf("Running saslauthd authentication for user \"%s\" \n", username);

switch (saslauthd_verify_password(username, password, service,
        realm, (const uschar **)(&reply)))
  {
  case PWCHECK_OK:
  DEBUG(D_auth) debug_printf("saslauthd: success (%s)\n", reply);
  return OK;

  case PWCHECK_NO:
  DEBUG(D_auth) debug_printf("saslauthd: access denied (%s)\n", reply);
  return FAIL;

  default:
  DEBUG(D_auth) debug_printf("saslauthd: query failed (%s)\n", reply);
  *errptr = reply;
  return ERROR;
  }
}

/* End of call_pwcheck.c */
