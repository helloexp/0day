/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"

/* This module contains functions that call the PAM authentication mechanism
defined by Sun for Solaris and also available for Linux and other OS.

We can't just compile this code and allow the library mechanism to omit the
functions if they are not wanted, because we need to have the PAM headers
available for compiling. Therefore, compile these functions only if SUPPORT_PAM
is defined. However, some compilers don't like compiling empty modules, so keep
them happy with a dummy when skipping the rest. Make it reference itself to
stop picky compilers complaining that it is unused, and put in a dummy argument
to stop even pickier compilers complaining about infinite loops.
Then use a mutually-recursive pair as gcc is just getting stupid. */

#ifndef SUPPORT_PAM
static void dummy(int x);
static void dummy2(int x) { dummy(x-1); }
static void dummy(int x) { dummy2(x-1); }
#else  /* SUPPORT_PAM */

#ifdef PAM_H_IN_PAM
#include <pam/pam_appl.h>
#else
#include <security/pam_appl.h>
#endif

/* According to the specification, it should be possible to have an application
data pointer passed to the conversation function. However, I was unable to get
this to work on Solaris 2.6, so static variables are used instead. */

static int pam_conv_had_error;
static const uschar *pam_args;
static BOOL pam_arg_ended;



/*************************************************
*           PAM conversation function            *
*************************************************/

/* This function is passed to the PAM authentication function, and it calls it
back when it wants data from the client. The string list is in pam_args. When
we reach the end, we pass back an empty string once. If this function is called
again, it will give an error response. This is protection against something
crazy happening.

Arguments:
  num_msg        number of messages associated with the call
  msg            points to an array of length num_msg of pam_message structures
  resp           set to point to the response block, which has to be got by
                   this function
  appdata_ptr    the application data pointer - not used because in Solaris
                   2.6 it always arrived in pam_converse() as NULL

Returns:         a PAM return code
*/

static int
pam_converse (int num_msg, PAM_CONVERSE_ARG2_TYPE **msg,
  struct pam_response **resp, void *appdata_ptr)
{
int i;
int sep = 0;
struct pam_response *reply;

if (pam_arg_ended) return PAM_CONV_ERR;

reply = malloc(sizeof(struct pam_response) * num_msg);

if (reply == NULL) return PAM_CONV_ERR;

for (i = 0; i < num_msg; i++)
  {
  uschar *arg;
  switch (msg[i]->msg_style)
    {
    case PAM_PROMPT_ECHO_ON:
    case PAM_PROMPT_ECHO_OFF:
    arg = string_nextinlist(&pam_args, &sep, big_buffer, big_buffer_size);
    if (arg == NULL)
      {
      arg = US"";
      pam_arg_ended = TRUE;
      }
    reply[i].resp = CS string_copy_malloc(arg); /* PAM frees resp */
    reply[i].resp_retcode = PAM_SUCCESS;
    break;

    case PAM_TEXT_INFO:    /* Just acknowledge messages */
    case PAM_ERROR_MSG:
    reply[i].resp_retcode = PAM_SUCCESS;
    reply[i].resp = NULL;
    break;

    default:  /* Must be an error of some sort... */
    free (reply);
    pam_conv_had_error = TRUE;
    return PAM_CONV_ERR;
    }
  }

*resp = reply;
return PAM_SUCCESS;
}



/*************************************************
*              Perform PAM authentication        *
*************************************************/

/* This function calls the PAM authentication mechanism, passing over one or
more data strings.

Arguments:
  s        a colon-separated list of strings
  errptr   where to point an error message

Returns:   OK if authentication succeeded
           FAIL if authentication failed
           ERROR some other error condition
*/

int
auth_call_pam(const uschar *s, uschar **errptr)
{
pam_handle_t *pamh = NULL;
struct pam_conv pamc;
int pam_error;
int sep = 0;
uschar *user;

/* Set up the input data structure: the address of the conversation function,
and a pointer to application data, which we don't use because I couldn't get it
to work under Solaris 2.6 - it always arrived in pam_converse() as NULL. */

pamc.conv = pam_converse;
pamc.appdata_ptr = NULL;

/* Initialize the static data - the current input data, the error flag, and the
flag for data end. */

pam_args = s;
pam_conv_had_error = FALSE;
pam_arg_ended = FALSE;

/* The first string in the list is the user. If this is an empty string, we
fail. PAM doesn't support authentication with an empty user (it prompts for it,
causing a potential mis-interpretation). */

user = string_nextinlist(&pam_args, &sep, big_buffer, big_buffer_size);
if (user == NULL || user[0] == 0) return FAIL;

/* Start off PAM interaction */

DEBUG(D_auth)
  debug_printf("Running PAM authentication for user \"%s\"\n", user);

pam_error = pam_start ("exim", CS user, &pamc, &pamh);

/* Do the authentication - the pam_authenticate() will call pam_converse() to
get the data it wants. After successful authentication we call pam_acct_mgmt()
to apply any other restrictions (e.g. only some times of day). */

if (pam_error == PAM_SUCCESS)
  {
  pam_error = pam_authenticate (pamh, PAM_SILENT);
  if (pam_error == PAM_SUCCESS && !pam_conv_had_error)
    pam_error = pam_acct_mgmt (pamh, PAM_SILENT);
  }

/* Finish the PAM interaction - this causes it to clean up store etc. Unclear
what should be passed as the second argument. */

pam_end(pamh, PAM_SUCCESS);

/* Sort out the return code. If not success, set the error message. */

if (pam_error == PAM_SUCCESS)
  {
  DEBUG(D_auth) debug_printf("PAM success\n");
  return OK;
  }

*errptr = US pam_strerror(pamh, pam_error);
DEBUG(D_auth) debug_printf("PAM error: %s\n", *errptr);

if (pam_error == PAM_USER_UNKNOWN ||
    pam_error == PAM_AUTH_ERR ||
    pam_error == PAM_ACCT_EXPIRED)
  return FAIL;

return ERROR;
}

#endif  /* SUPPORT_PAM */

/* End of call_pam.c */
