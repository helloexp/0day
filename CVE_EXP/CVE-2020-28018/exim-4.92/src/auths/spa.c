/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* This file, which provides support for Microsoft's Secure Password
Authentication, was contributed by Marc Prud'hommeaux. Tom Kistner added SPA
server support. I (PH) have only modified it in very trivial ways.

References:
  http://www.innovation.ch/java/ntlm.html
  http://www.kuro5hin.org/story/2002/4/28/1436/66154
  http://download.microsoft.com/download/9/5/e/95ef66af-9026-4bb0-a41d-a4f81802d92c/%5bMS-SMTP%5d.pdf

 * It seems that some systems have existing but different definitions of some
 * of the following types. I received a complaint about "int16" causing
 * compilation problems. So I (PH) have renamed them all, to be on the safe
 * side, by adding 'x' on the end. See auths/auth-spa.h.

 * typedef signed short int16;
 * typedef unsigned short uint16;
 * typedef unsigned uint32;
 * typedef unsigned char  uint8;

07-August-2003:  PH: Patched up the code to avoid assert bombouts for stupid
                     input data. Find appropriate comment by grepping for "PH".
16-October-2006: PH: Added a call to auth_check_serv_cond() at the end
05-June-2010:    PP: handle SASL initial response
*/


#include "../exim.h"
#include "spa.h"

/* #define DEBUG_SPA */

#ifdef DEBUG_SPA
#define DSPA(x,y,z)   debug_printf(x,y,z)
#else
#define DSPA(x,y,z)
#endif

/* Options specific to the spa authentication mechanism. */

optionlist auth_spa_options[] = {
  { "client_domain",             opt_stringptr,
      (void *)(offsetof(auth_spa_options_block, spa_domain)) },
  { "client_password",           opt_stringptr,
      (void *)(offsetof(auth_spa_options_block, spa_password)) },
  { "client_username",           opt_stringptr,
      (void *)(offsetof(auth_spa_options_block, spa_username)) },
  { "server_password",           opt_stringptr,
      (void *)(offsetof(auth_spa_options_block, spa_serverpassword)) }
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int auth_spa_options_count =
  sizeof(auth_spa_options)/sizeof(optionlist);

/* Default private options block for the condition authentication method. */

auth_spa_options_block auth_spa_option_defaults = {
  NULL,              /* spa_password */
  NULL,              /* spa_username */
  NULL,              /* spa_domain */
  NULL               /* spa_serverpassword (for server side use) */
};


#ifdef MACRO_PREDEF

/* Dummy values */
void auth_spa_init(auth_instance *ablock) {}
int auth_spa_server(auth_instance *ablock, uschar *data) {return 0;}
int auth_spa_client(auth_instance *ablock, void * sx, int timeout,
    uschar *buffer, int buffsize) {return 0;}

#else   /*!MACRO_PREDEF*/




/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */

void
auth_spa_init(auth_instance *ablock)
{
auth_spa_options_block *ob =
  (auth_spa_options_block *)(ablock->options_block);

/* The public name defaults to the authenticator name */

if (ablock->public_name == NULL) ablock->public_name = ablock->name;

/* Both username and password must be set for a client */

if ((ob->spa_username == NULL) != (ob->spa_password == NULL))
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s authenticator:\n  "
      "one of client_username and client_password cannot be set without "
      "the other", ablock->name);
ablock->client = ob->spa_username != NULL;

/* For a server we have just one option */

ablock->server = ob->spa_serverpassword != NULL;
}



/*************************************************
*             Server entry point                 *
*************************************************/

/* For interface, see auths/README */

#define CVAL(buf,pos) ((US (buf))[pos])
#define PVAL(buf,pos) ((unsigned)CVAL(buf,pos))
#define SVAL(buf,pos) (PVAL(buf,pos)|PVAL(buf,(pos)+1)<<8)
#define IVAL(buf,pos) (SVAL(buf,pos)|SVAL(buf,(pos)+2)<<16)

int
auth_spa_server(auth_instance *ablock, uschar *data)
{
auth_spa_options_block *ob = (auth_spa_options_block *)(ablock->options_block);
uint8x lmRespData[24];
uint8x ntRespData[24];
SPAAuthRequest request;
SPAAuthChallenge challenge;
SPAAuthResponse  response;
SPAAuthResponse  *responseptr = &response;
uschar msgbuf[2048];
uschar *clearpass;

/* send a 334, MS Exchange style, and grab the client's request,
unless we already have it via an initial response. */

if ((*data == '\0') &&
    (auth_get_no64_data(&data, US"NTLM supported") != OK))
  {
  /* something borked */
  return FAIL;
  }

if (spa_base64_to_bits(CS (&request), sizeof(request), CCS (data)) < 0)
  {
  DEBUG(D_auth) debug_printf("auth_spa_server(): bad base64 data in "
  "request: %s\n", data);
  return FAIL;
  }

/* create a challenge and send it back */

spa_build_auth_challenge(&request,&challenge);
spa_bits_to_base64 (msgbuf, (unsigned char*)&challenge,
    spa_request_length(&challenge));

if (auth_get_no64_data(&data, msgbuf) != OK)
  {
  /* something borked */
  return FAIL;
  }

/* dump client response */
if (spa_base64_to_bits(CS (&response), sizeof(response), CCS (data)) < 0)
  {
  DEBUG(D_auth) debug_printf("auth_spa_server(): bad base64 data in "
  "response: %s\n", data);
  return FAIL;
  }

/***************************************************************
PH 07-Aug-2003: The original code here was this:

Ustrcpy(msgbuf, unicodeToString(((char*)responseptr) +
  IVAL(&responseptr->uUser.offset,0),
  SVAL(&responseptr->uUser.len,0)/2) );

However, if the response data is too long, unicodeToString bombs out on
an assertion failure. It uses a 1024 fixed buffer. Bombing out is not a good
idea. It's too messy to try to rework that function to return an error because
it is called from a number of other places in the auth-spa.c module. Instead,
since it is a very small function, I reproduce its code here, with a size check
that causes failure if the size of msgbuf is exceeded. ****/

  {
  int i;
  char *p = ((char*)responseptr) + IVAL(&responseptr->uUser.offset,0);
  int len = SVAL(&responseptr->uUser.len,0)/2;

  if (len + 1 >= sizeof(msgbuf)) return FAIL;
  for (i = 0; i < len; ++i)
    {
    msgbuf[i] = *p & 0x7f;
    p += 2;
    }
  msgbuf[i] = 0;
  }

/***************************************************************/

/* Put the username in $auth1 and $1. The former is now the preferred variable;
the latter is the original variable. These have to be out of stack memory, and
need to be available once known even if not authenticated, for error messages
(server_set_id, which only makes it to authenticated_id if we return OK) */

auth_vars[0] = expand_nstring[1] = string_copy(msgbuf);
expand_nlength[1] = Ustrlen(msgbuf);
expand_nmax = 1;

debug_print_string(ablock->server_debug_string);    /* customized debug */

/* look up password */

clearpass = expand_string(ob->spa_serverpassword);
if (clearpass == NULL)
  {
  if (f.expand_string_forcedfail)
    {
    DEBUG(D_auth) debug_printf("auth_spa_server(): forced failure while "
      "expanding spa_serverpassword\n");
    return FAIL;
    }
  else
    {
    DEBUG(D_auth) debug_printf("auth_spa_server(): error while expanding "
      "spa_serverpassword: %s\n", expand_string_message);
    return DEFER;
    }
  }

/* create local hash copy */

spa_smb_encrypt (clearpass, challenge.challengeData, lmRespData);
spa_smb_nt_encrypt (clearpass, challenge.challengeData, ntRespData);

/* compare NT hash (LM may not be available) */

if (memcmp(ntRespData,
      ((unsigned char*)responseptr)+IVAL(&responseptr->ntResponse.offset,0),
      24) == 0)
  /* success. we have a winner. */
  {
  return auth_check_serv_cond(ablock);
  }

  /* Expand server_condition as an authorization check (PH) */

return FAIL;
}


/*************************************************
*              Client entry point                *
*************************************************/

/* For interface, see auths/README */

int
auth_spa_client(
  auth_instance *ablock,                 /* authenticator block */
  void * sx,				 /* connection */
  int timeout,                           /* command timeout */
  uschar *buffer,                        /* buffer for reading response */
  int buffsize)                          /* size of buffer */
{
auth_spa_options_block *ob =
       (auth_spa_options_block *)(ablock->options_block);
SPAAuthRequest   request;
SPAAuthChallenge challenge;
SPAAuthResponse  response;
char msgbuf[2048];
char *domain = NULL;
char *username, *password;

/* Code added by PH to expand the options */

*buffer = 0;    /* Default no message when cancelled */

if (!(username = CS expand_string(ob->spa_username)))
  {
  if (f.expand_string_forcedfail) return CANCELLED;
  string_format(buffer, buffsize, "expansion of \"%s\" failed in %s "
   "authenticator: %s", ob->spa_username, ablock->name,
   expand_string_message);
  return ERROR;
  }

if (!(password = CS expand_string(ob->spa_password)))
  {
  if (f.expand_string_forcedfail) return CANCELLED;
  string_format(buffer, buffsize, "expansion of \"%s\" failed in %s "
   "authenticator: %s", ob->spa_password, ablock->name,
   expand_string_message);
  return ERROR;
  }

if (ob->spa_domain)
  if (!(domain = CS expand_string(ob->spa_domain)))
    {
    if (f.expand_string_forcedfail) return CANCELLED;
    string_format(buffer, buffsize, "expansion of \"%s\" failed in %s "
		  "authenticator: %s", ob->spa_domain, ablock->name,
		  expand_string_message);
    return ERROR;
    }

/* Original code */

if (smtp_write_command(sx, SCMD_FLUSH, "AUTH %s\r\n", ablock->public_name) < 0)
  return FAIL_SEND;

/* wait for the 3XX OK message */
if (!smtp_read_response(sx, US buffer, buffsize, '3', timeout))
  return FAIL;

DSPA("\n\n%s authenticator: using domain %s\n\n", ablock->name, domain);

spa_build_auth_request (&request, CS username, domain);
spa_bits_to_base64 (US msgbuf, (unsigned char*)&request,
       spa_request_length(&request));

DSPA("\n\n%s authenticator: sending request (%s)\n\n", ablock->name, msgbuf);

/* send the encrypted password */
if (smtp_write_command(sx, SCMD_FLUSH, "%s\r\n", msgbuf) < 0)
  return FAIL_SEND;

/* wait for the auth challenge */
if (!smtp_read_response(sx, US buffer, buffsize, '3', timeout))
  return FAIL;

/* convert the challenge into the challenge struct */
DSPA("\n\n%s authenticator: challenge (%s)\n\n", ablock->name, buffer + 4);
spa_base64_to_bits (CS (&challenge), sizeof(challenge), CCS (buffer + 4));

spa_build_auth_response (&challenge, &response, CS username, CS password);
spa_bits_to_base64 (US msgbuf, (unsigned char*)&response,
       spa_request_length(&response));
DSPA("\n\n%s authenticator: challenge response (%s)\n\n", ablock->name, msgbuf);

/* send the challenge response */
if (smtp_write_command(sx, SCMD_FLUSH, "%s\r\n", msgbuf) < 0)
       return FAIL_SEND;

/* If we receive a success response from the server, authentication
has succeeded. There may be more data to send, but is there any point
in provoking an error here? */

if (smtp_read_response(sx, US buffer, buffsize, '2', timeout))
  return OK;

/* Not a success response. If errno != 0 there is some kind of transmission
error. Otherwise, check the response code in the buffer. If it starts with
'3', more data is expected. */

if (errno != 0 || buffer[0] != '3')
  return FAIL;

return FAIL;
}

#endif   /*!MACRO_PREDEF*/
/* End of spa.c */
