/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Experimental SPF support.
   Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004 - 2014
   License: GPL
   Copyright (c) The Exim Maintainers 2015 - 2018
*/

/* Code for calling spf checks via libspf-alt. Called from acl.c. */

#include "exim.h"
#ifdef SUPPORT_SPF

/* must be kept in numeric order */
static spf_result_id spf_result_id_list[] = {
  /* name		value */
  { US"invalid",	0},
  { US"neutral",	1 },
  { US"pass",		2 },
  { US"fail",		3 },
  { US"softfail",	4 },
  { US"none",		5 },
  { US"temperror",	6 }, /* RFC 4408 defined */
  { US"permerror",	7 }  /* RFC 4408 defined */
};

SPF_server_t    *spf_server = NULL;
SPF_request_t   *spf_request = NULL;
SPF_response_t  *spf_response = NULL;
SPF_response_t  *spf_response_2mx = NULL;


/* spf_init sets up a context that can be re-used for several
   messages on the same SMTP connection (that come from the
   same host with the same HELO string)

Return: Boolean success */

BOOL
spf_init(uschar *spf_helo_domain, uschar *spf_remote_addr)
{
spf_server = SPF_server_new(SPF_DNS_CACHE, 0);

if (!spf_server)
  {
  DEBUG(D_receive) debug_printf("spf: SPF_server_new() failed.\n");
  return FALSE;
  }

if (SPF_server_set_rec_dom(spf_server, CS primary_hostname))
  {
  DEBUG(D_receive) debug_printf("spf: SPF_server_set_rec_dom(\"%s\") failed.\n",
    primary_hostname);
  spf_server = NULL;
  return FALSE;
  }

spf_request = SPF_request_new(spf_server);

if (  SPF_request_set_ipv4_str(spf_request, CS spf_remote_addr)
   && SPF_request_set_ipv6_str(spf_request, CS spf_remote_addr)
   )
  {
  DEBUG(D_receive)
    debug_printf("spf: SPF_request_set_ipv4_str() and "
      "SPF_request_set_ipv6_str() failed [%s]\n", spf_remote_addr);
  spf_server = NULL;
  spf_request = NULL;
  return FALSE;
  }

if (SPF_request_set_helo_dom(spf_request, CS spf_helo_domain))
  {
  DEBUG(D_receive) debug_printf("spf: SPF_set_helo_dom(\"%s\") failed.\n",
    spf_helo_domain);
  spf_server = NULL;
  spf_request = NULL;
  return FALSE;
  }

return TRUE;
}


/* spf_process adds the envelope sender address to the existing
   context (if any), retrieves the result, sets up expansion
   strings and evaluates the condition outcome.

Return: OK/FAIL  */

int
spf_process(const uschar **listptr, uschar *spf_envelope_sender, int action)
{
int sep = 0;
const uschar *list = *listptr;
uschar *spf_result_id;
int rc = SPF_RESULT_PERMERROR;

if (!(spf_server && spf_request))
  /* no global context, assume temp error and skip to evaluation */
  rc = SPF_RESULT_PERMERROR;

else if (SPF_request_set_env_from(spf_request, CS spf_envelope_sender))
  /* Invalid sender address. This should be a real rare occurrence */
  rc = SPF_RESULT_PERMERROR;

else
  {
  /* get SPF result */
  if (action == SPF_PROCESS_FALLBACK)
    {
    SPF_request_query_fallback(spf_request, &spf_response, CS spf_guess);
    spf_result_guessed = TRUE;
    }
  else
    SPF_request_query_mailfrom(spf_request, &spf_response);

  /* set up expansion items */
  spf_header_comment     = US SPF_response_get_header_comment(spf_response);
  spf_received           = US SPF_response_get_received_spf(spf_response);
  spf_result             = US SPF_strresult(SPF_response_result(spf_response));
  spf_smtp_comment       = US SPF_response_get_smtp_comment(spf_response);

  rc = SPF_response_result(spf_response);
  }

/* We got a result. Now see if we should return OK or FAIL for it */
DEBUG(D_acl) debug_printf("SPF result is %s (%d)\n", SPF_strresult(rc), rc);

if (action == SPF_PROCESS_GUESS && (!strcmp (SPF_strresult(rc), "none")))
  return spf_process(listptr, spf_envelope_sender, SPF_PROCESS_FALLBACK);

while ((spf_result_id = string_nextinlist(&list, &sep, NULL, 0)))
  {
  BOOL negate, result;

  if ((negate = spf_result_id[0] == '!'))
    spf_result_id++;

  result = Ustrcmp(spf_result_id, spf_result_id_list[rc].name) == 0;
  if (negate != result) return OK;
  }

/* no match */
return FAIL;
}



gstring *
authres_spf(gstring * g)
{
uschar * s;
if (!spf_result) return g;

g = string_append(g, 2, US";\n\tspf=", spf_result);
if (spf_result_guessed)
  g = string_cat(g, US" (best guess record for domain)");

s = expand_string(US"$sender_address_domain");
return s && *s
  ? string_append(g, 2, US" smtp.mailfrom=", s)
  : string_cat(g, US" smtp.mailfrom=<>");
}


#endif
