/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/*
 * Exim - SPF lookup module using libspf2
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Copyright (c) 2005 Chris Webb, Arachsys Internet Services Ltd
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * Copyright (c) The Exim Maintainers 2016
 */

#include "../exim.h"

#ifndef SUPPORT_SPF
static void dummy(int x);
static void dummy2(int x) { dummy(x-1); }
static void dummy(int x) { dummy2(x-1); }
#else

#include "lf_functions.h"
#ifndef HAVE_NS_TYPE
#define HAVE_NS_TYPE
#endif
#include <spf2/spf.h>
#include <spf2/spf_dns_resolv.h>
#include <spf2/spf_dns_cache.h>

static void *
spf_open(uschar *filename, uschar **errmsg)
{
  SPF_server_t *spf_server = NULL;
  spf_server = SPF_server_new(SPF_DNS_CACHE, 0);
  if (spf_server == NULL) {
    *errmsg = US"SPF_server_new() failed";
    return NULL;
  }
  return (void *) spf_server;
}

static void
spf_close(void *handle)
{
  SPF_server_t *spf_server = handle;
  if (spf_server) SPF_server_free(spf_server);
}

static int
spf_find(void *handle, uschar *filename, const uschar *keystring, int key_len,
             uschar **result, uschar **errmsg, uint *do_cache)
{
  SPF_server_t *spf_server = handle;
  SPF_request_t *spf_request = NULL;
  SPF_response_t *spf_response = NULL;

  spf_request = SPF_request_new(spf_server);
  if (spf_request == NULL) {
    *errmsg = US"SPF_request_new() failed";
    return FAIL;
  }

  if (SPF_request_set_ipv4_str(spf_request, CS filename)) {
    *errmsg = string_sprintf("invalid IP address '%s'", filename);
    return FAIL;
  }
  if (SPF_request_set_env_from(spf_request, CS keystring)) {
    *errmsg = string_sprintf("invalid envelope from address '%s'", keystring);
    return FAIL;
  }

  SPF_request_query_mailfrom(spf_request, &spf_response);
  *result = string_copy(US SPF_strresult(SPF_response_result(spf_response)));
  SPF_response_free(spf_response);
  SPF_request_free(spf_request);
  return OK;
}


/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
spf_version_report(FILE *f)
{
#ifdef DYNLOOKUP
fprintf(f, "Library version: SPF: Exim version %s\n", EXIM_VERSION_STR);
#endif
}


static lookup_info _lookup_info = {
  US"spf",                       /* lookup name */
  0,                             /* not absfile, not query style */
  spf_open,                      /* open function */
  NULL,                          /* no check function */
  spf_find,                      /* find function */
  spf_close,                     /* close function */
  NULL,                          /* no tidy function */
  NULL,                          /* no quoting function */
  spf_version_report             /* version reporting */
};

#ifdef DYNLOOKUP
#define spf_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info spf_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

#endif /* SUPPORT_SPF */
