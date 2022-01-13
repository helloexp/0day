/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Experimental SPF support.
   Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004
   License: GPL
   Copyright (c) The Exim Maintainers 2016
*/

#ifdef SUPPORT_SPF

/* Yes, we do have ns_type. spf.h redefines it if we don't set this. Doh */
#ifndef HAVE_NS_TYPE
# define HAVE_NS_TYPE
#endif
#include <spf2/spf.h>

#include <spf2/spf_dns_resolv.h>
#include <spf2/spf_dns_cache.h>

typedef struct spf_result_id {
  uschar *name;
  int    value;
} spf_result_id;

/* prototypes */
BOOL spf_init(uschar *,uschar *);
int  spf_process(const uschar **, uschar *, int);

#define SPF_PROCESS_NORMAL  0
#define SPF_PROCESS_GUESS   1
#define SPF_PROCESS_FALLBACK    2

#endif
