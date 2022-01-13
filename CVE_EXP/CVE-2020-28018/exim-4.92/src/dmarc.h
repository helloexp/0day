/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Experimental DMARC support.
   Copyright (c) Todd Lyons <tlyons@exim.org> 2012 - 2014
   License: GPL */

/* Portions Copyright (c) 2012, 2013, The Trusted Domain Project;
   All rights reserved, licensed for use per LICENSE.opendmarc. */

#ifdef EXPERIMENTAL_DMARC

# include "opendmarc/dmarc.h"
# ifdef SUPPORT_SPF
#  include "spf2/spf.h"
# endif /* SUPPORT_SPF */

/* prototypes */
int dmarc_init();
int dmarc_store_data(header_line *);
int dmarc_process();
uschar *dmarc_exim_expand_query(int);
uschar *dmarc_exim_expand_defaults(int);
uschar *dmarc_auth_results_header(header_line *,uschar *);
static int dmarc_write_history_file();

#define DMARC_AR_HEADER        US"Authentication-Results:"
#define DMARC_VERIFY_STATUS    1

#define DMARC_HIST_OK          1
#define DMARC_HIST_DISABLED    2
#define DMARC_HIST_EMPTY       3
#define DMARC_HIST_FILE_ERR    4
#define DMARC_HIST_WRITE_ERR   5

/* From opendmarc.c */
#define DMARC_RESULT_REJECT     0
#define DMARC_RESULT_DISCARD    1
#define DMARC_RESULT_ACCEPT     2
#define DMARC_RESULT_TEMPFAIL   3
#define DMARC_RESULT_QUARANTINE 4

/* From opendmarc-ar.h */
/* ARES_RESULT_T -- type for specifying an authentication result */
#define ARES_RESULT_UNDEFINED   (-1)
#define ARES_RESULT_PASS    0
#define ARES_RESULT_UNUSED  1
#define ARES_RESULT_SOFTFAIL    2
#define ARES_RESULT_NEUTRAL 3
#define ARES_RESULT_TEMPERROR   4
#define ARES_RESULT_PERMERROR   5
#define ARES_RESULT_NONE    6
#define ARES_RESULT_FAIL    7
#define ARES_RESULT_POLICY  8
#define ARES_RESULT_NXDOMAIN    9
#define ARES_RESULT_SIGNED  10
#define ARES_RESULT_UNKNOWN 11
#define ARES_RESULT_DISCARD 12

#endif /* EXPERIMENTAL_DMARC */
