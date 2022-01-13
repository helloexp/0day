/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* SRS - Sender rewriting scheme support
  ©2004 Miles Wilton <miles@mirtol.com>
  License: GPL */

#ifndef __SRS_H__

#define __SRS_H__ 1

#ifdef EXPERIMENTAL_SRS

#include "mytypes.h"
#include <srs_alt.h>

int eximsrs_init();
int eximsrs_done();
int eximsrs_forward(uschar **result, uschar *orig_sender, uschar *domain);
int eximsrs_reverse(uschar **result, uschar *address);
int eximsrs_db_set(BOOL reverse, uschar *srs_db);

srs_result eximsrs_db_insert(srs_t *srs, char *data, uint data_len, char *result, uint result_len);
srs_result eximsrs_db_lookup(srs_t *srs, char *data, uint data_len, char *result, uint result_len);

#endif

#endif
