/*************************************************
*                  Exim Monitor                  *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "mytypes.h"
#include "macros.h"
#include <string.h>
#include <stdlib.h>

#include "version.h"

extern uschar *version_string;
extern uschar *version_date;

void
version_init(void)
{
int i = 0;
uschar today[20];

version_string = US"2.06";

#ifdef EXIM_BUILD_DATE_OVERRIDE
/* Reproducible build support; build tooling should have given us something looking like
 * "25-Feb-2017 20:15:40" in EXIM_BUILD_DATE_OVERRIDE based on $SOURCE_DATE_EPOCH in environ
 * per <https://reproducible-builds.org/specs/source-date-epoch/>
 */
version_date = US malloc(32);
version_date[0] = 0;
Ustrncat(version_date, EXIM_BUILD_DATE_OVERRIDE, 31);

#else
Ustrcpy(today, __DATE__);
if (today[4] == ' ') i = 1;
today[3] = today[6] = '-';

version_date = US malloc(32);
version_date[0] = 0;
Ustrncat(version_date, today+4+i, 3-i);
Ustrncat(version_date, today, 4);
Ustrncat(version_date, today+7, 4);
Ustrcat(version_date, " ");
Ustrcat(version_date, __TIME__);
#endif
}

/* End of em_version.c */
