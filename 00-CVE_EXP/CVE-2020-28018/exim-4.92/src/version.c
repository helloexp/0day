/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* Copyright (c) The Exim Maintainers 2010 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Function for setting up the version string. */

#include "exim.h"

#include "version.h"


/* The header file cnumber.h contains a single line containing the
compilation number, making it easy to have it updated automatically.
Hence the fudgery below to get the number turned into a string, since
we can't use #include inside a macro argument list */

void
version_init(void)
{
static uschar cnumber_buffer[24];
static uschar date_buffer[32];

uschar today[20];
uschar *version_cnumber_format;

int cnumber =
#include "cnumber.h"
;

/* The odd magic after each of these is so they can be easily found
for automatic patching to standard values when running regression tests.
The reason that version_cnumber_format isn't just written inline in the
sprintf() call is the gcc -Wall warns about a \0 in a format string. */

version_cnumber = cnumber_buffer;
version_cnumber_format = US"%d\0<<eximcnumber>>";
sprintf(CS version_cnumber, CS version_cnumber_format, cnumber);
version_string = US EXIM_VERSION_STR "\0<<eximversion>>";

#ifdef EXIM_BUILD_DATE_OVERRIDE
/* Reproducible build support; build tooling should have given us something looking like
 * "25-Feb-2017 20:15:40" in EXIM_BUILD_DATE_OVERRIDE based on $SOURCE_DATE_EPOCH in environ
 * per <https://reproducible-builds.org/specs/source-date-epoch/>
 */
version_date = date_buffer;
version_date[0] = 0;
Ustrncat(version_date, EXIM_BUILD_DATE_OVERRIDE, sizeof(date_buffer));

#else
Ustrcpy(today, __DATE__);
if (today[4] == ' ') today[4] = '0';
today[3] = today[6] = '-';

version_date = date_buffer;
version_date[0] = 0;
Ustrncat(version_date, today+4, 3);
Ustrncat(version_date, today, 4);
Ustrncat(version_date, today+7, 4);
Ustrcat(version_date, " ");
Ustrcat(version_date, __TIME__);
#endif
}

/* End of version.c */
