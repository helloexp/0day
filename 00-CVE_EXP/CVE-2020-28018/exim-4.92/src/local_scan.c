/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */


/******************************************************************************
This file contains a template local_scan() function that just returns ACCEPT.
If you want to implement your own version, you should copy this file to, say
Local/local_scan.c, and edit the copy. To use your version instead of the
default, you must set

HAVE_LOCAL_SCAN=yes
LOCAL_SCAN_SOURCE=Local/local_scan.c

in your Local/Makefile. This makes it easy to copy your version for use with
subsequent Exim releases.

For a full description of the API to this function, see the Exim specification.
******************************************************************************/


/* This is the only Exim header that you should include. The effect of
including any other Exim header is not defined, and may change from release to
release. Use only the documented interface! */

#include "local_scan.h"


/* This is a "do-nothing" version of a local_scan() function. The arguments
are:

  fd             The file descriptor of the open -D file, which contains the
                   body of the message. The file is open for reading and
                   writing, but modifying it is dangerous and not recommended.

  return_text    A pointer to an unsigned char* variable which you can set in
                   order to return a text string. It is initialized to NULL.

The return values of this function are:

  LOCAL_SCAN_ACCEPT
                 The message is to be accepted. The return_text argument is
                   saved in $local_scan_data.

  LOCAL_SCAN_REJECT
                 The message is to be rejected. The returned text is used
                   in the rejection message.

  LOCAL_SCAN_TEMPREJECT
                 This specifies a temporary rejection. The returned text
                   is used in the rejection message.
*/

int
local_scan(int fd, uschar **return_text)
{
fd = fd;                      /* Keep picky compilers happy */
return_text = return_text;
return LOCAL_SCAN_ACCEPT;
}

/* End of local_scan.c */
