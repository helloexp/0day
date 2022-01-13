/*************************************************
*               Exim Monitor                     *
*************************************************/

/* Copyright (c) University of Cambridge, 1995 - 2016 */
/* See the file NOTICE for conditions of use and distribution. */

/* This file contains a number of subroutines that are in effect
just alternative packaging for calls to various X functions that
happen to be convenient for this program. */

#include "em_hdr.h"



/*************************************************
*                  xs_SetValues                  *
*************************************************/

/* Unpick a variable-length argument list and set up an
appropriate call to XtSetValues. To make it reasonably
efficient, we keep a working Arg structure of length 15;
the largest call in eximon sets 11 values. The code uses
malloc/free if more, just in case there is ever a longer
one that gets overlooked. */

static Arg xs_temparg[15];

void xs_SetValues(Widget w, Cardinal num_args, ...)
{
int i;
va_list ap;
Arg *aa = (num_args > 15)? (Arg *)malloc(num_args*sizeof(Arg)) : xs_temparg;
va_start(ap, num_args);
for (i = 0; i < num_args; i++)
  {
  aa[i].name = va_arg(ap, String);
  aa[i].value = va_arg(ap, XtArgVal);
  }
va_end(ap);
XtSetValues(w, aa, num_args);
if (num_args > 15) free(aa);
}

/* End of em_xs.c */
