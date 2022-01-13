/*************************************************
*               Exim Monitor                     *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2012 */
/* See the file NOTICE for conditions of use and distribution. */


#include "em_hdr.h"


/* This module contains functions for displaying text in a
text widget. It is not used for the log widget, because that
is dynamically updated and has special scrolling requirements. */


/* Count of characters displayed */

static int text_count = 0;


/*************************************************
*               Empty the widget                 *
*************************************************/

void text_empty(Widget w)
{
XawTextBlock b;
b.firstPos = 0;
b.ptr = CS &b;
b.format = FMT8BIT;
b.length = 0;
XawTextReplace(w, 0, text_count, &b);
text_count = 0;
XawTextSetInsertionPoint(w, text_count);
}



/*************************************************
*                 Display text                   *
*************************************************/

void text_show(Widget w, uschar *s)
{
XawTextBlock b;
b.firstPos = 0;
b.ptr = CS s;
b.format = FMT8BIT;
b.length = Ustrlen(s);
XawTextReplace(w, text_count, text_count, &b);
text_count += b.length;
XawTextSetInsertionPoint(w, text_count);
}


/*************************************************
*           Display text from format             *
*************************************************/

void text_showf(Widget w, char *s, ...) PRINTF_FUNCTION(2,3);

void text_showf(Widget w, char *s, ...)
{
va_list ap;
uschar buffer[1024];
va_start(ap, s);
vsprintf(CS buffer, s, ap);
va_end(ap);
text_show(w, buffer);
}

/* End of em_text.c */
