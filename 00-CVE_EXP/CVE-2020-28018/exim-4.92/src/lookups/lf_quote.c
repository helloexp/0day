/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "lf_functions.h"


/*************************************************
*   Add string to result, quoting if necessary   *
*************************************************/

/* This function is called by some lookups that create name=value result
strings, to handle the quoting of the data. It adds "name=" to the result,
followed by appropriately quoted data, followed by a single space.

Arguments:
  name           the field name
  value          the data value
  vlength        the data length
  result         the result expanding-string

Returns:         the result pointer (possibly updated)
*/

gstring *
lf_quote(uschar *name, uschar *value, int vlength, gstring * result)
{
result = string_append(result, 2, name, US"=");

/* NULL is handled as an empty string */

if (!value)
  {
  value = US"";
  vlength = 0;
  }

/* Quote the value if it is empty, contains white space, or starts with a quote
character. */

if (value[0] == 0 || Ustrpbrk(value, " \t\n\r") != NULL || value[0] == '\"')
  {
  int j;
  result = string_catn(result, US"\"", 1);
  for (j = 0; j < vlength; j++)
    {
    if (value[j] == '\"' || value[j] == '\\')
      result = string_catn(result, US"\\", 1);
    result = string_catn(result, US value+j, 1);
    }
  result = string_catn(result, US"\"", 1);
  }
else
  result = string_catn(result, US value, vlength);

return string_catn(result, US" ", 1);
}

/* End of lf_quote.c */
