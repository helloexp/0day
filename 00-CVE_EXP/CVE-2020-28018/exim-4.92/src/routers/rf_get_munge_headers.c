/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "rf_functions.h"


/*************************************************
*      Get additional headers for a router       *
*************************************************/

/* This function is called by routers to sort out the additional headers
and header remove list for a particular address.

Arguments:
  addr           the input address
  rblock         the router instance
  extra_headers  points to where to hang the header chain
  remove_headers points to where to hang the remove list

Returns:         OK if no problem
                 DEFER if expanding a string caused a deferment
                   or a big disaster (e.g. expansion failure)
*/

int
rf_get_munge_headers(address_item *addr, router_instance *rblock,
  header_line **extra_headers, uschar **remove_headers)
{
/* Default is to retain existing headers */
*extra_headers = addr->prop.extra_headers;

if (rblock->extra_headers)
  {
  const uschar * list = rblock->extra_headers;
  int sep = '\n';
  uschar * s;
  int slen;

  while ((s = string_nextinlist(&list, &sep, NULL, 0)))
    if (!(s = expand_string(s)))
      {
      if (!f.expand_string_forcedfail)
	{
	addr->message = string_sprintf(
	  "%s router failed to expand add_headers item \"%s\": %s",
	  rblock->name, s, expand_string_message);
	return DEFER;
	}
      }
    else if ((slen = Ustrlen(s)) > 0)
      {
      /* Expand succeeded. Put extra headers at the start of the chain because
      further down it may point to headers from other routers, which may be
      shared with other addresses. The output function outputs them in reverse
      order. */

      header_line *  h = store_get(sizeof(header_line));

      /* We used to use string_sprintf() to add the newline if needed, but that
      causes problems if the header line is exceedingly long (e.g. adding
      something to a pathologically long line). So avoid it. */

      if (s[slen-1] == '\n')
	h->text = s;
      else
	{
	h->text = store_get(slen+2);
	memcpy(h->text, s, slen);
	h->text[slen++] = '\n';
	h->text[slen] = 0;
	}

      h->next = *extra_headers;
      h->type = htype_other;
      h->slen = slen;
      *extra_headers = h;
      }
  }

/* Default is to retain existing removes */
*remove_headers = addr->prop.remove_headers;

/* Expand items from colon-sep list separately, then build new list */
if (rblock->remove_headers)
  {
  const uschar * list = rblock->remove_headers;
  int sep = ':';
  uschar * s;
  gstring * g = NULL;

  if (*remove_headers)
    g = string_cat(NULL, *remove_headers);

  while ((s = string_nextinlist(&list, &sep, NULL, 0)))
    if (!(s = expand_string(s)))
      {
      if (!f.expand_string_forcedfail)
	{
	addr->message = string_sprintf(
	  "%s router failed to expand remove_headers item \"%s\": %s",
	  rblock->name, s, expand_string_message);
	return DEFER;
	}
      }
    else if (*s)
      g = string_append_listele(g, ':', s);

  if (g)
    *remove_headers = g->s;
  }

return OK;
}

/* vi: aw ai sw=2
*/
/* End of rf_get_munge_headers.c */
