/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* Support functions for calling from local_scan(). These are mostly just
wrappers for various internal functions. */


#include "exim.h"


/*************************************************
*            Match a domain in a list            *
*************************************************/

/*
Arguments:
  domain         the domain we are testing
  list           the domain list

Returns:         OK/FAIL/DEFER
*/

int
lss_match_domain(uschar *domain, uschar *list)
{
return match_isinlist(CUS domain, CUSS &list, 0, &domainlist_anchor, NULL, MCL_DOMAIN,
  TRUE, NULL);
}



/*************************************************
*            Match a local part in a list        *
*************************************************/

/*
Arguments:
  local_part     the local part we are testing
  list           the local part list
  caseless       TRUE for caseless matching

Returns:         OK/FAIL/DEFER
*/

int
lss_match_local_part(uschar *local_part, uschar *list, BOOL caseless)
{
return match_isinlist(CUS local_part, CUSS &list, 0, &localpartlist_anchor, NULL,
  MCL_LOCALPART, caseless, NULL);
}



/*************************************************
*            Match an address in a list          *
*************************************************/

/*
Arguments:
  address        the address we are testing
  list           the address list
  caseless       TRUE for caseless matching

Returns:         OK/FAIL/DEFER
*/

int
lss_match_address(uschar *address, uschar *list, BOOL caseless)
{
return match_address_list(CUS address, caseless, TRUE, CUSS &list, NULL, -1, 0, NULL);
}



/*************************************************
*            Match a host in a list              *
*************************************************/

/*
Arguments:
  host name      the name of the host we are testing, or NULL if this is the
                   sender host and its name hasn't yet been looked up
  host address   the IP address of the host, or an empty string for a local
                   message
  list           the host list

Returns:         OK/FAIL/DEFER
                 ERROR if failed to find host name when needed
*/

int
lss_match_host(uschar *host_name, uschar *host_address, uschar *list)
{
return verify_check_this_host(CUSS &list, NULL, host_name, host_address, NULL);
}



/*************************************************
*           Base 64 encode/decode                *
*************************************************/

/* These functions just give less "internal" names to the functions.

Arguments:
  clear       points to the clear text bytes
  len         the number of bytes to encode

Returns:      a pointer to the zero-terminated base 64 string, which
              is in working store
*/

uschar *
lss_b64encode(uschar *clear, int len)
{
return b64encode(clear, len);
}

/*
Arguments:
  code        points to the coded string, zero-terminated
  ptr         where to put the pointer to the result, which is in
              dynamic store

Returns:      the number of bytes in the result,
              or -1 if the input was malformed

A zero is added on to the end to make it easy in cases where the result is to
be interpreted as text. This is not included in the count. */

int
lss_b64decode(uschar *code, uschar **ptr)
{
return b64decode(code, ptr);
}


/* End of lss.c */
