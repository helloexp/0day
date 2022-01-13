/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions for interfacing with the DNS. */

#include "exim.h"



/*************************************************
*               Fake DNS resolver                *
*************************************************/

/* This function is called instead of res_search() when Exim is running in its
test harness. It recognizes some special domain names, and uses them to force
failure and retry responses (optionally with a delay). Otherwise, it calls an
external utility that mocks-up a nameserver, if it can find the utility.
If not, it passes its arguments on to res_search(). The fake nameserver may
also return a code specifying that the name should be passed on.

Background: the original test suite required a real nameserver to carry the
test zones, whereas the new test suite has the fake server for portability. This
code supports both.

Arguments:
  domain      the domain name
  type        the DNS record type
  answerptr   where to put the answer
  size        size of the answer area

Returns:      length of returned data, or -1 on error (h_errno set)
*/

static int
fakens_search(const uschar *domain, int type, uschar *answerptr, int size)
{
int len = Ustrlen(domain);
int asize = size;                  /* Locally modified */
uschar name[256];
uschar utilname[256];
uschar *aptr = answerptr;          /* Locally modified */
struct stat statbuf;

/* Remove terminating dot. */

if (domain[len - 1] == '.') len--;
Ustrncpy(name, domain, len);
name[len] = 0;

/* Look for the fakens utility, and if it exists, call it. */

(void)string_format(utilname, sizeof(utilname), "%s/bin/fakens",
  config_main_directory);

if (stat(CS utilname, &statbuf) >= 0)
  {
  pid_t pid;
  int infd, outfd, rc;
  uschar *argv[5];

  DEBUG(D_dns) debug_printf("DNS lookup of %s (%s) using fakens\n", name, dns_text_type(type));

  argv[0] = utilname;
  argv[1] = config_main_directory;
  argv[2] = name;
  argv[3] = dns_text_type(type);
  argv[4] = NULL;

  pid = child_open(argv, NULL, 0000, &infd, &outfd, FALSE);
  if (pid < 0)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to run fakens: %s",
      strerror(errno));

  len = 0;
  rc = -1;
  while (asize > 0 && (rc = read(outfd, aptr, asize)) > 0)
    {
    len += rc;
    aptr += rc;       /* Don't modify the actual arguments, because they */
    asize -= rc;      /* may need to be passed on to res_search(). */
    }

  /* If we ran out of output buffer before exhausting the return,
  carry on reading and counting it. */

  if (asize == 0)
    while ((rc = read(outfd, name, sizeof(name))) > 0)
      len += rc;

  if (rc < 0)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "read from fakens failed: %s",
      strerror(errno));

  switch(child_close(pid, 0))
    {
    case 0: return len;
    case 1: h_errno = HOST_NOT_FOUND; return -1;
    case 2: h_errno = TRY_AGAIN; return -1;
    default:
    case 3: h_errno = NO_RECOVERY; return -1;
    case 4: h_errno = NO_DATA; return -1;
    case 5: /* Pass on to res_search() */
    DEBUG(D_dns) debug_printf("fakens returned PASS_ON\n");
    }
  }
else
  {
  DEBUG(D_dns) debug_printf("fakens (%s) not found\n", utilname);
  }

/* fakens utility not found, or it returned "pass on" */

DEBUG(D_dns) debug_printf("passing %s on to res_search()\n", domain);

return res_search(CS domain, C_IN, type, answerptr, size);
}



/*************************************************
*        Initialize and configure resolver       *
*************************************************/

/* Initialize the resolver and the storage for holding DNS answers if this is
the first time we have been here, and set the resolver options.

Arguments:
  qualify_single    TRUE to set the RES_DEFNAMES option
  search_parents    TRUE to set the RES_DNSRCH option
  use_dnssec        TRUE to set the RES_USE_DNSSEC option

Returns:            nothing
*/

void
dns_init(BOOL qualify_single, BOOL search_parents, BOOL use_dnssec)
{
res_state resp = os_get_dns_resolver_res();

if ((resp->options & RES_INIT) == 0)
  {
  DEBUG(D_resolver) resp->options |= RES_DEBUG;     /* For Cygwin */
  os_put_dns_resolver_res(resp);
  res_init();
  DEBUG(D_resolver) resp->options |= RES_DEBUG;
  os_put_dns_resolver_res(resp);
  }

resp->options &= ~(RES_DNSRCH | RES_DEFNAMES);
resp->options |= (qualify_single? RES_DEFNAMES : 0) |
                (search_parents? RES_DNSRCH : 0);
if (dns_retrans > 0) resp->retrans = dns_retrans;
if (dns_retry > 0) resp->retry = dns_retry;

#ifdef RES_USE_EDNS0
if (dns_use_edns0 >= 0)
  {
  if (dns_use_edns0)
    resp->options |= RES_USE_EDNS0;
  else
    resp->options &= ~RES_USE_EDNS0;
  DEBUG(D_resolver)
    debug_printf("Coerced resolver EDNS0 support %s.\n",
        dns_use_edns0 ? "on" : "off");
  }
#else
if (dns_use_edns0 >= 0)
  DEBUG(D_resolver)
    debug_printf("Unable to %sset EDNS0 without resolver support.\n",
        dns_use_edns0 ? "" : "un");
#endif

#ifndef DISABLE_DNSSEC
# ifdef RES_USE_DNSSEC
#  ifndef RES_USE_EDNS0
#   error Have RES_USE_DNSSEC but not RES_USE_EDNS0?  Something hinky ...
#  endif
if (use_dnssec)
  resp->options |= RES_USE_DNSSEC;
if (dns_dnssec_ok >= 0)
  {
  if (dns_use_edns0 == 0 && dns_dnssec_ok != 0)
    {
    DEBUG(D_resolver)
      debug_printf("CONFLICT: dns_use_edns0 forced false, dns_dnssec_ok forced true, ignoring latter!\n");
    }
  else
    {
    if (dns_dnssec_ok)
      resp->options |= RES_USE_DNSSEC;
    else
      resp->options &= ~RES_USE_DNSSEC;
    DEBUG(D_resolver) debug_printf("Coerced resolver DNSSEC support %s.\n",
        dns_dnssec_ok ? "on" : "off");
    }
  }
# else
if (dns_dnssec_ok >= 0)
  DEBUG(D_resolver)
    debug_printf("Unable to %sset DNSSEC without resolver support.\n",
        dns_dnssec_ok ? "" : "un");
if (use_dnssec)
  DEBUG(D_resolver)
    debug_printf("Unable to set DNSSEC without resolver support.\n");
# endif
#endif /* DISABLE_DNSSEC */

os_put_dns_resolver_res(resp);
}



/*************************************************
*       Build key name for PTR records           *
*************************************************/

/* This function inverts an IP address and adds the relevant domain, to produce
a name that can be used to look up PTR records.

Arguments:
  string     the IP address as a string
  buffer     a suitable buffer, long enough to hold the result

Returns:     nothing
*/

void
dns_build_reverse(const uschar *string, uschar *buffer)
{
const uschar *p = string + Ustrlen(string);
uschar *pp = buffer;

/* Handle IPv4 address */

#if HAVE_IPV6
if (Ustrchr(string, ':') == NULL)
#endif
  {
  int i;
  for (i = 0; i < 4; i++)
    {
    const uschar *ppp = p;
    while (ppp > string && ppp[-1] != '.') ppp--;
    Ustrncpy(pp, ppp, p - ppp);
    pp += p - ppp;
    *pp++ = '.';
    p = ppp - 1;
    }
  Ustrcpy(pp, "in-addr.arpa");
  }

/* Handle IPv6 address; convert to binary so as to fill out any
abbreviation in the textual form. */

#if HAVE_IPV6
else
  {
  int i;
  int v6[4];
  (void)host_aton(string, v6);

  /* The original specification for IPv6 reverse lookup was to invert each
  nibble, and look in the ip6.int domain. The domain was subsequently
  changed to ip6.arpa. */

  for (i = 3; i >= 0; i--)
    {
    int j;
    for (j = 0; j < 32; j += 4)
      pp += sprintf(CS pp, "%x.", (v6[i] >> j) & 15);
    }
  Ustrcpy(pp, "ip6.arpa.");

  /* Another way of doing IPv6 reverse lookups was proposed in conjunction
  with A6 records. However, it fell out of favour when they did. The
  alternative was to construct a binary key, and look in ip6.arpa. I tried
  to make this code do that, but I could not make it work on Solaris 8. The
  resolver seems to lose the initial backslash somehow. However, now that
  this style of reverse lookup has been dropped, it doesn't matter. These
  lines are left here purely for historical interest. */

  /**************************************************
  Ustrcpy(pp, "\\[x");
  pp += 3;

  for (i = 0; i < 4; i++)
    {
    sprintf(pp, "%08X", v6[i]);
    pp += 8;
    }
  Ustrcpy(pp, "].ip6.arpa.");
  **************************************************/

  }
#endif
}




/* Increment the aptr in dnss, checking against dnsa length.
Return: TRUE for a bad result
*/
static BOOL
dnss_inc_aptr(const dns_answer * dnsa, dns_scan * dnss, unsigned delta)
{
return (dnss->aptr += delta) >= dnsa->answer + dnsa->answerlen;
}

/*************************************************
*       Get next DNS record from answer block    *
*************************************************/

/* Call this with reset == RESET_ANSWERS to scan the answer block, reset ==
RESET_AUTHORITY to scan the authority records, reset == RESET_ADDITIONAL to
scan the additional records, and reset == RESET_NEXT to get the next record.
The result is in static storage which must be copied if it is to be preserved.

Arguments:
  dnsa      pointer to dns answer block
  dnss      pointer to dns scan block
  reset     option specifying what portion to scan, as described above

Returns:    next dns record, or NULL when no more
*/

dns_record *
dns_next_rr(const dns_answer *dnsa, dns_scan *dnss, int reset)
{
const HEADER * h = (const HEADER *)dnsa->answer;
int namelen;

char * trace = NULL;
#ifdef rr_trace
# define TRACE DEBUG(D_dns)
#else
trace = trace;
# define TRACE if (FALSE)
#endif

/* Reset the saved data when requested to, and skip to the first required RR */

if (reset != RESET_NEXT)
  {
  dnss->rrcount = ntohs(h->qdcount);
  TRACE debug_printf("%s: reset (Q rrcount %d)\n", __FUNCTION__, dnss->rrcount);
  dnss->aptr = dnsa->answer + sizeof(HEADER);

  /* Skip over questions; failure to expand the name just gives up */

  while (dnss->rrcount-- > 0)
    {
    TRACE trace = "Q-namelen";
    namelen = dn_expand(dnsa->answer, dnsa->answer + dnsa->answerlen,
      dnss->aptr, (DN_EXPAND_ARG4_TYPE) &dnss->srr.name, DNS_MAXNAME);
    if (namelen < 0) goto null_return;
    /* skip name & type & class */
    TRACE trace = "Q-skip";
    if (dnss_inc_aptr(dnsa, dnss, namelen+4)) goto null_return;
    }

  /* Get the number of answer records. */

  dnss->rrcount = ntohs(h->ancount);
  TRACE debug_printf("%s: reset (A rrcount %d)\n", __FUNCTION__, dnss->rrcount);

  /* Skip over answers if we want to look at the authority section. Also skip
  the NS records (i.e. authority section) if wanting to look at the additional
  records. */

  if (reset == RESET_ADDITIONAL)
    {
    TRACE debug_printf("%s: additional\n", __FUNCTION__);
    dnss->rrcount += ntohs(h->nscount);
    TRACE debug_printf("%s: reset (NS rrcount %d)\n", __FUNCTION__, dnss->rrcount);
    }

  if (reset == RESET_AUTHORITY || reset == RESET_ADDITIONAL)
    {
    TRACE if (reset == RESET_AUTHORITY)
      debug_printf("%s: authority\n", __FUNCTION__);
    while (dnss->rrcount-- > 0)
      {
      TRACE trace = "A-namelen";
      namelen = dn_expand(dnsa->answer, dnsa->answer + dnsa->answerlen,
        dnss->aptr, (DN_EXPAND_ARG4_TYPE) &dnss->srr.name, DNS_MAXNAME);
      if (namelen < 0) goto null_return;
      /* skip name, type, class & TTL */
      TRACE trace = "A-hdr";
      if (dnss_inc_aptr(dnsa, dnss, namelen+8)) goto null_return;
      GETSHORT(dnss->srr.size, dnss->aptr); /* size of data portion */
      /* skip over it */
      TRACE trace = "A-skip";
      if (dnss_inc_aptr(dnsa, dnss, dnss->srr.size)) goto null_return;
      }
    dnss->rrcount = reset == RESET_AUTHORITY
      ? ntohs(h->nscount) : ntohs(h->arcount);
    TRACE debug_printf("%s: reset (%s rrcount %d)\n", __FUNCTION__,
      reset == RESET_AUTHORITY ? "NS" : "AR", dnss->rrcount);
    }
  TRACE debug_printf("%s: %d RRs to read\n", __FUNCTION__, dnss->rrcount);
  }
else
  TRACE debug_printf("%s: next (%d left)\n", __FUNCTION__, dnss->rrcount);

/* The variable dnss->aptr is now pointing at the next RR, and dnss->rrcount
contains the number of RR records left. */

if (dnss->rrcount-- <= 0) return NULL;

/* If expanding the RR domain name fails, behave as if no more records
(something safe). */

TRACE trace = "R-namelen";
namelen = dn_expand(dnsa->answer, dnsa->answer + dnsa->answerlen, dnss->aptr,
  (DN_EXPAND_ARG4_TYPE) &dnss->srr.name, DNS_MAXNAME);
if (namelen < 0) goto null_return;

/* Move the pointer past the name and fill in the rest of the data structure
from the following bytes. */

TRACE trace = "R-name";
if (dnss_inc_aptr(dnsa, dnss, namelen)) goto null_return;

GETSHORT(dnss->srr.type, dnss->aptr);		/* Record type */
TRACE trace = "R-class";
if (dnss_inc_aptr(dnsa, dnss, 2)) goto null_return;	/* Don't want class */
GETLONG(dnss->srr.ttl, dnss->aptr);		/* TTL */
GETSHORT(dnss->srr.size, dnss->aptr);		/* Size of data portion */
dnss->srr.data = dnss->aptr;			/* The record's data follows */

/* Unchecked increment ok here since no further access on this iteration;
will be checked on next at "R-name". */

dnss->aptr += dnss->srr.size;			/* Advance to next RR */

/* Return a pointer to the dns_record structure within the dns_answer. This is
for convenience so that the scans can use nice-looking for loops. */

return &dnss->srr;

null_return:
  TRACE debug_printf("%s: terminate (%d RRs left). Last op: %s; errno %d %s\n",
    __FUNCTION__, dnss->rrcount, trace, errno, strerror(errno));
  dnss->rrcount = 0;
  return NULL;
}


/* Extract the AUTHORITY information from the answer. If the answer isn't
authoritative (AA not set), we do not extract anything.

The AUTHORITY section contains NS records if the name in question was found,
it contains a SOA record otherwise. (This is just from experience and some
tests, is there some spec?)

Scan the whole AUTHORITY section, since it may contain other records
(e.g. NSEC3) too.

Return: name for the authority, in an allocated string, or NULL if none found */

static const uschar *
dns_extract_auth_name(const dns_answer * dnsa)	/* FIXME: const dns_answer */
{
dns_scan dnss;
dns_record * rr;
const HEADER * h = (const HEADER *) dnsa->answer;

if (h->nscount && h->aa)
  for (rr = dns_next_rr(dnsa, &dnss, RESET_AUTHORITY);
       rr; rr = dns_next_rr(dnsa, &dnss, RESET_NEXT))
    if (rr->type == (h->ancount ? T_NS : T_SOA))
      return string_copy(rr->name);
return NULL;
}




/*************************************************
*    Return whether AD bit set in DNS result     *
*************************************************/

/* We do not perform DNSSEC work ourselves; if the administrator has installed
a verifying resolver which sets AD as appropriate, though, we'll use that.
(AD = Authentic Data, AA = Authoritative Answer)

Argument:   pointer to dns answer block
Returns:    bool indicating presence of AD bit
*/

BOOL
dns_is_secure(const dns_answer * dnsa)
{
#ifdef DISABLE_DNSSEC
DEBUG(D_dns)
  debug_printf("DNSSEC support disabled at build-time; dns_is_secure() false\n");
return FALSE;
#else
const HEADER * h = (const HEADER *) dnsa->answer;
const uschar * auth_name;
const uschar * trusted;

if (h->ad) return TRUE;

/* If the resolver we ask is authoritative for the domain in question, it
* may not set the AD but the AA bit. If we explicitly trust
* the resolver for that domain (via a domainlist in dns_trust_aa),
* we return TRUE to indicate a secure answer.
*/

if (  !h->aa
   || !dns_trust_aa
   || !(trusted = expand_string(dns_trust_aa))
   || !*trusted
   || !(auth_name = dns_extract_auth_name(dnsa))
   || OK != match_isinlist(auth_name, &trusted, 0, NULL, NULL,
			    MCL_DOMAIN, TRUE, NULL)
   )
  return FALSE;

DEBUG(D_dns) debug_printf("DNS faked the AD bit "
  "(got AA and matched with dns_trust_aa (%s in %s))\n",
  auth_name, dns_trust_aa);

return TRUE;
#endif
}

static void
dns_set_insecure(dns_answer * dnsa)
{
#ifndef DISABLE_DNSSEC
HEADER * h = (HEADER *)dnsa->answer;
h->aa = h->ad = 0;
#endif
}

/************************************************
 *	Check whether the AA bit is set		*
 *	We need this to warn if we requested AD *
 *	from an authoritative server		*
 ************************************************/

BOOL
dns_is_aa(const dns_answer *dnsa)
{
#ifdef DISABLE_DNSSEC
return FALSE;
#else
return ((const HEADER*)dnsa->answer)->aa;
#endif
}



/*************************************************
*            Turn DNS type into text             *
*************************************************/

/* Turn the coded record type into a string for printing. All those that Exim
uses should be included here.

Argument:   record type
Returns:    pointer to string
*/

uschar *
dns_text_type(int t)
{
switch(t)
  {
  case T_A:     return US"A";
  case T_MX:    return US"MX";
  case T_AAAA:  return US"AAAA";
  case T_A6:    return US"A6";
  case T_TXT:   return US"TXT";
  case T_SPF:   return US"SPF";
  case T_PTR:   return US"PTR";
  case T_SOA:   return US"SOA";
  case T_SRV:   return US"SRV";
  case T_NS:    return US"NS";
  case T_CNAME: return US"CNAME";
  case T_TLSA:  return US"TLSA";
  default:      return US"?";
  }
}



/*************************************************
*        Cache a failed DNS lookup result        *
*************************************************/

static void
dns_fail_tag(uschar * buf, const uschar * name, int dns_type)
{
res_state resp = os_get_dns_resolver_res();
sprintf(CS buf, "%.255s-%s-%lx", name, dns_text_type(dns_type),
  (unsigned long) resp->options);
}


/* We cache failed lookup results so as not to experience timeouts many
times for the same domain. We need to retain the resolver options because they
may change. For successful lookups, we rely on resolver and/or name server
caching.

Arguments:
  name       the domain name
  type       the lookup type
  rc         the return code

Returns:     the return code
*/

static int
dns_return(const uschar * name, int type, int rc)
{
tree_node *node = store_get_perm(sizeof(tree_node) + 290);
dns_fail_tag(node->name, name, type);
node->data.val = rc;
(void)tree_insertnode(&tree_dns_fails, node);
return rc;
}

/*************************************************
*              Do basic DNS lookup               *
*************************************************/

/* Call the resolver to look up the given domain name, using the given type,
and check the result. The error code TRY_AGAIN is documented as meaning "non-
Authoritative Host not found, or SERVERFAIL". Sometimes there are badly set
up nameservers that produce this error continually, so there is the option of
providing a list of domains for which this is treated as a non-existent
host.

The dns_answer structure is pretty big; enough to hold a max-sized DNS message
- so best allocated from fast-release memory.  As of writing, all our callers
use a stack-auto variable.

Arguments:
  dnsa      pointer to dns_answer structure
  name      name to look up
  type      type of DNS record required (T_A, T_MX, etc)

Returns:    DNS_SUCCEED   successful lookup
            DNS_NOMATCH   name not found (NXDOMAIN)
                          or name contains illegal characters (if checking)
                          or name is an IP address (for IP address lookup)
            DNS_NODATA    domain exists, but no data for this type (NODATA)
            DNS_AGAIN     soft failure, try again later
            DNS_FAIL      DNS failure
*/

int
dns_basic_lookup(dns_answer *dnsa, const uschar *name, int type)
{
#ifndef STAND_ALONE
int rc = -1;
const uschar *save_domain;
#endif

tree_node *previous;
uschar node_name[290];

/* DNS lookup failures of any kind are cached in a tree. This is mainly so that
a timeout on one domain doesn't happen time and time again for messages that
have many addresses in the same domain. We rely on the resolver and name server
caching for successful lookups. */

dns_fail_tag(node_name, name, type);
if ((previous = tree_search(tree_dns_fails, node_name)))
  {
  DEBUG(D_dns) debug_printf("DNS lookup of %.255s-%s: using cached value %s\n",
    name, dns_text_type(type),
      previous->data.val == DNS_NOMATCH ? "DNS_NOMATCH" :
      previous->data.val == DNS_NODATA ? "DNS_NODATA" :
      previous->data.val == DNS_AGAIN ? "DNS_AGAIN" :
      previous->data.val == DNS_FAIL ? "DNS_FAIL" : "??");
  return previous->data.val;
  }

#ifdef SUPPORT_I18N
/* Convert all names to a-label form before doing lookup */
  {
  uschar * alabel;
  uschar * errstr = NULL;
  DEBUG(D_dns) if (string_is_utf8(name))
    debug_printf("convert utf8 '%s' to alabel for for lookup\n", name);
  if ((alabel = string_domain_utf8_to_alabel(name, &errstr)), errstr)
    {
    DEBUG(D_dns)
      debug_printf("DNS name '%s' utf8 conversion to alabel failed: %s\n", name,
        errstr);
    f.host_find_failed_syntax = TRUE;
    return DNS_NOMATCH;
    }
  name = alabel;
  }
#endif

/* If configured, check the hygiene of the name passed to lookup. Otherwise,
although DNS lookups may give REFUSED at the lower level, some resolvers
turn this into TRY_AGAIN, which is silly. Give a NOMATCH return, since such
domains cannot be in the DNS. The check is now done by a regular expression;
give it space for substring storage to save it having to get its own if the
regex has substrings that are used - the default uses a conditional.

This test is omitted for PTR records. These occur only in calls from the dnsdb
lookup, which constructs the names itself, so they should be OK. Besides,
bitstring labels don't conform to normal name syntax. (But the aren't used any
more.)

For SRV records, we omit the initial _smtp._tcp. components at the start. */

#ifndef STAND_ALONE   /* Omit this for stand-alone tests */

if (check_dns_names_pattern[0] != 0 && type != T_PTR && type != T_TXT)
  {
  const uschar *checkname = name;
  int ovector[3*(EXPAND_MAXN+1)];

  dns_pattern_init();

  /* For an SRV lookup, skip over the first two components (the service and
  protocol names, which both start with an underscore). */

  if (type == T_SRV || type == T_TLSA)
    {
    while (*checkname++ != '.');
    while (*checkname++ != '.');
    }

  if (pcre_exec(regex_check_dns_names, NULL, CCS checkname, Ustrlen(checkname),
      0, PCRE_EOPT, ovector, nelem(ovector)) < 0)
    {
    DEBUG(D_dns)
      debug_printf("DNS name syntax check failed: %s (%s)\n", name,
        dns_text_type(type));
    f.host_find_failed_syntax = TRUE;
    return DNS_NOMATCH;
    }
  }

#endif /* STAND_ALONE */

/* Call the resolver; for an overlong response, res_search() will return the
number of bytes the message would need, so we need to check for this case. The
effect is to truncate overlong data.

On some systems, res_search() will recognize "A-for-A" queries and return
the IP address instead of returning -1 with h_error=HOST_NOT_FOUND. Some
nameservers are also believed to do this. It is, of course, contrary to the
specification of the DNS, so we lock it out. */

if ((type == T_A || type == T_AAAA) && string_is_ip_address(name, NULL) != 0)
  return DNS_NOMATCH;

/* If we are running in the test harness, instead of calling the normal resolver
(res_search), we call fakens_search(), which recognizes certain special
domains, and interfaces to a fake nameserver for certain special zones. */

dnsa->answerlen = f.running_in_test_harness
  ? fakens_search(name, type, dnsa->answer, sizeof(dnsa->answer))
  : res_search(CCS name, C_IN, type, dnsa->answer, sizeof(dnsa->answer));

if (dnsa->answerlen > (int) sizeof(dnsa->answer))
  {
  DEBUG(D_dns) debug_printf("DNS lookup of %s (%s) resulted in overlong packet"
    " (size %d), truncating to %u.\n",
    name, dns_text_type(type), dnsa->answerlen, (unsigned int) sizeof(dnsa->answer));
  dnsa->answerlen = sizeof(dnsa->answer);
  }

if (dnsa->answerlen < 0) switch (h_errno)
  {
  case HOST_NOT_FOUND:
    DEBUG(D_dns) debug_printf("DNS lookup of %s (%s) gave HOST_NOT_FOUND\n"
      "returning DNS_NOMATCH\n", name, dns_text_type(type));
    return dns_return(name, type, DNS_NOMATCH);

  case TRY_AGAIN:
    DEBUG(D_dns) debug_printf("DNS lookup of %s (%s) gave TRY_AGAIN\n",
      name, dns_text_type(type));

    /* Cut this out for various test programs */
#ifndef STAND_ALONE
    save_domain = deliver_domain;
    deliver_domain = string_copy(name);  /* set $domain */
    rc = match_isinlist(name, (const uschar **)&dns_again_means_nonexist, 0, NULL, NULL,
      MCL_DOMAIN, TRUE, NULL);
    deliver_domain = save_domain;
    if (rc != OK)
      {
      DEBUG(D_dns) debug_printf("returning DNS_AGAIN\n");
      return dns_return(name, type, DNS_AGAIN);
      }
    DEBUG(D_dns) debug_printf("%s is in dns_again_means_nonexist: returning "
      "DNS_NOMATCH\n", name);
    return dns_return(name, type, DNS_NOMATCH);

#else   /* For stand-alone tests */
    return dns_return(name, type, DNS_AGAIN);
#endif

  case NO_RECOVERY:
    DEBUG(D_dns) debug_printf("DNS lookup of %s (%s) gave NO_RECOVERY\n"
      "returning DNS_FAIL\n", name, dns_text_type(type));
    return dns_return(name, type, DNS_FAIL);

  case NO_DATA:
    DEBUG(D_dns) debug_printf("DNS lookup of %s (%s) gave NO_DATA\n"
      "returning DNS_NODATA\n", name, dns_text_type(type));
    return dns_return(name, type, DNS_NODATA);

  default:
    DEBUG(D_dns) debug_printf("DNS lookup of %s (%s) gave unknown DNS error %d\n"
      "returning DNS_FAIL\n", name, dns_text_type(type), h_errno);
    return dns_return(name, type, DNS_FAIL);
  }

DEBUG(D_dns) debug_printf("DNS lookup of %s (%s) succeeded\n",
  name, dns_text_type(type));

return DNS_SUCCEED;
}




/************************************************
*        Do a DNS lookup and handle CNAMES      *
************************************************/

/* Look up the given domain name, using the given type. Follow CNAMEs if
necessary, but only so many times. There aren't supposed to be CNAME chains in
the DNS, but you are supposed to cope with them if you find them.
By default, follow one CNAME since a resolver has been seen, faced with
an MX request and a CNAME (to an A) but no MX present, returning the CNAME.

The assumption is made that if the resolver gives back records of the
requested type *and* a CNAME, we don't need to make another call to look up
the CNAME. I can't see how it could return only some of the right records. If
it's done a CNAME lookup in the past, it will have all of them; if not, it
won't return any.

If fully_qualified_name is not NULL, set it to point to the full name
returned by the resolver, if this is different to what it is given, unless
the returned name starts with "*" as some nameservers seem to be returning
wildcards in this form.  In international mode "different" means "alabel
forms are different".

Arguments:
  dnsa                  pointer to dns_answer structure
  name                  domain name to look up
  type                  DNS record type (T_A, T_MX, etc)
  fully_qualified_name  if not NULL, return the returned name here if its
                          contents are different (i.e. it must be preset)

Returns:                DNS_SUCCEED   successful lookup
                        DNS_NOMATCH   name not found
                        DNS_NODATA    no data found
                        DNS_AGAIN     soft failure, try again later
                        DNS_FAIL      DNS failure
*/

int
dns_lookup(dns_answer *dnsa, const uschar *name, int type,
  const uschar **fully_qualified_name)
{
int i;
const uschar *orig_name = name;
BOOL secure_so_far = TRUE;

/* By default, assume the resolver follows CNAME chains (and returns NODATA for
an unterminated one). If it also does that for a CNAME loop, fine; if it returns
a CNAME (maybe the last?) whine about it.  However, retain the coding for dumb
resolvers hiding behind a config variable. Loop to follow CNAME chains so far,
but no further...  The testsuite tests the latter case, mostly assuming that the
former will work. */

for (i = 0; i <= dns_cname_loops; i++)
  {
  uschar * data;
  dns_record *rr, cname_rr, type_rr;
  dns_scan dnss;
  int rc;

  /* DNS lookup failures get passed straight back. */

  if ((rc = dns_basic_lookup(dnsa, name, type)) != DNS_SUCCEED)
    return rc;

  /* We should have either records of the required type, or a CNAME record,
  or both. We need to know whether both exist for getting the fully qualified
  name, but avoid scanning more than necessary. Note that we must copy the
  contents of any rr blocks returned by dns_next_rr() as they use the same
  area in the dnsa block. */

  cname_rr.data = type_rr.data = NULL;
  for (rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS);
       rr; rr = dns_next_rr(dnsa, &dnss, RESET_NEXT))
    if (rr->type == type)
      {
      if (type_rr.data == NULL) type_rr = *rr;
      if (cname_rr.data != NULL) break;
      }
    else if (rr->type == T_CNAME)
      cname_rr = *rr;

  /* For the first time round this loop, if a CNAME was found, take the fully
  qualified name from it; otherwise from the first data record, if present. */

  if (i == 0 && fully_qualified_name)
    {
    uschar * rr_name = cname_rr.data
      ? cname_rr.name : type_rr.data ? type_rr.name : NULL;
    if (  rr_name
       && Ustrcmp(rr_name, *fully_qualified_name) != 0
       && rr_name[0] != '*'
#ifdef SUPPORT_I18N
       && (  !string_is_utf8(*fully_qualified_name)
	  || Ustrcmp(rr_name,
	       string_domain_utf8_to_alabel(*fully_qualified_name, NULL)) != 0
	  )
#endif
       )
        *fully_qualified_name = string_copy_dnsdomain(rr_name);
    }

  /* If any data records of the correct type were found, we are done. */

  if (type_rr.data)
    {
    if (!secure_so_far)	/* mark insecure if any element of CNAME chain was */
      dns_set_insecure(dnsa);
    return DNS_SUCCEED;
    }

  /* If there are no data records, we need to re-scan the DNS using the
  domain given in the CNAME record, which should exist (otherwise we should
  have had a failure from dns_lookup). However code against the possibility of
  its not existing. */

  if (!cname_rr.data)
    return DNS_FAIL;

  data = store_get(256);
  if (dn_expand(dnsa->answer, dnsa->answer + dnsa->answerlen,
      cname_rr.data, (DN_EXPAND_ARG4_TYPE)data, 256) < 0)
    return DNS_FAIL;
  name = data;

  if (!dns_is_secure(dnsa))
    secure_so_far = FALSE;

  DEBUG(D_dns) debug_printf("CNAME found: change to %s\n", name);
  }       /* Loop back to do another lookup */

/*Control reaches here after 10 times round the CNAME loop. Something isn't
right... */

log_write(0, LOG_MAIN, "CNAME loop for %s encountered", orig_name);
return DNS_FAIL;
}






/************************************************
*    Do a DNS lookup and handle virtual types   *
************************************************/

/* This function handles some invented "lookup types" that synthesize features
not available in the basic types. The special types all have negative values.
Positive type values are passed straight on to dns_lookup().

Arguments:
  dnsa                  pointer to dns_answer structure
  name                  domain name to look up
  type                  DNS record type (T_A, T_MX, etc or a "special")
  fully_qualified_name  if not NULL, return the returned name here if its
                          contents are different (i.e. it must be preset)

Returns:                DNS_SUCCEED   successful lookup
                        DNS_NOMATCH   name not found
                        DNS_NODATA    no data found
                        DNS_AGAIN     soft failure, try again later
                        DNS_FAIL      DNS failure
*/

int
dns_special_lookup(dns_answer *dnsa, const uschar *name, int type,
  const uschar **fully_qualified_name)
{
switch (type)
  {
  /* The "mx hosts only" type doesn't require any special action here */
  case T_MXH:
    return dns_lookup(dnsa, name, T_MX, fully_qualified_name);

  /* Find nameservers for the domain or the nearest enclosing zone, excluding
  the root servers. */
  case T_ZNS:
    type = T_NS;
    /* FALLTHROUGH */
  case T_SOA:
    {
    const uschar *d = name;
    while (d != 0)
      {
      int rc = dns_lookup(dnsa, d, type, fully_qualified_name);
      if (rc != DNS_NOMATCH && rc != DNS_NODATA) return rc;
      while (*d != 0 && *d != '.') d++;
      if (*d++ == 0) break;
      }
    return DNS_NOMATCH;
    }

  /* Try to look up the Client SMTP Authorization SRV record for the name. If
  there isn't one, search from the top downwards for a CSA record in a parent
  domain, which might be making assertions about subdomains. If we find a record
  we set fully_qualified_name to whichever lookup succeeded, so that the caller
  can tell whether to look at the explicit authorization field or the subdomain
  assertion field. */
  case T_CSA:
    {
    uschar *srvname, *namesuff, *tld;
    int priority, weight, port;
    int limit, rc, i;
    BOOL ipv6;
    dns_record *rr;
    dns_scan dnss;

    DEBUG(D_dns) debug_printf("CSA lookup of %s\n", name);

    srvname = string_sprintf("_client._smtp.%s", name);
    rc = dns_lookup(dnsa, srvname, T_SRV, NULL);
    if (rc == DNS_SUCCEED || rc == DNS_AGAIN)
      {
      if (rc == DNS_SUCCEED) *fully_qualified_name = string_copy(name);
      return rc;
      }

    /* Search for CSA subdomain assertion SRV records from the top downwards,
    starting with the 2nd level domain. This order maximizes cache-friendliness.
    We skip the top level domains to avoid loading their nameservers and because
    we know they'll never have CSA SRV records. */

    namesuff = Ustrrchr(name, '.');
    if (namesuff == NULL) return DNS_NOMATCH;
    tld = namesuff + 1;
    ipv6 = FALSE;
    limit = dns_csa_search_limit;

    /* Use more appropriate search parameters if we are in the reverse DNS. */

    if (strcmpic(namesuff, US".arpa") == 0)
      if (namesuff - 8 > name && strcmpic(namesuff - 8, US".in-addr.arpa") == 0)
	{
	namesuff -= 8;
	tld = namesuff + 1;
	limit = 3;
	}
      else if (namesuff - 4 > name && strcmpic(namesuff - 4, US".ip6.arpa") == 0)
	{
	namesuff -= 4;
	tld = namesuff + 1;
	ipv6 = TRUE;
	limit = 3;
	}

    DEBUG(D_dns) debug_printf("CSA TLD %s\n", tld);

    /* Do not perform the search if the top level or 2nd level domains do not
    exist. This is quite common, and when it occurs all the search queries would
    go to the root or TLD name servers, which is not friendly. So we check the
    AUTHORITY section; if it contains the root's SOA record or the TLD's SOA then
    the TLD or the 2LD (respectively) doesn't exist and we can skip the search.
    If the TLD and the 2LD exist but the explicit CSA record lookup failed, then
    the AUTHORITY SOA will be the 2LD's or a subdomain thereof. */

    if (rc == DNS_NOMATCH)
      {
      /* This is really gross. The successful return value from res_search() is
      the packet length, which is stored in dnsa->answerlen. If we get a
      negative DNS reply then res_search() returns -1, which causes the bounds
      checks for name decompression to fail when it is treated as a packet
      length, which in turn causes the authority search to fail. The correct
      packet length has been lost inside libresolv, so we have to guess a
      replacement value. (The only way to fix this properly would be to
      re-implement res_search() and res_query() so that they don't muddle their
      success and packet length return values.) For added safety we only reset
      the packet length if the packet header looks plausible. */

      const HEADER * h = (const HEADER *)dnsa->answer;
      if (h->qr == 1 && h->opcode == QUERY && h->tc == 0
	  && (h->rcode == NOERROR || h->rcode == NXDOMAIN)
	  && ntohs(h->qdcount) == 1 && ntohs(h->ancount) == 0
	  && ntohs(h->nscount) >= 1)
	    dnsa->answerlen = sizeof(dnsa->answer);

      for (rr = dns_next_rr(dnsa, &dnss, RESET_AUTHORITY);
	   rr; rr = dns_next_rr(dnsa, &dnss, RESET_NEXT)
	  )
	if (rr->type != T_SOA) continue;
	else if (strcmpic(rr->name, US"") == 0 ||
		 strcmpic(rr->name, tld) == 0) return DNS_NOMATCH;
	else break;
      }

    for (i = 0; i < limit; i++)
      {
      if (ipv6)
	{
	/* Scan through the IPv6 reverse DNS in chunks of 16 bits worth of IP
	address, i.e. 4 hex chars and 4 dots, i.e. 8 chars. */
	namesuff -= 8;
	if (namesuff <= name) return DNS_NOMATCH;
	}
      else
	/* Find the start of the preceding domain name label. */
	do
	  if (--namesuff <= name) return DNS_NOMATCH;
	while (*namesuff != '.');

      DEBUG(D_dns) debug_printf("CSA parent search at %s\n", namesuff + 1);

      srvname = string_sprintf("_client._smtp.%s", namesuff + 1);
      rc = dns_lookup(dnsa, srvname, T_SRV, NULL);
      if (rc == DNS_AGAIN) return rc;
      if (rc != DNS_SUCCEED) continue;

      /* Check that the SRV record we have found is worth returning. We don't
      just return the first one we find, because some lower level SRV record
      might make stricter assertions than its parent domain. */

      for (rr = dns_next_rr(dnsa, &dnss, RESET_ANSWERS);
	   rr; rr = dns_next_rr(dnsa, &dnss, RESET_NEXT)) if (rr->type == T_SRV)
	{
	const uschar * p = rr->data;

	/* Extract the numerical SRV fields (p is incremented) */
	GETSHORT(priority, p);
	GETSHORT(weight, p);	weight = weight; /* compiler quietening */
	GETSHORT(port, p);

	/* Check the CSA version number */
	if (priority != 1) continue;

	/* If it's making an interesting assertion, return this response. */
	if (port & 1)
	  {
	  *fully_qualified_name = namesuff + 1;
	  return DNS_SUCCEED;
	  }
	}
      }
    return DNS_NOMATCH;
    }

  default:
    if (type >= 0)
      return dns_lookup(dnsa, name, type, fully_qualified_name);
  }

/* Control should never reach here */

return DNS_FAIL;
}





/*************************************************
*          Get address(es) from DNS record       *
*************************************************/

/* The record type is either T_A for an IPv4 address or T_AAAA for an IPv6 address.

Argument:
  dnsa       the DNS answer block
  rr         the RR

Returns:     pointer to a chain of dns_address items; NULL when the dnsa was overrun
*/

dns_address *
dns_address_from_rr(dns_answer *dnsa, dns_record *rr)
{
dns_address * yield = NULL;
uschar * dnsa_lim = dnsa->answer + dnsa->answerlen;

if (rr->type == T_A)
  {
  uschar *p = US rr->data;
  if (p + 4 <= dnsa_lim)
    {
    yield = store_get(sizeof(dns_address) + 20);
    (void)sprintf(CS yield->address, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    yield->next = NULL;
    }
  }

#if HAVE_IPV6

else
  {
  if (rr->data + 16 <= dnsa_lim)
    {
    struct in6_addr in6;
    int i;
    for (i = 0; i < 16; i++) in6.s6_addr[i] = rr->data[i];
    yield = store_get(sizeof(dns_address) + 50);
    inet_ntop(AF_INET6, &in6, CS yield->address, 50);
    yield->next = NULL;
    }
  }
#endif  /* HAVE_IPV6 */

return yield;
}



void
dns_pattern_init(void)
{
if (check_dns_names_pattern[0] != 0 && !regex_check_dns_names)
  regex_check_dns_names =
    regex_must_compile(check_dns_names_pattern, FALSE, TRUE);
}

/* vi: aw ai sw=2
*/
/* End of dns.c */
