/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions for matching strings */


#include "exim.h"


/* Argument block for the check_string() function. This is used for general
strings, domains, and local parts. */

typedef struct check_string_block {
  const uschar *origsubject;           /* caseful; keep these two first, in */
  const uschar *subject;               /* step with the block below */
  int    expand_setup;
  BOOL   use_partial;
  BOOL   caseless;
  BOOL   at_is_special;
} check_string_block;


/* Argument block for the check_address() function. This is used for whole
addresses. */

typedef struct check_address_block {
  const uschar *origaddress;         /* caseful; keep these two first, in */
  uschar *address;                   /* step with the block above */
  int    expand_setup;
  BOOL   caseless;
} check_address_block;



/*************************************************
*           Generalized string match             *
*************************************************/

/* This function does a single match of a subject against a pattern, and
optionally sets up the numeric variables according to what it matched. It is
called from match_isinlist() via match_check_list() when scanning a list, and
from match_check_string() when testing just a single item. The subject and
options arguments are passed in a check_string_block so as to make it easier to
pass them through match_check_list.

The possible types of pattern are:

  . regular expression - starts with ^
  . tail match - starts with *
  . lookup - starts with search type
  . if at_is_special is set in the argument block:
      @              matches the primary host name
      @[]            matches a local IP address in brackets
      @mx_any        matches any domain with an MX to the local host
      @mx_primary    matches any domain with a primary MX to the local host
      @mx_secondary  matches any domain with a secondary MX to the local host
  . literal - anything else

Any of the @mx_xxx options can be followed by "/ignore=<list>" where <list> is
a list of IP addresses that are to be ignored (typically 127.0.0.1).

Arguments:
  arg            check_string_block pointer - see below
  pattern        the pattern to be matched
  valueptr       if not NULL, and a lookup is done, return the result here
                   instead of discarding it; else set it to point to NULL
  error          for error messages (not used in this function; it never
                   returns ERROR)

Contents of the argument block:
  origsubject    the subject in its original casing
  subject        the subject string to be checked, lowercased if caseless
  expand_setup   if < 0, don't set up any numeric expansion variables;
                 if = 0, set $0 to whole subject, and either
                   $1 to what matches * or
                   $1, $2, ... to r.e. bracketed items
                 if > 0, don't set $0, but do set either
                   $n to what matches *, or
                   $n, $n+1, ... to r.e. bracketed items
                 (where n = expand_setup)
  use_partial    if FALSE, override any partial- search types
  caseless       TRUE for caseless matching where possible
  at_is_special  enable special handling of items starting with @

Returns:       OK    if matched
               FAIL  if not matched
               DEFER if lookup deferred
*/

static int
check_string(void *arg, const uschar *pattern, const uschar **valueptr, uschar **error)
{
const check_string_block *cb = arg;
int search_type, partial, affixlen, starflags;
int expand_setup = cb->expand_setup;
const uschar *affix;
uschar *s;
uschar *filename = NULL;
uschar *keyquery, *result, *semicolon;
void *handle;

error = error;  /* Keep clever compilers from complaining */

if (valueptr != NULL) *valueptr = NULL;  /* For non-lookup matches */

/* For regular expressions, use cb->origsubject rather than cb->subject so that
it works if the pattern uses (?-i) to turn off case-independence, overriding
"caseless". */

s = string_copy(pattern[0] == '^' ? cb->origsubject : cb->subject);

/* If required to set up $0, initialize the data but don't turn on by setting
expand_nmax until the match is assured. */

expand_nmax = -1;
if (expand_setup == 0)
  {
  expand_nstring[0] = s;
  expand_nlength[0] = Ustrlen(s);
  }
else if (expand_setup > 0) expand_setup--;

/* Regular expression match: compile, match, and set up $ variables if
required. */

if (pattern[0] == '^')
  {
  const pcre *re = regex_must_compile(pattern, cb->caseless, FALSE);
  return ((expand_setup < 0)?
           pcre_exec(re, NULL, CCS s, Ustrlen(s), 0, PCRE_EOPT, NULL, 0) >= 0
           :
           regex_match_and_setup(re, s, 0, expand_setup)
         )?
         OK : FAIL;
  }

/* Tail match */

if (pattern[0] == '*')
  {
  BOOL yield;
  int slen = Ustrlen(s);
  int patlen;    /* Sun compiler doesn't like non-constant initializer */

  patlen = Ustrlen(++pattern);
  if (patlen > slen) return FAIL;
  yield = cb->caseless?
    (strncmpic(s + slen - patlen, pattern, patlen) == 0) :
    (Ustrncmp(s + slen - patlen, pattern, patlen) == 0);
  if (yield && expand_setup >= 0)
    {
    expand_nstring[++expand_setup] = s;
    expand_nlength[expand_setup] = slen - patlen;
    expand_nmax = expand_setup;
    }
  return yield? OK : FAIL;
  }

/* Match a special item starting with @ if so enabled. On its own, "@" matches
the primary host name - implement this by changing the pattern. For the other
cases we have to do some more work. If we don't recognize a special pattern,
just fall through - the match will fail. */

if (cb->at_is_special && pattern[0] == '@')
  {
  if (pattern[1] == 0)
    {
    pattern = primary_hostname;
    goto NOT_AT_SPECIAL;               /* Handle as exact string match */
    }

  if (Ustrcmp(pattern, "@[]") == 0)
    {
    ip_address_item *ip;
    int slen = Ustrlen(s);
    if (s[0] != '[' && s[slen-1] != ']') return FAIL;
    for (ip = host_find_interfaces(); ip != NULL; ip = ip->next)
      if (Ustrncmp(ip->address, s+1, slen - 2) == 0
            && ip->address[slen - 2] == 0)
        return OK;
    return FAIL;
    }

  if (strncmpic(pattern, US"@mx_", 4) == 0)
    {
    int rc;
    host_item h;
    BOOL prim = FALSE;
    BOOL secy = FALSE;
    BOOL removed = FALSE;
    const uschar *ss = pattern + 4;
    const uschar *ignore_target_hosts = NULL;

    if (strncmpic(ss, US"any", 3) == 0) ss += 3;
    else if (strncmpic(ss, US"primary", 7) == 0)
      {
      ss += 7;
      prim = TRUE;
      }
    else if (strncmpic(ss, US"secondary", 9) == 0)
      {
      ss += 9;
      secy = TRUE;
      }
    else goto NOT_AT_SPECIAL;

    if (strncmpic(ss, US"/ignore=", 8) == 0) ignore_target_hosts = ss + 8;
      else if (*ss != 0) goto NOT_AT_SPECIAL;

    h.next = NULL;
    h.name = s;
    h.address = NULL;

    rc = host_find_bydns(&h,
      ignore_target_hosts,
      HOST_FIND_BY_MX,     /* search only for MX, not SRV or A */
      NULL,                /* service name not relevant */
      NULL,                /* srv_fail_domains not relevant */
      NULL,                /* mx_fail_domains not relevant */
      NULL,                /* no dnssec request/require XXX ? */
      NULL,                /* no feedback FQDN */
      &removed);           /* feedback if local removed */

    if (rc == HOST_FIND_AGAIN)
      {
      search_error_message = string_sprintf("DNS lookup of \"%s\" deferred", s);
      return DEFER;
      }

    if (rc == HOST_FOUND_LOCAL && !secy) return OK;
    if (prim) return FAIL;
    return removed? OK : FAIL;

    /*** The above line used to be the following line, but this is incorrect,
    because host_find_bydns() may return HOST_NOT_FOUND if it removed some MX
    hosts, but the remaining ones were non-existent. All we are interested in
    is whether or not it removed some hosts.

    return (rc == HOST_FOUND && removed)? OK : FAIL;
    ***/
    }
  }

/* Escape point from code for specials that start with "@" */

NOT_AT_SPECIAL:

/* This is an exact string match if there is no semicolon in the pattern. */

if ((semicolon = Ustrchr(pattern, ';')) == NULL)
  {
  BOOL yield = cb->caseless?
    (strcmpic(s, pattern) == 0) : (Ustrcmp(s, pattern) == 0);
  if (yield && expand_setup >= 0) expand_nmax = expand_setup;
  return yield? OK : FAIL;
  }

/* Otherwise we have a lookup item. The lookup type, including partial, etc. is
the part of the string preceding the semicolon. */

*semicolon = 0;
search_type = search_findtype_partial(pattern, &partial, &affix, &affixlen,
  &starflags);
*semicolon = ';';
if (search_type < 0) log_write(0, LOG_MAIN|LOG_PANIC_DIE, "%s",
  search_error_message);

/* Partial matching is not appropriate for certain lookups (e.g. when looking
up user@domain for sender rejection). There's a flag to disable it. */

if (!cb->use_partial) partial = -1;

/* Set the parameters for the three different kinds of lookup. */

keyquery = semicolon + 1;
while (isspace(*keyquery)) keyquery++;

if (mac_islookup(search_type, lookup_absfilequery))
  {
  filename = keyquery;
  while (*keyquery != 0 && !isspace(*keyquery)) keyquery++;
  filename = string_copyn(filename, keyquery - filename);
  while (isspace(*keyquery)) keyquery++;
  }

else if (!mac_islookup(search_type, lookup_querystyle))
  {
  filename = keyquery;
  keyquery = s;
  }

/* Now do the actual lookup; throw away the data returned unless it was asked
for; partial matching is all handled inside search_find(). Note that there is
no search_close() because of the caching arrangements. */

if (!(handle = search_open(filename, search_type, 0, NULL, NULL)))
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "%s", search_error_message);
result = search_find(handle, filename, keyquery, partial, affix, affixlen,
  starflags, &expand_setup);

if (!result) return f.search_find_defer? DEFER : FAIL;
if (valueptr) *valueptr = result;

expand_nmax = expand_setup;
return OK;
}



/*************************************************
*      Public interface to check_string()        *
*************************************************/

/* This function is called from several places where is it most convenient to
pass the arguments individually. It places them in a check_string_block
structure, and then calls check_string().

Arguments:
  s            the subject string to be checked
  pattern      the pattern to check it against
  expand_setup expansion setup option (see check_string())
  use_partial  if FALSE, override any partial- search types
  caseless     TRUE for caseless matching where possible
  at_is_special TRUE to recognize @, @[], etc.
  valueptr     if not NULL, and a file lookup was done, return the result
                 here instead of discarding it; else set it to point to NULL

Returns:       OK    if matched
               FAIL  if not matched
               DEFER if lookup deferred
*/

int
match_check_string(const uschar *s, const uschar *pattern, int expand_setup,
  BOOL use_partial, BOOL caseless, BOOL at_is_special, const uschar **valueptr)
{
check_string_block cb;
cb.origsubject = s;
cb.subject = caseless? string_copylc(s) : string_copy(s);
cb.expand_setup = expand_setup;
cb.use_partial = use_partial;
cb.caseless = caseless;
cb.at_is_special = at_is_special;
return check_string(&cb, pattern, valueptr, NULL);
}



/*************************************************
*       Get key string from check block          *
*************************************************/

/* When caching the data from a lookup for a named list, we have to save the
key that was found, because other lookups of different keys on the same list
may occur. This function has knowledge of the different lookup types, and
extracts the appropriate key.

Arguments:
  arg          the check block
  type         MCL_STRING, MCL_DOMAIN, MCL_HOST, MCL_ADDRESS, or MCL_LOCALPART
*/

static const uschar *
get_check_key(void *arg, int type)
{
switch(type)
  {
  case MCL_STRING:
  case MCL_DOMAIN:
  case MCL_LOCALPART:
  return ((check_string_block *)arg)->subject;

  case MCL_HOST:
  return ((check_host_block *)arg)->host_address;

  case MCL_ADDRESS:
  return ((check_address_block *)arg)->address;
  }
return US"";  /* In practice, should never happen */
}



/*************************************************
*       Scan list and run matching function      *
*************************************************/

/* This function scans a list of patterns, and runs a matching function for
each item in the list. It is called from the functions that match domains,
local parts, hosts, and addresses, because its overall structure is the same in
all cases. However, the details of each particular match is different, so it
calls back to a given function do perform an actual match.

We can't quite keep the different types anonymous here because they permit
different special cases. A pity.

If a list item starts with !, that implies negation if the subject matches the
rest of the item (ignoring white space after the !). The result when the end of
the list is reached is FALSE unless the last item on the list is negated, in
which case it is TRUE. A file name in the list causes its lines to be
interpolated as if items in the list. An item starting with + is a named
sublist, obtained by searching the tree pointed to by anchorptr, with possible
cached match results in cache_bits.

Arguments:
  listptr      pointer to the pointer to the list
  sep          separator character for string_nextinlist();
                 normally zero for a standard list;
                 sometimes UCHAR_MAX+1 for single items;
  anchorptr    -> tree of named items, or NULL if no named items
  cache_ptr    pointer to pointer to cache bits for named items, or
                 pointer to NULL if not caching; may get set NULL if an
                 uncacheable named list is encountered
  func         function to call back to do one test
  arg          pointer to pass to the function; the string to be matched is
                 in the structure it points to
  type         MCL_STRING, MCL_DOMAIN, MCL_HOST, MCL_ADDRESS, or MCL_LOCALPART
                 these are used for some special handling
               MCL_NOEXPAND (whose value is greater than any of them) may
                 be added to any value to suppress expansion of the list
  name         string to use in debugging info
  valueptr     where to pass back data from a lookup

Returns:       OK    if matched a non-negated item
               OK    if hit end of list after a negated item
               FAIL  if expansion force-failed
               FAIL  if matched a negated item
               FAIL  if hit end of list after a non-negated item
               DEFER if a something deferred or expansion failed
*/

int
match_check_list(const uschar **listptr, int sep, tree_node **anchorptr,
  unsigned int **cache_ptr, int (*func)(void *,const uschar *,const uschar **,uschar **),
  void *arg, int type, const uschar *name, const uschar **valueptr)
{
int yield = OK;
unsigned int *original_cache_bits = *cache_ptr;
BOOL include_unknown = FALSE;
BOOL ignore_unknown = FALSE;
BOOL include_defer = FALSE;
BOOL ignore_defer = FALSE;
const uschar *list;
uschar *sss;
uschar *ot = NULL;
uschar buffer[1024];

/* Save time by not scanning for the option name when we don't need it. */

HDEBUG(D_any)
  {
  uschar *listname = readconf_find_option(listptr);
  if (listname[0] != 0) ot = string_sprintf("%s in %s?", name, listname);
  }

/* If the list is empty, the answer is no. Skip the debugging output for
an unnamed list. */

if (!*listptr)
  {
  HDEBUG(D_lists) if (ot) debug_printf("%s no (option unset)\n", ot);
  return FAIL;
  }

/* Expand the list before we scan it. A forced expansion gives the answer
"not in list"; other expansion errors cause DEFER to be returned. However,
if the type value is greater than or equal to than MCL_NOEXPAND, do not expand
the list. */

if (type >= MCL_NOEXPAND)
  {
  list = *listptr;
  type -= MCL_NOEXPAND;       /* Remove the "no expand" flag */
  }
else
  {
  /* If we are searching a domain list, and $domain is not set, set it to the
  subject that is being sought for the duration of the expansion. */

  if (type == MCL_DOMAIN && !deliver_domain)
    {
    check_string_block *cb = (check_string_block *)arg;
    deliver_domain = string_copy(cb->subject);
    list = expand_cstring(*listptr);
    deliver_domain = NULL;
    }
  else
    list = expand_cstring(*listptr);

  if (!list)
    {
    if (f.expand_string_forcedfail)
      {
      HDEBUG(D_lists) debug_printf("expansion of \"%s\" forced failure: "
        "assume not in this list\n", *listptr);
      return FAIL;
      }
    log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand \"%s\" while checking "
      "a list: %s", *listptr, expand_string_message);
    return DEFER;
    }
  }

/* For an unnamed list, use the expanded version in comments */

HDEBUG(D_any) if (ot == NULL) ot = string_sprintf("%s in \"%s\"?", name, list);

/* Now scan the list and process each item in turn, until one of them matches,
or we hit an error. */

while ((sss = string_nextinlist(&list, &sep, buffer, sizeof(buffer))))
  {
  uschar * ss = sss;

  /* Address lists may contain +caseful, to restore caseful matching of the
  local part. We have to know the layout of the control block, unfortunately.
  The lower cased address is in a temporary buffer, so we just copy the local
  part back to the start of it (if a local part exists). */

  if (type == MCL_ADDRESS)
    {
    if (Ustrcmp(ss, "+caseful") == 0)
      {
      check_address_block *cb = (check_address_block *)arg;
      uschar *at = Ustrrchr(cb->origaddress, '@');

      if (at)
        Ustrncpy(cb->address, cb->origaddress, at - cb->origaddress);
      cb->caseless = FALSE;
      continue;
      }
    }

  /* Similar processing for local parts */

  else if (type == MCL_LOCALPART)
    {
    if (Ustrcmp(ss, "+caseful") == 0)
      {
      check_string_block *cb = (check_string_block *)arg;
      Ustrcpy(cb->subject, cb->origsubject);
      cb->caseless = FALSE;
      continue;
      }
    }

  /* If the host item is "+include_unknown" or "+ignore_unknown", remember it
  in case there's a subsequent failed reverse lookup. There is similar
  processing for "defer". */

  else if (type == MCL_HOST && *ss == '+')
    {
    if (Ustrcmp(ss, "+include_unknown") == 0)
      {
      include_unknown = TRUE;
      ignore_unknown = FALSE;
      continue;
      }
    if (Ustrcmp(ss, "+ignore_unknown") == 0)
      {
      ignore_unknown = TRUE;
      include_unknown = FALSE;
      continue;
      }
    if (Ustrcmp(ss, "+include_defer") == 0)
      {
      include_defer = TRUE;
      ignore_defer = FALSE;
      continue;
      }
    if (Ustrcmp(ss, "+ignore_defer") == 0)
      {
      ignore_defer = TRUE;
      include_defer = FALSE;
      continue;
      }
    }

  /* Starting with ! specifies a negative item. It is theoretically possible
  for a local part to start with !. In that case, a regex has to be used. */

  if (*ss == '!')
    {
    yield = FAIL;
    while (isspace((*(++ss))));
    }
  else
    yield = OK;

  /* If the item does not begin with '/', it might be a + item for a named
  list. Otherwise, it is just a single list entry that has to be matched.
  We recognize '+' only when supplied with a tree of named lists. */

  if (*ss != '/')
    {
    if (*ss == '+' && anchorptr)
      {
      int bits = 0;
      int offset = 0;
      int shift = 0;
      unsigned int *use_cache_bits = original_cache_bits;
      uschar *cached = US"";
      namedlist_block *nb;
      tree_node * t;

      if (!(t = tree_search(*anchorptr, ss+1)))
	{
        log_write(0, LOG_MAIN|LOG_PANIC, "unknown named%s list \"%s\"",
          type == MCL_DOMAIN ?    " domain" :
          type == MCL_HOST ?      " host" :
          type == MCL_ADDRESS ?   " address" :
          type == MCL_LOCALPART ? " local part" : "",
          ss);
	return DEFER;
	}
      nb = t->data.ptr;

      /* If the list number is negative, it means that this list is not
      cacheable because it contains expansion items. */

      if (nb->number < 0) use_cache_bits = NULL;

      /* If we have got a cache pointer, get the bits. This is not an "else"
      because the pointer may be NULL from the start if caching is not
      required. */

      if (use_cache_bits)
        {
        offset = (nb->number)/16;
        shift = ((nb->number)%16)*2;
        bits = use_cache_bits[offset] & (3 << shift);
        }

      /* Not previously tested or no cache - run the full test */

      if (bits == 0)
        {
        switch (match_check_list(&(nb->string), 0, anchorptr, &use_cache_bits,
                func, arg, type, name, valueptr))
          {
          case OK:   bits = 1; break;
          case FAIL: bits = 3; break;
          case DEFER: goto DEFER_RETURN;
          }

        /* If this list was uncacheable, or a sublist turned out to be
        uncacheable, the value of use_cache_bits will now be NULL, even if it
        wasn't before. Ensure that this is passed up to the next level.
        Otherwise, remember the result of the search in the cache. */

        if (!use_cache_bits)
          *cache_ptr = NULL;
        else
          {
          use_cache_bits[offset] |= bits << shift;

          if (valueptr)
            {
            int old_pool = store_pool;
            namedlist_cacheblock *p;

            /* Cached data for hosts persists over more than one message,
            so we use the permanent store pool */

            store_pool = POOL_PERM;
            p = store_get(sizeof(namedlist_cacheblock));
            p->key = string_copy(get_check_key(arg, type));


            p->data = *valueptr ? string_copy(*valueptr) : NULL;
            store_pool = old_pool;

            p->next = nb->cache_data;
            nb->cache_data = p;
            if (*valueptr)
              DEBUG(D_lists) debug_printf("data from lookup saved for "
                "cache for %s: %s\n", ss, *valueptr);
            }
          }
        }

       /* Previously cached; to find a lookup value, search a chain of values
       and compare keys. Typically, there is only one such, but it is possible
       for different keys to have matched the same named list. */

      else
        {
        DEBUG(D_lists) debug_printf("cached %s match for %s\n",
          ((bits & (-bits)) == bits)? "yes" : "no", ss);

        cached = US" - cached";
        if (valueptr)
          {
          const uschar *key = get_check_key(arg, type);
          namedlist_cacheblock *p;
          for (p = nb->cache_data; p; p = p->next)
            if (Ustrcmp(key, p->key) == 0)
              {
              *valueptr = p->data;
              break;
              }
          DEBUG(D_lists) debug_printf("cached lookup data = %s\n", *valueptr);
          }
        }

      /* Result of test is indicated by value in bits. For each test, we
      have 00 => untested, 01 => tested yes, 11 => tested no. */

      if ((bits & (-bits)) == bits)    /* Only one of the two bits is set */
        {
        HDEBUG(D_lists) debug_printf("%s %s (matched \"%s\"%s)\n", ot,
          (yield == OK)? "yes" : "no", sss, cached);
        return yield;
        }
      }

    /* Run the provided function to do the individual test. */

    else
      {
      uschar * error = NULL;
      switch ((func)(arg, ss, valueptr, &error))
        {
        case OK:
	  HDEBUG(D_lists) debug_printf("%s %s (matched \"%s\")\n", ot,
	    (yield == OK)? "yes" : "no", sss);
	  return yield;

        case DEFER:
	  if (!error)
	    error = string_sprintf("DNS lookup of \"%s\" deferred", ss);
	  if (ignore_defer)
	    {
	    HDEBUG(D_lists) debug_printf("%s: item ignored by +ignore_defer\n",
	      error);
	    break;
	    }
	  if (include_defer)
	    {
	    log_write(0, LOG_MAIN, "%s: accepted by +include_defer", error);
	    return OK;
	    }
	  if (!search_error_message) search_error_message = error;
	  goto DEFER_RETURN;

        /* The ERROR return occurs when checking hosts, when either a forward
        or reverse lookup has failed. It can also occur in a match_ip list if a
        non-IP address item is encountered. The error string gives details of
        which it was. */

        case ERROR:
	  if (ignore_unknown)
	    {
	    HDEBUG(D_lists) debug_printf("%s: item ignored by +ignore_unknown\n",
	      error);
	    }
	  else
	    {
	    HDEBUG(D_lists) debug_printf("%s %s (%s)\n", ot,
	      include_unknown? "yes":"no", error);
	    if (!include_unknown)
	      {
	      if (LOGGING(unknown_in_list))
		log_write(0, LOG_MAIN, "list matching forced to fail: %s", error);
	      return FAIL;
	      }
	    log_write(0, LOG_MAIN, "%s: accepted by +include_unknown", error);
	    return OK;
	    }
        }
      }
    }

  /* If the item is a file name, we read the file and do a match attempt
  on each line in the file, including possibly more negation processing. */

  else
    {
    int file_yield = yield;       /* In case empty file */
    uschar * filename = ss;
    FILE * f = Ufopen(filename, "rb");
    uschar filebuffer[1024];

    /* ot will be null in non-debugging cases, and anyway, we get better
    wording by reworking it. */

    if (!f)
      {
      uschar * listname = readconf_find_option(listptr);
      if (listname[0] == 0)
        listname = string_sprintf("\"%s\"", *listptr);
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "%s",
        string_open_failed(errno, "%s when checking %s", sss, listname));
      }

    /* Trailing comments are introduced by #, but in an address list or local
    part list, the # must be preceded by white space or the start of the line,
    because the # character is a legal character in local parts. */

    while (Ufgets(filebuffer, sizeof(filebuffer), f) != NULL)
      {
      uschar *error;
      uschar *sss = filebuffer;

      while ((ss = Ustrchr(sss, '#')) != NULL)
        {
        if ((type != MCL_ADDRESS && type != MCL_LOCALPART) ||
              ss == filebuffer || isspace(ss[-1]))
          {
          *ss = 0;
          break;
          }
        sss = ss + 1;
        }

      ss = filebuffer + Ustrlen(filebuffer);             /* trailing space */
      while (ss > filebuffer && isspace(ss[-1])) ss--;
      *ss = 0;

      ss = filebuffer;
      while (isspace(*ss)) ss++;                         /* leading space */

      if (*ss == 0) continue;                            /* ignore empty */

      file_yield = yield;                                /* positive yield */
      sss = ss;                                          /* for debugging */

      if (*ss == '!')                                    /* negation */
        {
        file_yield = (file_yield == OK)? FAIL : OK;
        while (isspace((*(++ss))));
        }

      switch ((func)(arg, ss, valueptr, &error))
        {
        case OK:
	  (void)fclose(f);
	  HDEBUG(D_lists) debug_printf("%s %s (matched \"%s\" in %s)\n", ot,
	    yield == OK ? "yes" : "no", sss, filename);
	  return file_yield;

        case DEFER:
	  if (!error)
	    error = string_sprintf("DNS lookup of %s deferred", ss);
	  if (ignore_defer)
	    {
	    HDEBUG(D_lists) debug_printf("%s: item ignored by +ignore_defer\n",
	      error);
	    break;
	    }
	  (void)fclose(f);
	  if (include_defer)
	    {
	    log_write(0, LOG_MAIN, "%s: accepted by +include_defer", error);
	    return OK;
	    }
	  goto DEFER_RETURN;

        case ERROR:		/* host name lookup failed - this can only */
	  if (ignore_unknown)	/* be for an incoming host (not outgoing) */
	    {
	    HDEBUG(D_lists) debug_printf("%s: item ignored by +ignore_unknown\n",
	      error);
	    }
	  else
	   {
	    HDEBUG(D_lists) debug_printf("%s %s (%s)\n", ot,
	      include_unknown? "yes":"no", error);
	    (void)fclose(f);
	    if (!include_unknown)
	      {
	      if (LOGGING(unknown_in_list))
		log_write(0, LOG_MAIN, "list matching forced to fail: %s", error);
	      return FAIL;
	      }
	    log_write(0, LOG_MAIN, "%s: accepted by +include_unknown", error);
	    return OK;
	    }
        }
      }

    /* At the end of the file, leave the yield setting at the final setting
    for the file, in case this is the last item in the list. */

    yield = file_yield;
    (void)fclose(f);
    }
  }    /* Loop for the next item on the top-level list */

/* End of list reached: if the last item was negated yield OK, else FAIL. */

HDEBUG(D_lists)
  debug_printf("%s %s (end of list)\n", ot, yield == OK ? "no":"yes");
return yield == OK ? FAIL : OK;

/* Something deferred */

DEFER_RETURN:
HDEBUG(D_lists) debug_printf("%s list match deferred for %s\n", ot, sss);
return DEFER;
}


/*************************************************
*          Match in colon-separated list         *
*************************************************/

/* This function is used for domain lists and local part lists. It is not used
for host lists or address lists, which have additional interpretation of the
patterns. Some calls of it set sep > UCHAR_MAX in order to use its matching
facilities on single items. When this is done, it arranges to set the numerical
variables as a result of the match.

This function is now just a short interface to match_check_list(), which does
list scanning in a general way. A good compiler will optimize the tail
recursion.

Arguments:
  s              string to search for
  listptr        ptr to ptr to colon separated list of patterns, or NULL
  sep            a separator value for the list (see string_nextinlist())
  anchorptr      ptr to tree for named items, or NULL if no named items
  cache_bits     ptr to cache_bits for ditto, or NULL if not caching
  type           MCL_DOMAIN when matching a domain list
                 MCL_LOCALPART when matching a local part list (address lists
                   have their own function)
                 MCL_STRING for others (e.g. list of ciphers)
                 MCL_NOEXPAND (whose value is greater than any of them) may
                   be added to any value to suppress expansion of the list
  caseless       TRUE for (mostly) caseless matching - passed directly to
                   match_check_string()
  valueptr       pointer to where any lookup data is to be passed back,
                 or NULL (just passed on to match_check_string)

Returns:         OK    if matched a non-negated item
                 OK    if hit end of list after a negated item
                 FAIL  if expansion force-failed
                 FAIL  if matched a negated item
                 FAIL  if hit end of list after a non-negated item
                 DEFER if a lookup deferred
*/

int
match_isinlist(const uschar *s, const uschar **listptr, int sep,
   tree_node **anchorptr,
  unsigned int *cache_bits, int type, BOOL caseless, const uschar **valueptr)
{
unsigned int *local_cache_bits = cache_bits;
check_string_block cb;
cb.origsubject = s;
cb.subject = caseless? string_copylc(s) : string_copy(s);
cb.expand_setup = (sep > UCHAR_MAX)? 0 : -1;
cb.use_partial = TRUE;
cb.caseless = caseless;
cb.at_is_special = (type == MCL_DOMAIN || type == MCL_DOMAIN + MCL_NOEXPAND);
if (valueptr != NULL) *valueptr = NULL;
return  match_check_list(listptr, sep, anchorptr, &local_cache_bits,
  check_string, &cb, type, s, valueptr);
}



/*************************************************
*    Match address to single address-list item   *
*************************************************/

/* This function matches an address to an item from an address list. It is
called from match_address_list() via match_check_list(). That is why most of
its arguments are in an indirect block.

Arguments:
  arg            the argument block (see below)
  pattern        the pattern to match
  valueptr       where to return a value
  error          for error messages (not used in this function; it never
                   returns ERROR)

The argument block contains:
  address        the start of the subject address; when called from retry.c
                   it may be *@domain if the local part isn't relevant
  origaddress    the original, un-case-forced address (not used here, but used
                   in match_check_list() when +caseful is encountered)
  expand_setup   controls setting up of $n variables
  caseless       TRUE for caseless local part matching

Returns:         OK     for a match
                 FAIL   for no match
                 DEFER  if a lookup deferred
*/

static int
check_address(void *arg, const uschar *pattern, const uschar **valueptr, uschar **error)
{
check_address_block *cb = (check_address_block *)arg;
check_string_block csb;
int rc;
int expand_inc = 0;
unsigned int *null = NULL;
const uschar *listptr;
uschar *subject = cb->address;
const uschar *s;
uschar *pdomain, *sdomain;

error = error;  /* Keep clever compilers from complaining */

DEBUG(D_lists) debug_printf("address match test: subject=%s pattern=%s\n",
  subject, pattern);

/* Find the subject's domain */

sdomain = Ustrrchr(subject, '@');

/* The only case where a subject may not have a domain is if the subject is
empty. Otherwise, a subject with no domain is a serious configuration error. */

if (sdomain == NULL && *subject != 0)
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "no @ found in the subject of an "
    "address list match: subject=\"%s\" pattern=\"%s\"", subject, pattern);
  return FAIL;
  }

/* Handle a regular expression, which must match the entire incoming address.
This may be the empty address. */

if (*pattern == '^')
  return match_check_string(subject, pattern, cb->expand_setup, TRUE,
    cb->caseless, FALSE, NULL);

/* Handle a pattern that is just a lookup. Skip over possible lookup names
(letters, digits, hyphens). Skip over a possible * or *@ at the end. Then we
must have a semicolon for it to be a lookup. */

for (s = pattern; isalnum(*s) || *s == '-'; s++);
if (*s == '*') s++;
if (*s == '@') s++;

/* If it is a straight lookup, do a lookup for the whole address. This may be
the empty address. Partial matching doesn't make sense here, so we ignore it,
but write a panic log entry. However, *@ matching will be honoured. */

if (*s == ';')
  {
  if (Ustrncmp(pattern, "partial-", 8) == 0)
    log_write(0, LOG_MAIN|LOG_PANIC, "partial matching is not applicable to "
      "whole-address lookups: ignored \"partial-\" in \"%s\"", pattern);
  return match_check_string(subject, pattern, -1, FALSE, cb->caseless, FALSE,
    valueptr);
  }

/* For the remaining cases, an empty subject matches only an empty pattern,
because other patterns expect to have a local part and a domain to match
against. */

if (*subject == 0) return (*pattern == 0)? OK : FAIL;

/* If the pattern starts with "@@" we have a split lookup, where the domain is
looked up to obtain a list of local parts. If the subject's local part is just
"*" (called from retry) the match always fails. */

if (pattern[0] == '@' && pattern[1] == '@')
  {
  int watchdog = 50;
  const uschar *key;
  uschar *list, *ss;
  uschar buffer[1024];

  if (sdomain == subject + 1 && *subject == '*') return FAIL;

  /* Loop for handling chains. The last item in any list may be of the form
  ">name" in order to chain on to another list. */

  for (key = sdomain + 1; key != NULL && watchdog-- > 0; )
    {
    int sep = 0;

    if ((rc = match_check_string(key, pattern + 2, -1, TRUE, FALSE, FALSE,
      CUSS &list)) != OK) return rc;

    /* Check for chaining from the last item; set up the next key if one
    is found. */

    ss = Ustrrchr(list, ':');
    if (ss == NULL) ss = list; else ss++;
    while (isspace(*ss)) ss++;
    if (*ss == '>')
      {
      *ss++ = 0;
      while (isspace(*ss)) ss++;
      key = string_copy(ss);
      }
    else key = NULL;

    /* Look up the local parts provided by the list; negation is permitted.
    If a local part has to begin with !, a regex can be used. */

    while ((ss = string_nextinlist(CUSS &list, &sep, buffer, sizeof(buffer))))
      {
      int local_yield;

      if (*ss == '!')
        {
        local_yield = FAIL;
        while (isspace((*(++ss))));
        }
      else local_yield = OK;

      *sdomain = 0;
      rc = match_check_string(subject, ss, -1, TRUE, cb->caseless, FALSE,
        valueptr);
      *sdomain = '@';

      switch(rc)
        {
        case OK:
        return local_yield;

        case DEFER:
        return DEFER;
        }
      }
    }

  /* End of chain loop; panic if too many times */

  if (watchdog <= 0)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "Loop detected in lookup of "
      "local part of %s in %s", subject, pattern);

  /* Otherwise the local part check has failed, so the whole match
  fails. */

  return FAIL;
  }


/* We get here if the pattern is not a lookup or a regular expression. If it
contains an @ there is both a local part and a domain. */

pdomain = Ustrrchr(pattern, '@');
if (pdomain != NULL)
  {
  int pllen, sllen;

  /* If the domain in the pattern is empty or one of the special cases [] or
  mx_{any,primary,secondary}, and the local part in the pattern ends in "@",
  we have a pattern of the form <something>@@, <something>@@[], or
  <something>@@mx_{any,primary,secondary}. These magic "domains" are
  automatically interpreted in match_check_string. We just need to arrange that
  the leading @ is included in the domain. */

  if (pdomain > pattern && pdomain[-1] == '@' &&
       (pdomain[1] == 0 ||
        Ustrcmp(pdomain+1, "[]") == 0 ||
        Ustrcmp(pdomain+1, "mx_any") == 0 ||
        Ustrcmp(pdomain+1, "mx_primary") == 0 ||
        Ustrcmp(pdomain+1, "mx_secondary") == 0))
    pdomain--;

  pllen = pdomain - pattern;
  sllen = sdomain - subject;

  /* Compare the local parts in the subject and the pattern */

  if (*pattern == '*')
    {
    int cllen = pllen - 1;
    if (sllen < cllen) return FAIL;
    if (cb->caseless)
      {
      if (strncmpic(subject+sllen-cllen, pattern + 1, cllen) != 0)
        return FAIL;
      }
    else
      {
      if (Ustrncmp(subject+sllen-cllen, pattern + 1, cllen) != 0)
        return FAIL;
      }
    if (cb->expand_setup > 0)
      {
      expand_nstring[cb->expand_setup] = subject;
      expand_nlength[cb->expand_setup] = sllen - cllen;
      expand_inc = 1;
      }
    }
  else
    {
    if (sllen != pllen) return FAIL;
    if (cb->caseless)
      {
      if (strncmpic(subject, pattern, sllen) != 0) return FAIL;
      }
    else
      {
      if (Ustrncmp(subject, pattern, sllen) != 0) return FAIL;
      }
    }
  }

/* If the local part matched, or was not being checked, check the domain using
the generalized function, which supports file lookups (which may defer). The
original code read as follows:

  return match_check_string(sdomain + 1,
      (pdomain == NULL)? pattern : pdomain + 1,
      cb->expand_setup + expand_inc, TRUE, cb->caseless, TRUE, NULL);

This supported only literal domains and *.x.y patterns. In order to allow for
named domain lists (so that you can right, for example, "senders=+xxxx"), it
was changed to use the list scanning function. */

csb.origsubject = sdomain + 1;
csb.subject = (cb->caseless)? string_copylc(sdomain+1) : string_copy(sdomain+1);
csb.expand_setup = cb->expand_setup + expand_inc;
csb.use_partial = TRUE;
csb.caseless = cb->caseless;
csb.at_is_special = TRUE;

listptr = (pdomain == NULL)? pattern : pdomain + 1;
if (valueptr != NULL) *valueptr = NULL;

return match_check_list(
  &listptr,                  /* list of one item */
  UCHAR_MAX+1,               /* impossible separator; single item */
  &domainlist_anchor,        /* it's a domain list */
  &null,                     /* ptr to NULL means no caching */
  check_string,              /* the function to do one test */
  &csb,                      /* its data */
  MCL_DOMAIN + MCL_NOEXPAND, /* domain list; don't expand */
  csb.subject,               /* string for messages */
  valueptr);                 /* where to pass back lookup data */
}




/*************************************************
*    Test whether address matches address list   *
*************************************************/

/* This function is given an address and a list of things to match it against.
The list may contain individual addresses, regular expressions, lookup
specifications, and indirection via bare files. Negation is supported. The
address to check can consist of just a domain, which will then match only
domain items or items specified as *@domain.

Domains are always lower cased before the match. Local parts are also lower
cased unless "caseless" is false. The work of actually scanning the list is
done by match_check_list(), with an appropriate block of arguments and a
callback to check_address(). During caseless matching, it will recognize
+caseful and revert to caseful matching.

Arguments:
  address         address to test
  caseless        TRUE to start in caseless state
  expand          TRUE to allow list expansion
  listptr         list to check against
  cache_bits      points to cache bits for named address lists, or NULL
  expand_setup    controls setting up of $n variables - passed through
                  to check_address (q.v.)
  sep             separator character for the list;
                  may be 0 to get separator from the list;
                  may be UCHAR_MAX+1 for one-item list
  valueptr        where to return a lookup value, or NULL

Returns:          OK    for a positive match, or end list after a negation;
                  FAIL  for a negative match, or end list after non-negation;
                  DEFER if a lookup deferred
*/

int
match_address_list(const uschar *address, BOOL caseless, BOOL expand,
  const uschar **listptr, unsigned int *cache_bits, int expand_setup, int sep,
  const uschar **valueptr)
{
uschar *p;
check_address_block ab;
unsigned int *local_cache_bits = cache_bits;

/* RFC 2505 recommends that for spam checking, local parts should be caselessly
compared. Therefore, Exim now forces the entire address into lower case here,
provided that "caseless" is set. (It is FALSE for calls for matching rewriting
patterns.) Otherwise just the domain is lower cases. A magic item "+caseful" in
the list can be used to restore a caseful copy of the local part from the
original address. */

sprintf(CS big_buffer, "%.*s", big_buffer_size - 1, address);
for (p = big_buffer + Ustrlen(big_buffer) - 1; p >= big_buffer; p--)
  {
  if (!caseless && *p == '@') break;
  *p = tolower(*p);
  }

/* If expand_setup is zero, we need to set up $0 to the whole thing, in
case there is a match. Can't use the built-in facilities of match_check_string
(via check_address), as we may just be calling that for part of the address
(the domain). */

if (expand_setup == 0)
  {
  expand_nstring[0] = string_copy(address);
  expand_nlength[0] = Ustrlen(address);
  expand_setup++;
  }

/* Set up the data to be passed ultimately to check_address. */

ab.origaddress = address;
ab.address = big_buffer;
ab.expand_setup = expand_setup;
ab.caseless = caseless;

return match_check_list(listptr, sep, &addresslist_anchor, &local_cache_bits,
  check_address, &ab, MCL_ADDRESS + (expand? 0:MCL_NOEXPAND), address,
    valueptr);
}

/* Simpler version of match_address_list; always caseless, expanding,
no cache bits, no value-return.

Arguments:
  address         address to test
  listptr         list to check against
  sep             separator character for the list;
                  may be 0 to get separator from the list;
                  may be UCHAR_MAX+1 for one-item list

Returns:          OK    for a positive match, or end list after a negation;
                  FAIL  for a negative match, or end list after non-negation;
                  DEFER if a lookup deferred
*/

int
match_address_list_basic(const uschar *address, const uschar **listptr, int sep)
{
return match_address_list(address, TRUE, TRUE, listptr, NULL, -1, sep, NULL);
}

/* End of match.c */
