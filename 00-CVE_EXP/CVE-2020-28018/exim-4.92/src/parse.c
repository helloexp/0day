/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions for parsing addresses */


#include "exim.h"


static uschar *last_comment_position;



/* In stand-alone mode, provide a replacement for deliver_make_addr()
and rewrite_address[_qualify]() so as to avoid having to drag in too much
redundant apparatus. */

#ifdef STAND_ALONE

address_item *deliver_make_addr(uschar *address, BOOL copy)
{
address_item *addr = store_get(sizeof(address_item));
addr->next = NULL;
addr->parent = NULL;
addr->address = address;
return addr;
}

uschar *rewrite_address(uschar *recipient, BOOL dummy1, BOOL dummy2, rewrite_rule
  *dummy3, int dummy4)
{
return recipient;
}

uschar *rewrite_address_qualify(uschar *recipient, BOOL dummy1)
{
return recipient;
}

#endif




/*************************************************
*             Find the end of an address         *
*************************************************/

/* Scan over a string looking for the termination of an address at a comma,
or end of the string. It's the source-routed addresses which cause much pain
here. Although Exim ignores source routes, it must recognize such addresses, so
we cannot get rid of this logic.

Argument:
  s        pointer to the start of an address
  nl_ends  if TRUE, '\n' terminates an address

Returns:   pointer past the end of the address
           (i.e. points to null or comma)
*/

uschar *
parse_find_address_end(uschar *s, BOOL nl_ends)
{
BOOL source_routing = *s == '@';
int no_term = source_routing? 1 : 0;

while (*s != 0 && (*s != ',' || no_term > 0) && (*s != '\n' || !nl_ends))
  {
  /* Skip single quoted characters. Strictly these should not occur outside
  quoted strings in RFC 822 addresses, but they can in RFC 821 addresses. Pity
  about the lack of consistency, isn't it? */

  if (*s == '\\' && s[1] != 0) s += 2;

  /* Skip quoted items that are not inside brackets. Note that
  quoted pairs are allowed inside quoted strings. */

  else if (*s == '\"')
    {
    while (*(++s) != 0 && (*s != '\n' || !nl_ends))
      {
      if (*s == '\\' && s[1] != 0) s++;
        else if (*s == '\"') { s++; break; }
      }
    }

  /* Skip comments, which may include nested brackets, but quotes
  are not recognized inside comments, though quoted pairs are. */

  else if (*s == '(')
    {
    int level = 1;
    while (*(++s) != 0 && (*s != '\n' || !nl_ends))
      {
      if (*s == '\\' && s[1] != 0) s++;
        else if (*s == '(') level++;
          else if (*s == ')' && --level <= 0) { s++; break; }
      }
    }

  /* Non-special character; just advance. Passing the colon in a source
  routed address means that any subsequent comma or colon may terminate unless
  inside angle brackets. */

  else
    {
    if (*s == '<')
      {
      source_routing = s[1] == '@';
      no_term = source_routing? 2 : 1;
      }
    else if (*s == '>') no_term--;
    else if (source_routing && *s == ':') no_term--;
    s++;
    }
  }

return s;
}



/*************************************************
*            Find last @ in an address           *
*************************************************/

/* This function is used when we have something that may not qualified. If we
know it's qualified, searching for the rightmost '@' is sufficient. Here we
have to be a bit more clever than just a plain search, in order to handle
unqualified local parts like "thing@thong" correctly. Since quotes may not
legally be part of a domain name, we can give up on hitting the first quote
when searching from the right. Now that the parsing also permits the RFC 821
form of address, where quoted-pairs are allowed in unquoted local parts, we
must take care to handle that too.

Argument:  pointer to an address, possibly unqualified
Returns:   pointer to the last @ in an address, or NULL if none
*/

uschar *
parse_find_at(uschar *s)
{
uschar *t = s + Ustrlen(s);
while (--t >= s)
  {
  if (*t == '@')
    {
    int backslash_count = 0;
    uschar *tt = t - 1;
    while (tt > s && *tt-- == '\\') backslash_count++;
    if ((backslash_count & 1) == 0) return t;
    }
  else if (*t == '\"') return NULL;
  }
return NULL;
}




/***************************************************************************
* In all the functions below that read a particular object type from       *
* the input, return the new value of the pointer s (the first argument),   *
* and put the object into the store pointed to by t (the second argument), *
* adding a terminating zero. If no object is found, t will point to zero   *
* on return.                                                               *
***************************************************************************/


/*************************************************
*          Skip white space and comment          *
*************************************************/

/* Algorithm:
  (1) Skip spaces.
  (2) If uschar not '(', return.
  (3) Skip till matching ')', not counting any characters
      escaped with '\'.
  (4) Move past ')' and goto (1).

The start of the last potential comment position is remembered to
make it possible to ignore comments at the end of compound items.

Argument: current character pointer
Returns:  new character pointer
*/

static uschar *
skip_comment(uschar *s)
{
last_comment_position = s;
while (*s)
  {
  int c, level;
  while (isspace(*s)) s++;
  if (*s != '(') break;
  level = 1;
  while((c = *(++s)) != 0)
    {
    if (c == '(') level++;
    else if (c == ')') { if (--level <= 0) { s++; break; } }
    else if (c == '\\' && s[1] != 0) s++;
    }
  }
return s;
}



/*************************************************
*             Read a domain                      *
*************************************************/

/* A domain is a sequence of subdomains, separated by dots. See comments below
for detailed syntax of the subdomains.

If allow_domain_literals is TRUE, a "domain" may also be an IP address enclosed
in []. Make sure the output is set to the null string if there is a syntax
error as well as if there is no domain at all.

Arguments:
  s          current character pointer
  t          where to put the domain
  errorptr   put error message here on failure (*t will be 0 on exit)

Returns:     new character pointer
*/

static uschar *
read_domain(uschar *s, uschar *t, uschar **errorptr)
{
uschar *tt = t;
s = skip_comment(s);

/* Handle domain literals if permitted. An RFC 822 domain literal may contain
any character except [ ] \, including linear white space, and may contain
quoted characters. However, RFC 821 restricts literals to being dot-separated
3-digit numbers, and we make the obvious extension for IPv6. Go for a sequence
of digits, dots, hex digits, and colons here; later this will be checked for
being a syntactically valid IP address if it ever gets to a router.

Allow both the formal IPv6 form, with IPV6: at the start, and the informal form
without it, and accept IPV4: as well, 'cause someone will use it sooner or
later. */

if (*s == '[')
  {
  *t++ = *s++;

  if (strncmpic(s, US"IPv6:", 5) == 0 || strncmpic(s, US"IPv4:", 5) == 0)
    {
    memcpy(t, s, 5);
    t += 5;
    s += 5;
    }
  while (*s == '.' || *s == ':' || isxdigit(*s)) *t++ = *s++;

  if (*s == ']') *t++ = *s++; else
    {
    *errorptr = US"malformed domain literal";
    *tt = 0;
    }

  if (!allow_domain_literals)
    {
    *errorptr = US"domain literals not allowed";
    *tt = 0;
    }
  *t = 0;
  return skip_comment(s);
  }

/* Handle a proper domain, which is a sequence of dot-separated atoms. Remove
trailing dots if strip_trailing_dot is set. A subdomain is an atom.

An atom is a sequence of any characters except specials, space, and controls.
The specials are ( ) < > @ , ; : \ " . [ and ]. This is the rule for RFC 822
and its successor (RFC 2822). However, RFC 821 and its successor (RFC 2821) is
tighter, allowing only letters, digits, and hyphens, not starting with a
hyphen.

There used to be a global flag that got set when checking addresses that came
in over SMTP and which should therefore should be checked according to the
stricter rule. However, it seems silly to make the distinction, because I don't
suppose anybody ever uses local domains that are 822-compliant and not
821-compliant. Furthermore, Exim now has additional data on the spool file line
after an address (after "one_time" processing), and it makes use of a #
character to delimit it. When I wrote that code, I forgot about this 822-domain
stuff, and assumed # could never appear in a domain.

So the old code is now cut out for Release 4.11 onwards, on 09-Aug-02. In a few
years, when we are sure this isn't actually causing trouble, throw it away.

March 2003: the story continues: There is a camp that is arguing for the use of
UTF-8 in domain names as the way to internationalization, and other MTAs
support this. Therefore, we now have a flag that permits the use of characters
with values greater than 127, encoded in UTF-8, in subdomains, so that Exim can
be used experimentally in this way. */

for (;;)
  {
  uschar *tsave = t;

/*********************
  if (rfc821_domains)
    {
    if (*s != '-') while (isalnum(*s) || *s == '-') *t++ = *s++;
    }
  else
    while (!mac_iscntrl_or_special(*s)) *t++ = *s++;
*********************/

  if (*s != '-')
    {
    /* Only letters, digits, and hyphens */

    if (!allow_utf8_domains)
      {
      while (isalnum(*s) || *s == '-') *t++ = *s++;
      }

    /* Permit legal UTF-8 characters to be included */

    else for(;;)
      {
      int i, d;
      if (isalnum(*s) || *s == '-')    /* legal ascii characters */
        {
        *t++ = *s++;
        continue;
        }
      if ((*s & 0xc0) != 0xc0) break;  /* not start of UTF-8 character */
      d = *s << 2;
      for (i = 1; i < 6; i++)          /* i is the number of additional bytes */
        {
        if ((d & 0x80) == 0) break;
        d <<= 1;
        }
      if (i == 6) goto BAD_UTF8;       /* invalid UTF-8 */
      *t++ = *s++;                     /* leading UTF-8 byte */
      while (i-- > 0)                  /* copy and check remainder */
        {
        if ((*s & 0xc0) != 0x80)
          {
          BAD_UTF8:
          *errorptr = US"invalid UTF-8 byte sequence";
          *tt = 0;
          return s;
          }
        *t++ = *s++;
        }
      }    /* End of loop for UTF-8 character */
    }      /* End of subdomain */

  s = skip_comment(s);
  *t = 0;

  if (t == tsave)   /* empty component */
    {
    if (strip_trailing_dot && t > tt && *s != '.') t[-1] = 0; else
      {
      *errorptr = US"domain missing or malformed";
      *tt = 0;
      }
    return s;
    }

  if (*s != '.') break;
  *t++ = *s++;
  s = skip_comment(s);
  }

return s;
}



/*************************************************
*            Read a local-part                   *
*************************************************/

/* A local-part is a sequence of words, separated by periods. A null word
between dots is not strictly allowed but apparently many mailers permit it,
so, sigh, better be compatible. Even accept a trailing dot...

A <word> is either a quoted string, or an <atom>, which is a sequence
of any characters except specials, space, and controls. The specials are
( ) < > @ , ; : \ " . [ and ]. In RFC 822, a single quoted character, (a
quoted-pair) is not allowed in a word. However, in RFC 821, it is permitted in
the local part of an address. Rather than have separate parsing functions for
the different cases, take the liberal attitude always. At least one MUA is
happy to recognize this case; I don't know how many other programs do.

Arguments:
  s           current character pointer
  t           where to put the local part
  error       where to point error text
  allow_null  TRUE if an empty local part is not an error

Returns:   new character pointer
*/

static uschar *
read_local_part(uschar *s, uschar *t, uschar **error, BOOL allow_null)
{
uschar *tt = t;
*error = NULL;
for (;;)
  {
  int c;
  uschar *tsave = t;
  s = skip_comment(s);

  /* Handle a quoted string */

  if (*s == '\"')
    {
    *t++ = '\"';
    while ((c = *++s) && c != '\"')
      {
      *t++ = c;
      if (c == '\\' && s[1]) *t++ = *++s;
      }
    if (c == '\"')
      {
      s++;
      *t++ = '\"';
      }
    else
      {
      *error = US"unmatched doublequote in local part";
      return s;
      }
    }

  /* Handle an atom, but allow quoted pairs within it. */

  else while (!mac_iscntrl_or_special(*s) || *s == '\\')
    {
    c = *t++ = *s++;
    if (c == '\\' && *s) *t++ = *s++;
    }

  /* Terminate the word and skip subsequent comment */

  *t = 0;
  s = skip_comment(s);

  /* If we have read a null component at this point, give an error unless it is
  terminated by a dot - an extension to RFC 822 - or if it is the first
  component of the local part and an empty local part is permitted, in which
  case just return normally. */

  if (t == tsave && *s != '.')
    {
    if (t == tt && !allow_null)
      *error = US"missing or malformed local part";
    return s;
    }

  /* Anything other than a dot terminates the local part. Treat multiple dots
  as a single dot, as this seems to be a common extension. */

  if (*s != '.') break;
  do { *t++ = *s++; } while (*s == '.');
  }

return s;
}


/*************************************************
*            Read route part of route-addr       *
*************************************************/

/* The pointer is at the initial "@" on entry. Return it following the
terminating colon. Exim no longer supports the use of source routes, but it is
required to accept the syntax.

Arguments:
  s          current character pointer
  t          where to put the route
  errorptr   where to put an error message

Returns:     new character pointer
*/

static uschar *
read_route(uschar *s, uschar *t, uschar **errorptr)
{
BOOL commas = FALSE;
*errorptr = NULL;

while (*s == '@')
  {
  *t++ = '@';
  s = read_domain(s+1, t, errorptr);
  if (*t == 0) return s;
  t += Ustrlen((const uschar *)t);
  if (*s != ',') break;
  *t++ = *s++;
  commas = TRUE;
  s = skip_comment(s);
  }

if (*s == ':') *t++ = *s++;

/* If there is no colon, and there were no commas, the most likely error
is in fact a missing local part in the address rather than a missing colon
after the route. */

else *errorptr = commas?
  US"colon expected after route list" :
  US"no local part";

/* Terminate the route and return */

*t = 0;
return skip_comment(s);
}



/*************************************************
*                Read addr-spec                  *
*************************************************/

/* Addr-spec is local-part@domain. We make the domain optional -
the expected terminator for the whole thing is passed to check this.
This function is called only when we know we have a route-addr.

Arguments:
  s          current character pointer
  t          where to put the addr-spec
  term       expected terminator (0 or >)
  errorptr   where to put an error message
  domainptr  set to point to the start of the domain

Returns:     new character pointer
*/

static uschar *
read_addr_spec(uschar *s, uschar *t, int term, uschar **errorptr,
  uschar **domainptr)
{
s = read_local_part(s, t, errorptr, FALSE);
if (*errorptr == NULL)
  if (*s != term)
    if (*s != '@')
      *errorptr = string_sprintf("\"@\" or \".\" expected after \"%s\"", t);
    else
      {
      t += Ustrlen((const uschar *)t);
      *t++ = *s++;
      *domainptr = t;
      s = read_domain(s, t, errorptr);
      }
return s;
}



/*************************************************
*         Extract operative address              *
*************************************************/

/* This function extracts an operative address from a full RFC822 mailbox and
returns it in a piece of dynamic store. We take the easy way and get a piece
of store the same size as the input, and then copy into it whatever is
necessary. If we cannot find a valid address (syntax error), return NULL, and
point the error pointer to the reason. The arguments "start" and "end" are used
to return the offsets of the first and one past the last characters in the
original mailbox of the address that has been extracted, to aid in re-writing.
The argument "domain" is set to point to the first character after "@" in the
final part of the returned address, or zero if there is no @.

Exim no longer supports the use of source routed addresses (those of the form
@domain,...:route_addr). It recognizes the syntax, but collapses such addresses
down to their final components. Formerly, collapse_source_routes had to be set
to achieve this effect. RFC 1123 allows collapsing with MAY, while the revision
of RFC 821 had increased this to SHOULD, so I've gone for it, because it makes
a lot of code elsewhere in Exim much simpler.

There are some special fudges here for handling RFC 822 group address notation
which may appear in certain headers. If the flag parse_allow_group is set
TRUE and parse_found_group is FALSE when this function is called, an address
which is the start of a group (i.e. preceded by a phrase and a colon) is
recognized; the phrase is ignored and the flag parse_found_group is set. If
this flag is TRUE at the end of an address, and if an extraneous semicolon is
found, it is ignored and the flag is cleared.

This logic is used only when scanning through addresses in headers, either to
fulfil the -t option, or for rewriting, or for checking header syntax. Because
the group "state" has to be remembered between multiple calls of this function,
the variables parse_{allow,found}_group are global. It is important to ensure
that they are reset to FALSE at the end of scanning a header's list of
addresses.

Arguments:
  mailbox     points to the RFC822 mailbox
  errorptr    where to point an error message
  start       set to start offset in mailbox
  end         set to end offset in mailbox
  domain      set to domain offset in result, or 0 if no domain present
  allow_null  allow <> if TRUE

Returns:      points to the extracted address, or NULL on error
*/

#define FAILED(s) { *errorptr = s; goto PARSE_FAILED; }

uschar *
parse_extract_address(uschar *mailbox, uschar **errorptr, int *start, int *end,
  int *domain, BOOL allow_null)
{
uschar *yield = store_get(Ustrlen(mailbox) + 1);
uschar *startptr, *endptr;
uschar *s = US mailbox;
uschar *t = US yield;

*domain = 0;

/* At the start of the string we expect either an addr-spec or a phrase
preceding a <route-addr>. If groups are allowed, we might also find a phrase
preceding a colon and an address. If we find an initial word followed by
a dot, strict interpretation of the RFC would cause it to be taken
as the start of an addr-spec. However, many mailers break the rules
and use addresses of the form "a.n.other <ano@somewhere>" and so we
allow this case. */

RESTART:   /* Come back here after passing a group name */

s = skip_comment(s);
startptr = s;                                 /* In case addr-spec */
s = read_local_part(s, t, errorptr, TRUE);    /* Dot separated words */
if (*errorptr) goto PARSE_FAILED;

/* If the terminator is neither < nor @ then the format of the address
must either be a bare local-part (we are now at the end), or a phrase
followed by a route-addr (more words must follow). */

if (*s != '@' && *s != '<')
  {
  if (*s == 0 || *s == ';')
    {
    if (*t == 0) FAILED(US"empty address");
    endptr = last_comment_position;
    goto PARSE_SUCCEEDED;              /* Bare local part */
    }

  /* Expect phrase route-addr, or phrase : if groups permitted, but allow
  dots in the phrase; complete the loop only when '<' or ':' is encountered -
  end of string will produce a null local_part and therefore fail. We don't
  need to keep updating t, as the phrase isn't to be kept. */

  while (*s != '<' && (!f.parse_allow_group || *s != ':'))
    {
    s = read_local_part(s, t, errorptr, FALSE);
    if (*errorptr)
      {
      *errorptr = string_sprintf("%s (expected word or \"<\")", *errorptr);
      goto PARSE_FAILED;
      }
    }

  if (*s == ':')
    {
    f.parse_found_group = TRUE;
    f.parse_allow_group = FALSE;
    s++;
    goto RESTART;
    }

  /* Assert *s == '<' */
  }

/* At this point the next character is either '@' or '<'. If it is '@', only a
single local-part has previously been read. An angle bracket signifies the
start of an <addr-spec>. Throw away anything we have saved so far before
processing it. Note that this is "if" rather than "else if" because it's also
used after reading a preceding phrase.

There are a lot of broken sendmails out there that put additional pairs of <>
round <route-addr>s.  If strip_excess_angle_brackets is set, allow a limited
number of them, as long as they match. */

if (*s == '<')
  {
  uschar *domainptr = yield;
  BOOL source_routed = FALSE;
  int bracket_count = 1;

  s++;
  if (strip_excess_angle_brackets) while (*s == '<')
   {
   if(bracket_count++ > 5) FAILED(US"angle-brackets nested too deep");
   s++;
   }

  t = yield;
  startptr = s;
  s = skip_comment(s);

  /* Read an optional series of routes, each of which is a domain. They
  are separated by commas and terminated by a colon. However, we totally ignore
  such routes (RFC 1123 says we MAY, and the revision of RFC 821 says we
  SHOULD). */

  if (*s == '@')
    {
    s = read_route(s, t, errorptr);
    if (*errorptr) goto PARSE_FAILED;
    *t = 0;                  /* Ensure route is ignored - probably overkill */
    source_routed = TRUE;
    }

  /* Now an addr-spec, terminated by '>'. If there is no preceding route,
  we must allow an empty addr-spec if allow_null is TRUE, to permit the
  address "<>" in some circumstances. A source-routed address MUST have
  a domain in the final part. */

  if (allow_null && !source_routed && *s == '>')
    {
    *t = 0;
    *errorptr = NULL;
    }
  else
    {
    s = read_addr_spec(s, t, '>', errorptr, &domainptr);
    if (*errorptr) goto PARSE_FAILED;
    *domain = domainptr - yield;
    if (source_routed && *domain == 0)
      FAILED(US"domain missing in source-routed address");
    }

  endptr = s;
  if (*errorptr != NULL) goto PARSE_FAILED;
  while (bracket_count-- > 0) if (*s++ != '>')
    {
    *errorptr = s[-1] == 0
      ? US"'>' missing at end of address"
      : string_sprintf("malformed address: %.32s may not follow %.*s",
	  s-1, (int)(s - US mailbox - 1), mailbox);
    goto PARSE_FAILED;
    }

  s = skip_comment(s);
  }

/* Hitting '@' after the first local-part means we have definitely got an
addr-spec, on a strict reading of the RFC, and the rest of the string
should be the domain. However, for flexibility we allow for a route-address
not enclosed in <> as well, which is indicated by an empty first local
part preceding '@'. The source routing is, however, ignored. */

else if (*t == 0)
  {
  uschar *domainptr = yield;
  s = read_route(s, t, errorptr);
  if (*errorptr != NULL) goto PARSE_FAILED;
  *t = 0;         /* Ensure route is ignored - probably overkill */
  s = read_addr_spec(s, t, 0, errorptr, &domainptr);
  if (*errorptr != NULL) goto PARSE_FAILED;
  *domain = domainptr - yield;
  endptr = last_comment_position;
  if (*domain == 0) FAILED(US"domain missing in source-routed address");
  }

/* This is the strict case of local-part@domain. */

else
  {
  t += Ustrlen((const uschar *)t);
  *t++ = *s++;
  *domain = t - yield;
  s = read_domain(s, t, errorptr);
  if (*t == 0) goto PARSE_FAILED;
  endptr = last_comment_position;
  }

/* Use goto to get here from the bare local part case. Arrive by falling
through for other cases. Endptr may have been moved over whitespace, so
move it back past white space if necessary. */

PARSE_SUCCEEDED:
if (*s != 0)
  {
  if (f.parse_found_group && *s == ';')
    {
    f.parse_found_group = FALSE;
    f.parse_allow_group = TRUE;
    }
  else
    {
    *errorptr = string_sprintf("malformed address: %.32s may not follow %.*s",
      s, (int)(s - US mailbox), mailbox);
    goto PARSE_FAILED;
    }
  }
*start = startptr - US mailbox;      /* Return offsets */
while (isspace(endptr[-1])) endptr--;
*end = endptr - US mailbox;

/* Although this code has no limitation on the length of address extracted,
other parts of Exim may have limits, and in any case, RFC 2821 limits local
parts to 64 and domains to 255, so we do a check here, giving an error if the
address is ridiculously long. */

if (*end - *start > ADDRESS_MAXLENGTH)
  {
  *errorptr = string_sprintf("address is ridiculously long: %.64s...", yield);
  return NULL;
  }

return yield;

/* Use goto (via the macro FAILED) to get to here from a variety of places.
We might have an empty address in a group - the caller can choose to ignore
this. We must, however, keep the flags correct. */

PARSE_FAILED:
if (f.parse_found_group && *s == ';')
  {
  f.parse_found_group = FALSE;
  f.parse_allow_group = TRUE;
  }
return NULL;
}

#undef FAILED



/*************************************************
*        Quote according to RFC 2047             *
*************************************************/

/* This function is used for quoting text in headers according to RFC 2047.
If the only characters that strictly need quoting are spaces, we return the
original string, unmodified. If a quoted string is too long for the buffer, it
is truncated. (This shouldn't happen: this is normally handling short strings.)

Hmmph. As always, things get perverted for other uses. This function was
originally for the "phrase" part of addresses. Now it is being used for much
longer texts in ACLs and via the ${rfc2047: expansion item. This means we have
to check for overlong "encoded-word"s and split them. November 2004.

Arguments:
  string       the string to quote - already checked to contain non-printing
                 chars
  len          the length of the string
  charset      the name of the character set; NULL => iso-8859-1
  buffer       the buffer to put the answer in
  buffer_size  the size of the buffer
  fold         if TRUE, a newline is inserted before the separating space when
                 more than one encoded-word is generated

Returns:       pointer to the original string, if no quoting needed, or
               pointer to buffer containing the quoted string, or
               a pointer to "String too long" if the buffer can't even hold
               the introduction
*/

const uschar *
parse_quote_2047(const uschar *string, int len, uschar *charset, uschar *buffer,
  int buffer_size, BOOL fold)
{
const uschar *s = string;
uschar *p, *t;
int hlen;
BOOL coded = FALSE;
BOOL first_byte = FALSE;

if (!charset) charset = US"iso-8859-1";

/* We don't expect this to fail! */

if (!string_format(buffer, buffer_size, "=?%s?Q?", charset))
  return US"String too long";

hlen = Ustrlen(buffer);
t = buffer + hlen;
p = buffer;

for (; len > 0; len--)
  {
  int ch = *s++;
  if (t > buffer + buffer_size - hlen - 8) break;

  if ((t - p > 67) && !first_byte)
    {
    *t++ = '?';
    *t++ = '=';
    if (fold) *t++ = '\n';
    *t++ = ' ';
    p = t;
    Ustrncpy(p, buffer, hlen);
    t += hlen;
    }

  if (ch < 33 || ch > 126 ||
      Ustrchr("?=()<>@,;:\\\".[]_", ch) != NULL)
    {
    if (ch == ' ')
      {
      *t++ = '_';
      first_byte = FALSE;
      }
    else
      {
      t += sprintf(CS t, "=%02X", ch);
      coded = TRUE;
      first_byte = !first_byte;
      }
    }
  else { *t++ = ch; first_byte = FALSE; }
  }

*t++ = '?';
*t++ = '=';
*t = 0;

return coded ? buffer : string;
}




/*************************************************
*            Fix up an RFC 822 "phrase"          *
*************************************************/

/* This function is called to repair any syntactic defects in the "phrase" part
of an RFC822 address. In particular, it is applied to the user's name as read
from the passwd file when accepting a local message, and to the data from the
-F option.

If the string contains existing quoted strings or comments containing
freestanding quotes, then we just quote those bits that need quoting -
otherwise it would get awfully messy and probably not look good. If not, we
quote the whole thing if necessary. Thus

   John Q. Smith            =>  "John Q. Smith"
   John "Jack" Smith        =>  John "Jack" Smith
   John "Jack" Q. Smith     =>  John "Jack" "Q." Smith
   John (Jack) Q. Smith     =>  "John (Jack) Q. Smith"
   John ("Jack") Q. Smith   =>  John ("Jack") "Q." Smith
but
   John (\"Jack\") Q. Smith =>  "John (\"Jack\") Q. Smith"

Sheesh! This is tedious code. It is a great pity that the syntax of RFC822 is
the way it is...

August 2000: Additional code added:

  Previously, non-printing characters were turned into question marks, which do
  not need to be quoted.

  Now, a different tactic is used if there are any non-printing ASCII
  characters. The encoding method from RFC 2047 is used, assuming iso-8859-1 as
  the character set.

  We *could* use this for all cases, getting rid of the messy original code,
  but leave it for now. It would complicate simple cases like "John Q. Smith".

The result is passed back in the buffer; it is usually going to be added to
some other string. In order to be sure there is going to be no overflow,
restrict the length of the input to 1/4 of the buffer size - this allows for
every single character to be quoted or encoded without overflowing, and that
wouldn't happen because of amalgamation. If the phrase is too long, return a
fixed string.

Arguments:
  phrase       an RFC822 phrase
  len          the length of the phrase
  buffer       a buffer to put the result in
  buffer_size  the size of the buffer

Returns:       the fixed RFC822 phrase
*/

const uschar *
parse_fix_phrase(const uschar *phrase, int len, uschar *buffer, int buffer_size)
{
int ch, i;
BOOL quoted = FALSE;
const uschar *s, *end;
uschar *t, *yield;

while (len > 0 && isspace(*phrase)) { phrase++; len--; }
if (len > buffer_size/4) return US"Name too long";

/* See if there are any non-printing characters, and if so, use the RFC 2047
encoding for the whole thing. */

for (i = 0, s = phrase; i < len; i++, s++)
  if ((*s < 32 && *s != '\t') || *s > 126) break;

if (i < len) return parse_quote_2047(phrase, len, headers_charset, buffer,
  buffer_size, FALSE);

/* No non-printers; use the RFC 822 quoting rules */

s = phrase;
end = s + len;
yield = t = buffer + 1;

while (s < end)
  {
  ch = *s++;

  /* Copy over quoted strings, remembering we encountered one */

  if (ch == '\"')
    {
    *t++ = '\"';
    while (s < end && (ch = *s++) != '\"')
      {
      *t++ = ch;
      if (ch == '\\' && s < end) *t++ = *s++;
      }
    *t++ = '\"';
    if (s >= end) break;
    quoted = TRUE;
    }

  /* Copy over comments, noting if they contain freestanding quote
  characters */

  else if (ch == '(')
    {
    int level = 1;
    *t++ = '(';
    while (s < end)
      {
      ch = *s++;
      *t++ = ch;
      if (ch == '(') level++;
      else if (ch == ')') { if (--level <= 0) break; }
      else if (ch == '\\' && s < end) *t++ = *s++ & 127;
      else if (ch == '\"') quoted = TRUE;
      }
    if (ch == 0)
      {
      while (level--) *t++ = ')';
      break;
      }
    }

  /* Handle special characters that need to be quoted */

  else if (Ustrchr(")<>@,;:\\.[]", ch) != NULL)
    {
    /* If hit previous quotes just make one quoted "word" */

    if (quoted)
      {
      uschar *tt = t++;
      while (*(--tt) != ' ' && *tt != '\"' && *tt != ')') tt[1] = *tt;
      tt[1] = '\"';
      *t++ = ch;
      while (s < end)
        {
        ch = *s++;
        if (ch == ' ' || ch == '\"') { s--; break; } else *t++ = ch;
        }
      *t++ = '\"';
      }

    /* Else quote the whole string so far, and the rest up to any following
    quotes. We must treat anything following a backslash as a literal. */

    else
      {
      BOOL escaped = (ch == '\\');
      *(--yield) = '\"';
      *t++ = ch;

      /* Now look for the end or a quote */

      while (s < end)
        {
        ch = *s++;

        /* Handle escaped pairs */

        if (escaped)
          {
          *t++ = ch;
          escaped = FALSE;
          }

        else if (ch == '\\')
          {
          *t++ = ch;
          escaped = TRUE;
          }

        /* If hit subsequent quotes, insert our quote before any trailing
        spaces and back up to re-handle the quote in the outer loop. */

        else if (ch == '\"')
          {
          int count = 0;
          while (t[-1] == ' ') { t--; count++; }
          *t++ = '\"';
          while (count-- > 0) *t++ = ' ';
          s--;
          break;
          }

        /* If hit a subsequent comment, check it for unescaped quotes,
        and if so, end our quote before it. */

        else if (ch == '(')
          {
          const uschar *ss = s;     /* uschar after '(' */
          int level = 1;
          while(ss < end)
            {
            ch = *ss++;
            if (ch == '(') level++;
            else if (ch == ')') { if (--level <= 0) break; }
            else if (ch == '\\' && ss+1 < end) ss++;
            else if (ch == '\"') { quoted = TRUE; break; }
            }

          /* Comment contains unescaped quotes; end our quote before
          the start of the comment. */

          if (quoted)
            {
            int count = 0;
            while (t[-1] == ' ') { t--; count++; }
            *t++ = '\"';
            while (count-- > 0) *t++ = ' ';
            break;
            }

          /* Comment does not contain unescaped quotes; include it in
          our quote. */

          else
            {
            if (ss >= end) ss--;
            *t++ = '(';
            Ustrncpy(t, s, ss-s);
            t += ss-s;
            s = ss;
            }
          }

        /* Not a comment or quote; include this character in our quotes. */

        else *t++ = ch;
        }
      }

    /* Add a final quote if we hit the end of the string. */

    if (s >= end) *t++ = '\"';
    }

  /* Non-special character; just copy it over */

  else *t++ = ch;
  }

*t = 0;
return yield;
}


/*************************************************
*          Extract addresses from a list         *
*************************************************/

/* This function is called by the redirect router to scan a string containing a
list of addresses separated by commas (with optional white space) or by
newlines, and to generate a chain of address items from them. In other words,
to unpick data from an alias or .forward file.

The SunOS5 documentation for alias files is not very clear on the syntax; it
does not say that either a comma or a newline can be used for separation.
However, that is the way Smail does it, so we follow suit.

If a # character is encountered in a white space position, then characters from
there to the next newline are skipped.

If an unqualified address begins with '\', just skip that character. This gives
compatibility with Sendmail's use of \ to prevent looping. Exim has its own
loop prevention scheme which handles other cases too - see the code in
route_address().

An "address" can be a specification of a file or a pipe; the latter may often
need to be quoted because it may contain spaces, but we don't want to retain
the quotes. Quotes may appear in normal addresses too, and should be retained.
We can distinguish between these cases, because in addresses, quotes are used
only for parts of the address, not the whole thing. Therefore, we remove quotes
from items when they entirely enclose them, but not otherwise.

An "address" can also be of the form :include:pathname to include a list of
addresses contained in the specified file.

Any unqualified addresses are qualified with and rewritten if necessary, via
the rewrite_address() function.

Arguments:
  s                the list of addresses (typically a complete
                     .forward file or a list of entries in an alias file)
  options          option bits for permitting or denying various special cases;
                     not all bits are relevant here - some are for filter
                     files; those we use here are:
                       RDO_DEFER
                       RDO_FREEZE
                       RDO_FAIL
                       RDO_BLACKHOLE
                       RDO_REWRITE
                       RDO_INCLUDE
  anchor           where to hang the chain of newly-created addresses. This
                     should be initialized to NULL.
  error            where to return an error text
  incoming domain  domain of the incoming address; used to qualify unqualified
                     local parts preceded by \
  directory        if NULL, no checks are done on :include: files
                   otherwise, included file names must start with the given
                     directory
  syntax_errors    if not NULL, it carries on after syntax errors in addresses,
                     building up a list of errors as error blocks chained on
                     here.

Returns:      FF_DELIVERED      addresses extracted
              FF_NOTDELIVERED   no addresses extracted, but no errors
              FF_BLACKHOLE      :blackhole:
              FF_DEFER          :defer:
              FF_FAIL           :fail:
              FF_INCLUDEFAIL    some problem with :include:; *error set
              FF_ERROR          other problems; *error is set
*/

int
parse_forward_list(uschar *s, int options, address_item **anchor,
  uschar **error, const uschar *incoming_domain, uschar *directory,
  error_block **syntax_errors)
{
int count = 0;

DEBUG(D_route) debug_printf("parse_forward_list: %s\n", s);

for (;;)
  {
  int len;
  int special = 0;
  int specopt = 0;
  int specbit = 0;
  uschar *ss, *nexts;
  address_item *addr;
  BOOL inquote = FALSE;

  for (;;)
    {
    while (isspace(*s) || *s == ',') s++;
    if (*s == '#') { while (*s != 0 && *s != '\n') s++; } else break;
    }

  /* When we reach the end of the list, we return FF_DELIVERED if any child
  addresses have been generated. If nothing has been generated, there are two
  possibilities: either the list is really empty, or there were syntax errors
  that are being skipped. (If syntax errors are not being skipped, an FF_ERROR
  return is generated on hitting a syntax error and we don't get here.) For a
  truly empty list we return FF_NOTDELIVERED so that the router can decline.
  However, if the list is empty only because syntax errors were skipped, we
  return FF_DELIVERED. */

  if (*s == 0)
    {
    return (count > 0 || (syntax_errors != NULL && *syntax_errors != NULL))?
      FF_DELIVERED : FF_NOTDELIVERED;

    /* This previous code returns FF_ERROR if nothing is generated but a
    syntax error has been skipped. I now think it is the wrong approach, but
    have left this here just in case, and for the record. */

    #ifdef NEVER
    if (count > 0) return FF_DELIVERED;   /* Something was generated */

    if (syntax_errors == NULL ||          /* Not skipping syntax errors, or */
       *syntax_errors == NULL)            /*   we didn't actually skip any */
      return FF_NOTDELIVERED;

    *error = string_sprintf("no addresses generated: syntax error in %s: %s",
       (*syntax_errors)->text2, (*syntax_errors)->text1);
    return FF_ERROR;
    #endif

    }

  /* Find the end of the next address. Quoted strings in addresses may contain
  escaped characters; I haven't found a proper specification of .forward or
  alias files that mentions the quoting properties, but it seems right to do
  the escaping thing in all cases, so use the function that finds the end of an
  address. However, don't let a quoted string extend over the end of a line. */

  ss = parse_find_address_end(s, TRUE);

  /* Remember where we finished, for starting the next one. */

  nexts = ss;

  /* Remove any trailing spaces; we know there's at least one non-space. */

  while (isspace((ss[-1]))) ss--;

  /* We now have s->start and ss->end of the next address. Remove quotes
  if they completely enclose, remembering the address started with a quote
  for handling pipes and files. Another round of removal of leading and
  trailing spaces is then required. */

  if (*s == '\"' && ss[-1] == '\"')
    {
    s++;
    ss--;
    inquote = TRUE;
    while (s < ss && isspace(*s)) s++;
    while (ss > s && isspace((ss[-1]))) ss--;
    }

  /* Set up the length of the address. */

  len = ss - s;

  DEBUG(D_route)
    {
    int save = s[len];
    s[len] = 0;
    debug_printf("extract item: %s\n", s);
    s[len] = save;
    }

  /* Handle special addresses if permitted. If the address is :unknown:
  ignore it - this is for backward compatibility with old alias files. You
  don't need to use it nowadays - just generate an empty string. For :defer:,
  :blackhole:, or :fail: we have to set up the error message and give up right
  away. */

  if (Ustrncmp(s, ":unknown:", len) == 0)
    {
    s = nexts;
    continue;
    }

  if      (Ustrncmp(s, ":defer:", 7) == 0)
    { special = FF_DEFER; specopt = RDO_DEFER; }  /* specbit is 0 */
  else if (Ustrncmp(s, ":blackhole:", 11) == 0)
    { special = FF_BLACKHOLE; specopt = specbit = RDO_BLACKHOLE; }
  else if (Ustrncmp(s, ":fail:", 6) == 0)
    { special = FF_FAIL; specopt = RDO_FAIL; }  /* specbit is 0 */

  if (special != 0)
    {
    uschar *ss = Ustrchr(s+1, ':') + 1;
    if ((options & specopt) == specbit)
      {
      *error = string_sprintf("\"%.*s\" is not permitted", len, s);
      return FF_ERROR;
      }
    while (*ss != 0 && isspace(*ss)) ss++;
    while (s[len] != 0 && s[len] != '\n') len++;
    s[len] = 0;
    *error = string_copy(ss);
    return special;
    }

  /* If the address is of the form :include:pathname, read the file, and call
  this function recursively to extract the addresses from it. If directory is
  NULL, do no checks. Otherwise, insist that the file name starts with the
  given directory and is a regular file. */

  if (Ustrncmp(s, ":include:", 9) == 0)
    {
    uschar *filebuf;
    uschar filename[256];
    uschar *t = s+9;
    int flen = len - 9;
    int frc;
    struct stat statbuf;
    address_item *last;
    FILE *f;

    while (flen > 0 && isspace(*t)) { t++; flen--; }

    if (flen <= 0)
      {
      *error = string_sprintf("file name missing after :include:");
      return FF_ERROR;
      }

    if (flen > 255)
      {
      *error = string_sprintf("included file name \"%s\" is too long", t);
      return FF_ERROR;
      }

    Ustrncpy(filename, t, flen);
    filename[flen] = 0;

    /* Insist on absolute path */

    if (filename[0]!= '/')
      {
      *error = string_sprintf("included file \"%s\" is not an absolute path",
        filename);
      return FF_ERROR;
      }

    /* Check if include is permitted */

    if ((options & RDO_INCLUDE) != 0)
      {
      *error = US"included files not permitted";
      return FF_ERROR;
      }

    /* Check file name if required */

    if (directory)
      {
      int len = Ustrlen(directory);
      uschar *p = filename + len;

      if (Ustrncmp(filename, directory, len) != 0 || *p != '/')
        {
        *error = string_sprintf("included file %s is not in directory %s",
          filename, directory);
        return FF_ERROR;
        }

#ifdef EXIM_HAVE_OPENAT
      /* It is necessary to check that every component inside the directory
      is NOT a symbolic link, in order to keep the file inside the directory.
      This is mighty tedious. We open the directory and openat every component,
      with a flag that fails symlinks. */

      {
      int fd = open(CS directory, O_RDONLY);
      if (fd < 0)
	{
	*error = string_sprintf("failed to open directory %s", directory);
	return FF_ERROR;
	}
      while (*p)
	{
	uschar temp;
	int fd2;
	uschar * q = p;

	while (*++p && *p != '/') ;
	temp = *p;
	*p = '\0';

	fd2 = openat(fd, CS q, O_RDONLY|O_NOFOLLOW);
	close(fd);
	*p = temp;
	if (fd2 < 0)
	  {
          *error = string_sprintf("failed to open %s (component of included "
            "file); could be symbolic link", filename);
	  return FF_ERROR;
	  }
	fd = fd2;
	}
      f = fdopen(fd, "rb");
      }
#else
      /* It is necessary to check that every component inside the directory
      is NOT a symbolic link, in order to keep the file inside the directory.
      This is mighty tedious. It is also not totally foolproof in that it
      leaves the possibility of a race attack, but I don't know how to do
      any better. */

      while (*p)
        {
        int temp;
        while (*++p && *p != '/');
        temp = *p;
        *p = 0;
        if (Ulstat(filename, &statbuf) != 0)
          {
          *error = string_sprintf("failed to stat %s (component of included "
            "file)", filename);
          *p = temp;
          return FF_ERROR;
          }

        *p = temp;

        if ((statbuf.st_mode & S_IFMT) == S_IFLNK)
          {
          *error = string_sprintf("included file %s in the %s directory "
            "involves a symbolic link", filename, directory);
          return FF_ERROR;
          }
        }
#endif
      }

#ifdef EXIM_HAVE_OPENAT
    else
#endif
      /* Open and stat the file */
      f = Ufopen(filename, "rb");

    if (!f)
      {
      *error = string_open_failed(errno, "included file %s", filename);
      return FF_INCLUDEFAIL;
      }

    if (fstat(fileno(f), &statbuf) != 0)
      {
      *error = string_sprintf("failed to stat included file %s: %s",
        filename, strerror(errno));
      (void)fclose(f);
      return FF_INCLUDEFAIL;
      }

    /* If directory was checked, double check that we opened a regular file */

    if (directory && (statbuf.st_mode & S_IFMT) != S_IFREG)
      {
      *error = string_sprintf("included file %s is not a regular file in "
        "the %s directory", filename, directory);
      return FF_ERROR;
      }

    /* Get a buffer and read the contents */

    if (statbuf.st_size > MAX_INCLUDE_SIZE)
      {
      *error = string_sprintf("included file %s is too big (max %d)",
        filename, MAX_INCLUDE_SIZE);
      return FF_ERROR;
      }

    filebuf = store_get(statbuf.st_size + 1);
    if (fread(filebuf, 1, statbuf.st_size, f) != statbuf.st_size)
      {
      *error = string_sprintf("error while reading included file %s: %s",
        filename, strerror(errno));
      (void)fclose(f);
      return FF_ERROR;
      }
    filebuf[statbuf.st_size] = 0;
    (void)fclose(f);

    addr = NULL;
    frc = parse_forward_list(filebuf, options, &addr,
      error, incoming_domain, directory, syntax_errors);
    if (frc != FF_DELIVERED && frc != FF_NOTDELIVERED) return frc;

    if (addr)
      {
      for (last = addr; last->next; last = last->next) count++;
      last->next = *anchor;
      *anchor = addr;
      count++;
      }
    }

  /* Else (not :include:) ensure address is syntactically correct and fully
  qualified if not a pipe or a file, removing a leading \ if present on an
  unqualified address. For pipes and files we must handle quoting. It's
  not quite clear exactly what to do for partially quoted things, but the
  common case of having the whole thing in quotes is straightforward. If this
  was the case, inquote will have been set TRUE above and the quotes removed.

  There is a possible ambiguity over addresses whose local parts start with
  a vertical bar or a slash, and the latter do in fact occur, thanks to X.400.
  Consider a .forward file that contains the line

     /X=xxx/Y=xxx/OU=xxx/@some.gate.way

  Is this a file or an X.400 address? Does it make any difference if it is in
  quotes? On the grounds that file names of this type are rare, Exim treats
  something that parses as an RFC 822 address and has a domain as an address
  rather than a file or a pipe. This is also how an address such as the above
  would be treated if it came in from outside. */

  else
    {
    int start, end, domain;
    uschar *recipient = NULL;
    int save = s[len];
    s[len] = 0;

    /* If it starts with \ and the rest of it parses as a valid mail address
    without a domain, carry on with that address, but qualify it with the
    incoming domain. Otherwise arrange for the address to fall through,
    causing an error message on the re-parse. */

    if (*s == '\\')
      {
      recipient =
        parse_extract_address(s+1, error, &start, &end, &domain, FALSE);
      if (recipient != NULL)
        recipient = (domain != 0)? NULL :
          string_sprintf("%s@%s", recipient, incoming_domain);
      }

    /* Try parsing the item as an address. */

    if (recipient == NULL) recipient =
      parse_extract_address(s, error, &start, &end, &domain, FALSE);

    /* If item starts with / or | and is not a valid address, or there
    is no domain, treat it as a file or pipe. If it was a quoted item,
    remove the quoting occurrences of \ within it. */

    if ((*s == '|' || *s == '/') && (recipient == NULL || domain == 0))
      {
      uschar *t = store_get(Ustrlen(s) + 1);
      uschar *p = t;
      uschar *q = s;
      while (*q != 0)
        {
        if (inquote)
          {
          *p++ = (*q == '\\')? *(++q) : *q;
          q++;
          }
        else *p++ = *q++;
        }
      *p = 0;
      addr = deliver_make_addr(t, TRUE);
      setflag(addr, af_pfr);                   /* indicates pipe/file/reply */
      if (*s != '|') setflag(addr, af_file);   /* indicates file */
      }

    /* Item must be an address. Complain if not, else qualify, rewrite and set
    up the control block. It appears that people are in the habit of using
    empty addresses but with comments as a way of putting comments into
    alias and forward files. Therefore, ignore the error "empty address".
    Mailing lists might want to tolerate syntax errors; there is therefore
    an option to do so. */

    else
      {
      if (recipient == NULL)
        {
        if (Ustrcmp(*error, "empty address") == 0)
          {
          *error = NULL;
          s[len] = save;
          s = nexts;
          continue;
          }

        if (syntax_errors != NULL)
          {
          error_block *e = store_get(sizeof(error_block));
          error_block *last = *syntax_errors;
          if (last == NULL) *syntax_errors = e; else
            {
            while (last->next != NULL) last = last->next;
            last->next = e;
            }
          e->next = NULL;
          e->text1 = *error;
          e->text2 = string_copy(s);
          s[len] = save;
          s = nexts;
          continue;
          }
        else
          {
          *error = string_sprintf("%s in \"%s\"", *error, s);
          s[len] = save;   /* _after_ using it for *error */
          return FF_ERROR;
          }
        }

      /* Address was successfully parsed. Rewrite, and then make an address
      block. */

      recipient = ((options & RDO_REWRITE) != 0)?
        rewrite_address(recipient, TRUE, FALSE, global_rewrite_rules,
          rewrite_existflags) :
        rewrite_address_qualify(recipient, TRUE);
      addr = deliver_make_addr(recipient, TRUE);  /* TRUE => copy recipient */
      }

    /* Restore the final character in the original data, and add to the
    output chain. */

    s[len] = save;
    addr->next = *anchor;
    *anchor = addr;
    count++;
    }

  /* Advance pointer for the next address */

  s = nexts;
  }
}


/*************************************************
*            Extract a Message-ID                *
*************************************************/

/* This function is used to extract message ids from In-Reply-To: and
References: header lines.

Arguments:
  str          pointer to the start of the message-id
  yield        put pointer to the message id (in dynamic memory) here
  error        put error message here on failure

Returns:       points after the processed message-id or NULL on error
*/

uschar *
parse_message_id(uschar *str, uschar **yield, uschar **error)
{
uschar *domain = NULL;
uschar *id;

str = skip_comment(str);
if (*str != '<')
  {
  *error = US"Missing '<' before message-id";
  return NULL;
  }

/* Getting a block the size of the input string will definitely be sufficient
for the answer, but it may also be very long if we are processing a header
line. Therefore, take care to release unwanted store afterwards. */

id = *yield = store_get(Ustrlen(str) + 1);
*id++ = *str++;

str = read_addr_spec(str, id, '>', error, &domain);

if (*error == NULL)
  {
  if (*str != '>') *error = US"Missing '>' after message-id";
    else if (domain == NULL) *error = US"domain missing in message-id";
  }

if (*error != NULL)
  {
  store_reset(*yield);
  return NULL;
  }

while (*id != 0) id++;
*id++ = *str++;
*id++ = 0;
store_reset(id);

str = skip_comment(str);
return str;
}


/*************************************************
*        Parse a fixed digit number              *
*************************************************/

/* Parse a string containing an ASCII encoded fixed digits number

Arguments:
  str          pointer to the start of the ASCII encoded number
  n            pointer to the resulting value
  digits       number of required digits

Returns:       points after the processed date or NULL on error
*/

static uschar *
parse_number(uschar *str, int *n, int digits)
{
  *n=0;
  while (digits--)
  {
    if (*str<'0' || *str>'9') return NULL;
    *n=10*(*n)+(*str++-'0');
  }
  return str;
}


/*************************************************
*        Parse a RFC 2822 day of week            *
*************************************************/

/* Parse the day of the week from a RFC 2822 date, but do not
   decode it, because it is only for humans.

Arguments:
  str          pointer to the start of the day of the week

Returns:       points after the parsed day or NULL on error
*/

static uschar *
parse_day_of_week(uschar *str)
{
/*
day-of-week     =       ([FWS] day-name) / obs-day-of-week

day-name        =       "Mon" / "Tue" / "Wed" / "Thu" /
                        "Fri" / "Sat" / "Sun"

obs-day-of-week =       [CFWS] day-name [CFWS]
*/

static const uschar *day_name[7]={ US"mon", US"tue", US"wed", US"thu", US"fri", US"sat", US"sun" };
int i;
uschar day[4];

str=skip_comment(str);
for (i=0; i<3; ++i)
  {
  if ((day[i]=tolower(*str))=='\0') return NULL;
  ++str;
  }
day[3]='\0';
for (i=0; i<7; ++i) if (Ustrcmp(day,day_name[i])==0) break;
if (i==7) return NULL;
str=skip_comment(str);
return str;
}


/*************************************************
*            Parse a RFC 2822 date               *
*************************************************/

/* Parse the date part of a RFC 2822 date-time, extracting the
   day, month and year.

Arguments:
  str          pointer to the start of the date
  d            pointer to the resulting day
  m            pointer to the resulting month
  y            pointer to the resulting year

Returns:       points after the processed date or NULL on error
*/

static uschar *
parse_date(uschar *str, int *d, int *m, int *y)
{
/*
date            =       day month year

year            =       4*DIGIT / obs-year

obs-year        =       [CFWS] 2*DIGIT [CFWS]

month           =       (FWS month-name FWS) / obs-month

month-name      =       "Jan" / "Feb" / "Mar" / "Apr" /
                        "May" / "Jun" / "Jul" / "Aug" /
                        "Sep" / "Oct" / "Nov" / "Dec"

obs-month       =       CFWS month-name CFWS

day             =       ([FWS] 1*2DIGIT) / obs-day

obs-day         =       [CFWS] 1*2DIGIT [CFWS]
*/

uschar *c,*n;
static const uschar *month_name[]={ US"jan", US"feb", US"mar", US"apr", US"may", US"jun", US"jul", US"aug", US"sep", US"oct", US"nov", US"dec" };
int i;
uschar month[4];

str=skip_comment(str);
if ((str=parse_number(str,d,1))==NULL) return NULL;
if (*str>='0' && *str<='9') *d=10*(*d)+(*str++-'0');
c=skip_comment(str);
if (c==str) return NULL;
else str=c;
for (i=0; i<3; ++i) if ((month[i]=tolower(*(str+i)))=='\0') return NULL;
month[3]='\0';
for (i=0; i<12; ++i) if (Ustrcmp(month,month_name[i])==0) break;
if (i==12) return NULL;
str+=3;
*m=i;
c=skip_comment(str);
if (c==str) return NULL;
else str=c;
if ((n=parse_number(str,y,4)))
  {
  str=n;
  if (*y<1900) return NULL;
  *y=*y-1900;
  }
else if ((n=parse_number(str,y,2)))
  {
  str=skip_comment(n);
  while (*(str-1)==' ' || *(str-1)=='\t') --str; /* match last FWS later */
  if (*y<50) *y+=100;
  }
else return NULL;
return str;
}


/*************************************************
*            Parse a RFC 2822 Time               *
*************************************************/

/* Parse the time part of a RFC 2822 date-time, extracting the
   hour, minute, second and timezone.

Arguments:
  str          pointer to the start of the time
  h            pointer to the resulting hour
  m            pointer to the resulting minute
  s            pointer to the resulting second
  z            pointer to the resulting timezone (offset in seconds)

Returns:       points after the processed time or NULL on error
*/

static uschar *
parse_time(uschar *str, int *h, int *m, int *s, int *z)
{
/*
time            =       time-of-day FWS zone

time-of-day     =       hour ":" minute [ ":" second ]

hour            =       2DIGIT / obs-hour

obs-hour        =       [CFWS] 2DIGIT [CFWS]

minute          =       2DIGIT / obs-minute

obs-minute      =       [CFWS] 2DIGIT [CFWS]

second          =       2DIGIT / obs-second

obs-second      =       [CFWS] 2DIGIT [CFWS]

zone            =       (( "+" / "-" ) 4DIGIT) / obs-zone

obs-zone        =       "UT" / "GMT" /          ; Universal Time
                                                ; North American UT
                                                ; offsets
                        "EST" / "EDT" /         ; Eastern:  - 5/ - 4
                        "CST" / "CDT" /         ; Central:  - 6/ - 5
                        "MST" / "MDT" /         ; Mountain: - 7/ - 6
                        "PST" / "PDT" /         ; Pacific:  - 8/ - 7

                        %d65-73 /               ; Military zones - "A"
                        %d75-90 /               ; through "I" and "K"
                        %d97-105 /              ; through "Z", both
                        %d107-122               ; upper and lower case
*/

uschar *c;

str=skip_comment(str);
if ((str=parse_number(str,h,2))==NULL) return NULL;
str=skip_comment(str);
if (*str!=':') return NULL;
++str;
str=skip_comment(str);
if ((str=parse_number(str,m,2))==NULL) return NULL;
c=skip_comment(str);
if (*str==':')
  {
  ++str;
  str=skip_comment(str);
  if ((str=parse_number(str,s,2))==NULL) return NULL;
  c=skip_comment(str);
  }
if (c==str) return NULL;
else str=c;
if (*str=='+' || *str=='-')
  {
  int neg;

  neg=(*str=='-');
  ++str;
  if ((str=parse_number(str,z,4))==NULL) return NULL;
  *z=(*z/100)*3600+(*z%100)*60;
  if (neg) *z=-*z;
  }
else
  {
  char zone[5];
  struct { const char *name; int off; } zone_name[10]=
  { {"gmt",0}, {"ut",0}, {"est",-5}, {"edt",-4}, {"cst",-6}, {"cdt",-5}, {"mst",-7}, {"mdt",-6}, {"pst",-8}, {"pdt",-7}};
  int i,j;

  for (i=0; i<4; ++i)
    {
    zone[i]=tolower(*(str+i));
    if (zone[i]<'a' || zone[i]>'z') break;
    }
  zone[i]='\0';
  for (j=0; j<10 && strcmp(zone,zone_name[j].name); ++j);
  /* Besides zones named in the grammar, RFC 2822 says other alphabetic */
  /* time zones should be treated as unknown offsets. */
  if (j<10)
    {
    *z=zone_name[j].off*3600;
    str+=i;
    }
  else if (zone[0]<'a' || zone[1]>'z') return 0;
  else
    {
    while ((*str>='a' && *str<='z') || (*str>='A' && *str<='Z')) ++str;
    *z=0;
    }
  }
return str;
}


/*************************************************
*          Parse a RFC 2822 date-time            *
*************************************************/

/* Parse a RFC 2822 date-time and return it in seconds since the epoch.

Arguments:
  str          pointer to the start of the date-time
  t            pointer to the parsed time

Returns:       points after the processed date-time or NULL on error
*/

uschar *
parse_date_time(uschar *str, time_t *t)
{
/*
date-time       =       [ day-of-week "," ] date FWS time [CFWS]
*/

struct tm tm;
int zone;
extern char **environ;
char **old_environ;
static char gmt0[]="TZ=GMT0";
static char *gmt_env[]={ gmt0, (char*)0 };
uschar *try;

if ((try=parse_day_of_week(str)))
  {
  str=try;
  if (*str!=',') return 0;
  ++str;
  }
if ((str=parse_date(str,&tm.tm_mday,&tm.tm_mon,&tm.tm_year))==NULL) return NULL;
if (*str!=' ' && *str!='\t') return NULL;
while (*str==' ' || *str=='\t') ++str;
if ((str=parse_time(str,&tm.tm_hour,&tm.tm_min,&tm.tm_sec,&zone))==NULL) return NULL;
tm.tm_isdst=0;
old_environ=environ;
environ=gmt_env;
*t=mktime(&tm);
environ=old_environ;
if (*t==-1) return NULL;
*t-=zone;
str=skip_comment(str);
return str;
}




/*************************************************
**************************************************
*             Stand-alone test program           *
**************************************************
*************************************************/

#if defined STAND_ALONE
int main(void)
{
int start, end, domain;
uschar buffer[1024];
uschar outbuff[1024];

big_buffer = store_malloc(big_buffer_size);

/* strip_trailing_dot = TRUE; */
allow_domain_literals = TRUE;

printf("Testing parse_fix_phrase\n");

while (Ufgets(buffer, sizeof(buffer), stdin) != NULL)
  {
  buffer[Ustrlen(buffer)-1] = 0;
  if (buffer[0] == 0) break;
  printf("%s\n", CS parse_fix_phrase(buffer, Ustrlen(buffer), outbuff,
    sizeof(outbuff)));
  }

printf("Testing parse_extract_address without group syntax and without UTF-8\n");

while (Ufgets(buffer, sizeof(buffer), stdin) != NULL)
  {
  uschar *out;
  uschar *errmess;
  buffer[Ustrlen(buffer) - 1] = 0;
  if (buffer[0] == 0) break;
  out = parse_extract_address(buffer, &errmess, &start, &end, &domain, FALSE);
  if (out == NULL) printf("*** bad address: %s\n", errmess); else
    {
    uschar extract[1024];
    Ustrncpy(extract, buffer+start, end-start);
    extract[end-start] = 0;
    printf("%s %d %d %d \"%s\"\n", out, start, end, domain, extract);
    }
  }

printf("Testing parse_extract_address without group syntax but with UTF-8\n");

allow_utf8_domains = TRUE;
while (Ufgets(buffer, sizeof(buffer), stdin) != NULL)
  {
  uschar *out;
  uschar *errmess;
  buffer[Ustrlen(buffer) - 1] = 0;
  if (buffer[0] == 0) break;
  out = parse_extract_address(buffer, &errmess, &start, &end, &domain, FALSE);
  if (out == NULL) printf("*** bad address: %s\n", errmess); else
    {
    uschar extract[1024];
    Ustrncpy(extract, buffer+start, end-start);
    extract[end-start] = 0;
    printf("%s %d %d %d \"%s\"\n", out, start, end, domain, extract);
    }
  }
allow_utf8_domains = FALSE;

printf("Testing parse_extract_address with group syntax\n");

f.parse_allow_group = TRUE;
while (Ufgets(buffer, sizeof(buffer), stdin) != NULL)
  {
  uschar *out;
  uschar *errmess;
  uschar *s;
  buffer[Ustrlen(buffer) - 1] = 0;
  if (buffer[0] == 0) break;
  s = buffer;
  while (*s != 0)
    {
    uschar *ss = parse_find_address_end(s, FALSE);
    int terminator = *ss;
    *ss = 0;
    out = parse_extract_address(buffer, &errmess, &start, &end, &domain, FALSE);
    *ss = terminator;

    if (out == NULL) printf("*** bad address: %s\n", errmess); else
      {
      uschar extract[1024];
      Ustrncpy(extract, buffer+start, end-start);
      extract[end-start] = 0;
      printf("%s %d %d %d \"%s\"\n", out, start, end, domain, extract);
      }

    s = ss + (terminator? 1:0);
    while (isspace(*s)) s++;
    }
  }

printf("Testing parse_find_at\n");

while (Ufgets(buffer, sizeof(buffer), stdin) != NULL)
  {
  uschar *s;
  buffer[Ustrlen(buffer)-1] = 0;
  if (buffer[0] == 0) break;
  s = parse_find_at(buffer);
  if (s == NULL) printf("no @ found\n");
    else printf("offset = %d\n", s - buffer);
  }

printf("Testing parse_extract_addresses\n");

while (Ufgets(buffer, sizeof(buffer), stdin) != NULL)
  {
  uschar *errmess;
  int extracted;
  address_item *anchor = NULL;
  buffer[Ustrlen(buffer) - 1] = 0;
  if (buffer[0] == 0) break;
  if ((extracted = parse_forward_list(buffer, -1, &anchor,
      &errmess, US"incoming.domain", NULL, NULL)) == FF_DELIVERED)
    {
    while (anchor != NULL)
      {
      address_item *addr = anchor;
      anchor = anchor->next;
      printf("%d %s\n", testflag(addr, af_pfr), addr->address);
      }
    }
  else printf("Failed: %d %s\n", extracted, errmess);
  }

printf("Testing parse_message_id\n");

while (Ufgets(buffer, sizeof(buffer), stdin) != NULL)
  {
  uschar *s, *t, *errmess;
  buffer[Ustrlen(buffer) - 1] = 0;
  if (buffer[0] == 0) break;
  s = buffer;
  while (*s != 0)
    {
    s = parse_message_id(s, &t, &errmess);
    if (errmess != NULL)
      {
      printf("Failed: %s\n", errmess);
      break;
      }
    printf("%s\n", t);
    }
  }

return 0;
}

#endif

/* End of parse.c */
