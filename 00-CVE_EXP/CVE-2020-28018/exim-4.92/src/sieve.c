/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Michael Haardt 2003 - 2015
 * Copyright (c) The Exim Maintainers 2016 - 2018
 * See the file NOTICE for conditions of use and distribution.
 */

/* This code was contributed by Michael Haardt. */


/* Sieve mail filter. */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "exim.h"

#if HAVE_ICONV
# include <iconv.h>
#endif

/* Define this for RFC compliant \r\n end-of-line terminators.      */
/* Undefine it for UNIX-style \n end-of-line terminators (default). */
#undef RFC_EOL

/* Define this for development of the Sieve extension "encoded-character". */
#define ENCODED_CHARACTER

/* Define this for development of the Sieve extension "envelope-auth". */
#undef ENVELOPE_AUTH

/* Define this for development of the Sieve extension "enotify".    */
#define ENOTIFY

/* Define this for the Sieve extension "subaddress".                */
#define SUBADDRESS

/* Define this for the Sieve extension "vacation".                  */
#define VACATION

/* Must be >= 1                                                     */
#define VACATION_MIN_DAYS 1
/* Must be >= VACATION_MIN_DAYS, must be > 7, should be > 30        */
#define VACATION_MAX_DAYS 31

/* Keep this at 75 to accept only RFC compliant MIME words.         */
/* Increase it if you want to match headers from buggy MUAs.        */
#define MIMEWORD_LENGTH 75

struct Sieve
  {
  uschar *filter;
  const uschar *pc;
  int line;
  const uschar *errmsg;
  int keep;
  int require_envelope;
  int require_fileinto;
#ifdef ENCODED_CHARACTER
  int require_encoded_character;
#endif
#ifdef ENVELOPE_AUTH
  int require_envelope_auth;
#endif
#ifdef ENOTIFY
  int require_enotify;
  struct Notification *notified;
#endif
  uschar *enotify_mailto_owner;
#ifdef SUBADDRESS
  int require_subaddress;
#endif
#ifdef VACATION
  int require_vacation;
  int vacation_ran;
#endif
  uschar *vacation_directory;
  const uschar *subaddress;
  const uschar *useraddress;
  int require_copy;
  int require_iascii_numeric;
  };

enum Comparator { COMP_OCTET, COMP_EN_ASCII_CASEMAP, COMP_ASCII_NUMERIC };
enum MatchType { MATCH_IS, MATCH_CONTAINS, MATCH_MATCHES };
#ifdef SUBADDRESS
enum AddressPart { ADDRPART_USER, ADDRPART_DETAIL, ADDRPART_LOCALPART, ADDRPART_DOMAIN, ADDRPART_ALL };
#else
enum AddressPart { ADDRPART_LOCALPART, ADDRPART_DOMAIN, ADDRPART_ALL };
#endif
enum RelOp { LT, LE, EQ, GE, GT, NE };

struct String
  {
  uschar *character;
  int length;
  };

struct Notification
  {
  struct String method;
  struct String importance;
  struct String message;
  struct Notification *next;
  };

/* This should be a complete list of supported extensions, so that an external
ManageSieve (RFC 5804) program can interrogate the current Exim binary for the
list of extensions and provide correct information to a client.

We'll emit the list in the order given here; keep it alphabetically sorted, so
that callers don't get surprised.

List *MUST* end with a NULL.  Which at least makes ifdef-vs-comma easier. */

const uschar *exim_sieve_extension_list[] = {
  CUS"comparator-i;ascii-numeric",
  CUS"copy",
#ifdef ENCODED_CHARACTER
  CUS"encoded-character",
#endif
#ifdef ENOTIFY
  CUS"enotify",
#endif
  CUS"envelope",
#ifdef ENVELOPE_AUTH
  CUS"envelope-auth",
#endif
  CUS"fileinto",
#ifdef SUBADDRESS
  CUS"subaddress",
#endif
#ifdef VACATION
  CUS"vacation",
#endif
  NULL
};

static int eq_asciicase(const struct String *needle, const struct String *haystack, int match_prefix);
static int parse_test(struct Sieve *filter, int *cond, int exec);
static int parse_commands(struct Sieve *filter, int exec, address_item **generated);

static uschar str_from_c[]="From";
static const struct String str_from={ str_from_c, 4 };
static uschar str_to_c[]="To";
static const struct String str_to={ str_to_c, 2 };
static uschar str_cc_c[]="Cc";
static const struct String str_cc={ str_cc_c, 2 };
static uschar str_bcc_c[]="Bcc";
static const struct String str_bcc={ str_bcc_c, 3 };
#ifdef ENVELOPE_AUTH
static uschar str_auth_c[]="auth";
static const struct String str_auth={ str_auth_c, 4 };
#endif
static uschar str_sender_c[]="Sender";
static const struct String str_sender={ str_sender_c, 6 };
static uschar str_resent_from_c[]="Resent-From";
static const struct String str_resent_from={ str_resent_from_c, 11 };
static uschar str_resent_to_c[]="Resent-To";
static const struct String str_resent_to={ str_resent_to_c, 9 };
static uschar str_fileinto_c[]="fileinto";
static const struct String str_fileinto={ str_fileinto_c, 8 };
static uschar str_envelope_c[]="envelope";
static const struct String str_envelope={ str_envelope_c, 8 };
#ifdef ENCODED_CHARACTER
static uschar str_encoded_character_c[]="encoded-character";
static const struct String str_encoded_character={ str_encoded_character_c, 17 };
#endif
#ifdef ENVELOPE_AUTH
static uschar str_envelope_auth_c[]="envelope-auth";
static const struct String str_envelope_auth={ str_envelope_auth_c, 13 };
#endif
#ifdef ENOTIFY
static uschar str_enotify_c[]="enotify";
static const struct String str_enotify={ str_enotify_c, 7 };
static uschar str_online_c[]="online";
static const struct String str_online={ str_online_c, 6 };
static uschar str_maybe_c[]="maybe";
static const struct String str_maybe={ str_maybe_c, 5 };
static uschar str_auto_submitted_c[]="Auto-Submitted";
static const struct String str_auto_submitted={ str_auto_submitted_c, 14 };
#endif
#ifdef SUBADDRESS
static uschar str_subaddress_c[]="subaddress";
static const struct String str_subaddress={ str_subaddress_c, 10 };
#endif
#ifdef VACATION
static uschar str_vacation_c[]="vacation";
static const struct String str_vacation={ str_vacation_c, 8 };
static uschar str_subject_c[]="Subject";
static const struct String str_subject={ str_subject_c, 7 };
#endif
static uschar str_copy_c[]="copy";
static const struct String str_copy={ str_copy_c, 4 };
static uschar str_iascii_casemap_c[]="i;ascii-casemap";
static const struct String str_iascii_casemap={ str_iascii_casemap_c, 15 };
static uschar str_enascii_casemap_c[]="en;ascii-casemap";
static const struct String str_enascii_casemap={ str_enascii_casemap_c, 16 };
static uschar str_ioctet_c[]="i;octet";
static const struct String str_ioctet={ str_ioctet_c, 7 };
static uschar str_iascii_numeric_c[]="i;ascii-numeric";
static const struct String str_iascii_numeric={ str_iascii_numeric_c, 15 };
static uschar str_comparator_iascii_casemap_c[]="comparator-i;ascii-casemap";
static const struct String str_comparator_iascii_casemap={ str_comparator_iascii_casemap_c, 26 };
static uschar str_comparator_enascii_casemap_c[]="comparator-en;ascii-casemap";
static const struct String str_comparator_enascii_casemap={ str_comparator_enascii_casemap_c, 27 };
static uschar str_comparator_ioctet_c[]="comparator-i;octet";
static const struct String str_comparator_ioctet={ str_comparator_ioctet_c, 18 };
static uschar str_comparator_iascii_numeric_c[]="comparator-i;ascii-numeric";
static const struct String str_comparator_iascii_numeric={ str_comparator_iascii_numeric_c, 26 };


/*************************************************
*          Encode to quoted-printable            *
*************************************************/

/*
Arguments:
  src               UTF-8 string
  dst               US-ASCII string

Returns
  dst
*/

static struct String *quoted_printable_encode(const struct String *src, struct String *dst)
{
int pass;
const uschar *start,*end;
uschar *new = NULL;
uschar ch;
size_t line;

/* Two passes: one to count output allocation size, second
to do the encoding */

for (pass=0; pass<=1; ++pass)
  {
  line=0;
  if (pass==0)
    dst->length=0;
  else
    {
    dst->character=store_get(dst->length+1); /* plus one for \0 */
    new=dst->character;
    }
  for (start=src->character,end=start+src->length; start<end; ++start)
    {
    ch=*start;
    if (line>=73)	/* line length limit */
      {
      if (pass==0)
        dst->length+=2;
      else
        {
        *new++='=';	/* line split */
        *new++='\n';
        }
      line=0;
      }
    if (  (ch>='!' && ch<='<')
       || (ch>='>' && ch<='~')
       || (  (ch=='\t' || ch==' ')
          && start+2<end
          && (*(start+1)!='\r' || *(start+2)!='\n')	/* CRLF */
          )
       )
      {
      if (pass==0)
        ++dst->length;
      else
        *new++=*start;	/* copy char */
      ++line;
      }
    else if (ch=='\r' && start+1<end && *(start+1)=='\n') /* CRLF */
      {
      if (pass==0)
        ++dst->length;
      else
        *new++='\n';					/* NL */
      line=0;
      ++start;	/* consume extra input char */
      }
    else
      {
      if (pass==0)
        dst->length+=3;
      else
        {		/* encoded char */
        new += sprintf(CS new,"=%02X",ch);
        }
      line+=3;
      }
    }
  }
  *new='\0'; /* not included in length, but nice */
  return dst;
}


/*************************************************
*     Check mail address for correct syntax      *
*************************************************/

/*
Check mail address for being syntactically correct.

Arguments:
  filter      points to the Sieve filter including its state
  address     String containing one address

Returns
  1           Mail address is syntactically OK
 -1           syntax error
*/

int check_mail_address(struct Sieve *filter, const struct String *address)
{
int start, end, domain;
uschar *error,*ss;

if (address->length>0)
  {
  ss = parse_extract_address(address->character, &error, &start, &end, &domain,
    FALSE);
  if (ss == NULL)
    {
    filter->errmsg=string_sprintf("malformed address \"%s\" (%s)",
      address->character, error);
    return -1;
    }
  else
    return 1;
  }
else
  {
  filter->errmsg=CUS "empty address";
  return -1;
  }
}


/*************************************************
*          Decode URI encoded string             *
*************************************************/

/*
Arguments:
  str               URI encoded string

Returns
  0                 Decoding successful
 -1                 Encoding error
*/

#ifdef ENOTIFY
static int uri_decode(struct String *str)
{
uschar *s,*t,*e;

if (str->length==0) return 0;
for (s=str->character,t=s,e=s+str->length; s<e; )
  {
  if (*s=='%')
    {
    if (s+2<e && isxdigit(*(s+1)) && isxdigit(*(s+2)))
      {
      *t++=((isdigit(*(s+1)) ? *(s+1)-'0' : tolower(*(s+1))-'a'+10)<<4)
           | (isdigit(*(s+2)) ? *(s+2)-'0' : tolower(*(s+2))-'a'+10);
      s+=3;
      }
    else return -1;
    }
  else
    *t++=*s++;
  }
*t='\0';
str->length=t-str->character;
return 0;
}


/*************************************************
*               Parse mailto URI                 *
*************************************************/

/*
Parse mailto-URI.

       mailtoURI   = "mailto:" [ to ] [ headers ]
       to          = [ addr-spec *("%2C" addr-spec ) ]
       headers     = "?" header *( "&" header )
       header      = hname "=" hvalue
       hname       = *urlc
       hvalue      = *urlc

Arguments:
  filter      points to the Sieve filter including its state
  uri         URI, excluding scheme
  recipient
  body

Returns
  1           URI is syntactically OK
  0           Unknown URI scheme
 -1           syntax error
*/

static int
parse_mailto_uri(struct Sieve *filter, const uschar *uri,
  string_item **recipient, struct String *header, struct String *subject,
  struct String *body)
{
const uschar *start;
struct String to, hname;
struct String hvalue = {.character = NULL, .length = 0};
string_item *new;

if (Ustrncmp(uri,"mailto:",7))
  {
  filter->errmsg=US "Unknown URI scheme";
  return 0;
  }

uri+=7;
if (*uri && *uri!='?')
  for (;;)
    {
    /* match to */
    for (start=uri; *uri && *uri!='?' && (*uri!='%' || *(uri+1)!='2' || tolower(*(uri+2))!='c'); ++uri);
    if (uri>start)
      {
      gstring * g = string_catn(NULL, start, uri-start);

      to.character = string_from_gstring(g);
      to.length = g->ptr;
      if (uri_decode(&to)==-1)
        {
        filter->errmsg=US"Invalid URI encoding";
        return -1;
        }
      new=store_get(sizeof(string_item));
      new->text=store_get(to.length+1);
      if (to.length) memcpy(new->text,to.character,to.length);
      new->text[to.length]='\0';
      new->next=*recipient;
      *recipient=new;
      }
    else
      {
      filter->errmsg=US"Missing addr-spec in URI";
      return -1;
      }
    if (*uri=='%') uri+=3;
    else break;
    }
if (*uri=='?')
  {
  ++uri;
  for (;;)
    {
    /* match hname */
    for (start=uri; *uri && (isalnum(*uri) || strchr("$-_.+!*'(),%",*uri)); ++uri);
    if (uri>start)
      {
      gstring * g = string_catn(NULL, start, uri-start);

      hname.character = string_from_gstring(g);
      hname.length = g->ptr;
      if (uri_decode(&hname)==-1)
        {
        filter->errmsg=US"Invalid URI encoding";
        return -1;
        }
      }
    /* match = */
    if (*uri=='=')
      ++uri;
    else
      {
      filter->errmsg=US"Missing equal after hname";
      return -1;
      }
    /* match hvalue */
    for (start=uri; *uri && (isalnum(*uri) || strchr("$-_.+!*'(),%",*uri)); ++uri);
    if (uri>start)
      {
      gstring * g = string_catn(NULL, start, uri-start);

      hname.character = string_from_gstring(g);
      hname.length = g->ptr;
      if (uri_decode(&hvalue)==-1)
        {
        filter->errmsg=US"Invalid URI encoding";
        return -1;
        }
      }
    if (hname.length==2 && strcmpic(hname.character, US"to")==0)
      {
      new=store_get(sizeof(string_item));
      new->text=store_get(hvalue.length+1);
      if (hvalue.length) memcpy(new->text,hvalue.character,hvalue.length);
      new->text[hvalue.length]='\0';
      new->next=*recipient;
      *recipient=new;
      }
    else if (hname.length==4 && strcmpic(hname.character, US"body")==0)
      *body=hvalue;
    else if (hname.length==7 && strcmpic(hname.character, US"subject")==0)
      *subject=hvalue;
    else
      {
      static struct String ignore[]=
        {
        {US"date",4},
        {US"from",4},
        {US"message-id",10},
        {US"received",8},
        {US"auto-submitted",14}
        };
      static struct String *end=ignore+sizeof(ignore)/sizeof(ignore[0]);
      struct String *i;

      for (i=ignore; i<end && !eq_asciicase(&hname,i,0); ++i);
      if (i==end)
        {
	gstring * g;

        if (header->length==-1) header->length = 0;

	g = string_catn(NULL, header->character, header->length);
        g = string_catn(g, hname.character, hname.length);
        g = string_catn(g, CUS ": ", 2);
        g = string_catn(g, hvalue.character, hvalue.length);
        g = string_catn(g, CUS "\n", 1);

	header->character = string_from_gstring(g);
	header->length = g->ptr;
        }
      }
    if (*uri=='&') ++uri;
    else break;
    }
  }
if (*uri)
  {
  filter->errmsg=US"Syntactically invalid URI";
  return -1;
  }
return 1;
}
#endif


/*************************************************
*          Octet-wise string comparison          *
*************************************************/

/*
Arguments:
  needle            UTF-8 string to search ...
  haystack          ... inside the haystack
  match_prefix      1 to compare if needle is a prefix of haystack

Returns:      0               needle not found in haystack
              1               needle found
*/

static int eq_octet(const struct String *needle,
  const struct String *haystack, int match_prefix)
{
size_t nl,hl;
const uschar *n,*h;

nl=needle->length;
n=needle->character;
hl=haystack->length;
h=haystack->character;
while (nl>0 && hl>0)
  {
#if !HAVE_ICONV
  if (*n&0x80) return 0;
  if (*h&0x80) return 0;
#endif
  if (*n!=*h) return 0;
  ++n;
  ++h;
  --nl;
  --hl;
  }
return (match_prefix ? nl==0 : nl==0 && hl==0);
}


/*************************************************
*    ASCII case-insensitive string comparison    *
*************************************************/

/*
Arguments:
  needle            UTF-8 string to search ...
  haystack          ... inside the haystack
  match_prefix      1 to compare if needle is a prefix of haystack

Returns:      0               needle not found in haystack
              1               needle found
*/

static int eq_asciicase(const struct String *needle,
  const struct String *haystack, int match_prefix)
{
size_t nl,hl;
const uschar *n,*h;
uschar nc,hc;

nl=needle->length;
n=needle->character;
hl=haystack->length;
h=haystack->character;
while (nl>0 && hl>0)
  {
  nc=*n;
  hc=*h;
#if !HAVE_ICONV
  if (nc&0x80) return 0;
  if (hc&0x80) return 0;
#endif
  /* tolower depends on the locale and only ASCII case must be insensitive */
  if ((nc>='A' && nc<='Z' ? nc|0x20 : nc) != (hc>='A' && hc<='Z' ? hc|0x20 : hc)) return 0;
  ++n;
  ++h;
  --nl;
  --hl;
  }
return (match_prefix ? nl==0 : nl==0 && hl==0);
}


/*************************************************
*              Glob pattern search               *
*************************************************/

/*
Arguments:
  needle          pattern to search ...
  haystack        ... inside the haystack
  ascii_caseless  ignore ASCII case
  match_octet     match octets, not UTF-8 multi-octet characters

Returns:      0               needle not found in haystack
              1               needle found
              -1              pattern error
*/

static int eq_glob(const struct String *needle,
  const struct String *haystack, int ascii_caseless, int match_octet)
{
const uschar *n,*h,*nend,*hend;
int may_advance=0;

n=needle->character;
h=haystack->character;
nend=n+needle->length;
hend=h+haystack->length;
while (n<nend)
  {
  if (*n=='*')
    {
    ++n;
    may_advance=1;
    }
  else
    {
    const uschar *npart,*hpart;

    /* Try to match a non-star part of the needle at the current */
    /* position in the haystack.                                 */
    match_part:
    npart=n;
    hpart=h;
    while (npart<nend && *npart!='*') switch (*npart)
      {
      case '?':
        {
        if (hpart==hend) return 0;
        if (match_octet)
          ++hpart;
        else
          {
          /* Match one UTF8 encoded character */
          if ((*hpart&0xc0)==0xc0)
            {
            ++hpart;
            while (hpart<hend && ((*hpart&0xc0)==0x80)) ++hpart;
            }
          else
            ++hpart;
          }
        ++npart;
        break;
        }
      case '\\':
        {
        ++npart;
        if (npart==nend) return -1;
        /* FALLTHROUGH */
        }
      default:
        {
        if (hpart==hend) return 0;
        /* tolower depends on the locale, but we need ASCII */
        if
          (
#if !HAVE_ICONV
          (*hpart&0x80) || (*npart&0x80) ||
#endif
          ascii_caseless
          ? ((*npart>='A' && *npart<='Z' ? *npart|0x20 : *npart) != (*hpart>='A' && *hpart<='Z' ? *hpart|0x20 : *hpart))
          : *hpart!=*npart
          )
          {
          if (may_advance)
            /* string match after a star failed, advance and try again */
            {
            ++h;
            goto match_part;
            }
          else return 0;
          }
        else
          {
          ++npart;
          ++hpart;
          };
        }
      }
    /* at this point, a part was matched successfully */
    if (may_advance && npart==nend && hpart<hend)
      /* needle ends, but haystack does not: if there was a star before, advance and try again */
      {
      ++h;
      goto match_part;
      }
    h=hpart;
    n=npart;
    may_advance=0;
    }
  }
return (h==hend ? 1 : may_advance);
}


/*************************************************
*    ASCII numeric comparison                    *
*************************************************/

/*
Arguments:
  a                 first numeric string
  b                 second numeric string
  relop             relational operator

Returns:      0               not (a relop b)
              1               a relop b
*/

static int eq_asciinumeric(const struct String *a,
  const struct String *b, enum RelOp relop)
{
size_t al,bl;
const uschar *as,*aend,*bs,*bend;
int cmp;

as=a->character;
aend=a->character+a->length;
bs=b->character;
bend=b->character+b->length;

while (*as>='0' && *as<='9' && as<aend) ++as;
al=as-a->character;
while (*bs>='0' && *bs<='9' && bs<bend) ++bs;
bl=bs-b->character;

if (al && bl==0) cmp=-1;
else if (al==0 && bl==0) cmp=0;
else if (al==0 && bl) cmp=1;
else
  {
  cmp=al-bl;
  if (cmp==0) cmp=memcmp(a->character,b->character,al);
  }
switch (relop)
  {
  case LT: return cmp<0;
  case LE: return cmp<=0;
  case EQ: return cmp==0;
  case GE: return cmp>=0;
  case GT: return cmp>0;
  case NE: return cmp!=0;
  }
  /*NOTREACHED*/
  return -1;
}


/*************************************************
*             Compare strings                    *
*************************************************/

/*
Arguments:
  filter      points to the Sieve filter including its state
  needle      UTF-8 pattern or string to search ...
  haystack    ... inside the haystack
  co          comparator to use
  mt          match type to use

Returns:      0               needle not found in haystack
              1               needle found
              -1              comparator does not offer matchtype
*/

static int compare(struct Sieve *filter, const struct String *needle, const struct String *haystack,
  enum Comparator co, enum MatchType mt)
{
int r=0;

if ((filter_test != FTEST_NONE && debug_selector != 0) ||
  (debug_selector & D_filter) != 0)
  {
  debug_printf("String comparison (match ");
  switch (mt)
    {
    case MATCH_IS: debug_printf(":is"); break;
    case MATCH_CONTAINS: debug_printf(":contains"); break;
    case MATCH_MATCHES: debug_printf(":matches"); break;
    }
  debug_printf(", comparison \"");
  switch (co)
    {
    case COMP_OCTET: debug_printf("i;octet"); break;
    case COMP_EN_ASCII_CASEMAP: debug_printf("en;ascii-casemap"); break;
    case COMP_ASCII_NUMERIC: debug_printf("i;ascii-numeric"); break;
    }
  debug_printf("\"):\n");
  debug_printf("  Search = %s (%d chars)\n", needle->character,needle->length);
  debug_printf("  Inside = %s (%d chars)\n", haystack->character,haystack->length);
  }
switch (mt)
  {
  case MATCH_IS:
    {
    switch (co)
      {
      case COMP_OCTET:
        {
        if (eq_octet(needle,haystack,0)) r=1;
        break;
        }
      case COMP_EN_ASCII_CASEMAP:
        {
        if (eq_asciicase(needle,haystack,0)) r=1;
        break;
        }
      case COMP_ASCII_NUMERIC:
        {
        if (!filter->require_iascii_numeric)
          {
          filter->errmsg=CUS "missing previous require \"comparator-i;ascii-numeric\";";
          return -1;
          }
        if (eq_asciinumeric(needle,haystack,EQ)) r=1;
        break;
        }
      }
    break;
    }
  case MATCH_CONTAINS:
    {
    struct String h;

    switch (co)
      {
      case COMP_OCTET:
        {
        for (h=*haystack; h.length; ++h.character,--h.length) if (eq_octet(needle,&h,1)) { r=1; break; }
        break;
        }
      case COMP_EN_ASCII_CASEMAP:
        {
        for (h=*haystack; h.length; ++h.character,--h.length) if (eq_asciicase(needle,&h,1)) { r=1; break; }
        break;
        }
      default:
        {
        filter->errmsg=CUS "comparator does not offer specified matchtype";
        return -1;
        }
      }
    break;
    }
  case MATCH_MATCHES:
    {
    switch (co)
      {
      case COMP_OCTET:
        {
        if ((r=eq_glob(needle,haystack,0,1))==-1)
          {
          filter->errmsg=CUS "syntactically invalid pattern";
          return -1;
          }
        break;
        }
      case COMP_EN_ASCII_CASEMAP:
        {
        if ((r=eq_glob(needle,haystack,1,1))==-1)
          {
          filter->errmsg=CUS "syntactically invalid pattern";
          return -1;
          }
        break;
        }
      default:
        {
        filter->errmsg=CUS "comparator does not offer specified matchtype";
        return -1;
        }
      }
    break;
    }
  }
if ((filter_test != FTEST_NONE && debug_selector != 0) ||
  (debug_selector & D_filter) != 0)
  debug_printf("  Result %s\n",r?"true":"false");
return r;
}


/*************************************************
*         Check header field syntax              *
*************************************************/

/*
RFC 2822, section 3.6.8 says:

  field-name      =       1*ftext

  ftext           =       %d33-57 /               ; Any character except
                          %d59-126                ;  controls, SP, and
                                                  ;  ":".

That forbids 8-bit header fields.  This implementation accepts them, since
all of Exim is 8-bit clean, so it adds %d128-%d255.

Arguments:
  header      header field to quote for suitable use in Exim expansions

Returns:      0               string is not a valid header field
              1               string is a value header field
*/

static int is_header(const struct String *header)
{
size_t l;
const uschar *h;

l=header->length;
h=header->character;
if (l==0) return 0;
while (l)
  {
  if (((unsigned char)*h)<33 || ((unsigned char)*h)==':' || ((unsigned char)*h)==127) return 0;
  else
    {
    ++h;
    --l;
    }
  }
return 1;
}


/*************************************************
*       Quote special characters string          *
*************************************************/

/*
Arguments:
  header      header field to quote for suitable use in Exim expansions
              or as debug output

Returns:      quoted string
*/

static const uschar *
quote(const struct String *header)
{
gstring * quoted = NULL;
size_t l;
const uschar *h;

l=header->length;
h=header->character;
while (l)
  {
  switch (*h)
    {
    case '\0':
      quoted = string_catn(quoted, CUS "\\0", 2);
      break;
    case '$':
    case '{':
    case '}':
      quoted = string_catn(quoted, CUS "\\", 1);
    default:
      quoted = string_catn(quoted, h, 1);
    }
  ++h;
  --l;
  }
quoted = string_catn(quoted, CUS "", 1);
return string_from_gstring(quoted);
}


/*************************************************
*   Add address to list of generated addresses   *
*************************************************/

/*
According to RFC 5228, duplicate delivery to the same address must
not happen, so the list is first searched for the address.

Arguments:
  generated   list of generated addresses
  addr        new address to add
  file        address denotes a file

Returns:      nothing
*/

static void
add_addr(address_item **generated, uschar *addr, int file, int maxage, int maxmessages, int maxstorage)
{
address_item *new_addr;

for (new_addr=*generated; new_addr; new_addr=new_addr->next)
  if (  Ustrcmp(new_addr->address,addr) == 0
     && (  !file
	|| testflag(new_addr, af_pfr)
	|| testflag(new_addr, af_file)
	)
     )
    {
    if ((filter_test != FTEST_NONE && debug_selector != 0) || (debug_selector & D_filter) != 0)
      debug_printf("Repeated %s `%s' ignored.\n",file ? "fileinto" : "redirect", addr);

    return;
    }

if ((filter_test != FTEST_NONE && debug_selector != 0) || (debug_selector & D_filter) != 0)
  debug_printf("%s `%s'\n",file ? "fileinto" : "redirect", addr);

new_addr = deliver_make_addr(addr,TRUE);
if (file)
  {
  setflag(new_addr, af_pfr);
  setflag(new_addr, af_file);
  new_addr->mode = 0;
  }
new_addr->prop.errors_address = NULL;
new_addr->next = *generated;
*generated = new_addr;
}


/*************************************************
*         Return decoded header field            *
*************************************************/

/*
Unfold the header field as described in RFC 2822 and remove all
leading and trailing white space, then perform MIME decoding and
translate the header field to UTF-8.

Arguments:
  value       returned value of the field
  header      name of the header field

Returns:      nothing          The expanded string is empty
                               in case there is no such header
*/

static void expand_header(struct String *value, const struct String *header)
{
uschar *s,*r,*t;
uschar *errmsg;

value->length=0;
value->character=(uschar*)0;

t=r=s=expand_string(string_sprintf("$rheader_%s",quote(header)));
while (*r==' ' || *r=='\t') ++r;
while (*r)
  {
  if (*r=='\n')
    ++r;
  else
    *t++=*r++;
  }
while (t>s && (*(t-1)==' ' || *(t-1)=='\t')) --t;
*t='\0';
value->character=rfc2047_decode(s,check_rfc2047_length,US"utf-8",'\0',&value->length,&errmsg);
}


/*************************************************
*        Parse remaining hash comment            *
*************************************************/

/*
Token definition:
  Comment up to terminating CRLF

Arguments:
  filter      points to the Sieve filter including its state

Returns:      1                success
              -1               syntax error
*/

static int parse_hashcomment(struct Sieve *filter)
{
++filter->pc;
while (*filter->pc)
  {
#ifdef RFC_EOL
  if (*filter->pc=='\r' && *(filter->pc+1)=='\n')
#else
  if (*filter->pc=='\n')
#endif
    {
#ifdef RFC_EOL
    filter->pc+=2;
#else
    ++filter->pc;
#endif
    ++filter->line;
    return 1;
    }
  else ++filter->pc;
  }
filter->errmsg=CUS "missing end of comment";
return -1;
}


/*************************************************
*       Parse remaining C-style comment          *
*************************************************/

/*
Token definition:
  Everything up to star slash

Arguments:
  filter      points to the Sieve filter including its state

Returns:      1                success
              -1               syntax error
*/

static int parse_comment(struct Sieve *filter)
{
  filter->pc+=2;
  while (*filter->pc)
  {
    if (*filter->pc=='*' && *(filter->pc+1)=='/')
    {
      filter->pc+=2;
      return 1;
    }
    else ++filter->pc;
  }
  filter->errmsg=CUS "missing end of comment";
  return -1;
}


/*************************************************
*         Parse optional white space             *
*************************************************/

/*
Token definition:
  Spaces, tabs, CRLFs, hash comments or C-style comments

Arguments:
  filter      points to the Sieve filter including its state

Returns:      1                success
              -1               syntax error
*/

static int parse_white(struct Sieve *filter)
{
while (*filter->pc)
  {
  if (*filter->pc==' ' || *filter->pc=='\t') ++filter->pc;
#ifdef RFC_EOL
  else if (*filter->pc=='\r' && *(filter->pc+1)=='\n')
#else
  else if (*filter->pc=='\n')
#endif
    {
#ifdef RFC_EOL
    filter->pc+=2;
#else
    ++filter->pc;
#endif
    ++filter->line;
    }
  else if (*filter->pc=='#')
    {
    if (parse_hashcomment(filter)==-1) return -1;
    }
  else if (*filter->pc=='/' && *(filter->pc+1)=='*')
    {
    if (parse_comment(filter)==-1) return -1;
    }
  else break;
  }
return 1;
}


#ifdef ENCODED_CHARACTER
/*************************************************
*      Decode hex-encoded-character string       *
*************************************************/

/*
Encoding definition:
   blank                = SP / TAB / CRLF
   hex-pair-seq         = *blank hex-pair *(1*blank hex-pair) *blank
   hex-pair             = 1*2HEXDIG

Arguments:
  src         points to a hex-pair-seq
  end         points to its end
  dst         points to the destination of the decoded octets,
              optionally to (uschar*)0 for checking only

Returns:      >=0              number of decoded octets
              -1               syntax error
*/

static int hex_decode(uschar *src, uschar *end, uschar *dst)
{
int decoded=0;

while (*src==' ' || *src=='\t' || *src=='\n') ++src;
do
  {
  int x,d,n;

  for (x=0,d=0; d<2 && src<end && isxdigit(n=tolower(*src)); x=(x<<4)|(n>='0' && n<='9' ? n-'0' : 10+(n-'a')),++d,++src);
  if (d==0) return -1;
  if (dst) *dst++=x;
  ++decoded;
  if (src==end) return decoded;
  if (*src==' ' || *src=='\t' || *src=='\n')
    while (*src==' ' || *src=='\t' || *src=='\n') ++src;
  else
    return -1;
  }
while (src<end);
return decoded;
}


/*************************************************
*    Decode unicode-encoded-character string     *
*************************************************/

/*
Encoding definition:
   blank                = SP / TAB / CRLF
   unicode-hex-seq      = *blank unicode-hex *(blank unicode-hex) *blank
   unicode-hex          = 1*HEXDIG

   It is an error for a script to use a hexadecimal value that isn't in
   either the range 0 to D7FF or the range E000 to 10FFFF.

   At this time, strings are already scanned, thus the CRLF is converted
   to the internally used \n (should RFC_EOL have been used).

Arguments:
  src         points to a unicode-hex-seq
  end         points to its end
  dst         points to the destination of the decoded octets,
              optionally to (uschar*)0 for checking only

Returns:      >=0              number of decoded octets
              -1               syntax error
              -2               semantic error (character range violation)
*/

static int unicode_decode(uschar *src, uschar *end, uschar *dst)
{
int decoded=0;

while (*src==' ' || *src=='\t' || *src=='\n') ++src;
do
  {
  uschar *hex_seq;
  int c,d,n;

  unicode_hex:
  for (hex_seq=src; src<end && *src=='0'; ++src);
  for (c=0,d=0; d<7 && src<end && isxdigit(n=tolower(*src)); c=(c<<4)|(n>='0' && n<='9' ? n-'0' : 10+(n-'a')),++d,++src);
  if (src==hex_seq) return -1;
  if (d==7 || (!((c>=0 && c<=0xd7ff) || (c>=0xe000 && c<=0x10ffff)))) return -2;
  if (c<128)
    {
    if (dst) *dst++=c;
    ++decoded;
    }
  else if (c>=0x80 && c<=0x7ff)
    {
      if (dst)
        {
        *dst++=192+(c>>6);
        *dst++=128+(c&0x3f);
        }
      decoded+=2;
    }
  else if (c>=0x800 && c<=0xffff)
    {
      if (dst)
        {
        *dst++=224+(c>>12);
        *dst++=128+((c>>6)&0x3f);
        *dst++=128+(c&0x3f);
        }
      decoded+=3;
    }
  else if (c>=0x10000 && c<=0x1fffff)
    {
      if (dst)
        {
        *dst++=240+(c>>18);
        *dst++=128+((c>>10)&0x3f);
        *dst++=128+((c>>6)&0x3f);
        *dst++=128+(c&0x3f);
        }
      decoded+=4;
    }
  if (*src==' ' || *src=='\t' || *src=='\n')
    {
    while (*src==' ' || *src=='\t' || *src=='\n') ++src;
    if (src==end) return decoded;
    goto unicode_hex;
    }
  }
while (src<end);
return decoded;
}


/*************************************************
*       Decode encoded-character string          *
*************************************************/

/*
Encoding definition:
   encoded-arb-octets   = "${hex:" hex-pair-seq "}"
   encoded-unicode-char = "${unicode:" unicode-hex-seq "}"

Arguments:
  encoded     points to an encoded string, returns decoded string
  filter      points to the Sieve filter including its state

Returns:      1                success
              -1               syntax error
*/

static int string_decode(struct Sieve *filter, struct String *data)
{
uschar *src,*dst,*end;

src=data->character;
dst=src;
end=data->character+data->length;
while (src<end)
  {
  uschar *brace;

  if (
      strncmpic(src,US "${hex:",6)==0
      && (brace=Ustrchr(src+6,'}'))!=(uschar*)0
      && (hex_decode(src+6,brace,(uschar*)0))>=0
     )
    {
    dst+=hex_decode(src+6,brace,dst);
    src=brace+1;
    }
  else if (
           strncmpic(src,US "${unicode:",10)==0
           && (brace=Ustrchr(src+10,'}'))!=(uschar*)0
          )
    {
    switch (unicode_decode(src+10,brace,(uschar*)0))
      {
      case -2:
        {
        filter->errmsg=CUS "unicode character out of range";
        return -1;
        }
      case -1:
        {
        *dst++=*src++;
        break;
        }
      default:
        {
        dst+=unicode_decode(src+10,brace,dst);
        src=brace+1;
        }
      }
    }
  else *dst++=*src++;
  }
  data->length=dst-data->character;
  *dst='\0';
return 1;
}
#endif


/*************************************************
*          Parse an optional string              *
*************************************************/

/*
Token definition:
   quoted-string = DQUOTE *CHAR DQUOTE
           ;; in general, \ CHAR inside a string maps to CHAR
           ;; so \" maps to " and \\ maps to \
           ;; note that newlines and other characters are all allowed
           ;; in strings

   multi-line          = "text:" *(SP / HTAB) (hash-comment / CRLF)
                         *(multi-line-literal / multi-line-dotstuff)
                         "." CRLF
   multi-line-literal  = [CHAR-NOT-DOT *CHAR-NOT-CRLF] CRLF
   multi-line-dotstuff = "." 1*CHAR-NOT-CRLF CRLF
           ;; A line containing only "." ends the multi-line.
           ;; Remove a leading '.' if followed by another '.'.
  string           = quoted-string / multi-line

Arguments:
  filter      points to the Sieve filter including its state
  id          specifies identifier to match

Returns:      1                success
              -1               syntax error
              0                identifier not matched
*/

static int
parse_string(struct Sieve *filter, struct String *data)
{
gstring * g = NULL;

data->length = 0;
data->character = NULL;

if (*filter->pc=='"') /* quoted string */
  {
  ++filter->pc;
  while (*filter->pc)
    {
    if (*filter->pc=='"') /* end of string */
      {
      ++filter->pc;

      if (g)
	{
	data->character = string_from_gstring(g);
	data->length = g->ptr;
	}
      else
	data->character = US"\0";
      /* that way, there will be at least one character allocated */

#ifdef ENCODED_CHARACTER
      if (filter->require_encoded_character
          && string_decode(filter,data)==-1)
        return -1;
#endif
      return 1;
      }
    else if (*filter->pc=='\\' && *(filter->pc+1)) /* quoted character */
      {
      g = string_catn(g, filter->pc+1, 1);
      filter->pc+=2;
      }
    else /* regular character */
      {
#ifdef RFC_EOL
      if (*filter->pc=='\r' && *(filter->pc+1)=='\n') ++filter->line;
#else
      if (*filter->pc=='\n')
        {
        g = string_catn(g, US"\r", 1);
        ++filter->line;
        }
#endif
      g = string_catn(g, filter->pc, 1);
      filter->pc++;
      }
    }
  filter->errmsg=CUS "missing end of string";
  return -1;
  }
else if (Ustrncmp(filter->pc,CUS "text:",5)==0) /* multiline string */
  {
  filter->pc+=5;
  /* skip optional white space followed by hashed comment or CRLF */
  while (*filter->pc==' ' || *filter->pc=='\t') ++filter->pc;
  if (*filter->pc=='#')
    {
    if (parse_hashcomment(filter)==-1) return -1;
    }
#ifdef RFC_EOL
  else if (*filter->pc=='\r' && *(filter->pc+1)=='\n')
#else
  else if (*filter->pc=='\n')
#endif
    {
#ifdef RFC_EOL
    filter->pc+=2;
#else
    ++filter->pc;
#endif
    ++filter->line;
    }
  else
    {
    filter->errmsg=CUS "syntax error";
    return -1;
    }
  while (*filter->pc)
    {
#ifdef RFC_EOL
    if (*filter->pc=='\r' && *(filter->pc+1)=='\n') /* end of line */
#else
    if (*filter->pc=='\n') /* end of line */
#endif
      {
      g = string_catn(g, CUS "\r\n", 2);
#ifdef RFC_EOL
      filter->pc+=2;
#else
      ++filter->pc;
#endif
      ++filter->line;
#ifdef RFC_EOL
      if (*filter->pc=='.' && *(filter->pc+1)=='\r' && *(filter->pc+2)=='\n') /* end of string */
#else
      if (*filter->pc=='.' && *(filter->pc+1)=='\n') /* end of string */
#endif
        {
	if (g)
	  {
	  data->character = string_from_gstring(g);
	  data->length = g->ptr;
	  }
	else
	  data->character = US"\0";
	/* that way, there will be at least one character allocated */

#ifdef RFC_EOL
        filter->pc+=3;
#else
        filter->pc+=2;
#endif
        ++filter->line;
#ifdef ENCODED_CHARACTER
        if (filter->require_encoded_character
            && string_decode(filter,data)==-1)
          return -1;
#endif
        return 1;
        }
      else if (*filter->pc=='.' && *(filter->pc+1)=='.') /* remove dot stuffing */
        {
        g = string_catn(g, CUS ".", 1);
        filter->pc+=2;
        }
      }
    else /* regular character */
      {
      g = string_catn(g, filter->pc, 1);
      filter->pc++;
      }
    }
  filter->errmsg=CUS "missing end of multi line string";
  return -1;
  }
else return 0;
}


/*************************************************
*          Parse a specific identifier           *
*************************************************/

/*
Token definition:
  identifier       = (ALPHA / "_") *(ALPHA DIGIT "_")

Arguments:
  filter      points to the Sieve filter including its state
  id          specifies identifier to match

Returns:      1                success
              0                identifier not matched
*/

static int parse_identifier(struct Sieve *filter, const uschar *id)
{
  size_t idlen=Ustrlen(id);

  if (strncmpic(US filter->pc,US id,idlen)==0)
  {
    uschar next=filter->pc[idlen];

    if ((next>='A' && next<='Z') || (next>='a' && next<='z') || next=='_' || (next>='0' && next<='9')) return 0;
    filter->pc+=idlen;
    return 1;
  }
  else return 0;
}


/*************************************************
*                 Parse a number                 *
*************************************************/

/*
Token definition:
  number           = 1*DIGIT [QUANTIFIER]
  QUANTIFIER       = "K" / "M" / "G"

Arguments:
  filter      points to the Sieve filter including its state
  data        returns value

Returns:      1                success
              -1               no string list found
*/

static int parse_number(struct Sieve *filter, unsigned long *data)
{
unsigned long d,u;

if (*filter->pc>='0' && *filter->pc<='9')
  {
  uschar *e;

  errno=0;
  d=Ustrtoul(filter->pc,&e,10);
  if (errno==ERANGE)
    {
    filter->errmsg=CUstrerror(ERANGE);
    return -1;
    }
  filter->pc=e;
  u=1;
  if (*filter->pc=='K') { u=1024; ++filter->pc; }
  else if (*filter->pc=='M') { u=1024*1024; ++filter->pc; }
  else if (*filter->pc=='G') { u=1024*1024*1024; ++filter->pc; }
  if (d>(ULONG_MAX/u))
    {
    filter->errmsg=CUstrerror(ERANGE);
    return -1;
    }
  d*=u;
  *data=d;
  return 1;
  }
else
  {
  filter->errmsg=CUS "missing number";
  return -1;
  }
}


/*************************************************
*              Parse a string list               *
*************************************************/

/*
Grammar:
  string-list      = "[" string *("," string) "]" / string

Arguments:
  filter      points to the Sieve filter including its state
  data        returns string list

Returns:      1                success
              -1               no string list found
*/

static int
parse_stringlist(struct Sieve *filter, struct String **data)
{
const uschar *orig=filter->pc;
int dataCapacity = 0;
int dataLength = 0;
struct String *d = NULL;
int m;

if (*filter->pc=='[') /* string list */
  {
  ++filter->pc;
  for (;;)
    {
    if (parse_white(filter)==-1) goto error;
    if (dataLength+1 >= dataCapacity) /* increase buffer */
      {
      struct String *new;

      dataCapacity = dataCapacity ? dataCapacity * 2 : 4;
      new = store_get(sizeof(struct String) * dataCapacity);

      if (d) memcpy(new,d,sizeof(struct String)*dataLength);
      d = new;
      }

    m=parse_string(filter,&d[dataLength]);
    if (m==0)
      {
      if (dataLength==0) break;
      else
        {
        filter->errmsg=CUS "missing string";
        goto error;
        }
      }
    else if (m==-1) goto error;
    else ++dataLength;
    if (parse_white(filter)==-1) goto error;
    if (*filter->pc==',') ++filter->pc;
    else break;
    }
  if (*filter->pc==']')
    {
    d[dataLength].character=(uschar*)0;
    d[dataLength].length=-1;
    ++filter->pc;
    *data=d;
    return 1;
    }
  else
    {
    filter->errmsg=CUS "missing closing bracket";
    goto error;
    }
  }
else /* single string */
  {
  if ((d=store_get(sizeof(struct String)*2))==(struct String*)0)
    {
    return -1;
    }
  m=parse_string(filter,&d[0]);
  if (m==-1)
    {
    return -1;
    }
  else if (m==0)
    {
    filter->pc=orig;
    return 0;
    }
  else
    {
    d[1].character=(uschar*)0;
    d[1].length=-1;
    *data=d;
    return 1;
    }
  }
error:
filter->errmsg=CUS "missing string list";
return -1;
}


/*************************************************
*    Parse an optional address part specifier    *
*************************************************/

/*
Grammar:
  address-part     =  ":localpart" / ":domain" / ":all"
  address-part     =/ ":user" / ":detail"

Arguments:
  filter      points to the Sieve filter including its state
  a           returns address part specified

Returns:      1                success
              0                no comparator found
              -1               syntax error
*/

static int parse_addresspart(struct Sieve *filter, enum AddressPart *a)
{
#ifdef SUBADDRESS
if (parse_identifier(filter,CUS ":user")==1)
  {
  if (!filter->require_subaddress)
    {
    filter->errmsg=CUS "missing previous require \"subaddress\";";
    return -1;
    }
  *a=ADDRPART_USER;
  return 1;
  }
else if (parse_identifier(filter,CUS ":detail")==1)
  {
  if (!filter->require_subaddress)
    {
    filter->errmsg=CUS "missing previous require \"subaddress\";";
    return -1;
    }
  *a=ADDRPART_DETAIL;
  return 1;
  }
else
#endif
if (parse_identifier(filter,CUS ":localpart")==1)
  {
  *a=ADDRPART_LOCALPART;
  return 1;
  }
else if (parse_identifier(filter,CUS ":domain")==1)
  {
  *a=ADDRPART_DOMAIN;
  return 1;
  }
else if (parse_identifier(filter,CUS ":all")==1)
  {
  *a=ADDRPART_ALL;
  return 1;
  }
else return 0;
}


/*************************************************
*         Parse an optional comparator           *
*************************************************/

/*
Grammar:
  comparator = ":comparator" <comparator-name: string>

Arguments:
  filter      points to the Sieve filter including its state
  c           returns comparator

Returns:      1                success
              0                no comparator found
              -1               incomplete comparator found
*/

static int parse_comparator(struct Sieve *filter, enum Comparator *c)
{
struct String comparator_name;

if (parse_identifier(filter,CUS ":comparator")==0) return 0;
if (parse_white(filter)==-1) return -1;
switch (parse_string(filter,&comparator_name))
  {
  case -1: return -1;
  case 0:
    {
    filter->errmsg=CUS "missing comparator";
    return -1;
    }
  default:
    {
    int match;

    if (eq_asciicase(&comparator_name,&str_ioctet,0))
      {
      *c=COMP_OCTET;
      match=1;
      }
    else if (eq_asciicase(&comparator_name,&str_iascii_casemap,0))
      {
      *c=COMP_EN_ASCII_CASEMAP;
      match=1;
      }
    else if (eq_asciicase(&comparator_name,&str_enascii_casemap,0))
      {
      *c=COMP_EN_ASCII_CASEMAP;
      match=1;
      }
    else if (eq_asciicase(&comparator_name,&str_iascii_numeric,0))
      {
      *c=COMP_ASCII_NUMERIC;
      match=1;
      }
    else
      {
      filter->errmsg=CUS "invalid comparator";
      match=-1;
      }
    return match;
    }
  }
}


/*************************************************
*          Parse an optional match type          *
*************************************************/

/*
Grammar:
  match-type = ":is" / ":contains" / ":matches"

Arguments:
  filter      points to the Sieve filter including its state
  m           returns match type

Returns:      1                success
              0                no match type found
*/

static int parse_matchtype(struct Sieve *filter, enum MatchType *m)
{
  if (parse_identifier(filter,CUS ":is")==1)
  {
    *m=MATCH_IS;
    return 1;
  }
  else if (parse_identifier(filter,CUS ":contains")==1)
  {
    *m=MATCH_CONTAINS;
    return 1;
  }
  else if (parse_identifier(filter,CUS ":matches")==1)
  {
    *m=MATCH_MATCHES;
    return 1;
  }
  else return 0;
}


/*************************************************
*   Parse and interpret an optional test list    *
*************************************************/

/*
Grammar:
  test-list = "(" test *("," test) ")"

Arguments:
  filter      points to the Sieve filter including its state
  n           total number of tests
  num_true    number of passed tests
  exec        Execute parsed statements

Returns:      1                success
              0                no test list found
              -1               syntax or execution error
*/

static int parse_testlist(struct Sieve *filter, int *n, int *num_true, int exec)
{
if (parse_white(filter)==-1) return -1;
if (*filter->pc=='(')
  {
  ++filter->pc;
  *n=0;
   *num_true=0;
  for (;;)
    {
    int cond;

    switch (parse_test(filter,&cond,exec))
      {
      case -1: return -1;
      case 0: filter->errmsg=CUS "missing test"; return -1;
      default: ++*n; if (cond) ++*num_true; break;
      }
    if (parse_white(filter)==-1) return -1;
    if (*filter->pc==',') ++filter->pc;
    else break;
    }
  if (*filter->pc==')')
    {
    ++filter->pc;
    return 1;
    }
  else
    {
    filter->errmsg=CUS "missing closing paren";
    return -1;
    }
  }
else return 0;
}


/*************************************************
*     Parse and interpret an optional test       *
*************************************************/

/*
Arguments:
  filter      points to the Sieve filter including its state
  cond        returned condition status
  exec        Execute parsed statements

Returns:      1                success
              0                no test found
              -1               syntax or execution error
*/

static int parse_test(struct Sieve *filter, int *cond, int exec)
{
if (parse_white(filter)==-1) return -1;
if (parse_identifier(filter,CUS "address"))
  {
  /*
  address-test = "address" { [address-part] [comparator] [match-type] }
                 <header-list: string-list> <key-list: string-list>

  header-list From, To, Cc, Bcc, Sender, Resent-From, Resent-To
  */

  enum AddressPart addressPart=ADDRPART_ALL;
  enum Comparator comparator=COMP_EN_ASCII_CASEMAP;
  enum MatchType matchType=MATCH_IS;
  struct String *hdr,*h,*key,*k;
  int m;
  int ap=0,co=0,mt=0;

  for (;;)
    {
    if (parse_white(filter)==-1) return -1;
    if ((m=parse_addresspart(filter,&addressPart))!=0)
      {
      if (m==-1) return -1;
      if (ap)
        {
        filter->errmsg=CUS "address part already specified";
        return -1;
        }
      else ap=1;
      }
    else if ((m=parse_comparator(filter,&comparator))!=0)
      {
      if (m==-1) return -1;
      if (co)
        {
        filter->errmsg=CUS "comparator already specified";
        return -1;
        }
      else co=1;
      }
    else if ((m=parse_matchtype(filter,&matchType))!=0)
      {
      if (m==-1) return -1;
      if (mt)
        {
        filter->errmsg=CUS "match type already specified";
        return -1;
        }
      else mt=1;
      }
    else break;
    }
  if (parse_white(filter)==-1) return -1;
  if ((m=parse_stringlist(filter,&hdr))!=1)
    {
    if (m==0) filter->errmsg=CUS "header string list expected";
    return -1;
    }
  if (parse_white(filter)==-1) return -1;
  if ((m=parse_stringlist(filter,&key))!=1)
    {
    if (m==0) filter->errmsg=CUS "key string list expected";
    return -1;
    }
  *cond=0;
  for (h=hdr; h->length!=-1 && !*cond; ++h)
    {
    uschar *header_value=(uschar*)0,*extracted_addr,*end_addr;

    if
      (
      !eq_asciicase(h,&str_from,0)
      && !eq_asciicase(h,&str_to,0)
      && !eq_asciicase(h,&str_cc,0)
      && !eq_asciicase(h,&str_bcc,0)
      && !eq_asciicase(h,&str_sender,0)
      && !eq_asciicase(h,&str_resent_from,0)
      && !eq_asciicase(h,&str_resent_to,0)
      )
      {
      filter->errmsg=CUS "invalid header field";
      return -1;
      }
    if (exec)
      {
      /* We are only interested in addresses below, so no MIME decoding */
      header_value=expand_string(string_sprintf("$rheader_%s",quote(h)));
      if (header_value == NULL)
        {
        filter->errmsg=CUS "header string expansion failed";
        return -1;
        }
      f.parse_allow_group = TRUE;
      while (*header_value && !*cond)
        {
        uschar *error;
        int start, end, domain;
        int saveend;
        uschar *part=NULL;

        end_addr = parse_find_address_end(header_value, FALSE);
        saveend = *end_addr;
        *end_addr = 0;
        extracted_addr = parse_extract_address(header_value, &error, &start, &end, &domain, FALSE);

        if (extracted_addr) switch (addressPart)
          {
          case ADDRPART_ALL: part=extracted_addr; break;
#ifdef SUBADDRESS
          case ADDRPART_USER:
#endif
          case ADDRPART_LOCALPART: part=extracted_addr; part[domain-1]='\0'; break;
          case ADDRPART_DOMAIN: part=extracted_addr+domain; break;
#ifdef SUBADDRESS
          case ADDRPART_DETAIL: part=NULL; break;
#endif
          }

        *end_addr = saveend;
        if (part)
          {
          for (k=key; k->length!=-1; ++k)
            {
            struct String partStr;

            partStr.character=part;
            partStr.length=Ustrlen(part);
            if (extracted_addr)
              {
              *cond=compare(filter,k,&partStr,comparator,matchType);
              if (*cond==-1) return -1;
              if (*cond) break;
              }
            }
          }
        if (saveend == 0) break;
        header_value = end_addr + 1;
        }
      f.parse_allow_group = FALSE;
      f.parse_found_group = FALSE;
      }
    }
  return 1;
  }
else if (parse_identifier(filter,CUS "allof"))
  {
  /*
  allof-test   = "allof" <tests: test-list>
  */

  int n,num_true;

  switch (parse_testlist(filter,&n,&num_true,exec))
    {
    case -1: return -1;
    case 0: filter->errmsg=CUS "missing test list"; return -1;
    default: *cond=(n==num_true); return 1;
    }
  }
else if (parse_identifier(filter,CUS "anyof"))
  {
  /*
  anyof-test   = "anyof" <tests: test-list>
  */

  int n,num_true;

  switch (parse_testlist(filter,&n,&num_true,exec))
    {
    case -1: return -1;
    case 0: filter->errmsg=CUS "missing test list"; return -1;
    default: *cond=(num_true>0); return 1;
    }
  }
else if (parse_identifier(filter,CUS "exists"))
  {
  /*
  exists-test = "exists" <header-names: string-list>
  */

  struct String *hdr,*h;
  int m;

  if (parse_white(filter)==-1) return -1;
  if ((m=parse_stringlist(filter,&hdr))!=1)
    {
    if (m==0) filter->errmsg=CUS "header string list expected";
    return -1;
    }
  if (exec)
    {
    *cond=1;
    for (h=hdr; h->length!=-1 && *cond; ++h)
      {
      uschar *header_def;

      header_def=expand_string(string_sprintf("${if def:header_%s {true}{false}}",quote(h)));
      if (header_def == NULL)
        {
        filter->errmsg=CUS "header string expansion failed";
        return -1;
        }
      if (Ustrcmp(header_def,"false")==0) *cond=0;
      }
    }
  return 1;
  }
else if (parse_identifier(filter,CUS "false"))
  {
  /*
  false-test = "false"
  */

  *cond=0;
  return 1;
  }
else if (parse_identifier(filter,CUS "header"))
  {
  /*
  header-test = "header" { [comparator] [match-type] }
                <header-names: string-list> <key-list: string-list>
  */

  enum Comparator comparator=COMP_EN_ASCII_CASEMAP;
  enum MatchType matchType=MATCH_IS;
  struct String *hdr,*h,*key,*k;
  int m;
  int co=0,mt=0;

  for (;;)
    {
    if (parse_white(filter)==-1) return -1;
    if ((m=parse_comparator(filter,&comparator))!=0)
      {
      if (m==-1) return -1;
      if (co)
        {
        filter->errmsg=CUS "comparator already specified";
        return -1;
        }
      else co=1;
      }
    else if ((m=parse_matchtype(filter,&matchType))!=0)
      {
      if (m==-1) return -1;
      if (mt)
        {
        filter->errmsg=CUS "match type already specified";
        return -1;
        }
      else mt=1;
      }
    else break;
    }
  if (parse_white(filter)==-1) return -1;
  if ((m=parse_stringlist(filter,&hdr))!=1)
    {
    if (m==0) filter->errmsg=CUS "header string list expected";
    return -1;
    }
  if (parse_white(filter)==-1) return -1;
  if ((m=parse_stringlist(filter,&key))!=1)
    {
    if (m==0) filter->errmsg=CUS "key string list expected";
    return -1;
    }
  *cond=0;
  for (h=hdr; h->length!=-1 && !*cond; ++h)
    {
    if (!is_header(h))
      {
      filter->errmsg=CUS "invalid header field";
      return -1;
      }
    if (exec)
      {
      struct String header_value;
      uschar *header_def;

      expand_header(&header_value,h);
      header_def=expand_string(string_sprintf("${if def:header_%s {true}{false}}",quote(h)));
      if (header_value.character == NULL || header_def == NULL)
        {
        filter->errmsg=CUS "header string expansion failed";
        return -1;
        }
      for (k=key; k->length!=-1; ++k)
        {
        if (Ustrcmp(header_def,"true")==0)
          {
          *cond=compare(filter,k,&header_value,comparator,matchType);
          if (*cond==-1) return -1;
          if (*cond) break;
          }
        }
      }
    }
  return 1;
  }
else if (parse_identifier(filter,CUS "not"))
  {
  if (parse_white(filter)==-1) return -1;
  switch (parse_test(filter,cond,exec))
    {
    case -1: return -1;
    case 0: filter->errmsg=CUS "missing test"; return -1;
    default: *cond=!*cond; return 1;
    }
  }
else if (parse_identifier(filter,CUS "size"))
  {
  /*
  relop = ":over" / ":under"
  size-test = "size" relop <limit: number>
  */

  unsigned long limit;
  int overNotUnder;

  if (parse_white(filter)==-1) return -1;
  if (parse_identifier(filter,CUS ":over")) overNotUnder=1;
  else if (parse_identifier(filter,CUS ":under")) overNotUnder=0;
  else
    {
    filter->errmsg=CUS "missing :over or :under";
    return -1;
    }
  if (parse_white(filter)==-1) return -1;
  if (parse_number(filter,&limit)==-1) return -1;
  *cond=(overNotUnder ? (message_size>limit) : (message_size<limit));
  return 1;
  }
else if (parse_identifier(filter,CUS "true"))
  {
  *cond=1;
  return 1;
  }
else if (parse_identifier(filter,CUS "envelope"))
  {
  /*
  envelope-test = "envelope" { [comparator] [address-part] [match-type] }
                  <envelope-part: string-list> <key-list: string-list>

  envelope-part is case insensitive "from" or "to"
#ifdef ENVELOPE_AUTH
  envelope-part =/ "auth"
#endif
  */

  enum Comparator comparator=COMP_EN_ASCII_CASEMAP;
  enum AddressPart addressPart=ADDRPART_ALL;
  enum MatchType matchType=MATCH_IS;
  struct String *env,*e,*key,*k;
  int m;
  int co=0,ap=0,mt=0;

  if (!filter->require_envelope)
    {
    filter->errmsg=CUS "missing previous require \"envelope\";";
    return -1;
    }
  for (;;)
    {
    if (parse_white(filter)==-1) return -1;
    if ((m=parse_comparator(filter,&comparator))!=0)
      {
      if (m==-1) return -1;
      if (co)
        {
        filter->errmsg=CUS "comparator already specified";
        return -1;
        }
      else co=1;
      }
    else if ((m=parse_addresspart(filter,&addressPart))!=0)
      {
      if (m==-1) return -1;
      if (ap)
        {
        filter->errmsg=CUS "address part already specified";
        return -1;
        }
      else ap=1;
      }
    else if ((m=parse_matchtype(filter,&matchType))!=0)
      {
      if (m==-1) return -1;
      if (mt)
        {
        filter->errmsg=CUS "match type already specified";
        return -1;
        }
      else mt=1;
      }
    else break;
    }
  if (parse_white(filter)==-1) return -1;
  if ((m=parse_stringlist(filter,&env))!=1)
    {
    if (m==0) filter->errmsg=CUS "envelope string list expected";
    return -1;
    }
  if (parse_white(filter)==-1) return -1;
  if ((m=parse_stringlist(filter,&key))!=1)
    {
    if (m==0) filter->errmsg=CUS "key string list expected";
    return -1;
    }
  *cond=0;
  for (e=env; e->length!=-1 && !*cond; ++e)
    {
    const uschar *envelopeExpr=CUS 0;
    uschar *envelope=US 0;

    if (eq_asciicase(e,&str_from,0))
      {
      switch (addressPart)
        {
        case ADDRPART_ALL: envelopeExpr=CUS "$sender_address"; break;
#ifdef SUBADDRESS
        case ADDRPART_USER:
#endif
        case ADDRPART_LOCALPART: envelopeExpr=CUS "${local_part:$sender_address}"; break;
        case ADDRPART_DOMAIN: envelopeExpr=CUS "${domain:$sender_address}"; break;
#ifdef SUBADDRESS
        case ADDRPART_DETAIL: envelopeExpr=CUS 0; break;
#endif
        }
      }
    else if (eq_asciicase(e,&str_to,0))
      {
      switch (addressPart)
        {
        case ADDRPART_ALL: envelopeExpr=CUS "$local_part_prefix$local_part$local_part_suffix@$domain"; break;
#ifdef SUBADDRESS
        case ADDRPART_USER: envelopeExpr=filter->useraddress; break;
        case ADDRPART_DETAIL: envelopeExpr=filter->subaddress; break;
#endif
        case ADDRPART_LOCALPART: envelopeExpr=CUS "$local_part_prefix$local_part$local_part_suffix"; break;
        case ADDRPART_DOMAIN: envelopeExpr=CUS "$domain"; break;
        }
      }
#ifdef ENVELOPE_AUTH
    else if (eq_asciicase(e,&str_auth,0))
      {
      switch (addressPart)
        {
        case ADDRPART_ALL: envelopeExpr=CUS "$authenticated_sender"; break;
#ifdef SUBADDRESS
        case ADDRPART_USER:
#endif
        case ADDRPART_LOCALPART: envelopeExpr=CUS "${local_part:$authenticated_sender}"; break;
        case ADDRPART_DOMAIN: envelopeExpr=CUS "${domain:$authenticated_sender}"; break;
#ifdef SUBADDRESS
        case ADDRPART_DETAIL: envelopeExpr=CUS 0; break;
#endif
        }
      }
#endif
    else
      {
      filter->errmsg=CUS "invalid envelope string";
      return -1;
      }
    if (exec && envelopeExpr)
      {
      if ((envelope=expand_string(US envelopeExpr)) == NULL)
        {
        filter->errmsg=CUS "header string expansion failed";
        return -1;
        }
      for (k=key; k->length!=-1; ++k)
        {
        struct String envelopeStr;

        envelopeStr.character=envelope;
        envelopeStr.length=Ustrlen(envelope);
        *cond=compare(filter,k,&envelopeStr,comparator,matchType);
        if (*cond==-1) return -1;
        if (*cond) break;
        }
      }
    }
  return 1;
  }
#ifdef ENOTIFY
else if (parse_identifier(filter,CUS "valid_notify_method"))
  {
  /*
  valid_notify_method = "valid_notify_method"
                        <notification-uris: string-list>
  */

  struct String *uris,*u;
  int m;

  if (!filter->require_enotify)
    {
    filter->errmsg=CUS "missing previous require \"enotify\";";
    return -1;
    }
  if (parse_white(filter)==-1) return -1;
  if ((m=parse_stringlist(filter,&uris))!=1)
    {
    if (m==0) filter->errmsg=CUS "URI string list expected";
    return -1;
    }
  if (exec)
    {
    *cond=1;
    for (u=uris; u->length!=-1 && *cond; ++u)
      {
        string_item *recipient;
        struct String header,subject,body;

        recipient=NULL;
        header.length=-1;
        header.character=(uschar*)0;
        subject.length=-1;
        subject.character=(uschar*)0;
        body.length=-1;
        body.character=(uschar*)0;
        if (parse_mailto_uri(filter,u->character,&recipient,&header,&subject,&body)!=1)
          *cond=0;
      }
    }
  return 1;
  }
else if (parse_identifier(filter,CUS "notify_method_capability"))
  {
  /*
  notify_method_capability = "notify_method_capability" [COMPARATOR] [MATCH-TYPE]
                             <notification-uri: string>
                             <notification-capability: string>
                             <key-list: string-list>
  */

  int m;
  int co=0,mt=0;

  enum Comparator comparator=COMP_EN_ASCII_CASEMAP;
  enum MatchType matchType=MATCH_IS;
  struct String uri,capa,*keys,*k;

  if (!filter->require_enotify)
    {
    filter->errmsg=CUS "missing previous require \"enotify\";";
    return -1;
    }
  for (;;)
    {
    if (parse_white(filter)==-1) return -1;
    if ((m=parse_comparator(filter,&comparator))!=0)
      {
      if (m==-1) return -1;
      if (co)
        {
        filter->errmsg=CUS "comparator already specified";
        return -1;
        }
      else co=1;
      }
    else if ((m=parse_matchtype(filter,&matchType))!=0)
      {
      if (m==-1) return -1;
      if (mt)
        {
        filter->errmsg=CUS "match type already specified";
        return -1;
        }
      else mt=1;
      }
    else break;
    }
    if ((m=parse_string(filter,&uri))!=1)
      {
      if (m==0) filter->errmsg=CUS "missing notification URI string";
      return -1;
      }
    if (parse_white(filter)==-1) return -1;
    if ((m=parse_string(filter,&capa))!=1)
      {
      if (m==0) filter->errmsg=CUS "missing notification capability string";
      return -1;
      }
    if (parse_white(filter)==-1) return -1;
    if ((m=parse_stringlist(filter,&keys))!=1)
      {
      if (m==0) filter->errmsg=CUS "missing key string list";
      return -1;
      }
    if (exec)
      {
      string_item *recipient;
      struct String header,subject,body;

      *cond=0;
      recipient=NULL;
      header.length=-1;
      header.character=(uschar*)0;
      subject.length=-1;
      subject.character=(uschar*)0;
      body.length=-1;
      body.character=(uschar*)0;
      if (parse_mailto_uri(filter,uri.character,&recipient,&header,&subject,&body)==1)
        {
        if (eq_asciicase(&capa,&str_online,0)==1)
          for (k=keys; k->length!=-1; ++k)
            {
            *cond=compare(filter,k,&str_maybe,comparator,matchType);
            if (*cond==-1) return -1;
            if (*cond) break;
            }
        }
      }
    return 1;
  }
#endif
else return 0;
}


/*************************************************
*     Parse and interpret an optional block      *
*************************************************/

/*
Arguments:
  filter      points to the Sieve filter including its state
  exec        Execute parsed statements
  generated   where to hang newly-generated addresses

Returns:      2                success by stop
              1                other success
              0                no block command found
              -1               syntax or execution error
*/

static int parse_block(struct Sieve *filter, int exec,
  address_item **generated)
{
int r;

if (parse_white(filter)==-1) return -1;
if (*filter->pc=='{')
  {
  ++filter->pc;
  if ((r=parse_commands(filter,exec,generated))==-1 || r==2) return r;
  if (*filter->pc=='}')
    {
    ++filter->pc;
    return 1;
    }
  else
    {
    filter->errmsg=CUS "expecting command or closing brace";
    return -1;
    }
  }
else return 0;
}


/*************************************************
*           Match a semicolon                    *
*************************************************/

/*
Arguments:
  filter      points to the Sieve filter including its state

Returns:      1                success
              -1               syntax error
*/

static int parse_semicolon(struct Sieve *filter)
{
  if (parse_white(filter)==-1) return -1;
  if (*filter->pc==';')
  {
    ++filter->pc;
    return 1;
  }
  else
  {
    filter->errmsg=CUS "missing semicolon";
    return -1;
  }
}


/*************************************************
*     Parse and interpret a Sieve command        *
*************************************************/

/*
Arguments:
  filter      points to the Sieve filter including its state
  exec        Execute parsed statements
  generated   where to hang newly-generated addresses

Returns:      2                success by stop
              1                other success
              -1               syntax or execution error
*/
static int
parse_commands(struct Sieve *filter, int exec, address_item **generated)
{
while (*filter->pc)
  {
  if (parse_white(filter)==-1) return -1;
  if (parse_identifier(filter,CUS "if"))
    {
    /*
    if-command = "if" test block *( "elsif" test block ) [ else block ]
    */

    int cond,m,unsuccessful;

    /* test block */
    if (parse_white(filter)==-1) return -1;
    if ((m=parse_test(filter,&cond,exec))==-1) return -1;
    if (m==0)
      {
      filter->errmsg=CUS "missing test";
      return -1;
      }
    if ((filter_test != FTEST_NONE && debug_selector != 0) ||
        (debug_selector & D_filter) != 0)
      {
      if (exec) debug_printf("if %s\n",cond?"true":"false");
      }
    m=parse_block(filter,exec ? cond : 0, generated);
    if (m==-1 || m==2) return m;
    if (m==0)
      {
      filter->errmsg=CUS "missing block";
      return -1;
      }
    unsuccessful = !cond;
    for (;;) /* elsif test block */
      {
      if (parse_white(filter)==-1) return -1;
      if (parse_identifier(filter,CUS "elsif"))
        {
        if (parse_white(filter)==-1) return -1;
        m=parse_test(filter,&cond,exec && unsuccessful);
        if (m==-1 || m==2) return m;
        if (m==0)
          {
          filter->errmsg=CUS "missing test";
          return -1;
          }
        if ((filter_test != FTEST_NONE && debug_selector != 0) ||
            (debug_selector & D_filter) != 0)
          {
          if (exec) debug_printf("elsif %s\n",cond?"true":"false");
          }
        m=parse_block(filter,exec && unsuccessful ? cond : 0, generated);
        if (m==-1 || m==2) return m;
        if (m==0)
          {
          filter->errmsg=CUS "missing block";
          return -1;
          }
        if (exec && unsuccessful && cond) unsuccessful = 0;
        }
      else break;
      }
    /* else block */
    if (parse_white(filter)==-1) return -1;
    if (parse_identifier(filter,CUS "else"))
      {
      m=parse_block(filter,exec && unsuccessful, generated);
      if (m==-1 || m==2) return m;
      if (m==0)
        {
        filter->errmsg=CUS "missing block";
        return -1;
        }
      }
    }
  else if (parse_identifier(filter,CUS "stop"))
    {
    /*
    stop-command     =  "stop" { stop-options } ";"
    stop-options     =
    */

    if (parse_semicolon(filter)==-1) return -1;
    if (exec)
      {
      filter->pc+=Ustrlen(filter->pc);
      return 2;
      }
    }
  else if (parse_identifier(filter,CUS "keep"))
    {
    /*
    keep-command     =  "keep" { keep-options } ";"
    keep-options     =
    */

    if (parse_semicolon(filter)==-1) return -1;
    if (exec)
      {
      add_addr(generated,US"inbox",1,0,0,0);
      filter->keep = 0;
      }
    }
  else if (parse_identifier(filter,CUS "discard"))
    {
    /*
    discard-command  =  "discard" { discard-options } ";"
    discard-options  =
    */

    if (parse_semicolon(filter)==-1) return -1;
    if (exec) filter->keep=0;
    }
  else if (parse_identifier(filter,CUS "redirect"))
    {
    /*
    redirect-command =  "redirect" redirect-options "string" ";"
    redirect-options =
    redirect-options =) ":copy"
    */

    struct String recipient;
    int m;
    int copy=0;

    for (;;)
      {
      if (parse_white(filter)==-1) return -1;
      if (parse_identifier(filter,CUS ":copy")==1)
        {
        if (!filter->require_copy)
          {
          filter->errmsg=CUS "missing previous require \"copy\";";
          return -1;
          }
          copy=1;
        }
      else break;
      }
    if (parse_white(filter)==-1) return -1;
    if ((m=parse_string(filter,&recipient))!=1)
      {
      if (m==0) filter->errmsg=CUS "missing redirect recipient string";
      return -1;
      }
    if (strchr(CCS recipient.character,'@')==(char*)0)
      {
      filter->errmsg=CUS "unqualified recipient address";
      return -1;
      }
    if (exec)
      {
      add_addr(generated,recipient.character,0,0,0,0);
      if (!copy) filter->keep = 0;
      }
    if (parse_semicolon(filter)==-1) return -1;
    }
  else if (parse_identifier(filter,CUS "fileinto"))
    {
    /*
    fileinto-command =  "fileinto" { fileinto-options } string ";"
    fileinto-options =
    fileinto-options =) [ ":copy" ]
    */

    struct String folder;
    uschar *s;
    int m;
    unsigned long maxage, maxmessages, maxstorage;
    int copy=0;

    maxage = maxmessages = maxstorage = 0;
    if (!filter->require_fileinto)
      {
      filter->errmsg=CUS "missing previous require \"fileinto\";";
      return -1;
      }
    for (;;)
      {
      if (parse_white(filter)==-1) return -1;
      if (parse_identifier(filter,CUS ":copy")==1)
        {
        if (!filter->require_copy)
          {
          filter->errmsg=CUS "missing previous require \"copy\";";
          return -1;
          }
          copy=1;
        }
      else break;
      }
    if (parse_white(filter)==-1) return -1;
    if ((m=parse_string(filter,&folder))!=1)
      {
      if (m==0) filter->errmsg=CUS "missing fileinto folder string";
      return -1;
      }
    m=0; s=folder.character;
    if (folder.length==0) m=1;
    if (Ustrcmp(s,"..")==0 || Ustrncmp(s,"../",3)==0) m=1;
    else while (*s)
      {
      if (Ustrcmp(s,"/..")==0 || Ustrncmp(s,"/../",4)==0) { m=1; break; }
      ++s;
      }
    if (m)
      {
      filter->errmsg=CUS "invalid folder";
      return -1;
      }
    if (exec)
      {
      add_addr(generated, folder.character, 1, maxage, maxmessages, maxstorage);
      if (!copy) filter->keep = 0;
      }
    if (parse_semicolon(filter)==-1) return -1;
    }
#ifdef ENOTIFY
  else if (parse_identifier(filter,CUS "notify"))
    {
    /*
    notify-command =  "notify" { notify-options } <method: string> ";"
    notify-options =  [":from" string]
                      [":importance" <"1" / "2" / "3">]
                      [":options" 1*(string-list / number)]
                      [":message" string]
    */

    int m;
    struct String from;
    struct String importance;
    struct String message;
    struct String method;
    struct Notification *already;
    string_item *recipient;
    struct String header;
    struct String subject;
    struct String body;
    uschar *envelope_from;
    struct String auto_submitted_value;
    uschar *auto_submitted_def;

    if (!filter->require_enotify)
      {
      filter->errmsg=CUS "missing previous require \"enotify\";";
      return -1;
      }
    from.character=(uschar*)0;
    from.length=-1;
    importance.character=(uschar*)0;
    importance.length=-1;
    message.character=(uschar*)0;
    message.length=-1;
    recipient=NULL;
    header.length=-1;
    header.character=(uschar*)0;
    subject.length=-1;
    subject.character=(uschar*)0;
    body.length=-1;
    body.character=(uschar*)0;
    envelope_from=(sender_address && sender_address[0]) ? expand_string(US"$local_part_prefix$local_part$local_part_suffix@$domain") : US "";
    for (;;)
      {
      if (parse_white(filter)==-1) return -1;
      if (parse_identifier(filter,CUS ":from")==1)
        {
        if (parse_white(filter)==-1) return -1;
        if ((m=parse_string(filter,&from))!=1)
          {
          if (m==0) filter->errmsg=CUS "from string expected";
          return -1;
          }
        }
      else if (parse_identifier(filter,CUS ":importance")==1)
        {
        if (parse_white(filter)==-1) return -1;
        if ((m=parse_string(filter,&importance))!=1)
          {
          if (m==0) filter->errmsg=CUS "importance string expected";
          return -1;
          }
        if (importance.length!=1 || importance.character[0]<'1' || importance.character[0]>'3')
          {
          filter->errmsg=CUS "invalid importance";
          return -1;
          }
        }
      else if (parse_identifier(filter,CUS ":options")==1)
        {
        if (parse_white(filter)==-1) return -1;
        }
      else if (parse_identifier(filter,CUS ":message")==1)
        {
        if (parse_white(filter)==-1) return -1;
        if ((m=parse_string(filter,&message))!=1)
          {
          if (m==0) filter->errmsg=CUS "message string expected";
          return -1;
          }
        }
      else break;
      }
    if (parse_white(filter)==-1) return -1;
    if ((m=parse_string(filter,&method))!=1)
      {
      if (m==0) filter->errmsg=CUS "missing method string";
      return -1;
      }
    if (parse_semicolon(filter)==-1) return -1;
    if (parse_mailto_uri(filter,method.character,&recipient,&header,&subject,&body)!=1)
      return -1;
    if (exec)
      {
      if (message.length==-1) message=subject;
      if (message.length==-1) expand_header(&message,&str_subject);
      expand_header(&auto_submitted_value,&str_auto_submitted);
      auto_submitted_def=expand_string(string_sprintf("${if def:header_auto-submitted {true}{false}}"));
      if (auto_submitted_value.character == NULL || auto_submitted_def == NULL)
        {
        filter->errmsg=CUS "header string expansion failed";
        return -1;
        }
        if (Ustrcmp(auto_submitted_def,"true")!=0 || Ustrcmp(auto_submitted_value.character,"no")==0)
        {
        for (already=filter->notified; already; already=already->next)
          {
          if (already->method.length==method.length
              && (method.length==-1 || Ustrcmp(already->method.character,method.character)==0)
              && already->importance.length==importance.length
              && (importance.length==-1 || Ustrcmp(already->importance.character,importance.character)==0)
              && already->message.length==message.length
              && (message.length==-1 || Ustrcmp(already->message.character,message.character)==0))
            break;
          }
        if (already==(struct Notification*)0)
          /* New notification, process it */
          {
          struct Notification *sent;
          sent=store_get(sizeof(struct Notification));
          sent->method=method;
          sent->importance=importance;
          sent->message=message;
          sent->next=filter->notified;
          filter->notified=sent;
  #ifndef COMPILE_SYNTAX_CHECKER
          if (filter_test == FTEST_NONE)
            {
            string_item *p;
            int pid,fd;

            if ((pid = child_open_exim2(&fd,envelope_from,envelope_from))>=1)
              {
              FILE *f;
              uschar *buffer;
              int buffer_capacity;

              f = fdopen(fd, "wb");
              fprintf(f,"From: %s\n",from.length==-1 ? expand_string(US"$local_part_prefix$local_part$local_part_suffix@$domain") : from.character);
              for (p=recipient; p; p=p->next) fprintf(f,"To: %s\n",p->text);
              fprintf(f,"Auto-Submitted: auto-notified; %s\n",filter->enotify_mailto_owner);
              if (header.length>0) fprintf(f,"%s",header.character);
              if (message.length==-1)
                {
                message.character=US"Notification";
                message.length=Ustrlen(message.character);
                }
              /* Allocation is larger than necessary, but enough even for split MIME words */
              buffer_capacity=32+4*message.length;
              buffer=store_get(buffer_capacity);
              if (message.length!=-1) fprintf(f,"Subject: %s\n",parse_quote_2047(message.character, message.length, US"utf-8", buffer, buffer_capacity, TRUE));
              fprintf(f,"\n");
              if (body.length>0) fprintf(f,"%s\n",body.character);
              fflush(f);
              (void)fclose(f);
              (void)child_close(pid, 0);
              }
            }
          if ((filter_test != FTEST_NONE && debug_selector != 0) || (debug_selector & D_filter) != 0)
            {
            debug_printf("Notification to `%s': '%s'.\n",method.character,message.length!=-1 ? message.character : CUS "");
            }
#endif
          }
        else
          {
          if ((filter_test != FTEST_NONE && debug_selector != 0) || (debug_selector & D_filter) != 0)
            {
            debug_printf("Repeated notification to `%s' ignored.\n",method.character);
            }
          }
        }
      else
        {
        if ((filter_test != FTEST_NONE && debug_selector != 0) || (debug_selector & D_filter) != 0)
          {
          debug_printf("Ignoring notification, triggering message contains Auto-submitted: field.\n");
          }
        }
      }
    }
#endif
#ifdef VACATION
  else if (parse_identifier(filter,CUS "vacation"))
    {
    /*
    vacation-command =  "vacation" { vacation-options } <reason: string> ";"
    vacation-options =  [":days" number]
                        [":subject" string]
                        [":from" string]
                        [":addresses" string-list]
                        [":mime"]
                        [":handle" string]
    */

    int m;
    unsigned long days;
    struct String subject;
    struct String from;
    struct String *addresses;
    int reason_is_mime;
    string_item *aliases;
    struct String handle;
    struct String reason;

    if (!filter->require_vacation)
      {
      filter->errmsg=CUS "missing previous require \"vacation\";";
      return -1;
      }
    if (exec)
      {
      if (filter->vacation_ran)
        {
        filter->errmsg=CUS "trying to execute vacation more than once";
        return -1;
        }
      filter->vacation_ran=1;
      }
    days=VACATION_MIN_DAYS>7 ? VACATION_MIN_DAYS : 7;
    subject.character=(uschar*)0;
    subject.length=-1;
    from.character=(uschar*)0;
    from.length=-1;
    addresses=(struct String*)0;
    aliases=NULL;
    reason_is_mime=0;
    handle.character=(uschar*)0;
    handle.length=-1;
    for (;;)
      {
      if (parse_white(filter)==-1) return -1;
      if (parse_identifier(filter,CUS ":days")==1)
        {
        if (parse_white(filter)==-1) return -1;
        if (parse_number(filter,&days)==-1) return -1;
        if (days<VACATION_MIN_DAYS) days=VACATION_MIN_DAYS;
        else if (days>VACATION_MAX_DAYS) days=VACATION_MAX_DAYS;
        }
      else if (parse_identifier(filter,CUS ":subject")==1)
        {
        if (parse_white(filter)==-1) return -1;
        if ((m=parse_string(filter,&subject))!=1)
          {
          if (m==0) filter->errmsg=CUS "subject string expected";
          return -1;
          }
        }
      else if (parse_identifier(filter,CUS ":from")==1)
        {
        if (parse_white(filter)==-1) return -1;
        if ((m=parse_string(filter,&from))!=1)
          {
          if (m==0) filter->errmsg=CUS "from string expected";
          return -1;
          }
        if (check_mail_address(filter,&from)!=1)
          return -1;
        }
      else if (parse_identifier(filter,CUS ":addresses")==1)
        {
        struct String *a;

        if (parse_white(filter)==-1) return -1;
        if ((m=parse_stringlist(filter,&addresses))!=1)
          {
          if (m==0) filter->errmsg=CUS "addresses string list expected";
          return -1;
          }
        for (a=addresses; a->length!=-1; ++a)
          {
          string_item *new;

          new=store_get(sizeof(string_item));
          new->text=store_get(a->length+1);
          if (a->length) memcpy(new->text,a->character,a->length);
          new->text[a->length]='\0';
          new->next=aliases;
          aliases=new;
          }
        }
      else if (parse_identifier(filter,CUS ":mime")==1)
        reason_is_mime=1;
      else if (parse_identifier(filter,CUS ":handle")==1)
        {
        if (parse_white(filter)==-1) return -1;
        if ((m=parse_string(filter,&from))!=1)
          {
          if (m==0) filter->errmsg=CUS "handle string expected";
          return -1;
          }
        }
      else break;
      }
    if (parse_white(filter)==-1) return -1;
    if ((m=parse_string(filter,&reason))!=1)
      {
      if (m==0) filter->errmsg=CUS "missing reason string";
      return -1;
      }
    if (reason_is_mime)
      {
      uschar *s,*end;

      for (s=reason.character,end=reason.character+reason.length; s<end && (*s&0x80)==0; ++s);
      if (s<end)
        {
        filter->errmsg=CUS "MIME reason string contains 8bit text";
        return -1;
        }
      }
    if (parse_semicolon(filter)==-1) return -1;

    if (exec)
      {
      address_item *addr;
      uschar *buffer;
      int buffer_capacity;
      md5 base;
      uschar digest[16];
      uschar hexdigest[33];
      int i;
      gstring * once;

      if (filter_personal(aliases,TRUE))
        {
        if (filter_test == FTEST_NONE)
          {
          /* ensure oncelog directory exists; failure will be detected later */

          (void)directory_make(NULL, filter->vacation_directory, 0700, FALSE);
          }
        /* build oncelog filename */

        md5_start(&base);

        if (handle.length==-1)
          {
	  gstring * key = NULL;
          if (subject.length!=-1) key =string_catn(key, subject.character, subject.length);
          if (from.length!=-1) key = string_catn(key, from.character, from.length);
          key = string_catn(key, reason_is_mime?US"1":US"0", 1);
          key = string_catn(key, reason.character, reason.length);
	  md5_end(&base, key->s, key->ptr, digest);
          }
        else
	  md5_end(&base, handle.character, handle.length, digest);

        for (i = 0; i < 16; i++) sprintf(CS (hexdigest+2*i), "%02X", digest[i]);

        if ((filter_test != FTEST_NONE && debug_selector != 0) || (debug_selector & D_filter) != 0)
          debug_printf("Sieve: mail was personal, vacation file basename: %s\n", hexdigest);

        if (filter_test == FTEST_NONE)
          {
          once = string_cat (NULL, filter->vacation_directory);
          once = string_catn(once, US"/", 1);
          once = string_catn(once, hexdigest, 33);

          /* process subject */

          if (subject.length==-1)
            {
            uschar *subject_def;

            subject_def=expand_string(US"${if def:header_subject {true}{false}}");
            if (Ustrcmp(subject_def,"true")==0)
              {
	      gstring * g = string_catn(NULL, US"Auto: ", 6);

              expand_header(&subject,&str_subject);
              g = string_catn(g, subject.character, subject.length);
	      subject.character = string_from_gstring(g);
              subject.length = g->ptr;
              }
            else
              {
              subject.character=US"Automated reply";
              subject.length=Ustrlen(subject.character);
              }
            }

          /* add address to list of generated addresses */

          addr = deliver_make_addr(string_sprintf(">%.256s", sender_address), FALSE);
          setflag(addr, af_pfr);
          addr->prop.ignore_error = TRUE;
          addr->next = *generated;
          *generated = addr;
          addr->reply = store_get(sizeof(reply_item));
          memset(addr->reply,0,sizeof(reply_item)); /* XXX */
          addr->reply->to = string_copy(sender_address);
          if (from.length==-1)
            addr->reply->from = expand_string(US"$local_part@$domain");
          else
            addr->reply->from = from.character;
          /* Allocation is larger than necessary, but enough even for split MIME words */
          buffer_capacity=32+4*subject.length;
          buffer=store_get(buffer_capacity);
	  /* deconst cast safe as we pass in a non-const item */
          addr->reply->subject = US parse_quote_2047(subject.character, subject.length, US"utf-8", buffer, buffer_capacity, TRUE);
          addr->reply->oncelog = string_from_gstring(once);
          addr->reply->once_repeat=days*86400;

          /* build body and MIME headers */

          if (reason_is_mime)
            {
            uschar *mime_body,*reason_end;
            static const uschar nlnl[]="\r\n\r\n";

            for
              (
              mime_body = reason.character, reason_end = reason.character + reason.length;
              mime_body < (reason_end-(sizeof(nlnl)-1)) && memcmp(mime_body, nlnl, (sizeof(nlnl)-1));
              ++mime_body
              );

            addr->reply->headers = string_copyn(reason.character, mime_body-reason.character);

            if (mime_body+(sizeof(nlnl)-1)<reason_end) mime_body+=(sizeof(nlnl)-1);
            else mime_body=reason_end-1;
            addr->reply->text = string_copyn(mime_body, reason_end-mime_body);
            }
          else
            {
            struct String qp = { .character = NULL, .length = 0 };  /* Keep compiler happy (PH) */

            addr->reply->headers = US"MIME-Version: 1.0\n"
                                   "Content-Type: text/plain;\n"
                                   "\tcharset=\"utf-8\"\n"
                                   "Content-Transfer-Encoding: quoted-printable";
            addr->reply->text = quoted_printable_encode(&reason,&qp)->character;
            }
          }
        }
        else if ((filter_test != FTEST_NONE && debug_selector != 0) || (debug_selector & D_filter) != 0)
          debug_printf("Sieve: mail was not personal, vacation would ignore it\n");
      }
    }
    else break;
#endif
  }
return 1;
}


/*************************************************
*       Parse and interpret a sieve filter       *
*************************************************/

/*
Arguments:
  filter      points to the Sieve filter including its state
  exec        Execute parsed statements
  generated   where to hang newly-generated addresses

Returns:      1                success
              -1               syntax or execution error
*/

static int
parse_start(struct Sieve *filter, int exec, address_item **generated)
{
filter->pc=filter->filter;
filter->line=1;
filter->keep=1;
filter->require_envelope=0;
filter->require_fileinto=0;
#ifdef ENCODED_CHARACTER
filter->require_encoded_character=0;
#endif
#ifdef ENVELOPE_AUTH
filter->require_envelope_auth=0;
#endif
#ifdef ENOTIFY
filter->require_enotify=0;
filter->notified=(struct Notification*)0;
#endif
#ifdef SUBADDRESS
filter->require_subaddress=0;
#endif
#ifdef VACATION
filter->require_vacation=0;
filter->vacation_ran=0;
#endif
filter->require_copy=0;
filter->require_iascii_numeric=0;

if (parse_white(filter)==-1) return -1;

if (exec && filter->vacation_directory != NULL && filter_test == FTEST_NONE)
  {
  DIR *oncelogdir;
  struct dirent *oncelog;
  struct stat properties;
  time_t now;

  /* clean up old vacation log databases */

  oncelogdir=opendir(CS filter->vacation_directory);

  if (oncelogdir ==(DIR*)0 && errno != ENOENT)
    {
    filter->errmsg=CUS "unable to open vacation directory";
    return -1;
    }

  if (oncelogdir != NULL)
    {
    time(&now);

    while ((oncelog=readdir(oncelogdir))!=(struct dirent*)0)
      {
      if (strlen(oncelog->d_name)==32)
        {
        uschar *s=string_sprintf("%s/%s",filter->vacation_directory,oncelog->d_name);
        if (Ustat(s,&properties)==0 && (properties.st_mtime+VACATION_MAX_DAYS*86400)<now)
          Uunlink(s);
        }
      }
    closedir(oncelogdir);
    }
  }

while (parse_identifier(filter,CUS "require"))
  {
  /*
  require-command = "require" <capabilities: string-list>
  */

  struct String *cap,*check;
  int m;

  if (parse_white(filter)==-1) return -1;
  if ((m=parse_stringlist(filter,&cap))!=1)
    {
    if (m==0) filter->errmsg=CUS "capability string list expected";
    return -1;
    }
  for (check=cap; check->character; ++check)
    {
    if (eq_octet(check,&str_envelope,0)) filter->require_envelope=1;
    else if (eq_octet(check,&str_fileinto,0)) filter->require_fileinto=1;
#ifdef ENCODED_CHARACTER
    else if (eq_octet(check,&str_encoded_character,0)) filter->require_encoded_character=1;
#endif
#ifdef ENVELOPE_AUTH
    else if (eq_octet(check,&str_envelope_auth,0)) filter->require_envelope_auth=1;
#endif
#ifdef ENOTIFY
    else if (eq_octet(check,&str_enotify,0))
      {
      if (filter->enotify_mailto_owner == NULL)
        {
        filter->errmsg=CUS "enotify disabled";
        return -1;
        }
        filter->require_enotify=1;
      }
#endif
#ifdef SUBADDRESS
    else if (eq_octet(check,&str_subaddress,0)) filter->require_subaddress=1;
#endif
#ifdef VACATION
    else if (eq_octet(check,&str_vacation,0))
      {
      if (filter_test == FTEST_NONE && filter->vacation_directory == NULL)
        {
        filter->errmsg=CUS "vacation disabled";
        return -1;
        }
      filter->require_vacation=1;
      }
#endif
    else if (eq_octet(check,&str_copy,0)) filter->require_copy=1;
    else if (eq_octet(check,&str_comparator_ioctet,0)) ;
    else if (eq_octet(check,&str_comparator_iascii_casemap,0)) ;
    else if (eq_octet(check,&str_comparator_enascii_casemap,0)) ;
    else if (eq_octet(check,&str_comparator_iascii_numeric,0)) filter->require_iascii_numeric=1;
    else
      {
      filter->errmsg=CUS "unknown capability";
      return -1;
      }
    }
    if (parse_semicolon(filter)==-1) return -1;
  }
  if (parse_commands(filter,exec,generated)==-1) return -1;
  if (*filter->pc)
    {
    filter->errmsg=CUS "syntax error";
    return -1;
    }
  return 1;
}


/*************************************************
*            Interpret a sieve filter file       *
*************************************************/

/*
Arguments:
  filter      points to the entire file, read into store as a single string
  options     controls whether various special things are allowed, and requests
              special actions (not currently used)
  vacation_directory    where to store vacation "once" files
  enotify_mailto_owner  owner of mailto notifications
  useraddress string expression for :user part of address
  subaddress  string expression for :subaddress part of address
  generated   where to hang newly-generated addresses
  error       where to pass back an error text

Returns:      FF_DELIVERED     success, a significant action was taken
              FF_NOTDELIVERED  success, no significant action
              FF_DEFER         defer requested
              FF_FAIL          fail requested
              FF_FREEZE        freeze requested
              FF_ERROR         there was a problem
*/

int
sieve_interpret(uschar *filter, int options, uschar *vacation_directory,
  uschar *enotify_mailto_owner, uschar *useraddress, uschar *subaddress,
  address_item **generated, uschar **error)
{
struct Sieve sieve;
int r;
uschar *msg;

options = options; /* Keep picky compilers happy */
error = error;

DEBUG(D_route) debug_printf("Sieve: start of processing\n");
sieve.filter=filter;

if (vacation_directory == NULL)
  sieve.vacation_directory = NULL;
else
  {
  sieve.vacation_directory=expand_string(vacation_directory);
  if (sieve.vacation_directory == NULL)
    {
    *error = string_sprintf("failed to expand \"%s\" "
      "(sieve_vacation_directory): %s", vacation_directory,
      expand_string_message);
    return FF_ERROR;
    }
  }

if (enotify_mailto_owner == NULL)
  sieve.enotify_mailto_owner = NULL;
else
  {
  sieve.enotify_mailto_owner=expand_string(enotify_mailto_owner);
  if (sieve.enotify_mailto_owner == NULL)
    {
    *error = string_sprintf("failed to expand \"%s\" "
      "(sieve_enotify_mailto_owner): %s", enotify_mailto_owner,
      expand_string_message);
    return FF_ERROR;
    }
  }

sieve.useraddress = useraddress == NULL ? CUS "$local_part_prefix$local_part$local_part_suffix" : useraddress;
sieve.subaddress = subaddress;

#ifdef COMPILE_SYNTAX_CHECKER
if (parse_start(&sieve,0,generated)==1)
#else
if (parse_start(&sieve,1,generated)==1)
#endif
  {
  if (sieve.keep)
    {
    add_addr(generated,US"inbox",1,0,0,0);
    msg = string_sprintf("Implicit keep");
    r = FF_DELIVERED;
    }
  else
    {
    msg = string_sprintf("No implicit keep");
    r = FF_DELIVERED;
    }
  }
else
  {
  msg = string_sprintf("Sieve error: %s in line %d",sieve.errmsg,sieve.line);
#ifdef COMPILE_SYNTAX_CHECKER
  r = FF_ERROR;
  *error = msg;
#else
  add_addr(generated,US"inbox",1,0,0,0);
  r = FF_DELIVERED;
#endif
  }

#ifndef COMPILE_SYNTAX_CHECKER
if (filter_test != FTEST_NONE) printf("%s\n", (const char*) msg);
  else debug_printf("%s\n", msg);
#endif

DEBUG(D_route) debug_printf("Sieve: end of processing\n");
return r;
}
