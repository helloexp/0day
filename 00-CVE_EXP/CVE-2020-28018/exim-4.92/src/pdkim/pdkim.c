/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Copyright (C) 2009 - 2016  Tom Kistner <tom@duncanthrax.net>
 *  Copyright (C) 2016 - 2018  Jeremy Harris <jgh@exim.org>
 *
 *  http://duncanthrax.net/pdkim/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "../exim.h"


#ifndef DISABLE_DKIM	/* entire file */

#ifndef SUPPORT_TLS
# error Need SUPPORT_TLS for DKIM
#endif

#include "crypt_ver.h"

#ifdef SIGN_OPENSSL
# include <openssl/rsa.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
#elif defined(SIGN_GNUTLS)
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
#endif

#include "pdkim.h"
#include "signing.h"

#define PDKIM_SIGNATURE_VERSION     "1"
#define PDKIM_PUB_RECORD_VERSION    US "DKIM1"

#define PDKIM_MAX_HEADER_LEN        65536
#define PDKIM_MAX_HEADERS           512
#define PDKIM_MAX_BODY_LINE_LEN     16384
#define PDKIM_DNS_TXT_MAX_NAMELEN   1024

/* -------------------------------------------------------------------------- */
struct pdkim_stringlist {
  uschar * value;
  int      tag;
  void *   next;
};

/* -------------------------------------------------------------------------- */
/* A bunch of list constants */
const uschar * pdkim_querymethods[] = {
  US"dns/txt",
  NULL
};
const uschar * pdkim_canons[] = {
  US"simple",
  US"relaxed",
  NULL
};

const pdkim_hashtype pdkim_hashes[] = {
  { US"sha1",   HASH_SHA1 },
  { US"sha256", HASH_SHA2_256 },
  { US"sha512", HASH_SHA2_512 }
};

const uschar * pdkim_keytypes[] = {
  [KEYTYPE_RSA] =	US"rsa",
#ifdef SIGN_HAVE_ED25519
  [KEYTYPE_ED25519] =	US"ed25519",		/* Works for 3.6.0 GnuTLS, OpenSSL 1.1.1 */
#endif

#ifdef notyet_EC_dkim_extensions	/* https://tools.ietf.org/html/draft-srose-dkim-ecc-00 */
  US"eccp256",
  US"eccp348",
  US"ed448",
#endif
};

typedef struct pdkim_combined_canon_entry {
  const uschar *	str;
  int			canon_headers;
  int			canon_body;
} pdkim_combined_canon_entry;

pdkim_combined_canon_entry pdkim_combined_canons[] = {
  { US"simple/simple",    PDKIM_CANON_SIMPLE,   PDKIM_CANON_SIMPLE },
  { US"simple/relaxed",   PDKIM_CANON_SIMPLE,   PDKIM_CANON_RELAXED },
  { US"relaxed/simple",   PDKIM_CANON_RELAXED,  PDKIM_CANON_SIMPLE },
  { US"relaxed/relaxed",  PDKIM_CANON_RELAXED,  PDKIM_CANON_RELAXED },
  { US"simple",           PDKIM_CANON_SIMPLE,   PDKIM_CANON_SIMPLE },
  { US"relaxed",          PDKIM_CANON_RELAXED,  PDKIM_CANON_SIMPLE },
  { NULL,                 0,                    0 }
};


static blob lineending = {.data = US"\r\n", .len = 2};

/* -------------------------------------------------------------------------- */
uschar *
dkim_sig_to_a_tag(const pdkim_signature * sig)
{
if (  sig->keytype < 0  || sig->keytype > nelem(pdkim_keytypes)
   || sig->hashtype < 0 || sig->hashtype > nelem(pdkim_hashes))
  return US"err";
return string_sprintf("%s-%s",
  pdkim_keytypes[sig->keytype], pdkim_hashes[sig->hashtype].dkim_hashname);
}


int
pdkim_hashname_to_hashtype(const uschar * s, unsigned len)
{
int i;
if (!len) len = Ustrlen(s);
for (i = 0; i < nelem(pdkim_hashes); i++)
  if (Ustrncmp(s, pdkim_hashes[i].dkim_hashname, len) == 0)
    return i;
return -1;
}

void
pdkim_cstring_to_canons(const uschar * s, unsigned len,
  int * canon_head, int * canon_body)
{
int i;
if (!len) len = Ustrlen(s);
for (i = 0; pdkim_combined_canons[i].str; i++)
  if (  Ustrncmp(s, pdkim_combined_canons[i].str, len) == 0
     && len == Ustrlen(pdkim_combined_canons[i].str))
    {
    *canon_head = pdkim_combined_canons[i].canon_headers;
    *canon_body = pdkim_combined_canons[i].canon_body;
    break;
    }
}



const char *
pdkim_verify_status_str(int status)
{
switch(status)
  {
  case PDKIM_VERIFY_NONE:    return "PDKIM_VERIFY_NONE";
  case PDKIM_VERIFY_INVALID: return "PDKIM_VERIFY_INVALID";
  case PDKIM_VERIFY_FAIL:    return "PDKIM_VERIFY_FAIL";
  case PDKIM_VERIFY_PASS:    return "PDKIM_VERIFY_PASS";
  default:                   return "PDKIM_VERIFY_UNKNOWN";
  }
}

const char *
pdkim_verify_ext_status_str(int ext_status)
{
switch(ext_status)
  {
  case PDKIM_VERIFY_FAIL_BODY: return "PDKIM_VERIFY_FAIL_BODY";
  case PDKIM_VERIFY_FAIL_MESSAGE: return "PDKIM_VERIFY_FAIL_MESSAGE";
  case PDKIM_VERIFY_FAIL_SIG_ALGO_MISMATCH: return "PDKIM_VERIFY_FAIL_SIG_ALGO_MISMATCH";
  case PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE: return "PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE";
  case PDKIM_VERIFY_INVALID_BUFFER_SIZE: return "PDKIM_VERIFY_INVALID_BUFFER_SIZE";
  case PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD: return "PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD";
  case PDKIM_VERIFY_INVALID_PUBKEY_IMPORT: return "PDKIM_VERIFY_INVALID_PUBKEY_IMPORT";
  case PDKIM_VERIFY_INVALID_SIGNATURE_ERROR: return "PDKIM_VERIFY_INVALID_SIGNATURE_ERROR";
  case PDKIM_VERIFY_INVALID_DKIM_VERSION: return "PDKIM_VERIFY_INVALID_DKIM_VERSION";
  default: return "PDKIM_VERIFY_UNKNOWN";
  }
}

const uschar *
pdkim_errstr(int status)
{
switch(status)
  {
  case PDKIM_OK:		return US"OK";
  case PDKIM_FAIL:		return US"FAIL";
  case PDKIM_ERR_RSA_PRIVKEY:	return US"PRIVKEY";
  case PDKIM_ERR_RSA_SIGNING:	return US"SIGNING";
  case PDKIM_ERR_LONG_LINE:	return US"LONG_LINE";
  case PDKIM_ERR_BUFFER_TOO_SMALL:	return US"BUFFER_TOO_SMALL";
  case PDKIM_ERR_EXCESS_SIGS:	return US"EXCESS_SIGS";
  case PDKIM_SIGN_PRIVKEY_WRAP:	return US"PRIVKEY_WRAP";
  case PDKIM_SIGN_PRIVKEY_B64D:	return US"PRIVKEY_B64D";
  default: return US"(unknown)";
  }
}


/* -------------------------------------------------------------------------- */
/* Print debugging functions */
void
pdkim_quoteprint(const uschar *data, int len)
{
int i;
for (i = 0; i < len; i++)
  {
  const int c = data[i];
  switch (c)
    {
    case ' ' : debug_printf("{SP}"); break;
    case '\t': debug_printf("{TB}"); break;
    case '\r': debug_printf("{CR}"); break;
    case '\n': debug_printf("{LF}"); break;
    case '{' : debug_printf("{BO}"); break;
    case '}' : debug_printf("{BC}"); break;
    default:
      if ( (c < 32) || (c > 127) )
	debug_printf("{%02x}", c);
      else
	debug_printf("%c", c);
      break;
    }
  }
debug_printf("\n");
}

void
pdkim_hexprint(const uschar *data, int len)
{
int i;
if (data) for (i = 0 ; i < len; i++) debug_printf("%02x", data[i]);
else debug_printf("<NULL>");
debug_printf("\n");
}



static pdkim_stringlist *
pdkim_prepend_stringlist(pdkim_stringlist * base, const uschar * str)
{
pdkim_stringlist * new_entry = store_get(sizeof(pdkim_stringlist));

memset(new_entry, 0, sizeof(pdkim_stringlist));
new_entry->value = string_copy(str);
if (base) new_entry->next = base;
return new_entry;
}



/* Trim whitespace fore & aft */

static void
pdkim_strtrim(gstring * str)
{
uschar * p = str->s;
uschar * q;

while (*p == '\t' || *p == ' ')		/* dump the leading whitespace */
  { str->size--; str->ptr--; str->s++; }

while (  str->ptr > 0
      && ((q = str->s + str->ptr - 1),  (*q == '\t' || *q == ' '))
      )
  str->ptr--;				/* dump trailing whitespace */

(void) string_from_gstring(str);
}



/* -------------------------------------------------------------------------- */

DLLEXPORT void
pdkim_free_ctx(pdkim_ctx *ctx)
{
}


/* -------------------------------------------------------------------------- */
/* Matches the name of the passed raw "header" against
   the passed colon-separated "tick", and invalidates
   the entry in tick.  Entries can be prefixed for multi- or over-signing,
   in which case do not invalidate.

   Returns OK for a match, or fail-code
*/

static int
header_name_match(const uschar * header, uschar * tick)
{
const uschar * ticklist = tick;
int sep = ':';
BOOL multisign;
uschar * hname, * p, * ele;
uschar * hcolon = Ustrchr(header, ':');		/* Get header name */

if (!hcolon)
  return PDKIM_FAIL; /* This isn't a header */

/* if we had strncmpic() we wouldn't need this copy */
hname = string_copyn(header, hcolon-header);

while (p = US ticklist, ele = string_nextinlist(&ticklist, &sep, NULL, 0))
  {
  switch (*ele)
  {
  case '=': case '+':	multisign = TRUE; ele++; break;
  default:		multisign = FALSE; break;
  }

  if (strcmpic(ele, hname) == 0)
    {
    if (!multisign)
      *p = '_';	/* Invalidate this header name instance in tick-off list */
    return PDKIM_OK;
    }
  }
return PDKIM_FAIL;
}


/* -------------------------------------------------------------------------- */
/* Performs "relaxed" canonicalization of a header. */

uschar *
pdkim_relax_header_n(const uschar * header, int len, BOOL append_crlf)
{
BOOL past_field_name = FALSE;
BOOL seen_wsp = FALSE;
const uschar * p;
uschar * relaxed = store_get(len+3);
uschar * q = relaxed;

for (p = header; p - header < len; p++)
  {
  uschar c = *p;

  if (c == '\r' || c == '\n')	/* Ignore CR & LF */
    continue;
  if (c == '\t' || c == ' ')
    {
    if (seen_wsp)
      continue;
    c = ' ';			/* Turns WSP into SP */
    seen_wsp = TRUE;
    }
  else
    if (!past_field_name && c == ':')
      {
      if (seen_wsp) q--;	/* This removes WSP immediately before the colon */
      seen_wsp = TRUE;		/* This removes WSP immediately after the colon */
      past_field_name = TRUE;
      }
    else
      seen_wsp = FALSE;

  /* Lowercase header name */
  if (!past_field_name) c = tolower(c);
  *q++ = c;
  }

if (q > relaxed && q[-1] == ' ') q--; /* Squash eventual trailing SP */

if (append_crlf) { *q++ = '\r'; *q++ = '\n'; }
*q = '\0';
return relaxed;
}


uschar *
pdkim_relax_header(const uschar * header, BOOL append_crlf)
{
return pdkim_relax_header_n(header, Ustrlen(header), append_crlf);
}


/* -------------------------------------------------------------------------- */
#define PDKIM_QP_ERROR_DECODE -1

static const uschar *
pdkim_decode_qp_char(const uschar *qp_p, int *c)
{
const uschar *initial_pos = qp_p;

/* Advance one char */
qp_p++;

/* Check for two hex digits and decode them */
if (isxdigit(*qp_p) && isxdigit(qp_p[1]))
  {
  /* Do hex conversion */
  *c = (isdigit(*qp_p) ? *qp_p - '0' : toupper(*qp_p) - 'A' + 10) << 4;
  *c |= isdigit(qp_p[1]) ? qp_p[1] - '0' : toupper(qp_p[1]) - 'A' + 10;
  return qp_p + 2;
  }

/* Illegal char here */
*c = PDKIM_QP_ERROR_DECODE;
return initial_pos;
}


/* -------------------------------------------------------------------------- */

static uschar *
pdkim_decode_qp(const uschar * str)
{
int nchar = 0;
uschar * q;
const uschar * p = str;
uschar * n = store_get(Ustrlen(str)+1);

*n = '\0';
q = n;
while (*p)
  {
  if (*p == '=')
    {
    p = pdkim_decode_qp_char(p, &nchar);
    if (nchar >= 0)
      {
      *q++ = nchar;
      continue;
      }
    }
  else
    *q++ = *p;
  p++;
  }
*q = '\0';
return n;
}


/* -------------------------------------------------------------------------- */

void
pdkim_decode_base64(const uschar * str, blob * b)
{
int dlen = b64decode(str, &b->data);
if (dlen < 0) b->data = NULL;
b->len = dlen;
}

uschar *
pdkim_encode_base64(blob * b)
{
return b64encode(b->data, b->len);
}


/* -------------------------------------------------------------------------- */
#define PDKIM_HDR_LIMBO 0
#define PDKIM_HDR_TAG   1
#define PDKIM_HDR_VALUE 2

static pdkim_signature *
pdkim_parse_sig_header(pdkim_ctx * ctx, uschar * raw_hdr)
{
pdkim_signature * sig;
uschar *p, *q;
gstring * cur_tag = NULL;
gstring * cur_val = NULL;
BOOL past_hname = FALSE;
BOOL in_b_val = FALSE;
int where = PDKIM_HDR_LIMBO;
int i;

sig = store_get(sizeof(pdkim_signature));
memset(sig, 0, sizeof(pdkim_signature));
sig->bodylength = -1;

/* Set so invalid/missing data error display is accurate */
sig->version = 0;
sig->keytype = -1;
sig->hashtype = -1;

q = sig->rawsig_no_b_val = store_get(Ustrlen(raw_hdr)+1);

for (p = raw_hdr; ; p++)
  {
  char c = *p;

  /* Ignore FWS */
  if (c == '\r' || c == '\n')
    goto NEXT_CHAR;

  /* Fast-forward through header name */
  if (!past_hname)
    {
    if (c == ':') past_hname = TRUE;
    goto NEXT_CHAR;
    }

  if (where == PDKIM_HDR_LIMBO)
    {
    /* In limbo, just wait for a tag-char to appear */
    if (!(c >= 'a' && c <= 'z'))
      goto NEXT_CHAR;

    where = PDKIM_HDR_TAG;
    }

  if (where == PDKIM_HDR_TAG)
    {
    if (c >= 'a' && c <= 'z')
      cur_tag = string_catn(cur_tag, p, 1);

    if (c == '=')
      {
      if (Ustrcmp(string_from_gstring(cur_tag), "b") == 0)
        {
	*q++ = '=';
	in_b_val = TRUE;
	}
      where = PDKIM_HDR_VALUE;
      goto NEXT_CHAR;
      }
    }

  if (where == PDKIM_HDR_VALUE)
    {
    if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
      goto NEXT_CHAR;

    if (c == ';' || c == '\0')
      {
      /* We must have both tag and value, and tags must be one char except
      for the possibility of "bh". */

      if (  cur_tag && cur_val
	 && (cur_tag->ptr == 1 || *cur_tag->s == 'b')
	 )
        {
	(void) string_from_gstring(cur_val);
	pdkim_strtrim(cur_val);

	DEBUG(D_acl) debug_printf(" %s=%s\n", cur_tag->s, cur_val->s);

	switch (*cur_tag->s)
	  {
	  case 'b':				/* sig-data or body-hash */
	    switch (cur_tag->s[1])
	      {
	      case '\0': pdkim_decode_base64(cur_val->s, &sig->sighash); break;
	      case 'h':  if (cur_tag->ptr == 2)
			   pdkim_decode_base64(cur_val->s, &sig->bodyhash);
			 break;
	      default:   break;
	      }
	    break;
	  case 'v':					/* version */
	      /* We only support version 1, and that is currently the
		 only version there is. */
	    sig->version =
	      Ustrcmp(cur_val->s, PDKIM_SIGNATURE_VERSION) == 0 ? 1 : -1;
	    break;
	  case 'a':					/* algorithm */
	    {
	    const uschar * list = cur_val->s;
	    int sep = '-';
	    uschar * elem;

	    if ((elem = string_nextinlist(&list, &sep, NULL, 0)))
	      for(i = 0; i < nelem(pdkim_keytypes); i++)
		if (Ustrcmp(elem, pdkim_keytypes[i]) == 0)
		  { sig->keytype = i; break; }
	    if ((elem = string_nextinlist(&list, &sep, NULL, 0)))
	      for (i = 0; i < nelem(pdkim_hashes); i++)
		if (Ustrcmp(elem, pdkim_hashes[i].dkim_hashname) == 0)
		  { sig->hashtype = i; break; }
	    }

	  case 'c':					/* canonicalization */
	    pdkim_cstring_to_canons(cur_val->s, 0,
				    &sig->canon_headers, &sig->canon_body);
	    break;
	  case 'q':				/* Query method (for pubkey)*/
	    for (i = 0; pdkim_querymethods[i]; i++)
	      if (Ustrcmp(cur_val->s, pdkim_querymethods[i]) == 0)
	        {
		sig->querymethod = i;	/* we never actually use this */
		break;
		}
	    break;
	  case 's':					/* Selector */
	    sig->selector = string_copyn(cur_val->s, cur_val->ptr); break;
	  case 'd':					/* SDID */
	    sig->domain = string_copyn(cur_val->s, cur_val->ptr); break;
	  case 'i':					/* AUID */
	    sig->identity = pdkim_decode_qp(cur_val->s); break;
	  case 't':					/* Timestamp */
	    sig->created = strtoul(CS cur_val->s, NULL, 10); break;
	  case 'x':					/* Expiration */
	    sig->expires = strtoul(CS cur_val->s, NULL, 10); break;
	  case 'l':					/* Body length count */
	    sig->bodylength = strtol(CS cur_val->s, NULL, 10); break;
	  case 'h':					/* signed header fields */
	    sig->headernames = string_copyn(cur_val->s, cur_val->ptr); break;
	  case 'z':					/* Copied headfields */
	    sig->copiedheaders = pdkim_decode_qp(cur_val->s); break;
/*XXX draft-ietf-dcrup-dkim-crypto-05 would need 'p' tag support
for rsafp signatures.  But later discussion is dropping those. */
	  default:
	    DEBUG(D_acl) debug_printf(" Unknown tag encountered\n");
	    break;
	  }
	}
      cur_tag = cur_val = NULL;
      in_b_val = FALSE;
      where = PDKIM_HDR_LIMBO;
      }
    else
      cur_val = string_catn(cur_val, p, 1);
    }

NEXT_CHAR:
  if (c == '\0')
    break;

  if (!in_b_val)
    *q++ = c;
  }

if (sig->keytype < 0 || sig->hashtype < 0)	/* Cannot verify this signature */
  return NULL;

*q = '\0';
/* Chomp raw header. The final newline must not be added to the signature. */
while (--q > sig->rawsig_no_b_val  && (*q == '\r' || *q == '\n'))
  *q = '\0';

DEBUG(D_acl)
  {
  debug_printf(
	  "PDKIM >> Raw signature w/o b= tag value >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
  pdkim_quoteprint(US sig->rawsig_no_b_val, Ustrlen(sig->rawsig_no_b_val));
  debug_printf(
	  "PDKIM >> Sig size: %4u bits\n", (unsigned) sig->sighash.len*8);
  debug_printf(
	  "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
  }

if (!pdkim_set_sig_bodyhash(ctx, sig))
  return NULL;

return sig;
}


/* -------------------------------------------------------------------------- */

pdkim_pubkey *
pdkim_parse_pubkey_record(const uschar *raw_record)
{
const uschar * ele;
int sep = ';';
pdkim_pubkey * pub;

pub = store_get(sizeof(pdkim_pubkey));
memset(pub, 0, sizeof(pdkim_pubkey));

while ((ele = string_nextinlist(&raw_record, &sep, NULL, 0)))
  {
  const uschar * val;

  if ((val = Ustrchr(ele, '=')))
    {
    int taglen = val++ - ele;

    DEBUG(D_acl) debug_printf(" %.*s=%s\n", taglen, ele, val);
    switch (ele[0])
      {
      case 'v': pub->version = val;			break;
      case 'h': pub->hashes = val;			break;
      case 'k': pub->keytype = val;			break;
      case 'g': pub->granularity = val;			break;
      case 'n': pub->notes = pdkim_decode_qp(val);	break;
      case 'p': pdkim_decode_base64(val, &pub->key);	break;
      case 's': pub->srvtype = val;			break;
      case 't': if (Ustrchr(val, 'y')) pub->testing = 1;
		if (Ustrchr(val, 's')) pub->no_subdomaining = 1;
		break;
      default:  DEBUG(D_acl) debug_printf(" Unknown tag encountered\n"); break;
      }
    }
  }

/* Set fallback defaults */
if (!pub->version)
  pub->version = string_copy(PDKIM_PUB_RECORD_VERSION);
else if (Ustrcmp(pub->version, PDKIM_PUB_RECORD_VERSION) != 0)
  {
  DEBUG(D_acl) debug_printf(" Bad v= field\n");
  return NULL;
  }

if (!pub->granularity) pub->granularity = US"*";
if (!pub->keytype    ) pub->keytype     = US"rsa";
if (!pub->srvtype    ) pub->srvtype     = US"*";

/* p= is required */
if (pub->key.data)
  return pub;

DEBUG(D_acl) debug_printf(" Missing p= field\n");
return NULL;
}


/* -------------------------------------------------------------------------- */

/* Update one bodyhash with some additional data.
If we have to relax the data for this sig, return our copy of it. */

static blob *
pdkim_update_ctx_bodyhash(pdkim_bodyhash * b, blob * orig_data, blob * relaxed_data)
{
blob * canon_data = orig_data;
/* Defaults to simple canon (no further treatment necessary) */

if (b->canon_method == PDKIM_CANON_RELAXED)
  {
  /* Relax the line if not done already */
  if (!relaxed_data)
    {
    BOOL seen_wsp = FALSE;
    const uschar * p, * r;
    int q = 0;

    /* We want to be able to free this else we allocate
    for the entire message which could be many MB. Since
    we don't know what allocations the SHA routines might
    do, not safe to use store_get()/store_reset(). */

    relaxed_data = store_malloc(sizeof(blob) + orig_data->len+1);
    relaxed_data->data = US (relaxed_data+1);

    for (p = orig_data->data, r = p + orig_data->len; p < r; p++)
      {
      char c = *p;
      if (c == '\r')
	{
	if (q > 0 && relaxed_data->data[q-1] == ' ')
	  q--;
	}
      else if (c == '\t' || c == ' ')
	{
	c = ' '; /* Turns WSP into SP */
	if (seen_wsp)
	  continue;
	seen_wsp = TRUE;
	}
      else
	seen_wsp = FALSE;
      relaxed_data->data[q++] = c;
      }
    relaxed_data->data[q] = '\0';
    relaxed_data->len = q;
    }
  canon_data = relaxed_data;
  }

/* Make sure we don't exceed the to-be-signed body length */
if (  b->bodylength >= 0
   && b->signed_body_bytes + (unsigned long)canon_data->len > b->bodylength
   )
  canon_data->len = b->bodylength - b->signed_body_bytes;

if (canon_data->len > 0)
  {
  exim_sha_update(&b->body_hash_ctx, CUS canon_data->data, canon_data->len);
  b->signed_body_bytes += canon_data->len;
  DEBUG(D_acl) pdkim_quoteprint(canon_data->data, canon_data->len);
  }

return relaxed_data;
}


/* -------------------------------------------------------------------------- */

static void
pdkim_finish_bodyhash(pdkim_ctx * ctx)
{
pdkim_bodyhash * b;
pdkim_signature * sig;

for (b = ctx->bodyhash; b; b = b->next)		/* Finish hashes */
  {
  DEBUG(D_acl) debug_printf("PDKIM: finish bodyhash %d/%d/%ld len %ld\n",
	    b->hashtype, b->canon_method, b->bodylength, b->signed_body_bytes);
  exim_sha_finish(&b->body_hash_ctx, &b->bh);
  }

/* Traverse all signatures */
for (sig = ctx->sig; sig; sig = sig->next)
  {
  b = sig->calc_body_hash;

  DEBUG(D_acl)
    {
    debug_printf("PDKIM [%s] Body bytes (%s) hashed: %lu\n"
		 "PDKIM [%s] Body %s computed: ",
	sig->domain, pdkim_canons[b->canon_method], b->signed_body_bytes,
	sig->domain, pdkim_hashes[b->hashtype].dkim_hashname);
    pdkim_hexprint(CUS b->bh.data, b->bh.len);
    }

  /* SIGNING -------------------------------------------------------------- */
  if (ctx->flags & PDKIM_MODE_SIGN)
    {
    /* If bodylength limit is set, and we have received less bytes
       than the requested amount, effectively remove the limit tag. */
    if (b->signed_body_bytes < sig->bodylength)
      sig->bodylength = -1;
    }

  else
  /* VERIFICATION --------------------------------------------------------- */
  /* Be careful that the header sig included a bodyash */

    if (  sig->bodyhash.data
       && memcmp(b->bh.data, sig->bodyhash.data, b->bh.len) == 0)
      {
      DEBUG(D_acl) debug_printf("PDKIM [%s] Body hash compared OK\n", sig->domain);
      }
    else
      {
      DEBUG(D_acl)
        {
	debug_printf("PDKIM [%s] Body hash signature from headers: ", sig->domain);
	pdkim_hexprint(sig->bodyhash.data, sig->bodyhash.len);
	debug_printf("PDKIM [%s] Body hash did NOT verify\n", sig->domain);
	}
      sig->verify_status     = PDKIM_VERIFY_FAIL;
      sig->verify_ext_status = PDKIM_VERIFY_FAIL_BODY;
      }
  }
}



static void
pdkim_body_complete(pdkim_ctx * ctx)
{
pdkim_bodyhash * b;

/* In simple body mode, if any empty lines were buffered,
replace with one. rfc 4871 3.4.3 */
/*XXX checking the signed-body-bytes is a gross hack; I think
it indicates that all linebreaks should be buffered, including
the one terminating a text line */

for (b = ctx->bodyhash; b; b = b->next)
  if (  b->canon_method == PDKIM_CANON_SIMPLE
     && b->signed_body_bytes == 0
     && b->num_buffered_blanklines > 0
     )
    (void) pdkim_update_ctx_bodyhash(b, &lineending, NULL);

ctx->flags |= PDKIM_SEEN_EOD;
ctx->linebuf_offset = 0;
}



/* -------------------------------------------------------------------------- */
/* Call from pdkim_feed below for processing complete body lines */
/* NOTE: the line is not NUL-terminated; but we have a count */

static void
pdkim_bodyline_complete(pdkim_ctx * ctx)
{
blob line = {.data = ctx->linebuf, .len = ctx->linebuf_offset};
pdkim_bodyhash * b;
blob * rnl = NULL;
blob * rline = NULL;

/* Ignore extra data if we've seen the end-of-data marker */
if (ctx->flags & PDKIM_SEEN_EOD) goto all_skip;

/* We've always got one extra byte to stuff a zero ... */
ctx->linebuf[line.len] = '\0';

/* Terminate on EOD marker */
if (ctx->flags & PDKIM_DOT_TERM)
  {
  if (memcmp(line.data, ".\r\n", 3) == 0)
    { pdkim_body_complete(ctx); return; }

  /* Unstuff dots */
  if (memcmp(line.data, "..", 2) == 0)
    { line.data++; line.len--; }
  }

/* Empty lines need to be buffered until we find a non-empty line */
if (memcmp(line.data, "\r\n", 2) == 0)
  {
  for (b = ctx->bodyhash; b; b = b->next) b->num_buffered_blanklines++;
  goto all_skip;
  }

/* Process line for each bodyhash separately */
for (b = ctx->bodyhash; b; b = b->next)
  {
  if (b->canon_method == PDKIM_CANON_RELAXED)
    {
    /* Lines with just spaces need to be buffered too */
    uschar * cp = line.data;
    char c;

    while ((c = *cp))
      {
      if (c == '\r' && cp[1] == '\n') break;
      if (c != ' ' && c != '\t') goto hash_process;
      cp++;
      }

    b->num_buffered_blanklines++;
    goto hash_skip;
    }

hash_process:
  /* At this point, we have a non-empty line, so release the buffered ones. */

  while (b->num_buffered_blanklines)
    {
    rnl = pdkim_update_ctx_bodyhash(b, &lineending, rnl);
    b->num_buffered_blanklines--;
    }

  rline = pdkim_update_ctx_bodyhash(b, &line, rline);
hash_skip: ;
  }

if (rnl) store_free(rnl);
if (rline) store_free(rline);

all_skip:

ctx->linebuf_offset = 0;
return;
}


/* -------------------------------------------------------------------------- */
/* Callback from pdkim_feed below for processing complete headers */
#define DKIM_SIGNATURE_HEADERNAME "DKIM-Signature:"

static int
pdkim_header_complete(pdkim_ctx * ctx)
{
pdkim_signature * sig, * last_sig;

/* Special case: The last header can have an extra \r appended */
if ( (ctx->cur_header->ptr > 1) &&
     (ctx->cur_header->s[ctx->cur_header->ptr-1] == '\r') )
  --ctx->cur_header->ptr;
(void) string_from_gstring(ctx->cur_header);

#ifdef EXPERIMENTAL_ARC
/* Feed the header line to ARC processing */
(void) arc_header_feed(ctx->cur_header, !(ctx->flags & PDKIM_MODE_SIGN));
#endif

if (++ctx->num_headers > PDKIM_MAX_HEADERS) goto BAIL;

/* SIGNING -------------------------------------------------------------- */
if (ctx->flags & PDKIM_MODE_SIGN)
  for (sig = ctx->sig; sig; sig = sig->next)			/* Traverse all signatures */

    /* Add header to the signed headers list (in reverse order) */
    sig->headers = pdkim_prepend_stringlist(sig->headers, ctx->cur_header->s);

/* VERIFICATION ----------------------------------------------------------- */
/* DKIM-Signature: headers are added to the verification list */
else
  {
#ifdef notdef
  DEBUG(D_acl)
    {
    debug_printf("PDKIM >> raw hdr: ");
    pdkim_quoteprint(CUS ctx->cur_header->s, ctx->cur_header->ptr);
    }
#endif
  if (strncasecmp(CCS ctx->cur_header->s,
		  DKIM_SIGNATURE_HEADERNAME,
		  Ustrlen(DKIM_SIGNATURE_HEADERNAME)) == 0)
    {
    /* Create and chain new signature block.  We could error-check for all
    required tags here, but prefer to create the internal sig and expicitly
    fail verification of it later. */

    DEBUG(D_acl) debug_printf(
	"PDKIM >> Found sig, trying to parse >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");

    sig = pdkim_parse_sig_header(ctx, ctx->cur_header->s);

    if (!(last_sig = ctx->sig))
      ctx->sig = sig;
    else
      {
      while (last_sig->next) last_sig = last_sig->next;
      last_sig->next = sig;
      }

    if (--dkim_collect_input == 0)
      {
      ctx->headers = pdkim_prepend_stringlist(ctx->headers, ctx->cur_header->s);
      ctx->cur_header->s[ctx->cur_header->ptr = 0] = '\0';
      return PDKIM_ERR_EXCESS_SIGS;
      }
    }

  /* all headers are stored for signature verification */
  ctx->headers = pdkim_prepend_stringlist(ctx->headers, ctx->cur_header->s);
  }

BAIL:
ctx->cur_header->s[ctx->cur_header->ptr = 0] = '\0';	/* leave buffer for reuse */
return PDKIM_OK;
}



/* -------------------------------------------------------------------------- */
#define HEADER_BUFFER_FRAG_SIZE 256

DLLEXPORT int
pdkim_feed(pdkim_ctx * ctx, uschar * data, int len)
{
int p, rc;

/* Alternate EOD signal, used in non-dotstuffing mode */
if (!data)
  pdkim_body_complete(ctx);

else for (p = 0; p < len; p++)
  {
  uschar c = data[p];

  if (ctx->flags & PDKIM_PAST_HDRS)
    {
    if (c == '\n' && !(ctx->flags & PDKIM_SEEN_CR))	/* emulate the CR */
      {
      ctx->linebuf[ctx->linebuf_offset++] = '\r';
      if (ctx->linebuf_offset == PDKIM_MAX_BODY_LINE_LEN-1)
	return PDKIM_ERR_LONG_LINE;
      }

    /* Processing body byte */
    ctx->linebuf[ctx->linebuf_offset++] = c;
    if (c == '\r')
      ctx->flags |= PDKIM_SEEN_CR;
    else if (c == '\n')
      {
      ctx->flags &= ~PDKIM_SEEN_CR;
      pdkim_bodyline_complete(ctx);
      }

    if (ctx->linebuf_offset == PDKIM_MAX_BODY_LINE_LEN-1)
      return PDKIM_ERR_LONG_LINE;
    }
  else
    {
    /* Processing header byte */
    if (c == '\r')
      ctx->flags |= PDKIM_SEEN_CR;
    else if (c == '\n')
      {
      if (!(ctx->flags & PDKIM_SEEN_CR))		/* emulate the CR */
	ctx->cur_header = string_catn(ctx->cur_header, CUS "\r", 1);

      if (ctx->flags & PDKIM_SEEN_LF)		/* Seen last header line */
	{
	if ((rc = pdkim_header_complete(ctx)) != PDKIM_OK)
	  return rc;

	ctx->flags = (ctx->flags & ~(PDKIM_SEEN_LF|PDKIM_SEEN_CR)) | PDKIM_PAST_HDRS;
	DEBUG(D_acl) debug_printf(
	    "PDKIM >> Body data for hash, canonicalized >>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
	continue;
	}
      else
	ctx->flags = (ctx->flags & ~PDKIM_SEEN_CR) | PDKIM_SEEN_LF;
      }
    else if (ctx->flags & PDKIM_SEEN_LF)
      {
      if (!(c == '\t' || c == ' '))			/* End of header */
	if ((rc = pdkim_header_complete(ctx)) != PDKIM_OK)
	  return rc;
      ctx->flags &= ~PDKIM_SEEN_LF;
      }

    if (!ctx->cur_header || ctx->cur_header->ptr < PDKIM_MAX_HEADER_LEN)
      ctx->cur_header = string_catn(ctx->cur_header, CUS &data[p], 1);
    }
  }
return PDKIM_OK;
}



/* Extend a growing header with a continuation-linebreak */
static gstring *
pdkim_hdr_cont(gstring * str, int * col)
{
*col = 1;
return string_catn(str, US"\r\n\t", 3);
}



/*
 * RFC 5322 specifies that header line length SHOULD be no more than 78
 * lets make it so!
 *  pdkim_headcat
 *
 * returns uschar * (not nul-terminated)
 *
 * col: this int holds and receives column number (octets since last '\n')
 * str: partial string to append to
 * pad: padding, split line or space after before or after eg: ";"
 * intro: - must join to payload eg "h=", usually the tag name
 * payload: eg base64 data - long data can be split arbitrarily.
 *
 * this code doesn't fold the header in some of the places that RFC4871
 * allows: As per RFC5322(2.2.3) it only folds before or after tag-value
 * pairs and inside long values. it also always spaces or breaks after the
 * "pad"
 *
 * no guarantees are made for output given out-of range input. like tag
 * names longer than 78, or bogus col. Input is assumed to be free of line breaks.
 */

static gstring *
pdkim_headcat(int * col, gstring * str,
  const uschar * pad, const uschar * intro, const uschar * payload)
{
size_t l;

if (pad)
  {
  l = Ustrlen(pad);
  if (*col + l > 78)
    str = pdkim_hdr_cont(str, col);
  str = string_catn(str, pad, l);
  *col += l;
  }

l = (pad?1:0) + (intro?Ustrlen(intro):0);

if (*col + l > 78)
  { /*can't fit intro - start a new line to make room.*/
  str = pdkim_hdr_cont(str, col);
  l = intro?Ustrlen(intro):0;
  }

l += payload ? Ustrlen(payload):0 ;

while (l>77)
  { /* this fragment will not fit on a single line */
  if (pad)
    {
    str = string_catn(str, US" ", 1);
    *col += 1;
    pad = NULL; /* only want this once */
    l--;
    }

  if (intro)
    {
    size_t sl = Ustrlen(intro);

    str = string_catn(str, intro, sl);
    *col += sl;
    l -= sl;
    intro = NULL; /* only want this once */
    }

  if (payload)
    {
    size_t sl = Ustrlen(payload);
    size_t chomp = *col+sl < 77 ? sl : 78-*col;

    str = string_catn(str, payload, chomp);
    *col += chomp;
    payload += chomp;
    l -= chomp-1;
    }

  /* the while precondition tells us it didn't fit. */
  str = pdkim_hdr_cont(str, col);
  }

if (*col + l > 78)
  {
  str = pdkim_hdr_cont(str, col);
  pad = NULL;
  }

if (pad)
  {
  str = string_catn(str, US" ", 1);
  *col += 1;
  pad = NULL;
  }

if (intro)
  {
  size_t sl = Ustrlen(intro);

  str = string_catn(str, intro, sl);
  *col += sl;
  l -= sl;
  intro = NULL;
  }

if (payload)
  {
  size_t sl = Ustrlen(payload);

  str = string_catn(str, payload, sl);
  *col += sl;
  }

return str;
}


/* -------------------------------------------------------------------------- */

/* Signing: create signature header
*/
static uschar *
pdkim_create_header(pdkim_signature * sig, BOOL final)
{
uschar * base64_bh;
uschar * base64_b;
int col = 0;
gstring * hdr;
gstring * canon_all;

canon_all = string_cat (NULL, pdkim_canons[sig->canon_headers]);
canon_all = string_catn(canon_all, US"/", 1);
canon_all = string_cat (canon_all, pdkim_canons[sig->canon_body]);
(void) string_from_gstring(canon_all);

hdr = string_cat(NULL, US"DKIM-Signature: v="PDKIM_SIGNATURE_VERSION);
col = hdr->ptr;

/* Required and static bits */
hdr = pdkim_headcat(&col, hdr, US";", US"a=", dkim_sig_to_a_tag(sig));
hdr = pdkim_headcat(&col, hdr, US";", US"q=", pdkim_querymethods[sig->querymethod]);
hdr = pdkim_headcat(&col, hdr, US";", US"c=", canon_all->s);
hdr = pdkim_headcat(&col, hdr, US";", US"d=", sig->domain);
hdr = pdkim_headcat(&col, hdr, US";", US"s=", sig->selector);

/* list of header names can be split between items. */
  {
  uschar * n = string_copy(sig->headernames);
  uschar * i = US"h=";
  uschar * s = US";";

  while (*n)
    {
    uschar * c = Ustrchr(n, ':');

    if (c) *c ='\0';

    if (!i)
      hdr = pdkim_headcat(&col, hdr, NULL, NULL, US":");

    hdr = pdkim_headcat(&col, hdr, s, i, n);

    if (!c)
      break;

    n = c+1;
    s = NULL;
    i = NULL;
    }
  }

base64_bh = pdkim_encode_base64(&sig->calc_body_hash->bh);
hdr = pdkim_headcat(&col, hdr, US";", US"bh=", base64_bh);

/* Optional bits */
if (sig->identity)
  hdr = pdkim_headcat(&col, hdr, US";", US"i=", sig->identity);

if (sig->created > 0)
  {
  uschar minibuf[20];

  snprintf(CS minibuf, sizeof(minibuf), "%lu", sig->created);
  hdr = pdkim_headcat(&col, hdr, US";", US"t=", minibuf);
}

if (sig->expires > 0)
  {
  uschar minibuf[20];

  snprintf(CS minibuf, sizeof(minibuf), "%lu", sig->expires);
  hdr = pdkim_headcat(&col, hdr, US";", US"x=", minibuf);
  }

if (sig->bodylength >= 0)
  {
  uschar minibuf[20];

  snprintf(CS minibuf, sizeof(minibuf), "%lu", sig->bodylength);
  hdr = pdkim_headcat(&col, hdr, US";", US"l=", minibuf);
  }

/* Preliminary or final version? */
if (final)
  {
  base64_b = pdkim_encode_base64(&sig->sighash);
  hdr = pdkim_headcat(&col, hdr, US";", US"b=", base64_b);

  /* add trailing semicolon: I'm not sure if this is actually needed */
  hdr = pdkim_headcat(&col, hdr, NULL, US";", US"");
  }
else
  {
  /* To satisfy the rule "all surrounding whitespace [...] deleted"
  ( RFC 6376 section 3.7 ) we ensure there is no whitespace here.  Otherwise
  the headcat routine could insert a linebreak which the relaxer would reduce
  to a single space preceding the terminating semicolon, resulting in an
  incorrect header-hash. */
  hdr = pdkim_headcat(&col, hdr, US";", US"b=;", US"");
  }

return string_from_gstring(hdr);
}


/* -------------------------------------------------------------------------- */

/* According to draft-ietf-dcrup-dkim-crypto-07 "keys are 256 bits" (referring
to DNS, hence the pubkey).  Check for more than 32 bytes; if so assume the
alternate possible representation (still) being discussed: a
SubjectPublickeyInfo wrapped key - and drop all but the trailing 32-bytes (it
should be a DER, with exactly 12 leading bytes - but we could accept a BER also,
which could be any size).  We still rely on the crypto library for checking for
undersize.

When the RFC is published this should be re-addressed. */

static void
check_bare_ed25519_pubkey(pdkim_pubkey * p)
{
int excess = p->key.len - 32;
if (excess > 0)
  {
  DEBUG(D_acl) debug_printf("PDKIM: unexpected pubkey len %lu\n", p->key.len);
  p->key.data += excess; p->key.len = 32;
  }
}


static pdkim_pubkey *
pdkim_key_from_dns(pdkim_ctx * ctx, pdkim_signature * sig, ev_ctx * vctx,
  const uschar ** errstr)
{
uschar * dns_txt_name, * dns_txt_reply;
pdkim_pubkey * p;

/* Fetch public key for signing domain, from DNS */

dns_txt_name = string_sprintf("%s._domainkey.%s.", sig->selector, sig->domain);

if (  !(dns_txt_reply = ctx->dns_txt_callback(dns_txt_name))
   || dns_txt_reply[0] == '\0'
   )
  {
  sig->verify_status =      PDKIM_VERIFY_INVALID;
  sig->verify_ext_status =  PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE;
  return NULL;
  }

DEBUG(D_acl)
  {
  debug_printf(
    "PDKIM >> Parsing public key record >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"
    " %s\n"
    " Raw record: ",
    dns_txt_name);
  pdkim_quoteprint(CUS dns_txt_reply, Ustrlen(dns_txt_reply));
  }

if (  !(p = pdkim_parse_pubkey_record(CUS dns_txt_reply))
   || (Ustrcmp(p->srvtype, "*") != 0 && Ustrcmp(p->srvtype, "email") != 0)
   )
  {
  sig->verify_status =      PDKIM_VERIFY_INVALID;
  sig->verify_ext_status =  PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD;

  DEBUG(D_acl)
    {
    if (p)
      debug_printf(" Invalid public key service type '%s'\n", p->srvtype);
    else
      debug_printf(" Error while parsing public key record\n");
    debug_printf(
      "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    }
  return NULL;
  }

DEBUG(D_acl) debug_printf(
      "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

/* Import public key */

/* Normally we use the signature a= tag to tell us the pubkey format.
When signing under debug we do a test-import of the pubkey, and at that
time we do not have a signature so we must interpret the pubkey k= tag
instead.  Assume writing on the sig is ok in that case. */

if (sig->keytype < 0)
  {
  int i;
  for(i = 0; i < nelem(pdkim_keytypes); i++)
    if (Ustrcmp(p->keytype, pdkim_keytypes[i]) == 0)
      { sig->keytype = i; goto k_ok; }
  DEBUG(D_acl) debug_printf("verify_init: unhandled keytype %s\n", p->keytype);
  sig->verify_status =      PDKIM_VERIFY_INVALID;
  sig->verify_ext_status =  PDKIM_VERIFY_INVALID_PUBKEY_IMPORT;
  return NULL;
  }
k_ok:

if (sig->keytype == KEYTYPE_ED25519)
  check_bare_ed25519_pubkey(p);

if ((*errstr = exim_dkim_verify_init(&p->key,
	    sig->keytype == KEYTYPE_ED25519 ? KEYFMT_ED25519_BARE : KEYFMT_DER,
	    vctx)))
  {
  DEBUG(D_acl) debug_printf("verify_init: %s\n", *errstr);
  sig->verify_status =      PDKIM_VERIFY_INVALID;
  sig->verify_ext_status =  PDKIM_VERIFY_INVALID_PUBKEY_IMPORT;
  return NULL;
  }

vctx->keytype = sig->keytype;
return p;
}


/* -------------------------------------------------------------------------- */

DLLEXPORT int
pdkim_feed_finish(pdkim_ctx * ctx, pdkim_signature ** return_signatures,
  const uschar ** err)
{
pdkim_bodyhash * b;
pdkim_signature * sig;
BOOL verify_pass = FALSE;

/* Check if we must still flush a (partial) header. If that is the
   case, the message has no body, and we must compute a body hash
   out of '<CR><LF>' */
if (ctx->cur_header && ctx->cur_header->ptr > 0)
  {
  blob * rnl = NULL;
  int rc;

  if ((rc = pdkim_header_complete(ctx)) != PDKIM_OK)
    return rc;

  for (b = ctx->bodyhash; b; b = b->next)
    rnl = pdkim_update_ctx_bodyhash(b, &lineending, rnl);
  if (rnl) store_free(rnl);
  }
else
  DEBUG(D_acl) debug_printf(
      "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

/* Build (and/or evaluate) body hash.  Do this even if no DKIM sigs, in case we
have a hash to do for ARC. */

pdkim_finish_bodyhash(ctx);

if (!ctx->sig)
  {
  DEBUG(D_acl) debug_printf("PDKIM: no signatures\n");
  *return_signatures = NULL;
  return PDKIM_OK;
  }

for (sig = ctx->sig; sig; sig = sig->next)
  {
  hctx hhash_ctx;
  uschar * sig_hdr = US"";
  blob hhash;
  gstring * hdata = NULL;
  es_ctx sctx;

  if (  !(ctx->flags & PDKIM_MODE_SIGN)
     && sig->verify_status == PDKIM_VERIFY_FAIL)
    {
    DEBUG(D_acl)
       debug_printf("PDKIM: [%s] abandoning this signature\n", sig->domain);
    continue;
    }

  /*XXX The hash of the headers is needed for GCrypt (for which we can do RSA
  suging only, as it happens) and for either GnuTLS and OpenSSL when we are
  signing with EC (specifically, Ed25519).  The former is because the GCrypt
  signing operation is pure (does not do its own hash) so we must hash.  The
  latter is because we (stupidly, but this is what the IETF draft is saying)
  must hash with the declared hash method, then pass the result to the library
  hash-and-sign routine (because that's all the libraries are providing.  And
  we're stuck with whatever that hidden hash method is, too).  We may as well
  do this hash incrementally.
  We don't need the hash we're calculating here for the GnuTLS and OpenSSL
  cases of RSA signing, since those library routines can do hash-and-sign.
 
  Some time in the future we could easily avoid doing the hash here for those
  cases (which will be common for a long while.  We could also change from
  the current copy-all-the-headers-into-one-block, then call the hash-and-sign
  implementation  - to a proper incremental one.  Unfortunately, GnuTLS just
  cannot do incremental - either signing or verification.  Unsure about GCrypt.
  */

  /*XXX The header hash is also used (so far) by the verify operation */

  if (!exim_sha_init(&hhash_ctx, pdkim_hashes[sig->hashtype].exim_hashmethod))
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
      "PDKIM: hash setup error, possibly nonhandled hashtype");
    break;
    }

  if (ctx->flags & PDKIM_MODE_SIGN)
    DEBUG(D_acl) debug_printf(
	"PDKIM >> Headers to be signed:                            >>>>>>>>>>>>\n"
	" %s\n",
	sig->sign_headers);

  DEBUG(D_acl) debug_printf(
      "PDKIM >> Header data for hash, canonicalized (%-7s), in sequence >>\n",
	pdkim_canons[sig->canon_headers]);


  /* SIGNING ---------------------------------------------------------------- */
  /* When signing, walk through our header list and add them to the hash. As we
     go, construct a list of the header's names to use for the h= parameter.
     Then append to that list any remaining header names for which there was no
     header to sign. */

  if (ctx->flags & PDKIM_MODE_SIGN)
    {
    gstring * g = NULL;
    pdkim_stringlist *p;
    const uschar * l;
    uschar * s;
    int sep = 0;

    /* Import private key, including the keytype which we need for building
    the signature header  */

/*XXX extend for non-RSA algos */
    if ((*err = exim_dkim_signing_init(CUS sig->privkey, &sctx)))
      {
      log_write(0, LOG_MAIN|LOG_PANIC, "signing_init: %s", *err);
      return PDKIM_ERR_RSA_PRIVKEY;
      }
    sig->keytype = sctx.keytype;

    for (sig->headernames = NULL,		/* Collected signed header names */
	  p = sig->headers; p; p = p->next)
      {
      uschar * rh = p->value;

      if (header_name_match(rh, sig->sign_headers) == PDKIM_OK)
	{
	/* Collect header names (Note: colon presence is guaranteed here) */
	g = string_append_listele_n(g, ':', rh, Ustrchr(rh, ':') - rh);

	if (sig->canon_headers == PDKIM_CANON_RELAXED)
	  rh = pdkim_relax_header(rh, TRUE);	/* cook header for relaxed canon */

	/* Feed header to the hash algorithm */
	exim_sha_update(&hhash_ctx, CUS rh, Ustrlen(rh));

	/* Remember headers block for signing (when the library cannot do incremental)  */
	/*XXX we could avoid doing this for all but the GnuTLS/RSA case */
	hdata = exim_dkim_data_append(hdata, rh);

	DEBUG(D_acl) pdkim_quoteprint(rh, Ustrlen(rh));
	}
      }

    /* Any headers we wanted to sign but were not present must also be listed.
    Ignore elements that have been ticked-off or are marked as never-oversign. */

    l = sig->sign_headers;
    while((s = string_nextinlist(&l, &sep, NULL, 0)))
      {
      if (*s == '+')			/* skip oversigning marker */
        s++;
      if (*s != '_' && *s != '=')
	g = string_append_listele(g, ':', s);
      }
    sig->headernames = string_from_gstring(g);

    /* Create signature header with b= omitted */
    sig_hdr = pdkim_create_header(sig, FALSE);
    }

  /* VERIFICATION ----------------------------------------------------------- */
  /* When verifying, walk through the header name list in the h= parameter and
     add the headers to the hash in that order. */
  else
    {
    uschar * p = sig->headernames;
    uschar * q;
    pdkim_stringlist * hdrs;

    if (p)
      {
      /* clear tags */
      for (hdrs = ctx->headers; hdrs; hdrs = hdrs->next)
	hdrs->tag = 0;

      p = string_copy(p);
      while(1)
	{
	if ((q = Ustrchr(p, ':')))
	  *q = '\0';

  /*XXX walk the list of headers in same order as received. */
	for (hdrs = ctx->headers; hdrs; hdrs = hdrs->next)
	  if (  hdrs->tag == 0
	     && strncasecmp(CCS hdrs->value, CCS p, Ustrlen(p)) == 0
	     && (hdrs->value)[Ustrlen(p)] == ':'
	     )
	    {
	    /* cook header for relaxed canon, or just copy it for simple  */

	    uschar * rh = sig->canon_headers == PDKIM_CANON_RELAXED
	      ? pdkim_relax_header(hdrs->value, TRUE)
	      : string_copy(CUS hdrs->value);

	    /* Feed header to the hash algorithm */
	    exim_sha_update(&hhash_ctx, CUS rh, Ustrlen(rh));

	    DEBUG(D_acl) pdkim_quoteprint(rh, Ustrlen(rh));
	    hdrs->tag = 1;
	    break;
	    }

	if (!q) break;
	p = q+1;
	}

      sig_hdr = string_copy(sig->rawsig_no_b_val);
      }
    }

  DEBUG(D_acl) debug_printf(
	    "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

  DEBUG(D_acl)
    {
    debug_printf(
	    "PDKIM >> Signed DKIM-Signature header, pre-canonicalized >>>>>>>>>>>>>\n");
    pdkim_quoteprint(CUS sig_hdr, Ustrlen(sig_hdr));
    debug_printf(
	    "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    }

  /* Relax header if necessary */
  if (sig->canon_headers == PDKIM_CANON_RELAXED)
    sig_hdr = pdkim_relax_header(sig_hdr, FALSE);

  DEBUG(D_acl)
    {
    debug_printf("PDKIM >> Signed DKIM-Signature header, canonicalized (%-7s) >>>>>>>\n",
	    pdkim_canons[sig->canon_headers]);
    pdkim_quoteprint(CUS sig_hdr, Ustrlen(sig_hdr));
    debug_printf(
	    "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    }

  /* Finalize header hash */
  exim_sha_update(&hhash_ctx, CUS sig_hdr, Ustrlen(sig_hdr));
  exim_sha_finish(&hhash_ctx, &hhash);

  DEBUG(D_acl)
    {
    debug_printf("PDKIM [%s] Header %s computed: ",
      sig->domain, pdkim_hashes[sig->hashtype].dkim_hashname);
    pdkim_hexprint(hhash.data, hhash.len);
    }

  /* Remember headers block for signing (when the signing library cannot do
  incremental)  */
  if (ctx->flags & PDKIM_MODE_SIGN)
    hdata = exim_dkim_data_append(hdata, US sig_hdr);

  /* SIGNING ---------------------------------------------------------------- */
  if (ctx->flags & PDKIM_MODE_SIGN)
    {
    hashmethod hm = sig->keytype == KEYTYPE_ED25519
#if defined(SIGN_OPENSSL)
      ? HASH_NULL
#else
      ? HASH_SHA2_512
#endif
      : pdkim_hashes[sig->hashtype].exim_hashmethod;

#ifdef SIGN_HAVE_ED25519
    /* For GCrypt, and for EC, we pass the hash-of-headers to the signing
    routine.  For anything else we just pass the headers. */

    if (sig->keytype != KEYTYPE_ED25519)
#endif
      {
      hhash.data = hdata->s;
      hhash.len = hdata->ptr;
      }

    if ((*err = exim_dkim_sign(&sctx, hm, &hhash, &sig->sighash)))
      {
      log_write(0, LOG_MAIN|LOG_PANIC, "signing: %s", *err);
      return PDKIM_ERR_RSA_SIGNING;
      }

    DEBUG(D_acl)
      {
      debug_printf( "PDKIM [%s] b computed: ", sig->domain);
      pdkim_hexprint(sig->sighash.data, sig->sighash.len);
      }

    sig->signature_header = pdkim_create_header(sig, TRUE);
    }

  /* VERIFICATION ----------------------------------------------------------- */
  else
    {
    ev_ctx vctx;
    hashmethod hm;

    /* Make sure we have all required signature tags */
    if (!(  sig->domain        && *sig->domain
	 && sig->selector      && *sig->selector
	 && sig->headernames   && *sig->headernames
	 && sig->bodyhash.data
	 && sig->sighash.data
	 && sig->keytype >= 0
	 && sig->hashtype >= 0
	 && sig->version
       ) )
      {
      sig->verify_status     = PDKIM_VERIFY_INVALID;
      sig->verify_ext_status = PDKIM_VERIFY_INVALID_SIGNATURE_ERROR;

      DEBUG(D_acl) debug_printf(
	  " Error in DKIM-Signature header: tags missing or invalid (%s)\n"
	  "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",
	  !(sig->domain && *sig->domain) ? "d="
	  : !(sig->selector && *sig->selector) ? "s="
	  : !(sig->headernames && *sig->headernames) ? "h="
	  : !sig->bodyhash.data ? "bh="
	  : !sig->sighash.data ? "b="
	  : sig->keytype < 0 || sig->hashtype < 0 ? "a="
	  : "v="
	  );
      goto NEXT_VERIFY;
      }
 
    /* Make sure sig uses supported DKIM version (only v1) */
    if (sig->version != 1)
      {
      sig->verify_status     = PDKIM_VERIFY_INVALID;
      sig->verify_ext_status = PDKIM_VERIFY_INVALID_DKIM_VERSION;

      DEBUG(D_acl) debug_printf(
          " Error in DKIM-Signature header: unsupported DKIM version\n"
          "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
      goto NEXT_VERIFY;
      }

    DEBUG(D_acl)
      {
      debug_printf( "PDKIM [%s] b from mail: ", sig->domain);
      pdkim_hexprint(sig->sighash.data, sig->sighash.len);
      }

    if (!(sig->pubkey = pdkim_key_from_dns(ctx, sig, &vctx, err)))
      {
      log_write(0, LOG_MAIN, "PDKIM: %s%s %s%s [failed key import]",
	sig->domain   ? "d=" : "", sig->domain   ? sig->domain   : US"",
	sig->selector ? "s=" : "", sig->selector ? sig->selector : US"");
      goto NEXT_VERIFY;
      }

    /* If the pubkey limits to a list of specific hashes, ignore sigs that
    do not have the hash part of the sig algorithm matching */

    if (sig->pubkey->hashes)
      {
      const uschar * list = sig->pubkey->hashes, * ele;
      int sep = ':';
      while ((ele = string_nextinlist(&list, &sep, NULL, 0)))
	if (Ustrcmp(ele, pdkim_hashes[sig->hashtype].dkim_hashname) == 0) break;
      if (!ele)
	{
	DEBUG(D_acl) debug_printf("pubkey h=%s vs. sig a=%s_%s\n",
	  sig->pubkey->hashes,
	  pdkim_keytypes[sig->keytype],
	  pdkim_hashes[sig->hashtype].dkim_hashname);
	sig->verify_status =      PDKIM_VERIFY_FAIL;
	sig->verify_ext_status =  PDKIM_VERIFY_FAIL_SIG_ALGO_MISMATCH;
	goto NEXT_VERIFY;
	}
      }

    hm = sig->keytype == KEYTYPE_ED25519
#if defined(SIGN_OPENSSL)
      ? HASH_NULL
#else
      ? HASH_SHA2_512
#endif
      : pdkim_hashes[sig->hashtype].exim_hashmethod;

    /* Check the signature */

    if ((*err = exim_dkim_verify(&vctx, hm, &hhash, &sig->sighash)))
      {
      DEBUG(D_acl) debug_printf("headers verify: %s\n", *err);
      sig->verify_status =      PDKIM_VERIFY_FAIL;
      sig->verify_ext_status =  PDKIM_VERIFY_FAIL_MESSAGE;
      goto NEXT_VERIFY;
      }


    /* We have a winner! (if bodyhash was correct earlier) */
    if (sig->verify_status == PDKIM_VERIFY_NONE)
      {
      sig->verify_status = PDKIM_VERIFY_PASS;
      verify_pass = TRUE;
      }

NEXT_VERIFY:

    DEBUG(D_acl)
      {
      debug_printf("PDKIM [%s] %s signature status: %s",
	      sig->domain, dkim_sig_to_a_tag(sig),
	      pdkim_verify_status_str(sig->verify_status));
      if (sig->verify_ext_status > 0)
	debug_printf(" (%s)\n",
		pdkim_verify_ext_status_str(sig->verify_ext_status));
      else
	debug_printf("\n");
      }
    }
  }

/* If requested, set return pointer to signature(s) */
if (return_signatures)
  *return_signatures = ctx->sig;

return ctx->flags & PDKIM_MODE_SIGN  ||  verify_pass
  ? PDKIM_OK : PDKIM_FAIL;
}


/* -------------------------------------------------------------------------- */

DLLEXPORT pdkim_ctx *
pdkim_init_verify(uschar * (*dns_txt_callback)(uschar *), BOOL dot_stuffing)
{
pdkim_ctx * ctx;

ctx = store_get(sizeof(pdkim_ctx));
memset(ctx, 0, sizeof(pdkim_ctx));

if (dot_stuffing) ctx->flags = PDKIM_DOT_TERM;
ctx->linebuf = store_get(PDKIM_MAX_BODY_LINE_LEN);
ctx->dns_txt_callback = dns_txt_callback;

return ctx;
}


/* -------------------------------------------------------------------------- */

DLLEXPORT pdkim_signature *
pdkim_init_sign(pdkim_ctx * ctx,
  uschar * domain, uschar * selector, uschar * privkey,
  uschar * hashname, const uschar ** errstr)
{
int hashtype;
pdkim_signature * sig;

if (!domain || !selector || !privkey)
  return NULL;

/* Allocate & init one signature struct */

sig = store_get(sizeof(pdkim_signature));
memset(sig, 0, sizeof(pdkim_signature));

sig->bodylength = -1;

sig->domain = string_copy(US domain);
sig->selector = string_copy(US selector);
sig->privkey = string_copy(US privkey);
sig->keytype = -1;

for (hashtype = 0; hashtype < nelem(pdkim_hashes); hashtype++)
  if (Ustrcmp(hashname, pdkim_hashes[hashtype].dkim_hashname) == 0)
  { sig->hashtype = hashtype; break; }
if (hashtype >= nelem(pdkim_hashes))
  {
  log_write(0, LOG_MAIN|LOG_PANIC,
    "PDKIM: unrecognised hashname '%s'", hashname);
  return NULL;
  }

DEBUG(D_acl)
  {
  pdkim_signature s = *sig;
  ev_ctx vctx;

  debug_printf("PDKIM (checking verify key)>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
  if (!pdkim_key_from_dns(ctx, &s, &vctx, errstr))
    debug_printf("WARNING: bad dkim key in dns\n");
  debug_printf("PDKIM (finished checking verify key)<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
  }
return sig;
}


/* -------------------------------------------------------------------------- */

DLLEXPORT void
pdkim_set_optional(pdkim_signature * sig,
                       char * sign_headers,
                       char * identity,
                       int canon_headers,
                       int canon_body,
                       long bodylength,
                       unsigned long created,
                       unsigned long expires)
{
if (identity)
  sig->identity = string_copy(US identity);

sig->sign_headers = string_copy(sign_headers
	? US sign_headers : US PDKIM_DEFAULT_SIGN_HEADERS);

sig->canon_headers = canon_headers;
sig->canon_body = canon_body;
sig->bodylength = bodylength;
sig->created = created;
sig->expires = expires;

return;
}



/* Set up a blob for calculating the bodyhash according to the
given needs.  Use an existing one if possible, or create a new one.

Return: hashblob pointer, or NULL on error
*/
pdkim_bodyhash *
pdkim_set_bodyhash(pdkim_ctx * ctx, int hashtype, int canon_method,
	long bodylength)
{
pdkim_bodyhash * b;

for (b = ctx->bodyhash; b; b = b->next)
  if (  hashtype == b->hashtype
     && canon_method == b->canon_method
     && bodylength == b->bodylength)
    {
    DEBUG(D_receive) debug_printf("PDKIM: using existing bodyhash %d/%d/%ld\n",
				  hashtype, canon_method, bodylength);
    return b;
    }

DEBUG(D_receive) debug_printf("PDKIM: new bodyhash %d/%d/%ld\n",
			      hashtype, canon_method, bodylength);
b = store_get(sizeof(pdkim_bodyhash));
b->next = ctx->bodyhash;
b->hashtype = hashtype;
b->canon_method = canon_method;
b->bodylength = bodylength;
if (!exim_sha_init(&b->body_hash_ctx,		/*XXX hash method: extend for sha512 */
		  pdkim_hashes[hashtype].exim_hashmethod))
  {
  DEBUG(D_acl)
    debug_printf("PDKIM: hash init error, possibly nonhandled hashtype\n");
  return NULL;
  }
b->signed_body_bytes = 0;
b->num_buffered_blanklines = 0;
ctx->bodyhash = b;
return b;
}


/* Set up a blob for calculating the bodyhash according to the
needs of this signature.  Use an existing one if possible, or
create a new one.

Return: hashblob pointer, or NULL on error (only used as a boolean).
*/
pdkim_bodyhash *
pdkim_set_sig_bodyhash(pdkim_ctx * ctx, pdkim_signature * sig)
{
pdkim_bodyhash * b = pdkim_set_bodyhash(ctx,
			sig->hashtype, sig->canon_body, sig->bodylength);
sig->calc_body_hash = b;
return b;
}


/* -------------------------------------------------------------------------- */


void
pdkim_init_context(pdkim_ctx * ctx, BOOL dot_stuffed,
  uschar * (*dns_txt_callback)(uschar *))
{
memset(ctx, 0, sizeof(pdkim_ctx));
ctx->flags = dot_stuffed ? PDKIM_MODE_SIGN | PDKIM_DOT_TERM : PDKIM_MODE_SIGN;
ctx->linebuf = store_get(PDKIM_MAX_BODY_LINE_LEN);
DEBUG(D_acl) ctx->dns_txt_callback = dns_txt_callback;
}


void
pdkim_init(void)
{
exim_dkim_init();
}



#endif	/*DISABLE_DKIM*/
