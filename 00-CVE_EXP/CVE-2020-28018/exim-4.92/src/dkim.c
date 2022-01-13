/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge, 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Code for DKIM support. Other DKIM relevant code is in
   receive.c, transport.c and transports/smtp.c */

#include "exim.h"

#ifndef DISABLE_DKIM

# include "pdkim/pdkim.h"

# ifdef MACRO_PREDEF
#  include "macro_predef.h"

void
params_dkim(void)
{
builtin_macro_create_var(US"_DKIM_SIGN_HEADERS", US PDKIM_DEFAULT_SIGN_HEADERS);
}
# else	/*!MACRO_PREDEF*/



pdkim_ctx dkim_sign_ctx;

int dkim_verify_oldpool;
pdkim_ctx *dkim_verify_ctx = NULL;
pdkim_signature *dkim_cur_sig = NULL;
static const uschar * dkim_collect_error = NULL;

#define DKIM_MAX_SIGNATURES 20



/*XXX the caller only uses the first record if we return multiple.
*/

uschar *
dkim_exim_query_dns_txt(uschar * name)
{
dns_answer dnsa;
dns_scan dnss;
dns_record *rr;
gstring * g = NULL;

lookup_dnssec_authenticated = NULL;
if (dns_lookup(&dnsa, name, T_TXT, NULL) != DNS_SUCCEED)
  return NULL;	/*XXX better error detail?  logging? */

/* Search for TXT record */

for (rr = dns_next_rr(&dnsa, &dnss, RESET_ANSWERS);
     rr;
     rr = dns_next_rr(&dnsa, &dnss, RESET_NEXT))
  if (rr->type == T_TXT)
    {
    int rr_offset = 0;

    /* Copy record content to the answer buffer */

    while (rr_offset < rr->size)
      {
      uschar len = rr->data[rr_offset++];

      g = string_catn(g, US(rr->data + rr_offset), len);
      if (g->ptr >= PDKIM_DNS_TXT_MAX_RECLEN)
	goto bad;

      rr_offset += len;
      }

    /* check if this looks like a DKIM record */
    if (Ustrncmp(g->s, "v=", 2) != 0 || strncasecmp(CS g->s, "v=dkim", 6) == 0)
      {
      gstring_reset_unused(g);
      return string_from_gstring(g);
      }

    if (g) g->ptr = 0;		/* overwrite previous record */
    }

bad:
if (g) store_reset(g);
return NULL;	/*XXX better error detail?  logging? */
}


void
dkim_exim_init(void)
{
pdkim_init();
}



void
dkim_exim_verify_init(BOOL dot_stuffing)
{
/* There is a store-reset between header & body reception
so cannot use the main pool. Any allocs done by Exim
memory-handling must use the perm pool. */

dkim_verify_oldpool = store_pool;
store_pool = POOL_PERM;

/* Free previous context if there is one */

if (dkim_verify_ctx)
  pdkim_free_ctx(dkim_verify_ctx);

/* Create new context */

dkim_verify_ctx = pdkim_init_verify(&dkim_exim_query_dns_txt, dot_stuffing);
dkim_collect_input = dkim_verify_ctx ? DKIM_MAX_SIGNATURES : 0;
dkim_collect_error = NULL;

/* Start feed up with any cached data */
receive_get_cache();

store_pool = dkim_verify_oldpool;
}


void
dkim_exim_verify_feed(uschar * data, int len)
{
int rc;

store_pool = POOL_PERM;
if (  dkim_collect_input
   && (rc = pdkim_feed(dkim_verify_ctx, data, len)) != PDKIM_OK)
  {
  dkim_collect_error = pdkim_errstr(rc);
  log_write(0, LOG_MAIN,
	     "DKIM: validation error: %.100s", dkim_collect_error);
  dkim_collect_input = 0;
  }
store_pool = dkim_verify_oldpool;
}


/* Log the result for the given signature */
static void
dkim_exim_verify_log_sig(pdkim_signature * sig)
{
gstring * logmsg;
uschar * s;

if (!sig) return;

/* Remember the domain for the first pass result */

if (  !dkim_verify_overall
   && dkim_verify_status
      ? Ustrcmp(dkim_verify_status, US"pass") == 0
      : sig->verify_status == PDKIM_VERIFY_PASS
   )
  dkim_verify_overall = string_copy(sig->domain);

/* Rewrite the sig result if the ACL overrode it.  This is only
needed because the DMARC code (sigh) peeks at the dkim sigs.
Mark the sig for this having been done. */

if (  dkim_verify_status
   && (  dkim_verify_status != dkim_exim_expand_query(DKIM_VERIFY_STATUS)
      || dkim_verify_reason != dkim_exim_expand_query(DKIM_VERIFY_REASON)
   )  )
  {			/* overridden by ACL */
  sig->verify_ext_status = -1;
  if (Ustrcmp(dkim_verify_status, US"fail") == 0)
    sig->verify_status = PDKIM_VERIFY_POLICY | PDKIM_VERIFY_FAIL;
  else if (Ustrcmp(dkim_verify_status, US"invalid") == 0)
    sig->verify_status = PDKIM_VERIFY_POLICY | PDKIM_VERIFY_INVALID;
  else if (Ustrcmp(dkim_verify_status, US"none") == 0)
    sig->verify_status = PDKIM_VERIFY_POLICY | PDKIM_VERIFY_NONE;
  else if (Ustrcmp(dkim_verify_status, US"pass") == 0)
    sig->verify_status = PDKIM_VERIFY_POLICY | PDKIM_VERIFY_PASS;
  else
    sig->verify_status = -1;
  }

if (!LOGGING(dkim_verbose)) return;


logmsg = string_catn(NULL, US"DKIM: ", 6);
if (!(s = sig->domain)) s = US"<UNSET>";
logmsg = string_append(logmsg, 2, "d=", s);
if (!(s = sig->selector)) s = US"<UNSET>";
logmsg = string_append(logmsg, 2, " s=", s);
logmsg = string_fmt_append(logmsg, " c=%s/%s a=%s b=" SIZE_T_FMT,
	  sig->canon_headers == PDKIM_CANON_SIMPLE ? "simple" : "relaxed",
	  sig->canon_body    == PDKIM_CANON_SIMPLE ? "simple" : "relaxed",
	  dkim_sig_to_a_tag(sig),
	  (int)sig->sighash.len > -1 ? sig->sighash.len * 8 : (size_t)0);
if ((s= sig->identity)) logmsg = string_append(logmsg, 2, " i=", s);
if (sig->created > 0) logmsg = string_fmt_append(logmsg, " t=%lu",
				    sig->created);
if (sig->expires > 0) logmsg = string_fmt_append(logmsg, " x=%lu",
				    sig->expires);
if (sig->bodylength > -1) logmsg = string_fmt_append(logmsg, " l=%lu",
				    sig->bodylength);

if (sig->verify_status & PDKIM_VERIFY_POLICY)
  logmsg = string_append(logmsg, 5,
	    US" [", dkim_verify_status, US" - ", dkim_verify_reason, US"]");
else
  switch (sig->verify_status)
    {
    case PDKIM_VERIFY_NONE:
      logmsg = string_cat(logmsg, US" [not verified]");
      break;

    case PDKIM_VERIFY_INVALID:
      logmsg = string_cat(logmsg, US" [invalid - ");
      switch (sig->verify_ext_status)
	{
	case PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE:
	  logmsg = string_cat(logmsg,
			US"public key record (currently?) unavailable]");
	  break;

	case PDKIM_VERIFY_INVALID_BUFFER_SIZE:
	  logmsg = string_cat(logmsg, US"overlong public key record]");
	  break;

	case PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD:
	case PDKIM_VERIFY_INVALID_PUBKEY_IMPORT:
	  logmsg = string_cat(logmsg, US"syntax error in public key record]");
	  break;

	case PDKIM_VERIFY_INVALID_SIGNATURE_ERROR:
	  logmsg = string_cat(logmsg, US"signature tag missing or invalid]");
	  break;

	case PDKIM_VERIFY_INVALID_DKIM_VERSION:
	  logmsg = string_cat(logmsg, US"unsupported DKIM version]");
	  break;

	default:
	  logmsg = string_cat(logmsg, US"unspecified problem]");
	}
      break;

    case PDKIM_VERIFY_FAIL:
      logmsg = string_cat(logmsg, US" [verification failed - ");
      switch (sig->verify_ext_status)
	{
	case PDKIM_VERIFY_FAIL_BODY:
	  logmsg = string_cat(logmsg,
	       US"body hash mismatch (body probably modified in transit)]");
	  break;

	case PDKIM_VERIFY_FAIL_MESSAGE:
	  logmsg = string_cat(logmsg,
		US"signature did not verify "
		"(headers probably modified in transit)]");
	  break;

	default:
	  logmsg = string_cat(logmsg, US"unspecified reason]");
	}
      break;

    case PDKIM_VERIFY_PASS:
      logmsg = string_cat(logmsg, US" [verification succeeded]");
      break;
    }

log_write(0, LOG_MAIN, "%s", string_from_gstring(logmsg));
return;
}


/* Log a line for each signature */
void
dkim_exim_verify_log_all(void)
{
pdkim_signature * sig;
for (sig = dkim_signatures; sig; sig = sig->next) dkim_exim_verify_log_sig(sig);
}


void
dkim_exim_verify_finish(void)
{
pdkim_signature * sig;
int rc;
gstring * g = NULL;
const uschar * errstr = NULL;

store_pool = POOL_PERM;

/* Delete eventual previous signature chain */

dkim_signers = NULL;
dkim_signatures = NULL;

if (dkim_collect_error)
  {
  log_write(0, LOG_MAIN,
      "DKIM: Error during validation, disabling signature verification: %.100s",
      dkim_collect_error);
  f.dkim_disable_verify = TRUE;
  goto out;
  }

dkim_collect_input = 0;

/* Finish DKIM operation and fetch link to signatures chain */

rc = pdkim_feed_finish(dkim_verify_ctx, (pdkim_signature **)&dkim_signatures,
			&errstr);
if (rc != PDKIM_OK && errstr)
  log_write(0, LOG_MAIN, "DKIM: validation error: %s", errstr);

/* Build a colon-separated list of signing domains (and identities, if present) in dkim_signers */

for (sig = dkim_signatures; sig; sig = sig->next)
  {
  if (sig->domain)   g = string_append_listele(g, ':', sig->domain);
  if (sig->identity) g = string_append_listele(g, ':', sig->identity);
  }

if (g) dkim_signers = g->s;

out:
store_pool = dkim_verify_oldpool;
}



/* Args as per dkim_exim_acl_run() below */
static int
dkim_acl_call(uschar * id, gstring ** res_ptr,
  uschar ** user_msgptr, uschar ** log_msgptr)
{
int rc;
DEBUG(D_receive)
  debug_printf("calling acl_smtp_dkim for dkim_cur_signer='%s'\n", id);

rc = acl_check(ACL_WHERE_DKIM, NULL, acl_smtp_dkim, user_msgptr, log_msgptr);
dkim_exim_verify_log_sig(dkim_cur_sig);
*res_ptr = string_append_listele(*res_ptr, ':', dkim_verify_status);
return rc;
}



/* For the given identity, run the DKIM ACL once for each matching signature.

Arguments
 id		Identity to look for in dkim signatures
 res_ptr	ptr to growable string-list of status results,
		appended to per ACL run
 user_msgptr	where to put a user error (for SMTP response)
 log_msgptr	where to put a logging message (not for SMTP response)

Returns:       OK         access is granted by an ACCEPT verb
               DISCARD    access is granted by a DISCARD verb
               FAIL       access is denied
               FAIL_DROP  access is denied; drop the connection
               DEFER      can't tell at the moment
               ERROR      disaster
*/

int
dkim_exim_acl_run(uschar * id, gstring ** res_ptr,
  uschar ** user_msgptr, uschar ** log_msgptr)
{
pdkim_signature * sig;
uschar * cmp_val;
int rc = -1;

dkim_verify_status = US"none";
dkim_verify_reason = US"";
dkim_cur_signer = id;

if (f.dkim_disable_verify || !id || !dkim_verify_ctx)
  return OK;

/* Find signatures to run ACL on */

for (sig = dkim_signatures; sig; sig = sig->next)
  if (  (cmp_val = Ustrchr(id, '@') != NULL ? US sig->identity : US sig->domain)
     && strcmpic(cmp_val, id) == 0
     )
    {
    /* The "dkim_domain" and "dkim_selector" expansion variables have
    related globals, since they are used in the signing code too.
    Instead of inventing separate names for verification, we set
    them here. This is easy since a domain and selector is guaranteed
    to be in a signature. The other dkim_* expansion items are
    dynamically fetched from dkim_cur_sig at expansion time (see
    dkim_exim_expand_query() below). */

    dkim_cur_sig = sig;
    dkim_signing_domain = US sig->domain;
    dkim_signing_selector = US sig->selector;
    dkim_key_length = sig->sighash.len * 8;

    /* These two return static strings, so we can compare the addr
    later to see if the ACL overwrote them.  Check that when logging */

    dkim_verify_status = dkim_exim_expand_query(DKIM_VERIFY_STATUS);
    dkim_verify_reason = dkim_exim_expand_query(DKIM_VERIFY_REASON);

    if ((rc = dkim_acl_call(id, res_ptr, user_msgptr, log_msgptr)) != OK)
      return rc;
    }

if (rc != -1)
  return rc;

/* No matching sig found.  Call ACL once anyway. */

dkim_cur_sig = NULL;
return dkim_acl_call(id, res_ptr, user_msgptr, log_msgptr);
}


static uschar *
dkim_exim_expand_defaults(int what)
{
switch (what)
  {
  case DKIM_ALGO:		return US"";
  case DKIM_BODYLENGTH:		return US"9999999999999";
  case DKIM_CANON_BODY:		return US"";
  case DKIM_CANON_HEADERS:	return US"";
  case DKIM_COPIEDHEADERS:	return US"";
  case DKIM_CREATED:		return US"0";
  case DKIM_EXPIRES:		return US"9999999999999";
  case DKIM_HEADERNAMES:	return US"";
  case DKIM_IDENTITY:		return US"";
  case DKIM_KEY_GRANULARITY:	return US"*";
  case DKIM_KEY_SRVTYPE:	return US"*";
  case DKIM_KEY_NOTES:		return US"";
  case DKIM_KEY_TESTING:	return US"0";
  case DKIM_NOSUBDOMAINS:	return US"0";
  case DKIM_VERIFY_STATUS:	return US"none";
  case DKIM_VERIFY_REASON:	return US"";
  default:			return US"";
  }
}


uschar *
dkim_exim_expand_query(int what)
{
if (!dkim_verify_ctx || f.dkim_disable_verify || !dkim_cur_sig)
  return dkim_exim_expand_defaults(what);

switch (what)
  {
  case DKIM_ALGO:
    return dkim_sig_to_a_tag(dkim_cur_sig);

  case DKIM_BODYLENGTH:
    return dkim_cur_sig->bodylength >= 0
      ? string_sprintf("%ld", dkim_cur_sig->bodylength)
      : dkim_exim_expand_defaults(what);

  case DKIM_CANON_BODY:
    switch (dkim_cur_sig->canon_body)
      {
      case PDKIM_CANON_RELAXED:	return US"relaxed";
      case PDKIM_CANON_SIMPLE:
      default:			return US"simple";
      }

  case DKIM_CANON_HEADERS:
    switch (dkim_cur_sig->canon_headers)
      {
      case PDKIM_CANON_RELAXED:	return US"relaxed";
      case PDKIM_CANON_SIMPLE:
      default:			return US"simple";
      }

  case DKIM_COPIEDHEADERS:
    return dkim_cur_sig->copiedheaders
      ? US dkim_cur_sig->copiedheaders : dkim_exim_expand_defaults(what);

  case DKIM_CREATED:
    return dkim_cur_sig->created > 0
      ? string_sprintf("%lu", dkim_cur_sig->created)
      : dkim_exim_expand_defaults(what);

  case DKIM_EXPIRES:
    return dkim_cur_sig->expires > 0
      ? string_sprintf("%lu", dkim_cur_sig->expires)
      : dkim_exim_expand_defaults(what);

  case DKIM_HEADERNAMES:
    return dkim_cur_sig->headernames
      ? dkim_cur_sig->headernames : dkim_exim_expand_defaults(what);

  case DKIM_IDENTITY:
    return dkim_cur_sig->identity
      ? US dkim_cur_sig->identity : dkim_exim_expand_defaults(what);

  case DKIM_KEY_GRANULARITY:
    return dkim_cur_sig->pubkey
      ? dkim_cur_sig->pubkey->granularity
      ? US dkim_cur_sig->pubkey->granularity
      : dkim_exim_expand_defaults(what)
      : dkim_exim_expand_defaults(what);

  case DKIM_KEY_SRVTYPE:
    return dkim_cur_sig->pubkey
      ? dkim_cur_sig->pubkey->srvtype
      ? US dkim_cur_sig->pubkey->srvtype
      : dkim_exim_expand_defaults(what)
      : dkim_exim_expand_defaults(what);

  case DKIM_KEY_NOTES:
    return dkim_cur_sig->pubkey
      ? dkim_cur_sig->pubkey->notes
      ? US dkim_cur_sig->pubkey->notes
      : dkim_exim_expand_defaults(what)
      : dkim_exim_expand_defaults(what);

  case DKIM_KEY_TESTING:
    return dkim_cur_sig->pubkey
      ? dkim_cur_sig->pubkey->testing
      ? US"1"
      : dkim_exim_expand_defaults(what)
      : dkim_exim_expand_defaults(what);

  case DKIM_NOSUBDOMAINS:
    return dkim_cur_sig->pubkey
      ? dkim_cur_sig->pubkey->no_subdomaining
      ? US"1"
      : dkim_exim_expand_defaults(what)
      : dkim_exim_expand_defaults(what);

  case DKIM_VERIFY_STATUS:
    switch (dkim_cur_sig->verify_status)
      {
      case PDKIM_VERIFY_INVALID:	return US"invalid";
      case PDKIM_VERIFY_FAIL:		return US"fail";
      case PDKIM_VERIFY_PASS:		return US"pass";
      case PDKIM_VERIFY_NONE:
      default:				return US"none";
      }

  case DKIM_VERIFY_REASON:
    switch (dkim_cur_sig->verify_ext_status)
      {
      case PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE:
						return US"pubkey_unavailable";
      case PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD:return US"pubkey_dns_syntax";
      case PDKIM_VERIFY_INVALID_PUBKEY_IMPORT:	return US"pubkey_der_syntax";
      case PDKIM_VERIFY_FAIL_BODY:		return US"bodyhash_mismatch";
      case PDKIM_VERIFY_FAIL_MESSAGE:		return US"signature_incorrect";
      }

  default:
    return US"";
  }
}


void
dkim_exim_sign_init(void)
{
int old_pool = store_pool;
store_pool = POOL_MAIN;
pdkim_init_context(&dkim_sign_ctx, FALSE, &dkim_exim_query_dns_txt);
store_pool = old_pool;
}


/* Generate signatures for the given file.
If a prefix is given, prepend it to the file for the calculations.

Return:
  NULL:		error; error string written
  string: 	signature header(s), or a zero-length string (not an error)
*/

gstring *
dkim_exim_sign(int fd, off_t off, uschar * prefix,
  struct ob_dkim * dkim, const uschar ** errstr)
{
const uschar * dkim_domain = NULL;
int sep = 0;
gstring * seen_doms = NULL;
pdkim_signature * sig;
gstring * sigbuf;
int pdkim_rc;
int sread;
uschar buf[4096];
int save_errno = 0;
int old_pool = store_pool;
uschar * errwhen;
const uschar * s;

if (dkim->dot_stuffed)
  dkim_sign_ctx.flags |= PDKIM_DOT_TERM;

store_pool = POOL_MAIN;

if ((s = dkim->dkim_domain) && !(dkim_domain = expand_cstring(s)))
  /* expansion error, do not send message. */
  { errwhen = US"dkim_domain"; goto expand_bad; }

/* Set $dkim_domain expansion variable to each unique domain in list. */

if (dkim_domain)
  while ((dkim_signing_domain = string_nextinlist(&dkim_domain, &sep, NULL, 0)))
  {
  const uschar * dkim_sel;
  int sel_sep = 0;

  if (dkim_signing_domain[0] == '\0')
    continue;

  /* Only sign once for each domain, no matter how often it
  appears in the expanded list. */

  if (match_isinlist(dkim_signing_domain, CUSS &seen_doms,
      0, NULL, NULL, MCL_STRING, TRUE, NULL) == OK)
    continue;

  seen_doms = string_append_listele(seen_doms, ':', dkim_signing_domain);

  /* Set $dkim_selector expansion variable to each selector in list,
  for this domain. */

  if (!(dkim_sel = expand_string(dkim->dkim_selector)))
    { errwhen = US"dkim_selector"; goto expand_bad; }

  while ((dkim_signing_selector = string_nextinlist(&dkim_sel, &sel_sep,
	  NULL, 0)))
    {
    uschar * dkim_canon_expanded;
    int pdkim_canon;
    uschar * dkim_sign_headers_expanded = NULL;
    uschar * dkim_private_key_expanded;
    uschar * dkim_hash_expanded;
    uschar * dkim_identity_expanded = NULL;
    uschar * dkim_timestamps_expanded = NULL;
    unsigned long tval = 0, xval = 0;

    /* Get canonicalization to use */

    dkim_canon_expanded = dkim->dkim_canon
      ? expand_string(dkim->dkim_canon) : US"relaxed";
    if (!dkim_canon_expanded)	/* expansion error, do not send message. */
      { errwhen = US"dkim_canon"; goto expand_bad; }

    if (Ustrcmp(dkim_canon_expanded, "relaxed") == 0)
      pdkim_canon = PDKIM_CANON_RELAXED;
    else if (Ustrcmp(dkim_canon_expanded, "simple") == 0)
      pdkim_canon = PDKIM_CANON_SIMPLE;
    else
      {
      log_write(0, LOG_MAIN,
		 "DKIM: unknown canonicalization method '%s', defaulting to 'relaxed'.\n",
		 dkim_canon_expanded);
      pdkim_canon = PDKIM_CANON_RELAXED;
      }

    if (  dkim->dkim_sign_headers
       && !(dkim_sign_headers_expanded = expand_string(dkim->dkim_sign_headers)))
      { errwhen = US"dkim_sign_header"; goto expand_bad; }
    /* else pass NULL, which means default header list */

    /* Get private key to use. */

    if (!(dkim_private_key_expanded = expand_string(dkim->dkim_private_key)))
      { errwhen = US"dkim_private_key"; goto expand_bad; }

    if (  Ustrlen(dkim_private_key_expanded) == 0
       || Ustrcmp(dkim_private_key_expanded, "0") == 0
       || Ustrcmp(dkim_private_key_expanded, "false") == 0
       )
      continue;		/* don't sign, but no error */

    if (  dkim_private_key_expanded[0] == '/'
       && !(dkim_private_key_expanded =
	     expand_file_big_buffer(dkim_private_key_expanded)))
      goto bad;

    if (!(dkim_hash_expanded = expand_string(dkim->dkim_hash)))
      { errwhen = US"dkim_hash"; goto expand_bad; }

    if (dkim->dkim_identity)
      if (!(dkim_identity_expanded = expand_string(dkim->dkim_identity)))
	{ errwhen = US"dkim_identity"; goto expand_bad; }
      else if (!*dkim_identity_expanded)
	dkim_identity_expanded = NULL;

    if (dkim->dkim_timestamps)
      if (!(dkim_timestamps_expanded = expand_string(dkim->dkim_timestamps)))
	{ errwhen = US"dkim_timestamps"; goto expand_bad; }
      else
	xval = (tval = (unsigned long) time(NULL))
	      + strtoul(CCS dkim_timestamps_expanded, NULL, 10);

    if (!(sig = pdkim_init_sign(&dkim_sign_ctx, dkim_signing_domain,
			  dkim_signing_selector,
			  dkim_private_key_expanded,
			  dkim_hash_expanded,
			  errstr
			  )))
      goto bad;
    dkim_private_key_expanded[0] = '\0';

    pdkim_set_optional(sig,
			CS dkim_sign_headers_expanded,
			CS dkim_identity_expanded,
			pdkim_canon,
			pdkim_canon, -1, tval, xval);

    if (!pdkim_set_sig_bodyhash(&dkim_sign_ctx, sig))
      goto bad;

    if (!dkim_sign_ctx.sig)		/* link sig to context chain */
      dkim_sign_ctx.sig = sig;
    else
      {
      pdkim_signature * n = dkim_sign_ctx.sig;
      while (n->next) n = n->next;
      n->next = sig;
      }
    }
  }

/* We may need to carry on with the data-feed even if there are no DKIM sigs to
produce, if some other package (eg. ARC) is signing. */

if (!dkim_sign_ctx.sig && !dkim->force_bodyhash)
  {
  DEBUG(D_transport) debug_printf("DKIM: no viable signatures to use\n");
  sigbuf = string_get(1);	/* return a zero-len string */
  }
else
  {
  if (prefix && (pdkim_rc = pdkim_feed(&dkim_sign_ctx, prefix, Ustrlen(prefix))) != PDKIM_OK)
    goto pk_bad;

  if (lseek(fd, off, SEEK_SET) < 0)
    sread = -1;
  else
    while ((sread = read(fd, &buf, sizeof(buf))) > 0)
      if ((pdkim_rc = pdkim_feed(&dkim_sign_ctx, buf, sread)) != PDKIM_OK)
	goto pk_bad;

  /* Handle failed read above. */
  if (sread == -1)
    {
    debug_printf("DKIM: Error reading -K file.\n");
    save_errno = errno;
    goto bad;
    }

  /* Build string of headers, one per signature */

  if ((pdkim_rc = pdkim_feed_finish(&dkim_sign_ctx, &sig, errstr)) != PDKIM_OK)
    goto pk_bad;

  if (!sig)
    {
    DEBUG(D_transport) debug_printf("DKIM: no signatures to use\n");
    sigbuf = string_get(1);	/* return a zero-len string */
    }
  else for (sigbuf = NULL; sig; sig = sig->next)
    sigbuf = string_append(sigbuf, 2, US sig->signature_header, US"\r\n");
  }

CLEANUP:
  (void) string_from_gstring(sigbuf);
  store_pool = old_pool;
  errno = save_errno;
  return sigbuf;

pk_bad:
  log_write(0, LOG_MAIN|LOG_PANIC,
	       	"DKIM: signing failed: %.100s", pdkim_errstr(pdkim_rc));
bad:
  sigbuf = NULL;
  goto CLEANUP;

expand_bad:
  log_write(0, LOG_MAIN | LOG_PANIC, "failed to expand %s: %s",
	      errwhen, expand_string_message);
  goto bad;
}




gstring *
authres_dkim(gstring * g)
{
pdkim_signature * sig;
int start = 0;		/* compiler quietening */

DEBUG(D_acl) start = g->ptr;

for (sig = dkim_signatures; sig; sig = sig->next)
  {
  g = string_catn(g, US";\n\tdkim=", 8);

  if (sig->verify_status & PDKIM_VERIFY_POLICY)
    g = string_append(g, 5,
      US"policy (", dkim_verify_status, US" - ", dkim_verify_reason, US")");
  else switch(sig->verify_status)
    {
    case PDKIM_VERIFY_NONE:    g = string_cat(g, US"none"); break;
    case PDKIM_VERIFY_INVALID:
      switch (sig->verify_ext_status)
	{
	case PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE:
          g = string_cat(g, US"tmperror (pubkey unavailable)\n\t\t"); break;
        case PDKIM_VERIFY_INVALID_BUFFER_SIZE:
          g = string_cat(g, US"permerror (overlong public key record)\n\t\t"); break;
        case PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD:
        case PDKIM_VERIFY_INVALID_PUBKEY_IMPORT:
          g = string_cat(g, US"neutral (public key record import problem)\n\t\t");
          break;
        case PDKIM_VERIFY_INVALID_SIGNATURE_ERROR:
          g = string_cat(g, US"neutral (signature tag missing or invalid)\n\t\t");
          break;
        case PDKIM_VERIFY_INVALID_DKIM_VERSION:
          g = string_cat(g, US"neutral (unsupported DKIM version)\n\t\t");
          break;
        default:
          g = string_cat(g, US"permerror (unspecified problem)\n\t\t"); break;
	}
      break;
    case PDKIM_VERIFY_FAIL:
      switch (sig->verify_ext_status)
	{
	case PDKIM_VERIFY_FAIL_BODY:
          g = string_cat(g,
	    US"fail (body hash mismatch; body probably modified in transit)\n\t\t");
	  break;
        case PDKIM_VERIFY_FAIL_MESSAGE:
          g = string_cat(g,
	    US"fail (signature did not verify; headers probably modified in transit)\n\t\t");
	  break;
        default:
          g = string_cat(g, US"fail (unspecified reason)\n\t\t");
	  break;
	}
      break;
    case PDKIM_VERIFY_PASS:    g = string_cat(g, US"pass"); break;
    default:                   g = string_cat(g, US"permerror"); break;
    }
  if (sig->domain)   g = string_append(g, 2, US" header.d=", sig->domain);
  if (sig->identity) g = string_append(g, 2, US" header.i=", sig->identity);
  if (sig->selector) g = string_append(g, 2, US" header.s=", sig->selector);
  g = string_append(g, 2, US" header.a=", dkim_sig_to_a_tag(sig));
  }

DEBUG(D_acl)
  if (g->ptr == start)
    debug_printf("DKIM: no authres\n");
  else
    debug_printf("DKIM: authres '%.*s'\n", g->ptr - start - 3, g->s + start + 3);
return g;
}


# endif	/*!MACRO_PREDEF*/
#endif	/*!DISABLE_DKIM*/
