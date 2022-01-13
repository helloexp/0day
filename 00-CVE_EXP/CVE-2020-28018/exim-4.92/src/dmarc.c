/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/
/* Experimental DMARC support.
   Copyright (c) Todd Lyons <tlyons@exim.org> 2012 - 2014
   License: GPL */

/* Portions Copyright (c) 2012, 2013, The Trusted Domain Project;
   All rights reserved, licensed for use per LICENSE.opendmarc. */

/* Code for calling dmarc checks via libopendmarc. Called from acl.c. */

#include "exim.h"
#ifdef EXPERIMENTAL_DMARC
# if !defined SUPPORT_SPF
#  error SPF must also be enabled for DMARC
# elif defined DISABLE_DKIM
#  error DKIM must also be enabled for DMARC
# else

#  include "functions.h"
#  include "dmarc.h"
#  include "pdkim/pdkim.h"

OPENDMARC_LIB_T     dmarc_ctx;
DMARC_POLICY_T     *dmarc_pctx = NULL;
OPENDMARC_STATUS_T  libdm_status, action, dmarc_policy;
OPENDMARC_STATUS_T  da, sa, action;
BOOL dmarc_abort  = FALSE;
uschar *dmarc_pass_fail = US"skipped";
header_line *from_header   = NULL;
extern SPF_response_t   *spf_response;
int dmarc_spf_ares_result  = 0;
uschar *spf_sender_domain  = NULL;
uschar *spf_human_readable = NULL;
u_char *header_from_sender = NULL;
int history_file_status    = DMARC_HIST_OK;
uschar *dkim_history_buffer= NULL;

typedef struct dmarc_exim_p {
  uschar *name;
  int    value;
} dmarc_exim_p;

static dmarc_exim_p dmarc_policy_description[] = {
  /* name		value */
  { US"",           DMARC_RECORD_P_UNSPECIFIED },
  { US"none",       DMARC_RECORD_P_NONE },
  { US"quarantine", DMARC_RECORD_P_QUARANTINE },
  { US"reject",     DMARC_RECORD_P_REJECT },
  { NULL,           0 }
};
/* Accept an error_block struct, initialize if empty, parse to the
 * end, and append the two strings passed to it.  Used for adding
 * variable amounts of value:pair data to the forensic emails. */

static error_block *
add_to_eblock(error_block *eblock, uschar *t1, uschar *t2)
{
error_block *eb = store_malloc(sizeof(error_block));
if (eblock == NULL)
  eblock = eb;
else
  {
  /* Find the end of the eblock struct and point it at eb */
  error_block *tmp = eblock;
  while(tmp->next != NULL)
    tmp = tmp->next;
  tmp->next = eb;
  }
eb->text1 = t1;
eb->text2 = t2;
eb->next  = NULL;
return eblock;
}

/* dmarc_init sets up a context that can be re-used for several
   messages on the same SMTP connection (that come from the
   same host with the same HELO string) */

int
dmarc_init()
{
int *netmask   = NULL;   /* Ignored */
int is_ipv6    = 0;

/* Set some sane defaults.  Also clears previous results when
 * multiple messages in one connection. */
dmarc_pctx         = NULL;
dmarc_status       = US"none";
dmarc_abort        = FALSE;
dmarc_pass_fail    = US"skipped";
dmarc_used_domain  = US"";
f.dmarc_has_been_checked = FALSE;
header_from_sender = NULL;
spf_sender_domain  = NULL;
spf_human_readable = NULL;

/* ACLs have "control=dmarc_disable_verify" */
if (f.dmarc_disable_verify == TRUE)
  return OK;

(void) memset(&dmarc_ctx, '\0', sizeof dmarc_ctx);
dmarc_ctx.nscount = 0;
libdm_status = opendmarc_policy_library_init(&dmarc_ctx);
if (libdm_status != DMARC_PARSE_OKAY)
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "DMARC failure to init library: %s",
		       opendmarc_policy_status_to_str(libdm_status));
  dmarc_abort = TRUE;
  }
if (!dmarc_tld_file)
  {
  DEBUG(D_receive) debug_printf("DMARC: no dmarc_tld_file\n");
  dmarc_abort = TRUE;
  }
else if (opendmarc_tld_read_file(CS dmarc_tld_file, NULL, NULL, NULL))
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "DMARC failure to load tld list %s: %d",
		       dmarc_tld_file, errno);
  dmarc_abort = TRUE;
  }
if (!sender_host_address)
  {
  DEBUG(D_receive) debug_printf("DMARC: no sender_host_address\n");
  dmarc_abort = TRUE;
  }
/* This catches locally originated email and startup errors above. */
if (!dmarc_abort)
  {
  is_ipv6 = string_is_ip_address(sender_host_address, netmask) == 6;
  if (!(dmarc_pctx = opendmarc_policy_connect_init(sender_host_address, is_ipv6)))
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
      "DMARC failure creating policy context: ip=%s", sender_host_address);
    dmarc_abort = TRUE;
    }
  }

return OK;
}


/* dmarc_store_data stores the header data so that subsequent
dmarc_process can access the data */

int
dmarc_store_data(header_line *hdr)
{
/* No debug output because would change every test debug output */
if (!f.dmarc_disable_verify)
  from_header = hdr;
return OK;
}


static void
dmarc_send_forensic_report(u_char **ruf)
{
int   c;
uschar *recipient, *save_sender;
BOOL  send_status = FALSE;
error_block *eblock = NULL;
FILE *message_file = NULL;

/* Earlier ACL does not have *required* control=dmarc_enable_forensic */
if (!f.dmarc_enable_forensic)
  return;

if (  dmarc_policy == DMARC_POLICY_REJECT     && action == DMARC_RESULT_REJECT
   || dmarc_policy == DMARC_POLICY_QUARANTINE && action == DMARC_RESULT_QUARANTINE
   || dmarc_policy == DMARC_POLICY_NONE       && action == DMARC_RESULT_REJECT
   || dmarc_policy == DMARC_POLICY_NONE       && action == DMARC_RESULT_QUARANTINE
   )
  if (ruf)
    {
    eblock = add_to_eblock(eblock, US"Sender Domain", dmarc_used_domain);
    eblock = add_to_eblock(eblock, US"Sender IP Address", sender_host_address);
    eblock = add_to_eblock(eblock, US"Received Date", tod_stamp(tod_full));
    eblock = add_to_eblock(eblock, US"SPF Alignment",
		     sa == DMARC_POLICY_SPF_ALIGNMENT_PASS ? US"yes" : US"no");
    eblock = add_to_eblock(eblock, US"DKIM Alignment",
		     da == DMARC_POLICY_DKIM_ALIGNMENT_PASS ? US"yes" : US"no");
    eblock = add_to_eblock(eblock, US"DMARC Results", dmarc_status_text);

    for (c = 0; ruf[c]; c++)
      {
      recipient = string_copylc(ruf[c]);
      if (Ustrncmp(recipient, "mailto:",7))
	continue;
      /* Move to first character past the colon */
      recipient += 7;
      DEBUG(D_receive)
	debug_printf("DMARC forensic report to %s%s\n", recipient,
	     (host_checking || f.running_in_test_harness) ? " (not really)" : "");
      if (host_checking || f.running_in_test_harness)
	continue;

      if (!moan_send_message(recipient, ERRMESS_DMARC_FORENSIC, eblock,
			    header_list, message_file, NULL))
	log_write(0, LOG_MAIN|LOG_PANIC,
	  "failure to send DMARC forensic report to %s", recipient);
      }
    }
}

/* dmarc_process adds the envelope sender address to the existing
context (if any), retrieves the result, sets up expansion
strings and evaluates the condition outcome. */

int
dmarc_process()
{
int sr, origin;             /* used in SPF section */
int dmarc_spf_result  = 0;  /* stores spf into dmarc conn ctx */
int tmp_ans, c;
pdkim_signature * sig = dkim_signatures;
BOOL has_dmarc_record = TRUE;
u_char **ruf; /* forensic report addressees, if called for */

/* ACLs have "control=dmarc_disable_verify" */
if (f.dmarc_disable_verify)
  return OK;

/* Store the header From: sender domain for this part of DMARC.
 * If there is no from_header struct, then it's likely this message
 * is locally generated and relying on fixups to add it.  Just skip
 * the entire DMARC system if we can't find a From: header....or if
 * there was a previous error.
 */
if (!from_header)
  {
  DEBUG(D_receive) debug_printf("DMARC: no From: header\n");
  dmarc_abort = TRUE;
  }
else if (!dmarc_abort)
  {
  uschar * errormsg;
  int dummy, domain;
  uschar * p;
  uschar saveend;

  f.parse_allow_group = TRUE;
  p = parse_find_address_end(from_header->text, FALSE);
  saveend = *p; *p = '\0';
  if ((header_from_sender = parse_extract_address(from_header->text, &errormsg,
			      &dummy, &dummy, &domain, FALSE)))
    header_from_sender += domain;
  *p = saveend;

  /* The opendmarc library extracts the domain from the email address, but
   * only try to store it if it's not empty.  Otherwise, skip out of DMARC. */
  if (!header_from_sender || (strcmp( CCS header_from_sender, "") == 0))
    dmarc_abort = TRUE;
  libdm_status = dmarc_abort
    ? DMARC_PARSE_OKAY
    : opendmarc_policy_store_from_domain(dmarc_pctx, header_from_sender);
  if (libdm_status != DMARC_PARSE_OKAY)
    {
    log_write(0, LOG_MAIN|LOG_PANIC,
	      "failure to store header From: in DMARC: %s, header was '%s'",
	      opendmarc_policy_status_to_str(libdm_status), from_header->text);
    dmarc_abort = TRUE;
    }
  }

/* Skip DMARC if connection is SMTP Auth. Temporarily, admin should
 * instead do this in the ACLs.  */
if (!dmarc_abort && !sender_host_authenticated)
  {
  uschar * dmarc_domain;

  /* Use the envelope sender domain for this part of DMARC */
  spf_sender_domain = expand_string(US"$sender_address_domain");
  if (!spf_response)
    {
    /* No spf data means null envelope sender so generate a domain name
     * from the sender_helo_name  */
    if (!spf_sender_domain)
      {
      spf_sender_domain = sender_helo_name;
      log_write(0, LOG_MAIN, "DMARC using synthesized SPF sender domain = %s\n",
			     spf_sender_domain);
      DEBUG(D_receive)
	debug_printf("DMARC using synthesized SPF sender domain = %s\n",
	  spf_sender_domain);
      }
    dmarc_spf_result = DMARC_POLICY_SPF_OUTCOME_NONE;
    dmarc_spf_ares_result = ARES_RESULT_UNKNOWN;
    origin = DMARC_POLICY_SPF_ORIGIN_HELO;
    spf_human_readable = US"";
    }
  else
    {
    sr = spf_response->result;
    dmarc_spf_result = sr == SPF_RESULT_NEUTRAL  ? DMARC_POLICY_SPF_OUTCOME_NONE :
		       sr == SPF_RESULT_PASS     ? DMARC_POLICY_SPF_OUTCOME_PASS :
		       sr == SPF_RESULT_FAIL     ? DMARC_POLICY_SPF_OUTCOME_FAIL :
		       sr == SPF_RESULT_SOFTFAIL ? DMARC_POLICY_SPF_OUTCOME_TMPFAIL :
		       DMARC_POLICY_SPF_OUTCOME_NONE;
    dmarc_spf_ares_result = sr == SPF_RESULT_NEUTRAL   ? ARES_RESULT_NEUTRAL :
			    sr == SPF_RESULT_PASS      ? ARES_RESULT_PASS :
			    sr == SPF_RESULT_FAIL      ? ARES_RESULT_FAIL :
			    sr == SPF_RESULT_SOFTFAIL  ? ARES_RESULT_SOFTFAIL :
			    sr == SPF_RESULT_NONE      ? ARES_RESULT_NONE :
			    sr == SPF_RESULT_TEMPERROR ? ARES_RESULT_TEMPERROR :
			    sr == SPF_RESULT_PERMERROR ? ARES_RESULT_PERMERROR :
			    ARES_RESULT_UNKNOWN;
    origin = DMARC_POLICY_SPF_ORIGIN_MAILFROM;
    spf_human_readable = US spf_response->header_comment;
    DEBUG(D_receive)
      debug_printf("DMARC using SPF sender domain = %s\n", spf_sender_domain);
    }
  if (strcmp( CCS spf_sender_domain, "") == 0)
    dmarc_abort = TRUE;
  if (!dmarc_abort)
    {
    libdm_status = opendmarc_policy_store_spf(dmarc_pctx, spf_sender_domain,
				dmarc_spf_result, origin, spf_human_readable);
    if (libdm_status != DMARC_PARSE_OKAY)
      log_write(0, LOG_MAIN|LOG_PANIC, "failure to store spf for DMARC: %s",
			   opendmarc_policy_status_to_str(libdm_status));
    }

  /* Now we cycle through the dkim signature results and put into
   * the opendmarc context, further building the DMARC reply.  */
  dkim_history_buffer = US"";
  while (sig)
    {
    int dkim_result, dkim_ares_result, vs, ves;

    vs  = sig->verify_status & ~PDKIM_VERIFY_POLICY;
    ves = sig->verify_ext_status;
    dkim_result = vs == PDKIM_VERIFY_PASS ? DMARC_POLICY_DKIM_OUTCOME_PASS :
		  vs == PDKIM_VERIFY_FAIL ? DMARC_POLICY_DKIM_OUTCOME_FAIL :
		  vs == PDKIM_VERIFY_INVALID ? DMARC_POLICY_DKIM_OUTCOME_TMPFAIL :
		  DMARC_POLICY_DKIM_OUTCOME_NONE;
    libdm_status = opendmarc_policy_store_dkim(dmarc_pctx, US sig->domain,
					       dkim_result, US"");
    DEBUG(D_receive)
      debug_printf("DMARC adding DKIM sender domain = %s\n", sig->domain);
    if (libdm_status != DMARC_PARSE_OKAY)
      log_write(0, LOG_MAIN|LOG_PANIC,
		"failure to store dkim (%s) for DMARC: %s",
		sig->domain, opendmarc_policy_status_to_str(libdm_status));

    dkim_ares_result =
      vs == PDKIM_VERIFY_PASS    ? ARES_RESULT_PASS :
      vs == PDKIM_VERIFY_FAIL    ? ARES_RESULT_FAIL :
      vs == PDKIM_VERIFY_NONE    ? ARES_RESULT_NONE :
      vs == PDKIM_VERIFY_INVALID ?
       ves == PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE ? ARES_RESULT_PERMERROR :
       ves == PDKIM_VERIFY_INVALID_BUFFER_SIZE        ? ARES_RESULT_PERMERROR :
       ves == PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD   ? ARES_RESULT_PERMERROR :
       ves == PDKIM_VERIFY_INVALID_PUBKEY_IMPORT      ? ARES_RESULT_PERMERROR :
       ARES_RESULT_UNKNOWN :
      ARES_RESULT_UNKNOWN;
    dkim_history_buffer = string_sprintf("%sdkim %s %d\n", dkim_history_buffer,
					 sig->domain, dkim_ares_result);
    sig = sig->next;
    }
  libdm_status = opendmarc_policy_query_dmarc(dmarc_pctx, US"");
  switch (libdm_status)
    {
    case DMARC_DNS_ERROR_NXDOMAIN:
    case DMARC_DNS_ERROR_NO_RECORD:
      DEBUG(D_receive)
	debug_printf("DMARC no record found for %s\n", header_from_sender);
      has_dmarc_record = FALSE;
      break;
    case DMARC_PARSE_OKAY:
      DEBUG(D_receive)
	debug_printf("DMARC record found for %s\n", header_from_sender);
      break;
    case DMARC_PARSE_ERROR_BAD_VALUE:
      DEBUG(D_receive)
	debug_printf("DMARC record parse error for %s\n", header_from_sender);
      has_dmarc_record = FALSE;
      break;
    default:
      /* everything else, skip dmarc */
      DEBUG(D_receive)
	debug_printf("DMARC skipping (%d), unsure what to do with %s",
		      libdm_status, from_header->text);
      has_dmarc_record = FALSE;
      break;
    }

/* Store the policy string in an expandable variable. */

  libdm_status = opendmarc_policy_fetch_p(dmarc_pctx, &tmp_ans);
  for (c = 0; dmarc_policy_description[c].name; c++)
    if (tmp_ans == dmarc_policy_description[c].value)
      {
      dmarc_domain_policy = string_sprintf("%s",dmarc_policy_description[c].name);
      break;
      }

  /* Can't use exim's string manipulation functions so allocate memory
  for libopendmarc using its max hostname length definition. */

  dmarc_domain = US calloc(DMARC_MAXHOSTNAMELEN, sizeof(uschar));
  libdm_status = opendmarc_policy_fetch_utilized_domain(dmarc_pctx,
    dmarc_domain, DMARC_MAXHOSTNAMELEN-1);
  dmarc_used_domain = string_copy(dmarc_domain);
  free(dmarc_domain);

  if (libdm_status != DMARC_PARSE_OKAY)
    log_write(0, LOG_MAIN|LOG_PANIC,
      "failure to read domainname used for DMARC lookup: %s",
      opendmarc_policy_status_to_str(libdm_status));

  dmarc_policy = libdm_status = opendmarc_get_policy_to_enforce(dmarc_pctx);
  switch(libdm_status)
    {
    case DMARC_POLICY_ABSENT:     /* No DMARC record found */
      dmarc_status = US"norecord";
      dmarc_pass_fail = US"none";
      dmarc_status_text = US"No DMARC record";
      action = DMARC_RESULT_ACCEPT;
      break;
    case DMARC_FROM_DOMAIN_ABSENT:    /* No From: domain */
      dmarc_status = US"nofrom";
      dmarc_pass_fail = US"temperror";
      dmarc_status_text = US"No From: domain found";
      action = DMARC_RESULT_ACCEPT;
      break;
    case DMARC_POLICY_NONE:       /* Accept and report */
      dmarc_status = US"none";
      dmarc_pass_fail = US"none";
      dmarc_status_text = US"None, Accept";
      action = DMARC_RESULT_ACCEPT;
      break;
    case DMARC_POLICY_PASS:       /* Explicit accept */
      dmarc_status = US"accept";
      dmarc_pass_fail = US"pass";
      dmarc_status_text = US"Accept";
      action = DMARC_RESULT_ACCEPT;
      break;
    case DMARC_POLICY_REJECT:       /* Explicit reject */
      dmarc_status = US"reject";
      dmarc_pass_fail = US"fail";
      dmarc_status_text = US"Reject";
      action = DMARC_RESULT_REJECT;
      break;
    case DMARC_POLICY_QUARANTINE:       /* Explicit quarantine */
      dmarc_status = US"quarantine";
      dmarc_pass_fail = US"fail";
      dmarc_status_text = US"Quarantine";
      action = DMARC_RESULT_QUARANTINE;
      break;
    default:
      dmarc_status = US"temperror";
      dmarc_pass_fail = US"temperror";
      dmarc_status_text = US"Internal Policy Error";
      action = DMARC_RESULT_TEMPFAIL;
      break;
    }

  libdm_status = opendmarc_policy_fetch_alignment(dmarc_pctx, &da, &sa);
  if (libdm_status != DMARC_PARSE_OKAY)
    log_write(0, LOG_MAIN|LOG_PANIC, "failure to read DMARC alignment: %s",
			     opendmarc_policy_status_to_str(libdm_status));

  if (has_dmarc_record)
    {
    log_write(0, LOG_MAIN, "DMARC results: spf_domain=%s dmarc_domain=%s "
			   "spf_align=%s dkim_align=%s enforcement='%s'",
			   spf_sender_domain, dmarc_used_domain,
			   sa==DMARC_POLICY_SPF_ALIGNMENT_PASS  ?"yes":"no",
			   da==DMARC_POLICY_DKIM_ALIGNMENT_PASS ?"yes":"no",
			   dmarc_status_text);
    history_file_status = dmarc_write_history_file();
    /* Now get the forensic reporting addresses, if any */
    ruf = opendmarc_policy_fetch_ruf(dmarc_pctx, NULL, 0, 1);
    dmarc_send_forensic_report(ruf);
    }
  }

/* shut down libopendmarc */
if (dmarc_pctx)
  (void) opendmarc_policy_connect_shutdown(dmarc_pctx);
if (!f.dmarc_disable_verify)
  (void) opendmarc_policy_library_shutdown(&dmarc_ctx);

return OK;
}

static int
dmarc_write_history_file()
{
int history_file_fd;
ssize_t written_len;
int tmp_ans;
u_char **rua; /* aggregate report addressees */
uschar *history_buffer = NULL;

if (!dmarc_history_file)
  {
  DEBUG(D_receive) debug_printf("DMARC history file not set\n");
  return DMARC_HIST_DISABLED;
  }
history_file_fd = log_create(dmarc_history_file);

if (history_file_fd < 0)
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "failure to create DMARC history file: %s",
			   dmarc_history_file);
  return DMARC_HIST_FILE_ERR;
  }

/* Generate the contents of the history file */
history_buffer = string_sprintf(
  "job %s\nreporter %s\nreceived %ld\nipaddr %s\nfrom %s\nmfrom %s\n",
  message_id, primary_hostname, time(NULL), sender_host_address,
  header_from_sender, expand_string(US"$sender_address_domain"));

if (spf_response)
  history_buffer = string_sprintf("%sspf %d\n", history_buffer, dmarc_spf_ares_result);
  /* history_buffer = string_sprintf("%sspf -1\n", history_buffer); */

history_buffer = string_sprintf(
  "%s%spdomain %s\npolicy %d\n",
  history_buffer, dkim_history_buffer, dmarc_used_domain, dmarc_policy);

if ((rua = opendmarc_policy_fetch_rua(dmarc_pctx, NULL, 0, 1)))
  for (tmp_ans = 0; rua[tmp_ans]; tmp_ans++)
    history_buffer = string_sprintf("%srua %s\n", history_buffer, rua[tmp_ans]);
else
  history_buffer = string_sprintf("%srua -\n", history_buffer);

opendmarc_policy_fetch_pct(dmarc_pctx, &tmp_ans);
history_buffer = string_sprintf("%spct %d\n", history_buffer, tmp_ans);

opendmarc_policy_fetch_adkim(dmarc_pctx, &tmp_ans);
history_buffer = string_sprintf("%sadkim %d\n", history_buffer, tmp_ans);

opendmarc_policy_fetch_aspf(dmarc_pctx, &tmp_ans);
history_buffer = string_sprintf("%saspf %d\n", history_buffer, tmp_ans);

opendmarc_policy_fetch_p(dmarc_pctx, &tmp_ans);
history_buffer = string_sprintf("%sp %d\n", history_buffer, tmp_ans);

opendmarc_policy_fetch_sp(dmarc_pctx, &tmp_ans);
history_buffer = string_sprintf("%ssp %d\n", history_buffer, tmp_ans);

history_buffer = string_sprintf(
  "%salign_dkim %d\nalign_spf %d\naction %d\n",
  history_buffer, da, sa, action);

/* Write the contents to the history file */
DEBUG(D_receive)
  debug_printf("DMARC logging history data for opendmarc reporting%s\n",
	     (host_checking || f.running_in_test_harness) ? " (not really)" : "");
if (host_checking || f.running_in_test_harness)
  {
  DEBUG(D_receive)
    debug_printf("DMARC history data for debugging:\n%s", history_buffer);
  }
else
  {
  written_len = write_to_fd_buf(history_file_fd,
				history_buffer,
				Ustrlen(history_buffer));
  if (written_len == 0)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "failure to write to DMARC history file: %s",
			   dmarc_history_file);
    return DMARC_HIST_WRITE_ERR;
    }
  (void)close(history_file_fd);
  }
return DMARC_HIST_OK;
}


uschar *
dmarc_exim_expand_query(int what)
{
if (f.dmarc_disable_verify || !dmarc_pctx)
  return dmarc_exim_expand_defaults(what);

if (what == DMARC_VERIFY_STATUS)
  return dmarc_status;
return US"";
}

uschar *
dmarc_exim_expand_defaults(int what)
{
if (what == DMARC_VERIFY_STATUS)
  return f.dmarc_disable_verify ?  US"off" : US"none";
return US"";
}


gstring *
authres_dmarc(gstring * g)
{
if (f.dmarc_has_been_checked)
  {
  g = string_append(g, 2, US";\n\tdmarc=", dmarc_pass_fail);
  if (header_from_sender)
    g = string_append(g, 2, US" header.from=", header_from_sender);
  }
return g;
}

# endif /* SUPPORT_SPF */
#endif /* EXPERIMENTAL_DMARC */
/* vi: aw ai sw=2
 */
