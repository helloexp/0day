/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions concerned with rewriting headers */


#include "exim.h"

/* Names for testing rewriting */

static const char *rrname[] = {
  "  sender",
  "    from",
  "      to",
  "      cc",
  "     bcc",
  "reply-to",
  "env-from",
  "  env-to"
};

/* Structure and table for finding source of address for debug printing */

typedef struct where_list_block {
  int bit;
  const uschar *string;
} where_list_block;

static where_list_block where_list[] = {
  { rewrite_sender,  CUS"sender:" },
  { rewrite_from,    CUS"from:" },
  { rewrite_to,      CUS"to:" },
  { rewrite_cc,      CUS"cc:" },
  { rewrite_bcc,     CUS"bcc:" },
  { rewrite_replyto, CUS"reply-to:" },
  { rewrite_envfrom, CUS"env-from" },
  { rewrite_envto,   CUS"env-to" },
  { rewrite_smtp,    CUS"smtp recipient" },
  { rewrite_smtp|rewrite_smtp_sender, CUS"smtp sender" }
};

static int where_list_size = sizeof(where_list)/sizeof(where_list_block);



/*************************************************
*            Ensure an address is qualified      *
*************************************************/

/*
Arguments:
  s              address to check
  is_recipient   TRUE if a recipient address; FALSE if a sender address

Returns:         fully-qualified address
*/

uschar *
rewrite_address_qualify(uschar *s, BOOL is_recipient)
{
return (parse_find_at(s) != NULL)? s :
  string_sprintf("%s@%s", s,
    is_recipient? qualify_domain_recipient : qualify_domain_sender);
}



/*************************************************
*               Rewrite a single address         *
*************************************************/

/* The yield is the input address if there is no rewriting to be done. Assume
the input is a valid address, except in the case of SMTP-time rewriting, which
is handled specially. When this function is called while processing filter and
forward files, the uid may be that of the user. Ensure it is reset while
expanding a replacement, in case that involves file lookups.

Arguments:
  s              address to rewrite
  flag           indicates where this address comes from; it must match the
                   flags in the rewriting rule
  whole          if not NULL, set TRUE if any rewriting rule contained the
                   "whole" bit and it is a header that is being rewritten
  add_header     if TRUE and rewriting occurs, add an "X-rewrote-xxx" header
                   if headers are in existence; this should be TRUE only when
                   a message is being received, not during delivery
  name           name of header, for use when adding X-rewrote-xxxx
  rewrite_rules  chain of rewriting rules

Returns:         new address if rewritten; the input address if no change;
                 for a header rewrite, if the "whole" bit is set, the entire
                 rewritten address is returned, not just the active bit.
*/

uschar *
rewrite_one(uschar *s, int flag, BOOL *whole, BOOL add_header, uschar *name,
  rewrite_rule *rewrite_rules)
{
rewrite_rule *rule;
uschar *yield = s;
uschar *subject = s;
uschar *domain = NULL;
BOOL done = FALSE;
int rule_number = 1;
int yield_start = 0, yield_end = 0;

if (whole != NULL) *whole = FALSE;

/* Scan the rewriting rules */

for (rule = rewrite_rules;
     rule != NULL && !done;
     rule_number++, rule = rule->next)
  {
  int start, end, pdomain;
  int count = 0;
  uschar *save_localpart;
  const uschar *save_domain;
  uschar *error, *new, *newparsed;

  /* Ensure that the flag matches the flags in the rule. */

  if ((rule->flags & flag) == 0) continue;

  /* Come back here for a repeat after a successful rewrite. We do this
  only so many times. */

  REPEAT_RULE:

  /* If this is an SMTP-time rewrite, the pattern must be a regex and
  the subject may have any structure. No local part or domain variables
  can be set for the expansion. We expand the pattern in order to be consistent
  with the other kinds of rewrite, where expansion happens inside
  match_address_list(). */

  if ((flag & rewrite_smtp) != 0)
    {
    uschar *key = expand_string(rule->key);
    if (key == NULL)
      {
      if (!f.expand_string_forcedfail)
        log_write(0, LOG_MAIN|LOG_PANIC, "failed to expand \"%s\" while "
          "checking for SMTP rewriting: %s", rule->key, expand_string_message);
      continue;
      }
    if (match_check_string(subject, key, 0, TRUE, FALSE, FALSE, NULL) != OK)
      continue;
    new = expand_string(rule->replacement);
    }

  /* All other rewrites expect the input to be a valid address, so local part
  and domain variables can be set for expansion. For the first rule, to be
  applied to this address, domain will be NULL and needs to be set. */

  else
    {
    if (domain == NULL) domain = Ustrrchr(subject, '@') + 1;

    /* Use the general function for matching an address against a list (here
    just one item, so use the "impossible value" separator UCHAR_MAX+1). */

    if (match_address_list(subject, FALSE, TRUE, CUSS &(rule->key), NULL, 0,
        UCHAR_MAX + 1, NULL) != OK)
      continue;

    /* The source address matches, and numerical variables have been
    set up. If the replacement string consists of precisely "*" then no
    rewriting is required for this address - the behaviour is as for "fail"
    in the replacement expansion, but assuming the quit flag. */

    if (Ustrcmp(rule->replacement, "*") == 0) break;

    /* Otherwise, expand the replacement string. Set $local_part and $domain to
    the appropriate values, restoring whatever value they previously had
    afterwards. */

    save_localpart = deliver_localpart;
    save_domain = deliver_domain;

    /* We have subject pointing to "localpart@domain" and domain pointing to
    the domain. Temporarily terminate the local part so that it can be
    set up as an expansion variable */

    domain[-1] = 0;
    deliver_localpart = subject;
    deliver_domain = domain;

    new = expand_string(rule->replacement);

    domain[-1] = '@';
    deliver_localpart = save_localpart;
    deliver_domain = save_domain;
    }

  /* If the expansion failed with the "forcedfail" flag, don't generate
  an error - just give up on this rewriting rule. If the "q" flag is set,
  give up altogether. For other expansion failures we have a configuration
  error. */

  if (new == NULL)
    {
    if (f.expand_string_forcedfail)
      { if ((rule->flags & rewrite_quit) != 0) break; else continue; }

    expand_string_message = expand_hide_passwords(expand_string_message);

    log_write(0, LOG_MAIN|LOG_PANIC, "Expansion of %s failed while rewriting: "
      "%s", rule->replacement, expand_string_message);
    break;
    }

  /* Check the what has been generated is a valid RFC 2822 address. Only
  envelope from or SMTP sender is permitted to be rewritten as <>.*/

  newparsed = parse_extract_address(new, &error, &start, &end, &pdomain,
    flag == rewrite_envfrom || flag == (rewrite_smtp|rewrite_smtp_sender));

  if (newparsed == NULL)
    {
    log_write(0, LOG_MAIN|LOG_PANIC, "Rewrite of %s yielded unparseable "
      "address: %s in address %s", subject, error, new);
    break;   /* Give up on this address */
    }

  /* A non-null unqualified address can be qualified if requested. Otherwise,
  this is an error unless it's the empty address in circumstances where that is
  permitted. */

  if (pdomain == 0 && (*newparsed != 0 ||
      (flag != rewrite_envfrom && flag != (rewrite_smtp|rewrite_smtp_sender))))
    {
    if ((rule->flags & rewrite_qualify) != 0)
      {
      newparsed = rewrite_address_qualify(newparsed, TRUE);
      new = string_sprintf("%.*s%s%.*s", start, new, newparsed,
        Ustrlen(new) - end, new + end);
      end = start + Ustrlen(newparsed);
      }
    else
      {
      log_write(0, LOG_MAIN|LOG_PANIC, "Rewrite of %s yielded unqualified "
        "address \"%s\"", subject, new);
      break;   /* Give up on this address */
      }
    }

  /* We have a validly rewritten address */

  if (LOGGING(address_rewrite) || (debug_selector & D_rewrite) != 0)
    {
    int i;
    const uschar *where = CUS"?";

    for (i = 0; i < where_list_size; i++)
      {
      if (flag == where_list[i].bit)
        {
        where = where_list[i].string;
        break;
        }
      }
    log_write(L_address_rewrite,
           LOG_MAIN, "\"%s\" from %s rewritten as \"%s\" by rule %d",
           yield, where, new, rule_number);
    }

  /* A header will only actually be added if header_last is non-NULL,
  i.e. during message reception or delivery, but add_header should not
  be set TRUE during delivery, as otherwise multiple instances of the header
  can fill up the -H file and make it embarrassingly large. We don't need
  to set header_rewritten because the -H file always gets written at the end
  of message reception. */

  if (add_header)
    header_add(htype_old, "X-rewrote-%s: %s\n", name, subject);

  /* Handle the case when replacement of the whole address is possible.
  This happens only when whole is not NULL and we are rewriting a header.
  If *whole is already TRUE it means that a previous rule had the w
  flag set and so we must preserve the non-active portion of the current
  subject unless the current rule also has the w flag set. */

  if (whole != NULL && (flag & rewrite_all_headers) != 0)
    {
    /* Current rule has the w flag set. We must ensure the phrase parts
    are syntactically valid if they are present. */

    if ((rule->flags & rewrite_whole) != 0)
      {
      if (start > 0 && new[start-1] == '<')
        {
        uschar *p1 = new + start - 1;
        uschar *p2 = new + end + 1;
        const uschar *pf1, *pf2;
        uschar buff1[256], buff2[256];

        while (p1 > new && p1[-1] == ' ') p1--;
        pf1 = parse_fix_phrase(new, p1 - new, buff1, sizeof(buff1));
        while (*p2 == ' ') p2++;
        pf2 = parse_fix_phrase(p2, Ustrlen(p2), buff2, sizeof(buff2));

        /* Note that pf1 and pf2 are NOT necessarily buff1 and buff2. For
        a non-RFC 2047 phrase that does not need to be RFC 2822 quoted, they
        will be buff1+1 and buff2+1. */

        start = Ustrlen(pf1) + start + new - p1;
        end = start + Ustrlen(newparsed);
        new = string_sprintf("%s%.*s%s", pf1, (int)(p2 - p1), p1, pf2);
        }

      /* Now accept the whole thing */

      yield = new;
      yield_start = start;
      yield_end = end;
      subject = newparsed;
      *whole = TRUE;
      }

    /* Current rule does not have the w flag set; if not previously
    done any whole rewriting, behave in non-whole manner. */

    else if (!*whole) goto NEVER_WHOLE;

    /* Current rule does not have the w flag set, but a previous
    rule did rewrite the whole address. Thus yield and subject will be
    different. Preserve the previous non-active part of the address. */

    else
      {
      subject = newparsed;
      new = string_sprintf("%.*s%s%n%s",
         yield_start, yield, subject, &end, yield + yield_end);
      yield_end = end;
      yield = new;
      }
    }

  /* Rule just rewrites active part, or handling an envelope. This
  code is obeyed only when all rules so far have not done "whole"
  replacement. */

  else
    {
    NEVER_WHOLE:
    subject = yield = newparsed;
    }

  domain = NULL;    /* Reset for next rule */

  /* If no further rewrites are to be done, set the done flag. This allows
  repeats of the current rule if configured before breaking the loop. */

  if ((rule->flags & rewrite_quit) != 0) done = TRUE;

  /* Allow the current rule to be applied up to 10 times if
  requested. */

  if ((rule->flags & rewrite_repeat) != 0)
    {
    if (count++ < 10) goto REPEAT_RULE;
    log_write(0, LOG_MAIN|LOG_PANIC, "rewrite rule repeat ignored after 10 "
      "times");
    }
  }

/* Unset expansion numeric variables, and that's it. */

expand_nmax = -1;
return yield;
}



/*************************************************
*         Ensure qualification and rewrite       *
*************************************************/

/* This function is called for envelope addresses, the boolean specifying
whether a recipient or a sender. It must first of all ensure the address is
fully qualified, and then apply any relevant re-writing rules. The add-header
flag causes a header to be added, recording the old address. This is marked
"old", so that it is never transported anywhere; it exists for local checking
and debugging purposes.

Arguments:
  s              the address to be considered
  is_recipient   TRUE for recipient addresses; FALSE otherwise
  add_header     add "X-rewrote-xxx" header when rewriting; this is
                   set TRUE only for calls from the reception functions
  rewrite_rules  points to chain of rewrite rules
  existflags     bits indicating which headers there are rewrites for
                 (just an optimisation)

Returns:         possibly rewritten address
*/

uschar *
rewrite_address(uschar *s, BOOL is_recipient, BOOL add_header,
  rewrite_rule *rewrite_rules, int existflags)
{
int flag = is_recipient? rewrite_envto : rewrite_envfrom;
s = rewrite_address_qualify(s, is_recipient);
if ((existflags & flag) != 0)
  {
  uschar *new = rewrite_one(s, flag, NULL, add_header, is_recipient?
    US"original-recipient" : US"sender", rewrite_rules);
  if (new != s) s = new;
  }
return s;
}



/*************************************************
*    Qualify and possibly rewrite one header     *
*************************************************/

/* This is called only from rewrite_header() below, either when reading a
message. or when routing, in order to rewrite addresses that get changed by a
router. This is normally the addition of full qualification to a partial
domain. The first rewriting rule in this case is "change routed_old into
routed_new", and it applies to all header lines that contain addresses. Then
header-specific rewriting rules are applied.

Before rewriting can be done, addresses without domains have to be qualified.
This should only be done for messages from "local" senders. This is a difficult
concept to pin down, what with the use of SMTP both as a submission and as a
transmission protocol. Exim normally requires incoming SMTP to contain fully-
qualified addresses, but there are options to permit unqualified ones from
certain hosts. For those hosts only, addresses in headers can also be
qualified. For other hosts, unqualified addresses in headers do not get touched
in any way. For locally sourced messages, unqualified addresses always get
qualified, except when -bnq is used to explicitly suppress this.

Arguments:
  h              pointer to header line block
  flag           indicates which header this is
  routed_old     if not NULL, this is a rewrite caused by a router, changing
                   this domain into routed_new
  routed_new     new routed domain if routed_old is not NULL
  rewrite_rules  points to chain of rewriting rules
  existflags     bits indicating which rewrites exist
  replace        if TRUE, insert the new header in the chain after the old
                   one, and mark the old one "replaced"

Returns:         NULL if header unchanged; otherwise the rewritten header
*/

static header_line *
rewrite_one_header(header_line *h, int flag,
  const uschar *routed_old, const uschar *routed_new,
  rewrite_rule *rewrite_rules, int existflags, BOOL replace)
{
int lastnewline = 0;
header_line *newh = NULL;
void *function_reset_point = store_get(0);
uschar *s = Ustrchr(h->text, ':') + 1;
while (isspace(*s)) s++;

DEBUG(D_rewrite)
  debug_printf("rewrite_one_header: type=%c:\n  %s", h->type, h->text);

f.parse_allow_group = TRUE;     /* Allow group syntax */

/* Loop for multiple addresses in the header. We have to go through them all
in case any need qualifying, even if there's no rewriting. Pathological headers
may have thousands of addresses in them, so cause the store to be reset for
any that don't actually get rewritten. We also play silly games for those that
_are_ rewritten so as to avoid runaway store usage for these kinds of header.
We want to avoid keeping store for any intermediate versions. */

while (*s != 0)
  {
  uschar *sprev;
  uschar *ss = parse_find_address_end(s, FALSE);
  uschar *recipient, *new, *errmess;
  void *loop_reset_point = store_get(0);
  BOOL changed = FALSE;
  int terminator = *ss;
  int start, end, domain;

  /* Temporarily terminate the string at this point, and extract the
  operative address within. Then put back the terminator and prepare for
  the next address, saving the start of the old one. */

  *ss = 0;
  recipient = parse_extract_address(s,&errmess,&start,&end,&domain,FALSE);
  *ss = terminator;
  sprev = s;
  s = ss + (terminator? 1:0);
  while (isspace(*s)) s++;

  /* There isn't much we can do for syntactic disasters at this stage.
  Pro tem (possibly for ever) ignore them. */

  if (recipient == NULL)
    {
    store_reset(loop_reset_point);
    continue;
    }

  /* If routed_old is not NULL, this is a rewrite caused by a router,
  consisting of changing routed_old into routed_new, and applying to all
  headers. If the header address has no domain, it is excluded, since a router
  rewrite affects domains only. The new value should always be fully qualified,
  but it may be something that has an explicit re-write rule set, so we need to
  check the configured rules subsequently as well. (Example: there's an
  explicit rewrite turning *.foo.com into foo.com, and an address is supplied
  as abc@xyz, which the DNS lookup turns into abc@xyz.foo.com). However, if no
  change is made here, don't bother carrying on. */

  if (routed_old != NULL)
    {
    if (domain <= 0 || strcmpic(recipient+domain, routed_old) != 0) continue;
    recipient[domain-1] = 0;
    new = string_sprintf("%s@%s", recipient, routed_new);
    DEBUG(D_rewrite)
      {
      recipient[domain-1] = '@';
      debug_printf("%s rewritten by router as %s\n", recipient, new);
      }
    recipient = new;
    changed = TRUE;
    }

  /* This is not a router-inspired rewrite. Ensure the address is fully
  qualified if that is permitted. If an unqualified address was received
  from a host that isn't listed, do not continue rewriting this address.
  Sender, From or Reply-To headers are treated as senders, the rest as
  recipients. This matters only when there are different qualify strings. */

  else
    {
    BOOL is_recipient =
      (flag & (rewrite_sender | rewrite_from | rewrite_replyto)) == 0;
    new = rewrite_address_qualify(recipient, is_recipient);
    changed = (new != recipient);
    recipient = new;

    /* Can only qualify if permitted; if not, no rewrite. */

    if (changed && ((is_recipient && !f.allow_unqualified_recipient) ||
                    (!is_recipient && !f.allow_unqualified_sender)))
      {
      store_reset(loop_reset_point);
      continue;
      }
    }

  /* If there are rewrite rules for this type of header, apply
  them. This test is just for efficiency, to save scanning the rules
  in cases when nothing is going to change. If any rewrite rule had the
  "whole" flag set, adjust the pointers so that the whole address gets
  replaced, except possibly a final \n. */

  if ((existflags & flag) != 0)
    {
    BOOL whole;
    new = rewrite_one(recipient, flag, &whole, FALSE, NULL, rewrite_rules);
    if (new != recipient)
      {
      changed = TRUE;
      if (whole)
        {
        start = 0;
        end = ss - sprev;
        if (sprev[end-1] == '\n') end--;
        }
      }
    }

  /* If nothing has changed, lose all dynamic store obtained in this loop, and
  move on to the next address. We can't reset to the function start store
  point, because we may have a rewritten line from a previous time round the
  loop. */

  if (!changed) store_reset(loop_reset_point);

  /* If the address has changed, create a new header containing the
  rewritten address. We do not need to set the chain pointers at this
  stage. We want to avoid using more and more memory if the header is very long
  and contains lots and lots of rewritten addresses. Therefore, we build the
  new text string in malloc store, then at the end we reset dynamic store
  before copying the new header to a new block (and then freeing the malloc
  block). The header must end up in dynamic store so that it's freed at the end
  of receiving a message. */

  else
    {
    int remlen;
    int newlen = Ustrlen(new);
    int oldlen = end - start;

    header_line *prev = (newh == NULL)? h : newh;
    uschar *newt = store_malloc(prev->slen - oldlen + newlen + 4);
    uschar *newtstart = newt;

    int type = prev->type;
    int slen = prev->slen - oldlen + newlen;

    /* Build the new header text by copying the old and putting in the
    replacement. This process may make the header substantially longer
    than it was before - qualification of a list of bare addresses can
    often do this - so we stick in a newline after the re-written address
    if it has increased in length and ends more than 40 characters in. In
    fact, the code is not perfect, since it does not scan for existing
    newlines in the header, but it doesn't seem worth going to that
    amount of trouble. */

    Ustrncpy(newt, prev->text, sprev - prev->text + start);
    newt += sprev - prev->text + start;
    *newt = 0;
    Ustrcat(newt, new);
    newt += newlen;
    remlen = s - (sprev + end);
    if (remlen > 0)
      {
      Ustrncpy(newt, sprev + end, remlen);
      newt += remlen;
      *newt = 0;
      }

    /* Must check that there isn't a newline here anyway; in particular, there
    will be one at the very end of the header, where we DON'T want to insert
    another one! The pointer s has been skipped over white space, so just
    look back to see if the last non-space-or-tab was a newline. */

    if (newlen > oldlen && newt - newtstart - lastnewline > 40)
      {
      uschar *p = s - 1;
      while (p >= prev->text && (*p == ' ' || *p == '\t')) p--;
      if (*p != '\n')
        {
        lastnewline = newt - newtstart;
        Ustrcat(newt, "\n\t");
        slen += 2;
        }
      }

    /* Finally, the remaining unprocessed addresses, if any. */

    Ustrcat(newt, s);

    DEBUG(D_rewrite) debug_printf("newlen=%d newtype=%c newtext:\n%s",
      slen, type, newtstart);

    /* Compute the length of the rest of the header line before we possibly
    flatten a previously rewritten copy. */

    remlen = (s - prev->text) - oldlen + newlen;

    /* We have the new text in a malloc block. That enables us to release all
    the memory that has been used, back to the point at which the function was
    entered. Then set up a new header in dynamic store. This will override a
    rewritten copy from a previous time round this loop. */

    store_reset(function_reset_point);
    newh = store_get(sizeof(header_line));
    newh->type = type;
    newh->slen = slen;
    newh->text = string_copyn(newtstart, slen);
    store_free(newtstart);

    /* Set up for scanning the rest of the header */

    s = newh->text + remlen;
    DEBUG(D_rewrite) debug_printf("remainder: %s", (*s == 0)? US"\n" : s);
    }
  }

f.parse_allow_group = FALSE;  /* Reset group flags */
f.parse_found_group = FALSE;

/* If a rewrite happened and "replace" is true, put the new header into the
chain following the old one, and mark the old one as replaced. */

if (newh != NULL && replace)
  {
  newh->next = h->next;
  if (newh->next == NULL) header_last = newh;
  h->type = htype_old;
  h->next = newh;
  }

return newh;
}




/*************************************************
*              Rewrite a header line             *
*************************************************/

/* This function may be passed any old header line. It must detect those which
contain addresses, then then apply any rewriting rules that apply. If
routed_old is NULL, only the configured rewriting rules are consulted.
Otherwise, the rewriting rule is "change routed_old into routed_new", and it
applies to all header lines that contain addresses. Then header-specific
rewriting rules are applied.

The old header line is flagged as "old". Old headers are saved on the spool for
debugging but are never sent to any recipients.

Arguments:
  h              header line to rewrite
  routed_old     if not NULL, this is a rewrite caused by a router, changing
                   this domain into routed_new
  routed_new     new routed domain if routed_old is not NULL
  rewrite_rules  points to chain of rewrite rules
  existflags     bits indicating which rewrites exist
  replace        if TRUE, the new header is inserted into the header chain
                    after the old one, and the old one is marked replaced

Returns:         NULL if header unchanged; otherwise the rewritten header
*/

header_line *
rewrite_header(header_line *h,
  const uschar *routed_old, const uschar *routed_new,
  rewrite_rule *rewrite_rules, int existflags, BOOL replace)
{
switch (h->type)
  {
  case htype_sender:
  return rewrite_one_header(h, rewrite_sender, routed_old, routed_new,
    rewrite_rules, existflags, replace);

  case htype_from:
  return rewrite_one_header(h, rewrite_from, routed_old, routed_new,
    rewrite_rules, existflags, replace);

  case htype_to:
  return rewrite_one_header(h, rewrite_to, routed_old, routed_new,
    rewrite_rules, existflags, replace);

  case htype_cc:
  return rewrite_one_header(h, rewrite_cc, routed_old, routed_new,
    rewrite_rules, existflags, replace);

  case htype_bcc:
  return rewrite_one_header(h, rewrite_bcc, routed_old, routed_new,
    rewrite_rules, existflags, replace);

  case htype_reply_to:
  return rewrite_one_header(h, rewrite_replyto, routed_old, routed_new,
    rewrite_rules, existflags, replace);
  }

return NULL;
}



/************************************************
*            Test rewriting rules               *
************************************************/

/* Called from the mainline as a result of the -brw option. Test the
address for all possible cases.

Argument: the address to test
Returns:  nothing
*/

void rewrite_test(uschar *s)
{
uschar *recipient, *error;
int i, start, end, domain;
BOOL done_smtp = FALSE;

if (rewrite_existflags == 0)
  {
  printf("No rewrite rules are defined\n");
  return;
  }

/* Do SMTP rewrite only if a rule with the S flag exists. Allow <> by
pretending it is a sender. */

if ((rewrite_existflags & rewrite_smtp) != 0)
  {
  uschar *new = rewrite_one(s, rewrite_smtp|rewrite_smtp_sender, NULL, FALSE,
    US"", global_rewrite_rules);
  if (new != s)
    {
    if (*new == 0)
      printf("    SMTP: <>\n");
    else
      printf("    SMTP: %s\n", new);
    done_smtp = TRUE;
    }
  }

/* Do the other rewrites only if a rule without the S flag exists */

if ((rewrite_existflags & ~rewrite_smtp) == 0) return;

/* Qualify if necessary before extracting the address */

if (parse_find_at(s) == NULL)
  s = string_sprintf("%s@%s", s, qualify_domain_recipient);

recipient = parse_extract_address(s, &error, &start, &end, &domain, FALSE);

if (recipient == NULL)
  {
  if (!done_smtp)
    printf("Syntax error in %s\n%c%s\n", s, toupper(error[0]), error+1);
  return;
  }

for (i = 0; i < 8; i++)
  {
  BOOL whole = FALSE;
  int flag = 1 << i;
  uschar *new = rewrite_one(recipient, flag, &whole, FALSE, US"",
    global_rewrite_rules);
  printf("%s: ", rrname[i]);
  if (*new == 0)
    printf("<>\n");
  else if (whole || (flag & rewrite_all_headers) == 0)
    printf("%s\n", CS new);
  else printf("%.*s%s%s\n", start, s, new, s+end);
  }
}

/* End of rewrite.c */
