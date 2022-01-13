/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "rf_functions.h"
#include "redirect.h"



/* Options specific to the redirect router. */

optionlist redirect_router_options[] = {
  { "allow_defer",        opt_bit | (RDON_DEFER << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "allow_fail",         opt_bit | (RDON_FAIL << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "allow_filter",       opt_bit | (RDON_FILTER << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "allow_freeze",       opt_bit | (RDON_FREEZE << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "check_ancestor",     opt_bool,
      (void *)offsetof(redirect_router_options_block, check_ancestor) },
  { "check_group",        opt_bool,
      (void *)offsetof(redirect_router_options_block, check_group) },
  { "check_owner",        opt_bool,
      (void *)offsetof(redirect_router_options_block, check_owner) },
  { "data",               opt_stringptr,
      (void *)offsetof(redirect_router_options_block, data) },
  { "directory_transport",opt_stringptr,
      (void *)offsetof(redirect_router_options_block, directory_transport_name) },
  { "file",               opt_stringptr,
      (void *)offsetof(redirect_router_options_block, file) },
  { "file_transport",     opt_stringptr,
      (void *)offsetof(redirect_router_options_block, file_transport_name) },
  { "filter_prepend_home",opt_bit | (RDON_PREPEND_HOME << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "forbid_blackhole",   opt_bit | (RDON_BLACKHOLE << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "forbid_exim_filter", opt_bit | (RDON_EXIM_FILTER << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "forbid_file",        opt_bool,
      (void *)offsetof(redirect_router_options_block, forbid_file) },
  { "forbid_filter_dlfunc", opt_bit | (RDON_DLFUNC << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "forbid_filter_existstest",  opt_bit | (RDON_EXISTS << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "forbid_filter_logwrite",opt_bit | (RDON_LOG << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "forbid_filter_lookup", opt_bit | (RDON_LOOKUP << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "forbid_filter_perl", opt_bit | (RDON_PERL << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "forbid_filter_readfile", opt_bit | (RDON_READFILE << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "forbid_filter_readsocket", opt_bit | (RDON_READSOCK << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "forbid_filter_reply",opt_bool,
      (void *)offsetof(redirect_router_options_block, forbid_filter_reply) },
  { "forbid_filter_run",  opt_bit | (RDON_RUN << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "forbid_include",     opt_bit | (RDON_INCLUDE << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "forbid_pipe",        opt_bool,
      (void *)offsetof(redirect_router_options_block, forbid_pipe) },
  { "forbid_sieve_filter",opt_bit | (RDON_SIEVE_FILTER << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "forbid_smtp_code",     opt_bool,
      (void *)offsetof(redirect_router_options_block, forbid_smtp_code) },
  { "hide_child_in_errmsg", opt_bool,
      (void *)offsetof(redirect_router_options_block,  hide_child_in_errmsg) },
  { "ignore_eacces",      opt_bit | (RDON_EACCES << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "ignore_enotdir",     opt_bit | (RDON_ENOTDIR << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "include_directory",  opt_stringptr,
      (void *)offsetof(redirect_router_options_block,  include_directory) },
  { "modemask",           opt_octint,
      (void *)offsetof(redirect_router_options_block, modemask) },
  { "one_time",           opt_bool,
      (void *)offsetof(redirect_router_options_block, one_time) },
  { "owners",             opt_uidlist,
      (void *)offsetof(redirect_router_options_block, owners) },
  { "owngroups",          opt_gidlist,
      (void *)offsetof(redirect_router_options_block, owngroups) },
  { "pipe_transport",     opt_stringptr,
      (void *)offsetof(redirect_router_options_block, pipe_transport_name) },
  { "qualify_domain",     opt_stringptr,
      (void *)offsetof(redirect_router_options_block, qualify_domain) },
  { "qualify_preserve_domain", opt_bool,
      (void *)offsetof(redirect_router_options_block, qualify_preserve_domain) },
  { "repeat_use",         opt_bool | opt_public,
      (void *)offsetof(router_instance, repeat_use) },
  { "reply_transport",    opt_stringptr,
      (void *)offsetof(redirect_router_options_block, reply_transport_name) },
  { "rewrite",            opt_bit | (RDON_REWRITE << 16),
      (void *)offsetof(redirect_router_options_block, bit_options) },
  { "sieve_enotify_mailto_owner", opt_stringptr,
      (void *)offsetof(redirect_router_options_block, sieve_enotify_mailto_owner) },
  { "sieve_subaddress", opt_stringptr,
      (void *)offsetof(redirect_router_options_block, sieve_subaddress) },
  { "sieve_useraddress", opt_stringptr,
      (void *)offsetof(redirect_router_options_block, sieve_useraddress) },
  { "sieve_vacation_directory", opt_stringptr,
      (void *)offsetof(redirect_router_options_block, sieve_vacation_directory) },
  { "skip_syntax_errors", opt_bool,
      (void *)offsetof(redirect_router_options_block, skip_syntax_errors) },
#ifdef EXPERIMENTAL_SRS
  { "srs",                opt_stringptr,
      (void *)offsetof(redirect_router_options_block, srs) },
  { "srs_alias",          opt_stringptr,
      (void *)offsetof(redirect_router_options_block, srs_alias) },
  { "srs_condition",      opt_stringptr,
      (void *)offsetof(redirect_router_options_block, srs_condition) },
  { "srs_dbinsert",       opt_stringptr,
      (void *)offsetof(redirect_router_options_block, srs_dbinsert) },
  { "srs_dbselect",       opt_stringptr,
      (void *)offsetof(redirect_router_options_block, srs_dbselect) },
#endif
  { "syntax_errors_text", opt_stringptr,
      (void *)offsetof(redirect_router_options_block, syntax_errors_text) },
  { "syntax_errors_to",   opt_stringptr,
      (void *)offsetof(redirect_router_options_block, syntax_errors_to) }
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int redirect_router_options_count =
  sizeof(redirect_router_options)/sizeof(optionlist);


#ifdef MACRO_PREDEF

/* Dummy entries */
redirect_router_options_block redirect_router_option_defaults = {0};
void redirect_router_init(router_instance *rblock) {}
int redirect_router_entry(router_instance *rblock, address_item *addr,
  struct passwd *pw, int verify, address_item **addr_local,
  address_item **addr_remote, address_item **addr_new,
  address_item **addr_succeed) {return 0;}

#else   /*!MACRO_PREDEF*/



/* Default private options block for the redirect router. */

redirect_router_options_block redirect_router_option_defaults = {
  NULL,        /* directory_transport */
  NULL,        /* file_transport */
  NULL,        /* pipe_transport */
  NULL,        /* reply_transport */
  NULL,        /* data */
  NULL,        /* directory_transport_name */
  NULL,        /* file */
  NULL,        /* file_dir */
  NULL,        /* file_transport_name */
  NULL,        /* include_directory */
  NULL,        /* pipe_transport_name */
  NULL,        /* reply_transport_name */
  NULL,        /* sieve_subaddress */
  NULL,        /* sieve_useraddress */
  NULL,        /* sieve_vacation_directory */
  NULL,        /* sieve_enotify_mailto_owner */
  NULL,        /* syntax_errors_text */
  NULL,        /* syntax_errors_to */
  NULL,        /* qualify_domain */
  NULL,        /* owners */
  NULL,        /* owngroups */
#ifdef EXPERIMENTAL_SRS
  NULL,        /* srs */
  NULL,        /* srs_alias */
  NULL,        /* srs_condition */
  NULL,        /* srs_dbinsert */
  NULL,        /* srs_dbselect */
#endif
  022,         /* modemask */
  RDO_REWRITE | RDO_PREPEND_HOME, /* bit_options */
  FALSE,       /* check_ancestor */
  TRUE_UNSET,  /* check_owner */
  TRUE_UNSET,  /* check_group */
  FALSE,       /* forbid_file */
  FALSE,       /* forbid_filter_reply */
  FALSE,       /* forbid_pipe */
  FALSE,       /* forbid_smtp_code */
  FALSE,       /* hide_child_in_errmsg */
  FALSE,       /* one_time */
  FALSE,       /* qualify_preserve_domain */
  FALSE        /* skip_syntax_errors */
};



/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to enable
consistency checks to be done, or anything else that needs to be set up. */

void redirect_router_init(router_instance *rblock)
{
redirect_router_options_block *ob =
  (redirect_router_options_block *)(rblock->options_block);

/* Either file or data must be set, but not both */

if ((ob->file == NULL) == (ob->data == NULL))
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s router:\n  "
    "%sone of \"file\" or \"data\" must be specified",
    rblock->name, (ob->file == NULL)? "" : "only ");

/* Onetime aliases can only be real addresses. Headers can't be manipulated.
The combination of one_time and unseen is not allowed. We can't check the
expansion of "unseen" here, but we assume that if it is set to anything other
than false, there is likely to be a problem. */

if (ob->one_time)
  {
  ob->forbid_pipe = ob->forbid_file = ob->forbid_filter_reply = TRUE;
  if (rblock->extra_headers || rblock->remove_headers)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s router:\n  "
      "\"headers_add\" and \"headers_remove\" are not permitted with "
      "\"one_time\"", rblock->name);
  if (rblock->unseen || rblock->expand_unseen)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s router:\n  "
      "\"unseen\" may not be used with \"one_time\"", rblock->name);
  }

/* The defaults for check_owner and check_group depend on other settings. The
defaults are: Check the owner if check_local_user or owners is set; check the
group if check_local_user is set without a restriction on the group write bit,
or if owngroups is set. */

if (ob->check_owner == TRUE_UNSET)
  ob->check_owner = rblock->check_local_user ||
                    (ob->owners && ob->owners[0] != 0);

if (ob->check_group == TRUE_UNSET)
  ob->check_group = (rblock->check_local_user && (ob->modemask & 020) == 0) ||
                    (ob->owngroups != NULL && ob->owngroups[0] != 0);

/* If explicit qualify domain set, the preserve option is locked out */

if (ob->qualify_domain && ob->qualify_preserve_domain)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s router:\n  "
    "only one of \"qualify_domain\" or \"qualify_preserve_domain\" must be set",
    rblock->name);

/* If allow_filter is set, either user or check_local_user must be set. */

if (!rblock->check_local_user &&
    !rblock->uid_set &&
    rblock->expand_uid == NULL &&
    (ob->bit_options & RDO_FILTER) != 0)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s router:\n  "
    "\"user\" or \"check_local_user\" must be set with \"allow_filter\"",
    rblock->name);
}



/*************************************************
*       Get errors address and header mods       *
*************************************************/

/* This function is called when new addresses are generated, in order to
sort out errors address and header modifications. We put the errors address
into the parent address (even though it is never used from there because that
address is never transported) so that it can be retrieved if any of the
children gets routed by an "unseen" router. The clone of the child that is
passed on must have the original errors_address value.

Arguments:
  rblock               the router control block
  addr                 the address being routed
  verify               v_none/v_recipient/v_sender/v_expn
  addr_prop            point to the propagated block, which is where the
                         new values are to be placed

Returns:    the result of rf_get_errors_address() or rf_get_munge_headers(),
            which is either OK or DEFER
*/

static int
sort_errors_and_headers(router_instance *rblock, address_item *addr,
  int verify, address_item_propagated *addr_prop)
{
int frc = rf_get_errors_address(addr, rblock, verify,
  &addr_prop->errors_address);
if (frc != OK) return frc;
addr->prop.errors_address = addr_prop->errors_address;
return rf_get_munge_headers(addr, rblock, &addr_prop->extra_headers,
  &addr_prop->remove_headers);
}



/*************************************************
*    Process a set of generated new addresses    *
*************************************************/

/* This function sets up a set of newly generated child addresses and puts them
on the new address chain. Copy in the uid, gid and permission flags for use by
pipes and files, set the parent, and "or" its af_ignore_error flag. Also record
the setting for any starting router.

If the generated address is the same as one of its ancestors, and the
check_ancestor flag is set, do not use this generated address, but replace it
with a copy of the input address. This is to cope with cases where A is aliased
to B and B has a .forward file pointing to A, though it is usually set on the
forwardfile rather than the aliasfile. We can't just pass on the old
address by returning FAIL, because it must act as a general parent for
generated addresses, and only get marked "done" when all its children are
delivered.

Arguments:
  rblock                  router block
  addr_new                new address chain
  addr                    original address
  generated               list of generated addresses
  addr_prop               the propagated block, containing the errors_address,
                            header modification stuff, and address_data
  ugidptr                 points to uid/gid data for files, pipes, autoreplies
  pw                      password entry, set if ob->check_local_user is TRUE

Returns:         nothing
*/

static void
add_generated(router_instance *rblock, address_item **addr_new,
  address_item *addr, address_item *generated,
  address_item_propagated *addr_prop, ugid_block *ugidptr, struct passwd *pw)
{
redirect_router_options_block *ob =
  (redirect_router_options_block *)(rblock->options_block);

while (generated)
  {
  address_item *parent;
  address_item *next = generated;
  uschar *errors_address = next->prop.errors_address;

  generated = next->next;
  next->parent = addr;
  next->start_router = rblock->redirect_router;
  if (addr->child_count == USHRT_MAX)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "%s router generated more than %d "
      "child addresses for <%s>", rblock->name, USHRT_MAX, addr->address);
  addr->child_count++;

  next->next = *addr_new;
  *addr_new = next;

  /* Don't do the "one_time" thing for the first pass of a 2-stage queue run. */

  if (ob->one_time && !f.queue_2stage)
    {
    for (parent = addr; parent->parent; parent = parent->parent) ;
    next->onetime_parent = parent->address;
    }

  if (ob->hide_child_in_errmsg) setflag(next, af_hide_child);

  /* If check_ancestor is set, we want to know if any ancestor of this address
  is the address we are about to generate. The check must be done caselessly
  unless the ancestor was routed by a case-sensitive router. */

  if (ob->check_ancestor)
    for (parent = addr; parent; parent = parent->parent)
      if ((parent->router && parent->router->caseful_local_part
	   ? Ustrcmp(next->address, parent->address)
           : strcmpic(next->address, parent->address)
          ) == 0)
        {
        DEBUG(D_route) debug_printf("generated parent replaced by child\n");
        next->address = string_copy(addr->address);
        break;
        }

  /* A user filter may, under some circumstances, set up an errors address.
  If so, we must take care to re-instate it when we copy in the propagated
  data so that it overrides any errors_to setting on the router. */

    {
    BOOL ignore_error = next->prop.ignore_error;
    next->prop = *addr_prop;
    next->prop.ignore_error = ignore_error || addr->prop.ignore_error;
    }
  if (errors_address) next->prop.errors_address = errors_address;

  /* For pipes, files, and autoreplies, record this router as handling them,
  because they don't go through the routing process again. Then set up uid,
  gid, home and current directories for transporting. */

  if (testflag(next, af_pfr))
    {
    next->router = rblock;
    rf_set_ugid(next, ugidptr);   /* Will contain pw values if not overridden */

    /* When getting the home directory out of the password information, wrap it
    in \N...\N to avoid expansion later. In Cygwin, home directories can
    contain $ characters. */

    if (rblock->home_directory != NULL)
      next->home_dir = rblock->home_directory;
    else if (rblock->check_local_user)
      next->home_dir = string_sprintf("\\N%s\\N", pw->pw_dir);
    else if (rblock->router_home_directory != NULL &&
             testflag(addr, af_home_expanded))
      {
      next->home_dir = deliver_home;
      setflag(next, af_home_expanded);
      }

    next->current_dir = rblock->current_directory;

    /* Permission options */

    if (!ob->forbid_pipe) setflag(next, af_allow_pipe);
    if (!ob->forbid_file) setflag(next, af_allow_file);
    if (!ob->forbid_filter_reply) setflag(next, af_allow_reply);

    /* If the transport setting fails, the error gets picked up at the outer
    level from the setting of basic_errno in the address. */

    if (next->address[0] == '|')
      {
      address_pipe = next->address;
      if (rf_get_transport(ob->pipe_transport_name, &(ob->pipe_transport),
          next, rblock->name, US"pipe_transport"))
        next->transport = ob->pipe_transport;
      address_pipe = NULL;
      }
    else if (next->address[0] == '>')
      {
      if (rf_get_transport(ob->reply_transport_name, &(ob->reply_transport),
          next, rblock->name, US"reply_transport"))
        next->transport = ob->reply_transport;
      }
    else  /* must be file or directory */
      {
      int len = Ustrlen(next->address);
      address_file = next->address;
      if (next->address[len-1] == '/')
        {
        if (rf_get_transport(ob->directory_transport_name,
            &(ob->directory_transport), next, rblock->name,
            US"directory_transport"))
          next->transport = ob->directory_transport;
        }
      else
        {
        if (rf_get_transport(ob->file_transport_name, &(ob->file_transport),
            next, rblock->name, US"file_transport"))
          next->transport = ob->file_transport;
        }
      address_file = NULL;
      }
    }

#ifdef SUPPORT_I18N
    if (!next->prop.utf8_msg)
      next->prop.utf8_msg = string_is_utf8(next->address)
        || (sender_address && string_is_utf8(sender_address));
#endif

  DEBUG(D_route)
    {
    debug_printf("%s router generated %s\n  %serrors_to=%s transport=%s\n",
      rblock->name,
      next->address,
      testflag(next, af_pfr)? "pipe, file, or autoreply\n  " : "",
      next->prop.errors_address,
      (next->transport == NULL)? US"NULL" : next->transport->name);

    if (testflag(next, af_uid_set))
      debug_printf("  uid=%ld ", (long int)(next->uid));
    else
      debug_printf("  uid=unset ");

    if (testflag(next, af_gid_set))
      debug_printf("gid=%ld ", (long int)(next->gid));
    else
      debug_printf("gid=unset ");

#ifdef SUPPORT_I18N
    if (next->prop.utf8_msg) debug_printf("utf8 ");
#endif

    debug_printf("home=%s\n", next->home_dir);
    }
  }
}


/*************************************************
*              Main entry point                  *
*************************************************/

/* See local README for interface description. This router returns:

DECLINE
  . empty address list, or filter did nothing significant

DEFER
  . verifying the errors address caused a deferment or a big disaster such
      as an expansion failure (rf_get_errors_address)
  . expanding a headers_{add,remove} string caused a deferment or another
      expansion error (rf_get_munge_headers)
  . :defer: or "freeze" in a filter
  . error in address list or filter
  . skipped syntax errors, but failed to send the message

DISCARD
  . address was :blackhole:d or "seen finish"ed

FAIL
  . :fail:

OK
  . new addresses added to addr_new
*/

int redirect_router_entry(
  router_instance *rblock,        /* data for this instantiation */
  address_item *addr,             /* address we are working on */
  struct passwd *pw,              /* passwd entry after check_local_user */
  int verify,                     /* v_none/v_recipient/v_sender/v_expn */
  address_item **addr_local,      /* add it to this if it's local */
  address_item **addr_remote,     /* add it to this if it's remote */
  address_item **addr_new,        /* put new addresses on here */
  address_item **addr_succeed)    /* put old address here on success */
{
redirect_router_options_block *ob =
  (redirect_router_options_block *)(rblock->options_block);
address_item *generated = NULL;
const uschar *save_qualify_domain_recipient = qualify_domain_recipient;
uschar *discarded = US"discarded";
address_item_propagated addr_prop;
error_block *eblock = NULL;
ugid_block ugid;
redirect_block redirect;
int filtertype = FILTER_UNSET;
int yield = OK;
int options = ob->bit_options;
int frc = 0;
int xrc = 0;

addr_local = addr_local;     /* Keep picky compilers happy */
addr_remote = addr_remote;

/* Initialize the data to be propagated to the children */

addr_prop.address_data = deliver_address_data;
addr_prop.domain_data = deliver_domain_data;
addr_prop.localpart_data = deliver_localpart_data;
addr_prop.errors_address = NULL;
addr_prop.extra_headers = NULL;
addr_prop.remove_headers = NULL;

#ifdef EXPERIMENTAL_SRS
addr_prop.srs_sender = NULL;
#endif
#ifdef SUPPORT_I18N
addr_prop.utf8_msg = addr->prop.utf8_msg;
addr_prop.utf8_downcvt = addr->prop.utf8_downcvt;
addr_prop.utf8_downcvt_maybe = addr->prop.utf8_downcvt_maybe;
#endif


/* When verifying and testing addresses, the "logwrite" command in filters
must be bypassed. */

if (verify == v_none && !f.address_test_mode) options |= RDO_REALLOG;

/* Sort out the fixed or dynamic uid/gid. This uid is used (a) for reading the
file (and interpreting a filter) and (b) for running the transports for
generated file and pipe addresses. It is not (necessarily) the same as the uids
that may own the file. Exim panics if an expanded string is not a number and
can't be found in the password file. Other errors set the freezing bit. */

if (!rf_get_ugid(rblock, addr, &ugid)) return DEFER;

if (!ugid.uid_set && pw != NULL)
  {
  ugid.uid = pw->pw_uid;
  ugid.uid_set = TRUE;
  }

if (!ugid.gid_set && pw != NULL)
  {
  ugid.gid = pw->pw_gid;
  ugid.gid_set = TRUE;
  }

#ifdef EXPERIMENTAL_SRS
  /* Perform SRS on recipient/return-path as required  */

  if(ob->srs != NULL)
  {
    BOOL usesrs = TRUE;

    if(ob->srs_condition != NULL)
      usesrs = expand_check_condition(ob->srs_condition, "srs_condition expansion failed", NULL);

    if(usesrs)
    {
      int srs_action = 0, n_srs;
      uschar *res;
      uschar *usedomain;

      /* What are we doing? */
      if(Ustrcmp(ob->srs, "forward") == 0)
        srs_action = 1;
      else if(Ustrcmp(ob->srs, "reverseandforward") == 0)
      {
        srs_action = 3;

        if((ob->srs_dbinsert == NULL) ^ (ob->srs_dbselect == NULL))
          return DEFER;
      }
      else if(Ustrcmp(ob->srs, "reverse") == 0)
        srs_action = 2;

      /* Reverse SRS */
      if(srs_action & 2)
      {
        srs_orig_recipient = addr->address;

        eximsrs_init();
        if(ob->srs_dbselect)
          eximsrs_db_set(TRUE, ob->srs_dbselect);
/* Comment this out for now...
//        else
//          eximsrs_db_set(TRUE, NULL);
*/

        if((n_srs = eximsrs_reverse(&res, addr->address)) == OK)
        {
          srs_recipient = res;
          DEBUG(D_any)
            debug_printf("SRS (reverse): Recipient '%s' rewritten to '%s'\n", srs_orig_recipient, srs_recipient);
        }

        eximsrs_done();

        if(n_srs != OK)
          return n_srs;
      }

      /* Forward SRS */
      /* No point in actually performing SRS if we are just verifying a recipient */
      if((srs_action & 1) && verify == v_none &&
         (sender_address ? sender_address[0] != 0 : FALSE))
      {

        srs_orig_sender = sender_address;
        eximsrs_init();
        if(ob->srs_dbinsert)
          eximsrs_db_set(FALSE, ob->srs_dbinsert);
/* Comment this out for now...
//        else
//          eximsrs_db_set(FALSE, NULL);
*/

        if (!(usedomain = ob->srs_alias ? expand_string(ob->srs_alias) : NULL))
          usedomain = string_copy(deliver_domain);

        if((n_srs = eximsrs_forward(&res, sender_address, usedomain)) == OK)
        {
          addr_prop.srs_sender = res;
          DEBUG(D_any)
            debug_printf("SRS (forward): Sender '%s' rewritten to '%s'\n", srs_orig_sender, res);
        }

        eximsrs_done();

        if(n_srs != OK)
          return n_srs;
      }
    }
  }
#endif

/* Call the function that interprets redirection data, either inline or from a
file. This is a separate function so that the system filter can use it. It will
run the function in a subprocess if necessary. If qualify_preserve_domain is
set, temporarily reset qualify_domain_recipient to the current domain so that
any unqualified addresses get qualified with the same domain as the incoming
address. Otherwise, if a local qualify_domain is provided, set that up. */

if (ob->qualify_preserve_domain)
  qualify_domain_recipient = addr->domain;
else if (ob->qualify_domain != NULL)
  {
  uschar *new_qdr = rf_expand_data(addr, ob->qualify_domain, &xrc);
  if (new_qdr == NULL) return xrc;
  qualify_domain_recipient = new_qdr;
  }

redirect.owners = ob->owners;
redirect.owngroups = ob->owngroups;
redirect.modemask = ob->modemask;
redirect.check_owner = ob->check_owner;
redirect.check_group = ob->check_group;
redirect.pw = pw;

if (ob->file != NULL)
  {
  redirect.string = ob->file;
  redirect.isfile = TRUE;
  }
else
  {
  redirect.string = ob->data;
  redirect.isfile = FALSE;
  }

frc = rda_interpret(&redirect, options, ob->include_directory,
  ob->sieve_vacation_directory, ob->sieve_enotify_mailto_owner,
  ob->sieve_useraddress, ob->sieve_subaddress, &ugid, &generated,
  &(addr->message), ob->skip_syntax_errors? &eblock : NULL, &filtertype,
  string_sprintf("%s router (recipient is %s)", rblock->name, addr->address));

qualify_domain_recipient = save_qualify_domain_recipient;

/* Handle exceptional returns from filtering or processing an address list.
For FAIL and FREEZE we honour any previously set up deliveries by a filter. */

switch (frc)
  {
  case FF_NONEXIST:
  addr->message = addr->user_message = NULL;
  return DECLINE;

  case FF_BLACKHOLE:
  DEBUG(D_route) debug_printf("address :blackhole:d\n");
  generated = NULL;
  discarded = US":blackhole:";
  frc = FF_DELIVERED;
  break;

  /* FF_DEFER and FF_FAIL can arise only as a result of explicit commands
  (:defer: or :fail: in an alias file or "fail" in a filter). If a configured
  message was supplied, allow it to be included in an SMTP response after
  verifying. Remove any SMTP code if it is not allowed. */

  case FF_DEFER:
  yield = DEFER;
  goto SORT_MESSAGE;

  case FF_FAIL:
  if ((xrc = sort_errors_and_headers(rblock, addr, verify, &addr_prop)) != OK)
    return xrc;
  add_generated(rblock, addr_new, addr, generated, &addr_prop, &ugid, pw);
  yield = FAIL;

  SORT_MESSAGE:
  if (addr->message == NULL)
    addr->message = (yield == FAIL)? US"forced rejection" : US"forced defer";
  else
    {
    int ovector[3];
    if (ob->forbid_smtp_code &&
        pcre_exec(regex_smtp_code, NULL, CS addr->message,
          Ustrlen(addr->message), 0, PCRE_EOPT,
          ovector, sizeof(ovector)/sizeof(int)) >= 0)
      {
      DEBUG(D_route) debug_printf("SMTP code at start of error message "
        "is ignored because forbid_smtp_code is set\n");
      addr->message += ovector[1];
      }
    addr->user_message = addr->message;
    setflag(addr, af_pass_message);
    }
  return yield;

  /* As in the case of a system filter, a freeze does not happen after a manual
  thaw. In case deliveries were set up by the filter, we set the child count
  high so that their completion does not mark the original address done. */

  case FF_FREEZE:
  if (!f.deliver_manual_thaw)
    {
    if ((xrc = sort_errors_and_headers(rblock, addr, verify, &addr_prop))
      != OK) return xrc;
    add_generated(rblock, addr_new, addr, generated, &addr_prop, &ugid, pw);
    if (addr->message == NULL) addr->message = US"frozen by filter";
    addr->special_action = SPECIAL_FREEZE;
    addr->child_count = 9999;
    return DEFER;
    }
  frc = FF_NOTDELIVERED;
  break;

  /* Handle syntax errors and :include: failures and lookup defers */

  case FF_ERROR:
  case FF_INCLUDEFAIL:

  /* If filtertype is still FILTER_UNSET, it means that the redirection data
  was never inspected, so the error was an expansion failure or failure to open
  the file, or whatever. In these cases, the existing error message is probably
  sufficient. */

  if (filtertype == FILTER_UNSET) return DEFER;

  /* If it was a filter and skip_syntax_errors is set, we want to set up
  the error message so that it can be logged and mailed to somebody. */

  if (filtertype != FILTER_FORWARD && ob->skip_syntax_errors)
    {
    eblock = store_get(sizeof(error_block));
    eblock->next = NULL;
    eblock->text1 = addr->message;
    eblock->text2 = NULL;
    addr->message = addr->user_message = NULL;
    }

  /* Otherwise set up the error for the address and defer. */

  else
    {
    addr->basic_errno = ERRNO_BADREDIRECT;
    addr->message = string_sprintf("error in %s %s: %s",
      (filtertype != FILTER_FORWARD)? "filter" : "redirect",
      (ob->data == NULL)? "file" : "data",
      addr->message);
    return DEFER;
    }
  }


/* Yield is either FF_DELIVERED (significant action) or FF_NOTDELIVERED (no
significant action). Before dealing with these, however, we must handle the
effect of skip_syntax_errors.

If skip_syntax_errors was set and there were syntax errors in an address list,
error messages will be present in eblock. Log them and send a message if so
configured. We cannot do this earlier, because the error message must not be
sent as the local user. If there were no valid addresses, generated will be
NULL. In this case, the router declines.

For a filter file, the error message has been fudged into an eblock. After
dealing with it, the router declines. */

if (eblock != NULL)
  {
  if (!moan_skipped_syntax_errors(
        rblock->name,                            /* For message content */
        eblock,                                  /* Ditto */
        (verify != v_none || f.address_test_mode)?
          NULL : ob->syntax_errors_to,           /* Who to mail */
        generated != NULL,                       /* True if not all failed */
        ob->syntax_errors_text))                 /* Custom message */
    return DEFER;

  if (filtertype != FILTER_FORWARD || generated == NULL)
    {
    addr->message = US"syntax error in redirection data";
    return DECLINE;
    }
  }

/* Sort out the errors address and any header modifications, and handle the
generated addresses, if any. If there are no generated addresses, we must avoid
calling sort_errors_and_headers() in case this router declines - that function
may modify the errors_address field in the current address, and we don't want
to do that for a decline. */

if (generated != NULL)
  {
  if ((xrc = sort_errors_and_headers(rblock, addr, verify, &addr_prop)) != OK)
    return xrc;
  add_generated(rblock, addr_new, addr, generated, &addr_prop, &ugid, pw);
  }

/* FF_DELIVERED with no generated addresses is what we get when an address list
contains :blackhole: or a filter contains "seen finish" without having
generated anything. Log what happened to this address, and return DISCARD. */

if (frc == FF_DELIVERED)
  {
  if (generated == NULL && verify == v_none && !f.address_test_mode)
    {
    log_write(0, LOG_MAIN, "=> %s <%s> R=%s", discarded, addr->address,
      rblock->name);
    yield = DISCARD;
    }
  }

/* For an address list, FF_NOTDELIVERED always means that no addresses were
generated. For a filter, addresses may or may not have been generated. If none
were, it's the same as an empty address list, and the router declines. However,
if addresses were generated, we can't just decline because successful delivery
of the base address gets it marked "done", so deferred generated addresses
never get tried again. We have to generate a new version of the base address,
as if there were a "deliver" command in the filter file, with the original
address as parent. */

else
  {
  address_item *next;

  if (generated == NULL) return DECLINE;

  next = deliver_make_addr(addr->address, FALSE);
  next->parent = addr;
  addr->child_count++;
  next->next = *addr_new;
  *addr_new = next;

  /* Set the data that propagates. */

  next->prop = addr_prop;

  DEBUG(D_route) debug_printf("%s router autogenerated %s\n%s%s%s",
    rblock->name,
    next->address,
    (addr_prop.errors_address != NULL)? "  errors to " : "",
    (addr_prop.errors_address != NULL)? addr_prop.errors_address : US"",
    (addr_prop.errors_address != NULL)? "\n" : "");
  }

/* Control gets here only when the address has been completely handled. Put the
original address onto the succeed queue so that any retry items that get
attached to it get processed. */

addr->next = *addr_succeed;
*addr_succeed = addr;

return yield;
}

#endif   /*!MACRO_PREDEF*/
/* End of routers/redirect.c */
