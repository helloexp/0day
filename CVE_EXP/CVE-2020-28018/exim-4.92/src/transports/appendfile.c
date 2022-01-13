/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "appendfile.h"

#ifdef SUPPORT_MAILDIR
#include "tf_maildir.h"
#endif


/* Options specific to the appendfile transport. They must be in alphabetic
order (note that "_" comes before the lower case letters). Some of them are
stored in the publicly visible instance block - these are flagged with the
opt_public flag. */

optionlist appendfile_transport_options[] = {
#ifdef SUPPORT_MAILDIR
  { "*expand_maildir_use_size_file", opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, expand_maildir_use_size_file) },
#endif
  { "*set_use_fcntl_lock",opt_bool | opt_hidden,
      (void *)offsetof(appendfile_transport_options_block, set_use_fcntl) },
  { "*set_use_flock_lock",opt_bool | opt_hidden,
      (void *)offsetof(appendfile_transport_options_block, set_use_flock) },
  { "*set_use_lockfile", opt_bool | opt_hidden,
      (void *)offsetof(appendfile_transport_options_block, set_use_lockfile) },
#ifdef SUPPORT_MBX
  { "*set_use_mbx_lock", opt_bool | opt_hidden,
      (void *)offsetof(appendfile_transport_options_block, set_use_mbx_lock) },
#endif
  { "allow_fifo",        opt_bool,
      (void *)offsetof(appendfile_transport_options_block, allow_fifo) },
  { "allow_symlink",     opt_bool,
      (void *)offsetof(appendfile_transport_options_block, allow_symlink) },
  { "batch_id",          opt_stringptr | opt_public,
      (void *)offsetof(transport_instance, batch_id) },
  { "batch_max",         opt_int | opt_public,
      (void *)offsetof(transport_instance, batch_max) },
  { "check_group",       opt_bool,
      (void *)offsetof(appendfile_transport_options_block, check_group) },
  { "check_owner",       opt_bool,
      (void *)offsetof(appendfile_transport_options_block, check_owner) },
  { "check_string",      opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, check_string) },
  { "create_directory",  opt_bool,
      (void *)offsetof(appendfile_transport_options_block, create_directory) },
  { "create_file",       opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, create_file_string) },
  { "directory",         opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, dirname) },
  { "directory_file",    opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, dirfilename) },
  { "directory_mode",    opt_octint,
      (void *)offsetof(appendfile_transport_options_block, dirmode) },
  { "escape_string",     opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, escape_string) },
  { "file",              opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, filename) },
  { "file_format",       opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, file_format) },
  { "file_must_exist",   opt_bool,
      (void *)offsetof(appendfile_transport_options_block, file_must_exist) },
  { "lock_fcntl_timeout", opt_time,
      (void *)offsetof(appendfile_transport_options_block, lock_fcntl_timeout) },
  { "lock_flock_timeout", opt_time,
      (void *)offsetof(appendfile_transport_options_block, lock_flock_timeout) },
  { "lock_interval",     opt_time,
      (void *)offsetof(appendfile_transport_options_block, lock_interval) },
  { "lock_retries",      opt_int,
      (void *)offsetof(appendfile_transport_options_block, lock_retries) },
  { "lockfile_mode",     opt_octint,
      (void *)offsetof(appendfile_transport_options_block, lockfile_mode) },
  { "lockfile_timeout",  opt_time,
      (void *)offsetof(appendfile_transport_options_block, lockfile_timeout) },
  { "mailbox_filecount", opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, mailbox_filecount_string) },
  { "mailbox_size",      opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, mailbox_size_string) },
#ifdef SUPPORT_MAILDIR
  { "maildir_format",    opt_bool,
      (void *)offsetof(appendfile_transport_options_block, maildir_format ) } ,
  { "maildir_quota_directory_regex", opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, maildir_dir_regex) },
  { "maildir_retries",   opt_int,
      (void *)offsetof(appendfile_transport_options_block, maildir_retries) },
  { "maildir_tag",       opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, maildir_tag) },
  { "maildir_use_size_file", opt_expand_bool,
      (void *)offsetof(appendfile_transport_options_block, maildir_use_size_file ) } ,
  { "maildirfolder_create_regex", opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, maildirfolder_create_regex ) },
#endif  /* SUPPORT_MAILDIR */
#ifdef SUPPORT_MAILSTORE
  { "mailstore_format",  opt_bool,
      (void *)offsetof(appendfile_transport_options_block, mailstore_format ) },
  { "mailstore_prefix",  opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, mailstore_prefix ) },
  { "mailstore_suffix",  opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, mailstore_suffix ) },
#endif  /* SUPPORT_MAILSTORE */
#ifdef SUPPORT_MBX
  { "mbx_format",        opt_bool,
      (void *)offsetof(appendfile_transport_options_block, mbx_format ) } ,
#endif  /* SUPPORT_MBX */
  { "message_prefix",    opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, message_prefix) },
  { "message_suffix",    opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, message_suffix) },
  { "mode",              opt_octint,
      (void *)offsetof(appendfile_transport_options_block, mode) },
  { "mode_fail_narrower",opt_bool,
      (void *)offsetof(appendfile_transport_options_block, mode_fail_narrower) },
  { "notify_comsat",     opt_bool,
      (void *)offsetof(appendfile_transport_options_block, notify_comsat) },
  { "quota",             opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, quota) },
  { "quota_directory",   opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, quota_directory) },
  { "quota_filecount",   opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, quota_filecount) },
  { "quota_is_inclusive", opt_bool,
      (void *)offsetof(appendfile_transport_options_block, quota_is_inclusive) },
  { "quota_size_regex",   opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, quota_size_regex) },
  { "quota_warn_message", opt_stringptr | opt_public,
      (void *)offsetof(transport_instance, warn_message) },
  { "quota_warn_threshold", opt_stringptr,
      (void *)offsetof(appendfile_transport_options_block, quota_warn_threshold) },
  { "use_bsmtp",         opt_bool,
      (void *)offsetof(appendfile_transport_options_block, use_bsmtp) },
  { "use_crlf",          opt_bool,
      (void *)offsetof(appendfile_transport_options_block, use_crlf) },
  { "use_fcntl_lock",    opt_bool_set,
      (void *)offsetof(appendfile_transport_options_block, use_fcntl) },
  { "use_flock_lock",    opt_bool_set,
      (void *)offsetof(appendfile_transport_options_block, use_flock) },
  { "use_lockfile",      opt_bool_set,
      (void *)offsetof(appendfile_transport_options_block, use_lockfile) },
#ifdef SUPPORT_MBX
  { "use_mbx_lock",      opt_bool_set,
      (void *)offsetof(appendfile_transport_options_block, use_mbx_lock) },
#endif  /* SUPPORT_MBX */
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int appendfile_transport_options_count =
  sizeof(appendfile_transport_options)/sizeof(optionlist);


#ifdef MACRO_PREDEF

/* Dummy values */
appendfile_transport_options_block appendfile_transport_option_defaults = {0};
void appendfile_transport_init(transport_instance *tblock) {}
BOOL appendfile_transport_entry(transport_instance *tblock, address_item *addr) {return FALSE;}

#else	/*!MACRO_PREDEF*/

/* Default private options block for the appendfile transport. */

appendfile_transport_options_block appendfile_transport_option_defaults = {
  NULL,           /* filename */
  NULL,           /* dirname */
  US"q${base62:$tod_epoch}-$inode", /* dirfilename */
  NULL,           /* message_prefix (default reset in init if not bsmtp) */
  NULL,           /* message_suffix (ditto) */
  US"anywhere",   /* create_file_string (string value for create_file) */
  NULL,           /* quota */
  NULL,           /* quota_directory */
  NULL,           /* quota_filecount */
  NULL,           /* quota_size_regex */
  NULL,           /* quota_warn_threshold */
  NULL,           /* mailbox_size_string */
  NULL,           /* mailbox_filecount_string */
  NULL,           /* expand_maildir_use_size_file */
  US"^(?:cur|new|\\..*)$",  /* maildir_dir_regex */
  NULL,           /* maildir_tag */
  NULL,           /* maildirfolder_create_regex */
  NULL,           /* mailstore_prefix */
  NULL,           /* mailstore_suffix */
  NULL,           /* check_string (default changed for non-bsmtp file)*/
  NULL,           /* escape_string (ditto) */
  NULL,           /* file_format */
  0,              /* quota_value */
  0,              /* quota_warn_threshold_value */
  -1,             /* mailbox_size_value */
  -1,             /* mailbox_filecount_value */
  0,              /* quota_filecount_value */
  APPENDFILE_MODE,           /* mode */
  APPENDFILE_DIRECTORY_MODE, /* dirmode */
  APPENDFILE_LOCKFILE_MODE,  /* lockfile_mode */
  30*60,          /* lockfile_timeout */
  0,              /* lock_fcntl_timeout */
  0,              /* lock_flock_timeout */
  10,             /* lock_retries */
   3,             /* lock_interval */
  10,             /* maildir_retries */
  create_anywhere,/* create_file */
  0,              /* options */
  FALSE,          /* allow_fifo */
  FALSE,          /* allow_symlink */
  FALSE,          /* check_group */
  TRUE,           /* check_owner */
  TRUE,           /* create_directory */
  FALSE,          /* notify_comsat */
  TRUE,           /* use_lockfile */
  FALSE,          /* set_use_lockfile */
  TRUE,           /* use_fcntl */
  FALSE,          /* set_use_fcntl */
  FALSE,          /* use_flock */
  FALSE,          /* set_use_flock */
  FALSE,          /* use_mbx_lock */
  FALSE,          /* set_use_mbx_lock */
  FALSE,          /* use_bsmtp */
  FALSE,          /* use_crlf */
  FALSE,          /* file_must_exist */
  TRUE,           /* mode_fail_narrower */
  FALSE,          /* maildir_format */
  FALSE,          /* maildir_use_size_file */
  FALSE,          /* mailstore_format */
  FALSE,          /* mbx_format */
  FALSE,          /* quota_warn_threshold_is_percent */
  TRUE,           /* quota_is_inclusive */
  FALSE,          /* quota_no_check */
  FALSE           /* quota_filecount_no_check */
};


/* Encodings for mailbox formats, and their names. MBX format is actually
supported only if SUPPORT_MBX is set. */

enum { mbf_unix, mbf_mbx, mbf_smail, mbf_maildir, mbf_mailstore };

static const char *mailbox_formats[] = {
  "unix", "mbx", "smail", "maildir", "mailstore" };


/* Check warn threshold only if quota size set or not a percentage threshold
   percentage check should only be done if quota > 0 */

#define THRESHOLD_CHECK  (ob->quota_warn_threshold_value > 0 && \
  (!ob->quota_warn_threshold_is_percent || ob->quota_value > 0))



/*************************************************
*              Setup entry point                 *
*************************************************/

/* Called for each delivery in the privileged state, just before the uid/gid
are changed and the main entry point is called. We use this function to
expand any quota settings, so that it can access files that may not be readable
by the user. It is also used to pick up external mailbox size information, if
set.

Arguments:
  tblock     points to the transport instance
  addrlist   addresses about to be delivered (not used)
  dummy      not used (doesn't pass back data)
  uid        the uid that will be set (not used)
  gid        the gid that will be set (not used)
  errmsg     where to put an error message

Returns:     OK, FAIL, or DEFER
*/

static int
appendfile_transport_setup(transport_instance *tblock, address_item *addrlist,
  transport_feedback *dummy, uid_t uid, gid_t gid, uschar **errmsg)
{
appendfile_transport_options_block *ob =
  (appendfile_transport_options_block *)(tblock->options_block);
uschar *q = ob->quota;
double default_value = 0.0;
int i;

addrlist = addrlist;    /* Keep picky compilers happy */
dummy = dummy;
uid = uid;
gid = gid;

if (ob->expand_maildir_use_size_file)
	ob->maildir_use_size_file = expand_check_condition(ob->expand_maildir_use_size_file,
		US"`maildir_use_size_file` in transport", tblock->name);

/* Loop for quota, quota_filecount, quota_warn_threshold, mailbox_size,
mailbox_filecount */

for (i = 0; i < 5; i++)
  {
  double d;
  int no_check = 0;
  uschar *which = NULL;

  if (q == NULL) d = default_value;
  else
    {
    uschar *rest;
    uschar *s = expand_string(q);

    if (!s)
      {
      *errmsg = string_sprintf("Expansion of \"%s\" in %s transport failed: "
        "%s", q, tblock->name, expand_string_message);
      return f.search_find_defer ? DEFER : FAIL;
      }

    d = Ustrtod(s, &rest);

    /* Handle following characters K, M, G, %, the latter being permitted
    for quota_warn_threshold only. A threshold with no quota setting is
    just ignored. */

    if (tolower(*rest) == 'k') { d *= 1024.0; rest++; }
    else if (tolower(*rest) == 'm') { d *= 1024.0*1024.0; rest++; }
    else if (tolower(*rest) == 'g') { d *= 1024.0*1024.0*1024.0; rest++; }
    else if (*rest == '%' && i == 2)
      {
      if (ob->quota_value <= 0 && !ob->maildir_use_size_file)
	d = 0;
      else if ((int)d < 0 || (int)d > 100)
        {
        *errmsg = string_sprintf("Invalid quota_warn_threshold percentage (%d)"
          " for %s transport", (int)d, tblock->name);
        return FAIL;
        }
      ob->quota_warn_threshold_is_percent = TRUE;
      rest++;
      }


    /* For quota and quota_filecount there may be options
    appended. Currently only "no_check", so we can be lazy parsing it */
    if (i < 2 && Ustrstr(rest, "/no_check") == rest)
      {
       no_check = 1;
       rest += sizeof("/no_check") - 1;
      }

    while (isspace(*rest)) rest++;

    if (*rest != 0)
      {
      *errmsg = string_sprintf("Malformed value \"%s\" (expansion of \"%s\") "
        "in %s transport", s, q, tblock->name);
      return FAIL;
      }
    }

  /* Set each value, checking for possible overflow. */

  switch (i)
    {
    case 0:
      if (d >= 2.0*1024.0*1024.0*1024.0 && sizeof(off_t) <= 4)
	which = US"quota";
      ob->quota_value = (off_t)d;
      ob->quota_no_check = no_check;
      q = ob->quota_filecount;
      break;

    case 1:
      if (d >= 2.0*1024.0*1024.0*1024.0)
	which = US"quota_filecount";
      ob->quota_filecount_value = (int)d;
      ob->quota_filecount_no_check = no_check;
      q = ob->quota_warn_threshold;
      break;

    case 2:
    if (d >= 2.0*1024.0*1024.0*1024.0 && sizeof(off_t) <= 4)
	which = US"quota_warn_threshold";
      ob->quota_warn_threshold_value = (off_t)d;
      q = ob->mailbox_size_string;
      default_value = -1.0;
      break;

    case 3:
      if (d >= 2.0*1024.0*1024.0*1024.0 && sizeof(off_t) <= 4)
	which = US"mailbox_size";;
      ob->mailbox_size_value = (off_t)d;
      q = ob->mailbox_filecount_string;
      break;

    case 4:
      if (d >= 2.0*1024.0*1024.0*1024.0)
	which = US"mailbox_filecount";
      ob->mailbox_filecount_value = (int)d;
      break;
    }

  if (which)
    {
    *errmsg = string_sprintf("%s value %.10g is too large (overflow) in "
      "%s transport", which, d, tblock->name);
    return FAIL;
    }
  }

return OK;
}



/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */

void
appendfile_transport_init(transport_instance *tblock)
{
appendfile_transport_options_block *ob =
  (appendfile_transport_options_block *)(tblock->options_block);

/* Set up the setup entry point, to be called in the privileged state */

tblock->setup = appendfile_transport_setup;

/* Lock_retries must be greater than zero */

if (ob->lock_retries == 0) ob->lock_retries = 1;

/* Only one of a file name or directory name must be given. */

if (ob->filename != NULL && ob->dirname != NULL)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s transport:\n  "
  "only one of \"file\" or \"directory\" can be specified", tblock->name);

/* If a file name was specified, neither quota_filecount nor quota_directory
must be given. */

if (ob->filename != NULL)
  {
  if (ob->quota_filecount != NULL)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s transport:\n  "
      "quota_filecount must not be set without \"directory\"", tblock->name);
  if (ob->quota_directory != NULL)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s transport:\n  "
      "quota_directory must not be set without \"directory\"", tblock->name);
  }

/* The default locking depends on whether MBX is set or not. Change the
built-in default if none of the lock options has been explicitly set. At least
one form of locking is required in all cases, but mbx locking changes the
meaning of fcntl and flock locking. */

/* Not all operating systems provide flock(). For those that do, if flock is
requested, the default for fcntl is FALSE. */

if (ob->use_flock)
  {
  #ifdef NO_FLOCK
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s transport:\n  "
    "flock() support was not available in the operating system when this "
    "binary was built", tblock->name);
  #endif  /* NO_FLOCK */
  if (!ob->set_use_fcntl) ob->use_fcntl = FALSE;
  }

#ifdef SUPPORT_MBX
if (ob->mbx_format)
  {
  if (!ob->set_use_lockfile && !ob->set_use_fcntl && !ob->set_use_flock &&
      !ob->set_use_mbx_lock)
    {
    ob->use_lockfile = ob->use_flock = FALSE;
    ob->use_mbx_lock = ob->use_fcntl = TRUE;
    }
  else if (ob->use_mbx_lock)
    {
    if (!ob->set_use_lockfile) ob->use_lockfile = FALSE;
    if (!ob->set_use_fcntl) ob->use_fcntl = FALSE;
    if (!ob->set_use_flock) ob->use_flock = FALSE;
    if (!ob->use_fcntl && !ob->use_flock) ob->use_fcntl = TRUE;
    }
  }
#endif  /* SUPPORT_MBX */

if (!ob->use_fcntl && !ob->use_flock && !ob->use_lockfile && !ob->use_mbx_lock)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s transport:\n  "
    "no locking configured", tblock->name);

/* Unset timeouts for non-used locking types */

if (!ob->use_fcntl) ob->lock_fcntl_timeout = 0;
if (!ob->use_flock) ob->lock_flock_timeout = 0;

/* If a directory name was specified, only one of maildir or mailstore may be
specified, and if quota_filecount or quota_directory is given, quota must
be set. */

if (ob->dirname != NULL)
  {
  if (ob->maildir_format && ob->mailstore_format)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s transport:\n  "
      "only one of maildir and mailstore may be specified", tblock->name);
  if (ob->quota_filecount != NULL && ob->quota == NULL)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s transport:\n  "
      "quota must be set if quota_filecount is set", tblock->name);
  if (ob->quota_directory != NULL && ob->quota == NULL)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, "%s transport:\n  "
      "quota must be set if quota_directory is set", tblock->name);
  }

/* If a fixed uid field is set, then a gid field must also be set. */

if (tblock->uid_set && !tblock->gid_set && tblock->expand_gid == NULL)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
    "user set without group for the %s transport", tblock->name);

/* If "create_file" is set, check that a valid option is given, and set the
integer variable. */

if (ob->create_file_string != NULL)
  {
  int value = 0;
  if (Ustrcmp(ob->create_file_string, "anywhere") == 0) value = create_anywhere;
  else if (Ustrcmp(ob->create_file_string, "belowhome") == 0) value =
    create_belowhome;
  else if (Ustrcmp(ob->create_file_string, "inhome") == 0)
    value = create_inhome;
  else
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
      "invalid value given for \"file_create\" for the %s transport: %s",
        tblock->name, ob->create_file_string);
  ob->create_file = value;
  }

/* If quota_warn_threshold is set, set up default for warn_message. It may
not be used if the actual threshold for a given delivery ends up as zero,
of if it's given as a percentage and there's no quota setting. */

if (ob->quota_warn_threshold != NULL)
  {
  if (tblock->warn_message == NULL) tblock->warn_message = US
    "To: $local_part@$domain\n"
    "Subject: Your mailbox\n\n"
    "This message is automatically created by mail delivery software (Exim).\n\n"
    "The size of your mailbox has exceeded a warning threshold that is\n"
    "set by the system administrator.\n";
  }

/* If batch SMTP is set, force the check and escape strings, and arrange that
headers are also escaped. */

if (ob->use_bsmtp)
  {
  ob->check_string = US".";
  ob->escape_string = US"..";
  ob->options |= topt_escape_headers;
  }

/* If not batch SMTP, not maildir, not mailstore, and directory is not set,
insert default values for for the affixes and the check/escape strings. */

else if (ob->dirname == NULL && !ob->maildir_format && !ob->mailstore_format)
  {
  if (ob->message_prefix == NULL) ob->message_prefix =
    US"From ${if def:return_path{$return_path}{MAILER-DAEMON}} ${tod_bsdinbox}\n";
  if (ob->message_suffix == NULL) ob->message_suffix = US"\n";
  if (ob->check_string == NULL) ob->check_string = US"From ";
  if (ob->escape_string == NULL) ob->escape_string = US">From ";

  }

/* Set up the bitwise options for transport_write_message from the various
driver options. Only one of body_only and headers_only can be set. */

ob->options |=
  (tblock->body_only ? topt_no_headers : 0) |
  (tblock->headers_only ? topt_no_body : 0) |
  (tblock->return_path_add ? topt_add_return_path : 0) |
  (tblock->delivery_date_add ? topt_add_delivery_date : 0) |
  (tblock->envelope_to_add ? topt_add_envelope_to : 0) |
  ((ob->use_crlf || ob->mbx_format) ? topt_use_crlf : 0);
}



/*************************************************
*                  Notify comsat                 *
*************************************************/

/* The comsat daemon is the thing that provides asynchronous notification of
the arrival of local messages, if requested by the user by "biff y". It is a
BSD thing that uses a TCP/IP protocol for communication. A message consisting
of the text "user@offset" must be sent, where offset is the place in the
mailbox where new mail starts. There is no scope for telling it which file to
look at, which makes it a less than useful if mail is being delivered into a
non-standard place such as the user's home directory. In fact, it doesn't seem
to pay much attention to the offset.

Arguments:
  user       user name
  offset     offset in mailbox

Returns:     nothing
*/

static void
notify_comsat(uschar *user, off_t offset)
{
struct servent *sp;
host_item host;
host_item *h;
uschar buffer[256];

DEBUG(D_transport) debug_printf("notify_comsat called\n");

sprintf(CS buffer, "%.200s@" OFF_T_FMT "\n", user, offset);

if ((sp = getservbyname("biff", "udp")) == NULL)
  {
  DEBUG(D_transport) debug_printf("biff/udp is an unknown service");
  return;
  }

host.name = US"localhost";
host.next = NULL;


/* This code is all set up to look up "localhost" and use all its addresses
until one succeeds. However, it appears that at least on some systems, comsat
doesn't listen on the ::1 address. So for the moment, just force the address to
be 127.0.0.1. At some future stage, when IPv6 really is superseding IPv4, this
can be changed. (But actually, comsat is probably dying out anyway.) */

/******
if (host_find_byname(&host, NULL, 0, NULL, FALSE) == HOST_FIND_FAILED)
  {
  DEBUG(D_transport) debug_printf("\"localhost\" unknown\n");
  return;
  }
******/

host.address = US"127.0.0.1";


for (h = &host; h; h = h->next)
  {
  int sock, rc;
  int host_af = Ustrchr(h->address, ':') != NULL ? AF_INET6 : AF_INET;

  DEBUG(D_transport) debug_printf("calling comsat on %s\n", h->address);

  if ((sock = ip_socket(SOCK_DGRAM, host_af)) < 0) continue;

  /* Connect never fails for a UDP socket, so don't set a timeout. */

  (void)ip_connect(sock, host_af, h->address, ntohs(sp->s_port), 0, NULL);
  rc = send(sock, buffer, Ustrlen(buffer) + 1, 0);
  (void)close(sock);

  if (rc >= 0) break;
  DEBUG(D_transport)
    debug_printf("send to comsat failed for %s: %s\n", strerror(errno),
      h->address);
  }
}



/*************************************************
*     Check the format of a file                 *
*************************************************/

/* This function is called when file_format is set, to check that an existing
file has the right format. The format string contains text/transport pairs. The
string matching is literal. we just read big_buffer_size bytes, because this is
all about the first few bytes of a file.

Arguments:
  cfd          the open file
  tblock       the transport block
  addr         the address block - for inserting error data

Returns:       pointer to the required transport, or NULL
*/

transport_instance *
check_file_format(int cfd, transport_instance *tblock, address_item *addr)
{
const uschar *format =
  ((appendfile_transport_options_block *)(tblock->options_block))->file_format;
uschar data[256];
int len = read(cfd, data, sizeof(data));
int sep = 0;
uschar *s;

DEBUG(D_transport) debug_printf("checking file format\n");

/* An empty file matches the current transport */

if (len == 0) return tblock;

/* Search the formats for a match */

while ((s = string_nextinlist(&format,&sep,big_buffer,big_buffer_size)))
  {
  int slen = Ustrlen(s);
  BOOL match = len >= slen && Ustrncmp(data, s, slen) == 0;
  uschar *tp = string_nextinlist(&format, &sep, big_buffer, big_buffer_size);

  if (match && tp)
    {
    transport_instance *tt;
    for (tt = transports; tt; tt = tt->next)
      if (Ustrcmp(tp, tt->name) == 0)
        {
        DEBUG(D_transport)
          debug_printf("file format -> %s transport\n", tt->name);
        return tt;
        }
    addr->basic_errno = ERRNO_BADTRANSPORT;
    addr->message = string_sprintf("%s transport (for %.*s format) not found",
      tp, slen, data);
    return NULL;
    }
  }

/* Failed to find a match */

addr->basic_errno = ERRNO_FORMATUNKNOWN;
addr->message = US"mailbox file format unrecognized";
return NULL;
}




/*************************************************
*       Check directory's files for quota        *
*************************************************/

/* This function is called if quota is set for one of the delivery modes that
delivers into a specific directory. It scans the directory and stats all the
files in order to get a total size and count. This is an expensive thing to do,
but some people are prepared to bear the cost. Alternatively, if size_regex is
set, it is used as a regex to try to extract the size from the file name, a
strategy that some people use on maildir files on systems where the users have
no shell access.

The function is global, because it is also called from tf_maildir.c for maildir
folders (which should contain only regular files).

Note: Any problems can be written to debugging output, but cannot be written to
the log, because we are running as an unprivileged user here.

Arguments:
  dirname       the name of the directory
  countptr      where to add the file count (because this function recurses)
  regex         a compiled regex to get the size from a name

Returns:        the sum of the sizes of the stattable files
                zero if the directory cannot be opened
*/

off_t
check_dir_size(uschar *dirname, int *countptr, const pcre *regex)
{
DIR *dir;
off_t sum = 0;
int count = *countptr;
struct dirent *ent;
struct stat statbuf;

dir = opendir(CS dirname);
if (dir == NULL) return 0;

while ((ent = readdir(dir)) != NULL)
  {
  uschar *name = US ent->d_name;
  uschar buffer[1024];

  if (Ustrcmp(name, ".") == 0 || Ustrcmp(name, "..") == 0) continue;

  count++;

  /* If there's a regex, try to find the size using it */

  if (regex != NULL)
    {
    int ovector[6];
    if (pcre_exec(regex, NULL, CS name, Ustrlen(name), 0, 0, ovector,6) >= 2)
      {
      uschar *endptr;
      off_t size = (off_t)Ustrtod(name + ovector[2], &endptr);
      if (endptr == name + ovector[3])
        {
        sum += size;
        DEBUG(D_transport)
          debug_printf("check_dir_size: size from %s is " OFF_T_FMT "\n", name,
            size);
        continue;
        }
      }
    DEBUG(D_transport)
      debug_printf("check_dir_size: regex did not match %s\n", name);
    }

  /* No regex or no match for the regex, or captured non-digits */

  if (!string_format(buffer, sizeof(buffer), "%s/%s", dirname, name))
    {
    DEBUG(D_transport)
      debug_printf("check_dir_size: name too long: dir=%s name=%s\n", dirname,
        name);
    continue;
    }

  if (Ustat(buffer, &statbuf) < 0)
    {
    DEBUG(D_transport)
      debug_printf("check_dir_size: stat error %d for %s: %s\n", errno, buffer,
        strerror(errno));
    continue;
    }

  if ((statbuf.st_mode & S_IFMT) == S_IFREG)
    sum += statbuf.st_size;
  else if ((statbuf.st_mode & S_IFMT) == S_IFDIR)
    sum += check_dir_size(buffer, &count, regex);
  }

closedir(dir);
DEBUG(D_transport)
  debug_printf("check_dir_size: dir=%s sum=" OFF_T_FMT " count=%d\n", dirname,
    sum, count);

*countptr = count;
return sum;
}




/*************************************************
*         Apply a lock to a file descriptor      *
*************************************************/

/* This function applies a lock to a file descriptor, using a blocking or
non-blocking lock, depending on the timeout value. It can apply either or
both of a fcntl() and a flock() lock. However, not all OS support flock();
for those that don't, the use_flock option cannot be set.

Arguments:
  fd          the file descriptor
  fcntltype   type of lock, specified as F_WRLCK or F_RDLCK (that is, in
                fcntl() format); the flock() type is deduced if needed
  dofcntl     do fcntl() locking
  fcntltime   non-zero to use blocking fcntl()
  doflock     do flock() locking
  flocktime   non-zero to use blocking flock()

Returns:      yield of the fcntl() or flock() call, with errno preserved;
              sigalrm_seen set if there has been a timeout
*/

static int
apply_lock(int fd, int fcntltype, BOOL dofcntl, int fcntltime, BOOL doflock,
    int flocktime)
{
int yield = 0;
int save_errno;
struct flock lock_data;
lock_data.l_type = fcntltype;
lock_data.l_whence = lock_data.l_start = lock_data.l_len = 0;

sigalrm_seen = FALSE;

if (dofcntl)
  {
  if (fcntltime > 0)
    {
    ALARM(fcntltime);
    yield = fcntl(fd, F_SETLKW, &lock_data);
    save_errno = errno;
    ALARM_CLR(0);
    errno = save_errno;
    }
  else yield = fcntl(fd, F_SETLK, &lock_data);
  }

#ifndef NO_FLOCK
if (doflock && (yield >= 0))
  {
  int flocktype = (fcntltype == F_WRLCK) ? LOCK_EX : LOCK_SH;
  if (flocktime > 0)
    {
    ALARM(flocktime);
    yield = flock(fd, flocktype);
    save_errno = errno;
    ALARM_CLR(0);
    errno = save_errno;
    }
  else yield = flock(fd, flocktype | LOCK_NB);
  }
#endif  /* NO_FLOCK */

return yield;
}




#ifdef SUPPORT_MBX
/*************************************************
*         Copy message into MBX mailbox          *
*************************************************/

/* This function is called when a message intended for a MBX mailbox has been
written to a temporary file. We can now get the size of the message and then
copy it in MBX format to the mailbox.

Arguments:
  to_fd        fd to write to (the real mailbox)
  from_fd      fd to read from (the temporary file)
  saved_size   current size of mailbox

Returns:       OK if all went well, DEFER otherwise, with errno preserved
               the number of bytes written are added to transport_count
                 by virtue of calling transport_write_block()
*/

/* Values taken from c-client */

#define MBX_HDRSIZE            2048
#define MBX_NUSERFLAGS           30

static int
copy_mbx_message(int to_fd, int from_fd, off_t saved_size)
{
int used;
off_t size;
struct stat statbuf;
transport_ctx tctx = { .u={.fd = to_fd}, .options = topt_not_socket };

/* If the current mailbox size is zero, write a header block */

if (saved_size == 0)
  {
  int i;
  uschar *s;
  memset (deliver_out_buffer, '\0', MBX_HDRSIZE);
  sprintf(CS(s = deliver_out_buffer), "*mbx*\015\012%08lx00000000\015\012",
    (long int)time(NULL));
  for (i = 0; i < MBX_NUSERFLAGS; i++)
    sprintf (CS(s += Ustrlen(s)), "\015\012");
  if (!transport_write_block (&tctx, deliver_out_buffer, MBX_HDRSIZE, FALSE))
    return DEFER;
  }

DEBUG(D_transport) debug_printf("copying MBX message from temporary file\n");

/* Now construct the message's header from the time and the RFC822 file
size, including CRLFs, which is the size of the input (temporary) file. */

if (fstat(from_fd, &statbuf) < 0) return DEFER;
size = statbuf.st_size;

sprintf (CS deliver_out_buffer, "%s," OFF_T_FMT ";%08lx%04x-%08x\015\012",
  tod_stamp(tod_mbx), size, 0L, 0, 0);
used = Ustrlen(deliver_out_buffer);

/* Rewind the temporary file, and copy it over in chunks. */

if (lseek(from_fd, 0 , SEEK_SET) < 0) return DEFER;

while (size > 0)
  {
  int len = read(from_fd, deliver_out_buffer + used,
    DELIVER_OUT_BUFFER_SIZE - used);
  if (len <= 0)
    {
    if (len == 0) errno = ERRNO_MBXLENGTH;
    return DEFER;
    }
  if (!transport_write_block(&tctx, deliver_out_buffer, used + len, FALSE))
    return DEFER;
  size -= len;
  used = 0;
  }

return OK;
}
#endif  /* SUPPORT_MBX */



/*************************************************
*            Check creation is permitted         *
*************************************************/

/* This function checks whether a given file name is permitted to be created,
as controlled by the create_file option. If no home directory is set, however,
we can't do any tests.

Arguments:
  filename     the file name
  create_file  the ob->create_file option

Returns:       TRUE if creation is permitted
*/

static BOOL
check_creation(uschar *filename, int create_file)
{
BOOL yield = TRUE;

if (deliver_home != NULL && create_file != create_anywhere)
  {
  int len = Ustrlen(deliver_home);
  uschar *file = filename;

  while (file[0] == '/' && file[1] == '/') file++;
  if (Ustrncmp(file, deliver_home, len) != 0 || file[len] != '/' ||
       ( Ustrchr(file+len+2, '/') != NULL &&
         (
         create_file != create_belowhome ||
         Ustrstr(file+len, "/../") != NULL
         )
       )
     ) yield = FALSE;

  /* If yield is TRUE, the file name starts with the home directory, and does
  not contain any instances of "/../" in the "belowhome" case. However, it may
  still contain symbolic links. We can check for this by making use of
  realpath(), which most Unixes seem to have (but make it possible to cut this
  out). We can't just use realpath() on the whole file name, because we know
  the file itself doesn't exist, and intermediate directories may also not
  exist. What we want to know is the real path of the longest existing part of
  the path. That must match the home directory's beginning, whichever is the
  shorter. */

  #ifndef NO_REALPATH
  if (yield && create_file == create_belowhome)
    {
    uschar *slash, *next;
    uschar *rp = NULL;
    for (slash = Ustrrchr(file, '/');       /* There is known to be one */
         rp == NULL && slash > file;        /* Stop if reached beginning */
         slash = next)
      {
      *slash = 0;
      rp = US realpath(CS file, CS big_buffer);
      next = Ustrrchr(file, '/');
      *slash = '/';
      }

    /* If rp == NULL it means that none of the relevant directories exist.
    This is not a problem here - it means that no symbolic links can exist,
    which is all we are worried about. Otherwise, we must compare it
    against the start of the home directory. However, that may itself
    contain symbolic links, so we have to "realpath" it as well, if
    possible. */

    if (rp != NULL)
      {
      uschar hdbuffer[PATH_MAX+1];
      uschar *rph = deliver_home;
      int rlen = Ustrlen(big_buffer);

      rp = US realpath(CS deliver_home, CS hdbuffer);
      if (rp != NULL)
        {
        rph = hdbuffer;
        len = Ustrlen(rph);
        }

      if (rlen > len) rlen = len;
      if (Ustrncmp(rph, big_buffer, rlen) != 0)
        {
        yield = FALSE;
        DEBUG(D_transport) debug_printf("Real path \"%s\" does not match \"%s\"\n",
          big_buffer, deliver_home);
        }
      }
    }
  #endif  /* NO_REALPATH */
  }

return yield;
}



/*************************************************
*              Main entry point                  *
*************************************************/

/* See local README for general interface details. This transport always
returns FALSE, indicating that the status which has been placed in the first
address should be copied to any other addresses in a batch.

Appendfile delivery is tricky and has led to various security problems in other
mailers. The logic used here is therefore laid out in some detail. When this
function is called, we are running in a subprocess which has had its gid and
uid set to the appropriate values. Therefore, we cannot write directly to the
exim logs. Any errors must be handled by setting appropriate return codes.
Note that the default setting for addr->transport_return is DEFER, so it need
not be set unless some other value is required.

The code below calls geteuid() rather than getuid() to get the current uid
because in weird configurations not running setuid root there may be a
difference. In the standard configuration, where setuid() has been used in the
delivery process, there will be no difference between the uid and the euid.

(1)  If the af_file flag is set, this is a delivery to a file after .forward or
     alias expansion. Otherwise, there must be a configured file name or
     directory name.

The following items apply in the case when a file name (as opposed to a
directory name) is given, that is, when appending to a single file:

(2f) Expand the file name.

(3f) If the file name is /dev/null, return success (optimization).

(4f) If the file_format options is set, open the file for reading, and check
     that the bytes at the start of the file match one of the given strings.
     If the check indicates a transport other than the current one should be
     used, pass control to that other transport. Otherwise continue. An empty
     or non-existent file matches the current transport. The file is closed
     after the check.

(5f) If a lock file is required, create it (see extensive separate comments
     below about the algorithm for doing this). It is important to do this
     before opening the mailbox if NFS is in use.

(6f) Stat the file, using lstat() rather than stat(), in order to pick up
     details of any symbolic link.

(7f) If the file already exists:

     Check the owner and group if necessary, and defer if they are wrong.

     If it is a symbolic link AND the allow_symlink option is set (NOT the
     default), go back to (6f) but this time use stat() instead of lstat().

     If it's not a regular file (or FIFO when permitted), defer delivery.

     Check permissions. If the required permissions are *less* than the
     existing ones, or supplied by the address (often by the user via filter),
     chmod() the file. Otherwise, defer.

     Save the inode number.

     Open with O_RDRW + O_APPEND, thus failing if the file has vanished.

     If open fails because the file does not exist, go to (6f); on any other
     failure, defer.

     Check the inode number hasn't changed - I realize this isn't perfect (an
     inode can be reused) but it's cheap and will catch some of the races.

     Check it's still a regular file (or FIFO if permitted).

     Check that the owner and permissions haven't changed.

     If file_format is set, check that the file still matches the format for
     the current transport. If not, defer delivery.

(8f) If file does not exist initially:

     Open with O_WRONLY + O_EXCL + O_CREAT with configured mode, unless we know
     this is via a symbolic link (only possible if allow_symlinks is set), in
     which case don't use O_EXCL, as it doesn't work.

     If open fails because the file already exists, go to (6f). To avoid
     looping for ever in a situation where the file is continuously being
     created and deleted, all of this happens inside a loop that operates
     lock_retries times and includes the fcntl and flock locking. If the
     loop completes without the file getting opened, defer and request
     freezing, because something really weird is happening.

     If open fails for any other reason, defer for subsequent delivery except
     when this is a file delivery resulting from an alias or forward expansion
     and the error is EPERM or ENOENT or EACCES, in which case FAIL as this is
     most likely a user rather than a configuration error.

(9f) We now have the file checked and open for writing. If so configured, lock
     it using fcntl, flock, or MBX locking rules. If this fails, close the file
     and goto (6f), up to lock_retries times, after sleeping for a while. If it
     still fails, give up and defer delivery.

(10f)Save the access time (for subsequent restoration) and the size of the
     file, for comsat and for re-setting if delivery fails in the middle -
     e.g. for quota exceeded.

The following items apply in the case when a directory name is given:

(2d) Create a new file in the directory using a temporary name, by opening for
     writing and with O_CREAT. If maildir format is being used, the file
     is created in a temporary subdirectory with a prescribed name. If
     mailstore format is being used, the envelope file is first created with a
     temporary name, then the data file.

The following items apply in all cases:

(11) We now have the file open for writing, and locked if it was given as a
     file name. Write the message and flush the file, unless there is a setting
     of the local quota option, in which case we can check for its excession
     without doing any writing.

     In the case of MBX format mailboxes, the message is first written to a
     temporary file, in order to get its correct length. This is then copied to
     the real file, preceded by an MBX header.

     If there is a quota error on writing, defer the address. Timeout logic
     will determine for how long retries are attempted. We restore the mailbox
     to its original length if it's a single file. There doesn't seem to be a
     uniform error code for quota excession (it even differs between SunOS4
     and some versions of SunOS5) so a system-dependent macro called
     ERRNO_QUOTA is used for it, and the value gets put into errno_quota at
     compile time.

     For any other error (most commonly disk full), do the same.

The following applies after appending to a file:

(12f)Restore the atime; notify_comsat if required; close the file (which
     unlocks it if it was locked). Delete the lock file if it exists.

The following applies after writing a unique file in a directory:

(12d)For maildir format, rename the file into the new directory. For mailstore
     format, rename the envelope file to its correct name. Otherwise, generate
     a unique name from the directory_file option, and rename to that, possibly
     trying a few times if the file exists and re-expanding the name gives a
     different string.

This transport yields FAIL only when a file name is generated by an alias or
forwarding operation and attempting to open it gives EPERM, ENOENT, or EACCES.
All other failures return DEFER (in addr->transport_return). */


BOOL
appendfile_transport_entry(
  transport_instance *tblock,      /* data for this instantiation */
  address_item *addr)              /* address we are working on */
{
appendfile_transport_options_block *ob =
  (appendfile_transport_options_block *)(tblock->options_block);
struct stat statbuf;
uschar *fdname = NULL;
uschar *filename = NULL;
uschar *hitchname = NULL;
uschar *dataname = NULL;
uschar *lockname = NULL;
uschar *newname = NULL;
uschar *nametag = NULL;
uschar *cr = US"";
uschar *filecount_msg = US"";
uschar *path;
struct utimbuf times;
struct timeval msg_tv;
BOOL disable_quota = FALSE;
BOOL isdirectory = FALSE;
BOOL isfifo = FALSE;
BOOL wait_for_tick = FALSE;
uid_t uid = geteuid();     /* See note above */
gid_t gid = getegid();
int mbformat;
int mode = (addr->mode > 0) ? addr->mode : ob->mode;
off_t saved_size = -1;
off_t mailbox_size = ob->mailbox_size_value;
int mailbox_filecount = ob->mailbox_filecount_value;
int hd = -1;
int fd = -1;
int yield = FAIL;
int i;

#ifdef SUPPORT_MBX
int save_fd = 0;
int mbx_lockfd = -1;
uschar mbx_lockname[40];
FILE *temp_file = NULL;
#endif  /* SUPPORT_MBX */

#ifdef SUPPORT_MAILDIR
int maildirsize_fd = -1;      /* fd for maildirsize file */
int maildir_save_errno;
#endif


DEBUG(D_transport) debug_printf("appendfile transport entered\n");

/* An "address_file" or "address_directory" transport is used to deliver to
files specified via .forward or an alias file. Prior to release 4.20, the
"file" and "directory" options were ignored in this case. This has been changed
to allow the redirection data to specify what is in effect a folder, whose
location is determined by the options on the transport.

Compatibility with the case when neither option is set is retained by forcing a
value for the file or directory name. A directory delivery is assumed if the
last character of the path from the router is '/'.

The file path is in the local part of the address, but not in the $local_part
variable (that holds the parent local part). It is, however, in the
$address_file variable. Below, we update the local part in the address if it
changes by expansion, so that the final path ends up in the log. */

if (testflag(addr, af_file) &&
    ob->filename == NULL &&
    ob->dirname == NULL)
  {
  fdname = US"$address_file";
  if (address_file[Ustrlen(address_file)-1] == '/' ||
      ob->maildir_format ||
      ob->mailstore_format)
    isdirectory = TRUE;
  }

/* Handle (a) an "address file" delivery where "file" or "directory" is
explicitly set and (b) a non-address_file delivery, where one of "file" or
"directory" must be set; initialization ensures that they are not both set. */

if (fdname == NULL)
  {
  fdname = ob->filename;
  if (fdname == NULL)
    {
    fdname = ob->dirname;
    isdirectory = TRUE;
    }
  if (fdname == NULL)
    {
    addr->transport_return = PANIC;
    addr->message = string_sprintf("Mandatory file or directory option "
      "missing from %s transport", tblock->name);
    return FALSE;
    }
  }

/* Maildir and mailstore require a directory */

if ((ob->maildir_format || ob->mailstore_format) && !isdirectory)
  {
  addr->transport_return = PANIC;
  addr->message = string_sprintf("mail%s_format requires \"directory\" "
    "to be specified for the %s transport",
    ob->maildir_format ? "dir" : "store", tblock->name);
  return FALSE;
  }

path = expand_string(fdname);

if (path == NULL)
  {
  addr->transport_return = PANIC;
  addr->message = string_sprintf("Expansion of \"%s\" (file or directory "
    "name for %s transport) failed: %s", fdname, tblock->name,
    expand_string_message);
  return FALSE;
  }

if (path[0] != '/')
  {
  addr->message = string_sprintf("appendfile: file or directory name "
    "\"%s\" is not absolute", path);
  addr->basic_errno = ERRNO_NOTABSOLUTE;
  return FALSE;
  }

/* For a file delivery, make sure the local part in the address(es) is updated
to the true local part. */

if (testflag(addr, af_file))
  {
  address_item *addr2;
  for (addr2 = addr; addr2 != NULL; addr2 = addr2->next)
    addr2->local_part = string_copy(path);
  }

/* The available mailbox formats depend on whether it is a directory or a file
delivery. */

if (isdirectory)
  {
  mbformat =
  #ifdef SUPPORT_MAILDIR
    (ob->maildir_format) ? mbf_maildir :
  #endif
  #ifdef SUPPORT_MAILSTORE
    (ob->mailstore_format) ? mbf_mailstore :
  #endif
    mbf_smail;
  }
else
  {
  mbformat =
  #ifdef SUPPORT_MBX
    (ob->mbx_format) ? mbf_mbx :
  #endif
    mbf_unix;
  }

DEBUG(D_transport)
  {
  debug_printf("appendfile: mode=%o notify_comsat=%d quota=" OFF_T_FMT
    "%s%s"
    " warning=" OFF_T_FMT "%s\n"
    "  %s=%s format=%s\n  message_prefix=%s\n  message_suffix=%s\n  "
    "maildir_use_size_file=%s\n",
    mode, ob->notify_comsat, ob->quota_value,
    ob->quota_no_check ? " (no_check)" : "",
    ob->quota_filecount_no_check ? " (no_check_filecount)" : "",
    ob->quota_warn_threshold_value,
    ob->quota_warn_threshold_is_percent ? "%" : "",
    isdirectory ? "directory" : "file",
    path, mailbox_formats[mbformat],
    (ob->message_prefix == NULL) ? US"null" : string_printing(ob->message_prefix),
    (ob->message_suffix == NULL) ? US"null" : string_printing(ob->message_suffix),
    (ob->maildir_use_size_file) ? "yes" : "no");

  if (!isdirectory) debug_printf("  locking by %s%s%s%s%s\n",
    ob->use_lockfile ? "lockfile " : "",
    ob->use_mbx_lock ? "mbx locking (" : "",
    ob->use_fcntl ? "fcntl " : "",
    ob->use_flock ? "flock" : "",
    ob->use_mbx_lock ? ")" : "");
  }

/* If the -N option is set, can't do any more. */

if (f.dont_deliver)
  {
  DEBUG(D_transport)
    debug_printf("*** delivery by %s transport bypassed by -N option\n",
      tblock->name);
  addr->transport_return = OK;
  return FALSE;
  }

/* Handle the case of a file name. If the file name is /dev/null, we can save
ourselves some effort and just give a success return right away. */

if (!isdirectory)
  {
  BOOL use_lstat = TRUE;
  BOOL file_opened = FALSE;
  BOOL allow_creation_here = TRUE;

  if (Ustrcmp(path, "/dev/null") == 0)
    {
    addr->transport_return = OK;
    return FALSE;
    }

  /* Set the name of the file to be opened, and the file to which the data
  is written, and find out if we are permitted to create a non-existent file. */

  dataname = filename = path;
  allow_creation_here = check_creation(filename, ob->create_file);

  /* If ob->create_directory is set, attempt to create the directories in
  which this mailbox lives, but only if we are permitted to create the file
  itself. We know we are dealing with an absolute path, because this was
  checked above. */

  if (ob->create_directory && allow_creation_here)
    {
    uschar *p = Ustrrchr(path, '/');
    *p = '\0';
    if (!directory_make(NULL, path, ob->dirmode, FALSE))
      {
      addr->basic_errno = errno;
      addr->message =
        string_sprintf("failed to create directories for %s: %s", path,
          strerror(errno));
      DEBUG(D_transport) debug_printf("%s transport: %s\n", tblock->name, path);
      return FALSE;
      }
    *p = '/';
    }

  /* If file_format is set we must check that any existing file matches one of
  the configured formats by checking the bytes it starts with. A match then
  indicates a specific transport - if it is not this one, pass control to it.
  Otherwise carry on here. An empty or non-existent file matches the current
  transport. We don't need to distinguish between non-existence and other open
  failures because if an existing file fails to open here, it will also fail
  again later when O_RDWR is used. */

  if (ob->file_format != NULL)
    {
    int cfd = Uopen(path, O_RDONLY, 0);
    if (cfd >= 0)
      {
      transport_instance *tt = check_file_format(cfd, tblock, addr);
      (void)close(cfd);

      /* If another transport is indicated, call it and return; if no transport
      was found, just return - the error data will have been set up.*/

      if (tt != tblock)
        {
        if (tt != NULL)
          {
          set_process_info("delivering %s to %s using %s", message_id,
            addr->local_part, tt->name);
          debug_print_string(tt->debug_string);
          addr->transport = tt;
          (tt->info->code)(tt, addr);
          }
        return FALSE;
        }
      }
    }

  /* The locking of mailbox files is worse than the naming of cats, which is
  known to be "a difficult matter" (T.S. Eliot) and just as cats must have
  three different names, so several different styles of locking are used.

  Research in other programs that lock mailboxes shows that there is no
  universally standard method. Having mailboxes NFS-mounted on the system that
  is delivering mail is not the best thing, but people do run like this,
  and so the code must do its best to cope.

  Three different locking mechanisms are supported. The initialization function
  checks that at least one is configured.

  LOCK FILES

  Unless no_use_lockfile is set, we attempt to build a lock file in a way that
  will work over NFS. Only after that is done do we actually open the mailbox
  and apply locks to it (if configured).

  Originally, Exim got the file opened before doing anything about locking.
  However, a very occasional problem was observed on Solaris 2 when delivering
  over NFS. It is seems that when a file is opened with O_APPEND, the file size
  gets remembered at open time. If another process on another host (that's
  important) has the file open and locked and writes to it and then releases
  the lock while the first process is waiting to get the lock, the first
  process may fail to write at the new end point of the file - despite the very
  definite statement about O_APPEND in the man page for write(). Experiments
  have reproduced this problem, but I do not know any way of forcing a host to
  update its attribute cache for an open NFS file. It would be nice if it did
  so when a lock was taken out, but this does not seem to happen. Anyway, to
  reduce the risk of this problem happening, we now create the lock file
  (if configured) *before* opening the mailbox. That will prevent two different
  Exims opening the file simultaneously. It may not prevent clashes with MUAs,
  however, but Pine at least seems to operate in the same way.

  Lockfiles should normally be used when NFS is involved, because of the above
  problem.

  The logic for creating the lock file is:

  . The name of the lock file is <mailbox-name>.lock

  . First, create a "hitching post" name by adding the primary host name,
    current time and pid to the lock file name. This should be unique.

  . Create the hitching post file using WRONLY + CREAT + EXCL.

  . If that fails EACCES, we assume it means that the user is unable to create
    files in the mail spool directory. Some installations might operate in this
    manner, so there is a configuration option to allow this state not to be an
    error - we proceed to lock using fcntl only, after the file is open.

  . Otherwise, an error causes a deferment of the address.

  . Hard link the hitching post to the lock file name.

  . If the link succeeds, we have successfully created the lock file. Simply
    close and unlink the hitching post file.

  . If the link does not succeed, proceed as follows:

    o Fstat the hitching post file, and then close and unlink it.

    o Now examine the stat data. If the number of links to the file is exactly
      2, the linking succeeded but for some reason, e.g. an NFS server crash,
      the return never made it back, so the link() function gave a failure
      return.

  . This method allows for the lock file to be created by some other process
    right up to the moment of the attempt to hard link it, and is also robust
    against NFS server crash-reboots, which would probably result in timeouts
    in the middle of link().

  . System crashes may cause lock files to get left lying around, and some means
    of flushing them is required. The approach of writing a pid (used by smail
    and by elm) into the file isn't useful when NFS may be in use. Pine uses a
    timeout, which seems a better approach. Since any program that writes to a
    mailbox using a lock file should complete its task very quickly, Pine
    removes lock files that are older than 5 minutes. We allow the value to be
    configurable on the transport.

  FCNTL LOCKING

  If use_fcntl_lock is set, then Exim gets an exclusive fcntl() lock on the
  mailbox once it is open. This is done by default with a non-blocking lock.
  Failures to lock cause retries after a sleep, but only for a certain number
  of tries. A blocking lock is deliberately not used so that we don't hold the
  mailbox open. This minimizes the possibility of the NFS problem described
  under LOCK FILES above, if for some reason NFS deliveries are happening
  without lock files. However, the use of a non-blocking lock and sleep, though
  the safest approach, does not give the best performance on very busy systems.
  A blocking lock plus timeout does better. Therefore Exim has an option to
  allow it to work this way. If lock_fcntl_timeout is set greater than zero, it
  enables the use of blocking fcntl() calls.

  FLOCK LOCKING

  If use_flock_lock is set, then Exim gets an exclusive flock() lock in the
  same manner as for fcntl locking above. No-blocking/timeout is also set as
  above in lock_flock_timeout. Not all operating systems provide or support
  flock(). For those that don't (as determined by the definition of LOCK_SH in
  /usr/include/sys/file.h), use_flock_lock may not be set. For some OS, flock()
  is implemented (not precisely) on top of fcntl(), which means there's no
  point in actually using it.

  MBX LOCKING

  If use_mbx_lock is set (this is supported only if SUPPORT_MBX is defined)
  then the rules used for locking in c-client are used. Exim takes out a shared
  lock on the mailbox file, and an exclusive lock on the file whose name is
  /tmp/.<device-number>.<inode-number>. The shared lock on the mailbox stops
  any other MBX client from getting an exclusive lock on it and expunging it.
  It also stops any other MBX client from unlinking the /tmp lock when it has
  finished with it.

  The exclusive lock on the /tmp file prevents any other MBX client from
  updating the mailbox in any way. When writing is finished, if an exclusive
  lock on the mailbox can be obtained, indicating there are no current sharers,
  the /tmp file is unlinked.

  MBX locking can use either fcntl() or flock() locking. If neither
  use_fcntl_lock or use_flock_lock is set, it defaults to using fcntl() only.
  The calls for getting these locks are by default non-blocking, as for non-mbx
  locking, but can be made blocking by setting lock_fcntl_timeout and/or
  lock_flock_timeout as appropriate.  As MBX delivery doesn't work over NFS, it
  probably makes sense to set timeouts for any MBX deliveries. */


  /* Build a lock file if configured to do so - the existence of a lock
  file is subsequently checked by looking for a non-negative value of the
  file descriptor hd - even though the file is no longer open. */

  if (ob->use_lockfile)
    {
    /* cf. exim_lock.c */
    lockname = string_sprintf("%s.lock", filename);
    hitchname = string_sprintf( "%s.%s.%08x.%08x", lockname, primary_hostname,
      (unsigned int)(time(NULL)), (unsigned int)getpid());

    DEBUG(D_transport) debug_printf("lock name: %s\nhitch name: %s\n", lockname,
      hitchname);

    /* Lock file creation retry loop */

    for (i = 0; i < ob->lock_retries; sleep(ob->lock_interval), i++)
      {
      int rc;
      hd = Uopen(hitchname, O_WRONLY | O_CREAT | O_EXCL, ob->lockfile_mode);

      if (hd < 0)
        {
        addr->basic_errno = errno;
        addr->message =
          string_sprintf("creating lock file hitching post %s "
            "(euid=%ld egid=%ld)", hitchname, (long int)geteuid(),
            (long int)getegid());
        return FALSE;
        }

      /* Attempt to hitch the hitching post to the lock file. If link()
      succeeds (the common case, we hope) all is well. Otherwise, fstat the
      file, and get rid of the hitching post. If the number of links was 2,
      the link was created, despite the failure of link(). If the hitch was
      not successful, try again, having unlinked the lock file if it is too
      old.

      There's a version of Linux (2.0.27) which doesn't update its local cache
      of the inode after link() by default - which many think is a bug - but
      if the link succeeds, this code will be OK. It just won't work in the
      case when link() fails after having actually created the link. The Linux
      NFS person is fixing this; a temporary patch is available if anyone is
      sufficiently worried. */

      if ((rc = Ulink(hitchname, lockname)) != 0) fstat(hd, &statbuf);
      (void)close(hd);
      Uunlink(hitchname);
      if (rc != 0 && statbuf.st_nlink != 2)
        {
        if (ob->lockfile_timeout > 0 && Ustat(lockname, &statbuf) == 0 &&
            time(NULL) - statbuf.st_ctime > ob->lockfile_timeout)
          {
          DEBUG(D_transport) debug_printf("unlinking timed-out lock file\n");
          Uunlink(lockname);
          }
        DEBUG(D_transport) debug_printf("link of hitching post failed - retrying\n");
        continue;
        }

      DEBUG(D_transport) debug_printf("lock file created\n");
      break;
      }

    /* Check for too many tries at creating the lock file */

    if (i >= ob->lock_retries)
      {
      addr->basic_errno = ERRNO_LOCKFAILED;
      addr->message = string_sprintf("failed to lock mailbox %s (lock file)",
        filename);
      return FALSE;
      }
    }


  /* We now have to get the file open. First, stat() it and act on existence or
  non-existence. This is in a loop to handle the case of a file's being created
  or deleted as we watch, and also to handle retries when the locking fails.
  Rather than holding the file open while waiting for the fcntl() and/or
  flock() lock, we close and do the whole thing again. This should be safer,
  especially for NFS files, which might get altered from other hosts, making
  their cached sizes incorrect.

  With the default settings, no symlinks are permitted, but there is an option
  to permit symlinks for those sysadmins that know what they are doing.
  Shudder. However, insist that the initial symlink is owned by the right user.
  Thus lstat() is used initially; if a symlink is discovered, the loop is
  repeated such that stat() is used, to look at the end file. */

  for (i = 0; i < ob->lock_retries; i++)
    {
    int sleep_before_retry = TRUE;
    file_opened = FALSE;

    if((use_lstat ? Ulstat(filename, &statbuf) : Ustat(filename, &statbuf)) != 0)
      {
      /* Let's hope that failure to stat (other than non-existence) is a
      rare event. */

      if (errno != ENOENT)
        {
        addr->basic_errno = errno;
        addr->message = string_sprintf("attempting to stat mailbox %s",
          filename);
        goto RETURN;
        }

      /* File does not exist. If it is required to pre-exist this state is an
      error. */

      if (ob->file_must_exist)
        {
        addr->basic_errno = errno;
        addr->message = string_sprintf("mailbox %s does not exist, "
          "but file_must_exist is set", filename);
        goto RETURN;
        }

      /* If not permitted to create this file because it isn't in or below
      the home directory, generate an error. */

      if (!allow_creation_here)
        {
        addr->basic_errno = ERRNO_BADCREATE;
        addr->message = string_sprintf("mailbox %s does not exist, "
          "but creation outside the home directory is not permitted",
          filename);
        goto RETURN;
        }

      /* Attempt to create and open the file. If open fails because of
      pre-existence, go round the loop again. For any other error, defer the
      address, except for an alias or forward generated file name with EPERM,
      ENOENT, or EACCES, as those are most likely to be user errors rather
      than Exim config errors. When a symbolic link is permitted and points
      to a non-existent file, we get here with use_lstat = FALSE. In this case
      we mustn't use O_EXCL, since it doesn't work. The file is opened RDRW for
      consistency and because MBX locking requires it in order to be able to
      get a shared lock. */

      fd = Uopen(filename, O_RDWR | O_APPEND | O_CREAT |
        (use_lstat ? O_EXCL : 0), mode);
      if (fd < 0)
        {
        if (errno == EEXIST) continue;
        addr->basic_errno = errno;
        addr->message = string_sprintf("while creating mailbox %s",
          filename);
        if (testflag(addr, af_file) &&
            (errno == EPERM || errno == ENOENT || errno == EACCES))
          addr->transport_return = FAIL;
        goto RETURN;
        }

      /* We have successfully created and opened the file. Ensure that the group
      and the mode are correct. */

      if(Uchown(filename, uid, gid) || Uchmod(filename, mode))
        {
        addr->basic_errno = errno;
        addr->message = string_sprintf("while setting perms on mailbox %s",
          filename);
        addr->transport_return = FAIL;
        goto RETURN;
        }
      }


    /* The file already exists. Test its type, ownership, and permissions, and
    save the inode for checking later. If symlinks are permitted (not the
    default or recommended state) it may be a symlink that already exists.
    Check its ownership and then look for the file at the end of the link(s).
    This at least prevents one user creating a symlink for another user in
    a sticky directory. */

    else
      {
      int oldmode = (int)statbuf.st_mode;
      ino_t inode = statbuf.st_ino;
      BOOL islink = (oldmode & S_IFMT) == S_IFLNK;

      isfifo = FALSE;        /* In case things are changing */

      /* Check owner if required - the default. */

      if (ob->check_owner && statbuf.st_uid != uid)
        {
        addr->basic_errno = ERRNO_BADUGID;
        addr->message = string_sprintf("mailbox %s%s has wrong uid "
          "(%ld != %ld)", filename,
          islink ? " (symlink)" : "",
          (long int)(statbuf.st_uid), (long int)uid);
        goto RETURN;
        }

      /* Group is checked only if check_group is set. */

      if (ob->check_group && statbuf.st_gid != gid)
        {
        addr->basic_errno = ERRNO_BADUGID;
        addr->message = string_sprintf("mailbox %s%s has wrong gid (%d != %d)",
          filename, islink ? " (symlink)" : "", statbuf.st_gid, gid);
        goto RETURN;
        }

      /* Just in case this is a sticky-bit mail directory, we don't want
      users to be able to create hard links to other users' files. */

      if (statbuf.st_nlink != 1)
        {
        addr->basic_errno = ERRNO_NOTREGULAR;
        addr->message = string_sprintf("mailbox %s%s has too many links (%d)",
          filename, islink ? " (symlink)" : "", statbuf.st_nlink);
        goto RETURN;

        }

      /* If symlinks are permitted (not recommended), the lstat() above will
      have found the symlink. Its ownership has just been checked; go round
      the loop again, using stat() instead of lstat(). That will never yield a
      mode of S_IFLNK. */

      if (islink && ob->allow_symlink)
        {
        use_lstat = FALSE;
        i--;                   /* Don't count this time round */
        continue;
        }

      /* An actual file exists. Check that it is a regular file, or FIFO
      if permitted. */

      if (ob->allow_fifo && (oldmode & S_IFMT) == S_IFIFO) isfifo = TRUE;

      else if ((oldmode & S_IFMT) != S_IFREG)
        {
        addr->basic_errno = ERRNO_NOTREGULAR;
        addr->message = string_sprintf("mailbox %s is not a regular file%s",
          filename, ob->allow_fifo ? " or named pipe" : "");
        goto RETURN;
        }

      /* If the mode is not what it would be for a newly created file, change
      the permissions if the mode is supplied for the address. Otherwise,
      reduce but do not extend the permissions. If the newly created
      permissions are greater than the existing permissions, don't change
      things when the mode is not from the address. */

      if ((oldmode = (oldmode & 07777)) != mode)
        {
        int diffs = oldmode ^ mode;
        if (addr->mode > 0 || (diffs & oldmode) == diffs)
          {
          DEBUG(D_transport) debug_printf("chmod %o %s\n", mode, filename);
          if (Uchmod(filename, mode) < 0)
            {
            addr->basic_errno = errno;
            addr->message = string_sprintf("attempting to chmod mailbox %s",
              filename);
            goto RETURN;
            }
          oldmode = mode;
          }

        /* Mode not from address, and newly-created permissions are greater
        than existing permissions. Default is to complain, but it can be
        configured to go ahead and try to deliver anyway if that's what
        the administration wants. */

        else if (ob->mode_fail_narrower)
          {
          addr->basic_errno = ERRNO_BADMODE;
          addr->message = string_sprintf("mailbox %s has the wrong mode %o "
            "(%o expected)", filename, oldmode, mode);
          goto RETURN;
          }
        }

      /* We are happy with the existing file. Open it, and then do further
      tests to ensure that it is the same file that we were just looking at.
      If the file does not now exist, restart this loop, going back to using
      lstat again. For an NFS error, just defer; other opening errors are
      more serious. The file is opened RDWR so that its format can be checked,
      and also MBX locking requires the use of a shared (read) lock. However,
      a FIFO is opened WRONLY + NDELAY so that it fails if there is no process
      reading the pipe. */

      fd = Uopen(filename, isfifo ? (O_WRONLY|O_NDELAY) : (O_RDWR|O_APPEND),
        mode);
      if (fd < 0)
        {
        if (errno == ENOENT)
          {
          use_lstat = TRUE;
          continue;
          }
        addr->basic_errno = errno;
        if (isfifo)
          {
          addr->message = string_sprintf("while opening named pipe %s "
            "(could mean no process is reading it)", filename);
          }
        else if (errno != EWOULDBLOCK)
          {
          addr->message = string_sprintf("while opening mailbox %s", filename);
          }
        goto RETURN;
        }

      /* This fstat really shouldn't fail, as we have an open file! There's a
      dilemma here. We use fstat in order to be sure we are peering at the file
      we have got open. However, that won't tell us if the file was reached
      via a symbolic link. We checked this above, but there is a race exposure
      if the link was created between the previous lstat and the open. However,
      it would have to be created with the same inode in order to pass the
      check below. If ob->allow_symlink is set, causing the use of stat rather
      than lstat above, symbolic links may be there anyway, and the checking is
      weaker. */

      if (fstat(fd, &statbuf) < 0)
        {
        addr->basic_errno = errno;
        addr->message = string_sprintf("attempting to stat open mailbox %s",
          filename);
        goto RETURN;
        }

      /* Check the inode; this is isn't a perfect check, but gives some
      confidence. */

      if (inode != statbuf.st_ino)
        {
        addr->basic_errno = ERRNO_INODECHANGED;
        addr->message = string_sprintf("opened mailbox %s inode number changed "
          "from " INO_T_FMT " to " INO_T_FMT, filename, inode, statbuf.st_ino);
        addr->special_action = SPECIAL_FREEZE;
        goto RETURN;
        }

      /* Check it's still a regular file or FIFO, and the uid, gid, and
      permissions have not changed. */

      if ((!isfifo && (statbuf.st_mode & S_IFMT) != S_IFREG) ||
          (isfifo && (statbuf.st_mode & S_IFMT) != S_IFIFO))
        {
        addr->basic_errno = ERRNO_NOTREGULAR;
        addr->message =
          string_sprintf("opened mailbox %s is no longer a %s", filename,
            isfifo ? "named pipe" : "regular file");
        addr->special_action = SPECIAL_FREEZE;
        goto RETURN;
        }

      if ((ob->check_owner && statbuf.st_uid != uid) ||
          (ob->check_group && statbuf.st_gid != gid))
        {
        addr->basic_errno = ERRNO_BADUGID;
        addr->message =
          string_sprintf("opened mailbox %s has wrong uid or gid", filename);
        addr->special_action = SPECIAL_FREEZE;
        goto RETURN;
        }

      if ((statbuf.st_mode & 07777) != oldmode)
        {
        addr->basic_errno = ERRNO_BADMODE;
        addr->message = string_sprintf("opened mailbox %s has wrong mode %o "
          "(%o expected)", filename, statbuf.st_mode & 07777, mode);
        addr->special_action = SPECIAL_FREEZE;
        goto RETURN;
        }

      /* If file_format is set, check that the format of the file has not
      changed. Error data is set by the testing function. */

      if (ob->file_format != NULL &&
          check_file_format(fd, tblock, addr) != tblock)
        {
        addr->message = US"open mailbox has changed format";
        goto RETURN;
        }

      /* The file is OK. Carry on to do the locking. */
      }

    /* We now have an open file, and must lock it using fcntl(), flock() or MBX
    locking rules if configured to do so. If a lock file is also required, it
    was created above and hd was left >= 0. At least one form of locking is
    required by the initialization function. If locking fails here, close the
    file and go round the loop all over again, after waiting for a bit, unless
    blocking locking was used. */

    file_opened = TRUE;
    if ((ob->lock_fcntl_timeout > 0) || (ob->lock_flock_timeout > 0))
      sleep_before_retry = FALSE;

    /* Simple fcntl() and/or flock() locking */

    if (!ob->use_mbx_lock && (ob->use_fcntl || ob->use_flock))
      {
      if (apply_lock(fd, F_WRLCK, ob->use_fcntl, ob->lock_fcntl_timeout,
         ob->use_flock, ob->lock_flock_timeout) >= 0) break;
      }

    /* MBX locking rules */

    #ifdef SUPPORT_MBX
    else if (ob->use_mbx_lock)
      {
      int mbx_tmp_oflags;
      struct stat lstatbuf, statbuf2;
      if (apply_lock(fd, F_RDLCK, ob->use_fcntl, ob->lock_fcntl_timeout,
           ob->use_flock, ob->lock_flock_timeout) >= 0 &&
           fstat(fd, &statbuf) >= 0)
        {
        sprintf(CS mbx_lockname, "/tmp/.%lx.%lx", (long)statbuf.st_dev,
          (long)statbuf.st_ino);

        /*
         * 2010-05-29: SECURITY
         * Dan Rosenberg reported the presence of a race-condition in the
         * original code here.  Beware that many systems still allow symlinks
         * to be followed in /tmp so an attacker can create a symlink pointing
         * elsewhere between a stat and an open, which we should avoid
         * following.
         *
         * It's unfortunate that we can't just use all the heavily debugged
         * locking from above.
         *
         * Also: remember to mirror changes into exim_lock.c */

        /* first leave the old pre-check in place, it provides better
         * diagnostics for common cases */
        if (Ulstat(mbx_lockname, &statbuf) >= 0)
          {
          if ((statbuf.st_mode & S_IFMT) == S_IFLNK)
            {
            addr->basic_errno = ERRNO_LOCKFAILED;
            addr->message = string_sprintf("symbolic link on MBX lock file %s",
              mbx_lockname);
            goto RETURN;
            }
          if (statbuf.st_nlink > 1)
            {
            addr->basic_errno = ERRNO_LOCKFAILED;
            addr->message = string_sprintf("hard link to MBX lock file %s",
              mbx_lockname);
            goto RETURN;
            }
          }

        /* If we could just declare "we must be the ones who create this
         * file" then a hitching post in a subdir would work, since a
         * subdir directly in /tmp/ which we create wouldn't follow links
         * but this isn't our locking logic, so we can't safely change the
         * file existence rules. */

        /* On systems which support O_NOFOLLOW, it's the easiest and most
         * obviously correct security fix */
        mbx_tmp_oflags = O_RDWR | O_CREAT;
#ifdef O_NOFOLLOW
        mbx_tmp_oflags |= O_NOFOLLOW;
#endif
        mbx_lockfd = Uopen(mbx_lockname, mbx_tmp_oflags, ob->lockfile_mode);
        if (mbx_lockfd < 0)
          {
          addr->basic_errno = ERRNO_LOCKFAILED;
          addr->message = string_sprintf("failed to open MBX lock file %s :%s",
            mbx_lockname, strerror(errno));
          goto RETURN;
          }

        if (Ulstat(mbx_lockname, &lstatbuf) < 0)
          {
          addr->basic_errno = ERRNO_LOCKFAILED;
          addr->message = string_sprintf("attempting to lstat open MBX "
             "lock file %s: %s", mbx_lockname, strerror(errno));
          goto RETURN;
          }
        if (fstat(mbx_lockfd, &statbuf2) < 0)
          {
          addr->basic_errno = ERRNO_LOCKFAILED;
          addr->message = string_sprintf("attempting to stat fd of open MBX "
              "lock file %s: %s", mbx_lockname, strerror(errno));
          goto RETURN;
          }

        /*
         * At this point:
         *  statbuf: if exists, is file which existed prior to opening the
         *           lockfile, might have been replaced since then
         *  statbuf2: result of stat'ing the open fd, is what was actually
         *            opened
         *  lstatbuf: result of lstat'ing the filename immediately after
         *            the open but there's a race condition again between
         *            those two steps: before open, symlink to foo, after
         *            open but before lstat have one of:
         *             * was no symlink, so is the opened file
         *               (we created it, no messing possible after that point)
         *             * hardlink to foo
         *             * symlink elsewhere
         *             * hardlink elsewhere
         *             * new file/other
         * Don't want to compare to device of /tmp because some modern systems
         * have regressed to having /tmp be the safe actual filesystem as
         * valuable data, so is mostly worthless, unless we assume that *only*
         * Linux systems do this and that all Linux has O_NOFOLLOW.  Something
         * for further consideration.
         * No point in doing a readlink on the lockfile as that will always be
         * at a different point in time from when we open it, so tells us
         * nothing; attempts to clean up and delete after ourselves would risk
         * deleting a *third* filename.
         */
        if ((statbuf2.st_nlink > 1) ||
            (lstatbuf.st_nlink > 1) ||
            (!S_ISREG(lstatbuf.st_mode)) ||
            (lstatbuf.st_dev != statbuf2.st_dev) ||
            (lstatbuf.st_ino != statbuf2.st_ino))
          {
          addr->basic_errno = ERRNO_LOCKFAILED;
          addr->message = string_sprintf("RACE CONDITION detected: "
              "mismatch post-initial-checks between \"%s\" and opened "
              "fd lead us to abort!", mbx_lockname);
          goto RETURN;
          }

        (void)Uchmod(mbx_lockname, ob->lockfile_mode);

        if (apply_lock(mbx_lockfd, F_WRLCK, ob->use_fcntl,
            ob->lock_fcntl_timeout, ob->use_flock, ob->lock_flock_timeout) >= 0)
          {
          struct stat ostatbuf;

          /* This tests for a specific race condition. Ensure that we still
          have the same file. */

          if (Ulstat(mbx_lockname, &statbuf) == 0 &&
              fstat(mbx_lockfd, &ostatbuf) == 0 &&
              statbuf.st_dev == ostatbuf.st_dev &&
              statbuf.st_ino == ostatbuf.st_ino)
            break;
          DEBUG(D_transport) debug_printf("MBX lockfile %s changed "
            "between creation and locking\n", mbx_lockname);
          }

        DEBUG(D_transport) debug_printf("failed to lock %s: %s\n", mbx_lockname,
          strerror(errno));
        (void)close(mbx_lockfd);
        mbx_lockfd = -1;
        }
      else
        {
        DEBUG(D_transport) debug_printf("failed to fstat or get read lock on %s: %s\n",
          filename, strerror(errno));
        }
      }
    #endif  /* SUPPORT_MBX */

    else break;   /* No on-file locking required; break the open/lock loop */

    DEBUG(D_transport)
      debug_printf("fcntl(), flock(), or MBX locking failed - retrying\n");

    (void)close(fd);
    fd = -1;
    use_lstat = TRUE;             /* Reset to use lstat first */


    /* If a blocking call timed out, break the retry loop if the total time
    so far is not less than than retries * interval. Use the larger of the
    flock() and fcntl() timeouts. */

    if (sigalrm_seen &&
        (i+1) * ((ob->lock_fcntl_timeout > ob->lock_flock_timeout)?
          ob->lock_fcntl_timeout : ob->lock_flock_timeout) >=
          ob->lock_retries * ob->lock_interval)
      i = ob->lock_retries;

    /* Wait a bit before retrying, except when it was a blocked fcntl() or
    flock() that caused the problem. */

    if (i < ob->lock_retries && sleep_before_retry) sleep(ob->lock_interval);
    }

  /* Test for exceeding the maximum number of tries. Either the file remains
  locked, or, if we haven't got it open, something is terribly wrong... */

  if (i >= ob->lock_retries)
    {
    if (!file_opened)
      {
      addr->basic_errno = ERRNO_EXISTRACE;
      addr->message = string_sprintf("mailbox %s: existence unclear", filename);
      addr->special_action = SPECIAL_FREEZE;
      }
    else
      {
      addr->basic_errno = ERRNO_LOCKFAILED;
      addr->message = string_sprintf("failed to lock mailbox %s (fcntl/flock)",
        filename);
      }
    goto RETURN;
    }

  DEBUG(D_transport) debug_printf("mailbox %s is locked\n", filename);

  /* Save access time (for subsequent restoration), modification time (for
  restoration if updating fails), size of file (for comsat and for re-setting if
  delivery fails in the middle - e.g. for quota exceeded). */

  if (fstat(fd, &statbuf) < 0)
    {
    addr->basic_errno = errno;
    addr->message = string_sprintf("while fstatting opened mailbox %s",
      filename);
    goto RETURN;
    }

  times.actime = statbuf.st_atime;
  times.modtime = statbuf.st_mtime;
  saved_size = statbuf.st_size;
  if (mailbox_size < 0) mailbox_size = saved_size;
  mailbox_filecount = 0;  /* Not actually relevant for single-file mailbox */
  }

/* Prepare for writing to a new file (as opposed to appending to an old one).
There are several different formats, but there is preliminary stuff concerned
with quotas that applies to all of them. Finding the current size by directory
scanning is expensive; for maildirs some fudges have been invented:

  (1) A regex can be used to extract a file size from its name;
  (2) If maildir_use_size is set, a maildirsize file is used to cache the
      mailbox size.
*/

else
  {
  uschar *check_path = path;    /* Default quota check path */
  const pcre *regex = NULL;     /* Regex for file size from file name */

  if (!check_creation(string_sprintf("%s/any", path), ob->create_file))
    {
    addr->basic_errno = ERRNO_BADCREATE;
    addr->message = string_sprintf("tried to create file in %s, but "
      "file creation outside the home directory is not permitted", path);
    goto RETURN;
    }

  #ifdef SUPPORT_MAILDIR
  /* For a maildir delivery, ensure that all the relevant directories exist,
  and a maildirfolder file if necessary. */

  if (mbformat == mbf_maildir && !maildir_ensure_directories(path, addr,
    ob->create_directory, ob->dirmode, ob->maildirfolder_create_regex))
      return FALSE;
  #endif  /* SUPPORT_MAILDIR */

  /* If we are going to do a quota check, of if maildir_use_size_file is set
  for a maildir delivery, compile the regular expression if there is one. We
  may also need to adjust the path that is used. We need to do this for
  maildir_use_size_file even if the quota is unset, because we still want to
  create the file. When maildir support is not compiled,
  ob->maildir_use_size_file is always FALSE. */

  if (ob->quota_value > 0 || THRESHOLD_CHECK || ob->maildir_use_size_file)
    {
    const uschar *error;
    int offset;

    /* Compile the regex if there is one. */

    if (ob->quota_size_regex != NULL)
      {
      regex = pcre_compile(CS ob->quota_size_regex, PCRE_COPT,
        (const char **)&error, &offset, NULL);
      if (regex == NULL)
        {
        addr->message = string_sprintf("appendfile: regular expression "
          "error: %s at offset %d while compiling %s", error, offset,
          ob->quota_size_regex);
        return FALSE;
        }
      DEBUG(D_transport) debug_printf("using regex for file sizes: %s\n",
        ob->quota_size_regex);
      }

    /* Use an explicitly configured directory if set */

    if (ob->quota_directory != NULL)
      {
      check_path = expand_string(ob->quota_directory);
      if (check_path == NULL)
        {
        addr->transport_return = PANIC;
        addr->message = string_sprintf("Expansion of \"%s\" (quota_directory "
         "name for %s transport) failed: %s", ob->quota_directory,
          tblock->name, expand_string_message);
        return FALSE;
        }

      if (check_path[0] != '/')
        {
        addr->message = string_sprintf("appendfile: quota_directory name "
          "\"%s\" is not absolute", check_path);
        addr->basic_errno = ERRNO_NOTABSOLUTE;
        return FALSE;
        }
      }

    #ifdef SUPPORT_MAILDIR
    /* Otherwise, if we are handling a maildir delivery, and the directory
    contains a file called maildirfolder, this is a maildir++ feature telling
    us that this is a sub-directory of the real inbox. We should therefore do
    the quota check on the parent directory. Beware of the special case when
    the directory name itself ends in a slash. */

    else if (mbformat == mbf_maildir)
      {
      struct stat statbuf;
      if (Ustat(string_sprintf("%s/maildirfolder", path), &statbuf) >= 0)
        {
        uschar *new_check_path = string_copy(check_path);
        uschar *slash = Ustrrchr(new_check_path, '/');
        if (slash != NULL)
          {
          if (slash[1] == 0)
            {
            *slash = 0;
            slash = Ustrrchr(new_check_path, '/');
            }
          if (slash != NULL)
            {
            *slash = 0;
            check_path = new_check_path;
            DEBUG(D_transport) debug_printf("maildirfolder file exists: "
              "quota check directory changed to %s\n", check_path);
            }
          }
        }
      }
    #endif  /* SUPPORT_MAILDIR */
    }

  /* If we are using maildirsize files, we need to ensure that such a file
  exists and, if necessary, recalculate its contents. As a byproduct of this,
  we obtain the current size of the maildir. If no quota is to be enforced
  (ob->quota_value == 0), we still need the size if a threshold check will
  happen later.

  Another regular expression is used to determine which directories inside the
  maildir are going to be counted. */

  #ifdef SUPPORT_MAILDIR
  if (ob->maildir_use_size_file)
    {
    const pcre *dir_regex = NULL;
    const uschar *error;
    int offset;

    if (ob->maildir_dir_regex != NULL)
      {
      int check_path_len = Ustrlen(check_path);

      dir_regex = pcre_compile(CS ob->maildir_dir_regex, PCRE_COPT,
        (const char **)&error, &offset, NULL);
      if (dir_regex == NULL)
        {
        addr->message = string_sprintf("appendfile: regular expression "
          "error: %s at offset %d while compiling %s", error, offset,
          ob->maildir_dir_regex);
        return FALSE;
        }

      DEBUG(D_transport)
        debug_printf("using regex for maildir directory selection: %s\n",
          ob->maildir_dir_regex);

      /* Check to see if we are delivering into an ignored directory, that is,
      if the delivery path starts with the quota check path, and the rest
      of the deliver path matches the regex; if so, set a flag to disable quota
      checking and maildirsize updating. */

      if (Ustrncmp(path, check_path, check_path_len) == 0)
        {
        uschar *s = path + check_path_len;
        while (*s == '/') s++;
        s = (*s == 0) ? US "new" : string_sprintf("%s/new", s);
        if (pcre_exec(dir_regex, NULL, CS s, Ustrlen(s), 0, 0, NULL, 0) < 0)
          {
          disable_quota = TRUE;
          DEBUG(D_transport) debug_printf("delivery directory does not match "
            "maildir_quota_directory_regex: disabling quota\n");
          }
        }
      }

    /* Quota enforcement; create and check the file. There is some discussion
    about whether this should happen if the quota is unset. At present, Exim
    always creates the file. If we ever want to change this, uncomment
    appropriate lines below, possibly doing a check on some option. */

/*  if (???? || ob->quota_value > 0) */

    if (!disable_quota)
      {
      off_t size;
      int filecount;

      maildirsize_fd = maildir_ensure_sizefile(check_path, ob, regex, dir_regex,
        &size, &filecount);

      if (maildirsize_fd == -1)
        {
        addr->basic_errno = errno;
        addr->message = string_sprintf("while opening or reading "
          "%s/maildirsize", check_path);
        return FALSE;
        }
      /* can also return -2, which means that the file was removed because of
      raciness; but in this case, the size & filecount will still have been
      updated. */

      if (mailbox_size < 0) mailbox_size = size;
      if (mailbox_filecount < 0) mailbox_filecount = filecount;
      }

    /* No quota enforcement; ensure file does *not* exist; calculate size if
    needed. */

/*  else
 *    {
 *    time_t old_latest;
 *    (void)unlink(CS string_sprintf("%s/maildirsize", check_path));
 *    if (THRESHOLD_CHECK)
 *      mailbox_size = maildir_compute_size(check_path, &mailbox_filecount, &old_latest,
 *        regex, dir_regex, FALSE);
 *    }
*/

    }
  #endif  /* SUPPORT_MAILDIR */

  /* Otherwise if we are going to do a quota check later on, and the mailbox
  size is not set, find the current size of the mailbox. Ditto for the file
  count. Note that ob->quota_filecount_value cannot be set without
  ob->quota_value being set. */

  if (!disable_quota &&
      (ob->quota_value > 0 || THRESHOLD_CHECK) &&
      (mailbox_size < 0 ||
        (mailbox_filecount < 0 && ob->quota_filecount_value > 0)))
    {
    off_t size;
    int filecount = 0;
    DEBUG(D_transport)
      debug_printf("quota checks on directory %s\n", check_path);
    size = check_dir_size(check_path, &filecount, regex);
    if (mailbox_size < 0) mailbox_size = size;
    if (mailbox_filecount < 0) mailbox_filecount = filecount;
    }

  /* Handle the case of creating a unique file in a given directory (not in
  maildir or mailstore format - this is how smail did it). A temporary name is
  used to create the file. Later, when it is written, the name is changed to a
  unique one. There is no need to lock the file. An attempt is made to create
  the directory if it does not exist. */

  if (mbformat == mbf_smail)
    {
    DEBUG(D_transport)
      debug_printf("delivering to new file in %s\n", path);
    filename = dataname =
      string_sprintf("%s/temp.%d.%s", path, (int)getpid(), primary_hostname);
    fd = Uopen(filename, O_WRONLY|O_CREAT, mode);
    if (fd < 0 &&                                 /* failed to open, and */
        (errno != ENOENT ||                       /* either not non-exist */
         !ob->create_directory ||                 /* or not allowed to make */
         !directory_make(NULL, path, ob->dirmode, FALSE) ||  /* or failed to create dir */
         (fd = Uopen(filename, O_WRONLY|O_CREAT|O_EXCL, mode)) < 0)) /* or then failed to open */
      {
      addr->basic_errno = errno;
      addr->message = string_sprintf("while creating file %s", filename);
      return FALSE;
      }
    }

  #ifdef SUPPORT_MAILDIR

  /* Handle the case of a unique file in maildir format. The file is written to
  the tmp subdirectory, with a prescribed form of name. */

  else if (mbformat == mbf_maildir)
    {
    DEBUG(D_transport)
      debug_printf("delivering in maildir format in %s\n", path);

    nametag = ob->maildir_tag;

    /* Check that nametag expands successfully; a hard failure causes a panic
    return. The actual expansion for use happens again later, when
    $message_size is accurately known. */

    if (nametag != NULL && expand_string(nametag) == NULL &&
        !f.expand_string_forcedfail)
      {
      addr->transport_return = PANIC;
      addr->message = string_sprintf("Expansion of \"%s\" (maildir_tag "
        "for %s transport) failed: %s", nametag, tblock->name,
        expand_string_message);
      return FALSE;
      }

    /* We ensured the existence of all the relevant directories above. Attempt
    to open the temporary file a limited number of times. I think this rather
    scary-looking for statement is actually OK. If open succeeds, the loop is
    broken; if not, there is a test on the value of i. Get the time again
    afresh each time round the loop. Its value goes into a variable that is
    checked at the end, to make sure we don't release this process until the
    clock has ticked. */

    for (i = 1;; i++)
      {
      uschar *basename;

      (void)gettimeofday(&msg_tv, NULL);
      basename = string_sprintf(TIME_T_FMT ".H%luP" PID_T_FMT ".%s",
       	msg_tv.tv_sec, msg_tv.tv_usec, getpid(), primary_hostname);

      filename = dataname = string_sprintf("tmp/%s", basename);
      newname = string_sprintf("new/%s", basename);

      if (Ustat(filename, &statbuf) == 0)
        errno = EEXIST;
      else if (errno == ENOENT)
        {
        fd = Uopen(filename, O_WRONLY | O_CREAT | O_EXCL, mode);
        if (fd >= 0) break;
        DEBUG (D_transport) debug_printf ("open failed for %s: %s\n",
          filename, strerror(errno));
        }

      /* Too many retries - give up */

      if (i >= ob->maildir_retries)
        {
        addr->message = string_sprintf ("failed to open %s (%d tr%s)",
          filename, i, (i == 1) ? "y" : "ies");
        addr->basic_errno = errno;
        if (errno == errno_quota || errno == ENOSPC)
          addr->user_message = US"mailbox is full";
        return FALSE;
        }

      /* Open or stat failed but we haven't tried too many times yet. */

      sleep(2);
      }

    /* Note that we have to ensure the clock has ticked before leaving */

    wait_for_tick = TRUE;

    /* Why are these here? Put in because they are present in the non-maildir
    directory case above. */

    if(Uchown(filename, uid, gid) || Uchmod(filename, mode))
      {
      addr->basic_errno = errno;
      addr->message = string_sprintf("while setting perms on maildir %s",
        filename);
      return FALSE;
      }
    }

  #endif  /* SUPPORT_MAILDIR */

  #ifdef SUPPORT_MAILSTORE

  /* Handle the case of a unique file in mailstore format. First write the
  envelope to a temporary file, then open the main file. The unique base name
  for the files consists of the message id plus the pid of this delivery
  process. */

  else
    {
    FILE *env_file;
    address_item *taddr;
    mailstore_basename = string_sprintf("%s/%s-%s", path, message_id,
      string_base62((long int)getpid()));

    DEBUG(D_transport)
      debug_printf("delivering in mailstore format in %s\n", path);

    filename = string_sprintf("%s.tmp", mailstore_basename);
    newname  = string_sprintf("%s.env", mailstore_basename);
    dataname = string_sprintf("%s.msg", mailstore_basename);

    fd = Uopen(filename, O_WRONLY|O_CREAT|O_EXCL, mode);
    if (fd < 0 &&                                 /* failed to open, and */
        (errno != ENOENT ||                       /* either not non-exist */
         !ob->create_directory ||                 /* or not allowed to make */
         !directory_make(NULL, path, ob->dirmode, FALSE) ||  /* or failed to create dir */
         (fd = Uopen(filename, O_WRONLY|O_CREAT|O_EXCL, mode)) < 0)) /* or then failed to open */
      {
      addr->basic_errno = errno;
      addr->message = string_sprintf("while creating file %s", filename);
      return FALSE;
      }

    /* Why are these here? Put in because they are present in the non-maildir
    directory case above. */

    if(Uchown(filename, uid, gid) || Uchmod(filename, mode))
      {
      addr->basic_errno = errno;
      addr->message = string_sprintf("while setting perms on file %s",
        filename);
      return FALSE;
      }

    /* Built a C stream from the open file descriptor. */

    if ((env_file = fdopen(fd, "wb")) == NULL)
      {
      addr->basic_errno = errno;
      addr->transport_return = PANIC;
      addr->message = string_sprintf("fdopen of %s ("
        "for %s transport) failed", filename, tblock->name);
      (void)close(fd);
      Uunlink(filename);
      return FALSE;
      }

    /* Write the envelope file, then close it. */

    if (ob->mailstore_prefix != NULL)
      {
      uschar *s = expand_string(ob->mailstore_prefix);
      if (s == NULL)
        {
        if (!f.expand_string_forcedfail)
          {
          addr->transport_return = PANIC;
          addr->message = string_sprintf("Expansion of \"%s\" (mailstore "
            "prefix for %s transport) failed: %s", ob->mailstore_prefix,
            tblock->name, expand_string_message);
          (void)fclose(env_file);
          Uunlink(filename);
          return FALSE;
          }
        }
      else
        {
        int n = Ustrlen(s);
        fprintf(env_file, "%s", CS s);
        if (n == 0 || s[n-1] != '\n') fprintf(env_file, "\n");
        }
      }

    fprintf(env_file, "%s\n", sender_address);

    for (taddr = addr; taddr!= NULL; taddr = taddr->next)
      fprintf(env_file, "%s@%s\n", taddr->local_part, taddr->domain);

    if (ob->mailstore_suffix != NULL)
      {
      uschar *s = expand_string(ob->mailstore_suffix);
      if (s == NULL)
        {
        if (!f.expand_string_forcedfail)
          {
          addr->transport_return = PANIC;
          addr->message = string_sprintf("Expansion of \"%s\" (mailstore "
            "suffix for %s transport) failed: %s", ob->mailstore_suffix,
            tblock->name, expand_string_message);
          (void)fclose(env_file);
          Uunlink(filename);
          return FALSE;
          }
        }
      else
        {
        int n = Ustrlen(s);
        fprintf(env_file, "%s", CS s);
        if (n == 0 || s[n-1] != '\n') fprintf(env_file, "\n");
        }
      }

    if (fclose(env_file) != 0)
      {
      addr->basic_errno = errno;
      addr->message = string_sprintf("while closing %s", filename);
      Uunlink(filename);
      return FALSE;
      }

    DEBUG(D_transport) debug_printf("Envelope file %s written\n", filename);

    /* Now open the data file, and ensure that it has the correct ownership and
    mode. */

    fd = Uopen(dataname, O_WRONLY|O_CREAT|O_EXCL, mode);
    if (fd < 0)
      {
      addr->basic_errno = errno;
      addr->message = string_sprintf("while creating file %s", dataname);
      Uunlink(filename);
      return FALSE;
      }
    if(Uchown(dataname, uid, gid) || Uchmod(dataname, mode))
      {
      addr->basic_errno = errno;
      addr->message = string_sprintf("while setting perms on file %s",
        dataname);
      return FALSE;
      }
    }

  #endif  /* SUPPORT_MAILSTORE */


  /* In all cases of writing to a new file, ensure that the file which is
  going to be renamed has the correct ownership and mode. */

  if(Uchown(filename, uid, gid) || Uchmod(filename, mode))
    {
    addr->basic_errno = errno;
    addr->message = string_sprintf("while setting perms on file %s",
      filename);
    return FALSE;
    }
  }


/* At last we can write the message to the file, preceded by any configured
prefix line, and followed by any configured suffix line. If there are any
writing errors, we must defer. */

DEBUG(D_transport) debug_printf("writing to file %s\n", dataname);

yield = OK;
errno = 0;

/* If there is a local quota setting, check that we are not going to exceed it
with this message if quota_is_inclusive is set; if it is not set, the check
is for the mailbox already being over quota (i.e. the current message is not
included in the check). */

if (!disable_quota && ob->quota_value > 0)
  {
  DEBUG(D_transport)
    {
    debug_printf("Exim quota = " OFF_T_FMT " old size = " OFF_T_FMT
      " this message = %d (%sincluded)\n",
      ob->quota_value, mailbox_size, message_size,
      ob->quota_is_inclusive ? "" : "not ");
    debug_printf("  file count quota = %d count = %d\n",
      ob->quota_filecount_value, mailbox_filecount);
    }

  if (mailbox_size + (ob->quota_is_inclusive ? message_size:0) > ob->quota_value)
    {

      if (!ob->quota_no_check)
        {
        DEBUG(D_transport) debug_printf("mailbox quota exceeded\n");
        yield = DEFER;
        errno = ERRNO_EXIMQUOTA;
        }
      else DEBUG(D_transport) debug_printf("mailbox quota exceeded but ignored\n");

    }

  if (ob->quota_filecount_value > 0
           && mailbox_filecount + (ob->quota_is_inclusive ? 1:0) >
              ob->quota_filecount_value)
    if(!ob->quota_filecount_no_check)
      {
      DEBUG(D_transport) debug_printf("mailbox file count quota exceeded\n");
      yield = DEFER;
      errno = ERRNO_EXIMQUOTA;
      filecount_msg = US" filecount";
      }
    else DEBUG(D_transport) if (ob->quota_filecount_no_check)
      debug_printf("mailbox file count quota exceeded but ignored\n");

  }

/* If we are writing in MBX format, what we actually do is to write the message
to a temporary file, and then copy it to the real file once we know its size.
This is the most straightforward way of getting the correct length in the
separator line. So, what we do here is to save the real file descriptor, and
replace it with one for a temporary file. The temporary file gets unlinked once
opened, so that it goes away on closure. */

#ifdef SUPPORT_MBX
if (yield == OK && ob->mbx_format)
  {
  temp_file = tmpfile();
  if (temp_file == NULL)
    {
    addr->basic_errno = errno;
    addr->message = US"while setting up temporary file";
    yield = DEFER;
    goto RETURN;
    }
  save_fd = fd;
  fd = fileno(temp_file);
  DEBUG(D_transport) debug_printf("writing to temporary file\n");
  }
#endif  /* SUPPORT_MBX */

/* Zero the count of bytes written. It is incremented by the transport_xxx()
functions. */

transport_count = 0;
transport_newlines = 0;

/* Write any configured prefix text first */

if (yield == OK && ob->message_prefix != NULL && ob->message_prefix[0] != 0)
  {
  uschar *prefix = expand_string(ob->message_prefix);
  if (prefix == NULL)
    {
    errno = ERRNO_EXPANDFAIL;
    addr->transport_return = PANIC;
    addr->message = string_sprintf("Expansion of \"%s\" (prefix for %s "
      "transport) failed", ob->message_prefix, tblock->name);
    yield = DEFER;
    }
  else if (!transport_write_string(fd, "%s", prefix)) yield = DEFER;
  }

/* If the use_bsmtp option is on, we need to write SMTP prefix information. The
various different values for batching are handled outside; if there is more
than one address available here, all must be included. If any address is a
file, use its parent in the RCPT TO. */

if (yield == OK && ob->use_bsmtp)
  {
  transport_count = 0;
  transport_newlines = 0;
  if (ob->use_crlf) cr = US"\r";
  if (!transport_write_string(fd, "MAIL FROM:<%s>%s\n", return_path, cr))
    yield = DEFER;
  else
    {
    address_item *a;
    transport_newlines++;
    for (a = addr; a != NULL; a = a->next)
      {
      address_item *b = testflag(a, af_pfr) ? a->parent: a;
      if (!transport_write_string(fd, "RCPT TO:<%s>%s\n",
        transport_rcpt_address(b, tblock->rcpt_include_affixes), cr))
          { yield = DEFER; break; }
      transport_newlines++;
      }
    if (yield == OK && !transport_write_string(fd, "DATA%s\n", cr))
      yield = DEFER;
    else
      transport_newlines++;
    }
  }

/* Now the message itself. The options for transport_write_message were set up
at initialization time. */

if (yield == OK)
  {
  transport_ctx tctx = {
    .u = {.fd=fd},
    .tblock = tblock,
    .addr = addr,
    .check_string = ob->check_string,
    .escape_string = ob->escape_string,
    .options =  ob->options | topt_not_socket
  };
  if (!transport_write_message(&tctx, 0))
    yield = DEFER;
  }

/* Now a configured suffix. */

if (yield == OK && ob->message_suffix != NULL && ob->message_suffix[0] != 0)
  {
  uschar *suffix = expand_string(ob->message_suffix);
  if (suffix == NULL)
    {
    errno = ERRNO_EXPANDFAIL;
    addr->transport_return = PANIC;
    addr->message = string_sprintf("Expansion of \"%s\" (suffix for %s "
      "transport) failed", ob->message_suffix, tblock->name);
    yield = DEFER;
    }
  else if (!transport_write_string(fd, "%s", suffix)) yield = DEFER;
  }

/* If batch smtp, write the terminating dot. */

if (yield == OK && ob->use_bsmtp ) {
  if(!transport_write_string(fd, ".%s\n", cr)) yield = DEFER;
  else transport_newlines++;
}

/* If MBX format is being used, all that writing was to the temporary file.
However, if there was an earlier failure (Exim quota exceeded, for example),
the temporary file won't have got opened - and no writing will have been done.
If writing was OK, we restore the fd, and call a function that copies the
message in MBX format into the real file. Otherwise use the temporary name in
any messages. */

#ifdef SUPPORT_MBX
if (temp_file != NULL && ob->mbx_format)
  {
  int mbx_save_errno;
  fd = save_fd;

  if (yield == OK)
    {
    transport_count = 0;   /* Reset transport count for actual write */
    /* No need to reset transport_newlines as we're just using a block copy
     * routine so the number won't be affected */
    yield = copy_mbx_message(fd, fileno(temp_file), saved_size);
    }
  else if (errno >= 0) dataname = US"temporary file";

  /* Preserve errno while closing the temporary file. */

  mbx_save_errno = errno;
  (void)fclose(temp_file);
  errno = mbx_save_errno;
  }
#endif  /* SUPPORT_MBX */

/* Force out the remaining data to check for any errors; some OS don't allow
fsync() to be called for a FIFO. */

if (yield == OK && !isfifo && EXIMfsync(fd) < 0) yield = DEFER;

/* Update message_size and message_linecount to the accurate count of bytes
written, including added headers. Note; we subtract 1 from message_linecount as
this variable doesn't count the new line between the header and the body of the
message. */

message_size = transport_count;
message_linecount = transport_newlines - 1;

/* If using a maildir++ quota file, add this message's size to it, and
close the file descriptor, except when the quota has been disabled because we
are delivering into an uncounted folder. */

#ifdef SUPPORT_MAILDIR
if (!disable_quota)
  {
  if (yield == OK && maildirsize_fd >= 0)
    maildir_record_length(maildirsize_fd, message_size);
  maildir_save_errno = errno;    /* Preserve errno while closing the file */
  if (maildirsize_fd >= 0)
    (void)close(maildirsize_fd);
  errno = maildir_save_errno;
  }
#endif  /* SUPPORT_MAILDIR */

/* If there is a quota warning threshold and we are have crossed it with this
message, set the SPECIAL_WARN flag in the address, to cause a warning message
to be sent. */

if (!disable_quota && THRESHOLD_CHECK)
  {
  off_t threshold = ob->quota_warn_threshold_value;
  if (ob->quota_warn_threshold_is_percent)
    threshold = (off_t)(((double)ob->quota_value * threshold) / 100);
  DEBUG(D_transport)
    debug_printf("quota = " OFF_T_FMT
      " threshold = " OFF_T_FMT
      " old size = " OFF_T_FMT
      " message size = %d\n",
      ob->quota_value, threshold, mailbox_size,
      message_size);
  if (mailbox_size <= threshold && mailbox_size + message_size > threshold)
    addr->special_action = SPECIAL_WARN;

  /******* You might think that the test ought to be this:
  *
  * if (ob->quota_value > 0 && threshold > 0 && mailbox_size > 0 &&
  *     mailbox_size <= threshold && mailbox_size + message_size > threshold)
  *
  * (indeed, I was sent a patch with that in). However, it is possible to
  * have a warning threshold without actually imposing a quota, and I have
  * therefore kept Exim backwards compatible.
  ********/

  }

/* Handle error while writing the file. Control should come here directly after
the error, with the reason in errno. In the case of expansion failure in prefix
or suffix, it will be ERRNO_EXPANDFAIL. */

if (yield != OK)
  {
  addr->special_action = SPECIAL_NONE;     /* Cancel any quota warning */

  /* Save the error number. If positive, it will ultimately cause a strerror()
  call to generate some text. */

  addr->basic_errno = errno;

  /* For system or Exim quota excession, or disk full, set more_errno to the
  time since the file was last read. If delivery was into a directory, the
  time since last read logic is not relevant, in general. However, for maildir
  deliveries we can approximate it by looking at the last modified time of the
  "new" subdirectory. Since Exim won't be adding new messages, a change to the
  "new" subdirectory implies that an MUA has moved a message from there to the
  "cur" directory. */

  if (errno == errno_quota || errno == ERRNO_EXIMQUOTA || errno == ENOSPC)
    {
    addr->more_errno = 0;
    if (!isdirectory) addr->more_errno = (int)(time(NULL) - times.actime);

    #ifdef SUPPORT_MAILDIR
    else if (mbformat == mbf_maildir)
      {
      struct stat statbuf;
      if (Ustat("new", &statbuf) < 0)
        {
        DEBUG(D_transport) debug_printf("maildir quota exceeded: "
          "stat error %d for \"new\": %s\n", errno, strerror(errno));
        }
      else   /* Want a repeatable time when in test harness */
        {
        addr->more_errno = f.running_in_test_harness ? 10 :
          (int)time(NULL) - statbuf.st_mtime;
        }
      DEBUG(D_transport)
        debug_printf("maildir: time since \"new\" directory modified = %s\n",
        readconf_printtime(addr->more_errno));
      }
    #endif /* SUPPORT_MAILDIR */
    }

  /* Handle system quota excession. Add an explanatory phrase for the error
  message, since some systems don't have special quota-excession errors,
  and on those that do, "quota" doesn't always mean anything to the user. */

  if (errno == errno_quota)
    {
    #ifndef EDQUOT
    addr->message = string_sprintf("mailbox is full "
      "(quota exceeded while writing to file %s)", filename);
    #else
    addr->message = string_sprintf("mailbox is full");
    #endif  /* EDQUOT */
    addr->user_message = US"mailbox is full";
    DEBUG(D_transport) debug_printf("System quota exceeded for %s%s%s\n",
      dataname,
      isdirectory ? US"" : US": time since file read = ",
      isdirectory ? US"" : readconf_printtime(addr->more_errno));
    }

  /* Handle Exim's own quota-imposition */

  else if (errno == ERRNO_EXIMQUOTA)
    {
    addr->message = string_sprintf("mailbox is full "
      "(MTA-imposed%s quota exceeded while writing to %s)", filecount_msg,
        dataname);
    addr->user_message = US"mailbox is full";
    DEBUG(D_transport) debug_printf("Exim%s quota exceeded for %s%s%s\n",
      filecount_msg, dataname,
      isdirectory ? US"" : US": time since file read = ",
      isdirectory ? US"" : readconf_printtime(addr->more_errno));
    }

  /* Handle a process failure while writing via a filter; the return
  from child_close() is in more_errno. */

  else if (errno == ERRNO_FILTER_FAIL)
    {
    yield = PANIC;
    addr->message = string_sprintf("transport filter process failed (%d) "
      "while writing to %s%s", addr->more_errno, dataname,
      (addr->more_errno == EX_EXECFAILED) ? ": unable to execute command" : "");
    }

  /* Handle failure to expand header changes */

  else if (errno == ERRNO_CHHEADER_FAIL)
    {
    yield = PANIC;
    addr->message =
      string_sprintf("failed to expand headers_add or headers_remove while "
        "writing to %s: %s", dataname, expand_string_message);
    }

  /* Handle failure to complete writing of a data block */

  else if (errno == ERRNO_WRITEINCOMPLETE)
    {
    addr->message = string_sprintf("failed to write data block while "
      "writing to %s", dataname);
    }

  /* Handle length mismatch on MBX copying */

  #ifdef SUPPORT_MBX
  else if (errno == ERRNO_MBXLENGTH)
    {
    addr->message = string_sprintf("length mismatch while copying MBX "
      "temporary file to %s", dataname);
    }
  #endif  /* SUPPORT_MBX */

  /* For other errors, a general-purpose explanation, if the message is
  not already set. */

  else if (addr->message == NULL)
    addr->message = string_sprintf("error while writing to %s", dataname);

  /* For a file, reset the file size to what it was before we started, leaving
  the last modification time unchanged, so it will get reset also. All systems
  investigated so far have ftruncate(), whereas not all have the F_FREESP
  fcntl() call (BSDI & FreeBSD do not). */

  if (!isdirectory && ftruncate(fd, saved_size))
    DEBUG(D_transport) debug_printf("Error resetting file size\n");
  }

/* Handle successful writing - we want the modification time to be now for
appended files. Remove the default backstop error number. For a directory, now
is the time to rename the file with a unique name. As soon as such a name
appears it may get used by another process, so we close the file first and
check that all is well. */

else
  {
  times.modtime = time(NULL);
  addr->basic_errno = 0;

  /* Handle the case of writing to a new file in a directory. This applies
  to all single-file formats - maildir, mailstore, and "smail format". */

  if (isdirectory)
    {
    if (fstat(fd, &statbuf) < 0)
      {
      addr->basic_errno = errno;
      addr->message = string_sprintf("while fstatting opened message file %s",
        filename);
      yield = DEFER;
      }

    else if (close(fd) < 0)
      {
      addr->basic_errno = errno;
      addr->message = string_sprintf("close() error for %s",
        (ob->mailstore_format) ? dataname : filename);
      yield = DEFER;
      }

    /* File is successfully written and closed. Arrange to rename it. For the
    different kinds of single-file delivery, some games can be played with the
    name. The message size is by this time set to the accurate value so that
    its value can be used in expansions. */

    else
      {
      uschar *renamename = newname;
      fd = -1;

      DEBUG(D_transport) debug_printf("renaming temporary file\n");

      /* If there is no rename name set, we are in a non-maildir, non-mailstore
      situation. The name is built by expanding the directory_file option, and
      we make the inode number available for use in this. The expansion was
      checked for syntactic validity above, before we wrote the file.

      We have to be careful here, in case the file name exists. (In the other
      cases, the names used are constructed to be unique.) The rename()
      function just replaces an existing file - we don't want that! So instead
      of calling rename(), we must use link() and unlink().

      In this case, if the link fails because of an existing file, we wait
      for one second and try the expansion again, to see if it produces a
      different value. Do this up to 5 times unless the name stops changing.
      This makes it possible to build values that are based on the time, and
      still cope with races from multiple simultaneous deliveries. */

      if (newname == NULL)
        {
        int i;
        uschar *renameleaf;
        uschar *old_renameleaf = US"";

        for (i = 0; ; sleep(1), i++)
          {
          deliver_inode = statbuf.st_ino;
          renameleaf = expand_string(ob->dirfilename);
          deliver_inode = 0;

          if (renameleaf == NULL)
            {
            addr->transport_return = PANIC;
            addr->message = string_sprintf("Expansion of \"%s\" "
              "(directory_file for %s transport) failed: %s",
              ob->dirfilename, tblock->name, expand_string_message);
            goto RETURN;
            }

          renamename = string_sprintf("%s/%s", path, renameleaf);
          if (Ulink(filename, renamename) < 0)
            {
            DEBUG(D_transport) debug_printf("link failed: %s\n",
              strerror(errno));
            if (errno != EEXIST || i >= 4 ||
                Ustrcmp(renameleaf, old_renameleaf) == 0)
              {
              addr->basic_errno = errno;
              addr->message = string_sprintf("while renaming %s as %s",
                filename, renamename);
              yield = DEFER;
              break;
              }
            old_renameleaf = renameleaf;
            DEBUG(D_transport) debug_printf("%s exists - trying again\n",
              renamename);
            }
          else
            {
            Uunlink(filename);
            filename = NULL;
            break;
            }
          }        /* re-expand loop */
        }          /* not mailstore or maildir */

      /* For maildir and mailstore formats, the new name was created earlier,
      except that for maildir, there is the possibility of adding a "tag" on
      the end of the name by expanding the value of nametag. This usually
      includes a reference to the message size. The expansion of nametag was
      checked above, before the file was opened. It either succeeded, or
      provoked a soft failure. So any failure here can be treated as soft.
      Ignore non-printing characters and / and put a colon at the start if the
      first character is alphanumeric. */

      else
        {
        if (nametag != NULL)
          {
          uschar *iptr = expand_string(nametag);
          if (iptr != NULL)
            {
            uschar *etag = store_get(Ustrlen(iptr) + 2);
            uschar *optr = etag;
            while (*iptr != 0)
              {
              if (mac_isgraph(*iptr) && *iptr != '/')
                {
                if (optr == etag && isalnum(*iptr)) *optr++ = ':';
                *optr++ = *iptr;
                }
              iptr++;
              }
            *optr = 0;
            renamename = string_sprintf("%s%s", newname, etag);
            }
          }

        /* Do the rename. If the name is too long and a tag exists, try again
        without the tag. */

        if (Urename(filename, renamename) < 0 &&
               (nametag == NULL || errno != ENAMETOOLONG ||
               (renamename = newname, Urename(filename, renamename) < 0)))
          {
          addr->basic_errno = errno;
          addr->message = string_sprintf("while renaming %s as %s",
            filename, renamename);
          yield = DEFER;
          }

        /* Rename succeeded */

        else
          {
          DEBUG(D_transport) debug_printf("renamed %s as %s\n", filename,
            renamename);
          filename = dataname = NULL;   /* Prevents attempt to unlink at end */
          }
        }        /* maildir or mailstore */
      }          /* successful write + close */
    }            /* isdirectory */
  }              /* write success */


/* For a file, restore the last access time (atime), and set the modification
time as required - changed if write succeeded, unchanged if not. */

if (!isdirectory) utime(CS filename, &times);

/* Notify comsat if configured to do so. It only makes sense if the configured
file is the one that the comsat daemon knows about. */

if (ob->notify_comsat && yield == OK && deliver_localpart != NULL)
  notify_comsat(deliver_localpart, saved_size);

/* Pass back the final return code in the address structure */

DEBUG(D_transport)
  debug_printf("appendfile yields %d with errno=%d more_errno=%d\n",
    yield, addr->basic_errno, addr->more_errno);

addr->transport_return = yield;

/* Close the file, which will release the fcntl lock. For a directory write it
is closed above, except in cases of error which goto RETURN, when we also need
to remove the original file(s). For MBX locking, if all has gone well, before
closing the file, see if we can get an exclusive lock on it, in which case we
can unlink the /tmp lock file before closing it. This is always a non-blocking
lock; there's no need to wait if we can't get it. If everything has gone right
but close fails, defer the message. Then unlink the lock file, if present. This
point in the code is jumped to from a number of places when errors are
detected, in order to get the file closed and the lock file tidied away. */

RETURN:

#ifdef SUPPORT_MBX
if (mbx_lockfd >= 0)
  {
  if (yield == OK && apply_lock(fd, F_WRLCK, ob->use_fcntl, 0,
      ob->use_flock, 0) >= 0)
    {
    DEBUG(D_transport)
      debug_printf("unlinking MBX lock file %s\n", mbx_lockname);
    Uunlink(mbx_lockname);
    }
  (void)close(mbx_lockfd);
  }
#endif  /* SUPPORT_MBX */

if (fd >= 0 && close(fd) < 0 && yield == OK)
  {
  addr->basic_errno = errno;
  addr->message = string_sprintf("while closing %s", filename);
  addr->transport_return = DEFER;
  }

if (hd >= 0) Uunlink(lockname);

/* We get here with isdirectory and filename set only in error situations. */

if (isdirectory && filename != NULL)
  {
  Uunlink(filename);
  if (dataname != filename) Uunlink(dataname);
  }

/* If wait_for_tick is TRUE, we have done a delivery where the uniqueness of a
file name relies on time + pid. We must not allow the process to finish until
the clock has move on by at least one microsecond. Usually we expect this
already to be the case, but machines keep getting faster... */

if (wait_for_tick) exim_wait_tick(&msg_tv, 1);

/* A return of FALSE means that if there was an error, a common error was
put in the first address of a batch. */

return FALSE;
}

#endif	/*!MACRO_PREDEF*/
/* End of transport/appendfile.c */
