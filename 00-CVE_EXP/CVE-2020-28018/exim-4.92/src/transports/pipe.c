/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "pipe.h"

#ifdef HAVE_SETCLASSRESOURCES
#include <login_cap.h>
#endif



/* Options specific to the pipe transport. They must be in alphabetic
order (note that "_" comes before the lower case letters). Those starting
with "*" are not settable by the user but are used by the option-reading
software for alternative value types. Some options are stored in the transport
instance block so as to be publicly visible; these are flagged with opt_public.
*/

optionlist pipe_transport_options[] = {
  { "allow_commands",    opt_stringptr,
      (void *)offsetof(pipe_transport_options_block, allow_commands) },
  { "batch_id",          opt_stringptr | opt_public,
      (void *)offsetof(transport_instance, batch_id) },
  { "batch_max",         opt_int | opt_public,
      (void *)offsetof(transport_instance, batch_max) },
  { "check_string",      opt_stringptr,
      (void *)offsetof(pipe_transport_options_block, check_string) },
  { "command",           opt_stringptr,
      (void *)offsetof(pipe_transport_options_block, cmd) },
  { "environment",       opt_stringptr,
      (void *)offsetof(pipe_transport_options_block, environment) },
  { "escape_string",     opt_stringptr,
      (void *)offsetof(pipe_transport_options_block, escape_string) },
  { "force_command",         opt_bool,
      (void *)offsetof(pipe_transport_options_block, force_command) },
  { "freeze_exec_fail",  opt_bool,
      (void *)offsetof(pipe_transport_options_block, freeze_exec_fail) },
  { "freeze_signal",     opt_bool,
      (void *)offsetof(pipe_transport_options_block, freeze_signal) },
  { "ignore_status",     opt_bool,
      (void *)offsetof(pipe_transport_options_block, ignore_status) },
  { "log_defer_output",  opt_bool | opt_public,
      (void *)offsetof(transport_instance, log_defer_output) },
  { "log_fail_output",   opt_bool | opt_public,
      (void *)offsetof(transport_instance, log_fail_output) },
  { "log_output",        opt_bool | opt_public,
      (void *)offsetof(transport_instance, log_output) },
  { "max_output",        opt_mkint,
      (void *)offsetof(pipe_transport_options_block, max_output) },
  { "message_prefix",    opt_stringptr,
      (void *)offsetof(pipe_transport_options_block, message_prefix) },
  { "message_suffix",    opt_stringptr,
      (void *)offsetof(pipe_transport_options_block, message_suffix) },
  { "path",              opt_stringptr,
      (void *)offsetof(pipe_transport_options_block, path) },
  { "permit_coredump",   opt_bool,
      (void *)offsetof(pipe_transport_options_block, permit_coredump) },
  { "pipe_as_creator",   opt_bool | opt_public,
      (void *)offsetof(transport_instance, deliver_as_creator) },
  { "restrict_to_path",  opt_bool,
      (void *)offsetof(pipe_transport_options_block, restrict_to_path) },
  { "return_fail_output",opt_bool | opt_public,
      (void *)offsetof(transport_instance, return_fail_output) },
  { "return_output",     opt_bool | opt_public,
      (void *)offsetof(transport_instance, return_output) },
  { "temp_errors",       opt_stringptr,
      (void *)offsetof(pipe_transport_options_block, temp_errors) },
  { "timeout",           opt_time,
      (void *)offsetof(pipe_transport_options_block, timeout) },
  { "timeout_defer",     opt_bool,
      (void *)offsetof(pipe_transport_options_block, timeout_defer) },
  { "umask",             opt_octint,
      (void *)offsetof(pipe_transport_options_block, umask) },
  { "use_bsmtp",         opt_bool,
      (void *)offsetof(pipe_transport_options_block, use_bsmtp) },
  #ifdef HAVE_SETCLASSRESOURCES
  { "use_classresources", opt_bool,
      (void *)offsetof(pipe_transport_options_block, use_classresources) },
  #endif
  { "use_crlf",          opt_bool,
      (void *)offsetof(pipe_transport_options_block, use_crlf) },
  { "use_shell",         opt_bool,
      (void *)offsetof(pipe_transport_options_block, use_shell) },
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int pipe_transport_options_count =
  sizeof(pipe_transport_options)/sizeof(optionlist);


#ifdef MACRO_PREDEF

/* Dummy values */
pipe_transport_options_block pipe_transport_option_defaults = {0};
void pipe_transport_init(transport_instance *tblock) {}
BOOL pipe_transport_entry(transport_instance *tblock, address_item *addr) {return FALSE;}

#else   /*!MACRO_PREDEF*/


/* Default private options block for the pipe transport. */

pipe_transport_options_block pipe_transport_option_defaults = {
  NULL,           /* cmd */
  NULL,           /* allow_commands */
  NULL,           /* environment */
  US"/bin:/usr/bin",  /* path */
  NULL,           /* message_prefix (reset in init if not bsmtp) */
  NULL,           /* message_suffix (ditto) */
  US mac_expanded_string(EX_TEMPFAIL) ":"    /* temp_errors */
     mac_expanded_string(EX_CANTCREAT),
  NULL,           /* check_string */
  NULL,           /* escape_string */
  022,            /* umask */
  20480,          /* max_output */
  60*60,          /* timeout */
  0,              /* options */
  FALSE,          /* force_command */
  FALSE,          /* freeze_exec_fail */
  FALSE,          /* freeze_signal */
  FALSE,          /* ignore_status */
  FALSE,          /* permit_coredump */
  FALSE,          /* restrict_to_path */
  FALSE,          /* timeout_defer */
  FALSE,          /* use_shell */
  FALSE,          /* use_bsmtp */
  FALSE,          /* use_classresources */
  FALSE           /* use_crlf */
};



/*************************************************
*              Setup entry point                 *
*************************************************/

/* Called for each delivery in the privileged state, just before the uid/gid
are changed and the main entry point is called. In a system that supports the
login_cap facilities, this function is used to set the class resource limits
for the user.  It may also re-enable coredumps.

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
pipe_transport_setup(transport_instance *tblock, address_item *addrlist,
  transport_feedback *dummy, uid_t uid, gid_t gid, uschar **errmsg)
{
pipe_transport_options_block *ob =
  (pipe_transport_options_block *)(tblock->options_block);

addrlist = addrlist;  /* Keep compiler happy */
dummy = dummy;
uid = uid;
gid = gid;
errmsg = errmsg;
ob = ob;

#ifdef HAVE_SETCLASSRESOURCES
if (ob->use_classresources)
  {
  struct passwd *pw = getpwuid(uid);
  if (pw != NULL)
    {
    login_cap_t *lc = login_getpwclass(pw);
    if (lc != NULL)
      {
      setclassresources(lc);
      login_close(lc);
      }
    }
  }
#endif

#ifdef RLIMIT_CORE
if (ob->permit_coredump)
  {
  struct rlimit rl;
  rl.rlim_cur = RLIM_INFINITY;
  rl.rlim_max = RLIM_INFINITY;
  if (setrlimit(RLIMIT_CORE, &rl) < 0)
    {
#ifdef SETRLIMIT_NOT_SUPPORTED
    if (errno != ENOSYS && errno != ENOTSUP)
#endif
      log_write(0, LOG_MAIN,
          "delivery setrlimit(RLIMIT_CORE, RLIM_INFINITY) failed: %s",
          strerror(errno));
    }
  }
#endif

return OK;
}



/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */

void
pipe_transport_init(transport_instance *tblock)
{
pipe_transport_options_block *ob =
  (pipe_transport_options_block *)(tblock->options_block);

/* Set up the setup entry point, to be called in the privileged state */

tblock->setup = pipe_transport_setup;

/* If pipe_as_creator is set, then uid/gid should not be set. */

if (tblock->deliver_as_creator && (tblock->uid_set || tblock->gid_set ||
  tblock->expand_uid != NULL || tblock->expand_gid != NULL))
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
      "both pipe_as_creator and an explicit uid/gid are set for the %s "
        "transport", tblock->name);

/* If a fixed uid field is set, then a gid field must also be set. */

if (tblock->uid_set && !tblock->gid_set && tblock->expand_gid == NULL)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
    "user set without group for the %s transport", tblock->name);

/* Temp_errors must consist only of digits and colons, but there can be
spaces round the colons, so allow them too. */

if (ob->temp_errors != NULL && Ustrcmp(ob->temp_errors, "*") != 0)
  {
  size_t p = Ustrspn(ob->temp_errors, "0123456789: ");
  if (ob->temp_errors[p] != 0)
    log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
      "temp_errors must be a list of numbers or an asterisk for the %s "
      "transport", tblock->name);
  }

/* Only one of return_output/return_fail_output or log_output/log_fail_output
should be set. */

if (tblock->return_output && tblock->return_fail_output)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
    "both return_output and return_fail_output set for %s transport",
    tblock->name);

if (tblock->log_output && tblock->log_fail_output)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
    "both log_output and log_fail_output set for the %s transport",
    tblock->name);

/* If batch SMTP is set, force the check and escape strings, and arrange that
headers are also escaped. */

if (ob->use_bsmtp)
  {
  ob->check_string = US".";
  ob->escape_string = US"..";
  ob->options |= topt_escape_headers;
  }

/* If not batch SMTP, and message_prefix or message_suffix are unset, insert
default values for them. */

else
  {
  if (ob->message_prefix == NULL) ob->message_prefix =
    US"From ${if def:return_path{$return_path}{MAILER-DAEMON}} ${tod_bsdinbox}\n";
  if (ob->message_suffix == NULL) ob->message_suffix = US"\n";
  }

/* The restrict_to_path  and use_shell options are incompatible */

if (ob->restrict_to_path && ob->use_shell)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
    "both restrict_to_path and use_shell set for %s transport",
    tblock->name);

/* The allow_commands and use_shell options are incompatible */

if (ob->allow_commands && ob->use_shell)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
    "both allow_commands and use_shell set for %s transport",
    tblock->name);

/* Set up the bitwise options for transport_write_message from the various
driver options. Only one of body_only and headers_only can be set. */

ob->options |=
  (tblock->body_only? topt_no_headers : 0) |
  (tblock->headers_only? topt_no_body : 0) |
  (tblock->return_path_add? topt_add_return_path : 0) |
  (tblock->delivery_date_add? topt_add_delivery_date : 0) |
  (tblock->envelope_to_add? topt_add_envelope_to : 0) |
  (ob->use_crlf? topt_use_crlf : 0);
}



/*************************************************
*          Set up direct (non-shell) command     *
*************************************************/

/* This function is called when a command line is to be parsed by the transport
and executed directly, without the use of /bin/sh.

Arguments:
  argvptr            pointer to anchor for argv vector
  cmd                points to the command string
  expand_arguments   true if expansion is to occur
  expand_fail        error if expansion fails
  addr               chain of addresses
  tname              the transport name
  ob                 the transport options block

Returns:             TRUE if all went well; otherwise an error will be
                     set in the first address and FALSE returned
*/

static BOOL
set_up_direct_command(const uschar ***argvptr, uschar *cmd,
  BOOL expand_arguments, int expand_fail, address_item *addr, uschar *tname,
  pipe_transport_options_block *ob)
{
BOOL permitted = FALSE;
const uschar **argv;

/* Set up "transport <name>" to be put in any error messages, and then
call the common function for creating an argument list and expanding
the items if necessary. If it fails, this function fails (error information
is in the addresses). */

if (!transport_set_up_command(argvptr, cmd, expand_arguments, expand_fail,
      addr, string_sprintf("%.50s transport", tname), NULL))
  return FALSE;

/* Point to the set-up arguments. */

argv = *argvptr;

/* If allow_commands is set, see if the command is in the permitted list. */

if (ob->allow_commands)
  {
  int sep = 0;
  const uschar *s;
  uschar *p;

  if (!(s = expand_string(ob->allow_commands)))
    {
    addr->transport_return = DEFER;
    addr->message = string_sprintf("failed to expand string \"%s\" "
      "for %s transport: %s", ob->allow_commands, tname, expand_string_message);
    return FALSE;
    }

  while ((p = string_nextinlist(&s, &sep, NULL, 0)))
    if (Ustrcmp(p, argv[0]) == 0) { permitted = TRUE; break; }
  }

/* If permitted is TRUE it means the command was found in the allowed list, and
no further checks are done. If permitted = FALSE, it either means
allow_commands wasn't set, or that the command didn't match anything in the
list. In both cases, if restrict_to_path is set, we fail if the command
contains any slashes, but if restrict_to_path is not set, we must fail the
command only if allow_commands is set. */

if (!permitted)
  {
  if (ob->restrict_to_path)
    {
    if (Ustrchr(argv[0], '/') != NULL)
      {
      addr->transport_return = FAIL;
      addr->message = string_sprintf("\"/\" found in \"%s\" (command for %s "
        "transport) - failed for security reasons", cmd, tname);
      return FALSE;
      }
    }

  else if (ob->allow_commands)
    {
    addr->transport_return = FAIL;
    addr->message = string_sprintf("\"%s\" command not permitted by %s "
      "transport", argv[0], tname);
    return FALSE;
    }
  }

/* If the command is not an absolute path, search the PATH directories
for it. */

if (argv[0][0] != '/')
  {
  int sep = 0;
  uschar *p;
  const uschar *listptr = expand_string(ob->path);

  while ((p = string_nextinlist(&listptr, &sep, NULL, 0)))
    {
    struct stat statbuf;
    sprintf(CS big_buffer, "%.256s/%.256s", p, argv[0]);
    if (Ustat(big_buffer, &statbuf) == 0)
      {
      argv[0] = string_copy(big_buffer);
      break;
      }
    }
  if (!p)
    {
    addr->transport_return = FAIL;
    addr->message = string_sprintf("\"%s\" command not found for %s transport",
      argv[0], tname);
    return FALSE;
    }
  }

return TRUE;
}


/*************************************************
*               Set up shell command             *
*************************************************/

/* This function is called when a command line is to be passed to /bin/sh
without parsing inside the transport.

Arguments:
  argvptr            pointer to anchor for argv vector
  cmd                points to the command string
  expand_arguments   true if expansion is to occur
  expand_fail        error if expansion fails
  addr               chain of addresses
  tname              the transport name

Returns:             TRUE if all went well; otherwise an error will be
                     set in the first address and FALSE returned
*/

static BOOL
set_up_shell_command(const uschar ***argvptr, uschar *cmd,
  BOOL expand_arguments, int expand_fail, address_item *addr, uschar *tname)
{
const uschar **argv;

*argvptr = argv = store_get((4)*sizeof(uschar *));

argv[0] = US"/bin/sh";
argv[1] = US"-c";

/* We have to take special action to handle the special "variable" called
$pipe_addresses, which is not recognized by the normal expansion function. */

if (expand_arguments)
  {
  uschar * p = Ustrstr(cmd, "pipe_addresses");
  gstring * g = NULL;

  DEBUG(D_transport)
    debug_printf("shell pipe command before expansion:\n  %s\n", cmd);

  /* Allow $recipients in the expansion iff it comes from a system filter */

  f.enable_dollar_recipients = addr && addr->parent &&
    Ustrcmp(addr->parent->address, "system-filter") == 0;

  if (p != NULL && (
         (p > cmd && p[-1] == '$') ||
         (p > cmd + 1 && p[-2] == '$' && p[-1] == '{' && p[14] == '}')))
    {
    address_item *ad;
    uschar *q = p + 14;

    if (p[-1] == '{') { q++; p--; }

    g = string_get(Ustrlen(cmd) + 64);
    g = string_catn(g, cmd, p - cmd - 1);

    for (ad = addr; ad; ad = ad->next)
      {
      /*XXX string_append_listele() ? */
      if (ad != addr) g = string_catn(g, US" ", 1);
      g = string_cat(g, ad->address);
      }

    g = string_cat(g, q);
    argv[2] = (cmd = string_from_gstring(g)) ? expand_string(cmd) : NULL;
    }
  else
    argv[2] = expand_string(cmd);

  f.enable_dollar_recipients = FALSE;

  if (!argv[2])
    {
    addr->transport_return = f.search_find_defer ? DEFER : expand_fail;
    addr->message = string_sprintf("Expansion of command \"%s\" "
      "in %s transport failed: %s",
      cmd, tname, expand_string_message);
    return FALSE;
    }

  DEBUG(D_transport)
    debug_printf("shell pipe command after expansion:\n  %s\n", argv[2]);
  }
else
  {
  DEBUG(D_transport)
    debug_printf("shell pipe command (no expansion):\n  %s\n", cmd);
  argv[2] = cmd;
  }

argv[3] = US 0;
return TRUE;
}




/*************************************************
*              Main entry point                  *
*************************************************/

/* See local README for interface details. This transport always returns FALSE,
indicating that the status in the first address is the status for all addresses
in a batch. */

BOOL
pipe_transport_entry(
  transport_instance *tblock,      /* data for this instantiation */
  address_item *addr)              /* address(es) we are working on */
{
pid_t pid, outpid;
int fd_in, fd_out, rc;
int envcount = 0;
int envsep = 0;
int expand_fail;
pipe_transport_options_block *ob =
  (pipe_transport_options_block *)(tblock->options_block);
int timeout = ob->timeout;
BOOL written_ok = FALSE;
BOOL expand_arguments;
const uschar **argv;
uschar *envp[50];
const uschar *envlist = ob->environment;
uschar *cmd, *ss;
uschar *eol = ob->use_crlf ? US"\r\n" : US"\n";
transport_ctx tctx = {
  .tblock = tblock,
  .addr = addr,
  .check_string = ob->check_string,
  .escape_string = ob->escape_string,
  ob->options | topt_not_socket /* set at initialization time */
};

DEBUG(D_transport) debug_printf("%s transport entered\n", tblock->name);

/* Set up for the good case */

addr->transport_return = OK;
addr->basic_errno = 0;

/* Pipes are not accepted as general addresses, but they can be generated from
.forward files or alias files. In those cases, the pfr flag is set, and the
command to be obeyed is pointed to by addr->local_part; it starts with the pipe
symbol. In other cases, the command is supplied as one of the pipe transport's
options. */

if (testflag(addr, af_pfr) && addr->local_part[0] == '|')
  {
  if (ob->force_command)
    {
    /* Enables expansion of $address_pipe into separate arguments */
    setflag(addr, af_force_command);
    cmd = ob->cmd;
    expand_arguments = TRUE;
    expand_fail = PANIC;
    }
  else
    {
    cmd = addr->local_part + 1;
    while (isspace(*cmd)) cmd++;
    expand_arguments = testflag(addr, af_expand_pipe);
    expand_fail = FAIL;
    }
  }
else
  {
  cmd = ob->cmd;
  expand_arguments = TRUE;
  expand_fail = PANIC;
  }

/* If no command has been supplied, we are in trouble.
 * We also check for an empty string since it may be
 * coming from addr->local_part[0] == '|'
 */

if (cmd == NULL || *cmd == '\0')
  {
  addr->transport_return = DEFER;
  addr->message = string_sprintf("no command specified for %s transport",
    tblock->name);
  return FALSE;
  }

/* When a pipe is set up by a filter file, there may be values for $thisaddress
and numerical the variables in existence. These are passed in
addr->pipe_expandn for use here. */

if (expand_arguments && addr->pipe_expandn)
  {
  uschar **ss = addr->pipe_expandn;
  expand_nmax = -1;
  if (*ss != NULL) filter_thisaddress = *ss++;
  while (*ss != NULL)
    {
    expand_nstring[++expand_nmax] = *ss;
    expand_nlength[expand_nmax] = Ustrlen(*ss++);
    }
  }

/* The default way of processing the command is to split it up into arguments
here, and run it directly. This offers some security advantages. However, there
are installations that want by default to run commands under /bin/sh always, so
there is an option to do that. */

if (ob->use_shell)
  {
  if (!set_up_shell_command(&argv, cmd, expand_arguments, expand_fail, addr,
    tblock->name)) return FALSE;
  }
else if (!set_up_direct_command(&argv, cmd, expand_arguments, expand_fail, addr,
  tblock->name, ob)) return FALSE;

expand_nmax = -1;           /* Reset */
filter_thisaddress = NULL;

/* Set up the environment for the command. */

envp[envcount++] = string_sprintf("LOCAL_PART=%s", deliver_localpart);
envp[envcount++] = string_sprintf("LOGNAME=%s", deliver_localpart);
envp[envcount++] = string_sprintf("USER=%s", deliver_localpart);
envp[envcount++] = string_sprintf("LOCAL_PART_PREFIX=%#s",
  deliver_localpart_prefix);
envp[envcount++] = string_sprintf("LOCAL_PART_SUFFIX=%#s",
  deliver_localpart_suffix);
envp[envcount++] = string_sprintf("DOMAIN=%s", deliver_domain);
envp[envcount++] = string_sprintf("HOME=%#s", deliver_home);
envp[envcount++] = string_sprintf("MESSAGE_ID=%s", message_id);
envp[envcount++] = string_sprintf("PATH=%s", expand_string(ob->path));
envp[envcount++] = string_sprintf("RECIPIENT=%#s%#s%#s@%#s",
  deliver_localpart_prefix, deliver_localpart, deliver_localpart_suffix,
  deliver_domain);
envp[envcount++] = string_sprintf("QUALIFY_DOMAIN=%s", qualify_domain_sender);
envp[envcount++] = string_sprintf("SENDER=%s", sender_address);
envp[envcount++] = US"SHELL=/bin/sh";

if (addr->host_list != NULL)
  envp[envcount++] = string_sprintf("HOST=%s", addr->host_list->name);

if (f.timestamps_utc) envp[envcount++] = US"TZ=UTC";
else if (timezone_string != NULL && timezone_string[0] != 0)
  envp[envcount++] = string_sprintf("TZ=%s", timezone_string);

/* Add any requested items */

if (envlist)
  {
  envlist = expand_cstring(envlist);
  if (envlist == NULL)
    {
    addr->transport_return = DEFER;
    addr->message = string_sprintf("failed to expand string \"%s\" "
      "for %s transport: %s", ob->environment, tblock->name,
      expand_string_message);
    return FALSE;
    }
  }

while ((ss = string_nextinlist(&envlist, &envsep, big_buffer, big_buffer_size)))
   {
   if (envcount > nelem(envp) - 2)
     {
     addr->transport_return = DEFER;
     addr->message = string_sprintf("too many environment settings for "
       "%s transport", tblock->name);
     return FALSE;
     }
   envp[envcount++] = string_copy(ss);
   }

envp[envcount] = NULL;

/* If the -N option is set, can't do any more. */

if (f.dont_deliver)
  {
  DEBUG(D_transport)
    debug_printf("*** delivery by %s transport bypassed by -N option",
      tblock->name);
  return FALSE;
  }


/* Handling the output from the pipe is tricky. If a file for catching this
output is provided, we could in theory just hand that fd over to the process,
but this isn't very safe because it might loop and carry on writing for
ever (which is exactly what happened in early versions of Exim). Therefore we
use the standard child_open() function, which creates pipes. We can then read
our end of the output pipe and count the number of bytes that come through,
chopping the sub-process if it exceeds some limit.

However, this means we want to run a sub-process with both its input and output
attached to pipes. We can't handle that easily from a single parent process
using straightforward code such as the transport_write_message() function
because the subprocess might not be reading its input because it is trying to
write to a full output pipe. The complication of redesigning the world to
handle this is too great - simpler just to run another process to do the
reading of the output pipe. */


/* As this is a local transport, we are already running with the required
uid/gid and current directory. Request that the new process be a process group
leader, so we can kill it and all its children on a timeout. */

if ((pid = child_open(USS argv, envp, ob->umask, &fd_in, &fd_out, TRUE)) < 0)
  {
  addr->transport_return = DEFER;
  addr->message = string_sprintf(
    "Failed to create child process for %s transport: %s", tblock->name,
      strerror(errno));
  return FALSE;
  }
tctx.u.fd = fd_in;

/* Now fork a process to handle the output that comes down the pipe. */

if ((outpid = fork()) < 0)
  {
  addr->basic_errno = errno;
  addr->transport_return = DEFER;
  addr->message = string_sprintf(
    "Failed to create process for handling output in %s transport",
      tblock->name);
  (void)close(fd_in);
  (void)close(fd_out);
  return FALSE;
  }

/* This is the code for the output-handling subprocess. Read from the pipe
in chunks, and write to the return file if one is provided. Keep track of
the number of bytes handled. If the limit is exceeded, try to kill the
subprocess group, and in any case close the pipe and exit, which should cause
the subprocess to fail. */

if (outpid == 0)
  {
  int count = 0;
  (void)close(fd_in);
  set_process_info("reading output from |%s", cmd);
  while ((rc = read(fd_out, big_buffer, big_buffer_size)) > 0)
    {
    if (addr->return_file >= 0)
      if(write(addr->return_file, big_buffer, rc) != rc)
        DEBUG(D_transport) debug_printf("Problem writing to return_file\n");
    count += rc;
    if (count > ob->max_output)
      {
      DEBUG(D_transport) debug_printf("Too much output from pipe - killed\n");
      if (addr->return_file >= 0)
	{
        uschar *message = US"\n\n*** Too much output - remainder discarded ***\n";
        rc = Ustrlen(message);
        if(write(addr->return_file, message, rc) != rc)
          DEBUG(D_transport) debug_printf("Problem writing to return_file\n");
	}
      killpg(pid, SIGKILL);
      break;
      }
    }
  (void)close(fd_out);
  _exit(0);
  }

(void)close(fd_out);  /* Not used in this process */


/* Carrying on now with the main parent process. Attempt to write the message
to it down the pipe. It is a fallacy to think that you can detect write errors
when the sub-process fails to read the pipe. The parent process may complete
writing and close the pipe before the sub-process completes. We could sleep a
bit here to let the sub-process get going, but it may still not complete. So we
ignore all writing errors. (When in the test harness, we do do a short sleep so
any debugging output is likely to be in the same order.) */

if (f.running_in_test_harness) millisleep(500);

DEBUG(D_transport) debug_printf("Writing message to pipe\n");

/* Arrange to time out writes if there is a timeout set. */

if (timeout > 0)
  {
  sigalrm_seen = FALSE;
  transport_write_timeout = timeout;
  }

/* Reset the counter of bytes written */

transport_count = 0;

/* First write any configured prefix information */

if (ob->message_prefix != NULL)
  {
  uschar *prefix = expand_string(ob->message_prefix);
  if (prefix == NULL)
    {
    addr->transport_return = f.search_find_defer? DEFER : PANIC;
    addr->message = string_sprintf("Expansion of \"%s\" (prefix for %s "
      "transport) failed: %s", ob->message_prefix, tblock->name,
      expand_string_message);
    return FALSE;
    }
  if (!transport_write_block(&tctx, prefix, Ustrlen(prefix), FALSE))
    goto END_WRITE;
  }

/* If the use_bsmtp option is set, we need to write SMTP prefix information.
The various different values for batching are handled outside; if there is more
than one address available here, all must be included. Force SMTP dot-handling.
*/

if (ob->use_bsmtp)
  {
  address_item *a;

  if (!transport_write_string(fd_in, "MAIL FROM:<%s>%s", return_path, eol))
    goto END_WRITE;

  for (a = addr; a; a = a->next)
    if (!transport_write_string(fd_in,
        "RCPT TO:<%s>%s",
        transport_rcpt_address(a, tblock->rcpt_include_affixes),
        eol))
      goto END_WRITE;

  if (!transport_write_string(fd_in, "DATA%s", eol)) goto END_WRITE;
  }

/* Now the actual message */

if (!transport_write_message(&tctx, 0))
    goto END_WRITE;

/* Now any configured suffix */

if (ob->message_suffix)
  {
  uschar *suffix = expand_string(ob->message_suffix);
  if (!suffix)
    {
    addr->transport_return = f.search_find_defer? DEFER : PANIC;
    addr->message = string_sprintf("Expansion of \"%s\" (suffix for %s "
      "transport) failed: %s", ob->message_suffix, tblock->name,
      expand_string_message);
    return FALSE;
    }
  if (!transport_write_block(&tctx, suffix, Ustrlen(suffix), FALSE))
    goto END_WRITE;
  }

/* If local_smtp, write the terminating dot. */

if (ob->use_bsmtp && !transport_write_string(fd_in, ".%s", eol))
  goto END_WRITE;

/* Flag all writing completed successfully. */

written_ok = TRUE;

/* Come here if there are errors during writing. */

END_WRITE:

/* OK, the writing is now all done. Close the pipe. */

(void) close(fd_in);

/* Handle errors during writing. For timeouts, set the timeout for waiting for
the child process to 1 second. If the process at the far end of the pipe died
without reading all of it, we expect an EPIPE error, which should be ignored.
We used also to ignore WRITEINCOMPLETE but the writing function is now cleverer
at handling OS where the death of a pipe doesn't give EPIPE immediately. See
comments therein. */

if (!written_ok)
  {
  if (errno == ETIMEDOUT)
    {
    addr->message = string_sprintf("%stimeout while writing to pipe",
      f.transport_filter_timed_out ? "transport filter " : "");
    addr->transport_return = ob->timeout_defer? DEFER : FAIL;
    timeout = 1;
    }
  else if (errno == EPIPE)
    {
    debug_printf("transport error EPIPE ignored\n");
    }
  else
    {
    addr->transport_return = PANIC;
    addr->basic_errno = errno;
    if (errno == ERRNO_CHHEADER_FAIL)
      addr->message =
        string_sprintf("Failed to expand headers_add or headers_remove: %s",
          expand_string_message);
    else if (errno == ERRNO_FILTER_FAIL)
      addr->message = string_sprintf("Transport filter process failed (%d)%s",
      addr->more_errno,
      (addr->more_errno == EX_EXECFAILED)? ": unable to execute command" : "");
    else if (errno == ERRNO_WRITEINCOMPLETE)
      addr->message = string_sprintf("Failed repeatedly to write data");
    else
      addr->message = string_sprintf("Error %d", errno);
    return FALSE;
    }
  }

/* Wait for the child process to complete and take action if the returned
status is nonzero. The timeout will be just 1 second if any of the writes
above timed out. */

if ((rc = child_close(pid, timeout)) != 0)
  {
  uschar *tmsg = (addr->message == NULL)? US"" :
    string_sprintf(" (preceded by %s)", addr->message);

  /* The process did not complete in time; kill its process group and fail
  the delivery. It appears to be necessary to kill the output process too, as
  otherwise it hangs on for some time if the actual pipe process is sleeping.
  (At least, that's what I observed on Solaris 2.5.1.) Since we are failing
  the delivery, that shouldn't cause any problem. */

  if (rc == -256)
    {
    killpg(pid, SIGKILL);
    kill(outpid, SIGKILL);
    addr->transport_return = ob->timeout_defer? DEFER : FAIL;
    addr->message = string_sprintf("pipe delivery process timed out%s", tmsg);
    }

  /* Wait() failed. */

  else if (rc == -257)
    {
    addr->transport_return = PANIC;
    addr->message = string_sprintf("Wait() failed for child process of %s "
      "transport: %s%s", tblock->name, strerror(errno), tmsg);
    }

  /* Since the transport_filter timed out we assume it has sent the child process
  a malformed or incomplete data stream.  Kill off the child process
  and prevent checking its exit status as it will has probably exited in error.
  This prevents the transport_filter timeout message from getting overwritten
  by the exit error which is not the cause of the problem. */

  else if (f.transport_filter_timed_out)
    {
    killpg(pid, SIGKILL);
    kill(outpid, SIGKILL);
    }

  /* Either the process completed, but yielded a non-zero (necessarily
  positive) status, or the process was terminated by a signal (rc will contain
  the negation of the signal number). Treat killing by signal as failure unless
  status is being ignored. By default, the message is bounced back, unless
  freeze_signal is set, in which case it is frozen instead. */

  else if (rc < 0)
    {
    if (ob->freeze_signal)
      {
      addr->transport_return = DEFER;
      addr->special_action = SPECIAL_FREEZE;
      addr->message = string_sprintf("Child process of %s transport (running "
        "command \"%s\") was terminated by signal %d (%s)%s", tblock->name, cmd,
        -rc, os_strsignal(-rc), tmsg);
      }
    else if (!ob->ignore_status)
      {
      addr->transport_return = FAIL;
      addr->message = string_sprintf("Child process of %s transport (running "
        "command \"%s\") was terminated by signal %d (%s)%s", tblock->name, cmd,
        -rc, os_strsignal(-rc), tmsg);
      }
    }

  /* For positive values (process terminated with non-zero status), we need a
  status code to request deferral. A number of systems contain the following
  line in sysexits.h:

      #define EX_TEMPFAIL 75

  with the description

      EX_TEMPFAIL -- temporary failure, indicating something that
         is not really an error.  In sendmail, this means
         that a mailer (e.g.) could not create a connection,
         and the request should be reattempted later.

  Based on this, we use exit code EX_TEMPFAIL as a default to mean "defer" when
  not ignoring the returned status. However, there is now an option that
  contains a list of temporary codes, with TEMPFAIL and CANTCREAT as defaults.

  Another case that needs special treatment is if execve() failed (typically
  the command that was given is a non-existent path). By default this is
  treated as just another failure, but if freeze_exec_fail is set, the reaction
  is to freeze the message rather than bounce the address. Exim used to signal
  this failure with EX_UNAVAILABLE, which is defined in many systems as

      #define EX_UNAVAILABLE  69

  with the description

      EX_UNAVAILABLE -- A service is unavailable.  This can occur
            if a support program or file does not exist.  This
            can also be used as a catchall message when something
            you wanted to do doesn't work, but you don't know why.

  However, this can be confused with a command that actually returns 69 because
  something *it* wanted is unavailable. At release 4.21, Exim was changed to
  use return code 127 instead, because this is what the shell returns when it
  is unable to exec a command. We define it as EX_EXECFAILED, and use it in
  child.c to signal execve() failure and other unexpected failures such as
  setuid() not working - though that won't be the case here because we aren't
  changing uid. */

  else
    {
    /* Always handle execve() failure specially if requested to */

    if (ob->freeze_exec_fail && (rc == EX_EXECFAILED))
      {
      addr->transport_return = DEFER;
      addr->special_action = SPECIAL_FREEZE;
      addr->message = string_sprintf("pipe process failed to exec \"%s\"%s",
        cmd, tmsg);
      }

    /* Otherwise take action only if not ignoring status */

    else if (!ob->ignore_status)
      {
      uschar *ss;
      gstring * g;
      int i;

      /* If temp_errors is "*" all codes are temporary. Initialization checks
      that it's either "*" or a list of numbers. If not "*", scan the list of
      temporary failure codes; if any match, the result is DEFER. */

      if (ob->temp_errors[0] == '*')
        addr->transport_return = DEFER;

      else
        {
        const uschar *s = ob->temp_errors;
        uschar *p;
        int sep = 0;

        addr->transport_return = FAIL;
        while ((p = string_nextinlist(&s,&sep,NULL,0)))
          if (rc == Uatoi(p)) { addr->transport_return = DEFER; break; }
        }

      /* Ensure the message contains the expanded command and arguments. This
      doesn't have to be brilliantly efficient - it is an error situation. */

      addr->message = string_sprintf("Child process of %s transport returned "
        "%d", tblock->name, rc);
      g = string_cat(NULL, addr->message);

      /* If the return code is > 128, it often means that a shell command
      was terminated by a signal. */

      ss = (rc > 128)?
        string_sprintf("(could mean shell command ended by signal %d (%s))",
          rc-128, os_strsignal(rc-128)) :
        US os_strexit(rc);

      if (*ss != 0)
        {
        g = string_catn(g, US" ", 1);
        g = string_cat (g, ss);
        }

      /* Now add the command and arguments */

      g = string_catn(g, US" from command:", 14);

      for (i = 0; i < sizeof(argv)/sizeof(int *) && argv[i] != NULL; i++)
        {
        BOOL quote = FALSE;
        g = string_catn(g, US" ", 1);
        if (Ustrpbrk(argv[i], " \t") != NULL)
          {
          quote = TRUE;
          g = string_catn(g, US"\"", 1);
          }
        g = string_cat(g, argv[i]);
        if (quote)
          g = string_catn(g, US"\"", 1);
        }

      /* Add previous filter timeout message, if present. */

      if (*tmsg)
        g = string_cat(g, tmsg);

      addr->message = string_from_gstring(g);
      }
    }
  }

/* Ensure all subprocesses (in particular, the output handling process)
are complete before we pass this point. */

while (wait(&rc) >= 0);

DEBUG(D_transport) debug_printf("%s transport yielded %d\n", tblock->name,
  addr->transport_return);

/* If there has been a problem, the message in addr->message contains details
of the pipe command. We don't want to expose these to the world, so we set up
something bland to return to the sender. */

if (addr->transport_return != OK)
  addr->user_message = US"local delivery failed";

return FALSE;
}

#endif	/*!MACRO_PREDEF*/
/* End of transport/pipe.c */
