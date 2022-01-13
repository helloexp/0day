/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* This module contains code for extracting addresses from a forwarding list
(from an alias or forward file) or by running the filter interpreter. It may do
this in a sub-process if a uid/gid are supplied. */


#include "exim.h"

enum { FILE_EXIST, FILE_NOT_EXIST, FILE_EXIST_UNCLEAR };

#define REPLY_EXISTS    0x01
#define REPLY_EXPAND    0x02
#define REPLY_RETURN    0x04


/*************************************************
*         Check string for filter program        *
*************************************************/

/* This function checks whether a string is actually a filter program. The rule
is that it must start with "# Exim filter ..." (any capitalization, spaces
optional). It is envisaged that in future, other kinds of filter may be
implemented. That's why it is implemented the way it is. The function is global
because it is also called from filter.c when checking filters.

Argument:  the string

Returns:   FILTER_EXIM    if it starts with "# Exim filter"
           FILTER_SIEVE   if it starts with "# Sieve filter"
           FILTER_FORWARD otherwise
*/

/* This is an auxiliary function for matching a tag. */

static BOOL
match_tag(const uschar *s, const uschar *tag)
{
for (; *tag != 0; s++, tag++)
  {
  if (*tag == ' ')
    {
    while (*s == ' ' || *s == '\t') s++;
    s--;
    }
  else if (tolower(*s) != tolower(*tag)) break;
  }
return (*tag == 0);
}

/* This is the real function. It should be easy to add checking different
tags for other types of filter. */

int
rda_is_filter(const uschar *s)
{
while (isspace(*s)) s++;     /* Skips initial blank lines */
if (match_tag(s, CUS"# exim filter")) return FILTER_EXIM;
  else if (match_tag(s, CUS"# sieve filter")) return FILTER_SIEVE;
    else return FILTER_FORWARD;
}




/*************************************************
*         Check for existence of file            *
*************************************************/

/* First of all, we stat the file. If this fails, we try to stat the enclosing
directory, because a file in an unmounted NFS directory will look the same as a
non-existent file. It seems that in Solaris 2.6, statting an entry in an
indirect map that is currently unmounted does not cause the mount to happen.
Instead, dummy data is returned, which defeats the whole point of this test.
However, if a stat() is done on some object inside the directory, such as the
"." back reference to itself, then the mount does occur. If an NFS host is
taken offline, it is possible for the stat() to get stuck until it comes back.
To guard against this, stick a timer round it. If we can't access the "."
inside the directory, try the plain directory, just in case that helps.

Argument:
  filename   the file name
  error      for message on error

Returns:     FILE_EXIST          the file exists
             FILE_NOT_EXIST      the file does not exist
             FILE_EXIST_UNCLEAR  cannot determine existence
*/

static int
rda_exists(uschar *filename, uschar **error)
{
int rc, saved_errno;
uschar *slash;
struct stat statbuf;

if ((rc = Ustat(filename, &statbuf)) >= 0) return FILE_EXIST;
saved_errno = errno;

Ustrncpy(big_buffer, filename, big_buffer_size - 3);
sigalrm_seen = FALSE;

if (saved_errno == ENOENT)
  {
  slash = Ustrrchr(big_buffer, '/');
  Ustrcpy(slash+1, ".");

  ALARM(30);
  rc = Ustat(big_buffer, &statbuf);
  if (rc != 0 && errno == EACCES && !sigalrm_seen)
    {
    *slash = 0;
    rc = Ustat(big_buffer, &statbuf);
    }
  saved_errno = errno;
  ALARM_CLR(0);

  DEBUG(D_route) debug_printf("stat(%s)=%d\n", big_buffer, rc);
  }

if (sigalrm_seen || rc != 0)
  {
  *error = string_sprintf("failed to stat %s (%s)", big_buffer,
    sigalrm_seen? "timeout" : strerror(saved_errno));
  return FILE_EXIST_UNCLEAR;
  }

*error = string_sprintf("%s does not exist", filename);
DEBUG(D_route) debug_printf("%s\n", *error);
return FILE_NOT_EXIST;
}



/*************************************************
*     Get forwarding list from a file            *
*************************************************/

/* Open a file and read its entire contents into a block of memory. Certain
opening errors are optionally treated the same as "file does not exist".

ENOTDIR means that something along the line is not a directory: there are
installations that set home directories to be /dev/null for non-login accounts
but in normal circumstances this indicates some kind of configuration error.

EACCES means there's a permissions failure. Some users turn off read permission
on a .forward file to suspend forwarding, but this is probably an error in any
kind of mailing list processing.

The redirect block that contains the file name also contains constraints such
as who may own the file, and mode bits that must not be set. This function is

Arguments:
  rdata       rdirect block, containing file name and constraints
  options     for the RDO_ENOTDIR and RDO_EACCES options
  error       where to put an error message
  yield       what to return from rda_interpret on error

Returns:      pointer to string in store; NULL on error
*/

static uschar *
rda_get_file_contents(redirect_block *rdata, int options, uschar **error,
  int *yield)
{
FILE *fwd;
uschar *filebuf;
uschar *filename = rdata->string;
BOOL uid_ok = !rdata->check_owner;
BOOL gid_ok = !rdata->check_group;
struct stat statbuf;

/* Attempt to open the file. If it appears not to exist, check up on the
containing directory by statting it. If the directory does not exist, we treat
this situation as an error (which will cause delivery to defer); otherwise we
pass back FF_NONEXIST, which causes the redirect router to decline.

However, if the ignore_enotdir option is set (to ignore "something on the
path is not a directory" errors), the right behaviour seems to be not to do the
directory test. */

fwd = Ufopen(filename, "rb");
if (fwd == NULL)
  {
  switch(errno)
    {
    case ENOENT:          /* File does not exist */
    DEBUG(D_route) debug_printf("%s does not exist\n%schecking parent directory\n",
      filename,
      ((options & RDO_ENOTDIR) != 0)? "ignore_enotdir set => skip " : "");
    *yield = (((options & RDO_ENOTDIR) != 0) ||
              rda_exists(filename, error) == FILE_NOT_EXIST)?
      FF_NONEXIST : FF_ERROR;
    return NULL;

    case ENOTDIR:         /* Something on the path isn't a directory */
    if ((options & RDO_ENOTDIR) == 0) goto DEFAULT_ERROR;
    DEBUG(D_route) debug_printf("non-directory on path %s: file assumed not to "
      "exist\n", filename);
    *yield = FF_NONEXIST;
    return NULL;

    case EACCES:           /* Permission denied */
    if ((options & RDO_EACCES) == 0) goto DEFAULT_ERROR;
    DEBUG(D_route) debug_printf("permission denied for %s: file assumed not to "
      "exist\n", filename);
    *yield = FF_NONEXIST;
    return NULL;

    DEFAULT_ERROR:
    default:
    *error = string_open_failed(errno, "%s", filename);
    *yield = FF_ERROR;
    return NULL;
    }
  }

/* Check that we have a regular file. */

if (fstat(fileno(fwd), &statbuf) != 0)
  {
  *error = string_sprintf("failed to stat %s: %s", filename, strerror(errno));
  goto ERROR_RETURN;
  }

if ((statbuf.st_mode & S_IFMT) != S_IFREG)
  {
  *error = string_sprintf("%s is not a regular file", filename);
  goto ERROR_RETURN;
  }

/* Check for unwanted mode bits */

if ((statbuf.st_mode & rdata->modemask) != 0)
  {
  *error = string_sprintf("bad mode (0%o) for %s: 0%o bit(s) unexpected",
    statbuf.st_mode, filename, statbuf.st_mode & rdata->modemask);
  goto ERROR_RETURN;
  }

/* Check the file owner and file group if required to do so. */

if (!uid_ok)
  {
  if (rdata->pw != NULL && statbuf.st_uid == rdata->pw->pw_uid)
    uid_ok = TRUE;
  else if (rdata->owners != NULL)
    {
    int i;
    for (i = 1; i <= (int)(rdata->owners[0]); i++)
      if (rdata->owners[i] == statbuf.st_uid) { uid_ok = TRUE; break; }
    }
  }

if (!gid_ok)
  {
  if (rdata->pw != NULL && statbuf.st_gid == rdata->pw->pw_gid)
    gid_ok = TRUE;
  else if (rdata->owngroups != NULL)
    {
    int i;
    for (i = 1; i <= (int)(rdata->owngroups[0]); i++)
      if (rdata->owngroups[i] == statbuf.st_gid) { gid_ok = TRUE; break; }
    }
  }

if (!uid_ok || !gid_ok)
  {
  *error = string_sprintf("bad %s for %s", uid_ok? "group" : "owner", filename);
  goto ERROR_RETURN;
  }

/* Put an upper limit on the size of the file, just to stop silly people
feeding in ridiculously large files, which can easily be created by making
files that have holes in them. */

if (statbuf.st_size > MAX_FILTER_SIZE)
  {
  *error = string_sprintf("%s is too big (max %d)", filename, MAX_FILTER_SIZE);
  goto ERROR_RETURN;
  }

/* Read the file in one go in order to minimize the time we have it open. */

filebuf = store_get(statbuf.st_size + 1);

if (fread(filebuf, 1, statbuf.st_size, fwd) != statbuf.st_size)
  {
  *error = string_sprintf("error while reading %s: %s",
    filename, strerror(errno));
  goto ERROR_RETURN;
  }
filebuf[statbuf.st_size] = 0;

DEBUG(D_route)
  debug_printf(OFF_T_FMT " bytes read from %s\n", statbuf.st_size, filename);

(void)fclose(fwd);
return filebuf;

/* Return an error: the string is already set up. */

ERROR_RETURN:
*yield = FF_ERROR;
(void)fclose(fwd);
return NULL;
}



/*************************************************
*      Extract info from list or filter          *
*************************************************/

/* This function calls the appropriate function to extract addresses from a
forwarding list, or to run a filter file and get addresses from there.

Arguments:
  rdata                     the redirection block
  options                   the options bits
  include_directory         restrain to this directory
  sieve_vacation_directory  passed to sieve_interpret
  sieve_enotify_mailto_owner passed to sieve_interpret
  sieve_useraddress         passed to sieve_interpret
  sieve_subaddress          passed to sieve_interpret
  generated                 where to hang generated addresses
  error                     for error messages
  eblockp                   for details of skipped syntax errors
                              (NULL => no skip)
  filtertype                set to the filter type:
                              FILTER_FORWARD => a traditional .forward file
                              FILTER_EXIM    => an Exim filter file
                              FILTER_SIEVE   => a Sieve filter file
                            a system filter is always forced to be FILTER_EXIM

Returns:                    a suitable return for rda_interpret()
*/

static int
rda_extract(redirect_block *rdata, int options, uschar *include_directory,
  uschar *sieve_vacation_directory, uschar *sieve_enotify_mailto_owner,
  uschar *sieve_useraddress, uschar *sieve_subaddress,
  address_item **generated, uschar **error, error_block **eblockp,
  int *filtertype)
{
uschar *data;

if (rdata->isfile)
  {
  int yield = 0;
  data = rda_get_file_contents(rdata, options, error, &yield);
  if (data == NULL) return yield;
  }
else data = rdata->string;

*filtertype = f.system_filtering ? FILTER_EXIM : rda_is_filter(data);

/* Filter interpretation is done by a general function that is also called from
the filter testing option (-bf). There are two versions: one for Exim filtering
and one for Sieve filtering. Several features of string expansion may be locked
out at sites that don't trust users. This is done by setting flags in
expand_forbid that the expander inspects. */

if (*filtertype != FILTER_FORWARD)
  {
  int frc;
  int old_expand_forbid = expand_forbid;

  DEBUG(D_route) debug_printf("data is %s filter program\n",
    (*filtertype == FILTER_EXIM)? "an Exim" : "a Sieve");

  /* RDO_FILTER is an "allow" bit */

  if ((options & RDO_FILTER) == 0)
    {
    *error = US"filtering not enabled";
    return FF_ERROR;
    }

  expand_forbid =
    (expand_forbid & ~RDO_FILTER_EXPANSIONS) |
    (options & RDO_FILTER_EXPANSIONS);

  /* RDO_{EXIM,SIEVE}_FILTER are forbid bits */

  if (*filtertype == FILTER_EXIM)
    {
    if ((options & RDO_EXIM_FILTER) != 0)
      {
      *error = US"Exim filtering not enabled";
      return FF_ERROR;
      }
    frc = filter_interpret(data, options, generated, error);
    }
  else
    {
    if ((options & RDO_SIEVE_FILTER) != 0)
      {
      *error = US"Sieve filtering not enabled";
      return FF_ERROR;
      }
    frc = sieve_interpret(data, options, sieve_vacation_directory,
      sieve_enotify_mailto_owner, sieve_useraddress, sieve_subaddress,
      generated, error);
    }

  expand_forbid = old_expand_forbid;
  return frc;
  }

/* Not a filter script */

DEBUG(D_route) debug_printf("file is not a filter file\n");

return parse_forward_list(data,
  options,                           /* specials that are allowed */
  generated,                         /* where to hang them */
  error,                             /* for errors */
  deliver_domain,                    /* to qualify \name */
  include_directory,                 /* restrain to directory */
  eblockp);                          /* for skipped syntax errors */
}




/*************************************************
*         Write string down pipe                 *
*************************************************/

/* This function is used for transferring a string down a pipe between
processes. If the pointer is NULL, a length of zero is written.

Arguments:
  fd         the pipe
  s          the string

Returns:     -1 on error, else 0
*/

static int
rda_write_string(int fd, const uschar *s)
{
int len = (s == NULL)? 0 : Ustrlen(s) + 1;
return (  write(fd, &len, sizeof(int)) != sizeof(int)
       || (s != NULL  &&  write(fd, s, len) != len)
       )
       ? -1 : 0;
}



/*************************************************
*          Read string from pipe                 *
*************************************************/

/* This function is used for receiving a string from a pipe.

Arguments:
  fd         the pipe
  sp         where to put the string

Returns:     FALSE if data missing
*/

static BOOL
rda_read_string(int fd, uschar **sp)
{
int len;

if (read(fd, &len, sizeof(int)) != sizeof(int)) return FALSE;
if (len == 0)
  *sp = NULL;
else
  /* We know we have enough memory so disable the error on "len" */
  /* coverity[tainted_data] */
  if (read(fd, *sp = store_get(len), len) != len) return FALSE;
return TRUE;
}



/*************************************************
*         Interpret forward list or filter       *
*************************************************/

/* This function is passed a forward list string (unexpanded) or the name of a
file (unexpanded) whose contents are the forwarding list. The list may in fact
be a filter program if it starts with "#Exim filter" or "#Sieve filter". Other
types of filter, with different initial tag strings, may be introduced in due
course.

The job of the function is to process the forwarding list or filter. It is
pulled out into this separate function, because it is used for system filter
files as well as from the redirect router.

If the function is given a uid/gid, it runs a subprocess that passes the
results back via a pipe. This provides security for things like :include:s in
users' .forward files, and "logwrite" calls in users' filter files. A
sub-process is NOT used when:

  . No uid/gid is provided
  . The input is a string which is not a filter string, and does not contain
    :include:
  . The input is a file whose non-existence can be detected in the main
    process (which is usually running as root).

Arguments:
  rdata                     redirect data (file + constraints, or data string)
  options                   options to pass to the extraction functions,
                              plus ENOTDIR and EACCES handling bits
  include_directory         restrain :include: to this directory
  sieve_vacation_directory  directory passed to sieve_interpret
  sieve_enotify_mailto_owner passed to sieve_interpret
  sieve_useraddress         passed to sieve_interpret
  sieve_subaddress          passed to sieve_interpret
  ugid                      uid/gid to run under - if NULL, no change
  generated                 where to hang generated addresses, initially NULL
  error                     pointer for error message
  eblockp                   for skipped syntax errors; NULL if no skipping
  filtertype                set to the type of file:
                              FILTER_FORWARD => traditional .forward file
                              FILTER_EXIM    => an Exim filter file
                              FILTER_SIEVE   => a Sieve filter file
                            a system filter is always forced to be FILTER_EXIM
  rname                     router name for error messages in the format
                              "xxx router" or "system filter"

Returns:        values from extraction function, or FF_NONEXIST:
                  FF_DELIVERED     success, a significant action was taken
                  FF_NOTDELIVERED  success, no significant action
                  FF_BLACKHOLE     :blackhole:
                  FF_DEFER         defer requested
                  FF_FAIL          fail requested
                  FF_INCLUDEFAIL   some problem with :include:
                  FF_FREEZE        freeze requested
                  FF_ERROR         there was a problem
                  FF_NONEXIST      the file does not exist
*/

int
rda_interpret(redirect_block *rdata, int options, uschar *include_directory,
  uschar *sieve_vacation_directory, uschar *sieve_enotify_mailto_owner,
  uschar *sieve_useraddress, uschar *sieve_subaddress, ugid_block *ugid,
  address_item **generated, uschar **error, error_block **eblockp,
  int *filtertype, uschar *rname)
{
int fd, rc, pfd[2];
int yield, status;
BOOL had_disaster = FALSE;
pid_t pid;
uschar *data;
uschar *readerror = US"";
void (*oldsignal)(int);

DEBUG(D_route) debug_printf("rda_interpret (%s): %s\n",
  (rdata->isfile)? "file" : "string", rdata->string);

/* Do the expansions of the file name or data first, while still privileged. */

data = expand_string(rdata->string);
if (data == NULL)
  {
  if (f.expand_string_forcedfail) return FF_NOTDELIVERED;
  *error = string_sprintf("failed to expand \"%s\": %s", rdata->string,
    expand_string_message);
  return FF_ERROR;
  }
rdata->string = data;

DEBUG(D_route) debug_printf("expanded: %s\n", data);

if (rdata->isfile && data[0] != '/')
  {
  *error = string_sprintf("\"%s\" is not an absolute path", data);
  return FF_ERROR;
  }

/* If no uid/gid are supplied, or if we have a data string which does not start
with #Exim filter or #Sieve filter, and does not contain :include:, do all the
work in this process. Note that for a system filter, we always have a file, so
the work is done in this process only if no user is supplied. */

if (!ugid->uid_set ||                         /* Either there's no uid, or */
    (!rdata->isfile &&                        /* We've got the data, and */
     rda_is_filter(data) == FILTER_FORWARD && /* It's not a filter script, */
     Ustrstr(data, ":include:") == NULL))     /* and there's no :include: */
  {
  return rda_extract(rdata, options, include_directory,
    sieve_vacation_directory, sieve_enotify_mailto_owner, sieve_useraddress,
    sieve_subaddress, generated, error, eblockp, filtertype);
  }

/* We need to run the processing code in a sub-process. However, if we can
determine the non-existence of a file first, we can decline without having to
create the sub-process. */

if (rdata->isfile && rda_exists(data, error) == FILE_NOT_EXIST)
  return FF_NONEXIST;

/* If the file does exist, or we can't tell (non-root mounted NFS directory)
we have to create the subprocess to do everything as the given user. The
results of processing are passed back via a pipe. */

if (pipe(pfd) != 0)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "creation of pipe for filter or "
    ":include: failed for %s: %s", rname, strerror(errno));

/* Ensure that SIGCHLD is set to SIG_DFL before forking, so that the child
process can be waited for. We sometimes get here with it set otherwise. Save
the old state for resetting on the wait. Ensure that all cached resources are
freed so that the subprocess starts with a clean slate and doesn't interfere
with the parent process. */

oldsignal = signal(SIGCHLD, SIG_DFL);
search_tidyup();

if ((pid = fork()) == 0)
  {
  header_line *waslast = header_last;   /* Save last header */

  fd = pfd[pipe_write];
  (void)close(pfd[pipe_read]);
  exim_setugid(ugid->uid, ugid->gid, FALSE, rname);

  /* Addresses can get rewritten in filters; if we are not root or the exim
  user (and we probably are not), turn off rewrite logging, because we cannot
  write to the log now. */

  if (ugid->uid != root_uid && ugid->uid != exim_uid)
    {
    DEBUG(D_rewrite) debug_printf("turned off address rewrite logging (not "
      "root or exim in this process)\n");
    BIT_CLEAR(log_selector, log_selector_size, Li_address_rewrite);
    }

  /* Now do the business */

  yield = rda_extract(rdata, options, include_directory,
    sieve_vacation_directory, sieve_enotify_mailto_owner, sieve_useraddress,
    sieve_subaddress, generated, error, eblockp, filtertype);

  /* Pass back whether it was a filter, and the return code and any overall
  error text via the pipe. */

  if (  write(fd, filtertype, sizeof(int)) != sizeof(int)
     || write(fd, &yield, sizeof(int)) != sizeof(int)
     || rda_write_string(fd, *error) != 0
     )
    goto bad;

  /* Pass back the contents of any syntax error blocks if we have a pointer */

  if (eblockp != NULL)
    {
    error_block *ep;
    for (ep = *eblockp; ep != NULL; ep = ep->next)
      if (  rda_write_string(fd, ep->text1) != 0
         || rda_write_string(fd, ep->text2) != 0
	 )
	goto bad;
    if (rda_write_string(fd, NULL) != 0)    /* Indicates end of eblocks */
      goto bad;
    }

  /* If this is a system filter, we have to pass back the numbers of any
  original header lines that were removed, and then any header lines that were
  added but not subsequently removed. */

  if (f.system_filtering)
    {
    int i = 0;
    header_line *h;
    for (h = header_list; h != waslast->next; i++, h = h->next)
      if (  h->type == htype_old
         && write(fd, &i, sizeof(i)) != sizeof(i)
	 )
	goto bad;

    i = -1;
    if (write(fd, &i, sizeof(i)) != sizeof(i))
	goto bad;

    while (waslast != header_last)
      {
      waslast = waslast->next;
      if (waslast->type != htype_old)
	if (  rda_write_string(fd, waslast->text) != 0
           || write(fd, &(waslast->type), sizeof(waslast->type))
	      != sizeof(waslast->type)
	   )
	  goto bad;
      }
    if (rda_write_string(fd, NULL) != 0)    /* Indicates end of added headers */
      goto bad;
    }

  /* Write the contents of the $n variables */

  if (write(fd, filter_n, sizeof(filter_n)) != sizeof(filter_n))
    goto bad;

  /* If the result was DELIVERED or NOTDELIVERED, we pass back the generated
  addresses, and their associated information, through the pipe. This is
  just tedious, but it seems to be the only safe way. We do this also for
  FAIL and FREEZE, because a filter is allowed to set up deliveries that
  are honoured before freezing or failing. */

  if (yield == FF_DELIVERED || yield == FF_NOTDELIVERED ||
      yield == FF_FAIL || yield == FF_FREEZE)
    {
    address_item *addr;
    for (addr = *generated; addr; addr = addr->next)
      {
      int reply_options = 0;
      int ig_err = addr->prop.ignore_error ? 1 : 0;

      if (  rda_write_string(fd, addr->address) != 0
         || write(fd, &addr->mode, sizeof(addr->mode)) != sizeof(addr->mode)
         || write(fd, &addr->flags, sizeof(addr->flags)) != sizeof(addr->flags)
         || rda_write_string(fd, addr->prop.errors_address) != 0
         || write(fd, &ig_err, sizeof(ig_err)) != sizeof(ig_err)
	 )
	goto bad;

      if (addr->pipe_expandn)
        {
        uschar **pp;
        for (pp = addr->pipe_expandn; *pp; pp++)
          if (rda_write_string(fd, *pp) != 0)
	    goto bad;
        }
      if (rda_write_string(fd, NULL) != 0)
        goto bad;

      if (!addr->reply)
	{
        if (write(fd, &reply_options, sizeof(int)) != sizeof(int))    /* 0 means no reply */
	  goto bad;
	}
      else
        {
        reply_options |= REPLY_EXISTS;
        if (addr->reply->file_expand) reply_options |= REPLY_EXPAND;
        if (addr->reply->return_message) reply_options |= REPLY_RETURN;
        if (  write(fd, &reply_options, sizeof(int)) != sizeof(int)
           || write(fd, &(addr->reply->expand_forbid), sizeof(int))
	      != sizeof(int)
           || write(fd, &(addr->reply->once_repeat), sizeof(time_t))
	      != sizeof(time_t)
           || rda_write_string(fd, addr->reply->to) != 0
           || rda_write_string(fd, addr->reply->cc) != 0
           || rda_write_string(fd, addr->reply->bcc) != 0
           || rda_write_string(fd, addr->reply->from) != 0
           || rda_write_string(fd, addr->reply->reply_to) != 0
           || rda_write_string(fd, addr->reply->subject) != 0
           || rda_write_string(fd, addr->reply->headers) != 0
           || rda_write_string(fd, addr->reply->text) != 0
           || rda_write_string(fd, addr->reply->file) != 0
           || rda_write_string(fd, addr->reply->logfile) != 0
           || rda_write_string(fd, addr->reply->oncelog) != 0
	   )
	  goto bad;
        }
      }

    if (rda_write_string(fd, NULL) != 0)   /* Marks end of addresses */
      goto bad;
    }

  /* OK, this process is now done. Free any cached resources. Must use _exit()
  and not exit() !! */

out:
  (void)close(fd);
  search_tidyup();
  _exit(0);

bad:
  DEBUG(D_rewrite) debug_printf("rda_interpret: failed write to pipe\n");
  goto out;
  }

/* Back in the main process: panic if the fork did not succeed. */

if (pid < 0)
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "fork failed for %s", rname);

/* Read the pipe to get the data from the filter/forward. Our copy of the
writing end must be closed first, as otherwise read() won't return zero on an
empty pipe. Afterwards, close the reading end. */

(void)close(pfd[pipe_write]);

/* Read initial data, including yield and contents of *error */

fd = pfd[pipe_read];
if (read(fd, filtertype, sizeof(int)) != sizeof(int) ||
    read(fd, &yield, sizeof(int)) != sizeof(int) ||
    !rda_read_string(fd, error)) goto DISASTER;

/* Read the contents of any syntax error blocks if we have a pointer */

if (eblockp)
  {
  error_block *e;
  error_block **p;
  for (p = eblockp; ; p = &e->next)
    {
    uschar *s;
    if (!rda_read_string(fd, &s)) goto DISASTER;
    if (!s) break;
    e = store_get(sizeof(error_block));
    e->next = NULL;
    e->text1 = s;
    if (!rda_read_string(fd, &s)) goto DISASTER;
    e->text2 = s;
    *p = e;
    }
  }

/* If this is a system filter, read the identify of any original header lines
that were removed, and then read data for any new ones that were added. */

if (f.system_filtering)
  {
  int hn = 0;
  header_line *h = header_list;

  for (;;)
    {
    int n;
    if (read(fd, &n, sizeof(int)) != sizeof(int)) goto DISASTER;
    if (n < 0) break;
    while (hn < n)
      {
      hn++;
      if (!(h = h->next)) goto DISASTER_NO_HEADER;
      }
    h->type = htype_old;
    }

  for (;;)
    {
    uschar *s;
    int type;
    if (!rda_read_string(fd, &s)) goto DISASTER;
    if (!s) break;
    if (read(fd, &type, sizeof(type)) != sizeof(type)) goto DISASTER;
    header_add(type, "%s", s);
    }
  }

/* Read the values of the $n variables */

if (read(fd, filter_n, sizeof(filter_n)) != sizeof(filter_n)) goto DISASTER;

/* If the yield is DELIVERED, NOTDELIVERED, FAIL, or FREEZE there may follow
addresses and data to go with them. Keep them in the same order in the
generated chain. */

if (yield == FF_DELIVERED || yield == FF_NOTDELIVERED ||
    yield == FF_FAIL || yield == FF_FREEZE)
  {
  address_item **nextp = generated;

  for (;;)
    {
    int i, reply_options;
    address_item *addr;
    uschar *recipient;
    uschar *expandn[EXPAND_MAXN + 2];

    /* First string is the address; NULL => end of addresses */

    if (!rda_read_string(fd, &recipient)) goto DISASTER;
    if (recipient == NULL) break;

    /* Hang on the end of the chain */

    addr = deliver_make_addr(recipient, FALSE);
    *nextp = addr;
    nextp = &(addr->next);

    /* Next comes the mode and the flags fields */

    if (  read(fd, &addr->mode, sizeof(addr->mode)) != sizeof(addr->mode)
       || read(fd, &addr->flags, sizeof(addr->flags)) != sizeof(addr->flags)
       || !rda_read_string(fd, &addr->prop.errors_address)
       || read(fd, &i, sizeof(i)) != sizeof(i)
       )
      goto DISASTER;
    addr->prop.ignore_error = (i != 0);

    /* Next comes a possible setting for $thisaddress and any numerical
    variables for pipe expansion, terminated by a NULL string. The maximum
    number of numericals is EXPAND_MAXN. Note that we put filter_thisaddress
    into the zeroth item in the vector - this is sorted out inside the pipe
    transport. */

    for (i = 0; i < EXPAND_MAXN + 1; i++)
      {
      uschar *temp;
      if (!rda_read_string(fd, &temp)) goto DISASTER;
      if (i == 0) filter_thisaddress = temp;           /* Just in case */
      expandn[i] = temp;
      if (temp == NULL) break;
      }

    if (i > 0)
      {
      addr->pipe_expandn = store_get((i+1) * sizeof(uschar *));
      addr->pipe_expandn[i] = NULL;
      while (--i >= 0) addr->pipe_expandn[i] = expandn[i];
      }

    /* Then an int containing reply options; zero => no reply data. */

    if (read(fd, &reply_options, sizeof(int)) != sizeof(int)) goto DISASTER;
    if ((reply_options & REPLY_EXISTS) != 0)
      {
      addr->reply = store_get(sizeof(reply_item));

      addr->reply->file_expand = (reply_options & REPLY_EXPAND) != 0;
      addr->reply->return_message = (reply_options & REPLY_RETURN) != 0;

      if (read(fd,&(addr->reply->expand_forbid),sizeof(int)) !=
            sizeof(int) ||
          read(fd,&(addr->reply->once_repeat),sizeof(time_t)) !=
            sizeof(time_t) ||
          !rda_read_string(fd, &(addr->reply->to)) ||
          !rda_read_string(fd, &(addr->reply->cc)) ||
          !rda_read_string(fd, &(addr->reply->bcc)) ||
          !rda_read_string(fd, &(addr->reply->from)) ||
          !rda_read_string(fd, &(addr->reply->reply_to)) ||
          !rda_read_string(fd, &(addr->reply->subject)) ||
          !rda_read_string(fd, &(addr->reply->headers)) ||
          !rda_read_string(fd, &(addr->reply->text)) ||
          !rda_read_string(fd, &(addr->reply->file)) ||
          !rda_read_string(fd, &(addr->reply->logfile)) ||
          !rda_read_string(fd, &(addr->reply->oncelog)))
        goto DISASTER;
      }
    }
  }

/* All data has been transferred from the sub-process. Reap it, close the
reading end of the pipe, and we are done. */

WAIT_EXIT:
while ((rc = wait(&status)) != pid)
  {
  if (rc < 0 && errno == ECHILD)      /* Process has vanished */
    {
    log_write(0, LOG_MAIN, "redirection process %d vanished unexpectedly", pid);
    goto FINAL_EXIT;
    }
  }

DEBUG(D_route)
  debug_printf("rda_interpret: subprocess yield=%d error=%s\n", yield, *error);

if (had_disaster)
  {
  *error = string_sprintf("internal problem in %s: failure to transfer "
    "data from subprocess: status=%04x%s%s%s", rname,
    status, readerror,
    (*error == NULL)? US"" : US": error=",
    (*error == NULL)? US"" : *error);
  log_write(0, LOG_MAIN|LOG_PANIC, "%s", *error);
  }
else if (status != 0)
  {
  log_write(0, LOG_MAIN|LOG_PANIC, "internal problem in %s: unexpected status "
    "%04x from redirect subprocess (but data correctly received)", rname,
    status);
  }

FINAL_EXIT:
(void)close(fd);
signal(SIGCHLD, oldsignal);   /* restore */
return yield;


/* Come here if the data indicates removal of a header that we can't find */

DISASTER_NO_HEADER:
readerror = US" readerror=bad header identifier";
had_disaster = TRUE;
yield = FF_ERROR;
goto WAIT_EXIT;

/* Come here is there's a shambles in transferring the data over the pipe. The
value of errno should still be set. */

DISASTER:
readerror = string_sprintf(" readerror='%s'", strerror(errno));
had_disaster = TRUE;
yield = FF_ERROR;
goto WAIT_EXIT;
}

/* End of rda.c */
