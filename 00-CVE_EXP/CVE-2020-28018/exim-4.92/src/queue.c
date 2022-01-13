/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions that operate on the input queue. */


#include "exim.h"



/* Routines with knowledge of spool layout */

#ifndef COMPILE_UTILITY
static void
spool_pname_buf(uschar * buf, int len)
{
snprintf(CS buf, len, "%s/%s/input", spool_directory, queue_name);
}

uschar *
spool_dname(const uschar * purpose, uschar * subdir)
{
return string_sprintf("%s/%s/%s/%s",
	spool_directory, queue_name, purpose, subdir);
}
#endif

uschar *
spool_sname(const uschar * purpose, uschar * subdir)
{
return string_sprintf("%s%s%s%s%s",
		    queue_name, *queue_name ? "/" : "",
		    purpose,
		    *subdir ? "/" : "", subdir);
}

uschar *
spool_fname(const uschar * purpose, const uschar * subdir, const uschar * fname,
       	const uschar * suffix)
{
return string_sprintf("%s/%s/%s/%s/%s%s",
	spool_directory, queue_name, purpose, subdir, fname, suffix);
}




#ifndef COMPILE_UTILITY

/* The number of nodes to use for the bottom-up merge sort when a list of queue
items is to be ordered. The code for this sort was contributed as a patch by
Michael Haardt. */

#define LOG2_MAXNODES 32



/*************************************************
*  Helper sort function for queue_get_spool_list *
*************************************************/

/* This function is used when sorting the queue list in the function
queue_get_spool_list() below.

Arguments:
  a            points to an ordered list of queue_filename items
  b            points to another ordered list

Returns:       a pointer to a merged ordered list
*/

static queue_filename *
merge_queue_lists(queue_filename *a, queue_filename *b)
{
queue_filename *first = NULL;
queue_filename **append = &first;

while (a && b)
  {
  int d;
  if ((d = Ustrncmp(a->text, b->text, 6)) == 0)
    d = Ustrcmp(a->text + 14, b->text + 14);
  if (d < 0)
    {
    *append = a;
    append= &a->next;
    a = a->next;
    }
  else
    {
    *append = b;
    append= &b->next;
    b = b->next;
    }
  }

*append = a ? a : b;
return first;
}





/*************************************************
*             Get list of spool files            *
*************************************************/

/* Scan the spool directory and return a list of the relevant file names
therein. Single-character sub-directories are handled as follows:

  If the first argument is > 0, a sub-directory is scanned; the letter is
  taken from the nth entry in subdirs.

  If the first argument is 0, sub-directories are not scanned. However, a
  list of them is returned.

  If the first argument is < 0, sub-directories are scanned for messages,
  and a single, unified list is created. The returned data blocks contain the
  identifying character of the subdirectory, if any. The subdirs vector is
  still required as an argument.

If the randomize argument is TRUE, messages are returned in "randomized" order.
Actually, the order is anything but random, but the algorithm is cheap, and the
point is simply to ensure that the same order doesn't occur every time, in case
a particular message is causing a remote MTA to barf - we would like to try
other messages to that MTA first.

If the randomize argument is FALSE, sort the list according to the file name.
This should give the order in which the messages arrived. It is normally used
only for presentation to humans, in which case the (possibly expensive) sort
that it does is not part of the normal operational code. However, if
queue_run_in_order is set, sorting has to take place for queue runs as well.
When randomize is FALSE, the first argument is normally -1, so all messages are
included.

Arguments:
  subdiroffset   sub-directory character offset, or 0 or -1 (see above)
  subdirs        vector to store list of subdirchars
  subcount       pointer to int in which to store count of subdirs
  randomize      TRUE if the order of the list is to be unpredictable

Returns:         pointer to a chain of queue name items
*/

static queue_filename *
queue_get_spool_list(int subdiroffset, uschar *subdirs, int *subcount,
  BOOL randomize)
{
int i;
int flags = 0;
int resetflags = -1;
int subptr;
queue_filename *yield = NULL;
queue_filename *last = NULL;
struct dirent *ent;
DIR *dd;
uschar buffer[256];
queue_filename *root[LOG2_MAXNODES];

/* When randomizing, the file names are added to the start or end of the list
according to the bits of the flags variable. Get a collection of bits from the
current time. Use the bottom 16 and just keep re-using them if necessary. When
not randomizing, initialize the sublists for the bottom-up merge sort. */

if (randomize)
  resetflags = time(NULL) & 0xFFFF;
else
   for (i = 0; i < LOG2_MAXNODES; i++)
     root[i] = NULL;

/* If processing the full queue, or just the top-level, start at the base
directory, and initialize the first subdirectory name (as none). Otherwise,
start at the sub-directory offset. */

if (subdiroffset <= 0)
  {
  i = 0;
  subdirs[0] = 0;
  *subcount = 0;
  }
else
  i = subdiroffset;

/* Set up prototype for the directory name. */

spool_pname_buf(buffer, sizeof(buffer));
buffer[sizeof(buffer) - 3] = 0;
subptr = Ustrlen(buffer);
buffer[subptr+2] = 0;               /* terminator for lengthened name */

/* This loop runs at least once, for the main or given directory, and then as
many times as necessary to scan any subdirectories encountered in the main
directory, if they are to be scanned at this time. */

for (; i <= *subcount; i++)
  {
  int count = 0;
  int subdirchar = subdirs[i];      /* 0 for main directory */

  if (subdirchar != 0)
    {
    buffer[subptr] = '/';
    buffer[subptr+1] = subdirchar;
    }

  DEBUG(D_queue_run) debug_printf("looking in %s\n", buffer);
  if (!(dd = opendir(CS buffer)))
    continue;

  /* Now scan the directory. */

  while ((ent = readdir(dd)))
    {
    uschar *name = US ent->d_name;
    int len = Ustrlen(name);

    /* Count entries */

    count++;

    /* If we find a single alphameric sub-directory in the base directory,
    add it to the list for subsequent scans. */

    if (i == 0 && len == 1 && isalnum(*name))
      {
      *subcount = *subcount + 1;
      subdirs[*subcount] = *name;
      continue;
      }

    /* Otherwise, if it is a header spool file, add it to the list */

    if (len == SPOOL_NAME_LENGTH &&
        Ustrcmp(name + SPOOL_NAME_LENGTH - 2, "-H") == 0)
      {
      queue_filename *next =
        store_get(sizeof(queue_filename) + Ustrlen(name));
      Ustrcpy(next->text, name);
      next->dir_uschar = subdirchar;

      /* Handle the creation of a randomized list. The first item becomes both
      the top and bottom of the list. Subsequent items are inserted either at
      the top or the bottom, randomly. This is, I argue, faster than doing a
      sort by allocating a random number to each item, and it also saves having
      to store the number with each item. */

      if (randomize)
        if (!yield)
          {
          next->next = NULL;
          yield = last = next;
          }
        else
          {
          if (flags == 0)
	    flags = resetflags;
          if ((flags & 1) == 0)
            {
            next->next = yield;
            yield = next;
            }
          else
            {
            next->next = NULL;
            last->next = next;
            last = next;
            }
          flags = flags >> 1;
          }

      /* Otherwise do a bottom-up merge sort based on the name. */

      else
        {
        int j;
        next->next = NULL;
        for (j = 0; j < LOG2_MAXNODES; j++)
          if (root[j])
            {
            next = merge_queue_lists(next, root[j]);
            root[j] = j == LOG2_MAXNODES - 1 ? next : NULL;
            }
          else
            {
            root[j] = next;
            break;
            }
        }
      }
    }

  /* Finished with this directory */

  closedir(dd);

  /* If we have just scanned a sub-directory, and it was empty (count == 2
  implies just "." and ".." entries), and Exim is no longer configured to
  use sub-directories, attempt to get rid of it. At the same time, try to
  get rid of any corresponding msglog subdirectory. These are just cosmetic
  tidying actions, so just ignore failures. If we are scanning just a single
  sub-directory, break the loop. */

  if (i != 0)
    {
    if (!split_spool_directory && count <= 2)
      {
      uschar subdir[2];

      rmdir(CS buffer);
      subdir[0] = subdirchar; subdir[1] = 0;
      rmdir(CS spool_dname(US"msglog", subdir));
      }
    if (subdiroffset > 0) break;    /* Single sub-directory */
    }

  /* If we have just scanned the base directory, and subdiroffset is 0,
  we do not want to continue scanning the sub-directories. */

  else if (subdiroffset == 0)
    break;
  }    /* Loop for multiple subdirectories */

/* When using a bottom-up merge sort, do the final merging of the sublists.
Then pass back the final list of file items. */

if (!randomize)
  for (i = 0; i < LOG2_MAXNODES; ++i)
    yield = merge_queue_lists(yield, root[i]);

return yield;
}




/*************************************************
*              Perform a queue run               *
*************************************************/

/* The arguments give the messages to start and stop at; NULL means start at
the beginning or stop at the end. If the given start message doesn't exist, we
start at the next lexically greater one, and likewise we stop at the after the
previous lexically lesser one if the given stop message doesn't exist. Because
a queue run can take some time, stat each file before forking, in case it has
been delivered in the meantime by some other means.

The global variables queue_run_force and queue_run_local may be set to cause
forced deliveries or local-only deliveries, respectively.

If deliver_selectstring[_sender] is not NULL, skip messages whose recipients do
not contain the string. As this option is typically used when a machine comes
back online, we want to ensure that at least one delivery attempt takes place,
so force the first one. The selecting string can optionally be a regex, or
refer to the sender instead of recipients.

If queue_2stage is set, the queue is scanned twice. The first time, queue_smtp
is set so that routing is done for all messages. Thus in the second run those
that are routed to the same host should go down the same SMTP connection.

Arguments:
  start_id   message id to start at, or NULL for all
  stop_id    message id to end at, or NULL for all
  recurse    TRUE if recursing for 2-stage run

Returns:     nothing
*/

void
queue_run(uschar *start_id, uschar *stop_id, BOOL recurse)
{
BOOL force_delivery = f.queue_run_force || deliver_selectstring != NULL ||
  deliver_selectstring_sender != NULL;
const pcre *selectstring_regex = NULL;
const pcre *selectstring_regex_sender = NULL;
uschar *log_detail = NULL;
int subcount = 0;
int i;
uschar subdirs[64];

/* Cancel any specific queue domains. Turn off the flag that causes SMTP
deliveries not to happen, unless doing a 2-stage queue run, when the SMTP flag
gets set. Save the queue_runner's pid and the flag that indicates any
deliveries run directly from this process. Deliveries that are run by handing
on TCP/IP channels have queue_run_pid set, but not queue_running. */

queue_domains = NULL;
queue_smtp_domains = NULL;
f.queue_smtp = f.queue_2stage;

queue_run_pid = getpid();
f.queue_running = TRUE;

/* Log the true start of a queue run, and fancy options */

if (!recurse)
  {
  uschar extras[8];
  uschar *p = extras;

  if (f.queue_2stage) *p++ = 'q';
  if (f.queue_run_first_delivery) *p++ = 'i';
  if (f.queue_run_force) *p++ = 'f';
  if (f.deliver_force_thaw) *p++ = 'f';
  if (f.queue_run_local) *p++ = 'l';
  *p = 0;

  p = big_buffer;
  p += sprintf(CS p, "pid=%d", (int)queue_run_pid);

  if (extras[0] != 0)
    p += sprintf(CS p, " -q%s", extras);

  if (deliver_selectstring)
    p += sprintf(CS p, " -R%s %s", f.deliver_selectstring_regex? "r" : "",
      deliver_selectstring);

  if (deliver_selectstring_sender)
    p += sprintf(CS p, " -S%s %s", f.deliver_selectstring_sender_regex? "r" : "",
      deliver_selectstring_sender);

  log_detail = string_copy(big_buffer);
  if (*queue_name)
    log_write(L_queue_run, LOG_MAIN, "Start '%s' queue run: %s",
      queue_name, log_detail);
  else
    log_write(L_queue_run, LOG_MAIN, "Start queue run: %s", log_detail);
  }

/* If deliver_selectstring is a regex, compile it. */

if (deliver_selectstring && f.deliver_selectstring_regex)
  selectstring_regex = regex_must_compile(deliver_selectstring, TRUE, FALSE);

if (deliver_selectstring_sender && f.deliver_selectstring_sender_regex)
  selectstring_regex_sender =
    regex_must_compile(deliver_selectstring_sender, TRUE, FALSE);

/* If the spool is split into subdirectories, we want to process it one
directory at a time, so as to spread out the directory scanning and the
delivering when there are lots of messages involved, except when
queue_run_in_order is set.

In the random order case, this loop runs once for the main directory (handling
any messages therein), and then repeats for any subdirectories that were found.
When the first argument of queue_get_spool_list() is 0, it scans the top
directory, fills in subdirs, and sets subcount. The order of the directories is
then randomized after the first time through, before they are scanned in
subsequent iterations.

When the first argument of queue_get_spool_list() is -1 (for queue_run_in_
order), it scans all directories and makes a single message list. */

for (i = queue_run_in_order ? -1 : 0;
     i <= (queue_run_in_order ? -1 : subcount);
     i++)
  {
  queue_filename * fq;
  void *reset_point1 = store_get(0);

  DEBUG(D_queue_run)
    {
    if (i == 0)
      debug_printf("queue running main directory\n");
    else if (i == -1)
      debug_printf("queue running combined directories\n");
    else
      debug_printf("queue running subdirectory '%c'\n", subdirs[i]);
    }

  for (fq = queue_get_spool_list(i, subdirs, &subcount, !queue_run_in_order);
       fq;
       fq = fq->next)
    {
    pid_t pid;
    int status;
    int pfd[2];
    struct stat statbuf;
    uschar buffer[256];

    /* Unless deliveries are forced, if deliver_queue_load_max is non-negative,
    check that the load average is low enough to permit deliveries. */

    if (!f.queue_run_force && deliver_queue_load_max >= 0)
      if ((load_average = os_getloadavg()) > deliver_queue_load_max)
        {
        log_write(L_queue_run, LOG_MAIN, "Abandon queue run: %s (load %.2f, max %.2f)",
          log_detail,
          (double)load_average/1000.0,
          (double)deliver_queue_load_max/1000.0);
        i = subcount;                 /* Don't process other directories */
        break;
        }
      else
        DEBUG(D_load) debug_printf("load average = %.2f max = %.2f\n",
          (double)load_average/1000.0,
          (double)deliver_queue_load_max/1000.0);

    /* Skip this message unless it's within the ID limits */

    if (stop_id && Ustrncmp(fq->text, stop_id, MESSAGE_ID_LENGTH) > 0)
      continue;
    if (start_id && Ustrncmp(fq->text, start_id, MESSAGE_ID_LENGTH) < 0)
      continue;

    /* Check that the message still exists */

    message_subdir[0] = fq->dir_uschar;
    if (Ustat(spool_fname(US"input", message_subdir, fq->text, US""), &statbuf) < 0)
      continue;

    /* There are some tests that require the reading of the header file. Ensure
    the store used is scavenged afterwards so that this process doesn't keep
    growing its store. We have to read the header file again when actually
    delivering, but it's cheaper than forking a delivery process for each
    message when many are not going to be delivered. */

    if (deliver_selectstring || deliver_selectstring_sender ||
        f.queue_run_first_delivery)
      {
      BOOL wanted = TRUE;
      BOOL orig_dont_deliver = f.dont_deliver;
      void *reset_point2 = store_get(0);

      /* Restore the original setting of dont_deliver after reading the header,
      so that a setting for a particular message doesn't force it for any that
      follow. If the message is chosen for delivery, the header is read again
      in the deliver_message() function, in a subprocess. */

      if (spool_read_header(fq->text, FALSE, TRUE) != spool_read_OK) continue;
      f.dont_deliver = orig_dont_deliver;

      /* Now decide if we want to deliver this message. As we have read the
      header file, we might as well do the freeze test now, and save forking
      another process. */

      if (f.deliver_freeze && !f.deliver_force_thaw)
        {
        log_write(L_skip_delivery, LOG_MAIN, "Message is frozen");
        wanted = FALSE;
        }

      /* Check first_delivery in the case when there are no message logs. */

      else if (f.queue_run_first_delivery && !f.deliver_firsttime)
        {
        DEBUG(D_queue_run) debug_printf("%s: not first delivery\n", fq->text);
        wanted = FALSE;
        }

      /* Check for a matching address if deliver_selectstring[_sender] is set.
      If so, we do a fully delivery - don't want to omit other addresses since
      their routing might trigger re-writing etc. */

      /* Sender matching */

      else if (  deliver_selectstring_sender
	      && !(f.deliver_selectstring_sender_regex
		  ? (pcre_exec(selectstring_regex_sender, NULL,
		      CS sender_address, Ustrlen(sender_address), 0, PCRE_EOPT,
		      NULL, 0) >= 0)
		  : (strstric(sender_address, deliver_selectstring_sender, FALSE)
		      != NULL)
	      )   )
        {
        DEBUG(D_queue_run) debug_printf("%s: sender address did not match %s\n",
          fq->text, deliver_selectstring_sender);
        wanted = FALSE;
        }

      /* Recipient matching */

      else if (deliver_selectstring)
        {
        int i;
        for (i = 0; i < recipients_count; i++)
          {
          uschar *address = recipients_list[i].address;
          if (  (f.deliver_selectstring_regex
		? (pcre_exec(selectstring_regex, NULL, CS address,
		     Ustrlen(address), 0, PCRE_EOPT, NULL, 0) >= 0)
                : (strstric(address, deliver_selectstring, FALSE) != NULL)
		)
             && tree_search(tree_nonrecipients, address) == NULL
	     )
            break;
          }

        if (i >= recipients_count)
          {
          DEBUG(D_queue_run)
            debug_printf("%s: no recipient address matched %s\n",
              fq->text, deliver_selectstring);
          wanted = FALSE;
          }
        }

      /* Recover store used when reading the header */

      spool_clear_header_globals();
      store_reset(reset_point2);
      if (!wanted) continue;      /* With next message */
      }

    /* OK, got a message we want to deliver. Create a pipe which will
    serve as a means of detecting when all the processes created by the
    delivery process are finished. This is relevant when the delivery
    process passes one or more SMTP channels on to its own children. The
    pipe gets passed down; by reading on it here we detect when the last
    descendent dies by the unblocking of the read. It's a pity that for
    most of the time the pipe isn't used, but creating a pipe should be
    pretty cheap. */

    if (pipe(pfd) < 0)
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to create pipe in queue "
        "runner process %d: %s", queue_run_pid, strerror(errno));
    queue_run_pipe = pfd[pipe_write];  /* To ensure it gets passed on. */

    /* Make sure it isn't stdin. This seems unlikely, but just to be on the
    safe side... */

    if (queue_run_pipe == 0)
      {
      queue_run_pipe = dup(queue_run_pipe);
      (void)close(0);
      }

    /* Before forking to deliver the message, ensure any open and cached
    lookup files or databases are closed. Otherwise, closing in the subprocess
    can make the next subprocess have problems. There won't often be anything
    open here, but it is possible (e.g. if spool_directory is an expanded
    string). A single call before this loop would probably suffice, but just in
    case expansions get inserted at some point, I've taken the heavy-handed
    approach. When nothing is open, the call should be cheap. */

    search_tidyup();

    /* Now deliver the message; get the id by cutting the -H off the file
    name. The return of the process is zero if a delivery was attempted. */

    set_process_info("running queue: %s", fq->text);
    fq->text[SPOOL_NAME_LENGTH-2] = 0;
    if ((pid = fork()) == 0)
      {
      int rc;
      if (f.running_in_test_harness) millisleep(100);
      (void)close(pfd[pipe_read]);
      rc = deliver_message(fq->text, force_delivery, FALSE);
      _exit(rc == DELIVER_NOT_ATTEMPTED);
      }
    if (pid < 0)
      log_write(0, LOG_MAIN|LOG_PANIC_DIE, "fork of delivery process from "
        "queue runner %d failed\n", queue_run_pid);

    /* Close the writing end of the synchronizing pipe in this process,
    then wait for the first level process to terminate. */

    (void)close(pfd[pipe_write]);
    set_process_info("running queue: waiting for %s (%d)", fq->text, pid);
    while (wait(&status) != pid);

    /* A zero return means a delivery was attempted; turn off the force flag
    for any subsequent calls unless queue_force is set. */

    if ((status & 0xffff) == 0) force_delivery = f.queue_run_force;

    /* If the process crashed, tell somebody */

    else if ((status & 0x00ff) != 0)
      log_write(0, LOG_MAIN|LOG_PANIC,
        "queue run: process %d crashed with signal %d while delivering %s",
        (int)pid, status & 0x00ff, fq->text);

    /* Before continuing, wait till the pipe gets closed at the far end. This
    tells us that any children created by the delivery to re-use any SMTP
    channels have all finished. Since no process actually writes to the pipe,
    the mere fact that read() unblocks is enough. */

    set_process_info("running queue: waiting for children of %d", pid);
    if ((status = read(pfd[pipe_read], buffer, sizeof(buffer))) != 0)
      log_write(0, LOG_MAIN|LOG_PANIC, "queue run: %s on pipe",
		status > 0 ? "unexpected data" : "error");
    (void)close(pfd[pipe_read]);
    set_process_info("running queue");

    /* If we are in the test harness, and this is not the first of a 2-stage
    queue run, update fudged queue times. */

    if (f.running_in_test_harness && !f.queue_2stage)
      {
      uschar *fqtnext = Ustrchr(fudged_queue_times, '/');
      if (fqtnext != NULL) fudged_queue_times = fqtnext + 1;
      }
    }                                  /* End loop for list of messages */

  tree_nonrecipients = NULL;
  store_reset(reset_point1);           /* Scavenge list of messages */

  /* If this was the first time through for random order processing, and
  sub-directories have been found, randomize their order if necessary. */

  if (i == 0 && subcount > 1 && !queue_run_in_order)
    {
    int j, r;
    for (j = 1; j <= subcount; j++)
      if ((r = random_number(100)) >= 50)
        {
        int k = (r % subcount) + 1;
        int x = subdirs[j];
        subdirs[j] = subdirs[k];
        subdirs[k] = x;
        }
    }
  }                                    /* End loop for multiple directories */

/* If queue_2stage is true, we do it all again, with the 2stage flag
turned off. */

if (f.queue_2stage)
  {
  f.queue_2stage = FALSE;
  queue_run(start_id, stop_id, TRUE);
  }

/* At top level, log the end of the run. */

if (!recurse)
  if (*queue_name)
    log_write(L_queue_run, LOG_MAIN, "End '%s' queue run: %s",
      queue_name, log_detail);
  else
    log_write(L_queue_run, LOG_MAIN, "End queue run: %s", log_detail);
}




/************************************************
*         Count messages on the queue           *
************************************************/

/* Called as a result of -bpc

Arguments:  none
Returns:    nothing
*/

void
queue_count(void)
{
int subcount;
int count = 0;
queue_filename *f = NULL;
uschar subdirs[64];
f = queue_get_spool_list(
        -1,             /* entire queue */
        subdirs,        /* for holding sub list */
        &subcount,      /* for subcount */
        FALSE);         /* not random */
for (; f != NULL; f = f->next) count++;
fprintf(stdout, "%d\n", count);
}



/************************************************
*          List extra deliveries                *
************************************************/

/* This is called from queue_list below to print out all addresses that
have received a message but which were not primary addresses. That is, all
the addresses in the tree of non-recipients that are not primary addresses.
The tree has been scanned and the data field filled in for those that are
primary addresses.

Argument:    points to the tree node
Returns:     nothing
*/

static void queue_list_extras(tree_node *p)
{
if (p->left != NULL) queue_list_extras(p->left);
if (!p->data.val) printf("       +D %s\n", p->name);
if (p->right != NULL) queue_list_extras(p->right);
}



/************************************************
*          List messages on the queue           *
************************************************/

/* Or a given list of messages. In the "all" case, we get a list of file names
as quickly as possible, then scan each one for information to output. If any
disappear while we are processing, just leave them out, but give an error if an
explicit list was given. This function is a top-level function that is obeyed
as a result of the -bp argument. As there may be a lot of messages on the
queue, we must tidy up the store after reading the headers for each one.

Arguments:
   option     0 => list top-level recipients, with "D" for those delivered
              1 => list only undelivered top-level recipients
              2 => as 0, plus any generated delivered recipients
              If 8 is added to any of these values, the queue is listed in
                random order.
   list       => first of any message ids to list
   count      count of message ids; 0 => all

Returns:      nothing
*/

void
queue_list(int option, uschar **list, int count)
{
int i;
int subcount;
int now = (int)time(NULL);
void *reset_point;
queue_filename * qf = NULL;
uschar subdirs[64];

/* If given a list of messages, build a chain containing their ids. */

if (count > 0)
  {
  queue_filename *last = NULL;
  for (i = 0; i < count; i++)
    {
    queue_filename *next =
      store_get(sizeof(queue_filename) + Ustrlen(list[i]) + 2);
    sprintf(CS next->text, "%s-H", list[i]);
    next->dir_uschar = '*';
    next->next = NULL;
    if (i == 0) qf = next; else last->next = next;
    last = next;
    }
  }

/* Otherwise get a list of the entire queue, in order if necessary. */

else
  qf = queue_get_spool_list(
          -1,             /* entire queue */
          subdirs,        /* for holding sub list */
          &subcount,      /* for subcount */
          option >= 8);   /* randomize if required */

if (option >= 8) option -= 8;

/* Now scan the chain and print information, resetting store used
each time. */

for (reset_point = store_get(0);
    qf;
    spool_clear_header_globals(), store_reset(reset_point), qf = qf->next
    )
  {
  int rc, save_errno;
  int size = 0;
  BOOL env_read;

  message_size = 0;
  message_subdir[0] = qf->dir_uschar;
  rc = spool_read_header(qf->text, FALSE, count <= 0);
  if (rc == spool_read_notopen && errno == ENOENT && count <= 0)
    continue;
  save_errno = errno;

  env_read = (rc == spool_read_OK || rc == spool_read_hdrerror);

  if (env_read)
    {
    int ptr;
    FILE *jread;
    struct stat statbuf;
    uschar * fname = spool_fname(US"input", message_subdir, qf->text, US"");

    ptr = Ustrlen(fname)-1;
    fname[ptr] = 'D';

    /* Add the data size to the header size; don't count the file name
    at the start of the data file, but add one for the notional blank line
    that precedes the data. */

    if (Ustat(fname, &statbuf) == 0)
      size = message_size + statbuf.st_size - SPOOL_DATA_START_OFFSET + 1;
    i = (now - received_time.tv_sec)/60;  /* minutes on queue */
    if (i > 90)
      {
      i = (i + 30)/60;
      if (i > 72) printf("%2dd ", (i + 12)/24); else printf("%2dh ", i);
      }
    else printf("%2dm ", i);

    /* Collect delivered addresses from any J file */

    fname[ptr] = 'J';
    if ((jread = Ufopen(fname, "rb")))
      {
      while (Ufgets(big_buffer, big_buffer_size, jread) != NULL)
        {
        int n = Ustrlen(big_buffer);
        big_buffer[n-1] = 0;
        tree_add_nonrecipient(big_buffer);
        }
      (void)fclose(jread);
      }
    }

  fprintf(stdout, "%s ", string_format_size(size, big_buffer));
  for (i = 0; i < 16; i++) fputc(qf->text[i], stdout);

  if (env_read && sender_address)
    {
    printf(" <%s>", sender_address);
    if (f.sender_set_untrusted) printf(" (%s)", originator_login);
    }

  if (rc != spool_read_OK)
    {
    printf("\n    ");
    if (save_errno == ERRNO_SPOOLFORMAT)
      {
      struct stat statbuf;
      uschar * fname = spool_fname(US"input", message_subdir, qf->text, US"");

      if (Ustat(fname, &statbuf) == 0)
        printf("*** spool format error: size=" OFF_T_FMT " ***",
          statbuf.st_size);
      else printf("*** spool format error ***");
      }
    else printf("*** spool read error: %s ***", strerror(save_errno));
    if (rc != spool_read_hdrerror)
      {
      printf("\n\n");
      continue;
      }
    }

  if (f.deliver_freeze) printf(" *** frozen ***");

  printf("\n");

  if (recipients_list)
    {
    for (i = 0; i < recipients_count; i++)
      {
      tree_node *delivered =
        tree_search(tree_nonrecipients, recipients_list[i].address);
      if (!delivered || option != 1)
        printf("        %s %s\n",
	  delivered ? "D" : " ", recipients_list[i].address);
      if (delivered) delivered->data.val = TRUE;
      }
    if (option == 2 && tree_nonrecipients)
      queue_list_extras(tree_nonrecipients);
    printf("\n");
    }
  }
}



/*************************************************
*             Act on a specific message          *
*************************************************/

/* Actions that require a list of addresses make use of argv/argc/
recipients_arg. Other actions do not. This function does its own
authority checking.

Arguments:
  id              id of the message to work on
  action          which action is required (MSG_xxx)
  argv            the original argv for Exim
  argc            the original argc for Exim
  recipients_arg  offset to the list of recipients in argv

Returns:          FALSE if there was any problem
*/

BOOL
queue_action(uschar *id, int action, uschar **argv, int argc, int recipients_arg)
{
int i, j;
BOOL yield = TRUE;
BOOL removed = FALSE;
struct passwd *pw;
uschar *doing = NULL;
uschar *username;
uschar *errmsg;
uschar spoolname[32];

/* Set the global message_id variable, used when re-writing spool files. This
also causes message ids to be added to log messages. */

Ustrcpy(message_id, id);

/* The "actions" that just list the files do not require any locking to be
done. Only admin users may read the spool files. */

if (action >= MSG_SHOW_BODY)
  {
  int fd, i, rc;
  uschar *subdirectory, *suffix;

  if (!f.admin_user)
    {
    printf("Permission denied\n");
    return FALSE;
    }

  if (recipients_arg < argc)
    {
    printf("*** Only one message can be listed at once\n");
    return FALSE;
    }

  if (action == MSG_SHOW_BODY)
    {
    subdirectory = US"input";
    suffix = US"-D";
    }
  else if (action == MSG_SHOW_HEADER)
    {
    subdirectory = US"input";
    suffix = US"-H";
    }
  else
    {
    subdirectory = US"msglog";
    suffix = US"";
    }

  for (i = 0; i < 2; i++)
    {
    message_subdir[0] = split_spool_directory == (i == 0) ? id[5] : 0;
    if ((fd = Uopen(spool_fname(subdirectory, message_subdir, id, suffix),
		    O_RDONLY, 0)) >= 0)
      break;
    if (i == 0)
      continue;

    printf("Failed to open %s file for %s%s: %s\n", subdirectory, id, suffix,
      strerror(errno));
    if (action == MSG_SHOW_LOG && !message_logs)
      printf("(No message logs are being created because the message_logs "
        "option is false.)\n");
    return FALSE;
    }

  while((rc = read(fd, big_buffer, big_buffer_size)) > 0)
    rc = write(fileno(stdout), big_buffer, rc);

  (void)close(fd);
  return TRUE;
  }

/* For actions that actually act, open and lock the data file to ensure that no
other process is working on this message. If the file does not exist, continue
only if the action is remove and the user is an admin user, to allow for
tidying up broken states. */

if ((deliver_datafile = spool_open_datafile(id)) < 0)
  if (errno == ENOENT)
    {
    yield = FALSE;
    printf("Spool data file for %s does not exist\n", id);
    if (action != MSG_REMOVE || !f.admin_user) return FALSE;
    printf("Continuing, to ensure all files removed\n");
    }
  else
    {
    if (errno == 0) printf("Message %s is locked\n", id);
      else printf("Couldn't open spool file for %s: %s\n", id,
        strerror(errno));
    return FALSE;
    }

/* Read the spool header file for the message. Again, continue after an
error only in the case of deleting by an administrator. Setting the third
argument false causes it to look both in the main spool directory and in
the appropriate subdirectory, and set message_subdir according to where it
found the message. */

sprintf(CS spoolname, "%s-H", id);
if (spool_read_header(spoolname, TRUE, FALSE) != spool_read_OK)
  {
  yield = FALSE;
  if (errno != ERRNO_SPOOLFORMAT)
    printf("Spool read error for %s: %s\n", spoolname, strerror(errno));
  else
    printf("Spool format error for %s\n", spoolname);
  if (action != MSG_REMOVE || !f.admin_user)
    {
    (void)close(deliver_datafile);
    deliver_datafile = -1;
    return FALSE;
    }
  printf("Continuing to ensure all files removed\n");
  }

/* Check that the user running this process is entitled to operate on this
message. Only admin users may freeze/thaw, add/cancel recipients, or otherwise
mess about, but the original sender is permitted to remove a message. That's
why we leave this check until after the headers are read. */

if (!f.admin_user && (action != MSG_REMOVE || real_uid != originator_uid))
  {
  printf("Permission denied\n");
  (void)close(deliver_datafile);
  deliver_datafile = -1;
  return FALSE;
  }

/* Set up the user name for logging. */

pw = getpwuid(real_uid);
username = (pw != NULL)?
  US pw->pw_name : string_sprintf("uid %ld", (long int)real_uid);

/* Take the necessary action. */

if (action != MSG_SHOW_COPY) printf("Message %s ", id);

switch(action)
  {
  case MSG_SHOW_COPY:
    {
    transport_ctx tctx = {{0}};
    deliver_in_buffer = store_malloc(DELIVER_IN_BUFFER_SIZE);
    deliver_out_buffer = store_malloc(DELIVER_OUT_BUFFER_SIZE);
    tctx.u.fd = 1;
    (void) transport_write_message(&tctx, 0);
    break;
    }


  case MSG_FREEZE:
  if (f.deliver_freeze)
    {
    yield = FALSE;
    printf("is already frozen\n");
    }
  else
    {
    f.deliver_freeze = TRUE;
    f.deliver_manual_thaw = FALSE;
    deliver_frozen_at = time(NULL);
    if (spool_write_header(id, SW_MODIFYING, &errmsg) >= 0)
      {
      printf("is now frozen\n");
      log_write(0, LOG_MAIN, "frozen by %s", username);
      }
    else
      {
      yield = FALSE;
      printf("could not be frozen: %s\n", errmsg);
      }
    }
  break;


  case MSG_THAW:
  if (!f.deliver_freeze)
    {
    yield = FALSE;
    printf("is not frozen\n");
    }
  else
    {
    f.deliver_freeze = FALSE;
    f.deliver_manual_thaw = TRUE;
    if (spool_write_header(id, SW_MODIFYING, &errmsg) >= 0)
      {
      printf("is no longer frozen\n");
      log_write(0, LOG_MAIN, "unfrozen by %s", username);
      }
    else
      {
      yield = FALSE;
      printf("could not be unfrozen: %s\n", errmsg);
      }
    }
  break;


  /* We must ensure all files are removed from both the input directory
  and the appropriate subdirectory, to clean up cases when there are odd
  files left lying around in odd places. In the normal case message_subdir
  will have been set correctly by spool_read_header, but as this is a rare
  operation, just run everything twice. */

  case MSG_REMOVE:
    {
    uschar suffix[3];

    suffix[0] = '-';
    suffix[2] = 0;
    message_subdir[0] = id[5];

    for (j = 0; j < 2; message_subdir[0] = 0, j++)
      {
      uschar * fname = spool_fname(US"msglog", message_subdir, id, US"");

      DEBUG(D_any) debug_printf(" removing %s", fname);
      if (Uunlink(fname) < 0)
	{
	if (errno != ENOENT)
	  {
	  yield = FALSE;
	  printf("Error while removing %s: %s\n", fname, strerror(errno));
	  }
	else DEBUG(D_any) debug_printf(" (no file)\n");
	}
      else
	{
	removed = TRUE;
	DEBUG(D_any) debug_printf(" (ok)\n");
	}

      for (i = 0; i < 3; i++)
	{
	uschar * fname;

	suffix[1] = (US"DHJ")[i];
	fname = spool_fname(US"input", message_subdir, id, suffix);

	DEBUG(D_any) debug_printf(" removing %s", fname);
	if (Uunlink(fname) < 0)
	  {
	  if (errno != ENOENT)
	    {
	    yield = FALSE;
	    printf("Error while removing %s: %s\n", fname, strerror(errno));
	    }
	  else DEBUG(D_any) debug_printf(" (no file)\n");
	  }
	else
	  {
	  removed = TRUE;
	  DEBUG(D_any) debug_printf(" (done)\n");
	  }
	}
      }

    /* In the common case, the datafile is open (and locked), so give the
    obvious message. Otherwise be more specific. */

    if (deliver_datafile >= 0) printf("has been removed\n");
      else printf("has been removed or did not exist\n");
    if (removed)
      {
#ifndef DISABLE_EVENT
      for (i = 0; i < recipients_count; i++)
	{
	tree_node *delivered =
	  tree_search(tree_nonrecipients, recipients_list[i].address);
	if (!delivered)
	  {
	  uschar * save_local = deliver_localpart;
	  const uschar * save_domain = deliver_domain;
	  uschar * addr = recipients_list[i].address, * errmsg = NULL;
	  int start, end, dom;

	  if (!parse_extract_address(addr, &errmsg, &start, &end, &dom, TRUE))
	    log_write(0, LOG_MAIN|LOG_PANIC,
	      "failed to parse address '%.100s'\n: %s", addr, errmsg);
	  else
	    {
	    deliver_localpart =
	      string_copyn(addr+start, dom ? (dom-1) - start : end - start);
	    deliver_domain = dom
	      ? CUS string_copyn(addr+dom, end - dom) : CUS"";

	    event_raise(event_action, US"msg:fail:internal",
	      string_sprintf("message removed by %s", username));

	    deliver_localpart = save_local;
	    deliver_domain = save_domain;
	    }
	  }
	}
      (void) event_raise(event_action, US"msg:complete", NULL);
#endif
      log_write(0, LOG_MAIN, "removed by %s", username);
      log_write(0, LOG_MAIN, "Completed");
      }
    break;
    }


  case MSG_MARK_ALL_DELIVERED:
  for (i = 0; i < recipients_count; i++)
    tree_add_nonrecipient(recipients_list[i].address);

  if (spool_write_header(id, SW_MODIFYING, &errmsg) >= 0)
    {
    printf("has been modified\n");
    for (i = 0; i < recipients_count; i++)
      log_write(0, LOG_MAIN, "address <%s> marked delivered by %s",
        recipients_list[i].address, username);
    }
  else
    {
    yield = FALSE;
    printf("- could not mark all delivered: %s\n", errmsg);
    }
  break;


  case MSG_EDIT_SENDER:
  if (recipients_arg < argc - 1)
    {
    yield = FALSE;
    printf("- only one sender address can be specified\n");
    break;
    }
  doing = US"editing sender";
  /* Fall through */

  case MSG_ADD_RECIPIENT:
  if (doing == NULL) doing = US"adding recipient";
  /* Fall through */

  case MSG_MARK_DELIVERED:
  if (doing == NULL) doing = US"marking as delivered";

  /* Common code for EDIT_SENDER, ADD_RECIPIENT, & MARK_DELIVERED */

  if (recipients_arg >= argc)
    {
    yield = FALSE;
    printf("- error while %s: no address given\n", doing);
    break;
    }

  for (; recipients_arg < argc; recipients_arg++)
    {
    int start, end, domain;
    uschar *errmess;
    uschar *recipient =
      parse_extract_address(argv[recipients_arg], &errmess, &start, &end,
        &domain, (action == MSG_EDIT_SENDER));

    if (recipient == NULL)
      {
      yield = FALSE;
      printf("- error while %s:\n  bad address %s: %s\n",
        doing, argv[recipients_arg], errmess);
      }
    else if (recipient[0] != 0 && domain == 0)
      {
      yield = FALSE;
      printf("- error while %s:\n  bad address %s: "
        "domain missing\n", doing, argv[recipients_arg]);
      }
    else
      {
      if (action == MSG_ADD_RECIPIENT)
        {
#ifdef SUPPORT_I18N
	if (string_is_utf8(recipient)) allow_utf8_domains = message_smtputf8 = TRUE;
#endif
        receive_add_recipient(recipient, -1);
        log_write(0, LOG_MAIN, "recipient <%s> added by %s",
          recipient, username);
        }
      else if (action == MSG_MARK_DELIVERED)
        {
        for (i = 0; i < recipients_count; i++)
          if (Ustrcmp(recipients_list[i].address, recipient) == 0) break;
        if (i >= recipients_count)
          {
          printf("- error while %s:\n  %s is not a recipient:"
            " message not updated\n", doing, recipient);
          yield = FALSE;
          }
        else
          {
          tree_add_nonrecipient(recipients_list[i].address);
          log_write(0, LOG_MAIN, "address <%s> marked delivered by %s",
            recipient, username);
          }
        }
      else  /* MSG_EDIT_SENDER */
        {
#ifdef SUPPORT_I18N
	if (string_is_utf8(recipient)) allow_utf8_domains = message_smtputf8 = TRUE;
#endif
        sender_address = recipient;
        log_write(0, LOG_MAIN, "sender address changed to <%s> by %s",
          recipient, username);
        }
      }
    }

  if (yield)
    if (spool_write_header(id, SW_MODIFYING, &errmsg) >= 0)
      printf("has been modified\n");
    else
      {
      yield = FALSE;
      printf("- while %s: %s\n", doing, errmsg);
      }

  break;
  }

/* Closing the datafile releases the lock and permits other processes
to operate on the message (if it still exists). */

if (deliver_datafile >= 0)
  {
  (void)close(deliver_datafile);
  deliver_datafile = -1;
  }
return yield;
}



/*************************************************
*       Check the queue_only_file condition      *
*************************************************/

/* The queue_only_file option forces certain kinds of queueing if a given file
exists.

Arguments:  none
Returns:    nothing
*/

void
queue_check_only(void)
{
int sep = 0;
struct stat statbuf;
const uschar *s;
uschar *ss;
uschar buffer[1024];

if (queue_only_file == NULL) return;

s = queue_only_file;
while ((ss = string_nextinlist(&s, &sep, buffer, sizeof(buffer))) != NULL)
  {
  if (Ustrncmp(ss, "smtp", 4) == 0)
    {
    ss += 4;
    if (Ustat(ss, &statbuf) == 0)
      {
      f.queue_smtp = TRUE;
      DEBUG(D_receive) debug_printf("queue_smtp set because %s exists\n", ss);
      }
    }
  else
    {
    if (Ustat(ss, &statbuf) == 0)
      {
      queue_only = TRUE;
      DEBUG(D_receive) debug_printf("queue_only set because %s exists\n", ss);
      }
    }
  }
}

#endif /*!COMPILE_UTILITY*/

/* End of queue.c */
