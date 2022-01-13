/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions for sending messages to sender or to mailmaster. */


#include "exim.h"



/*************************************************
*            Write From: line for DSN            *
*************************************************/

/* This function is called to write the From: line in automatically generated
messages - bounces, warnings, etc. It expands a configuration item in order to
get the text. If the expansion fails, a panic is logged and the default value
for the option is used.

Argument:   the FILE to write to
Returns:    nothing
*/

void
moan_write_from(FILE *f)
{
uschar *s = expand_string(dsn_from);
if (!s)
  {
  log_write(0, LOG_MAIN|LOG_PANIC,
    "Failed to expand dsn_from (using default): %s", expand_string_message);
  s = expand_string(US DEFAULT_DSN_FROM);
  }
fprintf(f, "From: %s\n", s);
}



/*************************************************
*              Send error message                *
*************************************************/

/* This function sends an error message by opening a pipe to a new process
running Exim, and writing a message to it using the "-t" option. This is not
used for delivery failures, which have their own code for handing failed
addresses.

Arguments:
  recipient      addressee for the message
  ident          identifies the type of error
  eblock         chain of error_blocks containing data about the error
  headers        the message's headers
  message_file   FILE containing the body of the message
  firstline      contains first line of file, if it was read to check for
                   "From ", but it turned out not to be

Returns:         TRUE if message successfully sent
*/

BOOL
moan_send_message(uschar *recipient, int ident, error_block *eblock,
  header_line *headers, FILE *message_file, uschar *firstline)
{
int written = 0;
int fd;
int status;
int count = 0;
int size_limit = bounce_return_size_limit;
FILE * fp;
int pid;

#ifdef EXPERIMENTAL_DMARC
uschar * s, * s2;

/* For DMARC if there is a specific sender set, expand the variable for the
header From: and grab the address from that for the envelope FROM. */

if (  ident == ERRMESS_DMARC_FORENSIC
   && dmarc_forensic_sender
   && (s = expand_string(dmarc_forensic_sender))
   && *s
   && (s2 = expand_string(string_sprintf("${address:%s}", s)))
   && *s2
   )
  pid = child_open_exim2(&fd, s2, bounce_sender_authentication);
else
  {
  s = NULL;
  pid = child_open_exim(&fd);
  }

#else
pid = child_open_exim(&fd);
#endif

if (pid < 0)
  {
  DEBUG(D_any) debug_printf("Failed to create child to send message: %s\n",
    strerror(errno));
  return FALSE;
  }
else DEBUG(D_any) debug_printf("Child process %d for sending message\n", pid);

/* Creation of child succeeded */

fp = fdopen(fd, "wb");
if (errors_reply_to) fprintf(fp, "Reply-To: %s\n", errors_reply_to);
fprintf(fp, "Auto-Submitted: auto-replied\n");

#ifdef EXPERIMENTAL_DMARC
if (s)
  fprintf(fp, "From: %s\n", s);
else
#endif
  moan_write_from(fp);

fprintf(fp, "To: %s\n", recipient);

switch(ident)
  {
  case ERRMESS_BADARGADDRESS:
    fprintf(fp,
      "Subject: Mail failure - malformed recipient address\n\n");
    fprintf(fp,
      "A message that you sent contained a recipient address that was incorrectly\n"
      "constructed:\n\n");
    fprintf(fp, "  %s  %s\n", eblock->text1, eblock->text2);
    count = Ustrlen(eblock->text1);
    if (count > 0 && eblock->text1[count-1] == '.')
      fprintf(fp,
	"\nRecipient addresses must not end with a '.' character.\n");
    fprintf(fp,
      "\nThe message has not been delivered to any recipients.\n");
    break;

  case ERRMESS_BADNOADDRESS:
  case ERRMESS_BADADDRESS:
    fprintf(fp,
      "Subject: Mail failure - malformed recipient address\n\n");
    fprintf(fp,
      "A message that you sent contained one or more recipient addresses that were\n"
      "incorrectly constructed:\n\n");

    while (eblock != NULL)
      {
      fprintf(fp, "  %s: %s\n", eblock->text1, eblock->text2);
      count++;
      eblock = eblock->next;
      }

    fprintf(fp, (count == 1)? "\nThis address has been ignored. " :
      "\nThese addresses have been ignored. ");

    fprintf(fp, (ident == ERRMESS_BADADDRESS)?
      "The other addresses in the message were\n"
      "syntactically valid and have been passed on for an attempt at delivery.\n" :

      "There were no other addresses in your\n"
      "message, and so no attempt at delivery was possible.\n");
    break;

  case ERRMESS_IGADDRESS:
    fprintf(fp, "Subject: Mail failure - no recipient addresses\n\n");
    fprintf(fp,
      "A message that you sent using the -t command line option contained no\n"
      "addresses that were not also on the command line, and were therefore\n"
      "suppressed. This left no recipient addresses, and so no delivery could\n"
      "be attempted.\n");
    break;

  case ERRMESS_NOADDRESS:
    fprintf(fp, "Subject: Mail failure - no recipient addresses\n\n");
    fprintf(fp,
      "A message that you sent contained no recipient addresses, and therefore no\n"
      "delivery could be attempted.\n");
    break;

  case ERRMESS_IOERR:
    fprintf(fp, "Subject: Mail failure - system failure\n\n");
    fprintf(fp,
      "A system failure was encountered while processing a message that you sent,\n"
      "so it has not been possible to deliver it. The error was:\n\n%s\n",
      eblock->text1);
    break;

  case ERRMESS_VLONGHEADER:
    fprintf(fp, "Subject: Mail failure - overlong header section\n\n");
    fprintf(fp,
      "A message that you sent contained a header section that was excessively\n"
      "long and could not be handled by the mail transmission software. The\n"
      "message has not been delivered to any recipients.\n");
    break;

  case ERRMESS_VLONGHDRLINE:
    fprintf(fp, "Subject: Mail failure - overlong header line\n\n");
    fprintf(fp,
      "A message that you sent contained a header line that was excessively\n"
      "long and could not be handled by the mail transmission software. The\n"
      "message has not been delivered to any recipients.\n");
    break;

  case ERRMESS_TOOBIG:
    fprintf(fp, "Subject: Mail failure - message too big\n\n");
    fprintf(fp,
      "A message that you sent was longer than the maximum size allowed on this\n"
      "system. It was not delivered to any recipients.\n");
    break;

  case ERRMESS_TOOMANYRECIP:
    fprintf(fp, "Subject: Mail failure - too many recipients\n\n");
    fprintf(fp,
      "A message that you sent contained more recipients than allowed on this\n"
      "system. It was not delivered to any recipients.\n");
    break;

  case ERRMESS_LOCAL_SCAN:
  case ERRMESS_LOCAL_ACL:
    fprintf(fp, "Subject: Mail failure - rejected by local scanning code\n\n");
    fprintf(fp,
      "A message that you sent was rejected by the local scanning code that\n"
      "checks incoming messages on this system.");
      if (eblock->text1)
	fprintf(fp, " The following error was given:\n\n  %s", eblock->text1);
  fprintf(fp, "\n");
  break;

#ifdef EXPERIMENTAL_DMARC
  case ERRMESS_DMARC_FORENSIC:
    bounce_return_message = TRUE;
    bounce_return_body    = FALSE;
    fprintf(fp, "Subject: DMARC Forensic Report for %s from IP %s\n\n",
	  eblock ? eblock->text2 : US"Unknown",
          sender_host_address);
    fprintf(fp,
      "A message claiming to be from you has failed the published DMARC\n"
      "policy for your domain.\n\n");
    while (eblock)
      {
      fprintf(fp, "  %s: %s\n", eblock->text1, eblock->text2);
      count++;
      eblock = eblock->next;
      }
  break;
#endif

  default:
    fprintf(fp, "Subject: Mail failure\n\n");
    fprintf(fp,
      "A message that you sent has caused the error routine to be entered with\n"
      "an unknown error number (%d).\n", ident);
    break;
  }

/* Now, if configured, copy the message; first the headers and then the rest of
the input if available, up to the configured limit, if the option for including
message bodies in bounces is set. */

if (bounce_return_message)
  {
  if (bounce_return_body)
    {
    fprintf(fp, "\n"
      "------ This is a copy of your message, including all the headers.");
    if (size_limit == 0 || size_limit > thismessage_size_limit)
      size_limit = thismessage_size_limit;
    if (size_limit > 0 && size_limit < message_size)
      {
      int x = size_limit;
      uschar *k = US"";
      if ((x & 1023) == 0)
        {
        k = US"K";
        x >>= 10;
        }
      fprintf(fp, "\n"
        "------ No more than %d%s characters of the body are included.\n\n",
          x, k);
      }
    else fprintf(fp, " ------\n\n");
    }
  else
    {
    fprintf(fp, "\n"
      "------ This is a copy of the headers that were received before the "
      "error\n       was detected.\n\n");
    }

  /* If the error occurred before the Received: header was created, its text
  field will still be NULL; just omit such a header line. */

  while (headers)
    {
    if (headers->text != NULL) fprintf(fp, "%s", CS headers->text);
    headers = headers->next;
    }

  if (ident != ERRMESS_VLONGHEADER && ident != ERRMESS_VLONGHDRLINE)
    fputc('\n', fp);

  /* After early detection of an error, the message file may be STDIN,
  in which case we might have to terminate on a line containing just "."
  as well as on EOF. We may already have the first line in memory. */

  if (bounce_return_body && message_file)
    {
    BOOL enddot = f.dot_ends && message_file == stdin;
    uschar * buf = store_get(bounce_return_linesize_limit+2);

    if (firstline) fprintf(fp, "%s", CS firstline);

    while (fgets(CS buf, bounce_return_linesize_limit+2, message_file))
      {
      int len;

      if (enddot && *buf == '.' && buf[1] == '\n')
	{
	fputc('.', fp);
	break;
	}

      len = Ustrlen(buf);
      if (buf[len-1] != '\n')
	{	/* eat rest of partial line */
	int ch;
	while ((ch = fgetc(message_file)) != EOF && ch != '\n') ;
	}

      if (size_limit > 0 && len > size_limit - written)
	{
	buf[size_limit - written] = '\0';
	fputs(CS buf, fp);
	break;
	}

      fputs(CS buf, fp);
      }
    }
#ifdef EXPERIMENTAL_DMARC
  /* Overkill, but use exact test in case future code gets inserted */
  else if (bounce_return_body && message_file == NULL)
    {
    /*XXX limit line length here? */
    /* This doesn't print newlines, disable until can parse and fix
     * output to be legible.  */
    fprintf(fp, "%s", expand_string(US"$message_body"));
    }
#endif
  }
/* Close the file, which should send an EOF to the child process
that is receiving the message. Wait for it to finish, without a timeout. */

(void)fclose(fp);
status = child_close(pid, 0);  /* Waits for child to close */
if (status != 0)
  {
  uschar *msg = US"Child mail process returned status";
  if (status == -257)
    log_write(0, LOG_MAIN, "%s %d: errno=%d: %s", msg, status, errno,
      strerror(errno));
  else
    log_write(0, LOG_MAIN, "%s %d", msg, status);
  return FALSE;
  }

return TRUE;
}



/*************************************************
*          Send message to sender                *
*************************************************/

/* This function is called when errors are detected during the receipt of a
message. Delivery failures are handled separately in deliver.c.

If there is a valid sender_address, and the failing message is not a local
error message, then this function calls moan_send_message to send a message to
that person. If the sender's address is null, then an error has occurred with a
message that was generated by a mailer daemon. All we can do is to write
information to log files. The same action is taken if local_error_message is
set - this can happen for non null-senders in certain configurations where exim
doesn't run setuid root.

Arguments:
  ident         identifies the particular error
  eblock        chain of error_blocks containing data about the error
  headers       message's headers (chain)
  message_file  a FILE where the body of the message can be read
  check_sender  if TRUE, read the first line of the file for a possible
                  "From " sender (if a trusted caller)

Returns:        FALSE if there is no sender_address to send to;
                else the return from moan_send_message()
*/

BOOL
moan_to_sender(int ident, error_block *eblock, header_line *headers,
  FILE *message_file, BOOL check_sender)
{
uschar *firstline = NULL;
uschar *msg = US"Error while reading message with no usable sender address";

if (message_reference)
  msg = string_sprintf("%s (R=%s)", msg, message_reference);

/* Find the sender from a From line if permitted and possible */

if (check_sender && message_file && f.trusted_caller &&
    Ufgets(big_buffer, BIG_BUFFER_SIZE, message_file) != NULL)
  {
  uschar *new_sender = NULL;
  if (regex_match_and_setup(regex_From, big_buffer, 0, -1))
    new_sender = expand_string(uucp_from_sender);
  if (new_sender) sender_address = new_sender;
    else firstline = big_buffer;
  }

/* If viable sender address, send a message */

if (sender_address && sender_address[0] && !f.local_error_message)
  return moan_send_message(sender_address, ident, eblock, headers,
    message_file, firstline);

/* Otherwise, we can only log */

switch(ident)
  {
  case ERRMESS_BADARGADDRESS:
  case ERRMESS_BADNOADDRESS:
  case ERRMESS_BADADDRESS:
  log_write(0, LOG_MAIN, "%s: at least one malformed recipient address: "
    "%s - %s", msg, eblock->text1, eblock->text2);
  break;

  case ERRMESS_IGADDRESS:
  case ERRMESS_NOADDRESS:
  log_write(0, LOG_MAIN, "%s: no recipient addresses", msg);
  break;

  /* This error has already been logged. */
  case ERRMESS_IOERR:
  break;

  case ERRMESS_VLONGHEADER:
  log_write(0, LOG_MAIN, "%s: excessively long message header section read "
    "(more than %d characters)", msg, header_maxsize);
  break;

  case ERRMESS_VLONGHDRLINE:
  log_write(0, LOG_MAIN, "%s: excessively long message header line read "
    "(more than %d characters)", msg, header_line_maxsize);
  break;

  case ERRMESS_TOOBIG:
  log_write(0, LOG_MAIN, "%s: message too big (limit set to %d)", msg,
    thismessage_size_limit);
  break;

  case ERRMESS_TOOMANYRECIP:
  log_write(0, LOG_MAIN, "%s: too many recipients (max set to %d)", msg,
    recipients_max);
  break;

  case ERRMESS_LOCAL_SCAN:
  log_write(0, LOG_MAIN, "%s: rejected by local_scan: %s", msg, eblock->text1);
  break;

  case ERRMESS_LOCAL_ACL:
  log_write(0, LOG_MAIN, "%s: rejected by non-SMTP ACL: %s", msg, eblock->text1);
  break;

  default:
  log_write(0, LOG_MAIN|LOG_PANIC, "%s: unknown error number %d", msg,
    ident);
  break;
  }

return FALSE;
}



/*************************************************
*            Send message to someone             *
*************************************************/

/* This is called when exim is configured to tell someone (often the
mailmaster) about some incident.

Arguments:
  who           address to send mail to
  addr          chain of deferred addresses whose details are to be included
  subject       subject text for the message
  format        a printf() format for the body of the message
  ...           arguments for the format

Returns:        nothing
*/

void
moan_tell_someone(uschar *who, address_item *addr,
  const uschar *subject, const char *format, ...)
{
FILE *f;
va_list ap;
int fd;
int pid = child_open_exim(&fd);

if (pid < 0)
  {
  DEBUG(D_any) debug_printf("Failed to create child to send message: %s\n",
    strerror(errno));
  return;
  }

f = fdopen(fd, "wb");
fprintf(f, "Auto-Submitted: auto-replied\n");
moan_write_from(f);
fprintf(f, "To: %s\n", who);
fprintf(f, "Subject: %s\n\n", subject);
va_start(ap, format);
vfprintf(f, format, ap);
va_end(ap);

if (addr != NULL)
  {
  fprintf(f, "\nThe following address(es) have yet to be delivered:\n");
  for (; addr != NULL; addr = addr->next)
    {
    uschar *parent = (addr->parent == NULL)? NULL : addr->parent->address;
    fprintf(f, "  %s", addr->address);
    if (parent != NULL) fprintf(f, " <%s>", parent);
    if (addr->basic_errno > 0) fprintf(f, ": %s", strerror(addr->basic_errno));
    if (addr->message != NULL) fprintf(f, ": %s", addr->message);
    fprintf(f, "\n");
    }
  }

(void)fclose(f);
child_close(pid, 0);  /* Waits for child to close; no timeout */
}



/*************************************************
*            Handle SMTP batch error             *
*************************************************/

/* This is called when something goes wrong in batched (-bS) SMTP input.
Information is written to stdout and/or stderr, and Exim exits with a non-zero
completion code. BSMTP is almost always called by some other program, so it is
up to that program to interpret the return code and do something with the error
information, and also to preserve the batch input file for human analysis.

Formerly, Exim used to attempt to continue after some errors, but this strategy
has been abandoned as it can lead to loss of messages.

Arguments:
  cmd_buffer   the command causing the error, or NULL
  format       a printf() format
  ...          arguments for the format

Returns:       does not return; exits from the program
               exit code = 1 if some messages were accepted
               exit code = 2 if no messages were accepted
*/

void
moan_smtp_batch(uschar *cmd_buffer, const char *format, ...)
{
va_list ap;
int yield = (receive_messagecount > 0)? 1 : 2;

DEBUG(D_any) debug_printf("Handling error in batched SMTP input\n");

/* On stdout, write stuff that a program could parse fairly easily. */

va_start(ap, format);
vfprintf(stdout, format, ap);
va_end(ap);

fprintf(stdout, "\nTransaction started in line %d\n",
  bsmtp_transaction_linecount);
fprintf(stdout,   "Error detected in line %d\n", receive_linecount);
if (cmd_buffer != NULL) fprintf(stdout, "%s\n", cmd_buffer);

/* On stderr, write stuff for human consumption */

fprintf(stderr,
  "An error was detected while processing a file of BSMTP input.\n"
  "The error message was:\n\n  ");

va_start(ap, format);
vfprintf(stderr, format, ap);
va_end(ap);

fprintf(stderr,
  "\n\nThe SMTP transaction started in line %d.\n"
      "The error was detected in line %d.\n",
  bsmtp_transaction_linecount, receive_linecount);

if (cmd_buffer != NULL)
  {
  fprintf(stderr, "The SMTP command at fault was:\n\n   %s\n\n",
    cmd_buffer);
  }

fprintf(stderr, "%d previous message%s successfully processed.\n",
  receive_messagecount, (receive_messagecount == 1)? " was" : "s were");

fprintf(stderr, "The rest of the batch was abandoned.\n");

exim_exit(yield, US"batch");
}




/*************************************************
*         Check for error copies                 *
*************************************************/

/* This function is passed the recipient of an error message, and must check
the error_copies string to see whether there is an additional recipient list to
which errors for this recipient must be bcc'd. The incoming recipient is always
fully qualified.

Argument:   recipient address
Returns:    additional recipient list or NULL
*/

uschar *
moan_check_errorcopy(uschar *recipient)
{
uschar *item, *localpart, *domain;
const uschar *listptr = errors_copy;
uschar *yield = NULL;
uschar buffer[256];
int sep = 0;
int llen;

if (errors_copy == NULL) return NULL;

/* Set up pointer to the local part and domain, and compute the
length of the local part. */

localpart = recipient;
domain = Ustrrchr(recipient, '@');
if (domain == NULL) return NULL;  /* should not occur, but avoid crash */
llen = domain++ - recipient;

/* Scan through the configured items */

while ((item = string_nextinlist(&listptr, &sep, buffer, sizeof(buffer)))
       != NULL)
  {
  const uschar *newaddress = item;
  const uschar *pattern = string_dequote(&newaddress);

  /* If no new address found, just skip this item. */

  while (isspace(*newaddress)) newaddress++;
  if (*newaddress == 0) continue;

  /* We now have an item to match as an address in item, and the additional
  address in newaddress. If the pattern matches, expand the new address string
  and return it. During expansion, make local part and domain available for
  insertion. This requires a copy to be made; we can't just temporarily
  terminate it, as the whole address is required for $0. */

  if (match_address_list(recipient, TRUE, TRUE, &pattern, NULL, 0, UCHAR_MAX+1,
        NULL) == OK)
    {
    deliver_localpart = string_copyn(localpart, llen);
    deliver_domain = domain;
    yield = expand_string_copy(newaddress);
    deliver_domain = deliver_localpart = NULL;
    if (yield == NULL)
      log_write(0, LOG_MAIN|LOG_PANIC, "Failed to expand %s when processing "
        "errors_copy: %s", newaddress, expand_string_message);
    break;
    }
  }

DEBUG(D_any) debug_printf("errors_copy check returned %s\n",
  (yield == NULL)? US"NULL" : yield);

expand_nmax = -1;
return yield;
}



/************************************************
*        Handle skipped syntax errors           *
************************************************/

/* This function is called by the redirect router when it has skipped over one
or more syntax errors in the list of addresses. If there is an address to mail
to, send a message, and always write the information to the log. In the case of
a filter file, a "syntax error" might actually be something else, such as the
inability to open a log file. Thus, the wording of the error message is
general.

Arguments:
  rname             the router name
  eblock            chain of error blocks
  syntax_errors_to  address to send mail to, or NULL
  some              TRUE if some addresses were generated; FALSE if none were
  custom            custom message text

Returns:            FALSE if string expansion failed; TRUE otherwise
*/

BOOL
moan_skipped_syntax_errors(uschar *rname, error_block *eblock,
  uschar *syntax_errors_to, BOOL some, uschar *custom)
{
int pid, fd;
uschar *s, *t;
FILE *f;
error_block *e;

for (e = eblock; e != NULL; e = e->next)
  {
  if (e->text2 != NULL)
    log_write(0, LOG_MAIN, "%s router: skipped error: %s in \"%s\"",
      rname, e->text1, e->text2);
  else
    log_write(0, LOG_MAIN, "%s router: skipped error: %s", rname,
      e->text1);
  }

if (syntax_errors_to == NULL) return TRUE;

s = expand_string(syntax_errors_to);
if (s == NULL)
  {
  log_write(0, LOG_MAIN, "%s router failed to expand %s: %s", rname,
    syntax_errors_to, expand_string_message);
  return FALSE;
  }

/* If we can't create a process to send the message, just forget about
it. */

pid = child_open_exim(&fd);

if (pid < 0)
  {
  DEBUG(D_any) debug_printf("Failed to create child to send message: %s\n",
    strerror(errno));
  return TRUE;
  }

f = fdopen(fd, "wb");
fprintf(f, "Auto-Submitted: auto-replied\n");
moan_write_from(f);
fprintf(f, "To: %s\n", s);
fprintf(f, "Subject: error(s) in forwarding or filtering\n\n");

if (custom != NULL)
  {
  t = expand_string(custom);
  if (t == NULL)
    {
    log_write(0, LOG_MAIN, "%s router failed to expand %s: %s", rname,
      custom, expand_string_message);
    return FALSE;
    }
  fprintf(f, "%s\n\n", t);
  }

fprintf(f, "The %s router encountered the following error(s):\n\n",
  rname);

for (e = eblock; e != NULL; e = e->next)
  {
  fprintf(f, "  %s", e->text1);
  if (e->text2 != NULL)
    fprintf(f, " in the address\n  \"%s\"", e->text2);
  fprintf(f, "\n\n");
  }

if (some)
  fprintf(f, "Other addresses were processed normally.\n");
else
  fprintf(f, "No valid addresses were generated.\n");

(void)fclose(f);
child_close(pid, 0);  /* Waits for child to close; no timeout */

return TRUE;
}

/* End of moan.c */
