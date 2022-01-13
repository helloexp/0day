/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "lmtp.h"

#define PENDING_OK 256


/* Options specific to the lmtp transport. They must be in alphabetic
order (note that "_" comes before the lower case letters). Those starting
with "*" are not settable by the user but are used by the option-reading
software for alternative value types. Some options are stored in the transport
instance block so as to be publicly visible; these are flagged with opt_public.
*/

optionlist lmtp_transport_options[] = {
  { "batch_id",          opt_stringptr | opt_public,
      (void *)offsetof(transport_instance, batch_id) },
  { "batch_max",         opt_int | opt_public,
      (void *)offsetof(transport_instance, batch_max) },
  { "command",           opt_stringptr,
      (void *)offsetof(lmtp_transport_options_block, cmd) },
  { "ignore_quota",      opt_bool,
      (void *)offsetof(lmtp_transport_options_block, ignore_quota) },
  { "socket",            opt_stringptr,
      (void *)offsetof(lmtp_transport_options_block, skt) },
  { "timeout",           opt_time,
      (void *)offsetof(lmtp_transport_options_block, timeout) }
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int lmtp_transport_options_count =
  sizeof(lmtp_transport_options)/sizeof(optionlist);


#ifdef MACRO_PREDEF

/* Dummy values */
lmtp_transport_options_block lmtp_transport_option_defaults = {0};
void lmtp_transport_init(transport_instance *tblock) {}
BOOL lmtp_transport_entry(transport_instance *tblock, address_item *addr) {return FALSE;}

#else   /*!MACRO_PREDEF*/


/* Default private options block for the lmtp transport. */

lmtp_transport_options_block lmtp_transport_option_defaults = {
  NULL,           /* cmd */
  NULL,           /* skt */
  5*60,           /* timeout */
  0,              /* options */
  FALSE           /* ignore_quota */
};



/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */

void
lmtp_transport_init(transport_instance *tblock)
{
lmtp_transport_options_block *ob =
  (lmtp_transport_options_block *)(tblock->options_block);

/* Either the command field or the socket field must be set */

if ((ob->cmd == NULL) == (ob->skt == NULL))
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
    "one (and only one) of command or socket must be set for the %s transport",
    tblock->name);

/* If a fixed uid field is set, then a gid field must also be set. */

if (tblock->uid_set && !tblock->gid_set && tblock->expand_gid == NULL)
  log_write(0, LOG_PANIC_DIE|LOG_CONFIG,
    "user set without group for the %s transport", tblock->name);

/* Set up the bitwise options for transport_write_message from the various
driver options. Only one of body_only and headers_only can be set. */

ob->options |=
  (tblock->body_only? topt_no_headers : 0) |
  (tblock->headers_only? topt_no_body : 0) |
  (tblock->return_path_add? topt_add_return_path : 0) |
  (tblock->delivery_date_add? topt_add_delivery_date : 0) |
  (tblock->envelope_to_add? topt_add_envelope_to : 0) |
  topt_use_crlf | topt_end_dot;
}


/*************************************************
*          Check an LMTP response                *
*************************************************/

/* This function is given an errno code and the LMTP response buffer to
analyse. It sets an appropriate message and puts the first digit of the
response code into the yield variable. If no response was actually read, a
suitable digit is chosen.

Arguments:
  errno_value  pointer to the errno value
  more_errno   from the top address for use with ERRNO_FILTER_FAIL
  buffer       the LMTP response buffer
  yield        where to put a one-digit LMTP response code
  message      where to put an error message

Returns:       TRUE if a "QUIT" command should be sent, else FALSE
*/

static BOOL check_response(int *errno_value, int more_errno, uschar *buffer,
  int *yield, uschar **message)
{
*yield = '4';    /* Default setting is to give a temporary error */

/* Handle response timeout */

if (*errno_value == ETIMEDOUT)
  {
  *message = string_sprintf("LMTP timeout after %s", big_buffer);
  if (transport_count > 0)
    *message = string_sprintf("%s (%d bytes written)", *message,
      transport_count);
  *errno_value = 0;
  return FALSE;
  }

/* Handle malformed LMTP response */

if (*errno_value == ERRNO_SMTPFORMAT)
  {
  *message = string_sprintf("Malformed LMTP response after %s: %s",
    big_buffer, string_printing(buffer));
  return FALSE;
  }

/* Handle a failed filter process error; can't send QUIT as we mustn't
end the DATA. */

if (*errno_value == ERRNO_FILTER_FAIL)
  {
  *message = string_sprintf("transport filter process failed (%d)%s",
    more_errno,
    (more_errno == EX_EXECFAILED)? ": unable to execute command" : "");
  return FALSE;
  }

/* Handle a failed add_headers expansion; can't send QUIT as we mustn't
end the DATA. */

if (*errno_value == ERRNO_CHHEADER_FAIL)
  {
  *message =
    string_sprintf("failed to expand headers_add or headers_remove: %s",
      expand_string_message);
  return FALSE;
  }

/* Handle failure to write a complete data block */

if (*errno_value == ERRNO_WRITEINCOMPLETE)
  {
  *message = string_sprintf("failed to write a data block");
  return FALSE;
  }

/* Handle error responses from the remote process. */

if (buffer[0] != 0)
  {
  const uschar *s = string_printing(buffer);
  *message = string_sprintf("LMTP error after %s: %s", big_buffer, s);
  *yield = buffer[0];
  return TRUE;
  }

/* No data was read. If there is no errno, this must be the EOF (i.e.
connection closed) case, which causes deferral. Otherwise, leave the errno
value to be interpreted. In all cases, we have to assume the connection is now
dead. */

if (*errno_value == 0)
  {
  *errno_value = ERRNO_SMTPCLOSED;
  *message = string_sprintf("LMTP connection closed after %s", big_buffer);
  }

return FALSE;
}



/*************************************************
*             Write LMTP command                 *
*************************************************/

/* The formatted command is left in big_buffer so that it can be reflected in
any error message.

Arguments:
  fd         the fd to write to
  format     a format, starting with one of
             of HELO, MAIL FROM, RCPT TO, DATA, ".", or QUIT.
  ...        data for the format

Returns:     TRUE if successful, FALSE if not, with errno set
*/

static BOOL
lmtp_write_command(int fd, const char *format, ...)
{
gstring gs = { .size = big_buffer_size, .ptr = 0, .s = big_buffer };
int rc;
va_list ap;

va_start(ap, format);
if (!string_vformat(&gs, FALSE, CS format, ap))
  {
  va_end(ap);
  errno = ERRNO_SMTPFORMAT;
  return FALSE;
  }
va_end(ap);
DEBUG(D_transport|D_v) debug_printf("  LMTP>> %s", string_from_gstring(&gs));
rc = write(fd, gs.s, gs.ptr);
gs.ptr -= 2; string_from_gstring(&gs); /* remove \r\n for debug and error message */
if (rc > 0) return TRUE;
DEBUG(D_transport) debug_printf("write failed: %s\n", strerror(errno));
return FALSE;
}




/*************************************************
*              Read LMTP response                *
*************************************************/

/* This function reads an LMTP response with a timeout, and returns the
response in the given buffer. It also analyzes the first digit of the reply
code and returns FALSE if it is not acceptable.

FALSE is also returned after a reading error. In this case buffer[0] will be
zero, and the error code will be in errno.

Arguments:
  f         a file to read from
  buffer    where to put the response
  size      the size of the buffer
  okdigit   the expected first digit of the response
  timeout   the timeout to use

Returns:    TRUE if a valid, non-error response was received; else FALSE
*/

static BOOL
lmtp_read_response(FILE *f, uschar *buffer, int size, int okdigit, int timeout)
{
int count;
uschar *ptr = buffer;
uschar *readptr = buffer;

/* Ensure errno starts out zero */

errno = 0;

/* Loop for handling LMTP responses that do not all come in one line. */

for (;;)
  {
  /* If buffer is too full, something has gone wrong. */

  if (size < 10)
    {
    *readptr = 0;
    errno = ERRNO_SMTPFORMAT;
    return FALSE;
    }

  /* Loop to cover the read getting interrupted. */

  for (;;)
    {
    char *rc;
    int save_errno;

    *readptr = 0;           /* In case nothing gets read */
    sigalrm_seen = FALSE;
    ALARM(timeout);
    rc = Ufgets(readptr, size-1, f);
    save_errno = errno;
    ALARM_CLR(0);
    errno = save_errno;

    if (rc != NULL) break;  /* A line has been read */

    /* Handle timeout; must do this first because it uses EINTR */

    if (sigalrm_seen) errno = ETIMEDOUT;

    /* If some other interrupt arrived, just retry. We presume this to be rare,
    but it can happen (e.g. the SIGUSR1 signal sent by exiwhat causes
    read() to exit). */

    else if (errno == EINTR)
      {
      DEBUG(D_transport) debug_printf("EINTR while reading LMTP response\n");
      continue;
      }

    /* Handle other errors, including EOF; ensure buffer is completely empty. */

    buffer[0] = 0;
    return FALSE;
    }

  /* Adjust size in case we have to read another line, and adjust the
  count to be the length of the line we are about to inspect. */

  count = Ustrlen(readptr);
  size -= count;
  count += readptr - ptr;

  /* See if the final two characters in the buffer are \r\n. If not, we
  have to read some more. At least, that is what we should do on a strict
  interpretation of the RFC. But accept LF as well, as we do for SMTP. */

  if (ptr[count-1] != '\n')
    {
    DEBUG(D_transport)
      {
      int i;
      debug_printf("LMTP input line incomplete in one buffer:\n  ");
      for (i = 0; i < count; i++)
        {
        int c = (ptr[i]);
        if (mac_isprint(c)) debug_printf("%c", c); else debug_printf("<%d>", c);
        }
      debug_printf("\n");
      }
    readptr = ptr + count;
    continue;
    }

  /* Remove any whitespace at the end of the buffer. This gets rid of CR, LF
  etc. at the end. Show it, if debugging, formatting multi-line responses. */

  while (count > 0 && isspace(ptr[count-1])) count--;
  ptr[count] = 0;

  DEBUG(D_transport|D_v)
    {
    uschar *s = ptr;
    uschar *t = ptr;
    while (*t != 0)
      {
      while (*t != 0 && *t != '\n') t++;
      debug_printf("  %s %*s\n", (s == ptr)? "LMTP<<" : "      ",
        (int)(t-s), s);
      if (*t == 0) break;
      s = t = t + 1;
      }
    }

  /* Check the format of the response: it must start with three digits; if
  these are followed by a space or end of line, the response is complete. If
  they are followed by '-' this is a multi-line response and we must look for
  another line until the final line is reached. The only use made of multi-line
  responses is to pass them back as error messages. We therefore just
  concatenate them all within the buffer, which should be large enough to
  accept any reasonable number of lines. A multiline response may already
  have been read in one go - hence the loop here. */

  for(;;)
    {
    uschar *p;
    if (count < 3 ||
       !isdigit(ptr[0]) ||
       !isdigit(ptr[1]) ||
       !isdigit(ptr[2]) ||
       (ptr[3] != '-' && ptr[3] != ' ' && ptr[3] != 0))
      {
      errno = ERRNO_SMTPFORMAT;    /* format error */
      return FALSE;
      }

    /* If a single-line response, exit the loop */

    if (ptr[3] != '-') break;

    /* For a multi-line response see if the next line is already read, and if
    so, stay in this loop to check it. */

    p = ptr + 3;
    while (*(++p) != 0)
      {
      if (*p == '\n')
        {
        ptr = ++p;
        break;
        }
      }
    if (*p == 0) break;   /* No more lines to check */
    }

  /* End of response. If the last of the lines we are looking at is the final
  line, we are done. Otherwise more data has to be read. */

  if (ptr[3] != '-') break;

  /* Move the reading pointer upwards in the buffer and insert \n in case this
  is an error message that subsequently gets printed. Set the scanning pointer
  to the reading pointer position. */

  ptr += count;
  *ptr++ = '\n';
  size--;
  readptr = ptr;
  }

/* Return a value that depends on the LMTP return code. Ensure that errno is
zero, because the caller of this function looks at errno when FALSE is
returned, to distinguish between an unexpected return code and other errors
such as timeouts, lost connections, etc. */

errno = 0;
return buffer[0] == okdigit;
}






/*************************************************
*              Main entry point                  *
*************************************************/

/* See local README for interface details. For setup-errors, this transport
returns FALSE, indicating that the first address has the status for all; in
normal cases it returns TRUE, indicating that each address has its own status
set. */

BOOL
lmtp_transport_entry(
  transport_instance *tblock,      /* data for this instantiation */
  address_item *addrlist)          /* address(es) we are working on */
{
pid_t pid = 0;
FILE *out;
lmtp_transport_options_block *ob =
  (lmtp_transport_options_block *)(tblock->options_block);
struct sockaddr_un sockun;         /* don't call this "sun" ! */
int timeout = ob->timeout;
int fd_in = -1, fd_out = -1;
int code, save_errno;
BOOL send_data;
BOOL yield = FALSE;
address_item *addr;
uschar *igquotstr = US"";
uschar *sockname = NULL;
const uschar **argv;
uschar buffer[256];

DEBUG(D_transport) debug_printf("%s transport entered\n", tblock->name);

/* Initialization ensures that either a command or a socket is specified, but
not both. When a command is specified, call the common function for creating an
argument list and expanding the items. */

if (ob->cmd)
  {
  DEBUG(D_transport) debug_printf("using command %s\n", ob->cmd);
  sprintf(CS buffer, "%.50s transport", tblock->name);
  if (!transport_set_up_command(&argv, ob->cmd, TRUE, PANIC, addrlist, buffer,
       NULL))
    return FALSE;

  /* If the -N option is set, can't do any more. Presume all has gone well. */
  if (f.dont_deliver)
    goto MINUS_N;

/* As this is a local transport, we are already running with the required
uid/gid and current directory. Request that the new process be a process group
leader, so we can kill it and all its children on an error. */

  if ((pid = child_open(USS argv, NULL, 0, &fd_in, &fd_out, TRUE)) < 0)
    {
    addrlist->message = string_sprintf(
      "Failed to create child process for %s transport: %s", tblock->name,
        strerror(errno));
    return FALSE;
    }
  }

/* When a socket is specified, expand the string and create a socket. */

else
  {
  DEBUG(D_transport) debug_printf("using socket %s\n", ob->skt);
  sockname = expand_string(ob->skt);
  if (sockname == NULL)
    {
    addrlist->message = string_sprintf("Expansion of \"%s\" (socket setting "
      "for %s transport) failed: %s", ob->skt, tblock->name,
      expand_string_message);
    return FALSE;
    }
  if ((fd_in = fd_out = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
    {
    addrlist->message = string_sprintf(
      "Failed to create socket %s for %s transport: %s",
        ob->skt, tblock->name, strerror(errno));
    return FALSE;
    }

  /* If the -N option is set, can't do any more. Presume all has gone well. */
  if (f.dont_deliver)
    goto MINUS_N;

  sockun.sun_family = AF_UNIX;
  sprintf(sockun.sun_path, "%.*s", (int)(sizeof(sockun.sun_path)-1), sockname);
  if(connect(fd_out, (struct sockaddr *)(&sockun), sizeof(sockun)) == -1)
    {
    addrlist->message = string_sprintf(
      "Failed to connect to socket %s for %s transport: %s",
        sockun.sun_path, tblock->name, strerror(errno));
    return FALSE;
    }
  }


/* Make the output we are going to read into a file. */

out = fdopen(fd_out, "rb");

/* Now we must implement the LMTP protocol. It is like SMTP, except that after
the end of the message, a return code for every accepted RCPT TO is sent. This
allows for message+recipient checks after the message has been received. */

/* First thing is to wait for an initial greeting. */

Ustrcpy(big_buffer, "initial connection");
if (!lmtp_read_response(out, buffer, sizeof(buffer), '2',
  timeout)) goto RESPONSE_FAILED;

/* Next, we send a LHLO command, and expect a positive response */

if (!lmtp_write_command(fd_in, "%s %s\r\n", "LHLO",
  primary_hostname)) goto WRITE_FAILED;

if (!lmtp_read_response(out, buffer, sizeof(buffer), '2',
     timeout)) goto RESPONSE_FAILED;

/* If the ignore_quota option is set, note whether the server supports the
IGNOREQUOTA option, and if so, set an appropriate addition for RCPT. */

if (ob->ignore_quota)
  igquotstr = (pcre_exec(regex_IGNOREQUOTA, NULL, CS buffer,
    Ustrlen(CS buffer), 0, PCRE_EOPT, NULL, 0) >= 0)? US" IGNOREQUOTA" : US"";

/* Now the envelope sender */

if (!lmtp_write_command(fd_in, "MAIL FROM:<%s>\r\n", return_path))
  goto WRITE_FAILED;

if (!lmtp_read_response(out, buffer, sizeof(buffer), '2', timeout))
  {
  if (errno == 0 && buffer[0] == '4')
    {
    errno = ERRNO_MAIL4XX;
    addrlist->more_errno |= ((buffer[1] - '0')*10 + buffer[2] - '0') << 8;
    }
  goto RESPONSE_FAILED;
  }

/* Next, we hand over all the recipients. Some may be permanently or
temporarily rejected; others may be accepted, for now. */

send_data = FALSE;
for (addr = addrlist; addr != NULL; addr = addr->next)
  {
  if (!lmtp_write_command(fd_in, "RCPT TO:<%s>%s\r\n",
       transport_rcpt_address(addr, tblock->rcpt_include_affixes), igquotstr))
    goto WRITE_FAILED;
  if (lmtp_read_response(out, buffer, sizeof(buffer), '2', timeout))
    {
    send_data = TRUE;
    addr->transport_return = PENDING_OK;
    }
  else
    {
    if (errno != 0 || buffer[0] == 0) goto RESPONSE_FAILED;
    addr->message = string_sprintf("LMTP error after %s: %s", big_buffer,
      string_printing(buffer));
    setflag(addr, af_pass_message);   /* Allow message to go to user */
    if (buffer[0] == '5') addr->transport_return = FAIL; else
      {
      addr->basic_errno = ERRNO_RCPT4XX;
      addr->more_errno |= ((buffer[1] - '0')*10 + buffer[2] - '0') << 8;
      }
    }
  }

/* Now send the text of the message if there were any good recipients. */

if (send_data)
  {
  BOOL ok;
  transport_ctx tctx = {
    {fd_in},
    tblock,
    addrlist,
    US".", US"..",
    ob->options
  };

  if (!lmtp_write_command(fd_in, "DATA\r\n")) goto WRITE_FAILED;
  if (!lmtp_read_response(out, buffer, sizeof(buffer), '3', timeout))
    {
    if (errno == 0 && buffer[0] == '4')
      {
      errno = ERRNO_DATA4XX;
      addrlist->more_errno |= ((buffer[1] - '0')*10 + buffer[2] - '0') << 8;
      }
    goto RESPONSE_FAILED;
    }

  sigalrm_seen = FALSE;
  transport_write_timeout = timeout;
  Ustrcpy(big_buffer, "sending data block");   /* For error messages */
  DEBUG(D_transport|D_v)
    debug_printf("  LMTP>> writing message and terminating \".\"\n");

  transport_count = 0;
  ok = transport_write_message(&tctx, 0);

  /* Failure can either be some kind of I/O disaster (including timeout),
  or the failure of a transport filter or the expansion of added headers. */

  if (!ok)
    {
    buffer[0] = 0;              /* There hasn't been a response */
    goto RESPONSE_FAILED;
    }

  Ustrcpy(big_buffer, "end of data");   /* For error messages */

  /* We now expect a response for every address that was accepted above,
  in the same order. For those that get a response, their status is fixed;
  any that are accepted have been handed over, even if later responses crash -
  at least, that's how I read RFC 2033. */

  for (addr = addrlist; addr != NULL; addr = addr->next)
    {
    if (addr->transport_return != PENDING_OK) continue;

    if (lmtp_read_response(out, buffer, sizeof(buffer), '2', timeout))
      {
      addr->transport_return = OK;
      if (LOGGING(smtp_confirmation))
        {
        const uschar *s = string_printing(buffer);
	/* de-const safe here as string_printing known to have alloc'n'copied */
        addr->message = (s == buffer)? US string_copy(s) : US s;
        }
      }
    /* If the response has failed badly, use it for all the remaining pending
    addresses and give up. */

    else if (errno != 0 || buffer[0] == 0)
      {
      address_item *a;
      save_errno = errno;
      check_response(&save_errno, addr->more_errno, buffer, &code,
        &(addr->message));
      addr->transport_return = (code == '5')? FAIL : DEFER;
      for (a = addr->next; a != NULL; a = a->next)
        {
        if (a->transport_return != PENDING_OK) continue;
        a->basic_errno = addr->basic_errno;
        a->message = addr->message;
        a->transport_return = addr->transport_return;
        }
      break;
      }

    /* Otherwise, it's an LMTP error code return for one address */

    else
      {
      if (buffer[0] == '4')
        {
        addr->basic_errno = ERRNO_DATA4XX;
        addr->more_errno |= ((buffer[1] - '0')*10 + buffer[2] - '0') << 8;
        }
      addr->message = string_sprintf("LMTP error after %s: %s", big_buffer,
        string_printing(buffer));
      addr->transport_return = (buffer[0] == '5')? FAIL : DEFER;
      setflag(addr, af_pass_message);   /* Allow message to go to user */
      }
    }
  }

/* The message transaction has completed successfully - this doesn't mean that
all the addresses have necessarily been transferred, but each has its status
set, so we change the yield to TRUE. */

yield = TRUE;
(void) lmtp_write_command(fd_in, "QUIT\r\n");
(void) lmtp_read_response(out, buffer, sizeof(buffer), '2', 1);

goto RETURN;


/* Come here if any call to read_response, other than a response after the data
phase, failed. Put the error in the top address - this will be replicated
because the yield is still FALSE. (But omit ETIMEDOUT, as there will already be
a suitable message.) Analyse the error, and if if isn't too bad, send a QUIT
command. Wait for the response with a short timeout, so we don't wind up this
process before the far end has had time to read the QUIT. */

RESPONSE_FAILED:

save_errno = errno;
if (errno != ETIMEDOUT && errno != 0) addrlist->basic_errno = errno;
addrlist->message = NULL;

if (check_response(&save_errno, addrlist->more_errno,
    buffer, &code, &(addrlist->message)))
  {
  (void) lmtp_write_command(fd_in, "QUIT\r\n");
  (void) lmtp_read_response(out, buffer, sizeof(buffer), '2', 1);
  }

addrlist->transport_return = (code == '5')? FAIL : DEFER;
if (code == '4' && save_errno > 0)
  addrlist->message = string_sprintf("%s: %s", addrlist->message,
    strerror(save_errno));
goto KILL_AND_RETURN;

/* Come here if there are errors during writing of a command or the message
itself. This error will be applied to all the addresses. */

WRITE_FAILED:

addrlist->transport_return = PANIC;
addrlist->basic_errno = errno;
if (errno == ERRNO_CHHEADER_FAIL)
  addrlist->message =
    string_sprintf("Failed to expand headers_add or headers_remove: %s",
      expand_string_message);
else if (errno == ERRNO_FILTER_FAIL)
  addrlist->message = string_sprintf("Filter process failure");
else if (errno == ERRNO_WRITEINCOMPLETE)
  addrlist->message = string_sprintf("Failed repeatedly to write data");
else if (errno == ERRNO_SMTPFORMAT)
  addrlist->message = US"overlong LMTP command generated";
else
  addrlist->message = string_sprintf("Error %d", errno);

/* Come here after errors. Kill off the process. */

KILL_AND_RETURN:

if (pid > 0) killpg(pid, SIGKILL);

/* Come here from all paths after the subprocess is created. Wait for the
process, but with a timeout. */

RETURN:

(void)child_close(pid, timeout);

if (fd_in >= 0) (void)close(fd_in);
if (fd_out >= 0) (void)fclose(out);

DEBUG(D_transport)
  debug_printf("%s transport yields %d\n", tblock->name, yield);

return yield;


MINUS_N:
  DEBUG(D_transport)
    debug_printf("*** delivery by %s transport bypassed by -N option",
      tblock->name);
  addrlist->transport_return = OK;
  return FALSE;
}

#endif	/*!MACRO_PREDEF*/
/* End of transport/lmtp.c */
