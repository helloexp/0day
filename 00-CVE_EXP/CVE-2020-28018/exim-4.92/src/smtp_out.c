/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* A number of functions for driving outgoing SMTP calls. */


#include "exim.h"
#include "transports/smtp.h"



/*************************************************
*           Find an outgoing interface           *
*************************************************/

/* This function is called from the smtp transport and also from the callout
code in verify.c. Its job is to expand a string to get a list of interfaces,
and choose a suitable one (IPv4 or IPv6) for the outgoing address.

Arguments:
  istring    string interface setting, may be NULL, meaning "any", in
               which case the function does nothing
  host_af    AF_INET or AF_INET6 for the outgoing IP address
  addr       the mail address being handled (for setting errors)
  interface  point this to the interface
  msg        to add to any error message

Returns:     TRUE on success, FALSE on failure, with error message
               set in addr and transport_return set to PANIC
*/

BOOL
smtp_get_interface(uschar *istring, int host_af, address_item *addr,
  uschar **interface, uschar *msg)
{
const uschar * expint;
uschar *iface;
int sep = 0;

if (!istring) return TRUE;

if (!(expint = expand_string(istring)))
  {
  if (f.expand_string_forcedfail) return TRUE;
  addr->transport_return = PANIC;
  addr->message = string_sprintf("failed to expand \"interface\" "
      "option for %s: %s", msg, expand_string_message);
  return FALSE;
  }

while (isspace(*expint)) expint++;
if (*expint == 0) return TRUE;

while ((iface = string_nextinlist(&expint, &sep, big_buffer,
          big_buffer_size)))
  {
  if (string_is_ip_address(iface, NULL) == 0)
    {
    addr->transport_return = PANIC;
    addr->message = string_sprintf("\"%s\" is not a valid IP "
      "address for the \"interface\" option for %s",
      iface, msg);
    return FALSE;
    }

  if (((Ustrchr(iface, ':') == NULL)? AF_INET:AF_INET6) == host_af)
    break;
  }

if (iface) *interface = string_copy(iface);
return TRUE;
}



/*************************************************
*           Find an outgoing port                *
*************************************************/

/* This function is called from the smtp transport and also from the callout
code in verify.c. Its job is to find a port number. Note that getservbyname()
produces the number in network byte order.

Arguments:
  rstring     raw (unexpanded) string representation of the port
  addr        the mail address being handled (for setting errors)
  port        stick the port in here
  msg         for adding to error message

Returns:      TRUE on success, FALSE on failure, with error message set
                in addr, and transport_return set to PANIC
*/

BOOL
smtp_get_port(uschar *rstring, address_item *addr, int *port, uschar *msg)
{
uschar *pstring = expand_string(rstring);

if (!pstring)
  {
  addr->transport_return = PANIC;
  addr->message = string_sprintf("failed to expand \"%s\" (\"port\" option) "
    "for %s: %s", rstring, msg, expand_string_message);
  return FALSE;
  }

if (isdigit(*pstring))
  {
  uschar *end;
  *port = Ustrtol(pstring, &end, 0);
  if (end != pstring + Ustrlen(pstring))
    {
    addr->transport_return = PANIC;
    addr->message = string_sprintf("invalid port number for %s: %s", msg,
      pstring);
    return FALSE;
    }
  }

else
  {
  struct servent *smtp_service = getservbyname(CS pstring, "tcp");
  if (!smtp_service)
    {
    addr->transport_return = PANIC;
    addr->message = string_sprintf("TCP port \"%s\" is not defined for %s",
      pstring, msg);
    return FALSE;
    }
  *port = ntohs(smtp_service->s_port);
  }

return TRUE;
}




#ifdef TCP_FASTOPEN
static void
tfo_out_check(int sock)
{
# if defined(TCP_INFO) && defined(EXIM_HAVE_TCPI_UNACKED)
struct tcp_info tinfo;
socklen_t len = sizeof(tinfo);

switch (tcp_out_fastopen)
  {
    /* This is a somewhat dubious detection method; totally undocumented so likely
    to fail in future kernels.  There seems to be no documented way.  What we really
    want to know is if the server sent smtp-banner data before our ACK of his SYN,ACK
    hit him.  What this (possibly?) detects is whether we sent a TFO cookie with our
    SYN, as distinct from a TFO request.  This gets a false-positive when the server
    key is rotated; we send the old one (which this test sees) but the server returns
    the new one and does not send its SMTP banner before we ACK his SYN,ACK.
     To force that rotation case:
     '# echo -n "00000000-00000000-00000000-0000000" >/proc/sys/net/ipv4/tcp_fastopen_key'
    The kernel seems to be counting unack'd packets. */

  case TFO_ATTEMPTED_NODATA:
    if (  getsockopt(sock, IPPROTO_TCP, TCP_INFO, &tinfo, &len) == 0
       && tinfo.tcpi_state == TCP_SYN_SENT
       && tinfo.tcpi_unacked > 1
       )
      {
      DEBUG(D_transport|D_v)
	debug_printf("TCP_FASTOPEN tcpi_unacked %d\n", tinfo.tcpi_unacked);
      tcp_out_fastopen = TFO_USED_NODATA;
      }
    break;

    /* When called after waiting for received data we should be able
    to tell if data we sent was accepted. */

  case TFO_ATTEMPTED_DATA:
    if (  getsockopt(sock, IPPROTO_TCP, TCP_INFO, &tinfo, &len) == 0
       && tinfo.tcpi_state == TCP_ESTABLISHED
       )
      if (tinfo.tcpi_options & TCPI_OPT_SYN_DATA)
	{
	DEBUG(D_transport|D_v) debug_printf("TFO: data was acked\n");
	tcp_out_fastopen = TFO_USED_DATA;
	}
      else
	{
	DEBUG(D_transport|D_v) debug_printf("TFO: had to retransmit\n");
	tcp_out_fastopen = TFO_NOT_USED;
	}
    break;
  }
# endif
}
#endif


/* Arguments as for smtp_connect(), plus
  early_data	if non-NULL, idenmpotent data to be sent -
		preferably in the TCP SYN segment

Returns:      connected socket number, or -1 with errno set
*/

int
smtp_sock_connect(host_item * host, int host_af, int port, uschar * interface,
  transport_instance * tb, int timeout, const blob * early_data)
{
smtp_transport_options_block * ob =
  (smtp_transport_options_block *)tb->options_block;
const uschar * dscp = ob->dscp;
int dscp_value;
int dscp_level;
int dscp_option;
int sock;
int save_errno = 0;
const blob * fastopen_blob = NULL;


#ifndef DISABLE_EVENT
deliver_host_address = host->address;
deliver_host_port = port;
if (event_raise(tb->event_action, US"tcp:connect", NULL)) return -1;
#endif

if ((sock = ip_socket(SOCK_STREAM, host_af)) < 0) return -1;

/* Set TCP_NODELAY; Exim does its own buffering. */

if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, US &on, sizeof(on)))
  HDEBUG(D_transport|D_acl|D_v)
    debug_printf_indent("failed to set NODELAY: %s ", strerror(errno));

/* Set DSCP value, if we can. For now, if we fail to set the value, we don't
bomb out, just log it and continue in default traffic class. */

if (dscp && dscp_lookup(dscp, host_af, &dscp_level, &dscp_option, &dscp_value))
  {
  HDEBUG(D_transport|D_acl|D_v)
    debug_printf_indent("DSCP \"%s\"=%x ", dscp, dscp_value);
  if (setsockopt(sock, dscp_level, dscp_option, &dscp_value, sizeof(dscp_value)) < 0)
    HDEBUG(D_transport|D_acl|D_v)
      debug_printf_indent("failed to set DSCP: %s ", strerror(errno));
  /* If the kernel supports IPv4 and IPv6 on an IPv6 socket, we need to set the
  option for both; ignore failures here */
  if (host_af == AF_INET6 &&
      dscp_lookup(dscp, AF_INET, &dscp_level, &dscp_option, &dscp_value))
    (void) setsockopt(sock, dscp_level, dscp_option, &dscp_value, sizeof(dscp_value));
  }

/* Bind to a specific interface if requested. Caller must ensure the interface
is the same type (IPv4 or IPv6) as the outgoing address. */

if (interface && ip_bind(sock, host_af, interface, 0) < 0)
  {
  save_errno = errno;
  HDEBUG(D_transport|D_acl|D_v)
    debug_printf_indent("unable to bind outgoing SMTP call to %s: %s", interface,
    strerror(errno));
  }

/* Connect to the remote host, and add keepalive to the socket before returning
it, if requested.  If the build supports TFO, request it - and if the caller
requested some early-data then include that in the TFO request.  If there is
early-data but no TFO support, send it after connecting. */

else
  {
#ifdef TCP_FASTOPEN
  if (verify_check_given_host(CUSS &ob->hosts_try_fastopen, host) == OK)
    fastopen_blob = early_data ? early_data : &tcp_fastopen_nodata;
#endif

  if (ip_connect(sock, host_af, host->address, port, timeout, fastopen_blob) < 0)
    save_errno = errno;
  else if (early_data && !fastopen_blob && early_data->data && early_data->len)
    {
    HDEBUG(D_transport|D_acl|D_v)
      debug_printf("sending %ld nonTFO early-data\n", (long)early_data->len);

#ifdef TCP_QUICKACK
    (void) setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, US &off, sizeof(off));
#endif
    if (send(sock, early_data->data, early_data->len, 0) < 0)
      save_errno = errno;
    }
  }

/* Either bind() or connect() failed */

if (save_errno != 0)
  {
  HDEBUG(D_transport|D_acl|D_v)
    {
    debug_printf_indent("failed: %s", CUstrerror(save_errno));
    if (save_errno == ETIMEDOUT)
      debug_printf(" (timeout=%s)", readconf_printtime(timeout));
    debug_printf("\n");
    }
  (void)close(sock);
  errno = save_errno;
  return -1;
  }

/* Both bind() and connect() succeeded, and any early-data */

else
  {
  union sockaddr_46 interface_sock;
  EXIM_SOCKLEN_T size = sizeof(interface_sock);

  HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("connected\n");
  if (getsockname(sock, (struct sockaddr *)(&interface_sock), &size) == 0)
    sending_ip_address = host_ntoa(-1, &interface_sock, NULL, &sending_port);
  else
    {
    log_write(0, LOG_MAIN | ((errno == ECONNRESET)? 0 : LOG_PANIC),
      "getsockname() failed: %s", strerror(errno));
    close(sock);
    return -1;
    }

  if (ob->keepalive) ip_keepalive(sock, host->address, TRUE);
#ifdef TCP_FASTOPEN
  tfo_out_check(sock);
#endif
  return sock;
  }
}





void
smtp_port_for_connect(host_item * host, int port)
{
if (host->port != PORT_NONE)
  {
  HDEBUG(D_transport|D_acl|D_v)
    debug_printf_indent("Transport port=%d replaced by host-specific port=%d\n", port,
      host->port);
  port = host->port;
  }
else host->port = port;    /* Set the port actually used */
}


/*************************************************
*           Connect to remote host               *
*************************************************/

/* Create a socket, and connect it to a remote host. IPv6 addresses are
detected by checking for a colon in the address. AF_INET6 is defined even on
non-IPv6 systems, to enable the code to be less messy. However, on such systems
host->address will always be an IPv4 address.

Arguments:
  sc	      details for making connection: host, af, interface, transport
  early_data  if non-NULL, data to be sent - preferably in the TCP SYN segment

Returns:      connected socket number, or -1 with errno set
*/

int
smtp_connect(smtp_connect_args * sc, const blob * early_data)
{
int port = sc->host->port;
smtp_transport_options_block * ob = sc->ob;

callout_address = string_sprintf("[%s]:%d", sc->host->address, port);

HDEBUG(D_transport|D_acl|D_v)
  {
  uschar * s = US" ";
  if (sc->interface) s = string_sprintf(" from %s ", sc->interface);
#ifdef SUPPORT_SOCKS
  if (ob->socks_proxy) s = string_sprintf("%svia proxy ", s);
#endif
  debug_printf_indent("Connecting to %s %s%s... ", sc->host->name, callout_address, s);
  }

/* Create and connect the socket */

#ifdef SUPPORT_SOCKS
if (ob->socks_proxy)
  {
  int sock = socks_sock_connect(sc->host, sc->host_af, port, sc->interface,
				sc->tblock, ob->connect_timeout);
  
  if (sock >= 0)
    {
    if (early_data && early_data->data && early_data->len)
      if (send(sock, early_data->data, early_data->len, 0) < 0)
	{
	int save_errno = errno;
	HDEBUG(D_transport|D_acl|D_v)
	  {
	  debug_printf_indent("failed: %s", CUstrerror(save_errno));
	  if (save_errno == ETIMEDOUT)
	    debug_printf(" (timeout=%s)", readconf_printtime(ob->connect_timeout));
	  debug_printf("\n");
	  }
	(void)close(sock);
	sock = -1;
	errno = save_errno;
	}
    }
  return sock;
  }
#endif

return smtp_sock_connect(sc->host, sc->host_af, port, sc->interface,
			  sc->tblock, ob->connect_timeout, early_data);
}


/*************************************************
*        Flush outgoing command buffer           *
*************************************************/

/* This function is called only from smtp_write_command() below. It flushes
the buffer of outgoing commands. There is more than one in the buffer only when
pipelining.

Argument:
  outblock   the SMTP output block
  mode	     further data expected, or plain

Returns:     TRUE if OK, FALSE on error, with errno set
*/

static BOOL
flush_buffer(smtp_outblock * outblock, int mode)
{
int rc;
int n = outblock->ptr - outblock->buffer;
BOOL more = mode == SCMD_MORE;

HDEBUG(D_transport|D_acl) debug_printf_indent("cmd buf flush %d bytes%s\n", n,
  more ? " (more expected)" : "");

#ifdef SUPPORT_TLS
if (outblock->cctx->tls_ctx)
  rc = tls_write(outblock->cctx->tls_ctx, outblock->buffer, n, more);
else
#endif

  {
  if (outblock->conn_args)
    {
    blob early_data = { .data = outblock->buffer, .len = n };

    /* We ignore the more-flag if we're doing a connect with early-data, which
    means we won't get BDAT+data. A pity, but wise due to the idempotency
    requirement: TFO with data can, in rare cases, replay the data to the
    receiver. */

    if (  (outblock->cctx->sock = smtp_connect(outblock->conn_args, &early_data))
       < 0)
      return FALSE;
    outblock->conn_args = NULL;
    rc = n;
    }
  else

    rc = send(outblock->cctx->sock, outblock->buffer, n,
#ifdef MSG_MORE
	      more ? MSG_MORE : 0
#else
	      0
#endif
	     );
  }

if (rc <= 0)
  {
  HDEBUG(D_transport|D_acl) debug_printf_indent("send failed: %s\n", strerror(errno));
  return FALSE;
  }

outblock->ptr = outblock->buffer;
outblock->cmd_count = 0;
return TRUE;
}



/*************************************************
*             Write SMTP command                 *
*************************************************/

/* The formatted command is left in big_buffer so that it can be reflected in
any error message.

Arguments:
  sx	     SMTP connection, contains buffer for pipelining, and socket
  mode       buffer, write-with-more-likely, write
  format     a format, starting with one of
             of HELO, MAIL FROM, RCPT TO, DATA, ".", or QUIT.
	     If NULL, flush pipeline buffer only.
  ...        data for the format

Returns:     0 if command added to pipelining buffer, with nothing transmitted
            +n if n commands transmitted (may still have buffered the new one)
            -1 on error, with errno set
*/

int
smtp_write_command(void * sx, int mode, const char *format, ...)
{
smtp_outblock * outblock = &((smtp_context *)sx)->outblock;
int rc = 0;

if (format)
  {
  gstring gs = { .size = big_buffer_size, .ptr = 0, .s = big_buffer };
  va_list ap;

  va_start(ap, format);
  if (!string_vformat(&gs, FALSE, CS format, ap))
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "overlong write_command in outgoing "
      "SMTP");
  va_end(ap);
  string_from_gstring(&gs);

  if (gs.ptr > outblock->buffersize)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "overlong write_command in outgoing "
      "SMTP");

  if (gs.ptr > outblock->buffersize - (outblock->ptr - outblock->buffer))
    {
    rc = outblock->cmd_count;                 /* flush resets */
    if (!flush_buffer(outblock, SCMD_FLUSH)) return -1;
    }

  Ustrncpy(CS outblock->ptr, gs.s, gs.ptr);
  outblock->ptr += gs.ptr;
  outblock->cmd_count++;
  gs.ptr -= 2; string_from_gstring(&gs); /* remove \r\n for error message */

  /* We want to hide the actual data sent in AUTH transactions from reflections
  and logs. While authenticating, a flag is set in the outblock to enable this.
  The AUTH command itself gets any data flattened. Other lines are flattened
  completely. */

  if (outblock->authenticating)
    {
    uschar *p = big_buffer;
    if (Ustrncmp(big_buffer, "AUTH ", 5) == 0)
      {
      p += 5;
      while (isspace(*p)) p++;
      while (!isspace(*p)) p++;
      while (isspace(*p)) p++;
      }
    while (*p != 0) *p++ = '*';
    }

  HDEBUG(D_transport|D_acl|D_v) debug_printf_indent("  SMTP>> %s\n", big_buffer);
  }

if (mode != SCMD_BUFFER)
  {
  rc += outblock->cmd_count;                /* flush resets */
  if (!flush_buffer(outblock, mode)) return -1;
  }

return rc;
}



/*************************************************
*          Read one line of SMTP response        *
*************************************************/

/* This function reads one line of SMTP response from the server host. This may
not be a complete response - it could be just part of a multiline response. We
have to use a buffer for incoming packets, because when pipelining or using
LMTP, there may well be more than one response in a single packet. This
function is called only from the one that follows.

Arguments:
  inblock   the SMTP input block (contains holding buffer, socket, etc.)
  buffer    where to put the line
  size      space available for the line
  timeout   the timeout to use when reading a packet

Returns:    length of a line that has been put in the buffer
            -1 otherwise, with errno set
*/

static int
read_response_line(smtp_inblock *inblock, uschar *buffer, int size, int timeout)
{
uschar *p = buffer;
uschar *ptr = inblock->ptr;
uschar *ptrend = inblock->ptrend;
client_conn_ctx * cctx = inblock->cctx;

/* Loop for reading multiple packets or reading another packet after emptying
a previously-read one. */

for (;;)
  {
  int rc;

  /* If there is data in the input buffer left over from last time, copy
  characters from it until the end of a line, at which point we can return,
  having removed any whitespace (which will include CR) at the end of the line.
  The rules for SMTP say that lines end in CRLF, but there are have been cases
  of hosts using just LF, and other MTAs are reported to handle this, so we
  just look for LF. If we run out of characters before the end of a line,
  carry on to read the next incoming packet. */

  while (ptr < ptrend)
    {
    int c = *ptr++;
    if (c == '\n')
      {
      while (p > buffer && isspace(p[-1])) p--;
      *p = 0;
      inblock->ptr = ptr;
      return p - buffer;
      }
    *p++ = c;
    if (--size < 4)
      {
      *p = 0;                     /* Leave malformed line for error message */
      errno = ERRNO_SMTPFORMAT;
      return -1;
      }
    }

  /* Need to read a new input packet. */

  if((rc = ip_recv(cctx, inblock->buffer, inblock->buffersize, timeout)) <= 0)
    {
    DEBUG(D_deliver|D_transport|D_acl)
      debug_printf_indent(errno ? "  SMTP(%s)<<\n" : "  SMTP(closed)<<\n",
	strerror(errno));
    break;
    }

  /* Another block of data has been successfully read. Set up the pointers
  and let the loop continue. */

  ptrend = inblock->ptrend = inblock->buffer + rc;
  ptr = inblock->buffer;
  DEBUG(D_transport|D_acl) debug_printf_indent("read response data: size=%d\n", rc);
  }

/* Get here if there has been some kind of recv() error; errno is set, but we
ensure that the result buffer is empty before returning. */

*buffer = 0;
return -1;
}





/*************************************************
*              Read SMTP response                *
*************************************************/

/* This function reads an SMTP response with a timeout, and returns the
response in the given buffer, as a string. A multiline response will contain
newline characters between the lines. The function also analyzes the first
digit of the reply code and returns FALSE if it is not acceptable. FALSE is
also returned after a reading error. In this case buffer[0] will be zero, and
the error code will be in errno.

Arguments:
  sx        the SMTP connection (contains input block with holding buffer,
		socket, etc.)
  buffer    where to put the response
  size      the size of the buffer
  okdigit   the expected first digit of the response
  timeout   the timeout to use, in seconds

Returns:    TRUE if a valid, non-error response was received; else FALSE
*/
/*XXX could move to smtp transport; no other users */

BOOL
smtp_read_response(void * sx0, uschar *buffer, int size, int okdigit,
   int timeout)
{
smtp_context * sx = sx0;
uschar *ptr = buffer;
int count = 0;

errno = 0;  /* Ensure errno starts out zero */

#ifdef EXPERIMENTAL_PIPE_CONNECT
if (sx->pending_BANNER || sx->pending_EHLO)
  if (smtp_reap_early_pipe(sx, &count) != OK)
    {
    DEBUG(D_transport) debug_printf("failed reaping pipelined cmd responsess\n");
    return FALSE;
    }
#endif

/* This is a loop to read and concatenate the lines that make up a multi-line
response. */

for (;;)
  {
  if ((count = read_response_line(&sx->inblock, ptr, size, timeout)) < 0)
    return FALSE;

  HDEBUG(D_transport|D_acl|D_v)
    debug_printf_indent("  %s %s\n", ptr == buffer ? "SMTP<<" : "      ", ptr);

  /* Check the format of the response: it must start with three digits; if
  these are followed by a space or end of line, the response is complete. If
  they are followed by '-' this is a multi-line response and we must look for
  another line until the final line is reached. The only use made of multi-line
  responses is to pass them back as error messages. We therefore just
  concatenate them all within the buffer, which should be large enough to
  accept any reasonable number of lines. */

  if (count < 3 ||
     !isdigit(ptr[0]) ||
     !isdigit(ptr[1]) ||
     !isdigit(ptr[2]) ||
     (ptr[3] != '-' && ptr[3] != ' ' && ptr[3] != 0))
    {
    errno = ERRNO_SMTPFORMAT;    /* format error */
    return FALSE;
    }

  /* If the line we have just read is a terminal line, line, we are done.
  Otherwise more data has to be read. */

  if (ptr[3] != '-') break;

  /* Move the reading pointer upwards in the buffer and insert \n between the
  components of a multiline response. Space is left for this by read_response_
  line(). */

  ptr += count;
  *ptr++ = '\n';
  size -= count + 1;
  }

#ifdef TCP_FASTOPEN
  tfo_out_check(sx->cctx.sock);
#endif

/* Return a value that depends on the SMTP return code. On some systems a
non-zero value of errno has been seen at this point, so ensure it is zero,
because the caller of this function looks at errno when FALSE is returned, to
distinguish between an unexpected return code and other errors such as
timeouts, lost connections, etc. */

errno = 0;
return buffer[0] == okdigit;
}

/* End of smtp_out.c */
/* vi: aw ai sw=2
*/
