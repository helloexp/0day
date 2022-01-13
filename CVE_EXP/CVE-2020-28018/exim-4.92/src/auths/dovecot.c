/*
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 * Copyright (c) 2006-2017 The Exim Maintainers
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* A number of modifications have been made to the original code. Originally I
commented them specially, but now they are getting quite extensive, so I have
ceased doing that. The biggest change is to use unbuffered I/O on the socket
because using C buffered I/O gives problems on some operating systems. PH */

/* Protocol specifications:
 * Dovecot 1, protocol version 1.1
 *   http://wiki.dovecot.org/Authentication%20Protocol
 *
 * Dovecot 2, protocol version 1.1
 *   http://wiki2.dovecot.org/Design/AuthProtocol
 */

#include "../exim.h"
#include "dovecot.h"

#define VERSION_MAJOR  1
#define VERSION_MINOR  0

/* http://wiki.dovecot.org/Authentication%20Protocol
"The maximum line length isn't defined,
 but it's currently expected to fit into 8192 bytes"
*/
#define DOVECOT_AUTH_MAXLINELEN 8192

/* This was hard-coded as 8.
AUTH req C->S sends {"AUTH", id, mechanism, service } + params, 5 defined for
Dovecot 1; Dovecot 2 (same protocol version) defines 9.

Master->Server sends {"USER", id, userid} + params, 6 defined.
Server->Client only gives {"OK", id} + params, unspecified, only 1 guaranteed.

We only define here to accept S->C; max seen is 3+<unspecified>, plus the two
for the command and id, where unspecified might include _at least_ user=...

So: allow for more fields than we ever expect to see, while aware that count
can go up without changing protocol version.
The cost is the length of an array of pointers on the stack.
*/
#define DOVECOT_AUTH_MAXFIELDCOUNT 16

/* Options specific to the authentication mechanism. */
optionlist auth_dovecot_options[] = {
       {
       "server_socket",
       opt_stringptr,
       (void *)(offsetof(auth_dovecot_options_block, server_socket))
       },
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int auth_dovecot_options_count =
       sizeof(auth_dovecot_options) / sizeof(optionlist);

/* Default private options block for the authentication method. */

auth_dovecot_options_block auth_dovecot_option_defaults = {
       NULL,                           /* server_socket */
};




#ifdef MACRO_PREDEF

/* Dummy values */
void auth_dovecot_init(auth_instance *ablock) {}
int auth_dovecot_server(auth_instance *ablock, uschar *data) {return 0;}
int auth_dovecot_client(auth_instance *ablock, void * sx,
  int timeout, uschar *buffer, int buffsize) {return 0;}

#else   /*!MACRO_PREDEF*/


/* Static variables for reading from the socket */

static uschar sbuffer[256];
static int socket_buffer_left;



/*************************************************
 *          Initialization entry point           *
 *************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */

void auth_dovecot_init(auth_instance *ablock)
{
       auth_dovecot_options_block *ob =
               (auth_dovecot_options_block *)(ablock->options_block);

       if (ablock->public_name == NULL)
               ablock->public_name = ablock->name;
       if (ob->server_socket != NULL)
               ablock->server = TRUE;
       ablock->client = FALSE;
}

/*************************************************
 *    "strcut" to split apart server lines       *
 *************************************************/

/* Dovecot auth protocol uses TAB \t as delimiter; a line consists
of a command-name, TAB, and then any parameters, each separated by a TAB.
A parameter can be param=value or a bool, just param.

This function modifies the original str in-place, inserting NUL characters.
It initialises ptrs entries, setting all to NULL and only setting
non-NULL N entries, where N is the return value, the number of fields seen
(one more than the number of tabs).

Note that the return value will always be at least 1, is the count of
actual fields (so last valid offset into ptrs is one less).
*/

static int
strcut(uschar *str, uschar **ptrs, int nptrs)
{
       uschar *last_sub_start = str;
       int n;

       for (n = 0; n < nptrs; n++)
               ptrs[n] = NULL;
       n = 1;

       while (*str) {
               if (*str == '\t') {
                       if (n <= nptrs) {
                               *ptrs++ = last_sub_start;
                               last_sub_start = str + 1;
                               *str = '\0';
                       }
                       n++;
               }
               str++;
       }

       /* It's acceptable for the string to end with a tab character.  We see
       this in AUTH PLAIN without an initial response from the client, which
       causing us to send "334 " and get the data from the client. */
       if (n <= nptrs) {
               *ptrs = last_sub_start;
       } else {
               HDEBUG(D_auth) debug_printf("dovecot: warning: too many results from tab-splitting; saw %d fields, room for %d\n", n, nptrs);
               n = nptrs;
       }

       return n <= nptrs ? n : nptrs;
}

static void debug_strcut(uschar **ptrs, int nlen, int alen) ARG_UNUSED;
static void
debug_strcut(uschar **ptrs, int nlen, int alen)
{
        int i;
        debug_printf("%d read but unreturned bytes; strcut() gave %d results: ",
                        socket_buffer_left, nlen);
        for (i = 0; i < nlen; i++) {
                debug_printf(" {%s}", ptrs[i]);
        }
        if (nlen < alen)
                debug_printf(" last is %s\n", ptrs[i] ? ptrs[i] : US"<null>");
        else
                debug_printf(" (max for capacity)\n");
}

#define CHECK_COMMAND(str, arg_min, arg_max) do { \
       if (strcmpic(US(str), args[0]) != 0) \
               goto out; \
       if (nargs - 1 < (arg_min)) \
               goto out; \
       if ( (arg_max != -1) && (nargs - 1 > (arg_max)) ) \
               goto out; \
} while (0)

#define OUT(msg) do { \
       auth_defer_msg = (US msg); \
       goto out; \
} while(0)



/*************************************************
*      "fgets" to read directly from socket      *
*************************************************/

/* Added by PH after a suggestion by Steve Usher because the previous use of
C-style buffered I/O gave trouble. */

static uschar *
dc_gets(uschar *s, int n, int fd)
{
int p = 0;
int count = 0;

for (;;)
  {
  if (socket_buffer_left == 0)
    {
    socket_buffer_left = read(fd, sbuffer, sizeof(sbuffer));
    if (socket_buffer_left == 0) { if (count == 0) return NULL; else break; }
    p = 0;
    }

  while (p < socket_buffer_left)
    {
    if (count >= n - 1) break;
    s[count++] = sbuffer[p];
    if (sbuffer[p++] == '\n') break;
    }

  memmove(sbuffer, sbuffer + p, socket_buffer_left - p);
  socket_buffer_left -= p;

  if (s[count-1] == '\n' || count >= n - 1) break;
  }

s[count] = '\0';
return s;
}




/*************************************************
*              Server entry point                *
*************************************************/

int
auth_dovecot_server(auth_instance * ablock, uschar * data)
{
auth_dovecot_options_block *ob =
       (auth_dovecot_options_block *) ablock->options_block;
struct sockaddr_un sa;
uschar buffer[DOVECOT_AUTH_MAXLINELEN];
uschar *args[DOVECOT_AUTH_MAXFIELDCOUNT];
uschar *auth_command;
uschar *auth_extra_data = US"";
uschar *p;
int nargs, tmp;
int crequid = 1, cont = 1, fd = -1, ret = DEFER;
BOOL found = FALSE, have_mech_line = FALSE;

HDEBUG(D_auth) debug_printf("dovecot authentication\n");

if (!data)
  {
  ret = FAIL;
  goto out;
  }

memset(&sa, 0, sizeof(sa));
sa.sun_family = AF_UNIX;

/* This was the original code here: it is nonsense because strncpy()
does not return an integer. I have converted this to use the function
that formats and checks length. PH */

/*
if (strncpy(sa.sun_path, ob->server_socket, sizeof(sa.sun_path)) < 0) {
}
*/

if (!string_format(US sa.sun_path, sizeof(sa.sun_path), "%s",
		  ob->server_socket))
  {
  auth_defer_msg = US"authentication socket path too long";
  return DEFER;
  }

auth_defer_msg = US"authentication socket connection error";

if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
  return DEFER;

if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
  goto out;

auth_defer_msg = US"authentication socket protocol error";

socket_buffer_left = 0;  /* Global, used to read more than a line but return by line */
while (cont)
  {
  if (dc_gets(buffer, sizeof(buffer), fd) == NULL)
    OUT("authentication socket read error or premature eof");
  p = buffer + Ustrlen(buffer) - 1;
  if (*p != '\n')
    OUT("authentication socket protocol line too long");

  *p = '\0';
  HDEBUG(D_auth) debug_printf("received: %s\n", buffer);

  nargs = strcut(buffer, args, sizeof(args) / sizeof(args[0]));

  /* HDEBUG(D_auth) debug_strcut(args, nargs, sizeof(args) / sizeof(args[0])); */

  /* Code below rewritten by Kirill Miazine (km@krot.org). Only check commands that
    Exim will need. Original code also failed if Dovecot server sent unknown
    command. E.g. COOKIE in version 1.1 of the protocol would cause troubles. */
  /* pdp: note that CUID is a per-connection identifier sent by the server,
    which increments at server discretion.
    By contrast, the "id" field of the protocol is a connection-specific request
    identifier, which needs to be unique per request from the client and is not
    connected to the CUID value, so we ignore CUID from server.  It's purely for
    diagnostics. */

  if (Ustrcmp(args[0], US"VERSION") == 0)
    {
    CHECK_COMMAND("VERSION", 2, 2);
    if (Uatoi(args[1]) != VERSION_MAJOR)
      OUT("authentication socket protocol version mismatch");
    }
  else if (Ustrcmp(args[0], US"MECH") == 0)
    {
    CHECK_COMMAND("MECH", 1, INT_MAX);
    have_mech_line = TRUE;
    if (strcmpic(US args[1], ablock->public_name) == 0)
      found = TRUE;
    }
  else if (Ustrcmp(args[0], US"SPID") == 0)
    {
    /* Unfortunately the auth protocol handshake wasn't designed well
    to differentiate between auth-client/userdb/master. auth-userdb
    and auth-master send VERSION + SPID lines only and nothing
    afterwards, while auth-client sends VERSION + MECH + SPID +
    CUID + more. The simplest way that we can determine if we've
    connected to the correct socket is to see if MECH line exists or
    not (alternatively we'd have to have a small timeout after SPID
    to see if CUID is sent or not). */

    if (!have_mech_line)
      OUT("authentication socket type mismatch"
	" (connected to auth-master instead of auth-client)");
    }
  else if (Ustrcmp(args[0], US"DONE") == 0)
    {
    CHECK_COMMAND("DONE", 0, 0);
    cont = 0;
    }
  }

if (!found)
  {
  auth_defer_msg = string_sprintf(
    "Dovecot did not advertise mechanism \"%s\" to us", ablock->public_name);
  goto out;
  }

/* Added by PH: data must not contain tab (as it is
b64 it shouldn't, but check for safety). */

if (Ustrchr(data, '\t') != NULL)
  {
  ret = FAIL;
  goto out;
  }

/* Added by PH: extra fields when TLS is in use or if the TCP/IP
connection is local. */

if (tls_in.cipher != NULL)
  auth_extra_data = string_sprintf("secured\t%s%s",
     tls_in.certificate_verified? "valid-client-cert" : "",
     tls_in.certificate_verified? "\t" : "");

else if (  interface_address != NULL
        && Ustrcmp(sender_host_address, interface_address) == 0)
  auth_extra_data = US"secured\t";


/****************************************************************************
The code below was the original code here. It didn't work. A reading of the
file auth-protocol.txt.gz that came with Dovecot 1.0_beta8 indicated that
this was not right. Maybe something changed. I changed it to move the
service indication into the AUTH command, and it seems to be better. PH

fprintf(f, "VERSION\t%d\t%d\r\nSERVICE\tSMTP\r\nCPID\t%d\r\n"
       "AUTH\t%d\t%s\trip=%s\tlip=%s\tresp=%s\r\n",
       VERSION_MAJOR, VERSION_MINOR, getpid(), cuid,
       ablock->public_name, sender_host_address, interface_address,
       data ? CS  data : "");

Subsequently, the command was modified to add "secured" and "valid-client-
cert" when relevant.
****************************************************************************/

auth_command = string_sprintf("VERSION\t%d\t%d\nCPID\t%d\n"
       "AUTH\t%d\t%s\tservice=smtp\t%srip=%s\tlip=%s\tnologin\tresp=%s\n",
       VERSION_MAJOR, VERSION_MINOR, getpid(), crequid,
       ablock->public_name, auth_extra_data, sender_host_address,
       interface_address, data);

if (write(fd, auth_command, Ustrlen(auth_command)) < 0)
  HDEBUG(D_auth) debug_printf("error sending auth_command: %s\n",
    strerror(errno));

HDEBUG(D_auth) debug_printf("sent: %s", auth_command);

while (1)
  {
  uschar *temp;
  uschar *auth_id_pre = NULL;
  int i;

  if (dc_gets(buffer, sizeof(buffer), fd) == NULL)
    {
    auth_defer_msg = US"authentication socket read error or premature eof";
    goto out;
    }

  buffer[Ustrlen(buffer) - 1] = 0;
  HDEBUG(D_auth) debug_printf("received: %s\n", buffer);
  nargs = strcut(buffer, args, sizeof(args) / sizeof(args[0]));

  if (Uatoi(args[1]) != crequid)
    OUT("authentication socket connection id mismatch");

  switch (toupper(*args[0]))
    {
    case 'C':
      CHECK_COMMAND("CONT", 1, 2);

      if ((tmp = auth_get_no64_data(&data, US args[2])) != OK)
	{
	ret = tmp;
	goto out;
	}

      /* Added by PH: data must not contain tab (as it is
      b64 it shouldn't, but check for safety). */

      if (Ustrchr(data, '\t') != NULL)
        {
	ret = FAIL;
	goto out;
	}

      temp = string_sprintf("CONT\t%d\t%s\n", crequid, data);
      if (write(fd, temp, Ustrlen(temp)) < 0)
	OUT("authentication socket write error");
      break;

    case 'F':
      CHECK_COMMAND("FAIL", 1, -1);

      for (i=2; (i<nargs) && (auth_id_pre == NULL); i++)
	{
	if ( Ustrncmp(args[i], US"user=", 5) == 0 )
	  {
	  auth_id_pre = args[i]+5;
	  expand_nstring[1] = auth_vars[0] = string_copy(auth_id_pre); /* PH */
	  expand_nlength[1] = Ustrlen(auth_id_pre);
	  expand_nmax = 1;
	  }
	}

      ret = FAIL;
      goto out;

    case 'O':
      CHECK_COMMAND("OK", 2, -1);

      /* Search for the "user=$USER" string in the args array
      and return the proper value.  */

      for (i=2; (i<nargs) && (auth_id_pre == NULL); i++)
	{
	if ( Ustrncmp(args[i], US"user=", 5) == 0 )
	  {
	  auth_id_pre = args[i]+5;
	  expand_nstring[1] = auth_vars[0] = string_copy(auth_id_pre); /* PH */
	  expand_nlength[1] = Ustrlen(auth_id_pre);
	  expand_nmax = 1;
	  }
	}

      if (auth_id_pre == NULL)
        OUT("authentication socket protocol error, username missing");

      ret = OK;
      /* fallthrough */

    default:
      goto out;
    }
  }

out:
/* close the socket used by dovecot */
if (fd >= 0)
  close(fd);

/* Expand server_condition as an authorization check */
return ret == OK ? auth_check_serv_cond(ablock) : ret;
}


#endif   /*!MACRO_PREDEF*/
