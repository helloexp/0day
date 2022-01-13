/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "plaintext.h"


/* Options specific to the plaintext authentication mechanism. */

optionlist auth_plaintext_options[] = {
  { "client_ignore_invalid_base64", opt_bool,
      (void *)(offsetof(auth_plaintext_options_block, client_ignore_invalid_base64)) },
  { "client_send",        opt_stringptr,
      (void *)(offsetof(auth_plaintext_options_block, client_send)) },
  { "server_prompts",     opt_stringptr,
      (void *)(offsetof(auth_plaintext_options_block, server_prompts)) }
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int auth_plaintext_options_count =
  sizeof(auth_plaintext_options)/sizeof(optionlist);

/* Default private options block for the plaintext authentication method. */

auth_plaintext_options_block auth_plaintext_option_defaults = {
  NULL,              /* server_prompts */
  NULL,              /* client_send */
  FALSE              /* client_ignore_invalid_base64 */
};


#ifdef MACRO_PREDEF

/* Dummy values */
void auth_plaintext_init(auth_instance *ablock) {}
int auth_plaintext_server(auth_instance *ablock, uschar *data) {return 0;}
int auth_plaintext_client(auth_instance *ablock, void * sx, int timeout,
    uschar *buffer, int buffsize) {return 0;}

#else   /*!MACRO_PREDEF*/



/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */

void
auth_plaintext_init(auth_instance *ablock)
{
auth_plaintext_options_block *ob =
  (auth_plaintext_options_block *)(ablock->options_block);
if (ablock->public_name == NULL) ablock->public_name = ablock->name;
if (ablock->server_condition != NULL) ablock->server = TRUE;
if (ob->client_send != NULL) ablock->client = TRUE;
}



/*************************************************
*             Server entry point                 *
*************************************************/

/* For interface, see auths/README */

int
auth_plaintext_server(auth_instance *ablock, uschar *data)
{
auth_plaintext_options_block *ob =
  (auth_plaintext_options_block *)(ablock->options_block);
const uschar *prompts = ob->server_prompts;
uschar *clear, *end, *s;
int number = 1;
int len, rc;
int sep = 0;

/* Expand a non-empty list of prompt strings */

if (prompts != NULL)
  {
  prompts = expand_cstring(prompts);
  if (prompts == NULL)
    {
    auth_defer_msg = expand_string_message;
    return DEFER;
    }
  }

/* If data was supplied on the AUTH command, decode it, and split it up into
multiple items at binary zeros. The strings are put into $auth1, $auth2, etc,
up to a maximum. To retain backwards compatibility, they are also put int $1,
$2, etc. If the data consists of the string "=" it indicates a single, empty
string. */

if (*data != 0)
  {
  if (Ustrcmp(data, "=") == 0)
    {
    auth_vars[0] = expand_nstring[++expand_nmax] = US"";
    expand_nlength[expand_nmax] = 0;
    }
  else
    {
    if ((len = b64decode(data, &clear)) < 0) return BAD64;
    end = clear + len;
    while (clear < end && expand_nmax < EXPAND_MAXN)
      {
      if (expand_nmax < AUTH_VARS) auth_vars[expand_nmax] = clear;
      expand_nstring[++expand_nmax] = clear;
      while (*clear != 0) clear++;
      expand_nlength[expand_nmax] = clear++ - expand_nstring[expand_nmax];
      }
    }
  }

/* Now go through the list of prompt strings. Skip over any whose data has
already been provided as part of the AUTH command. For the rest, send them
out as prompts, and get a data item back. If the data item is "*", abandon the
authentication attempt. Otherwise, split it into items as above. */

while ((s = string_nextinlist(&prompts, &sep, big_buffer, big_buffer_size))
        != NULL && expand_nmax < EXPAND_MAXN)
  {
  if (number++ <= expand_nmax) continue;
  if ((rc = auth_get_data(&data, s, Ustrlen(s))) != OK) return rc;
  if ((len = b64decode(data, &clear)) < 0) return BAD64;
  end = clear + len;

  /* This loop must run at least once, in case the length is zero */
  do
    {
    if (expand_nmax < AUTH_VARS) auth_vars[expand_nmax] = clear;
    expand_nstring[++expand_nmax] = clear;
    while (*clear != 0) clear++;
    expand_nlength[expand_nmax] = clear++ - expand_nstring[expand_nmax];
    }
  while (clear < end && expand_nmax < EXPAND_MAXN);
  }

/* We now have a number of items of data in $auth1, $auth2, etc (and also, for
compatibility, in $1, $2, etc). Authentication and authorization are handled
together for this authenticator by expanding the server_condition option. Note
that ablock->server_condition is always non-NULL because that's what configures
this authenticator as a server. */

return auth_check_serv_cond(ablock);
}



/*************************************************
*              Client entry point                *
*************************************************/

/* For interface, see auths/README */

int
auth_plaintext_client(
  auth_instance *ablock,                 /* authenticator block */
  void * sx,				 /* smtp connextion */
  int timeout,                           /* command timeout */
  uschar *buffer,                        /* buffer for reading response */
  int buffsize)                          /* size of buffer */
{
auth_plaintext_options_block *ob =
  (auth_plaintext_options_block *)(ablock->options_block);
const uschar *text = ob->client_send;
uschar *s;
BOOL first = TRUE;
int sep = 0;
int auth_var_idx = 0;

/* The text is broken up into a number of different data items, which are
sent one by one. The first one is sent with the AUTH command; the remainder are
sent in response to subsequent prompts. Each is expanded before being sent. */

while ((s = string_nextinlist(&text, &sep, big_buffer, big_buffer_size)))
  {
  int i, len, clear_len;
  uschar *ss = expand_string(s);
  uschar *clear;

  /* Forced expansion failure is not an error; authentication is abandoned. On
  all but the first string, we have to abandon the authentication attempt by
  sending a line containing "*". Save the failed expansion string, because it
  is in big_buffer, and that gets used by the sending function. */

  if (!ss)
    {
    uschar *ssave = string_copy(s);
    if (!first)
      {
      if (smtp_write_command(sx, SCMD_FLUSH, "*\r\n") >= 0)
        (void) smtp_read_response(sx, US buffer, buffsize, '2', timeout);
      }
    if (f.expand_string_forcedfail)
      {
      *buffer = 0;       /* No message */
      return CANCELLED;
      }
    string_format(buffer, buffsize, "expansion of \"%s\" failed in %s "
      "authenticator: %s", ssave, ablock->name, expand_string_message);
    return ERROR;
    }

  len = Ustrlen(ss);

  /* The character ^ is used as an escape for a binary zero character, which is
  needed for the PLAIN mechanism. It must be doubled if really needed. */

  for (i = 0; i < len; i++)
    if (ss[i] == '^')
      if (ss[i+1] != '^')
	ss[i] = 0;
      else
        {
        i++;
        len--;
        memmove(ss + i, ss + i + 1, len - i);
        }

  /* The first string is attached to the AUTH command; others are sent
  unembellished. */

  if (first)
    {
    first = FALSE;
    if (smtp_write_command(sx, SCMD_FLUSH, "AUTH %s%s%s\r\n",
         ablock->public_name, len == 0 ? "" : " ", b64encode(ss, len)) < 0)
      return FAIL_SEND;
    }
  else
    {
    if (smtp_write_command(sx, SCMD_FLUSH, "%s\r\n", b64encode(ss, len)) < 0)
      return FAIL_SEND;
    }

  /* If we receive a success response from the server, authentication
  has succeeded. There may be more data to send, but is there any point
  in provoking an error here? */

  if (smtp_read_response(sx, US buffer, buffsize, '2', timeout)) return OK;

  /* Not a success response. If errno != 0 there is some kind of transmission
  error. Otherwise, check the response code in the buffer. If it starts with
  '3', more data is expected. */

  if (errno != 0 || buffer[0] != '3') return FAIL;

  /* If there is no more data to send, we have to cancel the authentication
  exchange and return ERROR. */

  if (!text)
    {
    if (smtp_write_command(sx, SCMD_FLUSH, "*\r\n") >= 0)
      (void)smtp_read_response(sx, US buffer, buffsize, '2', timeout);
    string_format(buffer, buffsize, "Too few items in client_send in %s "
      "authenticator", ablock->name);
    return ERROR;
    }

  /* Now that we know we'll continue, we put the received data into $auth<n>,
  if possible. First, decode it: buffer+4 skips over the SMTP status code. */

  clear_len = b64decode(buffer+4, &clear);

  /* If decoding failed, the default is to terminate the authentication, and
  return FAIL, with the SMTP response still in the buffer. However, if client_
  ignore_invalid_base64 is set, we ignore the error, and put an empty string
  into $auth<n>. */

  if (clear_len < 0)
    {
    uschar *save_bad = string_copy(buffer);
    if (!ob->client_ignore_invalid_base64)
      {
      if (smtp_write_command(sx, SCMD_FLUSH, "*\r\n") >= 0)
        (void)smtp_read_response(sx, US buffer, buffsize, '2', timeout);
      string_format(buffer, buffsize, "Invalid base64 string in server "
        "response \"%s\"", save_bad);
      return CANCELLED;
      }
    clear = US"";
    clear_len = 0;
    }

  if (auth_var_idx < AUTH_VARS)
    auth_vars[auth_var_idx++] = string_copy(clear);
  }

/* Control should never actually get here. */

return FAIL;
}

#endif   /*!MACRO_PREDEF*/
/* End of plaintext.c */
