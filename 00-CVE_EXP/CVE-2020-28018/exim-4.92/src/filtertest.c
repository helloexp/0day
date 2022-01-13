/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */


/* Code for the filter test function. */

#include "exim.h"



/*************************************************
*    Read message and set body/size variables    *
*************************************************/

/* We have to read the remainder of the message in order to find its size, so
we can set up the message_body variables at the same time (in normal use, the
message_body variables are not set up unless needed). The reading code is
written out here rather than having options in read_message_data, in order to
keep that function as efficient as possible. (Later: this function is now
global because it is also used by the -bem testing option.) Handling
message_body_end is somewhat more tedious. Pile it all into a circular buffer
and sort out at the end.

Arguments:
  dot_ended   TRUE if message already terminated by '.'

Returns:      nothing
*/

void
read_message_body(BOOL dot_ended)
{
register int ch;
int body_len, body_end_len, header_size;
uschar *s;

message_body = store_malloc(message_body_visible + 1);
message_body_end = store_malloc(message_body_visible + 1);
s = message_body_end;
body_len = 0;
body_linecount = 0;
header_size = message_size;

if (!dot_ended && !feof(stdin))
  {
  if (!f.dot_ends)
    {
    while ((ch = getc(stdin)) != EOF)
      {
      if (ch == 0) body_zerocount++;
      if (ch == '\n') body_linecount++;
      if (body_len < message_body_visible) message_body[body_len++] = ch;
      *s++ = ch;
      if (s > message_body_end + message_body_visible) s = message_body_end;
      message_size++;
      }
    }
  else
    {
    int ch_state = 1;
    while ((ch = getc(stdin)) != EOF)
      {
      if (ch == 0) body_zerocount++;
      switch (ch_state)
        {
        case 0:                         /* Normal state */
        if (ch == '\n') { body_linecount++; ch_state = 1; }
        break;

        case 1:                         /* After "\n" */
        if (ch == '.')
          {
          ch_state = 2;
          continue;
          }
        if (ch != '\n') ch_state = 0;
        break;

        case 2:                         /* After "\n." */
        if (ch == '\n') goto READ_END;
        if (body_len < message_body_visible) message_body[body_len++] = '.';
        *s++ = '.';
        if (s > message_body_end + message_body_visible)
          s = message_body_end;
        message_size++;
        ch_state = 0;
        break;
        }
      if (body_len < message_body_visible) message_body[body_len++] = ch;
      *s++ = ch;
      if (s > message_body_end + message_body_visible) s = message_body_end;
      message_size++;
      }
    READ_END: ch = ch;  /* Some compilers don't like null statements */
    }
  if (s == message_body_end || s[-1] != '\n') body_linecount++;
  }

message_body[body_len] = 0;
message_body_size = message_size - header_size;

/* body_len stops at message_body_visible; it if got there, we may have
wrapped round in message_body_end. */

if (body_len >= message_body_visible)
  {
  int below = s - message_body_end;
  int above = message_body_visible - below;
  if (above > 0)
    {
    uschar *temp = store_get(below);
    memcpy(temp, message_body_end, below);
    memmove(message_body_end, s+1, above);
    memcpy(message_body_end + above, temp, below);
    s = message_body_end + message_body_visible;
    }
  }

*s = 0;
body_end_len = s - message_body_end;

/* Convert newlines and nulls in the body variables to spaces */

while (body_len > 0)
  {
  if (message_body[--body_len] == '\n' || message_body[body_len] == 0)
    message_body[body_len] = ' ';
  }

while (body_end_len > 0)
  {
  if (message_body_end[--body_end_len] == '\n' ||
      message_body_end[body_end_len] == 0)
    message_body_end[body_end_len] = ' ';
  }
}



/*************************************************
*            Test a mail filter                  *
*************************************************/

/* This is called when exim is run with the -bf option. At this point it is
running under an unprivileged uid/gid. A test message's headers have been read
into store, and the body of the message is still accessible on the standard
input if this is the first time this function has been called. It may be called
twice if both system and user filters are being tested.

Argument:
  fd          an fd containing the filter file
  filename    the name of the filter file
  is_system   TRUE if testing is to be as a system filter
  dot_ended   TRUE if message already terminated by '.'

Returns:      TRUE if no errors
*/

BOOL
filter_runtest(int fd, uschar *filename, BOOL is_system, BOOL dot_ended)
{
int rc, filter_type;
BOOL yield;
struct stat statbuf;
address_item *generated = NULL;
uschar *error, *filebuf;

/* Read the filter file into store as will be done by the router in a real
case. */

if (fstat(fd, &statbuf) != 0)
  {
  printf("exim: failed to get size of %s: %s\n", filename, strerror(errno));
  return FALSE;
  }

filebuf = store_get(statbuf.st_size + 1);
rc = read(fd, filebuf, statbuf.st_size);
(void)close(fd);

if (rc != statbuf.st_size)
  {
  printf("exim: error while reading %s: %s\n", filename, strerror(errno));
  return FALSE;
  }

filebuf[statbuf.st_size] = 0;

/* Check the filter type. User filters start with "# Exim filter" or "# Sieve
filter". If the filter type is not recognized, the file is treated as an
ordinary .forward file. System filters do not need the "# Exim filter" in order
to be recognized as Exim filters. */

filter_type = rda_is_filter(filebuf);
if (is_system && filter_type == FILTER_FORWARD) filter_type = FILTER_EXIM;

printf("Testing %s file \"%s\"\n\n",
  (filter_type == FILTER_EXIM)? "Exim filter" :
  (filter_type == FILTER_SIEVE)? "Sieve filter" :
  "forward file",
  filename);

/* Handle a plain .forward file */

if (filter_type == FILTER_FORWARD)
  {
  yield = parse_forward_list(filebuf,
    RDO_REWRITE,
    &generated,                     /* for generated addresses */
    &error,                         /* for errors */
    deliver_domain,                 /* incoming domain for \name */
    NULL,                           /* no check on includes */
    NULL);                          /* fail on syntax errors */

  switch(yield)
    {
    case FF_FAIL:
    printf("exim: forward file contains \":fail:\"\n");
    break;

    case FF_BLACKHOLE:
    printf("exim: forwardfile contains \":blackhole:\"\n");
    break;

    case FF_ERROR:
    printf("exim: error in forward file: %s\n", error);
    return FALSE;
    }

  if (generated == NULL)
    printf("exim: no addresses generated from forward file\n");

  else
    {
    printf("exim: forward file generated:\n");
    while (generated != NULL)
      {
      printf("  %s\n", generated->address);
      generated = generated->next;
      }
    }

  return TRUE;
  }

/* For a filter, set up the message_body variables and the message size if this
is the first time this function has been called. */

if (message_body == NULL) read_message_body(dot_ended);

/* Now pass the filter file to the function that interprets it. Because
filter_test is not FILTER_NONE, the interpreter will output comments about what
it is doing. No need to clean up store. Indeed, we must not, because we may be
testing a system filter that is going to be followed by a user filter test. */

if (is_system)
  {
  f.system_filtering = TRUE;
  f.enable_dollar_recipients = TRUE; /* Permit $recipients in system filter */
  yield = filter_interpret
    (filebuf,
    RDO_DEFER|RDO_FAIL|RDO_FILTER|RDO_FREEZE|RDO_REWRITE, &generated, &error);
  f.enable_dollar_recipients = FALSE;
  f.system_filtering = FALSE;
  }
else
  {
  yield = (filter_type == FILTER_SIEVE)?
    sieve_interpret(filebuf, RDO_REWRITE, NULL, NULL, NULL, NULL, &generated, &error)
    :
    filter_interpret(filebuf, RDO_REWRITE, &generated, &error);
  }

return yield != FF_ERROR;
}

/* End of filtertest.c */
