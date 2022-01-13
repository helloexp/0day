/*************************************************
*                 Exim Monitor                   *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* This module contains code for scanning the main log,
extracting information from it, and displaying a "tail". */

#include "em_hdr.h"

#define log_buffer_len 4096      /* For each log entry */

/* If anonymizing, don't alter these strings (this is all an ad hoc hack). */

#ifdef ANONYMIZE
static char *oklist[] = {
  "Completed",
  "defer",
  "from",
  "Connection timed out",
  "Start queue run: pid=",
  "End queue run: pid=",
  "host lookup did not complete",
  "unexpected disconnection while reading SMTP command from",
  "verify failed for SMTP recipient",
  "H=",
  "U=",
  "id=",
  "<",
  ">",
  "(",
  ")",
  "[",
  "]",
  "@",
  "=",
  "*",
  ".",
  "-",
  "\"",
  " ",
  "\n"};
static int oklist_size = sizeof(oklist) / sizeof(uschar *);
#endif



/*************************************************
*             Write to the log display           *
*************************************************/

static int visible = 0;
static int scrolled = FALSE;
static int size = 0;
static int top = 0;

static void show_log(char *s, ...) PRINTF_FUNCTION(1,2);

static void show_log(char *s, ...)
{
int length, newtop;
va_list ap;
XawTextBlock b;
uschar buffer[log_buffer_len + 24];

/* Do nothing if not tailing a log */

if (log_widget == NULL) return;

/* Initialize the text block structure */

b.firstPos = 0;
b.ptr = CS buffer;
b.format = FMT8BIT;

/* We want to know whether the window has been scrolled back or not,
so that we can cease automatically scrolling with new text. This turns
out to be tricky with the text widget. We can detect whether the
scroll bar has been operated by checking on the "top" value, but it's
harder to detect that it has been returned to the bottom. The following
heuristic does its best. */

newtop = XawTextTopPosition(log_widget);
if (newtop != top)
  {
  if (!scrolled)
    {
    visible = size - top;      /* save size of window */
    scrolled = newtop < top;
    }
  else if (newtop > size - visible) scrolled = FALSE;
  top = newtop;
  }

/* Format the text that is to be written. */

va_start(ap, s);
vsprintf(CS buffer, s, ap);
va_end(ap);
length = Ustrlen(buffer);

/* If we are anonymizing for screen shots, flatten various things. */

#ifdef ANONYMIZE
  {
  uschar *p = buffer + 9;
  if (p[6] == '-' && p[13] == '-') p += 17;

  while (p < buffer + length)
    {
    int i;

    /* Check for strings to be left alone */

    for (i = 0; i < oklist_size; i++)
      {
      int len = Ustrlen(oklist[i]);
      if (Ustrncmp(p, oklist[i], len) == 0)
        {
        p += len;
        break;
        }
      }
    if (i < oklist_size) continue;

    /* Leave driver names, size, protocol, alone */

    if ((*p == 'D' || *p == 'P' || *p == 'T' || *p == 'S' || *p == 'R') &&
        p[1] == '=')
      {
      p += 2;
      while (*p != ' ' && *p != 0) p++;
      continue;
      }

    /* Leave C= text alone */

    if (Ustrncmp(p, "C=\"", 3) == 0)
      {
      p += 3;
      while (*p != 0 && *p != '"') p++;
      continue;
      }

    /* Flatten remaining chars */

    if (isdigit(*p)) *p++ = 'x';
    else if (isalpha(*p)) *p++ = 'x';
    else *p++ = '$';
    }
  }
#endif

/* If this would overflow the buffer, throw away 50% of the
current stuff in the buffer. Code defensively against odd
extreme cases that shouldn't actually arise. */

if (size + length > log_buffer_size)
  {
  if (size == 0) length = log_buffer_size/2; else
    {
    int cutcount = log_buffer_size/2;
    if (cutcount > size) cutcount = size; else
      {
      while (cutcount < size && log_display_buffer[cutcount] != '\n')
        cutcount++;
      cutcount++;
      }
    b.length = 0;
    XawTextReplace(log_widget, 0, cutcount, &b);
    size -= cutcount;
    top -= cutcount;
    if (top < 0) top = 0;
    if (top < cutcount) XawTextInvalidate(log_widget, 0, 999999);
    xs_SetValues(log_widget, 1, "displayPosition", top);
    }
  }

/* Insert the new text at the end of the buffer. */

b.length = length;
XawTextReplace(log_widget, 999999, 999999, &b);
size += length;

/* When not scrolled back, we want to keep the bottom line
always visible. Put the insert point at the start of it because
this stops left/right scrolling with some X libraries. */

if (!scrolled)
  {
  XawTextSetInsertionPoint(log_widget, size - length);
  top = XawTextTopPosition(log_widget);
  }
}




/*************************************************
*            Function to read the log            *
*************************************************/

/* We read any new log entries, and use their data to
updated total counts for the configured stripcharts.
The count for the queue chart is handled separately.
We also munge the log entries and display a one-line
version in the log window. */

void read_log(void)
{
struct stat statdata;
uschar buffer[log_buffer_len];

/* If log is not yet open, skip all of this. */

if (LOG != NULL)
  {
  if (fseek(LOG, log_position, SEEK_SET))
    {
    perror("logfile fseek");
    exit(1);
    }

  while (Ufgets(buffer, log_buffer_len, LOG) != NULL)
    {
    uschar *id;
    uschar *p = buffer;
    void *reset_point;
    int length = Ustrlen(buffer);
    int i;

    /* Skip totally blank lines (paranoia: there shouldn't be any) */

    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\n') continue;

    /* We should now have a complete log entry in the buffer; check
    it for various regular expression matches and take appropriate
    action. Get the current store point so we can reset to it. */

    reset_point = store_get(0);

    /* First, update any stripchart data values, noting that the zeroth
    stripchart is the queue length, which is handled elsewhere, and the
    1st may the a size monitor. */

    for (i = stripchart_varstart; i < stripchart_number; i++)
      {
      if (pcre_exec(stripchart_regex[i], NULL, CS buffer, length, 0, PCRE_EOPT,
            NULL, 0) >= 0)
        stripchart_total[i]++;
      }

    /* Munge the log entry and display shortened form on one line.
    We omit the date and show only the time. Remove any time zone offset.
    Take note of the presence of [pid]. */

    if (pcre_exec(yyyymmdd_regex,NULL,CS buffer,length,0,PCRE_EOPT,NULL,0) >= 0)
      {
      int pidlength = 0;
      if ((buffer[20] == '+' || buffer[20] == '-') &&
          isdigit(buffer[21]) && buffer[25] == ' ')
        memmove(buffer + 20, buffer + 26, Ustrlen(buffer + 26) + 1);
      if (buffer[20] == '[')
        {
        while (Ustrchr("[]0123456789", buffer[20+pidlength++]) != NULL);
        }
      id = string_copyn(buffer + 20 + pidlength, MESSAGE_ID_LENGTH);
      show_log("%s", buffer+11);
      }
    else
      {
      id = US"";
      show_log("%s", buffer);
      }

    /* Deal with frozen and unfrozen messages */

    if (strstric(buffer, US"frozen", FALSE) != NULL)
      {
      queue_item *qq = find_queue(id, queue_noop, 0);
      if (qq)
        qq->frozen = strstric(buffer, US"unfrozen", FALSE) == NULL;
      }

    /* Notice defer messages, and add the destination if it
    isn't already on the list for this message, with a pointer
    to the parent if we can. */

    if ((p = Ustrstr(buffer, "==")) != NULL)
      {
      queue_item *qq = find_queue(id, queue_noop, 0);
      if (qq != NULL)
        {
        dest_item *d;
        uschar *q, *r;
        p += 2;
        while (isspace(*p)) p++;
        q = p;
        while (*p != 0 && !isspace(*p))
          {
          if (*p++ != '\"') continue;
          while (*p != 0)
            {
            if (*p == '\\') p += 2;
              else if (*p++ == '\"') break;
            }
          }
        *p++ = 0;
        if ((r = strstric(q, qualify_domain, FALSE)) != NULL &&
          *(--r) == '@') *r = 0;

        /* If we already have this destination, as tested case-insensitively,
        do not add it to the destinations list. */

        d = find_dest(qq, q, dest_add, TRUE);

        if (d->parent == NULL)
          {
          while (isspace(*p)) p++;
          if (*p == '<')
            {
            dest_item *dd;
            q = ++p;
            while (*p != 0 && *p != '>') p++;
            *p = 0;
            if ((p = strstric(q, qualify_domain, FALSE)) != NULL &&
              *(--p) == '@') *p = 0;
            dd = find_dest(qq, q, dest_noop, FALSE);
            if (dd != NULL && dd != d) d->parent = dd;
            }
          }
        }
      }

    store_reset(reset_point);
    }
  }


/* We have to detect when the log file is changed, and switch to the new file.
In practice, for non-datestamped files, this means that some deliveries might
go unrecorded, since they'll be written to the old file, but this usually
happens in the middle of the night, and I don't think the hassle of keeping
track of two log files is worth it.

First we check the datestamped name of the log file if necessary; if it is
different to the file we currently have open, go for the new file. As happens
in Exim itself, we leave in the following inode check, even when datestamping
because it does no harm and will cope should a file actually be renamed for
some reason.

The test for a changed log file is to look up the inode of the file by name and
compare it with the saved inode of the file we currently are processing. This
accords with the usual interpretation of POSIX and other Unix specs that imply
"one file, one inode". However, it appears that on some Digital systems, if an
open file is unlinked, a new file may be created with the same inode while the
old file remains in existence. This can happen if the old log file is renamed,
processed in some way, and then deleted. To work round this, also test for a
link count of zero on the currently open file. */

if (log_datestamping)
  {
  uschar log_file_wanted[256];
  /* Do *not* use "%s" here, we need the %D datestamp in the log_file to
   *   be expanded! */
  string_format(log_file_wanted, sizeof(log_file_wanted), CS log_file);
  if (Ustrcmp(log_file_wanted, log_file_open) != 0)
    {
    if (LOG != NULL)
      {
      fclose(LOG);
      LOG = NULL;
      }
    Ustrcpy(log_file_open, log_file_wanted);
    }
  }

if (LOG == NULL ||
    (fstat(fileno(LOG), &statdata) == 0 && statdata.st_nlink == 0) ||
    (Ustat(log_file, &statdata) == 0 && log_inode != statdata.st_ino))
  {
  FILE *TEST;

  /* Experiment shows that sometimes you can't immediately open
  the new log file - presumably immediately after the old one
  is renamed and before the new one exists. Therefore do a
  trial open first to be sure. */

  if ((TEST = fopen(CS log_file_open, "r")) != NULL)
    {
    if (LOG != NULL) fclose(LOG);
    LOG = TEST;
    if (fstat(fileno(LOG), &statdata))
      {
      fprintf(stderr, "fstat %s: %s\n", log_file_open, strerror(errno));
      exit(1);
      }
    log_inode = statdata.st_ino;
    }
  }

/* Save the position we have got to in the log. */

if (LOG != NULL) log_position = ftell(LOG);
}

/* End of em_log.c */
