/*************************************************
*                  Exim Monitor                  *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "em_hdr.h"

/* This module contains the main program of the Exim monitor, which
sets up the world and then lets the XtAppMainLoop function
run things off X events. */


/*************************************************
*               Static variables                 *
*************************************************/

/* Fallback resources */

static String fallback_resources[] = {"eximon.geometry: +150+0", NULL};

/* X11 fixed argument lists */

static Arg quit_args[] = {
  {XtNfromVert, (XtArgVal) NULL},         /* must be first */
  {XtNlabel,    (XtArgVal) " Quit "},
  {"left",      XawChainLeft},
  {"right",     XawChainLeft},
  {"top",       XawChainTop},
  {"bottom",    XawChainTop}
};

static Arg resize_args[] = {
  {XtNfromVert, (XtArgVal) NULL},         /* must be first */
  {XtNfromHoriz,(XtArgVal) NULL},         /* must be second */
  {XtNlabel,    (XtArgVal) " Size "},
  {"left",      XawChainLeft},
  {"right",     XawChainLeft},
  {"top",       XawChainTop},
  {"bottom",    XawChainTop}
};

static Arg update_args[] = {
  {XtNfromVert, (XtArgVal) NULL},         /* must be first */
  {XtNlabel,    (XtArgVal) " Update "},
  {"left",      XawChainLeft},
  {"right",     XawChainLeft},
  {"top",       XawChainTop},
  {"bottom",    XawChainTop}
};

static Arg hide_args[] = {
  {XtNfromVert, (XtArgVal) NULL},         /* must be first */
  {XtNfromHoriz,(XtArgVal) NULL},         /* must be second */
  {XtNlabel,    (XtArgVal) " Hide "},
  {"left",      XawChainLeft},
  {"right",     XawChainLeft},
  {"top",       XawChainTop},
  {"bottom",    XawChainTop}
};

static Arg unhide_args[] = {
  {XtNfromVert, (XtArgVal) NULL},         /* must be first */
  {XtNfromHoriz,(XtArgVal) NULL},         /* must be second */
  {XtNlabel,    (XtArgVal) " Unhide "},
  {"left",      XawChainLeft},
  {"right",     XawChainLeft},
  {"top",       XawChainTop},
  {"bottom",    XawChainTop}
};

static Arg log_args[] = {
  {XtNfromVert, (XtArgVal) NULL},         /* must be first */
  {"editType",  XawtextEdit},
  {"useStringInPlace", (XtArgVal)TRUE},
  {"string",    (XtArgVal)""},            /* dummy to get it going */
  {"scrollVertical", XawtextScrollAlways},
  {"scrollHorizontal", XawtextScrollAlways},
  {"right",     XawChainRight},
  {"top",       XawChainTop},
  {"bottom",    XawChainTop}
};

static Arg queue_args[] = {
  {XtNfromVert, (XtArgVal) NULL},         /* must be first */
  {"editType",  XawtextEdit},
  {"string",    (XtArgVal)""},            /* dummy to get it going */
  {"scrollVertical", XawtextScrollAlways},
  {"right",     XawChainRight},
  {"top",       XawChainTop},
  {"bottom",    XawChainBottom}
};

static Arg sizepos_args[] = {
  {"width",     (XtArgVal)NULL},
  {"height",    (XtArgVal)NULL},
  {"x",         (XtArgVal)NULL},
  {"y",         (XtArgVal)NULL}
};

XtActionsRec menu_action_table[] = {
  { "menu-create",  menu_create } };

/* Types of non-message dialog action */

enum { da_hide };

/* Miscellaneous local variables */

static int dialog_action;
static int tick_stripchart_accumulator = 999999;
static int tick_interval = 2;
static int maxposset = 0;
static int minposset = 0;
static int x_adjustment = -1;
static int y_adjustment = -1;
static Dimension screenwidth, screenheight;
static Dimension original_x, original_y;
static Dimension maxposx, maxposy;
static Dimension minposx, minposy;
static Dimension maxwidth, maxheight;
static Widget outer_form_widget;
static Widget hide_widget;
static Widget above_queue_widget;




#ifdef STRERROR_FROM_ERRLIST
/*************************************************
*     Provide strerror() for non-ANSI libraries  *
*************************************************/

/* Some old-fashioned systems still around (e.g. SunOS4) don't have strerror()
in their libraries, but can provide the same facility by this simple
alternative function. */

uschar *
strerror(int n)
{
if (n < 0 || n >= sys_nerr) return "unknown error number";
return sys_errlist[n];
}
#endif /* STRERROR_FROM_ERRLIST */



/*************************************************
*         Handle attempts to write the log       *
*************************************************/

/* The message gets written to stderr when log_write() is called from a
utility. The message always gets '\n' added on the end of it. These calls come
from modules such as store.c when things go drastically wrong (e.g. malloc()
failing). In normal use they won't get obeyed.

Arguments:
  selector  not relevant when running a utility
  flags     not relevant when running a utility
  format    a printf() format
  ...       arguments for format

Returns:    nothing
*/

void
log_write(unsigned int selector, int flags, const char *format, ...)
{
va_list ap;
va_start(ap, format);
vfprintf(stderr, format, ap);
fprintf(stderr, "\n");
va_end(ap);
selector = selector;     /* Keep picky compilers happy */
flags = flags;
}




/*************************************************
*        Extract port from address string        *
*************************************************/

/* In the spool file, a host plus port is given as an IP address followed by a
dot and a port number. This function decodes this. It is needed by the
spool-reading function, and copied here to avoid having to include the whole
host.c module. One day the interaction between exim and eximon with regard to
included code MUST be tidied up!

Argument:
  address    points to the string; if there is a port, the '.' in the string
             is overwritten with zero to terminate the address

Returns:     0 if there is no port, else the port number.
*/

int
host_address_extract_port(uschar *address)
{
int skip = -3;                     /* Skip 3 dots in IPv4 addresses */
address--;
while (*(++address) != 0)
  {
  int ch = *address;
  if (ch == ':') skip = 0;         /* Skip 0 dots in IPv6 addresses */
    else if (ch == '.' && skip++ >= 0) break;
  }
if (*address == 0) return 0;
*address++ = 0;
return Uatoi(address);
}




/*************************************************
*                SIGCHLD handler                 *
*************************************************/

/* Operations on messages are done in subprocesses; this handler
just catches them when they finish. It causes a queue display update
unless configured not to. */

static void sigchld_handler(int sig)
{
while (waitpid(-1, NULL, WNOHANG) > 0);
signal(sig, sigchld_handler);
if (action_queue_update) tick_queue_accumulator = 999999;
}



/*************************************************
*             Callback routines                  *
*************************************************/


void updateAction(Widget w, XtPointer client_data, XtPointer call_data)
{
w = w;       /* Keep picky compilers happy */
client_data = client_data;
call_data = call_data;
scan_spool_input(TRUE);
queue_display();
tick_queue_accumulator = 0;
}

void hideAction(Widget w, XtPointer client_data, XtPointer call_data)
{
w = w;       /* Keep picky compilers happy */
client_data = client_data;
call_data = call_data;
actioned_message[0] = 0;
dialog_ref_widget = w;
dialog_action = da_hide;
create_dialog(US"Hide addresses ending with", US"");
}

void unhideAction(Widget w, XtPointer client_data, XtPointer call_data)
{
skip_item *sk = queue_skip;

w = w;       /* Keep picky compilers happy */
client_data = client_data;
call_data = call_data;

while (sk != NULL)
  {
  skip_item *next = sk->next;
  store_free(sk);
  sk = next;
  }
queue_skip = NULL;

XtDestroyWidget(unhide_widget);
unhide_widget = NULL;

scan_spool_input(TRUE);
queue_display();
tick_queue_accumulator = 0;
}

void quitAction(Widget w, XtPointer client_data, XtPointer call_data)
{
w = w;       /* Keep picky compilers happy */
client_data = client_data;
call_data = call_data;
exit(0);
}


/* Action when the "Size" button is pressed. This is a kludged up mess
that I made work after much messing around. Reading the position of the
toplevel widget gets the absolute position of the data portion of the window,
excluding the window manager's furniture. However, positioning the toplevel
widget's window seems to position the top corner of the furniture under the twm
window manager, but not under fwvm and others. The two cases are distinguished
by the values of x_adjustment and y_adjustment.

For twm (adjustment >= 0), one has to fudge the miminizing function to ensure
that we go back to exactly the same position as before.

For fwvm (adjustment < 0), one has to fudge the "top left hand corner"
positioning to ensure that the window manager's furniture gets displayed on the
screen. I haven't found a way of discovering the thickness of the furniture, so
some screwed-in values are used.

This is all ad hoc, developed by floundering around as I haven't found any
documentation that tells me what I really should do. */

void resizeAction(Widget button, XtPointer client_data, XtPointer call_data)
{
Dimension x, y;
Dimension width, height;
XWindowAttributes a;
Window w = XtWindow(toplevel_widget);

button = button;    /* Keep picky compilers happy */
client_data = client_data;
call_data = call_data;

/* Get the position and size of the top level widget. */

sizepos_args[0].value = (XtArgVal)(&width);
sizepos_args[1].value = (XtArgVal)(&height);
sizepos_args[2].value = (XtArgVal)(&x);
sizepos_args[3].value = (XtArgVal)(&y);
XtGetValues(toplevel_widget, sizepos_args, 4);

/* Get the position of the widget's window relative to its parent; this
gives the thickness of the window manager's furniture. At least it does
in twm. For fwvm it gives zero. The size/movement function uses this data.
I tried doing this before entering the main loop, but it didn't always
work properly with twm. Running it every time seems to be OK. */

XGetWindowAttributes(X_display, XtWindow(toplevel_widget), &a);
if (a.x != 0) x_adjustment = a.x;
if (a.y != 0) y_adjustment = a.y;

/* If at maximum size, reduce to minimum and move back to where it was
when maximized, if that value is set, allowing for the furniture in cases
where the positioning includes the furniture. */

if (width == maxwidth && height == maxheight)
  {
  maxposx = x;
  maxposy = y;
  maxposset = 1;

  if (minposset)
    xs_SetValues(toplevel_widget, 4,
      "width",     min_width,
      "height",    min_height,
      "x",         minposx - ((x_adjustment >= 0)? x_adjustment : 0),
      "y",         minposy - ((y_adjustment >= 0)? y_adjustment : 0));
  else
    xs_SetValues(toplevel_widget, 2,
      "width",     min_width,
      "height",    min_height);
  }

/* Else always expand to maximum. If currently at minimum size, remember where
it was for coming back. If we don't have a value for the thickness of the
furniture, the implication is that the coordinates position the application
window, so we can't use (0,0) because that loses the furniture. Use screwed in
values that seem to work with fvwm. */

else
  {
  int xx = x;
  int yy = y;

  if (width == min_width && height == min_height)
    {
    minposx = x;
    minposy = y;
    minposset = 1;
    }

  if ((int)(x + maxwidth) > (int)screenwidth ||
      (int)(y + maxheight + 10) > (int)screenheight)
    {
    if (maxposset)
      {
      xx = maxposx - ((x_adjustment >= 0)? x_adjustment : 0);
      yy = maxposy - ((y_adjustment >= 0)? y_adjustment : 0);
      }
    else
      {
      if ((int)(x + maxwidth) > (int)screenwidth)
        xx = (x_adjustment >= 0)? 0 : 4;
      if ((int)(y + maxheight + 10) > (int)screenheight)
        yy = (y_adjustment >= 0)? 0 : 21;
      }

    xs_SetValues(toplevel_widget, 4,
      "width",     maxwidth,
      "height",    maxheight,
      "x",         xx,
      "y",         yy);
    }

  else xs_SetValues(toplevel_widget, 2,
        "width",     maxwidth,
        "height",    maxheight);
  }

/* Ensure the window is at the top */

XRaiseWindow(X_display, w);
}




/*************************************************
*          Handle input from non-msg dialogue    *
*************************************************/

/* The various cases here are: hide domain, (no more yet) */

void NonMessageDialogue(uschar *s)
{
skip_item *sk;

switch(dialog_action)
  {
  case da_hide:

  /* Create the unhide button if not present */

  if (unhide_widget == NULL)
    {
    unhide_args[0].value = (XtArgVal) above_queue_widget;
    unhide_args[1].value = (XtArgVal) hide_widget;
    unhide_widget = XtCreateManagedWidget("unhide", commandWidgetClass,
      outer_form_widget, unhide_args, XtNumber(unhide_args));
    XtAddCallback(unhide_widget, "callback",  unhideAction, NULL);
    }

  /* Add item to skip queue */

  sk = (skip_item *)store_malloc(sizeof(skip_item) + Ustrlen(s));
  sk->next = queue_skip;
  queue_skip = sk;
  Ustrcpy(sk->text, s);
  sk->reveal = time(NULL) + 60 * 60;
  scan_spool_input(TRUE);
  queue_display();
  tick_queue_accumulator = 0;
  break;
  }
}



/*************************************************
*              Ticker function                   *
*************************************************/

/* This function is called initially to set up the starting data
values; it then sets a timeout so that it continues to be called
every 2 seconds. */

static void ticker(XtPointer pt, XtIntervalId *i)
{
pipe_item **pp = &pipe_chain;
pipe_item *p = pipe_chain;
tick_queue_accumulator += tick_interval;
tick_stripchart_accumulator += tick_interval;
read_log();

pt = pt;    /* Keep picky compilers happy */
i = i;

/* If we have passed the queue update time, we must do a full
scan of the queue, checking for new arrivals, etc. This will
as a by-product set the count of items for use by the stripchart
display. On some systems, SIGCHLD signals can get lost at busy times,
so just in case, clean up any completed children here. */

if (tick_queue_accumulator >= queue_update)
  {
  scan_spool_input(TRUE);
  queue_display();
  tick_queue_accumulator = 0;
  if (tick_stripchart_accumulator >= stripchart_update)
    tick_stripchart_accumulator = 0;
  while (waitpid(-1, NULL, WNOHANG) > 0);
  }

/* Otherwise, if we have exceeded the stripchart interval,
do a reduced queue scan that simply provides the count for
the stripchart. */

else if (tick_stripchart_accumulator >= stripchart_update)
  {
  scan_spool_input(FALSE);
  tick_stripchart_accumulator = 0;
  }

/* Scan any pipes that are set up for listening to delivery processes,
and display their output if their windows are still open. */

while (p != NULL)
  {
  int count;
  uschar buffer[256];

  while ((count = read(p->fd, buffer, 254)) > 0)
    {
    buffer[count] = 0;
    if (p->widget != NULL) text_show(p->widget, buffer);
    }

  if (count == 0)
    {
    close(p->fd);
    *pp = p->next;
    store_free(p);
    /* If configured, cause display update */
    if (action_queue_update) tick_queue_accumulator = 999999;
    }

  else pp = &(p->next);

  p = *pp;
  }

/* Reset the timer for next time */

XtAppAddTimeOut(X_appcon, tick_interval * 1000, ticker, 0);
}



/*************************************************
*             Find Num Lock modifiers            *
*************************************************/

/* Return a string with the modifiers generated by XK_Num_Lock, or return
NULL if XK_Num_Lock doesn't generate any modifiers. This is needed because Num
Lock isn't always the same modifier on all servers.

Arguments:
  display   the Display
  buf       a buffer in which to put the answers (long enough to hold 5)

Returns:    points to the buffer, or NULL
*/

static uschar *
numlock_modifiers(Display *display, uschar *buf)
{
XModifierKeymap *m;
int i, j;
uschar *ret = NULL;

m = XGetModifierMapping(display);
if (m == NULL)
  {
  printf("Not enough memory\n");
  exit (EXIT_FAILURE);
  }

/* Look at Mod1 through Mod5, and fill in the buffer as necessary. */

buf[0] = 0;
for (i = 3; i < 8; i++)
  {
  for (j = 0; j < m->max_keypermod; j++)
    {
    if (XKeycodeToKeysym(display, m->modifiermap [i*m->max_keypermod + j], 0)
        == XK_Num_Lock)
      {
      sprintf(CS(buf+Ustrlen(buf)), " Mod%d", i-2);
      ret = buf;
      }
    }
  }

XFreeModifiermap(m);
return ret;
}



/*************************************************
*               Initialize                       *
*************************************************/

int main(int argc, char **argv)
{
int i;
struct stat statdata;
uschar modbuf[] = " Mod1 Mod2 Mod3 Mod4 Mod5";
uschar *numlock;
Widget stripchart_form_widget,
       update_widget,
       quit_widget,
       resize_widget;

/* The exim global message_id needs to get set */

message_id_external = message_id_option + 1;
message_id = message_id_external + 1;
message_subdir[1] = 0;

/* Some store needs getting for big_buffer, which is used for
constructing file names and things. This call will initialize
the store_get() function. */

big_buffer = store_get(big_buffer_size);

/* Set up the version string and date and output them */

version_init();
printf("\nExim Monitor version %s (compiled %s) initializing\n",
  version_string, version_date);

/* Initialize various things from the environment and arguments. */

init(argc, USS argv);

/* Set up the SIGCHLD handler */

signal(SIGCHLD, sigchld_handler);

/* Get the buffer for storing the string for the log display. */

log_display_buffer = US store_malloc(log_buffer_size);
log_display_buffer[0] = 0;

/* Initialize the data structures for the stripcharts */

stripchart_init();

/* If log_file contains the empty string, then Exim is running using syslog
only, and we can't tail the log. If not, open the log file and position to the
end of it. Before doing so, we have to detect whether the log files are
datestamped, and if so, sort out the name. The string in log_file already has
%s replaced by "main"; if datestamping is occurring, %D or %M will be present.
In fact, we don't need to test explicitly - just process the string with
string_format.

Once opened, save the file's inode so that we can detect when the file is
switched to another one for non-datestamped files. However, allow the monitor
to start up without a log file (can happen if no messages have been sent
today.) */

if (log_file[0] != 0)
  {
  /* Do *not* use "%s" here, we need the %D datestamp in the log_file to
  be expanded! */
  (void)string_format(log_file_open, sizeof(log_file_open), CS log_file);
  log_datestamping = string_datestamp_offset >= 0;

  LOG = fopen(CS log_file_open, "r");

  if (LOG == NULL)
    {
    printf("*** eximon warning: can't open log file %s - will try "
      "periodically\n", log_file_open);
    }
  else
    {
    fseek(LOG, 0, SEEK_END);
    log_position = ftell(LOG);
    if (fstat(fileno(LOG), &statdata))
      {
      perror("log file fstat");
      fclose(LOG);
      LOG=NULL;
      }
    else
      log_inode = statdata.st_ino;
    }
  }
else
  {
  printf("*** eximon warning: no log file available to tail\n");
  }

/* Now initialize the X world and create the top-level widget */

toplevel_widget = XtAppInitialize(&X_appcon, "Eximon", NULL, 0, &argc, argv,
  fallback_resources, NULL, 0);
X_display = XtDisplay(toplevel_widget);
xs_SetValues(toplevel_widget, 4,
  "title",     window_title,
  "iconName",  window_title,
  "minWidth",  min_width,
  "minHeight", min_height);


/* Create the action for setting up the menu in the queue display
window, and register the action for positioning the menu. */

XtAppAddActions(X_appcon, menu_action_table, 1);
XawSimpleMenuAddGlobalActions(X_appcon);

/* Set up translation tables for the text widgets we use. We don't
want all the generality of editing, etc. that the defaults provide.
This cannot be done before initializing X - the parser complains
about unknown events, modifiers, etc. in an unhelpful way... The
queue text widget has a different table which includes the button
for popping up the menu. Note that the order of things in these
tables is significant. Shift<thing> must come before <thing> as
otherwise it isn't noticed. */

/*
   <FocusIn>:      display-caret(on)\n\
   <FocusOut>:     display-caret(off)\n\
*/

/* The translation manager sets up passive grabs for the menu popups as a
result of MenuPopup(), but the grabs match only the exact modifiers listed,
hence combinations with and without caps-lock and num-lock must be given,
rather than just one "Shift<Btn1Down>" (or whatever menu_event is set to),
despite the fact that that notation (without a leading !) should ignore the
state of other modifiers. Thanks to Kevin Ryde for this information, and for
the function above that discovers which modifier is Num Lock, because it turns
out that it varies from server to server. */

sprintf(CS big_buffer,
  "!%s:            menu-create() XawPositionSimpleMenu(menu) MenuPopup(menu)\n\
   !Lock %s:       menu-create() XawPositionSimpleMenu(menu) MenuPopup(menu)\n\
  ", menu_event, menu_event);

numlock = numlock_modifiers(X_display, modbuf); /* Get Num Lock modifier(s) */

if (numlock != NULL) sprintf(CS big_buffer + Ustrlen(big_buffer),
  "!%s %s:         menu-create() XawPositionSimpleMenu(menu) MenuPopup(menu)\n\
   !Lock %s %s:    menu-create() XawPositionSimpleMenu(menu) MenuPopup(menu)\n\
  ", numlock, menu_event, numlock, menu_event);

sprintf(CS big_buffer + Ustrlen(big_buffer),
  "<Btn1Down>:     select-start()\n\
   <Btn1Motion>:   extend-adjust()\n\
   <Btn1Up>:       extend-end(PRIMARY,CUT_BUFFER0)\n\
   <Btn3Down>:     extend-start()\n\
   <Btn3Motion>:   extend-adjust()\n\
   <Btn3Up>:       extend-end(PRIMARY,CUT_BUFFER0)\n\
   <Key>Up:        scroll-one-line-down()\n\
   <Key>Down:      scroll-one-line-up()\n\
   Ctrl<Key>R:     search(backward)\n\
   Ctrl<Key>S:     search(forward)\n\
  ");

queue_trans = XtParseTranslationTable(CS big_buffer);

text_trans = XtParseTranslationTable(
  "<Btn1Down>:     select-start()\n\
   <Btn1Motion>:   extend-adjust()\n\
   <Btn1Up>:       extend-end(PRIMARY,CUT_BUFFER0)\n\
   <Btn3Down>:     extend-start()\n\
   <Btn3Motion>:   extend-adjust()\n\
   <Btn3Up>:       extend-end(PRIMARY,CUT_BUFFER0)\n\
   <Key>Up:        scroll-one-line-down()\n\
   <Key>Down:      scroll-one-line-up()\n\
   Ctrl<Key>R:     search(backward)\n\
   Ctrl<Key>S:     search(forward)\n\
  ");


/* Create a toplevel form widget to hold all the other things */

outer_form_widget = XtCreateManagedWidget("form", formWidgetClass,
  toplevel_widget, NULL, 0);

/* Now create an inner form to hold the stripcharts */

stripchart_form_widget = XtCreateManagedWidget("form", formWidgetClass,
  outer_form_widget, NULL, 0);
xs_SetValues(stripchart_form_widget, 5,
  "defaultDistance", 8,
  "left",            XawChainLeft,
  "right",           XawChainLeft,
  "top",             XawChainTop,
  "bottom",          XawChainTop);

/* Create the queue count stripchart and its label. */

create_stripchart(stripchart_form_widget, queue_stripchart_name);

/* If configured, create the size monitoring stripchart, but
only if the OS supports statfs(). */

if (size_stripchart != NULL)
  {
#ifdef HAVE_STATFS
  if (size_stripchart_name == NULL)
    {
    size_stripchart_name = size_stripchart + Ustrlen(size_stripchart) - 1;
    while (size_stripchart_name > size_stripchart &&
      *size_stripchart_name == '/') size_stripchart_name--;
    while (size_stripchart_name > size_stripchart &&
      *size_stripchart_name != '/') size_stripchart_name--;
    }
  create_stripchart(stripchart_form_widget, size_stripchart_name);
#else
  printf("Can't create size stripchart: statfs() function not available\n");
#endif
  }

/* Now create the configured input/output stripcharts; note
the total number includes the queue stripchart. */

for (i = stripchart_varstart; i < stripchart_number; i++)
  create_stripchart(stripchart_form_widget, stripchart_title[i]);

/* Next in vertical order come the Resize & Quit buttons */

quit_args[0].value = (XtArgVal) stripchart_form_widget;
quit_widget = XtCreateManagedWidget("quit", commandWidgetClass,
  outer_form_widget, quit_args, XtNumber(quit_args));
XtAddCallback(quit_widget, "callback",  quitAction, NULL);

resize_args[0].value = (XtArgVal) stripchart_form_widget;
resize_args[1].value = (XtArgVal) quit_widget;
resize_widget = XtCreateManagedWidget("resize", commandWidgetClass,
  outer_form_widget, resize_args, XtNumber(resize_args));
XtAddCallback(resize_widget, "callback",  resizeAction, NULL);

/* In the absence of log tailing, the quit widget is the one above the
queue listing. */

above_queue_widget = quit_widget;

/* Create an Ascii text widget for the log tail display if we are tailing a
log. Skip it if not. */

if (log_file[0] != 0)
  {
  log_args[0].value = (XtArgVal) quit_widget;
  log_widget = XtCreateManagedWidget("log", asciiTextWidgetClass,
    outer_form_widget, log_args, XtNumber(log_args));
  XawTextDisplayCaret(log_widget, TRUE);
  xs_SetValues(log_widget, 6,
    "editType",  XawtextEdit,
    "translations", text_trans,
    "string",    log_display_buffer,
    "length",    log_buffer_size,
    "height",    log_depth,
    "width",     log_width);

  if (log_font != NULL)
    {
    XFontStruct *f = XLoadQueryFont(X_display, CS log_font);
    if (f != NULL) xs_SetValues(log_widget, 1, "font", f);
    }

  above_queue_widget = log_widget;
  }

/* The update button */

update_args[0].value = (XtArgVal) above_queue_widget;
update_widget = XtCreateManagedWidget("update", commandWidgetClass,
  outer_form_widget, update_args, XtNumber(update_args));
XtAddCallback(update_widget, "callback",  updateAction, NULL);

/* The hide button */

hide_args[0].value = (XtArgVal) above_queue_widget;
hide_args[1].value = (XtArgVal) update_widget;
hide_widget = XtCreateManagedWidget("hide", commandWidgetClass,
  outer_form_widget, hide_args, XtNumber(hide_args));
XtAddCallback(hide_widget, "callback",  hideAction, NULL);

/* Create an Ascii text widget for the queue display. */

queue_args[0].value = (XtArgVal) update_widget;
queue_widget = XtCreateManagedWidget("queue", asciiTextWidgetClass,
  outer_form_widget, queue_args, XtNumber(queue_args));
XawTextDisplayCaret(queue_widget, TRUE);

xs_SetValues(queue_widget, 4,
  "editType",  XawtextEdit,
  "height",    queue_depth,
  "width",     queue_width,
  "translations", queue_trans);

if (queue_font != NULL)
  {
  XFontStruct *f = XLoadQueryFont(X_display, CS queue_font);
  if (f != NULL) xs_SetValues(queue_widget, 1, "font", f);
  }

/* Call the ticker function to get the initial data set up. It
arranges to have itself recalled every 2 seconds. */

ticker(NULL, NULL);

/* Everything is now set up; this flag is used by the regerror
function and also by the queue reader. */

eximon_initialized = TRUE;
printf("\nExim Monitor running\n");

/* Realize the toplevel and thereby get things displayed */

XtRealizeWidget(toplevel_widget);

/* Find out the size of the initial window, and set that as its
maximum. While we are at it, get the initial position. */

sizepos_args[0].value = (XtArgVal)(&maxwidth);
sizepos_args[1].value = (XtArgVal)(&maxheight);
sizepos_args[2].value = (XtArgVal)(&original_x);
sizepos_args[3].value = (XtArgVal)(&original_y);
XtGetValues(toplevel_widget, sizepos_args, 4);

xs_SetValues(toplevel_widget, 2,
  "maxWidth",  maxwidth,
  "maxHeight", maxheight);

/* Set up the size of the screen */

screenwidth = XDisplayWidth(X_display, 0);
screenheight= XDisplayHeight(X_display,0);

/* Register the action table */

XtAppAddActions(X_appcon, actionTable, actionTableSize);

/* Reduce the window to the small size if this is wanted */

if (start_small) resizeAction(NULL, NULL, NULL);

/* Enter the application loop which handles things from here
onwards. The return statement is never obeyed, but is needed to
keep pedantic ANSI compilers happy. */

XtAppMainLoop(X_appcon);

return 0;
}

/* End of em_main.c */

