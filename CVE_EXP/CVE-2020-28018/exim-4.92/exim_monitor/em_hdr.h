/*************************************************
*                 Exim Monitor                   *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */


/* This is the general header file for all the modules that comprise
the exim monitor program. */

/* If this macro is defined, Eximon will anonymize all email addresses. This
feature is just so that screen shots can be obtained for documentation
purposes! */

/* #define ANONYMIZE */

/* System compilation parameters */

#define queue_index_size  10      /* Size of index into queue */

/* Assume most systems have statfs() unless os.h undefines this macro */

#define HAVE_STATFS

/* Bring in the system-dependent stuff */

#include "os.h"


/* ANSI C includes */

#include <ctype.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Not-fully-ANSI systems (e.g. SunOS4 are missing some things) */

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

/* Unix includes */

#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

/* The new standard is statvfs; some OS have statfs. Also arrange
to be able to cut it out altogether for way-out OS that don't have
anything. */

#ifdef HAVE_STATFS
#ifdef HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>

#else
  #define statvfs statfs
  #ifdef HAVE_SYS_VFS_H
    #include <sys/vfs.h>
    #ifdef HAVE_SYS_STATFS_H
    #include <sys/statfs.h>
    #endif
  #endif
  #ifdef HAVE_SYS_MOUNT_H
  #include <sys/mount.h>
  #endif
#endif
#endif

#include <sys/wait.h>

/* Regular expression include */

#include <pcre.h>

/* Includes from the main source of Exim.  One of these days I should tidy up
this interface so that this kind of kludge isn't needed. */

#ifndef NS_MAXMSG
# define NS_MAXMSG 65535
#endif
typedef void hctx;

#include "config.h"
#include "mytypes.h"
#include "macros.h"

#include "local_scan.h"
#include "structs.h"
#include "blob.h"
#include "globals.h"
#include "dbstuff.h"
#include "functions.h"
#include "osfunctions.h"
#include "store.h"

/* The sys/resource.h header on SunOS 4 causes trouble with the gcc
compiler. Just stuff the bit we want in here; pragmatic easy way out. */

#ifdef NO_SYS_RESOURCE_H
#define RLIMIT_NOFILE   6               /* maximum descriptor index + 1 */
struct rlimit {
        int     rlim_cur;               /* current (soft) limit */
        int     rlim_max;               /* maximum value for rlim_cur */
};
#else
#include <sys/time.h>
#include <sys/resource.h>
#endif

/* X11 includes */

#include <X11/Xlib.h>
#include <X11/Intrinsic.h>
#include <X11/StringDefs.h>
#include <X11/cursorfont.h>
#include <X11/keysym.h>
#include <X11/Shell.h>
#include <X11/Xaw/AsciiText.h>
#include <X11/Xaw/Command.h>
#include <X11/Xaw/Form.h>
#include <X11/Xaw/Dialog.h>
#include <X11/Xaw/Label.h>
#include <X11/Xaw/SimpleMenu.h>
#include <X11/Xaw/SmeBSB.h>
#include <X11/Xaw/SmeLine.h>
#include <X11/Xaw/TextSrc.h>
#include <X11/Xaw/TextSink.h>

/* These are required because exim monitor has its own munged
version of the stripchart widget. */

#include <X11/IntrinsicP.h>
#include <X11/StringDefs.h>
#include <X11/Xaw/XawInit.h>
#include <X11/Xaw/StripCharP.h>

extern WidgetClass mystripChartWidgetClass;



/*************************************************
*               Enumerations                     *
*************************************************/

/* Operations on the in-store message queue */

enum { queue_noop, queue_add };

/* Operations on the destinations queue */

enum { dest_noop, dest_add, dest_remove };


/*************************************************
*          Structure for destinations            *
*************************************************/

typedef struct dest_item {
  struct dest_item *next;
  struct dest_item *parent;
  uschar address[1];
} dest_item;



/*************************************************
*           Structure for queue items            *
*************************************************/

typedef struct queue_item {
  struct queue_item *next;
  struct queue_item *prev;
  struct dest_item  *destinations;
  int  input_time;
  int  update_time;
  int  size;
  uschar *sender;
  uschar name[17];
  uschar seen;
  uschar frozen;
  uschar dir_char;
} queue_item;


/*************************************************
*          Structure for queue skip items        *
*************************************************/

typedef struct skip_item {
  struct skip_item *next;
  time_t reveal;
  uschar text[1];
} skip_item;


/*************************************************
*           Structure for delivery displays      *
*************************************************/

typedef struct pipe_item {
  struct pipe_item *next;
  int fd;
  Widget widget;
} pipe_item;



/*************************************************
*                Global variables                *
*************************************************/

extern Display *X_display;         /* Current display */
extern XtAppContext X_appcon;      /* Application context */
extern XtActionsRec actionTable[]; /* Actions table */

extern XtTranslations queue_trans; /* translation table for queue text widget */
extern XtTranslations text_trans;  /* translation table for other text widgets */

extern Widget  dialog_ref_widget;   /* for positioning dialog box */
extern Widget  toplevel_widget;
extern Widget  log_widget;          /* widget for tail display */
extern Widget  queue_widget;        /* widget for queue display */
extern Widget  unhide_widget;       /* widget for unhide button */

extern FILE   *LOG;

extern int     action_output;       /* TRUE when wanting action command output */
extern int     action_queue_update; /* controls auto updates */
extern int     actionTableSize;     /* # entries in actionTable */
extern uschar  actioned_message[];  /* For menu handling */
extern uschar *action_required;
extern uschar *alternate_config;    /* Alternate Exim configuration file */

extern int     body_max;            /* Max size of body to display */

extern int     eximon_initialized;  /* TRUE when initialized */

extern int     log_buffer_size;     /* size of log buffer */
extern BOOL    log_datestamping;    /* TRUE if logs are datestamped */
extern int     log_depth;           /* depth of log tail window */
extern uschar *log_display_buffer;  /* to hold display text */
extern uschar *log_file;            /* supplied name of exim log file */
extern uschar  log_file_open[256];  /* actual open file */
extern uschar *log_font;            /* font for log display */
extern ino_t   log_inode;           /* the inode of the log file */
extern long int log_position;      /* position in log file */
extern int     log_width;           /* width of log tail window */

extern uschar *menu_event;          /* name of menu event */
extern int     menu_is_up;          /* TRUE when menu displayed */
extern int     min_height;          /* min window height */
extern int     min_width;           /* min window width */

extern pipe_item *pipe_chain;      /* for delivery displays */

extern uschar *qualify_domain;
extern int     queue_depth;         /* depth of queue window */
extern uschar *queue_font;          /* font for queue display */
extern int     queue_max_addresses; /* limit on per-message list */
extern skip_item *queue_skip;      /* for hiding bits of queue */
extern uschar *queue_stripchart_name; /* sic */
extern int     queue_update;        /* update interval */
extern int     queue_width;         /* width of queue window */

extern pcre   *yyyymmdd_regex;    /* for matching yyyy-mm-dd */

extern uschar *size_stripchart;     /* path for size monitoring */
extern uschar *size_stripchart_name; /* name for size stripchart */
extern uschar *spool_directory;     /* Name of exim spool directory */
extern int     spool_is_split;      /* True if detected split spool */
extern int     start_small;         /* True to start with small window */
extern int     stripchart_height;   /* height of stripcharts */
extern int     stripchart_number;   /* number of stripcharts */
extern pcre  **stripchart_regex;  /* vector of regexps */
extern uschar **stripchart_title;    /* vector of titles */
extern int    *stripchart_total;    /* vector of accumulating values */
extern int     stripchart_update;   /* update interval */
extern int     stripchart_width;    /* width of stripcharts */
extern int     stripchart_varstart; /* starting number for variable charts */

extern int     text_depth;          /* depth of text windows */
extern int     tick_queue_accumulator; /* For timing next auto update */

extern uschar *window_title;        /* title of the exim monitor window */


/*************************************************
*                Global functions                *
*************************************************/

extern XtActionProc dialogAction(Widget, XEvent *, String *, Cardinal *);

extern uschar *copystring(uschar *);
extern void    create_dialog(uschar *, uschar *);
extern void    create_stripchart(Widget, uschar *);
extern void    debug(char *, ...);
extern dest_item *find_dest(queue_item *, uschar *, int, BOOL);
extern queue_item *find_queue(uschar *, int, int);
extern void    init(int, uschar **);
extern void    menu_create(Widget, XEvent *, String *, Cardinal *);
extern void    NonMessageDialogue(uschar *);
extern void    queue_display(void);
extern void    read_log(void);
extern int     read_spool(uschar *);
extern int     read_spool_init(uschar *);
extern void    read_spool_tidy(void);
extern int     repaint_window(StripChartWidget, int, int);
extern void    scan_spool_input(int);
extern void    stripchart_init(void);
extern void    text_empty(Widget);
extern void    text_show(Widget, uschar *);
extern void    text_showf(Widget, char *, ...);
extern void    xs_SetValues(Widget, Cardinal, ...);

/* End of em_hdr.h */
