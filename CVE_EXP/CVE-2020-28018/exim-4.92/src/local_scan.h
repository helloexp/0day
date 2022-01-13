/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* This file is the header that is the only Exim header to be included in the
source for the local_scan.c() function. It contains definitions that are made
available for use in that function, and which are documented.

This API is also used for functions called by the ${dlfunc expansion item. */


/* Some basic types that make some things easier, the Exim configuration
settings, and the store functions. */

#include <stdarg.h>
#include <sys/types.h>
#include "config.h"
#include "mytypes.h"
#include "store.h"


/* The function and its return codes. */

extern int local_scan(int, uschar **);

enum {
  LOCAL_SCAN_ACCEPT,              /* Accept */
  LOCAL_SCAN_ACCEPT_FREEZE,       /* Accept, but freeze */
  LOCAL_SCAN_ACCEPT_QUEUE,        /* Accept, but no immediate delivery */
  LOCAL_SCAN_REJECT,              /* Permanent rejection */
  LOCAL_SCAN_REJECT_NOLOGHDR,     /* Permanent rejection, no log header */
  LOCAL_SCAN_TEMPREJECT,          /* Temporary rejection */
  LOCAL_SCAN_TEMPREJECT_NOLOGHDR  /* Temporary rejection, no log header */
};


/* Functions called by ${dlfunc{file}{func}{arg}...} return one of the five
status codes defined immediately below. The function's first argument is either
the result of expansion, or the error message in case of failure. The second
and third arguments are standard argument count and vector, comprising the
{arg} values specified in the expansion item. */

typedef int exim_dlfunc_t(uschar **yield, int argc, uschar *argv[]);


/* Return codes from the support functions lss_match_xxx(). These are also the
codes that dynamically-loaded ${dlfunc functions must return. */

#define  OK            0          /* Successful match */
#define  DEFER         1          /* Defer - some problem */
#define  FAIL          2          /* Matching failed */
#define  ERROR         3          /* Internal or config error */

/* Extra return code for ${dlfunc functions */

#define  FAIL_FORCED   4          /* "Forced" failure */


/* Available logging destinations */

#define LOG_MAIN        1    /* Write to the main log */
#define LOG_PANIC       2    /* Write to the panic log */
#define LOG_REJECT     16    /* Write to the reject log, with headers */


/* Accessible debugging bits */

#define D_v                          0x00000001
#define D_local_scan                 0x00000002


/* Option types that can be used for local_scan_options. The boolean ones
MUST be last so that they are contiguous with the internal boolean specials. */

enum { opt_stringptr, opt_int, opt_octint, opt_mkint, opt_Kint, opt_fixed,
  opt_time, opt_bool };


/* The length of message identification strings. This is the id used internally
by exim. The external version for use in Received: strings has a leading 'E'
added to ensure it starts with a letter. */

#define MESSAGE_ID_LENGTH 16

/* The offset to the start of the data in the data file - this allows for
the name of the data file to be present in the first line. */

#define SPOOL_DATA_START_OFFSET (MESSAGE_ID_LENGTH+3)

/* Some people (Marc Merlin et al) are maintaining a patch that allows for
dynamic local_scan() libraries. This code is not yet in Exim proper, but it
helps the maintainers if we keep their ABI version numbers here. This may
mutate into more general support later. The major number is increased when the
ABI is changed in a non backward compatible way. The minor number is increased
each time a new feature is added (in a way that doesn't break backward
compatibility). */

#define LOCAL_SCAN_ABI_VERSION_MAJOR 2
#define LOCAL_SCAN_ABI_VERSION_MINOR 0
#define LOCAL_SCAN_ABI_VERSION \
  LOCAL_SCAN_ABI_VERSION_MAJOR.LOCAL_SCAN_ABI_VERSION_MINOR

/* Structure definitions that are documented as visible in the function. */

typedef struct header_line {
  struct header_line *next;
  int    type;
  int    slen;
  uschar *text;
} header_line;

/* Entries in lists options are in this form. */

typedef struct {
  const char   *name; /* should have been uschar but too late now */
  int           type;
  void         *value;
} optionlist;

/*Structure for holding information about an envelope address. The errors_to
field is always NULL except for one_time aliases that had errors_to on the
routers that generated them. */

typedef struct recipient_item {
  uschar *address;              /* the recipient address */
  int     pno;                  /* parent number for "one_time" alias, or -1 */
  uschar *errors_to;            /* the errors_to address or NULL */
  uschar *orcpt;                /* DSN orcpt */
  int     dsn_flags;            /* DSN flags */
#ifdef EXPERIMENTAL_BRIGHTMAIL
  uschar *bmi_optin;
#endif
} recipient_item;


/* Global variables that are documented as visible in the function. */

extern unsigned int debug_selector;    /* Debugging bits */

extern int     body_linecount;         /* Line count in body */
extern int     body_zerocount;         /* Binary zero count in body */
extern uschar *expand_string_message;  /* Error info for failing expansion */
extern uschar *headers_charset;        /* Charset for RFC 2047 decoding */
extern header_line *header_last;       /* Final header */
extern header_line *header_list;       /* First header */
extern BOOL    host_checking;          /* Set when checking a host */
extern uschar *interface_address;      /* Interface for incoming call */
extern int     interface_port;         /* Port number for incoming call */
extern uschar *message_id;             /* Internal id of message being handled */
extern uschar *received_protocol;      /* Name of incoming protocol */
extern int     recipients_count;       /* Number of recipients */
extern recipient_item *recipients_list;/* List of recipient addresses */
extern unsigned char *sender_address;  /* Sender address */
extern uschar *sender_host_address;    /* IP address of sender, as chars */
extern uschar *sender_host_authenticated; /* Name of authentication mechanism */
extern uschar *sender_host_name;       /* Host name from lookup */
extern int     sender_host_port;       /* Port number of sender */
extern BOOL    smtp_batched_input;     /* TRUE if SMTP batch (no interaction) */
extern BOOL    smtp_input;             /* TRUE if input is via SMTP */


/* Functions that are documented as visible in local_scan(). */

extern int     child_close(pid_t, int);
extern pid_t   child_open(uschar **, uschar **, int, int *, int *, BOOL);
extern pid_t   child_open_exim(int *);
extern pid_t   child_open_exim2(int *, uschar *, uschar *);
extern void    debug_printf(const char *, ...) PRINTF_FUNCTION(1,2);
extern uschar *expand_string(uschar *);
extern void    header_add(int, const char *, ...);
extern void    header_add_at_position(BOOL, uschar *, BOOL, int, const char *, ...);
extern void    header_remove(int, const uschar *);
extern BOOL    header_testname(header_line *, const uschar *, int, BOOL);
extern BOOL    header_testname_incomplete(header_line *, const uschar *, int, BOOL);
extern void    log_write(unsigned int, int, const char *format, ...) PRINTF_FUNCTION(3,4);
extern int     lss_b64decode(uschar *, uschar **);
extern uschar *lss_b64encode(uschar *, int);
extern int     lss_match_domain(uschar *, uschar *);
extern int     lss_match_local_part(uschar *, uschar *, BOOL);
extern int     lss_match_address(uschar *, uschar *, BOOL);
extern int     lss_match_host(uschar *, uschar *, uschar *);
extern void    receive_add_recipient(uschar *, int);
extern BOOL    receive_remove_recipient(uschar *);
extern uschar *rfc2047_decode(uschar *, BOOL, uschar *, int, int *, uschar **);
extern int     smtp_fflush(void);
extern void    smtp_printf(const char *, BOOL, ...) PRINTF_FUNCTION(1,3);
extern void    smtp_vprintf(const char *, BOOL, va_list);
extern uschar *string_copy(const uschar *);
extern uschar *string_copyn(const uschar *, int);
extern uschar *string_sprintf(const char *, ...) ALMOST_PRINTF(1,2);

/* End of local_scan.h */
