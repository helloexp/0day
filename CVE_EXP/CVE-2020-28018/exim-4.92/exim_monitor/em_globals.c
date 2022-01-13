/*************************************************
*                Exim Monitor                    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "em_hdr.h"

/* This source module contains all the global variables used in
the exim monitor, including those that are used by the standard
Exim modules that are included in Eximon. For comments on their
usage, see em_hdr.h and globals.h. */


/* The first set are unique to Eximon */

Display *X_display;
XtAppContext X_appcon;

XtActionsRec actionTable[] = {
  { "dialogAction",  (XtActionProc)dialogAction}};

int actionTableSize = sizeof(actionTable)/sizeof(XtActionsRec);

XtTranslations queue_trans;
XtTranslations text_trans;

Widget  dialog_ref_widget;
Widget  toplevel_widget;
Widget  log_widget = NULL;
Widget  queue_widget;
Widget  unhide_widget = NULL;


FILE   *LOG;

int     action_output = FALSE;
int     action_queue_update = TRUE;
uschar  actioned_message[24];
uschar *action_required;
uschar *alternate_config = NULL;

#ifdef EXPERIMENTAL_BRIGHTMAIL
int     bmi_run                = 0;
uschar *bmi_verdicts           = NULL;
#endif

int     body_max = 20000;

uschar *exim_path              = US BIN_DIRECTORY "/exim"
                        "\0<---------------Space to patch exim_path->";

int     eximon_initialized = FALSE;

int     log_buffer_size = 10240;
BOOL    log_datestamping = FALSE;
int     log_depth = 150;
uschar *log_display_buffer;
uschar *log_file = NULL;
uschar  log_file_open[256];
uschar *log_font = NULL;
ino_t   log_inode;
long int log_position;
int     log_width = 600;

uschar *menu_event = US"Shift<Btn1Down>";
int     menu_is_up = FALSE;
int     min_height = 162;
int     min_width  = 103;

pipe_item *pipe_chain = NULL;

uschar *qualify_domain = NULL;
int     queue_depth = 200;
uschar *queue_font = NULL;
int     queue_max_addresses = 10;
skip_item *queue_skip = NULL;
uschar *queue_stripchart_name = NULL;
int     queue_update = 60;
int     queue_width = 600;

pcre   *yyyymmdd_regex;

uschar *size_stripchart = NULL;
uschar *size_stripchart_name = NULL;
int     spool_is_split = FALSE;
int     start_small = FALSE;
int     stripchart_height = 90;
int     stripchart_number = 1;
pcre  **stripchart_regex;
uschar **stripchart_title;
int    *stripchart_total;
int     stripchart_update = 60;
int     stripchart_width = 80;
int     stripchart_varstart = 1;

int     text_depth = 200;
int     tick_queue_accumulator = 999999;

uschar *window_title = US"exim monitor";


/***********************************************************/
/***********************************************************/


/* These ones are used by Exim modules included in Eximon. Not all are
actually relevant to the operation of Eximon. If SPOOL_DIRECTORY is not
defined (Exim was compiled with it unset), just define it empty. The script
that fires up the monitor fishes the value out by using -bP anyway. */

#ifndef SPOOL_DIRECTORY
#define SPOOL_DIRECTORY ""
#endif

tree_node *acl_var_c           = NULL;
tree_node *acl_var_m           = NULL;
uschar *active_hostname        = NULL;
BOOL    allow_unqualified_recipient = FALSE;
BOOL    allow_unqualified_sender = FALSE;
uschar *authenticated_id       = NULL;
uschar *authenticated_sender   = NULL;

uschar *big_buffer             = NULL;
int     big_buffer_size        = BIG_BUFFER_SIZE;
int     body_linecount         = 0;
int     body_zerocount         = 0;

BOOL    deliver_firsttime      = FALSE;
BOOL    deliver_freeze         = FALSE;
time_t  deliver_frozen_at      = 0;
BOOL    deliver_manual_thaw    = FALSE;

#ifndef DISABLE_DKIM
uschar *dkim_cur_signer          = NULL;
uschar *dkim_signers             = NULL;
uschar *dkim_signing_domain      = NULL;
uschar *dkim_signing_selector    = NULL;
uschar *dkim_verify_signers      = US"$dkim_signers";
unsigned dkim_collect_input      = 0;
BOOL    dkim_disable_verify      = FALSE;
#endif

BOOL    dont_deliver           = FALSE;

int     dsn_ret                = 0;
uschar *dsn_envid              = NULL;

struct global_flags f = {
 .sender_local		= FALSE,
};

#ifdef WITH_CONTENT_SCAN
int     fake_response          = OK;
#endif

header_line *header_last       = NULL;
header_line *header_list       = NULL;

BOOL    host_lookup_deferred   = FALSE;
BOOL    host_lookup_failed     = FALSE;
uschar *interface_address      = NULL;
int     interface_port         = 0;

BOOL    local_error_message    = FALSE;
uschar *local_scan_data        = NULL;
BOOL    log_timezone           = FALSE;

#ifdef WITH_CONTENT_SCAN
uschar *spam_bar               = NULL;
uschar *spam_report            = NULL;
uschar *spam_score             = NULL;
uschar *spam_score_int         = NULL;
#endif

int     max_received_linelength= 0;
int     message_age            = 0;
uschar *message_id;
uschar *message_id_external;
uschar  message_id_option[MESSAGE_ID_LENGTH + 3];

int     message_linecount      = 0;
int     message_size           = 0;
uschar  message_subdir[2]      = { 0, 0 };

gid_t   originator_gid;
uschar *originator_login;
uid_t   originator_uid;

uschar *primary_hostname       = NULL;

uschar *queue_name             = US"";

int     received_count         = 0;
uschar *received_protocol      = NULL;
struct timeval received_time   = { 0, 0 };
int     recipients_count       = 0;
recipient_item *recipients_list = NULL;
int     recipients_list_max    = 0;
BOOL    running_in_test_harness=FALSE;

uschar *sender_address         = NULL;
uschar *sender_fullhost        = NULL;
uschar *sender_helo_name       = NULL;
uschar *sender_host_address    = NULL;
uschar *sender_host_authenticated = NULL;
uschar *sender_host_name       = NULL;
int     sender_host_port       = 0;
uschar *sender_ident           = NULL;
BOOL    sender_set_untrusted   = FALSE;
uschar *smtp_active_hostname   = NULL;

BOOL    split_spool_directory  = FALSE;
uschar *spool_directory        = US SPOOL_DIRECTORY;
int     string_datestamp_offset=-1;
int     string_datestamp_length= 0;
int     string_datestamp_type  = -1;

BOOL    timestamps_utc         = FALSE;
tls_support tls_in = {
 {-1},	/* tls_active */
 0,	/* bits */
 FALSE,	/* tls_certificate_verified */
#ifdef SUPPORT_DANE
 FALSE, /* dane_verified */
 0,     /* tlsa_usage */
#endif
 NULL,	/* tls_cipher */
 FALSE,	/* tls_on_connect */
 NULL,	/* tls_on_connect_ports */
 NULL,	/* tls_peerdn */
 NULL	/* tls_sni */
};

tree_node *tree_duplicates     = NULL;
tree_node *tree_nonrecipients  = NULL;
tree_node *tree_unusable       = NULL;

uschar *version_date           = US"?";
uschar *version_string         = US"?";

int     warning_count          = 0;

/* End of em_globals.c */
