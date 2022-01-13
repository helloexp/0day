/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2014 */
/* See the file NOTICE for conditions of use and distribution. */

/* Private structure for the private options. */

typedef struct {
  uschar *cmd;
  uschar *allow_commands;
  uschar *environment;
  uschar *path;
  uschar *message_prefix;
  uschar *message_suffix;
  uschar *temp_errors;
  uschar *check_string;
  uschar *escape_string;
  int   umask;
  int   max_output;
  int   timeout;
  int   options;
  BOOL  force_command;
  BOOL  freeze_exec_fail;
  BOOL  freeze_signal;
  BOOL  ignore_status;
  BOOL  permit_coredump;
  BOOL  restrict_to_path;
  BOOL  timeout_defer;
  BOOL  use_shell;
  BOOL  use_bsmtp;
  BOOL  use_classresources;
  BOOL  use_crlf;
} pipe_transport_options_block;

/* Data for reading the private options. */

extern optionlist pipe_transport_options[];
extern int pipe_transport_options_count;

/* Block containing default values. */

extern pipe_transport_options_block pipe_transport_option_defaults;

/* The main and init entry points for the transport */

extern BOOL pipe_transport_entry(transport_instance *, address_item *);
extern void pipe_transport_init(transport_instance *);

/* End of transports/pipe.h */
