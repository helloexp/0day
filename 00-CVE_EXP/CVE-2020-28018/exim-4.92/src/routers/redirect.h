/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

/* Header for the redirect router */

/* Private structure for the private options. */

typedef struct {
  transport_instance *directory_transport;
  transport_instance *file_transport;
  transport_instance *pipe_transport;
  transport_instance *reply_transport;

  uschar *data;
  uschar *directory_transport_name;
  uschar *file;
  uschar *file_dir;
  uschar *file_transport_name;
  uschar *include_directory;
  uschar *pipe_transport_name;
  uschar *reply_transport_name;
  uschar *sieve_subaddress;
  uschar *sieve_useraddress;
  uschar *sieve_vacation_directory;
  uschar *sieve_enotify_mailto_owner;
  uschar *syntax_errors_text;
  uschar *syntax_errors_to;
  uschar *qualify_domain;

  uid_t  *owners;
  gid_t  *owngroups;

#ifdef EXPERIMENTAL_SRS
  uschar *srs;
  uschar *srs_alias;
  uschar *srs_condition;
  uschar *srs_dbinsert;
  uschar *srs_dbselect;
#endif

  int   modemask;
  int   bit_options;
  BOOL  check_ancestor;
  BOOL  check_group;
  BOOL  check_owner;
  BOOL  forbid_file;
  BOOL  forbid_filter_reply;
  BOOL  forbid_pipe;
  BOOL  forbid_smtp_code;
  BOOL  hide_child_in_errmsg;
  BOOL  one_time;
  BOOL  qualify_preserve_domain;
  BOOL  skip_syntax_errors;
} redirect_router_options_block;

/* Data for reading the private options. */

extern optionlist redirect_router_options[];
extern int redirect_router_options_count;

/* Block containing default values. */

extern redirect_router_options_block redirect_router_option_defaults;

/* The main and initialization entry points for the router */

extern int redirect_router_entry(router_instance *, address_item *,
  struct passwd *, int, address_item **, address_item **,
  address_item **, address_item **);

extern void redirect_router_init(router_instance *);

/* End of routers/redirect.h */
