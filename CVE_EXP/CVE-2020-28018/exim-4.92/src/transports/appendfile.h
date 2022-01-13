/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Private structure for the private options. */

typedef struct {
  uschar *filename;
  uschar *dirname;
  uschar *dirfilename;
  uschar *message_prefix;
  uschar *message_suffix;
  uschar *create_file_string;
  uschar *quota;
  uschar *quota_directory;
  uschar *quota_filecount;
  uschar *quota_size_regex;
  uschar *quota_warn_threshold;
  uschar *mailbox_size_string;
  uschar *mailbox_filecount_string;
  uschar *expand_maildir_use_size_file;
  uschar *maildir_dir_regex;
  uschar *maildir_tag;
  uschar *maildirfolder_create_regex;
  uschar *mailstore_prefix;
  uschar *mailstore_suffix;
  uschar *check_string;
  uschar *escape_string;
  uschar *file_format;
  off_t quota_value;
  off_t quota_warn_threshold_value;
  off_t mailbox_size_value;
  int   mailbox_filecount_value;
  int   quota_filecount_value;
  int   mode;
  int   dirmode;
  int   lockfile_mode;
  int   lockfile_timeout;
  int   lock_fcntl_timeout;
  int   lock_flock_timeout;
  int   lock_retries;
  int   lock_interval;
  int   maildir_retries;
  int   create_file;
  int   options;
  BOOL  allow_fifo;
  BOOL  allow_symlink;
  BOOL  check_group;
  BOOL  check_owner;
  BOOL  create_directory;
  BOOL  notify_comsat;
  BOOL  use_lockfile;
  BOOL  set_use_lockfile;
  BOOL  use_fcntl;
  BOOL  set_use_fcntl;
  BOOL  use_flock;
  BOOL  set_use_flock;
  BOOL  use_mbx_lock;
  BOOL  set_use_mbx_lock;
  BOOL  use_bsmtp;
  BOOL  use_crlf;
  BOOL  file_must_exist;
  BOOL  mode_fail_narrower;
  BOOL  maildir_format;
  BOOL  maildir_use_size_file;
  BOOL  mailstore_format;
  BOOL  mbx_format;
  BOOL  quota_warn_threshold_is_percent;
  BOOL  quota_is_inclusive;
  BOOL  quota_no_check;
  BOOL  quota_filecount_no_check;
} appendfile_transport_options_block;

/* Restricted creation options */

enum { create_anywhere, create_belowhome, create_inhome };

/* Data for reading the private options. */

extern optionlist appendfile_transport_options[];
extern int appendfile_transport_options_count;

/* Block containing default values. */

extern appendfile_transport_options_block appendfile_transport_option_defaults;

/* The main and init entry points for the transport */

extern BOOL appendfile_transport_entry(transport_instance *, address_item *);
extern void appendfile_transport_init(transport_instance *);

/* Function that is shared with tf_maildir.c */

extern off_t  check_dir_size(uschar *, int *, const pcre *);

/* End of transports/appendfile.h */
