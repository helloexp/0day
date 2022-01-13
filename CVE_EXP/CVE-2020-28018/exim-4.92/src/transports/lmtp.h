/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

/* Private structure for the private options. */

typedef struct {
  uschar *cmd;
  uschar *skt;
  int   timeout;
  int   options;
  BOOL  ignore_quota;
} lmtp_transport_options_block;

/* Data for reading the private options. */

extern optionlist lmtp_transport_options[];
extern int lmtp_transport_options_count;

/* Block containing default values. */

extern lmtp_transport_options_block lmtp_transport_option_defaults;

/* The main and init entry points for the transport */

extern BOOL lmtp_transport_entry(transport_instance *, address_item *);
extern void lmtp_transport_init(transport_instance *);

/* End of transports/lmtp.h */
