/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Andrew Colin Kissa <andrew@topdog.za.net> 2016 */
/* Copyright (c) University of Cambridge 2016 */
/* See the file NOTICE for conditions of use and distribution. */

/* Private structure for the private options. */

typedef struct {
    uschar *dirname;
} queuefile_transport_options_block;

/* Data for reading the private options. */

extern optionlist queuefile_transport_options[];
extern int queuefile_transport_options_count;

/* Block containing default values. */

extern queuefile_transport_options_block queuefile_transport_option_defaults;

/* The main and init entry points for the transport */

extern BOOL queuefile_transport_entry(transport_instance *, address_item *);
extern void queuefile_transport_init(transport_instance *);

/* End of transports/queuefile.h */
