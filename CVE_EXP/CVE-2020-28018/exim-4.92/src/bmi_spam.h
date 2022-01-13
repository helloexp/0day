/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Code for calling Brightmail AntiSpam.
   Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004
   License: GPL */

#ifdef EXPERIMENTAL_BRIGHTMAIL

#include <bmi_api.h>

extern uschar *bmi_process_message(header_line *, int);
extern uschar *bmi_get_base64_verdict(uschar *, uschar *);
extern uschar *bmi_get_base64_tracker_verdict(uschar *);
extern int bmi_get_delivery_status(uschar *);
extern uschar *bmi_get_alt_location(uschar *);
extern int bmi_check_rule(uschar *,uschar *);

extern uschar *bmi_current_optin;

#endif
