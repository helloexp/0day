/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004, 2015
 * License: GPL
 * Copyright (c) The Exim Maintainers 2016
 */

#ifdef WITH_CONTENT_SCAN

#define MIME_MAX_HEADER_SIZE 8192
#define MIME_MAX_LINE_LENGTH 32768

#define MBC_ATTACHMENT            0
#define MBC_COVERLETTER_ONESHOT   1
#define MBC_COVERLETTER_ALL       2

struct mime_boundary_context
{
  struct mime_boundary_context *parent;
  unsigned char *boundary;
  int context;
};

typedef struct mime_header {
  uschar *  name;
  int       namelen;
  uschar ** value;
} mime_header;


typedef struct mime_parameter {
  uschar *  name;
  int       namelen;
  uschar ** value;
} mime_parameter;

/* MIME Anomaly list */
#define MIME_ANOMALY_BROKEN_BASE64    1
#define MIME_ANOMALY_BROKEN_QP        0


#endif
