/*
 * ProFTPD - mod_sftp date(1) simulation
 * Copyright (c) 2012-2016 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#include "mod_sftp.h"
#include "ssh2.h"
#include "packet.h"
#include "msg.h"
#include "channel.h"
#include "date.h"
#include "misc.h"
#include "disconnect.h"

static pool *date_pool = NULL;
static int date_use_gmt = FALSE;

/* Use a struct to maintain the per-channel date-specific values. */
struct date_session {
  struct date_session *next, *prev;

  pool *pool;
  uint32_t channel_id;
  int use_gmt;
};

static struct date_session *date_sessions = NULL;

static const char *trace_channel = "ssh2";

static struct date_session *date_get_session(uint32_t channel_id) {
  struct date_session *sess;

  sess = date_sessions;
  while (sess) {
    pr_signals_handle();

    if (sess->channel_id == channel_id) {
      return sess;
    }

    sess = sess->next;
  }

  errno = ENOENT;
  return NULL;
}

/* Main entry point */
int sftp_date_handle_packet(pool *p, void *ssh2, uint32_t channel_id,
    unsigned char *data, uint32_t datalen) {

  (void) ssh2;
  (void) channel_id;
  (void) data;
  (void) datalen;

  /* This callback should never be called; the client will request an
   * 'exec date' command, and mod_sftp should send the channel data back
   * immediately, without needing anything more from the client.
   *
   * Thus this is essentially a no-op.
   */

  return 0;
}

int sftp_date_set_params(pool *p, uint32_t channel_id, array_header *req) {
  char **reqargv = NULL;
  int optc;
  const char *opts = "u";

  if (!(sftp_services & SFTP_SERVICE_FL_DATE)) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION, "%s",
      "'date' exec request denied by Protocols config");
    errno = EPERM;
    return -1;
  }

  reqargv = (char **) req->elts;

  if (pr_trace_get_level(trace_channel) >= 5) {
    register unsigned int i;

    for (i = 0; i < req->nelts; i++) {
      if (reqargv[i]) {
        pr_trace_msg(trace_channel, 5, "reqargv[%u] = '%s'", i, reqargv[i]);
      }
    }
  }

  /* Possible options are:
   *
   *  -u (GMT time)
   */

  pr_getopt_reset();

  while ((optc = getopt(req->nelts-1, reqargv, opts)) != -1) {
    switch (optc) {
      case 'u':
        date_use_gmt = TRUE;
        break;

      case '?':
        /* Ignore unsupported options */
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "ignoring supported date(1) option '%c'", (char) optopt);
        break;
    }
  }

  date_pool = make_sub_pool(sftp_pool);
  pr_pool_tag(date_pool, "SSH2 Date Pool");

  return 0;
}

int sftp_date_postopen_session(uint32_t channel_id) {
  struct date_session *sess;
  unsigned char *buf, *ptr;
  const char *date_str;
  uint32_t buflen, bufsz;
  time_t now;

  sess = date_get_session(channel_id);
  if (sess == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no existing date(1) session for channel ID %lu, rejecting request",
      (unsigned long) channel_id);
    return -1;
  }

  time(&now);
  date_str = pr_strtime2(now, sess->use_gmt);

  /* XXX Is this big enough?  Too big? */
  buflen = bufsz = 128;
  buf = ptr = palloc(sess->pool, bufsz);

  /* pr_strtime() trims off the trailing newline, so add it back in. */
  sftp_msg_write_string(&buf, &buflen,
    pstrcat(sess->pool, date_str, "\n", NULL));

  if (sftp_channel_write_data(sess->pool, channel_id, ptr,
      (bufsz - buflen)) < 0) {
    return -1;
  }

  /* Return 1 to indicate that we're already done with this channel. */
  return 1;
}

int sftp_date_open_session(uint32_t channel_id) {
  pool *sub_pool;
  struct date_session *sess, *last;

  /* Check to see if we already have an date session opened for the given
   * channel ID.
   */
  sess = last = date_sessions;
  while (sess) {
    pr_signals_handle();

    if (sess->channel_id == channel_id) {
      errno = EEXIST;
      return -1;
    }

    if (sess->next == NULL) {
      /* This is the last item in the list. */
      last = sess;
    }

    sess = sess->next;
  }

  /* Looks like we get to allocate a new one. */
  sub_pool = make_sub_pool(date_pool);
  pr_pool_tag(sub_pool, "date session pool");

  sess = pcalloc(sub_pool, sizeof(struct date_session));
  sess->pool = sub_pool;
  sess->channel_id = channel_id;
  sess->use_gmt = date_use_gmt;

  if (last) {
    last->next = sess;
    sess->prev = last;

  } else {
    date_sessions = sess;
  }

  return 0;
}

int sftp_date_close_session(uint32_t channel_id) {
  /* no-op */
  return 0;
}
