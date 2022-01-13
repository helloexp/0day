/*
 * ProFTPD - mod_sftp channels
 * Copyright (c) 2008-2017 TJ Saunders
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
#include "msg.h"
#include "packet.h"
#include "channel.h"
#include "disconnect.h"
#include "interop.h"
#include "fxp.h"
#include "scp.h"
#include "date.h"

extern module sftp_module;

/* Used for maintaining our list of 'exec' channel handlers. */
struct ssh2_channel_exec_handler {
  /* The module which registered this handler (err, collection of
   * callbacks).
   */
  module *m;

  /* The 'exec' command for which these handlers should be used. */
  const char *command;

  int (*set_params)(pool *, uint32_t, array_header *);
  int (*prepare)(uint32_t);
  int (*postopen)(uint32_t);
  int (*handle_packet)(pool *, void *, uint32_t, unsigned char *, uint32_t);
  int (*finish)(uint32_t);
};

static array_header *channel_exec_handlers = NULL;

/* Used for buffering up incoming/outgoing packets until the channel windows
 * open.
 */
struct ssh2_channel_databuf {
  pool *pool;

  struct ssh2_channel_databuf *next;

  /* Points to the start of the buffer. */
  char *ptr;

  /* Points to the start of the data which needs to be sent.  Usually, but
   * not always, this is the same as ptr.
   */
  char *buf;

  uint32_t buflen;
  uint32_t bufsz;
};

static pool *channel_pool = NULL;
static uint32_t channelno = 0;

static unsigned int channel_max = SFTP_SSH2_CHANNEL_MAX_COUNT;
static unsigned int channel_count = 0;

static pool *channel_databuf_pool = NULL;

/* XXX Use a table, rather than a list, for tracking channels? */
static array_header *channel_list = NULL;

static uint32_t chan_window_size = SFTP_SSH2_CHANNEL_WINDOW_SIZE;
static uint32_t chan_packet_size = SFTP_SSH2_CHANNEL_MAX_PACKET_SIZE;

static array_header *accepted_envs = NULL;

static const char *trace_channel = "ssh2";

static int send_channel_done(pool *, uint32_t);

static struct ssh2_channel *alloc_channel(const char *type,
    uint32_t remote_channel_id, uint32_t remote_windowsz,
    uint32_t remote_max_packetsz) {
  struct ssh2_channel *chan = NULL;
  pool *sub_pool = NULL;
 
  sub_pool = make_sub_pool(channel_pool);
  pr_pool_tag(sub_pool, "SSH2 channel pool");
   
  chan = pcalloc(sub_pool, sizeof(struct ssh2_channel));
  chan->pool = sub_pool;
  chan->type = pstrdup(sub_pool, type);

  chan->local_channel_id = channelno++;

  chan->local_windowsz = chan_window_size;
  chan->local_max_packetsz = chan_packet_size;

  chan->remote_channel_id = remote_channel_id;
  chan->remote_windowsz = remote_windowsz;
  chan->remote_max_packetsz = remote_max_packetsz;

  if (channel_list == NULL) {
    channel_list = make_array(channel_pool, 1, sizeof(struct ssh2_channel *));
  }

  *((struct ssh2_channel **) push_array(channel_list)) = chan;

  channel_count++;
  return chan;
}

static void destroy_channel(uint32_t channel_id) {
  register unsigned int i;
  struct ssh2_channel **chans;

  if (channel_list == NULL)
    return;

  chans = channel_list->elts;
  for (i = 0; i < channel_list->nelts; i++) {
    if (chans[i] != NULL &&
        chans[i]->local_channel_id == channel_id) {

      /* If both parties have said that this channel is closed, we can
       * close it.
       */
      if (chans[i]->recvd_close &&
          chans[i]->sent_close) {
        if (chans[i]->finish != NULL) {
          pr_trace_msg(trace_channel, 15,
            "calling finish handler for channel ID %lu",
            (unsigned long) channel_id);
          (chans[i]->finish)(channel_id);
        }

        chans[i] = NULL;
        channel_count--;
        break;
      }
    }
  }

  return;
}

static struct ssh2_channel *get_channel(uint32_t channel_id) {
  register unsigned int i;
  struct ssh2_channel **chans;

  if (channel_list == NULL) {
    errno = EACCES;
    return NULL;
  }

  chans = channel_list->elts;
  for (i = 0; i < channel_list->nelts; i++) {
    if (chans[i] != NULL &&
        chans[i]->local_channel_id == channel_id) {
      return chans[i];
    }
  }

  errno = ENOENT;
  return NULL;
}

static uint32_t get_channel_pending_size(struct ssh2_channel *chan) {
  struct ssh2_channel_databuf *db;
  uint32_t pending_datalen = 0;

  db = chan->outgoing;
  while (db &&
         db->buflen > 0) {
    pr_signals_handle();

    pending_datalen += db->buflen;
    db = db->next;
  }

  return pending_datalen;
}

static void drain_pending_channel_data(uint32_t channel_id) {
  struct ssh2_channel *chan;

  chan = get_channel(channel_id);
  if (chan == NULL) {
    return;
  }

  if (chan->outgoing) {
    pool *tmp_pool;
    struct ssh2_channel_databuf *db;

    tmp_pool = make_sub_pool(channel_pool);

    pr_trace_msg(trace_channel, 15, "draining pending data for channel ID %lu "
      "(%lu bytes)", (unsigned long) channel_id,
      (unsigned long) get_channel_pending_size(chan));

    db = chan->outgoing;

    /* While we have room remaining in the remote window (and we are not
     * rekeying), and while there are still pending outgoing messages,
     * send them.
     */

    while (!(sftp_sess_state & SFTP_SESS_STATE_REKEYING) &&
           db &&
           db->buflen > 0 &&
           chan->remote_windowsz > 0) {
      struct ssh2_packet *pkt;
      unsigned char *buf, *ptr;
      uint32_t bufsz, buflen, payload_len;
      int res;

      pr_signals_handle();

      /* If the remote window size or remote max packet size changes the
       * length we can send, then payload_len is NOT the same as buflen.  Hence
       * the separate variable.
       */
      payload_len = db->buflen;

      /* The maximum size of the CHANNEL_DATA payload we can send to the client
       * is the smaller of the remote window size and the remote packet size.
       */

      if (payload_len > chan->remote_max_packetsz)
        payload_len = chan->remote_max_packetsz;

      if (payload_len > chan->remote_windowsz)
        payload_len = chan->remote_windowsz;

      pkt = sftp_ssh2_packet_create(tmp_pool);

      /* In addition to the data itself, we need to allocate room in the
       * outgoing packet for the type (1 byte), the channel ID (4 bytes),
       * and for the data length (4 bytes).
       */
      bufsz = buflen = payload_len + 9;
      ptr = buf = palloc(pkt->pool, bufsz);

      sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_CHANNEL_DATA);
      sftp_msg_write_int(&buf, &buflen, chan->remote_channel_id);
      sftp_msg_write_int(&buf, &buflen, payload_len);
      memcpy(buf, db->buf, payload_len);
      buflen -= payload_len;

      pkt->payload = ptr;
      pkt->payload_len = (bufsz - buflen);

      pr_trace_msg(trace_channel, 9, "sending CHANNEL_DATA (remote channel "
        "ID %lu, %lu data bytes)", (unsigned long) chan->remote_channel_id,
        (unsigned long) payload_len);

      res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
      if (res < 0) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error draining pending CHANNEL_DATA for channel ID %lu: %s",
          (unsigned long) channel_id, strerror(errno));
        destroy_pool(tmp_pool);
        return;
      }

      chan->remote_windowsz -= payload_len;

      pr_trace_msg(trace_channel, 11,
        "channel ID %lu remote window size currently at %lu bytes",
        (unsigned long) chan->remote_channel_id,
        (unsigned long) chan->remote_windowsz);

      /* If we sent this entire databuf, then we can dispose of it, and
       * advance to the next one on the list.  However, we may have only
       * sent a portion of it, in which case it needs to stay where it is;
       * we only need to update buf and buflen.
       */

      if (payload_len == db->buflen) {
        struct ssh2_channel_databuf *next;

        next = db->next;
        destroy_pool(db->pool);
        chan->outgoing = db = next;

      } else {
        db->buf += payload_len;
        db->buflen -= payload_len;
      }
    }

    /* If we still have pending data at this point, it is probably because
     * the window wasn't big enough; we need to wait for another
     * CHANNEL_WINDOW_ADJUST.
     */
    if (chan->outgoing) {
      pr_trace_msg(trace_channel, 15, "still have pending channel data "
        "(%lu bytes) for channel ID %lu (window at %lu bytes)",
        (unsigned long) get_channel_pending_size(chan),
        (unsigned long) channel_id, (unsigned long) chan->remote_windowsz);
    }

    destroy_pool(tmp_pool);
  }

  return;
}

static struct ssh2_channel_databuf *get_databuf(uint32_t channel_id,
    uint32_t buflen) {
  struct ssh2_channel *chan;
  struct ssh2_channel_databuf *db;
  pool *sub_pool;

  chan = get_channel(channel_id);
  if (chan == NULL) {
    errno = EPERM;
    return NULL;
  }

  if (!channel_databuf_pool) {
    channel_databuf_pool = make_sub_pool(channel_pool);
    pr_pool_tag(channel_databuf_pool, "SSH2 Channel data buffer pool");
  }

  sub_pool = pr_pool_create_sz(channel_databuf_pool, 128);
  pr_pool_tag(sub_pool, "channel databuf pool");

  db = pcalloc(sub_pool, sizeof(struct ssh2_channel_databuf));
  db->pool = sub_pool;
  db->bufsz = buflen;
  db->ptr = db->buf = palloc(db->pool, db->bufsz);

  db->buflen = 0;
  db->next = NULL;

  /* Make sure the returned outbuf is already in place at the end of
   * the pending outgoing list.
   */
  if (chan->outgoing) {
    struct ssh2_channel_databuf *iter;

    iter = chan->outgoing;
    while (iter->next) {
      pr_signals_handle();
      iter = iter->next;
    }

    iter->next = db;

  } else {
    chan->outgoing = db;
  }

  return db;
}

static int read_channel_open(struct ssh2_packet *pkt, uint32_t *channel_id) {
  unsigned char *buf;
  char *channel_type;
  uint32_t buflen, initial_windowsz, max_packetsz;
  cmd_rec *cmd;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  channel_type = sftp_msg_read_string(pkt->pool, &buf, &buflen);
  *channel_id = sftp_msg_read_int(pkt->pool, &buf, &buflen);

  /* First check if this would cause the client to exceed its count of
   * open channels.
   */
  if (channel_count + 1 > channel_max) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "maximum number of channels (%u) open, denying request to "
      "open '%s' channel", channel_count, channel_type);
    return -1;
  }

  initial_windowsz = sftp_msg_read_int(pkt->pool, &buf, &buflen);
  max_packetsz = sftp_msg_read_int(pkt->pool, &buf, &buflen);

  pr_trace_msg(trace_channel, 8, "open of '%s' channel using remote "
    "ID %lu requested: initial client window len = %lu bytes, client max "
    "packet size = %lu bytes", channel_type, (unsigned long) *channel_id,
    (unsigned long) initial_windowsz, (unsigned long) max_packetsz);

  cmd = pr_cmd_alloc(pkt->pool, 2, pstrdup(pkt->pool, "CHANNEL_OPEN"),
    pstrdup(pkt->pool, channel_type));
  cmd->arg = channel_type;
  cmd->cmd_class = CL_MISC|CL_SSH;

  if (strncmp(channel_type, "session", 8) != 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unsupported channel type '%s' requested, denying", channel_type);
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
    return -1;
  }

  if (alloc_channel(channel_type, *channel_id, initial_windowsz,
      max_packetsz) == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error allocating channel");
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
    return -1;
  }

  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  return 0;
}

static int handle_channel_close(struct ssh2_packet *pkt) {
  char chan_str[16];
  unsigned char *buf;
  uint32_t buflen, channel_id;
  struct ssh2_channel *chan;
  cmd_rec *cmd;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  channel_id = sftp_msg_read_int(pkt->pool, &buf, &buflen);

  memset(chan_str, '\0', sizeof(chan_str));
  pr_snprintf(chan_str, sizeof(chan_str)-1, "%lu", (unsigned long) channel_id);

  cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, "CHANNEL_CLOSE"));
  cmd->arg = pstrdup(pkt->pool, chan_str);
  cmd->cmd_class = CL_MISC|CL_SSH;

  chan = get_channel(channel_id);
  if (chan == NULL) {
    pr_trace_msg(trace_channel, 8, "unable to close channel ID %lu: %s",
      (unsigned long) channel_id, strerror(errno));

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no open channel for channel ID %lu", (unsigned long) channel_id);
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
    return -1;
  }

  /* The order of these calls, and the setting of recvd_close, is important.
   * Do not set recvd_close to true before calling send_channel_done,
   * otherwise the client will receive an EOF prematurely.
   */

  if (!chan->sent_close) {
    send_channel_done(pkt->pool, channel_id);
  }

  chan->recvd_close = TRUE;
  destroy_channel(channel_id);

  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  return 0;
}

static int process_channel_data(struct ssh2_channel *chan,
    struct ssh2_packet *pkt, unsigned char *data, uint32_t datalen) {
  int res;

  if (chan->handle_packet == NULL) {
    pr_trace_msg(trace_channel, 3, "no handler registered for data on "
      "channel ID %lu, rejecting packet",
      (unsigned long) chan->local_channel_id);
    errno = EACCES;
    return -1;
  }

  res = chan->handle_packet(pkt->pool, pkt, chan->local_channel_id, data,
    datalen);

  chan->local_windowsz -= datalen;

  if (chan->local_windowsz < (chan->local_max_packetsz * 3)) {
    unsigned char *buf, *ptr;
    uint32_t buflen, bufsz, window_adjlen;
    struct ssh2_packet *resp;

    /* Need to send a CHANNEL_WINDOW_ADJUST message to the client, so that
     * they know to send more data.
     */
    buflen = bufsz = 128;
    ptr = buf = palloc(pkt->pool, bufsz);

    window_adjlen = chan_window_size - chan->local_windowsz;

    sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_CHANNEL_WINDOW_ADJUST);
    sftp_msg_write_int(&buf, &buflen, chan->remote_channel_id);
    sftp_msg_write_int(&buf, &buflen, window_adjlen);

    pr_trace_msg(trace_channel, 15, "sending CHANNEL_WINDOW_ADJUST message "
      "for channel ID %lu, adding %lu bytes to the window size (currently %lu "
      "bytes)", (unsigned long) chan->local_channel_id,
      (unsigned long) window_adjlen, (unsigned long) chan->local_windowsz);

    resp = sftp_ssh2_packet_create(pkt->pool);
    resp->payload = ptr;
    resp->payload_len = (bufsz - buflen);

    if (sftp_ssh2_packet_write(sftp_conn->wfd, resp) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error sending CHANNEL_WINDOW_ADJUST request to client: %s",
        strerror(errno));
    }

    destroy_pool(resp->pool); 
    chan->local_windowsz += window_adjlen;
  }

  return res;
}

static int handle_channel_data(struct ssh2_packet *pkt, uint32_t *channel_id) {
  unsigned char *buf, *data;
  uint32_t buflen, datalen;
  struct ssh2_channel *chan;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  *channel_id = sftp_msg_read_int(pkt->pool, &buf, &buflen);

  chan = get_channel(*channel_id);
  if (chan == NULL) {
    pr_trace_msg(trace_channel, 8, "unable to handle data for "
      "channel ID %lu: %s", (unsigned long) *channel_id, strerror(errno));

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no open channel for remote channel ID %lu", (unsigned long) *channel_id);
    return -1;
  }

  if (chan->recvd_eof) {
    pr_trace_msg(trace_channel, 3, "received data on channel ID %lu after "
      "client had sent CHANNEL_EOF", (unsigned long) *channel_id);
  }

  datalen = sftp_msg_read_int(pkt->pool, &buf, &buflen);

  if (datalen > chan->local_windowsz) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "received too much data (%lu bytes) for local window size (%lu bytes) "
      "for channel ID %lu, ignoring CHANNEL_DATA message",
      (unsigned long) datalen, (unsigned long) chan->local_windowsz,
      (unsigned long) *channel_id);
    return 0;
  }

  pr_trace_msg(trace_channel, 17,
    "processing %lu %s of data for channel ID %lu", (unsigned long) datalen,
    datalen != 1 ? "bytes" : "byte", (unsigned long) *channel_id);
  data = sftp_msg_read_data(pkt->pool, &buf, &buflen, datalen);

  return process_channel_data(chan, pkt, data, datalen);
}

/* Sends an "exit-status" message, followed by CHANNEL_EOF, and
 * finishes with CHANNEL_CLOSE.
 */
static int send_channel_done(pool *p, uint32_t channel_id) {
  int res;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;
  struct ssh2_channel *chan;
  struct ssh2_packet *pkt;

  chan = get_channel(channel_id);
  if (chan == NULL) {
    return 0;
  }

  buflen = bufsz = 128;
  ptr = buf = palloc(p, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_CHANNEL_REQUEST);
  sftp_msg_write_int(&buf, &buflen, chan->remote_channel_id);
  sftp_msg_write_string(&buf, &buflen, "exit-status");
  sftp_msg_write_bool(&buf, &buflen, FALSE);
  sftp_msg_write_int(&buf, &buflen, 0);

  pkt = sftp_ssh2_packet_create(p);
  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  pr_trace_msg(trace_channel, 9,
    "sending CHANNEL_REQUEST (remote channel ID %lu, exit status 0)",
    (unsigned long) chan->remote_channel_id);

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    return res;
  }

  if (!chan->sent_eof) {
    buf = ptr;
    buflen = bufsz;

    sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_CHANNEL_EOF);
    sftp_msg_write_int(&buf, &buflen, chan->remote_channel_id);

    pkt = sftp_ssh2_packet_create(p);
    pkt->payload = ptr;
    pkt->payload_len = (bufsz - buflen);

    pr_trace_msg(trace_channel, 9,
      "sending CHANNEL_EOF (remote channel ID %lu)",
      (unsigned long) chan->remote_channel_id);

    res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
    if (res < 0) {
      destroy_pool(pkt->pool);
      return res;
    }

    chan->sent_eof = TRUE;
  }

  if (!chan->sent_close) {
    buf = ptr;
    buflen = bufsz;

    sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_CHANNEL_CLOSE);
    sftp_msg_write_int(&buf, &buflen, chan->remote_channel_id);

    pkt->payload = ptr;
    pkt->payload_len = (bufsz - buflen);

    pr_trace_msg(trace_channel, 9,
      "sending CHANNEL_CLOSE (remote channel ID %lu)",
      (unsigned long) chan->remote_channel_id);

    res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
    if (res < 0) {
      destroy_pool(pkt->pool);
      return res;
    }

    destroy_pool(pkt->pool);
    chan->sent_close = TRUE;
  }

  destroy_channel(channel_id);
  return res;
}

static int handle_channel_eof(struct ssh2_packet *pkt) {
  char chan_str[16];
  unsigned char *buf;
  uint32_t buflen, channel_id;
  struct ssh2_channel *chan;
  cmd_rec *cmd;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  channel_id = sftp_msg_read_int(pkt->pool, &buf, &buflen);

  memset(chan_str, '\0', sizeof(chan_str));
  pr_snprintf(chan_str, sizeof(chan_str)-1, "%lu", (unsigned long) channel_id);

  cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, "CHANNEL_EOF"));
  cmd->arg = pstrdup(pkt->pool, chan_str);
  cmd->cmd_class = CL_MISC|CL_SSH;

  chan = get_channel(channel_id);
  if (chan == NULL) {
    pr_trace_msg(trace_channel, 8, "unable to handle EOF for "
      "channel ID %lu: %s", (unsigned long) channel_id, strerror(errno));

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no open channel for remote channel ID %lu", (unsigned long) channel_id);
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
    return -1;
  }

  /* The client is telling us it will not send any more data on this channel.*/
  chan->recvd_eof = TRUE;

  /* First, though, drain any pending data for the channel. */
  drain_pending_channel_data(channel_id);

  if (!chan->sent_eof) {
    send_channel_done(pkt->pool, channel_id);
  }

  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  return 0;
}

static int allow_env(const char *key) {
  register unsigned int i;
  char **elts;

  /* The following is a hardcoded list of environment variables set by
   * mod_sftp itself.  These are not allowed to be changed by the client.
   *
   * XXX At some point, this should be changed to use a table; lookups of
   * barred keys will be much faster, especially as the list of barred
   * keys grows.
   */

  const char *prohibited_envs[] = {
    "DYLD_LIBRARY_PATH", /* Mac OSX */
    "HOME",
    "LD_CONFIG",         /* Solaris */
    "LD_CONFIG_32",      /* Solaris */
    "LD_CONFIG_64",      /* Solaris */
    "LD_LIBMAP",         /* FreeBSD */
    "LD_LIBRARY_PATH",
    "LD_NOCONFIG",       /* Solaris */
    "LD_NOCONFIG_32",    /* Solaris */
    "LD_NOCONFIG_64",    /* Solaris */
    "LD_PRELOAD",
    "LD_RUN_PATH",
    "LIBPATH",           /* AIX */
    "PATH",
    "SFTP",
    "SFTP_LIBRARY_VERSION",
    "SFTP_CLIENT_CIPHER_ALGO",
    "SFTP_CLIENT_MAC_ALGO",
    "SFTP_CLIENT_COMPRESSION_ALGO",
    "SFTP_KEX_ALGO",
    "SFTP_SERVER_CIPHER_ALGO",
    "SFTP_SERVER_MAC_ALGO",
    "SFTP_SERVER_COMPRESSION_ALGO",
    "SHLIB_PATH",        /* HP-UX */
    "TMP",
    "TMPDIR",
    "TZ",
    "USER",
    NULL
  };

  for (i = 0; prohibited_envs[i]; i++) {
    if (strcasecmp(key, prohibited_envs[i]) == 0) {
      return FALSE;
    }
  }

  elts = accepted_envs->elts;
  for (i = 0; i < accepted_envs->nelts; i++) {
    if (pr_fnmatch(elts[i], key, 0) == 0) {
      return TRUE;
    }
  }

  /* Bar all environment variables by default. */
  return FALSE;
}

static int handle_exec_channel(struct ssh2_channel *chan,
    struct ssh2_packet *pkt, unsigned char **buf, uint32_t *buflen) {
  register unsigned int i;
  int flags = PR_STR_FL_PRESERVE_WHITESPACE, have_handler = FALSE;
  char *command, *ptr, *word;
  array_header *req;
  struct ssh2_channel_exec_handler **handlers;

  command = sftp_msg_read_string(pkt->pool, buf, buflen);

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "'exec' channel request: command = '%s'", command);

  req = make_array(pkt->pool, 2, sizeof(char *));
  ptr = command;

  while ((word = pr_str_get_word(&ptr, flags)) != NULL) {
    pr_signals_handle();
    *((char **) push_array(req)) = pstrdup(pkt->pool, word);
  }

  *((char **) push_array(req)) = NULL;

  handlers = channel_exec_handlers->elts;
  for (i = 0; i < channel_exec_handlers->nelts; i++) {
    struct ssh2_channel_exec_handler *handler;

    handler = handlers[i];

    pr_trace_msg(trace_channel, 18,
      "checking exec command '%s' against handler registered by 'mod_%s.c'",
      command, handler->m->name);

    if (strcmp(command, handler->command) == 0) {
      int res;

      pr_trace_msg(trace_channel, 18,
        "found '%s' exec handler registered by 'mod_%s.c'",
        command, handler->m->name);

      res = (handler->set_params)(pkt->pool, chan->local_channel_id, req);
      if (res < 0) {
        int xerrno = errno;

        pr_trace_msg(trace_channel, 18, "'set_params' callback error: %s",
          strerror(xerrno));

        errno = xerrno;
        return -1;
      }

      chan->prepare = handler->prepare;
      chan->postopen = handler->postopen;
      chan->handle_packet = handler->handle_packet;
      chan->finish = handler->finish;

      have_handler = TRUE;
      break;
    }
  }

  if (!have_handler) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unsupported exec command '%s'", command);
    return -1;
  }

  return 0;
}

static int handle_env_channel(struct ssh2_channel *chan,
    struct ssh2_packet *pkt, unsigned char **buf, uint32_t *buflen) {
  int res;
  char *key, *value;

  key = sftp_msg_read_string(pkt->pool, buf, buflen);
  value = sftp_msg_read_string(pkt->pool, buf, buflen);

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "'env' channel request: '%s' = '%s'", key, value);

  if (allow_env(key) == TRUE) {
    res = pr_env_set(sftp_pool, pstrdup(session.pool, key),
      pstrdup(session.pool, value));
    if (res < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error setting environment variable '%s' with value '%s': %s",
        key, value, strerror(errno));
    }

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "environment variable '%s' prohibited by policy", key);
    res = -1;
  }

  return res;
}

static int handle_signal_channel(struct ssh2_channel *chan,
    struct ssh2_packet *pkt, unsigned char **buf, uint32_t *buflen) {
  int res;
  char bool, *sig_name;

  bool = sftp_msg_read_bool(pkt->pool, buf, buflen);
  if (bool != FALSE) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "malformed 'signal' request (bool must be FALSE)");
  }

  sig_name = sftp_msg_read_string(pkt->pool, buf, buflen);

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "'signal' channel request: SIG%s", sig_name);

  if (strncmp(sig_name, "ABRT", 5) == 0) {
    res = raise(SIGABRT);

  } else if (strncmp(sig_name, "ALRM", 5) == 0) {
    res = raise(SIGALRM);

#ifdef SIGFPE
  } else if (strncmp(sig_name, "FPE", 4) == 0) {
    res = raise(SIGFPE);

#endif
  } else if (strncmp(sig_name, "HUP", 4) == 0) {
    /* Sending SIGHUP to this process is not a good idea, but we'll act
     * like it succeeded anyway.
     */
    res = 0;

#ifdef SIGILL
  } else if (strncmp(sig_name, "ILL", 4) == 0) {
    res = raise(SIGILL);

#endif
  } else if (strncmp(sig_name, "INT", 4) == 0) {
    res = raise(SIGINT);

  } else if (strncmp(sig_name, "KILL", 5) == 0) {
    res = raise(SIGKILL);

  } else if (strncmp(sig_name, "PIPE", 5) == 0) {
    /* Ignore SIGPIPE, since we told the kernel we would ignore it. */
    res = 0;

  } else if (strncmp(sig_name, "QUIT", 5) == 0) {
    res = raise(SIGQUIT);

  } else if (strncmp(sig_name, "SEGV", 5) == 0) {
    res = raise(SIGSEGV);

  } else if (strncmp(sig_name, "TERM", 5) == 0) {
    res = raise(SIGTERM);

  } else if (strncmp(sig_name, "USR1", 5) == 0 ||
             strncmp(sig_name, "USR2", 5) == 0) {
    /* We already use these for very specific uses. */
    res = 0;

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unknown signal name 'SIG%s'", sig_name);
    res = -1;
  }

  return res;
}

static int handle_subsystem_channel(struct ssh2_channel *chan,
    struct ssh2_packet *pkt, unsigned char **buf, uint32_t *buflen) {
  char *subsystem;

  subsystem = sftp_msg_read_string(pkt->pool, buf, buflen);

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "'subsystem' channel request for '%s' subsystem", subsystem);

  if (strncmp(subsystem, "sftp", 5) == 0) {

    if (sftp_services & SFTP_SERVICE_FL_SFTP) {
      chan->prepare = sftp_fxp_open_session;
      chan->postopen = NULL;
      chan->handle_packet = sftp_fxp_handle_packet;
      chan->finish = sftp_fxp_close_session;

    } else {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "'%s' subsystem denied by Protocols config", subsystem);
      return -1;
    }

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "subsystem '%s' unsupported", subsystem);
    return -1;
  }

  return 0;
}

static int handle_channel_req(struct ssh2_packet *pkt) {
  unsigned char *buf;
  char *channel_request;
  uint32_t buflen, channel_id;
  int res, unsupported = FALSE, want_reply;
  struct ssh2_channel *chan;
  cmd_rec *cmd;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  channel_id = sftp_msg_read_int(pkt->pool, &buf, &buflen);
  channel_request = sftp_msg_read_string(pkt->pool, &buf, &buflen);
  want_reply = sftp_msg_read_bool(pkt->pool, &buf, &buflen);

  pr_trace_msg(trace_channel, 7,
    "received '%s' request for channel ID %lu, want reply = %s",
    channel_request, (unsigned long) channel_id,
    want_reply ? "true" : "false");

  cmd = pr_cmd_alloc(pkt->pool, 2, pstrdup(pkt->pool, "CHANNEL_REQUEST"),
    pstrdup(pkt->pool, channel_request));
  cmd->arg = channel_request;
  cmd->cmd_class = CL_MISC|CL_SSH;

  chan = get_channel(channel_id);
  if (chan == NULL) {
    pr_trace_msg(trace_channel, 8, "unable to handle request for "
      "channel ID %lu: %s", (unsigned long) channel_id, strerror(errno));

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no open channel for remote channel ID %lu", (unsigned long) channel_id);
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
    return -1;
  }

  if (strncmp(channel_request, "subsystem", 10) == 0) {
    res = handle_subsystem_channel(chan, pkt, &buf, &buflen);

  } else if (strncmp(channel_request, "exec", 5) == 0) {
    res = handle_exec_channel(chan, pkt, &buf, &buflen);

  } else if (strncmp(channel_request, "env", 4) == 0) {
    res = handle_env_channel(chan, pkt, &buf, &buflen);

  } else if (strncmp(channel_request, "signal", 7) == 0) {
    res = handle_signal_channel(chan, pkt, &buf, &buflen);

  } else if (strncmp(channel_request, "break", 6) == 0) {
    uint32_t breaklen;

    /* Handle RFC4335 messages.  We will still return CHANNEL_FAILURE for
     * them, but at least we can log that we understood the request.
     */

    breaklen = sftp_msg_read_int(pkt->pool, &buf, &buflen);

    pr_trace_msg(trace_channel, 10,
      "received '%s' request for %lu millisecs, ignoring", channel_request,
      (unsigned long) breaklen);

    res = -1;

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unsupported '%s' channel requested, ignoring", channel_request);
    res = -1;
    unsupported = TRUE;
  }

  if (res == 0 &&
      chan->prepare) {
    if ((chan->prepare)(chan->local_channel_id) < 0) {
      int xerrno = errno;

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "unable to prepare channel ID %lu: %s",
        (unsigned long) chan->local_channel_id, strerror(xerrno));

      errno = xerrno;
      res = -1;
    }
  }

  if (want_reply) {
    struct ssh2_packet *pkt2;
    unsigned char *buf2, *ptr2;
    uint32_t buflen2, bufsz2;

    buflen2 = bufsz2 = 128;
    buf2 = ptr2 = palloc(pkt->pool, bufsz2);

    if (res < 0) {
      sftp_msg_write_byte(&buf2, &buflen2, SFTP_SSH2_MSG_CHANNEL_FAILURE);

    } else {
      sftp_msg_write_byte(&buf2, &buflen2, SFTP_SSH2_MSG_CHANNEL_SUCCESS);
    }

    sftp_msg_write_int(&buf2, &buflen2, chan->remote_channel_id);

    pkt2 = sftp_ssh2_packet_create(pkt->pool);
    pkt2->payload = ptr2;
    pkt2->payload_len = (bufsz2 - buflen2);

    if (sftp_ssh2_packet_write(sftp_conn->wfd, pkt2) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error sending reply to CHANNEL_REQUEST: %s", strerror(errno));
    }

    destroy_pool(pkt2->pool);
  }

  /* If the handler has a postopen callback, invoke that. */
  if (res == 0 &&
      chan->postopen) {
    int pres;

    pr_trace_msg(trace_channel, 18,
      "calling '%s' handler postopen callback", channel_request);

    pres = (chan->postopen)(chan->local_channel_id);
    if (pres < 0) {
      int xerrno = errno;

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "postopen error on channel ID %lu: %s",
        (unsigned long) chan->local_channel_id, strerror(xerrno));

    } else if (pres == 1) {
      /* Special case: if the postopen callback returns 1, the handler
       * is indicating that it has already handled the requests and requires
       * no further data from the client.
       *
       * This means that we can call send_channel_done() for this channel.
       */
      pr_trace_msg(trace_channel, 18,
        "sending CHANNEL_CLOSE for '%s', due to postopen return value",
        channel_request);
      send_channel_done(pkt->pool, chan->local_channel_id);
    }
  }

  /* Make a special case for failed, but unsupported, channel requests.
   * For these, we essentially treat them as "succeeded", but ignore them.
   * Clients like PuTTY send some strange requests, and there's no reason to
   * support such requests unnecessarily.
   */

  if (!unsupported &&
      res < 0) {
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
    return 0;
  }

  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  return 0;
}

static int handle_channel_window_adjust(struct ssh2_packet *pkt) {
  char adjust_str[32];
  unsigned char *buf;
  uint32_t buflen, channel_id, adjust_len, max_adjust_len;
  struct ssh2_channel *chan;
  cmd_rec *cmd;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  channel_id = sftp_msg_read_int(pkt->pool, &buf, &buflen);
  adjust_len = sftp_msg_read_int(pkt->pool, &buf, &buflen);

  memset(adjust_str, '\0', sizeof(adjust_str));
  pr_snprintf(adjust_str, sizeof(adjust_str)-1, "%lu %lu",
    (unsigned long) channel_id, (unsigned long) adjust_len);

  cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, "CHANNEL_WINDOW_ADJUST"));
  cmd->arg = pstrdup(pkt->pool, adjust_str);
  cmd->cmd_class = CL_MISC|CL_SSH;

  chan = get_channel(channel_id);
  if (chan == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no open channel for channel ID %lu", (unsigned long) channel_id);
    pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
    return -1;
  }

  /* As per RFC4254, Section 5.2, we MUST NOT allow the window size to be
   * increased above 2^32-1 bytes.
   *
   * To check this, we cannot simply add the given increment to our current
   * size; if the given increment is large, it could overflow our data
   * type.  So instead, we check whether the difference between the max
   * possible window size and the current window size is larger than the
   * given increment.  If not, we will only increment the window up to the
   * max possible window size.
   */
  max_adjust_len = SFTP_SSH2_CHANNEL_WINDOW_SIZE - chan->remote_windowsz;

  if (adjust_len > max_adjust_len) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "received WINDOW_ADJUST message whose window size adjustment (%lu bytes) "
      "exceeds max possible adjustment (%lu bytes), trimming",
      (unsigned long) adjust_len, (unsigned long) max_adjust_len);
    adjust_len = max_adjust_len;
  }

  pr_trace_msg(trace_channel, 15, "adjusting remote window size "
    "for local channel ID %lu, adding %lu bytes to current window size "
    "(%lu bytes)", (unsigned long) channel_id, (unsigned long) adjust_len,
    (unsigned long) chan->remote_windowsz);

  chan->remote_windowsz += adjust_len;

  drain_pending_channel_data(channel_id);

  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  return 0;
}

static int write_channel_open_confirm(struct ssh2_packet *pkt,
    uint32_t channel_id) {
  register unsigned int i;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;
  struct ssh2_channel *chan = NULL, **chans;

  chans = channel_list->elts;
  for (i = 0; i < channel_list->nelts; i++) {
    if (chans[i] != NULL &&
        chans[i]->remote_channel_id == channel_id) {
      chan = chans[i];
      break;
    }
  }

  if (chan == NULL) {
    pr_trace_msg(trace_channel, 8, "unable to confirm open channel ID %lu: %s",
      (unsigned long) channel_id, strerror(errno));

    return -1;
  }

  buflen = bufsz = 1024;
  ptr = buf = palloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION);
  sftp_msg_write_int(&buf, &buflen, chan->remote_channel_id);
  sftp_msg_write_int(&buf, &buflen, chan->local_channel_id);
  sftp_msg_write_int(&buf, &buflen, chan->local_windowsz);
  sftp_msg_write_int(&buf, &buflen, chan->local_max_packetsz);

  pr_trace_msg(trace_channel, 8, "confirm open channel remote ID %lu, "
    "local ID %lu: initial server window len = %lu bytes, server max "
    "packet size = %lu bytes", (unsigned long) chan->remote_channel_id,
    (unsigned long) chan->local_channel_id, (unsigned long)
    chan->local_windowsz, (unsigned long) chan->local_max_packetsz);

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  return 0;
}

static int write_channel_open_failed(struct ssh2_packet *pkt,
    uint32_t channel_id) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;

  buflen = bufsz = 1024;
  ptr = buf = palloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_CHANNEL_OPEN_FAILURE);
  sftp_msg_write_int(&buf, &buflen, channel_id);
  sftp_msg_write_int(&buf, &buflen,
    SFTP_SSH2_CHANNEL_OPEN_UNKNOWN_CHANNEL_TYPE);
  sftp_msg_write_string(&buf, &buflen, "Unsupported channel type requested");
  sftp_msg_write_string(&buf, &buflen, "en-US");

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  return 0;
}

uint32_t sftp_channel_get_windowsz(uint32_t channel_id) {
  struct ssh2_channel *chan;

  chan = get_channel(channel_id);
  if (chan == NULL) {
    pr_trace_msg(trace_channel, 1, "cannot return window size for unknown "
      "channel ID %lu", (unsigned long) channel_id);
    return 0;
  }

  return chan->remote_windowsz;
}

unsigned int sftp_channel_set_max_count(unsigned int max) {
  unsigned int prev_max;

  prev_max = channel_max;
  channel_max = max;

  return prev_max;
}

uint32_t sftp_channel_get_max_packetsz(void) {
  return chan_packet_size;
}

uint32_t sftp_channel_set_max_packetsz(uint32_t packetsz) {
  uint32_t prev_packetsz;

  prev_packetsz = chan_packet_size;
  chan_packet_size = packetsz;

  return prev_packetsz;
}

uint32_t sftp_channel_set_max_windowsz(uint32_t windowsz) {
  uint32_t prev_windowsz;

  prev_windowsz = chan_window_size;
  chan_window_size = windowsz;

  return prev_windowsz;
}

int sftp_channel_handle(struct ssh2_packet *pkt, char mesg_type) {
  int res;
  uint32_t channel_id;

  switch (mesg_type) {
    case SFTP_SSH2_MSG_CHANNEL_OPEN: {
      res = read_channel_open(pkt, &channel_id);
      if (res < 0) {
        struct ssh2_packet *pkt2;
        pkt2 = sftp_ssh2_packet_create(channel_pool);

        if (write_channel_open_failed(pkt2, channel_id) == 0) {
          (void) sftp_ssh2_packet_write(sftp_conn->wfd, pkt2);
        }

        destroy_pool(pkt2->pool);
        destroy_pool(pkt->pool);

        return -1;
      }

      destroy_pool(pkt->pool);

      pkt = sftp_ssh2_packet_create(channel_pool);
      res = write_channel_open_confirm(pkt, channel_id);
      if (res < 0) {
        destroy_pool(pkt->pool);
        return -1;
      }

      res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
      if (res < 0) {
        destroy_pool(pkt->pool);
        return -1;
      }

      destroy_pool(pkt->pool);
      return 0;
    }

    case SFTP_SSH2_MSG_CHANNEL_REQUEST:
      res = handle_channel_req(pkt);
      destroy_pool(pkt->pool);
      return res;

    case SFTP_SSH2_MSG_CHANNEL_CLOSE:
      res = handle_channel_close(pkt);
      destroy_pool(pkt->pool);
      return res;

    case SFTP_SSH2_MSG_CHANNEL_DATA:
      res = handle_channel_data(pkt, &channel_id);
      if (res == 1) {
        /* Send an EOF, since the channel has indicated it has finished
         * gracefully.
         */
        res = send_channel_done(pkt->pool, channel_id);
      }

      destroy_pool(pkt->pool);
      return res;

    case SFTP_SSH2_MSG_CHANNEL_EOF:
      res = handle_channel_eof(pkt);
      destroy_pool(pkt->pool);
      return res;

    case SFTP_SSH2_MSG_CHANNEL_WINDOW_ADJUST:
      res = handle_channel_window_adjust(pkt);
      destroy_pool(pkt->pool);
      return res;

    default:
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "expecting CHANNEL message, received %s (%d), disconnecting",
        sftp_ssh2_packet_get_mesg_type_desc(mesg_type), mesg_type);
      destroy_pool(pkt->pool);
      SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_PROTOCOL_ERROR, NULL);
  }

  errno = EINVAL;
  return -1;
}

int sftp_channel_free(void) {
  register unsigned int i;
  struct ssh2_channel **chans;

  if (channel_count == 0 ||
      channel_list == NULL) {
    return 0;
  }

  /* Iterate through all the open channels, destroying each one. */
  chans = channel_list->elts;
  for (i = 0; i < channel_list->nelts; i++) {
    if (chans[i] != NULL) {
      uint32_t pending_len;

      pending_len = get_channel_pending_size(chans[i]);
      pr_trace_msg(trace_channel, 15,
        "destroying unclosed channel ID %lu (%lu bytes pending)",
        (unsigned long) chans[i]->local_channel_id,
        (unsigned long) pending_len);

      if (chans[i]->finish != NULL) {
        (chans[i]->finish)(chans[i]->local_channel_id);
      }

      chans[i] = NULL;
      channel_count--;
    }
  }

  return 0;
}

int sftp_channel_init(void) {
  struct ssh2_channel_exec_handler *handler;
  config_rec *c;

  if (channel_pool == NULL) {
    channel_pool = make_sub_pool(sftp_pool);
    pr_pool_tag(channel_pool, "SSH2 Channel Pool");
  }

  if (channel_exec_handlers == NULL) {
    /* Initialize our list of 'exec' channel handlers. */
    channel_exec_handlers = make_array(channel_pool, 1,
      sizeof(struct ssh2_channel_exec_handler *));
  }

  /* Allocate the 'scp' handler */

  handler = pcalloc(channel_pool, sizeof(struct ssh2_channel_exec_handler));
  handler->m = &sftp_module;

  /* XXX In the future, we should be able to handle clients which request
   * something like "/usr/bin/scp", in addition to just "scp".
   */
  handler->command = pstrdup(channel_pool, "scp");
  handler->set_params = sftp_scp_set_params;
  handler->prepare = sftp_scp_open_session;
  handler->postopen = NULL;
  handler->handle_packet = sftp_scp_handle_packet;
  handler->finish = sftp_scp_close_session;

  *((struct ssh2_channel_exec_handler **) push_array(channel_exec_handlers)) =
    handler;

  /* Allocate the 'date' handler */

  handler = pcalloc(channel_pool, sizeof(struct ssh2_channel_exec_handler));
  handler->m = &sftp_module;

  /* XXX In the future, we should be able to handle clients which request
   * something like "/bin/date", in addition to just "date".
   */
  handler->command = pstrdup(channel_pool, "date");
  handler->set_params = sftp_date_set_params;
  handler->prepare = sftp_date_open_session;
  handler->postopen = sftp_date_postopen_session;
  handler->handle_packet = sftp_date_handle_packet;
  handler->finish = sftp_date_close_session;

  *((struct ssh2_channel_exec_handler **) push_array(channel_exec_handlers)) =
    handler;

  accepted_envs = make_array(channel_pool, 0, sizeof(char *));

  c = find_config(main_server->conf, CONF_PARAM, "SFTPAcceptEnv", FALSE);
  if (c) {
    while (c) {
      register unsigned int i;
      array_header *envs; 
      char **elts;

      pr_signals_handle();

      envs = c->argv[0];
      elts = envs->elts;
      for (i = 0; i < envs->nelts; i++) {
        *((char **) push_array(accepted_envs)) = pstrdup(channel_pool, elts[i]);
      }

      c = find_config_next(c, c->next, CONF_PARAM, "SFTPAcceptEnv", FALSE);
    }
   
  } else {
    /* Allow the LANG environment variable by default. */
    *((char **) push_array(accepted_envs)) = pstrdup(channel_pool, "LANG");
  }

  return 0;
}

int sftp_channel_drain_data(void) {
  register unsigned int i;
  struct ssh2_channel **chans;

  if (channel_list == NULL) {
    errno = EACCES;
    return -1;
  }

  /* Iterate through all the open channels, draining any pending data they
   * might have.
   */
  chans = channel_list->elts;
  for (i = 0; i < channel_list->nelts; i++) {
    if (chans[i] != NULL) {
      pr_trace_msg(trace_channel, 15, "draining pending data for local "
        "channel ID %lu", (unsigned long) chans[i]->local_channel_id);

      drain_pending_channel_data(chans[i]->local_channel_id);
    }
  }

  return 0;
}

static int channel_write_data(pool *p, uint32_t channel_id,
    unsigned char *buf, uint32_t buflen, char msg_type, uint32_t data_type) {
  struct ssh2_channel *chan;
  int res;

  chan = get_channel(channel_id);
  if (chan == NULL) {
    errno = EACCES;
    return -1;
  }

  /* We may need to send the given buffer in multiple CHANNEL_DATA packets,
   * for example of the remote window size is large but the remote max
   * packet size is small.  Hence the loop.
   */

  while (!(sftp_sess_state & SFTP_SESS_STATE_REKEYING) &&
         chan->remote_windowsz > 0 &&
         buflen > 0) {
    uint32_t payload_len;

    pr_signals_handle();

    /* First try to drain any pending data for this channel. */
    drain_pending_channel_data(channel_id);
    if (chan->remote_windowsz == 0)
      break;

    /* If the remote window size or remote max packet size changes the
     * length we can send, then payload_len is NOT the same as buflen.  Hence
     * the separate variable.
     */
    payload_len = buflen;

    /* The maximum size of the CHANNEL_DATA payload we can send to the client
     * is the smaller of the remote window size and the remote packet size.
     */ 

    if (payload_len > chan->remote_max_packetsz)
      payload_len = chan->remote_max_packetsz;

    if (payload_len > chan->remote_windowsz)
      payload_len = chan->remote_windowsz;

    if (payload_len > 0) {
      struct ssh2_packet *pkt;
      unsigned char *buf2, *ptr2;
      uint32_t bufsz2, buflen2;

      /* In addition to the data itself, we need to allocate room in the
       * outgoing packet for the type (1 byte), the channel ID (4 bytes),
       * a possible data type ID (4 bytes),  and for the data length (4 bytes).
       */
      bufsz2 = buflen2 = payload_len + 13;
 
      pkt = sftp_ssh2_packet_create(p);
      ptr2 = buf2 = palloc(pkt->pool, bufsz2);

      sftp_msg_write_byte(&buf2, &buflen2, msg_type);
      sftp_msg_write_int(&buf2, &buflen2, chan->remote_channel_id);

      if (data_type != 0) {
        /* Right now, this is only used for EXTENDED_DATA messages of type
         * STDERR.
         */
        sftp_msg_write_int(&buf2, &buflen2, data_type);
      }

      sftp_msg_write_int(&buf2, &buflen2, payload_len);
      memcpy(buf2, buf, payload_len);
      buflen2 -= payload_len;

      pkt->payload = ptr2;
      pkt->payload_len = (bufsz2 - buflen2);

      pr_trace_msg(trace_channel, 9, "sending %s (remote channel ID %lu, "
        "%lu data bytes)",
        msg_type == SFTP_SSH2_MSG_CHANNEL_DATA ? "CHANNEL_DATA" :
          "CHANNEL_EXTENDED_DATA", (unsigned long) chan->remote_channel_id,
        (unsigned long) payload_len);

      res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
      if (res == 0) {
        chan->remote_windowsz -= payload_len;

        pr_trace_msg(trace_channel, 11,
          "channel ID %lu remote window size currently at %lu bytes",
          (unsigned long) chan->remote_channel_id,
          (unsigned long) chan->remote_windowsz);
      }

      destroy_pool(pkt->pool);

      /* If that was the entire payload, we can be done now. */
      if (payload_len == buflen) {
        return res;
      }

      buf += payload_len;
      buflen -= payload_len;

      /* Otherwise try sending another packet.  If the window closes, the loop
       * will end.
       */

    } else {
      pr_trace_msg(trace_channel, 6, "allowed payload size of %lu bytes is too "
        "small for data (%lu bytes)", (unsigned long) payload_len,
        (unsigned long) buflen);

      /* For now, leave this case as is, and break out of the while loop. */
      break;
    }
  }

  /* We have to buffer up the remaining payload, and wait for a
   * CHANNEL_WINDOW_ADJUST from the client before we can send more.
   */

  if (buflen > 0) {
    struct ssh2_channel_databuf *db;
    const char *reason;

    db = get_databuf(channel_id, buflen);

    db->buflen = buflen;
    memcpy(db->buf, buf, buflen);

    /* Why are we buffering these bytes? */
    reason = "remote window size too small";
    if (sftp_sess_state & SFTP_SESS_STATE_REKEYING) {
      reason = "rekeying";
    }

    pr_trace_msg(trace_channel, 8, "buffering %lu remaining bytes of "
      "outgoing data (%s)", (unsigned long) buflen, reason);
  }

  return 0;
}

int sftp_channel_write_data(pool *p, uint32_t channel_id,
    unsigned char *buf, uint32_t buflen) {
  return channel_write_data(p, channel_id, buf, buflen,
    SFTP_SSH2_MSG_CHANNEL_DATA, 0);
}

int sftp_channel_write_ext_data_stderr(pool *p, uint32_t channel_id,
    unsigned char *buf, uint32_t buflen) {
  return channel_write_data(p, channel_id, buf, buflen,
    SFTP_SSH2_MSG_CHANNEL_EXTENDED_DATA,
    SFTP_SSH2_MSG_CHANNEL_EXTENDED_DATA_TYPE_STDERR);
}

/* Return the number of open channels, if any. */
unsigned int sftp_channel_opened(uint32_t *remote_channel_id) {
  register unsigned int i;
  struct ssh2_channel **chans;

  if (channel_count == 0 ||
      channel_list == NULL) {
    return 0;
  }

  if (channel_list == NULL) {
    errno = EACCES;
    return 0;
  }

  chans = channel_list->elts;
  for (i = 0; i < channel_list->nelts; i++) {
    if (chans[i] != NULL) {
      if (remote_channel_id != NULL) {
        *remote_channel_id = chans[i]->remote_channel_id;
      }
    }
  }

  return channel_count;
}

int sftp_channel_register_exec_handler(module *m, const char *command,
    int (*set_params)(pool *, uint32_t, array_header *),
    int (*prepare)(uint32_t),
    int (*postopen)(uint32_t),
    int (*handle_packet)(pool *, void *, uint32_t, unsigned char *, uint32_t),
    int (*finish)(uint32_t),
    int (**write_data)(pool *, uint32_t, unsigned char *, uint32_t)) {
  struct ssh2_channel_exec_handler *handler;

  if (m == NULL ||
      command == NULL ||
      set_params == NULL ||
      prepare == NULL ||
      handle_packet == NULL ||
      finish == NULL ||
      write_data == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (channel_pool == NULL) {
    channel_pool = make_sub_pool(sftp_pool);
    pr_pool_tag(channel_pool, "SSH2 Channel Pool");
  }

  if (channel_exec_handlers == NULL) {
    /* Initialize our list of 'exec' channel handlers. */
    channel_exec_handlers = make_array(channel_pool, 1,
      sizeof(struct ssh2_channel_exec_handler *));

  } else {
    register unsigned int i;
    struct ssh2_channel_exec_handler **handlers;

    /* Make sure that another handler for this command hasn't already been
     * registered.
     */
    handlers = channel_exec_handlers->elts;
    for (i = 0; i < channel_exec_handlers->nelts; i++) {
      handler = handlers[i];

      if (strcmp(handler->command, command) == 0) {
        errno = EEXIST;
        return -1;
      }
    }
  }

  handler = pcalloc(channel_pool, sizeof(struct ssh2_channel_exec_handler));

  handler->m = m;
  handler->command = pstrdup(channel_pool, command);
  handler->set_params = set_params;
  handler->prepare = prepare;
  handler->postopen = postopen;
  handler->handle_packet = handle_packet;
  handler->finish = finish;

  *((struct ssh2_channel_exec_handler **) push_array(channel_exec_handlers)) =
    handler;

  /* Send back to the caller, via the value-result argument, the address
   * of the function which the caller can use for writing data back to
   * the SSH2 channel.  This pointer trickery means that we don't have to
   * expose the sftp_channel_write_data() function via the public mod_sftp.h
   * header file.
   */

  *write_data = sftp_channel_write_data;

  return 0;
}
