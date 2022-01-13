/*
 * ProFTPD - mod_sftp packet IO
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
#include "packet.h"
#include "msg.h"
#include "disconnect.h"
#include "cipher.h"
#include "mac.h"
#include "compress.h"
#include "kex.h"
#include "service.h"
#include "auth.h"
#include "channel.h"
#include "tap.h"

#define SFTP_PACKET_IO_RD	5
#define SFTP_PACKET_IO_WR	7

extern pr_response_t *resp_list, *resp_err_list;

extern module sftp_module;

static uint32_t packet_client_seqno = 0;
static uint32_t packet_server_seqno = 0;

/* Maximum length of the payload data of an SSH2 packet we're willing to
 * accept.  Any packets reporting a payload length longer than this will be
 * ignored/dropped.
 */
#define SFTP_PACKET_MAX_PAYLOAD_LEN	(256 * 1024)

/* RFC4344 recommends 2^31 for the client packet sequence number at which
 * we should request a rekey, and 2^32 for the server packet sequence number.
 *
 * However, the uint32_t data type may not be unsigned for some
 * platforms/compilers.  To avoid issues on these platforms, use 2^31-1
 * for rekeying for both client and server packet sequence numbers.
 */
#define SFTP_PACKET_CLIENT_REKEY_SEQNO_LIMIT		2147483647
#define SFTP_PACKET_SERVER_REKEY_SEQNO_LIMIT		2147483647

static uint32_t rekey_client_seqno = SFTP_PACKET_CLIENT_REKEY_SEQNO_LIMIT;
static uint32_t rekey_server_seqno = SFTP_PACKET_SERVER_REKEY_SEQNO_LIMIT;

static off_t rekey_client_len = 0;
static off_t rekey_server_len = 0;
static off_t rekey_size = 0;

static int poll_timeout = -1;
static time_t last_recvd, last_sent;

static const char *server_version = SFTP_ID_DEFAULT_STRING;
static const char *version_id = SFTP_ID_DEFAULT_STRING "\r\n";
static int sent_version_id = FALSE;

static void is_client_alive(void);

/* Count of the number of "client alive" messages sent without a response. */
static unsigned int client_alive_max = 0, client_alive_count = 0;
static unsigned int client_alive_interval = 0;

static const char *trace_channel = "ssh2";
static const char *timing_channel = "timing";

#define MAX_POLL_TIMEOUTS	3

static int packet_poll(int sockfd, int io) {
  fd_set rfds, wfds;
  struct timeval tv;
  int res, timeout, using_client_alive = FALSE;
  unsigned int ntimeouts = 0;

  if (poll_timeout == -1) {
    /* If we have "client alive" timeout interval configured, use that --
     * but only if we have already done the key exchange, and are not
     * rekeying.
     *
     * Otherwise, we use the default (i.e. TimeoutIdle).
     */

    if (client_alive_interval > 0 &&
        (!(sftp_sess_state & SFTP_SESS_STATE_REKEYING) && 
         (sftp_sess_state & SFTP_SESS_STATE_HAVE_AUTH))) {
      timeout = client_alive_interval;
      using_client_alive = TRUE;

    } else {
      timeout = pr_data_get_timeout(PR_DATA_TIMEOUT_IDLE);
    }

  } else {
    timeout = poll_timeout;
  }

  tv.tv_sec = timeout;
  tv.tv_usec = 0;

  pr_trace_msg(trace_channel, 19,
    "waiting for max of %lu secs while polling socket %d for %s "
    "using select(2)", (unsigned long) tv.tv_sec, sockfd,
    io == SFTP_PACKET_IO_RD ? "reading" : "writing");

  while (1) {
    pr_signals_handle();

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    switch (io) {
      case SFTP_PACKET_IO_RD: {
        FD_SET(sockfd, &rfds);
        res = select(sockfd + 1, &rfds, NULL, NULL, &tv);
        break;
      }

      case SFTP_PACKET_IO_WR: {
        FD_SET(sockfd, &wfds);
        res = select(sockfd + 1, NULL, &wfds, NULL, &tv);
        break;
      }

      default:
        errno = EINVAL;
        return -1;
    }

    if (res < 0) {
      int xerrno = errno;

      if (xerrno == EINTR) {
        pr_signals_handle();
        continue;
      }

      pr_trace_msg(trace_channel, 18, "error calling select(2) on fd %d: %s",
        sockfd, strerror(xerrno));

      errno = xerrno;
      return -1;

    } else if (res == 0) {
      tv.tv_sec = timeout;
      tv.tv_usec = 0;

      ntimeouts++;

      if (ntimeouts > MAX_POLL_TIMEOUTS) {
        pr_trace_msg(trace_channel, 18,
          "polling on socket %d timed out after %lu sec, failing", sockfd,
          (unsigned long) tv.tv_sec);
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "polling on socket %d timed out after %lu sec, failing", sockfd,
          (unsigned long) tv.tv_sec);
        errno = ETIMEDOUT;
        return -1;
      }

      if (using_client_alive) {
        is_client_alive();

      } else {
        pr_trace_msg(trace_channel, 18,
          "polling on socket %d timed out after %lu sec, trying again "
          "(timeout #%u)", sockfd, (unsigned long) tv.tv_sec, ntimeouts);
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "polling on socket %d timed out after %lu sec, trying again "
          "(timeout #%u)", sockfd, (unsigned long) tv.tv_sec, ntimeouts);
      }

      continue;
    }

    break;
  }

  return 0;
}

/* The purpose of sock_read() is to loop until either we have read in the
 * requested reqlen from the socket, or the socket gives us an I/O error.
 * We want to prevent short reads from causing problems elsewhere (e.g.
 * in the decipher or MAC code).
 *
 * It is the caller's responsibility to ensure that buf is large enough to
 * hold reqlen bytes.
 */
int sftp_ssh2_packet_sock_read(int sockfd, void *buf, size_t reqlen,
    int flags) {
  void *ptr;
  size_t remainlen;

  if (reqlen == 0) {
    return 0;
  }

  errno = 0;

  ptr = buf;
  remainlen = reqlen;

  while (remainlen > 0) {
    int res;

    if (packet_poll(sockfd, SFTP_PACKET_IO_RD) < 0) {
      return -1;
    }

    /* The socket we accept is blocking, thus there's no need to handle
     * EAGAIN/EWOULDBLOCK errors.
     */
    res = read(sockfd, ptr, remainlen);
    while (res <= 0) {
      if (res < 0) {
        int xerrno = errno;

        if (xerrno == EINTR) {
          pr_signals_handle();
          res = read(sockfd, ptr, remainlen);
          continue;
        }

        pr_trace_msg(trace_channel, 16,
          "error reading from client (fd %d): %s", sockfd, strerror(xerrno));
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error reading from client (fd %d): %s", sockfd, strerror(xerrno));

        errno = xerrno;

        /* We explicitly disconnect the client here, rather than sending
         * a DISCONNECT message, because the errors below all indicate
         * a problem with the TCP connection, such that trying to write
         * more data on that connection would cause problems.
         */
        if (errno == ECONNRESET ||
            errno == ECONNABORTED ||
#ifdef ETIMEDOUT
            errno == ETIMEDOUT ||
#endif /* ETIMEDOUT */
#ifdef ENOTCONN
            errno == ENOTCONN ||
#endif /* ENOTCONN */
#ifdef ESHUTDOWN
            errno == ESHUTDOWN ||
#endif /* ESHUTDOWNN */
            errno == EPIPE) {
          xerrno = errno;

          pr_trace_msg(trace_channel, 16,
            "disconnecting client (%s)", strerror(xerrno));
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "disconnecting client (%s)", strerror(xerrno));
          pr_session_disconnect(&sftp_module, PR_SESS_DISCONNECT_CLIENT_EOF,
            strerror(xerrno));
        }

        return -1;

      } else {
        /* If we read zero bytes here, treat it as an EOF and hang up on
         * the uncommunicative client.
         */

        pr_trace_msg(trace_channel, 16, "%s",
          "disconnecting client (received EOF)");
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "disconnecting client (received EOF)");
        pr_session_disconnect(&sftp_module, PR_SESS_DISCONNECT_CLIENT_EOF,
          NULL);
      }
    }

    /* Generate an event for any interested listeners.  Since the data are
     * probably encrypted and such, and since listeners won't/shouldn't
     * have the facilities for handling such data, we only pass the
     * amount of data read in.
     */
    pr_event_generate("ssh2.netio-read", &res);

    session.total_raw_in += reqlen;
    time(&last_recvd);

    if ((size_t) res == remainlen) {
      break;
    }

    if (flags & SFTP_PACKET_READ_FL_PESSIMISTIC) {
      pr_trace_msg(trace_channel, 20, "read %lu bytes, expected %lu bytes; "
        "pessimistically returning", (unsigned long) res,
        (unsigned long) remainlen);
      break;
    }

    pr_trace_msg(trace_channel, 20, "read %lu bytes, expected %lu bytes; "
      "reading more", (unsigned long) res, (unsigned long) remainlen);
    ptr = ((char *) ptr + res);
    remainlen -= res;
  }

  return reqlen;
}

static char peek_mesg_type(struct ssh2_packet *pkt) {
  char mesg_type;

  memmove(&mesg_type, pkt->payload, sizeof(char));
  return mesg_type;
}

static void handle_global_request_mesg(struct ssh2_packet *pkt) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;
  char *request_name;
  int want_reply;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  request_name = sftp_msg_read_string(pkt->pool, &buf, &buflen);
  want_reply = sftp_msg_read_bool(pkt->pool, &buf, &buflen);

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "client sent GLOBAL_REQUEST for '%s', denying", request_name);

  if (want_reply) {
    struct ssh2_packet *pkt2;
    int res;

    buflen = bufsz = 1024;
    ptr = buf = palloc(pkt->pool, bufsz);

    sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_REQUEST_FAILURE);

    pkt2 = sftp_ssh2_packet_create(pkt->pool);
    pkt2->payload = ptr;
    pkt2->payload_len = (bufsz - buflen);

    res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt2);
    if (res < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error writing REQUEST_FAILURE message: %s", strerror(errno));
    }
  }

  destroy_pool(pkt->pool);
}

static void handle_client_alive_mesg(struct ssh2_packet *pkt, char mesg_type) {
  const char *mesg_desc;

  mesg_desc = sftp_ssh2_packet_get_mesg_type_desc(mesg_type);

  pr_trace_msg(trace_channel, 12,
    "client sent %s message, considering client alive", mesg_desc);

  client_alive_count = 0;
  destroy_pool(pkt->pool);
}

static void is_client_alive(void) {
  unsigned int count;
  unsigned char *buf, *ptr;
  uint32_t bufsz, buflen, channel_id;
  struct ssh2_packet *pkt;
  pool *tmp_pool;

  if (++client_alive_count > client_alive_max) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "SFTPClientAlive threshold (max %u checks, %u sec interval) reached, "
      "disconnecting client", client_alive_max, client_alive_interval);    

    /* XXX Generate an event for this? */

    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_BY_APPLICATION,
      "client alive threshold reached");
  }

  /* If we have any opened channels, send a CHANNEL_REQUEST to one of
   * them.  Otherwise, send a GLOBAL_REQUEST.
   */

  tmp_pool = make_sub_pool(session.pool);

  bufsz = buflen = 64;
  ptr = buf = palloc(tmp_pool, bufsz);

  count = sftp_channel_opened(&channel_id);  
  if (count > 0) {
    sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_CHANNEL_REQUEST);
    sftp_msg_write_int(&buf, &buflen, channel_id);

    pr_trace_msg(trace_channel, 9,
      "sending CHANNEL_REQUEST (remote channel ID %lu, keepalive@proftpd.org)",
      (unsigned long) channel_id);

  } else {
    sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_GLOBAL_REQUEST);

    pr_trace_msg(trace_channel, 9,
      "sending GLOBAL_REQUEST (keepalive@proftpd.org)");
  }

  sftp_msg_write_string(&buf, &buflen, "keepalive@proftpd.org");
  sftp_msg_write_bool(&buf, &buflen, TRUE);

  pkt = sftp_ssh2_packet_create(tmp_pool);
  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  (void) sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  destroy_pool(tmp_pool);
}

/* Attempt to read in a random amount of data (up to the maximum amount of
 * SSH2 packet data we support) from the socket.  This is used to help
 * mitigate the plaintext recovery attack described by CPNI-957037.
 *
 * Technically this is only necessary if a CBC mode cipher is in use, but
 * there should be no harm in using for any cipher; we are going to
 * disconnect the client after reading this data anyway.
 */
static void read_packet_discard(int sockfd) {
  char buf[SFTP_MAX_PACKET_LEN];
  size_t buflen;

  buflen = SFTP_MAX_PACKET_LEN -
    ((int) (SFTP_MAX_PACKET_LEN * (rand() / (RAND_MAX + 1.0))));

  pr_trace_msg(trace_channel, 3, "reading %lu bytes of data for discarding",
    (unsigned long) buflen);

  if (buflen > 0) {
    int flags = SFTP_PACKET_READ_FL_PESSIMISTIC;

    /* We don't necessarily want to wait for the entire random amount of data
     * to be read in.
     */
    sftp_ssh2_packet_sock_read(sockfd, buf, buflen, flags);
  }

  return;
}

static int read_packet_len(int sockfd, struct ssh2_packet *pkt,
    unsigned char *buf, size_t *offset, size_t *buflen, size_t bufsz) {
  uint32_t packet_len = 0, len = 0;
  size_t blocksz; 
  int res;
  unsigned char *ptr = NULL;

  blocksz = sftp_cipher_get_block_size();

  /* Since the packet length may be encrypted, we need to read in the first
   * cipher_block_size bytes from the socket, and try to decrypt them, to know
   * how many more bytes there are in the packet.
   */

  res = sftp_ssh2_packet_sock_read(sockfd, buf, blocksz, 0);
  if (res < 0)
    return res;

  len = res;
  if (sftp_cipher_read_data(pkt->pool, buf, blocksz, &ptr, &len) < 0) {
    return -1;
  }

  memmove(&packet_len, ptr, sizeof(uint32_t));
  pkt->packet_len = ntohl(packet_len);

  ptr += sizeof(uint32_t);
  len -= sizeof(uint32_t);

  /* Copy the remaining unencrypted bytes from the block into the given
   * buffer.
   */
  if (len > 0) {
    memmove(buf, ptr, len);
    *buflen = (size_t) len;
  }

  *offset = 0;
  return 0;
}

static int read_packet_padding_len(int sockfd, struct ssh2_packet *pkt,
    unsigned char *buf, size_t *offset, size_t *buflen, size_t bufsz) {

  if (*buflen > sizeof(char)) {
    /* XXX Assume the data in the buffer is unencrypted, and thus usable. */
    memmove(&pkt->padding_len, buf + *offset, sizeof(char));

    /* Advance the buffer past the byte we just read off. */
    *offset += sizeof(char);
    *buflen -= sizeof(char);

    return 0;
  }

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "unable to read padding len: not enough data in buffer (%u bytes)",
    (unsigned int) *buflen);
  return -1;
}

static int read_packet_payload(int sockfd, struct ssh2_packet *pkt,
    unsigned char *buf, size_t *offset, size_t *buflen, size_t bufsz) {
  unsigned char *ptr = NULL;
  int res;
  uint32_t payload_len = pkt->payload_len, padding_len = pkt->padding_len,
    data_len, len = 0;

  if (payload_len + padding_len == 0)
    return 0;

  if (payload_len > 0) {
    /* We don't want to reject the packet outright yet; but we can ignore
     * the payload data we're going to read in.  This packet will fail
     * eventually anyway.
     */
    if (payload_len > SFTP_PACKET_MAX_PAYLOAD_LEN) {
      pr_trace_msg(trace_channel, 20,
        "payload len (%lu bytes) exceeds max payload len (%lu), "
        "ignoring payload", (unsigned long) payload_len,
        (unsigned long) SFTP_PACKET_MAX_PAYLOAD_LEN);

      pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "client sent buggy/malicious packet payload length, ignoring");

      errno = EPERM;
      return -1;
    }

    pkt->payload = pcalloc(pkt->pool, payload_len);
  }

  /* If there's data in the buffer we received, it's probably already part
   * of the payload, unencrypted.  That will leave the remaining payload
   * data, if any, to be read in and decrypted.
   */
  if (*buflen > 0) {
    if (*buflen < payload_len) {
      memmove(pkt->payload, buf + *offset, *buflen);

      payload_len -= *buflen;
      *offset = 0;
      *buflen = 0;

    } else {
      /* There's enough already for the payload length.  Nice. */
      memmove(pkt->payload, buf + *offset, payload_len);

      *offset += payload_len;
      *buflen -= payload_len;
      payload_len = 0;
    }
  }

  /* The padding length is required to be greater than zero. */
  pkt->padding = pcalloc(pkt->pool, padding_len);

  /* If there's data in the buffer we received, it's probably already part
   * of the padding, unencrypted.  That will leave the remaining padding
   * data, if any, to be read in and decrypted.
   */
  if (*buflen > 0) {
    if (*buflen < padding_len) {
      memmove(pkt->padding, buf + *offset, *buflen);

      padding_len -= *buflen;
      *offset = 0;
      *buflen = 0;

    } else {
      /* There's enough already for the padding length.  Nice. */
      memmove(pkt->padding, buf + *offset, padding_len);

      *offset += padding_len;
      *buflen -= padding_len;
      padding_len = 0;
    }
  }

  data_len = payload_len + padding_len;
  if (data_len == 0)
    return 0;

  if (data_len > bufsz) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "remaining packet data (%lu bytes) exceeds packet buffer size (%lu "
      "bytes)", (unsigned long) data_len, (unsigned long) bufsz);
    errno = EPERM;
    return -1;
  }

  res = sftp_ssh2_packet_sock_read(sockfd, buf + *offset, data_len, 0);
  if (res < 0) {
    return res;
  }
 
  len = res;
  if (sftp_cipher_read_data(pkt->pool, buf + *offset, data_len, &ptr,
      &len) < 0) {
    return -1;
  }

  if (payload_len > 0) {
    memmove(pkt->payload + (pkt->payload_len - payload_len), ptr,
      payload_len);
  }

  memmove(pkt->padding + (pkt->padding_len - padding_len), ptr + payload_len,
    padding_len);
  return 0;
}

static int read_packet_mac(int sockfd, struct ssh2_packet *pkt,
    unsigned char *buf) {
  int res;
  uint32_t mac_len = pkt->mac_len;

  if (mac_len == 0)
    return 0;

  res = sftp_ssh2_packet_sock_read(sockfd, buf, mac_len, 0);
  if (res < 0)
    return res;

  pkt->mac = palloc(pkt->pool, pkt->mac_len);
  memmove(pkt->mac, buf, res);

  return 0;
}

struct ssh2_packet *sftp_ssh2_packet_create(pool *p) {
  pool *tmp_pool;
  struct ssh2_packet *pkt;

  tmp_pool = make_sub_pool(p);
  pr_pool_tag(tmp_pool, "SSH2 packet pool");

  pkt = pcalloc(tmp_pool, sizeof(struct ssh2_packet));
  pkt->pool = tmp_pool;
  pkt->packet_len = 0;
  pkt->payload = NULL;
  pkt->payload_len = 0;
  pkt->padding_len = 0;

  return pkt;
}

int sftp_ssh2_packet_get_last_recvd(time_t *tp) {
  if (tp == NULL) {
    errno = EINVAL;
    return -1;
  }

  memmove(tp, &last_recvd, sizeof(time_t));
  return 0;
}

int sftp_ssh2_packet_get_last_sent(time_t *tp) {
  if (tp == NULL) {
    errno = EINVAL;
    return -1;
  }

  memmove(tp, &last_sent, sizeof(time_t));
  return 0;
}

char sftp_ssh2_packet_get_mesg_type(struct ssh2_packet *pkt) {
  char mesg_type;

  memmove(&mesg_type, pkt->payload, sizeof(char));
  pkt->payload += sizeof(char);
  pkt->payload_len -= sizeof(char);

  return mesg_type;
}

const char *sftp_ssh2_packet_get_mesg_type_desc(unsigned char mesg_type) {
  switch (mesg_type) {
    case SFTP_SSH2_MSG_DISCONNECT:
      return "SSH_MSG_DISCONNECT";

    case SFTP_SSH2_MSG_IGNORE:
      return "SSH_MSG_IGNORE";

    case SFTP_SSH2_MSG_UNIMPLEMENTED:
      return "SSH_MSG_UNIMPLEMENTED";

    case SFTP_SSH2_MSG_DEBUG:
      return "SSH_MSG_DEBUG";

    case SFTP_SSH2_MSG_SERVICE_REQUEST:
      return "SSH_MSG_SERVICE_REQUEST";

    case SFTP_SSH2_MSG_SERVICE_ACCEPT:
      return "SSH_MSG_SERVICE_ACCEPT";

    case SFTP_SSH2_MSG_KEXINIT:
      return "SSH_MSG_KEXINIT";

    case SFTP_SSH2_MSG_NEWKEYS:
      return "SSH_MSG_NEWKEYS";

    case SFTP_SSH2_MSG_KEX_DH_INIT:
      return "SSH_MSG_KEX_DH_INIT";

    case SFTP_SSH2_MSG_KEX_DH_REPLY:
      return "SSH_MSG_KEX_DH_REPLY";

    case SFTP_SSH2_MSG_KEX_DH_GEX_INIT:
      return "SSH_MSG_KEX_DH_GEX_INIT";

    case SFTP_SSH2_MSG_KEX_DH_GEX_REPLY:
      return "SSH_MSG_KEX_DH_GEX_REPLY";

    case SFTP_SSH2_MSG_KEX_DH_GEX_REQUEST:
      return "SSH_MSG_KEX_DH_GEX_REQUEST";

    case SFTP_SSH2_MSG_USER_AUTH_REQUEST:
      return "SSH_MSG_USER_AUTH_REQUEST";

    case SFTP_SSH2_MSG_USER_AUTH_FAILURE:
      return "SSH_MSG_USER_AUTH_FAILURE";

    case SFTP_SSH2_MSG_USER_AUTH_SUCCESS:
      return "SSH_MSG_USER_AUTH_SUCCESS";

    case SFTP_SSH2_MSG_USER_AUTH_BANNER:
      return "SSH_MSG_USER_AUTH_BANNER";

    case SFTP_SSH2_MSG_USER_AUTH_PASSWD:
      return "SSH_MSG_USER_AUTH_PASSWD";

    case SFTP_SSH2_MSG_USER_AUTH_INFO_RESP:
      return "SSH_MSG_USER_AUTH_INFO_RESP";

    case SFTP_SSH2_MSG_GLOBAL_REQUEST:
      return "SSH_MSG_GLOBAL_REQUEST";

    case SFTP_SSH2_MSG_REQUEST_SUCCESS:
      return "SSH_MSG_REQUEST_SUCCESS";

    case SFTP_SSH2_MSG_REQUEST_FAILURE:
      return "SSH_MSG_REQUEST_FAILURE";

    case SFTP_SSH2_MSG_CHANNEL_OPEN:
      return "SSH_MSG_CHANNEL_OPEN";

    case SFTP_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
      return "SSH_MSG_CHANNEL_OPEN_CONFIRMATION";

    case SFTP_SSH2_MSG_CHANNEL_OPEN_FAILURE:
      return "SSH_MSG_CHANNEL_OPEN_FAILURE";

    case SFTP_SSH2_MSG_CHANNEL_WINDOW_ADJUST:
      return "SSH_MSG_CHANNEL_WINDOW_ADJUST";

    case SFTP_SSH2_MSG_CHANNEL_DATA:
      return "SSH_MSG_CHANNEL_DATA";

    case SFTP_SSH2_MSG_CHANNEL_EXTENDED_DATA:
      return "SSH_MSG_CHANNEL_EXTENDED_DATA";

    case SFTP_SSH2_MSG_CHANNEL_EOF:
      return "SSH_MSG_CHANNEL_EOF";

    case SFTP_SSH2_MSG_CHANNEL_CLOSE:
      return "SSH_MSG_CHANNEL_CLOSE";

    case SFTP_SSH2_MSG_CHANNEL_REQUEST:
      return "SSH_MSG_CHANNEL_REQUEST";

    case SFTP_SSH2_MSG_CHANNEL_SUCCESS:
      return "SSH_MSG_CHANNEL_SUCCESS";

    case SFTP_SSH2_MSG_CHANNEL_FAILURE:
      return "SSH_MSG_CHANNEL_FAILURE";
  }

  return "(unknown)";
}

int sftp_ssh2_packet_set_poll_timeout(int timeout) {
  if (timeout <= 0) {
    poll_timeout = -1;

  } else {
    poll_timeout = timeout;
  }

  return 0;
}

int sftp_ssh2_packet_set_client_alive(unsigned int max, unsigned int interval) {
  client_alive_max = max;
  client_alive_interval = interval;
  return 0;
}

int sftp_ssh2_packet_read(int sockfd, struct ssh2_packet *pkt) {
  unsigned char buf[SFTP_MAX_PACKET_LEN];
  size_t buflen, bufsz = SFTP_MAX_PACKET_LEN, offset = 0;

  pr_session_set_idle();

  while (1) {
    uint32_t req_blocksz;
    int res;

    pr_signals_handle();

    /* This is in a while loop in order to consume any debug/ignore
     * messages which the client may send.
     */

    buflen = 0;
    memset(buf, 0, sizeof(buf));

    if (read_packet_len(sockfd, pkt, buf, &offset, &buflen, bufsz) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "no data to be read from socket %d", sockfd);
      return -1;
    }

    pr_trace_msg(trace_channel, 20, "SSH2 packet len = %lu bytes",
      (unsigned long) pkt->packet_len);

    /* In order to mitigate the plaintext recovery attack described in
     * CPNI-957037:
     *
     *  http://www.cpni.gov.uk/Docs/Vulnerability_Advisory_SSH.txt
     *
     * we do NOT check that the packet length is sane here; we have to
     * wait until the MAC check succeeds.
     */
 
    /* Note: Checking for the RFC4253-recommended minimum packet length
     * of 16 bytes causes KEX to fail (the NEWKEYS packet is 12 bytes).
     * Thus that particular check is omitted.
     */

    if (read_packet_padding_len(sockfd, pkt, buf, &offset, &buflen,
        bufsz) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "no data to be read from socket %d", sockfd);
      read_packet_discard(sockfd);
      return -1;
    }

    pr_trace_msg(trace_channel, 20, "SSH2 packet padding len = %u bytes",
      (unsigned int) pkt->padding_len);

    pkt->payload_len = (pkt->packet_len - pkt->padding_len - 1);

    pr_trace_msg(trace_channel, 20, "SSH2 packet payload len = %lu bytes",
      (unsigned long) pkt->payload_len);

    /* Read both payload and padding, since we may need to have both before
     * decrypting the data.
     */
    if (read_packet_payload(sockfd, pkt, buf, &offset, &buflen, bufsz) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "unable to read payload from socket %d", sockfd);
      read_packet_discard(sockfd);
      return -1;
    }

    memset(buf, 0, sizeof(buf));
    pkt->mac_len = sftp_mac_get_block_size();

    pr_trace_msg(trace_channel, 20, "SSH2 packet MAC len = %lu bytes",
      (unsigned long) pkt->mac_len);

    if (read_packet_mac(sockfd, pkt, buf) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "unable to read MAC from socket %d", sockfd);
      read_packet_discard(sockfd);
      return -1;
    }

    pkt->seqno = packet_client_seqno;
    if (sftp_mac_read_data(pkt) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "unable to verify MAC on packet from socket %d", sockfd);

      /* In order to further mitigate CPNI-957037, we will read in a
       * random amount of more data from the network before closing
       * the connection.
       */
      read_packet_discard(sockfd);
      return -1;
    }

    /* Now that the MAC check has passed, we can do sanity checks based
     * on the fields we have read in, and trust that those fields are
     * correct.
     */

    if (pkt->packet_len < 5) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "packet length too short (%lu), less than minimum packet length (5)",
        (unsigned long) pkt->packet_len);
      read_packet_discard(sockfd);
      return -1;
    }

    if (pkt->packet_len > SFTP_MAX_PACKET_LEN) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "packet length too long (%lu), exceeds maximum packet length (%lu)",
        (unsigned long) pkt->packet_len, (unsigned long) SFTP_MAX_PACKET_LEN);
      read_packet_discard(sockfd);
      return -1;
    }

    /* Per Section 6 of RFC4253, the minimum padding length is 4, the
     * maximum padding length is 255.
     */

    if (pkt->padding_len < SFTP_MIN_PADDING_LEN) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "padding length too short (%u), less than minimum padding length (%u)",
        (unsigned int) pkt->padding_len, (unsigned int) SFTP_MIN_PADDING_LEN);
      read_packet_discard(sockfd);
      return -1;
    }

    if (pkt->padding_len > pkt->packet_len) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "padding length too long (%u), exceeds packet length (%lu)",
        (unsigned int) pkt->padding_len, (unsigned long) pkt->packet_len);
      read_packet_discard(sockfd);
      return -1;
    }

    /* From RFC4253, Section 6:
     *
     * random padding
     *   Arbitrary-length padding, such that the total length of
     *   (packet_length || padding_length || payload || random padding)
     *   is a multiple of the cipher block size or 8, whichever is
     *   larger.
     *
     * Thus packet_len + sizeof(uint32_t) (for the actual packet length field)
     * is that "(packet_length || padding_length || payload || padding)"
     * value.
     */

    req_blocksz = MAX(8, sftp_cipher_get_block_size());

    if ((pkt->packet_len + sizeof(uint32_t)) % req_blocksz != 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "packet length (%lu) not a multiple of the required block size (%lu)",
        (unsigned long) pkt->packet_len + sizeof(uint32_t),
        (unsigned long) req_blocksz);
      read_packet_discard(sockfd);
      return -1;
    }

    /* XXX I'm not so sure about this check; we SHOULD have a maximum
     * payload check, but using the max packet length check for the payload
     * length seems awkward.
     */
    if (pkt->payload_len > SFTP_MAX_PACKET_LEN) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "payload length too long (%lu), exceeds maximum payload length (%lu) "
        "(packet len %lu, padding len %u)", (unsigned long) pkt->payload_len,
        (unsigned long) SFTP_MAX_PACKET_LEN, (unsigned long) pkt->packet_len,
        (unsigned int) pkt->padding_len);
      read_packet_discard(sockfd);
      return -1;
    }

    /* Sanity checks passed; move on to the reading the packet payload. */
    if (sftp_compress_read_data(pkt) < 0) {
      return -1;
    }

    packet_client_seqno++;

    /* Handle the case where timers might be being processed at the
     * moment.
     */
    res = pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
    while (res < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
        res = pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
      }

      break;
    }

    break;
  }

  if (rekey_size > 0) {
    rekey_client_len += pkt->packet_len;

    if (rekey_client_len >= rekey_size) {
      pr_trace_msg(trace_channel, 17, "client packet bytes recvd (%" PR_LU
        ") reached rekey bytes limit (%" PR_LU "), requesting rekey",
        (pr_off_t) rekey_client_len, (pr_off_t) rekey_size);
      sftp_kex_rekey();
    }
  }

  if (rekey_client_seqno > 0 &&
      packet_client_seqno == rekey_client_seqno) {
    pr_trace_msg(trace_channel, 17, "client packet sequence number (%lu) "
      "reached rekey packet number %lu, requesting rekey",
      (unsigned long) packet_client_seqno, (unsigned long) rekey_client_seqno);
    sftp_kex_rekey();
  }

  return 0;
}

static int write_packet_padding(struct ssh2_packet *pkt) {
  register unsigned int i;
  uint32_t packet_len = 0;
  size_t blocksz;

  blocksz = sftp_cipher_get_block_size();

  /* RFC 4253, section 6, says that the random padding is calculated
   * as follows:
   *
   *  random padding
   *     Arbitrary-length padding, such that the total length of
   *     (packet_length || padding_length || payload || random padding)
   *     is a multiple of the cipher block size or 8, whichever is
   *     larger.  There MUST be at least four bytes of padding.  The
   *     padding SHOULD consist of random bytes.  The maximum amount of
   *     padding is 255 bytes.
   *
   * This means:
   *
   *  packet len = sizeof(packet_len field) + sizeof(padding_len field) +
   *    sizeof(payload field) + sizeof(padding field)
   */

  packet_len = sizeof(uint32_t) + sizeof(char) + pkt->payload_len;

  pkt->padding_len = (char) (blocksz - (packet_len % blocksz));
  if (pkt->padding_len < 4) {
    /* As per RFC, there must be at least 4 bytes of padding.  So if the
     * above calculated less, then we need to add another block's worth
     * of padding.
     */
    pkt->padding_len += blocksz;
  }

  pkt->padding = palloc(pkt->pool, pkt->padding_len);

  /* Fill the padding with pseudo-random data. */
  for (i = 0; i < pkt->padding_len; i++) {
    pkt->padding[i] = (unsigned char) pr_random_next(0, UCHAR_MAX);
  }

  return 0;
}

#define SFTP_SSH2_PACKET_IOVSZ		12
static struct iovec packet_iov[SFTP_SSH2_PACKET_IOVSZ];
static unsigned int packet_niov = 0;

int sftp_ssh2_packet_send(int sockfd, struct ssh2_packet *pkt) {
  unsigned char buf[SFTP_MAX_PACKET_LEN * 2], mesg_type;
  size_t buflen = 0, bufsz = SFTP_MAX_PACKET_LEN;
  uint32_t packet_len = 0;
  int res, write_len = 0, block_alarms = FALSE;

  /* No interruptions, please.  If, for example, we are interrupted here
   * by the SFTPRekey timer, that timer will cause this same function to
   * be called -- but the packet_iov/packet_niov values will be different.
   * Which in turn leads to malformed packets, and thus badness (Bug#4216).
   */

  if (sftp_sess_state & SFTP_SESS_STATE_HAVE_AUTH) {
    block_alarms = TRUE;
  }

  if (block_alarms == TRUE) {
    pr_alarms_block();
  }

  /* Clear the iovec array before sending the data, if possible. */
  if (packet_niov == 0) {
    memset(packet_iov, 0, sizeof(packet_iov));
  }

  mesg_type = peek_mesg_type(pkt);

  if (sftp_compress_write_data(pkt) < 0) {
    int xerrno = errno;

    if (block_alarms == TRUE) {
      pr_alarms_unblock();
    }
    errno = xerrno;
    return -1;
  }

  if (write_packet_padding(pkt) < 0) {
    int xerrno = errno;

    if (block_alarms == TRUE) {
      pr_alarms_unblock();
    }
    errno = xerrno;
    return -1;
  }

  /* Packet length: padding len + payload + padding */
  pkt->packet_len = packet_len = sizeof(char) + pkt->payload_len +
    pkt->padding_len;

  pkt->seqno = packet_server_seqno;

  if (sftp_mac_write_data(pkt) < 0) {
    int xerrno = errno;

    if (block_alarms == TRUE) {
      pr_alarms_unblock();
    }
    errno = xerrno;
    return -1;
  }

  memset(buf, 0, sizeof(buf));
  buflen = bufsz;

  if (sftp_cipher_write_data(pkt, buf, &buflen) < 0) {
    int xerrno = errno;

    if (block_alarms == TRUE) {
      pr_alarms_unblock();
    }
    errno = xerrno;
    return -1;
  }

  if (buflen > 0) {
    /* We have encrypted data, which means we don't need as many of the
     * iovec slots as for unencrypted data.
     */

    if (!sent_version_id) {
      packet_iov[packet_niov].iov_base = (void *) version_id;
      packet_iov[packet_niov].iov_len = strlen(version_id);
      write_len += packet_iov[packet_niov].iov_len;
      packet_niov++;
    }

    packet_iov[packet_niov].iov_base = (void *) buf;
    packet_iov[packet_niov].iov_len = buflen;
    write_len += packet_iov[packet_niov].iov_len;
    packet_niov++;

    if (pkt->mac_len > 0) {
      packet_iov[packet_niov].iov_base = (void *) pkt->mac;
      packet_iov[packet_niov].iov_len = pkt->mac_len;
      write_len += packet_iov[packet_niov].iov_len;
      packet_niov++;
    }

  } else {
    /* Don't forget to convert the packet len to network-byte order, since
     * this length is sent over the wire.
     */
    packet_len = htonl(packet_len);

    if (!sent_version_id) {
      packet_iov[packet_niov].iov_base = (void *) version_id;
      packet_iov[packet_niov].iov_len = strlen(version_id);
      write_len += packet_iov[packet_niov].iov_len;
      packet_niov++;
    }

    packet_iov[packet_niov].iov_base = (void *) &packet_len;
    packet_iov[packet_niov].iov_len = sizeof(uint32_t);
    write_len += packet_iov[packet_niov].iov_len;
    packet_niov++;

    packet_iov[packet_niov].iov_base = (void *) &(pkt->padding_len);
    packet_iov[packet_niov].iov_len = sizeof(char);
    write_len += packet_iov[packet_niov].iov_len;
    packet_niov++;

    packet_iov[packet_niov].iov_base = (void *) pkt->payload;
    packet_iov[packet_niov].iov_len = pkt->payload_len;
    write_len += packet_iov[packet_niov].iov_len;
    packet_niov++;

    packet_iov[packet_niov].iov_base = (void *) pkt->padding;
    packet_iov[packet_niov].iov_len = pkt->padding_len;
    write_len += packet_iov[packet_niov].iov_len;
    packet_niov++;

    if (pkt->mac_len > 0) {
      packet_iov[packet_niov].iov_base = (void *) pkt->mac;
      packet_iov[packet_niov].iov_len = pkt->mac_len;
      write_len += packet_iov[packet_niov].iov_len;
      packet_niov++;
    }
  }

  if (packet_poll(sockfd, SFTP_PACKET_IO_WR) < 0) {
    int xerrno = errno;

    /* Socket not writable?  Clear the array, and try again. */
    memset(packet_iov, 0, sizeof(packet_iov));
    packet_niov = 0;

    if (block_alarms == TRUE) {
      pr_alarms_unblock();
    }
    errno = xerrno;
    return -1;
  }

  /* Generate an event for any interested listeners.  Since the data are
   * probably encrypted and such, and since listeners won't/shouldn't
   * have the facilities for handling such data, we only pass the
   * amount of data to be written out.
   */
  pr_event_generate("ssh2.netio-write", &write_len);

  /* The socket we accept is blocking, thus there's no need to handle
   * EAGAIN/EWOULDBLOCK errors.
   */
  res = writev(sockfd, packet_iov, packet_niov);
  while (res < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();

      res = writev(sockfd, packet_iov, packet_niov);
      continue;
    }

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error writing packet (fd %d): %s", sockfd, strerror(xerrno));

    if (xerrno == ECONNRESET ||
        xerrno == ECONNABORTED ||
        xerrno == EPIPE) {

      if (block_alarms == TRUE) {
        pr_alarms_unblock();
      }

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "disconnecting client (%s)", strerror(xerrno));
      pr_session_disconnect(&sftp_module, PR_SESS_DISCONNECT_BY_APPLICATION,
        strerror(xerrno));
    }

    /* Always clear the iovec array after sending the data. */
    memset(packet_iov, 0, sizeof(packet_iov));
    packet_niov = 0;

    if (block_alarms == TRUE) {
      pr_alarms_unblock();
    }
    errno = xerrno;
    return -1;
  }

  session.total_raw_out += res;

  /* Always clear the iovec array after sending the data. */
  memset(packet_iov, 0, sizeof(packet_iov));
  packet_niov = 0;

  if (sent_version_id == FALSE) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "sent server version '%s'", server_version);
    sent_version_id = TRUE;
  }

  time(&last_sent);

  packet_server_seqno++;

  pr_trace_msg(trace_channel, 3, "sent %s (%d) packet (%d bytes)",
    sftp_ssh2_packet_get_mesg_type_desc(mesg_type), mesg_type, res);

  if (block_alarms == TRUE) {
    /* Now that we've written out the packet, we can be interrupted again. */
    pr_alarms_unblock();
  }

  if (rekey_size > 0) {
    rekey_server_len += pkt->packet_len;

    if (rekey_server_len >= rekey_size) {
      pr_trace_msg(trace_channel, 17, "server packet bytes sent (%" PR_LU
        ") reached rekey bytes limit (%" PR_LU "), requesting rekey",
        (pr_off_t) rekey_server_len, (pr_off_t) rekey_size);
      sftp_kex_rekey();
    }
  }

  if (rekey_server_seqno > 0 &&
      packet_server_seqno == rekey_server_seqno) {
    pr_trace_msg(trace_channel, 17, "server packet sequence number (%lu) "
      "reached rekey packet number %lu, requesting rekey",
      (unsigned long) packet_server_seqno, (unsigned long) rekey_server_seqno);
    sftp_kex_rekey();
  }

  return 0;
}

int sftp_ssh2_packet_write(int sockfd, struct ssh2_packet *pkt) {
  int res;

  /* For future reference, I tried buffering up the possible TAP message
   * and the given message using TCP_CORK/TCP_NOPUSH.  I tried this test
   * on a Mac OSX 10.5 box.  It was for this test that I refactored the
   * core pr_inet_* functions, creating pr_inet_set_proto_cork().
   *
   * Turned out to be a very bad idea.  Using sftp(1), the login process
   * itself was incredibly slow.  mod_sftp was behaving as if the
   * "uncorking" call was not causing any flushing of the partially-full
   * network buffer to be written out, and instead was waiting until the
   * buffer was full before writing it out.
   *
   * Now, this could be due to a bug in Mac OSX's handling of TCP_NOPUSH;
   * there are articles about such a problem in earlier Mac OSX versions.
   * I should try this test again, on a Linux (TCP_CORK) and FreeBSD
   * (TCP_NOPUSH), to see if this can be done at least on those platforms.
   */

  if (sent_version_id) {
    res = sftp_tap_send_packet();
    if (res < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error sending TAP packet: %s", strerror(errno));
    }
  }

  return sftp_ssh2_packet_send(sockfd, pkt);
}

void sftp_ssh2_packet_handle_debug(struct ssh2_packet *pkt) {
  register unsigned int i;
  char always_display;
  char *str;

  always_display = sftp_msg_read_bool(pkt->pool, &pkt->payload,
    &pkt->payload_len);
  str = sftp_msg_read_string(pkt->pool, &pkt->payload, &pkt->payload_len);

  /* Ignore the language tag. */
  (void) sftp_msg_read_string(pkt->pool, &pkt->payload, &pkt->payload_len);

  /* Sanity-check the message for control (and other non-printable)
   * characters.
   */
  for (i = 0; i < strlen(str); i++) {
    if (PR_ISCNTRL(str[i]) ||
        !PR_ISPRINT(str[i])) {
      str[i] = '?';
    }
  }

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "client sent SSH_MSG_DEBUG message '%s'", str);

  if (always_display) {
    pr_log_debug(DEBUG0, MOD_SFTP_VERSION
      ": client sent SSH_MSG_DEBUG message '%s'", str);
  }

  destroy_pool(pkt->pool);
}

void sftp_ssh2_packet_handle_disconnect(struct ssh2_packet *pkt) {
  register unsigned int i;
  char *explain = NULL, *lang = NULL;
  const char *reason_str = NULL;
  uint32_t reason_code;

  reason_code = sftp_msg_read_int(pkt->pool, &pkt->payload, &pkt->payload_len);
  reason_str = sftp_disconnect_get_str(reason_code);
  if (reason_str == NULL) {
    pr_trace_msg(trace_channel, 9,
      "client sent unknown disconnect reason code %lu",
      (unsigned long) reason_code);
    reason_str = "Unknown reason code";
  }

  explain = sftp_msg_read_string(pkt->pool, &pkt->payload, &pkt->payload_len);

  /* Not all clients send a language tag. */
  if (pkt->payload_len > 0) {
    lang = sftp_msg_read_string(pkt->pool, &pkt->payload, &pkt->payload_len);
  }

  /* Sanity-check the message for control characters. */
  for (i = 0; i < strlen(explain); i++) {
    if (PR_ISCNTRL(explain[i])) {
      explain[i] = '?';
    }
  }

  /* XXX Use the language tag somehow, if provided. */
  if (lang != NULL) {
    pr_trace_msg(trace_channel, 19, "client sent DISCONNECT language tag '%s'",
      lang);
  }

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "client at %s sent SSH_DISCONNECT message: %s (%s)",
    pr_netaddr_get_ipstr(session.c->remote_addr), explain, reason_str);
  pr_session_disconnect(&sftp_module, PR_SESS_DISCONNECT_CLIENT_QUIT, explain);
}

void sftp_ssh2_packet_handle_ignore(struct ssh2_packet *pkt) {
  char *str;
  size_t len;

  str = sftp_msg_read_string(pkt->pool, &pkt->payload, &pkt->payload_len);
  len = strlen(str);

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "client sent SSH_MSG_IGNORE message (%u bytes)", (unsigned int) len);

  destroy_pool(pkt->pool);
}

void sftp_ssh2_packet_handle_unimplemented(struct ssh2_packet *pkt) {
  uint32_t seqno;

  seqno = sftp_msg_read_int(pkt->pool, &pkt->payload, &pkt->payload_len);

  pr_trace_msg(trace_channel, 7, "received SSH_MSG_UNIMPLEMENTED for "
    "packet #%lu", (unsigned long) seqno);

  destroy_pool(pkt->pool);
}

int sftp_ssh2_packet_handle(void) {
  struct ssh2_packet *pkt;
  char mesg_type;
  int res;

  pkt = sftp_ssh2_packet_create(sftp_pool);

  res = sftp_ssh2_packet_read(sftp_conn->rfd, pkt);
  if (res < 0) {
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_BY_APPLICATION, NULL);
  }

  mesg_type = sftp_ssh2_packet_get_mesg_type(pkt);
  pr_trace_msg(trace_channel, 3, "received %s (%d) packet",
    sftp_ssh2_packet_get_mesg_type_desc(mesg_type), mesg_type);

  pr_response_clear(&resp_list);
  pr_response_clear(&resp_err_list);
  pr_response_set_pool(pkt->pool);

  /* Note: Some of the SSH messages will be handled regardless of the
   * sftp_sess_state flags; this is intentional, and is the way that
   * the protocol is supposed to work.
   */
  
  switch (mesg_type) {
    case SFTP_SSH2_MSG_DEBUG:
      sftp_ssh2_packet_handle_debug(pkt);
      break;

    case SFTP_SSH2_MSG_DISCONNECT:
      sftp_ssh2_packet_handle_disconnect(pkt);
      break;

    case SFTP_SSH2_MSG_GLOBAL_REQUEST:
      handle_global_request_mesg(pkt);
      break;

    case SFTP_SSH2_MSG_REQUEST_SUCCESS:
    case SFTP_SSH2_MSG_REQUEST_FAILURE:
    case SFTP_SSH2_MSG_CHANNEL_SUCCESS:
    case SFTP_SSH2_MSG_CHANNEL_FAILURE:
      handle_client_alive_mesg(pkt, mesg_type);
      break;

    case SFTP_SSH2_MSG_IGNORE:
      sftp_ssh2_packet_handle_ignore(pkt);
      break;

    case SFTP_SSH2_MSG_UNIMPLEMENTED:
      sftp_ssh2_packet_handle_unimplemented(pkt);
      break;

    case SFTP_SSH2_MSG_KEXINIT: {
      uint64_t start_ms;

      if (pr_trace_get_level(timing_channel) > 0) {
        pr_gettimeofday_millis(&start_ms);
      }

      /* The client might be initiating a rekey; watch for this. */
      if (!(sftp_sess_state & SFTP_SESS_STATE_HAVE_KEX)) {
        if (pr_trace_get_level(timing_channel)) {
          unsigned long elapsed_ms;
          uint64_t finish_ms;

          pr_gettimeofday_millis(&finish_ms);
          elapsed_ms = (unsigned long) (finish_ms - session.connect_time_ms);

          pr_trace_msg(timing_channel, 4,
            "Time before first SSH key exchange: %lu ms", elapsed_ms);
        }
      }
 
      sftp_sess_state |= SFTP_SESS_STATE_REKEYING;

      /* Clear any current "have KEX" state. */
      sftp_sess_state &= ~SFTP_SESS_STATE_HAVE_KEX;

      if (sftp_kex_handle(pkt) < 0) {
        pr_event_generate("mod_sftp.ssh2.kex.failed", NULL);
        SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_BY_APPLICATION, NULL);
      }

      sftp_sess_state |= SFTP_SESS_STATE_HAVE_KEX;

      if (pr_trace_get_level(timing_channel)) {
        unsigned long elapsed_ms;
        uint64_t finish_ms;

        pr_gettimeofday_millis(&finish_ms);
        elapsed_ms = (unsigned long) (finish_ms - start_ms);

        pr_trace_msg(timing_channel, 4,
          "SSH key exchange duration: %lu ms", elapsed_ms);
      }

      /* If we just finished rekeying, drain any of the pending channel
       * data which may have built up during the rekeying exchange.
       */
      if (sftp_sess_state & SFTP_SESS_STATE_REKEYING) {
        sftp_sess_state &= ~SFTP_SESS_STATE_REKEYING;
        sftp_channel_drain_data();
      }
      break;
    }

    case SFTP_SSH2_MSG_SERVICE_REQUEST:
      if (sftp_sess_state & SFTP_SESS_STATE_HAVE_KEX) {
        if (sftp_service_handle(pkt) < 0) {
          SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_BY_APPLICATION, NULL);
        }

        sftp_sess_state |= SFTP_SESS_STATE_HAVE_SERVICE;
        break;

      } else {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "unable to handle %s (%d) message: Key exchange required",
          sftp_ssh2_packet_get_mesg_type_desc(mesg_type), mesg_type);
      }

    case SFTP_SSH2_MSG_USER_AUTH_REQUEST:
      if (sftp_sess_state & SFTP_SESS_STATE_HAVE_SERVICE) {

        /* If the client has already authenticated this connection, then
         * silently ignore this additional auth request, per recommendation
         * in RFC4252.
         */
        if (sftp_sess_state & SFTP_SESS_STATE_HAVE_AUTH) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "ignoring %s (%d) message: Connection already authenticated",
            sftp_ssh2_packet_get_mesg_type_desc(mesg_type), mesg_type);

        } else {
          int ok;

          ok = sftp_auth_handle(pkt);
          if (ok == 1) {
            sftp_sess_state |= SFTP_SESS_STATE_HAVE_AUTH;

          } else if (ok < 0) {
            SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_BY_APPLICATION, NULL);
          }
        }

        break;

      } else {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "unable to handle %s (%d) message: Service request required",
          sftp_ssh2_packet_get_mesg_type_desc(mesg_type), mesg_type);
      }

    case SFTP_SSH2_MSG_CHANNEL_OPEN:
    case SFTP_SSH2_MSG_CHANNEL_REQUEST:
    case SFTP_SSH2_MSG_CHANNEL_CLOSE:
    case SFTP_SSH2_MSG_CHANNEL_DATA:
    case SFTP_SSH2_MSG_CHANNEL_EOF:
    case SFTP_SSH2_MSG_CHANNEL_WINDOW_ADJUST:
      if (sftp_sess_state & SFTP_SESS_STATE_HAVE_AUTH) {
        if (sftp_channel_handle(pkt, mesg_type) < 0) {
          SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_BY_APPLICATION, NULL);
        }

        break;

      } else {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "unable to handle %s (%d) message: User authentication required",
          sftp_ssh2_packet_get_mesg_type_desc(mesg_type), mesg_type);
      }

    default:
      pr_event_generate("ssh2.invalid-packet", pkt);

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "unhandled %s (%d) message, disconnecting",
        sftp_ssh2_packet_get_mesg_type_desc(mesg_type), mesg_type);
      SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_BY_APPLICATION,
        "Unsupported protocol sequence");
  }

  pr_response_set_pool(NULL);
  return 0;
}

int sftp_ssh2_packet_rekey_reset(void) {
  rekey_client_len = 0;
  rekey_server_len = 0;

  /* Add the rekey seqno limit to the current sequence numbers. */

  if (rekey_client_seqno > 0) {
    rekey_client_seqno = packet_client_seqno + SFTP_PACKET_CLIENT_REKEY_SEQNO_LIMIT;

    if (rekey_client_seqno == 0)
      rekey_client_seqno++;
  }

  if (rekey_server_seqno > 0) {
    rekey_server_seqno = packet_client_seqno + SFTP_PACKET_SERVER_REKEY_SEQNO_LIMIT;

    if (rekey_server_seqno == 0)
      rekey_server_seqno++;
  }

  return 0;
}

int sftp_ssh2_packet_rekey_set_seqno(uint32_t seqno) {
  rekey_client_seqno = seqno;
  rekey_server_seqno = seqno;
  return 0;
}

int sftp_ssh2_packet_rekey_set_size(off_t size) {
  rekey_size = size;
  return 0;
}

int sftp_ssh2_packet_send_version(void) {
  if (!sent_version_id) {
    int res;
    size_t version_len;

    version_len = strlen(version_id);

    res = write(sftp_conn->wfd, version_id, version_len);
    while (res < 0) {
      if (errno == EINTR) {
        pr_signals_handle();

        res = write(sftp_conn->wfd, version_id, version_len);
        continue;
      }

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error sending version to client wfd %d: %s", sftp_conn->wfd,
        strerror(errno));
      return res;
    }

    sent_version_id = TRUE;
    session.total_raw_out += res;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "sent server version '%s'", server_version);
  }

  return 0;
}

int sftp_ssh2_packet_set_version(const char *version) {
  if (server_version == NULL) {
    errno = EINVAL;
    return -1;
  }

  server_version = version;
  version_id = pstrcat(sftp_pool, version, "\r\n", NULL);
  return 0;
}

