/*
 * ProFTPD - mod_sftp keyboard-interactive driver mgmt
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
#include "utf8.h"
#include "kbdint.h"

#define SFTP_KBDINT_MAX_RESPONSES	500

extern pr_response_t *resp_list, *resp_err_list;

struct kbdint_driver {
  struct kbdint_driver *next, *prev;

  const char *name;
  sftp_kbdint_driver_t *driver;
};

static pool *kbdint_pool = NULL;
static struct kbdint_driver *drivers = NULL;
static unsigned int ndrivers = 0;

static const char *trace_channel = "ssh2";

unsigned int sftp_kbdint_have_drivers(void) {
  return ndrivers;
}

sftp_kbdint_driver_t *sftp_kbdint_get_driver(const char *name) {
  struct kbdint_driver *kd;

  if (name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  for (kd = drivers; kd; kd = kd->next) {
    if (strcmp(kd->name, name) == 0) {
      return kd->driver;
    }
  }

  errno = ENOENT;
  return NULL;
}

static struct kbdint_driver *kdi = NULL;

sftp_kbdint_driver_t *sftp_kbdint_first_driver(void) {
  sftp_kbdint_driver_t *d = NULL;

  if (drivers == NULL) {
    errno = ENOENT;
    return NULL;
  }

  if (kdi != NULL) {
    errno = EPERM;
    return NULL;
  }

  d = drivers->driver;
  kdi = drivers->next;

  return d;
}

sftp_kbdint_driver_t *sftp_kbdint_next_driver(void) {
  sftp_kbdint_driver_t *d = NULL;

  if (drivers == NULL) {
    errno = ENOENT;
    return NULL;
  }

  if (kdi == NULL) {
    errno = EPERM;
    return NULL;
  }

  d = kdi->driver;
  kdi = kdi->next;

  return d;
}

int sftp_kbdint_register_driver(const char *name,
    sftp_kbdint_driver_t *driver) {
  struct kbdint_driver *kd;

  if (name == NULL ||
      driver == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (kbdint_pool == NULL) {
    kbdint_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(kbdint_pool, "SFTP keyboard-interactive API Pool");
  }

  /* Make sure that the driver hasn't already been registered. */
  if (sftp_kbdint_get_driver(name) != NULL) {
    errno = EEXIST;
    return -1;
  }

  kd = pcalloc(kbdint_pool, sizeof(struct kbdint_driver));

  /* XXX Should this name string be dup'd from the kbdint_pool? */
  kd->name = name;
  driver->driver_name = pstrdup(kbdint_pool, name);
  kd->driver = driver;

  if (drivers) {
    kd->next = drivers;

  } else {
    kd->next = NULL;
  }

  drivers = kd;
  ndrivers++;

  return 0;
}

int sftp_kbdint_unregister_driver(const char *name) {
  struct kbdint_driver *kd;

  if (name == NULL) {
    errno = EINVAL;
    return -1;
  }

  for (kd = drivers; kd; kd = kd->next) {
    if (strcmp(kd->name, name) == 0) {

      if (kd->prev) {
        kd->prev->next = kd->next;

      } else {
        /* If prev is NULL, this is the head of the list. */
        drivers = kd->next;
      }

      if (kd->next)
        kd->next->prev = kd->prev;

      kd->next = kd->prev = NULL;
      ndrivers--;

      /* NOTE: a counter should be kept of the number of unregistrations,
       * as the memory for a registration is not freed on unregistration.
       */

      return 0;
    }
  }

  errno = ENOENT;
  return -1;
}

/* Convenience functions that can be used by the driver implementations
 * for communicating with the client, without needing to worry about
 * SSH2 message formatting, I/O, etc.
 */

int sftp_kbdint_send_challenge(const char *user, const char *instruction,
    uint32_t count, sftp_kbdint_challenge_t *challenges) {
  register unsigned int i;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;
  struct ssh2_packet *pkt;
  int res;

  if (count == 0 ||
      challenges == NULL) {
    errno = EINVAL;
    return -1;
  }

  pkt = sftp_ssh2_packet_create(kbdint_pool);

  /* XXX Is this large enough?  Too large? */
  buflen = bufsz = 3072;
  buf = ptr = palloc(pkt->pool, bufsz);

  /* See RFC4256, Section 3.2. */
  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_USER_AUTH_INFO_REQ);

  if (user) {
    sftp_msg_write_string(&buf, &buflen,
      sftp_utf8_encode_str(pkt->pool, user));

  } else {
    /* Empty user strings are allowed. */
    sftp_msg_write_string(&buf, &buflen, "");
  }

  if (instruction) {
    sftp_msg_write_string(&buf, &buflen,
      sftp_utf8_encode_str(pkt->pool, instruction));

  } else {
    /* Empty instruction strings are allowed. */
    sftp_msg_write_string(&buf, &buflen, "");
  }

  /* Empty language string. */
  sftp_msg_write_string(&buf, &buflen, "");

  sftp_msg_write_int(&buf, &buflen, count);

  for (i = 0; i < count; i++) {
    sftp_msg_write_string(&buf, &buflen, challenges[i].challenge);
    sftp_msg_write_bool(&buf, &buflen, challenges[i].display_response);
  }

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  pr_trace_msg(trace_channel, 9,
    "sending USER_AUTH_INFO_REQ message to client");

  res = sftp_ssh2_packet_write(sftp_conn->wfd, pkt);
  destroy_pool(pkt->pool);

  return res;
}

int sftp_kbdint_recv_response(pool *p, uint32_t expected_count,
    uint32_t *rcvd_count, const char ***responses) {
  register unsigned int i;
  unsigned char *buf;
  cmd_rec *cmd;
  array_header *list;
  uint32_t buflen, resp_count;
  struct ssh2_packet *pkt;
  char mesg_type;
  int res;
  pool *resp_pool = NULL;

  if (p == NULL ||
      rcvd_count == NULL ||
      responses == NULL) {
    errno = EINVAL;
    return -1;
  }

  pkt = sftp_ssh2_packet_create(kbdint_pool);

  res = sftp_ssh2_packet_read(sftp_conn->rfd, pkt);
  if (res < 0) {
    destroy_pool(pkt->pool);
    return res;
  }

  pr_response_clear(&resp_list);
  pr_response_clear(&resp_err_list);

  /* Cache a reference to the current response pool used. */
  resp_pool = pr_response_get_pool();
  pr_response_set_pool(pkt->pool);

  mesg_type = sftp_ssh2_packet_get_mesg_type(pkt);
  if (mesg_type != SFTP_SSH2_MSG_USER_AUTH_INFO_RESP) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "expecting USER_AUTH_INFO_RESP message, received %s (%d)",
      sftp_ssh2_packet_get_mesg_type_desc(mesg_type), mesg_type);
    destroy_pool(pkt->pool);
    pr_response_set_pool(resp_pool);
    errno = EPERM;
    return -1;
  }

  cmd = pr_cmd_alloc(pkt->pool, 2, pstrdup(pkt->pool, "USER_AUTH_INFO_RESP"));
  cmd->arg = "(data)";

  pr_trace_msg(trace_channel, 9,
    "reading USER_AUTH_INFO_RESP message from client");

  buf = pkt->payload;
  buflen = pkt->payload_len;

  resp_count = sftp_msg_read_int(pkt->pool, &buf, &buflen);

  /* Ensure that the number of responses sent by the client is the same
   * as the number of challenges sent, lest a malicious client attempt to
   * trick us into allocating too much memory (Bug#3973).
   */
  if (resp_count != expected_count) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "sent %lu %s, but received %lu %s", (unsigned long) expected_count,
      expected_count != 1 ? "challenges" : "challenge",
      (unsigned long) resp_count, resp_count != 1 ? "responses" : "response");
    destroy_pool(pkt->pool);
    pr_response_set_pool(resp_pool);
    errno = EPERM;
    return -1;
  }

  if (resp_count > SFTP_KBDINT_MAX_RESPONSES) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "received too many responses (%lu > max %lu), rejecting",
      (unsigned long) resp_count, (unsigned long) SFTP_KBDINT_MAX_RESPONSES);
    destroy_pool(pkt->pool);
    pr_response_set_pool(resp_pool);
    errno = EPERM;
    return -1;
  }

  list = make_array(p, resp_count, sizeof(char *));
  for (i = 0; i < resp_count; i++) {
    char *resp;

    resp = sftp_msg_read_string(pkt->pool, &buf, &buflen);
    *((char **) push_array(list)) = pstrdup(p, sftp_utf8_decode_str(p, resp));
  }

  *rcvd_count = resp_count;
  *responses = ((const char **) list->elts);
  destroy_pool(pkt->pool);
  pr_response_set_pool(resp_pool);

  return 0;
}
