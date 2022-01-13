/*
 * ProFTPD - mod_sftp services
 * Copyright (c) 2008-2015 TJ Saunders
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
#include "service.h"
#include "msg.h"
#include "packet.h"
#include "disconnect.h"

static pool *service_pool = NULL;
static const char *trace_channel = "ssh2";

static int read_service_req(struct ssh2_packet *pkt, char **service) {
  unsigned char *buf;
  char *service_name;
  uint32_t buflen;
  cmd_rec *cmd;

  buf = pkt->payload;
  buflen = pkt->payload_len;

  service_name = sftp_msg_read_string(pkt->pool, &buf, &buflen);
  pr_trace_msg(trace_channel, 10, "'%s' service requested", service_name);

  cmd = pr_cmd_alloc(pkt->pool, 1, pstrdup(pkt->pool, "SERVICE_REQUEST"),
    pstrdup(pkt->pool, service_name));
  cmd->arg = service_name;
  cmd->cmd_class = CL_MISC|CL_SSH;

  if (strncmp(service_name, "ssh-userauth", 13) == 0 ||
      strncmp(service_name, "ssh-connection", 14) == 0) {
    if (service)
      *service = pstrdup(service_pool, service_name);

    pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
    return 0;
  }

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "client requested unsupported '%s' service", service_name);

  pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
  return -1;
}

static int write_service_accept(struct ssh2_packet *pkt, const char *service) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz = 1024;

  buflen = bufsz;
  ptr = buf = palloc(pkt->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_MSG_SERVICE_ACCEPT);
  sftp_msg_write_string(&buf, &buflen, service);

  pkt->payload = ptr;
  pkt->payload_len = (bufsz - buflen);

  return 0;
}

int sftp_service_handle(struct ssh2_packet *pkt) {
  int res;
  char *service = NULL;

  res = read_service_req(pkt, &service);
  if (res < 0) {
    destroy_pool(pkt->pool);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, NULL);
  }

  destroy_pool(pkt->pool);

  pkt = sftp_ssh2_packet_create(service_pool);
  res = write_service_accept(pkt, service);
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

int sftp_service_init(void) {
  if (service_pool == NULL) {
    service_pool = make_sub_pool(sftp_pool);
    pr_pool_tag(service_pool, "Service Pool");
  }

  return 0;
}
