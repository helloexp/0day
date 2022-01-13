/*
 * ProFTPD - mod_snmp packet routines
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

#include "mod_snmp.h"
#include "packet.h"
#include "db.h"

static const char *trace_channel = "snmp";

struct snmp_packet *snmp_packet_create(pool *p) {
  struct snmp_packet *pkt;
  pool *sub_pool;

  sub_pool = pr_pool_create_sz(p, 128);
  pr_pool_tag(sub_pool, "SNMP packet pool");

  pkt = pcalloc(sub_pool, sizeof(struct snmp_packet));
  pkt->pool = sub_pool;

  /* Allocate the request data buffer for now; leave the response data
   * buffer to be allocated later.
   */

  pkt->req_datalen = SNMP_PACKET_MAX_LEN;
  pkt->req_data = palloc(sub_pool, pkt->req_datalen);

  pkt->resp_datalen = SNMP_PACKET_MAX_LEN;
  pkt->resp_data = palloc(sub_pool, pkt->resp_datalen);

  return pkt;
}

int snmp_packet_write(pool *p, int sockfd, struct snmp_packet *pkt) {
  int res;
  fd_set writefds;
  struct timeval tv;

  if (sockfd < 0) {
    errno = EINVAL;
    return -1; 
  }

  FD_ZERO(&writefds);
  FD_SET(sockfd, &writefds);

  while (TRUE) {
    /* XXX Do we really need a timeout, after which we drop this packet? */
    tv.tv_sec = 15;
    tv.tv_usec = 0;

    res = select(sockfd + 1, NULL, &writefds, NULL, &tv);
    if (res < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
        continue;
      }

      return -1;
    }

    break;
  }

  if (res > 0) {
    if (FD_ISSET(sockfd, &writefds)) {
      pr_trace_msg(trace_channel, 3,
        "sending %lu UDP message bytes to %s#%u",
        (unsigned long) pkt->resp_datalen,
        pr_netaddr_get_ipstr(pkt->remote_addr),
        ntohs(pr_netaddr_get_port(pkt->remote_addr)));

      res = sendto(sockfd, pkt->resp_data, pkt->resp_datalen, 0,
        pr_netaddr_get_sockaddr(pkt->remote_addr),
        pr_netaddr_get_sockaddr_len(pkt->remote_addr));
      if (res < 0) {
        (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
          "error sending %u UDP message bytes to %s#%u: %s",
          (unsigned int) pkt->resp_datalen,
          pr_netaddr_get_ipstr(pkt->remote_addr),
          ntohs(pr_netaddr_get_port(pkt->remote_addr)), strerror(errno));

      } else {
        pr_trace_msg(trace_channel, 3,
          "sent %d UDP message bytes to %s#%u", res,
          pr_netaddr_get_ipstr(pkt->remote_addr),
          ntohs(pr_netaddr_get_port(pkt->remote_addr)));

        res = snmp_db_incr_value(pkt->pool, SNMP_DB_SNMP_F_PKTS_SENT_TOTAL, 1);
        if (res < 0) {
          (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
            "error incrementing SNMP database for "
            "snmp.packetsSentTotal: %s", strerror(errno));
        }
      }
    }

  } else {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "dropping response after waiting %u secs for available socket space",
      (unsigned int) tv.tv_sec);

    res = snmp_db_incr_value(pkt->pool, SNMP_DB_SNMP_F_PKTS_DROPPED_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing snmp.packetsDroppedTotal: %s", strerror(errno));
    }
  }

  return res;
}
