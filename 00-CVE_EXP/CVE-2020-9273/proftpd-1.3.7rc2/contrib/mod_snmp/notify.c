/*
 * ProFTPD - mod_snmp notification routines
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

#include "mod_snmp.h"
#include "msg.h"
#include "pdu.h"
#include "smi.h"
#include "mib.h"
#include "packet.h"
#include "db.h"
#include "notify.h"

static const char *trace_channel = "snmp.notify";

struct snmp_notify_oid {
  unsigned int notify_id;
  oid_t notify_oid[SNMP_MIB_MAX_OIDLEN];
  unsigned int notify_oidlen;
};

static struct snmp_notify_oid notify_oids[] = {
  { SNMP_NOTIFY_DAEMON_MAX_INSTANCES,
    { SNMP_MIB_DAEMON_NOTIFY_OID_MAX_INSTANCES, 0 },
    SNMP_MIB_DAEMON_NOTIFY_OIDLEN_MAX_INSTANCES + 1 },

  { SNMP_NOTIFY_FTP_BAD_PASSWD,
    { SNMP_MIB_FTP_NOTIFY_OID_LOGIN_BAD_PASSWORD, 0 },
    SNMP_MIB_FTP_NOTIFY_OIDLEN_LOGIN_BAD_PASSWORD + 1 },

  { SNMP_NOTIFY_FTP_BAD_USER,
    { SNMP_MIB_FTP_NOTIFY_OID_LOGIN_BAD_USER, 0 },
    SNMP_MIB_FTP_NOTIFY_OIDLEN_LOGIN_BAD_USER + 1 },

  { 0, { }, 0 }
};

static const char *get_notify_str(unsigned int notify_id) {
  const char *name = NULL;

  switch (notify_id) {
    case SNMP_NOTIFY_DAEMON_MAX_INSTANCES:
      name = "maxInstancesExceeded";
      break;

    case SNMP_NOTIFY_FTP_BAD_PASSWD:
      name = "loginFailedBadPassword";
      break;

    case SNMP_NOTIFY_FTP_BAD_USER:
      name = "loginFailedBadUser";
      break;

    default:
      name = "<Unknown>";
  }

  return name;
}

static oid_t *get_notify_oid(pool *p, unsigned int notify_id,
    unsigned int *oidlen) {
  register unsigned int i;

  for (i = 0; notify_oids[i].notify_oidlen > 0; i++) {
    if (notify_oids[i].notify_id == notify_id) {
      *oidlen = notify_oids[i].notify_oidlen;
      return notify_oids[i].notify_oid;
    }
  }

  errno = ENOENT;
  return NULL;
}

static struct snmp_packet *get_notify_pkt(pool *p, const char *community,
    const pr_netaddr_t *dst_addr, unsigned int notify_id,
    struct snmp_var **head_var, struct snmp_var **tail_var) {
  struct snmp_packet *pkt = NULL;
  struct snmp_mib *mib = NULL;
  struct snmp_var *resp_var = NULL;
  int32_t mib_int = -1;
  char *mib_str = NULL;
  size_t mib_strlen = 0;
  oid_t *notify_oid = NULL;
  unsigned int notify_oidlen = 0;
  int res;

  pkt = snmp_packet_create(p);
  pkt->snmp_version = SNMP_PROTOCOL_VERSION_2;
  pkt->community = (char *) community;
  pkt->community_len = strlen(community);
  pkt->remote_addr = dst_addr;

  pkt->resp_pdu = snmp_pdu_create(pkt->pool, SNMP_PDU_TRAP_V2);
  pkt->resp_pdu->err_code = 0;
  pkt->resp_pdu->err_idx = 0;
  pkt->resp_pdu->request_id = snmp_notify_get_request_id();

  /* Set first varbind to sysUptime.0 (1.3.6.1.2.1.1.3.0, TimeTicks),
   * per RFC 1905, Section 4.2.6.
   */
  res = snmp_db_get_value(pkt->pool, SNMP_DB_NOTIFY_F_SYS_UPTIME, &mib_int,
    &mib_str, &mib_strlen);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "unable to get system uptime for notification: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  mib = snmp_mib_get_by_idx(SNMP_MIB_SYS_UPTIME_IDX);
  resp_var = snmp_smi_create_var(pkt->pool, mib->mib_oid, mib->mib_oidlen,
    mib->smi_type, mib_int, mib_str, mib_strlen);
  snmp_smi_util_add_list_var(head_var, tail_var, resp_var);

  /* Set second varbind to snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0, OID)
   * per RFC 1905, Section 4.2.6.
   */
  mib = snmp_mib_get_by_idx(SNMP_MIB_SNMP2_TRAP_OID_IDX);
  notify_oid = get_notify_oid(pkt->pool, notify_id, &notify_oidlen);
  resp_var = snmp_smi_create_oid(pkt->pool, mib->mib_oid, mib->mib_oidlen,
    mib->smi_type, notify_oid, notify_oidlen);
  snmp_smi_util_add_list_var(head_var, tail_var, resp_var);

  return pkt;
}

static int get_notify_varlist(pool *p, unsigned int notify_id,
    struct snmp_var **head_var) {
  struct snmp_var *tail_var = NULL;
  int var_count = 0;

  switch (notify_id) {
    case SNMP_NOTIFY_DAEMON_MAX_INSTANCES: {
      struct snmp_var *var;
      int32_t int_value = 0;
      char *str_value = NULL;
      size_t str_valuelen = 0;
      int res;

      /* The MaxInstances check happens very early on in the session
       * lifecycle, thus there is not much information that we can add
       * to notifications for this event, other than the fact that it
       * happened.
       *
       * Per PROFTPD-MIB, we need to include:
       *
       *  daemon.maxInstancesConfig
       */

      res = snmp_db_get_value(p, SNMP_DB_DAEMON_F_MAXINST_CONF, &int_value,
        &str_value, &str_valuelen);
      if (res < 0) {
        pr_trace_msg(trace_channel, 5,
          "unable to get daemon.maxInstancesConfig value: %s", strerror(errno));

      } else {
        oid_t oid[] = { SNMP_MIB_DAEMON_OID_MAXINST_CONF, 0 };
        unsigned int oidlen = SNMP_MIB_DAEMON_OIDLEN_MAXINST_CONF + 1;

        var = snmp_smi_create_var(p, oid, oidlen, SNMP_SMI_INTEGER, int_value,
          str_value, str_valuelen);
        var_count = snmp_smi_util_add_list_var(head_var, &tail_var, var);
      }

      return var_count;
    }

    case SNMP_NOTIFY_FTP_BAD_PASSWD:
    case SNMP_NOTIFY_FTP_BAD_USER: {
      struct snmp_var *var;
      int32_t int_value = 0;
      char *str_value = NULL;
      size_t str_valuelen = 0;
      int res;

      /* Per PROFTPD-MIB, we need to include:
       *
       *  connection.serverName
       *  connection.serverAddress
       *  connection.serverPort
       *  connection.clientAddress
       *  connection.processId
       *  connection.userName
       *  connection.protocol
       */

      /* connection.serverName */
      res = snmp_db_get_value(p, SNMP_DB_CONN_F_SERVER_NAME, &int_value,
        &str_value, &str_valuelen);
      if (res < 0) {
        pr_trace_msg(trace_channel, 5,
          "unable to get connection.serverName value: %s", strerror(errno));

      } else {
        oid_t oid[] = { SNMP_MIB_CONN_OID_SERVER_NAME, 0 };
        unsigned int oidlen = SNMP_MIB_CONN_OIDLEN_SERVER_NAME + 1;

        var = snmp_smi_create_var(p, oid, oidlen, SNMP_SMI_STRING, int_value,
          str_value, str_valuelen);
        var_count = snmp_smi_util_add_list_var(head_var, &tail_var, var);
      }

      /* connection.serverAddress */
      res = snmp_db_get_value(p, SNMP_DB_CONN_F_SERVER_ADDR, &int_value,
        &str_value, &str_valuelen);
      if (res < 0) {
        pr_trace_msg(trace_channel, 5,
          "unable to get connection.serverAddress value: %s", strerror(errno));

      } else {
        oid_t oid[] = { SNMP_MIB_CONN_OID_SERVER_ADDR, 0 };
        unsigned int oidlen = SNMP_MIB_CONN_OIDLEN_SERVER_ADDR + 1;

        var = snmp_smi_create_var(p, oid, oidlen, SNMP_SMI_STRING, int_value,
          str_value, str_valuelen);
        var_count = snmp_smi_util_add_list_var(head_var, &tail_var, var);
      }

      /* connection.serverPort */
      res = snmp_db_get_value(p, SNMP_DB_CONN_F_SERVER_PORT, &int_value,
        &str_value, &str_valuelen);
      if (res < 0) {
        pr_trace_msg(trace_channel, 5,
          "unable to get connection.serverPort value: %s", strerror(errno));

      } else {
        oid_t oid[] = { SNMP_MIB_CONN_OID_SERVER_PORT, 0 };
        unsigned int oidlen = SNMP_MIB_CONN_OIDLEN_SERVER_PORT + 1;

        var = snmp_smi_create_var(p, oid, oidlen, SNMP_SMI_INTEGER, int_value,
          str_value, str_valuelen);
        var_count = snmp_smi_util_add_list_var(head_var, &tail_var, var);
      }

      /* connection.clientAddress */
      res = snmp_db_get_value(p, SNMP_DB_CONN_F_CLIENT_ADDR, &int_value,
        &str_value, &str_valuelen);
      if (res < 0) {
        pr_trace_msg(trace_channel, 5,
          "unable to get connection.clientAddress value: %s", strerror(errno));

      } else {
        oid_t oid[] = { SNMP_MIB_CONN_OID_CLIENT_ADDR, 0 };
        unsigned int oidlen = SNMP_MIB_CONN_OIDLEN_CLIENT_ADDR + 1;

        var = snmp_smi_create_var(p, oid, oidlen, SNMP_SMI_STRING, int_value,
          str_value, str_valuelen);
        var_count = snmp_smi_util_add_list_var(head_var, &tail_var, var);
      }

      /* connection.processId */
      res = snmp_db_get_value(p, SNMP_DB_CONN_F_PID, &int_value, &str_value,
        &str_valuelen);
      if (res < 0) {
        pr_trace_msg(trace_channel, 5,
          "unable to get connection.processId value: %s", strerror(errno));

      } else {
        oid_t oid[] = { SNMP_MIB_CONN_OID_PID, 0 };
        unsigned int oidlen = SNMP_MIB_CONN_OIDLEN_PID + 1;

        var = snmp_smi_create_var(p, oid, oidlen, SNMP_SMI_INTEGER, int_value,
          str_value, str_valuelen);
        var_count = snmp_smi_util_add_list_var(head_var, &tail_var, var);
      }

      /* connection.userName */
      res = snmp_db_get_value(p, SNMP_DB_CONN_F_USER_NAME, &int_value,
        &str_value, &str_valuelen);
      if (res < 0) {
        pr_trace_msg(trace_channel, 5,
          "unable to get connection.userName value: %s", strerror(errno));

      } else {
        oid_t oid[] = { SNMP_MIB_CONN_OID_USER_NAME, 0 };
        unsigned int oidlen = SNMP_MIB_CONN_OIDLEN_USER_NAME + 1;

        var = snmp_smi_create_var(p, oid, oidlen, SNMP_SMI_STRING, int_value,
          str_value, str_valuelen);
        var_count = snmp_smi_util_add_list_var(head_var, &tail_var, var);
      }

      /* connection.protocol */
      res = snmp_db_get_value(p, SNMP_DB_CONN_F_PROTOCOL, &int_value,
        &str_value, &str_valuelen);
      if (res < 0) {
        pr_trace_msg(trace_channel, 5,
          "unable to get connection.protocol value: %s", strerror(errno));

      } else {
        oid_t oid[] = { SNMP_MIB_CONN_OID_PROTOCOL, 0 };
        unsigned int oidlen = SNMP_MIB_CONN_OIDLEN_PROTOCOL + 1;

        var = snmp_smi_create_var(p, oid, oidlen, SNMP_SMI_STRING, int_value,
          str_value, str_valuelen);
        var_count = snmp_smi_util_add_list_var(head_var, &tail_var, var);
      }

      return var_count;
    }

    default:
      break;
  }

  errno = ENOENT;
  return -1;
}

int snmp_notify_generate(pool *p, int sockfd, const char *community,
    const pr_netaddr_t *src_addr, const pr_netaddr_t *dst_addr,
    unsigned int notify_id) {
  const char *notify_str;
  struct snmp_packet *pkt;
  struct snmp_var *notify_varlist = NULL, *head_var = NULL, *tail_var = NULL,
    *iter_var;
  int fd = -1, res;
  unsigned int var_count = 0;

  notify_str = get_notify_str(notify_id);

  pkt = get_notify_pkt(p, community, dst_addr, notify_id, &head_var, &tail_var);
  if (pkt == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 7,
      "unable to create %s notification packet: %s", notify_str,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* Add trap-specific varbinds */
  res = get_notify_varlist(p, notify_id, &notify_varlist);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 7,
      "unable to create %s notification varbind list: %s", notify_str,
      strerror(xerrno));

    destroy_pool(pkt->pool);
    errno = xerrno;
    return -1;
  }

  for (iter_var = notify_varlist; iter_var; iter_var = iter_var->next) {
    pr_signals_handle();

    var_count = snmp_smi_util_add_list_var(&head_var, &tail_var, iter_var);
  }

  pkt->resp_pdu->varlist = head_var;
  pkt->resp_pdu->varlistlen = var_count;

  (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
    "writing %s SNMP notification for %s, community = '%s', request ID %ld, "
    "request type '%s'", notify_str,
    snmp_msg_get_versionstr(pkt->snmp_version), pkt->community,
    pkt->resp_pdu->request_id,
    snmp_pdu_get_request_type_desc(pkt->resp_pdu->request_type));

  res = snmp_msg_write(pkt->pool, &(pkt->resp_data), &(pkt->resp_datalen),
    pkt->community, pkt->community_len, pkt->snmp_version, pkt->resp_pdu);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "error writing %s SNMP notification to UDP packet: %s", notify_str,
      strerror(xerrno));

    destroy_pool(pkt->pool);
    errno = xerrno;
    return -1;
  }

  if (sockfd < 0) {
    /* If the given fd isn't open, then we need to open our own. */

    /* XXX Support IPv6? */

    fd = socket(AF_INET, SOCK_DGRAM, snmp_proto_udp);
    if (fd < 0) {
      int xerrno = errno;

      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "unable to create UDP socket: %s", strerror(xerrno));

      destroy_pool(pkt->pool);
      errno = xerrno;
      return -1;
    }

  } else {
    fd = sockfd;
  }

  snmp_packet_write(p, fd, pkt);

  /* If we opened our own socket here, then close it. */
  if (sockfd < 0) {
    (void) close(fd);
  }

  res = snmp_db_incr_value(pkt->pool, SNMP_DB_SNMP_F_TRAPS_SENT_TOTAL, 1);
  if (res < 0) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "error incrementing snmp.trapsSentTotal: %s", strerror(errno));
  }

  destroy_pool(pkt->pool);
  return 0;
}

long snmp_notify_get_request_id(void) {
  return pr_random_next(1L, 10000L);
}

void snmp_notify_poll_cond(void) {
  /* XXX Poll for notify conditions here, based on the criteria configured
   * for various notification receivers.
   */
}
