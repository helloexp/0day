/*
 * ProFTPD - mod_snmp database storage
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
#include "db.h"
#include "uptime.h"

/* On some platforms, this may not be defined.  On AIX, for example, this
 * symbol is only defined when _NO_PROTO is defined, and _XOPEN_SOURCE is 500.
 * How annoying.
 */
#ifndef MAP_FAILED
# define MAP_FAILED	((void *) -1)
#endif

#define SNMP_MAX_LOCK_ATTEMPTS		10

/* Note: Not all database IDs are in this list; only those databases which
 * have on-disk tables are here.  Thus the NOTIFY and CONN database IDs are
 * explicitly NOT here, as they are ephemeral/synthetic databases anyway.
 */
int snmp_table_ids[] = {
  SNMP_DB_ID_DAEMON,
  SNMP_DB_ID_TIMEOUTS,
  SNMP_DB_ID_FTP,
  SNMP_DB_ID_SNMP,
  SNMP_DB_ID_TLS,
  SNMP_DB_ID_SSH,
  SNMP_DB_ID_SFTP,
  SNMP_DB_ID_SCP,
  SNMP_DB_ID_BAN,

  /* XXX Not supported just yet */
#if 0
  SNMP_DB_ID_SQL,
  SNMP_DB_ID_QUOTA,
  SNMP_DB_ID_GEOIP,
#endif

  SNMP_DB_ID_UNKNOWN
};

static const char *snmp_db_root = NULL;

static const char *trace_channel = "snmp.db";

struct snmp_field_info {
  unsigned int field;
  int db_id;
  off_t field_start;
  size_t field_len;
  const char *field_name;
};

static struct snmp_field_info snmp_fields[] = {

  /* Miscellaneous SNMP-related fields */
  { SNMP_DB_NOTIFY_F_SYS_UPTIME, SNMP_DB_ID_NOTIFY, 0,
    0, "NOTIFY_F_SYS_UPTIME" },

  /* Connection fields */
  { SNMP_DB_CONN_F_SERVER_NAME, SNMP_DB_ID_CONN, 0,
    0, "CONN_F_SERVER_NAME" },
  { SNMP_DB_CONN_F_SERVER_ADDR, SNMP_DB_ID_CONN, 0,
    0, "CONN_F_SERVER_ADDR" },
  { SNMP_DB_CONN_F_SERVER_PORT, SNMP_DB_ID_CONN, 0,
    0, "CONN_F_SERVER_PORT" },
  { SNMP_DB_CONN_F_CLIENT_ADDR, SNMP_DB_ID_CONN, 0,
    0, "CONN_F_CLIENT_ADDR" },
  { SNMP_DB_CONN_F_PID, SNMP_DB_ID_CONN, 0,
    0, "CONN_F_PID" },
  { SNMP_DB_CONN_F_USER_NAME, SNMP_DB_ID_CONN, 0,
    0, "CONN_F_USER_NAME" },
  { SNMP_DB_CONN_F_PROTOCOL, SNMP_DB_ID_CONN, 0,
    0, "CONN_F_PROTOCOL" },

  /* Daemon fields */
  { SNMP_DB_DAEMON_F_SOFTWARE, SNMP_DB_ID_DAEMON, 0,
    0, "DAEMON_F_SOFTWARE" },
  { SNMP_DB_DAEMON_F_VERSION, SNMP_DB_ID_DAEMON, 0,
    0, "DAEMON_F_VERSION" },
  { SNMP_DB_DAEMON_F_ADMIN, SNMP_DB_ID_DAEMON, 0,
    0, "DAEMON_F_ADMIN" },
  { SNMP_DB_DAEMON_F_UPTIME, SNMP_DB_ID_DAEMON, 0,
    0, "DAEMON_F_UPTIME" },
  { SNMP_DB_DAEMON_F_VHOST_COUNT, SNMP_DB_ID_DAEMON, 0,
    sizeof(uint32_t), "DAEMON_F_VHOST_COUNT" },
  { SNMP_DB_DAEMON_F_CONN_COUNT, SNMP_DB_ID_DAEMON, 4,
    sizeof(uint32_t), "DAEMON_F_CONN_COUNT" },
  { SNMP_DB_DAEMON_F_CONN_TOTAL, SNMP_DB_ID_DAEMON, 8,
    sizeof(uint32_t), "DAEMON_F_CONN_TOTAL" },
  { SNMP_DB_DAEMON_F_CONN_REFUSED_TOTAL, SNMP_DB_ID_DAEMON, 12,
    sizeof(uint32_t), "DAEMON_F_CONN_REFUSED_TOTAL" },
  { SNMP_DB_DAEMON_F_RESTART_COUNT, SNMP_DB_ID_DAEMON, 16,
    sizeof(uint32_t), "DAEMON_F_RESTART_COUNT" },
  { SNMP_DB_DAEMON_F_SEGFAULT_COUNT, SNMP_DB_ID_DAEMON, 20,
    sizeof(uint32_t), "DAEMON_F_SEGFAULT_COUNT" },
  { SNMP_DB_DAEMON_F_MAXINST_TOTAL, SNMP_DB_ID_DAEMON, 24,
    sizeof(uint32_t), "DAEMON_F_MAXINST_TOTAL" },
  { SNMP_DB_DAEMON_F_MAXINST_CONF, SNMP_DB_ID_DAEMON, 28,
    sizeof(uint32_t), "DAEMON_F_MAXINST_CONF" },

  /* timeouts fields */
  { SNMP_DB_TIMEOUTS_F_IDLE_TOTAL, SNMP_DB_ID_TIMEOUTS, 0,
    sizeof(uint32_t), "TIMEOUTS_F_IDLE_TOTAL" },
  { SNMP_DB_TIMEOUTS_F_LOGIN_TOTAL, SNMP_DB_ID_TIMEOUTS, 4,
    sizeof(uint32_t), "TIMEOUTS_F_LOGIN_TOTAL" },
  { SNMP_DB_TIMEOUTS_F_NOXFER_TOTAL, SNMP_DB_ID_TIMEOUTS, 8,
    sizeof(uint32_t), "TIMEOUTS_F_NOXFER_TOTAL" },
  { SNMP_DB_TIMEOUTS_F_STALLED_TOTAL, SNMP_DB_ID_TIMEOUTS, 12,
    sizeof(uint32_t), "TIMEOUTS_F_STALLED_TOTAL" },

  /* ftp.sessions fields */
  { SNMP_DB_FTP_SESS_F_SESS_COUNT, SNMP_DB_ID_FTP, 0,
    sizeof(uint32_t), "FTP_SESS_F_SESS_COUNT" },
  { SNMP_DB_FTP_SESS_F_SESS_TOTAL, SNMP_DB_ID_FTP, 4,
    sizeof(uint32_t), "FTP_SESS_F_SESS_TOTAL" },
  { SNMP_DB_FTP_SESS_F_CMD_INVALID_TOTAL, SNMP_DB_ID_FTP, 8,
    sizeof(uint32_t), "FTP_SESS_F_CMD_INVALID_TOTAL" },

  /* ftp.logins fields */
  { SNMP_DB_FTP_LOGINS_F_TOTAL, SNMP_DB_ID_FTP, 12,
    sizeof(uint32_t), "FTP_LOGINS_F_TOTAL" },
  { SNMP_DB_FTP_LOGINS_F_ERR_TOTAL, SNMP_DB_ID_FTP, 16,
    sizeof(uint32_t), "FTP_LOGINS_F_ERR_TOTAL" },
  { SNMP_DB_FTP_LOGINS_F_ERR_BAD_USER_TOTAL, SNMP_DB_ID_FTP, 20,
    sizeof(uint32_t), "FTP_LOGINS_F_ERR_BAD_USER_TOTAL" },
  { SNMP_DB_FTP_LOGINS_F_ERR_BAD_PASSWD_TOTAL, SNMP_DB_ID_FTP, 24,
    sizeof(uint32_t), "FTP_LOGINS_F_ERR_BAD_PASSWD_TOTAL" },
  { SNMP_DB_FTP_LOGINS_F_ERR_GENERAL_TOTAL, SNMP_DB_ID_FTP, 28,
    sizeof(uint32_t), "FTP_LOGINS_F_ERR_GENERAL_TOTAL" },
  { SNMP_DB_FTP_LOGINS_F_ANON_COUNT, SNMP_DB_ID_FTP, 32,
    sizeof(uint32_t), "FTP_LOGINS_F_ANON_COUNT" },
  { SNMP_DB_FTP_LOGINS_F_ANON_TOTAL, SNMP_DB_ID_FTP, 36,
    sizeof(uint32_t), "FTP_LOGINS_F_ANON_TOTAL" },

  /* ftp.dataTransfers fields */
  { SNMP_DB_FTP_XFERS_F_DIR_LIST_COUNT, SNMP_DB_ID_FTP, 40,
    sizeof(uint32_t), "FTP_XFERS_F_DIR_LIST_COUNT" },
  { SNMP_DB_FTP_XFERS_F_DIR_LIST_TOTAL, SNMP_DB_ID_FTP, 44,
    sizeof(uint32_t), "FTP_XFERS_F_DIR_LIST_TOTAL" },
  { SNMP_DB_FTP_XFERS_F_DIR_LIST_ERR_TOTAL, SNMP_DB_ID_FTP, 48,
    sizeof(uint32_t), "FTP_XFERS_F_DIR_LIST_ERR_TOTAL" },
  { SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_COUNT, SNMP_DB_ID_FTP, 52,
    sizeof(uint32_t), "FTP_XFERS_F_FILE_UPLOAD_COUNT" },
  { SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_TOTAL, SNMP_DB_ID_FTP, 56,
    sizeof(uint32_t), "FTP_XFERS_F_FILE_UPLOAD_TOTAL" },
  { SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_ERR_TOTAL, SNMP_DB_ID_FTP, 60,
    sizeof(uint32_t), "FTP_XFERS_F_FILE_UPLOAD_ERR_TOTAL" },
  { SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_COUNT, SNMP_DB_ID_FTP, 64,
    sizeof(uint32_t), "FTP_XFERS_F_FILE_DOWNLOAD_COUNT" },
  { SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_TOTAL, SNMP_DB_ID_FTP, 68,
    sizeof(uint32_t), "FTP_XFERS_F_FILE_DOWNLOAD_TOTAL" },
  { SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL, SNMP_DB_ID_FTP, 72,
    sizeof(uint32_t), "FTP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL" },
  { SNMP_DB_FTP_XFERS_F_KB_UPLOAD_TOTAL, SNMP_DB_ID_FTP, 76,
    sizeof(uint32_t), "FTP_XFERS_F_KB_UPLOAD_TOTAL" },
  { SNMP_DB_FTP_XFERS_F_KB_DOWNLOAD_TOTAL, SNMP_DB_ID_FTP, 80,
    sizeof(uint32_t), "FTP_XFERS_F_KB_DOWNLOAD_TOTAL" },

  /* snmp fields */
  { SNMP_DB_SNMP_F_PKTS_RECVD_TOTAL, SNMP_DB_ID_SNMP, 0,
    sizeof(uint32_t), "SNMP_F_PKTS_RECVD_TOTAL" },
  { SNMP_DB_SNMP_F_PKTS_SENT_TOTAL, SNMP_DB_ID_SNMP, 4,
    sizeof(uint32_t), "SNMP_F_PKTS_SENT_TOTAL" },
  { SNMP_DB_SNMP_F_TRAPS_SENT_TOTAL, SNMP_DB_ID_SNMP, 8,
    sizeof(uint32_t), "SNMP_F_TRAPS_SENT_TOTAL" },
  { SNMP_DB_SNMP_F_PKTS_AUTH_ERR_TOTAL, SNMP_DB_ID_SNMP, 12,
    sizeof(uint32_t), "SNMP_F_PKTS_AUTH_ERR_TOTAL" },
  { SNMP_DB_SNMP_F_PKTS_DROPPED_TOTAL, SNMP_DB_ID_SNMP, 16,
    sizeof(uint32_t), "SNMP_F_PKTS_DROPPED_TOTAL" },

  /* ftps.tlsSessions fields */
  { SNMP_DB_FTPS_SESS_F_SESS_COUNT, SNMP_DB_ID_TLS, 0,
    sizeof(uint32_t), "FTPS_SESS_F_SESS_COUNT" },
  { SNMP_DB_FTPS_SESS_F_SESS_TOTAL, SNMP_DB_ID_TLS, 4,
    sizeof(uint32_t), "FTPS_SESS_F_SESS_TOTAL" },
  { SNMP_DB_FTPS_SESS_F_CTRL_HANDSHAKE_ERR_TOTAL, SNMP_DB_ID_TLS, 8,
    sizeof(uint32_t), "FTPS_SESS_F_CTRL_HANDSHAKE_ERR_TOTAL" },
  { SNMP_DB_FTPS_SESS_F_DATA_HANDSHAKE_ERR_TOTAL, SNMP_DB_ID_TLS, 12,
    sizeof(uint32_t), "FTPS_SESS_F_DATA_HANDSHAKE_ERR_TOTAL" },
  { SNMP_DB_FTPS_SESS_F_CCC_TOTAL, SNMP_DB_ID_TLS, 16,
    sizeof(uint32_t), "FTPS_SESS_F_CCC_TOTAL" },
  { SNMP_DB_FTPS_SESS_F_CCC_ERR_TOTAL, SNMP_DB_ID_TLS, 20,
    sizeof(uint32_t), "FTPS_SESS_F_CCC_ERR_TOTAL" },
  { SNMP_DB_FTPS_SESS_F_VERIFY_CLIENT_TOTAL, SNMP_DB_ID_TLS, 24,
    sizeof(uint32_t), "FTPS_SESS_F_VERIFY_CLIENT_TOTAL" },
  { SNMP_DB_FTPS_SESS_F_VERIFY_CLIENT_ERR_TOTAL, SNMP_DB_ID_TLS, 28,
    sizeof(uint32_t), "FTPS_SESS_F_VERIFY_CLIENT_ERR_TOTAL" },

  /* ftps.tlsLogins fields */
  { SNMP_DB_FTPS_LOGINS_F_TOTAL, SNMP_DB_ID_TLS, 32,
    sizeof(uint32_t), "FTPS_LOGINS_F_TOTAL" },
  { SNMP_DB_FTPS_LOGINS_F_ERR_TOTAL, SNMP_DB_ID_TLS, 36,
    sizeof(uint32_t), "FTPS_LOGINS_F_ERR_TOTAL" },
  { SNMP_DB_FTPS_LOGINS_F_ERR_BAD_USER_TOTAL, SNMP_DB_ID_TLS, 40,
    sizeof(uint32_t), "FTPS_LOGINS_F_ERR_BAD_USER_TOTAL" },
  { SNMP_DB_FTPS_LOGINS_F_ERR_BAD_PASSWD_TOTAL, SNMP_DB_ID_TLS, 44,
    sizeof(uint32_t), "FTPS_LOGINS_F_ERR_BAD_PASSWD_TOTAL" },
  { SNMP_DB_FTPS_LOGINS_F_ERR_GENERAL_TOTAL, SNMP_DB_ID_TLS, 48,
    sizeof(uint32_t), "FTPS_LOGINS_F_ERR_GENERAL_TOTAL" },
  { SNMP_DB_FTPS_LOGINS_F_CERT_TOTAL, SNMP_DB_ID_TLS, 52,
    sizeof(uint32_t), "FTPS_LOGINS_F_CERT_TOTAL" },

  /* ftps.tlsDataTransfers fields */
  { SNMP_DB_FTPS_XFERS_F_DIR_LIST_COUNT, SNMP_DB_ID_TLS, 56,
    sizeof(uint32_t), "FTPS_XFERS_F_DIR_LIST_COUNT" },
  { SNMP_DB_FTPS_XFERS_F_DIR_LIST_TOTAL, SNMP_DB_ID_TLS, 60,
    sizeof(uint32_t), "FTPS_XFERS_F_DIR_LIST_TOTAL" },
  { SNMP_DB_FTPS_XFERS_F_DIR_LIST_ERR_TOTAL, SNMP_DB_ID_TLS, 64,
    sizeof(uint32_t), "FTPS_XFERS_F_DIR_LIST_ERR_TOTAL" },
  { SNMP_DB_FTPS_XFERS_F_FILE_UPLOAD_COUNT, SNMP_DB_ID_TLS, 68,
    sizeof(uint32_t), "FTPS_XFERS_F_FILE_UPLOAD_COUNT" },
  { SNMP_DB_FTPS_XFERS_F_FILE_UPLOAD_TOTAL, SNMP_DB_ID_TLS, 72,
    sizeof(uint32_t), "FTPS_XFERS_F_FILE_UPLOAD_TOTAL" },
  { SNMP_DB_FTPS_XFERS_F_FILE_UPLOAD_ERR_TOTAL, SNMP_DB_ID_TLS, 76,
    sizeof(uint32_t), "FTPS_XFERS_F_FILE_UPLOAD_ERR_TOTAL" },
  { SNMP_DB_FTPS_XFERS_F_FILE_DOWNLOAD_COUNT, SNMP_DB_ID_TLS, 80,
    sizeof(uint32_t), "FTPS_XFERS_F_FILE_DOWNLOAD_COUNT" },
  { SNMP_DB_FTPS_XFERS_F_FILE_DOWNLOAD_TOTAL, SNMP_DB_ID_TLS, 84,
    sizeof(uint32_t), "FTPS_XFERS_F_FILE_DOWNLOAD_TOTAL" },
  { SNMP_DB_FTPS_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL, SNMP_DB_ID_TLS, 88,
    sizeof(uint32_t), "FTPS_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL" },
  { SNMP_DB_FTPS_XFERS_F_KB_UPLOAD_TOTAL, SNMP_DB_ID_TLS, 92,
    sizeof(uint32_t), "FTPS_XFERS_F_KB_UPLOAD_TOTAL" },
  { SNMP_DB_FTPS_XFERS_F_KB_DOWNLOAD_TOTAL, SNMP_DB_ID_TLS, 96,
    sizeof(uint32_t), "FTPS_XFERS_F_KB_DOWNLOAD_TOTAL" },

  /* ssh.sshSessions fields */
  { SNMP_DB_SSH_SESS_F_KEX_ERR_TOTAL, SNMP_DB_ID_SSH, 0,
    sizeof(uint32_t), "SSH_SESS_F_KEX_ERR_TOTAL" },
  { SNMP_DB_SSH_SESS_F_C2S_COMPRESS_TOTAL, SNMP_DB_ID_SSH, 4,
    sizeof(uint32_t), "SSH_SESS_F_C2S_COMPRESS_TOTAL" },
  { SNMP_DB_SSH_SESS_F_S2C_COMPRESS_TOTAL, SNMP_DB_ID_SSH, 8,
    sizeof(uint32_t), "SSH_SESS_F_S2C_COMPRESS_TOTAL" },

  /* ssh.sshLogins fields */
  { SNMP_DB_SSH_LOGINS_F_HOSTBASED_TOTAL, SNMP_DB_ID_SSH, 12,
    sizeof(uint32_t), "SSH_LOGINS_F_HOSTBASED_TOTAL" },
  { SNMP_DB_SSH_LOGINS_F_HOSTBASED_ERR_TOTAL, SNMP_DB_ID_SSH, 16,
    sizeof(uint32_t), "SSH_LOGINS_F_HOSTBASED_ERR_TOTAL" },
  { SNMP_DB_SSH_LOGINS_F_KBDINT_TOTAL, SNMP_DB_ID_SSH, 20,
    sizeof(uint32_t), "SSH_LOGINS_F_KBDINT_TOTAL" },
  { SNMP_DB_SSH_LOGINS_F_KBDINT_ERR_TOTAL, SNMP_DB_ID_SSH, 24,
    sizeof(uint32_t), "SSH_LOGINS_F_KBDINT_ERR_TOTAL" },
  { SNMP_DB_SSH_LOGINS_F_PASSWD_TOTAL, SNMP_DB_ID_SSH, 28,
    sizeof(uint32_t), "SSH_LOGINS_F_PASSWD_TOTAL" },
  { SNMP_DB_SSH_LOGINS_F_PASSWD_ERR_TOTAL, SNMP_DB_ID_SSH, 32,
    sizeof(uint32_t), "SSH_LOGINS_F_PASSWD_ERR_TOTAL" },
  { SNMP_DB_SSH_LOGINS_F_PUBLICKEY_TOTAL, SNMP_DB_ID_SSH, 36,
    sizeof(uint32_t), "SSH_LOGINS_F_PUBLICKEY_TOTAL" },
  { SNMP_DB_SSH_LOGINS_F_PUBLICKEY_ERR_TOTAL, SNMP_DB_ID_SSH, 40,
    sizeof(uint32_t), "SSH_LOGINS_F_PUBLICKEY_ERR_TOTAL" },

  /* sftp.sftpSessions fields */
  { SNMP_DB_SFTP_SESS_F_SESS_COUNT, SNMP_DB_ID_SFTP, 0,
    sizeof(uint32_t), "SFTP_SESS_F_SESS_COUNT" },
  { SNMP_DB_SFTP_SESS_F_SESS_TOTAL, SNMP_DB_ID_SFTP, 4,
    sizeof(uint32_t), "SFTP_SESS_F_SESS_TOTAL" },
  { SNMP_DB_SFTP_SESS_F_SFTP_V3_TOTAL, SNMP_DB_ID_SFTP, 8,
    sizeof(uint32_t), "SFTP_SESS_F_SFTP_V3_TOTAL" },
  { SNMP_DB_SFTP_SESS_F_SFTP_V4_TOTAL, SNMP_DB_ID_SFTP, 12,
    sizeof(uint32_t), "SFTP_SESS_F_SFTP_V4_TOTAL" },
  { SNMP_DB_SFTP_SESS_F_SFTP_V5_TOTAL, SNMP_DB_ID_SFTP, 16,
    sizeof(uint32_t), "SFTP_SESS_F_SFTP_V5_TOTAL" },
  { SNMP_DB_SFTP_SESS_F_SFTP_V6_TOTAL, SNMP_DB_ID_SFTP, 20,
    sizeof(uint32_t), "SFTP_SESS_F_SFTP_V6_TOTAL" },

  /* sftp.sftpDataTransfers fields */
  { SNMP_DB_SFTP_XFERS_F_DIR_LIST_COUNT, SNMP_DB_ID_SFTP, 24,
    sizeof(uint32_t), "SFTP_XFERS_F_DIR_LIST_COUNT" },
  { SNMP_DB_SFTP_XFERS_F_DIR_LIST_TOTAL, SNMP_DB_ID_SFTP, 28,
    sizeof(uint32_t), "SFTP_XFERS_F_DIR_LIST_TOTAL" },
  { SNMP_DB_SFTP_XFERS_F_DIR_LIST_ERR_TOTAL, SNMP_DB_ID_SFTP, 32,
    sizeof(uint32_t), "SFTP_XFERS_F_DIR_LIST_ERR_TOTAL" },
  { SNMP_DB_SFTP_XFERS_F_FILE_UPLOAD_COUNT, SNMP_DB_ID_SFTP, 36,
    sizeof(uint32_t), "SFTP_XFERS_F_FILE_UPLOAD_COUNT" },
  { SNMP_DB_SFTP_XFERS_F_FILE_UPLOAD_TOTAL, SNMP_DB_ID_SFTP, 40,
    sizeof(uint32_t), "SFTP_XFERS_F_FILE_UPLOAD_TOTAL" },
  { SNMP_DB_SFTP_XFERS_F_FILE_UPLOAD_ERR_TOTAL, SNMP_DB_ID_SFTP, 44,
    sizeof(uint32_t), "SFTP_XFERS_F_FILE_UPLOAD_ERR_TOTAL" },
  { SNMP_DB_SFTP_XFERS_F_FILE_DOWNLOAD_COUNT, SNMP_DB_ID_SFTP, 48,
    sizeof(uint32_t), "SFTP_XFERS_F_FILE_DOWNLOAD_COUNT" },
  { SNMP_DB_SFTP_XFERS_F_FILE_DOWNLOAD_TOTAL, SNMP_DB_ID_SFTP, 52,
    sizeof(uint32_t), "SFTP_XFERS_F_FILE_DOWNLOAD_TOTAL" },
  { SNMP_DB_SFTP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL, SNMP_DB_ID_SFTP, 56,
    sizeof(uint32_t), "SFTP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL" },
  { SNMP_DB_SFTP_XFERS_F_KB_UPLOAD_TOTAL, SNMP_DB_ID_SFTP, 60,
    sizeof(uint32_t), "SFTP_XFERS_F_KB_UPLOAD_TOTAL" },
  { SNMP_DB_SFTP_XFERS_F_KB_DOWNLOAD_TOTAL, SNMP_DB_ID_SFTP, 64,
    sizeof(uint32_t), "SFTP_XFERS_F_KB_DOWNLOAD_TOTAL" },

  /* scp.scpSessions fields */
  { SNMP_DB_SCP_SESS_F_SESS_COUNT, SNMP_DB_ID_SCP, 0,
    sizeof(uint32_t), "SCP_SESS_F_SESS_COUNT" },
  { SNMP_DB_SCP_SESS_F_SESS_TOTAL, SNMP_DB_ID_SCP, 4,
    sizeof(uint32_t), "SCP_SESS_F_SESS_TOTAL" },

  /* scp.scpDataTransfers fields */
  { SNMP_DB_SCP_XFERS_F_FILE_UPLOAD_COUNT, SNMP_DB_ID_SCP, 8,
    sizeof(uint32_t), "SCP_XFERS_F_FILE_UPLOAD_COUNT" },
  { SNMP_DB_SCP_XFERS_F_FILE_UPLOAD_TOTAL, SNMP_DB_ID_SCP, 12,
    sizeof(uint32_t), "SCP_XFERS_F_FILE_UPLOAD_TOTAL" },
  { SNMP_DB_SCP_XFERS_F_FILE_UPLOAD_ERR_TOTAL, SNMP_DB_ID_SCP, 16,
    sizeof(uint32_t), "SCP_XFERS_F_FILE_UPLOAD_ERR_TOTAL" },
  { SNMP_DB_SCP_XFERS_F_FILE_DOWNLOAD_COUNT, SNMP_DB_ID_SCP, 20,
    sizeof(uint32_t), "SCP_XFERS_F_FILE_DOWNLOAD_COUNT" },
  { SNMP_DB_SCP_XFERS_F_FILE_DOWNLOAD_TOTAL, SNMP_DB_ID_SCP, 24,
    sizeof(uint32_t), "SCP_XFERS_F_FILE_DOWNLOAD_TOTAL" },
  { SNMP_DB_SCP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL, SNMP_DB_ID_SCP, 28,
    sizeof(uint32_t), "SCP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL" },
  { SNMP_DB_SCP_XFERS_F_KB_UPLOAD_TOTAL, SNMP_DB_ID_SCP, 32,
    sizeof(uint32_t), "SCP_XFERS_F_KB_UPLOAD_TOTAL" },
  { SNMP_DB_SCP_XFERS_F_KB_DOWNLOAD_TOTAL, SNMP_DB_ID_SCP, 36,
    sizeof(uint32_t), "SCP_XFERS_F_KB_DOWNLOAD_TOTAL" },

  /* ban.connections fields */
  { SNMP_DB_BAN_CONNS_F_CONN_BAN_TOTAL, SNMP_DB_ID_BAN, 0,
    sizeof(uint32_t), "BAN_CONNS_F_CONN_BAN_TOTAL" },
  { SNMP_DB_BAN_CONNS_F_USER_BAN_TOTAL, SNMP_DB_ID_BAN, 4,
    sizeof(uint32_t), "BAN_CONNS_F_USER_BAN_TOTAL" },
  { SNMP_DB_BAN_CONNS_F_HOST_BAN_TOTAL, SNMP_DB_ID_BAN, 8,
    sizeof(uint32_t), "BAN_CONNS_F_HOST_BAN_TOTAL" },
  { SNMP_DB_BAN_CONNS_F_CLASS_BAN_TOTAL, SNMP_DB_ID_BAN, 12,
    sizeof(uint32_t), "BAN_CONNS_F_CLASS_BAN_TOTAL" },

  /* ban.bans fields */
  { SNMP_DB_BAN_BANS_F_BAN_COUNT, SNMP_DB_ID_BAN, 16,
    sizeof(uint32_t), "BAN_BANS_F_BAN_COUNT" },
  { SNMP_DB_BAN_BANS_F_BAN_TOTAL, SNMP_DB_ID_BAN, 20,
    sizeof(uint32_t), "BAN_BANS_F_BAN_TOTAL" },
  { SNMP_DB_BAN_BANS_F_USER_BAN_COUNT, SNMP_DB_ID_BAN, 24,
    sizeof(uint32_t), "BAN_BANS_F_USER_BAN_COUNT" },
  { SNMP_DB_BAN_BANS_F_USER_BAN_TOTAL, SNMP_DB_ID_BAN, 28,
    sizeof(uint32_t), "BAN_BANS_F_USER_BAN_TOTAL" },
  { SNMP_DB_BAN_BANS_F_HOST_BAN_COUNT, SNMP_DB_ID_BAN, 32,
    sizeof(uint32_t), "BAN_BANS_F_HOST_BAN_COUNT" },
  { SNMP_DB_BAN_BANS_F_HOST_BAN_TOTAL, SNMP_DB_ID_BAN, 36,
    sizeof(uint32_t), "BAN_BANS_F_HOST_BAN_TOTAL" },
  { SNMP_DB_BAN_BANS_F_CLASS_BAN_COUNT, SNMP_DB_ID_BAN, 40,
    sizeof(uint32_t), "BAN_BANS_F_CLASS_BAN_COUNT" },
  { SNMP_DB_BAN_BANS_F_CLASS_BAN_TOTAL, SNMP_DB_ID_BAN, 44,
    sizeof(uint32_t), "BAN_BANS_F_CLASS_BAN_TOTAL" },
  
  { 0, -1, 0, 0 }
};

struct snmp_db_info {
  int db_id;
  int db_fd;
  const char *db_name;
  char *db_path;
  void *db_data;
  size_t db_datasz;
};

static struct snmp_db_info snmp_dbs[] = {
  { SNMP_DB_ID_UNKNOWN, -1, NULL, NULL, 0 },

  /* This "table" is synthetic; nothing to be persisted to disk. */
  { SNMP_DB_ID_NOTIFY, -1, "notify.dat", NULL, NULL, 0 },

  /* This "table" is comprised purely of values in memory; nothing to be
   * persisted to disk.
   */
  { SNMP_DB_ID_CONN, -1, "conn.dat", NULL, NULL, 0 },

  /* Eight numeric fields only in this table: 8 x 4 bytes = 32 bytes */
  { SNMP_DB_ID_DAEMON, -1, "daemon.dat", NULL, NULL, 32 },

  /* The size of the timeouts table is calculated as:
   *
   *  4 timeout fields        x 4 bytes = 16 bytes
   *
   * for a total of 16 bytes.
   */
  { SNMP_DB_ID_TIMEOUTS, -1, "timeouts.dat", NULL, NULL, 16 },
 
  /* The size of the ftp table is calculated as:
   *
   *  3 session fields        x 4 bytes = 12 bytes
   *  7 login fields          x 4 bytes = 28 bytes
   *  11 data transfer fields x 4 bytes = 44 bytes
   *
   * for a total of 84 bytes.
   */
  { SNMP_DB_ID_FTP, -1, "ftp.dat", NULL, NULL, 84 },

  /* The size of the snmp table is calculated as:
   *
   *  4 fields                x 4 bytes = 20 bytes
   */
  { SNMP_DB_ID_SNMP, -1, "snmp.dat", NULL, NULL, 20 },

  /* The size of the ftps table is calculated as:
   *
   *  8 session fields        x 4 bytes = 32 bytes
   *  6 login fields          x 4 bytes = 24 bytes
   *  11 data transfer fields x 4 bytes = 44 bytes
   *
   * for a total of 100 bytes.
   */
  { SNMP_DB_ID_TLS, -1, "tls.dat", NULL, NULL, 100 },

  /* The size of the ssh table is calculated as:
   *
   *  3 session fields        x 4 bytes = 12 bytes
   *  8 auth fields           x 4 bytes = 32 bytes
   *
   * for a total of 40 bytes.
   */
  { SNMP_DB_ID_SSH, -1, "ssh.dat", NULL, NULL, 44 },

  /* The size of the sftp table is calculated as:
   *
   *  6 session fields        x 4 bytes = 24 bytes
   *  11 data transfer fields x 4 bytes = 44 bytes
   *
   * for a total of 68 bytes.
   */
  { SNMP_DB_ID_SFTP, -1, "sftp.dat", NULL, NULL, 68 },

  /* The size of the scp table is calculated as:
   *
   *  2 session fields        x 4 bytes =  8 bytes
   *  8 data transfer fields  x 4 bytes = 32 bytes
   *
   * for a total of 40 bytes.
   */
  { SNMP_DB_ID_SCP, -1, "scp.dat", NULL, NULL, 40 },

  /* The size of the ban table is calculated as:
   *
   *  12 ban fields            x 4 bytes = 48 bytes
   *
   * for a total of 48 bytes.
   */
  { SNMP_DB_ID_BAN, -1, "ban.dat", NULL, NULL, 48 },

#if 0
  { SNMP_DB_ID_SQL, -1, "sql.dat", NULL, NULL, 0 },

  { SNMP_DB_ID_QUOTA, -1, "quota.dat", NULL, NULL, 0 },

  { SNMP_DB_ID_GEOIP, -1, "geoip.dat", NULL, NULL, 0 }
#endif

  { -1, -1, NULL, NULL, 0 },
};

/* For the given field, provision the corresponding lock start and len
 * values, for the byte-range locking.
 */
static int get_field_range(unsigned int field, off_t *field_start,
    size_t *field_len) {
  register unsigned int i;
  int field_idx = -1;

  if (field_start == NULL &&
      field_len == NULL) {
    /* Nothing to do here. */
    return 0;
  }

  for (i = 0; snmp_fields[i].db_id > 0; i++) {
    if (snmp_fields[i].field == field) {
      field_idx = i;
      break;
    }
  }

  if (field_idx < 0) {
    errno = ENOENT;
    return -1;
  }

  if (field_start != NULL) {
    *field_start = snmp_fields[field_idx].field_start;
  }

  if (field_len != NULL) {
    *field_len = snmp_fields[field_idx].field_len;
  }

  return 0;
}

static const char *get_lock_type(struct flock *lock) {
  const char *lock_type;

  switch (lock->l_type) {
    case F_RDLCK:
      lock_type = "read";
      break;

    case F_WRLCK:
      lock_type = "write";
      break;

    case F_UNLCK:
      lock_type = "unlock";
      break;

    default:
      lock_type = "[unknown]";
  }

  return lock_type;
}

int snmp_db_get_field_db_id(unsigned int field) {
  register unsigned int i;
  int db_id = -1;

  for (i = 0; snmp_fields[i].db_id > 0; i++) {
    if (snmp_fields[i].field == field) {
      db_id = snmp_fields[i].db_id;
      break;
    }
  }

  if (db_id < 0) {
    errno = ENOENT;
  }

  return db_id;
}

const char *snmp_db_get_fieldstr(pool *p, unsigned int field) {
  register unsigned int i;
  char fieldstr[256];
  int db_id = -1;
  const char *db_name = NULL, *field_name = NULL;

  for (i = 0; snmp_fields[i].db_id > 0; i++) {
    if (snmp_fields[i].field == field) {
      db_id = snmp_fields[i].db_id;
      field_name = snmp_fields[i].field_name;
      break;
    }
  }

  if (db_id < 0) {
    return NULL;
  }

  db_name = snmp_dbs[db_id].db_name;

  memset(fieldstr, '\0', sizeof(fieldstr));
  pr_snprintf(fieldstr, sizeof(fieldstr)-1, "%s (%d) [%s (%d)]",
    field_name, field, db_name, db_id);
  return pstrdup(p, fieldstr);
}

int snmp_db_rlock(unsigned int field) {
  struct flock lock;
  unsigned int nattempts = 1;
  int db_id, db_fd;
  size_t field_len;

  lock.l_type = F_RDLCK;
  lock.l_whence = SEEK_SET;

  db_id = snmp_db_get_field_db_id(field);
  if (db_id < 0) {
    return -1;
  }

  db_fd = snmp_dbs[db_id].db_fd;
  if (get_field_range(field, &(lock.l_start), &field_len) < 0) {
    return -1;
  }
  lock.l_len = (off_t) field_len;

  pr_trace_msg(trace_channel, 9,
    "attempt #%u to read-lock field %u db ID %d table '%s' "
    "(fd %d start %lu len %lu)", nattempts, field, db_id,
    snmp_dbs[db_id].db_path, db_fd, (unsigned long) lock.l_start,
    (unsigned long) lock.l_len);

  while (fcntl(db_fd, F_SETLK, &lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg(trace_channel, 3, "read-lock of table fd %d failed: %s",
      db_fd, strerror(xerrno));
    if (xerrno == EACCES) {
      struct flock locker;

      /* Get the PID of the process blocking this lock. */
      if (fcntl(db_fd, F_GETLK, &locker) == 0) {
        pr_trace_msg(trace_channel, 3, "process ID %lu has blocking %s lock on "
          "table fd %d, start %lu len %lu", (unsigned long) locker.l_pid,
          get_lock_type(&locker), db_fd, (unsigned long) lock.l_start,
          (unsigned long) lock.l_len);
      }
    }

    if (xerrno == EAGAIN ||
        xerrno == EACCES) {
      /* Treat this as an interrupted call, call pr_signals_handle() (which
       * will delay for a few msecs because of EINTR), and try again.
       * After SNMP_MAX_LOCK_ATTEMPTS attempts, give up altogether.
       */

      nattempts++;
      if (nattempts <= SNMP_MAX_LOCK_ATTEMPTS) {
        errno = EINTR;

        pr_signals_handle();

        errno = 0;
        pr_trace_msg(trace_channel, 9,
          "attempt #%u to read-lock table fd %d", nattempts, db_fd);
        continue;
      }

      pr_trace_msg(trace_channel, 3,
        "unable to acquire read-lock on table fd %d: %s", db_fd,
        strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 9,
    "read-lock of field %u table fd %d (start %lu len %lu) successful",
    field, db_fd, (unsigned long) lock.l_start, (unsigned long) lock.l_len);
  return 0;
}

int snmp_db_wlock(unsigned int field) {
  struct flock lock;
  unsigned int nattempts = 1;
  int db_id, db_fd;
  size_t field_len;

  lock.l_type = F_WRLCK;
  lock.l_whence = SEEK_SET;

  db_id = snmp_db_get_field_db_id(field);
  if (db_id < 0) {
    return -1;
  }

  db_fd = snmp_dbs[db_id].db_fd;
  if (get_field_range(field, &(lock.l_start), &field_len) < 0) {
    return -1;
  }
  lock.l_len = (off_t) field_len;

  pr_trace_msg(trace_channel, 9,
    "attempt #%u to write-lock field %u db ID %d table '%s' "
    "(fd %d start %lu len %lu)", nattempts, field, db_id,
    snmp_dbs[db_id].db_path, db_fd, (unsigned long) lock.l_start,
    (unsigned long) lock.l_len);

  while (fcntl(db_fd, F_SETLK, &lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg(trace_channel, 3, "write-lock of table fd %d failed: %s",
      db_fd, strerror(xerrno));
    if (xerrno == EACCES) {
      struct flock locker;

      /* Get the PID of the process blocking this lock. */
      if (fcntl(db_fd, F_GETLK, &locker) == 0) {
        pr_trace_msg(trace_channel, 3, "process ID %lu has blocking %s lock on "
          "table fd %d, start %lu len %lu", (unsigned long) locker.l_pid,
          get_lock_type(&locker), db_fd, (unsigned long) lock.l_start,
          (unsigned long) lock.l_len);
      }
    }

    if (xerrno == EAGAIN ||
        xerrno == EACCES) {
      /* Treat this as an interrupted call, call pr_signals_handle() (which
       * will delay for a few msecs because of EINTR), and try again.
       * After SNMP_MAX_LOCK_ATTEMPTS attempts, give up altogether.
       */

      nattempts++;
      if (nattempts <= SNMP_MAX_LOCK_ATTEMPTS) {
        errno = EINTR;

        pr_signals_handle();

        errno = 0;
        pr_trace_msg(trace_channel, 9,
          "attempt #%u to write-lock table fd %d", nattempts, db_fd);
        continue;
      }

      pr_trace_msg(trace_channel, 3,
        "unable to acquire write-lock on table fd %d: %s", db_fd,
        strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 9,
    "write-lock of field %u table fd %d (start %lu len %lu) successful",
    field, db_fd, (unsigned long) lock.l_start, (unsigned long) lock.l_len);
  return 0;
}

int snmp_db_unlock(unsigned int field) {
  struct flock lock;
  unsigned int nattempts = 1;
  int db_id, db_fd;
  size_t field_len;

  lock.l_type = F_UNLCK;
  lock.l_whence = SEEK_SET;

  db_id = snmp_db_get_field_db_id(field);
  if (db_id < 0) {
    return -1;
  }

  db_fd = snmp_dbs[db_id].db_fd;
  if (get_field_range(field, &(lock.l_start), &field_len) < 0) {
    return -1;
  }
  lock.l_len = (off_t) field_len;

  pr_trace_msg(trace_channel, 9,
    "attempt #%u to unlock field %u table '%s' (fd %d start %lu len %lu)",
    nattempts, field, snmp_dbs[db_id].db_path, db_fd,
    (unsigned long) lock.l_start, (unsigned long) lock.l_len);

  while (fcntl(db_fd, F_SETLK, &lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg(trace_channel, 3, "unlock of table fd %d failed: %s",
      db_fd, strerror(xerrno));
    if (xerrno == EACCES) {
      struct flock locker;

      /* Get the PID of the process blocking this lock. */
      if (fcntl(db_fd, F_GETLK, &locker) == 0) {
        pr_trace_msg(trace_channel, 3, "process ID %lu has blocking %s lock on "
          "table fd %d, start %lu len %lu", (unsigned long) locker.l_pid,
          get_lock_type(&locker), db_fd, (unsigned long) lock.l_start,
          (unsigned long) lock.l_len);
      }
    }

    if (xerrno == EAGAIN ||
        xerrno == EACCES) {
      /* Treat this as an interrupted call, call pr_signals_handle() (which
       * will delay for a few msecs because of EINTR), and try again.
       * After SNMP_MAX_LOCK_ATTEMPTS attempts, give up altogether.
       */

      nattempts++;
      if (nattempts <= SNMP_MAX_LOCK_ATTEMPTS) {
        errno = EINTR;

        pr_signals_handle();

        errno = 0;
        pr_trace_msg(trace_channel, 9,
          "attempt #%u to unlock table fd %d", nattempts, db_fd);
        continue;
      }

      pr_trace_msg(trace_channel, 3,
        "unable to acquire unlock on table fd %d: %s", db_fd,
        strerror(xerrno));
    }

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 9,
    "unlock of field %u table fd %d (start %lu len %lu) successful",
    field, db_fd, (unsigned long) lock.l_start, (unsigned long) lock.l_len);
  return 0;
}

int snmp_db_open(pool *p, int db_id) {
  int db_fd, mmap_flags, xerrno;
  char *db_path;
  size_t db_datasz;
  void *db_data;

  if (db_id < 0) {
    errno = EINVAL;
    return -1;
  }

  /* First, see if the database is already opened. */
  if (snmp_dbs[db_id].db_path != NULL) {
    return 0;
  }

  pr_trace_msg(trace_channel, 19,
    "opening db ID %d (db root = %s, db name = %s)", db_id, snmp_db_root,
    snmp_dbs[db_id].db_name);

  db_path = pdircat(p, snmp_db_root, snmp_dbs[db_id].db_name, NULL);

  PRIVS_ROOT
  db_fd = open(db_path, O_RDWR|O_CREAT, 0600);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (db_fd < 0) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "error opening SNMPTable '%s': %s", db_path, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  /* Make sure the fd isn't one of the big three. */
  (void) pr_fs_get_usable_fd2(&db_fd);

  pr_trace_msg(trace_channel, 19, "opened fd %d for SNMPTable '%s'", db_fd,
    db_path);

  snmp_dbs[db_id].db_fd = db_fd;
  snmp_dbs[db_id].db_path = db_path;

  db_datasz = snmp_dbs[db_id].db_datasz;

  /* Truncate the table first; any existing data should be deleted. */
  if (ftruncate(db_fd, 0) < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error truncating SNMPTable '%s' to size 0: %s", db_path,
      strerror(xerrno));

    (void) snmp_db_close(p, db_id);
    errno = xerrno;
    return -1;
  }

  /* Seek to the desired table size (actually, one byte less than the desired
   * size) and write a single byte, so that there's enough allocated backing
   * store on the filesystem to support the ensuing mmap() call.
   */
  if (lseek(db_fd, db_datasz, SEEK_SET) < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error seeking to %lu in table '%s': %s",
      (unsigned long) db_datasz-1, db_path, strerror(xerrno));

    (void) snmp_db_close(p, db_id);
    errno = xerrno;
    return -1;
  }

  if (write(db_fd, "", 1) != 1) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error writing single byte to table '%s': %s", db_path, strerror(xerrno));

    (void) snmp_db_close(p, db_id);
    errno = xerrno;
    return -1;
  }

  mmap_flags = MAP_SHARED;

  /* Make sure to set the fd to -1 if MAP_ANON(YMOUS) is used.  By definition,
   * anonymous mapped memory does not need (or want) a valid file backing
   * store; some implementations will not do what is expected when anonymous
   * memory is requested AND a valid fd is passed in.
   *
   * However, we want to keep a valid fd open anyway, for later use by
   * fcntl(2) for byte range locking; we simply don't use the valid fd for
   * the mmap(2) call.
   */

#if defined(MAP_ANONYMOUS)
  /* Linux */
  mmap_flags |= MAP_ANONYMOUS;
  db_fd = -1;

#elif defined(MAP_ANON)
  /* FreeBSD, MacOSX, Solaris, others? */
  mmap_flags |= MAP_ANON;
  db_fd = -1;

#else
  (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
    "mmap(2) MAP_ANONYMOUS and MAP_ANON flags not defined");
#endif

  db_data = mmap(NULL, db_datasz, PROT_READ|PROT_WRITE, mmap_flags, db_fd, 0);
  if (db_data == MAP_FAILED) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error mapping table '%s' fd %d size %lu into memory: %s", db_path,
      db_fd, (unsigned long) db_datasz, strerror(xerrno));

    (void) snmp_db_close(p, db_id);
    errno = xerrno;
    return -1;
  }

  snmp_dbs[db_id].db_data = db_data;

  /* Make sure the data are zeroed. */
  memset(db_data, 0, db_datasz);

  return 0;
}

int snmp_db_close(pool *p, int db_id) {
  int db_fd, res;
  void *db_data;

  if (db_id < 0) {
    errno = EINVAL;
    return -1;
  }

  db_data = snmp_dbs[db_id].db_data;

  if (db_data != NULL) {
    size_t db_datasz;

    db_datasz = snmp_dbs[db_id].db_datasz;

    if (munmap(db_data, db_datasz) < 0) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 1,
        "error unmapping SNMPTable '%s' from memory: %s",
        pdircat(p, snmp_db_root, snmp_dbs[db_id].db_path, NULL),
        strerror(xerrno));

      errno = xerrno;
      return -1;
    }
  }

  snmp_dbs[db_id].db_data = NULL;

  db_fd = snmp_dbs[db_id].db_fd;
  res = close(db_fd);
  if (res < 0) {
    return -1;
  }

  snmp_dbs[db_id].db_fd = -1;
  return 0;
}

int snmp_db_get_value(pool *p, unsigned int field, int32_t *int_value,
    char **str_value, size_t *str_valuelen) {
  void *db_data, *field_data;
  int db_id, res;
  off_t field_start;
  size_t field_len;

  switch (field) {
    case SNMP_DB_NOTIFY_F_SYS_UPTIME: {
      struct timeval start_tv, now_tv;

      /* TimeTicks are in hundredths of seconds since start time. */
      res = snmp_uptime_get(p, &start_tv);
      if (res < 0)
        return -1;

      gettimeofday(&now_tv, NULL);

      *int_value = (int32_t) (((now_tv.tv_sec - start_tv.tv_sec) * 100) +
        ((now_tv.tv_usec - start_tv.tv_usec) / 10000));

      pr_trace_msg(trace_channel, 19,
        "read value %lu for field %s", (unsigned long) *int_value,
        snmp_db_get_fieldstr(p, field));
      return 0;
    }

    case SNMP_DB_CONN_F_SERVER_NAME:
      if (main_server->ServerName == NULL) {
        errno = ENOENT;
        return -1;
      }

      *str_value = (char *) main_server->ServerName;
      *str_valuelen = strlen(*str_value);

      pr_trace_msg(trace_channel, 19,
        "read value '%s' for field %s", *str_value,
        snmp_db_get_fieldstr(p, field));
      return 0;

    case SNMP_DB_CONN_F_SERVER_ADDR:
      if (session.c == NULL) {
        errno = ENOENT;
        return -1;
      }

      *str_value = (char *) pr_netaddr_get_ipstr(session.c->local_addr);
      *str_valuelen = strlen(*str_value);

      pr_trace_msg(trace_channel, 19,
        "read value '%s' for field %s", *str_value,
        snmp_db_get_fieldstr(p, field));
      return 0;

    case SNMP_DB_CONN_F_SERVER_PORT:
      if (session.c == NULL) {
        errno = ENOENT;
        return -1;
      }

      *int_value = ntohs(pr_netaddr_get_port(session.c->remote_addr));
      pr_trace_msg(trace_channel, 19,
        "read value %lu for field %s", (unsigned long) *int_value,
        snmp_db_get_fieldstr(p, field));
      return 0;

    case SNMP_DB_CONN_F_CLIENT_ADDR:
      if (session.c == NULL) {
        errno = ENOENT;
        return -1;
      }

      *str_value = (char *) pr_netaddr_get_ipstr(session.c->remote_addr);
      *str_valuelen = strlen(*str_value);

      pr_trace_msg(trace_channel, 19,
        "read value '%s' for field %s", *str_value,
        snmp_db_get_fieldstr(p, field));
      return 0;

    case SNMP_DB_CONN_F_PID:
      *int_value = session.pid;
      pr_trace_msg(trace_channel, 19,
        "read value %lu for field %s", (unsigned long) *int_value,
        snmp_db_get_fieldstr(p, field));
      return 0;

    case SNMP_DB_CONN_F_USER_NAME: {
      const char *orig_user;

      orig_user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
      if (orig_user == NULL) {
        errno = ENOENT;
        return -1;
      }
    
      *str_value = (char *) orig_user;
      *str_valuelen = strlen(*str_value);  

      pr_trace_msg(trace_channel, 19,
        "read value '%s' for field %s", *str_value,
        snmp_db_get_fieldstr(p, field));
      return 0;
    }

    case SNMP_DB_CONN_F_PROTOCOL: {
      const char *proto;

      proto = pr_session_get_protocol(0);
   
      *str_value = (char *) proto;
      *str_valuelen = strlen(*str_value);

      pr_trace_msg(trace_channel, 19,
        "read value '%s' for field %s", *str_value,
        snmp_db_get_fieldstr(p, field));
      return 0;
    }

    case SNMP_DB_DAEMON_F_SOFTWARE:
      *str_value = "proftpd";
      *str_valuelen = strlen(*str_value);

      pr_trace_msg(trace_channel, 19,
        "read value '%s' for field %s", *str_value,
        snmp_db_get_fieldstr(p, field));
      return 0;

    case SNMP_DB_DAEMON_F_VERSION:
      *str_value = "ProFTPD Version " PROFTPD_VERSION_TEXT " (built at " BUILD_STAMP ")";
      *str_valuelen = strlen(*str_value);

      pr_trace_msg(trace_channel, 19,
        "read value '%s' for field %s", *str_value,
        snmp_db_get_fieldstr(p, field));
      return 0;

    case SNMP_DB_DAEMON_F_ADMIN:
      *str_value = (char *) main_server->ServerAdmin;
      *str_valuelen = strlen(*str_value);

      pr_trace_msg(trace_channel, 19,
        "read value '%s' for field %s", *str_value,
        snmp_db_get_fieldstr(p, field));
      return 0;

    case SNMP_DB_DAEMON_F_UPTIME: {
      struct timeval now_tv;

      /* TimeTicks are in hundredths of seconds since start time. */
      gettimeofday(&now_tv, NULL);

      *int_value = (int32_t) (((now_tv.tv_sec - snmp_start_tv.tv_sec) * 100) +
        ((now_tv.tv_usec - snmp_start_tv.tv_usec) / 10000));

      pr_trace_msg(trace_channel, 19,
        "read value %lu for field %s", (unsigned long) *int_value,
        snmp_db_get_fieldstr(p, field));
      return 0;
    }

    case SNMP_DB_DAEMON_F_MAXINST_CONF:
      *int_value = ServerMaxInstances;

      pr_trace_msg(trace_channel, 19,
        "read value %lu for field %s", (unsigned long) *int_value,
        snmp_db_get_fieldstr(p, field));
      return 0;

    default:
      break;
  }

  db_id = snmp_db_get_field_db_id(field);
  if (db_id < 0) {
    return -1;
  }

  if (get_field_range(field, &field_start, &field_len) < 0) {
    return -1;
  }

  res = snmp_db_rlock(field);
  if (res < 0) {
    return -1;
  }

  db_data = snmp_dbs[db_id].db_data;
  field_data = &(((uint32_t *) db_data)[field_start]);
  memmove(int_value, field_data, field_len);

  res = snmp_db_unlock(field);
  if (res < 0) {
    return -1;
  }

  pr_trace_msg(trace_channel, 19,
    "read value %lu for field %s", (unsigned long) *int_value,
     snmp_db_get_fieldstr(p, field));
  return 0;
}

int snmp_db_incr_value(pool *p, unsigned int field, int32_t incr) {
  uint32_t orig_val, new_val;
  int db_id, res;
  void *db_data, *field_data;
  off_t field_start;
  size_t field_len;

  db_id = snmp_db_get_field_db_id(field);
  if (db_id < 0) {
    return -1;
  }

  if (get_field_range(field, &field_start, &field_len) < 0) {
    return -1;
  }

  res = snmp_db_wlock(field);
  if (res < 0) {
    return -1;
  }

  db_data = snmp_dbs[db_id].db_data;
  field_data = &(((uint32_t *) db_data)[field_start]);
  memmove(&new_val, field_data, field_len);
  orig_val = new_val;

  if (orig_val == 0 &&
      incr < 0) {
    /* If we are in fact decrementing a value, and that value is
     * already zero, then do nothing.
     */

    res = snmp_db_unlock(field);
    if (res < 0) {
      return -1;
    }

    pr_trace_msg(trace_channel, 19,
      "value already zero for field %s (%d), not decrementing by %ld",
      snmp_db_get_fieldstr(p, field), field, (long) incr);
    return 0;
  }

  new_val += incr;
  memmove(field_data, &new_val, field_len);

#if 0
  res = msync(field_data, field_len, MS_SYNC);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "msync(2) error for field %s (%d): %s",
      snmp_db_get_fieldstr(p, field), field, strerror(errno));  
  }
#endif

  res = snmp_db_unlock(field);
  if (res < 0) {
    return -1;
  }

  pr_trace_msg(trace_channel, 19,
    "wrote value %lu (was %lu) for field %s (%d)", (unsigned long) new_val,
    (unsigned long) orig_val, snmp_db_get_fieldstr(p, field), field);
  return 0;
}

int snmp_db_reset_value(pool *p, unsigned int field) {
  uint32_t val;
  int db_id, res;
  void *db_data, *field_data;
  off_t field_start;
  size_t field_len;

  db_id = snmp_db_get_field_db_id(field);
  if (db_id < 0) {
    return -1;
  }

  if (get_field_range(field, &field_start, &field_len) < 0) {
    return -1;
  }

  res = snmp_db_wlock(field);
  if (res < 0) {
    return -1;
  }

  db_data = snmp_dbs[db_id].db_data;
  field_data = &(((uint32_t *) db_data)[field_start]);

  val = 0;
  memmove(field_data, &val, field_len);

  res = snmp_db_unlock(field);
  if (res < 0) {
    return -1;
  }

  pr_trace_msg(trace_channel, 19,
    "reset value to 0 for field %s", snmp_db_get_fieldstr(p, field));
  return 0;
}

int snmp_db_set_root(const char *db_root) {
  if (db_root == NULL) {
    errno = EINVAL;
    return -1;
  }

  snmp_db_root = db_root;
  return 0;
}
