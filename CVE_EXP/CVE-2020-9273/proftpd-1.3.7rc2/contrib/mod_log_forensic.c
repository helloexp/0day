/*
 * mod_log_forensic - a buffering log module for aiding in server behavior
 *                    forensic analysis
 * Copyright (c) 2011-2017 TJ Saunders
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

#include "conf.h"
#include "privs.h"

#include <sys/uio.h>

#define MOD_LOG_FORENSIC_VERSION		"mod_log_forensic/0.2"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030403
# error "ProFTPD 1.3.4rc3 or later required"
#endif

module log_forensic_module;

static pool *forensic_pool = NULL;
static int forensic_engine = FALSE;
static int forensic_logfd = -1;

/* Criteria for flushing out the "forensic" logs. */
#define FORENSIC_CRIT_FAILED_LOGIN		0x00001
#define FORENSIC_CRIT_MODULE_CONFIG		0x00002
#define FORENSIC_CRIT_UNTIMELY_DEATH		0x00004

#define FORENSIC_CRIT_DEFAULT \
  (FORENSIC_CRIT_FAILED_LOGIN|FORENSIC_CRIT_UNTIMELY_DEATH)

static unsigned long forensic_criteria = FORENSIC_CRIT_DEFAULT;

/* Use a ring buffer for the cached/buffered log messages; the index pointing
 * to where to stash the next message then moves around the ring.
 *
 * Overwritten messages will be allocated of a module-specific pool.  To
 * prevent this pool from growing unboundedly, we need to clear/destroy it
 * periodically.  But doing this without having to re-copy all of the
 * buffered log lines could be expensive.
 *
 * Instead, what if we use subpools, for every 1/10th of the ring.  When
 * the last message for a subpool is purged/overwritten, that subpool can
 * be destroyed without effecting any existing message in the ring.
 */

#define FORENSIC_DEFAULT_NMSGS		1024

/* Regardless of the configured ForensicLogBufferSize, this defines the
 * number of messages per sub-pool.
 *
 * Why 256 messages per sub-pool?
 *
 *  80 chars (avg) per message * 256 messages = 20 KB
 *
 * This means that a given sub-pool will hold roughly 20 KB.  Which means
 * that 20 KB + ring max size is the largest memory that mod_log_forensic
 * should hold, before releasing a sub-pool back to the Pool API.
 */

#define FORENSIC_DEFAULT_MSGS_PER_POOL		256
static unsigned int forensic_msgs_per_pool = FORENSIC_DEFAULT_MSGS_PER_POOL;

struct forensic_msg {
  pool *fm_pool;
  unsigned int fm_pool_msgno;

  unsigned int fm_log_type;
  int fm_log_level;
  const char *fm_msg;
  size_t fm_msglen;
};

static struct forensic_msg **forensic_msgs = NULL;
static unsigned int forensic_nmsgs = FORENSIC_DEFAULT_NMSGS;
static unsigned int forensic_msg_idx = 0;

static pool *forensic_subpool = NULL;
static unsigned int forensic_subpool_msgno = 1;

#define FORENSIC_MAX_LEVELS	50
static const char *forensic_log_levels[] = {
  "0",   "1",  "2",  "3",  "4",  "5",  "6",  "7",  "8",  "9",
  "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
  "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
  "30", "31", "32", "33", "34", "35", "36", "37", "38", "39",
  "40", "41", "42", "43", "44", "45", "46", "47", "48", "49"
};

/* Necessary prototypes */
static int forensic_sess_init(void);

static void forensic_add_msg(unsigned int log_type, int log_level,
    const char *log_msg, size_t log_msglen) {
  struct forensic_msg *fm;
  pool *sub_pool;
  char *fm_msg;

  /* Get the message that's currently in the ring where we want add our new
   * one.
   */
  fm = forensic_msgs[forensic_msg_idx];
  if (fm) {
    /* If this message is the last one of it subpool, destroy that pool. */
    if (fm->fm_pool_msgno == forensic_msgs_per_pool) {
      destroy_pool(fm->fm_pool);
    }

    forensic_msgs[forensic_msg_idx] = NULL;
  }

  /* Add this message into the ring. */
  sub_pool = pr_pool_create_sz(forensic_subpool, 128);
  fm = pcalloc(sub_pool, sizeof(struct forensic_msg)); 
  fm->fm_pool = sub_pool;
  fm->fm_pool_msgno = forensic_subpool_msgno;
  fm->fm_log_type = log_type;
  fm->fm_log_level = log_level;

  fm_msg = palloc(fm->fm_pool, log_msglen + 1);
  memcpy(fm_msg, log_msg, log_msglen);
  fm_msg[log_msglen] = '\0';   

  fm->fm_msg = fm_msg;
  fm->fm_msglen = log_msglen;

  forensic_msgs[forensic_msg_idx] = fm;

  forensic_msg_idx += 1;
  if (forensic_msg_idx == forensic_nmsgs) {
    /* Wrap around */
    forensic_msg_idx = 0;
  }

  if (forensic_subpool_msgno == forensic_msgs_per_pool) {
    /* Time to create a new subpool */
    forensic_subpool = pr_pool_create_sz(forensic_pool, 256);
    forensic_subpool_msgno = 1;

  } else {
    forensic_subpool_msgno++;
  }
}

static const char *forensic_get_begin_marker(unsigned int criterion,
    size_t *markerlen) {
  const char *marker = NULL;

  switch (criterion) {
    case FORENSIC_CRIT_FAILED_LOGIN:
      marker = "-----BEGIN FAILED LOGIN FORENSICS-----\n";
      break;

    case FORENSIC_CRIT_MODULE_CONFIG:
      marker = "-----BEGIN MODULE CONFIG FORENSICS-----\n"; 
      break;

    case FORENSIC_CRIT_UNTIMELY_DEATH:
      marker = "-----BEGIN UNTIMELY DEATH FORENSICS-----\n";
      break;
  }

  if (marker != NULL) {
    *markerlen = strlen(marker);
  }

  return marker;
}

static const char *forensic_get_end_marker(unsigned int criterion,
    size_t *markerlen) {
  const char *marker = NULL;

  switch (criterion) {
    case FORENSIC_CRIT_FAILED_LOGIN:
      marker = "-----END FAILED LOGIN FORENSICS-----\n";
      break;

    case FORENSIC_CRIT_MODULE_CONFIG:
      marker = "-----END MODULE CONFIG FORENSICS-----\n";
      break;
    
    case FORENSIC_CRIT_UNTIMELY_DEATH:
      marker = "-----END UNTIMELY DEATH FORENSICS-----\n";
      break;
  }

  if (marker != NULL) {
    *markerlen = strlen(marker);
  }

  return marker;
}

/* Rather than deal with some homegrown itoa() sort of thing for converting
 * the log level number to an easily printable string, I'm using the level
 * as an index in a precomputed array of strings.
 */
static const char *forensic_get_level_str(int log_level) {
  int i;

  i = log_level;
  if (i < 0) {
    i = 0;
  }

  if (i >= FORENSIC_MAX_LEVELS) {
    return "N";
  }

  return forensic_log_levels[i];
}

static void forensic_write_metadata(void) {
  const char *client_ip, *server_ip, *proto, *unique_id;
  int server_port;
  char server_port_str[32], uid_str[32], gid_str[32], elapsed_str[64],
    raw_bytes_in_str[64], raw_bytes_out_str[64],
    total_bytes_in_str[64], total_bytes_out_str[64],
    total_files_in_str[64], total_files_out_str[64];
  size_t unique_idlen = 0;

  /* 64 vectors is currently more than necessary, but it's better to have
   * too many than too little.
   */
  struct iovec iov[64];
  int niov = 0, res;
  uint64_t now;
  unsigned long elapsed_ms;

  /* Write session metadata in key/value message headers:
   *
   * Client-Address:
   * Server-Address:
   * Elapsed:
   * Protocol:
   * User:
   * UID:
   * GID:
   * [UNIQUE_ID:]
   * Raw-Bytes-In:
   * Raw-Bytes-Out:
   * Total-Bytes-In:
   * Total-Bytes-Out:
   * Total-Files-In:
   * Total-Files-Out:
   */

  client_ip = pr_netaddr_get_ipstr(pr_netaddr_get_sess_remote_addr());
  server_ip = pr_netaddr_get_ipstr(pr_netaddr_get_sess_local_addr());
  server_port = ntohs(pr_netaddr_get_port(pr_netaddr_get_sess_local_addr()));

  /* Client address */
  iov[niov].iov_base = "Client-Address: ";
  iov[niov].iov_len = 16;
  niov++;

  iov[niov].iov_base = (void *) client_ip;
  iov[niov].iov_len = strlen(client_ip);
  niov++;

  iov[niov].iov_base = "\n";
  iov[niov].iov_len = 1;
  niov++;

  /* Server address */
  iov[niov].iov_base = "Server-Address: ";
  iov[niov].iov_len = 16;
  niov++;

  iov[niov].iov_base = (void *) server_ip;
  iov[niov].iov_len = strlen(server_ip);
  niov++;

  memset(server_port_str, '\0', sizeof(server_port_str));
  res = pr_snprintf(server_port_str, sizeof(server_port_str)-1, ":%d\n",
    server_port);
  iov[niov].iov_base = server_port_str;
  iov[niov].iov_len = res;
  niov++;

  /* Elapsed (in ms) */
  iov[niov].iov_base = "Elapsed: ";
  iov[niov].iov_len = 9;
  niov++;

  pr_gettimeofday_millis(&now);
  elapsed_ms = (unsigned long) (now - session.connect_time_ms);

  memset(elapsed_str, '\0', sizeof(elapsed_str));
  res = pr_snprintf(elapsed_str, sizeof(elapsed_str)-1, "%lu\n", elapsed_ms);
  iov[niov].iov_base = (void *) elapsed_str;
  iov[niov].iov_len = res;
  niov++;

  /* Protocol */
  proto = pr_session_get_protocol(0);
  iov[niov].iov_base = "Protocol: ";
  iov[niov].iov_len = 10;
  niov++;

  iov[niov].iov_base = (char *) proto;
  iov[niov].iov_len = strlen(proto);
  niov++;

  iov[niov].iov_base = "\n";
  iov[niov].iov_len = 1;
  niov++;

  /* User */
  if (session.user) {
    iov[niov].iov_base = "User: ";
    iov[niov].iov_len = 6;
    niov++;

    iov[niov].iov_base = (void *) session.user;
    iov[niov].iov_len = strlen(session.user);
    niov++;

    iov[niov].iov_base = "\n";
    iov[niov].iov_len = 1;
    niov++;
  }

  /* UID */
  iov[niov].iov_base = "UID: ";
  iov[niov].iov_len = 5;
  niov++;

  memset(uid_str, '\0', sizeof(uid_str));
  res = pr_snprintf(uid_str, sizeof(uid_str)-1, "%lu\n",
    (unsigned long) geteuid());
  iov[niov].iov_base = uid_str;
  iov[niov].iov_len = res;
  niov++;

  /* GID */
  iov[niov].iov_base = "GID: ";
  iov[niov].iov_len = 5;
  niov++;

  memset(gid_str, '\0', sizeof(gid_str));
  res = pr_snprintf(gid_str, sizeof(gid_str)-1, "%lu\n",
    (unsigned long) getegid());
  iov[niov].iov_base = gid_str;
  iov[niov].iov_len = res;
  niov++;

  /* UNIQUE_ID (from mod_unique_id), if present. */
  unique_id = pr_table_get(session.notes, "UNIQUE_ID", &unique_idlen);
  if (unique_id != NULL) {
    iov[niov].iov_base = "UNIQUE_ID: ";
    iov[niov].iov_len = 11;
    niov++;

    iov[niov].iov_base = (char *) unique_id;
    iov[niov].iov_len = unique_idlen;
    niov++;

    iov[niov].iov_base = "\n";
    iov[niov].iov_len = 1;
    niov++;
  }

  /* Raw bytes in */
  iov[niov].iov_base = "Raw-Bytes-In: ";
  iov[niov].iov_len = 14;
  niov++;

  if (session.total_raw_in == 0) {
    iov[niov].iov_base = "0\n";
    iov[niov].iov_len = 2;
    niov++;

  } else {
    memset(raw_bytes_in_str, '\0', sizeof(raw_bytes_in_str));
    res = pr_snprintf(raw_bytes_in_str, sizeof(raw_bytes_in_str)-1,
      "%" PR_LU "\n", (pr_off_t) session.total_raw_in);
    iov[niov].iov_base = raw_bytes_in_str;
    iov[niov].iov_len = res;
    niov++;
  }

  /* Raw bytes out */
  iov[niov].iov_base = "Raw-Bytes-Out: ";
  iov[niov].iov_len = 15;
  niov++;

  if (session.total_raw_out == 0) {
    iov[niov].iov_base = "0\n";
    iov[niov].iov_len = 2;
    niov++;

  } else {
    memset(raw_bytes_out_str, '\0', sizeof(raw_bytes_out_str));
    res = pr_snprintf(raw_bytes_out_str, sizeof(raw_bytes_out_str)-1,
      "%" PR_LU "\n", (pr_off_t) session.total_raw_out);
    iov[niov].iov_base = raw_bytes_out_str;
    iov[niov].iov_len = res;
    niov++;
  }

  /* Total bytes in */
  iov[niov].iov_base = "Total-Bytes-In: ";
  iov[niov].iov_len = 16;
  niov++;

  if (session.total_bytes_in == 0) {
    iov[niov].iov_base = "0\n";
    iov[niov].iov_len = 2;
    niov++;

  } else {
    memset(total_bytes_in_str, '\0', sizeof(total_bytes_in_str));
    res = pr_snprintf(total_bytes_in_str, sizeof(total_bytes_in_str)-1,
      "%" PR_LU "\n", (pr_off_t) session.total_bytes_in);
    iov[niov].iov_base = total_bytes_in_str;
    iov[niov].iov_len = res;
    niov++;
  } 

  /* Total bytes out */
  iov[niov].iov_base = "Total-Bytes-Out: ";
  iov[niov].iov_len = 17;
  niov++;

  if (session.total_bytes_out == 0) {
    iov[niov].iov_base = "0\n";
    iov[niov].iov_len = 2;
    niov++;

  } else {
    memset(total_bytes_out_str, '\0', sizeof(total_bytes_out_str));
    res = pr_snprintf(total_bytes_out_str, sizeof(total_bytes_out_str)-1,
      "%" PR_LU "\n", (pr_off_t) session.total_bytes_out);
    iov[niov].iov_base = total_bytes_out_str;
    iov[niov].iov_len = res;
    niov++;
  }

  /* Total files in */
  iov[niov].iov_base = "Total-Files-In: ";
  iov[niov].iov_len = 16;
  niov++;

  if (session.total_files_in == 0) {
    iov[niov].iov_base = "0\n";
    iov[niov].iov_len = 2;
    niov++;

  } else {
    memset(total_files_in_str, '\0', sizeof(total_files_in_str));
    res = pr_snprintf(total_files_in_str, sizeof(total_files_in_str)-1,
      "%u\n", session.total_files_in);
    iov[niov].iov_base = total_files_in_str;
    iov[niov].iov_len = res;
    niov++;
  }

  /* Total files out */
  iov[niov].iov_base = "Total-Files-Out: ";
  iov[niov].iov_len = 17;
  niov++;

  if (session.total_files_out == 0) {
    iov[niov].iov_base = "0\n";
    iov[niov].iov_len = 2;
    niov++;

  } else {
    memset(total_files_out_str, '\0', sizeof(total_files_out_str));
    res = pr_snprintf(total_files_out_str, sizeof(total_files_out_str)-1,
      "%u\n", session.total_files_out);
    iov[niov].iov_base = total_files_out_str;
    iov[niov].iov_len = res;
    niov++;
  }

  iov[niov].iov_base = "\n";
  iov[niov].iov_len = 1;
  niov++;

  res = writev(forensic_logfd, iov, niov);
}

static void forensic_write_msgs(unsigned int criterion) {
  register unsigned int i;
  unsigned int start_idx, end_idx;
  int res;
  const char *crit_marker = NULL;
  size_t crit_markerlen = 0;

  /* XXX An interesting optimization would be to rework this code so that
   * we used writev(2) to write out the buffer as quickly as possible,
   * taking IOV_MAX into account.
   */

  crit_marker = forensic_get_begin_marker(criterion, &crit_markerlen);
  if (crit_marker != NULL) {
    res = write(forensic_logfd, crit_marker, crit_markerlen);
  }

  forensic_write_metadata();

  /* The head of the log messages (i.e. the oldest message) is always where we
   * want to place the newest message.
   */
  start_idx = forensic_msg_idx;
  end_idx = forensic_msg_idx - 1;
  if (forensic_msg_idx == 0) {
    end_idx = forensic_nmsgs - 1;
  }

  i = start_idx;
  while (i != end_idx) {
    struct forensic_msg *fm;

    pr_signals_handle();

    fm = forensic_msgs[i];
    if (fm != NULL) {
      const char *level;
      size_t level_len;

      level = forensic_get_level_str(fm->fm_log_level);
      level_len = strlen(level);

      switch (fm->fm_log_type) {
        case PR_LOG_TYPE_UNSPEC:
          res = write(forensic_logfd, "[Unspec:", 8);
          res = write(forensic_logfd, level, level_len);
          res = write(forensic_logfd, "] ", 2);
          break;

        case PR_LOG_TYPE_XFERLOG:
          res = write(forensic_logfd, "[TransferLog:", 13);
          res = write(forensic_logfd, level, level_len);
          res = write(forensic_logfd, "] ", 2);
          break;

        case PR_LOG_TYPE_SYSLOG: {
          char pid_str[32];

          res = write(forensic_logfd, "[syslog:", 8);
          res = write(forensic_logfd, level, level_len);

          /* syslogd normally adds the PID; we thus need to add the PID in
           * here as well, to aid in the correlation of these log lines
           * with other tools/diagnostics.
           */
          res = write(forensic_logfd, ", PID ", 6);

          memset(pid_str, '\0', sizeof(pid_str));
          res = pr_snprintf(pid_str, sizeof(pid_str)-1, "%lu",
            (unsigned long) (session.pid ? session.pid : getpid()));
          res = write(forensic_logfd, pid_str, res);

          res = write(forensic_logfd, "] ", 2);
          break;
        }

        case PR_LOG_TYPE_SYSTEMLOG:
          res = write(forensic_logfd, "[SystemLog:", 11);
          res = write(forensic_logfd, level, level_len);
          res = write(forensic_logfd, "] ", 2);
          break;

        case PR_LOG_TYPE_EXTLOG:
          res = write(forensic_logfd, "[ExtendedLog:", 13);
          res = write(forensic_logfd, level, level_len);
          res = write(forensic_logfd, "] ", 2);
          break;

        case PR_LOG_TYPE_TRACELOG:
          res = write(forensic_logfd, "[TraceLog:", 10);
          res = write(forensic_logfd, level, level_len);
          res = write(forensic_logfd, "] ", 2);
          break;
      }

      res = write(forensic_logfd, fm->fm_msg, fm->fm_msglen);
      while (res < 0) {
        if (errno == EINTR) {
          pr_signals_handle();
          res = write(forensic_logfd, fm->fm_msg, fm->fm_msglen);
          continue;
        }
      }

      /* syslog-type messages don't have a newline appended to them, since
       * syslogd handles that.  So we then need to add our own newline here.
       */
      if (fm->fm_log_type == PR_LOG_TYPE_SYSLOG) {
        res = write(forensic_logfd, "\n", 1);
      }

      if (fm->fm_pool_msgno == forensic_msgs_per_pool) {
        destroy_pool(fm->fm_pool);
      }

      forensic_msgs[i] = NULL;
    }

    i++;
    if (i == forensic_nmsgs) {
      /* Wrap around */
      i = 0;
    }
  }

  crit_marker = forensic_get_end_marker(criterion, &crit_markerlen);
  if (crit_marker != NULL) {
    res = write(forensic_logfd, crit_marker, crit_markerlen);
  }
}

/* Configuration handlers
 */

/* usage: ForensicLogBufferSize count */
MODRET set_forensiclogbuffersize(cmd_rec *cmd) {
  config_rec *c;
  unsigned int count;
  char *ptr = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  count = strtoul(cmd->argv[1], &ptr, 10);
  if (ptr && *ptr) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "badly formatted number: ",
      cmd->argv[1], NULL));
  }

  if (count == 0) {
    CONF_ERROR(cmd, "size must be greater than zero");
  }
 
  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = count;

  return PR_HANDLED(cmd);
}

/* usage: ForensicLogCapture type1 ... typeN */
MODRET set_forensiclogcapture(cmd_rec *cmd) {
  config_rec *c;
  int unspec_listen = FALSE;
  int xferlog_listen = FALSE;
  int syslog_listen = FALSE;
  int systemlog_listen = FALSE;
  int extlog_listen = FALSE;
  int tracelog_listen = FALSE;
  register unsigned int i;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  for (i = 1; i < cmd->argc; i++) {
    if (strncasecmp(cmd->argv[i], "Unspec", 7) == 0 ||
        strncasecmp(cmd->argv[i], "Unknown", 8) == 0) {
      unspec_listen = TRUE;

    } else if (strncasecmp(cmd->argv[i], "TransferLog", 12) == 0) {
      xferlog_listen = TRUE;

    } else if (strncasecmp(cmd->argv[i], "Syslog", 7) == 0) {
      syslog_listen = TRUE;

    } else if (strncasecmp(cmd->argv[i], "SystemLog", 10) == 0) {
      systemlog_listen = TRUE;

    } else if (strncasecmp(cmd->argv[i], "ExtendedLog", 12) == 0) {
      extlog_listen = TRUE;

    } else if (strncasecmp(cmd->argv[i], "TraceLog", 9) == 0) {
      tracelog_listen = TRUE;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown log type: ",
        cmd->argv[i], NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 6, NULL, NULL, NULL, NULL, NULL, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = unspec_listen;
  c->argv[1] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = xferlog_listen;
  c->argv[2] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[2]) = syslog_listen;
  c->argv[3] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[3]) = systemlog_listen;
  c->argv[4] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[4]) = extlog_listen;
  c->argv[5] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[5]) = tracelog_listen;

  return PR_HANDLED(cmd);
}

/* usage: ForensicLogCriteria ... */
MODRET set_forensiclogcriteria(cmd_rec *cmd) {
  config_rec *c;
  unsigned long criteria = 0UL;
  register unsigned int i;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* Possible criteria:
   *
   *  FailedLogin
   *  ModuleConfig
   *  UntimelyDeath
   */

  for (i = 1; i < cmd->argc; i++) {
    if (strncasecmp(cmd->argv[i], "FailedLogin", 12) == 0) {
      criteria |= FORENSIC_CRIT_FAILED_LOGIN;

    } else if (strncasecmp(cmd->argv[i], "ModuleConfig", 13) == 0) {
      criteria |= FORENSIC_CRIT_MODULE_CONFIG;

    } else if (strncasecmp(cmd->argv[i], "UntimelyDeath", 14) == 0) {
      criteria |= FORENSIC_CRIT_UNTIMELY_DEATH;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown criterion: ",
        cmd->argv[i], NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = criteria;

  return PR_HANDLED(cmd);
}

/* usage: ForensicLogEngine on|off */
MODRET set_forensiclogengine(cmd_rec *cmd) {
  config_rec *c;
  int bool;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: ForensicLogFile path */
MODRET set_forensiclogfile(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET forensic_pass_err(cmd_rec *cmd) {
  if (!forensic_engine) {
    return PR_DECLINED(cmd);
  }

  if (forensic_criteria & FORENSIC_CRIT_FAILED_LOGIN) {
    forensic_write_msgs(FORENSIC_CRIT_FAILED_LOGIN);
  }

  return PR_DECLINED(cmd);
}

/* Event Listeners
 */

static void forensic_exit_ev(const void *event_data, void *user_data) {

  switch (session.disconnect_reason) {
    case PR_SESS_DISCONNECT_SIGNAL:
      if (forensic_criteria & FORENSIC_CRIT_UNTIMELY_DEATH) {
        forensic_write_msgs(FORENSIC_CRIT_UNTIMELY_DEATH);
      }
      break;

    case PR_SESS_DISCONNECT_MODULE_ACL:
      if (forensic_criteria & FORENSIC_CRIT_MODULE_CONFIG) {
        forensic_write_msgs(FORENSIC_CRIT_MODULE_CONFIG);
      }
      break;
  }

  return;
}

static void forensic_log_ev(const void *event_data, void *user_data) {
  const pr_log_event_t *le;

  le = event_data;
  forensic_add_msg(le->log_type, le->log_level, le->log_msg, le->log_msglen);
}

#if defined(PR_SHARED_MODULE)
static void forensic_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_log_forensic.c", (const char *) event_data) == 0) {
    pr_event_unregister(&log_forensic_module, NULL, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

static void forensic_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&log_forensic_module, "core.exit", forensic_exit_ev);
  pr_event_unregister(&log_forensic_module, "core.log.unspec", forensic_log_ev);
  pr_event_unregister(&log_forensic_module, "core.log.xferlog",
    forensic_log_ev);
  pr_event_unregister(&log_forensic_module, "core.log.syslog", forensic_log_ev);
  pr_event_unregister(&log_forensic_module, "core.log.systemlog",
    forensic_log_ev);
  pr_event_unregister(&log_forensic_module, "core.log.extlog", forensic_log_ev);
  pr_event_unregister(&log_forensic_module, "core.log.tracelog",
    forensic_log_ev);
  pr_event_unregister(&log_forensic_module, "core.session-reinit",
    forensic_sess_reinit_ev);

  forensic_engine = FALSE;
  (void) close(forensic_logfd);
  forensic_logfd = -1;
  forensic_criteria = FORENSIC_CRIT_DEFAULT;
  forensic_msgs = NULL;
  forensic_nmsgs = FORENSIC_DEFAULT_NMSGS;
  forensic_msg_idx = 0;

  if (forensic_subpool != NULL) {
    destroy_pool(forensic_subpool);
    forensic_subpool = NULL;
  }

  forensic_subpool_msgno = 1;

  res = forensic_sess_init();
  if (res < 0) {
    pr_session_disconnect(&log_forensic_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Module Initialization
 */

static int forensic_init(void) {
#if defined(PR_SHARED_MODULE)
  pr_event_register(&log_forensic_module, "core.module-unload",
    forensic_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  return 0;
}

static int forensic_sess_init(void) {
  config_rec *c;
  int unspec_listen = TRUE;
  int xferlog_listen = TRUE;
  int syslog_listen = TRUE;
  int systemlog_listen = TRUE;
  int extlog_listen = TRUE;
  int tracelog_listen = TRUE;
  int res, xerrno;

  pr_event_register(&log_forensic_module, "core.session-reinit",
    forensic_sess_reinit_ev, NULL);

  /* Is this module enabled? */
  c = find_config(main_server->conf, CONF_PARAM, "ForensicLogEngine", FALSE);
  if (c != NULL) {
    forensic_engine = *((int *) c->argv[0]);
  }

  if (forensic_engine != TRUE) {
    return 0;
  }

  /* Do we have the required path for our logging? */
  c = find_config(main_server->conf, CONF_PARAM, "ForensicLogFile", FALSE);
  if (c == NULL) {
    pr_log_debug(DEBUG1, MOD_LOG_FORENSIC_VERSION
      ": missing required ForensicLogFile setting, disabling module");
    forensic_engine = FALSE;
    return 0;
  }

  pr_signals_block();
  PRIVS_ROOT
  res = pr_log_openfile((const char *) c->argv[0], &forensic_logfd, 0640);
  xerrno = errno;
  PRIVS_RELINQUISH
  pr_signals_unblock();

  if (res < 0) {
    const char *path;

    path = c->argv[0];

    if (res == -1) {
      pr_log_pri(PR_LOG_NOTICE, MOD_LOG_FORENSIC_VERSION
        ": notice: unable to open ForensicLogFile '%s': %s", path,
        strerror(xerrno));

    } else if (res == PR_LOG_WRITABLE_DIR) {
      pr_log_pri(PR_LOG_WARNING, MOD_LOG_FORENSIC_VERSION
        ": notice: unable to open ForensicLogFile '%s': parent directory is "
        "world-writable", path);

    } else if (res == PR_LOG_SYMLINK) {
      pr_log_pri(PR_LOG_WARNING, MOD_LOG_FORENSIC_VERSION
        ": notice: unable to open ForensicLogFile '%s': "
        "cannot log to a symlink", path);
    }

    pr_log_debug(DEBUG0, MOD_LOG_FORENSIC_VERSION
      ": unable to ForensicLogFile '%s', disabling module", path);
    forensic_engine = FALSE;
    return 0;
  }

  /* Are there any log types for which we shouldn't be listening? */
  c = find_config(main_server->conf, CONF_PARAM, "ForensicLogCapture", FALSE);
  if (c) {
    unspec_listen = *((int *) c->argv[0]);
    xferlog_listen = *((int *) c->argv[1]);
    syslog_listen = *((int *) c->argv[2]);
    systemlog_listen = *((int *) c->argv[3]);
    extlog_listen = *((int *) c->argv[4]);
    tracelog_listen = *((int *) c->argv[5]);
  }

  /* What criteria are we to use for logging our captured log messages */
  c = find_config(main_server->conf, CONF_PARAM, "ForensicLogCriteria", FALSE);
  if (c) {
    forensic_criteria = *((unsigned long *) c->argv[0]);
  }

  if (forensic_pool == NULL) {
    forensic_pool = make_sub_pool(session.pool);
    pr_pool_tag(forensic_pool, MOD_LOG_FORENSIC_VERSION);
  }

  c = find_config(main_server->conf, CONF_PARAM, "ForensicLogBufferSize",
    FALSE);
  if (c) {
    forensic_nmsgs = *((unsigned int *) c->argv[0]);

    if (forensic_nmsgs < forensic_msgs_per_pool) {
      forensic_msgs_per_pool = forensic_nmsgs;
    }
  }

  forensic_msgs = pcalloc(forensic_pool,
    sizeof(struct forensic_msg) * forensic_nmsgs);
  forensic_subpool = pr_pool_create_sz(forensic_pool, 256);

  /* We register our event listeners as the last thing we do. */

  if ((forensic_criteria & FORENSIC_CRIT_MODULE_CONFIG) ||
      (forensic_criteria & FORENSIC_CRIT_UNTIMELY_DEATH)) {
    pr_event_register(&log_forensic_module, "core.exit", forensic_exit_ev,
      NULL);
  }

  if (unspec_listen) {
    pr_event_register(&log_forensic_module, "core.log.unspec", forensic_log_ev,
      NULL);
  }

  if (xferlog_listen) {
    pr_event_register(&log_forensic_module, "core.log.xferlog", forensic_log_ev,
      NULL);
  }

  if (syslog_listen) {
    pr_event_register(&log_forensic_module, "core.log.syslog", forensic_log_ev,
      NULL);
  }

  if (systemlog_listen) {
    pr_event_register(&log_forensic_module, "core.log.systemlog",
      forensic_log_ev, NULL);
  }

  if (extlog_listen) {
    pr_event_register(&log_forensic_module, "core.log.extlog", forensic_log_ev,
      NULL);
  }

  if (tracelog_listen) {
    pr_event_register(&log_forensic_module, "core.log.tracelog",
      forensic_log_ev, NULL);
  }

  return 0;
}

/* Module API tables
 */

static conftable forensic_conftab[] = {
  { "ForensicLogBufferSize",	set_forensiclogbuffersize,	NULL },
  { "ForensicLogCapture",	set_forensiclogcapture,		NULL },
  { "ForensicLogCriteria",	set_forensiclogcriteria,	NULL },
  { "ForensicLogEngine",	set_forensiclogengine,		NULL },
  { "ForensicLogFile",		set_forensiclogfile,		NULL },

  { NULL, NULL, NULL }
};

static cmdtable forensic_cmdtab[] = {
  { LOG_CMD_ERR, C_PASS,	G_NONE,	forensic_pass_err, FALSE, FALSE },

  { 0, NULL }
};

module log_forensic_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "log_forensic",

  /* Module configuration directive table */
  forensic_conftab,

  /* Module command handler table */
  forensic_cmdtab,

  /* Module auth handler table */
  NULL,

  /* Module initialization */
  forensic_init,

  /* Session initialization */
  forensic_sess_init,

  /* Module version */
  MOD_LOG_FORENSIC_VERSION
};

