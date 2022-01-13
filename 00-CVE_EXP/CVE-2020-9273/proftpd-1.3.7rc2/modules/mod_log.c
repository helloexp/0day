/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2017 The ProFTPD Project team
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
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* Flexible logging module for proftpd */

#include "conf.h"
#include "privs.h"
#include "logfmt.h"
#include "jot.h"

#define MOD_LOG_VERSION				"mod_log/1.0"

module log_module;

/* Max path length plus 128 bytes for additional info. */
#define EXTENDED_LOG_BUFFER_SIZE		(PR_TUNABLE_PATH_MAX + 128)

#define EXTENDED_LOG_MODE			0644
#define EXTENDED_LOG_FORMAT_DEFAULT		"default"

typedef struct logformat_struc	logformat_t;
typedef struct logfile_struc 	logfile_t;

struct logformat_struc {
  logformat_t *next, *prev;

  char *lf_fmt_name;
  unsigned char	*lf_format;
};

struct logfile_struc {
  logfile_t		*next, *prev;

  char			*lf_filename;
  int			lf_fd;
  int			lf_syslog_level;

  logformat_t		*lf_format;
  pr_jot_filters_t	*lf_jot_filters;

  /* Pointer to the "owning" configuration */
  config_rec		*lf_conf;
};

/* Value for lf_fd signalling that data should be logged via syslog, rather
 * than written to a file.
 */
#define EXTENDED_LOG_SYSLOG	-4

static pool *log_pool = NULL;
static logformat_t *formats = NULL;
static xaset_t *format_set = NULL;
static logfile_t *logs = NULL;
static xaset_t *log_set = NULL;

static const char *trace_channel = "extlog";

/* format string args:
   %A			- Anonymous username (password given)
   %a			- Remote client IP address
   %b			- Bytes sent for request
   %{basename}		- Basename of path
   %c			- Class
   %D			- full directory path
   %d			- directory (for client)
   %E			- End-of-session reason
   %{FOOBAR}e		- Contents of environment variable FOOBAR
   %F			- Transfer path (filename for client)
   %f			- Filename
   %g			- Local user's primary group name
   %H                   - Local IP address of server handling session
   %h			- Remote client DNS name
   %I                   - Total number of "raw" bytes read in from network
   %J                   - Request (command) arguments (file.txt, etc)
   %L                   - Local IP address contacted by client
   %l			- Remote logname (from identd)
   %m			- Request (command) method (RETR, etc)
   %O                   - Total number of "raw" bytes written out to network
   %P                   - Process ID of child serving request
   %p			- Port of server serving request
   %R                   - Response time for command/request, in milliseconds
   %r			- Full request (command)
   %s			- Response code (status)
   %S                   - Response string
   %T			- Time taken to transfer file, in seconds
   %t			- Time
   %{format}t		- Formatted time (strftime(3) format)
   %U                   - Original username sent by client
   %u			- Local user
   %V                   - DNS name of server serving request
   %v			- ServerName of server serving request
   %w                   - RNFR path ("whence" a rename comes, i.e. the source)
   %{epoch}             - Unix epoch (seconds since Jan 1 1970)
   %{file-modified}     - Indicates whether a file is being modified
                          (i.e. already exists) or not.
   %{file-offset}       - Contains the offset at which the file is read/written
   %{file-size}         - Contains the file size at the end of the transfer
   %{iso8601}           - ISO-8601 timestamp: YYYY-MM-dd HH:mm:ss,SSS
                            for example: "1999-11-27 15:49:37,459"
   %{microsecs}         - 6 digits of microseconds of current time
   %{millisecs}         - 3 digits of milliseconds of current time
   %{protocol}          - Current protocol (e.g. "ftp", "sftp", etc)
   %{uid}               - UID of logged-in user
   %{gid}               - Primary GID of logged-in user
   %{transfer-failure}  - reason, or "-"
   %{transfer-millisecs}- Time taken to transfer file, in milliseconds
   %{transfer-status}   - "success", "failed", "cancelled", "timeout", or "-"
   %{transfer-type}     - "binary" or "ASCII"
   %{version}           - ProFTPD version
*/

/* Necessary prototypes */
static int log_sess_init(void);
static void log_xfer_stalled_ev(const void *, void *);

static void parse_logformat(const char *directive, char *fmt_name,
    char *fmt_text) {
  int res;
  pool *tmp_pool;
  pr_jot_ctx_t *jot_ctx;
  pr_jot_parsed_t *jot_parsed;
  unsigned char format_buf[4096] = {'\0'};
  size_t fmt_len;
  logformat_t *lf;

  /* This function can cause potential problems.  Custom LogFormats
   * might overrun the format buffer.  Fixing this problem involves a
   * rewrite of most of this module.  This will happen post 1.2.0.
   */

  tmp_pool = make_sub_pool(log_pool);
  jot_ctx = pcalloc(tmp_pool, sizeof(pr_jot_ctx_t));
  jot_parsed = pcalloc(tmp_pool, sizeof(pr_jot_parsed_t));
  jot_parsed->bufsz = jot_parsed->buflen = sizeof(format_buf);
  jot_parsed->ptr = jot_parsed->buf = format_buf;

  jot_ctx->log = jot_parsed;

  res = pr_jot_parse_logfmt(tmp_pool, fmt_text, jot_ctx, pr_jot_parse_on_meta,
    pr_jot_parse_on_unknown, pr_jot_parse_on_other, 0);
  if (res < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_LOG_VERSION
      ": error parsing LogFormat '%s': %s", fmt_text, strerror(errno));

    destroy_pool(tmp_pool);
    return;
  }

  fmt_len = jot_parsed->bufsz - jot_parsed->buflen;

  lf = (logformat_t *) pcalloc(log_pool, sizeof(logformat_t));
  lf->lf_fmt_name = pstrdup(log_pool, fmt_name);
  lf->lf_format = palloc(log_pool, fmt_len + 1);
  memcpy(lf->lf_format, format_buf, fmt_len);
  lf->lf_format[fmt_len] = '\0';

  if (format_set == NULL) {
    format_set = xaset_create(log_pool, NULL);
  }

  xaset_insert_end(format_set, (xasetmember_t *) lf);
  formats = (logformat_t *) format_set->xas_list;

  if (directive != NULL) {
    config_rec *c;
    char *ptr;

    /* Store the parsed format in the config tree as well, for use by other
     * logging-related modules.
     */
    c = add_config_param(directive, 2, NULL, NULL);
    c->argv[0] = pstrdup(c->pool, fmt_name);
    c->argv[1] = palloc(c->pool, fmt_len + 1);

    ptr = c->argv[1];
    memcpy(ptr, format_buf, fmt_len);
    ptr[fmt_len] = '\0';
  }

  destroy_pool(tmp_pool);
}

/* Syntax: LogFormat name "format string" */
MODRET set_logformat(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 2);
  CHECK_CONF(cmd, CONF_ROOT);

  if (strlen(cmd->argv[1]) == 0) {
    CONF_ERROR(cmd, "missing required name parameter");
  }

  parse_logformat(cmd->argv[0], cmd->argv[1], cmd->argv[2]);
  return PR_HANDLED(cmd);
}

/* Syntax: ExtendedLog file [<cmd-classes> [<name>]] */
MODRET set_extendedlog(cmd_rec *cmd) {
  config_rec *c = NULL;
  int argc;
  char *path;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  argc = cmd->argc;

  if (argc < 2) {
    CONF_ERROR(cmd, "Syntax: ExtendedLog file [<cmd-classes> [<name>]]");
  }

  c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);

  path = cmd->argv[1];
  if (strncasecmp(path, "syslog:", 7) == 0) {
    char *ptr;

    ptr = strchr(path, ':');

    if (pr_log_str2sysloglevel(++ptr) < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown syslog level: '",
        ptr, "'", NULL));
    }

    c->argv[0] = pstrdup(log_pool, path);

  } else if (path[0] != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "relative paths not allowed: '",
      path, "'", NULL));

  } else {
    c->argv[0] = pstrdup(log_pool, path);
  }

  if (argc > 2) {
    pr_jot_filters_t *jot_filters;
    const char *rules;

    rules = cmd->argv[2];
    jot_filters = pr_jot_filters_create(c->pool, rules,
      PR_JOT_FILTER_TYPE_CLASSES, 0);
    if (jot_filters == NULL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "invalid log class in '", rules,
        "': ", strerror(errno), NULL));
    }

    c->argv[1] = jot_filters;
  }

  if (argc > 3) {
    c->argv[2] = pstrdup(log_pool, cmd->argv[3]);
  }

  return PR_HANDLED(cmd);
}

/* Syntax: AllowLogSymlinks <on|off> */
MODRET set_allowlogsymlinks(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* Syntax: ServerLog <filename> */
MODRET set_serverlog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);

  return PR_HANDLED(cmd);
}

/* Syntax: SystemLog <filename> */
MODRET set_systemlog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

static struct tm *get_gmtoff(int *tz) {
  time_t now;
  struct tm *gmt, *tm = NULL;

  /* Note that the ordering of the calls to gmtime(3) and pr_localtime()
   * here are IMPORTANT; gmtime(3) MUST be called first.  Otherwise,
   * the TZ environment variable may not be honored as one would expect;
   * see:
   *  https://forums.proftpd.org/smf/index.php/topic,11971.0.html
   */
  time(&now);
  gmt = gmtime(&now);
  if (gmt != NULL) {
    int days, hours, minutes;

    tm = pr_localtime(NULL, &now);
    if (tm != NULL) {
      days = tm->tm_yday - gmt->tm_yday;
      hours = ((days < -1 ? 24 : 1 < days ? -24 : days * 24)
              + tm->tm_hour - gmt->tm_hour);
      minutes = hours * 60 + tm->tm_min - gmt->tm_min;
      *tz = minutes;
    }
  }

  return tm;
}

/* Note: maybe the pr_buffer_t should be made to look like this? */
struct extlog_buffer {
  char *ptr, *buf;
  size_t bufsz, buflen;
};

static void extlog_buffer_append(struct extlog_buffer *log, const char *text,
    size_t text_len) {
  if (text == NULL ||
      text_len == 0) {
    return;
  }

  if (text_len > log->buflen) {
    text_len = log->buflen;
  }

  pr_trace_msg(trace_channel, 19, "appending text '%.*s' (%lu) to buffer",
    (int) text_len, text, (unsigned long) text_len);
  memcpy(log->buf, text, text_len);
  log->buf += text_len;
  log->buflen -= text_len;
}

static int resolve_on_meta(pool *p, pr_jot_ctx_t *jot_ctx,
    unsigned char logfmt_id, const char *jot_hint, const void *val) {
  struct extlog_buffer *log;

  log = jot_ctx->log;
  if (log->buflen > 0) {
    const char *text = NULL;
    size_t text_len = 0;
    char buf[1024];

    switch (logfmt_id) {
      case LOGFMT_META_MICROSECS: {
        unsigned long num;

        num = *((double *) val);
        text_len = pr_snprintf(buf, sizeof(buf)-1, "%06lu", num);
        buf[text_len] = '\0';
        text = buf;
        break;
      }

      case LOGFMT_META_MILLISECS: {
        unsigned long num;

        num = *((double *) val);
        text_len = pr_snprintf(buf, sizeof(buf)-1, "%03lu", num);
        buf[text_len] = '\0';
        text = buf;
        break;
      }

      case LOGFMT_META_LOCAL_PORT:
      case LOGFMT_META_REMOTE_PORT:
      case LOGFMT_META_RESPONSE_CODE: {
        int num;

        num = *((double *) val);
        text_len = pr_snprintf(buf, sizeof(buf)-1, "%d", num);
        buf[text_len] = '\0';
        text = buf;
        break;
      }

      case LOGFMT_META_UID: {
        uid_t uid;

        uid = *((double *) val);
        text = pr_uid2str(p, uid);
        break;
      }

      case LOGFMT_META_GID: {
        gid_t gid;

        gid = *((double *) val);
        text = pr_gid2str(p, gid);
        break;
      }

      case LOGFMT_META_BYTES_SENT:
      case LOGFMT_META_FILE_OFFSET:
      case LOGFMT_META_FILE_SIZE:
      case LOGFMT_META_RAW_BYTES_IN:
      case LOGFMT_META_RAW_BYTES_OUT:
      case LOGFMT_META_RESPONSE_MS:
      case LOGFMT_META_XFER_MS: {
        off_t num;

        num = *((double *) val);
        text_len = pr_snprintf(buf, sizeof(buf)-1, "%" PR_LU, (pr_off_t) num);
        buf[text_len] = '\0';
        text = buf;
        break;
      }

      case LOGFMT_META_EPOCH:
      case LOGFMT_META_PID: {
        unsigned long num;

        num = *((double *) val);
        text_len = pr_snprintf(buf, sizeof(buf)-1, "%lu", num);
        buf[text_len] = '\0';
        text = buf;
        break;
      }

      case LOGFMT_META_FILE_MODIFIED: {
        int truth;

        truth = *((int *) val);
        text = truth ? "true" : "false";
        break;
      }

      case LOGFMT_META_SECONDS: {
        float num;

        num = *((double *) val);
        text_len = pr_snprintf(buf, sizeof(buf)-1, "%0.3f", num);
        buf[text_len] = '\0';
        text = buf;
        break;
      }

      /* mod_log has a different implementation of META_TIME than the Jot
       * API.  Thus we do it ourselves here.
       */
      case LOGFMT_META_TIME: {
        char sign, *time_fmt = "[%d/%b/%Y:%H:%M:%S ";
        struct tm t;
        int internal_fmt = TRUE, with_tz = FALSE;

        if (jot_hint != NULL) {
          time_fmt = (char *) jot_hint;
          internal_fmt = FALSE;
        }

        t = *get_gmtoff(&with_tz);
        sign = (with_tz < 0 ? '-' : '+');
        if (with_tz < 0) {
          with_tz = -with_tz;
        }

        if (time_fmt != NULL) {
          memset(buf, '\0', sizeof(buf));
          text_len = strftime(buf, sizeof(buf) - 1, time_fmt, &t);
          if (internal_fmt == TRUE) {
            if (text_len < sizeof(buf)) {
              text_len += pr_snprintf(buf + text_len,
                sizeof(buf) - text_len - 1, "%c%.2d%.2d]", sign,
                (with_tz / 60), (with_tz % 60));
            }
          }

          text = buf;
        }

        break;
      }

      case LOGFMT_META_ANON_PASS:
      case LOGFMT_META_BASENAME:
      case LOGFMT_META_CLASS:
      case LOGFMT_META_CMD_PARAMS:
      case LOGFMT_META_COMMAND:
      case LOGFMT_META_DIR_NAME:
      case LOGFMT_META_DIR_PATH:
      case LOGFMT_META_ENV_VAR:
      case LOGFMT_META_EOS_REASON:
      case LOGFMT_META_FILENAME:
      case LOGFMT_META_GROUP:
      case LOGFMT_META_IDENT_USER:
      case LOGFMT_META_ISO8601:
      case LOGFMT_META_LOCAL_FQDN:
      case LOGFMT_META_LOCAL_IP:
      case LOGFMT_META_LOCAL_NAME:
      case LOGFMT_META_METHOD:
      case LOGFMT_META_NOTE_VAR:
      case LOGFMT_META_ORIGINAL_USER:
      case LOGFMT_META_PROTOCOL:
      case LOGFMT_META_REMOTE_HOST:
      case LOGFMT_META_REMOTE_IP:
      case LOGFMT_META_RENAME_FROM:
      case LOGFMT_META_RESPONSE_STR:
      case LOGFMT_META_USER:
      case LOGFMT_META_VERSION:
      case LOGFMT_META_VHOST_IP:
      case LOGFMT_META_XFER_FAILURE:
      case LOGFMT_META_XFER_PATH:
      case LOGFMT_META_XFER_STATUS:
      case LOGFMT_META_XFER_TYPE:
      default:
        text = val;
        break;
    }

    if (text != NULL &&
        text_len == 0) {
      text_len = strlen(text);
    }

    extlog_buffer_append(log, text, text_len);
  }

  return 0;
}

static int resolve_on_default(pool *p, pr_jot_ctx_t *jot_ctx,
    unsigned char logfmt_id) {
  struct extlog_buffer *log;

  log = jot_ctx->log;
  if (log->buflen > 0) {
    const char *text = NULL;
    size_t text_len = 0;

    switch (logfmt_id) {
      case LOGFMT_META_ANON_PASS:
      case LOGFMT_META_IDENT_USER:
        text = "UNKNOWN";
        text_len = strlen(text);
        break;

      case LOGFMT_META_BASENAME:
      case LOGFMT_META_BYTES_SENT:
      case LOGFMT_META_CLASS:
      case LOGFMT_META_FILENAME:
      case LOGFMT_META_FILE_OFFSET:
      case LOGFMT_META_FILE_SIZE:
      case LOGFMT_META_GROUP:
      case LOGFMT_META_ORIGINAL_USER:
      case LOGFMT_META_RENAME_FROM:
      case LOGFMT_META_RESPONSE_CODE:
      case LOGFMT_META_RESPONSE_MS:
      case LOGFMT_META_RESPONSE_STR:
      case LOGFMT_META_SECONDS:
      case LOGFMT_META_USER:
      case LOGFMT_META_XFER_FAILURE:
      case LOGFMT_META_XFER_MS:
      case LOGFMT_META_XFER_PATH:
      case LOGFMT_META_XFER_STATUS:
      case LOGFMT_META_XFER_TYPE:
        text = "-";
        text_len = 1;
        break;

      /* These explicitly do NOT have default values. */
      case LOGFMT_META_CMD_PARAMS:
      case LOGFMT_META_COMMAND:
      case LOGFMT_META_DIR_NAME:
      case LOGFMT_META_DIR_PATH:
      case LOGFMT_META_ENV_VAR:
      case LOGFMT_META_EOS_REASON:
      case LOGFMT_META_NOTE_VAR:
      case LOGFMT_META_METHOD:
      default:
        break;
    }

    extlog_buffer_append(log, text, text_len);
  }

  return 0;
}

static int resolve_on_other(pool *p, pr_jot_ctx_t *jot_ctx,
    unsigned char *text, size_t text_len) {
  struct extlog_buffer *log;

  log = jot_ctx->log;
  if (log->buflen > 0) {
    pr_trace_msg(trace_channel, 19, "appending text '%.*s' (%lu) to buffer",
      (int) text_len, text, (unsigned long) text_len);
    memcpy(log->buf, text, text_len);
    log->buf += text_len;
    log->buflen -= text_len;
  }

  return 0;
}

/* from src/log.c */
extern int syslog_sockfd;

static void log_event(cmd_rec *cmd, logfile_t *lf) {
  int res;
  unsigned char *f = NULL;
  char logbuf[EXTENDED_LOG_BUFFER_SIZE] = {'\0'};
  logformat_t *fmt = NULL;
  size_t logbuflen;
  pool *tmp_pool;
  pr_jot_ctx_t *jot_ctx;
  struct extlog_buffer *log;

  fmt = lf->lf_format;
  f = fmt->lf_format;

  tmp_pool = make_sub_pool(cmd->tmp_pool);
  jot_ctx = pcalloc(tmp_pool, sizeof(pr_jot_ctx_t));
  log = pcalloc(tmp_pool, sizeof(struct extlog_buffer));
  log->bufsz = log->buflen = sizeof(logbuf) - 1;
  log->ptr = log->buf = logbuf;

  jot_ctx->log = log;

  res = pr_jot_resolve_logfmt(tmp_pool, cmd, lf->lf_jot_filters, f, jot_ctx,
    resolve_on_meta, resolve_on_default, resolve_on_other);
  if (res < 0) {
    /* EPERM indicates that the event was filtered, thus is not necessarily
     * an unexpected condition.
     */
    if (errno != EPERM) {
      pr_log_pri(PR_LOG_NOTICE, MOD_LOG_VERSION
        ": error formatting ExtendedLog message: %s", strerror(errno));
    }

    destroy_pool(tmp_pool);
    return;
  }

  extlog_buffer_append(log, "\n", 1);
  logbuflen = (log->bufsz - log->buflen);

  if (lf->lf_fd != EXTENDED_LOG_SYSLOG) {
    pr_log_event_generate(PR_LOG_TYPE_EXTLOG, lf->lf_fd, -1, logbuf, logbuflen);

    /* What about short writes? */
    if (write(lf->lf_fd, logbuf, logbuflen) < 0) {
      pr_log_pri(PR_LOG_ALERT, "error: cannot write ExtendedLog '%s': %s",
        lf->lf_filename, strerror(errno));
    }

  } else {
    pr_log_event_generate(PR_LOG_TYPE_EXTLOG, syslog_sockfd,
      lf->lf_syslog_level, logbuf, logbuflen);
    pr_syslog(syslog_sockfd, lf->lf_syslog_level, "%s", logbuf);
  }

  destroy_pool(tmp_pool);
}

MODRET log_any(cmd_rec *cmd) {
  logfile_t *lf = NULL;

  /* If not in anon mode, only handle logs for main servers */
  for (lf = logs; lf; lf = lf->next) {
    pr_signals_handle();

    /* Skip any unopened files (obviously); make sure that special fd
     * for syslog is NOT skipped, though.
     */
    if (lf->lf_fd < 0 &&
        lf->lf_fd != EXTENDED_LOG_SYSLOG) {
      continue;
    }

    /* If this is not an <Anonymous> section, and this IS an <Anonymous>
     * ExtendedLog, skip it.
     */
    if (session.anon_config == NULL &&
        lf->lf_conf != NULL &&
        lf->lf_conf->config_type == CONF_ANON) {
      continue;
    }

    log_event(cmd, lf);
  }

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

static void log_exit_ev(const void *event_data, void *user_data) {
  cmd_rec *cmd;

  cmd = pr_cmd_alloc(session.pool, 1, pstrdup(session.pool, "EXIT"));
  cmd->cmd_class |= CL_DISCONNECT;
  (void) pr_cmd_dispatch_phase(cmd, LOG_CMD,
    PR_CMD_DISPATCH_FL_CLEAR_RESPONSE);
}

static void log_postparse_ev(const void *event_data, void *user_data) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "SystemLog", FALSE);
  if (c != NULL) {
    char *path;

    path = c->argv[0];
    log_closesyslog();

    if (strncasecmp(path, "none", 5) != 0) {
      int res, xerrno;

      path = dir_canonical_path(main_server->pool, path);

      pr_signals_block();
      PRIVS_ROOT
      res = log_opensyslog(path);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      if (res < 0) {
        if (res == PR_LOG_WRITABLE_DIR) {
          pr_log_pri(PR_LOG_ERR,
            "unable to open SystemLog '%s': %s is a world-writable directory",
            path, path);

        } else if (res == PR_LOG_SYMLINK) {
          pr_log_pri(PR_LOG_ERR,
            "unable to open SystemLog '%s': %s is a symbolic link", path, path);

        } else {
          if (xerrno != ENXIO) {
            pr_log_pri(PR_LOG_ERR,
              "unable to open SystemLog '%s': %s", path, strerror(xerrno));

          } else {
            pr_log_pri(PR_LOG_ERR,
              "unable to open SystemLog '%s': "
              "FIFO reader process must be running first", path);
          }
        }

        exit(1);
      }

    } else {
      log_discard();
    }
  }
}

static void log_restart_ev(const void *event_data, void *user_data) {
  destroy_pool(log_pool);

  formats = NULL;
  format_set = NULL;
  logs = NULL;
  log_set = NULL;

  log_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(log_pool, "mod_log pool");

  parse_logformat(NULL, "", "%h %l %u %t \"%r\" %s %b");
  return;
}

static void log_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;
  logfile_t *lf = NULL;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&log_module, "core.exit", log_exit_ev);
  pr_event_unregister(&log_module, "core.session-reinit", log_sess_reinit_ev);
  pr_event_unregister(&log_module, "core.timeout-stalled", log_xfer_stalled_ev);

  /* XXX If ServerLog configured, close/reopen syslog? */

  /* Close all ExtendedLog files, to prevent duplicate fds. */
  for (lf = logs; lf; lf = lf->next) {
    if (lf->lf_fd > -1) {
      /* No need to close the special EXTENDED_LOG_SYSLOG (i.e. fake) fd. */
      if (lf->lf_fd != EXTENDED_LOG_SYSLOG) {
        (void) close(lf->lf_fd);
      }

      lf->lf_fd = -1;
    }
  }

  res = log_sess_init();
  if (res < 0) {
    pr_session_disconnect(&log_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

static void log_xfer_stalled_ev(const void *event_data, void *user_data) {
  if (session.curr_cmd_rec != NULL) {
    /* Automatically dispatch the current command, at the LOG_CMD_ERR phase,
     * so that the ExtendedLog entry for the command gets written out.  This
     * should handle any LIST/MLSD/NLST commands as well (Bug#3696).
     */
    (void) log_any(session.curr_cmd_rec);
  }
}

/* Initialization handlers
 */

static int log_init(void) {
  log_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(log_pool, "mod_log pool");

  /* Add the "default" extendedlog format */
  parse_logformat(NULL, "", "%h %l %u %t \"%r\" %s %b");

  pr_event_register(&log_module, "core.postparse", log_postparse_ev, NULL);
  pr_event_register(&log_module, "core.restart", log_restart_ev, NULL);

  return 0;
}

static void find_extendedlogs(void) {
  config_rec *c;
  char *logfname, *logfmt_name = NULL;
  logformat_t *logfmt;
  logfile_t *extlog = NULL;
  unsigned long config_flags = (PR_CONFIG_FIND_FL_SKIP_DIR|PR_CONFIG_FIND_FL_SKIP_LIMIT|PR_CONFIG_FIND_FL_SKIP_DYNDIR);

  /* We DO actually want the recursion here.  The reason is that we want
   * to find ALL_ ExtendedLog directives in the configuration, including
   * those in <Anonymous> sections.  We have the ability to use root privs
   * now, to make sure these files can be opened, but after the user has
   * authenticated (and we know for sure whether they're anonymous or not),
   * root privs may be permanently revoked.
   *
   * We mitigate the cost of the recursive search (especially for configs
   * with thousands of <Directory>/<Limit> sections) by specifying the
   * find_config() flags to skip those sections; we are only interested
   * in the top-level (CONF_ROOT, CONF_VIRTUAL) and <Anonymous> sections.
   */

  c = find_config2(main_server->conf, CONF_PARAM, "ExtendedLog", TRUE,
    config_flags);
  while (c != NULL) {
    pr_jot_filters_t *jot_filters = NULL;

    pr_signals_handle();

    logfname = c->argv[0];
    logfmt_name = NULL;

    if (c->argc > 1) {
      jot_filters = c->argv[1];

      if (c->argc > 2) {
        if (c->argv[2] != NULL) {
          logfmt_name = c->argv[2];
        }
      }
    }

    /* No logging for this round.  If, however, this was found in an
     * <Anonymous> section, add a logfile entry for it anyway; the anonymous
     * directive might be trying to override a higher-level config; see
     * Bug#1908.
     */
    if (c->parent != NULL &&
        c->parent->config_type != CONF_ANON) {
      goto loop_extendedlogs;
    }

    if (logfmt_name != NULL) {
      /* Search for the format name */
      for (logfmt = formats; logfmt; logfmt = logfmt->next) {
        if (strcmp(logfmt->lf_fmt_name, logfmt_name) == 0) {
          break;
        }
      }

      if (logfmt == NULL) {
        if (strcasecmp(logfmt_name, EXTENDED_LOG_FORMAT_DEFAULT) == 0) {
          /* Try again, this time looking for the default LogFormat
           * name, which is registered using a name of "".
           */
          for (logfmt = formats; logfmt; logfmt = logfmt->next) {
            if (strcmp(logfmt->lf_fmt_name, "") == 0) {
              break;
            }
          }
        }
      }

      if (logfmt == NULL) {
        pr_log_pri(PR_LOG_NOTICE,
          "ExtendedLog '%s' uses unknown format name '%s'", logfname,
          logfmt_name);
        goto loop_extendedlogs;
      }

    } else {
      logfmt = formats;
    }

    extlog = (logfile_t *) pcalloc(session.pool, sizeof(logfile_t));

    extlog->lf_filename = pstrdup(session.pool, logfname);
    extlog->lf_fd = -1;
    extlog->lf_syslog_level = -1;
    extlog->lf_jot_filters = jot_filters;
    extlog->lf_format = logfmt;
    extlog->lf_conf = c->parent;
    if (log_set == NULL) {
      log_set = xaset_create(session.pool, NULL);
    }

    xaset_insert(log_set, (xasetmember_t *) extlog);
    logs = (logfile_t *) log_set->xas_list;

loop_extendedlogs:
    c = find_config_next2(c, c->next, CONF_PARAM, "ExtendedLog", TRUE,
      config_flags);
  }
}

MODRET log_pre_dele(cmd_rec *cmd) {
  char *path;

  jot_set_deleted_filesz(0);

  path = dir_canonical_path(cmd->tmp_pool,
    pr_fs_decode_path(cmd->tmp_pool, cmd->arg));
  if (path != NULL) {
    struct stat st;

    /* Briefly cache the size of the file being deleted, so that it can be
     * logged properly using %b.
     */
    pr_fs_clear_cache2(path);
    if (pr_fsio_stat(path, &st) == 0) {
      jot_set_deleted_filesz(st.st_size);
    }
  }

  return PR_DECLINED(cmd);
}

MODRET log_post_pass(cmd_rec *cmd) {
  logfile_t *lf;

  /* Authentication is complete, if we aren't in anon-mode, close
   * all extendedlogs opened inside <Anonymous> blocks.
   */
  if (!session.anon_config) {
    for (lf = logs; lf; lf = lf->next) {
      if (lf->lf_fd != -1 &&
          lf->lf_fd != EXTENDED_LOG_SYSLOG &&
          lf->lf_conf &&
          lf->lf_conf->config_type == CONF_ANON) {
        pr_log_debug(DEBUG7, "mod_log: closing ExtendedLog '%s' (fd %d)",
          lf->lf_filename, lf->lf_fd);
        (void) close(lf->lf_fd);
        lf->lf_fd = -1;
      }
    }

  } else {
    /* Close all logs which were opened inside a _different_ anonymous
     * context.
     */
    for (lf = logs; lf; lf = lf->next) {
      if (lf->lf_fd != -1 &&
          lf->lf_fd != EXTENDED_LOG_SYSLOG &&
          lf->lf_conf &&
          lf->lf_conf != session.anon_config) {
        pr_log_debug(DEBUG7, "mod_log: closing ExtendedLog '%s' (fd %d)",
          lf->lf_filename, lf->lf_fd);
        (void) close(lf->lf_fd);
        lf->lf_fd = -1;
      }
    }

    /* If any ExtendedLogs set inside our context match an outer log,
     * close the outer (this allows overriding inside <Anonymous>).
     */
    for (lf = logs; lf; lf = lf->next) {
      if (lf->lf_conf &&
          lf->lf_conf == session.anon_config) {
        /* This should "override" any lower-level extendedlog with the
         * same filename.
         */
        logfile_t *lfi = NULL;

        for (lfi = logs; lfi; lfi = lfi->next) {
          if (lfi->lf_fd != -1 &&
              lfi->lf_fd != EXTENDED_LOG_SYSLOG &&
              !lfi->lf_conf &&
              strcmp(lfi->lf_filename, lf->lf_filename) == 0) {
            pr_log_debug(DEBUG7, "mod_log: closing ExtendedLog '%s' (fd %d)",
              lf->lf_filename, lfi->lf_fd);
            (void) close(lfi->lf_fd);
            lfi->lf_fd = -1;
          }
        }

        /* Go ahead and close the log if it's CL_NONE */
        if (lf->lf_fd != -1 &&
            lf->lf_fd != EXTENDED_LOG_SYSLOG &&
            pr_jot_filters_include_classes(lf->lf_jot_filters, CL_NONE) == TRUE) {
          (void) close(lf->lf_fd);
          lf->lf_fd = -1;
        }
      }
    }
  }

  return PR_DECLINED(cmd);
}

/* Open all the log files */
static int dispatched_connect = FALSE;

static int log_sess_init(void) {
  char *serverlog_name = NULL;
  logfile_t *lf = NULL;

  pr_event_register(&log_module, "core.session-reinit", log_sess_reinit_ev,
    NULL);

  /* Open the ServerLog, if present. */
  serverlog_name = get_param_ptr(main_server->conf, "ServerLog", FALSE);
  if (serverlog_name != NULL) {
    log_closesyslog();

    if (strncasecmp(serverlog_name, "none", 5) != 0) {
      int res, xerrno;

      PRIVS_ROOT
      res = log_opensyslog(serverlog_name);
      xerrno = errno;
      PRIVS_RELINQUISH

      if (res < 0) {
        if (xerrno != ENXIO) {
          pr_log_debug(DEBUG4, "unable to open ServerLog '%s': %s",
            serverlog_name, strerror(xerrno));

        } else {
          pr_log_debug(DEBUG4,
            "unable to open ServerLog '%s': "
            "FIFO reader process must be running first", serverlog_name);
        }
      }
    }

  } else {
    config_rec *c;

    c = find_config(main_server->conf, CONF_PARAM, "SystemLog", FALSE);
    if (c != NULL) {
      char *path;

      path = c->argv[0];
      log_closesyslog();

      if (strncasecmp(path, "none", 5) != 0) {
        int res, xerrno;

        path = dir_canonical_path(main_server->pool, path);

        pr_signals_block();
        PRIVS_ROOT
        res = log_opensyslog(path);
        xerrno = errno;
        PRIVS_RELINQUISH
        pr_signals_unblock();

        if (res < 0) {
          if (res == PR_LOG_WRITABLE_DIR) {
            pr_log_pri(PR_LOG_ERR,
              "unable to open SystemLog '%s': %s is a world-writable directory",
              path, path);

          } else if (res == PR_LOG_SYMLINK) {
            pr_log_pri(PR_LOG_ERR,
              "unable to open SystemLog '%s': %s is a symbolic link", path,
              path);

          } else {
            if (xerrno != ENXIO) {
              pr_log_pri(PR_LOG_ERR,
                "unable to open SystemLog '%s': %s", path, strerror(xerrno));

            } else {
              pr_log_pri(PR_LOG_ERR,
                "unable to open SystemLog '%s': "
                "FIFO reader process must be running first", path);
            }
          }
        }

      } else {
        log_discard();
      }
    }
  }

  /* Open all the ExtendedLog files. */
  find_extendedlogs();

  for (lf = logs; lf; lf = lf->next) {
    if (lf->lf_fd == -1) {

      /* Is this ExtendedLog to be written to a file, or to syslog? */
      if (strncasecmp(lf->lf_filename, "syslog:", 7) != 0) {
        int res = 0, xerrno;

        pr_log_debug(DEBUG7, "mod_log: opening ExtendedLog '%s'",
          lf->lf_filename);

        pr_signals_block();
        PRIVS_ROOT
        res = pr_log_openfile(lf->lf_filename, &(lf->lf_fd), EXTENDED_LOG_MODE);
        xerrno = errno;
        PRIVS_RELINQUISH
        pr_signals_unblock();

        if (res < 0) {
          if (res == -1) {
            if (xerrno != ENXIO) {
              pr_log_pri(PR_LOG_NOTICE, "unable to open ExtendedLog '%s': %s",
                lf->lf_filename, strerror(xerrno));

            } else {
              pr_log_pri(PR_LOG_NOTICE, "unable to open ExtendedLog '%s': "
                "FIFO reader process must be running first", lf->lf_filename);
            }

          } else if (res == PR_LOG_WRITABLE_DIR) {
            pr_log_pri(PR_LOG_WARNING, "unable to open ExtendedLog '%s': "
              "parent directory is world-writable", lf->lf_filename);

          } else if (res == PR_LOG_SYMLINK) {
            pr_log_pri(PR_LOG_WARNING, "unable to open ExtendedLog '%s': "
              "%s is a symbolic link", lf->lf_filename, lf->lf_filename);
          }
        }

      } else {
        char *tmp = strchr(lf->lf_filename, ':');

        lf->lf_syslog_level = pr_log_str2sysloglevel(++tmp);
        lf->lf_fd = EXTENDED_LOG_SYSLOG;
      }
    }
  }

  /* Register event handlers for the session. */
  pr_event_register(&log_module, "core.exit", log_exit_ev, NULL);
  pr_event_register(&log_module, "core.timeout-stalled", log_xfer_stalled_ev,
    NULL);

  /* Have we send our CONNECT event yet? */
  if (dispatched_connect == FALSE) {
    pool *tmp_pool;
    cmd_rec *cmd;

    tmp_pool = make_sub_pool(session.pool);
    cmd = pr_cmd_alloc(tmp_pool, 1, pstrdup(tmp_pool, "CONNECT"));
    cmd->cmd_class |= CL_CONNECT;
    (void) pr_cmd_dispatch_phase(cmd, LOG_CMD,
      PR_CMD_DISPATCH_FL_CLEAR_RESPONSE);
    destroy_pool(tmp_pool);

    dispatched_connect = TRUE;
  }

  return 0;
}

/* Module API tables
 */

static conftable log_conftab[] = {
  { "AllowLogSymlinks",	set_allowlogsymlinks,			NULL },
  { "ExtendedLog",	set_extendedlog,			NULL },
  { "LogFormat",	set_logformat,				NULL },
  { "ServerLog",	set_serverlog,				NULL },
  { "SystemLog",	set_systemlog,				NULL },
  { NULL,		NULL,					NULL }
};

static cmdtable log_cmdtab[] = {
  { PRE_CMD,		C_DELE,	G_NONE,	log_pre_dele,	FALSE, FALSE },
  { LOG_CMD,		C_ANY,	G_NONE,	log_any,	FALSE, FALSE },
  { LOG_CMD_ERR,	C_ANY,	G_NONE,	log_any,	FALSE, FALSE },
  { POST_CMD,		C_PASS,	G_NONE,	log_post_pass,	FALSE, FALSE },
  { 0, NULL }
};

module log_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "log",

  /* Module configuration handler table */
  log_conftab,

  /* Module command handler table */
  log_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  log_init,

  /* Session initialization */
  log_sess_init,

  /* Module version */
  MOD_LOG_VERSION
};
