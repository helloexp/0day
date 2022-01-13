/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2017 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Jot API */

#ifndef PR_JOT_H
#define PR_JOT_H

#include "conf.h"
#include "logfmt.h"

/* Jot keys for LogFormat variables, e.g. for key/value logging via JSON. */
#define PR_JOT_LOGFMT_ANON_PASSWD_KEY	"anon_password"
#define PR_JOT_LOGFMT_BASENAME_KEY	"basename"
#define PR_JOT_LOGFMT_BYTES_SENT_KEY	"bytes_sent"
#define PR_JOT_LOGFMT_CLASS_KEY		"connection_class"
#define PR_JOT_LOGFMT_COMMAND_KEY	"raw_command"
#define PR_JOT_LOGFMT_CONNECT_KEY	"connecting"
#define PR_JOT_LOGFMT_CMD_PARAMS_KEY	"command_params"
#define PR_JOT_LOGFMT_DIR_NAME_KEY	"dir_name"
#define PR_JOT_LOGFMT_DIR_PATH_KEY	"dir_path"
#define PR_JOT_LOGFMT_DISCONNECT_KEY	"disconnecting"
#define PR_JOT_LOGFMT_ENV_VAR_KEY	"ENV:"
#define PR_JOT_LOGFMT_EPOCH_KEY		"epoch"
#define PR_JOT_LOGFMT_EOS_REASON_KEY	"session_end_reason"
#define PR_JOT_LOGFMT_FILENAME_KEY	"file"
#define PR_JOT_LOGFMT_FILE_MODIFIED_KEY	"file_modified"
#define PR_JOT_LOGFMT_FILE_OFFSET_KEY	"file_offset"
#define PR_JOT_LOGFMT_FILE_SIZE_KEY	"file_size"
#define PR_JOT_LOGFMT_GID_KEY		"gid"
#define PR_JOT_LOGFMT_GROUP_KEY		"group"
#define PR_JOT_LOGFMT_IDENT_USER_KEY	"identd_user"
#define PR_JOT_LOGFMT_ISO8601_KEY	"timestamp"
#define PR_JOT_LOGFMT_LOCAL_FQDN_KEY	"server_dns"
#define PR_JOT_LOGFMT_LOCAL_IP_KEY	"local_ip"
#define PR_JOT_LOGFMT_LOCAL_NAME_KEY	"server_name"
#define PR_JOT_LOGFMT_LOCAL_PORT_KEY	"local_port"
#define PR_JOT_LOGFMT_METHOD_KEY	"command"
#define PR_JOT_LOGFMT_MILLISECS_KEY	"millisecs"
#define PR_JOT_LOGFMT_MICROSECS_KEY	"microsecs"
#define PR_JOT_LOGFMT_NOTE_KEY		"NOTE:"
#define PR_JOT_LOGFMT_ORIG_USER_KEY	"original_user"
#define PR_JOT_LOGFMT_PID_KEY		"pid"
#define PR_JOT_LOGFMT_PROTOCOL_KEY	"protocol"
#define PR_JOT_LOGFMT_RAW_BYTES_IN_KEY	"session_bytes_rcvd"
#define PR_JOT_LOGFMT_RAW_BYTES_OUT_KEY	"session_bytes_sent"
#define PR_JOT_LOGFMT_REMOTE_HOST_KEY	"remote_dns"
#define PR_JOT_LOGFMT_REMOTE_IP_KEY	"remote_ip"
#define PR_JOT_LOGFMT_REMOTE_PORT_KEY	"remote_port"
#define PR_JOT_LOGFMT_RENAME_FROM_KEY	"rename_from"
#define PR_JOT_LOGFMT_RESPONSE_CODE_KEY	"response_code"
#define PR_JOT_LOGFMT_RESPONSE_MS_KEY	"response_millis"
#define PR_JOT_LOGFMT_RESPONSE_MSG_KEY	"response_msg"
#define PR_JOT_LOGFMT_SECONDS_KEY	"transfer_secs"
#define PR_JOT_LOGFMT_TIME_KEY		"local_time"
#define PR_JOT_LOGFMT_UID_KEY		"uid"
#define PR_JOT_LOGFMT_USER_KEY		"user"
#define PR_JOT_LOGFMT_VERSION_KEY	"server_version"
#define PR_JOT_LOGFMT_VHOST_IP_KEY	"server_ip"
#define PR_JOT_LOGFMT_XFER_MS_KEY	"transfer_millis"
#define PR_JOT_LOGFMT_XFER_PATH_KEY	"transfer_path"
#define PR_JOT_LOGFMT_XFER_FAILURE_KEY	"transfer_failure"
#define PR_JOT_LOGFMT_XFER_STATUS_KEY	"transfer_status"
#define PR_JOT_LOGFMT_XFER_TYPE_KEY	"transfer_type"

/* This opaque structure is used for tracking filters for events. */
typedef struct jot_filters_rec pr_jot_filters_t;

/* Use this for passing data to your jotting callbacks. */
typedef struct {
  /* A pointer to the object into which resolved variables are written. */
  void *log;

  /* User-supplied data/context to use when writing resolved variables. */
  const void *user_data;

} pr_jot_ctx_t;

/* Use this for accumulating the state of a parsed LogFormat-style text. */
typedef struct {
  unsigned char *ptr, *buf;
  size_t bufsz, buflen;
} pr_jot_parsed_t;

/* Returns table which maps LOGFMT_META_ values to JSON keys and types. */
pr_table_t *pr_jot_get_logfmt2json(pool *p);

pr_jot_filters_t *pr_jot_filters_create(pool *p, const char *rules,
  int rules_type, int flags);
#define PR_JOT_FILTER_TYPE_COMMANDS_WITH_CLASSES	0
#define PR_JOT_FILTER_TYPE_COMMANDS			1
#define PR_JOT_FILTER_TYPE_CLASSES			2

/* Use this flag to indicate that an "ALL" name means _everything_.  By
 * default, the CL_ALL logging class does NOT include all classes, due to
 * backward compatibility requirements.
 */
#define PR_JOT_FILTER_FL_ALL_INCL_ALL		0x001

int pr_jot_filters_destroy(pr_jot_filters_t *filters);

/* Do the filters include the given command class? */
int pr_jot_filters_include_classes(pr_jot_filters_t *filters, int log_class);

/* Return the printable name of the given LogFormat ID. */
const char *pr_jot_get_logfmt_id_name(unsigned char logfmt_id);

/* Parse the text for LogFormat variables.  For each one found, invoke the
 * `on_meta` callback with the parsed LogFormat ID and its related data.
 * If an unknown variable sequence, i.e. text within the expected "%{...}"
 * format appears, the `on_unknown` callback will be invoked with that text.
 * For non-variable characters, the `on_other` callback is invoked.
 */
int pr_jot_parse_logfmt(pool *p, const char *text, pr_jot_ctx_t *ctx,
  int (*on_meta)(pool *, pr_jot_ctx_t *, unsigned char, const char *, size_t),
  int (*on_unknown)(pool *, pr_jot_ctx_t *, const char *, size_t),
  int (*on_other)(pool *, pr_jot_ctx_t *, char), int flags);

/* The following are the conventional callbacks to use for
 * pr_jot_parse_logfmt.  Note that they ASSUME the use of `pr_jot_parsed_t`,
 * i.e.
 *
 *  jot_ctx = pcalloc(tmp_pool, sizeof(pr_jot_ctx_t));
 *  parsed = pcalloc(tmp_pool, sizeof(pr_jot_parsed_t));
 *  ...
 *  jot_ctx->log = parsed;
 */
int pr_jot_parse_on_meta(pool *p, pr_jot_ctx_t *jot_ctx,
  unsigned char logfmt_id, const char *logfmt_data, size_t logfmt_datalen);
int pr_jot_parse_on_unknown(pool *p, pr_jot_ctx_t *jot_ctx, const char *text,
  size_t text_len);
int pr_jot_parse_on_other(pool *p, pr_jot_ctx_t *jot_ctx, char ch);

/* Use this flag to indicate that unknown variables should be parsed as
 * LOGFMT_META_CUSTOM variables.
 */
#define PR_JOT_LOGFMT_PARSE_FL_UNKNOWN_AS_CUSTOM	0x001

/* Given a LogFormat ID (i.e. one of the LOGFMT_META_ values), resolve it to
 * its respective value.  If resolved, the `on_meta` callback will be invoked
 * with the resolved value.  If the variable has no resolved value, the
 * `on_default` callback is invoked.
 */
int pr_jot_resolve_logfmt_id(pool *p, cmd_rec *cmd, pr_jot_filters_t *filter,
  unsigned char logfmt_id, const char *logfmt_data, size_t logfmt_datalen,
  pr_jot_ctx_t *ctx,
  int (*on_meta)(pool *, pr_jot_ctx_t *, unsigned char, const char *,
    const void *),
  int (*on_default)(pool *, pr_jot_ctx_t *, unsigned char));

/* Given a LogFormat buffer, resolve each of the variables (i.e. "meta") to
 * their respective values.  For each resolved variable, the `on_meta` callback
 * will be invoked.  For each variable which has not resolved value, the
 * `on_default` callback is invoked.  For any non-variable characters, the
 * `on_other` callback is invoked.
 */
int pr_jot_resolve_logfmt(pool *p, cmd_rec *cmd, pr_jot_filters_t *filters,
  unsigned char *logfmt, pr_jot_ctx_t *ctx,
  int (*on_meta)(pool *, pr_jot_ctx_t *, unsigned char, const char *,
    const void *),
  int (*on_default)(pool *, pr_jot_ctx_t *, unsigned char),
  int (*on_other)(pool *, pr_jot_ctx_t *, unsigned char *, size_t));

/* Canned `on_meta` callback to use when resolving LogFormat strings into
 * JSON objects.
 */
int pr_jot_on_json(pool *p, pr_jot_ctx_t *ctx, unsigned char logfmt_id,
  const char *key, const void *val);

/* Scans the given parsed LogFormat buffer for the given LogFormat ID, and
 * invokes the `on_meta` callback for each occurrence found.
 */
int pr_jot_scan_logfmt(pool *p, unsigned char *logfmt, unsigned char logfmt_id,
  pr_jot_ctx_t *ctx,
  int (*on_meta)(pool *, pr_jot_ctx_t *, unsigned char, const char *, size_t),
  int flags);

/* For internal use only. */
void jot_set_deleted_filesz(off_t deleted_filesz);

#endif /* PR_JOT_H */
