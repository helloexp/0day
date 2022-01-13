/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2017-2019 The ProFTPD Project team
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
#include "logfmt.h"
#include "json.h"
#include "jot.h"

struct jot_filters_rec {
  pool *pool;

  int included_classes;
  int excluded_classes;
  array_header *cmd_ids;
};

/* For tracking the size of deleted files. */
static off_t jot_deleted_filesz = 0;

static const char *trace_channel = "jot";

/* Entries in the JSON map table identify the key, and the data type:
 * Boolean, number, or string.
 */
struct logfmt_json_info {
  unsigned int json_type;
  const char *json_key;
};

/* Key comparison for the ID/key table. */
static int logfmt_json_keycmp(const void *k1, size_t ksz1, const void *k2,
  size_t ksz2) {

  /* Return zero to indicate a match, non-zero otherwise. */
  return (*((unsigned char *) k1) == *((unsigned char *) k2) ? 0 : 1);
}

/* Key "hash" callback for ID/key table. */
static unsigned int logfmt_json_keyhash(const void *k, size_t ksz) {
  unsigned char c;
  unsigned int res;

  c = *((unsigned char *) k);
  res = (c << 8);

  return res;
}

static void add_json_info(pool *p, pr_table_t *tab, unsigned char logfmt_id,
    const char *json_key, unsigned int json_type) {
  unsigned char *k;
  struct logfmt_json_info *lji;

  k = palloc(p, sizeof(unsigned char));
  *k = logfmt_id;

  lji = palloc(p, sizeof(struct logfmt_json_info));
  lji->json_type = json_type;
  lji->json_key = json_key;

  (void) pr_table_kadd(tab, (const void *) k, sizeof(unsigned char),
    lji, sizeof(struct logfmt_json_info *));
}

const char *pr_jot_get_logfmt_id_name(unsigned char logfmt_id) {
  const char *name = NULL;

  switch (logfmt_id) {
    case LOGFMT_META_BYTES_SENT:
      name = "BYTE_SENT";
      break;

    case LOGFMT_META_FILENAME:
      name = "FILENAME";
      break;

    case LOGFMT_META_ENV_VAR:
      name = "ENV_VAR";
      break;

    case LOGFMT_META_REMOTE_HOST:
      name = "REMOTE_HOST";
      break;

    case LOGFMT_META_REMOTE_IP:
      name = "REMOTE_IP";
      break;

    case LOGFMT_META_IDENT_USER:
      name = "IDENT_USER";
      break;

    case LOGFMT_META_PID:
      name = "PID";
      break;

    case LOGFMT_META_TIME:
      name = "TIME";
      break;

    case LOGFMT_META_SECONDS:
      name = "SECONDS";
      break;

    case LOGFMT_META_COMMAND:
      name = "COMMAND";
      break;

    case LOGFMT_META_LOCAL_NAME:
      name = "LOCAL_NAME";
      break;

    case LOGFMT_META_LOCAL_PORT:
      name = "LOCAL_PORT";
      break;

    case LOGFMT_META_LOCAL_IP:
      name = "LOCAL_IP";
      break;

    case LOGFMT_META_LOCAL_FQDN:
      name = "LOCAL_FQDN";
      break;

    case LOGFMT_META_USER:
      name = "USER";
      break;

    case LOGFMT_META_ORIGINAL_USER:
      name = "ORIGINAL_USER";
      break;

    case LOGFMT_META_RESPONSE_CODE:
      name = "RESPONSE_CODE";
      break;

    case LOGFMT_META_CLASS:
      name = "CLASS";
      break;

    case LOGFMT_META_ANON_PASS:
      name = "ANON_PASS";
      break;

    case LOGFMT_META_METHOD:
      name = "METHOD";
      break;

    case LOGFMT_META_XFER_PATH:
      name = "XFER_PATH";
      break;

    case LOGFMT_META_DIR_NAME:
      name = "DIR_NAME";
      break;

    case LOGFMT_META_DIR_PATH:
      name = "DIR_PATH";
      break;

    case LOGFMT_META_CMD_PARAMS:
      name = "CMD_PARAMS";
      break;

    case LOGFMT_META_RESPONSE_STR:
      name = "RESPONSE_STR";
      break;

    case LOGFMT_META_PROTOCOL:
      name = "PROTOCOL";
      break;

    case LOGFMT_META_VERSION:
      name = "VERSION";
      break;

    case LOGFMT_META_RENAME_FROM:
      name = "RENAME_FROM";
      break;

    case LOGFMT_META_FILE_MODIFIED:
      name = "FILE_MODIFIED";
      break;

    case LOGFMT_META_UID:
      name = "UID";
      break;

    case LOGFMT_META_GID:
      name = "GID";
      break;

    case LOGFMT_META_RAW_BYTES_IN:
      name = "RAW_BYTES_IN";
      break;

    case LOGFMT_META_RAW_BYTES_OUT:
      name = "RAW_BYTES_OUT";
      break;

    case LOGFMT_META_EOS_REASON:
      name = "EOS_REASON";
      break;

    case LOGFMT_META_VHOST_IP:
      name = "VHOST_IP";
      break;

    case LOGFMT_META_NOTE_VAR:
      name = "NOTE_VAR";
      break;

    case LOGFMT_META_XFER_STATUS:
      name = "XFER_STATUS";
      break;

    case LOGFMT_META_XFER_FAILURE:
      name = "XFER_FAILURE";
      break;

    case LOGFMT_META_MICROSECS:
      name = "MICROSECS";
      break;

    case LOGFMT_META_MILLISECS:
      name = "MILLISECS";
      break;

    case LOGFMT_META_ISO8601:
      name = "ISO8601";
      break;

    case LOGFMT_META_GROUP:
      name = "GROUP";
      break;

    case LOGFMT_META_BASENAME:
      name = "BASENAME";
      break;

    case LOGFMT_META_FILE_OFFSET:
      name = "FILE_OFFSET";
      break;

    case LOGFMT_META_XFER_MS:
      name = "XFER_MS";
      break;

    case LOGFMT_META_RESPONSE_MS:
      name = "RESPONSE_MS";
      break;

    case LOGFMT_META_FILE_SIZE:
      name = "FILE_SIZE";
      break;

    case LOGFMT_META_XFER_TYPE:
      name = "XFER_TYPE";
      break;

    case LOGFMT_META_REMOTE_PORT:
      name = "REMOTE_PORT";
      break;

    case LOGFMT_META_EPOCH:
      name = "EPOCH";
      break;

    case LOGFMT_META_CONNECT:
      name = "CONNECT";
      break;

    case LOGFMT_META_DISCONNECT:
      name = "DISCONNECT";
      break;

    case LOGFMT_META_CUSTOM:
      name = "CUSTOM";
      break;

    default:
      errno = EINVAL;
      name = NULL;
      break;
  }

  return name;
}

pr_table_t *pr_jot_get_logfmt2json(pool *p) {
  pr_table_t *map;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  map = pr_table_alloc(p, 0);

  (void) pr_table_ctl(map, PR_TABLE_CTL_SET_KEY_CMP,
    (void *) logfmt_json_keycmp);
  (void) pr_table_ctl(map, PR_TABLE_CTL_SET_KEY_HASH,
    (void *) logfmt_json_keyhash);

  /* Now populate the map with the ID/name values.  The key is the
   * LogFormat "meta" ID, and the value is the corresponding name string,
   * for use e.g. as JSON object member names.
   */

  add_json_info(p, map, LOGFMT_META_BYTES_SENT, PR_JOT_LOGFMT_BYTES_SENT_KEY,
    PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_FILENAME, PR_JOT_LOGFMT_FILENAME_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_ENV_VAR, PR_JOT_LOGFMT_ENV_VAR_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_EPOCH, PR_JOT_LOGFMT_EPOCH_KEY,
    PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_REMOTE_HOST, PR_JOT_LOGFMT_REMOTE_HOST_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_REMOTE_IP, PR_JOT_LOGFMT_REMOTE_IP_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_IDENT_USER, PR_JOT_LOGFMT_IDENT_USER_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_PID, PR_JOT_LOGFMT_PID_KEY,
    PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_TIME, PR_JOT_LOGFMT_TIME_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_SECONDS, PR_JOT_LOGFMT_SECONDS_KEY,
    PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_COMMAND, PR_JOT_LOGFMT_COMMAND_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_LOCAL_NAME, PR_JOT_LOGFMT_LOCAL_NAME_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_LOCAL_PORT, PR_JOT_LOGFMT_LOCAL_PORT_KEY,
    PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_LOCAL_IP, PR_JOT_LOGFMT_LOCAL_IP_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_LOCAL_FQDN, PR_JOT_LOGFMT_LOCAL_FQDN_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_USER, PR_JOT_LOGFMT_USER_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_ORIGINAL_USER, PR_JOT_LOGFMT_ORIG_USER_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_RESPONSE_CODE,
    PR_JOT_LOGFMT_RESPONSE_CODE_KEY, PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_CLASS, PR_JOT_LOGFMT_CLASS_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_ANON_PASS, PR_JOT_LOGFMT_ANON_PASSWD_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_METHOD, PR_JOT_LOGFMT_METHOD_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_XFER_PATH, PR_JOT_LOGFMT_XFER_PATH_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_DIR_NAME, PR_JOT_LOGFMT_DIR_NAME_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_DIR_PATH, PR_JOT_LOGFMT_DIR_PATH_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_CMD_PARAMS, PR_JOT_LOGFMT_CMD_PARAMS_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_RESPONSE_STR,
    PR_JOT_LOGFMT_RESPONSE_MSG_KEY, PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_PROTOCOL, PR_JOT_LOGFMT_PROTOCOL_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_VERSION, PR_JOT_LOGFMT_VERSION_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_RENAME_FROM, PR_JOT_LOGFMT_RENAME_FROM_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_FILE_MODIFIED,
    PR_JOT_LOGFMT_FILE_MODIFIED_KEY, PR_JSON_TYPE_BOOL);
  add_json_info(p, map, LOGFMT_META_UID, PR_JOT_LOGFMT_UID_KEY,
    PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_GID, PR_JOT_LOGFMT_GID_KEY,
    PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_RAW_BYTES_IN,
    PR_JOT_LOGFMT_RAW_BYTES_IN_KEY, PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_RAW_BYTES_OUT,
    PR_JOT_LOGFMT_RAW_BYTES_OUT_KEY, PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_EOS_REASON, PR_JOT_LOGFMT_EOS_REASON_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_VHOST_IP, PR_JOT_LOGFMT_VHOST_IP_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_NOTE_VAR, PR_JOT_LOGFMT_NOTE_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_XFER_STATUS, PR_JOT_LOGFMT_XFER_STATUS_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_XFER_FAILURE,
    PR_JOT_LOGFMT_XFER_FAILURE_KEY, PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_XFER_TYPE, PR_JOT_LOGFMT_XFER_TYPE_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_MICROSECS, PR_JOT_LOGFMT_MICROSECS_KEY,
    PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_MILLISECS, PR_JOT_LOGFMT_MILLISECS_KEY,
    PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_ISO8601, PR_JOT_LOGFMT_ISO8601_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_GROUP, PR_JOT_LOGFMT_GROUP_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_BASENAME, PR_JOT_LOGFMT_BASENAME_KEY,
    PR_JSON_TYPE_STRING);
  add_json_info(p, map, LOGFMT_META_FILE_OFFSET, PR_JOT_LOGFMT_FILE_OFFSET_KEY,
    PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_XFER_MS, PR_JOT_LOGFMT_XFER_MS_KEY,
    PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_RESPONSE_MS, PR_JOT_LOGFMT_RESPONSE_MS_KEY,
    PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_FILE_SIZE, PR_JOT_LOGFMT_FILE_SIZE_KEY,
    PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_REMOTE_PORT, PR_JOT_LOGFMT_REMOTE_PORT_KEY,
    PR_JSON_TYPE_NUMBER);
  add_json_info(p, map, LOGFMT_META_CONNECT, PR_JOT_LOGFMT_CONNECT_KEY,
    PR_JSON_TYPE_BOOL);
  add_json_info(p, map, LOGFMT_META_DISCONNECT, PR_JOT_LOGFMT_DISCONNECT_KEY,
    PR_JSON_TYPE_BOOL);

  return map;
}

int pr_jot_on_json(pool *p, pr_jot_ctx_t *ctx, unsigned char logfmt_id,
    const char *jot_hint, const void *val) {
  int res = 0;
  const struct logfmt_json_info *lji;
  pr_json_object_t *json;
  pr_table_t *logfmt_json_map;

  if (p == NULL ||
      ctx == NULL ||
      val == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (ctx->log == NULL) {
    pr_trace_msg(trace_channel, 16,
      "missing required JSON object for jotting LogFormat ID %u",
      (unsigned int) logfmt_id);
    errno = EINVAL;
    return -1;
  }

  if (ctx->user_data == NULL) {
    pr_trace_msg(trace_channel, 16,
      "missing required JSON map for jotting LogFormat ID %u",
      (unsigned int) logfmt_id);
    errno = EINVAL;
    return -1;
  }

  json = ctx->log;
  logfmt_json_map = (pr_table_t *) ctx->user_data;

  lji = pr_table_kget(logfmt_json_map, (const void *) &logfmt_id,
    sizeof(unsigned char), NULL);
  if (lji == NULL) {
    pr_trace_msg(trace_channel, 16,
      "missing required JSON information for jotting LogFormat ID %u",
      (unsigned int) logfmt_id);
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 18, "jotting LogFormat ID %u as JSON %s (%s)",
    (unsigned int) logfmt_id, pr_json_type_name(lji->json_type), lji->json_key);

  switch (lji->json_type) {
    case PR_JSON_TYPE_STRING: {
      const char *json_key;

      json_key = lji->json_key;

      /* Use the hinted key, if available (e.g. for ENV/NOTE variables). */
      if (jot_hint != NULL) {
        json_key = jot_hint;
      }

      res = pr_json_object_set_string(p, json, json_key, (const char *) val);
      break;
    }

    case PR_JSON_TYPE_NUMBER:
      res = pr_json_object_set_number(p, json, lji->json_key,
        *((double *) val));
      break;

    case PR_JSON_TYPE_BOOL:
      res = pr_json_object_set_bool(p, json, lji->json_key, *((int *) val));
      break;
  }

  return res;
}

static char *get_meta_arg(pool *p, unsigned char *meta, size_t *arg_len) {
  char buf[PR_TUNABLE_PATH_MAX+1], *ptr;
  size_t len;

  ptr = buf;
  len = 0;

  while (*meta != LOGFMT_META_ARG_END) {
    pr_signals_handle();
    *ptr++ = (char) *meta++;
    len++;
  }

  *ptr = '\0';
  *arg_len = len;

  return pstrndup(p, buf, len);
}

static const char *get_meta_basename(cmd_rec *cmd) {
  const char *base = NULL, *path = NULL;
  pool *p;

  p = cmd->tmp_pool;
  if (pr_cmd_cmp(cmd, PR_CMD_RNTO_ID) == 0) {
    path = pr_fs_decode_path(p, cmd->arg);

  } else if (pr_cmd_cmp(cmd, PR_CMD_RETR_ID) == 0) {
    path = pr_table_get(cmd->notes, "mod_xfer.retr-path", NULL);

  } else if (pr_cmd_cmp(cmd, PR_CMD_APPE_ID) == 0 ||
             pr_cmd_cmp(cmd, PR_CMD_STOR_ID) == 0) {
    path = pr_table_get(cmd->notes, "mod_xfer.store-path", NULL);

  } else if (session.xfer.p != NULL &&
             session.xfer.path != NULL) {
    path = session.xfer.path;

  } else if (pr_cmd_cmp(cmd, PR_CMD_CDUP_ID) == 0 ||
             pr_cmd_cmp(cmd, PR_CMD_PWD_ID) == 0 ||
             pr_cmd_cmp(cmd, PR_CMD_XCUP_ID) == 0 ||
             pr_cmd_cmp(cmd, PR_CMD_XPWD_ID) == 0) {
    path = pr_fs_getcwd();

  } else if (pr_cmd_cmp(cmd, PR_CMD_CWD_ID) == 0 ||
             pr_cmd_cmp(cmd, PR_CMD_XCWD_ID) == 0) {

    /* Note: by this point in the dispatch cycle, the current working
     * directory has already been changed.  For the CWD/XCWD commands, this
     * means that dir_abs_path() may return an improper path, with the target
     * directory being reported twice.  To deal with this, do not use
     * dir_abs_path(), and use pr_fs_getvwd()/pr_fs_getcwd() instead.
     */
    if (session.chroot_path != NULL) {
      /* Chrooted session. */
      path = strcmp(pr_fs_getvwd(), "/") ?  pr_fs_getvwd() :
        session.chroot_path;

    } else {
      /* Non-chrooted session. */
       path = pr_fs_getcwd();
    }

  } else if (pr_cmd_cmp(cmd, PR_CMD_SITE_ID) == 0 &&
             (strncasecmp(cmd->argv[1], "CHGRP", 6) == 0 ||
              strncasecmp(cmd->argv[1], "CHMOD", 6) == 0 ||
              strncasecmp(cmd->argv[1], "UTIME", 6) == 0)) {
    register unsigned int i;
    char *ptr = "";

    for (i = 3; i <= cmd->argc-1; i++) {
      ptr = pstrcat(p, ptr, *ptr ? " " : "",
        pr_fs_decode_path(p, cmd->argv[i]), NULL);
    }

    path = ptr;

  } else {
    /* Some commands (i.e. DELE, MKD, RMD, XMKD, and XRMD) have associated
     * filenames that are not stored in the session.xfer structure; these
     * should be expanded properly as well.
     */
    if (pr_cmd_cmp(cmd, PR_CMD_DELE_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_LIST_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_MDTM_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_MKD_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_MLSD_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_MLST_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_NLST_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_RMD_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_XMKD_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_XRMD_ID) == 0) {
       path = pr_fs_decode_path(p, cmd->arg);

    } else if (pr_cmd_cmp(cmd, PR_CMD_MFMT_ID) == 0) {
      /* MFMT has, as its filename, the second argument. */
      path = pr_fs_decode_path(p, cmd->argv[2]);
    }
  }

  if (path != NULL) {
    char *ptr = NULL;

    ptr = strrchr(path, '/');
    if (ptr != NULL) {
      if (ptr != path) {
        base = ptr + 1;

      } else if (*(ptr + 1) != '\0') {
        base = ptr + 1;

      } else {
        base = path;
      }

    } else {
      base = path;
    }
  }

  return base;
}

static const char *get_meta_dir_name(cmd_rec *cmd) {
  const char *dir_name = NULL;
  pool *p;

  p = cmd->tmp_pool;

  if (pr_cmd_cmp(cmd, PR_CMD_CDUP_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_CWD_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_LIST_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_MLSD_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_MKD_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_NLST_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_RMD_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_XCWD_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_XCUP_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_XMKD_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_XRMD_ID) == 0) {
    char *path, *ptr;

    path = pr_fs_decode_path(p, cmd->arg);
    ptr = strrchr(path, '/');

    if (ptr != NULL) {
      if (ptr != path) {
        dir_name = ptr + 1;

      } else if (*(ptr + 1) != '\0') {
        dir_name = ptr + 1;

      } else {
        dir_name = path;
      }

    } else {
      dir_name = path;
    }

  } else {
    dir_name = pr_fs_getvwd();
  }

  return dir_name;
}

static const char *get_meta_dir_path(cmd_rec *cmd) {
  const char *dir_path = NULL;
  pool *p;

  p = cmd->tmp_pool;

  if (pr_cmd_cmp(cmd, PR_CMD_CDUP_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_LIST_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_MLSD_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_MKD_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_NLST_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_RMD_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_XCUP_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_XMKD_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_XRMD_ID) == 0) {
    dir_path = dir_abs_path(p, pr_fs_decode_path(p, cmd->arg), TRUE);

  } else if (pr_cmd_cmp(cmd, PR_CMD_CWD_ID) == 0 ||
             pr_cmd_cmp(cmd, PR_CMD_XCWD_ID) == 0) {

    /* Note: by this point in the dispatch cycle, the current working
     * directory has already been changed.  For the CWD/XCWD commands, this
     * means that dir_abs_path() may return an improper path, with the target
     * directory being reported twice.  To deal with this, do not use
     * dir_abs_path(), and use pr_fs_getvwd()/pr_fs_getcwd() instead.
     */

    if (session.chroot_path != NULL) {
      /* Chrooted session. */
      if (strncmp(pr_fs_getvwd(), "/", 2) == 0) {
        dir_path = session.chroot_path;

      } else {
        dir_path = pdircat(p, session.chroot_path, pr_fs_getvwd(), NULL);
      }

    } else {
      /* Non-chrooted session. */
      dir_path = pr_fs_getcwd();
    }
  }

  return dir_path;
}

static const char *get_meta_filename(cmd_rec *cmd) {
  const char *filename = NULL;
  pool *p;

  p = cmd->tmp_pool;

  if (pr_cmd_cmp(cmd, PR_CMD_RNTO_ID) == 0) {
    filename = dir_abs_path(p, pr_fs_decode_path(p, cmd->arg), TRUE);

  } else if (pr_cmd_cmp(cmd, PR_CMD_RETR_ID) == 0) {
    const char *path;

    path = pr_table_get(cmd->notes, "mod_xfer.retr-path", NULL);
    if (path != NULL) {
      filename = dir_abs_path(p, path, TRUE);
    }

  } else if (pr_cmd_cmp(cmd, PR_CMD_APPE_ID) == 0 ||
             pr_cmd_cmp(cmd, PR_CMD_STOR_ID) == 0) {
    const char *path;

    path = pr_table_get(cmd->notes, "mod_xfer.store-path", NULL);
    if (path != NULL) {
      filename = dir_abs_path(p, path, TRUE);
    }

  } else if (session.xfer.p != NULL &&
             session.xfer.path != NULL) {
    filename = dir_abs_path(p, session.xfer.path, TRUE);

  } else if (pr_cmd_cmp(cmd, PR_CMD_CDUP_ID) == 0 ||
             pr_cmd_cmp(cmd, PR_CMD_PWD_ID) == 0 ||
             pr_cmd_cmp(cmd, PR_CMD_XCUP_ID) == 0 ||
             pr_cmd_cmp(cmd, PR_CMD_XPWD_ID) == 0) {
    filename = dir_abs_path(p, pr_fs_getcwd(), TRUE);

  } else if (pr_cmd_cmp(cmd, PR_CMD_CWD_ID) == 0 ||
             pr_cmd_cmp(cmd, PR_CMD_XCWD_ID) == 0) {

    /* Note: by this point in the dispatch cycle, the current working
     * directory has already been changed.  For the CWD/XCWD commands, this
     * means that dir_abs_path() may return an improper path, with the target
     * directory being reported twice.  To deal with this, do not use
     * dir_abs_path(), and use pr_fs_getvwd()/pr_fs_getcwd() instead.
     */
    if (session.chroot_path != NULL) {
      /* Chrooted session. */
      if (strncmp(pr_fs_getvwd(), "/", 2) == 0) {
        filename = session.chroot_path;

      } else {
        filename = pdircat(p, session.chroot_path, pr_fs_getvwd(), NULL);
      }

    } else {
      /* Non-chrooted session. */
      filename = pr_fs_getcwd();
    }

  } else if (pr_cmd_cmp(cmd, PR_CMD_SITE_ID) == 0 &&
             (strncasecmp(cmd->argv[1], "CHGRP", 6) == 0 ||
              strncasecmp(cmd->argv[1], "CHMOD", 6) == 0 ||
              strncasecmp(cmd->argv[1], "UTIME", 6) == 0)) {
    register unsigned int i;
    char *ptr = "";

    for (i = 3; i <= cmd->argc-1; i++) {
      ptr = pstrcat(p, ptr, *ptr ? " " : "",
        pr_fs_decode_path(p, cmd->argv[i]), NULL);
    }

    filename = dir_abs_path(p, ptr, TRUE);

  } else {
    /* Some commands (i.e. DELE, MKD, RMD, XMKD, and XRMD) have associated
     * filenames that are not stored in the session.xfer structure; these
     * should be expanded properly as well.
     */
    if (pr_cmd_cmp(cmd, PR_CMD_DELE_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_LIST_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_MDTM_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_MKD_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_MLSD_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_MLST_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_NLST_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_RMD_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_XMKD_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_XRMD_ID) == 0) {
      char *decoded_path;

      decoded_path = pr_fs_decode_path(p, cmd->arg);
      filename = dir_abs_path(p, decoded_path, TRUE);
      if (filename == NULL) {
        filename = dir_abs_path(p, decoded_path, FALSE);
      }

      if (filename == NULL) {
        filename = decoded_path;
      }

    } else if (pr_cmd_cmp(cmd, PR_CMD_MFMT_ID) == 0) {
      char *decoded_path;

      /* MFMT has, as its filename, the second argument. */
      decoded_path = pr_fs_decode_path(p, cmd->argv[2]);
      filename = dir_abs_path(p, decoded_path, TRUE);
      if (filename == NULL) {
        /* This time, try without the interpolation. */
        filename = dir_abs_path(p, decoded_path, FALSE);
      }

      if (filename == NULL) {
        filename = decoded_path;
      }
    }
  }

  return filename;
}

static const char *get_meta_transfer_failure(cmd_rec *cmd) {
  const char *transfer_failure = NULL;

  /* If the current command is one that incurs a data transfer, then we
   * need to do more work.  If not, it's an easy substitution.
   */
  if (pr_cmd_cmp(cmd, PR_CMD_APPE_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_LIST_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_MLSD_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_NLST_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_RETR_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_STOR_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_STOU_ID) == 0) {
    const char *proto;

    proto = pr_session_get_protocol(0);

    if (strncmp(proto, "ftp", 4) == 0 ||
        strncmp(proto, "ftps", 5) == 0) {

      if (!(XFER_ABORTED)) {
        int res;
        const char *resp_code = NULL, *resp_msg = NULL;

        /* Get the last response code/message.  We use heuristics here to
         * determine when to use "failed" versus "success".
         */
        res = pr_response_get_last(cmd->tmp_pool, &resp_code, &resp_msg);
        if (res == 0 &&
            resp_code != NULL) {
          if (*resp_code != '2' &&
              *resp_code != '1') {
            char *ptr;

            /* Parse out/prettify the resp_msg here */
            ptr = strchr(resp_msg, '.');
            if (ptr != NULL) {
              transfer_failure = ptr + 2;

            } else {
              transfer_failure = resp_msg;
            }
          }
        }
      }
    }
  }

  return transfer_failure;
}

static const char *get_meta_transfer_path(cmd_rec *cmd) {
  const char *transfer_path = NULL;
  pool *p;

  p = cmd->tmp_pool;

  if (pr_cmd_cmp(cmd, PR_CMD_RNTO_ID) == 0) {
    transfer_path = dir_best_path(p, pr_fs_decode_path(p, cmd->arg));

  } else if (session.xfer.p != NULL &&
             session.xfer.path != NULL) {
    transfer_path = session.xfer.path;

  } else {
    /* Some commands (i.e. DELE, MKD, XMKD, RMD, XRMD) have associated
     * filenames that are not stored in the session.xfer structure; these
     * should be expanded properly as well.
     */
    if (pr_cmd_cmp(cmd, PR_CMD_DELE_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_MKD_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_XMKD_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_RMD_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_XRMD_ID) == 0) {
      transfer_path = dir_best_path(p, pr_fs_decode_path(p, cmd->arg));
    }
  }

  return transfer_path;
}

static int get_meta_transfer_secs(cmd_rec *cmd, double *transfer_secs) {
  if (session.xfer.p == NULL) {
    return -1;
  }

  /* Make sure that session.xfer.start_time actually has values (which is
   * not always the case).
   */
  if (session.xfer.start_time.tv_sec != 0 ||
      session.xfer.start_time.tv_usec != 0) {
    uint64_t start_ms = 0, end_ms = 0;

    pr_timeval2millis(&(session.xfer.start_time), &start_ms);
    pr_gettimeofday_millis(&end_ms);

    *transfer_secs = (end_ms - start_ms) / 1000.0;
    return 0;
  }

  return -1;
}

static const char *get_meta_transfer_status(cmd_rec *cmd) {
  const char *transfer_status = NULL;

  /* If the current command is one that incurs a data transfer, then we need
   * to do more work.  If not, it's an easy substitution.
   */
  if (pr_cmd_cmp(cmd, PR_CMD_ABOR_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_APPE_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_LIST_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_MLSD_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_NLST_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_RETR_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_STOR_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_STOU_ID) == 0) {
    const char *proto;

    proto = pr_session_get_protocol(0);

    if (strncmp(proto, "ftp", 4) == 0 ||
        strncmp(proto, "ftps", 5) == 0) {
      if (!(XFER_ABORTED)) {
        int res;
        const char *resp_code = NULL, *resp_msg = NULL;

        /* Get the last response code/message.  We use heuristics here to
         * determine when to use "failed" versus "success".
         */
        res = pr_response_get_last(cmd->tmp_pool, &resp_code, &resp_msg);
        if (res == 0 &&
            resp_code != NULL) {
          if (*resp_code == '2') {
            if (pr_cmd_cmp(cmd, PR_CMD_ABOR_ID) != 0) {
              transfer_status = "success";

            } else {
              /* We're handling the ABOR command, so obviously the value
               * should be 'cancelled'.
               */
              transfer_status = "cancelled";
            }

          } else if (*resp_code == '1') {
            /* If the first digit of the response code is 1, then the
             * response code (for a data transfer command) is probably 150,
             * which means that the transfer was still in progress (didn't
             * complete with a 2xx/4xx response code) when we are called here,
             * which in turn means a timeout kicked in.
             */
            transfer_status = "timeout";

          } else {
            transfer_status = "failed";
          }

        } else {
          transfer_status = "success";
        }

      } else {
        transfer_status = "cancelled";
      }

    } else {
      /* mod_sftp stashes a note for us in the command notes if the transfer
       * failed.
       */
      const char *sftp_status;

      sftp_status = pr_table_get(cmd->notes, "mod_sftp.file-status", NULL);
      if (sftp_status == NULL) {
        transfer_status = "success";

      } else {
        transfer_status = "failed";
      }
    }
  }

  return transfer_status;
}

static const char *get_meta_transfer_type(cmd_rec *cmd) {
  const char *transfer_type = NULL;

  /* If the current command is one that incurs a data transfer, then we
   * need to do more work.  If not, it's an easy substitution.
   */
  if (pr_cmd_cmp(cmd, PR_CMD_APPE_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_LIST_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_MLSD_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_NLST_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_RETR_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_STOR_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_STOU_ID) == 0) {
    const char *proto;

    proto = pr_session_get_protocol(0);

    if (strncmp(proto, "sftp", 5) == 0 ||
        strncmp(proto, "scp", 4) == 0) {

      /* Always binary. */
      transfer_type = "binary";

    } else {
      if ((session.sf_flags & SF_ASCII) ||
          (session.sf_flags & SF_ASCII_OVERRIDE)) {
        transfer_type = "ASCII";

      } else {
        transfer_type = "binary";
      }
    }
  }

  return transfer_type;
}

static int resolve_logfmt_id(pool *p, unsigned char logfmt_id,
    const char *logfmt_data, pr_jot_ctx_t *ctx, cmd_rec *cmd,
    int (*on_meta)(pool *, pr_jot_ctx_t *, unsigned char,
      const char *, const void *),
    int (*on_default)(pool *, pr_jot_ctx_t *, unsigned char)) {
  int res = 0;

  if (pr_trace_get_level(trace_channel) >= 17) {
    const char *id_name;

    id_name = pr_jot_get_logfmt_id_name(logfmt_id);
    if (id_name != NULL) {

      if (logfmt_data != NULL) {
        pr_trace_msg(trace_channel, 17,
          "resolving LogFormat ID %u (%s) with data '%s' (%lu)",
          (unsigned int) logfmt_id, id_name, logfmt_data,
          (unsigned long) strlen(logfmt_data));

      } else {
        pr_trace_msg(trace_channel, 17, "resolving LogFormat ID %u (%s)",
          (unsigned int) logfmt_id, id_name);
      }
    }
  }

  switch (logfmt_id) {
    case LOGFMT_META_BASENAME: {
      const char *basename;

      basename = get_meta_basename(cmd);
      if (basename != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, basename);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_BYTES_SENT: {
      double bytes_sent;
      int have_bytes = FALSE;

      if (session.xfer.p != NULL) {
        bytes_sent = session.xfer.total_bytes;
        have_bytes = TRUE;

      } else if (pr_cmd_cmp(cmd, PR_CMD_DELE_ID) == 0) {
        bytes_sent = jot_deleted_filesz;
        have_bytes = TRUE;
      }

      if (have_bytes == TRUE) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, &bytes_sent);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_CUSTOM: {
      if (logfmt_data != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, logfmt_data);
      }

      break;
    }

    case LOGFMT_META_EPOCH: {
      double epoch;
      struct timeval tv;

      (void) gettimeofday(&tv, NULL);
      epoch = (double) tv.tv_sec;
      res = (on_meta)(p, ctx, logfmt_id, NULL, &epoch);
      break;
    }

    case LOGFMT_META_FILENAME: {
      const char *filename;

      filename = get_meta_filename(cmd);
      if (filename != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, filename);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_FILE_OFFSET: {
      const off_t *note;

      note = pr_table_get(cmd->notes, "mod_xfer.file-offset", NULL);
      if (note != NULL) {
        double file_offset;

        file_offset = (double) *note;;
        res = (on_meta)(p, ctx, logfmt_id, NULL, &file_offset);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_FILE_SIZE: {
      const off_t *note;

      note = pr_table_get(cmd->notes, "mod_xfer.file-size", NULL);
      if (note != NULL) {
        double file_size;

        file_size = (double) *note;
        res = (on_meta)(p, ctx, logfmt_id, NULL, &file_size);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_ENV_VAR: {
      if (logfmt_data != NULL) {
        const char *key;
        char *env;

        key = logfmt_data;
        env = pr_env_get(p, key);
        if (env != NULL) {
          char *field_name;

          field_name = pstrcat(p, PR_JOT_LOGFMT_ENV_VAR_KEY, key, NULL);
          res = (on_meta)(p, ctx, logfmt_id, field_name, env);

        } else {
          res = (on_default)(p, ctx, logfmt_id);
        }
      }

      break;
    }

    case LOGFMT_META_REMOTE_HOST: {
      const char *name;

      name = pr_netaddr_get_sess_remote_name();
      res = (on_meta)(p, ctx, logfmt_id, NULL, name);
      break;
    }

    case LOGFMT_META_REMOTE_IP: {
      const char *ipstr;

      ipstr = pr_netaddr_get_ipstr(pr_netaddr_get_sess_local_addr());
      res = (on_meta)(p, ctx, logfmt_id, NULL, ipstr);
      break;
    }

    case LOGFMT_META_REMOTE_PORT: {
      double client_port;
      const pr_netaddr_t *remote_addr;

      remote_addr = pr_netaddr_get_sess_remote_addr();
      if (remote_addr != NULL) {
        client_port = ntohs(pr_netaddr_get_port(remote_addr));
        res = (on_meta)(p, ctx, logfmt_id, NULL, &client_port);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_IDENT_USER: {
      const char *ident_user;

      ident_user = pr_table_get(session.notes, "mod_ident.rfc1413-ident", NULL);
      if (ident_user != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, ident_user);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_PID: {
      double sess_pid;

      sess_pid = session.pid;
      res = (on_meta)(p, ctx, logfmt_id, NULL, &sess_pid);
      break;
    }

    case LOGFMT_META_TIME: {
      const char *time_fmt = "%Y-%m-%d %H:%M:%S %z";
      char ts[128];
      struct tm *tm;
      time_t now;

      now = time(NULL);
      tm = pr_gmtime(NULL, &now);

      if (logfmt_data != NULL) {
        time_fmt = logfmt_data;
      }

      strftime(ts, sizeof(ts)-1, time_fmt, tm);
      res = (on_meta)(p, ctx, logfmt_id, logfmt_data, ts);
      break;
    }

    case LOGFMT_META_SECONDS: {
      double transfer_secs;

      if (get_meta_transfer_secs(cmd, &transfer_secs) == 0) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, &transfer_secs);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_COMMAND: {
      const char *full_cmd;

      /* Note: Ignore "fake" commands like CONNECT, DISCONNECT, EXIT. */
      if ((cmd->cmd_class & CL_CONNECT) ||
          (cmd->cmd_class & CL_DISCONNECT)) {
        full_cmd = NULL;

      } else {
        if (pr_cmd_cmp(cmd, PR_CMD_PASS_ID) == 0 &&
            session.hide_password) {
          full_cmd = "PASS (hidden)";

        } else if (pr_cmd_cmp(cmd, PR_CMD_ADAT_ID) == 0) {
          full_cmd = "ADAT (hidden)";

        } else {
          full_cmd = get_full_cmd(cmd);
        }
      }

      if (full_cmd != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, full_cmd);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_LOCAL_NAME: {
      if (cmd->server != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, cmd->server->ServerName);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_LOCAL_PORT: {
      if (cmd->server != NULL) {
        double server_port;

        server_port = cmd->server->ServerPort;
        res = (on_meta)(p, ctx, logfmt_id, NULL, &server_port);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_LOCAL_IP: {
      const char *ipstr;

      ipstr = pr_netaddr_get_ipstr(pr_netaddr_get_sess_local_addr());
      res = (on_meta)(p, ctx, logfmt_id, NULL, ipstr);
      break;
    }

    case LOGFMT_META_LOCAL_FQDN: {
      const char *dnsstr;

      dnsstr = pr_netaddr_get_dnsstr(pr_netaddr_get_sess_local_addr());
      res = (on_meta)(p, ctx, logfmt_id, NULL, dnsstr);
      break;
    }

    case LOGFMT_META_USER: {
      if (session.user != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, session.user);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_ORIGINAL_USER: {
      const char *orig_user = NULL;

      orig_user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
      if (orig_user != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, orig_user);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_RESPONSE_CODE: {
      const char *resp_code = NULL;
      double resp_num;
      int have_code = FALSE, last;

      last = pr_response_get_last(cmd->tmp_pool, &resp_code, NULL);
      if (last == 0 &&
          resp_code != NULL) {
        resp_num = atoi(resp_code);
        have_code = TRUE;

      /* Hack to add return code for proper logging of QUIT command. */
      } else if (pr_cmd_cmp(cmd, PR_CMD_QUIT_ID) == 0) {
        resp_num = 221;
        have_code = TRUE;
      }

      if (have_code == TRUE) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, &resp_num);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_CLASS: {
      if (session.conn_class != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, session.conn_class);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_ANON_PASS: {
      const char *anon_pass;

      anon_pass = pr_table_get(session.notes, "mod_auth.anon-passwd", NULL);
      if (anon_pass != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, anon_pass);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_METHOD: {
      const char *method = NULL;

      if (pr_cmd_cmp(cmd, PR_CMD_SITE_ID) != 0) {
        /* Note: Ignore "fake" commands like CONNECT, but NOT DISCONNECT/EXIT.
         * This is for backward compatibility, for better/worse.
         */
        if (!(cmd->cmd_class & CL_CONNECT)) {
          method = cmd->argv[0];
        }

      } else {
        char buf[128], *ch;
        size_t len;

        /* Make sure that the SITE command used is all in uppercase, for
         * logging purposes.
         */
        for (ch = cmd->argv[1]; *ch; ch++) {
          *ch = toupper((int) *ch);
        }

        len = pr_snprintf(buf, sizeof(buf)-1, "%s %s", (char *) cmd->argv[0],
          (char *) cmd->argv[1]);

        method = pstrndup(p, buf, len);
      }

      if (method != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, method);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_XFER_PATH: {
      const char *transfer_path;

      transfer_path = get_meta_transfer_path(cmd);
      if (transfer_path != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, transfer_path);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_DIR_NAME: {
      const char *dir_name;

      dir_name = get_meta_dir_name(cmd);
      if (dir_name != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, dir_name);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_DIR_PATH: {
      const char *dir_path;

      dir_path = get_meta_dir_path(cmd);
      if (dir_path != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, dir_path);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_CMD_PARAMS: {
      const char *params = NULL;

      /* Note: Ignore "fake" commands like CONNECT, DISCONNECT, EXIT. */
      if ((cmd->cmd_class & CL_CONNECT) ||
          (cmd->cmd_class & CL_DISCONNECT)) {
        params = NULL;

      } else {
        if (pr_cmd_cmp(cmd, PR_CMD_ADAT_ID) == 0 ||
            pr_cmd_cmp(cmd, PR_CMD_PASS_ID) == 0) {
          params = "(hidden)";

        } else if (cmd->argc > 1) {
          params = pr_fs_decode_path(p, cmd->arg);
        }
      }

      if (params != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, params);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_RESPONSE_STR: {
      const char *resp_msg = NULL;
      int last;

      last = pr_response_get_last(p, NULL, &resp_msg);
      if (last == 0 &&
          resp_msg != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, resp_msg);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_RESPONSE_MS: {
      const uint64_t *start_ms;

      start_ms = pr_table_get(cmd->notes, "start_ms", NULL);
      if (start_ms != NULL) {
        uint64_t end_ms = 0;
        double response_ms;

        pr_gettimeofday_millis(&end_ms);

        response_ms = end_ms - *start_ms;
        res = (on_meta)(p, ctx, logfmt_id, NULL, &response_ms);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_PROTOCOL: {
      const char *proto;

      proto = pr_session_get_protocol(0);
      res = (on_meta)(p, ctx, logfmt_id, NULL, proto);
      break;
    }

    case LOGFMT_META_VERSION: {
      const char *version;

      version = PROFTPD_VERSION_TEXT;
      res = (on_meta)(p, ctx, logfmt_id, NULL, version);
      break;
    }

    case LOGFMT_META_RENAME_FROM: {
      if (pr_cmd_cmp(cmd, PR_CMD_RNTO_ID) == 0) {
        const char *rnfr_path;

        rnfr_path = pr_table_get(session.notes, "mod_core.rnfr-path", NULL);
        if (rnfr_path != NULL) {
          res = (on_meta)(p, ctx, logfmt_id, NULL, rnfr_path);

        } else {
          res = (on_default)(p, ctx, logfmt_id);
        }

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_FILE_MODIFIED: {
      int modified = FALSE;
      const char *val;

      val = pr_table_get(cmd->notes, "mod_xfer.file-modified", NULL);
      if (val != NULL) {
        if (strncmp(val, "true", 5) == 0) {
          modified = TRUE;
        }
      }

      res = (on_meta)(p, ctx, logfmt_id, NULL, &modified);
      break;
    }

    case LOGFMT_META_UID: {
      double sess_uid;

      if (session.auth_mech != NULL) {
        sess_uid = session.login_uid;

      } else {
        sess_uid = geteuid();
      }

      res = (on_meta)(p, ctx, logfmt_id, NULL, &sess_uid);
      break;
    }

    case LOGFMT_META_GID: {
      double sess_gid;

      if (session.auth_mech != NULL) {
        sess_gid = session.login_gid;

      } else {
        sess_gid = getegid();
      }

      res = (on_meta)(p, ctx, logfmt_id, NULL, &sess_gid);
      break;
    }

    case LOGFMT_META_RAW_BYTES_IN: {
      double bytes_rcvd;

      bytes_rcvd = session.total_raw_in;
      res = (on_meta)(p, ctx, logfmt_id, NULL, &bytes_rcvd);
      break;
    }

    case LOGFMT_META_RAW_BYTES_OUT: {
      double bytes_sent;

      bytes_sent = session.total_raw_out;
      res = (on_meta)(p, ctx, logfmt_id, NULL, &bytes_sent);
      break;
    }

    case LOGFMT_META_EOS_REASON: {
      const char *reason = NULL, *details = NULL, *eos = NULL;

      if (session.disconnect_reason != PR_SESS_DISCONNECT_UNSPECIFIED) {
        eos = pr_session_get_disconnect_reason(&details);
        if (eos != NULL) {
          if (details != NULL) {
            reason = pstrcat(p, eos, ": ", details, NULL);

          } else {
            reason = eos;
          }
        }
      }

      if (reason != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, reason);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_VHOST_IP:
      if (cmd->server != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, cmd->server->ServerAddress);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;

    case LOGFMT_META_NOTE_VAR: {
      if (logfmt_data != NULL) {
        const char *note = NULL;

        pr_trace_msg(trace_channel, 19,
          "resolving NOTE_VAR using note key '%s'", logfmt_data);

        /* Check in the cmd->notes table first. */
        note = pr_table_get(cmd->notes, logfmt_data, NULL);
        if (note == NULL) {

          /* If not there, check in the session.notes table. */
          note = pr_table_get(session.notes, logfmt_data, NULL);
        }

        if (note != NULL) {
          char *field_name;

          field_name = pstrcat(p, PR_JOT_LOGFMT_NOTE_KEY, note, NULL);
          res = (on_meta)(p, ctx, logfmt_id, field_name, note);

        } else {
          res = (on_default)(p, ctx, logfmt_id);
        }
      }

      break;
    }

    case LOGFMT_META_XFER_STATUS: {
      const char *transfer_status;

      transfer_status = get_meta_transfer_status(cmd);
      if (transfer_status != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, transfer_status);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_XFER_FAILURE: {
      const char *transfer_failure;

      transfer_failure = get_meta_transfer_failure(cmd);
      if (transfer_failure != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, transfer_failure);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_XFER_MS: {
      if (session.xfer.p != NULL) {
        /* Make sure that session.xfer.start_time actually has values (which
         * is not always the case).
         */
        if (session.xfer.start_time.tv_sec != 0 ||
            session.xfer.start_time.tv_usec != 0) {
          uint64_t start_ms = 0, end_ms = 0;
          double transfer_ms;

          pr_timeval2millis(&(session.xfer.start_time), &start_ms);
          pr_gettimeofday_millis(&end_ms);

          transfer_ms = end_ms - start_ms;
          res = (on_meta)(p, ctx, logfmt_id, NULL, &transfer_ms);

        } else {
          res = (on_default)(p, ctx, logfmt_id);
        }

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_XFER_TYPE: {
      const char *transfer_type;

      transfer_type = get_meta_transfer_type(cmd);
      if (transfer_type != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, transfer_type);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    case LOGFMT_META_MICROSECS: {
      double sess_usecs;
      struct timeval now;

      gettimeofday(&now, NULL);
      sess_usecs = now.tv_usec;

      res = (on_meta)(p, ctx, logfmt_id, NULL, &sess_usecs);
      break;
    }

    case LOGFMT_META_MILLISECS: {
      double sess_msecs;
      struct timeval now;

      gettimeofday(&now, NULL);

      /* Convert microsecs to millisecs. */
      sess_msecs = (now.tv_usec / 1000);

      res = (on_meta)(p, ctx, logfmt_id, NULL, &sess_msecs);
      break;
    }

    case LOGFMT_META_ISO8601: {
      char ts[128];
      struct tm *tm;
      struct timeval now;
      unsigned long millis;
      size_t len;

      gettimeofday(&now, NULL);
      tm = pr_localtime(NULL, (const time_t *) &(now.tv_sec));

      len = strftime(ts, sizeof(ts)-1, "%Y-%m-%d %H:%M:%S", tm);

      /* Convert microsecs to millisecs. */
      millis = now.tv_usec / 1000;

      pr_snprintf(ts + len, sizeof(ts) - len - 1, ",%03lu", millis);
      res = (on_meta)(p, ctx, logfmt_id, NULL, ts);
      break;
    }

    case LOGFMT_META_GROUP: {
      if (session.group != NULL) {
        res = (on_meta)(p, ctx, logfmt_id, NULL, session.group);

      } else {
        res = (on_default)(p, ctx, logfmt_id);
      }

      break;
    }

    default:
      pr_trace_msg(trace_channel, 2, "skipping unsupported LogFormat ID %u",
        (unsigned int) logfmt_id);
      break;
  }

  if (res < 0) {
    return -1;
  }

  return 0;
}

static int resolve_meta(pool *p, unsigned char **logfmt, pr_jot_ctx_t *ctx,
    cmd_rec *cmd,
    int (*on_meta)(pool *, pr_jot_ctx_t *, unsigned char, const char *,
      const void *),
    int (*on_default)(pool *, pr_jot_ctx_t *, unsigned char)) {
  int res = 0;
  unsigned char *ptr, logfmt_id;
  const char *logfmt_data = NULL;
  size_t consumed_bytes = 0, logfmt_datalen = 0;

  ptr = (*logfmt) + 1;
  logfmt_id = *ptr;

  switch (logfmt_id) {
    case LOGFMT_META_CUSTOM:
    case LOGFMT_META_ENV_VAR:
    case LOGFMT_META_NOTE_VAR:
    case LOGFMT_META_TIME: {
      if (*(ptr + 1) == LOGFMT_META_START &&
          *(ptr + 2) == LOGFMT_META_ARG) {
        logfmt_data = get_meta_arg(p, (ptr + 3), &logfmt_datalen);

        /* Skip past the META_START, META_ARG, META_ARG_END, and the data. */
        consumed_bytes += (3 + logfmt_datalen);
      }
    }

    default:
      consumed_bytes += 1;
  }

  /* Note: the LogFormat data, if present, is always text.  Callbacks ASSUME
   * that that text will be a NUL-terminated string.
   */
  logfmt_data = pstrndup(p, logfmt_data, logfmt_datalen);

  res = resolve_logfmt_id(p, logfmt_id, logfmt_data, ctx, cmd, on_meta,
    on_default);
  if (res < 0) {
    return -1;
  }

  /* Most of the time, a meta is encoded in just one byte, so we adjust the
   * pointer by incrementing by one.  Some meta are encoded using multiple
   * bytes (e.g. environment variables, notes, etc).  The resolving of these
   * meta will adjust the `consumed_bytes` value themselves.
   */

  ptr += consumed_bytes;
  *logfmt = ptr;
  return 0;
}

static int is_jottable_class(cmd_rec *cmd, int included_classes,
    int excluded_classes) {
  int jottable = FALSE;

  if (cmd->cmd_class != 0) {
    /* If the command is unknown, then we only want to log if this filter is
     * configured to log ALL commands (Bug#4313).
     */
    if (cmd->cmd_id >= 0) {
      if (cmd->cmd_class & included_classes) {
        jottable = TRUE;
      }

      if (cmd->cmd_class & excluded_classes) {
        jottable = FALSE;
      }

    } else {
      /* Handle unknown command.  The "CONNECT" and "EXIT" commands are
       * internally generated, and thus have special treatment.
       */

      if ((cmd->cmd_class & CL_CONNECT) ||
          (cmd->cmd_class & CL_DISCONNECT)) {
        if (cmd->cmd_class & included_classes) {
          jottable = TRUE;
        }

        if (cmd->cmd_class & excluded_classes) {
          jottable = FALSE;
        }

      } else {
        if (included_classes == CL_ALL) {
          jottable = TRUE;
        }
      }
    }

  } else {
    /* If the logging class of this command is unknown (defaults to zero),
     * AND this filter logs ALL events, it is jottable.
     */
    if (included_classes == CL_ALL) {
      jottable = TRUE;
    }
  }

  return jottable;
}

static int is_jottable_cmd(cmd_rec *cmd, int *cmd_ids, size_t ncmd_ids) {
  register unsigned int i;
  int jottable = FALSE;

  for (i = 0; i < ncmd_ids; i++) {
    if (pr_cmd_cmp(cmd, cmd_ids[i]) == 0) {
      jottable = TRUE;
      break;
    }
  }

  return jottable;
}

static int is_jottable(pool *p, cmd_rec *cmd, pr_jot_filters_t *filters) {
  int jottable = FALSE;

  if (filters == NULL) {
    return TRUE;
  }

  jottable = is_jottable_class(cmd, filters->included_classes,
    filters->excluded_classes);
  if (jottable == TRUE) {
    return TRUE;
  }

  if (filters->cmd_ids != NULL) {
    jottable = is_jottable_cmd(cmd, filters->cmd_ids->elts,
      filters->cmd_ids->nelts);
  }

  return jottable;
}

static int jot_resolve_on_default(pool *p, pr_jot_ctx_t *ctx,
    unsigned char meta) {
  return 0;
}

static int jot_resolve_on_other(pool *p, pr_jot_ctx_t *ctx, unsigned char *text,
    size_t text_len) {
  return 0;
}

int pr_jot_resolve_logfmt_id(pool *p, cmd_rec *cmd, pr_jot_filters_t *filters,
    unsigned char logfmt_id, const char *logfmt_data, size_t logfmt_datalen,
    pr_jot_ctx_t *ctx,
    int (*on_meta)(pool *, pr_jot_ctx_t *, unsigned char, const char *,
      const void *),
    int (*on_default)(pool *, pr_jot_ctx_t *, unsigned char)) {
  int jottable = FALSE, res = 0;

  if (p == NULL ||
      cmd == NULL ||
      on_meta == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* There are some IDs which are reserved. */
  if (logfmt_id == 0 ||
      logfmt_id == LOGFMT_META_START ||
      logfmt_id == LOGFMT_META_ARG_END) {
    errno = EINVAL;
    return -1;
  }

  if (on_default == NULL) {
    on_default = jot_resolve_on_default;
  }

  jottable = is_jottable(p, cmd, filters);
  if (jottable == FALSE) {
    pr_trace_msg(trace_channel, 17, "ignoring filtered event '%s'",
      (const char *) cmd->argv[0]);
    errno = EPERM;
    return -1;
  }

  /* Special handling for the CONNECT/DISCONNECT meta. */
  switch (logfmt_id) {
    case LOGFMT_META_CONNECT: {
      pr_trace_msg(trace_channel, 17, "resolving LogFormat ID %u (%s)",
        (unsigned int) logfmt_id, pr_jot_get_logfmt_id_name(logfmt_id));
      if (cmd->cmd_class == CL_CONNECT) {
        int val = TRUE;
        res = (on_meta)(p, ctx, LOGFMT_META_CONNECT, NULL, &val);
      }

      return res;
    }

    case LOGFMT_META_DISCONNECT: {
      pr_trace_msg(trace_channel, 17, "resolving LogFormat ID %u (%s)",
        (unsigned int) logfmt_id, pr_jot_get_logfmt_id_name(logfmt_id));
      if (cmd->cmd_class == CL_DISCONNECT) {
        int val = TRUE;
        res = (on_meta)(p, ctx, LOGFMT_META_DISCONNECT, NULL, &val);
      }
      return res;
    }

    default:
      break;
  }

  res = resolve_logfmt_id(p, logfmt_id, logfmt_data, ctx, cmd, on_meta,
    on_default);
  return res;
}

int pr_jot_resolve_logfmt(pool *p, cmd_rec *cmd, pr_jot_filters_t *filters,
    unsigned char *logfmt, pr_jot_ctx_t *ctx,
    int (*on_meta)(pool *, pr_jot_ctx_t *, unsigned char, const char *,
      const void *),
    int (*on_default)(pool *, pr_jot_ctx_t *, unsigned char),
    int (*on_other)(pool *, pr_jot_ctx_t *, unsigned char *, size_t)) {
  int jottable = FALSE, res;
  size_t text_len;

  if (p == NULL ||
      cmd == NULL ||
      logfmt == NULL ||
      on_meta == NULL) {
    errno = EINVAL;
    return -1;
  }

  jottable = is_jottable(p, cmd, filters);
  if (jottable == FALSE) {
    pr_trace_msg(trace_channel, 17, "ignoring filtered event '%s'",
      (const char *) cmd->argv[0]);
    errno = EPERM;
    return -1;
  }

  if (on_default == NULL) {
    on_default = jot_resolve_on_default;
  }

  if (on_other == NULL) {
    on_other = jot_resolve_on_other;
  }

  text_len = 0;
  res = 0;

  while (*logfmt) {
    pr_signals_handle();

    if (res < 0) {
      return -1;
    }

    /* Scan the buffer until we reach a variable.  Keep track of how much
     * we've scanned, so that that entire segment of text can be given
     * to the `on_other` callback at once.
     */
    if (*logfmt != LOGFMT_META_START) {
      logfmt++;
      text_len++;
      continue;
    }

    if (text_len > 0) {
      res = (on_other)(p, ctx, logfmt - text_len, text_len);
      if (res < 0) {
        return -1;
      }

      /* Reset our non-variable segment length for the next iteration. */
      text_len = 0;
    }

    /* Special handling for the CONNECT/DISCONNECT meta. */
    switch (*(logfmt + 1)) {
      case LOGFMT_META_CONNECT:
        if (cmd->cmd_class == CL_CONNECT) {
          int val = TRUE;
          pr_trace_msg(trace_channel, 17, "resolving LogFormat ID %u (%s)",
            LOGFMT_META_CONNECT,
            pr_jot_get_logfmt_id_name(LOGFMT_META_CONNECT));
          res = (on_meta)(p, ctx, LOGFMT_META_CONNECT, NULL, &val);
        }

        /* Don't forget to advance past the META_START and META_CONNECT. */
        logfmt += 2;
        break;

      case LOGFMT_META_DISCONNECT:
        if (cmd->cmd_class == CL_DISCONNECT) {
          int val = TRUE;
          pr_trace_msg(trace_channel, 17, "resolving LogFormat ID %u (%s)",
            LOGFMT_META_DISCONNECT,
            pr_jot_get_logfmt_id_name(LOGFMT_META_DISCONNECT));
          res = (on_meta)(p, ctx, LOGFMT_META_DISCONNECT, NULL, &val);
        }

        /* Don't forget to advance past the META_START and
         * META_DISCONNECT.
         */
        logfmt += 2;
        break;

      default:
        res = resolve_meta(p, &logfmt, ctx, cmd, on_meta, on_default);
    }
  }

  /* "Flush" any remaining non-variable text. */
  if (text_len > 0) {
    res = (on_other)(p, ctx, logfmt - text_len, text_len);
    if (res < 0) {
      return -1;
    }
  }

  return 0;
}

static int jot_parse_on_unknown(pool *p, pr_jot_ctx_t *ctx, const char *text,
    size_t text_len) {
  return 0;
}

static int jot_parse_on_other(pool *p, pr_jot_ctx_t *ctx, char ch) {
  return 0;
}

static int parse_short_id(const char *text, unsigned char *logfmt_id) {
  switch (*text) {
    case 'A':
      *logfmt_id = LOGFMT_META_ANON_PASS;
      break;

    case 'D':
      *logfmt_id = LOGFMT_META_DIR_PATH;
      break;

    case 'E':
      *logfmt_id = LOGFMT_META_EOS_REASON;
      break;

    case 'F':
      *logfmt_id = LOGFMT_META_XFER_PATH;
      break;

    case 'H':
      *logfmt_id = LOGFMT_META_VHOST_IP;
      break;

    case 'I':
      *logfmt_id = LOGFMT_META_RAW_BYTES_IN;
      break;

    case 'J':
      *logfmt_id = LOGFMT_META_CMD_PARAMS;
      break;

    case 'L':
      *logfmt_id = LOGFMT_META_LOCAL_IP;
      break;

    case 'O':
      *logfmt_id = LOGFMT_META_RAW_BYTES_OUT;
      break;

    case 'P':
      *logfmt_id = LOGFMT_META_PID;
      break;

    case 'R':
      *logfmt_id = LOGFMT_META_RESPONSE_MS;
      break;

    case 'S':
      *logfmt_id = LOGFMT_META_RESPONSE_STR;
      break;

    case 'T':
      *logfmt_id = LOGFMT_META_SECONDS;
      break;

    case 'U':
      *logfmt_id = LOGFMT_META_ORIGINAL_USER;
      break;

    case 'V':
      *logfmt_id = LOGFMT_META_LOCAL_FQDN;
      break;

    case 'a':
      *logfmt_id = LOGFMT_META_REMOTE_IP;
      break;

    case 'b':
      *logfmt_id = LOGFMT_META_BYTES_SENT;
      break;

    case 'c':
      *logfmt_id = LOGFMT_META_CLASS;
      break;

    case 'd':
      *logfmt_id = LOGFMT_META_DIR_NAME;
      break;

    case 'f':
      *logfmt_id = LOGFMT_META_FILENAME;
      break;

    case 'g':
      *logfmt_id = LOGFMT_META_GROUP;
      break;

    case 'h':
      *logfmt_id = LOGFMT_META_REMOTE_HOST;
      break;

    case 'l':
      *logfmt_id = LOGFMT_META_IDENT_USER;
      break;

    case 'm':
      *logfmt_id = LOGFMT_META_METHOD;
      break;

    case 'p':
      *logfmt_id = LOGFMT_META_LOCAL_PORT;
      break;

    case 'r':
      *logfmt_id = LOGFMT_META_COMMAND;
      break;

    case 's':
      *logfmt_id = LOGFMT_META_RESPONSE_CODE;
      break;

    case 't':
      *logfmt_id = LOGFMT_META_TIME;
      break;

    case 'u':
      *logfmt_id = LOGFMT_META_USER;
      break;

    case 'v':
      *logfmt_id = LOGFMT_META_LOCAL_NAME;
      break;

    case 'w':
      *logfmt_id = LOGFMT_META_RENAME_FROM;
      break;

    default:
      errno = ENOENT;
      return -1;
  }

  return 1;
}

static int parse_unknown_id(const char *text, const char **logfmt_data,
    size_t *logfmt_datalen) {
  char *ptr;

  if (*text != '{') {
    errno = ENOENT;
    return -1;
  }

  ptr = strchr(text + 1, '}');
  if (ptr == NULL) {
    errno = ENOENT;
    return -1;
  }

  *logfmt_data = (text + 1);
  *logfmt_datalen = (ptr - text - 1);
  return (2 + *logfmt_datalen);
}

static int parse_long_id(const char *text, unsigned char *logfmt_id,
    const char **logfmt_data, size_t *logfmt_datalen) {
  int res;

  if (strncmp(text, "{basename}", 10) == 0) {
    *logfmt_id = LOGFMT_META_BASENAME;
    return 10;
  }

  if (strncmp(text, "{env:", 5) == 0) {
    char *ptr;

    ptr = strchr(text + 5, '}');
    if (ptr != NULL) {
      *logfmt_id = LOGFMT_META_ENV_VAR;
      *logfmt_data = text + 5;
      *logfmt_datalen = (ptr - text) - 5;

      /* Advance 5 for the leading '{env:', and one more for the
       * trailing '}' character.
       */
      return (6 + *logfmt_datalen);
    }
  }

  if (strncmp(text, "{epoch}", 7) == 0) {
    *logfmt_id = LOGFMT_META_EPOCH;
    return 7;
  }

  if (strncmp(text, "{file-modified}", 15) == 0) {
    *logfmt_id = LOGFMT_META_FILE_MODIFIED;
    return 15;
  }

  if (strncmp(text, "{file-offset}", 13) == 0) {
    *logfmt_id = LOGFMT_META_FILE_OFFSET;
    return 13;
  }

  if (strncmp(text, "{file-size}", 11) == 0) {
    *logfmt_id = LOGFMT_META_FILE_SIZE;
    return 11;
  }

  if (strncmp(text, "{gid}", 5) == 0) {
    *logfmt_id = LOGFMT_META_GID;
    return 5;
  }

  if (strncasecmp(text, "{iso8601}", 9) == 0) {
    *logfmt_id = LOGFMT_META_ISO8601;
    return 9;
  }

  if (strncmp(text, "{microsecs}", 11) == 0) {
    *logfmt_id = LOGFMT_META_MICROSECS;
    return 11;
  }

  if (strncmp(text, "{millisecs}", 11) == 0) {
    *logfmt_id = LOGFMT_META_MILLISECS;
    return 11;
  }

  if (strncmp(text, "{note:", 6) == 0) {
    char *ptr;

    ptr = strchr(text + 6, '}');
    if (ptr != NULL) {
      *logfmt_id = LOGFMT_META_NOTE_VAR;
      *logfmt_data = text + 6;
      *logfmt_datalen = (ptr - text) - 6;

      /* Advance 6 for the leading '{note:', and one more for the
       * trailing '}' character.
       */
      return (7 + *logfmt_datalen);
    }
  }

  if (strncmp(text, "{protocol}", 10) == 0) {
    *logfmt_id = LOGFMT_META_PROTOCOL;
    return 10;
  }

  if (strncmp(text, "{remote-port}", 13) == 0) {
    *logfmt_id = LOGFMT_META_REMOTE_PORT;
    return 13;
  }

  if (strncmp(text, "{time:", 6) == 0) {
    char *ptr;

    ptr = strchr(text + 6, '}');
    if (ptr != NULL) {
      *logfmt_id = LOGFMT_META_TIME;
      *logfmt_data = text + 6;
      *logfmt_datalen = (ptr - text) - 6;

      /* Advance 6 for the leading '{time:', and one more for the
       * trailing '}' character.
       */
      return (7 + *logfmt_datalen);
    }
  }

  if (strncmp(text, "{transfer-failure}", 18) == 0) {
    *logfmt_id = LOGFMT_META_XFER_FAILURE;
    return 18;
  }

  if (strncmp(text, "{transfer-millisecs}", 20) == 0) {
    *logfmt_id = LOGFMT_META_XFER_MS;
    return 20;
  }

  if (strncmp(text, "{transfer-status}", 17) == 0) {
    *logfmt_id = LOGFMT_META_XFER_STATUS;
    return 17;
  }

  if (strncmp(text, "{transfer-type}", 15) == 0) {
    *logfmt_id = LOGFMT_META_XFER_TYPE;
    return 15;
  }

  if (strncmp(text, "{uid}", 5) == 0) {
    *logfmt_id = LOGFMT_META_UID;
    return 5;
  }

  if (strncmp(text, "{version}", 9) == 0) {
    *logfmt_id = LOGFMT_META_VERSION;
    return 9;
  }

  /* Check whether the text looks like it might be a long variable with the
   * odd syntax that mod_log uses, e.g. "%{...}e" or "%{...}t".
   */
  res = parse_unknown_id(text, logfmt_data, logfmt_datalen);
  if (res > 0) {
    if (*(text + res) == 'e') {
      *logfmt_id = LOGFMT_META_ENV_VAR;
      return (1 + res);
    }

    if (*(text + res) == 't') {
      *logfmt_id = LOGFMT_META_TIME;
      return (1 + res);
    }
  }

  errno = ENOENT;
  return -1;
}

static void jot_parsed_append_byte(pr_jot_parsed_t *parsed, char ch) {
  if (parsed->buflen > 0) {
    pr_trace_msg(trace_channel, 19, "appending character (%c) to format", ch);
    *(parsed->buf++) = (unsigned char) ch;
    parsed->buflen -= 1;
  }
}

static void jot_parsed_append_text(pr_jot_parsed_t *parsed, const char *text,
    size_t text_len) {
  register unsigned int i;

  if (text == NULL ||
      text_len == 0) {
    return;
  }

  if (text_len > parsed->buflen) {
    text_len = parsed->buflen;
  }

  pr_trace_msg(trace_channel, 19, "appending text '%.*s' to format",
    (int) text_len, text);

  for (i = 0; i < text_len; i++) {
    *(parsed->buf++) = (unsigned char) text[i];
  }

  parsed->buflen -= text_len;
}

static void jot_parsed_append_var(pr_jot_parsed_t *parsed,
    unsigned char logfmt_id) {

  if (parsed->buflen >= 2) {
    pr_trace_msg(trace_channel, 19, "appending LogFormat ID %u (%s) to format",
      logfmt_id, pr_jot_get_logfmt_id_name(logfmt_id));
    *(parsed->buf++) = LOGFMT_META_START;
    *(parsed->buf++) = logfmt_id;
    parsed->buflen -= 2;
  }
}

static void jot_parsed_append_arg(pr_jot_parsed_t *parsed, const char *text,
    size_t text_len) {

  if (text == NULL ||
      text_len == 0) {
    return;
  }

  if (parsed->buflen >= (text_len + 3)) {
    *(parsed->buf++) = LOGFMT_META_START;
    *(parsed->buf++) = LOGFMT_META_ARG;
    parsed->buflen -= 2;

    jot_parsed_append_text(parsed, text, text_len);

    *(parsed->buf++) = LOGFMT_META_ARG_END;
    parsed->buflen -= 1;
  }
}

int pr_jot_parse_on_meta(pool *p, pr_jot_ctx_t *jot_ctx,
    unsigned char logfmt_id, const char *logfmt_data, size_t logfmt_datalen) {
  pr_jot_parsed_t *parsed;

  if (jot_ctx == NULL) {
    errno = EINVAL;
    return -1;
  }

  parsed = jot_ctx->log;
  if (parsed == NULL) {
    errno = EINVAL;
    return -1;
  }

  jot_parsed_append_var(parsed, logfmt_id);
  jot_parsed_append_arg(parsed, logfmt_data, logfmt_datalen);
  return 0;
}

int pr_jot_parse_on_unknown(pool *p, pr_jot_ctx_t *jot_ctx, const char *text,
    size_t text_len) {
  pr_jot_parsed_t *parsed;

  if (jot_ctx == NULL) {
    errno = EINVAL;
    return -1;
  }

  parsed = jot_ctx->log;
  if (parsed == NULL) {
    errno = EINVAL;
    return -1;
  }

  jot_parsed_append_text(parsed, text, text_len);
  return 0;
}

int pr_jot_parse_on_other(pool *p, pr_jot_ctx_t *jot_ctx, char ch) {
  pr_jot_parsed_t *parsed;

  if (jot_ctx == NULL) {
    errno = EINVAL;
    return -1;
  }

  parsed = jot_ctx->log;
  if (parsed == NULL) {
    errno = EINVAL;
    return -1;
  }

  jot_parsed_append_byte(parsed, ch);
  return 0;
}

int pr_jot_parse_logfmt(pool *p, const char *text, pr_jot_ctx_t *ctx,
    int (*on_meta)(pool *, pr_jot_ctx_t *, unsigned char, const char *, size_t),
    int (*on_unknown)(pool *, pr_jot_ctx_t *, const char *, size_t),
    int (*on_other)(pool *, pr_jot_ctx_t *, char), int flags) {
  int res = 0;
  const char *ptr;

  if (p == NULL ||
      text == NULL ||
      on_meta == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (on_unknown == NULL) {
    on_unknown = jot_parse_on_unknown;
  }

  if (on_other == NULL) {
    on_other = jot_parse_on_other;
  }

  pr_trace_msg(trace_channel, 19, "parsing text: %s", text);

  for (ptr = text; *ptr; ) {
    int len;
    unsigned char logfmt_id = 0;
    const char *logfmt_data = NULL;
    size_t logfmt_datalen = 0;

    pr_signals_handle();

    if (res < 0) {
      return -1;
    }

    if (*ptr != '%') {
      res = (on_other)(p, ctx, *ptr);
      ptr += 1;
      continue;
    }

    len = parse_short_id(ptr + 1, &logfmt_id);
    if (len > 0) {
      res = (on_meta)(p, ctx, logfmt_id, NULL, 0);
      ptr += (len + 1);
      continue;
    }

    len = parse_long_id(ptr + 1, &logfmt_id, &logfmt_data, &logfmt_datalen);
    if (len > 0) {
      res = (on_meta)(p, ctx, logfmt_id, logfmt_data, logfmt_datalen);
      ptr += (len + 1);
      continue;
    }

    len = parse_unknown_id(ptr + 1, &logfmt_data, &logfmt_datalen);
    if (len > 0) {
      if (flags & PR_JOT_LOGFMT_PARSE_FL_UNKNOWN_AS_CUSTOM) {
        pr_trace_msg(trace_channel, 19,
          "handling unknown variable '%.*s' as CUSTOM", (int) logfmt_datalen,
          logfmt_data);
        res = (on_meta)(p, ctx, LOGFMT_META_CUSTOM, logfmt_data,
          logfmt_datalen);

      } else {
        res = (on_unknown)(p, ctx, logfmt_data, logfmt_datalen);
      }

      ptr += (len + 1);
      continue;
    }

    res = (on_other)(p, ctx, *ptr);
    ptr += 1;
  }

  return 0;
}

static int scan_meta(pool *p, unsigned char **logfmt, pr_jot_ctx_t *ctx,
    int (*on_meta)(pool *, pr_jot_ctx_t *, unsigned char, const char *,
      size_t)) {
  int res = 0;
  unsigned char *ptr, logfmt_id;
  const char *logfmt_data = NULL;
  size_t consumed_bytes = 0;

  logfmt_id = **logfmt;
  ptr = (*logfmt) + 1;

  switch (logfmt_id) {
    case LOGFMT_META_CUSTOM:
    case LOGFMT_META_ENV_VAR:
    case LOGFMT_META_NOTE_VAR:
    case LOGFMT_META_TIME: {
      if (*(ptr + 1) == LOGFMT_META_START &&
          *(ptr + 2) == LOGFMT_META_ARG) {
        size_t logfmt_datalen = 0;

        logfmt_data = get_meta_arg(p, (ptr + 3), &logfmt_datalen);
        res = (on_meta)(p, ctx, logfmt_id, logfmt_data, logfmt_datalen);

        /* Skip past the META_START, META_ARG, META_ARG_END, and the data. */
        consumed_bytes += (3 + logfmt_datalen);
        break;
      }
    }

    default:
      res = (on_meta)(p, ctx, logfmt_id, NULL, 0);
      consumed_bytes += 1;
  }

  if (res < 0) {
    return -1;
  }

  ptr += consumed_bytes;
  *logfmt = ptr;
  return 0;
}

int pr_jot_scan_logfmt(pool *p, unsigned char *logfmt, unsigned char logfmt_id,
    pr_jot_ctx_t *ctx,
    int (*on_meta)(pool *, pr_jot_ctx_t *, unsigned char, const char *, size_t),
    int flags) {
  int res = 0;

  if (p == NULL ||
      logfmt == NULL ||
      on_meta == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (pr_jot_get_logfmt_id_name(logfmt_id) == NULL) {
    errno = EINVAL;
    return -1;
  }

  while (*logfmt) {
    pr_signals_handle();

    if (res < 0) {
      return -1;
    }

    if (*logfmt == logfmt_id) {
      res = scan_meta(p, &logfmt, ctx, on_meta);
      continue;
    }

    logfmt++;
  }

  return 0;
}

static array_header *filter_text_to_array(pool *p, char *text) {
  char delim;
  size_t text_len;

  text_len = strlen(text);

  /* What delimiter to use?  By default, we will assume CSV, and thus use
   * a comma.  For backward compatibility, we also support pipes; first one
   * seen wins.
   */
  delim = ',';
  if (memchr(text, '|', text_len) != NULL) {
    delim = '|';
  }

  return pr_str_text_to_array(p, text, delim);
}

static int filter_get_classes(pool *p, array_header *names,
    int *included_classes, int *excluded_classes, int flags) {
  register unsigned int i;
  int incl, excl, exclude = FALSE;

  incl = excl = CL_NONE;

  for (i = 0; i < names->nelts; i++) {
    const char *name;

    pr_signals_handle();

    name = ((const char **) names->elts)[i];

    if (*name == '!') {
      exclude = TRUE;
      name++;
    }

    if (strcasecmp(name, "NONE") == 0) {
      if (exclude) {
        incl = CL_ALL;
        excl = CL_NONE;

      } else {
        incl = CL_NONE;
      }

    } else if (strcasecmp(name, "ALL") == 0) {
      if (exclude) {
        incl = CL_NONE;
        excl = CL_ALL;

      } else {
        incl = CL_ALL;
      }

    } else if (strcasecmp(name, "AUTH") == 0) {
      if (exclude) {
        incl &= ~CL_AUTH;
        excl |= CL_AUTH;

      } else {
        incl |= CL_AUTH;
      }

    } else if (strcasecmp(name, "INFO") == 0) {
      if (exclude) {
        incl &= ~CL_INFO;
        excl |= CL_INFO;

      } else {
        incl |= CL_INFO;
      }

    } else if (strcasecmp(name, "DIRS") == 0) {
      if (exclude) {
        incl &= ~CL_DIRS;
        excl |= CL_DIRS;

      } else {
        incl |= CL_DIRS;
      }

    } else if (strcasecmp(name, "READ") == 0) {
      if (exclude) {
        incl &= ~CL_READ;
        excl |= CL_READ;

      } else {
        incl |= CL_READ;
      }

    } else if (strcasecmp(name, "WRITE") == 0) {
      if (exclude) {
        incl &= ~CL_WRITE;
        excl |= CL_WRITE;

      } else {
        incl |= CL_WRITE;
      }

    } else if (strcasecmp(name, "MISC") == 0) {
      if (exclude) {
        incl &= ~CL_MISC;
        excl |= CL_MISC;

      } else {
        incl |= CL_MISC;
      }

    } else if (strcasecmp(name, "SEC") == 0 ||
               strcasecmp(name, "SECURE") == 0) {
      if (exclude) {
        incl &= ~CL_SEC;
        excl |= CL_SEC;

      } else {
        incl |= CL_SEC;
      }

    } else if (strcasecmp(name, "CONNECT") == 0) {
      if (exclude) {
        incl &= ~CL_CONNECT;
        excl |= CL_CONNECT;

      } else {
        incl |= CL_CONNECT;
      }

    } else if (strcasecmp(name, "EXIT") == 0 ||
               strcasecmp(name, "DISCONNECT") == 0) {
      if (exclude) {
        incl &= ~CL_DISCONNECT;
        excl |= CL_DISCONNECT;

      } else {
        incl |= CL_DISCONNECT;
      }

    } else if (strcasecmp(name, "SSH") == 0) {
      if (exclude) {
        incl &= ~CL_SSH;
        excl |= CL_SSH;

      } else {
        incl |= CL_SSH;
      }

    } else if (strcasecmp(name, "SFTP") == 0) {
      if (exclude) {
        incl &= ~CL_SFTP;
        excl |= CL_SFTP;

      } else {
        incl |= CL_SFTP;
      }

    } else {
      pr_trace_msg(trace_channel, 2, "ignoring unknown/unsupported class '%s'",
        name);
      errno = ENOENT;
      return -1;
    }
  }

  *included_classes = incl;
  *excluded_classes = excl;
  return 0;
}

static array_header *filter_get_cmd_ids(pool *p, array_header *names,
    int *included_classes, int *excluded_classes, int rules_type, int flags) {
  register unsigned int i;
  array_header *cmd_ids;

  cmd_ids = make_array(p, names->nelts, sizeof(int));
  for (i = 0; i < names->nelts; i++) {
    const char *name;
    int cmd_id, valid = TRUE;

    pr_signals_handle();

    name = ((const char **) names->elts)[i];

    cmd_id = pr_cmd_get_id(name);
    if (cmd_id < 0) {
      valid = FALSE;

      if (rules_type == PR_JOT_FILTER_TYPE_COMMANDS_WITH_CLASSES) {
        if (strcmp(name, "ALL") == 0) {
          *included_classes = CL_ALL;
          valid = TRUE;

          if (flags & PR_JOT_FILTER_FL_ALL_INCL_ALL) {
            *included_classes |= (CL_CONNECT|CL_DISCONNECT);
          }

        } else if (strcmp(name, "CONNECT") == 0) {
          *included_classes |= CL_CONNECT;
          valid = TRUE;

        } else if (strcmp(name, "DISCONNECT") == 0) {
          *included_classes |= CL_DISCONNECT;
          valid = TRUE;
        }
      }

      if (valid == FALSE) {
        pr_trace_msg(trace_channel, 2, "ignoring unknown command '%s'", name);
      }
    }

    if (valid == TRUE) {
      *((int *) push_array(cmd_ids)) = cmd_id;
    }
  }

  return cmd_ids;
}

pr_jot_filters_t *pr_jot_filters_create(pool *p, const char *rules,
    int rules_type, int flags) {
  int included_classes, excluded_classes;
  pool *sub_pool, *tmp_pool;
  array_header *cmd_ids, *names;
  pr_jot_filters_t *filters;

  if (p == NULL ||
      rules == NULL) {
    errno = EINVAL;
    return NULL;
  }

  included_classes = excluded_classes = CL_NONE;
  cmd_ids = NULL;

  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "Jot Filters pool");

  tmp_pool = make_sub_pool(p);
  names = filter_text_to_array(tmp_pool, pstrdup(tmp_pool, rules));

  switch (rules_type) {
    case PR_JOT_FILTER_TYPE_CLASSES: {
      int res;

      res = filter_get_classes(sub_pool, names, &included_classes,
        &excluded_classes, flags);
      if (res < 0) {
        int xerrno = errno;

        destroy_pool(tmp_pool);
        destroy_pool(sub_pool);
        errno = xerrno;
        return NULL;
      }

      break;
    }

    case PR_JOT_FILTER_TYPE_COMMANDS:
    case PR_JOT_FILTER_TYPE_COMMANDS_WITH_CLASSES:
      cmd_ids = filter_get_cmd_ids(sub_pool, names, &included_classes,
        &excluded_classes, rules_type, flags);
      break;

    default:
      destroy_pool(tmp_pool);
      destroy_pool(sub_pool);
      errno = EINVAL;
      return NULL;
  }

  destroy_pool(tmp_pool);

  filters = pcalloc(sub_pool, sizeof(pr_jot_filters_t));
  filters->pool = sub_pool;
  filters->included_classes = included_classes;
  filters->excluded_classes = excluded_classes;
  filters->cmd_ids = cmd_ids;

  return filters;
}

int pr_jot_filters_destroy(pr_jot_filters_t *filters) {
  if (filters == NULL) {
    errno = EINVAL;
    return -1;
  }

  destroy_pool(filters->pool);
  return 0;
}

int pr_jot_filters_include_classes(pr_jot_filters_t *filters, int log_class) {
  if (filters == NULL) {
    errno = EINVAL;
    return -1;
  }

  return (filters->included_classes == log_class);
}

void jot_set_deleted_filesz(off_t deleted_filesz) {
  jot_deleted_filesz = deleted_filesz;
}
