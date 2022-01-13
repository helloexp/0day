/*
 * ProFTPD: mod_ban -- a module implementing ban lists using the Controls API
 * Copyright (c) 2004-2017 TJ Saunders
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
 *
 * This is mod_ban, contrib software for proftpd 1.3.x.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"
#include "mod_ctrls.h"
#include "hanson-tpl.h"
#include "json.h"

#include <sys/ipc.h>
#include <sys/shm.h>

#define MOD_BAN_VERSION			"mod_ban/0.7"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030602
# error "ProFTPD 1.3.6rc2 or later required"
#endif

#ifndef PR_USE_CTRLS
# error "Controls support required (use --enable-ctrls)"
#endif

#define BAN_PROJ_ID		76
#define BAN_TIMER_INTERVAL	60

#ifndef HAVE_FLOCK
# define LOCK_SH        1
# define LOCK_EX        2
# define LOCK_UN        8
# define LOCK_NB        4
#endif /* HAVE_FLOCK */

/* Maximum length of user name/reason/event strings.
 */
#ifndef BAN_STRING_MAXSZ
# define BAN_STRING_MAXSZ	128
#endif

#ifndef BAN_LIST_MAXSZ
# define BAN_LIST_MAXSZ		512
#endif

#ifndef BAN_EVENT_LIST_MAXSZ
# define BAN_EVENT_LIST_MAXSZ	512
#endif

/* This "headroom" is for cases where many concurrent processes are
 * incrementing the index, possibly past the MAXSZs above.  We thus allocate
 * some headroom for them, to mitigate/avoid array out-of-bounds faults.
 */
#ifndef BAN_LIST_HEADROOMSZ
# define BAN_LIST_HEADROOMSZ	10
#endif

/* From src/main.c */
extern pid_t mpid;
extern xaset_t *server_list;

module ban_module;
static ctrls_acttab_t ban_acttab[];

/* Pool for this module's use */
static pool *ban_pool = NULL;

struct ban_entry {
  unsigned int be_type;
  char be_name[BAN_STRING_MAXSZ];
  char be_reason[BAN_STRING_MAXSZ];
  char be_mesg[BAN_STRING_MAXSZ];
  time_t be_expires;
  unsigned int be_sid;
};

#define BAN_TYPE_CLASS		1
#define BAN_TYPE_HOST		2
#define BAN_TYPE_USER		3

struct ban_list {
  struct ban_entry bl_entries[BAN_LIST_MAXSZ + BAN_LIST_HEADROOMSZ];
  unsigned int bl_listlen;
  unsigned int bl_next_slot;
};

struct ban_event_entry {
  unsigned int bee_type;
  char bee_src[BAN_STRING_MAXSZ];
  unsigned int bee_count_max;
  unsigned int bee_count_curr;
  time_t bee_start;
  time_t bee_window;
  time_t bee_expires;
  char bee_mesg[BAN_STRING_MAXSZ];
  unsigned int bee_sid;
};

#define BAN_EV_TYPE_ANON_REJECT_PASSWORDS	1
#define BAN_EV_TYPE_MAX_CLIENTS_PER_CLASS	2
#define BAN_EV_TYPE_MAX_CLIENTS_PER_HOST	3
#define BAN_EV_TYPE_MAX_CLIENTS_PER_USER	4
#define BAN_EV_TYPE_MAX_HOSTS_PER_USER		5
#define BAN_EV_TYPE_MAX_LOGIN_ATTEMPTS		6
#define BAN_EV_TYPE_TIMEOUT_IDLE		7
#define BAN_EV_TYPE_TIMEOUT_NO_TRANSFER		8
#define BAN_EV_TYPE_MAX_CONN_PER_HOST		9
#define BAN_EV_TYPE_CLIENT_CONNECT_RATE		10
#define BAN_EV_TYPE_TIMEOUT_LOGIN		11
#define BAN_EV_TYPE_LOGIN_RATE			12
#define BAN_EV_TYPE_MAX_CMD_RATE		13
#define BAN_EV_TYPE_UNHANDLED_CMD		14
#define BAN_EV_TYPE_TLS_HANDSHAKE		15
#define BAN_EV_TYPE_ROOT_LOGIN			16
#define BAN_EV_TYPE_USER_DEFINED		17
#define BAN_EV_TYPE_BAD_PROTOCOL		18
#define BAN_EV_TYPE_EMPTY_PASSWORD		19

struct ban_event_list {
  struct ban_event_entry bel_entries[BAN_EVENT_LIST_MAXSZ + BAN_LIST_HEADROOMSZ];
  unsigned int bel_listlen;
  unsigned int bel_next_slot;
};

struct ban_data {
  struct ban_list bans;
  struct ban_event_list events;
};

/* Tracks whether we have already seen the client connect, so that we only
 * generate the 'client-connect-rate' event once, even in the face of multiple
 * HOST commands.
 */
static int ban_client_connected = FALSE;

static struct ban_data *ban_lists = NULL;
static int ban_engine = -1;

/* Track whether "BanEngine on" was EVER seen in the configuration; see
 * Bug#3865.
 */
static int ban_engine_overall = -1;

static int ban_logfd = -1;
static char *ban_log = NULL;
static char *ban_mesg = NULL;
static int ban_shmid = -1;
static char *ban_table = NULL;
static pr_fh_t *ban_tabfh = NULL;
static int ban_timerno = -1;

static const char *trace_channel = "ban";

/* Needed for implementing LoginRate rules; command handlers don't get an
 * arbitrary data pointer like event listeners do.
 */
static struct ban_event_entry *login_rate_tmpl = NULL;

/* For communicating with memcached servers for shared/cached ban data. */
static pr_memcache_t *mcache = NULL;

/* For communicating with Redis servers for shared/cached ban data. */
static pr_redis_t *redis = NULL;

struct ban_cache_entry {
  int version;

  /* Timestamp indicating when this entry last changed.  Ideally it will
   * be a uint64_t value, but I don't know how portable that data type is yet.
   */
  uint32_t update_ts;

  /* IP address/port of origin/source server/vhost of this cache entry. */
  char *ip_addr;
  unsigned int port;

  /* We could use a struct ban_entry here, except that it uses fixed-size
   * buffers for the strings, and for cache storage, dynamically allocated
   * strings are easier.
   *
   * So instead, we duplicate the fields from struct ban_entry here.
   */

  int be_type;
  char *be_name;
  char *be_reason;
  char *be_mesg;
  uint32_t be_expires;
  int be_sid;
};

#define BAN_CACHE_VALUE_VERSION	2

/* These are tpl format strings */
#define BAN_CACHE_TPL_KEY_FMT		"vs"
#define BAN_CACHE_TPL_VALUE_FMT		"S(iusiisssui)"

/* These are the JSON format field names */
#define BAN_CACHE_JSON_KEY_VERSION	"version"
#define BAN_CACHE_JSON_KEY_UPDATE_TS	"update_ts"
#define BAN_CACHE_JSON_KEY_IP_ADDR	"ip_addr"
#define BAN_CACHE_JSON_KEY_PORT		"port"
#define BAN_CACHE_JSON_KEY_TYPE		"ban_type"
#define BAN_CACHE_JSON_KEY_NAME		"ban_name"
#define BAN_CACHE_JSON_KEY_REASON	"ban_reason"
#define BAN_CACHE_JSON_KEY_MESSAGE	"ban_message"
#define BAN_CACHE_JSON_KEY_EXPIRES_TS	"expires_ts"
#define BAN_CACHE_JSON_KEY_SERVER_ID	"server_id"

#define BAN_CACHE_JSON_TYPE_USER_TEXT	"user ban"
#define BAN_CACHE_JSON_TYPE_HOST_TEXT	"host ban"
#define BAN_CACHE_JSON_TYPE_CLASS_TEXT	"class ban"

/* BanCacheOptions flags */
static unsigned long ban_cache_opts = 0UL;
#define BAN_CACHE_OPT_MATCH_SERVER	0x001
#define BAN_CACHE_OPT_USE_JSON		0x002

static int ban_lock_shm(int);
static int ban_sess_init(void);

static void ban_anonrejectpasswords_ev(const void *, void *);
static void ban_badprotocol_ev(const void *, void *);
static void ban_clientconnectrate_ev(const void *, void *);
static void ban_emptypassword_ev(const void *, void *);
static void ban_maxclientsperclass_ev(const void *, void *);
static void ban_maxclientsperhost_ev(const void *, void *);
static void ban_maxclientsperuser_ev(const void *, void *);
static void ban_maxcmdrate_ev(const void *, void *);
static void ban_maxconnperhost_ev(const void *, void *);
static void ban_maxhostsperuser_ev(const void *, void *);
static void ban_maxloginattempts_ev(const void *, void *);
static void ban_rootlogin_ev(const void *, void *);
static void ban_timeoutidle_ev(const void *, void *);
static void ban_timeoutlogin_ev(const void *, void *);
static void ban_timeoutnoxfer_ev(const void *, void *);
static void ban_tlshandshake_ev(const void *, void *);
static void ban_unhandledcmd_ev(const void *, void *);
static void ban_userdefined_ev(const void *, void *);

static void ban_handle_event(unsigned int, int, const char *,
  struct ban_event_entry *);

/* Functions for marshalling key/value data to/from Redis/Memchache shared
 * cache.
 */
static int ban_cache_get_tpl_key(pool *p, unsigned int type, const char *name,
    void **key, size_t *keysz) {
  int res;
  void *data = NULL;
  size_t datasz = 0;

  res = tpl_jot(TPL_MEM, &data, &datasz, BAN_CACHE_TPL_KEY_FMT, &type, &name);
  if (res < 0) {
    return -1;
  }

  *keysz = datasz;
  *key = palloc(p, datasz);
  memcpy(*key, data, datasz);
  free(data);

  return 0;
}

static int ban_cache_get_json_key(pool *p, unsigned int type, const char *name,
    void **key, size_t *keysz) {
  pr_json_object_t *json;
  char *json_text;

  json = pr_json_object_alloc(p);
  (void) pr_json_object_set_number(p, json, "ban_type_id", (double) type);
  (void) pr_json_object_set_string(p, json, "ban_name", name);

  json_text = pr_json_object_to_text(p, json, "");

  /* Include the terminating NUL in the key. */
  *keysz = strlen(json_text) + 1;
  *key = pstrndup(p, json_text, *keysz - 1);
  (void) pr_json_object_free(json);

  return 0;
}

static int ban_cache_get_key(pool *p, unsigned int type, const char *name,
    void **key, size_t *keysz) {
  int res;
  const char *key_type = "unknown";

  if (ban_cache_opts & BAN_CACHE_OPT_USE_JSON) {
    key_type = "JSON";
    res = ban_cache_get_json_key(p, type, name, key, keysz);

  } else {
    key_type = "TPL";
    res = ban_cache_get_tpl_key(p, type, name, key, keysz);
  }

  if (res < 0) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "error constructing cache %s lookup key for type %u, name %s", key_type,
      type, name);
    return -1;
  }

  return 0;
}

static int ban_cache_entry_delete(pool *p, unsigned int type,
    const char *name) {
  int res;
  void *key = NULL;
  size_t keysz = 0;

  res = ban_cache_get_key(p, type, name, &key, &keysz);
  if (res < 0) {
    return -1;
  }

  if (redis != NULL) {
    res = pr_redis_kremove(redis, &ban_module, key, keysz);

  } else {
    res = pr_memcache_kremove(mcache, &ban_module, key, keysz, 0);
  }

  return res;
}

static int ban_cache_entry_decode_tpl(pool *p, void *value, size_t valuesz,
    struct ban_cache_entry *bce) {
  int res;
  tpl_node *tn;
  char *ptr = NULL;

  tn = tpl_map(BAN_CACHE_TPL_VALUE_FMT, bce);
  if (tn == NULL) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "error allocating tpl_map for format '%s'", BAN_CACHE_TPL_VALUE_FMT);
    return -1;
  }

  res = tpl_load(tn, TPL_MEM, value, valuesz);
  if (res < 0) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION, "%s",
      "error loading TPL ban cache data");
    tpl_free(tn);
    return -1;
  }

  res = tpl_unpack(tn, 0);
  if (res < 0) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION, "%s",
      "error unpacking TPL ban cache data");
    tpl_free(tn);
    return -1;
  }

  tpl_free(tn);

  /* Now that we've called tpl_free(), we need to free up the memory
   * associated with the strings in the struct ban_cache_entry, so we
   * allocate them out of the given pool.
   */

  ptr = bce->ip_addr;
  if (ptr != NULL) {
    bce->ip_addr = pstrdup(p, ptr);
    free(ptr);
  }

  ptr = bce->be_name;
  if (ptr != NULL) {
    bce->be_name = pstrdup(p, ptr);
    free(ptr);
  }

  ptr = bce->be_reason;
  if (ptr != NULL) {
    bce->be_reason = pstrdup(p, ptr);
    free(ptr);
  }

  ptr = bce->be_mesg;
  if (ptr != NULL) {
    bce->be_mesg = pstrdup(p, ptr);
    free(ptr);
  }

  return 0;
}

static int entry_get_json_number(pool *p, pr_json_object_t *json,
    const char *key, double *val, const char *text) {
  if (pr_json_object_get_number(p, json, key, val) < 0) {
    if (errno == EEXIST) {
      pr_trace_msg(trace_channel, 3,
       "ignoring non-number '%s' JSON field in '%s'", key, text);

    } else {
      (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
        "missing required '%s' JSON field in '%s'", key, text);
    }

    (void) pr_json_object_free(json);
    errno = EINVAL;
    return -1;
  }

  return 0;
}

static int entry_get_json_string(pool *p, pr_json_object_t *json,
    const char *key, char **val, const char *text) {
  if (pr_json_object_get_string(p, json, key, val) < 0) {
    if (errno == EEXIST) {
      pr_trace_msg(trace_channel, 3,
       "ignoring non-string '%s' JSON field in '%s'", key, text);

    } else {
      (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
        "missing required '%s' JSON field in '%s'", key, text);
    }

    (void) pr_json_object_free(json);
    errno = EINVAL;
    return -1;
  }

  return 0;
}

static int ban_cache_entry_decode_json(pool *p, void *value, size_t valuesz,
    struct ban_cache_entry *bce) {
  int res;
  pr_json_object_t *json;
  const char *key;
  char *entry, *text;
  double number;

  entry = value;
  if (pr_json_text_validate(p, entry) == FALSE) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "unable to decode invalid JSON cache entry: '%s'", entry);
    errno = EINVAL;
    return -1;
  }

  json = pr_json_object_from_text(p, entry);

  key = BAN_CACHE_JSON_KEY_VERSION;
  res = entry_get_json_number(p, json, key, &number, entry);
  if (res < 0) {
    return -1;
  }
  bce->version = (int) number;

  if (bce->version != BAN_CACHE_VALUE_VERSION) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "unsupported/unknown version value '%d' in cached JSON value, rejecting",
      bce->version);
    (void) pr_json_object_free(json);
    errno = EINVAL;
    return -1;
  }

  key = BAN_CACHE_JSON_KEY_UPDATE_TS;
  res = entry_get_json_number(p, json, key, &number, entry);
  if (res < 0) {
    return -1;
  }
  bce->update_ts = (uint32_t) number;

  key = BAN_CACHE_JSON_KEY_IP_ADDR;
  res = entry_get_json_string(p, json, key, &text, entry);
  if (res < 0) {
    return -1;
  }
  bce->ip_addr = text;

  key = BAN_CACHE_JSON_KEY_PORT;
  res = entry_get_json_number(p, json, key, &number, entry);
  if (res < 0) {
    return -1;
  }
  bce->port = (unsigned int) number;

  if (bce->port == 0 ||
      bce->port > 65535) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "invalid port number %u in cached JSON value, rejecting", bce->port);
    (void) pr_json_object_free(json);
    errno = EINVAL;
    return -1;
  }

  key = BAN_CACHE_JSON_KEY_TYPE;
  res = entry_get_json_string(p, json, key, &text, entry);
  if (res < 0) {
    return -1;
  }

  if (strcmp(text, BAN_CACHE_JSON_TYPE_USER_TEXT) == 0) {
    bce->be_type = BAN_TYPE_USER;

  } else if (strcmp(text, BAN_CACHE_JSON_TYPE_HOST_TEXT) == 0) {
    bce->be_type = BAN_TYPE_HOST;

  } else if (strcmp(text, BAN_CACHE_JSON_TYPE_CLASS_TEXT) == 0) {
    bce->be_type = BAN_TYPE_CLASS;

  } else {
    pr_trace_msg(trace_channel, 3,
      "ignoring unknown/unsupported '%s' JSON field value: %s", key, text);
    (void) pr_json_object_free(json);
    errno = EINVAL;
    return -1;
  }

  key = BAN_CACHE_JSON_KEY_NAME;
  res = entry_get_json_string(p, json, key, &text, entry);
  if (res < 0) {
    return -1;
  }
  bce->be_name = text;

  key = BAN_CACHE_JSON_KEY_REASON;
  res = entry_get_json_string(p, json, key, &text, entry);
  if (res < 0) {
    return -1;
  }
  bce->be_reason = text;

  key = BAN_CACHE_JSON_KEY_MESSAGE;
  res = entry_get_json_string(p, json, key, &text, entry);
  if (res < 0) {
    return -1;
  }
  bce->be_mesg = text;

  key = BAN_CACHE_JSON_KEY_EXPIRES_TS;
  res = entry_get_json_number(p, json, key, &number, entry);
  if (res < 0) {
    return -1;
  }
  bce->be_expires = (uint32_t) number;

  key = BAN_CACHE_JSON_KEY_SERVER_ID;
  res = entry_get_json_number(p, json, key, &number, entry);
  if (res < 0) {
    return -1;
  }
  bce->be_sid = (int) number;

  (void) pr_json_object_free(json);

  if (bce->be_sid <= 0) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "invalid server ID %d in cached JSON value, rejecting", bce->be_sid);
    errno = EINVAL;
    return -1;
  }

  return 0;
}

static int ban_cache_entry_get(pool *p, unsigned int type, const char *name,
    struct ban_cache_entry *bce) {
  int res;
  void *key = NULL, *value = NULL;
  size_t keysz = 0, valuesz = 0;
  const char *driver = NULL;

  res = ban_cache_get_key(p, type, name, &key, &keysz);
  if (res < 0) {
    return -1;
  }

  if (redis != NULL) {
    driver = "Redis";

    value = pr_redis_kget(p, redis, &ban_module, (const char *) key, keysz,
      &valuesz);

  } else {
    uint32_t flags = 0;

    driver = "memcache";
    value = pr_memcache_kget(mcache, &ban_module, (const char *) key, keysz,
      &valuesz, &flags);
  }

  if (value == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 8,
      "no matching %s entry found for name %s, type %u", driver, name, type);

    errno = xerrno;
    return -1;
  }

  /* Decode the cached ban entry. */
  if (ban_cache_opts & BAN_CACHE_OPT_USE_JSON) {
    res = ban_cache_entry_decode_json(p, value, valuesz, bce);

  } else {
    res = ban_cache_entry_decode_tpl(p, value, valuesz, bce);
  }

  if (res == 0) {
    pr_trace_msg(trace_channel, 9, "retrieved ban entry in cache using %s",
      ban_cache_opts & BAN_CACHE_OPT_USE_JSON ? "JSON" : "TPL");
  }

  return res;
}

static int ban_cache_entry_encode_tpl(pool *p, void **value, size_t *valuesz,
    struct ban_cache_entry *bce) {
  int res;
  tpl_node *tn;
  void *ptr = NULL;

  tn = tpl_map(BAN_CACHE_TPL_VALUE_FMT, bce);
  if (tn == NULL) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "error allocating tpl_map for format '%s'", BAN_CACHE_TPL_VALUE_FMT);
    return -1;
  }

  res = tpl_pack(tn, 0);
  if (res < 0) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION, "%s",
      "error encoding TPL ban cache data");
    return -1;
  }

  res = tpl_dump(tn, TPL_MEM, &ptr, valuesz);
  if (res < 0) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION, "%s",
      "error dumping TPL ban cache data");
    return -1;
  }

  /* Duplicate the value using the given pool, so that we can free up the
   * memory allocated by tpl_dump().
   */
  *value = palloc(p, *valuesz);
  memcpy(*value, ptr, *valuesz);

  tpl_free(tn);
  free(ptr);

  return 0;
}

static int ban_cache_entry_encode_json(pool *p, void **value, size_t *valuesz,
    struct ban_cache_entry *bce) {
  pr_json_object_t *json;
  const char *ban_type = "unknown";
  char *json_text;

  json = pr_json_object_alloc(p);

  (void) pr_json_object_set_number(p, json, BAN_CACHE_JSON_KEY_VERSION,
    (double) bce->version);
  (void) pr_json_object_set_number(p, json, BAN_CACHE_JSON_KEY_UPDATE_TS,
    (double) bce->update_ts);
  (void) pr_json_object_set_string(p, json, BAN_CACHE_JSON_KEY_IP_ADDR,
    bce->ip_addr);
  (void) pr_json_object_set_number(p, json, BAN_CACHE_JSON_KEY_PORT,
    (double) bce->port);

  /* Textify the ban type, for better inoperability. */
  switch (bce->be_type) {
    case BAN_TYPE_USER:
      ban_type = BAN_CACHE_JSON_TYPE_USER_TEXT;
      break;

    case BAN_TYPE_HOST:
      ban_type = BAN_CACHE_JSON_TYPE_HOST_TEXT;
      break;

    case BAN_TYPE_CLASS:
      ban_type = BAN_CACHE_JSON_TYPE_CLASS_TEXT;
      break;
  }

  (void) pr_json_object_set_string(p, json, BAN_CACHE_JSON_KEY_TYPE,
    ban_type);
  (void) pr_json_object_set_string(p, json, BAN_CACHE_JSON_KEY_NAME,
    bce->be_name);
  (void) pr_json_object_set_string(p, json, BAN_CACHE_JSON_KEY_REASON,
    bce->be_reason);
  (void) pr_json_object_set_string(p, json, BAN_CACHE_JSON_KEY_MESSAGE,
    bce->be_mesg);
  (void) pr_json_object_set_number(p, json, BAN_CACHE_JSON_KEY_EXPIRES_TS,
    (double) bce->be_expires);
  (void) pr_json_object_set_number(p, json, BAN_CACHE_JSON_KEY_SERVER_ID,
    (double) bce->be_sid);

  json_text = pr_json_object_to_text(p, json, "");

  /* Include the terminating NUL in the value. */
  *valuesz = strlen(json_text) + 1;
  *value = pstrndup(p, json_text, *valuesz - 1);

  (void) pr_json_object_free(json);
  return 0;
}

static int ban_cache_entry_set(pool *p, struct ban_cache_entry *bce) {
  int res;
  void *key = NULL, *value = NULL;
  size_t keysz = 0, valuesz = 0;
  const char *driver = NULL;

  /* Encode the ban entry. */
  if (ban_cache_opts & BAN_CACHE_OPT_USE_JSON) {
    res = ban_cache_entry_encode_json(p, &value, &valuesz, bce);

  } else {
    res = ban_cache_entry_encode_tpl(p, &value, &valuesz, bce);
  }

  if (res < 0) {
    return -1;
  }

  res = ban_cache_get_key(p, bce->be_type, bce->be_name, &key, &keysz);
  if (res < 0) {
    return -1;
  }

  if (redis != NULL) {
    driver = "Redis";

    res = pr_redis_kset(redis, &ban_module, (const char *) key, keysz,
      value, valuesz, bce->be_expires);

  } else {
    uint32_t flags = 0;

    driver = "memcache";
    res = pr_memcache_kset(mcache, &ban_module, (const char *) key, keysz,
      value, valuesz, bce->be_expires, flags);
  }

  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "unable to add %s entry for name %s, type %u: %s", driver, bce->be_name,
      bce->be_type, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 9, "stored ban entry in cache using %s",
    ban_cache_opts & BAN_CACHE_OPT_USE_JSON ? "JSON" : "TPL");
  return 0;
}

/* Functions for marshalling key/value data to/from local cache,
 * i.e. SysV shm.
 */
static struct ban_data *ban_get_shm(pr_fh_t *tabfh) {
  int shmid;
  int shm_existed = FALSE;
  struct ban_data *data = NULL;
  key_t key;

  /* If we already have a shmid, no need to do anything. */
  if (ban_shmid >= 0) {
    errno = EEXIST;
    return NULL;
  }

  /* Get a key for this path. */
  key = ftok(tabfh->fh_path, BAN_PROJ_ID);
  if (key == (key_t) -1) {
    int xerrno = errno;

    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "unable to get key for '%s': %s", tabfh->fh_path, strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  /* Try first using IPC_CREAT|IPC_EXCL, to check if there is an existing
   * shm for this key.  If there is, try again, using a flag of zero.
   */

  shmid = shmget(key, sizeof(struct ban_data), IPC_CREAT|IPC_EXCL|0666);
  if (shmid < 0) {

    if (errno == EEXIST) {
      shm_existed = TRUE;

      shmid = shmget(key, 0, 0);

    } else {
      return NULL;
    }
  }

  /* Attach to the shm. */
  data = (struct ban_data *) shmat(shmid, NULL, 0);
  if (data == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "unable to attach to shm: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  if (!shm_existed) {

    /* Make sure the memory is initialized. */
    if (ban_lock_shm(LOCK_EX) < 0) {
      (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
        "error write-locking shm: %s", strerror(errno));
    }

    memset(data, '\0', sizeof(struct ban_data));

    if (ban_lock_shm(LOCK_UN) < 0) {
      (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
        "error unlocking shm: %s", strerror(errno));
    }
  }

  ban_shmid = shmid;
  (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
    "obtained shmid %d for BanTable '%s'", ban_shmid, tabfh->fh_path);

  return data;
}

static int ban_lock_shm(int flags) {
  static unsigned int ban_nlocks = 0;

#ifndef HAVE_FLOCK
  int lock_flag;
  struct flock lock;
#endif /* HAVE_FLOCK */

  if (ban_nlocks &&
      ((flags & LOCK_SH) || (flags & LOCK_EX))) {
    ban_nlocks++;
    return 0;
  }

  if (ban_nlocks == 0 &&
      (flags & LOCK_UN)) {
    return 0;
  }

#ifdef HAVE_FLOCK
  while (flock(ban_tabfh->fh_fd, flags) < 0) {
    if (errno == EINTR) {
      pr_signals_handle();
      continue;
    }

    return -1;
  }

  if ((flags & LOCK_SH) ||
      (flags & LOCK_EX)) {
    ban_nlocks++;

  } else if (flags & LOCK_UN) {
    ban_nlocks--;
  }

  return 0;
#else
  lock_flag = F_SETLKW;

  lock.l_whence = 0;
  lock.l_start = lock.l_len = 0;

  if (flags & LOCK_SH) {
    lock.l_type = F_RDLCK;

  } else if (flags & LOCK_EX) {
    lock.l_type = F_WRLCK;

  } else if (flags & LOCK_UN) {
    lock.l_type= F_UNLCK;

  } else {
    errno = EINVAL;
    return -1;
  }

  if (flags & LOCK_NB)
    lock_flag = F_SETLK;

  while (fcntl(ban_tabfh->fh_fd, lock_flag, &lock) < 0) {
    if (errno == EINTR) {
      pr_signals_handle();
      continue;
    }

    return -1;
  }

  if ((flags & LOCK_SH) ||
      (flags & LOCK_EX)) {
    ban_nlocks++;

  } else if (flags & LOCK_UN) {
    ban_nlocks--;
  }

  return 0;
#endif /* HAVE_FLOCK */
}

static int ban_disconnect_class(const char *class) {
  pr_scoreboard_entry_t *score = NULL;
  unsigned char kicked_class = FALSE;
  unsigned int nclients = 0;
  pid_t session_pid;

  if (!class) {
    errno = EINVAL;
    return -1;
  }

  /* Iterate through the scoreboard, and send a SIGTERM to each
   * PID whose class matches the given class.  Make sure that we exclude
   * our own PID from that list; our own termination is handled elsewhere.
   */

  if (pr_rewind_scoreboard() < 0 &&
      errno != EINVAL) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "error rewinding scoreboard: %s", strerror(errno));
  }

  session_pid = getpid();

  while ((score = pr_scoreboard_entry_read()) != NULL) {
    pr_signals_handle();

    if (score->sce_pid != session_pid &&
        strcmp(class, score->sce_class) == 0) {
      int res = 0;

      PRIVS_ROOT
      res = pr_scoreboard_entry_kill(score, SIGTERM);
      PRIVS_RELINQUISH

      if (res == 0) {
        kicked_class = TRUE;
        nclients++;

      } else {
        (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
          "error disconnecting class '%s' [process %lu]: %s", class,
            (unsigned long) score->sce_pid, strerror(errno));
      }
    }
  }

  if (pr_restore_scoreboard() < 0 &&
      errno != EINVAL) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "error restoring scoreboard: %s", strerror(errno));
  }

  if (kicked_class) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "disconnected %u %s from class '%s'", nclients,
      nclients != 1 ? "clients" : "client", class);
    return 0;
  }

  errno = ENOENT;
  return -1;
}

static int ban_disconnect_host(const char *host) {
  pr_scoreboard_entry_t *score = NULL;
  unsigned char kicked_host = FALSE;
  unsigned int nclients = 0;
  pid_t session_pid;

  if (!host) {
    errno = EINVAL;
    return -1;
  }

  /* Iterate through the scoreboard, and send a SIGTERM to each
   * PID whose address matches the given host.  Make sure that we exclude
   * our own PID from that list; our own termination is handled elsewhere.
   */

  if (pr_rewind_scoreboard() < 0 &&
      errno != EINVAL) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "error rewinding scoreboard: %s", strerror(errno));
  }

  session_pid = getpid();

  while ((score = pr_scoreboard_entry_read()) != NULL) {
    pr_signals_handle();

    if (score->sce_pid != session_pid &&
        strcmp(host, score->sce_client_addr) == 0) {
      int res = 0;

      PRIVS_ROOT
      res = pr_scoreboard_entry_kill(score, SIGTERM);
      PRIVS_RELINQUISH

      if (res == 0) {
        kicked_host = TRUE;
        nclients++;

      } else {
        (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
          "error disconnecting host '%s' [process %lu]: %s", host,
            (unsigned long) score->sce_pid, strerror(errno));
      }
    }
  }

  if (pr_restore_scoreboard() < 0 &&
      errno != EINVAL) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "error restoring scoreboard: %s", strerror(errno));
  }

  if (kicked_host) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "disconnected %u %s from host '%s'", nclients,
      nclients != 1 ? "clients" : "client", host);
    return 0;
  }

  errno = ENOENT;
  return -1;
}

static int ban_disconnect_user(const char *user) {
  pr_scoreboard_entry_t *score = NULL;
  unsigned char kicked_user = FALSE;
  unsigned int nclients = 0;
  pid_t session_pid;

  if (!user) {
    errno = EINVAL;
    return -1;
  }

  /* Iterate through the scoreboard, and send a SIGTERM to each
   * PID whose name matches the given user name.  Make sure that we exclude
   * our own PID from that list; our own termination is handled elsewhere.
   */

  if (pr_rewind_scoreboard() < 0 &&
      errno != EINVAL) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "error rewinding scoreboard: %s", strerror(errno));
  }

  session_pid = getpid();

  while ((score = pr_scoreboard_entry_read()) != NULL) {
    pr_signals_handle();

    if (score->sce_pid != session_pid &&
        strcmp(user, score->sce_user) == 0) {
      int res = 0;

      PRIVS_ROOT
      res = pr_scoreboard_entry_kill(score, SIGTERM);
      PRIVS_RELINQUISH

      if (res == 0) {
        kicked_user = TRUE;
        nclients++;

      } else {
        (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
          "error disconnecting user '%s' [process %lu]: %s", user,
            (unsigned long) score->sce_pid, strerror(errno));
      }
    }
  }

  if (pr_restore_scoreboard() < 0 &&
      errno != EINVAL) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "error restoring scoreboard: %s", strerror(errno));
  }

  if (kicked_user) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "disconnected %u %s from user '%s'", nclients,
      nclients != 1 ? "clients" : "client", user);
    return 0;
  }

  errno = ENOENT;
  return -1;
}

/* Parse a string formatted as "hh:mm:ss" into a time_t. */
static time_t ban_parse_timestr(const char *str) {
  unsigned int hours, mins, secs;

  if (sscanf(str, "%2u:%2u:%2u", &hours, &mins, &secs) != 3) {
    errno = EINVAL;
    return -1;
  }

  return (hours * 60 * 60) + (mins * 60) + secs;
}

/* Send a configured rule-specific message (from the BanOnEvent configuration)
 * or, if there isn't a rule-specific message, the BanMessage to the client.
 */
static void ban_send_mesg(pool *p, const char *user, const char *rule_mesg) {
  const char *mesg = NULL;

  if (rule_mesg) {
    mesg = pstrdup(p, rule_mesg);

  } else if (ban_mesg) {
    mesg = pstrdup(p, ban_mesg);
  }

  if (mesg != NULL) {
    mesg = pstrdup(p, mesg);

    if (strstr(mesg, "%c")) {
      const char *class;

      class = session.conn_class ? session.conn_class->cls_name : "(none)";
      mesg = sreplace(p, mesg, "%c", class, NULL);
    }

    if (strstr(mesg, "%a")) {
      const char *remote_ip;

      remote_ip = pr_netaddr_get_ipstr(session.c->remote_addr);
      mesg = sreplace(p, mesg, "%a", remote_ip, NULL);
    }

    if (strstr(mesg, "%u")) {
      mesg = sreplace(p, mesg, "%u", user, NULL);
    }

    pr_response_send_async(R_530, "%s", mesg);
  }

  return;
}

/* List manipulation routines
 */

/* Add an entry to the ban list. */
static int ban_list_add(pool *p, unsigned int type, unsigned int sid,
    const char *name, const char *reason, time_t lasts, const char *rule_mesg) {
  unsigned int old_slot;
  int res = 0, seen = FALSE;

  if (!ban_lists) {
    errno = EPERM;
    return -1;
  }

  old_slot = ban_lists->bans.bl_next_slot;

  /* Find an open slot in the list for this new entry. */
  while (TRUE) {
    struct ban_entry *be;

    pr_signals_handle();

    if (ban_lists->bans.bl_next_slot >= BAN_LIST_MAXSZ)
      ban_lists->bans.bl_next_slot = 0;

    be = &(ban_lists->bans.bl_entries[ban_lists->bans.bl_next_slot]);
    if (be->be_type == 0) {
      be->be_type = type;
      be->be_sid = sid;

      sstrncpy(be->be_name, name, sizeof(be->be_name));
      sstrncpy(be->be_reason, reason, sizeof(be->be_reason));
      be->be_expires = lasts ? time(NULL) + lasts : 0;

      memset(be->be_mesg, '\0', sizeof(be->be_mesg));
      if (rule_mesg) {
        sstrncpy(be->be_mesg, rule_mesg, sizeof(be->be_mesg));
      }

      switch (type) {
        case BAN_TYPE_USER:
          pr_event_generate("mod_ban.ban-user",
            ban_lists->bans.bl_entries[ban_lists->bans.bl_next_slot].be_name);
          ban_disconnect_user(name);
          break;

        case BAN_TYPE_HOST:
          pr_event_generate("mod_ban.ban-host",
            ban_lists->bans.bl_entries[ban_lists->bans.bl_next_slot].be_name);
          ban_disconnect_host(name);
          break;

        case BAN_TYPE_CLASS:
          pr_event_generate("mod_ban.ban-class",
            ban_lists->bans.bl_entries[ban_lists->bans.bl_next_slot].be_name);
          ban_disconnect_class(name);
          break;
      }

      ban_lists->bans.bl_next_slot++;
      ban_lists->bans.bl_listlen++;
      break;
      
    } else {
      pr_signals_handle(); 

      if (ban_lists->bans.bl_next_slot == old_slot &&
          seen == TRUE) {

        /* This happens when we've scanned the entire list, found no
         * empty slot, and have returned back to the slot at which we
         * started.
         */
        (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
          "maximum number of ban slots (%u) already in use", BAN_LIST_MAXSZ);

        errno = ENOSPC;
        res = -1;
        break;
      }

      ban_lists->bans.bl_next_slot++;
      seen = TRUE;
    }
  }

  /* Add the entry to cache, if configured AND if the caller provided a pool
   * for such uses.
   */
  if ((mcache != NULL || redis != NULL) &&
      p != NULL) {
    struct ban_cache_entry bce;
    const pr_netaddr_t *na;

    memset(&bce, 0, sizeof(bce));

    bce.version = BAN_CACHE_VALUE_VERSION;
    bce.update_ts = (uint32_t) time(NULL);

    na = pr_netaddr_get_sess_local_addr();
    bce.ip_addr = (char *) pr_netaddr_get_ipstr(na);
    bce.port = pr_netaddr_get_port(na);

    bce.be_type = type;
    bce.be_name = (char *) name;
    bce.be_reason = (char *) reason;
    bce.be_mesg = (char *) (rule_mesg ? rule_mesg : "");
    bce.be_expires = (uint32_t) (lasts ? time(NULL) + lasts : 0);
    bce.be_sid = main_server->sid;

    if (ban_cache_entry_set(p, &bce) == 0) {
      (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
        "cache entry added for name %s, type %u", name, type);
    }
  }

  return res;
}

/* Check if a ban of the specified type, for the given server ID and name,
 * is present in the ban list.
 *
 * If the caller provides a `mesg' pointer, then if a ban exists, that
 * pointer will point to any custom client-displayable message.
 */
static int ban_list_exists(pool *p, unsigned int type, unsigned int sid,
    const char *name, char **mesg) {

  if (!ban_lists) {
    errno = EPERM;
    return -1;
  }

  if (ban_lists->bans.bl_listlen) {
    register unsigned int i = 0;

    for (i = 0; i < BAN_LIST_MAXSZ; i++) {
      pr_signals_handle();

      if (ban_lists->bans.bl_entries[i].be_type == type &&
          (ban_lists->bans.bl_entries[i].be_sid == 0 ||
           ban_lists->bans.bl_entries[i].be_sid == sid) &&
          strcmp(ban_lists->bans.bl_entries[i].be_name, name) == 0) {

        if (mesg != NULL &&
            strlen(ban_lists->bans.bl_entries[i].be_mesg) > 0) {
          *mesg = ban_lists->bans.bl_entries[i].be_mesg;
        }

        return 0;
      }
    }
  }

  /* Check with cache, if configured AND if the caller provided a pool for
   * such uses.
   */
  if ((mcache != NULL || redis != NULL) &&
      p != NULL) {
    int res;
    struct ban_cache_entry bce;

    memset(&bce, 0, sizeof(bce));

    res = ban_cache_entry_get(p, type, name, &bce);
    if (res == 0) {
      int use_entry = TRUE;
      time_t now;

      /* Check the expiration timestamp; if too old, delete it from the
       * cache.
       */
      time(&now);
      if (bce.be_expires != 0 &&
          bce.be_expires <= (uint32_t) now) {
        pr_trace_msg(trace_channel, 3,
          "purging expired entry from cache: %lu <= now %lu",
          (unsigned long) bce.be_expires, (unsigned long) now);

        (void) ban_cache_entry_delete(p, type, name);
        errno = ENOENT;
        return -1;
      }

      /* XXX Check the entry version; if it doesn't match ours, then we
       * need to Do Something Intelligent(tm).
       */

      (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
        "found cache entry for name %s, type %u: version %u, update_ts %s, "
        "ip_addr %s, port %u, be_type %u, be_name %s, be_reason %s, "
        "be_mesg %s, be_expires %s, be_sid %u", name, type, bce.version,
        pr_strtime(bce.update_ts), bce.ip_addr, bce.port, bce.be_type,
        bce.be_name, bce.be_reason, bce.be_mesg ? bce.be_mesg : "<nil>",
        pr_strtime(bce.be_expires), bce.be_sid);

      /* Use BanCacheOptions to check the various struct fields for usability.
       */

      if (ban_cache_opts & BAN_CACHE_OPT_MATCH_SERVER) {
        const pr_netaddr_t *na;

        /* Make sure that the IP address/port in the cache entry matches
         * our address/port.
         */
        na = pr_netaddr_get_sess_local_addr();
        if (use_entry == TRUE &&
            bce.ip_addr != NULL &&
            strcmp(bce.ip_addr, pr_netaddr_get_ipstr(na)) != 0) {
          use_entry = FALSE;

          (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
            "BanCacheOption MatchServer: cache entry IP address '%s' "
            "does not match vhost IP address '%s', ignoring entry",
            bce.ip_addr, pr_netaddr_get_ipstr(na));
        }

        if (use_entry == TRUE &&
            bce.port != pr_netaddr_get_port(na)) {
          use_entry = FALSE;

          (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
            "BanCacheOption MatchServer: cache entry port %u "
            "does not match vhost port %d, ignoring entry",
            bce.port, pr_netaddr_get_port(na));
        }
      }

      if (use_entry == TRUE) {
        if (mesg != NULL &&
            bce.be_mesg != NULL &&
            strlen(bce.be_mesg) > 0) {
          *mesg = bce.be_mesg;
        }

        return 0;
      }
    }
  }

  errno = ENOENT;
  return -1;
}

static int ban_list_remove(unsigned int type, unsigned int sid,
    const char *name) {

  if (!ban_lists) {
    errno = EPERM;
    return -1;
  }

  if (ban_lists->bans.bl_listlen) {
    register unsigned int i = 0;

    for (i = 0; i < BAN_LIST_MAXSZ; i++) {
      pr_signals_handle();

      if (ban_lists->bans.bl_entries[i].be_type == type &&
          (sid == 0 || ban_lists->bans.bl_entries[i].be_sid == sid) &&
          (name ? strcmp(ban_lists->bans.bl_entries[i].be_name, name) == 0 :
           TRUE)) {

        switch (type) {
          case BAN_TYPE_USER:
            pr_event_generate("mod_ban.permit-user",
              ban_lists->bans.bl_entries[i].be_name);
            break;

          case BAN_TYPE_HOST:
            pr_event_generate("mod_ban.permit-host",
              ban_lists->bans.bl_entries[i].be_name);
            break;

          case BAN_TYPE_CLASS:
            pr_event_generate("mod_ban.permit-class",
              ban_lists->bans.bl_entries[i].be_name);
            break;
        }

        memset(&(ban_lists->bans.bl_entries[i]), '\0',
          sizeof(struct ban_entry)); 

        ban_lists->bans.bl_listlen--;

        /* If name is null, it means the caller wants to remove all
         * names for the given type/SID combination.
         *
         * If name is not null, but sid is zero, then it means the caller
         * wants to remove the given name/type combination for all SIDs.
         *
         * Thus we only want to return here if sid is non-zero and name
         * is not null.
         */
        if (sid != 0 &&
            name != NULL) {
          return 0;
        }
      }
    }
  }

  if (sid == 0 ||
      name == NULL) {
    return 0;
  }

  errno = ENOENT;
  return -1;
}

/* Remove all expired bans from the list. */
static void ban_list_expire(void) {
  time_t now = time(NULL);
  register unsigned int i = 0;

  if (!ban_lists || ban_lists->bans.bl_listlen == 0)
    return;

  for (i = 0; i < BAN_LIST_MAXSZ; i++) {
    pr_signals_handle();

    if (ban_lists->bans.bl_entries[i].be_type &&
        ban_lists->bans.bl_entries[i].be_expires &&
        !(ban_lists->bans.bl_entries[i].be_expires > now)) {
      char *ban_desc, *ban_name;
      int ban_type;
      pool *tmp_pool;

      ban_type = ban_lists->bans.bl_entries[i].be_type;
      ban_name = ban_lists->bans.bl_entries[i].be_name;

      (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
        "ban for %s '%s' has expired (%lu seconds ago)",
        ban_type == BAN_TYPE_USER ? "user" : 
          ban_type == BAN_TYPE_HOST ? "host" : "class", ban_name,
        (unsigned long) now - ban_lists->bans.bl_entries[i].be_expires);

      tmp_pool = make_sub_pool(ban_pool ? ban_pool : session.pool);
      ban_desc = pstrcat(tmp_pool,
        ban_type == BAN_TYPE_USER ? "USER:" :
          ban_type == BAN_TYPE_HOST ? "HOST:" : "CLASS:", ban_name, NULL);
      pr_event_generate("mod_ban.ban.expired", ban_desc);
      destroy_pool(tmp_pool);

      ban_list_remove(ban_type, 0, ban_name);
    }
  }
}

static const char *ban_event_entry_typestr(unsigned int type) {
  switch (type) {
    case BAN_EV_TYPE_ANON_REJECT_PASSWORDS:
      return "AnonRejectPasswords";

    case BAN_EV_TYPE_EMPTY_PASSWORD:
      return "EmptyPassword";

    case BAN_EV_TYPE_BAD_PROTOCOL:
      return "BadProtocol";

    case BAN_EV_TYPE_MAX_CLIENTS_PER_CLASS:
      return "MaxClientsPerClass";

    case BAN_EV_TYPE_MAX_CLIENTS_PER_HOST:
      return "MaxClientsPerHost";

    case BAN_EV_TYPE_MAX_CLIENTS_PER_USER:
      return "MaxClientsPerUser";

    case BAN_EV_TYPE_MAX_HOSTS_PER_USER:
      return "MaxHostsPerUser";

    case BAN_EV_TYPE_MAX_LOGIN_ATTEMPTS:
      return "MaxLoginAttempts";

    case BAN_EV_TYPE_TIMEOUT_IDLE:
      return "TimeoutIdle";

    case BAN_EV_TYPE_TIMEOUT_LOGIN:
      return "TimeoutLogin";

    case BAN_EV_TYPE_TIMEOUT_NO_TRANSFER:
      return "TimeoutNoTransfer";

    case BAN_EV_TYPE_MAX_CONN_PER_HOST:
      return "MaxConnectionsPerHost";

    case BAN_EV_TYPE_CLIENT_CONNECT_RATE:
      return "ClientConnectRate";

    case BAN_EV_TYPE_LOGIN_RATE:
      return "LoginRate";

    case BAN_EV_TYPE_MAX_CMD_RATE:
      return "MaxCommandRate";

    case BAN_EV_TYPE_UNHANDLED_CMD:
      return "UnhandledCommand";

    case BAN_EV_TYPE_TLS_HANDSHAKE:
      return "TLSHandshake";

    case BAN_EV_TYPE_ROOT_LOGIN:
      return "RootLogin";

    case BAN_EV_TYPE_USER_DEFINED:
      return "(user-defined)";
  }

  return NULL;
}

/* Add an entry to the ban event list. */
static int ban_event_list_add(unsigned int type, unsigned int sid,
    const char *src, unsigned int max, time_t window, time_t expires) {
  unsigned int old_slot;
  int seen = FALSE;

  if (!ban_lists) {
    errno = EPERM;
    return -1;
  }

  old_slot = ban_lists->events.bel_next_slot;

  /* Find an open slot in the list for this new entry. */
  while (TRUE) {
    struct ban_event_entry *bee;

    pr_signals_handle();

    if (ban_lists->events.bel_next_slot >= BAN_EVENT_LIST_MAXSZ)
      ban_lists->events.bel_next_slot = 0;

    bee = &(ban_lists->events.bel_entries[ban_lists->events.bel_next_slot]);

    if (bee->bee_type == 0) {
      bee->bee_type = type;
      bee->bee_sid = sid;

      sstrncpy(bee->bee_src, src, sizeof(bee->bee_src));
      bee->bee_count_max = max;
      time(&bee->bee_start);
      bee->bee_window = window;
      bee->bee_expires = expires;

      ban_lists->events.bel_next_slot++;
      ban_lists->events.bel_listlen++;
      break;

    } else {
      pr_signals_handle();

      if (ban_lists->events.bel_next_slot == old_slot &&
          seen == TRUE) {

        /* This happens when we've scanned the entire list, found no
         * empty slot, and have returned back to the slot at which we
         * started.
         */
        (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
          "maximum number of ban event slots (%u) already in use",
          BAN_EVENT_LIST_MAXSZ);

        errno = ENOSPC;
        return -1;
      }

      ban_lists->events.bel_next_slot++;
      seen = TRUE;
    }
  }

  return 0;
}

static struct ban_event_entry *ban_event_list_get(unsigned int type,
    unsigned int sid, const char *src) {

  if (!ban_lists)
    return NULL;

  if (ban_lists->events.bel_listlen) {
    register unsigned int i = 0;

    for (i = 0; i < BAN_EVENT_LIST_MAXSZ; i++) {
      pr_signals_handle();

      if (ban_lists->events.bel_entries[i].bee_type == type &&
          ban_lists->events.bel_entries[i].bee_sid == sid &&
          strcmp(ban_lists->events.bel_entries[i].bee_src, src) == 0) {
        return &(ban_lists->events.bel_entries[i]);
      }
    }
  }

  return NULL;
}

static int ban_event_list_remove(unsigned int type, unsigned int sid,
    const char *src) {

  if (!ban_lists) {
    errno = EPERM;
    return -1;
  }

  if (ban_lists->events.bel_listlen) {
    register unsigned int i = 0;

    for (i = 0; i < BAN_EVENT_LIST_MAXSZ; i++) {
      pr_signals_handle();

      if (ban_lists->events.bel_entries[i].bee_type == type &&
          ban_lists->events.bel_entries[i].bee_sid == sid &&
          (src ? strcmp(ban_lists->events.bel_entries[i].bee_src, src) == 0 :
           TRUE)) {
        memset(&(ban_lists->events.bel_entries[i]), 0,
          sizeof(struct ban_event_entry));

        ban_lists->events.bel_listlen--;

        if (src)
          return 0;
      }
    }
  }

  if (!src)
    return 0;

  errno = ENOENT;
  return -1;
}

static void ban_event_list_expire(void) {
  register unsigned int i = 0;
  time_t now = time(NULL);

  if (!ban_lists ||
      ban_lists->events.bel_listlen == 0)
    return;

  for (i = 0; i < BAN_EVENT_LIST_MAXSZ; i++) {
    time_t bee_end = ban_lists->events.bel_entries[i].bee_start +
      ban_lists->events.bel_entries[i].bee_window;

    pr_signals_handle();

    if (ban_lists->events.bel_entries[i].bee_type &&
        ban_lists->events.bel_entries[i].bee_expires &&
        !(bee_end > now)) {
      (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
        "ban event %s entry '%s' has expired (%lu seconds ago)",
        ban_event_entry_typestr(ban_lists->events.bel_entries[i].bee_type),
        ban_lists->events.bel_entries[i].bee_src,
        (unsigned long) now - bee_end);

      ban_event_list_remove(ban_lists->events.bel_entries[i].bee_type,
        ban_lists->events.bel_entries[i].bee_sid,
        ban_lists->events.bel_entries[i].bee_src);
    }
  }
}

/* Controls handlers
 */

static server_rec *ban_get_server_by_id(unsigned int sid) {
  server_rec *s = NULL;

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    if (s->sid == sid) {
      break;
    }
  }

  if (s == NULL) {
    errno = ENOENT;
  }

  return s;
}

static int ban_get_sid_by_addr(const pr_netaddr_t *server_addr,
    unsigned int server_port) {
  server_rec *s = NULL;

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    pr_signals_handle();

    if (s->ServerPort == 0) {
      continue;
    }

    if (pr_netaddr_cmp(s->addr, server_addr) == 0 &&
        s->ServerPort == server_port) {
      return s->sid;
    }
  }

  errno = ENOENT;
  return -1;
}

static int ban_handle_info(pr_ctrls_t *ctrl, int reqargc, char **reqargv) {
  register unsigned int i;
  int optc, verbose = FALSE, show_events = FALSE;
  const char *reqopts = "ev";

  /* Check for options. */
  pr_getopt_reset();

  while ((optc = getopt(reqargc, reqargv, reqopts)) != -1) {
    switch (optc) {
      case 'e':
        show_events = TRUE;
        break;

      case 'v':
        verbose = TRUE;
        break;

      case '?':
        pr_ctrls_add_response(ctrl, "unsupported parameter: '%s'",
          reqargv[0]);
        return -1;
    }
  }

  if (ban_lock_shm(LOCK_SH) < 0) {
    pr_ctrls_add_response(ctrl, "error locking shm: %s", strerror(errno));
    return -1;
  }

  (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION, "showing ban lists");

  if (ban_lists->bans.bl_listlen) {
    int have_user = FALSE, have_host = FALSE, have_class = FALSE;

    for (i = 0; i < BAN_LIST_MAXSZ; i++) {
      if (ban_lists->bans.bl_entries[i].be_type == BAN_TYPE_USER) {

        if (!have_user) {
          pr_ctrls_add_response(ctrl, "Banned Users:");
          have_user = TRUE;
        }

        pr_ctrls_add_response(ctrl, "  %s",
          ban_lists->bans.bl_entries[i].be_name);

        if (verbose) {
          server_rec *s;

          pr_ctrls_add_response(ctrl, "    Reason: %s",
            ban_lists->bans.bl_entries[i].be_reason);

          if (ban_lists->bans.bl_entries[i].be_expires) {
            time_t now = time(NULL);
            time_t then = ban_lists->bans.bl_entries[i].be_expires;

            pr_ctrls_add_response(ctrl, "    Expires: %s (in %lu seconds)",
              pr_strtime(then), (unsigned long) (then - now));

          } else {
            pr_ctrls_add_response(ctrl, "    Expires: never");
          }

          s = ban_get_server_by_id(ban_lists->bans.bl_entries[i].be_sid);
          if (s) {
            pr_ctrls_add_response(ctrl, "    <VirtualHost>: %s (%s#%u)",
              s->ServerName, pr_netaddr_get_ipstr(s->addr),
              s->ServerPort);
          }
        }
      }
    }

    for (i = 0; i < BAN_LIST_MAXSZ; i++) {
      if (ban_lists->bans.bl_entries[i].be_type == BAN_TYPE_HOST) {

        if (!have_host) {
          if (have_user)
            pr_ctrls_add_response(ctrl, "%s", "");

          pr_ctrls_add_response(ctrl, "Banned Hosts:");
          have_host = TRUE;
        }

        pr_ctrls_add_response(ctrl, "  %s",
          ban_lists->bans.bl_entries[i].be_name);

        if (verbose) {
          server_rec *s;

          pr_ctrls_add_response(ctrl, "    Reason: %s",
            ban_lists->bans.bl_entries[i].be_reason);

          if (ban_lists->bans.bl_entries[i].be_expires) {
            time_t now = time(NULL);
            time_t then = ban_lists->bans.bl_entries[i].be_expires;

            pr_ctrls_add_response(ctrl, "    Expires: %s (in %lu seconds)",
              pr_strtime(then), (unsigned long) (then - now));

          } else {
            pr_ctrls_add_response(ctrl, "    Expires: never");
          }

          s = ban_get_server_by_id(ban_lists->bans.bl_entries[i].be_sid);
          if (s) {
            pr_ctrls_add_response(ctrl, "    <VirtualHost>: %s (%s#%u)",
              s->ServerName, pr_netaddr_get_ipstr(s->addr),
              s->ServerPort);
          }
        }
      }
    }

    for (i = 0; i < BAN_LIST_MAXSZ; i++) {
      if (ban_lists->bans.bl_entries[i].be_type == BAN_TYPE_CLASS) {

        if (!have_class) {
          if (have_host)
            pr_ctrls_add_response(ctrl, "%s", "");

          pr_ctrls_add_response(ctrl, "Banned Classes:");
          have_class = TRUE;
        }

        pr_ctrls_add_response(ctrl, "  %s",
          ban_lists->bans.bl_entries[i].be_name);

        if (verbose) {
          server_rec *s;

          pr_ctrls_add_response(ctrl, "    Reason: %s",
            ban_lists->bans.bl_entries[i].be_reason);

          if (ban_lists->bans.bl_entries[i].be_expires) {
            time_t now = time(NULL);
            time_t then = ban_lists->bans.bl_entries[i].be_expires;

            pr_ctrls_add_response(ctrl, "    Expires: %s (in %lu seconds)",
              pr_strtime(then), (unsigned long) (then - now));

          } else {
            pr_ctrls_add_response(ctrl, "    Expires: never");
          }

          s = ban_get_server_by_id(ban_lists->bans.bl_entries[i].be_sid);
          if (s) {
            pr_ctrls_add_response(ctrl, "    <VirtualHost>: %s (%s#%u)",
              s->ServerName, pr_netaddr_get_ipstr(s->addr),
              s->ServerPort);
          }
        }
      }
    }

  } else {
    pr_ctrls_add_response(ctrl, "No bans");
  }

/* XXX need a way to clear the event list, too, I think...? */

  if (show_events) {
    pr_ctrls_add_response(ctrl, "%s", "");

    if (ban_lists->events.bel_listlen) {
      int have_banner = FALSE;
      time_t now = time(NULL);

      for (i = 0; i < BAN_EVENT_LIST_MAXSZ; i++) {
        server_rec *s;
        int type = ban_lists->events.bel_entries[i].bee_type;

        switch (type) {
          case BAN_EV_TYPE_ANON_REJECT_PASSWORDS:
          case BAN_EV_TYPE_EMPTY_PASSWORD:
          case BAN_EV_TYPE_BAD_PROTOCOL:
          case BAN_EV_TYPE_MAX_CLIENTS_PER_CLASS:
          case BAN_EV_TYPE_MAX_CLIENTS_PER_HOST:
          case BAN_EV_TYPE_MAX_CLIENTS_PER_USER:
          case BAN_EV_TYPE_MAX_HOSTS_PER_USER:
          case BAN_EV_TYPE_MAX_LOGIN_ATTEMPTS:
          case BAN_EV_TYPE_TIMEOUT_IDLE:
          case BAN_EV_TYPE_TIMEOUT_LOGIN:
          case BAN_EV_TYPE_TIMEOUT_NO_TRANSFER:
          case BAN_EV_TYPE_MAX_CONN_PER_HOST:
          case BAN_EV_TYPE_CLIENT_CONNECT_RATE:
          case BAN_EV_TYPE_LOGIN_RATE:
          case BAN_EV_TYPE_MAX_CMD_RATE:
          case BAN_EV_TYPE_UNHANDLED_CMD:
          case BAN_EV_TYPE_TLS_HANDSHAKE:
          case BAN_EV_TYPE_ROOT_LOGIN:
          case BAN_EV_TYPE_USER_DEFINED:
            if (!have_banner) {
              pr_ctrls_add_response(ctrl, "Ban Events:");
              have_banner = TRUE;
            }

            pr_ctrls_add_response(ctrl, "  Event: %s",
              ban_event_entry_typestr(type));
            pr_ctrls_add_response(ctrl, "  Source: %s",
              ban_lists->events.bel_entries[i].bee_src);
            pr_ctrls_add_response(ctrl, "    Occurrences: %u/%u",
              ban_lists->events.bel_entries[i].bee_count_curr,
              ban_lists->events.bel_entries[i].bee_count_max);
            pr_ctrls_add_response(ctrl, "    Entry Expires: %lu seconds",
              (unsigned long) ban_lists->events.bel_entries[i].bee_start +
                ban_lists->events.bel_entries[i].bee_window - now);

            s = ban_get_server_by_id(ban_lists->events.bel_entries[i].bee_sid);
            if (s) {
              pr_ctrls_add_response(ctrl, "    <VirtualHost>: %s (%s#%u)",
                s->ServerName, pr_netaddr_get_ipstr(s->addr),
                s->ServerPort);
            }

            break;
        }
      }

    } else {
      pr_ctrls_add_response(ctrl, "No ban events");
    }
  }

  ban_lock_shm(LOCK_UN);

  return 0;
}

static int ban_handle_ban(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register int i = 0;
  unsigned int sid = 0;

  /* Check the ban ACL */
  if (!pr_ctrls_check_acl(ctrl, ban_acttab, "ban")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */
  if (reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "missing parameters");
    return -1;
  }

  if (ban_engine_overall != TRUE) {
    pr_ctrls_add_response(ctrl, MOD_BAN_VERSION " not enabled");
    return -1;
  }

  pr_getopt_reset();

  /* Only check for/process command-line options if this is not the 'info'
   * request; that request has its own command-line options.
   */
  if (strcmp(reqargv[0], "info") != 0) {
    int optc;
    char *server_str = NULL;
    const char *reqopts = "s:";

    while ((optc = getopt(reqargc, reqargv, reqopts)) != -1) {
      switch (optc) {
        case 's':
          if (!optarg) {
            pr_ctrls_add_response(ctrl, "-s requires server address");
            return -1;
          }
          server_str = pstrdup(ctrl->ctrls_tmp_pool, optarg);
          break;

        case '?':
          pr_ctrls_add_response(ctrl, "unsupported option: '%c'",
            (char) optopt);
          return -1;
      }
    }

    if (server_str != NULL) {
      char *ptr;
      const pr_netaddr_t *server_addr = NULL;
      unsigned int server_port = 21;
      int res;

      ptr = strchr(server_str, '#');
      if (ptr != NULL) {
        server_port = atoi(ptr + 1);
        *ptr = '\0';
      }

      server_addr = pr_netaddr_get_addr(ctrl->ctrls_tmp_pool, server_str, NULL);
      if (server_addr == NULL) {
        pr_ctrls_add_response(ctrl, "no such server '%s#%u'", server_str,
          server_port);
        return -1;
      }

      res = ban_get_sid_by_addr(server_addr, server_port);
      if (res < 0) {
        pr_ctrls_add_response(ctrl, "no such server '%s#%u'", server_str,
          server_port);
        return -1;
      }

      sid = res;
    }
  }

  /* Make sure the lists are up-to-date. */
  ban_list_expire();
  ban_event_list_expire();

  /* Handle 'ban user' requests */
  if (strcmp(reqargv[0], "user") == 0) {

    if (reqargc < 2) {
      pr_ctrls_add_response(ctrl, "missing parameters");
      return -1;
    }

    if (ban_lock_shm(LOCK_EX) < 0) {
      pr_ctrls_add_response(ctrl, "error locking shm: %s", strerror(errno));
      return -1;
    }

    /* Add each given user name to the list */
    for (i = optind; i < reqargc; i++) {
     
      /* Check for duplicates. */
      if (ban_list_exists(NULL, BAN_TYPE_USER, sid, reqargv[i], NULL) < 0) {

        if (ban_lists->bans.bl_listlen < BAN_LIST_MAXSZ) {
          const char *reason = pstrcat(ctrl->ctrls_tmp_pool, "requested by '",
            ctrl->ctrls_cl->cl_user, "' on ", pr_strtime(time(NULL)), NULL);

          ban_list_add(NULL, BAN_TYPE_USER, sid, reqargv[i],
            reason, 0, NULL);
          (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
            "added '%s' to banned users list", reqargv[i]);
          pr_ctrls_add_response(ctrl, "user %s banned", reqargv[i]);

        } else {
          pr_ctrls_add_response(ctrl, "maximum list size reached, unable to "
            "ban user '%s'", reqargv[i]);
        }

      } else {
        pr_ctrls_add_response(ctrl, "user %s already banned", reqargv[i]);
      }
    }

    ban_lock_shm(LOCK_UN);

  /* Handle 'ban host' requests */
  } else if (strcmp(reqargv[0], "host") == 0) {

    if (reqargc < 2) {
      pr_ctrls_add_response(ctrl, "missing parameters");
      return -1;
    }

    if (ban_lock_shm(LOCK_EX) < 0) {
      pr_ctrls_add_response(ctrl, "error locking shm: %s", strerror(errno));
      return -1;
    }

    /* Add each site to the list */
    for (i = optind; i < reqargc; i++) {
      const pr_netaddr_t *site;

      /* XXX handle multiple addresses */
      site = pr_netaddr_get_addr(ctrl->ctrls_tmp_pool, reqargv[i], NULL);
      if (site == NULL) {
        pr_ctrls_add_response(ctrl, "ban: unknown host '%s'", reqargv[i]);
        continue;
      }
 
      /* Check for duplicates. */
      if (ban_list_exists(NULL, BAN_TYPE_HOST, sid, pr_netaddr_get_ipstr(site),
          NULL) < 0) {

        if (ban_lists->bans.bl_listlen < BAN_LIST_MAXSZ) {
          ban_list_add(NULL, BAN_TYPE_HOST, sid, pr_netaddr_get_ipstr(site),
            pstrcat(ctrl->ctrls_tmp_pool, "requested by '",
              ctrl->ctrls_cl->cl_user, "' on ",
              pr_strtime(time(NULL)), NULL), 0, NULL);
          (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
            "added '%s' to banned hosts list", reqargv[i]);
          pr_ctrls_add_response(ctrl, "host %s banned", reqargv[i]);

        } else {
          pr_ctrls_add_response(ctrl, "maximum list size reached, unable to "
            "ban host '%s'", reqargv[i]);
        }

      } else {
        pr_ctrls_add_response(ctrl, "host %s already banned", reqargv[i]);
      }
    }

    ban_lock_shm(LOCK_UN);

  /* Handle 'ban class' requests */
  } else if (strcmp(reqargv[0], "class") == 0) {

    if (reqargc < 2) {
      pr_ctrls_add_response(ctrl, "missing parameters");
      return -1;
    }

    if (ban_lock_shm(LOCK_EX) < 0) {
      pr_ctrls_add_response(ctrl, "error locking shm: %s", strerror(errno));
      return -1;
    }

    /* Add each given class name to the list */
    for (i = optind; i < reqargc; i++) {

      /* Check for duplicates. */
      if (ban_list_exists(NULL, BAN_TYPE_CLASS, sid, reqargv[i], NULL) < 0) {

        if (ban_lists->bans.bl_listlen < BAN_LIST_MAXSZ) {
          const char *reason = pstrcat(ctrl->ctrls_tmp_pool, "requested by '",
            ctrl->ctrls_cl->cl_user, "' on ", pr_strtime(time(NULL)), NULL);

          ban_list_add(NULL, BAN_TYPE_CLASS, sid, reqargv[i], reason, 0, NULL);
          (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
            "added '%s' to banned classes list", reqargv[i]);
          pr_ctrls_add_response(ctrl, "class %s banned", reqargv[i]);

        } else {
          pr_ctrls_add_response(ctrl, "maximum list size reached, unable to "
            "ban class '%s'", reqargv[i]);
        }

      } else {
        pr_ctrls_add_response(ctrl, "class %s already banned", reqargv[i]);
      }
    }

    ban_lock_shm(LOCK_UN);

  /* Handle 'ban info' requests */
  } else if (strcmp(reqargv[0], "info") == 0) {
    return ban_handle_info(ctrl, reqargc, reqargv);

  } else {
    pr_ctrls_add_response(ctrl, "unknown ban action requested: '%s'",
      reqargv[0]);
    return -1;
  }

  return 0;
}

static int ban_handle_permit(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register int i = 0;
  int optc;
  unsigned int sid = 0;
  const char *reqopts = "s:";
  char *server_str = NULL;

  /* Check the permit ACL */
  if (!pr_ctrls_check_acl(ctrl, ban_acttab, "permit")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  /* Sanity check */
  if (reqargc < 2 ||
      reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "missing parameters");
    return -1;
  }

  if (ban_engine_overall != TRUE) {
    pr_ctrls_add_response(ctrl, MOD_BAN_VERSION " not enabled");
    return -1;
  }

  /* Check for options. */
  pr_getopt_reset();

  while ((optc = getopt(reqargc, reqargv, reqopts)) != -1) {
    switch (optc) {
      case 's':
        if (!optarg) {
          pr_ctrls_add_response(ctrl, "-s requires server address");
          return -1;
        }
        server_str = pstrdup(ctrl->ctrls_tmp_pool, optarg);
        break;

      case '?':
        pr_ctrls_add_response(ctrl, "unsupported parameter: '%c'",
          (char) optopt);
        return -1;
    }
  }

  if (server_str != NULL) {
    char *ptr;
    const pr_netaddr_t *server_addr = NULL;
    unsigned int server_port = 21;
    int res;

    ptr = strchr(server_str, '#');
    if (ptr != NULL) {
      server_port = atoi(ptr + 1);
      *ptr = '\0';
    }

    server_addr = pr_netaddr_get_addr(ctrl->ctrls_tmp_pool, server_str, NULL);
    if (server_addr == NULL) {
      pr_ctrls_add_response(ctrl, "no such server '%s#%u'", server_str,
        server_port);
      return -1;
    }

    res = ban_get_sid_by_addr(server_addr, server_port);
    if (res < 0) {
      pr_ctrls_add_response(ctrl, "no such server '%s#%u'", server_str,
        server_port);
      return -1;
    }

    sid = res;
  }

  /* Make sure the lists are up-to-date. */
  ban_list_expire();

  /* Handle 'permit user' requests */
  if (strcmp(reqargv[0], "user") == 0) {

    if (ban_lists->bans.bl_listlen == 0) {
      pr_ctrls_add_response(ctrl, "permit request unnecessary");
      pr_ctrls_add_response(ctrl, "no users are banned");
      return 0;
    }

    if (ban_lock_shm(LOCK_EX) < 0) {
      pr_ctrls_add_response(ctrl, "error locking shm: %s", strerror(errno));
      return -1;
    }

    if (strcmp(reqargv[optind], "*") == 0) {

      /* Clear the list by permitting all users. */
      ban_list_remove(BAN_TYPE_USER, sid, NULL);
      pr_ctrls_add_response(ctrl, "all users permitted");

    } else {
      server_rec *s = NULL;

      if (sid != 0) {
        s = ban_get_server_by_id(sid);
      }

      /* Permit each given user name. */
      for (i = optind; i < reqargc; i++) {
        if (ban_list_remove(BAN_TYPE_USER, sid, reqargv[i]) == 0) {
          (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
            "removed '%s' from ban list", reqargv[i]);
          pr_ctrls_add_response(ctrl, "user '%s' permitted", reqargv[i]);

        } else {
          if (s == NULL) {
            pr_ctrls_add_response(ctrl, "user '%s' not banned", reqargv[i]);

          } else {
            pr_ctrls_add_response(ctrl, "user '%s' not banned on %s#%u",
              reqargv[i], pr_netaddr_get_ipstr(s->addr), s->ServerPort);
          }
        }
      }
    }

    ban_lock_shm(LOCK_UN);

  /* Handle 'permit host' requests */
  } else if (strcmp(reqargv[0], "host") == 0) {

    if (ban_lists->bans.bl_listlen == 0) {
      pr_ctrls_add_response(ctrl, "permit request unnecessary");
      pr_ctrls_add_response(ctrl, "no hosts are banned");
      return 0;
    }

    if (ban_lock_shm(LOCK_EX) < 0) {
      pr_ctrls_add_response(ctrl, "error locking shm: %s", strerror(errno));
      return -1;
    }

    if (strcmp(reqargv[optind], "*") == 0) {

      /* Clear the list by permitting all hosts. */
      ban_list_remove(BAN_TYPE_HOST, sid, NULL);
      pr_ctrls_add_response(ctrl, "all hosts permitted");

    } else {
      server_rec *s = NULL;

      if (sid != 0) {
        s = ban_get_server_by_id(sid);
      }

      for (i = optind; i < reqargc; i++) {
        const pr_netaddr_t *site;

        /* XXX handle multiple addresses */
        site = pr_netaddr_get_addr(ctrl->ctrls_tmp_pool, reqargv[i], NULL);
        if (site != NULL) {
          if (ban_list_remove(BAN_TYPE_HOST, sid,
                pr_netaddr_get_ipstr(site)) == 0) {
            (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
              "removed '%s' from banned hosts list", reqargv[i]);
            pr_ctrls_add_response(ctrl, "host '%s' permitted", reqargv[i]);

          } else {
            if (s == NULL) {
              pr_ctrls_add_response(ctrl, "host '%s' not banned", reqargv[i]);

            } else {
              pr_ctrls_add_response(ctrl, "host '%s' not banned on %s#%u",
                reqargv[i], pr_netaddr_get_ipstr(s->addr), s->ServerPort);
            }
          }

        } else {
          pr_ctrls_add_response(ctrl, "unable to resolve '%s' to an IP address",
            reqargv[i]);
        }
      }
    }

    ban_lock_shm(LOCK_UN);

  /* Handle 'permit class' requests */
  } else if (strcmp(reqargv[0], "class") == 0) {

    if (ban_lists->bans.bl_listlen == 0) {
      pr_ctrls_add_response(ctrl, "permit request unnecessary");
      pr_ctrls_add_response(ctrl, "no classes are banned");
      return 0;
    }

    if (ban_lock_shm(LOCK_EX) < 0) {
      pr_ctrls_add_response(ctrl, "error locking shm: %s", strerror(errno));
      return -1;
    }

    if (strcmp(reqargv[optind], "*") == 0) {

      /* Clear the list by permitting all classes. */
      ban_list_remove(BAN_TYPE_CLASS, 0, NULL);
      pr_ctrls_add_response(ctrl, "all classes permitted");

    } else {
      server_rec *s = NULL;

      if (sid != 0) {
        s = ban_get_server_by_id(sid);
      }

      /* Permit each given class name. */
      for (i = optind; i < reqargc; i++) {
        if (ban_list_remove(BAN_TYPE_CLASS, sid, reqargv[i]) == 0) {
          (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
            "removed '%s' from banned classes list", reqargv[i]);
          pr_ctrls_add_response(ctrl, "class '%s' permitted", reqargv[i]);

        } else {
          if (s == NULL) {
            pr_ctrls_add_response(ctrl, "class '%s' not banned", reqargv[i]);

          } else {
            pr_ctrls_add_response(ctrl, "class '%s' not banned on %s#%u",
              reqargv[i], pr_netaddr_get_ipstr(s->addr), s->ServerPort);
          }
        }
      }
    }

    ban_lock_shm(LOCK_UN);
 
  } else {
    pr_ctrls_add_response(ctrl, "unknown ban action requested: '%s'",
      reqargv[0]);
    return -1;
  }

  return 0;
}

/* Command handlers
 */

MODRET ban_pre_pass(cmd_rec *cmd) {
  const char *user;
  char *rule_mesg = NULL;

  if (ban_engine != TRUE) {
    return PR_DECLINED(cmd);
  }

  user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
  if (user == NULL) {
    return PR_DECLINED(cmd);
  }

  /* Make sure the list is up-to-date. */
  ban_list_expire();

  /* Check banned user list */
  if (ban_list_exists(cmd->tmp_pool, BAN_TYPE_USER, main_server->sid, user,
      &rule_mesg) == 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_BAN_VERSION
      ": Login denied: user '%s' banned", user);
    ban_send_mesg(cmd->tmp_pool, user, rule_mesg);
    return PR_ERROR_MSG(cmd, R_530, _("Login incorrect."));
  }

  return PR_DECLINED(cmd);
}

MODRET ban_post_pass(cmd_rec *cmd) {
  if (ban_engine != TRUE) {
    return PR_DECLINED(cmd);
  }

  if (login_rate_tmpl == NULL) {
    return PR_DECLINED(cmd);
  }

  ban_handle_event(BAN_EV_TYPE_LOGIN_RATE, BAN_TYPE_USER, session.user,
    login_rate_tmpl);

  return PR_DECLINED(cmd);
}

/* Configuration handlers
 */

/* usage: BanCache driver */
MODRET set_bancache(cmd_rec *cmd) {
  if (cmd->argc-1 < 1 ||
      cmd->argc-1 > 3) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

#if defined(PR_USE_MEMCACHE)
  if (strcmp(cmd->argv[1], "memcache") == 0) {
    config_rec *c;

    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pstrdup(c->pool, cmd->argv[1]);

    return PR_HANDLED(cmd);
  }
#endif /* PR_USE_MEMCACHE */

#if defined(PR_USE_REDIS)
  if (strcmp(cmd->argv[1], "redis") == 0) {
    config_rec *c;

    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pstrdup(c->pool, cmd->argv[1]);

    return PR_HANDLED(cmd);
  }
#endif /* PR_USE_REDIS */

  CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unsupported BanCache driver '",
    cmd->argv[1], "'", NULL));
}

/* usage: BanCacheOptions opt1 ... optN */
MODRET set_bancacheoptions(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  unsigned long opts = 0UL;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "MatchServer") == 0) {
      opts |= BAN_CACHE_OPT_MATCH_SERVER;

    } else if (strcmp(cmd->argv[i], "UseJSON") == 0) {
      opts |= BAN_CACHE_OPT_USE_JSON;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown BanCacheOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: BanControlsACLs actions|all allow|deny user|group list */
MODRET set_banctrlsacls(cmd_rec *cmd) {
  char *bad_action = NULL, **actions = NULL;

  CHECK_ARGS(cmd, 4);
  CHECK_CONF(cmd, CONF_ROOT);

  /* We can cheat here, and use the ctrls_parse_acl() routine to
   * separate the given string...
   */
  actions = ctrls_parse_acl(cmd->tmp_pool, cmd->argv[1]);

  /* Check the second parameter to make sure it is "allow" or "deny" */
  if (strcmp(cmd->argv[2], "allow") != 0 &&
      strcmp(cmd->argv[2], "deny") != 0)
    CONF_ERROR(cmd, "second parameter must be 'allow' or 'deny'");

  /* Check the third parameter to make sure it is "user" or "group" */
  if (strcmp(cmd->argv[3], "user") != 0 &&
      strcmp(cmd->argv[3], "group") != 0)
    CONF_ERROR(cmd, "third parameter must be 'user' or 'group'");

  bad_action = pr_ctrls_set_module_acls(ban_acttab, ban_pool, actions,
    cmd->argv[2], cmd->argv[3], cmd->argv[4]);
  if (bad_action != NULL)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown action: '",
      bad_action, "'", NULL));

  return PR_HANDLED(cmd);
}

/* usage: BanEngine on|off */
MODRET set_banengine(cmd_rec *cmd) {
  int engine = -1, ctx_type;
  config_rec *c;

  CHECK_ARGS(cmd, 1);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (engine == TRUE) {
    /* If "BanEngine on" is configured anywhere, then set this flag. */
    ban_engine_overall = engine;
  }

  ctx_type = (cmd->config && cmd->config->config_type != CONF_PARAM ?
     cmd->config->config_type : cmd->server->config_type ?
     cmd->server->config_type : CONF_ROOT);

  if (ctx_type == CONF_ROOT) {
    /* If ban_engine has not been initialized yet, and this is the
     * "server config" section, we can do it here.  And even if the
     * previously initialized value is 0 ("BanEngine off"), if the
     * current value is 1 ("BanEngine on"), use it.  This can happen,
     * for example, when there are multiple BanEngine directives in the
     * config, in <IfClass> sections, for whitelisting.
     */

    if (ban_engine == -1) {
      ban_engine = engine;
    }

    if (engine == TRUE) {
      ban_engine = engine;
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: BanLog path|"none" */
MODRET set_banlog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (strcasecmp(cmd->argv[1], "none") != 0 &&
      pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  ban_log = pstrdup(ban_pool, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: BanMessage mesg */
MODRET set_banmessage(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  ban_mesg = pstrdup(ban_pool, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: BanOnEvent event freq duration [mesg] */
MODRET set_banonevent(cmd_rec *cmd) {
  struct ban_event_entry *bee;
  int n;
  char *tmp;

  CHECK_ARGS(cmd, 3);
  CHECK_CONF(cmd, CONF_ROOT);

  bee = pcalloc(ban_pool, sizeof(struct ban_event_entry));

  tmp = strchr(cmd->argv[2], '/');
  if (tmp == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "badly formatted freq parameter: '",
      cmd->argv[2], "'", NULL));
  }

  /* The frequency string is formatted as "N/hh:mm:ss", where N is the count
   * to be reached within the given time interval.
   */

  *tmp = '\0';

  n = atoi(cmd->argv[2]);
  if (n < 1) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "freq occurrences must be greater than 0", NULL));
  }
  bee->bee_count_max = n;

  bee->bee_window = ban_parse_timestr(tmp+1);
  if (bee->bee_window == (time_t) -1) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "badly formatted freq parameter: '", cmd->argv[2], "'", NULL));
  }

  if (bee->bee_window == 0) {
    CONF_ERROR(cmd, "freq parameter cannot be '00:00:00'");
  }

  /* The duration is the next parameter. */
  bee->bee_expires = ban_parse_timestr(cmd->argv[3]);
  if (bee->bee_expires == (time_t) -1) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "badly formatted duration parameter: '", cmd->argv[2], "'", NULL));
  }

  if (bee->bee_expires == 0) {
    CONF_ERROR(cmd, "duration parameter cannot be '00:00:00'");
  }

  /* If present, the next parameter is a custom ban message. */
  if (cmd->argc == 5) {
    sstrncpy(bee->bee_mesg, cmd->argv[4], sizeof(bee->bee_mesg));
  }

  if (strcasecmp(cmd->argv[1], "AnonRejectPasswords") == 0) {
    bee->bee_type = BAN_EV_TYPE_ANON_REJECT_PASSWORDS;
    pr_event_register(&ban_module, "mod_auth.anon-reject-passwords",
      ban_anonrejectpasswords_ev, bee);

  } else if (strcasecmp(cmd->argv[1], "BadProtocol") == 0) {
    bee->bee_type = BAN_EV_TYPE_BAD_PROTOCOL;
    pr_event_register(&ban_module, "core.bad-protocol", ban_badprotocol_ev,
      bee);

  } else if (strcasecmp(cmd->argv[1], "ClientConnectRate") == 0) {
    bee->bee_type = BAN_EV_TYPE_CLIENT_CONNECT_RATE;
    pr_event_register(&ban_module, "mod_ban.client-connect-rate",
      ban_clientconnectrate_ev, bee);

  } else if (strcasecmp(cmd->argv[1], "EmptyPassword") == 0) {
    bee->bee_type = BAN_EV_TYPE_EMPTY_PASSWORD;
    pr_event_register(&ban_module, "mod_auth.empty-password",
      ban_emptypassword_ev, bee);

  } else if (strcasecmp(cmd->argv[1], "LoginRate") == 0) {
    /* We don't register an event listener here.  Instead we rely on
     * the POST_CMD handler for the PASS command; it's the "event"
     * which we would handle for this rule.
     */
    bee->bee_type = BAN_EV_TYPE_LOGIN_RATE;
    login_rate_tmpl = bee;

  } else if (strcasecmp(cmd->argv[1], "MaxClientsPerClass") == 0) {
    bee->bee_type = BAN_EV_TYPE_MAX_CLIENTS_PER_CLASS;
    pr_event_register(&ban_module, "mod_auth.max-clients-per-class",
      ban_maxclientsperclass_ev, bee);

  } else if (strcasecmp(cmd->argv[1], "MaxClientsPerHost") == 0) {
    bee->bee_type = BAN_EV_TYPE_MAX_CLIENTS_PER_HOST;
    pr_event_register(&ban_module, "mod_auth.max-clients-per-host",
      ban_maxclientsperhost_ev, bee);

  } else if (strcasecmp(cmd->argv[1], "MaxClientsPerUser") == 0) {
    bee->bee_type = BAN_EV_TYPE_MAX_CLIENTS_PER_USER;
    pr_event_register(&ban_module, "mod_auth.max-clients-per-user",
      ban_maxclientsperuser_ev, bee);

  } else if (strcasecmp(cmd->argv[1], "MaxCommandRate") == 0) {
    bee->bee_type = BAN_EV_TYPE_MAX_CMD_RATE;
    pr_event_register(&ban_module, "core.max-command-rate",
      ban_maxcmdrate_ev, bee);
  
  } else if (strcasecmp(cmd->argv[1], "MaxConnectionsPerHost") == 0) {
    bee->bee_type = BAN_EV_TYPE_MAX_CONN_PER_HOST;
    pr_event_register(&ban_module, "mod_auth.max-connections-per-host",
      ban_maxconnperhost_ev, bee);
  
  } else if (strcasecmp(cmd->argv[1], "MaxHostsPerUser") == 0) {
    bee->bee_type = BAN_EV_TYPE_MAX_HOSTS_PER_USER;
    pr_event_register(&ban_module, "mod_auth.max-hosts-per-user",
      ban_maxhostsperuser_ev, bee);

  } else if (strcasecmp(cmd->argv[1], "MaxLoginAttempts") == 0) {
    bee->bee_type = BAN_EV_TYPE_MAX_LOGIN_ATTEMPTS;
    pr_event_register(&ban_module, "mod_auth.max-login-attempts",
      ban_maxloginattempts_ev, bee);

  } else if (strcasecmp(cmd->argv[1], "RootLogin") == 0) {
    bee->bee_type = BAN_EV_TYPE_ROOT_LOGIN;
    pr_event_register(&ban_module, "mod_auth.root-login",
      ban_rootlogin_ev, bee);

  } else if (strcasecmp(cmd->argv[1], "TimeoutIdle") == 0) {
    bee->bee_type = BAN_EV_TYPE_TIMEOUT_IDLE;
    pr_event_register(&ban_module, "core.timeout-idle",
      ban_timeoutidle_ev, bee);

  } else if (strcasecmp(cmd->argv[1], "TimeoutLogin") == 0) {
    bee->bee_type = BAN_EV_TYPE_TIMEOUT_LOGIN;
    pr_event_register(&ban_module, "core.timeout-login",
      ban_timeoutlogin_ev, bee);

  } else if (strcasecmp(cmd->argv[1], "TimeoutNoTransfer") == 0) {
    bee->bee_type = BAN_EV_TYPE_TIMEOUT_NO_TRANSFER;
    pr_event_register(&ban_module, "core.timeout-no-transfer",
      ban_timeoutnoxfer_ev, bee);

  } else if (strcasecmp(cmd->argv[1], "TLSHandshake") == 0) {
    bee->bee_type = BAN_EV_TYPE_TLS_HANDSHAKE;
    pr_event_register(&ban_module, "mod_tls.ctrl-handshake",
      ban_tlshandshake_ev, bee);

  } else if (strcasecmp(cmd->argv[1], "UnhandledCommand") == 0) {
    bee->bee_type = BAN_EV_TYPE_UNHANDLED_CMD;
    pr_event_register(&ban_module, "core.unhandled-command",
      ban_unhandledcmd_ev, bee);

  } else {
    bee->bee_type = BAN_EV_TYPE_USER_DEFINED;
    pr_event_register(&ban_module, cmd->argv[1], ban_userdefined_ev, bee);
  }

  return PR_HANDLED(cmd);
}

/* usage: BanTable path */
MODRET set_bantable(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_fs_valid_path(cmd->argv[1]) < 0)
    CONF_ERROR(cmd, "must be an absolute path");

  ban_table = pstrdup(ban_pool, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Timer handlers
 */

static int ban_timer_cb(CALLBACK_FRAME) {
  ban_list_expire();
  ban_event_list_expire();
  return 1;
}

/* Event handlers
 */

static void ban_shutdown_ev(const void *event_data, void *user_data) {

  /* Remove the shm from the system.  We can only do this reliably
   * when the standalone daemon process exits; if it's an inetd process,
   * there many be other proftpd processes still running.
   */

  if (getpid() == mpid &&
      ServerType == SERVER_STANDALONE &&
      ban_shmid >= 0) {
    struct shmid_ds ds;
    int res;

#if !defined(_POSIX_SOURCE)
    res = shmdt((char *) ban_lists);
#else
    res = shmdt((const void *) ban_lists);
#endif

    if (res < 0) {
      pr_log_debug(DEBUG1, MOD_BAN_VERSION ": error detaching shm: %s",
        strerror(errno));

    } else {
      (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
        "detached shmid %d for BanTable '%s'", ban_shmid, ban_table);
    }

    memset(&ds, 0, sizeof(ds));

    PRIVS_ROOT
    res = shmctl(ban_shmid, IPC_RMID, &ds);
    PRIVS_RELINQUISH

    if (res < 0) {
      pr_log_debug(DEBUG1, MOD_BAN_VERSION ": error removing shmid %d: %s",
        ban_shmid, strerror(errno));

    } else {
      (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
        "removed shmid %d for BanTable '%s'", ban_shmid, ban_table);
    }
  }
}

/* A helper function, to factor many of the BanOnEvent event handling
 * code into a single location.
 */
static void ban_handle_event(unsigned int ev_type, int ban_type,
    const char *src, struct ban_event_entry *tmpl) {
  config_rec *c;
  int end_session = FALSE;
  struct ban_event_entry *bee = NULL;
  const char *event = ban_event_entry_typestr(ev_type);
  pool *tmp_pool = NULL;

  /* Check to see if the BanEngine directive is set to 'off'.  We need
   * to do this here since events can happen before the POST_CMD PASS
   * handling that mod_ban does.
   */
  c = find_config(main_server->conf, CONF_PARAM, "BanEngine", FALSE);
  if (c) {
    int use_bans = *((int *) c->argv[0]);

    if (!use_bans)
      return;
  }

  if (ban_lock_shm(LOCK_EX) < 0) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "error write-locking shm: %s", strerror(errno));
    return;
  }

  tmp_pool = make_sub_pool(ban_pool);

  ban_event_list_expire();

  bee = ban_event_list_get(ev_type, main_server->sid, src);

  if (!bee &&
      tmpl->bee_count_max > 0) {
    /* Add a new entry. */
    if (ban_event_list_add(ev_type, main_server->sid, src, tmpl->bee_count_max,
        tmpl->bee_window, tmpl->bee_expires) < 0) {
      (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
        "error adding ban event for %s: %s", event, strerror(errno));

    } else {
      (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
        "added ban event for %s", event);
    }

    bee = ban_event_list_get(ev_type, main_server->sid, src);
  }

  if (bee) {
    /* Update the entry. */
    if (bee->bee_count_curr < bee->bee_count_max) {
      bee->bee_count_curr++;
    }

    if (bee->bee_count_curr >= bee->bee_count_max) {
      int res;

      /* Threshold has been reached, add an entry to the ban list.
       * Check for an existing entry first, though.
       */

      res = ban_list_exists(NULL, ban_type, main_server->sid, src, NULL);
      if (res < 0) {
        const char *reason = pstrcat(tmp_pool, event, " autoban at ",
          pr_strtime(time(NULL)), NULL);

        ban_list_expire();

        if (ban_list_add(tmp_pool, ban_type, main_server->sid, src, reason,
            tmpl->bee_expires, tmpl->bee_mesg) < 0) {
          (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
            "error adding %s-triggered autoban for %s '%s': %s", event,
            ban_type == BAN_TYPE_USER ? "user" :
              ban_type == BAN_TYPE_HOST ? "host" : "class", src,
            strerror(errno));

        } else {
          (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
            "added %s-triggered autoban for %s '%s'", event,
              ban_type == BAN_TYPE_USER ? "user" :
                ban_type == BAN_TYPE_HOST ? "host" : "class", src);
        }

        end_session = TRUE;

      } else {
        (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
          "updated count for %s event entry: %u curr, %u max", event,
          bee->bee_count_curr, bee->bee_count_max);
      }
    }
  }

  ban_lock_shm(LOCK_UN);

  if (end_session) {
    char *ban_desc;

    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "%s autoban threshold reached, ending session", event);
    pr_log_debug(DEBUG3, MOD_BAN_VERSION
      ": autoban threshold reached, ending session");

    /* Generate a specific event for listeners who want to know when mod_ban
     * disconnects a client, and why.
     */
    ban_desc = pstrcat(tmp_pool,
      ban_type == BAN_TYPE_USER ? "USER:" :
        ban_type == BAN_TYPE_HOST ? "HOST:" : "CLASS:", event, NULL);
    pr_event_generate("mod_ban.ban.client-disconnected", ban_desc);

    ban_send_mesg(tmp_pool, ban_type == BAN_TYPE_USER ? src : "(none)", NULL);
    pr_session_disconnect(&ban_module, PR_SESS_DISCONNECT_BANNED, NULL);
  }

  destroy_pool(tmp_pool);
  return;
}

static void ban_anonrejectpasswords_ev(const void *event_data,
    void *user_data) {

  /* For this event, event_data is the client. */
  conn_t *c = (conn_t *) event_data;
  const char *ipstr;

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ipstr = pr_netaddr_get_ipstr(c->remote_addr);
  ban_handle_event(BAN_EV_TYPE_ANON_REJECT_PASSWORDS, BAN_TYPE_HOST,
    ipstr, tmpl);
}

static void ban_badprotocol_ev(const void *event_data, void *user_data) {

  /* For this event, event_data is the client. */
  conn_t *c = (conn_t *) event_data;
  const char *ipstr;

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ipstr = pr_netaddr_get_ipstr(c->remote_addr);
  ban_handle_event(BAN_EV_TYPE_BAD_PROTOCOL, BAN_TYPE_HOST, ipstr, tmpl);
}

static void ban_clientconnectrate_ev(const void *event_data, void *user_data) {

  /* For this event, event_data is the client. */
  conn_t *c = (conn_t *) event_data;
  const char *ipstr;

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ipstr = pr_netaddr_get_ipstr(c->remote_addr);
  ban_handle_event(BAN_EV_TYPE_CLIENT_CONNECT_RATE, BAN_TYPE_HOST, ipstr, tmpl);
}

static void ban_emptypassword_ev(const void *event_data, void *user_data) {
  const char *ipstr;

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);
  ban_handle_event(BAN_EV_TYPE_EMPTY_PASSWORD, BAN_TYPE_HOST, ipstr, tmpl);
}

static void ban_maxclientsperclass_ev(const void *event_data, void *user_data) {

  /* For this event, event_data is the class name. */
  char *class = (char *) event_data;

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  if (class) {
    ban_handle_event(BAN_EV_TYPE_MAX_CLIENTS_PER_CLASS, BAN_TYPE_CLASS,
      class, tmpl);
  }
}

static void ban_maxclientsperhost_ev(const void *event_data, void *user_data) {

  /* For this event, event_data is the client. */
  conn_t *c = (conn_t *) event_data;
  const char *ipstr;

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ipstr = pr_netaddr_get_ipstr(c->remote_addr);
  ban_handle_event(BAN_EV_TYPE_MAX_CLIENTS_PER_HOST, BAN_TYPE_HOST,
    ipstr, tmpl);
}

static void ban_maxclientsperuser_ev(const void *event_data, void *user_data) {

  /* For this event, event_data is the user name. */
  char *user = (char *) event_data;

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ban_handle_event(BAN_EV_TYPE_MAX_CLIENTS_PER_USER, BAN_TYPE_USER,
    user, tmpl);
}

static void ban_maxcmdrate_ev(const void *event_data, void *user_data) {
  const char *ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ban_handle_event(BAN_EV_TYPE_MAX_CMD_RATE, BAN_TYPE_HOST, ipstr, tmpl);
}

static void ban_maxconnperhost_ev(const void *event_data, void *user_data) {

  /* For this event, event_data is the client. */
  conn_t *c = (conn_t *) event_data;
  const char *ipstr;

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ipstr = pr_netaddr_get_ipstr(c->remote_addr);
  ban_handle_event(BAN_EV_TYPE_MAX_CONN_PER_HOST, BAN_TYPE_HOST,
    ipstr, tmpl);
}

static void ban_maxhostsperuser_ev(const void *event_data, void *user_data) {

  /* For this event, event_data is the user name. */
  char *user = (char *) event_data;

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ban_handle_event(BAN_EV_TYPE_MAX_HOSTS_PER_USER, BAN_TYPE_USER,
    user, tmpl);
}

static void ban_maxloginattempts_ev(const void *event_data, void *user_data) {

  /* For this event, event_data is the client. */
  conn_t *c = (conn_t *) event_data;
  const char *ipstr;

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ipstr = pr_netaddr_get_ipstr(c->remote_addr);
  ban_handle_event(BAN_EV_TYPE_MAX_LOGIN_ATTEMPTS, BAN_TYPE_HOST, ipstr,
    tmpl);
}

#if defined(PR_SHARED_MODULE)
static void ban_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_ban.c", (const char *) event_data) == 0) {
    register unsigned int i;

    for (i = 0; ban_acttab[i].act_action; i++) {
      (void) pr_ctrls_unregister(&ban_module, ban_acttab[i].act_action);
    }

    if (ban_timerno > 0) {
      (void) pr_timer_remove(ban_timerno, &ban_module);
      ban_timerno = -1;
    }

    pr_event_unregister(&ban_module, NULL, NULL);

    if (ban_pool) {
      destroy_pool(ban_pool);
      ban_pool = NULL;
    }

    if (ban_tabfh) {
      (void) pr_fsio_close(ban_tabfh);
      ban_tabfh = NULL;
    }

    if (ban_logfd > 0) {
      (void) close(ban_logfd);
      ban_logfd = -1;
    }

    ban_engine = -1;
  }
}
#endif /* PR_SHARED_MODULE */

static void ban_postparse_ev(const void *event_data, void *user_data) {
  struct ban_data *lists;
  int xerrno;
  struct stat st;

  if (ban_engine_overall != TRUE) {
    return;
  }

  /* Open the BanLog. */
  if (ban_log &&
      strncasecmp(ban_log, "none", 5) != 0) {
    int res;

    PRIVS_ROOT
    res = pr_log_openfile(ban_log, &ban_logfd, 0660);
    xerrno = errno;
    PRIVS_RELINQUISH

    switch (res) {
      case 0:
        break;

      case -1:
        pr_log_debug(DEBUG1, MOD_BAN_VERSION ": unable to open BanLog '%s': %s",
          ban_log, strerror(xerrno));
        break;

      case PR_LOG_SYMLINK:
        pr_log_debug(DEBUG1, MOD_BAN_VERSION ": unable to open BanLog '%s': %s",
          ban_log, "is a symlink");
        break;

      case PR_LOG_WRITABLE_DIR:
        pr_log_debug(DEBUG1, MOD_BAN_VERSION ": unable to open BanLog '%s': %s",
          ban_log, "parent directory is world-writable");
        break;
    } 
  }

  /* Make sure the BanTable exists. */
  if (ban_table == NULL) {
    pr_log_pri(PR_LOG_WARNING, MOD_BAN_VERSION
      ": missing required BanTable configuration");
    pr_session_disconnect(&ban_module, PR_SESS_DISCONNECT_BAD_CONFIG, NULL);
  }

  PRIVS_ROOT
  ban_tabfh = pr_fsio_open(ban_table, O_RDWR|O_CREAT); 
  xerrno = errno;
  PRIVS_RELINQUISH

  if (ban_tabfh == NULL) {
    pr_log_pri(PR_LOG_WARNING, MOD_BAN_VERSION
      ": unable to open BanTable '%s': %s", ban_table, strerror(xerrno));
    pr_session_disconnect(&ban_module, PR_SESS_DISCONNECT_BAD_CONFIG, NULL);
  }

  if (pr_fsio_fstat(ban_tabfh, &st) < 0) {
    xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, MOD_BAN_VERSION
      ": unable to stat BanTable '%s': %s", ban_table, strerror(xerrno));
    pr_fsio_close(ban_tabfh);
    ban_tabfh = NULL;
    pr_session_disconnect(&ban_module, PR_SESS_DISCONNECT_BAD_CONFIG, NULL);
  }

  if (S_ISDIR(st.st_mode)) {
    xerrno = EISDIR;

    pr_log_pri(PR_LOG_WARNING, MOD_BAN_VERSION
      ": unable to use BanTable '%s': %s", ban_table, strerror(xerrno));
    pr_fsio_close(ban_tabfh);
    ban_tabfh = NULL;
    pr_session_disconnect(&ban_module, PR_SESS_DISCONNECT_BAD_CONFIG, NULL);
  }

  if (ban_tabfh->fh_fd <= STDERR_FILENO) {
    int usable_fd;

    usable_fd = pr_fs_get_usable_fd(ban_tabfh->fh_fd);
    if (usable_fd < 0) {
      pr_log_debug(DEBUG0, MOD_BAN_VERSION
        "warning: unable to find good fd for BanTable %s: %s", ban_table,
        strerror(errno));

    } else {
      close(ban_tabfh->fh_fd);
      ban_tabfh->fh_fd = usable_fd;
    }
  } 

  /* Get the shm for storing all of our ban info. */
  lists = ban_get_shm(ban_tabfh);
  if (lists == NULL &&
      errno != EEXIST) {
    pr_log_pri(PR_LOG_WARNING, MOD_BAN_VERSION
      ": unable to get shared memory for BanTable '%s': %s", ban_table,
      strerror(errno));
    pr_session_disconnect(&ban_module, PR_SESS_DISCONNECT_BAD_CONFIG, NULL);
  }

  if (lists)
    ban_lists = lists;

  ban_timerno = pr_timer_add(BAN_TIMER_INTERVAL, -1, &ban_module, ban_timer_cb,
    "ban list expiry");
  return;
}

static void ban_restart_ev(const void *event_data, void *user_data) {
  register unsigned int i;

  if (ban_pool) {
    destroy_pool(ban_pool);
    ban_pool = NULL;
  }

  ban_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(ban_pool, MOD_BAN_VERSION);

  /* Register the control handlers */
  for (i = 0; ban_acttab[i].act_action; i++) {

    /* Allocate and initialize the ACL for this control. */
    ban_acttab[i].act_acl = pcalloc(ban_pool, sizeof(ctrls_acl_t));
    pr_ctrls_init_acl(ban_acttab[i].act_acl);
  }

  /* Unregister any BanOnEvent event handlers */
  pr_event_unregister(&ban_module, "core.timeout-idle", NULL);
  pr_event_unregister(&ban_module, "core.timeout-login", NULL);
  pr_event_unregister(&ban_module, "core.timeout-no-transfer", NULL);
  pr_event_unregister(&ban_module, "mod_auth.anon-reject-passwords", NULL);
  pr_event_unregister(&ban_module, "mod_auth.empty-password", NULL);
  pr_event_unregister(&ban_module, "mod_auth.max-clients-per-class", NULL);
  pr_event_unregister(&ban_module, "mod_auth.max-clients-per-host", NULL);
  pr_event_unregister(&ban_module, "mod_auth.max-clients-per-user", NULL);
  pr_event_unregister(&ban_module, "mod_auth.max-connections-per-host", NULL);
  pr_event_unregister(&ban_module, "mod_auth.max-hosts-per-user", NULL);
  pr_event_unregister(&ban_module, "mod_auth.max-login-attempts", NULL);
  pr_event_unregister(&ban_module, "mod_auth.max-users-per-host", NULL);
  pr_event_unregister(&ban_module, "mod_ban.client-connect-rate", NULL);
  pr_event_unregister(&ban_module, "mod_tls.ctrl-handshake", NULL);

  /* Close the BanLog file descriptor; it will be reopened by the postparse
   * event listener.
   */
  close(ban_logfd);
  ban_logfd = -1;

  /* Close the BanTable file descriptor; it will be reopened by the postparse
   * event listener.
   */
  if (ban_tabfh != NULL) {
    pr_fsio_close(ban_tabfh);
    ban_tabfh = NULL;
  }

  /* Remove the timer. */
  if (ban_timerno > 0) {
    (void) pr_timer_remove(ban_timerno, &ban_module);
    ban_timerno = -1;
  }

  return;
}

static void ban_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  ban_cache_opts = 0UL;

#if defined(PR_USE_MEMCACHE)
  if (mcache != NULL) {
    (void) pr_memcache_conn_set_namespace(mcache, &ban_module, NULL);
    mcache = NULL;
  }
#endif /* PR_USE_MEMCACHE */

#if defined(PR_USE_REDIS)
  if (redis != NULL) {
    (void) pr_redis_conn_set_namespace(redis, &ban_module, NULL, 0);
    redis = NULL;
  }
#endif /* PR_USE_REDIS */

  pr_event_unregister(&ban_module, "core.session-reinit", ban_sess_reinit_ev);

  res = ban_sess_init();
  if (res < 0) {
    pr_session_disconnect(&ban_module, PR_SESS_DISCONNECT_SESSION_INIT_FAILED,
      NULL);
  }
}

static void ban_rootlogin_ev(const void *event_data, void *user_data) {
  const char *ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ban_handle_event(BAN_EV_TYPE_ROOT_LOGIN, BAN_TYPE_HOST, ipstr, tmpl);
}

static void ban_timeoutidle_ev(const void *event_data, void *user_data) {
  const char *ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ban_handle_event(BAN_EV_TYPE_TIMEOUT_IDLE, BAN_TYPE_HOST, ipstr, tmpl);
}

static void ban_timeoutlogin_ev(const void *event_data, void *user_data) {
  const char *ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ban_handle_event(BAN_EV_TYPE_TIMEOUT_LOGIN, BAN_TYPE_HOST, ipstr, tmpl);
}

static void ban_timeoutnoxfer_ev(const void *event_data, void *user_data) {
  const char *ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);
  
  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;
  
  if (ban_engine != TRUE)
    return;
  
  ban_handle_event(BAN_EV_TYPE_TIMEOUT_NO_TRANSFER, BAN_TYPE_HOST, ipstr, tmpl);
}

static void ban_tlshandshake_ev(const void *event_data, void *user_data) {

  /* For this event, event_data is the client. */
  conn_t *c = (conn_t *) event_data;
  const char *ipstr;

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ipstr = pr_netaddr_get_ipstr(c->remote_addr);
  ban_handle_event(BAN_EV_TYPE_TLS_HANDSHAKE, BAN_TYPE_HOST, ipstr, tmpl);
}

static void ban_unhandledcmd_ev(const void *event_data, void *user_data) {
  const char *ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);
  
  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;
  
  if (ban_engine != TRUE)
    return;
  
  ban_handle_event(BAN_EV_TYPE_UNHANDLED_CMD, BAN_TYPE_HOST, ipstr, tmpl);
}

static void ban_userdefined_ev(const void *event_data, void *user_data) {
  const char *ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);

  /* user_data is a template of the ban event entry. */
  struct ban_event_entry *tmpl = user_data;

  if (ban_engine != TRUE)
    return;

  ban_handle_event(BAN_EV_TYPE_USER_DEFINED, BAN_TYPE_HOST, ipstr, tmpl);
}

/* Initialization routines
 */

static int ban_init(void) {
  register unsigned int i = 0;

  /* Allocate the pool for this module's use. */
  ban_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(ban_pool, MOD_BAN_VERSION);

  /* Register the control handlers */
  for (i = 0; ban_acttab[i].act_action; i++) {

    /* Allocate and initialize the ACL for this control. */
    ban_acttab[i].act_acl = pcalloc(ban_pool, sizeof(ctrls_acl_t));
    pr_ctrls_init_acl(ban_acttab[i].act_acl);

    if (pr_ctrls_register(&ban_module, ban_acttab[i].act_action,
        ban_acttab[i].act_desc, ban_acttab[i].act_cb) < 0)
     pr_log_pri(PR_LOG_NOTICE, MOD_BAN_VERSION
        ": error registering '%s' control: %s",
        ban_acttab[i].act_action, strerror(errno));
  }

#if defined(PR_SHARED_MODULE)
  pr_event_register(&ban_module, "core.module-unload", ban_mod_unload_ev,
    NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&ban_module, "core.postparse", ban_postparse_ev, NULL);
  pr_event_register(&ban_module, "core.restart", ban_restart_ev, NULL);
  pr_event_register(&ban_module, "core.shutdown", ban_shutdown_ev, NULL);

  return 0;
}

static int ban_sess_init(void) {
  config_rec *c;
  pool *tmp_pool;
  const char *remote_ip;
  char *rule_mesg = NULL;

  pr_event_register(&ban_module, "core.session-reinit", ban_sess_reinit_ev,
    NULL);

  if (ban_engine != TRUE) {
    return 0;
  }

  /* Check to see if the BanEngine directive is set to 'off'. */
  c = find_config(main_server->conf, CONF_PARAM, "BanEngine", FALSE);
  if (c) {
    int use_bans;

    use_bans = *((int *) c->argv[0]);
    if (use_bans == FALSE) {
      ban_engine = FALSE;
      return 0;
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "BanCache", FALSE);
  if (c != NULL) {
    int supported_driver = FALSE;
    char *driver;

    driver = c->argv[0];

#if defined(PR_USE_MEMCACHE)
    if (strcasecmp(driver, "memcache") == 0) {
      mcache = pr_memcache_conn_get();
      if (mcache == NULL) {
        (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
          "error connecting to memcached: %s", strerror(errno));
      }

      /* We really only need to look up BanCacheOptions if the BanCache
       * driver is acceptable.
       */
      c = find_config(main_server->conf, CONF_PARAM, "BanCacheOptions", FALSE);
      if (c != NULL) {
        ban_cache_opts = *((unsigned long *) c->argv[0]);
      }

      /* Configure a namespace prefix for our memcached keys. */
      if (pr_memcache_conn_set_namespace(mcache, &ban_module, "mod_ban.") < 0) {
        (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
          "error setting memcache namespace prefix: %s", strerror(errno));
      }

      supported_driver = TRUE;
    }
#endif /* PR_USE_MEMCACHE */

#if defined(PR_USE_REDIS)
    if (strcasecmp(driver, "redis") == 0) {
      redis = pr_redis_conn_get(session.pool, 0UL);
      if (redis == NULL) {
        (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
          "error connecting to Redis: %s", strerror(errno));
      }

      /* We really only need to look up BanCacheOptions if the BanCache
       * driver is acceptable.
       */
      c = find_config(main_server->conf, CONF_PARAM, "BanCacheOptions", FALSE);
      if (c != NULL) {
        ban_cache_opts = *((unsigned long *) c->argv[0]);
      }

      /* When using Redis, always use JSON. */
      if (!(ban_cache_opts & BAN_CACHE_OPT_USE_JSON)) {
        (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION, "%s",
          "using JSON for Redis caching");
        ban_cache_opts |= BAN_CACHE_OPT_USE_JSON;
      }

      /* Configure a namespace prefix for our Redis keys. */
      if (pr_redis_conn_set_namespace(redis, &ban_module, "mod_ban.", 8) < 0) {
        (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
          "error setting Redis namespace prefix: %s", strerror(errno));
      }

      supported_driver = TRUE;
    }
#endif /* PR_USE_MEMCACHE */

    if (supported_driver == FALSE) {
      (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
        "unsupported BanCache driver '%s' configured, ignoring", driver);
    }
  }

  tmp_pool = make_sub_pool(ban_pool);

  /* Make sure the list is up-to-date. */
  ban_list_expire();

  /* Check banned host list */
  remote_ip = pr_netaddr_get_ipstr(session.c->remote_addr);
  if (ban_list_exists(tmp_pool, BAN_TYPE_HOST, main_server->sid, remote_ip,
      &rule_mesg) == 0) {
    (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
      "login from host '%s' denied due to host ban", remote_ip);
    pr_log_pri(PR_LOG_NOTICE, MOD_BAN_VERSION
      ": Login denied: host '%s' banned", remote_ip);

    ban_send_mesg(tmp_pool, "(none)", rule_mesg);
    destroy_pool(tmp_pool);

    errno = EACCES;
    return -1;
  }

  /* Check banned class list */
  if (session.conn_class != NULL) {
    if (ban_list_exists(tmp_pool, BAN_TYPE_CLASS, main_server->sid,
        session.conn_class->cls_name, &rule_mesg) == 0) {
      (void) pr_log_writefile(ban_logfd, MOD_BAN_VERSION,
        "login from class '%s' denied due to class ban",
        session.conn_class->cls_name);
      pr_log_pri(PR_LOG_NOTICE, MOD_BAN_VERSION
        ": Login denied: class '%s' banned", session.conn_class->cls_name);

      ban_send_mesg(tmp_pool, "(none)", rule_mesg); 
      destroy_pool(tmp_pool);

      errno = EACCES;
      return -1;
    }
  }

  if (!ban_client_connected) {
    pr_event_generate("mod_ban.client-connect-rate", session.c);
    ban_client_connected = TRUE;
  }

  pr_event_unregister(&ban_module, "core.restart", ban_restart_ev);

  return 0;
}

/* Controls table
 */

static ctrls_acttab_t ban_acttab[] = {
  { "ban",	"ban a class, host, or user from using the daemon",	NULL,
     ban_handle_ban },
  { "permit",	"allow a banned class, host or user to use the daemon",	NULL,
    ban_handle_permit },
  { NULL, NULL, NULL, NULL }
};

/* Module API tables
 */

static conftable ban_conftab[] = {
  { "BanCache",			set_bancache,		NULL },
  { "BanCacheOptions",		set_bancacheoptions,	NULL },
  { "BanControlsACLs",		set_banctrlsacls,	NULL },
  { "BanEngine",		set_banengine,		NULL },
  { "BanLog",			set_banlog,		NULL },
  { "BanMessage",		set_banmessage,		NULL },
  { "BanOnEvent",		set_banonevent,		NULL },
  { "BanTable",			set_bantable,		NULL },
  { NULL }
};

static cmdtable ban_cmdtab[] = {
  { PRE_CMD,	C_PASS,	G_NONE,	ban_pre_pass,	FALSE,	FALSE },
  { POST_CMD,	C_PASS,	G_NONE,	ban_post_pass,	FALSE,	FALSE },
  { 0, NULL }
};

module ban_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "ban",

  /* Module configuration handler table */
  ban_conftab,

  /* Module command handler table */
  ban_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  ban_init,

  /* Session initialization function */
  ban_sess_init,

  /* Module version */
  MOD_BAN_VERSION
};
