/*
 * ProFTPD: mod_tls_memcache -- a module which provides shared SSL session
 *                              and OCSP response caches using memcached servers
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
 *
 * This is mod_tls_memcache, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"
#include "mod_tls.h"
#include "json.h"
#include "hanson-tpl.h"

#define MOD_TLS_MEMCACHE_VERSION		"mod_tls_memcache/0.2"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030602
# error "ProFTPD 1.3.6rc2 or later required"
#endif

module tls_memcache_module;

/* For communicating with memcached servers for shared data. */
static pr_memcache_t *sess_mcache = NULL;

/* Assume a maximum SSL session (serialized) length of 10K.  Note that this
 * is different from the SSL_MAX_SSL_SESSION_ID_LENGTH provided by OpenSSL.
 * There is no limit imposed on the length of the ASN1 description of the
 * SSL session data.
 */
#ifndef TLS_MAX_SSL_SESSION_SIZE
# define TLS_MAX_SSL_SESSION_SIZE	1024 * 10
#endif

static unsigned long sess_cache_opts = 0UL;
#define SESS_CACHE_OPT_USE_JSON		0x0001

struct sesscache_entry {
  uint32_t expires;
  unsigned int sess_datalen;
  unsigned char sess_data[TLS_MAX_SSL_SESSION_SIZE];
};

/* These are tpl format strings */
#define SESS_CACHE_TPL_KEY_FMT			"s"
#define SESS_CACHE_TPL_VALUE_FMT		"S(uic#)"

/* These are the JSON format field names */
#define SESS_CACHE_JSON_KEY_EXPIRES		"expires"
#define SESS_CACHE_JSON_KEY_DATA		"data"
#define SESS_CACHE_JSON_KEY_DATA_LENGTH		"data_len"

/* The difference between sesscache_entry and sesscache_large_entry is that the
 * buffers in the latter are dynamically allocated from the heap, not
 * stored in memcached (given that memcached has limits on how much it can
 * store).  The large_entry struct is used for storing sessions which don't
 * fit into memcached; this also means that these large entries are NOT shared
 * across processes.
 */
struct sesscache_large_entry {
  time_t expires;
  unsigned int sess_id_len;
  const unsigned char *sess_id;
  unsigned int sess_datalen;
  const unsigned char *sess_data;
};

/* These stats are stored in memcached as well, so that the status command can
 * be run on _any_ proftpd in the cluster.
 */
struct sesscache_key {
  const char *key;
  const char *desc;
};

static struct sesscache_key sesscache_keys[] = {
  { "cache_hits", "Cache lifetime hits" },
  { "cache_misses", "Cache lifetime misses" },
  { "cache_stores", "Cache lifetime sessions stored" },
  { "cache_deletes", "Cache lifetime sessions deleted" },
  { "cache_errors", "Cache lifetime errors handling sessions in cache" },
  { "cache_exceeds", "Cache lifetime sessions exceeding max entry size" },
  { "cache_max_sess_len", "Largest session exceeding max entry size" },
  { NULL, NULL }
};

/* Indexes into the sesscache_keys array */
#define SESSCACHE_KEY_HITS	0
#define SESSCACHE_KEY_MISSES	1
#define SESSCACHE_KEY_STORES	2
#define SESSCACHE_KEY_DELETES	3
#define SESSCACHE_KEY_ERRORS	4
#define SESSCACHE_KEY_EXCEEDS	5
#define SESSCACHE_KEY_MAX_LEN	6

static tls_sess_cache_t sess_cache;
static array_header *sesscache_sess_list = NULL;

#if defined(PR_USE_OPENSSL_OCSP)
static pr_memcache_t *ocsp_mcache = NULL;

/* Assume a maximum OCSP response (serialized) length of 4K. */
# ifndef TLS_MAX_OCSP_RESPONSE_SIZE
#  define TLS_MAX_OCSP_RESPONSE_SIZE		1024 * 4
# endif

struct ocspcache_entry {
  time_t age;
  unsigned int fingerprint_len;
  char fingerprint[EVP_MAX_MD_SIZE];
  unsigned int resp_derlen;
  unsigned char resp_der[TLS_MAX_OCSP_RESPONSE_SIZE];
};

/* These are the JSON format field names */
#define OCSP_CACHE_JSON_KEY_AGE			"expires"
#define OCSP_CACHE_JSON_KEY_RESPONSE		"response"
#define OCSP_CACHE_JSON_KEY_RESPONSE_LENGTH	"response_len"

/* The difference between ocspcache_entry and ocspcache_large_entry is that the
 * buffers in the latter are dynamically allocated from the heap, not
 * stored in memcached (given that memcached has limits on how much it can
 * store).  The large_entry struct is used for storing responses which don't
 * fit into memcached; this also means that these large entries are NOT shared
 * across processes.
 */
struct ocspcache_large_entry {
  time_t age;
  unsigned int fingerprint_len;
  char *fingerprint;
  unsigned int resp_derlen;
  unsigned char *resp_der;
};

/* These stats are stored in memcached as well, so that the status command can
 * be run on _any_ proftpd in the cluster.
 */
struct ocspcache_key {
  const char *key;
  const char *desc;
};

static struct ocspcache_key ocspcache_keys[] = {
  { "cache_hits", "Cache lifetime hits" },
  { "cache_misses", "Cache lifetime misses" },
  { "cache_stores", "Cache lifetime responses stored" },
  { "cache_deletes", "Cache lifetime responses deleted" },
  { "cache_errors", "Cache lifetime errors handling responses in cache" },
  { "cache_exceeds", "Cache lifetime responses exceeding max entry size" },
  { "cache_max_resp_len", "Largest response exceeding max entry size" },
  { NULL, NULL }
};

/* Indexes into the ocspcache_keys array */
#define OCSPCACHE_KEY_HITS	0
#define OCSPCACHE_KEY_MISSES	1
#define OCSPCACHE_KEY_STORES	2
#define OCSPCACHE_KEY_DELETES	3
#define OCSPCACHE_KEY_ERRORS	4
#define OCSPCACHE_KEY_EXCEEDS	5
#define OCSPCACHE_KEY_MAX_LEN	6

static tls_ocsp_cache_t ocsp_cache;
static array_header *ocspcache_resp_list = NULL;
#endif

static const char *trace_channel = "tls.memcache";

static int sess_cache_close(tls_sess_cache_t *);
#if defined(PR_USE_OPENSSL_OCSP)
static int ocsp_cache_close(tls_ocsp_cache_t *);
#endif /* PR_USE_OPENSSL_OCSP */
static int tls_mcache_sess_init(void);

static const char *mcache_get_errors(void) {
  unsigned int count = 0;
  unsigned long error_code;
  BIO *bio = NULL;
  char *data = NULL;
  long datalen;
  const char *error_data = NULL, *str = "(unknown)";
  int error_flags = 0;

  /* Use ERR_print_errors() and a memory BIO to build up a string with
   * all of the error messages from the error queue.
   */

  error_code = ERR_get_error_line_data(NULL, NULL, &error_data, &error_flags);
  if (error_code) {
    bio = BIO_new(BIO_s_mem());
  }

  while (error_code) {
    pr_signals_handle();

    if (error_flags & ERR_TXT_STRING) {
      BIO_printf(bio, "\n  (%u) %s [%s]", ++count,
        ERR_error_string(error_code, NULL), error_data);

    } else {
      BIO_printf(bio, "\n  (%u) %s", ++count,
        ERR_error_string(error_code, NULL));
    }

    error_data = NULL;
    error_flags = 0;
    error_code = ERR_get_error_line_data(NULL, NULL, &error_data, &error_flags);
  }

  datalen = BIO_get_mem_data(bio, &data);
  if (data) {
    data[datalen] = '\0';
    str = pstrdup(permanent_pool, data);
  }

  if (bio != NULL) {
    BIO_free(bio);
  }

  return str;
}

/* SSL session cache implementation callbacks.
 */

/* Functions for marshalling key/value data to/from memcached. */

static int sess_cache_get_tpl_key(pool *p, const unsigned char *sess_id,
    unsigned int sess_id_len, void **key, size_t *keysz) {
  char *sess_id_hex;
  void *data = NULL;
  size_t datasz = 0;
  int res;

  sess_id_hex = pr_str_bin2hex(p, sess_id, sess_id_len, 0);

  res = tpl_jot(TPL_MEM, &data, &datasz, SESS_CACHE_TPL_KEY_FMT, &sess_id_hex);
  if (res < 0) {
    return -1;
  }

  *keysz = datasz;
  *key = palloc(p, datasz);
  memcpy(*key, data, datasz);
  free(data);

  return 0;
}

static int sess_cache_get_json_key(pool *p, const unsigned char *sess_id,
    unsigned int sess_id_len, void **key, size_t *keysz) {
  char *sess_id_hex, *json_text;
  pr_json_object_t *json;

  sess_id_hex = pr_str_bin2hex(p, sess_id, sess_id_len, 0);
  json = pr_json_object_alloc(p);
  (void) pr_json_object_set_string(p, json, "id", sess_id_hex);

  json_text = pr_json_object_to_text(p, json, "");

  /* Include the terminating NUL in the key. */
  *keysz = strlen(json_text) + 1;
  *key = pstrndup(p, json_text, *keysz - 1);
  (void) pr_json_object_free(json);

  return 0;
}

static int sess_cache_get_key(pool *p, const unsigned char *sess_id,
    unsigned int sess_id_len, void **key, size_t *keysz) {
  int res;
  const char *key_type = "unknown";

  if (sess_cache_opts & SESS_CACHE_OPT_USE_JSON) {
    key_type = "JSON";
    res = sess_cache_get_json_key(p, sess_id, sess_id_len, key, keysz);

  } else {
    key_type = "TPL";
    res = sess_cache_get_tpl_key(p, sess_id, sess_id_len, key, keysz);
  }

  if (res < 0) {
    pr_trace_msg(trace_channel, 3,
      "error constructing cache %s lookup key for session ID (%lu bytes)",
      key_type, (unsigned long) keysz);
    return -1;
  }

  return 0;
}

static int sess_cache_entry_decode_tpl(pool *p, void *value, size_t valuesz,
    struct sesscache_entry *se) {
  int res;
  tpl_node *tn;

  tn = tpl_map(SESS_CACHE_TPL_VALUE_FMT, se, TLS_MAX_SSL_SESSION_SIZE);
  if (tn == NULL) {
    tls_log(MOD_TLS_MEMCACHE_VERSION
      ": error allocating tpl_map for format '%s'", SESS_CACHE_TPL_VALUE_FMT);
    errno = ENOMEM;
    return -1;
  }

  res = tpl_load(tn, TPL_MEM, value, valuesz);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3, "%s",
      "error loading TPL memcache session data");
    tpl_free(tn);
    errno = EINVAL;
    return -1;
  }

  res = tpl_unpack(tn, 0);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3, "%s",
      "error unpacking TPL memcache session data");
    tpl_free(tn);
    errno = EINVAL;
    return -1;
  }

  tpl_free(tn);

  return 0;
}

static int entry_get_json_number(pool *p, pr_json_object_t *json,
    const char *key, double *val, const char *text) {
  if (pr_json_object_get_number(p, json, key, val) < 0) {
    if (errno == EEXIST) {
      pr_trace_msg(trace_channel, 3,
       "ignoring non-number '%s' JSON field in '%s'", key, text);

    } else {
      tls_log(MOD_TLS_MEMCACHE_VERSION
        ": missing required '%s' JSON field in '%s'", key, text);
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
      tls_log(MOD_TLS_MEMCACHE_VERSION
        ": missing required '%s' JSON field in '%s'", key, text);
    }

    (void) pr_json_object_free(json);
    errno = EINVAL;
    return -1;
  }

  return 0;
}

static int sess_cache_entry_decode_json(pool *p, void *value, size_t valuesz,
    struct sesscache_entry *se) {
  int res;
  pr_json_object_t *json;
  const char *key;
  char *entry, *text;
  double number;

  entry = value;
  if (pr_json_text_validate(p, entry) == FALSE) {
    tls_log(MOD_TLS_MEMCACHE_VERSION
      ": unable to decode invalid JSON session cache entry: '%s'", entry);
    errno = EINVAL;
    return -1;
  }

  json = pr_json_object_from_text(p, entry);

  key = SESS_CACHE_JSON_KEY_EXPIRES;
  res = entry_get_json_number(p, json, key, &number, entry);
  if (res < 0) {
    return -1;
  }
  se->expires = (uint32_t) number;

  key = SESS_CACHE_JSON_KEY_DATA;
  res = entry_get_json_string(p, json, key, &text, entry);
  if (res == 0) {
    int have_padding = FALSE;
    char *base64_data;
    size_t base64_datalen;
    unsigned char *data;

    base64_data = text;
    base64_datalen = strlen(base64_data);

    /* Due to Base64's padding, we need to detect if the last block was
     * padded with zeros; we do this by looking for '=' characters at the
     * end of the text being decoded.  If we see these characters, then we
     * will "trim" off any trailing zero values in the decoded data, on the
     * ASSUMPTION that they are the auto-added padding bytes.
     */
    if (base64_data[base64_datalen-1] == '=') {
      have_padding = TRUE;
    }

    data = se->sess_data;
    res = EVP_DecodeBlock(data, (unsigned char *) base64_data,
      (int) base64_datalen);
    if (res <= 0) {
      /* Base64-decoding error. */
      pr_trace_msg(trace_channel, 5,
        "error base64-decoding session data in '%s', rejecting", entry);
      (void) pr_json_object_free(json);
      errno = EINVAL;
      return -1;
    }

    if (have_padding) {
      /* Assume that only one or two zero bytes of padding were added. */
      if (data[res-1] == '\0') {
        res -= 1;

        if (data[res-1] == '\0') {
          res -= 1;
        }
      }
    }
  } else {
    return -1;
  }

  key = SESS_CACHE_JSON_KEY_DATA_LENGTH;
  res = entry_get_json_number(p, json, key, &number, entry);
  if (res < 0) {
    return -1;
  }
  se->sess_datalen = (unsigned int) number;

  (void) pr_json_object_free(json);
  return 0;
}

static int sess_cache_mcache_entry_get(pool *p, const unsigned char *sess_id,
    unsigned int sess_id_len, struct sesscache_entry *se) {
  int res;
  void *key = NULL, *value = NULL;
  size_t keysz = 0, valuesz = 0;
  uint32_t flags = 0;

  res = sess_cache_get_key(p, sess_id, sess_id_len, &key, &keysz);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1,
      "unable to get cache entry: error getting cache key: %s",
      strerror(errno));

    return -1;
  }

  value = pr_memcache_kget(sess_mcache, &tls_memcache_module,
    (const char *) key, keysz, &valuesz, &flags);
  if (value == NULL) {
    pr_trace_msg(trace_channel, 3,
      "no matching memcache entry found for session ID (%lu bytes)",
      (unsigned long) keysz);
    errno = ENOENT;
    return -1;
  }

  /* Decode the cached session data. */
  if (sess_cache_opts & SESS_CACHE_OPT_USE_JSON) {
    res = sess_cache_entry_decode_json(p, value, valuesz, se);

  } else {
    res = sess_cache_entry_decode_tpl(p, value, valuesz, se);
  }

  if (res == 0) {
    time_t now;

    /* Check for expired cache entries. */
    time(&now);

    if (se->expires <= now) {
      pr_trace_msg(trace_channel, 4,
        "ignoring expired cached session data (expires %lu <= now %lu)",
        (unsigned long) se->expires, (unsigned long) now);
      errno = EPERM;
      return -1;
    }

    pr_trace_msg(trace_channel, 9, "retrieved session data from cache using %s",
      sess_cache_opts & SESS_CACHE_OPT_USE_JSON ? "JSON" : "TPL");
  }

  return 0;
}

static int sess_cache_mcache_entry_delete(pool *p, const unsigned char *sess_id,
    unsigned int sess_id_len) {
  int res;
  void *key = NULL;
  size_t keysz = 0;

  res = sess_cache_get_key(p, sess_id, sess_id_len, &key, &keysz);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1,
      "unable to remove cache entry: error getting cache key: %s",
      strerror(errno));

    return -1;
  }

  res = pr_memcache_kremove(sess_mcache, &tls_memcache_module,
    (const char *) key, keysz, 0);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "unable to remove memcache entry for session ID (%lu bytes): %s",
      (unsigned long) keysz, strerror(xerrno));

    errno = xerrno;
    return -1;
  }
 
  return 0;
}

static int sess_cache_entry_encode_tpl(pool *p, void **value, size_t *valuesz,
    struct sesscache_entry *se) {
  int res;
  tpl_node *tn;
  void *ptr = NULL;

  tn = tpl_map(SESS_CACHE_TPL_VALUE_FMT, se, TLS_MAX_SSL_SESSION_SIZE);
  if (tn == NULL) {
    pr_trace_msg(trace_channel, 1,
      "error allocating tpl_map for format '%s'", SESS_CACHE_TPL_VALUE_FMT);
    return -1;
  }

  res = tpl_pack(tn, 0);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "%s",
      "error marshalling TPL memcache session data");
    return -1;
  }

  res = tpl_dump(tn, TPL_MEM, &ptr, valuesz);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "%s",
      "error dumping marshalled TPL memcache session data");
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

static int sess_cache_entry_encode_json(pool *p, void **value, size_t *valuesz,
    struct sesscache_entry *se) {
  pr_json_object_t *json;
  pool *tmp_pool;
  char *base64_data = NULL, *json_text;

  json = pr_json_object_alloc(p);
  (void) pr_json_object_set_number(p, json, SESS_CACHE_JSON_KEY_EXPIRES,
    (double) se->expires);

  /* Base64-encode the session data.  Note that EVP_EncodeBlock does
   * NUL-terminate the encoded data.
   */
  tmp_pool = make_sub_pool(p);
  base64_data = pcalloc(tmp_pool, se->sess_datalen * 2);

  EVP_EncodeBlock((unsigned char *) base64_data, se->sess_data,
    (int) se->sess_datalen);
  (void) pr_json_object_set_string(p, json, SESS_CACHE_JSON_KEY_DATA,
    base64_data);
  (void) pr_json_object_set_number(p, json, SESS_CACHE_JSON_KEY_DATA_LENGTH,
    (double) se->sess_datalen);

  destroy_pool(tmp_pool);

  json_text = pr_json_object_to_text(p, json, "");
  (void) pr_json_object_free(json);

  if (json_text == NULL) {
    errno = ENOMEM;
    return -1;
  }

  /* Safety check */
  if (pr_json_text_validate(p, json_text) == FALSE) {
    pr_trace_msg(trace_channel, 1, "invalid JSON emitted: '%s'", json_text);
    errno = EINVAL;
    return -1;
  }

  /* Include the terminating NUL in the value. */
  *valuesz = strlen(json_text) + 1;
  *value = pstrndup(p, json_text, *valuesz - 1);

  return 0;
}

static int sess_cache_mcache_entry_set(pool *p, const unsigned char *sess_id,
    unsigned int sess_id_len, struct sesscache_entry *se) {
  int res, xerrno = 0;
  void *key = NULL, *value = NULL;
  size_t keysz = 0, valuesz = 0;
  uint32_t flags = 0;

  /* Encode the SSL session data. */
  if (sess_cache_opts & SESS_CACHE_OPT_USE_JSON) {
    res = sess_cache_entry_encode_json(p, &value, &valuesz, se);

  } else {
    res = sess_cache_entry_encode_tpl(p, &value, &valuesz, se);
  }

  if (res < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 4, "error %s encoding session data: %s",
      sess_cache_opts & SESS_CACHE_OPT_USE_JSON ? "JSON" : "TPL",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  res = sess_cache_get_key(p, sess_id, sess_id_len, &key, &keysz);
  xerrno = errno;
  if (res < 0) {
    pr_trace_msg(trace_channel, 1,
      "unable to set cache entry: error getting cache key: %s",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  res = pr_memcache_kset(sess_mcache, &tls_memcache_module, (const char *) key,
    keysz, value, valuesz, se->expires, flags);
  xerrno = errno;

  if (res < 0) {
    pr_trace_msg(trace_channel, 2,
      "unable to add memcache entry for session ID (%lu bytes): %s",
      (unsigned long) keysz, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 9, "stored session data in cache using %s",
    sess_cache_opts & SESS_CACHE_OPT_USE_JSON ? "JSON" : "TPL");
  return 0;
}

static int sess_cache_open(tls_sess_cache_t *cache, char *info, long timeout) {
  config_rec *c;

  cache->cache_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(cache->cache_pool, MOD_TLS_MEMCACHE_VERSION);

  pr_trace_msg(trace_channel, 9, "opening memcache cache %p (info '%s')",
    cache, info ? info : "(none)");

  /* This is a little messy, but necessary. The mod_memcache module does
   * not set the configured list of memcached servers until a connection
   * arrives.  But mod_tls opens its session cache prior to that, when the
   * server is starting up.  Thus we need to set the configured list of
   * memcached servers ourselves.
   */
  c = find_config(main_server->conf, CONF_PARAM, "MemcacheEngine", FALSE);
  if (c != NULL) {
    int engine;

    engine = *((int *) c->argv[0]);
    if (engine == FALSE) {
      pr_trace_msg(trace_channel, 2, "%s",
        "memcache support disabled (see MemcacheEngine directive)");
      errno = EPERM;
      return -1;
    }
  }

  sess_mcache = pr_memcache_conn_new(cache->cache_pool,
    &tls_memcache_module, 0, 0);
  if (sess_mcache == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error connecting to memcached: %s", strerror(errno));
    errno = EPERM;
    return -1;
  }

  /* Configure a namespace prefix for our memcached keys. */
  if (pr_memcache_conn_set_namespace(sess_mcache, &tls_memcache_module,
      "mod_tls_memcache.sessions.") < 0) {
    pr_trace_msg(trace_channel, 2, 
      "error setting memcache namespace prefix: %s", strerror(errno));
  }

  cache->cache_timeout = timeout;

  if (info != NULL &&
      strcasecmp(info, "/json") == 0) {
    sess_cache_opts |= SESS_CACHE_OPT_USE_JSON;
  }

  return 0;
}

static int sess_cache_close(tls_sess_cache_t *cache) {
  pr_trace_msg(trace_channel, 9, "closing memcache session cache %p", cache);

  if (cache != NULL &&
      cache->cache_pool != NULL) {

    /* We do NOT destroy the cache_pool here or close the mcache connection;
     * both were created at daemon startup, and should live as long as
     * the daemon lives.
     */

    if (sesscache_sess_list != NULL) {
      register unsigned int i;
      struct sesscache_large_entry *entries;

      entries = sesscache_sess_list->elts;
      for (i = 0; i < sesscache_sess_list->nelts; i++) {
        struct sesscache_large_entry *entry;

        entry = &(entries[i]);
        if (entry->expires > 0) {
          pr_memscrub((void *) entry->sess_data, entry->sess_datalen);
        }
      }

      clear_array(sesscache_sess_list);
    }
  }

  return 0;
}

static int sess_cache_add_large_sess(tls_sess_cache_t *cache,
    const unsigned char *sess_id, unsigned int sess_id_len, time_t expires,
    SSL_SESSION *sess, int sess_len) {
  struct sesscache_large_entry *entry = NULL;

  if (sess_len > TLS_MAX_SSL_SESSION_SIZE) {
    const char *exceeds_key = sesscache_keys[SESSCACHE_KEY_EXCEEDS].key,
      *max_len_key = sesscache_keys[SESSCACHE_KEY_MAX_LEN].key;
    void *value = NULL;
    size_t valuesz = 0;

    if (pr_memcache_incr(sess_mcache, &tls_memcache_module, exceeds_key,
        1, NULL) < 0) {
      pr_trace_msg(trace_channel, 2,
        "error incrementing '%s' value: %s", exceeds_key, strerror(errno));
    }

    /* XXX Yes, this is subject to race conditions; other proftpd servers
     * might also be modifying this value in memcached.  Oh well.
     */

    value = pr_memcache_get(sess_mcache, &tls_memcache_module, max_len_key,
      &valuesz, NULL);
    if (value != NULL) {
      uint64_t max_len;

      memcpy(&max_len, value, valuesz);
      if ((uint64_t) sess_len > max_len) {
        if (pr_memcache_set(sess_mcache, &tls_memcache_module, max_len_key,
            &max_len, sizeof(max_len), 0, 0) < 0) {
          pr_trace_msg(trace_channel, 2,
            "error setting '%s' value: %s", max_len_key, strerror(errno));
        }
      }

    } else {
      pr_trace_msg(trace_channel, 2,
        "error getting '%s' value: %s", max_len_key, strerror(errno));
    }
  }

  if (sesscache_sess_list != NULL) {
    register unsigned int i;
    struct sesscache_large_entry *entries;
    time_t now;
    int ok = FALSE;

    /* Look for any expired sessions in the list to overwrite/reuse. */
    entries = sesscache_sess_list->elts;
    time(&now);
    for (i = 0; i < sesscache_sess_list->nelts; i++) {
      entry = &(entries[i]);

      if (entry->expires <= now) {
        /* This entry has expired; clear and reuse its slot. */
        entry->expires = 0;
        pr_memscrub((void *) entry->sess_data, entry->sess_datalen);

        ok = TRUE;
        break;
      }
    }

    if (!ok) {
      /* We didn't find an open slot in the list.  Need to add one. */
      entry = push_array(sesscache_sess_list);
    }

  } else {
    sesscache_sess_list = make_array(cache->cache_pool, 1,
      sizeof(struct sesscache_large_entry));
    entry = push_array(sesscache_sess_list);
  }

  entry->expires = expires;
  entry->sess_id_len = sess_id_len;
  entry->sess_id = palloc(cache->cache_pool, sess_id_len);
  memcpy((unsigned char *) entry->sess_id, sess_id, sess_id_len);
  entry->sess_datalen = sess_len;
  entry->sess_data = palloc(cache->cache_pool, sess_len);
  i2d_SSL_SESSION(sess, (unsigned char **) &(entry->sess_data));

  return 0;
}

static int sess_cache_add(tls_sess_cache_t *cache, const unsigned char *sess_id,
    unsigned int sess_id_len, time_t expires, SSL_SESSION *sess) {
  struct sesscache_entry entry;
  int sess_len;
  unsigned char *ptr;
  time_t now;

  time(&now);
  pr_trace_msg(trace_channel, 9,
    "adding session to memcache cache %p (expires = %lu, now = %lu)", cache,
    (unsigned long) expires, (unsigned long) now);

  /* First we need to find out how much space is needed for the serialized
   * session data.  There is no known maximum size for SSL session data;
   * this module is currently designed to allow only up to a certain size.
   */
  sess_len = i2d_SSL_SESSION(sess, NULL);
  if (sess_len > TLS_MAX_SSL_SESSION_SIZE) {
    pr_trace_msg(trace_channel, 2,
      "length of serialized SSL session data (%d) exceeds maximum size (%u), "
      "unable to add to shared memcache, adding to list", sess_len,
      TLS_MAX_SSL_SESSION_SIZE);

    /* Instead of rejecting the add here, we add the session to a "large
     * session" list.  Thus the large session would still be cached per process
     * and will not be lost.
     */

    return sess_cache_add_large_sess(cache, sess_id, sess_id_len, expires,
      sess, sess_len);
  }

  entry.expires = expires;
  entry.sess_datalen = sess_len;
  ptr = entry.sess_data;
  i2d_SSL_SESSION(sess, &ptr);

  if (sess_cache_mcache_entry_set(cache->cache_pool, sess_id, sess_id_len,
      &entry) < 0) {
    pr_trace_msg(trace_channel, 2,
      "error adding session to memcache: %s", strerror(errno));

    /* Add this session to the "large session" list instead as a fallback. */
    return sess_cache_add_large_sess(cache, sess_id, sess_id_len, expires,
        sess, sess_len);

  } else {
    const char *key = sesscache_keys[SESSCACHE_KEY_STORES].key;

    if (pr_memcache_incr(sess_mcache, &tls_memcache_module, key, 1, NULL) < 0) {
      pr_trace_msg(trace_channel, 2,
        "error incrementing '%s' value: %s", key, strerror(errno));
    }
  }

  return 0;
}

static SSL_SESSION *sess_cache_get(tls_sess_cache_t *cache,
    const unsigned char *sess_id, unsigned int sess_id_len) {
  struct sesscache_entry entry;
  time_t now;
  SSL_SESSION *sess = NULL;

  pr_trace_msg(trace_channel, 9, "getting session from memcache cache %p",
    cache); 

  /* Look for the requested session in the "large session" list first. */
  if (sesscache_sess_list != NULL) {
    register unsigned int i;
    struct sesscache_large_entry *entries;

    entries = sesscache_sess_list->elts;
    for (i = 0; i < sesscache_sess_list->nelts; i++) {
      struct sesscache_large_entry *large_entry;

      large_entry = &(entries[i]);
      if (large_entry->expires > 0 &&
          large_entry->sess_id_len == sess_id_len &&
          memcmp(large_entry->sess_id, sess_id,
            large_entry->sess_id_len) == 0) {

        now = time(NULL);
        if (large_entry->expires > now) {
          TLS_D2I_SSL_SESSION_CONST unsigned char *ptr;

          ptr = large_entry->sess_data;
          sess = d2i_SSL_SESSION(NULL, &ptr, large_entry->sess_datalen);
          if (sess == NULL) {
            pr_trace_msg(trace_channel, 2,
              "error retrieving session from cache: %s", mcache_get_errors());

          } else {
            break;
          }
        }
      }
    }
  }

  if (sess) {
    return sess;
  }

  if (sess_cache_mcache_entry_get(cache->cache_pool, sess_id, sess_id_len,
      &entry) < 0) {
    return NULL;
  }
 
  now = time(NULL);
  if (entry.expires > now) {
    TLS_D2I_SSL_SESSION_CONST unsigned char *ptr;

    ptr = entry.sess_data;
    sess = d2i_SSL_SESSION(NULL, &ptr, entry.sess_datalen);
    if (sess != NULL) {
      const char *key = sesscache_keys[SESSCACHE_KEY_HITS].key;

      if (pr_memcache_incr(sess_mcache, &tls_memcache_module, key, 1,
          NULL) < 0) {
        pr_trace_msg(trace_channel, 2,
          "error incrementing '%s' value: %s", key, strerror(errno));
      }

    } else {
      const char *key = sesscache_keys[SESSCACHE_KEY_ERRORS].key;

      pr_trace_msg(trace_channel, 2,
        "error retrieving session from cache: %s", mcache_get_errors());

      if (pr_memcache_incr(sess_mcache, &tls_memcache_module, key, 1,
          NULL) < 0) {
        pr_trace_msg(trace_channel, 2,
          "error incrementing '%s' value: %s", key, strerror(errno));
      }
    }
  }

  if (sess == NULL) {
    const char *key = sesscache_keys[SESSCACHE_KEY_MISSES].key;

    if (pr_memcache_incr(sess_mcache, &tls_memcache_module, key, 1, NULL) < 0) {
      pr_trace_msg(trace_channel, 2,
        "error incrementing '%s' value: %s", key, strerror(errno));
    }

    errno = ENOENT;
  }

  return sess;
}

static int sess_cache_delete(tls_sess_cache_t *cache,
    const unsigned char *sess_id, unsigned int sess_id_len) {
  const char *key = sesscache_keys[SESSCACHE_KEY_DELETES].key;
  int res;

  pr_trace_msg(trace_channel, 9, "removing session from memcache cache %p",
    cache);

  /* Look for the requested session in the "large session" list first. */
  if (sesscache_sess_list != NULL) {
    register unsigned int i;
    struct sesscache_large_entry *entries;

    entries = sesscache_sess_list->elts;
    for (i = 0; i < sesscache_sess_list->nelts; i++) {
      struct sesscache_large_entry *entry;

      entry = &(entries[i]);
      if (entry->sess_id_len == sess_id_len &&
          memcmp(entry->sess_id, sess_id, entry->sess_id_len) == 0) {

        pr_memscrub((void *) entry->sess_data, entry->sess_datalen);
        entry->expires = 0;
        return 0;
      }
    }
  }

  res = sess_cache_mcache_entry_delete(cache->cache_pool, sess_id, sess_id_len);
  if (res < 0) {
    return -1;
  }

  /* Don't forget to update the stats. */

  if (pr_memcache_incr(sess_mcache, &tls_memcache_module, key, 1, NULL) < 0) {
    pr_trace_msg(trace_channel, 2,
      "error incrementing '%s' value: %s", key, strerror(errno));
  }

  return res;
}

static int sess_cache_clear(tls_sess_cache_t *cache) {
  register unsigned int i;
  int res = 0;

  if (sess_mcache == NULL) {
    pr_trace_msg(trace_channel, 9, "missing required memcached connection");
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 9, "clearing memcache session cache %p", cache);

  if (sesscache_sess_list != NULL) {
    struct sesscache_large_entry *entries;
    
    entries = sesscache_sess_list->elts;
    for (i = 0; i < sesscache_sess_list->nelts; i++) {
      struct sesscache_large_entry *entry;

      entry = &(entries[i]);
      entry->expires = 0;
      pr_memscrub((void *) entry->sess_data, entry->sess_datalen);
    }
  }

  /* XXX iterate through keys, kremoving any "mod_tls_memcache" prefixed keys */

  return res;
}

static int sess_cache_remove(tls_sess_cache_t *cache) {
  int res;

  pr_trace_msg(trace_channel, 9, "removing memcache session cache %p", cache);

  res = sess_cache_clear(cache);
  /* XXX close memcache conn */

  return res;
}

static int sess_cache_status(tls_sess_cache_t *cache,
    void (*statusf)(void *, const char *, ...), void *arg, int flags) {
  register unsigned int i;
  pool *tmp_pool;

  pr_trace_msg(trace_channel, 9, "checking memcache session cache %p", cache);

  tmp_pool = make_sub_pool(permanent_pool);

  statusf(arg, "%s", "Memcache SSL session cache provided by "
    MOD_TLS_MEMCACHE_VERSION);
  statusf(arg, "%s", "");
  statusf(arg, "Memcache servers: ");

  for (i = 0; sesscache_keys[i].key != NULL; i++) {
    const char *key, *desc;
    void *value = NULL;
    size_t valuesz = 0;
    uint32_t stat_flags = 0;

    key = sesscache_keys[i].key;
    desc = sesscache_keys[i].desc;

    value = pr_memcache_get(sess_mcache, &tls_memcache_module, key, &valuesz,
      &stat_flags);
    if (value != NULL) {
      uint64_t num = 0;
      memcpy(&num, value, valuesz);
      statusf(arg, "%s: %lu", desc, (unsigned long) num);
    }
  }

  /* XXX run stats on memcached servers? */

#if 0
  if (flags & TLS_SESS_CACHE_STATUS_FL_SHOW_SESSIONS) {
    statusf(arg, "%s", "");
    statusf(arg, "%s", "Cached sessions:");

    /* XXX Get keys, looking for our namespace prefix, dump each one */

    /* We _could_ use SSL_SESSION_print(), which is what the sess_id
     * command-line tool does.  The problem is that SSL_SESSION_print() shows
     * too much (particularly, it shows the master secret).  And
     * SSL_SESSION_print() does not support a flags argument to use for
     * specifying which bits of the session we want to print.
     *
     * Instead, we get to do the more dangerous (compatibility-wise) approach
     * of rolling our own printing function.
     */

    for (i = 0; i < 0; i++) {
      struct sesscache_entry *entry;

      pr_signals_handle();

      /* XXX Get entries */
      if (entry->expires > 0) {
        SSL_SESSION *sess;
        TLS_D2I_SSL_SESSION_CONST unsigned char *ptr;
        time_t ts;

        ptr = entry->sess_data;
        sess = d2i_SSL_SESSION(NULL, &ptr, entry->sess_datalen); 
        if (sess == NULL) {
          pr_log_pri(PR_LOG_NOTICE, MOD_TLS_MEMCACHE_VERSION
            ": error retrieving session from cache: %s", mcache_get_errors());
          continue;
        }

        statusf(arg, "%s", "  -----BEGIN SSL SESSION PARAMETERS-----");

        /* XXX Directly accessing these fields cannot be a Good Thing. */
        if (sess->session_id_length > 0) {
          char *sess_id_str;

          sess_id_str = pr_str2hex(tmp_pool, sess->session_id,
            sess->session_id_length, PR_STR_FL_HEX_USE_UC);

          statusf(arg, "    Session ID: %s", sess_id_str);
        }

        if (sess->sid_ctx_length > 0) {
          char *sid_ctx_str;

          sid_ctx_str = pr_str2hex(tmp_pool, sess->sid_ctx,
            sess->sid_ctx_length, PR_STR_FL_HEX_USE_UC);

          statusf(arg, "    Session ID Context: %s", sid_ctx_str);
        }

        switch (sess->ssl_version) {
          case SSL3_VERSION:
            statusf(arg, "    Protocol: %s", "SSLv3");
            break;

          case TLS1_VERSION:
            statusf(arg, "    Protocol: %s", "TLSv1");
            break;

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
          case TLS1_1_VERSION:
            statusf(arg, "    Protocol: %s", "TLSv1.1");
            break;

          case TLS1_2_VERSION:
            statusf(arg, "    Protocol: %s", "TLSv1.2");
            break;
#endif

          default:
            statusf(arg, "    Protocol: %s", "unknown");
        }

        ts = SSL_SESSION_get_time(sess);
        statusf(arg, "    Started: %s", pr_strtime(ts));
        ts = entry->expires;
        statusf(arg, "    Expires: %s (%u secs)", pr_strtime(ts),
          SSL_SESSION_get_timeout(sess));

        SSL_SESSION_free(sess);
        statusf(arg, "%s", "  -----END SSL SESSION PARAMETERS-----");
        statusf(arg, "%s", "");
      }
    }
  }
#endif

  destroy_pool(tmp_pool);
  return 0;
}

#if defined(PR_USE_OPENSSL_OCSP)
/* OCSP response cache implementation callbacks.
 */

/* Functions for marshalling key/value data to/from memcached. */

static int ocsp_cache_get_json_key(pool *p, const char *fingerprint,
    void **key, size_t *keysz) {
  pr_json_object_t *json;
  char *json_text;

  json = pr_json_object_alloc(p);
  (void) pr_json_object_set_string(p, json, "fingerprint", fingerprint);

  json_text = pr_json_object_to_text(p, json, "");
  (void) pr_json_object_free(json);

  /* Include the terminating NUL in the key. */
  *keysz = strlen(json_text) + 1;
  *key = pstrndup(p, json_text, *keysz - 1);

  return 0;
}

static int ocsp_cache_get_key(pool *p, const char *fingerprint, void **key,
    size_t *keysz) {
  int res;

  res = ocsp_cache_get_json_key(p, fingerprint, key, keysz);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3,
      "error constructing ocsp cache JSON lookup key for fingerprint '%s'",
      fingerprint);
    return -1;
  }

  return 0;
}

static int ocsp_cache_entry_decode_json(pool *p, void *value, size_t valuesz,
    struct ocspcache_entry *oe) {
  int res;
  pr_json_object_t *json;
  const char *key;
  char *entry, *text;
  double number;

  entry = value;
  if (pr_json_text_validate(p, entry) == FALSE) {
    tls_log(MOD_TLS_MEMCACHE_VERSION
      ": unable to decode invalid JSON ocsp cache entry: '%s'", entry);
    errno = EINVAL;
    return -1;
  }

  json = pr_json_object_from_text(p, entry);

  key = OCSP_CACHE_JSON_KEY_AGE;
  res = entry_get_json_number(p, json, key, &number, entry);
  if (res < 0) {
    return -1;
  }
  oe->age = (uint32_t) number;

  key = OCSP_CACHE_JSON_KEY_RESPONSE;
  res = entry_get_json_string(p, json, key, &text, entry);
  if (res == 0) {
    int have_padding = FALSE;
    char *base64_data;
    size_t base64_datalen;
    unsigned char *data;

    base64_data = text;
    base64_datalen = strlen(base64_data);

    /* Due to Base64's padding, we need to detect if the last block was
     * padded with zeros; we do this by looking for '=' characters at the
     * end of the text being decoded.  If we see these characters, then we
     * will "trim" off any trailing zero values in the decoded data, on the
     * ASSUMPTION that they are the auto-added padding bytes.
     */
    if (base64_data[base64_datalen-1] == '=') {
      have_padding = TRUE;
    }

    data = oe->resp_der;
    res = EVP_DecodeBlock(data, (unsigned char *) base64_data,
      (int) base64_datalen);
    if (res <= 0) {
      /* Base64-decoding error. */
      pr_trace_msg(trace_channel, 5,
        "error base64-decoding OCSP data in '%s', rejecting", entry);
      pr_json_object_free(json);
      errno = EINVAL;
      return -1;
    }

    if (have_padding) {
      /* Assume that only one or two zero bytes of padding were added. */
      if (data[res-1] == '\0') {
        res -= 1;

        if (data[res-1] == '\0') {
          res -= 1;
        }
      }
    }

  } else {
    return -1;
  }

  key = OCSP_CACHE_JSON_KEY_RESPONSE_LENGTH;
  res = entry_get_json_number(p, json, key, &number, entry);
  if (res < 0) {
    return -1;
  }
  oe->resp_derlen = (unsigned int) number;

  (void) pr_json_object_free(json);
  return 0;
}

static int ocsp_cache_mcache_entry_get(pool *p, const char *fingerprint,
    struct ocspcache_entry *oe) {
  int res;
  void *key = NULL, *value = NULL;
  size_t keysz = 0, valuesz = 0;
  uint32_t flags = 0;

  res = ocsp_cache_get_key(p, fingerprint, &key, &keysz);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1,
      "unable to get ocsp cache entry: error getting cache key: %s",
      strerror(errno));

    return -1;
  }

  value = pr_memcache_kget(ocsp_mcache, &tls_memcache_module,
    (const char *) key, keysz, &valuesz, &flags);
  if (value == NULL) {
    pr_trace_msg(trace_channel, 3,
      "no matching memcache entry found for fingerprint '%s'", fingerprint);
    errno = ENOENT;
    return -1;
  }

  /* Decode the cached response data. */
  res = ocsp_cache_entry_decode_json(p, value, valuesz, oe);
  if (res == 0) {
    pr_trace_msg(trace_channel, 9,
     "retrieved response data from cache using JSON");
  }

  return 0;
}

static int ocsp_cache_mcache_entry_delete(pool *p, const char *fingerprint) {
  int res;
  void *key = NULL;
  size_t keysz = 0;

  res = ocsp_cache_get_key(p, fingerprint, &key, &keysz);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1,
      "unable to remove ocsp cache entry: error getting cache key: %s",
      strerror(errno));

    return -1;
  }

  res = pr_memcache_kremove(ocsp_mcache, &tls_memcache_module,
    (const char *) key, keysz, 0);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "unable to remove memcache entry for fingerpring '%s': %s", fingerprint,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

static int ocsp_cache_entry_encode_json(pool *p, void **value, size_t *valuesz,
    struct ocspcache_entry *oe) {
  pr_json_object_t *json;
  pool *tmp_pool;
  char *base64_data = NULL, *json_text;

  json = pr_json_object_alloc(p);
  (void) pr_json_object_set_number(p, json, OCSP_CACHE_JSON_KEY_AGE,
    (double) oe->age);

  /* Base64-encode the response data.  Note that EVP_EncodeBlock does
   * NUL-terminate the encoded data.
   */
  tmp_pool = make_sub_pool(p);
  base64_data = pcalloc(tmp_pool, (oe->resp_derlen * 2) + 1);

  EVP_EncodeBlock((unsigned char *) base64_data, oe->resp_der,
    (int) oe->resp_derlen);
  (void) pr_json_object_set_string(p, json, OCSP_CACHE_JSON_KEY_RESPONSE,
    base64_data);
  (void) pr_json_object_set_number(p, json, OCSP_CACHE_JSON_KEY_RESPONSE_LENGTH,
    (double) oe->resp_derlen);
  destroy_pool(tmp_pool);

  json_text = pr_json_object_to_text(p, json, "");
  (void) pr_json_object_free(json);

  /* Safety check */
  if (pr_json_text_validate(p, json_text) == FALSE) {
    pr_trace_msg(trace_channel, 1, "invalid JSON emitted: '%s'", json_text);
    errno = EINVAL;
    return -1;
  }

  /* Include the terminating NUL in the value. */
  *valuesz = strlen(json_text) + 1;
  *value = pstrndup(p, json_text, *valuesz - 1);

  return 0;
}

static int ocsp_cache_mcache_entry_set(pool *p, const char *fingerprint,
    struct ocspcache_entry *oe) {
  int res, xerrno = 0;
  void *key = NULL, *value = NULL;
  size_t keysz = 0, valuesz = 0;
  uint32_t flags = 0;

  /* Encode the OCSP response data. */
  res = ocsp_cache_entry_encode_json(p, &value, &valuesz, oe);
  if (res < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 4, "error JSON encoding OCSP response data: %s",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  res = ocsp_cache_get_key(p, fingerprint, &key, &keysz);
  xerrno = errno;
  if (res < 0) {
    pr_trace_msg(trace_channel, 1,
      "unable to set ocsp cache entry: error getting cache key: %s",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  res = pr_memcache_kset(ocsp_mcache, &tls_memcache_module, (const char *) key,
    keysz, value, valuesz, 0, flags);
  xerrno = errno;

  if (res < 0) {
    pr_trace_msg(trace_channel, 2,
      "unable to add memcache entry for fingerprint '%s': %s", fingerprint,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  pr_trace_msg(trace_channel, 9,
    "stored OCSP response data in cache using JSON");
  return 0;
}

static int ocsp_cache_open(tls_ocsp_cache_t *cache, char *info) {
  config_rec *c;

  pr_trace_msg(trace_channel, 9, "opening memcache cache %p (info '%s')",
    cache, info ? info : "(none)");

  cache->cache_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(cache->cache_pool, MOD_TLS_MEMCACHE_VERSION);

  /* This is a little messy, but necessary. The mod_memcache module does
   * not set the configured list of memcached servers until a connection
   * arrives.  But mod_tls opens its session cache prior to that, when the
   * server is starting up.  Thus we need to set the configured list of
   * memcached servers ourselves.
   */
  c = find_config(main_server->conf, CONF_PARAM, "MemcacheEngine", FALSE);
  if (c != NULL) {
    int engine;

    engine = *((int *) c->argv[0]);
    if (engine == FALSE) {
      pr_trace_msg(trace_channel, 2, "%s",
        "memcache support disabled (see MemcacheEngine directive)");
      errno = EPERM;
      return -1;
    }
  }

  ocsp_mcache = pr_memcache_conn_new(cache->cache_pool,
    &tls_memcache_module, 0, 0);
  if (ocsp_mcache == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error connecting to memcached: %s", strerror(errno));
    errno = EPERM;
    return -1;
  }

  /* Configure a namespace prefix for our memcached keys. */
  if (pr_memcache_conn_set_namespace(ocsp_mcache, &tls_memcache_module,
      "mod_tls_memcache.ocsp.") < 0) {
    pr_trace_msg(trace_channel, 2,
      "error setting memcache namespace prefix: %s", strerror(errno));
  }

  return 0;
}

static int ocsp_cache_close(tls_ocsp_cache_t *cache) {
  pr_trace_msg(trace_channel, 9, "closing memcache ocsp cache %p", cache);

  if (cache != NULL &&
      cache->cache_pool != NULL) {

    /* We do NOT destroy the cache_pool here or close the mcache connection;
     * both were created at daemon startup, and should live as long as
     * the daemon lives.
     */

    if (ocspcache_resp_list != NULL) {
      register unsigned int i;
      struct ocspcache_large_entry *entries;

      entries = ocspcache_resp_list->elts;
      for (i = 0; i < ocspcache_resp_list->nelts; i++) {
        struct ocspcache_large_entry *entry;

        entry = &(entries[i]);
        pr_memscrub(entry->resp_der, entry->resp_derlen);
        entry->resp_derlen = 0;
        pr_memscrub(entry->fingerprint, entry->fingerprint_len);
        entry->fingerprint_len = 0;
        entry->age = 0;
      }

      clear_array(ocspcache_resp_list);
    }
  }

  return 0;
}

static int ocsp_cache_add_large_resp(tls_ocsp_cache_t *cache,
    const char *fingerprint, OCSP_RESPONSE *resp, time_t resp_age) {
  struct ocspcache_large_entry *entry = NULL;
  int resp_derlen;
  unsigned char *ptr;

  resp_derlen = i2d_OCSP_RESPONSE(resp, NULL);
  if (resp_derlen > TLS_MAX_OCSP_RESPONSE_SIZE) {
    const char *exceeds_key = ocspcache_keys[OCSPCACHE_KEY_EXCEEDS].key,
      *max_len_key = ocspcache_keys[OCSPCACHE_KEY_MAX_LEN].key;
    void *value = NULL;
    size_t valuesz = 0;

    if (pr_memcache_incr(ocsp_mcache, &tls_memcache_module, exceeds_key,
        1, NULL) < 0) {
      pr_trace_msg(trace_channel, 2,
        "error incrementing '%s' value: %s", exceeds_key, strerror(errno));
    }

    /* XXX Yes, this is subject to race conditions; other proftpd servers
     * might also be modifying this value in memcached.  Oh well.
     */

    value = pr_memcache_get(ocsp_mcache, &tls_memcache_module, max_len_key,
      &valuesz, NULL);
    if (value != NULL) {
      uint64_t max_len;

      memcpy(&max_len, value, valuesz);
      if ((uint64_t) resp_derlen > max_len) {
        if (pr_memcache_set(ocsp_mcache, &tls_memcache_module, max_len_key,
            &max_len, sizeof(max_len), 0, 0) < 0) {
          pr_trace_msg(trace_channel, 2,
            "error setting '%s' value: %s", max_len_key, strerror(errno));
        }
      }

    } else {
      pr_trace_msg(trace_channel, 2,
        "error getting '%s' value: %s", max_len_key, strerror(errno));
    }
  }

  if (ocspcache_resp_list != NULL) {
    register unsigned int i;
    struct ocspcache_large_entry *entries;
    time_t now;
    int ok = FALSE;

    /* Look for any expired sessions in the list to overwrite/reuse. */
    entries = ocspcache_resp_list->elts;
    time(&now);
    for (i = 0; i < ocspcache_resp_list->nelts; i++) {
      entry = &(entries[i]);

      if (entry->age > (now - 3600)) {
        /* This entry has expired; clear and reuse its slot. */
        entry->age = 0;
        pr_memscrub(entry->resp_der, entry->resp_derlen);
        entry->resp_derlen = 0;
        pr_memscrub(entry->fingerprint, entry->fingerprint_len);
        entry->fingerprint_len = 0;

        ok = TRUE;
        break;
      }
    }

    if (!ok) {
      /* We didn't find an open slot in the list.  Need to add one. */
      entry = push_array(ocspcache_resp_list);
    }

  } else {
    ocspcache_resp_list = make_array(cache->cache_pool, 1,
      sizeof(struct ocspcache_large_entry));
    entry = push_array(ocspcache_resp_list);
  }

  entry->age = resp_age;
  entry->fingerprint_len = strlen(fingerprint);
  entry->fingerprint = pstrdup(cache->cache_pool, fingerprint);
  entry->resp_derlen = resp_derlen;
  entry->resp_der = ptr = palloc(cache->cache_pool, resp_derlen);
  i2d_OCSP_RESPONSE(resp, &ptr);

  return 0;
}

static int ocsp_cache_add(tls_ocsp_cache_t *cache, const char *fingerprint,
    OCSP_RESPONSE *resp, time_t resp_age) {
  struct ocspcache_entry entry;
  int resp_derlen;
  unsigned char *ptr;

  pr_trace_msg(trace_channel, 9,
    "adding response to memcache ocsp cache %p", cache);

  /* First we need to find out how much space is needed for the serialized
   * response data.  There is no known maximum size for OCSP response data;
   * this module is currently designed to allow only up to a certain size.
   */
  resp_derlen = i2d_OCSP_RESPONSE(resp, NULL);
  if (resp_derlen > TLS_MAX_OCSP_RESPONSE_SIZE) {
    pr_trace_msg(trace_channel, 2,
      "length of serialized OCSP response data (%d) exceeds maximum size (%u), "
      "unable to add to shared memcache, adding to list", resp_derlen,
      TLS_MAX_OCSP_RESPONSE_SIZE);

    /* Instead of rejecting the add here, we add the response to a "large
     * response" list.  Thus the large response would still be cached per
     * process and will not be lost.
     */

    return ocsp_cache_add_large_resp(cache, fingerprint, resp, resp_age);
  }

  entry.age = resp_age;
  entry.resp_derlen = resp_derlen;
  ptr = entry.resp_der;
  i2d_OCSP_RESPONSE(resp, &ptr);

  if (ocsp_cache_mcache_entry_set(cache->cache_pool, fingerprint, &entry) < 0) {
    pr_trace_msg(trace_channel, 2,
      "error adding response to memcache: %s", strerror(errno));

    /* Add this response to the "large response" list instead as a fallback. */
    return ocsp_cache_add_large_resp(cache, fingerprint, resp, resp_age);

  } else {
    const char *key = ocspcache_keys[OCSPCACHE_KEY_STORES].key;

    if (pr_memcache_incr(ocsp_mcache, &tls_memcache_module, key, 1, NULL) < 0) {
      pr_trace_msg(trace_channel, 2,
        "error incrementing '%s' value: %s", key, strerror(errno));
    }
  }

  return 0;
}

static OCSP_RESPONSE *ocsp_cache_get(tls_ocsp_cache_t *cache,
    const char *fingerprint, time_t *resp_age) {
  struct ocspcache_entry entry;
  OCSP_RESPONSE *resp = NULL;
  size_t fingerprint_len;
  const unsigned char *ptr;

  pr_trace_msg(trace_channel, 9, "getting response from memcache ocsp cache %p",
    cache);

  fingerprint_len = strlen(fingerprint);

  /* Look for the requested response in the "large response" list first. */
  if (ocspcache_resp_list != NULL) {
    register unsigned int i;
    struct ocspcache_large_entry *entries;

    entries = ocspcache_resp_list->elts;
    for (i = 0; i < ocspcache_resp_list->nelts; i++) {
      struct ocspcache_large_entry *large_entry;

      large_entry = &(entries[i]);
      if (large_entry->fingerprint_len > 0 &&
          large_entry->fingerprint_len == fingerprint_len &&
          memcmp(large_entry->fingerprint, fingerprint, fingerprint_len) == 0) {
        ptr = large_entry->resp_der;
        resp = d2i_OCSP_RESPONSE(NULL, &ptr, large_entry->resp_derlen);
        if (resp == NULL) {
          pr_trace_msg(trace_channel, 2,
            "error retrieving response from ocsp cache: %s",
            mcache_get_errors());

        } else {
          *resp_age = large_entry->age;
          break;
        }
      }
    }
  }

  if (resp) {
    return resp;
  }

  if (ocsp_cache_mcache_entry_get(cache->cache_pool, fingerprint, &entry) < 0) {
    return NULL;
  }

  ptr = entry.resp_der;
  resp = d2i_OCSP_RESPONSE(NULL, &ptr, entry.resp_derlen);
  if (resp != NULL) {
    const char *key = ocspcache_keys[OCSPCACHE_KEY_HITS].key;

    *resp_age = entry.age;

    if (pr_memcache_incr(ocsp_mcache, &tls_memcache_module, key, 1, NULL) < 0) {
      pr_trace_msg(trace_channel, 2,
        "error incrementing '%s' value: %s", key, strerror(errno));
    }

  } else {
    const char *key = ocspcache_keys[OCSPCACHE_KEY_ERRORS].key;

    pr_trace_msg(trace_channel, 2,
      "error retrieving response from ocsp cache: %s", mcache_get_errors());

    if (pr_memcache_incr(ocsp_mcache, &tls_memcache_module, key, 1, NULL) < 0) {
      pr_trace_msg(trace_channel, 2,
        "error incrementing '%s' value: %s", key, strerror(errno));
    }
  }

  if (resp == NULL) {
    const char *key = ocspcache_keys[OCSPCACHE_KEY_MISSES].key;

    if (pr_memcache_incr(ocsp_mcache, &tls_memcache_module, key, 1, NULL) < 0) {
      pr_trace_msg(trace_channel, 2,
        "error incrementing '%s' value: %s", key, strerror(errno));
    }

    errno = ENOENT;
  }

  return resp;
}

static int ocsp_cache_delete(tls_ocsp_cache_t *cache,
    const char *fingerprint) {
  const char *key = ocspcache_keys[OCSPCACHE_KEY_DELETES].key;
  int res;
  size_t fingerprint_len;

  pr_trace_msg(trace_channel, 9,
    "deleting response from memcache ocsp cache %p", cache);

  fingerprint_len = strlen(fingerprint);

  /* Look for the requested response in the "large response" list first. */
  if (ocspcache_resp_list != NULL) {
    register unsigned int i;
    struct ocspcache_large_entry *entries;

    entries = ocspcache_resp_list->elts;
    for (i = 0; i < ocspcache_resp_list->nelts; i++) {
      struct ocspcache_large_entry *entry;

      entry = &(entries[i]);
      if (entry->fingerprint_len == fingerprint_len &&
          memcmp(entry->fingerprint, fingerprint, fingerprint_len) == 0) {

        pr_memscrub(entry->resp_der, entry->resp_derlen);
        entry->resp_derlen = 0;
        pr_memscrub(entry->fingerprint, entry->fingerprint_len);
        entry->fingerprint_len = 0;
        entry->age = 0;

        return 0;
      }
    }
  }

  res = ocsp_cache_mcache_entry_delete(cache->cache_pool, fingerprint);
  if (res < 0) {
    return -1;
  }

  /* Don't forget to update the stats. */

  if (pr_memcache_incr(ocsp_mcache, &tls_memcache_module, key, 1, NULL) < 0) {
    pr_trace_msg(trace_channel, 2,
      "error incrementing '%s' value: %s", key, strerror(errno));
  }

  return res;
}

static int ocsp_cache_clear(tls_ocsp_cache_t *cache) {
  register unsigned int i;
  int res = 0;

  if (ocsp_mcache == NULL) {
    pr_trace_msg(trace_channel, 9, "missing required memcached connection");
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 9, "clearing memcache ocsp cache %p", cache);

  if (ocspcache_resp_list != NULL) {
    struct ocspcache_large_entry *entries;

    entries = ocspcache_resp_list->elts;
    for (i = 0; i < ocspcache_resp_list->nelts; i++) {
      struct ocspcache_large_entry *entry;

      entry = &(entries[i]);
      entry->age = 0;
      pr_memscrub(entry->resp_der, entry->resp_derlen);
      entry->resp_derlen = 0;
      pr_memscrub(entry->fingerprint, entry->fingerprint_len);
      entry->fingerprint_len = 0;
    }
  }

  /* XXX iterate through keys, kremoving any "mod_tls_memcache" prefixed keys */

  return res;
}

static int ocsp_cache_remove(tls_ocsp_cache_t *cache) {
  int res;

  pr_trace_msg(trace_channel, 9, "removing memcache ocsp cache %p", cache);

  res = ocsp_cache_clear(cache);
  /* XXX close memcache conn */

  return res;
}

static int ocsp_cache_status(tls_ocsp_cache_t *cache,
    void (*statusf)(void *, const char *, ...), void *arg, int flags) {
  register unsigned int i;
  pool *tmp_pool;

  pr_trace_msg(trace_channel, 9, "checking memcache ocsp cache %p", cache);

  tmp_pool = make_sub_pool(permanent_pool);

  statusf(arg, "%s", "Memcache OCSP response cache provided by "
    MOD_TLS_MEMCACHE_VERSION);
  statusf(arg, "%s", "");
  statusf(arg, "Memcache servers: ");

  for (i = 0; ocspcache_keys[i].key != NULL; i++) {
    const char *key, *desc;
    void *value = NULL;
    size_t valuesz = 0;
    uint32_t stat_flags = 0;

    key = ocspcache_keys[i].key;
    desc = ocspcache_keys[i].desc;

    value = pr_memcache_get(ocsp_mcache, &tls_memcache_module, key, &valuesz,
      &stat_flags);
    if (value != NULL) {
      uint64_t num = 0;
      memcpy(&num, value, valuesz);
      statusf(arg, "%s: %lu", desc, (unsigned long) num);
    }
  }

  /* XXX run stats on memcached servers? */

  destroy_pool(tmp_pool);
  return 0;
}
#endif /* PR_USE_OPENSSL_OCSP */

/* Event Handlers
 */

#if defined(PR_SHARED_MODULE)
static void tls_mcache_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_tls_memcache.c", (const char *) event_data) == 0) {
    pr_event_unregister(&tls_memcache_module, NULL, NULL);
    tls_sess_cache_unregister("memcache");
# if defined(PR_USE_OPENSSL_OCSP)
    tls_ocsp_cache_unregister("memcache");
# endif /* PR_USE_OPENSSL_OCSP */
  }
}
#endif /* !PR_SHARED_MODULE */

/* Initialization functions
 */

static int tls_mcache_init(void) {
#if defined(PR_SHARED_MODULE)
  pr_event_register(&tls_memcache_module, "core.module-unload",
    tls_mcache_mod_unload_ev, NULL);
#endif /* !PR_SHARED_MODULE */

  /* Prepare our SSL session cache handler. */
  memset(&sess_cache, 0, sizeof(sess_cache));

  sess_cache.cache_name = "memcache";
  pr_pool_tag(sess_cache.cache_pool, MOD_TLS_MEMCACHE_VERSION);

  sess_cache.open = sess_cache_open;
  sess_cache.close = sess_cache_close;
  sess_cache.add = sess_cache_add;
  sess_cache.get = sess_cache_get;
  sess_cache.delete = sess_cache_delete;
  sess_cache.clear = sess_cache_clear;
  sess_cache.remove = sess_cache_remove;
  sess_cache.status = sess_cache_status;

#ifdef SSL_SESS_CACHE_NO_INTERNAL
  /* Take a chance, and inform OpenSSL that it does not need to use its own
   * internal session cache lookups/storage; using the external session cache
   * (i.e. us) will be enough.
   */
  sess_cache.cache_mode = SSL_SESS_CACHE_NO_INTERNAL;
#endif

#if defined(PR_USE_OPENSSL_OCSP)
  /* Prepare our OCSP response cache handler. */
  memset(&ocsp_cache, 0, sizeof(ocsp_cache));

  ocsp_cache.cache_name = "memcache";
  pr_pool_tag(ocsp_cache.cache_pool, MOD_TLS_MEMCACHE_VERSION);

  ocsp_cache.open = ocsp_cache_open;
  ocsp_cache.close = ocsp_cache_close;
  ocsp_cache.add = ocsp_cache_add;
  ocsp_cache.get = ocsp_cache_get;
  ocsp_cache.delete = ocsp_cache_delete;
  ocsp_cache.clear = ocsp_cache_clear;
  ocsp_cache.remove = ocsp_cache_remove;
  ocsp_cache.status = ocsp_cache_status;
#endif /* PR_USE_OPENSSL_OCSP */

#ifdef PR_USE_MEMCACHE
  if (tls_sess_cache_register("memcache", &sess_cache) < 0) {
    pr_log_debug(DEBUG1, MOD_TLS_MEMCACHE_VERSION
      ": notice: error registering 'memcache' SSL session cache: %s",
      strerror(errno));
    return -1;
  }

# if defined(PR_USE_OPENSSL_OCSP)
  if (tls_ocsp_cache_register("memcache", &ocsp_cache) < 0) {
    pr_log_debug(DEBUG1, MOD_TLS_MEMCACHE_VERSION
      ": notice: error registering 'memcache' OCSP response cache: %s",
      strerror(errno));
    return -1;
  }
# endif /* PR_USE_OPENSSL_OCSP */

#else
  pr_log_debug(DEBUG1, MOD_TLS_MEMCACHE_VERSION
    ": unable to register 'memcache' SSL session cache: Memcache support not enabled");
# if defined(PR_USE_OPENSSL_OCSP)
  pr_log_debug(DEBUG1, MOD_TLS_MEMCACHE_VERSION
    ": unable to register 'memcache' OCSP response cache: Memcache support not enabled");
# endif /* PR_USE_OPENSSL_OCSP */
#endif /* PR_USE_MEMCACHE */

  return 0;
}

static int tls_mcache_sess_init(void) {
  /* Reset our memcache handles. */

  if (sess_mcache != NULL) {
    if (pr_memcache_conn_clone(session.pool, sess_mcache) < 0) {
      tls_log(MOD_TLS_MEMCACHE_VERSION
        ": error resetting memcache handle: %s", strerror(errno));
    }
  }

#if defined(PR_USE_OPENSSL_OCSP)
  if (ocsp_mcache != NULL) {
    if (pr_memcache_conn_clone(session.pool, ocsp_mcache) < 0) {
      tls_log(MOD_TLS_MEMCACHE_VERSION
        ": error resetting memcache handle: %s", strerror(errno));
    }
  }
#endif /* PR_USE_OPENSSL_OCSP */

  return 0;
}

/* Module API tables
 */

module tls_memcache_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "tls_memcache",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  tls_mcache_init,

  /* Session initialization function */
  tls_mcache_sess_init,

  /* Module version */
  MOD_TLS_MEMCACHE_VERSION
};
