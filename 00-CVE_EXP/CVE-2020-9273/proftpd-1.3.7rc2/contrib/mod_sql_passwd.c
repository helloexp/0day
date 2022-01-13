/*
 * ProFTPD: mod_sql_passwd -- Various SQL password handlers
 * Copyright (c) 2009-2017 TJ Saunders
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
 * resulting executable, without including the source code for OpenSSL in
 * the source distribution.
 */

#include "conf.h"
#include "privs.h"
#include "mod_sql.h"

#define MOD_SQL_PASSWD_VERSION		"mod_sql_passwd/1.1"

#ifdef PR_USE_SODIUM
# include <sodium.h>
/* Use/support Argon2, if libsodium is new enough. */
# if SODIUM_LIBRARY_VERSION_MAJOR > 9 || \
     (SODIUM_LIBRARY_VERSION_MAJOR == 9 && \
      SODIUM_LIBRARY_VERSION_MINOR >= 2)
#  define USE_SODIUM_ARGON2
# endif
#endif /* PR_USE_SODIUM */

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030302 
# error "ProFTPD 1.3.3rc2 or later required"
#endif

#if !defined(HAVE_OPENSSL) && !defined(PR_USE_OPENSSL)
# error "OpenSSL support required (--enable-openssl)"
#else
# include <openssl/evp.h>
# include <openssl/err.h>
# include <openssl/objects.h>
#endif

module sql_passwd_module;

static int sql_passwd_engine = FALSE;

#define SQL_PASSWD_COST_INTERACTIVE		1
#define SQL_PASSWD_COST_SENSITIVE		2
static unsigned int sql_passwd_cost = SQL_PASSWD_COST_INTERACTIVE;

#define SQL_PASSWD_ENC_USE_BASE64		1
#define SQL_PASSWD_ENC_USE_HEX_LC		2
#define SQL_PASSWD_ENC_USE_HEX_UC		3
#define SQL_PASSWD_ENC_USE_NONE			4
static unsigned int sql_passwd_encoding = SQL_PASSWD_ENC_USE_HEX_LC;
static unsigned int sql_passwd_salt_encoding = SQL_PASSWD_ENC_USE_NONE;

static unsigned char *sql_passwd_file_salt = NULL;
static size_t sql_passwd_file_salt_len = 0;
static unsigned char *sql_passwd_user_salt = NULL;
static size_t sql_passwd_user_salt_len = 0;

#define SQL_PASSWD_SALT_FL_APPEND	0x0001
#define SQL_PASSWD_SALT_FL_PREPEND	0x0002
static unsigned long sql_passwd_file_salt_flags = SQL_PASSWD_SALT_FL_APPEND;
static unsigned long sql_passwd_user_salt_flags = SQL_PASSWD_SALT_FL_APPEND;

#define SQL_PASSWD_OPT_HASH_SALT		0x0001
#define SQL_PASSWD_OPT_ENCODE_SALT		0x0002
#define SQL_PASSWD_OPT_HASH_PASSWORD		0x0004
#define SQL_PASSWD_OPT_ENCODE_PASSWORD		0x0008

static unsigned long sql_passwd_opts = 0UL;

static unsigned long sql_passwd_nrounds = 1;

/* For PBKDF2 */
static const EVP_MD *sql_passwd_pbkdf2_digest = NULL;
static int sql_passwd_pbkdf2_iter = -1;
static int sql_passwd_pbkdf2_len = -1;
#define SQL_PASSWD_ERR_PBKDF2_UNKNOWN_DIGEST		-1
#define SQL_PASSWD_ERR_PBKDF2_UNSUPPORTED_DIGEST	-2
#define SQL_PASSWD_ERR_PBKDF2_BAD_ROUNDS		-3
#define SQL_PASSWD_ERR_PBKDF2_BAD_LENGTH		-4

#ifdef PR_USE_SODIUM
/* For Scrypt */
# define SQL_PASSWD_SCRYPT_DEFAULT_HASH_SIZE	32U
# define SQL_PASSWD_SCRYPT_DEFAULT_SALT_SIZE	32U
static unsigned int sql_passwd_scrypt_hash_len = SQL_PASSWD_SCRYPT_DEFAULT_HASH_SIZE;

/* For Argon2 */
# ifdef USE_SODIUM_ARGON2
#  define SQL_PASSWD_ARGON2_DEFAULT_HASH_SIZE	32U
#  define SQL_PASSWD_ARGON2_DEFAULT_SALT_SIZE	16U
static unsigned int sql_passwd_argon2_hash_len = SQL_PASSWD_ARGON2_DEFAULT_HASH_SIZE;
# endif /* USE_SODIUM_ARGON2 */
#endif /* PR_USE_SODIUM */

static const char *trace_channel = "sql.passwd";

/* Necessary prototypes */
static int sql_passwd_sess_init(void);

static cmd_rec *sql_passwd_cmd_create(pool *parent_pool,
    unsigned int argc, ...) {
  register unsigned int i = 0;
  pool *cmd_pool = NULL;
  cmd_rec *cmd = NULL;
  va_list argp;
 
  cmd_pool = make_sub_pool(parent_pool);
  cmd = (cmd_rec *) pcalloc(cmd_pool, sizeof(cmd_rec));
  cmd->pool = cmd_pool;
 
  cmd->argc = argc;
  cmd->argv = pcalloc(cmd->pool, argc * sizeof(void *));

  /* Hmmm... */
  cmd->tmp_pool = cmd->pool;

  va_start(argp, argc);
  for (i = 0; i < argc; i++) {
    cmd->argv[i] = va_arg(argp, char *);
  } 
  va_end(argp);

  return cmd;
}

static const char *sql_passwd_get_str(pool *p, const char *str) {
  cmdtable *cmdtab;
  cmd_rec *cmd;
  modret_t *res;

  if (strlen(str) == 0) {
    return str;
  }

  /* Find the cmdtable for the sql_escapestr command. */
  cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_escapestr", NULL, NULL, NULL);
  if (cmdtab == NULL) {
    pr_log_debug(DEBUG2, MOD_SQL_PASSWD_VERSION
      ": unable to find SQL hook symbol 'sql_escapestr'");
    return str;
  }

  cmd = sql_passwd_cmd_create(p, 1, pr_str_strip(p, str));

  /* Call the handler. */
  res = pr_module_call(cmdtab->m, cmdtab->handler, cmd);

  /* Check the results. */
  if (MODRET_ISDECLINED(res) ||
      MODRET_ISERROR(res)) {
    pr_log_debug(DEBUG0, MOD_SQL_PASSWD_VERSION
      ": error executing 'sql_escapestring'");
    return str;
  }

  return res->data;
}

static const char *get_crypto_errors(void) {
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
    str = pstrdup(session.pool, data);
  }

  if (bio) {
    BIO_free(bio);
  }

  return str;
}

static int get_pbkdf2_config(char *algo, const EVP_MD **md,
    char *iter_str, int *iter, char *len_str, int *len) {

  *md = EVP_get_digestbyname(algo);
  if (*md == NULL) {
    return SQL_PASSWD_ERR_PBKDF2_UNKNOWN_DIGEST;
  }

#if OPENSSL_VERSION_NUMBER < 0x1000003f
  /* The necessary OpenSSL support for non-SHA1 digests for PBKDF2 appeared in
   * 1.0.0c.
   */
  if (EVP_MD_type(*md) != EVP_MD_type(EVP_sha1())) {
    return SQL_PASSWD_ERR_PBKDF2_UNSUPPORTED_DIGEST;
  }
#endif /* OpenSSL-1.0.0b and earlier */

  *iter = atoi(iter_str);
  if (*iter < 1) {
    return SQL_PASSWD_ERR_PBKDF2_BAD_ROUNDS;
  }

  *len = atoi(len_str);
  if (*len < 1) {
    return SQL_PASSWD_ERR_PBKDF2_BAD_LENGTH;
  }

  return 0;
}

static unsigned char *sql_passwd_decode(pool *p, unsigned int encoding,
    char *text, size_t text_len, size_t *data_len) {
  unsigned char *data = NULL;

  switch (encoding) {
    case SQL_PASSWD_ENC_USE_NONE:
      *data_len = text_len;
      data = (unsigned char *) pstrndup(p, text, text_len);
      break;

    case SQL_PASSWD_ENC_USE_BASE64: {
      int have_padding = FALSE, res;

      /* Due to Base64's padding, we need to detect if the last block was
       * padded with zeros; we do this by looking for '=' characters at the
       * end of the text being decoded.  If we see these characters, then we
       * will "trim" off any trailing zero values in the decoded data, on the
       * ASSUMPTION that they are the auto-added padding bytes.
       */
      if (text[text_len-1] == '=') {
        have_padding = TRUE;
      }

      data = pcalloc(p, text_len);
      res = EVP_DecodeBlock((unsigned char *) data, (unsigned char *) text,
        (int) text_len);
      if (res <= 0) {
        /* Base64-decoding error. */
        errno = EINVAL;
        return NULL;
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

      *data_len = (size_t) res;
      break;
    }

    case SQL_PASSWD_ENC_USE_HEX_LC: {
      register unsigned int i, j;
      unsigned int len = 0;

      data = pcalloc(p, text_len);
      for (i = 0, j = 0; i < text_len; i += 2) {
        int res;

        res = sscanf(text + i, "%02hhx", &(data[j++]));
        if (res == 0) {
          /* hex decoding error. */
          errno = EINVAL;
          return NULL;
        }

        len += res;
      }

      *data_len = len;
      break;
    }

    case SQL_PASSWD_ENC_USE_HEX_UC: {
      register unsigned int i, j;
      unsigned int len = 0;

      data = pcalloc(p, text_len);
      for (i = 0, j = 0; i < text_len; i += 2) {
        int res;

        res = sscanf(text + i, "%02hhX", &(data[j++]));
        if (res == 0) {
          /* hex decoding error. */
          errno = EINVAL;
          return NULL;
        }

        len += res;
      }

      *data_len = len;
      break;
    }

    default:
      errno = EPERM;
      return NULL;
  }

  return data;
}

static char *sql_passwd_encode(pool *p, unsigned int encoding,
    unsigned char *data, size_t data_len) {
  char *buf = NULL;

  switch (encoding) {
    case SQL_PASSWD_ENC_USE_BASE64: {
      /* According to RATS, the output buffer for EVP_EncodeBlock() needs to be
       * 4/3 the size of the input buffer (which is usually EVP_MAX_MD_SIZE).
       * Let's make it easy, and use an output buffer that's twice the size of
       * the input buffer.
       */
      buf = pcalloc(p, (2 * data_len) + 1);
      EVP_EncodeBlock((unsigned char *) buf, data, (int) data_len);
      break;
    }

    case SQL_PASSWD_ENC_USE_HEX_LC: {
      buf = pr_str_bin2hex(p, data, data_len, PR_STR_FL_HEX_USE_LC);
      break;
    }

    case SQL_PASSWD_ENC_USE_HEX_UC: {
      buf = pr_str_bin2hex(p, data, data_len, PR_STR_FL_HEX_USE_UC);
      break;
    }

    default:
      errno = EPERM;
      return NULL;
  }

  return buf;
}

/* This may look a little weird, with the data, prefix, and suffix arguments.
 * But they are used to handle the case where we are hashing data with
 * a salt (either as a prefix or as a suffix), and where we are hashing
 * already hashed data.
 */
static unsigned char *sql_passwd_hash(pool *p, const EVP_MD *md,
    unsigned char *data, size_t data_len,
    unsigned char *prefix, size_t prefix_len,
    unsigned char *suffix, size_t suffix_len,
    unsigned int *hash_len) {

  EVP_MD_CTX *md_ctx;
  unsigned char *hash;

  hash = palloc(p, EVP_MAX_MD_SIZE);

  /* In OpenSSL 0.9.6, many of the EVP_Digest* functions returned void, not
   * int.  Without these ugly OpenSSL version preprocessor checks, the
   * compiler will error out with "void value not ignored as it ought to be".
   */

  md_ctx = EVP_MD_CTX_create();
#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestInit(md_ctx, md) != 1) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": error initializing '%s' digest: %s", OBJ_nid2ln(EVP_MD_type(md)),
      get_crypto_errors());
    EVP_MD_CTX_destroy(md_ctx);
    errno = EPERM;
    return NULL;
  }
#else
  EVP_DigestInit(md_ctx, md);
#endif

  if (prefix != NULL) {
#if OPENSSL_VERSION_NUMBER >= 0x000907000L
    if (EVP_DigestUpdate(md_ctx, prefix, prefix_len) != 1) {
      sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
        ": error updating '%s' digest: %s", OBJ_nid2ln(EVP_MD_type(md)),
        get_crypto_errors());
      EVP_MD_CTX_destroy(md_ctx);
      errno = EPERM;
      return NULL;
    }
#else
    EVP_DigestUpdate(md_ctx, prefix, prefix_len);
#endif
  }

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestUpdate(md_ctx, data, data_len) != 1) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": error updating '%s' digest: %s", OBJ_nid2ln(EVP_MD_type(md)),
      get_crypto_errors());
    EVP_MD_CTX_destroy(md_ctx);
    errno = EPERM;
    return NULL;
  }
#else
  EVP_DigestUpdate(md_ctx, data, data_len);
#endif

  if (suffix != NULL) {
#if OPENSSL_VERSION_NUMBER >= 0x000907000L
    if (EVP_DigestUpdate(md_ctx, suffix, suffix_len) != 1) {
      sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
        ": error updating '%s' digest: %s", OBJ_nid2ln(EVP_MD_type(md)),
        get_crypto_errors());
      EVP_MD_CTX_destroy(md_ctx);
      errno = EPERM;
      return NULL;
    }
#else
    EVP_DigestUpdate(md_ctx, suffix, suffix_len);
#endif
  }

#if OPENSSL_VERSION_NUMBER >= 0x000907000L
  if (EVP_DigestFinal(md_ctx, hash, hash_len) != 1) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": error finishing '%s' digest: %s", OBJ_nid2ln(EVP_MD_type(md)),
      get_crypto_errors());
    EVP_MD_CTX_destroy(md_ctx);
    errno = EPERM;
    return NULL;
  }
#else
  EVP_DigestFinal(md_ctx, hash, hash_len);
#endif
  EVP_MD_CTX_destroy(md_ctx);

  return hash;
}

static modret_t *sql_passwd_auth(cmd_rec *cmd, const char *plaintext,
    const char *ciphertext, const char *digest) {
  const EVP_MD *md;
  unsigned char *hash = NULL, *data = NULL, *prefix = NULL, *suffix = NULL;
  size_t data_len = 0, prefix_len = 0, suffix_len = 0;
  unsigned int hash_len = 0;

  /* Temporary copy of the ciphertext string */
  char *copytext;
  const char *encodedtext;

  if (!sql_passwd_engine) {
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  /* We need a copy of the ciphertext. */
  copytext = pstrdup(cmd->tmp_pool, ciphertext);

  md = EVP_get_digestbyname(digest);
  if (md == NULL) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": no such digest '%s' supported", digest);
    return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
  }

  /* If a salt is configured, do we prepend the salt as a prefix (i.e. throw
   * it into the digest before the user-supplied password) or append it as a
   * suffix?
   */

  if (sql_passwd_file_salt_len > 0 &&
      (sql_passwd_file_salt_flags & SQL_PASSWD_SALT_FL_PREPEND)) {

    /* If we have salt data, add it to the mix. */

    if (!(sql_passwd_opts & SQL_PASSWD_OPT_HASH_SALT)) {
      prefix = (unsigned char *) sql_passwd_file_salt;
      prefix_len = sql_passwd_file_salt_len;

      pr_trace_msg(trace_channel, 9,
        "prepending %lu bytes of file salt data", (unsigned long) prefix_len);

    } else {
      unsigned int salt_hashlen = 0;

      prefix = sql_passwd_hash(cmd->tmp_pool, md,
        (unsigned char *) sql_passwd_file_salt, sql_passwd_file_salt_len,
        NULL, 0, NULL, 0, &salt_hashlen);
      prefix_len = salt_hashlen;

      if (sql_passwd_opts & SQL_PASSWD_OPT_ENCODE_SALT) {
        prefix = (unsigned char *) sql_passwd_encode(cmd->tmp_pool,
          sql_passwd_encoding, (unsigned char *) prefix, prefix_len);
        prefix_len = strlen((char *) prefix);
      }

      pr_trace_msg(trace_channel, 9,
        "prepending %lu bytes of %s-hashed file salt data (%s)",
        (unsigned long) prefix_len, digest, prefix);
    }
  }

  if (sql_passwd_user_salt_len > 0 &&
      (sql_passwd_user_salt_flags & SQL_PASSWD_SALT_FL_PREPEND)) {

    /* If we have user salt data, add it to the mix. */

    if (!(sql_passwd_opts & SQL_PASSWD_OPT_HASH_SALT)) {
      prefix = (unsigned char *) sql_passwd_user_salt;
      prefix_len = sql_passwd_user_salt_len;

      pr_trace_msg(trace_channel, 9,
        "prepending %lu bytes of user salt data", (unsigned long) prefix_len);

    } else {
      unsigned int salt_hashlen = 0;

      prefix = sql_passwd_hash(cmd->tmp_pool, md,
        (unsigned char *) sql_passwd_user_salt, sql_passwd_user_salt_len,
        NULL, 0, NULL, 0, &salt_hashlen);
      prefix_len = salt_hashlen;

      if (sql_passwd_opts & SQL_PASSWD_OPT_ENCODE_SALT) {
        prefix = (unsigned char *) sql_passwd_encode(cmd->tmp_pool,
          sql_passwd_encoding, (unsigned char *) prefix, prefix_len);
        prefix_len = strlen((char *) prefix);
      }

      pr_trace_msg(trace_channel, 9,
        "prepending %lu bytes of %s-hashed user salt data (%s)",
        (unsigned long) prefix_len, digest, prefix);
    }
  }

  if (!(sql_passwd_opts & SQL_PASSWD_OPT_HASH_PASSWORD)) {
    data = (unsigned char *) plaintext;
    data_len = strlen(plaintext);

  } else {
    /* Note: We will only honor a HashEncodePassword option IFF there is
     * also salt data present.  Otherwise, it is equivalent to another
     * round of processing, which defeats the principle of least surprise.
     */
    if ((sql_passwd_file_salt_len == 0 &&
         sql_passwd_user_salt_len == 0) &&
        (sql_passwd_opts & SQL_PASSWD_OPT_HASH_PASSWORD) &&
        (sql_passwd_opts & SQL_PASSWD_OPT_ENCODE_PASSWORD)) {
      pr_trace_msg(trace_channel, 4, "%s",
        "no salt present, ignoring HashEncodePassword SQLPasswordOption");
      data = (unsigned char *) plaintext;
      data_len = strlen(plaintext);

    } else {
      unsigned int salt_hashlen = 0;

      data = sql_passwd_hash(cmd->tmp_pool, md,
        (unsigned char *) plaintext, strlen(plaintext),
        NULL, 0, NULL, 0, &salt_hashlen);
      data_len = salt_hashlen;

      if (sql_passwd_opts & SQL_PASSWD_OPT_ENCODE_PASSWORD) {
        data = (unsigned char *) sql_passwd_encode(cmd->tmp_pool,
          sql_passwd_encoding, (unsigned char *) data, data_len);
        data_len = strlen((char *) data);
      }
    }
  }

  if (sql_passwd_file_salt_len > 0 &&
      (sql_passwd_file_salt_flags & SQL_PASSWD_SALT_FL_APPEND)) {
    /* If we have file salt data, add it to the mix. */

    if (!(sql_passwd_opts & SQL_PASSWD_OPT_HASH_SALT)) {
      suffix = (unsigned char *) sql_passwd_file_salt;
      suffix_len = sql_passwd_file_salt_len;

      pr_trace_msg(trace_channel, 9,
        "appending %lu bytes of file salt data", (unsigned long) suffix_len);

    } else {
      unsigned int salt_hashlen = 0;

      suffix = sql_passwd_hash(cmd->tmp_pool, md,
        (unsigned char *) sql_passwd_file_salt, sql_passwd_file_salt_len,
        NULL, 0, NULL, 0, &salt_hashlen);
      suffix_len = salt_hashlen;

      if (sql_passwd_opts & SQL_PASSWD_OPT_ENCODE_SALT) {
        suffix = (unsigned char *) sql_passwd_encode(cmd->tmp_pool,
          sql_passwd_encoding, (unsigned char *) suffix, suffix_len);
        suffix_len = strlen((char *) suffix);
      }

      pr_trace_msg(trace_channel, 9, 
        "appending %lu bytes of %s-hashed file salt data",
        (unsigned long) suffix_len, digest);
    }
  }

  if (sql_passwd_user_salt_len > 0 &&
      (sql_passwd_user_salt_flags & SQL_PASSWD_SALT_FL_APPEND)) {
    /* If we have user salt data, add it to the mix. */

    if (!(sql_passwd_opts & SQL_PASSWD_OPT_HASH_SALT)) {
      suffix = (unsigned char *) sql_passwd_user_salt;
      suffix_len = sql_passwd_user_salt_len;

      pr_trace_msg(trace_channel, 9,
        "appending %lu bytes of user salt data", (unsigned long) suffix_len);

    } else {
      unsigned int salt_hashlen = 0;

      suffix = sql_passwd_hash(cmd->tmp_pool, md,
        (unsigned char *) sql_passwd_user_salt, sql_passwd_user_salt_len,
        NULL, 0, NULL, 0, &salt_hashlen);
      suffix_len = salt_hashlen;

      if (sql_passwd_opts & SQL_PASSWD_OPT_ENCODE_SALT) {
        suffix = (unsigned char *) sql_passwd_encode(cmd->tmp_pool,
          sql_passwd_encoding, (unsigned char *) suffix, suffix_len);
        suffix_len = strlen((char *) suffix);
      }

      pr_trace_msg(trace_channel, 9, 
        "appending %lu bytes of %s-hashed user salt data",
        (unsigned long) suffix_len, digest);
    }
  }

  hash = sql_passwd_hash(cmd->tmp_pool, md, data, data_len, prefix, prefix_len,
    suffix, suffix_len, &hash_len);
  if (hash == NULL) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": unable to obtain password hash: %s", strerror(errno));
    return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
  }

  encodedtext = sql_passwd_encode(cmd->tmp_pool, sql_passwd_encoding, hash,
    hash_len);
  if (encodedtext == NULL) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": unsupported SQLPasswordEncoding configured");
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  /* The case of nrounds == 1 is a special case, as that is when the salt
   * data is processed.  Any additional rounds are simply hashing and
   * encoding the resulting data, over and over.
   */
  if (sql_passwd_nrounds > 1) {
    register unsigned int i;
    unsigned long nrounds = sql_passwd_nrounds - 1;

    pr_trace_msg(trace_channel, 9, 
      "transforming the data for another %lu %s", nrounds,
      nrounds != 1 ? "rounds" : "round");

    for (i = 0; i < nrounds; i++) {
      pr_signals_handle();

      hash = sql_passwd_hash(cmd->tmp_pool, md, (unsigned char *) encodedtext,
        strlen(encodedtext), NULL, 0, NULL, 0, &hash_len);
      encodedtext = sql_passwd_encode(cmd->tmp_pool, sql_passwd_encoding,
        hash, hash_len);

      pr_trace_msg(trace_channel, 15, "data after round %u: '%s'", i + 1,
        encodedtext);
    }
  }

  if (strcmp((char *) encodedtext, copytext) == 0) {
    return PR_HANDLED(cmd);

  } else {
    pr_trace_msg(trace_channel, 9, "expected '%s', got '%s'", copytext,
      encodedtext);

    pr_log_debug(DEBUG9, MOD_SQL_PASSWD_VERSION ": expected '%s', got '%s'",
      copytext, encodedtext);
  }

  return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
}

static modret_t *sql_passwd_md5(cmd_rec *cmd, const char *plaintext,
    const char *ciphertext) {
  return sql_passwd_auth(cmd, plaintext, ciphertext, "md5");
}

static modret_t *sql_passwd_sha1(cmd_rec *cmd, const char *plaintext,
    const char *ciphertext) {
  return sql_passwd_auth(cmd, plaintext, ciphertext, "sha1");
}

static modret_t *sql_passwd_sha256(cmd_rec *cmd, const char *plaintext,
    const char *ciphertext) {
  return sql_passwd_auth(cmd, plaintext, ciphertext, "sha256");
}

static modret_t *sql_passwd_sha512(cmd_rec *cmd, const char *plaintext,
    const char *ciphertext) {
  return sql_passwd_auth(cmd, plaintext, ciphertext, "sha512");
}

static modret_t *sql_passwd_pbkdf2(cmd_rec *cmd, const char *plaintext,
    const char *ciphertext) {
  unsigned char *derived_key;
  const char *encodedtext;
  char *pbkdf2_salt = NULL;
  size_t pbkdf2_salt_len = 0;
  int res;

  if (sql_passwd_engine == FALSE) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": SQLPasswordEngine disabled; unable to handle PBKDF2 SQLAuthType");
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  if (sql_passwd_pbkdf2_digest == NULL) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": PBKDF2 not configured (see SQLPasswordPBKDF2 directive)");
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  /* PBKDF2 requires a salt; if no salt is configured, it is an error. */
  if (sql_passwd_file_salt == NULL &&
      sql_passwd_user_salt == NULL) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": no salt configured (PBKDF2 requires salt)");
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  derived_key = palloc(cmd->tmp_pool, sql_passwd_pbkdf2_len);

  /* Prefer user salts over global salts. */
  if (sql_passwd_user_salt_len > 0) {
    pbkdf2_salt = (char *) sql_passwd_user_salt;
    pbkdf2_salt_len = sql_passwd_user_salt_len;

  } else {
    pbkdf2_salt = (char *) sql_passwd_file_salt;
    pbkdf2_salt_len = sql_passwd_file_salt_len;
  }

#if OPENSSL_VERSION_NUMBER >= 0x1000003f
  /* For digests other than SHA1, the necessary OpenSSL support
   * (via PKCS5_PBKDF2_HMAC) appeared in 1.0.0c.
   */
  res = PKCS5_PBKDF2_HMAC(plaintext, -1,
    (const unsigned char *) pbkdf2_salt, pbkdf2_salt_len,
    sql_passwd_pbkdf2_iter, sql_passwd_pbkdf2_digest, sql_passwd_pbkdf2_len,
    derived_key);
#else
  res = PKCS5_PBKDF2_HMAC_SHA1(plaintext, -1,
    (const unsigned char *) pbkdf2_salt, pbkdf2_salt_len,
    sql_passwd_pbkdf2_iter, sql_passwd_pbkdf2_len, derived_key);
#endif /* OpenSSL-1.0.0b and earlier */

  if (res != 1) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": error deriving PBKDF2 key: %s", get_crypto_errors());
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  encodedtext = sql_passwd_encode(cmd->tmp_pool, sql_passwd_encoding,
    derived_key,
    sql_passwd_pbkdf2_len);
  if (encodedtext == NULL) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": unsupported SQLPasswordEncoding configured");
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  if (strcmp((char *) encodedtext, ciphertext) == 0) {
    return PR_HANDLED(cmd);

  } else {
    pr_trace_msg(trace_channel, 9, "expected '%s', got '%s'", ciphertext,
      encodedtext);

    pr_log_debug(DEBUG9, MOD_SQL_PASSWD_VERSION ": expected '%s', got '%s'",
      ciphertext, encodedtext);
  }

  return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
}

#ifdef PR_USE_SODIUM
static modret_t *sql_passwd_scrypt(cmd_rec *cmd, const char *plaintext,
    const char *ciphertext) {
  int res;
  unsigned char *hash = NULL;
  unsigned int hash_len = 0;
  const char *encodedtext;
  const unsigned char *scrypt_salt;
  size_t ops_limit, mem_limit, plaintext_len, scrypt_salt_len;

  if (sql_passwd_engine == FALSE) {
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  /* scrypt requires a salt; if no salt is configured, it is an error. */
  if (sql_passwd_file_salt == NULL &&
      sql_passwd_user_salt == NULL) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": no salt configured (scrypt requires salt)");
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  /* Prefer user salts over global salts. */
  if (sql_passwd_user_salt_len > 0) {
    scrypt_salt = sql_passwd_user_salt;
    scrypt_salt_len = sql_passwd_user_salt_len;

  } else {
    scrypt_salt = sql_passwd_file_salt;
    scrypt_salt_len = sql_passwd_file_salt_len;
  }

  /* scrypt requires 32 bytes of salt */
  if (scrypt_salt_len != SQL_PASSWD_SCRYPT_DEFAULT_SALT_SIZE) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": scrypt requires %u bytes of salt (%lu bytes of salt configured)",
      SQL_PASSWD_SCRYPT_DEFAULT_SALT_SIZE, (unsigned long) scrypt_salt_len);
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  switch (sql_passwd_cost) {
    case SQL_PASSWD_COST_INTERACTIVE:
      ops_limit = crypto_pwhash_scryptsalsa208sha256_opslimit_interactive();
      mem_limit = crypto_pwhash_scryptsalsa208sha256_memlimit_interactive();
      break;

    case SQL_PASSWD_COST_SENSITIVE:
      ops_limit = crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive();
      mem_limit = crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive();
      break;

    default:
      sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
        ": unknown SQLPasswordCost value");
      return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  hash_len = sql_passwd_scrypt_hash_len;
  hash = palloc(cmd->tmp_pool, hash_len);

  plaintext_len = strlen(plaintext);
  res = crypto_pwhash_scryptsalsa208sha256(hash, hash_len, plaintext,
    plaintext_len, scrypt_salt, ops_limit, mem_limit);
  if (res < 0) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION ": scrypt error: %s",
      strerror(errno));
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  encodedtext = sql_passwd_encode(cmd->tmp_pool, sql_passwd_encoding, hash,
    hash_len);
  if (encodedtext == NULL) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": unsupported SQLPasswordEncoding configured");
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  if (strcmp((char *) encodedtext, ciphertext) == 0) {
    return PR_HANDLED(cmd);

  } else {
    pr_trace_msg(trace_channel, 9, "expected '%s', got '%s'", ciphertext,
      encodedtext);

    pr_log_debug(DEBUG9, MOD_SQL_PASSWD_VERSION ": expected '%s', got '%s'",
      ciphertext, encodedtext);
  }

  return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
}

static modret_t *sql_passwd_argon2(cmd_rec *cmd, const char *plaintext,
    const char *ciphertext) {
# if defined(USE_SODIUM_ARGON2)
  int argon2_algo, res;
  unsigned char *hash = NULL;
  unsigned int hash_len = 0;
  const char *encodedtext;
  const unsigned char *argon2_salt;
  size_t ops_limit, mem_limit, plaintext_len, argon2_salt_len;

  if (sql_passwd_engine == FALSE) {
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  /* argon2 requires a salt; if no salt is configured, it is an error. */
  if (sql_passwd_file_salt == NULL &&
      sql_passwd_user_salt == NULL) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": no salt configured (argon2 requires salt)");
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  /* Prefer user salts over global salts. */
  if (sql_passwd_user_salt_len > 0) {
    argon2_salt = sql_passwd_user_salt;
    argon2_salt_len = sql_passwd_user_salt_len;

  } else {
    argon2_salt = sql_passwd_file_salt;
    argon2_salt_len = sql_passwd_file_salt_len;
  }

  /* argon2 requires 16 bytes of salt */
  if (argon2_salt_len != SQL_PASSWD_ARGON2_DEFAULT_SALT_SIZE) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": argon2 requires %u bytes of salt (%lu bytes of salt configured)",
      SQL_PASSWD_ARGON2_DEFAULT_SALT_SIZE, (unsigned long) argon2_salt_len);
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  argon2_algo = crypto_pwhash_argon2i_alg_argon2i13();

  switch (sql_passwd_cost) {
    case SQL_PASSWD_COST_INTERACTIVE:
      ops_limit = crypto_pwhash_argon2i_opslimit_interactive();
      mem_limit = crypto_pwhash_argon2i_memlimit_interactive();
      break;

    case SQL_PASSWD_COST_SENSITIVE:
      ops_limit = crypto_pwhash_argon2i_opslimit_sensitive();
      mem_limit = crypto_pwhash_argon2i_memlimit_sensitive();
      break;

    default:
      sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
        ": unknown SQLPasswordCost value");
      return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  hash_len = sql_passwd_argon2_hash_len;
  hash = palloc(cmd->tmp_pool, hash_len);

  plaintext_len = strlen(plaintext);
  res = crypto_pwhash_argon2i(hash, hash_len, plaintext, plaintext_len,
    argon2_salt, ops_limit, mem_limit, argon2_algo);
  if (res < 0) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION ": argon2 error: %s",
      strerror(errno));
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  encodedtext = sql_passwd_encode(cmd->tmp_pool, sql_passwd_encoding, hash,
    hash_len);
  if (encodedtext == NULL) {
    sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
      ": unsupported SQLPasswordEncoding configured");
    return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
  }

  if (strcmp((char *) encodedtext, ciphertext) == 0) {
    return PR_HANDLED(cmd);

  } else {
    pr_trace_msg(trace_channel, 9, "expected '%s', got '%s'", ciphertext,
      encodedtext);

    pr_log_debug(DEBUG9, MOD_SQL_PASSWD_VERSION ": expected '%s', got '%s'",
      ciphertext, encodedtext);
  }

  return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
# else
  sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
    ": argon2 not supported on this system (requires libsodium-1.0.9 or "
    "later)");
  return PR_ERROR_INT(cmd, PR_AUTH_ERROR);
# endif /* USE_SODIUM_ARGON2 */
}
#endif /* PR_USE_SODIUM */

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void sql_passwd_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_sql_passwd.c", (const char *) event_data) == 0) {
    sql_unregister_authtype("md5");
    sql_unregister_authtype("sha1");
    sql_unregister_authtype("sha256");
    sql_unregister_authtype("sha512");
    sql_unregister_authtype("pbkdf2");
# ifdef PR_USE_SODIUM
    sql_unregister_authtype("argon2");
    sql_unregister_authtype("scrypt");
# endif /* PR_USE_SODIUM */

    pr_event_unregister(&sql_passwd_module, NULL, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

/* Command handlers
 */

MODRET sql_passwd_pre_pass(cmd_rec *cmd) {
  config_rec *c;

  if (sql_passwd_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  c = find_config(main_server->conf, CONF_PARAM, "SQLPasswordRounds", FALSE);
  if (c != NULL) {
    sql_passwd_nrounds = *((unsigned long *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "SQLPasswordPBKDF2", FALSE);
  if (c != NULL) {
    if (c->argc == 3) {
      sql_passwd_pbkdf2_digest = c->argv[0];
      sql_passwd_pbkdf2_iter = *((int *) c->argv[1]);
      sql_passwd_pbkdf2_len = *((int *) c->argv[2]);

    } else {
      const char *user;
      char *key, *named_query, *ptr;
      cmdtable *sql_cmdtab;
      cmd_rec *sql_cmd;
      modret_t *sql_res;
      array_header *sql_data;

      key = c->argv[0];

      ptr = key + 5; 
      named_query = pstrcat(cmd->tmp_pool, "SQLNamedQuery_", ptr, NULL);

      c = find_config(main_server->conf, CONF_PARAM, named_query, FALSE);
      if (c == NULL) {
        sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
          ": unable to resolve SQLNamedQuery '%s'", ptr);
        return PR_DECLINED(cmd);
      }

      sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_lookup", NULL, NULL,
        NULL);
      if (sql_cmdtab == NULL) {
        sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
          ": unable to find SQL hook symbol 'sql_lookup'");
        return PR_DECLINED(cmd);
      }

      user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);

      sql_cmd = sql_passwd_cmd_create(cmd->tmp_pool, 3, "sql_lookup", ptr,
        sql_passwd_get_str(cmd->tmp_pool, user));

      /* Call the handler. */
      sql_res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, sql_cmd);
      if (sql_res == NULL ||
          MODRET_ISERROR(sql_res)) {
        sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
          ": error processing SQLNamedQuery '%s'", ptr);
        return PR_DECLINED(cmd);
      }

      sql_data = (array_header *) sql_res->data;

      if (sql_data->nelts != 3) {
        sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
          ": SQLNamedQuery '%s' returned wrong number of columns (%d)", ptr,
          sql_data->nelts);

      } else {
        char **values;
        int iter, len, res;
        const EVP_MD *md;

        values = sql_data->elts;

        res = get_pbkdf2_config(values[0], &md, values[1], &iter,
          values[2], &len);
        switch (res) {
          case SQL_PASSWD_ERR_PBKDF2_UNKNOWN_DIGEST:
            sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
              ": SQLNamedQuery '%s' returned unknown PKBDF2 digest: %s",
              ptr, values[0]);
            break;

          case SQL_PASSWD_ERR_PBKDF2_UNSUPPORTED_DIGEST:
            sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
              ": SQLNamedQuery '%s' returned unsupported PKBDF2 digest: %s",
              ptr, values[0]);
            break;

          case SQL_PASSWD_ERR_PBKDF2_BAD_ROUNDS:
            sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
              ": SQLNamedQuery '%s' returned insufficient number of rounds: %s",
              ptr, values[1]);
            break;

          case SQL_PASSWD_ERR_PBKDF2_BAD_LENGTH:
            sql_log(DEBUG_WARN, MOD_SQL_PASSWD_VERSION
              ": SQLNamedQuery '%s' returned insufficient length: %s", ptr,
              values[2]);
            break;

          case 0:
            sql_passwd_pbkdf2_digest = md;
            sql_passwd_pbkdf2_iter = iter;
            sql_passwd_pbkdf2_len = len;
            break;
        }
      }
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "SQLPasswordUserSalt", FALSE);
  if (c != NULL) {
    char *key;
    unsigned long salt_flags;

    key = c->argv[0];
    salt_flags = *((unsigned long *) c->argv[1]);

    if (strcasecmp(key, "name") == 0) {
      const char *user;

      user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
      if (user == NULL) {
        pr_log_debug(DEBUG3, MOD_SQL_PASSWD_VERSION
          ": unable to determine original USER name");
        return PR_DECLINED(cmd);
      }

      sql_passwd_user_salt = (unsigned char *) user;
      sql_passwd_user_salt_len = strlen(user);

    } else if (strncasecmp(key, "sql:/", 5) == 0) {
      const char *user;
      char *named_query, *ptr, **values;
      cmdtable *sql_cmdtab;
      cmd_rec *sql_cmd;
      modret_t *sql_res;
      array_header *sql_data;
      size_t value_len;

      ptr = key + 5;
      named_query = pstrcat(cmd->tmp_pool, "SQLNamedQuery_", ptr, NULL);

      c = find_config(main_server->conf, CONF_PARAM, named_query, FALSE);
      if (c == NULL) {
        pr_log_debug(DEBUG3, MOD_SQL_PASSWD_VERSION
          ": unable to resolve SQLNamedQuery '%s'", ptr);
        return PR_DECLINED(cmd);
      }

      sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_lookup", NULL, NULL,
        NULL);
      if (sql_cmdtab == NULL) {
        pr_log_debug(DEBUG3, MOD_SQL_PASSWD_VERSION
          ": unable to find SQL hook symbol 'sql_lookup'");
        return PR_DECLINED(cmd);
      }

      user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
      if (user == NULL) {
        pr_log_debug(DEBUG3, MOD_SQL_PASSWD_VERSION
          ": unable to determine original USER name");
        return PR_DECLINED(cmd);
      }

      sql_cmd = sql_passwd_cmd_create(cmd->tmp_pool, 3, "sql_lookup", ptr,
        sql_passwd_get_str(cmd->tmp_pool, user));

      /* Call the handler. */
      sql_res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, sql_cmd);
      if (sql_res == NULL ||
          MODRET_ISERROR(sql_res)) {
        pr_log_debug(DEBUG0, MOD_SQL_PASSWD_VERSION
          ": error processing SQLNamedQuery '%s'", ptr);
        return PR_DECLINED(cmd);
      }

      sql_data = (array_header *) sql_res->data;

      if (sql_data->nelts != 1) {
        pr_log_debug(DEBUG0, MOD_SQL_PASSWD_VERSION
          ": SQLNamedQuery '%s' returned wrong number of rows (%d)", ptr,
          sql_data->nelts);
        return PR_DECLINED(cmd);
      }

      values = sql_data->elts;

      /* Note: this ASSUMES that the value coming from the database is a 
       * string.
       */ 
      value_len = strlen(values[0]);

      sql_passwd_user_salt = sql_passwd_decode(session.pool,
        sql_passwd_salt_encoding, values[0], value_len,
        &sql_passwd_user_salt_len);
      if (sql_passwd_user_salt == NULL) {
        pr_log_debug(DEBUG0, MOD_SQL_PASSWD_VERSION
          ": error decoding salt from SQLNamedQuery '%s': %s", ptr,
          strerror(errno));
        return PR_DECLINED(cmd);
      }

    } else {
      return PR_DECLINED(cmd);
    }

    sql_passwd_user_salt_flags = salt_flags;
  }

  return PR_DECLINED(cmd);
}

/* Configuration handlers
 */

/* usage: SQLPasswordArgon2 len */
MODRET set_sqlpasswdargon2(cmd_rec *cmd) {
#ifdef USE_SODIUM_ARGON2
  config_rec *c;
  int len;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  len = atoi(cmd->argv[1]);
  if (len <= 0) {
    CONF_ERROR(cmd, "length must be greater than 0");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = len;

  return PR_HANDLED(cmd);
#else
  CONF_ERROR(cmd, "requires libsodium Argon2 support");
#endif /* No libsodium Argon2 support */
}

/* usage: SQLPasswordCost "interactive"|"sensitive" */
MODRET set_sqlpasswdcost(cmd_rec *cmd) {
  unsigned int cost;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "interactive") == 0) {
    cost = SQL_PASSWD_COST_INTERACTIVE;

  } else if (strcasecmp(cmd->argv[1], "sensitive") == 0) {
    cost = SQL_PASSWD_COST_SENSITIVE;

  } else {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown/unsupported cost: '",
      cmd->argv[1], "'", NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = cost;

  return PR_HANDLED(cmd);
}

/* usage: SQLPasswordEncoding "base64"|"hex"|"HEX" */
MODRET set_sqlpasswdencoding(cmd_rec *cmd) {
  unsigned int encoding;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "none") == 0) {
    encoding = SQL_PASSWD_ENC_USE_NONE;

  } else if (strcasecmp(cmd->argv[1], "base64") == 0) {
    encoding = SQL_PASSWD_ENC_USE_BASE64;

  } else if (strcmp(cmd->argv[1], "hex") == 0) {
    encoding = SQL_PASSWD_ENC_USE_HEX_LC;

  } else if (strcmp(cmd->argv[1], "HEX") == 0) {
    encoding = SQL_PASSWD_ENC_USE_HEX_UC;

  } else {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unsupported encoding '",
      cmd->argv[1], "' configured", NULL));
  }
 
  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = encoding;

  return PR_HANDLED(cmd);
}

/* usage: SQLPasswordEngine on|off */
MODRET set_sqlpasswdengine(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: SQLPasswordOptions opt1 ... optN */
MODRET set_sqlpasswdoptions(cmd_rec *cmd) {
  config_rec *c;
  unsigned long opts = 0UL;
  register unsigned int i;

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcasecmp(cmd->argv[i], "HashPassword") == 0) {
      opts |= SQL_PASSWD_OPT_HASH_PASSWORD;

    } else if (strcasecmp(cmd->argv[i], "HashSalt") == 0) {
      opts |= SQL_PASSWD_OPT_HASH_SALT;

    } else if (strcasecmp(cmd->argv[i], "HashEncodePassword") == 0) {
      opts |= SQL_PASSWD_OPT_HASH_PASSWORD;
      opts |= SQL_PASSWD_OPT_ENCODE_PASSWORD;

    } else if (strcasecmp(cmd->argv[i], "HashEncodeSalt") == 0) {
      opts |= SQL_PASSWD_OPT_HASH_SALT;
      opts |= SQL_PASSWD_OPT_ENCODE_SALT;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown SQLPasswordOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: SQLPasswordPBKDF2 "sql:/"named-query|algo iter len */
MODRET set_sqlpasswdpbkdf2(cmd_rec *cmd) {
  config_rec *c;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (cmd->argc == 4) {
    int iter, len, res;
    const EVP_MD *md;

    res = get_pbkdf2_config(cmd->argv[1], &md, cmd->argv[2], &iter,
      cmd->argv[3], &len);
    switch (res) {
      case SQL_PASSWD_ERR_PBKDF2_UNKNOWN_DIGEST:
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unsupported digest algorithm '",
          cmd->argv[1], "' configured", NULL));
        break;

      case SQL_PASSWD_ERR_PBKDF2_UNSUPPORTED_DIGEST:
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
          "Use of non-SHA1 digests for PBKDF2, such as ", cmd->argv[1],
          ", requires OpenSSL-1.0.0c or later (currently using ",
          OPENSSL_VERSION_TEXT, ")", NULL));
        break;

      case SQL_PASSWD_ERR_PBKDF2_BAD_ROUNDS:
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
          "insufficient number of rounds (", cmd->argv[2], ")", NULL));
        break;

      case SQL_PASSWD_ERR_PBKDF2_BAD_LENGTH:
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "insufficient length (",
          cmd->argv[3], ")", NULL));
        break;

      case 0:
        break;
    }

    c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);
    c->argv[0] = (void *) md;
    c->argv[1] = palloc(c->pool, sizeof(int));
    *((int *) c->argv[1]) = iter;
    c->argv[2] = palloc(c->pool, sizeof(int));
    *((int *) c->argv[2]) = len;

  } else if (cmd->argc == 2) {
    if (strncasecmp(cmd->argv[1], "sql:/", 5) != 0) {
      CONF_ERROR(cmd, "badly formatted parameter");
    }

    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pstrdup(c->pool, cmd->argv[1]);

  } else {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  return PR_HANDLED(cmd);
}

/* usage: SQLPasswordRounds count */
MODRET set_sqlpasswdrounds(cmd_rec *cmd) {
  config_rec *c;
  long nrounds;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  nrounds = atol(cmd->argv[1]);
  if (nrounds < 1) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "insufficient number of rounds (",
      cmd->argv[1], ")", NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned int));
  *((unsigned long *) c->argv[0]) = nrounds;

  return PR_HANDLED(cmd);
}

/* usage: SQLPasswordSaltEncoding "base64"|"hex"|"HEX"|"none" */
MODRET set_sqlpasswdsaltencoding(cmd_rec *cmd) {
  /* Reuse the parsing code for the SQLPasswordEncoding directive. */
  return set_sqlpasswdencoding(cmd);
}

/* usage: SQLPasswordSaltFile path|"none" [flags] */
MODRET set_sqlpasswdsaltfile(cmd_rec *cmd) {
  config_rec *c;
  register unsigned int i;
  unsigned long flags = SQL_PASSWD_SALT_FL_APPEND;

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  for (i = 2; i < cmd->argc; i++) {
    if (strcasecmp(cmd->argv[i], "Append") == 0) {
      flags &= ~SQL_PASSWD_SALT_FL_PREPEND;
      flags |= SQL_PASSWD_SALT_FL_APPEND;
 
    } else if (strcasecmp(cmd->argv[i], "Prepend") == 0) {
      flags &= ~SQL_PASSWD_SALT_FL_APPEND;
      flags |= SQL_PASSWD_SALT_FL_PREPEND;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown salt flag '",
        cmd->argv[i], "'", NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, cmd->argv[1]);
  c->argv[1] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[1]) = flags;

  return PR_HANDLED(cmd);
}

/* usage: SQLPasswordScrypt len */
MODRET set_sqlpasswdscrypt(cmd_rec *cmd) {
#ifdef PR_USE_SODIUM
  config_rec *c;
  int len;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  len = atoi(cmd->argv[1]);
  if (len <= 0) {
    CONF_ERROR(cmd, "length must be greater than 0");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = len;

  return PR_HANDLED(cmd);
#else
  CONF_ERROR(cmd, "requires libsodium support");
#endif /* No libsodium support */
}

/* usage: SQLPasswordUserSalt "name"|"sql:/named-query" [flags] */
MODRET set_sqlpasswdusersalt(cmd_rec *cmd) {
  config_rec *c;
  register unsigned int i;
  unsigned long flags = SQL_PASSWD_SALT_FL_APPEND;

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "name") != 0 &&
      strcasecmp(cmd->argv[1], "uid") != 0 &&
      strncasecmp(cmd->argv[1], "sql:/", 5) != 0) {
    CONF_ERROR(cmd, "badly formatted parameter");
  }

  for (i = 2; i < cmd->argc; i++) {
    if (strcasecmp(cmd->argv[i], "Append") == 0) {
      flags &= ~SQL_PASSWD_SALT_FL_PREPEND;
      flags |= SQL_PASSWD_SALT_FL_APPEND;
 
    } else if (strcasecmp(cmd->argv[i], "Prepend") == 0) {
      flags &= ~SQL_PASSWD_SALT_FL_APPEND;
      flags |= SQL_PASSWD_SALT_FL_PREPEND;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown salt flag '",
        cmd->argv[i], "'", NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, cmd->argv[1]);
  c->argv[1] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[1]) = flags;

  return PR_HANDLED(cmd);
}

/* Event listeners
 */

static void sql_passwd_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer; reinitialize ourselves. */

  pr_event_unregister(&sql_passwd_module, "core.session-reinit",
    sql_passwd_sess_reinit_ev);

  sql_passwd_engine = FALSE;
  sql_passwd_encoding = SQL_PASSWD_ENC_USE_HEX_LC;
  sql_passwd_salt_encoding = SQL_PASSWD_ENC_USE_NONE;
  sql_passwd_file_salt = NULL;
  sql_passwd_file_salt_len = 0;
  sql_passwd_user_salt = NULL;
  sql_passwd_user_salt_len = 0;
  sql_passwd_file_salt_flags = SQL_PASSWD_SALT_FL_APPEND;
  sql_passwd_user_salt_flags = SQL_PASSWD_SALT_FL_APPEND;
  sql_passwd_opts = 0UL;
  sql_passwd_nrounds = 1;

#ifdef PR_USE_SODIUM
  sql_passwd_scrypt_hash_len = SQL_PASSWD_SCRYPT_DEFAULT_HASH_SIZE;
# ifdef USE_SODIUM_ARGON2
  sql_passwd_argon2_hash_len = SQL_PASSWD_ARGON2_DEFAULT_HASH_SIZE;
# endif /* USE_SODIUM_ARGON2 */
#endif /* PR_USE_SODIUM */

  res = sql_passwd_sess_init();
  if (res < 0) {
    pr_session_disconnect(&sql_passwd_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Initialization routines
 */

static int sql_passwd_init(void) {
  OpenSSL_add_all_digests();

#if defined(PR_SHARED_MODULE)
  pr_event_register(&sql_passwd_module, "core.module-unload",
    sql_passwd_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

#ifdef PR_USE_SODIUM
  if (sodium_init() < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_SQL_PASSWD_VERSION
      ": error initializing libsodium");

  } else {
    const char *sodium_version;

    sodium_version = sodium_version_string();
    pr_log_debug(DEBUG2, MOD_SQL_PASSWD_VERSION ": using libsodium-%s",
      sodium_version);
  }
#endif /* PR_USE_SODIUM */

  if (sql_register_authtype("md5", sql_passwd_md5) < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_SQL_PASSWD_VERSION
      ": unable to register 'md5' SQLAuthType handler: %s", strerror(errno));

  } else {
    pr_log_debug(DEBUG6, MOD_SQL_PASSWD_VERSION
      ": registered 'md5' SQLAuthType handler");
  }

  if (sql_register_authtype("sha1", sql_passwd_sha1) < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_SQL_PASSWD_VERSION
      ": unable to register 'sha1' SQLAuthType handler: %s", strerror(errno));

  } else {
    pr_log_debug(DEBUG6, MOD_SQL_PASSWD_VERSION
      ": registered 'sha1' SQLAuthType handler");
  }

  if (sql_register_authtype("sha256", sql_passwd_sha256) < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_SQL_PASSWD_VERSION
      ": unable to register 'sha256' SQLAuthType handler: %s", strerror(errno));

  } else {
    pr_log_debug(DEBUG6, MOD_SQL_PASSWD_VERSION
      ": registered 'sha256' SQLAuthType handler");
  }

  if (sql_register_authtype("sha512", sql_passwd_sha512) < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_SQL_PASSWD_VERSION
      ": unable to register 'sha512' SQLAuthType handler: %s", strerror(errno));

  } else {
    pr_log_debug(DEBUG6, MOD_SQL_PASSWD_VERSION
      ": registered 'sha512' SQLAuthType handler");
  }

  if (sql_register_authtype("pbkdf2", sql_passwd_pbkdf2) < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_SQL_PASSWD_VERSION
      ": unable to register 'pbkdf2' SQLAuthType handler: %s", strerror(errno));

  } else {
    pr_log_debug(DEBUG6, MOD_SQL_PASSWD_VERSION
      ": registered 'pbkdf2' SQLAuthType handler");
  }

#ifdef PR_USE_SODIUM
  if (sql_register_authtype("scrypt", sql_passwd_scrypt) < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_SQL_PASSWD_VERSION
      ": unable to register 'scrypt' SQLAuthType handler: %s", strerror(errno));

  } else {
    pr_log_debug(DEBUG6, MOD_SQL_PASSWD_VERSION
      ": registered 'scrypt' SQLAuthType handler");
  }

  if (sql_register_authtype("argon2", sql_passwd_argon2) < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_SQL_PASSWD_VERSION
      ": unable to register 'argon2' SQLAuthType handler: %s", strerror(errno));

  } else {
    pr_log_debug(DEBUG6, MOD_SQL_PASSWD_VERSION
      ": registered 'argon2' SQLAuthType handler");
  }
#endif /* PR_USE_SODIUM */

  return 0;
}

static int sql_passwd_sess_init(void) {
  config_rec *c;

  pr_event_register(&sql_passwd_module, "core.session-reinit",
    sql_passwd_sess_reinit_ev, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "SQLPasswordEngine", FALSE);
  if (c != NULL) {
    sql_passwd_engine = *((int *) c->argv[0]);
  }

  if (sql_passwd_engine == FALSE) {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "SQLPasswordCost", FALSE);
  if (c != NULL) {
    sql_passwd_cost = *((unsigned int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "SQLPasswordEncoding", FALSE);
  if (c != NULL) {
    sql_passwd_encoding = *((unsigned int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "SQLPasswordOptions", FALSE);
  while (c != NULL) {
    unsigned long opts;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    sql_passwd_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "SQLPasswordOptions", FALSE);
  }

  c = find_config(main_server->conf, CONF_PARAM, "SQLPasswordSaltEncoding",
    FALSE);
  if (c != NULL) {
    sql_passwd_salt_encoding = *((unsigned int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "SQLPasswordSaltFile", FALSE);
  if (c != NULL) {
    char *path;
    unsigned long salt_flags;

    path = c->argv[0];
    salt_flags = *((unsigned long *) c->argv[1]);

    if (strcasecmp(path, "none") != 0) {
      int fd, xerrno = 0;

      PRIVS_ROOT
      fd = open(path, O_RDONLY|O_NONBLOCK);
      if (fd < 0) {
        xerrno = errno;
      }
      PRIVS_RELINQUISH

      if (fd >= 0) {
        char *file_salt = NULL;
        size_t file_salt_len = 0;
        int flags;

        /* XXX Rather than using a fixed size, this should be a dynamically
         * allocated buffer, of st.st_blksize bytes, for optimal disk IO.
         */
        char buf[512];
        ssize_t nread;
  
        /* Set this descriptor for blocking. */
        flags = fcntl(fd, F_GETFL);
        if (fcntl(fd, F_SETFL, flags & (U32BITS^O_NONBLOCK)) < 0) {
          pr_log_debug(DEBUG3, MOD_SQL_PASSWD_VERSION
            ": error setting blocking mode on SQLPasswordSaltFile '%s': %s",
            path, strerror(errno));
        }
 
        nread = read(fd, buf, sizeof(buf));
        while (nread > 0) {
          pr_signals_handle();

          if (file_salt == NULL) {
            /* If the very last byte in the buffer is a newline, trim it. */
            if (buf[nread-1] == '\n') {
              buf[nread-1] = '\0';
              nread--;
            }

            file_salt_len = nread;
            file_salt = palloc(session.pool, file_salt_len);
            memcpy(file_salt, buf, nread);

          } else {
            char *ptr, *tmp;

            /* Allocate a larger buffer for the salt. */
            ptr = tmp = palloc(session.pool, file_salt_len + nread);
            memcpy(tmp, file_salt, file_salt_len);
            tmp += file_salt_len;

            memcpy(tmp, buf, nread);
            file_salt_len += nread;
            file_salt = ptr;
          }

          nread = read(fd, buf, sizeof(buf));
        }

        if (nread < 0) {
          pr_log_debug(DEBUG1, MOD_SQL_PASSWD_VERSION
            ": error reading salt data from SQLPasswordSaltFile '%s': %s",
            path, strerror(errno));
          file_salt = NULL;
        }

        (void) close(fd);

        if (file_salt != NULL) {
          /* If the very last byte in the buffer is a newline, trim it.  This
           * is to deal with cases where the SaltFile may have been written
           * with an editor (e.g. vi) which automatically adds a trailing
           * newline.
           */
          if (file_salt[file_salt_len-1] == '\n') {
            file_salt[file_salt_len-1] = '\0';
            file_salt_len--;
          }

          sql_passwd_file_salt = sql_passwd_decode(session.pool,
            sql_passwd_salt_encoding, file_salt, file_salt_len,
            &sql_passwd_file_salt_len);
          if (sql_passwd_file_salt == NULL) {
            pr_log_debug(DEBUG0, MOD_SQL_PASSWD_VERSION
              ": error decoding salt from SQLPasswordSaltFile '%s': %s", path,
              strerror(errno));

          } else {
            sql_passwd_file_salt_flags = salt_flags;
          }
        }

      } else {
        pr_log_debug(DEBUG1, MOD_SQL_PASSWD_VERSION
          ": unable to read SQLPasswordSaltFile '%s': %s", path,
          strerror(xerrno));
      }
    }
  }

#ifdef PR_USE_SODIUM
  c = find_config(main_server->conf, CONF_PARAM, "SQLPasswordScrypt", FALSE);
  if (c != NULL) {
    sql_passwd_scrypt_hash_len = *((unsigned int *) c->argv[0]);
  }

# ifdef USE_SODIUM_ARGON2
  c = find_config(main_server->conf, CONF_PARAM, "SQLPasswordArgon2", FALSE);
  if (c != NULL) {
    sql_passwd_argon2_hash_len = *((unsigned int *) c->argv[0]);
  }
# endif /* USE_SODIUM_ARGON2 */
#endif /* PR_USE_SODIUM */

  return 0;
}

/* Module API tables
 */

static conftable sql_passwd_conftab[] = {
  { "SQLPasswordArgon2",	set_sqlpasswdargon2,		NULL },
  { "SQLPasswordCost",		set_sqlpasswdcost,		NULL },
  { "SQLPasswordEncoding",	set_sqlpasswdencoding,		NULL },
  { "SQLPasswordEngine",	set_sqlpasswdengine,		NULL },
  { "SQLPasswordOptions",	set_sqlpasswdoptions,		NULL },
  { "SQLPasswordPBKDF2",	set_sqlpasswdpbkdf2,		NULL },
  { "SQLPasswordRounds",	set_sqlpasswdrounds,		NULL },
  { "SQLPasswordSaltEncoding",	set_sqlpasswdsaltencoding,	NULL },
  { "SQLPasswordSaltFile",	set_sqlpasswdsaltfile,		NULL },
  { "SQLPasswordScrypt",	set_sqlpasswdscrypt,		NULL },
  { "SQLPasswordUserSalt",	set_sqlpasswdusersalt,		NULL },

  { NULL, NULL, NULL }
};

static cmdtable sql_passwd_cmdtab[] = {
  { PRE_CMD,	C_PASS, G_NONE,	sql_passwd_pre_pass,	FALSE,	FALSE },

  { 0, NULL }
};

module sql_passwd_module = {

  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "sql_passwd",

  /* Module configuration directive table */
  sql_passwd_conftab,

  /* Module command handler table */
  sql_passwd_cmdtab,

  /* Module auth handler table */
  NULL,

  /* Module initialization */
  sql_passwd_init,

  /* Session initialization */
  sql_passwd_sess_init,

  /* Module version */
  MOD_SQL_PASSWD_VERSION
};
