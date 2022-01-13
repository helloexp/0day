/*
 * ProFTPD - mod_sftp RFC4716 keystore
 * Copyright (c) 2008-2016 TJ Saunders
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

#include "mod_sftp.h"
#include "keys.h"
#include "keystore.h"
#include "crypto.h"
#include "rfc4716.h"

/* File-based keystore implementation */

struct filestore_key {
  /* Supported headers.  We don't really care about the Comment header
   * at the moment.
   */
  const char *subject;

  /* Key data */
  unsigned char *key_data;
  uint32_t key_datalen;
};

struct filestore_data {
  pr_fh_t *fh;
  const char *path;
  unsigned int lineno;
};

static const char *trace_channel = "ssh2";

/* This getline() function is quite similar to pr_fsio_getline(), except
 * that it a) enforces the 72-byte max line length from RFC4716, and b)
 * properly handles lines ending with CR, LF, or CRLF.
 *
 * Technically it allows one more byte than necessary, since the worst case
 * is 74 bytes (72 + CRLF); this also means 73 + CR or 73 + LF.  The extra
 * byte is for the terminating NUL.
 */
static char *filestore_getline(sftp_keystore_t *store, pool *p) {
  char linebuf[75], *line = "", *res;
  struct filestore_data *store_data = store->keystore_data;

  while (TRUE) {
    size_t linelen;

    pr_signals_handle();

    memset(&linebuf, '\0', sizeof(linebuf));
    res = pr_fsio_gets(linebuf, sizeof(linebuf) - 1, store_data->fh);

    if (res == NULL) {
      if (errno == EINTR) {
        continue;
      }

      pr_trace_msg(trace_channel, 10, "reached end of '%s', no matching "
        "key found", store_data->path);
      errno = EOF;
      return NULL;
    }

    linelen = strlen(linebuf);
    if (linelen >= 1) {
      if (linebuf[linelen - 1] == '\r' ||
          linebuf[linelen - 1] == '\n') {
        char *tmp;
        unsigned int header_taglen, header_valuelen;
        int have_line_continuation = FALSE;

        store_data->lineno++;

        linebuf[linelen - 1] = '\0';
        line = pstrcat(p, line, linebuf, NULL);

        if (line[strlen(line) - 1] == '\\') {
          have_line_continuation = TRUE;
          line[strlen(line) - 1] = '\0';
        }

        tmp = strchr(line, ':');
        if (tmp == NULL) {
          return line;
        } 

        /* We have a header.  Make sure the header tag is not longer than
         * the specified length of 64 bytes, and that the header value is
         * not longer than 1024 bytes.
         */
        header_taglen = tmp - line;
        if (header_taglen > 64) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "header tag too long (%u) on line %u of '%s'", header_taglen,
            store_data->lineno, store_data->path);
          errno = EINVAL;
          return NULL;
        }

        /* Header value starts at 2 after the ':' (one for the mandatory
         * space character.
         */
        header_valuelen = strlen(line) - (header_taglen + 2);
        if (header_valuelen > 1024) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "header value too long (%u) on line %u of '%s'", header_valuelen,
            store_data->lineno, store_data->path);
          errno = EINVAL;
          return NULL;
        }

        if (!have_line_continuation) {
          return line;
        }

        continue;

      } else if (linelen >= 2 &&
          linebuf[linelen - 2] == '\r' &&
          linebuf[linelen - 1] == '\n') {
        char *tmp;
        unsigned int header_taglen, header_valuelen;
        int have_line_continuation = FALSE;

        store_data->lineno++;

        linebuf[linelen - 2] = '\0';
        linebuf[linelen - 1] = '\0';
        line = pstrcat(p, line, linebuf, NULL);

        if (line[strlen(line) - 1] == '\\') {
          have_line_continuation = TRUE;
          line[strlen(line) - 1] = '\0';
        }

        tmp = strchr(line, ':');
        if (tmp == NULL) {
          return line;
        } 

        /* We have a header.  Make sure the header tag is not longer than
         * the specified length of 64 bytes, and that the header value is
         * not longer than 1024 bytes.
         */
        header_taglen = tmp - line;
        if (header_taglen > 64) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "header tag too long (%u) on line %u of '%s'", header_taglen,
            store_data->lineno, store_data->path);
          errno = EINVAL;
          return NULL;
        }

        /* Header value starts at 2 after the ':' (one for the mandatory
         * space character.
         */
        header_valuelen = strlen(line) - (header_taglen + 2);
        if (header_valuelen > 1024) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "header value too long (%u) on line %u of '%s'", header_valuelen,
            store_data->lineno, store_data->path);
          errno = EINVAL;
          return NULL;
        }

        if (!have_line_continuation) {
          return line;
        }

        continue;

      } else if (linelen < sizeof(linebuf)) {
        /* No CR or LF terminator; maybe a badly formatted file?  Try to
         * work with the data, if we can.
         */
        line = pstrcat(p, line, linebuf, NULL);
        return line;

      } else {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "line too long (%lu) on line %u of '%s'", (unsigned long) linelen,
          store_data->lineno, store_data->path);
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "Make sure that '%s' is a RFC4716 formatted key", store_data->path);
        errno = EINVAL;
        break;
      }
    }
  }

  return NULL;
}

static struct filestore_key *filestore_get_key(sftp_keystore_t *store,
    pool *p) {
  char *line;
  BIO *bio = NULL;
  struct filestore_key *key = NULL;
  struct filestore_data *store_data = store->keystore_data;
  size_t begin_markerlen = 0, end_markerlen = 0;

  line = filestore_getline(store, p);
  while (line == NULL &&
         errno == EINVAL) {
    line = filestore_getline(store, p);
  }

  begin_markerlen = strlen(SFTP_SSH2_PUBKEY_BEGIN_MARKER);
  end_markerlen = strlen(SFTP_SSH2_PUBKEY_END_MARKER);

  while (line) {
    pr_signals_handle();

    if (key == NULL &&
        strncmp(line, SFTP_SSH2_PUBKEY_BEGIN_MARKER,
        begin_markerlen + 1) == 0) {
      key = pcalloc(p, sizeof(struct filestore_key));
      bio = BIO_new(BIO_s_mem());

    } else if (key != NULL &&
               strncmp(line, SFTP_SSH2_PUBKEY_END_MARKER,
                 end_markerlen + 1) == 0) {
      if (bio) {
        BIO *b64 = NULL, *bmem = NULL;
        char chunk[1024], *data = NULL;
        int chunklen;
        long datalen = 0;

        /* Add a base64 filter BIO, and read the data out, thus base64-decoding
         * the key.  Write the decoded data into another memory BIO.
         */
        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);

        bmem = BIO_new(BIO_s_mem());

        memset(chunk, '\0', sizeof(chunk));
        chunklen = BIO_read(bio, chunk, sizeof(chunk));

        if (chunklen < 0 &&
            !BIO_should_retry(bio)) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "unable to base64-decode data in '%s': %s",
            store_data->path, sftp_crypto_get_errors());
          BIO_free_all(bio);
          BIO_free_all(bmem);

          errno = EPERM;
          return NULL;
        }

        while (chunklen > 0) {
          pr_signals_handle();

          if (BIO_write(bmem, chunk, chunklen) < 0) {
            (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
              "error writing to memory BIO: %s", sftp_crypto_get_errors());
            BIO_free_all(bio);
            BIO_free_all(bmem);

            errno = EPERM;
            return NULL;
          }

          memset(chunk, '\0', sizeof(chunk));
          chunklen = BIO_read(bio, chunk, sizeof(chunk));
        }

        datalen = BIO_get_mem_data(bmem, &data);

        if (data != NULL &&
            datalen > 0) {
          key->key_data = palloc(p, datalen);
          key->key_datalen = datalen;
          memcpy(key->key_data, data, datalen);

        } else {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error base64-decoding key data in '%s'", store_data->path);
        }

        BIO_free_all(bio);
        bio = NULL;

        BIO_free_all(bmem);
      }

      break;

    } else {
      if (key) {
        if (strstr(line, ": ") != NULL) {
          if (strncasecmp(line, "Subject: ", 9) == 0) {
            key->subject = pstrdup(p, line + 9);
          }

        } else {
          if (BIO_write(bio, line, strlen(line)) < 0) {
            (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
              "error buffering base64 data");
          }
        }
      }
    }

    line = filestore_getline(store, p);
    while (line == NULL &&
           errno == EINVAL) {
      line = filestore_getline(store, p);
    }
  }

  return key;
}

static int filestore_verify_host_key(sftp_keystore_t *store, pool *p,
    const char *user, const char *host_fqdn, const char *host_user,
    unsigned char *key_data, uint32_t key_len) {
  struct filestore_key *key = NULL;
  struct filestore_data *store_data = store->keystore_data;

  int res = -1;

  if (!store_data->path) {
    errno = EPERM;
    return -1;
  }

  /* XXX Note that this will scan the file from the beginning, each time.
   * There's room for improvement; perhaps mmap() the file into memory?
   */

  key = filestore_get_key(store, p);
  while (key) {
    int ok;

    pr_signals_handle();

    ok = sftp_keys_compare_keys(p, key_data, key_len, key->key_data,
      key->key_datalen);
    if (ok != TRUE) {
      if (ok == -1) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error comparing keys from '%s': %s", store_data->path,
          strerror(errno));
      }

    } else {

      /* XXX Verify that the user and the host_user match?? */

      res = 0;
      break;
    }

    key = filestore_get_key(store, p);
  }

  if (res == 0) {
    pr_trace_msg(trace_channel, 10, "found matching public key for host '%s' "
      "in '%s'", host_fqdn, store_data->path);
  }

  if (pr_fsio_lseek(store_data->fh, 0, SEEK_SET) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error seeking to start of '%s': %s", store_data->path, strerror(errno));
    return -1;
  }

  store_data->lineno = 0;
  return res;
}

static int filestore_verify_user_key(sftp_keystore_t *store, pool *p,
    const char *user, unsigned char *key_data, uint32_t key_len) {
  struct filestore_key *key = NULL;
  struct filestore_data *store_data = store->keystore_data;
  unsigned int count = 0;

  int res = -1;

  if (!store_data->path) {
    errno = EPERM;
    return -1;
  }

  /* XXX Note that this will scan the file from the beginning, each time.
   * There's room for improvement; perhaps mmap() the file into memory?
   */

  key = filestore_get_key(store, p);
  while (key) {
    int ok;

    pr_signals_handle();
    count++;

    ok = sftp_keys_compare_keys(p, key_data, key_len, key->key_data,
      key->key_datalen);
    if (ok != TRUE) {
      if (ok == -1) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error comparing keys from '%s': %s", store_data->path,
          strerror(errno));

      } else {
        pr_trace_msg(trace_channel, 10,
          "failed to match key #%u from file '%s'", count, store_data->path);
      }

    } else {
      /* If we are configured to check for Subject headers, and if the file key
       * has a Subject header, and that header value does not match the
       * logging in user, then continue looking.
       */
      if ((sftp_opts & SFTP_OPT_MATCH_KEY_SUBJECT) &&
          key->subject != NULL) {
        if (strcmp(key->subject, user) != 0) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "found matching key for user '%s' in '%s', but Subject "
            "header ('%s') does not match, skipping key", user,
            store_data->path, key->subject);

        } else {
          res = 0;
          break;
        }

      } else {
        res = 0;
        break;
      }
    }

    key = filestore_get_key(store, p);
  }

  if (res == 0) {
    pr_trace_msg(trace_channel, 10, "found matching public key for user '%s' "
      "in '%s'", user, store_data->path);
  }

  if (pr_fsio_lseek(store_data->fh, 0, SEEK_SET) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error seeking to start of '%s': %s", store_data->path, strerror(errno));
    return -1;
  }

  store_data->lineno = 0;
  return res;
}

static int filestore_close(sftp_keystore_t *store) {
  struct filestore_data *store_data = store->keystore_data;

  pr_fsio_close(store_data->fh);
  return 0;
}

static sftp_keystore_t *filestore_open(pool *parent_pool,
    int requested_key_type, const char *store_info, const char *user) {
  int xerrno;
  sftp_keystore_t *store;
  pool *filestore_pool;
  struct filestore_data *store_data;
  pr_fh_t *fh;
  char buf[PR_TUNABLE_PATH_MAX+1], *path;
  struct stat st;

  filestore_pool = make_sub_pool(parent_pool);
  pr_pool_tag(filestore_pool, "SFTP File-based Keystore Pool");

  store = pcalloc(filestore_pool, sizeof(sftp_keystore_t));
  store->keystore_pool = filestore_pool;

  /* Open the file.  The given path (store_info) may need to be
   * interpolated.
   */
  session.user = (char *) user;

  memset(buf, '\0', sizeof(buf));
  switch (pr_fs_interpolate(store_info, buf, sizeof(buf)-1)) {
    case 1:
      /* Interpolate occurred; make a copy of the interpolated path. */
      path = pstrdup(filestore_pool, buf);
      break;

    default:
      /* Otherwise, use the path as is. */
      path = pstrdup(filestore_pool, store_info);
      break;
  }

  session.user = NULL;

  PRIVS_ROOT
  fh = pr_fsio_open(path, O_RDONLY|O_NONBLOCK);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (fh == NULL) {
    destroy_pool(filestore_pool);
    errno = xerrno;
    return NULL;
  }

  if (pr_fsio_set_block(fh) < 0) {
   xerrno = errno;

    destroy_pool(filestore_pool);
    (void) pr_fsio_close(fh);

    errno = xerrno;
    return NULL;
  }

  /* Stat the opened file to determine the optimal buffer size for IO. */
  memset(&st, 0, sizeof(st));
  if (pr_fsio_fstat(fh, &st) < 0) {
    xerrno = errno;

    destroy_pool(filestore_pool);
    (void) pr_fsio_close(fh);

    errno = xerrno;
    return NULL;
  }

  if (S_ISDIR(st.st_mode)) {
    destroy_pool(filestore_pool);
    (void) pr_fsio_close(fh);

    errno = EISDIR;
    return NULL;
  }

  fh->fh_iosz = st.st_blksize;

  store_data = pcalloc(filestore_pool, sizeof(struct filestore_data));
  store->keystore_data = store_data;

  store_data->path = path;
  store_data->fh = fh;
  store_data->lineno = 0;

  store->store_ktypes = requested_key_type;

  switch (requested_key_type) {
    case SFTP_SSH2_HOST_KEY_STORE:
      store->verify_host_key = filestore_verify_host_key;
      break;

    case SFTP_SSH2_USER_KEY_STORE:
      store->verify_user_key = filestore_verify_user_key; 
      break;
  }

  store->store_close = filestore_close;
  return store;
}

int sftp_rfc4716_init(void) {
  sftp_keystore_register_store("file", filestore_open,
    SFTP_SSH2_HOST_KEY_STORE|SFTP_SSH2_USER_KEY_STORE);

  return 0;
}

int sftp_rfc4716_free(void) {
  sftp_keystore_unregister_store("file",
    SFTP_SSH2_HOST_KEY_STORE|SFTP_SSH2_USER_KEY_STORE);

  return 0;
}
