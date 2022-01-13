/*
 * ProFTPD: mod_deflate -- a module for supporting on-the-fly compression
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
 * This is mod_deflate, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 *
 * $Libraries: -lz$
 */

#include <zlib.h>

#include "conf.h"
#include "privs.h"

#define MOD_DEFLATE_VERSION		"mod_deflate/0.6"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030604
# error "ProFTPD 1.3.6 or later required"
#endif

module deflate_module;

static int deflate_sess_init(void);

static int deflate_enabled = FALSE;
static int deflate_engine = FALSE;
static int deflate_logfd = -1;
static pr_netio_t *deflate_netio = NULL;
static pr_netio_t *deflate_next_netio = NULL;

/* These are for tracking the callbacks of the next NetIO, if any, that we
 * override, for restoring later via OPTS.
 */
static int (*deflate_next_netio_close)(pr_netio_stream_t *) = NULL;
static pr_netio_stream_t *(*deflate_next_netio_open)(pr_netio_stream_t *, int, int) = NULL;
static int (*deflate_next_netio_read)(pr_netio_stream_t *, char *, size_t) = NULL;
static int (*deflate_next_netio_shutdown)(pr_netio_stream_t *, int) = NULL;
static int (*deflate_next_netio_write)(pr_netio_stream_t *, char *, size_t) = NULL;

/* Draft-recommended ZLIB defaults:
 *
 *  The following ZLIB [5] parameters are recommended for deflate
 *  transmission mode:
 *
 *     Compression level:   7
 *     Compression method:  Z_DEFLATED
 *     Window bits:         -15
 *     Memory level:        8
 *     Strategy:            Z_DEFAULT_STRATEGY
 */

#define MOD_DEFLATE_DEFAULT_COMPRESS_LEVEL		7
static int deflate_compression_level = MOD_DEFLATE_DEFAULT_COMPRESS_LEVEL;

#define MOD_DEFLATE_DEFAULT_MEM_LEVEL			8
static int deflate_mem_level = MOD_DEFLATE_DEFAULT_MEM_LEVEL;

#define MOD_DEFLATE_DEFAULT_STRATEGY			Z_DEFAULT_STRATEGY
static int deflate_strategy = MOD_DEFLATE_DEFAULT_STRATEGY;

#define MOD_DEFLATE_DEFAULT_WINDOW_BITS			15
static int deflate_window_bits = MOD_DEFLATE_DEFAULT_WINDOW_BITS;

/* The _ptr pointer always points to the start of the buffer; the _zbuf
 * pointer points to the current place within the buffer from which to read
 * data.
 */
static Byte *deflate_zbuf_ptr = NULL;
static Byte *deflate_zbuf = NULL;
static size_t deflate_zbuflen = 0;
static size_t deflate_zbufsz = 0;

static Byte *deflate_rbuf = NULL;
static size_t deflate_rbuflen = 0;
static size_t deflate_rbufsz = 0;

#define DEFLATE_NETIO_NOTE	"mod_deflate.z_stream"
static int deflate_zerrno = 0;

static const char *trace_channel = "deflate";

static const char *deflate_zstrerror(int zerrno) {
  const char *zstr = "unknown";

  switch (zerrno) {
    case Z_OK:
      zstr = "OK";
      break;

    case Z_STREAM_END:
      return "End of stream";
      break;

    case Z_NEED_DICT:
      return "Need dictionary";
      break;

    case Z_ERRNO:
      zstr = strerror(errno);
      break;

    case Z_DATA_ERROR:
      zstr = "Data error";
      break;

    case Z_MEM_ERROR:
      zstr = "Memory error";
      break;

    case Z_BUF_ERROR:
      zstr = "Buffer error";
      break;

    case Z_VERSION_ERROR:
      zstr = "Version error";
      break;
  }

  return zstr;
}

/* NetIO callbacks
 */

static int deflate_netio_close_cb(pr_netio_stream_t *nstrm) {
  int res = 0;

  if (nstrm->strm_type == PR_NETIO_STRM_DATA) {
    z_stream *zstrm;

    zstrm = (z_stream *) pr_table_get(nstrm->notes, DEFLATE_NETIO_NOTE, NULL);
    if (zstrm == NULL) {
      int xerrno = 0;

      res = 0;

      if (deflate_next_netio_close != NULL) {
        res = (deflate_next_netio_close)(nstrm);
        xerrno = errno;

        if (res < 0) {
          pr_trace_msg(trace_channel, 1, "error calling next netio close: %s",
            strerror(xerrno));
        }
      }

      errno = xerrno;
      return res;
    }

    if (nstrm->strm_mode == PR_NETIO_IO_WR) {
      if (zstrm->total_in > 0) {
        float ratio;

        ratio = ((float) zstrm->total_out / (float) zstrm->total_in);

        (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
          "%s: deflated %lu bytes to %lu bytes (%0.2lf%% compression)",
          session.curr_cmd, zstrm->total_in, zstrm->total_out,
          (1.0 - ratio) * 100.0);
      }

      res = deflateEnd(zstrm);
      if (res != Z_OK) {
        pr_trace_msg(trace_channel, 3,
          "close: error closing deflating netio: [%d] %s", res,
          zstrm->msg ? zstrm->msg : deflate_zstrerror(res));

        (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
          "error closing deflating netio: [%d] %s", res,
          zstrm->msg ? zstrm->msg : deflate_zstrerror(res));
      }

    } else if (nstrm->strm_mode == PR_NETIO_IO_RD) {
      if (zstrm->total_in > 0) {
        float ratio;

        ratio = ((float) zstrm->total_in / (float) zstrm->total_out);

        (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
          "%s: inflated %lu bytes to %lu bytes (%0.2lf%% compression)",
          session.curr_cmd, zstrm->total_in, zstrm->total_out,
          (1.0 - ratio) * 100.0);
      }

      res = inflateEnd(zstrm);
      if (res != Z_OK) {
        pr_trace_msg(trace_channel, 3,
          "close: error closing inflating netio: [%d] %s", res,
          zstrm->msg ? zstrm->msg : deflate_zstrerror(res));

        (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
          "error closing inflating netio: [%d] %s", res,
          zstrm->msg ? zstrm->msg : deflate_zstrerror(res));
      }
    }

    if (deflate_next_netio == NULL) {
      res = close(nstrm->strm_fd);
      nstrm->strm_fd = -1;
    }

    pr_table_remove(nstrm->notes, DEFLATE_NETIO_NOTE, NULL);
  }

  if (deflate_next_netio_close != NULL) {
    if ((deflate_next_netio_close)(nstrm) < 0) {
      pr_trace_msg(trace_channel, 1, "error calling next netio close: %s",
        strerror(errno));
    }
  }

  return res;
}

static pr_netio_stream_t *deflate_netio_open_cb(pr_netio_stream_t *nstrm,
    int fd, int mode) {

  nstrm->strm_fd = fd;
  nstrm->strm_mode = mode;

  if (deflate_next_netio_open != NULL) {
    if ((deflate_next_netio_open)(nstrm, fd, mode) == NULL) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 1, "error calling next netio open: %s",
        strerror(xerrno));
      errno = xerrno;
      return NULL;
    }
  }

  if (nstrm->strm_type == PR_NETIO_STRM_DATA) {
    int res;
    z_stream *zstrm;

    /* Set the initial ZLIB parameters. */
    zstrm = pcalloc(nstrm->strm_pool, sizeof(z_stream));
    zstrm->zalloc = Z_NULL;
    zstrm->zfree = Z_NULL;
    zstrm->opaque = Z_NULL;
    zstrm->next_in = Z_NULL;
    zstrm->next_out = Z_NULL;
    zstrm->avail_in = 0;
    zstrm->avail_out = 0;

    if (pr_table_add(nstrm->notes,
        pstrdup(nstrm->strm_pool, DEFLATE_NETIO_NOTE), zstrm,
        sizeof(z_stream *)) < 0) {
      if (errno != EEXIST) {
        (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
          "error stashing '%s' note: %s", DEFLATE_NETIO_NOTE, strerror(errno));
      }
    }

    memset(deflate_zbuf_ptr, '\0', deflate_zbufsz);
    deflate_zbuf = deflate_zbuf_ptr;

    if (nstrm->strm_mode == PR_NETIO_IO_WR) {
      /* Initialize the zlib data for deflation. */
      res = deflateInit2(zstrm, deflate_compression_level, Z_DEFLATED,
        deflate_window_bits, deflate_mem_level, deflate_strategy);

      switch (res) {
        case Z_OK:
          zstrm->next_out = deflate_zbuf;
          zstrm->avail_out = deflate_zbufsz;
          break;

        case Z_MEM_ERROR:
        case Z_STREAM_ERROR:
          pr_trace_msg(trace_channel, 3,
            "open: error initializing for deflation: [%d] %s", res,
            zstrm->msg ? zstrm->msg : deflate_zstrerror(res));

          (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
            "error initializing for deflation: [%d] %s", res,
            zstrm->msg ? zstrm->msg : deflate_zstrerror(res));

          errno = EINVAL;
          return NULL;
      }

    } else if (nstrm->strm_mode == PR_NETIO_IO_RD) {
      /* Initialize the zlib data for inflation.
       *
       * The magic number 32 here from the zlib.h documentation; it enables
       * the automatic header detection of zlib/gzip headers.
       */
      res = inflateInit2(zstrm, deflate_window_bits + 32);

      switch (res) {
        case Z_OK:
          zstrm->next_out = deflate_zbuf;
          zstrm->avail_out = deflate_zbufsz;
          break;

        case Z_MEM_ERROR:
        case Z_STREAM_ERROR:
          pr_trace_msg(trace_channel, 3,
            "open: error initializing for inflation: [%d] %s", res,
            zstrm->msg ? zstrm->msg : deflate_zstrerror(res));

          (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
            "error initializing for inflation: [%d] %s", res, 
            zstrm->msg ? zstrm->msg : deflate_zstrerror(res));

          errno = EINVAL;
          return NULL;
      }

      /* These are used by the read callback; ensure they are initialised to
       * zero before every read data transfer.
       */
      deflate_rbuflen = 0;
      deflate_zbuflen = 0;
    }
  }

  return nstrm;
}

static int deflate_netio_read_cb(pr_netio_stream_t *nstrm, char *buf,
    size_t bufsz) {

  if (bufsz == 0) {
    return 0;
  }

  if (nstrm->strm_type == PR_NETIO_STRM_DATA) {
    int datalen = 0, nread = 0, res, xerrno;
    size_t copylen = 0;
    z_stream *zstrm;

    zstrm = (z_stream *) pr_table_get(nstrm->notes, DEFLATE_NETIO_NOTE, NULL);
    if (zstrm == NULL) {
      pr_trace_msg(trace_channel, 2,
        "no zstream found in stream data for reading");
      errno = EIO;
      return -1;
    }

    res = 0;

    /* If we have data leftover in deflate_zbuf, start by copying all of that
     * into the provided buffer.  Only read more data from the network and
     * inflate it when there's no leftover data.
     */

    if (deflate_zbuflen > 0) {
      if (bufsz >= deflate_zbuflen) {
        /* Excellent.  We can consume all of the data in the deflate_zbuf
         * buffer.
         */

        pr_trace_msg(trace_channel, 9, "read: returning %lu bytes of "
          "previously uncompressed data; no data read from client",
          (unsigned long) deflate_zbuflen);

        memcpy(buf, deflate_zbuf, deflate_zbuflen);
        res = deflate_zbuflen;

        /* Reset the pointer to the start of the buffer. */
        deflate_zbuf = deflate_zbuf_ptr;
        deflate_zbuflen = 0;

        /* Manually adjust the "raw" bytes in counter, so that it will
         * be accurate for %I logging.
         *
         * We subtract the number we are returning here, since our return
         * value will simply be added back to the counter in pr_netio_read().
         * And if our subtraction causes an underflow, it's still OK since
         * the subsequent addition will overflow, and get the value back to
         * what it should be.
         */
        session.total_raw_in -= res;

        return res;
      }

      /* The given buffer can't hold all of our already-inflated data; but
       * maybe it can hold some of it?
       */

      pr_trace_msg(trace_channel, 9, "read: returning %lu bytes of previously "
        "uncompressed data (of %lu bytes total); no data read from client",
        (unsigned long) bufsz, (unsigned long) deflate_zbuflen);

      memcpy(buf, deflate_zbuf, bufsz);
      res = bufsz;

      deflate_zbuf += bufsz;
      deflate_zbuflen -= bufsz;

      /* Manually adjust the "raw" bytes in counter, so that it will
       * be accurate for %I logging.
       *
       * We subtract the number we are returning here, since our return
       * value will simply be added back to the counter in pr_netio_read().
       * And if our subtraction causes an underflow, it's still OK since
       * the subsequent addition will overflow, and get the value back to
       * what it should be.
       */
      session.total_raw_in -= res;

      return res;
    }

    /* If we reach this point, then the deflate_zbuf buffer is empty of
     * uncompressed data.  We might have some compressed data left over from
     * the previous inflate() call that we need to process
     * (i.e. zstrm->avail_in > 0), though.
     *
     * Try to read more deta in from the network.  If we get no data, AND
     * zstrm->avail_in is zero, then we've reached EOF.  Otherwise, add the
     * new data to the inflator, and see if we can make some progress.
     */

    datalen = deflate_rbufsz - deflate_rbuflen;

    if (deflate_next_netio_read != NULL) {
      nread = (deflate_next_netio_read)(nstrm, (char *) deflate_rbuf, datalen);

    } else {
      /* Read in some data from the stream's fd. */
      nread = read(nstrm->strm_fd, deflate_rbuf, datalen);
    }

    if (nread < 0) {
      xerrno = errno;

      (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
        "error reading from socket %d: %s", nstrm->strm_fd, strerror(xerrno));

      errno = xerrno;
      return -1;
    }

    if (nread == 0) {
      if (zstrm->avail_in == 0) {
        /* EOF.  We know we can return zero here because the deflate_zbuf
         * is empty (see above comment), and we haven't read any more data
         * in from the network.
         */
        pr_trace_msg(trace_channel, 8,
          "read: read EOF from client, returning 0");
        return 0;
      }
    }

    pr_trace_msg(trace_channel, 9,
      "read: read %d bytes of compressed data from client", nread);

    /* Manually adjust the "raw" bytes in counter, so that it will
     * be accurate for %I logging.
     */
    session.total_raw_in += nread;

    if (zstrm->avail_in > 0) {
      pr_trace_msg(trace_channel, 9,
        "read: processing %d bytes of leftover compressed data from client, "
        "plus %d additional new bytes from client", zstrm->avail_in, nread);

    } else {
      pr_trace_msg(trace_channel, 9, "read: processing %d bytes from client",
        nread);
    }

    datalen = nread;
    zstrm->next_in = deflate_rbuf;
    zstrm->avail_in += datalen;

    copylen = 0;

    zstrm->next_out = deflate_zbuf;
    zstrm->avail_out = deflate_zbufsz;

    pr_trace_msg(trace_channel, 19,
      "read: pre-inflate zstream state: avail_in = %d, avail_out = %d",
      zstrm->avail_in, zstrm->avail_out);

    deflate_zerrno = inflate(zstrm, Z_SYNC_FLUSH);
    xerrno = errno;

    pr_trace_msg(trace_channel, 19,
      "read: post-inflate zstream state: avail_in = %d, avail_out = %d "
      "(zerrno = %s)", zstrm->avail_in, zstrm->avail_out,
      deflate_zstrerror(deflate_zerrno));

    errno = xerrno;

    switch (deflate_zerrno) {
      case Z_OK:
      case Z_STREAM_END:
        copylen = deflate_zbufsz - zstrm->avail_out;

        /* Allocate more space for the data if necessary. */
        if ((deflate_zbuflen + copylen) > deflate_zbufsz) {
          size_t new_bufsz;
          Byte *tmp;

          new_bufsz = deflate_zbufsz;
          while ((deflate_zbuflen + copylen) > new_bufsz) {
            pr_signals_handle();
            new_bufsz *= 2;
          }

          pr_trace_msg(trace_channel, 9,
            "read: allocated new deflate buffer (size %lu)",
            (unsigned long) new_bufsz);

          tmp = palloc(session.pool, new_bufsz);
          memcpy(tmp, deflate_zbuf, deflate_zbuflen);

          deflate_zbuf_ptr = deflate_zbuf = tmp;
          deflate_zbufsz = new_bufsz;
        } 

        break;

      default:
        pr_trace_msg(trace_channel, 3,
          "read: error inflating %lu bytes of data: [%d] %s: %s",
          (unsigned long) datalen, deflate_zerrno,
          deflate_zstrerror(deflate_zerrno),
          zstrm->msg ? zstrm->msg : "unavailable");

        errno = xerrno;
        (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
          "error inflating %lu bytes of data: [%d] %s",
          (unsigned long) datalen, deflate_zerrno,
          zstrm->msg ? zstrm->msg : deflate_zstrerror(deflate_zerrno));

        errno = EIO;
        return -1;
    }

    deflate_zbuflen = deflate_zbufsz - zstrm->avail_out;

    /* Now all we have to do is return EAGAIN, so that the FSIO API calls
     * us back immediately.  That will hit the check for deflate_zbuflen
     * earlier in this function, and return the data we just decompressed.
     */
    errno = EAGAIN;
    return -1;
  }

  return read(nstrm->strm_fd, buf, bufsz);
}

static int deflate_netio_shutdown_cb(pr_netio_stream_t *nstrm, int how) {

  if (nstrm->strm_type == PR_NETIO_STRM_DATA) {
    int res = 0;
    z_stream *zstrm;

    zstrm = (z_stream *) pr_table_get(nstrm->notes, DEFLATE_NETIO_NOTE, NULL);
    if (zstrm == NULL) {
      return 0;
    }

    if (nstrm->strm_mode == PR_NETIO_IO_WR) {
      zstrm->next_in = Z_NULL;
      zstrm->avail_in = 0;

      pr_trace_msg(trace_channel, 19,
        "shutdown: pre-deflate zstream state: avail_in = %d, avail_out = %d",
        zstrm->avail_in, zstrm->avail_out);

      deflate_zerrno = deflate(zstrm, Z_FINISH);

      pr_trace_msg(trace_channel, 19,
        "shutdown: post-inflate zstream state: avail_in = %d, avail_out = %d "
        "(zerrno = %s)", zstrm->avail_in, zstrm->avail_out,
        deflate_zstrerror(deflate_zerrno));

      if (deflate_zerrno != Z_OK &&
          deflate_zerrno != Z_STREAM_END) {
        pr_trace_msg(trace_channel, 3,
          "shutdown: error deflating data: [%d] %s: %s", deflate_zerrno,
          deflate_zstrerror(deflate_zerrno),
          zstrm->msg ? zstrm->msg : "unavailable");

        (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
          "error deflating data: [%d] %s", deflate_zerrno,
          zstrm->msg ? zstrm->msg : deflate_zstrerror(deflate_zerrno));

      } else {
        size_t datalen, offset;

        datalen = deflate_zbufsz - zstrm->avail_out;
        offset = 0;

        while (datalen > 0) {
          if (deflate_next_netio_write != NULL) {
            res = (deflate_next_netio_write)(nstrm,
              (char *) (deflate_zbuf + offset), datalen);

          } else {
            res = write(nstrm->strm_fd, deflate_zbuf + offset, datalen);
          }

          if (res < 0) {
            if (errno == EINTR ||
                errno == EAGAIN) {
              /* The socket might be busy, especially if the peer is a bit
               * slow in reading data from it.
               */
              pr_signals_handle();
              continue;
            }

            (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
              "error writing to socket %d: %s", nstrm->strm_fd,
              strerror(errno));
            return -1;
          }

          /* Manually update the "raw" bytes counter, so that it will be
           * accurate for %O logging.
           */
          session.total_raw_out += res;

          /* Watch out for short writes. */
          if ((size_t) res == datalen) {
            break;
          }

          offset += res;
          datalen -= res;
        }
      }

      if (deflate_next_netio_shutdown != NULL) {
        res = (deflate_next_netio_shutdown)(nstrm, how);

      } else {
        res = shutdown(nstrm->strm_fd, how);
      }

      return res;
    }
  }

  return shutdown(nstrm->strm_fd, how);
}

static int deflate_netio_write_cb(pr_netio_stream_t *nstrm, char *buf,
    size_t buflen) {

  if (buflen == 0) {
    return 0;
  }

  if (nstrm->strm_type == PR_NETIO_STRM_DATA) {
    int res = 0, xerrno;
    size_t datalen, offset = 0;
    z_stream *zstrm;

    zstrm = (z_stream *) pr_table_get(nstrm->notes, DEFLATE_NETIO_NOTE, NULL);
    if (zstrm == NULL) {
      pr_trace_msg(trace_channel, 2,
        "no zstream found in stream data for writing");
      errno = EIO;
      return -1;
    }

    /* Deflate the data to be written out. */
    zstrm->next_in = (Bytef *) buf;
    zstrm->avail_in = buflen;

    pr_trace_msg(trace_channel, 19,
      "write: pre-deflate zstream state: avail_in = %d, avail_out = %d",
      zstrm->avail_in, zstrm->avail_out);

    deflate_zerrno = deflate(zstrm, Z_SYNC_FLUSH);
    xerrno = errno;

    pr_trace_msg(trace_channel, 19,
      "write: post-inflate zstream state: avail_in = %d, avail_out = %d "
      "(zerrno = %s)", zstrm->avail_in, zstrm->avail_out,
      deflate_zstrerror(deflate_zerrno));

    errno = xerrno;

    if (deflate_zerrno != Z_OK) {
      pr_trace_msg(trace_channel, 3, "write: error deflating data: [%d] %s: %s",
        deflate_zerrno, deflate_zstrerror(deflate_zerrno),
        zstrm->msg ? zstrm->msg : "unavailable");

      errno = xerrno;

      (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
        "error deflating data: [%d] %s", deflate_zerrno,
        zstrm->msg ? zstrm->msg : deflate_zstrerror(deflate_zerrno));

      errno = EIO;
      return -1;
    }

    datalen = deflate_zbufsz - zstrm->avail_out;

    while (datalen > 0) {
      pr_signals_handle();

      if (deflate_next_netio_write != NULL) {
        res = (deflate_next_netio_write)(nstrm,
          (char *) (deflate_zbuf + offset), datalen);

      } else {
        res = write(nstrm->strm_fd, deflate_zbuf + offset, datalen);
      }

      if (res < 0) {
        if (errno == EINTR ||
            errno == EAGAIN) {
          /* The socket might be busy, especially if the peer is a bit
           * slow in reading data from it.
           */
          pr_signals_handle();
          continue;
        }

        (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
          "error writing to socket %d: %s", nstrm->strm_fd, strerror(errno));
        return -1;
      }

      /* Manually adjust the "raw" bytes counter, so that it will be
       * accurate for %O logging.
       */
      session.total_raw_out += res;

      (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
        "wrote %d (of %lu) bytes of compressed of data to socket %d", res,
        (unsigned long) datalen, nstrm->strm_fd);

      /* Watch out for short writes */
      if ((size_t) res == datalen) {
        zstrm->next_out = deflate_zbuf;
        zstrm->avail_out = deflate_zbufsz;
        break;

      } else {
        offset += res;
        datalen -= res;
      }
    }

    /* Manually adjust the "raw" bytes in counter, so that it will
     * be accurate for %O logging.
     *
     * We subtract the number we are returning here, since our return
     * value will simply be added back to the counter in pr_netio_write().
     * And if our subtraction causes an underflow, it's still OK since
     * the subsequent addition will overflow, and get the value back to
     * what it should be.
     */

    res = (buflen - zstrm->avail_in);
    session.total_raw_out -= res;

    pr_trace_msg(trace_channel, 9, "write: returning %d for %lu bytes",
      res, (unsigned long) buflen);
    return res;
  }

  return write(nstrm->strm_fd, buf, buflen);
}

/* Configuration handlers
 */

/* usage: DeflateEngine on|off */
MODRET set_deflateengine(cmd_rec *cmd) {
  int bool;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: DeflateLog path|"none" */
MODRET set_deflatelog(cmd_rec *cmd) {
  char *path;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  path = cmd->argv[1];
  if (pr_fs_valid_path(path) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": ", path, " is not a valid path",
      NULL));
  }

  add_config_param_str(cmd->argv[0], 1, path);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET deflate_opts(cmd_rec *cmd) {
  if (deflate_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (cmd->argc < 3) {
    return PR_DECLINED(cmd);
  }

  if (strcasecmp(cmd->argv[1], "Z") == 0) {

    /* Twiddle the requested ZLIB parameters. */

    if (cmd->argc == 3) {
      /* If no key/value pairs were given, reset the deflate parameters
       * to their default settings.
       */
      deflate_compression_level = MOD_DEFLATE_DEFAULT_COMPRESS_LEVEL;
      deflate_mem_level = MOD_DEFLATE_DEFAULT_MEM_LEVEL;
      deflate_strategy = MOD_DEFLATE_DEFAULT_STRATEGY;
      deflate_window_bits = MOD_DEFLATE_DEFAULT_WINDOW_BITS;

      pr_response_add(R_200, _("%s OK"), (char *) cmd->argv[0]);
      return PR_HANDLED(cmd);

    } else {
      register unsigned int i;

      if (cmd->argc % 2 != 0) {
        pr_response_add_err(R_501, _("Bad number of parameters"));

        pr_cmd_set_errno(cmd, EINVAL);
        errno = EINVAL;
        return PR_ERROR(cmd);
      }

      for (i = 2; i < cmd->argc; i += 2) {
        char *key, *val;

        key = cmd->argv[i];
        val = cmd->argv[i+1];

        if (strcasecmp(key, "blocksize") == 0 ||
            strcasecmp(key, "engine") == 0) {
          pr_response_add_err(R_501, _("%s: unsupported MODE Z option: %s"),
            (char *) cmd->argv[0], key);

          pr_cmd_set_errno(cmd, ENOSYS);
          errno = ENOSYS;
          return PR_ERROR(cmd);

        } else if (strcasecmp(key, "level") == 0) {
          int level;

          level = atoi(val);
          if (level < 0 ||
              level > 9) {
            pr_response_add_err(R_501, _("%s: bad MODE Z option value: %s %s"),
              (char *) cmd->argv[0], key, val);

            pr_cmd_set_errno(cmd, EINVAL);
            errno = EINVAL;
            return PR_ERROR(cmd);
          }

          deflate_compression_level = level;

        } else {
          pr_response_add_err(R_501, _("%s: unknown MODE Z option: %s"),
            (char *) cmd->argv[0], key);

          pr_cmd_set_errno(cmd, EINVAL);
          errno = EINVAL;
          return PR_ERROR(cmd);
        }
      }
    }

    pr_response_add(R_200, _("OPTS MODE Z OK"));
    return PR_HANDLED(cmd);
  }

  return PR_DECLINED(cmd);
}

MODRET deflate_mode(cmd_rec *cmd) {
  char *mode;

  if (deflate_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (cmd->argc != 2) {
    (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
      "declining MODE Z (wrong number of parameters: %d)", cmd->argc);
    return PR_DECLINED(cmd);
  }

  mode = cmd->argv[1];
  mode[0] = toupper(mode[0]);

  if (mode[0] == 'Z') {
    if (session.rfc2228_mech != NULL) {
      if (strcasecmp(session.rfc2228_mech, "tls") != 0) {
        (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
          "declining MODE Z (RFC2228 mechanism '%s' in effect)",
          session.rfc2228_mech);
        pr_log_debug(DEBUG2, MOD_DEFLATE_VERSION
          ": declining MODE Z (RFC2228 mechanism '%s' in effect)",
          session.rfc2228_mech);

        pr_response_add_err(R_504, _("Unable to handle MODE Z at this time"));

        pr_cmd_set_errno(cmd, EPERM);
        errno = EPERM;
        return PR_ERROR(cmd);
      }
    }

    if (deflate_enabled == TRUE) {
      pr_response_add(R_200, _("OK"));
      return PR_HANDLED(cmd);
    }

    deflate_next_netio = pr_get_netio(PR_NETIO_STRM_DATA);
    if (deflate_next_netio != NULL) {
      /* If another module has registered a NetIO callback already (e.g.
       * mod_tls), we want to leave it in place, but replace some (but not all)
       * of its callbacks with our own.
       *
       * We cache copies/pointers of the original callbacks, for restoring
       * later if requested.
       */
      pr_trace_msg(trace_channel, 9, "overriding existing %s NetIO callbacks",
        deflate_next_netio->owner_name? deflate_next_netio->owner_name :
        deflate_next_netio->owner->name);

      deflate_next_netio_close = deflate_next_netio->close;
      deflate_next_netio->close = deflate_netio_close_cb;

      deflate_next_netio_open = deflate_next_netio->open;
      deflate_next_netio->open = deflate_netio_open_cb;

      deflate_next_netio_read = deflate_next_netio->read;
      deflate_next_netio->read = deflate_netio_read_cb;

      deflate_next_netio_shutdown = deflate_next_netio->shutdown;
      deflate_next_netio->shutdown = deflate_netio_shutdown_cb;

      deflate_next_netio_write = deflate_next_netio->write;
      deflate_next_netio->write = deflate_netio_write_cb;

    } else {
      /* Need to install some sort of NetIO handlers here, to handle
       * compression.
       */
      deflate_netio = pr_alloc_netio2(session.pool, &deflate_module, NULL);
      deflate_netio->close = deflate_netio_close_cb;
      deflate_netio->open = deflate_netio_open_cb;
      deflate_netio->read = deflate_netio_read_cb;
      deflate_netio->shutdown = deflate_netio_shutdown_cb;
      deflate_netio->write = deflate_netio_write_cb;

      if (pr_register_netio(deflate_netio, PR_NETIO_STRM_DATA) < 0) {
        (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
          "error registering netio: %s", strerror(errno));
      }
    }

    deflate_enabled = TRUE;

    pr_response_add(R_200, _("OK"));
    return PR_HANDLED(cmd);

  } else {
    if (deflate_enabled) {
      /* Switch to some other transmission mode.  Remove our NetIO. */

      if (deflate_next_netio != NULL) {
        deflate_next_netio->close = deflate_next_netio_close;
        deflate_next_netio_close = NULL;

        deflate_next_netio->open = deflate_next_netio_open;
        deflate_next_netio_open = NULL;

        deflate_next_netio->read = deflate_next_netio_read;
        deflate_next_netio_read = NULL;

        deflate_next_netio->shutdown = deflate_next_netio_shutdown;
        deflate_next_netio_shutdown = NULL;

        deflate_next_netio->write = deflate_next_netio_write;
        deflate_next_netio_write = NULL;

        deflate_next_netio = NULL;

      } else {
        if (pr_unregister_netio(PR_NETIO_STRM_DATA) < 0) {
          (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
            "error unregistering netio: %s", strerror(errno));

        } else {
          (void) pr_log_writefile(deflate_logfd, MOD_DEFLATE_VERSION,
            "%s %s: unregistered netio", (char *) cmd->argv[0],
            (char *) cmd->argv[1]);
        }

        if (deflate_netio != NULL) {
          destroy_pool(deflate_netio->pool);
          deflate_netio = NULL;
        }
      }

      deflate_enabled = FALSE;
    }
  }

  return PR_DECLINED(cmd);
}

/* Event listeners
 */

static void deflate_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&deflate_module, "core.session-reinit",
    deflate_sess_reinit_ev);

  deflate_engine = FALSE;
  pr_feat_remove("MODE Z");
  (void) close(deflate_logfd);
  deflate_logfd = -1;

  res = deflate_sess_init();
  if (res < 0) {
    pr_session_disconnect(&deflate_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Initialization functions
 */

static int deflate_init(void) {
  pr_log_debug(DEBUG5, MOD_DEFLATE_VERSION ": using zlib " ZLIB_VERSION);
  return 0;
}

static int deflate_sess_init(void) {
  config_rec *c;

  pr_event_register(&deflate_module, "core.session-reinit",
    deflate_sess_reinit_ev, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "DeflateEngine", FALSE);
  if (c &&
      *((unsigned int *) c->argv[0]) == TRUE) {
    deflate_engine = TRUE;

  } else {
    return 0;
  }

  /* Add a FEAT string indicating support of MODE Z.  Note that, in the
   * future, other compression engines (e.g. bzip2) will need to be handled
   * here as well.
   */
  pr_feat_add("MODE Z");

  c = find_config(main_server->conf, CONF_PARAM, "DeflateLog", FALSE);
  if (c &&
      strcasecmp(c->argv[0], "none") != 0) {
    int res, xerrno = 0;

    pr_signals_block();
    PRIVS_ROOT
    res = pr_log_openfile(c->argv[0], &deflate_logfd, PR_LOG_SYSTEM_MODE);
    xerrno = errno;
    PRIVS_RELINQUISH
    pr_signals_unblock();

    switch (res) {
      case -1:
        pr_log_pri(PR_LOG_NOTICE, MOD_DEFLATE_VERSION
          ": notice: unable to open DeflateLog '%s': %s",
          (char *) c->argv[0], strerror(xerrno));
        break;

      case PR_LOG_WRITABLE_DIR:
        pr_log_pri(PR_LOG_WARNING, MOD_DEFLATE_VERSION
          ": notice: unable to use DeflateLog '%s': parent directory is "
            "world-writable", (char *) c->argv[0]);
        break;

      case PR_LOG_SYMLINK:
        pr_log_pri(PR_LOG_WARNING, MOD_DEFLATE_VERSION
          ": notice: unable to use DeflateLog '%s': cannot log to a symlink",
          (char *) c->argv[0]);
        break;
    }
  }

  /* Allocate the buffers which will be used for inflating/deflating data.
   * Look up the optimal transfer buffer size, and use a factor of 8.
   * Later, if needed, a larger buffer will be allocated when necessary.
   */
  if (deflate_zbuf == NULL) {
    deflate_zbufsz = pr_config_get_xfer_bufsz() * 8;
    deflate_zbuf_ptr = deflate_zbuf = pcalloc(session.pool, deflate_zbufsz);
    deflate_zbuflen = 0;
  }

  if (deflate_rbuf == NULL) {
    deflate_rbufsz = pr_config_get_xfer_bufsz();
    deflate_rbuf = palloc(session.pool, deflate_rbufsz);
    deflate_rbuflen = 0;
  }

  return 0;
}

/* Module API tables
 */

static conftable deflate_conftab[] = {
  { "DeflateEngine",		set_deflateengine,		NULL },
  { "DeflateLog",		set_deflatelog,			NULL },
  { NULL }
};

static cmdtable deflate_cmdtab[] = {
  { CMD, C_OPTS "_MODE",	G_NONE, deflate_opts,	FALSE, FALSE, CL_MISC },
  { CMD, C_MODE,		G_NONE, deflate_mode,	FALSE, FALSE, CL_MISC },
  { 0, NULL }
};

module deflate_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "deflate",

  /* Module configuration handler table */
  deflate_conftab,

  /* Module command handler table */
  deflate_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  deflate_init,

  /* Session initialization function */
  deflate_sess_init,

  /* Module version */
  MOD_DEFLATE_VERSION
};
