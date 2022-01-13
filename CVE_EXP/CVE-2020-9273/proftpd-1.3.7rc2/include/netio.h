/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2016 The ProFTPD Project team
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

/* Network IO stream layer */

#ifndef PR_NETIO_H
#define PR_NETIO_H

/* Network I/O stream types */

/* This indicates that the netio being registered should be used when
 * performing network I/O for the control connection.
 */
#define PR_NETIO_STRM_CTRL		0x00010

/* This indicates that the netio being registered should be used when
 * performing network I/O for the data connection.
 */
#define PR_NETIO_STRM_DATA		0x00020

/* This indicates that the netio being registered should be used when
 * performing network I/O for other connections (e.g. RFC931 lookups).
 * This is rarely used.
 */
#define PR_NETIO_STRM_OTHR		0x00040

/* Network I/O stream direction */
#define PR_NETIO_IO_RD		1
#define PR_NETIO_IO_WR		2

/* Network I/O stream session flags */

/* This indicates that netio functions are allowed to be interrupted by
 * EINTR, and to return -2.
 */
#define PR_NETIO_SESS_INTR		(1 << 1)

/* This is a temporary internal flag used to indicate that I/O on a
 * network stream has been aborted, and should return -2 at the next
 * possible instant.  In combination with NETIO_INTR and interruptible
 * syscalls, this should be near instantly.  This flag cannot be tested
 * for as it is cleared immediately after being detected.
 */
#define PR_NETIO_SESS_ABORT	(1 << 2)

/* Network I/O objects */

typedef struct {

  /* Pointer to the buffer memory. */
  char *buf;

  /* Total length of the buffer. */
  unsigned long buflen;

  /* Pointer to the current byte in the buffer. */
  char *current;

  /* Number of bytes left in the buffer. */
  size_t remaining;

} pr_buffer_t;

typedef struct {

  /* Memory pool for this object. */
  struct pool_rec *strm_pool;

  /* Stream type */
  int strm_type;

  /* File descriptor for this I/O stream. */
  int strm_fd;

  /* I/O mode: PR_NETIO_IO_RD or PR_NETIO_IO_WR.  Patterned after
   * open(2).
   */
  int strm_mode;

  /* Poll interval for this stream. */
  unsigned int strm_interval;

  /* Internal use. */
  volatile unsigned long strm_flags;

  /* Buffer. */
  pr_buffer_t *strm_buf;

  /* Arbitrary data for outside use. */
  void *strm_data;

  /* errno, if applicable. */
  int strm_errno;

  /* Private data for passing/retaining among modules. */
  pr_table_t *notes;

} pr_netio_stream_t;

#define PR_NETIO_ERRNO(s)	((s)->strm_errno)
#define PR_NETIO_FD(s)		((s)->strm_fd)

typedef struct {
  /* Memory pool for this object. */
  struct pool_rec *pool;

  /* NetIO callbacks */
  void (*abort)(pr_netio_stream_t *);
  int (*close)(pr_netio_stream_t *);
  pr_netio_stream_t *(*open)(pr_netio_stream_t *, int, int);
  int (*poll)(pr_netio_stream_t *);
  int (*postopen)(pr_netio_stream_t *);
  int (*read)(pr_netio_stream_t *, char *, size_t);
  pr_netio_stream_t *(*reopen)(pr_netio_stream_t *, int, int);
  int (*shutdown)(pr_netio_stream_t *, int);
  int (*write)(pr_netio_stream_t *, char *, size_t);

  /* Registering/owning module */
  module *owner;
  const char *owner_name;

} pr_netio_t;

/* Network IO function prototypes */
pr_buffer_t *pr_netio_buffer_alloc(pr_netio_stream_t *nstrm);

void pr_netio_abort(pr_netio_stream_t *);
int pr_netio_lingering_abort(pr_netio_stream_t *, long);

int pr_netio_close(pr_netio_stream_t *);
int pr_netio_lingering_close(pr_netio_stream_t *, long);
#define NETIO_LINGERING_CLOSE_FL_NO_SHUTDOWN	0x00001

char *pr_netio_gets(char *, size_t, pr_netio_stream_t *);

pr_netio_stream_t *pr_netio_open(pool *, int, int, int);

int pr_netio_postopen(pr_netio_stream_t *);

int pr_netio_printf(pr_netio_stream_t *, const char *, ...);
int pr_netio_vprintf(pr_netio_stream_t *, const char *, va_list);

/* pr_netio_printf_async() is for use inside alarm handlers, where no
 * pr_netio_poll() blocking is allowed.  This is necessary because otherwise,
 * pr_netio_poll() can potentially hang forever if the send queue is maxed and
 * the socket has been closed.
 */
int pr_netio_printf_async(pr_netio_stream_t *, char *,...);

/* pr_netio_poll() is needed instead of simply blocking read/write because
 * there is a race condition if the syscall _should_ be interrupted inside
 * read(), or write(), but the signal is received before we actually hit the
 * read or write call.  select() alleviates this problem by timing out
 * (configurable by pr_netio_set_poll_interval()), restarting the syscall if
 * PR_NETIO_SESS_INTR is not set, or returning if it is set and we were
 * interrupted by a signal.  If after the timeout PR_NETIO_SESS_ABORT is set
 * (presumably by a signal handler) or PR_NETIO_SESS_INTR & errno == EINTR,
 * we return 1.  Otherwise, return zero when data is available, or -1 on
 * other errors.
 */
int pr_netio_poll(pr_netio_stream_t *);

/* Read, from the given stream, into the buffer the requested size_t number
 * of bytes.  The last argument is the minimum number of bytes to read before
 * returning 1 (or greater).
 */
int pr_netio_read(pr_netio_stream_t *, char *, size_t, int);

pr_netio_stream_t *pr_netio_reopen(pr_netio_stream_t *, int, int);

int pr_netio_shutdown(pr_netio_stream_t *, int);

/* pr_netio_telnet_gets() is exactly like pr_netio_gets(), except a few special
 * telnet characters are handled (which takes care of the [IAC]ABOR
 * command, and odd clients
 */
char *pr_netio_telnet_gets(char *, size_t, pr_netio_stream_t *,
  pr_netio_stream_t *);

/* Similar to pr_netio_telnet_gets(), except that it returns the number of
 * bytes stored in the given buffer, or -1 if there was an error.
 */
int pr_netio_telnet_gets2(char *, size_t, pr_netio_stream_t *,
  pr_netio_stream_t *);

int pr_netio_write(pr_netio_stream_t *, char *, size_t);

/* This is a bit odd, because io_ functions are opaque, we can't be sure
 * we are dealing with a conn_t or that it is in O_NONBLOCK mode.  Trying
 * to do this without O_NONBLOCK would cause the kernel itself to block
 * here, and thus invalidate the whole principal.  Instead we save
 * the flags and put the fd in O_NONBLOCK mode.
 */
int pr_netio_write_async(pr_netio_stream_t *, char *, size_t);

void pr_netio_reset_poll_interval(pr_netio_stream_t *);
void pr_netio_set_poll_interval(pr_netio_stream_t *, unsigned int);

/* Allocate a NetIO object, and set all of its NetIO callbacks to their
 * default handlers.
 */
pr_netio_t *pr_alloc_netio(pool *);
pr_netio_t *pr_alloc_netio2(pool *, module *, const char *);

/* Register the given NetIO object and all its callbacks for the network
 * I/O layer's use.  If given a NULL argument, it will automatically
 * instantiate and register the default NetIO object.
 */
int pr_register_netio(pr_netio_t *, int);

/* Unregister the NetIO objects indicated by strm_types. */
int pr_unregister_netio(int);

/* Peek at the NetIO registered for the given stream type. */
pr_netio_t *pr_get_netio(int);

/* Initialize the network I/O layer. */
void init_netio(void);

#endif /* PR_NETIO_H */
