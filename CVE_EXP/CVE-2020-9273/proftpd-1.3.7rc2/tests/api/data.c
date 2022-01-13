/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2015-2018 The ProFTPD Project team
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

/* Data API tests */

#include "tests.h"

static pool *p = NULL;

static const char *data_test_path = "/tmp/prt-data.dat";

static void set_up(void) {
  if (p == NULL) {
    p = session.pool = permanent_pool = make_sub_pool(NULL);
  }

  init_fs();
  init_netio();
  init_dirtree();

  pr_response_set_pool(p);
  (void) pr_fsio_unlink(data_test_path);

  if (session.c != NULL) {
    pr_inet_close(p, session.c);
    session.c = NULL;
  }

  session.sf_flags = 0;

  pr_trace_set_levels("timing", 1, 1);
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("data", 1, 20);
  }
}

static void tear_down(void) {
  pr_unregister_netio(PR_NETIO_STRM_CTRL|PR_NETIO_STRM_CTRL);
  pr_unregister_netio(PR_NETIO_STRM_CTRL|PR_NETIO_STRM_DATA);
  (void) pr_fsio_unlink(data_test_path);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("data", 0, 0);
  }
  pr_trace_set_levels("timing", 0, 0);

  if (session.c != NULL) {
    (void) pr_inet_close(p, session.c);

    if (session.c == session.d) {
      session.d = NULL;
    }

    session.c = NULL;
  }

  if (session.d != NULL) {
    (void) pr_inet_close(p, session.d);
    session.d = NULL;
  }

  pr_response_set_pool(NULL);

  if (p) {
    destroy_pool(p);
    p = session.pool = session.xfer.p = permanent_pool = NULL;
  } 
}

START_TEST (data_get_timeout_test) {
  int res;

  res = pr_data_get_timeout(-1);
  fail_unless(res < 0, "Failed to handle invalid timeout ID");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_data_get_timeout(PR_DATA_TIMEOUT_IDLE);
  fail_unless(res == PR_TUNABLE_TIMEOUTIDLE, "Expected %d, got %d",
    PR_TUNABLE_TIMEOUTIDLE, res);

  res = pr_data_get_timeout(PR_DATA_TIMEOUT_NO_TRANSFER);
  fail_unless(res == PR_TUNABLE_TIMEOUTNOXFER, "Expected %d, got %d",
    PR_TUNABLE_TIMEOUTNOXFER, res);

  res = pr_data_get_timeout(PR_DATA_TIMEOUT_STALLED);
  fail_unless(res == PR_TUNABLE_TIMEOUTSTALLED, "Expected %d, got %d",
    PR_TUNABLE_TIMEOUTSTALLED, res);
}
END_TEST

START_TEST (data_set_timeout_test) {
  int res, timeout = 7;

  pr_data_set_timeout(PR_DATA_TIMEOUT_IDLE, timeout);
  res = pr_data_get_timeout(PR_DATA_TIMEOUT_IDLE);
  fail_unless(res == timeout, "Expected %d, got %d", timeout, res);

  pr_data_set_timeout(PR_DATA_TIMEOUT_NO_TRANSFER, timeout);
  res = pr_data_get_timeout(PR_DATA_TIMEOUT_NO_TRANSFER);
  fail_unless(res == timeout, "Expected %d, got %d", timeout, res);

  pr_data_set_timeout(PR_DATA_TIMEOUT_STALLED, timeout);
  res = pr_data_get_timeout(PR_DATA_TIMEOUT_STALLED);
  fail_unless(res == timeout, "Expected %d, got %d", timeout, res);

  /* Interestingly, the linger timeout has its own function. */
  pr_data_set_linger(7L);
}
END_TEST

START_TEST (data_ignore_ascii_test) {
  int res;

  res = pr_data_ignore_ascii(-1);
  fail_unless(res < 0, "Failed to handle invalid argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_data_ignore_ascii(TRUE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);

  res = pr_data_ignore_ascii(TRUE);
  fail_unless(res == TRUE, "Expected TRUE (%d), got %d", TRUE, res);

  res = pr_data_ignore_ascii(FALSE);
  fail_unless(res == TRUE, "Expected TRUE (%d), got %d", TRUE, res);

  res = pr_data_ignore_ascii(FALSE);
  fail_unless(res == FALSE, "Expected FALSE (%d), got %d", FALSE, res);
}
END_TEST

static int data_close_cb(pr_netio_stream_t *nstrm) {
  return 0;
}

static int data_poll_cb(pr_netio_stream_t *nstrm) {
  /* Always return >0, to indicate that we haven't timed out, AND that there
   * is a writable fd available.
   */
  return 7;
}

static int data_read_eagain = FALSE;
static int data_read_epipe = FALSE;
static int data_read_dangling_cr = FALSE;

static int data_read_cb(pr_netio_stream_t *nstrm, char *buf, size_t buflen) {
  const char *data = "Hello,\r\n World!\r\n";
  size_t sz;

  if (data_read_eagain) {
    data_read_eagain = FALSE;
    errno = EAGAIN;
    return -1;
  }

  if (data_read_epipe) {
    data_read_epipe = FALSE;
    errno = EPIPE;
    return -1;
  }

  if (data_read_dangling_cr) {
    data = "Hello,\r\n World!\r\n\r";
  }

  sz = strlen(data);
  if (buflen < sz) {
    sz = buflen;
  }

  memcpy(buf, data, sz);
  return (int) sz;
}

static int data_write_eagain = FALSE;
static int data_write_epipe = FALSE;

static int data_write_cb(pr_netio_stream_t *nstrm, char *buf, size_t buflen) {
  if (data_write_eagain) {
    data_write_eagain = FALSE;
    errno = EAGAIN;
    return -1;
  }

  if (data_write_epipe) {
    data_write_epipe = FALSE;
    errno = EPIPE;
    return -1;
  }

  return buflen;
}

static int data_open_streams(conn_t *conn, int strm_type) {
  int fd = 2, res;
  pr_netio_t *netio;
  pr_netio_stream_t *nstrm;

  netio = pr_alloc_netio2(p, NULL, "testsuite");
  netio->close = data_close_cb;
  netio->poll = data_poll_cb;
  netio->read = data_read_cb;
  netio->write = data_write_cb;

  res = pr_register_netio(netio, strm_type);
  if (res < 0) {
    return -1;
  }

  nstrm = pr_netio_open(p, strm_type, fd, PR_NETIO_IO_WR);
  if (nstrm == NULL) {
    return -1;
  }

  conn->outstrm = nstrm;

  nstrm = pr_netio_open(p, strm_type, fd, PR_NETIO_IO_RD);
  if (nstrm == NULL) {
    return -1;
  }

  conn->instrm = nstrm;
  return 0;
}

START_TEST (data_sendfile_test) {
  int fd = -1, res;
  off_t offset = 0;
  pr_fh_t *fh;
  const char *text;

  res = (int) pr_data_sendfile(fd, NULL, 0);
  if (res < 0 &&
      errno == ENOSYS) {
    return;
  }

  res = pr_data_sendfile(fd, NULL, 0);
  fail_unless(res < 0, "Failed to handle null offset");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_data_sendfile(fd, &offset, 0);
  fail_unless(res < 0, "Failed to handle zero count");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  session.xfer.direction = PR_NETIO_IO_RD;
  res = pr_data_sendfile(fd, &offset, 1);
  fail_unless(res < 0, "Failed to handle invalid transfer direction");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  session.xfer.direction = PR_NETIO_IO_WR;
  res = pr_data_sendfile(fd, &offset, 1);
  fail_unless(res < 0, "Failed to handle lack of data connection");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  session.d = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.d != NULL, "Failed to create conn: %s", strerror(errno));

  res = data_open_streams(session.d, PR_NETIO_STRM_DATA);
  fail_unless(res == 0, "Failed to open streams: %s", strerror(errno));

  mark_point();
  res = pr_data_sendfile(fd, &offset, 1);
  fail_unless(res < 0, "Failed to handle bad file descriptor");
  fail_unless(errno == EBADF || errno == EINVAL,
    "Expected EBADF (%d) or EINVAL (%d), got %s (%d)", EBADF, EINVAL,
    strerror(errno), errno);

  fh = pr_fsio_open(data_test_path, O_CREAT|O_EXCL|O_WRONLY);
  fail_unless(fh != NULL, "Failed to open '%s': %s", data_test_path,
    strerror(errno));

  text = "Hello, World!\n";
  res = pr_fsio_write(fh, text, strlen(text));
  fail_unless(res >= 0, "Failed to write to '%s': %s", data_test_path,
    strerror(errno));
  res = pr_fsio_close(fh);
  fail_unless(res == 0, "Failed to close '%s': %s", data_test_path,
    strerror(errno));

  fd = open(data_test_path, O_RDONLY);
  fail_unless(fd >= 0, "Failed to open '%s': %s", data_test_path,
    strerror(errno));

  mark_point();
  res = pr_data_sendfile(fd, &offset, strlen(text));
  if (res < 0) {
    fail_unless(errno == ENOTSOCK || errno == EINVAL,
     "Expected ENOTSOCK (%d) or EINVAL (%d), got %s (%d)", ENOTSOCK, EINVAL,
     strerror(errno), errno);
  }

  (void) close(fd);
  (void) pr_netio_close(session.d->outstrm);
  session.d->outstrm = NULL;
  (void) pr_inet_close(p, session.d);
  session.d = NULL;

  pr_unregister_netio(PR_NETIO_STRM_DATA);
}
END_TEST

START_TEST (data_init_test) {
  int rd = PR_NETIO_IO_RD, wr = PR_NETIO_IO_WR;
  char *filename = NULL;

  mark_point();
  pr_data_init(filename, 0);
  fail_unless(session.xfer.direction == 0, "Expected xfer direction %d, got %d",
    0, session.xfer.direction);
  fail_unless(session.xfer.p != NULL, "Transfer pool not created as expected");
  fail_unless(session.xfer.filename == NULL, "Expected null filename, got %s",
    session.xfer.filename);

  filename = "test.dat";
  pr_data_clear_xfer_pool();

  mark_point();
  pr_data_init(filename, rd);
  fail_unless(session.xfer.direction == rd,
    "Expected xfer direction %d, got %d", rd, session.xfer.direction);
  fail_unless(session.xfer.p != NULL, "Transfer pool not created as expected");
  fail_unless(session.xfer.filename != NULL, "Missing transfer filename");
  fail_unless(strcmp(session.xfer.filename, filename) == 0,
    "Expected '%s', got '%s'", filename, session.xfer.filename);

  mark_point();
  pr_data_init("test2.dat", wr);
  fail_unless(session.xfer.direction == wr,
    "Expected xfer direction %d, got %d", wr, session.xfer.direction);
  fail_unless(session.xfer.p != NULL, "Transfer pool not created as expected");
  fail_unless(session.xfer.filename != NULL, "Missing transfer filename");

  /* Even though we opened with a new filename, the previous filename should
   * still be there, as we didn't actually clear/reset this transfer.
   */
  fail_unless(strcmp(session.xfer.filename, filename) == 0,
    "Expected '%s', got '%s'", filename, session.xfer.filename);
}
END_TEST

START_TEST (data_open_active_test) {
  int dir = PR_NETIO_IO_RD, port = INPORT_ANY, sockfd = -1, res;
  conn_t *conn;

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  /* Note: these tests REQUIRE that session.c be non-NULL */
  session.c = conn;

  /* Open a READing data transfer connection...*/

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Note: we also need session.c to have valid local/remote_addr, too! */
  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(session.c->remote_addr != NULL, "Failed to get address: %s",
    strerror(errno));

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Opened active READ data connection unexpectedly");
  fail_unless(errno == EADDRNOTAVAIL || errno == ECONNREFUSED,
    "Expected EADDRNOTAVAIL (%d) or ECONNREFUSED (%d), got %s (%d)",
    EADDRNOTAVAIL, ECONNREFUSED, strerror(errno), errno);

  /* Open a WRITing data transfer connection...*/
  dir = PR_NETIO_IO_WR;

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Opened active READ data connection unexpectedly");
  fail_unless(errno == EADDRNOTAVAIL || errno == ECONNREFUSED,
    "Expected EADDRNOTAVAIL (%d) or ECONNREFUSED (%d), got %s (%d)",
    EADDRNOTAVAIL, ECONNREFUSED, strerror(errno), errno);

  mark_point();
  session.xfer.p = NULL;
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Opened active READ data connection unexpectedly");
  fail_unless(errno == EADDRNOTAVAIL || errno == ECONNREFUSED,
    "Expected EADDRNOTAVAIL (%d) or ECONNREFUSED (%d), got %s (%d)",
    EADDRNOTAVAIL, ECONNREFUSED, strerror(errno), errno);

  (void) pr_inet_close(p, session.c);
  session.c = NULL;
  if (session.d != NULL) {
    (void) pr_inet_close(p, session.d);
    session.d = NULL;
  }
}
END_TEST

START_TEST (data_open_passive_test) {
  int dir = PR_NETIO_IO_RD, port = INPORT_ANY, sockfd = -1, res;

  /* Set the session flags for a passive transfer data connection. */
  session.sf_flags |= SF_PASSIVE;

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Note: these tests REQUIRE that session.c be non-NULL, AND that session.d
   * be non-NULL.
   */
  session.c = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(session.c != NULL, "Failed to create conn: %s", strerror(errno));

  session.d = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(session.d != NULL, "Failed to create conn: %s", strerror(errno));

  /* Open a READing data transfer connection...*/

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Note: we also need session.c to have valid local/remote_addr, too! */
  session.c->local_addr = session.c->remote_addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(session.c->remote_addr != NULL, "Failed to get address: %s",
    strerror(errno));

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Opened passive READ data connection unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Open a WRITing data transfer connection...*/
  dir = PR_NETIO_IO_WR;

  mark_point();
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Opened passive READ data connection unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  session.xfer.p = NULL;
  res = pr_data_open(NULL, NULL, dir, 0);
  fail_unless(res < 0, "Opened passive READ data connection unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) pr_inet_close(p, session.c);
  session.c = NULL;
  if (session.d != NULL) {
    (void) pr_inet_close(p, session.d);
    session.d = NULL;
  }
}
END_TEST

START_TEST (data_close_test) {
  session.sf_flags |= SF_PASSIVE;
  pr_data_close(TRUE);
  fail_unless(!(session.sf_flags & SF_PASSIVE),
    "Failed to clear SF_PASSIVE session flag");

  session.sf_flags |= SF_PASSIVE;
  pr_data_close(FALSE);
  fail_unless(!(session.sf_flags & SF_PASSIVE),
    "Failed to clear SF_PASSIVE session flag");

  session.d = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.d != NULL, "Failed to create conn: %s", strerror(errno));

  pr_data_close(TRUE);
  fail_unless(session.d == NULL, "Failed to close session.d");
}
END_TEST

START_TEST (data_abort_test) {
  session.sf_flags |= SF_PASSIVE;
  pr_data_abort(EPERM, TRUE);
  fail_unless(!(session.sf_flags & SF_PASSIVE),
    "Failed to clear SF_PASSIVE session flag");

  session.sf_flags |= SF_PASSIVE;
  pr_data_abort(EPERM, FALSE);
  fail_unless(!(session.sf_flags & SF_PASSIVE),
    "Failed to clear SF_PASSIVE session flag");

  session.d = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.d != NULL, "Failed to create conn: %s", strerror(errno));

  pr_data_abort(ESPIPE, FALSE);
  fail_unless(session.d == NULL, "Failed to close session.d");
}
END_TEST

START_TEST (data_reset_test) {
  mark_point();

  /* Set a session flag, make sure it's cleared properly. */
  session.sf_flags |= SF_PASSIVE;
  pr_data_reset();
  fail_unless(session.d == NULL, "Expected NULL session.d, got %p", session.d);
  fail_unless(!(session.sf_flags & SF_PASSIVE),
    "SF_PASSIVE session flag not cleared");

  session.d = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.d != NULL, "Failed to create conn: %s", strerror(errno));

  pr_data_reset();
  fail_unless(session.d == NULL, "Expected NULL session.d, got %p", session.d);
  fail_unless(!(session.sf_flags & SF_PASSIVE),
    "SF_PASSIVE session flag not cleared");
}
END_TEST

START_TEST (data_cleanup_test) {
  mark_point();

  /* Set a session flag, make sure it's cleared properly. */
  session.sf_flags |= SF_PASSIVE;
  pr_data_cleanup();
  fail_unless(session.d == NULL, "Expected NULL session.d, got %p", session.d);
  fail_unless(session.sf_flags & SF_PASSIVE,
    "SF_PASSIVE session flag not preserved");
  fail_unless(session.xfer.xfer_type == STOR_DEFAULT, "Expected %d, got %d",
    STOR_DEFAULT, session.xfer.xfer_type);

  session.d = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.d != NULL, "Failed to create conn: %s", strerror(errno));

  pr_data_cleanup();
  fail_unless(session.d == NULL, "Failed to close session.d");
}
END_TEST

START_TEST (data_clear_xfer_pool_test) {
  int xfer_type = 7;

  mark_point();
  pr_data_clear_xfer_pool();
  fail_unless(session.xfer.p == NULL, "Failed to clear session.xfer.p");

  session.xfer.xfer_type = xfer_type; 
  session.xfer.p = make_sub_pool(p);

  mark_point();
  pr_data_clear_xfer_pool();
  fail_unless(session.xfer.p == NULL, "Failed to clear session.xfer.p");
  fail_unless(session.xfer.xfer_type == xfer_type, "Expected %d, got %d",
    xfer_type, session.xfer.xfer_type);
}
END_TEST

START_TEST (data_xfer_read_binary_test) {
  int res;
  char *buf, *expected;
  size_t bufsz, expected_len;
  cmd_rec *cmd;

  pr_data_clear_xfer_pool();
  pr_data_reset();

  res = pr_data_xfer(NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  bufsz = 1024;
  buf = palloc(p, bufsz);

  res = pr_data_xfer(buf, 0);
  fail_unless(res < 0, "Failed to handle zero buffer length");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_data_xfer(buf, bufsz);
  fail_unless(res < 0, "Transferred data unexpectedly");
  fail_unless(errno == ECONNABORTED,
    "Expected ECONNABORTED (%d), got %s (%d)", ECONNABORTED,
    strerror(errno), errno);

  session.d = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.d != NULL, "Failed to create conn: %s", strerror(errno));

  /* read binary data */
  session.xfer.direction = PR_NETIO_IO_RD;

  /* Note: this string comes from the data_read_cb() we register with our
   * DATA stream callback.
   */
  expected = "Hello,\r\n World!\r\n";
  expected_len = strlen(expected);

  mark_point();
  data_write_eagain = TRUE;
  session.xfer.buf = NULL;
  session.xfer.buflen = 0;

  res = pr_data_xfer(buf, bufsz);
  fail_unless(res < 0, "Transferred data unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = data_open_streams(session.d, PR_NETIO_STRM_DATA);
  fail_unless(res == 0, "Failed to open streams on session.d: %s",
    strerror(errno));

  mark_point();
  session.xfer.buf = NULL;
  session.xfer.buflen = 0;

  res = pr_data_xfer(buf, bufsz);
  fail_unless((size_t) res == expected_len, "Expected %lu, got %d",
    (unsigned long) expected_len, res);

  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.c != NULL, "Failed to create conn: %s", strerror(errno));

  res = data_open_streams(session.c, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to open streams on session.c: %s",
    strerror(errno));

  mark_point();
  session.xfer.buf = NULL;
  session.xfer.buflen = 0;

  res = pr_data_xfer(buf, bufsz);
  fail_unless(res == (int) expected_len, "Expected %lu, got %d",
    (unsigned long) expected_len, res);
  fail_unless(session.xfer.buflen == 0,
    "Expected session.xfer.buflen 0, got %lu",
    (unsigned long) session.xfer.buflen);

  mark_point();
  session.xfer.buf = NULL;
  session.xfer.buflen = 0;
  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "syst"));
  tests_stubs_set_next_cmd(cmd);
  data_read_eagain = TRUE;

  res = pr_data_xfer(buf, bufsz);
  fail_unless(res == (int) expected_len, "Expected %lu, got %d",
    (unsigned long) expected_len, res);
  fail_unless(session.xfer.buflen == 0,
    "Expected session.xfer.buflen 0, got %lu",
    (unsigned long) session.xfer.buflen);
}
END_TEST

START_TEST (data_xfer_write_binary_test) {
  int res;
  char *buf;
  size_t buflen;

  pr_data_clear_xfer_pool();
  pr_data_reset();

  res = pr_data_xfer(NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  buf = "Hello, World!\n";
  buflen = strlen(buf);

  res = pr_data_xfer(buf, 0);
  fail_unless(res < 0, "Failed to handle zero buffer length");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_data_xfer(buf, buflen);
  fail_unless(res < 0, "Transferred data unexpectedly");
  fail_unless(errno == ECONNABORTED,
    "Expected ECONNABORTED (%d), got %s (%d)", ECONNABORTED,
    strerror(errno), errno);

  session.d = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.d != NULL, "Failed to create conn: %s", strerror(errno));

  /* write binary data */
  session.xfer.direction = PR_NETIO_IO_WR;
  session.xfer.p = make_sub_pool(p);
  session.xfer.buflen = 1024;
  session.xfer.buf = pcalloc(p, session.xfer.buflen);

  mark_point();
  data_write_eagain = TRUE;
  res = pr_data_xfer(buf, buflen);
  fail_unless(res < 0, "Transferred data unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = data_open_streams(session.d, PR_NETIO_STRM_DATA);
  fail_unless(res == 0, "Failed to open streams on session.d: %s",
    strerror(errno));

  mark_point();
  res = pr_data_xfer(buf, buflen);
  fail_unless(res == (int) buflen, "Expected %lu, got %d",
    (unsigned long) buflen, res);

  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.c != NULL, "Failed to create conn: %s", strerror(errno));

  res = data_open_streams(session.c, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to open streams on session.c: %s",
    strerror(errno));

  mark_point();
  res = pr_data_xfer(buf, buflen);
  fail_unless(res == (int) buflen, "Expected %lu, got %d",
    (unsigned long) buflen, res);
  fail_unless(strncmp(session.xfer.buf, buf, buflen) == 0,
    "Expected '%s', got '%.100s'", buf, session.xfer.buf);
}
END_TEST

START_TEST (data_xfer_read_ascii_test) {
  int res;
  char *buf, *expected;
  size_t bufsz, expected_len;
  cmd_rec *cmd;

  pr_data_clear_xfer_pool();
  pr_data_reset();

  res = pr_data_xfer(NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  bufsz = 1024;
  buf = palloc(p, bufsz);

  res = pr_data_xfer(buf, 0);
  fail_unless(res < 0, "Failed to handle zero buffer length");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_data_xfer(buf, bufsz);
  fail_unless(res < 0, "Transferred data unexpectedly");
  fail_unless(errno == ECONNABORTED,
    "Expected ECONNABORTED (%d), got %s (%d)", ECONNABORTED,
    strerror(errno), errno);

  session.d = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.d != NULL, "Failed to create conn: %s", strerror(errno));

  /* read ASCII data */
  session.xfer.direction = PR_NETIO_IO_RD;
  session.xfer.p = make_sub_pool(p);
  session.xfer.bufsize = 1024;

  /* Note: this string comes from the data_read_cb() we register with our
   * DATA stream callback.
   */
  expected = "Hello,\n World!\n";
  expected_len = strlen(expected);

  mark_point();
  data_write_eagain = TRUE;
  pr_ascii_ftp_reset();
  session.xfer.buf = pcalloc(p, session.xfer.bufsize);
  session.xfer.buflen = 0;

  session.sf_flags |= SF_ASCII;
  res = pr_data_xfer(buf, bufsz);
  session.sf_flags &= ~SF_ASCII;

  fail_unless(res < 0, "Transferred data unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = data_open_streams(session.d, PR_NETIO_STRM_DATA);
  fail_unless(res == 0, "Failed to open streams on session.d: %s",
    strerror(errno));

  mark_point();
  pr_ascii_ftp_reset();
  session.xfer.buf = pcalloc(p, session.xfer.bufsize);
  session.xfer.buflen = 0;

  session.sf_flags |= SF_ASCII;
  res = pr_data_xfer(buf, bufsz);
  session.sf_flags &= ~SF_ASCII;

  fail_unless((size_t) res == expected_len, "Expected %lu, got %d",
    (unsigned long) expected_len, res);

  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.c != NULL, "Failed to create conn: %s", strerror(errno));

  res = data_open_streams(session.c, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to open streams on session.c: %s",
    strerror(errno));

  mark_point();
  pr_ascii_ftp_reset();
  session.xfer.buf = pcalloc(p, session.xfer.bufsize);
  session.xfer.buflen = 0;

  session.sf_flags |= SF_ASCII;
  res = pr_data_xfer(buf, bufsz);
  session.sf_flags &= ~SF_ASCII;

  fail_unless(res == (int) expected_len, "Expected %lu, got %d",
    (unsigned long) expected_len, res);
  fail_unless(session.xfer.buflen == 0,
    "Expected session.xfer.buflen 0, got %lu",
    (unsigned long) session.xfer.buflen);
  fail_unless(strncmp(buf, expected, expected_len) == 0,
    "Expected '%s', got '%.100s'", expected, buf);

  mark_point();
  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "noop"));
  tests_stubs_set_next_cmd(cmd);
  pr_ascii_ftp_reset();
  session.xfer.buf = pcalloc(p, session.xfer.bufsize);
  session.xfer.buflen = 0;

  session.sf_flags |= SF_ASCII;
  res = pr_data_xfer(buf, bufsz);
  session.sf_flags &= ~SF_ASCII;

  fail_unless(res == (int) expected_len, "Expected %lu, got %d",
    (unsigned long) expected_len, res);
  fail_unless(session.xfer.buflen == 0,
    "Expected session.xfer.buflen 0, got %lu",
    (unsigned long) session.xfer.buflen);
  fail_unless(strncmp(buf, expected, expected_len) == 0,
    "Expected '%s', got '%.100s'", expected, buf);

  mark_point();
  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "pasv"));
  tests_stubs_set_next_cmd(cmd);
  pr_ascii_ftp_reset();
  session.xfer.buf = pcalloc(p, session.xfer.bufsize);
  session.xfer.buflen = 0;

  session.sf_flags |= SF_ASCII;
  res = pr_data_xfer(buf, bufsz);
  session.sf_flags &= ~SF_ASCII;

  fail_unless(res == (int) expected_len, "Expected %lu, got %d",
    (unsigned long) expected_len, res);
  fail_unless(session.xfer.buflen == 0,
    "Expected session.xfer.buflen 0, got %lu",
    (unsigned long) session.xfer.buflen);
  fail_unless(strncmp(buf, expected, expected_len) == 0,
    "Expected '%s', got '%.100s'", expected, buf);

  /* Bug#4237 happened because of insufficient testing of the edge case
   * where the LAST character in the buffer is a CR.
   *
   * Note that to properly test this, we need to KEEP the same session.xfer.buf
   * in place, and do the read TWICE (at least; maybe more).
   */

  mark_point();
  pr_ascii_ftp_reset();
  session.xfer.buf = pcalloc(p, session.xfer.bufsize);
  session.xfer.buflen = 0;
  data_read_dangling_cr = TRUE;

  session.sf_flags |= SF_ASCII;
  res = pr_data_xfer(buf, bufsz);
  session.sf_flags &= ~SF_ASCII;

  fail_unless(res == (int) expected_len, "Expected %lu, got %d",
    (unsigned long) expected_len, res);
  fail_unless(session.xfer.buflen == 1,
    "Expected session.xfer.buflen 1, got %lu",
    (unsigned long) session.xfer.buflen);
  fail_unless(strncmp(buf, expected, expected_len) == 0,
    "Expected '%s', got '%.100s'", expected, buf);
}
END_TEST

START_TEST (data_xfer_write_ascii_test) {
  int res;
  char *buf, *ascii_buf;
  size_t buflen, ascii_buflen;
  cmd_rec *cmd;

  pr_data_clear_xfer_pool();
  pr_data_reset();

  res = pr_data_xfer(NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  buf = "Hello,\n World\n";
  buflen = strlen(buf);

  ascii_buf = "Hello,\r\n World\r\n";
  ascii_buflen = strlen(ascii_buf);

  res = pr_data_xfer(buf, 0);
  fail_unless(res < 0, "Failed to handle zero buffer length");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_data_xfer(buf, buflen);
  fail_unless(res < 0, "Transferred data unexpectedly");
  fail_unless(errno == ECONNABORTED,
    "Expected ECONNABORTED (%d), got %s (%d)", ECONNABORTED,
    strerror(errno), errno);

  session.d = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.d != NULL, "Failed to create conn: %s", strerror(errno));

  /* write ASCII data */
  session.xfer.direction = PR_NETIO_IO_WR;
  session.xfer.p = make_sub_pool(p);
  session.xfer.buflen = 1024;
  session.xfer.buf = pcalloc(p, session.xfer.buflen);

  mark_point();
  data_write_eagain = TRUE;
  pr_ascii_ftp_reset();
  session.sf_flags |= SF_ASCII_OVERRIDE;
  res = pr_data_xfer(buf, buflen);
  session.sf_flags &= ~SF_ASCII_OVERRIDE;

  fail_unless(res < 0, "Transferred data unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = data_open_streams(session.d, PR_NETIO_STRM_DATA);
  fail_unless(res == 0, "Failed to open streams on session.d: %s",
    strerror(errno));

  mark_point();
  pr_ascii_ftp_reset();
  session.sf_flags |= SF_ASCII_OVERRIDE;
  res = pr_data_xfer(buf, buflen);
  session.sf_flags &= ~SF_ASCII_OVERRIDE;

  fail_unless(res == (int) buflen, "Expected %lu, got %d",
    (unsigned long) buflen, res);

  session.c = pr_inet_create_conn(p, -1, NULL, INPORT_ANY, FALSE);
  fail_unless(session.c != NULL, "Failed to create conn: %s", strerror(errno));

  res = data_open_streams(session.c, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to open streams on session.c: %s",
    strerror(errno));

  mark_point();
  pr_ascii_ftp_reset();
  session.xfer.buflen = 1024;
  session.xfer.buf = pcalloc(p, session.xfer.buflen);

  session.sf_flags |= SF_ASCII_OVERRIDE;
  res = pr_data_xfer(buf, buflen);
  session.sf_flags &= ~SF_ASCII_OVERRIDE;

  fail_unless(res == (int) buflen, "Expected %lu, got %d",
    (unsigned long) buflen, res);
  fail_unless(session.xfer.buflen == ascii_buflen,
    "Expected session.xfer.buflen %lu, got %lu", (unsigned long) ascii_buflen,
    (unsigned long) session.xfer.buflen);

  mark_point();
  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "noop"));
  tests_stubs_set_next_cmd(cmd);
  pr_ascii_ftp_reset();
  session.xfer.buflen = 1024;
  session.xfer.buf = pcalloc(p, session.xfer.buflen);

  session.sf_flags |= SF_ASCII_OVERRIDE;
  res = pr_data_xfer(buf, buflen);
  session.sf_flags &= ~SF_ASCII_OVERRIDE;

  fail_unless(res == (int) buflen, "Expected %lu, got %d",
    (unsigned long) buflen, res);
  fail_unless(session.xfer.buflen == ascii_buflen,
    "Expected session.xfer.buflen %lu, got %lu", (unsigned long) ascii_buflen,
    (unsigned long) session.xfer.buflen);

  session.xfer.p = make_sub_pool(p);
  mark_point();
  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "pasv"));
  tests_stubs_set_next_cmd(cmd);
  pr_ascii_ftp_reset();
  session.xfer.buflen = 1024;
  session.xfer.buf = pcalloc(p, session.xfer.buflen);

  session.sf_flags |= SF_ASCII_OVERRIDE;
  res = pr_data_xfer(buf, buflen);
  session.sf_flags &= ~SF_ASCII_OVERRIDE;

  fail_unless(res == (int) buflen, "Expected %lu, got %d",
    (unsigned long) buflen, res);
  fail_unless(session.xfer.buflen == ascii_buflen,
    "Expected session.xfer.buflen %lu, got %lu", (unsigned long) ascii_buflen,
    (unsigned long) session.xfer.buflen);

  mark_point();
  pr_ascii_ftp_reset();
  session.xfer.buflen = 1024;
  session.xfer.buf = pcalloc(p, session.xfer.buflen);

  session.sf_flags |= SF_ASCII;
  res = pr_data_xfer(buf, buflen);
  session.sf_flags &= ~SF_ASCII;

  fail_unless(res == (int) buflen, "Expected %lu, got %d",
    (unsigned long) buflen, res);
  fail_unless(session.xfer.buflen == ascii_buflen,
    "Expected session.xfer.buflen %lu, got %lu", (unsigned long) ascii_buflen,
    (unsigned long) session.xfer.buflen);
}
END_TEST

Suite *tests_get_data_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("data");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, data_get_timeout_test);
  tcase_add_test(testcase, data_set_timeout_test);
  tcase_add_test(testcase, data_ignore_ascii_test);
  tcase_add_test(testcase, data_sendfile_test);

  tcase_add_test(testcase, data_init_test);
  tcase_add_test(testcase, data_open_active_test);
  tcase_add_test(testcase, data_open_passive_test);
  tcase_add_test(testcase, data_close_test);
  tcase_add_test(testcase, data_abort_test);
  tcase_add_test(testcase, data_reset_test);
  tcase_add_test(testcase, data_cleanup_test);
  tcase_add_test(testcase, data_clear_xfer_pool_test);
  tcase_add_test(testcase, data_xfer_read_binary_test);
  tcase_add_test(testcase, data_xfer_write_binary_test);
  tcase_add_test(testcase, data_xfer_read_ascii_test);
  tcase_add_test(testcase, data_xfer_write_ascii_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
