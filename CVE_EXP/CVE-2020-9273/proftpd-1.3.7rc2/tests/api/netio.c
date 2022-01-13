/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2008-2016 The ProFTPD Project team
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

/* NetIO API tests. */

#include "tests.h"

/* See RFC 854 for the definition of these Telnet values */

/* Telnet "Interpret As Command" indicator */
#define TELNET_IAC     255
#define TELNET_DONT    254
#define TELNET_DO      253
#define TELNET_WONT    252
#define TELNET_WILL    251
#define TELNET_IP      244
#define TELNET_DM      242

static pool *p = NULL;
static int xfer_bufsz = -1;

static int tmp_fd = -1;
static const char *tmp_path = NULL;

static void test_cleanup(void) {
  (void) close(tmp_fd);
  tmp_fd = -1;

  if (tmp_path != NULL) {
    (void) unlink(tmp_path);
    tmp_path = NULL;
  }

  pr_unregister_netio(PR_NETIO_STRM_CTRL|PR_NETIO_STRM_DATA|PR_NETIO_STRM_OTHR);
}

static int open_tmpfile(void) {
  int fd;

  if (tmp_path != NULL) {
    test_cleanup();
  }

  tmp_path = "/tmp/netio-test.dat";
  fd = open(tmp_path, O_RDWR|O_CREAT, 0666);
  fail_unless(fd >= 0, "Failed to open '%s': %s", tmp_path, strerror(errno));  
  tmp_fd = fd;

  return fd;
}

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_netio();
  xfer_bufsz = pr_config_get_server_xfer_bufsz(PR_NETIO_IO_RD);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("netio", 0, 0);
  }

  test_cleanup();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

/* Tests */

START_TEST (netio_open_test) {
  pr_netio_stream_t *nstrm;
  int fd = -1;

  nstrm = pr_netio_open(NULL, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm == NULL, "Failed to handle null pool argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  nstrm = pr_netio_open(p, 7777, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm == NULL, "Failed to handle unknown stream type argument");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM, got %s (%d)",
    strerror(errno), errno);

  /* open/close CTRL stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm != NULL, "Failed to open ctrl stream on fd %d: %s", fd,
    strerror(errno));

  pr_netio_close(nstrm);

  /* open/close DATA stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_DATA, fd, PR_NETIO_IO_WR);
  fail_unless(nstrm != NULL, "Failed to open data stream on fd %d: %s", fd,
    strerror(errno));

  pr_netio_close(nstrm);

  /* open/close OTHR stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_OTHR, fd, PR_NETIO_IO_WR);
  fail_unless(nstrm != NULL, "Failed to open othr stream on fd %d: %s", fd,
    strerror(errno));

  pr_netio_close(nstrm);
}
END_TEST

START_TEST (netio_postopen_test) {
  pr_netio_stream_t *nstrm;
  int fd = -1, res;

  res = pr_netio_postopen(NULL);
  fail_unless(res < 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* open/postopen/close CTRL stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm != NULL, "Failed to open stream on fd %d: %s", fd,
    strerror(errno));

  res = pr_netio_postopen(nstrm);
  fail_unless(res == 0, "Failed to post-open ctrl stream: %s", strerror(errno));
  (void) pr_netio_close(nstrm);

  /* open/postopen/close DATA stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_DATA, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm != NULL, "Failed to open stream on fd %d: %s", fd,
    strerror(errno));

  res = pr_netio_postopen(nstrm);
  fail_unless(res == 0, "Failed to post-open data stream: %s", strerror(errno));
  (void) pr_netio_close(nstrm);

  /* open/postopen/close OTHR stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_OTHR, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm != NULL, "Failed to open stream on fd %d: %s", fd,
    strerror(errno));

  res = pr_netio_postopen(nstrm);
  fail_unless(res == 0, "Failed to post-open othr stream: %s", strerror(errno));
  (void) pr_netio_close(nstrm);
}
END_TEST

START_TEST (netio_close_test) {
  pr_netio_stream_t *nstrm;
  int res, fd = -1;

  res = pr_netio_close(NULL);
  fail_unless(res == -1, "Failed to handle null stream argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  /* Open/close CTRL stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_RD);
  nstrm->strm_type = 7777;

  res = pr_netio_close(nstrm);
  fail_unless(res == -1, "Failed to handle unknown stream type argument");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM, got %s (%d)",
    strerror(errno), errno);

  nstrm->strm_type = PR_NETIO_STRM_CTRL;
  res = pr_netio_close(nstrm);
  fail_unless(res == -1, "Failed to handle bad file descriptor");
  fail_unless(errno == EBADF, "Failed to set errno to EBADF, got %s (%d)",
    strerror(errno), errno);

  /* Open/close DATA stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_DATA, fd, PR_NETIO_IO_RD);
  res = pr_netio_close(nstrm);
  fail_unless(res == -1, "Failed to handle bad file descriptor");
  fail_unless(errno == EBADF, "Failed to set errno to EBADF, got %s (%d)",
    strerror(errno), errno);

  /* Open/close OTHR stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_OTHR, fd, PR_NETIO_IO_RD);
  res = pr_netio_close(nstrm);
  fail_unless(res == -1, "Failed to handle bad file descriptor");
  fail_unless(errno == EBADF, "Failed to set errno to EBADF, got %s (%d)",
    strerror(errno), errno);
}
END_TEST

START_TEST (netio_lingering_close_test) {
  pr_netio_stream_t *nstrm;
  int res, fd = -1;
  long linger = 0L;

  res = pr_netio_lingering_close(NULL, linger);
  fail_unless(res == -1, "Failed to handle null stream argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  /* Open/close CTRL stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_RD);
  nstrm->strm_type = 7777;

  res = pr_netio_lingering_close(nstrm, linger);
  fail_unless(res < 0, "Failed to handle unknown stream type argument");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM, got %s (%d)",
    strerror(errno), errno);

  nstrm->strm_type = PR_NETIO_STRM_CTRL;
  res = pr_netio_lingering_close(nstrm, linger);
  fail_unless(res == 0, "Failed to close stream: %s", strerror(errno));

  /* Open/close DATA stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_DATA, fd, PR_NETIO_IO_RD);
  res = pr_netio_lingering_close(nstrm, linger);
  fail_unless(res == 0, "Failed to close stream: %s", strerror(errno));

  /* Open/close OTHR stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_OTHR, fd, PR_NETIO_IO_RD);
  res = pr_netio_lingering_close(nstrm, linger);
  fail_unless(res == 0, "Failed to close stream: %s", strerror(errno));
}
END_TEST

START_TEST (netio_reopen_test) {
  pr_netio_stream_t *nstrm, *nstrm2;
  int res, fd = -1;

  nstrm2 = pr_netio_reopen(NULL, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm2 == NULL, "Failed to handle null stream argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  /* Open/reopen/close CTRL stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_RD);
  nstrm->strm_type = 7777;

  nstrm2 = pr_netio_reopen(nstrm, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm2 == NULL, "Failed to handle unknown stream type argument");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM, got %s (%d)",
    strerror(errno), errno);

  nstrm->strm_type = PR_NETIO_STRM_CTRL;
  nstrm2 = pr_netio_reopen(nstrm, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm2 != NULL, "Failed to reopen ctrl stream: %s",
    strerror(errno));

  /* Open/reopen/close DATA stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_DATA, fd, PR_NETIO_IO_RD);
  nstrm2 = pr_netio_reopen(nstrm, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm2 != NULL, "Failed to reopen data stream: %s",
    strerror(errno));

  res = pr_netio_close(nstrm);
  fail_unless(res == -1, "Failed to handle bad file descriptor");
  fail_unless(errno == EBADF, "Failed to set errno to EBADF, got %s (%d)",
    strerror(errno), errno);

  /* Open/reopen/close OTHR stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_OTHR, fd, PR_NETIO_IO_RD);
  nstrm2 = pr_netio_reopen(nstrm, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm2 != NULL, "Failed to reopen othr stream: %s",
    strerror(errno));

  res = pr_netio_close(nstrm);
  fail_unless(res == -1, "Failed to handle bad file descriptor");
  fail_unless(errno == EBADF, "Failed to set errno to EBADF, got %s (%d)",
    strerror(errno), errno);
}
END_TEST

START_TEST (netio_buffer_alloc_test) {
  pr_buffer_t *pbuf;
  pr_netio_stream_t *nstrm;

  pbuf = pr_netio_buffer_alloc(NULL);
  fail_unless(pbuf == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  nstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);

  pbuf = pr_netio_buffer_alloc(nstrm);
  fail_unless(pbuf != NULL, "Failed to allocate buffer: %s", strerror(errno));

  pr_netio_close(nstrm);
}
END_TEST

START_TEST (netio_telnet_gets_args_test) {
  char *buf, *res;
  pr_netio_stream_t *in, *out;

  res = pr_netio_telnet_gets(NULL, 0, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  buf = "";
  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  res = pr_netio_telnet_gets(buf, 0, in, out);
  fail_unless(res == NULL,
    "Failed to handle zero-length buffer length argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  res = pr_netio_telnet_gets(buf, 1, NULL, out);
  fail_unless(res == NULL, "Failed to handle null input stream argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  res = pr_netio_telnet_gets(buf, 1, in, NULL);
  fail_unless(res == NULL, "Failed to handle null output stream argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  pr_netio_close(in);
  pr_netio_close(out);
}
END_TEST

START_TEST (netio_telnet_gets_single_line_test) {
  char buf[256], *cmd, *res;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;
  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", cmd);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strcmp(buf, cmd) == 0, "Expected string '%s', got '%s'", cmd,
    buf);
  fail_unless(pbuf->remaining == (size_t) xfer_bufsz,
    "Expected %d remaining bytes, got %lu", xfer_bufsz,
    (unsigned long) pbuf->remaining);
}
END_TEST

START_TEST (netio_telnet_gets_multi_line_test) {
  char buf[256], *cmd, *first_cmd, *second_cmd, *res;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  /* Note: the line terminator in Telnet is CRLF, not just a bare LF. */
  cmd = "Hello, World!\r\nHow are you?\r\n";
  first_cmd = "Hello, World!\n";
  second_cmd = "How are you?\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;
  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", cmd);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strcmp(buf, first_cmd) == 0, "Expected string '%s', got '%s'",
    first_cmd, buf);

  memset(buf, '\0', sizeof(buf));
  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strcmp(buf, second_cmd) == 0, "Expected string '%s', got '%s'",
    second_cmd, buf);

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(pbuf->remaining == (size_t) xfer_bufsz,
    "Expected %d remaining bytes, got %lu", xfer_bufsz,
    (unsigned long) pbuf->remaining);
}
END_TEST

START_TEST (netio_telnet_gets_no_newline_test) {
  char buf[8], *cmd, *res;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, World!";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;
  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", cmd);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res == NULL, "Read in string unexpectedly, got '%s'", buf);
  fail_unless(xerrno == E2BIG, "Failed to set errno to E2BIG, got (%d) %s",
    xerrno, strerror(xerrno));
}
END_TEST

START_TEST (netio_telnet_gets_telnet_will_test) {
  char buf[256], *cmd, *res, telnet_opt;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, out_fd, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);

  out_fd = open_tmpfile();
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, out_fd, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  telnet_opt = 7;
  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %c%c%cWorld!\n", TELNET_IAC,
    TELNET_WILL, telnet_opt);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strcmp(buf, cmd) == 0, "Expected string '%s', got '%s'", cmd,
    buf);

  /* Rewind the output stream fd. */
  lseek(out_fd, 0, SEEK_SET);
  len = read(out_fd, buf, sizeof(buf)-1);
  pr_netio_close(out);

  fail_unless(len == 3, "Expected to read 3 bytes from output stream, got %d",
    len);
  fail_unless(buf[0] == (char) TELNET_IAC, "Expected IAC at index 0, got %d",
    buf[0]);
  fail_unless(buf[1] == (char) TELNET_DONT, "Expected DONT at index 1, got %d",
    buf[1]);
  fail_unless(buf[2] == telnet_opt, "Expected opt '%c' at index 2, got %c",
    telnet_opt, buf[2]);

  test_cleanup();
}
END_TEST

START_TEST (netio_telnet_gets_telnet_bare_will_test) {
  char buf[256], *cmd, *res, telnet_opt;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  telnet_opt = 7;
  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %c%cWorld!\n", TELNET_WILL,
    telnet_opt);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strncmp(buf, cmd, 7) == 0, "Expected string '%*s', got '%*s'",
    7, cmd, 7, buf);
  fail_unless(buf[7] == (char) TELNET_WILL, "Expected WILL at index 7, got %d",
    buf[7]);
  fail_unless(buf[8] == telnet_opt, "Expected Telnet opt %c at index 8, got %d",
    telnet_opt, buf[8]);
  fail_unless(strcmp(buf + 9, cmd + 7) == 0, "Expected string '%s', got '%s'",
    cmd + 7, buf + 9);
}
END_TEST

START_TEST (netio_telnet_gets_telnet_will_multi_read_test) {
  char buf[256], *cmd, *res, telnet_opt;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, out_fd, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);

  out_fd = open_tmpfile();
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, out_fd, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %c%c", TELNET_IAC,
    TELNET_WILL);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strncmp(buf, cmd, 7) == 0, "Expected string '%*s', got '%*s'",
    7, cmd, 7, buf);

  /* Fill up the input stream's buffer with the rest of the Telnet WILL
   * sequence.
   */
  telnet_opt = 7;
  len = snprintf(pbuf->buf, pbuf->buflen-1, "%cWorld!\n", telnet_opt);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  /* Read again, to see if the state was preserved across multiple calls
   * to pr_netio_telnet_gets().
   */
  res = pr_netio_telnet_gets(buf + 7, sizeof(buf)-8, in, out);
  xerrno = errno;

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strcmp(buf, cmd) == 0, "Expected string '%s', got '%s'",
    cmd, buf);

  pr_netio_close(in);

  /* Rewind the output stream fd. */
  lseek(out_fd, 0, SEEK_SET);
  len = read(out_fd, buf, sizeof(buf)-1);
  pr_netio_close(out);

  fail_unless(len == 3, "Expected to read 3 bytes from output stream, got %d",
    len);
  fail_unless(buf[0] == (char) TELNET_IAC, "Expected IAC at index 0, got %d",
    buf[0]);
  fail_unless(buf[1] == (char) TELNET_DONT, "Expected DONT at index 1, got %d",
    buf[1]);
  fail_unless(buf[2] == telnet_opt, "Expected %c at index 2, got %d",
    telnet_opt, buf[2]);

  test_cleanup();
}
END_TEST

START_TEST (netio_telnet_gets_telnet_wont_test) {
  char buf[256], *cmd, *res, telnet_opt;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, out_fd, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);

  out_fd = open_tmpfile();
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, out_fd, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  telnet_opt = 7;
  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %c%c%cWorld!\n", TELNET_IAC,
    TELNET_WONT, telnet_opt);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strcmp(buf, cmd) == 0, "Expected string '%s', got '%s'", cmd,
    buf);

  /* Rewind the output stream fd. */
  lseek(out_fd, 0, SEEK_SET);
  len = read(out_fd, buf, sizeof(buf)-1);
  pr_netio_close(out);

  fail_unless(len == 3, "Expected to read 3 bytes from output stream, got %d",
    len);
  fail_unless(buf[0] == (char) TELNET_IAC, "Expected IAC at index 0, got %d",
    buf[0]);
  fail_unless(buf[1] == (char) TELNET_DONT, "Expected DONT at index 1, got %d",
    buf[1]);
  fail_unless(buf[2] == telnet_opt, "Expected opt '%c' at index 2, got %c",
    telnet_opt, buf[2]);

  test_cleanup();
}
END_TEST

START_TEST (netio_telnet_gets_telnet_bare_wont_test) {
  char buf[256], *cmd, *res, telnet_opt;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  telnet_opt = 7;
  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %c%cWorld!\n", TELNET_WONT,
    telnet_opt);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strncmp(buf, cmd, 7) == 0, "Expected string '%*s', got '%*s'",
    7, cmd, 7, buf);
  fail_unless(buf[7] == (char) TELNET_WONT, "Expected WONT at index 7, got %d",
    buf[7]);
  fail_unless(buf[8] == telnet_opt, "Expected Telnet opt %c at index 8, got %d",
    telnet_opt, buf[8]);
  fail_unless(strcmp(buf + 9, cmd + 7) == 0, "Expected string '%s', got '%s'",
    cmd + 7, buf + 9);
}
END_TEST

START_TEST (netio_telnet_gets_telnet_do_test) {
  char buf[256], *cmd, *res, telnet_opt;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, out_fd, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);

  out_fd = open_tmpfile();
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, out_fd, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  telnet_opt = 7;
  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %c%c%cWorld!\n", TELNET_IAC,
    TELNET_DO, telnet_opt);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strcmp(buf, cmd) == 0, "Expected string '%s', got '%s'", cmd,
    buf);

  /* Rewind the output stream fd. */
  lseek(out_fd, 0, SEEK_SET);
  len = read(out_fd, buf, sizeof(buf)-1);
  pr_netio_close(out);

  fail_unless(len == 3, "Expected to read 3 bytes from output stream, got %d",
    len);
  fail_unless(buf[0] == (char) TELNET_IAC, "Expected IAC at index 0, got %d",
    buf[0]);
  fail_unless(buf[1] == (char) TELNET_WONT, "Expected WONT at index 1, got %d",
    buf[1]);
  fail_unless(buf[2] == telnet_opt, "Expected opt '%c' at index 2, got %c",
    telnet_opt, buf[2]);

  test_cleanup();
}
END_TEST

START_TEST (netio_telnet_gets_telnet_bare_do_test) {
  char buf[256], *cmd, *res, telnet_opt;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  telnet_opt = 7;
  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %c%cWorld!\n", TELNET_DO,
    telnet_opt);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strncmp(buf, cmd, 7) == 0, "Expected string '%*s', got '%*s'",
    7, cmd, 7, buf);
  fail_unless(buf[7] == (char) TELNET_DO, "Expected DO at index 7, got %d",
    buf[7]);
  fail_unless(buf[8] == telnet_opt, "Expected Telnet opt %c at index 8, got %d",
    telnet_opt, buf[8]);
  fail_unless(strcmp(buf + 9, cmd + 7) == 0, "Expected string '%s', got '%s'",
    cmd + 7, buf + 9);
}
END_TEST

START_TEST (netio_telnet_gets_telnet_dont_test) {
  char buf[256], *cmd, *res, telnet_opt;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, out_fd, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);

  out_fd = open_tmpfile();
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, out_fd, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  telnet_opt = 7;
  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %c%c%cWorld!\n", TELNET_IAC,
    TELNET_DONT, telnet_opt);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strcmp(buf, cmd) == 0, "Expected string '%s', got '%s'", cmd,
    buf);

  /* Rewind the output stream fd. */
  lseek(out_fd, 0, SEEK_SET);
  len = read(out_fd, buf, sizeof(buf)-1);
  pr_netio_close(out);

  fail_unless(len == 3, "Expected to read 3 bytes from output stream, got %d",
    len);
  fail_unless(buf[0] == (char) TELNET_IAC, "Expected IAC at index 0, got %d",
    buf[0]);
  fail_unless(buf[1] == (char) TELNET_WONT, "Expected WONT at index 1, got %d",
    buf[1]);
  fail_unless(buf[2] == telnet_opt, "Expected opt '%c' at index 2, got %c",
    telnet_opt, buf[2]);

  test_cleanup();
}
END_TEST

START_TEST (netio_telnet_gets_telnet_bare_dont_test) {
  char buf[256], *cmd, *res, telnet_opt;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  telnet_opt = 7;
  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %c%cWorld!\n", TELNET_DONT,
    telnet_opt);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strncmp(buf, cmd, 7) == 0, "Expected string '%*s', got '%*s'",
    7, cmd, 7, buf);
  fail_unless(buf[7] == (char) TELNET_DONT, "Expected DONT at index 7, got %d",
    buf[7]);
  fail_unless(buf[8] == telnet_opt, "Expected Telnet opt %c at index 8, got %d",
    telnet_opt, buf[8]);
  fail_unless(strcmp(buf + 9, cmd + 7) == 0, "Expected string '%s', got '%s'",
    cmd + 7, buf + 9);
}
END_TEST

START_TEST (netio_telnet_gets_telnet_ip_test) {
  char buf[256], *cmd, *res;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %c%cWorld!\n", TELNET_IAC,
    TELNET_IP);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strcmp(buf, cmd) == 0, "Expected string '%s', got '%s'", cmd,
    buf);
}
END_TEST

START_TEST (netio_telnet_gets_telnet_bare_ip_test) {
  char buf[256], *cmd, *res;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %cWorld!\n", TELNET_IP);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strncmp(buf, cmd, 7) == 0, "Expected string '%*s', got '%*s'",
    7, cmd, 7, buf);
  fail_unless(buf[7] == (char) TELNET_IP, "Expected IP at index 7, got %d",
    buf[7]);
  fail_unless(strcmp(buf + 8, cmd + 7) == 0, "Expected string '%s', got '%s'",
    cmd + 7, buf + 8);
}
END_TEST

START_TEST (netio_telnet_gets_telnet_dm_test) {
  char buf[256], *cmd, *res;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %c%cWorld!\n", TELNET_IAC,
    TELNET_DM);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strcmp(buf, cmd) == 0, "Expected string '%s', got '%s'", cmd,
    buf);
}
END_TEST

START_TEST (netio_telnet_gets_telnet_bare_dm_test) {
  char buf[256], *cmd, *res;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %cWorld!\n", TELNET_DM);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strncmp(buf, cmd, 7) == 0, "Expected string '%*s', got '%*s'",
    7, cmd, 7, buf);
  fail_unless(buf[7] == (char) TELNET_DM, "Expected DM at index 7, got %d",
    buf[7]);
  fail_unless(strcmp(buf + 8, cmd + 7) == 0, "Expected string '%s', got '%s'",
    cmd + 7, buf + 8);
}
END_TEST

START_TEST (netio_telnet_gets_telnet_single_iac_test) {
  char buf[256], *cmd, *res;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %cWorld!\n", TELNET_IAC);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strncmp(buf, cmd, 7) == 0, "Expected string '%*s', got '%*s'",
    7, cmd, 7, buf);
  fail_unless(buf[7] == (char) TELNET_IAC, "Expected IAC at index 7, got %d",
    buf[7]);
  fail_unless(strcmp(buf + 8, cmd + 7) == 0, "Expected string '%s', got '%s'",
    cmd + 7, buf + 8);
}
END_TEST

START_TEST (netio_telnet_gets_bug3521_test) {
  char buf[10], *res, telnet_opt;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  telnet_opt = 7;
  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %c%c%c%cWorld!\n",
    TELNET_IAC, TELNET_IAC, TELNET_WILL, telnet_opt);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res == NULL, "Expected null");
  fail_unless(xerrno == E2BIG, "Failed to set errno to E2BIG, got %s (%d)",
    strerror(xerrno), xerrno);
}
END_TEST

START_TEST (netio_telnet_gets_bug3697_test) {
  char buf[256], *cmd, *res;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  len = snprintf(pbuf->buf, pbuf->buflen-1, "Hello, %c%cWorld!\n", TELNET_IAC,
    TELNET_IAC);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strncmp(buf, cmd, 7) == 0, "Expected string '%*s', got '%*s'",
    7, cmd, 7, buf);
  fail_unless(buf[7] == (char) TELNET_IAC, "Expected IAC at index 7, got %d",
    buf[7]);
  fail_unless(strcmp(buf + 8, cmd + 7) == 0, "Expected string '%s', got '%s'",
    cmd + 7, buf + 8);
}
END_TEST

START_TEST (netio_telnet_gets_eof_test) {
  char buf[256], *cmd, *res;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, World!";

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;

  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", cmd);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  /* In this scenario, we have not supplied an LF, but the resulting buffer
   * is terminated with a NUL because of the end-of-stream (or error) checks
   * in pr_netio_telnet_gets(), when we read the input stream for more data
   * looking for that LF.
   */
  res = pr_netio_telnet_gets(buf, strlen(cmd) + 2, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res != NULL, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strcmp(buf, cmd) == 0, "Expected string '%s', got '%s'", cmd,
    buf);
}
END_TEST

START_TEST (netio_telnet_gets2_single_line_test) {
  int res;
  char buf[256], *cmd;
  size_t cmd_len;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int len, xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, World!\n";
  cmd_len = strlen(cmd);

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;
  len = snprintf(pbuf->buf, pbuf->buflen-1, "%s", cmd);
  pbuf->remaining = pbuf->buflen - len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets2(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res > 0, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strcmp(buf, cmd) == 0, "Expected string '%s', got '%s'", cmd,
    buf);

  fail_unless((size_t) res == cmd_len, "Expected length %lu, got %d",
    (unsigned long) cmd_len, res);
  fail_unless(pbuf->remaining == (size_t) xfer_bufsz,
    "Expected %d remaining bytes, got %lu", xfer_bufsz,
    (unsigned long) pbuf->remaining);
}
END_TEST

START_TEST (netio_telnet_gets2_single_line_crnul_test) {
  int res;
  char buf[256], *cmd;
  size_t cmd_len;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  /* See Bug#4167.  We cannot use strlen(3) due to the embedded NUL. */
  cmd = "Hello, \015\000World!\n";
  cmd_len = 14;

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;
  memcpy(pbuf->buf, cmd, cmd_len);
  pbuf->remaining = pbuf->buflen - cmd_len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets2(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res > 0, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strcmp(buf, cmd) == 0, "Expected string '%s', got '%s'", cmd,
    buf);

  fail_unless((size_t) res == cmd_len, "Expected length %lu, got %d",
    (unsigned long) cmd_len, res);
  fail_unless(pbuf->remaining == (size_t) xfer_bufsz,
    "Expected %d remaining bytes, got %lu", xfer_bufsz,
    (unsigned long) pbuf->remaining);
}
END_TEST

START_TEST (netio_telnet_gets2_single_line_lf_test) {
  int res;
  char buf[256], *cmd;
  size_t cmd_len;
  pr_netio_stream_t *in, *out;
  pr_buffer_t *pbuf;
  int xerrno;

  in = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_RD);
  out = pr_netio_open(p, PR_NETIO_STRM_CTRL, -1, PR_NETIO_IO_WR);

  cmd = "Hello, \012World!\n";
  cmd_len = strlen(cmd);

  pr_netio_buffer_alloc(in);
  pbuf = in->strm_buf;
  memcpy(pbuf->buf, cmd, cmd_len);
  pbuf->remaining = pbuf->buflen - cmd_len;
  pbuf->current = pbuf->buf;

  buf[sizeof(buf)-1] = '\0';

  res = pr_netio_telnet_gets2(buf, sizeof(buf)-1, in, out);
  xerrno = errno;

  pr_netio_close(in);
  pr_netio_close(out);

  fail_unless(res > 0, "Failed to get string from stream: (%d) %s",
    xerrno, strerror(xerrno));
  fail_unless(strcmp(buf, cmd) == 0, "Expected string '%s', got '%s'", cmd,
    buf);

  fail_unless((size_t) res == cmd_len, "Expected length %lu, got %d",
    (unsigned long) cmd_len, res);
  fail_unless(pbuf->remaining == (size_t) xfer_bufsz,
    "Expected %d remaining bytes, got %lu", xfer_bufsz,
    (unsigned long) pbuf->remaining);
}
END_TEST

static int netio_poll_cb(pr_netio_stream_t *nstrm) {
  /* Always return >0, to indicate that we haven't timed out, AND that there
   * is a writable fd available.
   */
  return 7;
}

static int netio_read_eof = FALSE;
static int netio_read_epipe = FALSE;

static int netio_read_cb(pr_netio_stream_t *nstrm, char *buf, size_t buflen) {
  const char *text;
  int res;

  if (netio_read_eof) {
    netio_read_eof = FALSE;
    return 0;
  }

  if (netio_read_epipe) {
    netio_read_epipe = FALSE;
    errno = EPIPE;
    return -1;
  }

  text = "Hello, World!\r\n";
  sstrncpy(buf, text, buflen);

  /* Make sure the next read returns EOF. */
  netio_read_eof = TRUE;

  res = strlen(text);
  return res;
}

static int netio_write_epipe = FALSE;

static int netio_write_cb(pr_netio_stream_t *nstrm, char *buf, size_t buflen) {
  if (netio_write_epipe) {
    netio_write_epipe = FALSE;
    errno = EPIPE;
    return -1;
  }

  return buflen;
}

static int netio_read_from_stream(int strm_type) {
  int fd = 2, res;
  char buf[1024], *expected_text;
  size_t expected_sz;
  pr_netio_stream_t *nstrm;

  res = pr_netio_read(NULL, NULL, 0, 0);
  if (res == 0) {
    errno = EINVAL;
    return -1;
  }

  nstrm = pr_netio_open(p, strm_type, fd, PR_NETIO_IO_RD);
  if (nstrm == NULL) {
    int xerrno = errno;

    pr_trace_msg("netio", 1, "error opening custom netio stream: %s",
      strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = pr_netio_read(nstrm, NULL, 0, 0);
  if (res == 0) {
    pr_netio_close(nstrm);
    errno = EINVAL;
    return -1;
  }

  res = pr_netio_read(nstrm, buf, 0, 0);
  if (res == 0) {
    pr_netio_close(nstrm);
    errno = EINVAL;
    return -1;
  }

  expected_text = "Hello, World!\r\n";
  expected_sz = strlen(expected_text);

  memset(buf, '\0', sizeof(buf));
  res = pr_netio_read(nstrm, buf, sizeof(buf)-1, 1);

  if (res != (int) expected_sz) {
    pr_trace_msg("netio", 1, "Expected %lu bytes, got %d",
      (unsigned long) expected_sz, res);
    pr_netio_close(nstrm);

    if (res < 0) {
      return -1;
    }

    errno = EIO;
    return -1;
  }

  if (strcmp(buf, expected_text) != 0) {
    pr_trace_msg("netio", 1, "Expected '%s', got '%s'", expected_text, buf);
    pr_netio_close(nstrm);

    errno = EIO;
    return -1;
  }

  netio_read_eof = TRUE;
  res = pr_netio_read(nstrm, buf, sizeof(buf)-1, 1);
  if (res > 0) {
    pr_trace_msg("netio", 1, "Expected EOF (0), got %d", res);
    pr_netio_close(nstrm);

    errno = EIO;
    return -1;
  }

  netio_read_epipe = TRUE;
  res = pr_netio_read(nstrm, buf, sizeof(buf)-1, sizeof(buf)-1);
  if (res >= 0) {
    pr_trace_msg("netio", 1, "Expected EPIPE (-1), got %d", res);
    pr_netio_close(nstrm);

    errno = EIO;
    return -1;
  }

  mark_point();
  pr_netio_close(nstrm);
  return 0;
}

static int netio_write_to_stream(int strm_type, int use_async) {
  int fd = 2, res;
  char *buf;
  size_t buflen;
  pr_netio_stream_t *nstrm;

  res = pr_netio_write(NULL, NULL, 0);
  if (res == 0) {
    errno = EINVAL;
    return -1;
  }

  nstrm = pr_netio_open(p, strm_type, fd, PR_NETIO_IO_WR);
  if (nstrm == NULL) {
    int xerrno = errno;

    pr_trace_msg("netio", 1, "error opening custom netio stream: %s",
      strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  res = pr_netio_write(nstrm, NULL, 0);
  if (res == 0) {
    pr_netio_close(nstrm);
    errno = EINVAL;
    return -1;
  }

  buf = "Hello, World!\n";
  buflen = strlen(buf);

  res = pr_netio_write(nstrm, buf, 0);
  if (res == 0) {
    pr_netio_close(nstrm);
    errno = EINVAL;
    return -1;
  }

  if (use_async) {
    res = pr_netio_write_async(nstrm, buf, buflen);

  } else {
    res = pr_netio_write(nstrm, buf, buflen);
  }

  if ((size_t) res != buflen) {
    pr_trace_msg("netio", 1, "wrote buffer (%lu bytes), got %d",
      (unsigned long) buflen, res);
    pr_netio_close(nstrm);

    if (res < 0) {
      return -1;
    }

    errno = EIO;
    return -1;
  }

  netio_write_epipe = TRUE;
  res = pr_netio_write(nstrm, buf, buflen);
  if (res >= 0) {
    pr_trace_msg("netio", 1, "Expected EPIPE (-1), got %d", res);
    pr_netio_close(nstrm);
    errno = EIO;
    return -1;
  }

  mark_point();
  pr_netio_close(nstrm);
  return 0;
}

START_TEST (netio_read_test) {
  int res;
  pr_netio_t *netio, *netio2;

  netio = pr_alloc_netio2(p, NULL, "testsuite");
  netio->poll = netio_poll_cb;
  netio->read = netio_read_cb;

  /* Write to control stream */
  res = pr_register_netio(netio, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to register custom ctrl NetIO: %s",
    strerror(errno));

  netio2 = pr_get_netio(PR_NETIO_STRM_CTRL);
  fail_unless(netio2 != NULL, "Failed to get custom ctrl NetIO: %s",
    strerror(errno));
  fail_unless(netio2 == netio, "Expected custom ctrl NetIO %p, got %p",
    netio, netio2);

  res = netio_read_from_stream(PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to read from custom ctrl NetIO: %s",
    strerror(errno));

  mark_point();
  pr_unregister_netio(PR_NETIO_STRM_CTRL);

  /* Read from data stream */
  res = pr_register_netio(netio, PR_NETIO_STRM_DATA);
  fail_unless(res == 0, "Failed to register custom data NetIO: %s",
    strerror(errno));

  netio2 = pr_get_netio(PR_NETIO_STRM_DATA);
  fail_unless(netio2 != NULL, "Failed to get custom data NetIO: %s",
    strerror(errno));
  fail_unless(netio2 == netio, "Expected custom data NetIO %p, got %p",
    netio, netio2);

  res = netio_read_from_stream(PR_NETIO_STRM_DATA);
  fail_unless(res == 0, "Failed to read from custom data NetIO: %s",
    strerror(errno));

  mark_point();
  pr_unregister_netio(PR_NETIO_STRM_DATA);

  /* Read from other stream */
  res = pr_register_netio(netio, PR_NETIO_STRM_OTHR);
  fail_unless(res == 0, "Failed to register custom other NetIO: %s",
    strerror(errno));

  netio2 = pr_get_netio(PR_NETIO_STRM_OTHR);
  fail_unless(netio2 != NULL, "Failed to get custom othr NetIO: %s",
    strerror(errno));
  fail_unless(netio2 == netio, "Expected custom othr NetIO %p, got %p",
    netio, netio2);

  res = netio_read_from_stream(PR_NETIO_STRM_OTHR);
  fail_unless(res == 0, "Failed to read from custom other NetIO: %s",
    strerror(errno));

  mark_point();
  pr_unregister_netio(PR_NETIO_STRM_OTHR);
}
END_TEST

START_TEST (netio_gets_test) {
  int fd = 2, res;
  char *buf, *expected, *text;
  size_t buflen;
  pr_netio_t *netio;
  pr_netio_stream_t *nstrm;

  text = pr_netio_gets(NULL, 0, NULL);
  fail_unless(text == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  netio = pr_alloc_netio2(p, NULL, "testsuite");
  netio->poll = netio_poll_cb;
  netio->read = netio_read_cb;

  res = pr_register_netio(netio, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to register custom ctrl NetIO: %s",
    strerror(errno));

  nstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm != NULL, "Failed to open stream: %s", strerror(errno));

  text = pr_netio_gets(NULL, 0, nstrm);
  fail_unless(text == NULL, "Failed to handle null buffer");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  buflen = 1024;
  buf = pcalloc(p, buflen);

  text = pr_netio_gets(buf, 0, nstrm);
  fail_unless(text == NULL, "Failed to handle zero buffer length");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  expected = "Hello, World!\r\n";
  text = pr_netio_gets(buf, buflen-1, nstrm);
  fail_unless(text != NULL, "Failed to get text: %s", strerror(errno));
  fail_unless(strcmp(text, expected) == 0, "Expected '%s', got '%s'",
    expected, text);

  mark_point();
  pr_unregister_netio(PR_NETIO_STRM_CTRL);
}
END_TEST

START_TEST (netio_write_test) {
  int res;
  pr_netio_t *netio, *netio2;

  netio = pr_alloc_netio2(p, NULL, "testsuite");
  netio->poll = netio_poll_cb;
  netio->write = netio_write_cb;

  /* Write to control stream */
  res = pr_register_netio(netio, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to register custom ctrl NetIO: %s",
    strerror(errno));

  netio2 = pr_get_netio(PR_NETIO_STRM_CTRL);
  fail_unless(netio2 != NULL, "Failed to get custom ctrl NetIO: %s",
    strerror(errno));
  fail_unless(netio2 == netio, "Expected custom ctrl NetIO %p, got %p",
    netio, netio2);

  res = netio_write_to_stream(PR_NETIO_STRM_CTRL, FALSE);
  fail_unless(res == 0, "Failed to write to custom ctrl NetIO: %s",
    strerror(errno));

  mark_point();
  pr_unregister_netio(PR_NETIO_STRM_CTRL);

  /* Write to data stream */
  res = pr_register_netio(netio, PR_NETIO_STRM_DATA);
  fail_unless(res == 0, "Failed to register custom data NetIO: %s",
    strerror(errno));

  netio2 = pr_get_netio(PR_NETIO_STRM_DATA);
  fail_unless(netio2 != NULL, "Failed to get custom data NetIO: %s",
    strerror(errno));
  fail_unless(netio2 == netio, "Expected custom data NetIO %p, got %p",
    netio, netio2);

  res = netio_write_to_stream(PR_NETIO_STRM_DATA, FALSE);
  fail_unless(res == 0, "Failed to write to custom data NetIO: %s",
    strerror(errno));

  mark_point();
  pr_unregister_netio(PR_NETIO_STRM_DATA);

  /* Write to other stream */
  res = pr_register_netio(netio, PR_NETIO_STRM_OTHR);
  fail_unless(res == 0, "Failed to register custom other NetIO: %s",
    strerror(errno));

  netio2 = pr_get_netio(PR_NETIO_STRM_OTHR);
  fail_unless(netio2 != NULL, "Failed to get custom othr NetIO: %s",
    strerror(errno));
  fail_unless(netio2 == netio, "Expected custom othr NetIO %p, got %p",
    netio, netio2);

  res = netio_write_to_stream(PR_NETIO_STRM_OTHR, FALSE);
  fail_unless(res == 0, "Failed to write to custom other NetIO: %s",
    strerror(errno));

  mark_point();
  pr_unregister_netio(PR_NETIO_STRM_OTHR);
}
END_TEST

START_TEST (netio_write_async_test) {
  int res;
  pr_netio_t *netio;

  netio = pr_alloc_netio2(p, NULL, "testsuite");
  netio->poll = netio_poll_cb;
  netio->write = netio_write_cb;

  res = pr_register_netio(netio, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to register custom ctrl NetIO: %s",
    strerror(errno));

  res = netio_write_to_stream(PR_NETIO_STRM_CTRL, TRUE);
  fail_unless(res == 0, "Failed to write to custom ctrl NetIO: %s",
    strerror(errno));

  mark_point();
  pr_unregister_netio(PR_NETIO_STRM_CTRL);
}
END_TEST

static int netio_print_to_stream(int strm_type, int use_async) {
  int fd = 2, res;
  char *buf;
  size_t buflen;
  pr_netio_stream_t *nstrm;

  nstrm = pr_netio_open(p, strm_type, fd, PR_NETIO_IO_WR);
  if (nstrm == NULL) {
    int xerrno = errno;

    pr_trace_msg("netio", 1, "error opening custom netio stream: %s",
      strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  buf = "Hello, World!\n";
  buflen = strlen(buf);

  if (use_async) {
    res = pr_netio_printf_async(nstrm, "%s", buf);

  } else {
    res = pr_netio_printf(nstrm, "%s", buf);
  }

  if ((size_t) res != buflen) {
    pr_trace_msg("netio", 1, "printed buffer (%lu bytes), got %d",
      (unsigned long) buflen, res);
    pr_netio_close(nstrm);

    if (res < 0) {
      return -1;
    }

    errno = EIO;
    return -1;
  }

  mark_point();
  pr_netio_close(nstrm);
  return 0;
}

START_TEST (netio_printf_test) {
  int res;
  pr_netio_t *netio;

  netio = pr_alloc_netio2(p, NULL, "testsuite");
  netio->poll = netio_poll_cb;
  netio->write = netio_write_cb;

  res = pr_register_netio(netio, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to register custom ctrl NetIO: %s",
    strerror(errno));

  res = netio_print_to_stream(PR_NETIO_STRM_CTRL, FALSE);
  fail_unless(res == 0, "Failed to print to custom ctrl NetIO: %s",
    strerror(errno));

  mark_point();
  pr_unregister_netio(PR_NETIO_STRM_CTRL);
}
END_TEST

START_TEST (netio_printf_async_test) {
  int res;
  pr_netio_t *netio;

  netio = pr_alloc_netio2(p, NULL, "testsuite");
  netio->poll = netio_poll_cb;
  netio->write = netio_write_cb;

  res = pr_register_netio(netio, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to register custom ctrl NetIO: %s",
    strerror(errno));

  res = netio_print_to_stream(PR_NETIO_STRM_CTRL, TRUE);
  fail_unless(res == 0, "Failed to print to custom ctrl NetIO: %s",
    strerror(errno));

  mark_point();
  pr_unregister_netio(PR_NETIO_STRM_CTRL);
}
END_TEST

START_TEST (netio_abort_test) {
  pr_netio_stream_t *nstrm;
  int fd = -1;

  mark_point();
  pr_netio_abort(NULL);

  /* open/abort/close CTRL stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm != NULL, "Failed to open ctrl stream on fd %d: %s", fd,
    strerror(errno));

  pr_netio_abort(nstrm);
  fail_unless(nstrm->strm_flags & PR_NETIO_SESS_ABORT,
    "Failed to set PR_NETIO_SESS_ABORT flags on ctrl stream");

  pr_netio_close(nstrm);

  /* open/abort/close DATA stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_DATA, fd, PR_NETIO_IO_WR);
  fail_unless(nstrm != NULL, "Failed to open data stream on fd %d: %s", fd,
    strerror(errno));

  pr_netio_abort(nstrm);
  fail_unless(nstrm->strm_flags & PR_NETIO_SESS_ABORT,
    "Failed to set PR_NETIO_SESS_ABORT flags on data stream");

  pr_netio_close(nstrm);

  /* open/abort/close OTHR stream */
  nstrm = pr_netio_open(p, PR_NETIO_STRM_OTHR, fd, PR_NETIO_IO_WR);
  fail_unless(nstrm != NULL, "Failed to open othr stream on fd %d: %s", fd,
    strerror(errno));

  pr_netio_abort(nstrm);
  fail_unless(nstrm->strm_flags & PR_NETIO_SESS_ABORT,
    "Failed to set PR_NETIO_SESS_ABORT flags on othr stream");

  pr_netio_close(nstrm);
}
END_TEST

static int netio_close_cb(pr_netio_stream_t *nstrm) {
  return 0;
}

START_TEST (netio_lingering_abort_test) {
  pr_netio_t *netio;
  pr_netio_stream_t *nstrm;
  int fd = 0, res;
  long linger = 0L;

  mark_point();
  res = pr_netio_lingering_abort(NULL, linger);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  netio = pr_alloc_netio2(p, NULL, "testsuite");
  netio->close = netio_close_cb;

  /* open/abort/close CTRL stream */
  res = pr_register_netio(netio, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to register custom ctrl NetIO: %s",
    strerror(errno));

  nstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm != NULL, "Failed to open ctrl stream on fd %d: %s", fd,
    strerror(errno));

  res = pr_netio_lingering_abort(nstrm, linger);
  fail_unless(res == 0, "Failed to set lingering abort on ctrl stream: %s",
    strerror(errno));

  fail_unless(nstrm->strm_flags & PR_NETIO_SESS_ABORT,
    "Failed to set PR_NETIO_SESS_ABORT flags on ctrl stream");

  pr_netio_close(nstrm);
  pr_unregister_netio(PR_NETIO_STRM_CTRL);

  /* open/abort/close DATA stream */
  res = pr_register_netio(netio, PR_NETIO_STRM_DATA);
  fail_unless(res == 0, "Failed to register custom data NetIO: %s",
    strerror(errno));

  nstrm = pr_netio_open(p, PR_NETIO_STRM_DATA, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm != NULL, "Failed to open data stream on fd %d: %s", fd,
    strerror(errno));

  res = pr_netio_lingering_abort(nstrm, linger);
  fail_unless(res == 0, "Failed to set lingering abort on data stream: %s",
    strerror(errno));

  fail_unless(nstrm->strm_flags & PR_NETIO_SESS_ABORT,
    "Failed to set PR_NETIO_SESS_ABORT flags on data stream");

  pr_netio_close(nstrm);
  pr_unregister_netio(PR_NETIO_STRM_DATA);

  /* open/abort/close OTHR stream */
  res = pr_register_netio(netio, PR_NETIO_STRM_OTHR);
  fail_unless(res == 0, "Failed to register custom othr NetIO: %s",
    strerror(errno));

  nstrm = pr_netio_open(p, PR_NETIO_STRM_OTHR, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm != NULL, "Failed to open othr stream on fd %d: %s", fd,
    strerror(errno));

  res = pr_netio_lingering_abort(nstrm, linger);
  fail_unless(res == 0, "Failed to set lingering abort on othr stream: %s",
    strerror(errno));

  fail_unless(nstrm->strm_flags & PR_NETIO_SESS_ABORT,
    "Failed to set PR_NETIO_SESS_ABORT flags on othr stream");

  pr_netio_close(nstrm);
  pr_unregister_netio(PR_NETIO_STRM_OTHR);
}
END_TEST

START_TEST (netio_poll_interval_test) {
  pr_netio_stream_t *nstrm;
  int fd = -1;
  unsigned int interval = 3;

  mark_point();
  pr_netio_set_poll_interval(NULL, 0);

  nstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm != NULL, "Failed to open ctrl stream on fd %d: %s", fd,
    strerror(errno));

  pr_netio_set_poll_interval(nstrm, interval); 
  fail_unless(nstrm->strm_interval == interval,
    "Expected stream interval %u, got %u", interval, nstrm->strm_interval);
  fail_unless(nstrm->strm_flags & PR_NETIO_SESS_INTR,
    "Failed to set PR_NETIO_SESS_INTR stream flag");

  mark_point();
  pr_netio_reset_poll_interval(NULL);

  pr_netio_reset_poll_interval(nstrm);
  fail_if(nstrm->strm_flags & PR_NETIO_SESS_INTR,
    "Failed to clear PR_NETIO_SESS_INTR stream flag");

  (void) pr_netio_close(nstrm);
}
END_TEST

static int netio_shutdown_cb(pr_netio_stream_t *nstrm, int how) {
  return 0;
}

START_TEST (netio_shutdown_test) {
  pr_netio_t *netio;
  pr_netio_stream_t *nstrm;
  int fd = 0, how = SHUT_RD, res;

  mark_point();
  res = pr_netio_shutdown(NULL, how);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  netio = pr_alloc_netio2(p, NULL, "testsuite");
  netio->close = netio_close_cb;
  netio->shutdown = netio_shutdown_cb;

  /* open/shutdown/close CTRL stream */
  res = pr_register_netio(netio, PR_NETIO_STRM_CTRL);
  fail_unless(res == 0, "Failed to register custom ctrl NetIO: %s",
    strerror(errno));

  nstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm != NULL, "Failed to open ctrl stream on fd %d: %s", fd,
    strerror(errno));

  res = pr_netio_shutdown(nstrm, how);
  fail_unless(res == 0, "Failed to shutdown ctrl stream: %s", strerror(errno));

  pr_netio_close(nstrm);
  pr_unregister_netio(PR_NETIO_STRM_CTRL);

  /* open/shutdown/close DATA stream */
  res = pr_register_netio(netio, PR_NETIO_STRM_DATA);
  fail_unless(res == 0, "Failed to register custom data NetIO: %s",
    strerror(errno));

  nstrm = pr_netio_open(p, PR_NETIO_STRM_DATA, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm != NULL, "Failed to open data stream on fd %d: %s", fd,
    strerror(errno));

  res = pr_netio_shutdown(nstrm, how);
  fail_unless(res == 0, "Failed to shutdown ctrl stream: %s", strerror(errno));

  pr_netio_close(nstrm);
  pr_unregister_netio(PR_NETIO_STRM_DATA);

  /* open/shutdown/close OTHR stream */
  res = pr_register_netio(netio, PR_NETIO_STRM_OTHR);
  fail_unless(res == 0, "Failed to register custom othr NetIO: %s",
    strerror(errno));

  nstrm = pr_netio_open(p, PR_NETIO_STRM_OTHR, fd, PR_NETIO_IO_RD);
  fail_unless(nstrm != NULL, "Failed to open othr stream on fd %d: %s", fd,
    strerror(errno));

  res = pr_netio_shutdown(nstrm, how);
  fail_unless(res == 0, "Failed to shutdown ctrl stream: %s", strerror(errno));

  pr_netio_close(nstrm);
  pr_unregister_netio(PR_NETIO_STRM_OTHR);
}
END_TEST

Suite *tests_get_netio_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("netio");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, netio_open_test);
  tcase_add_test(testcase, netio_postopen_test);
  tcase_add_test(testcase, netio_close_test);
  tcase_add_test(testcase, netio_lingering_close_test);
  tcase_add_test(testcase, netio_reopen_test);
  tcase_add_test(testcase, netio_buffer_alloc_test);

  tcase_add_test(testcase, netio_telnet_gets_args_test);
  tcase_add_test(testcase, netio_telnet_gets_single_line_test);
  tcase_add_test(testcase, netio_telnet_gets_multi_line_test);
  tcase_add_test(testcase, netio_telnet_gets_no_newline_test);
  tcase_add_test(testcase, netio_telnet_gets_telnet_will_test);
  tcase_add_test(testcase, netio_telnet_gets_telnet_bare_will_test);
  tcase_add_test(testcase, netio_telnet_gets_telnet_will_multi_read_test);
  tcase_add_test(testcase, netio_telnet_gets_telnet_wont_test);
  tcase_add_test(testcase, netio_telnet_gets_telnet_bare_wont_test);
  tcase_add_test(testcase, netio_telnet_gets_telnet_do_test);
  tcase_add_test(testcase, netio_telnet_gets_telnet_bare_do_test);
  tcase_add_test(testcase, netio_telnet_gets_telnet_dont_test);
  tcase_add_test(testcase, netio_telnet_gets_telnet_bare_dont_test);
  tcase_add_test(testcase, netio_telnet_gets_telnet_ip_test);
  tcase_add_test(testcase, netio_telnet_gets_telnet_bare_ip_test);
  tcase_add_test(testcase, netio_telnet_gets_telnet_dm_test);
  tcase_add_test(testcase, netio_telnet_gets_telnet_bare_dm_test);
  tcase_add_test(testcase, netio_telnet_gets_telnet_single_iac_test);
  tcase_add_test(testcase, netio_telnet_gets_bug3521_test);
  tcase_add_test(testcase, netio_telnet_gets_bug3697_test);
  tcase_add_test(testcase, netio_telnet_gets_eof_test);

  tcase_add_test(testcase, netio_telnet_gets2_single_line_test);
  tcase_add_test(testcase, netio_telnet_gets2_single_line_crnul_test);
  tcase_add_test(testcase, netio_telnet_gets2_single_line_lf_test);

  tcase_add_test(testcase, netio_read_test);
  tcase_add_test(testcase, netio_gets_test);
  tcase_add_test(testcase, netio_write_test);
  tcase_add_test(testcase, netio_write_async_test);
  tcase_add_test(testcase, netio_printf_test);
  tcase_add_test(testcase, netio_printf_async_test);
  tcase_add_test(testcase, netio_abort_test);
  tcase_add_test(testcase, netio_lingering_abort_test);
  tcase_add_test(testcase, netio_poll_interval_test);
  tcase_add_test(testcase, netio_shutdown_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
