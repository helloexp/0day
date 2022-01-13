/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2014-2018 The ProFTPD Project team
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

/* Inet API tests */

#include "tests.h"

static pool *p = NULL;

/* Use Google's DNS resolvers by default. */
static const char *dns_resolver = "8.8.8.8";

static void set_up(void) {
  const char *use_resolver = NULL;

  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_netaddr();
  init_netio();
  init_inet();

  use_resolver = getenv("PR_USE_DNS_RESOLVER");
  if (use_resolver != NULL) {
    dns_resolver = use_resolver;
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("inet", 1, 20);
  }

  pr_inet_set_default_family(p, AF_INET);
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("inet", 0, 0);
  }

  pr_inet_set_default_family(p, 0);
  pr_inet_clear();

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

/* Tests */

START_TEST (inet_family_test) {
  int res;

  pr_inet_set_default_family(p, 0);

  res = pr_inet_set_default_family(p, AF_INET);
  fail_unless(res == 0, "Expected previous family 0, got %d", res);

  res = pr_inet_set_default_family(p, 0);
  fail_unless(res == AF_INET, "Expected previous family %d, got %d", AF_INET,
    res);

  /* Restore the default family to AF_INET, for other tests. */
  pr_inet_set_default_family(p, AF_INET);
}
END_TEST

START_TEST (inet_create_conn_test) {
  int sockfd = -2, port = INPORT_ANY;
  conn_t *conn, *conn2;

  conn = pr_inet_create_conn(NULL, sockfd, NULL, port, FALSE);
  fail_unless(conn == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL,
    "Failed to set errno to EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));
  fail_unless(conn->listen_fd == sockfd, "Expected listen_fd %d, got %d",
    sockfd, conn->listen_fd);
  pr_inet_close(p, conn);

  sockfd = -1;
  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));
  fail_unless(conn->listen_fd != sockfd,
    "Expected listen_fd other than %d, got %d",
    sockfd, conn->listen_fd);

  /* Create another conn, with the same port, make sure it fails. */
  conn2 = pr_inet_create_conn(p, sockfd, NULL, conn->local_port, FALSE);
  if (conn2 == NULL) {
    fail_unless(errno == EADDRINUSE, "Expected EADDRINUSE (%d), got %s (%d)",
      EADDRINUSE, strerror(errno), errno);
    pr_inet_close(p, conn2);
  }

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_create_conn_portrange_test) {
  conn_t *conn;

  conn = pr_inet_create_conn_portrange(NULL, NULL, -1, -1);
  fail_unless(conn == NULL, "Failed to handle negative ports");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn_portrange(NULL, NULL, 10, 1);
  fail_unless(conn == NULL, "Failed to handle bad ports");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  conn = pr_inet_create_conn_portrange(p, NULL, 49152, 65534);
  fail_unless(conn != NULL, "Failed to create conn in portrange: %s",
    strerror(errno));
  pr_inet_lingering_close(p, conn, 0L);
}
END_TEST

START_TEST (inet_copy_conn_test) {
  int fd = -1, sockfd = -1, port = INPORT_ANY;
  conn_t *conn, *conn2;
  const char *name;

  conn = pr_inet_copy_conn(NULL, NULL);
  fail_unless(conn == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_copy_conn(p, NULL);
  fail_unless(conn == NULL, "Failed to handle null conn argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  conn2 = pr_inet_copy_conn(p, conn);
  fail_unless(conn2 != NULL, "Failed to copy conn: %s", strerror(errno));

  pr_inet_close(p, conn);
  pr_inet_close(p, conn2);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  name = "127.0.0.1";
  conn->remote_addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(conn->remote_addr != NULL, "Failed to resolve '%s': %s",
    name, strerror(errno));
  conn->remote_name = pstrdup(p, name);
  conn->instrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_RD);
  fail_unless(conn->instrm != NULL, "Failed to open ctrl reading stream: %s",
    strerror(errno));
  conn->outstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_WR);
  fail_unless(conn->instrm != NULL, "Failed to open ctrl writing stream: %s",
    strerror(errno));

  conn2 = pr_inet_copy_conn(p, conn);
  fail_unless(conn2 != NULL, "Failed to copy conn: %s", strerror(errno));

  mark_point();
  pr_inet_lingering_close(NULL, NULL, 0L);

  pr_inet_lingering_close(p, conn, 0L);
  pr_inet_close(p, conn2);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  conn->instrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_RD);
  fail_unless(conn->instrm != NULL, "Failed to open ctrl reading stream: %s",
    strerror(errno));
  conn->outstrm = pr_netio_open(p, PR_NETIO_STRM_CTRL, fd, PR_NETIO_IO_WR);
  fail_unless(conn->instrm != NULL, "Failed to open ctrl writing stream: %s",
    strerror(errno));

  mark_point();
  pr_inet_lingering_abort(NULL, NULL, 0L);

  pr_inet_lingering_abort(p, conn, 0L);
}
END_TEST

START_TEST (inet_set_async_test) {
  int fd, sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;

  res = pr_inet_set_async(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno EINVAL (%d), got '%s' (%d)",
    EINVAL, strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_set_async(p, conn);
  fail_unless(res == 0, "Failed to set conn %p async: %s", conn,
    strerror(errno));

  fd = conn->rfd;
  conn->rfd = 77;
  res = pr_inet_set_async(p, conn);
  fail_unless(res == 0, "Failed to set conn %p async: %s", conn,
    strerror(errno));
  conn->rfd = fd;

  fd = conn->wfd;
  conn->wfd = 78;
  res = pr_inet_set_async(p, conn);
  fail_unless(res == 0, "Failed to set conn %p async: %s", conn,
    strerror(errno));
  conn->wfd = fd;

  fd = conn->listen_fd;
  conn->listen_fd = 79;
  res = pr_inet_set_async(p, conn);
  fail_unless(res == 0, "Failed to set conn %p async: %s", conn,
    strerror(errno));
  conn->listen_fd = fd;

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_set_block_test) {
  int sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn; 

  res = pr_inet_set_block(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno EINVAL (%d), got '%s' (%d)",
    EINVAL, strerror(errno), errno);

  res = pr_inet_set_nonblock(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected errno EINVAL (%d), got '%s' (%d)",
    EINVAL, strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_set_nonblock(p, conn);
  fail_unless(res < 0, "Failed to handle bad socket");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  res = pr_inet_set_block(p, conn);
  fail_unless(res < 0, "Failed to handle bad socket");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_set_proto_cork_test) {
  int res, sockfd = -1;

  res = pr_inet_set_proto_cork(sockfd, TRUE);
  fail_unless(res < 0, "Failed to handle bad socket descriptor");
  fail_unless(errno == EBADF,
    "Failed to set errno to EBADF (%d), got '%s' (%d)", EBADF, strerror(errno),
    errno);
}
END_TEST

START_TEST (inet_set_proto_nodelay_test) {
  int fd, sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;

  res = pr_inet_set_proto_nodelay(NULL, NULL, 1);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_set_proto_nodelay(p, conn, 1);
  fail_unless(res == 0, "Failed to enable nodelay: %s", strerror(errno));

  res = pr_inet_set_proto_nodelay(p, conn, 0);
  fail_unless(res == 0, "Failed to disable nodelay: %s", strerror(errno));

  fd = conn->rfd;
  conn->rfd = 8;
  res = pr_inet_set_proto_nodelay(p, conn, 0);
  fail_unless(res == 0, "Failed to disable nodelay: %s", strerror(errno));
  conn->rfd = fd;

  fd = conn->rfd;
  conn->rfd = -2;
  res = pr_inet_set_proto_nodelay(p, conn, 0);
  fail_unless(res == 0, "Failed to disable nodelay: %s", strerror(errno));
  conn->rfd = fd;

  fd = conn->wfd;
  conn->rfd = 9;
  res = pr_inet_set_proto_nodelay(p, conn, 0);
  fail_unless(res == 0, "Failed to disable nodelay: %s", strerror(errno));
  conn->wfd = fd;

  fd = conn->wfd;
  conn->rfd = -3;
  res = pr_inet_set_proto_nodelay(p, conn, 0);
  fail_unless(res == 0, "Failed to disable nodelay: %s", strerror(errno));
  conn->wfd = fd;

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_set_proto_opts_test) {
  int fd, sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;

  mark_point();
  res = pr_inet_set_proto_opts(NULL, NULL, 1, 1, 1, 1);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  mark_point();
  res = pr_inet_set_proto_opts(p, conn, 1, 1, 1, 1);
  fail_unless(res == 0, "Failed to set proto opts: %s", strerror(errno));

  mark_point();
  fd = conn->rfd;
  conn->rfd = 8;
  res = pr_inet_set_proto_opts(p, conn, 1, 1, 1, 1);
  fail_unless(res == 0, "Failed to set proto opts: %s", strerror(errno));
  conn->rfd = fd;

  mark_point();
  fd = conn->wfd;
  conn->wfd = 9;
  res = pr_inet_set_proto_opts(p, conn, 1, 1, 1, 1);
  fail_unless(res == 0, "Failed to set proto opts: %s", strerror(errno));
  conn->wfd = fd;

  mark_point();
  fd = conn->listen_fd;
  conn->listen_fd = 10;
  res = pr_inet_set_proto_opts(p, conn, 1, 1, 1, 1);
  fail_unless(res == 0, "Failed to set proto opts: %s", strerror(errno));
  conn->listen_fd = fd;

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_set_proto_opts_ipv6_test) {
#ifdef PR_USE_IPV6
  int fd, sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;
  unsigned char use_ipv6;

  use_ipv6 = pr_netaddr_use_ipv6();

  pr_netaddr_enable_ipv6();
  pr_inet_set_default_family(p, AF_INET6);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  mark_point();
  res = pr_inet_set_proto_opts(p, conn, 1, 1, 1, 1);
  fail_unless(res == 0, "Failed to set proto opts: %s", strerror(errno));

  mark_point();
  fd = conn->rfd;
  conn->rfd = 8;
  res = pr_inet_set_proto_opts(p, conn, 1, 1, 1, 1);
  fail_unless(res == 0, "Failed to set proto opts: %s", strerror(errno));
  conn->rfd = fd;

  mark_point();
  fd = conn->wfd;
  conn->wfd = 9;
  res = pr_inet_set_proto_opts(p, conn, 1, 1, 1, 1);
  fail_unless(res == 0, "Failed to set proto opts: %s", strerror(errno));
  conn->wfd = fd;

  mark_point();
  fd = conn->listen_fd;
  conn->listen_fd = 10;
  res = pr_inet_set_proto_opts(p, conn, 1, 1, 1, 1);
  fail_unless(res == 0, "Failed to set proto opts: %s", strerror(errno));
  conn->listen_fd = fd;

  pr_inet_close(p, conn);

  pr_inet_set_default_family(p, AF_INET);
  if (use_ipv6 == FALSE) {
    pr_netaddr_disable_ipv6();
  }
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (inet_set_socket_opts_test) {
  int sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;
  struct tcp_keepalive keepalive;

  res = pr_inet_set_socket_opts(NULL, NULL, 1, 2, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_set_socket_opts(p, conn, 1, 2, NULL);
  fail_unless(res == 0, "Failed to set socket opts: %s", strerror(errno));

  res = pr_inet_set_socket_opts(p, conn, INT_MAX, INT_MAX, NULL);
  fail_unless(res == 0, "Failed to set socket opts: %s", strerror(errno));

  keepalive.keepalive_enabled = 1;
  keepalive.keepalive_idle = 1;
  keepalive.keepalive_count = 2;
  keepalive.keepalive_intvl = 3;
  res = pr_inet_set_socket_opts(p, conn, 1, 2, &keepalive);
  fail_unless(res == 0, "Failed to set socket opts: %s", strerror(errno));

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_listen_test) {
  int fd, mode, sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;

  res = pr_inet_listen(NULL, NULL, 5, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_inet_resetlisten(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  fd = conn->listen_fd;
  conn->listen_fd = 777;
  res = pr_inet_listen(p, conn, 5, 0);
  fail_unless(res < 0, "Succeeded in listening on conn unexpectedly");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  mode = conn->mode;
  res = pr_inet_resetlisten(p, conn);
  fail_unless(res < 0, "Succeeded in resetting listening on conn unexpectedly");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  conn->listen_fd = fd;
  conn->mode = mode;

  res = pr_inet_listen(p, conn, 5, 0);
  fail_unless(res == 0, "Failed to listen on conn: %s", strerror(errno));

  res = pr_inet_resetlisten(p, conn);
  fail_unless(res == 0, "Failed to reset listen mode: %s", strerror(errno));

  res = pr_inet_listen(p, conn, 5, 0);
  fail_unless(res < 0, "Failed to handle already-listening socket");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_connect_ipv4_test) {
  int sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;
  const pr_netaddr_t *addr;

  res = pr_inet_connect(NULL, NULL, NULL, port);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_connect(p, conn, NULL, 180);
  fail_unless(res < 0, "Failed to handle null address");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(addr != NULL, "Failed to resolve '127.0.0.1': %s",
    strerror(errno));

  res = pr_inet_connect(p, conn, addr, 180);
  fail_unless(res < 0, "Connected to 127.0.0.1#180 unexpectedly");
  fail_unless(errno == ECONNREFUSED, "Expected ECONNREFUSED (%d), got %s (%d)",
    ECONNREFUSED, strerror(errno), errno);

#if defined(PR_USE_NETWORK_TESTS)
  addr = pr_netaddr_get_addr(p, dns_resolver, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", dns_resolver,
    strerror(errno));

  res = pr_inet_connect(p, conn, addr, 53);
  if (res < 0) {
    /* Note: We get EINVAL here because the socket already tried (and failed)
     * to connect to a different address.  Interestingly, trying to connect(2)
     * using that same fd to a different address yields EINVAL.
     */
    fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
      strerror(errno), errno);
  }
  pr_inet_close(p, conn);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_connect(p, conn, addr, 53);
  fail_if(res < 0, "Failed to connect to %s#53: %s", dns_resolver,
    strerror(errno));

  res = pr_inet_connect(p, conn, addr, 53);
  fail_unless(res < 0, "Failed to connect to %s#53: %s", dns_resolver,
    strerror(errno));
  fail_unless(errno == EISCONN, "Expected EISCONN (%d), got %s (%d)",
    EISCONN, strerror(errno), errno);
  pr_inet_close(p, conn);
#endif
}
END_TEST

START_TEST (inet_connect_ipv6_test) {
#ifdef PR_USE_IPV6
  int sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;
  const pr_netaddr_t *addr;
  unsigned char use_ipv6;

  use_ipv6 = pr_netaddr_use_ipv6();

  pr_netaddr_enable_ipv6();
  pr_inet_set_default_family(p, AF_INET6);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  addr = pr_netaddr_get_addr(p, "::1", NULL);
  fail_unless(addr != NULL, "Failed to resolve '::1': %s",
    strerror(errno));

  res = pr_inet_connect(p, conn, addr, 180);
  fail_unless(res < 0, "Connected to ::1#180 unexpectedly");
  fail_unless(errno == ECONNREFUSED || errno == ENETUNREACH || errno == EADDRNOTAVAIL,
    "Expected ECONNREFUSED (%d), ENETUNREACH (%d), or EADDRNOTAVAIL (%d), got %s (%d)",
    ECONNREFUSED, ENETUNREACH, EADDRNOTAVAIL, strerror(errno), errno);

#if defined(PR_USE_NETWORK_TESTS)
  /* Try connecting to Google's DNS server. */

  addr = pr_netaddr_get_addr(p, "2001:4860:4860::8888", NULL);
  fail_unless(addr != NULL, "Failed to resolve '2001:4860:4860::8888': %s",
    strerror(errno));

  res = pr_inet_connect(p, conn, addr, 53);
  if (res < 0) {
    /* Note: We get EINVAL here because the socket already tried (and failed)
     * to connect to a different address.  Interestingly, trying to connect(2)
     * using that same fd to a different address yields EINVAL.
     */
    fail_unless(errno == EINVAL || errno == ENETUNREACH || errno == EADDRNOTAVAIL,
      "Expected EINVAL (%d), ENETUNREACH (%d) or EADDRNOTAVAIL (%d), got %s (%d)",
      EINVAL, ENETUNREACH, EADDRNOTAVAIL, strerror(errno), errno);
  }
  pr_inet_close(p, conn);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_connect(p, conn, addr, 53);
  if (res < 0) {
    /* This could be expected, e.g. if there's no route. */
    fail_unless(errno == EHOSTUNREACH || errno == ENETUNREACH || errno == EADDRNOTAVAIL,
      "Expected EHOSTUNREACH (%d) or ENETUNREACH (%d) or EADDRNOTAVAIL (%d), got %s (%d)",
      EHOSTUNREACH, ENETUNREACH, EADDRNOTAVAIL, strerror(errno), errno);
  }

  res = pr_inet_connect(p, conn, addr, 53);
  fail_unless(res < 0, "Failed to connect to 2001:4860:4860::8888#53: %s",
    strerror(errno));
  fail_unless(errno == EISCONN || errno == EHOSTUNREACH || errno == ENETUNREACH || errno == EADDRNOTAVAIL,
    "Expected EISCONN (%d) or EHOSTUNREACH (%d) or ENETUNREACH (%d) or EADDRNOTAVAIL (%d), got %s (%d)", EISCONN, EHOSTUNREACH, ENETUNREACH, EADDRNOTAVAIL, strerror(errno), errno);
  pr_inet_close(p, conn);
#endif

  pr_inet_set_default_family(p, AF_INET);

  if (use_ipv6 == FALSE) {
    pr_netaddr_disable_ipv6();
  }
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (inet_connect_nowait_test) {
  int sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;
  const pr_netaddr_t *addr;

  res = pr_inet_connect_nowait(NULL, NULL, NULL, port);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_connect_nowait(p, conn, NULL, 180);
  fail_unless(res < 0, "Failed to handle null address");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(addr != NULL, "Failed to resolve '127.0.0.1': %s",
    strerror(errno));

  res = pr_inet_connect_nowait(p, conn, addr, 180);
  fail_unless(res != -1, "Connected to 127.0.0.1#180 unexpectedly");

#if defined(PR_USE_NETWORK_TESTS)
  /* Try connecting to Google's DNS server. */

  addr = pr_netaddr_get_addr(p, dns_resolver, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", dns_resolver,
    strerror(errno));

  res = pr_inet_connect_nowait(p, conn, addr, 53);
  if (res < 0 &&
      errno != ECONNREFUSED &&
      errno != EBADF) {
    fail_unless(res != -1, "Failed to connect to %s#53: %s", dns_resolver,
      strerror(errno));
  }

  pr_inet_close(p, conn);
#endif

  /* Restore the default family to AF_INET, for other tests. */
  pr_inet_set_default_family(p, AF_INET);
}
END_TEST

START_TEST (inet_accept_test) {
  conn_t *conn;

  conn = pr_inet_accept(NULL, NULL, NULL, 0, 2, FALSE);
  fail_unless(conn == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (inet_accept_nowait_test) {
  int sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;

  res = pr_inet_accept_nowait(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_accept_nowait(p, conn);
  fail_unless(res < 0, "Accepted connection unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_conn_info_test) {
  int sockfd = -1, port = INPORT_ANY, res;
  conn_t *conn;

  res = pr_inet_get_conn_info(NULL, -1);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_get_conn_info(conn, -1);
  fail_unless(res < 0, "Failed to handle bad file descriptor");
  fail_unless(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  res = pr_inet_get_conn_info(conn, 1);
  fail_unless(res < 0, "Failed to handle bad file descriptor");
  fail_unless(errno == ENOTSOCK, "Expected ENOTSOCK (%d), got %s (%d)",
    ENOTSOCK, strerror(errno), errno);

  pr_inet_close(p, conn);
}
END_TEST

START_TEST (inet_openrw_test) {
  int sockfd = -1, port = INPORT_ANY;
  conn_t *conn, *res;
  const pr_netaddr_t *addr;

  res = pr_inet_openrw(NULL, NULL, NULL, PR_NETIO_STRM_CTRL, -1, -1, -1, FALSE);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  conn = pr_inet_create_conn(p, sockfd, NULL, port, FALSE);
  fail_unless(conn != NULL, "Failed to create conn: %s", strerror(errno));

  res = pr_inet_openrw(p, conn, NULL, PR_NETIO_STRM_CTRL, -1, -1, -1, FALSE);
  fail_unless(res == NULL, "Opened rw conn unexpectedly");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  addr = pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(addr != NULL, "Failed to resolve 127.0.0.1: %s", strerror(errno));

  res = pr_inet_openrw(p, conn, addr, PR_NETIO_STRM_CTRL, -1, -1, -1, FALSE);
  fail_unless(res != NULL, "Failed to open rw conn: %s", strerror(errno));
  (void) pr_inet_close(p, res);

  res = pr_inet_openrw(p, conn, addr, PR_NETIO_STRM_CTRL, -1, -1, -1, TRUE);
  fail_unless(res != NULL, "Failed to open rw conn: %s", strerror(errno));
}
END_TEST

START_TEST (inet_generate_socket_event_test) {
  int res;
  const char *name;
  server_rec *s;

  res = pr_inet_generate_socket_event(NULL, NULL, NULL, -1);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "foo.bar";
  res = pr_inet_generate_socket_event(name, NULL, NULL, -1);
  fail_unless(res < 0, "Failed to handle null server_rec");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  s = pcalloc(p, sizeof(server_rec));
  res = pr_inet_generate_socket_event(name, s, NULL, -1);
  fail_unless(res < 0, "Failed to handle null address");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

Suite *tests_get_inet_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("inet");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, inet_family_test);
  tcase_add_test(testcase, inet_create_conn_test);
  tcase_add_test(testcase, inet_create_conn_portrange_test);
  tcase_add_test(testcase, inet_copy_conn_test);
  tcase_add_test(testcase, inet_set_async_test);
  tcase_add_test(testcase, inet_set_block_test);
  tcase_add_test(testcase, inet_set_proto_cork_test);
  tcase_add_test(testcase, inet_set_proto_nodelay_test);
  tcase_add_test(testcase, inet_set_proto_opts_test);
  tcase_add_test(testcase, inet_set_proto_opts_ipv6_test);
  tcase_add_test(testcase, inet_set_socket_opts_test);
  tcase_add_test(testcase, inet_listen_test);
  tcase_add_test(testcase, inet_connect_ipv4_test);
  tcase_add_test(testcase, inet_connect_ipv6_test);
  tcase_add_test(testcase, inet_connect_nowait_test);
  tcase_add_test(testcase, inet_accept_test);
  tcase_add_test(testcase, inet_accept_nowait_test);
  tcase_add_test(testcase, inet_conn_info_test);
  tcase_add_test(testcase, inet_openrw_test);
  tcase_add_test(testcase, inet_generate_socket_event_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
