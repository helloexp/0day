/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2008-2017 The ProFTPD Project team
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

/* NetAddr API tests */

#include "tests.h"

static pool *p = NULL;

/* Fixtures */

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_netaddr();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("dns", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("dns", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

/* Tests */

START_TEST (netaddr_alloc_test) {
  pr_netaddr_t *res;

  res = pr_netaddr_alloc(NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_netaddr_alloc(p);
  fail_unless(res != NULL, "Failed to allocate netaddr: %s", strerror(errno));
  fail_unless(res->na_family == 0, "Allocated netaddr is not zeroed");
}
END_TEST

START_TEST (netaddr_dup_test) {
  pr_netaddr_t *res, *addr;

  res = pr_netaddr_dup(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_netaddr_dup(p, NULL);
  fail_unless(res == NULL, "Failed to handle null addr");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  addr = pr_netaddr_alloc(p);
  pr_netaddr_set_family(addr, AF_INET);
  
  res = pr_netaddr_dup(NULL, addr);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_netaddr_dup(p, addr);
  fail_unless(res != NULL, "Failed to dup netaddr: %s", strerror(errno));
  fail_unless(res->na_family == addr->na_family, "Expected family %d, got %d",
    addr->na_family, res->na_family);
}
END_TEST

START_TEST (netaddr_clear_test) {
  pr_netaddr_t *addr;

  mark_point();
  pr_netaddr_clear(NULL);

  addr = pr_netaddr_alloc(p);
  addr->na_family = 1;

  pr_netaddr_clear(addr);
  fail_unless(addr->na_family == 0, "Failed to clear addr");
}
END_TEST

START_TEST (netaddr_get_addr_test) {
  const pr_netaddr_t *res;
  const char *name;
  array_header *addrs = NULL;

  res = pr_netaddr_get_addr(NULL, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_netaddr_get_addr(p, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null name");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  name = "134.289.999.0";

  res = pr_netaddr_get_addr(NULL, name, NULL);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(res == NULL, "Unexpected got address for '%s'", name);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  name = "localhost";

  res = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(res != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  fail_unless(res->na_family == AF_INET, "Expected family %d, got %d",
    AF_INET, res->na_family);

  res = pr_netaddr_get_addr(p, name, &addrs);
  fail_unless(res != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  fail_unless(res->na_family == AF_INET, "Expected family %d, got %d",
    AF_INET, res->na_family);

#if defined(PR_USE_NETWORK_TESTS)
  /* Google: the Dial Tone of the Internet. */
  name = "www.google.com";

  res = pr_netaddr_get_addr(p, name, &addrs);
  fail_unless(res != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  fail_unless(res->na_family == AF_INET, "Expected family %d, got %d",
    AF_INET, res->na_family);
  fail_unless(addrs != NULL, "Expected additional addresses for '%s'", name);

  res = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(res != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  fail_unless(res->na_family == AF_INET, "Expected family %d, got %d",
    AF_INET, res->na_family);
#endif

  name = "127.0.0.1";

  res = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(res != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  fail_unless(res->na_family == AF_INET, "Expected family %d, got %d",
    AF_INET, res->na_family);

  res = pr_netaddr_get_addr(p, name, &addrs);
  fail_unless(res != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  fail_unless(res->na_family == AF_INET, "Expected family %d, got %d",
    AF_INET, res->na_family);
  fail_unless(addrs == NULL, "Expected no additional addresses for '%s'", name);

  /* Deliberately test an unresolvable name (related to Bug#4104). */
  name = "foo.bar.castaglia.example.com";

  res = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(res == NULL, "Resolved '%s' unexpectedly", name);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

#if defined(PR_USE_IPV6)
  name = "::1";

  res = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(res != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  fail_unless(res->na_family == AF_INET6, "Expected family %d, got %d",
    AF_INET6, res->na_family);

  res = pr_netaddr_get_addr(p, name, &addrs);
  fail_unless(res != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  fail_unless(res->na_family == AF_INET6, "Expected family %d, got %d",
    AF_INET6, res->na_family);
  fail_unless(addrs == NULL, "Expected no additional addresses for '%s'", name);
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (netaddr_get_addr2_test) {
  const pr_netaddr_t *res;
  const char *name;
  int flags;

  flags = PR_NETADDR_GET_ADDR_FL_INCL_DEVICE;
  name = "foobarbaz";
  res = pr_netaddr_get_addr2(p, name, NULL, flags);
  fail_unless(res == NULL, "Failed to handle unknown device '%s'", name);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  name = "lo0";
  res = pr_netaddr_get_addr2(p, name, NULL, flags);
  if (res == NULL) {
    /* Fallback to using a device name of "lo". */
    name = "lo";
    res = pr_netaddr_get_addr2(p, name, NULL, flags);
  }

  fail_if(res == NULL,
    "Expected to resolve name '%s' to an address via INCL_DEVICE", name);

  flags = PR_NETADDR_GET_ADDR_FL_EXCL_DNS;
  name = "localhost";
  res = pr_netaddr_get_addr2(p, name, NULL, flags);
  fail_unless(res == NULL, "Resolved name '%s' to IP address unexpectedly",
    name);
  fail_unless(errno == ENOENT, "Failed to set errno to ENOENT");
}
END_TEST

START_TEST (netaddr_get_family_test) {
  const pr_netaddr_t *addr;
  int res;

  res = pr_netaddr_get_family(NULL);
  fail_unless(res == -1, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  addr = pr_netaddr_get_addr(p, "localhost", NULL);
  fail_unless(addr != NULL, "Failed to get addr for 'localhost': %s",
    strerror(errno));

  res = pr_netaddr_get_family(addr);
  fail_unless(res == AF_INET, "Expected family %d, got %d", AF_INET,
    res);
}
END_TEST

START_TEST (netaddr_set_family_test) {
  pr_netaddr_t *addr;
  int res;

  res = pr_netaddr_set_family(NULL, 0);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(addr != NULL, "Failed to get addr for '127.0.0.1': %s",
    strerror(errno));

  res = pr_netaddr_set_family(addr, -1);
  fail_unless(res == -1, "Failed to handle bad family");
#ifdef EAFNOSUPPORT
  fail_unless(errno == EAFNOSUPPORT, "Failed to set errno to EAFNOSUPPORT");
#else
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");
#endif

  res = pr_netaddr_set_family(addr, AF_INET);
  fail_unless(res == 0, "Failed to set family to AF_INET: %s", strerror(errno));
}
END_TEST

START_TEST (netaddr_cmp_test) {
  const pr_netaddr_t *addr, *addr2;
  int res;
  const char *name;

  res = pr_netaddr_cmp(NULL, NULL);
  fail_unless(res == 0, "Expected 0, got %d", res);

  name = "127.0.0.1";
  addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_cmp(addr, NULL);
  fail_unless(res == 1, "Expected 1, got %d", res);

  res = pr_netaddr_cmp(NULL, addr);
  fail_unless(res == -1, "Expected -1, got %d", res);

  name = "::1";
  addr2 = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr2 != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_cmp(addr, addr2);
  fail_unless(res == -1, "Expected -1, got %d", res);

  res = pr_netaddr_cmp(addr2, addr);
  fail_unless(res == -1, "Expected -1, got %d", res);

  name = "::ffff:127.0.0.1";
  addr2 = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr2 != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_cmp(addr, addr2);
  fail_unless(res == 0, "Expected 0, got %d", res);

  res = pr_netaddr_cmp(addr2, addr);
  fail_unless(res == 0, "Expected 0, got %d", res);
}
END_TEST

START_TEST (netaddr_ncmp_test) {
  const pr_netaddr_t *addr, *addr2;
  int res;
  unsigned int nbits = 0;
  const char *name;

  res = pr_netaddr_ncmp(NULL, NULL, nbits);
  fail_unless(res == 0, "Expected 0, got %d", res);

  name = "127.0.0.1";
  addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_ncmp(addr, NULL, nbits);
  fail_unless(res == 1, "Expected 1, got %d", res);

  res = pr_netaddr_ncmp(NULL, addr, nbits);
  fail_unless(res == -1, "Expected -1, got %d", res);

  res = pr_netaddr_ncmp(NULL, addr, nbits);
  fail_unless(res == -1, "Expected -1, got %d", res);

  nbits = 48;
  res = pr_netaddr_ncmp(addr, addr, nbits);
  fail_unless(res == -1, "Expected -1, got %d", res);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "::1";
  addr2 = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr2 != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  nbits = 0;
  res = pr_netaddr_ncmp(addr, addr2, nbits);
  fail_unless(res == -1, "Expected -1, got %d", res);

  res = pr_netaddr_ncmp(addr2, addr, nbits);
  fail_unless(res == -1, "Expected -1, got %d", res);

  name = "::ffff:127.0.0.1";
  addr2 = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr2 != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_ncmp(addr, addr2, nbits);
  fail_unless(res == 0, "Expected 0, got %d", res);

  res = pr_netaddr_ncmp(addr2, addr, nbits);
  fail_unless(res == 0, "Expected 0, got %d", res);

  nbits = 24;
  res = pr_netaddr_ncmp(addr2, addr, nbits);
  fail_unless(res == 0, "Expected 0, got %d", res);
}
END_TEST

START_TEST (netaddr_fnmatch_test) {
  const pr_netaddr_t *addr;
  int flags, res;
  const char *name;

  res = pr_netaddr_fnmatch(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null address");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "localhost";
  addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_fnmatch(addr, NULL, 0);
  fail_unless(res < 0, "Failed to handle null pattern");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  flags = PR_NETADDR_MATCH_DNS;
  res = pr_netaddr_fnmatch(addr, "foo", flags);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);

  res = pr_netaddr_fnmatch(addr, "LOCAL*", flags);
  if (getenv("TRAVIS") == NULL) {
    /* This test is sensitive the environment. */
    fail_unless(res == TRUE, "Expected TRUE, got %d", res);
  }

  flags = PR_NETADDR_MATCH_IP;
  res = pr_netaddr_fnmatch(addr, "foo", flags);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);

  res = pr_netaddr_fnmatch(addr, "127.0*", flags);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);

#ifdef PR_USE_IPV6
  name = "::ffff:127.0.0.1";
  addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_fnmatch(addr, "foo", flags);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);

  res = pr_netaddr_fnmatch(addr, "127.0.*", flags);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (netaddr_get_sockaddr_test) {
  pr_netaddr_t *addr;
  struct sockaddr *sockaddr;
  const char *name;
#ifdef PR_USE_IPV6
  int family;
#endif /* PR_USE_IPV6 */

  sockaddr = pr_netaddr_get_sockaddr(NULL);
  fail_unless(sockaddr == NULL, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "127.0.0.1";
  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  sockaddr = pr_netaddr_get_sockaddr(addr);
  fail_unless(sockaddr != NULL, "Failed to get sock addr: %s", strerror(errno));

#ifdef PR_USE_IPV6
  name = "::1";
  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  sockaddr = pr_netaddr_get_sockaddr(addr);
  fail_unless(sockaddr != NULL, "Failed to get sock addr: %s", strerror(errno));

  pr_netaddr_disable_ipv6();
  sockaddr = pr_netaddr_get_sockaddr(addr);
  fail_unless(sockaddr == NULL, "Got sock addr for IPv6 addr", strerror(errno));
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  pr_netaddr_enable_ipv6();
  family = addr->na_family;
  addr->na_family = 777;
  sockaddr = pr_netaddr_get_sockaddr(addr);
  fail_unless(sockaddr == NULL, "Got sock addr for IPv6 addr", strerror(errno));
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  addr->na_family = family;
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (netaddr_get_sockaddr_len_test) {
  pr_netaddr_t *addr;
  size_t res;
  const char *name;
#ifdef PR_USE_IPV6
  int family;
#endif /* PR_USE_IPV6 */

  res = pr_netaddr_get_sockaddr_len(NULL);
  fail_unless(res == (size_t) -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "127.0.0.1";
  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_get_sockaddr_len(addr);
  fail_unless(res > 0, "Failed to get sockaddr len: %s", strerror(errno));

#ifdef PR_USE_IPV6
  name = "::1";
  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_get_sockaddr_len(addr);
  fail_unless(res > 0, "Failed to get sockaddr len: %s", strerror(errno));

  pr_netaddr_disable_ipv6();
  res = pr_netaddr_get_sockaddr_len(addr);
  fail_unless(res == (size_t) -1, "Got sockaddr len unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  pr_netaddr_enable_ipv6();

  family = addr->na_family;
  addr->na_family = 777;
  res = pr_netaddr_get_sockaddr_len(addr);
  addr->na_family = family;

  fail_unless(res == (size_t) -1, "Got sockaddr len unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (netaddr_set_sockaddr_test) {
  pr_netaddr_t *addr;
  int res;
  struct sockaddr sa;
  const char *name;
#ifdef PR_USE_IPV6
  int family;
# if defined(HAVE_GETADDRINFO)
  struct addrinfo hints, *info = NULL;
# endif /* HAVE_GETADDRINFO */
#endif /* PR_USE_IPV6 */

  res = pr_netaddr_set_sockaddr(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "127.0.0.1";
  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_set_sockaddr(addr, NULL);
  fail_unless(res < 0, "Failed to handle null sockaddr");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  memset(&sa, 0, sizeof(sa));

  res = pr_netaddr_set_sockaddr(addr, &sa);
  fail_unless(res == 0, "Failed to set sockaddr: %s", strerror(errno));

#ifdef PR_USE_IPV6
  name = "::1";
  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

# if defined(HAVE_GETADDRINFO)
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICHOST;
#  if defined(AI_V4MAPPED)
  hints.ai_flags |= AI_V4MAPPED;
#  endif /* AI_V4MAPPED */
  res = getaddrinfo("::1", NULL, &hints, &info);
  fail_unless(res == 0, "getaddrinfo('::1') failed: %s", gai_strerror(res));

  res = pr_netaddr_set_sockaddr(addr, info->ai_addr);
  fail_unless(res == 0, "Failed to set sockaddr: %s", strerror(errno));

  pr_netaddr_disable_ipv6();
  res = pr_netaddr_set_sockaddr(addr, info->ai_addr);
  fail_unless(res < 0, "Set sockaddr unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  freeaddrinfo(info);
  pr_netaddr_enable_ipv6();
# endif /* HAVE_GETADDRINFO */

  family = addr->na_family;
  addr->na_family = 777;
  res = pr_netaddr_set_sockaddr(addr, &sa);
  addr->na_family = family;

  fail_unless(res < 0, "Set sockaddr unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (netaddr_set_sockaddr_any_test) {
  pr_netaddr_t *addr;
  int res;
  const char *name;
#ifdef PR_USE_IPV6
  int family;
#endif /* PR_USE_IPV6 */

  res = pr_netaddr_set_sockaddr_any(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "127.0.0.1";
  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_set_sockaddr_any(addr);
  fail_unless(res == 0, "Failed to set sockaddr any: %s", strerror(errno));

#ifdef PR_USE_IPV6
  name = "::1";
  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_set_sockaddr_any(addr);
  fail_unless(res == 0, "Failed to set sockaddr any: %s", strerror(errno));

  pr_netaddr_disable_ipv6();
  res = pr_netaddr_set_sockaddr_any(addr);
  fail_unless(res < 0, "Set sockaddr any unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  pr_netaddr_enable_ipv6();

  family = addr->na_family;
  addr->na_family = 777;
  res = pr_netaddr_set_sockaddr_any(addr);
  addr->na_family = family;

  fail_unless(res < 0, "Set sockaddr any unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (netaddr_get_inaddr_test) {
  pr_netaddr_t *addr;
  int family;
  void *inaddr;
  const char *name;

  inaddr = pr_netaddr_get_inaddr(NULL);
  fail_unless(inaddr == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  family = AF_INET;
  name = "127.0.0.1";
  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  inaddr = pr_netaddr_get_inaddr(addr);
  fail_unless(inaddr != NULL, "Failed to get inaddr: %s", strerror(errno));

#ifdef PR_USE_IPV6
  family = AF_INET6;
  name = "::1";
  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  inaddr = pr_netaddr_get_inaddr(addr);
  fail_unless(inaddr != NULL, "Failed to get inaddr: %s", strerror(errno));

  pr_netaddr_disable_ipv6();
  inaddr = pr_netaddr_get_inaddr(addr);
  fail_unless(inaddr == NULL, "Got inaddr unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  pr_netaddr_enable_ipv6();

  family = addr->na_family;
  addr->na_family = 777;
  inaddr = pr_netaddr_get_inaddr(addr);
  addr->na_family = family;

  fail_unless(inaddr == NULL, "Got inaddr unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (netaddr_get_inaddr_len_test) {
  pr_netaddr_t *addr;
  size_t res;
  const char *name;
#ifdef PR_USE_IPV6
  int family;
#endif /* PR_USE_IPV6 */

  res = pr_netaddr_get_inaddr_len(NULL);
  fail_unless(res == (size_t) -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "127.0.0.1";
  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_get_inaddr_len(addr);
  fail_unless(res > 0, "Failed to get inaddr len: %s", strerror(errno));

#ifdef PR_USE_IPV6
  name = "::1";
  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_get_inaddr_len(addr);
  fail_unless(res > 0, "Failed to get inaddr len: %s", strerror(errno));

  family = addr->na_family;
  addr->na_family = 777;
  res = pr_netaddr_get_inaddr_len(addr);
  addr->na_family = family;

  fail_unless(res == (size_t) -1, "Got inaddr len unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (netaddr_get_port_test) {
  pr_netaddr_t *addr;
  unsigned int res;

  res = pr_netaddr_get_port(NULL);
  fail_unless(res == 0, "Failed to handle null addr");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(addr != NULL, "Failed to get addr for '127.0.0.1': %s",
    strerror(errno));

  res = pr_netaddr_get_port(addr);
  fail_unless(res == 0, "Expected port %u, got %u", 0, res);

  addr->na_family = -1;
  res = pr_netaddr_get_port(addr);
  fail_unless(res == 0, "Expected port %u, got %u", 0, res);
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");
}
END_TEST

START_TEST (netaddr_set_port_test) {
  pr_netaddr_t *addr;
  unsigned int port;
  int res;

  res = pr_netaddr_set_port(NULL, 0);
  fail_unless(res == -1, "Failed to handle null addr");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  addr = (pr_netaddr_t *) pr_netaddr_get_addr(p, "127.0.0.1", NULL);
  fail_unless(addr != NULL, "Failed to get addr for '127.0.0.1': %s",
    strerror(errno));

  addr->na_family = -1;
  res = pr_netaddr_set_port(addr, 1);
  fail_unless(res == -1, "Failed to handle bad family");
  fail_unless(errno == EPERM, "Failed to set errno to EPERM");

  addr->na_family = AF_INET;
  res = pr_netaddr_set_port(addr, 1);
  fail_unless(res == 0, "Failed to set port: %s", strerror(errno));

  port = pr_netaddr_get_port(addr);
  fail_unless(port == 1, "Expected port %u, got %u", 1, port);
}
END_TEST

START_TEST (netaddr_set_reverse_dns_test) {
  int res;

  res = pr_netaddr_set_reverse_dns(FALSE);
  fail_unless(res == 1, "Expected reverse %d, got %d", 1, res);

  res = pr_netaddr_set_reverse_dns(TRUE);
  fail_unless(res == 0, "Expected reverse %d, got %d", 0, res);
}
END_TEST

START_TEST (netaddr_get_dnsstr_test) {
  const pr_netaddr_t *addr;
  const char *ip, *res;

  ip = "127.0.0.1";

  res = pr_netaddr_get_dnsstr(NULL);
  fail_unless(res == NULL, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  addr = pr_netaddr_get_addr(p, ip, NULL);
  fail_unless(addr != NULL, "Failed to get addr for '%s': %s", ip,
    strerror(errno));

  pr_netaddr_set_reverse_dns(FALSE);

  res = pr_netaddr_get_dnsstr(addr);
  fail_unless(res != NULL, "Failed to get DNS str for addr: %s",
    strerror(errno));
  fail_unless(strcmp(res, ip) == 0, "Expected '%s', got '%s'", ip, res);

  pr_netaddr_set_reverse_dns(TRUE);

  /* Even though we should expect a DNS name, not an IP address, the
   * previous call to pr_netaddr_get_dnsstr() cached the IP address.
   */
  res = pr_netaddr_get_dnsstr(addr);
  fail_unless(res != NULL, "Failed to get DNS str for addr: %s",
    strerror(errno));
  fail_unless(strcmp(res, ip) == 0, "Expected '%s', got '%s'", ip, res);

  pr_netaddr_clear((pr_netaddr_t *) addr);

  /* Clearing the address doesn't work, since that removes even the address
   * info, in addition to the cached strings.
   */
  res = pr_netaddr_get_dnsstr(addr);
  fail_unless(res != NULL, "Failed to get DNS str for addr: %s",
    strerror(errno));
  fail_unless(strcmp(res, "") == 0, "Expected '%s', got '%s'", "", res);

  /* We need to clear the netaddr internal cache as well. */
  pr_netaddr_clear_ipcache(ip);
  addr = pr_netaddr_get_addr(p, ip, NULL);
  fail_unless(addr != NULL, "Failed to get addr for '%s': %s", ip,
    strerror(errno));

  mark_point();
  fail_unless(addr->na_have_dnsstr == 0, "addr already has cached DNS str");

  mark_point();
  res = pr_netaddr_get_dnsstr(addr);
  fail_unless(res != NULL, "Failed to get DNS str for addr: %s",
    strerror(errno));

  mark_point();

  /* Depending on the contents of /etc/hosts, resolving 127.0.0.1 could
   * return either "localhost" or "localhost.localdomain".  Perhaps even
   * other variations, although these should be the most common.
   */
  if (getenv("TRAVIS") == NULL) {
    /* This test is sensitive the environment. */
    fail_unless(strcmp(res, "localhost") == 0 ||
                strcmp(res, "localhost.localdomain") == 0,
      "Expected '%s', got '%s'", "localhost or localhost.localdomain", res);
  }
}
END_TEST

START_TEST (netaddr_get_dnsstr_list_test) {
  array_header *res, *addrs = NULL;
  const pr_netaddr_t *addr;
  int reverse_dns;
  const char *dnsstr;

  res = pr_netaddr_get_dnsstr_list(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_netaddr_get_dnsstr_list(p, NULL);
  fail_unless(res == NULL, "Failed to handle null address");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  addr = pr_netaddr_get_addr(p, "localhost", NULL);
  fail_unless(addr != NULL, "Failed to resolve 'localhost': %s",
    strerror(errno));

  res = pr_netaddr_get_dnsstr_list(p, addr);
  fail_unless(res != NULL, "Failed to get DNS list: %s", strerror(errno));

  reverse_dns = pr_netaddr_set_reverse_dns(TRUE);

  pr_netaddr_clear_cache();

#if defined(PR_USE_NETWORK_TESTS)
  addr = pr_netaddr_get_addr(p, "www.google.com", &addrs);
  fail_unless(addr != NULL, "Failed to resolve 'www.google.com': %s",
    strerror(errno));

  dnsstr = pr_netaddr_get_dnsstr(addr);
  fail_unless(dnsstr != NULL, "Failed to get DNS string for '%s': %s",
    pr_netaddr_get_ipstr(addr), strerror(errno));

  /* We may get a DNS name, but there is no guarantee that the reverse
   * DNS lookup will return the original "www.google.com" we requested.
   */

  res = pr_netaddr_get_dnsstr_list(p, addr);
  fail_unless(res != NULL, "Failed to get DNS list: %s", strerror(errno));

  /* Ideally we would check that res->nelts > 0, BUT this turns out to
   * a fragile test condition, dependent on DNS vagaries.
   */
#endif

  pr_netaddr_set_reverse_dns(reverse_dns);
}
END_TEST

#ifdef PR_USE_IPV6
START_TEST (netaddr_get_dnsstr_ipv6_test) {
  const pr_netaddr_t *addr;
  const char *ip, *res;

  ip = "::1";

  res = pr_netaddr_get_dnsstr(NULL);
  fail_unless(res == NULL, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  addr = pr_netaddr_get_addr(p, ip, NULL);
  fail_unless(addr != NULL, "Failed to get addr for '%s': %s", ip,
    strerror(errno));

  pr_netaddr_set_reverse_dns(FALSE);

  res = pr_netaddr_get_dnsstr(addr);
  fail_unless(res != NULL, "Failed to get DNS str for addr: %s",
    strerror(errno));
  fail_unless(strcmp(res, ip) == 0, "Expected '%s', got '%s'", ip, res);

  pr_netaddr_set_reverse_dns(TRUE);

  /* Even though we should expect a DNS name, not an IP address, the
   * previous call to pr_netaddr_get_dnsstr() cached the IP address.
   */
  res = pr_netaddr_get_dnsstr(addr);
  fail_unless(res != NULL, "Failed to get DNS str for addr: %s",
    strerror(errno));
  fail_unless(strcmp(res, ip) == 0, "Expected '%s', got '%s'", ip, res);

  pr_netaddr_clear((pr_netaddr_t *) addr);

  /* Clearing the address doesn't work, since that removes even the address
   * info, in addition to the cached strings.
   */
  res = pr_netaddr_get_dnsstr(addr);
  fail_unless(res != NULL, "Failed to get DNS str for addr: %s",
    strerror(errno));
  fail_unless(strcmp(res, "") == 0, "Expected '%s', got '%s'", "", res);

  /* We need to clear the netaddr internal cache as well. */
  pr_netaddr_clear_ipcache(ip);
  addr = pr_netaddr_get_addr(p, ip, NULL);
  fail_unless(addr != NULL, "Failed to get addr for '%s': %s", ip,
    strerror(errno));

  mark_point();
  fail_unless(addr->na_have_dnsstr == 0, "addr already has cached DNS str");

  mark_point();
  res = pr_netaddr_get_dnsstr(addr);
  fail_unless(res != NULL, "Failed to get DNS str for addr: %s",
    strerror(errno));

  mark_point();

  /* Depending on the contents of /etc/hosts, resolving ::1 could
   * return either "localhost" or "localhost.localdomain".  Perhaps even
   * other variations, although these should be the most common.
   */
  if (getenv("TRAVIS") == NULL) {
    fail_unless(strcmp(res, "localhost") == 0 ||
                strcmp(res, "localhost.localdomain") == 0 ||
                strcmp(res, "localhost6") == 0 ||
                strcmp(res, "localhost6.localdomain") == 0 ||
                strcmp(res, "ip6-localhost") == 0 ||
                strcmp(res, "ip6-loopback") == 0 ||
                strcmp(res, ip) == 0,
      "Expected '%s', got '%s'", "localhost, localhost.localdomain et al", res);
  }
}
END_TEST
#endif /* PR_USE_IPV6 */

START_TEST (netaddr_get_ipstr_test) {
  const pr_netaddr_t *addr;
  const char *res;

  res = pr_netaddr_get_ipstr(NULL);
  fail_unless(res == NULL, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  addr = pr_netaddr_get_addr(p, "localhost", NULL);
  fail_unless(addr != NULL, "Failed to get addr for 'localhost': %s",
    strerror(errno));

  res = pr_netaddr_get_ipstr(addr);
  fail_unless(res != NULL, "Failed to get IP str for addr: %s",
    strerror(errno));
  fail_unless(strcmp(res, "127.0.0.1") == 0, "Expected '%s', got '%s'",
    "127.0.0.1", res);
  fail_unless(addr->na_have_ipstr == 1, "addr should have cached IP str");

  pr_netaddr_clear((pr_netaddr_t *) addr);
  res = pr_netaddr_get_ipstr(addr);
  fail_unless(res == NULL, "Expected null, got '%s'", res);
}
END_TEST

START_TEST (netaddr_validate_dns_str_test) {
  char *res, *str;

  res = pr_netaddr_validate_dns_str(NULL);
  fail_unless(res == NULL, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = pstrdup(p, "foo");
  res = pr_netaddr_validate_dns_str(str);
  fail_unless(strcmp(res, str) == 0, "Expected '%s', got '%s'", str, res);

  str = pstrdup(p, "[foo]");
  res = pr_netaddr_validate_dns_str(str);
  fail_unless(strcmp(res, "_foo_") == 0, "Expected '%s', got '%s'",
    "_foo_", res);

  str = pstrdup(p, "foo.");
  res = pr_netaddr_validate_dns_str(str);
  fail_unless(strcmp(res, str) == 0, "Expected '%s', got '%s'",
    str, res);

  str = pstrdup(p, "foo:");
  res = pr_netaddr_validate_dns_str(str);
#ifdef PR_USE_IPV6
  fail_unless(strcmp(res, str) == 0, "Expected '%s', got '%s'",
    str, res);
#else
  fail_unless(strcmp(res, "foo_") == 0, "Expected '%s', got '%s'",
    "foo_", res);
#endif
}
END_TEST

START_TEST (netaddr_get_localaddr_str_test) {
  const char *res;

  res = pr_netaddr_get_localaddr_str(NULL);
  fail_unless(res == NULL, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_netaddr_get_localaddr_str(p);
  fail_unless(res != NULL, "Failed to get local addr: %s", strerror(errno));
}
END_TEST

START_TEST (netaddr_is_loopback_test) {
  const pr_netaddr_t *addr;
  int res;
  const char *name;

  res = pr_netaddr_is_loopback(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

#if defined(PR_USE_NETWORK_TESTS)
  name = "www.google.com";
  addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_is_loopback(addr);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);
#endif

  name = "127.0.0.1";
  addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_is_loopback(addr);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);

#ifdef PR_USE_IPV6
  name = "::1";
  addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_is_loopback(addr);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);

  name = "::ffff:127.0.0.1";
  addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  res = pr_netaddr_is_loopback(addr);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (netaddr_is_v4_test) {
  int res;
  const char *name;

  res = pr_netaddr_is_v4(NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  name = "::1";
  res = pr_netaddr_is_v4(name);
  fail_unless(res == FALSE, "Expected 'false' for IPv6 address '%s', got %d",
    name, res);

  name = "localhost";
  res = pr_netaddr_is_v4(name);
  fail_unless(res == FALSE, "Expected 'false' for DNS name '%s', got %d",
    name, res);

  name = "127.0.0.1";
  res = pr_netaddr_is_v4(name);
  fail_unless(res == TRUE, "Expected 'true' for IPv4 address '%s', got %d",
    name, res);
}
END_TEST

START_TEST (netaddr_is_v6_test) {
  int res;
  const char *name;

  res = pr_netaddr_is_v6(NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  name = "127.0.0.1";
  res = pr_netaddr_is_v6(name);
  fail_unless(res == FALSE, "Expected 'false' for IPv4 address '%s', got %d",
    name, res);

  name = "localhost";
  res = pr_netaddr_is_v6(name);
  fail_unless(res == FALSE, "Expected 'false' for DNS name '%s', got %d",
    name, res);

  pr_netaddr_enable_ipv6();

  if (pr_netaddr_use_ipv6() == TRUE) {
    name = "::1";
    res = pr_netaddr_is_v6(name);
    fail_unless(res == TRUE, "Expected 'true' for IPv6 address '%s', got %d",
      name, res);
  }
}
END_TEST

START_TEST (netaddr_is_v4mappedv6_test) {
  int res;
  const char *name;
  const pr_netaddr_t *addr;

  res = pr_netaddr_is_v4mappedv6(NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  name = "127.0.0.1";
  addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  res = pr_netaddr_is_v4mappedv6(addr);
  fail_unless(res == -1, "Expected -1 for IPv4 address '%s', got %d",
    name, res);
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL; got %d [%s]",
    errno, strerror(errno));

  name = "::1";
  addr = pr_netaddr_get_addr(p, name, NULL);
#ifdef PR_USE_IPV6
  fail_unless(addr != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  res = pr_netaddr_is_v4mappedv6(addr);
  fail_unless(res == FALSE, "Expected 'false' for IPv6 address '%s', got %d",
    name, res);
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL; got %d [%s]",
    errno, strerror(errno));
#else
  fail_unless(addr == NULL,
    "IPv6 support disabled, should not be able to get addr for '%s'", name);
#endif /* PR_USE_IPV6 */

  name = "::ffff:127.0.0.1";
  addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  res = pr_netaddr_is_v4mappedv6(addr);
#ifdef PR_USE_IPV6
  fail_unless(res == TRUE,
    "Expected 'true' for IPv4-mapped IPv6 address '%s', got %d", name, res);
#else
  fail_unless(res == -1,
    "Expected -1 for IPv4-mapped IPv6 address '%s' (--disable-ipv6 used)");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL; got %d [%s]",
    errno, strerror(errno));
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (netaddr_is_rfc1918_test) {
  int res;
  const char *name;
  const pr_netaddr_t *addr;

  res = pr_netaddr_is_rfc1918(NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  name = "127.0.0.1";
  addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  res = pr_netaddr_is_rfc1918(addr);
  fail_unless(res == FALSE, "Failed to handle non-RFC1918 IPv4 address");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  name = "::1";
  addr = pr_netaddr_get_addr(p, name, NULL);
#ifdef PR_USE_IPV6
  fail_unless(addr != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  res = pr_netaddr_is_rfc1918(addr);
  fail_unless(res == FALSE, "Failed to handle IPv6 address");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");
#else
  fail_unless(addr == NULL,
    "IPv6 support disabled, should not be able to get addr for '%s'", name);
#endif /* PR_USE_IPV6 */

  name = "10.0.0.1";
  addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  res = pr_netaddr_is_rfc1918(addr);
  fail_unless(res == TRUE, "Expected 'true' for address '%s'", name);

  name = "192.168.0.1";
  addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  res = pr_netaddr_is_rfc1918(addr);
  fail_unless(res == TRUE, "Expected 'true' for address '%s'", name);

  name = "172.31.200.55";
  addr = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr != NULL, "Failed to get addr for '%s': %s", name,
    strerror(errno));
  res = pr_netaddr_is_rfc1918(addr);
  fail_unless(res == TRUE, "Expected 'true' for address '%s'", name);
}
END_TEST

START_TEST (netaddr_v6tov4_test) {
  const pr_netaddr_t *addr, *addr2;
  const char *name, *ipstr;

  addr = pr_netaddr_v6tov4(NULL, NULL);
  fail_unless(addr == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  addr = pr_netaddr_v6tov4(p, NULL);
  fail_unless(addr == NULL, "Failed to handle null address");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "127.0.0.1";
  addr2 = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr2 != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  addr = pr_netaddr_v6tov4(p, addr2);
  fail_unless(addr == NULL, "Converted '%s' to IPv4 address unexpectedly",
    name);
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  name = "::ffff:127.0.0.1";
  addr2 = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr2 != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  addr = pr_netaddr_v6tov4(p, addr2);
  fail_unless(addr != NULL, "Failed to convert '%s' to IPv4 address: %s",
    name, strerror(errno));
  fail_unless(pr_netaddr_get_family(addr) == AF_INET,
    "Expected %d, got %d", AF_INET, pr_netaddr_get_family(addr));

  ipstr = pr_netaddr_get_ipstr(addr);
  fail_unless(strcmp(ipstr, "127.0.0.1") == 0,
    "Expected '127.0.0.1', got '%s'", ipstr);
}
END_TEST

START_TEST (netaddr_v4tov6_test) {
  const pr_netaddr_t *addr, *addr2;
  const char *name, *ipstr;

  addr = pr_netaddr_v4tov6(NULL, NULL);
  fail_unless(addr == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  addr = pr_netaddr_v4tov6(p, NULL);
  fail_unless(addr == NULL, "Failed to handle null address");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "::ffff:127.0.0.1";
  addr2 = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr2 != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  addr = pr_netaddr_v4tov6(p, addr2);
  fail_unless(addr == NULL, "Converted '%s' to IPv6 address unexpectedly",
    name);
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  name = "127.0.0.1";
  addr2 = pr_netaddr_get_addr(p, name, NULL);
  fail_unless(addr2 != NULL, "Failed to resolve '%s': %s", name,
    strerror(errno));

  addr = pr_netaddr_v4tov6(p, addr2);
#ifdef PR_USE_IPV6
  fail_unless(addr != NULL, "Failed to convert '%s' to IPv6 address: %s",
    name, strerror(errno));
  fail_unless(pr_netaddr_get_family(addr) == AF_INET6,
    "Expected %d, got %d", AF_INET6, pr_netaddr_get_family(addr));

  ipstr = pr_netaddr_get_ipstr(addr);
  fail_unless(strcmp(ipstr, "::ffff:127.0.0.1") == 0,
    "Expected '::ffff:127.0.0.1', got '%s'", ipstr);

#else
  fail_unless(addr == NULL, "Converted '%s' to IPv6 address unexpectedly",
    name);
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
#endif /* PR_USE_IPV6 */
}
END_TEST

START_TEST (netaddr_disable_ipv6_test) {
  unsigned char use_ipv6;

  use_ipv6 = pr_netaddr_use_ipv6();

#ifdef PR_USE_IPV6
  fail_unless(use_ipv6 == TRUE, "Expected %d, got %d", TRUE, use_ipv6);
#else
  fail_unless(use_ipv6 == FALSE, "Expected %d, got %d", FALSE, use_ipv6);
#endif

  pr_netaddr_disable_ipv6();

  use_ipv6 = pr_netaddr_use_ipv6();
  fail_unless(use_ipv6 == FALSE, "Expected %d, got %d", FALSE, use_ipv6);
}
END_TEST

START_TEST (netaddr_enable_ipv6_test) {
  unsigned char use_ipv6;

  pr_netaddr_enable_ipv6();

  use_ipv6 = pr_netaddr_use_ipv6();
#ifdef PR_USE_IPV6
  fail_unless(use_ipv6 == TRUE, "Expected %d, got %d", TRUE, use_ipv6);
#else
  fail_unless(use_ipv6 == FALSE, "Expected %d, got %d", FALSE, use_ipv6);
#endif
}
END_TEST

Suite *tests_get_netaddr_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("netaddr");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, netaddr_alloc_test);
  tcase_add_test(testcase, netaddr_dup_test);
  tcase_add_test(testcase, netaddr_clear_test);
  tcase_add_test(testcase, netaddr_get_addr_test);
  tcase_add_test(testcase, netaddr_get_addr2_test);
  tcase_add_test(testcase, netaddr_get_family_test);
  tcase_add_test(testcase, netaddr_set_family_test);
  tcase_add_test(testcase, netaddr_cmp_test);
  tcase_add_test(testcase, netaddr_ncmp_test);
  tcase_add_test(testcase, netaddr_fnmatch_test);
  tcase_add_test(testcase, netaddr_get_sockaddr_test);
  tcase_add_test(testcase, netaddr_get_sockaddr_len_test);
  tcase_add_test(testcase, netaddr_set_sockaddr_test);
  tcase_add_test(testcase, netaddr_set_sockaddr_any_test);
  tcase_add_test(testcase, netaddr_get_inaddr_test);
  tcase_add_test(testcase, netaddr_get_inaddr_len_test);
  tcase_add_test(testcase, netaddr_get_port_test);
  tcase_add_test(testcase, netaddr_set_port_test);
  tcase_add_test(testcase, netaddr_set_reverse_dns_test);
  tcase_add_test(testcase, netaddr_get_dnsstr_test);
  tcase_add_test(testcase, netaddr_get_dnsstr_list_test);
#ifdef PR_USE_IPV6
  tcase_add_test(testcase, netaddr_get_dnsstr_ipv6_test);
#endif /* PR_USE_IPV6 */
  tcase_add_test(testcase, netaddr_get_ipstr_test);
  tcase_add_test(testcase, netaddr_validate_dns_str_test);
  tcase_add_test(testcase, netaddr_get_localaddr_str_test);
  tcase_add_test(testcase, netaddr_is_loopback_test);
  tcase_add_test(testcase, netaddr_is_v4_test);
  tcase_add_test(testcase, netaddr_is_v6_test);
  tcase_add_test(testcase, netaddr_is_v4mappedv6_test);
  tcase_add_test(testcase, netaddr_is_rfc1918_test);
  tcase_add_test(testcase, netaddr_v6tov4_test);
  tcase_add_test(testcase, netaddr_v4tov6_test);
  tcase_add_test(testcase, netaddr_disable_ipv6_test);
  tcase_add_test(testcase, netaddr_enable_ipv6_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
