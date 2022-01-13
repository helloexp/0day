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

/* NetACL API tests */

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
    pr_trace_set_levels("netacl", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("dns", 0, 0);
    pr_trace_set_levels("netacl", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

/* Tests */

START_TEST (netacl_create_test) {
  pr_netacl_t *res;
  pr_netacl_type_t acl_type;
  char *acl_str;

  res = pr_netacl_create(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle NULL arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_netacl_create(NULL, "");
  fail_unless(res == NULL, "Failed to handle NULL pool");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_netacl_create(p, NULL);
  fail_unless(res == NULL, "Failed to handle NULL ACL string");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_netacl_create(p, "");
  fail_unless(res == NULL, "Failed to handle empty ACL string");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  acl_str = "ALL";
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s'", acl_str);

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_ALL,
    "Failed to have ALL type for ACL string '%s'", acl_str);

  acl_str = "none";
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s'", acl_str);

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_NONE,
    "Failed to have NONE type for ACL string '%s'", acl_str);

  acl_str = pstrdup(p, "localhost/24");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res == NULL, "Failed to handle bad ACL string '%s': %s",
    acl_str, strerror(errno));
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  acl_str = pstrdup(p, "127.0.0.1/24");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_IPMASK,
    "Failed to have IPMASK type for ACL string '%s'", acl_str);

  acl_str = pstrdup(p, "127.0.0.1/36");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res == NULL, "Failed to handle bad ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_str = pstrdup(p, "0.0.0.0/0");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

#ifdef PR_USE_IPV6
  acl_str = pstrdup(p, "::1/36");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_IPMASK,
    "Failed to have IPMASK type for ACL string '%s'", acl_str);

  acl_str = pstrdup(p, "::ffff:127.0.0.1/111");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_IPMASK,
    "Failed to have IPMASK type for ACL string '%s'", acl_str);

  acl_str = pstrdup(p, "::1/136");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res == NULL, "Failed to handle bad ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_str = pstrdup(p, "::ffff:127.0.0.1/136");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res == NULL, "Failed to handle bad ACL string '%s': %s", acl_str,
    strerror(errno));
#endif

  acl_str = pstrdup(p, "127.0.0.1/0");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_IPMASK,
    "Failed to have IPMASK type for ACL string '%s'", acl_str);

  acl_str = pstrdup(p, "127.0.0.1/-1");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res == NULL, "Failed to handle bad ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_str = pstrdup(p, "127.0.0.1.2/24");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res == NULL, "Failed to handle bad ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_str = pstrdup(p, "127.0.0.1/25f");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res == NULL, "Failed to handle bad ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_str = pstrdup(p, "127.0.0.");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_IPGLOB,
    "Failed to have IPGLOB type for ACL string '%s'", acl_str);

  acl_str = pstrdup(p, "127.0.0.1");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_IPMATCH,
    "Failed to have IPMATCH type for ACL string '%s'", acl_str);

  acl_str = pstrdup(p, "!127.0.0.1");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_IPMATCH,
    "Failed to have IPMATCH type for ACL string '%s'", acl_str);

  acl_str = pstrdup(p, "127.0.0.1.1");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res == NULL, "Failed to handle bad ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_str = pstrdup(p, ".0.0.1");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res == NULL, "Failed to handle bad ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_str = pstrdup(p, "*.0.0.1");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_IPGLOB,
    "Failed to have IPGLOB type for ACL string '%s'", acl_str);

  acl_str = pstrdup(p, ".edu");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_DNSGLOB,
    "Failed to have DNSGLOB type for ACL string '%s'", acl_str);

  acl_str = pstrdup(p, "localhost");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_DNSMATCH,
    "Failed to have DNSMATCH type for ACL string '%s'", acl_str);

  acl_str = pstrdup(p, "foobar");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_DNSMATCH,
    "Failed to have DNSMATCH type for ACL string '%s'", acl_str);

  acl_str = pstrdup(p, "!foobar");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_DNSMATCH,
    "Failed to have DNSMATCH type for ACL string '%s'", acl_str);

  acl_str = pstrdup(p, "!fo?bar");
  res = pr_netacl_create(p, acl_str);
  fail_unless(res != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  acl_type = pr_netacl_get_type(res);
  fail_unless(acl_type == PR_NETACL_TYPE_DNSGLOB,
    "Failed to have DNSGLOB type for ACL string '%s'", acl_str);
}
END_TEST

START_TEST (netacl_get_str_test) {
  pr_netacl_t *acl;
  char *acl_str, *ok;
  const char *res;

  res = pr_netacl_get_str(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle NULL arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_netacl_get_str(p, NULL);
  fail_unless(res == NULL, "Failed to handle NULL ACL");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  acl_str = "all";
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_netacl_get_str(NULL, acl);
  fail_unless(res == NULL, "Failed to handle NULL pool");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  ok = "all <all>";
  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = "AlL";
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = "None";
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));
 
  ok = "none <none>";
  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "127.0.0.1");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "127.0.0.1 <IP address match>";
  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "!127.0.0.1");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "!127.0.0.1 <IP address match, inverted>";
  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "127.0.0.");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "127.0.0.* <IP address glob>";
  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "localhost");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "localhost <DNS hostname match>";
  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, ".castaglia.org");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "*.castaglia.org <DNS hostname glob>";
  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "127.0.0.1/24");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "127.0.0.1/24 <IP address mask, 24-bit mask>";
  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "127.0.0.1/0");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "127.0.0.1/0 <IP address mask, 0-bit mask>";
  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "0.0.0.0/0");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "0.0.0.0/0 <IP address mask, 0-bit mask>";
  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "!127.0.0.1/24");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "!127.0.0.1/24 <IP address mask, 24-bit mask, inverted>";
  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

#ifdef PR_USE_IPV6
  acl_str = pstrdup(p, "::1/24");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "::1/24 <IP address mask, 24-bit mask>";
  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "::1/127");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "::1/127 <IP address mask, 127-bit mask>";
  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "::ffff:127.0.0.1/127");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "::ffff:127.0.0.1/127 <IP address mask, 127-bit mask>";
  res = pr_netacl_get_str(p, acl);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);
#endif
}
END_TEST

START_TEST (netacl_get_str2_test) {
  pr_netacl_t *acl;
  char *acl_str, *ok;
  const char *res;
  int flags = PR_NETACL_FL_STR_NO_DESC;

  res = pr_netacl_get_str2(NULL, NULL, 0);
  fail_unless(res == NULL, "Failed to handle NULL arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_netacl_get_str2(p, NULL, 0);
  fail_unless(res == NULL, "Failed to handle NULL ACL");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  acl_str = "all";
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_netacl_get_str2(NULL, acl, flags);
  fail_unless(res == NULL, "Failed to handle NULL pool");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  ok = "all";
  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = "AlL";
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = "None";
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "none";
  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "127.0.0.1");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "127.0.0.1";
  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "!127.0.0.1");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "!127.0.0.1";
  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "127.0.0.");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "127.0.0.*";
  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "localhost");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "localhost";
  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, ".castaglia.org");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "*.castaglia.org";
  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "127.0.0.1/24");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "127.0.0.1/24";
  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "127.0.0.1/0");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "127.0.0.1/0";
  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "0.0.0.0/0");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "0.0.0.0/0";
  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "!127.0.0.1/24");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "!127.0.0.1/24";
  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

#ifdef PR_USE_IPV6
  acl_str = pstrdup(p, "::1/24");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "::1/24";
  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "::1/127");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "::1/127";
  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  acl_str = pstrdup(p, "::ffff:127.0.0.1/127");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  ok = "::ffff:127.0.0.1/127";
  res = pr_netacl_get_str2(p, acl, flags);
  fail_unless(res != NULL, "Failed to get ACL string: %s", strerror(errno));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);
#endif
}
END_TEST

START_TEST (netacl_dup_test) {
  pr_netacl_t *acl, *res;

  res = pr_netacl_dup(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle NULL arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_netacl_dup(p, NULL);
  fail_unless(res == NULL, "Failed to handle NULL ACL argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  acl = pr_netacl_create(p, "ALL");
  fail_unless(acl != NULL, "Failed to create ALL ACL");

  res = pr_netacl_dup(NULL, acl);
  fail_unless(res == NULL, "Failed to handle NULL pool");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_netacl_dup(p, acl);
  fail_unless(res != NULL, "Failed to dup ACL: %s", strerror(errno));
  fail_unless(strcmp(pr_netacl_get_str(p, res), pr_netacl_get_str(p, acl)) == 0,
    "Expected '%s', got '%s'", pr_netacl_get_str(p, acl),
    pr_netacl_get_str(p, res));
}
END_TEST

START_TEST (netacl_match_test) {
  pr_netacl_t *acl;
  const pr_netaddr_t *addr;
  char *acl_str;
  int have_localdomain = FALSE, res, reverse_dns;

  res = pr_netacl_match(NULL, NULL);
  fail_unless(res == -2, "Failed to handle NULL arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  acl_str = "all";
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, NULL);
  fail_unless(res == -2, "Failed to handle NULL addr");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  addr = pr_netaddr_get_addr(p, "localhost", NULL);
  fail_unless(addr != NULL, "Failed to get addr for '%s': %s", "localhost",
    strerror(errno));

  if (getenv("TRAVIS") == NULL) {
    /* It's possible that the DNS name for 'localhost' that is used will
     * actually be 'localhost.localdomain', depending on the contents of
     * the host's /etc/hosts file.
     */
    if (strcmp(pr_netaddr_get_dnsstr(addr), "localhost.localdomain") == 0) {
      have_localdomain = TRUE;
    }
  }

  res = pr_netacl_match(NULL, addr);
  fail_unless(res == -2, "Failed to handle NULL ACL");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_netacl_match(acl, addr);
  fail_unless(res == 1, "Failed to positively match ACL to addr: %s",
    strerror(errno));

  acl_str = "none";
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  fail_unless(res == -1, "Failed to negatively match ACL to addr: %s",
    strerror(errno));

  acl_str = pstrdup(p, "127.0.0.1");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  fail_unless(res == 1, "Failed to positively match ACL to addr: %s",
    strerror(errno));

  acl_str = pstrdup(p, "!127.0.0.1");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  fail_unless(res == -1, "Failed to negatively match ACL to addr: %s",
    strerror(errno));

  acl_str = pstrdup(p, "192.168.0.1");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  fail_unless(res == 0, "Failed to match ACL to addr: %s", strerror(errno));

  acl_str = pstrdup(p, "!192.168.0.1");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  fail_unless(res == 1, "Failed to positively match ACL to addr: %s",
    strerror(errno));

  acl_str = pstrdup(p, "127.0.0.0/24");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  fail_unless(res == 1, "Failed to positively match ACL to addr: %s",
    strerror(errno));

  acl_str = pstrdup(p, "!127.0.0.0/24");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  fail_unless(res == -1, "Failed to negatively match ACL to addr: %s",
    strerror(errno));

  acl_str = pstrdup(p, "!1.2.3.4/24");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  fail_unless(res == 1, "Failed to positively match ACL to addr: %s",
    strerror(errno));

  acl_str = pstrdup(p, "127.0.0.");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  fail_unless(res == 1, "Failed to positively match ACL to addr: %s",
    strerror(errno));

  acl_str = pstrdup(p, "!127.0.0.");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  fail_unless(res == -1, "Failed to negatively match ACL to addr: %s",
    strerror(errno));

  acl_str = pstrdup(p, "!1.2.3.");
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  fail_unless(res == 1, "Failed to positively match ACL to addr: %s",
    strerror(errno));

  if (!have_localdomain) {
    acl_str = pstrdup(p, "localhost");

  } else {
    acl_str = pstrdup(p, "localhost.localdomain");
  }

  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  if (getenv("TRAVIS") == NULL) {
    fail_unless(res == 1, "Failed to positively match ACL to addr: %s",
      strerror(errno));
  }

  if (!have_localdomain) {
    acl_str = pstrdup(p, "!localhost");

  } else {
    acl_str = pstrdup(p, "!localhost.localdomain");
  }

  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  if (getenv("TRAVIS") == NULL) {
    fail_unless(res == -1, "Failed to negatively match ACL to addr: %s",
      strerror(errno));
  }

  acl_str = "!www.google.com";
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  fail_unless(res == 1, "Failed to positively match ACL to addr: %s",
    strerror(errno));

  if (!have_localdomain) {
    acl_str = pstrdup(p, "loc*st");

  } else {
    acl_str = pstrdup(p, "loc*st.loc*in");
  }

  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  if (getenv("TRAVIS") == NULL) {
    fail_unless(res == 1, "Failed to positively match ACL to addr: %s",
      strerror(errno));
  }

  if (!have_localdomain) {
    acl_str = pstrdup(p, "!loc*st");

  } else {
    acl_str = pstrdup(p, "!loc*st.loc*in");
  }

  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  if (getenv("TRAVIS") == NULL) {
    fail_unless(res == -1, "Failed to negatively match ACL to addr: %s",
      strerror(errno));
  }

  acl_str = "!www.g*g.com";
  acl = pr_netacl_create(p, acl_str);
  fail_unless(acl != NULL, "Failed to handle ACL string '%s': %s", acl_str,
    strerror(errno));

  res = pr_netacl_match(acl, addr);
  fail_unless(res == 1, "Failed to positively match ACL to addr: %s",
    strerror(errno));

  reverse_dns = ServerUseReverseDNS;
  ServerUseReverseDNS = FALSE;

  res = pr_netacl_match(acl, addr);
  fail_unless(res == 0, "Matched DNS glob ACL to addr unexpectedly");

  ServerUseReverseDNS = reverse_dns;
}
END_TEST

START_TEST (netacl_get_negated_test) {
  pr_netacl_t *acl;
  int res;

  res = pr_netacl_get_negated(NULL);
  fail_unless(res == -1, "Failed to handle NULL argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  acl = pr_netacl_create(p, "127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_netacl_get_negated(acl);
  fail_unless(res == 0, "Expected %d, got %d", 0, res);

  acl = pr_netacl_create(p, "!127.0.0.1");
  fail_unless(acl != NULL, "Failed to create ACL: %s", strerror(errno));

  res = pr_netacl_get_negated(acl);
  fail_unless(res == 1, "Expected %d, got %d", 1, res);
}
END_TEST

Suite *tests_get_netacl_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("netacl");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, netacl_create_test);
  tcase_add_test(testcase, netacl_get_str_test);
  tcase_add_test(testcase, netacl_get_str2_test);
  tcase_add_test(testcase, netacl_dup_test);
  tcase_add_test(testcase, netacl_match_test);
  tcase_add_test(testcase, netacl_get_negated_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
