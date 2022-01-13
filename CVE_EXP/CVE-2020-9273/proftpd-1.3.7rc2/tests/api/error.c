/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2016-2017 The ProFTPD Project team
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

/* Error API tests */

#include "tests.h"
#include "error.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("error", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("error", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

static const char *get_errnum(pool *err_pool, int xerrno) {
  char errnum[32];
  memset(errnum, '\0', sizeof(errnum));
  snprintf(errnum, sizeof(errnum)-1, "%d", xerrno);
  return pstrdup(err_pool, errnum);
}

static const char *get_uid(pool *err_pool) {
  char uid[32];
  memset(uid, '\0', sizeof(uid));
  snprintf(uid, sizeof(uid)-1, "%lu", (unsigned long) geteuid());
  return pstrdup(err_pool, uid);
}

static const char *get_gid(pool *err_pool) {
  char gid[32];
  memset(gid, '\0', sizeof(gid));
  snprintf(gid, sizeof(gid)-1, "%lu", (unsigned long) getegid());
  return pstrdup(err_pool, gid);
}

START_TEST (error_create_test) {
  pr_error_t *err;

  err = pr_error_create(NULL, 0);
  fail_unless(err == NULL, "Failed handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  err = pr_error_create(p, -1);
  fail_unless(err == NULL, "Failed handle negative errno");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  err = pr_error_create(p, 0);
  fail_unless(err != NULL, "Failed allocate error: %s", strerror(errno));
  pr_error_destroy(err);
}
END_TEST

START_TEST (error_destroy_test) {
  pr_error_t *err;
  int xerrno = 77;

  err = pr_error_create(p, 0);
  fail_unless(err != NULL, "Failed allocate error: %s", strerror(errno));

  /* Make sure that pr_error_destroy() preserves the existing errno value. */
  errno = xerrno;
  pr_error_destroy(NULL);
  pr_error_destroy(err);

  fail_unless(errno == xerrno, "Expected errno %d, got %d", xerrno, errno);
}
END_TEST

START_TEST (error_get_who_test) {
  int res, xerrno;
  uid_t err_uid = -1, uid;
  gid_t err_gid = -1, gid;
  pr_error_t *err = NULL;

  uid = geteuid();
  gid = getegid();

  res = pr_error_get_who(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EACCES;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_get_who(err, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null uid_t pointer");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_error_get_who(err, &err_uid, NULL);
  fail_unless(res == 0, "Failed to get error identity: %s", strerror(errno));
  fail_unless(err_uid == uid, "Expected %lu, got %lu", (unsigned long) uid,
    (unsigned long) err_uid);

  err_uid = -1;

  res = pr_error_get_who(err, NULL, &err_gid);
  fail_unless(res == 0, "Failed to get error identity: %s", strerror(errno));
  fail_unless(err_gid == gid, "Expected %lu, got %lu", (unsigned long) gid,
    (unsigned long) err_gid);

  err_gid = -1;

  res = pr_error_get_who(err, &err_uid, &err_gid);
  fail_unless(res == 0, "Failed to get error identity: %s", strerror(errno));
  fail_unless(err_uid == uid, "Expected %lu, got %lu", (unsigned long) uid,
    (unsigned long) err_uid);
  fail_unless(err_gid == gid, "Expected %lu, got %lu", (unsigned long) gid,
    (unsigned long) err_gid);

  pr_error_destroy(err);
}
END_TEST

START_TEST (error_set_why_test) {
  int res;
  pr_error_t *err;

  mark_point();
  res = pr_error_set_why(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  err = pr_error_create(p, 1);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_set_why(err, NULL);
  fail_unless(res < 0, "Failed to handle null why");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_error_set_why(err, "because I wanted to");
  fail_unless(res == 0, "Failed to set why: %s", strerror(errno));

  pr_error_destroy(err);
}
END_TEST

START_TEST (error_set_where_test) {
  int res;
  pr_error_t *err;

  mark_point();
  res = pr_error_set_where(NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  err = pr_error_create(p, 1);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_set_where(err, NULL, NULL, 0);
  fail_unless(res == 0, "Failed to set where: %s", strerror(errno));

  pr_error_destroy(err);
}
END_TEST

START_TEST (error_set_what_test) {
  int res;
  pr_error_t *err;

  mark_point();
  res = pr_error_set_what(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  err = pr_error_create(p, 1);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_set_what(err, NULL);
  fail_unless(res < 0, "Failed to handle null what");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_error_set_what(err, "testing");
  fail_unless(res == 0, "Failed to set what: %s", strerror(errno));

  pr_error_destroy(err);
}
END_TEST

START_TEST (error_explainer_test) {
  module m;
  const char *name;
  pr_error_explainer_t *explainer;
  int res;

  /* Unregister with none registered -- ENOENT */

  mark_point();
  res = pr_error_unregister_explainer(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "testing";
  res = pr_error_unregister_explainer(p, NULL, name);
  fail_unless(res < 0, "Failed to handle no registered explainers");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";

  res = pr_error_unregister_explainer(p, &m, NULL);
  fail_unless(res < 0, "Failed to handle no registered explainers");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res < 0, "Failed to handle no registered explainers");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  res = pr_error_use_explainer(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle no registered explainers");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  explainer = pr_error_register_explainer(NULL, NULL, NULL);
  fail_unless(explainer == NULL, "Failed to handle null pool argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  explainer = pr_error_register_explainer(p, NULL, NULL);
  fail_unless(explainer == NULL, "Failed to handle null name argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer == NULL, "Failed to handle duplicate registration");
  fail_unless(errno == EEXIST, "Expected EEXIST (%d), got %s (%d)", EEXIST,
    strerror(errno), errno);

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to handle unregister '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res < 0, "Failed to handle no registered explainers");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_unregister_explainer(p, NULL, name);
  fail_unless(res == 0, "Failed to handle unregister '%s' explainer: %s",
    name, strerror(errno));

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_unregister_explainer(p, &m, NULL);
  fail_unless(res == 0, "Failed to handle unregister module explainer: %s",
    strerror(errno));

  /* Selecting the explainer to use. */

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_use_explainer(p, &m, NULL);
  fail_unless(res < 0, "Failed to handle null name argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_error_use_explainer(p, &m, "foobar");
  fail_unless(res < 0, "Used 'foobar' explainer unexpectedly");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  res = pr_error_use_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to use '%s' explainer: %s", name,
    strerror(errno));

  /* Use already-selected explainers */
  res = pr_error_use_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to use '%s' explainer: %s", name,
    strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to handle unregister module explainer: %s",
    strerror(errno));
}
END_TEST

START_TEST (error_strerror_minimal_test) {
  int format = PR_ERROR_FORMAT_USE_MINIMAL, xerrno;
  pr_error_t *err;
  const char *res, *expected, *what;

  pr_error_use_formats(PR_ERROR_FORMAT_DEFAULT);

  xerrno = errno = ENOENT;
  expected = strerror(xerrno);
  res = pr_error_strerror(NULL, format);
  fail_unless(res != NULL, "Failed to handle null error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_strerror(err, -1);
  fail_unless(res != NULL, "Failed to handle invalid format: %s",
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  expected = pstrcat(p, "No such file or directory [ENOENT (",
    get_errnum(p, xerrno), ")]", NULL);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  pr_error_use_formats(format);
  expected = pstrcat(p, "No such file or directory [ENOENT (",
    get_errnum(p, xerrno), ")]", NULL);
  res = pr_error_strerror(err, 0);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  pr_error_destroy(err);
  xerrno = 0;

  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  expected = "Success [EOK (0)]";
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  pr_error_destroy(err);

  /* We want to test what happens when we use an invalid errno value. */
  xerrno = INT_MAX - 786;

  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  expected = pstrcat(p, strerror(xerrno), " [<unknown/unsupported error> (",
    get_errnum(p, xerrno), ")]", NULL);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  pr_error_destroy(err);
  xerrno = ENOSYS;

  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  what = "test";
  pr_error_set_what(err, what);

  expected = pstrcat(p, what, " failed with \"", strerror(xerrno), " [ENOSYS (",
    get_errnum(p, xerrno), ")]\"", NULL);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  pr_error_destroy(err);

  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  what = "test2";
  pr_error_set_what(err, what);

  expected = pstrcat(p, what, " failed with \"", strerror(xerrno),
    " [ENOSYS (", get_errnum(p, xerrno), ")]\"", NULL);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  pr_error_destroy(err);
  pr_error_use_formats(PR_ERROR_FORMAT_DEFAULT);
}
END_TEST

START_TEST (error_strerror_terse_test) {
  int format = PR_ERROR_FORMAT_USE_TERSE, xerrno;
  pr_error_t *err;
  const char *res, *expected, *what;

  pr_error_use_formats(PR_ERROR_FORMAT_USE_TERSE);

  xerrno = errno = ENOENT;
  expected = strerror(xerrno);
  res = pr_error_strerror(NULL, format);
  fail_unless(res != NULL, "Failed to handle null error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_strerror(err, -1);
  fail_unless(res != NULL, "Failed to handle invalid format: %s",
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  expected = pstrdup(p, "No such file or directory");
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  pr_error_destroy(err);

  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  what = "test2";
  pr_error_set_what(err, what);

  expected = pstrcat(p, what, " failed with \"", strerror(xerrno),
    " [ENOENT (", get_errnum(p, xerrno), ")]\"", NULL);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  pr_error_destroy(err);
  pr_error_use_formats(PR_ERROR_FORMAT_DEFAULT);
}
END_TEST

START_TEST (error_strerror_detailed_test) {
  int format = PR_ERROR_FORMAT_USE_DETAILED, xerrno, res2, error_details;
  pr_error_t *err;
  const char *res, *expected, *what, *why;

  pr_error_use_formats(PR_ERROR_FORMAT_DEFAULT);

  xerrno = errno = ENOENT;
  expected = strerror(xerrno);
  res = pr_error_strerror(NULL, format);
  fail_unless(res != NULL, "Failed to handle null error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_strerror(err, -1);
  fail_unless(res != NULL, "Failed to handle invalid format: %s",
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  /* no what */
  expected = pstrcat(p, "in API, UID ", get_uid(p), ", GID ", get_gid(p),
    " failed with \"", strerror(xerrno),
    " [ENOENT (", get_errnum(p, xerrno), ")]\"", NULL);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  /* Exercise the "lineno = 0" code path. */
  res2 = pr_error_set_where(err, NULL, __FILE__, 0);
  fail_unless(res2 == 0, "Failed to set error where: %s", strerror(errno));

  expected = pstrcat(p, "in API [api/error.c], UID ", get_uid(p),
    ", GID ", get_gid(p), " failed with \"", strerror(xerrno),
    " [ENOENT (", get_errnum(p, xerrno), ")]\"", NULL);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  res2 = pr_error_set_where(err, NULL, __FILE__, __LINE__);
  fail_unless(res2 == 0, "Failed to set error where: %s", strerror(errno));

  expected = pstrcat(p, "in API [api/error.c:534], UID ", get_uid(p),
    ", GID ", get_gid(p), " failed with \"", strerror(xerrno),
    " [ENOENT (", get_errnum(p, xerrno), ")]\"", NULL);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  /* Disable use of the module name. */
  error_details = pr_error_use_details(PR_ERROR_DETAILS_DEFAULT);
  error_details &= ~PR_ERROR_DETAILS_USE_MODULE;
  (void) pr_error_use_details(error_details);

  expected = pstrcat(p, "in api/error.c:534, UID ", get_uid(p), ", GID ",
    get_gid(p), " failed with \"", strerror(xerrno),
    " [ENOENT (", get_errnum(p, xerrno), ")]\"", NULL);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  /* Disable use of the file location. */
  error_details &= ~PR_ERROR_DETAILS_USE_FILE;
  (void) pr_error_use_details(error_details);

  /* We have no who, no where, no why, no what.  Expect the default/fallback,
   * then.
   */
  expected = strerror(xerrno);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  what = "test";
  res2 = pr_error_set_what(err, what);
  fail_unless(res2 == 0, "Failed to set what '%s': %s", what,
    strerror(errno));

  expected = pstrcat(p, "UID ", get_uid(p), ", GID ", get_gid(p),
    " attempting to ", what, " failed with \"", strerror(xerrno), " [ENOENT (",
    get_errnum(p, xerrno), ")]\"", NULL);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  session.user = "foo";

  /* Since the error's user is set at time of creation, we need to make
   * a new error for these tests.
   */
  pr_error_destroy(err);
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  (void) pr_error_set_where(err, NULL, __FILE__, __LINE__);
  (void) pr_error_set_what(err, what);

  expected = pstrcat(p, "user ", session.user, " (UID ", get_uid(p),
    ", GID ", get_gid(p), ") via ftp attempting to ", what,
    " failed with \"No such file or directory [ENOENT (",
    get_errnum(p, xerrno), ")]\"", NULL);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  /* Disable use of names. */
  error_details |= (PR_ERROR_DETAILS_USE_MODULE|PR_ERROR_DETAILS_USE_FILE);
  error_details &= ~PR_ERROR_DETAILS_USE_NAMES;
  (void) pr_error_use_details(error_details);

  expected = pstrcat(p, "in API [api/error.c:593], UID ", get_uid(p),
    ", GID ", get_gid(p), " via ftp attempting to ", what,
    " failed with \"", strerror(xerrno), " [ENOENT (",
    get_errnum(p, xerrno), ")]\"", NULL);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  /* Enable use of names, disable use of IDs. */
  error_details |= PR_ERROR_DETAILS_USE_NAMES;
  error_details &= ~PR_ERROR_DETAILS_USE_IDS;
  (void) pr_error_use_details(error_details);

  expected = pstrcat(p, "in API [api/error.c:593], user ", session.user,
    " via ftp attempting to ", what, " failed with \"", strerror(xerrno),
    " [ENOENT (", get_errnum(p, xerrno), ")]\"", NULL);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  /* Enable use of IDs, disable use of protocol. */
  error_details |= PR_ERROR_DETAILS_USE_IDS;
  error_details &= ~PR_ERROR_DETAILS_USE_PROTOCOL;
  (void) pr_error_use_details(error_details);

  expected = pstrcat(p, "in API [api/error.c:593], user ", session.user,
    " (UID ", get_uid(p), ", GID ", get_gid(p), ") attempting to ", what,
    " failed with \"", strerror(xerrno), " [ENOENT (",
    get_errnum(p, xerrno), ")]\"", NULL);
  res = pr_error_strerror(err, format);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  /* Enable everything */
  error_details = PR_ERROR_DETAILS_DEFAULT;
  (void) pr_error_use_details(error_details);

  why = "test a function";
  res2 = pr_error_set_why(err, why);
  fail_unless(res2 == 0, "Failed to set why: %s", strerror(errno));

  expected = pstrcat(p, "in API [api/error.c:593], user ", session.user,
    " (UID ", get_uid(p), ", GID ", get_gid(p), ") via ftp wanted to ", why,
    " but ", what, " failed with \"", strerror(xerrno), " [ENOENT (",
    get_errnum(p, xerrno), ")]\"", NULL);
  res = pr_error_strerror(err, 0);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  pr_error_destroy(err);
  pr_error_use_details(PR_ERROR_DETAILS_DEFAULT);
}
END_TEST

static const char *test_explainer(pool *err_pool, int xerrno,
    const char *path, int flags, mode_t mode, const char **args) {
  *args = pstrcat(err_pool, "path = '", path,
    "', flags = O_RDONLY, mode = 0755", NULL);
  return pstrdup(err_pool, "test mode is not real");
}

START_TEST (error_strerror_detailed_explained_test) {
  int xerrno, res2;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  const char *res, *expected, *what, *why;
  module m;

  session.user = "foo";

  xerrno = ENOENT;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  what = "test";
  res2 = pr_error_set_what(err, what);
  fail_unless(res2 == 0, "Failed to set what: %s", strerror(errno));

  why = "demonstrate an error explanation";
  res2 = pr_error_set_why(err, why);
  fail_unless(res2 == 0, "Failed to set why: %s", strerror(errno));

  memset(&m, 0, sizeof(m));
  m.name = "error";

  res2 = pr_error_set_where(err, &m, __FILE__, __LINE__);
  fail_unless(res2 == 0, "Failed to set where: %s", strerror(errno));

  explainer = pr_error_register_explainer(p, &m, "error");
  explainer->explain_open = test_explainer;

  res2 = pr_error_explain_open(err, "path", O_RDONLY, 0755);
  fail_unless(res2 == 0, "Failed to explain error: %s", strerror(errno));

  expected = pstrcat(p, "in mod_", m.name, " [api/error.c:699], user ",
    session.user, " (UID ", get_uid(p), ", GID ",
    get_gid(p), ") via ftp wanted to ", why,
    " but open() using path = 'path', flags = O_RDONLY, mode = 0755 "
    "failed with \"", strerror(xerrno), " [ENOENT (", get_errnum(p, xerrno),
    ")]\" because test mode is not real", NULL);
  res = pr_error_strerror(err, 0);
  fail_unless(res != NULL, "Failed to format error: %s", strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  (void) pr_error_unregister_explainer(p, &m, NULL);
  pr_error_destroy(err);
}
END_TEST

static int test_explain_return_eperm = FALSE;

/* accept */
static const char *test_explain_accept(pool *err_pool, int xerrno, int fd,
    struct sockaddr *addr, socklen_t *addr_len, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_accept_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_accept(NULL, -1, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_accept(err, -1, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null explainer");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_accept(err, -1, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_accept = test_explain_accept;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_accept(err, -1, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_accept(err, -1, NULL, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* bind */
static const char *test_explain_bind(pool *err_pool, int xerrno, int fd,
    const struct sockaddr *addr, socklen_t addr_len, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_bind_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_bind(NULL, -1, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_bind(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_bind(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_bind = test_explain_bind;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_bind(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_bind(err, -1, NULL, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* chdir */
static const char *test_explain_chdir(pool *err_pool, int xerrno,
    const char *path, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_chdir_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_chdir(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_chdir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_chdir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_chdir = test_explain_chdir;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_chdir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_chdir(err, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* chmod */
static const char *test_explain_chmod(pool *err_pool, int xerrno,
    const char *path, mode_t mode, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_chmod_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_chmod(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_chmod(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_chmod(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_chmod = test_explain_chmod;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_chmod(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_chmod(err, NULL, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* chown */
static const char *test_explain_chown(pool *err_pool, int xerrno,
    const char *path, uid_t uid, gid_t gid, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_chown_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_chown(NULL, NULL, -1, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_chown(err, NULL, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_chown(err, NULL, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_chown = test_explain_chown;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_chown(err, NULL, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_chown(err, NULL, -1, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* chroot */
static const char *test_explain_chroot(pool *err_pool, int xerrno,
    const char *path, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_chroot_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_chroot(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_chroot(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_chroot(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_chroot = test_explain_chroot;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_chroot(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_chroot(err, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* close */
static const char *test_explain_close(pool *err_pool, int xerrno, int fd,
    const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_close_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_close(NULL, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_close(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_close(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_close = test_explain_close;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_close(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_close(err, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* closedir */
static const char *test_explain_closedir(pool *err_pool, int xerrno,
    void *dirh, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_closedir_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_closedir(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_closedir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_closedir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_closedir = test_explain_closedir;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_closedir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_closedir(err, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* connect */
static const char *test_explain_connect(pool *err_pool, int xerrno, int fd,
    const struct sockaddr *addr, socklen_t addr_len, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_connect_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_connect(NULL, -1, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_connect(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_connect(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_connect = test_explain_connect;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_connect(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_connect(err, -1, NULL, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* fchmod */
static const char *test_explain_fchmod(pool *err_pool, int xerrno, int fd,
    mode_t mode, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_fchmod_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_fchmod(NULL, -1, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_fchmod(err, -1, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_fchmod(err, -1, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_fchmod = test_explain_fchmod;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_fchmod(err, -1, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_fchmod(err, -1, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* fchown */
static const char *test_explain_fchown(pool *err_pool, int xerrno, int fd,
    uid_t uid, gid_t gid, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_fchown_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_fchown(NULL, -1, -1, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_fchown(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_fchown(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_fchown = test_explain_fchown;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_fchown(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_fchown(err, -1, -1, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* fclose */
static const char *test_explain_fclose(pool *err_pool, int xerrno, FILE *fh,
    const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_fclose_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_fclose(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_fclose(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_fclose(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_fclose = test_explain_fclose;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_fclose(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_fclose(err, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* fcntl */
static const char *test_explain_fcntl(pool *err_pool, int xerrno, int fd,
    int op, long arg, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_fcntl_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_fcntl(NULL, -1, -1, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_fcntl(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_fcntl(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_fcntl = test_explain_fcntl;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_fcntl(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_fcntl(err, -1, -1, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* fdopen */
static const char *test_explain_fdopen(pool *err_pool, int xerrno, int fd,
    const char *mode, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_fdopen_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_fdopen(NULL, -1, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_fdopen(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_fdopen(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_fdopen = test_explain_fdopen;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_fdopen(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_fdopen(err, -1, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* flock */
static const char *test_explain_flock(pool *err_pool, int xerrno, int fd,
    int op, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_flock_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_flock(NULL, -1, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_flock(err, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_flock(err, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_flock = test_explain_flock;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_flock(err, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_flock(err, -1, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* fopen */
static const char *test_explain_fopen(pool *err_pool, int xerrno,
    const char *path, const char *mode, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_fopen_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_fopen(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_fopen(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_fopen(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_fopen = test_explain_fopen;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_fopen(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_fopen(err, NULL, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* fork */
static const char *test_explain_fork(pool *err_pool, int xerrno,
    const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_fork_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_fork(NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_fork(err);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_fork(err);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_fork = test_explain_fork;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_fork(err);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_fork(err);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* fstat */
static const char *test_explain_fstat(pool *err_pool, int xerrno, int fd,
    struct stat *st, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_fstat_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_fstat(NULL, -1, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_fstat(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_fstat(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_fstat = test_explain_fstat;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_fstat(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_fstat(err, -1, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* fstatfs */
static const char *test_explain_fstatfs(pool *err_pool, int xerrno, int fd,
    void *stfs, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_fstatfs_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_fstatfs(NULL, -1, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_fstatfs(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_fstatfs(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_fstatfs = test_explain_fstatfs;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_fstatfs(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_fstatfs(err, -1, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* fstatvfs */
static const char *test_explain_fstatvfs(pool *err_pool, int xerrno, int fd,
    void *stfs, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_fstatvfs_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_fstatvfs(NULL, -1, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_fstatvfs(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_fstatvfs(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_fstatvfs = test_explain_fstatvfs;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_fstatvfs(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_fstatvfs(err, -1, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* fsync */
static const char *test_explain_fsync(pool *err_pool, int xerrno, int fd,
    const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_fsync_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_fsync(NULL, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_fsync(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_fsync(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_fsync = test_explain_fsync;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_fsync(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_fsync(err, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* ftruncate */
static const char *test_explain_ftruncate(pool *err_pool, int xerrno, int fd,
    off_t len, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_ftruncate_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_ftruncate(NULL, -1, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_ftruncate(err, -1, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_ftruncate(err, -1, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_ftruncate = test_explain_ftruncate;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_ftruncate(err, -1, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_ftruncate(err, -1, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* futimes */
static const char *test_explain_futimes(pool *err_pool, int xerrno, int fd,
    const struct timeval *tvs, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_futimes_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_futimes(NULL, -1, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_futimes(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_futimes(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_futimes = test_explain_futimes;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_futimes(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_futimes(err, -1, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* getaddrinfo */
static const char *test_explain_getaddrinfo(pool *err_pool, int xerrno,
    const char *name, const char *service, const struct addrinfo *hints,
    struct addrinfo **res, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_getaddrinfo_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_getaddrinfo(NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_getaddrinfo(err, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_getaddrinfo(err, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_getaddrinfo = test_explain_getaddrinfo;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_getaddrinfo(err, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_getaddrinfo(err, NULL, NULL, NULL, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* gethostbyname */
static const char *test_explain_gethostbyname(pool *err_pool, int xerrno,
    const char *name, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_gethostbyname_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_gethostbyname(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_gethostbyname(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_gethostbyname(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_gethostbyname = test_explain_gethostbyname;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_gethostbyname(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_gethostbyname(err, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* gethostbyname2 */
static const char *test_explain_gethostbyname2(pool *err_pool, int xerrno,
    const char *name, int family, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_gethostbyname2_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_gethostbyname2(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_gethostbyname2(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_gethostbyname2(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_gethostbyname2 = test_explain_gethostbyname2;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_gethostbyname2(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_gethostbyname2(err, NULL, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* gethostname */
static const char *test_explain_gethostname(pool *err_pool, int xerrno,
    char *buf, size_t sz, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_gethostname_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_gethostname(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_gethostname(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_gethostname(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_gethostname = test_explain_gethostname;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_gethostname(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_gethostname(err, NULL, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* getnameinfo */
static const char *test_explain_getnameinfo(pool *err_pool, int xerrno,
    const struct sockaddr *addr, socklen_t addr_len,
    char *host, size_t host_len, char *service, size_t service_len, int flags,
    const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_getnameinfo_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_getnameinfo(NULL, NULL, 0, NULL, 0, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_getnameinfo(err, NULL, 0, NULL, 0, NULL, 0, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_getnameinfo(err, NULL, 0, NULL, 0, NULL, 0, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_getnameinfo = test_explain_getnameinfo;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_getnameinfo(err, NULL, 0, NULL, 0, NULL, 0, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_getnameinfo(err, NULL, 0, NULL, 0, NULL, 0, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* getpeername */
static const char *test_explain_getpeername(pool *err_pool, int xerrno,
    int fd, struct sockaddr *addr, socklen_t *addr_len, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_getpeername_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_getpeername(NULL, -1, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_getpeername(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_getpeername(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_getpeername = test_explain_getpeername;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_getpeername(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_getpeername(err, -1, NULL, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* getrlimit */
static const char *test_explain_getrlimit(pool *err_pool, int xerrno,
    int resource, struct rlimit *rlim, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_getrlimit_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_getrlimit(NULL, -1, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_getrlimit(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_getrlimit(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_getrlimit = test_explain_getrlimit;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_getrlimit(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_getrlimit(err, -1, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* getsockname */
static const char *test_explain_getsockname(pool *err_pool, int xerrno,
    int fd, struct sockaddr *addr, socklen_t *addr_len, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_getsockname_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_getsockname(NULL, -1, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_getsockname(err, -1, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_getsockname(err, -1, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_getsockname = test_explain_getsockname;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_getsockname(err, -1, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_getsockname(err, -1, NULL, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* getsockopt */
static const char *test_explain_getsockopt(pool *err_pool, int xerrno,
    int fd, int level, int option, void *val, socklen_t *valsz,
    const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_getsockopt_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_getsockopt(NULL, -1, -1, -1, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_getsockopt(err, -1, -1, -1, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_getsockopt(err, -1, -1, -1, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_getsockopt = test_explain_getsockopt;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_getsockopt(err, -1, -1, -1, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_getsockopt(err, -1, -1, -1, NULL, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* lchown */
static const char *test_explain_lchown(pool *err_pool, int xerrno,
    const char *path, uid_t uid, gid_t gid, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_lchown_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_lchown(NULL, NULL, -1, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_lchown(err, NULL, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_lchown(err, NULL, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_lchown = test_explain_lchown;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_lchown(err, NULL, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_lchown(err, NULL, -1, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* link */
static const char *test_explain_link(pool *err_pool, int xerrno,
    const char *target_path, const char *link_path, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_link_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_link(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_link(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_link(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_link = test_explain_link;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_link(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_link(err, NULL, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* listen */
static const char *test_explain_listen(pool *err_pool, int xerrno, int fd,
    int backlog, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_listen_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_listen(NULL, -1, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_listen(err, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_listen(err, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_listen = test_explain_listen;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_listen(err, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_listen(err, -1, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* lseek */
static const char *test_explain_lseek(pool *err_pool, int xerrno, int fd,
    off_t offset, int whence, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_lseek_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_lseek(NULL, -1, 0, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_lseek(err, -1, 0, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_lseek(err, -1, 0, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_lseek = test_explain_lseek;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_lseek(err, -1, 0, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_lseek(err, -1, 0, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* lstat */
static const char *test_explain_lstat(pool *err_pool, int xerrno,
    const char *path, struct stat *st, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_lstat_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_lstat(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_lstat(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_lstat(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_lstat = test_explain_lstat;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_lstat(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_lstat(err, NULL, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* mkdir */
static const char *test_explain_mkdir(pool *err_pool, int xerrno,
    const char *path, mode_t mode, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_mkdir_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_mkdir(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_mkdir(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_mkdir(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_mkdir = test_explain_mkdir;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_mkdir(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_mkdir(err, NULL, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* mkdtemp */
static const char *test_explain_mkdtemp(pool *err_pool, int xerrno,
    char *tmpl, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_mkdtemp_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_mkdtemp(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_mkdtemp(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_mkdtemp(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_mkdtemp = test_explain_mkdtemp;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_mkdtemp(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_mkdtemp(err, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* mkstemp */
static const char *test_explain_mkstemp(pool *err_pool, int xerrno,
    char *tmpl, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_mkstemp_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_mkstemp(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_mkstemp(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_mkstemp(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_mkstemp = test_explain_mkstemp;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_mkstemp(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_mkstemp(err, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* open */
static const char *test_explain_open(pool *err_pool, int xerrno,
    const char *path, int flags, mode_t mode, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_open_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_open(NULL, NULL, 0, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_open(err, NULL, 0, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_open(err, NULL, 0, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_open = test_explain_open;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_open(err, NULL, 0, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_open(err, NULL, 0, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* opendir */
static const char *test_explain_opendir(pool *err_pool, int xerrno,
    const char *path, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_opendir_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_opendir(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_opendir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_opendir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_opendir = test_explain_opendir;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_opendir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_opendir(err, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* read */
static const char *test_explain_read(pool *err_pool, int xerrno, int fd,
    void *buf, size_t sz, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_read_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_read(NULL, -1, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_read(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_read(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_read = test_explain_read;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_read(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_read(err, -1, NULL, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* readdir */
static const char *test_explain_readdir(pool *err_pool, int xerrno, void *dirh,
    const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_readdir_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_readdir(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_readdir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_readdir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_readdir = test_explain_readdir;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_readdir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_readdir(err, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* readlink */
static const char *test_explain_readlink(pool *err_pool, int xerrno,
    const char *path, char *buf, size_t sz, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_readlink_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_readlink(NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_readlink(err, NULL, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_readlink(err, NULL, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_readlink = test_explain_readlink;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_readlink(err, NULL, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_readlink(err, NULL, NULL, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* readv */
static const char *test_explain_readv(pool *err_pool, int xerrno, int fd,
    const struct iovec *iov, int iov_len, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_readv_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_readv(NULL, -1, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_readv(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_readv(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_readv = test_explain_readv;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_readv(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_readv(err, -1, NULL, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* rename */
static const char *test_explain_rename(pool *err_pool, int xerrno,
    const char *old_path, const char *new_path, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_rename_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_rename(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_rename(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_rename(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_rename = test_explain_rename;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_rename(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_rename(err, NULL, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* rmdir */
static const char *test_explain_rmdir(pool *err_pool, int xerrno,
    const char *path, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_rmdir_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_rmdir(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_rmdir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_rmdir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_rmdir = test_explain_rmdir;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_rmdir(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_rmdir(err, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* setegid */
static const char *test_explain_setegid(pool *err_pool, int xerrno,
    gid_t egid, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_setegid_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_setegid(NULL, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_setegid(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_setegid(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_setegid = test_explain_setegid;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_setegid(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_setegid(err, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* seteuid */
static const char *test_explain_seteuid(pool *err_pool, int xerrno,
    uid_t euid, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_seteuid_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_seteuid(NULL, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_seteuid(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_seteuid(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_seteuid = test_explain_seteuid;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_seteuid(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_seteuid(err, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* setgid */
static const char *test_explain_setgid(pool *err_pool, int xerrno,
    gid_t gid, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_setgid_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_setgid(NULL, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_setgid(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_setgid(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_setgid = test_explain_setgid;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_setgid(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_setgid(err, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* setregid */
static const char *test_explain_setregid(pool *err_pool, int xerrno,
    gid_t rgid, gid_t egid, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_setregid_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_setregid(NULL, -1, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_setregid(err, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_setregid(err, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_setregid = test_explain_setregid;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_setregid(err, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_setregid(err, -1, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* setresgid */
static const char *test_explain_setresgid(pool *err_pool, int xerrno,
    gid_t rgid, gid_t egid, gid_t sgid, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_setresgid_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_setresgid(NULL, -1, -1, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_setresgid(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_setresgid(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_setresgid = test_explain_setresgid;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_setresgid(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_setresgid(err, -1, -1, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* setresuid */
static const char *test_explain_setresuid(pool *err_pool, int xerrno,
    uid_t ruid, uid_t euid, uid_t suid, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_setresuid_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_setresuid(NULL, -1, -1, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_setresuid(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_setresuid(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_setresuid = test_explain_setresuid;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_setresuid(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_setresuid(err, -1, -1, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* setreuid */
static const char *test_explain_setreuid(pool *err_pool, int xerrno,
    uid_t ruid, uid_t euid, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_setreuid_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_setreuid(NULL, -1, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_setreuid(err, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_setreuid(err, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_setreuid = test_explain_setreuid;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_setreuid(err, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_setreuid(err, -1, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* setrlimit */
static const char *test_explain_setrlimit(pool *err_pool, int xerrno,
    int resource, const struct rlimit *rlim, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_setrlimit_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_setrlimit(NULL, -1, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_setrlimit(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_setrlimit(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_setrlimit = test_explain_setrlimit;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_setrlimit(err, -1, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_setrlimit(err, -1, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* setsockopt */
static const char *test_explain_setsockopt(pool *err_pool, int xerrno, int fd,
    int level, int option, const void *val, socklen_t valsz,
    const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_setsockopt_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_setsockopt(NULL, -1, -1, -1, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_setsockopt(err, -1, -1, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_setsockopt(err, -1, -1, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_setsockopt = test_explain_setsockopt;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_setsockopt(err, -1, -1, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_setsockopt(err, -1, -1, -1, NULL, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* setuid */
static const char *test_explain_setuid(pool *err_pool, int xerrno,
    uid_t uid, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_setuid_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_setuid(NULL, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_setuid(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_setuid(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_setuid = test_explain_setuid;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_setuid(err, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_setuid(err, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* socket */
static const char *test_explain_socket(pool *err_pool, int xerrno,
    int domain, int type, int proto, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_socket_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_socket(NULL, -1, -1, -1);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_socket(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_socket(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_socket = test_explain_socket;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_socket(err, -1, -1, -1);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_socket(err, -1, -1, -1);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* stat */
static const char *test_explain_stat(pool *err_pool, int xerrno,
    const char *path, struct stat *st, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_stat_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_stat(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_stat(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_stat(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_stat = test_explain_stat;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_stat(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_stat(err, NULL, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* statfs */
static const char *test_explain_statfs(pool *err_pool, int xerrno,
    const char *path, void *stfs, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_statfs_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_statfs(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_statfs(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_statfs(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_statfs = test_explain_statfs;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_statfs(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_statfs(err, NULL, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* statvfs */
static const char *test_explain_statvfs(pool *err_pool, int xerrno,
    const char *path, void *stfs, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_statvfs_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_statvfs(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_statvfs(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_statvfs(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_statvfs = test_explain_statvfs;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_statvfs(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_statvfs(err, NULL, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* symlink */
static const char *test_explain_symlink(pool *err_pool, int xerrno,
    const char *target_path, const char *link_path, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_symlink_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_symlink(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_symlink(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_symlink(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_symlink = test_explain_symlink;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_symlink(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_symlink(err, NULL, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* truncate */
static const char *test_explain_truncate(pool *err_pool, int xerrno,
    const char *path, off_t len, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_truncate_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_truncate(NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_truncate(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_truncate(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_truncate = test_explain_truncate;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_truncate(err, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_truncate(err, NULL, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* unlink */
static const char *test_explain_unlink(pool *err_pool, int xerrno,
    const char *path, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_unlink_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_unlink(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_unlink(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_unlink(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_unlink = test_explain_unlink;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_unlink(err, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_unlink(err, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* utimes */
static const char *test_explain_utimes(pool *err_pool, int xerrno,
    const char *path, const struct timeval *tvs, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_utimes_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_utimes(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_utimes(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_utimes(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_utimes = test_explain_utimes;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_utimes(err, NULL, NULL);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_utimes(err, NULL, NULL);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* write */
static const char *test_explain_write(pool *err_pool, int xerrno, int fd,
    const void *buf, size_t sz, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_write_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_write(NULL, -1, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_write(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_write(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_write = test_explain_write;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_write(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_write(err, -1, NULL, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

/* writev */
static const char *test_explain_writev(pool *err_pool, int xerrno, int fd,
    const struct iovec *iov, int iov_len, const char **args) {

  if (test_explain_return_eperm == TRUE) {
    errno = EPERM;
    return NULL;
  }

  return pstrdup(err_pool, "it was not meant to be");
}

START_TEST (error_explain_writev_test) {
  int res, xerrno;
  pr_error_t *err;
  pr_error_explainer_t *explainer;
  module m;
  const char *name;

  res = pr_error_explain_writev(NULL, -1, NULL, 0);
  fail_unless(res < 0, "Failed to handle null error");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  xerrno = EINVAL;
  err = pr_error_create(p, xerrno);
  fail_unless(err != NULL, "Failed to allocate error: %s", strerror(errno));

  res = pr_error_explain_writev(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "error";
  name = "testsuite";

  explainer = pr_error_register_explainer(p, &m, name);
  fail_unless(explainer != NULL, "Failed to register '%s' explainer: %s",
    name, strerror(errno));

  res = pr_error_explain_writev(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == ENOSYS, "Expected ENOSYS (%d), got %s (%d)", ENOSYS,
    strerror(errno), errno);

  explainer->explain_writev = test_explain_writev;
  test_explain_return_eperm = TRUE;

  res = pr_error_explain_writev(err, -1, NULL, 0);
  fail_unless(res < 0, "Unexpectedly explained error");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  test_explain_return_eperm = FALSE;
  res = pr_error_explain_writev(err, -1, NULL, 0);
  fail_unless(res == 0, "Failed to explain error: %s", strerror(errno));

  res = pr_error_unregister_explainer(p, &m, name);
  fail_unless(res == 0, "Failed to unregister '%s' explainer: %s", name,
    strerror(errno));

  pr_error_destroy(err);
}
END_TEST

Suite *tests_get_error_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("error");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, error_create_test);
  tcase_add_test(testcase, error_destroy_test);
  tcase_add_test(testcase, error_get_who_test);
  tcase_add_test(testcase, error_set_why_test);
  tcase_add_test(testcase, error_set_where_test);
  tcase_add_test(testcase, error_set_what_test);
  tcase_add_test(testcase, error_explainer_test);
  tcase_add_test(testcase, error_strerror_minimal_test);
  tcase_add_test(testcase, error_strerror_terse_test);
  tcase_add_test(testcase, error_strerror_detailed_test);
  tcase_add_test(testcase, error_strerror_detailed_explained_test);

  tcase_add_test(testcase, error_explain_accept_test);
  tcase_add_test(testcase, error_explain_bind_test);
  tcase_add_test(testcase, error_explain_chdir_test);
  tcase_add_test(testcase, error_explain_chmod_test);
  tcase_add_test(testcase, error_explain_chown_test);
  tcase_add_test(testcase, error_explain_chroot_test);
  tcase_add_test(testcase, error_explain_close_test);
  tcase_add_test(testcase, error_explain_closedir_test);
  tcase_add_test(testcase, error_explain_connect_test);
  tcase_add_test(testcase, error_explain_fchmod_test);
  tcase_add_test(testcase, error_explain_fchown_test);
  tcase_add_test(testcase, error_explain_fclose_test);
  tcase_add_test(testcase, error_explain_fcntl_test);
  tcase_add_test(testcase, error_explain_fdopen_test);
  tcase_add_test(testcase, error_explain_flock_test);
  tcase_add_test(testcase, error_explain_fopen_test);
  tcase_add_test(testcase, error_explain_fork_test);
  tcase_add_test(testcase, error_explain_fstat_test);
  tcase_add_test(testcase, error_explain_fstatfs_test);
  tcase_add_test(testcase, error_explain_fstatvfs_test);
  tcase_add_test(testcase, error_explain_fsync_test);
  tcase_add_test(testcase, error_explain_ftruncate_test);
  tcase_add_test(testcase, error_explain_futimes_test);
  tcase_add_test(testcase, error_explain_getaddrinfo_test);
  tcase_add_test(testcase, error_explain_gethostbyname_test);
  tcase_add_test(testcase, error_explain_gethostbyname2_test);
  tcase_add_test(testcase, error_explain_gethostname_test);
  tcase_add_test(testcase, error_explain_getnameinfo_test);
  tcase_add_test(testcase, error_explain_getpeername_test);
  tcase_add_test(testcase, error_explain_getrlimit_test);
  tcase_add_test(testcase, error_explain_getsockname_test);
  tcase_add_test(testcase, error_explain_getsockopt_test);
  tcase_add_test(testcase, error_explain_lchown_test);
  tcase_add_test(testcase, error_explain_link_test);
  tcase_add_test(testcase, error_explain_listen_test);
  tcase_add_test(testcase, error_explain_lseek_test);
  tcase_add_test(testcase, error_explain_lstat_test);
  tcase_add_test(testcase, error_explain_mkdir_test);
  tcase_add_test(testcase, error_explain_mkdtemp_test);
  tcase_add_test(testcase, error_explain_mkstemp_test);
  tcase_add_test(testcase, error_explain_open_test);
  tcase_add_test(testcase, error_explain_opendir_test);
  tcase_add_test(testcase, error_explain_read_test);
  tcase_add_test(testcase, error_explain_readdir_test);
  tcase_add_test(testcase, error_explain_readlink_test);
  tcase_add_test(testcase, error_explain_readv_test);
  tcase_add_test(testcase, error_explain_rename_test);
  tcase_add_test(testcase, error_explain_rmdir_test);
  tcase_add_test(testcase, error_explain_setegid_test);
  tcase_add_test(testcase, error_explain_seteuid_test);
  tcase_add_test(testcase, error_explain_setgid_test);
  tcase_add_test(testcase, error_explain_setregid_test);
  tcase_add_test(testcase, error_explain_setresgid_test);
  tcase_add_test(testcase, error_explain_setresuid_test);
  tcase_add_test(testcase, error_explain_setreuid_test);
  tcase_add_test(testcase, error_explain_setrlimit_test);
  tcase_add_test(testcase, error_explain_setsockopt_test);
  tcase_add_test(testcase, error_explain_setuid_test);
  tcase_add_test(testcase, error_explain_socket_test);
  tcase_add_test(testcase, error_explain_stat_test);
  tcase_add_test(testcase, error_explain_statfs_test);
  tcase_add_test(testcase, error_explain_statvfs_test);
  tcase_add_test(testcase, error_explain_symlink_test);
  tcase_add_test(testcase, error_explain_truncate_test);
  tcase_add_test(testcase, error_explain_unlink_test);
  tcase_add_test(testcase, error_explain_utimes_test);
  tcase_add_test(testcase, error_explain_write_test);
  tcase_add_test(testcase, error_explain_writev_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
