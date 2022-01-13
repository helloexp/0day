/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2017 The ProFTPD Project team
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

/* Jot API tests. */

#include "tests.h"
#include "logfmt.h"
#include "json.h"
#include "jot.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("jot", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("jot", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

/* Tests */

static void assert_jot_class_filter(const char *class_name) {
  pr_jot_filters_t *filters;
  const char *rules;

  rules = class_name;

  mark_point();
  filters = pr_jot_filters_create(p, rules, PR_JOT_FILTER_TYPE_CLASSES, 0);
  fail_unless(filters != NULL, "Failed to create filters from '%s': %s",
    rules, strerror(errno));
  (void) pr_jot_filters_destroy(filters);

  rules = pstrcat(p, "!", class_name, NULL);

  mark_point();
  filters = pr_jot_filters_create(p, rules, PR_JOT_FILTER_TYPE_CLASSES, 0);
  fail_unless(filters != NULL, "Failed to create filters from '%s': %s",
    rules, strerror(errno));
  (void) pr_jot_filters_destroy(filters);
}

START_TEST (jot_filters_create_test) {
  pr_jot_filters_t *filters;
  const char *rules;

  mark_point();
  filters = pr_jot_filters_create(NULL, NULL, 0, 0);
  fail_unless(filters == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  filters = pr_jot_filters_create(p, NULL, 0, 0);
  fail_unless(filters == NULL, "Failed to handle null rules");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  rules = "foo";

  mark_point();
  filters = pr_jot_filters_create(p, rules, -1, 0);
  fail_unless(filters == NULL, "Failed to handle invalid rules type");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Class rules */

  mark_point();
  filters = pr_jot_filters_create(p, rules, PR_JOT_FILTER_TYPE_CLASSES, 0);
  fail_unless(filters == NULL, "Failed to handle invalid class name '%s'",
    rules);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  assert_jot_class_filter("NONE");
  assert_jot_class_filter("ALL");
  assert_jot_class_filter("AUTH");
  assert_jot_class_filter("INFO");
  assert_jot_class_filter("DIRS");
  assert_jot_class_filter("READ");
  assert_jot_class_filter("WRITE");
  assert_jot_class_filter("SEC");
  assert_jot_class_filter("SECURE");
  assert_jot_class_filter("CONNECT");
  assert_jot_class_filter("EXIT");
  assert_jot_class_filter("DISCONNECT");
  assert_jot_class_filter("SSH");
  assert_jot_class_filter("SFTP");

  rules = "AUTH,!INFO";

  mark_point();
  filters = pr_jot_filters_create(p, rules, PR_JOT_FILTER_TYPE_CLASSES, 0);
  fail_unless(filters != NULL, "Failed to create filters from '%s': %s",
    rules, strerror(errno));
  (void) pr_jot_filters_destroy(filters);

  rules = "!INFO|AUTH";

  mark_point();
  filters = pr_jot_filters_create(p, rules, PR_JOT_FILTER_TYPE_CLASSES, 0);
  fail_unless(filters != NULL, "Failed to create filters from '%s': %s",
    rules, strerror(errno));
  (void) pr_jot_filters_destroy(filters);

  /* Command rules */

  rules = "FOO,BAR";
  mark_point();
  filters = pr_jot_filters_create(p, rules, PR_JOT_FILTER_TYPE_COMMANDS, 0);
  fail_unless(filters != NULL, "Failed to create filters from '%s': %s",
    rules, strerror(errno));
  (void) pr_jot_filters_destroy(filters);

  rules = "APPE,RETR,STOR,STOU";
  mark_point();
  filters = pr_jot_filters_create(p, rules, PR_JOT_FILTER_TYPE_COMMANDS, 0);
  fail_unless(filters != NULL, "Failed to create filters from '%s': %s",
    rules, strerror(errno));
  (void) pr_jot_filters_destroy(filters);

  /* Rules with commands and classes */

  rules = "CONNECT,RETR,STOR,DISCONNECT";
  mark_point();
  filters = pr_jot_filters_create(p, rules,
    PR_JOT_FILTER_TYPE_COMMANDS_WITH_CLASSES, 0);
  fail_unless(filters != NULL, "Failed to create filters from '%s': %s",
    rules, strerror(errno));
  (void) pr_jot_filters_destroy(filters);

  rules = "ALL";
  mark_point();
  filters = pr_jot_filters_create(p, rules,
    PR_JOT_FILTER_TYPE_COMMANDS_WITH_CLASSES, 0);
  fail_unless(filters != NULL, "Failed to create filters from '%s': %s",
    rules, strerror(errno));
  (void) pr_jot_filters_destroy(filters);

  /* Flags */

  rules = "ALL";
  mark_point();
  filters = pr_jot_filters_create(p, rules,
    PR_JOT_FILTER_TYPE_COMMANDS_WITH_CLASSES, PR_JOT_FILTER_FL_ALL_INCL_ALL);
  fail_unless(filters != NULL, "Failed to create filters from '%s': %s",
    rules, strerror(errno));
  (void) pr_jot_filters_destroy(filters);
}
END_TEST

START_TEST (jot_filters_destroy_test) {
  int res;
  pr_jot_filters_t *filters;

  mark_point();
  res = pr_jot_filters_destroy(NULL);
  fail_unless(res < 0, "Failed to handle null filters");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  filters = pr_jot_filters_create(p, "NONE", PR_JOT_FILTER_TYPE_CLASSES, 0);

  mark_point();
  res = pr_jot_filters_destroy(filters);
  fail_unless(res == 0, "Failed to destroy filters: %s", strerror(errno));
}
END_TEST

START_TEST (jot_filters_include_classes_test) {
  int res;
  pr_jot_filters_t *filters;

  mark_point();
  res = pr_jot_filters_include_classes(NULL, 0);
  fail_unless(res < 0, "Failed to handle null filters");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  filters = pr_jot_filters_create(p, "NONE", PR_JOT_FILTER_TYPE_CLASSES, 0);

  res = pr_jot_filters_include_classes(filters, CL_ALL);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);

  res = pr_jot_filters_include_classes(filters, CL_NONE);
  fail_unless(res == TRUE, "Expected TRUE, got %d", res);

  res = pr_jot_filters_destroy(filters);
  fail_unless(res == 0, "Failed to destroy filters: %s", strerror(errno));
}
END_TEST

static unsigned int parse_on_meta_count = 0;
static unsigned int parse_on_unknown_count = 0;
static unsigned int parse_on_other_count = 0;

static int parse_on_meta(pool *jot_pool, pr_jot_ctx_t *jot_ctx,
    unsigned char logfmt_id, const char *text, size_t text_len) {
  parse_on_meta_count++;
  return 0;
}

static int parse_on_unknown(pool *jot_pool, pr_jot_ctx_t *jot_ctx,
    const char *text, size_t text_len) {
  parse_on_unknown_count++;
  return 0;
}

static int parse_on_other(pool *jot_pool, pr_jot_ctx_t *jot_ctx, char ch) {
  parse_on_other_count++;
  return 0;
}

START_TEST (jot_parse_on_meta_test) {
  int res;
  pr_jot_ctx_t *jot_ctx;
  pr_jot_parsed_t *jot_parsed;

  mark_point();
  res = pr_jot_parse_on_meta(p, NULL, 0, NULL, 0);
  fail_unless(res < 0, "Failed to handle null jot_ctx");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  jot_ctx = pcalloc(p, sizeof(pr_jot_ctx_t));

  mark_point();
  res = pr_jot_parse_on_meta(p, jot_ctx, 0, NULL, 0);
  fail_unless(res < 0, "Failed to handle null jot_ctx->log");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  jot_parsed = pcalloc(p, sizeof(pr_jot_parsed_t));
  jot_ctx->log = jot_parsed;

  mark_point();
  res = pr_jot_parse_on_meta(p, jot_ctx, 0, NULL, 0);
  fail_unless(res == 0, "Failed to handle parse_on_meta callback: %s",
    strerror(errno));
}
END_TEST

START_TEST (jot_parse_on_unknown_test) {
  int res;
  pr_jot_ctx_t *jot_ctx;
  pr_jot_parsed_t *jot_parsed;

  mark_point();
  res = pr_jot_parse_on_unknown(p, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null jot_ctx");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  jot_ctx = pcalloc(p, sizeof(pr_jot_ctx_t));

  mark_point();
  res = pr_jot_parse_on_unknown(p, jot_ctx, NULL, 0);
  fail_unless(res < 0, "Failed to handle null jot_ctx->log");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  jot_parsed = pcalloc(p, sizeof(pr_jot_parsed_t));
  jot_ctx->log = jot_parsed;

  mark_point();
  res = pr_jot_parse_on_unknown(p, jot_ctx, NULL, 0);
  fail_unless(res == 0, "Failed to handle parse_on_unknown callback: %s",
    strerror(errno));
}
END_TEST

START_TEST (jot_parse_on_other_test) {
  int res;
  pr_jot_ctx_t *jot_ctx;
  pr_jot_parsed_t *jot_parsed;

  mark_point();
  res = pr_jot_parse_on_other(p, NULL, 0);
  fail_unless(res < 0, "Failed to handle null jot_ctx");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  jot_ctx = pcalloc(p, sizeof(pr_jot_ctx_t));

  mark_point();
  res = pr_jot_parse_on_other(p, jot_ctx, 0);
  fail_unless(res < 0, "Failed to handle null jot_ctx->log");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  jot_parsed = pcalloc(p, sizeof(pr_jot_parsed_t));
  jot_ctx->log = jot_parsed;

  mark_point();
  res = pr_jot_parse_on_other(p, jot_ctx, 0);
  fail_unless(res == 0, "Failed to handle parse_on_other callback: %s",
    strerror(errno));
}
END_TEST

START_TEST (jot_parse_logfmt_test) {
  int res;
  const char *text;
  size_t text_len;
  pr_jot_ctx_t *jot_ctx;

  mark_point();
  res = pr_jot_parse_logfmt(NULL, NULL, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_jot_parse_logfmt(p, NULL, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null text");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text = "Hello, World!";

  mark_point();
  res = pr_jot_parse_logfmt(p, text, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null ctx");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  jot_ctx = pcalloc(p, sizeof(pr_jot_ctx_t));

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null on_meta");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, parse_on_meta, NULL, NULL, 0);
  fail_unless(res == 0, "Failed to parse text '%s': %s", text, strerror(errno));
  fail_unless(parse_on_meta_count == 0,
    "Expected on_meta count 0, got %u", parse_on_meta_count);
  fail_unless(parse_on_unknown_count == 0,
    "Expected on_unknown count 0, got %u", parse_on_unknown_count);
  fail_unless(parse_on_other_count == 0,
    "Expected on_other count 0, got %u", parse_on_other_count);

  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;
  text_len = strlen(text);

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, parse_on_meta, NULL,
    parse_on_other, 0);
  fail_unless(res == 0, "Failed to parse text '%s': %s", text, strerror(errno));
  fail_unless(parse_on_meta_count == 0,
    "Expected on_meta count 0, got %u", parse_on_meta_count);
  fail_unless(parse_on_unknown_count == 0,
    "Expected on_unknown count 0, got %u", parse_on_unknown_count);
  fail_unless((unsigned long) parse_on_other_count == text_len,
    "Expected on_other count %lu, got %u", (unsigned long) text_len,
    parse_on_other_count);

  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;
  text = "%A %b %{epoch} %{unknown key here}, boo!";
  text_len = strlen(text);

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, parse_on_meta, parse_on_unknown,
    parse_on_other, 0);
  fail_unless(res == 0, "Failed to parse text '%s': %s", text, strerror(errno));
  fail_unless(parse_on_meta_count == 3,
    "Expected on_meta count 0, got %u", parse_on_meta_count);
  fail_unless(parse_on_unknown_count == 1,
    "Expected on_unknown count 0, got %u", parse_on_unknown_count);
  fail_unless(parse_on_other_count == 9,
    "Expected on_other count 9, got %u", parse_on_other_count);

  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;
  text = "%A %b %{epoch} %{unknown key here}, %{not closed";
  text_len = strlen(text);

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, parse_on_meta, parse_on_unknown,
    parse_on_other, 0);
  fail_unless(res == 0, "Failed to parse text '%s': %s", text, strerror(errno));
  fail_unless(parse_on_meta_count == 3,
    "Expected on_meta count 0, got %u", parse_on_meta_count);
  fail_unless(parse_on_unknown_count == 1,
    "Expected on_unknown count 0, got %u", parse_on_unknown_count);
  fail_unless(parse_on_other_count == 17,
    "Expected on_other count 17, got %u", parse_on_other_count);
}
END_TEST

START_TEST (jot_parse_logfmt_short_vars_test) {
  register unsigned int i;
  int res;
  unsigned int text_count = 0;
  pr_jot_ctx_t *jot_ctx;
  const char *text;
  const char *texts[] = {
    "%A",
    "%D",
    "%E",
    "%F",
    "%H",
    "%I",
    "%J",
    "%L",
    "%O",
    "%R",
    "%S",
    "%T",
    "%U",
    "%V",
    "%a",
    "%b",
    "%c",
    "%d",
    "%f",
    "%g",
    "%h",
    "%l",
    "%m",
    "%p",
    "%r",
    "%s",
    "%u",
    "%v",
    "%w",
    NULL
  };

  jot_ctx = pcalloc(p, sizeof(pr_jot_ctx_t));
  text = "%X";
  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;

  /* Here we expect an other count of 2, for the '%' and the 'X'.  This is
   * not a recognized/supported short variable, and definitely not a long
   * variable, and thus the entire text is treated as "other", for each
   * character.
   */

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, parse_on_meta, NULL,
    parse_on_other, 0);
  fail_unless(res == 0, "Failed to parse text '%s': %s", text, strerror(errno));
  fail_unless(parse_on_meta_count == 0, "Expected on_meta count 0, got %u",
    parse_on_meta_count);
  fail_unless(parse_on_other_count == 2, "Expected on_other count 2, got %u",
    parse_on_other_count);

  text = "%{0}";
  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, parse_on_meta, parse_on_unknown,
    parse_on_other, 0);
  fail_unless(res == 0, "Failed to parse text '%s': %s", text, strerror(errno));
  fail_unless(parse_on_meta_count == 0,
    "Expected on_meta count 0, got %u", parse_on_meta_count);
  fail_unless(parse_on_unknown_count == 1,
    "Expected on_unknown count 1, got %u", parse_on_unknown_count);
  fail_unless(parse_on_other_count == 0,
    "Expected on_other count 0, got %u", parse_on_other_count);

  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;
  text_count = 0;

  for (i = 0; texts[i]; i++) {
    text = (const char *) texts[i];
    text_count++;

    mark_point();
    res = pr_jot_parse_logfmt(p, text, jot_ctx, parse_on_meta, parse_on_unknown,
      parse_on_other, 0);
    fail_unless(res == 0, "Failed to parse text '%s': %s", text,
      strerror(errno));
  }

  fail_unless(parse_on_meta_count == text_count,
    "Expected on_meta count %d, got %u", text_count, parse_on_meta_count);
  fail_unless(parse_on_unknown_count == 0,
    "Expected on_unknown count 0, got %u", parse_on_unknown_count);
  fail_unless(parse_on_other_count == 0,
    "Expected on_other count 0, got %u", parse_on_other_count);
}
END_TEST

static int long_on_meta(pool *jot_pool, pr_jot_ctx_t *jot_ctx,
    unsigned char logfmt_id, const char *text, size_t text_len) {
  if (strncmp(text, "FOOBAR", text_len) == 0) {
    parse_on_meta_count++;
  }

  return 0;
}

START_TEST (jot_parse_logfmt_long_vars_test) {
  register unsigned int i;
  int res;
  unsigned int text_count = 0;
  pr_jot_ctx_t *jot_ctx;
  const char *text;
  const char *texts[] = {
    "%{basename}",
    "%{epoch}",
    "%{file-modified}",
    "%{file-offset}",
    "%{file-size}",
    "%{gid}",
    "%{iso8601}",
    "%{microsecs}",
    "%{millisecs}",
    "%{protocol}",
    "%{remote-port}",
    "%{transfer-failure}",
    "%{transfer-millisecs}",
    "%{transfer-status}",
    "%{transfer-type}",
    "%{uid}",
    "%{version}",
    NULL
  };

  jot_ctx = pcalloc(p, sizeof(pr_jot_ctx_t));
  text = "%{env:FOOBAR}!";
  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, long_on_meta, NULL,
    parse_on_other, 0);
  fail_unless(res == 0, "Failed to parse text '%s': %s", text, strerror(errno));
  fail_unless(parse_on_meta_count == 1, "Expected on_meta count 1, got %u",
    parse_on_meta_count);
  fail_unless(parse_on_other_count == 1, "Expected on_other count 1, got %u",
    parse_on_other_count);

  text = "%{note:FOOBAR}!";
  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, long_on_meta, NULL,
    parse_on_other, 0);
  fail_unless(res == 0, "Failed to parse text '%s': %s", text, strerror(errno));
  fail_unless(parse_on_meta_count == 1, "Expected on_meta count 1, got %u",
    parse_on_meta_count);
  fail_unless(parse_on_other_count == 1, "Expected on_other count 1, got %u",
    parse_on_other_count);

  text = "%{time:FOOBAR}!";
  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, long_on_meta, NULL,
    parse_on_other, 0);
  fail_unless(res == 0, "Failed to parse text '%s': %s", text, strerror(errno));
  fail_unless(parse_on_meta_count == 1, "Expected on_meta count 1, got %u",
    parse_on_meta_count);
  fail_unless(parse_on_other_count == 1, "Expected on_other count 1, got %u",
    parse_on_other_count);

  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;
  text_count = 0;

  for (i = 0; texts[i]; i++) {
    text = (const char *) texts[i];
    text_count++;

    mark_point();
    res = pr_jot_parse_logfmt(p, text, jot_ctx, parse_on_meta, NULL,
      parse_on_other, 0);
    fail_unless(res == 0, "Failed to parse text '%s': %s", text,
      strerror(errno));
  }

  fail_unless(parse_on_meta_count == text_count,
    "Expected on_meta count %d, got %u", text_count, parse_on_meta_count);
  fail_unless(parse_on_other_count == 0, "Expected on_other count 0, got %u",
    parse_on_other_count);

  text = "%{FOOBAR}e";
  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, long_on_meta, NULL,
    parse_on_other, 0);
  fail_unless(res == 0, "Failed to parse text '%s': %s", text, strerror(errno));
  fail_unless(parse_on_meta_count == 1, "Expected on_meta count 1, got %u",
    parse_on_meta_count);
  fail_unless(parse_on_other_count == 0, "Expected on_other count 0, got %u",
    parse_on_other_count);

  text = "%{FOOBAR}t";
  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, long_on_meta, NULL,
    parse_on_other, 0);
  fail_unless(res == 0, "Failed to parse text '%s': %s", text, strerror(errno));
  fail_unless(parse_on_meta_count == 1, "Expected on_meta count 1, got %u",
    parse_on_meta_count);
  fail_unless(parse_on_other_count == 0, "Expected on_other count 0, got %u",
    parse_on_other_count);

  text = "%{FOOBAR}T";
  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;

  /* Here we should see 1 unknown for "%{FOOBAR}", and 1 other for the
   * trailing "T".
   */

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, long_on_meta, parse_on_unknown,
    parse_on_other, 0);
  fail_unless(res == 0, "Failed to parse text '%s': %s", text, strerror(errno));
  fail_unless(parse_on_meta_count == 0,
    "Expected on_meta count 0, got %u", parse_on_meta_count);
  fail_unless(parse_on_unknown_count == 1,
    "Expected on_unknown count 1, got %u", parse_on_unknown_count);
  fail_unless(parse_on_other_count == 1,
    "Expected on_other count 1, got %u", parse_on_other_count);
}
END_TEST

START_TEST (jot_parse_logfmt_custom_vars_test) {
  int res;
  pr_jot_ctx_t *jot_ctx;
  const char *text;

  jot_ctx = pcalloc(p, sizeof(pr_jot_ctx_t));
  text = "%{0}";
  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, parse_on_meta, parse_on_unknown,
    parse_on_other, 0);
  fail_unless(res == 0, "Failed to parse text '%s': %s", text, strerror(errno));
  fail_unless(parse_on_meta_count == 0,
    "Expected on_meta count 0, got %u", parse_on_meta_count);
  fail_unless(parse_on_unknown_count == 1,
    "Expected on_unknown count 1, got %u", parse_on_unknown_count);
  fail_unless(parse_on_other_count == 0,
    "Expected on_other count 0, got %u", parse_on_other_count);

  parse_on_meta_count = parse_on_unknown_count = parse_on_other_count = 0;

  mark_point();
  res = pr_jot_parse_logfmt(p, text, jot_ctx, parse_on_meta, parse_on_unknown,
    parse_on_other, PR_JOT_LOGFMT_PARSE_FL_UNKNOWN_AS_CUSTOM);
  fail_unless(res == 0, "Failed to parse text '%s': %s", text, strerror(errno));
  fail_unless(parse_on_meta_count == 1,
    "Expected on_meta count 1, got %u", parse_on_meta_count);
  fail_unless(parse_on_unknown_count == 0,
    "Expected on_unknown count 0, got %u", parse_on_unknown_count);
  fail_unless(parse_on_other_count == 0,
    "Expected on_other count 0, got %u", parse_on_other_count);
}
END_TEST

static unsigned int resolve_on_meta_count = 0;
static unsigned int resolve_on_default_count = 0;
static unsigned int resolve_on_other_count = 0;

static int resolve_id_on_meta(pool *jot_pool, pr_jot_ctx_t *jot_ctx,
    unsigned char logfmt_id, const char *jot_hint, const void *jot_val) {
  resolve_on_meta_count++;
  return 0;
}

static int resolve_id_on_default(pool *jot_pool, pr_jot_ctx_t *jot_ctx,
    unsigned char logfmt_id) {
  resolve_on_default_count++;
  return 0;
}

START_TEST (jot_resolve_logfmt_id_test) {
  int res;
  cmd_rec *cmd;
  unsigned char logfmt_id;

  mark_point();
  res = pr_jot_resolve_logfmt_id(NULL, NULL, NULL, 0, NULL, 0, NULL, NULL,
    NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, NULL, NULL, 0, NULL, 0, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null cmd");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, NULL, 0, NULL, 0, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null on_meta");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  logfmt_id = 0;

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, NULL, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res < 0, "Failed to handle invalid logfmt_id %u", logfmt_id);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  logfmt_id = LOGFMT_META_START;

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, NULL, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res < 0, "Failed to handle invalid logfmt_id %u", logfmt_id);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  logfmt_id = LOGFMT_META_ARG_END;

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, NULL, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res < 0, "Failed to handle invalid logfmt_id %u", logfmt_id);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (jot_resolve_logfmt_id_on_default_test) {
  int res;
  cmd_rec *cmd;
  unsigned char logfmt_id;

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));
  logfmt_id = LOGFMT_META_BASENAME;
  resolve_on_meta_count = resolve_on_default_count = 0;

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, NULL, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, resolve_id_on_default);
  fail_unless(res == 0, "Failed to handle logfmt_id %u: %s", logfmt_id,
    strerror(errno));
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 1,
    "Expected on_default count 1, got %u", resolve_on_default_count);
}
END_TEST

START_TEST (jot_resolve_logfmt_id_filters_test) {
  int res;
  cmd_rec *cmd;
  pr_jot_filters_t *jot_filters;
  unsigned char logfmt_id;

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));
  cmd->cmd_class = CL_CONNECT;
  logfmt_id = LOGFMT_META_CONNECT;

  /* No filters; should be implicitly jottable. */
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = NULL;

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, jot_filters, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res == 0, "Failed to handle logfmt_id %u: %s", logfmt_id,
    strerror(errno));
  fail_unless(resolve_on_meta_count == 1,
    "Expected on_meta count 1, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);

  /* With an ALL filter, and no command class. */
  cmd->cmd_class = 0;
  logfmt_id = LOGFMT_META_COMMAND;
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = pr_jot_filters_create(p, "ALL",
    PR_JOT_FILTER_TYPE_CLASSES, PR_JOT_FILTER_FL_ALL_INCL_ALL);

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, jot_filters, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res == 0, "Failed to handle logfmt_id %u: %s", logfmt_id,
    strerror(errno));
  fail_unless(resolve_on_meta_count == 1,
    "Expected on_meta count 1, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);

  /* With explicit filters that allow the class. */
  cmd->cmd_class = CL_CONNECT;
  logfmt_id = LOGFMT_META_CONNECT;
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = pr_jot_filters_create(p, "CONNECT",
    PR_JOT_FILTER_TYPE_CLASSES, 0);

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, jot_filters, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res == 0, "Failed to handle logfmt_id %u: %s", logfmt_id,
    strerror(errno));
  fail_unless(resolve_on_meta_count == 1,
    "Expected on_meta count 1, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);

  /* With explicit filters that ignore the class. */
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = pr_jot_filters_create(p, "!CONNECT",
    PR_JOT_FILTER_TYPE_CLASSES, 0);

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, jot_filters, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res < 0, "Failed to handle filtered logfmt_id %u", logfmt_id);
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);

  /* With explicit filters that do not match the class. */
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = pr_jot_filters_create(p, "DISCONNECT",
    PR_JOT_FILTER_TYPE_CLASSES, 0);

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, jot_filters, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res < 0, "Failed to handle filtered logfmt_id %u", logfmt_id);
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);

  /* With explicit filters that allow the command. Note that this REQUIRES
   * that we use a known command, since allowed command comparisons are done
   * by ID.
   */
  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "RANG"));
  cmd->cmd_class = CL_CONNECT;
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = pr_jot_filters_create(p, "RANG",
    PR_JOT_FILTER_TYPE_COMMANDS, 0);

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, jot_filters, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res == 0, "Failed to handle logfmt_id %u: %s", logfmt_id,
    strerror(errno));
  fail_unless(resolve_on_meta_count == 1,
    "Expected on_meta count 1, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);

  /* With explicit filters that ignore the command. */
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = pr_jot_filters_create(p, "!RANG",
    PR_JOT_FILTER_TYPE_COMMANDS, 0);

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, jot_filters, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res < 0, "Failed to handle filtered logfmt_id %u", logfmt_id);
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);

  /* With explicit filters that do not match the command. */
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = pr_jot_filters_create(p, "FOO",
    PR_JOT_FILTER_TYPE_COMMANDS, 0);

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, jot_filters, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res < 0, "Failed to handle filtered logfmt_id %u", logfmt_id);
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);
}
END_TEST

START_TEST (jot_resolve_logfmt_id_connect_test) {
  int res;
  cmd_rec *cmd;
  unsigned char logfmt_id;

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));
  cmd->cmd_class = CL_CONNECT;
  logfmt_id = LOGFMT_META_CONNECT;

  resolve_on_meta_count = resolve_on_default_count = 0;

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, NULL, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res == 0, "Failed to handle logfmt_id %u: %s", logfmt_id,
    strerror(errno));
  fail_unless(resolve_on_meta_count == 1,
    "Expected on_meta count 1, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);

  resolve_on_meta_count = resolve_on_default_count = 0;
  cmd->cmd_class = CL_DISCONNECT;

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, NULL, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res == 0, "Failed to handle logfmt_id %u: %s", logfmt_id,
    strerror(errno));
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);
}
END_TEST

START_TEST (jot_resolve_logfmt_id_disconnect_test) {
  int res;
  cmd_rec *cmd;
  unsigned char logfmt_id;

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));
  cmd->cmd_class = CL_DISCONNECT;
  logfmt_id = LOGFMT_META_DISCONNECT;

  resolve_on_meta_count = resolve_on_default_count = 0;

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, NULL, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res == 0, "Failed to handle logfmt_id %u: %s", logfmt_id,
    strerror(errno));
  fail_unless(resolve_on_meta_count == 1,
    "Expected on_meta count 1, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);

  resolve_on_meta_count = resolve_on_default_count = 0;
  cmd->cmd_class = CL_CONNECT;

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, NULL, logfmt_id, NULL, 0, NULL,
    resolve_id_on_meta, NULL);
  fail_unless(res == 0, "Failed to handle logfmt_id %u: %s", logfmt_id,
    strerror(errno));
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);
}
END_TEST

START_TEST (jot_resolve_logfmt_id_custom_test) {
  int res;
  cmd_rec *cmd;
  unsigned char logfmt_id;
  const char *custom_data;
  size_t custom_datalen;

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));
  cmd->cmd_class = CL_MISC;
  logfmt_id = LOGFMT_META_CUSTOM;

  resolve_on_meta_count = resolve_on_default_count = 0;
  custom_data = "%{0}";
  custom_datalen = strlen(custom_data);

  mark_point();
  res = pr_jot_resolve_logfmt_id(p, cmd, NULL, logfmt_id, custom_data,
    custom_datalen, NULL, resolve_id_on_meta, NULL);
  fail_unless(res == 0, "Failed to handle logfmt_id %u: %s", logfmt_id,
    strerror(errno));
  fail_unless(resolve_on_meta_count == 1,
    "Expected on_meta count 1, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);
}
END_TEST

START_TEST (jot_resolve_logfmt_ids_test) {
  register unsigned char i;
  int res;
  cmd_rec *cmd;
  unsigned char logfmt_id;

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));
  resolve_on_meta_count = resolve_on_default_count = 0;

  /* Currently, the max known LogFormat meta/ID is 53 (DISCONNECT). */
  for (i = 1; i < 54; i++) {
    logfmt_id = i;

    mark_point();
    res = pr_jot_resolve_logfmt_id(p, cmd, NULL, logfmt_id, NULL, 0, NULL,
      resolve_id_on_meta, resolve_id_on_default);
    fail_unless(res == 0, "Failed to handle logfmt_id %u: %s", logfmt_id,
      strerror(errno));
  }

  fail_unless(resolve_on_meta_count == 20,
    "Expected on_meta count 20, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 28,
    "Expected on_default count 28, got %u", resolve_on_default_count);
}
END_TEST

static int resolve_on_meta(pool *jot_pool, pr_jot_ctx_t *jot_ctx,
    unsigned char logfmt_id, const char *jot_hint, const void *val) {
  resolve_on_meta_count++;
  return 0;
}

static int resolve_on_default(pool *jot_pool, pr_jot_ctx_t *jot_ctx,
    unsigned char logfmt_id) {
  resolve_on_default_count++;
  return 0;
}

static int resolve_on_other(pool *jot_pool, pr_jot_ctx_t *jot_ctx,
    unsigned char *text, size_t text_len) {
  resolve_on_other_count++;
  return 0;
}

START_TEST (jot_resolve_logfmt_test) {
  int res;
  cmd_rec *cmd;
  unsigned char *logfmt;

  mark_point();
  res = pr_jot_resolve_logfmt(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_jot_resolve_logfmt(p, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null cmd");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null logfmt");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  logfmt = (unsigned char *) "";

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, NULL, logfmt, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null on_meta");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, NULL, logfmt, NULL, resolve_on_meta,
    NULL, NULL);
  fail_unless(res == 0, "Failed to handle empty logfmt: %s", strerror(errno));
}
END_TEST

START_TEST (jot_resolve_logfmt_filters_test) {
  int res;
  cmd_rec *cmd;
  pr_jot_filters_t *jot_filters;
  unsigned char logfmt[3];

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));
  cmd->cmd_class = CL_CONNECT;

  /* No filters; should be implicitly jottable. */
  resolve_on_meta_count = resolve_on_default_count = resolve_on_other_count = 0;
  jot_filters = NULL;
  logfmt[0] = LOGFMT_META_START;
  logfmt[1] = LOGFMT_META_CONNECT;
  logfmt[2] = 0;

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, jot_filters, logfmt, NULL,
    resolve_on_meta, NULL, NULL);
  fail_unless(res == 0, "Failed to handle logfmt: %s", strerror(errno));
  fail_unless(resolve_on_meta_count == 1,
    "Expected on_meta count 1, got %u", resolve_on_meta_count);

  /* With an ALL filter, and no command class. */
  cmd->cmd_class = 0;
  logfmt[1] = LOGFMT_META_COMMAND;
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = pr_jot_filters_create(p, "ALL",
    PR_JOT_FILTER_TYPE_CLASSES, PR_JOT_FILTER_FL_ALL_INCL_ALL);

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, jot_filters, logfmt, NULL,
    resolve_on_meta, NULL, NULL);
  fail_unless(res == 0, "Failed to handle logfmt: %s", strerror(errno));
  fail_unless(resolve_on_meta_count == 1,
    "Expected on_meta count 1, got %u", resolve_on_meta_count);

  /* With explicit filters that allow the class. */
  cmd->cmd_class = CL_CONNECT;
  logfmt[1] = LOGFMT_META_CONNECT;
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = pr_jot_filters_create(p, "CONNECT",
    PR_JOT_FILTER_TYPE_CLASSES, 0);

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, jot_filters, logfmt, NULL,
    resolve_on_meta, NULL, NULL);
  fail_unless(res == 0, "Failed to handle logfmt: %s", strerror(errno));
  fail_unless(resolve_on_meta_count == 1,
    "Expected on_meta count 1, got %u", resolve_on_meta_count);

  /* With explicit filters that ignore the class. */
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = pr_jot_filters_create(p, "!CONNECT",
    PR_JOT_FILTER_TYPE_CLASSES, 0);

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, jot_filters, logfmt, NULL,
    resolve_on_meta, NULL, NULL);
  fail_unless(res < 0, "Failed to handle filtered logfmt");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);

  /* With explicit filters that do not match the class. */
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = pr_jot_filters_create(p, "DISCONNECT",
    PR_JOT_FILTER_TYPE_CLASSES, 0);

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, jot_filters, logfmt, NULL,
    resolve_on_meta, NULL, NULL);
  fail_unless(res < 0, "Failed to handle filtered logfmt");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);

  /* With explicit filters that allow the command. Note that this REQUIRES
   * that we use a known command, since allowed command comparisons are done
   * by ID.
   */
  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "RANG"));
  cmd->cmd_class = CL_CONNECT;
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = pr_jot_filters_create(p, "RANG",
    PR_JOT_FILTER_TYPE_COMMANDS, 0);

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, jot_filters, logfmt, NULL,
    resolve_on_meta, NULL, NULL);
  fail_unless(res == 0, "Failed to handle logfmt: %s", strerror(errno));
  fail_unless(resolve_on_meta_count == 1,
    "Expected on_meta count 1, got %u", resolve_on_meta_count);

  /* With explicit filters that ignore the command. */
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = pr_jot_filters_create(p, "!RANG",
    PR_JOT_FILTER_TYPE_COMMANDS, 0);

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, jot_filters, logfmt, NULL,
    resolve_on_meta, NULL, NULL);
  fail_unless(res < 0, "Failed to handle filtered logfmt");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);

  /* With explicit filters that do not match the command. */
  resolve_on_meta_count = resolve_on_default_count = 0;
  jot_filters = pr_jot_filters_create(p, "FOO",
    PR_JOT_FILTER_TYPE_COMMANDS, 0);

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, jot_filters, logfmt, NULL,
    resolve_on_meta, NULL, NULL);
  fail_unless(res < 0, "Failed to handle filtered logfmt");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);
}
END_TEST

START_TEST (jot_resolve_logfmt_on_default_test) {
  int res;
  cmd_rec *cmd;
  unsigned char logfmt[3];

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));
  logfmt[0] = LOGFMT_META_START;
  logfmt[1] = LOGFMT_META_BASENAME;
  logfmt[2] = 0;
  resolve_on_meta_count = resolve_on_default_count = resolve_on_other_count = 0;

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, NULL, logfmt, NULL,
    resolve_on_meta, resolve_on_default, NULL);
  fail_unless(res == 0, "Failed to handle logfmt: %s", strerror(errno));
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 1,
    "Expected on_default count 1, got %u", resolve_on_default_count);
}
END_TEST

START_TEST (jot_resolve_logfmt_on_other_test) {
  int res;
  cmd_rec *cmd;
  unsigned char logfmt[3];

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));
  logfmt[0] = 'A';
  logfmt[1] = '!';
  logfmt[2] = 0;
  resolve_on_meta_count = resolve_on_default_count = resolve_on_other_count = 0;

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, NULL, logfmt, NULL,
    resolve_on_meta, resolve_on_default, resolve_on_other);
  fail_unless(res == 0, "Failed to handle logfmt: %s", strerror(errno));
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);
  fail_unless(resolve_on_other_count == 1,
    "Expected on_other count 1, got %u", resolve_on_other_count);
}
END_TEST

START_TEST (jot_resolve_logfmt_connect_test) {
  int res;
  cmd_rec *cmd;
  unsigned char logfmt[3];

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));
  cmd->cmd_class = CL_CONNECT;
  logfmt[0] = LOGFMT_META_START;
  logfmt[1] = LOGFMT_META_CONNECT;
  logfmt[2] = 0;

  resolve_on_meta_count = resolve_on_default_count = resolve_on_other_count = 0;

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, NULL, logfmt, NULL,
    resolve_on_meta, resolve_on_default, resolve_on_other);
  fail_unless(res == 0, "Failed to handle logfmt: %s", strerror(errno));
  fail_unless(resolve_on_meta_count == 1,
    "Expected on_meta count 1, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);
  fail_unless(resolve_on_other_count == 0,
    "Expected on_other count 0, got %u", resolve_on_other_count);

  resolve_on_meta_count = resolve_on_default_count = resolve_on_other_count = 0;
  cmd->cmd_class = CL_DISCONNECT;

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, NULL, logfmt, NULL,
    resolve_on_meta, resolve_on_default, resolve_on_other);
  fail_unless(res == 0, "Failed to handle logfmt: %s", strerror(errno));
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);
  fail_unless(resolve_on_other_count == 0,
    "Expected on_other count 0, got %u", resolve_on_other_count);
}
END_TEST

START_TEST (jot_resolve_logfmt_disconnect_test) {
  int res;
  cmd_rec *cmd;
  unsigned char logfmt[3];

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));
  cmd->cmd_class = CL_DISCONNECT;
  logfmt[0] = LOGFMT_META_START;
  logfmt[1] = LOGFMT_META_DISCONNECT;
  logfmt[2] = 0;

  resolve_on_meta_count = resolve_on_default_count = resolve_on_other_count = 0;

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, NULL, logfmt, NULL,
    resolve_on_meta, resolve_on_default, resolve_on_other);
  fail_unless(res == 0, "Failed to handle logfmt: %s", strerror(errno));
  fail_unless(resolve_on_meta_count == 1,
    "Expected on_meta count 1, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);
  fail_unless(resolve_on_other_count == 0,
    "Expected on_other count 0, got %u", resolve_on_other_count);

  resolve_on_meta_count = resolve_on_default_count = resolve_on_other_count = 0;
  cmd->cmd_class = CL_CONNECT;

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, NULL, logfmt, NULL,
    resolve_on_meta, resolve_on_default, resolve_on_other);
  fail_unless(res == 0, "Failed to handle logfmt: %s", strerror(errno));
  fail_unless(resolve_on_meta_count == 0,
    "Expected on_meta count 0, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);
  fail_unless(resolve_on_other_count == 0,
    "Expected on_other count 0, got %u", resolve_on_other_count);
}
END_TEST

START_TEST (jot_resolve_logfmt_custom_test) {
  int res;
  cmd_rec *cmd;
  unsigned char logfmt[10];

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));
  cmd->cmd_class = CL_MISC;
  logfmt[0] = LOGFMT_META_START;
  logfmt[1] = LOGFMT_META_CUSTOM;
  logfmt[2] = LOGFMT_META_START;
  logfmt[3] = LOGFMT_META_ARG;
  logfmt[4] = '%';
  logfmt[5] = '{';
  logfmt[6] = '0';
  logfmt[7] = '}';
  logfmt[8] = LOGFMT_META_ARG_END;
  logfmt[9] = 0;

  resolve_on_meta_count = resolve_on_default_count = resolve_on_other_count = 0;

  mark_point();
  res = pr_jot_resolve_logfmt(p, cmd, NULL, logfmt, NULL,
    resolve_on_meta, resolve_on_default, resolve_on_other);
  fail_unless(res == 0, "Failed to handle logfmt: %s", strerror(errno));
  fail_unless(resolve_on_meta_count == 1,
    "Expected on_meta count 1, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 0,
    "Expected on_default count 0, got %u", resolve_on_default_count);
  fail_unless(resolve_on_other_count == 0,
    "Expected on_other count 0, got %u", resolve_on_other_count);
}
END_TEST

START_TEST (jot_resolve_logfmts_test) {
  register unsigned char i;
  int res;
  cmd_rec *cmd;
  unsigned char logfmt[3];

  cmd = pr_cmd_alloc(p, 1, pstrdup(p, "FOO"));
  logfmt[0] = LOGFMT_META_START;
  logfmt[2] = 0;
  resolve_on_meta_count = resolve_on_default_count = resolve_on_other_count = 0;

  /* Currently, the max known LogFormat meta/ID is 53 (DISCONNECT). */
  for (i = 1; i < 54; i++) {
    logfmt[1] = i;

    mark_point();
    res = pr_jot_resolve_logfmt(p, cmd, NULL, logfmt, NULL,
      resolve_on_meta, resolve_on_default, resolve_on_other);
    fail_unless(res == 0, "Failed to handle logfmt_id %u: %s", logfmt[1],
      strerror(errno));
  }

  fail_unless(resolve_on_meta_count == 20,
    "Expected on_meta count 20, got %u", resolve_on_meta_count);
  fail_unless(resolve_on_default_count == 28,
    "Expected on_default count 28, got %u", resolve_on_default_count);
  fail_unless(resolve_on_other_count == 0,
    "Expected on_other count 0, got %u", resolve_on_other_count);
}
END_TEST

static unsigned int scan_on_meta_count = 0;

static int scan_on_meta(pool *jot_pool, pr_jot_ctx_t *jot_ctx,
    unsigned char logfmt_id, const char *logfmt_data, size_t logfmt_datalen) {
  scan_on_meta_count++;
  return 0;
}

START_TEST (jot_scan_logfmt_test) {
  int res;
  unsigned char logfmt[12];

  mark_point();
  res = pr_jot_scan_logfmt(NULL, NULL, 0, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_jot_scan_logfmt(p, NULL, 0, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null logfmt");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  logfmt[0] = LOGFMT_META_START;
  logfmt[1] = LOGFMT_META_CUSTOM;
  logfmt[2] = LOGFMT_META_START;
  logfmt[3] = LOGFMT_META_ARG;
  logfmt[4] = '%';
  logfmt[5] = '{';
  logfmt[6] = 'f';
  logfmt[7] = 'o';
  logfmt[8] = 'o';
  logfmt[9] = '}';
  logfmt[10] = LOGFMT_META_ARG_END;
  logfmt[11] = 0;

  mark_point();
  res = pr_jot_scan_logfmt(p, logfmt, 0, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null on_meta");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_jot_scan_logfmt(p, logfmt, 0, NULL, scan_on_meta, 0);
  fail_unless(res < 0, "Failed to handle invalid LogFormat ID");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  scan_on_meta_count = 0;

  mark_point();
  res = pr_jot_scan_logfmt(p, logfmt, LOGFMT_META_ENV_VAR, NULL, scan_on_meta,
    0);
  fail_unless(res == 0, "Failed to scan logmt for ENV_VAR: %s",
    strerror(errno));
  fail_unless(scan_on_meta_count == 0, "Expected scan_on_meta 0, got %u",
    scan_on_meta_count);

  scan_on_meta_count = 0;

  mark_point();
  res = pr_jot_scan_logfmt(p, logfmt, LOGFMT_META_CUSTOM, NULL, scan_on_meta,
    0);
  fail_unless(res == 0, "Failed to scan logmt for CUSTOM: %s",
    strerror(errno));
  fail_unless(scan_on_meta_count == 1, "Expected scan_on_meta 1, got %u",
    scan_on_meta_count);
}
END_TEST

START_TEST (jot_on_json_test) {
  pr_jot_ctx_t *ctx;
  pr_json_object_t *json;
  double num;
  int res, truth;
  const char *text;

  mark_point();
  res = pr_jot_on_json(NULL, NULL, 0, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_jot_on_json(p, NULL, 0, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null ctx");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  ctx = pcalloc(p, sizeof(pr_jot_ctx_t));

  mark_point();
  res = pr_jot_on_json(p, ctx, 0, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null val");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_jot_on_json(p, ctx, 0, NULL, &num);
  fail_unless(res < 0, "Failed to handle null ctx->log");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  json = pr_json_object_alloc(p);
  ctx->log = json;

  mark_point();
  res = pr_jot_on_json(p, ctx, 0, NULL, &num);
  fail_unless(res < 0, "Failed to handle null ctx->user_data");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  ctx->user_data = pr_table_alloc(p, 0);

  mark_point();
  res = pr_jot_on_json(p, ctx, 0, NULL, &num);
  fail_unless(res < 0, "Failed to handle null JSON info");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  ctx->user_data = pr_jot_get_logfmt2json(p);

  mark_point();
  truth = FALSE;
  res = pr_jot_on_json(p, ctx, LOGFMT_META_CONNECT, NULL, &truth);
  fail_unless(res == 0, "Failed to handle LOGFMT_META_CONNECT: %s",
    strerror(errno));

  mark_point();
  num = 2476;
  res = pr_jot_on_json(p, ctx, LOGFMT_META_PID, NULL, &num);
  fail_unless(res == 0, "Failed to handle LOGFMT_META_PID: %s",
    strerror(errno));

  mark_point();
  text = "lorem ipsum";
  res = pr_jot_on_json(p, ctx, LOGFMT_META_IDENT_USER, NULL, text);
  fail_unless(res == 0, "Failed to handle LOGFMT_META_IDENT_USER: %s",
    strerror(errno));

  mark_point();
  text = "alef bet vet";
  res = pr_jot_on_json(p, ctx, LOGFMT_META_USER, "USER_KEY", text);
  fail_unless(res == 0, "Failed to handle LOGFMT_META_USER: %s",
    strerror(errno));

  (void) pr_json_object_free(json);
}
END_TEST

START_TEST (jot_get_logfmt2json_test) {
  pr_table_t *res;

  mark_point();
  res = pr_jot_get_logfmt2json(NULL);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_jot_get_logfmt2json(p);
  fail_unless(res != NULL, "Failed to get map: %s", strerror(errno));
}
END_TEST

START_TEST (jot_get_logfmt_id_name_test) {
  register unsigned char i;
  const char *res;

  mark_point();
  res = pr_jot_get_logfmt_id_name(0);
  fail_unless(res == NULL, "Failed to handle invalid logfmt_id");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Currently, the max known LogFormat meta/ID is 53 (DISCONNECT). */
  for (i = 2; i < 54; i++) {
    mark_point();
    res = pr_jot_get_logfmt_id_name(i);
    fail_unless(res != NULL, "Failed to get name for LogFormat ID %u: %s",
      i, strerror(errno)); 
  }

  res = pr_jot_get_logfmt_id_name(LOGFMT_META_CUSTOM);
  fail_unless(res != NULL, "Failed to get name for LogFormat ID %u: %s",
    LOGFMT_META_CUSTOM, strerror(errno)); 
}
END_TEST

Suite *tests_get_jot_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("jot");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, jot_filters_create_test);
  tcase_add_test(testcase, jot_filters_destroy_test);
  tcase_add_test(testcase, jot_filters_include_classes_test);

  tcase_add_test(testcase, jot_parse_on_meta_test);
  tcase_add_test(testcase, jot_parse_on_unknown_test);
  tcase_add_test(testcase, jot_parse_on_other_test);
  tcase_add_test(testcase, jot_parse_logfmt_test);
  tcase_add_test(testcase, jot_parse_logfmt_short_vars_test);
  tcase_add_test(testcase, jot_parse_logfmt_long_vars_test);
  tcase_add_test(testcase, jot_parse_logfmt_custom_vars_test);

  tcase_add_test(testcase, jot_resolve_logfmt_id_test);
  tcase_add_test(testcase, jot_resolve_logfmt_id_on_default_test);
  tcase_add_test(testcase, jot_resolve_logfmt_id_filters_test);
  tcase_add_test(testcase, jot_resolve_logfmt_id_connect_test);
  tcase_add_test(testcase, jot_resolve_logfmt_id_disconnect_test);
  tcase_add_test(testcase, jot_resolve_logfmt_id_custom_test);
  tcase_add_test(testcase, jot_resolve_logfmt_ids_test);

  tcase_add_test(testcase, jot_resolve_logfmt_test);
  tcase_add_test(testcase, jot_resolve_logfmt_filters_test);
  tcase_add_test(testcase, jot_resolve_logfmt_on_default_test);
  tcase_add_test(testcase, jot_resolve_logfmt_on_other_test);
  tcase_add_test(testcase, jot_resolve_logfmt_connect_test);
  tcase_add_test(testcase, jot_resolve_logfmt_disconnect_test);
  tcase_add_test(testcase, jot_resolve_logfmt_custom_test);
  tcase_add_test(testcase, jot_resolve_logfmts_test);

  tcase_add_test(testcase, jot_scan_logfmt_test);
  tcase_add_test(testcase, jot_on_json_test);
  tcase_add_test(testcase, jot_get_logfmt2json_test);
  tcase_add_test(testcase, jot_get_logfmt_id_name_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
