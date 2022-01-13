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

/* String API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
  }
}

START_TEST (sstrncpy_test) {
  char *ok, *dst;
  size_t len, sz = 32;
  int res;

  len = 0;
  res = sstrncpy(NULL, NULL, len);
  fail_unless(res == -1, "Failed to handle null arguments");

  dst = "";
  res = sstrncpy(dst, "foo", 0);
  fail_unless(res == 0, "Failed to handle zero length");

  dst = pcalloc(p, sz);
  memset(dst, 'A', sz);

  len = 1;
  res = sstrncpy(dst, NULL, len);
  fail_unless(res == -1, "Failed to handle null arguments");

  ok = "Therefore, all progress depends on the unreasonable man";

  mark_point();
  res = sstrncpy(ok, ok, 1);
  fail_unless(res == 1, "Expected result 1, got %d", len, res);

  mark_point();
  memset(dst, 'A', sz);
  len = 1;

  res = sstrncpy(dst, ok, len);
  fail_unless((size_t) res <= len, "Expected result %d, got %d", len, res);
  fail_unless(strlen(dst) == (len - 1), "Expected len %u, got len %u", len - 1,
    strlen(dst));
  fail_unless(dst[len-1] == '\0', "Expected NUL, got '%c'", dst[len-1]);

  memset(dst, 'A', sz);
  len = 7;

  res = sstrncpy(dst, ok, len);
  fail_unless((size_t) res <= len, "Expected result %d, got %d", len, res);
  fail_unless(strlen(dst) == (len - 1), "Expected len %u, got len %u", len - 1,
    strlen(dst));
  fail_unless(dst[len-1] == '\0', "Expected NUL, got '%c'", dst[len-1]);

  memset(dst, 'A', sz);
  len = sz;

  res = sstrncpy(dst, ok, len);
  fail_unless((size_t) res <= len, "Expected result %d, got %d", len, res);
  fail_unless(strlen(dst) == (len - 1), "Expected len %u, got len %u", len - 1,
    strlen(dst));
  fail_unless(dst[len-1] == '\0', "Expected NUL, got '%c'", dst[len-1]);

  memset(dst, 'A', sz);
  len = sz;

  res = sstrncpy(dst, "", len);
  fail_unless((size_t) res <= len, "Expected result %d, got %d", len, res);
  fail_unless(strlen(dst) == 0, "Expected len %u, got len %u", 0, strlen(dst));
  fail_unless(*dst == '\0', "Expected NUL, got '%c'", *dst);
}
END_TEST

START_TEST (sstrcat_test) {
  register unsigned int i;
  char c = 'A', src[1024], dst[1024], *res;

  res = sstrcat(dst, src, 0);
  fail_unless(res == NULL, "Non-null result for zero-length strcat");

  src[0] = 'f';
  src[1] = '\0';
  dst[0] = 'e';
  dst[1] = '\0';
  res = sstrcat(dst, src, 1);
  fail_unless(res == dst, "Returned wrong destination buffer");

  /* In this case, we told sstrcat() that dst is len 1, which means that
   * sstrcat() should set dst[0] to NUL.
   */
  fail_unless(dst[0] == 0, "Failed to terminate destination buffer");

  src[0] = 'f';
  src[1] = '\0';
  dst[0] = 'e';
  dst[1] = '\0';
  res = sstrcat(dst, src, 2);
  fail_unless(res == dst, "Returned wrong destination buffer");

  /* In this case, we told sstrcat() that dst is len 2, which means that
   * sstrcat() should preserve the value at 0, and set dst[1] to NUL.
   */
  fail_unless(dst[0] == 'e',
    "Failed to preserve destination buffer (expected '%c' at index 0, "
    "got '%c')", 'e', dst[0]);

  fail_unless(dst[1] == 0, "Failed to terminate destination buffer");

  mark_point();
  src[0] = 'f';
  src[1] = '\0';
  dst[0] = 'e';
  dst[1] = '\0';
  res = sstrcat(dst, src, 3);
  fail_unless(res == dst, "Returned wrong destination buffer");

  mark_point();
  fail_unless(dst[0] == 'e',
    "Failed to preserve destination buffer (expected '%c' at index 0, "
    "got '%c')", 'e', dst[0]);

  mark_point();
  fail_unless(dst[1] == 'f',
    "Failed to copy source buffer (expected '%c' at index 1, got '%c')",
    'f', dst[1]);

  mark_point();
  fail_unless(dst[2] == 0, "Failed to terminate destination buffer");

  mark_point();
  memset(src, c, sizeof(src)-1);

  /* Note: we need to NUL-terminate the source buffer, for e.g. strlcat(3)
   * implementations.  Failure to do so can yield SIGABRT/SIGSEGV problems
   * during e.g. unit tests.
   */
  src[sizeof(src)-1] = '\0';
  dst[0] = '\0';

  mark_point();
  res = sstrcat(dst, src, sizeof(dst));

  mark_point();
  fail_unless(res == dst, "Returned wrong destination buffer");

  mark_point();
  fail_unless(dst[sizeof(dst)-1] == 0,
    "Failed to terminate destination buffer");

  mark_point();
  fail_unless(strlen(dst) == (sizeof(dst)-1),
    "Failed to copy all the data (expected len %u, got len %u)",
    sizeof(dst)-1, strlen(dst));

  mark_point();
  for (i = 0; i < sizeof(dst)-1; i++) {
    fail_unless(dst[i] == c, "Copied wrong value (expected '%c', got '%c')",
      c, dst[i]);
  }
}
END_TEST

START_TEST (sreplace_test) {
  const char *res;
  char *fmt = NULL, *ok;

  res = sreplace(NULL, NULL, 0);
  fail_unless(res == NULL, "Failed to handle invalid arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = sreplace(NULL, "", 0);
  fail_unless(res == NULL, "Failed to handle invalid arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = sreplace(p, NULL, 0);
  fail_unless(res == NULL, "Failed to handle invalid arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  fmt = "%a";
  res = sreplace(p, fmt, "foo", NULL);
  fail_unless(strcmp(res, fmt) == 0, "Expected '%s', got '%s'", fmt, res);

  fmt = "foo %a";
  res = sreplace(p, fmt, "%b", NULL);
  fail_unless(strcmp(res, fmt) == 0, "Expected '%s', got '%s'", fmt, res);

  fmt = "foo %a";
  ok = "foo bar";
  res = sreplace(p, fmt, "%a", "bar", NULL);
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  fmt = "foo %a %a";
  ok = "foo bar bar";
  res = sreplace(p, fmt, "%a", "bar", NULL);
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  fmt = "foo %a %a %a %a %a %a %a %a";
  ok = "foo bar bar bar bar bar bar bar bar";
  res = sreplace(p, fmt, "%a", "bar", NULL);
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  /* sreplace() will not handle more than 8 occurrences of the same escape
   * sequence in the same line.  Make sure this happens.
   */
  fmt = "foo %a %a %a %a %a %a %a %a %a";
  ok = "foo bar bar bar bar bar bar bar bar bar";
  res = sreplace(p, fmt, "%a", "bar", NULL);
  fail_unless(strcmp(res, fmt) == 0, "Expected '%s', got '%s'", fmt, res);
}
END_TEST

START_TEST (sreplace_enospc_test) {
  const char *res;
  char *fmt = NULL;
  size_t bufsz = 8192;

  fmt = palloc(p, bufsz + 1);
  memset(fmt, ' ', bufsz);
  fmt[bufsz-2] = '%';
  fmt[bufsz-1] = 'a';
  fmt[bufsz] = '\0';

  res = sreplace(p, fmt, "%a", "foo", NULL);
  fail_unless(res == NULL, "Failed to reject too-long buffer");
  fail_unless(errno == ENOSPC, "Failed to set errno to ENOSPC");
}
END_TEST

START_TEST (sreplace_bug3614_test) {
  const char *res;
  char *fmt = NULL, *ok;

  fmt = "%a %b %c %d %e %f %g %h %i %j %k %l %m "
        "%n %o %p %q %r %s %t %u %v %w %x %y %z "
        "%A %B %C %D %E %F %G %H %I %J %K %L %M "
        "%N %O %P %Q %R %S %T %U %V %W %X %Y %Z "
        "%0 %1 %2 %3 %4 %5 %6 %7 %8 %9 "
        "%{a} %{b} %{c} %{d} %{e} %{f} %{g} %{h} %{i} %{j} %{k} %{l} %{m} "
        "%{n} %{o} %{p} %{q} %{r} %{s} %{t} %{u} %{v} %{w} %{x} %{y} %{z} "
        "%{A} %{B} %{C} %{D} %{E} %{F} %{G} %{H} %{I} %{J} %{K} %{L} %{M} "
        "%{N} %{O} %{P} %{Q} %{R} %{S} %{T} %{U} %{V} %{W} %{X} %{Y} %{Z} "
        "%{aa} %{bb} %{cc} %{dd} %{ee} %{ff} %{gg} %{hh} %{ii} %{jj} "
        "%{kk} %{ll} %{mm} %{nn} %{oo} %{pp} %{qq} %{rr} %{ss} %{tt} "
        "%{uu} %{vv} %{ww} %{xx} %{yy} %{zz}";

  /* We put a limit on the maximum number of replacements that sreplace()
   * will perform on a given string, per Bug#3614.
   */
  ok = "bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar bar %{oo} %{pp} %{qq} %{rr} %{ss} %{tt} %{uu} %{vv} %{ww} %{xx} %{yy} %{zz}";

  res = sreplace(p, fmt,
    "%a", "bar", "%b", "bar", "%c", "bar", "%d", "bar", "%e", "bar",
    "%f", "bar", "%g", "bar", "%h", "bar", "%i", "bar", "%j", "bar",
    "%k", "bar", "%l", "bar", "%m", "bar", "%n", "bar", "%o", "bar",
    "%p", "bar", "%q", "bar", "%r", "bar", "%s", "bar", "%t", "bar",
    "%u", "bar", "%v", "bar", "%w", "bar", "%x", "bar", "%y", "bar",
    "%z", "bar",
    "%A", "bar", "%B", "bar", "%C", "bar", "%D", "bar", "%E", "bar",
    "%F", "bar", "%G", "bar", "%H", "bar", "%I", "bar", "%J", "bar",
    "%K", "bar", "%L", "bar", "%M", "bar", "%N", "bar", "%O", "bar",
    "%P", "bar", "%Q", "bar", "%R", "bar", "%S", "bar", "%T", "bar",
    "%U", "bar", "%V", "bar", "%W", "bar", "%X", "bar", "%Y", "bar",
    "%Z", "bar",
    "%0", "bar", "%1", "bar", "%2", "bar", "%3", "bar", "%4", "bar",
    "%5", "bar", "%6", "bar", "%7", "bar", "%8", "bar", "%9", "bar",
    "%{a}", "bar", "%{b}", "bar", "%{c}", "bar", "%{d}", "bar", "%{e}", "bar",
    "%{f}", "bar", "%{g}", "bar", "%{h}", "bar", "%{i}", "bar", "%{j}", "bar",
    "%{k}", "bar", "%{l}", "bar", "%{m}", "bar", "%{n}", "bar", "%{o}", "bar",
    "%{p}", "bar", "%{q}", "bar", "%{r}", "bar", "%{s}", "bar", "%{t}", "bar",
    "%{u}", "bar", "%{v}", "bar", "%{w}", "bar", "%{x}", "bar", "%{y}", "bar",
    "%{z}", "bar",
    "%{A}", "bar", "%{B}", "bar", "%{C}", "bar", "%{D}", "bar", "%{E}", "bar",
    "%{F}", "bar", "%{G}", "bar", "%{H}", "bar", "%{I}", "bar", "%{J}", "bar",
    "%{K}", "bar", "%{L}", "bar", "%{M}", "bar", "%{N}", "bar", "%{O}", "bar",
    "%{P}", "bar", "%{Q}", "bar", "%{R}", "bar", "%{S}", "bar", "%{T}", "bar",
    "%{U}", "bar", "%{V}", "bar", "%{W}", "bar", "%{X}", "bar", "%{Y}", "bar",
    "%{Z}", "bar",
    "%{aa}", "bar", "%{bb}", "bar", "%{cc}", "bar", "%{dd}", "bar",
    "%{ee}", "bar", "%{ff}", "bar", "%{gg}", "bar", "%{hh}", "bar",
    "%{ii}", "bar", "%{jj}", "bar", "%{kk}", "bar", "%{ll}", "bar",
    "%{mm}", "bar", "%{nn}", "bar", "%{oo}", "bar", "%{pp}", "bar",
    "%{qq}", "bar", "%{rr}", "bar", "%{ss}", "bar", "%{tt}", "bar",
    "%{uu}", "bar", "%{vv}", "bar", "%{ww}", "bar", "%{xx}", "bar",
    "%{yy}", "bar", "%{zz}", "bar",
    NULL);
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);
}
END_TEST

START_TEST (str_replace_test) {
  const char *res;
  char *fmt = NULL, *ok;
  int max_replace = PR_STR_MAX_REPLACEMENTS;

  res = pr_str_replace(NULL, max_replace, NULL, 0);
  fail_unless(res == NULL, "Failed to handle invalid arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_str_replace(NULL, max_replace, "", 0);
  fail_unless(res == NULL, "Failed to handle invalid arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_str_replace(p, max_replace, NULL, 0);
  fail_unless(res == NULL, "Failed to handle invalid arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  fmt = "%a";
  res = pr_str_replace(p, max_replace, fmt, "foo", NULL);
  fail_unless(strcmp(res, fmt) == 0, "Expected '%s', got '%s'", fmt, res);

  fmt = "foo %a";
  res = pr_str_replace(p, max_replace, fmt, "%b", NULL);
  fail_unless(strcmp(res, fmt) == 0, "Expected '%s', got '%s'", fmt, res);

  fmt = "foo %a";
  ok = "foo bar";
  res = pr_str_replace(p, max_replace, fmt, "%a", "bar", NULL);
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  fmt = "foo %a %a";
  ok = "foo bar bar";
  res = pr_str_replace(p, max_replace, fmt, "%a", "bar", NULL);
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  fmt = "foo %a %a %a %a %a %a %a %a";
  ok = "foo bar bar bar bar bar bar bar bar";
  res = pr_str_replace(p, max_replace, fmt, "%a", "bar", NULL);
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  fmt = "foo %a %a %a %a %a %a %a %a %a";
  ok = "foo bar bar bar bar bar bar bar bar bar";
  res = pr_str_replace(p, max_replace, fmt, "%a", "bar", NULL);
  fail_unless(res == NULL, "Failed to handle too many replacements");
  fail_unless(errno == E2BIG, "Failed to set errno to E2BIG");
}
END_TEST

START_TEST (pdircat_test) {
  char *res, *ok;

  res = pdircat(NULL, 0);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pdircat(p, 0);
  fail_unless(res != NULL,
    "Failed to handle empty arguments (expected '', got '%s')", res);
  fail_unless(strcmp(res, "") == 0, "Expected '%s', got '%s'", "", res);

  /* Comments in the pdircat() function suggest that an empty string
   * should be treated as a leading slash.  However, that never got
   * implemented.  Is this a bug, or just an artifact?  I doubt that it
   * is causing problems at present.
   */
  res = pdircat(p, "", NULL);
  ok = "";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pdircat(p, "foo", "bar", NULL);
  ok = "foo/bar";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pdircat(p, "", "foo", "bar", NULL);
  ok = "foo/bar";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pdircat(p, "/", "/foo/", "/bar/", NULL);
  ok = "/foo/bar/";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  /* Sadly, pdircat() only handles single leading/trailing slashes, not
   * an arbitrary number of leading/trailing slashes.
   */
  res = pdircat(p, "//", "//foo//", "//bar//", NULL);
  ok = "///foo///bar//";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);
}
END_TEST

START_TEST (pstrcat_test) {
  char *res, *ok;

  res = pstrcat(NULL, 0);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pstrcat(p, 0);
  fail_unless(res != NULL,
    "Failed to handle empty arguments (expected '', got '%s')", res);
  fail_unless(strcmp(res, "") == 0, "Expected '%s', got '%s'", "", res);

  res = pstrcat(p, "", NULL);
  ok = "";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pstrcat(p, "foo", "bar", NULL);
  ok = "foobar";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pstrcat(p, "", "foo", "bar", NULL);
  ok = "foobar";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pstrcat(p, "/", "/foo/", "/bar/", NULL);
  ok = "//foo//bar/";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pdircat(p, "//", "//foo//", NULL, "//bar//", NULL);
  ok = "///foo//";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);
}
END_TEST

START_TEST (pstrdup_test) {
  char *res, *ok;

  res = pstrdup(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pstrdup(p, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pstrdup(NULL, "");
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pstrdup(p, "foo");
  ok = "foo";
  fail_unless(strlen(res) == strlen(ok), "Expected len %u, got len %u",
    strlen(ok), strlen(res));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);
}
END_TEST

START_TEST (pstrndup_test) {
  char *res, *ok;

  res = pstrndup(NULL, NULL, 0);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pstrndup(p, NULL, 0);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pstrndup(NULL, "", 0);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pstrndup(p, "foo", 0);
  ok = "";
  fail_unless(strlen(res) == strlen(ok), "Expected len %u, got len %u",
    strlen(ok), strlen(res));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pstrndup(p, "foo", 1);
  ok = "f";
  fail_unless(strlen(res) == strlen(ok), "Expected len %u, got len %u",
    strlen(ok), strlen(res));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pstrndup(p, "foo", 10);
  ok = "foo";
  fail_unless(strlen(res) == strlen(ok), "Expected len %u, got len %u",
    strlen(ok), strlen(res));
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);
}
END_TEST

START_TEST (strip_test) {
  const char *ok, *res, *str;

  res = pr_str_strip(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_str_strip(p, NULL);
  fail_unless(res == NULL, "Failed to handle null str argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_str_strip(NULL, "foo");
  fail_unless(res == NULL, "Failed to handle null pool argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = pstrdup(p, "foo");
  res = pr_str_strip(p, str);
  fail_unless(res != NULL, "Failed to strip '%s': %s", str, strerror(errno));

  ok = "foo";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  str = pstrdup(p, " \n \t foo");
  res = pr_str_strip(p, str);
  fail_unless(res != NULL, "Failed to strip '%s': %s", str, strerror(errno));

  ok = "foo";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  str = pstrdup(p, "foo  \n \t \r");
  res = pr_str_strip(p, str);
  fail_unless(res != NULL, "Failed to strip '%s': %s", str, strerror(errno));

  ok = "foo";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  str = pstrdup(p, "\r \n\n\t    foo  \n \t \r");
  res = pr_str_strip(p, str);
  fail_unless(res != NULL, "Failed to strip '%s': %s", str, strerror(errno));

  ok = "foo";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);
}
END_TEST

START_TEST (strip_end_test) {
  char *ch, *ok, *res, *str;

  res = pr_str_strip_end(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = pstrdup(p, "foo");

  res = pr_str_strip_end(str, NULL);
  fail_unless(res == NULL, "Failed to handle null char argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  ch = "\r\n";

  res = pr_str_strip_end(NULL, ch);
  fail_unless(res == NULL, "Failed to handle null str argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_str_strip_end(str, ch);
  fail_unless(res != NULL, "Failed to strip '%s' from end of '%s': %s",
    ch, str, strerror(errno));

  ok = "foo";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  str = pstrdup(p, "foo\r\n");
  res = pr_str_strip_end(str, ch);
  fail_unless(res != NULL, "Failed to strip '%s' from end of '%s': %s",
    ch, str, strerror(errno));

  ok = "foo";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  str = pstrdup(p, "foo\r\n\r\n\r\n");
  res = pr_str_strip_end(str, ch);
  fail_unless(res != NULL, "Failed to strip '%s' from end of '%s': %s",
    ch, str, strerror(errno));

  ok = "foo";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);
}
END_TEST

START_TEST (get_token_test) {
  char *ok, *res, *str;

  res = pr_str_get_token(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = NULL;
  res = pr_str_get_token(&str, NULL);
  fail_unless(res == NULL, "Failed to handle null str argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = pstrdup(p, "foo,bar,baz");
  res = pr_str_get_token(&str, NULL);
  fail_unless(res == NULL, "Failed to handle null sep argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_str_get_token(&str, ",");
  fail_unless(res != NULL, "Failed to get token from '%s': %s", str,
    strerror(errno));

  ok = "foo";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pr_str_get_token(&str, ",");
  fail_unless(res != NULL, "Failed to get token from '%s': %s", str,
    strerror(errno));

  ok = "bar";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pr_str_get_token(&str, ",");
  fail_unless(res != NULL, "Failed to get token from '%s': %s", str,
    strerror(errno));

  ok = "baz";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pr_str_get_token(&str, ",");
  fail_unless(res == NULL, "Unexpectedly got token '%s'", res);
}
END_TEST

START_TEST (get_token2_test) {
  char *ok, *res, *str;
  size_t len = 0, ok_len;

  res = pr_str_get_token2(NULL, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = NULL;
  res = pr_str_get_token2(&str, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null str argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = pstrdup(p, "foo,bar,bazz");
  res = pr_str_get_token2(&str, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null sep argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_str_get_token2(&str, ",", &len);
  fail_unless(res != NULL, "Failed to get token from '%s': %s", str,
    strerror(errno));

  ok = "foo";
  ok_len = 3;
  fail_unless(len == ok_len, "Expected len %lu, got %lu",
    (unsigned long) ok_len, (unsigned long) len);
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pr_str_get_token2(&str, ",", &len);
  fail_unless(res != NULL, "Failed to get token from '%s': %s", str,
    strerror(errno));

  ok = "bar";
  ok_len = 3; 
  fail_unless(len == ok_len, "Expected len %lu, got %lu",
    (unsigned long) ok_len, (unsigned long) len);
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pr_str_get_token2(&str, ",", &len);
  fail_unless(res != NULL, "Failed to get token from '%s': %s", str,
    strerror(errno));

  ok = "bazz";
  ok_len = 4; 
  fail_unless(len == ok_len, "Expected len %lu, got %lu",
    (unsigned long) ok_len, (unsigned long) len);
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pr_str_get_token2(&str, ",", &len);

  ok_len = 0;
  fail_unless(len == ok_len, "Expected len %lu, got %lu",
    (unsigned long) ok_len, (unsigned long) len);
  fail_unless(res == NULL, "Unexpectedly got token '%s'", res);
}
END_TEST

START_TEST (get_word_test) {
  char *ok, *res, *str;

  res = pr_str_get_word(NULL, 0);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = NULL;
  res = pr_str_get_word(&str, 0);
  fail_unless(res == NULL, "Failed to handle null str argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = pstrdup(p, "  ");
  res = pr_str_get_word(&str, 0);
  fail_unless(res == NULL, "Failed to handle whitespace argument");

  str = pstrdup(p, " foo");
  res = pr_str_get_word(&str, PR_STR_FL_PRESERVE_WHITESPACE);
  fail_unless(res != NULL, "Failed to handle whitespace argument: %s",
    strerror(errno));

  ok = "";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pr_str_get_word(&str, PR_STR_FL_PRESERVE_WHITESPACE);
  fail_unless(res != NULL, "Failed to handle whitespace argument: %s",
    strerror(errno));

  ok = "foo";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  str = pstrdup(p, "  # foo");
  res = pr_str_get_word(&str, 0);
  fail_unless(res == NULL, "Failed to handle commented argument");

  res = pr_str_get_word(&str, PR_STR_FL_PRESERVE_COMMENTS);
  fail_unless(res != NULL, "Failed to handle commented argument: %s",
    strerror(errno));

  ok = "#";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pr_str_get_word(&str, PR_STR_FL_PRESERVE_COMMENTS);
  fail_unless(res != NULL, "Failed to handle commented argument: %s",
    strerror(errno));

  ok = "foo";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  /* Test multiple embedded quotes. */
  str = pstrdup(p, "foo \"bar baz\" qux \"quz norf\"");
  res = pr_str_get_word(&str, 0);
  fail_unless(res != NULL, "Failed to handle quoted argument: %s",
    strerror(errno));

  ok = "foo";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pr_str_get_word(&str, 0);
  fail_unless(res != NULL, "Failed to handle quoted argument: %s",
    strerror(errno));

  ok = "bar baz";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pr_str_get_word(&str, 0);
  fail_unless(res != NULL, "Failed to handle quoted argument: %s",
    strerror(errno));

  ok = "qux";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);

  res = pr_str_get_word(&str, 0);
  fail_unless(res != NULL, "Failed to handle quoted argument: %s",
    strerror(errno));

  ok = "quz norf";
  fail_unless(strcmp(res, ok) == 0, "Expected '%s', got '%s'", ok, res);
}
END_TEST

START_TEST (get_word_utf8_test) {
  const char *path;
  FILE *fh;

  /* Test UT8 spaces. Note that in order to do this, I had to use
   * some other tool (Perl) to emit the desired UTF8 characters to
   * a file; we then read in the bytes to parse from that file.  Some
   * compilers (e.g. gcc), in conjunction with the terminal/editor I'm
   * using, don't like using the '\uNNNN' syntax for encoding UTF8 in C
   * source code.
   */

  path = "api/etc/str/utf8-space.txt";
  fh = fopen(path, "r"); 
  if (fh != NULL) {
    char *ok, *res, *str;
    size_t nread = 0, sz;

    sz = 256;
    str = pcalloc(p, sz);

    nread = fread(str, sizeof(char), sz-1, fh);
    fail_if(ferror(fh), "Error reading '%s': %s", path, strerror(errno));
    fail_unless(nread > 0, "Expected >0 bytes read, got 0");

    res = pr_str_get_word(&str, 0);
      fail_unless(res != NULL, "Failed to handle UTF8 argument: %s",
      strerror(errno));

    ok = "foo";
    fail_if(strcmp(res, ok) == 0, "Did NOT expect '%s'", ok);

    fclose(fh);
  }
}
END_TEST

START_TEST (is_boolean_test) {
  int res;

  res = pr_str_is_boolean(NULL);
  fail_unless(res == -1, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL (got %d)",
    errno);

  res = pr_str_is_boolean("on");
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_str_is_boolean("Yes");
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_str_is_boolean("TrUe");
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_str_is_boolean("1");
  fail_unless(res == TRUE, "Expected TRUE, got FALSE");

  res = pr_str_is_boolean("oFF");
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  res = pr_str_is_boolean("no");
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  res = pr_str_is_boolean("false");
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  res = pr_str_is_boolean("0");
  fail_unless(res == FALSE, "Expected FALSE, got TRUE");

  res = pr_str_is_boolean("foo");
  fail_unless(res == -1, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL (got %d)",
    errno);
}
END_TEST

START_TEST (is_fnmatch_test) {
  int res;
  char *str;

  res = pr_str_is_fnmatch(NULL);
  fail_unless(res == FALSE, "Expected false for NULL");

  str = "foo";
  res = pr_str_is_fnmatch(str);
  fail_if(res != FALSE, "Expected false for string '%s'", str);

  str = "foo?";
  res = pr_str_is_fnmatch(str);
  fail_if(res != TRUE, "Expected true for string '%s'", str);

  str = "foo*";
  res = pr_str_is_fnmatch(str);
  fail_if(res != TRUE, "Expected true for string '%s'", str);

  str = "foo[";
  res = pr_str_is_fnmatch(str);
  fail_if(res != FALSE, "Expected false for string '%s'", str);

  str = "foo]";
  res = pr_str_is_fnmatch(str);
  fail_if(res != FALSE, "Expected false for string '%s'", str);

  str = "foo[]";
  res = pr_str_is_fnmatch(str);
  fail_if(res != TRUE, "Expected true for string '%s'", str);

  /* Now the fun cases using the escape character. */

  str = "f\\oo";
  res = pr_str_is_fnmatch(str);
  fail_if(res != FALSE, "Expected false for string '%s'", str);

  str = "foo\\";
  res = pr_str_is_fnmatch(str);
  fail_if(res != FALSE, "Expected false for string '%s'", str);

  str = "foo\\?";
  res = pr_str_is_fnmatch(str);
  fail_if(res != FALSE, "Expected false for string '%s'", str);

  str = "foo\\??";
  res = pr_str_is_fnmatch(str);
  fail_if(res != TRUE, "Expected true for string '%s'", str);
}
END_TEST

START_TEST (get_nbytes_test) {
  char *str, *units;
  off_t nbytes;
  int res;

  res = pr_str_get_nbytes(NULL, NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = NULL;
  res = pr_str_get_nbytes(str, NULL, NULL);
  fail_unless(res == -1, "Failed to handle null str argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = "1";
  units = "f";
  res = pr_str_get_nbytes(str, units, NULL);
  fail_unless(res == -1, "Failed to handle bad suffix argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = "a";
  units = "";
  res = pr_str_get_nbytes(str, units, NULL);
  fail_unless(res == -1, "Failed to handle invalid str argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = "1 1";
  units = "";
  res = pr_str_get_nbytes(str, units, NULL);
  fail_unless(res == -1, "Failed to handle invalid str argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = "1.1";
  units = "";
  res = pr_str_get_nbytes(str, units, NULL);
  fail_unless(res == -1, "Failed to handle invalid str argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = "-1";
  units = "";
  res = pr_str_get_nbytes(str, units, NULL);
  fail_unless(res == -1, "Failed to handle invalid str argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  /* XXX Test good suffix: B, KB, MB, GB, TB */

  str = "1";
  units = "";
  res = pr_str_get_nbytes(str, units, &nbytes);
  fail_unless(res == 0, "Expected result 0, got %d: %s", res, strerror(errno));
  fail_unless(nbytes == 1, "Expected nbytes = 1, got %" PR_LU,
    (pr_off_t) nbytes);

  str = "1";
  units = "B";
  res = pr_str_get_nbytes(str, units, &nbytes);
  fail_unless(res == 0, "Expected result 0, got %d: %s", res, strerror(errno));
  fail_unless(nbytes == 1,
    "Expected nbytes = 1, got %" PR_LU, (pr_off_t) nbytes);

  str = "1";
  units = "KB";
  res = pr_str_get_nbytes(str, units, &nbytes);
  fail_unless(res == 0, "Expected result 0, got %d: %s", res, strerror(errno));
  fail_unless(nbytes == 1024UL,
    "Expected nbytes = 1024, got %" PR_LU, (pr_off_t) nbytes);

  str = "1";
  units = "MB";
  res = pr_str_get_nbytes(str, units, &nbytes);
  fail_unless(res == 0, "Expected result 0, got %d: %s", res, strerror(errno));
  fail_unless(nbytes == 1048576UL,
    "Expected nbytes = 1048576, got %" PR_LU, (pr_off_t) nbytes);

  str = "1";
  units = "GB";
  res = pr_str_get_nbytes(str, units, &nbytes);
  fail_unless(res == 0, "Expected result 0, got %d: %s", res, strerror(errno));
  fail_unless(nbytes == 1073741824UL,
    "Expected nbytes = 1073741824, got %" PR_LU, (pr_off_t) nbytes);

  str = "1";
  units = "TB";
  res = pr_str_get_nbytes(str, units, &nbytes);
  fail_unless(res == 0, "Expected result 0, got %d: %s", res, strerror(errno));
  fail_unless(nbytes == 1099511627776UL,
    "Expected nbytes = 1099511627776, got %" PR_LU, (pr_off_t) nbytes);

  /* This should definitely trigger the ERANGE error. */
  str = "1099511627776";
  units = "TB";
  res = pr_str_get_nbytes(str, units, &nbytes);
  fail_unless(res == -1, "Expected ERANGE failure, succeeded unexpectedly");
  fail_unless(errno == ERANGE, "Expected %s [%d], got %s [%d]",
    strerror(ERANGE), ERANGE, strerror(errno), errno);
}
END_TEST

START_TEST (get_duration_test) {
  char *str;
  int duration, expected;
  int res;

  res = pr_str_get_duration(NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = "";
  res = pr_str_get_duration(str, NULL);
  fail_unless(res == -1,
    "Failed to handle badly formatted string '%s'", str);
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = "-1:-1:-1";
  res = pr_str_get_duration(str, NULL);
  fail_unless(res == -1,
    "Failed to handle badly formatted string '%s'", str);
  fail_unless(errno == ERANGE, "Failed to set errno to ERANGE");

  str = "a:b:c";
  res = pr_str_get_duration(str, NULL);
  fail_unless(res == -1,
    "Failed to handle badly formatted string '%s'", str);
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = "111:222:333";
  res = pr_str_get_duration(str, NULL);
  fail_unless(res == -1,
    "Failed to handle badly formatted string '%s'", str);
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  /* Test well-formatted hh::mm::ss strings. */

  str = "00:00:00";
  expected = 0;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "01:02:03";
  expected = 3723;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "99:99:99";
  expected = 362439;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  /* Test bad suffixes: -1h, -1hr, 9999foo, etc */

  str = "-1h";
  res = pr_str_get_duration(str, NULL);
  fail_unless(res == -1,
    "Failed to handle badly formatted suffix string '%s'", str);
  fail_unless(errno == ERANGE, "Failed to set errno to ERANGE");

  str = "-1hr";
  res = pr_str_get_duration(str, NULL);
  fail_unless(res == -1,
    "Failed to handle badly formatted suffix string '%s'", str);
  fail_unless(errno == ERANGE, "Failed to set errno to ERANGE");

  str = "99foo";
  res = pr_str_get_duration(str, NULL);
  fail_unless(res == -1,
    "Failed to handle badly formatted suffix string '%s'", str);
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  str = "foo";
  res = pr_str_get_duration(str, NULL);
  fail_unless(res == -1,
    "Failed to handle badly formatted suffix string '%s'", str);
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  /* Test good suffices: "H"/"h"/"hr", "M"/"m"/"min", "S"/"s"/"sec" */

  str = "76H";
  expected = 273600;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "76h";
  expected = 273600;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "76Hr";
  expected = 273600;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "888M";
  expected = 53280;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "888m";
  expected = 53280;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "888MiN";
  expected = 53280;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "999S";
  expected = 999;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "999s";
  expected = 999;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "999sEc";
  expected = 999;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "0h";
  expected = 0;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "0M";
  expected = 0;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "0sec";
  expected = 0;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "17";
  expected = 17;
  res = pr_str_get_duration(str, &duration);
  fail_unless(res == 0,
    "Failed to parse well-formed time string '%s': %s", str, strerror(errno));
  fail_unless(duration == expected,
    "Expected duration %d secs, got %d", expected, duration);

  str = "-1";
  res = pr_str_get_duration(str, NULL);
  fail_unless(res == -1,
    "Failed to handle badly formatted suffix string '%s'", str);
  fail_unless(errno == ERANGE, "Failed to set errno to ERANGE");
}
END_TEST

START_TEST (strnrstr_test) {
  int res, flags = 0;
  const char *s = NULL, *suffix = NULL;

  res = pr_strnrstr(NULL, 0, NULL, 0, flags);
  fail_unless(res == -1, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_strnrstr(NULL, 0, "", 0, flags);
  fail_unless(res == -1, "Failed to handle null s");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  res = pr_strnrstr("", 0, NULL, 0, flags);
  fail_unless(res == -1, "Failed to handle null suffix");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL");

  s = suffix = "";
  res = pr_strnrstr(s, 0, suffix, 0, flags);
  fail_unless(res == TRUE, "Expected true, got false");

  s = "";
  suffix = "s";
  res = pr_strnrstr(s, 0, suffix, 0, flags);
  fail_unless(res == FALSE, "Expected false, got true");

  s = "food";
  suffix = "ood";
  res = pr_strnrstr(s, 0, suffix, 0, flags);
  fail_unless(res == TRUE, "Expected true, got false");

  s = "food";
  suffix = "ood";
  res = pr_strnrstr(s, 4, suffix, 3, flags);
  fail_unless(res == TRUE, "Expected true, got false");

  s = "FOOD";
  suffix = "ood";
  res = pr_strnrstr(s, 4, suffix, 3, flags);
  fail_unless(res == FALSE, "Expected false, got true");

  flags = PR_STR_FL_IGNORE_CASE;
  s = "FOOD";
  suffix = "ood";
  res = pr_strnrstr(s, 4, suffix, 3, flags);
  fail_unless(res == TRUE, "Expected true, got false");
}
END_TEST

START_TEST (bin2hex_test) {
  char *expected, *res;
  const unsigned char *str;

  res = pr_str_bin2hex(NULL, NULL, 0, 0);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_str_bin2hex(p, NULL, 0, 0);
  fail_unless(res == NULL, "Failed to handle null data argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Empty string. */
  str = (const unsigned char *) "foobar";
  expected = "";
  res = pr_str_bin2hex(p, (const unsigned char *) str, 0, 0);
  fail_unless(res != NULL, "Failed to hexify '%s': %s", str, strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

  /* default (lowercase) */
  expected = "666f6f626172";
  res = pr_str_bin2hex(p, str, strlen((char *) str), 0);
  fail_unless(res != NULL, "Failed to hexify '%s': %s", str, strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

  /* lowercase */
  expected = "666f6f626172";
  res = pr_str_bin2hex(p, str, strlen((char *) str), 0);
  fail_unless(res != NULL, "Failed to hexify '%s': %s", str, strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

  /* uppercase */
  expected = "666F6F626172";
  res = pr_str_bin2hex(p, str, strlen((char *) str), PR_STR_FL_HEX_USE_UC);
  fail_unless(res != NULL, "Failed to hexify '%s': %s", str, strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);
}
END_TEST

START_TEST (hex2bin_test) {
  unsigned char *expected, *res;
  const unsigned char *hex;
  size_t expected_len, hex_len, len;

  res = pr_str_hex2bin(NULL, NULL, 0, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_str_hex2bin(p, NULL, 0, 0);
  fail_unless(res == NULL, "Failed to handle null data argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Empty string. */
  hex = (const unsigned char *) "";
  hex_len = strlen((char *) hex);
  expected = (unsigned char *) "";
  res = pr_str_hex2bin(p, hex, hex_len, &len);
  fail_unless(res != NULL, "Failed to unhexify '%s': %s", hex, strerror(errno));
  fail_unless(strcmp((const char *) res, (const char *) expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  hex = (const unsigned char *) "112233";
  hex_len = strlen((char *) hex);
  expected_len = 3;
  expected = palloc(p, expected_len);
  expected[0] = 17;
  expected[1] = 34;
  expected[2] = 51;

  res = pr_str_hex2bin(p, (const unsigned char *) hex, hex_len, &len);
  fail_unless(res != NULL, "Failed to unhexify '%s': %s", hex, strerror(errno));
  fail_unless(len == expected_len, "Expected len %lu, got %lu",
    (unsigned long) expected_len, len);
  fail_unless(memcmp(res, expected, len) == 0,
    "Did not receive expected unhexified data");

  /* lowercase */
  hex = (const unsigned char *) "666f6f626172";
  hex_len = strlen((char *) hex);
  expected_len = 6;
  expected = palloc(p, expected_len);
  expected[0] = 'f';
  expected[1] = 'o';
  expected[2] = 'o';
  expected[3] = 'b';
  expected[4] = 'a';
  expected[5] = 'r';

  res = pr_str_hex2bin(p, (const unsigned char *) hex, hex_len, &len);
  fail_unless(res != NULL, "Failed to unhexify '%s': %s", hex, strerror(errno));
  fail_unless(len == expected_len, "Expected len %lu, got %lu",
    (unsigned long) expected_len, len);
  fail_unless(memcmp(res, expected, len) == 0,
    "Did not receive expected unhexified data");

  /* uppercase */
  hex = (const unsigned char *) "666F6F626172";
  hex_len = strlen((char *) hex);

  res = pr_str_hex2bin(p, (const unsigned char *) hex, hex_len, &len);
  fail_unless(res != NULL, "Failed to unhexify '%s': %s", hex, strerror(errno));
  fail_unless(len == expected_len, "Expected len %lu, got %lu",
    (unsigned long) expected_len, len);
  fail_unless(memcmp(res, expected, len) == 0,
    "Did not receive expected unhexified data");

  /* Handle known not-hex data properly. */
  hex = (const unsigned char *) "Hello, World!\n";
  hex_len = strlen((char *) hex);
  res = pr_str_hex2bin(p, hex, hex_len, &len);
  fail_unless(res == NULL, "Successfully unhexified '%s' unexpectedly", hex);
  fail_unless(errno == ERANGE, "Expected ERANGE (%d), got %s (%d)", ERANGE,
    strerror(errno), errno);
}
END_TEST

START_TEST (levenshtein_test) {
  int res, expected, flags = 0;
  const char *a, *b;

  mark_point();
  res = pr_str_levenshtein(NULL, NULL, NULL, 0, 0, 0, 0, flags);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_str_levenshtein(p, NULL, NULL, 0, 0, 0, 0, flags);
  fail_unless(res < 0, "Failed to handle null a string");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  a = "foo";

  mark_point();
  res = pr_str_levenshtein(p, a, NULL, 0, 0, 0, 0, flags);
  fail_unless(res < 0, "Failed to handle null b string");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  expected = 0;
  b = "Foo";

  mark_point();
  res = pr_str_levenshtein(p, a, b, 0, 0, 0, 0, flags);
  fail_if(res < 0,
    "Failed to compute Levenshtein distance from '%s' to '%s': %s", a, b,
    strerror(errno));
  fail_unless(expected == res, "Expected distance %d, got %d", expected, res);

  expected = 3;
  b = "Foo";
  res = pr_str_levenshtein(p, a, b, 0, 1, 1, 1, flags);
  fail_if(res < 0,
    "Failed to compute Levenshtein distance from '%s' to '%s': %s", a, b,
    strerror(errno));
  fail_unless(expected == res, "Expected distance %d, got %d", expected, res);

  flags = PR_STR_FL_IGNORE_CASE;
  expected = 2;
  b = "Foo";
  res = pr_str_levenshtein(p, a, b, 0, 1, 1, 1, flags);
  fail_if(res < 0,
    "Failed to compute Levenshtein distance from '%s' to '%s': %s", a, b,
    strerror(errno));
  fail_unless(expected == res, "Expected distance %d, got %d", expected, res);
}
END_TEST

START_TEST (similars_test) {
  array_header *res, *candidates;
  const char *s, **similars, *expected;

  mark_point();
  res = pr_str_get_similars(NULL, NULL, NULL, 0, 0);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_str_get_similars(p, NULL, NULL, 0, 0);
  fail_unless(res == NULL, "Failed to handle null string");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  s = "foo";

  mark_point();
  res = pr_str_get_similars(p, s, NULL, 0, 0);
  fail_unless(res == NULL, "Failed to handle null candidates");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  candidates = make_array(p, 5, sizeof(const char *));

  mark_point();
  res = pr_str_get_similars(p, s, candidates, 0, 0);
  fail_unless(res == NULL, "Failed to handle empty candidates");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  *((const char **) push_array(candidates)) = pstrdup(p, "fools");
  *((const char **) push_array(candidates)) = pstrdup(p, "odd");
  *((const char **) push_array(candidates)) = pstrdup(p, "bar");
  *((const char **) push_array(candidates)) = pstrdup(p, "FOO");

  mark_point();
  res = pr_str_get_similars(p, s, candidates, 0, 0);
  fail_unless(res != NULL, "Failed to find similar strings to '%s': %s", s,
    strerror(errno));
  fail_unless(res->nelts > 0, "Expected >0 similar strings, got %u",
    res->nelts);

  mark_point();
  similars = (const char **) res->elts;

  /*
   * Note: expected distances are as follows:
   *
   * Candidate       Case-Sensitive      Case-Insensitive
   * fools                 0                     0
   * odd                   5                     5
   * bar                   5                     5
   * FOO                   5                     0
   */

  expected = "fools";

  fail_unless(strcmp(similars[0], expected) == 0,
    "Expected similar '%s', got '%s'", expected, similars[0]);

  fail_unless(strcmp(similars[1], expected) != 0,
    "Unexpectedly got similar '%s'", similars[1]);

  mark_point();
  res = pr_str_get_similars(p, s, candidates, 0, PR_STR_FL_IGNORE_CASE);
  fail_unless(res != NULL, "Failed to find similar strings to '%s': %s", s,
    strerror(errno));
  fail_unless(res->nelts > 0, "Expected >0 similar strings, got %u",
    res->nelts);

  mark_point();
  similars = (const char **) res->elts;

  /*
   * similars[0] and similars[1] should be "FOO" and "fools", but
   * not necessarily in that order
   */
  expected = "FOO";
  if (strcmp(similars[0], expected) != 0) {
    expected = similars[0];
    similars[0] = similars[1];
    similars[1] = expected;
    expected = "FOO";
  }

  fail_unless(strcmp(similars[0], expected) == 0,
    "Expected similar '%s', got '%s'", expected, similars[0]);

  expected = "fools";

  fail_unless(strcmp(similars[1], expected) == 0,
    "Expected similar '%s', got '%s'", expected, similars[1]);
}
END_TEST

START_TEST (str2uid_test) {
  int res;

  res = pr_str2uid(NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
}
END_TEST

START_TEST (str2gid_test) {
  int res;

  res = pr_str2gid(NULL, NULL);
  fail_unless(res == -1, "Failed to handle null arguments");
}
END_TEST

START_TEST (uid2str_test) {
  const char *res;

  res = pr_uid2str(NULL, (uid_t) 1);
  fail_unless(strcmp(res, "1") == 0);

  res = pr_uid2str(NULL, (uid_t) -1);
  fail_unless(strcmp(res, "-1") == 0);
}
END_TEST

START_TEST (gid2str_test) {
  const char *res;

  res = pr_gid2str(NULL, (gid_t) 1);
  fail_unless(strcmp(res, "1") == 0);

  res = pr_gid2str(NULL, (gid_t) -1);
  fail_unless(strcmp(res, "-1") == 0);
}
END_TEST

START_TEST (str_quote_test) {
  const char *res;
  char *expected, *path;

  res = pr_str_quote(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_str_quote(p, NULL);
  fail_unless(res == NULL, "Failed to handle null path argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/tmp/";
  expected = path;
  res = pr_str_quote(p, path);
  fail_unless(res != NULL, "Failed to quote '%s': %s", path, strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  path = "/\"tmp\"/";
  expected = "/\"\"tmp\"\"/";
  res = pr_str_quote(p, path);
  fail_unless(res != NULL, "Failed to quote '%s': %s", path, strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);
}
END_TEST

START_TEST (quote_dir_test) {
  const char *res;
  char *expected, *path;

  res = quote_dir(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = quote_dir(p, NULL);
  fail_unless(res == NULL, "Failed to handle null path argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = "/tmp/";
  expected = path;
  res = quote_dir(p, path);
  fail_unless(res != NULL, "Failed to quote '%s': %s", path, strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  path = "/\"tmp\"/";
  expected = "/\"\"tmp\"\"/";
  res = quote_dir(p, path);
  fail_unless(res != NULL, "Failed to quote '%s': %s", path, strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);
}
END_TEST

START_TEST (text_to_array_test) {
  register unsigned int i;
  array_header *res;
  const char *text;

  mark_point();
  res = pr_str_text_to_array(NULL, NULL, ',');
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = pr_str_text_to_array(p, NULL, ',');
  fail_unless(res == NULL, "Failed to handle null text");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text = "";

  mark_point();
  res = pr_str_text_to_array(p, text, ',');
  fail_unless(res != NULL, "Failed to handle text '%s': %s", text,
    strerror(errno));
  fail_unless(res->nelts == 0, "Expected 0 items, got %u", res->nelts);

  text = ",";

  mark_point();
  res = pr_str_text_to_array(p, text, ',');
  fail_unless(res != NULL, "Failed to handle text '%s': %s", text,
    strerror(errno));
  fail_unless(res->nelts == 0, "Expected 0 items, got %u", res->nelts);

  text = ",,,";

  mark_point();
  res = pr_str_text_to_array(p, text, ',');
  fail_unless(res != NULL, "Failed to handle text '%s': %s", text,
    strerror(errno));
  fail_unless(res->nelts == 0, "Expected 0 items, got %u", res->nelts);

  text = "foo";

  mark_point();
  res = pr_str_text_to_array(p, text, ',');
  fail_unless(res != NULL, "Failed to handle text '%s': %s", text,
    strerror(errno));
  fail_unless(res->nelts == 1, "Expected 1 item, got %u", res->nelts);

  text = "foo,foo,foo";

  mark_point();
  res = pr_str_text_to_array(p, text, ',');
  fail_unless(res != NULL, "Failed to handle text '%s': %s", text,
    strerror(errno));
  fail_unless(res->nelts == 3, "Expected 3 items, got %u", res->nelts);
  for (i = 0; i < res->nelts; i++) {
    char *item, *expected;

    item = ((char **) res->elts)[i];
    fail_unless(item != NULL, "Expected item at index %u, got null", i);

    expected = "foo";
    fail_unless(strcmp(item, expected) == 0,
      "Expected '%s' at index %u, got '%s'", expected, i, item);
  }

  text = "foo,foo,foo,";

  mark_point();
  res = pr_str_text_to_array(p, text, ',');
  fail_unless(res != NULL, "Failed to handle text '%s': %s", text,
    strerror(errno));
  fail_unless(res->nelts == 3, "Expected 3 items, got %u", res->nelts);
  for (i = 0; i < res->nelts; i++) {
    char *item, *expected;

    item = ((char **) res->elts)[i];
    fail_unless(item != NULL, "Expected item at index %u, got null", i);

    if (i == 3) {
      expected = "";

    } else {
      expected = "foo";
    }

    fail_unless(strcmp(item, expected) == 0,
      "Expected '%s' at index %u, got '%s'", expected, i, item);
  }

  text = "foo|foo|foo";

  mark_point();
  res = pr_str_text_to_array(p, text, '|');
  fail_unless(res != NULL, "Failed to handle text '%s': %s", text,
    strerror(errno));
  fail_unless(res->nelts == 3, "Expected 3 items, got %u", res->nelts);
  for (i = 0; i < res->nelts; i++) {
    char *item, *expected;

    item = ((char **) res->elts)[i];
    fail_unless(item != NULL, "Expected item at index %u, got null", i);

    expected = "foo";
    fail_unless(strcmp(item, expected) == 0,
      "Expected '%s' at index %u, got '%s'", expected, i, item);
  }
}
END_TEST

Suite *tests_get_str_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("str");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, sstrncpy_test);
  tcase_add_test(testcase, sstrcat_test);
  tcase_add_test(testcase, sreplace_test);
  tcase_add_test(testcase, sreplace_enospc_test);
  tcase_add_test(testcase, sreplace_bug3614_test);
  tcase_add_test(testcase, str_replace_test);
  tcase_add_test(testcase, pdircat_test);
  tcase_add_test(testcase, pstrcat_test);
  tcase_add_test(testcase, pstrdup_test);
  tcase_add_test(testcase, pstrndup_test);
  tcase_add_test(testcase, strip_test);
  tcase_add_test(testcase, strip_end_test);
  tcase_add_test(testcase, get_token_test);
  tcase_add_test(testcase, get_token2_test);
  tcase_add_test(testcase, get_word_test);
  tcase_add_test(testcase, get_word_utf8_test);
  tcase_add_test(testcase, is_boolean_test);
  tcase_add_test(testcase, is_fnmatch_test);
  tcase_add_test(testcase, get_nbytes_test);
  tcase_add_test(testcase, get_duration_test);
  tcase_add_test(testcase, bin2hex_test);
  tcase_add_test(testcase, hex2bin_test);
  tcase_add_test(testcase, levenshtein_test);
  tcase_add_test(testcase, similars_test);
  tcase_add_test(testcase, strnrstr_test);
  tcase_add_test(testcase, str2uid_test);
  tcase_add_test(testcase, str2gid_test);
  tcase_add_test(testcase, uid2str_test);
  tcase_add_test(testcase, gid2str_test);
  tcase_add_test(testcase, str_quote_test);
  tcase_add_test(testcase, quote_dir_test);
  tcase_add_test(testcase, text_to_array_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
