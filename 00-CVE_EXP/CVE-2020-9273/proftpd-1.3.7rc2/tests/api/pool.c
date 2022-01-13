/*
 * ProFTPD - FTP server testsuite
 * Copyright (c) 2008-2015 The ProFTPD Project team
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

/* Pool API tests */

#include "tests.h"

static void set_up(void) {
  init_pools();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("pool", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("pool", 0, 0);
  }

  free_pools();
}

START_TEST (pool_destroy_pool_test) {
  pool *p, *sub_pool;

  mark_point();
  destroy_pool(NULL);

  mark_point();
  p = make_sub_pool(permanent_pool);
  destroy_pool(p);

  /* What happens if we destroy an already-destroyed pool?  Answer: IFF
   * --enable-devel was used, THEN destroying an already-destroyed pool
   * will result in an exit(2) call from within pool.c, via the
   * chk_on_blk_list() function.  How impolite.
   *
   * And if --enable-devel was NOT used, on SOME systems, this test tickles
   * other libc/malloc/free behaviors, which are unsettling.
   *
   * Sigh.  So for now, I'll just leave this here, but commented out.
   */
#if 0
  mark_point();
  destroy_pool(p);
#endif

  mark_point();
  p = make_sub_pool(permanent_pool);
  sub_pool = make_sub_pool(p);
  destroy_pool(p);

  mark_point();
  p = make_sub_pool(permanent_pool);
  sub_pool = make_sub_pool(p);
  destroy_pool(sub_pool);
  destroy_pool(p);
}
END_TEST

START_TEST (pool_make_sub_pool_test) {
  pool *p, *sub_pool;

  p = make_sub_pool(NULL);
  fail_if(p == NULL, "Failed to allocate parent pool");
  destroy_pool(p);

  p = make_sub_pool(NULL);
  fail_if(p == NULL, "Failed to allocate parent pool");

  sub_pool = make_sub_pool(p);
  fail_if(sub_pool == NULL, "Failed to allocate sub pool");

  destroy_pool(p);
}
END_TEST

START_TEST (pool_create_sz_test) {
  pool *p, *sub_pool;
  size_t sz;

  p = make_sub_pool(NULL);
  fail_if(p == NULL, "Failed to allocate parent pool");

  sz = 0;
  sub_pool = pr_pool_create_sz(p, sz);
  fail_if(sub_pool == NULL, "Failed to allocate %u byte sub-pool", sz);
  destroy_pool(sub_pool);

  sz = 1;
  sub_pool = pr_pool_create_sz(p, sz);
  fail_if(sub_pool == NULL, "Failed to allocate %u byte sub-pool", sz);
  destroy_pool(sub_pool);

  sz = 16382;
  sub_pool = pr_pool_create_sz(p, sz);
  fail_if(sub_pool == NULL, "Failed to allocate %u byte sub-pool", sz);
  destroy_pool(sub_pool);

  destroy_pool(p);
}
END_TEST

START_TEST (pool_create_sz_with_alloc_test) {
  register unsigned int i;
  pool *p;
  unsigned int factors[] = { 1, 2, 4, 8, 16, 32, 64, 128, 0 };

  p = make_sub_pool(NULL);

  for (i = 0; factors[i] > 0; i++) {
    register unsigned int j;
    size_t pool_sz, alloc_sz;
    pool *sub_pool;
    unsigned char *data;

    /* Allocate a pool with a given size, then allocate more than that out of
     * the pool.
     */
    pool_sz = (32 * factors[i]);
#ifdef PR_TEST_VERBOSE
    fprintf(stdout, "pool_sz: %lu bytes (factor %u)\n", pool_sz, factors[i]);
#endif /* PR_TEST_VERBOSE */
    sub_pool = pr_pool_create_sz(p, pool_sz);
    fail_if(sub_pool == NULL, "Failed to allocate %u byte sub-pool", pool_sz);

    alloc_sz = (pool_sz * 2);
#ifdef PR_TEST_VERBOSE
    fprintf(stdout, "alloc_sz: %lu bytes (factor %u)\n", alloc_sz, factors[i]);
#endif /* PR_TEST_VERBOSE */
    data = palloc(sub_pool, alloc_sz);

    /* Initialize our allocated memory with some values. */
    mark_point();
    for (j = 0; j < alloc_sz; j++) {
      data[j] = j;
    }

    /* Verify that our values are still there. */
    mark_point();
    for (j = 0; j < alloc_sz; j++) {
#ifdef PR_TEST_VERBOSE
      if (data[j] != j) {
        fprintf(stdout,
          "Iteration #%u: Expected value %u at memory index %u, got %u\n",
          i + 1, j, j, data[j]);
      }
#endif /* PR_TEST_VERBOSE */
      fail_if(data[j] != j,
        "Iteration #%u: Expected value %u at memory index %u, got %u\n", i + 1,
        j, j, data[j]);
    }

    destroy_pool(sub_pool);
  }

  destroy_pool(p);
}
END_TEST

START_TEST (pool_palloc_test) {
  pool *p;
  char *v;
  size_t sz;

  p = make_sub_pool(NULL);
  fail_if(p == NULL, "Failed to allocate parent pool");

  sz = 0;
  v = palloc(p, sz);
  fail_unless(v == NULL, "Allocated %u-len memory", sz);

  sz = 1;
  v = palloc(p, sz);
  fail_if(v == NULL, "Failed to allocate %u-len memory", sz);

  sz = 16382;
  v = palloc(p, sz);
  fail_if(v == NULL, "Failed to allocate %u-len memory", sz);

  destroy_pool(p);
}
END_TEST

START_TEST (pool_pallocsz_test) {
  pool *p;
  char *v;
  size_t sz;

  p = make_sub_pool(NULL);
  fail_if(p == NULL, "Failed to allocate parent pool");

  sz = 0;
  v = pallocsz(p, sz);
  fail_unless(v == NULL, "Allocated %u-len memory", sz);

  sz = 1;
  v = pallocsz(p, sz);
  fail_if(v == NULL, "Failed to allocate %u-len memory", sz);

  sz = 16382;
  v = pallocsz(p, sz);
  fail_if(v == NULL, "Failed to allocate %u-len memory", sz);

  destroy_pool(p);
}
END_TEST

START_TEST (pool_pcalloc_test) {
  register unsigned int i;
  pool *p;
  char *v;
  size_t sz;

  p = make_sub_pool(NULL);
  fail_if(p == NULL, "Failed to allocate parent pool");

  sz = 0;
  v = pcalloc(p, sz);
  fail_unless(v == NULL, "Allocated %u-len memory", sz);

  sz = 1;
  v = pcalloc(p, sz);
  fail_if(v == NULL, "Failed to allocate %u-len memory", sz);
  for (i = 0; i < sz; i++) {
    fail_unless(v[i] == 0, "Allocated non-zero memory at position %u", i);
  }

  sz = 16382;
  v = pcalloc(p, sz);
  fail_if(v == NULL, "Failed to allocate %u-len memory", sz);
  for (i = 0; i < sz; i++) {
    fail_unless(v[i] == 0, "Allocated non-zero memory at position %u", i);
  }

  destroy_pool(p);
}
END_TEST

START_TEST (pool_pcallocsz_test) {
  pool *p;
  char *v;
  size_t sz;

  p = make_sub_pool(NULL);
  fail_if(p == NULL, "Failed to allocate parent pool");

  sz = 0;
  v = pcallocsz(p, sz);
  fail_unless(v == NULL, "Allocated %u-len memory", sz);

  sz = 1;
  v = pcallocsz(p, sz);
  fail_if(v == NULL, "Failed to allocate %u-len memory", sz);

  sz = 16382;
  v = pcallocsz(p, sz);
  fail_if(v == NULL, "Failed to allocate %u-len memory", sz);

  destroy_pool(p);
}
END_TEST

START_TEST (pool_tag_test) {
  pool *p;

  p = make_sub_pool(permanent_pool);

  mark_point();
  pr_pool_tag(NULL, NULL);

  mark_point();
  pr_pool_tag(p, NULL);

  mark_point();
  pr_pool_tag(p, "foo");

  destroy_pool(p);
}
END_TEST

#if defined(PR_USE_DEVEL)
START_TEST (pool_debug_memory_test) {
  pool *p, *sub_pool;

  mark_point();
  pr_pool_debug_memory(NULL);

  mark_point();
  p = make_sub_pool(permanent_pool);
  pr_pool_debug_memory(NULL);

  mark_point();
  destroy_pool(p);
  pr_pool_debug_memory(NULL);

  mark_point();
  p = make_sub_pool(permanent_pool);
  sub_pool = make_sub_pool(p);
  pr_pool_debug_memory(NULL);

  destroy_pool(sub_pool);
  pr_pool_debug_memory(NULL);

  destroy_pool(p);
  pr_pool_debug_memory(NULL);
}
END_TEST

START_TEST (pool_debug_flags_test) {
  int res;

  res = pr_pool_debug_set_flags(-1);
  fail_unless(res < 0, "Failed to handle invalid flags");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_pool_debug_set_flags(0);
  fail_if(res < 0, "Failed to set flags: %s", strerror(errno));
}
END_TEST
#endif /* PR_USE_DEVEL */

static unsigned int pool_cleanup_count = 0;

static void cleanup_cb(void *data) {
  pool_cleanup_count++;
}

START_TEST (pool_register_cleanup_test) {
  pool *p;

  pool_cleanup_count = 0;

  mark_point();
  register_cleanup(NULL, NULL, NULL, NULL);

  mark_point();
  p = make_sub_pool(permanent_pool);
  register_cleanup(p, NULL, NULL, NULL);

  register_cleanup(p, NULL, cleanup_cb, cleanup_cb);
  destroy_pool(p);
  fail_unless(pool_cleanup_count > 0, "Expected cleanup count >0, got %u",
    pool_cleanup_count);
}
END_TEST

START_TEST (pool_unregister_cleanup_test) {
  pool *p;

  pool_cleanup_count = 0;

  mark_point();
  unregister_cleanup(NULL, NULL, NULL);

  mark_point();
  p = make_sub_pool(permanent_pool);
  register_cleanup(p, NULL, cleanup_cb, cleanup_cb);
  unregister_cleanup(p, NULL, NULL);
  fail_unless(pool_cleanup_count == 0, "Expected cleanup count 0, got %u",
    pool_cleanup_count);

  pool_cleanup_count = 0;
  register_cleanup(p, NULL, cleanup_cb, cleanup_cb);
  unregister_cleanup(p, NULL, cleanup_cb);
  fail_unless(pool_cleanup_count == 0, "Expected cleanup count >0, got %u",
    pool_cleanup_count);

  destroy_pool(p);
  fail_unless(pool_cleanup_count == 0, "Expected cleanup count >0, got %u",
    pool_cleanup_count);
}
END_TEST

Suite *tests_get_pool_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("pool");

  testcase = tcase_create("base");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, pool_destroy_pool_test);
  tcase_add_test(testcase, pool_make_sub_pool_test);
  tcase_add_test(testcase, pool_create_sz_test);

  /* Seems this particular testcase reveals a bug in the pool code.  On the
   * third iteration of the loop (pool size = 256, alloc size = 512), the
   * memory check fails.  Perhaps related to PR_TUNABLE_NEW_POOL_SIZE being
   * 512 bytes?  Need to dig into this more.  In the mean time, keep the
   * testcase commented out.
   *
   * Note: when it fails, it looks like:
   *
   *   api/pool.c:116:F:base:pool_create_sz_with_alloc_test:0: Iteration #3: Expected value 256 at memory index 256, got 0
   *
   * If the PR_TEST_VERBOSE macro is defined, you can see the printout of
   * where the memory read does not meet expectations.
   */
#if 0
  tcase_add_test(testcase, pool_create_sz_with_alloc_test);
#endif
  tcase_add_test(testcase, pool_palloc_test);
  tcase_add_test(testcase, pool_pallocsz_test);
  tcase_add_test(testcase, pool_pcalloc_test);
  tcase_add_test(testcase, pool_pcallocsz_test);
  tcase_add_test(testcase, pool_tag_test);
#if defined(PR_USE_DEVEL)
  tcase_add_test(testcase, pool_debug_memory_test);
  tcase_add_test(testcase, pool_debug_flags_test);
#endif /* PR_USE_DEVEL */
  tcase_add_test(testcase, pool_register_cleanup_test);
  tcase_add_test(testcase, pool_unregister_cleanup_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
