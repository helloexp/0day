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

/* Modules API tests */

#include "tests.h"

extern module *loaded_modules;

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  modules_init();
}

static void tear_down(void) {
  loaded_modules = NULL;

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

/* Tests */

static int sess_init_eperm = FALSE;

static int module_sess_init_cb(void) {
  if (sess_init_eperm) {
    sess_init_eperm = FALSE;
    errno = EPERM;
    return -1;
  }

  return 0;
}

START_TEST (module_sess_init_test) {
  int res;
  module m;

  res = modules_session_init();
  fail_unless(res == 0, "Failed to initialize modules: %s", strerror(errno));

  memset(&m, 0, sizeof(m));
  m.name = "testsuite";

  loaded_modules = &m;
  res = modules_session_init();
  fail_unless(res == 0, "Failed to initialize modules: %s", strerror(errno));

  m.sess_init = module_sess_init_cb;
  res = modules_session_init();
  fail_unless(res == 0, "Failed to initialize modules: %s", strerror(errno));

  sess_init_eperm = TRUE;
  res = modules_session_init();
  fail_unless(res < 0, "Initialized modules unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  loaded_modules = NULL;
}
END_TEST

START_TEST (module_command_exists_test) {
  int res;

  res = command_exists(NULL);
  fail_unless(res == FALSE, "Expected FALSE, got %d", res);
}
END_TEST

START_TEST (module_exists_test) {
  unsigned char res;
  module m;

  res = pr_module_exists(NULL);
  fail_unless(res == FALSE, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_module_exists("mod_foo.c");
  fail_unless(res == FALSE, "Failed to handle nonexistent module");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "bar";

  loaded_modules = &m;

  res = pr_module_exists("mod_foo.c");
  fail_unless(res == FALSE, "Failed to handle nonexistent module");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  res = pr_module_exists("mod_bar.c");
  fail_unless(res == TRUE, "Failed to detect existing module");

  res = pr_module_exists("mod_BAR.c");
  fail_unless(res == FALSE, "Failed to handle nonexistent module");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  loaded_modules = NULL;
}
END_TEST

START_TEST (module_get_test) {
  module m, *res;

  res = pr_module_get(NULL);
  fail_unless(res == NULL, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = pr_module_get("mod_foo.c");
  fail_unless(res == NULL, "Failed to handle nonexistent module");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));
  m.name = "bar";

  loaded_modules = &m;

  res = pr_module_get("mod_foo.c");
  fail_unless(res == NULL, "Failed to handle nonexistent module");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  res = pr_module_get("mod_bar.c");
  fail_unless(res != NULL, "Failed to detect existing module");
  fail_unless(res == &m, "Expected %p, got %p", &m, res);

  res = pr_module_get("mod_BAR.c");
  fail_unless(res == NULL, "Failed to handle nonexistent module");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  loaded_modules = NULL;
}
END_TEST

static unsigned int listed = 0;
static int module_listf(const char *fmt, ...) {
  listed++;
  return 0;
}

START_TEST (module_list_test) {
  module m, m2;

  mark_point();
  listed = 0;
  modules_list2(module_listf, 0);
  fail_unless(listed > 0, "Expected >0, got %u", listed);

  memset(&m, 0, sizeof(m));
  m.name = "testsuite";
  m.module_version = "a.b";

  memset(&m2, 0, sizeof(m2));
  m2.name = "testsuite2";

  m.next = &m2;
  loaded_modules = &m;

  mark_point();
  listed = 0;
  modules_list2(module_listf, PR_MODULES_LIST_FL_SHOW_STATIC);
  fail_unless(listed > 0, "Expected >0, got %u", listed);

  mark_point();
  listed = 0;
  modules_list2(module_listf, PR_MODULES_LIST_FL_SHOW_VERSION);
  fail_unless(listed > 0, "Expected >0, got %u", listed);

  mark_point();
  modules_list(PR_MODULES_LIST_FL_SHOW_STATIC);

  loaded_modules = NULL;
}
END_TEST

static int init_cb(void) {
  errno = EACCES;
  return -1;
}

START_TEST (module_load_test) {
  int res;
  module m;

  res = pr_module_load(NULL);
  fail_unless(res < 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));

  res = pr_module_load(&m);
  fail_unless(res < 0, "Failed to handle null name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  m.name = "foo";

  res = pr_module_load(&m);
  fail_unless(res < 0, "Failed to handle badly versioned module");
  fail_unless(errno == EACCES, "Expected EACCES (%d), got %s (%d)", EACCES,
    strerror(errno), errno);

  m.api_version = PR_MODULE_API_VERSION;
  m.init = init_cb;

  res = pr_module_load(&m);
  fail_unless(res < 0, "Failed to handle bad module init callback");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  m.init = NULL;

  res = pr_module_load(&m);
  fail_unless(res == 0, "Failed to load module: %s", strerror(errno));

  res = pr_module_load(&m);
  fail_unless(res < 0, "Failed to handle duplicate module load");
  fail_unless(errno == EEXIST, "Expected EEXIST (%d), got %s (%d)", EEXIST,
    strerror(errno), errno);
}
END_TEST

START_TEST (module_unload_test) {
  int res;
  module m;
  authtable authtab[] = {
    { 0, "setpwent", NULL },
    { 0, NULL, NULL }
  };
  cmdtable cmdtab[] = {
    { CMD, C_RETR, G_READ, NULL, TRUE, FALSE, CL_READ },
    { HOOK, "foo", G_READ, NULL, FALSE, FALSE },
    { 0, NULL }
  };
  conftable conftab[] = {
    { "TestSuite", NULL, NULL },
    { NULL }
  };

  res = pr_module_unload(NULL);
  fail_unless(res < 0, "Failed to handle null argument");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));

  res = pr_module_unload(&m);
  fail_unless(res < 0, "Failed to handle null module name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  m.name = "bar";

  res = pr_module_unload(&m);
  fail_unless(res < 0, "Failed to handle nonexistent module");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  loaded_modules = &m;

  res = pr_module_unload(&m);
  fail_unless(res == 0, "Failed to unload module: %s", strerror(errno));

  res = pr_module_unload(&m);
  fail_unless(res < 0, "Failed to handle nonexistent module");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  m.authtable = authtab;
  m.cmdtable = cmdtab;
  m.conftable = conftab;
  loaded_modules = &m;

  res = pr_module_unload(&m);
  fail_unless(res == 0, "Failed to unload module: %s", strerror(errno));

  loaded_modules = NULL;
}
END_TEST

START_TEST (module_load_authtab_test) {
  int res;
  module m;
  authtable authtab[] = {
    { 0, "setpwent", NULL },
    { 0, NULL, NULL }
  };

  res = pr_module_load_authtab(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));

  res = pr_module_load_authtab(&m);
  fail_unless(res < 0, "Failed to handle null module name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  m.name = "testsuite";
  res = pr_module_load_authtab(&m);
  fail_unless(res == 0, "Failed to load module authtab: %s", strerror(errno));

  pr_module_unload(&m);
  fail_unless(res == 0, "Failed to unload module: %s", strerror(errno));

  m.authtable = authtab;
  res = pr_module_load_authtab(&m);
  fail_unless(res == 0, "Failed to load module authtab: %s", strerror(errno));

  pr_module_unload(&m);
  fail_unless(res == 0, "Failed to unload module: %s", strerror(errno));
}
END_TEST

START_TEST (module_load_cmdtab_test) {
  int res;
  module m;
  cmdtable cmdtab[] = {
    { CMD, C_RETR, G_READ, NULL, TRUE, FALSE, CL_READ },
    { HOOK, "foo", G_READ, NULL, FALSE, FALSE },
    { 0, NULL }
  };

  res = pr_module_load_cmdtab(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));

  res = pr_module_load_cmdtab(&m);
  fail_unless(res < 0, "Failed to handle null module name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  m.name = "testsuite";
  res = pr_module_load_cmdtab(&m);
  fail_unless(res == 0, "Failed to load module cmdtab: %s", strerror(errno));

  pr_module_unload(&m);
  fail_unless(res == 0, "Failed to unload module: %s", strerror(errno));

  m.name = "testsuite";
  m.cmdtable = cmdtab;
  res = pr_module_load_cmdtab(&m);
  fail_unless(res == 0, "Failed to load module cmdtab: %s", strerror(errno));

  pr_module_unload(&m);
  fail_unless(res == 0, "Failed to unload module: %s", strerror(errno));
}
END_TEST

START_TEST (module_load_conftab_test) {
  int res;
  module m;
  conftable conftab[] = {
    { "TestSuite", NULL, NULL },
    { NULL }
  };

  res = pr_module_load_conftab(NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  memset(&m, 0, sizeof(m));

  res = pr_module_load_conftab(&m);
  fail_unless(res < 0, "Failed to handle null module name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  m.name = "testsuite";
  res = pr_module_load_conftab(&m);
  fail_unless(res == 0, "Failed to load module conftab: %s", strerror(errno));

  pr_module_unload(&m);
  fail_unless(res == 0, "Failed to unload module: %s", strerror(errno));

  m.conftable = conftab;
  res = pr_module_load_conftab(&m);
  fail_unless(res == 0, "Failed to load module conftab: %s", strerror(errno));

  pr_module_unload(&m);
  fail_unless(res == 0, "Failed to unload module: %s", strerror(errno));
}
END_TEST

static modret_t *call_cb(cmd_rec *cmd) {
  return PR_HANDLED(cmd);
}

START_TEST (module_call_test) {
  modret_t *res;
  module m;
  cmd_rec *cmd;

  res = pr_module_call(NULL, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL (got %d)",
    errno);

  memset(&m, 0, sizeof(m));

  res = pr_module_call(&m, NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null callback, cmd arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL (got %d)",
    errno);

  res = pr_module_call(NULL, call_cb, NULL);
  fail_unless(res == NULL, "Failed to handle null module, cmd arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL (got %d)",
    errno);

  cmd = pcalloc(p, sizeof(cmd_rec));
  cmd->pool = p;

  res = pr_module_call(NULL, NULL, cmd);
  fail_unless(res == NULL, "Failed to handle null module, callback arguments");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL (got %d)",
    errno);

  res = pr_module_call(&m, call_cb, NULL);
  fail_unless(res == NULL, "Failed to handle null cmd argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL (got %d)",
    errno);

  res = pr_module_call(&m, NULL, cmd);
  fail_unless(res == NULL, "Failed to handle null callback argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL (got %d)",
    errno);

  res = pr_module_call(NULL, call_cb, cmd);
  fail_unless(res == NULL, "Failed to handle null module argument");
  fail_unless(errno == EINVAL, "Failed to set errno to EINVAL (got %d)",
    errno);

  res = pr_module_call(&m, call_cb, cmd);
  fail_unless(res != NULL, "Failed to call function: %s", strerror(errno));
  fail_unless(MODRET_ISHANDLED(res), "Expected HANDLED result");
}
END_TEST

START_TEST (module_create_ret_test) {
  cmd_rec *cmd;
  modret_t *mr;
  char *numeric, *msg;

  mr = mod_create_ret(NULL, 0, NULL, NULL);
  fail_unless(mr == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 1, "testsuite");
  mr = mod_create_ret(cmd, 1, NULL, NULL);
  fail_unless(mr != NULL, "Failed to create modret: %s", strerror(errno));
  fail_unless(mr->mr_error == 1, "Expected 1, got %d", mr->mr_error);
  fail_unless(mr->mr_numeric == NULL, "Expected null, got '%s'",
    mr->mr_numeric);
  fail_unless(mr->mr_message == NULL, "Expected null, got '%s'",
    mr->mr_message);

  numeric = "foo";
  msg = "bar";
  mr = mod_create_ret(cmd, 1, numeric, msg);
  fail_unless(mr != NULL, "Failed to create modret: %s", strerror(errno));
  fail_unless(mr->mr_error == 1, "Expected 1, got %d", mr->mr_error);
  fail_unless(mr->mr_numeric != NULL, "Expected '%s', got null");
  fail_unless(strcmp(mr->mr_numeric, numeric) == 0,
    "Expected '%s', got '%s'", numeric, mr->mr_numeric);
  fail_unless(mr->mr_message != NULL, "Expected '%s', got null");
  fail_unless(strcmp(mr->mr_message, msg) == 0,
    "Expected '%s', got '%s'", msg, mr->mr_message);
}
END_TEST

START_TEST (module_create_error_test) {
  cmd_rec *cmd;
  modret_t *mr;

  mr = mod_create_error(NULL, 0);
  fail_unless(mr == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 1, "testsuite");
  mr = mod_create_error(cmd, 1);
  fail_unless(mr != NULL, "Failed to create modret: %s", strerror(errno));
  fail_unless(mr->mr_error == 1, "Expected 1, got %d", mr->mr_error);
}
END_TEST

START_TEST (module_create_data_test) {
  cmd_rec *cmd;
  modret_t *mr;
  int data = 1;

  mr = mod_create_data(NULL, NULL);
  fail_unless(mr == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  cmd = pr_cmd_alloc(p, 1, "testsuite");
  mr = mod_create_data(cmd, &data);
  fail_unless(mr != NULL, "Failed to create modret: %s", strerror(errno));
  fail_unless(mr->data == &data, "Expected %p, got %p", &data, mr->data);
}
END_TEST

Suite *tests_get_modules_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("modules");

  testcase = tcase_create("module");
  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, module_sess_init_test);
  tcase_add_test(testcase, module_command_exists_test);
  tcase_add_test(testcase, module_exists_test);
  tcase_add_test(testcase, module_get_test);
  tcase_add_test(testcase, module_list_test);
  tcase_add_test(testcase, module_load_test);
  tcase_add_test(testcase, module_unload_test);
  tcase_add_test(testcase, module_load_authtab_test);
  tcase_add_test(testcase, module_load_cmdtab_test);
  tcase_add_test(testcase, module_load_conftab_test);
  tcase_add_test(testcase, module_call_test);

  tcase_add_test(testcase, module_create_ret_test);
  tcase_add_test(testcase, module_create_error_test);
  tcase_add_test(testcase, module_create_data_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
