/*
 * ProFTPD - mod_auth_otp API testsuite
 * Copyright (c) 2015 The ProFTPD Project team
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

#include "tests.h"

/* Stubs */

session_t session;
server_rec *main_server = NULL;
pool *auth_otp_pool = NULL;
int auth_otp_logfd = -1;

config_rec *find_config(xaset_t *set, int type, const char *name, int recurse) {
  return NULL;
}

void *get_param_ptr(xaset_t *set, const char *name, int recurse) {
  errno = ENOENT;
  return NULL;
}

struct passwd *pr_auth_getpwnam(pool *p, const char *name) {
  return getpwnam(name);
}

void pr_alarms_block(void) {
}

void pr_alarms_unblock(void) {
}

char *pr_env_get(pool *p, const char *key) {
  errno = ENOSYS;
  return NULL;
}

int pr_env_set(pool *p, const char *key, const char *value) {
  return 0;
}

module *pr_module_get(const char *name) {
  errno = ENOENT;
  return NULL;
}

void pr_signals_handle(void) {
}

int pr_trace_get_level(const char *channel) {
  return 0;
}

int pr_trace_msg(const char *channel, int level, const char *fmt, ...) {
  return 0;
}
