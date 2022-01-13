/*
 * ProFTPD: mod_unique_id -- a module for generating a unique ID for each
 *                           FTP session.
 * Copyright (c) 2006-2017 TJ Saunders
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
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_unique_id, contrib software for proftpd 1.2.x/1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"

/* A lot of ideas for this module were liberally borrowed from the mod_uniq_id
 * module for Apache.
 */

#define MOD_UNIQUE_ID_VERSION		"mod_unique_id/0.2"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030402
# error "ProFTPD 1.3.4rc2 or later required"
#endif

module unique_id_module;

static const char base64[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
  'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
  'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
  't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', '+', '/'
};

static unsigned int host_ipaddr = 0;

/* Configuration handlers
 */

/* usage: UniqueIDEngine on|off */
MODRET set_uniqueidengine(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void uniqid_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_unique_id.c", (const char *) event_data) == 0) {
    /* Unregister ourselves from all events. */
    pr_event_unregister(&unique_id_module, NULL, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

static void uniqid_postparse_ev(const void *event_data, void *user_data) {
  pool *tmp_pool = make_sub_pool(main_server->pool);
  const char *host_name = NULL;
  const pr_netaddr_t *host_addr = NULL;
  void *addr_data = NULL;

  host_name = pr_netaddr_get_localaddr_str(tmp_pool);
  if (host_name == NULL) {
    pr_log_pri(PR_LOG_WARNING, MOD_UNIQUE_ID_VERSION
      ": unable to determine hostname");
    destroy_pool(tmp_pool);
    pr_session_disconnect(&unique_id_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  host_addr = pr_netaddr_get_addr(tmp_pool, host_name, NULL);
  if (host_addr == NULL) {
    pr_log_pri(PR_LOG_WARNING, MOD_UNIQUE_ID_VERSION
      ": unable to resolve '%s' to an IP address", host_name);
    destroy_pool(tmp_pool);
    pr_session_disconnect(&unique_id_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  addr_data = pr_netaddr_get_inaddr(host_addr);
  if (addr_data) {
    /* Copy bits from addr_data up to the size of an unsigned int (32 bits,
     * ideally).  In the case of an IPv6 address, this will only use the
     * low-order bits of the entire address.  C'est la vie.
     */
    memcpy(&host_ipaddr, addr_data, sizeof(host_ipaddr));
  }

  destroy_pool(tmp_pool);
  return;
}

/* Initialization functions
 */

static int uniqid_init(void) {

#if defined(PR_SHARED_MODULE)
  pr_event_register(&unique_id_module, "core.module-unload",
    uniqid_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&unique_id_module, "core.postparse", uniqid_postparse_ev,
    NULL);

  return 0;
}

static int uniqid_sess_init(void) {
  config_rec *c;
  int uniqid_engine = TRUE;
  unsigned int client_ipaddr = 0;
  void *addr_data = NULL;
  unsigned int pid;
  unsigned int now;
  unsigned short counter;
  struct timeval tv;
  struct timezone tz;
  char *key = "UNIQUE_ID", *id = NULL;
  unsigned char *x, *y;
  register unsigned int i, j;

  /* Four pieces of data as unsigned ints:
   *
   *  host IP address
   *  client IP address
   *  PID
   *  timestamp (in seconds)
   *
   * and one piece of unsigned short data:
   *
   *  counter (derived from number of microsecond)
   */
  unsigned short id_sz = (sizeof(unsigned int) * 4) + (sizeof(unsigned short));
  unsigned short id_encoded_sz = (id_sz * 8 + 5) / 6;
  unsigned char buf[id_sz];

  c = find_config(main_server->conf, CONF_PARAM, "UniqueIDEngine", FALSE);
  if (c) {
    uniqid_engine = *((int *) c->argv[0]);
  }

  if (!uniqid_engine)
    return 0;

  pr_log_debug(DEBUG8, MOD_UNIQUE_ID_VERSION ": generating unique session ID");

  if (gettimeofday(&tv, &tz) < 0) {
    pr_log_debug(DEBUG1, MOD_UNIQUE_ID_VERSION
      ": error getting time of day: %s", strerror(errno));
    now = 0;
    counter = 0;

  } else {
    now = htonl((unsigned int) tv.tv_sec);
    counter = htons((unsigned short) (tv.tv_usec / 10));
  }

  pid = htonl((unsigned int) getpid());

  addr_data = pr_netaddr_get_inaddr(session.c->remote_addr);
  if (addr_data) {
    /* Copy bits from addr_data up to the size of an unsigned int (32 bits,
     * ideally).  In the case of an IPv6 address, this will only use the
     * low-order bits of the entire address.  C'est la vie.
     */
    memcpy(&client_ipaddr, addr_data, sizeof(client_ipaddr));
  }

  /* Populate buf with the binary pieces of data we've collected. */
  memset(buf, '\0', sizeof(buf));
  x = buf;

  j = 0;
  y = (unsigned char *) &now;
  for (i = 0; i < sizeof(unsigned int); i++, j++) {
    x[j] = y[i];
  }

  y = (unsigned char *) &host_ipaddr;
  for (i = 0; i < sizeof(unsigned int); i++, j++) {
    x[j] = y[i];
  }

  y = (unsigned char *) &client_ipaddr;
  for (i = 0; i < sizeof(unsigned int); i++, j++) {
    x[j] = y[i];
  }

  y = (unsigned char *) &pid;
  for (i = 0; i < sizeof(unsigned int); i++, j++) {
    x[j] = y[i];
  }

  y = (unsigned char *) &counter;
  for (i = 0; i < sizeof(unsigned short); i++, j++) {
    x[j] = y[i];
  }

  /* Add one to the encoded size, for the trailing NUL. */
  id = pcalloc(session.pool, id_encoded_sz + 1);

  j = 0;
  for (i = 0; i < id_sz; i += 3) {
    y = x + i;

    id[j++] = base64[y[0] >> 2];
    id[j++] = base64[((y[0] & 0x03) << 4) | ((y[1] & 0xf0) >> 4)];

    if (j == id_encoded_sz)
      break;

    id[j++] = base64[((y[1] & 0x0f) << 2) | ((y[2] & 0xc0) >> 6)];

    if (j == id_encoded_sz)
      break;

    id[j++] = base64[y[2] & 0x3f];
  }

  if (j >= id_encoded_sz)
    j = id_encoded_sz;
  id[j] = '\0';

  if (pr_env_set(session.pool, key, id) < 0) {
    pr_log_debug(DEBUG0, MOD_UNIQUE_ID_VERSION
      ": error setting UNIQUE_ID environment variable: %s", strerror(errno));

  } else {
    pr_log_debug(DEBUG8, MOD_UNIQUE_ID_VERSION
      ": unique session ID is '%s'", id);
  }

  if (pr_table_add_dup(session.notes, pstrdup(session.pool, key), id, 0) < 0) {
    pr_log_debug(DEBUG0, MOD_UNIQUE_ID_VERSION
      ": error adding %s session note: %s", key, strerror(errno));
  }

  return 0;
}

/* Module API tables
 */

static conftable uniqid_conftab[] = {
  { "UniqueIDEngine",	set_uniqueidengine,	NULL },
  { NULL }
};

module unique_id_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "unique_id",

  /* Module configuration handler table */
  uniqid_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  uniqid_init,

  /* Session initialization function */
  uniqid_sess_init,

  /* Module version */
  MOD_UNIQUE_ID_VERSION
};
