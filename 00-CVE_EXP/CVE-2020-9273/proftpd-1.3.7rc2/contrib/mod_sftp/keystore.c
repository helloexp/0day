/*
 * ProFTPD - mod_sftp keystores
 * Copyright (c) 2008-2016 TJ Saunders
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
 */

#include "mod_sftp.h"
#include "keystore.h"
#include "rfc4716.h"

extern int ServerUseReverseDNS;

struct sftp_keystore_store {
  struct sftp_keystore_store *prev, *next;

  const char *store_type;
  sftp_keystore_t *(*store_open)(pool *, int, const char *, const char *);
  unsigned int store_ktypes;
};

static pool *keystore_pool = NULL;
static struct sftp_keystore_store *keystore_stores = NULL;
static unsigned int keystore_nstores = 0;

static const char *trace_channel = "ssh2";

/* Keystore API internals */

static struct sftp_keystore_store *keystore_get_store(const char *store_type,
    unsigned int ktypes) {
  struct sftp_keystore_store *store;

  for (store = keystore_stores; store; store = store->next) {
    pr_signals_handle();

    if ((store->store_ktypes & ktypes) &&
        strcmp(store->store_type, store_type) == 0) {
      return store;
    }
  }

  errno = ENOENT;
  return NULL;
}

/* Main keystore API */

int sftp_keystore_register_store(const char *store_type,
    sftp_keystore_t *(*store_open)(pool *, int, const char *, const char *),
    unsigned int store_ktypes) {
  struct sftp_keystore_store *store;

  if (store_type == NULL ||
      store_open == NULL) {
    errno = EINVAL;
    return -1;
  } 

  if (keystore_pool == NULL) {
    keystore_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(keystore_pool, "SFTP Keystore Pool");
  }

  store = keystore_get_store(store_type, store_ktypes);
  if (store) {
    errno = EEXIST;
    return -1;
  }

  store = pcalloc(keystore_pool, sizeof(struct sftp_keystore_store));
  store->store_type = pstrdup(keystore_pool, store_type);
  store->store_open = store_open;
  store->store_ktypes = store_ktypes;

  store->next = keystore_stores;
  keystore_stores = store;
  keystore_nstores++;

  return 0;
}

int sftp_keystore_unregister_store(const char *store_type,
    unsigned int store_ktypes) {
  struct sftp_keystore_store *store;

  if (store_type == NULL) {
    errno = EINVAL;
    return -1;
  }

  store = keystore_get_store(store_type, store_ktypes);
  if (store == NULL) {
    errno = ENOENT;
    return -1;
  }

  if (store->prev) {
    store->prev->next = store->next;

  } else {
    keystore_stores = store->next;
  }

  if (store->next)
    store->next->prev = store->prev;

  store->prev = store->next = NULL;
  keystore_nstores--;
  
  return 0;
}

int sftp_keystore_init(void) {
  /* Always support RFC4716 keys, via files, by default. */
  sftp_rfc4716_init();

  return 0;
}

int sftp_keystore_free(void) {
  sftp_rfc4716_free();

  return 0;
}

int sftp_keystore_supports_store(const char *store_type,
    unsigned int store_ktype) {
  struct sftp_keystore_store *store;

  store = keystore_get_store(store_type, store_ktype);
  if (store) {
    return 0;
  }

  errno = ENOENT;
  return -1;
}

int sftp_keystore_verify_host_key(pool *p, const char *user,
    const char *host_fqdn, const char *host_user, unsigned char *key_data,
    uint32_t key_len) {
  register unsigned int i;
  int res = -1;
  config_rec *c;

  if (host_fqdn == NULL ||
      host_user == NULL ||
      key_data == NULL ||
      key_len == 0) {
    errno = EINVAL;
    return -1;
  }

  c = find_config(main_server->conf, CONF_PARAM, "SFTPAuthorizedHostKeys",
    FALSE);
  if (c == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no SFTPAuthorizedHostKeys configured");
    errno = EPERM;
    return -1;
  }

  if (ServerUseReverseDNS) {
    if (strcasecmp(host_fqdn, pr_netaddr_get_dnsstr(session.c->remote_addr)) != 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "client-sent FQDN '%s' DOES NOT match client DNS name '%s'", host_fqdn,
         pr_netaddr_get_dnsstr(session.c->remote_addr));
      errno = EACCES;
      return -1;

    } else {
      pr_trace_msg(trace_channel, 9, "client-sent FQDN '%s' matches client "
        "DNS name '%s'", host_fqdn,
        pr_netaddr_get_dnsstr(session.c->remote_addr));
    }

  } else {
    pr_trace_msg(trace_channel, 1, "unable to double-check client-sent "
      "FQDN '%s' against DNS: UseReverseDNS is off", host_fqdn);
  }

  for (i = 0; i < c->argc; i++) {
    struct sftp_keystore_store *sks;
    char *store_type, *ptr;

    res = -1;
    pr_signals_handle();

    store_type = c->argv[i];

    pr_trace_msg(trace_channel, 2,
      "using SFTPAuthorizedHostKeys '%s' for public key authentication for "
      "user '%s', host %s", store_type, user, host_fqdn);

    ptr = strchr(store_type, ':');
    if (ptr == NULL) {
      pr_trace_msg(trace_channel, 2,
        "skipping badly formatted SFTPAuthorizedHostKeys '%s'", store_type);
      continue;
    }

    *ptr = '\0';

    sks = keystore_get_store(store_type, SFTP_SSH2_HOST_KEY_STORE);
    if (sks) {
      sftp_keystore_t *store;

      store = (sks->store_open)(p, SFTP_SSH2_HOST_KEY_STORE, ptr + 1, user);
      if (store) {
        if (store->verify_host_key != NULL) {
          res = (store->verify_host_key)(store, p, user, host_fqdn, host_user,
            key_data, key_len);
          (store->store_close)(store);

          *ptr = ':';
          if (res == 0) {
            break;

          } else {
            pr_trace_msg(trace_channel, 3,
              "error verifying host key for host '%s', user '%s' ('%s'): %s",
              host_fqdn, user, host_user, strerror(errno));
            continue;
          }

        } else {
          *ptr = ':';
          pr_trace_msg(trace_channel, 7,
            "error using SFTPAuthorizedHostKeys '%s': %s", store_type,
            strerror(ENOSYS));
          continue;
        }

      } else {
        *ptr = ':';
        pr_trace_msg(trace_channel, 7,
          "error opening SFTPAuthorizedHostKeys '%s': %s", store_type,
          strerror(errno));
      }
    }

    *ptr = ':';
  }

  if (res == 0) {
    pr_trace_msg(trace_channel, 8,
      "verified host public key for user '%s', host '%s'", user, host_fqdn);
    return res;
  }

  errno = EACCES;
  return -1;
}

int sftp_keystore_verify_user_key(pool *p, const char *user,
    unsigned char *key_data, uint32_t key_len) {
  register unsigned int i;
  int res = -1;
  config_rec *c;

  if (key_data == NULL ||
      key_len == 0) {
    errno = EINVAL;
    return -1;
  }

  c = find_config(main_server->conf, CONF_PARAM, "SFTPAuthorizedUserKeys",
    FALSE);
  if (c == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no SFTPAuthorizedUserKeys configured");
    errno = EPERM;
    return -1;
  }

  for (i = 0; i < c->argc; i++) {
    struct sftp_keystore_store *sks;
    const char *path, *sess_user;
    char *store_type, *ptr;

    pr_signals_handle();

    res = -1;
    store_type = c->argv[i];

    ptr = strchr(store_type, ':');
    if (ptr == NULL) {
      pr_trace_msg(trace_channel, 2,
        "skipping badly formatted SFTPAuthorizedUserKeys '%s'", store_type);
      continue;
    }

    *ptr = '\0';
    path = ptr + 1;

    /* Check for any variables in the configured path.
     *
     * Note that path_subst_uservar() relies on the session.user variable
     * being set, hence why we cache/restore its value.
     */
    sess_user = session.user;
    session.user = user;
    path = path_subst_uservar(p, &path);
    session.user = sess_user;

    pr_trace_msg(trace_channel, 2,
      "using SFTPAuthorizedUserKeys '%s:%s' for public key authentication for "
      "user '%s'", store_type, path, user);

    sks = keystore_get_store(store_type, SFTP_SSH2_USER_KEY_STORE);
    if (sks) {
      sftp_keystore_t *store;

      store = (sks->store_open)(p, SFTP_SSH2_USER_KEY_STORE, path, user);
      if (store) {
        if (store->verify_user_key != NULL) {
          res = (store->verify_user_key)(store, p, user, key_data, key_len);
          (store->store_close)(store);

          *ptr = ':';
          if (res == 0) {
            break;

          } else {
            pr_trace_msg(trace_channel, 3,
              "error verifying user key for user '%s': %s", user,
              strerror(errno));
            continue;
          }

        } else {
          *ptr = ':';
          pr_trace_msg(trace_channel, 7,
            "error using SFTPAuthorizedUserKeys '%s': %s", store_type,
            strerror(ENOSYS));
          continue;
        }

      } else {
        *ptr = ':';
        pr_trace_msg(trace_channel, 7,
          "error opening SFTPAuthorizedUserKeys '%s': %s", store_type,
          strerror(errno));
      }
    }

    *ptr = ':';
  }

  if (res == 0) {
    pr_trace_msg(trace_channel, 8,
      "verified public key for user '%s'", user);
    return res;
  }

  errno = EACCES;
  return -1;
}
