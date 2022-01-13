/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2001-2016 The ProFTPD Project team
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

/* Routines to work with ProFTPD bindings. */

#include "conf.h"

/* From src/dirtree.c */
extern xaset_t *server_list;
extern server_rec *main_server;

static pr_ipbind_t *ipbind_table[PR_BINDINGS_TABLE_SIZE];
static pool *binding_pool = NULL;
static pr_ipbind_t *ipbind_default_server = NULL,
                   *ipbind_localhost_server = NULL;

static const char *trace_channel = "binding";

/* Server cleanup callback function */
static void server_cleanup_cb(void *conn) {
  *((conn_t **) conn) = NULL;
}

/* The hashing function for the hash table of bindings.  This algorithm
 * is stolen from Apache's http_vhost.c
 */
static unsigned int ipbind_hash_addr(const pr_netaddr_t *addr) {
  size_t offset;
  unsigned int key;

  offset = pr_netaddr_get_inaddr_len(addr);

  /* The key is the last four bytes of the IP address.
   * For IPv4, this is the entire address, as always.
   * For IPv6, this is usually part of the MAC address.
   */
  key = *(unsigned *) ((char *) pr_netaddr_get_inaddr(addr) + offset - 4);

  key ^= (key >> 16);
  return ((key >> 8) ^ key) % PR_BINDINGS_TABLE_SIZE;
}

static pool *listening_conn_pool = NULL;
static xaset_t *listening_conn_list = NULL;
struct listener_rec {
  struct listener_rec *next, *prev;

  pool *pool;
  const pr_netaddr_t *addr;
  unsigned int port;
  conn_t *conn;
  int claimed;
};

conn_t *pr_ipbind_get_listening_conn(server_rec *server,
    const pr_netaddr_t *addr, unsigned int port) {
  conn_t *l;
  pool *p;
  struct listener_rec *lr;

  if (listening_conn_list) {
    for (lr = (struct listener_rec *) listening_conn_list->xas_list; lr;
        lr = lr->next) {
      int use_elt = FALSE;

      pr_signals_handle();

      if (addr != NULL &&
          lr->addr != NULL) {
        const char *lr_ipstr = NULL;

        lr_ipstr = pr_netaddr_get_ipstr(lr->addr);

        /* Note: lr_ipstr should never be null.  If it is, it means that
         * the lr->addr object never had its IP address resolved/stashed,
         * and in attempting to do, getnameinfo(3) failed for some reason.
         *
         * The IP address on which it's listening, if not available via
         * lr->addr, should thus be available via lr->conn->local_addr.
         */

        if (lr_ipstr == NULL &&
            lr->conn != NULL) {
          lr_ipstr = pr_netaddr_get_ipstr(lr->conn->local_addr);
        }

        if (lr_ipstr != NULL) {
          if (strcmp(pr_netaddr_get_ipstr(addr), lr_ipstr) == 0 &&
              port == lr->port) {
            use_elt = TRUE;
          }
        }

      } else if (addr == NULL &&
                 port == lr->port) {
        use_elt = TRUE;
      }

      if (use_elt) { 
        lr->claimed = TRUE;
        return lr->conn;
      }
    }
  }

  if (listening_conn_pool == NULL) {
    listening_conn_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(listening_conn_pool, "Listening Connection Pool");

    listening_conn_list = xaset_create(listening_conn_pool, NULL);
  }

  p = make_sub_pool(listening_conn_pool); 
  pr_pool_tag(p, "Listening conn subpool");

  l = pr_inet_create_conn(p, -1, addr, port, FALSE);
  if (l == NULL) {
    return NULL;
  }

  /* Inform any interested listeners that this socket was opened. */
  pr_inet_generate_socket_event("core.ctrl-listen", server, l->local_addr,
    l->listen_fd);

  lr = pcalloc(p, sizeof(struct listener_rec));
  lr->pool = p;
  lr->conn = l;
  lr->addr = pr_netaddr_dup(p, addr);
  if (lr->addr == NULL &&
      errno != EINVAL) {
    return NULL;
  }
  lr->port = port;
  lr->claimed = TRUE;

  xaset_insert(listening_conn_list, (xasetmember_t *) lr);
  return l;
}

/* Slight (clever?) optimization: the loop in server_loop() always
 * calls pr_ipbind_listen(), selects, then pr_ipbind_accept_conn().  Now,
 * rather than having both pr_ipbind_listen() and pr_ipbind_accept_conn()
 * scan the entire ipbind table looking for matches, what if pr_ipbind_listen
 * kept track of which listeners (connt_s) it used, so that
 * pr_ipbind_accept_conn() need merely check those listeners, rather than
 * scanning the entire table itself?
 */

static array_header *listener_list = NULL;

conn_t *pr_ipbind_accept_conn(fd_set *readfds, int *listenfd) {
  conn_t **listeners = listener_list->elts;
  register unsigned int i = 0;

  if (readfds == NULL ||
      listenfd == NULL) {
    errno = EINVAL;
    return NULL;
  }

  for (i = 0; i < listener_list->nelts; i++) {
    conn_t *listener = listeners[i];

    pr_signals_handle();
    if (FD_ISSET(listener->listen_fd, readfds) &&
        listener->mode == CM_LISTEN) {
      int fd = pr_inet_accept_nowait(listener->pool, listener);

      if (fd == -1) {
        int xerrno = errno;

        /* Handle errors gracefully.  If we're here, then
         * ipbind->ib_server->listen contains either error information, or
         * we just got caught in a blocking condition.
         */
        if (listener->mode == CM_ERROR) {

          /* Ignore ECONNABORTED, as they tend to be health checks/probes by
           * e.g. load balancers and other naive TCP clients.
           */
          if (listener->xerrno != ECONNABORTED) {
            pr_log_pri(PR_LOG_ERR, "error: unable to accept an incoming "
              "connection: %s", strerror(listener->xerrno));
          }

          listener->xerrno = 0;
          listener->mode = CM_LISTEN;

          errno = xerrno;
          return NULL;
        }
      }

      *listenfd = fd;
      return listener;
    }
  }

  errno = ENOENT;
  return NULL;
}

int pr_ipbind_add_binds(server_rec *serv) {
  int res = 0;
  config_rec *c = NULL;
  conn_t *listen_conn = NULL;
  const pr_netaddr_t *addr = NULL;

  if (serv == NULL) {
    errno = EINVAL;
    return -1;
  }

  c = find_config(serv->conf, CONF_PARAM, "_bind_", FALSE);
  while (c != NULL) {
    listen_conn = NULL;

    pr_signals_handle();

    addr = pr_netaddr_get_addr(serv->pool, c->argv[0], NULL);
    if (addr == NULL) {
      pr_log_pri(PR_LOG_WARNING,
       "notice: unable to determine IP address of '%s'", (char *) c->argv[0]);
      c = find_config_next(c, c->next, CONF_PARAM, "_bind_", FALSE);
      continue;
    }

    /* If the SocketBindTight directive is in effect, create a separate
     * listen socket for this address, and add it to the binding list.
     */
    if (SocketBindTight &&
        serv->ServerPort) {
      listen_conn = pr_ipbind_get_listening_conn(serv, addr, serv->ServerPort);
      if (listen_conn == NULL) {
        return -1;
      }

      PR_CREATE_IPBIND(serv, addr, serv->ServerPort);
      PR_OPEN_IPBIND(addr, serv->ServerPort, listen_conn, FALSE, FALSE, TRUE);

    } else {

      PR_CREATE_IPBIND(serv, addr, serv->ServerPort);
      PR_OPEN_IPBIND(addr, serv->ServerPort, serv->listen, FALSE, FALSE, TRUE);
    }

    c = find_config_next(c, c->next, CONF_PARAM, "_bind_", FALSE);
  }

  return 0;
}

int pr_ipbind_close(const pr_netaddr_t *addr, unsigned int port,
    unsigned char close_namebinds) {
  register unsigned int i = 0;

  if (addr) {
    pr_ipbind_t *ipbind = NULL;
    unsigned char have_ipbind = FALSE;

    i = ipbind_hash_addr(addr);

    if (ipbind_table[i] == NULL) {
      pr_log_pri(PR_LOG_NOTICE, "notice: no ipbind found for %s:%d",
        pr_netaddr_get_ipstr(addr), port);
      errno = ENOENT;
      return -1;
    }

    for (ipbind = ipbind_table[i]; ipbind; ipbind = ipbind->ib_next) {
      if (pr_netaddr_cmp(ipbind->ib_addr, addr) == 0 &&
          (!ipbind->ib_port || ipbind->ib_port == port)) {
        have_ipbind = TRUE;
        break;
      }
    }

    if (!have_ipbind) {
      pr_log_pri(PR_LOG_NOTICE, "notice: no ipbind found for %s:%d",
        pr_netaddr_get_ipstr(addr), port);
      errno = ENOENT;
      return -1;
    }

    /* If already closed, exit now. */
    if (!ipbind->ib_isactive) {
      errno = EPERM;
      return -1;
    }

    /* Close the ipbinding's listen connection, if present.  The trick
     * here is determining whether this binding's listen member is
     * _the_ listening socket for the master daemon, or whether it's
     * been created for SocketBindTight, and can be closed.
     *
     * Actually, it's not that hard.  It's only _the_ listening socket
     * for the master daemon in inetd mode, in which case virtual servers
     * can't be shutdown via ftpdctl, anyway.
     */
    if (SocketBindTight && ipbind->ib_listener != NULL) {
      pr_inet_close(ipbind->ib_server->pool, ipbind->ib_listener);
      ipbind->ib_listener = ipbind->ib_server->listen = NULL;
    }

    /* Mark this ipbind as inactive.  For SocketBindTight sockets, the
     * closing of the listening connection will suffice, from the clients'
     * point of view.  However, this covers the non-SocketBindTight case,
     * and will prevent this binding from returning its server_rec pointer
     * on future lookup requests via pr_ipbind_get_server().
     */
    ipbind->ib_isactive = FALSE;

    if (close_namebinds && ipbind->ib_namebinds) {
      register unsigned int j = 0;
      pr_namebind_t **namebinds = NULL;

      namebinds = (pr_namebind_t **) ipbind->ib_namebinds->elts;
      for (j = 0; j < ipbind->ib_namebinds->nelts; j++) {
        pr_namebind_t *nb = namebinds[j];

        if (pr_namebind_close(nb->nb_name, nb->nb_server->addr) < 0) {
          pr_trace_msg(trace_channel, 7,
            "notice: error closing namebind '%s' for address %s: %s",
            nb->nb_name, pr_netaddr_get_ipstr(nb->nb_server->addr),
            strerror(errno));
        }
      }
    }

  } else {
    /* A NULL addr has a special meaning: close _all_ ipbinds in the list. */
    for (i = 0; i < PR_BINDINGS_TABLE_SIZE; i++) {
      pr_ipbind_t *ipbind = NULL;
      for (ipbind = ipbind_table[i]; ipbind; ipbind = ipbind->ib_next) {

        if (SocketBindTight && ipbind->ib_listener != NULL) {
          pr_inet_close(main_server->pool, ipbind->ib_listener);
          ipbind->ib_listener = ipbind->ib_server->listen = NULL;
        }

        /* Note: do not need to check if this ipbind was previously closed,
         * for the NULL addr is a request to shut down all ipbinds,
         * regardless of their current state.
         */
        ipbind->ib_isactive = FALSE;

        if (close_namebinds && ipbind->ib_namebinds) {
          register unsigned int j = 0;
          pr_namebind_t **namebinds = NULL;

          namebinds = (pr_namebind_t **) ipbind->ib_namebinds->elts;
          for (j = 0; j < ipbind->ib_namebinds->nelts; j++) {
            pr_namebind_t *nb = namebinds[j];

            if (pr_namebind_close(nb->nb_name, nb->nb_server->addr) < 0) {
              pr_trace_msg(trace_channel, 7,
                "notice: error closing namebind '%s' for address %s: %s",
                nb->nb_name, pr_netaddr_get_ipstr(nb->nb_server->addr),
               strerror(errno));
            }
          }
        }
      }
    }
  }

  return 0;
}

/* Need a way to close all listening fds in a child process. */
int pr_ipbind_close_listeners(void) {
  conn_t **listeners;
  register unsigned int i = 0;

  if (!listener_list ||
      listener_list->nelts == 0)
    return 0;

  listeners = listener_list->elts;
  for (i = 0; i < listener_list->nelts; i++) {
    conn_t *listener = listeners[i];

    pr_signals_handle();

    if (listener->listen_fd != -1) {
      close(listener->listen_fd);
      listener->listen_fd = -1;
    }
  }

  return 0;
}

int pr_ipbind_create(server_rec *server, const pr_netaddr_t *addr,
    unsigned int port) {
  pr_ipbind_t *ipbind = NULL;
  register unsigned int i = 0;

  if (server == NULL||
      addr == NULL) {
    errno = EINVAL;
    return -1;
  }

  i = ipbind_hash_addr(addr);

  /* Make sure the address is not already in use */
  for (ipbind = ipbind_table[i]; ipbind; ipbind = ipbind->ib_next) {
    if (pr_netaddr_cmp(ipbind->ib_addr, addr) == 0 &&
        ipbind->ib_port == port) {

      /* An ipbind already exists for this IP address */
      pr_log_pri(PR_LOG_WARNING, "notice: '%s' (%s:%u) already bound to '%s'",
        server->ServerName, pr_netaddr_get_ipstr(addr), port,
        ipbind->ib_server->ServerName);

      errno = EADDRINUSE;
      return -1;
    }
  }

  if (!binding_pool) {
    binding_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(binding_pool, "Bindings Pool");
  }

  ipbind = pcalloc(server->pool, sizeof(pr_ipbind_t));
  ipbind->ib_server = server;
  ipbind->ib_addr = addr;
  ipbind->ib_port = port;
  ipbind->ib_namebinds = NULL;
  ipbind->ib_isdefault = FALSE;
  ipbind->ib_islocalhost = FALSE;
  ipbind->ib_isactive = FALSE;

  pr_trace_msg(trace_channel, 8, "created IP binding for %s#%u, server %p",
    pr_netaddr_get_ipstr(ipbind->ib_addr), ipbind->ib_port, ipbind->ib_server);

  /* Add the ipbind to the table. */
  if (ipbind_table[i]) {
    ipbind->ib_next = ipbind_table[i];
  }

  ipbind_table[i] = ipbind;
  return 0;
}

/* Returns the LAST matching ipbind for the given port, if any.  If provided,
 * the match_count pointer will contain the number of ipbinds found that
 * matched that port.
 */
static pr_ipbind_t *ipbind_find_port(unsigned int port,
    unsigned char skip_inactive, unsigned int *match_count) {
  register unsigned int i;
  pr_ipbind_t *matched_ipbind = NULL;

  for (i = 0; i < PR_BINDINGS_TABLE_SIZE; i++) {
    pr_ipbind_t *ipbind;

    for (ipbind = ipbind_table[i]; ipbind; ipbind = ipbind->ib_next) {
      pr_signals_handle();

      if (skip_inactive &&
          !ipbind->ib_isactive) {
        continue;
      }

      if (ipbind->ib_port == port) {
        if (match_count != NULL) {
          (*match_count)++;
        }

        matched_ipbind = ipbind;
      }
    }
  }

  if (matched_ipbind == NULL) {
    errno = ENOENT;
    return NULL;
  }

  return matched_ipbind;
}

pr_ipbind_t *pr_ipbind_find(const pr_netaddr_t *addr, unsigned int port,
    unsigned char skip_inactive) {
  register unsigned int i;
  pr_ipbind_t *ipbind = NULL;

  if (addr == NULL) {
    errno = EINVAL;
    return NULL;
  }

  i = ipbind_hash_addr(addr);

  for (ipbind = ipbind_table[i]; ipbind; ipbind = ipbind->ib_next) {
    pr_signals_handle();

    if (skip_inactive &&
        !ipbind->ib_isactive) {
      continue;
    }

    if (pr_netaddr_cmp(ipbind->ib_addr, addr) == 0) {
      if (ipbind->ib_port == 0 ||
          port == 0 ||
          ipbind->ib_port == port) {
        return ipbind;
      }
    }
  }

  errno = ENOENT;
  return NULL;
}

pr_ipbind_t *pr_ipbind_get(pr_ipbind_t *prev) {
  static unsigned int i = 0;

  if (prev) {

    /* If there's another ipbind in this chain, simply return that. */
    if (prev->ib_next) {
      return prev->ib_next;
    }

    /* If the increment is at the maximum size, return NULL (no more chains
     * to be examined).
     */
    if (i == PR_BINDINGS_TABLE_SIZE) {
      errno = ENOENT;
      return NULL;
    }

    /* Increment the index. At this point, we know that the given pointer is
     * the last in the chain, and that there are more chains in the table
     * to be examined.
     */
    i++;

  } else {
    /* Reset the index if prev is NULL. */
    i = 0;
  }

  /* Search for the next non-empty chain in the table. */
  for (; i < PR_BINDINGS_TABLE_SIZE; i++) {
    if (ipbind_table[i]) {
      return ipbind_table[i];
    }
  }

  errno = ENOENT;
  return NULL;
}

server_rec *pr_ipbind_get_server(const pr_netaddr_t *addr, unsigned int port) {
  pr_ipbind_t *ipbind = NULL;
  pr_netaddr_t wildcard_addr;
  int addr_family;
  unsigned int match_count = 0;

  /* If we've got a binding configured for this exact address, return it
   * straight away.
   */
  ipbind = pr_ipbind_find(addr, port, TRUE);
  if (ipbind != NULL) {
    return ipbind->ib_server;
  }

  /* Look for a vhost bound to the wildcard address (i.e. INADDR_ANY).
   *
   * This allows for "<VirtualHost 0.0.0.0>" configurations, where the
   * IP address to which the client might connect is not known at
   * configuration time.  (Usually happens when the same config file
   * is deployed to multiple machines.)
   */

  addr_family = pr_netaddr_get_family(addr);

  pr_netaddr_clear(&wildcard_addr);
  pr_netaddr_set_family(&wildcard_addr, addr_family);
  pr_netaddr_set_sockaddr_any(&wildcard_addr);

  ipbind = pr_ipbind_find(&wildcard_addr, port, TRUE);
  if (ipbind != NULL) {
    pr_log_debug(DEBUG7, "no matching vhost found for %s#%u, using "
      "'%s' listening on wildcard address", pr_netaddr_get_ipstr(addr), port,
      ipbind->ib_server->ServerName);
    return ipbind->ib_server;

  } else {
#ifdef PR_USE_IPV6
    if (addr_family == AF_INET6 &&
        pr_netaddr_use_ipv6()) {

      /* The pr_ipbind_find() probably returned NULL because there aren't any
       * <VirtualHost> sections configured explicitly for the wildcard IPv6
       * address of "::", just the IPv4 wildcard "0.0.0.0" address.
       *
       * So try the pr_ipbind_find() again, this time using the IPv4
       * wildcard.
       */
      pr_netaddr_clear(&wildcard_addr);
      pr_netaddr_set_family(&wildcard_addr, AF_INET);
      pr_netaddr_set_sockaddr_any(&wildcard_addr);

      ipbind = pr_ipbind_find(&wildcard_addr, port, TRUE);
      if (ipbind != NULL) {
        pr_log_debug(DEBUG7, "no matching vhost found for %s#%u, using "
          "'%s' listening on wildcard address", pr_netaddr_get_ipstr(addr),
          port, ipbind->ib_server->ServerName);
        return ipbind->ib_server;
      }
    }
#endif /* PR_USE_IPV6 */
  }

  /* Check for any bindings that match the port.  IF there is only one ONE
   * vhost which matches the requested port, use that (Bug#4251).
   */
  ipbind = ipbind_find_port(port, TRUE, &match_count);
  if (ipbind != NULL) {
    pr_trace_msg(trace_channel, 18, "found %u possible %s for port %u",
      match_count, match_count != 1 ? "ipbinds" : "ipbind", port);
    if (match_count == 1) {
      return ipbind->ib_server;
    }
  }

  /* Use the default server, if set. */
  if (ipbind_default_server &&
      ipbind_default_server->ib_isactive) {
    pr_log_debug(DEBUG7, "no matching vhost found for %s#%u, using "
      "DefaultServer '%s'", pr_netaddr_get_ipstr(addr), port,
      ipbind_default_server->ib_server->ServerName);
    return ipbind_default_server->ib_server;
  }

  /* Not found in binding list, and no DefaultServer, so see if it's the
   * loopback address
   */
  if (ipbind_localhost_server &&
      pr_netaddr_is_loopback(addr)) {
    return ipbind_localhost_server->ib_server;
  }

  return NULL;
}

int pr_ipbind_listen(fd_set *readfds) {
  int listen_flags = PR_INET_LISTEN_FL_FATAL_ON_ERROR, maxfd = 0;
  register unsigned int i = 0;

  /* sanity check */
  if (readfds == NULL) {
    errno = EINVAL;
    return -1;
  }

  FD_ZERO(readfds);

  if (binding_pool == NULL) {
    binding_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(binding_pool, "Bindings Pool");
  }

  /* Reset the listener list. */
  if (!listener_list) {
    listener_list = make_array(binding_pool, 1, sizeof(conn_t *));

  } else {
    /* Nasty hack to "clear" the list by making it think it has no
     * elements.
     */
    listener_list->nelts = 0;
  }

  /* Slower than the hash lookup, but...we have to check each and every
   * ipbind in the table.
   */
  for (i = 0; i < PR_BINDINGS_TABLE_SIZE; i++) {
    pr_ipbind_t *ipbind = NULL;

    for (ipbind = ipbind_table[i]; ipbind; ipbind = ipbind->ib_next) {

      /* Skip inactive bindings, but only if SocketBindTight is in effect. */
      if (SocketBindTight &&
          !ipbind->ib_isactive)
        continue;

      if (ipbind->ib_listener) {

        if (ipbind->ib_listener->mode == CM_NONE) {
          pr_inet_listen(ipbind->ib_listener->pool, ipbind->ib_listener,
            tcpBackLog, listen_flags);
        }

        if (ipbind->ib_listener->mode == CM_ACCEPT) {
          if (pr_inet_resetlisten(ipbind->ib_listener->pool,
              ipbind->ib_listener) < 0) {
            pr_trace_msg(trace_channel, 3,
              "error resetting %s#%u for listening: %s",
              pr_netaddr_get_ipstr(ipbind->ib_addr), ipbind->ib_port,
              strerror(errno));
          }
        }

        if (ipbind->ib_listener->mode == CM_LISTEN) {
          FD_SET(ipbind->ib_listener->listen_fd, readfds);
          if (ipbind->ib_listener->listen_fd > maxfd)
            maxfd = ipbind->ib_listener->listen_fd;

          /* Add this to the listener list as well. */
          *((conn_t **) push_array(listener_list)) = ipbind->ib_listener;
        }
      }
    }
  }

  return maxfd;
}

int pr_ipbind_open(const pr_netaddr_t *addr, unsigned int port,
    conn_t *listen_conn, unsigned char isdefault, unsigned char islocalhost,
    unsigned char open_namebinds) {
  int res = 0;
  pr_ipbind_t *ipbind = NULL;

  if (addr == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Find the binding for this server/address */
  ipbind = pr_ipbind_find(addr, port, FALSE);
  if (ipbind == NULL) {
    errno = ENOENT;
    return -1;
  }

  if (listen_conn)
    listen_conn->next = NULL;

  ipbind->ib_listener = ipbind->ib_server->listen = listen_conn;
  ipbind->ib_listener = listen_conn;
  ipbind->ib_isdefault = isdefault;
  ipbind->ib_islocalhost = islocalhost;

  /* Stash a pointer to this ipbind, since it is designated as the
   * default server (via the DefaultServer directive), for use in the
   * lookup functions.
   *
   * Stash pointers to this ipbind for use in the lookup functions if:
   *
   * - It's the default server (specified via the DefaultServer directive)
   * - It handles connections to the loopback interface
   */
  if (isdefault)
    ipbind_default_server = ipbind;

  if (islocalhost)
    ipbind_localhost_server = ipbind;

  /* If requested, look for any namebinds for this ipbind, and open them. */
  if (open_namebinds &&
      ipbind->ib_namebinds) {
    register unsigned int i = 0;
    pr_namebind_t **namebinds = NULL;

    /* NOTE: in the future, these namebinds may need to be stored/
     * manipulated in hash tables themselves, but, for now, linked lists
     * should suffice.
     */
    namebinds = (pr_namebind_t **) ipbind->ib_namebinds->elts;
    for (i = 0; i < ipbind->ib_namebinds->nelts; i++) {
      pr_namebind_t *nb = namebinds[i];

      res = pr_namebind_open(nb->nb_name, nb->nb_server->addr);
      if (res < 0) {
        pr_trace_msg(trace_channel, 2,
          "notice: unable to open namebind '%s': %s", nb->nb_name,
          strerror(errno));
      }
    }
  }

  /* Mark this binding as now being active. */
  ipbind->ib_isactive = TRUE;

  return 0;
}

int pr_namebind_close(const char *name, const pr_netaddr_t *addr) {
  pr_namebind_t *namebind = NULL;
  unsigned int port;

  if (name == NULL||
      addr == NULL) {
    errno = EINVAL;
    return -1;
  }

  port = ntohs(pr_netaddr_get_port(addr));
  namebind = pr_namebind_find(name, addr, port, FALSE);
  if (namebind == NULL) {
    errno = ENOENT;
    return -1;
  }

  namebind->nb_isactive = FALSE;
  return 0;
}

int pr_namebind_create(server_rec *server, const char *name,
    const pr_netaddr_t *addr, unsigned int server_port) {
  pr_ipbind_t *ipbind = NULL;
  pr_namebind_t *namebind = NULL, **namebinds = NULL;
  unsigned int port;

  if (server == NULL ||
      name == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* First, find the ipbind to hold this namebind. */
  port = ntohs(pr_netaddr_get_port(addr));
  if (port == 0) {
    port = server_port;
  }
  ipbind = pr_ipbind_find(addr, port, FALSE);
  pr_trace_msg(trace_channel, 19,
    "found ipbind %p for namebind (name '%s', addr %s, port %u)", ipbind, name,
    pr_netaddr_get_ipstr(addr), port);

  if (ipbind == NULL) {
    pr_netaddr_t wildcard_addr;
    int addr_family;

    /* If not found, look for the wildcard address. */

    addr_family = pr_netaddr_get_family(addr);
    pr_netaddr_clear(&wildcard_addr);
    pr_netaddr_set_family(&wildcard_addr, addr_family);
    pr_netaddr_set_sockaddr_any(&wildcard_addr);

    ipbind = pr_ipbind_find(&wildcard_addr, port, FALSE);
#ifdef PR_USE_IPV6
    if (ipbind == FALSE &&
        addr_family == AF_INET6 &&
        pr_netaddr_use_ipv6()) {

      /* No IPv6 wildcard address found; try the IPv4 wildcard address. */
      pr_netaddr_clear(&wildcard_addr);
      pr_netaddr_set_family(&wildcard_addr, AF_INET);
      pr_netaddr_set_sockaddr_any(&wildcard_addr);

      ipbind = pr_ipbind_find(&wildcard_addr, port, FALSE);
    }
#endif /* PR_USE_IPV6 */

    pr_trace_msg(trace_channel, 19,
      "found wildcard ipbind %p for namebind (name '%s', addr %s, port %u)",
      ipbind, name, pr_netaddr_get_ipstr(addr), port);
  }

  if (ipbind == NULL) {
    errno = ENOENT;
    return -1;
  }

  /* Make sure we can add this namebind. */
  if (!ipbind->ib_namebinds) {
    ipbind->ib_namebinds = make_array(binding_pool, 0, sizeof(pr_namebind_t *));

  } else {
    register unsigned int i = 0;
    namebinds = (pr_namebind_t **) ipbind->ib_namebinds->elts;

    /* See if there is already a namebind for the given name. */
    for (i = 0; i < ipbind->ib_namebinds->nelts; i++) {
      namebind = namebinds[i];
      if (namebind != NULL &&
          namebind->nb_name != NULL) {

        /* DNS names are case-insensitive, hence the case-insensitive check
         * here.
         *
         * XXX Ideally, we should check whether any existing namebinds which
         * are globs will match the newly added namebind as well.
         */

        if (strcasecmp(namebind->nb_name, name) == 0) {
          errno = EEXIST;
          return -1;
        }
      }
    }
  }

  namebind = (pr_namebind_t *) pcalloc(server->pool, sizeof(pr_namebind_t));
  namebind->nb_name = name;
  namebind->nb_server = server;
  namebind->nb_isactive = FALSE;

  if (pr_str_is_fnmatch(name) == TRUE) {
    namebind->nb_iswildcard = TRUE;
  }

  pr_trace_msg(trace_channel, 8,
    "created named binding '%s' for %s#%u, server %p", name,
    pr_netaddr_get_ipstr(server->addr), server->ServerPort, server->ServerName);

  /* The given server should already have the following populated:
   *
   *  server->ServerName
   *  server->ServerAddress
   *  server->ServerFQDN
   */

  /* These TCP socket tweaks will not apply to the control connection (it will
   * already have been established by the time this named vhost is used),
   * but WILL apply to any data connections established to this named vhost.
   */

#if 0
  namebind->nb_server->tcp_mss_len = (server->tcp_mss_len ?
    server->tcp_mss_len : main_server->tcp_mss_len);
  namebind->nb_server->tcp_rcvbuf_len = (server->tcp_rcvbuf_len ?
    server->tcp_rcvbuf_len : main_server->tcp_rcvbuf_len);
  namebind->nb_server->tcp_rcvbuf_override = (server->tcp_rcvbuf_override ?
    TRUE : main_server->tcp_rcvbuf_override);
  namebind->nb_server->tcp_sndbuf_len = (server->tcp_sndbuf_len ?
    server->tcp_sndbuf_len : main_server->tcp_sndbuf_len);
  namebind->nb_server->tcp_sndbuf_override = (server->tcp_sndbuf_override ?
    TRUE : main_server->tcp_sndbuf_override);

  /* XXX Shouldn't need these; the ipbind container handles all of the
   * connection (listener, port, addr) stuff.
   */

  namebind->nb_server->addr = (server->addr ? server->addr :
    main_server->addr);
  namebind->nb_server->ServerPort = (server->ServerPort ? server->ServerPort :
    main_server->ServerPort);
  namebind->nb_listener = (server->listen ? server->listen :
    main_server->listen);
#endif

  *((pr_namebind_t **) push_array(ipbind->ib_namebinds)) = namebind;
  return 0;
}

pr_namebind_t *pr_namebind_find(const char *name, const pr_netaddr_t *addr,
    unsigned int port, unsigned char skip_inactive) {
  pr_ipbind_t *ipbind = NULL;
  pr_namebind_t *namebind = NULL;

  if (name == NULL ||
      addr == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* First, find an active ipbind for the given address. */
  ipbind = pr_ipbind_find(addr, port, skip_inactive);
  if (ipbind == NULL) {
    pr_netaddr_t wildcard_addr;
    int addr_family;

    /* If not found, look for the wildcard address. */

    addr_family = pr_netaddr_get_family(addr);
    pr_netaddr_clear(&wildcard_addr);
    pr_netaddr_set_family(&wildcard_addr, addr_family);
    pr_netaddr_set_sockaddr_any(&wildcard_addr);

    ipbind = pr_ipbind_find(&wildcard_addr, port, FALSE);
#ifdef PR_USE_IPV6
    if (ipbind == FALSE &&
        addr_family == AF_INET6 &&
        pr_netaddr_use_ipv6()) {

      /* No IPv6 wildcard address found; try the IPv4 wildcard address. */
      pr_netaddr_clear(&wildcard_addr);
      pr_netaddr_set_family(&wildcard_addr, AF_INET);
      pr_netaddr_set_sockaddr_any(&wildcard_addr);

      ipbind = pr_ipbind_find(&wildcard_addr, port, FALSE);
    }
#endif /* PR_USE_IPV6 */
  } else {
    pr_trace_msg(trace_channel, 17,
      "found ipbind %p (server %p) for %s#%u", ipbind, ipbind->ib_server,
      pr_netaddr_get_ipstr(addr), port);
  }

  if (ipbind == NULL) {
    errno = ENOENT;
    return NULL;
  }

  if (ipbind->ib_namebinds == NULL) {
    pr_trace_msg(trace_channel, 17,
      "ipbind %p (server %p) for %s#%u has no namebinds", ipbind,
      ipbind->ib_server, pr_netaddr_get_ipstr(addr), port);
    return NULL;

  } else {
    register unsigned int i = 0;
    pr_namebind_t **namebinds = (pr_namebind_t **) ipbind->ib_namebinds->elts;

    pr_trace_msg(trace_channel, 17,
      "ipbind %p (server %p) for %s#%u has namebinds (%d)", ipbind,
      ipbind->ib_server, pr_netaddr_get_ipstr(addr), port,
      ipbind->ib_namebinds->nelts);

    for (i = 0; i < ipbind->ib_namebinds->nelts; i++) {
      namebind = namebinds[i];
      if (namebind == NULL) {
        continue;
      }

      /* Skip inactive namebinds */
      if (skip_inactive == TRUE &&
          namebind->nb_isactive == FALSE) {
        pr_trace_msg(trace_channel, 17,
          "namebind #%u: %s is inactive, skipping", i, namebind->nb_name);
        continue;
      }

      /* At present, this looks for an exactly matching name.  In the future,
       * we may want to have something like Apache's matching scheme, which
       * looks for the most specific domain to the most general.  Note that
       * that scheme, however, is specific to DNS; should any other naming
       * scheme be desired, that sort of matching will be unnecessary.
       */
      if (namebind->nb_name != NULL) {
        pr_trace_msg(trace_channel, 17,
          "namebind #%u: %s", i, namebind->nb_name);

        if (namebind->nb_iswildcard == FALSE) {
          if (strcasecmp(namebind->nb_name, name) == 0) {
            return namebind;
          }

        } else {
          int match_flags = PR_FNM_NOESCAPE|PR_FNM_CASEFOLD;

          if (pr_fnmatch(namebind->nb_name, name, match_flags) == 0) {
            pr_trace_msg(trace_channel, 9,
              "matched name '%s' against pattern '%s'", name,
              namebind->nb_name);
            return namebind;
          }

          pr_trace_msg(trace_channel, 9,
            "failed to match name '%s' against pattern '%s'", name,
            namebind->nb_name);
        }
      }
    }
  }

  return NULL;
}

server_rec *pr_namebind_get_server(const char *name, const pr_netaddr_t *addr,
    unsigned int port) {
  pr_namebind_t *namebind = NULL;

  /* Basically, just a wrapper around pr_namebind_find() */

  namebind = pr_namebind_find(name, addr, port, TRUE);
  if (namebind == NULL) {
    return NULL;
  }

  return namebind->nb_server;
}

unsigned int pr_namebind_count(server_rec *srv) {
  unsigned int count = 0;
  pr_ipbind_t *ipbind = NULL;

  if (srv == NULL) {
    return 0;
  }

  ipbind = pr_ipbind_find(srv->addr, srv->ServerPort, FALSE); 
  if (ipbind != NULL &&
      ipbind->ib_namebinds != NULL) {
    count = ipbind->ib_namebinds->nelts; 
  }

  return count;
}

int pr_namebind_open(const char *name, const pr_netaddr_t *addr) {
  pr_namebind_t *namebind = NULL;
  unsigned int port;

  if (name == NULL ||
      addr == NULL) {
    errno = EINVAL;
    return -1;
  }

  port = ntohs(pr_netaddr_get_port(addr));
  namebind = pr_namebind_find(name, addr, port, FALSE);
  if (namebind == NULL) {
    errno = ENOENT;
    return -1;
  }

  namebind->nb_isactive = TRUE;
  return 0;
}

void free_bindings(void) {
  if (binding_pool) {
    destroy_pool(binding_pool);
    binding_pool = NULL;
    listener_list = NULL;
  }

  memset(ipbind_table, 0, sizeof(ipbind_table));

  /* Mark all listening conns as "unclaimed"; any that remaining unclaimed
   * after init_bindings() can be closed.
   */
  if (listening_conn_list) {
    struct listener_rec *lr;

    for (lr = (struct listener_rec *) listening_conn_list->xas_list; lr; lr = lr->next) {
      lr->claimed = FALSE;
    }
  }
}

static int init_inetd_bindings(void) {
  int res = 0;
  server_rec *serv = NULL;
  unsigned char *default_server = NULL, is_default = FALSE;

  /* We explicitly do NOT use the get_listening_conn() function here, since
   * inetd-run daemons will not a) handle restarts, and thus b) will not have
   * already-open connections to choose from.
   */

  main_server->listen = pr_inet_create_conn(main_server->pool, STDIN_FILENO,
    NULL, INPORT_ANY, FALSE);
  if (main_server->listen == NULL) {
    return -1;
  }

  /* Note: Since we are being called via inetd/xinetd, any socket options
   * which may be attempted by listeners for this event may not work.
   */
  pr_inet_generate_socket_event("core.ctrl-listen", main_server,
    main_server->addr, main_server->listen->listen_fd);

  /* Fill in all the important connection information. */
  if (pr_inet_get_conn_info(main_server->listen, STDIN_FILENO) == -1) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "fatal: unable to get connection info: %s",
      strerror(xerrno));

    if (xerrno == ENOTSOCK) {
      pr_log_pri(PR_LOG_ERR, "(Running from command line? "
        "Use `ServerType standalone' in config file!)");
    }

    exit(1);
  }

  default_server = get_param_ptr(main_server->conf, "DefaultServer", FALSE);
  if (default_server != NULL &&
      *default_server == TRUE) {
    is_default = TRUE;
  }

  PR_CREATE_IPBIND(main_server, main_server->addr, main_server->ServerPort);
  PR_OPEN_IPBIND(main_server->addr, main_server->ServerPort,
    main_server->listen, is_default, TRUE, TRUE);
  PR_ADD_IPBINDS(main_server);

  /* Now attach the faked connection to all virtual servers. */
  for (serv = main_server->next; serv; serv = serv->next) {

    /* Because this server is sharing the connection with the
     * main server, we need a cleanup handler to remove
     * the server's reference when the original connection's
     * pool is destroyed.
     */

    serv->listen = main_server->listen;
    register_cleanup(serv->listen->pool, &serv->listen, server_cleanup_cb,
      server_cleanup_cb);

    is_default = FALSE;
    default_server = get_param_ptr(serv->conf, "DefaultServer", FALSE);
    if (default_server != NULL &&
        *default_server == TRUE) {
      is_default = TRUE;
    }

    PR_CREATE_IPBIND(serv, serv->addr, serv->ServerPort);
    PR_OPEN_IPBIND(serv->addr, serv->ServerPort, serv->listen, is_default,
      FALSE, TRUE);
    PR_ADD_IPBINDS(serv);
  }

  return 0;
}

static int init_standalone_bindings(void) {
  int res = 0;
  server_rec *serv = NULL;
  unsigned char *default_server = NULL, is_default = FALSE;

  /* If a port is set to zero, the address/port is not bound to a socket
   * at all.
   */
  if (main_server->ServerPort) {

    /* If SocketBindTight is off, then pr_inet_create_conn() will
     * create and bind to a wildcard socket.  However, should it be an
     * IPv4 or an IPv6 wildcard socket?
     */
    if (!SocketBindTight) {
#ifdef PR_USE_IPV6
      if (pr_netaddr_use_ipv6()) {
        pr_inet_set_default_family(NULL, AF_INET6);

      } else {
        int default_family;

        default_family = pr_netaddr_get_family(main_server->addr);
        pr_inet_set_default_family(NULL, default_family);
      }
#else
      pr_inet_set_default_family(NULL,
        pr_netaddr_get_family(main_server->addr));
#endif /* PR_USE_IPV6 */
    }

    main_server->listen = pr_ipbind_get_listening_conn(main_server,
      (SocketBindTight ? main_server->addr : NULL), main_server->ServerPort);
    if (main_server->listen == NULL) {
      return -1;
    }

  } else {
    main_server->listen = NULL;
  }

  default_server = get_param_ptr(main_server->conf, "DefaultServer", FALSE);
  if (default_server != NULL &&
      *default_server == TRUE) {
    is_default = TRUE;
  }

  if (main_server->ServerPort ||
      is_default) {
    PR_CREATE_IPBIND(main_server, main_server->addr, main_server->ServerPort);
    PR_OPEN_IPBIND(main_server->addr, main_server->ServerPort,
      main_server->listen, is_default, TRUE, TRUE);
    PR_ADD_IPBINDS(main_server);
  }

  for (serv = main_server->next; serv; serv = serv->next) {
    config_rec *c;
    int is_namebind = FALSE;

    /* See if this server is a namebind, to be part of an existing ipbind. */
    c = find_config(serv->conf, CONF_PARAM, "ServerAlias", FALSE);
    while (c != NULL) {
      pr_signals_handle();

      res = pr_namebind_create(serv, c->argv[0], serv->addr, serv->ServerPort);
      if (res == 0) {
        is_namebind = TRUE;

        res = pr_namebind_open(c->argv[0], serv->addr);
        if (res < 0) {
          pr_trace_msg(trace_channel, 2,
            "notice: unable to open namebind '%s': %s", (char *) c->argv[0],
            strerror(errno));
        }

      } else {
        if (errno != ENOENT) {
          pr_trace_msg(trace_channel, 3,
            "unable to create namebind for '%s' to %s#%u: %s",
            (char *) c->argv[0], pr_netaddr_get_ipstr(serv->addr),
            serv->ServerPort, strerror(errno));
        }
      }

      c = find_config_next(c, c->next, CONF_PARAM, "ServerAlias", FALSE);
    }

    if (is_namebind == TRUE) {
      continue;
    }

    if (serv->ServerPort != main_server->ServerPort ||
        SocketBindTight ||
        !main_server->listen) {
      is_default = FALSE;

      default_server = get_param_ptr(serv->conf, "DefaultServer", FALSE);
      if (default_server != NULL &&
          *default_server == TRUE) {
        is_default = TRUE;
      }

      if (serv->ServerPort) {
        if (!SocketBindTight) {
#ifdef PR_USE_IPV6
          if (pr_netaddr_use_ipv6()) {
            pr_inet_set_default_family(NULL, AF_INET6);

          } else {
            pr_inet_set_default_family(NULL, pr_netaddr_get_family(serv->addr));
          }
#else
          pr_inet_set_default_family(NULL, pr_netaddr_get_family(serv->addr));
#endif /* PR_USE_IPV6 */
        }

        serv->listen = pr_ipbind_get_listening_conn(serv,
          (SocketBindTight ? serv->addr : NULL), serv->ServerPort);
        if (serv->listen == NULL) {
          return -1;
        }

        PR_CREATE_IPBIND(serv, serv->addr, serv->ServerPort);
        PR_OPEN_IPBIND(serv->addr, serv->ServerPort, serv->listen, is_default,
          FALSE, TRUE);
        PR_ADD_IPBINDS(serv);

      } else if (is_default) {
        serv->listen = NULL;

        PR_CREATE_IPBIND(serv, serv->addr, serv->ServerPort);
        PR_OPEN_IPBIND(serv->addr, serv->ServerPort, serv->listen, is_default,
          FALSE, TRUE);
        PR_ADD_IPBINDS(serv);

      } else {
        serv->listen = NULL;
      }

    } else {
      /* Because this server is sharing the connection with the main server,
       * we need a cleanup handler to remove the server's reference when the
       * original connection's pool is destroyed.
       */

      is_default = FALSE;
      default_server = get_param_ptr(serv->conf, "DefaultServer", FALSE);
      if (default_server != NULL &&
          *default_server == TRUE) {
        is_default = TRUE;
      }

      serv->listen = main_server->listen;
      register_cleanup(serv->listen->pool, &serv->listen, server_cleanup_cb,
        server_cleanup_cb);

      PR_CREATE_IPBIND(serv, serv->addr, serv->ServerPort);
      PR_OPEN_IPBIND(serv->addr, serv->ServerPort, NULL, is_default, FALSE,
        TRUE);
      PR_ADD_IPBINDS(serv);
    }
  }

  /* Any "unclaimed" listening conns can be removed and closed. */
  if (listening_conn_list) {
    struct listener_rec *lr, *lrn;

    for (lr = (struct listener_rec *) listening_conn_list->xas_list; lr; lr = lrn) {
      lrn = lr->next;

      if (!lr->claimed) {
        xaset_remove(listening_conn_list, (xasetmember_t *) lr);
        destroy_pool(lr->pool);
      }
    }
  }

  return 0;
}

void init_bindings(void) {
  int res = 0;

#ifdef PR_USE_IPV6
  int sock;

  /* Check to see whether we can actually create an IPv6 socket. */
  sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) {
    pr_netaddr_disable_ipv6();

  } else {
    (void) close(sock);
  }
#endif /* PR_USE_IPV6 */

  if (ServerType == SERVER_INETD) {
    res = init_inetd_bindings();

  } else if (ServerType == SERVER_STANDALONE) {
    res = init_standalone_bindings();
  }

  if (res < 0) {
    pr_log_pri(PR_LOG_ERR, "%s",
      "Unable to start proftpd; check logs for more details");
    exit(1);
  }
}

