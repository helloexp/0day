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

/* ProFTPD bindings support routines. */

#ifndef PR_BINDINGS_H
#define PR_BINDINGS_H

#include "conf.h"
#include "pool.h"

/* NOTE: the is* members could possibly become a bitmasked number */

/* Structure associating an IP address to a server_rec */
typedef struct ipbind_rec {
  struct ipbind_rec *ib_next;

  /* IP address to which this binding is "bound" */
  const pr_netaddr_t *ib_addr;
  unsigned int ib_port;

  /* Default server to handle requests to this binding.  If namebinds are
   * present, they will be checked before using this server
   */
  server_rec *ib_server;

  /* Listener associated with this binding.  This listener, and
   * ib_server->listen, are the same listener.  The duplicate locations
   * are necessary for inetd-run servers (at present).
   */
  conn_t *ib_listener;

  /* List of name-based servers bound to the above IP address.  Note that
   * if this functionality becomes widely adopted and used, a more efficient
   * search-and-lookup mechanism will be needed, for performance reasons.
   */
  array_header *ib_namebinds;

  /* If this binding is the DefaultServer binding */
  unsigned char ib_isdefault;

  /* If this binding handles localhost requests */
  unsigned char ib_islocalhost;

  /* If this binding is active */
  unsigned char ib_isactive;

} pr_ipbind_t;

/* Structure associating a name to a server_rec */
typedef struct namebind_rec {
  const char *nb_name;
  unsigned char nb_iswildcard;
  unsigned char nb_isactive;
  server_rec *nb_server;

} pr_namebind_t;

/* Define the size of the hash table used to store server configurations.
 * It needs to be a power of two.
 */
#define PR_BINDINGS_TABLE_SIZE	256

/* Given an fd returned by select(), accept() and return the connt_t structure
 * for the binding associated with that fd.  Returns the conn_t if successful,
 * NULL if not found or if the arguments were NULL.
 */
conn_t *pr_ipbind_accept_conn(fd_set *readfds, int *listenfd);

/* Create a new IP-based binding for the server given, using the provided
 * arguments. The new binding is added the list maintained by the bindings
 * layer.  Returns 0 on success, -1 on failure.
 */
int pr_ipbind_create(server_rec *server, const pr_netaddr_t *addr,
  unsigned int port);

/* Close all IP bindings associated with the given IP address/port combination.
 * The bindings are then marked as inactive, so that future lookups via
 * pr_ipbind_find() skip these bindings.  Returns 0 on success, -1 on failure
 * (eg no associated bindings found).
 */
int pr_ipbind_close(const pr_netaddr_t *addr, unsigned int port,
  unsigned char close_namebinds);

/* Close all listenings fds.  This needs to happen just after a process
 * has been forked to handle a session.
 */
int pr_ipbind_close_listeners(void);

/* Search through the given server's configuration records, and for each
 * associated bind configuration found, create an additional IP binding for
 * that bind address.  Honors SocketBindTight, if set.  Returns 0 on
 * success, -1 on failure (if server == NULL, for example).
 */
int pr_ipbind_add_binds(server_rec *server);

/* Search the binding list, and return the pr_ipbind_t for the given addr and
 * port.  If requested, skip over inactive bindings while searching.
 */
pr_ipbind_t *pr_ipbind_find(const pr_netaddr_t *addr, unsigned int port,
  unsigned char skip_inactive);

/* Iterate through the binding list, returning the next ipbind.  Returns NULL
 * once the end of the list is reached.  If prev is NULL, the iterator
 * restarts at the beginning of the list.
 */
pr_ipbind_t *pr_ipbind_get(pr_ipbind_t *prev);

/* Search the binding list, and return the server_rec * that is bound to the
 * given IP address/port combination.
 */
server_rec *pr_ipbind_get_server(const pr_netaddr_t *addr, unsigned int port);

/* Listens on each file descriptor in the given set, and returns the file
 * descriptor associated with an incoming connection request.  Returns -1
 * on error, as when the fd_set argument is NULL.
 */
int pr_ipbind_listen(fd_set *readfds);

/* Prepares the IP-based binding associated with the given server for listening.
 * Returns 0 on success, -1 on failure.
 */
int pr_ipbind_open(const pr_netaddr_t *addr, unsigned int port,
  conn_t *listen_conn, unsigned char isdefault, unsigned char islocalhost,
  unsigned char open_namebinds);

conn_t *pr_ipbind_get_listening_conn(server_rec *server,
  const pr_netaddr_t *addr, unsigned int port);

/* Close the pr_namebind_t with the given name. */
int pr_namebind_close(const char *name, const pr_netaddr_t *addr);

/* Create a pr_namebind_t, similar to a pr_ipbind_t, which maps the name (usu.
 * DNS hostname) to the server_rec.  The given addr is used to associate this
 * pr_namebind_t with the given IP address (to which the DNS hostname should
 * resolve).
 */
int pr_namebind_create(server_rec *server, const char *name,
  const pr_netaddr_t *addr, unsigned int port);

/* Search the Bindings layer, and return the pr_namebind_t associated with
 * the given addr, port, and name.  If requested, skip over inactive
 * bindings while searching.
 */
pr_namebind_t *pr_namebind_find(const char *name, const pr_netaddr_t *addr,
  unsigned int port, unsigned char skip_inactive);

/* Find the server_rec associated with the given name.  If none are found,
 * default to the server_rec of the containing pr_ipbind_t.
 */
server_rec *pr_namebind_get_server(const char *name, const pr_netaddr_t *addr,
  unsigned int port);

/* Opens the pr_namebind_t with the given name. */
int pr_namebind_open(const char *name, const pr_netaddr_t *addr);

/* Provides a count of the number of namebinds associated with this
 * server_rec.
 */
unsigned int pr_namebind_count(server_rec *);

/* Initialize the Bindings layer. */
void init_bindings(void);

/* Free the Bindings layer. */
void free_bindings(void);

/* Macro error-handling wrappers */
#define PR_ADD_IPBINDS(s) \
  if ((res = pr_ipbind_add_binds((s))) < 0) \
    pr_log_pri(PR_LOG_NOTICE, \
      "%s:%d: notice: unable to add binds to ipbind '%s': %s", \
      __FILE__, __LINE__, (s)->ServerAddress, strerror(errno))

#define PR_CLOSE_IPBIND(a, p, c) \
  if ((res = pr_ipbind_close((a), (p), (c))) < 0) \
    pr_log_pri(PR_LOG_NOTICE, \
      "%s:%d: notice: unable to close ipbind: %s", \
      __FILE__, __LINE__, strerror(errno))

#define PR_CREATE_IPBIND(s, a, p) \
  if ((res = pr_ipbind_create((s), (a), (p))) < 0) \
    pr_log_pri(PR_LOG_NOTICE, \
      "%s:%d: notice: unable to create ipbind '%s#%u': %s", \
      __FILE__, __LINE__, (s)->ServerAddress, (p), strerror(errno))

#define PR_OPEN_IPBIND(a, p, c, d, l, o) \
  if ((res = pr_ipbind_open((a), (p), (c), (d), (l), (o))) < 0) \
    pr_log_pri(PR_LOG_NOTICE, \
      "%s:%d: notice: unable to open ipbind '%s': %s", \
      __FILE__, __LINE__, pr_netaddr_get_ipstr((a)), strerror(errno))

#endif /* PR_BINDINGS_H */
