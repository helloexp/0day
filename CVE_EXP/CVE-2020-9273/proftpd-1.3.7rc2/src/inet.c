/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2019 The ProFTPD Project team
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
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* Inet support functions, many wrappers for netdb functions */

#include "conf.h"
#include "privs.h"

extern unsigned char is_master;
extern server_rec *main_server;

/* A private work pool for all pr_inet_* functions to use. */
static pool *inet_pool = NULL;

static int ip_proto = IPPROTO_IP;
#ifdef PR_USE_IPV6
static int ipv6_proto = IPPROTO_IPV6;
#endif /* PR_USE_IPV6 */
static int tcp_proto = IPPROTO_TCP;

static int inet_errno = 0;		/* Holds errno */

/* The default address family to use when creating a socket, if a pr_netaddr_t
 * is not given.  This is mainly for the benefit of init_conn().
 */
static int inet_family = 0;

static const char *trace_channel = "inet";

/* Called by others after running a number of pr_inet_* functions in order
 * to free up memory.
 */
void pr_inet_clear(void) {
  destroy_pool(inet_pool);
  inet_pool = NULL;
}

/* All inet_ interface functions take a pool as the first arg, which
 * is where any returned allocated memory is taken from.  For purposes
 * of uniformity the pool is included in all calls, even those that
 * don't need to return allocated memory.
 */

int pr_inet_set_default_family(pool *p, int family) {
  int old_family = inet_family;
  inet_family = family;
  return old_family;
}

/* Find a service and return its port number. */
int pr_inet_getservport(pool *p, const char *serv, const char *proto) {
  struct servent *servent;

  servent = getservbyname(serv, proto);
  if (servent == NULL) {
    return -1;
  }

  /* getservbyname returns the port in network byte order. */
  return ntohs(servent->s_port);
}

static void conn_cleanup_cb(void *cv) {
  conn_t *c = (conn_t *) cv;

  /* XXX These closes' return values should be checked, ideally. Do
   * we really care if they fail, though?
   */

  if (c->instrm != NULL) {
    pr_netio_close(c->instrm);
  }

  if (c->outstrm != NULL &&
      c->outstrm != c->instrm) {
    pr_netio_close(c->outstrm);
  }

  /* Set these to NULL only AFTER comparing them with each other, and closing
   * them.  Otherwise, we may try to close the same stream twice.
   */
  c->instrm = c->outstrm = NULL;

  if (c->listen_fd != -1) {
    close(c->listen_fd);
    c->listen_fd = -1;
  }

  if (c->rfd != -1) {
    close(c->rfd);
    c->rfd = -1;
  }

  if (c->wfd != -1) {
    close(c->wfd);
    c->wfd = -1;
  }
}

/* Copy a connection structure, also creates a sub pool for the new
 * connection.
 */
conn_t *pr_inet_copy_conn(pool *p, conn_t *c) {
  conn_t *res = NULL;
  pool *sub_pool = NULL;

  if (p == NULL ||
      c == NULL) {
    errno = EINVAL;
    return NULL;
  }

  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "inet_copy_conn pool");

  res = (conn_t *) pcalloc(sub_pool, sizeof(conn_t));

  memcpy(res, c, sizeof(conn_t));
  res->pool = sub_pool;
  res->instrm = res->outstrm = NULL;

  if (c->local_addr != NULL) {
    pr_netaddr_t *local_addr;

    local_addr = pr_netaddr_alloc(res->pool);

    if (pr_netaddr_set_family(local_addr,
        pr_netaddr_get_family(c->local_addr)) < 0) {
      destroy_pool(res->pool);
      return NULL;
    }

    pr_netaddr_set_sockaddr(local_addr, pr_netaddr_get_sockaddr(c->local_addr));
    res->local_addr = local_addr;
  }

  if (c->remote_addr != NULL) {
    pr_netaddr_t *remote_addr;

    remote_addr = pr_netaddr_alloc(res->pool);

    if (pr_netaddr_set_family(remote_addr,
        pr_netaddr_get_family(c->remote_addr)) < 0) {
      destroy_pool(res->pool);
      return NULL;
    }

    pr_netaddr_set_sockaddr(remote_addr,
      pr_netaddr_get_sockaddr(c->remote_addr));
    res->remote_addr = remote_addr;
  }

  if (c->remote_name) {
    res->remote_name = pstrdup(res->pool, c->remote_name);
  }

  register_cleanup(res->pool, (void *) res, conn_cleanup_cb, conn_cleanup_cb);
  return res;
}

/* Initialize a new connection record, also creates a new subpool just for the
 * new connection.
 */
static conn_t *init_conn(pool *p, int fd, const pr_netaddr_t *bind_addr,
    int port, int retry_bind, int reporting) {
  pool *sub_pool = NULL;
  conn_t *c;
  pr_netaddr_t na;
  int addr_family;
  int res = 0, one = 1, hold_errno;

  if (p == NULL) {
    errno = inet_errno = EINVAL;
    return NULL;
  }

  if (!inet_pool) {
    inet_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(inet_pool, "Inet Pool");
  }

  /* Initialize the netaddr. */
  pr_netaddr_clear(&na);

  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "init_conn pool");

  c = (conn_t *) pcalloc(sub_pool, sizeof(conn_t));
  c->pool = sub_pool;

  c->local_port = port;
  c->rfd = c->wfd = -1;

  if (bind_addr) {
    addr_family = pr_netaddr_get_family(bind_addr);

  } else if (inet_family) {
    addr_family = inet_family;

  } else {

    /* If no default family has been set, then default to IPv6 (if IPv6
     * support is enabled), otherwise use IPv4.
     */
#ifdef PR_USE_IPV6
    if (pr_netaddr_use_ipv6()) {
      addr_family = AF_INET6;

    } else {
      addr_family = AF_INET;
    }
#else
    addr_family = AF_INET;
#endif /* PR_USE_IPV6 */
  }

  /* If fd == -1, there is no currently open socket, so create one.
   */
  if (fd == -1) {
    socklen_t salen;
    register unsigned int i = 0;

    /* Certain versions of Solaris apparently require us to be root
     * in order to create a socket inside a chroot.
     *
     * FreeBSD 2.2.6 (possibly other versions as well), has a security
     * "feature" which disallows SO_REUSEADDR from working if the socket
     * owners don't match.  The easiest thing to do is simply make sure
     * the socket is created as root.  (Note: this "feature" seems to apply
     * to _all_ BSDs.)
     */

    if (port != INPORT_ANY) {
#if defined(SOLARIS2) || defined(FREEBSD2) || defined(FREEBSD3) || \
    defined(FREEBSD4) || defined(FREEBSD5) || defined(FREEBSD6) || \
    defined(FREEBSD7) || defined(FREEBSD8) || defined(FREEBSD9) || \
    defined(FREEBSD10) || defined(FREEBSD11) || \
    defined(__OpenBSD__) || defined(__NetBSD__) || \
    defined(DARWIN6) || defined(DARWIN7) || defined(DARWIN8) || \
    defined(DARWIN9) || defined(DARWIN10) || defined(DARWIN11) || \
    defined(DARWIN12) || defined(DARWIN13) || defined(DARWIN14) || \
    defined(DARWIN15) || defined(DARWIN16) || defined(DARWIN17) || \
    defined(DARWIN18) || \
    defined(SCO3) || defined(CYGWIN) || defined(SYSV4_2MP) || \
    defined(SYSV5SCO_SV6) || defined(SYSV5UNIXWARE7)
# ifdef SOLARIS2
      if (port < 1024) {
# endif
        pr_signals_block();
        PRIVS_ROOT
# ifdef SOLARIS2
      }
# endif
#endif
    }

    fd = socket(addr_family, SOCK_STREAM, tcp_proto);
    inet_errno = errno;

    if (port != INPORT_ANY) {
#if defined(SOLARIS2) || defined(FREEBSD2) || defined(FREEBSD3) || \
    defined(FREEBSD4) || defined(FREEBSD5) || defined(FREEBSD6) || \
    defined(FREEBSD7) || defined(FREEBSD8) || defined(FREEBSD9) || \
    defined(FREEBSD10) || defined(FREEBSD11) || \
    defined(__OpenBSD__) || defined(__NetBSD__) || \
    defined(DARWIN6) || defined(DARWIN7) || defined(DARWIN8) || \
    defined(DARWIN9) || defined(DARWIN10) || defined(DARWIN11) || \
    defined(DARWIN12) || defined(DARWIN13) || defined(DARWIN14) || \
    defined(DARWIN15) || defined(DARWIN16) || defined(DARWIN17) || \
    defined(DARWIN18) || \
    defined(SCO3) || defined(CYGWIN) || defined(SYSV4_2MP) || \
    defined(SYSV5SCO_SV6) || defined(SYSV5UNIXWARE7)
# ifdef SOLARIS2
      if (port < 1024) {
# endif
        PRIVS_RELINQUISH
        pr_signals_unblock();
# ifdef SOLARIS2
      }
# endif
#endif
    }

    if (fd == -1) {
      /* On failure, destroy the connection and return NULL. */
      if (reporting) {
        pr_log_pri(PR_LOG_WARNING,
          "socket() failed in connection initialization: %s",
          strerror(inet_errno));
      }

      destroy_pool(c->pool);
      errno = inet_errno;
      return NULL;
    }

    /* Allow address reuse. */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &one,
        sizeof(one)) < 0) {
      pr_log_pri(PR_LOG_NOTICE, "error setting SO_REUSEADDR: %s",
        strerror(errno));
    }

#ifdef SO_REUSEPORT
    /* Note that we only want to use this socket option if we are NOT the
     * master/parent daemon.  Otherwise, we would allow multiple daemon
     * processes to bind to the same socket, causing unexpected terror
     * and madness (see Issue #622).
     */
    if (!is_master) {
      if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (void *) &one,
          sizeof(one)) < 0) {
        pr_log_pri(PR_LOG_NOTICE, "error setting SO_REUSEPORT: %s",
          strerror(errno));
      }
    }
#endif /* SO_REUSEPORT */

    /* Allow socket keep-alive messages. */
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *) &one,
        sizeof(one)) < 0) {
      pr_log_pri(PR_LOG_NOTICE, "error setting SO_KEEPALIVE: %s",
        strerror(errno));
    }

#if defined(IP_FREEBIND)
    /* Allow binding to an as-yet-nonexistent address. */
    if (setsockopt(fd, SOL_IP, IP_FREEBIND, (void *) &one,
        sizeof(one)) < 0) {
      if (errno != ENOSYS) {
        pr_log_pri(PR_LOG_INFO, "error setting IP_FREEBIND: %s",
          strerror(errno));
      }
    }
#endif /* IP_FREEBIND */

    memset(&na, 0, sizeof(na));
    if (pr_netaddr_set_family(&na, addr_family) < 0) {
      int xerrno = errno;

      destroy_pool(c->pool);
      (void) close(fd);

      errno = xerrno;
      return NULL;
    }

    if (bind_addr) {
      pr_netaddr_set_sockaddr(&na, pr_netaddr_get_sockaddr(bind_addr));

    } else {
      pr_netaddr_set_sockaddr_any(&na);
    }

#if defined(PR_USE_IPV6) && defined(IPV6_V6ONLY)
    if (pr_netaddr_use_ipv6() &&
        addr_family == AF_INET6) {
      int level = ipv6_proto;
      int off;
      socklen_t len = sizeof(off);

      /* If creating a wildcard socket IPv6 socket, make sure that it
       * will accept IPv4 connections as well.  This is the default on
       * Linux and Solaris; BSD usually defaults to allowing only IPv6
       * (depending on the net.inet6.ip6.v6only sysctl value).
       *
       * Ideally, this setsockopt() call would be configurable via the
       * SocketOptions directive.
       */

      if (getsockopt(fd, level, IPV6_V6ONLY, (void *) &off, &len) >= 0) {
        if (off != 0) {
          off = 0;

          pr_trace_msg(trace_channel, 5,
            "disabling IPV6_V6ONLY on server socket %d", fd);

          res = setsockopt(fd, level, IPV6_V6ONLY, (void *) &off, len);

          /* Bug#3237 shows that some systems do NOT like setting the V6ONLY
           * option on an IPv4-mapped IPv6 address.  However, other systems
           * (e.g. FreeBSD) require that this be done in order for EPSV
           * to work properly.  Portability strikes again!
           */

          if (res < 0
#ifdef ENOPROTOOPT
              && errno != ENOPROTOOPT
#endif /* !ENOPROTOOPT */
              ) {
            pr_log_pri(PR_LOG_NOTICE, "error setting IPV6_V6ONLY: %s",
              strerror(errno));
          }
        }

      } else {
        pr_trace_msg(trace_channel, 3,
          "error getting IPV6_V6ONLY setting on socket %d: %s", fd,
          strerror(errno));
      }
    }
#endif /* PR_USE_IPV6 and IPV6_V6ONLY */

    pr_netaddr_set_port(&na, htons(port));

    if (port != INPORT_ANY &&
        port < 1024) {
      pr_signals_block();
      PRIVS_ROOT
    }

    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
      pr_log_pri(PR_LOG_WARNING, "unable to set CLOEXEC on socket fd %d: %s",
        fd, strerror(errno));
    }

    /* According to one expert, the very nature of the FTP protocol, and it's
     * multiple data-connections creates problems with "rapid-fire" connections
     * (transferring lots of files) causing an eventual "Address already in use"
     * error.  As a result, this nasty kludge retries ten times (once per
     * second) if the port being bound to is INPORT_ANY.
     */
    for (i = 10; i; i--) {
      res = bind(fd, pr_netaddr_get_sockaddr(&na),
        pr_netaddr_get_sockaddr_len(&na));
      hold_errno = errno;

      if (res == -1 &&
          hold_errno == EINTR) {
        pr_signals_handle();
        i++;
        continue;
      }

      if (res != -1 ||
        /* Note that on Solaris, bind(2) might fail with EACCES if the
         * randomly selected port for e.g. passive transfers is used by
         * NFS.  Thus, for Solaris only, we treat EACCES as the same as
         * EADDRINUSE.  Silly Solaris.
         */
#ifdef SOLARIS2
          (hold_errno != EADDRINUSE && hold_errno != EACCES) ||
#else
          hold_errno != EADDRINUSE ||
#endif /* SOLARIS2 */
          (port != INPORT_ANY && !retry_bind)) {
        break;
      }

      if (port != INPORT_ANY &&
          port < 1024) {
        PRIVS_RELINQUISH
        pr_signals_unblock();
      }

      pr_timer_sleep(1);

      if (port != INPORT_ANY &&
          port < 1024) {
        pr_signals_block();
        PRIVS_ROOT
      }
    }

    if (res == -1) {
      if (port != INPORT_ANY &&
          port < 1024) {
        PRIVS_RELINQUISH
        pr_signals_unblock();
      }

      if (reporting) {
        pr_log_pri(PR_LOG_ERR, "Failed binding to %s, port %d: %s",
          pr_netaddr_get_ipstr(&na), port, strerror(hold_errno));
        pr_log_pri(PR_LOG_ERR, "Check the ServerType directive to ensure "
          "you are configured correctly");
        pr_log_pri(PR_LOG_ERR, "Check to see if inetd/xinetd, or another "
          "proftpd instance, is already using %s, port %d",
          pr_netaddr_get_ipstr(&na), port);
      }

      inet_errno = hold_errno;
      destroy_pool(c->pool);
      (void) close(fd);

      errno = inet_errno;
      return NULL;
    }

    if (port != INPORT_ANY &&
        port < 1024) {
      PRIVS_RELINQUISH
      pr_signals_unblock();
    }

    /* We use getsockname here because the caller might be binding to
     * INPORT_ANY (0), in which case our port number will be dynamic.
     */

    salen = pr_netaddr_get_sockaddr_len(&na);
    if (getsockname(fd, pr_netaddr_get_sockaddr(&na), &salen) == 0) {
      pr_netaddr_t *local_addr;

      if (c->local_addr != NULL) {
        local_addr = (pr_netaddr_t *) c->local_addr;

      } else {
        local_addr = pr_netaddr_alloc(c->pool);
      }

      pr_netaddr_set_family(local_addr, pr_netaddr_get_family(&na));
      pr_netaddr_set_sockaddr(local_addr, pr_netaddr_get_sockaddr(&na));
      c->local_port = ntohs(pr_netaddr_get_port(&na));

      if (c->local_addr == NULL) {
        c->local_addr = local_addr;
      }

    } else {
      pr_log_debug(DEBUG3, "getsockname error on socket %d: %s", fd,
        strerror(errno));
    }

  } else {
    /* Make sure the netaddr has its address family set. */
    if (pr_netaddr_get_family(&na) == 0) {
      pr_netaddr_set_family(&na, addr_family);
    }
  }

  c->listen_fd = fd;
  register_cleanup(c->pool, (void *) c, conn_cleanup_cb, conn_cleanup_cb);

  pr_trace_msg("binding", 4, "bound address %s, port %d to socket fd %d",
    pr_netaddr_get_ipstr(&na), c->local_port, fd);

  return c;
}

conn_t *pr_inet_create_conn(pool *p, int fd, const pr_netaddr_t *bind_addr,
    int port, int retry_bind) {
  conn_t *c = NULL;

  c = init_conn(p, fd, bind_addr, port, retry_bind, TRUE);
  if (c == NULL) {
    errno = inet_errno;
  }

  return c;
}

/* Attempt to create a connection bound to a given port range, returns NULL
 * if unable to bind to any port in the range.
 */
conn_t *pr_inet_create_conn_portrange(pool *p, const pr_netaddr_t *bind_addr,
    int low_port, int high_port) {
  int range_len, i;
  int *range, *ports;
  int attempt, random_index;
  conn_t *c = NULL;

  if (low_port < 0 ||
      high_port < 0) {
    errno = EINVAL;
    return NULL;
  }

  if (low_port >= high_port) {
    errno = EPERM;
    return NULL;
  }

  /* Make sure the temporary inet work pool exists. */
  if (!inet_pool) {
    inet_pool = make_sub_pool(permanent_pool); 
    pr_pool_tag(inet_pool, "Inet Pool");
  }

  range_len = high_port - low_port + 1;
  range = (int *) pcalloc(inet_pool, range_len * sizeof(int));
  ports = (int *) pcalloc(inet_pool, range_len * sizeof(int));

  i = range_len;
  while (i--) {
    range[i] = low_port + i;
  }

  for (attempt = 3; attempt > 0 && !c; attempt--) {
    for (i = range_len - 1; i >= 0 && !c; i--) {
      /* If this is the first attempt through the range, randomize
       * the order of the port numbers used.
       */
      if (attempt == 3) {
	/* Obtain a random index into the port array range. */
	random_index = (int) ((1.0 * i * rand()) / (RAND_MAX+1.0));

	/* Copy the port at that index into the array from which port
	 * numbers will be selected when calling init_conn().
	 */
	ports[i] = range[random_index];

	/* Move non-selected numbers down so that the next randomly chosen
	 * port will be from the range of as-yet untried ports.
	 */
	while (++random_index <= i) {
	  range[random_index-1] = range[random_index];
        }
      }

      c = init_conn(p, -1, bind_addr, ports[i], FALSE, FALSE);

      if (!c &&
          inet_errno != EADDRINUSE) {
        pr_log_pri(PR_LOG_WARNING, "error initializing connection: %s",
          strerror(inet_errno));
        pr_session_disconnect(NULL, PR_SESS_DISCONNECT_BY_APPLICATION, NULL);
      }
    }
  }

  return c;
}

void pr_inet_close(pool *p, conn_t *c) {
  if (c == NULL) {
    return;
  }

  /* It is not necessary to close the fds or schedule netio streams for
   * removal, because the creator of the connection (either
   * pr_inet_create_conn() or pr_inet_copy_conn() will have registered a pool
   * cleanup handler (conn_cleanup_cb()) which will do all this for us.
   * Simply destroy the pool and all the dirty work gets done.
   */

  if (c->pool != NULL) {
    destroy_pool(c->pool);
    c->pool = NULL;
  }
}

/* Perform shutdown/read on streams */
void pr_inet_lingering_close(pool *p, conn_t *c, long linger) {
  if (c == NULL) {
    return;
  }

  (void) pr_inet_set_block(p, c);

  if (c->outstrm) {
    pr_netio_lingering_close(c->outstrm, linger);
  }

  /* Only close the input stream if it is actually a different stream than
   * the output stream.
   */
  if (c->instrm != c->outstrm) {
    pr_netio_close(c->instrm);
  }

  c->outstrm = NULL;
  c->instrm = NULL;

  destroy_pool(c->pool);
}

/* Similar to a lingering close, perform a lingering abort. */
void pr_inet_lingering_abort(pool *p, conn_t *c, long linger) {
  if (c == NULL) {
    return;
  }

  (void) pr_inet_set_block(p, c);

  if (c->instrm) {
    pr_netio_lingering_abort(c->instrm, linger);
  }

  /* Only close the output stream if it is actually a different stream
   * than the input stream.
   *
   * Note: we do not call pr_netio_lingering_abort() on the input stream
   * since doing so would result in two 426 responses sent; we only
   * want and need one.
   */
  if (c->outstrm != c->instrm) {
    pr_netio_close(c->outstrm);
  }

  c->instrm = NULL;
  c->outstrm = NULL;

  destroy_pool(c->pool);
}

int pr_inet_set_proto_cork(int sockfd, int cork) {
  int res = 0;

  /* Linux defines TCP_CORK; BSD-derived systems (including Mac OSX) use
   * TCP_NOPUSH.
   *
   * Both options work by "corking" the socket, only sending TCP packets
   * if there's enough data for a full packet, otherwise buffering the data
   * to be written.  "Uncorking" the socket should flush out the buffered
   * data.
   */

#if defined(TCP_CORK) || defined(TCP_NOPUSH)
# ifdef SOL_TCP
  int tcp_level = SOL_TCP;
# else
  int tcp_level = tcp_proto;
# endif /* SOL_TCP */
#endif /* TCP_CORK or TCP_NOPUSH */

#if defined(TCP_CORK)
  res = setsockopt(sockfd, tcp_level, TCP_CORK, (void *) &cork, sizeof(cork));
  
#elif defined(TCP_NOPUSH)
  res = setsockopt(sockfd, tcp_level, TCP_NOPUSH, (void *) &cork, sizeof(cork));
#endif

  return res;
}

int pr_inet_set_proto_nodelay(pool *p, conn_t *conn, int nodelay) {

#if defined(TCP_NODELAY)
  int res = 0;
# ifdef SOL_TCP
  int tcp_level = SOL_TCP;
# else
  int tcp_level = tcp_proto;
# endif /* SOL_TCP */

  if (conn == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (conn->rfd != -1) {
    res = setsockopt(conn->rfd, tcp_level, TCP_NODELAY, (void *) &nodelay,
      sizeof(nodelay));
    if (res < 0 &&
        errno != EBADF) {
      pr_log_pri(PR_LOG_NOTICE, "error setting read fd %d TCP_NODELAY %d: %s",
       conn->rfd, nodelay, strerror(errno));
    }
  }

  if (conn->wfd != -1) {
    res = setsockopt(conn->wfd, tcp_level, TCP_NODELAY, (void *) &nodelay,
      sizeof(nodelay));
    if (res < 0 &&
        errno != EBADF &&
        errno != EINVAL) {
      pr_log_pri(PR_LOG_NOTICE, "error setting write fd %d TCP_NODELAY %d: %s",
       conn->wfd, nodelay, strerror(errno));
    }
  }
#endif

  return 0;
}

int pr_inet_set_proto_opts(pool *p, conn_t *c, int mss, int nodelay,
    int tos, int nopush) {

  /* More portability fun.  Traditional BSD-style sockets want the value from
   * getprotobyname() in the setsockopt(2) call; Linux wants SOL_TCP for
   * these options.  Also, *BSD want IPPROTO_IP for IP_TOS options, Linux
   * wants SOL_IP.  How many other platforms will have variations?  Will
   * networking code always be this fragmented?
   */
#ifdef SOL_IP
  int ip_level = SOL_IP;
#else
  int ip_level = ip_proto;
#endif /* SOL_IP */

#ifdef SOL_TCP
  int tcp_level = SOL_TCP;
#else
  int tcp_level = tcp_proto;
#endif /* SOL_TCP */
  unsigned char *no_delay = NULL;

  /* Some of these setsockopt() calls may fail when they operate on IPv6
   * sockets, rather than on IPv4 sockets.
   */

  if (c == NULL) {
    errno = EINVAL;
    return -1;
  }

#ifdef TCP_NODELAY

  /* Note: main_server might be null when those code runs in the testsuite. */
  if (main_server != NULL) {
    no_delay = get_param_ptr(main_server->conf, "TCPNoDelay", FALSE);
  }

  if (no_delay == NULL ||
      *no_delay == TRUE) {
    if (c->rfd != -1) {
      if (setsockopt(c->rfd, tcp_level, TCP_NODELAY, (void *) &nodelay,
          sizeof(nodelay)) < 0) {
        if (errno != EBADF) {
          pr_log_pri(PR_LOG_NOTICE, "error setting read fd %d TCP_NODELAY: %s",
            c->rfd, strerror(errno));
        }
      }
    }

    if (c->wfd != -1) {
      if (setsockopt(c->wfd, tcp_level, TCP_NODELAY, (void *) &nodelay,
          sizeof(nodelay)) < 0) {
        if (errno != EBADF) {
          pr_log_pri(PR_LOG_NOTICE, "error setting write fd %d TCP_NODELAY: %s",
            c->wfd, strerror(errno));
        }
      }
    }

    if (c->listen_fd != -1) {
      if (setsockopt(c->listen_fd, tcp_level, TCP_NODELAY, (void *) &nodelay,
          sizeof(nodelay)) < 0) {
        if (errno != EBADF) {
          pr_log_pri(PR_LOG_NOTICE,
            "error setting listen fd %d TCP_NODELAY: %s",
            c->listen_fd, strerror(errno));
        }
      }
    }
  }
#endif /* TCP_NODELAY */

#ifdef TCP_MAXSEG
  if (c->listen_fd != -1 &&
      mss > 0) {
    if (setsockopt(c->listen_fd, tcp_level, TCP_MAXSEG, &mss,
        sizeof(mss)) < 0) {
      pr_log_pri(PR_LOG_NOTICE, "error setting listen fd TCP_MAXSEG(%d): %s",
        mss, strerror(errno));
    }
  }
#endif /* TCP_MAXSEG */

#ifdef IP_TOS
  /* Only set TOS flags on IPv4 sockets; IPv6 sockets use TCLASS. */
  if (pr_netaddr_get_family(c->local_addr) == AF_INET) {
    if (c->listen_fd != -1) {
      if (setsockopt(c->listen_fd, ip_level, IP_TOS, (void *) &tos,
          sizeof(tos)) < 0) {
        pr_log_pri(PR_LOG_NOTICE, "error setting listen fd IP_TOS: %s",
          strerror(errno));
      }
    }
  }
#endif /* IP_TOS */

#if defined(PR_USE_IPV6) && defined(IPV6_TCLASS)
  if (pr_netaddr_use_ipv6()) {
    /* Only set TCLASS flags on IPv6 sockets; IPv4 sockets use TOS. */
    if (pr_netaddr_get_family(c->local_addr) == AF_INET6) {
      if (c->listen_fd != -1) {
        int level, res;

        level = ipv6_proto;
        res = setsockopt(c->listen_fd, level, IPV6_TCLASS, (void *) &tos,
          sizeof(tos));
        if (res < 0
            && errno != EINVAL
#ifdef ENOPROTOOPT
            && errno != ENOPROTOOPT
#endif /* !ENOPROTOOPT */
          ) {
          pr_log_pri(PR_LOG_NOTICE, "error setting listen fd IPV6_TCLASS: %s",
            strerror(errno));
        }
      }
    }
  }
#endif /* IPV6_TCLASS */

  if (c->listen_fd != -1) {
    if (pr_inet_set_proto_cork(c->listen_fd, nopush) < 0) {
      pr_log_pri(PR_LOG_NOTICE, "error corking listen fd %d: %s", c->listen_fd,
        strerror(errno));
    }
  }

  return 0;
}

/* Set socket options on a connection.  */
int pr_inet_set_socket_opts(pool *p, conn_t *c, int rcvbuf, int sndbuf,
    struct tcp_keepalive *tcp_keepalive) {

  if (c == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Linux and "most" newer networking OSes probably use a highly adaptive
   * window size system, which generally wouldn't require user-space
   * modification at all.  Thus, check the current sndbuf and rcvbuf sizes
   * before changing them, and only change them if we are making them larger
   * than their current size.
   */

  if (c->listen_fd != -1) {
    int keepalive = 1;
    int crcvbuf = 0, csndbuf = 0;
    socklen_t len;

    if (tcp_keepalive != NULL) {
      keepalive = tcp_keepalive->keepalive_enabled;
    }

    if (setsockopt(c->listen_fd, SOL_SOCKET, SO_KEEPALIVE, (void *)
        &keepalive, sizeof(int)) < 0) {
      pr_log_pri(PR_LOG_NOTICE, "error setting listen fd SO_KEEPALIVE: %s",
        strerror(errno));

    } else {
      /* We only try to set the TCP keepalive specifics if SO_KEEPALIVE was
       * set successfully.
       */
      pr_trace_msg(trace_channel, 15,
        "enabled SO_KEEPALIVE on socket fd %d", c->listen_fd);

      if (tcp_keepalive != NULL) {
        int val = 0;

#ifdef TCP_KEEPIDLE
        val = tcp_keepalive->keepalive_idle;
        if (val != -1) {
# ifdef __DragonFly__
          /* DragonFly BSD uses millsecs as the KEEPIDLE unit. */
          val *= 1000;
# endif /* DragonFly BSD */
          if (setsockopt(c->listen_fd, SOL_SOCKET, TCP_KEEPIDLE, (void *)
              &val, sizeof(int)) < 0) {
            pr_log_pri(PR_LOG_NOTICE,
              "error setting TCP_KEEPIDLE %d on fd %d: %s", val, c->listen_fd,
              strerror(errno));

          } else {
            pr_trace_msg(trace_channel, 15,
              "enabled TCP_KEEPIDLE %d on socket fd %d", val, c->listen_fd);
          }
        }
#endif /* TCP_KEEPIDLE */

#ifdef TCP_KEEPCNT
        val = tcp_keepalive->keepalive_count;
        if (val != -1) {
          if (setsockopt(c->listen_fd, SOL_SOCKET, TCP_KEEPCNT, (void *)
              &val, sizeof(int)) < 0) {
            pr_log_pri(PR_LOG_NOTICE,
              "error setting TCP_KEEPCNT %d on fd %d: %s", val, c->listen_fd,
              strerror(errno));

          } else {
            pr_trace_msg(trace_channel, 15,
              "enabled TCP_KEEPCNT %d on socket fd %d", val, c->listen_fd);
          }
        }
#endif /* TCP_KEEPCNT */

#ifdef TCP_KEEPINTVL
        val = tcp_keepalive->keepalive_intvl;
        if (val != -1) {
# ifdef __DragonFly__
          /* DragonFly BSD uses millsecs as the KEEPINTVL unit. */
          val *= 1000;
# endif /* DragonFly BSD */
          if (setsockopt(c->listen_fd, SOL_SOCKET, TCP_KEEPINTVL, (void *)
              &val, sizeof(int)) < 0) {
            pr_log_pri(PR_LOG_NOTICE,
              "error setting TCP_KEEPINTVL %d on fd %d: %s", val, c->listen_fd,
              strerror(errno));

          } else {
            pr_trace_msg(trace_channel, 15,
              "enabled TCP_KEEPINTVL %d on socket fd %d", val, c->listen_fd);
          }
        }
#endif /* TCP_KEEPINTVL */

        /* Avoid compiler warnings on platforms which do not support any
         * of the above TCP keepalive macros.
         */
        (void) val;
      }
    }

    if (sndbuf > 0) {
      len = sizeof(csndbuf);
      if (getsockopt(c->listen_fd, SOL_SOCKET, SO_SNDBUF, (void *) &csndbuf,
          &len) == 0) {
        if (sndbuf > csndbuf) {
          if (setsockopt(c->listen_fd, SOL_SOCKET, SO_SNDBUF, (void *) &sndbuf,
              sizeof(sndbuf)) < 0) {
            pr_log_pri(PR_LOG_NOTICE, "error setting listen fd SO_SNDBUF: %s",
              strerror(errno));

          } else {
            pr_trace_msg("data", 8,
              "set socket sndbuf of %lu bytes", (unsigned long) sndbuf);
          }

        } else {
          pr_trace_msg("data", 8,
            "socket %d has sndbuf of %lu bytes, ignoring "
            "requested %lu bytes sndbuf", c->listen_fd, (unsigned long) csndbuf,
            (unsigned long) sndbuf);
        }

      } else {
        pr_trace_msg("data", 3,
          "error getting SO_SNDBUF on listen fd %d: %s", c->listen_fd,
          strerror(errno));
      }
    }

    c->sndbuf = (sndbuf ? sndbuf : csndbuf);

    if (rcvbuf > 0) {
      len = sizeof(crcvbuf);
      if (getsockopt(c->listen_fd, SOL_SOCKET, SO_RCVBUF, (void *) &crcvbuf,
          &len) == 0) {
        if (rcvbuf > crcvbuf) {
          if (setsockopt(c->listen_fd, SOL_SOCKET, SO_RCVBUF, (void *) &rcvbuf,
              sizeof(rcvbuf)) < 0) {
            pr_log_pri(PR_LOG_NOTICE, "error setting listen fd SO_RCVFBUF: %s",
              strerror(errno));

          } else {
            pr_trace_msg("data", 8,
              "set socket rcvbuf of %lu bytes", (unsigned long) rcvbuf);
          }

        } else {
          pr_trace_msg("data", 8,
           "socket %d has rcvbuf of %lu bytes, ignoring "
            "requested %lu bytes rcvbuf", c->listen_fd, (unsigned long) crcvbuf,
            (unsigned long) rcvbuf);
        }

      } else {
        pr_trace_msg("data", 3,
          "error getting SO_RCVBUF on listen fd %d: %s", c->listen_fd,
          strerror(errno));
      }
    }

    c->rcvbuf = (rcvbuf ? rcvbuf : crcvbuf);
  }

  return 0;
}

#ifdef SO_OOBINLINE
static void set_oobinline(int fd) {
  int on = 1;
  if (fd >= 0) {
    if (setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, (void*)&on, sizeof(on)) < 0) {
      pr_log_pri(PR_LOG_NOTICE, "error setting SO_OOBINLINE: %s",
        strerror(errno));
    }
  }
}
#endif

#ifdef F_SETOWN
static void set_socket_owner(int fd) {
  if (fd >= 0) {
    pid_t pid;

    pid = session.pid ? session.pid : getpid();
    if (fcntl(fd, F_SETOWN, pid) < 0) {
      pr_trace_msg(trace_channel, 3,
        "failed to SETOWN PID %lu on socket fd %d: %s", (unsigned long) pid,
        fd, strerror(errno));
    }
  }
}
#endif

/* Put a socket in async mode (so SIGURG is raised on OOB)
 */
int pr_inet_set_async(pool *p, conn_t *c) {
  if (p == NULL ||
      c == NULL) {
    errno = EINVAL;
    return -1;
  }

#ifdef SO_OOBINLINE
  pr_trace_msg(trace_channel, 7,
    "setting SO_OOBINLINE for listening socket %d", c->listen_fd);
  set_oobinline(c->listen_fd);

  pr_trace_msg(trace_channel, 7,
    "setting SO_OOBINLINE for reading socket %d", c->rfd);
  set_oobinline(c->rfd);

  pr_trace_msg(trace_channel, 7,
    "setting SO_OOBINLINE for writing socket %d", c->wfd);
  set_oobinline(c->wfd);
#endif

#ifdef F_SETOWN
  set_socket_owner(c->listen_fd);
  set_socket_owner(c->rfd);
  set_socket_owner(c->wfd);
#endif

  return 0;
}

/* Put a socket in nonblocking mode.
 */
int pr_inet_set_nonblock(pool *p, conn_t *c) {
  int flags;
  int res = -1;

  (void) p;

  if (c == NULL) {
    errno = EINVAL;
    return -1;
  }

  errno = EBADF;		/* Default */

  if (c->mode == CM_LISTEN ||
      c->mode == CM_CONNECT) {
    flags = fcntl(c->listen_fd, F_GETFL);
    if (flags >= 0) {
      res = fcntl(c->listen_fd, F_SETFL, flags|O_NONBLOCK);

    } else {
      res = flags;
    }

  } else {
    if (c->rfd != -1) {
      flags = fcntl(c->rfd, F_GETFL);
      if (flags >= 0) {
        res = fcntl(c->rfd, F_SETFL, flags|O_NONBLOCK);

      } else {
        res = flags;
      }
    }

    if (c->wfd != -1) {
      flags = fcntl(c->wfd, F_GETFL);
      if (flags >= 0) {
        res = fcntl(c->wfd, F_SETFL, flags|O_NONBLOCK);

      } else {
        res = flags;
      }
    }
  }

  return res;
}

int pr_inet_set_block(pool *p, conn_t *c) {
  int flags;
  int res = -1;

  (void) p;

  if (c == NULL) {
    errno = EINVAL;
    return -1;
  }

  errno = EBADF;		/* Default */

  if (c->mode == CM_LISTEN ||
      c->mode == CM_CONNECT) {
    flags = fcntl(c->listen_fd, F_GETFL);
    if (flags >= 0) {
      res = fcntl(c->listen_fd, F_SETFL, flags & (U32BITS ^ O_NONBLOCK));

    } else {
      res = flags;
    }

  } else {
    if (c->rfd != -1) {
      flags = fcntl(c->rfd, F_GETFL);
      if (flags >= 0) {
        res = fcntl(c->rfd, F_SETFL, flags & (U32BITS ^ O_NONBLOCK));

      } else {
        res = flags;
      }
    }

    if (c->wfd != -1) {
      flags = fcntl(c->wfd, F_GETFL);
      if (flags >= 0) {
        res = fcntl(c->wfd, F_SETFL, flags & (U32BITS ^ O_NONBLOCK));

      } else {
        res = flags;
      }
    }
  }

  return res;
}

/* Put a connection in listen mode */
int pr_inet_listen(pool *p, conn_t *c, int backlog, int flags) {
  if (c == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (c->mode == CM_LISTEN) {
    errno = EPERM;
    return -1;
  }

  while (TRUE) {
    if (listen(c->listen_fd, backlog) < 0) {
      int xerrno = errno;

      if (xerrno == EINTR) {
        pr_signals_handle();
        continue;
      }

      pr_log_pri(PR_LOG_ERR, "unable to listen on %s#%u: %s",
        pr_netaddr_get_ipstr(c->local_addr), c->local_port, strerror(xerrno));

      if (flags & PR_INET_LISTEN_FL_FATAL_ON_ERROR) {
        pr_session_disconnect(NULL, PR_SESS_DISCONNECT_BY_APPLICATION, NULL);
      }

      errno = xerrno;
      return -1;
    }

    break;
  }

  c->mode = CM_LISTEN;
  return 0;
}

/* Reset a connection back to listen mode.  Enables blocking mode
 * for safety.
 */
int pr_inet_resetlisten(pool *p, conn_t *c) {
  if (c == NULL) {
    errno = EINVAL;
    return -1;
  }

  c->mode = CM_LISTEN;
  if (pr_inet_set_block(c->pool, c) < 0) {
    c->xerrno = errno;
    return -1;
  }

  return 0;
}

int pr_inet_connect(pool *p, conn_t *c, const pr_netaddr_t *addr, int port) {
  pr_netaddr_t remote_na;
  int res = 0;

  if (c == NULL ||
      addr == NULL) {
    errno = EINVAL;
    return -1;
  }

  c->mode = CM_CONNECT;
  if (pr_inet_set_block(p, c) < 0) {
    c->mode = CM_ERROR;
    c->xerrno = errno;
    return -1;
  }

  /* No need to initialize the remote_na netaddr here, as we're directly
   * copying the data from the given netaddr into that memory area.
   */

  memcpy(&remote_na, addr, sizeof(remote_na));
  pr_netaddr_set_port(&remote_na, htons(port));

  while (TRUE) {
    res = connect(c->listen_fd, pr_netaddr_get_sockaddr(&remote_na),
      pr_netaddr_get_sockaddr_len(&remote_na));
    if (res < 0 &&
        errno == EINTR) {
      pr_signals_handle();
      continue;
    }

    break;
  }

  if (res < 0) {
    c->mode = CM_ERROR;
    c->xerrno = errno;
    return -1;
  }

  c->mode = CM_OPEN;

  if (pr_inet_get_conn_info(c, c->listen_fd) < 0) {
    c->mode = CM_ERROR;
    c->xerrno = errno;
    return -1;
  }

  return 1;
}

/* Attempt to connect a connection, returning immediately with 1 if connected,
 * 0 if not connected, or -1 if error.  Only needs to be called once, and can
 * then be selected for writing.
 */
int pr_inet_connect_nowait(pool *p, conn_t *c, const pr_netaddr_t *addr,
    int port) {
  pr_netaddr_t remote_na;

  if (c == NULL ||
      addr == NULL) {
    errno = EINVAL;
    return -1;
  }

  c->mode = CM_CONNECT;
  if (pr_inet_set_nonblock(p, c) < 0) {
    c->mode = CM_ERROR;
    c->xerrno = errno;
    return -1;
  }

  /* No need to initialize the remote_na netaddr here, as we're directly
   * copying the data from the given netaddr into that memory area.
   */

  memcpy(&remote_na, addr, sizeof(remote_na));
  pr_netaddr_set_port(&remote_na, htons(port));

  if (connect(c->listen_fd, pr_netaddr_get_sockaddr(&remote_na),
      pr_netaddr_get_sockaddr_len(&remote_na)) == -1) {
    if (errno != EINPROGRESS &&
        errno != EALREADY) {
      c->mode = CM_ERROR;
      c->xerrno = errno;

      (void) pr_inet_set_block(c->pool, c);

      errno = c->xerrno;
      return -1;
    }

    return 0;
  }

  c->mode = CM_OPEN;

  if (pr_inet_get_conn_info(c, c->listen_fd) < 0) {
    c->xerrno = errno;

    (void) pr_inet_set_block(c->pool, c);
    errno = c->xerrno;
    return -1;
  }

  if (pr_inet_set_block(c->pool, c) < 0) {
    c->xerrno = errno;
    return -1;
  }

  return 1;
}

/* Accepts a new connection, returning immediately with -1 if no connection is
 * available.  If a connection is accepted, creating a new conn_t and potential
 * resolving is deferred, and a normal socket fd is returned for the new
 * connection, which can later be used in pr_inet_openrw() to fully open and
 * resolve addresses.
 */
int pr_inet_accept_nowait(pool *p, conn_t *c) {
  int fd;

  if (c == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (c->mode == CM_LISTEN) {
    if (pr_inet_set_nonblock(c->pool, c) < 0) {
      if (errno != EBADF) {
        pr_trace_msg(trace_channel, 3,
          "error making connection nonblocking: %s", strerror(errno));
      }
    }
  }

  /* A directive could enforce only IPv4 or IPv6 connections here, by
   * actually using a sockaddr argument to accept(2), and checking the
   * family of the connecting entity.
   */

  c->mode = CM_ACCEPT;
  while (TRUE) {
    pr_signals_handle();
    fd = accept(c->listen_fd, NULL, NULL);

    if (fd == -1) {
      if (errno == EINTR) {
        continue;
      }

      if (errno != EWOULDBLOCK) {
        c->mode = CM_ERROR;
        c->xerrno = errno;
        return -1;
      }

      c->mode = CM_LISTEN;
      c->xerrno = 0;
      return -1;
    }

    break;
  }

  /* Leave the connection in CM_ACCEPT mode, so others can see
   * our state.  Re-enable blocking mode, however.
   */
  if (pr_inet_set_block(c->pool, c) < 0) {
    if (errno != EBADF) {
      pr_trace_msg(trace_channel, 3,
        "error making connection blocking: %s", strerror(errno));
    }
  }

  return fd;
}

/* Accepts a new connection, cloning the existing conn_t and returning
 * it, or NULL upon error.
 */
conn_t *pr_inet_accept(pool *p, conn_t *d, conn_t *c, int rfd, int wfd,
    unsigned char resolve) {
  conn_t *res = NULL;
  unsigned char *foreign_addr = NULL;
  int fd = -1, allow_foreign_address = FALSE;
  pr_netaddr_t na;
  socklen_t nalen;

  if (c == NULL ||
      d == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* Initialize the netaddr. */
  pr_netaddr_clear(&na);

  pr_netaddr_set_family(&na, pr_netaddr_get_family(c->remote_addr));
  nalen = pr_netaddr_get_sockaddr_len(&na);

  d->mode = CM_ACCEPT;

  foreign_addr = get_param_ptr(TOPLEVEL_CONF, "AllowForeignAddress", FALSE);
  if (foreign_addr != NULL) {
    allow_foreign_address = *foreign_addr;
  }

  /* A directive could enforce only IPv4 or IPv6 connections here, by
   * actually using a sockaddr argument to accept(2), and checking the
   * family of the connecting entity.
   */

  while (TRUE) {
    pr_signals_handle();

    fd = accept(d->listen_fd, pr_netaddr_get_sockaddr(&na), &nalen);
    if (fd < 0) {
      if (errno == EINTR) {
        continue;
      }

      d->mode = CM_ERROR;
      d->xerrno = errno;
      break;
    }

    if (allow_foreign_address == FALSE) {
      /* If foreign addresses (i.e. IP addresses that do not match the
       * control connection's remote IP address) are not allowed, we
       * need to see just what our remote address IS.
       */
      if (getpeername(fd, pr_netaddr_get_sockaddr(&na), &nalen) < 0) {
        /* If getpeername(2) fails, should we still allow this connection?
         * Caution (and the AllowForeignAddress setting say "no".
         */
        pr_log_pri(PR_LOG_DEBUG, "rejecting passive connection; "
          "failed to get address of remote peer: %s", strerror(errno));
        (void) close(fd);
        continue;
      }

      if (pr_netaddr_cmp(&na, c->remote_addr) != 0) {
        pr_log_pri(PR_LOG_NOTICE, "SECURITY VIOLATION: Passive connection "
          "from foreign IP address %s rejected (does not match client "
          "IP address %s).", pr_netaddr_get_ipstr(&na),
          pr_netaddr_get_ipstr(c->remote_addr));
        (void) close(fd);
        continue;
      }
    }

    d->mode = CM_OPEN;
    res = pr_inet_openrw(p, d, NULL, PR_NETIO_STRM_DATA, fd, rfd, wfd,
      resolve);

    break;
  }

  return res;
}

int pr_inet_get_conn_info(conn_t *c, int fd) {
  pr_netaddr_t na;
  socklen_t nalen;

  if (c == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (fd < 0) {
    errno = EBADF;
    return -1;
  }

  /* Initialize the netaddr. */
  pr_netaddr_clear(&na);

#ifdef PR_USE_IPV6
  if (pr_netaddr_use_ipv6()) {
    pr_netaddr_set_family(&na, AF_INET6);

  } else {
    pr_netaddr_set_family(&na, AF_INET);
  }
#else
  pr_netaddr_set_family(&na, AF_INET);
#endif /* PR_USE_IPV6 */
  nalen = pr_netaddr_get_sockaddr_len(&na);

  if (getsockname(fd, pr_netaddr_get_sockaddr(&na), &nalen) == 0) {
    pr_netaddr_t *local_addr;

    if (c->local_addr != NULL) {
      local_addr = (pr_netaddr_t *) c->local_addr;

    } else {
      local_addr = pr_netaddr_alloc(c->pool);
    }

    /* getsockname(2) will read the local socket information into the struct
     * sockaddr * given.  Which means that the address family of the local
     * socket can be found in struct sockaddr *->sa_family, and not (yet)
     * via pr_netaddr_get_family().
     */
    pr_netaddr_set_family(local_addr, pr_netaddr_get_sockaddr(&na)->sa_family);
    pr_netaddr_set_sockaddr(local_addr, pr_netaddr_get_sockaddr(&na));
    c->local_port = ntohs(pr_netaddr_get_port(&na));

    if (c->local_addr == NULL) {
      c->local_addr = local_addr;
    }

  } else {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "getsockname(2) error on fd %d: %s", fd, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* "Reset" the pr_netaddr_t struct for the getpeername(2) call. */
#ifdef PR_USE_IPV6
  if (pr_netaddr_use_ipv6()) {
    pr_netaddr_set_family(&na, AF_INET6);

  } else {
    pr_netaddr_set_family(&na, AF_INET);
  }
#else
  pr_netaddr_set_family(&na, AF_INET);
#endif /* PR_USE_IPV6 */
  nalen = pr_netaddr_get_sockaddr_len(&na);

  if (getpeername(fd, pr_netaddr_get_sockaddr(&na), &nalen) == 0) {
    /* Handle IPv4-mapped IPv6 peers as IPv4 peers (Bug#2196). */
    if (pr_netaddr_is_v4mappedv6(&na) == TRUE) {
      c->remote_addr = pr_netaddr_v6tov4(c->pool, &na);

    } else {
      pr_netaddr_t *remote_addr;

      remote_addr = pr_netaddr_alloc(c->pool);

      pr_netaddr_set_family(remote_addr,
        pr_netaddr_get_sockaddr(&na)->sa_family);
      pr_netaddr_set_sockaddr(remote_addr, pr_netaddr_get_sockaddr(&na));

      c->remote_addr = remote_addr;
    }

    c->remote_port = ntohs(pr_netaddr_get_port(&na));

  } else {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "getpeername(2) error on fd %d: %s", fd, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

/* Open streams for a new socket. If rfd and wfd != -1, two new fds are duped
 * to the respective read/write fds. If the fds specified correspond to the
 * normal stdin and stdout, the streams opened will be assigned to stdin and
 * stdout in an intuitive fashion (so that they may be later be used by
 * printf/fgets type libc functions).  If inaddr is non-NULL, the address is
 * assigned to the connection (as the *source* of the connection).  If it is
 * NULL, remote address discovery will be attempted.  The connection structure
 * appropriate fields are filled in, including the *destination* address.
 * Finally, if resolve is non-zero, this function will attempt to reverse
 * resolve the remote address.  A new connection structure is created in the
 * specified pool.
 *
 * Important, do not call any log_* functions from inside of pr_inet_openrw()
 * or any functions it calls, as the possibility for fd overwriting occurs.
 */
conn_t *pr_inet_openrw(pool *p, conn_t *c, const pr_netaddr_t *addr,
    int strm_type, int fd, int rfd, int wfd, int resolve) {
  conn_t *res = NULL;
  int close_fd = TRUE;

  res = pr_inet_copy_conn(p, c);
  if (res == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "error copying connection: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  res->listen_fd = -1;

  /* Note: there are some cases where the given file descriptor will
   * intentionally be bad (e.g. in get_ident() lookups).  In this case,
   * errno will have a value of EBADF; this is an "acceptable" error.  Any
   * other errno value constitutes an unacceptable error.
   */
  if (pr_inet_get_conn_info(res, fd) < 0 &&
      errno != EBADF) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "error getting info for connection on fd %d: %s", fd, strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  if (addr != NULL) {
    if (res->remote_addr == NULL) {
      res->remote_addr = pr_netaddr_dup(res->pool, addr);
    }
  }

  if (resolve == TRUE &&
      res->remote_addr != NULL) {
    res->remote_name = pr_netaddr_get_dnsstr(res->remote_addr);
  }

  if (res->remote_name == NULL) {
    res->remote_name = pr_netaddr_get_ipstr(res->remote_addr);
    if (res->remote_name == NULL) {
      int xerrno = errno;

      /* If we can't even get the IP address as a string, then something
       * is very wrong, and we should not continue to handle this connection.
       */

      pr_trace_msg(trace_channel, 3,
        "error getting IP address for client: %s", strerror(xerrno));
 
      errno = xerrno;
      return NULL;
    }
  }

  if (fd == -1 &&
      c->listen_fd != -1) {
    fd = c->listen_fd;
  }

  if (rfd > -1) {
    if (fd != rfd) {
      dup2(fd, rfd);

    } else {
      close_fd = FALSE;
    }

  } else {
    /* dup(2) cannot take a negative value. */
    if (fd >= 0) {
      rfd = dup(fd);
    }
  }

  if (wfd > -1) {
    if (fd != wfd) {
      if (wfd == STDOUT_FILENO) {
        fflush(stdout);
      }

      dup2(fd, wfd);

    } else {
      close_fd = FALSE;
    }

  } else {
    /* dup(2) cannot take a negative value. */
    if (fd >= 0) {
      wfd = dup(fd);
    }
  }

  /* Now discard the original socket */
  if (rfd > -1 &&
      wfd > -1 &&
      close_fd) {
    (void) close(fd);
  }

  res->rfd = rfd;
  res->wfd = wfd;

  res->instrm = pr_netio_open(res->pool, strm_type, res->rfd, PR_NETIO_IO_RD);
  res->outstrm = pr_netio_open(res->pool, strm_type, res->wfd, PR_NETIO_IO_WR);

  /* Set options on the sockets. */
  pr_inet_set_socket_opts(res->pool, res, 0, 0, NULL);
  (void) pr_inet_set_block(res->pool, res);

  res->mode = CM_OPEN;

#if defined(HAVE_STROPTS_H) && defined(I_SRDOPT) && defined(RPROTDIS) && \
    (defined(SOLARIS2_9) || defined(SOLARIS2_10))
  /* This is needed to work around control messages in STREAMS devices
   * (as on Solaris 9/NFS).  The underlying issue is reported to be fixed
   * in Solaris 11.
   */
  while (ioctl(res->rfd, I_SRDOPT, RPROTDIS) < 0) {
    if (errno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_log_pri(PR_LOG_WARNING, "error calling ioctl(RPROTDIS): %s", 
      strerror(errno));
    break;
  }
#endif

  return res;
}

int pr_inet_generate_socket_event(const char *event, server_rec *s,
    const pr_netaddr_t *addr, int fd) {
  pool *p;
  struct socket_ctx *sc;

  if (event == NULL ||
      s == NULL ||
      addr == NULL) {
    errno = EINVAL;
    return -1;
  }

  p = make_sub_pool(permanent_pool);
  sc = pcalloc(p, sizeof(struct socket_ctx));
  sc->server = s;
  sc->addr = addr;
  sc->sockfd = fd;
  pr_event_generate(event, sc);
  destroy_pool(p);

  return 0;
}

void init_inet(void) {
  struct protoent *pr = NULL;

#ifdef HAVE_SETPROTOENT
  setprotoent(FALSE);
#endif

  /* AIX ships with a broken /etc/protocols file; the entry for 'ip' in that
   * file defines a value of 252, which is unacceptable to the AIX
   * setsockopt(2) system call (Bug#3780).
   *
   * To work around this, do not perform the /etc/protocols lookup for AIX;
   * instead, keep the default IP_PROTO value defined in its other system
   * headers.
   */
#ifndef _AIX
  pr = getprotobyname("ip"); 
  if (pr != NULL) {
    ip_proto = pr->p_proto;
  }
#endif /* AIX */

#ifdef PR_USE_IPV6
  pr = getprotobyname("ipv6"); 
  if (pr != NULL) {
    ipv6_proto = pr->p_proto;
  }
#endif /* PR_USE_IPV6 */

  pr = getprotobyname("tcp");
  if (pr != NULL) {
    tcp_proto = pr->p_proto;
  }

#ifdef HAVE_ENDPROTOENT
  endprotoent();
#endif

  if (inet_pool) {
    destroy_pool(inet_pool);
  }

  inet_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(inet_pool, "Inet Pool");
}
