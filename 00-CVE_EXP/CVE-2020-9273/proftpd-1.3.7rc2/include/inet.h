/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
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
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* BSD socket manipulation tools. */

#ifndef PR_INET_H
#define PR_INET_H

#include "conf.h"

#ifndef AF_INET6
# define AF_INET6	AF_UNSPEC
#endif /* AF_INET6 */

#ifndef INADDR_ANY
# define INADDR_ANY	((unsigned long int) 0x00000000)
#endif /* INADDR_ANY */

#ifndef INADDR_LOOPBACK
# define INADDR_LOOPBACK	((unsigned long int) 0x7f000001)
#endif /* INADDR_LOOPBACK */

#ifndef INADDR_NONE
# define INADDR_NONE	0xffffffff
#endif /* INADDR_NONE */

#ifndef INPORT_ANY
# define INPORT_ANY	0
#endif

#ifndef IN6_IS_ADDR_UNSPECIFIED
# define IN6_IS_ADDR_UNSPECIFIED(a)	0
#endif

#ifndef IN6_IS_ADDR_LOOPBACK
# define IN6_IS_ADDR_LOOPBACK(a)	0
#endif

#ifndef IN6_IS_ADDR_MULTICAST
# define IN6_IS_ADDR_MULTICAST(a)	0
#endif

#ifndef IN6_IS_ADDR_LINKLOCAL
# define IN6_IS_ADDR_LINKLOCAL(a)	0
#endif

#ifndef IN6_IS_ADDR_SITELOCAL
# define IN6_IS_ADDR_SITELOCAL(a)	0
#endif

#ifndef IN6_IS_ADDR_V4MAPPED
# define IN6_IS_ADDR_V4MAPPED(a)	0
#endif

#ifndef IN6_IS_ADDR_V4COMPAT
# define IN6_IS_ADDR_V4COMPAT(a)	0
#endif

#ifndef IN6_ARE_ADDR_EQUAL
# define IN6_ARE_ADDR_EQUAL(a, b)	0
#endif

#ifndef U32BITS
# define U32BITS	0xffffffff
#endif

/* Connection modes */
#define CM_NONE         0
#define CM_LISTEN       1
#define CM_OPEN         2
#define CM_ACCEPT       3
#define CM_CONNECT      4
#define CM_CLOSED       5
#define CM_ERROR        6

/* connection structure */
typedef struct conn_struc {
  struct conn_struc *next;
  struct pool_rec *pool;
  int mode;				/* Current connection mode */
  int listen_fd;			/* Listening file descriptor */
  int rcvbuf, sndbuf;			/* Socket recv and send sizes */

  int xerrno;				/* Set to error if mode == CM_ERROR */

  int rfd,wfd;				/* Read and write fds */
  pr_netio_stream_t *instrm, *outstrm;	/* Input/Output streams */

  /* Remote address of the connection. */
  const pr_netaddr_t *remote_addr;

  /* Remote port of the connection. */
  int remote_port;

  /* Remote FQDN of the connection. */
  const char *remote_name;

  /* Local address of the connection. */
  const pr_netaddr_t *local_addr;

  /* Local port of the connection. */
  int local_port;

} conn_t;

/* Used for event data for events related to opening of sockets */
struct socket_ctx {
  server_rec *server;
  const pr_netaddr_t *addr;
  int sockfd;
};

/* Prototypes */
void pr_inet_clear(void);
int pr_inet_reverse_dns(pool *, int);
int pr_inet_getservport(pool *, const char *, const char *);
pr_netaddr_t *pr_inet_getaddr(pool *, const char *, array_header **);
conn_t *pr_inet_copy_conn(pool *, conn_t *);
conn_t *pr_inet_create_conn(pool *, int, const pr_netaddr_t *, int, int);
conn_t *pr_inet_create_conn_portrange(pool *, const pr_netaddr_t *, int, int);
void pr_inet_close(pool *, conn_t *);
void pr_inet_lingering_abort(pool *, conn_t *, long);
void pr_inet_lingering_close(pool *, conn_t *, long);
int pr_inet_set_default_family(pool *, int);
int pr_inet_set_async(pool *, conn_t *);
int pr_inet_set_block(pool *, conn_t *);
int pr_inet_set_nonblock(pool *, conn_t *);
int pr_inet_set_proto_cork(int, int);
int pr_inet_set_proto_nodelay(pool *, conn_t *, int);
int pr_inet_set_proto_opts(pool *, conn_t *, int, int, int, int);
int pr_inet_set_socket_opts(pool *, conn_t *, int, int, struct tcp_keepalive *);

int pr_inet_listen(pool *p, conn_t *conn, int backlog, int flags);
#define PR_INET_LISTEN_FL_FATAL_ON_ERROR		0x0001

int pr_inet_resetlisten(pool *, conn_t *);
int pr_inet_accept_nowait(pool *, conn_t *);
int pr_inet_connect(pool *, conn_t *, const pr_netaddr_t *, int);
int pr_inet_connect_nowait(pool *, conn_t *, const pr_netaddr_t *, int);
int pr_inet_get_conn_info(conn_t *, int);
conn_t *pr_inet_accept(pool *, conn_t *, conn_t *, int, int, unsigned char);
conn_t *pr_inet_openrw(pool *, conn_t *, const pr_netaddr_t *, int, int, int,
  int, int);
int pr_inet_generate_socket_event(const char *, server_rec *,
  const pr_netaddr_t *, int);

void init_inet(void);

#endif /* PR_INET_H */
