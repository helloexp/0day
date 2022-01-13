/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2017 The ProFTPD Project team
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

/* Server, command and associated prototypes. */

#ifndef PR_DIRTREE_H
#define PR_DIRTREE_H

#include "pool.h"
#include "sets.h"
#include "table.h"
#include "configdb.h"
#include "netaddr.h"

struct conn_struc;

struct tcp_keepalive {
  int keepalive_enabled;
  int keepalive_idle;
  int keepalive_count;
  int keepalive_intvl;
};

typedef struct server_struc {
  struct server_struc *next, *prev;

  struct pool_rec *pool;	/* Memory pool for this server */
  xaset_t *set;			/* Set holding all servers */

  /* The label/name for this server configuration. */
  const char *ServerName;

  /* The address for this server configuration. */
  const char *ServerAddress;

  /* The fully qualified domain name for this server configuration. */
  const char *ServerFQDN;

  /* Port number to which to listen. A value of zero disables the server_rec.
   */
  unsigned int ServerPort;

  /* TCP settings: keepalive, max segment size, receive/send buffer sizes.
   */

  struct tcp_keepalive *tcp_keepalive;

  int tcp_mss_len;

  /* If the tcp_rcvbuf_override/tcp_sndbuf_override flags are true, then
   * the corresponding buffer lengths are to be configured as socket options
   * via setsockopt(2).
   */ 
  int tcp_rcvbuf_len;
  unsigned char tcp_rcvbuf_override;

  int tcp_sndbuf_len;
  unsigned char tcp_sndbuf_override;

  /* Administrator name */
  const char *ServerAdmin;

  /* Internal address of this server */
  const pr_netaddr_t *addr;

  /* The listener for this server.  Note that this listener, and that
   * pointed to by ipbind->ib_listener (where ipbind->ib_server points to
   * this server_rec) are the same.  Ideally, we'd only want one pointer to
   * the listener around, and avoid the duplication.  To do this would
   * require further structural changes.
   */
  struct conn_struc *listen;

  /* Configuration details */
  xaset_t *conf;
  int config_type;

  /* Internal server ID, automatically assigned */
  unsigned int sid;

  /* Private data for passing among modules for this vhost. */
  pr_table_t *notes;

} server_rec;

typedef struct cmd_struc {
  struct pool_rec *pool;
  server_rec *server;
  config_rec *config;
  struct pool_rec *tmp_pool;	/* Temporary pool which only exists
				 * while the cmd's handler is running
				 */
  unsigned int argc;

  char *arg;			/* entire argument (excluding command) */
  void **argv;

  char *group;			/* Command grouping */

  int cmd_class;		/* The command class */

  /* These are used to speed up symbol hashing/lookups in stash.c. */
  int stash_index;
  unsigned int stash_hash;

  pr_table_t *notes;		/* Private data for passing/retaining between handlers */

  int cmd_id;			/* Index into commands list, for faster comparisons */

  /* If we detect that the client sent commands for a protocol OTHER than
   * FTP, then this field will be FALSE; the protocol field will identify
   * the detected protocol.
   */
  int is_ftp;
  const char *protocol;

} cmd_rec;

/* Operation codes for dir_* funcs */
#define OP_HIDE			1	/* Op for hiding dirs/files */
#define OP_COMMAND		2	/* Command operation */

/* For the Order directive */
#define ORDER_ALLOWDENY		0
#define ORDER_DENYALLOW		1

extern server_rec		*main_server;
extern int			tcpBackLog;
extern int			SocketBindTight;
extern char			ServerType;
extern unsigned long		ServerMaxInstances;
extern int			ServerUseReverseDNS;

/* These macros are used to help handle configuration in modules */
#define CONF_ERROR(x, s)	return PR_ERROR_MSG((x),NULL,pstrcat((x)->tmp_pool, \
				(x)->argv[0],": ",(s),NULL));

#define CHECK_ARGS(x, n)	if ((n) > 0 && (x)->argc > 0 && (x)->argc-1 < (n)) \
				CONF_ERROR(x,"missing parameters")

#define CHECK_VARARGS(x, n, m)	if ((x)->argc - 1 < n || (x)->argc - 1 > m) \
				CONF_ERROR(x,"missing parameters")

#define CHECK_HASARGS(x, n)	((x)->argc - 1) == (n)

#define CHECK_CONF(x,p)		if (!check_context((x),(p))) \
				CONF_ERROR((x), \
				pstrcat((x)->tmp_pool,"directive not allowed in ", \
				get_context_name((x)), \
				" context",NULL))

#define CHECK_CMD_ARGS(x, n)	\
  if ((x)->argc != (n)) { \
    pr_response_add_err(R_501, _("Invalid number of parameters")); \
    return PR_ERROR((x)); \
  }

#define CHECK_CMD_MIN_ARGS(x, n)	\
  if ((x)->argc < (n)) { \
    pr_response_add_err(R_501, _("Invalid number of parameters")); \
    return PR_ERROR((x)); \
  }

/* Prototypes */

/* KLUDGE: disable umask() for not G_WRITE operations.  Config/
 * Directory walking code will be completely redesigned in 1.3,
 * this is only necessary for performance reasons in 1.1/1.2
 */
void kludge_disable_umask(void);
void kludge_enable_umask(void);

int pr_define_add(const char *, int);
unsigned char pr_define_exists(const char *);

int fixup_servers(xaset_t *list);
xaset_t *get_dir_ctxt(pool *, char *);

/* Returns the buffer size to use for data transfers, regardless of IO
 * direction.
 */
int pr_config_get_xfer_bufsz(void);

/* Returns the buffer size to use for data transfers given an IO direction
 * (either PR_NETIO_IO_RD for reads/uploads, or PR_NETIO_IO_WR for
 * writes/downloads).
 */
int pr_config_get_xfer_bufsz2(int);

/* Returns the buffer size to use for data transfers given an IO direction
 * (either PR_NETIO_IO_RD for reads/uploads, or PR_NETIO_IO_WR for
 * writes/downloads).  This takes into account any server-specific buffer
 * sizes, e.g. as configured via SocketOptions.
 */
int pr_config_get_server_xfer_bufsz(int);

config_rec *dir_match_path(pool *, char *);
void build_dyn_config(pool *, const char *, struct stat *, unsigned char);
unsigned char dir_hide_file(const char *);
int dir_check_full(pool *, cmd_rec *, const char *, const char *, int *);
int dir_check_limits(cmd_rec *, config_rec *, const char *, int);
int dir_check(pool *, cmd_rec *, const char *, const char *, int *);
int dir_check_canon(pool *, cmd_rec *, const char *, const char *, int *);
int is_dotdir(const char *);
int login_check_limits(xaset_t *, int, int, int *);
void resolve_anonymous_dirs(xaset_t *);
void resolve_deferred_dirs(server_rec *);
void fixup_dirs(server_rec *, int);
unsigned char check_context(cmd_rec *, int);
char *get_context_name(cmd_rec *);
int get_boolean(cmd_rec *, int);
const char *get_full_cmd(cmd_rec *);

/* Internal use only. */
void init_dirtree(void);

#ifdef PR_USE_DEVEL
void pr_dirs_dump(void (*)(const char *, ...), xaset_t *, char *);
#endif /* PR_USE_DEVEL */

#endif /* PR_DIRTREE_H */
