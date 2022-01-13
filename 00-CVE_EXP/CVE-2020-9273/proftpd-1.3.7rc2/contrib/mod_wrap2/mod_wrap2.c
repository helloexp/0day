/*
 * ProFTPD: mod_wrap2 -- tcpwrappers-like access control
 * Copyright (c) 2000-2017 TJ Saunders
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
 * As a special exemption, TJ Saunders gives permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

#include "mod_wrap2.h"

#ifdef WRAP2_USE_NIS
#include <rpc/rpc.h>
#include <rpcsvc/ypclnt.h>
#endif /* WRAP2_USE_NIS */

typedef struct regtab_obj {
  struct regtab_obj *prev, *next;

  /* Table source type name */
  const char *regtab_name;

  /* Initialization function for this type of table source */
  wrap2_table_t *(*regtab_open)(pool *, const char *);

} wrap2_regtab_t;

module wrap2_module;
unsigned long wrap2_opts = 0UL;

/* Wrap tables for the current session */
static char *wrap2_allow_table = NULL;
static char *wrap2_deny_table = NULL;

/* Memory pool for this module */
static pool *wrap2_pool = NULL;

/* List of registered quotatab sources */
static wrap2_regtab_t *wrap2_regtab_list = NULL;

/* Logging data */
static int wrap2_logfd = -1;
static const char *wrap2_logname = NULL;

static int wrap2_engine = FALSE;
static const char *wrap2_service_name = WRAP2_DEFAULT_SERVICE_NAME;
static const char *wrap2_client_name = NULL;
static config_rec *wrap2_ctxt = NULL;

/* Access check variables */

#define WRAP2_UNKNOWN	"unknown"
#define WRAP2_PARANOID	"paranoid"

#define WRAP2_IS_KNOWN_HOSTNAME(s) \
  (strcasecmp((s), WRAP2_UNKNOWN) != 0 && strcasecmp((s), WRAP2_PARANOID))

#define WRAP2_IS_NOT_INADDR(s) \
  (s[strspn(s,"01234567890./")] != 0)

#define WRAP2_GET_DAEMON(r) \
  ((r)->daemon)

/* Data structures */

typedef struct host_info {
  char name[WRAP2_BUFFER_SIZE];
  char addr[WRAP2_BUFFER_SIZE];
  struct sockaddr_in *sin;            /* socket address or 0 */
  struct t_unitdata *unit;            /* TLI transport address or 0 */
  struct conn_info *connection;       /* for shared information */

} wrap2_host_t;

typedef struct conn_info {
  int sock_fd;                         /* socket handle */
  char user[WRAP2_BUFFER_SIZE];        /* access via eval_user(request) */
  char daemon[WRAP2_BUFFER_SIZE];      /* access via eval_daemon(request) */
  struct host_info client[1];         /* client endpoint info */
  struct host_info server[1];         /* server endpoint info */
  void  (*sink) (int);                /* datagram sink function or 0 */
  void  (*hostname) (struct host_info *); /* address to printable hostname */
  void  (*hostaddr) (struct host_info *); /* address to printable address */
  void  (*cleanup) (struct conn_info *);   /* cleanup function or 0 */
  struct netconfig *config;           /* netdir handle */

} wrap2_conn_t;

#define WRAP2_CONN_SOCK_FD	1	/* socket descriptor */
#define WRAP2_CONN_DAEMON	2	/* server process (argv[0]) */

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

/* Necessary prototypes. */
static int wrap2_sess_init(void);

/* Logging routines */

static int wrap2_closelog(void) {
  if (wrap2_logfd != -1) {
    close(wrap2_logfd);
    wrap2_logfd = -1;
    wrap2_logname = NULL;
  }

  return 0;
}

int wrap2_log(const char *fmt, ...) {
  va_list msg;
  int res;

  if (!wrap2_logname)
    return 0;

  va_start(msg, fmt);
  res = pr_log_vwritefile(wrap2_logfd, MOD_WRAP2_VERSION, fmt, msg);
  va_end(msg);

  return res;
}

static int wrap2_openlog(void) {
  int res = 0, xerrno;

  /* Sanity check */
  wrap2_logname = get_param_ptr(main_server->conf, "WrapLog", FALSE);
  if (wrap2_logname == NULL)
    return 0;

  /* Check for "none" */
  if (strcasecmp(wrap2_logname, "none") == 0) {
    wrap2_logname = NULL;
    return 0;
  }

  pr_signals_block();
  PRIVS_ROOT
  res = pr_log_openfile(wrap2_logname, &wrap2_logfd, PR_LOG_SYSTEM_MODE);
  xerrno = errno;
  PRIVS_RELINQUISH
  pr_signals_unblock();

  errno = xerrno;
  return res;
}

/* Table routines */

static int wrap2_close_table(wrap2_table_t *tab) {
  return tab->tab_close(tab);
}

static wrap2_table_t *wrap2_open_table(char *name) {
  char *info = NULL, *ptr = NULL;
  unsigned char have_type = FALSE;
  register wrap2_regtab_t *regtab = NULL;
  wrap2_table_t *tab = NULL;

  info = ptr = strchr(name, ':');
  if (info == NULL) {
    errno = EINVAL;
    return NULL;
  }

  *info++ = '\0';

  /* Look up the table source open routine by name, and invoke it */
  for (regtab = wrap2_regtab_list; regtab; regtab = regtab->next) {
    if (strcmp(regtab->regtab_name, name) == 0) {
      tab = regtab->regtab_open(wrap2_pool, info);
      if (tab == NULL) {
        *ptr = ':';
        return NULL;
      }

      have_type = TRUE;
      *ptr = ':';
      break;
    }
  }

  if (!have_type) {
    wrap2_log("unsupported table source: '%s'", name);
    errno = EINVAL;
    return NULL;
  }

  return tab;
}

/* Information structure routines */

static wrap2_conn_t *wrap2_conn_update(wrap2_conn_t *conn, va_list ap) {
  int key = 0;
  char *val = NULL;

  while ((key = va_arg(ap, int)) > 0) {
    switch (key) {

      default:
        wrap2_log("invalid key: %d", key);
        return conn;

      case WRAP2_CONN_SOCK_FD:
        conn->sock_fd = va_arg(ap, int);
        continue;

#if 0
      case WRAP2_CONN_CLIENT_SIN:
        conn->client->sin = va_arg(ap, struct sockaddr_in *);
        continue;

      case WRAP2_CONN_SERVER_SIN:
        conn->server->sin = va_arg(ap, struct sockaddr_in *);
        continue;
#endif

      case WRAP2_CONN_DAEMON:
        val = conn->daemon;
        break;

#if 0
      case WRAP2_CONN_USER:
        val = conn->user;
        break;

      case WRAP2_CONN_CLIENT_NAME:
        val = conn->client->name;
        break;

      case WRAP2_CONN_CLIENT_ADDR:
        val = conn->client->addr;
        break;

      case WRAP2_CONN_SERVER_NAME:
        val = conn->server->name;
        break;

      case WRAP2_CONN_SERVER_ADDR:
        val = conn->server->addr;
        break;
#endif
    }

    /* Copy in the string */
    sstrncpy(val, va_arg(ap, char *), WRAP2_BUFFER_SIZE);
  }

  return conn;
}

static wrap2_conn_t *wrap2_conn_set(wrap2_conn_t *conn, ...) {
  static wrap2_conn_t default_conn;
  wrap2_conn_t *c = NULL;
  va_list ap;

  /* Initialize the data members.  We do not assign default callbacks,
   * to avoid pulling in the whole socket module when it is not really
   * needed.
   */
  va_start(ap, conn);

  *conn = default_conn;

  conn->sock_fd = -1;
  sstrncpy(conn->daemon, WRAP2_UNKNOWN, sizeof(conn->daemon));

  conn->client->connection = conn;
  conn->server->connection = conn;

  c = wrap2_conn_update(conn, ap);
  va_end(ap);

  return c;
}

static char *wrap2_get_user(wrap2_conn_t *conn) {

  if (*conn->user == '\0') {
    const char *rfc1413_ident;

    /* RFC1413 lookups may have already been done by the mod_ident module.
     * If so, use the ident name stashed; otherwise, use the user name issued
     * by the client.
     */

    rfc1413_ident = pr_table_get(session.notes, "mod_ident.rfc1413-ident",
      NULL);
    if (rfc1413_ident != NULL) {
      sstrncpy(conn->user, rfc1413_ident, sizeof(conn->user));

    } else {
      const char *user;

      user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
      if (user != NULL) {
        sstrncpy(conn->user, user, sizeof(conn->user));
      }
    }
  }

  return conn->user;
}

static char *wrap2_get_hostaddr(wrap2_host_t *host) {
  if (*host->addr == '\0') {
    sstrncpy(host->addr, pr_netaddr_get_ipstr(session.c->remote_addr),
      sizeof(host->addr));
  }

  return host->addr;
}

static char *wrap2_get_hostname(wrap2_host_t *host) {

  if (*host->name == '\0') {
    int reverse_dns;
    size_t namelen;

    reverse_dns = pr_netaddr_set_reverse_dns(TRUE);
    if (reverse_dns) {
      pr_netaddr_t *remote_addr;

      /* If UseReverseDNS is on, then clear any caches, so that we really do
       * use the DNS name here if possible.
       */
      pr_netaddr_clear_cache();

      remote_addr = (pr_netaddr_t *) session.c->remote_addr;
      remote_addr->na_have_dnsstr = FALSE;

      sstrncpy(host->name, pr_netaddr_get_dnsstr(session.c->remote_addr),
        sizeof(host->name));

      /* If the retrieved hostname ends in a trailing period, trim it off. */
      namelen = strlen(host->name); 
      if (host->name[namelen-1] == '.') {
        host->name[namelen-1] = '\0';
        namelen--;
      }

      pr_netaddr_set_reverse_dns(reverse_dns);
      remote_addr->na_have_dnsstr = TRUE;

    } else {
      wrap2_log("'UseReverseDNS off' in effect, NOT resolving %s to DNS name "
        "for comparison", pr_netaddr_get_ipstr(session.c->remote_addr));

      sstrncpy(host->name, pr_netaddr_get_dnsstr(session.c->remote_addr),
        sizeof(host->name));
      pr_netaddr_set_reverse_dns(reverse_dns);
    }
  }

  return host->name;
}

static char *wrap2_get_hostinfo(wrap2_host_t *host) {
  char *hostname;

  hostname = wrap2_get_hostname(host);

  if (WRAP2_IS_KNOWN_HOSTNAME(hostname))
    return hostname;

  return wrap2_get_hostaddr(host);
}

static char *wrap2_get_client(wrap2_conn_t *conn) {
  static char both[WRAP2_BUFFER_SIZE] = {'\0'};
  char *hostinfo;

  hostinfo = wrap2_get_hostinfo(conn->client);

  if (strcasecmp(wrap2_get_user(conn), WRAP2_UNKNOWN) != 0) {
    pr_snprintf(both, sizeof(both), "%s@%s", conn->user, hostinfo);
    both[sizeof(both)-1] = '\0';
    return both;
  }

  return hostinfo;
}

/* Access checking routines */

char *wrap2_strsplit(char *str, int delim) {
  char *tmp = NULL;

  tmp = strchr(str, delim);
  if (tmp != NULL)
    *tmp++ = '\0';

  return tmp;
}

static char *wrap2_skip_whitespace(char *str) {
  register unsigned int i;
  char *tmp;

  /* Skip any leading whitespace. */
  tmp = str;
  for (i = 0; str[i]; i++) {
    if (PR_ISSPACE(str[i])) {
      tmp = &str[i+1];
      continue;
    }

    break;
  }

  return tmp;
}

static unsigned char wrap2_match_string(const char *tok, const char *str) {
  size_t len = 0;

  if (tok[0] == '.') {

    /* Suffix */
    len = strlen(str) - strlen(tok);
    return (len > 0 && (strcasecmp(tok, str + len) == 0));

  } else if (strcasecmp(tok, "ALL") == 0) {
    /* ALL: match any */
    return TRUE;

  } else if (strcasecmp(tok, "KNOWN") == 0) {

    /* Not unknown */
    return (strcasecmp(str, WRAP2_UNKNOWN) != 0);

  } else if (tok[(len = strlen(tok)) - 1] == '.') {

    /* Prefix */
    return (strncasecmp(tok, str, len) == 0);
  }

  /* Exact match */
  return (strcasecmp(tok, str) == 0);
}

static unsigned long wrap2_addr_a2n(const char *str) {
  unsigned char within_run = FALSE;
  unsigned int nruns = 0;
  const char *cp = str;

  /* Count the number of runs of non-dot characters. */

  while (*cp) {
    if (*cp == '.') {
      within_run = FALSE;

    } else if (within_run == FALSE) {
      within_run = TRUE;
      nruns++;
    }
    cp++;
  }

  return (nruns == 4 ? inet_addr(str) : INADDR_NONE);
}

static unsigned char wrap2_match_netmask(const char *net_tok,
    const char *mask_tok, const char *str) {
  unsigned long net = 0UL;
  unsigned long mask = 0UL;
  unsigned long addr = 0UL;

  /* Disallow forms other than dotted quad: the treatment that inet_addr()
   * gives to forms with less than four components is inconsistent with the
   * access control language. John P. Rouillard <rouilj@cs.umb.edu>.
   */

  addr = wrap2_addr_a2n(str);
  if (addr == INADDR_NONE) {
    return FALSE;
  }

  net = wrap2_addr_a2n(net_tok);
  mask = wrap2_addr_a2n(mask_tok);
  if (net == INADDR_NONE ||
      mask == INADDR_NONE) {
    wrap2_log("warning: bad net/mask expression: '%s/%s'", net_tok, mask_tok);
    return FALSE;
  }

  return ((addr & mask) == net);
}

static unsigned char wrap2_match_host(char *tok, wrap2_host_t *host) {
  char *mask = NULL;
  size_t len;

  tok = wrap2_skip_whitespace(tok);

  /* This code looks a little hairy because we want to avoid unnecessary
   * hostname lookups.
   *
   * The KNOWN pattern requires that both address AND name be known; some
   * patterns are specific to host names or to host addresses; all other
   * patterns are satisfied when either the address OR the name match.
   */

  if (tok[0] == '@') {
#ifdef WRAP2_USE_NIS
    /* netgroup: look it up. */
    static char *mydomain = NULL;

    if (mydomain == NULL)
      yp_get_default_domain(&mydomain);

    return (innetgr(tok + 1, wrap2_get_hostname(host), NULL, mydomain));
#else
    wrap2_log("warning: '%s': NIS support is not enabled", tok);
    return FALSE;
#endif

  } else if (strcasecmp(tok, "ALL") == 0) {
    /* Matches everything */
    return TRUE;

  } else if (strcasecmp(tok, "KNOWN") == 0) {
    char *name;

    /* Check address and name. */
    name = wrap2_get_hostname(host);
    return ((strcasecmp(wrap2_get_hostaddr(host), WRAP2_UNKNOWN) != 0) &&
      WRAP2_IS_KNOWN_HOSTNAME(name));

  } else if (strcasecmp(tok, "LOCAL") == 0) {
    char *name;

    /* Local: no dots in name. */
    name = wrap2_get_hostname(host);
    return (strchr(name, '.') == NULL && WRAP2_IS_KNOWN_HOSTNAME(name));

  } else if (tok[(len = strlen(tok)) - 1] == '.') {
    const char *ip_str;
 
    /* Prefix */

    ip_str = wrap2_get_hostaddr(host);
    return (strncasecmp(tok, ip_str, len) == 0);

  } else if (tok[0] == '.') {
    register unsigned int i;
    char *primary_name;
    array_header *dns_names;

    /* Suffix */
    primary_name = wrap2_get_hostname(host);
    len = strlen(primary_name) - strlen(tok);

    wrap2_log("comparing client hostname '%s' (part %s) against DNS "
      "pattern '%s'", primary_name, primary_name+len, tok);

    if (len > 0 &&
        strcasecmp(tok, primary_name + len) == 0) {
      return TRUE;
    }

    if (!(wrap2_opts & WRAP_OPT_CHECK_ALL_NAMES)) {
      return FALSE;
    }

    dns_names = pr_netaddr_get_dnsstr_list(session.pool,
      session.c->remote_addr);
    if (dns_names != NULL &&
        dns_names->nelts > 0) {
      char **names;

      names = dns_names->elts;
      for (i = 0; i < dns_names->nelts; i++) {
        char *name;

        name = names[i];
        if (name != NULL) {
          len = strlen(name) - strlen(tok);

          wrap2_log("comparing client hostname '%s' (part %s) against DNS "
            "pattern '%s'", name, name+len, tok);

          if (len > 0 &&
              strcasecmp(tok, name + len) == 0) {
            return TRUE;
          }
        }
      }
    }

    return FALSE;

#ifdef PR_USE_IPV6 
  } else if (pr_netaddr_use_ipv6() &&
             *tok == '[') {
    char *cp;
    const pr_netaddr_t *acl_addr;

    /* IPv6 address */

    if (pr_netaddr_get_family(session.c->remote_addr) == AF_INET) {
      /* No need to try to match an IPv6 address against an IPv4 client. */
      return FALSE;
    }

    /* Find the terminating ']'. */
    cp = strchr(tok, ']');
    if (cp == NULL) {
      wrap2_log("bad IPv6 address syntax: '%s'", tok);
      return FALSE;
    }

    *cp = '\0';

    /* Lookup a netaddr for the IPv6 address. */
    acl_addr = pr_netaddr_get_addr(wrap2_pool, tok + 1, NULL);
    if (acl_addr == NULL) {
      wrap2_log("unable to resolve IPv6 address '%s'", tok + 1);
      return FALSE;
    }

    if (*(cp + 1) != '/') {
      if (pr_netaddr_cmp(session.c->remote_addr, acl_addr) == 0) {
        return TRUE;
      }

      return FALSE;

    } else {
      unsigned int nmaskbits;
      char *tmp;

      /* Netmask */

      /* Determine the number of mask bits. */
      nmaskbits = strtol(cp + 2, &tmp, 10);
      if (tmp && *tmp) {
        wrap2_log("bad mask syntax: '%s'", tmp);
        return FALSE;
      }

      return (pr_netaddr_ncmp(session.c->remote_addr, acl_addr,
        nmaskbits) == 0);
    }
#endif /* PR_USE_IPV6 */

  } else if ((mask = wrap2_strsplit(tok, '/')) != 0) {

    /* Net/mask */
    return (wrap2_match_netmask(tok, mask, wrap2_get_hostaddr(host)));

  } else {
    const pr_netaddr_t *acl_addr;

    /* Anything else.
     *
     * In order to properly compare IP addresses (and to handle cases of
     * handling IPv4-mapped IPv6 addresses compared against IPv4 addresses),
     * we need to use pr_netaddr_cmp(), rather than doing the string
     * comparison that libwrap used.
     */

    acl_addr = pr_netaddr_get_addr(wrap2_pool, tok, NULL);
    if (acl_addr == NULL) {
      if (wrap2_match_string(tok, wrap2_get_hostname(host))) {
        return TRUE;
      }

      wrap2_log("unable to handle address '%s'", tok);

    } else {
      if (pr_netaddr_cmp(session.c->remote_addr, acl_addr) == 0) {
        return TRUE;
      }
    }

    if (WRAP2_IS_NOT_INADDR(tok)) {
      register unsigned int i;
      char *primary_name;
      array_header *dns_names;

      primary_name = wrap2_get_hostname(host);
      wrap2_log("comparing client hostname '%s' against DNS name '%s'",
        primary_name, tok);

      if (wrap2_match_string(tok, primary_name)) {
        return TRUE;
      }

      if (!(wrap2_opts & WRAP_OPT_CHECK_ALL_NAMES)) {
        return FALSE;
      }

      dns_names = pr_netaddr_get_dnsstr_list(session.pool,
        session.c->remote_addr);
      if (dns_names != NULL &&
          dns_names->nelts > 0) {
        char **names;

        names = dns_names->elts;
        for (i = 0; i < dns_names->nelts; i++) {
          char *name;

          name = names[i];
          if (name != NULL) {
            wrap2_log("comparing client hostname '%s' against DNS name '%s'",
              name, tok);

            if (wrap2_match_string(tok, name)) {
              return TRUE;
            }
          }
        }
      }
    }
  }

  return FALSE;
}

static unsigned char wrap2_match_client(char *tok, wrap2_conn_t *conn) {
  unsigned char match = FALSE;
  char *host = NULL;

  host = wrap2_strsplit(tok + 1, '@');
  if (host == 0) {

    /* Plain host */
    match = wrap2_match_host(tok, conn->client);

    if (match) {
      wrap2_log("client matches '%s'", tok);
    }

  } else {

    /* user@host */
    match = (wrap2_match_host(host, conn->client) &&
      wrap2_match_string(tok, wrap2_get_user(conn)));

    if (match) {
      wrap2_log("client matches '%s@%s'", tok, host);
    }
  }

  return match;
}

static unsigned char wrap2_match_daemon(char *tok, wrap2_conn_t *conn) {
  unsigned char match = FALSE;
  char *host = NULL;

  host = wrap2_strsplit(tok + 1, '@');
  if (host == 0) {

    /* Plain daemon */
    match = wrap2_match_string(tok, WRAP2_GET_DAEMON(conn));

    if (match)
      wrap2_log("daemon matches '%s'", tok);

  } else {

    /* daemon@host */
    match = (wrap2_match_string(tok, WRAP2_GET_DAEMON(conn)) &&
      wrap2_match_host(host, conn->server));

    if (match)
      wrap2_log("daemon matches '%s@%s'", tok, host);
  }

  return match;
}

static unsigned char wrap2_match_list(array_header *list, wrap2_conn_t *conn,
    unsigned char (*match_token)(char *, wrap2_conn_t *),
    unsigned int list_idx) {
  register unsigned int i;
  char **tokens = NULL;

  if (list == NULL)
    return FALSE;

  tokens = list->elts;

  /* Process tokens one at a time. We have exhausted all possible matches
   * when we reach an "EXCEPT" token or the end of the list. If we do find
   * a match, look for an "EXCEPT" list and recurse to determine whether
   * the match is affected by any exceptions.
   */

  for (i = list_idx; i < list->nelts; i++) {
    char *token;

    /* It's possible that the token string is actually NULL; handle this
     * case gracefully.
     */
    if (tokens[i] == NULL) {
      continue;
    }

    token = wrap2_skip_whitespace(tokens[i]);

    if (strcasecmp(token, "EXCEPT") == 0) {
      /* EXCEPT -- give up now. */
      return FALSE;
    }

    if (match_token(token, conn)) {
      register unsigned int j;

      /* If yes, look for exceptions */
      for (j = i + 1; j < list->nelts; j++) {
        token = wrap2_skip_whitespace(tokens[j]);
        if (strcasecmp(token, "EXCEPT") == 0) {
          return (wrap2_match_list(list, conn, match_token, j+1) == 0);
        } 
      }

      return TRUE;
    }
  }

  return FALSE;
}

#ifdef WRAP2_USE_OPTIONS

#define WRAP2_WHITESPACE		" \t\r\n"

/* Options flag for requiring a value. */
#define WRAP2_OF_NEED_ARG	(1 << 1)

/* Options flag specifying the option must be last in the list. */
#define WRAP2_OF_USE_LAST	(1 << 2)

/* Options flag allowing for optional values. */
#define WRAP2_OF_OPT_ARG	(1 << 3)

#define WRAP2_OPT_NEEDS_VAL(o)	\
  ((o)->flags & WRAP2_OF_NEED_ARG)
#define WRAP2_OPT_ALLOWS_VAL(o)	\
  ((o)->flags & (WRAP2_OF_NEED_ARG|WRAP2_OF_OPT_ARG))
#define WRAP2_OPT_NEEDS_LAST(o)	\
  ((o)->flags & WRAP2_OF_USE_LAST)

#define WRAP2_OPT_ALLOW  4
#define WRAP2_OPT_DENY   -4

/* Options routines */

static char *wrap2_opt_trim_string(char *string) {
  char *start = NULL, *end = NULL, *cp = NULL;

  for (cp = string; *cp; cp++) {
    if (!PR_ISSPACE(*cp)) {
      if (start == '\0') {
        start = cp;
      }
      end = cp;
    }
  }

  return (start ? (end[1] = '\0', start) : cp);
}

static char *wrap2_opt_get_field(array_header *opts, unsigned int *opt_idx) {
  static char *last = "";
  char *src = NULL, *dst = NULL, *res = NULL;
  char c = 0;

  char *string = ((char **) opts->elts)[*opt_idx];

  /* This function returns pointers to successive fields within a given
   * string. ":" is the field separator; warn if the rule ends in one. It
   * replaces a "\:" sequence by ":", without treating the result of
   * substitution as field terminator. A null argument means resume search
   * where the previous call terminated. This function destroys its
   * argument.
   *
   * Work from explicit source or from memory. While processing \: we
   * overwrite the input. This way we do not have to maintain buffers for
   * copies of input fields.
   */

  src = dst = res = (string ? string : last);

  if (*src == '\0')
    return NULL;

  while ((c = *src)) {
    if (c == ':') {
      if (*++src == '\0')
        wrap2_log("option rule ends in ':'");

      break;
    }

    if (c == '\\' && src[1] == ':')
      src++;
    *dst++ = *src++;
  }

  last = src;
  *dst = '\0';

  *opt_idx++;
  return res;
}

/* "allow" option - grant access */
static int wrap2_opt_allow(char *val) {
  return WRAP2_OPT_ALLOW;
}

/* "deny" option - deny access */
static int wrap2_opt_deny(char *val) {
  return WRAP2_OPT_DENY;
}

/* "nice" option - set process nice value */
static int wrap2_opt_nice(char *val) {
  int niceness = 10;
  char *tmp = NULL;

  if (val != 0) {
    niceness = (int) strtol(val, &tmp, 10);

    if (niceness < 0 || (tmp && *tmp)) {
      wrap2_log("bad nice value: '%s'", val);
      return 0;
    }
  }

  if (nice(niceness) < 0)
    wrap2_log("error handling nice option: %s", strerror(errno));

  return 0;
}

/* "setenv" option - set environment variable */
static int wrap2_opt_setenv(char *val) {
  char *value = NULL;

  if (*(value = val + strcspn(val, WRAP2_WHITESPACE)))
    *value++ = '\0';

  if (pr_env_set(session.pool, wrap2_opt_trim_string(val),
      wrap2_opt_trim_string(value)) < 0) {
    wrap2_log("error handling setenv option: %s", strerror(errno));
  }

  return 0;
}

struct wrap2_opt {
  /* Keyword name (case-insensitive) */
  char *name;

  /* Options handler */
  int (*func)(char *);

  /* Modifying flags */
  int flags;
};

static const struct wrap2_opt options_tab[] = {
  { "setenv",	wrap2_opt_setenv,	WRAP2_OF_NEED_ARG },
  { "nice",	wrap2_opt_nice,		WRAP2_OF_OPT_ARG },
  { "allow",	wrap2_opt_allow,	WRAP2_OF_USE_LAST },
  { "deny",	wrap2_opt_deny,		WRAP2_OF_USE_LAST },
  { NULL, NULL, 0 }
};

static int wrap2_handle_opts(array_header *options, wrap2_conn_t *conn) {
  char *key = NULL, *value = NULL;
  char *curr_opt = NULL, *next_opt = NULL;
  const struct wrap2_opt *opt = NULL;
  unsigned int opt_idx = 0;

  for (curr_opt = wrap2_opt_get_field(options, &opt_idx); curr_opt;
       curr_opt = next_opt) {
    int res = 0;
    next_opt = wrap2_opt_get_field(options, &opt_idx);

    /* Separate the option into name and value parts. For backwards
     * compatibility we ignore exactly one '=' between name and value.
     */
    curropt = wrap2_opt_trim_string(curr_opt);

    if (*(value = curr_opt + strcspn(curr_opt, "=" WRAP2_WHITESPACE))) {
      if (*value != '=') {
        *value++ = '\0';
        value += strspn(value, WRAP2_WHITESPACE);
      }

      if (*value == '=') {
        *value++ = '\0';
        value += strspn(value, WRAP2_WHITESPACE);
      }
    }

    if (*value == '\0')
      value = NULL;

    key = curr_opt;

    /* Disallow missing option names (and empty option fields). */
    if (*key == '\0') {
      wrap2_log("warning: missing option name");
      continue;
    }

    /* Lookup the option-specific info and do some common error checks.
     * Delegate option-specific processing to the specific functions.
     */

    /* Advance to the matching option table entry. */
    for (opt = options_tab; opt->name && strcasecmp(opt->name, key) != 0;
      opt++);

    if (opt->name == 0) {
      wrap2_log("unknown option name: '%s'", key);
      continue;
    }

    if (!value && WRAP2_OPT_NEEDS_VAL(opt)) {
      wrap2_log("option '%s' requires value", key);
      continue;
    }

    if (value && !WRAP2_OPT_ALLOWS_VAL(opt)) {
      wrap2_log("option '%s' requires no value", key);
      continue;
    }

    if (next_opt && WRAP2_OPT_NEEDS_LAST(opt)) {
      wrap2_log("option '%s' must be the last option in the list", key);
      continue;
    }

    wrap2_log("processing option: '%s %s'", key, value ? value : "");

    res = opt->func(value);
    if (res != 0)
      return res;
  }

  return 0;
}
#endif /* WRAP2_USE_OPTIONS */

#define WRAP2_TAB_ALLOW	2
#define WRAP2_TAB_MATCH	1
#define WRAP2_TAB_DENY	-1

static int wrap2_match_table(wrap2_table_t *tab, wrap2_conn_t *conn) {
  register unsigned int i;
  int res;
  array_header *daemon_list = NULL, *client_list = NULL, *options_list = NULL;

  /* Build daemon list. */
  daemon_list = tab->tab_fetch_daemons(tab, wrap2_service_name);
  if (daemon_list == NULL ||
      daemon_list->nelts == 0) {
    wrap2_log("%s", "daemon list is empty");
    return 0;
  }

  wrap2_log("table daemon list:");
  for (i = 0; i < daemon_list->nelts; i++) {
    char **daemons = daemon_list->elts;
    wrap2_log("  %s", daemons[i] ? daemons[i] : "<null>");
  }

  /* Build client list. */
  client_list = tab->tab_fetch_clients(tab, wrap2_client_name);
  if (client_list == NULL ||
      client_list->nelts == 0) {
    wrap2_log("%s", "client list is empty");
    return 0;
  }

  wrap2_log("table client list:");
  for (i = 0; i < client_list->nelts; i++) {
    char **clients = client_list->elts;
    wrap2_log("  %s", clients[i] ? clients[i] : "<null>");
  }

  /* Build options list. */
  options_list = tab->tab_fetch_options(tab, wrap2_client_name);
  if (options_list &&
      options_list->nelts > 0) {
    wrap2_log("table options list:");
    for (i = 0; i < options_list->nelts; i++) {
      char **opts = options_list->elts;
      wrap2_log("  %s", opts[i] ? opts[i] : "<null>");
    }
  }

  res = wrap2_match_list(daemon_list, conn, wrap2_match_daemon, 0);
  if (res == FALSE) {
    return 0;
  }

  res = wrap2_match_list(client_list, conn, wrap2_match_client, 0);
  if (res == FALSE) {
    return 0;
  }

#ifdef WRAP2_USE_OPTIONS
  res = wrap2_handle_opts(options_list, conn);
  if (res == WRAP2_OPT_ALLOW) {
    return WRAP2_TAB_ALLOW;
  }

  if (res == WRAP2_OPT_DENY) {
    return WRAP2_TAB_DENY;
  }
#endif

  return WRAP2_TAB_MATCH;
}

static unsigned char wrap2_allow_access(wrap2_conn_t *conn) {
  wrap2_table_t *allow_tab = NULL, *deny_tab = NULL;
  int res = 0;

  /* If the (daemon, client) pair is matched by an entry in the allow
   * table, access is granted. Otherwise, if the (daemon, client) pair is
   * matched by an entry in the deny table, access is denied. Otherwise,
   * access is granted. A non-existent access-control table is treated as an
   * empty table.
   */

  /* Open allow table. */
  allow_tab = wrap2_open_table(wrap2_allow_table);
  if (allow_tab != NULL) {

    /* Check the allow table. */
    wrap2_log("%s", "checking allow table rules");
    res = wrap2_match_table(allow_tab, conn);

    /* Close allow table. */
    wrap2_close_table(allow_tab);
    destroy_pool(allow_tab->tab_pool);
    allow_tab = NULL;

    /* No need to check the deny table if the verdict is to explicitly allow. */
    if (res == WRAP2_TAB_ALLOW ||
        res == WRAP2_TAB_MATCH) {
      wrap2_allow_table = wrap2_deny_table = NULL;
      return TRUE;
    }

    if (res == WRAP2_TAB_DENY) {
      wrap2_allow_table = wrap2_deny_table = NULL;
      return FALSE;
    }

  } else {
    wrap2_log("error opening allow table: %s", strerror(errno));
  }

  /* Open deny table. */
  deny_tab = wrap2_open_table(wrap2_deny_table);
  if (deny_tab != NULL) {

    /* Check the deny table. */
    wrap2_log("%s", "checking deny table rules");
    res = wrap2_match_table(deny_tab, conn);

    /* Close the deny table. */
    wrap2_close_table(deny_tab);
    destroy_pool(deny_tab->tab_pool);
    deny_tab = NULL;

    if (res == WRAP2_TAB_DENY ||
        res == WRAP2_TAB_MATCH) {
      wrap2_allow_table = wrap2_deny_table = NULL;
      return FALSE; 
    }

  } else {
    wrap2_log("error opening deny table: %s", strerror(errno));
  }

  wrap2_allow_table = wrap2_deny_table = NULL;
  return TRUE;
}

/* Boolean OR expression evaluation, returning TRUE if any element in the
 * expression matches, FALSE otherwise.
 */
static unsigned char wrap2_eval_or_expression(char **acl, array_header *creds) {
  unsigned char found = FALSE;
  char *elem = NULL, **list = NULL;

  if (!acl || !*acl || !creds)
    return FALSE;

  list = (char **) creds->elts;

  for (; *acl; acl++) {
    register unsigned int i = 0;
    elem = *acl;
    found = FALSE;

    if (*elem == '!') {
      found = !found;
      elem++;
    }

    for (i = 0; i < creds->nelts; i++) {
      if (strcmp(elem, "*") == 0 || (list[i] && strcmp(elem, list[i]) == 0)) {
        found = !found;
        break;
      }
    }

    if (found)
      return TRUE;
  }

  return FALSE;
}

/* Boolean AND expression evaluation, returning TRUE if every element in the
 * expression matches, FALSE otherwise.
 */
static unsigned char wrap2_eval_and_expression(char **acl, array_header *creds) {
  unsigned char found = FALSE;
  char *elem = NULL, **list = NULL;

  if (!acl || !*acl || !creds)
    return FALSE;

  list = (char **) creds->elts;

  for (; *acl; acl++) {
    register unsigned int i = 0;
    elem = *acl;
    found = FALSE;

    if (*elem == '!') {
      found = !found;
      elem++;
    }

    for (i = 0; i < creds->nelts; i++) {
      if (list[i] && strcmp(list[i], elem) == 0) {
        found = !found;
        break;
      }
    }

    if (!found) 
      return FALSE;
  }

  return TRUE;
}

int wrap2_register(const char *srcname,
    wrap2_table_t *(*srcopen)(pool *, const char *)) {

  /* Note: I know that use of permanent_pool is discouraged as much as
   * possible, but in this particular instance, I need a pool that
   * persists across rehashes.
   *
   * Ideally, the wrap2_regtab_t struct would have a subpool member;
   * the objects would have their own pools which could then be
   * destroyed upon unregistration.
   */
  wrap2_regtab_t *regtab = pcalloc(permanent_pool, sizeof(wrap2_regtab_t));

  regtab->regtab_name = pstrdup(permanent_pool, srcname);
  regtab->regtab_open = srcopen;

  /* Add this object to the list. */
  if (wrap2_regtab_list) {
    wrap2_regtab_list->prev = regtab;
    regtab->next = wrap2_regtab_list;
  }

  wrap2_regtab_list = regtab;
  return 0;
}

int wrap2_unregister(const char *srcname) {
  if (wrap2_regtab_list) {
    register wrap2_regtab_t *regtab = NULL;

    for (regtab = wrap2_regtab_list; regtab; regtab = regtab->next) {
      if (strcmp(regtab->regtab_name, srcname) == 0) {

        if (regtab->prev) {
          regtab->prev->next = regtab->next;

        } else {
          wrap2_regtab_list = regtab->next;
        }

        if (regtab->next) {
          regtab->next->prev = regtab->prev;
        }

        regtab->prev = regtab->next = NULL;

        /* NOTE: a counter should be kept of the number of unregistrations,
         * as the memory for a registration is not freed on unregistration.
         */
        return 0;
      }
    }

    errno = ENOENT;
    return -1;
  }

  errno = EPERM;
  return -1;
}

/* "builtin" source callbacks. */

static int builtin_close_cb(wrap2_table_t *tab) {
  return 0;
}

static array_header *builtin_fetch_clients_cb(wrap2_table_t *tab,
    const char *name) {
  array_header *list = make_array(tab->tab_pool, 1, sizeof(char *));

  *((char **) push_array(list)) = pstrdup(tab->tab_pool, "ALL");
  return list;
}

static array_header *builtin_fetch_daemons_cb(wrap2_table_t *tab,
    const char *name) {
  array_header *list = make_array(tab->tab_pool, 1, sizeof(char *));

  *((char **) push_array(list)) = pstrdup(tab->tab_pool, name);
  return list;
}

static array_header *builtin_fetch_options_cb(wrap2_table_t *tab,
    const char *name) {
  return NULL;
}

static wrap2_table_t *builtin_open_cb(pool *parent_pool, const char *srcinfo) {
  wrap2_table_t *tab = NULL;
  pool *tab_pool = make_sub_pool(parent_pool);

  /* Do not allow any parameters other than 'all. */
  if (strcasecmp(srcinfo, "all") != 0) {
    wrap2_log("error: unknown builtin parameter: '%s'", srcinfo);
    destroy_pool(tab_pool);
    errno = EINVAL;
    return NULL;
  }

  tab = (wrap2_table_t *) pcalloc(tab_pool, sizeof(wrap2_table_t));
  tab->tab_pool = tab_pool;

  tab->tab_name = "builtin";

  /* Set the necessary callbacks. */
  tab->tab_close = builtin_close_cb;
  tab->tab_fetch_clients = builtin_fetch_clients_cb;
  tab->tab_fetch_daemons = builtin_fetch_daemons_cb;
  tab->tab_fetch_options = builtin_fetch_options_cb;

  return tab;
}

/* Configuration handlers
 */

/* usage: Wrap{Allow,Deny}Msg mesg */
MODRET set_wrapmsg(cmd_rec *cmd) {
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: WrapEngine on|off */
MODRET set_wrapengine(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expecting Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: WrapGroupTables group-and-expression allow-table deny-table */
MODRET set_wrapgrouptables(cmd_rec *cmd) {
  register wrap2_regtab_t *regtab = NULL;
  register unsigned int i = 0;
  unsigned char have_registration = FALSE;
  config_rec *c = NULL;
  unsigned int argc = 1;
  void **argv = NULL;
  array_header *acl = NULL;

  CHECK_ARGS(cmd, 3);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  /* Verify that the requested source types have been registered. */
  for (i = 2; i < cmd->argc-1; i++) {
    char *tmp = NULL;

    tmp = strchr(cmd->argv[i], ':');
    if (tmp == NULL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad table parameter: '",
        (char *) cmd->argv[i], "'", NULL));
    }

    *tmp = '\0';

    for (regtab = wrap2_regtab_list; regtab; regtab = regtab->next) {
      if (strcmp(regtab->regtab_name, cmd->argv[i]) == 0) {
        have_registration = TRUE;
        break;
      }
    }

    if (!have_registration) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unsupported table source type: '",
        (char *) cmd->argv[1], "'", NULL));
    }

    *tmp = ':';
  }

  c = add_config_param(cmd->argv[0], 0);
  acl = pr_expr_create(cmd->tmp_pool, &argc, (char **) &cmd->argv[0]);

  /* Build the desired config_rec manually. */
  c->argc = argc + 2;
  c->argv = pcalloc(c->pool, (argc + 3) * sizeof(void *));
  argv = c->argv;

  /* The tables are the first two parameters */
  *argv++ = pstrdup(c->pool, cmd->argv[2]);
  *argv++ = pstrdup(c->pool, cmd->argv[3]);

  /* Now populate the group-expression names */
  if (argc && acl) {
    while (argc--) {
      *argv++ = pstrdup(c->pool, *((char **) acl->elts));
      acl->elts = ((char **) acl->elts) + 1;
    }
  }

  /* Do not forget the terminating NULL */
  *argv = NULL;

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

/* usage: WrapLog file|"none" */
MODRET set_wraplog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: WrapOptions opt1 ... optN */
MODRET set_wrapoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "CheckOnConnect") == 0) {
      opts |= WRAP_OPT_CHECK_ON_CONNECT;

    } else if (strcmp(cmd->argv[i], "CheckAllNames") == 0) {
      opts |= WRAP_OPT_CHECK_ALL_NAMES;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown WrapOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: WrapServiceName <name> */
MODRET set_wrapservicename(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: WrapTables allow-table deny-table */
MODRET set_wraptables(cmd_rec *cmd) {
  register wrap2_regtab_t *regtab = NULL;
  register unsigned int i = 0;
  unsigned char have_registration = FALSE;
  config_rec *c = NULL;
  
  CHECK_ARGS(cmd, 2);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  /* Verify that the requested source types have been registered. */
  for (i = 1; i < cmd->argc-1; i++) {
    char *tmp = NULL;

    tmp = strchr(cmd->argv[i], ':');
    if (tmp == NULL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad table parameter: '",
        cmd->argv[i], "'", NULL));
    }

    *tmp = '\0';

    for (regtab = wrap2_regtab_list; regtab; regtab = regtab->next) {
      if (strcmp(regtab->regtab_name, cmd->argv[i]) == 0) {
        have_registration = TRUE;
        break;
      }
    }

    if (!have_registration) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unsupported table source type: '",
        cmd->argv[1], "'", NULL));
    }

    *tmp = ':'; 
  }

  c = add_config_param_str(cmd->argv[0], 2, cmd->argv[1], cmd->argv[2]);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: WrapUserTables user-or-expression allow-table deny-table */
MODRET set_wrapusertables(cmd_rec *cmd) {
  register wrap2_regtab_t *regtab = NULL;
  register unsigned int i = 0;
  unsigned char have_registration = FALSE;
  config_rec *c = NULL;
  unsigned int argc = 1;
  void **argv = NULL;
  array_header *acl = NULL;

  CHECK_ARGS(cmd, 3);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  /* Verify that the requested source types have been registered. */
  for (i = 2; i < cmd->argc-1; i++) {
    char *tmp = NULL;

    tmp = strchr(cmd->argv[i], ':');
    if (tmp == NULL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "bad table parameter: '",
        (char *) cmd->argv[i], "'", NULL));
    }

    *tmp = '\0';

    for (regtab = wrap2_regtab_list; regtab; regtab = regtab->next) {
      if (strcmp(regtab->regtab_name, cmd->argv[i]) == 0) {
        have_registration = TRUE;
        break;
      }
    }

    if (!have_registration) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unsupported table source type: '",
        (char *) cmd->argv[1], "'", NULL));
    }

    *tmp = ':';
  }

  c = add_config_param(cmd->argv[0], 0);
  acl = pr_expr_create(cmd->tmp_pool, &argc, (char **) &cmd->argv[0]);

  /* Build the desired config_rec manually. */
  c->argc = argc + 2;
  c->argv = pcalloc(c->pool, (argc + 3) * sizeof(void *));
  argv = c->argv;

  /* The tables are the first two parameters */
  *argv++ = pstrdup(c->pool, cmd->argv[2]);
  *argv++ = pstrdup(c->pool, cmd->argv[3]); 

  /* Now populate the user-expression names */
  if (argc && acl) {
    while (argc--) {
      *argv++ = pstrdup(c->pool, *((char **) acl->elts));
      acl->elts = ((char **) acl->elts) + 1;
    }
  }

  /* Do not forget the terminating NULL */
  *argv = NULL;

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET wrap2_pre_pass(cmd_rec *cmd) {
  wrap2_conn_t conn;
  unsigned char have_tables = FALSE;
  const char *user = NULL;
  config_rec *c = NULL;

  if (wrap2_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Hide passwords */
  session.hide_password = TRUE;

  user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
  if (user == NULL) {
    return PR_DECLINED(cmd);
  }

  wrap2_ctxt = pr_auth_get_anon_config(cmd->pool, &user, NULL, NULL);

  if (user == NULL) {
    return PR_DECLINED(cmd);
  }

  {
    /* Cheat a little here, and pre-populate some of session's members.  Do
     * not worry: these values are only temporary, and will be overwritten
     * during the login process.  This needs to be done here, before the
     * call to wrap2_allow_access(), for that function does the opening of
     * the tables.
     */
    struct passwd *pw = NULL;

    pw = pr_auth_getpwnam(cmd->pool, user);
    if (pw != NULL) {
      struct group *gr = NULL;

      /* For the dir_realpath() function to work, some session members need to
       * be set.
       */
      session.user = pstrdup(cmd->pool, pw->pw_name);

      session.login_uid = pw->pw_uid;
      session.login_gid = pw->pw_gid;

      gr = pr_auth_getgrgid(cmd->pool, session.login_gid);
      if (gr != NULL) {
        session.group = pstrdup(cmd->pool, gr->gr_name);

      } else {
        wrap2_log("unable to resolve GID for '%s'", user);
      }

    } else {
      wrap2_log("unable to resolve UID for '%s'", user);
      return PR_DECLINED(cmd);
    }
  }

  /* Search first for user-specific access tables.  Multiple WrapUserTables
   * directives are allowed.
   */
  
  c = find_config(wrap2_ctxt ? wrap2_ctxt->subset : main_server->conf,
    CONF_PARAM, "WrapUserTables", FALSE);
  while (c) {
    array_header *user_array;

    pr_signals_handle();

    user_array = make_array(cmd->tmp_pool, 0, sizeof(char *));
    *((char **) push_array(user_array)) = pstrdup(cmd->tmp_pool, user);

    /* Check the user OR expression. Do not forget the offset, to skip
     * the table name strings in c->argv.
     */
    if (wrap2_eval_or_expression((char **) &c->argv[2], user_array)) {
      wrap2_log("matched WrapUserTables expression for user '%s'", user);

      wrap2_allow_table = c->argv[0];
      wrap2_deny_table = c->argv[1];
      wrap2_client_name = session.user;

      have_tables = TRUE;
      c = NULL;

      break;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "WrapUserTables", FALSE);
  }

  /* Next, search for group-specific access tables.  Multiple WrapGroupTables
   * directives are allowed.
   */ 
  if (!have_tables) {
    c = find_config(wrap2_ctxt ? wrap2_ctxt->subset : main_server->conf,
      CONF_PARAM, "WrapGroupTables", FALSE);
  }

  while (c) {
    array_header *gid_array, *group_array;

    pr_signals_handle();

    gid_array = make_array(cmd->pool, 0, sizeof(gid_t));
    group_array = make_array(cmd->pool, 0, sizeof(char *));

    if (pr_auth_getgroups(cmd->pool, user, &gid_array, &group_array) < 1) {
      wrap2_log("no supplemental groups found for user '%s'", user);

    } else {

      /* Check the group AND expression.  Do not forget the offset, to skip
       * the table names strings in c->argv.
       */
      if (wrap2_eval_and_expression((char **) &c->argv[2], group_array)) {
        wrap2_log("matched WrapGroupTables expression for user '%s'", user);

        wrap2_allow_table = c->argv[0];
        wrap2_deny_table = c->argv[1];
        wrap2_client_name = session.group;

        have_tables = TRUE;
        c = NULL;

        break;
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "WrapGroupTables", FALSE);
  }

  /* Finally for globally-applicable access files.  Only one such directive
   * is allowed.
   */
  if (!have_tables) {
    c = find_config(wrap2_ctxt ? wrap2_ctxt->subset : main_server->conf,
      CONF_PARAM, "WrapTables", FALSE);
  }

  if (c) {
    wrap2_allow_table = c->argv[0];
    wrap2_deny_table = c->argv[1];

    wrap2_client_name = "";
    have_tables = TRUE;
  }

  if (have_tables) {
    /* Log the names of the allow/deny tables being used. */
    wrap2_log("using '%s' for allow table", wrap2_allow_table);
    wrap2_log("using '%s' for deny table", wrap2_deny_table);

  } else {
    wrap2_log("no tables configured, allowing connection");
    return PR_DECLINED(cmd);
  }

  wrap2_log("looking under service name '%s'", wrap2_service_name);

  memset(&conn, '\0', sizeof(conn));

  wrap2_conn_set(&conn, WRAP2_CONN_DAEMON, wrap2_service_name,
    WRAP2_CONN_SOCK_FD, session.c->rfd, 0);

  wrap2_log("%s", "checking access rules for connection");

  if (wrap2_allow_access(&conn) == FALSE) {
    const char *msg = NULL;

    /* Log the denied connection */
    wrap2_log("refused connection from %s", wrap2_get_client(&conn));

    /* Broadcast this event to any interested listeners.  We use the same
     * event name as mod_wrap for consistency.
     */
    pr_event_generate("mod_wrap.connection-denied", NULL);

    /* Check for a configured WrapDenyMsg.  If not present, then use the
     * default denied message.
     */
    msg = get_param_ptr(wrap2_ctxt ? wrap2_ctxt->subset : main_server->conf,
      "WrapDenyMsg", FALSE);
    if (msg != NULL) {
      msg = sreplace(cmd->tmp_pool, msg, "%u", user, NULL);
    }

    pr_response_send(R_530, "%s", msg ? msg : _("Access denied"));
    pr_session_disconnect(&wrap2_module, PR_SESS_DISCONNECT_MODULE_ACL, NULL);
  }

  wrap2_log("allowed connection from %s", wrap2_get_client(&conn));
  return PR_DECLINED(cmd);
}

MODRET wrap2_post_pass(cmd_rec *cmd) {
  const char *msg = NULL;

  if (wrap2_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Check for a configured WrapAllowMsg.  If the connection were denied,
   * it would have been terminated before reaching this command handler.
   */
  msg = get_param_ptr(wrap2_ctxt ? wrap2_ctxt->subset : main_server->conf,
    "WrapAllowMsg", FALSE);
  if (msg != NULL) {
    const char *user;

    user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
    msg = sreplace(cmd->tmp_pool, msg, "%u", user, NULL);
    pr_response_add(R_DUP, "%s", msg);
  }

  return PR_DECLINED(cmd);
}

MODRET wrap2_post_pass_err(cmd_rec *cmd) {
  if (!wrap2_engine)
    return PR_DECLINED(cmd);

  /* Clear the values from the session struct as well, specifically
   * session.user.  Failure to do so caused Bug#3727.
   */
  session.user = NULL;
  session.group = NULL;
   
  wrap2_ctxt = NULL;
  wrap2_allow_table = NULL;
  wrap2_deny_table = NULL;
  wrap2_client_name = NULL;

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

static void wrap2_exit_ev(const void *event_data, void *user_data) {
  wrap2_closelog();
  return;
}

#if defined(PR_SHARED_MODULE)
static void wrap2_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_wrap2.c", (const char *) event_data) == 0) {
    /* Unregister ourselves from all events. */
    pr_event_unregister(&wrap2_module, NULL, NULL);

    wrap2_unregister("builtin");

    if (wrap2_pool) {
      destroy_pool(wrap2_pool);
      wrap2_pool = NULL;
    }

    close(wrap2_logfd);
    wrap2_logfd = -1;
  }
}

#endif /* PR_SHARED_MODULE */

static void wrap2_restart_ev(const void *event_data, void *user_data) {

  /* Bounce the log file descriptor. */
  wrap2_closelog();
  wrap2_openlog();

  /* Reset the module's memory pool. */
  destroy_pool(wrap2_pool);
  wrap2_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(wrap2_pool, MOD_WRAP2_VERSION);
}

static void wrap2_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer; reinitialize ourselves. */

  pr_event_unregister(&wrap2_module, "core.exit", wrap2_exit_ev);
  pr_event_unregister(&wrap2_module, "core.session-reinit",
    wrap2_sess_reinit_ev);

  /* Reset defaults. */
  wrap2_engine = FALSE;
  (void) close(wrap2_logfd);
  wrap2_logfd = -1;
  wrap2_logname = NULL;
  wrap2_service_name = WRAP2_DEFAULT_SERVICE_NAME;
  wrap2_opts = 0UL;
  wrap2_allow_table = NULL;
  wrap2_deny_table = NULL;
  wrap2_client_name = NULL;

  res = wrap2_sess_init();
  if (res < 0) {
    pr_session_disconnect(&wrap2_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Initialization routines
 */

static int wrap2_init(void) {

  /* Initialize the module's memory pool. */
  if (!wrap2_pool) {
    wrap2_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(wrap2_pool, MOD_WRAP2_VERSION);
  }

#if defined(PR_SHARED_MODULE)
  pr_event_register(&wrap2_module, "core.module-unload", wrap2_mod_unload_ev,
    NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&wrap2_module, "core.restart", wrap2_restart_ev, NULL);

  /* Initialize the source object for type "builtin". */
  wrap2_register("builtin", builtin_open_cb);

  return 0;
}

static int wrap2_sess_init(void) {
  config_rec *c;

  pr_event_register(&wrap2_module, "core.session-reinit", wrap2_sess_reinit_ev,
    NULL);

  c = find_config(main_server->conf, CONF_PARAM, "WrapEngine", FALSE);
  if (c != NULL) {
    wrap2_engine = *((int *) c->argv[0]);
  }

  if (wrap2_engine == FALSE) {
    return 0;
  }

  wrap2_openlog();

  /* Look up any configured WrapServiceName */
  wrap2_service_name = get_param_ptr(main_server->conf, "WrapServiceName",
    FALSE);
  if (wrap2_service_name == NULL)
    wrap2_service_name = WRAP2_DEFAULT_SERVICE_NAME;

  /* Make sure that tables will be closed when the child exits. */
  pr_event_register(&wrap2_module, "core.exit", wrap2_exit_ev, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "WrapOptions", FALSE);
  while (c != NULL) {
    unsigned long opts;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    wrap2_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "WrapOptions", FALSE);
  }

  if (wrap2_opts & WRAP_OPT_CHECK_ON_CONNECT) {
    c = find_config(main_server->conf, CONF_PARAM, "WrapTables", FALSE);
    if (c) {
      wrap2_conn_t conn;

      wrap2_allow_table = c->argv[0];
      wrap2_deny_table = c->argv[1];
      wrap2_client_name = "";

      wrap2_log("using '%s' for allow table", wrap2_allow_table);
      wrap2_log("using '%s' for deny table", wrap2_deny_table);
      wrap2_log("looking under service name '%s'", wrap2_service_name);

      memset(&conn, '\0', sizeof(conn));
      wrap2_conn_set(&conn, WRAP2_CONN_DAEMON, wrap2_service_name,
        WRAP2_CONN_SOCK_FD, session.c->rfd, 0);

      wrap2_log("%s", "checking access rules for connection");

      if (wrap2_allow_access(&conn) == FALSE) {
        const char *msg = NULL;

        /* Log the denied connection */
        wrap2_log("refused connection from %s", wrap2_get_client(&conn));

        /* Broadcast this event to any interested listeners.  We use the same
         * event name as mod_wrap for consistency.
         */
        pr_event_generate("mod_wrap.connection-denied", NULL);

        /* Check for a configured WrapDenyMsg.  If not present, then use the
         * default denied message.
         */
        msg = get_param_ptr(main_server->conf, "WrapDenyMsg", FALSE);
        if (msg != NULL) {
          msg = sreplace(session.pool, msg, "%u", "unknown", NULL);
        }

        pr_response_send(R_530, "%s", msg ? msg : _("Access denied"));
        pr_session_disconnect(&wrap2_module, PR_SESS_DISCONNECT_MODULE_ACL,
          NULL);
      }
    }
  }

  return 0;
}

/* Module API tables
 */

static conftable wrap2_conftab[] = {
  { "WrapAllowMsg",		set_wrapmsg,		NULL },
  { "WrapDenyMsg",		set_wrapmsg,		NULL },
  { "WrapEngine",		set_wrapengine,		NULL },
  { "WrapGroupTables",		set_wrapgrouptables,	NULL },
  { "WrapLog",			set_wraplog,		NULL },
  { "WrapOptions",		set_wrapoptions,	NULL },
  { "WrapServiceName",		set_wrapservicename,	NULL },
  { "WrapTables",		set_wraptables,		NULL },
  { "WrapUserTables",		set_wrapusertables,	NULL },
  { NULL }
};

static cmdtable wrap2_cmdtab[] = {
  { PRE_CMD,	C_PASS,	G_NONE,	wrap2_pre_pass,		FALSE,	FALSE },
  { POST_CMD,	C_PASS,	G_NONE,	wrap2_post_pass,	FALSE,	FALSE },
  { POST_CMD_ERR,C_PASS,G_NONE,	wrap2_post_pass_err,	FALSE,	FALSE },
  { 0, NULL }
};

module wrap2_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "wrap2",

  /* Mmodule configuration handler table */
  wrap2_conftab,

  /* Module command handler table */
  wrap2_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  wrap2_init,

  /* Session initialization */
  wrap2_sess_init,

  /* Module version */
  MOD_WRAP2_VERSION
};
