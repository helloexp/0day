/*
 * ProFTPD: mod_dnsbl -- a module for checking DNSBL (DNS Black Lists)
 *                       servers before allowing a connection
 * Copyright (c) 2007-2016 TJ Saunders
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
 * This is mod_dnsbl, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "mod_dnsbl.h"

/* The C_ANY macro is defined in ProFTPD's ftp.h file for "any" FTP command,
 * and may conflict with the DNS macros.  This module does not use ProFTPD's
 * C_ANY macro, so remove it and avoid the collision.
 */
#undef C_ANY

#include <arpa/nameser.h>
#include <resolv.h>

#define DNSBL_REASON_MAX_LEN		256

module dnsbl_module;

static int dnsbl_engine = FALSE;
static int dnsbl_logfd = -1;

static const char *trace_channel = "dnsbl";

/* Necessary prototypes. */
static int dnsbl_sess_init(void);

typedef enum {
  DNSBL_POLICY_ALLOW_DENY,
  DNSBL_POLICY_DENY_ALLOW

} dnsbl_policy_e;

static const char *reverse_ip_addr(pool *p, const char *ip_addr) {
  char *addr2, *res, *tmp;
  size_t addrlen = strlen(ip_addr) +1;

  res = pcalloc(p, addrlen);
  addr2 = pstrdup(p, ip_addr);
 
  tmp = strrchr(addr2, '.');
  sstrcat(res, tmp+1, addrlen);
  sstrcat(res, ".", addrlen);
  *tmp = '\0';

  tmp = strrchr(addr2, '.');
  sstrcat(res, tmp+1, addrlen);
  sstrcat(res, ".", addrlen);
  *tmp = '\0';

  tmp = strrchr(addr2, '.');
  sstrcat(res, tmp+1, addrlen);
  sstrcat(res, ".", addrlen);
  *tmp = '\0';

  sstrcat(res, addr2, addrlen);
  return res;
}

static const char *get_reversed_addr(pool *p) {
  const char *ipstr = NULL;

  if (pr_netaddr_get_family(session.c->remote_addr) == AF_INET) {
    ipstr = pr_netaddr_get_ipstr(session.c->remote_addr);

#ifdef PR_USE_IPV6
  } else {
    if (pr_netaddr_use_ipv6() &&
        pr_netaddr_get_family(session.c->remote_addr) == AF_INET6 &&
        pr_netaddr_is_v4mappedv6(session.c->remote_addr) == TRUE) {
      const char *ipv6str = pr_netaddr_get_ipstr(session.c->remote_addr);
      pr_netaddr_t *tmp = pr_netaddr_alloc(p);

      pr_netaddr_set_family(tmp, AF_INET);
      pr_netaddr_set_port(tmp, pr_netaddr_get_port(session.c->remote_addr));
      memcpy(&tmp->na_addr.v4.sin_addr,
        (((char *) pr_netaddr_get_inaddr(session.c->remote_addr)) + 12),
        sizeof(struct in_addr));

      ipstr = pr_netaddr_get_ipstr(tmp);

      (void) pr_log_writefile(dnsbl_logfd, MOD_DNSBL_VERSION,
        "client address '%s' is an IPv4-mapped IPv6 address, treating it as "
        "IPv4 address '%s'", ipv6str, ipstr);

    } else {
      return NULL;
    }
#endif /* PR_USE_IPV6 */
  }

  return reverse_ip_addr(p, ipstr);
}

static void lookup_reason(pool *p, const char *name) {
  int reasonlen;
  unsigned char reason[NS_PACKETSZ];

  reasonlen = res_query(name, ns_c_in, ns_t_txt, reason, sizeof(reason));
  if (reasonlen > 0) {
    ns_msg handle;
    int rrno;

    /* Now we get the unenviable task of hand-parsing the response record,
     * trying to get at the actual text message contained within.
     */

    if (ns_initparse(reason, reasonlen, &handle) < 0) {
      (void) pr_log_writefile(dnsbl_logfd, MOD_DNSBL_VERSION,
        "error initialising nameserver response parser: %s", strerror(errno));
      return;
    }

    for (rrno = 0; rrno < ns_msg_count(handle, ns_s_an); rrno++) {
      ns_rr rr;

      if (ns_parserr(&handle, ns_s_an, rrno, &rr) < 0) {
        (void) pr_log_writefile(dnsbl_logfd, MOD_DNSBL_VERSION,
          "error parsing resource record %d: %s", rrno, strerror(errno));
        continue;
      }

      if (ns_rr_type(rr) == ns_t_txt) {
        char *reject_reason;
        size_t len = ns_rr_rdlen(rr);

        reject_reason = pcalloc(p, len+1);
        memcpy(reject_reason, (unsigned char *) ns_rr_rdata(rr), len);

        (void) pr_log_writefile(dnsbl_logfd, MOD_DNSBL_VERSION,
         "reason for blacklisting client address: '%s'", reject_reason);
      }
    }
  }

  return;
}

static int lookup_addr(pool *p, const char *addr, const char *domain) {
  const pr_netaddr_t *reject_addr = NULL;
  const char *name = pstrcat(p, addr, ".", domain, NULL);

  (void) pr_log_writefile(dnsbl_logfd, MOD_DNSBL_VERSION,
    "for DNSBLDomain '%s', resolving DNS name '%s'", domain, name);

  reject_addr = pr_netaddr_get_addr(p, name, NULL);
  if (reject_addr) {
    (void) pr_log_writefile(dnsbl_logfd, MOD_DNSBL_VERSION,
      "found record for DNS name '%s', client address has been blacklisted",
      name);

    /* Check for TXT record for this DNS name, to see if the reason for
     * blacklisting has been configured.
     */
    lookup_reason(p, name);
    return -1;
  }

  (void) pr_log_writefile(dnsbl_logfd, MOD_DNSBL_VERSION,
    "no record returned for DNS name '%s', client address is not blacklisted",
    name);
  return 0;
}

static int dnsbl_reject_conn(void) {
  config_rec *c;
  pool *tmp_pool = NULL;
  const char *rev_ip_addr = NULL;
  int reject_conn = FALSE;
  dnsbl_policy_e policy = DNSBL_POLICY_DENY_ALLOW;

  c = find_config(main_server->conf, CONF_PARAM, "DNSBLPolicy", FALSE);
  if (c) {
    policy = *((dnsbl_policy_e *) c->argv[0]);
  }

  switch (policy) {
    case DNSBL_POLICY_ALLOW_DENY:
      pr_trace_msg(trace_channel, 8,
        "using policy of allowing connections unless listed by DNSBLDomains");
      reject_conn = FALSE;
      break;

    case DNSBL_POLICY_DENY_ALLOW:
      pr_trace_msg(trace_channel, 8,
        "using policy of rejecting connections unless listed by DNSBLDomains");
      reject_conn = TRUE;
      break;
  }

  tmp_pool = make_sub_pool(permanent_pool);
  rev_ip_addr = get_reversed_addr(tmp_pool);
  if (rev_ip_addr == NULL) {
    (void) pr_log_writefile(dnsbl_logfd, MOD_DNSBL_VERSION,
      "client address '%s' is an IPv6 address, skipping",
      pr_netaddr_get_ipstr(session.c->remote_addr));
    destroy_pool(tmp_pool);
    return -1;
  }

  switch (policy) {
    /* For this policy, the connection will be allowed unless the connecting
     * client is listed by any of the DNSBLDomain sites.
     */
    case DNSBL_POLICY_ALLOW_DENY: {
      c = find_config(main_server->conf, CONF_PARAM, "DNSBLDomain", FALSE);
      while (c) {
        const char *domain;
    
        pr_signals_handle();

        domain = c->argv[0];

        if (lookup_addr(tmp_pool, rev_ip_addr, domain) < 0) {
          (void) pr_log_writefile(dnsbl_logfd, MOD_DNSBL_VERSION,
            "client address '%s' is listed by DNSBLDomain '%s', rejecting "
            "connection", pr_netaddr_get_ipstr(session.c->remote_addr), domain);
          reject_conn = TRUE;
          break;
        }

        c = find_config_next(c, c->next, CONF_PARAM, "DNSBLDomain", FALSE);
      }

      break;
    }

    /* For this policy, the connection will be NOT allowed unless the
     * connecting client is listed by any of the DNSBLDomain sites.
     */
    case DNSBL_POLICY_DENY_ALLOW: {
      c = find_config(main_server->conf, CONF_PARAM, "DNSBLDomain", FALSE);
      while (c) {
        const char *domain;

        pr_signals_handle();

        domain = c->argv[0];

        if (lookup_addr(tmp_pool, rev_ip_addr, domain) < 0) {
          (void) pr_log_writefile(dnsbl_logfd, MOD_DNSBL_VERSION,
            "client address '%s' is listed by DNSBLDomain '%s', allowing "
            "connection", pr_netaddr_get_ipstr(session.c->remote_addr), domain);
          reject_conn = FALSE;
          break;
        }
    
        c = find_config_next(c, c->next, CONF_PARAM, "DNSBLDomain", FALSE);
      } 

      break; 
    }
  }

  destroy_pool(tmp_pool);

  if (reject_conn) {
    return TRUE;
  }

  return FALSE;
}

/* Configuration handlers
 */

/* usage: DNSBLDomain domain */
MODRET set_dnsbldomain(cmd_rec *cmd) {
  char *domain;
  config_rec *c;
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  domain = cmd->argv[1];

  /* Ignore leading '.' in domain, if present. */
  if (*domain == '.')
    domain++;

  c = add_config_param_str(cmd->argv[0], 1, domain);
  c->flags |= CF_MERGEDOWN_MULTI;

  return PR_HANDLED(cmd);
}

/* usage: DNSBLEngine on|off */
MODRET set_dnsblengine(cmd_rec *cmd) {
  int bool;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: DNSBLLog path|"none" */
MODRET set_dnsbllog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (pr_fs_valid_path(cmd->argv[1]) < 0)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": ", cmd->argv[1],
      " is not a valid path", NULL));

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: DNSBLPolicy "allow,deny"|"deny,allow" */
MODRET set_dnsblpolicy(cmd_rec *cmd) {
  dnsbl_policy_e policy;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "allow,deny") == 0) {
    policy = DNSBL_POLICY_ALLOW_DENY;
  
  } else if (strcasecmp(cmd->argv[1], "deny,allow") == 0) {
    policy = DNSBL_POLICY_DENY_ALLOW;

  } else {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": '", cmd->argv[1],
      "' is not one of the approved DNSBLPolicy settings", NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(dnsbl_policy_e));
  *((dnsbl_policy_e *) c->argv[0]) = policy;

  return PR_HANDLED(cmd);
}

/* Event listeners
 */

/* Initialization functions
 */

static void dnsbl_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&dnsbl_module, "core.session-reinit",
    dnsbl_sess_reinit_ev);

  (void) close(dnsbl_logfd);
  dnsbl_logfd = -1;

  res = dnsbl_sess_init();
  if (res < 0) {
    pr_session_disconnect(&dnsbl_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

static int dnsbl_sess_init(void) {
  config_rec *c;

  pr_event_register(&dnsbl_module, "core.session-reinit", dnsbl_sess_reinit_ev,
    NULL);

  c = find_config(main_server->conf, CONF_PARAM, "DNSBLEngine", FALSE);
  if (c &&
      *((unsigned int *) c->argv[0]) == TRUE) {
    dnsbl_engine = TRUE;

  } else {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "DNSBLLog", FALSE);
  if (c &&
      strcasecmp(c->argv[0], "none") != 0) {
    int res, xerrno = 0;

    PRIVS_ROOT
    res = pr_log_openfile(c->argv[0], &dnsbl_logfd, 0600);
    xerrno = errno;
    PRIVS_RELINQUISH

    switch (res) {
      case -1:
        pr_log_pri(PR_LOG_NOTICE, MOD_DNSBL_VERSION
          ": notice: unable to open DNSBLLog '%s': %s", (char *) c->argv[0],
          strerror(xerrno));
        break;

      case PR_LOG_WRITABLE_DIR:
        pr_log_pri(PR_LOG_WARNING, MOD_DNSBL_VERSION
          ": notice: unable to use DNSBLLog '%s': parent directory is "
            "world-writable", (char *) c->argv[0]);
        break;

      case PR_LOG_SYMLINK:
        pr_log_pri(PR_LOG_WARNING, MOD_DNSBL_VERSION
          ": notice: unable to use DNSBLLog '%s': cannot log to a symlink",
          (char *) c->argv[0]);
        break;
    }
  }

  if (dnsbl_reject_conn() == TRUE) {
    (void) pr_log_writefile(dnsbl_logfd, MOD_DNSBL_VERSION,
      "client not allowed by DNSBLPolicy, rejecting connection");
    errno = EACCES;
    return -1;
  }

  return 0;
}

/* Module API tables
 */

static conftable dnsbl_conftab[] = {
  { "DNSBLDomain",	set_dnsbldomain,	NULL },
  { "DNSBLEngine",	set_dnsblengine,	NULL },
  { "DNSBLLog",		set_dnsbllog,		NULL },
  { "DNSBLPolicy",	set_dnsblpolicy,	NULL },
  { NULL }
};

module dnsbl_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "dnsbl",

  /* Module configuration handler table */
  dnsbl_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  NULL,

  /* Session initialization function */
  dnsbl_sess_init,

  /* Module version */
  MOD_DNSBL_VERSION
};
