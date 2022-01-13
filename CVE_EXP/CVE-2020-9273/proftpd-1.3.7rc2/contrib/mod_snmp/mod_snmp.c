/*
 * ProFTPD - mod_snmp
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
 *
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Archive: mod_snmp.a $
 */

#include "mod_snmp.h"
#include "asn1.h"
#include "db.h"
#include "mib.h"
#include "packet.h"
#include "pdu.h"
#include "msg.h"
#include "notify.h"

/* Defaults */
#define SNMP_DEFAULT_AGENT_PORT		161
#define SNMP_DEFAULT_TRAP_PORT		162

/* Agent type/role */
#define SNMP_AGENT_TYPE_MASTER		1
#define SNMP_AGENT_TYPE_AGENTX		2

extern xaset_t *server_list;

module snmp_module;

int snmp_logfd = -1;
pool *snmp_pool = NULL;
conn_t *snmp_conn = NULL;
struct timeval snmp_start_tv;
int snmp_proto_udp = IPPROTO_UDP;

/* mod_snmp option flags */
#define SNMP_OPT_RESTART_CLEARS_COUNTERS		0x0001

static pid_t snmp_agent_pid = 0;
static int snmp_enabled = TRUE;
static int snmp_engine = FALSE;
static const char *snmp_logname = NULL;
static unsigned long snmp_opts = 0UL;

static const char *snmp_community = NULL;

/* The list of SNMPNotify receivers/managers to which to send notifications. */
static array_header *snmp_notifys = NULL;

/* This number defined as the maximum 'max-bindings' value in RFC19105; it's
 * good enough for the default maximum number of variables in a bindings list
 * to process.
 */
static unsigned int snmp_max_variables = SNMP_PDU_MAX_BINDINGS;

/* Number of seconds to wait for the SNMP agent process to stop before
 * we terminate it with extreme prejudice.
 *
 * Currently this has a granularity of seconds; needs to be in millsecs
 * (e.g. for 500 ms timeout).
 */
static time_t snmp_agent_timeout = 1;

static off_t snmp_retr_bytes = 0, snmp_stor_bytes = 0;

static const char *trace_channel = "snmp";

static int snmp_check_class_access(xaset_t *set, const char *name,
    struct snmp_packet *pkt) {
  config_rec *c;
  int ok = FALSE;

  /* If no class was found for this session, short-circuit the check.
   * Note: this is an optimization that can/should be applied to the
   * core engine as well, e.g. in the proftpd-1.3.5 devel cycle.
   */
  if (pkt->remote_class == NULL) {
    return ok;
  }

  /* XXX Note: the pr_expr_eval_class_* functions assume the use of the
   * global session variable.  They should be refactored to take the
   * class as an argument.
   */

#if PROFTPD_VERSION_NUMBER >= 0x0001030501
  session.conn_class = pkt->remote_class;
#else
  session.class = pkt->remote_class;
#endif /* ProFTPD-1.3.5rc1 and later */

  c = find_config(set, CONF_PARAM, name, FALSE);
  while (c) {
    pr_signals_handle();

#ifdef PR_USE_REGEX
    if (*((unsigned char *) c->argv[0]) == PR_EXPR_EVAL_REGEX) {
      pr_regex_t *pre = (pr_regex_t *) c->argv[1];

      if (pkt->remote_class != NULL &&
          pr_regexp_exec(pre, pkt->remote_class->cls_name, 0, NULL,
            0, 0, 0) == 0) {
        ok = TRUE;
        break;
      }

    } else
#endif /* regex support */

    if (*((unsigned char *) c->argv[0]) == PR_EXPR_EVAL_OR) {
      ok = pr_expr_eval_class_or((char **) &c->argv[1]);
      if (ok == TRUE)
        break;

    } else if (*((unsigned char *) c->argv[0]) == PR_EXPR_EVAL_AND) {
      ok = pr_expr_eval_class_and((char **) &c->argv[1]);
      if (ok == TRUE)
        break;
    }

    c = find_config_next(c, c->next, CONF_PARAM, name, FALSE);
  }

#if PROFTPD_VERSION_NUMBER >= 0x0001030501
  session.conn_class = NULL;
#else
  session.class = NULL;
#endif /* ProFTPD-1.3.5rc1 and later */

  return ok;
}

static int snmp_check_ip_positive(const config_rec *c,
    struct snmp_packet *pkt) {
  int aclc;
  pr_netacl_t **aclv;

  for (aclc = c->argc, aclv = (pr_netacl_t **) c->argv; aclc; aclc--, aclv++) {
    if (pr_netacl_get_negated(*aclv) == TRUE) {
      continue;
    }

    switch (pr_netacl_match(*aclv, pkt->remote_addr)) {
      case 1:
        /* Found it! */
        return TRUE;

      case -1:
        /* Special value "NONE", meaning nothing can match, so we can
         * short-circuit on this as well.
         */
        return FALSE;

      default:
        /* No match, keep trying */
        break;
    }
  }

  return FALSE;
}

static int snmp_check_ip_negative(const config_rec *c,
    struct snmp_packet *pkt) {
  int aclc;
  pr_netacl_t **aclv;

  for (aclc = c->argc, aclv = (pr_netacl_t **) c->argv; aclc; aclc--, aclv++) {
    if (pr_netacl_get_negated(*aclv) == FALSE) {
      continue;
    }

    switch (pr_netacl_match(*aclv, pkt->remote_addr)) {
      case 1:
        /* This actually means we DID NOT match, and it's ok to short circuit
         * everything (negative).
         */
        return FALSE;

      case -1:
        /* -1 signifies a NONE match, which isn't valid for negative
         * conditions.
         */
        pr_log_pri(PR_LOG_NOTICE, MOD_SNMP_VERSION
          ": ooops, it looks like !NONE was used in an ACL somehow");
        return FALSE;

      default:
        /* This means our match is actually true and we can continue */
        break;
    }
  }

  /* If we got this far either all conditions were TRUE or there were no
   * conditions.
   */

  return TRUE;
}

static int snmp_check_ip_access(xaset_t *set, const char *name,
    struct snmp_packet *pkt) {
  config_rec *c;
  int ok = FALSE;

  c = find_config(set, CONF_PARAM, name, FALSE);
  while (c) {
    pr_signals_handle();

    if (snmp_check_ip_negative(c, pkt) != TRUE) {
      ok = FALSE;
      break;
    }

    if (snmp_check_ip_positive(c, pkt) == TRUE) {
      ok = TRUE;
      break;
    }

    c = find_config_next(c, c->next, CONF_PARAM, name, FALSE);
  }

  return ok;
}

static int snmp_check_allow_limit(config_rec *c, struct snmp_packet *pkt) {
  unsigned char *allow_all = NULL;

  if (pkt->remote_class != NULL) {
    if (snmp_check_class_access(c->subset, "AllowClass", pkt)) {
      return 1;
    }
  }

  if (snmp_check_ip_access(c->subset, "Allow", pkt)) {
    return 1;
  }

  allow_all = get_param_ptr(c->subset, "AllowAll", FALSE);
  if (allow_all != NULL &&
      *allow_all == TRUE) {
    return 1;
  }

  return 0;
}

static int snmp_check_deny_limit(config_rec *c, struct snmp_packet *pkt) {
  unsigned char *deny_all;

  deny_all = get_param_ptr(c->subset, "DenyAll", FALSE);
  if (deny_all != NULL &&
      *deny_all == TRUE) {
    return 1;
  }

  if (pkt->remote_class != NULL) {
    if (snmp_check_class_access(c->subset, "DenyClass", pkt)) {
      return 1;
    }
  }

  if (snmp_check_ip_access(c->subset, "Deny", pkt)) {
    return 1;
  }

  return 0;
}

static int snmp_check_limit(config_rec *c, struct snmp_packet *pkt) {
  int *ptr = get_param_ptr(c->subset, "Order", FALSE);
  int order = ptr ? *ptr : ORDER_ALLOWDENY;

  if (order == ORDER_DENYALLOW) {
    /* Check deny first */

    if (snmp_check_deny_limit(c, pkt)) {
      /* Explicit deny */
      errno = EPERM;
      return -2;
    }

    if (snmp_check_allow_limit(c, pkt)) {
      /* Explicit allow */
      return 1;
    }

    /* Implicit deny */
    errno = EPERM;
    return -1;
  }

  /* Check allow first */
  if (snmp_check_allow_limit(c, pkt)) {
    /* Explicit allow */
    return 1;
  }

  if (snmp_check_deny_limit(c, pkt)) {
    /* Explicit deny */
    errno = EPERM;
    return -2;
  }

  /* Implicit allow */
  return 0;
}

/* Similar to the login_check_limits() function from src/dirtree.c, except
 * that we assume some of the argument values (and thus don't need them
 * from callers), we don't handle the per-user/group ACLs, and we look
 * for <Limit SNMP> sections.
 */
static int snmp_limits_allow(xaset_t *set, struct snmp_packet *pkt) {
  config_rec *c = NULL;
  int ok = FALSE;
  int found = 0;

  if (set == NULL ||
      set->xas_list == NULL) {
    /* Allow by default */
    return TRUE;
  }

  for (c = (config_rec *) set->xas_list; c; c = c->next) {
    int argc = -1;
    char **argv = NULL;

    if (c->config_type != CONF_LIMIT) {
      continue;
    }

    argc = c->argc;
    argv = (char **) c->argv;     

    for (; argc; argc--, argv++) {
      if (strncasecmp(*argv, "SNMP", 5) == 0) {
        break;
      }
    }

    if (argc > 0) {
      switch (snmp_check_limit(c, pkt)) {
        case 1:
          ok = TRUE;
          found++;
          break;

        case -1:
        case -2:
          found++;
          break;
      }
    }
  }

  if (found == 0) {
    /* Allow by default. */
    ok = TRUE;
  }

  return ok;
}

static int snmp_security_check(struct snmp_packet *pkt) {
  int res = 0;

  switch (pkt->snmp_version) {
    case SNMP_PROTOCOL_VERSION_1:
    case SNMP_PROTOCOL_VERSION_2:
      /* Check the community string against the configured SNMPCommunity. */
      if (strncmp(snmp_community, pkt->community, pkt->community_len) != 0) {
        (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
          "%s message community '%s' does not match configured community, "
          "ignoring message", snmp_msg_get_versionstr(pkt->snmp_version),
          pkt->community);

        /* XXX Send authenticationFailure trap to SNMPNotify address */

        res = snmp_db_incr_value(pkt->pool,
          SNMP_DB_SNMP_F_PKTS_AUTH_ERR_TOTAL, 1);
        if (res < 0) {
          (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
            "error incrementing snmp.packetsAuthFailedTotal: %s",
            strerror(errno));
        }

        errno = EACCES;
        return -1;
      }
      break;

    case SNMP_PROTOCOL_VERSION_3:
      /* XXX Not supported yet */
      errno = ENOSYS;
      return -1;
  }

  return res;
}

static int snmp_mkdir(const char *dir, uid_t uid, gid_t gid, mode_t mode) {
  mode_t prev_mask;
  struct stat st;
  int res = -1;

  pr_fs_clear_cache2(dir);
  res = pr_fsio_stat(dir, &st);

  if (res == -1 &&
      errno != ENOENT) {
    return -1;
  }

  /* The directory already exists. */
  if (res == 0) {
    return 0;
  }

  /* The given mode is absolute, not subject to any Umask setting. */
  prev_mask = umask(0);

  if (pr_fsio_mkdir(dir, mode) < 0) {
    int xerrno = errno;

    (void) umask(prev_mask);
    errno = xerrno;
    return -1;
  }

  umask(prev_mask);

  if (pr_fsio_chown(dir, uid, gid) < 0) {
    return -1;
  }

  return 0;
}

static int snmp_mkpath(pool *p, const char *path, uid_t uid, gid_t gid,
    mode_t mode) {
  char *currpath = NULL, *tmppath = NULL;
  struct stat st;

  pr_fs_clear_cache2(path);
  if (pr_fsio_stat(path, &st) == 0) {
    /* Path already exists, nothing to be done. */
    errno = EEXIST;
    return -1;
  }

  tmppath = pstrdup(p, path);

  currpath = "/";
  while (tmppath && *tmppath) {
    char *currdir = strsep(&tmppath, "/");
    currpath = pdircat(p, currpath, currdir, NULL);

    if (snmp_mkdir(currpath, uid, gid, mode) < 0) {
      return -1;
    }

    pr_signals_handle();
  }

  return 0;
}

static int snmp_openlog(void) {
  int res = 0;
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "SNMPLog", FALSE);
  if (c) {
    snmp_logname = c->argv[0];

    if (strncasecmp(snmp_logname, "none", 5) != 0) {
      int xerrno;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(snmp_logname, &snmp_logfd, 0600);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      if (res < 0) {
        if (res == -1) {
          pr_log_pri(PR_LOG_NOTICE, MOD_SNMP_VERSION
            ": notice: unable to open SNMPLog '%s': %s", snmp_logname,
            strerror(xerrno));

        } else if (res == PR_LOG_WRITABLE_DIR) {
          pr_log_pri(PR_LOG_WARNING, MOD_SNMP_VERSION
            ": notice: unable to open SNMPLog '%s': parent directory is "
            "world-writable", snmp_logname);

        } else if (res == PR_LOG_SYMLINK) {
          pr_log_pri(PR_LOG_WARNING, MOD_SNMP_VERSION
            ": notice: unable to open SNMPLog '%s': cannot log to a symlink",
            snmp_logname);
        }
      }
    }
  }

  return res;
}

/* We don't want to do the full daemonize() as provided in main.c; we
 * already forked.
 */
static void snmp_daemonize(const char *daemon_dir) {
#ifndef HAVE_SETSID
  int tty_fd;
#endif

#ifdef HAVE_SETSID
  /* setsid() is the preferred way to disassociate from the
   * controlling terminal
   */
  setsid();
#else
  /* Open /dev/tty to access our controlling tty (if any) */
  tty_fd = open("/dev/tty", O_RDWR);
  if (tty_fd != -1) {
    if (ioctl(tty_fd, TIOCNOTTY, NULL) == -1) {
      perror("ioctl");
      exit(1);
    }

    close(tty_fd);
  }
#endif /* HAVE_SETSID */

  /* Close the three big boys. */
  close(fileno(stdin));
  close(fileno(stdout));
  close(fileno(stderr));

  /* Portable way to prevent re-acquiring a tty in the future */

#ifdef HAVE_SETPGID
  setpgid(0, getpid());

#else
# ifdef SETPGRP_VOID
  setpgrp();

# else
  setpgrp(0, getpid());
# endif /* SETPGRP_VOID */
#endif /* HAVE_SETPGID */

  pr_fsio_chdir(daemon_dir, 0);
}

static int snmp_agent_handle_get(struct snmp_packet *pkt) {
  struct snmp_var *iter_var = NULL, *head_var = NULL, *tail_var = NULL;
  unsigned int var_count = 0;
  int res;

  if (pkt->req_pdu->varlist == NULL) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "missing request PDU variable bindings list, rejecting invalid request");
    errno = EINVAL;
    return -1;
  }

  pkt->resp_pdu = snmp_pdu_dup(pkt->pool, pkt->req_pdu);
  pkt->resp_pdu->request_type = SNMP_PDU_RESPONSE;

  if (pkt->req_pdu->varlistlen > snmp_max_variables) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "%s %s of too many OIDs (%u, max %u)",
      snmp_msg_get_versionstr(pkt->snmp_version),
      snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
      pkt->req_pdu->varlistlen, snmp_max_variables);

    pkt->resp_pdu->err_code = SNMP_ERR_TOO_BIG;
    pkt->resp_pdu->err_idx = 0;

    return 0;
  }

  for (iter_var = pkt->req_pdu->varlist; iter_var; iter_var = iter_var->next) { 
    struct snmp_mib *mib = NULL;
    struct snmp_var *resp_var = NULL;
    int32_t mib_int = -1;
    char *mib_str = NULL;
    size_t mib_strlen = 0;
    int lacks_instance_id = FALSE;

    pr_signals_handle();

    mib = snmp_mib_get_by_oid(iter_var->name, iter_var->namelen,
      &lacks_instance_id);
    if (mib == NULL) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "%s %s of unknown OID %s (lacks instance ID = %s)",
        snmp_msg_get_versionstr(pkt->snmp_version),
        snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
        snmp_asn1_get_oidstr(pkt->req_pdu->pool, iter_var->name,
          iter_var->namelen), lacks_instance_id ? "true" : "false");

      /* If SNMPv1, then set the err_code/err_idx values, and duplicate the
       * varlist.
       *
       * If SNMPv2, then leave err_code/err_idex values set to zero, but
       * create a var of exception 'noSuchObject' or 'noSuchInstance' as
       * appropriate.
       */

      switch (pkt->snmp_version) {
        case SNMP_PROTOCOL_VERSION_1:
          pkt->resp_pdu->err_code = SNMP_ERR_NO_SUCH_NAME;
          pkt->resp_pdu->err_idx = var_count + 1;
          pkt->resp_pdu->varlist = snmp_smi_dup_var(pkt->pool,
            pkt->req_pdu->varlist);
          pkt->resp_pdu->varlistlen = pkt->req_pdu->varlistlen;
          break;

        case SNMP_PROTOCOL_VERSION_2:
        case SNMP_PROTOCOL_VERSION_3:
          resp_var = snmp_smi_create_exception(pkt->pool, iter_var->name,
            iter_var->namelen, lacks_instance_id ? SNMP_SMI_NO_SUCH_INSTANCE :
              SNMP_SMI_NO_SUCH_OBJECT);
          break;
      }

      if (resp_var == NULL) {
        return 0;
      }
    }

    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "%s %s of OID %s (%s)", snmp_msg_get_versionstr(pkt->snmp_version),
      snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
      snmp_asn1_get_oidstr(iter_var->pool, iter_var->name, iter_var->namelen),
      mib ? mib->instance_name : "unknown");

    /* A response variable may be have generated above, e.g. when the MIB
     * not known/supported.
     */
    if (resp_var == NULL) { 
      res = snmp_db_get_value(pkt->pool, mib->db_field, &mib_int, &mib_str,
        &mib_strlen);

      /* XXX Response with genErr instead? */
      if (res < 0) {
        int xerrno = errno;

        (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
          "error retrieving database value for field %s: %s",
          snmp_db_get_fieldstr(pkt->pool, mib->db_field), strerror(xerrno));
        errno = xerrno;
        return -1;
      }

      resp_var = snmp_smi_create_var(pkt->pool, mib->mib_oid, mib->mib_oidlen,
        mib->smi_type, mib_int, mib_str, mib_strlen);
    }

    var_count = snmp_smi_util_add_list_var(&head_var, &tail_var, resp_var);
  }

  pkt->resp_pdu->varlist = head_var;
  pkt->resp_pdu->varlistlen = var_count;

  return 0;
}

static int snmp_agent_handle_getnext(struct snmp_packet *pkt) {
  struct snmp_var *iter_var = NULL, *head_var = NULL, *tail_var = NULL;
  unsigned int var_count = 0;
  int max_idx, res;

  if (pkt->req_pdu->varlist == NULL) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "missing request PDU variable bindings list, rejecting invalid request");
    errno = EINVAL;
    return -1;
  }

  pkt->resp_pdu = snmp_pdu_dup(pkt->pool, pkt->req_pdu);
  pkt->resp_pdu->request_type = SNMP_PDU_RESPONSE;

  if (pkt->req_pdu->varlistlen > snmp_max_variables) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "%s %s of too many OIDs (%u, max %u)",
      snmp_msg_get_versionstr(pkt->snmp_version),
      snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
      pkt->req_pdu->varlistlen, snmp_max_variables);

    pkt->resp_pdu->err_code = SNMP_ERR_TOO_BIG;
    pkt->resp_pdu->err_idx = 0;

    return 0;
  }

  max_idx = snmp_mib_get_max_idx();

  for (iter_var = pkt->req_pdu->varlist; iter_var; iter_var = iter_var->next) { 
    struct snmp_mib *mib = NULL;
    struct snmp_var *resp_var = NULL;
    int mib_idx = -1, next_idx = -1, lacks_instance_id = FALSE;
    int32_t mib_int = -1;
    char *mib_str = NULL;
    size_t mib_strlen = 0;

    pr_signals_handle();

    mib_idx = snmp_mib_get_idx(iter_var->name, iter_var->namelen,
      &lacks_instance_id);
    if (mib_idx < 0) {
      int unknown_oid = FALSE;

      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "%s %s of unknown OID %s (lacks instance ID = %s)",
        snmp_msg_get_versionstr(pkt->snmp_version),
        snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
        snmp_asn1_get_oidstr(pkt->req_pdu->pool, iter_var->name,
          iter_var->namelen), lacks_instance_id ? "true" : "false");

      if (lacks_instance_id) {
        oid_t *oid;
        unsigned int oidlen;

        /* For GetNextRequest-PDUs, a request for "A", without instance
         * identifier, gets the response of "A.0", since "A" comes before
         * "A.0".  (This does not hold true for GetRequest-PDUs.)
         */

        oidlen = iter_var->namelen + 1;
        oid = pcalloc(pkt->pool, oidlen * sizeof(oid_t));
        memmove(oid, iter_var->name, iter_var->namelen * sizeof(oid_t));

        mib_idx = snmp_mib_get_idx(oid, oidlen, NULL);
        if (mib_idx < 0) {
          lacks_instance_id = FALSE;
          unknown_oid = TRUE;

        } else {
          mib_idx--;
        }

      } else {
        /* Try to find the "nearest" OID. */
        mib_idx = snmp_mib_get_nearest_idx(iter_var->name, iter_var->namelen);
        if (mib_idx < 0) {
          unknown_oid = TRUE;

        } else {
          mib_idx--;
        }
      }

      if (unknown_oid) {
        /* If SNMPv1, then set the err_code/err_idx values, and duplicate the
         * varlist.
         *
         * If SNMPv2/SNMPv3, then leave err_code/err_idex values set to zero,
         * but create a var of exception 'noSuchObject' or 'noSuchInstance' as
         * appropriate.
         */

        switch (pkt->snmp_version) {
          case SNMP_PROTOCOL_VERSION_1:
            pkt->resp_pdu->err_code = SNMP_ERR_NO_SUCH_NAME;
            pkt->resp_pdu->err_idx = var_count + 1;
            pkt->resp_pdu->varlist = snmp_smi_dup_var(pkt->pool,
              pkt->req_pdu->varlist);
            pkt->resp_pdu->varlistlen = pkt->req_pdu->varlistlen;
            break;

          case SNMP_PROTOCOL_VERSION_2:
          case SNMP_PROTOCOL_VERSION_3:
            resp_var = snmp_smi_create_exception(pkt->pool, iter_var->name,
              iter_var->namelen, SNMP_SMI_NO_SUCH_OBJECT);
            break;
        }

        if (resp_var == NULL) {
          return 0;
        }
      }
    }

    pr_trace_msg(trace_channel, 19,
      "%s %s for OID %s at MIB index %d (max index %d)",
      snmp_msg_get_versionstr(pkt->snmp_version),
      snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
      snmp_asn1_get_oidstr(pkt->req_pdu->pool, iter_var->name,
        iter_var->namelen), mib_idx, max_idx);

    next_idx = mib_idx + 1;

    if (next_idx < max_idx) {
      /* Get the next MIB in the list.  Note that we may need to continue
       * looking for a short while, as some arcs are for notifications only.
       */
      mib = snmp_mib_get_by_idx(next_idx);
      while (mib != NULL &&
             (mib->mib_enabled == FALSE ||
              mib->notify_only == TRUE)) {
        pr_signals_handle();

        if (next_idx > max_idx) {
          break;
        }

        mib = snmp_mib_get_by_idx(++next_idx);
      }
    }

    if (mib_idx >= max_idx ||
        next_idx > max_idx) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "%s %s of last OID %s",
        snmp_msg_get_versionstr(pkt->snmp_version),
        snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
        snmp_asn1_get_oidstr(pkt->req_pdu->pool, iter_var->name,
          iter_var->namelen));

      /* If SNMPv1, then set the err_code/err_idx values, and duplicate the
       * varlist.
       *
       * If SNMPv2/SNMPv3, then leave err_code/err_idex values set to zero, but
       * create a var of value 'endOfMibView'.
       */

      switch (pkt->snmp_version) {
        case SNMP_PROTOCOL_VERSION_1:
          pkt->resp_pdu->err_code = SNMP_ERR_NO_SUCH_NAME;
          pkt->resp_pdu->err_idx = var_count + 1;
          pkt->resp_pdu->varlist = snmp_smi_dup_var(pkt->pool,
            pkt->req_pdu->varlist);
          pkt->resp_pdu->varlistlen = pkt->req_pdu->varlistlen;
          break;

        case SNMP_PROTOCOL_VERSION_2:
        case SNMP_PROTOCOL_VERSION_3:
          resp_var = snmp_smi_create_exception(pkt->pool, iter_var->name,
            iter_var->namelen, SNMP_SMI_END_OF_MIB_VIEW);
          break;
      }

      if (resp_var == NULL) {
        return 0;
      }
    }

    if (resp_var == NULL) {
      /* Get the next MIB in the list. */
      mib = snmp_mib_get_by_idx(next_idx);

      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "%s %s of OID %s (%s)", snmp_msg_get_versionstr(pkt->snmp_version),
        snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
        snmp_asn1_get_oidstr(iter_var->pool, mib->mib_oid, mib->mib_oidlen),
        mib->mib_name);
 
      res = snmp_db_get_value(pkt->pool, mib->db_field, &mib_int, &mib_str,
        &mib_strlen);

      /* XXX Response with genErr instead? */
      if (res < 0) {
        int xerrno = errno;

        (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
          "error retrieving database value for field %s: %s",
          snmp_db_get_fieldstr(pkt->pool, mib->db_field), strerror(xerrno));
        errno = xerrno;
        return -1;
      }

      resp_var = snmp_smi_create_var(pkt->pool, mib->mib_oid, mib->mib_oidlen,
        mib->smi_type, mib_int, mib_str, mib_strlen);
    }

    var_count = snmp_smi_util_add_list_var(&head_var, &tail_var, resp_var);
  }

  pkt->resp_pdu->varlist = head_var;
  pkt->resp_pdu->varlistlen = var_count;

  return 0;
}

static int snmp_agent_handle_getbulk(struct snmp_packet *pkt) {
  register unsigned int i = 0;
  struct snmp_var *iter_var = NULL, *head_var = NULL, *tail_var = NULL;
  unsigned int var_count = 0;
  int max_idx, res;

  /* SNMPv1 does not support GetBulkRequest PDUs. */
  if (pkt->snmp_version == SNMP_PROTOCOL_VERSION_1) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "GetBulkRequest-PDU not supported for %s packets, rejecting "
      "invalid request", snmp_msg_get_versionstr(pkt->snmp_version));
    errno = EINVAL;
    return -1;
  }

  if (pkt->req_pdu->varlist == NULL) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "missing request PDU variable bindings list, rejecting invalid request");
    errno = EINVAL;
    return -1;
  }

  /* If non-repeaters is zero, and max-repetitions is zero, treat this as
   * just another GetNextRequest PDU.
   */
  if (pkt->req_pdu->non_repeaters == 0 &&
      pkt->req_pdu->max_repetitions == 0) {
    return snmp_agent_handle_getnext(pkt);
  }

  pkt->resp_pdu = snmp_pdu_dup(pkt->pool, pkt->req_pdu);
  pkt->resp_pdu->request_type = SNMP_PDU_RESPONSE;

  if (pkt->req_pdu->varlistlen > snmp_max_variables) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "%s %s of too many OIDs (%u, max %u)",
      snmp_msg_get_versionstr(pkt->snmp_version),
      snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
      pkt->req_pdu->varlistlen, snmp_max_variables);

    pkt->resp_pdu->err_code = SNMP_ERR_TOO_BIG;
    pkt->resp_pdu->err_idx = 0;

    return 0;
  }

  max_idx = snmp_mib_get_max_idx();

  /* First, deal with the non_repeaters count.  This part is just like handling
   * any other GetNextRequest PDU.
   */
  for (i = 0, iter_var = pkt->req_pdu->varlist;
       i < pkt->req_pdu->non_repeaters && iter_var != NULL;
       i++, iter_var = iter_var->next) { 
    struct snmp_mib *mib = NULL;
    struct snmp_var *resp_var = NULL;
    int mib_idx = -1, lacks_instance_id = FALSE;
    int32_t mib_int = -1;
    char *mib_str = NULL;
    size_t mib_strlen = 0;

    pr_signals_handle();

    mib_idx = snmp_mib_get_idx(iter_var->name, iter_var->namelen,
      &lacks_instance_id);
    if (mib_idx < 0) {
      int unknown_oid = FALSE;

      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "%s %s of unknown OID %s (lacks instance ID = %s)",
        snmp_msg_get_versionstr(pkt->snmp_version),
        snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
        snmp_asn1_get_oidstr(pkt->req_pdu->pool, iter_var->name,
          iter_var->namelen), lacks_instance_id ? "true" : "false");

      if (lacks_instance_id) {
        oid_t *oid;
        unsigned int oidlen;

        /* For GetBulkRequest-PDUs, a request for "A", without instance
         * identifier, gets the response of "A.0", since "A" comes before
         * "A.0".  (This does not hold true for GetRequest-PDUs.)
         */

        oidlen = iter_var->namelen + 1;
        oid = pcalloc(pkt->pool, oidlen * sizeof(oid_t));
        memmove(oid, iter_var->name, iter_var->namelen * sizeof(oid_t));

        mib_idx = snmp_mib_get_idx(oid, oidlen, NULL);
        if (mib_idx < 0) {
          lacks_instance_id = FALSE;
          unknown_oid = TRUE;

        } else {
          mib_idx--;
        }

      } else {
        /* Try to find the "nearest" OID. */
        mib_idx = snmp_mib_get_nearest_idx(iter_var->name, iter_var->namelen);
        if (mib_idx < 0) {
          unknown_oid = TRUE;

        } else {
          mib_idx--;
        }
      }

      if (unknown_oid) {
        resp_var = snmp_smi_create_exception(pkt->pool, iter_var->name,
          iter_var->namelen, lacks_instance_id ? SNMP_SMI_NO_SUCH_INSTANCE :
            SNMP_SMI_NO_SUCH_OBJECT);
      }
    }

    pr_trace_msg(trace_channel, 19,
      "%s %s for OID %s at MIB index %d (max index %d)",
      snmp_msg_get_versionstr(pkt->snmp_version),
      snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
      snmp_asn1_get_oidstr(pkt->req_pdu->pool, iter_var->name,
        iter_var->namelen), mib_idx, max_idx);

    if (mib_idx >= max_idx) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "%s %s of last OID %s",
        snmp_msg_get_versionstr(pkt->snmp_version),
        snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
        snmp_asn1_get_oidstr(pkt->req_pdu->pool, iter_var->name,
          iter_var->namelen));

      resp_var = snmp_smi_create_exception(pkt->pool, iter_var->name,
        iter_var->namelen, SNMP_SMI_END_OF_MIB_VIEW);
    }

    if (resp_var == NULL) {
      /* Get the next MIB in the list. */
      mib = snmp_mib_get_by_idx(mib_idx + 1);

      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "%s %s of OID %s (%s)", snmp_msg_get_versionstr(pkt->snmp_version),
        snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
        snmp_asn1_get_oidstr(iter_var->pool, mib->mib_oid, mib->mib_oidlen),
        mib->mib_name);
 
      res = snmp_db_get_value(pkt->pool, mib->db_field, &mib_int, &mib_str,
        &mib_strlen);

      /* XXX Response with genErr instead? */
      if (res < 0) {
        int xerrno = errno;

        (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
          "error retrieving database value for field %s: %s",
          snmp_db_get_fieldstr(pkt->pool, mib->db_field), strerror(xerrno));
        errno = xerrno;
        return -1;
      }

      resp_var = snmp_smi_create_var(pkt->pool, mib->mib_oid, mib->mib_oidlen,
        mib->smi_type, mib_int, mib_str, mib_strlen);
    }

    var_count = snmp_smi_util_add_list_var(&head_var, &tail_var, resp_var);
  }

  /* Now, deal with the max_repetitions count.  Keep in mind the max_variables
   * limits.
   *
   * The iter_var variable should (after the above non_repeaters loop) be
   * pointing at the starting variable for us to process in the max_repetitions
   * loop.
   */
  for (; iter_var; iter_var = iter_var->next) {
    register unsigned int j;
    struct snmp_mib *mib = NULL;
    struct snmp_var *resp_var = NULL;
    int mib_idx = -1, lacks_instance_id = FALSE;
    int32_t mib_int = -1;
    char *mib_str = NULL;
    size_t mib_strlen = 0;

    mib_idx = snmp_mib_get_idx(iter_var->name, iter_var->namelen,
      &lacks_instance_id);
    if (mib_idx < 0) {
      int unknown_oid = FALSE;

      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "%s %s of unknown OID %s (lacks instance ID = %s)",
        snmp_msg_get_versionstr(pkt->snmp_version),
        snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
        snmp_asn1_get_oidstr(pkt->req_pdu->pool, iter_var->name,
          iter_var->namelen), lacks_instance_id ? "true" : "false");

      if (lacks_instance_id) {
        oid_t *oid;
        unsigned int oidlen;

        /* For GetBulkRequest-PDUs, a request for "A", without instance
         * identifier, gets the response of "A.0", since "A" comes before
         * "A.0".  (This does not hold true for GetRequest-PDUs.)
         */

        oidlen = iter_var->namelen + 1;
        oid = pcalloc(pkt->pool, oidlen * sizeof(oid_t));
        memmove(oid, iter_var->name, iter_var->namelen * sizeof(oid_t));

        mib_idx = snmp_mib_get_idx(oid, oidlen, NULL);
        if (mib_idx < 0) {
          lacks_instance_id = FALSE;
          unknown_oid = TRUE;

        } else {
          mib_idx--;
        }

      } else {
        /* Try to find the "nearest" OID. */
        mib_idx = snmp_mib_get_nearest_idx(iter_var->name, iter_var->namelen);
        if (mib_idx < 0) {
          unknown_oid = TRUE;

        } else {
          mib_idx--;
        }
      }

      if (unknown_oid) {
        resp_var = snmp_smi_create_exception(pkt->pool, iter_var->name,
          iter_var->namelen, lacks_instance_id ? SNMP_SMI_NO_SUCH_INSTANCE :
            SNMP_SMI_NO_SUCH_OBJECT);
      }
    }

    if (resp_var == NULL) {
      pr_trace_msg(trace_channel, 19,
        "%s %s for OID %s at MIB index %d (max index %d)",
        snmp_msg_get_versionstr(pkt->snmp_version),
        snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
        snmp_asn1_get_oidstr(pkt->req_pdu->pool, iter_var->name,
          iter_var->namelen), mib_idx, max_idx);

      if (mib_idx >= max_idx) {
        (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
          "%s %s of last OID %s",
          snmp_msg_get_versionstr(pkt->snmp_version),
          snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
          snmp_asn1_get_oidstr(pkt->req_pdu->pool, iter_var->name,
            iter_var->namelen));

        resp_var = snmp_smi_create_exception(pkt->pool, iter_var->name,
          iter_var->namelen, SNMP_SMI_END_OF_MIB_VIEW);
      }

      if (resp_var == NULL) {
        struct snmp_mib *prev_mib = NULL;

        for (j = 1; j <= pkt->req_pdu->max_repetitions; j++) {
          int next_idx;

          pr_signals_handle();

          /* Get the next MIB in the list. */
          next_idx = mib_idx + j;
          if (next_idx < max_idx) {
            mib = snmp_mib_get_by_idx(next_idx);
            while (mib != NULL &&
                   (mib->mib_enabled == FALSE ||
                    mib->notify_only == TRUE)) {
              pr_signals_handle();

              if (next_idx > max_idx) {
                break;
              }

              mib = snmp_mib_get_by_idx(++next_idx);
            }
          }

          mib = snmp_mib_get_by_idx(next_idx);
          if (mib != NULL) {
            (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
              "%s %s of OID %s (%s)",
              snmp_msg_get_versionstr(pkt->snmp_version),
              snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type),
              snmp_asn1_get_oidstr(iter_var->pool, mib->mib_oid,
                mib->mib_oidlen), mib->mib_name);

            res = snmp_db_get_value(pkt->pool, mib->db_field, &mib_int,
              &mib_str, &mib_strlen);

            /* XXX Response with genErr instead? */
            if (res < 0) {
              int xerrno = errno;

              (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
                "error retrieving database value for field %s: %s",
                snmp_db_get_fieldstr(pkt->pool, mib->db_field),
                strerror(xerrno));
              errno = xerrno;
              return -1;
            }

            resp_var = snmp_smi_create_var(pkt->pool, mib->mib_oid,
              mib->mib_oidlen, mib->smi_type, mib_int, mib_str, mib_strlen);
            prev_mib = mib;

          } else {
            oid_t *end_oid;
            unsigned int end_oidlen;

            /* We want to use the OID of the last MIB we processed, or the
             * last OID in the request, whichever is present.
             */
            if (prev_mib != NULL) {
              end_oid = prev_mib->mib_oid;
              end_oidlen = prev_mib->mib_oidlen;

            } else {
              end_oid = iter_var->name;
              end_oidlen = iter_var->namelen;
            }

            resp_var = snmp_smi_create_exception(pkt->pool, end_oid,
              end_oidlen, SNMP_SMI_END_OF_MIB_VIEW);
            var_count = snmp_smi_util_add_list_var(&head_var, &tail_var,
              resp_var);
            break;
          }

          var_count = snmp_smi_util_add_list_var(&head_var, &tail_var,
            resp_var);
        }

      } else {
        var_count = snmp_smi_util_add_list_var(&head_var, &tail_var, resp_var);
      }

    } else {
      var_count = snmp_smi_util_add_list_var(&head_var, &tail_var, resp_var);
    }
  }

  pkt->resp_pdu->varlist = head_var;
  pkt->resp_pdu->varlistlen = var_count;

  return 0;
}

static int snmp_agent_handle_set(struct snmp_packet *pkt) {

  /* We currently don't support any SET operations. */

  (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
    "%s %s not supported", snmp_msg_get_versionstr(pkt->snmp_version),
    snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type));

  /* Set the err_code/err_idx values, and duplicate the varlist.  The only
   * difference is that SNMPv1 gets NO_SUCH_NAME, and SNMPv2/SNMPv3 get
   * NO_ACCESS.
   */

  pkt->resp_pdu = snmp_pdu_dup(pkt->pool, pkt->req_pdu);
  pkt->resp_pdu->request_type = SNMP_PDU_RESPONSE;

  switch (pkt->snmp_version) {
    case SNMP_PROTOCOL_VERSION_1:
      pkt->resp_pdu->err_code = SNMP_ERR_NO_SUCH_NAME;
      pkt->resp_pdu->err_idx = 1;
      pkt->resp_pdu->varlist = snmp_smi_dup_var(pkt->pool,
        pkt->req_pdu->varlist);
      pkt->resp_pdu->varlistlen = pkt->req_pdu->varlistlen;
      break;

    case SNMP_PROTOCOL_VERSION_2:
    case SNMP_PROTOCOL_VERSION_3:
      pkt->resp_pdu->err_code = SNMP_ERR_NO_ACCESS;
      pkt->resp_pdu->err_idx = 1;
      pkt->resp_pdu->varlist = snmp_smi_dup_var(pkt->pool,
        pkt->req_pdu->varlist);
      pkt->resp_pdu->varlistlen = pkt->req_pdu->varlistlen;
      break;
  }

  return 0;
}

static int snmp_agent_handle_request(struct snmp_packet *pkt) {
  int res;

  switch (pkt->req_pdu->request_type) {
    case SNMP_PDU_GET:
      res = snmp_agent_handle_get(pkt);
      break;

    case SNMP_PDU_GETNEXT:
      res = snmp_agent_handle_getnext(pkt);
      break;

    case SNMP_PDU_GETBULK:
      res = snmp_agent_handle_getbulk(pkt);
      break;

    case SNMP_PDU_SET:
      res = snmp_agent_handle_set(pkt);
      break;

    default:
      errno = EINVAL; 
      res = -1;
  }

  return res;
}

static int snmp_agent_handle_packet(int sockfd, pr_netaddr_t *agent_addr) {
  int nbytes, res;
  struct sockaddr_in from_sockaddr;
  socklen_t from_sockaddrlen;
  pr_netaddr_t from_addr;
  struct snmp_packet *pkt = NULL;
  
  pkt = snmp_packet_create(snmp_pool);

  from_sockaddrlen = sizeof(struct sockaddr_in);
  nbytes = recvfrom(sockfd, pkt->req_data, pkt->req_datalen, 0,
    (struct sockaddr *) &from_sockaddr, &from_sockaddrlen);
  if (nbytes < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "error receiving data from socket %d: %s", sockfd, strerror(xerrno));

    destroy_pool(pkt->pool);
    errno = xerrno;
    return -1;
  }

  pkt->req_datalen = nbytes;

  /* XXX Support UDP/IPv6 in the future */

  pr_netaddr_clear(&from_addr);
  pr_netaddr_set_family(&from_addr, AF_INET);
  pr_netaddr_set_sockaddr(&from_addr, (struct sockaddr *) &from_sockaddr);

  pkt->remote_addr = &from_addr;

  pr_trace_msg(trace_channel, 3,
    "read %d UDP bytes from %s#%u", nbytes,
    pr_netaddr_get_ipstr(pkt->remote_addr),
    ntohs(pr_netaddr_get_port(pkt->remote_addr))); 

  res = snmp_db_incr_value(pkt->pool, SNMP_DB_SNMP_F_PKTS_RECVD_TOTAL, 1);
  if (res < 0) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "error incrementing SNMP database for "
      "snmp.packetsReceivedTotal: %s", strerror(errno));
  }

  pkt->remote_class = pr_class_match_addr(&from_addr);
  if (pkt->remote_class != NULL) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "received %d UDP bytes from client in '%s' class", nbytes,
      pkt->remote_class->cls_name);

  } else {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "received %d UDP bytes from client in unknown class", nbytes);
  }

  /* Check for malicious packets, which forge the from address/port to be
   * the same as our listening address/port, trying to induce us to talk
   * to ourselves.
   */
  if (pr_netaddr_cmp(&from_addr, agent_addr) == 0 &&
      pr_netaddr_get_port(&from_addr) == pr_netaddr_get_port(agent_addr)) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "rejecting forged UDP packet from %s#%u (appears to be from "
      "SNMPAgent %s#%u)",
      pr_netaddr_get_ipstr(&from_addr), ntohs(pr_netaddr_get_port(&from_addr)),
      pr_netaddr_get_ipstr(agent_addr), ntohs(pr_netaddr_get_port(agent_addr)));

    destroy_pool(pkt->pool);
    errno = EACCES;
    return -1;
  }

  /* Note: mod_ifsession does NOT affect mod_snmp ACLs; use <Limit SNMP> */

  if (snmp_limits_allow(main_server->conf, pkt) == FALSE) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "UDP packet from %s#%u denied by <Limit SNMP> rules",
      pr_netaddr_get_ipstr(&from_addr), ntohs(pr_netaddr_get_port(&from_addr)));

    destroy_pool(pkt->pool);
    errno = EACCES;
    return -1;
  }

  res = snmp_msg_read(pkt->pool, &(pkt->req_data), &(pkt->req_datalen),
    &(pkt->community), &(pkt->community_len), &(pkt->snmp_version),
    &(pkt->req_pdu));
  if (res < 0) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "error reading SNMP message from UDP packet: %s", strerror(errno));

    destroy_pool(pkt->pool);
    errno = EINVAL;
    return -1;
  }

  /* Check ACLs (community, SNMPv3, etc) */
  res = snmp_security_check(pkt);
  if (res < 0) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "%s message does not contain correct authentication info, "
      "ignoring message", snmp_msg_get_versionstr(pkt->snmp_version));

    destroy_pool(pkt->pool);
    errno = EINVAL;
    return -1;
  }

  (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
    "read SNMP message for %s, community = '%s', request ID %ld, "
    "request type '%s'", snmp_msg_get_versionstr(pkt->snmp_version),
    pkt->community, pkt->req_pdu->request_id,
    snmp_pdu_get_request_type_desc(pkt->req_pdu->request_type));

  res = snmp_agent_handle_request(pkt);
  if (res < 0) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "error handling SNMP message: %s", strerror(errno));
    destroy_pool(pkt->pool);
    errno = EINVAL;
    return -1;
  }

  /* We're done with the request PDU here. */
  destroy_pool(pkt->req_pdu->pool);
  pkt->req_pdu = NULL;

  (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
    "writing SNMP message for %s, community = '%s', request ID %ld, "
    "request type '%s'", snmp_msg_get_versionstr(pkt->snmp_version),
    pkt->community, pkt->resp_pdu->request_id,
    snmp_pdu_get_request_type_desc(pkt->resp_pdu->request_type));

  res = snmp_msg_write(pkt->pool, &(pkt->resp_data), &(pkt->resp_datalen),
    pkt->community, pkt->community_len, pkt->snmp_version, pkt->resp_pdu);
  if (res < 0) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "error writing SNMP message to UDP packet: %s", strerror(errno));

    destroy_pool(pkt->pool);
    errno = EINVAL;
    return -1;
  }

  snmp_packet_write(snmp_pool, sockfd, pkt);

  destroy_pool(pkt->pool);
  return 0;
}

static int snmp_agent_listen(pr_netaddr_t *agent_addr) {
  int family, res, sockfd;

  family = pr_netaddr_get_family(agent_addr);
  sockfd = socket(family, SOCK_DGRAM, snmp_proto_udp);
  if (sockfd < 0) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "unable to create %s UDP socket: %s",
      family == AF_INET ? "IPv4" : "IPv6", strerror(errno));
    exit(1);
  }

  res = bind(sockfd, pr_netaddr_get_sockaddr(agent_addr),
    pr_netaddr_get_sockaddr_len(agent_addr));
  if (res < 0) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "unable to bind %s UDP socket to %s#%u: %s",
      family == AF_INET ? "IPv4" : "IPv6",
      pr_netaddr_get_ipstr(agent_addr),
      ntohs(pr_netaddr_get_port(agent_addr)), strerror(errno));
    (void) close(sockfd);
    exit(1);

  } else {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "bound %s UDP socket to %s#%u", family == AF_INET ? "IPv4" : "IPv6",
      pr_netaddr_get_ipstr(agent_addr),
      ntohs(pr_netaddr_get_port(agent_addr)));
  }

  return sockfd;
}

static void snmp_agent_loop(array_header *sockfds, array_header *addrs) {
  fd_set listen_fds;
  struct timeval tv;
  int fd, res;

  while (TRUE) {
    register unsigned int i;
    int maxfd = -1, *fds;
    pr_netaddr_t **agent_addrs;

    /* XXX Is it necessary to even have a timeout?  We could simply block
     * in select(2) indefinitely, until either an event arrives or we are
     * interrupted by a signal.
     *
     * Yes, we DO need a timeout here, specifically to poll the trap table
     * for any trap-generating state.  Rather than using a timer and using
     * SIGALRM handling, we can reuse this event loop.
     */
    tv.tv_sec = 60;
    tv.tv_usec = 0L;

    /* To implement notification criteria/thresholds, we poll for the
     * necessary conditions here.
     */
    snmp_notify_poll_cond();

    FD_ZERO(&listen_fds);

    fds = sockfds->elts; 
    agent_addrs = addrs->elts;

    for (i = 0; i < sockfds->nelts; i++) {
      fd = fds[i];
      FD_SET(fd, &listen_fds);

      if (fd > maxfd) {
        maxfd = fd;
      }
    }

    res = select(maxfd + 1, &listen_fds, NULL, NULL, &tv);
    if (res == 0) {
      /* Select timeout reached.  Just try again. */
      continue;
    }

    if (res < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
        continue;
      }

    } else {
      for (i = 0; i < sockfds->nelts; i++) {
        pr_netaddr_t *agent_addr;

        fd = fds[i];
        agent_addr = agent_addrs[i];

        if (FD_ISSET(fd, &listen_fds)) {
          res = snmp_agent_handle_packet(fd, agent_addr);
          if (res < 0) {
            (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
              "error handling SNMP packet: %s", strerror(errno));
          }
        } 
      }
    }
  }
}

static pid_t snmp_agent_start(const char *tables_dir, int agent_type,
    array_header *agent_addrs) {
  register unsigned int i;
  pid_t agent_pid;
  char *agent_chroot = NULL;
  rlim_t curr_nproc, max_nproc;
  array_header *agent_fds = NULL;

  agent_pid = fork();
  switch (agent_pid) {
    case -1:
      pr_log_pri(PR_LOG_ALERT,
        MOD_SNMP_VERSION ": unable to fork: %s", strerror(errno));
      return 0;

    case 0:
      /* We're the child. */
      break;

    default:
      /* We're the parent. */
      return agent_pid;
  }

  /* Reset the cached PID, so that it is correctly reflected in the logs. */
  session.pid = getpid();

  pr_trace_msg("snmp", 3, "forked SNMP agent PID %lu",
    (unsigned long) session.pid);

  snmp_daemonize(tables_dir);

  /* Install our own signal handlers (mostly to ignore signals) */
  (void) signal(SIGALRM, SIG_IGN);
  (void) signal(SIGHUP, SIG_IGN);
  (void) signal(SIGUSR1, SIG_IGN);
  (void) signal(SIGUSR2, SIG_IGN);

  /* Remove our event listeners. */
  pr_event_unregister(&snmp_module, NULL, NULL);

  /* XXX Check the agent_type variable, to see if we are a master agent or
   * an AgentX sub-agent.
   */

  for (i = 0; i < agent_addrs->nelts; i++) {
    pr_netaddr_t *agent_addr, **addrs;
    int agent_fd;

    addrs = agent_addrs->elts;
    agent_addr = addrs[i];

    agent_fd = snmp_agent_listen(agent_addr);
    if (agent_fd < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "unable to create listening socket for SNMP agent process: %s",
       strerror(errno));
      exit(0);
    }

    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "SNMP agent process listening on %s UDP %s#%u",
      pr_netaddr_get_family(agent_addr) == AF_INET ? "IPv4" : "IPv6",
      pr_netaddr_get_ipstr(agent_addr), ntohs(pr_netaddr_get_port(agent_addr)));

    if (agent_fds == NULL) {
      agent_fds = make_array(snmp_pool, 1, sizeof(int));
    }

    *((int *) push_array(agent_fds)) = agent_fd;
  }

  PRIVS_ROOT

  if (getuid() == PR_ROOT_UID) {
    int res;

    /* Chroot to the SNMPTables/empty/ directory before dropping root privs. */

    agent_chroot = pdircat(snmp_pool, tables_dir, "empty", NULL);
    res = chroot(agent_chroot);
    if (res < 0) {
      int xerrno = errno;

      PRIVS_RELINQUISH
 
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "unable to chroot to SNMPTables/empty/ directory '%s': %s",
        agent_chroot, strerror(xerrno));
      exit(0);
    }

    if (chdir("/") < 0) {
      int xerrno = errno;

      PRIVS_RELINQUISH

      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "unable to chdir to root directory within chroot: %s",
        strerror(xerrno));
      exit(0);
    }
  }

  pr_proctitle_set("(listening for SNMP packets)");

  /* Make the SNMP process have the identity of the configured daemon
   * User/Group.
   */
  session.uid = geteuid();
  session.gid = getegid();
  PRIVS_REVOKE

  if (agent_chroot != NULL) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "SNMP agent process running with UID %s, GID %s, restricted to '%s'",
      pr_uid2str(snmp_pool, getuid()), pr_gid2str(snmp_pool, getgid()),
      agent_chroot);

  } else {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "SNMP agent process running with UID %s, GID %s, located in '%s'",
      pr_uid2str(snmp_pool, getuid()), pr_gid2str(snmp_pool, getgid()),
      getcwd(NULL, 0));
  }

  /* Once we have chrooted, and dropped root privs completely, we can now
   * lower our nproc resource limit, so that we cannot fork any new
   * processed.  We should not be doing so, and we want to mitigate any
   * possible exploitation.
   */
  if (pr_rlimit_get_nproc(&curr_nproc, NULL) == 0) {
    /* Override whatever the configured nproc is; we only want 1. */
    curr_nproc = 1;

    max_nproc = curr_nproc;

    if (pr_rlimit_set_nproc(curr_nproc, max_nproc) < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error setting nproc resource limits to %lu: %s",
        (unsigned long) max_nproc, strerror(errno));

    } else {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "set nproc resource limits to %lu", (unsigned long) max_nproc);
    }

  } else {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "error getting nproc limits: %s", strerror(errno));
  }

  snmp_agent_loop(agent_fds, agent_addrs);

  /* When we are done, we simply exit. */;
  pr_trace_msg("snmp", 3, "SNMP agent PID %lu exiting",
    (unsigned long) session.pid);
  exit(0);
}

static void snmp_agent_stop(pid_t agent_pid) {
  int res, status;
  time_t start_time = time(NULL);

  if (agent_pid == 0) {
    /* Nothing to do. */
    return;
  }

  pr_trace_msg("snmp", 3, "stopping agent PID %lu", (unsigned long) agent_pid);

  /* Litmus test: is the SNMP agent process still around?  If not, there's
   * nothing for us to do.
   */
  res = kill(agent_pid, 0);
  if (res < 0 &&
      errno == ESRCH) {
    return;
  }
  
  res = kill(agent_pid, SIGTERM);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "error sending SIGTERM (signal %d) to SNMP agent process ID %lu: %s",
      SIGTERM, (unsigned long) agent_pid, strerror(xerrno));
  }

  /* Poll every 500 millsecs. */
  pr_timer_usleep(500 * 1000);

  res = waitpid(agent_pid, &status, WNOHANG);
  while (res <= 0) {
    if (res < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
        continue;
      }

      if (errno == ECHILD) {
        /* XXX Maybe we shouldn't be using waitpid(2) here, since the
         * main SIGCHLD handler may handle the termination of the SNMP
         * agent process?
         */

        return;
      }

      if (errno != EINTR) {
        (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
          "error waiting for SNMP agent process ID %lu: %s",
          (unsigned long) agent_pid, strerror(errno));
        status = -1;
        break;
      }
    }

    /* Check the time elapsed since we started. */
    if ((time(NULL) - start_time) > snmp_agent_timeout) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "SNMP agent process ID %lu took longer than timeout (%lu secs) to "
        "stop, sending SIGKILL (signal %d)", (unsigned long) agent_pid,
        snmp_agent_timeout, SIGKILL);
      res = kill(agent_pid, SIGKILL);
      if (res < 0) {
        (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
         "error sending SIGKILL (signal %d) to SNMP agent process ID %lu: %s",
         SIGKILL, (unsigned long) agent_pid, strerror(errno));
      }

      break;
    }

    /* Poll every 500 millsecs. */
    pr_timer_usleep(500 * 1000);
  }

  if (WIFEXITED(status)) {
    int exit_status;

    exit_status = WEXITSTATUS(status);
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "SNMP agent process ID %lu terminated normally, with exit status %d",
      (unsigned long) agent_pid, exit_status);
  }

  if (WIFSIGNALED(status)) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "SNMP agent process ID %lu died from signal %d",
      (unsigned long) agent_pid, WTERMSIG(status));

    if (WCOREDUMP(status)) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "SNMP agent process ID %lu created a coredump",
        (unsigned long) agent_pid);
    }
  }

  snmp_agent_pid = 0;
  return;
}

/* Configuration handlers
 */

/* usage: SNMPAgent "master"|"agentx" address[:port] [...] */
MODRET set_snmpagent(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  array_header *agent_addrs;
  int agent_type;

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }
  CHECK_CONF(cmd, CONF_ROOT);

  if (strncasecmp(cmd->argv[1], "master", 7) == 0) {
    agent_type = SNMP_AGENT_TYPE_MASTER;

  } else if (strncasecmp(cmd->argv[1], "agentx", 7) == 0) {
    agent_type = SNMP_AGENT_TYPE_AGENTX;

  } else {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unsupported SNMP agent type '",
      cmd->argv[1], "'", NULL));
  }

  agent_addrs = make_array(snmp_pool, 1, sizeof(pr_netaddr_t *));

  for (i = 2; i < cmd->argc; i++) {
    const pr_netaddr_t *agent_addr;
    int agent_port = SNMP_DEFAULT_AGENT_PORT;
    char *addr = NULL, *ptr;
    size_t addrlen;

    /* Separate the port out from the address, if present. */
    ptr = strrchr(cmd->argv[i], ':');

    if (ptr != NULL) {
      char *ptr2;

      /* We need to handle the following possibilities:
       *
       *  ipv4-addr
       *  ipv4-addr:port
       *  [ipv6-addr]
       *  [ipv6-addr]:port
       *
       * Thus we check to see if the last ':' occurs before, or after,
       * a ']' for an IPv6 address.
       */

      ptr2 = strrchr(cmd->argv[i], ']');
      if (ptr2 != NULL) {
        if (ptr2 > ptr) {
          /* The found ':' is part of an IPv6 address, not a port delimiter. */
          ptr = NULL;
        }
      }

      if (ptr != NULL) {
        *ptr = '\0';

        agent_port = atoi(ptr + 1);
        if (agent_port < 1 ||
            agent_port > 65535) {
          CONF_ERROR(cmd, "port must be between 1-65535");
        }
      }
    }

    addr = cmd->argv[i];
    addrlen = strlen(addr);

    /* Make sure we can handle an IPv6 address here, e.g.:
     *
     *   [::1]:162
     */
    if (addrlen > 0 &&
        (addr[0] == '[' && addr[addrlen-1] == ']')) {
      addr = pstrndup(cmd->pool, addr + 1, addrlen - 2);
    }

    agent_addr = pr_netaddr_get_addr(snmp_pool, addr, NULL);
    if (agent_addr == NULL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to resolve \"", addr, "\"",
        NULL));
    }

    pr_netaddr_set_port((pr_netaddr_t *) agent_addr, htons(agent_port));
    *((pr_netaddr_t **) push_array(agent_addrs)) = (pr_netaddr_t *) agent_addr;
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = agent_type;
  c->argv[1] = agent_addrs;
 
  return PR_HANDLED(cmd);
}

/* usage: SNMPCommunity community */
MODRET set_snmpcommunity(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: SNMPEnable on|off */
MODRET set_snmpenable(cmd_rec *cmd) {
  int enabled = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  enabled = get_boolean(cmd, 1);
  if (enabled == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = enabled;

  return PR_HANDLED(cmd);
}

/* usage: SNMPEngine on|off */
MODRET set_snmpengine(cmd_rec *cmd) {
  int bool = 1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: SNMPLog path|"none" */
MODRET set_snmplog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: SNMPMaxVariables count */
MODRET set_snmpmaxvariables(cmd_rec *cmd) {
  int count = 0;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  count = atoi(cmd->argv[1]);
  if (count < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "count '", cmd->argv[1],
      "' must be greater than zero", NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = count;

  return PR_HANDLED(cmd);
}

/* usage: SNMPNotify address[:port]
 *
 * XXX In the future, allow specifying of notification types/thresholds
 */
MODRET set_snmpnotify(cmd_rec *cmd) {
  config_rec *c;
  const pr_netaddr_t *notify_addr;
  int notify_port = SNMP_DEFAULT_TRAP_PORT;
  char *ptr;

  if (cmd->argc != 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* Separate the port out from the address, if present.
   *
   * XXX Make sure we can handle an IPv6 address here, e.g.:
   *
   *   [::1]:162
   */
  ptr = strrchr(cmd->argv[1], ':');
  if (ptr != NULL) {
    *ptr = '\0';

    notify_port = atoi(ptr + 1);
    if (notify_port < 1 ||
        notify_port > 65535) {
      CONF_ERROR(cmd, "port must be between 1-65535");
    }
  }
 
  c = add_config_param(cmd->argv[0], 1, NULL);

  notify_addr = pr_netaddr_get_addr(c->pool, cmd->argv[1], NULL);
  if (notify_addr == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to resolve '", cmd->argv[1],
      "': ", strerror(errno), NULL));
  }

  pr_netaddr_set_port((pr_netaddr_t *) notify_addr, htons(notify_port));
  c->argv[0] = (void *) notify_addr;

  return PR_HANDLED(cmd);
}

/* usage: SNMPOptions opt1 ... optN */
MODRET set_snmpoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT);

  /* XXX Implement;
   *
   *  NoSNMPv1
   *  NoSNMPv2
   *  NoSMPv3
   *
   * Describe how these relate to SNMPProtocol; or should these be folded
   * into SNMPProtocol, e.g.:
   *
   *  SNMPProtocol 2-3
   *
   * Default SNMPProtocol would then be "1-3".
   */
 
  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "RestartClearsCounters") == 0) {
      opts |= SNMP_OPT_RESTART_CLEARS_COUNTERS;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown SNMPOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;
 
  return PR_HANDLED(cmd);
}

/* usage: SNMPTables path */
MODRET set_snmptables(cmd_rec *cmd) {
  int res;
  struct stat st;
  char *path;
 
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  path = cmd->argv[1]; 
  if (*path != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "must be a full path: '", path, "'",
      NULL));
  }

  res = stat(path, &st);
  if (res < 0) {
    char *agent_chroot;

    if (errno != ENOENT) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to stat '", path, "': ",
        strerror(errno), NULL));
    }

    pr_log_debug(DEBUG0, MOD_SNMP_VERSION
      ": SNMPTables directory '%s' does not exist, creating it", path);

    /* Create the directory. */
    res = snmp_mkpath(cmd->tmp_pool, path, geteuid(), getegid(), 0755);
    if (res < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to create directory '",
        path, "': ", strerror(errno), NULL));
    }

    /* Also create the empty/ directory underneath, for the chroot. */
    agent_chroot = pdircat(cmd->tmp_pool, path, "empty", NULL);

    res = snmp_mkpath(cmd->tmp_pool, agent_chroot, geteuid(), getegid(), 0111);
    if (res < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to create directory '",
        agent_chroot, "': ", strerror(errno), NULL));
    }

    pr_log_debug(DEBUG2, MOD_SNMP_VERSION
      ": created SNMPTables directory '%s'", path);

  } else {
    char *agent_chroot;

    if (!S_ISDIR(st.st_mode)) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to use '", path,
        ": Not a directory", NULL));
    }

    /* See if the chroot directory empty/ already exists as well.  And enforce
     * the permissions on that directory.
     */
    agent_chroot = pdircat(cmd->tmp_pool, path, "empty", NULL);

    res = stat(agent_chroot, &st);
    if (res < 0) {
      if (errno != ENOENT) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to stat '", agent_chroot,
          "': ", strerror(errno), NULL));
      }

      res = snmp_mkpath(cmd->tmp_pool, agent_chroot, geteuid(), getegid(),
        0111);
      if (res < 0) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to create directory '",
          agent_chroot, "': ", strerror(errno), NULL));
      }

    } else {
      mode_t dir_mode, expected_mode;

      dir_mode = st.st_mode;
      dir_mode &= ~S_IFMT;
      expected_mode = (S_IXUSR|S_IXGRP|S_IXOTH);

      if (dir_mode != expected_mode) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "directory '", agent_chroot,
          "' has incorrect permissions (not 0111 as required)", NULL));
      }
    }
  }

  (void) add_config_param_str(cmd->argv[0], 1, path);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET snmp_pre_list(cmd_rec *cmd) {
  const char *proto;
  int res;

  if (snmp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  if (strncmp(proto, "ftp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTP_XFERS_F_DIR_LIST_COUNT,
      1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftp.dataTransfers.dirListCount: %s", strerror(errno));
    }

  } else if (strncmp(proto, "ftps", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTPS_XFERS_F_DIR_LIST_COUNT,
      1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsDataTransfers.dirListCount: %s", strerror(errno));
    }

  } else if (strncmp(proto, "sftp", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_SFTP_XFERS_F_DIR_LIST_COUNT,
      1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "sftp.sftpDataTransfers.dirListCount: %s", strerror(errno));
    }
  }

  return PR_DECLINED(cmd);
}

MODRET snmp_log_list(cmd_rec *cmd) {
  const char *proto;
  int res;

  if (snmp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  if (strncmp(proto, "ftp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTP_XFERS_F_DIR_LIST_COUNT,
      -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "ftp.dataTransfers.dirListCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTP_XFERS_F_DIR_LIST_TOTAL,
      1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftp.dataTransfers.dirListTotal: %s", strerror(errno));
    }

  } else if (strncmp(proto, "ftps", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTPS_XFERS_F_DIR_LIST_COUNT,
      -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "ftps.tlsDataTransfers.dirListCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTPS_XFERS_F_DIR_LIST_TOTAL,
      1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsDataTransfers.dirListTotal: %s", strerror(errno));
    }

  } else if (strncmp(proto, "sftp", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_SFTP_XFERS_F_DIR_LIST_COUNT,
      -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "sftp.sftpDataTransfers.dirListCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_SFTP_XFERS_F_DIR_LIST_TOTAL,
      1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "sftp.sftpDataTransfers.dirListTotal: %s", strerror(errno));
    }
  }

  return PR_DECLINED(cmd);
}

MODRET snmp_err_list(cmd_rec *cmd) {
  const char *proto;
  int res;

  if (snmp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);

  if (strncmp(proto, "ftp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTP_XFERS_F_DIR_LIST_COUNT,
      -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "ftp.dataTransfers.dirListCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTP_XFERS_F_DIR_LIST_ERR_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftp.dataTranfers.dirListFailedTotal: %s", strerror(errno));
    }

  } else if (strncmp(proto, "ftps", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTPS_XFERS_F_DIR_LIST_COUNT,
      -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "ftps.tlsDataTransfers.dirListCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTPS_XFERS_F_DIR_LIST_ERR_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsDataTranfers.dirListFailedTotal: %s", strerror(errno));
    }

  } else if (strncmp(proto, "sftp", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_SFTP_XFERS_F_DIR_LIST_COUNT,
      -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "sftp.sftpDataTransfers.dirListCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SFTP_XFERS_F_DIR_LIST_ERR_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "sftp.sftpDataTranfers.dirListFailedTotal: %s", strerror(errno));
    }
  }

  return PR_DECLINED(cmd);
}

MODRET snmp_log_pass(cmd_rec *cmd) {
  const char *proto; 
  int res;

  if (snmp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);

  if (strncmp(proto, "ftp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTP_SESS_F_SESS_COUNT, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for ftp.sessions.sessionCount: %s",
        strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTP_SESS_F_SESS_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for ftp.sessions.sessionTotal: %s",
        strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTP_LOGINS_F_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for ftp.logins.loginsTotal: %s",
        strerror(errno));
    }

    if (session.anon_config != NULL) {
      res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTP_LOGINS_F_ANON_COUNT,
        1);
      if (res < 0) {
        (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
          "error incrementing SNMP database for ftp.logins.anonLoginCount: %s",
          strerror(errno));
      }

      res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTP_LOGINS_F_ANON_TOTAL,
        1);
      if (res < 0) {
        (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
          "error incrementing SNMP database for ftp.logins.anonLoginTotal: %s",
          strerror(errno));
      }
    }

  } else if (strncmp(proto, "ftps", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTPS_LOGINS_F_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for ftps.tlsLogins.loginsTotal: %s",
        strerror(errno));
    }

  } else {
    /* SSH2 password logins are handled elsewhere. */
  }

  return PR_DECLINED(cmd);
}

MODRET snmp_err_pass(cmd_rec *cmd) {
  const char *proto;
  int res;

  if (snmp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);

  if (strncmp(proto, "ftp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTP_LOGINS_F_ERR_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for ftp.logins.loginFailedTotal: %s",
        strerror(errno));
    }

  } else if (strncmp(proto, "ftps", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTPS_LOGINS_F_ERR_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsLogins.loginFailedTotal: %s", strerror(errno));
    }

  } else {
    /* SSH2 password logins are handled elsewhere. */
  }

  return PR_DECLINED(cmd);
}

MODRET snmp_pre_retr(cmd_rec *cmd) {
  const char *proto;
  int res;

  if (snmp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  if (strncmp(proto, "ftp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_COUNT, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftp.dataTransfers.fileDownloadCount: %s", strerror(errno));
    }

  } else if (strncmp(proto, "ftps", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTPS_XFERS_F_FILE_DOWNLOAD_COUNT, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsDataTransfers.fileDownloadCount: %s", strerror(errno));
    }

  } else if (strncmp(proto, "sftp", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SFTP_XFERS_F_FILE_DOWNLOAD_COUNT, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "sftp.sftpDataTransfers.fileDownloadCount: %s", strerror(errno));
    }

  } else if (strncmp(proto, "scp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SCP_XFERS_F_FILE_DOWNLOAD_COUNT, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "scp.scpDataTransfers.fileDownloadCount: %s", strerror(errno));
    }
  }

  return PR_DECLINED(cmd);
}

MODRET snmp_log_retr(cmd_rec *cmd) {
  const char *proto;
  uint32_t retr_kb;
  off_t rem_bytes;
  int res;

  if (snmp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);

  if (strncmp(proto, "ftp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "ftp.dataTransfers.fileDownloadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftp.dataTransfers.fileDownloadTotal: %s", strerror(errno));
    }

    /* We also need to increment the KB download count.  We know the number
     * of bytes downloaded as an off_t here, but we only store the number of KB
     * in the mod_snmp db tables.
     * 
     * We could just increment by xfer_bytes / 1024, but that would mean that
     * several small files of say 999 bytes could be downloaded, and the KB
     * count would not be incremented.
     *
     * To deal with this situation, we use the snmp_retr_bytes static variable
     * as a "holding bucket" of bytes, from which we get the KB to add to the
     * db tables.
     */
    snmp_retr_bytes += session.xfer.total_bytes;

    retr_kb = (snmp_retr_bytes / 1024);
    rem_bytes = (snmp_retr_bytes % 1024);

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTP_XFERS_F_KB_DOWNLOAD_TOTAL, retr_kb);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftp.dataTransfers.kbDownloadTotal: %s", strerror(errno));
    }

    snmp_retr_bytes = rem_bytes;

  } else if (strncmp(proto, "ftps", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTPS_XFERS_F_FILE_DOWNLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "ftps.tlsDataTransfers.fileDownloadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTPS_XFERS_F_FILE_DOWNLOAD_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsDataTransfers.fileDownloadTotal: %s", strerror(errno));
    }

    /* We also need to increment the KB download count.  We know the number
     * of bytes downloaded as an off_t here, but we only store the number of KB
     * in the mod_snmp db tables.
     * 
     * We could just increment by xfer_bytes / 1024, but that would mean that
     * several small files of say 999 bytes could be downloaded, and the KB
     * count would not be incremented.
     *
     * To deal with this situation, we use the snmp_retr_bytes static variable
     * as a "holding bucket" of bytes, from which we get the KB to add to the
     * db tables.
     */
    snmp_retr_bytes += session.xfer.total_bytes;

    retr_kb = (snmp_retr_bytes / 1024);
    rem_bytes = (snmp_retr_bytes % 1024);

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTPS_XFERS_F_KB_DOWNLOAD_TOTAL, retr_kb);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsDataTransfers.kbDownloadTotal: %s", strerror(errno));
    }

    snmp_retr_bytes = rem_bytes;

  } else if (strncmp(proto, "sftp", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SFTP_XFERS_F_FILE_DOWNLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "sftp.sftpDataTransfers.fileDownloadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SFTP_XFERS_F_FILE_DOWNLOAD_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "sftp.sftpDataTransfers.fileDownloadTotal: %s", strerror(errno));
    }

    /* We also need to increment the KB download count.  We know the number
     * of bytes downloaded as an off_t here, but we only store the number of KB
     * in the mod_snmp db tables.
     * 
     * We could just increment by xfer_bytes / 1024, but that would mean that
     * several small files of say 999 bytes could be downloaded, and the KB
     * count would not be incremented.
     *
     * To deal with this situation, we use the snmp_retr_bytes static variable
     * as a "holding bucket" of bytes, from which we get the KB to add to the
     * db tables.
     */
    snmp_retr_bytes += session.xfer.total_bytes;

    retr_kb = (snmp_retr_bytes / 1024);
    rem_bytes = (snmp_retr_bytes % 1024);

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SFTP_XFERS_F_KB_DOWNLOAD_TOTAL, retr_kb);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "sftp.sftpDataTransfers.kbDownloadTotal: %s", strerror(errno));
    }

    snmp_retr_bytes = rem_bytes;

  } else if (strncmp(proto, "scp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SCP_XFERS_F_FILE_DOWNLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "scp.scpDataTransfers.fileDownloadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SCP_XFERS_F_FILE_DOWNLOAD_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "scp.scpDataTransfers.fileDownloadTotal: %s", strerror(errno));
    }

    /* We also need to increment the KB download count.  We know the number
     * of bytes downloaded as an off_t here, but we only store the number of KB
     * in the mod_snmp db tables.
     * 
     * We could just increment by xfer_bytes / 1024, but that would mean that
     * several small files of say 999 bytes could be downloaded, and the KB
     * count would not be incremented.
     *
     * To deal with this situation, we use the snmp_retr_bytes static variable
     * as a "holding bucket" of bytes, from which we get the KB to add to the
     * db tables.
     */
    snmp_retr_bytes += session.xfer.total_bytes;

    retr_kb = (snmp_retr_bytes / 1024);
    rem_bytes = (snmp_retr_bytes % 1024);

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SCP_XFERS_F_KB_DOWNLOAD_TOTAL, retr_kb);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "scp.scpDataTransfers.kbDownloadTotal: %s", strerror(errno));
    }

    snmp_retr_bytes = rem_bytes;
  }

  return PR_DECLINED(cmd);
}

MODRET snmp_err_retr(cmd_rec *cmd) {
  const char *proto;
  int res;

  if (snmp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);

  if (strncmp(proto, "ftp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "ftp.dataTransfers.fileDownloadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftp.dataTransfers.fileDownloadFailedTotal: %s", strerror(errno));
    }

  } else if (strncmp(proto, "ftps", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTPS_XFERS_F_FILE_DOWNLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "ftps.tlsDataTransfers.fileDownloadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTPS_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsDataTransfers.fileDownloadFailedTotal: %s", strerror(errno));
    }

  } else if (strncmp(proto, "sftp", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SFTP_XFERS_F_FILE_DOWNLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "sftp.sftpDataTransfers.fileDownloadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SFTP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "sftp.sftpDataTransfers.fileDownloadFailedTotal: %s", strerror(errno));
    }

  } else if (strncmp(proto, "scp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SCP_XFERS_F_FILE_DOWNLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "scp.scpDataTransfers.fileDownloadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SCP_XFERS_F_FILE_DOWNLOAD_ERR_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "scp.scpDataTransfers.fileDownloadFailedTotal: %s", strerror(errno));
    }
  }

  return PR_DECLINED(cmd);
}

MODRET snmp_pre_stor(cmd_rec *cmd) {
  const char *proto;
  int res;

  if (snmp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  if (strncmp(proto, "ftp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_COUNT, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftp.dataTransfers.fileUploadCount: %s", strerror(errno));
    }

  } else if (strncmp(proto, "ftps", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTPS_XFERS_F_FILE_UPLOAD_COUNT, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsDataTransfers.fileUploadCount: %s", strerror(errno));
    }

  } else if (strncmp(proto, "sftp", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SFTP_XFERS_F_FILE_UPLOAD_COUNT, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "sftp.sftpDataTransfers.fileUploadCount: %s", strerror(errno));
    }

  } else if (strncmp(proto, "scp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SCP_XFERS_F_FILE_UPLOAD_COUNT, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "scp.scpDataTransfers.fileUploadCount: %s", strerror(errno));
    }
  }

  return PR_DECLINED(cmd);
}

MODRET snmp_log_stor(cmd_rec *cmd) {
  const char *proto;
  uint32_t stor_kb;
  off_t rem_bytes;
  int res;

  if (snmp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);

  if (strncmp(proto, "ftp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "ftp.dataTransfers.fileUploadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftp.dataTransfers.fileUploadTotal: %s", strerror(errno));
    }

    /* We also need to increment the KB upload count.  We know the number
     * of bytes downloaded as an off_t here, but we only store the number of KB
     * in the mod_snmp db tables.
     * 
     * We could just increment by xfer_bytes / 1024, but that would mean that
     * several small files of say 999 bytes could be uploaded, and the KB
     * count would not be incremented.
     *
     * To deal with this situation, we use the snmp_stor_bytes static variable
     * as a "holding bucket" of bytes, from which we get the KB to add to the
     * db tables.
     */
    snmp_stor_bytes += session.xfer.total_bytes;

    stor_kb = (snmp_stor_bytes / 1024);
    rem_bytes = (snmp_stor_bytes % 1024);

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTP_XFERS_F_KB_UPLOAD_TOTAL, stor_kb);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftp.dataTransfers.kbUploadTotal: %s", strerror(errno));
    }

    snmp_stor_bytes = rem_bytes;

  } else if (strncmp(proto, "ftps", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTPS_XFERS_F_FILE_UPLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "ftps.tlsDataTransfers.fileUploadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTPS_XFERS_F_FILE_UPLOAD_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsDataTransfers.fileUploadTotal: %s", strerror(errno));
    }

    /* We also need to increment the KB upload count.  We know the number
     * of bytes downloaded as an off_t here, but we only store the number of KB
     * in the mod_snmp db tables.
     * 
     * We could just increment by xfer_bytes / 1024, but that would mean that
     * several small files of say 999 bytes could be uploaded, and the KB
     * count would not be incremented.
     *
     * To deal with this situation, we use the snmp_stor_bytes static variable
     * as a "holding bucket" of bytes, from which we get the KB to add to the
     * db tables.
     */
    snmp_stor_bytes += session.xfer.total_bytes;

    stor_kb = (snmp_stor_bytes / 1024);
    rem_bytes = (snmp_stor_bytes % 1024);

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTPS_XFERS_F_KB_UPLOAD_TOTAL, stor_kb);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsDataTransfers.kbUploadTotal: %s", strerror(errno));
    }

    snmp_stor_bytes = rem_bytes;

  } else if (strncmp(proto, "sftp", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SFTP_XFERS_F_FILE_UPLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "sftp.sftpDataTransfers.fileUploadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SFTP_XFERS_F_FILE_UPLOAD_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "sftp.sftpDataTransfers.fileUploadTotal: %s", strerror(errno));
    }

    /* We also need to increment the KB upload count.  We know the number
     * of bytes downloaded as an off_t here, but we only store the number of KB
     * in the mod_snmp db tables.
     * 
     * We could just increment by xfer_bytes / 1024, but that would mean that
     * several small files of say 999 bytes could be uploaded, and the KB
     * count would not be incremented.
     *
     * To deal with this situation, we use the snmp_stor_bytes static variable
     * as a "holding bucket" of bytes, from which we get the KB to add to the
     * db tables.
     */
    snmp_stor_bytes += session.xfer.total_bytes;

    stor_kb = (snmp_stor_bytes / 1024);
    rem_bytes = (snmp_stor_bytes % 1024);

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SFTP_XFERS_F_KB_UPLOAD_TOTAL, stor_kb);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "sftp.sftpDataTransfers.kbUploadTotal: %s", strerror(errno));
    }

    snmp_stor_bytes = rem_bytes;

  } else if (strncmp(proto, "scp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SCP_XFERS_F_FILE_UPLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "scp.scpDataTransfers.fileUploadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SCP_XFERS_F_FILE_UPLOAD_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "scp.scpDataTransfers.fileUploadTotal: %s", strerror(errno));
    }

    /* We also need to increment the KB upload count.  We know the number
     * of bytes downloaded as an off_t here, but we only store the number of KB
     * in the mod_snmp db tables.
     * 
     * We could just increment by xfer_bytes / 1024, but that would mean that
     * several small files of say 999 bytes could be uploaded, and the KB
     * count would not be incremented.
     *
     * To deal with this situation, we use the snmp_stor_bytes static variable
     * as a "holding bucket" of bytes, from which we get the KB to add to the
     * db tables.
     */
    snmp_stor_bytes += session.xfer.total_bytes;

    stor_kb = (snmp_stor_bytes / 1024);
    rem_bytes = (snmp_stor_bytes % 1024);

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SCP_XFERS_F_KB_UPLOAD_TOTAL, stor_kb);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "scp.scpDataTransfers.kbUploadTotal: %s", strerror(errno));
    }

    snmp_stor_bytes = rem_bytes;
  }

  return PR_DECLINED(cmd);
}

MODRET snmp_err_stor(cmd_rec *cmd) {
  const char *proto;
  int res;

  if (snmp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);

  if (strncmp(proto, "ftp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "ftp.dataTransfers.fileUploadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTP_XFERS_F_FILE_UPLOAD_ERR_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftp.dataTransfers.fileUploadFailedTotal: %s", strerror(errno));
    }

  } else if (strncmp(proto, "ftps", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTPS_XFERS_F_FILE_UPLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "ftps.tlsDataTransfers.fileUploadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_FTPS_XFERS_F_FILE_UPLOAD_ERR_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsDataTransfers.fileUploadFailedTotal: %s", strerror(errno));
    }

  } else if (strncmp(proto, "sftp", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SFTP_XFERS_F_FILE_UPLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "sftp.sftpDataTransfers.fileUploadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SFTP_XFERS_F_FILE_UPLOAD_ERR_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "sftp.sftpDataTransfers.fileUploadFailedTotal: %s", strerror(errno));
    }

  } else if (strncmp(proto, "scp", 4) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SCP_XFERS_F_FILE_UPLOAD_COUNT, -1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error decrementing SNMP database for "
        "scp.scpDataTransfers.fileUploadCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool,
      SNMP_DB_SCP_XFERS_F_FILE_UPLOAD_ERR_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "scp.scpDataTransfers.fileUploadFailedTotal: %s", strerror(errno));
    }
  }

  return PR_DECLINED(cmd);
}

MODRET snmp_log_auth(cmd_rec *cmd) {
  const char *proto;
  int res;

  if (snmp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Note: we are not currently properly incrementing
   * SNMP_DB_FTPS_SESS_F_SESS_COUNT and SNMP_DB_FTPS_SESS_F_SESS_TOTAL
   * for FTPS connections accepted using the UseImplicitSSL TLSOption.
   *
   * The issue is that for those connections, the protocol will be set to
   * "ftps" in mod_tls' sess_init callback.  But here in mod_snmp, we
   * are not guaranteed to being called AFTER mod_tls, due to module load
   * ordering.  Thus we do not have a good way of determining when to
   * increment those counts for implicit FTPS connections.
   */

  proto = pr_session_get_protocol(0);
  if (strncmp(proto, "ftps", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTPS_SESS_F_SESS_COUNT,
      1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsSessions.sessionCount: %s", strerror(errno));
    }

    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTPS_SESS_F_SESS_TOTAL,
      1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsSessions.sessionTotal: %s", strerror(errno));
    }

  } else {
    /* XXX Some other RFC2228 mechanism (e.g. mod_gss) */
  }

  return PR_DECLINED(cmd);
}

MODRET snmp_log_ccc(cmd_rec *cmd) {
  const char *proto;
  int res;

  if (snmp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  if (strncmp(proto, "ftps", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTPS_SESS_F_CCC_TOTAL, 1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsSessions.clearCommandChannelTotal: %s", strerror(errno));
    }
  }

  return PR_DECLINED(cmd);
}

MODRET snmp_err_ccc(cmd_rec *cmd) {
  const char *proto;
  int res;

  if (snmp_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  if (strncmp(proto, "ftps", 5) == 0) {
    res = snmp_db_incr_value(cmd->tmp_pool, SNMP_DB_FTPS_SESS_F_CCC_ERR_TOTAL,
      1);
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error incrementing SNMP database for "
        "ftps.tlsSessions.clearCommandChannelFailedTotal: %s", strerror(errno));
    }
  }

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

static void ev_incr_value(unsigned int field_id, const char *field_str,
    int32_t incr) {
  int res;
  pool *p;

  p = session.pool;
  if (p == NULL) {
    p = snmp_pool;
  }
 
  res = snmp_db_incr_value(p, field_id, incr);
  if (res < 0) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "error %s SNMP database for %s: %s",
      incr < 0 ? "decrementing" : "incrementing", field_str, strerror(errno));
  }
}

static void snmp_auth_code_ev(const void *event_data, void *user_data) {
  int auth_code, res;
  unsigned int field_id = SNMP_DB_ID_UNKNOWN, is_ftps = FALSE, notify_id = 0;
  const char *notify_str = NULL, *proto;

  if (snmp_engine == FALSE) {
    return;
  }

  auth_code = *((int *) event_data);

  /* Any notifications we generate here may depend on the protocol in use. */
  proto = pr_session_get_protocol(0);

  if (strncmp(proto, "ftps", 5) == 0) {
    is_ftps = TRUE;
  }

  switch (auth_code) {
    case PR_AUTH_RFC2228_OK:
      if (is_ftps == TRUE) {
        field_id = SNMP_DB_FTPS_LOGINS_F_CERT_TOTAL;
      }
      break;

    case PR_AUTH_NOPWD:
      if (is_ftps == FALSE) {
        field_id = SNMP_DB_FTP_LOGINS_F_ERR_BAD_USER_TOTAL;

      } else {
        field_id = SNMP_DB_FTPS_LOGINS_F_ERR_BAD_USER_TOTAL;
      }

      notify_id = SNMP_NOTIFY_FTP_BAD_USER;
      notify_str = "loginFailedBadUser";
      break;

    case PR_AUTH_BADPWD:
      if (is_ftps == FALSE) {
        field_id = SNMP_DB_FTP_LOGINS_F_ERR_BAD_PASSWD_TOTAL;

      } else {
        field_id = SNMP_DB_FTPS_LOGINS_F_ERR_BAD_PASSWD_TOTAL;
      }

      notify_id = SNMP_NOTIFY_FTP_BAD_PASSWD;
      notify_str = "loginFailedBadPassword";
      break;

    default:
      if (is_ftps == FALSE) {
        field_id = SNMP_DB_FTP_LOGINS_F_ERR_GENERAL_TOTAL;

      } else {
        field_id = SNMP_DB_FTPS_LOGINS_F_ERR_GENERAL_TOTAL;
      }

      break;
  }
 
  if (auth_code >= 0) {
    ev_incr_value(field_id, "login total", 1); 

    /* We only send notifications for failed authentications. */
    return;

  } else {
    ev_incr_value(field_id, "login failure total", 1); 
  }

  if (notify_id > 0 &&
      snmp_notifys != NULL) {
    register unsigned int i;
    pr_netaddr_t **dst_addrs;

    dst_addrs = snmp_notifys->elts;
    for (i = 0; i < snmp_notifys->nelts; i++) {
      res = snmp_notify_generate(snmp_pool, -1, snmp_community,
        session.c->local_addr, dst_addrs[i], notify_id);
      if (res < 0) {
        (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
          "unable to send %s notification to SNMPNotify %s:%d: %s", notify_str,
          pr_netaddr_get_ipstr(dst_addrs[i]),
          ntohs(pr_netaddr_get_port(dst_addrs[i])), strerror(errno));
      }
    }
  }
}

static void snmp_cmd_invalid_ev(const void *event_data, void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }
  
  ev_incr_value(SNMP_DB_FTP_SESS_F_CMD_INVALID_TOTAL,
    "ftp.connections.commandInvalidTotal", 1);
}

static void snmp_exit_ev(const void *event_data, void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_DAEMON_F_CONN_COUNT, "daemon.connectionCount", -1);

  if (session.disconnect_reason == PR_SESS_DISCONNECT_SESSION_INIT_FAILED) {
    ev_incr_value(SNMP_DB_DAEMON_F_CONN_REFUSED_TOTAL,
      "daemon.connectionRefusedTotal", 1);

  } else {
    const char *proto;

    proto = pr_session_get_protocol(0);

    if (strncmp(proto, "ftp", 4) == 0) {
      ev_incr_value(SNMP_DB_FTP_SESS_F_SESS_COUNT,
        "ftp.sessions.sessionCount", -1);

      if (session.anon_config != NULL) {
        ev_incr_value(SNMP_DB_FTP_LOGINS_F_ANON_COUNT,
          "ftp.logins.anonLoginCount", -1);
      }

    } else if (strncmp(proto, "ftps", 5) == 0) {
      ev_incr_value(SNMP_DB_FTPS_SESS_F_SESS_COUNT,
        "ftps.tlsSessions.sessionCount", -1);

    } else {
      /* XXX ssh2/sftp/scp session end */
    }
  }

  if (snmp_logfd >= 0) {
    (void) close(snmp_logfd);
    snmp_logfd = -1;
  }
}

static void snmp_max_inst_ev(const void *event_data, void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_DAEMON_F_MAXINST_TOTAL,
    "daemon.maxInstancesLimitTotal", 1);
  
  if (snmp_notifys != NULL) {
    register unsigned int i;
    pr_netaddr_t **dst_addrs;
    unsigned int notify_id = SNMP_NOTIFY_DAEMON_MAX_INSTANCES;
    int res;

    dst_addrs = snmp_notifys->elts;
    for (i = 0; i < snmp_notifys->nelts; i++) {
      res = snmp_notify_generate(snmp_pool, -1, snmp_community,
        session.c->local_addr, dst_addrs[i], notify_id);
      if (res < 0) {
        (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
          "unable to send daemonMaxInstancesExceeded notification to "
          "SNMPNotify %s:%d: %s", pr_netaddr_get_ipstr(dst_addrs[i]),
          ntohs(pr_netaddr_get_port(dst_addrs[i])), strerror(errno));
      }
    }
  }
}

#if defined(PR_SHARED_MODULE)
static void snmp_mod_unload_ev(const void *event_data, void *user_data) {
  if (strncmp((const char *) event_data, "mod_snmp.c", 11) == 0) {
    register unsigned int i;

    /* Unregister ourselves from all events. */
    pr_event_unregister(&snmp_module, NULL, NULL);

    for (i = 0; snmp_table_ids[i] > 0; i++) {
      snmp_db_close(snmp_pool, snmp_table_ids[i]);
    }

    destroy_pool(snmp_pool);
    snmp_pool = NULL;

    (void) close(snmp_logfd);
    snmp_logfd = -1;
  }
}
#endif

static void snmp_postparse_ev(const void *event_data, void *user_data) {
  register unsigned int i;
  config_rec *c;
  server_rec *s;
  unsigned int nvhosts = 0;
  const char *tables_dir;
  int agent_type, res;
  array_header *agent_addrs;
  unsigned char ban_loaded = FALSE, sftp_loaded = FALSE, tls_loaded = FALSE;

  c = find_config(main_server->conf, CONF_PARAM, "SNMPEngine", FALSE);
  if (c) {
    snmp_engine = *((int *) c->argv[0]);
  }

  if (snmp_engine == FALSE) {
    return;
  }

  snmp_openlog();

  c = find_config(main_server->conf, CONF_PARAM, "SNMPOptions", FALSE);
  while (c != NULL) {
    unsigned long opts = 0;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    snmp_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "SNMPOptions", FALSE);
  }

  c = find_config(main_server->conf, CONF_PARAM, "SNMPCommunity", FALSE);
  if (c == NULL) {
    /* No SNMPCommunity configured, mod_snmp cannot authenticate messages
     * properly.
     */
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "no SNMPCommunity configured, disabling module");

    snmp_engine = FALSE;
    return;
  }

  snmp_community = c->argv[0];

  c = find_config(main_server->conf, CONF_PARAM, "SNMPMaxVariables", FALSE);
  if (c != NULL) {
    snmp_max_variables = *((unsigned int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "SNMPTables", FALSE);
  if (c == NULL) {
    /* No SNMPTables configured, mod_snmp cannot run. */
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "no SNMPTables configured, disabling module");

    snmp_engine = FALSE;
    return;
  }

  tables_dir = c->argv[0];

  if (snmp_db_set_root(tables_dir) < 0) {
    /* Unable to configure the SNMPTables root for some reason... */

    snmp_engine = FALSE;
    return;
  }

  /* Create the variable database table files, based on the configured
   * SNMPTables path.
   */
  tls_loaded = pr_module_exists("mod_tls.c");
  sftp_loaded = pr_module_exists("mod_sftp.c");
  ban_loaded = pr_module_exists("mod_ban.c");

  for (i = 0; snmp_table_ids[i] > 0; i++) {
    int skip_table = FALSE;

    switch (snmp_table_ids[i]) {
      case SNMP_DB_ID_TLS:
        if (tls_loaded == FALSE) {
          skip_table = TRUE;
        }
        break;

      case SNMP_DB_ID_SSH:
      case SNMP_DB_ID_SFTP:
      case SNMP_DB_ID_SCP:
        if (sftp_loaded == FALSE) {
          skip_table = TRUE;
        }
        break;

      case SNMP_DB_ID_BAN:
        if (ban_loaded == FALSE) {
          skip_table = TRUE;
        }
        break;

      default:
        break;
    }

    if (skip_table) {
      continue;
    }

    res = snmp_db_open(snmp_pool, snmp_table_ids[i]);
    if (res < 0) {
      register unsigned int j;

      /* If we fail to open this table, BUT have succeeded in opening previous
       * tables, AND we are just going to return here, then we need to make
       * sure to close the previously opened tables.
       */
      for (j = 0; snmp_table_ids[j] > 0 && j < i; j++) {
        (void) snmp_db_close(snmp_pool, snmp_table_ids[j]);
      }

      snmp_engine = FALSE;
      return;
    }
  }

  /* Initial the MIBs. */
  snmp_mib_init();

  /* Iterate through the server_list, and count up the number of vhosts. */
  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    nvhosts++;
  }

  ev_incr_value(SNMP_DB_DAEMON_F_VHOST_COUNT, "daemon.vhostCount", nvhosts);

  c = find_config(main_server->conf, CONF_PARAM, "SNMPAgent", FALSE);
  if (c == NULL) {
    snmp_engine = FALSE;
    pr_log_debug(DEBUG0, MOD_SNMP_VERSION
      ": missing required SNMPAgent directive, disabling module");

    /* Need to close database tables here. */
    for (i = 0; snmp_table_ids[i] > 0; i++) {
      (void) snmp_db_close(snmp_pool, snmp_table_ids[i]);
    }

    return;
  }

  agent_type = *((int *) c->argv[0]);
  agent_addrs = c->argv[1];

  snmp_agent_pid = snmp_agent_start(tables_dir, agent_type, agent_addrs);
  if (snmp_agent_pid == 0) {
    snmp_engine = FALSE;
    pr_log_debug(DEBUG0, MOD_SNMP_VERSION
      ": failed to start agent listening process, disabling module");

    /* Need to close database tables here. */
    for (i = 0; snmp_table_ids[i] > 0; i++) {
      (void) snmp_db_close(snmp_pool, snmp_table_ids[i]);
    }
  }

  return;
}

static void snmp_restart_ev(const void *event_data, void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_DAEMON_F_RESTART_COUNT, "daemon.restartCount", 1);

  if (snmp_opts & SNMP_OPT_RESTART_CLEARS_COUNTERS) {
    int res;

    pr_trace_msg(trace_channel, 17,
      "restart event received, resetting counters");
    res = snmp_mib_reset_counters();
    if (res < 0) {
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "error resetting SNMP database counters: %s", strerror(errno));
    }
  }

  snmp_agent_stop(snmp_agent_pid);

  /* Close the SNMPLog file descriptor; it will be reopened in the
   * postparse event listener.
   */
  (void) close(snmp_logfd);
  snmp_logfd = -1;
}

static void snmp_shutdown_ev(const void *event_data, void *user_data) {
  register unsigned int i;

  snmp_agent_stop(snmp_agent_pid);

  for (i = 0; snmp_table_ids[i] > 0; i++) {
    snmp_db_close(snmp_pool, snmp_table_ids[i]);
  }

  destroy_pool(snmp_pool);
  snmp_pool = NULL;

  (void) close(snmp_logfd);
  snmp_logfd = -1;
}

static void snmp_startup_ev(const void *event_data, void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  if (ServerType == SERVER_INETD) {
    snmp_engine = FALSE;
    pr_log_debug(DEBUG0, MOD_SNMP_VERSION
      ": cannot support SNMP for ServerType inetd, disabling module");
    return;
  }

  gettimeofday(&snmp_start_tv, NULL);
  return;
}

static void snmp_timeout_idle_ev(const void *event_data, void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_TIMEOUTS_F_IDLE_TOTAL,
    "timeouts.idleTimeoutTotal", 1);
}

static void snmp_timeout_login_ev(const void *event_data, void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_TIMEOUTS_F_LOGIN_TOTAL,
    "timeouts.loginTimeoutTotal", 1);
}

static void snmp_timeout_noxfer_ev(const void *event_data, void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_TIMEOUTS_F_NOXFER_TOTAL,
    "timeouts.noTransferTimeoutTotal", 1);
}

static void snmp_timeout_stalled_ev(const void *event_data, void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_TIMEOUTS_F_STALLED_TOTAL,
    "timeouts.stalledTimeoutTotal", 1);
}

/* mod_tls-generated events */
static void snmp_tls_ctrl_handshake_err_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }
  
  ev_incr_value(SNMP_DB_FTPS_SESS_F_CTRL_HANDSHAKE_ERR_TOTAL,
    "ftps.tlsSessions.ctrlHandshakeFailedTotal", 1);
}

static void snmp_tls_data_handshake_err_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }
  
  ev_incr_value(SNMP_DB_FTPS_SESS_F_DATA_HANDSHAKE_ERR_TOTAL,
    "ftps.tlsSessions.dataHandshakeFailedTotal", 1);
}

static void snmp_tls_verify_client_ev(const void *event_data, void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  } 

  ev_incr_value(SNMP_DB_FTPS_SESS_F_VERIFY_CLIENT_TOTAL,
    "ftps.tlsSessions.verifyClientTotal", 1);
}

static void snmp_tls_verify_client_err_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_FTPS_SESS_F_VERIFY_CLIENT_ERR_TOTAL,
    "ftps.tlsSessions.verifyClientFailedTotal", 1);
}

/* mod_sftp-generated events */
static void snmp_ssh2_kex_err_ev(const void *event_data, void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SSH_SESS_F_KEX_ERR_TOTAL,
    "ssh.sshSessions.keyExchangeFailedTotal", 1);
}

static void snmp_ssh2_c2s_compress_ev(const void *event_data, void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SSH_SESS_F_C2S_COMPRESS_TOTAL,
    "ssh.sshSessions.clientCompressionTotal", 1);
}

static void snmp_ssh2_s2c_compress_ev(const void *event_data, void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SSH_SESS_F_S2C_COMPRESS_TOTAL,
    "ssh.sshSessions.serverCompressionTotal", 1);
}

static void snmp_ssh2_auth_hostbased_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SSH_LOGINS_F_HOSTBASED_TOTAL,
    "ssh.sshLogins.hostbasedAuthTotal", 1);
}

static void snmp_ssh2_auth_hostbased_err_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SSH_LOGINS_F_HOSTBASED_ERR_TOTAL,
    "ssh.sshLogins.hostbasedAuthFailedTotal", 1);
}

static void snmp_ssh2_auth_kbdint_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SSH_LOGINS_F_KBDINT_TOTAL,
    "ssh.sshLogins.keyboardInteractiveAuthTotal", 1);
}

static void snmp_ssh2_auth_kbdint_err_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SSH_LOGINS_F_KBDINT_ERR_TOTAL,
    "ssh.sshLogins.keyboardInteractiveAuthFailedTotal", 1);
}

static void snmp_ssh2_auth_passwd_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SSH_LOGINS_F_PASSWD_TOTAL,
    "ssh.sshLogins.passwordAuthTotal", 1);
}

static void snmp_ssh2_auth_passwd_err_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SSH_LOGINS_F_PASSWD_ERR_TOTAL,
    "ssh.sshLogins.passwordAuthFailedTotal", 1);
}

static void snmp_ssh2_auth_publickey_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SSH_LOGINS_F_PUBLICKEY_TOTAL,
    "ssh.sshLogins.publickeyAuthTotal", 1);
}

static void snmp_ssh2_auth_publickey_err_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SSH_LOGINS_F_PUBLICKEY_ERR_TOTAL,
    "ssh.sshLogins.publickeyAuthFailedTotal", 1);
}

static void snmp_ssh2_sftp_proto_version_ev(const void *event_data,
    void *user_data) {
  unsigned long protocol_version;
  unsigned int field_id;
  const char *field_str;

  if (snmp_engine == FALSE) {
    return;
  }

  if (event_data == NULL) {
    /* Missing required data. */
    return;
  }

  protocol_version = *((unsigned long *) event_data);

  switch (protocol_version) {
    case 3:
      field_id = SNMP_DB_SFTP_SESS_F_SFTP_V3_TOTAL;
      field_str = "sftp.sftpSessions.protocolVersion3Total";
      break;

    case 4:
      field_id = SNMP_DB_SFTP_SESS_F_SFTP_V4_TOTAL;
      field_str = "sftp.sftpSessions.protocolVersion4Total";
      break;

    case 5:
      field_id = SNMP_DB_SFTP_SESS_F_SFTP_V5_TOTAL;
      field_str = "sftp.sftpSessions.protocolVersion5Total";
      break;

    case 6:
      field_id = SNMP_DB_SFTP_SESS_F_SFTP_V6_TOTAL;
      field_str = "sftp.sftpSessions.protocolVersion6Total";
      break;

    default:
      (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
        "unknown SFTP protocol version %lu, ignoring", protocol_version);
      return;
  }

  ev_incr_value(field_id, field_str, 1);
}

static void snmp_ssh2_sftp_sess_opened_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SFTP_SESS_F_SESS_COUNT,
    "sftp.sftpSessions.sessionCount", 1);
  ev_incr_value(SNMP_DB_SFTP_SESS_F_SESS_TOTAL,
    "sftp.sftpSessions.sessionTotal", 1);
}

static void snmp_ssh2_sftp_sess_closed_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SFTP_SESS_F_SESS_COUNT,
    "sftp.sftpSessions.sessionCount", -1);
}

static void snmp_ssh2_scp_sess_opened_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SCP_SESS_F_SESS_COUNT,
    "scp.scpSessions.sessionCount", 1);
  ev_incr_value(SNMP_DB_SCP_SESS_F_SESS_TOTAL,
    "scp.scpSessions.sessionTotal", 1);
}

static void snmp_ssh2_scp_sess_closed_ev(const void *event_data,
    void *user_data) {
  if (snmp_engine == FALSE) {
    return;
  }

  ev_incr_value(SNMP_DB_SCP_SESS_F_SESS_COUNT,
    "scp.scpSessions.sessionCount", -1);
}

/* mod_ban-generated events */
static void snmp_ban_ban_user_ev(const void *event_data, void *user_data) {
  ev_incr_value(SNMP_DB_BAN_BANS_F_USER_BAN_COUNT, "ban.bans.userBanCount", 1);
  ev_incr_value(SNMP_DB_BAN_BANS_F_USER_BAN_TOTAL, "ban.bans.userBanTotal", 1);

  ev_incr_value(SNMP_DB_BAN_BANS_F_BAN_COUNT, "ban.bans.banCount", 1);
  ev_incr_value(SNMP_DB_BAN_BANS_F_BAN_TOTAL, "ban.bans.banTotal", 1);
}

static void snmp_ban_ban_host_ev(const void *event_data, void *user_data) {
  ev_incr_value(SNMP_DB_BAN_BANS_F_HOST_BAN_COUNT, "ban.bans.hostBanCount", 1);
  ev_incr_value(SNMP_DB_BAN_BANS_F_HOST_BAN_TOTAL, "ban.bans.hostBanTotal", 1);

  ev_incr_value(SNMP_DB_BAN_BANS_F_BAN_COUNT, "ban.bans.banCount", 1);
  ev_incr_value(SNMP_DB_BAN_BANS_F_BAN_TOTAL, "ban.bans.banTotal", 1);
}

static void snmp_ban_ban_class_ev(const void *event_data, void *user_data) {
  ev_incr_value(SNMP_DB_BAN_BANS_F_CLASS_BAN_COUNT,
    "ban.bans.classBanCount", 1);
  ev_incr_value(SNMP_DB_BAN_BANS_F_CLASS_BAN_TOTAL,
    "ban.bans.classBanTotal", 1);

  ev_incr_value(SNMP_DB_BAN_BANS_F_BAN_COUNT, "ban.bans.banCount", 1);
  ev_incr_value(SNMP_DB_BAN_BANS_F_BAN_TOTAL, "ban.bans.banTotal", 1);
}

static void snmp_ban_expired_ban_ev(const void *event_data, void *user_data) {
  const char *ban_desc = NULL;

  if (event_data != NULL) {
    char *ptr = NULL;

    ban_desc = (const char *) event_data;

    ptr = strchr(ban_desc, ':');
    if (ptr != NULL) {
      /* To get the specific ban criteria/name later, use ptr + 1. */

      if (strncmp(ban_desc, "USER", 4) == 0) {
        ev_incr_value(SNMP_DB_BAN_BANS_F_USER_BAN_COUNT,
          "ban.bans.userBanCount", -1);

      } else if (strncmp(ban_desc, "HOST", 4) == 0) {
        ev_incr_value(SNMP_DB_BAN_BANS_F_HOST_BAN_COUNT,
          "ban.bans.hostBanCount", -1);

      } else if (strncmp(ban_desc, "CLASS", 5) == 0) {
        ev_incr_value(SNMP_DB_BAN_BANS_F_CLASS_BAN_COUNT,
          "ban.bans.classBanCount", -1);
      }

      ev_incr_value(SNMP_DB_BAN_BANS_F_BAN_COUNT, "ban.bans.banCount", -1);
    }
  }
}

static void snmp_ban_client_disconn_ev(const void *event_data,
    void *user_data) {
  const char *ban_desc = NULL;

  if (event_data != NULL) {
    char *ptr = NULL;

    ban_desc = (const char *) event_data;

    ptr = strchr(ban_desc, ':');
    if (ptr != NULL) {
      /* To get the specific ban criteria/name later, use ptr + 1. */

      if (strncmp(ban_desc, "USER", 4) == 0) {
        ev_incr_value(SNMP_DB_BAN_CONNS_F_USER_BAN_TOTAL,
          "ban.connections.userBannedTotal", 1);

      } else if (strncmp(ban_desc, "HOST", 4) == 0) {
        ev_incr_value(SNMP_DB_BAN_CONNS_F_HOST_BAN_TOTAL,
          "ban.connections.hostBannedTotal", 1);

      } else if (strncmp(ban_desc, "CLASS", 5) == 0) {
        ev_incr_value(SNMP_DB_BAN_CONNS_F_CLASS_BAN_TOTAL,
          "ban.connections.classBannedTotal", 1);
      }

      ev_incr_value(SNMP_DB_BAN_CONNS_F_CONN_BAN_TOTAL,
        "ban.connections.connectionBannedTotal", 1);
    }
  }
}

/* XXX Do we want to support any Controls/ftpctl actions? */

/* Initialization routines
 */

static int snmp_init(void) {
  struct protoent *pre = NULL;

  snmp_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(snmp_pool, MOD_SNMP_VERSION);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&snmp_module, "core.module-unload", snmp_mod_unload_ev,
    NULL);
#endif
  pr_event_register(&snmp_module, "core.postparse", snmp_postparse_ev, NULL);
  pr_event_register(&snmp_module, "core.restart", snmp_restart_ev, NULL);
  pr_event_register(&snmp_module, "core.shutdown", snmp_shutdown_ev, NULL);
  pr_event_register(&snmp_module, "core.startup", snmp_startup_ev, NULL);

  /* Normally we should register the 'core.exit' event listener in the
   * sess_init callback.  However, we use this listener to listen for
   * refused connections, e.g. connections refused by other modules'
   * sess_init callbacks.  And depending on the module load order, another
   * module might refuse the connection before mod_snmp's sess_init callback
   * is invoked, which would prevent mod_snmp from registering its 'core.exit'
   * event listener.
   *
   * Thus to work around this timing issue, we register our 'core.exit' event
   * listener here, in the daemon process.  It should not hurt anything.
   */
  pr_event_register(&snmp_module, "core.exit", snmp_exit_ev, NULL);

#ifdef HAVE_SETPROTOENT
  setprotoent(FALSE);
#endif

  pre = getprotobyname("udp");
  if (pre != NULL) {
    snmp_proto_udp = pre->p_proto;
  }

#ifdef HAVE_ENDPROTOENT
  endprotoent();
#endif

#ifdef HAVE_RANDOM
  /* Seed the random(3) generator. */ 
  srandom((unsigned int) (time(NULL) * getpid())); 
#endif /* HAVE_RANDOM */

  return 0;
}

static int snmp_sess_init(void) {
  config_rec *c;
  int res;

  c = find_config(main_server->conf, CONF_PARAM, "SNMPEnable", FALSE);
  if (c) {
    snmp_enabled = *((int *) c->argv[0]);
  }

  if (snmp_enabled == FALSE) {
    snmp_engine = FALSE;
    return 0;
  }

  pr_event_register(&snmp_module, "core.invalid-command",
    snmp_cmd_invalid_ev, NULL);
  pr_event_register(&snmp_module, "core.max-instances",
    snmp_max_inst_ev, NULL);
  pr_event_register(&snmp_module, "core.timeout-idle",
    snmp_timeout_idle_ev, NULL);
  pr_event_register(&snmp_module, "core.timeout-login",
    snmp_timeout_login_ev, NULL);
  pr_event_register(&snmp_module, "core.timeout-no-transfer",
    snmp_timeout_noxfer_ev, NULL);
  pr_event_register(&snmp_module, "core.timeout-stalled",
    snmp_timeout_stalled_ev, NULL);
  pr_event_register(&snmp_module, "core.unhandled-command",
    snmp_cmd_invalid_ev, NULL);

  pr_event_register(&snmp_module, "mod_auth.authentication-code",
    snmp_auth_code_ev, NULL);

  if (pr_module_exists("mod_tls.c") == TRUE) {
    /* mod_tls events */
    pr_event_register(&snmp_module, "mod_tls.ctrl-handshake-failed",
      snmp_tls_ctrl_handshake_err_ev, NULL);
    pr_event_register(&snmp_module, "mod_tls.data-handshake-failed",
      snmp_tls_data_handshake_err_ev, NULL);

    pr_event_register(&snmp_module, "mod_tls.verify-client",
      snmp_tls_verify_client_ev, NULL);
    pr_event_register(&snmp_module, "mod_tls.verify-client-failed",
      snmp_tls_verify_client_err_ev, NULL);
  }

  if (pr_module_exists("mod_sftp.c") == TRUE) {
    /* mod_sftp events */

    pr_event_register(&snmp_module, "mod_sftp.ssh2.kex.failed",
      snmp_ssh2_kex_err_ev, NULL);
    pr_event_register(&snmp_module, "mod_sftp.ssh2.client-compression",
      snmp_ssh2_c2s_compress_ev, NULL);
    pr_event_register(&snmp_module, "mod_sftp.ssh2.server-compression",
      snmp_ssh2_s2c_compress_ev, NULL);

    pr_event_register(&snmp_module, "mod_sftp.ssh2.auth-hostbased",
      snmp_ssh2_auth_hostbased_ev, NULL);
    pr_event_register(&snmp_module, "mod_sftp.ssh2.auth-hostbased.failed",
      snmp_ssh2_auth_hostbased_err_ev, NULL);

    pr_event_register(&snmp_module, "mod_sftp.ssh2.auth-kbdint",
      snmp_ssh2_auth_kbdint_ev, NULL);
    pr_event_register(&snmp_module, "mod_sftp.ssh2.auth-kbdint.failed",
      snmp_ssh2_auth_kbdint_err_ev, NULL);

    pr_event_register(&snmp_module, "mod_sftp.ssh2.auth-password",
      snmp_ssh2_auth_passwd_ev, NULL);
    pr_event_register(&snmp_module, "mod_sftp.ssh2.auth-password.failed",
      snmp_ssh2_auth_passwd_err_ev, NULL);

    pr_event_register(&snmp_module, "mod_sftp.ssh2.auth-publickey",
      snmp_ssh2_auth_publickey_ev, NULL);
    pr_event_register(&snmp_module, "mod_sftp.ssh2.auth-publickey.failed",
      snmp_ssh2_auth_publickey_err_ev, NULL);

    pr_event_register(&snmp_module, "mod_sftp.sftp.session-opened",
      snmp_ssh2_sftp_sess_opened_ev, NULL);
    pr_event_register(&snmp_module, "mod_sftp.sftp.session-closed",
      snmp_ssh2_sftp_sess_closed_ev, NULL);
    pr_event_register(&snmp_module, "mod_sftp.sftp.protocol-version",
      snmp_ssh2_sftp_proto_version_ev, NULL);

    pr_event_register(&snmp_module, "mod_sftp.scp.session-opened",
      snmp_ssh2_scp_sess_opened_ev, NULL);
    pr_event_register(&snmp_module, "mod_sftp.scp.session-closed",
      snmp_ssh2_scp_sess_closed_ev, NULL);
  }

  if (pr_module_exists("mod_ban.c") == TRUE) {
    /* mod_ban events */

    pr_event_register(&snmp_module, "mod_ban.ban-user", snmp_ban_ban_user_ev,
      NULL);
    pr_event_register(&snmp_module, "mod_ban.ban-host", snmp_ban_ban_host_ev,
      NULL);
    pr_event_register(&snmp_module, "mod_ban.ban-class", snmp_ban_ban_class_ev,
      NULL);

    /* Note: For these event listeners to work as expected, the mod_snmp
     * module needs to be loaded AFTER mod_ban, i.e.:
     *
     *   --with-modules=....:mod_ban:mod_snmp:...
     *
     * or:
     *
     *  LoadModule mod_ban.c
     *  ...
     *  LoadModule mod_snmp.c
     *
     * That we, we can have our event listeners registered by the time that
     * mod_ban's sess_init callback causes events to be generated for an
     * incoming connection (including ban expiration).
     */
    pr_event_register(&snmp_module, "mod_ban.ban.expired",
      snmp_ban_expired_ban_ev, NULL);
    pr_event_register(&snmp_module, "mod_ban.ban.client-disconnected",
      snmp_ban_client_disconn_ev, NULL);
  }

  res = snmp_db_incr_value(session.pool, SNMP_DB_DAEMON_F_CONN_COUNT, 1);
  if (res < 0) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "error incrementing daemon.connectionCount: %s",
      strerror(errno));
  }

  res = snmp_db_incr_value(session.pool, SNMP_DB_DAEMON_F_CONN_TOTAL, 1);
  if (res < 0) {
    (void) pr_log_writefile(snmp_logfd, MOD_SNMP_VERSION,
      "error incrementing daemon.connectionTotal: %s",
      strerror(errno));
  }

#ifdef HAVE_RANDOM
  /* Reseed the random(3) generator. */ 
  srandom((unsigned int) (time(NULL) * getpid())); 
#endif /* HAVE_RANDOM */

  c = find_config(main_server->conf, CONF_PARAM, "SNMPNotify", FALSE);
  while (c != NULL) {
    pr_signals_handle();

    if (snmp_notifys == NULL) {
      snmp_notifys = make_array(session.pool, 1, sizeof(pr_netaddr_t *));
    }

    *((pr_netaddr_t **) push_array(snmp_notifys)) = c->argv[0];

    c = find_config_next(c, c->next, CONF_PARAM, "SNMPNotify", FALSE);
  }

  return 0;
}

/* Module API tables
 */

static conftable snmp_conftab[] = {
  { "SNMPAgent",	set_snmpagent,		NULL },
  { "SNMPCommunity",	set_snmpcommunity,	NULL },
  { "SNMPEnable",	set_snmpenable,		NULL },
  { "SNMPEngine",	set_snmpengine,		NULL },
  { "SNMPLog",		set_snmplog,		NULL },
  { "SNMPMaxVariables",	set_snmpmaxvariables,	NULL },
  { "SNMPNotify",	set_snmpnotify,		NULL },
  { "SNMPOptions",	set_snmpoptions,	NULL },
  { "SNMPTables",	set_snmptables,		NULL },
  { NULL }
};

static cmdtable snmp_cmdtab[] = {
  { PRE_CMD,		C_LIST,	G_NONE,	snmp_pre_list,	FALSE,	FALSE },
  { LOG_CMD,		C_LIST,	G_NONE,	snmp_log_list,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_LIST,	G_NONE,	snmp_err_list,	FALSE,	FALSE },

  { PRE_CMD,		C_MLSD,	G_NONE,	snmp_pre_list,	FALSE,	FALSE },
  { LOG_CMD,		C_MLSD,	G_NONE,	snmp_log_list,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_MLSD,	G_NONE,	snmp_err_list,	FALSE,	FALSE },

  { PRE_CMD,		C_NLST,	G_NONE,	snmp_pre_list,	FALSE,	FALSE },
  { LOG_CMD,		C_NLST,	G_NONE,	snmp_log_list,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_NLST,	G_NONE,	snmp_err_list,	FALSE,	FALSE },

  { LOG_CMD,		C_PASS,	G_NONE,	snmp_log_pass,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_PASS,	G_NONE,	snmp_err_pass,	FALSE,	FALSE },

  { PRE_CMD,		C_RETR,	G_NONE,	snmp_pre_retr,	FALSE,	FALSE },
  { LOG_CMD,		C_RETR,	G_NONE,	snmp_log_retr,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_RETR,	G_NONE,	snmp_err_retr,	FALSE,	FALSE },

  { PRE_CMD,		C_STOR,	G_NONE,	snmp_pre_stor,	FALSE,	FALSE },
  { LOG_CMD,		C_STOR,	G_NONE,	snmp_log_stor,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_STOR,	G_NONE,	snmp_err_stor,	FALSE,	FALSE },

  /* For mod_tls */
  { LOG_CMD,		C_AUTH,	G_NONE,	snmp_log_auth,	FALSE,	FALSE },
  { LOG_CMD,		C_CCC,	G_NONE,	snmp_log_ccc,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_CCC,	G_NONE,	snmp_err_ccc,	FALSE,	FALSE },

  { 0, NULL }
};

module snmp_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "snmp",

  /* Module configuration handler table */
  snmp_conftab,

  /* Module command handler table */
  snmp_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  snmp_init,

  /* Session initialization */
  snmp_sess_init,

  /* Module version */
  MOD_SNMP_VERSION
};

