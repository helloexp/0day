/*
 * mod_ldap - LDAP password lookup module for ProFTPD
 * Copyright (c) 1999-2013, John Morrissey <jwm@horde.net>
 * Copyright (c) 2013-2017 The ProFTPD Project
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
 * Furthermore, John Morrissey gives permission to link this program with
 * OpenSSL, and distribute the resulting executable, without including the
 * source code for OpenSSL in the source distribution.
 *
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Libraries: -lldap -llber$
 */

#include "conf.h"
#include "privs.h"

#define MOD_LDAP_VERSION	"mod_ldap/2.9.4"

#if PROFTPD_VERSION_NUMBER < 0x0001030103
# error MOD_LDAP_VERSION " requires ProFTPD 1.3.4rc1 or later"
#endif

#if defined(HAVE_CRYPT_H) && !defined(AIX4) && !defined(AIX5)
# include <crypt.h>
#endif

#include <lber.h>
#include <ldap.h>

module ldap_module;

static int ldap_logfd = -1;
static pool *ldap_pool = NULL;

static const char *trace_channel = "ldap";
#if defined(LBER_OPT_LOG_PRINT_FN)
static const char *libtrace_channel = "ldap.library";
#endif

/* Necessary prototypes */
static int ldap_sess_init(void);

#if LDAP_API_VERSION >= 2000
# define HAS_LDAP_SASL_BIND_S
#endif

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_VENDOR_VERSION >= 192)
# define HAS_LDAP_UNBIND_EXT_S
#endif

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_VENDOR_VERSION >= 19905)
# define HAS_LDAP_INITIALIZE
#endif

#ifdef HAS_LDAP_UNBIND_EXT_S
# define LDAP_UNBIND(ld) (ldap_unbind_ext_s(ld, NULL, NULL))
#else
# define LDAP_UNBIND(ld) (ldap_unbind_s(ld))
static char *ldap_server;
static int ldap_port = LDAP_PORT;
#endif

/* On some systems LDAP_OPT_DIAGNOSTIC_MESSAGE isn't there (e.g. OpenLDAP-2.3.x)
 * but LDAP_OPT_ERROR_STRING is.
 */
#ifndef LDAP_OPT_DIAGNOSTIC_MESSAGE
# ifdef LDAP_OPT_ERROR_STRING
#  define LDAP_OPT_DIAGNOSTIC_MESSAGE LDAP_OPT_ERROR_STRING
# endif
#endif

#if LDAP_API_VERSION >= 2000
# define LDAP_VALUE_T struct berval
# define LDAP_GET_VALUES(ld, entry, attr) ldap_get_values_len(ld, entry, attr)
# define LDAP_VALUE(values, i) (values[i]->bv_val)
# define LDAP_COUNT_VALUES(values) (ldap_count_values_len(values))
# define LDAP_VALUE_FREE(values) (ldap_value_free_len(values))
# define LDAP_SEARCH(ld, base, scope, filter, attrs, timeout, sizelimit, res) \
   ldap_search_ext_s(ld, base, scope, filter, attrs, 0, NULL, NULL, \
                     timeout, sizelimit, res)
#else /* LDAP_API_VERSION >= 2000 */
# define LDAP_VALUE_T char
# define LDAP_GET_VALUES(ld, entry, attr) ldap_get_values(ld, entry, attr)
# define LDAP_VALUE(values, i) (values[i])
# define LDAP_COUNT_VALUES(values) (ldap_count_values(values))
# define LDAP_VALUE_FREE(values) (ldap_value_free(values))

static void pr_ldap_set_sizelimit(LDAP *limit_ld, int limit) {
#ifdef LDAP_OPT_SIZELIMIT
  int res;

  res = ldap_set_option(limit_ld, LDAP_OPT_SIZELIMIT, (void *) &limit);
  if (res != LDAP_OPT_SUCCESS) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "failed to set LDAP option for search query size limit to %d entries: %s",
      limit, ldap_err2string(res));

  } else {
    pr_trace_msg(trace_channel, 5,
      "set search query size limit to %d entries", limit);
  }

#else
  limit_ld->ld_sizelimit = limit;

  pr_trace_msg(trace_channel, 5,
    "set search query size limit to %d entries", limit);
#endif
}

static int
LDAP_SEARCH(LDAP *ld, char *base, int scope, char *filter, char *attrs[],
            struct timeval *timeout, int sizelimit, LDAPMessage **res) {
  pr_ldap_set_sizelimit(ld, sizelimit);
  return ldap_search_st(ld, base, scope, filter, attrs, 0, timeout, res);
}
#endif /* LDAP_API_VERSION >= 2000 */

/* Thanks, Sun. */
#ifndef LDAP_OPT_SUCCESS
# define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif
#ifndef LDAP_URL_SUCCESS
# define LDAP_URL_SUCCESS LDAP_SUCCESS
#endif
#ifndef LDAP_SCOPE_DEFAULT
# define LDAP_SCOPE_DEFAULT LDAP_SCOPE_SUBTREE
#endif

/* Config entries */
static array_header *ldap_servers = NULL;
static unsigned int cur_server_index = 0;
static char *ldap_dn, *ldap_dnpass,
            *ldap_user_basedn = NULL, *ldap_user_name_filter = NULL,
            *ldap_user_uid_filter = NULL,
            *ldap_gid_basedn = NULL, *ldap_group_gid_filter = NULL,
            *ldap_group_name_filter = NULL, *ldap_group_member_filter = NULL,
            *ldap_defaultauthscheme = "crypt", *ldap_authbind_dn = NULL,
            *ldap_genhdir_prefix = NULL, *ldap_default_quota = NULL,
            *ldap_attr_uid = "uid",
            *ldap_attr_uidnumber = "uidNumber",
            *ldap_attr_gidnumber = "gidNumber",
            *ldap_attr_homedirectory = "homeDirectory",
            *ldap_attr_userpassword = "userPassword",
            *ldap_attr_loginshell = "loginShell",
            *ldap_attr_cn = "cn",
            *ldap_attr_memberuid = "memberUid",
            *ldap_attr_ftpquota = "ftpQuota",
            *ldap_attr_ftpquota_profiledn = "ftpQuotaProfileDN",
            *ldap_attr_ssh_pubkey = "sshPublicKey";
#ifdef HAS_LDAP_INITIALIZE
static char *ldap_server_url;
#endif /* HAS_LDAP_INITIALIZE */
static int ldap_do_users = FALSE, ldap_do_groups = FALSE,
           ldap_authbinds = TRUE, ldap_querytimeout = 0,
           ldap_genhdir = FALSE, ldap_genhdir_prefix_nouname = FALSE,
           ldap_forcedefaultuid = FALSE, ldap_forcedefaultgid = FALSE,
           ldap_forcegenhdir = FALSE, ldap_protocol_version = 3,
           ldap_dereference = LDAP_DEREF_NEVER,
           ldap_search_scope = LDAP_SCOPE_SUBTREE;

static struct timeval ldap_querytimeout_tv;
#define PR_LDAP_QUERY_TIMEOUT_DEFAULT		5

static uid_t ldap_defaultuid = -1;
static gid_t ldap_defaultgid = -1;

#if defined(LDAP_OPT_X_TLS)
static int ldap_use_tls = FALSE;
#endif

static LDAP *ld = NULL;
static array_header *cached_quota = NULL;
static array_header *cached_ssh_pubkeys = NULL;

static void pr_ldap_unbind(void) {
  int res;

  if (ld == NULL) {
    pr_trace_msg(trace_channel, 13,
      "not unbinding to an already unbound connection");
    return;
  }

  res = LDAP_UNBIND(ld);
  if (res != LDAP_SUCCESS) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "error unbinding connection: %s", ldap_err2string(res));

  } else {
    pr_trace_msg(trace_channel, 8,
      "connection successfully unbound");
  }

  ld = NULL;
}

static int do_ldap_connect(LDAP **conn_ld, int do_bind) {
  int res, version;
#ifdef HAS_LDAP_SASL_BIND_S
  struct berval bindcred;
#endif

#ifdef HAS_LDAP_INITIALIZE
  (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
    "attempting connection to URL %s",
    ldap_server_url ? ldap_server_url : "(null)");

  res = ldap_initialize(conn_ld, ldap_server_url);
  if (res != LDAP_SUCCESS) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "ldap_initialize() to URL %s failed: %s",
      ldap_server_url ? ldap_server_url : "(null)", ldap_err2string(res));
    ++cur_server_index;
    if (cur_server_index >= ldap_servers->nelts) {
      cur_server_index = 0;
    }

    *conn_ld = NULL;
    return -1;
  }
#else /* HAS_LDAP_INITIALIZE */
  (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
    "attempting connection to %s:%d", ldap_server ? ldap_server : "(null)",
    ldap_port);

  *conn_ld = ldap_init(ldap_server, ldap_port);
  if (conn_ld == NULL) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "ldap_init() to %s:%d failed: %s", ldap_server ? ldap_server : "(null)",
      ldap_port, strerror(errno));
    return -1;
  }
#endif /* HAS_LDAP_INITIALIZE */

  version = LDAP_VERSION3;
  if (ldap_protocol_version == 2) {
    version = LDAP_VERSION2;
  }

  res = ldap_set_option(*conn_ld, LDAP_OPT_PROTOCOL_VERSION, &version);
  if (res != LDAP_OPT_SUCCESS) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "error setting LDAP protocol version option to %d: %s", version,
      ldap_err2string(res));
    pr_ldap_unbind();
    return -1;
  }

  (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
    "set LDAP protocol version to %d", version);

#ifdef HAS_LDAP_INITIALIZE
  (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
    "connected to URL %s", ldap_server_url ? ldap_server_url : "(null)");

#else /* HAS_LDAP_INITIALIZE */
  (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
    "connected to %s:%d", ldap_server ? ldap_server : "(null)", ldap_port);
#endif /* HAS_LDAP_INITIALIZE */

#if defined(LDAP_OPT_X_TLS)
  if (ldap_use_tls == TRUE) {
    res = ldap_start_tls_s(*conn_ld, NULL, NULL);
    if (res != LDAP_SUCCESS) {
      char *diag_msg = NULL;

      ldap_get_option(*conn_ld, LDAP_OPT_DIAGNOSTIC_MESSAGE,
        (void *) &diag_msg);

      if (diag_msg != NULL) {
        (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
         "failed to start TLS: %s: %s", ldap_err2string(res), diag_msg);
        ldap_memfree(diag_msg);

      } else {
        (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
         "failed to start TLS: %s", ldap_err2string(res));
      }

      pr_ldap_unbind();
      return -1;
    }

    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "enabled TLS for connection");
  }
#endif /* LDAP_OPT_X_TLS */

  if (do_bind == TRUE) {
#ifdef HAS_LDAP_SASL_BIND_S
    bindcred.bv_val = ldap_dnpass;
    bindcred.bv_len = ldap_dnpass != NULL ? strlen(ldap_dnpass) : 0;
    res = ldap_sasl_bind_s(*conn_ld, ldap_dn, NULL, &bindcred, NULL, NULL,
      NULL);
#else /* HAS_LDAP_SASL_BIND_S */
    res = ldap_simple_bind_s(*conn_ld, ldap_dn, ldap_dnpass);
#endif /* HAS_LDAP_SASL_BIND_S */

    if (res != LDAP_SUCCESS) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "bind as DN '%s' failed: %s", ldap_dn ? ldap_dn : "(anonymous)",
        ldap_err2string(res));
      pr_ldap_unbind();
      return -1;
    }

    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "successfully bound as DN '%s' with password %s",
      ldap_dn ? ldap_dn : "(anonymous)",
      ldap_dnpass ? "(see config)" : "(none)");
  }

#ifdef LDAP_OPT_DEREF
  res = ldap_set_option(*conn_ld, LDAP_OPT_DEREF, (void *) &ldap_dereference);
  if (res != LDAP_OPT_SUCCESS) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "failed to set LDAP option for dereference to %d: %s", ldap_dereference,
      ldap_err2string(res));
    pr_ldap_unbind();
    return -1;
  }
  
#else
  deref_ld->ld_deref = ldap_dereference;
#endif

  (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
    "set dereferencing to %d", ldap_dereference);

  ldap_querytimeout_tv.tv_sec = (ldap_querytimeout > 0 ? ldap_querytimeout :
    PR_LDAP_QUERY_TIMEOUT_DEFAULT);
  ldap_querytimeout_tv.tv_usec = 0;

  (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
    "set query timeout to %u secs", (unsigned int) ldap_querytimeout_tv.tv_sec);

  return 1;
}

#if defined(LBER_OPT_LOG_PRINT_FN)
static void ldap_tracelog_cb(const char *msg) {
  (void) pr_trace_msg(libtrace_channel, 1, "%s", msg);
}
#endif /* no LBER_OPT_LOG_PRINT_FN */

static int pr_ldap_connect(LDAP **conn_ld, int do_bind) {
  unsigned int start_server_index;
  char *item;
  LDAPURLDesc *url;

  if (ldap_servers == NULL ||
      ldap_servers->nelts == 0) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "internal error: no LDAP servers configured");
    return -1;
  }

  start_server_index = cur_server_index;
  do {
    pr_signals_handle();

    item = ((char **) ldap_servers->elts)[cur_server_index];

    /* item might be NULL if no LDAPServer directive was specified
     * and we're using the SDK default.
     */
    if (item != NULL) {
      if (ldap_is_ldap_url(item)) {
        char *url_desc;

        if (ldap_url_parse(item, &url) != LDAP_URL_SUCCESS) {
          (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
            "URL %s was valid during server startup, but is no longer valid?!",
            item);

          ++cur_server_index;
          if (cur_server_index >= ldap_servers->nelts) {
            cur_server_index = 0;
          }
          continue;
        }

        url_desc = ldap_url_desc2str(url);
        if (url_desc != NULL) {
          (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
            "parsed '%s' as '%s'", item, url_desc);
          ldap_memfree(url_desc);
        }

#ifdef HAS_LDAP_INITIALIZE
        ldap_server_url = item;
#else /* HAS_LDAP_INITIALIZE */
        /* Need to keep parsed host and port for pre-2000 ldap_init(). */
        if (url->lud_host != NULL) {
          ldap_server = pstrdup(session.pool, url->lud_host);
        }

        if (url->lud_port != 0) {
          ldap_port = url->lud_port;
        }
#endif /* HAS_LDAP_INITIALIZE */

        if (url->lud_scope != LDAP_SCOPE_DEFAULT) {
          ldap_search_scope = url->lud_scope;
          if (ldap_search_scope == LDAP_SCOPE_BASE) {
            pr_log_debug(DEBUG0, MOD_LDAP_VERSION
              ": WARNING: LDAP URL search scopes default to 'base', not 'subtree', and may not be what you want (see LDAPSearchScope)");
          }
        }

        ldap_free_urldesc(url);

      } else {
#ifdef HAS_LDAP_INITIALIZE
        ldap_server_url = pstrcat(session.pool, "ldap://", item, "/", NULL);

#else /* HAS_LDAP_INITIALIZE */
        ldap_server = pstrdup(session.pool, item);
        ldap_port = LDAP_PORT;
#endif /*  HAS_LDAP_INITIALIZE */
      }
    }

    if (do_ldap_connect(conn_ld, do_bind) == 1) {
      /* This debug level value should be LDAP_DEBUG_ANY, but that macro is, I
       * think, OpenLDAP-specific.
       */
      int debug_level = -1, res;

      res = ldap_set_option(*conn_ld, LDAP_OPT_DEBUG_LEVEL, &debug_level);
      if (res != LDAP_OPT_SUCCESS) {
        (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
          "error setting DEBUG_ANY debug level: %s", ldap_err2string(res));
      }

      return 1;
    }

    ++cur_server_index;
    if (cur_server_index >= ldap_servers->nelts) {
      cur_server_index = 0;
    }

  } while (cur_server_index != start_server_index);

  return -1;
}

static const char *pr_ldap_interpolate_filter(pool *p, char *template,
    const char *value) {
  const char *escaped_value, *filter;

  escaped_value = sreplace(p, (char *) value,
    "\\", "\\\\",
    "*", "\\*",
    "(", "\\(",
    ")", "\\)",
    NULL
  );

  if (escaped_value == NULL) {
    return NULL;
  }

  filter = sreplace(p, template,
    "%u", escaped_value,
    "%v", escaped_value,
    NULL
  );

  if (filter == NULL) {
    return NULL;
  }

  (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
    "generated filter %s from template %s and value %s", filter, template,
    value);
  return filter;
}

static LDAPMessage *pr_ldap_search(const char *basedn, const char *filter,
    char *attrs[], int sizelimit, int retry) {
  int res;
  LDAPMessage *result;

  if (basedn == NULL) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "no LDAP base DN specified for search filter %s, declining request",
      filter ? filter : "(null)");
    return NULL;
  }

  /* If the LDAP connection has gone away or hasn't been established
   * yet, attempt to establish it now.
   */
  if (ld == NULL) {
    /* If we _still_ can't connect, give up and return NULL. */
    if (pr_ldap_connect(&ld, TRUE) == -1) {
      return NULL;
    }
  }

  res = LDAP_SEARCH(ld, basedn, ldap_search_scope, filter, attrs,
    &ldap_querytimeout_tv, sizelimit, &result);
  if (res != LDAP_SUCCESS) {
    if (res != LDAP_SERVER_DOWN) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "LDAP search use DN '%s', filter '%s' failed: %s", basedn, filter,
        ldap_err2string(res));
      return NULL;
    }

    if (!retry) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "LDAP connection went away, search failed");
      pr_ldap_unbind();
      return NULL;
    }

    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "LDAP connection went away, retrying search operation");
    pr_ldap_unbind();
    return pr_ldap_search(basedn, filter, attrs, sizelimit, FALSE);
  }

  (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
    "searched under base DN %s using filter %s", basedn,
    filter ? filter : "(null)");
  return result;
}

static struct passwd *pr_ldap_user_lookup(pool *p, char *filter_template,
    const char *replace, const char *basedn, char *attrs[], char **user_dn) {
  const char *filter;
  char *dn;
  int i = 0;
  struct passwd *pw;
  LDAPMessage *result, *e;
  LDAP_VALUE_T **values;

  filter = pr_ldap_interpolate_filter(p, filter_template, replace);
  if (filter == NULL) {
    return NULL;
  }

  result = pr_ldap_search(basedn, filter, attrs, 2, TRUE);
  if (result == NULL) {
    return NULL;
  }

  if (ldap_count_entries(ld, result) > 1) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "LDAP search returned multiple entries during user lookup, "
      "aborting query");
    ldap_msgfree(result);
    return NULL;
  }

  e = ldap_first_entry(ld, result);
  if (e == NULL) {
    ldap_msgfree(result);

    /* No LDAP entries for this user. */
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "no entries for filter %s under base DN %s", filter, basedn);
    return NULL;
  }

  pw = pcalloc(ldap_pool, sizeof(struct passwd));
  while (attrs[i] != NULL) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "fetching values for attribute %s", attrs[i]);

    values = LDAP_GET_VALUES(ld, e, attrs[i]);
    if (values == NULL) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "no values for attribute %s, trying defaults", attrs[i]);

      /* Apply default values for attrs with no explicit values. */

      /* If we can't find the [ug]idNumber attrs, just fill the passwd
       * struct in with default values from the config file.
       */
      if (strcasecmp(attrs[i], ldap_attr_uidnumber) == 0) {
        if (ldap_defaultuid == (uid_t) -1) {
          dn = ldap_get_dn(ld, e);

          (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
            "no %s attribute for DN %s found, and LDAPDefaultUID not "
            "configured", ldap_attr_uidnumber, dn);
          free(dn);
          return NULL;
        }

        pw->pw_uid = ldap_defaultuid;
        ++i;

        (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
          "using LDAPDefaultUID %s", pr_uid2str(NULL, pw->pw_uid));
        continue;
      }

      if (strcasecmp(attrs[i], ldap_attr_gidnumber) == 0) {
        if (ldap_defaultgid == (gid_t) -1) {
          dn = ldap_get_dn(ld, e);

          (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
            "no %s attribute found for DN %s,  and LDAPDefaultGID not "
            "configured", ldap_attr_gidnumber, dn);
          free(dn);
          return NULL;
        }

        pw->pw_gid = ldap_defaultgid;
        ++i;

        (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
          "using LDAPDefaultGID %s", pr_gid2str(NULL, pw->pw_gid));
        continue;
      }

      if (strcasecmp(attrs[i], ldap_attr_homedirectory) == 0) {
        if (ldap_genhdir == FALSE ||
            ldap_genhdir_prefix == NULL) {
          dn = ldap_get_dn(ld, e);

          if (ldap_genhdir == FALSE) {
            (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
              "no %s attribute for DN %s, LDAPGenerateHomedir not enabled",
              ldap_attr_homedirectory, dn);

          } else {
            (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
              "no %s attribute for DN %s, LDAPGenerateHomedir enabled but "
              "LDAPGenerateHomedirPrefix not configured",
              ldap_attr_homedirectory, dn);
          }

          free(dn);
          return NULL;
        }

        if (ldap_genhdir_prefix_nouname == TRUE) {
          pw->pw_dir = pstrcat(session.pool, ldap_genhdir_prefix, NULL);

        } else {
          LDAP_VALUE_T **canon_username;
          canon_username = LDAP_GET_VALUES(ld, e, ldap_attr_uid);
          if (canon_username == NULL) {
            dn = ldap_get_dn(ld, e);

            (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
              "could not get %s attribute for canonical username for DN %s",
              ldap_attr_uid, dn);
            free(dn);
            return NULL;
          }

          pw->pw_dir = pstrcat(session.pool, ldap_genhdir_prefix, "/",
            LDAP_VALUE(canon_username, 0), NULL);
          LDAP_VALUE_FREE(canon_username);
        }

        ++i;

        (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
          "using default homedir %s", pw->pw_dir);
        continue;
      }

      /* Don't worry if we don't have a loginShell attr. */
      if (strcasecmp(attrs[i], ldap_attr_loginshell) == 0) {
        /* Prevent a segfault if no loginShell attribute, and
         * "RequireValidShell on" is in effect.
         */
        pw->pw_shell = pstrdup(session.pool, "");
        ++i;
        continue;
      }

      /* We only restart the while loop above if we can fill in alternate
       * values for certain attributes. If something odd has happened, we
       * fall through so we can complain.
       */

      dn = ldap_get_dn(ld, e);

      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "could not get values for attribute %s for DN %s, ignoring request "
        "(perhaps this DN's entry does not have the attribute?)", attrs[i], dn);
      free(dn);
      ldap_msgfree(result);
      return NULL;
    }

    /* Now that we've handled default values, fill in the struct as normal;
     * the if branches below for nonexistent attrs will just never be
     * called.
     */

    if (strcasecmp(attrs[i], ldap_attr_uid) == 0) {
      pw->pw_name = pstrdup(session.pool, LDAP_VALUE(values, 0));

    } else if (strcasecmp(attrs[i], ldap_attr_userpassword) == 0) {
      pw->pw_passwd = pstrdup(session.pool, LDAP_VALUE(values, 0));

    } else if (strcasecmp(attrs[i], ldap_attr_uidnumber) == 0) {
      if (ldap_forcedefaultuid == TRUE &&
          ldap_defaultuid != (uid_t) -1) {
        pw->pw_uid = ldap_defaultuid;

      } else {
        pw->pw_uid = (uid_t) strtoul(LDAP_VALUE(values, 0), NULL, 10);
      }

    } else if (strcasecmp(attrs[i], ldap_attr_gidnumber) == 0) {
      if (ldap_forcedefaultgid == TRUE &&
          ldap_defaultgid != (gid_t) -1) {
        pw->pw_gid = ldap_defaultgid;

      } else {
        pw->pw_gid = (gid_t) strtoul(LDAP_VALUE(values, 0), NULL, 10);
      }

    } else if (strcasecmp(attrs[i], ldap_attr_homedirectory) == 0) {
      if (ldap_forcegenhdir == TRUE) {
        if (ldap_genhdir == FALSE ||
            ldap_genhdir_prefix == NULL) {

          if (ldap_genhdir == FALSE) {
            (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
              "LDAPForceGeneratedHomedir enabled but LDAPGenerateHomedir is "
              "not enabled");

          } else {
            (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
              "LDAPForceGeneratedHomedir and LDAPGenerateHomedir enabled, but "
              "missing required LDAPGenerateHomedirPrefix");
          }

          return NULL;
        }

        if (pw->pw_dir != NULL) {
          pr_trace_msg(trace_channel, 8, "LDAPForceGeneratedHomedir in effect, "
            "overriding current LDAP home directory '%s'", pw->pw_dir);
        }

        if (ldap_genhdir_prefix_nouname == TRUE) {
          pw->pw_dir = pstrdup(session.pool, ldap_genhdir_prefix);

        } else {
          LDAP_VALUE_T **canon_username;
          canon_username = LDAP_GET_VALUES(ld, e, ldap_attr_uid);
          if (canon_username == NULL) {
            dn = ldap_get_dn(ld, e);

            (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
              "could not get %s attribute for canonical username for DN %s",
              ldap_attr_uid, dn);
            free(dn);
            return NULL;
          }

          pw->pw_dir = pstrcat(session.pool, ldap_genhdir_prefix, "/",
            LDAP_VALUE(canon_username, 0), NULL);
          LDAP_VALUE_FREE(canon_username);
        }

      } else {
        pw->pw_dir = pstrdup(session.pool, LDAP_VALUE(values, 0));
      }

      pr_trace_msg(trace_channel, 8, "using LDAP home directory '%s'",
        pw->pw_dir);

    } else if (strcasecmp(attrs[i], ldap_attr_loginshell) == 0) {
      pw->pw_shell = pstrdup(session.pool, LDAP_VALUE(values, 0));

    } else {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "user lookup attribute/value loop found unknown attribute %s",
        attrs[i]);
    }

    LDAP_VALUE_FREE(values);
    ++i;
  }

  /* If we're doing auth binds, save the DN of this entry so we can
   * bind to the LDAP server as it later.
   */
  if (user_dn) {
    *user_dn = ldap_get_dn(ld, e);
  }

  ldap_msgfree(result);

  (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
    "found user %s, UID %s, GID %s, homedir %s, shell %s",
    pw->pw_name, pr_uid2str(p, pw->pw_uid), pr_gid2str(p, pw->pw_gid),
    pw->pw_dir, pw->pw_shell);
  return pw;
}

static struct group *pr_ldap_group_lookup(pool *p, char *filter_template,
    const char *replace, char *attrs[]) {
  const char *filter;
  char *dn;
  int i = 0, value_count = 0, value_offset;
  struct group *gr;
  LDAPMessage *result, *e;
  LDAP_VALUE_T **values;

  if (ldap_gid_basedn == NULL) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "no LDAP base DN specified for group lookups");
    return NULL;
  }

  filter = pr_ldap_interpolate_filter(p, filter_template, replace);
  if (filter == NULL) {
    return NULL;
  }

  result = pr_ldap_search(ldap_gid_basedn, filter, attrs, 2, TRUE);
  if (result == NULL) {
    return NULL;
  }

  e = ldap_first_entry(ld, result);
  if (e == NULL) {
    ldap_msgfree(result);

    /* No LDAP entries found for this user. */
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "no group entries for filter %s", filter);
    return NULL;
  }

  gr = pcalloc(session.pool, sizeof(struct group));
  while (attrs[i] != NULL) {
    pr_signals_handle();

    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "fetching values for attribute %s", attrs[i]);

    values = LDAP_GET_VALUES(ld, e, attrs[i]);
    if (values == NULL) {
      if (strcasecmp(attrs[i], ldap_attr_memberuid) == 0) {
        gr->gr_mem = palloc(session.pool, 2 * sizeof(char *));
        gr->gr_mem[0] = pstrdup(session.pool, "");
        gr->gr_mem[1] = NULL;

        ++i;
        continue;
      }

      ldap_msgfree(result);
      dn = ldap_get_dn(ld, e);

      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "could not get values for attribute %s for DN %s, ignoring request "
        "(perhaps that DN does not have that attribute?)", attrs[i], dn);
      free(dn);
      return NULL;
    }

    if (strcasecmp(attrs[i], ldap_attr_cn) == 0) {
      gr->gr_name = pstrdup(session.pool, LDAP_VALUE(values, 0));

    } else if (strcasecmp(attrs[i], ldap_attr_gidnumber) == 0) {
      gr->gr_gid = strtoul(LDAP_VALUE(values, 0), NULL, 10);

    } else if (strcasecmp(attrs[i], ldap_attr_memberuid) == 0) {
      value_count = LDAP_COUNT_VALUES(values);
      gr->gr_mem = (char **) palloc(session.pool, value_count * sizeof(char *));

      for (value_offset = 0; value_offset < value_count; ++value_offset) {
        gr->gr_mem[value_offset] =
          pstrdup(session.pool, LDAP_VALUE(values, value_offset));
      }

    } else {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "group lookup attribute/value loop found unknown attribute %s",
        attrs[i]);
    }

    LDAP_VALUE_FREE(values);
    ++i;
  }

  ldap_msgfree(result);

  (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
    "found group %s, GID %s", gr->gr_name, pr_gid2str(NULL, gr->gr_gid));
  for (i = 0; i < value_count; ++i) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "+ member: %s", gr->gr_mem[i]);
  }

  return gr;
}

static void parse_quota(pool *p, const char *replace, char *str) {
  char **elts, *token;

  if (cached_quota == NULL) {
    cached_quota = make_array(p, 9, sizeof(char *));
  }

  elts = (char **) cached_quota->elts;
  elts[0] = pstrdup(session.pool, replace);
  cached_quota->nelts = 1;

  (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
    "parsing ftpQuota attribute value '%s'", str);

  while ((token = strsep(&str, ","))) {
    pr_signals_handle();
    *((char **) push_array(cached_quota)) = pstrdup(session.pool, token);
  }
}

static unsigned char pr_ldap_quota_lookup(pool *p, char *filter_template,
    const char *replace, const char *basedn) {
  const char *filter = NULL;
  char *attrs[] = {
         ldap_attr_ftpquota, ldap_attr_ftpquota_profiledn, NULL,
       };
  int orig_scope, res;
  LDAPMessage *result, *e;
  LDAP_VALUE_T **values;

  if (basedn == NULL) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "no LDAP base DN specified for quota lookups, declining request");
    return FALSE;
  }

  if (filter_template != NULL) {
    filter = pr_ldap_interpolate_filter(p, filter_template, replace);
    if (filter == NULL) {
      return FALSE;
    }
  }

  result = pr_ldap_search(basedn, filter, attrs, 2, TRUE);
  if (result == NULL) {
    return FALSE;
  }

  if (ldap_count_entries(ld, result) > 1) {
    ldap_msgfree(result);

    if (ldap_default_quota != NULL) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "multiple entries found for DN %s, using default quota %s", basedn,
          ldap_default_quota);
      parse_quota(p, replace, pstrdup(p, ldap_default_quota));
      return TRUE;

    } else {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "multiple entries found for DN %s, aborting query", basedn);
    }

    return FALSE;
  }

  e = ldap_first_entry(ld, result);
  if (e == NULL) {
    ldap_msgfree(result);
    if (ldap_default_quota == NULL) {
      if (filter == NULL) {
        (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
          "no entries for DN %s, and no default quota defined", basedn);

      } else {
        (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
          "no entries for filter %s, and no default quota defined", filter);
      }

      return FALSE;
    }

    if (filter == NULL) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "no entries for DN %s, using default quota %s", basedn,
        ldap_default_quota);

    } else {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "no entries for filter %s, using default quota %s", filter,
        ldap_default_quota);
    }

    parse_quota(p, replace, pstrdup(p, ldap_default_quota));
    return TRUE;
  }

  values = LDAP_GET_VALUES(ld, e, attrs[0]);
  if (values != NULL) {
    parse_quota(p, replace, pstrdup(p, LDAP_VALUE(values, 0)));
    LDAP_VALUE_FREE(values);
    ldap_msgfree(result);
    return TRUE;
  }

  if (filter == NULL) {
    if (ldap_default_quota == NULL) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "referenced DN %s does not have an ftpQuota attribute, and no "
        "default quota defined", basedn);
      return FALSE;
    }

    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "no ftpQuota attribute found for DN %s, using default quota %s", basedn,
      ldap_default_quota);
    parse_quota(p, replace, pstrdup(p, ldap_default_quota));
    return TRUE;
  }

  values = LDAP_GET_VALUES(ld, e, attrs[1]);
  if (values != NULL) {
    orig_scope = ldap_search_scope;
    ldap_search_scope = LDAP_SCOPE_BASE;
    res = pr_ldap_quota_lookup(p, NULL, replace, LDAP_VALUE(values, 0));
    ldap_search_scope = orig_scope;
    LDAP_VALUE_FREE(values);
    ldap_msgfree(result);
    return res;
  }

  ldap_msgfree(result);
  if (ldap_default_quota != NULL) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "no %s or %s attribute, using default quota %s", attrs[0], attrs[1],
      ldap_default_quota);
    parse_quota(p, replace, pstrdup(p, ldap_default_quota));
    return TRUE;
  }

  /* No quota attributes for this user. */
  (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
    "no %s or %s attribute, and no default quota defined", attrs[0], attrs[1]);
  return FALSE;
}

static unsigned char pr_ldap_ssh_pubkey_lookup(pool *p, char *filter_template,
    const char *replace, char *basedn) {
  const char *filter;
  char *attrs[] = {
    ldap_attr_ssh_pubkey, NULL,
  };
  int num_keys, i;
  LDAPMessage *result, *e;
  LDAP_VALUE_T **values;

  if (basedn == NULL) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "no LDAP base DN specified for user lookups, declining SSH publickey "
      "lookup request");
    return FALSE;
  }

  filter = pr_ldap_interpolate_filter(p, filter_template, replace);
  if (filter == NULL) {
    return FALSE;
  }

  result = pr_ldap_search(basedn, filter, attrs, 2, TRUE);
  if (result == NULL) {
    return FALSE;
  }

  if (ldap_count_entries(ld, result) > 1) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "LDAP search for SSH publickey using DN %s, filter %s returned multiple "
      "entries, aborting query", basedn, filter);
    ldap_msgfree(result);
    return FALSE;
  }

  e = ldap_first_entry(ld, result);
  if (e == NULL) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "LDAP search for SSH publickey using DN %s, filter %s returned "
      "no entries", basedn, filter);
    ldap_msgfree(result);
    return FALSE;
  }

  values = LDAP_GET_VALUES(ld, e, attrs[0]);
  if (values == NULL) {
    return FALSE;
  }

  num_keys = LDAP_COUNT_VALUES(values);
  cached_ssh_pubkeys = make_array(p, num_keys, sizeof(char *));
  for (i = 0; i < num_keys; ++i) {
    *((char **) push_array(cached_ssh_pubkeys)) = pstrdup(p,
      LDAP_VALUE(values, i));
  }
  LDAP_VALUE_FREE(values);

  ldap_msgfree(result);
  return TRUE;
}

static struct group *pr_ldap_getgrnam(pool *p, const char *group_name) {
  char *group_attrs[] = {
    ldap_attr_cn, ldap_attr_gidnumber, ldap_attr_memberuid, NULL,
  };

  return pr_ldap_group_lookup(p, ldap_group_name_filter, group_name,
    group_attrs);
}

static struct group *pr_ldap_getgrgid(pool *p, gid_t gid) {
  const char *gidstr;
  char *group_attrs[] = {
    ldap_attr_cn, ldap_attr_gidnumber, ldap_attr_memberuid, NULL,
  };

  gidstr = pr_gid2str(p, gid);
  return pr_ldap_group_lookup(p, ldap_group_gid_filter, gidstr, group_attrs);
}

static struct passwd *pr_ldap_getpwnam(pool *p, const char *username) {
  const char *filter;
  char *name_attrs[] = {
         ldap_attr_userpassword, ldap_attr_uid, ldap_attr_uidnumber,
         ldap_attr_gidnumber, ldap_attr_homedirectory,
         ldap_attr_loginshell, NULL,
       };

  filter = pr_ldap_interpolate_filter(p, ldap_user_basedn, username);
  if (filter == NULL) {
    return NULL;
  }

  /* pr_ldap_user_lookup() returns NULL if it doesn't find an entry or
   * encounters an error. If everything goes all right, it returns a
   * struct passwd, so we can just return its result directly.
   *
   * We also do some cute stuff here to work around lameness in LDAP servers
   * like Sun Directory Services (SDS) 1.x and 3.x. If you request an attr
   * that you don't have access to, SDS totally ignores any entries with
   * that attribute. Thank you, Sun; how very smart of you. So if we're
   * doing auth binds, we don't request the userPassword attr.
   *
   * NOTE: if the UserPassword directive is configured, mod_auth will pass
   * a crypted password to ldap_auth_check(), which will NOT do auth binds
   * in order to support UserPassword. (Otherwise, it would try binding to
   * the directory and would ignore UserPassword.)
   *
   * We're reasonably safe in making that assumption as long as we never
   * fetch userPassword from the directory if auth binds are enabled. If we
   * fetched userPassword, auth binds would never be done because
   * ldap_auth_check() would always get a crypted password.
   */
  return pr_ldap_user_lookup(p, ldap_user_name_filter, username, filter,
    ldap_authbinds ? name_attrs + 1 : name_attrs,
    ldap_authbinds ? &ldap_authbind_dn : NULL);
}

static struct passwd *pr_ldap_getpwuid(pool *p, uid_t uid) {
  const char *uidstr;
  char *uid_attrs[] = {
    ldap_attr_uid, ldap_attr_uidnumber, ldap_attr_gidnumber,
    ldap_attr_homedirectory, ldap_attr_loginshell, NULL,
  };

  uidstr = pr_uid2str(p, uid);
  return pr_ldap_user_lookup(p, ldap_user_uid_filter, uidstr,
    ldap_user_basedn, uid_attrs, ldap_authbinds ? &ldap_authbind_dn : NULL);
}

MODRET handle_ldap_quota_lookup(cmd_rec *cmd) {
  const char *basedn;

  basedn = pr_ldap_interpolate_filter(cmd->tmp_pool,
    ldap_user_basedn, cmd->argv[0]);
  if (basedn == NULL) {
    return PR_DECLINED(cmd);
  }

  if (cached_quota == NULL ||
      strcasecmp(((char **) cached_quota->elts)[0], cmd->argv[0]) != 0) {

    if (pr_ldap_quota_lookup(cmd->tmp_pool, ldap_user_name_filter,
        cmd->argv[0], basedn) == FALSE) {
      return PR_DECLINED(cmd);
    }

  } else {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "returning cached quota for user %s", (char *) cmd->argv[0]);
  }

  return mod_create_data(cmd, cached_quota);
}

MODRET handle_ldap_ssh_pubkey_lookup(cmd_rec *cmd) {
  char *user;

  if (ldap_do_users == FALSE) {
    return PR_DECLINED(cmd);
  }

  user = cmd->argv[0];

  if (cached_ssh_pubkeys != NULL &&
      cached_ssh_pubkeys->nelts > 0 &&
      strcasecmp(((char **) cached_ssh_pubkeys->elts)[0], user) == 0) {

    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "returning cached SSH public keys for user %s", user);
    return mod_create_data(cmd, cached_ssh_pubkeys);
  }

  if (pr_ldap_ssh_pubkey_lookup(cmd->tmp_pool, ldap_user_name_filter,
      user, ldap_user_basedn) == FALSE) {
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, cached_ssh_pubkeys);
}

MODRET ldap_auth_setpwent(cmd_rec *cmd) {
  if (ldap_do_users == FALSE &&
      ldap_do_groups == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (ld == NULL) {
    (void) pr_ldap_connect(&ld, TRUE);
  }

  return PR_HANDLED(cmd);
}

MODRET ldap_auth_endpwent(cmd_rec *cmd) {
  if (ldap_do_users == FALSE &&
      ldap_do_groups == FALSE) {
    return PR_DECLINED(cmd);
  }

  pr_ldap_unbind();
  return PR_HANDLED(cmd);
}

MODRET ldap_auth_getpwuid(cmd_rec *cmd) {
  struct passwd *pw = NULL;

  if (ldap_do_users == FALSE) {
    return PR_DECLINED(cmd);
  }

  pw = pr_ldap_getpwuid(cmd->tmp_pool, *((uid_t *) cmd->argv[0]));
  if (pw != NULL) {
    return mod_create_data(cmd, pw);
  }

  return PR_DECLINED(cmd);
}

MODRET ldap_auth_getpwnam(cmd_rec *cmd) {
  struct passwd *pw = NULL;

  if (ldap_do_users == FALSE) {
    return PR_DECLINED(cmd);
  }

  pw = pr_ldap_getpwnam(cmd->tmp_pool, cmd->argv[0]);
  if (pw != NULL) {
    return mod_create_data(cmd, pw);
  }

  return PR_DECLINED(cmd);
}

MODRET ldap_auth_getgrnam(cmd_rec *cmd) {
  struct group *gr = NULL;

  if (ldap_do_groups == FALSE) {
    return PR_DECLINED(cmd);
  }

  gr = pr_ldap_getgrnam(cmd->tmp_pool, cmd->argv[0]);
  if (gr != NULL) {
    return mod_create_data(cmd, gr);
  }

  return PR_DECLINED(cmd);
}

MODRET ldap_auth_getgrgid(cmd_rec *cmd) {
  struct group *gr = NULL;

  if (ldap_do_groups == FALSE) {
    return PR_DECLINED(cmd);
  }

  gr = pr_ldap_getgrgid(cmd->tmp_pool, *((gid_t *) cmd->argv[0]));
  if (gr != NULL) {
    return mod_create_data(cmd, gr);
  }

  return PR_DECLINED(cmd);
}

MODRET ldap_auth_getgroups(cmd_rec *cmd) {
  const char *filter;
  char *w[] = {
    ldap_attr_gidnumber, ldap_attr_cn, NULL,
  };
  struct passwd *pw;
  struct group *gr;
  LDAPMessage *result = NULL, *e;
  LDAP_VALUE_T **gidNumber, **cn;
  array_header *gids   = (array_header *)cmd->argv[1],
               *groups = (array_header *)cmd->argv[2];

  if (ldap_do_groups == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (gids == NULL ||
      groups == NULL) {
    return PR_DECLINED(cmd);
  }

  pw = pr_ldap_getpwnam(cmd->tmp_pool, cmd->argv[0]);
  if (pw != NULL) {
    gr = pr_ldap_getgrgid(cmd->tmp_pool, pw->pw_gid);
    if (gr != NULL) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "adding user %s primary group %s/%s", pw->pw_name, gr->gr_name,
        pr_gid2str(NULL, pw->pw_gid));
      *((gid_t *) push_array(gids)) = pw->pw_gid;
      *((char **) push_array(groups)) = pstrdup(session.pool, gr->gr_name);

    } else {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "unable to determine group name for user %s primary GID %s, skipping",
        pw->pw_name, pr_gid2str(NULL, pw->pw_gid));
    }
  }

  if (ldap_gid_basedn == NULL) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "no LDAP base DN specified for group lookups");
    goto return_groups;
  }

  filter = pr_ldap_interpolate_filter(cmd->tmp_pool,
    ldap_group_member_filter, cmd->argv[0]);
  if (filter == NULL) {
    return NULL;
  }

  result = pr_ldap_search(ldap_gid_basedn, filter, w, 0, TRUE);
  if (result == NULL) {
    return FALSE;
  }

  if (ldap_count_entries(ld, result) == 0) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "no entries found for filter %s", filter);
    goto return_groups;
  }

  for (e = ldap_first_entry(ld, result); e; e = ldap_next_entry(ld, e)) {
    gidNumber = LDAP_GET_VALUES(ld, e, w[0]);
    if (gidNumber == NULL) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "could not get values for %s attribute for getgroups(2), skipping "
        "current group", ldap_attr_gidnumber);
      continue;
    }

    cn = LDAP_GET_VALUES(ld, e, w[1]);
    if (cn == NULL) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "could not get values for %s attribute for getgroups(2), skipping "
        "current group", ldap_attr_cn);
      continue;
    }

    if (pw == NULL ||
        strtoul(LDAP_VALUE(gidNumber, 0), NULL, 10) != pw->pw_gid) {
      *((gid_t *) push_array(gids)) = strtoul(LDAP_VALUE(gidNumber, 0), NULL, 10);
      *((char **) push_array(groups)) = pstrdup(session.pool, LDAP_VALUE(cn, 0));

      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "added user %s secondary group %s/%s",
        (pw && pw->pw_name) ? pw->pw_name : (char *) cmd->argv[0],
        LDAP_VALUE(cn, 0), LDAP_VALUE(gidNumber, 0));
    }

    LDAP_VALUE_FREE(gidNumber);
    LDAP_VALUE_FREE(cn);
  }

return_groups:
  if (result) {
    ldap_msgfree(result);
  }

  if (gids->nelts > 0) {
    return mod_create_data(cmd, (void *) &gids->nelts);
  }

  return PR_DECLINED(cmd);
}

/* Authentication handlers
 */

/* cmd->argv[0] : user name
 * cmd->argv[1] : cleartext password
 */
MODRET ldap_auth_auth(cmd_rec *cmd) {
  const char *filter = NULL, *username;
  char *pass_attrs[] = {
         ldap_attr_userpassword, ldap_attr_uid, ldap_attr_uidnumber,
         ldap_attr_gidnumber, ldap_attr_homedirectory,
         ldap_attr_loginshell, NULL,
       };
  struct passwd *pw = NULL;
  int res;

  if (ldap_do_users == FALSE) {
    return PR_DECLINED(cmd);
  }

  username = cmd->argv[0];

  filter = pr_ldap_interpolate_filter(cmd->tmp_pool, ldap_user_basedn,
    username);
  if (filter == NULL) {
    return NULL;
  }

  /* If anything here fails hard (IOW, we've found an LDAP entry for the
   * user, but they appear to have entered the wrong password), fail auth.
   * Normally, I'd DECLINE here so other modules could have a shot, but if
   * we've found their LDAP entry, chances are that nothing else will be
   * able to auth them.
   */

  pw = pr_ldap_user_lookup(cmd->tmp_pool,
    ldap_user_name_filter, username, filter,
    ldap_authbinds ? pass_attrs + 1 : pass_attrs,
    ldap_authbinds ? &ldap_authbind_dn : NULL);
  if (pw == NULL) {
    /* Can't find the user in the LDAP directory. */
    return PR_DECLINED(cmd);
  }

  if (ldap_authbinds == FALSE &&
      pw->pw_passwd == NULL) {
    (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
      "LDAPAuthBinds not enabled, and unable to retrieve password for user %s",
      pw->pw_name);
    return PR_ERROR_INT(cmd, PR_AUTH_NOPWD);
  }

  res = pr_auth_check(cmd->tmp_pool, ldap_authbinds ? NULL : pw->pw_passwd,
    username, cmd->argv[1]);
  if (res != 0) {
    if (res == -1) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "bad password for user %s: %s", pw->pw_name, strerror(errno));

    } else {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "bad password for user %s", pw->pw_name);
    }

    return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
  }

  session.auth_mech = "mod_ldap.c";
  return PR_HANDLED(cmd);
}

/* cmd->argv[0] = hashed password,
 * cmd->argv[1] = user,
 * cmd->argv[2] = cleartext
 */
MODRET ldap_auth_check(cmd_rec *cmd) {
  char *pass, *cryptpass, *hash_method, *crypted;
  int encname_len, res;
  LDAP *ld_auth;
#ifdef HAS_LDAP_SASL_BIND_S
  struct berval bindcred;
#endif

  if (ldap_do_users == FALSE) {
    return PR_DECLINED(cmd);
  }

  cryptpass = cmd->argv[0];
  pass = cmd->argv[2];

  /* At this point, any encrypted password must have come from the UserPassword
   * directive. Don't perform auth binds in this case, since the crypted
   * password specified should override auth binds.
   */
  if (ldap_authbinds == TRUE &&
      cryptpass == NULL) {
    /* Don't try to do auth binds with a NULL/empty DN or password. */
    if (pass == NULL ||
        strlen(pass) == 0) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "LDAPAuthBinds is enabled, but no user-supplied cleartext password "
        "was found");
      return PR_DECLINED(cmd);
    }

    if (ldap_authbind_dn == NULL ||
        strlen(ldap_authbind_dn) == 0) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "LDAPAuthBinds is enabled, but no LDAP DN was found");
      return PR_DECLINED(cmd);
    }

    if (pr_ldap_connect(&ld_auth, FALSE) == -1) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "unable to check login: LDAP connection failed");
      return PR_DECLINED(cmd);
    }

#ifdef HAS_LDAP_SASL_BIND_S
    bindcred.bv_val = cmd->argv[2];
    bindcred.bv_len = strlen(cmd->argv[2]);
    res = ldap_sasl_bind_s(ld_auth, ldap_authbind_dn, NULL, &bindcred,
      NULL, NULL, NULL);
#else /* HAS_LDAP_SASL_BIND_S */
    res = ldap_simple_bind_s(ld_auth, ldap_authbind_dn, cmd->argv[2]);
#endif /* HAS_LDAP_SASL_BIND_S */

    if (res != LDAP_SUCCESS) {
      if (res != LDAP_INVALID_CREDENTIALS) {
        (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
          "unable to check login: bind as %s failed: %s", ldap_authbind_dn,
          ldap_err2string(res));
      }

      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "invalid credentials used for %s", ldap_authbind_dn);
      LDAP_UNBIND(ld_auth);
      return PR_ERROR(cmd);
    }

    LDAP_UNBIND(ld_auth);
    session.auth_mech = "mod_ldap.c";
    return PR_HANDLED(cmd);
  }

  /* Get the length of "scheme" in the leading {scheme} so we can skip it
   * in the password comparison.
   */
  encname_len = strcspn(cryptpass + 1, "}");
  hash_method = pstrndup(cmd->tmp_pool, cryptpass + 1, encname_len);

  /* Check to see how the password is encrypted, and check accordingly. */

  if ((size_t) encname_len == strlen(cryptpass + 1)) {
    /* No leading {scheme}. */
    hash_method = ldap_defaultauthscheme;
    encname_len = 0;

  } else {
    encname_len += 2;
  }

  /* The {crypt} scheme */
  if (strncasecmp(hash_method, "crypt", strlen(hash_method)) == 0) {
    crypted = crypt(pass, cryptpass + encname_len);
    if (crypted == NULL) {
      return PR_ERROR(cmd);
    }

    if (strcmp(crypted, cryptpass + encname_len) != 0) {
      return PR_ERROR(cmd);
    }

  /* The {clear} scheme */
  } else if (strncasecmp(hash_method, "clear", strlen(hash_method)) == 0) {
    if (strcmp(pass, cryptpass + encname_len) != 0) {
      return PR_ERROR(cmd);
    }

  } else {
    /* Can't find a supported {scheme} */
    return PR_DECLINED(cmd);
  }

  session.auth_mech = "mod_ldap.c";
  return PR_HANDLED(cmd);
}

MODRET ldap_auth_uid2name(cmd_rec *cmd) {
  struct passwd *pw = NULL;

  if (ldap_do_users == FALSE) {
    return PR_DECLINED(cmd);
  }

  pw = pr_ldap_getpwuid(cmd->tmp_pool, *((uid_t *) cmd->argv[0]));
  if (pw == NULL) {
    /* Can't find the user in the LDAP directory. */
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, pstrdup(permanent_pool, pw->pw_name));
}

MODRET ldap_auth_gid2name(cmd_rec *cmd) {
  struct group *gr = NULL;

  if (ldap_do_groups == FALSE) {
    return PR_DECLINED(cmd);
  }

  gr = pr_ldap_getgrgid(cmd->tmp_pool, *((gid_t *) cmd->argv[0]));
  if (gr == NULL) {
    /* Can't find the user in the LDAP directory. */
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, pstrdup(permanent_pool, gr->gr_name));
}

MODRET ldap_auth_name2uid(cmd_rec *cmd) {
  struct passwd *pw = NULL;

  if (ldap_do_users == FALSE) {
    return PR_DECLINED(cmd);
  }

  pw = pr_ldap_getpwnam(cmd->tmp_pool, cmd->argv[0]);
  if (pw == NULL) {
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, (void *) &pw->pw_uid);
}

MODRET ldap_auth_name2gid(cmd_rec *cmd) {
  struct group *gr = NULL;

  if (ldap_do_groups == FALSE) {
    return PR_DECLINED(cmd);
  }

  gr = pr_ldap_getgrnam(cmd->tmp_pool, cmd->argv[0]);
  if (gr == NULL) {
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, (void *) &gr->gr_gid);
}

/* Configuration handlers
 */

/* usage: LDAPLog path|"none" */
MODRET set_ldaplog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

MODRET set_ldapprotoversion(cmd_rec *cmd) {
  int i = 0;
  config_rec *c;
  char *version;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  version = cmd->argv[1];
  while (version[i]) {
    if (!PR_ISDIGIT((int) version[i])) {
      CONF_ERROR(cmd, "LDAPProtocolVersion: argument must be numeric!");
    }

    ++i;
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = atoi(version);

  return PR_HANDLED(cmd);
}

MODRET set_ldapserver(cmd_rec *cmd) {
  register unsigned int i;
  int len;
  LDAPURLDesc *url;
  array_header *urls = NULL;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);
  urls = make_array(c->pool, cmd->argc - 1, sizeof(char *));
  c->argv[0] = urls;

  for (i = 1; i < cmd->argc; ++i) {
    char *item;

    item = cmd->argv[i];

    if (ldap_is_ldap_url(item)) {
      char *url_desc;

      if (ldap_url_parse(item, &url) != LDAP_URL_SUCCESS) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
          "must be supplied with a valid LDAP URL: ", item, NULL));
      }

      url_desc = ldap_url_desc2str(url);
      if (url_desc != NULL) {
        pr_log_debug(DEBUG0, "%s: parsed URL '%s' as '%s'",
          (char *) cmd->argv[0], item, url_desc);
        ldap_memfree(url_desc);
      }

      if (find_config(cmd->server->conf, CONF_PARAM, "LDAPSearchScope", FALSE)) {
        CONF_ERROR(cmd, "LDAPSearchScope cannot be used when LDAPServer specifies a URL; specify a search scope in the LDAPServer URL instead");
      }

#ifdef HAS_LDAP_INITIALIZE
      if (strncasecmp(item, "ldap:", 5) != 0 &&
          strncasecmp(item, "ldaps:", 6) != 0) {
        CONF_ERROR(cmd, "Invalid scheme specified by LDAPServer URL: valid schemes are 'ldap' or 'ldaps'");
      }

#else /* HAS_LDAP_INITIALIZE */
      if (strncasecmp(item, "ldap:", 5) != 0) {
        CONF_ERROR(cmd, "Invalid scheme specified by LDAPServer URL: valid schemes are 'ldap'");
      }
#endif /* HAS_LDAP_INITIALIZE */

      if (url->lud_dn != NULL &&
          strcmp(url->lud_dn, "") != 0) {
        CONF_ERROR(cmd, "A base DN may not be specified by an LDAPServer URL, only by LDAPUsers or LDAPGroups");
      }

      if (url->lud_filter != NULL &&
         strcmp(url->lud_filter, "") != 0) {
        CONF_ERROR(cmd, "A search filter may not be specified by an LDAPServer URL, only by LDAPUsers or LDAPGroups");
      }

      ldap_free_urldesc(url);
      *((char **) push_array(urls)) = pstrdup(c->pool, item);

    } else {
      /* Split non-URL arguments on whitespace and insert them as separate
       * servers.
       */
      while (*item) {
        len = strcspn(item, " \f\n\r\t\v");
        *((char **) push_array(urls)) = pstrndup(c->pool, item, len);

        item += len;
        while (PR_ISSPACE(*item)) {
          ++item;
        }
      }
    }
  }

  return PR_HANDLED(cmd);
}

/* usage: LDAPUseTLS on|off */
MODRET set_ldapusetls(cmd_rec *cmd) {
#ifndef LDAP_OPT_X_TLS
  CONF_ERROR(cmd, "LDAPUseTLS: Your LDAP libraries do not appear to support TLS");

#else /* LDAP_OPT_X_TLS */
  int b;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  b = get_boolean(cmd, 1);
  if (b == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = b;

  return PR_HANDLED(cmd);
#endif /* LDAP_OPT_X_TLS */
}

MODRET set_ldapbinddn(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 2, cmd->argv[1], cmd->argv[2]);
  return PR_HANDLED(cmd);
}

MODRET set_ldapsearchscope(cmd_rec *cmd) {
  config_rec *c;
  const char *scope_name;
  int search_scope;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = find_config(main_server->conf, CONF_PARAM, "LDAPServer", FALSE);
  if (c != NULL) {
    register unsigned int i;
    array_header *servers = NULL;

    servers = c->argv[0];
    for (i = 0; i < servers->nelts; i++) {
      char *elt;

      elt = ((char **) servers->elts)[i];
      if (ldap_is_ldap_url(elt)) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "cannot be used when LDAPServer specifies a URL (see '", elt, "'); specify a search scope in the LDAPServer URL instead", NULL));
      }
    }
  }

  scope_name = cmd->argv[1];

  if (strcasecmp(scope_name, "base") == 0) {
    search_scope = LDAP_SCOPE_BASE;

  } else if (strcasecmp(scope_name, "one") == 0 ||
             strcasecmp(scope_name, "onelevel") == 0) {
    search_scope = LDAP_SCOPE_ONELEVEL;

  } else if (strcasecmp(scope_name, "subtree") == 0) {
    search_scope = LDAP_SCOPE_SUBTREE;

  } else {
    CONF_ERROR(cmd, "search scope must be one of: base, onelevel, subtree");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = search_scope;

  return PR_HANDLED(cmd);
}

MODRET set_ldapquerytimeout(cmd_rec *cmd) {
  config_rec *c;
  int timeout;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (pr_str_get_duration(cmd->argv[1], &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      cmd->argv[1], "': ", strerror(errno), NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;

  return PR_HANDLED(cmd);
}

MODRET set_ldapaliasdereference(cmd_rec *cmd) {
  int value;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "never") == 0) {
    value = LDAP_DEREF_NEVER;

  } else if (strcasecmp(cmd->argv[1], "search") == 0) {
    value = LDAP_DEREF_SEARCHING;

  } else if (strcasecmp(cmd->argv[1], "find") == 0) {
    value = LDAP_DEREF_FINDING;

  } else if (strcasecmp(cmd->argv[1], "always") == 0) {
    value = LDAP_DEREF_ALWAYS;

  } else {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "expected a valid dereference (never, search, find, always): ",
      cmd->argv[1], NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = value;

  return PR_HANDLED(cmd);
}

MODRET set_ldapauthbinds(cmd_rec *cmd) {
  int b;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  b = get_boolean(cmd, 1);
  if (b == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = b;

  return PR_HANDLED(cmd);
}

MODRET set_ldapdefaultauthscheme(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

MODRET set_ldapattr(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 2);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "uid") != 0 &&
      strcasecmp(cmd->argv[1], "uidNumber") != 0 &&
      strcasecmp(cmd->argv[1], "gidNumber") != 0 &&
      strcasecmp(cmd->argv[1], "homeDirectory") != 0 &&
      strcasecmp(cmd->argv[1], "userPassword") != 0 &&
      strcasecmp(cmd->argv[1], "loginShell") != 0 &&
      strcasecmp(cmd->argv[1], "cn") != 0 &&
      strcasecmp(cmd->argv[1], "memberUid") != 0 &&
      strcasecmp(cmd->argv[1], "ftpQuota") != 0 &&
      strcasecmp(cmd->argv[1], "ftpQuotaProfileDN") != 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      ": unknown attribute name: ", cmd->argv[1], NULL));
  }

  add_config_param_str(cmd->argv[0], 2, cmd->argv[1], cmd->argv[2]);
  return PR_HANDLED(cmd);
}

/* usage: LDAPUsers base-dn [name-filter-template [uid-filter-template]] */
MODRET set_ldapusers(cmd_rec *cmd) {
  config_rec *c;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (get_boolean(cmd, 1) != -1) {
    CONF_ERROR(cmd, "first parameter must be the base DN, not on/off");
  }

  c = add_config_param(cmd->argv[0], cmd->argc - 1, NULL, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, cmd->argv[1]);
  if (cmd->argc > 2) {
    c->argv[1] = pstrdup(c->pool, cmd->argv[2]);
  }
  if (cmd->argc > 3) {
    c->argv[2] = pstrdup(c->pool, cmd->argv[3]);
  }

  return PR_HANDLED(cmd);
}

MODRET set_ldapdefaultuid(cmd_rec *cmd) {
  config_rec *c;
  uid_t uid;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(uid_t));

  if (pr_str2uid(cmd->argv[1], &uid) < 0) {
    CONF_ERROR(cmd, "LDAPDefaultUID: UID argument must be numeric");
  }

  *((uid_t *) c->argv[0]) = uid;
  return PR_HANDLED(cmd);
}

MODRET set_ldapdefaultgid(cmd_rec *cmd) {
  config_rec *c;
  gid_t gid;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(gid_t));

  if (pr_str2gid(cmd->argv[1], &gid) < 0) {
    CONF_ERROR(cmd, "LDAPDefaultGID: GID argument must be numeric");
  }

  *((gid_t *) c->argv[0]) = gid;
  return PR_HANDLED(cmd);
}

MODRET set_ldapforcedefaultuid(cmd_rec *cmd) {
  int b;
  config_rec *c;

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  b = get_boolean(cmd, 1);
  if (b == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = b;

  return PR_HANDLED(cmd);
}

MODRET set_ldapforcedefaultgid(cmd_rec *cmd) {
  int b;
  config_rec *c;

  CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  b = get_boolean(cmd, 1);
  if (b == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = b;

  return PR_HANDLED(cmd);
}

MODRET set_ldapgenhdir(cmd_rec *cmd) {
  int b;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  b = get_boolean(cmd, 1);
  if (b == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = b;

  return PR_HANDLED(cmd);
}

MODRET set_ldapgenhdirprefix(cmd_rec *cmd) {
  char *prefix;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  prefix = cmd->argv[1];
  if (strlen(prefix) == 0) {
    CONF_ERROR(cmd, "must not be an empty string");
  }

  add_config_param_str(cmd->argv[0], 1, prefix);
  return PR_HANDLED(cmd);
}

MODRET set_ldapgenhdirprefixnouname(cmd_rec *cmd) {
  int b;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  b = get_boolean(cmd, 1);
  if (b == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = b;

  return PR_HANDLED(cmd);
}

MODRET set_ldapforcegenhdir(cmd_rec *cmd) {
  int b;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  b = get_boolean(cmd, 1);
  if (b == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = b;

  return PR_HANDLED(cmd);
}

MODRET set_ldapgrouplookups(cmd_rec *cmd) {
  config_rec *c;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (get_boolean(cmd, 1) != -1) {
    CONF_ERROR(cmd, "first parameter must be the base DN, not on/off.");
  }

  c = add_config_param(cmd->argv[0], cmd->argc - 1, NULL);
  c->argv[0] = pstrdup(c->pool, cmd->argv[1]);
  if (cmd->argc > 2) {
    c->argv[1] = pstrdup(c->pool, cmd->argv[2]);
  }

  if (cmd->argc > 3) {
    c->argv[2] = pstrdup(c->pool, cmd->argv[3]);
  }

  if (cmd->argc > 4) {
    c->argv[3] = pstrdup(c->pool, cmd->argv[4]);
  }

  return PR_HANDLED(cmd);
}

MODRET set_ldapdefaultquota(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Event listeners
 */

static void ldap_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer; reinitialize ourselves. */

  pr_event_unregister(&ldap_module, "core.session-reinit", ldap_sess_reinit_ev);

  /* Restore defaults. */
  (void) close(ldap_logfd);
  ldap_logfd = -1;
  ldap_protocol_version = 3;
  ldap_servers = NULL;
#if defined(LDAP_OPT_X_TLS)
  ldap_use_tls = FALSE;
#endif /* LDAP_OPT_X_TLS */
  ldap_dn = NULL;
  ldap_dnpass = NULL;
  ldap_search_scope = LDAP_SCOPE_SUBTREE;
  ldap_querytimeout = 0;
  ldap_dereference = LDAP_DEREF_NEVER;
  ldap_authbinds = TRUE;
  ldap_defaultauthscheme = "crypt";
  ldap_attr_uid = "uid";
  ldap_attr_uidnumber = "uidNumber";
  ldap_attr_gidnumber = "gidNumber";
  ldap_attr_homedirectory = "homeDirectory";
  ldap_attr_userpassword = "userPassword";
  ldap_attr_loginshell = "loginShell";
  ldap_attr_cn = "cn";
  ldap_attr_memberuid = "memberUid";
  ldap_attr_ftpquota = "ftpQuota";
  ldap_attr_ftpquota_profiledn = "ftpQuotaProfileDN";
  ldap_do_users = FALSE;
  ldap_user_basedn = NULL;
  ldap_user_name_filter = NULL;
  ldap_user_uid_filter = NULL;
  ldap_do_groups = FALSE;
  ldap_group_name_filter = NULL;
  ldap_group_gid_filter = NULL;
  ldap_group_member_filter = NULL;
  ldap_default_quota = NULL;
  ldap_defaultuid = (uid_t) -1;
  ldap_defaultgid = (gid_t) -1;
  ldap_forcedefaultuid = FALSE;
  ldap_forcedefaultgid = FALSE;
  ldap_forcegenhdir = FALSE;
  ldap_genhdir = FALSE;
  ldap_genhdir_prefix = NULL;
  ldap_genhdir_prefix_nouname = FALSE;

  destroy_pool(ldap_pool);
  ldap_pool = NULL;

  res = ldap_sess_init();
  if (res < 0) {
    pr_session_disconnect(&ldap_module, PR_SESS_DISCONNECT_SESSION_INIT_FAILED,
      NULL);
  }
}

/* Initialization routines
 */

static int ldap_mod_init(void) {
  pr_log_debug(DEBUG2, MOD_LDAP_VERSION
    ": compiled using LDAP vendor '%s', LDAP API version %lu",
    LDAP_VENDOR_NAME, (unsigned long) LDAP_API_VERSION);

  return 0;
}

static int ldap_sess_init(void) {
  config_rec *c;
  void *ptr;

  pr_event_register(&ldap_module, "core.session-reinit", ldap_sess_reinit_ev,
    NULL);

  ldap_pool = make_sub_pool(session.pool);
  pr_pool_tag(ldap_pool, MOD_LDAP_VERSION);

  c = find_config(main_server->conf, CONF_PARAM, "LDAPLog", FALSE);
  if (c != NULL) {
    char *path;

    path = c->argv[0];

    if (strncasecmp(path, "none", 5) != 0) {
      int res, xerrno = 0;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(path, &ldap_logfd, PR_LOG_SYSTEM_MODE);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      if (res < 0) {
        if (res == -1) {
          pr_log_pri(PR_LOG_NOTICE, MOD_LDAP_VERSION
            ": notice: unable to open LDAPLog '%s': %s", path,
            strerror(xerrno));

        } else if (res == PR_LOG_WRITABLE_DIR) {
          pr_log_pri(PR_LOG_WARNING, MOD_LDAP_VERSION
            ": notice: unable to open LDAPPLog '%s': parent directory is "
            "world-writable", path);

        } else if (res == PR_LOG_SYMLINK) {
          pr_log_pri(PR_LOG_WARNING, MOD_LDAP_VERSION
            ": notice: unable to open LDAPLog '%s': cannot log to a symlink",
            path);
        }
      }
    }
  }

  ptr = get_param_ptr(main_server->conf, "LDAPProtocolVersion", FALSE);
  if (ptr) {
    ldap_protocol_version = *((int *) ptr);
  }

  c = find_config(main_server->conf, CONF_PARAM, "LDAPServer", FALSE);
  if (c != NULL) {
    ldap_servers = c->argv[0];

  } else {
    /* Leave a NULL server entry if LDAPServer isn't present, so
     * ldap_init()/ldap_initialize() will connect to the LDAP SDK's
     * default.
     */
    ldap_servers = make_array(ldap_pool, 1, sizeof(char *));
    *((char **) push_array(ldap_servers)) = NULL;
  }

#if defined(LDAP_OPT_X_TLS)
  ptr = get_param_ptr(main_server->conf, "LDAPUseTLS", FALSE);
  if (ptr != NULL) {
    ldap_use_tls = *((int *) ptr);
  }
#endif /* LDAP_OPT_X_TLS */

  c = find_config(main_server->conf, CONF_PARAM, "LDAPBindDN", FALSE);
  if (c != NULL) {
    ldap_dn = pstrdup(ldap_pool, c->argv[0]);
    ldap_dnpass = pstrdup(ldap_pool, c->argv[1]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "LDAPSearchScope", FALSE);
  if (c != NULL) {
    ldap_search_scope = *((int *) c->argv[0]);
  }

  ptr = get_param_ptr(main_server->conf, "LDAPQueryTimeout", FALSE);
  if (ptr != NULL) {
    ldap_querytimeout = *((int *) ptr);
  }

  ptr = get_param_ptr(main_server->conf, "LDAPAliasDereference", FALSE);
  if (ptr != NULL) {
    ldap_dereference = *((int *) ptr);
  }

  ptr = get_param_ptr(main_server->conf, "LDAPAuthBinds", FALSE);
  if (ptr != NULL) {
    ldap_authbinds = *((int *) ptr);
  }

  ptr = get_param_ptr(main_server->conf, "LDAPDefaultAuthScheme", FALSE);
  if (ptr != NULL) {
    ldap_defaultauthscheme = (char *) ptr;
  }

  /* Look up any attr redefinitions (LDAPAttr) before using those
   * variables, such as when generating the default search filters.
   */
  c = find_config(main_server->conf, CONF_PARAM, "LDAPAttr", FALSE);
  if (c != NULL) {
    do {
      if (strcasecmp(c->argv[0], "uid") == 0) {
        ldap_attr_uid = pstrdup(ldap_pool, c->argv[1]);

      } else if (strcasecmp(c->argv[0], "uidNumber") == 0) {
        ldap_attr_uidnumber = pstrdup(ldap_pool, c->argv[1]);

      } else if (strcasecmp(c->argv[0], "gidNumber") == 0) {
        ldap_attr_gidnumber = pstrdup(ldap_pool, c->argv[1]);

      } else if (strcasecmp(c->argv[0], "homeDirectory") == 0) {
        ldap_attr_homedirectory = pstrdup(ldap_pool, c->argv[1]);

      } else if (strcasecmp(c->argv[0], "userPassword") == 0) {
        ldap_attr_userpassword = pstrdup(ldap_pool, c->argv[1]);

      } else if (strcasecmp(c->argv[0], "loginShell") == 0) {
        ldap_attr_loginshell = pstrdup(ldap_pool, c->argv[1]);

      } else if (strcasecmp(c->argv[0], "cn") == 0) {
        ldap_attr_cn = pstrdup(ldap_pool, c->argv[1]);

      } else if (strcasecmp(c->argv[0], "memberUid") == 0) {
        ldap_attr_memberuid = pstrdup(ldap_pool, c->argv[1]);

      } else if (strcasecmp(c->argv[0], "ftpQuota") == 0) {
        ldap_attr_ftpquota = pstrdup(ldap_pool, c->argv[1]);

      } else if (strcasecmp(c->argv[0], "ftpQuotaProfileDN") == 0) {
        ldap_attr_ftpquota_profiledn = pstrdup(ldap_pool, c->argv[1]);
      }

    } while ((c = find_config_next(c, c->next, CONF_PARAM, "LDAPAttr", FALSE)));
  }

  c = find_config(main_server->conf, CONF_PARAM, "LDAPUsers", FALSE);
  if (c != NULL) {
    ldap_do_users = TRUE;
    ldap_user_basedn = pstrdup(ldap_pool, c->argv[0]);

    if (c->argc > 1) {
      ldap_user_name_filter = pstrdup(ldap_pool, c->argv[1]);

    } else {
      ldap_user_name_filter = pstrcat(ldap_pool,
        "(&(", ldap_attr_uid, "=%v)(objectclass=posixAccount))", NULL);
    }

    if (c->argc > 2) {
      ldap_user_uid_filter = pstrdup(ldap_pool, c->argv[2]);

    } else {
      ldap_user_uid_filter = pstrcat(ldap_pool,
        "(&(", ldap_attr_uidnumber, "=%v)(objectclass=posixAccount))", NULL);
    }
  }

  ptr = get_param_ptr(main_server->conf, "LDAPDefaultUID", FALSE);
  if (ptr != NULL) {
    ldap_defaultuid = *((uid_t *) ptr);
  }

  ptr = get_param_ptr(main_server->conf, "LDAPDefaultGID", FALSE);
  if (ptr != NULL) {
    ldap_defaultgid = *((gid_t *) ptr);
  }

  ldap_default_quota = get_param_ptr(main_server->conf, "LDAPDefaultQuota",
    FALSE);

  ptr = get_param_ptr(main_server->conf, "LDAPForceDefaultUID", FALSE);
  if (ptr != NULL) {
    ldap_forcedefaultuid = *((int *) ptr);
  }

  ptr = get_param_ptr(main_server->conf, "LDAPForceDefaultGID", FALSE);
  if (ptr != NULL) {
    ldap_forcedefaultgid = *((int *) ptr);
  }

  ptr = get_param_ptr(main_server->conf, "LDAPForceGeneratedHomedir", FALSE);
  if (ptr != NULL) {
    ldap_forcegenhdir = *((int *) ptr);
  }

  ptr = get_param_ptr(main_server->conf, "LDAPGenerateHomedir", FALSE);
  if (ptr != NULL) {
    ldap_genhdir = *((int *) ptr);
  }

  ldap_genhdir_prefix = get_param_ptr(main_server->conf,
    "LDAPGenerateHomedirPrefix", FALSE);

  ptr = get_param_ptr(main_server->conf, "LDAPGenerateHomedirPrefixNoUsername",
    FALSE);
  if (ptr != NULL) {
    ldap_genhdir_prefix_nouname = *((int *) ptr);
  }

  c = find_config(main_server->conf, CONF_PARAM, "LDAPGroups", FALSE);
  if (c != NULL) {
    ldap_do_groups = TRUE;
    ldap_gid_basedn = pstrdup(ldap_pool, c->argv[0]);

    if (c->argc > 1) {
      ldap_group_name_filter = pstrdup(ldap_pool, c->argv[1]);

    } else {
      ldap_group_name_filter = pstrcat(ldap_pool,
        "(&(", ldap_attr_cn, "=%v)(objectclass=posixGroup))", NULL);
    }

    if (c->argc > 2) {
      ldap_group_gid_filter = pstrdup(ldap_pool, c->argv[2]);

    } else {
      ldap_group_gid_filter = pstrcat(ldap_pool,
        "(&(", ldap_attr_gidnumber, "=%v)(objectclass=posixGroup))", NULL);
    }

    if (c->argc > 3) {
      ldap_group_member_filter = pstrdup(ldap_pool, c->argv[3]);

    } else {
      ldap_group_member_filter = pstrcat(ldap_pool,
        "(&(", ldap_attr_memberuid, "=%v)(objectclass=posixGroup))", NULL);
    }
  }

#if defined(LBER_OPT_LOG_PRINT_FN)
  /* If trace logging is enabled for the 'ldap.library' channel, direct
   * libldap (via liblber) to log to our trace logging.
   */
  if (pr_trace_get_level(libtrace_channel) >= 1) {
    int res;

    res = ber_set_option(NULL, LBER_OPT_LOG_PRINT_FN, ldap_tracelog_cb);
    if (res != LBER_OPT_SUCCESS) {
      (void) pr_log_writefile(ldap_logfd, MOD_LDAP_VERSION,
        "error setting trace logging function: %s", strerror(EINVAL));
    }
  }
#endif /* LBER_OPT_LOG_PRINT_FN */

  return 0;
}

/* Module API tables
 */

static conftable ldap_conftab[] = {
  { "LDAPAliasDereference",	set_ldapaliasdereference,	NULL },
  { "LDAPAttr",			set_ldapattr,			NULL },
  { "LDAPAuthBinds",		set_ldapauthbinds,		NULL },
  { "LDAPBindDN",		set_ldapbinddn,			NULL },
  { "LDAPDefaultAuthScheme",	set_ldapdefaultauthscheme,	NULL },
  { "LDAPDefaultGID",		set_ldapdefaultgid,		NULL },
  { "LDAPDefaultQuota",		set_ldapdefaultquota,		NULL },
  { "LDAPDefaultUID",		set_ldapdefaultuid,		NULL },
  { "LDAPForceDefaultGID",	set_ldapforcedefaultgid,	NULL },
  { "LDAPForceDefaultUID",	set_ldapforcedefaultuid,	NULL },
  { "LDAPForceGeneratedHomedir",set_ldapforcegenhdir,		NULL },
  { "LDAPGenerateHomedir",	set_ldapgenhdir,		NULL },
  { "LDAPGenerateHomedirPrefix",set_ldapgenhdirprefix,		NULL },
  { "LDAPGenerateHomedirPrefixNoUsername",
				set_ldapgenhdirprefixnouname,	NULL },
  { "LDAPGroups",		set_ldapgrouplookups,		NULL },
  { "LDAPLog",			set_ldaplog,			NULL },
  { "LDAPProtocolVersion",	set_ldapprotoversion,		NULL },
  { "LDAPQueryTimeout",		set_ldapquerytimeout,		NULL },
  { "LDAPSearchScope",		set_ldapsearchscope,		NULL },
  { "LDAPServer",		set_ldapserver,			NULL },
  { "LDAPUsers",		set_ldapusers,			NULL },
  { "LDAPUseTLS",		set_ldapusetls,			NULL },

  { NULL, NULL, NULL },
};

static cmdtable ldap_cmdtab[] = {
  { HOOK, "ldap_quota_lookup",		G_NONE, handle_ldap_quota_lookup, FALSE, FALSE},
  { HOOK, "ldap_ssh_publickey_lookup",	G_NONE, handle_ldap_ssh_pubkey_lookup, FALSE, FALSE},

  { 0, NULL}
};

static authtable ldap_authtab[] = {
  { 0, "setpwent",	ldap_auth_setpwent },
  { 0, "endpwent",	ldap_auth_endpwent },
  { 0, "setgrent",	ldap_auth_setpwent },
  { 0, "endgrent",	ldap_auth_endpwent },
  { 0, "getpwnam",	ldap_auth_getpwnam },
  { 0, "getpwuid",	ldap_auth_getpwuid },
  { 0, "getgrnam",	ldap_auth_getgrnam },
  { 0, "getgrgid",	ldap_auth_getgrgid },
  { 0, "getgroups",	ldap_auth_getgroups },
  { 0, "auth",		ldap_auth_auth },
  { 0, "check",		ldap_auth_check },
  { 0, "uid2name",	ldap_auth_uid2name },
  { 0, "gid2name",	ldap_auth_gid2name },
  { 0, "name2uid",	ldap_auth_name2uid },
  { 0, "name2gid",	ldap_auth_name2gid },

  { 0, NULL }
};

module ldap_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "ldap",

  /* Module configuration handler table */
  ldap_conftab,

  /* Module command handler table */
  ldap_cmdtab,

  /* Module authentication handler table */
  ldap_authtab,

  /* Module initialization */
  ldap_mod_init,

  /* Session initialization */
  ldap_sess_init,

  /* Module version */
  MOD_LDAP_VERSION
};
