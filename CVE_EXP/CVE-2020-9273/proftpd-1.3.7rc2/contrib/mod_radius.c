/*
 * ProFTPD: mod_radius -- a module for RADIUS authentication and accounting
 * Copyright (c) 2001-2017 TJ Saunders
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
 *
 * This is mod_radius, contrib software for proftpd 1.2 and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 *
 * This module is based in part on code in Alan DeKok's (aland@freeradius.org)
 * mod_auth_radius for Apache, in part on the FreeRADIUS project's code.
 */

#define MOD_RADIUS_VERSION	"mod_radius/0.9.3"

#include "conf.h"
#include "privs.h"

/* RADIUS information */

/* From RFC2865, RFC2866 */
#define RADIUS_AUTH_PORT	1812
#define RADIUS_ACCT_PORT	1813

#define RADIUS_PASSWD_LEN	16
#define RADIUS_VECTOR_LEN	16

/* From RFC2138 */
#define RADIUS_STRING_LEN	254

/* RADIUS attribute structures */
typedef struct {
  unsigned char type;
  unsigned char length;
  unsigned char data[1];
} radius_attrib_t;

/* RADIUS packet header */
typedef struct {
  unsigned char code;
  unsigned char id;
  unsigned short length;
  unsigned char digest[RADIUS_VECTOR_LEN];
  unsigned char data[2];

  char _pad[PR_TUNABLE_BUFFER_SIZE];
} radius_packet_t;

#define RADIUS_HEADER_LEN	20

/* RADIUS ID Definitions (see RFC 2865, 2866) */
#define RADIUS_AUTH_REQUEST		1
#define RADIUS_AUTH_ACCEPT		2
#define RADIUS_AUTH_REJECT		3
#define RADIUS_ACCT_REQUEST		4
#define RADIUS_ACCT_RESPONSE		5
#define RADIUS_ACCT_STATUS		6
#define RADIUS_AUTH_CHALLENGE		11

/* RADIUS Attribute Definitions (see RFC 2865, 2866) */
#define RADIUS_USER_NAME		1
#define RADIUS_PASSWORD			2
#define RADIUS_NAS_IP_ADDRESS		4
#define RADIUS_NAS_PORT			5
#define RADIUS_SERVICE_TYPE		6
#define RADIUS_OLD_PASSWORD		17
#define RADIUS_REPLY_MESSAGE		18
#define RADIUS_STATE			24
#define RADIUS_CLASS			25
#define RADIUS_VENDOR_SPECIFIC		26
#define RADIUS_SESSION_TIMEOUT		27
#define RADIUS_IDLE_TIMEOUT		28
#define RADIUS_CALLING_STATION_ID	31
#define RADIUS_NAS_IDENTIFIER		32
#define RADIUS_ACCT_STATUS_TYPE		40
#define RADIUS_ACCT_INPUT_OCTETS	42
#define RADIUS_ACCT_OUTPUT_OCTETS	43
#define RADIUS_ACCT_SESSION_ID		44
#define RADIUS_ACCT_AUTHENTIC		45
#define RADIUS_ACCT_SESSION_TIME	46
#define RADIUS_ACCT_TERMINATE_CAUSE	49
#define RADIUS_ACCT_EVENT_TS		55
#define RADIUS_NAS_PORT_TYPE		61
#define RADIUS_MESSAGE_AUTHENTICATOR	80
#define RADIUS_NAS_IPV6_ADDRESS		95

/* RADIUS service types */
#define RADIUS_SVC_LOGIN		1
#define RADIUS_SVC_AUTHENTICATE_ONLY	8

/* RADIUS status types */
#define RADIUS_ACCT_STATUS_START	1
#define RADIUS_ACCT_STATUS_STOP		2
#define RADIUS_ACCT_STATUS_ALIVE	3

/* RADIUS NAS port types */
#define RADIUS_NAS_PORT_TYPE_VIRTUAL	5

/* RADIUS authentication types */
#define RADIUS_AUTH_NONE		0
#define RADIUS_AUTH_RADIUS		1
#define RADIUS_AUTH_LOCAL		2

/* RADIUS Acct-Terminate-Cause types */
#define RADIUS_ACCT_TERMINATE_CAUSE_USER_REQUEST	1
#define RADIUS_ACCT_TERMINATE_CAUSE_LOST_SERVICE	3
#define RADIUS_ACCT_TERMINATE_CAUSE_IDLE_TIMEOUT	4
#define RADIUS_ACCT_TERMINATE_CAUSE_SESSION_TIMEOUT	5
#define RADIUS_ACCT_TERMINATE_CAUSE_ADMIN_RESET		6
#define RADIUS_ACCT_TERMINATE_CAUSE_ADMIN_REBOOT	7
#define RADIUS_ACCT_TERMINATE_CAUSE_SERVICE_UNAVAIL	15
#define RADIUS_ACCT_TERMINATE_CAUSE_USER_ERROR		16

/* The RFC says 4096 octets max, and most packets are less than 256.
 * However, this number is just larger than the maximum MTU of just
 * most types of networks, except maybe for gigabit ethernet.
 */
#define RADIUS_PACKET_LEN		1600

/* Miscellaneous default values */
#define DEFAULT_RADIUS_TIMEOUT		10

#define RADIUS_ATTRIB_LEN(attr)		((attr)->length)

/* Adjust the VSA length (I'm not sure why this is necessary, but a reading
 * of the FreeRADIUS sources show it to be.  Weird.)
 */
#define RADIUS_VSA_ATTRIB_LEN(attr)	((attr)->length - 2)

typedef struct radius_server_obj {

  /* Next server in line */
  struct radius_server_obj *next;

  /* Memory pool for this object */
  pool *pool;

  /* RADIUS server IP address */
  const pr_netaddr_t *addr;

  /* RADIUS server port */
  unsigned short port;

  /* RADIUS server shared secret */
  unsigned char *secret;
  size_t secret_len;

  /* How long to wait for RADIUS responses */
  unsigned int timeout;

} radius_server_t;

module radius_module;

static pool *radius_pool = NULL;
static int radius_engine = FALSE;
static radius_server_t *radius_acct_server = NULL;
static radius_server_t *radius_auth_server = NULL;
static int radius_logfd = -1;

/* mod_radius option flags */
#define RADIUS_OPT_IGNORE_REPLY_MESSAGE_ATTR		0x0001
#define RADIUS_OPT_IGNORE_CLASS_ATTR			0x0002
#define RADIUS_OPT_IGNORE_SESSION_TIMEOUT_ATTR		0x0004
#define RADIUS_OPT_IGNORE_IDLE_TIMEOUT_ATTR		0x0008
#define RADIUS_OPT_REQUIRE_MAC				0x0010

static unsigned long radius_opts = 0UL;

static struct sockaddr radius_local_sock, radius_remote_sock;

/* For tracking various values not stored in the session struct */
static const char *radius_nas_identifier_config = NULL;
static char *radius_realm = NULL;
static time_t radius_session_start = 0;
static int radius_session_authtype = RADIUS_AUTH_LOCAL;
static unsigned char radius_auth_ok = FALSE;
static unsigned char radius_auth_reject = FALSE;

/* For tracking the Class attribute, for sending in accounting requests. */
static char *radius_acct_class = NULL;
static size_t radius_acct_classlen = 0;
static char *radius_acct_user = NULL;
static size_t radius_acct_userlen = 0;

/* "Fake" user/group information for RADIUS users. */
static unsigned char radius_have_user_info = FALSE;
static struct passwd radius_passwd;

static unsigned char radius_have_group_info = FALSE;
static char *radius_prime_group_name = NULL;
static unsigned int radius_addl_group_count = 0;
static char **radius_addl_group_names = NULL;
static char *radius_addl_group_names_str = NULL;
static gid_t *radius_addl_group_ids = NULL;
static char *radius_addl_group_ids_str = NULL;

/* Quota info */
static unsigned char radius_have_quota_info = FALSE;
static char *radius_quota_per_sess = NULL;
static char *radius_quota_limit_type = NULL;
static char *radius_quota_bytes_in = NULL;
static char *radius_quota_bytes_out = NULL;
static char *radius_quota_bytes_xfer = NULL;
static char *radius_quota_files_in = NULL;
static char *radius_quota_files_out = NULL;
static char *radius_quota_files_xfer = NULL;

/* Other info */
static unsigned char radius_have_other_info = FALSE;

/* Vendor information, defaults to Unix (Vendor-Id of 4) */
static const char *radius_vendor_name = "Unix";
static unsigned int radius_vendor_id = 4;

/* Custom VSA IDs that may be used for server-supplied RadiusUserInfo
 * parameters.
 */
static int radius_uid_attr_id = 0;
static int radius_gid_attr_id = 0;
static int radius_home_attr_id = 0;
static int radius_shell_attr_id = 0;

/* Custom VSA IDs that may be used for server-supplied RadiusGroupInfo
 * parameters.
 */
static int radius_prime_group_name_attr_id = 0;
static int radius_addl_group_names_attr_id = 0;
static int radius_addl_group_ids_attr_id = 0;

/* Custom VSA IDs that may be used for server-supplied QuotaLimitTable
 * parameters.
 */
static int radius_quota_per_sess_attr_id = 0;
static int radius_quota_limit_type_attr_id = 0;
static int radius_quota_bytes_in_attr_id = 0;
static int radius_quota_bytes_out_attr_id = 0;
static int radius_quota_bytes_xfer_attr_id = 0;
static int radius_quota_files_in_attr_id = 0;
static int radius_quota_files_out_attr_id = 0;
static int radius_quota_files_xfer_attr_id = 0;

/* For tracking the ID of the last accounting packet (to prevent the
 * same ID from being reused).
 */
static unsigned char radius_last_acct_pkt_id = 0;

static const char *trace_channel = "radius";

/* Convenience macros. */
#define RADIUS_IS_VAR(str) \
  ((str[0] == '$') && (str[1] == '(') && (str[strlen(str)-1] == ')'))

/* Function prototypes. */
static radius_attrib_t *radius_add_attrib(radius_packet_t *, unsigned char,
  const unsigned char *, size_t);
static void radius_add_passwd(radius_packet_t *, unsigned char,
  const unsigned char *, unsigned char *, size_t);
static void radius_build_packet(radius_packet_t *, const unsigned char *,
  const unsigned char *, unsigned char *, size_t);
static unsigned char radius_have_var(char *);
static radius_attrib_t *radius_get_attrib(radius_packet_t *, unsigned char);
static radius_attrib_t *radius_get_next_attrib(radius_packet_t *,
  unsigned char, unsigned int *, radius_attrib_t *);
static void radius_get_rnd_digest(radius_packet_t *);
static radius_attrib_t *radius_get_vendor_attrib(radius_packet_t *,
  unsigned char);
static void radius_set_acct_digest(radius_packet_t *, const unsigned char *,
  size_t);
static void radius_set_auth_mac(radius_packet_t *, const unsigned char *,
  size_t);
static radius_server_t *radius_make_server(pool *);
static int radius_openlog(void);
static int radius_open_socket(void);
static unsigned char radius_parse_gids_str(pool *, char *, gid_t **,
  unsigned int *);
static unsigned char radius_parse_groups_str(pool *, char *, char ***,
  unsigned int *);
static int radius_parse_var(char *, int *, char **);
static int radius_process_accept_packet(radius_packet_t *,
  const unsigned char *, size_t);
static int radius_process_reject_packet(radius_packet_t *,
  const unsigned char *, size_t);
static void radius_process_group_info(config_rec *);
static void radius_process_quota_info(config_rec *);
static void radius_process_user_info(config_rec *);
static radius_packet_t *radius_recv_packet(int, unsigned int);
static int radius_send_packet(int, radius_packet_t *, radius_server_t *);
static int radius_start_accting(void);
static int radius_stop_accting(void);
static int radius_verify_auth_mac(radius_packet_t *, const char *,
  const unsigned char *, size_t);
static int radius_verify_packet(radius_packet_t *, radius_packet_t *,
  const unsigned char *, size_t);
static int radius_sess_init(void);

/* Support functions
 */

static char *radius_argsep(char **arg) {
  char *ret = NULL, *dst = NULL;
  char quote_mode = 0;

  if (!arg || !*arg || !**arg)
    return NULL;

  while (**arg && PR_ISSPACE(**arg)) {
    (*arg)++;
  }

  if (!**arg)
    return NULL;

  ret = dst = *arg;

  if (**arg == '\"') {
    quote_mode++;
    (*arg)++;
  }

  while (**arg && **arg != ',' &&
      (quote_mode ? (**arg != '\"') : (!PR_ISSPACE(**arg)))) {

    if (**arg == '\\' && quote_mode) {

      /* escaped char */
      if (*((*arg) + 1))
        *dst = *(++(*arg));
    }

    *dst++ = **arg;
    ++(*arg);
  }

  if (**arg)
    (*arg)++;

  *dst = '\0';
  return ret;
}

/* Check a "$(attribute-id:default)" string for validity. */
static unsigned char radius_have_var(char *var) {
  int id = 0;
  char *ptr = NULL;
  size_t varlen;

  varlen = strlen(var);

  /* Must be at least six characters. */
  if (varlen < 7) {
    return FALSE;
  }

  /* Must start with '$(', and end with ')'. */
  if (RADIUS_IS_VAR(var) == FALSE) {
    return FALSE;
  }

  /* Must have a ':'. */
  ptr = strchr(var, ':');
  if (ptr == NULL) {
    return FALSE;
  }

  /* ':' must be between '(' and ')'. */
  if (ptr < (var + 3) ||
      ptr > &var[varlen-2]) {
    return FALSE;
  }

  /* Parse out the component int/string. */
  radius_parse_var(var, &id, NULL);

  /* Int must be greater than zero. */
  if (id < 1) {
    return FALSE;
  }

  return TRUE;
}

/* Separate the given "$(attribute-id:default)" string into its constituent
 * custom attribute ID (int) and default (string) components.
 */
static int radius_parse_var(char *var, int *attr_id, char **attr_default) {
  pool *tmp_pool;
  char *var_cpy, *ptr = NULL;
  size_t var_len, var_cpylen;

  if (var == NULL) {
    errno = EINVAL;
    return -1;
  }

  var_len = var_cpylen = strlen(var);
  if (var_len == 0) {
    /* Empty string; nothing to do. */
    return 0;
  }
  
  tmp_pool = make_sub_pool(radius_pool);
  var_cpy = pstrdup(tmp_pool, var);

  /* First, strip off the "$()" variable characters. */
  var_cpy[var_cpylen-1] = '\0';
  var_cpy += 2;

  /* Find the delimiting ':' */
  ptr = strchr(var_cpy, ':');
  if (ptr != NULL) {
    *ptr++ = '\0';
  }

  if (attr_id) {
    *attr_id = atoi(var_cpy);
  }

  if (attr_default) {
    ptr = strchr(var, ':');

    /* Note: this works because the calling of this function by
     * radius_have_var(), which occurs during the parsing process, uses
     * a NULL for this portion, so that the string stored in the config_rec
     * is not actually manipulated, as is done here.
     */
    if (var_len > 0) {
      var[var_len-1] = '\0';
    }

    if (ptr != NULL) {
      *attr_default = ++ptr;
    }
  }

  /* Clean up. */
  destroy_pool(tmp_pool);
  return 0;
}

static unsigned char radius_parse_gids_str(pool *p, char *gids_str, 
    gid_t **gids, unsigned int *ngids) {
  char *val = NULL;
  array_header *group_ids = make_array(p, 0, sizeof(gid_t));

  /* Add each GID to the array. */
  while ((val = radius_argsep(&gids_str)) != NULL) {
    gid_t gid;
    char *endp = NULL;

    pr_signals_handle();

    /* Make sure the given ID is a valid number. */
    gid = strtoul(val, &endp, 10);

    if (endp && *endp) {
      pr_log_pri(PR_LOG_NOTICE, "RadiusGroupInfo badly formed group ID: %s",
        val);
      return FALSE;
    }

    /* Push the ID into the ID array. */
    *((gid_t *) push_array(group_ids)) = gid;
  }

  *gids = (gid_t *) group_ids->elts;
  *ngids = group_ids->nelts;

  return TRUE;
}

static unsigned char radius_parse_groups_str(pool *p, char *groups_str,
    char ***groups, unsigned int *ngroups) {
  char *name = NULL;
  array_header *group_names = make_array(p, 0, sizeof(char *));

  /* Add each name to the array. */
  while ((name = radius_argsep(&groups_str)) != NULL) {
    char *tmp;

    pr_signals_handle();
    tmp = pstrdup(p, name);

    /* Push the name into the name array. */
    *((char **) push_array(group_names)) = tmp;
  }

  *groups = (char **) group_names->elts;
  *ngroups = group_names->nelts;

  return TRUE;
}

static int radius_process_standard_attribs(radius_packet_t *pkt,
    const unsigned char *secret, size_t secret_len) {
  int attrib_count = 0;
  radius_attrib_t *attrib = NULL;
  unsigned char attrib_len;

  pr_trace_msg(trace_channel, 2, "parsing packet for standard attribute IDs");

  if (radius_verify_auth_mac(pkt, "Access-Accept", secret, secret_len) < 0) {
    return -1;
  }

  /* TODO: Should we handle the Service-Type attribute here, make sure that it
   * is a) a service type we implement, and b) the service type that we
   * requested?
   */

  /* Handle any CLASS attribute. */
  if (!(radius_opts & RADIUS_OPT_IGNORE_CLASS_ATTR)) {
    attrib = radius_get_attrib(pkt, RADIUS_CLASS);
    if (attrib != NULL) {
      attrib_len = RADIUS_ATTRIB_LEN(attrib);
      if (attrib_len > 0) {
        char *class = NULL;

        class = pstrndup(radius_pool, (char *) attrib->data, attrib_len);
        pr_trace_msg(trace_channel, 7,
          "found Class attribute in Access-Accept message: %s", class);
        radius_acct_class = class;
        radius_acct_classlen = attrib_len;
      }

      attrib_count++;

    } else {
      pr_trace_msg(trace_channel, 6,
        "Access-Accept packet lacks Class attribute (%d)", RADIUS_CLASS);
    }
  }

  /* Handle any User-Name attribute, per RFC 2865, Section 5.1. */
  attrib = radius_get_attrib(pkt, RADIUS_USER_NAME);
  if (attrib != NULL) {
    attrib_len = RADIUS_ATTRIB_LEN(attrib);
    if (attrib_len > 0) {
      char *user_name = NULL;

      user_name = pstrndup(radius_pool, (char *) attrib->data, attrib_len);
      pr_trace_msg(trace_channel, 7,
        "found User-Name attribute in Access-Accept message: %s", user_name);
      radius_acct_user = user_name;
      radius_acct_userlen = attrib_len;
    }

    attrib_count++;

  } else {
    pr_trace_msg(trace_channel, 6,
      "Access-Accept packet lacks User-Name attribute (%d)", RADIUS_USER_NAME);
  }

  /* Handle any REPLY_MESSAGE attributes. */
  if (!(radius_opts & RADIUS_OPT_IGNORE_REPLY_MESSAGE_ATTR)) {
    unsigned int pkt_len = 0;

    attrib = radius_get_next_attrib(pkt, RADIUS_REPLY_MESSAGE, &pkt_len, NULL);
    while (attrib != NULL) {
      pr_signals_handle();

      attrib_len = RADIUS_ATTRIB_LEN(attrib);
      if (attrib_len > 0) {
        char *reply_msg = NULL;

        reply_msg = pstrndup(radius_pool, (char *) attrib->data, attrib_len);
        pr_trace_msg(trace_channel, 7,
          "found REPLY_MESSAGE attribute in Access-Accept message: '%s'",
          reply_msg);
        pr_response_add(R_DUP, "%s", reply_msg);
      }

      attrib_count++;

      if (pkt_len == 0) {
        break;
      }

      attrib = radius_get_next_attrib(pkt, RADIUS_REPLY_MESSAGE, &pkt_len,
        attrib);
    }

    if (attrib_count == 0) {
      pr_trace_msg(trace_channel, 6,
        "Access-Accept packet lacks Reply-Message attribute (%d)",
        RADIUS_REPLY_MESSAGE);
    }
  }

  /* Handle any IDLE_TIMEOUT attribute. */
  if (!(radius_opts & RADIUS_OPT_IGNORE_IDLE_TIMEOUT_ATTR)) {
    attrib = radius_get_attrib(pkt, RADIUS_IDLE_TIMEOUT);
    if (attrib != NULL) {
      attrib_len = RADIUS_ATTRIB_LEN(attrib);
      if (attrib_len > 0) {
        int timeout = -1;

        if (attrib_len > sizeof(timeout)) {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "invalid attribute length (%u) for Idle-Timeout, truncating",
            attrib_len);
          attrib_len = sizeof(timeout);
        }

        memcpy(&timeout, attrib->data, attrib_len);
        timeout = ntohl(timeout);

        if (timeout < 0) {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "packet includes Idle-Timeout attribute %d for illegal timeout: %d",
            RADIUS_IDLE_TIMEOUT, timeout);

        } else {
          config_rec *c;

          pr_trace_msg(trace_channel, 2,
            "packet includes Idle-Timeout attribute %d for timeout: %d",
            RADIUS_IDLE_TIMEOUT, timeout);
          remove_config(main_server->conf, "TimeoutIdle", TRUE);

          c = pr_config_add_set(&main_server->conf, "TimeoutIdle",
            PR_CONFIG_FL_INSERT_HEAD);
          c->config_type = CONF_PARAM;
          c->argc = 1;
          c->argv[0] = palloc(c->pool, sizeof(int));
          *((int *) c->argv[0]) = timeout;

          attrib_count++;
        }
      }

    } else {
      pr_trace_msg(trace_channel, 6,
        "Access-Accept packet lacks Idle-Timeout attribute (%d)",
        RADIUS_IDLE_TIMEOUT);
    }
  }

  /* Handle any SESSION_TIMEOUT attribute. */
  if (!(radius_opts & RADIUS_OPT_IGNORE_SESSION_TIMEOUT_ATTR)) {
    attrib = radius_get_attrib(pkt, RADIUS_SESSION_TIMEOUT);
    if (attrib != NULL) {
      attrib_len = RADIUS_ATTRIB_LEN(attrib);
      if (attrib_len > 0) {
        int timeout = -1;

        if (attrib_len > sizeof(timeout)) {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "invalid attribute length (%u) for Session-Timeout, truncating",
            attrib_len);
          attrib_len = sizeof(timeout);
        }

        memcpy(&timeout, attrib->data, attrib_len);
        timeout = ntohl(timeout);

        if (timeout < 0) {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "packet includes Session-Timeout attribute %d for illegal "
            "timeout: %d", RADIUS_SESSION_TIMEOUT, timeout);

        } else {
          config_rec *c;

          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "packet includes Session-Timeout attribute %d for timeout: %d",
            RADIUS_SESSION_TIMEOUT, timeout);
          remove_config(main_server->conf, "TimeoutSession", TRUE);

          c = pr_config_add_set(&main_server->conf, "TimeoutSession",
            PR_CONFIG_FL_INSERT_HEAD);
          c->config_type = CONF_PARAM;
          c->argc = 2;
          c->argv[0] = palloc(c->pool, sizeof(int));
          *((int *) c->argv[0]) = timeout;
          c->argv[1] = palloc(c->pool, sizeof(unsigned int));
          *((unsigned int *) c->argv[1]) = 0;

          attrib_count++;
        }
      }

    } else {
      pr_trace_msg(trace_channel, 6,
        "Access-Accept packet lacks Session-Timeout attribute (%d)",
        RADIUS_SESSION_TIMEOUT);
    }
  }

  return attrib_count;
}

static int radius_process_user_info_attribs(radius_packet_t *pkt) {
  int attrib_count = 0;

  if (radius_uid_attr_id || radius_gid_attr_id ||
      radius_home_attr_id || radius_shell_attr_id) {
    pr_trace_msg(trace_channel, 2,
      "parsing packet for RadiusUserInfo attributes");

    /* These custom values will been supplied in the configuration file, and
     * set when the RadiusUserInfo config_rec is retrieved, during
     * session initialization.
     */

    if (radius_uid_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_uid_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        int uid = -1;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);

        /* Parse the attribute value into an int, then cast it into the
         * radius_passwd.pw_uid field.  Make sure it's a sane UID
         * (ie non-negative).
         */

        if (attrib_len > sizeof(uid)) {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "invalid attribute length (%u) for user ID, truncating",
            attrib_len);
          attrib_len = sizeof(uid);
        }

        memcpy(&uid, attrib->data, attrib_len);
        uid = ntohl(uid);

        if (uid < 0) {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "packet includes '%s' Vendor-Specific Attribute %d for illegal "
            "user ID: %d", radius_vendor_name, radius_uid_attr_id, uid);

        } else {
          radius_passwd.pw_uid = uid;

          pr_trace_msg(trace_channel, 3,
            "packet includes '%s' Vendor-Specific Attribute %d for user ID: %d",
            radius_vendor_name, radius_uid_attr_id,
            radius_passwd.pw_uid);
          attrib_count++;
        }

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d "
          "for user ID; defaulting to '%u'", radius_vendor_name,
          radius_uid_attr_id, radius_passwd.pw_uid);
      }
    }

    if (radius_gid_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_gid_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        int gid = -1;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);

        /* Parse the attribute value into an int, then cast it into the
         * radius_passwd.pw_gid field.  Make sure it's a sane GID
         * (ie non-negative).
         */

        if (attrib_len > sizeof(gid)) {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "invalid attribute length (%u) for group ID, truncating",
            attrib_len);
          attrib_len = sizeof(gid);
        }

        memcpy(&gid, attrib->data, attrib_len);
        gid = ntohl(gid);

        if (gid < 0) {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "packet includes '%s' Vendor-Specific Attribute %d for illegal "
            "group ID: %d", radius_vendor_name, radius_gid_attr_id, gid);

        } else {
          radius_passwd.pw_gid = gid;

          pr_trace_msg(trace_channel, 3,
            "packet includes '%s' Vendor-Specific Attribute %d for group "
            "ID: %d", radius_vendor_name, radius_gid_attr_id,
            radius_passwd.pw_gid);
          attrib_count++;
        }

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d "
          "for group ID; defaulting to '%u'", radius_vendor_name,
          radius_gid_attr_id, radius_passwd.pw_gid);
      }
    }

    if (radius_home_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_home_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        char *home;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);

        home = pstrndup(radius_pool, (char *) attrib->data, attrib_len);
        if (*home != '/') {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "packet includes '%s' Vendor-Specific Attribute %d for illegal "
            "home: '%s'", radius_vendor_name, radius_home_attr_id, home);

        } else {
          radius_passwd.pw_dir = home;

          pr_trace_msg(trace_channel, 3,
            "packet includes '%s' Vendor-Specific Attribute %d for home "
            "directory: '%s'", radius_vendor_name, radius_home_attr_id,
            radius_passwd.pw_dir);
          attrib_count++;
        }

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d for "
          "home directory; defaulting to '%s'", radius_vendor_name,
          radius_home_attr_id, radius_passwd.pw_dir);
      }
    }

    if (radius_shell_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_shell_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        char *shell;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);

        shell = pstrndup(radius_pool, (char *) attrib->data, attrib_len);
        if (*shell != '/') {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "packet includes '%s' Vendor-Specific Attribute %d for illegal "
            "shell: '%s'", radius_vendor_name, radius_shell_attr_id, shell);

        } else {
          radius_passwd.pw_shell = shell;

          pr_trace_msg(trace_channel, 3,
            "packet includes '%s' Vendor-Specific Attribute %d for "
            "shell: '%s'", radius_vendor_name, radius_shell_attr_id,
            radius_passwd.pw_shell);
          attrib_count++;
        }

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d for "
          "shell; defaulting to '%s'", radius_vendor_name, radius_shell_attr_id,
          radius_passwd.pw_shell);
      }
    }
  }

  return attrib_count;
}

static int radius_process_group_info_attribs(radius_packet_t *pkt) {
  int attrib_count = 0;

  if (radius_prime_group_name_attr_id ||
      radius_addl_group_names_attr_id ||
      radius_addl_group_ids_attr_id) {
    unsigned int ngroups = 0, ngids = 0;
    char **groups = NULL;
    gid_t *gids = NULL;

    pr_trace_msg(trace_channel, 2,
      "parsing packet for RadiusGroupInfo attributes");

    if (radius_prime_group_name_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_prime_group_name_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        char *group_name;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);

        group_name = pstrndup(radius_pool, (char *) attrib->data, attrib_len);
        radius_prime_group_name = pstrdup(radius_pool, group_name);

        pr_trace_msg(trace_channel, 3,
          "packet includes '%s' Vendor-Specific Attribute %d for primary "
          "group name: '%s'", radius_vendor_name,
          radius_prime_group_name_attr_id, radius_prime_group_name);
        attrib_count++;

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d for "
          "prime group name; defaulting to '%s'", radius_vendor_name,
          radius_prime_group_name_attr_id, radius_prime_group_name);
      }
    }

    if (radius_addl_group_names_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_addl_group_names_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        char *group_names, *group_names_str;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);
        group_names = pstrndup(radius_pool, (char *) attrib->data, attrib_len);

        /* Make a copy of the string, for parsing purposes.  The parsing
         * of this string will consume it.
         */
        group_names_str = pstrdup(radius_pool, group_names);

        if (!radius_parse_groups_str(radius_pool, group_names_str, &groups,
            &ngroups)) {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "packet includes '%s' Vendor-Specific Attribute %d for illegal "
            "additional group names: '%s'", radius_vendor_name,
            radius_addl_group_names_attr_id, group_names);

        } else {
          pr_trace_msg(trace_channel, 3,
            "packet includes '%s' Vendor-Specific Attribute %d for "
            "additional group names: '%s'", radius_vendor_name,
            radius_addl_group_names_attr_id, group_names);
        }

        attrib_count++;

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d for "
          "additional group names; defaulting to '%s'", radius_vendor_name,
          radius_addl_group_names_attr_id, radius_addl_group_names_str);
      }
    }

    if (radius_addl_group_ids_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_addl_group_ids_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        char *group_ids, *group_ids_str;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);
        group_ids = pstrndup(radius_pool, (char *) attrib->data, attrib_len);

        /* Make a copy of the string, for parsing purposes.  The parsing
         * of this string will consume it.
         */
        group_ids_str = pstrdup(radius_pool, group_ids);

        if (!radius_parse_gids_str(radius_pool, group_ids_str, &gids, &ngids)) {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "packet includes '%s' Vendor-Specific Attribute %d for illegal "
            "additional group IDs: '%s'", radius_vendor_name,
            radius_addl_group_ids_attr_id, group_ids);

        } else {
          pr_trace_msg(trace_channel, 3,
            "packet includes '%s' Vendor-Specific Attribute %d for additional "
            "group IDs: '%s'", radius_vendor_name,
            radius_addl_group_ids_attr_id, group_ids);
        }

        attrib_count++;

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d for "
          "additional group IDs; defaulting to '%s'", radius_vendor_name,
          radius_addl_group_ids_attr_id, radius_addl_group_ids_str);
      }
    }

    /* One last RadiusGroupInfo check: does the number of returned group
     * names match the number of returned group IDs?
     */
    if (ngroups == ngids) {
      radius_have_group_info = TRUE;
      radius_addl_group_count = ngroups;
      radius_addl_group_names = groups;
      radius_addl_group_ids = gids;

    } else {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "server provided mismatched number of group names (%u) and group "
        "IDs (%u), ignoring them", ngroups, ngids);
    }
  }

  return attrib_count;
}

static int radius_process_quota_info_attribs(radius_packet_t *pkt) {
  int attrib_count = 0;

  if (radius_quota_per_sess_attr_id ||
      radius_quota_limit_type_attr_id ||
      radius_quota_bytes_in_attr_id ||
      radius_quota_bytes_out_attr_id ||
      radius_quota_bytes_xfer_attr_id ||
      radius_quota_files_in_attr_id ||
      radius_quota_files_out_attr_id ||
      radius_quota_files_xfer_attr_id) {

    pr_trace_msg(trace_channel, 2,
      "parsing packet for RadiusQuotaInfo attributes");

    if (radius_quota_per_sess_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_quota_per_sess_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        char *per_sess;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);
        per_sess = pstrndup(radius_pool, (char *) attrib->data, attrib_len);

        radius_quota_per_sess = per_sess;

        pr_trace_msg(trace_channel, 2,
          "packet includes '%s' Vendor-Specific Attribute %d for quota "
          "per-session: '%s'", radius_vendor_name,
          radius_quota_per_sess_attr_id, radius_quota_per_sess);
        attrib_count++;

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d for "
          "quota per-session; defaulting to '%s'", radius_vendor_name,
          radius_quota_per_sess_attr_id, radius_quota_per_sess);
      }
    }

    if (radius_quota_limit_type_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_quota_limit_type_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        char *limit_type;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);
        limit_type = pstrndup(radius_pool, (char *) attrib->data, attrib_len);
        radius_quota_limit_type = limit_type;

        pr_trace_msg(trace_channel, 2,
          "packet includes '%s' Vendor-Specific Attribute %d for quota limit "
          "type: '%s'", radius_vendor_name, radius_quota_limit_type_attr_id,
          radius_quota_limit_type);
        attrib_count++;

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d for "
          "quota limit type; defaulting to '%s'", radius_vendor_name,
          radius_quota_limit_type_attr_id, radius_quota_limit_type);
      }
    }

    if (radius_quota_bytes_in_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_quota_bytes_in_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        char *bytes_in;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);
        bytes_in = pstrndup(radius_pool, (char *) attrib->data, attrib_len);
        radius_quota_bytes_in = bytes_in;

        pr_trace_msg(trace_channel, 3,
          "packet includes '%s' Vendor-Specific Attribute %d for quota bytes "
          "in available: '%s'", radius_vendor_name,
          radius_quota_bytes_in_attr_id, radius_quota_bytes_in);
        attrib_count++;

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d for "
          "quota bytes in available; defaulting to '%s'", radius_vendor_name,
          radius_quota_bytes_in_attr_id, radius_quota_bytes_in);
      }
    }

    if (radius_quota_bytes_out_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_quota_bytes_out_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        char *bytes_out;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);
        bytes_out = pstrndup(radius_pool, (char *) attrib->data, attrib_len);
        radius_quota_bytes_out = bytes_out;

        pr_trace_msg(trace_channel, 3,
          "packet includes '%s' Vendor-Specific Attribute %d for quota bytes "
          "out available: '%s'", radius_vendor_name,
          radius_quota_bytes_out_attr_id, radius_quota_bytes_out);
        attrib_count++;

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d for "
          "quota bytes out available; defaulting to '%s'", radius_vendor_name,
          radius_quota_bytes_out_attr_id, radius_quota_bytes_out);
      }
    }

    if (radius_quota_bytes_xfer_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_quota_bytes_xfer_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        char *bytes_xfer;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);
        bytes_xfer = pstrndup(radius_pool, (char *) attrib->data, attrib_len);
        radius_quota_bytes_xfer = bytes_xfer;

        pr_trace_msg(trace_channel, 3,
          "packet includes '%s' Vendor-Specific Attribute %d for quota bytes "
          "xfer available: '%s'", radius_vendor_name,
          radius_quota_bytes_xfer_attr_id, radius_quota_bytes_xfer);
        attrib_count++;

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d for "
          "quota bytes xfer available; defaulting to '%s'", radius_vendor_name,
          radius_quota_bytes_xfer_attr_id, radius_quota_bytes_xfer);
      }
    }

    if (radius_quota_files_in_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_quota_files_in_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        char *files_in;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);
        files_in = pstrndup(radius_pool, (char *) attrib->data, attrib_len);
        radius_quota_files_in = files_in;

        pr_trace_msg(trace_channel, 3,
          "packet includes '%s' Vendor-Specific Attribute %d for quota files "
          "in available: '%s'", radius_vendor_name,
          radius_quota_files_in_attr_id, radius_quota_files_in);
        attrib_count++;

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d for "
          "quota files in available; defaulting to '%s'", radius_vendor_name,
          radius_quota_files_in_attr_id, radius_quota_files_in);
      }
    }

    if (radius_quota_files_out_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_quota_files_out_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        char *files_out;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);
        files_out = pstrndup(radius_pool, (char *) attrib->data, attrib_len);
        radius_quota_files_out = files_out;

        pr_trace_msg(trace_channel, 3,
          "packet includes '%s' Vendor-Specific Attribute %d for quota files "
          "out available: '%s'", radius_vendor_name,
          radius_quota_files_out_attr_id, radius_quota_files_out);
        attrib_count++;

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d for "
          "quota files out available; defaulting to '%s'", radius_vendor_name,
          radius_quota_files_out_attr_id, radius_quota_files_out);
      }
    }

    if (radius_quota_files_xfer_attr_id) {
      radius_attrib_t *attrib;

      attrib = radius_get_vendor_attrib(pkt, radius_quota_files_xfer_attr_id);
      if (attrib) {
        unsigned char attrib_len;
        char *files_xfer;

        attrib_len = RADIUS_VSA_ATTRIB_LEN(attrib);
        files_xfer = pstrndup(radius_pool, (char *) attrib->data, attrib_len);
        radius_quota_files_xfer = files_xfer;

        pr_trace_msg(trace_channel, 3,
          "packet includes '%s' Vendor-Specific Attribute %d for quota files "
          "xfer available: '%s'", radius_vendor_name,
          radius_quota_files_xfer_attr_id, radius_quota_files_xfer);
        attrib_count++;

      } else {
        pr_trace_msg(trace_channel, 6,
          "Access-Accept packet lacks '%s' Vendor-Specific Attribute %d for "
          "quota files xfer available; defaulting to '%s'", radius_vendor_name,
          radius_quota_files_xfer_attr_id, radius_quota_files_xfer);
      }
    }
  }

  return attrib_count;
}

static int radius_process_accept_packet(radius_packet_t *pkt,
    const unsigned char *secret, size_t secret_len) {
  int attrib_count = 0, res;;

  res = radius_process_standard_attribs(pkt, secret, secret_len);
  if (res < 0) {
    return -1;
  }

  attrib_count += res;

  /* Now, parse the packet for any server-supplied RadiusUserInfo attributes,
   * if RadiusUserInfo is indeed in effect.
   */

  if (radius_have_user_info == FALSE &&
      radius_have_group_info == FALSE &&
      radius_have_quota_info == FALSE) {
    /* Return now if there's no reason for doing extra work. */
    return attrib_count;
  }

  attrib_count += radius_process_user_info_attribs(pkt);
  attrib_count += radius_process_group_info_attribs(pkt);
  attrib_count += radius_process_quota_info_attribs(pkt);

  return attrib_count;
}

static int radius_process_reject_packet(radius_packet_t *pkt,
    const unsigned char *secret, size_t secret_len) {
  int attrib_count = 0;

  if (radius_verify_auth_mac(pkt, "Access-Reject", secret, secret_len) < 0) {
    return -1;
  }

  /* Handle any REPLY_MESSAGE attributes. */
  if (!(radius_opts & RADIUS_OPT_IGNORE_REPLY_MESSAGE_ATTR)) {
    radius_attrib_t *attrib = NULL;
    unsigned int pkt_len = 0;

    attrib = radius_get_next_attrib(pkt, RADIUS_REPLY_MESSAGE, &pkt_len,
      NULL);
    while (attrib != NULL) {
      unsigned char attrib_len;

      pr_signals_handle();

      attrib_len = RADIUS_ATTRIB_LEN(attrib);
      if (attrib_len > 0) {
        char *reply_msg = NULL;

        reply_msg = pstrndup(radius_pool, (char *) attrib->data, attrib_len);

        pr_trace_msg(trace_channel, 7,
          "found REPLY_MESSAGE attribute in Access-Reject message: '%s'",
          reply_msg);
        pr_response_add_err(R_DUP, "%s", reply_msg);
      }

      attrib_count++;

      if (pkt_len == 0) {
        break;
      }

      attrib = radius_get_next_attrib(pkt, RADIUS_REPLY_MESSAGE, &pkt_len,
        attrib);
    }
  }

  return attrib_count;
}

static void radius_process_group_info(config_rec *c) {
  char *param = NULL;
  unsigned char have_illegal_value = FALSE;
  unsigned int ngroups = 0, ngids = 0;
  char **groups = NULL;
  gid_t *gids = NULL;

  /* Parse out any configured attribute/defaults here. The stored strings will
   * already have been sanitized by the configuration handler, so I don't
   * need to worry about that here.
   */

  param = (char *) c->argv[0];
  if (RADIUS_IS_VAR(param) == TRUE) {
    radius_parse_var(param, &radius_prime_group_name_attr_id,
      &radius_prime_group_name);

  } else {
    radius_prime_group_name = param;
  }

  /* If the group name count is zero, then I know that the data will be
   * contained in a VSA.  Otherwise, the group names have already been parsed.
   */
  if (*((unsigned int *) c->argv[1]) == 0) {
    param = (char *) c->argv[2];

    radius_parse_var(param, &radius_addl_group_names_attr_id,
      &radius_addl_group_names_str);
  
    /* Now, parse the default value provided. */
    if (!radius_parse_groups_str(c->pool, radius_addl_group_names_str,
        &groups, &ngroups)) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "badly formatted RadiusGroupInfo default additional group names");
      have_illegal_value = TRUE;
    }

  } else {
    ngroups = *((unsigned int *) c->argv[1]);
    groups = (char **) c->argv[2];
  }

  if (*((unsigned int *) c->argv[3]) == 0) {
    param = (char *) c->argv[4];

    radius_parse_var(param, &radius_addl_group_ids_attr_id,
      &radius_addl_group_ids_str);

    /* Similarly, parse the default value provided. */
    if (!radius_parse_gids_str(c->pool, radius_addl_group_ids_str,
        &gids, &ngids)) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "badly formatted RadiusGroupInfo default additional group IDs");
      have_illegal_value = TRUE;
    }

  } else {
    ngids = *((unsigned int *) c->argv[3]);
    gids = (gid_t *) c->argv[4];
  }

  if (!have_illegal_value &&
      ngroups != ngids) {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "mismatched number of RadiusGroupInfo default additional group "
      "names (%u) and IDs (%u)", ngroups, ngids);
    have_illegal_value = TRUE;
  }

  if (!have_illegal_value) {
    radius_have_group_info = TRUE;
    radius_addl_group_count = ngroups;
    radius_addl_group_names = groups;
    radius_addl_group_ids = gids;

  } else {
    radius_have_group_info = FALSE;
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "error with RadiusGroupInfo parameters, ignoring them");
  }
}

static void radius_process_quota_info(config_rec *c) {
  char *param = NULL;
  unsigned char have_illegal_value = FALSE;

  /* Parse out any configured attribute/defaults here. The stored strings will
   * already have been sanitized by the configuration handler, so I don't
   * need to worry about that here.
   */

  param = (char *) c->argv[0];
  if (RADIUS_IS_VAR(param) == TRUE) {
    radius_parse_var(param, &radius_quota_per_sess_attr_id,
      &radius_quota_per_sess);

  } else {
    radius_quota_per_sess = param;

    if (strcasecmp(param, "false") != 0 &&
        strcasecmp(param, "true") != 0) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusQuotaInfo per-session value: '%s'", param);
      have_illegal_value = TRUE;

    } else {
      pr_trace_msg(trace_channel, 17,
        "found RadiusQuotaInfo per-session value: %s", param);
    }
  }

  param = (char *) c->argv[1];
  if (RADIUS_IS_VAR(param) == TRUE) {
    radius_parse_var(param, &radius_quota_limit_type_attr_id,
      &radius_quota_limit_type);

  } else {
    radius_quota_limit_type = param;

    if (strcasecmp(param, "hard") != 0 &&
        strcasecmp(param, "soft") != 0) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusQuotaInfo limit type value: '%s'", param);
      have_illegal_value = TRUE;

    } else {
      pr_trace_msg(trace_channel, 17,
        "found RadiusQuotaInfo limit type value: %s", param);
    }
  }

  param = (char *) c->argv[2];
  if (RADIUS_IS_VAR(param) == TRUE) {
    radius_parse_var(param, &radius_quota_bytes_in_attr_id,
      &radius_quota_bytes_in);

  } else {
    char *endp = NULL;

    if (strtod(param, &endp) < 0) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusQuotaInfo bytes in value: negative number");
      have_illegal_value = TRUE;
    }

    if (endp && *endp) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusQuotaInfo bytes in value: '%s' not a number", param);
      have_illegal_value = TRUE;

    } else {
      pr_trace_msg(trace_channel, 17,
        "found RadiusQuotaInfo bytes in value: %s", param);
    }

    radius_quota_bytes_in = param;
  }

  param = (char *) c->argv[3];
  if (RADIUS_IS_VAR(param) == TRUE) {
    radius_parse_var(param, &radius_quota_bytes_out_attr_id,
      &radius_quota_bytes_out);

  } else {
    char *endp = NULL;

    if (strtod(param, &endp) < 0) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusQuotaInfo bytes out value: negative number");
      have_illegal_value = TRUE;
    }

    if (endp && *endp) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusQuotaInfo bytes out value: '%s' not a number", param);
      have_illegal_value = TRUE;

    } else {
      pr_trace_msg(trace_channel, 17,
        "found RadiusQuotaInfo bytes out value: %s", param);
    }

    radius_quota_bytes_out = param;
  }

  param = (char *) c->argv[4];
  if (RADIUS_IS_VAR(param) == TRUE) {
    radius_parse_var(param, &radius_quota_bytes_xfer_attr_id,
      &radius_quota_bytes_xfer);

  } else {
    char *endp = NULL;

    if (strtod(param, &endp) < 0) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusQuotaInfo bytes xfer value: negative number");
      have_illegal_value = TRUE;
    }

    if (endp && *endp) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusQuotaInfo bytes xfer value: '%s' not a number", param);
      have_illegal_value = TRUE;

    } else {
      pr_trace_msg(trace_channel, 17,
        "found RadiusQuotaInfo bytes xfer value: %s", param);
    }

    radius_quota_bytes_xfer = param;
  }

  param = (char *) c->argv[5];
  if (RADIUS_IS_VAR(param) == TRUE) {
    radius_parse_var(param, &radius_quota_files_in_attr_id,
      &radius_quota_files_in);

  } else {
    char *endp = NULL;
    unsigned long res;

    res = strtoul(param, &endp, 10);
    if (endp && *endp) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusQuotaInfo files in value: '%s' not a number",
        param);
      have_illegal_value = TRUE;

    } else {
      pr_trace_msg(trace_channel, 17,
        "found RadiusQuotaInfo files in value: %lu", res);
    }

    radius_quota_files_in = param;
  }

  param = (char *) c->argv[6];
  if (RADIUS_IS_VAR(param) == TRUE) {
    radius_parse_var(param, &radius_quota_files_out_attr_id,
      &radius_quota_files_out);

  } else {
    char *endp = NULL;
    unsigned long res;

    res = strtoul(param, &endp, 10);
    if (endp && *endp) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusQuotaInfo files out value: '%s' not a number", param);
      have_illegal_value = TRUE;

    } else {
      pr_trace_msg(trace_channel, 17,
        "found RadiusQuotaInfo files out value: %lu", res);
    }

    radius_quota_files_out = param;
  }

  param = (char *) c->argv[7];
  if (RADIUS_IS_VAR(param) == TRUE) {
    radius_parse_var(param, &radius_quota_files_xfer_attr_id,
      &radius_quota_files_xfer);

  } else {
    char *endp = NULL;
    unsigned long res;

    res = strtoul(param, &endp, 10);
    if (endp && *endp) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusQuotaInfo files xfer value: '%s' not a number", param);
      have_illegal_value = TRUE;

    } else {
      pr_trace_msg(trace_channel, 17,
        "found RadiusQuotaInfo files xfer value: %lu", res);
    }

    radius_quota_files_xfer = param;
  }

  if (!have_illegal_value) {
    radius_have_quota_info = TRUE;

  } else {
   (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
     "error with RadiusQuotaInfo parameters, ignoring them");
  }
}

static void radius_process_user_info(config_rec *c) {
  char *param = NULL;
  unsigned char have_illegal_value = FALSE;

  /* radius_passwd.pw_name will be filled in later, after successful
   * authentication.  radius_passwd.pw_gecos will always be NULL, as there
   * is no practical need for this information.
   */

  radius_passwd.pw_passwd = NULL;
  radius_passwd.pw_gecos = NULL;

  /* Parse out any configured attribute/defaults here. The stored strings will
   * already have been sanitized by the configuration handler, so I don't
   * need to worry about that here.
   */

  /* Process the UID string. */
  param = (char *) c->argv[0];

  if (RADIUS_IS_VAR(param) == TRUE) {
    char *endp = NULL, *value = NULL;

    radius_parse_var(param, &radius_uid_attr_id, &value);
    radius_passwd.pw_uid = (uid_t) strtoul(value, &endp, 10);

    if (radius_passwd.pw_uid == (uid_t) -1) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusUserInfo default UID value: -1 not allowed");
      have_illegal_value = TRUE;
    }

    if (endp && *endp) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusUserInfo default UID value: '%s' not a number", value);
      have_illegal_value = TRUE;
    }

  } else {

    char *endp = NULL;
    radius_passwd.pw_uid = (uid_t) strtoul(param, &endp, 10);

    if (radius_passwd.pw_uid == (uid_t) -1) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusUserInfo UID value: -1 not allowed");
      have_illegal_value = TRUE;
    }

    if (endp && *endp) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusUserInfo UID value: '%s' not a number", param);
      have_illegal_value = TRUE;
    }
  }

  /* Process the GID string. */
  param = (char *) c->argv[1];

  if (RADIUS_IS_VAR(param) == TRUE) {
    char *endp = NULL, *value = NULL;

    radius_parse_var(param, &radius_gid_attr_id, &value);
    radius_passwd.pw_gid = (gid_t) strtoul(value, &endp, 10);

    if (radius_passwd.pw_gid == (gid_t) -1) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusUserInfo default GID value: -1 not allowed");
      have_illegal_value = TRUE;
    }

    if (endp && *endp) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusUserInfo default GID value: '%s' not a number", value);
      have_illegal_value = TRUE;
    }

  } else {

    char *endp = NULL;
    radius_passwd.pw_gid = (gid_t) strtoul(param, &endp, 10);

    if (radius_passwd.pw_gid == (gid_t) -1) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusUserInfo GID value: -1 not allowed");
      have_illegal_value = TRUE;
    }

    if (endp && *endp) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusUserInfo GID value: '%s' not a number", param);
      have_illegal_value = TRUE;
    }
  }

  /* Parse the home directory string. */
  param = (char *) c->argv[2];

  if (RADIUS_IS_VAR(param) == TRUE) {
    radius_parse_var(param, &radius_home_attr_id, &radius_passwd.pw_dir);

    if (*radius_passwd.pw_dir != '/') {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusUserInfo default home value: '%s' not an absolute path",
        radius_passwd.pw_dir);
      have_illegal_value = TRUE;
    }

  } else {

    /* Param already checked in this case. */
    radius_passwd.pw_dir = param;
  }

  /* Process the shell string. */
  param = (char *) c->argv[3];
  
  if (RADIUS_IS_VAR(param) == TRUE) {
    radius_parse_var(param, &radius_shell_attr_id, &radius_passwd.pw_shell);

    if (*radius_passwd.pw_shell != '/') {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "illegal RadiusUserInfo default shell value: '%s' not an absolute path",
        radius_passwd.pw_shell);
      have_illegal_value = TRUE;
    }

  } else {

    /* Param already checked in this case. */
    radius_passwd.pw_shell = param;
  }

  if (have_illegal_value == FALSE) {
    radius_have_user_info = TRUE;

  } else {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "error with RadiusUserInfo parameters, ignoring them");
  }
}

static void radius_reset(void) {
  /* Clear/reset user info */
  radius_have_user_info = FALSE;

  /* Clear/reset group info */
  radius_have_group_info = FALSE;
  radius_prime_group_name = NULL;
  radius_addl_group_count = 0;
  radius_addl_group_names = NULL;
  radius_addl_group_names_str = NULL;
  radius_addl_group_ids = NULL;
  radius_addl_group_ids_str = NULL;

  /* Clear/reset quota info */
  radius_have_quota_info = FALSE;
  radius_quota_per_sess = NULL;
  radius_quota_limit_type = NULL;
  radius_quota_bytes_in = NULL;
  radius_quota_bytes_out = NULL;
  radius_quota_bytes_xfer = NULL;
  radius_quota_files_in = NULL;
  radius_quota_files_out = NULL;

  /* Clear/reset quota info */
  radius_have_quota_info = FALSE;
  radius_quota_per_sess = NULL;
  radius_quota_limit_type = NULL;
  radius_quota_bytes_in = NULL;
  radius_quota_bytes_out = NULL;
  radius_quota_bytes_xfer = NULL;
  radius_quota_files_in = NULL;
  radius_quota_files_out = NULL;
  radius_quota_files_xfer = NULL;

  /* Clear/reset other info */
  radius_have_other_info = FALSE;
}

static unsigned char *radius_xor(unsigned char *p, unsigned char *q,
    size_t len) {
  register size_t i = 0;
  unsigned char *tmp = p;

  for (i = 0; i < len; i++) {
    *(p++) ^= *(q++);
  }

  return tmp;
}

#if defined(PR_USE_OPENSSL)
# include <openssl/err.h>
# include <openssl/md5.h>
# include <openssl/hmac.h>

#else
/* Built-in MD5 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991.
 *  All rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD5 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 */

/* MD5 context */
typedef struct {

  /* state (ABCD) */
  uint32_t state[4];

  /* number of bits, module 2^64 (LSB first) */
  uint32_t count[2];

  /* input buffer */
  unsigned char buffer[64];
} MD5_CTX;

static void MD5_Init(MD5_CTX *);
static void MD5_Update(MD5_CTX *, unsigned char *, size_t);
static void MD5_Final(unsigned char *, MD5_CTX *);

/* Note: these MD5 routines are taken from RFC 1321 */

#ifdef HAVE_MEMCPY
# define MD5_memcpy(a, b, c) memcpy((a), (b), (c))
# define MD5_memset(a, b, c) memset((a), (b), (c))
#endif

/* Constants for MD5Transform routine.
 */

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void MD5Transform(uint32_t *, unsigned char[64]);
static void Encode(unsigned char *, uint32_t *, unsigned int);
static void Decode(uint32_t *, unsigned char *, unsigned int);

#ifndef HAVE_MEMCPY
static void MD5_memcpy(unsigned char *, unsigned char *, unsigned int);
static void MD5_memset(unsigned char *, int, unsigned int);
#endif

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 * Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
static void MD5_Init(MD5_CTX *context) {
  context->count[0] = context->count[1] = 0;

  /* Load magic initialization constants.
   */
  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
 * operation, processing another message block, and updating the
 * context.
 */
static void MD5_Update(MD5_CTX *context, unsigned char *input,
    size_t inputLen) {
  unsigned int i, index, partLen;

  /* Compute number of bytes mod 64 */
  index = (unsigned int)((context->count[0] >> 3) & 0x3F);

  /* Update number of bits */
  if ((context->count[0] += ((uint32_t)inputLen << 3))
       < ((uint32_t)inputLen << 3))
    context->count[1]++;
  context->count[1] += ((uint32_t)inputLen >> 29);

  partLen = 64 - index;

  /* Transform as many times as possible */
  if (inputLen >= partLen) {
    MD5_memcpy((unsigned char *) &context->buffer[index],
      (unsigned char *) input, partLen);
    MD5Transform(context->state, context->buffer);

    for (i = partLen; i + 63 < inputLen; i += 64)
      MD5Transform(context->state, &input[i]);

    index = 0;

  } else
    i = 0;

  /* Buffer remaining input */
  MD5_memcpy((unsigned char *) &context->buffer[index],
    (unsigned char *) &input[i], inputLen-i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
 * the message digest and zeroizing the context.
 */
static void MD5_Final(unsigned char digest[16], MD5_CTX *context) {
  unsigned char bits[8];
  unsigned int index;
  size_t padLen;

  /* Save number of bits */
  Encode (bits, context->count, 8);

  /* Pad out to 56 mod 64.
   */
  index = (unsigned int) ((context->count[0] >> 3) & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  MD5_Update(context, PADDING, padLen);

  /* Append length (before padding) */
  MD5_Update(context, bits, 8);

  /* Store state in digest */
  Encode(digest, context->state, 16);

  /* Zeroize sensitive information.
   */
  MD5_memset((unsigned char *) context, 0, sizeof(*context));
}

/* MD5 basic transformation. Transforms state based on block.
 */
static void MD5Transform(uint32_t state[4], unsigned char block[64]) {
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

  Decode(x, block, 64);

  /* Round 1 */
  FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
  FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
  FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
  FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
  FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
  FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
  FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
  FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
  FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
  FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
  FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
  FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
  FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
  FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
  FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
  FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

 /* Round 2 */
  GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
  GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
  GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
  GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
  GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
  GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
  GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
  GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
  GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
  GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
  GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */

  GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
  GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
  GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
  GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
  GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

  /* Round 3 */
  HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
  HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
  HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
  HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
  HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
  HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
  HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
  HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
  HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
  HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
  HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
  HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
  HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
  HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
  HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
  HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

  /* Round 4 */
  II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
  II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
  II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
  II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
  II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
  II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
  II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
  II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
  II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
  II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
  II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
  II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
  II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
  II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
  II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
  II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;

  /* Zeroize sensitive information.
   */
  MD5_memset((unsigned char *) x, 0, sizeof(x));
}

/* Encodes input (unsigned long) into output (unsigned char). Assumes len is
 * a multiple of 4.
 */
static void Encode(unsigned char *output, uint32_t *input, unsigned int len) {
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4) {
    output[j] = (unsigned char)(input[i] & 0xff);
    output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
    output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
    output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
  }
}

/* Decodes input (unsigned char) into output (unsigned long). Assumes len is
 * a multiple of 4.
 */
static void Decode(uint32_t *output, unsigned char *input, unsigned int len) {
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4)
    output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j+1]) << 8) |
    (((uint32_t)input[j+2]) << 16) | (((uint32_t)input[j+3]) << 24);
}

#ifndef HAVE_MEMCPY
/* Note: Replace "for loop" with standard memcpy if possible. */
static void MD5_memcpy(unsigned char *output, unsigned char *input,
    unsigned int len) {
  unsigned int i;

  for (i = 0; i < len; i++) {
    output[i] = input[i];
  }
}

/* Note: Replace "for loop" with standard memset if possible. */
static void MD5_memset(unsigned char *output, int value, unsigned int len) {
  unsigned int i;

  for (i = 0; i < len; i++) {
    ((char *) output)[i] = (char) value;
  }
}
#endif
#endif /* !PR_USE_OPENSSL */

static int radius_openlog(void) {
  int res = 0, xerrno = 0;
  config_rec *c;
  const char *path;

  c = find_config(main_server->conf, CONF_PARAM, "RadiusLog", FALSE);
  if (c == NULL) {
    return 0;
  }

  path = c->argv[0];
  if (strcasecmp(path, "none") == 0) {
    return 0;
  }

  pr_signals_block();
  PRIVS_ROOT
  res = pr_log_openfile(path, &radius_logfd, PR_LOG_SYSTEM_MODE);
  xerrno = errno;
  PRIVS_RELINQUISH
  pr_signals_unblock();

  errno = xerrno;
  return res;
}

/* RADIUS routines */

/* Add an attribute to a RADIUS packet.  Returns the added attribute. */
static radius_attrib_t *radius_add_attrib(radius_packet_t *packet,
    unsigned char type, const unsigned char *data, size_t datalen) {
  radius_attrib_t *attrib = NULL;

  attrib = (radius_attrib_t *) ((unsigned char *) packet +
    ntohs(packet->length));
  attrib->type = type;

  /* Total size of the attribute.  The "+ 2" takes into account the size
   * of the attribute identifier.
   */
  attrib->length = datalen + 2;

  /* Increment the size of the given packet. */
  packet->length = htons(ntohs(packet->length) + attrib->length);

  memcpy(attrib->data, data, datalen);

  return attrib;
}

/* Add a RADIUS message authenticator attribute to the packet. */
static void radius_set_auth_mac(radius_packet_t *pkt,
   const unsigned char *secret, size_t secret_len) {
#ifdef PR_USE_OPENSSL
  const EVP_MD *md;
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_len = 0, mac_len = 16;
  radius_attrib_t *attrib = NULL;

  /* First, add the Message-Authenticator attribute, with a value of all zeroes,
   * per RFC 3579, Section 3.2.
   */
  memset(digest, '\0', sizeof(digest));
  attrib = radius_add_attrib(pkt, RADIUS_MESSAGE_AUTHENTICATOR,
    (const unsigned char *) digest, mac_len);

  /* Now, calculate the HMAC-MD5 of the packet. */

  md = EVP_md5();
  if (HMAC(md, secret, secret_len, (unsigned char *) pkt, ntohs(pkt->length),
      digest, &digest_len) == NULL) {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "error generating Message-Authenticator: %s",
      ERR_error_string(ERR_get_error(), NULL));

  } else {
    /* Finally, overwrite the all-zeroes Message-Authenticator value with our
     * calculated value.
     */
    memcpy(attrib->data, digest, mac_len);
  }
#endif /* PR_USE_OPENSSL */
}

static int radius_verify_auth_mac(radius_packet_t *pkt, const char *pkt_type,
    const unsigned char *secret, size_t secret_len) {
  int res = 0;
  radius_attrib_t *attrib = NULL;

  /* Handle any Message-Authenticator attribute, per RFC 2869, Section 5.14. */
  attrib = radius_get_attrib(pkt, RADIUS_MESSAGE_AUTHENTICATOR);
  if (attrib != NULL) {
    unsigned char attrib_len;
    unsigned int expected_len = 16;

    attrib_len = RADIUS_ATTRIB_LEN(attrib);
    if (attrib_len != expected_len) {
#ifdef PR_USE_OPENSSL
      const EVP_MD *md;
      unsigned char digest[EVP_MAX_MD_SIZE], replied[EVP_MAX_MD_SIZE];
      unsigned int digest_len = 0;

      /* First, make a copy of the packet's Message-Authenticator value, for
       * comparison with what we will calculate.
       */
      memset(replied, '\0', sizeof(replied));
      memcpy(replied, attrib->data, attrib_len);

      /* Next, zero out the value so that we can calculate it ourselves. */
      memset(attrib->data, '\0', attrib_len);

      memset(digest, '\0', sizeof(digest));
      md = EVP_md5();
      if (HMAC(md, secret, secret_len, (unsigned char *) pkt,
          ntohs(pkt->length), digest, &digest_len) == NULL) {
        (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
          "error generating Message-Authenticator: %s",
          ERR_error_string(ERR_get_error(), NULL));
        return 0;
      }

      if (memcmp(replied, digest, expected_len) != 0) {
        (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
          "packet Message-Authenticator verification failed: mismatched MACs");
        errno = EINVAL;
        return -1;
      }

      res = 0;

#endif /* PR_USE_OPENSSL */
    } else {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "%s packet has incorrect Message-Authenticator attribute length "
        "(%u != %u), rejecting", pkt_type, attrib_len, expected_len);
      errno = EINVAL;
      return -1;
    }

  } else {
    pr_trace_msg(trace_channel, 6,
      "%s packet lacks Message-Authenticator attribute (%d)", pkt_type,
      RADIUS_MESSAGE_AUTHENTICATOR);

    if (radius_opts & RADIUS_OPT_REQUIRE_MAC) {
      errno = EPERM;
      return -1;
    }
  }

  return res;
}

/* Add a RADIUS password attribute to the packet. */
static void radius_add_passwd(radius_packet_t *packet, unsigned char type,
    const unsigned char *passwd, unsigned char *secret, size_t secret_len) {
  MD5_CTX ctx, secret_ctx;
  radius_attrib_t *attrib = NULL;
  unsigned char calculated[RADIUS_VECTOR_LEN];
  unsigned char pwhash[PR_TUNABLE_BUFFER_SIZE];
  unsigned char *digest = NULL;
  register unsigned int i = 0;
  size_t pwlen;

  pwlen = strlen((const char *) passwd);

  if (pwlen == 0) {
    pwlen = RADIUS_PASSWD_LEN;

  } if ((pwlen & (RADIUS_PASSWD_LEN - 1)) != 0) {

    /* Round up the length. */
    pwlen += (RADIUS_PASSWD_LEN - 1);

    /* Truncate the length, as necessary. */
    pwlen &= ~(RADIUS_PASSWD_LEN - 1);
  }

  /* Clear the buffers. */
  memset(pwhash, '\0', sizeof(pwhash));
  memcpy(pwhash, passwd, pwlen);

  /* Find the password attribute. */
  attrib = radius_get_attrib(packet, RADIUS_PASSWORD);

  if (type == RADIUS_PASSWORD) {
    digest = packet->digest;

  } else {
    digest = attrib->data;
  }

  /* Encrypt the password.  Password: c[0] = p[0] ^ MD5(secret + digest) */
  MD5_Init(&secret_ctx);
  MD5_Update(&secret_ctx, secret, secret_len);

  /* Save this hash for later. */
  ctx = secret_ctx;

  MD5_Update(&ctx, digest, RADIUS_VECTOR_LEN);

  /* Set the calculated digest. */
  MD5_Final(calculated, &ctx);

  /* XOR the results. */
  radius_xor(pwhash, calculated, RADIUS_PASSWD_LEN);
  
  /* For each step through: e[i] = p[i] ^ MD5(secret + e[i-1]) */
  for (i = 1; i < (pwlen >> 4); i++) {

    /* Start with the old value of the MD5 sum. */
    ctx = secret_ctx;

    MD5_Update(&ctx, &pwhash[(i-1) * RADIUS_PASSWD_LEN], RADIUS_PASSWD_LEN);

    /* Set the calculated digest. */
    MD5_Final(calculated, &ctx);

    /* XOR the results. */
    radius_xor(&pwhash[i * RADIUS_PASSWD_LEN], calculated, RADIUS_PASSWD_LEN);
  }

  if (type == RADIUS_OLD_PASSWORD) {
    attrib = radius_get_attrib(packet, RADIUS_OLD_PASSWORD);
  }
 
  if (attrib == NULL) {
    radius_add_attrib(packet, type, pwhash, pwlen);

  } else {
    /* Overwrite the packet data. */
    memcpy(attrib->data, pwhash, pwlen);
  }

  pr_memscrub(pwhash, sizeof(pwhash));
}

static void radius_set_acct_digest(radius_packet_t *packet,
    const unsigned char *secret, size_t secret_len) {
  MD5_CTX ctx;

  /* Clear the current digest (not needed yet for accounting packets) */
  memset(packet->digest, 0, RADIUS_VECTOR_LEN);

  MD5_Init(&ctx);

  /* Add the packet data to the mix. */
  MD5_Update(&ctx, (unsigned char *) packet, ntohs(packet->length));

  /* Add the secret to the mix. */
  MD5_Update(&ctx, secret, secret_len);

  /* Set the calculated digest in place in the packet. */
  MD5_Final(packet->digest, &ctx);
}

/* Obtain a random digest. */
static void radius_get_rnd_digest(radius_packet_t *packet) {
  MD5_CTX ctx;
  struct timeval tv;
  struct timezone tz;

  /* Use the time of day with the best resolution the system can give us,
   * often close to microsecond accuracy.
   */
  gettimeofday(&tv, &tz);

  /* Add in some (possibly) hard to guess information. */      
  tv.tv_sec ^= getpid() * getppid();
      
  /* Use MD5 to obtain (hopefully) cryptographically strong pseudo-random
   * numbers
   */
  MD5_Init(&ctx);
  MD5_Update(&ctx, (unsigned char *) &tv, sizeof(tv));
  MD5_Update(&ctx, (unsigned char *) &tz, sizeof(tz));

  /* Set the calculated digest in the space provided. */
  MD5_Final(packet->digest, &ctx);
}

/* RADIUS packet manipulation functions.
 */

/* For iterating through all of the attributes in a packet, callers can
 * provide a pointer to the previous attribute returned, or NULL.
 */
static radius_attrib_t *radius_get_next_attrib(radius_packet_t *packet,
    unsigned char attrib_type, unsigned int *packet_len,
    radius_attrib_t *prev_attrib) {
  radius_attrib_t *attrib = NULL;
  unsigned int len;

  if (packet_len == NULL) {
    len = ntohs(packet->length) - RADIUS_HEADER_LEN;

  } else {
    len = *packet_len;
  }

  if (prev_attrib == NULL) {
    attrib = (radius_attrib_t *) &packet->data;

  } else {
    attrib = prev_attrib;
  }

  while (attrib->type != attrib_type) {
    if (attrib->length == 0 ||
        (len -= attrib->length) <= 0) {

      /* Requested attribute not found. */
      if (packet_len != NULL) {
        *packet_len = 0;
      }

      return NULL;
    }

    /* Examine the next attribute in the packet. */
    attrib = (radius_attrib_t *) ((char *) attrib + attrib->length);
  }

  if (packet_len != NULL) {
    *packet_len = len;
  }

  return attrib;
}

static radius_attrib_t *radius_get_attrib(radius_packet_t *packet,
    unsigned char attrib_type) {
  return radius_get_next_attrib(packet, attrib_type, NULL, NULL);
}

/* Find a Vendor-Specific Attribute (VSA) in a RADIUS packet.  Note that
 * the packet length is always kept in network byte order.
 */
static radius_attrib_t *radius_get_vendor_attrib(radius_packet_t *packet,
    unsigned char type) {
  radius_attrib_t *attrib = (radius_attrib_t *) &packet->data;
  int len = ntohs(packet->length) - RADIUS_HEADER_LEN;

  while (attrib) {
    unsigned int vendor_id = 0;

    pr_signals_handle();

    if (attrib->length == 0) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "packet includes invalid length (%u) for attribute type %u, rejecting",
        attrib->length, attrib->type);
      return NULL;
    }

    if (attrib->type != RADIUS_VENDOR_SPECIFIC) {
      len -= attrib->length;
      attrib = (radius_attrib_t *) ((char *) attrib + attrib->length);
      continue;
    }

    /* The first four octets (bytes) of data will contain the Vendor-Id. */
    if (attrib->length >= 4) {
      memcpy(&vendor_id, attrib->data, 4);
      vendor_id = ntohl(vendor_id);
    }

    if (vendor_id != radius_vendor_id) {
      len -= attrib->length;
      attrib = (radius_attrib_t *) ((char *) attrib + attrib->length);
      continue;
    }

    /* Parse the data value for this attribute into a VSA structure. */
    if (attrib->length > 4) {
      radius_attrib_t *vsa = NULL;

      vsa = (radius_attrib_t *) ((char *) attrib->data + sizeof(int));

      /* Does this VSA have the type requested? */
      if (vsa->type != type) {
        len -= attrib->length;
        attrib = (radius_attrib_t *) ((char *) attrib + attrib->length);
        continue;
      }

      return vsa;
    }
  }

  return NULL;
}

/* Build a RADIUS packet, initializing some of the header and adding
 * common attributes.
 */
static void radius_build_packet(radius_packet_t *packet,
    const unsigned char *user, const unsigned char *passwd,
    unsigned char *secret, size_t secret_len) {
  unsigned int nas_port_type = htonl(RADIUS_NAS_PORT_TYPE_VIRTUAL);
  int nas_port = htonl(main_server->ServerPort);
  char *caller_id = NULL;
  const char *nas_identifier = NULL;
  size_t userlen;

  /* Set the packet length. */
  packet->length = htons(RADIUS_HEADER_LEN);

  /* Obtain a random digest. */
  radius_get_rnd_digest(packet);

  /* Set the ID for the packet. */
  packet->id = packet->digest[0];
 
  /* Add the user attribute. */ 
  userlen = strlen((const char *) user);
  radius_add_attrib(packet, RADIUS_USER_NAME, user, userlen);

  /* Add the password attribute, if given. */
  if (passwd) {
    radius_add_passwd(packet, RADIUS_PASSWORD, passwd, secret, secret_len);

  } else if (packet->code != RADIUS_ACCT_REQUEST) {
    /* Add a NULL password if necessary. */
    radius_add_passwd(packet, RADIUS_PASSWORD, (const unsigned char *) "",
      secret, 1);
  }

  /* Add a NAS identifier attribute of the service name, e.g. 'ftp'. */

  nas_identifier = pr_session_get_protocol(0);
  if (radius_nas_identifier_config != NULL) {
    nas_identifier = radius_nas_identifier_config;
  }

  radius_add_attrib(packet, RADIUS_NAS_IDENTIFIER,
    (const unsigned char *) nas_identifier,
    strlen((const char *) nas_identifier));

#ifdef PR_USE_IPV6
  if (pr_netaddr_use_ipv6()) {
    const pr_netaddr_t *local_addr;
    int family;

    local_addr = pr_netaddr_get_sess_local_addr();
    family = pr_netaddr_get_family(local_addr);

    switch (family) {
      case AF_INET: {
        struct in_addr *inaddr;

        inaddr = pr_netaddr_get_inaddr(local_addr);

        /* Add a NAS-IP-Address attribute. */
        radius_add_attrib(packet, RADIUS_NAS_IP_ADDRESS,
          (unsigned char *) &(inaddr->s_addr), sizeof(inaddr->s_addr));
        break;
      }

      case AF_INET6: {
        if (pr_netaddr_is_v4mappedv6(local_addr)) {
          pr_netaddr_t *v4_addr;

          /* Note: in the future, switch to using a per-packet pool. */
          v4_addr = pr_netaddr_v6tov4(radius_pool, local_addr);
          if (v4_addr != NULL) {
            struct in_addr *inaddr;

            inaddr = pr_netaddr_get_inaddr(v4_addr);

            /* Add a NAS-IP-Address attribute. */
            radius_add_attrib(packet, RADIUS_NAS_IP_ADDRESS,
              (unsigned char *) &(inaddr->s_addr), sizeof(inaddr->s_addr));

          } else {
            (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
              "error converting '%s' to IPv4 address: %s",
              pr_netaddr_get_ipstr(local_addr), strerror(errno));
          }

        } else {
          struct in6_addr *inaddr;
          uint32_t ipv6_addr[4];

          inaddr = pr_netaddr_get_inaddr(pr_netaddr_get_sess_local_addr());

          /* Ideally we would use the inaddr->s6_addr32 to get to the 128-bit
           * IPv6 address.  But `s6_addr32' turns out to be a macro that is not
           * available on all systems (FreeBSD, for example, does not provide
           * this macro unless you're building its kernel).
           *
           * As a workaround, try using the (hopefully) more portable s6_addr
           * macro.
           */
          memcpy(ipv6_addr, inaddr->s6_addr, sizeof(ipv6_addr));

          /* Add a NAS-IPv6-Address attribute. */
          radius_add_attrib(packet, RADIUS_NAS_IPV6_ADDRESS,
            (unsigned char *) ipv6_addr, sizeof(ipv6_addr));
        }

        break;
      }
    }

  } else {
#else
  if (TRUE) {
#endif /* PR_USE_IPV6 */
    struct in_addr *inaddr;

    inaddr = pr_netaddr_get_inaddr(pr_netaddr_get_sess_local_addr());

    /* Add a NAS-IP-Address attribute. */
    radius_add_attrib(packet, RADIUS_NAS_IP_ADDRESS,
      (unsigned char *) &(inaddr->s_addr), sizeof(inaddr->s_addr));
  }

  /* Add a NAS port attribute. */
  radius_add_attrib(packet, RADIUS_NAS_PORT, (unsigned char *) &nas_port,
    sizeof(int));

  /* Add a NAS port type attribute. */ 
  radius_add_attrib(packet, RADIUS_NAS_PORT_TYPE,
    (unsigned char *) &nas_port_type, sizeof(int));

  /* Add the calling station ID attribute (this is the IP of the connecting
   * client).
   */
  caller_id = (char *) pr_netaddr_get_ipstr(pr_netaddr_get_sess_remote_addr()); 

  radius_add_attrib(packet, RADIUS_CALLING_STATION_ID,
    (const unsigned char *) caller_id, strlen(caller_id));
}

static radius_server_t *radius_make_server(pool *parent_pool) {
  pool *server_pool = NULL;
  radius_server_t *server = NULL;

  /* sanity check */
  if (!parent_pool)
    return NULL;

  /* allocate a subpool for the new rec */
  server_pool = make_sub_pool(parent_pool);

  /* allocate the rec from the subpool */
  server = (radius_server_t *) pcalloc(server_pool,
    sizeof(radius_server_t));

  /* set the members to sane default values */
  server->pool = server_pool;
  server->addr = NULL;
  server->port = RADIUS_AUTH_PORT;
  server->secret = NULL;
  server->secret_len = 0;
  server->timeout = DEFAULT_RADIUS_TIMEOUT;
  server->next = NULL;

  return server; 
}

static int radius_open_socket(void) {
  int sockfd = -1;
  struct sockaddr_in *radius_sockaddr_in = NULL;
  unsigned short local_port = 0;

  /* Obtain a socket descriptor. */
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "notice: unable to open socket for communication: %s",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* Set the members appropriately to bind to the descriptor. */
  memset((void *) &radius_local_sock, 0, sizeof(radius_local_sock));
  radius_sockaddr_in = (struct sockaddr_in *) &radius_local_sock;
  radius_sockaddr_in->sin_family = AF_INET;
  radius_sockaddr_in->sin_addr.s_addr = INADDR_ANY;

  /*  Use our process ID as a local port for RADIUS.
   */
  local_port = (getpid() & 0x7fff) + 1024;
  do {
    pr_signals_handle();

    local_port++;
    radius_sockaddr_in->sin_port = htons(local_port);

  } while ((bind(sockfd, &radius_local_sock, sizeof(radius_local_sock)) < 0) &&
    (local_port < USHRT_MAX));

  if (local_port >= USHRT_MAX) {
    (void) close(sockfd);
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "notice: unable to bind to socket: no open local ports");
    errno = EPERM;
    return -1;
  }

  /* Done */
  return sockfd;
}

static radius_packet_t *radius_recv_packet(int sockfd, unsigned int timeout) {
  static unsigned char recvbuf[RADIUS_PACKET_LEN];
  radius_packet_t *packet = NULL;
  int res = 0, recvlen = -1;
  socklen_t sockaddrlen = sizeof(struct sockaddr);
  struct timeval tv;
  fd_set rset;

  /* receive the response, waiting as necessary */
  memset(recvbuf, '\0', sizeof(recvbuf));

  tv.tv_sec = timeout;
  tv.tv_usec = 0;

  FD_ZERO(&rset);
  FD_SET(sockfd, &rset);

  res = select(sockfd + 1, &rset, NULL, NULL, &tv);
  if (res == 0) {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "server failed to respond in %u seconds", timeout);
    return NULL;

  } else if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "error: unable to receive response: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  recvlen = recvfrom(sockfd, (char *) recvbuf, RADIUS_PACKET_LEN, 0,
    &radius_remote_sock, &sockaddrlen);
  if (recvlen < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "error reading packet: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  packet = (radius_packet_t *) recvbuf;

  /* Make sure the packet is of valid length. */
  if (ntohs(packet->length) != recvlen ||
      ntohs(packet->length) > RADIUS_PACKET_LEN) {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "received corrupted packet");
    return NULL;
  }

  return packet;
}

static int radius_send_packet(int sockfd, radius_packet_t *packet,
    radius_server_t *server) {
  int res;
  struct sockaddr_in *radius_sockaddr_in =
    (struct sockaddr_in *) &radius_remote_sock;

  /* Set the members appropriately to send to the descriptor. */
  memset((void *) &radius_remote_sock, '\0', sizeof(radius_remote_sock));
  radius_sockaddr_in->sin_family = AF_INET;
  radius_sockaddr_in->sin_addr.s_addr = pr_netaddr_get_addrno(server->addr);
  radius_sockaddr_in->sin_port = htons(server->port);

  res = sendto(sockfd, (char *) packet, ntohs(packet->length), 0,
    &radius_remote_sock, sizeof(struct sockaddr_in));
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "error: unable to send packet: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
    "sending packet to %s:%u", inet_ntoa(radius_sockaddr_in->sin_addr),
    ntohs(radius_sockaddr_in->sin_port));

  return 0;
}

static int radius_start_accting(void) {
  int sockfd = -1, acct_status = 0, acct_authentic = 0, now = 0, pid_len = 0;
  radius_packet_t *request = NULL, *response = NULL;
  radius_server_t *acct_server = NULL;
  unsigned char recvd_response = FALSE, *authenticated = NULL;
  char pid_str[16];

  /* Check to see if RADIUS accounting should be done. */
  if (radius_engine == FALSE ||
      radius_acct_server == NULL) {
    return 0;
  }

  /* Only do accounting for authenticated users. */
  authenticated = get_param_ptr(main_server->conf, "authenticated", FALSE);
  if (authenticated == NULL ||
      *authenticated == FALSE) {
    return 0;
  }

  /* Open a RADIUS socket */
  sockfd = radius_open_socket();
  if (sockfd < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "socket open failed: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* Allocate a packet. */
  request = (radius_packet_t *) pcalloc(radius_pool, sizeof(radius_packet_t));

  now = htonl(time(NULL));

  memset(pid_str, '\0', sizeof(pid_str));
  pid_len = pr_snprintf(pid_str, sizeof(pid_str), "%08u",
    (unsigned int) session.pid);

  /* Loop through the list of servers, trying each one until the packet is
   * successfully sent.
   */
  acct_server = radius_acct_server;

  while (acct_server) {
    pr_signals_handle();

    /* Clear the packet. */
    memset(request, '\0', sizeof(radius_packet_t));

    /* Build the packet. */
    request->code = RADIUS_ACCT_REQUEST;
    radius_build_packet(request,
      radius_realm ?
        (const unsigned char *) pstrcat(radius_pool, session.user,
          radius_realm, NULL) :
        (const unsigned char *) session.user, NULL, acct_server->secret,
        acct_server->secret_len);

    radius_last_acct_pkt_id = request->id;

    /* Add accounting attributes. */
    acct_status = htonl(RADIUS_ACCT_STATUS_START);
    radius_add_attrib(request, RADIUS_ACCT_STATUS_TYPE,
      (unsigned char *) &acct_status, sizeof(int));

    radius_add_attrib(request, RADIUS_ACCT_SESSION_ID,
      (const unsigned char *) pid_str, pid_len);

    acct_authentic = htonl(RADIUS_AUTH_LOCAL);
    radius_add_attrib(request, RADIUS_ACCT_AUTHENTIC,
      (unsigned char *) &acct_authentic, sizeof(int));

    radius_add_attrib(request, RADIUS_ACCT_EVENT_TS, (unsigned char *) &now,
      sizeof(int));

    if (radius_acct_user != NULL) {
      /* See RFC 2865, Section 5.1. */
      radius_add_attrib(request, RADIUS_USER_NAME,
        (const unsigned char *) radius_acct_user, radius_acct_userlen);
    }

    if (radius_acct_class != NULL) {
      radius_add_attrib(request, RADIUS_CLASS,
        (const unsigned char *) radius_acct_class, radius_acct_classlen);
    }

    /* Calculate the signature. */
    radius_set_acct_digest(request, acct_server->secret,
      acct_server->secret_len);

    /* Send the request. */
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "sending start acct request packet");
    if (radius_send_packet(sockfd, request, acct_server) < 0) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "packet send failed");
      acct_server = acct_server->next;
      continue;
    }

    /* Receive the response. */
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "receiving acct response packet");
    response = radius_recv_packet(sockfd, acct_server->timeout);
    if (response == NULL) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "packet receive failed");
      acct_server = acct_server->next;
      continue;
    }

    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "packet receive succeeded");
    recvd_response = TRUE;
    break;
  }

  /* Close the socket. */
  (void) close(sockfd);

  if (recvd_response) {

    /* Verify the response. */
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "verifying packet");
    if (radius_verify_packet(request, response, acct_server->secret,
        acct_server->secret_len) < 0) {
      return -1;
    }

    /* Handle the response. */
    switch (response->code) {
      case RADIUS_ACCT_RESPONSE:
        (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
          "accounting started for user '%s'", session.user);
        return 0;

      default:
        (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
          "notice: server returned unknown response code: %02x",
          response->code);
        return -1;
    }

  } else {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "error: no acct servers responded");
  }

  /* Default return value. */
  return -1;
}

/* Maps the ProFTPD disconnect reason code to the RADIUS Acct-Terminate-Cause
 * attribute values.
 */
static unsigned int radius_get_terminate_cause(void) {
  unsigned int cause = RADIUS_ACCT_TERMINATE_CAUSE_SERVICE_UNAVAIL;

  switch (session.disconnect_reason) {
    case PR_SESS_DISCONNECT_CLIENT_QUIT:
      cause = RADIUS_ACCT_TERMINATE_CAUSE_USER_REQUEST;
      break;

    case PR_SESS_DISCONNECT_CLIENT_EOF:
      cause = RADIUS_ACCT_TERMINATE_CAUSE_LOST_SERVICE;
      break;

    case PR_SESS_DISCONNECT_SIGNAL:
      cause = RADIUS_ACCT_TERMINATE_CAUSE_ADMIN_RESET;
      break;

    case PR_SESS_DISCONNECT_SERVER_SHUTDOWN:
      cause = RADIUS_ACCT_TERMINATE_CAUSE_ADMIN_REBOOT;
      break;

    case PR_SESS_DISCONNECT_TIMEOUT: {
      const char *details = NULL;

      pr_session_get_disconnect_reason(&details);
      if (details != NULL) {
        if (strcasecmp(details, "TimeoutIdle") == 0) {
          cause = RADIUS_ACCT_TERMINATE_CAUSE_IDLE_TIMEOUT;

        } else if (strcasecmp(details, "TimeoutSession") == 0) {
          cause = RADIUS_ACCT_TERMINATE_CAUSE_SESSION_TIMEOUT;
        }
      }

      break;
    }
  }

  return cause;
}

static int radius_stop_accting(void) {
  int sockfd = -1, acct_status = 0, acct_authentic = 0, event_ts = 0,
    now = 0, pid_len = 0, session_duration = 0;
  unsigned int terminate_cause = 0;
  radius_packet_t *request = NULL, *response = NULL;
  radius_server_t *acct_server = NULL;
  unsigned char recvd_response = FALSE, *authenticated = NULL;
  off_t radius_session_bytes_in = 0;
  off_t radius_session_bytes_out = 0;
  char pid_str[16];

  /* Check to see if RADIUS accounting should be done. */
  if (radius_engine == FALSE ||
      radius_acct_server == NULL) {
    return 0;
  }

  /* Only do accounting for authenticated users. */
  authenticated = get_param_ptr(main_server->conf, "authenticated", FALSE);
  if (authenticated == NULL ||
      *authenticated == FALSE) {
    return 0;
  }

  /* Open a RADIUS socket */
  sockfd = radius_open_socket();
  if (sockfd < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "socket open failed: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* Allocate a packet. */
  request = (radius_packet_t *) pcalloc(radius_pool, sizeof(radius_packet_t));

  now = time(NULL);
  event_ts = htonl(now);
  session_duration = htonl(now - radius_session_start);
  terminate_cause = htonl(radius_get_terminate_cause());

  memset(pid_str, '\0', sizeof(pid_str));
  pid_len = pr_snprintf(pid_str, sizeof(pid_str)-1, "%08u",
    (unsigned int) session.pid);

  /* Loop through the list of servers, trying each one until the packet is
   * successfully sent.
   */
  acct_server = radius_acct_server;

  while (acct_server) {
    const char *ip_str;

    pr_signals_handle();

    /* Clear the packet. */
    memset(request, '\0', sizeof(radius_packet_t));

    /* Build the packet. */
    request->code = RADIUS_ACCT_REQUEST;
    radius_build_packet(request,
      radius_realm ?
        (const unsigned char *) pstrcat(radius_pool, session.user,
          radius_realm, NULL) :
        (const unsigned char *) session.user, NULL, acct_server->secret,
        acct_server->secret_len);

    /* Use the ID of the last accounting packet sent, plus one.  Be sure
     * to handle the datatype overflow case.
     */
    request->id = radius_last_acct_pkt_id + 1;
    if (request->id == 0) {
      request->id = 1;
    }

    /* Add accounting attributes. */
    acct_status = htonl(RADIUS_ACCT_STATUS_STOP);
    radius_add_attrib(request, RADIUS_ACCT_STATUS_TYPE,
      (unsigned char *) &acct_status, sizeof(int));
 
    radius_add_attrib(request, RADIUS_ACCT_SESSION_ID,
      (const unsigned char *) pid_str, pid_len);

    acct_authentic = htonl(RADIUS_AUTH_LOCAL);
    radius_add_attrib(request, RADIUS_ACCT_AUTHENTIC,
      (unsigned char *) &acct_authentic, sizeof(int));

    radius_add_attrib(request, RADIUS_ACCT_SESSION_TIME,
      (unsigned char *) &session_duration, sizeof(int));

    radius_session_bytes_in = htonl(session.total_bytes_in);
    radius_add_attrib(request, RADIUS_ACCT_INPUT_OCTETS,
      (unsigned char *) &radius_session_bytes_in, sizeof(int));

    radius_session_bytes_out = htonl(session.total_bytes_out);
    radius_add_attrib(request, RADIUS_ACCT_OUTPUT_OCTETS,
      (unsigned char *) &radius_session_bytes_out, sizeof(int));

    radius_add_attrib(request, RADIUS_ACCT_TERMINATE_CAUSE,
      (unsigned char *) &terminate_cause, sizeof(int));

    radius_add_attrib(request, RADIUS_ACCT_EVENT_TS,
      (unsigned char *) &event_ts, sizeof(int));

    if (radius_acct_user != NULL) {
      /* See RFC 2865, Section 5.1. */
      radius_add_attrib(request, RADIUS_USER_NAME,
        (const unsigned char *) radius_acct_user, radius_acct_userlen);
    }

    if (radius_acct_class != NULL) {
      radius_add_attrib(request, RADIUS_CLASS,
        (const unsigned char *) radius_acct_class, radius_acct_classlen);
    }

    /* Calculate the signature. */
    radius_set_acct_digest(request, acct_server->secret,
      acct_server->secret_len);

    /* Send the request. */
    ip_str = pr_netaddr_get_ipstr(acct_server->addr);
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "sending stop acct request packet to %s#%u", ip_str, acct_server->port);
    if (radius_send_packet(sockfd, request, acct_server) < 0) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "packet send failed to %s#%u", ip_str, acct_server->port);
      acct_server = acct_server->next;
      continue;
    }

    /* Receive the response. */
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "receiving acct response packet");
    response = radius_recv_packet(sockfd, acct_server->timeout);
    if (response == NULL) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "packet receive failed from %s#%u", ip_str, acct_server->port);
      acct_server = acct_server->next;
      continue;
    }

    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "packet receive succeeded succeeded from %s#%u", ip_str,
      acct_server->port);
    recvd_response = TRUE;
    break;
  }

  /* Close the socket. */
  (void) close(sockfd);

  if (recvd_response) {

    /* Verify the response. */
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "verifying packet");
    if (radius_verify_packet(request, response, acct_server->secret,
        acct_server->secret_len) < 0) {
      return -1;
    }

    /* Handle the response. */
    switch (response->code) {
      case RADIUS_ACCT_RESPONSE:
        (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
          "accounting ended for user '%s'", session.user);
        return 0;

      default:
        (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
          "notice: server returned unknown response code: %02x",
          response->code);
        return -1;
    }

  } else {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "error: no accounting servers responded");
  }

  /* Default return value. */
  return -1;
}

/* Verify the response packet from the server. */
static int radius_verify_packet(radius_packet_t *req_packet, 
    radius_packet_t *resp_packet, const unsigned char *secret,
    size_t secret_len) {
  MD5_CTX ctx;
  unsigned char calculated[RADIUS_VECTOR_LEN], replied[RADIUS_VECTOR_LEN];

  /* sanity check */
  if (req_packet == NULL ||
      resp_packet == NULL ||
      secret == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* NOTE: add checks for too-big, too-small packets, invalid packet->length
   * values, etc.
   */

  /* Check that the packet IDs match. */
  if (resp_packet->id != req_packet->id) {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "packet verification failed: response packet ID %d does not "
      "match the request packet ID %d", resp_packet->id, req_packet->id);
    return -1;
  }

  /* Make sure the buffers are void of junk values. */
  memset(calculated, '\0', sizeof(calculated));
  memset(replied, '\0', sizeof(replied));

  /* Save a copy of the response's digest. */
  memcpy(replied, resp_packet->digest, RADIUS_VECTOR_LEN);

  /* Copy in the digest sent in the request. */
  memcpy(resp_packet->digest, req_packet->digest, RADIUS_VECTOR_LEN);

  /* Re-calculate a digest from the given packet, and compare it against
   * the provided response digest:
   *   MD5(response packet header + digest + response packet data + secret)
   */
  MD5_Init(&ctx);
  MD5_Update(&ctx, (unsigned char *) resp_packet, ntohs(resp_packet->length));

  if (*secret) {
    MD5_Update(&ctx, secret, secret_len);
  }

  /* Set the calculated digest. */
  MD5_Final(calculated, &ctx);

  /* Do the digests match properly? */
  if (memcmp(calculated, replied, RADIUS_VECTOR_LEN) != 0) {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "packet verification failed: mismatched digests");
    errno = EINVAL;
    return -1;
  }

  return 0;
}

/* Authentication handlers
 */

MODRET radius_auth(cmd_rec *cmd) {

  /* This authentication check has already been performed; I just need
   * to report the results of that check now.
   */
  if (radius_auth_ok) {
    session.auth_mech = "mod_radius.c";
    return PR_HANDLED(cmd);

  } else if (radius_auth_reject) {
    return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
  }

  /* Default return value. */
  return PR_DECLINED(cmd);
}

MODRET radius_check(cmd_rec *cmd) {
  return PR_DECLINED(cmd);
}

MODRET radius_name2uid(cmd_rec *cmd) {
  return PR_DECLINED(cmd);
}

MODRET radius_name2gid(cmd_rec *cmd) {
  return PR_DECLINED(cmd);
}

MODRET radius_uid2name(cmd_rec *cmd) {
  return PR_DECLINED(cmd);
}

MODRET radius_gid2name(cmd_rec *cmd) {
  return PR_DECLINED(cmd);
}

MODRET radius_endgrent(cmd_rec *cmd) {
  return PR_DECLINED(cmd);
}

MODRET radius_getgrnam(cmd_rec *cmd) {
  return PR_DECLINED(cmd);
}

MODRET radius_getgrent(cmd_rec *cmd) {
  return PR_DECLINED(cmd);
}

MODRET radius_getgrgid(cmd_rec *cmd) {
  return PR_DECLINED(cmd);
}

MODRET radius_getgroups(cmd_rec *cmd) {

  if (radius_have_group_info) {
    array_header *gids = NULL, *groups = NULL;
    register unsigned int i = 0;

    /* Return the faked group information. */

    /* Don't forget to include the primary GID (with accompanying name!)
     * in the returned info -- if provided.  Otherwise, well...the user
     * is out of luck.
     */

    /* Check for NULL values */
    if (cmd->argv[1]) {
      gids = (array_header *) cmd->argv[1];

      if (radius_have_user_info) {
        *((gid_t *) push_array(gids)) = radius_passwd.pw_gid;
      }

      for (i = 0; i < radius_addl_group_count; i++) {
        *((gid_t *) push_array(gids)) = radius_addl_group_ids[i];
      }
    }

    if (cmd->argv[2]) {
      groups = (array_header *) cmd->argv[2];

      if (radius_have_user_info) {
        *((char **) push_array(groups)) = radius_prime_group_name;
      }

      for (i = 0; i < radius_addl_group_count; i++) {
        *((char **) push_array(groups)) = radius_addl_group_names[i];
      }
    }

    /* Increment this count, for the sake of proper reporting back to the
     * getgroups() caller.
     */
    if (radius_have_user_info) {
      radius_addl_group_count++;
    }

    return mod_create_data(cmd, (void *) &radius_addl_group_count);
  }

  return PR_DECLINED(cmd);
}

MODRET radius_setgrent(cmd_rec *cmd) {
  return PR_DECLINED(cmd);
}

MODRET radius_endpwent(cmd_rec *cmd) {
  return PR_DECLINED(cmd);
}

MODRET radius_getpwnam(cmd_rec *cmd) {

  if (radius_have_user_info) {

    if (radius_passwd.pw_name == NULL) {
      radius_passwd.pw_name = pstrdup(radius_pool, cmd->argv[0]);
    }

    if (strcmp(cmd->argv[0], radius_passwd.pw_name) == 0) {

      /* Return the faked user information. */
      return mod_create_data(cmd, &radius_passwd);
    }
  }

  /* Default response */
  return PR_DECLINED(cmd);
}

MODRET radius_getpwent(cmd_rec *cmd) {

  if (radius_have_user_info) {

    /* Return the faked user information. */
    return mod_create_data(cmd, &radius_passwd);
  }

  /* Default response */
  return PR_DECLINED(cmd);
}

MODRET radius_getpwuid(cmd_rec *cmd) {

  if (radius_have_user_info) {

    /* Check that given UID matches faked UID before returning. */
    if (*((uid_t *) cmd->argv[0]) == radius_passwd.pw_uid) {

      /* Return the faked user information. */
      return mod_create_data(cmd, &radius_passwd);
    }
  }

  /* Default response */
  return PR_DECLINED(cmd);
}

MODRET radius_setpwent(cmd_rec *cmd) {
  return PR_DECLINED(cmd);
}

/* Command handlers
 */

/* Handle retrieval of quota-related VSAs from response packets.
 */
MODRET radius_quota_lookup(cmd_rec *cmd) {

  if (radius_have_quota_info) {
    array_header *quota = make_array(session.pool, 9, sizeof(char *));
    *((char **) push_array(quota)) = cmd->argv[0];
    *((char **) push_array(quota)) = radius_quota_per_sess;
    *((char **) push_array(quota)) = radius_quota_limit_type;
    *((char **) push_array(quota)) = radius_quota_bytes_in;
    *((char **) push_array(quota)) = radius_quota_bytes_out;
    *((char **) push_array(quota)) = radius_quota_bytes_xfer;
    *((char **) push_array(quota)) = radius_quota_files_in;
    *((char **) push_array(quota)) = radius_quota_files_out;
    *((char **) push_array(quota)) = radius_quota_files_xfer;

    return mod_create_data(cmd, quota);
  }

  return PR_DECLINED(cmd);
}

/* Perform the check with the RADIUS auth server(s) now, prior to the
 * actual handling of the PASS command by mod_auth, so that any of the
 * RadiusUserInfo parameters can be supplied by the RADIUS server.
 *
 * NOTE: first draft, does not honor UserAlias'd names (eg it uses the
 * username as supplied by the client.
 */
MODRET radius_pre_pass(cmd_rec *cmd) {
  int pid_len = 0, sockfd = -1;
  radius_packet_t *request = NULL, *response = NULL;
  radius_server_t *auth_server = NULL;
  unsigned char recvd_response = FALSE;
  unsigned int service;
  const char *user;
  char pid_str[16];

  /* Check to see whether RADIUS authentication should even be done. */
  if (radius_engine == FALSE ||
      radius_auth_server == NULL) {
    return PR_DECLINED(cmd);
  }

  user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
  if (user == NULL) {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "missing prerequisite USER command, declining to handle PASS");
    pr_response_add_err(R_503, _("Login with USER first"));
    return PR_ERROR(cmd);
  }

  /* Open a RADIUS socket */
  sockfd = radius_open_socket();
  if (sockfd < 0) {
    int xerrno = errno;
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "socket open failed: %s", strerror(xerrno));
    errno = xerrno;
    return PR_DECLINED(cmd);
  }

  /* Allocate a packet. */
  request = (radius_packet_t *) pcalloc(cmd->tmp_pool,
    sizeof(radius_packet_t));

  /* Clear the OK flag. */
  radius_auth_ok = FALSE;

  memset(pid_str, '\0', sizeof(pid_str));
  pid_len = pr_snprintf(pid_str, sizeof(pid_str)-1, "%08u",
    (unsigned int) session.pid);

  /* If mod_radius expects to find VSAs in the returned packet, it needs
   * to send a service type of Login, otherwise, use the Authenticate-Only
   * service type.
   */
  if (radius_have_user_info == TRUE ||
      radius_have_group_info == TRUE ||
      radius_have_quota_info == TRUE ||
      radius_have_other_info == TRUE) {
    service = (unsigned int) htonl(RADIUS_SVC_LOGIN);

  } else {
    service = (unsigned int) htonl(RADIUS_SVC_AUTHENTICATE_ONLY);
  }

  /* Loop through the list of servers, trying each one until the packet is
   * successfully sent.
   */
  auth_server = radius_auth_server;
  while (auth_server != NULL) {
    const char *ip_str;

    pr_signals_handle();

    /* Clear the packet. */
    memset(request, '\0', sizeof(radius_packet_t));

    /* Build the packet. */
    request->code = RADIUS_AUTH_REQUEST;
    radius_build_packet(request, radius_realm ?
      (const unsigned char *) pstrcat(radius_pool, user, radius_realm, NULL) :
      (const unsigned char *) user, (const unsigned char *) cmd->arg,
      auth_server->secret, auth_server->secret_len);

    radius_add_attrib(request, RADIUS_SERVICE_TYPE, (unsigned char *) &service,
      sizeof(service));

    radius_add_attrib(request, RADIUS_ACCT_SESSION_ID,
      (const unsigned char *) pid_str, pid_len);

    /* Calculate the signature. */
    radius_set_auth_mac(request, auth_server->secret, auth_server->secret_len);

    /* Send the request. */
    ip_str = pr_netaddr_get_ipstr(auth_server->addr);
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "sending auth request packet to %s#%d", ip_str, auth_server->port);
    if (radius_send_packet(sockfd, request, auth_server) < 0) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "packet send failed to %s#%d", ip_str, auth_server->port);
      auth_server = auth_server->next;
      continue;
    }

    /* Receive the response. */
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "receiving auth response packet from %s#%d", ip_str, auth_server->port);
    response = radius_recv_packet(sockfd, auth_server->timeout);
    if (response == NULL) {
      (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
        "packet receive failed from %s#%d", ip_str, auth_server->port);
      auth_server = auth_server->next;
      continue;
    }

    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "packet receive succeeded from %s#%d", ip_str, auth_server->port);
    recvd_response = TRUE;
    break;
  }

  /* Close the socket. */
  (void) close(sockfd);

  if (recvd_response) {
    int res;

    /* Verify the response. */
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "verifying packet");
    res = radius_verify_packet(request, response, auth_server->secret,
        auth_server->secret_len);
    if (res < 0) {
      return PR_DECLINED(cmd);
    }

    /* Handle the response */
    switch (response->code) {
      case RADIUS_AUTH_ACCEPT:
        /* Process the packet for custom attributes */
        res = radius_process_accept_packet(response, auth_server->secret,
          auth_server->secret_len);
        if (res < 0) {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "DISCARDING Access-Accept packet for user '%s' due to failed "
            "Message-Authenticator check; is the shared secret correct?",
            user);
          pr_log_pri(PR_LOG_NOTICE, MOD_RADIUS_VERSION
            ": DISCARDING Access-Accept packet for user '%s' due to failed "
            "Message-Authenticator check; is the shared secret correct?", user);

        } else {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "authentication successful for user '%s'", user);
          pr_trace_msg(trace_channel, 9,
            "processed %d %s in Access-Accept packet", res,
            res != 1 ? "attributes" : "attribute");

          radius_auth_ok = TRUE;
          radius_session_authtype = htonl(RADIUS_AUTH_RADIUS);
        }
        break;

      case RADIUS_AUTH_REJECT:
        /* Process the packet for custom attributes */
        res = radius_process_reject_packet(response, auth_server->secret,
          auth_server->secret_len);
        if (res < 0) {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "DISCARDING Access-Reject packet for user '%s' due to failed "
            "Message-Authenticator check; is the shared secret correct?",
            user);
          pr_log_pri(PR_LOG_NOTICE, MOD_RADIUS_VERSION
            ": DISCARDING Access-Reject packet for user '%s' due to failed "
            "Message-Authenticator check; is the shared secret correct?", user);

        } else {
          (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
            "authentication failed for user '%s'", user);
          pr_trace_msg(trace_channel, 9,
            "processed %d %s in Access-Reject packet", res,
            res != 1 ? "attributes" : "attribute");

          radius_auth_ok = FALSE;
          radius_auth_reject = TRUE;
          radius_reset();
        }
        break;

      case RADIUS_AUTH_CHALLENGE:
        /* Just log this case for now. */
        (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
          "authentication challenged for user '%s'", user);
        radius_reset();
        break;

      default:
        (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
          "notice: server returned unknown response code: %02x",
          response->code);
        radius_reset();
        break;
    }

  } else {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "error: no auth servers responded");
  }

  return PR_DECLINED(cmd);
}

MODRET radius_post_pass(cmd_rec *cmd) {

  /* Check to see if RADIUS accounting should be done. */
  if (!radius_engine || !radius_acct_server) {
    return PR_DECLINED(cmd);
  }

  /* Fill in the username in the faked user info, if need be. */
  if (radius_have_user_info) {
    radius_passwd.pw_name = (char *) session.user;
  }

  if (radius_start_accting() < 0) {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "error: unable to start accounting: %s", strerror(errno));
  }

  return PR_DECLINED(cmd);
}

MODRET radius_post_pass_err(cmd_rec *cmd) {
  radius_reset();
  return PR_DECLINED(cmd);
}

/* Configuration handlers
 */

/* usage: RadiusAcctServer server[:port] shared-secret [timeout] */
MODRET set_radiusacctserver(cmd_rec *cmd) {
  config_rec *c = NULL;
  radius_server_t *radius_server = NULL;
  unsigned short server_port = 0;
  char *port = NULL;

  if (cmd->argc-1 < 2 ||
      cmd->argc-1 > 3) {
    CONF_ERROR(cmd, "missing parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* Check to see if there's a port specified in the server name */
  port = strchr(cmd->argv[1], ':');
  if (port != NULL) {

    /* Separate the server name from the port */
    *(port++) = '\0';

    server_port = (unsigned short) atoi(port);
    if (server_port < 1024) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "port number must be greater "
        "than 1023", NULL));
    }
  }

  if (pr_netaddr_get_addr(cmd->tmp_pool, cmd->argv[1], NULL) == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to resolve server address: ",
      cmd->argv[1], NULL));
  }

  /* Allocate a RADIUS server rec and populate the members */
  radius_server = radius_make_server(radius_pool);

  radius_server->addr = pr_netaddr_get_addr(radius_server->pool, cmd->argv[1],
    NULL);
  radius_server->port = (server_port ? server_port : RADIUS_ACCT_PORT);
  radius_server->secret = (unsigned char *) pstrdup(radius_server->pool,
    cmd->argv[2]);
  radius_server->secret_len = strlen((char *) radius_server->secret);

  if (cmd->argc-1 == 3) {
    int timeout = -1;

    if (pr_str_get_duration(cmd->argv[3], &timeout) < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
        cmd->argv[1], "': ", strerror(errno), NULL));
    }

    radius_server->timeout = timeout;
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(radius_server_t *));
  *((radius_server_t **) c->argv[0]) = radius_server;

  return PR_HANDLED(cmd);
}

/* usage: RadiusAuthServer server[:port] <shared-secret> [timeout] */
MODRET set_radiusauthserver(cmd_rec *cmd) {
  config_rec *c = NULL;
  radius_server_t *radius_server = NULL;
  unsigned short server_port = 0;
  char *port = NULL;

  if (cmd->argc-1 < 2 ||
      cmd->argc-1 > 3) {
    CONF_ERROR(cmd, "missing parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* Check to see if there's a port specified in the server name */
  if ((port = strchr(cmd->argv[1], ':')) != NULL) {

    /* Separate the server name from the port */
    *(port++) = '\0';

    server_port = (unsigned short) atoi(port);
    if (server_port < 1024) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "port number must be greater "
        "than 1023", NULL));
    }
  }

  if (pr_netaddr_get_addr(cmd->tmp_pool, cmd->argv[1], NULL) == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable resolve server address: ",
      cmd->argv[1], NULL));
  }

  /* OK, allocate a RADIUS server rec and populate the members */
  radius_server = radius_make_server(radius_pool);

  radius_server->addr = pr_netaddr_get_addr(radius_server->pool, cmd->argv[1],
    NULL);
  radius_server->port = (server_port ? server_port : RADIUS_AUTH_PORT);
  radius_server->secret = (unsigned char *) pstrdup(radius_server->pool,
    cmd->argv[2]);
  radius_server->secret_len = strlen((char *) radius_server->secret);

  if (cmd->argc-1 == 3) {
    int timeout = -1;

    if (pr_str_get_duration(cmd->argv[3], &timeout) < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
        cmd->argv[1], "': ", strerror(errno), NULL));
    } 
    
    radius_server->timeout = timeout;
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(radius_server_t *));
  *((radius_server_t **) c->argv[0]) = radius_server;

  return PR_HANDLED(cmd);
}

/* usage: RadiusEngine on|off */
MODRET set_radiusengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: RadiusGroupInfo primary-name addl-names add-ids */
MODRET set_radiusgroupinfo(cmd_rec *cmd) {
  config_rec *c = NULL;
  unsigned char group_names_vsa = FALSE;
  unsigned char group_ids_vsa = FALSE;
  unsigned int ngroups = 0, ngids = 0;

  CHECK_ARGS(cmd, 3);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  group_names_vsa = radius_have_var(cmd->argv[2]);
  group_ids_vsa = radius_have_var(cmd->argv[3]);

  /* There will be five parameters to this config_rec:
   *
   *  primary-group-name
   *  addl-group-name-count
   *  addl-group-names
   *  addl-group-id-count
   *  addl-group-ids
   */

  c = add_config_param(cmd->argv[0], 5, NULL, NULL, NULL, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, cmd->argv[1]);
  c->argv[1] = pcalloc(c->pool, sizeof(unsigned int));
  c->argv[3] = pcalloc(c->pool, sizeof(unsigned int));

  if (group_names_vsa) {
    /* As VSA variables, the group names won't be resolved until session time,
     * so just store the variable strings as is.
     */
    c->argv[2] = pstrdup(c->pool, cmd->argv[2]);

  } else {
    char **groups = NULL;

    if (!radius_parse_groups_str(c->pool, cmd->argv[2], &groups, &ngroups))
      CONF_ERROR(cmd, "badly formatted group names");

    *((unsigned int *) c->argv[1]) = ngroups;
    c->argv[2] = (void *) groups;
  }

  if (group_ids_vsa) {
    /* As VSA variables, the group IDs won't be resolved until session time,
     * so just store the variable strings as is.
     */
    c->argv[4] = pstrdup(c->pool, cmd->argv[3]);

  } else {
    gid_t *gids = NULL;

    if (!radius_parse_gids_str(c->pool, cmd->argv[3], &gids, &ngids))
      CONF_ERROR(cmd, "badly formatted group IDs");

    *((unsigned int *) c->argv[3]) = ngids;
    c->argv[4] = (void *) gids;
  }

  if (ngroups > 0 &&
      ngids > 0 &&
      ngroups != ngids) {
    char ngroups_str[32], ngids_str[32];

    memset(ngroups_str, '\0', sizeof(ngroups_str));
    pr_snprintf(ngroups_str, sizeof(ngroups_str)-1, "%u", ngroups);

    memset(ngids_str, '\0', sizeof(ngids_str));
    pr_snprintf(ngids_str, sizeof(ngids_str)-1, "%u", ngids);

    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "mismatched number of group names (",
      ngroups_str, ") and group IDs (", ngids_str, ")", NULL));
  }

  return PR_HANDLED(cmd);
}

/* usage: RadiusLog file|"none" */
MODRET set_radiuslog(cmd_rec *cmd) {
  if (cmd->argc-1 != 1)
    CONF_ERROR(cmd, "wrong number of parameters");
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: RadiusNASIdentifier string */
MODRET set_radiusnasidentifier(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: RadiusOptions opt1 ... */
MODRET set_radiusoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "IgnoreReplyMessage") == 0) {
      opts |= RADIUS_OPT_IGNORE_REPLY_MESSAGE_ATTR;

    } else if (strcmp(cmd->argv[i], "IgnoreClass") == 0) {
      opts |= RADIUS_OPT_IGNORE_CLASS_ATTR;

    } else if (strcmp(cmd->argv[i], "IgnoreIdleTimeout") == 0) {
      opts |= RADIUS_OPT_IGNORE_IDLE_TIMEOUT_ATTR;

    } else if (strcmp(cmd->argv[i], "IgnoreSessionTimeout") == 0) {
      opts |= RADIUS_OPT_IGNORE_SESSION_TIMEOUT_ATTR;

    } else if (strcmp(cmd->argv[i], "RequireMAC") == 0) {
      opts |= RADIUS_OPT_REQUIRE_MAC;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown TLSOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: RadiusQuotaInfo per-sess limit-type bytes-in bytes-out bytes-xfer
 *          files-in files-out files-xfer
 */
MODRET set_radiusquotainfo(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 8);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (!radius_have_var(cmd->argv[1])) {
    if (strcasecmp(cmd->argv[1], "false") != 0 &&
        strcasecmp(cmd->argv[1], "true") != 0)
      CONF_ERROR(cmd, "invalid per-session value");
  }

  if (!radius_have_var(cmd->argv[2])) {
    if (strcasecmp(cmd->argv[2], "hard") != 0 &&
        strcasecmp(cmd->argv[2], "soft") != 0) {
      CONF_ERROR(cmd, "invalid limit type value");
    }
  }

  if (!radius_have_var(cmd->argv[3])) {
    char *endp = NULL;

    /* Make sure it's a number, at least. */
    if (strtod(cmd->argv[3], &endp) < 0) {
      CONF_ERROR(cmd, "negative bytes value not allowed");
    }

    if (endp && *endp) {
      CONF_ERROR(cmd, "invalid bytes parameter: not a number");
    }
  }

  if (!radius_have_var(cmd->argv[4])) {
    char *endp = NULL;

    /* Make sure it's a number, at least. */
    if (strtod(cmd->argv[4], &endp) < 0) {
      CONF_ERROR(cmd, "negative bytes value not allowed");
    }

    if (endp && *endp) {
      CONF_ERROR(cmd, "invalid bytes parameter: not a number");
    }
  }

  if (!radius_have_var(cmd->argv[5])) {
    char *endp = NULL;

    /* Make sure it's a number, at least. */
    if (strtod(cmd->argv[5], &endp) < 0) {
      CONF_ERROR(cmd, "negative bytes value not allowed");
    }

    if (endp && *endp) {
      CONF_ERROR(cmd, "invalid bytes parameter: not a number");
    }
  }

  if (!radius_have_var(cmd->argv[6])) {
    char *endp = NULL;

    /* Make sure it's a number, at least. */
    (void) strtoul(cmd->argv[6], &endp, 10);
    if (endp && *endp) {
      CONF_ERROR(cmd, "invalid files parameter: not a number");
    }
  }

  if (!radius_have_var(cmd->argv[7])) {
    char *endp = NULL;

    /* Make sure it's a number, at least. */
    (void) strtoul(cmd->argv[7], &endp, 10);
    if (endp && *endp) {
      CONF_ERROR(cmd, "invalid files parameter: not a number");
    }
  }

  if (!radius_have_var(cmd->argv[8])) {
    char *endp = NULL;

    /* Make sure it's a number, at least. */
    (void) strtoul(cmd->argv[8], &endp, 10);
    if (endp && *endp) {
      CONF_ERROR(cmd, "invalid files parameter: not a number");
    }
  }

  add_config_param_str(cmd->argv[0], 8, cmd->argv[1], cmd->argv[2],
    cmd->argv[3], cmd->argv[4], cmd->argv[5], cmd->argv[6],
    cmd->argv[7], cmd->argv[8]);

  return PR_HANDLED(cmd);
}

/* usage: RadiusRealm string */
MODRET set_radiusrealm(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: RadiusUserInfo uid gid home shell */
MODRET set_radiususerinfo(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 4);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (!radius_have_var(cmd->argv[1])) {
    char *endp = NULL;

    /* Make sure it's a number, at least. */
    (void) strtoul(cmd->argv[1], &endp, 10);
    if (endp && *endp) {
      CONF_ERROR(cmd, "invalid UID parameter: not a number");
    }
  }

  if (!radius_have_var(cmd->argv[2])) {
    char *endp = NULL;

    /* Make sure it's a number, at least. */
    (void) strtoul(cmd->argv[2], &endp, 10);
    if (endp && *endp)
      CONF_ERROR(cmd, "invalid GID parameter: not a number");
  } 

  if (!radius_have_var(cmd->argv[3])) {
    char *path;

    path = cmd->argv[3];
    /* Make sure the path is absolute, at least. */
    if (*path != '/') {
      CONF_ERROR(cmd, "home relative path not allowed");
    }
  }

  if (!radius_have_var(cmd->argv[4])) {
    char *path;

    path = cmd->argv[4];
    /* Make sure the path is absolute, at least. */
    if (*path != '/') {
      CONF_ERROR(cmd, "shell relative path not allowed");
    }
  }

  add_config_param_str(cmd->argv[0], 4, cmd->argv[1], cmd->argv[2],
    cmd->argv[3], cmd->argv[4]);
  return PR_HANDLED(cmd);
}

/* usage: RadiusVendor name id */
MODRET set_radiusvendor(cmd_rec *cmd) {
  config_rec *c = NULL;
  long id = 0;
  char *tmp = NULL;

  CHECK_ARGS(cmd, 2);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* Make sure that the given vendor ID number is valid. */
  id = strtol(cmd->argv[2], &tmp, 10);

  if (tmp && *tmp) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": vendor id '", cmd->argv[2],
      "' is not a valid number", NULL));
  }

  if (id < 0) {
    CONF_ERROR(cmd, "vendor id must be a positive number");
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, cmd->argv[1]);
  c->argv[1] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[1]) = id;

  return PR_HANDLED(cmd);
}

/* Event handlers
 */

static void radius_exit_ev(const void *event_data, void *user_data) {
  if (radius_stop_accting() < 0) {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "error: unable to stop accounting: %s", strerror(errno));
  }

  (void) close(radius_logfd);
  radius_logfd = -1;
}

#if defined(PR_SHARED_MODULE)
static void radius_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_radius.c", (const char *) event_data) == 0) {
    pr_event_unregister(&radius_module, NULL, NULL);

    if (radius_pool) {
      destroy_pool(radius_pool);
      radius_pool = NULL;
    }

    close(radius_logfd);
    radius_logfd = -1;
  }
}
#endif /* PR_SHARED_MODULE */

static void radius_restart_ev(const void *event_data, void *user_data) {

  /* Re-allocate the pool used by this module. */
  if (radius_pool) {
    destroy_pool(radius_pool);
  }

  radius_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(radius_pool, MOD_RADIUS_VERSION);

  return;
}

static void radius_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer; reinitialize ourselves. */

  pr_event_unregister(&radius_module, "core.exit", radius_exit_ev);
  pr_event_unregister(&radius_module, "core.session-reinit",
    radius_sess_reinit_ev);

  /* Reset defaults. */
  radius_engine = FALSE;
  radius_acct_server = NULL;
  radius_auth_server = NULL;
  (void) close(radius_logfd);
  radius_logfd = -1;
  radius_opts = 0UL;
  radius_nas_identifier_config = NULL;
  radius_vendor_name = "Unix";
  radius_vendor_id = 4;
  radius_realm = NULL;

  radius_have_user_info = FALSE;
  radius_uid_attr_id = 0;
  radius_gid_attr_id = 0;
  radius_home_attr_id = 0;
  radius_shell_attr_id = 0;

  radius_have_group_info = FALSE;
  radius_prime_group_name_attr_id = 0;
  radius_addl_group_names_attr_id = 0;
  radius_addl_group_ids_attr_id = 0;
  radius_prime_group_name = NULL;
  radius_addl_group_count = 0;
  radius_addl_group_names = 0;
  radius_addl_group_names_str = NULL;
  radius_addl_group_ids = NULL;
  radius_addl_group_ids_str = NULL;

  radius_have_quota_info = FALSE;
  radius_quota_per_sess_attr_id = 0;
  radius_quota_limit_type_attr_id = 0;
  radius_quota_bytes_in_attr_id = 0;
  radius_quota_bytes_out_attr_id = 0;
  radius_quota_bytes_xfer_attr_id = 0;
  radius_quota_files_in_attr_id = 0;
  radius_quota_files_out_attr_id = 0;
  radius_quota_files_xfer_attr_id = 0;
  radius_quota_per_sess = NULL;
  radius_quota_limit_type = NULL;
  radius_quota_bytes_in = NULL;
  radius_quota_bytes_out = NULL;
  radius_quota_bytes_xfer = NULL;
  radius_quota_files_in = NULL;
  radius_quota_files_out = NULL;
  radius_quota_files_xfer = NULL;

  radius_have_other_info = FALSE;

  /* Note that we deliberately leave the radius_session_start time_t alone;
   * it is initialized at the start of the session, regardless of vhost.
   */

  res = radius_sess_init();
  if (res < 0) {
    pr_session_disconnect(&radius_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Initialization routines
 */

static int radius_sess_init(void) {
  int res = 0;
  config_rec *c = NULL;
  radius_server_t **current_server = NULL;

  pr_event_register(&radius_module, "core.session-reinit",
    radius_sess_reinit_ev, NULL);

  /* Is RadiusEngine on? */
  c = find_config(main_server->conf, CONF_PARAM, "RadiusEngine", FALSE);
  if (c != NULL) {
    radius_engine = *((int *) c->argv[0]);
  }

  if (radius_engine == FALSE) {
    return 0;
  }

  res = radius_openlog();
  if (res < 0) {
    if (res == -1) {
      pr_log_pri(PR_LOG_NOTICE, MOD_RADIUS_VERSION
        ": notice: unable to open RadiusLog: %s", strerror(errno));

    } else if (res == PR_LOG_WRITABLE_DIR) {
      pr_log_pri(PR_LOG_WARNING, MOD_RADIUS_VERSION
        ": notice: unable to open RadiusLog: parent directory is "
        "world-writable");

    } else if (res == PR_LOG_SYMLINK) {
      pr_log_pri(PR_LOG_WARNING, MOD_RADIUS_VERSION
        ": notice: unable to open RadiusLog: cannot log to a symbolic link");
    }
  }

  /* Initialize session variables */
  time(&radius_session_start);

  c = find_config(main_server->conf, CONF_PARAM, "RadiusOptions", FALSE);
  while (c != NULL) {
    unsigned long opts = 0;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    radius_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "RadiusOptions", FALSE);
  }

  c = find_config(main_server->conf, CONF_PARAM, "RadiusNASIdentifier", FALSE);
  if (c != NULL) {
    radius_nas_identifier_config = c->argv[0];

    pr_trace_msg(trace_channel, 3,
      "RadiusNASIdentifier '%s' configured", radius_nas_identifier_config);
  }

  c = find_config(main_server->conf, CONF_PARAM, "RadiusVendor", FALSE);
  if (c != NULL) {
    radius_vendor_name = c->argv[0];
    radius_vendor_id = *((unsigned int *) c->argv[1]);

    pr_trace_msg(trace_channel, 3,
      "RadiusVendor '%s' (Vendor-Id %u) configured", radius_vendor_name,
      radius_vendor_id);
  }

  /* Find any configured RADIUS servers for this session */
  c = find_config(main_server->conf, CONF_PARAM, "RadiusAcctServer", FALSE);

  /* Point to the start of the accounting server list. */
  current_server = &radius_acct_server;

  while (c != NULL) {
    pr_signals_handle();

    *current_server = *((radius_server_t **) c->argv[0]);
    current_server = &(*current_server)->next;

    c = find_config_next(c, c->next, CONF_PARAM, "RadiusAcctServer", FALSE);
  }

  if (radius_acct_server == NULL) {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "notice: no configured RadiusAcctServers, no accounting");
  }

  c = find_config(main_server->conf, CONF_PARAM, "RadiusAuthServer", FALSE);

  /* Point to the start of the authentication server list. */
  current_server = &radius_auth_server;

  while (c != NULL) {
    pr_signals_handle();

    *current_server = *((radius_server_t **) c->argv[0]);
    current_server = &(*current_server)->next;

    c = find_config_next(c, c->next, CONF_PARAM, "RadiusAuthServer", FALSE);
  }

  if (radius_auth_server == NULL) {
    (void) pr_log_writefile(radius_logfd, MOD_RADIUS_VERSION,
      "notice: no configured RadiusAuthServers, no authentication");
  }

  /* Prepare any configured fake user information. */
  c = find_config(main_server->conf, CONF_PARAM, "RadiusUserInfo", FALSE);
  if (c != NULL) {

    /* Process the parameter string stored in the found config_rec. */
    radius_process_user_info(c);

    /* Only use the faked information if authentication via RADIUS is
     * possible.  The radius_have_user_info flag will be set to
     * TRUE by radius_process_user_info(), unless there was some
     * illegal value.
     */
    if (radius_auth_server == NULL) {
      radius_have_user_info = FALSE;
    }
  }

  /* If the RadiusUserInfo directive has not been set (or if it has been
   * set, but it was not well-formed), then we will be acting in a
   * "yes/no" style of authentication, similar to PAM.
   *
   * The Auth API tries to use the same module for authenticating a user
   * as the one which provided information for that user.  If we are not
   * providing user information, then we won't get a chance to authenticate
   * the user -- unless we disable that Auth API behavior.
   */
  if (radius_have_user_info == FALSE) {
    if (pr_auth_add_auth_only_module("mod_radius.c") < 0) {
      pr_log_debug(DEBUG2, "error adding 'mod_radius.c' to auth-only module "
        "list: %s", strerror(errno));
    }
  }

  /* Prepare any configured fake group information. */
  c = find_config(main_server->conf, CONF_PARAM, "RadiusGroupInfo", FALSE);
  if (c != NULL) {

    /* Process the parameter string stored in the found config_rec. */
    radius_process_group_info(c);

    /* Only use the faked information if authentication via RADIUS is
     * possible.  The radius_have_group_info flag will be set to
     * TRUE by radius_process_group_info(), unless there was some
     * illegal value.
     */
    if (radius_auth_server == NULL) {
      radius_have_group_info = FALSE;
    }
  }

  /* Prepare any configure quota information. */
  c = find_config(main_server->conf, CONF_PARAM, "RadiusQuotaInfo", FALSE);
  if (c != NULL) {
    radius_process_quota_info(c);

    if (radius_auth_server == NULL) {
      radius_have_quota_info = FALSE;
    }
  }

  /* Check for a configured RadiusRealm.  If present, use username + realm
   * in RADIUS packets as the user name, else just use the username.
   */
  radius_realm = get_param_ptr(main_server->conf, "RadiusRealm", FALSE);
  if (radius_realm) {
    pr_trace_msg(trace_channel, 3,
      "using RadiusRealm '%s'", radius_realm);
  }

  pr_event_register(&radius_module, "core.exit", radius_exit_ev, NULL);
  return 0;
}

static int radius_init(void) {

  /* Allocate a pool for this module's use. */
  radius_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(radius_pool, MOD_RADIUS_VERSION);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&radius_module, "core.module-unload",
    radius_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  /* Register a restart handler, to cleanup the pool. */
  pr_event_register(&radius_module, "core.restart", radius_restart_ev, NULL);

  return 0;
}

/* Module API tables
 */

static conftable radius_conftab[] = {
  { "RadiusAcctServer", 	set_radiusacctserver,	NULL },
  { "RadiusAuthServer", 	set_radiusauthserver,	NULL },
  { "RadiusEngine",		set_radiusengine,	NULL },
  { "RadiusGroupInfo",		set_radiusgroupinfo,	NULL },
  { "RadiusLog",		set_radiuslog,		NULL },
  { "RadiusNASIdentifier",	set_radiusnasidentifier,NULL },
  { "RadiusOptions",		set_radiusoptions,	NULL },
  { "RadiusQuotaInfo",		set_radiusquotainfo,	NULL },
  { "RadiusRealm",		set_radiusrealm,	NULL },
  { "RadiusUserInfo",		set_radiususerinfo,	NULL },
  { "RadiusVendor",		set_radiusvendor,	NULL },
  { NULL }
};

static cmdtable radius_cmdtab[] = {
  { HOOK,		"radius_quota_lookup", G_NONE,
      radius_quota_lookup, FALSE, FALSE },

  { PRE_CMD,		C_PASS, G_NONE, radius_pre_pass,	FALSE, FALSE, CL_AUTH },
  { POST_CMD,		C_PASS, G_NONE, radius_post_pass, 	FALSE, FALSE, CL_AUTH },
  { POST_CMD_ERR,	C_PASS, G_NONE, radius_post_pass_err, 	FALSE, FALSE, CL_AUTH },
  { 0, NULL }
};

static authtable radius_authtab[] = {
  { 0, "setpwent",  radius_setpwent },
  { 0, "setgrent",  radius_setgrent },
  { 0, "endpwent",  radius_endpwent },
  { 0, "endgrent",  radius_endgrent },
  { 0, "getpwent",  radius_getpwent },
  { 0, "getgrent",  radius_getgrent },
  { 0, "getpwnam",  radius_getpwnam },
  { 0, "getgrnam",  radius_getgrnam },
  { 0, "getpwuid",  radius_getpwuid },
  { 0, "getgrgid",  radius_getgrgid },
  { 0, "getgroups", radius_getgroups },
  { 0, "auth",      radius_auth     },
  { 0, "check",     radius_check    },
  { 0, "uid2name",  radius_uid2name },
  { 0, "gid2name",  radius_gid2name },
  { 0, "name2uid",  radius_name2uid },
  { 0, "name2gid",  radius_name2gid },
  { 0, NULL }
};

module radius_module = {

  /* Always NULL */
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "radius",

  /* Module configuration handler table */
  radius_conftab,

  /* Module command handler table */
  radius_cmdtab,

  /* Module authentication handler table */
  radius_authtab,

  /* Module initialization function */
  radius_init,

  /* Module session initialization function */
  radius_sess_init,

  /* Module version */
  MOD_RADIUS_VERSION
};
