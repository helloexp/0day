/*
 * ProFTPD: mod_geoip -- a module for looking up country/city/etc for clients
 * Copyright (c) 2010-2017 TJ Saunders
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
 * This is mod_geoip, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 *
 * --- DO NOT DELETE BELOW THIS LINE ----
 * $Libraries: -lGeoIP$
 */

#include "conf.h"
#include "privs.h"

/* A lot of ideas for this module were liberally borrowed from the mod_geoip
 * module for Apache.
 */

#define MOD_GEOIP_VERSION		"mod_geoip/0.9"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030402
# error "ProFTPD 1.3.4rc2 or later required"
#endif

#include <GeoIP.h>
#include <GeoIPCity.h>

module geoip_module;

static int geoip_engine = FALSE;
static int geoip_logfd = -1;

static pool *geoip_pool = NULL;
static array_header *static_geoips = NULL;

/* The types of data that GeoIP can provide, and that we care about. */
static const char *geoip_city = NULL;
static const char *geoip_area_code = NULL;
static const char *geoip_postal_code = NULL;
static const char *geoip_latitude = NULL;
static const char *geoip_longitude = NULL;
static const char *geoip_isp = NULL;
static const char *geoip_org = NULL;
static const char *geoip_country_code2 = NULL;
static const char *geoip_country_code3 = NULL;
static const char *geoip_country_name = NULL;
static const char *geoip_region_code = NULL;
static const char *geoip_region_name = NULL;
static const char *geoip_continent_name = NULL;
static const char *geoip_network_speed = NULL;
static const char *geoip_asn = NULL;
static const char *geoip_proxy = NULL;
static const char *geoip_timezone = NULL;

/* Names of supported GeoIP values */
struct geoip_filter_key {
  const char *filter_name;
  int filter_id;
};

#define GEOIP_FILTER_KEY_COUNTRY_CODE		100
#define GEOIP_FILTER_KEY_COUNTRY_CODE3		101
#define GEOIP_FILTER_KEY_COUNTRY_NAME		102
#define GEOIP_FILTER_KEY_REGION_CODE		103
#define GEOIP_FILTER_KEY_REGION_NAME		104
#define GEOIP_FILTER_KEY_CONTINENT		105
#define GEOIP_FILTER_KEY_ISP			106
#define GEOIP_FILTER_KEY_ORGANIZATION		107
#define GEOIP_FILTER_KEY_NETWORK_SPEED		108
#define GEOIP_FILTER_KEY_CITY			109
#define GEOIP_FILTER_KEY_AREA_CODE		110
#define GEOIP_FILTER_KEY_POSTAL_CODE		111
#define GEOIP_FILTER_KEY_LATITUDE		112
#define GEOIP_FILTER_KEY_LONGITUDE		113
#define GEOIP_FILTER_KEY_ASN			114
#define GEOIP_FILTER_KEY_PROXY			115
#define GEOIP_FILTER_KEY_TIMEZONE		116

static struct geoip_filter_key geoip_filter_keys[] = {
  { "CountryCode",	GEOIP_FILTER_KEY_COUNTRY_CODE },
  { "CountryCode3",	GEOIP_FILTER_KEY_COUNTRY_CODE3 },
  { "CountryName",	GEOIP_FILTER_KEY_COUNTRY_NAME },
  { "RegionCode",	GEOIP_FILTER_KEY_REGION_CODE },
  { "RegionName",	GEOIP_FILTER_KEY_REGION_NAME },
  { "Continent",	GEOIP_FILTER_KEY_CONTINENT },
  { "ISP",		GEOIP_FILTER_KEY_ISP },
  { "Organization",	GEOIP_FILTER_KEY_ORGANIZATION },
  { "NetworkSpeed",	GEOIP_FILTER_KEY_NETWORK_SPEED },
  { "City",		GEOIP_FILTER_KEY_CITY },
  { "AreaCode",		GEOIP_FILTER_KEY_AREA_CODE },
  { "PostalCode",	GEOIP_FILTER_KEY_POSTAL_CODE },
  { "Latitude",		GEOIP_FILTER_KEY_LATITUDE },
  { "Longitude",	GEOIP_FILTER_KEY_LONGITUDE },
  { "ASN",		GEOIP_FILTER_KEY_ASN },
  { "Proxy",		GEOIP_FILTER_KEY_PROXY },
  { "Timezone",		GEOIP_FILTER_KEY_TIMEZONE },

  { NULL, -1 }
};

#if PR_USE_REGEX
/* GeoIP filter */
struct geoip_filter {
  int filter_id;
  const char *filter_pattern;
  pr_regex_t *filter_re;
};
#endif /* PR_USE_REGEX */

/* GeoIP policies */
typedef enum {
  GEOIP_POLICY_ALLOW_DENY,
  GEOIP_POLICY_DENY_ALLOW

} geoip_policy_e;

static geoip_policy_e geoip_policy = GEOIP_POLICY_ALLOW_DENY;

static const char *trace_channel = "geoip";

static const char *get_geoip_filter_name(int);
static const char *get_geoip_filter_value(int);

static int get_filter_id(const char *filter_name) {
  register unsigned int i;
  int filter_id = -1;

  for (i = 0; geoip_filter_keys[i].filter_name != NULL; i++) {
    if (strcasecmp(filter_name, geoip_filter_keys[i].filter_name) == 0) {
      filter_id = geoip_filter_keys[i].filter_id;
      break;
    }
  }

  return filter_id;
}

#if PR_USE_REGEX
static int get_filter(pool *p, const char *pattern, pr_regex_t **pre) {
  int res;

  *pre = pr_regexp_alloc(&geoip_module);

  res = pr_regexp_compile(*pre, pattern, REG_EXTENDED|REG_NOSUB|REG_ICASE);
  if (res != 0) {
    char errstr[256];

    memset(errstr, '\0', sizeof(errstr));
    pr_regexp_error(res, *pre, errstr, sizeof(errstr)-1);
    pr_regexp_free(&geoip_module, *pre);
    *pre = NULL;

    pr_log_pri(PR_LOG_DEBUG, MOD_GEOIP_VERSION
      ": pattern '%s' failed regex compilation: %s", pattern, errstr);
    errno = EINVAL;
    return -1;
  }

  return res;
}

static struct geoip_filter *make_filter(pool *p, const char *filter_name,
    const char *pattern) {
  struct geoip_filter *filter;
  int filter_id;
  pr_regex_t *pre = NULL;

  filter_id = get_filter_id(filter_name);
  if (filter_id < 0) {
    pr_log_debug(DEBUG0, MOD_GEOIP_VERSION ": unknown GeoIP filter name '%s'",
      filter_name);
    return NULL;
  }

  if (get_filter(p, pattern, &pre) < 0) {
    return NULL;
  }

  filter = pcalloc(p, sizeof(struct geoip_filter));
  filter->filter_id = filter_id;
  filter->filter_pattern = pstrdup(p, pattern);
  filter->filter_re = pre;

  return filter;
}

static array_header *get_sql_filters(pool *p, const char *query_name) {
  register unsigned int i;
  cmdtable *sql_cmdtab = NULL;
  cmd_rec *sql_cmd = NULL;
  modret_t *sql_res = NULL;
  array_header *sql_data = NULL;
  const char **values = NULL;
  array_header *sql_filters = NULL;

  sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_lookup", NULL, NULL,
    NULL);
  if (sql_cmdtab == NULL) {
    (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
      "unable to execute SQLNamedQuery '%s': mod_sql not loaded", query_name);
    errno = EPERM;
    return NULL;
  }

  sql_cmd = pr_cmd_alloc(p, 2, "sql_lookup", query_name);

  sql_res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, sql_cmd);
  if (sql_res == NULL ||
      MODRET_ISERROR(sql_res)) {
    (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
      "error processing SQLNamedQuery '%s'; check mod_sql logs for details",
      query_name);
    errno = EPERM;
    return NULL;
  }

  sql_data = sql_res->data;
  pr_trace_msg(trace_channel, 9, "SQLNamedQuery '%s' returned item count %d",
    query_name, sql_data->nelts);

  if (sql_data->nelts == 0) {
    (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
      "SQLNamedQuery '%s' returned no values", query_name);
    errno = ENOENT;
    return NULL;
  }

  if (sql_data->nelts % 2 == 1) {
    (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
      "SQLNamedQuery '%s' returned odd number of values (%d), "
      "expected even number", query_name, sql_data->nelts);
    errno = EINVAL;
    return NULL;
  }

  values = sql_data->elts;
  sql_filters = make_array(p, 0, sizeof(struct geoip_filter));

  for (i = 0; i < sql_data->nelts; i += 2) {
    const char *filter_name, *pattern = NULL;
    struct geoip_filter *filter;

    filter_name = values[i];
    pattern = values[i+1];

    filter = make_filter(p, filter_name, pattern);
    if (filter == NULL) {
      pr_trace_msg(trace_channel, 3, "unable to use '%s %s' as filter: %s",
        filter_name, pattern, strerror(errno));
      continue;
    }

    *((struct geoip_filter **) push_array(sql_filters)) = filter;
  }

  return sql_filters;
}
#endif /* PR_USE_REGEX */

static void resolve_deferred_patterns(pool *p, const char *directive) {
#if PR_USE_REGEX
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, directive, FALSE);
  while (c != NULL) {
    register unsigned int i;
    array_header *deferred_filters, *filters;

    pr_signals_handle();

    filters = c->argv[0];
    deferred_filters = c->argv[1];

    for (i = 0; i < deferred_filters->nelts; i++) {
      const char *query_name;
      array_header *sql_filters;

      query_name = ((const char **) deferred_filters->elts)[i];

      sql_filters = get_sql_filters(p, query_name);
      if (sql_filters == NULL) {
        continue;
      }

      array_cat(filters, sql_filters);
    }

    c = find_config_next(c, c->next, CONF_PARAM, directive, FALSE);
  }
#endif /* PR_USE_REGEX */
}

static void resolve_deferred_filters(pool *p) {
  resolve_deferred_patterns(p, "GeoIPAllowFilter");
  resolve_deferred_patterns(p, "GeoIPDenyFilter");
}

static int check_geoip_filters(geoip_policy_e policy) {
  int allow_conn = 0, matched_allow_filter = -1, matched_deny_filter = -1;
#if PR_USE_REGEX
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "GeoIPAllowFilter", FALSE);
  while (c != NULL) {
    register unsigned int i;
    int matched = TRUE;
    array_header *filters;

    pr_signals_handle();

    if (matched_allow_filter == -1) {
      matched_allow_filter = FALSE;
    }

    filters = c->argv[0];

    for (i = 0; i < filters->nelts; i++) {
      int filter_id, res;
      struct geoip_filter *filter;
      pr_regex_t *filter_re;
      const char *filter_name, *filter_pattern, *filter_value;

      filter = ((struct geoip_filter **) filters->elts)[i]; 
      filter_id = filter->filter_id;
      filter_pattern = filter->filter_pattern;
      filter_re = filter->filter_re;

      filter_value = get_geoip_filter_value(filter_id);
      if (filter_value == NULL) {
        matched = FALSE;
        break;
      }

      filter_name = get_geoip_filter_name(filter_id);

      res = pr_regexp_exec(filter_re, filter_value, 0, NULL, 0, 0, 0);
      pr_trace_msg(trace_channel, 12,
        "%s filter value %s %s GeoIPAllowFilter pattern '%s'",
        filter_name, filter_value, res == 0 ? "matched" : "did not match",
        filter_pattern);
      if (res == 0) {
        (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
          "%s filter value '%s' matched GeoIPAllowFilter pattern '%s'",
          filter_name, filter_value, filter_pattern);

      } else {
        (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
          "%s filter value '%s' did not match GeoIPAllowFilter pattern '%s'",
          filter_name, filter_value, filter_pattern);
          matched = FALSE;
          break;
      }
    }

    if (matched == TRUE) {
      matched_allow_filter = TRUE;
      break;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "GeoIPAllowFilter", FALSE);
  }

  c = find_config(main_server->conf, CONF_PARAM, "GeoIPDenyFilter", FALSE);
  while (c != NULL) {
    register unsigned int i;
    int matched = TRUE;
    array_header *filters;

    pr_signals_handle();

    if (matched_deny_filter == -1) {
      matched_deny_filter = FALSE;
    }

    filters = c->argv[0];

    for (i = 0; i < filters->nelts; i++) {
      int filter_id, res;
      struct geoip_filter *filter;
      pr_regex_t *filter_re;
      const char *filter_name, *filter_pattern, *filter_value;

      filter = ((struct geoip_filter **) filters->elts)[i];
      filter_id = filter->filter_id;
      filter_pattern = filter->filter_pattern;
      filter_re = filter->filter_re;

      filter_value = get_geoip_filter_value(filter_id);
      if (filter_value == NULL) {
        matched = FALSE;
        break;
      }

      filter_name = get_geoip_filter_name(filter_id);

      res = pr_regexp_exec(filter_re, filter_value, 0, NULL, 0, 0, 0);
      pr_trace_msg(trace_channel, 12,
        "%s filter value %s %s GeoIPDenyFilter pattern '%s'",
        filter_name, filter_value, res == 0 ? "matched" : "did not match",
        filter_pattern);
      if (res == 0) {
        (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
          "%s filter value '%s' matched GeoIPDenyFilter pattern '%s'",
          filter_name, filter_value, filter_pattern);
      } else {
        (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
          "%s filter value '%s' did not match GeoIPDenyFilter pattern '%s'",
          filter_name, filter_value, filter_pattern);
        matched = FALSE;
        break;
      }
    }

    if (matched == TRUE) {
      matched_deny_filter = TRUE;
      break;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "GeoIPDenyFilter", FALSE);
  }
#endif /* !HAVE_REGEX_H or !HAVE_REGCOMP */

  switch (policy) {
    case GEOIP_POLICY_ALLOW_DENY:
      if (matched_deny_filter == TRUE &&
          matched_allow_filter != TRUE) {
        /* If we explicitly matched any deny filters AND have NOT explicitly
         * matched any allow filters, the connection is rejected, otherwise,
         * it is allowed.
         */
        (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
          "client matched GeoIPDenyFilter, rejecting connection");
        allow_conn = -1;

      } else {
        pr_trace_msg(trace_channel, 9,
          "allowing client connection (policy 'allow,deny')");
      }
      break;

    case GEOIP_POLICY_DENY_ALLOW:
      if (matched_allow_filter == FALSE) {
        /* If we have not explicitly matched any allow filters, then
         * reject the connection.
         */
        (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
          "client did not match any GeoIPAllowFilters, rejecting connection");
        allow_conn = -1;

      } else {
        pr_trace_msg(trace_channel, 9,
          "allowing client connection (policy 'deny,allow')");
      }
      break;
  }

  return allow_conn;
}

static const char *get_geoip_filter_name(int filter_id) {
  register unsigned int i;

  for (i = 0; geoip_filter_keys[i].filter_name != NULL; i++) {
    if (geoip_filter_keys[i].filter_id == filter_id) {
      return geoip_filter_keys[i].filter_name;
    }
  }

  errno = ENOENT;
  return NULL;
}

static const char *get_geoip_filter_value(int filter_id) {
  switch (filter_id) {
    case GEOIP_FILTER_KEY_COUNTRY_CODE:
      if (geoip_country_code2 != NULL) {
        return geoip_country_code2;
      }
      break;

    case GEOIP_FILTER_KEY_COUNTRY_CODE3:
      if (geoip_country_code3 != NULL) {
        return geoip_country_code3;
      }
      break;

    case GEOIP_FILTER_KEY_COUNTRY_NAME:
      if (geoip_country_name != NULL) {
        return geoip_country_name;
      }
      break;

    case GEOIP_FILTER_KEY_REGION_CODE:
      if (geoip_region_code != NULL) {
        return geoip_region_code;
      }
      break;

    case GEOIP_FILTER_KEY_REGION_NAME:
      if (geoip_region_name != NULL) {
        return geoip_region_name;
      }
      break;

    case GEOIP_FILTER_KEY_CONTINENT:
      if (geoip_continent_name != NULL) {
        return geoip_continent_name;
      }
      break;

    case GEOIP_FILTER_KEY_ISP:
      if (geoip_isp != NULL) {
        return geoip_isp;
      }
      break;

    case GEOIP_FILTER_KEY_ORGANIZATION:
      if (geoip_org != NULL) {
        return geoip_org;
      }
      break;

    case GEOIP_FILTER_KEY_NETWORK_SPEED:
      if (geoip_network_speed != NULL) {
        return geoip_network_speed;
      }
      break;

    case GEOIP_FILTER_KEY_CITY:
      if (geoip_city != NULL) {
        return geoip_city;
      }
      break;

    case GEOIP_FILTER_KEY_AREA_CODE:
      if (geoip_area_code != NULL) {
        return geoip_area_code;
      }
      break;

    case GEOIP_FILTER_KEY_POSTAL_CODE:
      if (geoip_postal_code != NULL) {
        return geoip_postal_code;
      }
      break;

    case GEOIP_FILTER_KEY_LATITUDE:
      if (geoip_latitude != NULL) {
        return geoip_latitude;
      }
      break;

    case GEOIP_FILTER_KEY_LONGITUDE:
      if (geoip_longitude != NULL) {
        return geoip_longitude;
      }
      break;

    case GEOIP_FILTER_KEY_ASN:
      if (geoip_asn != NULL) {
        return geoip_asn;
      }
      break;

    case GEOIP_FILTER_KEY_PROXY:
      if (geoip_proxy != NULL) {
        return geoip_proxy;
      }
      break;

    case GEOIP_FILTER_KEY_TIMEZONE:
      if (geoip_timezone != NULL) {
        return geoip_timezone;
      }
      break;
  }

  errno = ENOENT;
  return NULL;
}

static void get_geoip_tables(array_header *geoips, int filter_flags,
    int skip_standard) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "GeoIPTable", FALSE);
  while (c) {
    GeoIP *gi;
    const char *path;
    int flags, use_utf8 = FALSE;

    pr_signals_handle();

    path = c->argv[0];
    flags = *((int *) c->argv[1]);
    use_utf8 = *((int *) c->argv[2]);

    /* Make sure we open tables that are marked with the default
     * GEOIP_STANDARD flag, which has a value of zero.
     */
    if (flags == GEOIP_STANDARD && skip_standard == TRUE) { 
      pr_trace_msg(trace_channel, 15,
        "skipping loading GeoIP table '%s'", path);
      c = find_config_next(c, c->next, CONF_PARAM, "GeoIPTable", FALSE);
      continue;
    } 

    PRIVS_ROOT
    gi = GeoIP_open(path, flags);
    if (gi == NULL &&
        (flags & GEOIP_INDEX_CACHE)) {
      /* Per Bug#3975, a common cause of this error is the fact that some
       * of the Maxmind GeoIP Lite database files simply do not have indexes.
       * So try to open them as standard databases as a fallback.
       */
      pr_log_debug(DEBUG8, MOD_GEOIP_VERSION
        ": unable to open GeoIPTable '%s' using the IndexCache flag "
        "(database lacks index?), retrying without IndexCache flag", path);
      flags &= ~GEOIP_INDEX_CACHE;
      gi = GeoIP_open(path, flags);
    }
    PRIVS_RELINQUISH

    if (gi != NULL) {
      if (use_utf8) {
        GeoIP_set_charset(gi, GEOIP_CHARSET_UTF8); 
      }

      *((GeoIP **) push_array(geoips)) = gi;

      pr_trace_msg(trace_channel, 15, "loaded GeoIP table '%s': %s (type %d)",
        path, GeoIP_database_info(gi), GeoIP_database_edition(gi));

    } else {
      /* XXX Sigh.  Stupid libGeoIP library logs to stdout/stderr, rather
       * than providing a strerror function.  Grr!
       */

      pr_log_pri(PR_LOG_WARNING, MOD_GEOIP_VERSION
        ": warning: unable to open/use GeoIPTable '%s'", path);
    }

    c = find_config_next(c, c->next, CONF_PARAM, "GeoIPTable", FALSE);
  }

  if (geoips->nelts == 0 &&
      static_geoips->nelts == 0 &&
      ((filter_flags == GEOIP_STANDARD) ||
       (filter_flags & GEOIP_CHECK_CACHE))) {
    GeoIP *gi;

    /* Let the library use its own default database file(s), if no others
     * have been configured.
     */

    PRIVS_ROOT
    gi = GeoIP_new(GEOIP_STANDARD);
    PRIVS_RELINQUISH

    if (gi != NULL) {
      *((GeoIP **) push_array(geoips)) = gi;

      pr_trace_msg(trace_channel, 15,
        "loaded default GeoIP table: %s (type %d)",
        GeoIP_database_info(gi), GeoIP_database_edition(gi));

    } else {
      pr_log_pri(PR_LOG_WARNING, MOD_GEOIP_VERSION
        ": warning: unable to open/use default GeoIP library database file(s)");
    }
  }
}

static void remove_geoip_tables(array_header *geoips) {
  register unsigned int i;
  GeoIP **gis;

  if (geoips == NULL ||
      geoips->nelts == 0) {
    return;
  }

  gis = geoips->elts;
  for (i = 0; i < geoips->nelts; i++) {
    if (gis[i] != NULL) {
      GeoIP_delete(gis[i]);
      gis[i] = NULL;
    }
  }
}

static void get_geoip_data(array_header *geoips, const char *ip_addr) {
  register unsigned int i;
  GeoIP **gis;

  gis = geoips->elts;
  for (i = 0; i < geoips->nelts; i++) {
    unsigned char db_type = -1;

    if (gis[i] == NULL) {
      continue;
    }

    db_type = GeoIP_database_edition(gis[i]);

    /* These types are defined in <GeoIP.h>'s GeoIPDBTypes enum. */
    switch (db_type) {
      case GEOIP_COUNTRY_EDITION:
      case GEOIP_COUNTRY_EDITION_V6: {
        int geoip_id;

        geoip_id = GeoIP_id_by_addr(gis[i], ip_addr);
#ifdef PR_USE_IPV6
        if (geoip_id <= 0 &&
            pr_netaddr_use_ipv6()) {

            pr_trace_msg(trace_channel, 2,
              "unable to find GeoIP country ID for IP address '%s', "
              "attempting lookup as IPv6 address", ip_addr);

            /* Try looking up the GeoIP ID using their IPv6 API. */
            geoip_id = GeoIP_id_by_addr_v6(gis[i], ip_addr);
        }
#endif /* PR_USE_IPV6 */

        if (geoip_id <= 0) {
          break;
        }

        geoip_continent_name = GeoIP_continent_by_id(geoip_id);
        geoip_country_code2 = GeoIP_code_by_id(geoip_id);
        geoip_country_code3 = GeoIP_code3_by_id(geoip_id);
        geoip_country_name = GeoIP_name_by_id(geoip_id);

        break;
      }

      case GEOIP_NETSPEED_EDITION: {
        int geoip_id;

        /* Apparently for NetSpeed database files, the GeoIP ID indicates
         * the speed, via the GeoIPNetspeedValues enum.
         */
        geoip_id = GeoIP_id_by_addr(gis[i], ip_addr);
#ifdef PR_USE_IPV6
        if (geoip_id <= 0 &&
            pr_netaddr_use_ipv6()) {

            pr_trace_msg(trace_channel, 2,
              "unable to find GeoIP network speed ID for IP address '%s', "
              "attempting lookup as IPv6 address", ip_addr);

            /* Try looking up the GeoIP ID using their IPv6 API. */
            geoip_id = GeoIP_id_by_addr_v6(gis[i], ip_addr);
        }
#endif /* PR_USE_IPV6 */

        switch (geoip_id) {
           case GEOIP_UNKNOWN_SPEED:
             geoip_network_speed = "unknown";
             break;

           case GEOIP_DIALUP_SPEED:
             geoip_network_speed = "dialup";
             break;

           case GEOIP_CABLEDSL_SPEED:
             geoip_network_speed = "cabledsl";
             break;

           case GEOIP_CORPORATE_SPEED:
             geoip_network_speed = "corporate";
             break;

           default:
             (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
               "unknown netspeed value (%d), ignoring", geoip_id);
             break;
        }

        break;
      }

      case GEOIP_ASNUM_EDITION:
        geoip_asn = GeoIP_name_by_addr(gis[i], ip_addr);
#ifdef PR_USE_IPV6
        if (geoip_asn == NULL &&
            pr_netaddr_use_ipv6()) {

            (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
              "unable to find GeoIP ASN for IP address '%s', "
              "attempting lookup as IPv6 address", ip_addr);

            /* Try looking up the GeoIP ASN using their IPv6 API. */
            geoip_asn = GeoIP_name_by_addr_v6(gis[i], ip_addr);
        }
#endif /* PR_USE_IPV6 */
        break;

      case GEOIP_ORG_EDITION:
        geoip_org = GeoIP_name_by_addr(gis[i], ip_addr);
#ifdef PR_USE_IPV6
        if (geoip_org == NULL &&
            pr_netaddr_use_ipv6()) {

            (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
              "unable to find GeoIP organization for IP address '%s', "
              "attempting lookup as IPv6 address", ip_addr);

            /* Try looking up the GeoIP name using their IPv6 API. */
            geoip_org = GeoIP_name_by_addr_v6(gis[i], ip_addr);
        }
#endif /* PR_USE_IPV6 */
        break;

      case GEOIP_ISP_EDITION:
        geoip_isp = GeoIP_name_by_addr(gis[i], ip_addr);
#ifdef PR_USE_IPV6
        if (geoip_isp == NULL &&
            pr_netaddr_use_ipv6()) {

            pr_trace_msg(trace_channel, 2,
              "unable to find GeoIP ISP for IP address '%s', "
              "attempting lookup as IPv6 address", ip_addr);

            /* Try looking up the GeoIP name using their IPv6 API. */
            geoip_isp = GeoIP_name_by_addr_v6(gis[i], ip_addr);
        }
#endif /* PR_USE_IPV6 */
        break;

      case GEOIP_REGION_EDITION_REV0:
      case GEOIP_REGION_EDITION_REV1: {
        GeoIPRegion *geoip_region = NULL;
        const char *region_name = NULL, *tz = NULL;

        geoip_region = GeoIP_region_by_addr(gis[i], ip_addr);
#ifdef PR_USE_IPV6
        if (geoip_region == NULL &&
            pr_netaddr_use_ipv6()) {

            pr_trace_msg(trace_channel, 2,
              "unable to find GeoIP region for IP address '%s', "
              "attempting lookup as IPv6 address", ip_addr);

            /* Try looking up the GeoIP region using their IPv6 API. */
            geoip_region = GeoIP_region_by_addr_v6(gis[i], ip_addr);
        }
#endif /* PR_USE_IPV6 */

        if (geoip_region == NULL) {
          break;
        }

        if (geoip_region->region[0]) {
          geoip_region_code = pstrdup(session.pool, geoip_region->region);
        }

        region_name = GeoIP_region_name_by_code(geoip_region->country_code,
          geoip_region->region);
        if (region_name != NULL) {
          geoip_region_name = pstrdup(session.pool, region_name);
        }

        tz = GeoIP_time_zone_by_country_and_region(geoip_region->country_code,
          geoip_region->region);
        if (tz != NULL) {
          geoip_timezone = pstrdup(session.pool, tz);
        }

        GeoIPRegion_delete(geoip_region);
        break;
      }

      case GEOIP_CITY_EDITION_REV0:
      case GEOIP_CITY_EDITION_REV1: {
        GeoIPRecord *geoip_record = NULL;
        char area_code_str[32], lat_str[64], lon_str[64];

        geoip_record = GeoIP_record_by_addr(gis[i], ip_addr);
#ifdef PR_USE_IPV6
        if (geoip_record == NULL &&
            pr_netaddr_use_ipv6()) {

            pr_trace_msg(trace_channel, 2,
              "unable to find GeoIP city record for IP address '%s', "
              "attempting lookup as IPv6 address", ip_addr);

            /* Try looking up the GeoIP record using their IPv6 API. */
            geoip_record = GeoIP_record_by_addr_v6(gis[i], ip_addr);
        }
#endif /* PR_USE_IPV6 */

        if (geoip_record == NULL) {
          break;
        }

        /* We use pstrdup() here on the fields of the retrieved record,
         * since the record is going to be freed once we're done, and we
         * don't want to be holding on to stale pointers.
         */
        geoip_continent_name = pstrdup(session.pool,
          geoip_record->continent_code);
        geoip_country_code2 = pstrdup(session.pool, geoip_record->country_code);
        geoip_country_code3 = pstrdup(session.pool, geoip_record->country_code3);
        geoip_country_name = pstrdup(session.pool, geoip_record->country_name);

        if (geoip_record->city != NULL) {
          geoip_city = pstrdup(session.pool, geoip_record->city);
        }

        if (geoip_record->postal_code != NULL) {
          geoip_postal_code = pstrdup(session.pool, geoip_record->postal_code);
        }

        memset(area_code_str, '\0', sizeof(area_code_str));
        pr_snprintf(area_code_str, sizeof(area_code_str)-1, "%d",
          geoip_record->area_code);
        geoip_area_code = pstrdup(session.pool, area_code_str);

        memset(lat_str, '\0', sizeof(lat_str));
        pr_snprintf(lat_str, sizeof(lat_str)-1, "%f", geoip_record->latitude);
        geoip_latitude = pstrdup(session.pool, lat_str);

        memset(lon_str, '\0', sizeof(lon_str));
        pr_snprintf(lon_str, sizeof(lon_str)-1, "%f", geoip_record->longitude);
        geoip_longitude = pstrdup(session.pool, lon_str);

        if (geoip_record->region != NULL &&
            geoip_record->region[0]) {
          geoip_region_code = pstrdup(session.pool, geoip_record->region);
        }

        if (geoip_record->country_code != NULL) {
          const char *region_name, *tz;

          region_name = GeoIP_region_name_by_code(geoip_record->country_code,
            geoip_record->region);
          if (region_name != NULL) {
            geoip_region_name = pstrdup(session.pool, region_name);
          }

          tz = GeoIP_time_zone_by_country_and_region(
            geoip_record->country_code, geoip_record->region);
          if (tz != NULL) {
            geoip_timezone = pstrdup(session.pool, tz);
          }
        }

        GeoIPRecord_delete(geoip_record);
        break;
      }

      case GEOIP_PROXY_EDITION: {
        int geoip_id;

        geoip_id = GeoIP_id_by_addr(gis[i], ip_addr);
#ifdef PR_USE_IPV6
        if (geoip_id <= 0 &&
            pr_netaddr_use_ipv6()) {

            pr_trace_msg(trace_channel, 2,
              "unable to find GeoIP proxy ID for IP address '%s', "
              "attempting lookup as IPv6 address", ip_addr);

            /* Try looking up the GeoIP ID using their IPv6 API. */
            geoip_id = GeoIP_id_by_addr_v6(gis[i], ip_addr);
        }
#endif /* PR_USE_IPV6 */

        if (geoip_id == 0) {
          break;
        }

        switch (geoip_id) {
           case GEOIP_ANON_PROXY:
             geoip_proxy = "anonymous";
             break;

           default:
             (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
               "unknown proxy value (%d), ignoring", geoip_id);
             break;
        }

        break;
      }

      default:
        (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
          "unknown database type (%d), skipping", db_type);
        break;
    }
  }
}

static void get_geoip_info(array_header *sess_geoips) {
  const char *ip_addr; 

  ip_addr = pr_netaddr_get_ipstr(session.c->remote_addr);

  get_geoip_data(static_geoips, ip_addr);
  get_geoip_data(sess_geoips, ip_addr);

  if (geoip_country_code2 != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: 2-Letter country code: %s", ip_addr,
      geoip_country_code2);
  }

  if (geoip_country_code3 != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: 3-Letter country code: %s", ip_addr,
      geoip_country_code3);
  }

  if (geoip_country_name != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Country name: %s", ip_addr,
      geoip_country_name);
  }

  if (geoip_region_code != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Region code: %s", ip_addr,
      geoip_region_code);
  }

  if (geoip_region_name != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Region name: %s", ip_addr,
      geoip_region_name);
  }

  if (geoip_timezone != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Timezone: %s", ip_addr, geoip_timezone);
  }

  if (geoip_continent_name != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Continent name: %s", ip_addr,
      geoip_continent_name);
  }

  if (geoip_isp != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: ISP: %s", ip_addr, geoip_isp);
  }

  if (geoip_org != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Organization: %s", ip_addr, geoip_org);
  }

  if (geoip_network_speed != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Network speed: %s", ip_addr,
      geoip_network_speed);
  }

  if (geoip_city != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: City: %s", ip_addr, geoip_city);
  }

  if (geoip_area_code != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Area code: %s", ip_addr,
      geoip_area_code);
  }

  if (geoip_postal_code != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Postal code: %s", ip_addr,
      geoip_postal_code);
  }

  if (geoip_latitude != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Latitude: %s", ip_addr,
      geoip_latitude);
  }

  if (geoip_longitude != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Longitude: %s", ip_addr,
      geoip_longitude);
  }

  if (geoip_asn != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: ASN: %s", ip_addr, geoip_asn);
  }

  if (geoip_proxy != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Proxy: %s", ip_addr, geoip_proxy);
  }
}

static void set_geoip_value(const char *key, const char *value) {
  int res;

  res = pr_env_set(session.pool, key, value);
  if (res < 0) {
    (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
      "error setting %s environment variable: %s", key, strerror(errno));
  }

  res = pr_table_add_dup(session.notes, pstrdup(session.pool, key),
    (char *) value, 0);
  if (res < 0) {
    (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
      "error adding %s session note: %s", key, strerror(errno));
  }
}

static void set_geoip_values(void) {

  if (geoip_country_code2 != NULL) {
    set_geoip_value("GEOIP_COUNTRY_CODE", geoip_country_code2);
  }

  if (geoip_country_code3 != NULL) {
    set_geoip_value("GEOIP_COUNTRY_CODE3", geoip_country_code3);
  }

  if (geoip_country_name != NULL) {
    set_geoip_value("GEOIP_COUNTRY_NAME", geoip_country_name);
  }

  if (geoip_region_code != NULL) {
    set_geoip_value("GEOIP_REGION", geoip_region_code);
  }

  if (geoip_region_name != NULL) {
    set_geoip_value("GEOIP_REGION_NAME", geoip_region_name);
  }

  if (geoip_continent_name != NULL) {
    set_geoip_value("GEOIP_CONTINENT_CODE", geoip_continent_name);
  }

  if (geoip_isp != NULL) {
    set_geoip_value("GEOIP_ISP", geoip_isp);
  }

  if (geoip_org != NULL) {
    set_geoip_value("GEOIP_ORGANIZATION", geoip_org);
  }

  if (geoip_network_speed != NULL) {
    set_geoip_value("GEOIP_NETSPEED", geoip_network_speed);
  }

  if (geoip_city != NULL) {
    set_geoip_value("GEOIP_CITY", geoip_city);
  }

  if (geoip_area_code != NULL) {
    set_geoip_value("GEOIP_AREA_CODE", geoip_area_code);
  }

  if (geoip_postal_code != NULL) {
    set_geoip_value("GEOIP_POSTAL_CODE", geoip_postal_code);
  }

  if (geoip_latitude != NULL) {
    set_geoip_value("GEOIP_LATITUDE", geoip_latitude);
  }

  if (geoip_longitude != NULL) {
    set_geoip_value("GEOIP_LONGITUDE", geoip_longitude);
  }

  if (geoip_asn != NULL) {
    set_geoip_value("GEOIP_ASN", geoip_asn);
  }

  if (geoip_proxy != NULL) {
    set_geoip_value("GEOIP_PROXY", geoip_proxy);
  }

  if (geoip_timezone != NULL) {
    set_geoip_value("GEOIP_TIMEZONE", geoip_timezone);
  }

}

/* Configuration handlers
 */

/* usage:
 *  GeoIPAllowFilter key1 regex1 [key2 regex2 ...]
 *                   sql:/...
 *  GeoIPDenyFilter key1 regex1 [key2 regex2 ...]
 *                  sql:/...
 */
MODRET set_geoipfilter(cmd_rec *cmd) {
#if PR_USE_REGEX
  config_rec *c;
  array_header *deferred_patterns, *filters;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (cmd->argc == 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  /* IFF the first parameter starts with "sql:/", then we expect ONLY one
   * parameter.  If not, then we expect an even number of parameters.
   */

  if (strncmp(cmd->argv[1], "sql:/", 5) == 0) {
    if (cmd->argc > 2) {
      CONF_ERROR(cmd, "wrong number of parameters");
    }

  } else {
    if ((cmd->argc-1) % 2 != 0) {
      CONF_ERROR(cmd, "wrong number of parameters");
    }
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  filters = make_array(c->pool, 0, sizeof(struct geoip_filter *));
  deferred_patterns = make_array(c->pool, 0, sizeof(char *));

  if (cmd->argc == 2) {
    const char *pattern;

    pattern = cmd->argv[1];

    /* Advance past the "sql:/" prefix. */
    *((char **) push_array(deferred_patterns)) = pstrdup(c->pool, pattern + 5);

  } else {
    register unsigned int i;

    for (i = 1; i < cmd->argc; i += 2) {
      const char *filter_name, *pattern = NULL;
      struct geoip_filter *filter;

      filter_name = cmd->argv[i];
      pattern = cmd->argv[i+1];

      filter = make_filter(c->pool, filter_name, pattern);
      if (filter == NULL) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to use '",
          filter_name, " ", pattern, "' as filter: ", strerror(errno), NULL));
      }

      *((struct geoip_filter **) push_array(filters)) = filter;
    }
  }

  c->argv[0] = filters;
  c->argv[1] = deferred_patterns;
  return PR_HANDLED(cmd);

#else /* no regular expression support at the moment */
  CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "The ", cmd->argv[0],
    " directive cannot be used on this system, as you do not have POSIX "
    "compliant regex support", NULL));
#endif
}

/* usage: GeoIPEngine on|off */
MODRET set_geoipengine(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: GeoIPLog path|"none" */
MODRET set_geoiplog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: GeoIPPolicy "allow,deny"|"deny,allow" */
MODRET set_geoippolicy(cmd_rec *cmd) {
  geoip_policy_e policy;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "allow,deny") == 0) {
    policy = GEOIP_POLICY_ALLOW_DENY;

  } else if (strcasecmp(cmd->argv[1], "deny,allow") == 0) {
    policy = GEOIP_POLICY_DENY_ALLOW;

  } else {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": '", cmd->argv[1],
      "' is not one of the approved GeoIPPolicy settings", NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(geoip_policy_e));
  *((geoip_policy_e *) c->argv[0]) = policy;

  return PR_HANDLED(cmd);
}

/* usage: GeoIPTable path [flags] */
MODRET set_geoiptable(cmd_rec *cmd) {
  config_rec *c;
  int flags = GEOIP_STANDARD, use_utf8 = FALSE;
  char *path;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  path = cmd->argv[1];

  if (cmd->argc > 2) {
    register unsigned int i;

    for (i = 2; i < cmd->argc; i++) {
      if (strcasecmp(cmd->argv[i], "Standard") == 0) {
        /* No-op. */

      } else if (strcasecmp(cmd->argv[i], "MemoryCache") == 0) {
        flags |= GEOIP_MEMORY_CACHE;

      } else if (strcasecmp(cmd->argv[i], "MMapCache") == 0) {
        flags |= GEOIP_MMAP_CACHE;

      } else if (strcasecmp(cmd->argv[i], "IndexCache") == 0) {
        flags |= GEOIP_INDEX_CACHE;

      } else if (strcasecmp(cmd->argv[i], "CheckCache") == 0) {
        flags |= GEOIP_CHECK_CACHE;

      } else if (strcasecmp(cmd->argv[i], "UTF8") == 0) {
        use_utf8 = TRUE;

      } else {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown GeoIPTable flag '",
          cmd->argv[i], "'", NULL));
      }
    }
  }

  c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, path);
  c->argv[1] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = flags;
  c->argv[2] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[2]) = use_utf8;

  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET geoip_post_pass(cmd_rec *cmd) {
  int res;

  if (geoip_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Scan for any deferred GeoIP filters and resolve them. */
  resolve_deferred_filters(cmd->tmp_pool);

  /* Modules such as mod_ifsession may have added new filters; check the
   * filters again.
   */
  res = check_geoip_filters(geoip_policy);
  if (res < 0) {
    (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
      "connection from %s denied due to GeoIP filter/policy",
      pr_netaddr_get_ipstr(session.c->remote_addr));
    pr_log_pri(PR_LOG_NOTICE, MOD_GEOIP_VERSION
      ": Connection denied to %s due to GeoIP filter/policy",
      pr_netaddr_get_ipstr(session.c->remote_addr));

    pr_event_generate("mod_geoip.connection-denied", NULL);
    pr_session_disconnect(&geoip_module, PR_SESS_DISCONNECT_CONFIG_ACL,
      "GeoIP Filters");
  }

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void geoip_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_geoip.c", (const char *) event_data) == 0) {
    remove_geoip_tables(static_geoips);
    destroy_pool(geoip_pool);

    /* Unregister ourselves from all events. */
    pr_event_unregister(&geoip_module, NULL, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

static void geoip_postparse_ev(const void *event_data, void *user_data) {
  int filter_flags;

  filter_flags = GEOIP_MEMORY_CACHE|GEOIP_MMAP_CACHE|GEOIP_INDEX_CACHE;

  pr_log_debug(DEBUG8, MOD_GEOIP_VERSION ": loading static GeoIP tables");
  get_geoip_tables(static_geoips, filter_flags, TRUE);
}

static void geoip_restart_ev(const void *event_data, void *user_data) {
  remove_geoip_tables(static_geoips);

  destroy_pool(geoip_pool);

  geoip_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(geoip_pool, MOD_GEOIP_VERSION);

  static_geoips = make_array(geoip_pool, 0, sizeof(GeoIP *));
}

/* Initialization functions
 */

static int geoip_init(void) {
  geoip_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(geoip_pool, MOD_GEOIP_VERSION);

  static_geoips = make_array(geoip_pool, 0, sizeof(GeoIP *));

#if defined(PR_SHARED_MODULE)
  pr_event_register(&geoip_module, "core.module-unload", geoip_mod_unload_ev,
    NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&geoip_module, "core.postparse", geoip_postparse_ev, NULL);
  pr_event_register(&geoip_module, "core.restart", geoip_restart_ev, NULL);

  return 0;
}

static int geoip_sess_init(void) {
  config_rec *c;
  array_header *sess_geoips;
  int res;
  pool *tmp_pool;

  c = find_config(main_server->conf, CONF_PARAM, "GeoIPEngine", FALSE);
  if (c) {
    geoip_engine = *((int *) c->argv[0]);
  }

  if (geoip_engine == FALSE) {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "GeoIPLog", FALSE);
  if (c) {
    char *path;

    path = c->argv[0];
    if (strcasecmp(path, "none") != 0) {
      int xerrno;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(path, &geoip_logfd, PR_LOG_SYSTEM_MODE);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      if (res < 0) {
        if (res == -1) {
          pr_log_pri(PR_LOG_NOTICE, MOD_GEOIP_VERSION
            ": notice: unable to open GeoIPLog '%s': %s", path,
            strerror(xerrno));

        } else if (res == PR_LOG_WRITABLE_DIR) {
          pr_log_pri(PR_LOG_WARNING, MOD_GEOIP_VERSION
            ": notice: unable to open GeoIPLog '%s': parent directory is "
            "world-writable", path);

        } else if (res == PR_LOG_SYMLINK) {
          pr_log_pri(PR_LOG_WARNING, MOD_GEOIP_VERSION
            ": notice: unable to open GeoIPLog '%s': cannot log to a symlink",
            path);
        }
      }
    }
  }

  tmp_pool = make_sub_pool(geoip_pool);
  pr_pool_tag(tmp_pool, "GeoIP Session Pool");

  sess_geoips = make_array(tmp_pool, 0, sizeof(GeoIP *));

  pr_log_debug(DEBUG8, MOD_GEOIP_VERSION ": loading session GeoIP tables");
  get_geoip_tables(sess_geoips, GEOIP_CHECK_CACHE, FALSE);

  if (static_geoips->nelts == 0 &&
      sess_geoips->nelts == 0) {
    (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
      "no usable GeoIPTable files found, skipping GeoIP lookups");

    (void) close(geoip_logfd);
    destroy_pool(tmp_pool);
    return 0;
  }

  get_geoip_info(sess_geoips);

  c = find_config(main_server->conf, CONF_PARAM, "GeoIPPolicy", FALSE);
  if (c != NULL) {
    geoip_policy = *((geoip_policy_e *) c->argv[0]);
  }

  switch (geoip_policy) {
    case GEOIP_POLICY_ALLOW_DENY:
      pr_trace_msg(trace_channel, 8,
        "using policy of allowing connections unless rejected by "
        "GeoIPDenyFilters");
      break;

    case GEOIP_POLICY_DENY_ALLOW:
      pr_trace_msg(trace_channel, 8,
        "using policy of rejecting connections unless allowed by "
        "GeoIPAllowFilters");
      break;
  }

  res = check_geoip_filters(geoip_policy);
  if (res < 0) {
    (void) pr_log_writefile(geoip_logfd, MOD_GEOIP_VERSION,
      "connection from %s denied due to GeoIP filter/policy",
      pr_netaddr_get_ipstr(session.c->remote_addr));
    pr_log_pri(PR_LOG_NOTICE, MOD_GEOIP_VERSION
      ": Connection denied to %s due to GeoIP filter/policy",
      pr_netaddr_get_ipstr(session.c->remote_addr));

    pr_event_generate("mod_geoip.connection-denied", NULL);

    /* XXX send_geoip_mesg(tmp_pool, mesg) */
    destroy_pool(tmp_pool);

    errno = EACCES;
    return -1;
  }

  set_geoip_values();
  remove_geoip_tables(sess_geoips);

  destroy_pool(tmp_pool);
  return 0;
}

/* Module API tables
 */

static conftable geoip_conftab[] = {
  { "GeoIPAllowFilter",	set_geoipfilter,	NULL },
  { "GeoIPDenyFilter",	set_geoipfilter,	NULL },
  { "GeoIPEngine",	set_geoipengine,	NULL },
  { "GeoIPLog",		set_geoiplog,		NULL },
  { "GeoIPPolicy",	set_geoippolicy,	NULL },
  { "GeoIPTable",	set_geoiptable,		NULL },
  { NULL }
};

static cmdtable geoip_cmdtab[] = {
  { POST_CMD,	C_PASS,	G_NONE,	geoip_post_pass,	FALSE, FALSE },
  { 0, NULL },
};

module geoip_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "geoip",

  /* Module configuration handler table */
  geoip_conftab,

  /* Module command handler table */
  geoip_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  geoip_init,

  /* Session initialization function */
  geoip_sess_init,

  /* Module version */
  MOD_GEOIP_VERSION
};
