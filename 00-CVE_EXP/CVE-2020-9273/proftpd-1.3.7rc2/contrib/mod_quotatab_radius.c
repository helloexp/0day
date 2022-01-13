/*
 * ProFTPD: mod_quotatab_radius -- a mod_quotatab sub-module for obtaining
 *                                 quota information from RADIUS servers.
 *
 * Copyright (c) 2005-2014 TJ Saunders
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
 * As a special exemption, the respective copyright holders give permission
 * to link this program with OpenSSL, and distribute the resulting
 * executable, without including the source code for OpenSSL in the source
 * distribution.
 */

#include "mod_quotatab.h"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030001
# error "ProFTPD 1.3.0rc1 or later required"
#endif

module quotatab_radius_module;

static int radiustab_close(quota_table_t *radiustab) {

  /* Nothing really needs to be done here. */
  return 0;
}

static unsigned char radiustab_lookup(quota_table_t *radiustab, void *ptr,
    const char *name, quota_type_t quota_type) {
  char **values = NULL;
  array_header *data = NULL;
  pool *tmp_pool = NULL;
  cmdtable *cmdtab = NULL;
  cmd_rec *cmd = NULL;
  modret_t *res = NULL;
  quota_limit_t *limit = ptr;

  if (quota_type != USER_QUOTA) {
    quotatab_log("error: mod_quotatab_radius only supports user quotas");
    return FALSE;
  }

  /* Find the cmdtable for the radius_quota_lookup command. */
  cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "radius_quota_lookup", NULL,
    NULL, NULL);
  if (cmdtab == NULL) {
    quotatab_log("error: unable to find RADIUS hook symbol "
      "'radius_quota_lookup'");
    return FALSE;
  }

  /* Allocate a temporary pool for the duration of this lookup. */
  tmp_pool = make_sub_pool(radiustab->tab_pool);

  /* Prepare the command and call the handler. */
  cmd = pr_cmd_alloc(tmp_pool, 1, name);
  res = pr_module_call(cmdtab->m, cmdtab->handler, cmd);

  destroy_pool(tmp_pool);

  /* Check the results. */
  if (!res || MODRET_ISERROR(res)) {
    quotatab_log("error retrieving RADIUS quota attributes");
    return FALSE;
  }

  data = (array_header *) res->data;
  if (data->nelts != 9) {
    quotatab_log("RADIUS server returned wrong number of attributes");
    return FALSE;
  }

  values = (char **) data->elts;

  /* Retrieve the limit record (9 values):
   *  name
   *  per_session
   *  limit_type
   *  bytes_{in,out,xfer}_avail
   *  files_{in,out,xfer}_avail
   */

  memmove(limit->name, values[0], strlen(values[0]) + 1);
  limit->quota_type = USER_QUOTA;

  if (strcasecmp(values[1], "false") == 0) {
    limit->quota_per_session = FALSE;

  } else if (strcasecmp(values[1], "true") == 0) {
    limit->quota_per_session = TRUE;
  }

  if (strcasecmp(values[2], "soft") == 0) {
    limit->quota_limit_type = SOFT_LIMIT;

  } else if (strcasecmp(values[2], "hard") == 0) {
    limit->quota_limit_type = HARD_LIMIT;
  }

  limit->bytes_in_avail = atof(values[3]);
  limit->bytes_out_avail = atof(values[4]);
  limit->bytes_xfer_avail = atof(values[5]);
  limit->files_in_avail = atoi(values[6]);
  limit->files_out_avail = atoi(values[7]);
  limit->files_xfer_avail = atoi(values[8]);

  return TRUE;
}

static unsigned char radiustab_verify(quota_table_t *radiustab) {

  /* Always TRUE. */
  return TRUE;
}

static quota_table_t *radiustab_open(pool *parent_pool,
    quota_tabtype_t tab_type, const char *srcinfo) {
  pool *tab_pool = make_sub_pool(parent_pool);
  quota_table_t *tab = NULL;

  tab = (quota_table_t *) pcalloc(tab_pool, sizeof(quota_table_t));
  tab->tab_pool = tab_pool;
  tab->tab_type = tab_type;

  /* Set all the necessary function pointers. */
  tab->tab_close = radiustab_close;
  tab->tab_lookup = radiustab_lookup;
  tab->tab_verify = radiustab_verify;

  return tab;
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void radiustab_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_quotatab_radius.c", (const char *) event_data) == 0) {
    pr_event_unregister(&quotatab_radius_module, NULL, NULL);
    quotatab_unregister_backend("radius", QUOTATAB_LIMIT_SRC);
  }
}
#endif /* PR_SHARED_MODULE */

/* Initialization routines
 */

static int radiustab_init(void) {
  quotatab_register_backend("radius", radiustab_open, QUOTATAB_LIMIT_SRC);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&quotatab_radius_module, "core.module-unload",
    radiustab_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  return 0;
}

module quotatab_radius_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "quotatab_radius",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  radiustab_init,

  /* Module child initialization function */
  NULL
};
