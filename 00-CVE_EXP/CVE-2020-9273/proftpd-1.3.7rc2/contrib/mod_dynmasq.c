/*
 * ProFTPD: mod_dynmasq -- a module for dynamically updating MasqueradeAddress
 *                         configurations, as when DynDNS names are used
 * Copyright (c) 2004-2016 TJ Saunders
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
 * This is mod_dynmasq, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"

#ifdef PR_USE_CTRLS
# include "mod_ctrls.h"
#endif

#define MOD_DYNMASQ_VERSION		"mod_dynmasq/0.5"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030602
# error "ProFTPD 1.3.6rc2 or later required"
#endif

extern xaset_t *server_list;
module dynmasq_module;
static int dynmasq_timer_id = -1;
static int dynmasq_timer_interval = -1;

#ifdef PR_USE_CTRLS
static pool *dynmasq_act_pool = NULL;
static ctrls_acttab_t dynmasq_acttab[];
#endif /* PR_USE_CTRLS */

static void dynmasq_refresh(void) {
  server_rec *s;

  pr_log_debug(DEBUG2, MOD_DYNMASQ_VERSION
    ": resolving all MasqueradeAddress directives (could take a little while)");

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    config_rec *c;

    c = find_config(s->conf, CONF_PARAM, "MasqueradeAddress", FALSE);
    if (c != NULL) {
      const char *masq_addr;
      const pr_netaddr_t *na;

      masq_addr = c->argv[1];

      pr_netaddr_clear_ipcache(masq_addr);
      na = pr_netaddr_get_addr(s->pool, masq_addr, NULL);
      if (na != NULL) {
        /* Compare the obtained netaddr with the one already present.
         * Only update the "live" netaddr if they differ.
         */
        pr_log_debug(DEBUG2, MOD_DYNMASQ_VERSION
          ": resolved MasqueradeAddress '%s' to IP address %s", masq_addr,
          pr_netaddr_get_ipstr(na));

        if (pr_netaddr_cmp(c->argv[0], na) != 0) {
          pr_log_pri(PR_LOG_DEBUG, MOD_DYNMASQ_VERSION
            ": MasqueradeAddress '%s' updated for new address %s (was %s)",
            masq_addr, pr_netaddr_get_ipstr(na),
            pr_netaddr_get_ipstr(c->argv[0]));

          /* Overwrite the old netaddr pointer.  Note that this constitutes
           * a minor memory leak, as there currently isn't a way to free
           * the memory used by a netaddr object.  Hrm.
           */
          c->argv[0] = (void *) na;

        } else {
          pr_log_debug(DEBUG2, MOD_DYNMASQ_VERSION
            ": MasqueradeAddress '%s' has not changed addresses", masq_addr);
        }
 
      } else {
        pr_log_pri(PR_LOG_INFO, MOD_DYNMASQ_VERSION
          ": unable to resolve '%s', keeping previous address", masq_addr);
      }
    }
  }

  return;
}

#ifdef PR_USE_CTRLS
static int dynmasq_handle_refresh(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  dynmasq_refresh();
  pr_ctrls_add_response(ctrl, "dynmasq: refreshed");
  return 0;
}

static int dynmasq_handle_dynmasq(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  /* Sanity check */
  if (reqargc == 0 ||
      reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "dynmasq: missing required parameters");
    return -1;
  }

  if (strcmp(reqargv[0], "refresh") == 0) {

    /* Check the ACLs. */
    if (!pr_ctrls_check_acl(ctrl, dynmasq_acttab, "refresh")) {
      pr_ctrls_add_response(ctrl, "access denied");
      return -1;
    }

    return dynmasq_handle_refresh(ctrl, --reqargc, ++reqargv);
  }

  pr_ctrls_add_response(ctrl, "dynmasq: unknown dynmasq action: '%s'",
    reqargv[0]);
  return -1;
}
#endif /* PR_USE_CTRLS */

/* Configuration handlers
 */

/* usage: DynMasqControlsACLs actions|all allow|deny user|group list */
MODRET set_dynmasqctrlsacls(cmd_rec *cmd) {
#ifdef PR_USE_CTRLS
  char *bad_action = NULL, **actions = NULL;

  CHECK_ARGS(cmd, 4);
  CHECK_CONF(cmd, CONF_ROOT);

  /* We can cheat here, and use the ctrls_parse_acl() routine to
   * separate the given string...
   */
  actions = ctrls_parse_acl(cmd->tmp_pool, cmd->argv[1]);

  /* Check the second parameter to make sure it is "allow" or "deny" */
  if (strcmp(cmd->argv[2], "allow") != 0 &&
      strcmp(cmd->argv[2], "deny") != 0) {
    CONF_ERROR(cmd, "second parameter must be 'allow' or 'deny'");
  }

  /* Check the third parameter to make sure it is "user" or "group" */
  if (strcmp(cmd->argv[3], "user") != 0 &&
      strcmp(cmd->argv[3], "group") != 0) {
    CONF_ERROR(cmd, "third parameter must be 'user' or 'group'");
  }

  bad_action = pr_ctrls_set_module_acls(dynmasq_acttab, dynmasq_act_pool,
    actions, cmd->argv[2], cmd->argv[3], cmd->argv[4]);
  if (bad_action != NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown action: '",
      bad_action, "'", NULL));
  }

  return PR_HANDLED(cmd);
#else
  CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "The ", cmd->argv[0],
    " directive requires Controls support (--enable-ctrls)", NULL));
#endif /* PR_USE_CTRLS */
}

/* usage: DynMasqRefresh <seconds> */
MODRET set_dynmasqrefresh(cmd_rec *cmd) {
  CHECK_CONF(cmd, CONF_ROOT);
  CHECK_ARGS(cmd, 1);

  dynmasq_timer_interval = atoi(cmd->argv[1]);
  if (dynmasq_timer_interval < 1)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
      "must be greater than zero: '", cmd->argv[1], "'", NULL));

  return PR_HANDLED(cmd);
}

/* Timers
 */

static int dynmasq_refresh_cb(CALLBACK_FRAME) {
  dynmasq_refresh();
  return 1;
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void dynmasq_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_dynmasq.c", (const char *) event_data) == 0) {
    pr_event_unregister(&dynmasq_module, NULL, NULL);

# ifdef PR_USE_CTRLS
    /* Unregister any control actions. */
    pr_ctrls_unregister(&dynmasq_module, "dynmasq");

    destroy_pool(dynmasq_act_pool);
    dynmasq_act_pool = NULL;
# endif /* PR_USE_CTRLS */

    pr_timer_remove(dynmasq_timer_id, &dynmasq_module);
    dynmasq_timer_id = -1;

  }
}
#endif /* !PR_SHARED_MODULE */

static void dynmasq_postparse_ev(const void *event_data, void *user_data) {
  if (dynmasq_timer_interval != -1) {
    dynmasq_timer_id = pr_timer_add(dynmasq_timer_interval, -1,
      &dynmasq_module, dynmasq_refresh_cb, "dynmasq address refresh");
  }
}

static void dynmasq_restart_ev(const void *event_data, void *user_data) {
#ifdef PR_USE_CTRLS
  register unsigned int i;
#endif /* PR_USE_CTRLS */

  if (dynmasq_timer_id != -1) {
    pr_timer_remove(dynmasq_timer_id, &dynmasq_module);
    dynmasq_timer_id = -1;
  }

#ifdef PR_USE_CTRLS
  if (dynmasq_act_pool) {
    destroy_pool(dynmasq_act_pool);
    dynmasq_act_pool = NULL;
  }

  dynmasq_act_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(dynmasq_act_pool, "DynMasq Controls Pool");

  /* Re-create the controls ACLs. */
  for (i = 0; dynmasq_acttab[i].act_action; i++) {
    dynmasq_acttab[i].act_acl = palloc(dynmasq_act_pool, sizeof(ctrls_acl_t));
    pr_ctrls_init_acl(dynmasq_acttab[i].act_acl);
  }
#endif /* PR_USE_CTRLS */
}

/* Initialization functions
 */

static int dynmasq_init(void) {
#if defined(PR_SHARED_MODULE)
  pr_event_register(&dynmasq_module, "core.module-unload",
    dynmasq_mod_unload_ev, NULL);
#endif /* !PR_SHARED_MODULE */

  pr_event_register(&dynmasq_module, "core.postparse", dynmasq_postparse_ev,
    NULL);
  pr_event_register(&dynmasq_module, "core.restart", dynmasq_restart_ev,
    NULL);

#ifdef PR_USE_CTRLS
  if (pr_ctrls_register(&dynmasq_module, "dynmasq", "mod_dynmasq controls",
      dynmasq_handle_dynmasq) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_DYNMASQ_VERSION
      ": error registering 'dynmasq' control: %s", strerror(errno));

  } else {
    register unsigned int i;

    dynmasq_act_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(dynmasq_act_pool, "DynMasq Controls Pool");

    for (i = 0; dynmasq_acttab[i].act_action; i++) {
      dynmasq_acttab[i].act_acl = palloc(dynmasq_act_pool, sizeof(ctrls_acl_t));
      pr_ctrls_init_acl(dynmasq_acttab[i].act_acl);
    }
  }
#endif /* PR_USE_CTRLS */

  return 0;
}

static int dynmasq_sess_init(void) {

  /* Ensure that the timer only fires on the daemon process. */
  pr_timer_remove(dynmasq_timer_id, &dynmasq_module);
  dynmasq_timer_id = -1;

  pr_event_unregister(&dynmasq_module, "core.restart", NULL);

  return 0;
}

/* Module API tables
 */

#ifdef PR_USE_CTRLS
static ctrls_acttab_t dynmasq_acttab[] = {
  { "refresh",	NULL, NULL, NULL },
  { NULL, 	NULL, NULL, NULL }
};
#endif /* PR_USE_CTRLS */

static conftable dynmasq_conftab[] = {
  { "DynMasqControlsACLs",	set_dynmasqctrlsacls,	NULL },
  { "DynMasqRefresh",		set_dynmasqrefresh,	NULL },
  { NULL }
};

module dynmasq_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "dynmasq",

  /* Module configuration handler table */
  dynmasq_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  dynmasq_init,

  /* Session initialization function */
  dynmasq_sess_init,

  /* Module version */
  MOD_DYNMASQ_VERSION
};
