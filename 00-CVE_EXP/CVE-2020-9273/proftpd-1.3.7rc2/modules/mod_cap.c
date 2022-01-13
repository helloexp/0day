/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 2003-2017 The ProFTPD Project team
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
 * As a special exemption, the copyright holders give permission to link
 * this program with OpenSSL and distribute the resulting executable without
 * including the source code for OpenSSL in the source distribution.
 */

/* Use POSIX "capabilities" in modern operating systems (currently, only
 * Linux is supported) to severely limit the process's access. After user
 * authentication, this module _completely_ gives up root privileges, except
 * for the bare minimum functionality that is required. VERY highly
 * recommended for security-consious admins. See README.capabilities for more
 * information.
 *
 * ----- DO NOT MODIFY THE TWO LINES BELOW -----
 * $Libraries: -L$(top_builddir)/lib/libcap -lcap$
 * $Directories: $(top_srcdir)/lib/libcap$
 */

#include <stdio.h>
#include <stdlib.h>

#ifdef LINUX
# ifdef __powerpc__
#  define _LINUX_BYTEORDER_GENERIC_H
# endif

# ifdef HAVE_LINUX_CAPABILITY_H
#  include <linux/capability.h>
# endif /* HAVE_LINUX_CAPABILITY_H */
# include "../lib/libcap/include/sys/capability.h"

/* What are these for? */
# undef WNOHANG
# undef WUNTRACED
#endif /* LINUX */

#include "conf.h"
#include "privs.h"

#ifdef HAVE_SYS_PRCTL_H
# include <sys/prctl.h>
#endif

#define MOD_CAP_VERSION		"mod_cap/1.1"

static cap_t capabilities = 0;
static unsigned char have_capabilities = FALSE;
static unsigned char use_capabilities = TRUE;

#define CAP_USE_CHOWN		0x0001
#define CAP_USE_DAC_OVERRIDE	0x0002
#define CAP_USE_DAC_READ_SEARCH	0x0004
#define CAP_USE_SETUID		0x0008
#define CAP_USE_AUDIT_WRITE	0x0010
#define CAP_USE_FOWNER		0x0020
#define CAP_USE_FSETID		0x0040

/* CAP_CHOWN and CAP_SETUID are enabled by default. */
static unsigned int cap_flags = (CAP_USE_CHOWN|CAP_USE_SETUID);

module cap_module;

/* Necessary prototypes */
static int cap_sess_init(void);

/* log current capabilities */
static void lp_debug(void) {
  char *res;
  ssize_t len;
  cap_t caps;

  caps = cap_get_proc();
  if (caps == NULL) {
    pr_log_pri(PR_LOG_ERR, MOD_CAP_VERSION ": cap_get_proc failed: %s",
      strerror(errno));
    return;
  }

  res = cap_to_text(caps, &len);
  if (res == NULL) {
    pr_log_pri(PR_LOG_ERR, MOD_CAP_VERSION ": cap_to_text failed: %s",
      strerror(errno));

    if (cap_free(caps) < 0) {
      pr_log_pri(PR_LOG_NOTICE, MOD_CAP_VERSION
        ": error freeing cap at line %d: %s", __LINE__ - 2, strerror(errno));
    }

    return;
  }

  pr_log_debug(DEBUG1, MOD_CAP_VERSION ": capabilities '%s'", res);
  (void) cap_free(res);

  if (cap_free(caps) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_CAP_VERSION
      ": error freeing cap at line %d: %s", __LINE__ - 2, strerror(errno));
  }
}

/* create a new capability structure */
static int lp_init_cap(void) {

  capabilities = cap_init();
  if (capabilities == NULL) {
    pr_log_pri(PR_LOG_ERR, MOD_CAP_VERSION ": initializing cap failed: %s",
      strerror(errno));
    return -1;
  }

  have_capabilities = TRUE;
  return 0;
}

/* free the capability structure */
static void lp_free_cap(void) {
  if (have_capabilities) {
    if (cap_free(capabilities) < 0) {
      pr_log_pri(PR_LOG_NOTICE, MOD_CAP_VERSION
        ": error freeing cap at line %d: %s", __LINE__ - 2, strerror(errno));
    }
  }
}

/* add a capability to a given set */
static int lp_add_cap(cap_value_t cap, cap_flag_t set) {
  if (cap_set_flag(capabilities, set, 1, &cap, CAP_SET) == -1) {
    pr_log_pri(PR_LOG_ERR, MOD_CAP_VERSION ": cap_set_flag failed: %s",
      strerror(errno));
    return -1;
  }

  return 0;
}

/* send the capabilities to the kernel */
static int lp_set_cap(void) {
  if (cap_set_proc(capabilities) == -1) {
    pr_log_pri(PR_LOG_ERR, MOD_CAP_VERSION ": cap_set_proc failed: %s",
      strerror(errno));
    return -1;
  }
 
  return 0;
}

/* Configuration handlers
 */

/* usage: CapabilitiesRootRevoke on|off */
MODRET set_caprootrevoke(cmd_rec *cmd) {
  int b = -1;
  config_rec *c = NULL;

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

MODRET set_caps(cmd_rec *cmd) {
  unsigned int flags = 0;
  config_rec *c = NULL;
  register unsigned int i = 0;

  if (cmd->argc - 1 < 1) {
    CONF_ERROR(cmd, "need at least one parameter");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  /* CAP_CHOWN and CAP_SETUID are enabled by default. */
  flags |= (CAP_USE_CHOWN|CAP_USE_SETUID);

  for (i = 1; i < cmd->argc; i++) {
    char *cap, *ptr;

    cap = ptr = cmd->argv[i];
    ptr++;

    if (*cap != '+' &&
        *cap != '-') {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": bad option: '", cap, "'",
        NULL));
    }

    if (strcasecmp(ptr, "CAP_CHOWN") == 0) {
      if (*cap == '-') {
        flags &= ~CAP_USE_CHOWN;
      }

    } else if (strcasecmp(ptr, "CAP_DAC_OVERRIDE") == 0) {
      if (*cap == '+') {
        flags |= CAP_USE_DAC_OVERRIDE;
      }

    } else if (strcasecmp(ptr, "CAP_DAC_READ_SEARCH") == 0) {
      if (*cap == '+') {
        flags |= CAP_USE_DAC_READ_SEARCH;
      }

    } else if (strcasecmp(ptr, "CAP_FOWNER") == 0) {
      if (*cap == '+') {
        flags |= CAP_USE_FOWNER;
      }

    } else if (strcasecmp(ptr, "CAP_FSETID") == 0) {
      if (*cap == '+') {
        flags |= CAP_USE_FSETID;
      }

    } else if (strcasecmp(ptr, "CAP_SETUID") == 0) {
      if (*cap == '-') {
        flags &= ~CAP_USE_SETUID;
      }

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown capability: '",
        ptr, "'", NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = flags;

  /* Make sure to set this flag, so that mod_ifsession handles these
   * config_recs properly.
   */
  c->flags |= CF_MULTI;

  return PR_HANDLED(cmd);
}

MODRET set_capengine(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expecting Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* Command handlers
 */

/* The POST_CMD handler for "PASS" is only called after PASS has
 * successfully completed, which means authentication is successful,
 * so we can "tweak" our root access down to almost nothing.
 */
MODRET cap_post_pass(cmd_rec *cmd) {
  int cap_root_revoke = TRUE, res;
  config_rec *c;
  unsigned char *cap_engine = NULL;
  uid_t dst_uid = PR_ROOT_UID;

  if (!use_capabilities)
    return PR_DECLINED(cmd);

  /* Check to see if we have been disabled via e.g. mod_ifsession. */
  cap_engine = get_param_ptr(main_server->conf, "CapabilitiesEngine", FALSE);
  if (cap_engine != NULL) {
    use_capabilities = *cap_engine;
    if (use_capabilities == FALSE) {
      return PR_DECLINED(cmd);
    }
  }

  /* Check for which specific capabilities to include/exclude. */
  c = find_config(main_server->conf, CONF_PARAM, "CapabilitiesSet", FALSE);
  if (c != NULL) {
    cap_flags = *((unsigned int *) c->argv[0]);

    if (!(cap_flags & CAP_USE_CHOWN)) {
      pr_log_debug(DEBUG3, MOD_CAP_VERSION
        ": removing CAP_CHOWN capability");
    }

    if (cap_flags & CAP_USE_DAC_OVERRIDE) {
      pr_log_debug(DEBUG3, MOD_CAP_VERSION
        ": adding CAP_DAC_OVERRIDE capability"); 
    }

    if (cap_flags & CAP_USE_DAC_READ_SEARCH) {
      pr_log_debug(DEBUG3, MOD_CAP_VERSION
        ": adding CAP_DAC_READ_SEARCH capability");
    }

    if (cap_flags & CAP_USE_FOWNER) {
      pr_log_debug(DEBUG3, MOD_CAP_VERSION
        ": adding CAP_FOWNER capability");
    }

    if (cap_flags & CAP_USE_FSETID) {
      pr_log_debug(DEBUG3, MOD_CAP_VERSION
        ": adding CAP_FSETID capability");
    }

    if (!(cap_flags & CAP_USE_SETUID)) {
      pr_log_debug(DEBUG3, MOD_CAP_VERSION
        ": removing CAP_SETUID capability");
    }
  }

  pr_signals_block();

#ifndef PR_DEVEL_COREDUMP
  /* glibc2.1 is BROKEN, seteuid() no longer lets one set euid to uid,
   * so we can't use PRIVS_ROOT/PRIVS_RELINQUISH. setreuid() is the
   * workaround.
   */
  if (setreuid(session.uid, PR_ROOT_UID) < 0) {
    int xerrno = errno;
    const char *proto;

    pr_signals_unblock();

    proto = pr_session_get_protocol(0);

    /* If this is for an SSH2 connection, don't log the error if it is
     * an EPERM.
     */
    if (strncmp(proto, "ssh2", 5) != 0 ||
        xerrno != EPERM) {
      pr_log_pri(PR_LOG_ERR, MOD_CAP_VERSION ": setreuid(%s, %s) failed: %s",
        pr_uid2str(cmd->tmp_pool, session.uid),
        pr_uid2str(cmd->tmp_pool, PR_ROOT_UID),
        strerror(xerrno));
    }

    return PR_DECLINED(cmd);
  }
#endif /* PR_DEVEL_COREDUMP */

  /* The only capability we need is CAP_NET_BIND_SERVICE (bind
   * ports < 1024).  Everything else can be discarded.  We set this
   * in CAP_PERMITTED set only, as when we switch away from root
   * we lose CAP_EFFECTIVE anyhow, and must reset it.
   */

  res = lp_init_cap();
  if (res != -1) {
    res = lp_add_cap(CAP_NET_BIND_SERVICE, CAP_PERMITTED);
  }

  /* Add the CAP_CHOWN capability, unless explicitly configured not to. */
  if (res != -1 &&
      (cap_flags & CAP_USE_CHOWN)) {
    res = lp_add_cap(CAP_CHOWN, CAP_PERMITTED);
  }

  if (res != -1 &&
      (cap_flags & CAP_USE_DAC_OVERRIDE)) {
    res = lp_add_cap(CAP_DAC_OVERRIDE, CAP_PERMITTED);
  }

  if (res != -1 &&
      (cap_flags & CAP_USE_DAC_READ_SEARCH)) {
    res = lp_add_cap(CAP_DAC_READ_SEARCH, CAP_PERMITTED);
  }

  if (res != -1 &&
      (cap_flags & CAP_USE_SETUID)) {
    res = lp_add_cap(CAP_SETUID, CAP_PERMITTED);
    if (res != -1) {
      res = lp_add_cap(CAP_SETGID, CAP_PERMITTED);
    }
  }

#ifdef CAP_AUDIT_WRITE
  if (res != -1 &&
      (cap_flags & CAP_USE_AUDIT_WRITE)) {
    res = lp_add_cap(CAP_AUDIT_WRITE, CAP_PERMITTED);
  }
#endif

  if (res != -1 &&
      (cap_flags & CAP_USE_FOWNER)) {
    res = lp_add_cap(CAP_FOWNER, CAP_PERMITTED);
  }

#ifdef CAP_FSETID
  if (res != -1 &&
      (cap_flags & CAP_USE_FSETID)) {
    res = lp_add_cap(CAP_FSETID, CAP_PERMITTED);
  }
#endif

  if (res != -1)
    res = lp_set_cap();

#ifdef PR_SET_KEEPCAPS
  /* Make sure that when we switch our IDs, we still keep the capabilities
   * we've set.
   */
  if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
    pr_log_pri(PR_LOG_ERR,
      MOD_CAP_VERSION ": prctl(PR_SET_KEEPCAPS) failed: %s", strerror(errno));
  }
#endif /* PR_SET_KEEPCAPS */

  /* Unless the config requests it, drop root privs completely. */
  c = find_config(main_server->conf, CONF_PARAM, "CapabilitiesRootRevoke",
    FALSE);
  if (c != NULL) {
    cap_root_revoke = *((int *) c->argv[0]);
  }

  if (cap_root_revoke == TRUE) {
    dst_uid = session.uid;

  } else {
    pr_log_debug(DEBUG4, MOD_CAP_VERSION
      ": CapabilitiesRootRevoke off, not dropping root privs");
  }

  if (setreuid(dst_uid, session.uid) == -1) {
    pr_log_pri(PR_LOG_ERR, MOD_CAP_VERSION ": setreuid(%s, %s) failed: %s",
      pr_uid2str(cmd->tmp_pool, dst_uid),
      pr_uid2str(cmd->tmp_pool, session.uid),
      strerror(errno));
    lp_free_cap();
    pr_signals_unblock();
    pr_session_disconnect(&cap_module, PR_SESS_DISCONNECT_BY_APPLICATION, NULL);
  }
  pr_signals_unblock();

  pr_log_debug(DEBUG9, MOD_CAP_VERSION
    ": uid = %s, euid = %s, gid = %s, egid = %s",
    pr_uid2str(cmd->tmp_pool, getuid()),
    pr_uid2str(cmd->tmp_pool, geteuid()),
    pr_gid2str(cmd->tmp_pool, getgid()),
    pr_gid2str(cmd->tmp_pool, getegid()));

  /* Now our only capabilities consist of CAP_NET_BIND_SERVICE (and other
   * configured caps), however in order to actually be able to bind to
   * low-numbered ports, we need the capability to be in the effective set.
   */

  if (res != -1) {
    res = lp_add_cap(CAP_NET_BIND_SERVICE, CAP_EFFECTIVE);
  }

  /* Add the CAP_CHOWN capability, unless explicitly configured not to. */
  if (res != -1 &&
      (cap_flags & CAP_USE_CHOWN)) {
    res = lp_add_cap(CAP_CHOWN, CAP_EFFECTIVE);
  }

  if (res != -1 &&
      (cap_flags & CAP_USE_DAC_OVERRIDE)) {
    res = lp_add_cap(CAP_DAC_OVERRIDE, CAP_EFFECTIVE);
  }

  if (res != -1 &&
      (cap_flags & CAP_USE_DAC_READ_SEARCH)) {
    res = lp_add_cap(CAP_DAC_READ_SEARCH, CAP_EFFECTIVE);
  }

  if (res != -1
      && (cap_flags & CAP_USE_SETUID)) {
    res = lp_add_cap(CAP_SETUID, CAP_EFFECTIVE);
    if (res != -1) {
      res = lp_add_cap(CAP_SETGID, CAP_EFFECTIVE);
    }
  }

#ifdef CAP_AUDIT_WRITE
  if (res != -1 &&
      (cap_flags & CAP_USE_AUDIT_WRITE)) {
    res = lp_add_cap(CAP_AUDIT_WRITE, CAP_EFFECTIVE);
  }
#endif

  if (res != -1 &&
      (cap_flags & CAP_USE_FOWNER)) {
    res = lp_add_cap(CAP_FOWNER, CAP_EFFECTIVE);
  }

#ifdef CAP_FSETID
  if (res != -1 &&
      (cap_flags & CAP_USE_FSETID)) {
    res = lp_add_cap(CAP_FSETID, CAP_EFFECTIVE);
  }
#endif

  if (res != -1)
    res = lp_set_cap();

  lp_free_cap();

  if (res != -1) {
    /* That's it!  Disable all further id switching */
    session.disable_id_switching = TRUE;
    lp_debug();

  } else {
    pr_log_pri(PR_LOG_WARNING, MOD_CAP_VERSION ": attempt to configure "
      "capabilities failed, reverting to normal operation");
  }

  return PR_DECLINED(cmd);
}

/* Event listeners
 */

static void cap_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&cap_module, "core.session-reinit", cap_sess_reinit_ev);

  have_capabilities = FALSE;
  use_capabilities = TRUE;
  cap_flags = 0;

  res = cap_sess_init();
  if (res < 0) {
    pr_session_disconnect(&cap_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Initialization routines
 */

static int cap_sess_init(void) {
  pr_event_register(&cap_module, "core.session-reinit", cap_sess_reinit_ev,
    NULL);

  /* Check to see if the lowering of capabilities has been disabled in the
   * configuration file.
   */
  if (use_capabilities) {
    unsigned char *cap_engine;

    cap_engine = get_param_ptr(main_server->conf, "CapabilitiesEngine", FALSE);
    if (cap_engine &&
        *cap_engine == FALSE) {
      pr_log_debug(DEBUG3, MOD_CAP_VERSION
        ": lowering of capabilities disabled");
      use_capabilities = FALSE;
    }
  }

  if (use_capabilities) {
    int use_setuid = FALSE;

    /* We need to check for things which want to revoke root privs altogether:
     * mod_exec, mod_sftp, and the RootRevoke directive.  Revoking root privs
     * completely requires the SETUID/SETGID capabilities.
     */

    if (use_setuid == FALSE &&
        pr_module_exists("mod_sftp.c")) {
      config_rec *c;

      c = find_config(main_server->conf, CONF_PARAM, "SFTPEngine", FALSE);
      if (c &&
          *((int *) c->argv[0]) == TRUE) {
        use_setuid = TRUE;
      }
    }

    if (use_setuid == FALSE &&
        pr_module_exists("mod_exec.c")) {
      config_rec *c;

      c = find_config(main_server->conf, CONF_PARAM, "ExecEngine", FALSE);
      if (c &&
          *((unsigned char *) c->argv[0]) == TRUE) {
        use_setuid = TRUE;
      }
    }

    if (use_setuid == FALSE) {
      config_rec *c;

      c = find_config(main_server->conf, CONF_PARAM, "RootRevoke", FALSE);
      if (c &&
          *((unsigned char *) c->argv[0]) == TRUE) {
        use_setuid = TRUE;
      }
    }

    if (use_setuid) {
      cap_flags |= CAP_USE_SETUID;
      pr_log_debug(DEBUG3, MOD_CAP_VERSION
        ": adding CAP_SETUID and CAP_SETGID capabilities");
    }

#ifdef CAP_AUDIT_WRITE
    if (pr_module_exists("mod_auth_pam.c")) {
      cap_flags |= CAP_USE_AUDIT_WRITE;
      pr_log_debug(DEBUG3, MOD_CAP_VERSION
        ": adding CAP_AUDIT_WRITE capability");
    }
#endif
  }

  return 0;
}

static int cap_module_init(void) {
  cap_t res;

  /* Attempt to determine if we are running on a kernel that supports
   * capabilities. This allows binary distributions to include the module
   * even if it may not work.
   */
  res = cap_get_proc();
  if (res == NULL &&
      errno == ENOSYS) {
    pr_log_debug(DEBUG2, MOD_CAP_VERSION
      ": kernel does not support capabilities, disabling module");
    use_capabilities = FALSE;
  }

  if (res != 0 &&
      cap_free(res) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_CAP_VERSION
      ": error freeing cap at line %d: %s", __LINE__ - 2, strerror(errno));
  }

  return 0;
}


/* Module API tables
 */

static conftable cap_conftab[] = {
  { "CapabilitiesEngine",	set_capengine,		NULL },
  { "CapabilitiesRootRevoke",	set_caprootrevoke,	NULL },
  { "CapabilitiesSet",		set_caps,		NULL },
  { NULL, NULL, NULL }
};

static cmdtable cap_cmdtab[] = {
  { POST_CMD,	C_PASS,	G_NONE,	cap_post_pass,	FALSE, FALSE },
  { 0, NULL }
};

module cap_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "cap",

  /* Module configuration handler table */
  cap_conftab,

  /* Module command handler table */
  cap_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  cap_module_init,

  /* Session initialization */
  cap_sess_init,

  /* Module version */
  MOD_CAP_VERSION
};
