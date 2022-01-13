/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2013-2017 The ProFTPD Project team
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

/* Resource limit module */

#include "conf.h"
#include "privs.h"

#define MOD_RLIMIT_VERSION		"mod_rlimit/1.0"

/* On some platforms, including both sys/prctl.h and linux/prctl.h will cause
 * build errors similar to this one:
 *
 *  https://github.com/dvarrazzo/py-setproctitle/issues/44
 *
 * So try to work around this behavior by including sys/prctrl.h if available,
 * and if not, try linux/prctl.h.
 */
#if defined(HAVE_SYS_PRCTL_H)
# include <sys/prctl.h>
#elif defined(HAVE_LINUX_PRCTL_H)
# include <linux/prctl.h>
#endif

module rlimit_module;

#define DAEMON_SCOPE		3
#define SESSION_SCOPE		4

static int get_num_bytes(const char *nbytes_str, rlim_t *nbytes) {
  unsigned long inb;
  char units, junk;
  int res;

  /* Scan in the given argument, checking for the leading number-of-bytes
   * as well as a trailing G, M, K, or B (case-insensitive).  The junk
   * variable is catch arguments like "2g2" or "number-letter-whatever".
   *
   * NOTE: There is no portable way to scan in an ssize_t, so we do unsigned
   * long and cast it.  This probably places a 32-bit limit on rlimit values.
   */
  res = sscanf(nbytes_str, "%lu%c%c", &inb, &units, &junk);
  if (res == 2) {
    if (units != 'G' && units != 'g' &&
        units != 'M' && units != 'm' &&
        units != 'K' && units != 'k' &&
        units != 'B' && units != 'b') {
      errno = EINVAL;
      return -1;
    }

    *nbytes = inb;

    /* Calculate the actual bytes, multiplying by the given units.  Doing
     * it this way means that <math.h> and -lm aren't required.
     */
    if (units == 'G' ||
        units == 'g') {
      *nbytes *= (1024 * 1024 * 1024);
    }

    if (units == 'M' ||
        units == 'm') {
      *nbytes *= (1024 * 1024);
    }

    if (units == 'K' ||
        units == 'k') {
      *nbytes *= 1024;
    }

    /* Silently ignore units of 'B' and 'b', as they don't affect
     * the requested number of bytes anyway.
     */

    return 0;

  } else if (res == 1) {
    /* No units given.  Return the number of bytes as is. */
    *nbytes = inb;
    return 0;
  }

  /* Default return value: the given argument was badly formatted.
   */
  errno = EINVAL;
  return -1;
}

/* usage: RLimitChroot on|off */
MODRET set_rlimitchroot(cmd_rec *cmd) {
  config_rec *c;
  int use_guard = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  use_guard = get_boolean(cmd, 1);
  if (use_guard == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = use_guard;

  return PR_HANDLED(cmd);
}

/* usage: RLimitCPU ["daemon"|"session"] soft-limit [hard-limit] */
MODRET set_rlimitcpu(cmd_rec *cmd) {
#ifdef RLIMIT_CPU
  config_rec *c = NULL;
  rlim_t current, max;

  /* Make sure the directive has between 1 and 3 parameters */
  if (cmd->argc-1 < 1 ||
      cmd->argc-1 > 3) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  /* The context check for this directive depends on the first parameter.
   * For backwards compatibility, this parameter may be a number, or it
   * may be "daemon", "session", or "none".  If it happens to be
   * "daemon", then this directive should be in the CONF_ROOT context only.
   * Otherwise, it can appear in the full range of server contexts.
   */

  if (strncmp(cmd->argv[1], "daemon", 7) == 0) {
    CHECK_CONF(cmd, CONF_ROOT);

  } else {
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
  }

  if (pr_rlimit_get_cpu(&current, &max) < 0 &&
      errno != ENOSYS) {
    pr_log_pri(PR_LOG_NOTICE, "unable to retrieve CPU resource limits: %s",
      strerror(errno));
  }

  /* Handle the newer format, which uses "daemon" or "session" or "none"
   * as the first parameter.
   */
  if (strncmp(cmd->argv[1], "daemon", 7) == 0 ||
      strncmp(cmd->argv[1], "session", 8) == 0) {

    if (strcasecmp(cmd->argv[2], "max") == 0 ||
        strcasecmp(cmd->argv[2], "unlimited") == 0) {
      current = RLIM_INFINITY;

    } else {
      /* Check that the non-max argument is a number, and error out if not. */
      char *ptr = NULL;
      unsigned long num = strtoul(cmd->argv[2], &ptr, 10);

      if (ptr && *ptr) {
        CONF_ERROR(cmd, "badly formatted argument");
      }

      current = num;
    }

    /* Handle the optional "hard limit" parameter, if present. */
    if (cmd->argc-1 == 3) {
      if (strcasecmp(cmd->argv[3], "max") == 0 ||
          strcasecmp(cmd->argv[3], "unlimited") == 0) {
        max = RLIM_INFINITY;

      } else {
        /* Check that the non-max argument is a number, and error out if not. */
        char *ptr = NULL;
        unsigned long num = strtoul(cmd->argv[3], &ptr, 10);

        if (ptr && *ptr) {
          CONF_ERROR(cmd, "badly formatted argument");
        }

        max = num;
      }

    } else {
      /* Assume that the hard limit should be the same as the soft limit. */
      max = current;
    }

    c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);
    c->argv[0] = pstrdup(c->pool, cmd->argv[1]);
    c->argv[1] = palloc(c->pool, sizeof(rlim_t));
    *((rlim_t *) c->argv[1]) = current;
    c->argv[2] = palloc(c->pool, sizeof(rlim_t));
    *((rlim_t *) c->argv[2]) = max;

  /* Handle the older format, which will have a number as the first parameter.
   */
  } else {
    if (strcasecmp(cmd->argv[1], "max") == 0 ||
        strcasecmp(cmd->argv[1], "unlimited") == 0) {
      current = RLIM_INFINITY;

    } else {
      /* Check that the non-max argument is a number, and error out if not. */
      char *ptr = NULL;
      long num = strtol(cmd->argv[1], &ptr, 10);

      if (ptr && *ptr) {
        CONF_ERROR(cmd, "badly formatted argument");
      }

      current = num;
    }

    /* Handle the optional "hard limit" parameter, if present. */
    if (cmd->argc-1 == 2) {
      if (strcasecmp(cmd->argv[2], "max") == 0 ||
          strcasecmp(cmd->argv[2], "unlimited") == 0) {
        max = RLIM_INFINITY;

      } else {
        /* Check that the non-max argument is a number, and error out if not. */
        char *ptr = NULL;
        long num = strtol(cmd->argv[2], &ptr, 10);

        if (ptr && *ptr) {
          CONF_ERROR(cmd, "badly formatted argument");
        }

        max = num;
      }

    } else {
      /* Assume that the hard limit should be the same as the soft limit. */
      max = current;
    }

    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[0] = palloc(c->pool, sizeof(rlim_t));
    *((rlim_t *) c->argv[0]) = current;
    c->argv[1] = palloc(c->pool, sizeof(rlim_t));
    *((rlim_t *) c->argv[1]) = max;
  }

  return PR_HANDLED(cmd);
#else
  CONF_ERROR(cmd, "RLimitCPU is not supported on this platform");
#endif
}

/* usage: RLimitMemory ["daemon"|"session"] soft-limit [hard-limit] */
MODRET set_rlimitmemory(cmd_rec *cmd) {
#if defined(RLIMIT_AS) || defined(RLIMIT_DATA) || defined(RLIMIT_VMEM)
  config_rec *c = NULL;
  rlim_t current, max;

  /* Make sure the directive has between 1 and 3 parameters */
  if (cmd->argc-1 < 1 ||
      cmd->argc-1 > 3) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  /* The context check for this directive depends on the first parameter.
   * For backwards compatibility, this parameter may be a number, or it
   * may be "daemon", "session", or "none".  If it happens to be
   * "daemon", then this directive should be in the CONF_ROOT context only.
   * Otherwise, it can appear in the full range of server contexts.
   */

  if (strncmp(cmd->argv[1], "daemon", 7) == 0) {
    CHECK_CONF(cmd, CONF_ROOT);

  } else {
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
  }

  /* Retrieve the current values */
  if (pr_rlimit_get_memory(&current, &max) < 0 &&
      errno != ENOSYS) {
    pr_log_pri(PR_LOG_NOTICE, "unable to get memory resource limits: %s",
      strerror(errno));
  }

  /* Handle the newer format, which uses "daemon" or "session" or "none"
   * as the first parameter.
   */
  if (strncmp(cmd->argv[1], "daemon", 7) == 0 ||
      strncmp(cmd->argv[1], "session", 8) == 0) {

    if (strcasecmp(cmd->argv[2], "max") == 0 ||
        strcasecmp(cmd->argv[2], "unlimited") == 0) {
      current = RLIM_INFINITY;

    } else {
      if (get_num_bytes(cmd->argv[2], &current) < 0) {
        CONF_ERROR(cmd, "badly formatted argument");
      }
    }

    /* Handle the optional "hard limit" parameter, if present. */
    if (cmd->argc-1 == 3) {
      if (strcasecmp(cmd->argv[3], "max") == 0 ||
          strcasecmp(cmd->argv[3], "unlimited") == 0) {
        max = RLIM_INFINITY;

      } else {
        if (get_num_bytes(cmd->argv[3], &max) < 0) {
          CONF_ERROR(cmd, "badly formatted argument");
        }
      }

    } else {
      /* Assume that the hard limit should be the same as the soft limit. */
      max = current;
    }

    c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);
    c->argv[0] = pstrdup(c->pool, cmd->argv[1]);
    c->argv[1] = palloc(c->pool, sizeof(rlim_t));
    *((rlim_t *) c->argv[1]) = current;
    c->argv[2] = palloc(c->pool, sizeof(rlim_t));
    *((rlim_t *) c->argv[2]) = max;

  /* Handle the older format, which will have a number as the first
   * parameter.
   */
  } else {

    if (strcasecmp(cmd->argv[1], "max") == 0 ||
        strcasecmp(cmd->argv[1], "unlimited") == 0) {
      current = RLIM_INFINITY;

    } else {
      if (get_num_bytes(cmd->argv[1], &current) < 0) {
        CONF_ERROR(cmd, "badly formatted argument");
      }
    }

    /* Handle the optional "hard limit" parameter, if present. */
    if (cmd->argc-1 == 2) {
      if (strcasecmp(cmd->argv[2], "max") == 0 ||
          strcasecmp(cmd->argv[2], "unlimited") == 0) {
        max = RLIM_INFINITY;

      } else {
        if (get_num_bytes(cmd->argv[2], &max) < 0) {
          CONF_ERROR(cmd, "badly formatted argument");
        }
      }

    } else {
      /* Assume that the hard limit should be the same as the soft limit. */
      max = current;
    }

    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[0] = palloc(c->pool, sizeof(rlim_t));
    *((rlim_t *) c->argv[0]) = current;
    c->argv[1] = palloc(c->pool, sizeof(rlim_t));
    *((rlim_t *) c->argv[1]) = max;
  }

  return PR_HANDLED(cmd);
#else
  CONF_ERROR(cmd, "RLimitMemory is not supported on this platform");
#endif
}

/* usage: RLimitOpenFiles ["daemon"|"session"] soft-limit [hard-limit] */
MODRET set_rlimitopenfiles(cmd_rec *cmd) {
#if defined(RLIMIT_NOFILE) || defined(RLIMIT_OFILE)
  config_rec *c = NULL;
  rlim_t current, max;

  /* Make sure the directive has between 1 and 3 parameters */
  if (cmd->argc-1 < 1 ||
      cmd->argc-1 > 3) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  /* The context check for this directive depends on the first parameter.
   * For backwards compatibility, this parameter may be a number, or it
   * may be "daemon", "session", or "none".  If it happens to be
   * "daemon", then this directive should be in the CONF_ROOT context only.
   * Otherwise, it can appear in the full range of server contexts.
   */

  if (strncmp(cmd->argv[1], "daemon", 7) == 0) {
    CHECK_CONF(cmd, CONF_ROOT);

  } else {
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
  }

  /* Retrieve the current values */
  if (pr_rlimit_get_files(&current, &max) < 0) {
    pr_log_pri(PR_LOG_NOTICE, "unable to get file resource limits: %s",
      strerror(errno));
  }

  /* Handle the newer format, which uses "daemon" or "session" or "none"
   * as the first parameter.
   */
  if (strncmp(cmd->argv[1], "daemon", 7) == 0 ||
      strncmp(cmd->argv[1], "session", 8) == 0) {

    if (strcasecmp(cmd->argv[2], "max") == 0 ||
        strcasecmp(cmd->argv[2], "unlimited") == 0) {
      current = sysconf(_SC_OPEN_MAX);

    } else {
      /* Check that the non-max argument is a number, and error out if not. */
      char *ptr = NULL;
      long num = strtol(cmd->argv[2], &ptr, 10);

      if (ptr && *ptr) {
        CONF_ERROR(cmd, "badly formatted argument");
      }

      current = num;
    }

    /* Handle the optional "hard limit" parameter, if present. */
    if (cmd->argc-1 == 3) {
      if (strcasecmp(cmd->argv[3], "max") == 0 ||
          strcasecmp(cmd->argv[3], "unlimited") == 0) {
        max = sysconf(_SC_OPEN_MAX);

      } else {
        /* Check that the non-max argument is a number, and error out if not. */
        char *ptr = NULL;
        long num = strtol(cmd->argv[3], &ptr, 10);

        if (ptr && *ptr) {
          CONF_ERROR(cmd, "badly formatted argument");
        }

        max = num;
      }

    } else {
      /* Assume that the hard limit should be the same as the soft limit. */
      max = current;
    }

    c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);
    c->argv[0] = pstrdup(c->pool, cmd->argv[1]);
    c->argv[1] = palloc(c->pool, sizeof(rlim_t));
    *((rlim_t *) c->argv[1]) = current;
    c->argv[2] = palloc(c->pool, sizeof(rlim_t));
    *((rlim_t *) c->argv[2]) = max;

  /* Handle the older format, which will have a number as the first
   * parameter.
   */
  } else {

    if (strcasecmp(cmd->argv[1], "max") == 0 ||
        strcasecmp(cmd->argv[1], "unlimited") == 0) {
      current = sysconf(_SC_OPEN_MAX);

    } else {
      /* Check that the non-max argument is a number, and error out if not. */
      char *ptr = NULL;
      long num = strtol(cmd->argv[1], &ptr, 10);

      if (ptr && *ptr) {
        CONF_ERROR(cmd, "badly formatted argument");
      }

      current = num;
    }

    /* Handle the optional "hard limit" parameter, if present. */
    if (cmd->argc-1 == 2) {
      if (strcasecmp(cmd->argv[2], "max") == 0 ||
          strcasecmp(cmd->argv[2], "unlimited") == 0) {
        max = sysconf(_SC_OPEN_MAX);

      } else {
        /* Check that the non-max argument is a number, and error out if not. */
        char *ptr = NULL;
        long num = strtol(cmd->argv[2], &ptr, 10);

        if (ptr && *ptr) {
          CONF_ERROR(cmd, "badly formatted argument");
        }

        max = num;
      }

    } else {
      /* Assume that the hard limit should be the same as the soft limit. */
      max = current;
    }

    c = add_config_param(cmd->argv[0], 2, NULL, NULL);
    c->argv[0] = palloc(c->pool, sizeof(rlim_t));
    *((rlim_t *) c->argv[0]) = current;
    c->argv[1] = palloc(c->pool, sizeof(rlim_t));
    *((rlim_t *) c->argv[1]) = max;
  }

  return PR_HANDLED(cmd);
#else
  CONF_ERROR(cmd, "RLimitOpenFiles is not supported on this platform");
#endif
}

MODRET rlimit_post_pass(cmd_rec *cmd) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "RLimitChroot", FALSE);
  if (c != NULL) {
    int guard_chroot;

    guard_chroot = *((int *) c->argv[0]);
    if (guard_chroot == FALSE) {
      pr_fsio_guard_chroot(FALSE);
    }
  }

  return PR_DECLINED(cmd);
}

static int rlimit_set_core(int scope) {
  rlim_t current, max;
  int res, xerrno;

#ifdef PR_DEVEL_COREDUMP
  current = max = RLIM_INFINITY;
#else
  current = max = 0;
#endif /* PR_DEVEL_COREDUMP */

  PRIVS_ROOT
  res = pr_rlimit_set_core(current, max);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (res < 0) {
    pr_log_pri(PR_LOG_ERR, "error setting core resource limits: %s",
      strerror(xerrno));

  } else {
    pr_log_debug(DEBUG2, "set core resource limits for daemon");
  }

#if !defined(PR_DEVEL_COREDUMP) && \
    defined(HAVE_PRCTL) && \
    defined(PR_SET_DUMPABLE)
  if (max == 0) {
    /* Really, no core dumps please. On Linux, there are exceptions made
     * even when setting RLIMIT_CORE = 0; see:
     *
     *  https://lkml.org/lkml/2011/8/24/136
     *
     * so when possible, use PR_SET_DUMPABLE to ensure that no coredumps
     * happen.
     */
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0) {
      pr_log_pri(PR_LOG_ERR, "error setting PR_SET_DUMPABLE to false: %s",
        strerror(errno));
    }
  }
#endif /* no --enable-devel=coredump and HAVE_PRCTL and PR_SET_DUMPABLE */

  errno = xerrno;
  return res;
}

static int rlimit_set_cpu(int scope) {
  config_rec *c;

  /* Now check for the configurable resource limits */
  c = find_config(main_server->conf, CONF_PARAM, "RLimitCPU", FALSE);
  while (c) {
    int res, use_config = FALSE, xerrno;
    rlim_t current, max;

    pr_signals_handle();

    if (scope == DAEMON_SCOPE) { 
      /* Does this limit apply to the daemon? */
      if (c->argc == 3 &&
          strncmp(c->argv[0], "daemon", 7) == 0) {
        use_config = TRUE;
      }

    } else if (scope == SESSION_SCOPE) {
      /* Does this limit apply to the session? */
      if (c->argc == 2 ||
          (c->argc == 3 && strncmp(c->argv[0], "session", 8) == 0)) {
        use_config = TRUE;
      }
    }

    if (use_config == FALSE) {
      c = find_config_next(c, c->next, CONF_PARAM, "RLimitCPU", FALSE);
      continue;
    }

    if (c->argc == 2) {
      current = *((rlim_t *) c->argv[0]);
      max = *((rlim_t *) c->argv[1]);

    } else {
      current = *((rlim_t *) c->argv[1]);
      max = *((rlim_t *) c->argv[2]);
    }

    PRIVS_ROOT
    res = pr_rlimit_set_cpu(current, max);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res < 0) {
      pr_log_pri(PR_LOG_ERR, "error setting CPU resource limits: %s",
        strerror(xerrno));

    } else {
      pr_log_debug(DEBUG2, "set CPU resource limits for %s",
        scope == DAEMON_SCOPE ? "daemon" : "session");
    }

    c = find_config_next(c, c->next, CONF_PARAM, "RLimitCPU", FALSE);
  }

  return 0;
}

static int rlimit_set_files(int scope) {
  config_rec *c;

  /* Now check for the configurable resource limits */
  c = find_config(main_server->conf, CONF_PARAM, "RLimitOpenFiles", FALSE);
  while (c) {
    int res, use_config = FALSE, xerrno;
    rlim_t current, max;

    pr_signals_handle();

    if (scope == DAEMON_SCOPE) { 
      /* Does this limit apply to the daemon? */
      if (c->argc == 3 &&
          strncmp(c->argv[0], "daemon", 7) == 0) {
        use_config = TRUE;
      }

    } else if (scope == SESSION_SCOPE) {
      /* Does this limit apply to the session? */
      if (c->argc == 2 ||
          (c->argc == 3 && strncmp(c->argv[0], "session", 8) == 0)) {
        use_config = TRUE;
      }
    }

    if (use_config == FALSE) {
      c = find_config_next(c, c->next, CONF_PARAM, "RLimitOpenFiles", FALSE);
      continue;
    }

    if (c->argc == 2) {
      current = *((rlim_t *) c->argv[0]);
      max = *((rlim_t *) c->argv[1]);

    } else {
      current = *((rlim_t *) c->argv[1]);
      max = *((rlim_t *) c->argv[2]);
    }

    PRIVS_ROOT
    res = pr_rlimit_set_files(current, max);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res < 0) {
      pr_log_pri(PR_LOG_ERR, "error setting file resource limits: %s",
        strerror(xerrno));

    } else {
      pr_log_debug(DEBUG2, "set file resource limits for %s",
        scope == DAEMON_SCOPE ? "daemon" : "session");
    }

    c = find_config_next(c, c->next, CONF_PARAM, "RLimitOpenFiles", FALSE);
  }

  return 0;
}

static int rlimit_set_memory(int scope) {
  config_rec *c;

  /* Now check for the configurable resource limits */
  c = find_config(main_server->conf, CONF_PARAM, "RLimitMemory", FALSE);
  while (c) {
    int res, use_config = FALSE, xerrno;
    rlim_t current, max;

    pr_signals_handle();

    if (scope == DAEMON_SCOPE) { 
      /* Does this limit apply to the daemon? */
      if (c->argc == 3 &&
          strncmp(c->argv[0], "daemon", 7) == 0) {
        use_config = TRUE;
      }

    } else if (scope == SESSION_SCOPE) {
      /* Does this limit apply to the session? */
      if (c->argc == 2 ||
          (c->argc == 3 && strncmp(c->argv[0], "session", 8) == 0)) {
        use_config = TRUE;
      }
    }

    if (use_config == FALSE) {
      c = find_config_next(c, c->next, CONF_PARAM, "RLimitMemory", FALSE);
      continue;
    }

    if (c->argc == 2) {
      current = *((rlim_t *) c->argv[0]);
      max = *((rlim_t *) c->argv[1]);

    } else {
      current = *((rlim_t *) c->argv[1]);
      max = *((rlim_t *) c->argv[2]);
    }

    PRIVS_ROOT
    res = pr_rlimit_set_memory(current, max);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res < 0) {
      pr_log_pri(PR_LOG_ERR, "error setting memory resource limits: %s",
        strerror(xerrno));

    } else {
      pr_log_debug(DEBUG2, "set memory resource limits for %s",
        scope == DAEMON_SCOPE ? "daemon" : "session");
    }

    c = find_config_next(c, c->next, CONF_PARAM, "RLimitMemory", FALSE);
  }

  return 0;
}

/* Event listeners */

static void rlimit_chroot_ev(const void *event_data, void *user_data) {
  const char *path;
  size_t path_len;

  /* If we are chrooted, AND the chroot path is anything other than "/",
   * then set the FSIO API flag to guard certain sensitive directories.
   */

  path = event_data;
  path_len = strlen(path);

  if (path_len > 1) {
    pr_fsio_guard_chroot(TRUE);
  }
}

static void rlimit_postparse_ev(const void *event_data, void *user_data) {
  /* Since we're the parent process, we do not want to set the process
   * resource limits; we would prevent future session processes.
   */

  rlimit_set_core(DAEMON_SCOPE);
  rlimit_set_cpu(DAEMON_SCOPE);
  rlimit_set_memory(DAEMON_SCOPE);
  rlimit_set_files(DAEMON_SCOPE);
}

/* Module initialization */
static int rlimit_init(void) {
  pr_event_register(&rlimit_module, "core.postparse", rlimit_postparse_ev,
    NULL);

  return 0;
}

static int rlimit_sess_init(void) {
  config_rec *c;
  int guard_chroot = TRUE;

  rlimit_set_cpu(SESSION_SCOPE);
  rlimit_set_memory(SESSION_SCOPE);
  rlimit_set_files(SESSION_SCOPE);

  c = find_config(main_server->conf, CONF_PARAM, "RLimitChroot", FALSE);
  if (c != NULL) {
    guard_chroot = *((int *) c->argv[0]);
  }

  if (guard_chroot) {
    /* Register an event listener for the 'core.chroot' event, so that we
     * can set the switch (if necessary) for guarding against attacks like
     * "Roaring Beast" when we are chrooted.
     */
    pr_event_register(&rlimit_module, "core.chroot", rlimit_chroot_ev, NULL);
  }

  return 0;
}

/* Module API tables
 */

static conftable rlimit_conftab[] = {
  { "RLimitChroot",		set_rlimitchroot,		NULL },
  { "RLimitCPU",		set_rlimitcpu,			NULL },
  { "RLimitMemory",		set_rlimitmemory,		NULL },
  { "RLimitOpenFiles",		set_rlimitopenfiles,		NULL },

  { NULL, NULL, NULL }
};

static cmdtable rlimit_cmdtab[] = {
  { POST_CMD,	C_PASS,	G_NONE,	rlimit_post_pass, FALSE, FALSE,	CL_AUTH },
  { 0, NULL }
};

module rlimit_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "rlimit",

  /* Module configuration directive table */
  rlimit_conftab,

  /* Module command handler table */
  rlimit_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  rlimit_init,

  /* Session initialization function */
  rlimit_sess_init,

  /* Module version */
  MOD_RLIMIT_VERSION
};
