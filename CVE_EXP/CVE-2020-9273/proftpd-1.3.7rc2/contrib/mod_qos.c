/*
 * ProFTPD: mod_qos -- a module for managing QoS socket options
 *
 * Copyright (c) 2010 Philip Prindeville
 * Copyright (c) 2010-2014 The ProFTPD Project
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
 * As a special exemption, Philip Prindeville and other respective copyright
 * holders give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_qos, contrib software for proftpd 1.3.x and above.
 */

#include "conf.h"

#define MOD_QOS_VERSION		"mod_qos/0.1"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030401
# error "ProFTPD 1.3.4rc1 or later required"
#endif

module qos_module;

/* The level argument in a setsockopt(2) call for the TCP level is platform
 * dependent.  Linux wants SOL_IP, *BSD wants IPPROTO_IP.
 */
#ifdef SOL_IP
static int ip_level = SOL_IP;
#else
static int ip_level = IPPROTO_IP;
#endif /* !SOL_IP */

/* These particular bits have yet to be widely deployed, thus the autodetection
 * fun here.
 *
 * The semantics of the categories thus defined (CS0-CS7, AF11-AF43) are
 * determined by the network configuration of each site; there are no
 * global conventions/semantics to attach to these categories.
 */

#ifdef IPTOS_CLASS_CS0
# define QOS_CLASS_CS0	IPTOS_CLASS_CS0
#else
# define QOS_CLASS_CS0	0x00
#endif

#ifdef IPTOS_CLASS_CS1
# define QOS_CLASS_CS1	IPTOS_CLASS_CS1
#else
# define QOS_CLASS_CS1	0x20
#endif

#ifdef IPTOS_CLASS_CS2
# define QOS_CLASS_CS2	IPTOS_CLASS_CS2
#else
# define QOS_CLASS_CS2	0x40
#endif

#ifdef IPTOS_CLASS_CS3
# define QOS_CLASS_CS3	IPTOS_CLASS_CS3
#else
# define QOS_CLASS_CS3	0x60
#endif

#ifdef IPTOS_CLASS_CS4
# define QOS_CLASS_CS4	IPTOS_CLASS_CS4
#else
# define QOS_CLASS_CS4	0x80
#endif

#ifdef IPTOS_CLASS_CS5
# define QOS_CLASS_CS5	IPTOS_CLASS_CS5
#else
# define QOS_CLASS_CS5	0xa0
#endif

#ifdef IPTOS_CLASS_CS6
# define QOS_CLASS_CS6	IPTOS_CLASS_CS6
#else
# define QOS_CLASS_CS6	0xc0
#endif

#ifdef IPTOS_CLASS_CS7
# define QOS_CLASS_CS7	IPTOS_CLASS_CS7
#else
# define QOS_CLASS_CS7	0xe0
#endif

/* See RFC2474 for a discussion of Differentiated Services field */

#ifdef IPTOS_DSCP_AF11
# define QOS_DSCP_AF11	IPTOS_DSCP_AF11
#else
# define QOS_DSCP_AF11	0x28
#endif

#ifdef IPTOS_DSCP_AF12
# define QOS_DSCP_AF12	IPTOS_DSCP_AF12
#else
# define QOS_DSCP_AF12	0x30
#endif

#ifdef IPTOS_DSCP_AF13
# define QOS_DSCP_AF13	IPTOS_DSCP_AF13
#else
# define QOS_DSCP_AF13	0x38
#endif

#ifdef IPTOS_DSCP_AF21
# define QOS_DSCP_AF21	IPTOS_DSCP_AF21
#else
# define QOS_DSCP_AF21	0x48
#endif

#ifdef IPTOS_DSCP_AF22
# define QOS_DSCP_AF22	IPTOS_DSCP_AF22
#else
# define QOS_DSCP_AF22	0x50
#endif

#ifdef IPTOS_DSCP_AF23
# define QOS_DSCP_AF23	IPTOS_DSCP_AF23
#else
# define QOS_DSCP_AF23	0x58
#endif

#ifdef IPTOS_DSCP_AF31
# define QOS_DSCP_AF31	IPTOS_DSCP_AF31
#else
# define QOS_DSCP_AF31	0x68
#endif

#ifdef IPTOS_DSCP_AF32
# define QOS_DSCP_AF32	IPTOS_DSCP_AF32
#else
# define QOS_DSCP_AF32	0x70
#endif

#ifdef IPTOS_DSCP_AF33
# define QOS_DSCP_AF33	IPTOS_DSCP_AF33
#else
# define QOS_DSCP_AF33	0x78
#endif

#ifdef IPTOS_DSCP_AF41
# define QOS_DSCP_AF41	IPTOS_DSCP_AF41
#else
# define QOS_DSCP_AF41	0x88
#endif

#ifdef IPTOS_DSCP_AF42
# define QOS_DSCP_AF42	IPTOS_DSCP_AF42
#else
# define QOS_DSCP_AF42	0x90
#endif

#ifdef IPTOS_DSCP_AF43
# define QOS_DSCP_AF43	IPTOS_DSCP_AF43
#else
# define QOS_DSCP_AF43	0x98
#endif

#ifdef IPTOS_DSCP_EF
# define QOS_DSCP_EF	IPTOS_DSCP_EF
#else
# define QOS_DSCP_EF	0xb8
#endif

struct qos_rec {
  const char *name;
  int value;
};

static struct qos_rec qos_vals[] = {
  { "cs0",	QOS_CLASS_CS0 },
  { "cs1",	QOS_CLASS_CS1 },
  { "cs2",	QOS_CLASS_CS2 },
  { "cs3",	QOS_CLASS_CS3 },
  { "cs4",	QOS_CLASS_CS4 },
  { "cs5",	QOS_CLASS_CS5 },
  { "cs6",	QOS_CLASS_CS6 },
  { "cs7",	QOS_CLASS_CS7 },

  { "af11",	QOS_DSCP_AF11 },
  { "af12",	QOS_DSCP_AF12 },
  { "af13",	QOS_DSCP_AF13 },
  { "af21",	QOS_DSCP_AF21 },
  { "af22",	QOS_DSCP_AF22 },
  { "af23",	QOS_DSCP_AF23 },
  { "af31",	QOS_DSCP_AF31 },
  { "af32",	QOS_DSCP_AF32 },
  { "af33",	QOS_DSCP_AF33 },
  { "af41",	QOS_DSCP_AF41 },
  { "af42",	QOS_DSCP_AF42 },
  { "af43",	QOS_DSCP_AF43 },

  { "ef",	QOS_DSCP_EF },

  /* Some more human-readable strings */
#ifdef IPTOS_LOWDELAY
  { "lowdelay",	IPTOS_LOWDELAY },
#endif

#ifdef IPTOS_THROUGHPUT
  { "throughput",IPTOS_THROUGHPUT },
#endif

#ifdef IPTOS_RELIABILITY
  { "reliability",IPTOS_RELIABILITY },
#endif

#ifdef IPTOS_LOWCOST
  { "lowcost",	IPTOS_LOWCOST },
#endif

#ifdef IPTOS_MINCOST
  { "mincost",	IPTOS_MINCOST },
#endif

  { NULL,	-1 }
};

/* Prototypes. */
static int qos_sess_init(void);

static int qos_get_int(const char *str) {
  register unsigned int i;

  for (i = 0; qos_vals[i].name; i++) {
    if (strcasecmp(qos_vals[i].name, str) == 0) {
      return qos_vals[i].value;
    }
  }

  return -1;
}

/* Configuration handlers
 */

/* usage: QoSOptions */
MODRET set_qosoptions(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  int ctrlqos = 0, dataqos = 0;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL);

  /* Make sure we have the right number of parameters. */
  if ((cmd->argc-1) % 2 != 0) {
   CONF_ERROR(cmd, "bad number of parameters");
  }

  for (i = 1; i < cmd->argc; i++) {
    if (strcasecmp(cmd->argv[i], "dataqos") == 0) {
      dataqos = qos_get_int(cmd->argv[++i]);
      if (dataqos == -1) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown dataqos parameter '",
          cmd->argv[i-1], "'", NULL));
      }

    } else if (strcasecmp(cmd->argv[i], "ctrlqos") == 0) {
      ctrlqos = qos_get_int(cmd->argv[++i]);
      if (ctrlqos == -1) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown ctrlqos parameter '",
          cmd->argv[i-1], "'", NULL));
      }

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown QoS option: '",
        cmd->argv[i], "'", NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = ctrlqos;
  c->argv[1] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = dataqos;

  return PR_HANDLED(cmd);
}

/* Event handlers
 */

#ifdef IP_TOS
static void qos_ctrl_listen_ev(const void *event_data, void *user_data) {
  const struct socket_ctx *sc;

  sc = event_data;

  /* Only set TOS flags on IPv4 sockets; IPv6 sockets don't seem to support
   * them.
   */

  if (pr_netaddr_get_family(sc->addr) == AF_INET) {
    config_rec *c;
    c = find_config(sc->server->conf, CONF_PARAM, "QoSOptions", FALSE);

    if (c) {
      int ctrlqos;

      ctrlqos = *((int *) c->argv[0]);
      if (ctrlqos != 0) {
        int res;

        res = setsockopt(sc->sockfd, ip_level, IP_TOS, (void *) &ctrlqos,
          sizeof(ctrlqos));
        if (res < 0) {
          pr_log_pri(PR_LOG_NOTICE, MOD_QOS_VERSION
            ": error setting control socket IP_TOS: %s", strerror(errno));
        }
      }
    }
  }
}

static void qos_data_listen_ev(const void *event_data, void *user_data) {
  const struct socket_ctx *sc;

  sc = event_data;

  /* Only set TOS flags on IPv4 sockets; IPv6 sockets don't seem to support
   * them.
   */
  if (pr_netaddr_get_family(sc->addr) == AF_INET) {
    config_rec *c;

    c = find_config(sc->server->conf, CONF_PARAM, "QoSOptions", FALSE);
    if (c) {
      int dataqos, res;

      dataqos = *((int *) c->argv[1]);

      res = setsockopt(sc->sockfd, ip_level, IP_TOS, (void *) &dataqos,
        sizeof(dataqos));
      if (res < 0) {
        pr_log_pri(PR_LOG_NOTICE, MOD_QOS_VERSION
          ": error setting data socket IP_TOS: %s", strerror(errno));
      }
    }
  }
}

static void qos_data_connect_ev(const void *event_data, void *user_data) {
  const struct socket_ctx *sc;

  sc = event_data;

  /* Only set TOS flags on IPv4 sockets; IPv6 sockets don't seem to support
   * them.
   */
  if (pr_netaddr_get_family(sc->addr) == AF_INET) {
    config_rec *c;
    c = find_config(sc->server->conf, CONF_PARAM, "QoSOptions", FALSE);
    if (c) {
      int dataqos, res;

      dataqos = *((int *) c->argv[1]);

      res = setsockopt(sc->sockfd, ip_level, IP_TOS, (void *) &dataqos,
        sizeof(dataqos));
      if (res < 0) {
        pr_log_pri(PR_LOG_NOTICE, MOD_QOS_VERSION
          ": error setting data socket IP_TOS: %s", strerror(errno));
      }
    }
  }
}
#endif /* IP_TOS */

#ifdef PR_SHARED_MODULE
static void qos_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_qos.c", (const char *) event_data) == 0) {
    pr_event_unregister(&qos_module, NULL, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

static void qos_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&qos_module, "core.data-connect", qos_data_connect_ev);
  pr_event_unregister(&qos_module, "core.data-listen", qos_data_listen_ev);
  pr_event_unregister(&qos_module, "core.session-reinit", qos_sess_reinit_ev);

  res = qos_sess_init();
  if (res < 0) {
    pr_session_disconnect(&qos_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Initialization routines
 */

static int qos_init(void) {
#ifdef IP_TOS
  pr_event_register(&qos_module, "core.ctrl-listen", qos_ctrl_listen_ev, NULL);
#endif

#ifdef PR_SHARED_MODULE
  pr_event_register(&qos_module, "core.module-unload", qos_mod_unload_ev, NULL);
#endif
  return 0;
}

static int qos_sess_init(void) {
#ifdef IP_TOS
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "QoSOptions", FALSE);
  if (c) {
    int dataqos;

    dataqos = *((int *) c->argv[1]);
    if (dataqos != 0) {
      pr_event_register(&qos_module, "core.data-connect", qos_data_connect_ev,
        NULL);
      pr_event_register(&qos_module, "core.data-listen", qos_data_listen_ev,
        NULL);
    }
  }
#endif

  pr_event_register(&qos_module, "core.session-reinit", qos_sess_reinit_ev,
    NULL);

  return 0;
}

/* Module API tables
 */

static conftable qos_conftab[] = {
  { "QoSOptions",	set_qosoptions,	NULL },
  { NULL }
};

module qos_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "qos",

  /* Module configuration handler table */
  qos_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  qos_init,

  /* Session initialization function */
  qos_sess_init,

  /* Module version */
  MOD_QOS_VERSION
};
