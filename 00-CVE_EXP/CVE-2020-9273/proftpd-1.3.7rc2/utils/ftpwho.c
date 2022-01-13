/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2017 The ProFTPD Project team
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

/* Shows a count of "who" is online via proftpd.  Uses the scoreboard file. */

#include "utils.h"
#include "ccan-json.h"

#define MAX_CLASSES 100
struct scoreboard_class {
   char *score_class;
   unsigned long score_count;
};

#define OF_COMPAT		0x001
#define OF_ONELINE		0x002
#define OF_JSON			0x004

static const char *config_filename = PR_CONFIG_FILE_PATH;

static char *percent_complete(off_t size, off_t done) {
  static char sbuf[32];

  memset(sbuf, '\0', sizeof(sbuf));

  if (done == 0) {
    util_sstrncpy(sbuf, "0", sizeof(sbuf));

  } else if (size == 0) {
    util_sstrncpy(sbuf, "Inf", sizeof(sbuf));

  } else if (done >= size) {
    util_sstrncpy(sbuf, "100", sizeof(sbuf));

  } else {
    snprintf(sbuf, sizeof(sbuf), "%.0f",
	     ((double) done / (double) size) * 100.0);
    sbuf[sizeof(sbuf)-1] = '\0';
  }

  return sbuf;
}

static JsonNode *get_server_json(void) {
  JsonNode *server;
  pid_t daemon_pid;
  time_t daemon_uptime;

  server = json_mkobject();

  daemon_pid = util_scoreboard_get_daemon_pid();
  if (daemon_pid != 0) {
    json_append_member(server, "server_type", json_mkstring("standalone"));
    json_append_member(server, "pid", json_mknumber((double) daemon_pid));

  } else {
    json_append_member(server, "server_type", json_mkstring("inetd"));
  }

  daemon_uptime = util_scoreboard_get_daemon_uptime();
  json_append_member(server, "started_ms",
    json_mknumber(((double) (daemon_uptime * 1000L))));

  return server;
}

static JsonNode *get_conns_json(void) {
  JsonNode *conns;
  pr_scoreboard_entry_t *score = NULL;

  conns = json_mkarray();

  while ((score = util_scoreboard_entry_read()) != NULL) {
    JsonNode *conn;
    int authenticating = FALSE, downloading = FALSE, uploading = FALSE;

    conn = json_mkobject();

    json_append_member(conn, "pid", json_mknumber((double) score->sce_pid));
    json_append_member(conn, "connected_since_ms",
      json_mknumber(((double) (score->sce_begin_session * 1000L))));
    json_append_member(conn, "remote_name",
      json_mkstring(score->sce_client_name));
    json_append_member(conn, "remote_address",
      json_mkstring(score->sce_client_addr));

    if (score->sce_server_addr[0]) {
      char *ptr, server_addr[80];

      /* Trim off the port portion of the server_addr field; we report that
       * separately.
       */
      memset(server_addr, '\0', sizeof(server_addr));

      ptr = strrchr(score->sce_server_addr, ':');
      if (ptr != NULL) {
        memcpy(server_addr, score->sce_server_addr,
          (ptr - score->sce_server_addr));
      } else {
        memcpy(server_addr, score->sce_server_addr, sizeof(server_addr)-1);
      }

      json_append_member(conn, "local_address", json_mkstring(server_addr));
    }

    json_append_member(conn, "local_port",
      json_mknumber((double) score->sce_server_port));

    if (strcmp(score->sce_user, "(none)") == 0) {
      authenticating = TRUE;
    }

    if (authenticating) {
      json_append_member(conn, "authenticating", json_mkbool(TRUE));

    } else {
      json_append_member(conn, "user", json_mkstring(score->sce_user));
    }

    if (score->sce_class[0]) {
      json_append_member(conn, "class", json_mkstring(score->sce_class));
    }

    if (score->sce_protocol[0]) {
      json_append_member(conn, "protocol", json_mkstring(score->sce_protocol));
    }

    if (score->sce_cwd[0]) {
      json_append_member(conn, "location", json_mkstring(score->sce_cwd));
    }

    if (score->sce_cmd[0]) {
      if (strcmp(score->sce_cmd, "idle") == 0) {
        json_append_member(conn, "idling", json_mkbool(TRUE));

        if (!authenticating) {
          json_append_member(conn, "idle_since_ms",
            json_mknumber(((double) (score->sce_begin_idle * 1000L))));
        }

      } else {
        json_append_member(conn, "command", json_mkstring(score->sce_cmd));

        if (score->sce_cmd_arg[0]) {
          json_append_member(conn, "command_args",
            json_mkstring(score->sce_cmd_arg));
        }
      }

    } else {
      json_append_member(conn, "idling", json_mkbool(TRUE));

      if (!authenticating) {
        json_append_member(conn, "idle_since_ms",
          json_mknumber(((double) (score->sce_begin_idle * 1000L))));
      }
    }

    if (strncmp(score->sce_cmd, "RETR", 5) == 0 ||
        strncmp(score->sce_cmd, "READ", 5) == 0 ||
        strcmp(score->sce_cmd, "scp download") == 0) {
      downloading = TRUE;

    } else {
      if (strncmp(score->sce_cmd, "STOR", 5) == 0 ||
          strncmp(score->sce_cmd, "STOU", 5) == 0 ||
          strncmp(score->sce_cmd, "APPE", 5) == 0 ||
          strncmp(score->sce_cmd, "WRITE", 6) == 0 ||
          strcmp(score->sce_cmd, "scp upload") == 0) {
        uploading = TRUE;
      }
    }

    if (downloading) {
      json_append_member(conn, "downloading", json_mkbool(TRUE));
      json_append_member(conn, "transfer_completed",
        json_mkstring(percent_complete(score->sce_xfer_size,
          score->sce_xfer_done)));
    }

    if (uploading) {
      json_append_member(conn, "uploading", json_mkbool(TRUE));
    }

    if (score->sce_xfer_done > 0) {
      json_append_member(conn, "transfer_bytes",
        json_mknumber((double) score->sce_xfer_done));
    }
 
    if (score->sce_xfer_elapsed > 0) {
      json_append_member(conn, "transfer_duration_ms",
        json_mknumber(((double) (score->sce_xfer_elapsed * 1000L))));
    }

    json_append_element(conns, conn);
  }

  return conns;
}

static JsonNode *get_json(void) {
  JsonNode *json, *server = NULL, *conns = NULL;

  server = get_server_json();
  conns = get_conns_json();
  json = json_mkobject();

  if (server != NULL) {
    json_append_member(json, "server", server);
  }

  if (conns != NULL) {
    json_append_member(json, "connections", conns);
  }

  return json;
}

static const char *strtime(time_t *then) {
  time_t now = time(NULL);
  unsigned long since;
  static char time_str[32];

  if (then == NULL ||
      *then == 0) {
    return "-";
  }

  memset(time_str, '\0', sizeof(time_str));
  since = now - *then;

  if (since < 3600) {
    snprintf(time_str, sizeof(time_str)-1, "%lum%lus", (since / 60),
      (since % 60));

  } else {
    snprintf(time_str, sizeof(time_str)-1, "%luh%lum", (since / 3600),
      ((since - (since / 3600) * 3600) / 60));
  }

  return time_str;
}

static int check_scoreboard_file(void) {
  struct stat st;

  if (stat(util_get_scoreboard(), &st) < 0) {
    return -1;
  }

  return 0;
}

static const char *show_uptime(time_t uptime_since) {
  static char buf[128] = {'\0'};
  time_t uptime_secs = time(NULL) - uptime_since;
  int upminutes, uphours, updays;
  int pos = 0;

  memset(buf, '\0', sizeof(buf));

  updays = (int) uptime_secs / (60 * 60 * 24);
  if (updays > 0) {
    pos += snprintf(buf + pos, sizeof(buf) - pos, "%d %s, ", updays,
      updays != 1 ? "days" : "day");
  }

  upminutes = (int) uptime_secs / 60;

  uphours = upminutes / 60;
  uphours = uphours % 24;

  upminutes = upminutes % 60;

  if (uphours) {
    snprintf(buf + pos, sizeof(buf) - pos, "%2d %s %02d min", uphours,
      uphours != 1 ? "hrs" : "hr", upminutes);

  } else {
    snprintf(buf + pos, sizeof(buf) - pos, "%d min", upminutes);
  }

  return buf;
}

static struct option_help {
  const char *long_opt,*short_opt,*desc;
} opts_help[] = {
  { "--config",	"-c",	"specify full path to proftpd configuration file" },
  { "--file",	"-f",	"specify full path to scoreboard file" },
  { "--help",	"-h",	NULL },
  { "--outform","-o",	"specify an output format" },
  { "--verbose","-v",	"display additional information for each connection" },
  { "--server",	"-S",	"show users only for specified ServerName" },
  { NULL }
};

#ifdef HAVE_GETOPT_LONG
static struct option opts[] = {
  { "config",  1, NULL, 'c' },
  { "file",    1, NULL, 'f' },
  { "help",    0, NULL, 'h' },
  { "outform", 1, NULL, 'o' },
  { "verbose", 0, NULL, 'v' },
  { "server",  1, NULL, 'S' },
  { NULL,      0, NULL, 0   }
};
#endif /* HAVE_GETOPT_LONG */

static void show_usage(const char *progname, int exit_code) {
  struct option_help *h = NULL;

  printf("usage: %s [options]\n", progname);
  for (h = opts_help; h->long_opt; h++) {
#ifdef HAVE_GETOPT_LONG
    printf("  %s, %s\n", h->short_opt, h->long_opt);
#else /* HAVE_GETOPT_LONG */
    printf("  %s\n", h->short_opt);
#endif
    if (h->desc == NULL) {
      printf("    display %s usage\n", progname);

    } else {
      printf("    %s\n", h->desc);
    }
  }

  exit(exit_code);
}

int main(int argc, char **argv) {
  pr_scoreboard_entry_t *score = NULL;
  pid_t mpid = 0;
  time_t uptime = 0;
  unsigned int count = 0, total = 0;
  int c = 0, res = 0;
  char *server_name = NULL;
  struct scoreboard_class classes[MAX_CLASSES];
  char *cp, *progname = *argv;
  const char *cmdopts = "S:c:f:ho:v";
  unsigned char verbose = FALSE;
  unsigned long outform = 0;

  memset(classes, 0, MAX_CLASSES * sizeof(struct scoreboard_class));

  cp = strrchr(progname, '/');
  if (cp != NULL)
    progname = cp+1;

  opterr = 0;
  while ((c =
#ifdef HAVE_GETOPT_LONG
	 getopt_long(argc, argv, cmdopts, opts, NULL)
#else /* HAVE_GETOPT_LONG */
	 getopt(argc, argv, cmdopts)
#endif /* HAVE_GETOPT_LONG */
	 ) != -1) {
    switch (c) {
      case 'h':
        show_usage(progname, 0);
        break;

      case 'v':
        verbose = TRUE;
        break;

      case 'f':
        util_set_scoreboard(optarg);
        break;

      case 'c':
        config_filename = strdup(optarg);
        break;

      case 'o':
        /* Check the given outform parameter. */
        if (strcasecmp(optarg, "compat") == 0) {
          outform |= OF_COMPAT;
          break;

        } else if (strcasecmp(optarg, "oneline") == 0) {
          outform |= OF_ONELINE;
          break;

        } else if (strcasecmp(optarg, "json") == 0) {
          outform = OF_JSON;
          break;
        }

        fprintf(stderr, "unknown outform value: '%s'\n", optarg);
        return 1;

      case 'S':
        server_name = strdup(optarg);
        break;

      case '?':
        fprintf(stderr, "unknown option: %c\n", (char) optopt);
        show_usage(progname, 1);
        break;
    }
  }

  /* First attempt to check the supplied/default scoreboard path.  If this is
   * incorrect, try the config file kludge.
   */
  if (check_scoreboard_file() < 0) {
    char *path;

    path = util_scan_config(config_filename, "ScoreboardFile");
    if (path != NULL) {
      util_set_scoreboard(path);
      free(path);
    }

    if (check_scoreboard_file() < 0) {
      fprintf(stderr, "%s: %s\n", util_get_scoreboard(), strerror(errno));
      fprintf(stderr, "(Perhaps you need to specify the ScoreboardFile with -f, or change\n");
      fprintf(stderr, " the compile-time default directory?)\n");
      exit(1);
    }
  }

  res = util_open_scoreboard(O_RDONLY);
  if (res < 0) {
    switch (res) {
      case -1:
        fprintf(stderr, "unable to open scoreboard: %s\n", strerror(errno));
        return 1;

      case UTIL_SCORE_ERR_BAD_MAGIC:
        fprintf(stderr, "scoreboard is corrupted or old\n");
        return 1;

      case UTIL_SCORE_ERR_OLDER_VERSION:
        fprintf(stderr, "scoreboard version is too old\n");
        return 1;

      case UTIL_SCORE_ERR_NEWER_VERSION:
        fprintf(stderr, "scoreboard version is too new\n");
        return 1;
    }
  }

  if (outform == OF_JSON) {
    JsonNode *json;

    json = get_json();
    if (json != NULL) {
      char *json_str;

      json_str = json_stringify(json, "  ");
      fprintf(stdout, "%s\n", json_str);
      free(json_str);
      json_delete(json);
    }

    if (server_name) {
      free(server_name);
      server_name = NULL;
    }

    return 0;
  }

  mpid = util_scoreboard_get_daemon_pid();
  uptime = util_scoreboard_get_daemon_uptime();
  count = 0;

  if (!mpid) {
    printf("inetd FTP daemon:\n");

  } else {
    printf("standalone FTP daemon [%u], up for %s\n", (unsigned int) mpid,
      show_uptime(uptime));
  }

  if (server_name) {
    printf("ProFTPD Server '%s'\n", server_name);
  }

  while ((score = util_scoreboard_entry_read()) != NULL) {
    int downloading = FALSE, uploading = FALSE;
    register unsigned int i = 0;

    /* If a ServerName was given, skip unless the scoreboard entry matches. */
    if (server_name != NULL &&
        strcmp(server_name, score->sce_server_label) != 0) {
      continue;
    }

    if (!count++) {
      if (total) {
        printf("   -  %d user%s\n\n", total, total > 1 ? "s" : "");
      }
      total = 0;
    }

    /* Tally up per-Class counters. */
    for (i = 0; i != MAX_CLASSES; i++) {
      if (classes[i].score_class == 0) {
        classes[i].score_class = strdup(score->sce_class);
        classes[i].score_count++;
        break;
      }

      if (strcasecmp(classes[i].score_class, score->sce_class) == 0) {
        classes[i].score_count++;
        break;
      }
    }

    total++;

    if (strncmp(score->sce_cmd, "RETR", 5) == 0 ||
        strncmp(score->sce_cmd, "READ", 5) == 0 ||
        strcmp(score->sce_cmd, "scp download") == 0) {
      downloading = TRUE;

    } else {
      if (strncmp(score->sce_cmd, "STOR", 5) == 0 ||
          strncmp(score->sce_cmd, "STOU", 5) == 0 ||
          strncmp(score->sce_cmd, "APPE", 5) == 0 ||
          strncmp(score->sce_cmd, "WRITE", 6) == 0 ||
          strcmp(score->sce_cmd, "scp upload") == 0) {
        uploading = TRUE;
      }
    }

    if (outform & OF_COMPAT) {
      if ((downloading || uploading) &&
          score->sce_xfer_size > 0) {
        if (downloading) {
          printf("%5d %-6s (%s%%) %s %s\n", (int) score->sce_pid,
            strtime(&score->sce_begin_idle),
            percent_complete(score->sce_xfer_size, score->sce_xfer_done),
            score->sce_cmd, score->sce_cmd_arg);

        } else {
          printf("%5d %-6s (n/a) %s %s\n", (int) score->sce_pid,
            strtime(&score->sce_begin_idle), score->sce_cmd,
            score->sce_cmd_arg);
        }

      } else {
        printf("%5d %-6s %s %s\n", (int) score->sce_pid,
          strtime(&score->sce_begin_idle), score->sce_cmd,
          score->sce_cmd_arg);
      }

      if (verbose) {
        if (score->sce_client_addr[0]) {
          printf("             (host: %s [%s])\n", score->sce_client_name,
            score->sce_client_addr);
        }

        if (score->sce_protocol[0]) {
          printf("              (protocol: %s)\n", score->sce_protocol);
        }

        if (score->sce_cwd[0]) {
          printf("              (cwd: %s)\n", score->sce_cwd);
        }

        if (score->sce_class[0]) {
          printf("              (class: %s)\n", score->sce_class);
        }
      }

      continue;
    }

    /* Has the client authenticated yet, or not? */
    if (strcmp(score->sce_user, "(none)")) {

      /* Is the client idle? */
      if (strncmp(score->sce_cmd, "idle", 5) == 0) {

        /* These printf() calls needs to be split up, as strtime() returns
         * a pointer to a static buffer, and pushing two invocations onto
         * the stack means that the times thus formatted will be incorrect.
         */
        printf("%5d %-8s [%6s] ", (int) score->sce_pid,
          score->sce_user, strtime(&score->sce_begin_session));
        printf("%6s %s", strtime(&score->sce_begin_idle), score->sce_cmd);

        if (verbose &&
            !(outform & OF_ONELINE)) {
          printf("\n");
        }

      } else {
        if (downloading) {
          printf("%5d %-8s [%6s] (%3s%%) %s %s", (int) score->sce_pid,
            score->sce_user, strtime(&score->sce_begin_session),
            percent_complete(score->sce_xfer_size, score->sce_xfer_done),
            score->sce_cmd, score->sce_cmd_arg);

        } else {
          printf("%5d %-8s [%6s] (n/a) %s %s", (int) score->sce_pid,
            score->sce_user, strtime(&score->sce_begin_session),
            score->sce_cmd, score->sce_cmd_arg);
        }

        if (verbose) {
          printf("%sKB/s: %3.2f%s",
            (outform & OF_ONELINE) ? " " : "\n\t",
            (score->sce_xfer_len / 1024.0) /
              (score->sce_xfer_elapsed / 1000),
            (outform & OF_ONELINE) ? "" : "\n");
        }
      }

      /* Display additional information, if requested. */
      if (verbose) {
        if (score->sce_client_addr[0]) {
          printf("%sclient: %s [%s]%s",
            (outform & OF_ONELINE) ? " " : "\t",
            score->sce_client_name, score->sce_client_addr,
            (outform & OF_ONELINE) ? "" : "\n");
        }

        if (score->sce_server_addr[0]) {
          printf("%sserver: %s (%s)%s",
            (outform & OF_ONELINE) ? " " : "\t",
            score->sce_server_addr, score->sce_server_label,
            (outform & OF_ONELINE) ? "" : "\n");
        }

        if (score->sce_protocol[0]) {
          printf("%sprotocol: %s%s",
            (outform & OF_ONELINE) ? " " : "\t",
            score->sce_protocol,
            (outform & OF_ONELINE) ? "" : "\n");
        }

        if (score->sce_cwd[0]) {
          printf("%slocation: %s%s",
            (outform & OF_ONELINE) ? " " : "\t",
            score->sce_cwd,
            (outform & OF_ONELINE) ? "" : "\n");
        }

        if (score->sce_class[0]) {
          printf("%sclass: %s",
            (outform & OF_ONELINE) ? " " : "\t",
            score->sce_class);
        }

        printf("%s", "\n");

      } else {
        printf("%s", "\n");
      }

    } else {
      printf("%5d %-8s [%6s] (authenticating)", (int) score->sce_pid,
        score->sce_user, strtime(&score->sce_begin_session));

      /* Display additional information, if requested. */
      if (verbose) {
        if (score->sce_client_addr[0]) {
          printf("%sclient: %s [%s]%s",
            (outform & OF_ONELINE) ? " " : "\n\t",
            score->sce_client_name, score->sce_client_addr,
            (outform & OF_ONELINE) ? "" : "\n");
        }

        if (score->sce_server_addr[0]) {
          printf("%sserver: %s (%s)%s",
            (outform & OF_ONELINE) ? " " : "\t",
            score->sce_server_addr, score->sce_server_label,
            (outform & OF_ONELINE) ? "" : "\n");
        }

        if (score->sce_protocol[0]) {
          printf("%sprotocol: %s%s",
            (outform & OF_ONELINE) ? " " : "\t",
            score->sce_protocol,
            (outform & OF_ONELINE) ? "" : "\n");
        }

        if (score->sce_class[0]) {
          printf("%sclass: %s",
            (outform & OF_ONELINE) ? " " : "\t",
            score->sce_class);
        }
      }

      printf("%s", "\n");
    }
  }
  util_close_scoreboard();

  if (total) {
    register unsigned int i = 0;

    for (i = 0; i != MAX_CLASSES; i++) {
      if (classes[i].score_class == 0) {
        break;
      }

      printf("Service class %-20s - %3lu user%s\n", classes[i].score_class,
        classes[i].score_count, classes[i].score_count > 1 ? "s" : "");
    }

  } else {
    printf("no users connected\n");
  }

  if (server_name) {
    free(server_name);
    server_name = NULL;
  }

  return 0;
}
