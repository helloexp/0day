/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2016 The ProFTPD Project team
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

#define MAX_CLASSES 100
struct scoreboard_class {
   char *score_class;
   unsigned long score_count;
};

static char *config_filename = PR_CONFIG_FILE_PATH;

static int check_scoreboard_file(void) {
  struct stat st;

  if (stat(util_get_scoreboard(), &st) < 0)
    return -1;

  return 0;
}

static struct option_help {
  char *long_opt, *short_opt, *desc;
} opts_help[] = {
  { "--config",	"-c",	"specify full path to proftpd configuration file" },
  { "--file",	"-f",	"specify full path to scoreboard file" },
  { "--help",	"-h",	NULL },
  { "--server",	"-S",	"show count only for specified ServerName" },
  { NULL }
};

#ifdef HAVE_GETOPT_LONG
static struct option opts[] = {
  { "config",  1, NULL, 'c' },
  { "file",    1, NULL, 'f' },
  { "help",    0, NULL, 'h' },
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
  pid_t oldpid = 0, mpid;
  unsigned int count = 0, total = 0;
  int c = 0, res = 0;
  char *server_name = NULL;
  struct scoreboard_class classes[MAX_CLASSES];
  char *cp, *progname = *argv;
  const char *cmdopts = "S:c:f:h";
  register unsigned int i;

  memset(classes, 0, MAX_CLASSES * sizeof(struct scoreboard_class));

  cp = strrchr(progname, '/');
  if (cp != NULL)
    progname = cp + 1;

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

      case 'f':
        util_set_scoreboard(optarg);
        break;

      case 'c':
        config_filename = strdup(optarg);
        break;

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
    if (path) {
      util_set_scoreboard(path);
      free(path);
    }

    if (check_scoreboard_file() < 0) {
      fprintf(stderr, "%s: %s\n", util_get_scoreboard(), strerror(errno));
      fprintf(stderr, "(Perhaps you need to specify the ScoreboardFile with -f, or change\n");
      fprintf(stderr," the compile-time default directory?)\n");
      exit(1);
    }
  }

  count = 0;
  res = util_open_scoreboard(O_RDONLY);
  if (res < 0) {
    switch (res) {
      case UTIL_SCORE_ERR_BAD_MAGIC:
        fprintf(stderr, "error opening scoreboard: bad/corrupted file\n");
        return 1;

      case UTIL_SCORE_ERR_OLDER_VERSION:
        fprintf(stderr, "error opening scoreboard: bad version (too old)\n");
        return 1;

      case UTIL_SCORE_ERR_NEWER_VERSION:
        fprintf(stderr, "error opening scoreboard: bad version (too new)\n");
        return 1;

      default:
        fprintf(stderr, "error opening scoreboard: %s\n", strerror(errno));
        return 1;
    }
  }

  mpid = util_scoreboard_get_daemon_pid();

  errno = 0;
  while ((score = util_scoreboard_entry_read()) != NULL) {

    if (errno) {
      break;
    }

    if (!count++ ||
        oldpid != mpid) {
      if (total) {
        printf("   -  %d user%s\n\n", total, total > 1 ? "s" : "");
      }

      if (!mpid) {
        printf("inetd FTP connections:\n");

      } else {
        printf("Master proftpd process %u:\n", (unsigned int) mpid);
      }

      if (server_name) {
        printf("ProFTPD Server '%s'\n", server_name);
      }

      oldpid = mpid;
      total = 0;
    }

    /* If a ServerName was given, skip unless the scoreboard entry matches. */
    if (server_name &&
        strcmp(server_name, score->sce_server_label) != 0) {
      continue;
    }

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
  }
  util_close_scoreboard();

  /* Print out the total. */
  if (total) {
    for (i = 0; i != MAX_CLASSES; i++) {
      if (classes[i].score_class == NULL) {
        break;
      }

      printf("Service class %-20s - %3lu %s\n", classes[i].score_class,
        classes[i].score_count, classes[i].score_count > 1 ? "users" : "user");

      /* Free up the memory, now that we're done with it. */
      free(classes[i].score_class);
      classes[i].score_class = NULL;
    }

  } else {
    if (!mpid) {
      printf("inetd FTP connections:\n");

    } else {
      printf("Master proftpd process %u:\n", (unsigned int) mpid);
    }

    printf("0 users\n");
  }

  if (server_name) {
    free(server_name);
  }

  return 0;
}
