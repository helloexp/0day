/*
 * ProFTPD - FTP server daemon
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
 * As a special exemption, The ProFTPD Project and other respective copyright
 * holders give permission to link this program with OpenSSL, and distribute
 * the resulting executable, without including the source code for OpenSSL in
 * the source distribution.
 */

/* "Scrubs" the scoreboard file, clearing it of old/stale entries. */

#include "utils.h"

static const char *config_filename = PR_CONFIG_FILE_PATH;

static int check_scoreboard_file(void) {
  struct stat st;

  if (stat(util_get_scoreboard(), &st) < 0) {
    return -1;
  }

  return 0;
}

static struct option_help {
  const char *long_opt, *short_opt, *desc;
} opts_help[] = {
  { "--config",	"-c",	"specify full path to proftpd configuration file" },
  { "--file",	"-f",	"specify full path to scoreboard file" },
  { "--help",	"-h",	NULL },
  { "--verbose","-v",	NULL },
  { NULL }
};

#ifdef HAVE_GETOPT_LONG
static struct option opts[] = {
  { "config",  1, NULL, 'c' },
  { "file",    1, NULL, 'f' },
  { "help",    0, NULL, 'h' },
  { "verbose", 0, NULL, 'v' },
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
  int c = 0, res = 0;
  int verbose = FALSE;
  char *cp, *progname = *argv;
  const char *cmdopts = "c:f:hv";

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

      case 'f':
        util_set_scoreboard(optarg);
        break;

      case 'c':
        config_filename = strdup(optarg);
        break;

      case 'v':
        verbose = TRUE;
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

  res = util_scoreboard_scrub(verbose);
  if (res < 0) {
    fprintf(stderr, "error scrubbing scoreboard %s: %s\n",
      util_get_scoreboard(), strerror(errno));
    return 1;
  }

  return 0;
}
