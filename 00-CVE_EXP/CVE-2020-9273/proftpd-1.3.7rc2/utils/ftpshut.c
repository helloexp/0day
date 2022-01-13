/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 2001-2015 The ProFTPD Project team
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

/* Simple utility to create the proftpd shutdown message file, allowing
 * an admin to configure the shutdown, deny, disconnect times and messages.
 */

#include "conf.h"

static void show_usage(char *progname) {
  printf("usage: %s [ -R ] [ -l min ] [ -d min ] time "
    " [ warning-message ... ]\n", progname);

  exit(1);
}

static int isnumeric(char *str) {
  while (str && PR_ISSPACE(*str)) {
    str++;
  }

  if (str == NULL ||
      !*str) {
    return 0;
  }

  for (; str && *str; str++) {
    if (!PR_ISDIGIT(*str)) {
      return 0;
    }
  }

  return 1;
}

int main(int argc, char *argv[]) {
  int deny = 10,disc = 5,c;
  FILE *outf;
  char *shut,*msg,*progname = argv[0];
  time_t now;
  struct tm *tm;
  int mn = 0,hr = 0;

  opterr = 0;

  while ((c = getopt(argc, argv, "Rl:d:")) != -1) {
    switch (c) {
      case 'R':
        if (unlink(PR_SHUTMSG_PATH) < 0) {
          fprintf(stderr, "%s: error removing '" PR_SHUTMSG_PATH "': %s\n",
            progname, strerror(errno));
          exit(1);
        }
        fprintf(stdout, "%s: " PR_SHUTMSG_PATH " removed\n", progname);
        exit(0);

      case 'l':
      case 'd':
        if (!optarg) {
          fprintf(stderr, "%s: -%c requires an argument\n", progname, c);
          show_usage(progname);
        }

        if (!isnumeric(optarg)) {
	  fprintf(stderr, "%s: -%c requires a numeric argument\n", progname, c);
	  show_usage(progname);
        }

        if (c == 'd') {
	  disc = atoi(optarg);

        } else if (c == 'l') {
	  deny = atoi(optarg);
        }

        break;

      case '?':
        fprintf(stderr, "%s: unknown option '%c'\n", progname, (char)optopt);
        show_usage(progname);
        break;

      case 'h':
      default:
        show_usage(progname);
    }
  }

  /* Everything left on the command line is the message */
  if (optind >= argc) {
    show_usage(progname);
  }

  shut = argv[optind++];

  if (optind < argc) {
    msg = argv[optind];

  } else {
    msg = "going down at %s";
  }

  time(&now);
  tm = localtime(&now);

  /* shut must be either 'now', '+number' or 'HHMM' */
  if (strcasecmp(shut,"now") != 0) {
    if (*shut == '+') {
      shut++;
      while (shut && *shut && PR_ISSPACE(*shut)) shut++;

      if (!isnumeric(shut)) {
        fprintf(stderr, "%s: Invalid time interval specified.\n", progname);
        show_usage(progname);
      }

      now += (60 * atoi(shut));
      tm = localtime(&now);

    } else {
      if ((strlen(shut) != 4 && strlen(shut) != 2) || !isnumeric(shut)) {
        fprintf(stderr, "%s: Invalid time interval specified.\n", progname);
        show_usage(progname);
      }

      if (strlen(shut) > 2) {
        mn = atoi((shut + strlen(shut) - 2));
        if (mn > 59) {
          fprintf(stderr, "%s: Invalid time interval specified.\n", progname);
          show_usage(progname);
        }

        *(shut + strlen(shut) - 2) = '\0';
      }

      hr = atoi(shut);
      if (hr > 23) {
        fprintf(stderr, "%s: Invalid time interval specified.\n", progname);
        show_usage(progname);
      }

      if (hr < tm->tm_hour ||
          (hr == tm->tm_hour &&
           mn <= tm->tm_min)) {
        now += 86400;		/* one day forward */
        tm = localtime(&now);
      }
      tm->tm_hour = hr;
      tm->tm_min = mn;
    }
  }

  umask(022);

  outf = fopen(PR_SHUTMSG_PATH, "w");
  if (outf == NULL) {
    fprintf(stderr,"%s: error opening '" PR_SHUTMSG_PATH "': %s\n", progname,
      strerror(errno));
    exit(1);
  }

  fprintf(outf, "%d %d %d %d %d %d",
          tm->tm_year+1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour,
          tm->tm_min, tm->tm_sec);
  fprintf(outf, " %02d%02d %02d%02d\n",
          (deny / 60), (deny % 60),
          (disc / 60), (disc % 60));
  fprintf(outf, "%s\n", msg);
  fclose(outf);
  return 0;
}
