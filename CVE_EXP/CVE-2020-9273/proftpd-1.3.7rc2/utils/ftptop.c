/*
 * ProFTPD - ftptop: a utility for monitoring proftpd sessions
 * Copyright (c) 2000-2002 TJ Saunders <tj@castaglia.org>
 * Copyright (c) 2003-2016 The ProFTPD Project team
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
 */

/* Shows who is online via proftpd, in a manner similar to top.  Uses the
 * scoreboard files.
 */

#define FTPTOP_VERSION 		"ftptop/0.9"

#include "utils.h"

#include <ctype.h>
#include <stdlib.h>
#include <time.h>

#if defined(PR_USE_NLS) && defined(HAVE_LOCALE_H)
# include <locale.h>
#endif

static const char *program = "ftptop";

/* ncurses is preferred...*/

#if defined(HAVE_NCURSES_H) && \
    ((defined(HAVE_LIBNCURSES) && defined(PR_USE_NCURSES) || \
     (defined(HAVE_LIBNCURSESW) && defined(PR_USE_NCURSESW))))
# define HAVE_NCURSES 1
# include <ncurses.h>
#elif defined(HAVE_CURSES_H) && defined(HAVE_LIBCURSES) && \
    defined(PR_USE_CURSES)
# define HAVE_CURSES 1
/* Sigh...portability.  It seems that Solaris' curses.h (at least for 2.8)
 * steps on wide-character macros, generating compiler warnings.  This, then
 * is just a hack to silence the compiler.
 */
# ifdef SOLARIS2
#  define __lint
# endif
# include <curses.h>
#endif

#if defined(HAVE_NCURSES) || defined(HAVE_CURSES)

/* Display options */

/* These are for displaying "PID S USER CLIENT SERVER TIME COMMAND" */
#define FTPTOP_REG_HEADER_FMT	"%-5s %s %-8s %-20s %-15s %-4s %-*s\n"
#define FTPTOP_REG_DISPLAY_FMT	"%-5u %s %-*.*s %-*.*s %-15s %-6.6s %4s %-*.*s\n"

/* These are for displaying tranfer data: "PID S USER CLIENT KB/s %DONE" */
#define FTPTOP_XFER_HEADER_FMT	"%-5s %s %-8s %-44s %-10s %-*s\n"
#define FTPTOP_XFER_DISPLAY_FMT	"%-5u %s %-*.*s %-*.*s %-10.2f %-*.*s\n"

#define FTPTOP_REG_ARG_MIN_SIZE		20
#define FTPTOP_XFER_DONE_MIN_SIZE	6
#define FTPTOP_REG_ARG_SIZE	\
  (COLS - (80 - FTPTOP_REG_ARG_MIN_SIZE) < FTPTOP_REG_ARG_MIN_SIZE ? \
  FTPTOP_REG_ARG_MIN_SIZE : COLS - (80 - FTPTOP_REG_ARG_MIN_SIZE))
#define FTPTOP_XFER_DONE_SIZE 	\
  (COLS - (80 - FTPTOP_XFER_DONE_MIN_SIZE) < FTPTOP_XFER_DONE_MIN_SIZE ? \
  FTPTOP_XFER_DONE_MIN_SIZE : COLS - (80 - FTPTOP_XFER_DONE_MIN_SIZE))

#define FTPTOP_SHOW_DOWNLOAD		0x0001
#define FTPTOP_SHOW_UPLOAD		0x0002
#define FTPTOP_SHOW_IDLE		0x0004
#define FTPTOP_SHOW_AUTH		0x0008
#define	FTPTOP_SHOW_REG \
  (FTPTOP_SHOW_DOWNLOAD|FTPTOP_SHOW_UPLOAD|FTPTOP_SHOW_IDLE)
#define FTPTOP_SHOW_RATES		0x0010

static int delay = 2;
static unsigned int display_mode = FTPTOP_SHOW_REG;

static char *config_filename = PR_CONFIG_FILE_PATH;

/* Scoreboard variables */
static time_t ftp_uptime = 0;
static unsigned int ftp_nsessions = 0;
static unsigned int ftp_nuploads = 0;
static unsigned int ftp_ndownloads = 0;
static unsigned int ftp_nidles = 0;
static char *server_name = NULL;
static char **ftp_sessions = NULL;
static unsigned int chunklen = 3;

/* necessary prototypes */
static void scoreboard_close(void);
static int scoreboard_open(void);

static void show_version(void);
static const char *show_ftpd_uptime(void);
static void usage(void);

static void clear_counters(void) {

  if (ftp_sessions &&
      ftp_nsessions > 0) {
    register unsigned int i = 0;

    for (i = 0; i < ftp_nsessions; i++)
      free(ftp_sessions[i]);
    free(ftp_sessions);
    ftp_sessions = NULL;
  }

  /* Reset the session counters. */
  ftp_nsessions = 0;
  ftp_nuploads = 0;
  ftp_ndownloads = 0;
  ftp_nidles = 0;
}

static void finish(int signo) {
  endwin();
  exit(0);
}

static char *calc_percent_done(off_t size, off_t done) {
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

/* Given a NUL-terminated string -- possibly UTF8-encoded -- and a maximum
 * CHARACTER length, return the number of bytes in the string which can fit in
 * that max length  without truncating a character.  This is needed since UTF8
 * characters are variable-width.
 */
static int str_getscreenlen(const char *str, size_t max_chars) {
#ifdef PR_USE_NLS
  register unsigned int i = 0;
  int nbytes = 0, nchars = 0;

  while (str[i] > 0 &&
         i < max_chars) {
ascii:
    i++;
    nbytes++;
    nchars++;
  }

  while (str[i] &&
         (size_t) nchars < max_chars) {
    size_t len;

    if (str[i] > 0) {
      goto ascii;
    }

    len = 0;

    switch (str[i] & 0xF0) {
      case 0xE0:
        len = 3;
        break;

      case 0xF0:
        len = 4;
        break;

      default:
        len = 2;
        break;
    }

    /* Increment the index with the given length, but increment the
     * character count only one.
     */

    i += len;
    nbytes += len;
    nchars++;
  }

  return nbytes;
#else
  /* No UTF8 support in this proftpd build; just return the max characters. */
  return (int) max_chars;
#endif /* !PR_USE_NLS */
}

/* Borrowed from ftpwho.c */
static const char *show_time(time_t *i) {
  time_t now = time(NULL);
  unsigned long l;
  static char sbuf[7];

  if (!i || !*i)
    return "-";

  memset(sbuf, '\0', sizeof(sbuf));
  l = now - *i;

  if (l < 3600) {
    snprintf(sbuf, sizeof(sbuf), "%lum%lus",(l / 60),(l % 60));

  } else {
    snprintf(sbuf, sizeof(sbuf), "%luh%lum",(l / 3600),
      ((l - (l / 3600) * 3600) / 60));
  }

  return sbuf;
}

static int check_scoreboard_file(void) {
  struct stat sbuf;

  if (stat(util_get_scoreboard(), &sbuf) < 0)
    return -1;

  return 0;
}

static const char *show_ftpd_uptime(void) {
  static char buf[128] = {'\0'};
  time_t uptime_secs = time(NULL) - ftp_uptime;
  int upminutes, uphours, updays;
  int pos = 0;

  if (!ftp_uptime)
    return "";

  memset(buf, '\0', sizeof(buf));
  pos += snprintf(buf, sizeof(buf)-1, "%s", ", up for ");

  updays = (int) uptime_secs / (60 * 60 * 24);

  if (updays) {
    pos += snprintf(buf + pos, sizeof(buf) - pos, "%d day%s, ", updays,
      (updays != 1) ? "s" : "");
  }

  upminutes = (int) uptime_secs / 60;

  uphours = upminutes / 60;
  uphours = uphours % 24;

  upminutes = upminutes % 60;

  if (uphours) {
    snprintf(buf + pos, sizeof(buf) - pos, "%2d hr%s %02d min", uphours,
      (uphours != 1) ? "s" : "", upminutes);

  } else {
    snprintf(buf + pos, sizeof(buf) - pos, "%d min", upminutes);
  }

  return buf;
}

static void process_opts(int argc, char *argv[]) {
  int optc = 0;
  const char *prgopts = "AaDS:d:f:hIiUV";

  while ((optc = getopt(argc, argv, prgopts)) != -1) {
    switch (optc) {
      case 'A':
        display_mode = 0U;
        display_mode |= FTPTOP_SHOW_AUTH;
        break;

      case 'a':
        display_mode &= ~FTPTOP_SHOW_AUTH;
        break;
 
      case 'D':
        display_mode = 0U;
        display_mode |= FTPTOP_SHOW_DOWNLOAD;
        break;

      case 'S':
        if (server_name != NULL) {
          free(server_name);
          server_name = NULL;
        }

        server_name = strdup(optarg);
        break;

      case 'd':
        delay = atoi(optarg);

        if (delay < 0) {
          fprintf(stderr, "%s: negative delay illegal: %d\n", program,
            delay);
          exit(1);
        }

        if (delay > 15) {
          fprintf(stderr, "%s: delay of 0-15 seconds only supported\n",
            program);
          exit(1);
        }

        break;

      case 'f':
        if (util_set_scoreboard(optarg) < 0) {
          fprintf(stderr, "%s: unable to use scoreboard '%s': %s\n",
            program, optarg, strerror(errno));
          exit(1);
        }
        break;

      case 'h':
        usage();
        break;

      case 'I':
        display_mode = 0U;
        display_mode |= FTPTOP_SHOW_IDLE;
        break;

      case 'i':
        display_mode &= ~FTPTOP_SHOW_IDLE;
        break;

      case 'U':
        display_mode = 0U;
        display_mode |= FTPTOP_SHOW_UPLOAD;
        break;

      case 'V':
        show_version();
        break;

      case '?':
        break;

     default:
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
}

static void read_scoreboard(void) {

  /* NOTE: this buffer should probably be limited to the maximum window
   * width, as it is used for display purposes.
   */
  static char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'};
  pr_scoreboard_entry_t *score = NULL;

  ftp_sessions = calloc(chunklen, sizeof(char *));
  if (ftp_sessions == NULL)
    exit(1);

  if (scoreboard_open() < 0)
    return;

  /* Iterate through the scoreboard. */
  while ((score = util_scoreboard_entry_read()) != NULL) {

    /* Default status: "A" for "authenticating" */
    char *status = "A";

    /* If a ServerName was given, skip unless the scoreboard entry matches. */
    if (server_name != NULL &&
        strcmp(server_name, score->sce_server_label) != 0) {
      continue;
    }

    /* Clear the buffer for this run. */
    memset(buf, '\0', sizeof(buf));

    /* Has the user authenticated yet? */
    if (strcmp(score->sce_user, "(none)") != 0) {

      /* Determine the status symbol to display. */
      if (strcmp(score->sce_cmd, "idle") == 0) {
        status = "I";
        ftp_nidles++;

        if (display_mode != FTPTOP_SHOW_RATES &&
            !(display_mode & FTPTOP_SHOW_IDLE))
          continue;

      } else if (strcmp(score->sce_cmd, "RETR") == 0 ||
                 strcmp(score->sce_cmd, "READ") == 0 ||
                 strcmp(score->sce_cmd, "scp download") == 0) {
        status = "D";
        ftp_ndownloads++;

        if (display_mode != FTPTOP_SHOW_RATES &&
            !(display_mode & FTPTOP_SHOW_DOWNLOAD))
          continue;

      } else if (strcmp(score->sce_cmd, "STOR") == 0 ||
                 strcmp(score->sce_cmd, "APPE") == 0 ||
                 strcmp(score->sce_cmd, "STOU") == 0 ||
                 strcmp(score->sce_cmd, "WRITE") == 0 ||
                 strcmp(score->sce_cmd, "scp upload") == 0) {
        status = "U";
        ftp_nuploads++;

        if (display_mode != FTPTOP_SHOW_RATES &&
            !(display_mode & FTPTOP_SHOW_UPLOAD))
          continue;

      } else if (strcmp(score->sce_cmd, "LIST") == 0 ||
                 strcmp(score->sce_cmd, "NLST") == 0 ||
                 strcmp(score->sce_cmd, "MLST") == 0 ||
                 strcmp(score->sce_cmd, "MLSD") == 0 ||
                 strcmp(score->sce_cmd, "READDIR") == 0) {
        status = "L";
      }

    } else {
      status = "A";

      /* Overwrite the "command", for display purposes */
      util_sstrncpy(score->sce_cmd, "(authenticating)", sizeof(score->sce_cmd));
    }

    if (display_mode != FTPTOP_SHOW_RATES) {
      int user_namelen, client_namelen, cmd_arglen;

      user_namelen = str_getscreenlen(score->sce_user, 8);
      client_namelen = str_getscreenlen(score->sce_client_name, 20);
      cmd_arglen = str_getscreenlen(score->sce_cmd_arg, FTPTOP_REG_ARG_SIZE);

      snprintf(buf, sizeof(buf), FTPTOP_REG_DISPLAY_FMT,
        (unsigned int) score->sce_pid, status,
        user_namelen, user_namelen, score->sce_user,
        client_namelen, client_namelen, score->sce_client_name,
        score->sce_server_addr,
        show_time(&score->sce_begin_session), score->sce_cmd,
        cmd_arglen, cmd_arglen, score->sce_cmd_arg);
      buf[sizeof(buf)-1] = '\0';

    } else {
      int user_namelen, client_namelen;

      user_namelen = str_getscreenlen(score->sce_user, 8);
      client_namelen = str_getscreenlen(score->sce_client_name, 44);

      /* Skip sessions unless they are actually transferring data */
      if (*status != 'U' && *status != 'D')
        continue;

      snprintf(buf, sizeof(buf), FTPTOP_XFER_DISPLAY_FMT,
        (unsigned int) score->sce_pid, status,
        user_namelen, user_namelen, score->sce_user,
        client_namelen, client_namelen, score->sce_client_name,
        (score->sce_xfer_len / 1024.0) / (score->sce_xfer_elapsed / 1000),
        FTPTOP_XFER_DONE_SIZE, FTPTOP_XFER_DONE_SIZE,
        *status == 'D' ?
          calc_percent_done(score->sce_xfer_size, score->sce_xfer_done) :
          "(n/a)");
      buf[sizeof(buf)-1] = '\0';
    }

    /* Make sure there is enough memory allocated in the session list.
     * Allocate more if needed.
     */
    if (ftp_nsessions &&
        ftp_nsessions % chunklen == 0) {
      ftp_sessions = realloc(ftp_sessions,
        (ftp_nsessions + chunklen) * sizeof(char *));

      if (ftp_sessions == NULL) {
        exit(1);
      }
    }

    ftp_sessions[ftp_nsessions] = calloc(1, strlen(buf) + 1);
    if (ftp_sessions[ftp_nsessions] == NULL) {
      exit(1);
    }

    util_sstrncpy(ftp_sessions[ftp_nsessions++], buf, strlen(buf) + 1);
  }

  scoreboard_close();
}

static void scoreboard_close(void) {
  util_close_scoreboard();
}

static int scoreboard_open(void) {
  int res = 0;

  res = util_open_scoreboard(O_RDONLY);
  if (res < 0) {
    switch (res) {
      case UTIL_SCORE_ERR_BAD_MAGIC:
        fprintf(stderr, "%s: error opening scoreboard: bad/corrupted file\n",
          program);
        return res;

      case UTIL_SCORE_ERR_OLDER_VERSION:
        fprintf(stderr, "%s: error opening scoreboard: bad version (too old)\n",
          program);
        return res;

      case UTIL_SCORE_ERR_NEWER_VERSION:
        fprintf(stderr, "%s: error opening scoreboard: bad version (too new)\n",
          program);
        return res;

      default:
        fprintf(stderr, "%s: error opening scoreboard: %s\n",
          program, strerror(errno));
        return res;
    }
  }

  ftp_uptime = util_scoreboard_get_daemon_uptime();

  return 0;
}

static void show_sessions(void) {
  time_t now;
  char *now_str = NULL;
  const char *uptime_str = NULL;

  clear_counters();
  read_scoreboard();

  time(&now);

  /* Trim ctime(3)'s trailing newline. */
  now_str = ctime(&now);
  now_str[strlen(now_str)-1] = '\0';

  uptime_str = show_ftpd_uptime();

  wclear(stdscr);
  move(0, 0);

  attron(A_BOLD);
  printw(FTPTOP_VERSION ": %s%s\n", now_str, uptime_str);
  printw("%u Total FTP Sessions: %u downloading, %u uploading, %u idle\n",
    ftp_nsessions, ftp_ndownloads, ftp_nuploads, ftp_nidles);
  attroff(A_BOLD);

  printw("\n");

  attron(A_REVERSE);

  if (display_mode != FTPTOP_SHOW_RATES) {
    printw(FTPTOP_REG_HEADER_FMT, "PID", "S", "USER", "CLIENT", "SERVER",
      "TIME", FTPTOP_REG_ARG_SIZE, "COMMAND");

  } else {
    printw(FTPTOP_XFER_HEADER_FMT, "PID", "S", "USER", "CLIENT", "KB/s", FTPTOP_XFER_DONE_SIZE, "%DONE");
  }

  attroff(A_REVERSE);

  /* Write out the scoreboard entries. */
  if (ftp_sessions &&
      ftp_nsessions > 0) {
    register unsigned int i = 0;

    for (i = 0; i < ftp_nsessions; i++) {
      printw("%s", ftp_sessions[i]);
    }
  }

  wrefresh(stdscr);
}

static void toggle_mode(void) {
  static unsigned int cached_mode = 0;

  if (cached_mode == 0)
    cached_mode = display_mode;

  if (display_mode != FTPTOP_SHOW_RATES) {
    display_mode = FTPTOP_SHOW_RATES;

  } else {
    display_mode = cached_mode;
  }
}

static void show_version(void) {
  fprintf(stdout, FTPTOP_VERSION "\n");
  exit(0);
}

static void usage(void) {
  fprintf(stdout, "usage: ftptop [options]\n\n");
  fprintf(stdout, "\t-A      \t\tshow only authenticatng sessions\n");
  fprintf(stdout, "\t-a      \t\tignores authenticating connections when listing\n");
  fprintf(stdout, "\t-D      \t\tshow only downloading sessions\n");
  fprintf(stdout, "\t-d <num>\t\trefresh delay in seconds\n");
  fprintf(stdout, "\t-f      \t\tconfigures the ScoreboardFile to use\n");
  fprintf(stdout, "\t-h      \t\tdisplays this message\n");
  fprintf(stdout, "\t-i      \t\tignores idle connections when listing\n");
  fprintf(stdout, "\t-U      \t\tshow only uploading sessions\n");
  fprintf(stdout, "\t-V      \t\tshows version\n");
  fprintf(stdout, "\n");
  fprintf(stdout, "  Use the 't' key to toggle between \"regular\" and \"transfer speed\"\n");
  fprintf(stdout, "  display modes. Use the 'q' key to quit.\n\n");
  exit(0);
}

static void verify_scoreboard_file(void) {
  struct stat sbuf;

  if (stat(util_get_scoreboard(), &sbuf) < 0) {
    fprintf(stderr, "%s: unable to stat '%s': %s\n", program,
      util_get_scoreboard(), strerror(errno));
    exit(1);
  }
}

int main(int argc, char *argv[]) {

  /* Process command line options. */
  process_opts(argc, argv);

  /* Verify that the scoreboard file is usable. */
  verify_scoreboard_file();

  /* Install signal handlers. */
  signal(SIGINT, finish);
  signal(SIGTERM, finish);

#if defined(PR_USE_NLS) && defined(HAVE_LOCALE_H)
  (void) setlocale(LC_ALL, "");
#endif

  /* Initialize the display. */
  initscr();
  cbreak();
  noecho();
#ifndef HAVE_NCURSES
  nodelay(stdscr, TRUE);
#endif
  curs_set(0);

  /* Paint the initial display. */
  show_sessions();

  /* Loop endlessly. */
  for (;;) {
    int c = -1;

#ifdef HAVE_NCURSES
    if (halfdelay(delay * 10) != ERR)
      c = getch();
#else
    sleep(delay);
    c = getch();
#endif

    if (c != -1) {
      if (tolower(c) == 'q') {
        break;
      }

      if (tolower(c) == 't') {
        toggle_mode();
      }
    }

    show_sessions();
  }

  /* done */
  finish(0);
  return 0;
}

#else /* defined(HAVE_CURSES) || defined(HAVE_NCURSES) */

#include <stdio.h>

int main(int argc, char *argv[]) {
  fprintf(stdout, "%s: no curses or ncurses library on this system\n", program);
  return 1;
}

#endif /* defined(HAVE_CURSES) || defined(HAVE_NCURSES) */
