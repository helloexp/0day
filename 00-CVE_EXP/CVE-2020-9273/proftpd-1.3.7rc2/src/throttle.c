/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2008-2017 The ProFTPD Project team
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

/* TransferRate throttling */

#include "conf.h"

/* Transfer rate variables */
static long double xfer_rate_kbps = 0.0, xfer_rate_bps = 0.0;
static off_t xfer_rate_freebytes = 0.0;
static int have_xfer_rate = FALSE;
static unsigned int xfer_rate_scoreboard_updates = 0;

/* Very similar to the {block,unblock}_signals() function, this masks most
 * of the same signals -- except for TERM.  This allows a throttling process
 * to be killed by the admin.
 */
static void xfer_rate_sigmask(int block) {
  static sigset_t sig_set;

  if (block) {
    sigemptyset(&sig_set);

    sigaddset(&sig_set, SIGCHLD);
    sigaddset(&sig_set, SIGUSR1);
    sigaddset(&sig_set, SIGINT);
    sigaddset(&sig_set, SIGQUIT);
#ifdef SIGIO
    sigaddset(&sig_set, SIGIO);
#endif /* SIGIO */
#ifdef SIGBUS
    sigaddset(&sig_set, SIGBUS);
#endif /* SIGBUS */
    sigaddset(&sig_set, SIGHUP);

    while (sigprocmask(SIG_BLOCK, &sig_set, NULL) < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
        continue;
      }

      break;
    }

  } else {
    while (sigprocmask(SIG_UNBLOCK, &sig_set, NULL) < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
        continue;
      }

      break;
    }
  }
}

/* Returns the difference, in milliseconds, between the given timeval and
 * now.
 */
static long xfer_rate_since(struct timeval *then) {
  struct timeval now;
  gettimeofday(&now, NULL);

  return (((now.tv_sec - then->tv_sec) * 1000L) +
    ((now.tv_usec - then->tv_usec) / 1000L));
}

int pr_throttle_have_rate(void) {
  return have_xfer_rate;
}

void pr_throttle_init(cmd_rec *cmd) {
  config_rec *c = NULL;
  char *xfer_cmd = NULL;
  unsigned char have_user_rate = FALSE, have_group_rate = FALSE,
    have_class_rate = FALSE;
  unsigned int precedence = 0;

  /* Make sure the variables are (re)initialized */
  xfer_rate_kbps = xfer_rate_bps = 0.0;
  xfer_rate_freebytes = 0;
  xfer_rate_scoreboard_updates = 0;
  have_xfer_rate = FALSE;

  c = find_config(CURRENT_CONF, CONF_PARAM, "TransferRate", FALSE);

  /* Note: need to cycle through all the matching config_recs, and using
   * the information from the current config_rec only if it matches
   * the target *and* has a higher precedence than any of the previously
   * found config_recs.
   */
  while (c) {
    char **cmdlist = (char **) c->argv[0];
    int matched_cmd = FALSE;

    pr_signals_handle();

    /* Does this TransferRate apply to the current command?  Note: this
     * could be made more efficient by using bitmasks rather than string
     * comparisons.
     */
    for (xfer_cmd = *cmdlist; xfer_cmd; xfer_cmd = *(cmdlist++)) {
      if (strcasecmp(xfer_cmd, cmd->argv[0]) == 0) {
        matched_cmd = TRUE;
        break;
      }
    }

    /* No -- continue on to the next TransferRate. */
    if (!matched_cmd) {
      c = find_config_next(c, c->next, CONF_PARAM, "TransferRate", FALSE);
      continue;
    }

    if (c->argc > 4) {
      if (strncmp(c->argv[4], "user", 5) == 0) {

        if (pr_expr_eval_user_or((char **) &c->argv[5]) == TRUE &&
            *((unsigned int *) c->argv[3]) > precedence) {

          /* Set the precedence. */
          precedence = *((unsigned int *) c->argv[3]);

          xfer_rate_kbps = *((long double *) c->argv[1]);
          xfer_rate_freebytes = *((off_t *) c->argv[2]);
          have_xfer_rate = TRUE;
          have_user_rate = TRUE;
          have_group_rate = have_class_rate = FALSE;
        }

      } else if (strncmp(c->argv[4], "group", 6) == 0) {

        if (pr_expr_eval_group_and((char **) &c->argv[5]) == TRUE &&
            *((unsigned int *) c->argv[3]) > precedence) {

          /* Set the precedence. */
          precedence = *((unsigned int *) c->argv[3]);

          xfer_rate_kbps = *((long double *) c->argv[1]);
          xfer_rate_freebytes = *((off_t *) c->argv[2]);
          have_xfer_rate = TRUE;
          have_group_rate = TRUE;
          have_user_rate = have_class_rate = FALSE;
        }

      } else if (strncmp(c->argv[4], "class", 6) == 0) {

        if (pr_expr_eval_class_or((char **) &c->argv[5]) == TRUE &&
          *((unsigned int *) c->argv[3]) > precedence) {

          /* Set the precedence. */
          precedence = *((unsigned int *) c->argv[3]);

          xfer_rate_kbps = *((long double *) c->argv[1]);
          xfer_rate_freebytes = *((off_t *) c->argv[2]);
          have_xfer_rate = TRUE;
          have_class_rate = TRUE;
          have_user_rate = have_group_rate = FALSE;
        }
      }

    } else {

      if (*((unsigned int *) c->argv[3]) > precedence) {

        /* Set the precedence. */
        precedence = *((unsigned int *) c->argv[3]);

        xfer_rate_kbps = *((long double *) c->argv[1]);
        xfer_rate_freebytes = *((off_t *) c->argv[2]);
        have_xfer_rate = TRUE;
        have_user_rate = have_group_rate = have_class_rate = FALSE;
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "TransferRate", FALSE);
  }

  /* Print out a helpful debugging message. */
  if (have_xfer_rate) {
    pr_log_debug(DEBUG3, "TransferRate (%.3Lf KB/s, %" PR_LU
        " bytes free) in effect%s", xfer_rate_kbps,
      (pr_off_t) xfer_rate_freebytes,
      have_user_rate ? " for current user" :
      have_group_rate ? " for current group" :
      have_class_rate ? " for current class" : "");

    /* Convert the configured Kbps to bytes per usec, for use later.
     * The 1024.0 factor converts for Kbytes to bytes, and the
     * 1000000.0 factor converts from secs to usecs.
     */
    xfer_rate_bps = xfer_rate_kbps * 1024.0;
  }
}

void pr_throttle_pause(off_t xferlen, int xfer_ending) {
  long ideal = 0, elapsed = 0;
  off_t orig_xferlen = xferlen;

  if (XFER_ABORTED) {
    return;
  }

  /* Calculate the time interval since the transfer of data started. */
  elapsed = xfer_rate_since(&session.xfer.start_time);

  /* Perform no throttling if no throttling has been configured. */
  if (!have_xfer_rate) {
    xfer_rate_scoreboard_updates++;

    if (xfer_ending ||
        xfer_rate_scoreboard_updates % PR_TUNABLE_XFER_SCOREBOARD_UPDATES == 0) {
      /* Update the scoreboard. */
      pr_scoreboard_entry_update(session.pid,
        PR_SCORE_XFER_LEN, orig_xferlen,
        PR_SCORE_XFER_ELAPSED, (unsigned long) elapsed,
        NULL);

      xfer_rate_scoreboard_updates = 0;
    }

    return;
  }

  /* Give credit for any configured freebytes. */
  if (xferlen > 0 &&
      xfer_rate_freebytes > 0) {

    if (xferlen > xfer_rate_freebytes) {
      /* Decrement the number of bytes transferred by the freebytes, so that
       * any throttling does not take into account the freebytes.
       */
      xferlen -= xfer_rate_freebytes;

    } else {
      xfer_rate_scoreboard_updates++;

      /* The number of bytes transferred is less than the freebytes.  Just
       * update the scoreboard -- no throttling needed.
       */

      if (xfer_ending ||
          xfer_rate_scoreboard_updates % PR_TUNABLE_XFER_SCOREBOARD_UPDATES == 0) {
        pr_scoreboard_entry_update(session.pid,
          PR_SCORE_XFER_LEN, orig_xferlen,
          PR_SCORE_XFER_ELAPSED, (unsigned long) elapsed,
          NULL);

        xfer_rate_scoreboard_updates = 0;
      }

      return;
    }
  }

  ideal = xferlen * 1000L / xfer_rate_bps;

  if (ideal > elapsed) {
    struct timeval tv;

    /* Setup for the select.  We use select() instead of usleep() because it
     * seems to be far more portable across platforms.
     *
     * ideal and elapsed are in milleconds, but tv_usec will be microseconds,
     * so be sure to convert properly.
     */
    tv.tv_usec = (ideal - elapsed) * 1000;
    tv.tv_sec = tv.tv_usec / 1000000L;
    tv.tv_usec = tv.tv_usec % 1000000L;

    pr_log_debug(DEBUG7, "transferring too fast, delaying %ld sec%s, %ld usecs",
      (long int) tv.tv_sec, tv.tv_sec == 1 ? "" : "s", (long int) tv.tv_usec);

    /* No interruptions, please... */
    xfer_rate_sigmask(TRUE);

    if (select(0, NULL, NULL, NULL, &tv) < 0) {
      int xerrno = errno;

      if (XFER_ABORTED) {
        pr_log_pri(PR_LOG_NOTICE, "throttling interrupted, transfer aborted");
        xfer_rate_sigmask(FALSE);
        return;
      }

      /* At this point, we've probably been interrupted by one of the few
       * signals not masked off, e.g. SIGTERM.
       */
      if (xerrno != EINTR) {
        pr_log_debug(DEBUG0, "unable to throttle bandwidth: %s",
          strerror(xerrno));
      }
    }

    xfer_rate_sigmask(FALSE);
    pr_signals_handle();

    /* Update the scoreboard. */
    pr_scoreboard_entry_update(session.pid,
      PR_SCORE_XFER_LEN, orig_xferlen,
      PR_SCORE_XFER_ELAPSED, (unsigned long) ideal,
      NULL);

  } else {

    /* Update the scoreboard. */
    pr_scoreboard_entry_update(session.pid,
      PR_SCORE_XFER_LEN, orig_xferlen,
      PR_SCORE_XFER_ELAPSED, (unsigned long) elapsed,
      NULL);
  }

  return;
}
