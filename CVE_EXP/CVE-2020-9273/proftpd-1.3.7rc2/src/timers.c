/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 2001-2016 The ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * BUT witHOUT ANY WARRANTY; without even the implied warranty of
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

/* Timer system, based on alarm() and SIGALRM. */

#include "conf.h"

/* From src/main.c */
extern volatile unsigned int recvd_signal_flags;

struct timer {
  struct timer *next, *prev;

  long count;                   /* Amount of time remaining */
  long interval;                /* Original length of timer */

  int timerno;                  /* Caller dependent timer number */
  module *mod;                  /* Module owning this timer */
  callback_t callback;          /* Function to callback */
  char remove;                  /* Internal use */

  const char *desc;		/* Description of timer, provided by caller */
};

#define PR_TIMER_DYNAMIC_TIMERNO	1024

static int _current_timeout = 0;
static int _total_time = 0;
static int _sleep_sem = 0;
static int alarms_blocked = 0, alarm_pending = 0;
static xaset_t *timers = NULL;
static xaset_t *recycled = NULL;
static xaset_t *free_timers = NULL;
static int _indispatch = 0;
static int dynamic_timerno = PR_TIMER_DYNAMIC_TIMERNO;
static unsigned int nalarms = 0;
static time_t _alarmed_time = 0;

static pool *timer_pool = NULL;

static const char *trace_channel = "timer";

static int timer_cmp(struct timer *t1, struct timer *t2) {
  if (t1->count < t2->count) {
    return -1;
  }

  if (t1->count > t2->count) {
    return 1;
  }

  return 0;
}

/* This function does the work of iterating through the list of registered
 * timers, checking to see if their callbacks should be invoked and whether
 * they should be removed from the registration list. Its return value is
 * the amount of time remaining on the first timer in the list.
 */
static int process_timers(int elapsed) {
  struct timer *t = NULL, *next = NULL;
  int res = 0;

  if (recycled == NULL) {
    recycled = xaset_create(timer_pool, NULL);
  }

  if (elapsed == 0 &&
      recycled->xas_list == NULL) {
    if (timers == NULL) {
      return 0;
    }

    if (timers->xas_list != NULL) {
      /* The value we return is a proposed timeout, for the next call to
       * alarm(3).  We start with the simple count of timers in our list.
       *
       * But then we reduce the number; some of the timers' intervals may
       * less than the number of total timers.
       */
      res = ((struct timer *) timers->xas_list)->count;
      if (res > 5) {
        res = 5;
      }
    }

    return res;
  }

  /* Critical code, no interruptions please */
  if (_indispatch) {
    return 0;
  }

  pr_alarms_block();
  _indispatch++;

  if (elapsed) {
    for (t = (struct timer *) timers->xas_list; t; t = next) {
      /* If this timer has already been handled, skip */
      next = t->next;

      if (t->remove) {
        /* Move the timer onto the free_timers chain, for later reuse. */
        xaset_remove(timers, (xasetmember_t *) t);
        xaset_insert(free_timers, (xasetmember_t *) t);

      } else if ((t->count -= elapsed) <= 0) {
        /* This timer's interval has elapsed, so trigger its callback. */

        pr_trace_msg(trace_channel, 4,
          "%ld %s for timer ID %d ('%s', for module '%s') elapsed, invoking "
          "callback (%p)", t->interval,
          t->interval != 1 ? "seconds" : "second", t->timerno,
          t->desc ? t->desc : "<unknown>",
          t->mod ? t->mod->name : "<none>", t->callback);

        if (t->callback(t->interval, t->timerno, t->interval - t->count,
            t->mod) == 0) {

          /* A return value of zero means this timer is done, and can be
           * removed.
           */
          xaset_remove(timers, (xasetmember_t *) t);
          xaset_insert(free_timers, (xasetmember_t *) t);

        } else {
          /* A non-zero return value from a timer callback signals that
           * the timer should be reused/restarted.
           */
          pr_trace_msg(trace_channel, 6,
            "restarting timer ID %d ('%s'), as per callback", t->timerno,
            t->desc ? t->desc : "<unknown>");

          xaset_remove(timers, (xasetmember_t *) t);
          t->count = t->interval;
          xaset_insert(recycled, (xasetmember_t *) t);
        }
      }
    }
  }

  /* Put the recycled timers back into the main timer list. */
  t = (struct timer *) recycled->xas_list;
  while (t != NULL) {
    xaset_remove(recycled, (xasetmember_t *) t);
    xaset_insert_sort(timers, (xasetmember_t *) t, TRUE);
    t = (struct timer *) recycled->xas_list;
  }

  _indispatch--;
  pr_alarms_unblock();

  /* If no active timers remain in the list, there is no reason to set the
   * SIGALRM handle.
   */

  if (timers->xas_list != NULL) {
    /* The value we return is a proposed timeout, for the next call to
     * alarm(3).  We start with the simple count of timers in our list.
     *
     * But then we reduce the number; some of the timers' intervals may
     * less than the number of total timers.
     */
    res = ((struct timer *) timers->xas_list)->count;
    if (res > 5) {
      res = 5;
    }
  }

  return res;
}

static RETSIGTYPE sig_alarm(int signo) {
  struct sigaction act;

  act.sa_handler = sig_alarm;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;

#ifdef SA_INTERRUPT
  act.sa_flags |= SA_INTERRUPT;
#endif

  /* Install this handler for SIGALRM. */
  if (sigaction(SIGALRM, &act, NULL) < 0) {
    pr_log_pri(PR_LOG_WARNING,
      "unable to install SIGALRM handler via sigaction(2): %s",
      strerror(errno));
  }

#ifdef HAVE_SIGINTERRUPT
  if (siginterrupt(SIGALRM, 1) < 0) {
    pr_log_pri(PR_LOG_WARNING,
      "unable to allow SIGALRM to interrupt system calls: %s", strerror(errno));
  }
#endif

  recvd_signal_flags |= RECEIVED_SIG_ALRM;
  nalarms++;

  /* Reset the alarm */
  _total_time += _current_timeout;
  if (_current_timeout) {
    _alarmed_time = time(NULL);
    alarm(_current_timeout);
  }
}

static void set_sig_alarm(void) {
  struct sigaction act;

  act.sa_handler = sig_alarm;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
#ifdef SA_INTERRUPT
  act.sa_flags |= SA_INTERRUPT;
#endif

  /* Install this handler for SIGALRM. */
  if (sigaction(SIGALRM, &act, NULL) < 0) {
    pr_log_pri(PR_LOG_WARNING,
      "unable to install SIGALRM handler via sigaction(2): %s",
      strerror(errno));
  }

#ifdef HAVE_SIGINTERRUPT
  if (siginterrupt(SIGALRM, 1) < 0) {
    pr_log_pri(PR_LOG_WARNING,
      "unable to allow SIGALRM to interrupt system calls: %s", strerror(errno));
  }
#endif
}

void handle_alarm(void) {
  int new_timeout = 0;

  /* We need to adjust for any time that might be remaining on the alarm,
   * in case we were called in order to change alarm durations.  Note
   * that rapid-fire calling of this function will probably screw
   * up the already poor resolution of alarm() _horribly_.  Oh well,
   * this shouldn't be used for any precise work anyway, it's only
   * for modules to perform approximate timing.
   */

  /* It's possible that alarms are blocked when this function is
   * called, if so, increment alarm_pending and exit swiftly.
   */
  while (nalarms) {
    nalarms = 0;

    if (!alarms_blocked) {
      int alarm_elapsed;
      time_t now;

      /* Clear any pending ALRM signals. */
      alarm(0);

      /* Determine how much time has elapsed since we last processed timers. */
      time(&now);
      alarm_elapsed = _alarmed_time > 0 ? (int) (now - _alarmed_time) : 0;

      new_timeout = _total_time + alarm_elapsed;
      _total_time = 0;
      new_timeout = process_timers(new_timeout);

      _alarmed_time = now;
      alarm(_current_timeout = new_timeout);

    } else {
      alarm_pending++;
    }
  }
}

int pr_timer_reset(int timerno, module *mod) {
  struct timer *t = NULL;

  if (timers == NULL) {
    errno = EPERM;
    return -1;
  }

  if (_indispatch) {
    errno = EINTR;
    return -1;
  }

  pr_alarms_block();

  if (recycled == NULL) {
    recycled = xaset_create(timer_pool, NULL);
  }

  for (t = (struct timer *) timers->xas_list; t; t = t->next) {
    if (t->timerno == timerno &&
        (t->mod == mod || mod == ANY_MODULE)) {
      t->count = t->interval;
      xaset_remove(timers, (xasetmember_t *) t);
      xaset_insert(recycled, (xasetmember_t *) t);
      nalarms++;

      /* The handle_alarm() function also readjusts the timers lists
       * as part of its processing, so it needs to be called when a timer
       * is reset.
       */
      handle_alarm();
      break;
    }
  }

  pr_alarms_unblock();

  if (t != NULL) {
    pr_trace_msg(trace_channel, 7, "reset timer ID %d ('%s', for module '%s')",
      t->timerno, t->desc, t->mod ? t->mod->name : "[none]");
    return t->timerno;
  }

  return 0;
}

int pr_timer_remove(int timerno, module *mod) {
  struct timer *t = NULL, *tnext = NULL;
  int nremoved = 0;

  /* If there are no timers currently registered, do nothing. */
  if (!timers)
    return 0;

  pr_alarms_block();

  for (t = (struct timer *) timers->xas_list; t; t = tnext) {
    tnext = t->next;

    if ((timerno < 0 || t->timerno == timerno) &&
        (mod == ANY_MODULE || t->mod == mod)) {
      nremoved++;

      if (_indispatch) {
        t->remove++;

      } else {
        xaset_remove(timers, (xasetmember_t *) t);
        xaset_insert(free_timers, (xasetmember_t *) t);
	nalarms++;

        /* The handle_alarm() function also readjusts the timers lists
         * as part of its processing, so it needs to be called when a timer
         * is removed.
         */
        handle_alarm();
      }

      pr_trace_msg(trace_channel, 7,
        "removed timer ID %d ('%s', for module '%s')", t->timerno, t->desc,
        t->mod ? t->mod->name : "[none]");
    }

    /* If we are removing a specific timer, break out of the loop now.
     * Otherwise, keep removing any matching timers.
     */
    if (nremoved > 0 &&
        timerno >= 0) {
      break;
    }
  }

  pr_alarms_unblock();

  if (nremoved == 0) {
    errno = ENOENT;
    return -1;
  }

  /* If we removed a specific timer because of the given timerno, return
   * that timerno value.
   */
  if (timerno >= 0) {
    return timerno;
  }

  return nremoved;
}

int pr_timer_add(int seconds, int timerno, module *mod, callback_t cb,
    const char *desc) {
  struct timer *t = NULL;

  if (seconds <= 0 ||
      cb == NULL ||
      desc == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (!timers)
    timers = xaset_create(timer_pool, (XASET_COMPARE) timer_cmp);

  /* Check to see that, if specified, the timerno is not already in use. */
  if (timerno >= 0) {
    for (t = (struct timer *) timers->xas_list; t; t = t->next) {
      if (t->timerno == timerno) {
        errno = EPERM;
        return -1;
      }
    }
  }

  if (!free_timers)
    free_timers = xaset_create(timer_pool, NULL);

  /* Try to use an old timer first */
  pr_alarms_block();
  t = (struct timer *) free_timers->xas_list;
  if (t != NULL) {
    xaset_remove(free_timers, (xasetmember_t *) t);

  } else {
    if (timer_pool == NULL) {
      timer_pool = make_sub_pool(permanent_pool);
      pr_pool_tag(timer_pool, "Timer Pool");
    }

    /* Must allocate a new one */
    t = palloc(timer_pool, sizeof(struct timer));
  }

  if (timerno < 0) {
    /* Dynamic timer */
    if (dynamic_timerno < PR_TIMER_DYNAMIC_TIMERNO) {
      dynamic_timerno = PR_TIMER_DYNAMIC_TIMERNO;
    }

    timerno = dynamic_timerno++;
  }

  t->timerno = timerno;
  t->count = t->interval = seconds;
  t->callback = cb;
  t->mod = mod;
  t->remove = 0;
  t->desc = desc;

  /* If called while _indispatch, add to the recycled list to prevent
   * list corruption
   */

  if (_indispatch) {
    if (!recycled)
      recycled = xaset_create(timer_pool, NULL);
    xaset_insert(recycled, (xasetmember_t *) t);

  } else {
    xaset_insert_sort(timers, (xasetmember_t *) t, TRUE);
    nalarms++;
    set_sig_alarm();

    /* The handle_alarm() function also readjusts the timers lists
     * as part of its processing, so it needs to be called when a timer
     * is added.
     */
    handle_alarm();
  }

  pr_alarms_unblock();

  pr_trace_msg(trace_channel, 7, "added timer ID %d ('%s', for module '%s'), "
    "triggering in %ld %s", t->timerno, t->desc,
    t->mod ? t->mod->name : "[none]", t->interval,
    t->interval != 1 ? "seconds" : "second");
  return timerno;
}

/* Alarm blocking.  This is done manually rather than with syscalls,
 * so as to allow for easier signal handling, portability and
 * detecting the number of blocked alarms, as well as nesting the
 * block/unblock functions.
 */

void pr_alarms_block(void) {
  ++alarms_blocked;
}

void pr_alarms_unblock(void) {
  --alarms_blocked;
  if (alarms_blocked == 0 && alarm_pending) {
    alarm_pending = 0;
    nalarms++;
    handle_alarm();
  }
}

static int sleep_cb(CALLBACK_FRAME) {
  _sleep_sem++;
  return 0;
}

int pr_timer_sleep(int seconds) {
  int timerno = 0;
  sigset_t oset;

  _sleep_sem = 0;

  if (alarms_blocked || _indispatch) {
    errno = EPERM;
    return -1;
  }

  timerno = pr_timer_add(seconds, -1, NULL, sleep_cb, "sleep");
  if (timerno == -1)
    return -1;

  sigemptyset(&oset);
  while (!_sleep_sem) {
    sigsuspend(&oset);
    handle_alarm();
  }

  return 0;
}

int pr_timer_usleep(unsigned long usecs) {
  struct timeval tv;

  if (usecs == 0) {
    errno = EINVAL;
    return -1;
  }

  tv.tv_sec = (usecs / 1000000);
  tv.tv_usec = (usecs - (tv.tv_sec * 1000000));

  pr_signals_block();
  (void) select(0, NULL, NULL, NULL, &tv);
  pr_signals_unblock();

  return 0;
}

void timers_init(void) {

  /* Reset some of the key static variables. */
  _current_timeout = 0;
  _total_time = 0;
  nalarms = 0;
  _alarmed_time = 0;
  dynamic_timerno = PR_TIMER_DYNAMIC_TIMERNO;

  /* Don't inherit the parent's timer lists. */
  timers = NULL;
  recycled = NULL;
  free_timers = NULL;

  /* Reset the timer pool. */
  if (timer_pool) {
    destroy_pool(timer_pool);
  }

  timer_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(timer_pool, "Timer Pool");

  return;
}
