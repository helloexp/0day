/*
 * ProFTPD - FTP server daemon
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Event management code */

#include "conf.h"

/* Note: as more events are added, and as this API grows more and more used
 * by the core code, look into using a different ADT for storage/retrieval
 * of these objects, such as hash tables.
 */

struct event_handler {
  struct event_handler *next, *prev;
  module *module;
  void (*cb)(const void *, void *);
  void *user_data;
  unsigned long flags;
};

struct event_list {
  struct event_list *next;
  pool *pool;
  const char *event;
  size_t event_len;
  struct event_handler *handlers;
};

static pool *event_pool = NULL;
static struct event_list *events = NULL;

static const char *curr_event = NULL;
static struct event_list *curr_evl = NULL;
static struct event_handler *curr_evh = NULL;

/* Certain events are NOT logged via Trace logging (in order to prevent
 * event/trace loops).
 */
static const char *untraced_events[] = {
  PR_LOG_NAME_UNSPEC,
  PR_LOG_NAME_XFERLOG,
  PR_LOG_NAME_SYSLOG,
  PR_LOG_NAME_SYSTEMLOG,
  PR_LOG_NAME_EXTLOG,
  PR_LOG_NAME_TRACELOG,
  NULL
};

#define PR_EVENT_FL_UNTRACED		0x001

static const char *trace_channel = "event";

#define EVENT_POOL_SZ	256

int pr_event_register(module *m, const char *event,
    void (*cb)(const void *, void *), void *user_data) {
  register unsigned int i;
  struct event_handler *evh;
  struct event_list *evl;
  pool *evl_pool;
  unsigned long flags = 0;

  if (event == NULL ||
      cb == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (event_pool == NULL) {
    event_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(event_pool, "Event Pool");
  }

  pr_trace_msg(trace_channel, 3,
    "module '%s' (%p) registering handler for event '%s' (at %p)",
    m ? m->name : "(none)", m, event, cb);

  evh = pcalloc(event_pool, sizeof(struct event_handler));

  evh->module = m;
  evh->cb = cb;
  evh->user_data = user_data;

  /* Is this an untraced event? */
  for (i = 0; untraced_events[i] != NULL; i++) {
    if (strcmp(event, untraced_events[i]) == 0) {
      flags = PR_EVENT_FL_UNTRACED;
      break;
    }
  }

  evh->flags = flags;

  /* Scan the currently registered lists, looking for where to add this
   * registration.
   */

  for (evl = events; evl; evl = evl->next) {
    if (strncmp(evl->event, event, evl->event_len + 1) == 0) {
      struct event_handler *evhi, *evhl = NULL;

      evhi = evl->handlers;
      if (evhi) {
        /* Make sure this event handler is added to the START of the list,
         * in order to preserve module load order handling of events (i.e.
         * last module loaded, first module handled).  The exception to this
         * rule are core callbacks (i.e. where m == NULL); these will always
         * be invoked last.
         *
         * Before that, though, check for duplicate registration/subscription.
         */ 
        while (evhi) {
          pr_signals_handle();

          if (evhi->cb == evh->cb) {
            /* Duplicate callback */
            errno = EEXIST;
            return -1;
          }

          evhl = evhi;

          if (evhi->next == NULL) {
            break;
          }

          evhi = evhi->next;
        }

        if (evh->module != NULL) {
          if (evl->handlers->next != NULL) {
            evl->handlers->next->prev = evh;
          }

          evh->next = evl->handlers;
          evl->handlers = evh;

        } else {
          /* Core event listeners go at the end. */
          evhl->next = evh;
          evh->prev = evhl;
        }

      } else {
        evl->handlers = evh;
      }

      /* All done */
      return 0;
    }
  }

  evl_pool = pr_pool_create_sz(event_pool, EVENT_POOL_SZ);
  pr_pool_tag(evl_pool, "Event listener list pool");

  evl = pcalloc(evl_pool, sizeof(struct event_list));
  evl->pool = evl_pool;
  evl->event = pstrdup(evl->pool, event);
  evl->event_len = strlen(evl->event);
  evl->handlers = evh; 
  evl->next = events;

  events = evl;

  /* Clear any cached data. */
  curr_event = NULL;
  curr_evl = NULL;
  curr_evh = NULL;

  return 0;
}

int pr_event_unregister(module *m, const char *event,
    void (*cb)(const void *, void *)) {
  struct event_list *evl;
  int unregistered = FALSE;

  if (!events)
    return 0;

  pr_trace_msg(trace_channel, 3,
    "module '%s' (%p) unregistering handler for event '%s'",
    m ? m->name : "(none)", m, event ? event : "(all)");

  /* For now, simply remove the event_handler entry for this callback.  In
   * the future, add a static counter, and churn the event pool after a
   * certain number of unregistrations, so that the memory pool doesn't
   * grow unnecessarily.
   */

  for (evl = events; evl; evl = evl->next) {
    pr_signals_handle();

    if (event == NULL ||
        strncmp(evl->event, event, evl->event_len + 1) == 0) {
      struct event_handler *evh;

      /* If there are no handlers for this event, there is nothing to
       * unregister.  Skip on to the next list.
       */
      if (!evl->handlers) {
        continue;
      }

      for (evh = evl->handlers; evh;) {

        if ((m == NULL || evh->module == m) &&
            (cb == NULL || evh->cb == cb)) { 
          struct event_handler *tmp = evh->next;

          if (evh->next) {
            evh->next->prev = evh->prev;
          }

          if (evh->prev) {
            evh->prev->next = evh->next;

          } else {
            /* This is the head of the list. */
            evl->handlers = evh->next;
          }

          evh->module = NULL;
          evh = tmp;
          unregistered = TRUE;
  
        } else {
          evh = evh->next;
        }
      }
    }
  }

  /* Clear any cached data. */
  curr_event = NULL;
  curr_evl = NULL;
  curr_evh = NULL;

  if (!unregistered) {
    errno = ENOENT;
    return -1;
  }

  return 0;
}

int pr_event_listening(const char *event) {
  struct event_list *evl;
  int count = 0;

  if (event == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (events == NULL) {
    /* No registered listeners at all. */
    return 0;
  }

  /* Lookup callbacks for this event. */
  for (evl = events; evl; evl = evl->next) {

    if (strncmp(evl->event, event, evl->event_len + 1) == 0) {
      struct event_handler *evh;

      /* If there are no registered callbacks for this event, be done. */
      if (evl->handlers == NULL) {
        return 0;
      }
 
      for (evh = evl->handlers; evh; evh = evh->next) {
        count++;
      }

      break;
    }
  }

  return count; 
}

void pr_event_generate(const char *event, const void *event_data) {
  int use_cache = FALSE;
  struct event_list *evl;

  if (!event)
    return;

  /* If there are no registered callbacks, be done. */
  if (!events)
    return;

  /* If there is a cached event, see if the given event matches. */
  if (curr_event &&
      strcmp(curr_event, event) == 0) {
    use_cache = TRUE;
  }

  /* Lookup callbacks for this event. */
  for (evl = use_cache ? curr_evl : events; evl; evl = evl->next) {

    if (strncmp(evl->event, event, evl->event_len + 1) == 0) {  
      struct event_handler *evh;

      /* If there are no registered callbacks for this event, be done. */
      if (!evl->handlers) {
        pr_trace_msg(trace_channel, 8, "no event handlers registered for '%s'",
          event);
        return;
      }

      curr_event = event;
      curr_evl = evl;

      for (evh = use_cache ? curr_evh : evl->handlers; evh; evh = evh->next) {
        /* Make sure that if the same event is generated by the current
         * listener, the next time through we go to the next listener, rather
         * sending the same event against to the same listener (Bug#3619).
         */
        curr_evh = evh->next;

        if (!(evh->flags & PR_EVENT_FL_UNTRACED)) {
          if (evh->module) {
            pr_trace_msg(trace_channel, 8,
              "dispatching event '%s' to mod_%s (at %p, use cache = %s)", event,
              evh->module->name, evh->cb, use_cache ? "true" : "false");

          } else {
            pr_trace_msg(trace_channel, 8,
              "dispatching event '%s' to core (at %p, use cache = %s)", event,
              evh->cb, use_cache ? "true" : "false");
          }
        }

        evh->cb(event_data, evh->user_data);
      }

      break;
    }
  }

  /* Clear any cached data after publishing the event to all interested
   * listeners.
   */
  curr_event = NULL;
  curr_evl = NULL;
  curr_evh = NULL;

  return;
}

void pr_event_dump(void (*dumpf)(const char *, ...)) {
  struct event_list *evl;

  if (!dumpf) {
    return;
  }

  if (!events) {
    dumpf("%s", "No events registered");
    return;
  }

  for (evl = events; evl; evl = evl->next) {
    pr_signals_handle();

    if (evl->handlers == NULL) {
      dumpf("No handlers registered for '%s'", evl->event);

    } else { 
      struct event_handler *evh;

      dumpf("Registered for '%s':", evl->event);
      for (evh = evl->handlers; evh; evh = evh->next) {
        if (evh->module != NULL) {
          dumpf("  mod_%s.c", evh->module->name);

        } else {
          dumpf("  (core)");
        }
      }
    }
  }

  return;
}
