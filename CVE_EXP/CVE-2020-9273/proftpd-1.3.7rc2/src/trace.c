/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2006-2019 The ProFTPD Project team
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
 * As a special exemption, the ProFTPD Project and other respective copyright
 * holders give permission to link this program with OpenSSL, and distribute
 * the resulting executable, without including the source code for OpenSSL
 * in the source distribution.
 */

/* Trace functions. */

#include "conf.h"
#include "privs.h"

#ifdef PR_USE_TRACE

static int trace_logfd = -1;
static unsigned long trace_opts = PR_TRACE_OPT_DEFAULT;
static pool *trace_pool = NULL;
static pr_table_t *trace_tab = NULL;

struct trace_levels {
  int min_level;
  int max_level;
};

static const char *trace_channels[] = {
  "auth",
  "binding",
  "command",
  "config",
  "ctrls",
  "data",
  "delay",
  "dns",
  "dso",
  "encode",
  "event",
  "facl",
  "fsio",
  "ident",
  "inet",
  "lock",
  "log",
  "module",
  "netacl",
  "netio",
  "pam",
  "pool",
  "regexp",
  "response",
  "scoreboard",
  "signal",
  "site",
  "timer",
  "var",
  "xfer",
  NULL
};

static void trace_restart_ev(const void *event_data, void *user_data) {
  trace_opts = PR_TRACE_OPT_DEFAULT;

  close(trace_logfd);
  trace_logfd = -1;

  if (trace_pool) {
    destroy_pool(trace_pool);
    trace_pool = NULL;
    trace_tab = NULL;

    pr_event_unregister(NULL, "core.restart", trace_restart_ev);
  }

  return;
}

static int trace_write(const char *channel, int level, const char *msg,
    int discard) {
  char buf[PR_TUNABLE_BUFFER_SIZE * 2];
  size_t buflen, len;
  struct tm *tm;
  int use_conn_ips = FALSE;

  if (trace_logfd < 0) {
    return 0;
  }

  memset(buf, '\0', sizeof(buf));

  if (!(trace_opts & PR_TRACE_OPT_USE_TIMESTAMP_MILLIS)) {
    time_t now;

    now = time(NULL);
    tm = pr_localtime(NULL, &now);

    len = strftime(buf, sizeof(buf)-1, "%Y-%m-%d %H:%M:%S", tm);
    buflen = len;

  } else {
    struct timeval now;
    unsigned long millis;

    gettimeofday(&now, NULL);

    tm = pr_localtime(NULL, (const time_t *) &(now.tv_sec));

    len = strftime(buf, sizeof(buf)-1, "%Y-%m-%d %H:%M:%S", tm);
    buflen = len;

    /* Convert microsecs to millisecs. */
    millis = now.tv_usec / 1000;

    len = pr_snprintf(buf + buflen, sizeof(buf) - buflen, ",%03lu", millis);
    buflen += len;
  }

  if ((trace_opts & PR_TRACE_OPT_LOG_CONN_IPS) &&
      session.c != NULL) {
    /* We can only support the "+ConnIPs" TraceOption if there actually
     * is a client connected in this process.  We might be the daemon
     * process, in which there is no client.
     */
    use_conn_ips = TRUE;
  }

  if (use_conn_ips == FALSE) {
    len = pr_snprintf(buf + buflen, sizeof(buf) - buflen, " [%u] <%s:%d>: %s",
      (unsigned int) (session.pid ? session.pid : getpid()), channel, level,
      msg);
    buflen += len;

  } else {
    const char *client_ip, *server_ip;
    int server_port;

    client_ip = pr_netaddr_get_ipstr(session.c->remote_addr);
    server_ip = pr_netaddr_get_ipstr(session.c->local_addr);
    server_port = pr_netaddr_get_port(session.c->local_addr);

    len = pr_snprintf(buf + buflen, sizeof(buf) - buflen,
      " [%u] (client %s, server %s:%d) <%s:%d>: %s",
      (unsigned int) (session.pid ? session.pid : getpid()),
      client_ip != NULL ? client_ip : "none",
      server_ip != NULL ? server_ip : "none", server_port, channel, level, msg);
    buflen += len;
  }

  buf[sizeof(buf)-1] = '\0';

  if (buflen < (sizeof(buf) - 1)) {
    buf[buflen] = '\n';
    buflen++;

  } else {
    buf[sizeof(buf)-5] = '.';
    buf[sizeof(buf)-4] = '.';
    buf[sizeof(buf)-3] = '.';
    buf[sizeof(buf)-2] = '.';
    buflen = sizeof(buf)-1;
  }

  pr_log_event_generate(PR_LOG_TYPE_TRACELOG, trace_logfd, level, buf, buflen);

  if (discard) {
    /* This log message would not have been written to disk, so just discard
     * it.  The discard value is TRUE when there's a log listener for
     * TraceLog logging events, and the Trace log level configuration would
     * otherwise have filtered out this log message.
     */
    return 0;
  }

  return write(trace_logfd, buf, buflen);
}

pr_table_t *pr_trace_get_table(void) {
  if (trace_tab == NULL) {
    errno = ENOENT;
    return NULL;
  }

  return trace_tab;
}

static const struct trace_levels *trace_get_levels(const char *channel) {
  const void *value;

  if (channel == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (trace_tab == NULL ||
      trace_logfd < 0) {
    errno = EPERM;
    return NULL;
  }

  value = pr_table_get(trace_tab, channel, NULL);
  if (value == NULL) {
    errno = ENOENT;
    return NULL;
  }

  return value;
}

int pr_trace_get_level(const char *channel) {
  return pr_trace_get_max_level(channel);
}

int pr_trace_get_max_level(const char *channel) {
  const struct trace_levels *levels;

  levels = trace_get_levels(channel);
  if (levels == NULL) {
    return -1;
  }

  return levels->max_level;
}

int pr_trace_get_min_level(const char *channel) {
  const struct trace_levels *levels;

  levels = trace_get_levels(channel);
  if (levels == NULL) {
    return -1;
  }

  return levels->min_level;
}

int pr_trace_parse_levels(char *str, int *min_level, int *max_level) {
  int low = 1, high = -1;
  char *ptr = NULL, *tmp = NULL;

  if (str == NULL ||
      min_level == NULL ||
      max_level == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Watch for blank strings for levels (i.e. misconfigured/typo in config). */
  if (*str == '\0') {
    errno = EINVAL;
    return -1;
  }

  /* Check for a value range. */
  if (*str == '-') {
    errno = EINVAL;
    return -1;
  }

  ptr = strchr(str, '-');
  if (ptr == NULL) {
    /* Just a single value. */
    errno = 0;
    high = (int) strtol(str, &ptr, 10);
    if (errno == ERANGE) {
      errno = EINVAL;
      return -1;
    }

    if (ptr && *ptr) {
      errno = EINVAL;
      return -1;
    }

    if (high < 0) {
      errno = EINVAL;
      return -1;
    }

    /* A special case is where the single value is zero.  If this is the
     * case, we make sure that the min value is the same.
     */
    if (high != 0) {
      *min_level = 1;

    } else {
      *min_level = 0;
    }

    *max_level = high;
    return 0;
  }

  /* We have a range of values. */
  *ptr = '\0';

  low = (int) strtol(str, &tmp, 10);
  if (errno == ERANGE) {
    errno = EINVAL;
    return -1;
  }

  if (tmp && *tmp) {
    *ptr = '-';
    errno = EINVAL;
    return -1;
  }
  *ptr = '-';

  if (low < 0) {
    errno = EINVAL;
    return -1;
  }

  tmp = NULL;
  high = (int) strtol(ptr + 1, &tmp, 10);
  if (errno == ERANGE) {
    errno = EINVAL;
    return -1;
  }

  if (tmp && *tmp) {
    errno = EINVAL;
    return -1;
  }

  if (high < 0) {
    errno = EINVAL;
    return -1;
  }

  if (high < low) {
    errno = EINVAL;
    return -1;
  }

  *min_level = low;
  *max_level = high;
  return 0;
}

int pr_trace_set_file(const char *path) {
  int res, xerrno;

  if (path == NULL) {
    if (trace_logfd < 0) {
      errno = EINVAL;
      return -1;
    }

    (void) close(trace_logfd);
    trace_logfd = -1;
    return 0;
  }

  pr_signals_block();
  PRIVS_ROOT
  res = pr_log_openfile(path, &trace_logfd, 0660);
  xerrno = errno;
  PRIVS_RELINQUISH
  pr_signals_unblock();

  if (res < 0) {
    if (res == -1) {
      pr_log_debug(DEBUG1, "unable to open TraceLog '%s': %s", path,
        strerror(xerrno));
      errno = xerrno;

    } else if (res == PR_LOG_WRITABLE_DIR) {
      pr_log_debug(DEBUG1,
        "unable to open TraceLog '%s': parent directory is world-writable",
        path);
      errno = EPERM;

    } else if (res == PR_LOG_SYMLINK) {
      pr_log_debug(DEBUG1,
        "unable to open TraceLog '%s': cannot log to a symbolic link",
        path);
      errno = EPERM;
    }

    return res;
  }

  return 0;
}

int pr_trace_set_levels(const char *channel, int min_level, int max_level) {

  if (channel == NULL) {
    if (trace_tab == NULL) {
      errno = EINVAL;
      return -1;
    }

    return 0;
  }

  if (min_level > max_level) {
    errno = EINVAL;
    return -1;
  }

  if (trace_tab == NULL &&
      min_level < 0) {
    return 0;
  }

  if (trace_pool == NULL) {
    trace_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(trace_pool, "Trace API");

    trace_tab = pr_table_alloc(trace_pool, 0);

    /* Register a handler for churning the log pool during HUP. */
    pr_event_register(NULL, "core.restart", trace_restart_ev, NULL);
  }

  if (min_level >= 0) {
    struct trace_levels *levels;

    levels = pcalloc(trace_pool, sizeof(struct trace_levels));
    levels->min_level = min_level;
    levels->max_level = max_level;

    if (strcmp(channel, PR_TRACE_DEFAULT_CHANNEL) != 0) {
      int count = pr_table_exists(trace_tab, channel);

      if (count <= 0) {
        if (pr_table_add(trace_tab, pstrdup(trace_pool, channel), levels,
            sizeof(struct trace_levels)) < 0) {
          return -1;
        }

      } else {
        if (pr_table_set(trace_tab, pstrdup(trace_pool, channel), levels,
            sizeof(struct trace_levels)) < 0)
          return -1;
      }

    } else {
      register unsigned int i;

      for (i = 0; trace_channels[i]; i++) {
        (void) pr_trace_set_levels(trace_channels[i], min_level, max_level);
      }
    }

  } else {
    if (strcmp(channel, PR_TRACE_DEFAULT_CHANNEL) != 0) {
      (void) pr_table_remove(trace_tab, channel, NULL);

    } else {
      register unsigned int i;

      for (i = 0; trace_channels[i]; i++) {
        (void) pr_table_remove(trace_tab, trace_channels[i], NULL);
      }
    }
  }

  return 0;
}

int pr_trace_set_options(unsigned long opts) {
  trace_opts = opts;
  return 0;
}

int pr_trace_use_stderr(int use_stderr) {
  if (use_stderr) {
    int res;

    res = dup(STDERR_FILENO);
    if (res < 0) {
      return -1;
    }

    /* Avoid a file descriptor leak by closing any existing fd. */
    (void) close(trace_logfd);
    trace_logfd = res;

  } else {
    (void) close(trace_logfd);
    trace_logfd = -1;
  }

  return 0;
}

int pr_trace_msg(const char *channel, int level, const char *fmt, ...) {
  int res;
  va_list msg;

  if (channel == NULL ||
      fmt == NULL ||
      level <= 0) {
    errno = EINVAL;
    return -1;
  }

  /* If no one's listening... */
  if (trace_logfd < 0 &&
      pr_log_event_listening(PR_LOG_TYPE_TRACELOG) <= 0) {
    return 0;
  }

  va_start(msg, fmt);
  res = pr_trace_vmsg(channel, level, fmt, msg);
  va_end(msg);

  return res;
}

int pr_trace_vmsg(const char *channel, int level, const char *fmt,
    va_list msg) {
  char buf[PR_TUNABLE_BUFFER_SIZE * 2];
  size_t buflen;
  const struct trace_levels *levels;
  int discard = FALSE, listening;

  /* Writing a trace message at level zero is NOT helpful; this makes it
   * impossible to quell messages to that trace channel by setting the level
   * filter to zero.  That being the case, treat level of zero as an invalid
   * level.
   */

  if (channel == NULL ||
      fmt == NULL ||
      level <= 0) {
    errno = EINVAL;
    return -1;
  }

  if (trace_tab == NULL) {
    errno = EPERM;
    return -1;
  }

  /* If no one's listening... */
  if (trace_logfd < 0) {
    return 0;
  }

  listening = pr_log_event_listening(PR_LOG_TYPE_TRACELOG);

  levels = trace_get_levels(channel);
  if (levels == NULL) {
    discard = TRUE;

    if (listening <= 0) {
      return 0;
    }
  }

  if (discard == FALSE &&
      level < levels->min_level) {
    discard = TRUE;

    if (listening <= 0) {
      return 0;
    }
  }

  if (discard == FALSE &&
      level > levels->max_level) {
    discard = TRUE;

    if (listening <= 0) {
      return 0;
    }
  }

  buflen = pr_vsnprintf(buf, sizeof(buf)-1, fmt, msg);

  /* Always make sure the buffer is NUL-terminated. */
  buf[sizeof(buf)-1] = '\0';

  if (buflen < sizeof(buf)) {
    buf[buflen] = '\0';

  } else {
    /* Note that vsnprintf() returns the number of characters _that would have
     * been printed if buffer were unlimited_.  Be careful of this.
     */
    buflen = sizeof(buf)-1;
  }

  /* Trim trailing newlines. */
  while (buflen >= 1 &&
         buf[buflen-1] == '\n') {
    pr_signals_handle();
    buf[buflen-1] = '\0';
    buflen--;
  }

  return trace_write(channel, level, buf, discard);
}

#else

pr_table_t *pr_trace_get_table(void) {
  errno = ENOSYS;
  return NULL;
}

int pr_trace_get_level(const char *channel) {
  errno = ENOSYS;
  return -1;
}

int pr_trace_get_max_level(const char *channel) {
  errno = ENOSYS;
  return -1;
}

int pr_trace_get_min_level(const char *channel) {
  errno = ENOSYS;
  return -1;
}

int pr_trace_parse_levels(char *str, int *min_level, int *max_level) {
  errno = ENOSYS;
  return -1;
}

int pr_trace_set_file(const char *path) {
  errno = ENOSYS;
  return -1;
}

int pr_trace_set_levels(const char *channel, int min_level, int max_level) {
  errno = ENOSYS;
  return -1;
}

int pr_trace_set_options(unsigned long opts) {
  errno = ENOSYS;
  return -1;
}

int pr_trace_msg(const char *channel, int level, const char *fmt, ...) {
  errno = ENOSYS;
  return -1;
}

int pr_trace_vmsg(const char *channel, int level, const char *fmt,
    va_list vargs) {
  errno = ENOSYS;
  return -1;
}

#endif /* PR_USE_TRACE */
