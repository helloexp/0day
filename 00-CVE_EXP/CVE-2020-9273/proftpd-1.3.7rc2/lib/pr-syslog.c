/*
 * Copyright (c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "conf.h"

#if defined(SOLARIS2) || defined(IRIX6) || defined(SYSV5UNIXWARE7)
# define HAVE_DEV_LOG_STREAMS 1
#endif /* SOLARIS2 or IRIX6 or SYSV5UNIXWARE7 */

#ifdef HAVE_DEV_LOG_STREAMS
# include <sys/strlog.h>
#endif

static int sock_type = SOCK_DGRAM;
static int log_opts = 0;
static const char *log_ident = NULL;
static int log_facility = LOG_USER;
static int log_mask = 0xff;

#ifdef HAVE___PROGNAME
extern char *__progname;
#endif /* HAVE___PROGNAME */

#if defined(SOLARIS2_9) || defined(SOLARIS2_10)
/* These tables are used for populating the stupid Solaris 9/10 syslog
 * "header".
 */

struct {
  int facility;
  const char *name;

} syslog_facility_names[] = {
  { LOG_AUTHPRIV,	"auth" },
#ifdef HAVE_LOG_FTP
  { LOG_FTP,		"ftp" },
#endif
#ifdef HAVE_LOG_CRON
  { LOG_CRON,		"cron" },
#endif
  { LOG_DAEMON,		"daemon" },
  { LOG_KERN,		"kern" },
  { LOG_LOCAL0,		"local0" },
  { LOG_LOCAL1,		"local1" },
  { LOG_LOCAL2,		"local2" },
  { LOG_LOCAL3,		"local3" },
  { LOG_LOCAL4,		"local4" },
  { LOG_LOCAL5,		"local5" },
  { LOG_LOCAL6,		"local6" },
  { LOG_LOCAL7,		"local7" },
  { LOG_LPR,		"lpr" },
  { LOG_MAIL,		"mail" },
  { LOG_NEWS,		"news" },
  { LOG_USER,		"user" },
  { LOG_UUCP,		"uucp" },
  { 0,			NULL }
};

struct {
  int level;
  const char *name;

} syslog_level_names[] = {
  { PR_LOG_EMERG,	"emerg" },
  { PR_LOG_ALERT,	"alert" },
  { PR_LOG_CRIT,	"crit" },
  { PR_LOG_ERR,		"error" },
  { PR_LOG_ERR,		"error" },
  { PR_LOG_WARNING,	"warn" },
  { PR_LOG_NOTICE,	"notice" },
  { PR_LOG_INFO,	"info" },
  { PR_LOG_DEBUG,	"debug" },
  { 0,			NULL }
};

#endif /* Solaris 9 or 10 */

static void pr_vsyslog(int sockfd, int pri, register const char *fmt,
    va_list ap) {
  time_t now;
  static char logbuf[PR_TUNABLE_BUFFER_SIZE] = {'\0'};
  size_t buflen = 0;
  int len = 0, saved_errno = errno;

#ifdef HAVE_DEV_LOG_STREAMS
  struct strbuf ctl, dat;
  struct log_ctl lc;
#else
  char *timestr = NULL;

# ifdef HAVE_TZNAME
  char *saved_tzname[2];
# endif /* HAVE_TZNAME */
#endif

  /* Clear the buffer */
  memset(logbuf, '\0', sizeof(logbuf));

  /* Check for invalid bits. */
  if (pri & ~(LOG_PRIMASK|LOG_FACMASK)) {
    pri &= LOG_PRIMASK|LOG_FACMASK;
  }

  /* Check priority against setlogmask values. */
  if ((LOG_MASK(pri & LOG_PRIMASK) & log_mask) == 0) {
    return;
  }

  /* Set default facility if none specified. */
  if ((pri & LOG_FACMASK) == 0) {
    pri |= log_facility;
  }

#ifndef HAVE_DEV_LOG_STREAMS
  len = snprintf(logbuf, sizeof(logbuf), "<%d>", pri);
  logbuf[sizeof(logbuf)-1] = '\0';
  buflen += len;

# ifdef HAVE_TZNAME
  /* Preserve the old tzname setting. */
  memcpy(saved_tzname, tzname, sizeof(saved_tzname));
# endif /* HAVE_TZNAME */

  time(&now);
  timestr = ctime(&now);

# ifdef HAVE_TZNAME
  /* Restore the old tzname setting, to prevent ctime(3) from inadvertently
   * affecting things, as when we're in a chroot, and ctime(3) loses the
   * timezone info.
   */
  memcpy(tzname, saved_tzname, sizeof(saved_tzname));
# endif /* HAVE_TZNAME */

  /* Remove the trailing newline from the time string returned by ctime(3). */
  timestr[strlen(timestr)-1] = '\0';

  /* Skip past the leading "day of week" prefix. */
  timestr += 4;

  len = snprintf(&(logbuf[buflen]), sizeof(logbuf) - buflen, "%.15s ", timestr);
  logbuf[sizeof(logbuf)-1] = '\0';
  buflen += len;
#endif

  time(&now);

  if (log_ident == NULL) {
#ifdef HAVE___PROGNAME
    log_ident = __progname;
#else
    log_ident = "proftpd";
#endif /* HAVE___PROGNAME */
  }

  if (buflen < sizeof(logbuf) &&
      log_ident != NULL) {
    len = snprintf(&(logbuf[buflen]), sizeof(logbuf) - buflen, "%s", log_ident);
    logbuf[sizeof(logbuf)-1] = '\0';
    buflen += len;
  }

  if (buflen < sizeof(logbuf)-1 &&
      (log_opts & LOG_PID)) {
    len = snprintf(&(logbuf[buflen]), sizeof(logbuf) - buflen, "[%d]",
      (int) getpid());
    logbuf[sizeof(logbuf)-1] = '\0';
    buflen += len;
  }

  if (buflen < sizeof(logbuf)-1 &&
      log_ident != NULL) {
    len = snprintf(&(logbuf[buflen]), sizeof(logbuf) - buflen, ": ");
    logbuf[sizeof(logbuf)-1] = '\0';
    buflen += len;
  }

#if defined(SOLARIS2_9) || defined(SOLARIS2_10)
  /* Add in the (IMHO stupid and nonportable) syslog "header" that was added
   * to the Solaris 9/10 libc syslog(3) function.  Some sites apparently
   * think that trying to use this header to generate reports of logging
   * is a Good Idea; I'll have the last laugh when those sites try to move
   * to a different platform with different syslog logging.
   *
   * The header to be added looks like:
   *
   *  "[ID %lu %s.%s]"
   *
   * where the ID is generated using STRLOG_MAKE_MSGID(), a macro defined
   * in <sys/strlog.h>, and the following two strings are the syslog
   * facility and level, respectively.
   */

  if (buflen < sizeof(logbuf)) {
    register unsigned int i;
    uint32_t msgid;
    const char *facility_name = "unknown", *level_name = "unknown";

    STRLOG_MAKE_MSGID(fmt, msgid);

    for (i = 0; syslog_facility_names[i].name; i++) {
      if (syslog_facility_names[i].facility == log_facility) {
        facility_name = syslog_facility_names[i].name;
        break;
      }
    }

    for (i = 0; syslog_level_names[i].name; i++) {
      if (syslog_level_names[i].level == (pri & LOG_PRIMASK)) {
        level_name = syslog_level_names[i].name;
        break;
      }
    }

    len = snprintf(&(logbuf[buflen]), sizeof(logbuf) - buflen,
      "[ID %lu %s.%s] ", (unsigned long) msgid, facility_name, level_name);
    logbuf[sizeof(logbuf)-1] = '\0';
    buflen += len;
  }
#endif /* Solaris 9 or 10 */

  /* Restore errno for %m format.  */
  errno = saved_errno;

  /* We have the header.  Print the user's format into the buffer.  */
  if (buflen < sizeof(logbuf)) {
    len = vsnprintf(&(logbuf[buflen]), sizeof(logbuf) - buflen, fmt, ap);
    logbuf[sizeof(logbuf)-1] = '\0';
    buflen += len;
  }

  /* Always make sure the buffer is NUL-terminated
   */
  logbuf[sizeof(logbuf)-1] = '\0';

  /* If we have a SOCK_STREAM connection, also send ASCII NUL as a record
   * terminator.
   */
  if (sock_type == SOCK_STREAM) {
    ++buflen;
  }

  /* If we have exceeded the capacity of the buffer, we're done here. */
  if (buflen >= sizeof(logbuf)) {
    return;
  }

#ifndef HAVE_DEV_LOG_STREAMS
  if (sockfd >= 0 &&
      send(sockfd, logbuf, buflen, 0) < 0) {
    fprintf(stderr, "error sending log message '%s' to socket fd %d: %s\n",
      logbuf, sockfd, strerror(errno));
  }
#else

  /* Prepare the structs for use by putmsg(). As /dev/log (or /dev/conslog)
   * is a STREAMS device on Solaris (and possibly other platforms?), putmsg() is
   * used so that syslog facility and level are properly honored; write()
   * does not seem to work as desired.
   */
  ctl.len = ctl.maxlen = sizeof(lc);
  ctl.buf = (char *) &lc;
  dat.len = dat.maxlen = buflen;
  dat.buf = logbuf;
  lc.level = 0;
  lc.flags = SL_CONSOLE;
  lc.pri = pri;

  putmsg(sockfd, &ctl, &dat, 0);
#endif
}

void pr_syslog(int sockfd, int pri, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  pr_vsyslog(sockfd, pri, fmt, ap);
  va_end(ap);
}

#ifndef HAVE_DEV_LOG_STREAMS
/* AF_UNIX address of local logger */
static struct sockaddr_un syslog_addr;
#endif

int pr_openlog(const char *ident, int opts, int facility) {
  int sockfd;

  if (ident != NULL)
    log_ident = ident;

  log_opts = opts;

  if (facility != 0 && (facility &~ LOG_FACMASK) == 0)
    log_facility = facility;

#ifndef HAVE_DEV_LOG_STREAMS
  sockfd = -1;
  while (1) {
    socklen_t addrlen = 0;

    if (sockfd == -1) {
      syslog_addr.sun_family = AF_UNIX;

      sstrncpy(syslog_addr.sun_path, PR_PATH_LOG, sizeof(syslog_addr.sun_path));
      syslog_addr.sun_path[sizeof(syslog_addr.sun_path)-1] = '\0';
      addrlen = sizeof(syslog_addr);

      if (log_opts & LOG_NDELAY) {
        sockfd = socket(AF_UNIX, sock_type, 0);
        if (sockfd < 0) {
          return -1;
        }

        (void) fcntl(sockfd, F_SETFD, 1);
      }
    }

    if (sockfd != -1) {
      int old_errno = errno;

      if (connect(sockfd, (struct sockaddr *) &syslog_addr, addrlen) == -1) {
        int saved_errno = errno;
        close(sockfd);
        sockfd = -1;

        if (sock_type == SOCK_DGRAM && saved_errno == EPROTOTYPE) {
          /* retry with next SOCK_STREAM */
          sock_type = SOCK_STREAM;
          errno = old_errno;
          continue;
        }
      }
    }
    break;
  }
#else
  sockfd = open(PR_PATH_LOG, O_WRONLY);

  if (sockfd < 0) {
    fprintf(stderr, "error opening '%s': %s\n", PR_PATH_LOG, strerror(errno));
  }
#endif

  return sockfd;
}

void pr_closelog(int sockfd) {
  close(sockfd);
  sockfd = -1;

  /* Clear the identity prefix string. */
  log_ident = NULL;

  /* default */
  sock_type = SOCK_DGRAM;
}

/* setlogmask -- set the log mask level */
int pr_setlogmask(int new_mask) {
  int old_mask;

  old_mask = log_mask;
  if (new_mask != 0)
    log_mask = new_mask;

  return old_mask;
}

int pr_setlogfacility(int new_facility) {
  int old_facility;

  old_facility = log_facility;
  if (new_facility > 0)
    log_facility = new_facility;

  return old_facility;
}
