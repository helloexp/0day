/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2009-2016 The ProFTPD Project team
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

#include "conf.h"

/* This next function logs an entry to wtmp, it MUST be called as root BEFORE
 * a chroot occurs.  Note: This has some portability ifdefs in it.  They
 * should work, but I haven't been able to test them.
 */

int log_wtmp(const char *line, const char *name, const char *host,
    const pr_netaddr_t *ip) {
  struct stat buf;
  int res = 0;

#if ((defined(SVR4) || defined(__SVR4)) || \
    (defined(__NetBSD__) && defined(HAVE_UTMPX_H)) || \
    (defined(__FreeBSD_version) && __FreeBSD_version >= 900007 && defined(HAVE_UTMPX_H))) && \
    !(defined(LINUX) || defined(__hpux) || defined (_AIX))
  /* This "auxiliary" utmp doesn't exist under linux. */

#if (defined(__sparcv9) || defined(__sun)) && !defined(__NetBSD__) && !defined(__FreeBSD__)
  struct futmpx utx;
  time_t t;

#else
  struct utmpx utx;
#endif

  static int fdx = -1;

#if !defined(WTMPX_FILE)
# if defined(_PATH_WTMPX)
#   define WTMPX_FILE _PATH_WTMPX
# elif defined(_PATH_UTMPX)
#   define WTMPX_FILE _PATH_UTMPX
# else
/* This path works for FreeBSD; not sure what to do for other platforms which
 * don't define _PATH_WTMPX or _PATH_UTMPX.
 */
#   define WTMPX_FILE "/var/log/utx.log"
# endif
#endif

  if (fdx < 0 &&
      (fdx = open(WTMPX_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "failed to open wtmpx %s: %s", WTMPX_FILE,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  (void) pr_fs_get_usable_fd2(&fdx);

  /* Unfortunately, utmp string fields are terminated by '\0' if they are
   * shorter than the size of the field, but if they are exactly the size of
   * the field they don't have to be terminated at all.  Frankly, this sucks.
   * Insane if you ask me.  Unless there's massive uproar, I prefer to err on
   * the side of caution and always null-terminate our strings.
   */
  if (fstat(fdx, &buf) == 0) {
    memset(&utx, 0, sizeof(utx));

    sstrncpy(utx.ut_user, name, sizeof(utx.ut_user));
    sstrncpy(utx.ut_id, pr_session_get_protocol(PR_SESS_PROTO_FL_LOGOUT),
      sizeof(utx.ut_user));
    sstrncpy(utx.ut_line, line, sizeof(utx.ut_line));
    sstrncpy(utx.ut_host, host, sizeof(utx.ut_host));
    utx.ut_pid = session.pid ? session.pid : getpid();

#if defined(__NetBSD__) && defined(HAVE_UTMPX_H)
    memcpy(&utx.ut_ss, pr_netaddr_get_inaddr(ip), sizeof(utx.ut_ss));
    gettimeofday(&utx.ut_tv, NULL);

#elif defined(__FreeBSD_version) && __FreeBSD_version >= 900007 && defined(HAVE_UTMPX_H)
    gettimeofday(&utx.ut_tv, NULL);

#else /* SVR4 */
    utx.ut_syslen = strlen(utx.ut_host)+1;

#  if (defined(__sparcv9) || defined(__sun)) && !defined(__FreeBSD__)
    time(&t);
    utx.ut_tv.tv_sec = (time32_t)t;
#  else
    time(&utx.ut_tv.tv_sec);
#  endif

#endif /* SVR4 */

    if (*name)
      utx.ut_type = USER_PROCESS;
    else
      utx.ut_type = DEAD_PROCESS;

#ifdef HAVE_UT_UT_EXIT
    utx.ut_exit.e_termination = 0;
    utx.ut_exit.e_exit = 0;
#endif /* HAVE_UT_UT_EXIT */

    if (write(fdx, (char *) &utx, sizeof(utx)) != sizeof(utx)) {
      (void) ftruncate(fdx, buf.st_size);
    }

  } else {
    pr_log_debug(DEBUG0, "%s fstat(): %s", WTMPX_FILE, strerror(errno));
    res = -1;
  }

#else /* Non-SVR4 systems */
  struct utmp ut;
  static int fd = -1;

  if (fd < 0 &&
      (fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "failed to open wtmp %s: %s", WTMP_FILE,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  (void) pr_fs_get_usable_fd2(&fd);

  if (fstat(fd, &buf) == 0) {
    memset(&ut, 0, sizeof(ut));

#ifdef HAVE_UTMAXTYPE

# ifdef LINUX
    if (ip)
#  ifndef PR_USE_IPV6
      memcpy(&ut.ut_addr, pr_netaddr_get_inaddr(ip), sizeof(ut.ut_addr));
#  else
      memcpy(&ut.ut_addr_v6, pr_netaddr_get_inaddr(ip), sizeof(ut.ut_addr_v6));
#  endif /* !PR_USE_IPV6 */

# else
    sstrncpy(ut.ut_id, pr_session_get_protocol(PR_SESS_PROTO_FL_LOGOUT),
      sizeof(ut.ut_id));

#  ifdef HAVE_UT_UT_EXIT
    ut.ut_exit.e_termination = 0;
    ut.ut_exit.e_exit = 0;
#  endif /* !HAVE_UT_UT_EXIT */

# endif /* !LINUX */
    sstrncpy(ut.ut_line, line, sizeof(ut.ut_line));

    if (name && *name)
      sstrncpy(ut.ut_user, name, sizeof(ut.ut_user));

    ut.ut_pid = session.pid ? session.pid : getpid();

    if (name && *name)
      ut.ut_type = USER_PROCESS;
    else
      ut.ut_type = DEAD_PROCESS;

#else  /* !HAVE_UTMAXTYPE */
    sstrncpy(ut.ut_line, line, sizeof(ut.ut_line));

    if (name && *name) {
      sstrncpy(ut.ut_name, name, sizeof(ut.ut_name));
    }
#endif /* HAVE_UTMAXTYPE */

#ifdef HAVE_UT_UT_HOST
    if (host && *host) {
      sstrncpy(ut.ut_host, host, sizeof(ut.ut_host));
    }
#endif /* HAVE_UT_UT_HOST */

    ut.ut_time = time(NULL);

    if (write(fd, (char *) &ut, sizeof(ut)) != sizeof(ut)) {
      if (ftruncate(fd, buf.st_size) < 0) {
        pr_log_debug(DEBUG0, "error truncating '%s': %s", WTMP_FILE,
          strerror(errno));
      }
    }

  } else {
    pr_log_debug(DEBUG0, "%s fstat(): %s", WTMP_FILE, strerror(errno));
    res = -1;
  }
#endif /* SVR4 */

  return res;
}
