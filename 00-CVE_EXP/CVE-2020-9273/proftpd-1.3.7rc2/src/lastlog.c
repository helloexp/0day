/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2006-2017 The ProFTPD Project team
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

/* Lastlog code */

#include "conf.h"

#ifdef PR_USE_LASTLOG

int log_lastlog(uid_t uid, const char *user_name, const char *tty,
    const pr_netaddr_t *remote_addr) {
  struct lastlog ll;
  struct stat st;
  int fd, res;
  char path[PR_TUNABLE_PATH_MAX] = {'\0'};

  memset(&ll, 0, sizeof(ll));
  sstrncpy(ll.ll_line, tty, sizeof(ll.ll_line));
  sstrncpy(ll.ll_host, pr_netaddr_get_ipstr(remote_addr),
    sizeof(ll.ll_host));
  time((time_t *) &ll.ll_time);

  /* Determine whether lastlog is a file or a directory, and act
   * appropriately.
   */
  if (stat(PR_LASTLOG_PATH, &st) < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_NOTICE, "unable to stat '%s': %s",
      PR_LASTLOG_PATH, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (S_ISDIR(st.st_mode)) {
    memset(path, '\0', sizeof(path));
    pr_snprintf(path, sizeof(path), "%s/%s", PR_LASTLOG_PATH, user_name);
    path[sizeof(path)-1] = '\0';

    fd = open(path, O_RDWR|O_CREAT, 0600);
    if (fd < 0) {
      int xerrno = errno;

      pr_log_pri(PR_LOG_NOTICE, "unable to open '%s': %s", path,
        strerror(xerrno));

      errno = xerrno;
      return -1;
    }

  } else if (S_ISREG(st.st_mode)) {
    off_t offset;

    sstrncpy(path, PR_LASTLOG_PATH, sizeof(path));

    fd = open(path, O_RDWR|O_CREAT, 0600);
    if (fd < 0) {
      int xerrno = errno;

      pr_log_pri(PR_LOG_NOTICE, "unable to open '%s': %s", path,
        strerror(xerrno));

      errno = xerrno;
      return -1;
    }

    /* Seek to the offset in the lastlog file for this UID. */
    offset = (off_t) ((long) uid * sizeof(ll));

    if (lseek(fd, offset, SEEK_SET) != offset) {
      int xerrno = errno;

      pr_log_pri(PR_LOG_NOTICE, "unable to seek to correct lastlog location "
        "in '%s': %s", path, strerror(xerrno));
      (void) close(fd);

      errno = xerrno;
      return -1;
    }

  } else {
    pr_log_pri(PR_LOG_NOTICE, "%s is not a file or directory",
      PR_LASTLOG_PATH);
    errno = EINVAL;
    return -1;
  }

  res = write(fd, &ll, sizeof(ll));
  if (res != sizeof(ll)) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "error updating lastlog: %s",
      strerror(xerrno));
    (void) close(fd);

    errno = xerrno;
    return -1;
  }

  (void) close(fd);
  return 0;
}

#endif /* PR_USE_LASTLOG */
