/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2003-2017 The ProFTPD Project team
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

/* ProFTPD xferlog(5) logging support. */

#include "conf.h"

#define LOGBUFFER_SIZE	2048

static int xferlogfd = -1;

void xferlog_close(void) {
  if (xferlogfd != -1)
    close(xferlogfd);

  xferlogfd = -1;
}

int xferlog_open(const char *path) {

  if (path == NULL) {
    if (xferlogfd != -1) {
      xferlog_close();
    }

    return 0;
  }

  if (xferlogfd < 0) {
    pr_log_debug(DEBUG6, "opening TransferLog '%s'", path);
    pr_log_openfile(path, &xferlogfd, PR_TUNABLE_XFER_LOG_MODE);

    if (xferlogfd < 0) {
      int xerrno = errno;

      pr_log_pri(PR_LOG_NOTICE, "unable to open TransferLog '%s': %s",
        path, strerror(xerrno));

      errno = xerrno;
    }
  }

  return xferlogfd;
}

int xferlog_write(long xfertime, const char *remhost, off_t fsize,
    const char *fname, char xfertype, char direction, char access_mode,
    const char *user, char abort_flag, const char *action_flags) {
  const char *rfc1413_ident = NULL, *xfer_proto;
  char buf[LOGBUFFER_SIZE] = {'\0'}, fbuf[LOGBUFFER_SIZE] = {'\0'};
  int have_ident = FALSE, len;
  register unsigned int i = 0;

  if (xferlogfd == -1 ||
      remhost == NULL ||
      user == NULL ||
      fname == NULL) {
    return 0;
  }

  for (i = 0; (i + 1 < sizeof(fbuf)) && fname[i] != '\0'; i++) {
    fbuf[i] = (PR_ISSPACE(fname[i]) || PR_ISCNTRL(fname[i])) ? '_' :
      fname[i];
  }
  fbuf[i] = '\0';

  rfc1413_ident = pr_table_get(session.notes, "mod_ident.rfc1413-ident", NULL);
  if (rfc1413_ident != NULL) {
    have_ident = TRUE;

    /* If the retrieved identity is "UNKNOWN", then change the string to be
     * "*", since "*" is to be logged in the xferlog, as per the doc, when
     * the authenticated user ID is not available.
     */
    if (strncmp(rfc1413_ident, "UNKNOWN", 8) == 0) {
      rfc1413_ident = "*";
    }

  } else {
    /* If an authenticated user ID is not available, log "*", as per the
     * xferlog man page/spec.
     */
    rfc1413_ident = "*";
  }

  xfer_proto = pr_session_get_protocol(0);

  len = pr_snprintf(buf, sizeof(buf),
    "%s %ld %s %" PR_LU " %s %c %s %c %c %s %s %c %s %c\n",
      pr_strtime(time(NULL)),
      xfertime,
      remhost,
      (pr_off_t) fsize,
      fbuf,
      xfertype,
      action_flags,
      direction,
      access_mode,
      user,
      xfer_proto,
      have_ident ? '1' : '0',
      rfc1413_ident,
      abort_flag);

  buf[sizeof(buf)-1] = '\0';

  pr_log_event_generate(PR_LOG_TYPE_XFERLOG, xferlogfd, -1, buf, len);
  return write(xferlogfd, buf, len);
}
