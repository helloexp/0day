/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2007-2016 The ProFTPD Project team
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

/* Pidfile management */

#include "conf.h"
#include "privs.h"

static const char *pidfile_path = PR_PID_FILE_PATH;

const char *pr_pidfile_get(void) {
  return pidfile_path;
}

int pr_pidfile_set(const char *path) {
  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Do not allow relative paths. */
  if (*path != '/') {
    errno = EINVAL;
    return -1;
  }

  pidfile_path = pstrdup(permanent_pool, path);
  return 0;
}

int pr_pidfile_write(void) {
  int xerrno;
  FILE *fh = NULL;

  PRIVS_ROOT
  fh = fopen(pidfile_path, "w");
  xerrno = errno;
  PRIVS_RELINQUISH

  if (fh == NULL) {
    errno = xerrno;
    return -1;
  }

  fprintf(fh, "%lu\n", (unsigned long) getpid());
  if (fclose(fh) < 0) {
    fprintf(stderr, "error writing PidFile '%s': %s\n", pidfile_path,
      strerror(errno));
  }

  return 0;
}

int pr_pidfile_remove(void) {
  return unlink(pidfile_path);
}
