/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2004-2016 The ProFTPD Project team
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

/* Management of child objects */

#ifndef PR_CHILD_H
#define PR_CHILD_H

typedef struct child {
  struct child *next, *prev;

  pool *ch_pool;
  pid_t ch_pid;
  time_t ch_when;
  int ch_pipefd;

  unsigned char ch_dead;
} pr_child_t;

int child_add(pid_t, int);
unsigned long child_count(void);
pr_child_t *child_get(pr_child_t *);
int child_remove(pid_t);
void child_signal(int);
void child_update(void);

#endif /* PR_CHILD_H */
