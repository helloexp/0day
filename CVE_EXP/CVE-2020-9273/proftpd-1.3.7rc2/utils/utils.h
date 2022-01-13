/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2015 The ProFTPD Project team
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

/* Utility scoreboard routines. */

#ifndef UTILS_UTILS_H
#define UTILS_UTILS_H

#include "config.h"
#include "version.h"
#include "options.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#else
#  include "../lib/getopt.h"
#endif /* !HAVE_GETOPT_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif

#ifdef HAVE_SYS_FILE_H
# include <sys/file.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#include "pool.h"
#include "ascii.h"
#include "default_paths.h"

#define	FALSE	0
#define TRUE	1

#ifndef INET_ADDRSTRLEN
# define INET_ADDRSTRLEN        16
#endif /* INET_ADDRSTRLEN */

#ifndef INET6_ADDRSTRLEN
# define INET6_ADDRSTRLEN       46
#endif /* INET6_ADDRSTRLEN */

/* UTIL_SCOREBOARD_VERSION is used for checking for scoreboard compatibility
 */
#define UTIL_SCOREBOARD_VERSION        0x01040003

/* Structure used as a header for scoreboard files.
 */
#define UTIL_SCOREBOARD_MAGIC			0xdeadbeef

typedef struct {

  /* Always 0xDEADBEEF */
  unsigned long sch_magic;

  /* Version of proftpd that created the scoreboard file */
  unsigned long sch_version;

  /* PID of the process to which this scoreboard belongs, or zero if inetd */
  pid_t sch_pid;

  /* Time when the daemon wrote this header */
  time_t sch_uptime;

} pr_scoreboard_header_t;

/* Structure used for writing scoreboard file entries.
 */

typedef struct {
  pid_t	sce_pid;
  uid_t sce_uid;
  gid_t sce_gid;
  char sce_user[32];

  int sce_server_port;
  char sce_server_addr[80], sce_server_label[32];

#ifdef PR_USE_IPV6
  char sce_client_addr[INET6_ADDRSTRLEN];
#else
  char sce_client_addr[INET_ADDRSTRLEN];
#endif /* PR_USE_IPV6 */
  char sce_client_name[PR_TUNABLE_SCOREBOARD_BUFFER_SIZE];

  char sce_class[32];
  char sce_protocol[32];
  char sce_cwd[PR_TUNABLE_SCOREBOARD_BUFFER_SIZE];

  char sce_cmd[65];
  char sce_cmd_arg[PR_TUNABLE_SCOREBOARD_BUFFER_SIZE];

  time_t sce_begin_idle, sce_begin_session;

  off_t sce_xfer_size, sce_xfer_done, sce_xfer_len;
  unsigned long sce_xfer_elapsed;

} pr_scoreboard_entry_t;

/* Scoreboard error values */
#define UTIL_SCORE_ERR_BAD_MAGIC	-2
#define UTIL_SCORE_ERR_OLDER_VERSION	-3
#define UTIL_SCORE_ERR_NEWER_VERSION	-4

char *util_sstrncpy(char *, const char *, size_t);

const char *util_get_scoreboard(void);
int util_set_scoreboard(const char *);

char *util_scan_config(const char *, const char *);

int util_close_scoreboard(void);
int util_open_scoreboard(int);
pid_t util_scoreboard_get_daemon_pid(void);
time_t util_scoreboard_get_daemon_uptime(void);
pr_scoreboard_entry_t *util_scoreboard_entry_read(void);
int util_scoreboard_scrub(int);

#endif /* UTILS_UTILS_H */
