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

/* Data connection management prototypes */

#ifndef PR_DATA_H
#define PR_DATA_H

/* Toggles whether to actually perform ASCII translation during the data
 * transfer.
 */
int pr_data_ignore_ascii(int);

void pr_data_init(char *, int);
void pr_data_cleanup(void);
int pr_data_open(char *, char *, int, off_t);
void pr_data_close(int);
void pr_data_abort(int, int);
int pr_data_xfer(char *, size_t);
void pr_data_reset(void);
void pr_data_set_linger(long);

/* Clear the session.xfer.p pool, if present, and reset any associated
 * state.
 */
void pr_data_clear_xfer_pool(void);

int pr_data_get_timeout(int);
void pr_data_set_timeout(int, int);
#define PR_DATA_TIMEOUT_IDLE			0x001
#define PR_DATA_TIMEOUT_NO_TRANSFER		0x002
#define PR_DATA_TIMEOUT_STALLED			0x004

#ifdef HAVE_SENDFILE
typedef

# if defined(HAVE_AIX_SENDFILE) || defined(HAVE_HPUX_SENDFILE) || \
    defined(HAVE_LINUX_SENDFILE) || defined(HAVE_SOLARIS_SENDFILE)
ssize_t
# elif defined(HAVE_BSD_SENDFILE) || defined(HAVE_MACOSX_SENDFILE)
off_t
# else
#  error "You have an unknown sendfile implementation."
# endif

pr_sendfile_t;
#else
typedef ssize_t pr_sendfile_t;
#endif /* HAVE_SENDFILE */

pr_sendfile_t pr_data_sendfile(int retr_fd, off_t *offset, off_t count);

#endif /* PR_DATA_H */
