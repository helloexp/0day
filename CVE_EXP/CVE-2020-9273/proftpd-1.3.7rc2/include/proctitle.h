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

/* Proctitle handling */

#ifndef PR_PROCTITLE_H
#define PR_PROCTITLE_H

/* For internal use only. */
void pr_proctitle_free(void);
void pr_proctitle_init(int, char *[], char *[]);

int pr_proctitle_get(char *, size_t);

void pr_proctitle_set(const char *, ...)
#ifdef __GNUC__
       __attribute__ ((format (printf, 1, 2)));
#else
       ;
#endif

void pr_proctitle_set_str(const char *);

/* If this function is used, all subsequent calls to pr_proctitle_set() and
 * pr_proctitle_set_str() will effectively be ignored.
 */
void pr_proctitle_set_static_str(const char *);

#endif /* PR_PROCTITLE_H */
