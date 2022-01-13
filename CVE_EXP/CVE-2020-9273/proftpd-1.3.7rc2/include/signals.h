/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2014 The ProFTPD Project team
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
 * As a special exemption, the ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Signal handling API. */

#ifndef PR_SIGNALS_H
#define PR_SIGNALS_H

#include "config.h"

void pr_signals_block(void);
void pr_signals_unblock(void);
void pr_signals_handle(void);

/* Signal handling functions. */
RETSIGTYPE pr_signals_handle_disconnect(int);
RETSIGTYPE pr_signals_handle_event(int);

/* Internal use only. */
int init_signals(void);

#endif /* PR_SIGNALS_H */
