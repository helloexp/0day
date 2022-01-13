/*
 * ProFTPD - mod_sftp SCP (Secure Copy Protocol)
 * Copyright (c) 2008-2016 TJ Saunders
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
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#ifndef MOD_SFTP_SCP_H
#define MOD_SFTP_SCP_H

#include "mod_sftp.h"

int sftp_scp_handle_packet(pool *, void *, uint32_t, unsigned char *, uint32_t);

int sftp_scp_open_session(uint32_t);
int sftp_scp_close_session(uint32_t);

/* Prepare for the SCP transfer, setting all the options and paths that will
 * be involved.
 */
int sftp_scp_set_params(pool *, uint32_t, array_header *);

#endif /* MOD_SFTP_SCP_H */
