/*
 * ProFTPD - mod_sftp key exchange (kex)
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

#ifndef MOD_SFTP_KEX_H
#define MOD_SFTP_KEX_H

#include "mod_sftp.h"

int sftp_kex_handle(struct ssh2_packet *);
int sftp_kex_init(const char *, const char *);
int sftp_kex_free(void);

int sftp_kex_rekey(void);
int sftp_kex_rekey_set_interval(int);
int sftp_kex_rekey_set_timeout(int);

int sftp_kex_send_first_kexinit(void);

#define SFTP_KEX_DH_GROUP_MIN	1024
#define SFTP_KEX_DH_GROUP_MAX	8192

#endif /* MOD_SFTP_KEX_H */
