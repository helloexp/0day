/*
 * ProFTPD - mod_sftp disconnect msgs
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

#ifndef MOD_SFTP_DISCONNECT_H
#define MOD_SFTP_DISCONNECT_H

#include "mod_sftp.h"

void sftp_disconnect_conn(uint32_t, const char *, const char *, int,
  const char *);
void sftp_disconnect_send(uint32_t, const char *, const char *, int,
  const char *);

/* Given a disconnect reason code from a client, return a string explaining
 * that code.
 */
const char *sftp_disconnect_get_str(uint32_t);

/* Deal with the fact that __FUNCTION__ is a gcc extension.  Sun's compilers
 * (e.g. SunStudio) like __func__.
 */

# if defined(__FUNCTION__)
#define SFTP_DISCONNECT_CONN(c, m) \
  sftp_disconnect_conn((c), (m), __FILE__, __LINE__, __FUNCTION__)

# elif defined(__func__)
#define SFTP_DISCONNECT_CONN(c, m) \
  sftp_disconnect_conn((c), (m), __FILE__, __LINE__, __func__)

# else
#define SFTP_DISCONNECT_CONN(c, m) \
  sftp_disconnect_conn((c), (m), __FILE__, __LINE__, "")

# endif

#endif /* MOD_SFTP_DISCONNECT_H */
