/*
 * ProFTPD - mod_sftp public key store (including RFC4716 public key file
 *                                      format)
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

#ifndef MOD_SFTP_KEYSTORE_H
#define MOD_SFTP_KEYSTORE_H

#include "mod_sftp.h"

int sftp_keystore_init(void);
int sftp_keystore_free(void);

int sftp_keystore_supports_store(const char *, unsigned int);
int sftp_keystore_verify_host_key(pool *, const char *, const char *,
  const char *, unsigned char *, uint32_t);
int sftp_keystore_verify_user_key(pool *, const char *, unsigned char *,
  uint32_t);

#endif /* MOD_SFTP_KEYSTORE_H */
