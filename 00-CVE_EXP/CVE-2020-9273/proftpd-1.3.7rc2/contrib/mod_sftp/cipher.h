/*
 * ProFTPD - mod_sftp cipher mgmt
 * Copyright (c) 2008-2017 TJ Saunders
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

#ifndef MOD_SFTP_CIPHER_H
#define MOD_SFTP_CIPHER_H

#include "mod_sftp.h"

int sftp_cipher_init(void);
int sftp_cipher_free(void);

/* Returns the cipher block size, or 8, whichever is larger. This value is
 * used when reading in the first bytes of a packet in order to determine
 * the packet length.  See RFC4253, Section 6, "Binary Packet Protocol".
 */
size_t sftp_cipher_get_block_size(void);
void sftp_cipher_set_block_size(size_t);

const char *sftp_cipher_get_read_algo(void);
int sftp_cipher_set_read_algo(const char *);
int sftp_cipher_set_read_key(pool *, const EVP_MD *, const BIGNUM *,
  const char *, uint32_t, int);
int sftp_cipher_read_data(pool *, unsigned char *, uint32_t,
  unsigned char **, uint32_t *);

const char *sftp_cipher_get_write_algo(void);
int sftp_cipher_set_write_algo(const char *);
int sftp_cipher_set_write_key(pool *, const EVP_MD *, const BIGNUM *,
  const char *, uint32_t, int);
int sftp_cipher_write_data(struct ssh2_packet *, unsigned char *, size_t *);

#endif /* MOD_SFTP_CIPHER_H */
