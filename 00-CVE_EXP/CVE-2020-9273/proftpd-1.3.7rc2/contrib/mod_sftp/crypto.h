/*
 * ProFTPD - mod_sftp misc crypto routines
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

#ifndef MOD_SFTP_CRYPTO_H
#define MOD_SFTP_CRYPTO_H

#include "mod_sftp.h"

void sftp_crypto_free(int);
const EVP_CIPHER *sftp_crypto_get_cipher(const char *, size_t *, size_t *);
const EVP_MD *sftp_crypto_get_digest(const char *, uint32_t *);
int sftp_crypto_set_driver(const char *);
const char *sftp_crypto_get_kexinit_cipher_list(pool *);
const char *sftp_crypto_get_kexinit_digest_list(pool *);

size_t sftp_crypto_get_size(size_t, size_t);

#endif /* MOD_SFTP_CRYPTO_H */
