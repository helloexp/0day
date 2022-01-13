/*
 * ProFTPD - mod_auth_otp misc crypto routines
 * Copyright (c) 2015-2016 TJ Saunders
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

#ifndef MOD_AUTH_OTP_CRYPTO_H
#define MOD_AUTH_OTP_CRYPTO_H

#include "mod_auth_otp.h"

int auth_otp_crypto_init(void);
void auth_otp_crypto_free(int);

const char *auth_otp_crypto_get_errors(void);

int auth_otp_hmac(const EVP_MD *md, const unsigned char *key, size_t key_len,
  const unsigned char *data, size_t data_len, unsigned char *mac,
  size_t *mac_len);

#endif /* MOD_AUTH_OTP_CRYPTO_H */
