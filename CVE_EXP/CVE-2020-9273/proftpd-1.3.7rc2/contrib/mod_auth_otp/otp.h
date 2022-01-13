/*
 * ProFTPD - mod_auth_otp
 * Copyright (c) 2015 TJ Saunders
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

#ifndef MOD_AUTH_OTP_OTP_H
#define MOD_AUTH_OTP_OTP_H

#include "mod_auth_otp.h"

/* Following the recommendation of RFC 6238, Section 5.2 */
#define AUTH_OTP_TOTP_TIMESTEP_SECS		30

/* Generate an OTP using the algorithm specified in RFC 4226 (HOTP). */
int auth_otp_hotp(pool *p, const unsigned char *key, size_t key_len,
  unsigned long counter, unsigned int *code);

/* Generate an OTP using the algorithm specified in RFC 6238 (TOTP).
 *
 * Note that RFC 6238 defines support using SHA1, SHA256, or SHA512;
 * the algo argument here indicates which one to use.
 */
int auth_otp_totp(pool *p, const unsigned char *key, size_t key_len,
  unsigned long ts, unsigned int algo, unsigned int *code);

#endif /* MOD_AUTH_OTP_OTP_H */
