/*
 * ProFTPD - mod_auth_otp API testsuite
 * Copyright (c) 2015 The ProFTPD Project team
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

/* Testsuite management
 */

#ifndef MOD_AUTH_OTP_TESTS_H
#define MOD_AUTH_OTP_TESTS_H

#include "mod_auth_otp.h"
#include "otp.h"

#if 0
#ifdef HAVE_CHECK_H
# include <check.h>
#else
# error "Missing Check installation; necessary for mod_auth_otp testsuite"
#endif
#else
# include <check.h>
#endif

Suite *tests_get_base32_suite(void);
Suite *tests_get_hotp_suite(void);
Suite *tests_get_totp_suite(void);

/* Temporary hack/placement for this variable, until we get to testing
 * the Signals API.
 */
unsigned int recvd_signal_flags;

extern pool *auth_otp_pool;
extern int auth_otp_logfd;

#endif /* MOD_AUTH_OTP_TESTS_H */
