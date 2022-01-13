/*
 * ProFTPD - mod_sftp interoperability
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

#ifndef MOD_SFTP_INTEROP_H
#define MOD_SFTP_INTEROP_H

#include "mod_sftp.h"

/* For clients which do not support IGNORE packets */
#define SFTP_SSH2_FEAT_IGNORE_MSG			0x0001

/* For clients which always truncate the HMAC len to 16 bits, regardless
 * of the actual HMAC len.
 */
#define SFTP_SSH2_FEAT_MAC_LEN				0x0002

/* For clients which do not include K when deriving cipher keys. */
#define SFTP_SSH2_FEAT_CIPHER_USE_K			0x0004

/* For clients which do not support rekeying */
#define SFTP_SSH2_FEAT_REKEYING				0x0008

/* For clients which do not support USERAUTH_BANNER packets */
#define SFTP_SSH2_FEAT_USERAUTH_BANNER			0x0010

/* For clients which do not send a string indicating the public key
 * algorithm in their publickey authentication requests.  This also
 * includes clients which do not use the string "publickey", and the
 * string for the public key algorithm, in the public key signature
 * (as dictated by Section 7 of RFC4252).
 */
#define SFTP_SSH2_FEAT_HAVE_PUBKEY_ALGO			0x0020

/* For clients whose publickey signatures always use a service name of
 * "ssh-userauth", regardless of the actual service name included in the
 * USERAUTH_REQUEST packet.
 */
#define SFTP_SSH2_FEAT_SERVICE_IN_PUBKEY_SIG		0x0040

/* For clients whose DSA publickey signatures do not include the string
 * "ssh-dss".
 */
#define SFTP_SSH2_FEAT_HAVE_PUBKEY_ALGO_IN_DSA_SIG	0x0080

/* For clients whose hostbased signatures always use a service name of
 * "ssh-userauth", regardless of the actual service name included in the
 * USERAUTH_REQUEST packet.
 */
#define SFTP_SSH2_FEAT_SERVICE_IN_HOST_SIG		0x0100

/* For clients that want the server to pessimistically send its NEWKEYS message
 * after they send their NEWKEYS message.
 */
#define SFTP_SSH2_FEAT_PESSIMISTIC_NEWKEYS		0x0200

/* For clients which cannot/do not tolerate non-kex related packets after a
 * server has requested rekeying.
 */
#define SFTP_SSH2_FEAT_NO_DATA_WHILE_REKEYING		0x0400

/* For scanners. */
#define SFTP_SSH2_FEAT_SCANNER				0xfffe

/* For probes. */
#define SFTP_SSH2_FEAT_PROBE				0xffff

/* Compares the given client version string against a table of known client
 * client versions and their interoperability/compatibility issues.
 */
int sftp_interop_handle_version(pool *, const char *);

/* Returns TRUE if the client supports the requested feature, FALSE
 * otherwise.
 */
int sftp_interop_supports_feature(int);

int sftp_interop_init(void);
int sftp_interop_free(void);

#endif /* MOD_SFTP_INTEROP_H */
