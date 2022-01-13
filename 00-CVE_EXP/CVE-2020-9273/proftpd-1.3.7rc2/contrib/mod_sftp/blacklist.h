/*
 * Support for RSA/DSA key blacklisting based on partial fingerprints,
 * developed under Openwall Project for Owl - http://www.openwall.com/Owl/
 *
 * Copyright (c) 2008 Dmitry V. Levin <ldv at cvs.openwall.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * The blacklist encoding was designed by Solar Designer and Dmitry V. Levin.
 * No intellectual property rights to the encoding scheme are claimed.
 *
 * This effort was supported by CivicActions - http://www.civicactions.com
 *
 * The file size to encode 294,903 of 48-bit fingerprints is just 1.3 MB,
 * which corresponds to less than 4.5 bytes per fingerprint.
 */

#ifndef MOD_SFTP_BLACKLIST_H
#define MOD_SFTP_BLACKLIST_H

#include "mod_sftp.h"

int sftp_blacklist_reject_key(pool *, unsigned char *, uint32_t);
int sftp_blacklist_set_file(const char *);

#endif /* MOD_SFTP_BLACKLIST_H */
