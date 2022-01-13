/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2013-2018 The ProFTPD Project team
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

/* ASCII character checks/conversions */

#ifndef PR_ASCII_H
#define PR_ASCII_H

/* These macros "wrap" many of the ctype(3) checks (which may themselves
 * be macros), doing an isascii(3) check FIRST, before calling the actual
 * ctype(3) check desired.
 */
#define PR_ISALNUM(c)		(isascii((int) (c)) && isalnum((int) (c)))
#define PR_ISALPHA(c)		(isascii((int) (c)) && isalpha((int) (c)))
#define PR_ISCNTRL(c)		(isascii((int) (c)) && iscntrl((int) (c)))
#define PR_ISDIGIT(c)		(isascii((int) (c)) && isdigit((int) (c)))
#define PR_ISPRINT(c)		(isascii((int) (c)) && isprint((int) (c)))
#define PR_ISSPACE(c)		(isascii((int) (c)) && isspace((int) (c)))
#define PR_ISXDIGIT(c)		(isascii((int) (c)) && isxdigit((int) (c)))

/* For FTP's ASCII conversion rules. */
void pr_ascii_ftp_reset(void);

/* Converts the given `in' buffer, character by character, writing the data into
 * the given `out' buffer, converting any CRLF sequences found into LF
 * sequences.  The amount of data written into the `out' buffer is returned
 * via the `outlen' argument.
 * 
 * Returns the number of "carry over" CRs on success, and -1 on error, setting
 * errno appropriately.
 */
int pr_ascii_ftp_from_crlf(pool *p, char *in, size_t inlen, char **out,
  size_t *outlen);

/*
 * Returns the number N on success, and -1 on error, setting errno
 * appropriately.
 *
 * NOTE: This function uses malloc(3) deliberately (see Bug#4352), and thus
 * the caller MUST call free(3) on the **out pointer.
 */
int pr_ascii_ftp_to_crlf(pool *p, char *in, size_t inlen, char **out,
  size_t *outlen);

#endif /* PR_ASCII_H */
