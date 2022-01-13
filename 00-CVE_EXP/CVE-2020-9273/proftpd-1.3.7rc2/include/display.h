/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2004-2015 The ProFTPD Project team
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

/* Display of files */

#ifndef PR_DISPLAY_H
#define PR_DISPLAY_H

struct fh_rec;

/* This flag should be used to tell the pr_display_file() function to NOT
 * end the displayed lines, and instead to send the last line of a possibly
 * multiline file as just another line; the response will be terminated
 * properly by the calling code.
 */
#define PR_DISPLAY_FL_NO_EOM	0x0001

/* This flag should be used to tell the pr_display_file() function to send
 * the file lines immediately via pr_response_send(), rather than queueing
 * up the lines, to be flushed out to the client later.
 */
#define PR_DISPLAY_FL_SEND_NOW	0x0002

/* Used to read the file handle given by fh, located on the filesystem fs, and
 * return the results, with variables expanded, to the client, using the
 * response code given by resp_code.  Returns 0 if the file handle's contents
 * are displayed without issue, -1 otherwise (with errno set appropriately).
 */
int pr_display_fh(struct fh_rec *fh, const char *fs, const char *resp_code,
  int flags);

/* Used to read the file given by path, located on the filesystem fs, and
 * return the results, with variables expanded, to the client, using the
 * response code given by resp_code.  Returns 0 if the file is displayed without
 * issue, -1 otherwise (with errno set appropriately).
 */
int pr_display_file(const char *path, const char *fs, const char *resp_code,
  int flags);

#endif /* PR_DISPLAY_H */
