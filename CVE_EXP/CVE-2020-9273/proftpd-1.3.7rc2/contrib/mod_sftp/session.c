/*
 * ProFTPD - mod_sftp session
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

#include "mod_sftp.h"
#include "session.h"

static unsigned char *session_id = NULL;
static uint32_t session_idlen = 0;

uint32_t sftp_session_get_id(const unsigned char **buf) {
  if (session_id) {
    *buf = session_id;
    return session_idlen;
  }

  return 0;
}

int sftp_session_set_id(const unsigned char *hash, uint32_t hashlen) {
  /* The session ID is only set once, regardless of how many times
   * (re)keying occurs during the course of a session.
   */

  if (session_id == NULL) {
    session_id = palloc(sftp_pool, hashlen);
    memcpy(session_id, hash, hashlen);
    session_idlen = hashlen;

#if OPENSSL_VERSION_NUMBER >= 0x000905000L
    /* Since the session ID contains unknown information from the client,
     * it can be used as a source of additional entropy.  The amount
     * of entropy is a rough guess.
     */
    RAND_add(hash, hashlen, hashlen * 0.5);
#endif

    return 0;
  }

  return -1;
}
