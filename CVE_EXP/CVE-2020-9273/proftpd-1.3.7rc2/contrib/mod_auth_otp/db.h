/*
 * ProFTPD - mod_auth_otp database routines
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

#ifndef MOD_AUTH_OTP_DB_H
#define MOD_AUTH_OTP_DB_H

#include "mod_auth_otp.h"

struct auth_otp_db {
  pool *pool;

  const char *select_query;
  const char *update_query;

  /* Database locking support. */
  struct flock db_lock;
  int db_lockfd;
};

int auth_otp_db_close(struct auth_otp_db *dbh);
struct auth_otp_db *auth_otp_db_open(pool *p, const char *dbinfo);
int auth_otp_db_rlock(struct auth_otp_db *dbh);
int auth_otp_db_wlock(struct auth_otp_db *dbh);
int auth_otp_db_unlock(struct auth_otp_db *dbh);

/* Ask if the table has info (secrets, counters) for this user. */
int auth_otp_db_have_user_info(pool *p, struct auth_otp_db *dbh,
  const char *user);

/* Retrieve the user's base32-encoded secret, and current counter (for HOTP). */
int auth_otp_db_get_user_info(pool *p, struct auth_otp_db *dbh,
  const char *user, const unsigned char **secret, size_t *secret_len,
  unsigned long *counter);

/* Update the user's current counter (for HOTP). */
int auth_otp_db_update_counter(struct auth_otp_db *dbh, const char *user,
  unsigned long counter);

#endif /* MOD_AUTH_OTP_DB_H */
