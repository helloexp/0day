/*
 * ProFTPD - mod_sftp keyboard-interactive API
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

#ifndef MOD_SFTP_KBDINT_H
#define MOD_SFTP_KBDINT_H

#include "mod_sftp.h"

/* Returns the registered driver by name, or NULL if no such driver has
 * been registered.
 */
sftp_kbdint_driver_t *sftp_kbdint_get_driver(const char *);

/* Returns the number of registered keyboard-interactive drivers. */
unsigned int sftp_kbdint_have_drivers(void);

/* Returns the first driver in the list. */
sftp_kbdint_driver_t *sftp_kbdint_first_driver(void);

/* Returns the next driver in the list, or NULL if there are no remaining
 * drivers.
 */
sftp_kbdint_driver_t *sftp_kbdint_next_driver(void);

#endif /* MOD_SFTP_KBDINT_H */
