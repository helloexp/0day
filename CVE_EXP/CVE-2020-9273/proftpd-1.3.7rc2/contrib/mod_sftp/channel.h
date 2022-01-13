/*
 * ProFTPD - mod_sftp channels
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

#ifndef MOD_SFTP_CHANNEL_H
#define MOD_SFTP_CHANNEL_H

#include "mod_sftp.h"
#include "packet.h"

#define SFTP_SSH2_CHANNEL_OPEN_ADMINISTRATIVELY_PROHIBITED	1
#define SFTP_SSH2_CHANNEL_OPEN_CONNECT_FAILED			2
#define SFTP_SSH2_CHANNEL_OPEN_UNKNOWN_CHANNEL_TYPE		3
#define SFTP_SSH2_CHANNEL_OPEN_RESOURCE_SHORTAGE		4

#define SFTP_SSH2_CHANNEL_MAX_COUNT		10
#define SFTP_SSH2_CHANNEL_MAX_PACKET_SIZE	32768UL

/* Max channel window size, per RFC4254 Section 5.2 is 2^32-1 bytes. */
#define SFTP_SSH2_CHANNEL_WINDOW_SIZE		4294967295UL

struct ssh2_channel_databuf;

struct ssh2_channel {
  pool *pool;
  const char *type;

  uint32_t local_channel_id;
  uint32_t local_windowsz;
  uint32_t local_max_packetsz;

  uint32_t remote_channel_id;
  uint32_t remote_windowsz;
  uint32_t remote_max_packetsz;

  struct ssh2_channel_databuf *outgoing;

  int recvd_eof, sent_eof;
  int recvd_close, sent_close;

  /* For channel handling systems (e.g. fxp, scp) */
  int (*prepare)(uint32_t);
  int (*postopen)(uint32_t);
  int (*handle_packet)(pool *, void *, uint32_t, unsigned char *, uint32_t);
  int (*finish)(uint32_t);
};

uint32_t sftp_channel_get_max_packetsz(void);
uint32_t sftp_channel_get_windowsz(uint32_t);
unsigned int sftp_channel_set_max_count(unsigned int);
uint32_t sftp_channel_set_max_packetsz(uint32_t);
uint32_t sftp_channel_set_max_windowsz(uint32_t);

int sftp_channel_drain_data(void);
int sftp_channel_free(void);
int sftp_channel_handle(struct ssh2_packet *, char);
int sftp_channel_init(void);
int sftp_channel_write_data(pool *, uint32_t, unsigned char *, uint32_t);

/* Like sftp_channel_write_data(), but sends EXTENDED_DATA messages. */
int sftp_channel_write_ext_data_stderr(pool *, uint32_t, unsigned char *,
  uint32_t);

/* Return the number of open channels, if any.  If a pointer to a uint32_t
 * is provided, AND the returned count is greater than zero, then the
 * pointer will point to a randomly selected remote channel ID for an open
 * channel.
 */
unsigned int sftp_channel_opened(uint32_t *);

#endif /* MOD_SFTP_CHANNEL_H */
