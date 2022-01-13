/*
 * ProFTPD - mod_sftp packet IO
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

#ifndef MOD_SFTP_PACKET_H
#define MOD_SFTP_PACKET_H

#include "mod_sftp.h"

/* From RFC 4253, Section 6 */
struct ssh2_packet {
  pool *pool;

  /* Length of the packet, not including mac or packet_len field itself. */
  uint32_t packet_len;

  /* Length of the padding field. */
  unsigned char padding_len;

  unsigned char *payload;
  uint32_t payload_len;

  /* Must be at least 4 bytes of padding, with a maximum of 255 bytes. */
  unsigned char *padding;

  /* Message Authentication Code. */
  unsigned char *mac;
  uint32_t mac_len;

  /* Packet sequence number. */
  uint32_t seqno;
};

#define SFTP_MIN_PADDING_LEN	4
#define SFTP_MAX_PADDING_LEN	255

/* From the SFTP Draft, Section 4. */
struct sftp_packet {
  uint32_t packet_len;
  unsigned char packet_type;
  uint32_t request_id;
};

struct ssh2_packet *sftp_ssh2_packet_create(pool *);
char sftp_ssh2_packet_get_mesg_type(struct ssh2_packet *);
const char *sftp_ssh2_packet_get_mesg_type_desc(unsigned char);

/* Returns a struct timeval populated with the time we last received an SSH2
 * packet from the client.
 */
int sftp_ssh2_packet_get_last_recvd(time_t *);

/* Returns a struct timeval populated with the time we last sent an SSH2
 * packet from the client.
 */
int sftp_ssh2_packet_get_last_sent(time_t *);

int sftp_ssh2_packet_read(int, struct ssh2_packet *);
int sftp_ssh2_packet_sock_read(int, void *, size_t, int);

/* This sftp_ssh2_packet_sock_read() flag is used to tell the function to
 * read in as many of the requested length of data as it can, but to NOT
 * keep polling until that length has been acquired (i.e. to read the
 * requested length pessimistically, assuming that it will not all appear).
 */
#define SFTP_PACKET_READ_FL_PESSIMISTIC		0x001

int sftp_ssh2_packet_send(int, struct ssh2_packet *);

/* Wrapper function around sftp_ssh2_packet_send() which handles the sending
 * of TAP messages and buffering of messages for network efficiency.
 */
int sftp_ssh2_packet_write(int, struct ssh2_packet *);

int sftp_ssh2_packet_handle(void);

/* These specialized functions are for handling the additional message types
 * defined in RFC 4253, Section 11, e.g. during KEX.
 */
void sftp_ssh2_packet_handle_debug(struct ssh2_packet *);
void sftp_ssh2_packet_handle_disconnect(struct ssh2_packet *);
void sftp_ssh2_packet_handle_ignore(struct ssh2_packet *);
void sftp_ssh2_packet_handle_unimplemented(struct ssh2_packet *);

int sftp_ssh2_packet_rekey_reset(void);
int sftp_ssh2_packet_rekey_set_seqno(uint32_t);
int sftp_ssh2_packet_rekey_set_size(off_t);

int sftp_ssh2_packet_send_version(void);
int sftp_ssh2_packet_set_poll_timeout(int);
int sftp_ssh2_packet_set_version(const char *);

int sftp_ssh2_packet_set_client_alive(unsigned int, unsigned int);

#endif /* MOD_SFTP_PACKET_H */
