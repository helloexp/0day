/*
 * ProFTPD - mod_sftp SSH2 constants
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

#ifndef MOD_SFTP_SSH2_H
#define MOD_SFTP_SSH2_H

/* As per RFC 4253, Section 6.1, we MUST be able to handle a packet whose
 * length is 35000 bytes; we SHOULD be able to handle larger packets.  We
 * impose a maximum size here to prevent overly-large packets from being
 * used by attackers.  The maximum size is a bit arbitrary.
 */
#define SFTP_MAX_PACKET_LEN             (1024 * 256)

/* SSH2 package message types */

#define SFTP_SSH2_MSG_DISCONNECT		1
#define SFTP_SSH2_MSG_IGNORE			2
#define SFTP_SSH2_MSG_UNIMPLEMENTED		3
#define SFTP_SSH2_MSG_DEBUG			4
#define SFTP_SSH2_MSG_SERVICE_REQUEST		5
#define SFTP_SSH2_MSG_SERVICE_ACCEPT		6
#define SFTP_SSH2_MSG_KEXINIT			20
#define SFTP_SSH2_MSG_NEWKEYS			21

/* Key exchange message types */
#define SFTP_SSH2_MSG_KEX_DH_INIT		30
#define SFTP_SSH2_MSG_KEX_DH_REPLY		31
#define SFTP_SSH2_MSG_KEX_DH_GEX_REQUEST_OLD	30
#define SFTP_SSH2_MSG_KEX_DH_GEX_GROUP		31
#define SFTP_SSH2_MSG_KEX_DH_GEX_INIT		32
#define SFTP_SSH2_MSG_KEX_DH_GEX_REPLY		33
#define SFTP_SSH2_MSG_KEX_DH_GEX_REQUEST	34
#define SFTP_SSH2_MSG_KEXRSA_PUBKEY		30
#define SFTP_SSH2_MSG_KEXRSA_SECRET		31
#define SFTP_SSH2_MSG_KEXRSA_DONE		32
#define SFTP_SSH2_MSG_KEX_ECDH_INIT		30
#define SFTP_SSH2_MSG_KEX_ECDH_REPLY		31

/* User authentication message types */
#define SFTP_SSH2_MSG_USER_AUTH_REQUEST		50
#define SFTP_SSH2_MSG_USER_AUTH_FAILURE		51
#define SFTP_SSH2_MSG_USER_AUTH_SUCCESS		52
#define SFTP_SSH2_MSG_USER_AUTH_BANNER		53
#define SFTP_SSH2_MSG_USER_AUTH_PUBKEY		60
#define SFTP_SSH2_MSG_USER_AUTH_PK_OK		60
#define SFTP_SSH2_MSG_USER_AUTH_PASSWD		60
#define SFTP_SSH2_MSG_USER_AUTH_INFO_REQ	60
#define SFTP_SSH2_MSG_USER_AUTH_INFO_RESP	61

/* Request types */
#define SFTP_SSH2_MSG_GLOBAL_REQUEST		80
#define SFTP_SSH2_MSG_REQUEST_SUCCESS		81
#define SFTP_SSH2_MSG_REQUEST_FAILURE		82

/* Channel message types */
#define SFTP_SSH2_MSG_CHANNEL_OPEN 		90
#define SFTP_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION	91
#define SFTP_SSH2_MSG_CHANNEL_OPEN_FAILURE	92
#define SFTP_SSH2_MSG_CHANNEL_WINDOW_ADJUST	93
#define SFTP_SSH2_MSG_CHANNEL_DATA		94
#define SFTP_SSH2_MSG_CHANNEL_EXTENDED_DATA	95
#define SFTP_SSH2_MSG_CHANNEL_EOF		96
#define SFTP_SSH2_MSG_CHANNEL_CLOSE		97
#define SFTP_SSH2_MSG_CHANNEL_REQUEST		98
#define SFTP_SSH2_MSG_CHANNEL_SUCCESS		99
#define SFTP_SSH2_MSG_CHANNEL_FAILURE		100

/* Channel extended data types */
#define SFTP_SSH2_MSG_CHANNEL_EXTENDED_DATA_TYPE_STDERR		1

/* SSH Disconnect reason codes */
#define SFTP_SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT	1
#define SFTP_SSH2_DISCONNECT_PROTOCOL_ERROR			2
#define SFTP_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED		3
#define SFTP_SSH2_DISCONNECT_RESERVED				4
#define SFTP_SSH2_DISCONNECT_MAC_ERROR				5
#define SFTP_SSH2_DISCONNECT_COMPRESSION_ERROR			6
#define SFTP_SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE		7
#define SFTP_SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED	8
#define SFTP_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE		9
#define SFTP_SSH2_DISCONNECT_CONNECTION_LOST			10
#define SFTP_SSH2_DISCONNECT_BY_APPLICATION			11
#define SFTP_SSH2_DISCONNECT_TOO_MANY_CONNECTIONS		12
#define SFTP_SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER		13
#define SFTP_SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE	14
#define SFTP_SSH2_DISCONNECT_ILLEGAL_USER_NAME			15

#endif /* MOD_SFTP_SSH2_H */
