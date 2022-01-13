/*
 * ProFTPD: LogFormat
 * Copyright (c) 2013-2017 TJ Saunders
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

#ifndef PR_LOGFMT_H
#define PR_LOGFMT_H

/* These "meta" sequences represent the parsed LogFormat variables.  Each one
 * MUST be a byte; we treat a buffer of sequences in a byte by byte fashion.
 * Thus 255 is the maximum value for these.
 *
 * Note: We explicit do NOT use the value zero here, since that value is
 * used to terminate a buffer of LogFormat data, as if it were a NUL-terminated
 * string.
 */

#define LOGFMT_META_ARG			1
#define LOGFMT_META_BYTES_SENT		2
#define LOGFMT_META_FILENAME		3
#define LOGFMT_META_ENV_VAR		4
#define LOGFMT_META_REMOTE_HOST		5
#define LOGFMT_META_REMOTE_IP		6
#define LOGFMT_META_IDENT_USER		7
#define LOGFMT_META_PID			8
#define LOGFMT_META_TIME		9
#define LOGFMT_META_SECONDS		10
#define LOGFMT_META_COMMAND		11
#define LOGFMT_META_LOCAL_NAME		12
#define LOGFMT_META_LOCAL_PORT		13
#define LOGFMT_META_LOCAL_IP		14
#define LOGFMT_META_LOCAL_FQDN		15
#define LOGFMT_META_USER		16
#define LOGFMT_META_ORIGINAL_USER	17
#define LOGFMT_META_RESPONSE_CODE	18
#define LOGFMT_META_CLASS		19
#define LOGFMT_META_ANON_PASS		20
#define LOGFMT_META_METHOD		21
#define LOGFMT_META_XFER_PATH		22
#define LOGFMT_META_DIR_NAME		23
#define LOGFMT_META_DIR_PATH		24
#define LOGFMT_META_CMD_PARAMS		25
#define LOGFMT_META_RESPONSE_STR	26
#define LOGFMT_META_PROTOCOL		27
#define LOGFMT_META_VERSION		28
#define LOGFMT_META_RENAME_FROM		29
#define LOGFMT_META_FILE_MODIFIED	30
#define LOGFMT_META_UID			31
#define LOGFMT_META_GID			32
#define LOGFMT_META_RAW_BYTES_IN	33
#define LOGFMT_META_RAW_BYTES_OUT	34
#define LOGFMT_META_EOS_REASON		35
#define LOGFMT_META_VHOST_IP		36
#define LOGFMT_META_NOTE_VAR		37
#define LOGFMT_META_XFER_STATUS		38
#define LOGFMT_META_XFER_FAILURE	39
#define LOGFMT_META_MICROSECS		40
#define LOGFMT_META_MILLISECS		41
#define LOGFMT_META_ISO8601		42
#define LOGFMT_META_GROUP		43
#define LOGFMT_META_BASENAME		44
#define LOGFMT_META_FILE_OFFSET		45
#define LOGFMT_META_XFER_MS		46
#define LOGFMT_META_RESPONSE_MS		47
#define LOGFMT_META_FILE_SIZE		48
#define LOGFMT_META_XFER_TYPE		49
#define LOGFMT_META_REMOTE_PORT		50
#define LOGFMT_META_EPOCH		51
#define LOGFMT_META_CONNECT		52
#define LOGFMT_META_DISCONNECT		53

#define LOGFMT_META_CUSTOM		253
#define LOGFMT_META_ARG_END		254
#define LOGFMT_META_START		255

#endif /* PR_LOGFMT_H */
