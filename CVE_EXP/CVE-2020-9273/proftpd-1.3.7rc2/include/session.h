/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2009-2016 The ProFTPD Project team
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

#ifndef PR_SESSION_H
#define PR_SESSION_H

/* List of disconnect/end-of-session reason codes. */

/* Unknown/unspecified reason for disconnection */
#define PR_SESS_DISCONNECT_UNSPECIFIED		0

/* Disconnected gracefully */
#define PR_SESS_DISCONNECT_CLIENT_QUIT		1

/* Disconnected because of EOF on read connection */
#define PR_SESS_DISCONNECT_CLIENT_EOF		2

/* Disconnected because of session initialization failure */
#define PR_SESS_DISCONNECT_SESSION_INIT_FAILED	3

/* Disconnected by signal */
#define PR_SESS_DISCONNECT_SIGNAL		4

/* Disconnected because of out-of-memory issues */
#define PR_SESS_DISCONNECT_NOMEM		5

/* Disconnected because server shutdown */
#define PR_SESS_DISCONNECT_SERVER_SHUTDOWN	6

/* Disconnected due to a timeout of some sort */
#define PR_SESS_DISCONNECT_TIMEOUT		7

/* Disconnected because client is banned */
#define PR_SESS_DISCONNECT_BANNED		8

/* Disconnected because of configured policy, e.g. <Limit LOGIN> */
#define PR_SESS_DISCONNECT_CONFIG_ACL		9

/* Disconnected because of module-specific policy, e.g. allow/deny files */
#define PR_SESS_DISCONNECT_MODULE_ACL		10

/* Disconnected due to module misconfiguration, bad config syntax, etc */
#define PR_SESS_DISCONNECT_BAD_CONFIG		11

/* Disconnected by application (general purpose code). */
#define PR_SESS_DISCONNECT_BY_APPLICATION	12

/* Disconnected due to snprintf(3) buffer truncation. */
#define PR_SESS_DISCONNECT_SNPRINTF_TRUNCATED	13

/* Disconnected due to wrong protocol used (e.g. HTTP/SMTP). */
#define PR_SESS_DISCONNECT_BAD_PROTOCOL		14

/* Disconnected due to segfault. */
#define PR_SESS_DISCONNECT_SEGFAULT		15

/* Returns a string describing the reason the client was disconnected or
 * the session ended.  If a pointer to a char * was provided, any extra
 * disconnect details will be provided.
 */
const char *pr_session_get_disconnect_reason(const char **details);

/* Returns the current protocol name in use.
 *
 * The PR_SESS_PROTO_FL_LOGOUT flag is used when retrieving the protocol
 * name to display in the login/logout messages, e.g. "FTP" or "SSH2".
 */
const char *pr_session_get_protocol(int);
#define PR_SESS_PROTO_FL_LOGOUT		0x01

/* Ends the current session but records the reason for the disconnection
 * via the reason code, the module which disconnected the client, and any
 * extra details the caller may provide.
 */
void pr_session_disconnect(module *m, int reason_code, const char *details);

/* Ends the current session process, unless the PR_SESS_END_FL_NOEXIT
 * flag value is set.  (This flag is really only used by signal handlers
 * which are going to use abort(2) rather than _exit(2) to end the process.)
 */
void pr_session_end(int flags);
#define PR_SESS_END_FL_NOEXIT		0x01
#define PR_SESS_END_FL_SYNTAX_CHECK	0x02
#define PR_SESS_END_FL_ERROR		0x04

/* Returns a so-called "tty name" suitable for use via PAM, and in WtmpLog
 * logging.
 */
const char *pr_session_get_ttyname(pool *);

/* Send the 220 response/banner information to the connecting client. */
void pr_session_send_banner(server_rec *, int);

/* Marks the current session as "idle" both in the scoreboard and in the
 * proctitle.
 */
int pr_session_set_idle(void);

/* Sets the current protocol name. */
int pr_session_set_protocol(const char *);

#endif /* PR_SESSION_H */
