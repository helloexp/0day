/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2009-2017 The ProFTPD Project team
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

#ifndef PR_CMD_H
#define PR_CMD_H

cmd_rec *pr_cmd_alloc(pool *p, unsigned int, ...);
int pr_cmd_clear_cache(cmd_rec *cmd);
const char *pr_cmd_get_displayable_str(cmd_rec *cmd, size_t *len);
int pr_cmd_get_errno(cmd_rec *cmd);

int pr_cmd_cmp(cmd_rec *cmd, int cmd_id);
int pr_cmd_strcmp(cmd_rec *cmd, const char *cmd_name);

/* Returns the cmd ID for the given command string, or -1 if there was an
 * error (with errno set appropriately).  NOTE: the given command name
 * MUST be all uppercased before being passed in for the proper ID to be
 * be returned.
 *
 * A return value of 0 means "unknown command".
 */
int pr_cmd_get_id(const char *name_name);

/* These IDs are indices into a static list in the Command API. */
#define	PR_CMD_USER_ID		1
#define PR_CMD_PASS_ID		2
#define PR_CMD_ACCT_ID		3
#define PR_CMD_CWD_ID		4
#define PR_CMD_XCWD_ID		5
#define PR_CMD_CDUP_ID		6
#define PR_CMD_XCUP_ID		7
#define PR_CMD_SMNT_ID		8
#define PR_CMD_REIN_ID		9
#define PR_CMD_QUIT_ID		10
#define PR_CMD_PORT_ID		11
#define PR_CMD_EPRT_ID		12
#define PR_CMD_PASV_ID		13
#define PR_CMD_EPSV_ID		14
#define PR_CMD_TYPE_ID		15
#define PR_CMD_STRU_ID		16
#define PR_CMD_MODE_ID		17
#define PR_CMD_RETR_ID		18
#define PR_CMD_STOR_ID		19
#define PR_CMD_STOU_ID		20
#define PR_CMD_APPE_ID		21
#define PR_CMD_ALLO_ID		22
#define PR_CMD_REST_ID		23
#define PR_CMD_RNFR_ID		24
#define PR_CMD_RNTO_ID		25
#define PR_CMD_ABOR_ID		26
#define PR_CMD_DELE_ID		27
#define PR_CMD_MDTM_ID		28
#define PR_CMD_RMD_ID		29
#define PR_CMD_XRMD_ID		30
#define PR_CMD_MKD_ID		31
#define PR_CMD_MLSD_ID		32
#define PR_CMD_MLST_ID		33
#define PR_CMD_XMKD_ID		34
#define PR_CMD_PWD_ID		35
#define PR_CMD_XPWD_ID		36
#define PR_CMD_SIZE_ID		37
#define PR_CMD_LIST_ID		38
#define PR_CMD_NLST_ID		39
#define PR_CMD_SITE_ID		40
#define PR_CMD_SYST_ID		41
#define PR_CMD_STAT_ID		42
#define PR_CMD_HELP_ID		43
#define PR_CMD_NOOP_ID		44
#define PR_CMD_FEAT_ID		45
#define PR_CMD_OPTS_ID		46
#define PR_CMD_LANG_ID		47
#define PR_CMD_ADAT_ID		48
#define PR_CMD_AUTH_ID		49
#define PR_CMD_CCC_ID		50
#define PR_CMD_CONF_ID		51
#define PR_CMD_ENC_ID		52
#define PR_CMD_MIC_ID		53
#define PR_CMD_PBSZ_ID		54
#define PR_CMD_PROT_ID		55
#define PR_CMD_MFF_ID		56
#define PR_CMD_MFMT_ID		57
#define PR_CMD_HOST_ID		58
#define PR_CMD_CLNT_ID		59
#define PR_CMD_RANG_ID		60

/* The minimum and maximum command name lengths. */
#define PR_CMD_MIN_NAMELEN	3
#define PR_CMD_MAX_NAMELEN	4

/* Returns TRUE if the given command is a known HTTP method, FALSE if not
 * a known HTTP method, and -1 if there is an error.
 */
int pr_cmd_is_http(cmd_rec *cmd);

/* Returns TRUE if the given command is a known SMTP method, FALSE if not
 * a known SMTP method, and -1 if there is an error.
 */
int pr_cmd_is_smtp(cmd_rec *cmd);

/* Returns TRUE if the given command appears to be an SSH2 request, FALSE
 * if not, and -1 if there was an error.
 */
int pr_cmd_is_ssh2(cmd_rec *cmd);

int pr_cmd_set_errno(cmd_rec *cmd, int xerrno);
int pr_cmd_set_name(cmd_rec *cmd, const char *name);

/* Implemented in main.c */
int pr_cmd_read(cmd_rec **cmd);
int pr_cmd_dispatch(cmd_rec *cmd);
int pr_cmd_dispatch_phase(cmd_rec *cmd, int, int);
#define PR_CMD_DISPATCH_FL_SEND_RESPONSE	0x001
#define PR_CMD_DISPATCH_FL_CLEAR_RESPONSE	0x002

void pr_cmd_set_handler(void (*)(server_rec *s, conn_t *conn));

#endif /* PR_CMD_H */
