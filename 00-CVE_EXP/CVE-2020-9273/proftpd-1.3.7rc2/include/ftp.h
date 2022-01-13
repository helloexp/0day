/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2017 The ProFTPD Project team
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
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* FTP commands and responses (may not all be implemented) */

#ifndef PR_FTP_H
#define PR_FTP_H

/* Commands (minimum required supported level) */
#define C_USER	"USER"		/* Specify a username */
#define C_PASS	"PASS"		/* Specify a password */
#define C_ACCT	"ACCT"		/* Specify an account (not implemented) */
#define C_CWD	"CWD"		/* Change working directory */
#define C_XCWD	"XCWD"		/* Change working directory */
#define C_CDUP	"CDUP"		/* Change CWD up one level */
#define C_XCUP	"XCUP"		/* Change CWD up one level */
#define C_SMNT	"SMNT"		/* Mount different file system data structure (not implemented) */
#define C_REIN	"REIN"		/* Reinitialize account information (not supported) */
#define C_QUIT	"QUIT"		/* Close control connection and logout (if no transfer pending) */
#define C_PORT	"PORT"		/* PORT h1,h2,h3,h4,p1,p2 (specify User address/port for data connection) */
#define	C_EPRT	"EPRT"		/* Extended PORT */
#define C_PASV	"PASV"		/* Next transfer data connection is from client to server */
#define	C_EPSV	"EPSV"		/* Extended PASV */
#define C_TYPE	"TYPE"		/* A = ASCII, E = EBCDIC, I = Image, L<byte size> = Local byte size */
#define C_STRU	"STRU"		/* File structure (not implemented) */
#define C_MODE	"MODE"		/* Transfer Mode (S - Stream, B - Block, C - Compressed (not supported) */
#define C_RETR	"RETR"		/* Retrieve a file (RETR name) */
#define C_STOR	"STOR"		/* Store a file (STOR name) */
#define C_STOU	"STOU"		/* Store unique */
#define C_APPE	"APPE"		/* Append to the end of a file */
#define C_ALLO	"ALLO"		/* Allocate storage space (not used) */
#define C_REST	"REST"		/* Restart a transfer (REST marker) */
#define C_RNFR	"RNFR"		/* Rename from (RNFR filename) */
#define C_RNTO	"RNTO"		/* Rename to (RNTO filename) */
#define C_ABOR	"ABOR"		/* Abort current operation */
#define C_DELE	"DELE"		/* Delete a file */
#define C_MDTM	"MDTM"		/* Modification time, NOT in RFC959. */
#define C_RMD	"RMD"		/* Remove a directory */
#define C_XRMD	"XRMD"		/* Remove a directory */
#define C_MKD	"MKD"		/* Create a directory */
#define C_MLSD	"MLSD"		/* List a directory (RFC3659) */
#define C_MLST	"MLST"		/* List a path (RFC3659) */
#define C_XMKD	"XMKD"		/* Create a directory */
#define C_PWD	"PWD"		/* Return current working directory */
#define C_XPWD	"XPWD"		/* Return current working directory */
#define C_SIZE	"SIZE"		/* Return the number of octets in a file */
#define C_LIST	"LIST"		/* Return contents of PWD or specified dir */
#define C_NLST	"NLST"		/* As list but returns names only */
#define C_SITE	"SITE"		/* Site specific command */
#define C_SYST	"SYST"		/* The type of OS (UNIX Type: L8) */
#define C_STAT	"STAT"		/* Status */
#define C_HELP	"HELP"		/* Help */
#define C_NOOP	"NOOP"		/* Returns 200 and does nothing */
#define C_FEAT	"FEAT"		/* Request list of server-supported features */
#define C_OPTS	"OPTS"		/* Specify options for FTP commands */
#define C_LANG	"LANG"		/* Request a specific language */
#define C_HOST	"HOST"		/* Request a named server */
#define C_CLNT	"CLNT"		/* Client-offered identification */
#define C_RANG	"RANG"		/* Range of bytes to transfer */

/* RFC2228 FTP Security commands */
#define C_ADAT  "ADAT"		/* Authentication/security data */
#define C_AUTH  "AUTH"		/* Authentication/security mechanism */
#define C_CCC   "CCC"		/* Clear command channel */
#define C_CONF  "CONF"		/* Confidentiality protected command */
#define C_ENC   "ENC"		/* Privacy protected command */
#define C_MIC   "MIC"		/* Integrity protected command */
#define C_PBSZ  "PBSZ"		/* Protection buffer size */
#define C_PROT  "PROT"		/* Data channel protection level */

/* Proposed commands */
#define C_MFF	"MFF"		/* Modify File Fact (RFC3659) */
#define C_MFMT	"MFMT"		/* Modify File Modify-Type (RFC3659) */

#define C_ANY	"*"		/* Special "wildcard" matching command */

/* Command groupings */

#define G_NONE	NULL
#define G_DIRS	"DIRS"		/* LIST, NLST */
#define G_READ	"READ"		/* RETR, etc */
#define G_WRITE "WRITE"		/* WRITE, etc */

/* Responses */

#define R_110	"110"		/* Restart marker reply (MARK yyyy = mmmm) */
#define R_120	"120"		/* Svc ready in nnn minutes */
#define R_125	"125"		/* Data connection already open; starting */
#define R_150	"150"		/* File status ok; opening data conn */
#define R_200	"200"		/* 'Generic' command ok */
#define R_202	"202"		/* Command not implemented, superfluous at this site */
#define R_211	"211"		/* System status or system help reply */
#define R_212	"212"		/* Directory status */
#define R_213	"213"		/* File status */
#define R_214	"214"		/* Help message (how to use server or non-standard command) */
#define R_215	"215"		/* NAME system type.  NAME == Official system name */
#define R_220	"220"		/* Service ready for new user. */
#define R_221	"221"		/* Service closing control connection, as per normal */
#define R_225	"225"		/* Data connection open; no transfer in progress */
#define R_226	"226"		/* Closing data connection.  File transfer/abort successful */
#define R_227	"227"		/* Entering passive mode (h1,h2,h3,h4,p1,p2) */
#define	R_229	"229"		/* Entering extended passive mode (|||p|) */
#define R_230	"230"		/* User logged in, proceed */
#define R_232   "232"		/* User logged in, authorized by security data */
#define R_234   "234"		/* Security data exchange complete */
#define R_235   "235"		/* Security exchange successful */

#define R_250	"250"		/* Requested file action okay, completed. */
#define R_257	"257"		/* "PATHNAME" created. */
#define R_331	"331"		/* User name okay, need password. */
#define R_332	"332"		/* Need account for login. */
#define R_334   "334"		/* Security data required */
#define R_335   "335"		/* Additional security data required */
#define R_336   "336"		/* Username OK, need password; presenting challenge */
#define R_350	"350"		/* Requested file action pending further info */
#define R_421	"421"		/* Service not available, closing control connection (service is about to be shutdown) */
#define R_425	"425"		/* Can't open data connection */
#define R_426	"426"		/* Connection closed; transfer aborted */
#define R_431   "431"		/* Necessary security resource is unavailable */
#define R_450	"450"		/* Requested file action not taken (file unavailable; busy) */
#define R_451	"451"		/* Requested action aborted; local error in processing */
#define R_452	"452"		/* Requested action not taken; insufficient storage space */
#define	R_500	"500"		/* Syntax error, command unrecognized */
#define R_501	"501"		/* Syntax error in parameters or arguments */
#define R_502	"502"		/* Command not implemented */
#define R_503	"503"		/* Bad sequence of commands */
#define R_504	"504"		/* Command not implemented for that parameter */
#define	R_522	"522"		/* Extended port failure: unknown network protocol */
#define R_530	"530"		/* Not logged in */
#define R_532	"532"		/* Need account for storing files */
#define R_533   "533"		/* Integrity protected command required by policy */
#define R_534   "534"		/* Unwilling to accept security arguments */
#define R_535   "535"		/* Data failed security check */
#define R_536   "536"		/* Unsupported data channel protection level */
#define R_537   "537"		/* Unsupported command protection by security mechanism */
#define R_550	"550"		/* Requested action not taken. No access, etc */
#define R_551	"551"		/* Requested action not taken, page type unknown */
#define R_552	"552"		/* Requested file action aborted, exceeding storage allocation */
#define	R_553	"553"		/* Requested action not taken, file name not allowed */
#define R_554   "554"           /* Requested action not taken, invalid REST parameter (RFC 1123) */
#define R_631	"631"		/* Integrity protected response (RFC 2228) */
#define R_632	"632"		/* Privacy protected response (RFC 2228) */
#define R_633	"633"		/* Confidentiality protected response (RFC 2228) */
#define R_DUP	NULL		/* Duplicate last numeric in ml response */

#endif /* PR_FTP_H */
