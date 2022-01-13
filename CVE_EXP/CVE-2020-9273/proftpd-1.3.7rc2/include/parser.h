/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2004-2016 The ProFTPD Project team
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

/* Configuration parser */

#ifndef PR_PARSER_H
#define PR_PARSER_H

/* Prepares the parser, allocating any necessary internal resources from
 * the given pool.  If provided, parsed_servers will, after parsing is
 * complete, contain a pointer to the list of configured server_rec
 * server configurations.
 */
int pr_parser_prepare(pool *p, xaset_t **parsed_servers);

/* Clears any internal state of the parser.  This function should always
 * be called after any parsing.
 */
int pr_parser_cleanup(void);

/* Called to push a "start-of-context" configuration marker onto the
 * parser stack.  The name of the configuration context (.e.g "Directory"
 * or "Anonymous") is provided by the name parameter.
 */
config_rec *pr_parser_config_ctxt_open(const char *name);

/* Called to push an "end-of-context" configuration marker onto the
 * parser stack.  If the parser determines that the configuration
 * context being closed is empty, it will remove the entire context from
 * the parser stacks: empty contexts are superfluous.  If this happens,
 * the isempty parameter, if non-NULL, will be set to TRUE.
 */
config_rec *pr_parser_config_ctxt_close(int *isempty);

/* Push the config_rec onto the parser stack directly.  This function can
 * be used, instead of the open/close semantics, for cases where the config_rec
 * is constructed by means other than file parsing.
 */
int pr_parser_config_ctxt_push(config_rec *c);

/* Returns a pointer to the current configuration record on the parser
 * configuration stack.
 */
config_rec *pr_parser_config_ctxt_get(void);

/* Returns the line number of the configuration stream being parsed. */
unsigned int pr_parser_get_lineno(void);

/* This is the main function to be used by consumers of the Parser
 * API.  Given a pool, a path to a file containing configuration text,
 * and a starting configuration context, the function will open and
 * parse the given data.
 *
 * In almost all cases, the starting configuration context given by the
 * start parameter is NULL, indicating that the path being parsed is
 * not part of any existing configuration tree.  The start parameter will
 * be non-NULL in the case of files such as .ftpaccess files, which are
 * part of the existing configuration tree.
 *
 * The flags parameter is used to indicate to the parser what type of
 * stream is being parsed.  The PR_PARSER_FL_DYNAMIC_CONFIG flag is
 * used when handling .ftpaccess files, so that the function will treat
 * unknown directives as warnings, rather than as fatal errors.
 */
int pr_parser_parse_file(pool *p, const char *path, config_rec *start,
  int flags);
#define PR_PARSER_FL_DYNAMIC_CONFIG	0x0001

/* The dispatching of configuration data to the registered configuration
 * handlers is done using a cmd_rec.  This function parses the given line of
 * text, then allocates a cmd_rec from the given pool p and populates the
 * struct with data from the line of text.
 */
cmd_rec *pr_parser_parse_line(pool *p, const char *text, size_t text_len);

/* This convenience function reads the next line from the configuration
 * stream, performing any necessary transformations on the text (e.g.
 * skipping comments, trimming leading and trailing spaces, etc).  NULL
 * is returned if there are no more lines of configuration text in the
 * the stream.
 *
 * The configuration stream itself is not provided by the caller deliberately;
 * this allows callers who do not have access to the configuration stream
 * to read data from it.
 */
char *pr_parser_read_line(char *buf, size_t bufsz);

/* Called to push a "start-of-server" configuration marker onto the
 * parser stack.  The name of the server context, usually a string
 * containing a DNS name or an IP address, is provided by the addrstr
 * parameter.
 */
server_rec *pr_parser_server_ctxt_open(const char *addrstr);

/* Called to push an "end-of-server" configuration record onto the
 * parser stack.  If the parser determines that the server context being
 * closed is empty, it will remove the entire context from the parser stacks:
 * empty contexts are superfluous.
 */
server_rec *pr_parser_server_ctxt_close(void);

/* Push the server_rec onto the parser stack directly.  This function can
 * be used, instead of the open/close semantics, for cases where the server_rec
 * is constructed by means other than file parsing.
 */
int pr_parser_server_ctxt_push(server_rec *s);

/* Returns a pointer to the current server record on the parser server
 * stack.
 */
server_rec *pr_parser_server_ctxt_get(void);

/* Configure optional Include behavior. Returns the previously set options. */
unsigned long pr_parser_set_include_opts(unsigned long opts);
#define PR_PARSER_INCLUDE_OPT_ALLOW_SYMLINKS		0x0001
#define PR_PARSER_INCLUDE_OPT_IGNORE_TMP_FILES		0x0002
#define PR_PARSER_INCLUDE_OPT_IGNORE_WILDCARDS		0x0004

/* Internal use only */
int parse_config_path(pool *p, const char *path);
int parse_config_path2(pool *p, const char *path, unsigned int depth);

#endif /* PR_PARSER_H */
