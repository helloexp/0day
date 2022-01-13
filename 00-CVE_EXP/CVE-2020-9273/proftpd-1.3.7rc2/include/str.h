/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2008-2017 The ProFTPD Project team
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

/* String manipulation functions */

#ifndef PR_STR_H
#define PR_STR_H

/* Default maximum number of replacements that will do in a given string. */
#define PR_STR_MAX_REPLACEMENTS                 8

/* Per RFC959, directory responses for MKD and PWD should be "dir_name" (with
 * quotes).  For directories that CONTAIN quotes, the additional quotes must
 * be duplicated.
 */
const char *quote_dir(pool *p, char *dir);

char *sstrcat(char *, const char *, size_t);
const char *sreplace(pool *, const char *, ...);

char *pdircat(pool *, ...);
char *pstrcat(pool *, ...);
char *pstrdup(pool *, const char *);
char *pstrndup(pool *, const char *, size_t);

/* Returns TRUE if the string `s' ends with given `suffix', FALSE if the string
 * does not end with the given suffix, and -1 if there was an error (errno
 * will be set appropriately).
 *
 * The `flags' value consisted of OR'ing the following:
 *
 *  PR_STR_FL_IGNORE_CASE
 *    Request a case-insensitive comparison
 */
int pr_strnrstr(const char *s, size_t slen, const char *suffix,
  size_t suffixlen, int flags);

/* Returns a quoted version of the given string. */
const char *pr_str_quote(pool *p, const char *str);

/* Newer version of sreplace(), with more control and better error reporting. */
const char *pr_str_replace(pool *, unsigned int, const char *, ...);
const char *pr_str_strip(pool *, const char *);
char *pr_str_strip_end(char *, const char *);
int pr_str_get_nbytes(const char *, const char *, off_t *);
char *pr_str_get_word(char **, int);

/* Parses a "time string" into its duration, in seconds.  Returns the number
 * of seconds obtained via the `duration' pointer, or -1 (with errno) if
 * there was a problem parsing the provided string.
 *
 * A "time string" is formatted as "hh:mm:ss".
 */
int pr_str_get_duration(const char *str, int *duration);

/* Encode the given buffer of binary data as a hex string.  The flags indicate
 * whether to use uppercase or lowercase hex values; the default is to use
 * lowercase values.
 *
 * Returns NULL on error, or the successfully encoded string, allocated out of
 * the given pool, on success.
 */
char *pr_str_bin2hex(pool *p, const unsigned char *buf, size_t len, int flags);
#define PR_STR_FL_HEX_USE_UC			0x0001
#define PR_STR_FL_HEX_USE_LC			0x0002

/* Decodes the given buffer of hex-encoded data into binary data. */
unsigned char *pr_str_hex2bin(pool *p, const unsigned char *hex, size_t hex_len,
  size_t *len);

/* Obtain the Levenshtein distance between the two strings.  The various
 * operations (swap, substitution, insertion, deletion) can be weighted.
 */
int pr_str_levenshtein(pool *p, const char *a, const char *b,
  int swap_cost, int subst_cost, int insert_cost, int del_cost, int flags);

/* Given a string and a list of possibly similar candidates, return an
 * array of the candidates, sorted in order of Levenshtein distance (ascending).
 * A maximum edit distance can be used to return the most relevant subset of
 * the candidates; if a max distance of zero is used, the default max distance
 * value will be used.
 */
array_header *pr_str_get_similars(pool *p, const char *s,
  array_header *candidates, int max_distance, int flags);
#define PR_STR_DEFAULT_MAX_EDIT_DISTANCE		7

/* Given a string delimited by a character (such as comma or pipe), return
 * an array of each item.
 */
array_header *pr_str_text_to_array(pool *p, const char *text, char delimiter);

/* Converts a string to a uid_t/gid_t, respectively. */
int pr_str2uid(const char *, uid_t *);
int pr_str2gid(const char *, gid_t *);

/* Converts a uid_t/gid_t to a string, respectively */
const char *pr_uid2str(pool *, uid_t);
const char *pr_gid2str(pool *, gid_t);

#define PR_STR_FL_PRESERVE_COMMENTS		0x0001
#define PR_STR_FL_PRESERVE_WHITESPACE		0x0002
#define PR_STR_FL_IGNORE_CASE			0x0004

char *pr_str_get_token(char **, char *);
char *pr_str_get_token2(char **, char *, size_t *);

/* Returns TRUE if the given string is "on", "yes", "true", or "1"; returns
 * FALSE if the string is "off", "false", "no", or "0".  Otherwise, -1
 * is returned, with errno set to EINVAL.
 */
int pr_str_is_boolean(const char *);

int pr_str_is_fnmatch(const char *);

#define CHOP(s)		pr_str_strip_end((s), "\r\n")

#endif /* PR_STR_H */
