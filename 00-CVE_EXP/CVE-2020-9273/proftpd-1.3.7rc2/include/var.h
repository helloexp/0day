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

/* Variables API definition */

#ifndef PR_VAR_H
#define PR_VAR_H

/* Deletes the named variable from the Variables table.  Returns 0 on
 * success, -1 on failure (e.g. the given variable was not in the table).
 */
int pr_var_delete(const char *name);

/* Returns TRUE if the given variable name exists in the Variables table,
 * FALSE if not.  A return value of -1 indicates an error, in which case
 * errno will be set appropriately.
 */
int pr_var_exists(const char *name);

/* Return the string associated with the given variable name.  Returns NULL
 * if there was an error, such as no matching value set for the given name,
 * or no string set for that variable.
 */
const char *pr_var_get(const char *name);

/* Returns the next name in the Variables table; NULL is returned if there
 * are no more variable names to return.  If desc is not NULL, it will be set
 * to the description associated with the given variable.  This function is
 * primarily for use in iterating through the current list of registered
 * names, for informational purposes.
 */
const char *pr_var_next(const char **desc);

/* Rewinds the iterator used by pr_var_next() to the start of the list.
 */
void pr_var_rewind(void);

/* Set a value to be associated with the given variable name.  Variable
 * names MUST start with a '%' character.  Variable names associated with
 * contributed/third-party modules should be of the format "%{name}".  The
 * core proftpd engine reserves the non-"%{var}" syntax for future use.
 *
 * A descriptive string can also be given, as a sort of informative label for
 * the purpose of the variable being set.
 *
 * The type of value being set must be indicated.  A type of PR_VAR_TYPE_STR
 * indicates that val should be handled as a NUL-terminated string.
 * The PR_VAR_TYPE_FUNC type indicates that val is a function pointer,
 * implementing "virtual" strings.  The function prototype for a
 * PR_VAR_TYPE_FUNC val is:
 *
 *  const char *(*func)(void *data, size_t datasz);
 *
 * If not NULL, the data and datasz parameters will be passed to the function
 * pointer/callbacks.  These parameters not useful when setting plain strings
 * or numbers.
 *
 * The values associated with the given name are kept in memory allocated
 * from the given pool; it is therefore the caller's responsibility to
 * make sure the pool used has a sufficient lifetime for retaining the
 * values for use by consumers of the Variables API.
 *
 * If there is a value already associated with the given name, its value
 * is overwritten with the given values.  The pr_var_exists() function can
 * be used to detect this case.  The pr_var_delete() function is used
 * to explicitly remove variables from the table.  However, since the memory
 * is allocated from the pool of the caller of pr_var_set(), deleting
 * a variable from the table does not free that memory; it is the
 * pr_var_set() caller's responsibility to recover memory.
 *
 * Returns -1 if there was an error processing the arguments (e.g. an
 * invalid type, NULL pool, name, or value, or if val is non-NULL but datasz
 * is zero).
 */
int pr_var_set(pool *p, const char *name, const char *desc,
  int type, void *val, void *data, size_t datasz);
#define PR_VAR_TYPE_STR         1
#define PR_VAR_TYPE_FUNC        2

int var_init(void);
int var_free(void);

#endif /* PR_VAR_H */
