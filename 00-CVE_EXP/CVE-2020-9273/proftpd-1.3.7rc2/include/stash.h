/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2010-2015 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project and other respective copyright
 * holders give permission to link this program with OpenSSL, and distribute
 * the resulting executable, without including the source code for OpenSSL in
 * the source distribution.
 */

/* ProFTPD symbol table hash ("stash") */

#ifndef PR_STASH_H
#define PR_STASH_H

typedef enum {
  PR_SYM_CONF = 1,
  PR_SYM_CMD,
  PR_SYM_AUTH,
  PR_SYM_HOOK
} pr_stash_type_t;

int pr_stash_add_symbol(pr_stash_type_t stash_type, void *sym);
void *pr_stash_get_symbol(pr_stash_type_t stash_type, const char *name,
  void *prev_sym, int *);
void *pr_stash_get_symbol2(pr_stash_type_t stash_type, const char *name,
  void *prev_sym, int *, unsigned int *);
int pr_stash_remove_symbol(pr_stash_type_t stash_type, const char *name,
  module *m);

/* These functions are similar to pr_stash_remove_symbol(), except that they
 * allow for providing type-specific criteria.
 */
int pr_stash_remove_conf(const char *directive_name, module *m);
int pr_stash_remove_cmd(const char *cmd_name, module *m,
  unsigned char cmd_type, const char *cmd_group, int cmd_class);
int pr_stash_remove_auth(const char *api_name, module *m);
int pr_stash_remove_hook(const char *hook_name, module *m);

void pr_stash_dump(void (*)(const char *, ...));

/* Internal use only */
int init_stash(void);

#endif /* PR_STASH_H */
