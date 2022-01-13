/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2014-2016 The ProFTPD Project team
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

/* Configuration database API. */

#ifndef PR_CONFIGDB_H
#define PR_CONFIGDB_H

#include "pool.h"
#include "sets.h"
#include "table.h"

typedef struct config_struc config_rec;
struct server_struc;

struct config_struc {
  struct config_struc *next, *prev;

  int config_type;
  unsigned int config_id;

  struct pool_rec *pool;	/* Memory pool for this object */
  xaset_t *set;			/* The set we are stored in */
  char *name;
  unsigned int argc;
  void **argv;

  long flags;			/* Flags */

  struct server_struc *server;	/* Server this config element is attached to */
  config_rec *parent;		/* Our parent configuration record */
  xaset_t *subset;		/* Sub-configuration */
};

#define CONF_ROOT		(1 << 0) /* No conf record */
#define CONF_DIR		(1 << 1) /* Per-Dir configuration */
#define CONF_ANON		(1 << 2) /* Anon. FTP configuration */
#define CONF_LIMIT		(1 << 3) /* Limits commands available */
#define CONF_VIRTUAL		(1 << 4) /* Virtual host */
#define CONF_DYNDIR		(1 << 5) /* .ftpaccess file */
#define CONF_GLOBAL		(1 << 6) /* "Global" context (applies to main server and ALL virtualhosts */
#define CONF_CLASS		(1 << 7) /* Class context */
#define CONF_NAMED		(1 << 8) /* Named virtual host */
#define CONF_USERDATA		(1 << 14) /* Runtime user data */
#define CONF_PARAM		(1 << 15) /* config/args pair */

/* config_rec flags */
#define CF_MERGEDOWN		(1 << 0) /* Merge option down */
#define CF_MERGEDOWN_MULTI	(1 << 1) /* Merge down, allowing multiple instances */
#define CF_DYNAMIC		(1 << 2) /* Dynamically added entry */
#define CF_DEFER		(1 << 3) /* Defer hashing until authentication */
#define CF_SILENT		(1 << 4) /* Do not print a config dump when merging */
#define CF_MULTI		(1 << 5) /* Allow multiple instances, but do not merge down */

/* The following macro determines the "highest" level available for
 * configuration directives.  If a current dir_config is available, it's
 * subset is used, otherwise anon config or main server
 */

#define CURRENT_CONF		(session.dir_config ? session.dir_config->subset \
				 : (session.anon_config ? session.anon_config->subset \
                                    : main_server ? main_server->conf : NULL))
#define TOPLEVEL_CONF		(session.anon_config ? session.anon_config->subset : (main_server ? main_server->conf : NULL))

/* Prototypes */

config_rec *add_config_set(xaset_t **, const char *);
config_rec *add_config(struct server_struc *, const char *);
config_rec *add_config_param(const char *, unsigned int, ...);
config_rec *add_config_param_str(const char *, unsigned int, ...);
config_rec *add_config_param_set(xaset_t **, const char *, unsigned int, ...);
config_rec *pr_conf_add_server_config_param_str(struct server_struc *,
  const char *, unsigned int, ...);

/* Flags used when searching for specific config_recs in the in-memory
 * config database, particularly when 'recurse' is TRUE.
 */
#define PR_CONFIG_FIND_FL_SKIP_ANON		0x001
#define PR_CONFIG_FIND_FL_SKIP_DIR		0x002
#define PR_CONFIG_FIND_FL_SKIP_LIMIT		0x004
#define PR_CONFIG_FIND_FL_SKIP_DYNDIR		0x008

config_rec *find_config_next(config_rec *, config_rec *, int,
  const char *, int);
config_rec *find_config_next2(config_rec *, config_rec *, int,
  const char *, int, unsigned long);
config_rec *find_config(xaset_t *, int, const char *, int);
config_rec *find_config2(xaset_t *, int, const char *, int, unsigned long);
void find_config_set_top(config_rec *);

int remove_config(xaset_t *set, const char *name, int recurse);

#define PR_CONFIG_FL_INSERT_HEAD	0x001
#define PR_CONFIG_FL_PRESERVE_ENTRY	0x002
config_rec *pr_config_add_set(xaset_t **, const char *, int);
config_rec *pr_config_add(struct server_struc *, const char *, int);
int pr_config_remove(xaset_t *set, const char *name, int flags, int recurse);

/* Returns the assigned ID for the provided directive name, or zero
 * if no ID mapping was found.
 */
unsigned int pr_config_get_id(const char *name);

/* Assigns a unique ID for the given configuration directive.  The
 * mapping of directive to ID is stored in a lookup table, so that
 * searching of the config database by directive name can be done using
 * ID comparisons rather than string comparisons.
 *
 * Returns the ID assigned for the given directive, or zero if there was an
 * error.
 */
unsigned int pr_config_set_id(const char *name);

void *get_param_ptr(xaset_t *, const char *, int);
void *get_param_ptr_next(const char *, int);

void pr_config_merge_down(xaset_t *, int);
void pr_config_dump(void (*)(const char *, ...), xaset_t *, char *);

/* Internal use only. */
void init_config(void);

#endif /* PR_CONFIGDB_H */
