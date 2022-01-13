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

/* ProFTPD module definitions. */

#ifndef PR_MODULES_H
#define PR_MODULES_H

typedef struct module_struc	module;
typedef struct modret_struc	modret_t;

struct modret_struc {
  module *mr_handler_module;		/* which module handled this? */
  int mr_error;				/* !0 if error */
  const char *mr_numeric;		/* numeric error code */
  const char *mr_message;		/* text message */
  void *data;				/* add'l data -- undefined */
};

/* The following macros are for creating basic modret_t, and can
 * only be used inside of module handlers
 */

#define MODRET				static modret_t*
#define PR_HANDLED(cmd)			mod_create_ret((cmd),\
					0,NULL,NULL)
#define PR_DECLINED(cmd)		(modret_t*)NULL
#define PR_ERROR(cmd)			mod_create_ret((cmd),\
					1,NULL,NULL)
#define PR_ERROR_MSG(cmd,n,m)		mod_create_ret((cmd),\
					1,(n),(m))
#define PR_ERROR_INT(cmd,n)		mod_create_error((cmd),(n))

#define MODRET_ISDECLINED(x)		((x) == NULL)
#define MODRET_ISHANDLED(x)		((x) && !(x)->mr_error)
#define MODRET_ISERROR(x)		((x) && (x)->mr_error)
#define MODRET_HASNUM(x)		((x) && (x)->mr_numeric)
#define MODRET_HASMSG(x)		((x) && (x)->mr_message)
#define MODRET_ERROR(x)			((x) ? (x)->mr_error : 0)
#define MODRET_ERRNUM(x)		((x) ? (x)->mr_numeric : NULL)
#define MODRET_ERRMSG(x)		((x) ? (x)->mr_message : NULL)
#define MODRET_HASDATA(x)		((x) ? ((x)->data ? TRUE : FALSE) : FALSE)

typedef struct conftab_rec {
  char *directive;
  modret_t *(*handler)(cmd_rec *);

  module *m;				/* Reference to owning module
					 * set when module is initialized
					 */

} conftable;

/* Classes of commands.  These are used as logging categories as well. */
#define CL_NONE		0x0000
#define CL_AUTH		0x0001  /* USER, PASS */
#define CL_INFO		0x0002  /* Informational commands (PWD, SYST, etc) */
#define CL_DIRS		0x0004  /* Directory commands (LIST, NLST, CWD, etc) */
#define CL_READ		0x0008  /* File reading commands (RETR) */
#define CL_WRITE	0x0010  /* Writing commands (STOR, MKD, etc) */
#define CL_MISC		0x0020  /* Miscellaneous (RNFR/RNTO, SITE, etc) */
#define CL_SEC		0x0040  /* RFC2228 Security commands */
#define CL_CONNECT	0x0080  /* Session start */
#define CL_DISCONNECT	0x0100  /* Session end */
#define CL_SSH		0x0200  /* SSH requests */
#define CL_SFTP		0x0400  /* SFTP requests */

/* Note that CL_ALL explicitly does NOT include CL_DISCONNECT; this is to
 * preserve backward compatible behavior.
 */
#define CL_ALL\
  (CL_AUTH|CL_INFO|CL_DIRS|CL_READ|\
   CL_WRITE|CL_MISC|CL_SEC|CL_SSH|CL_SFTP)

/* Command handler types for command table */
#define PRE_CMD				1
#define CMD				2
#define POST_CMD			3
#define POST_CMD_ERR			4
#define LOG_CMD				5
#define LOG_CMD_ERR			6
#define HOOK				7

typedef struct cmdtab_rec {

  /* See above for cmd types. */
  unsigned char cmd_type;
  const char *command;

  /* Command group. */
  const char *group;
  modret_t *(*handler)(cmd_rec *);

  /* Does this command require authentication? */
  unsigned char requires_auth;

  /* Can this command be issued during a transfer? (Now obsolete) */
  unsigned char interrupt_xfer;

  int cmd_class;
  module *m;

} cmdtable;

typedef struct authtab_rec {
  int auth_flags;			/* future use */
  const char *name;
  modret_t *(*handler)(cmd_rec *);

  module *m;
} authtable;

#define PR_AUTH_FL_REQUIRED		0x00001

struct module_struc {
  module *next, *prev;

  int api_version;			/* API version _not_ module version */
  const char *name;			/* Module name */

  struct conftab_rec *conftable;	/* Configuration directive table */
  struct cmdtab_rec *cmdtable;		/* Command table */
  struct authtab_rec *authtable; 	/* Authentication handler table */

  int (*init)(void); 			/* Module initialization */
  int (*sess_init)(void);		/* Session initialization */

  const char *module_version;		/* Module version */
  void *handle;				/* Module handle */

  /* Internal use; high number == higher priority. */
  int priority;
};

#define ANY_MODULE			((module*)0xffffffff)

/* Prototypes */

unsigned char command_exists(const char *);
int modules_init(void);
void modules_list(int flags);
void modules_list2(int (*listf)(const char *, ...), int flags);
#define PR_MODULES_LIST_FL_SHOW_VERSION		0x00001
#define PR_MODULES_LIST_FL_SHOW_STATIC		0x00002

int modules_session_init(void);

unsigned char pr_module_exists(const char *);
module *pr_module_get(const char *);
int pr_module_load(module *m);
int pr_module_unload(module *m);

/* Load the various symbol tables from this module. */
int pr_module_load_authtab(module *m);
int pr_module_load_cmdtab(module *m);
int pr_module_load_conftab(module *m);

modret_t *pr_module_call(module *, modret_t *(*)(cmd_rec *), cmd_rec *);

/* This function is in main.c, but is prototyped here */
void set_auth_check(int (*ck)(cmd_rec *));

/* This callback is defined/stored in src/main.c */
extern int (*cmd_auth_chk)(cmd_rec *);

/* For use from inside module handler functions */
modret_t *mod_create_ret(cmd_rec *, unsigned char, const char *, const char *);
modret_t *mod_create_error(cmd_rec *, int);
modret_t *mod_create_data(cmd_rec *, void *);

/* Implemented in mod_core.c */
int core_chgrp(cmd_rec *, const char *, uid_t, gid_t);
int core_chmod(cmd_rec *, const char *, mode_t);

#endif /* PR_MODULES_H */
