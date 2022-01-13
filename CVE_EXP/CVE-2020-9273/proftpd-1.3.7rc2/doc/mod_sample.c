/*
 * The following is an *EXAMPLE* ProFTPD module.  While it can be compiled
 * in to ProFTPD, it is not by default, and doesn't really do anything all
 * that terribly functional.
 */

/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2016 The ProFTPD Project team
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

/* Sample module for ProFTPD */

#include "conf.h"

#define MOD_SAMPLE_VERSION		"mod_sample/0.0"

/* Command handlers
 */

/* Example of a PRE_CMD handler here, which simply logs all received
 * commands via pr_log_debug().  We are careful to return PR_DECLINED,
 * otherwise other PRE_CMD handlers would not get the request.  Note that in
 * order for this to work properly, this module would need to be loaded _last_,
 * or after any other modules which don't return PR_DECLINED for all
 * their precmds.  In practice you should always return PR_DECLINED unless
 * you plan on having your module actually handle the command (or deny it).
 */
MODRET sample_pre_any(cmd_rec *cmd) {
  pr_log_debug(DEBUG0, "RECEIVED: command '%s', arguments '%s'.",
    cmd->argv[0], cmd->arg);

  return PR_DECLINED(cmd);
}

/* Next, an example of a LOG_CMD handler, which receives all commands
 * _after_ they have been processed, and additional only IF they were
 * successful.
 */
MODRET sample_log_any(cmd_rec *cmd) {
  pr_log_debug(DEBUG0, "SUCCESSFUL: command '%s', arguments '%s'.",
    cmd->argv[0], cmd->arg);

  return PR_DECLINED(cmd);
}

/* Now, a _slightly_ more useful handler.  We define POST_CMD handlers
 * for RETR, STOR and LIST/NLST, so we can calculate total data transfer
 * for a session.
 */
static unsigned long total_rx = 0, total_tx = 0;

MODRET sample_post_retr(cmd_rec *cmd) {

  /* The global variable 'session' contains lots of important data after
   * a file/directory transfer of any kind.  It doesn't get cleared until
   * mod_xfer gets a LOG_CMD, so we can still get to it here.
   */
  total_tx += session.xfer.total_bytes;

  return PR_DECLINED(cmd);
}

MODRET sample_post_stor(cmd_rec *cmd) {
  total_rx += session.xfer.total_bytes;
  return PR_DECLINED(cmd);
}

MODRET sample_post_list(cmd_rec *cmd) {
  return sample_post_retr(cmd);
}

MODRET sample_post_nlst(cmd_rec *cmd) {
  return sample_post_retr(cmd);
}

/* This command handler is for a non-standard FTP command, "XFOO".  It
 * illustrates how one can write a module that handles such non-standard
 * commands.
 */
MODRET sample_xfoo(cmd_rec *cmd) {
  char *path = NULL;

  if (cmd->argc < 2) {
    pr_response_add_err(R_500, "XFOO command needs at least one argument");
    return PR_ERROR(cmd);
  }

  /* We call pr_fs_decode_path() on the argument here, assuming that the
   * argument to this fictional XFOO command is indeed a path.  RFC2640
   * states that clients can encode paths as UTF8 strings; the
   * pr_fs_decode_path() function converts from UTF8 strings to the local
   * character set.
   */
  path = dir_realpath(cmd->tmp_pool,
    pr_fs_decode_path(cmd->tmp_pool, cmd->arg));

  if (!path) {
    pr_response_add_err(R_500, "It appears that '%s' does not exist",
      cmd->arg);
    return PR_ERROR(cmd);
  }

  pr_response_add_err(R_200, "XFOO command successful (yeah right!)");
  return PR_HANDLED(cmd);
}

/* Configuration handlers 
 */

/* This sample configuration directive handler will get called
 * whenever the "FooBarDirective" directive is encountered in the
 * configuration file.
 */

MODRET set_foobardirective(cmd_rec *cmd) {
  int bool = 1;
  config_rec *c = NULL;

  /* The CHECK_ARGS macro checks the number of arguments passed to the
   * directive against what we want.  Note that this is *one* less than
   * cmd->argc, because cmd->argc includes cmd->argv[0] (the directive
   * itself).  If CHECK_ARGS fails, a generic error is sent to the user
   */
  CHECK_ARGS(cmd, 1);

  /* The CHECK_CONF macro makes sure that this directive is not being
   * "used" in the wrong context (i.e. if the directive is only available
   * or applicable inside certain contexts).  In this case, we are allowing
   * the directive inside of <Anonymous> and <Limit>, but nowhere else.
   * If this macro fails a generic error is logged and the handler aborts.
   */
  CHECK_CONF(cmd, CONF_ANON|CONF_LIMIT);

  /* Get the Boolean value of the first directive parameter. */
  bool = get_boolean(cmd, 1);
  if (bool == -1) {

    /* The get_boolean() function returns -1 if the parameter was not a
     * recognized Boolean parameter.
     */
    CONF_ERROR(cmd, "requires a Boolean parameter");
  }

  /* add_config_param() adds a configuration parameter record to our current
   * configuration context.  We're initially setting the value stored in
   * the config_rec to be NULL, so that we can allocate memory of the
   * proper size for storing the Boolean value.
   */
  c = add_config_param(cmd->argv[0], 1, NULL);

  /* Allocate space for the Boolean value.  The smallest data type in C
   * is an unsigned char (1 byte), and a Boolean will easily fit within
   * that space.
   */
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned char));
  *((unsigned char *) c->argv[0]) = bool;

  /* By adding the CF_MERGEDOWN flag to the parameter we just created
   * we are telling proftpd that this parameter should be copied and
   * "merged" into all "lower" contexts until it either hits a
   * parameter w/ the same name or bottoms out.
   *
   * Example _without_ CF_MERGEDOWN:
   *
   * <VirtualHost>
   *      |----------\
   *             <Anonymous>
   *                 | - FooBarDirective  <------- Config places it here
   *                 |-----------\
   *                         <Directory>  <------- Doesn't apply here
   *                             |-------------\
   *                                        <Limit> <--- Or here.....
   *
   * Now, if we specify CF_MERGDOWN, the tree ends up looking like:
   *
   * <VirtualHost>
   *      |----------\
   *             <Anonymous>
   *                 | - FooBarDirective  <------- Config places it here
   *                 |-----------\
   *                         <Directory>  <------- Now, it DOES apply here
   *                             | - FooBarDirective
   *                             |-------------\
   *                                        <Limit> <-------- And here ...
   *                                           | - FooBarDirective
   *
   */

  c->flags |= CF_MERGEDOWN;

  /* Tell proftpd that we handled the request w/ no problems.
   */
  return PR_HANDLED(cmd);
}

/* Initialization routines
 */

/* Each module can supply up to two initialization routines (via
 * the module structure at the bottom of this file).  The first
 * init function is called immediately after the module is loaded,
 * while the second is called after proftpd is connected to a client,
 * and the main proftpd server (if not in inetd mode) has forked off.
 * The second init function's purpose is to let the module perform
 * any necessary work for initializing a session, once a client is connected
 * and the daemon is ready to service the new client.  In inetd mode, the
 * session initialization function will be called immediately after proftpd is
 * loaded, because proftpd is _always_ in "child mode" when run from inetd.
 * Note that both of these initialization routines are optional.  If you don't
 * need them (or only need one), simply set the function pointer to NULL
 * in the module structure.
 */

static int sample_init(void) {
  /* do something useful here, right? */

  return 0;
}

static int sample_sess_init(void) {
  /* same here */

  return 0;
}

/* Module API tables
 *
 * There are three tables which act as the "glue" between proftpd and
 * a module.  None of the tables are _required_ (however having none would
 * make the module fairly useless).
 *
 * The first table is the configuration directive handler table.  It specifies
 * handler routines in the module which will be used during configuration
 * file parsing.
 */

static conftable sample_conftab[] = {
  { "FooBarDirective",		set_foobardirective,	NULL },
  { NULL }
};

/* The command handler table:
 * first  : command "type" (see the doc/API for more info)
 *
 * second : command "name", or the actual null-terminated ascii text
 *          sent by a client (in uppercase) for this command.  see
 *          include/ftp.h for macros which define all rfced FTP protocol
 *          commands.  Can also be the special macro C_ANY, which receives
 *          ALL commands.
 *
 * third  : command "group" (used for access control via Limit directives),
 *          this can be either G_DIRS (for commands related to directory
 *          listing), G_READ (for commands related to reading files), 
 *          G_WRITE (for commands related to file writing), or the
 *          special G_NONE for those commands against which the
 *          special <Limit READ|WRITE|DIRS> will not be applied.
 *
 * fourth : function pointer to your handler
 *
 * fifth  : TRUE if the command cannot be used before authentication
 *          (via USER/PASS), otherwise FALSE.
 *
 * sixth  : TRUE if the command can be sent during a file transfer
 *          (note: as of 1.1.5, this is obsolete)
 *
 */

static cmdtable sample_cmdtab[] = {
  { PRE_CMD,	C_ANY,	G_NONE, sample_pre_any,		FALSE, FALSE },
  { LOG_CMD,	C_ANY,	G_NONE, sample_log_any, 	FALSE, FALSE },
  { POST_CMD,	C_RETR, G_NONE, sample_post_retr,	FALSE, FALSE },
  { POST_CMD,	C_STOR,	G_NONE, sample_post_stor,	FALSE, FALSE },
  { POST_CMD,	C_APPE, G_NONE, sample_post_stor,	FALSE, FALSE },
  { POST_CMD,	C_LIST,	G_NONE,	sample_post_list,	FALSE, FALSE },
  { POST_CMD,	C_NLST, G_NONE, sample_post_nlst,	FALSE, FALSE },
  { CMD,	"XFOO",	G_DIRS,	sample_xfoo,		TRUE,  FALSE },
  { 0,		NULL }
};

module sample_module = {

  /* Always NULL */
  NULL, NULL,

  /* Module API version (2.0) */
  0x20,

  /* Module name */
  "sample",

  /* Module configuration directive handlers */
  sample_conftab,

  /* Module command handlers */
  sample_cmdtab,

  /* Module authentication handlers (none in this case) */
  NULL,

  /* Module initialization */
  sample_init,

  /* Session initialization */
  sample_sess_init,

  /* Module version */
  MOD_SAMPLE_VERSION
};
