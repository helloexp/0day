/*
 * ProFTPD - FTP server daemon
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

/* Controls API definitions */

#ifndef PR_CTRLS_H
#define PR_CTRLS_H

#include <sys/un.h>

#include "conf.h"

/* Controls API build-time necessities
 */

/* mode for control socket */
#define PR_CTRLS_MODE		0777

/* mode for client sockets */
#define PR_CTRLS_CL_MODE	S_IRWXU

/* Controls API objects
 */

/* Controls client object */
typedef struct cl_obj {
  struct cl_obj *cl_next, *cl_prev;

  /* Pool for this object's use */
  pool *cl_pool;

  /* Client socket file descriptor */
  int cl_fd;

  /* Credentials of the connecting client */
  uid_t cl_uid;
  const char *cl_user;
  gid_t cl_gid;
  const char *cl_group;
  pid_t cl_pid;

  /* For internal use only */
  volatile unsigned long cl_flags;

  /* Pointers to all controls matching client request */
  array_header *cl_ctrls;

} pr_ctrls_cl_t;

/* Controls client flag values
 */
#define PR_CTRLS_CL_HAVEREQ     0x001
#define PR_CTRLS_CL_HAVERESP    0x002
#define PR_CTRLS_CL_NOACCESS    0x004
#define PR_CTRLS_CL_NOACTION    0x010
#define PR_CTRLS_CL_BLOCKED     0x020

/* Controls handler object */
typedef struct ctrls_obj {
  struct ctrls_obj *ctrls_next, *ctrls_prev;

  /* Object ID */
  unsigned int ctrls_id;

  /* Registering module */
  const module *ctrls_module;

  /* Requesting client */
  pr_ctrls_cl_t *ctrls_cl;

  /* Control "action" */
  const char *ctrls_action;
 
  /* Control trigger time.  If 0, triggers immediately */
  time_t ctrls_when;

  /* Simple description/help text */
  const char *ctrls_desc;

  /* Temporary pool */
  pool *ctrls_tmp_pool;

  /* Control handler callback */
  int (*ctrls_cb)(struct ctrls_obj *, int, char **);

  /* Control handler callback arguments */
  array_header *ctrls_cb_args;

  /* Control handler callback return value.  Used to determine when to clear
   * this object from the requested list
   */
  int ctrls_cb_retval;

  /* Control handler callback responses */
  array_header *ctrls_cb_resps;

  /* For possibly passing data among control handlers */
  void *ctrls_data;

  /* For internal use */
  volatile unsigned long ctrls_flags;

} pr_ctrls_t;

#define PR_CTRLS_REQUESTED		0x00001
#define PR_CTRLS_HANDLED		0x00002
#define PR_CTRLS_PENDING		0x00004

#define PR_CTRLS_ACT_SOLITARY		0x00010
#define PR_CTRLS_ACT_DISABLED		0x00020

#define CTRLS_GET_ACTION_ALL		7
#define CTRLS_GET_ACTION_ENABLED	8
#define CTRLS_GET_DESC			9

/* Controls API prototypes
 */

/* Register a control handler for the given action with the Controls layer,
 * to be available to requesting clients.  Returns the ID of the registered
 * handler, or -1 if there was an error.
 */
int pr_ctrls_register(const module *mod, const char *action,
  const char *desc, int (*ctrls_cb)(pr_ctrls_t *, int, char **));

/* Unregisters any control handlers that match the given module/action pair.
 * If the module argument is null, then the specified action for all modules
 * is unregistered.  If the action argument is null, then all actions for the
 * specified module are unregistered.
 *
 * Returns 0 on success, -1 on failure.
 */
int pr_ctrls_unregister(module *mod, const char *action);

/* Add the given ctrls_arg string to the pr_ctrls_t object's argument
 * array. Returns 0 on success, -1 on failure.
 */
int pr_ctrls_add_arg(pr_ctrls_t *ctrl, char *ctrls_arg, size_t ctrls_arglen);

/* Add the given string to the pr_ctrls_t object's response array.  Returns
 * 0 on success, -1 on failure.  Control handlers can use this function to
 * add a text response to be returned to the requesting client.
 */
int pr_ctrls_add_response(pr_ctrls_t *ctrl, char *fmt, ...)
#ifdef __GNUC__
       __attribute__ ((format (printf, 2, 3)));
#else
       ;
#endif

/* Meant for use in opening a client control socket, by ftpdctl and core 
 * routines.  Connects to the control socket, and returns the socket descriptor
 * opened, or -1 if there was an error.
 */
int pr_ctrls_connect(const char *socket_file);

int pr_ctrls_copy_args(pr_ctrls_t *src_ctrl, pr_ctrls_t *dest_ctrl);

int pr_ctrls_copy_resps(pr_ctrls_t *src_ctrl, pr_ctrls_t *dest_ctrl);

/* Flush any responses added to the pr_ctrls_t out the client.  This should
 * only be used when the control handler will not return (as when it is
 * going to end the process then and there).  Returns -1 with errno set to
 * EINVAL if the given pointer is NULL, EPERM if unable to flush the responses
 * out to the client.  Returns 0 on success.
 */
int pr_ctrls_flush_response(pr_ctrls_t *ctrl);

/* Parses the given string into the argc, argv pointers, creating inputs
 * suitable for passing to pr_ctrls_send_msg().  The argv array of strings
 * is allocated from the given pool.  Provided as a utility function.
 * Returns -1 on error, 0 if successful.
 */
int pr_ctrls_parse_msg(pool *msg_pool, char *msg, unsigned int *msgargc,
  char ***msgargv);

/* Reads a client control request from the given client.  Returns -1 with errno
 * set to EOF if there is nothing to read from the client socket, or errno set
 * to the appropriate error for other problems. Returns 0 on success.
 */
int pr_ctrls_recv_request(pr_ctrls_cl_t *cl);

/* respargv can be NULL, as when the client does not care to know the
 * response messages, just that a response was successfully received.
 * Returns respargc, or -1 if there was an error.
 */
int pr_ctrls_recv_response(pool *resp_pool, int ctrls_sockfd, int *status,
  char ***respargv);

/* Useful for core routines that themselves want to send a control message
 */
int pr_ctrls_send_msg(int sockfd, int msgstatus, unsigned int msgargc,
  char **msgargv);

/* Determine whether the given socket mode is for a Unix domain socket.
 * Returns zero if true, -1 otherwise.
 */
int pr_ctrls_issock_unix(mode_t sock_mode);

/* Accept a Controls connection.  Returns the fd of the connected client
 * if successful, -1 (with errno set appropriately) otherwise.
 *
 * The optional uid, gid, and pid pointers, if provided, will be filled in
 * with the uid, gid, and pid of the connecting client process.  These can
 * be used e.g. for access control checks.  The max_age parameter specifies
 * the maximum age, in seconds, for the connecting client; this is used
 * for some types of credentials checking.
 */
int pr_ctrls_accept(int sockfd, uid_t *uid, gid_t *gid, pid_t *pid,
  unsigned int max_age);

int pr_get_registered_actions(pr_ctrls_t *ctrl, int flags);

int pr_set_registered_actions(module *mod, const char *action,
    unsigned char skip_disabled, unsigned int flags);

/* Blocks ctrls from being run. */
void pr_block_ctrls(void);

/* Unblocks ctrls from being run. */
void pr_unblock_ctrls(void);

/* XXX */
int pr_check_actions(void);

/* Iterate through the list of pr_ctrls_ts and invoke the callbacks of any
 * that match the given module and action arguments.  Returns 0 if successful,
 * -1 if error (eg controls are blocked).
 */
int pr_run_ctrls(module *mod, const char *action);

/* XXX */
int pr_reset_ctrls(void);

/* For internal use only. */
void init_ctrls(void);

#endif /* PR_CTRLS_H */
