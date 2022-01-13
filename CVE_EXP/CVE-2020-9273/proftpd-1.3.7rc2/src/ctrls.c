/*
 * ProFTPD - FTP server daemon
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Controls API routines */

#include "conf.h"
#include "privs.h"

#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif /* !HAVE_UCRED_H */

#ifdef HAVE_SYS_UCRED_H
# include <sys/ucred.h>
#endif /* !HAVE_SYS_UCRED_H */

#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif /* !HAVE_SYS_UIO_H */

#ifdef PR_USE_CTRLS

#include "mod_ctrls.h"

/* Maximum number of request arguments. */
#define CTRLS_MAX_NREQARGS	32

/* Maximum number of response arguments. */
#define CTRLS_MAX_NRESPARGS	1024

/* Maximum length of a single request argument. */
#define CTRLS_MAX_REQARGLEN	256

typedef struct ctrls_act_obj {
  struct ctrls_act_obj *prev, *next;
  pool *pool;
  unsigned int id;
  const char *action;
  const char *desc;
  const module *module;
  volatile unsigned int flags;
  int (*action_cb)(pr_ctrls_t *, int, char **);
} ctrls_action_t;

static unsigned char ctrls_blocked = FALSE;

static pool *ctrls_pool = NULL;
static ctrls_action_t *ctrls_action_list = NULL;

static pr_ctrls_t *ctrls_active_list = NULL;
static pr_ctrls_t *ctrls_free_list = NULL;

static int ctrls_use_isfifo = FALSE;

static const char *trace_channel = "ctrls";

/* lookup/lookup_next indices */
static ctrls_action_t *action_lookup_next = NULL;
static const char *action_lookup_action = NULL;
static module *action_lookup_module = NULL;

/* Logging */
static int ctrls_logfd = -1;

/* necessary prototypes */
static ctrls_action_t *ctrls_action_new(void);
static pr_ctrls_t *ctrls_new(void);
static pr_ctrls_t *ctrls_lookup_action(module *, const char *, unsigned char);
static pr_ctrls_t *ctrls_lookup_next_action(module *, unsigned char);

static pr_ctrls_t *ctrls_prepare(ctrls_action_t *act) {
  pr_ctrls_t *ctrl = NULL;

  /* Sanity check */
  if (!act)
    return NULL;

  pr_block_ctrls();

  /* Get a blank ctrl object */
  ctrl = ctrls_new();

  /* Fill in the fields from the action object. */
  ctrl->ctrls_id = act->id;
  ctrl->ctrls_module = act->module;
  ctrl->ctrls_action = act->action;
  ctrl->ctrls_desc = act->desc;
  ctrl->ctrls_cb = act->action_cb;
  ctrl->ctrls_flags = act->flags;

  /* Add this to the "in use" list */
  ctrl->ctrls_next = ctrls_active_list;
  ctrls_active_list = ctrl;

  pr_unblock_ctrls();
  return ctrl;
}

static void ctrls_free(pr_ctrls_t *ctrl) {

  /* Make sure that ctrls are blocked while we're doing this */
  pr_block_ctrls();

  /* Remove this object from the active list */
  if (ctrl->ctrls_prev)
    ctrl->ctrls_prev->ctrls_next = ctrl->ctrls_next;

  else
    ctrls_active_list = ctrl->ctrls_next;

  if (ctrl->ctrls_next)
    ctrl->ctrls_next->ctrls_prev = ctrl->ctrls_prev;

  /* Clear its fields, and add it to the free list */
  ctrl->ctrls_next = NULL;
  ctrl->ctrls_prev = NULL;
  ctrl->ctrls_id = 0;
  ctrl->ctrls_module = NULL;
  ctrl->ctrls_action = NULL;
  ctrl->ctrls_cb = NULL;
  ctrl->ctrls_cb_retval = 1;
  ctrl->ctrls_flags = 0;

  if (ctrl->ctrls_tmp_pool) {
    destroy_pool(ctrl->ctrls_tmp_pool);
    ctrl->ctrls_tmp_pool = NULL;
  }

  ctrl->ctrls_cb_args = NULL;
  ctrl->ctrls_cb_resps = NULL;
  ctrl->ctrls_data = NULL;

  ctrl->ctrls_next = ctrls_free_list;
  ctrls_free_list = ctrl;

  pr_unblock_ctrls();
  return;
}

static ctrls_action_t *ctrls_action_new(void) {
  ctrls_action_t *act = NULL;
  pool *sub_pool = make_sub_pool(ctrls_pool);

  pr_pool_tag(sub_pool, "ctrls action subpool");
  act = pcalloc(sub_pool, sizeof(ctrls_action_t));
  act->pool = sub_pool;

  return act;
}

static pr_ctrls_t *ctrls_new(void) {
  pr_ctrls_t *ctrl = NULL;

  /* Check for a free ctrl first */
  if (ctrls_free_list) {

    /* Take one from the top */
    ctrl = ctrls_free_list;
    ctrls_free_list = ctrls_free_list->ctrls_next;

    if (ctrls_free_list)
      ctrls_free_list->ctrls_prev = NULL;

  } else {

    /* Have to allocate a new one. */
    ctrl = (pr_ctrls_t *) pcalloc(ctrls_pool, sizeof(pr_ctrls_t));

    /* It's important that a new ctrl object have the retval initialized
     * to 1; this tells the Controls layer that it is "pending", not yet
     * handled.
     */
    ctrl->ctrls_cb_retval = 1;
  }

  return ctrl;
}

static char *ctrls_sep(char **str) {
  char *ret = NULL, *dst = NULL;
  unsigned char quoted = FALSE;

  /* Sanity checks */
  if (!str || !*str || !**str)
    return NULL;

  while (**str && PR_ISSPACE(**str)) {
    (*str)++;
  }

  if (!**str)
    return NULL;

  ret = dst = *str;

  if (**str == '\"') {
    quoted = TRUE;
    (*str)++;
  }

  while (**str &&
         (quoted ? (**str != '\"') : !PR_ISSPACE(**str))) {

    if (**str == '\\' && quoted) {

      /* Escaped char */
      if (*((*str) + 1))
        *dst = *(++(*str));
    }

    *dst++ = **str;
    ++(*str);
  }

  if (**str)
    (*str)++;
  *dst = '\0';

  return ret;
}

int pr_ctrls_register(const module *mod, const char *action,
    const char *desc, int (*cb)(pr_ctrls_t *, int, char **)) {
  ctrls_action_t *act = NULL, *acti = NULL;
  unsigned int act_id = 0;

  /* sanity checks */
  if (action == NULL ||
      desc == NULL ||
      cb == NULL) {
    errno = EINVAL;
    return -1;
  }

  pr_trace_msg("ctrls", 3,
    "module '%s' registering handler for ctrl action '%s' (at %p)",
    mod ? mod->name : "(none)", action, cb);

  /* Block ctrls while we're doing this */
  pr_block_ctrls();

  /* Get a ctrl action object */
  act = ctrls_action_new();

  /* Randomly generate a unique random ID for this object */
  while (TRUE) {
    unsigned char have_id = FALSE;
    act_id = (unsigned int) pr_random_next(1L, RAND_MAX);

    /* Check the list for this ID */
    for (acti = ctrls_action_list; acti; acti = acti->next) {
      if (acti->id == act_id) {
        have_id = TRUE;
        break;
      }
    }

    if (!have_id)
      break;
  }

  act->next = NULL;
  act->id = act_id;
  act->action = pstrdup(ctrls_pool, action);
  act->desc = desc;
  act->module = mod;
  act->action_cb = cb;

  /* Add this to the list of "registered" actions */

  if (ctrls_action_list) {
    act->next = ctrls_action_list;
    ctrls_action_list->prev = act;
  }
  
  ctrls_action_list = act;

  pr_unblock_ctrls();

  return act_id;
}

int pr_ctrls_unregister(module *mod, const char *action) {
  ctrls_action_t *act = NULL;
  unsigned char have_action = FALSE;

  /* Make sure that ctrls are blocked while we're doing this */
  pr_block_ctrls();

  for (act = ctrls_action_list; act; act = act->next) {
    if ((action == NULL || strcmp(act->action, action) == 0) &&
        (act->module == mod || mod == ANY_MODULE || mod == NULL)) {
      have_action = TRUE;

      /* Remove this object from the list of registered actions */
      if (act->prev) {
        act->prev->next = act->next;

      } else {
        ctrls_action_list = act->next;
      }

      if (act->next) {
        act->next->prev = act->prev;
      }

      pr_trace_msg("ctrls", 3,
        "module '%s' unregistering handler for ctrl action '%s'",
        mod ? mod->name : "(none)", act->action);

      /* Destroy this action. */
      destroy_pool(act->pool); 
    }
  }
  
  pr_unblock_ctrls();

  if (!have_action) {
    errno = ENOENT;
    return -1;
  }

  return 0;
}

int pr_ctrls_add_arg(pr_ctrls_t *ctrl, char *ctrls_arg, size_t ctrls_arglen) {
  register unsigned int i;

  /* Sanity checks */
  if (ctrl == NULL ||
      ctrls_arg == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Scan for non-printable characters. */
  for (i = 0; i < ctrls_arglen; i++) {
    if (!PR_ISPRINT((int) ctrls_arg[i])) {
      errno = EPERM;
      return -1;
    }
  }

  /* Make sure the pr_ctrls_t has a temporary pool, from which the args will
   * be allocated.
   */
  if (ctrl->ctrls_tmp_pool == NULL) {
    ctrl->ctrls_tmp_pool = make_sub_pool(ctrls_pool);
    pr_pool_tag(ctrl->ctrls_tmp_pool, "ctrls tmp pool");
  }

  if (ctrl->ctrls_cb_args == NULL) {
    ctrl->ctrls_cb_args = make_array(ctrl->ctrls_tmp_pool, 0, sizeof(char *));
  }

  /* Add the given argument */
  *((char **) push_array(ctrl->ctrls_cb_args)) = pstrndup(ctrl->ctrls_tmp_pool,
    ctrls_arg, ctrls_arglen);

  return 0;
}

int pr_ctrls_copy_args(pr_ctrls_t *src_ctrl, pr_ctrls_t *dst_ctrl) {

  /* Sanity checks */
  if (src_ctrl == NULL ||
      dst_ctrl == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* If source ctrl has no ctrls_cb_args member, there's nothing to be
   * done.
   */
  if (src_ctrl->ctrls_cb_args == NULL) {
    return 0;
  }

  /* Make sure the pr_ctrls_t has a temporary pool, from which the args will
   * be allocated.
   */
  if (dst_ctrl->ctrls_tmp_pool == NULL) {
    dst_ctrl->ctrls_tmp_pool = make_sub_pool(ctrls_pool);
    pr_pool_tag(dst_ctrl->ctrls_tmp_pool, "ctrls tmp pool");
  }

  /* Overwrite any existing dst_ctrl->ctrls_cb_args.  This is OK, as
   * the ctrl will be reset (cleared) once it has been processed.
   */
  dst_ctrl->ctrls_cb_args = copy_array(dst_ctrl->ctrls_tmp_pool,
    src_ctrl->ctrls_cb_args);

  return 0;
}

int pr_ctrls_copy_resps(pr_ctrls_t *src_ctrl, pr_ctrls_t *dst_ctrl) {

  /* sanity checks */
  if (!src_ctrl || !dst_ctrl) {
    errno = EINVAL;
    return -1;
  }

  /* The source ctrl must have a ctrls_cb_resps member, and the destination
   * ctrl must not have a ctrls_cb_resps member.
   */
  if (!src_ctrl->ctrls_cb_resps || dst_ctrl->ctrls_cb_resps) {
    errno = EINVAL;
    return -1;
  }

  dst_ctrl->ctrls_cb_resps = copy_array(dst_ctrl->ctrls_tmp_pool,
    src_ctrl->ctrls_cb_resps);

  return 0;
}

int pr_ctrls_add_response(pr_ctrls_t *ctrl, char *fmt, ...) {
  char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'};
  va_list resp;

  /* Sanity check */
  if (!ctrl || !fmt) {
    errno = EINVAL;
    return -1;
  }

  /* Make sure the pr_ctrls_t has a temporary pool, from which the responses
   * will be allocated
   */
  if (!ctrl->ctrls_tmp_pool) {
    ctrl->ctrls_tmp_pool = make_sub_pool(ctrls_pool);
    pr_pool_tag(ctrl->ctrls_tmp_pool, "ctrls tmp pool");
  }

  if (!ctrl->ctrls_cb_resps)
    ctrl->ctrls_cb_resps = make_array(ctrl->ctrls_tmp_pool, 0,
      sizeof(char *));

  /* Affix the message */
  va_start(resp, fmt);
  pr_vsnprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), fmt, resp);
  va_end(resp);

  buf[sizeof(buf) - 1] = '\0';

  /* add the given response */
  *((char **) push_array(ctrl->ctrls_cb_resps)) =
    pstrdup(ctrl->ctrls_tmp_pool, buf);

  return 0;
}

int pr_ctrls_flush_response(pr_ctrls_t *ctrl) {

  /* Sanity check */
  if (!ctrl) {
    errno = EINVAL;
    return -1;
  }

  /* Make sure the callback(s) added responses */
  if (ctrl->ctrls_cb_resps) {
    if (pr_ctrls_send_msg(ctrl->ctrls_cl->cl_fd, ctrl->ctrls_cb_retval,
        ctrl->ctrls_cb_resps->nelts,
        (char **) ctrl->ctrls_cb_resps->elts) < 0)
      return -1;
  }

  return 0;
}

int pr_ctrls_parse_msg(pool *msg_pool, char *msg, unsigned int *msgargc,
    char ***msgargv) {
  char *tmp = msg, *str = NULL;
  pool *tmp_pool = NULL;
  array_header *msgs = NULL;

  /* Sanity checks */
  if (!msg_pool || !msgargc || !msgargv) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(msg_pool);

  /* Allocate an array_header, and push each space-delimited string
   * (respecting quotes and escapes) into the array.  Once done,
   * destroy the array.
   */
 
  msgs = make_array(tmp_pool, 0, sizeof(char *));

  while ((str = ctrls_sep(&tmp)) != NULL)
    *((char **) push_array(msgs)) = pstrdup(msg_pool, str);

  *msgargc = msgs->nelts;
  *msgargv = (char **) msgs->elts;

  destroy_pool(tmp_pool);

  return 0;
}

int pr_ctrls_recv_request(pr_ctrls_cl_t *cl) {
  pr_ctrls_t *ctrl = NULL, *next_ctrl = NULL;
  char reqaction[128] = {'\0'}, *reqarg = NULL;
  size_t reqargsz = 0;
  unsigned int nreqargs = 0, reqarglen = 0;
  int bread, status = 0;
  register unsigned int i = 0;

  if (cl == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (cl->cl_fd < 0) {
    errno = EBADF;
    return -1;
  }

  /* No interruptions */
  pr_signals_block();

  /* Read in the incoming number of args, including the action. */

  /* First, read the status (but ignore it).  This is necessary because
   * the same function, pr_ctrls_send_msg(), is used to send requests
   * as well as responses, and the status is a necessary part of a response.
   */
  bread = read(cl->cl_fd, &status, sizeof(int));
  if (bread < 0) {
    int xerrno = errno;

    pr_signals_unblock();

    errno = xerrno;
    return -1;
  }

  /* Watch for short reads. */
  if (bread != sizeof(int)) {
    (void) pr_trace_msg(trace_channel, 3,
      "short read (%d of %u bytes) of status, unable to receive request",
      bread, (unsigned int) sizeof(int));
    pr_signals_unblock();
    errno = EPERM;
    return -1;
  }
 
  /* Read in the args, length first, then string. */
  bread = read(cl->cl_fd, &nreqargs, sizeof(unsigned int));
  if (bread < 0) {
    int xerrno = errno;

    pr_signals_unblock();

    errno = xerrno;
    return -1;
  }

  /* Watch for short reads. */
  if (bread != sizeof(unsigned int)) {
    (void) pr_trace_msg(trace_channel, 3,
      "short read (%d of %u bytes) of nreqargs, unable to receive request",
      bread, (unsigned int) sizeof(unsigned int));
    pr_signals_unblock();
    errno = EPERM;
    return -1;
  }

  if (nreqargs > CTRLS_MAX_NREQARGS) {
    (void) pr_trace_msg(trace_channel, 3,
      "nreqargs (%u) exceeds max (%u), rejecting", nreqargs,
      CTRLS_MAX_NREQARGS);
    pr_signals_unblock();
    errno = ENOMEM;
    return -1;
  }

  /* Next, read in the requested number of arguments.  The client sends
   * the arguments in pairs: first the length of the argument, then the
   * argument itself.  The first argument is the action, so get the first
   * matching pr_ctrls_t (if present), and add the remaining arguments to it.
   */
  
  bread = read(cl->cl_fd, &reqarglen, sizeof(unsigned int));
  if (bread < 0) {
    int xerrno = errno;

    pr_signals_unblock();

    errno = xerrno;
    return -1;
  }

  /* Watch for short reads. */
  if (bread != sizeof(unsigned int)) {
    (void) pr_trace_msg(trace_channel, 3,
      "short read (%d of %u bytes) of reqarglen, unable to receive request",
      bread, (unsigned int) sizeof(unsigned int));
    pr_signals_unblock();
    errno = EPERM;
    return -1;
  }

  if (reqarglen >= sizeof(reqaction)) {
    pr_signals_unblock();
    errno = ENOMEM;
    return -1;
  }

  memset(reqaction, '\0', sizeof(reqaction));

  bread = read(cl->cl_fd, reqaction, reqarglen);
  if (bread < 0) {
    int xerrno = errno;

    pr_signals_unblock();

    errno = xerrno;
    return -1;
  }

  /* Watch for short reads. */
  if ((size_t) bread != reqarglen) {
    (void) pr_trace_msg(trace_channel, 3,
      "short read (%d of %u bytes) of reqaction, unable to receive request",
      bread, reqarglen);
    pr_signals_unblock();
    errno = EPERM;
    return -1;
  }

  reqaction[sizeof(reqaction)-1] = '\0';
  nreqargs--;

  /* Find a matching action object, and use it to populate a ctrl object,
   * preparing the ctrl object for dispatching to the action handlers.
   */
  ctrl = ctrls_lookup_action(NULL, reqaction, TRUE);
  if (ctrl == NULL) {
    pr_signals_unblock();

    /* XXX This is where we could also add "did you mean" functionality. */
    errno = EINVAL;
    return -1;
  }

  for (i = 0; i < nreqargs; i++) {
    memset(reqarg, '\0', reqargsz);

    bread = read(cl->cl_fd, &reqarglen, sizeof(unsigned int));
    if (bread < 0) {
      int xerrno = errno;

      pr_signals_unblock();

      errno = xerrno;
      return -1;
    }

    /* Watch for short reads. */
    if (bread != sizeof(unsigned int)) {
      (void) pr_trace_msg(trace_channel, 3,
        "short read (%d of %u bytes) of reqarglen (#%u), skipping",
        bread, i+1, (unsigned int) sizeof(unsigned int));
      continue;
    }

    if (reqarglen == 0) {
      /* Skip any zero-length arguments. */
      continue;
    }

    if (reqarglen > CTRLS_MAX_REQARGLEN) {
      (void) pr_trace_msg(trace_channel, 3,
        "reqarglen (#%u) of %u bytes exceeds max (%u bytes), rejecting",
        i+1, reqarglen, CTRLS_MAX_REQARGLEN);
      pr_signals_unblock();
      errno = ENOMEM;
      return -1;
    }

    /* Make sure reqarg is large enough to handle the given argument.  If
     * it is too small, allocate one of the necessary size.
     */

    if (reqargsz < reqarglen) {
      reqargsz = reqarglen + 1;

      if (!ctrl->ctrls_tmp_pool) {
        ctrl->ctrls_tmp_pool = make_sub_pool(ctrls_pool);
        pr_pool_tag(ctrl->ctrls_tmp_pool, "ctrls tmp pool");
      }

      reqarg = pcalloc(ctrl->ctrls_tmp_pool, reqargsz);
    }

    bread = read(cl->cl_fd, reqarg, reqarglen);
    if (bread < 0) {
      int xerrno = errno;

      pr_signals_unblock();

      errno = xerrno;
      return -1;
    }

    /* Watch for short reads. */
    if ((size_t) bread != reqarglen) {
      (void) pr_trace_msg(trace_channel, 3,
        "short read (%d of %u bytes) of reqarg (#%u), skipping",
        bread, i+1, reqarglen);
      continue;
    }

    if (pr_ctrls_add_arg(ctrl, reqarg, reqarglen)) {
      int xerrno = errno;

      pr_signals_unblock();

      errno = xerrno;
      return -1;
    }
  }

  /* Add this ctrls object to the client object. */
  *((pr_ctrls_t **) push_array(cl->cl_ctrls)) = ctrl;

  /* Set the flag that this control is ready to go */
  ctrl->ctrls_flags |= PR_CTRLS_REQUESTED;
  ctrl->ctrls_cl = cl;

  /* Copy the populated ctrl object args to ctrl objects for all other
   * matching action objects.
   */
  next_ctrl = ctrls_lookup_next_action(NULL, TRUE);

  while (next_ctrl != NULL) {
    if (pr_ctrls_copy_args(ctrl, next_ctrl) < 0) {
      int xerrno = errno;

      pr_signals_unblock();

      errno = xerrno;
      return -1;
    }

    /* Add this ctrl object to the client object. */
    *((pr_ctrls_t **) push_array(cl->cl_ctrls)) = next_ctrl;

    /* Set the flag that this control is ready to go. */ 
    next_ctrl->ctrls_flags |= PR_CTRLS_REQUESTED;
    next_ctrl->ctrls_cl = cl;

    next_ctrl = ctrls_lookup_next_action(NULL, TRUE);
  }

  pr_signals_unblock();
  return 0;
}

int pr_ctrls_recv_response(pool *resp_pool, int ctrls_sockfd,
    int *status, char ***respargv) {
  register unsigned int i = 0;
  array_header *resparr = NULL;
  unsigned int respargc = 0, resparglen = 0;
  char response[PR_TUNABLE_BUFFER_SIZE] = {'\0'};

  /* Sanity checks */
  if (resp_pool == NULL ||
      ctrls_sockfd < 0 ||
      status == NULL) {
    errno = EINVAL;
    return -1;
  }

  resparr = make_array(resp_pool, 0, sizeof(char *));

  /* No interruptions. */
  pr_signals_block();

  /* First, read the status, which is the return value of the control handler.
   */
  if (read(ctrls_sockfd, status, sizeof(int)) != sizeof(int)) {
    pr_signals_unblock();
    return -1;
  }

  /* Next, read the number of responses to be received */
  if (read(ctrls_sockfd, &respargc, sizeof(unsigned int)) !=
      sizeof(unsigned int)) {
    pr_signals_unblock();
    return -1;
  }

  if (respargc > CTRLS_MAX_NRESPARGS) {
    (void) pr_trace_msg(trace_channel, 3,
      "respargc (%u) exceeds max (%u), rejecting", respargc,
      CTRLS_MAX_NRESPARGS);
    pr_signals_unblock();
    errno = ENOMEM;
    return -1;
  }

  /* Read each response, and add it to the array */ 
  for (i = 0; i < respargc; i++) {
    int bread = 0, blen = 0;

    if (read(ctrls_sockfd, &resparglen,
        sizeof(unsigned int)) != sizeof(unsigned int)) {
      pr_signals_unblock();
      return -1;
    }

    /* Make sure resparglen is not too big */
    if (resparglen >= sizeof(response)) {
      pr_signals_unblock();
      errno = ENOMEM;
      return -1;
    }

    memset(response, '\0', sizeof(response));

    bread = read(ctrls_sockfd, response, resparglen);
    while ((size_t) bread != resparglen) {
      if (bread < 0) {
        pr_signals_unblock(); 
        return -1;
      }

      blen += bread;
      bread = read(ctrls_sockfd, response + blen, resparglen - blen);
    }

    /* Always make sure the buffer is zero-terminated */
    response[sizeof(response)-1] = '\0';

    *((char **) push_array(resparr)) = pstrdup(resp_pool, response);
  }

  if (respargv) {
    *respargv = ((char **) resparr->elts);
  }

  pr_signals_unblock(); 
  return respargc;
}

int pr_ctrls_send_msg(int sockfd, int msgstatus, unsigned int msgargc,
    char **msgargv) {
  register unsigned int i = 0;
  unsigned int msgarglen = 0;

  /* Sanity checks */
  if (sockfd < 0) {
    errno = EINVAL;
    return -1;
  }

  if (msgargc < 1) {
    return 0;
  }

  if (msgargv == NULL) {
    return 0;
  }

  /* No interruptions */
  pr_signals_block();

  /* Send the message status first */
  if (write(sockfd, &msgstatus, sizeof(int)) != sizeof(int)) {
    pr_signals_unblock();
    return -1;
  }

  /* Send the strings, one argument at a time.  First, send the number
   * of arguments to be sent; then send, for each argument, first the
   * length of the argument string, then the argument itself.
   */
  if (write(sockfd, &msgargc, sizeof(unsigned int)) !=
      sizeof(unsigned int)) {
    pr_signals_unblock();
    return -1;
  }

  for (i = 0; i < msgargc; i++) {
    int res = 0;

    msgarglen = strlen(msgargv[i]);

    while (TRUE) {
      res = write(sockfd, &msgarglen, sizeof(unsigned int));

      if (res != sizeof(unsigned int)) {
        if (errno == EAGAIN) {
          continue;
        }

        pr_signals_unblock();
        return -1;
      }

      break;
    }

    while (TRUE) {
      res = write(sockfd, msgargv[i], msgarglen);
      if ((size_t) res != msgarglen) {
        if (errno == EAGAIN) {
          continue;
        }

        pr_signals_unblock();
        return -1;

      }

      break;
    }
  }

  pr_signals_unblock();
  return 0;
}

static pr_ctrls_t *ctrls_lookup_action(module *mod, const char *action,
    unsigned char skip_disabled) {

  /* (Re)set the current indices */
  action_lookup_next = ctrls_action_list;
  action_lookup_action = action;
  action_lookup_module = mod;

  /* Wrapper around ctrls_lookup_next_action() */
  return ctrls_lookup_next_action(mod, skip_disabled);
}

static pr_ctrls_t *ctrls_lookup_next_action(module *mod,
    unsigned char skip_disabled) {
  ctrls_action_t *act = NULL;

  /* Sanity check */
  if (!action_lookup_action) {
    errno = EINVAL;
    return NULL;
  }

  if (mod != action_lookup_module)
    return ctrls_lookup_action(mod, action_lookup_action, skip_disabled);

  for (act = action_lookup_next; act; act = act->next) {

    if (skip_disabled && (act->flags & PR_CTRLS_ACT_DISABLED))
      continue;

    if (strcmp(act->action, action_lookup_action) == 0 &&
        (act->module == mod || mod == ANY_MODULE || mod == NULL)) {

      action_lookup_next = act->next;

      /* Use this action object to prepare a ctrl object. */
      return ctrls_prepare(act);
    }
  }

  return NULL;
}

int pr_get_registered_actions(pr_ctrls_t *ctrl, int flags) {
  ctrls_action_t *act = NULL;

  /* Are ctrls blocked? */
  if (ctrls_blocked) {
    errno = EPERM;
    return -1;
  }

  for (act = ctrls_action_list; act; act = act->next) {
    switch (flags) {
      case CTRLS_GET_ACTION_ALL:
        pr_ctrls_add_response(ctrl, "%s (mod_%s.c)", act->action,
          act->module->name);
        break;

      case CTRLS_GET_ACTION_ENABLED:
        if (act->flags & PR_CTRLS_ACT_DISABLED)
          break;
        pr_ctrls_add_response(ctrl, "%s (mod_%s.c)", act->action,
          act->module->name);
        break;

      case CTRLS_GET_DESC:
        pr_ctrls_add_response(ctrl, "%s: %s", act->action,
          act->desc);
        break;
    }
  }

  return 0;
}

int pr_set_registered_actions(module *mod, const char *action,
    unsigned char skip_disabled, unsigned int flags) {
  ctrls_action_t *act = NULL;
  unsigned char have_action = FALSE;

  /* Is flags a valid combination of settable flags? */
  if (flags && flags != PR_CTRLS_ACT_DISABLED) {
    errno = EINVAL;
    return -1;
  }

  /* Are ctrls blocked? */
  if (ctrls_blocked) {
    errno = EPERM;
    return -1;
  }

  for (act = ctrls_action_list; act; act = act->next) {
    if (skip_disabled && (act->flags & PR_CTRLS_ACT_DISABLED))
      continue;

    if ((!action ||
         strncmp(action, "all", 4) == 0 ||
         strcmp(act->action, action) == 0) &&
        (act->module == mod || mod == ANY_MODULE || mod == NULL)) {
      have_action = TRUE;
      act->flags = flags;
    }
  }

  if (!have_action) {
    errno = ENOENT;
    return -1;
  }

  return 0;
}

#if !defined(SO_PEERCRED) && !defined(HAVE_GETPEEREID) && \
    !defined(HAVE_GETPEERUCRED) && defined(LOCAL_CREDS)
static int ctrls_connect_local_creds(int sockfd) {
  char buf[1] = {'\0'};
  int res;

  /* The backend doesn't care what we send here, but it wants
   * exactly one character to force recvmsg() to block and wait
   * for us.
   */

  res = write(sockfd, buf, 1);
  while (res < 0) {
    if (errno == EINTR) {
      pr_signals_handle();

      res = write(sockfd, buf, 1);
      continue;
    }

    pr_trace_msg(trace_channel, 5,
      "error writing credentials byte for LOCAL_CREDS to fd %d: %s", sockfd,
      strerror(errno));
    return -1;
  }

  return res;
}
#endif /* !SCM_CREDS */

int pr_ctrls_connect(const char *socket_file) {
  int sockfd = -1, len = 0;
  struct sockaddr_un cl_sock, ctrl_sock;

  /* No interruptions */
  pr_signals_block();

  /* Create a Unix domain socket */
  sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sockfd < 0) {
    int xerrno = errno;

    pr_signals_unblock();

    errno = xerrno;
    return -1;
  }

  if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0) {
    int xerrno = errno;

    (void) close(sockfd);
    pr_signals_unblock();

    errno = xerrno;
    return -1;
  }

  /* Fill in the socket address */
  memset(&cl_sock, 0, sizeof(cl_sock));

  /* This first part is clever.  First, this process creates a socket in
   * the file system.  It _then_ connect()s to the server.  Upon accept()ing
   * the connection, the server examines the created socket to see that it
   * is indeed a socket, with the proper mode and time.  Clever, but not
   * ideal.
   */

  cl_sock.sun_family = AF_UNIX;
  pr_snprintf(cl_sock.sun_path, sizeof(cl_sock.sun_path) - 1, "%s%05u",
    "/tmp/ftp.cl", (unsigned int) getpid());
  len = sizeof(cl_sock);

  /* Make sure the file doesn't already exist */
  (void) unlink(cl_sock.sun_path);

  /* Make it a socket */
  if (bind(sockfd, (struct sockaddr *) &cl_sock, len) < 0) {
    int xerrno = errno;

    (void) unlink(cl_sock.sun_path);
    (void) close(sockfd);
    pr_signals_unblock();

    errno = xerrno;
    return -1;
  }

  /* Set the proper mode */
  if (chmod(cl_sock.sun_path, PR_CTRLS_CL_MODE) < 0) {
    int xerrno = errno;

    (void) unlink(cl_sock.sun_path);
    (void) close(sockfd);
    pr_signals_unblock();

    errno = xerrno;
    return -1;
  }

  /* Now connect to the real server */
  memset(&ctrl_sock, 0, sizeof(ctrl_sock));

  ctrl_sock.sun_family = AF_UNIX;
  sstrncpy(ctrl_sock.sun_path, socket_file, sizeof(ctrl_sock.sun_path));
  len = sizeof(ctrl_sock);

  if (connect(sockfd, (struct sockaddr *) &ctrl_sock, len) < 0) {
    int xerrno = errno;

    (void) unlink(cl_sock.sun_path);
    (void) close(sockfd);
    pr_signals_unblock();

    errno = xerrno;
    return -1;
  }

#if !defined(SO_PEERCRED) && !defined(HAVE_GETPEEREID) && \
    !defined(HAVE_GETPEERUCRED) && defined(LOCAL_CREDS)
  if (ctrls_connect_local_creds(sockfd) < 0) {
    int xerrno = errno;

    (void) unlink(cl_sock.sun_path);
    (void) close(sockfd);
    pr_signals_unblock();

    errno = xerrno;
    return -1;
  }
#endif /* LOCAL_CREDS */

  pr_signals_unblock();
  return sockfd;
}

int pr_ctrls_issock_unix(mode_t sock_mode) {

  if (ctrls_use_isfifo) {
#ifdef S_ISFIFO
    if (S_ISFIFO(sock_mode)) {
      return 0;
    }
#endif /* S_ISFIFO */
  } else {
#ifdef S_ISSOCK
    if (S_ISSOCK(sock_mode)) {
      return 0;
    }
#endif /* S_ISSOCK */
  }

  errno = ENOSYS;
  return -1;
}

#if defined(SO_PEERCRED)
static int ctrls_get_creds_peercred(int sockfd, uid_t *uid, gid_t *gid,
    pid_t *pid) {
# if defined(HAVE_STRUCT_SOCKPEERCRED)
  struct sockpeercred cred;
# else
  struct ucred cred;
# endif /* HAVE_STRUCT_SOCKPEERCRED */
  socklen_t cred_len;

  cred_len = sizeof(cred);
  if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2,
      "error obtaining peer credentials using SO_PEERCRED: %s",
      strerror(xerrno));

    errno = EPERM;
    return -1;
  }

  if (uid) {
    *uid = cred.uid;
  }

  if (gid) {
    *gid = cred.gid;
  }

  if (pid) {
    *pid = cred.pid;
  }

  return 0;
}
#endif /* SO_PEERCRED */

#if !defined(SO_PEERCRED) && defined(HAVE_GETPEEREID)
static int ctrls_get_creds_peereid(int sockfd, uid_t *uid, gid_t *gid) {
  if (getpeereid(sockfd, uid, gid) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 7, "error obtaining credentials using "
      "getpeereid(2) on fd %d: %s", sockfd, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}
#endif /* !HAVE_GETPEEREID */

#if !defined(SO_PEERCRED) && !defined(HAVE_GETPEEREID) && \
    defined(HAVE_GETPEERUCRED)
static int ctrls_get_creds_peerucred(int sockfd, uid_t *uid, gid_t *gid) {
  ucred_t *cred = NULL;

  if (getpeerucred(sockfd, &cred) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 7, "error obtaining credentials using "
      "getpeerucred(3) on fd %d: %s", sockfd, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (uid)
    *uid = ucred_getruid(cred);

  if (gid)
    *gid = ucred_getrgid(cred);

  ucred_free(cred);
  return 0;
}
#endif /* !HAVE_GETPEERUCRED */

#if !defined(SO_PEERCRED) && !defined(HAVE_GETPEEREID) && \
    !defined(HAVE_GETPEERUCRED) && defined(LOCAL_CREDS)
static int ctrls_get_creds_local(int sockfd, uid_t *uid, gid_t *gid,
    pid_t *pid) {
  int res;
  char buf[1];
  struct iovec iov;
  struct msghdr msg;

# if defined(SOCKCREDSIZE)
#  define MINCREDSIZE		(sizeof(struct cmsghdr) + SOCKCREDSIZE(0))
# else
#  if defined(HAVE_STRUCT_CMSGCRED)
#   define MINCREDSIZE		(sizeof(struct cmsghdr) + sizeof(struct cmsgcred))
#  elif defined(HAVE_STRUCT_SOCKCRED)
#   define MINCREDSIZE		(sizeof(struct cmsghdr) + sizeof(struct sockcred))
#  endif
# endif /* !SOCKCREDSIZE */

  char control[MINCREDSIZE];

  iov.iov_base = buf;
  iov.iov_len = 1;

  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  msg.msg_flags = 0;

  res = recvmsg(sockfd, &msg, 0);
  while (res < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();

      res = recvmsg(sockfd, &msg, 0);
      continue;
    }

    pr_trace_msg(trace_channel, 6,
      "error calling recvmsg() on fd %d: %s", sockfd, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (msg.msg_controllen > 0) {
#if defined(HAVE_STRUCT_CMSGCRED)
    struct cmsgcred cred;
#elif defined(HAVE_STRUCT_SOCKCRED)
    struct sockcred cred;
#endif /* !CMSGCRED and !SOCKCRED */

    struct cmsghdr *hdr = (struct cmsghdr *) control;

    if (hdr->cmsg_level != SOL_SOCKET) {
      pr_trace_msg(trace_channel, 5,
        "message received via recvmsg() on fd %d was not a SOL_SOCKET message",
        sockfd);

      errno = EINVAL;
      return -1;
    }

    if (hdr->cmsg_len < MINCREDSIZE) {
      pr_trace_msg(trace_channel, 5,
        "message received via recvmsg() on fd %d was not of proper "
        "length (%u bytes)", sockfd, MINCREDSIZE);

      errno = EINVAL;
      return -1;
    }

    if (hdr->cmsg_type != SCM_CREDS) {
      pr_trace_msg(trace_channel, 5,
        "message received via recvmsg() on fd %d was not of type SCM_CREDS",
        sockfd);

      errno = EINVAL;
      return -1;
    }

#if defined(HAVE_STRUCT_CMSGCRED)
    memcpy(&cred, CMSG_DATA(hdr), sizeof(struct cmsgcred));

    if (uid)
      *uid = cred.cmcred_uid;

    if (gid)
      *gid = cred.cmcred_gid;

    if (pid)
      *pid = cred.cmcred_pid;

#elif defined(HAVE_STRUCT_SOCKCRED)
    memcpy(&cred, CMSG_DATA(hdr), sizeof(struct sockcred));

    if (uid)
      *uid = cred.sc_uid;

    if (gid)
      *gid = cred.sc_gid;
#endif

    return 0;
  }

  return -1;
}
#endif /* !SCM_CREDS */

static int ctrls_get_creds_basic(struct sockaddr_un *sock, int cl_fd,
    unsigned int max_age, uid_t *uid, gid_t *gid, pid_t *pid) {
  pid_t cl_pid = 0;
  char *tmp = NULL;
  time_t stale_time;
  struct stat st;

  /* Check the path -- hmmm... */
  PRIVS_ROOT
  while (stat(sock->sun_path, &st) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    PRIVS_RELINQUISH
    pr_trace_msg(trace_channel, 2, "error: unable to stat %s: %s",
      sock->sun_path, strerror(xerrno));
    (void) close(cl_fd);

    errno = xerrno;
    return -1;
  }
  PRIVS_RELINQUISH

  /* Is it a socket? */
  if (pr_ctrls_issock_unix(st.st_mode) < 0) {
    (void) close(cl_fd);
    errno = ENOTSOCK;
    return -1;
  }

  /* Are the perms _not_ rwx------? */
  if (st.st_mode & (S_IRWXG|S_IRWXO) ||
      ((st.st_mode & S_IRWXU) != PR_CTRLS_CL_MODE)) {
    pr_trace_msg(trace_channel, 3,
      "error: unable to accept connection: incorrect mode");
    (void) close(cl_fd);
    errno = EPERM;
    return -1;
  }

  /* Is it new enough? */
  stale_time = time(NULL) - max_age;

  if (st.st_atime < stale_time ||
      st.st_ctime < stale_time ||
      st.st_mtime < stale_time) {
    char *msg = "error: stale connection";

    pr_trace_msg(trace_channel, 3,
      "unable to accept connection: stale connection");

    /* Log the times being compared, to aid in debugging this situation. */
    if (st.st_atime < stale_time) {
      time_t age = stale_time - st.st_atime;

      pr_trace_msg(trace_channel, 3,
         "last access time of '%s' is %lu secs old (must be less than %u secs)",
         sock->sun_path, (unsigned long) age, max_age);
    }

    if (st.st_ctime < stale_time) {
      time_t age = stale_time - st.st_ctime;

      pr_trace_msg(trace_channel, 3,
         "last change time of '%s' is %lu secs old (must be less than %u secs)",
         sock->sun_path, (unsigned long) age, max_age);
    }

    if (st.st_mtime < stale_time) {
      time_t age = stale_time - st.st_mtime;

      pr_trace_msg(trace_channel, 3,
         "last modified time of '%s' is %lu secs old (must be less than %u "
         "secs)", sock->sun_path, (unsigned long) age, max_age);
    }

    if (pr_ctrls_send_msg(cl_fd, -1, 1, &msg) < 0) {
      pr_trace_msg(trace_channel, 2, "error sending message: %s",
        strerror(errno));
    }

    (void) close(cl_fd);

    errno = ETIMEDOUT;
    return -1;
  }

  /* Parse the PID out of the path */
  tmp = sock->sun_path;
  tmp += strlen("/tmp/ftp.cl");
  cl_pid = atol(tmp);

  /* Return the IDs of the caller */
  if (uid)
    *uid = st.st_uid;

  if (gid)
    *gid = st.st_gid;

  if (pid)
    *pid = cl_pid;

  return 0;
}

int pr_ctrls_accept(int sockfd, uid_t *uid, gid_t *gid, pid_t *pid,
    unsigned int max_age) {
  socklen_t len = 0;
  struct sockaddr_un sock;
  int cl_fd = -1;
  int res = -1;

  len = sizeof(sock);

  while ((cl_fd = accept(sockfd, (struct sockaddr *) &sock, &len)) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg(trace_channel, 3,
      "error: unable to accept on local socket: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* NULL terminate the name */
  sock.sun_path[sizeof(sock.sun_path)-1] = '\0';

#if defined(SO_PEERCRED)
  pr_trace_msg(trace_channel, 5,
    "checking client credentials using SO_PEERCRED");
  res = ctrls_get_creds_peercred(cl_fd, uid, gid, pid);

#elif !defined(SO_PEERCRED) && defined(HAVE_GETPEEREID)
  pr_trace_msg(trace_channel, 5,
    "checking client credentials using getpeereid(2)");
  res = ctrls_get_creds_peereid(cl_fd, uid, gid);

#elif !defined(SO_PEERCRED) && !defined(HAVE_GETPEEREID) && \
      defined(HAVE_GETPEERUCRED)
  pr_trace_msg(trace_channel, 5,
    "checking client credentials using getpeerucred(3)");
  res = ctrls_get_creds_peerucred(cl_fd, uid, gid);

#elif !defined(SO_PEERCRED) && !defined(HAVE_GETPEEREID) && \
      !defined(HAVE_GETPEERUCRED) && defined(LOCAL_CREDS)
  pr_trace_msg(trace_channel, 5,
    "checking client credentials using SCM_CREDS");
  res = ctrls_get_creds_local(cl_fd, uid, gid, pid);

#endif

  /* Fallback to the Stevens method of determining connection credentials,
   * if the kernel-enforced methods did not pan out.
   */
  if (res < 0) {
    pr_trace_msg(trace_channel, 5,
      "checking client credentials using Stevens' method");
    res = ctrls_get_creds_basic(&sock, cl_fd, max_age, uid, gid, pid);

    if (res < 0)
      return res;
  }

  /* Done with the path now */
  PRIVS_ROOT
  unlink(sock.sun_path);
  PRIVS_RELINQUISH

  return cl_fd;
}

void pr_block_ctrls(void) {
  ctrls_blocked = TRUE;
}

void pr_unblock_ctrls(void) {
  ctrls_blocked = FALSE;
}

int pr_check_actions(void) {
  ctrls_action_t *act = NULL;

  for (act = ctrls_action_list; act; act = act->next) {

    if (act->flags & PR_CTRLS_ACT_SOLITARY) {
      /* This is a territorial action -- only one instance allowed */
      if (ctrls_lookup_action(NULL, act->action, FALSE)) {
        pr_log_pri(PR_LOG_NOTICE,
          "duplicate controls for '%s' action not allowed",
          act->action);
        return -1;
      }
    }
  }

  return 0;
}

int pr_run_ctrls(module *mod, const char *action) {
  pr_ctrls_t *ctrl = NULL;

  /* Are ctrls blocked? */
  if (ctrls_blocked) {
    errno = EPERM;
    return -1;
  }

  for (ctrl = ctrls_active_list; ctrl; ctrl = ctrl->ctrls_next) {

    /* Be watchful of the various client-side flags.  Note: if
     * ctrl->ctrls_cl is ever NULL, it means there's a bug in the code.
     */
    if (ctrl->ctrls_cl->cl_flags != PR_CTRLS_CL_HAVEREQ)
      continue;

    /* Has this control been disabled? */
    if (ctrl->ctrls_flags & PR_CTRLS_ACT_DISABLED)
      continue;

    /* Is it time to trigger this ctrl? */
    if (!(ctrl->ctrls_flags & PR_CTRLS_REQUESTED))
      continue;

    if (ctrl->ctrls_when > time(NULL)) {
      ctrl->ctrls_flags |= PR_CTRLS_PENDING;
      pr_ctrls_add_response(ctrl, "request pending");
      continue;
    }

    if (action &&
        strcmp(ctrl->ctrls_action, action) == 0) {
      pr_trace_msg(trace_channel, 7, "calling '%s' control handler",
        ctrl->ctrls_action);

      /* Invoke the callback, if the ctrl's action matches.  Unblock
       * ctrls before invoking the callback, then re-block them after the
       * callback returns.  This will allow the action handlers to use some
       * of the Controls API functions correctly.
       */
      pr_unblock_ctrls();
      ctrl->ctrls_cb_retval = ctrl->ctrls_cb(ctrl,
        (ctrl->ctrls_cb_args ? ctrl->ctrls_cb_args->nelts : 0),
        (ctrl->ctrls_cb_args ? (char **) ctrl->ctrls_cb_args->elts : NULL));
      pr_block_ctrls();

      if (ctrl->ctrls_cb_retval < 1) {
        ctrl->ctrls_flags &= ~PR_CTRLS_REQUESTED;
        ctrl->ctrls_flags &= ~PR_CTRLS_PENDING;
        ctrl->ctrls_flags |= PR_CTRLS_HANDLED;
      }

    } else if (!action) {
      pr_trace_msg(trace_channel, 7, "calling '%s' control handler",
        ctrl->ctrls_action);

      /* If no action was given, invoke every callback */
      pr_unblock_ctrls();
      ctrl->ctrls_cb_retval = ctrl->ctrls_cb(ctrl,
        (ctrl->ctrls_cb_args ? ctrl->ctrls_cb_args->nelts : 0),
        (ctrl->ctrls_cb_args ? (char **) ctrl->ctrls_cb_args->elts : NULL));
      pr_block_ctrls();

      if (ctrl->ctrls_cb_retval < 1) {
        ctrl->ctrls_flags &= ~PR_CTRLS_REQUESTED;
        ctrl->ctrls_flags &= ~PR_CTRLS_PENDING;
        ctrl->ctrls_flags |= PR_CTRLS_HANDLED;
      }
    }
  }

  return 0;
}

int pr_reset_ctrls(void) {
  pr_ctrls_t *ctrl = NULL;

  /* NOTE: need a clean_ctrls() or somesuch that will, after sending any
   * responses, iterate through the list and "free" any ctrls whose
   * ctrls_cb_retval is zero.  This feature is used to handle things like
   * shutdown requests in the future -- the request is only considered
   * "processed" when the callback returns zero.  Any non-zero requests are
   * not cleared, and are considered "pending".  However, this brings up the
   * complication of an additional request for that action being issued by the
   * client before the request is processed.  Simplest solution: remove the
   * old request args, and replace them with the new ones.
   *
   * This requires that the return value of the ctrl callback be explicitly
   * documented.
   *
   * How about: ctrls_cb_retval = 1  pending
   *                              0  processed, OK    (reset)
   *                             -1  processed, error (reset)
   */

  for (ctrl = ctrls_active_list; ctrl; ctrl = ctrl->ctrls_next) {
    if (ctrl->ctrls_cb_retval < 1)
      ctrls_free(ctrl);
  }

  return 0;
}

/* From include/mod_ctrls.h */

/* Returns TRUE if the given cl_gid is allowed by the group ACL, FALSE
 * otherwise. Note that the default is to deny everyone, unless an ACL has
 * been configured.
 */
unsigned char pr_ctrls_check_group_acl(gid_t cl_gid,
    const ctrls_grp_acl_t *grp_acl) {
  register unsigned int i = 0;
  unsigned char res = FALSE;

  /* Note: the special condition of ngids of 1 and gids of NULL signals
   * that all groups are to be treated according to the allow member.
   */
  if (grp_acl->gids) {
    for (i = 0; i < grp_acl->ngids; i++) {
      if ((grp_acl->gids)[i] == cl_gid) {
        res = TRUE;
      }
    }

  } else if (grp_acl->ngids == 1) {
    res = TRUE;
  }

  if (!grp_acl->allow) {
    res = !res;
  }

  return res;
}

/* Returns TRUE if the given cl_uid is allowed by the user ACL, FALSE
 * otherwise. Note that the default is to deny everyone, unless an ACL has
 * been configured.
 */
unsigned char pr_ctrls_check_user_acl(uid_t cl_uid,
    const ctrls_usr_acl_t *usr_acl) {
  register unsigned int i = 0;
  unsigned char res = FALSE;

  /* Note: the special condition of nuids of 1 and uids of NULL signals
   * that all users are to be treated according to the allow member.
   */
  if (usr_acl->uids) {
    for (i = 0; i < usr_acl->nuids; i++) {
      if ((usr_acl->uids)[i] == cl_uid) {
        res = TRUE;
      }
    }

  } else if (usr_acl->nuids == 1) {
    res = TRUE;
  }

  if (!usr_acl->allow) {
    res = !res;
  }

  return res;
}

/* Returns TRUE for allowed, FALSE for denied. */
unsigned char pr_ctrls_check_acl(const pr_ctrls_t *ctrl,
    const ctrls_acttab_t *acttab, const char *action) {
  register unsigned int i = 0;

  for (i = 0; acttab[i].act_action; i++) {
    if (strcmp(acttab[i].act_action, action) == 0) {

      if (!pr_ctrls_check_user_acl(ctrl->ctrls_cl->cl_uid,
            &(acttab[i].act_acl->acl_usrs)) &&
          !pr_ctrls_check_group_acl(ctrl->ctrls_cl->cl_gid,
            &(acttab[i].act_acl->acl_grps))) {

        /* Access denied */
        return FALSE;
      }
    }
  }

  return TRUE;
}

void pr_ctrls_init_acl(ctrls_acl_t *acl) {

  /* Sanity check */
  if (!acl)
    return;

  memset(acl, 0, sizeof(ctrls_acl_t));
  acl->acl_usrs.allow = acl->acl_grps.allow = TRUE;
}

static char *ctrls_argsep(char **arg) {
  char *ret = NULL, *dst = NULL;
  char quote_mode = 0;

  if (!arg || !*arg || !**arg)
    return NULL;

  while (**arg && PR_ISSPACE(**arg))
    (*arg)++;

  if (!**arg)
    return NULL;

  ret = dst = *arg;

  if (**arg == '\"') {
    quote_mode++;
    (*arg)++;
  }

  while (**arg && **arg != ',' &&
      (quote_mode ? (**arg != '\"') : (!PR_ISSPACE(**arg)))) {

    if (**arg == '\\' && quote_mode) {

      /* escaped char */
      if (*((*arg) + 1))
        *dst = *(++(*arg));
    }

    *dst++ = **arg;
    ++(*arg);
  }

  if (**arg)
    (*arg)++;

  *dst = '\0';
  return ret;
}

char **pr_ctrls_parse_acl(pool *acl_pool, char *acl_str) {
  char *name = NULL, *acl_str_dup = NULL, **acl_list = NULL;
  array_header *acl_arr = NULL;
  pool *tmp_pool = NULL;

  /* Sanity checks */
  if (!acl_pool || !acl_str)
    return NULL;

  tmp_pool = make_sub_pool(acl_pool);
  acl_str_dup = pstrdup(tmp_pool, acl_str);

  /* Allocate an array */
  acl_arr = make_array(acl_pool, 0, sizeof(char **));

  /* Add each name to the array */
  while ((name = ctrls_argsep(&acl_str_dup)) != NULL) {
    char *tmp = pstrdup(acl_pool, name);

    /* Push the name into the ACL array */
    *((char **) push_array(acl_arr)) = tmp;
  }

  /* Terminate the temp array with a NULL, as is proper. */
  *((char **) push_array(acl_arr)) = NULL;

  acl_list = (char **) acl_arr->elts;
  destroy_pool(tmp_pool);

  /* return the array of names */
  return acl_list;
}

void pr_ctrls_set_group_acl(pool *grp_acl_pool, ctrls_grp_acl_t *grp_acl,
    const char *allow, char *grouplist) {
  char *group = NULL, **groups = NULL;
  array_header *gid_list = NULL;
  gid_t gid = 0;
  pool *tmp_pool = NULL;

  if (grp_acl_pool == NULL ||
      grp_acl == NULL ||
      allow == NULL ||
      grouplist == NULL) {
    return;
  }

  tmp_pool = make_sub_pool(grp_acl_pool);

  if (strncmp(allow, "allow", 6) == 0) {
    grp_acl->allow = TRUE;

  } else {
    grp_acl->allow = FALSE;
  }

  /* Parse the given expression into an array, then retrieve the GID
   * for each given name.
   */
  groups = pr_ctrls_parse_acl(grp_acl_pool, grouplist);

  /* Allocate an array of gid_t's */
  gid_list = make_array(grp_acl_pool, 0, sizeof(gid_t));

  for (group = *groups; group != NULL; group = *++groups) {

    /* Handle a group name of "*" differently. */
    if (strncmp(group, "*", 2) == 0) {
      grp_acl->ngids = 1;
      grp_acl->gids = NULL;
      destroy_pool(tmp_pool);
      return;

    } else {
      gid = pr_auth_name2gid(tmp_pool, group);
      if (gid == (gid_t) -1)
        continue;
    }

    *((gid_t *) push_array(gid_list)) = gid;
  }

  grp_acl->ngids = gid_list->nelts;
  grp_acl->gids = (gid_t *) gid_list->elts;

  destroy_pool(tmp_pool);
}

void pr_ctrls_set_user_acl(pool *usr_acl_pool, ctrls_usr_acl_t *usr_acl,
    const char *allow, char *userlist) {
  char *user = NULL, **users = NULL;
  array_header *uid_list = NULL;
  uid_t uid = 0;
  pool *tmp_pool = NULL;

  /* Sanity checks */
  if (usr_acl_pool == NULL ||
      usr_acl == NULL ||
      allow == NULL ||
      userlist == NULL) {
    return;
  }

  tmp_pool = make_sub_pool(usr_acl_pool);

  if (strncmp(allow, "allow", 6) == 0) {
    usr_acl->allow = TRUE;

  } else {
    usr_acl->allow = FALSE;
  }

  /* Parse the given expression into an array, then retrieve the UID
   * for each given name.
   */
  users = pr_ctrls_parse_acl(usr_acl_pool, userlist);

  /* Allocate an array of uid_t's */
  uid_list = make_array(usr_acl_pool, 0, sizeof(uid_t));

  for (user = *users; user != NULL; user = *++users) {

    /* Handle a user name of "*" differently. */
    if (strncmp(user, "*", 2) == 0) {
      usr_acl->nuids = 1;
      usr_acl->uids = NULL;
      destroy_pool(tmp_pool);
      return;

    } else {
      uid = pr_auth_name2uid(tmp_pool, user);
      if (uid == (uid_t) -1)
        continue;
    }

    *((uid_t *) push_array(uid_list)) = uid;
  }

  usr_acl->nuids = uid_list->nelts;
  usr_acl->uids = (uid_t *) uid_list->elts;

  destroy_pool(tmp_pool);
}

char *pr_ctrls_set_module_acls(ctrls_acttab_t *acttab, pool *acl_pool,
    char **actions, const char *allow, const char *type, char *list) {
  register unsigned int i = 0;
  unsigned char all_actions = FALSE;

  /* First, sanity check the given list of actions against the actions
   * in the given table.
   */
  for (i = 0; actions[i]; i++) {
    register unsigned int j = 0;
    unsigned char valid_action = FALSE;

    if (strncmp(actions[i], "all", 4) == 0)
      continue;

    for (j = 0; acttab[j].act_action; j++) {
      if (strcmp(actions[i], acttab[j].act_action) == 0) {
        valid_action = TRUE;
        break;
      }
    }

    if (!valid_action)
      return actions[i];
  }

  for (i = 0; actions[i]; i++) {
    register unsigned int j = 0;

    if (!all_actions &&
        strncmp(actions[i], "all", 4) == 0)
      all_actions = TRUE;

    for (j = 0; acttab[j].act_action; j++) {
      if (all_actions || strcmp(actions[i], acttab[j].act_action) == 0) {

        /* Use the type parameter to determine whether the list is of users or
         * of groups.
         */
        if (strncmp(type, "user", 5) == 0) {
          pr_ctrls_set_user_acl(acl_pool, &(acttab[j].act_acl->acl_usrs),
            allow, list);

        } else if (strncmp(type, "group", 6) == 0) {
          pr_ctrls_set_group_acl(acl_pool, &(acttab[j].act_acl->acl_grps),
            allow, list);
        }
      }
    }
  }

  return NULL;
}

char *pr_ctrls_unregister_module_actions(ctrls_acttab_t *acttab,
    char **actions, module *mod) {
  register unsigned int i = 0;

  /* First, sanity check the given actions against the actions supported by
   * this module.
   */
  for (i = 0; actions[i]; i++) {
    register unsigned int j = 0;
    unsigned char valid_action = FALSE;

    for (j = 0; acttab[j].act_action; j++) {
      if (strcmp(actions[i], acttab[j].act_action) == 0) {
        valid_action = TRUE;
        break;
      }
    }

    if (!valid_action)
      return actions[i];
  }

  /* Next, iterate through both lists again, looking for actions of the
   * module _not_ in the given list.
   */
  for (i = 0; acttab[i].act_action; i++) {
    register unsigned int j = 0;
    unsigned char have_action = FALSE;

    for (j = 0; actions[j]; j++) {
      if (strcmp(acttab[i].act_action, actions[j]) == 0) {
        have_action = TRUE;
        break;
      }
    }

    if (have_action) {
      pr_trace_msg(trace_channel, 4, "mod_%s.c: removing '%s' control",
        mod->name, acttab[i].act_action);
      pr_ctrls_unregister(mod, acttab[i].act_action);
      destroy_pool(acttab[i].act_acl->acl_pool);
    }
  }

  return NULL;
}

int pr_ctrls_set_logfd(int fd) {

  /* Close any existing log fd. */
  if (ctrls_logfd >= 0) {
    (void) close(ctrls_logfd);
  }

  ctrls_logfd = fd;
  return 0;
}

int pr_ctrls_log(const char *module_version, const char *fmt, ...) {
  va_list msg;
  int res;

  /* sanity check */
  if (ctrls_logfd < 0)
    return 0;

  va_start(msg, fmt);
  res = pr_log_vwritefile(ctrls_logfd, module_version, fmt, msg);
  va_end(msg);

  return res;
}

/* Initialize the Controls API. */
void init_ctrls(void) {
  struct stat st;
  int sockfd;
  struct sockaddr_un sockun;
  size_t socklen;
  char *sockpath = PR_RUN_DIR "/test.sock";

  if (ctrls_pool) {
    destroy_pool(ctrls_pool);
  }

  ctrls_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(ctrls_pool, "Controls Pool");

  /* Make sure all of the lists are zero'd out. */
  ctrls_action_list = NULL;
  ctrls_active_list = NULL;
  ctrls_free_list = NULL;

   /* And that the lookup indices are (re)set as well... */
  action_lookup_next = NULL;
  action_lookup_action = NULL;
  action_lookup_module = NULL;

  /* Run-time check to find out whether this platform identifies a
   * Unix domain socket file descriptor via the S_ISFIFO macro, or
   * the S_ISSOCK macro.
   */

  sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sockfd < 0) {
    pr_log_debug(DEBUG10, "unable to create Unix domain socket: %s",
      strerror(errno));
    return;
  }

  memset(&sockun, 0, sizeof(sockun));
  sockun.sun_family = AF_UNIX;
  sstrncpy(sockun.sun_path, sockpath, sizeof(sockun.sun_path));
  socklen = sizeof(struct sockaddr_un);

  if (bind(sockfd, (struct sockaddr *) &sockun, socklen) < 0) {
    pr_log_debug(DEBUG10, "unable to bind to Unix domain socket at '%s': %s",
      sockpath, strerror(errno));
    (void) close(sockfd);
    (void) unlink(sockpath);
    return;
  }

  if (fstat(sockfd, &st) < 0) {
    pr_log_debug(DEBUG10, "unable to stat Unix domain socket at '%s': %s",
      sockpath, strerror(errno));
    (void) close(sockfd);
    (void) unlink(sockpath);
    return;
  }

#ifdef S_ISFIFO
  pr_log_debug(DEBUG10, "testing Unix domain socket using S_ISFIFO");
  if (S_ISFIFO(st.st_mode)) {
    ctrls_use_isfifo = TRUE;
  }
#else
  pr_log_debug(DEBUG10, "cannot test Unix domain socket using S_ISFIFO: "
    "macro undefined");
#endif

#ifdef S_ISSOCK
  pr_log_debug(DEBUG10, "testing Unix domain socket using S_ISSOCK");
  if (S_ISSOCK(st.st_mode)) {
    ctrls_use_isfifo = FALSE;
  }
#else
  pr_log_debug(DEBUG10, "cannot test Unix domain socket using S_ISSOCK: "
    "macro undefined");
#endif

  pr_log_debug(DEBUG10, "using %s macro for Unix domain socket detection",
    ctrls_use_isfifo ? "S_ISFIFO" : "S_ISSOCK");

  (void) close(sockfd);
  (void) unlink(sockpath);
  return;
}

#endif /* PR_USE_CTRLS */
