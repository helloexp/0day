/*
 * ProFTPD: mod_ctrls -- a module implementing the ftpdctl local socket
 *          server, as well as several utility functions for other Controls
 *          modules
 * Copyright (c) 2000-2017 TJ Saunders
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
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_ctrls, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"
#include "mod_ctrls.h"

#define MOD_CTRLS_VERSION	"mod_ctrls/0.9.5"

#ifndef PR_USE_CTRLS
# error "Controls support required (use --enable-ctrls)"
#endif

/* Master daemon in standalone mode? (from src/main.c) */
extern unsigned char is_master;

module ctrls_module;
static ctrls_acttab_t ctrls_acttab[];

static const char *trace_channel = "ctrls";

/* Hard-coded Controls timer IDs.  Need two, one for the initial timer, one
 * to identify the user-configured-interval timer
 */
#define CTRLS_TIMER_ID       24075

static unsigned int ctrls_interval = 10;

/* Controls listening socket fd */
static int ctrls_sockfd = -1;

#define MOD_CTRLS_DEFAULT_SOCK		PR_RUN_DIR "/proftpd.sock"
static char *ctrls_sock_file = MOD_CTRLS_DEFAULT_SOCK;

/* User/group ownership of the control socket */
static uid_t ctrls_sock_uid = 0;
static gid_t ctrls_sock_gid = 0;

/* Pool for this module's use */
static pool *ctrls_pool = NULL;

/* Required "freshness" of client credential sockets */
static unsigned int ctrls_cl_freshness = 10;

/* Start of the client list */
static pr_ctrls_cl_t *cl_list = NULL;
static unsigned int cl_listlen = 0;
static unsigned int cl_maxlistlen = 5;

/* Controls access control list.  This is for ACLs on the control socket
 * itself, rather than on individual actions.
 */
static ctrls_acl_t ctrls_sock_acl;

static unsigned char ctrls_engine = TRUE;

/* Necessary prototypes */
static int ctrls_setblock(int sockfd);
static int ctrls_setnonblock(int sockfd);

static const char *ctrls_logname = NULL;

/* Support routines
 */

/* Controls logging routines
 */

static int ctrls_closelog(void) {
  if (ctrls_logname != NULL) {
    pr_ctrls_set_logfd(-1);
    ctrls_logname = NULL;
  }

  return 0;
}

static int ctrls_openlog(void) {
  int logfd, res = 0, xerrno = 0;

  /* Sanity check */
  if (ctrls_logname == NULL)
    return 0;

  PRIVS_ROOT
  res = pr_log_openfile(ctrls_logname, &logfd, PR_LOG_SYSTEM_MODE);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (res == 0) {
    pr_ctrls_set_logfd(logfd);

  } else {
    if (res == -1) {
      pr_log_pri(PR_LOG_NOTICE, MOD_CTRLS_VERSION
        ": unable to open ControlsLog '%s': %s", ctrls_logname,
        strerror(xerrno));

    } else if (res == PR_LOG_WRITABLE_DIR) {
      pr_log_pri(PR_LOG_WARNING, MOD_CTRLS_VERSION
        ": unable to open ControlsLog '%s': "
        "parent directory is world-writable", ctrls_logname);

    } else if (res == PR_LOG_SYMLINK) {
      pr_log_pri(PR_LOG_WARNING, MOD_CTRLS_VERSION
        ": unable to open ControlsLog '%s': %s is a symbolic link",
        ctrls_logname, ctrls_logname);
    }
  }

  return res;
}

/* Controls client routines
 */

static pr_ctrls_cl_t *ctrls_new_cl(void) {
  pool *cl_pool = NULL;

  if (!cl_list) {

    /* Our first client */
    cl_pool = make_sub_pool(ctrls_pool);
    pr_pool_tag(cl_pool, "Controls client pool");

    cl_list = (pr_ctrls_cl_t *) pcalloc(cl_pool, sizeof(pr_ctrls_cl_t));

    cl_list->cl_pool = cl_pool;
    cl_list->cl_fd = -1;
    cl_list->cl_uid = 0;
    cl_list->cl_user = NULL;
    cl_list->cl_gid = 0;
    cl_list->cl_group = NULL;
    cl_list->cl_pid = 0;
    cl_list->cl_ctrls = make_array(cl_pool, 0, sizeof(pr_ctrls_t *));

    cl_list->cl_next = NULL;
    cl_list->cl_prev = NULL;

    cl_listlen = 1;

  } else {
    pr_ctrls_cl_t *cl = NULL;

    /* Add another victim to the list */
    cl_pool = make_sub_pool(ctrls_pool);
    pr_pool_tag(cl_pool, "Controls client pool");

    cl = (pr_ctrls_cl_t *) pcalloc(cl_pool, sizeof(pr_ctrls_cl_t));

    cl->cl_pool = cl_pool;
    cl->cl_fd = -1;
    cl->cl_uid = 0;
    cl->cl_user = NULL;
    cl->cl_gid = 0;
    cl->cl_group = NULL;
    cl->cl_pid = 0;
    cl->cl_ctrls = make_array(cl->cl_pool, 0, sizeof(pr_ctrls_t *));

    cl->cl_next = cl_list;
    cl->cl_prev = NULL;

    cl_list->cl_prev = cl;
    cl_list = cl;

    cl_listlen++;
  }

  return cl_list;
}

/* Add a new client to the set */
static pr_ctrls_cl_t *ctrls_add_cl(int cl_fd, uid_t cl_uid, gid_t cl_gid,
    pid_t cl_pid, unsigned long cl_flags) {
  pr_ctrls_cl_t *cl = NULL;

  /* Make sure there's an empty entry available */
  cl = ctrls_new_cl();

  cl->cl_fd = cl_fd;
  cl->cl_uid = cl_uid;
  cl->cl_user = pr_auth_uid2name(cl->cl_pool, cl->cl_uid);
  cl->cl_gid = cl_gid;
  cl->cl_group = pr_auth_gid2name(cl->cl_pool, cl->cl_gid);
  cl->cl_pid = cl_pid;
  cl->cl_flags = cl_flags;

  pr_ctrls_log(MOD_CTRLS_VERSION,
    "accepted connection from %s/%s client", cl->cl_user, cl->cl_group);
 
  return cl;
}

/* Remove a client from the set */
static void ctrls_del_cl(pr_ctrls_cl_t *cl) {

  /* Remove this ctr_cl_t from the list, and free it */
  if (cl->cl_next)
    cl->cl_next->cl_prev = cl->cl_prev;

  if (cl->cl_prev)
    cl->cl_prev->cl_next = cl->cl_next;

  else
    cl_list = cl->cl_next;

  close(cl->cl_fd);
  cl->cl_fd = -1;

  destroy_pool(cl->cl_pool);

  cl_listlen--;

  return;
}

/* Controls socket routines
 */


/* Iterate through any readable descriptors, reading each into appropriate
 * client objects
 */
static void ctrls_cls_read(void) {
  pr_ctrls_cl_t *cl = cl_list;

  while (cl) {
    pr_signals_handle();

    if (pr_ctrls_recv_request(cl) < 0) {

      if (errno == EOF) {
        ;
 
      } else if (errno == EINVAL) {

        /* Unsupported action requested */
        if (!cl->cl_flags) {
          cl->cl_flags = PR_CTRLS_CL_NOACTION;
        }

        pr_ctrls_log(MOD_CTRLS_VERSION,
          "recvd from %s/%s client: (invalid action)", cl->cl_user,
          cl->cl_group);

      } else if (errno == EAGAIN ||
                 errno == EWOULDBLOCK) {

        /* Malicious/blocked client */
        if (!cl->cl_flags) {
          cl->cl_flags = PR_CTRLS_CL_BLOCKED;
        }

      } else {
        pr_ctrls_log(MOD_CTRLS_VERSION,
          "error: unable to receive client request: %s", strerror(errno)); 
      }

    } else {
      pr_ctrls_t *ctrl = *((pr_ctrls_t **) cl->cl_ctrls->elts);
      char *request = (char *) ctrl->ctrls_action;

      /* Request successfully read.  Flag this client as being in such a
       * state.
       */
      if (!cl->cl_flags) {
        cl->cl_flags = PR_CTRLS_CL_HAVEREQ;
      }

      if (ctrl->ctrls_cb_args) {
        unsigned int reqargc = ctrl->ctrls_cb_args->nelts;
        char **reqargv = ctrl->ctrls_cb_args->elts;

        /* Reconstruct the original request string from the client for
         * logging.
         */
        while (reqargc--) {
          request = pstrcat(cl->cl_pool, request, " ", *reqargv++, NULL);
        }

        pr_ctrls_log(MOD_CTRLS_VERSION,
          "recvd from %s/%s client: '%s'", cl->cl_user, cl->cl_group,
          request);
      }
    }

    cl = cl->cl_next;
  }

  return;
}

/* Iterate through any writable descriptors, writing out the responses to the
 * appropriate client objects
 */
static int ctrls_cls_write(void) {
  pr_ctrls_cl_t *cl = cl_list;

  while (cl) {
    /* Necessary to keep track of the next client in the list while
     * the list is being modified.
     */
    pr_ctrls_cl_t *tmpcl = cl->cl_next;

    pr_signals_handle();

    /* This client has something to hear */
    if (cl->cl_flags == PR_CTRLS_CL_NOACCESS) {
      char *msg = "access denied";

      /* ACL-denied access */
      if (pr_ctrls_send_msg(cl->cl_fd, -1, 1, &msg) < 0) {
        pr_ctrls_log(MOD_CTRLS_VERSION,
          "error: unable to send response to %s/%s client: %s",
          cl->cl_user, cl->cl_group, strerror(errno));

      } else {
        pr_ctrls_log(MOD_CTRLS_VERSION, "sent to %s/%s client: '%s'",
          cl->cl_user, cl->cl_group, msg);
      }

    } else if (cl->cl_flags == PR_CTRLS_CL_NOACTION) {
      char *msg = "unsupported action requested";

      /* Unsupported action -- no matching controls */
      if (pr_ctrls_send_msg(cl->cl_fd, -1, 1, &msg) < 0) {
        pr_ctrls_log(MOD_CTRLS_VERSION,
          "error: unable to send response to %s/%s client: %s",
          cl->cl_user, cl->cl_group, strerror(errno));

      } else {
        pr_ctrls_log(MOD_CTRLS_VERSION, "sent to %s/%s client: '%s'",
          cl->cl_user, cl->cl_group, msg);
      }

    } else if (cl->cl_flags == PR_CTRLS_CL_BLOCKED) {
      char *msg = "blocked connection";

      if (pr_ctrls_send_msg(cl->cl_fd, -1, 1, &msg) < 0) {
        pr_ctrls_log(MOD_CTRLS_VERSION,
          "error: unable to send response to %s/%s client: %s",
          cl->cl_user, cl->cl_group, strerror(errno));

      } else {
        pr_ctrls_log(MOD_CTRLS_VERSION, "sent to %s/%s client: '%s'",
          cl->cl_user, cl->cl_group, msg);
      }

    } else if (cl->cl_flags == PR_CTRLS_CL_HAVEREQ) {

      if (cl->cl_ctrls != NULL &&
          cl->cl_ctrls->nelts > 0) {
        register unsigned int i = 0;
        pr_ctrls_t **ctrlv = NULL;

        ctrlv = (pr_ctrls_t **) cl->cl_ctrls->elts;

        for (i = 0; i < cl->cl_ctrls->nelts; i++) {
          if ((ctrlv[i])->ctrls_cb_retval < 1) {

            /* Make sure the callback(s) added responses */
            if ((ctrlv[i])->ctrls_cb_resps) {
              if (pr_ctrls_send_msg(cl->cl_fd, (ctrlv[i])->ctrls_cb_retval,
                  (ctrlv[i])->ctrls_cb_resps->nelts,
                  (char **) (ctrlv[i])->ctrls_cb_resps->elts) < 0) {
                pr_ctrls_log(MOD_CTRLS_VERSION,
                  "error: unable to send response to %s/%s "
                  "client: %s", cl->cl_user, cl->cl_group, strerror(errno));

              } else {
                /* For logging/accounting purposes */
                register unsigned int j = 0;
                int respval = (ctrlv[i])->ctrls_cb_retval;
                unsigned int respargc = (ctrlv[i])->ctrls_cb_resps->nelts;
                char **respargv = (ctrlv[i])->ctrls_cb_resps->elts;

                pr_ctrls_log(MOD_CTRLS_VERSION,
                  "sent to %s/%s client: return value: %d",
                  cl->cl_user, cl->cl_group, respval);

                for (j = 0; j < respargc; j++) {
                  pr_ctrls_log(MOD_CTRLS_VERSION,
                    "sent to %s/%s client: '%s'", cl->cl_user, cl->cl_group,
                    respargv[j]);
                }
              }

            } else {
              /* No responses added by callbacks */
              pr_ctrls_log(MOD_CTRLS_VERSION,
                "notice: no responses given for %s/%s client: "
                "check controls handlers", cl->cl_user, cl->cl_group);
            }
          }
        }
      }
    }

    pr_ctrls_log(MOD_CTRLS_VERSION,
      "closed connection to %s/%s client", cl->cl_user, cl->cl_group);

    /* Remove the client from the list */
    ctrls_del_cl(cl);
    cl = tmpcl;
  }

  return 0;
}

/* Create a listening local socket */
static int ctrls_listen(const char *sock_file) {
  int sockfd = -1, len = 0;
  struct sockaddr_un sock;
#if !defined(SO_PEERCRED) && !defined(HAVE_GETPEEREID) && \
    !defined(HAVE_GETPEERUCRED) && defined(LOCAL_CREDS)
  int opt = 1;
  socklen_t optlen = sizeof(opt);
#endif /* !LOCAL_CREDS */

  /* No interruptions */
  pr_signals_block();

  /* Create the Unix domain socket */
  sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sockfd < 0) {
    int xerrno = errno;

    pr_signals_unblock();
    pr_log_pri(PR_LOG_NOTICE, MOD_CTRLS_VERSION
      ": error: unable to create local socket: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* Ensure that the socket used is not one of the major three fds (stdin,
   * stdout, or stderr).
   */
  if (sockfd <= STDERR_FILENO) {
    int res;

    res = pr_fs_get_usable_fd(sockfd);
    if (res < 0) {
      int xerrno = errno;

      pr_log_pri(PR_LOG_NOTICE, MOD_CTRLS_VERSION
        ": error duplicating ctrls socket: %s", strerror(xerrno));
      (void) close(sockfd);

      errno = xerrno;
      return -1;

    } else {
      (void) close(sockfd);
      sockfd = res;
    }
  }

  if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING,
      "unable to set CLO_EXEC on ctrls socket fd %d: %s", sockfd,
      strerror(xerrno));

    (void) close(sockfd);
    errno = xerrno;
    return -1;
  }

  /* Make sure the path to which we want to bind this socket doesn't already
   * exist.
   */
  (void) unlink(sock_file);

  /* Fill in the socket structure fields */
  memset(&sock, 0, sizeof(sock));

  sock.sun_family = AF_UNIX;
  sstrncpy(sock.sun_path, sock_file, sizeof(sock.sun_path));

  len = sizeof(sock);

  /* Bind the name to the descriptor */
  pr_trace_msg(trace_channel, 1, "binding ctrls socket fd %d to path '%s'",
    sockfd, sock.sun_path);
  if (bind(sockfd, (struct sockaddr *) &sock, len) < 0) {
    int xerrno = errno;

    pr_signals_unblock();
    (void) close(sockfd);

    errno = xerrno;
    pr_log_pri(PR_LOG_NOTICE, MOD_CTRLS_VERSION
      ": error: unable to bind to local socket: %s", strerror(xerrno));
    pr_trace_msg(trace_channel, 1, "unable to bind to local socket: %s",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* Start listening to the socket */
  if (listen(sockfd, 5) < 0) {
    int xerrno = errno;

    pr_signals_unblock();
    (void) close(sockfd);

    errno = xerrno;
    pr_log_pri(PR_LOG_NOTICE, MOD_CTRLS_VERSION
      ": error: unable to listen on local socket '%s': %s", sock.sun_path,
      strerror(xerrno));
    pr_trace_msg(trace_channel, 1, "unable to listen on local socket '%s': %s",
      sock.sun_path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

#if !defined(SO_PEERCRED) && !defined(HAVE_GETPEEREID) && \
    !defined(HAVE_GETPEERUCRED) && defined(LOCAL_CREDS)
  /* Set the LOCAL_CREDS socket option. */
  if (setsockopt(sockfd, 0, LOCAL_CREDS, &opt, optlen) < 0) {
    pr_log_debug(DEBUG0, MOD_CTRLS_VERSION ": error enabling LOCAL_CREDS: %s",
      strerror(errno));
  }
#endif /* !LOCAL_CREDS */

  /* Change the permissions on the socket, so that users can connect */
  if (chmod(sock.sun_path, (mode_t) PR_CTRLS_MODE) < 0) {
    int xerrno = errno;

    pr_signals_unblock();
    (void) close(sockfd);

    errno = xerrno;
    pr_log_pri(PR_LOG_NOTICE, MOD_CTRLS_VERSION
      ": error: unable to chmod local socket: %s", strerror(xerrno));
    pr_trace_msg(trace_channel, 1, "unable to chmod local socket: %s",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  pr_signals_unblock();
  return sockfd;
}

static int ctrls_recv_cl_reqs(void) {
  fd_set cl_rset;
  struct timeval timeout;
  uid_t cl_uid;
  gid_t cl_gid;
  pid_t cl_pid;
  unsigned long cl_flags = 0;
  int cl_fd, max_fd;

  timeout.tv_usec = 500L;
  timeout.tv_sec = 0L;

  /* look for any pending client connections */
  while (cl_listlen < cl_maxlistlen) {
    int res = 0;

    pr_signals_handle();

    if (ctrls_sockfd < 0)
      break;

    FD_ZERO(&cl_rset);
    FD_SET(ctrls_sockfd, &cl_rset);
    max_fd = ctrls_sockfd + 1;

    res = select(max_fd + 1, &cl_rset, NULL, NULL, &timeout);
    if (res == 0) {

      /* Go through the client list */
      ctrls_cls_read();

      return 0;
    }

    if (res < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
        continue;
      }

      pr_ctrls_log(MOD_CTRLS_VERSION,
        "error: unable to select on local socket: %s", strerror(errno));
      return res;
    }
 
    if (FD_ISSET(ctrls_sockfd, &cl_rset)) {

      /* Make sure the ctrl socket is non-blocking */
      if (ctrls_setnonblock(ctrls_sockfd) < 0) {
        pr_ctrls_log(MOD_CTRLS_VERSION,
          "error: unable to set nonblocking on local socket: %s",
          strerror(errno));
        return -1;
      }

      /* Accept pending connections */
      cl_fd = pr_ctrls_accept(ctrls_sockfd, &cl_uid, &cl_gid, &cl_pid,
        ctrls_cl_freshness);
      if (cl_fd < 0) {
        if (errno != ETIMEDOUT) {
          pr_ctrls_log(MOD_CTRLS_VERSION,
            "error: unable to accept connection: %s", strerror(errno));
        }

        continue;
      }

      /* Restore blocking mode to the ctrl socket */
      if (ctrls_setblock(ctrls_sockfd) < 0) {
        pr_ctrls_log(MOD_CTRLS_VERSION,
          "error: unable to set blocking on local socket: %s",
          strerror(errno));
      }

      /* Set this socket as non-blocking */
      if (ctrls_setnonblock(cl_fd) < 0) {
        pr_ctrls_log(MOD_CTRLS_VERSION,
          "error: unable to set nonblocking on client socket: %s",
          strerror(errno));
        continue;
      }

      if (!pr_ctrls_check_user_acl(cl_uid, &ctrls_sock_acl.acl_usrs) &&
          !pr_ctrls_check_group_acl(cl_gid, &ctrls_sock_acl.acl_grps)) {
        cl_flags = PR_CTRLS_CL_NOACCESS;
      }

      /* Add the client to the list */
      ctrls_add_cl(cl_fd, cl_uid, cl_gid, cl_pid, cl_flags);
    }
  }

  /* Go through the client list */
  ctrls_cls_read();

  return 0; 
}

static int ctrls_send_cl_resps(void) {

  /* Go through the client list */
  ctrls_cls_write();

  return 0;
}

static int ctrls_setblock(int sockfd) {
  int flags = 0;
  int res = -1;

  /* default error */
  errno = EBADF;

  flags = fcntl(sockfd, F_GETFL);
  res = fcntl(sockfd, F_SETFL, flags & (U32BITS ^ O_NONBLOCK));

  return res;
}

static int ctrls_setnonblock(int sockfd) {
  int flags = 0;
  int res = -1;

  /* default error */
  errno = EBADF;

  flags = fcntl(sockfd, F_GETFL);
  res = fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

  return res;
}

static int ctrls_timer_cb(CALLBACK_FRAME) {
  static unsigned char first = TRUE;

  /* If the ControlsEngine is not to run, do nothing from here on out */
  if (!ctrls_engine) {
    close(ctrls_sockfd);
    ctrls_sockfd = -1;

    if (is_master) {
      /* Remove the local socket path as well */
      (void) unlink(ctrls_sock_file);
    }

    return 0;
  }

  if (first) {
    /* Change the ownership on the socket to that configured by the admin */
    PRIVS_ROOT
    if (chown(ctrls_sock_file, ctrls_sock_uid, ctrls_sock_gid) < 0) {
      pr_log_pri(PR_LOG_NOTICE, MOD_CTRLS_VERSION
        ": unable to chown local socket %s: %s", ctrls_sock_file,
        strerror(errno));
    }
    PRIVS_RELINQUISH

    first = FALSE;
  }

  /* Please no alarms while doing this. */
  pr_alarms_block();

  /* Process pending requests. */
  ctrls_recv_cl_reqs();

  /* Run through the controls */
  pr_run_ctrls(NULL, NULL);

  /* Process pending responses */
  ctrls_send_cl_resps();

  /* Reset controls */
  pr_reset_ctrls();

  pr_alarms_unblock();
  return 1;
}

/* Controls handlers
 */

static int respcmp(const void *a, const void *b) {
  return strcmp(*((char **) a), *((char **) b));
}

static int ctrls_handle_help(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {

  /* Run through the list of registered controls, and add them to the
   * response, including the module in which they appear.
   */

  if (reqargc != 0) {
    pr_ctrls_add_response(ctrl, "wrong number of parameters");
    return -1;
  }

  if (pr_get_registered_actions(ctrl, CTRLS_GET_DESC) < 0)
    pr_ctrls_add_response(ctrl, "unable to get actions: %s", strerror(errno));

  else {

    /* Be nice, and sort the directives lexicographically */
    qsort(ctrl->ctrls_cb_resps->elts, ctrl->ctrls_cb_resps->nelts,
      sizeof(char *), respcmp);
  }

  return 0;
}

static int ctrls_handle_insctrl(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  module *m = ANY_MODULE;

  /* Enable a control into the registered controls list. This requires the
   * action and, optionally, the module of the control to be enabled.
   */

  /* Check the insctrl ACL */
  if (!pr_ctrls_check_acl(ctrl, ctrls_acttab, "insctrl")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  if (reqargc < 1 || reqargc > 2) {
    pr_ctrls_add_response(ctrl, "wrong number of parameters");
    return -1;
  }

  /* If the optional second parameter, a module name, is used, lookup
   * the module pointer matching the name.
   */
  if (reqargc == 2)
    m = pr_module_get(reqargv[1]);

  if (pr_set_registered_actions(m, reqargv[0], FALSE, 0) < 0) {

    if (errno == ENOENT)
      pr_ctrls_add_response(ctrl, "no such control: '%s'", reqargv[0]);
    else
      pr_ctrls_add_response(ctrl, "unable to enable '%s': %s", reqargv[0],
        strerror(errno));

  } else
    pr_ctrls_add_response(ctrl, "'%s' control enabled", reqargv[0]);

  return 0;
}

static int ctrls_handle_lsctrl(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {

  /* Run through the list of registered controls, and add them to the
   * response, including the module in which they appear.
   */

  /* Check the lsctrl ACL */
  if (!pr_ctrls_check_acl(ctrl, ctrls_acttab, "lsctrl")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  if (reqargc != 0) {
    pr_ctrls_add_response(ctrl, "wrong number of parameters");
    return -1;
  }

  if (pr_get_registered_actions(ctrl, CTRLS_GET_ACTION_ENABLED) < 0)
    pr_ctrls_add_response(ctrl, "unable to get actions: %s", strerror(errno));

  else {

    /* Be nice, and sort the actions lexicographically */
    qsort(ctrl->ctrls_cb_resps->elts, ctrl->ctrls_cb_resps->nelts,
      sizeof(char *), respcmp);

  }

  return 0;
}

static int ctrls_handle_rmctrl(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  module *m = ANY_MODULE;
  
  /* Disable a control from the registered controls list. This requires the
   * action and, optionally, the module of the control to be removed.
   */

  /* Check the rmctrl ACL */
  if (!pr_ctrls_check_acl(ctrl, ctrls_acttab, "rmctrl")) {

    /* Access denied */
    pr_ctrls_add_response(ctrl, "access denied");
    return -1;
  }

  if (reqargc < 1 || reqargc > 2) {
    pr_ctrls_add_response(ctrl, "wrong number of parameters");
    return -1;
  }

  /* The three controls added by this module _cannot_ be removed (at least
   * not via this control handler).
   */
  if (strncmp(reqargv[0], "insctrl", 8) == 0 ||
      strncmp(reqargv[0], "lsctrl", 7) == 0 ||
      strncmp(reqargv[0], "rmctrl", 7) == 0) {
    pr_ctrls_add_response(ctrl, "'%s' control cannot be removed", reqargv[0]);
    return -1;
  }

  /* If the optional second parameter, a module name, is used, lookup
   * the module pointer matching the name.
   */
  if (reqargc == 2)
    m = pr_module_get(reqargv[1]);

  if (pr_set_registered_actions(m, reqargv[0], FALSE,
      PR_CTRLS_ACT_DISABLED) < 0) {
    int xerrno = errno;

    if (xerrno == ENOENT) {
      pr_ctrls_add_response(ctrl, "no such control: '%s'", reqargv[0]);

    } else {
      pr_ctrls_add_response(ctrl, "unable to disable '%s': %s", reqargv[0],
        strerror(xerrno));
    }

  } else {
    if (strncmp(reqargv[0], "all", 4) != 0) {
      pr_ctrls_add_response(ctrl, "'%s' control disabled", reqargv[0]);

    } else {

      /* If all actions have been disabled, stop listening on the local
       * socket, and turn off this module's engine.
       */
      pr_ctrls_add_response(ctrl, "all controls disabled");
      pr_ctrls_add_response(ctrl, "restart the daemon to re-enable controls");

      close(ctrls_sockfd);
      ctrls_sockfd = -1;

      ctrls_engine = FALSE;
    }
  }

  return 0;
}

/* Configuration handlers
 */

/* Default behavior is to deny everyone unless an ACL has been configured */
MODRET set_ctrlsacls(cmd_rec *cmd) {
  char *bad_action = NULL, **actions = NULL;

  CHECK_ARGS(cmd, 4);
  CHECK_CONF(cmd, CONF_ROOT);

  /* Parse the given string of actions into a char **.  Then iterate
   * through the acttab, checking to see if a given control is _not_ in
   * the list.  If not in the list, unregister that control.
   */

  /* We can cheat here, and use the ctrls_parse_acl() routine to
   * separate the given string...
   */
  actions = ctrls_parse_acl(cmd->tmp_pool, cmd->argv[1]);

  /* Check the second parameter to make sure it is "allow" or "deny" */
  if (strncmp(cmd->argv[2], "allow", 6) != 0 &&
      strncmp(cmd->argv[2], "deny", 5) != 0) {
    CONF_ERROR(cmd, "second parameter must be 'allow' or 'deny'");
  }

  /* Check the third parameter to make sure it is "user" or "group" */
  if (strncmp(cmd->argv[3], "user", 5) != 0 &&
      strncmp(cmd->argv[3], "group", 6) != 0) {
    CONF_ERROR(cmd, "third parameter must be 'user' or 'group'");
  }

  bad_action = pr_ctrls_set_module_acls(ctrls_acttab, ctrls_pool, actions,
    cmd->argv[2], cmd->argv[3], cmd->argv[4]);
  if (bad_action != NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown action: '",
      bad_action, "'", NULL));
  }

  return PR_HANDLED(cmd);
}

/* default: 10 secs */
MODRET set_ctrlsauthfreshness(cmd_rec *cmd) {
  int freshness = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  freshness = atoi(cmd->argv[1]);
  if (freshness <= 0) {
    CONF_ERROR(cmd, "must be a positive number");
  }

  ctrls_cl_freshness = freshness;
  return PR_HANDLED(cmd);
}

MODRET set_ctrlsengine(cmd_rec *cmd) {
  int bool = -1;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  ctrls_engine = bool;
  return PR_HANDLED(cmd);
}

/* default: 10 secs */
MODRET set_ctrlsinterval(cmd_rec *cmd) {
  int nsecs = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  nsecs = atoi(cmd->argv[1]);
  if (nsecs <= 0) {
    CONF_ERROR(cmd, "must be a positive number");
  }

  /* Remove the existing timer, and re-install it with this new interval. */
  ctrls_interval = nsecs;

  pr_timer_remove(CTRLS_TIMER_ID, &ctrls_module);
  pr_timer_add(ctrls_interval, CTRLS_TIMER_ID, &ctrls_module, ctrls_timer_cb,
    "Controls polling");

  return PR_HANDLED(cmd);
}

MODRET set_ctrlslog(cmd_rec *cmd) {
  int res = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  ctrls_logname = pstrdup(ctrls_pool, cmd->argv[1]);

  res = ctrls_openlog();
  if (res < 0) {
    if (res == -1) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to open '",
        (char *) cmd->argv[1], "': ", strerror(errno), NULL));
    }

    if (res == -2) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "unable to log to a world-writable directory", NULL));
    }
  }

  return PR_HANDLED(cmd);
}

/* Default: 5 max clients */
MODRET set_ctrlsmaxclients(cmd_rec *cmd) {
  int nclients = 0;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  nclients = atoi(cmd->argv[1]);
  if (nclients <= 0) {
    CONF_ERROR(cmd, "must be a positive number");
  }

  cl_maxlistlen = nclients;
  return PR_HANDLED(cmd);
}

/* Default: var/run/proftpd.sock */
MODRET set_ctrlssocket(cmd_rec *cmd) {
  char *path;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  path = cmd->argv[1];
  if (*path != '/') {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  /* Close the socket. */
  if (ctrls_sockfd >= 0) {
    pr_trace_msg(trace_channel, 3, "closing ctrls socket '%s' (fd %d)",
      ctrls_sock_file, ctrls_sockfd);
    (void) unlink(ctrls_sock_file);
    (void) close(ctrls_sockfd);
    ctrls_sockfd = -1;
  }

  /* Change the path. */
  if (strcmp(path, ctrls_sock_file) != 0) {
    ctrls_sock_file = pstrdup(ctrls_pool, path);
  }

  return PR_HANDLED(cmd);
}

/* Default behavior is to deny everyone unless an ACL has been configured */
MODRET set_ctrlssocketacl(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 3);
  CHECK_CONF(cmd, CONF_ROOT);

  pr_ctrls_init_acl(&ctrls_sock_acl);

  /* Check the first argument to make sure it either "allow" or "deny" */
  if (strncmp(cmd->argv[1], "allow", 6) != 0 &&
      strncmp(cmd->argv[1], "deny", 5) != 0) {
    CONF_ERROR(cmd, "first parameter must be either 'allow' or 'deny'");
  }

  /* Check the second argument to see how to handle the directive */
  if (strncmp(cmd->argv[2], "user", 5) == 0) {
    pr_ctrls_set_user_acl(ctrls_pool, &ctrls_sock_acl.acl_usrs, cmd->argv[1],
      cmd->argv[3]);
 
  } else if (strncmp(cmd->argv[2], "group", 6) == 0) {
    pr_ctrls_set_group_acl(ctrls_pool, &ctrls_sock_acl.acl_grps, cmd->argv[1],
      cmd->argv[3]);

  } else {
    CONF_ERROR(cmd, "second parameter must be either 'user' or 'group'");
  }

  return PR_HANDLED(cmd);
}

/* Default: root root */
MODRET set_ctrlssocketowner(cmd_rec *cmd) {
  gid_t gid = 0;
  uid_t uid = 0;

  CHECK_ARGS(cmd, 2);
  CHECK_CONF(cmd, CONF_ROOT);

  uid = pr_auth_name2uid(cmd->tmp_pool, cmd->argv[1]);
  if (uid == (uid_t) -1) {
    if (errno != EINVAL) {
      pr_log_debug(DEBUG0, "%s: %s has UID of -1", (char *) cmd->argv[0],
        (char *) cmd->argv[1]);

    } else {
      pr_log_debug(DEBUG0, "%s: no such user '%s'", (char *) cmd->argv[0],
        (char *) cmd->argv[1]);
    }

  } else {
    ctrls_sock_uid = uid;
  }

  gid = pr_auth_name2gid(cmd->tmp_pool, cmd->argv[2]);
  if (gid == (gid_t) -1) {
    if (errno != EINVAL) {
      pr_log_debug(DEBUG0, "%s: %s has GID of -1", (char *) cmd->argv[0],
        (char *) cmd->argv[2]);

    } else {
      pr_log_debug(DEBUG0, "%s: no such group '%s'", (char *) cmd->argv[0],
        (char *) cmd->argv[2]);
    }

  } else {
    ctrls_sock_gid = gid;
  }

  return PR_HANDLED(cmd);
}

/* Event handlers
 */

static void ctrls_shutdown_ev(const void *event_data, void *user_data) {
  if (!is_master || !ctrls_engine)
    return;

  /* Close any connected clients */
  if (cl_list) {
    pr_ctrls_cl_t *cl = NULL;

    for (cl = cl_list; cl; cl = cl->cl_next) {
      if (cl->cl_fd >= 0) {
        (void) close(cl->cl_fd);
        cl->cl_fd = -1;
      }
    }
  }

  (void) close(ctrls_sockfd);
  ctrls_sockfd = -1;

  /* Remove the local socket path as well */
  (void) unlink(ctrls_sock_file);
  return;
}

static void ctrls_postparse_ev(const void *event_data, void *user_data) {
  if (ctrls_engine == FALSE ||
      ServerType == SERVER_INETD) {
    return;
  }

  /* Start listening on the ctrl socket */
  PRIVS_ROOT
  ctrls_sockfd = ctrls_listen(ctrls_sock_file);
  PRIVS_RELINQUISH

  /* Start a timer for the checking/processing of the ctrl socket.  */
  pr_timer_remove(CTRLS_TIMER_ID, &ctrls_module);
  pr_timer_add(ctrls_interval, CTRLS_TIMER_ID, &ctrls_module, ctrls_timer_cb,
    "Controls polling");
}

static void ctrls_restart_ev(const void *event_data, void *user_data) {
  register unsigned int i;

  /* Block alarms while we're preparing for the restart. */
  pr_alarms_block();

  /* Close any connected clients */
  if (cl_list) {
    pr_ctrls_cl_t *cl = NULL;

    for (cl = cl_list; cl; cl = cl->cl_next) {
      if (cl->cl_fd >= 0) {
        (void) close(cl->cl_fd);
        cl->cl_fd = -1;
      }
    }
  }

  /* Reset the client list */
  cl_list = NULL;
  cl_listlen = 0;

  pr_trace_msg(trace_channel, 3, "closing ctrls socket '%s' (fd %d)",
    ctrls_sock_file, ctrls_sockfd);
  close(ctrls_sockfd);
  ctrls_sockfd = -1;

  ctrls_closelog();

  /* Clear the existing pool */
  if (ctrls_pool) {
    destroy_pool(ctrls_pool);

    ctrls_logname = NULL;
    ctrls_sock_file = MOD_CTRLS_DEFAULT_SOCK;
  }

  /* Allocate the pool for this module's use */
  ctrls_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(ctrls_pool, MOD_CTRLS_VERSION);

  /* Register the control handlers */
  for (i = 0; ctrls_acttab[i].act_action; i++) {

    /* Allocate and initialize the ACL for this control. */
    ctrls_acttab[i].act_acl = pcalloc(ctrls_pool, sizeof(ctrls_acl_t));
    pr_ctrls_init_acl(ctrls_acttab[i].act_acl);
  }

  pr_timer_remove(CTRLS_TIMER_ID, &ctrls_module);
  pr_alarms_unblock();
  return;
}

/* Initialization routines
 */

static int ctrls_init(void) {
  register unsigned int i = 0; 

  /* Allocate the pool for this module's use */
  ctrls_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(ctrls_pool, MOD_CTRLS_VERSION);

  /* Register the control handlers */
  for (i = 0; ctrls_acttab[i].act_action; i++) {

    /* Allocate and initialize the ACL for this control. */
    ctrls_acttab[i].act_acl = pcalloc(ctrls_pool, sizeof(ctrls_acl_t));
    pr_ctrls_init_acl(ctrls_acttab[i].act_acl);

    if (pr_ctrls_register(&ctrls_module, ctrls_acttab[i].act_action,
        ctrls_acttab[i].act_desc, ctrls_acttab[i].act_cb) < 0) {
      pr_log_pri(PR_LOG_NOTICE, MOD_CTRLS_VERSION
        ": error registering '%s' control: %s",
        ctrls_acttab[i].act_action, strerror(errno));
    }
  }

  /* Make certain the socket ACL is initialized. */
  memset(&ctrls_sock_acl, '\0', sizeof(ctrls_acl_t));
  ctrls_sock_acl.acl_usrs.allow = ctrls_sock_acl.acl_grps.allow = FALSE;

  pr_event_register(&ctrls_module, "core.restart", ctrls_restart_ev, NULL);
  pr_event_register(&ctrls_module, "core.shutdown", ctrls_shutdown_ev, NULL);
  pr_event_register(&ctrls_module, "core.postparse", ctrls_postparse_ev, NULL);

  return 0;
}

static int ctrls_sess_init(void) {

  /* Children are not to listen for or handle control requests */
  ctrls_engine = FALSE;
  pr_timer_remove(CTRLS_TIMER_ID, &ctrls_module);

  pr_event_unregister(&ctrls_module, "core.restart", ctrls_restart_ev);

  /* Close the inherited socket */
  close(ctrls_sockfd);
  ctrls_sockfd = -1;
 
  return 0;
}

static ctrls_acttab_t ctrls_acttab[] = {
  { "help",	"describe all registered controls", NULL,
    ctrls_handle_help },
  { "insctrl",	"enable a disabled control", NULL, 
    ctrls_handle_insctrl },
  { "lsctrl",	"list all registered controls", NULL, 
    ctrls_handle_lsctrl },
  { "rmctrl",	"disable a registered control", NULL,
    ctrls_handle_rmctrl },
  { NULL, NULL, NULL, NULL }
};

/* Module API tables
 */

static conftable ctrls_conftab[] = {
  { "ControlsACLs",		set_ctrlsacls,		NULL },
  { "ControlsAuthFreshness",	set_ctrlsauthfreshness,	NULL },
  { "ControlsEngine",		set_ctrlsengine,	NULL },
  { "ControlsInterval",		set_ctrlsinterval,	NULL },
  { "ControlsLog",		set_ctrlslog,		NULL },
  { "ControlsMaxClients",	set_ctrlsmaxclients,	NULL },
  { "ControlsSocket",		set_ctrlssocket,	NULL },
  { "ControlsSocketACL",	set_ctrlssocketacl,	NULL },
  { "ControlsSocketOwner",	set_ctrlssocketowner,	NULL },
  { NULL }
};

module ctrls_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "ctrls",

  /* Module configuration handler table */
  ctrls_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  ctrls_init,

  /* Session initialization function */
  ctrls_sess_init,

  /* Module version */
  MOD_CTRLS_VERSION
};
