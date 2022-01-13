/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2019 The ProFTPD Project team
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

/* House initialization and main program loop */

#include "conf.h"

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

#ifdef HAVE_LIBUTIL_H
# include <libutil.h>
#endif /* HAVE_LIBUTIL_H */

#ifdef HAVE_UNAME
# include <sys/utsname.h>
#endif

#include "privs.h"

#ifdef PR_USE_OPENSSL
# include <openssl/opensslv.h>
#endif /* PR_USE_OPENSSL */

int (*cmd_auth_chk)(cmd_rec *);
void (*cmd_handler)(server_rec *, conn_t *);

/* From modules/module_glue.c */
extern module *static_modules[];

extern int have_dead_child;
extern xaset_t *server_list;

unsigned long max_connects = 0UL;
unsigned int max_connect_interval = 1;

session_t session;

/* Is this process the master standalone daemon process? */
unsigned char is_master = TRUE;

pid_t mpid = 0;				/* Master pid */

uid_t daemon_uid;
gid_t daemon_gid;
array_header *daemon_gids;

static time_t shut = 0, deny = 0, disc = 0;
static char shutmsg[81] = {'\0'};

/* The default command buffer size SHOULD be large enough to handle the
 * maximum path length, plus 4 bytes for the FTP command, plus 1 for the
 * whitespace separating command from path, and 2 for the terminating CRLF.
 */
#define PR_DEFAULT_CMD_BUFSZ	(PR_TUNABLE_PATH_MAX + 7)

/* From response.c */
extern pr_response_t *resp_list, *resp_err_list;

int nodaemon = 0;

static int no_forking = FALSE;
static int quiet = 0;
static int shutting_down = 0;
static int syntax_check = 0;

/* Command handling */
static void cmd_loop(server_rec *s, conn_t *conn);

static cmd_rec *make_ftp_cmd(pool *p, char *buf, size_t buflen, int flags);

static const char *config_filename = PR_CONFIG_FILE_PATH;

/* Add child semaphore fds into the rfd for selecting */
static int semaphore_fds(fd_set *rfd, int maxfd) {
  if (child_count()) {
    pr_child_t *ch;

    for (ch = child_get(NULL); ch; ch = child_get(ch)) {
      pr_signals_handle();

      if (ch->ch_pipefd != -1) {
        FD_SET(ch->ch_pipefd, rfd);
        if (ch->ch_pipefd > maxfd) {
          maxfd = ch->ch_pipefd;
        }
      }
    }
  }

  return maxfd;
}

void set_auth_check(int (*chk)(cmd_rec*)) {
  cmd_auth_chk = chk;
}

void pr_cmd_set_handler(void (*handler)(server_rec *, conn_t *)) {
  if (handler == NULL) {
    cmd_handler = cmd_loop;

  } else {
    cmd_handler = handler;
  }
}

void session_exit(int pri, void *lv, int exitval, void *dummy) {
  char *msg = (char *) lv;

  pr_log_pri(pri, "%s", msg);

  if (ServerType == SERVER_STANDALONE &&
      is_master) {
    pr_log_pri(PR_LOG_NOTICE, "ProFTPD " PROFTPD_VERSION_TEXT
      " standalone mode SHUTDOWN");

    PRIVS_ROOT
    pr_delete_scoreboard();
    if (!nodaemon)
      pr_pidfile_remove();
    PRIVS_RELINQUISH
  }

  pr_session_end(0);
}

void shutdown_end_session(void *d1, void *d2, void *d3, void *d4) {
  if (check_shutmsg(PR_SHUTMSG_PATH, &shut, &deny, &disc, shutmsg,
      sizeof(shutmsg)) == 1) {
    const char *user;
    time_t now;
    const char *msg, *serveraddress;
    config_rec *c = NULL;
    unsigned char *authenticated = get_param_ptr(main_server->conf,
      "authenticated", FALSE);

    serveraddress = (session.c && session.c->local_addr) ?
      pr_netaddr_get_ipstr(session.c->local_addr) :
      main_server->ServerAddress;

    c = find_config(main_server->conf, CONF_PARAM, "MasqueradeAddress", FALSE);
    if (c != NULL) {
      pr_netaddr_t *masq_addr = NULL;

      if (c->argv[0] != NULL) {
        masq_addr = c->argv[0];
      }

      if (masq_addr != NULL) {
        serveraddress = pr_netaddr_get_ipstr(masq_addr);
      }
    }

    time(&now);
    if (authenticated && *authenticated == TRUE) {
      user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);

    } else {
      user = "NONE";
    }

    msg = sreplace(permanent_pool, shutmsg,
                   "%s", pstrdup(permanent_pool, pr_strtime(shut)),
                   "%r", pstrdup(permanent_pool, pr_strtime(deny)),
                   "%d", pstrdup(permanent_pool, pr_strtime(disc)),
		   "%C", (session.cwd[0] ? session.cwd : "(none)"),
		   "%L", serveraddress,
		   "%R", (session.c && session.c->remote_name ?
                         session.c->remote_name : "(unknown)"),
		   "%T", pstrdup(permanent_pool, pr_strtime(now)),
		   "%U", user,
		   "%V", main_server->ServerName,
                   NULL );

    pr_response_send_async(R_421, _("FTP server shutting down - %s"), msg);

    pr_log_pri(PR_LOG_NOTICE, "%s", msg);
    pr_session_disconnect(NULL, PR_SESS_DISCONNECT_SERVER_SHUTDOWN, NULL);
  }

  if (signal(SIGUSR1, pr_signals_handle_disconnect) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGUSR1 (signal %d) handler: %s", SIGUSR1,
      strerror(errno));
  }
}

static int get_command_class(const char *name) {
  int idx = -1;
  unsigned int hash = 0;
  cmdtable *c;

  c = pr_stash_get_symbol2(PR_SYM_CMD, name, NULL, &idx, &hash);
  while (c && c->cmd_type != CMD) {
    pr_signals_handle();
    c = pr_stash_get_symbol2(PR_SYM_CMD, name, c, &idx, &hash);
  }

  /* By default, every command has a class of CL_ALL.  This insures that
   * any configured ExtendedLogs that default to "all" will log the command.
   */
  return (c ? c->cmd_class : CL_ALL);
}

static int _dispatch(cmd_rec *cmd, int cmd_type, int validate, char *match) {
  const char *cmdargstr = NULL;
  cmdtable *c;
  modret_t *mr;
  int success = 0, xerrno = 0;
  int send_error = 0;
  static int match_index_cache = -1;
  static unsigned int match_hash_cache = 0;
  static char *last_match = NULL;
  int *index_cache = NULL;
  unsigned int *hash_cache = NULL;

  send_error = (cmd_type == PRE_CMD || cmd_type == CMD ||
    cmd_type == POST_CMD_ERR);

  if (!match) {
    match = cmd->argv[0];
    index_cache = &cmd->stash_index;
    hash_cache = &cmd->stash_hash;

  } else {
    if (last_match != match) {
      match_index_cache = -1;
      last_match = match;
    }

    index_cache = &match_index_cache;
    hash_cache = &match_hash_cache;
  }

  c = pr_stash_get_symbol2(PR_SYM_CMD, match, NULL, index_cache, hash_cache);

  while (c && !success) {
    size_t cmdargstrlen = 0;

    pr_signals_handle();

    session.curr_cmd = cmd->argv[0];
    session.curr_cmd_id = cmd->cmd_id;
    session.curr_cmd_rec = cmd;
    session.curr_phase = cmd_type;

    if (c->cmd_type == cmd_type) {
      if (c->group) {
        cmd->group = pstrdup(cmd->pool, c->group);
      }

      if (c->requires_auth &&
          cmd_auth_chk &&
          !cmd_auth_chk(cmd)) {
        pr_trace_msg("command", 8,
          "command '%s' failed 'requires_auth' check for mod_%s.c",
          (char *) cmd->argv[0], c->m->name);
        errno = EACCES;
        return -1;
      }

      if (cmd->tmp_pool == NULL) {
        cmd->tmp_pool = make_sub_pool(cmd->pool);
        pr_pool_tag(cmd->tmp_pool, "cmd_rec tmp pool");
      }

      cmdargstr = pr_cmd_get_displayable_str(cmd, &cmdargstrlen);

      if (cmd_type == CMD) {

        /* The client has successfully authenticated... */
        if (session.user) {
          char *args = NULL;

          /* Be defensive, and check whether cmdargstrlen has a value.
           * If it's zero, assume we need to use strchr(3), rather than
           * memchr(2); see Bug#3714.
           */
          if (cmdargstrlen > 0) {
            args = memchr(cmdargstr, ' ', cmdargstrlen);

          } else {
            args = strchr(cmdargstr, ' ');
          }

          pr_scoreboard_entry_update(session.pid,
            PR_SCORE_CMD, "%s", cmd->argv[0], NULL, NULL);
          pr_scoreboard_entry_update(session.pid,
            PR_SCORE_CMD_ARG, "%s", args ? (args + 1) : "", NULL, NULL);

          pr_proctitle_set("%s - %s: %s", session.user, session.proc_prefix,
            cmdargstr);

        /* ...else the client has not yet authenticated */
        } else {
          pr_proctitle_set("%s:%d: %s", session.c->remote_addr ?
            pr_netaddr_get_ipstr(session.c->remote_addr) : "?",
            session.c->remote_port ? session.c->remote_port : 0, cmdargstr);
        }
      }

      /* Skip logging the internal CONNECT/DISCONNECT commands. */
      if (!(cmd->cmd_class & CL_CONNECT) &&
          !(cmd->cmd_class & CL_DISCONNECT)) {

        pr_log_debug(DEBUG4, "dispatching %s command '%s' to mod_%s",
          (cmd_type == PRE_CMD ? "PRE_CMD" :
           cmd_type == CMD ? "CMD" :
           cmd_type == POST_CMD ? "POST_CMD" :
           cmd_type == POST_CMD_ERR ? "POST_CMD_ERR" :
           cmd_type == LOG_CMD ? "LOG_CMD" :
           cmd_type == LOG_CMD_ERR ? "LOG_CMD_ERR" :
           "(unknown)"),
          cmdargstr, c->m->name);

        pr_trace_msg("command", 7, "dispatching %s command '%s' to mod_%s.c",
          (cmd_type == PRE_CMD ? "PRE_CMD" :
           cmd_type == CMD ? "CMD" :
           cmd_type == POST_CMD ? "POST_CMD" :
           cmd_type == POST_CMD_ERR ? "POST_CMD_ERR" :
           cmd_type == LOG_CMD ? "LOG_CMD" :
           cmd_type == LOG_CMD_ERR ? "LOG_CMD_ERR" :
           "(unknown)"),
          cmdargstr, c->m->name);
      }

      cmd->cmd_class |= c->cmd_class;

      /* KLUDGE: disable umask() for not G_WRITE operations.  Config/
       * Directory walking code will be completely redesigned in 1.3,
       * this is only necessary for performance reasons in 1.1/1.2
       */

      if (!c->group || strcmp(c->group, G_WRITE) != 0)
        kludge_disable_umask();
      mr = pr_module_call(c->m, c->handler, cmd);
      kludge_enable_umask();

      if (MODRET_ISHANDLED(mr)) {
        success = 1;

      } else if (MODRET_ISERROR(mr)) {
        xerrno = errno;
        success = -1;

        if (cmd_type == POST_CMD ||
            cmd_type == LOG_CMD ||
            cmd_type == LOG_CMD_ERR) {
          if (MODRET_ERRMSG(mr)) {
            pr_log_pri(PR_LOG_NOTICE, "%s", MODRET_ERRMSG(mr));
          }

          /* Even though we normally want to return a negative value
           * for success (indicating lack of success), for
           * LOG_CMD/LOG_CMD_ERR handlers, we always want to handle
           * errors as a success value of zero (meaning "keep looking").
           *
           * This will allow the cmd_rec to continue to be dispatched to
           * the other interested handlers (Bug#3633).
           */
          if (cmd_type == LOG_CMD || 
              cmd_type == LOG_CMD_ERR) {
            success = 0;
          }

        } else if (send_error) {
          if (MODRET_ERRNUM(mr) &&
              MODRET_ERRMSG(mr)) {
            pr_response_add_err(MODRET_ERRNUM(mr), "%s", MODRET_ERRMSG(mr));

          } else if (MODRET_ERRMSG(mr)) {
            pr_response_send_raw("%s", MODRET_ERRMSG(mr));
          }
        }

        errno = xerrno;
      }

      if (session.user &&
          !(session.sf_flags & SF_XFER) &&
          cmd_type == CMD) {
        pr_session_set_idle();
      }

      destroy_pool(cmd->tmp_pool);
      cmd->tmp_pool = NULL;
    }

    if (!success) {
      c = pr_stash_get_symbol2(PR_SYM_CMD, match, c, index_cache, hash_cache);
    }
  }

  /* Note: validate is only TRUE for the CMD phase, for specific handlers
   * (as opposed to any C_ANY handlers).
   */

  if (!c &&
      !success &&
      validate) {
    char *method;

    /* Prettify the command method, if need be. */
    if (strchr(cmd->argv[0], '_') == NULL) {
      method = cmd->argv[0];

    } else {
      register unsigned int i;

      method = pstrdup(cmd->pool, cmd->argv[0]);
      for (i = 0; method[i]; i++) {
        if (method[i] == '_')
          method[i] = ' ';
      }
    }

    pr_event_generate("core.unhandled-command", cmd);

    pr_response_add_err(R_500, _("%s not understood"), method);
    success = -1;
  }

  return success;
}

/* Returns the appropriate maximum buffer size to use for FTP commands
 * from the client.
 */
static size_t get_max_cmd_sz(void) {
  size_t res;
  size_t *bufsz = NULL;

  bufsz = get_param_ptr(main_server->conf, "CommandBufferSize", FALSE);
  if (bufsz == NULL) {
    res = PR_DEFAULT_CMD_BUFSZ;

  } else {
    pr_log_debug(DEBUG1, "setting CommandBufferSize to %lu",
      (unsigned long) *bufsz);
    res = *bufsz;
  }

  return res;
}

int pr_cmd_read(cmd_rec **res) {
  static long cmd_bufsz = -1;
  static char *cmd_buf = NULL;
  int cmd_buflen;
  unsigned int too_large_count = 0;
  char *ptr;

  if (res == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (cmd_bufsz == -1) {
    cmd_bufsz = get_max_cmd_sz();
  }

  if (cmd_buf == NULL) {
    cmd_buf = pcalloc(session.pool, cmd_bufsz + 1);
  }

  while (TRUE) {
    pr_signals_handle();

    memset(cmd_buf, '\0', cmd_bufsz);

    cmd_buflen = pr_netio_telnet_gets2(cmd_buf, cmd_bufsz, session.c->instrm,
      session.c->outstrm);
    if (cmd_buflen < 0) {
      if (errno == E2BIG) {
        /* The client sent a too-long command which was ignored; give
         * them a few more chances, with minor delays?
         */
        too_large_count++;
        pr_timer_usleep(250 * 1000);

        if (too_large_count > 3) {
          return -1;
        }

        continue;
      }

      if (session.c->instrm->strm_errno == 0) {
        pr_trace_msg("command", 6,
          "client sent EOF, closing control connection");
      }

      return -1;
    }

    break;
  }

  /* If the read length is less than the cmd_bufsz, then there is no need to
   * truncate the buffer by inserting a NUL.
   */
  if (cmd_buflen > cmd_bufsz) {
    pr_log_debug(DEBUG0, "truncating incoming command length (%d bytes) to "
      "CommandBufferSize %lu; use the CommandBufferSize directive to increase "
      "the allowed command length", cmd_buflen, (unsigned long) cmd_bufsz);
    cmd_buf[cmd_bufsz-1] = '\0';
  }

  if (cmd_buflen > 0 &&
      (cmd_buf[cmd_buflen-1] == '\n' || cmd_buf[cmd_buflen-1] == '\r')) {
    cmd_buf[cmd_buflen-1] = '\0';
    cmd_buflen--;

    if (cmd_buflen > 0 &&
        (cmd_buf[cmd_buflen-1] == '\n' || cmd_buf[cmd_buflen-1] =='\r')) {
      cmd_buf[cmd_buflen-1] = '\0';
      cmd_buflen--;
    }
  }

  ptr = cmd_buf;
  if (*ptr == '\r') {
    ptr++;
  }

  if (*ptr) {
    int flags = 0;
    cmd_rec *cmd;

    /* If this is a SITE command, preserve embedded whitespace in the
     * command parameters, in order to handle file names that have multiple
     * spaces in the names.  Arguably this should be handled in the SITE
     * command handlers themselves, via cmd->arg.  This small hack
     * reduces the burden on SITE module developers, however.
     */
    if (strncasecmp(ptr, C_SITE, 4) == 0) {
      flags |= PR_STR_FL_PRESERVE_WHITESPACE;
    }

    cmd = make_ftp_cmd(session.pool, ptr, cmd_buflen, flags);
    if (cmd != NULL) {
      *res = cmd;

      if (pr_cmd_is_http(cmd) == TRUE) {
        cmd->is_ftp = FALSE;
        cmd->protocol = "HTTP";

      } else if (pr_cmd_is_ssh2(cmd) == TRUE) {
        cmd->is_ftp = FALSE;
        cmd->protocol = "SSH2";

      } else if (pr_cmd_is_smtp(cmd) == TRUE) {
        cmd->is_ftp = FALSE;
        cmd->protocol = "SMTP";

      } else {
        /* Assume that the client is sending valid FTP commands. */
        cmd->is_ftp = TRUE;
        cmd->protocol = "FTP";
      }
    } 
  }

  return 0;
}

static int set_cmd_start_ms(cmd_rec *cmd) {
  void *v;
  uint64_t start_ms;

  if (cmd->notes == NULL) {
    return 0;
  }

  v = (void *) pr_table_get(cmd->notes, "start_ms", NULL);
  if (v != NULL) {
    return 0;
  }

  if (pr_gettimeofday_millis(&start_ms) < 0) {
    return -1;
  }

  v = palloc(cmd->pool, sizeof(uint64_t));
  memcpy(v, &start_ms, sizeof(uint64_t));

  return pr_table_add(cmd->notes, "start_ms", v, sizeof(uint64_t));
}

int pr_cmd_dispatch_phase(cmd_rec *cmd, int phase, int flags) {
  char *cp = NULL;
  int success = 0, xerrno = 0;
  pool *resp_pool = NULL;

  if (cmd == NULL) {
    errno = EINVAL;
    return -1;
  }

  cmd->server = main_server;

  if (flags & PR_CMD_DISPATCH_FL_CLEAR_RESPONSE) {
    /* Skip logging the internal CONNECT/DISCONNECT commands. */
    if (!(cmd->cmd_class & CL_CONNECT) &&
        !(cmd->cmd_class & CL_DISCONNECT)) {
      pr_trace_msg("response", 9,
        "clearing response lists before dispatching command '%s'",
        (char *) cmd->argv[0]);
    }
    pr_response_clear(&resp_list);
    pr_response_clear(&resp_err_list);
  }

  /* Get any previous pool that may be being used by the Response API.
   *
   * In most cases, this will be NULL.  However, if proftpd is in the
   * midst of a data transfer when a command comes in on the control
   * connection, then the pool in use will be that of the data transfer
   * instigating command.  We want to stash that pool, so that after this
   * command is dispatched, we can return the pool of the old command.
   * Otherwise, Bad Things (segfaults) happen.
   */
  resp_pool = pr_response_get_pool();

  /* Set the pool used by the Response API for this command. */
  pr_response_set_pool(cmd->pool);

  for (cp = cmd->argv[0]; *cp; cp++) {
    *cp = toupper(*cp);
  }

  if (cmd->cmd_class == 0) {
    cmd->cmd_class = get_command_class(cmd->argv[0]);
  }

  if (cmd->cmd_id == 0) {
    cmd->cmd_id = pr_cmd_get_id(cmd->argv[0]);
  }

  set_cmd_start_ms(cmd);

  if (phase == 0) {
    /* First, dispatch to wildcard PRE_CMD handlers. */
    success = _dispatch(cmd, PRE_CMD, FALSE, C_ANY);

    if (!success)	/* run other pre_cmd */
      success = _dispatch(cmd, PRE_CMD, FALSE, NULL);

    if (success < 0) {
      /* Dispatch to POST_CMD_ERR handlers as well. */

      _dispatch(cmd, POST_CMD_ERR, FALSE, C_ANY);
      _dispatch(cmd, POST_CMD_ERR, FALSE, NULL);

      _dispatch(cmd, LOG_CMD_ERR, FALSE, C_ANY);
      _dispatch(cmd, LOG_CMD_ERR, FALSE, NULL);

      xerrno = errno;
      pr_trace_msg("response", 9, "flushing error response list for '%s'",
        (char *) cmd->argv[0]);
      pr_response_flush(&resp_err_list);

      /* Restore any previous pool to the Response API. */
      pr_response_set_pool(resp_pool);

      errno = xerrno;
      return success;
    }

    success = _dispatch(cmd, CMD, FALSE, C_ANY);
    if (!success)
      success = _dispatch(cmd, CMD, TRUE, NULL);

    if (success == 1) {
      success = _dispatch(cmd, POST_CMD, FALSE, C_ANY);
      if (!success)
        success = _dispatch(cmd, POST_CMD, FALSE, NULL);

      _dispatch(cmd, LOG_CMD, FALSE, C_ANY);
      _dispatch(cmd, LOG_CMD, FALSE, NULL);

      xerrno = errno;
      pr_trace_msg("response", 9, "flushing response list for '%s'",
        (char *) cmd->argv[0]);
      pr_response_flush(&resp_list);

      errno = xerrno;

    } else if (success < 0) {
      /* Allow for non-logging command handlers to be run if CMD fails. */

      success = _dispatch(cmd, POST_CMD_ERR, FALSE, C_ANY);
      if (!success)
        success = _dispatch(cmd, POST_CMD_ERR, FALSE, NULL);

      _dispatch(cmd, LOG_CMD_ERR, FALSE, C_ANY);
      _dispatch(cmd, LOG_CMD_ERR, FALSE, NULL);

      xerrno = errno;
      pr_trace_msg("response", 9, "flushing error response list for '%s'",
        (char *) cmd->argv[0]);
      pr_response_flush(&resp_err_list);

      errno = xerrno;
    }

  } else {
    switch (phase) {
      case PRE_CMD:
      case POST_CMD:
      case POST_CMD_ERR:
        success = _dispatch(cmd, phase, FALSE, C_ANY);
        if (!success) {
          success = _dispatch(cmd, phase, FALSE, NULL);
          xerrno = errno;
        }
        break;

      case CMD:
        success = _dispatch(cmd, phase, FALSE, C_ANY);
        if (!success)
          success = _dispatch(cmd, phase, TRUE, NULL);
        break;

      case LOG_CMD:
      case LOG_CMD_ERR:
        (void) _dispatch(cmd, phase, FALSE, C_ANY);
        (void) _dispatch(cmd, phase, FALSE, NULL);
        break;

      default:
        /* Restore any previous pool to the Response API. */
        pr_response_set_pool(resp_pool);

        errno = EINVAL;
        return -1;
    }

    if (flags & PR_CMD_DISPATCH_FL_SEND_RESPONSE) {
      xerrno = errno;

      if (success == 1) {
        pr_trace_msg("response", 9, "flushing response list for '%s'",
          (char *) cmd->argv[0]);
        pr_response_flush(&resp_list);

      } else if (success < 0) {
        pr_trace_msg("response", 9, "flushing error response list for '%s'",
          (char *) cmd->argv[0]);
        pr_response_flush(&resp_err_list);
      }

      errno = xerrno;
    }
  }

  /* Restore any previous pool to the Response API. */
  pr_response_set_pool(resp_pool);

  errno = xerrno;
  return success;
}

int pr_cmd_dispatch(cmd_rec *cmd) {
  return pr_cmd_dispatch_phase(cmd, 0,
    PR_CMD_DISPATCH_FL_SEND_RESPONSE|PR_CMD_DISPATCH_FL_CLEAR_RESPONSE);
}

static cmd_rec *make_ftp_cmd(pool *p, char *buf, size_t buflen, int flags) {
  register unsigned int i, j;
  char *arg, *ptr, *wrd;
  size_t arg_len;
  cmd_rec *cmd;
  pool *subpool;
  array_header *tarr;
  int have_crnul = FALSE, str_flags = PR_STR_FL_PRESERVE_COMMENTS|flags;

  /* Be pedantic (and RFC-compliant) by not allowing leading whitespace
   * in an issued FTP command.  Will this cause troubles with many clients?
   */
  if (PR_ISSPACE(buf[0])) {
    pr_trace_msg("ctrl", 5,
      "command '%s' has illegal leading whitespace, rejecting", buf);
    errno = EINVAL;
    return NULL;
  }

  ptr = buf;
  wrd = pr_str_get_word(&ptr, str_flags);
  if (wrd == NULL) {
    /* Nothing there...bail out. */
    pr_trace_msg("ctrl", 5, "command '%s' is empty, ignoring", buf);
    errno = ENOENT;
    return NULL;
  }

  subpool = make_sub_pool(p);
  pr_pool_tag(subpool, "make_ftp_cmd pool");
  cmd = pcalloc(subpool, sizeof(cmd_rec));
  cmd->pool = subpool;
  cmd->tmp_pool = NULL;
  cmd->stash_index = -1;
  cmd->stash_hash = 0;

  tarr = make_array(cmd->pool, 2, sizeof(char *));

  *((char **) push_array(tarr)) = pstrdup(cmd->pool, wrd);
  cmd->argc++;

  /* Make a copy of the command argument; we need to scan through it,
   * looking for any CR+NUL sequences, per RFC 2460, Section 3.1.
   *
   * Note for future readers that this scanning may cause problems for
   * commands such as ADAT, ENC, and MIC.  Per RFC 2228, the arguments for
   * these commands are base64-encoded Telnet strings, thus there is no
   * chance of them containing CRNUL sequences.  Any modules which implement
   * the translating of those arguments, e.g. mod_gss, will need to ensure
   * it does the proper handling of CRNUL sequences itself.
   */
  arg_len = buflen - strlen(wrd);
  arg = pcalloc(cmd->pool, arg_len + 1);

  for (i = 0, j = 0; i < arg_len; i++) {
    pr_signals_handle();
    if (i > 1 &&
        ptr[i] == '\0' &&
        ptr[i-1] == '\r') {

      /* Strip out the NUL by simply not copying it into the new buffer. */
      have_crnul = TRUE;
    } else {
      arg[j++] = ptr[i];
    }
  }

  cmd->arg = arg;

  if (have_crnul) {
    char *dup_arg;

    /* Now make a copy of the stripped argument; this is what we need to
     * tokenize into words, for further command dispatching/processing.
     */
    dup_arg = pstrdup(cmd->pool, arg);
    ptr = dup_arg;
  }

  while ((wrd = pr_str_get_word(&ptr, str_flags)) != NULL) {
    pr_signals_handle();
    *((char **) push_array(tarr)) = pstrdup(cmd->pool, wrd);
    cmd->argc++;
  }

  *((char **) push_array(tarr)) = NULL;
  cmd->argv = tarr->elts;

  /* This table will not contain that many entries, so a low number
   * of chains should suffice.
   */
  cmd->notes = pr_table_nalloc(cmd->pool, 0, 8);
  return cmd;
}

static void cmd_loop(server_rec *server, conn_t *c) {

  while (TRUE) {
    int res = 0; 
    cmd_rec *cmd = NULL;

    pr_signals_handle();

    res = pr_cmd_read(&cmd);
    if (res < 0) {
      if (PR_NETIO_ERRNO(session.c->instrm) == EINTR) {
        /* Simple interrupted syscall */
        continue;
      }

#ifndef PR_DEVEL_NO_DAEMON
      /* Otherwise, EOF */
      pr_session_disconnect(NULL, PR_SESS_DISCONNECT_CLIENT_EOF, NULL);
#else
      return;
#endif /* PR_DEVEL_NO_DAEMON */
    }

    /* Data received, reset idle timer */
    if (pr_data_get_timeout(PR_DATA_TIMEOUT_IDLE) > 0) {
      pr_timer_reset(PR_TIMER_IDLE, ANY_MODULE);
    }

    if (cmd) {

      /* Detect known commands for other protocols; if found, drop the
       * connection, lest we be used as part of an attack on a different
       * protocol server (Bug#4143).
       */
      if (cmd->is_ftp == FALSE) {
        pr_log_pri(PR_LOG_WARNING,
          "client sent %s command '%s', disconnecting", cmd->protocol,
          (char *) cmd->argv[0]);
        pr_event_generate("core.bad-protocol", cmd);
        pr_session_disconnect(NULL, PR_SESS_DISCONNECT_BAD_PROTOCOL,
          cmd->protocol);
      }
 
      pr_cmd_dispatch(cmd);
      destroy_pool(cmd->pool);

    } else {
      pr_event_generate("core.invalid-command", NULL);
      pr_response_send(R_500, _("Invalid command: try being more creative"));
    }

    /* Release any working memory allocated in inet */
    pr_inet_clear();
  }
}

void restart_daemon(void *d1, void *d2, void *d3, void *d4) {
  if (is_master && mpid) {
    int maxfd;
    fd_set childfds;
    struct timeval restart_start, restart_finish;
    long restart_elapsed = 0;

    pr_log_pri(PR_LOG_NOTICE, "received SIGHUP -- master server reparsing "
      "configuration file");

    gettimeofday(&restart_start, NULL);

    /* Make sure none of our children haven't completed start up */
    FD_ZERO(&childfds);
    maxfd = -1;

    maxfd = semaphore_fds(&childfds, maxfd);
    if (maxfd > -1) {
      pr_log_pri(PR_LOG_NOTICE, "waiting for child processes to complete "
        "initialization");

      while (maxfd != -1) {
	int i;
	
	i = select(maxfd + 1, &childfds, NULL, NULL, NULL);

        if (i > 0) {
          pr_child_t *ch;

          for (ch = child_get(NULL); ch; ch = child_get(ch)) {
            if (ch->ch_pipefd != -1 &&
               FD_ISSET(ch->ch_pipefd, &childfds)) {
              (void) close(ch->ch_pipefd);
              ch->ch_pipefd = -1;
            }
          }
        }

	FD_ZERO(&childfds);
        maxfd = -1;
	maxfd = semaphore_fds(&childfds, maxfd);
      }
    }

    free_bindings();

    /* Run through the list of registered restart callbacks. */
    pr_event_generate("core.restart", NULL);

    init_log();
    init_netaddr();
    init_class();
    init_config();
    init_dirtree();

#ifdef PR_USE_NLS
    encode_free();
#endif /* PR_USE_NLS */

    pr_netaddr_clear_cache();

    pr_parser_prepare(NULL, NULL);

    pr_event_generate("core.preparse", NULL);

    PRIVS_ROOT
    if (pr_parser_parse_file(NULL, config_filename, NULL, 0) < 0) {
      int xerrno = errno;

      PRIVS_RELINQUISH

      /* Note: EPERM is used to indicate the presence of unrecognized
       * configuration directives in the parsed file(s).
       */
      if (xerrno != EPERM) {
        pr_log_pri(PR_LOG_WARNING,
          "fatal: unable to read configuration file '%s': %s", config_filename,
          strerror(xerrno));
      }

      pr_session_end(0);
    }
    PRIVS_RELINQUISH

    if (pr_parser_cleanup() < 0) {
      pr_log_pri(PR_LOG_WARNING,
        "fatal: error processing configuration file '%s': "
        "unclosed configuration section", config_filename);
      pr_session_end(0);
    }

#ifdef PR_USE_NLS
    encode_init();
#endif /* PR_USE_NLS */

    /* After configuration is complete, make sure that passwd, group
     * aren't held open (unnecessary fds for master daemon)
     */
    endpwent();
    endgrent();

    if (fixup_servers(server_list) < 0) {
      pr_log_pri(PR_LOG_WARNING,
        "fatal: error processing configuration file '%s'", config_filename);
      pr_session_end(0);
    }

    pr_event_generate("core.postparse", NULL);

    /* Recreate the listen connection.  Can an inetd-spawned server accept
     * and process HUP?
     */
    init_bindings();

    gettimeofday(&restart_finish, NULL);

    restart_elapsed = ((restart_finish.tv_sec - restart_start.tv_sec) * 1000L) +
      ((restart_finish.tv_usec - restart_start.tv_usec) / 1000L);
    pr_trace_msg("config", 12, "restart took %ld millisecs", restart_elapsed);
      
  } else {

    /* Child process -- cannot restart, log error */
    pr_log_pri(PR_LOG_ERR, "received SIGHUP, cannot restart child process");
  }
}

static void set_server_privs(void) {
  uid_t server_uid, current_euid = geteuid();
  gid_t server_gid, current_egid = getegid();
  unsigned char switch_server_id = FALSE;

  uid_t *uid = get_param_ptr(main_server->conf, "UserID", FALSE);
  gid_t *gid =  get_param_ptr(main_server->conf, "GroupID", FALSE);

  if (uid) {
    server_uid = *uid;
    switch_server_id = TRUE;

  } else
    server_uid = current_euid;

  if (gid) {
    server_gid = *gid;
    switch_server_id = TRUE;

  } else
    server_gid = current_egid;

  if (switch_server_id) {
    PRIVS_ROOT

    /* Note: will it be necessary to double check this switch, as is done
     * in elsewhere in this file?
     */
    PRIVS_SETUP(server_uid, server_gid);
  }
}

static void fork_server(int fd, conn_t *l, unsigned char no_fork) {
  conn_t *conn = NULL;
  int i, rev;
  int semfds[2] = { -1, -1 };
  int xerrno = 0;

#ifndef PR_DEVEL_NO_FORK
  pid_t pid;
  sigset_t sig_set;

  if (no_fork == FALSE) {

    /* A race condition exists on heavily loaded servers where the parent
     * catches SIGHUP and attempts to close/re-open the main listening
     * socket(s), however the children haven't finished closing them
     * (EADDRINUSE).  We use a semaphore pipe here to flag the parent once
     * the child has closed all former listening sockets.
     */

    if (pipe(semfds) == -1) {
      pr_log_pri(PR_LOG_ALERT, "pipe(2) failed: %s", strerror(errno));
      (void) close(fd);
      return;
    }

    /* Need to make sure the child (writer) end of the pipe isn't
     * < 2 (stdio/stdout/stderr) as this will cause problems later.
     */
    semfds[1] = pr_fs_get_usable_fd(semfds[1]);

    /* Make sure we set the close-on-exec flag for the parent's read side
     * of the pipe.
     */
    (void) fcntl(semfds[0], F_SETFD, FD_CLOEXEC);

    /* We block SIGCHLD to prevent a race condition if the child
     * dies before we can record it's pid.  Also block SIGTERM to
     * prevent sig_terminate() from examining the child list
     */

    sigemptyset(&sig_set);
    sigaddset(&sig_set, SIGTERM);
    sigaddset(&sig_set, SIGCHLD);
    sigaddset(&sig_set, SIGUSR1);
    sigaddset(&sig_set, SIGUSR2);

    if (sigprocmask(SIG_BLOCK, &sig_set, NULL) < 0) {
      pr_log_pri(PR_LOG_NOTICE,
        "unable to block signal set: %s", strerror(errno));
    }

    pid = fork();
    xerrno = errno;

    switch (pid) {

    case 0: /* child */
      /* No longer the master process. */
      is_master = FALSE;
      if (sigprocmask(SIG_UNBLOCK, &sig_set, NULL) < 0) {
        pr_log_pri(PR_LOG_NOTICE,
          "unable to unblock signal set: %s", strerror(errno));
      }

      /* No longer need the read side of the semaphore pipe. */
      (void) close(semfds[0]);
      break;

    case -1:
      if (sigprocmask(SIG_UNBLOCK, &sig_set, NULL) < 0) {
        pr_log_pri(PR_LOG_NOTICE,
          "unable to unblock signal set: %s", strerror(errno));
      }

      pr_log_pri(PR_LOG_ALERT, "unable to fork(): %s", strerror(xerrno));

      /* The parent doesn't need the socket open. */
      (void) close(fd);
      (void) close(semfds[0]);
      (void) close(semfds[1]);

      return;

    default: /* parent */
      /* The parent doesn't need the socket open */
      (void) close(fd);

      child_add(pid, semfds[0]);
      (void) close(semfds[1]);

      /* Unblock the signals now as sig_child() will catch
       * an "immediate" death and remove the pid from the children list
       */
      if (sigprocmask(SIG_UNBLOCK, &sig_set, NULL) < 0) {
        pr_log_pri(PR_LOG_NOTICE,
          "unable to unblock signal set: %s", strerror(errno));
      }

      return;
    }
  }

  session.pid = getpid();

  /* No longer need any listening fds. */
  pr_ipbind_close_listeners();

  /* There would appear to be no useful purpose behind setting the process
   * group of the newly forked child.  In daemon/inetd mode, we should have no
   * controlling tty and either have the process group of the parent or of
   * inetd.  In non-daemon mode (-n), doing this may cause SIGTTOU to be
   * raised on output to the terminal (stderr logging).
   *
   * #ifdef HAVE_SETPGID
   *   setpgid(0,getpid());
   * #else
   * # ifdef SETPGRP_VOID
   *   setpgrp();
   * # else
   *   setpgrp(0,getpid());
   * # endif
   * #endif
   *
   */

  /* Reseed pseudo-randoms */
  pr_random_init();

#endif /* PR_DEVEL_NO_FORK */

  /* Child is running here */
  if (signal(SIGUSR1, pr_signals_handle_disconnect) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGUSR1 (signal %d) handler: %s", SIGUSR1,
      strerror(errno));
  }

  if (signal(SIGUSR2, pr_signals_handle_event) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGUSR2 (signal %d) handler: %s", SIGUSR2,
      strerror(errno));
  }

  if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGCHLD (signal %d) handler: %s", SIGCHLD,
      strerror(errno));
  }

  if (signal(SIGHUP, SIG_IGN) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGHUP (signal %d) handler: %s", SIGHUP,
      strerror(errno));
  }

  /* From this point on, syslog stays open. We close it first so that the
   * logger will pick up our new PID.
   *
   * We have to delay calling log_opensyslog() until after pr_inet_openrw()
   * is called, otherwise the potential exists for the syslog FD to
   * be overwritten and the user to see logging information.
   *
   * This isn't that big of a deal because the logging functions will
   * just open it dynamically if they need to.
   */
  log_closesyslog();

  /* Specifically DO NOT perform reverse DNS at this point, to alleviate
   * the race condition mentioned above.  Instead we do it after closing
   * all former listening sockets.
   */
  conn = pr_inet_openrw(permanent_pool, l, NULL, PR_NETIO_STRM_CTRL, fd,
    STDIN_FILENO, STDOUT_FILENO, FALSE);

  /* Capture errno here, if necessary. */
  if (conn == NULL) {
    xerrno = errno;
  }

  /* Now do the permanent syslog open
   */
  pr_signals_block();
  PRIVS_ROOT

  log_opensyslog(NULL);

  PRIVS_RELINQUISH
  pr_signals_unblock();

  if (conn == NULL) {
    /* There are some errors, e.g. ENOTCONN ("Transport endpoint is not
     * connected") which can easily happen, as during scans/TCP
     * probes/healthchecks, commonly done by load balancers, firewalls, and
     * other clients.  By the time proftpd reaches the point of looking up
     * the peer data for that connection, the client has disconnected.
     *
     * These are normal errors, and thus should not be logged as fatal
     * conditions.
     */
    if (xerrno == ENOTCONN ||
        xerrno == ECONNABORTED ||
        xerrno == ECONNRESET) {
      pr_log_pri(PR_LOG_DEBUG, "unable to open incoming connection: %s",
        strerror(xerrno));

    } else {
      pr_log_pri(PR_LOG_ERR, "fatal: unable to open incoming connection: %s",
        strerror(xerrno));
    }

    exit(1);
  }

  pr_gettimeofday_millis(&session.connect_time_ms);
  pr_event_generate("core.connect", conn);

  /* Find the server for this connection. */
  main_server = pr_ipbind_get_server(conn->local_addr, conn->local_port);

  /* Make sure we allocate a session pool, even if this connection will
   * dropped soon.
   */
  session.pool = make_sub_pool(permanent_pool);
  pr_pool_tag(session.pool, "Session Pool");

  session.c = conn;
  session.data_port = conn->remote_port - 1;
  session.sf_flags = 0;
  session.sp_flags = 0;
  session.proc_prefix = "(connecting)";

  /* If no server is configured to handle the addr the user is connected to,
   * drop them.
   */
  if (main_server == NULL) {
    pr_log_debug(DEBUG2, "No server configuration found for IP address %s",
      pr_netaddr_get_ipstr(conn->local_addr));
    pr_log_debug(DEBUG2, "Use the DefaultServer directive to designate "
      "a default server configuration to handle requests like this");

    pr_response_send(R_500,
      _("Sorry, no server available to handle request on %s"),
      pr_netaddr_get_dnsstr(conn->local_addr));
    exit(0);
  }

  pr_inet_set_proto_opts(permanent_pool, conn, 0, 1, IPTOS_LOWDELAY, 0);

  /* Close the write side of the semaphore pipe to tell the parent
   * we are all grown up and have finished housekeeping (closing
   * former listen sockets).
   */
  close(semfds[1]);

  /* Now perform reverse DNS lookups. */
  if (ServerUseReverseDNS) {
    rev = pr_netaddr_set_reverse_dns(ServerUseReverseDNS);

    if (conn->remote_addr)
      conn->remote_name = pr_netaddr_get_dnsstr(conn->remote_addr);

    pr_netaddr_set_reverse_dns(rev);
  }

  pr_netaddr_set_sess_addrs();

  /* Check and see if we are shutting down. */
  if (shutting_down) {
    time_t now;

    time(&now);
    if (!deny || deny <= now) {
      config_rec *c = NULL;
      const char *reason = NULL, *serveraddress;

      serveraddress = (session.c && session.c->local_addr) ?
        pr_netaddr_get_ipstr(session.c->local_addr) :
        main_server->ServerAddress;

      c = find_config(main_server->conf, CONF_PARAM, "MasqueradeAddress",
        FALSE);
      if (c != NULL) {
        pr_netaddr_t *masq_addr = NULL;

        if (c->argv[0] != NULL) {
          masq_addr = c->argv[0];
        }

        if (masq_addr != NULL) {
          serveraddress = pr_netaddr_get_ipstr(masq_addr);
        }
      }

      reason = sreplace(permanent_pool, shutmsg,
                   "%s", pstrdup(permanent_pool, pr_strtime(shut)),
                   "%r", pstrdup(permanent_pool, pr_strtime(deny)),
                   "%d", pstrdup(permanent_pool, pr_strtime(disc)),
		   "%C", (session.cwd[0] ? session.cwd : "(none)"),
		   "%L", serveraddress,
		   "%R", (session.c && session.c->remote_name ?
                         session.c->remote_name : "(unknown)"),
		   "%T", pstrdup(permanent_pool, pr_strtime(now)),
		   "%U", "NONE",
		   "%V", main_server->ServerName,
                   NULL );

      pr_log_auth(PR_LOG_NOTICE, "connection refused (%s) from %s [%s]",
               reason, session.c->remote_name,
               pr_netaddr_get_ipstr(session.c->remote_addr));

      pr_response_send(R_500,
        _("FTP server shut down (%s) -- please try again later"), reason);
      exit(0);
    }
  }

  if (main_server->listen) {
    if (main_server->listen->listen_fd == conn->rfd ||
        main_server->listen->listen_fd == conn->wfd) {
      main_server->listen->listen_fd = -1;
    }

    main_server->listen = NULL;
  }

  /* Set the ID/privs for the User/Group in this server */
  set_server_privs();

  /* Find the class for this session. */
  session.conn_class = pr_class_match_addr(session.c->remote_addr);
  if (session.conn_class != NULL) {
    pr_log_debug(DEBUG2, "session requested from client in '%s' class",
      session.conn_class->cls_name);

  } else {
    pr_log_debug(DEBUG5, "session requested from client in unknown class");
  }

  /* Check config tree for <Limit LOGIN> directives.  Do not perform
   * this check until after the class of the session has been determined,
   * in order to properly handle any AllowClass/DenyClass directives
   * within the <Limit> section.
   */
  if (!login_check_limits(main_server->conf, TRUE, FALSE, &i)) {
    pr_log_pri(PR_LOG_NOTICE, "Connection from %s [%s] denied",
      session.c->remote_name,
      pr_netaddr_get_ipstr(session.c->remote_addr));

    /* XXX Send DisplayConnect here? No chroot to worry about; modules have
     * NOT been initialized, so generating an event would not work as
     * expected.
     */

    exit(0);
  }

  /* Create a table for modules to use. */
  session.notes = pr_table_alloc(session.pool, 0);
  if (session.notes == NULL) {
    pr_log_debug(DEBUG3, "error creating session.notes table: %s",
      strerror(errno));
  }

  /* Prepare the Timers API. */
  timers_init();

  /* Inform all the modules that we are now a child */
  pr_log_debug(DEBUG7, "performing module session initializations");
  if (modules_session_init() < 0) {
    pr_session_disconnect(NULL, PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }

  pr_log_debug(DEBUG4, "connected - local  : %s:%d",
    pr_netaddr_get_ipstr(session.c->local_addr), session.c->local_port);
  pr_log_debug(DEBUG4, "connected - remote : %s:%d",
    pr_netaddr_get_ipstr(session.c->remote_addr), session.c->remote_port);

  pr_proctitle_set("connected: %s (%s:%d)",
    session.c->remote_name ? session.c->remote_name : "?",
    session.c->remote_addr ? pr_netaddr_get_ipstr(session.c->remote_addr) : "?",
    session.c->remote_port ? session.c->remote_port : 0);

  pr_log_pri(PR_LOG_INFO, "%s session opened.",
    pr_session_get_protocol(PR_SESS_PROTO_FL_LOGOUT));

  /* Make sure we can receive OOB data */
  pr_inet_set_async(session.pool, session.c);

  pr_session_send_banner(main_server,
    PR_DISPLAY_FL_NO_EOM|PR_DISPLAY_FL_SEND_NOW);

  cmd_handler(main_server, conn);

#ifdef PR_DEVEL_NO_DAEMON
  /* Cleanup */
  pr_session_end(PR_SESS_END_FL_NOEXIT);
  main_server = NULL;
  free_pools();
  pr_proctitle_free();
#endif /* PR_DEVEL_NO_DAEMON */
}

static void disc_children(void) {

  if (disc && disc <= time(NULL) && child_count()) {
    sigset_t sig_set;

    sigemptyset(&sig_set);
    sigaddset(&sig_set, SIGTERM);
    sigaddset(&sig_set, SIGCHLD);
    sigaddset(&sig_set, SIGUSR1);
    sigaddset(&sig_set, SIGUSR2);

    if (sigprocmask(SIG_BLOCK, &sig_set, NULL) < 0) {
      pr_log_pri(PR_LOG_NOTICE,
        "unable to block signal set: %s", strerror(errno));
    }

    PRIVS_ROOT
    child_signal(SIGUSR1);
    PRIVS_RELINQUISH

    if (sigprocmask(SIG_UNBLOCK, &sig_set, NULL) < 0) {
      pr_log_pri(PR_LOG_NOTICE,
        "unable to unblock signal set: %s", strerror(errno));
    }
  }
}

static void daemon_loop(void) {
  fd_set listenfds;
  conn_t *listen_conn;
  int fd, maxfd;
  int i, err_count = 0, xerrno = 0;
  unsigned long nconnects = 0UL;
  time_t last_error;
  struct timeval tv;
  static int running = 0;

  pr_proctitle_set("(accepting connections)");

  time(&last_error);

  while (TRUE) {
    run_schedule();

    FD_ZERO(&listenfds);
    maxfd = pr_ipbind_listen(&listenfds);

    /* Monitor children pipes */
    maxfd = semaphore_fds(&listenfds, maxfd);

    /* Check for ftp shutdown message file */
    switch (check_shutmsg(PR_SHUTMSG_PATH, &shut, &deny, &disc, shutmsg,
        sizeof(shutmsg))) {
      case 1:
        if (!shutting_down) {
          disc_children();
        }
        shutting_down = TRUE;
        break;

      default:
        shutting_down = FALSE;
        deny = disc = (time_t) 0;
        break;
    }

    if (shutting_down) {
      tv.tv_sec = 5L;
      tv.tv_usec = 0L;

    } else {

      tv.tv_sec = PR_TUNABLE_SELECT_TIMEOUT;
      tv.tv_usec = 0L;
    }

    /* If running (a flag signaling whether proftpd is just starting up)
     * AND shutting_down (a flag signalling the present of /etc/shutmsg) are
     * true, then log an error stating this -- but don't stop the server.
     */
    if (shutting_down && !running) {

      /* Check the value of the deny time_t struct w/ the current time.
       * If the deny time has passed, log that all incoming connections
       * will be refused.  If not, note the date at which they will be
       * refused in the future.
       */
      time_t now = time(NULL);

      if (difftime(deny, now) < 0.0) {
        pr_log_pri(PR_LOG_WARNING, PR_SHUTMSG_PATH
          " present: all incoming connections will be refused");

      } else {
        pr_log_pri(PR_LOG_NOTICE,
          PR_SHUTMSG_PATH " present: incoming connections "
          "will be denied starting %s", CHOP(ctime(&deny)));
      }
    }

    running = 1;
    xerrno = errno = 0;

    PR_DEVEL_CLOCK(i = select(maxfd + 1, &listenfds, NULL, NULL, &tv));
    if (i < 0) {
      xerrno = errno;
    }

    if (i == -1 &&
        xerrno == EINTR) {
      errno = xerrno;
      pr_signals_handle();

      /* We handled our signal; clear errno. */
      xerrno = errno = 0;
      continue;
    }

    if (have_dead_child) {
      sigset_t sig_set;

      sigemptyset(&sig_set);
      sigaddset(&sig_set, SIGCHLD);
      sigaddset(&sig_set, SIGTERM);
      pr_alarms_block();
      if (sigprocmask(SIG_BLOCK, &sig_set, NULL) < 0) {
        pr_log_pri(PR_LOG_NOTICE,
          "unable to block signal set: %s", strerror(errno));
      }

      have_dead_child = FALSE;
      child_update();

      if (sigprocmask(SIG_UNBLOCK, &sig_set, NULL) < 0) {
        pr_log_pri(PR_LOG_NOTICE,
          "unable to unblock signal set: %s", strerror(errno));
      }

      pr_alarms_unblock();
    }

    if (i == -1) {
      time_t this_error;

      time(&this_error);

      if ((this_error - last_error) <= 5 && err_count++ > 10) {
        pr_log_pri(PR_LOG_ERR, "fatal: select(2) failing repeatedly, shutting "
          "down");
        exit(1);

      } else if ((this_error - last_error) > 5) {
        last_error = this_error;
        err_count = 0;
      }

      pr_log_pri(PR_LOG_WARNING, "select(2) failed in daemon_loop(): %s",
        strerror(xerrno));
    }

    if (i == 0)
      continue;

    /* Reset the connection counter.  Take into account this current
     * connection, which does not (yet) have an entry in the child list.
     */
    nconnects = 1UL;

    /* See if child semaphore pipes have signaled */
    if (child_count()) {
      pr_child_t *ch;
      time_t now = time(NULL);

      for (ch = child_get(NULL); ch; ch = child_get(ch)) {
	if (ch->ch_pipefd != -1 &&
            FD_ISSET(ch->ch_pipefd, &listenfds)) {
	  (void) close(ch->ch_pipefd);
	  ch->ch_pipefd = -1;
	}

        /* While we're looking, tally up the number of children forked in
         * the past interval.
         */
        if (ch->ch_when >= (time_t) (now - (long) max_connect_interval)) {
          nconnects++;
        }
      }
    }

    pr_signals_handle();

    if (i < 0) {
      continue;
    }

    /* Accept the connection. */
    listen_conn = pr_ipbind_accept_conn(&listenfds, &fd);

    /* Fork off servers to handle each connection our job is to get back to
     * answering connections asap, so leave the work of determining which
     * server the connection is for to our child.
     */

    if (listen_conn) {

      /* Check for exceeded MaxInstances. */
      if (ServerMaxInstances > 0 &&
          child_count() >= ServerMaxInstances) {
        pr_event_generate("core.max-instances", NULL);
        
        pr_log_pri(PR_LOG_WARNING,
          "MaxInstances (%lu) reached, new connection denied",
          ServerMaxInstances);
        close(fd);

      /* Check for exceeded MaxConnectionRate. */
      } else if (max_connects && (nconnects > max_connects)) {
        pr_event_generate("core.max-connection-rate", NULL);

        pr_log_pri(PR_LOG_WARNING,
          "MaxConnectionRate (%lu/%u secs) reached, new connection denied",
          max_connects, max_connect_interval);
        close(fd);

      /* Fork off a child to handle the connection. */
      } else {
        PR_DEVEL_CLOCK(fork_server(fd, listen_conn, no_forking));
      }
    }
#ifdef PR_DEVEL_NO_DAEMON
    /* Do not continue the while() loop here if not daemonizing. */
    break;
#endif /* PR_DEVEL_NO_DAEMON */
  }
}

static void daemonize(void) {
#ifndef HAVE_SETSID
  int ttyfd;
#endif

  /* Fork off and have parent exit.
   */
  switch (fork()) {
    case -1:
      perror("fork(2) error");
      exit(1);

    case 0:
      break;

    default: 
      exit(0);
  }

#ifdef HAVE_SETSID
  /* setsid() is the preferred way to disassociate from the
   * controlling terminal
   */
  setsid();
#else
  /* Open /dev/tty to access our controlling tty (if any) */
  if ((ttyfd = open("/dev/tty", O_RDWR)) != -1) {
    if (ioctl(ttyfd, TIOCNOTTY, NULL) == -1) {
      perror("ioctl");
      exit(1);
    }

    close(ttyfd);
  }
#endif /* HAVE_SETSID */

  /* Close the three big boys */
  close(fileno(stdin));
  close(fileno(stdout));
  close(fileno(stderr));

  /* Portable way to prevent re-acquiring a tty in the future */

#ifdef HAVE_SETPGID
  setpgid(0, getpid());
#else
# ifdef SETPGRP_VOID
  setpgrp();
# else
  setpgrp(0, getpid());
# endif
#endif

  /* Reset the cached "master PID" value to that of the daemon process;
   * there are places in the code which check this value to see if they
   * are the daemon process, e.g. at shutdown.
   */
  mpid = getpid();

  pr_fsio_chdir("/", 0);
}

static void inetd_main(void) {
  int res = 0;

  /* Make sure the scoreboard file exists. */
  PRIVS_ROOT
  res = pr_open_scoreboard(O_RDWR);
  if (res < 0) {
    PRIVS_RELINQUISH

    switch (res) {
      case PR_SCORE_ERR_BAD_MAGIC:
        pr_log_pri(PR_LOG_ERR, "error opening scoreboard: bad/corrupted file");
        return;

      case PR_SCORE_ERR_OLDER_VERSION:
      case PR_SCORE_ERR_NEWER_VERSION:
        pr_log_pri(PR_LOG_ERR, "error opening scoreboard: wrong version, "
          "writing new scoreboard");

        /* Delete the scoreboard, then open it again. */
        PRIVS_ROOT
        pr_delete_scoreboard();
        if (pr_open_scoreboard(O_RDWR) < 0) {
          int xerrno = errno;

          PRIVS_RELINQUISH
          pr_log_pri(PR_LOG_ERR, "error opening scoreboard: %s",
            strerror(xerrno));
          return;
        }
        break;

      default:
        pr_log_pri(PR_LOG_ERR, "error opening scoreboard: %s",
          strerror(errno));
        return;
    }
  }
  PRIVS_RELINQUISH
  pr_close_scoreboard(FALSE);

  pr_event_generate("core.startup", NULL);

  init_bindings();

  /* Check our shutdown status */
  if (check_shutmsg(PR_SHUTMSG_PATH, &shut, &deny, &disc, shutmsg,
      sizeof(shutmsg)) == 1) {
    shutting_down = TRUE;
  }

  /* Finally, call right into fork_server() to start servicing the
   * connection immediately.
   */
  fork_server(STDIN_FILENO, main_server->listen, TRUE);
}

static void standalone_main(void) {
  int res = 0;

  if (nodaemon) {
    log_stderr(quiet ? FALSE : TRUE);
    close(fileno(stdin));
    close(fileno(stdout));

  } else {
    log_stderr(FALSE);
    daemonize();
  }

  PRIVS_ROOT
  pr_delete_scoreboard();
  res = pr_open_scoreboard(O_RDWR);
  if (res < 0) {
    PRIVS_RELINQUISH

    switch (res) {
      case PR_SCORE_ERR_BAD_MAGIC:
        pr_log_pri(PR_LOG_ERR,
          "error opening scoreboard: bad/corrupted file");
        return;

      case PR_SCORE_ERR_OLDER_VERSION:
        pr_log_pri(PR_LOG_ERR,
          "error opening scoreboard: bad version (too old)");
        return;

      case PR_SCORE_ERR_NEWER_VERSION:
        pr_log_pri(PR_LOG_ERR,
          "error opening scoreboard: bad version (too new)");
        return;

      default:
        pr_log_pri(PR_LOG_ERR, "error opening scoreboard: %s", strerror(errno));
        return;
    }
  }
  PRIVS_RELINQUISH
  pr_close_scoreboard(TRUE);

  pr_event_generate("core.startup", NULL);

  init_bindings();

  pr_log_pri(PR_LOG_NOTICE, "ProFTPD %s (built %s) standalone mode STARTUP",
    PROFTPD_VERSION_TEXT " " PR_STATUS, BUILD_STAMP);

  if (pr_pidfile_write() < 0) {
    fprintf(stderr, "error opening PidFile '%s': %s\n", pr_pidfile_get(),
      strerror(errno));
    exit(1);
  }

  daemon_loop();
}

extern char *optarg;
extern int optind, opterr, optopt;

#ifdef HAVE_GETOPT_LONG
static struct option opts[] = {
  { "nocollision",    0, NULL, 'N' },
  { "nodaemon",	      0, NULL, 'n' },
  { "quiet",	      0, NULL, 'q' },
  { "debug",	      1, NULL, 'd' },
  { "define",	      1, NULL, 'D' },
  { "config",	      1, NULL, 'c' },
  { "persistent",     1, NULL, 'p' },
  { "list",           0, NULL, 'l' },
  { "version",        0, NULL, 'v' },
  { "settings",       0, NULL, 'V' },
  { "version-status", 0, NULL, 1   },
  { "configtest",     0, NULL, 't' },
  { "help",	      0, NULL, 'h' },
  { "ipv4",           0, NULL, '4' },
  { "ipv6",           0, NULL, '6' },
  { NULL,	      0, NULL,  0  }
};
#endif /* HAVE_GETOPT_LONG */

static void show_settings(void) {
#ifdef HAVE_UNAME
  int res;
  struct utsname uts;
#endif /* !HAVE_UNAME */

  printf("%s", "Compile-time Settings:\n");
  printf("%s", "  Version: " PROFTPD_VERSION_TEXT " " PR_STATUS "\n");

#ifdef HAVE_UNAME
  /* We use uname(2) to get the 'machine', which will tell us whether
   * we're a 32- or 64-bit machine.
   */
  res = uname(&uts);
  if (res < 0) {
    printf("%s", "  Platform: " PR_PLATFORM " [unavailable]\n");

  } else {
    printf("  Platform: " PR_PLATFORM " [%s %s %s]\n", uts.sysname,
      uts.release, uts.machine);
  }
#else
  printf("%s", "  Platform: " PR_PLATFORM " [unknown]\n");
#endif /* !HAVE_UNAME */

  printf("%s", "  Built: " BUILD_STAMP "\n");
  printf("%s", "  Built With:\n    configure " PR_BUILD_OPTS "\n\n");

  printf("%s", "  CFLAGS: " PR_BUILD_CFLAGS "\n");
  printf("%s", "  LDFLAGS: " PR_BUILD_LDFLAGS "\n");
  printf("%s", "  LIBS: " PR_BUILD_LIBS "\n");

  /* Files/paths */
  printf("%s", "\n  Files:\n");
  printf("%s", "    Configuration File:\n");
  printf("%s", "      " PR_CONFIG_FILE_PATH "\n");
  printf("%s", "    Pid File:\n");
  printf("%s", "      " PR_PID_FILE_PATH "\n");
  printf("%s", "    Scoreboard File:\n");
  printf("%s", "      " PR_RUN_DIR "/proftpd.scoreboard\n");
#ifdef PR_USE_DSO
  printf("%s", "    Header Directory:\n");
  printf("%s", "      " PR_INCLUDE_DIR "/proftpd\n");
  printf("%s", "    Shared Module Directory:\n");
  printf("%s", "      " PR_LIBEXEC_DIR "\n");
#endif /* PR_USE_DSO */

  /* Informational */
  printf("%s", "\n  Info:\n");
#if SIZEOF_UID_T == SIZEOF_INT
  printf("    + Max supported UID: %u\n", UINT_MAX);
#elif SIZEOF_UID_T == SIZEOF_LONG
  printf("    + Max supported UID: %lu\n", ULONG_MAX);
#elif SIZEOF_UID_T == SIZEOF_LONG_LONG
  printf("    + Max supported UID: %llu\n", ULLONG_MAX);
#endif

#if SIZEOF_GID_T == SIZEOF_INT
  printf("    + Max supported GID: %u\n", UINT_MAX);
#elif SIZEOF_GID_T == SIZEOF_LONG
  printf("    + Max supported GID: %lu\n", ULONG_MAX);
#elif SIZEOF_GID_T == SIZEOF_LONG_LONG
  printf("    + Max supported GID: %llu\n", ULLONG_MAX);
#endif

  /* Feature settings */
  printf("%s", "\n  Features:\n");
#ifdef PR_USE_AUTO_SHADOW
  printf("%s", "    + Autoshadow support\n");
#else
  printf("%s", "    - Autoshadow support\n");
#endif /* PR_USE_AUTO_SHADOW */

#ifdef PR_USE_CTRLS
  printf("%s", "    + Controls support\n");
#else
  printf("%s", "    - Controls support\n");
#endif /* PR_USE_CTRLS */

#if defined(PR_USE_CURSES) && defined(HAVE_LIBCURSES)
  printf("%s", "    + curses support\n");
#else
  printf("%s", "    - curses support\n");
#endif /* PR_USE_CURSES && HAVE_LIBCURSES */

#ifdef PR_USE_DEVEL
  printf("%s", "    + Developer support\n");
#else
  printf("%s", "    - Developer support\n");
#endif /* PR_USE_DEVEL */

#ifdef PR_USE_DSO
  printf("%s", "    + DSO support\n");
#else
  printf("%s", "    - DSO support\n");
#endif /* PR_USE_DSO */

#ifdef PR_USE_IPV6
  printf("%s", "    + IPv6 support\n");
#else
  printf("%s", "    - IPv6 support\n");
#endif /* PR_USE_IPV6 */

#ifdef PR_USE_LARGEFILES
  printf("%s", "    + Largefile support\n");
#else
  printf("%s", "    - Largefile support\n");
#endif /* PR_USE_LARGEFILES */

#ifdef PR_USE_LASTLOG
  printf("%s", "    + Lastlog support\n");
#else
  printf("%s", "    - Lastlog support\n");
#endif /* PR_USE_LASTLOG */

#ifdef PR_USE_MEMCACHE
  printf("%s", "    + Memcache support\n");
#else
  printf("%s", "    - Memcache support\n");
#endif /* PR_USE_MEMCACHE */

#if defined(PR_USE_NCURSESW) && defined(HAVE_LIBNCURSESW)
  printf("%s", "    + ncursesw support\n");
#elif defined(PR_USE_NCURSES) && defined(HAVE_LIBNCURSES)
  printf("%s", "    + ncurses support\n");
#else
  printf("%s", "    - ncurses support\n");
#endif

#ifdef PR_USE_NLS
  printf("%s", "    + NLS support\n");
#else
  printf("%s", "    - NLS support\n");
#endif /* PR_USE_NLS */

#ifdef PR_USE_REDIS
  printf("%s", "    + Redis support\n");
#else
  printf("%s", "    - Redis support\n");
#endif /* PR_USE_REDIS */

#ifdef PR_USE_SODIUM
  printf("%s", "    + Sodium support\n");
#else
  printf("%s", "    - Sodium support\n");
#endif /* PR_USE_SODIUM */

#ifdef PR_USE_OPENSSL
# ifdef PR_USE_OPENSSL_FIPS
    printf("    + OpenSSL support (%s, FIPS enabled)\n", OPENSSL_VERSION_TEXT);
# else
    printf("    + OpenSSL support (%s)\n", OPENSSL_VERSION_TEXT);
# endif /* PR_USE_OPENSSL_FIPS */
#else
  printf("%s", "    - OpenSSL support\n");
#endif /* PR_USE_OPENSSL */

#ifdef PR_USE_PCRE
  printf("%s", "    + PCRE support\n");
#else
  printf("%s", "    - PCRE support\n");
#endif /* PR_USE_PCRE */

#ifdef PR_USE_FACL
  printf("%s", "    + POSIX ACL support\n");
#else
  printf("%s", "    - POSIX ACL support\n");
#endif /* PR_USE_FACL */

#ifdef PR_USE_SHADOW
  printf("%s", "    + Shadow file support\n");
#else
  printf("%s", "    - Shadow file support\n");
#endif /* PR_USE_SHADOW */

#ifdef PR_USE_SENDFILE
  printf("%s", "    + Sendfile support\n");
#else
  printf("%s", "    - Sendfile support\n");
#endif /* PR_USE_SENDFILE */

#ifdef PR_USE_TRACE
  printf("%s", "    + Trace support\n");
#else
  printf("%s", "    - Trace support\n");
#endif /* PR_USE_TRACE */

#ifdef PR_USE_XATTR
  printf("%s", "    + xattr support\n");
#else
  printf("%s", "    - xattr support\n");
#endif /* PR_USE_XATTR */

  /* Tunable settings */
  printf("%s", "\n  Tunable Options:\n");
  printf("    PR_TUNABLE_BUFFER_SIZE = %u\n", PR_TUNABLE_BUFFER_SIZE);
  printf("    PR_TUNABLE_DEFAULT_RCVBUFSZ = %u\n", PR_TUNABLE_DEFAULT_RCVBUFSZ);
  printf("    PR_TUNABLE_DEFAULT_SNDBUFSZ = %u\n", PR_TUNABLE_DEFAULT_SNDBUFSZ);
  printf("    PR_TUNABLE_ENV_MAX = %u\n", PR_TUNABLE_ENV_MAX);
  printf("    PR_TUNABLE_GLOBBING_MAX_MATCHES = %lu\n", PR_TUNABLE_GLOBBING_MAX_MATCHES);
  printf("    PR_TUNABLE_GLOBBING_MAX_RECURSION = %u\n", PR_TUNABLE_GLOBBING_MAX_RECURSION);
  printf("    PR_TUNABLE_HASH_TABLE_SIZE = %u\n", PR_TUNABLE_HASH_TABLE_SIZE);
  printf("    PR_TUNABLE_LOGIN_MAX = %u\n", PR_TUNABLE_LOGIN_MAX);
  printf("    PR_TUNABLE_NEW_POOL_SIZE = %u\n", PR_TUNABLE_NEW_POOL_SIZE);
  printf("    PR_TUNABLE_PATH_MAX = %u\n", PR_TUNABLE_PATH_MAX);
  printf("    PR_TUNABLE_SCOREBOARD_BUFFER_SIZE = %u\n",
    PR_TUNABLE_SCOREBOARD_BUFFER_SIZE);
  printf("    PR_TUNABLE_SCOREBOARD_SCRUB_TIMER = %u\n",
    PR_TUNABLE_SCOREBOARD_SCRUB_TIMER);
  printf("    PR_TUNABLE_SELECT_TIMEOUT = %u\n", PR_TUNABLE_SELECT_TIMEOUT);
  printf("    PR_TUNABLE_TIMEOUTIDENT = %u\n", PR_TUNABLE_TIMEOUTIDENT);
  printf("    PR_TUNABLE_TIMEOUTIDLE = %u\n", PR_TUNABLE_TIMEOUTIDLE);
  printf("    PR_TUNABLE_TIMEOUTLINGER = %u\n", PR_TUNABLE_TIMEOUTLINGER);
  printf("    PR_TUNABLE_TIMEOUTLOGIN = %u\n", PR_TUNABLE_TIMEOUTLOGIN);
  printf("    PR_TUNABLE_TIMEOUTNOXFER = %u\n", PR_TUNABLE_TIMEOUTNOXFER);
  printf("    PR_TUNABLE_TIMEOUTSTALLED = %u\n", PR_TUNABLE_TIMEOUTSTALLED);
  printf("    PR_TUNABLE_XFER_SCOREBOARD_UPDATES = %u\n\n",
    PR_TUNABLE_XFER_SCOREBOARD_UPDATES);
}

static struct option_help {
  const char *long_opt, *short_opt, *desc;

} opts_help[] = {
  { "--help", "-h",
    "Display proftpd usage"},

  { "--nocollision", "-N",
    "Disable address/port collision checking" },

  { "--nodaemon", "-n",
    "Disable background daemon mode (and send all output to stderr)" },

  { "--quiet", "-q",
    "Don't send output to stderr when running with -n or --nodaemon" },

  { "--debug", "-d [level]",
    "Set debugging level (0-10, 10 = most debugging)" },

  { "--define", "-D [definition]",
    "Set arbitrary IfDefine definition" },

  { "--config", "-c [config-file]",
    "Specify alternate configuration file" },

  { "--persistent", "-p [0|1]",
    "Enable/disable default persistent passwd support" },

  { "--list", "-l",
    "List all compiled-in modules" },

  { "--serveraddr", "-S",
    "Specify IP address for server config" },

  { "--configtest", "-t",
    "Test the syntax of the specified config" },

  { "--settings", "-V",
    "Print compile-time settings and exit" },

  { "--version", "-v",
    "Print version number and exit" },

  { "--version-status", "-vv",
    "Print extended version information and exit" },

  { "--nofork", "-X",
    "Non-forking debug mode; exits after one session" },

  { "--ipv4", "-4",
    "Support IPv4 connections only" },

  { "--ipv6", "-6",
    "Support IPv6 connections" },

  { NULL, NULL, NULL }
};

static void show_usage(int exit_code) {
  struct option_help *h;

  printf("%s", "usage: proftpd [options]\n");
  for (h = opts_help; h->long_opt; h++) {
#ifdef HAVE_GETOPT_LONG
    printf(" %s, %s\n ", h->short_opt, h->long_opt);
#else /* HAVE_GETOPT_LONG */
    printf(" %s\n", h->short_opt);
#endif /* HAVE_GETOPT_LONG */
    printf("    %s\n", h->desc);
  }

  exit(exit_code);
}

int main(int argc, char *argv[], char **envp) {
  int optc, show_version = 0;
  const char *cmdopts = "D:NVc:d:hlnp:qS:tvX46";
  mode_t *main_umask = NULL;
  socklen_t peerlen;
  struct sockaddr peer;

#ifdef HAVE_SET_AUTH_PARAMETERS
  (void) set_auth_parameters(argc, argv);
#endif

#ifdef HAVE_TZSET
  /* Preserve timezone information in jailed environments.
   */
  tzset();
#endif

  memset(&session, 0, sizeof(session));

  pr_fs_close_extra_fds();
  pr_proctitle_init(argc, argv, envp);

  /* Seed rand */
  pr_random_init();

  /* getpeername() fails if the fd isn't a socket */
  peerlen = sizeof(peer);
  memset(&peer, 0, peerlen);
  if (getpeername(fileno(stdin), &peer, &peerlen) != -1)
    log_stderr(FALSE);

  /* Open the syslog */
  log_opensyslog(NULL);

  /* Initialize the memory subsystem here */
  init_pools();

  /* Command line options supported:
   *
   * -D parameter       set run-time configuration parameter
   * --define parameter
   * -V
   * --settings         report compile-time settings
   * -c path            set the configuration path
   * --config path
   * -d n               set the debug level
   * --debug n
   * -q                 quiet mode; don't log to stderr when not daemonized
   * --quiet
   * -N                 disable address/port collision checks
   * --nocollision
   * -n                 standalone server does not daemonize, all logging
   * --nodaemon         redirected to stderr
   * -S                 specify the IP address for the 'server config',
   * --serveraddr       rather than using DNS on the hostname
   * -t                 syntax check of the configuration file
   * --configtest
   * -v                 report version number
   * --version
   * -X
   * --nofork           debug/non-fork mode
   * -4                 support IPv4 connections only
   * --ipv4
   * -6                 support IPv6 connections
   * --ipv6
   */

  opterr = 0;
  while ((optc =
#ifdef HAVE_GETOPT_LONG
	 getopt_long(argc, argv, cmdopts, opts, NULL)
#else /* HAVE_GETOPT_LONG */
	 getopt(argc, argv, cmdopts)
#endif /* HAVE_GETOPT_LONG */
	 ) != -1) {
    switch (optc) {

    case 'D':
      if (!optarg) {
        pr_log_pri(PR_LOG_WARNING, "fatal: -D requires definition parameter");
        exit(1);
      }

      pr_define_add(optarg, TRUE);
      break;

    case 'V':
      show_settings();
      exit(0);
      break;

    case 'N':
      AddressCollisionCheck = FALSE;
      break;

    case 'n':
      nodaemon++;
#ifdef PR_USE_DEVEL
      pr_pool_debug_set_flags(PR_POOL_DEBUG_FL_OOM_DUMP_POOLS);
#endif
      break;

    case 'q':
      quiet++;
      break;

    case 'd':
      if (!optarg) {
        pr_log_pri(PR_LOG_WARNING, "fatal: -d requires debug level parameter");
        exit(1);
      }
      pr_log_setdebuglevel(atoi(optarg));

      /* If the admin uses -d on the command-line, they explicitly WANT
       * debug logging, thus make sure the default SyslogLevel is set to
       * DEBUG (rather than NOTICE); see Bug#3983.
       */
      pr_log_setdefaultlevel(PR_LOG_DEBUG);
      break;

    case 'c':
      if (!optarg) {
        pr_log_pri(PR_LOG_WARNING,
          "fatal: -c requires configuration path parameter");
        exit(1);
      }

      /* Note: we delay sanity-checking the given path until after the FSIO
       * layer has been initialized.
       */
      config_filename = strdup(optarg);
      break;

    case 'l':
      modules_list2(NULL, PR_MODULES_LIST_FL_SHOW_STATIC);
      exit(0);
      break;

    case 'S':
      if (!optarg) {
        pr_log_pri(PR_LOG_WARNING, "fatal: -S requires IP address parameter");
        exit(1);
      }

      if (pr_netaddr_set_localaddr_str(optarg) < 0) {
        pr_log_pri(PR_LOG_WARNING,
          "fatal: unable to use '%s' as server address: %s", optarg,
          strerror(errno));
        exit(1);
      }
      break;

    case 't':
      syntax_check = 1;
      printf("%s", "Checking syntax of configuration file\n");
      fflush(stdout);
      break;

    /* Note: This is now unused, and should be deprecated in the next release.
     * See Bug#3952 for details.
     */
    case 'p': {
      if (!optarg ||
          (atoi(optarg) != 1 && atoi(optarg) != 0)) {
        pr_log_pri(PR_LOG_WARNING,
          "fatal: -p requires Boolean (0|1) parameter");
        exit(1);
      }

      break;
    }

    case 'v':
      show_version++;
      break;

    case 'X':
      no_forking = TRUE;
      break;

    case 1:
      show_version = 2;
      break;

    case 'h':
      show_usage(0);
      break;

    case '4':
      pr_netaddr_disable_ipv6();
      break;

    case '6':
      pr_netaddr_enable_ipv6();
      break;

    case '?':
      pr_log_pri(PR_LOG_WARNING, "unknown option: %c", (char) optopt);
      show_usage(1);
      break;
    }
  }

  /* If we have any leftover parameters, it's an error. */
  if (argv[optind]) {
    pr_log_pri(PR_LOG_WARNING, "fatal: unknown parameter: '%s'", argv[optind]);
    exit(1);
  }

  if (show_version &&
      show_version == 1) {
    printf("%s", "ProFTPD Version " PROFTPD_VERSION_TEXT "\n");
    exit(0);
  }

  mpid = getpid();

  /* Initialize sub-systems */
  init_signals();
  init_pools();
  init_privs();
  init_log();
  init_regexp();
  init_inet();
  init_netio();
  init_netaddr();
  init_fs();
  init_class();
  free_bindings();
  init_config();
  init_dirtree();
  init_stash();
  init_json();

#ifdef PR_USE_CTRLS
  init_ctrls();
#endif /* PR_USE_CTRLS */

  var_init();
  modules_init();

#ifdef PR_USE_NLS
# ifdef HAVE_LOCALE_H
  /* Initialize the locale based on environment variables. */
  if (setlocale(LC_ALL, "") == NULL) {
    const char *env_lang;

    env_lang = pr_env_get(permanent_pool, "LANG");
    pr_log_pri(PR_LOG_WARNING, "warning: unknown/unsupported LANG environment "
      "variable '%s', ignoring", env_lang);

    setlocale(LC_ALL, "C");

  } else {
    /* Make sure that LC_NUMERIC is always set to "C", so as not to interfere
     * with formatting of strings (like printing out floats in SQL query
     * strings).
     */
    setlocale(LC_NUMERIC, "C");
  }
# endif /* !HAVE_LOCALE_H */

  encode_init();
#endif /* PR_USE_NLS */

  /* Now, once the modules have had a chance to initialize themselves
   * but before the configuration stream is actually parsed, check
   * that the given configuration path is valid.
   */
  if (pr_fs_valid_path(config_filename) < 0) {
    pr_log_pri(PR_LOG_WARNING, "fatal: -c requires an absolute path");
    exit(1);
  }

  pr_parser_prepare(NULL, NULL);

  pr_event_generate("core.preparse", NULL);

  if (pr_parser_parse_file(NULL, config_filename, NULL, 0) < 0) {
    /* Note: EPERM is used to indicate the presence of unrecognized
     * configuration directives in the parsed file(s).
     */
    if (errno != EPERM) {
      pr_log_pri(PR_LOG_WARNING,
        "fatal: unable to read configuration file '%s': %s", config_filename,
        strerror(errno));
    }

    exit(1);
  }

  if (pr_parser_cleanup() < 0) {
    pr_log_pri(PR_LOG_WARNING,
      "fatal: error processing configuration file '%s': "
      "unclosed configuration section", config_filename);
    exit(1);
  }

  if (fixup_servers(server_list) < 0) {
    pr_log_pri(PR_LOG_WARNING,
      "fatal: error processing configuration file '%s'", config_filename);
    exit(1);
  }

  pr_event_generate("core.postparse", NULL);

  if (show_version &&
      show_version == 2) {

    printf("ProFTPD Version: %s", PROFTPD_VERSION_TEXT " " PR_STATUS "\n");
    printf("  Scoreboard Version: %08x\n", PR_SCOREBOARD_VERSION); 
    printf("  Built: %s\n\n", BUILD_STAMP);

    modules_list2(NULL, PR_MODULES_LIST_FL_SHOW_VERSION);
    exit(0);
  }

  /* We're only doing a syntax check of the configuration file. */
  if (syntax_check) {
    printf("%s", "Syntax check complete.\n");
    pr_session_end(PR_SESS_END_FL_SYNTAX_CHECK);
  }

  /* Security */
  {
    uid_t *uid = (uid_t *) get_param_ptr(main_server->conf, "UserID", FALSE);
    gid_t *gid = (gid_t *) get_param_ptr(main_server->conf, "GroupID", FALSE);

    daemon_uid = (uid != NULL ? *uid : PR_ROOT_UID);
    daemon_gid = (gid != NULL ? *gid : PR_ROOT_GID);
  }

  if (daemon_uid != PR_ROOT_UID) {
    /* Allocate space for daemon supplemental groups. */
    daemon_gids = make_array(permanent_pool, 2, sizeof(gid_t));

    if (pr_auth_getgroups(permanent_pool, (const char *) get_param_ptr(
        main_server->conf, "UserName", FALSE), &daemon_gids, NULL) < 0) {
      pr_log_debug(DEBUG2, "unable to retrieve daemon supplemental groups");
    }

    if (set_groups(permanent_pool, daemon_gid, daemon_gids) < 0) {
      if (errno != ENOSYS) {
        pr_log_pri(PR_LOG_WARNING, "unable to set daemon groups: %s",
          strerror(errno));
      }
    }
  }

  /* After configuration is complete, make sure that passwd, group
   * aren't held open (unnecessary fds for master daemon)
   */
  endpwent();
  endgrent();

  main_umask = get_param_ptr(main_server->conf, "Umask", FALSE);
  if (main_umask == NULL) {
    umask((mode_t) 0022);

  } else {
    umask(*main_umask);
  }

  /* Give up root and save our uid/gid for later use (if supported)
   * If we aren't currently root, PRIVS_SETUP will get rid of setuid
   * granted root and prevent further uid switching from being attempted.
   */

  PRIVS_SETUP(daemon_uid, daemon_gid)

#ifndef PR_DEVEL_COREDUMP
  /* Test to make sure that our uid/gid is correct.  Try to do this in
   * a portable fashion *gah!*
   */

  if (geteuid() != daemon_uid) {
    pr_log_pri(PR_LOG_ERR, "unable to set UID to %s, current UID: %s",
      pr_uid2str(permanent_pool, daemon_uid),
      pr_uid2str(permanent_pool, geteuid()));
    exit(1);
  }

  if (getegid() != daemon_gid) {
    pr_log_pri(PR_LOG_ERR, "unable to set GID to %s, current GID: %s",
      pr_gid2str(permanent_pool, daemon_gid),
      pr_gid2str(permanent_pool, getegid()));
    exit(1);
  }
#endif /* PR_DEVEL_COREDUMP */

  switch (ServerType) {
    case SERVER_STANDALONE:
      standalone_main();
      break;

    case SERVER_INETD:
      /* Reset the variable containing the pid of the master/daemon process;
       * it should only be non-zero in the case of standalone daemons.
       */
      mpid = 0;
      inetd_main();
      break;
  }

#ifdef PR_DEVEL_NO_DAEMON
  PRIVS_ROOT
  chdir(PR_RUN_DIR);
#endif /* PR_DEVEL_NO_DAEMON */

  return 0;
}
