/*
 * ProFTPD: mod_exec -- a module for executing external scripts
 * Copyright (c) 2002-2017 TJ Saunders
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
 * As a special exemption, TJ Saunders gives permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 *
 * This is mod_exec, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"

#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif

#define MOD_EXEC_VERSION	"mod_exec/0.9.16"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030701
# error "ProFTPD 1.3.7rc1 or later required"
#endif

module exec_module;

static pool *exec_pool = NULL;
static int exec_engine = FALSE;
static unsigned int exec_nexecs = 0;

static int exec_logfd = -1;
static char *exec_logname = NULL;

static int exec_stdin_pipe[2];
static int exec_stdout_pipe[2];
static int exec_stderr_pipe[2];

static unsigned int exec_opts = 0U;
#define EXEC_OPT_LOG_STDOUT	0x0001
#define EXEC_OPT_LOG_STDERR	0x0002
#define EXEC_OPT_SEND_STDOUT	0x0004
#define EXEC_OPT_USE_STDIN	0x0008

static int exec_timeout = 0;

/* Flags for exec_ssystem() */
#define EXEC_FL_CLEAR_GROUPS	0x0010	/* Clear supplemental groups */
#define EXEC_FL_NO_SEND		0x0020	/* Do not send output via response */
#define EXEC_FL_USE_SEND	0x0040	/* Use pr_response_send() instead of
					 * pr_response_add()
					 */
#define EXEC_FL_RUN_AS_ROOT	0x0080  /* Use root privs when executing
                                         * the command.  USE CAREFULLY!
                                         */
#define EXEC_FL_RUN_AS_USER	0x0100  /* Use user privs when executing
                                         * the command.  Useful for pre-login
                                         * events.
                                         */

struct exec_event_data {
  unsigned int flags;
  config_rec *c;
  const char *event;
};

/* Prototypes */
static void exec_any_ev(const void *, void *);
static const char *exec_subst_var(pool *, const char *, cmd_rec *);
static int exec_log(const char *, ...)
#ifdef __GNUC__
      __attribute__ ((format (printf, 1, 2)));
#else
      ;
#endif
static int exec_sess_init(void);

/* Support routines
 */

static int exec_closelog(void) {
  /* sanity check */
  if (exec_logfd != -1) {
    close(exec_logfd);
    exec_logfd = -1;
    exec_logname = NULL;
  }

  return 0;
}

static int exec_enabled(void) {
  config_rec *c;
  int enabled = TRUE;

  c = find_config(CURRENT_CONF, CONF_PARAM, "ExecEnable", FALSE);
  if (c) {
    enabled = *((int *) c->argv[0]);
  }

  return enabled;
}

static char *exec_get_cmd(char **list) {
  char *res = NULL, *dst = NULL;
  unsigned char quote_mode = FALSE;

  while (**list && PR_ISSPACE(**list)) {
    (*list)++;
  }

  if (!**list)
    return NULL;

  res = dst = *list;

  if (**list == '\"') {
    quote_mode = TRUE;
    (*list)++;
  }

  while (**list && **list != ',' &&
      (quote_mode ? (**list != '\"') : (!PR_ISSPACE(**list)))) {

    if (**list == '\\' && quote_mode) {

      /* Escaped char */
      if (*((*list) + 1))
        *dst = *(++(*list));
    }

    *dst++ = **list;
    ++(*list);
  }

  if (**list)
    (*list)++;

  *dst = '\0';

  return res;
}

static int exec_log(const char *fmt, ...) {
  va_list msg;
  int res;

  if (!exec_logname)
    return 0;

  va_start(msg, fmt);
  res = pr_log_vwritefile(exec_logfd, MOD_EXEC_VERSION, fmt, msg);
  va_end(msg);
  
  return res;
}

static unsigned char exec_match_cmd(cmd_rec *cmd, array_header *cmd_array) {
  char **cmds = NULL;
  register unsigned int i = 0;

  cmds = (char **) cmd_array->elts;

  for (i = 0; i < cmd_array->nelts && cmds[i]; i++) {
    if (strcasecmp(cmd->argv[0], cmds[i]) == 0)
      return TRUE;
 
    if (cmd->group &&
        strcasecmp(cmds[i], cmd->group) == 0)
      return TRUE;

    if (strncasecmp(cmds[i], "ALL", 4) == 0)
      return TRUE;
  }

  return FALSE;
}

static int exec_openlog(void) {
  int res = 0;

  /* Sanity check */
  exec_logname = (char *) get_param_ptr(main_server->conf, "ExecLog", FALSE);
  if (exec_logname == NULL)
    return 0;

  /* Check for "none". */
  if (strncasecmp(exec_logname, "none", 5) == 0) {
    exec_logname = NULL;
    return 0;
  }

  pr_signals_block();
  PRIVS_ROOT
  res = pr_log_openfile(exec_logname, &exec_logfd, PR_LOG_SYSTEM_MODE);
  PRIVS_RELINQUISH
  pr_signals_unblock();

  return res;
}

static void exec_parse_cmds(config_rec *c, char *cmds) {
  char *cmd = NULL;
  array_header *cmd_array = NULL;

  /* Allocate an array_header. */
  cmd_array = make_array(c->pool, 0, sizeof(char *));

  /* Add each command to the array. */
  while ((cmd = exec_get_cmd(&cmds)) != NULL)
    *((char **) push_array(cmd_array)) = pstrdup(c->pool, cmd);

  /* Terminate the array with a NULL. */
  *((char **) push_array(cmd_array)) = NULL;

  /* Store the array of commands in the config_rec. */
  c->argv[1] = cmd_array;

  return;
}

static char **exec_prepare_environ(pool *env_pool, cmd_rec *cmd) {
  config_rec *c = NULL;
  array_header *env = make_array(env_pool, 0, sizeof(char *));

  c = find_config(main_server->conf, CONF_PARAM, "ExecEnviron", FALSE);
  while (c != NULL) {
    pr_signals_handle();

    if (strncmp("-", c->argv[1], 2) == 0) {
      *((char **) push_array(env)) = pstrcat(env_pool, c->argv[0], "=",
        getenv(c->argv[0]) ? getenv(c->argv[0]) : "", NULL);

    } else {
      *((char **) push_array(env)) = pstrcat(env_pool, c->argv[0], "=",
        exec_subst_var(env_pool, c->argv[1], cmd), NULL);
    }

    c = find_config_next(c, c->next, CONF_PARAM, "ExecEnviron", FALSE);
  }

  /* Make sure the environment is NULL-terminated. */
  *((char **) push_array(env)) = NULL;

  return (char **) env->elts;
}

static void exec_prepare_fds(int stdin_fd, int stdout_fd, int stderr_fd) {
  if (stdin_fd < 0) {
    stdin_fd = open("/dev/null", O_RDONLY);
    if (stdin_fd < 0) {
      exec_log("error: unable to open /dev/null for stdin: %s",
        strerror(errno));

    } else {
      if (dup2(stdin_fd, STDIN_FILENO) < 0)
        exec_log("error: unable to dup fd %d to stdin: %s", stdin_fd,
          strerror(errno));

      (void) close(stdin_fd);
    }

  } else {
    if (stdin_fd != STDIN_FILENO) {
      if (dup2(stdin_fd, STDIN_FILENO) < 0) {
        exec_log("error: unable to dup fd %d to stdin: %s", stdin_fd,
          strerror(errno));
      }

      (void) close(stdin_fd);
    }
  }

  if (stdout_fd != STDOUT_FILENO) {
    if (dup2(stdout_fd, STDOUT_FILENO) < 0) {
      exec_log("error: unable to dup fd %d to stdout: %s", stdout_fd,
        strerror(errno));
    }

    (void) close(stdout_fd);
  }

  if (stderr_fd != STDERR_FILENO) {
    if (dup2(stderr_fd, STDERR_FILENO) < 0) {
      exec_log("error: unable to dup fd %d to stderr: %s", stderr_fd,
        strerror(errno));
    }

    (void) close(stderr_fd);
  }

  /* Make sure not to pass on open file descriptors.  For stdin, we
   * dup /dev/null.  For stdout and stderr, we dup some pipes, so that
   * we can capture what the command may write to stdout or stderr.  The
   * stderr output will be logged to the ExecLog.
   */
  pr_fs_close_extra_fds();
}

static void exec_prepare_pipes(void) {

  /* Open pipes for stdin, stdout and stderr. */
  if (exec_opts & EXEC_OPT_USE_STDIN) {
    if (pipe(exec_stdin_pipe) < 0) {
      exec_log("error: unable to open stdin pipe: %s", strerror(errno));
      exec_stdin_pipe[0] = STDIN_FILENO;
      exec_stdin_pipe[1] = -1;

    } else {
      if (fcntl(exec_stdin_pipe[0], F_SETFD, 0) < 0) {
        exec_log("error: unable to set cloexec flag on stdin pipe read fd: %s",
          strerror(errno));
      }

      if (fcntl(exec_stdin_pipe[1], F_SETFD, FD_CLOEXEC) < 0) {
        exec_log("error: unable to set cloexec flag on stdin pipe write fd: %s",
          strerror(errno));
      }
    }
  }

  if (pipe(exec_stdout_pipe) < 0) {
    exec_log("error: unable to open stdout pipe: %s", strerror(errno));
    exec_stdout_pipe[0] = -1;
    exec_stdout_pipe[1] = STDOUT_FILENO;

  } else {
    if (fcntl(exec_stdout_pipe[0], F_SETFD, FD_CLOEXEC) < 0) {
      exec_log("error: unable to set cloexec flag on stdout pipe read fd: %s",
        strerror(errno));
    }

    if (fcntl(exec_stdout_pipe[1], F_SETFD, 0) < 0) {
      exec_log("error: unable to set cloexec flag on stdout pipe write fd: %s",
        strerror(errno));
    }
  }

  if (pipe(exec_stderr_pipe) < 0) {
    exec_log("error: unable to open stderr pipe: %s", strerror(errno));
    exec_stderr_pipe[0] = -1;
    exec_stderr_pipe[1] = STDERR_FILENO;

  } else {
    if (fcntl(exec_stderr_pipe[0], F_SETFD, FD_CLOEXEC) < 0) {
      exec_log("error: unable to set cloexec flag on stderr pipe read fd: %s",
        strerror(errno));
    }

    if (fcntl(exec_stderr_pipe[1], F_SETFD, 0) < 0) {
      exec_log("error: unable to set cloexec flag on stderr pipe write fd: %s",
        strerror(errno));
    }
  }

  return;
}

/* Provides a "safe" version of the system(2) call by dropping all special
 * privileges, currently retained by the daemon, before exec()'ing the
 * given command.
 */
static int exec_ssystem(cmd_rec *cmd, config_rec *c, int flags) {
  pid_t pid;
  int status;

  struct sigaction sa_ignore, sa_intr, sa_quit;
  sigset_t set_chldmask, set_save;

  /* Prepare signal dispositions. */
  sa_ignore.sa_handler = SIG_IGN;
  sigemptyset(&sa_ignore.sa_mask);
  sa_ignore.sa_flags = 0;

  if (sigaction(SIGINT, &sa_ignore, &sa_intr) < 0)
    return errno;

  if (sigaction(SIGQUIT, &sa_ignore, &sa_quit) < 0)
    return errno;

  sigemptyset(&set_chldmask);
  sigaddset(&set_chldmask, SIGCHLD);

  if (sigprocmask(SIG_BLOCK, &set_chldmask, &set_save) < 0) {
    exec_log("sigprocmask error: %s", strerror(errno));
    return errno;
  }

  exec_prepare_pipes();

  pid = fork();
  if (pid < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_ALERT,
      MOD_EXEC_VERSION ": error: unable to fork: %s", strerror(xerrno));
    exec_log("error: unable to fork: %s", strerror(xerrno));

    errno = xerrno;
    status = -1;

  } else if (pid == 0) {
    /* Child process */
    char **env = NULL, *path = NULL, *ptr = NULL;
    register unsigned int i = 0;

    /* Note: there is no need to clean up this temporary pool, as we've
     * forked.  If the exec call succeeds, this child process will exit
     * normally, and its process space recovered by the OS.  If the exec
     * call fails, we still exit, and the process space is recovered by
     * the OS.  Either way, the memory will be cleaned up without need for
     * us to do it explicitly (unless one wanted to be pedantic about it,
     * of course).
     */
    pool *tmp_pool = cmd ? cmd->tmp_pool : make_sub_pool(session.pool);
 
    /* Don't forget to update the PID. */
    session.pid = getpid();

    if (!(exec_opts & EXEC_OPT_USE_STDIN)) {

      /* Prepare the environment. */
      env = exec_prepare_environ(tmp_pool, cmd);
 
      /* Perform any required substitution on the command arguments. */
      for (i = 3; i < c->argc; i++) {
        pr_signals_handle();
        c->argv[i] = (void *) exec_subst_var(tmp_pool, c->argv[i], cmd);
      }

    } else {
      /* Make sure that env is at least a NULL-terminated array. */
      env = pcalloc(tmp_pool, sizeof(char **));
    }

    /* Restore previous signal actions. */
    sigaction(SIGINT, &sa_intr, NULL);
    sigaction(SIGQUIT, &sa_quit, NULL);
    sigprocmask(SIG_SETMASK, &set_save, NULL);

    /* Per Bug#4049, when running the command as the user, do NOT clear
     * the supplemental groups.
     */
    if (flags & EXEC_FL_RUN_AS_USER) {
      flags &= ~EXEC_FL_CLEAR_GROUPS;
    }

    /* If requested, clear the supplemental group membership of the process. */
    if (flags & EXEC_FL_CLEAR_GROUPS) {
      PRIVS_ROOT
      setgroups(0, NULL);
      PRIVS_RELINQUISH
    }

    if (flags & EXEC_FL_RUN_AS_ROOT) {
      /* We were asked to run using root privs.  Yuck. */
      PRIVS_ROOT

    } else if (flags & EXEC_FL_RUN_AS_USER) {
      /* We were asked to run using user privs.  Sigh. */
      if (geteuid() != session.login_uid) {
        PRIVS_SETUP(session.login_uid, session.login_gid)
      }

      PRIVS_REVOKE

    } else {
      /* Drop all special privileges before exec()'ing the command.  This
       * allows for the user to specify arbitrary input via the given
       * filename without the admin worrying that some arbitrary command
       * is being executed that could take advantage of proftpd's retention
       * of root real user ID.
       */
      PRIVS_REVOKE
    }

    exec_log("preparing to execute '%s' with uid %s (euid %s), "
      "gid %s (egid %s)", (const char *) c->argv[2],
      pr_uid2str(tmp_pool, getuid()), pr_uid2str(tmp_pool, geteuid()),
      pr_gid2str(tmp_pool, getgid()), pr_gid2str(tmp_pool, getegid()));

    path = c->argv[2];

    /* Trim the given path to the command to execute to just the last
     * component; this name will be the first argument to the executed
     * command, as per execve(2) convention.
     */
    ptr = strrchr(c->argv[2], '/');
    c->argv[2] = ptr + 1;

    for (i = 3; i < c->argc; i++) {
      if (c->argv[i] != NULL) {
        exec_log(" + '%s': argv[%u] = %s", (const char *) path, i - 2,
          (const char *) c->argv[i]);
      }
    }

    /* Prepare the file descriptors that the process will inherit. */
    if (exec_opts & EXEC_OPT_USE_STDIN) {
      exec_prepare_fds(exec_stdin_pipe[0], exec_stdout_pipe[1],
        exec_stderr_pipe[1]);

    } else {
      exec_prepare_fds(-1, exec_stdout_pipe[1], exec_stderr_pipe[1]);
    }

    errno = 0;

    /* If we are using stdin to convey all of the arguments, then we need
     * not provide any sort of environment variables. 
     */
    if (exec_opts & EXEC_OPT_USE_STDIN) {
      char *args[] = { ptr + 1, NULL };

      execve(path, args, env);

    } else {
      execve(path, (char **) (c->argv + 2), env);
    }

    /* Since all previous file descriptors (including those for log files)
     * have been closed, and root privs have been revoked, there's little
     * chance of directing a message of execve() failure to proftpd's log
     * files.  execve() only returns if there's an error; the only way we
     * can signal this to the waiting parent process is to exit with a 
     * non-zero value (the value of errno will do nicely).
     */
    exit(errno);

  } else {
    int res;

    /* Parent process */

    /* If we are using stdin, then we need to write all of the arguments to
     * stdin before closing that pipe.
     */
    if (exec_opts & EXEC_OPT_USE_STDIN) {
      register unsigned int i;
      int maxfd = -1, fds;
      fd_set writefds;
      struct timeval tv;
      pool *tmp_pool = cmd ? cmd->tmp_pool : make_sub_pool(session.pool);

      /* Wait for stdin to be available for writing. */

      FD_ZERO(&writefds);
      FD_SET(exec_stdin_pipe[1], &writefds);
      if (exec_stdin_pipe[1] > maxfd) {
        maxfd = exec_stdin_pipe[1];
      }

      /* Note: this delay should be configurable somehow. */
      tv.tv_sec = 2L;
      tv.tv_usec = 0L;

      fds = select(maxfd + 1, &writefds, NULL, NULL, &tv);

      if (fds == -1 &&
          errno == EINTR) {
        pr_signals_handle();
      }

      /* Perform any required substitution on the command arguments. */
      for (i = 3; i < c->argc && c->argv[i] != NULL; i++) {
        pr_signals_handle();

        c->argv[i] = (void *) exec_subst_var(tmp_pool, c->argv[i], cmd);

        /* Write the argument to stdin, terminated by a newline. */
        if (write(exec_stdin_pipe[1], c->argv[i], strlen(c->argv[i])) < 0) {
          exec_log("error writing argument to stdin: %s", strerror(errno));

        } else {
          exec_log("wrote argument %u (%s) to stdin (%d)", i - 3,
            (char *) c->argv[i], exec_stdin_pipe[1]);
        }

        if (write(exec_stdin_pipe[1], "\n", 1) < 0) {
          exec_log("error writing newline to stdin: %s", strerror(errno));
        }
      }

      /* Signal the end of stdin arguments using a period followed by a newline.
       * (This is the end-of-arguments indicated used by other protocols such
       * as SMTP.)
       */
      if (write(exec_stdin_pipe[1], ".\n", 2) < 0) {
        exec_log("error writing end-of-argument indicator: %s",
          strerror(errno));
      }

      if (cmd == NULL) {
        destroy_pool(tmp_pool);
      }
    }

    if (exec_opts & EXEC_OPT_USE_STDIN) {
      (void) close(exec_stdin_pipe[0]);
      exec_stdin_pipe[0] = -1;
    }

    (void) close(exec_stdout_pipe[1]);
    exec_stdout_pipe[1] = -1;

    (void) close(exec_stderr_pipe[1]);
    exec_stderr_pipe[1] = -1;
  
    if ((exec_opts & EXEC_OPT_LOG_STDOUT) ||
        (exec_opts & EXEC_OPT_LOG_STDERR) ||
        (exec_opts & EXEC_OPT_SEND_STDOUT) ||
        exec_timeout > 0) {
      int maxfd = -1, fds, send_sigterm = 1;
      fd_set readfds;
      struct timeval tv;
      time_t start_time = time(NULL);
      pool *tmp_pool = cmd ? cmd->tmp_pool : make_sub_pool(session.pool);

      /* We set the result value to zero initially, so that at least one
       * pass through the stdout/stderr reading code happens.
       */
      res = 0;
      while (res <= 0) {
        if (res < 0) {
          if (errno != EINTR) {
            exec_log("error: unable to wait for pid %d: %s", pid,
              strerror(errno));
            status = -1;
            break;

          } else {
            pr_signals_handle();
            continue;
          }
        }

        if (exec_timeout > 0) {
          /* Check the time elapsed since we started. */
          if ((time(NULL) - start_time) > exec_timeout) {

            /* Send TERM, the first time, to be polite. */
            if (send_sigterm) {
              send_sigterm = 0;
              exec_log("'%s' has exceeded ExecTimeout (%lu seconds), sending "
                "SIGTERM (signal %d)", (const char *) c->argv[2],
                (unsigned long) exec_timeout, SIGTERM);
              kill(pid, SIGTERM);

            } else {
              /* The child is still around?  Terminate with extreme
               * prejudice.
               */
              exec_log("'%s' has exceeded ExecTimeout (%lu seconds), sending "
                "SIGKILL (signal %d)", (const char *) c->argv[2],
                (unsigned long) exec_timeout, SIGKILL);
              kill(pid, SIGKILL);
            }
          }
        }

        /* Select on the pipe read fds, to see if the child has anything
         * to tell us.
         */
        FD_ZERO(&readfds);

        if ((exec_opts & EXEC_OPT_LOG_STDOUT) ||
            (exec_opts & EXEC_OPT_SEND_STDOUT)) {
          FD_SET(exec_stdout_pipe[0], &readfds);

          if (exec_stdout_pipe[0] > maxfd) {
            maxfd = exec_stdout_pipe[0];
          }
        }

        if (exec_opts & EXEC_OPT_LOG_STDERR) {
          FD_SET(exec_stderr_pipe[0], &readfds);

          if (exec_stderr_pipe[0] > maxfd) {
            maxfd = exec_stderr_pipe[0];
          }
        }

        /* Note: this delay should be configurable somehow. */
        tv.tv_sec = 2L;
        tv.tv_usec = 0L;

        fds = select(maxfd + 1, &readfds, NULL, NULL, &tv);
        if (fds == -1 &&
            errno == EINTR) {
          pr_signals_handle();
        }

        if (fds >= 0) {
          long buflen, bufsz;
          char *buf;

          buf = pr_fsio_getpipebuf(tmp_pool, exec_stdout_pipe[0], &bufsz);

          /* The child sent us something.  How thoughtful. */

          if (FD_ISSET(exec_stdout_pipe[0], &readfds)) {
            memset(buf, '\0', bufsz);

            buflen = read(exec_stdout_pipe[0], buf, bufsz-1);
            if (buflen > 0) {
              if (exec_opts & EXEC_OPT_SEND_STDOUT) {

                if (!(flags & EXEC_FL_NO_SEND)) {
                  if (flags & EXEC_FL_USE_SEND) {
                    pr_response_send(R_220, "%s", buf);

                  } else {
                    pr_response_add(R_DUP, "%s", buf);
                  }

                } else {
                  exec_log("not appropriate to send stdout to client at "
                    "this time");
                }
              }

              /* Trim trailing CRs and LFs. */
              while (buflen > 0 &&
                     (buf[buflen-1] == '\r' || buf[buflen-1] == '\n')) {
                pr_signals_handle();
                buf[buflen-1] = '\0';
                buflen--;
              }

              /* We told read(2) that the size of buf is one less than its
               * actual size.  Which means that the buflen value returned
               * by read(2) can, at most, be one less than the size of buf.
               * Thus it should be OK to do the following.
               */
              buf[buflen] = '\0';

              if (exec_opts & EXEC_OPT_LOG_STDOUT) {
                exec_log("stdout from '%s': '%s'", (const char *) c->argv[2],
                  buf);
              }

            } else if (buflen < 0) {
              if (errno != 0) {
                exec_log("error reading stdout from '%s': %s",
                  (const char *) c->argv[2], strerror(errno));
              }
            }
          }

          if (FD_ISSET(exec_stderr_pipe[0], &readfds)) {
            memset(buf, '\0', bufsz);

            buflen = read(exec_stderr_pipe[0], buf, bufsz-1);
            if (buflen > 0) {

              /* Trim trailing CRs and LFs. */
              while (buflen > 0 &&
                     (buf[buflen-1] == '\r' || buf[buflen-1] == '\n')) {
                pr_signals_handle();
                buf[buflen-1] = '\0';
                buflen--;
              }

              /* We told read(2) that the size of buf is one less than its
               * actual size.  Which means that the buflen value returned
               * by read(2) can, at most, be one less than the size of buf.
               * Thus it should be OK to do the following.
               */
              buf[buflen] = '\0';

              if (exec_opts & EXEC_OPT_LOG_STDERR) {
                exec_log("stderr from '%s': '%s'", (const char *) c->argv[2],
                  buf);
              }

            } else if (buflen < 0) {
              if (errno != 0) {
                exec_log("error reading stderr from '%s': %s",
                  (const char *) c->argv[2], strerror(errno));
              }
            }
          }
        }

        res = waitpid(pid, &status, WNOHANG);
      }

      if (cmd == NULL) {
        destroy_pool(tmp_pool);
      }

    } else {
      res = waitpid(pid, &status, 0);
      while (res <= 0) {
        if (res < 0) {
          if (errno != EINTR) {
            exec_log("error: unable to wait for pid %d: %s", pid,
              strerror(errno));
            status = -1;
            break;

          } else {
            pr_signals_handle();
            continue;
          }
        }

        res = waitpid(pid, &status, 0);
      }
    }
  }

  close(exec_stdout_pipe[0]);
  close(exec_stderr_pipe[0]);

  /* Restore the previous signal actions. */
  if (sigaction(SIGINT, &sa_intr, NULL) < 0) {
    exec_log("sigaction() error: %s", strerror(errno));
    return errno;
  }

  if (sigaction(SIGQUIT, &sa_quit, NULL) < 0) {
    exec_log("sigaction() error: %s", strerror(errno));
    return errno;
  }

  if (sigprocmask(SIG_SETMASK, &set_save, NULL) < 0) {
    exec_log("sigprocmask() error: %s", strerror(errno));
    return errno;
  }

  if (WIFEXITED(status)) {
    int exit_status;

    exit_status = WEXITSTATUS(status);
    exec_log("'%s' terminated normally, with exit status %d",
      (const char *) c->argv[2], exit_status);
    return exit_status;
  }

  if (WIFSIGNALED(status)) {
    exec_log("'%s' died from signal %d", (const char *) c->argv[2],
      WTERMSIG(status));

    if (WCOREDUMP(status)) {
      exec_log("'%s' created a coredump", (const char *) c->argv[2]);
    }

    return EPERM;
  }

  return status;
}

/* Perform any substitution of "magic cookie" values. */
static const char *exec_subst_var(pool *tmp_pool, const char *varstr,
    cmd_rec *cmd) {
  char *ptr = NULL;

  if (varstr == NULL) {
    return NULL;
  }

  ptr = strstr(varstr, "%a");
  if (ptr != NULL) {
    const pr_netaddr_t *remote_addr;

    remote_addr = pr_netaddr_get_sess_remote_addr();
    varstr = sreplace(tmp_pool, varstr, "%a",
      remote_addr ? pr_netaddr_get_ipstr(remote_addr) : "", NULL);
  }

  ptr = strstr(varstr, "%A");
  if (ptr != NULL) {
    const char *anon_pass;

    anon_pass = pr_table_get(session.notes, "mod_auth.anon-passwd", NULL);
    if (anon_pass == NULL) {
      anon_pass = "UNKNOWN";
    }

    varstr = sreplace(tmp_pool, varstr, "%A", anon_pass, NULL);
  }

  ptr = strstr(varstr, "%b");
  if (ptr != NULL) {
    char buf[1024];

    memset(buf, '\0', sizeof(buf));

    if (session.xfer.p != NULL) {
      pr_snprintf(buf, sizeof(buf)-1, "%" PR_LU,
        (pr_off_t) session.xfer.total_bytes);
    }

    varstr = sreplace(tmp_pool, varstr, "%b", buf, NULL);
  }

  ptr = strstr(varstr, "%C");
  if (ptr != NULL) {
    varstr = sreplace(tmp_pool, varstr, "%C",
      session.cwd[0] ? session.cwd : "", NULL);
  }

  ptr = strstr(varstr, "%c");
  if (ptr != NULL) {
    varstr = sreplace(tmp_pool, varstr, "%c",
      session.conn_class ? session.conn_class->cls_name : "", NULL);
  }

  ptr = strstr(varstr, "%F");
  if (ptr != NULL &&
      cmd != NULL) {
    if (pr_cmd_cmp(cmd, PR_CMD_RNTO_ID) == 0) {
      char *path;

      path = dir_best_path(tmp_pool, pr_fs_decode_path(tmp_pool, cmd->arg));
      varstr = sreplace(tmp_pool, varstr, "%F", path, NULL);

    } else if (session.xfer.p &&
               session.xfer.path) {
      varstr = sreplace(tmp_pool, varstr, "%F", session.xfer.path, NULL);

    } else if (session.curr_phase == PRE_CMD &&
               (pr_cmd_cmp(cmd, PR_CMD_STOR_ID) == 0 ||
                pr_cmd_cmp(cmd, PR_CMD_RETR_ID) == 0 ||
                pr_cmd_cmp(cmd, PR_CMD_APPE_ID) == 0)) {
      char *path;

      /* If we're in the PRE_CMD phase, then the %f variable can't be
       * filled in using session.xfer.path for STOR, RETR, and APPE.
       */
      path = dir_best_path(tmp_pool, pr_fs_decode_path(tmp_pool, cmd->arg));
      varstr = sreplace(tmp_pool, varstr, "%F", path, NULL);

    } else {
      /* Some commands (i.e. DELE) have associated filenames that are not
       * stored in the session.xfer structure; these should be expanded
       * properly as well.
       */
      if (pr_cmd_cmp(cmd, PR_CMD_DELE_ID) == 0) {
        char *path;

        path = dir_best_path(tmp_pool, pr_fs_decode_path(tmp_pool, cmd->arg));
        varstr = sreplace(tmp_pool, varstr, "%F", path, NULL);

      } else {
        varstr = sreplace(tmp_pool, varstr, "%F", "", NULL);
      }
    }
  }

  ptr = strstr(varstr, "%f");
  if (ptr != NULL &&
      cmd != NULL) {

    if (pr_cmd_cmp(cmd, PR_CMD_RNTO_ID) == 0) {
      char *path;

      path = pr_fs_decode_path(tmp_pool, cmd->arg);
      varstr = sreplace(tmp_pool, varstr, "%f",
        dir_abs_path(tmp_pool, path, TRUE), NULL);

    } else if (session.xfer.p &&
               session.xfer.path) {
      varstr = sreplace(tmp_pool, varstr, "%f",
        dir_abs_path(tmp_pool, session.xfer.path, TRUE), NULL);

    } else if (session.curr_phase == PRE_CMD &&
               (pr_cmd_cmp(cmd, PR_CMD_STOR_ID) == 0 ||
                pr_cmd_cmp(cmd, PR_CMD_RETR_ID) == 0 ||
                pr_cmd_cmp(cmd, PR_CMD_APPE_ID) == 0)) {
      char *path;

      /* If we're in the PRE_CMD phase, then the %f variable can't be
       * filled in using session.xfer.path for STOR, RETR, and APPE.
       */

      path = pr_fs_decode_path(tmp_pool, cmd->arg);
      varstr = sreplace(tmp_pool, varstr, "%f",
        dir_abs_path(tmp_pool, path, TRUE), NULL);

    } else {
      /* Some commands (i.e. DELE, MKD, RMD, XMKD, and XRMD) have associated
       * filenames that are not stored in the session.xfer structure; these
       * should be expanded properly as well.
       */
      if (pr_cmd_cmp(cmd, PR_CMD_DELE_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_MKD_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_RMD_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_XMKD_ID) == 0 ||
          pr_cmd_cmp(cmd, PR_CMD_XRMD_ID) == 0) {
        varstr = sreplace(tmp_pool, varstr, "%f",
          dir_abs_path(tmp_pool, cmd->arg, TRUE), NULL);

      } else {

        /* All other situations get a "".  */
        varstr = sreplace(tmp_pool, varstr, "%f", "", NULL);
      }
    }
  }

  ptr = strstr(varstr, "%g");
  if (ptr != NULL) {
    varstr = sreplace(tmp_pool, varstr, "%g",
      session.group ? session.group : "", NULL);
  }

  ptr = strstr(varstr, "%h");
  if (ptr != NULL) {
    const char *remote_name;

    remote_name = pr_netaddr_get_sess_remote_name();
    varstr = sreplace(tmp_pool, varstr, "%h",
      remote_name ? remote_name : "", NULL);
  }

  ptr = strstr(varstr, "%l");
  if (ptr != NULL) {
    const char *rfc1413_ident;

    rfc1413_ident = pr_table_get(session.notes, "mod_ident.rfc1413-ident",
      NULL);
    if (rfc1413_ident == NULL) {
      rfc1413_ident = "UNKNOWN";
    }

    varstr = sreplace(tmp_pool, varstr, "%l", rfc1413_ident, NULL);
  }

  ptr = strstr(varstr, "%m");
  if (ptr != NULL) {
    varstr = sreplace(tmp_pool, varstr, "%m", cmd ? cmd->argv[0] : "", NULL);
  }

  ptr = strstr(varstr, "%r");
  if (ptr != NULL &&
      cmd != NULL) {
    if (pr_cmd_cmp(cmd, PR_CMD_PASS_ID) == 0 &&
        session.hide_password) {
      varstr = sreplace(tmp_pool, varstr, "%r", "PASS (hidden)", NULL);

    } else {
      varstr = sreplace(tmp_pool, varstr, "%r",
        pr_cmd_get_displayable_str(cmd, NULL), NULL);
    }
  }

  ptr = strstr(varstr, "%U");
  if (ptr != NULL) {
    const char *user;

    user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
    varstr = sreplace(tmp_pool, varstr, "%U",
      user ? user : "", NULL);
  }

  ptr = strstr(varstr, "%u");
  if (ptr != NULL) {
    varstr = sreplace(tmp_pool, varstr, "%u",
      session.user ? session.user : "", NULL);
  }

  ptr = strstr(varstr, "%V");
  if (ptr != NULL) {
    varstr = sreplace(tmp_pool, varstr, "%V",
      pr_netaddr_get_dnsstr(pr_netaddr_get_sess_local_addr()), NULL);
  }

  ptr = strstr(varstr, "%v");
  if (ptr != NULL) {
    varstr = sreplace(tmp_pool, varstr, "%v", cmd ? cmd->server->ServerName :
      "", NULL);
  }

  ptr = strstr(varstr, "%w");
  if (ptr != NULL &&
      cmd != NULL) {
    const char *rnfr_path = "-";

    if (pr_cmd_cmp(cmd, PR_CMD_RNTO_ID) == 0) {
      rnfr_path = pr_table_get(session.notes, "mod_core.rnfr-path", NULL);
      if (rnfr_path == NULL) {
        rnfr_path = "-";
      }
    }

    varstr = sreplace(tmp_pool, varstr, "%w", rnfr_path, NULL);
  }

  /* Check for any Variable-style strings. */
  ptr = strstr(varstr, "%{");
  while (ptr) {
    char *key, *ptr2;
    const char *val;

    pr_signals_handle();

    ptr2 = strchr(ptr, '}');
    if (ptr2 == NULL) {
      ptr = strstr(ptr + 1, "%{");
      continue;
    }

    key = pstrndup(tmp_pool, ptr, ptr2 - ptr + 1);

    /* There are a couple of special-case keys to watch for:
     *
     *   env:$var
     *   time:$fmt
     *
     * The Var API does not easily support returning values for keys
     * where part of the value depends on part of the key.  That's why
     * these keys are handled here, instead of in pr_var_get().
     */

    if (strncmp(key, "%{time:", 7) == 0) {
      char time_str[128], *fmt;
      time_t now;
      struct tm *tm;

      fmt = pstrndup(tmp_pool, key + 7, strlen(key) - 8);

      now = time(NULL);
      memset(time_str, 0, sizeof(time_str));

      tm = pr_localtime(NULL, &now);
      if (tm != NULL) {
        strftime(time_str, sizeof(time_str), fmt, tm);
      }

      val = pstrdup(tmp_pool, time_str);

    } else if (strncmp(key, "%{env:", 6) == 0) {
      char *env_var;

      env_var = pstrndup(tmp_pool, key + 6, strlen(key) - 7);
      val = pr_env_get(tmp_pool, env_var);
      if (val == NULL) {
        pr_trace_msg("var", 4,
          "no value set for environment variable '%s', using \"(none)\"",
          env_var);
        val = "(none)";
      }

    } else {
      val = pr_var_get(key);
      if (val == NULL) {
        pr_trace_msg("var", 4,
          "no value set for name '%s', using \"(none)\"", key);
        val = "(none)";
      }
    }

    varstr = sreplace(tmp_pool, varstr, key, val, NULL);

    ptr = strstr(varstr, "%{");
  }

  return varstr;
}

/* Command handlers
 */

MODRET exec_pre_cmd(cmd_rec *cmd) {
  config_rec *c = NULL;
  array_header *seen_execs = NULL;

  if (!exec_engine) {
    return PR_DECLINED(cmd);
  }

  if (!exec_enabled()) {
    return PR_DECLINED(cmd);
  }

  /* Create an array that will contain the IDs of the Execs we've
   * already processed.
   */
  seen_execs = make_array(cmd->tmp_pool, 0, sizeof(unsigned int));

  c = find_config(CURRENT_CONF, CONF_PARAM, "ExecBeforeCommand", FALSE);
  while (c) {
    pr_signals_handle();

    /* If we've already seen this Exec, skip on to the next Exec. */
    if (seen_execs->nelts > 0) {
      register unsigned int i = 0;
      unsigned char saw_exec = FALSE;
      unsigned int id = *((unsigned int *) c->argv[0]), *ids = seen_execs->elts;

      for (i = 0; i < seen_execs->nelts; i++) {
        if (ids[i] == id) {
          saw_exec = TRUE;
          break;
        }
      }

      if (saw_exec) {
        exec_log("already saw this Exec, skipping");
        c = find_config_next(c, c->next, CONF_PARAM, "ExecBeforeCommand",
          FALSE);
        continue;
      }
    }

    /* Add this Exec's ID to the list of seen Execs. */
    *((unsigned int *) push_array(seen_execs)) = *((unsigned int *) c->argv[0]);

    /* Check the command list for this program against the current command. */
    if (exec_match_cmd(cmd, c->argv[1])) {
      int res = exec_ssystem(cmd, c, EXEC_FL_NO_SEND);
      if (res != 0) {
        exec_log("%s ExecBeforeCommand '%s' failed: %s", (char *) cmd->argv[0],
          (const char *) c->argv[2], strerror(res));

      } else {
        exec_log("%s ExecBeforeCommand '%s' succeeded", (char *) cmd->argv[0],
          (const char *) c->argv[2]);
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "ExecBeforeCommand", FALSE);
  }

  return PR_DECLINED(cmd);
}

MODRET exec_post_cmd(cmd_rec *cmd) {
  config_rec *c = NULL;
  array_header *seen_execs = NULL;

  if (!exec_engine) {
    return PR_DECLINED(cmd);
  }

  if (!exec_enabled()) {
    return PR_DECLINED(cmd);
  }

  /* Create an array that will contain the IDs of the Execs we've
   * already processed.
   */
  seen_execs = make_array(cmd->tmp_pool, 0, sizeof(unsigned int));

  c = find_config(CURRENT_CONF, CONF_PARAM, "ExecOnCommand", FALSE);
  while (c) {
    pr_signals_handle();

    /* If we've already seen this Exec, skip on to the next Exec. */
    if (seen_execs->nelts > 0) {
      register unsigned int i = 0;
      unsigned char saw_exec = FALSE;
      unsigned int id = *((unsigned int *) c->argv[0]), *ids = seen_execs->elts;

      for (i = 0; i < seen_execs->nelts; i++) {
        if (ids[i] == id) {
          saw_exec = TRUE;
          break;
        }
      }

      if (saw_exec) {
        exec_log("already saw this Exec, skipping");
        c = find_config_next(c, c->next, CONF_PARAM, "ExecOnCommand", FALSE);
        continue;
      }
    }

    /* Add this Exec's ID to the list of seen Execs. */
    *((unsigned int *) push_array(seen_execs)) = *((unsigned int *) c->argv[0]);

    /* Check the command list for this program against the command. */
    if (exec_match_cmd(cmd, c->argv[1])) {
      int res = exec_ssystem(cmd, c, 0);
      if (res != 0) {
        exec_log("%s ExecOnCommand '%s' failed: %s", (char *) cmd->argv[0],
          (const char *) c->argv[2], strerror(res));

      } else {
        exec_log("%s ExecOnCommand '%s' succeeded", (char *) cmd->argv[0],
          (const char *) c->argv[2]);
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "ExecOnCommand", FALSE);
  }

  return PR_DECLINED(cmd);
}

MODRET exec_post_cmd_err(cmd_rec *cmd) {
  config_rec *c = NULL;
  array_header *seen_execs = NULL;

  if (!exec_engine) {
    return PR_DECLINED(cmd);
  }

  if (!exec_enabled()) {
    return PR_DECLINED(cmd);
  }

  /* Create an array that will contain the IDs of the Execs we've
   * already processed.
   */
  seen_execs = make_array(cmd->tmp_pool, 0, sizeof(unsigned int));

  c = find_config(CURRENT_CONF, CONF_PARAM, "ExecOnError", FALSE);
  while (c) {
    pr_signals_handle();

    /* If we've already seen this Exec, skip on to the next Exec. */
    if (seen_execs->nelts > 0) {
      register unsigned int i = 0;
      unsigned char saw_exec = FALSE;
      unsigned int id = *((unsigned int *) c->argv[0]), *ids = seen_execs->elts;

      for (i = 0; i < seen_execs->nelts; i++) {
        if (ids[i] == id) {
          saw_exec = TRUE;
          break;
        }
      }

      if (saw_exec) {
        exec_log("already saw this Exec, skipping");
        c = find_config_next(c, c->next, CONF_PARAM, "ExecOnError", FALSE);
        continue;
      }
    }

    /* Add this Exec's ID to the list of seen Execs. */
    *((unsigned int *) push_array(seen_execs)) = *((unsigned int *) c->argv[0]);

    /* Check the command list for this program against the errored command. */
    if (exec_match_cmd(cmd, c->argv[1])) {
      int res;

      res = exec_ssystem(cmd, c, 0);
      if (res != 0) {
        exec_log("%s ExecOnError '%s' failed: %s", (char *) cmd->argv[0],
          (const char *) c->argv[2], strerror(res));

      } else {
        exec_log("%s ExecOnError '%s' succeeded", (char *) cmd->argv[0],
          (const char *) c->argv[2]);
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "ExecOnError", FALSE);
  }

  return PR_DECLINED(cmd);
}

/* Configuration directive handlers
 */

/* usage: ExecBeforeCommand cmds path [args] */
MODRET set_execbeforecommand(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  char *path;

  if (cmd->argc-1 < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR);

  path = cmd->argv[2];
  if (*path != '/') {
    CONF_ERROR(cmd, "path to program must be a full path");
  }

  c = add_config_param(cmd->argv[0], 0);
  c->argc = cmd->argc + 1;
  c->argv = pcalloc(c->pool, sizeof(void *) * (c->argc + 1));

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = exec_nexecs++;

  exec_parse_cmds(c, cmd->argv[1]);

  for (i = 2; i < cmd->argc; i++) {
    c->argv[i] = pstrdup(c->pool, cmd->argv[i]);
  }

  c->flags |= CF_MERGEDOWN_MULTI;

  return PR_HANDLED(cmd);
}

/* usage: ExecEnable on|off */
MODRET set_execenable(cmd_rec *cmd) {
  int enable = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ANON|CONF_DIR|CONF_DYNDIR);

  enable = get_boolean(cmd, 1);
  if (enable == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = enable;

  return PR_HANDLED(cmd);
}

/* usage: ExecEngine on|off */
MODRET set_execengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  /* Also set this here, for the daemon process. */
  exec_engine = engine;
 
  return PR_HANDLED(cmd);
}

/* usage: ExecEnviron variable value */
MODRET set_execenviron(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  char *key;

  CHECK_ARGS(cmd, 2);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param_str(cmd->argv[0], 2, NULL, cmd->argv[2]);

  /* Make sure the given environment variable name is uppercased.
   * NOTE: Are there cases where this SHOULD NOT happen?  Why should
   * environment variable names always be uppercased?
   */
  key = cmd->argv[1];

  for (i = 0; i < strlen(key); i++) {
    key[i] = toupper(key[i]);
  }

  c->argv[0] = pstrdup(c->pool, key);
  return PR_HANDLED(cmd);
}

/* usage: ExecLog path|"none" */
MODRET set_execlog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: ExecOnCommand cmds path [args] */
MODRET set_execoncommand(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  char *path;

  if (cmd->argc-1 < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR);

  path = cmd->argv[2];
  if (*path != '/') {
    CONF_ERROR(cmd, "path to program must be a full path");
  }

  c = add_config_param(cmd->argv[0], 0);
  c->argc = cmd->argc + 1;
  c->argv = pcalloc(c->pool, sizeof(void *) * (c->argc + 1));

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = exec_nexecs++;

  exec_parse_cmds(c, cmd->argv[1]);

  for (i = 2; i < cmd->argc; i++) {
    c->argv[i] = pstrdup(c->pool, cmd->argv[i]);
  }

  c->flags |= CF_MERGEDOWN_MULTI;
  return PR_HANDLED(cmd);
}

/* usage: ExecOnConnect path [args] */
MODRET set_execonconnect(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  char *path;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  path = cmd->argv[1];
  if (*path != '/') {
    CONF_ERROR(cmd, "path to program must be a full path");
  }

  c = add_config_param(cmd->argv[0], 0);
  c->argc = cmd->argc + 1;

  /* Add one for the terminating NULL. */
  c->argv = pcalloc(c->pool, sizeof(void *) * (c->argc + 1)); 

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = exec_nexecs++;

  for (i = 1; i < cmd->argc; i++) {
    c->argv[i+1] = pstrdup(c->pool, cmd->argv[i]);
  }

  return PR_HANDLED(cmd);
}

/* usage: ExecOnError cmds path [args] */
MODRET set_execonerror(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  char *path;

  if (cmd->argc-1 < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|
    CONF_DIR); 

  path = cmd->argv[2];
  if (*path != '/') {
    CONF_ERROR(cmd, "path to program must be a full path");
  }

  c = add_config_param(cmd->argv[0], 0);
  c->argc = cmd->argc + 1;
  c->argv = pcalloc(c->pool, sizeof(void *) * (c->argc + 1));

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = exec_nexecs++;

  exec_parse_cmds(c, cmd->argv[1]);
  
  for (i = 2; i < cmd->argc; i++) {
    c->argv[i] = pstrdup(c->pool, cmd->argv[i]);
  }

  c->flags |= CF_MERGEDOWN_MULTI;
  return PR_HANDLED(cmd);
}

/* usage: ExecOnEvent event path [args] */
MODRET set_execonevent(cmd_rec *cmd) {
  register unsigned int i;
  unsigned int flags = EXEC_FL_CLEAR_GROUPS|EXEC_FL_NO_SEND;
  char *event_name, *path;
  size_t event_namelen;
  config_rec *c;
  struct exec_event_data *eed;

  if (cmd->argc-1 < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  event_name = cmd->argv[1];
  event_namelen = strlen(event_name);

  if (event_name[event_namelen-1] == '*') {
    flags |= EXEC_FL_RUN_AS_ROOT;
    event_name[event_namelen-1] = '\0';
    event_namelen--;

  } else if (event_name[event_namelen-1] == '~') {
    flags |= EXEC_FL_RUN_AS_USER;
    event_name[event_namelen-1] = '\0';
    event_namelen--;
  }

  path = cmd->argv[2];
  if (*path != '/') {
    CONF_ERROR(cmd, "path to program must be a full path");
  }

  c = pcalloc(cmd->server->pool, sizeof(config_rec));
  c->pool = make_sub_pool(cmd->server->pool);
  pr_pool_tag(c->pool, cmd->argv[0]);
  c->argc = cmd->argc + 1;
  c->argv = pcalloc(c->pool, sizeof(void *) * (c->argc + 1));

  /* Unused for event config_recs. */
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  c->argv[1] = NULL;

  for (i = 2; i < cmd->argc; i++) {
    c->argv[i] = pstrdup(c->pool, cmd->argv[i]);
  }

  eed = pcalloc(c->pool, sizeof(struct exec_event_data));
  eed->flags = flags;
  eed->event = pstrdup(c->pool, event_name);
  eed->c = c;

  if (strncasecmp(eed->event, "MaxConnectionRate", 18) == 0) {
    pr_event_register(&exec_module, "core.max-connection-rate", exec_any_ev,
      eed);

  } else if (strncasecmp(eed->event, "MaxInstances", 13) == 0) {
     pr_event_register(&exec_module, "core.max-instances", exec_any_ev, eed);

  } else {
    /* Assume that the sysadmin knows the name of the event to use. */
    pr_event_register(&exec_module, eed->event, exec_any_ev, eed);
  }

  return PR_HANDLED(cmd);
}

/* usage: ExecOnExit path [args] */
MODRET set_execonexit(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  char *path;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  path = cmd->argv[1];
  if (*path != '/') {
    CONF_ERROR(cmd, "path to program must be a full path");
  }

  c = add_config_param(cmd->argv[0], 0);
  c->argc = cmd->argc + 1;

  /* Add one for the terminating NULL. */
  c->argv = pcalloc(c->pool, sizeof(void *) * (c->argc + 1));

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = exec_nexecs++;

  for (i = 1; i < cmd->argc; i++) {
    c->argv[i+1] = pstrdup(c->pool, cmd->argv[i]);
  }

  return PR_HANDLED(cmd);
}

/* usage: ExecOnRestart path [args] */
MODRET set_execonrestart(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  char *path;

  if (cmd->argc-1 < 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  path = cmd->argv[1];
  if (*path != '/') {
    CONF_ERROR(cmd, "path to program must be a full path");
  }

  c = add_config_param(cmd->argv[0], 0);
  c->argc = cmd->argc + 1;

  /* Add one for the terminating NULL. */
  c->argv = pcalloc(c->pool, sizeof(void *) * (c->argc + 1));

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = exec_nexecs++;

  for (i = 1; i < cmd->argc; i++) {
    c->argv[i+1] = pstrdup(c->pool, cmd->argv[i]);
  }

  return PR_HANDLED(cmd);
}

/* usage: ExecOptions opt1 opt2 ... optN */
MODRET set_execoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i;
  unsigned int opts = 0U;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strncmp(cmd->argv[i], "logStdout", 10) == 0) {
      opts |= EXEC_OPT_LOG_STDOUT;

    } else if (strncmp(cmd->argv[i], "logStderr", 10) == 0) {
      opts |= EXEC_OPT_LOG_STDERR;

    } else if (strncmp(cmd->argv[i], "sendStdout", 11) == 0) {
      opts |= EXEC_OPT_SEND_STDOUT;

    } else if (strncmp(cmd->argv[i], "useStdin", 9) == 0) {
      opts |= EXEC_OPT_USE_STDIN;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown ExecOption: '",
        (char *) cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = palloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: ExecTimeout <seconds> */
MODRET set_exectimeout(cmd_rec *cmd) {
  int timeout = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (pr_str_get_duration(cmd->argv[1], &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      cmd->argv[1], "': ", strerror(errno), NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;

  return PR_HANDLED(cmd);
}

/* Event handlers
 */

static void exec_any_ev(const void *event_data, void *user_data) {
  struct exec_event_data *eed = user_data;
  int res;

  if (!exec_engine)
    return;

  res = exec_ssystem(NULL, eed->c, eed->flags);
  if (res != 0) {
    exec_log("ExecOnEvent '%s' for %s failed: %s", eed->event,
      (const char *) eed->c->argv[2], strerror(res));

  } else {
    exec_log("ExecOnEvent '%s' for %s succeeded", eed->event,
      (const char *) eed->c->argv[2]);
  }
}

static void exec_exit_ev(const void *event_data, void *user_data) {
  config_rec *c = NULL;

  if (!exec_engine)
    return;

  c = find_config(main_server->conf, CONF_PARAM, "ExecOnExit", FALSE);
  while (c) {
    int res;

    pr_signals_handle();

    res = exec_ssystem(NULL, c, EXEC_FL_CLEAR_GROUPS|EXEC_FL_NO_SEND);
    if (res != 0) {
      exec_log("ExecOnExit '%s' failed: %s", (const char *) c->argv[2],
        strerror(res));

    } else {
      exec_log("ExecOnExit '%s' succeeded", (const char *) c->argv[2]);
    }

    c = find_config_next(c, c->next, CONF_PARAM, "ExecOnExit", FALSE);
  }

  return;
}

#if defined(PR_SHARED_MODULE)
static void exec_mod_unload_ev(const void *event_data, void *user_data) {
  if (strncmp("mod_exec.c", (const char *) event_data, 11) == 0) {
    if (exec_pool) {
      destroy_pool(exec_pool);
      exec_pool = NULL;
    }

    pr_event_unregister(&exec_module, NULL, NULL);

    close(exec_logfd);
    exec_logfd = -1;
  }
}
#endif /* PR_SHARED_MODULE */

static void exec_postparse_ev(const void *event_data, void *user_data) {
  exec_openlog();
}

static void exec_restart_ev(const void *event_data, void *user_data) {

  if (exec_pool) {
    destroy_pool(exec_pool);
    exec_pool = NULL;
  }

  if (exec_engine) {
    config_rec *c = NULL;

    exec_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(exec_pool, MOD_EXEC_VERSION);

    /* Make sure the User/Group IDs are set, so the the PRIVS_REVOKE call
     * later succeeds properly.
     */
    {
      uid_t *uid = (uid_t *) get_param_ptr(main_server->conf, "UserID", FALSE);
      gid_t *gid = (gid_t *) get_param_ptr(main_server->conf, "GroupID", FALSE);

      session.uid = uid ? *uid : geteuid();
      session.gid = gid ? *gid : getegid();
    }

    c = find_config(main_server->conf, CONF_PARAM, "ExecOnRestart", FALSE);

    while (c) {
      int res;

      pr_signals_handle();

      res = exec_ssystem(NULL, c, EXEC_FL_CLEAR_GROUPS|EXEC_FL_NO_SEND);
      if (res != 0) {
        exec_log("ExecOnRestart '%s' failed: %s", (const char *) c->argv[1],
          strerror(res));

      } else {
        exec_log("ExecOnRestart '%s' succeeded", (const char *) c->argv[1]);
      }

      c = find_config_next(c, c->next, CONF_PARAM, "ExecOnRestart", FALSE);
    }
  }

  pr_event_unregister(&exec_module, "core.max-connection-rate", NULL);
  pr_event_unregister(&exec_module, "core.max-instances", NULL);

  /* Bounce the log file descriptor. */
  exec_closelog();
  exec_openlog();

  return;
}

static void exec_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&exec_module, "core.exit", exec_exit_ev);
  pr_event_unregister(&exec_module, "core.session-reinit", exec_sess_reinit_ev);

  exec_engine = FALSE;
  exec_opts = 0U;
  exec_timeout = 0;

  (void) close(exec_logfd);
  exec_logfd = -1;
  exec_logname = NULL;

  res = exec_sess_init();
  if (res < 0) {
    pr_session_disconnect(&exec_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Initialization routines
 */

static int exec_sess_init(void) {
  int *use_exec = NULL;
  config_rec *c = NULL;
  const char *proto;

  pr_event_register(&exec_module, "core.session-reinit", exec_sess_reinit_ev,
    NULL);

  use_exec = get_param_ptr(main_server->conf, "ExecEngine", FALSE);
  if (use_exec != NULL &&
      *use_exec == TRUE) {
    exec_engine = TRUE;

  } else {
    exec_engine = FALSE;
    return 0;
  }

  pr_event_register(&exec_module, "core.exit", exec_exit_ev, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "ExecOptions", FALSE);
  while (c != NULL) {
    unsigned long opts;

    pr_signals_handle();

    opts = *((unsigned int *) c->argv[0]);
    exec_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "ExecOptions", FALSE);
  }

  /* If we are handling an SSH2 session, then disable the sendStdout
   * ExecOption, if present.
   *
   * Attempting to send the stdout of commands to connecting SSH2 clients
   * can confuse them and lead to connection problems.
   */
  proto = pr_session_get_protocol(0);
  if (strncmp(proto, "ssh2", 5) == 0) {
    exec_opts &= ~EXEC_OPT_SEND_STDOUT;
  }

  c = find_config(main_server->conf, CONF_PARAM, "ExecTimeout", FALSE);
  if (c) {
    exec_timeout = *((int *) c->argv[0]);
  }

  exec_closelog();
  exec_openlog();

  /* Make sure the User/Group IDs are set, so the the PRIVS_REVOKE call
   * later succeeds properly.
   */
  {
    uid_t *uid = (uid_t *) get_param_ptr(main_server->conf, "UserID", FALSE);
    gid_t *gid = (gid_t *) get_param_ptr(main_server->conf, "GroupID", FALSE);

    session.uid = uid ? *uid : geteuid();
    session.gid = gid ? *gid : getegid();
  }

  c = find_config(main_server->conf, CONF_PARAM, "ExecOnConnect", FALSE);
  while (c) {
    int res;

    pr_signals_handle();

    res = exec_ssystem(NULL, c, EXEC_FL_CLEAR_GROUPS|EXEC_FL_USE_SEND);
    if (res != 0) {
      exec_log("ExecOnConnect '%s' failed: %s", (const char *) c->argv[2],
        strerror(res));

    } else {
      exec_log("ExecOnConnect '%s' succeeded", (const char *) c->argv[2]);
    }

    c = find_config_next(c, c->next, CONF_PARAM, "ExecOnConnect", FALSE);
  }

  return 0;
}

static int exec_init(void) {
  exec_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(exec_pool, MOD_EXEC_VERSION);

  /* Register event handlers. */
#if defined(PR_SHARED_MODULE)
  pr_event_register(&exec_module, "core.module-unload", exec_mod_unload_ev,
    NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&exec_module, "core.postparse", exec_postparse_ev, NULL);
  pr_event_register(&exec_module, "core.restart", exec_restart_ev, NULL);

  return 0;
}

/* Module API tables
 */

static conftable exec_conftab[] = {
  { "ExecBeforeCommand",set_execbeforecommand,	NULL },
  { "ExecEnable",	set_execenable,		NULL },
  { "ExecEngine",	set_execengine,		NULL },
  { "ExecEnviron",	set_execenviron,	NULL },
  { "ExecLog",		set_execlog,		NULL },
  { "ExecOnCommand",	set_execoncommand,	NULL },
  { "ExecOnConnect",	set_execonconnect,	NULL },
  { "ExecOnError",	set_execonerror,	NULL },
  { "ExecOnEvent",	set_execonevent,	NULL },
  { "ExecOnExit",	set_execonexit,		NULL },
  { "ExecOnRestart",	set_execonrestart,	NULL },
  { "ExecOptions",	set_execoptions,	NULL },
  { "ExecTimeout",	set_exectimeout,	NULL },
  { NULL }
};

static cmdtable exec_cmdtab[] = {
  { PRE_CMD,		C_ANY,	G_NONE,	exec_pre_cmd,		FALSE,	FALSE },
  { POST_CMD,		C_ANY,	G_NONE, exec_post_cmd,		FALSE,	FALSE },
  { POST_CMD_ERR,	C_ANY,	G_NONE,	exec_post_cmd_err,	FALSE,	FALSE },
  { 0,	NULL }
};

module exec_module = {

  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "exec",

  /* Configuration handler table */
  exec_conftab,

  /* Command handler table */
  exec_cmdtab,

  /* Authentication handler table */
  NULL,

  /* Module initialization */
  exec_init,

  /* Session initialization */
  exec_sess_init,

  /* Module version */
  MOD_EXEC_VERSION
};
