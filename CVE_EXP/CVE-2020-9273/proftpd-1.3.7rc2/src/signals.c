/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2014-2017 The ProFTPD Project team
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
 * As a special exemption, the ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Signal handling. */

#include "conf.h"
#include "privs.h"

#ifdef HAVE_EXECINFO_H
# include <execinfo.h>
#endif

#ifdef HAVE_UCONTEXT_H
# include <ucontext.h>
#endif

/* From src/main.c */
extern unsigned char is_master;
extern pid_t mpid;
extern int nodaemon;

int have_dead_child = FALSE;
volatile unsigned int recvd_signal_flags = 0;

static RETSIGTYPE sig_terminate(int);
static void install_stacktrace_handler(void);

/* Used to capture an "unknown" signal value that causes termination. */
static int term_signo = 0;

static void finish_terminate(int signo) {
  int reason_code = PR_SESS_DISCONNECT_SIGNAL;

  if (is_master &&
      mpid == getpid()) {
    PRIVS_ROOT

    /* Do not need the pidfile any longer. */
    if (ServerType == SERVER_STANDALONE &&
        !nodaemon) {
      pr_pidfile_remove();
    }

    /* Run any exit handlers registered in the master process here, so that
     * they may have the benefit of root privs.  More than likely these
     * exit handlers were registered by modules' module initialization
     * functions, which also occur under root priv conditions.
     *
     * If an exit handler is registered after the fork(), it won't be run here;
     * that registration occurs in a different process space.
     */
    pr_event_generate("core.exit", NULL);
    pr_event_generate("core.shutdown", NULL);

    /* Remove the registered exit handlers now, so that the ensuing
     * pr_session_end() call (outside the root privs condition) does not call
     * the exit handlers for the master process again.
     */
    pr_event_unregister(NULL, "core.exit", NULL);
    pr_event_unregister(NULL, "core.shutdown", NULL);

    PRIVS_RELINQUISH

    if (ServerType == SERVER_STANDALONE) {
      pr_log_pri(PR_LOG_NOTICE, "ProFTPD " PROFTPD_VERSION_TEXT
        " standalone mode SHUTDOWN");

      /* Clean up the scoreboard */
      PRIVS_ROOT
      pr_delete_scoreboard();
      PRIVS_RELINQUISH
    }
  }

  if (signo == SIGSEGV) {
    reason_code = PR_SESS_DISCONNECT_SEGFAULT;
  }

  pr_session_disconnect(NULL, reason_code, "Killed by signal");
}

static void handle_abort(void) {
  pr_log_pri(PR_LOG_NOTICE, "ProFTPD received SIGABRT signal, no core dump");
  finish_terminate(SIGABRT);
}

static void handle_chld(void) {
  sigset_t sig_set;
  pid_t pid;

  sigemptyset(&sig_set);
  sigaddset(&sig_set, SIGTERM);
  sigaddset(&sig_set, SIGCHLD);

  pr_alarms_block();

  /* Block SIGTERM in here, so we don't create havoc with the child list
   * while modifying it.
   */
  if (sigprocmask(SIG_BLOCK, &sig_set, NULL) < 0) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to block signal set: %s", strerror(errno));
  }

  while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
    if (child_remove(pid) == 0) {
      have_dead_child = TRUE;
    }
  }

  if (sigprocmask(SIG_UNBLOCK, &sig_set, NULL) < 0) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to unblock signal set: %s", strerror(errno));
  }

  pr_alarms_unblock();
}

static void handle_evnt(void) {
  pr_event_generate("core.signal.USR2", NULL);
}

static void handle_terminate_with_kids(void) {
  /* Do not log if we are a child that has been terminated. */
  if (is_master == TRUE) {

    /* Send a SIGTERM to all our children */
    if (child_count()) {
      PRIVS_ROOT
      child_signal(SIGTERM);
      PRIVS_RELINQUISH
    }

    pr_log_pri(PR_LOG_NOTICE, "ProFTPD killed (signal %d)", term_signo);
  }

  finish_terminate(term_signo);
}

static void handle_terminate_without_kids(void) {
  pr_log_pri(PR_LOG_WARNING, "ProFTPD terminating (signal %d)", term_signo);
  finish_terminate(term_signo);
}

static void handle_stacktrace_signal(int signo, siginfo_t *info, void *ptr) {
#ifdef HAVE_BACKTRACE
  register int i;
# if defined(HAVE_UCONTEXT_H)
  ucontext_t *uc = NULL;
# endif /* !HAVE_UCONTEXT_H */
  void *trace[PR_TUNABLE_CALLER_DEPTH];
  char **strings = NULL;
  int tracesz;
#endif /* HAVE_BACKTRACE */

  /* Call the "normal" signal handler. */
  table_handling_signal(TRUE);

  pr_log_pri(PR_LOG_ERR, "-----BEGIN STACK TRACE-----");

#ifdef HAVE_BACKTRACE
  tracesz = backtrace(trace, PR_TUNABLE_CALLER_DEPTH);
  if (tracesz < 0) {
    pr_log_pri(PR_LOG_ERR, "backtrace(3) error: %s", strerror(errno));
  }

# if defined(HAVE_UCONTEXT_H)
  /* Overwrite sigaction with caller's address */
  uc = (ucontext_t *) ptr;
#  if defined(REG_EIP)
  trace[1] = (void *) uc->uc_mcontext.gregs[REG_EIP];
#  elif defined(REG_RIP)
  trace[1] = (void *) uc->uc_mcontext.gregs[REG_RIP];
#  endif
# endif /* !HAVE_UCONTEXT_H */

# ifdef HAVE_BACKTRACE_SYMBOLS
  strings = backtrace_symbols(trace, tracesz);
  if (strings == NULL) {
    pr_log_pri(PR_LOG_ERR, "backtrace_symbols(3) error: %s", strerror(errno));
  }
# endif /* HAVE_BACKTRACE_SYMBOLS */

  if (strings != NULL) {
    /* Skip first stack frame; it just points here. */
    for (i = 1; i < tracesz; ++i) {
      pr_log_pri(PR_LOG_ERR, "[%u] %s", i-1, strings[i]);
    }
  }
#else
  pr_log_pri(PR_LOG_ERR, " backtrace(3) unavailable");
#endif /* HAVE_BACKTRACE */
  pr_log_pri(PR_LOG_ERR, "-----END STACK TRACE-----");

  sig_terminate(signo);
  finish_terminate(signo);
}

static void handle_xcpu(void) {
  pr_log_pri(PR_LOG_NOTICE, "ProFTPD CPU limit exceeded (signal %d)", SIGXCPU);
  finish_terminate(SIGXCPU);
}

#ifdef SIGXFSZ
static void handle_xfsz(void) {
  pr_log_pri(PR_LOG_NOTICE, "ProFTPD File size limit exceeded (signal %d)",
    SIGXFSZ);
  finish_terminate(SIGXFSZ);
}
#endif /* SIGXFSZ */

static RETSIGTYPE sig_child(int signo) {
  recvd_signal_flags |= RECEIVED_SIG_CHLD;

  /* We make an exception here to the synchronous processing that is done
   * for other signals; SIGCHLD is handled asynchronously.  This is made
   * necessary by two things.
   *
   * First, we need to support non-POSIX systems.  Under POSIX, once a
   * signal handler has been configured for a given signal, that becomes
   * that signal's disposition, until explicitly changed later.  Non-POSIX
   * systems, on the other hand, will restore the default disposition of
   * a signal after a custom signal handler has been configured.  Thus,
   * to properly support non-POSIX systems, a call to signal(2) is necessary
   * as one of the last steps in our signal handlers.
   *
   * Second, SVR4 systems differ specifically in their semantics of signal(2)
   * and SIGCHLD.  These systems will check for any unhandled SIGCHLD
   * signals, waiting to be reaped via wait(2) or waitpid(2), whenever
   * the disposition of SIGCHLD is changed.  This means that if our process
   * handles SIGCHLD, but does not call wait(2) or waitpid(2), and then
   * calls signal(2), another SIGCHLD is generated; this loop repeats,
   * until the process runs out of stack space and terminates.
   *
   * Thus, in order to cover this interaction, we'll need to call handle_chld()
   * here, asynchronously.  handle_chld() does the work of reaping dead
   * child processes, and does not seem to call any non-reentrant functions,
   * so it should be safe.
   */

  handle_chld();

  if (signal(SIGCHLD, sig_child) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGCHLD (signal %d) handler: %s", SIGCHLD,
      strerror(errno));
  }
}

#ifdef PR_DEVEL_COREDUMP
static char *prepare_core(void) {
  static char dir[256];

  memset(dir, '\0', sizeof(dir));
  pr_snprintf(dir, sizeof(dir)-1, "%s/proftpd-core-%lu", PR_CORE_DIR,
    (unsigned long) getpid());

  if (mkdir(dir, 0700) < 0) {
    pr_log_pri(PR_LOG_WARNING, "unable to create directory '%s' for "
      "coredump: %s", dir, strerror(errno));

  } else {
    chdir(dir);
  }

  return dir;
}
#endif /* PR_DEVEL_COREDUMP */

static RETSIGTYPE sig_abort(int signo) {
  recvd_signal_flags |= RECEIVED_SIG_ABORT;

  if (signal(SIGABRT, SIG_DFL) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGABRT (signal %d) handler: %s", SIGABRT,
      strerror(errno));
  }

#ifdef PR_DEVEL_COREDUMP
  pr_log_pri(PR_LOG_NOTICE, "ProFTPD received SIGABRT signal, generating core "
    "file in %s", prepare_core());
  pr_session_end(PR_SESS_END_FL_NOEXIT);
  abort();
#endif /* PR_DEVEL_COREDUMP */
}

static RETSIGTYPE sig_terminate(int signo) {
  const char *signame = "(unsupported)";
  int log_signal = TRUE, log_stacktrace = TRUE;

  /* Capture the signal number for later display purposes. */
  term_signo = signo;

  /* Some terminating signals get more special treatment than others. */

  switch (signo) {
    case SIGSEGV:
      recvd_signal_flags |= RECEIVED_SIG_SEGV;
      signame = "SIGSEGV";
      break;

    case SIGXCPU:
      recvd_signal_flags |= RECEIVED_SIG_XCPU;
      signame = "SIGXCPU";
      break;

#ifdef SIGXFSZ
      recvd_signal_flags |= RECEIVED_SIG_XFSZ;
      signame = "SIGXFSZ";
      break;
#endif /* SIGXFSZ */

    case SIGTERM:
      /* Since SIGTERM is more common, we do not want to log as much for it. */
      log_signal = log_stacktrace = FALSE;
      recvd_signal_flags |= RECEIVED_SIG_TERMINATE;
      signame = "SIGTERM";
      break;

#ifdef SIGBUS
    case SIGBUS:
      recvd_signal_flags |= RECEIVED_SIG_TERMINATE;
      signame = "SIGBUS";
      break;
#endif /* SIGBUS */

    case SIGILL:
      recvd_signal_flags |= RECEIVED_SIG_TERMINATE;
      signame = "SIGILL";
      break;

    case SIGINT:
      recvd_signal_flags |= RECEIVED_SIG_TERMINATE;
      signame = "SIGINT";
      break;

    default:
      /* Note that we do NOT want to automatically set the
       * RECEIVED_SIG_TERMINATE here by as a fallback for unspecified signals;
       * that flag causes the daemon to terminate all of its child processes.
       * And not every signal should have that effect; it's on a case-by-case
       * basis.
       */
      break;
  }

  if (log_signal == TRUE) {
    /* This is probably not the safest thing to be doing, but since the
     * process is terminating anyway, why not?  It helps when knowing/logging
     * that a segfault (or other unusual event) happened.
     */
    pr_trace_msg("signal", 9, "handling %s (signal %d)", signame, signo);
    pr_log_pri(PR_LOG_NOTICE, "ProFTPD terminating (signal %d)", signo);

    if (!is_master) {
      pr_log_pri(PR_LOG_INFO, "%s session closed.",
        pr_session_get_protocol(PR_SESS_PROTO_FL_LOGOUT));
    }
  }

  if (log_stacktrace == TRUE) {
    install_stacktrace_handler();
  }

  /* Ignore future occurrences of this signal; we'll be terminating anyway. */
  if (signal(signo, SIG_IGN) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install handler for signal %d: %s", signo, strerror(errno));
  }
}

static void install_stacktrace_handler(void) {
  struct sigaction action;

  memset(&action, 0, sizeof(action));
  action.sa_sigaction = handle_stacktrace_signal;
  action.sa_flags = SA_SIGINFO;

  if (sigaction(SIGSEGV, &action, NULL) < 0) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGSEGV stacktrace signal handler: %s",
      strerror(errno));
  }
#ifdef SIGBUS
  if (sigaction(SIGBUS, &action, NULL) < 0) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGBUS stacktrace signal handler: %s",
      strerror(errno));
  }
#endif /* SIGBUS */
  if (sigaction(SIGXCPU, &action, NULL) < 0) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGXCPU stacktrace signal handler: %s",
      strerror(errno));
  }
}

/* This function is to handle the dispatching of actions based on
 * signals received by the signal handlers, to avoid signal handler-based
 * race conditions.
 */
void pr_signals_handle(void) {
  table_handling_signal(TRUE);

  if (errno == EINTR &&
      PR_TUNABLE_EINTR_RETRY_INTERVAL > 0) {
    struct timeval tv;
    unsigned long interval_usecs = PR_TUNABLE_EINTR_RETRY_INTERVAL * 1000000;

    tv.tv_sec = (interval_usecs / 1000000);
    tv.tv_usec = (interval_usecs - (tv.tv_sec * 1000000));

    pr_trace_msg("signal", 18, "interrupted system call, "
      "delaying for %lu %s, %lu %s",
      (unsigned long) tv.tv_sec, tv.tv_sec != 1 ? "secs" : "sec",
      (unsigned long) tv.tv_usec, tv.tv_usec != 1 ? "microsecs" : "microsec");

    pr_timer_usleep(interval_usecs);

    /* Clear the EINTR errno, now that we've dealt with it. */
    errno = 0;
  }

  while (recvd_signal_flags) {
    if (recvd_signal_flags & RECEIVED_SIG_ALRM) {
      recvd_signal_flags &= ~RECEIVED_SIG_ALRM;
      pr_trace_msg("signal", 9, "handling SIGALRM (signal %d)", SIGALRM);
      handle_alarm();
    }

    if (recvd_signal_flags & RECEIVED_SIG_CHLD) {
      recvd_signal_flags &= ~RECEIVED_SIG_CHLD;
      pr_trace_msg("signal", 9, "handling SIGCHLD (signal %d)", SIGCHLD);
      handle_chld();
    }

    if (recvd_signal_flags & RECEIVED_SIG_EVENT) {
      recvd_signal_flags &= ~RECEIVED_SIG_EVENT;

      /* The "event" signal is SIGUSR2 in proftpd. */
      pr_trace_msg("signal", 9, "handling SIGUSR2 (signal %d)", SIGUSR2);
      handle_evnt();
    }

    if (recvd_signal_flags & RECEIVED_SIG_SEGV) {
      recvd_signal_flags &= ~RECEIVED_SIG_SEGV;
      pr_trace_msg("signal", 9, "handling SIGSEGV (signal %d)", SIGSEGV);
      handle_terminate_without_kids();
    }

    if (recvd_signal_flags & RECEIVED_SIG_TERMINATE) {
      recvd_signal_flags &= ~RECEIVED_SIG_TERMINATE;
      pr_trace_msg("signal", 9, "handling signal %d", term_signo);
      handle_terminate_with_kids();
    }

    if (recvd_signal_flags & RECEIVED_SIG_XCPU) {
      recvd_signal_flags &= ~RECEIVED_SIG_XCPU;
      pr_trace_msg("signal", 9, "handling SIGXCPU (signal %d)", SIGXCPU);
      handle_xcpu();
    }

#ifdef SIGXFSZ
    if (recvd_signal_flags & RECEIVED_SIG_XFSZ) {
      recvd_signal_flags &= ~RECEIVED_SIG_XFSZ;
      pr_trace_msg("signal", 9, "handling SIGXFSZ (signal %d)", SIGXFSZ);
      handle_xfsz();
    }
#endif /* SIGXFSZ */

    if (recvd_signal_flags & RECEIVED_SIG_ABORT) {
      recvd_signal_flags &= ~RECEIVED_SIG_ABORT;
      pr_trace_msg("signal", 9, "handling SIGABRT (signal %d)", SIGABRT);
      handle_abort();
    }

    if (recvd_signal_flags & RECEIVED_SIG_RESTART) {
      recvd_signal_flags &= ~RECEIVED_SIG_RESTART;
      pr_trace_msg("signal", 9, "handling SIGHUP (signal %d)", SIGHUP);

      /* NOTE: should this be done here, rather than using a schedule? */
      schedule(restart_daemon, 0, NULL, NULL, NULL, NULL);
    }

    if (recvd_signal_flags & RECEIVED_SIG_EXIT) {
      recvd_signal_flags &= ~RECEIVED_SIG_EXIT;
      pr_trace_msg("signal", 9, "handling SIGUSR1 (signal %d)", SIGUSR1);
      pr_log_pri(PR_LOG_NOTICE, "%s", "Parent process requested shutdown");
      pr_session_disconnect(NULL, PR_SESS_DISCONNECT_SERVER_SHUTDOWN, NULL);
    }

    if (recvd_signal_flags & RECEIVED_SIG_SHUTDOWN) {
      recvd_signal_flags &= ~RECEIVED_SIG_SHUTDOWN;
      pr_trace_msg("signal", 9, "handling SIGUSR1 (signal %d)", SIGUSR1);

      /* NOTE: should this be done here, rather than using a schedule? */
      schedule(shutdown_end_session, 0, NULL, NULL, NULL, NULL);
    }
  }

  table_handling_signal(FALSE);
}

/* sig_restart occurs in the master daemon when manually "kill -HUP"
 * in order to re-read configuration files, and is sent to all
 * children by the master.
 */
static RETSIGTYPE sig_restart(int signo) {
  recvd_signal_flags |= RECEIVED_SIG_RESTART;

  if (signal(SIGHUP, sig_restart) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGHUP (signal %d) handler: %s", SIGHUP,
      strerror(errno));
  }
}

/* pr_signals_handle_disconnect is called in children when the parent daemon
 * detects that shutmsg has been created and that client sessions should be
 * destroyed.  If a file transfer is underway, the process simply dies,
 * otherwise a function is scheduled to attempt to display the shutdown reason.
 */
RETSIGTYPE pr_signals_handle_disconnect(int signo) {

  /* If this is an anonymous session, or a transfer is in progress,
   * perform the exit a little later...
   */
  if ((session.sf_flags & SF_ANON) ||
      (session.sf_flags & SF_XFER)) {
    recvd_signal_flags |= RECEIVED_SIG_EXIT;

  } else {
    recvd_signal_flags |= RECEIVED_SIG_SHUTDOWN;
  }

  if (signal(SIGUSR1, SIG_IGN) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGUSR1 (signal %d) handler: %s", SIGUSR1,
      strerror(errno));
  }
}

/* "Events", in this case, are SIGUSR2 signals. */
RETSIGTYPE pr_signals_handle_event(int signo) {
  recvd_signal_flags |= RECEIVED_SIG_EVENT;

  if (signal(SIGUSR2, pr_signals_handle_event) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGUSR2 (signal %d) handler: %s", SIGUSR2,
      strerror(errno));
  }
}

int init_signals(void) {
  sigset_t sig_set;

  /* Should the master server (only applicable in standalone mode)
   * kill off children if we receive a signal that causes termination?
   * Hmmmm... maybe this needs to be rethought, but I've done it in
   * such a way as to only kill off our children if we receive a SIGTERM,
   * meaning that the admin wants us dead (and probably our kids too).
   */

  /* The sub-pool for the child list is created the first time we fork
   * off a child.  To conserve memory, the pool and list is destroyed
   * when our last child dies (to prevent the list from eating more and
   * more memory on long uptimes).
   */

  sigemptyset(&sig_set);

  sigaddset(&sig_set, SIGCHLD);
  sigaddset(&sig_set, SIGINT);
  sigaddset(&sig_set, SIGQUIT);
  sigaddset(&sig_set, SIGILL);
  sigaddset(&sig_set, SIGABRT);
  sigaddset(&sig_set, SIGFPE);
  sigaddset(&sig_set, SIGSEGV);
  sigaddset(&sig_set, SIGALRM);
  sigaddset(&sig_set, SIGTERM);
  sigaddset(&sig_set, SIGHUP);
  sigaddset(&sig_set, SIGUSR2);
#ifdef SIGSTKFLT
  sigaddset(&sig_set, SIGSTKFLT);
#endif /* SIGSTKFLT */
#ifdef SIGIO
  sigaddset(&sig_set, SIGIO);
#endif /* SIGIO */
#ifdef SIGBUS
  sigaddset(&sig_set, SIGBUS);
#endif /* SIGBUS */

  if (signal(SIGCHLD, sig_child) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGCHLD (signal %d) handler: %s", SIGCHLD,
      strerror(errno));
  }

  if (signal(SIGHUP, sig_restart) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGHUP (signal %d) handler: %s", SIGHUP,
      strerror(errno));
  }

  if (signal(SIGINT, sig_terminate) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGINT (signal %d) handler: %s", SIGINT,
      strerror(errno));
  }

  if (signal(SIGQUIT, sig_terminate) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGQUIT (signal %d) handler: %s", SIGQUIT,
      strerror(errno));
  }

  if (signal(SIGILL, sig_terminate) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGILL (signal %d) handler: %s", SIGILL,
      strerror(errno));
  }

  if (signal(SIGFPE, sig_terminate) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGFPE (signal %d) handler: %s", SIGFPE,
      strerror(errno));
  }

#ifdef SIGXFSZ
  if (signal(SIGXFSZ, sig_terminate) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGXFSZ (signal %d) handler: %s", SIGXFSZ,
      strerror(errno));
  }
#endif /* SIGXFSZ */

  if (signal(SIGABRT, sig_abort) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGABRT (signal %d) handler: %s", SIGABRT,
      strerror(errno));
  }

  /* Installs stacktrace handlers for SIGSEGV, SIGXCPU, and SIGBUS. */
  install_stacktrace_handler();

  /* Ignore SIGALRM; this will be changed when a timer is registered. But
   * this will prevent SIGALRMs from killing us if we don't currently have
   * any timers registered.
    */
  if (signal(SIGALRM, SIG_IGN) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGALRM (signal %d) handler: %s", SIGALRM,
      strerror(errno));
  }

  if (signal(SIGTERM, sig_terminate) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGTERM (signal %d) handler: %s", SIGTERM,
      strerror(errno));
  }

  if (signal(SIGURG, SIG_IGN) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGURG (signal %d) handler: %s", SIGURG,
      strerror(errno));
  }

#ifdef SIGSTKFLT
  if (signal(SIGSTKFLT, sig_terminate) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGSTKFLT (signal %d) handler: %s", SIGSTKFLT,
      strerror(errno));
  }
#endif /* SIGSTKFLT */

#ifdef SIGIO
  if (signal(SIGIO, SIG_IGN) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGIO (signal %d) handler: %s", SIGIO,
      strerror(errno));
  }
#endif /* SIGIO */

  if (signal(SIGUSR2, pr_signals_handle_event) == SIG_ERR) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to install SIGUSR2 (signal %d) handler: %s", SIGUSR2,
      strerror(errno));
  }

  /* In case our parent left signals blocked (as happens under some
   * poor inetd implementations)
   */
  if (sigprocmask(SIG_UNBLOCK, &sig_set, NULL) < 0) {
    pr_log_pri(PR_LOG_NOTICE,
      "unable to block signal set: %s", strerror(errno));
  }

  return 0;
}
