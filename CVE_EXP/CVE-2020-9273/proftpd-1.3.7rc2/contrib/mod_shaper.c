/*
 * ProFTPD: mod_shaper -- a module implementing daemon-wide rate throttling
 *                        via IPC
 * Copyright (c) 2004-2017 TJ Saunders
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
 * This is mod_shaper, contrib software for proftpd 1.2 and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"
#include "mod_ctrls.h"

#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/uio.h>

#define MOD_SHAPER_VERSION		"mod_shaper/0.6.6"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030402
# error "ProFTPD 1.3.4rc2 or later required"
#endif

#ifndef PR_USE_CTRLS
# error "Controls support required (use --enable-ctrls)"
#endif

/* From src/main.c */
extern pid_t mpid;

module shaper_module;

static ctrls_acttab_t shaper_acttab[];
static const char *shaper_down_cmds[] = { C_RETR, NULL };
static const char *shaper_up_cmds[] = { C_APPE, C_STOR, C_STOU, NULL };
static int shaper_engine = FALSE;
static char *shaper_log_path = NULL;
static int shaper_logfd = -1;
static pool *shaper_pool = NULL;
static int shaper_qid = -1;
static unsigned long shaper_qmaxbytes = 0;
static int shaper_scrub_timer_id = -1;
static char *shaper_tab_path = NULL;
static pool *shaper_tab_pool = NULL;
static int shaper_tabfd = -1;

#define SHAPER_PROJ_ID		24

#if defined(FREEBSD4)
#  define SHAPER_IOV_BASE		(char *)
#elif defined(LINUX)
#  define SHAPER_IOV_BASE		(__ptr_t)
#elif defined(SOLARIS2)
#  define SHAPER_IOV_BASE		(caddr_t)
#else
#  define SHAPER_IOV_BASE		(void *)
#endif

#ifndef HAVE_FLOCK
# define LOCK_SH	1
# define LOCK_EX	2
# define LOCK_NB	4
# define LOCK_UN	8
#endif /* !HAVE_FLOCK */

#define SHAPER_DEFAULT_RATE		-1.0
#define SHAPER_DEFAULT_PRIO		10
#define SHAPER_DEFAULT_SHARES		5
#define SHAPER_DEFAULT_UPSHARES		SHAPER_DEFAULT_SHARES
#define SHAPER_DEFAULT_DOWNSHARES	SHAPER_DEFAULT_SHARES

#define SHAPER_SCRUB_INTERVAL		60

#ifndef SHAPER_MAX_SEND_ATTEMPTS
# define SHAPER_MAX_SEND_ATTEMPTS	5
#endif

struct shaper_sess {
  pid_t sess_pid;
  unsigned int sess_prio;
  int sess_downincr;
  long double sess_downrate;
  int sess_upincr;
  long double sess_uprate;
};

struct {
  int def_prio;
  long double downrate;
  unsigned int def_downshares;
  long double uprate;
  unsigned int def_upshares;
  unsigned int nsessions;
  array_header *sess_list;

} shaper_tab;

/* Define our own structure for messages, since one is not portably defined.
 */
struct shaper_msg {
  /* Message type */
  long mtype;

  /* Message data */
  char mtext[1];
};

/* Necessary function prototypes. */
static void shaper_msg_clear(pid_t);
static int shaper_rate_alter(unsigned int, long double, long double);
static void shaper_sess_exit_ev(const void *, void *);
static void shaper_sigusr2_ev(const void *, void *);
static int shaper_table_send(void);

/* Support functions
 */

static key_t shaper_get_key(const char *path) {
  pr_fh_t *fh;
  struct stat st;

  /* ftok() uses stat(2) on the given path, which means that it needs to exist.
   */
  fh = pr_fsio_open(path, O_WRONLY|O_CREAT);
  if (fh == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "error opening '%s': %s", path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (pr_fsio_fstat(fh, &st) < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "error checking '%s': %s", path, strerror(xerrno));

    pr_fsio_close(fh);
    errno = xerrno;
    return -1;
  }

  if (S_ISDIR(st.st_mode)) {
    int xerrno = EISDIR;

    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "error using '%s': %s", path, strerror(xerrno));

    pr_fsio_close(fh);
    errno = xerrno;
    return -1;
  }

  pr_fsio_close(fh);

  return ftok(path, SHAPER_PROJ_ID);
}

static int shaper_get_queue(const char *path) {
  int qid;

  /* Obtain a key for this path. */
  key_t key = shaper_get_key(path);
  if (key == (key_t) -1) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "unable to get key for '%s': %s", path, strerror(errno));
    return -1;
  }

  /* Try first using IPC_CREAT|IPC_EXCL, to check if there is an existing
   * queue for this key.  If there is, try again, using a flag of zero.
   */
  qid = msgget(key, IPC_CREAT|IPC_EXCL|0666);
  if (qid < 0) {
    if (errno == EEXIST)
      qid = msgget(key, 0);

    else
      return -1;
  }

  return qid;
}

static int shaper_remove_queue(void) {
  struct msqid_ds ds;
  int res;

  memset(&ds, 0, sizeof(ds));

  res = msgctl(shaper_qid, IPC_RMID, &ds);
  if (res < 0) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "error removing queue ID %d: %s", shaper_qid, strerror(errno));

  } else {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "removed queue ID %d", shaper_qid);
    shaper_qid = -1;
  }

  return res;
}

static int shaper_msg_recv(void) {
  int nmsgs = 0;
  ssize_t msglen = 0;
  struct shaper_msg *msg;

  /* The expected message length consists of a priority (the unsigned int),
   * the new downrate (the long double), and the new uprate (another long
   * double).
   */
  size_t msgsz = sizeof(unsigned int) + sizeof(long double) +
    sizeof(long double);

  msg = malloc(sizeof(struct shaper_msg) + msgsz - sizeof(msg->mtext));
  if (msg == NULL) {
    pr_log_pri(PR_LOG_ALERT, MOD_SHAPER_VERSION ": Out of memory!");
    pr_session_disconnect(&shaper_module, PR_SESS_DISCONNECT_NOMEM, NULL);
  }

  msglen = msgrcv(shaper_qid, msg, msgsz, getpid(), IPC_NOWAIT|MSG_NOERROR);
  while (msglen > 0) {
    unsigned int prio;
    long double downrate, uprate;

    pr_signals_handle();
    nmsgs++;

    memcpy(&prio, msg->mtext, sizeof(unsigned int));
    memcpy(&downrate, msg->mtext + sizeof(unsigned int), sizeof(long double));
    memcpy(&uprate, msg->mtext + sizeof(unsigned int) + sizeof(long double),
      sizeof(long double));

    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "received prio %u, rate %3.2Lf down, %3.2Lf up", prio, downrate,
      uprate);

    if (shaper_rate_alter(prio, downrate, uprate) < 0) {
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error altering rate for current session: %s", strerror(errno));
    }

    msglen = msgrcv(shaper_qid, msg, msgsz, getpid(), IPC_NOWAIT|MSG_NOERROR);
  }

  free(msg);

  if (msglen < 0 &&
#ifdef ENOMSG
      errno != ENOMSG &&
#endif /* ENOMSG */
      errno != EAGAIN)
    return -1;

  return nmsgs;
}

static int shaper_msg_send(pid_t dst_pid, unsigned int prio,
    long double downrate, long double uprate) {
  unsigned int error_count = 0;
  int res;
  struct shaper_msg *msg;
  size_t msgsz = sizeof(unsigned int) + sizeof(long double) +
    sizeof(long double);

  msg = malloc(sizeof(struct shaper_msg) + msgsz - sizeof(msg->mtext));
  if (msg == NULL) {
    pr_log_pri(PR_LOG_ALERT, MOD_SHAPER_VERSION ": Out of memory!");
    pr_session_disconnect(&shaper_module, PR_SESS_DISCONNECT_NOMEM, NULL);
  }

  msg->mtype = dst_pid;
  memcpy(msg->mtext, &prio, sizeof(unsigned int));
  memcpy(msg->mtext + sizeof(unsigned int), &downrate, sizeof(long double));
  memcpy(msg->mtext + sizeof(unsigned int) + sizeof(long double), &uprate,
    sizeof(long double));

  /* Remove any old messages in the queue for the destination PID.  This
   * helps keep the queue clear and moving, more resistant to (inadvertent
   * or not) DoS situations.
   */
  shaper_msg_clear(dst_pid);

  while (msgsnd(shaper_qid, msg, msgsz, IPC_NOWAIT) < 0) {
    pr_signals_handle();

    if (errno != EAGAIN) {
      free(msg);
      return -1;

    } else {
      /* The EAGAIN error happens when there are too many bytes of messages
       * on the queue.  Check to see what the current number of messages
       * on the queue is, and log the error.
       *
       * If this error is hit too many times in a loop, we may need to give
       * up permanently.  (XXX in the future, if one queue is too small for
       * a busy daemon, look into a different queue allocation strategy.)
       */
      struct msqid_ds ds;

      if (msgctl(shaper_qid, IPC_STAT, &ds) < 0) {
        (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
          "error checking queue ID %d: %s", shaper_qid, strerror(errno));

      } else {
        (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
          "unable to send message to PID %lu via queue ID %d, max bytes (%lu) "
          "reached (%lu messages of %lu bytes currently in queue)",
          (unsigned long) dst_pid, shaper_qid, shaper_qmaxbytes,
          (unsigned long) ds.msg_qnum, (unsigned long) ds.msg_qnum * msgsz);
      }

      error_count++;
      if (error_count > SHAPER_MAX_SEND_ATTEMPTS) {
        free(msg);

        (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
          "unable to send message to PID %lu via queue ID %d after %u attempts "
          "(%u max attempts allowed), failing", (unsigned long) dst_pid,
          shaper_qid, error_count, SHAPER_MAX_SEND_ATTEMPTS);

        errno = EPERM;
        return -1;
      }
    }

  }
  free(msg);

  /* Send SIGUSR2 to the destination process, to let it know that it should
   * check the queue for messages.
   */
  PRIVS_ROOT
  res = kill(dst_pid, SIGUSR2);
  PRIVS_RELINQUISH

  if (res < 0) {
    if (errno == ESRCH) {
      shaper_msg_clear(dst_pid);

    } else {
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error sending notice: %s", strerror(errno));
    }
  }

#if 0
  /* Handle our own signal, if necessary. */
  if (getpid() == dst_pid)
    pr_signals_handle();
#endif

  return 0;
}

static void shaper_msg_clear(pid_t dst_pid) {
  ssize_t msglen = 0;
  struct shaper_msg *msg;
  size_t msgsz = sizeof(unsigned int) + sizeof(long double) +
    sizeof(long double);

  msg = malloc(sizeof(struct shaper_msg) + msgsz - sizeof(msg->mtext));
  if (msg == NULL) {
    pr_log_pri(PR_LOG_ALERT, MOD_SHAPER_VERSION ": Out of memory!");
    pr_session_disconnect(&shaper_module, PR_SESS_DISCONNECT_NOMEM, NULL);
  }

  (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
    "clearing queue ID %d of messages for process ID %lu", shaper_qid,
    (unsigned long) dst_pid);
  msglen = msgrcv(shaper_qid, msg, msgsz, dst_pid, IPC_NOWAIT|MSG_NOERROR);
  while (msglen > 0) {
    pr_signals_handle();

    msglen = msgrcv(shaper_qid, msg, msgsz, dst_pid, IPC_NOWAIT|MSG_NOERROR);
  }

  free(msg);
}

static void shaper_remove_config(unsigned int prio) {
  config_rec *c;
  register unsigned int i;
  pool *tmp_pool = make_sub_pool(shaper_pool);
  array_header *list = make_array(tmp_pool, 1, sizeof(config_rec *));

  /* This function is very similar to remove_config(), except that we
   * want to remove only TransferRate config_recs, and only those
   * config_recs whose priority matches the given priority.
   *
   * To do this, first we'll do a recursive scan for all TransferRate
   * config_recs that match our priority, and add them to a list.
   * Then we'll loop through the list, removing them from the config
   * tree.  It can't be done in one loop, as we'll not be able to
   * track which config_recs we've seen and left alone before.
   */

  c = find_config(main_server->conf, CONF_PARAM, "TransferRate", TRUE);
  while (c) {
    pr_signals_handle();

    if (*((unsigned int *) c->argv[3]) == prio)
      *((config_rec **) push_array(list)) = c;

    c = find_config_next(c, c->next, CONF_PARAM, "TransferRate", TRUE);
  }

  for (i = 0; i < list->nelts; i++) {
    xaset_t *set;

    c = ((config_rec **) list->elts)[i];
    set = c->set;

    xaset_remove(set, (xasetmember_t *) c);

    if (!set->xas_list) {
      if (c->parent && c->parent->subset == set)
        c->parent->subset = NULL;

      else if (main_server->conf == set)
        main_server->conf = NULL;

      destroy_pool(set->pool);

    } else {
      destroy_pool(c->pool);
    }
  }

  destroy_pool(tmp_pool);
  return;
}

static int shaper_rate_alter(unsigned int prio, long double downrate,
    long double uprate) {
  config_rec *c;

  /* Remove any TransferRate entries at this same priority. */
  shaper_remove_config(prio);

  /* Create separate TransferRate entries for the download and upload
   * rates, for now.  It would be more efficient to have a single config_rec
   * entry, but only when the downrate and uprate are the same.
   */

  if (downrate > 0.0) {
    c = add_config_param_set(&main_server->conf, "TransferRate", 4, NULL,
      NULL, NULL, NULL);
    c->argv[0] = shaper_down_cmds;

    c->argv[1] = pcalloc(c->pool, sizeof(long double));
    *((long double *) c->argv[1]) = downrate;

    /* No freebytes altered via mod_shaper. */
    c->argv[2] = pcalloc(c->pool, sizeof(off_t));
    *((off_t *) c->argv[2]) = 0;

    c->argv[3] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[3]) = prio;

    c->flags |= CF_MERGEDOWN_MULTI;
  } 

  if (uprate > 0.0) {
    c = add_config_param_set(&main_server->conf, "TransferRate", 4, NULL,
      NULL, NULL, NULL);
    c->argv[0] = shaper_up_cmds;

    c->argv[1] = pcalloc(c->pool, sizeof(long double));
    *((long double *) c->argv[1]) = uprate;

    /* No freebytes altered via mod_shaper. */
    c->argv[2] = pcalloc(c->pool, sizeof(off_t));
    *((off_t *) c->argv[2]) = 0;

    c->argv[3] = pcalloc(c->pool, sizeof(unsigned int));
    *((unsigned int *) c->argv[3]) = prio;

    c->flags |= CF_MERGEDOWN_MULTI;
  }

  (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
    "merging in new TransferRate entries");
  fixup_dirs(main_server, CF_SILENT);

  return 0;
}

/* Flush the ShaperTable out to disk. */
static int shaper_table_flush(void) {
  register unsigned int i;
  int res;
  struct iovec tab_iov[6];
  struct shaper_sess *sess_list;

  /* Seek to the start of the file. */
  if (lseek(shaper_tabfd, 0, SEEK_SET) == (off_t) -1) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "error seeking to start of ShaperTable: %s", strerror(errno));
    return -1;
  }

  /* Write out the ShaperTable header. */
  tab_iov[0].iov_base = SHAPER_IOV_BASE &shaper_tab.def_prio;
  tab_iov[0].iov_len = sizeof(shaper_tab.def_prio);

  tab_iov[1].iov_base = SHAPER_IOV_BASE &shaper_tab.downrate;
  tab_iov[1].iov_len = sizeof(shaper_tab.downrate);

  tab_iov[2].iov_base = SHAPER_IOV_BASE &shaper_tab.def_downshares;
  tab_iov[2].iov_len = sizeof(shaper_tab.def_downshares);

  tab_iov[3].iov_base = SHAPER_IOV_BASE &shaper_tab.uprate;
  tab_iov[3].iov_len = sizeof(shaper_tab.uprate);

  tab_iov[4].iov_base = SHAPER_IOV_BASE &shaper_tab.def_upshares;
  tab_iov[4].iov_len = sizeof(shaper_tab.def_upshares);

  tab_iov[5].iov_base = SHAPER_IOV_BASE &shaper_tab.nsessions;
  tab_iov[5].iov_len = sizeof(shaper_tab.nsessions);

  res = writev(shaper_tabfd, tab_iov, 6);
  if (res < 0) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "error writing ShaperTable (%d) header: %s", shaper_tabfd,
      strerror(errno));
    return -1;
  }

  sess_list = shaper_tab.sess_list->elts;
  for (i = 0; i < shaper_tab.nsessions; i++) {
    tab_iov[0].iov_base = SHAPER_IOV_BASE &sess_list[i].sess_pid;
    tab_iov[0].iov_len = sizeof(pid_t);

    tab_iov[1].iov_base = SHAPER_IOV_BASE &sess_list[i].sess_prio;
    tab_iov[1].iov_len = sizeof(unsigned int);

    tab_iov[2].iov_base = SHAPER_IOV_BASE &sess_list[i].sess_downincr;
    tab_iov[2].iov_len = sizeof(int);

    tab_iov[3].iov_base = SHAPER_IOV_BASE &sess_list[i].sess_downrate;
    tab_iov[3].iov_len = sizeof(long double);

    tab_iov[4].iov_base = SHAPER_IOV_BASE &sess_list[i].sess_upincr;
    tab_iov[4].iov_len = sizeof(int);

    tab_iov[5].iov_base = SHAPER_IOV_BASE &sess_list[i].sess_uprate;
    tab_iov[5].iov_len = sizeof(long double);

    res = writev(shaper_tabfd, tab_iov, 6);
    if (res < 0)
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error writing ShaperTable session entry: %s", strerror(errno));
  }

  return 0;
}

#ifndef HAVE_FLOCK
static const char *get_lock_type(struct flock *lock) {
  const char *lock_type;

  switch (lock->l_type) {
    case F_RDLCK:
      lock_type = "read";
      break;

    case F_WRLCK:
      lock_type = "write";
      break;

    case F_UNLCK:
      lock_type = "unlock";
      break;

    default:
      lock_type = "[unknown]";
  }

  return lock_type;
}
#endif /* !HAVE_FLOCK */

static int shaper_table_lock(int op) {
  static int have_lock = FALSE;

#ifndef HAVE_FLOCK
  int flag;
  struct flock lock;
#endif /* !HAVE_FLOCK */

  if (have_lock &&
      ((op & LOCK_SH) || (op & LOCK_EX))) {
    return 0;
  }

  if (!have_lock &&
      (op & LOCK_UN)) {
    return 0;
  }

#ifdef HAVE_FLOCK
  pr_trace_msg("lock", 9, "attempting to %s ShaperTable fd %d via flock(2)",
    op == LOCK_UN ? "unlock" : "lock", shaper_tabfd);
  while (flock(shaper_tabfd, op) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg("lock", 9, "%s of ShaperTable fd %d failed: %s",
      op == LOCK_UN ? "unlock" : "lock", shaper_tabfd, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  pr_trace_msg("lock", 9, "%s of ShaperTable fd %d successful",
    op == LOCK_UN ? "unlock" : "lock", shaper_tabfd);

  if ((op & LOCK_SH) ||
      (op & LOCK_EX)) {
    have_lock = TRUE;

  } else if (op & LOCK_UN) {
    have_lock = FALSE;
  }

  return 0;
#else
  flag = F_SETLKW;

  lock.l_whence = 0;
  lock.l_start = lock.l_len = 0;

  if (op & LOCK_SH) {
    lock.l_type = F_RDLCK;

  } else if (op & LOCK_EX) {
    lock.l_type = F_WRLCK;

  } else if (op & LOCK_UN) {
    lock.l_type = F_UNLCK;

  } else {
    errno = EINVAL;
    return -1;
  }

  if (op & LOCK_NB)
    flag = F_SETLK;

  pr_trace_msg("lock", 9, "attempting to %s ShaperTable fd %d via fcntl(2)",
    op == LOCK_UN ? "unlock" : "lock", shaper_tabfd);
  while (fcntl(shaper_tabfd, flag, &lock) < 0) {
    int xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();
      continue;
    }

    pr_trace_msg("lock", 9, "%s of ShaperTable fd %d failed: %s",
      op == LOCK_UN ? "unlock" : "lock", shaper_tabfd, strerror(xerrno));

    if (xerrno == EACCES) {
      /* Get the PID of the process blocking this lock. */
      if (fcntl(shaper_tabfd, F_GETLK, &lock) == 0) {
        pr_trace_msg("lock", 3, "process ID %lu has blocking %s lock on "
          "ShaperTable fd %d", (unsigned long) lock.l_pid, get_lock_type(&lock),
          shaper_tabfd);
      }
    }

    errno = xerrno;
    return -1;
  }

  pr_trace_msg("lock", 9, "%s of ShaperTable fd %d successful",
    op == LOCK_UN ? "unlock" : "lock", shaper_tabfd);

  if ((op & LOCK_SH) ||
      (op & LOCK_EX)) {
    have_lock = TRUE;

  } else if (op & LOCK_UN) {
    have_lock = FALSE;
  }

  return 0;
#endif /* HAVE_FLOCK */
}

static int shaper_table_init(pr_fh_t *fh) {
  unsigned int nsessions = 0;
  struct stat st;
  struct iovec tab_iov[6];

  if (pr_fsio_fstat(fh, &st) < 0) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "unable to fstat ShaperTable: %s", strerror(errno));
    errno = EINVAL;
    return -1;
  }

  shaper_tabfd = fh->fh_fd;

  /* XXX maybe add a shaper control to clear/re-init the table, in cases
   * where the format changes?
   */

  /* If the table already exists (i.e. size > 0), return. */
  if (st.st_size > 0) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "ShaperTable '%s' has size %" PR_LU " bytes, is already initialized",
      fh->fh_path, (pr_off_t) st.st_size);
    return 0;
  }

  tab_iov[0].iov_base = SHAPER_IOV_BASE &shaper_tab.def_prio;
  tab_iov[0].iov_len = sizeof(shaper_tab.def_prio);

  tab_iov[1].iov_base = SHAPER_IOV_BASE &shaper_tab.downrate;
  tab_iov[1].iov_len = sizeof(shaper_tab.downrate);

  tab_iov[2].iov_base = SHAPER_IOV_BASE &shaper_tab.def_downshares;
  tab_iov[2].iov_len = sizeof(shaper_tab.def_downshares);

  tab_iov[3].iov_base = SHAPER_IOV_BASE &shaper_tab.uprate;
  tab_iov[3].iov_len = sizeof(shaper_tab.uprate);

  tab_iov[4].iov_base = SHAPER_IOV_BASE &shaper_tab.def_upshares;
  tab_iov[4].iov_len = sizeof(shaper_tab.def_upshares);

  tab_iov[5].iov_base = SHAPER_IOV_BASE &nsessions;
  tab_iov[5].iov_len = sizeof(nsessions);

  if (lseek(fh->fh_fd, 0, SEEK_SET) < 0) {
    return -1;
  }
 
  if (writev(fh->fh_fd, tab_iov, 6) < 0) {
    return -1;
  }

  (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
    "initialized ShaperTable with rate %3.2Lf KB/s (down), %3.2Lf KB/s (up), "
    "default priority %u, default shares %u down, %u up", shaper_tab.downrate,
    shaper_tab.uprate, shaper_tab.def_prio, shaper_tab.def_downshares,
    shaper_tab.def_upshares);

  return 0;
}

/* Refresh the in-memory ShaperTable from disk. */
static int shaper_table_refresh(void) {
  register unsigned int i;
  int res;
  struct iovec tab_iov[6];

  if (lseek(shaper_tabfd, 0, SEEK_SET) == (off_t) -1) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "error seeking to start of ShaperTable: %s", strerror(errno));
    return -1;
  }

  /* Read the ShaperTable header. */

  tab_iov[0].iov_base = SHAPER_IOV_BASE &shaper_tab.def_prio;
  tab_iov[0].iov_len = sizeof(shaper_tab.def_prio);

  tab_iov[1].iov_base = SHAPER_IOV_BASE &shaper_tab.downrate;
  tab_iov[1].iov_len = sizeof(shaper_tab.downrate);

  tab_iov[2].iov_base = SHAPER_IOV_BASE &shaper_tab.def_downshares;
  tab_iov[2].iov_len = sizeof(shaper_tab.def_downshares);

  tab_iov[3].iov_base = SHAPER_IOV_BASE &shaper_tab.uprate;
  tab_iov[3].iov_len = sizeof(shaper_tab.uprate);

  tab_iov[4].iov_base = SHAPER_IOV_BASE &shaper_tab.def_upshares;
  tab_iov[4].iov_len = sizeof(shaper_tab.def_upshares);

  tab_iov[5].iov_base = SHAPER_IOV_BASE &shaper_tab.nsessions;
  tab_iov[5].iov_len = sizeof(shaper_tab.nsessions);

  res = readv(shaper_tabfd, tab_iov, 6);
  if (res < 0) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "error reading ShaperTable header: %s", strerror(errno));
    return -1;
  }
 
  /* For every session, read in its information and add it to the list.
   * For this, we need a pool for the session list.
   */

  if (shaper_tab_pool) {
    destroy_pool(shaper_tab_pool);
    shaper_tab_pool = NULL;
    shaper_tab.sess_list = NULL;
  }

  shaper_tab_pool = make_sub_pool(shaper_pool);
  pr_pool_tag(shaper_tab_pool, MOD_SHAPER_VERSION ": ShaperTable pool");

  shaper_tab.sess_list = make_array(shaper_tab_pool, 0,
    sizeof(struct shaper_sess));

  for (i = 0; i < shaper_tab.nsessions; i++) {
    struct shaper_sess *sess = push_array(shaper_tab.sess_list);

    tab_iov[0].iov_base = SHAPER_IOV_BASE &sess->sess_pid;
    tab_iov[0].iov_len = sizeof(sess->sess_pid);

    tab_iov[1].iov_base = SHAPER_IOV_BASE &sess->sess_prio;
    tab_iov[1].iov_len = sizeof(sess->sess_prio);

    tab_iov[2].iov_base = SHAPER_IOV_BASE &sess->sess_downincr;
    tab_iov[2].iov_len = sizeof(sess->sess_downincr);

    tab_iov[3].iov_base = SHAPER_IOV_BASE &sess->sess_downrate;
    tab_iov[3].iov_len = sizeof(sess->sess_downrate);

    tab_iov[4].iov_base = SHAPER_IOV_BASE &sess->sess_upincr;
    tab_iov[4].iov_len = sizeof(sess->sess_upincr);

    tab_iov[5].iov_base = SHAPER_IOV_BASE &sess->sess_uprate;
    tab_iov[5].iov_len = sizeof(sess->sess_uprate);

    res = readv(shaper_tabfd, tab_iov, 6);
    if (res < 0) {
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error reading session entry %u from ShaperTable: %s", i + 1,
        strerror(errno));
      return -1;
    }
  }

  return 0;
}

/* Scan the ShaperTable for any sessions who might have exited in a Bad Way
 * and not cleaned up their entries.
 */
static void shaper_table_scrub(void) {
  register unsigned int i;
  struct shaper_sess *sess_list;
  array_header *new_sess_list;
  int send_tab = FALSE;

  if (shaper_table_lock(LOCK_EX) < 0)
    return;

  if (shaper_table_refresh() < 0) {
    shaper_table_lock(LOCK_UN);
    return;
  }

  if (shaper_tab.nsessions == 0) {
    /* No sessions in the ShaperTable to be removed. */
    shaper_table_lock(LOCK_UN);
    return;
  }

  sess_list = shaper_tab.sess_list->elts;
  new_sess_list = make_array(shaper_tab_pool, 0, sizeof(struct shaper_sess));

  for (i = 0; i < shaper_tab.nsessions; i++) {

    /* Check to see if the PID in this entry is valid.  If not, erase
     * the slot.
     */
    if (kill(sess_list[i].sess_pid, 0) < 0) {
      if (errno == ESRCH) {

        /* OK, the recorded PID is no longer valid. */
        (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
          "removed dead session (pid %u) from ShaperTable",
          (unsigned int) sess_list[i].sess_pid);
        send_tab = TRUE;
      } 

    } else {
      struct shaper_sess *sess = push_array(new_sess_list);

      sess->sess_pid = sess_list[i].sess_pid;
      sess->sess_prio = sess_list[i].sess_prio;
      sess->sess_downincr = sess_list[i].sess_downincr;
      sess->sess_downrate = sess_list[i].sess_downrate;
      sess->sess_upincr = sess_list[i].sess_upincr;
      sess->sess_uprate = sess_list[i].sess_uprate;
    }
  }

  /* Replace the session list.  The memory pointed to by the overwritten
   * pointer will be freed when shaper_tab_pool is freed, which will be
   * when the table is next refreshed.
   */

  shaper_tab.nsessions = new_sess_list->nelts;
  shaper_tab.sess_list = new_sess_list;

  if (send_tab && shaper_table_send() < 0) {
    shaper_table_lock(LOCK_UN);
    return;
  }

  if (shaper_table_flush() < 0) {
    shaper_table_lock(LOCK_UN);
    return;
  }

  shaper_table_lock(LOCK_UN);
  return;
}

static int shaper_table_scrub_cb(CALLBACK_FRAME) {
  shaper_table_scrub();

  /* Always return 1, resetting the timer. */
  return 1;
}

/* Scan the ShaperTable, sending messages to each session for their new rate
 * and its priority.
 */
static int shaper_table_send(void) {
  register unsigned int i;
  unsigned int total_downshares = 0, total_upshares = 0;
  long double rate_per_downshare, rate_per_upshare;
  struct shaper_sess *sess_list = shaper_tab.sess_list->elts;

  for (i = 0; i < shaper_tab.nsessions; i++) {
    total_downshares += (shaper_tab.def_downshares +
      sess_list[i].sess_downincr);
    total_upshares += (shaper_tab.def_upshares +
      sess_list[i].sess_upincr);
  }

  if (total_downshares == 0) {
    total_downshares = 1;
  }

  if (total_upshares == 0) {
    total_upshares = 1;
  }

  (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
    "total session shares: %u down, %u up", total_downshares, total_upshares);

  rate_per_downshare = shaper_tab.downrate / total_downshares;
  rate_per_upshare = shaper_tab.uprate / total_upshares;

  (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
    "rate per share: %3.2Lf down, %3.2Lf up", rate_per_downshare,
    rate_per_upshare);

  for (i = 0; i < shaper_tab.nsessions; i++) {
    sess_list[i].sess_downrate = rate_per_downshare *
      (shaper_tab.def_downshares + sess_list[i].sess_downincr);
    sess_list[i].sess_uprate = rate_per_upshare *
      (shaper_tab.def_upshares + sess_list[i].sess_upincr);

    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "pid %u has shares of %u down, %u up, sending rates of %3.2Lf down, "
      "%3.2Lf up", (unsigned int) sess_list[i].sess_pid,
      shaper_tab.def_downshares + sess_list[i].sess_downincr,
      shaper_tab.def_upshares + sess_list[i].sess_upincr,
      sess_list[i].sess_downrate, sess_list[i].sess_uprate);

    if (shaper_msg_send(sess_list[i].sess_pid, sess_list[i].sess_prio,
        sess_list[i].sess_downrate, sess_list[i].sess_uprate) < 0) 
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error sending msg to pid %u: %s",
        (unsigned int) sess_list[i].sess_pid, strerror(errno));
  }

  return 0;
}

static int shaper_table_sess_add(pid_t sess_pid, unsigned int prio,
    int downincr, int upincr) {
  struct shaper_sess *sess;

  if (shaper_table_lock(LOCK_EX) < 0) {
    return -1;
  }

  if (shaper_table_refresh() < 0) {
    int xerrno = errno;

    shaper_table_lock(LOCK_UN);
    errno = xerrno;
    return -1;
  }

  shaper_tab.nsessions++;
  sess = push_array(shaper_tab.sess_list);
  sess->sess_pid = sess_pid;

  if (prio != (unsigned int) -1) {
    sess->sess_prio = prio;

  } else {
    sess->sess_prio = shaper_tab.def_prio;
  }

  sess->sess_downincr = downincr;
  sess->sess_downrate = 0.0;
  sess->sess_upincr = upincr;
  sess->sess_uprate = 0.0;

  if (shaper_table_send() < 0) {
    int xerrno = errno;

    shaper_table_lock(LOCK_UN);
    errno = xerrno;
    return -1;
  }

  if (shaper_table_flush() < 0) {
    int xerrno = errno;

    shaper_table_lock(LOCK_UN);
    errno = xerrno;
    return -1;
  }

  shaper_table_lock(LOCK_UN);
  return 0;
}

static int shaper_table_sess_modify(pid_t sess_pid, unsigned int prio,
    int downincr, int upincr) {
  register unsigned int i;
  int found = FALSE, adj_down_ok = FALSE, adj_up_ok = FALSE;
  struct shaper_sess *sess_list;

  if (shaper_table_lock(LOCK_EX) < 0)
    return -1;

  if (shaper_table_refresh() < 0) {
    int xerrno = errno;

    shaper_table_lock(LOCK_UN);
    errno = xerrno;
    return -1;
  }

  /* XXX for large ShaperTables, this linear scan will increase the time
   * needed for adjusting sessions.
   */
  sess_list = shaper_tab.sess_list->elts;
  for (i = 0; i < shaper_tab.nsessions; i++) {
    if (sess_list[i].sess_pid != sess_pid)
      continue;

    found = TRUE;

    if ((shaper_tab.def_downshares + sess_list[i].sess_downincr +
        downincr) >= 1) {
      adj_down_ok = TRUE;
      sess_list[i].sess_downincr += downincr;
    }

    if ((shaper_tab.def_upshares + sess_list[i].sess_upincr +
        upincr) >= 1) {
      adj_up_ok = TRUE;
      sess_list[i].sess_upincr += upincr;
    }

    if (prio != (unsigned int) -1)
      sess_list[i].sess_prio = prio;

    break;
  }

  /* If the session was not found, or if the given adjustments were not OK,
   * do not send the changes out, but be done now.
   */
  if (!found || (!adj_down_ok && !adj_up_ok)) {
    shaper_table_lock(LOCK_UN);

    if (!found)
      errno = ENOENT;

    else if (!adj_down_ok) {
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error modifying session: shares increment (%s%d) will drop "
        "session downshares (%u) below 1", downincr > 0 ? "+" : "", downincr,
        shaper_tab.def_downshares);
      errno = EINVAL;

    } else if (!adj_up_ok) {
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error modifying session: shares increment (%s%d) will drop "
        "session upshares (%u) below 1", upincr > 0 ? "+" : "", upincr,
        shaper_tab.def_upshares);
      errno = EINVAL;
    }

    return -1;
  }

  if (shaper_table_send() < 0) {
    int xerrno = errno;

    shaper_table_lock(LOCK_UN);
    errno = xerrno;
    return -1;
  }

  if (shaper_table_flush() < 0) {
    int xerrno = errno;

    shaper_table_lock(LOCK_UN);
    errno = xerrno;
    return -1;
  }

  shaper_table_lock(LOCK_UN);
  return 0;
}

static int shaper_table_sess_remove(pid_t sess_pid) {
  register unsigned int i;
  int found = FALSE;
  struct shaper_sess *sess_list;
  array_header *new_sess_list;

  if (shaper_table_lock(LOCK_EX) < 0)
    return -1;

  if (shaper_table_refresh() < 0) {
    int xerrno = errno;

    shaper_table_lock(LOCK_UN);
    errno = xerrno;
    return -1;
  }

  if (shaper_tab.nsessions == 0) {
    /* No sessions in the ShaperTable to be removed. */
    shaper_table_lock(LOCK_UN);
    return 0;
  }

  sess_list = shaper_tab.sess_list->elts;
  new_sess_list = make_array(shaper_tab_pool, 0, sizeof(struct shaper_sess));

  for (i = 0; i < shaper_tab.nsessions; i++) {
    if (sess_list[i].sess_pid != sess_pid) {
      struct shaper_sess *sess = push_array(new_sess_list);

      sess->sess_pid = sess_list[i].sess_pid;
      sess->sess_prio = sess_list[i].sess_prio;
      sess->sess_downincr = sess_list[i].sess_downincr;
      sess->sess_downrate = sess_list[i].sess_downrate;
      sess->sess_upincr = sess_list[i].sess_upincr;
      sess->sess_uprate = sess_list[i].sess_uprate;

    } else
       found = TRUE;
  }

  if (found)
    shaper_tab.nsessions--;

  /* Replace the session list.  The memory pointed to by the overwritten
   * pointer will be freed when shaper_tab_pool is freed, which will be
   * when the table is next refreshed.
   */

  shaper_tab.sess_list = new_sess_list;

  if (shaper_table_send() < 0) {
    int xerrno = errno;

    shaper_table_lock(LOCK_UN);
    errno = xerrno;
    return -1;
  }

  if (shaper_table_flush() < 0) {
    int xerrno = errno;

    shaper_table_lock(LOCK_UN);
    errno = xerrno;
    return -1;
  }

  shaper_table_lock(LOCK_UN);
  return 0;
}

/* Control handlers
 */

/* usage: shaper all priority|rate|downrate|uprate|shares|downshares|upshares
 *   val
 */
static int shaper_handle_all(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register int i;
  int send_tab = TRUE;

  if (reqargc < 2 ||
      reqargc > 14 ||
      reqargc % 2 != 0) {
    pr_ctrls_add_response(ctrl, "wrong number of parameters");
    return -1;
  }

  if (shaper_table_lock(LOCK_EX) < 0) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "error write-locking ShaperTable: %s", strerror(errno));
    pr_ctrls_add_response(ctrl, "error handling request");
    return -1;
  }

  if (shaper_table_refresh() < 0) {
    shaper_table_lock(LOCK_UN);
    pr_ctrls_add_response(ctrl, "error handling request");
    return -1;
  }

  for (i = 0; i < reqargc;) {
    if (strcmp(reqargv[i], "downrate") == 0) {
      char *tmp;
      long double rate;

      rate = strtod(reqargv[i+1], &tmp);

      if (tmp && *tmp) {
        pr_ctrls_add_response(ctrl, "invalid downrate value (%s)",
          reqargv[i+1]);
        send_tab = FALSE;
        i += 2;
        continue;
      }

      if (rate < 0.0) {
        pr_ctrls_add_response(ctrl, "downrate must be greater than 0 (%3.2Lf)",
          rate);
        send_tab = FALSE;
        i += 2;
        continue;
      }

      shaper_tab.downrate = rate;
      pr_ctrls_add_response(ctrl, "overall downrate (%3.2Lf) set",
        shaper_tab.downrate);

      i += 2;

    } else if (strcmp(reqargv[i], "downshares") == 0) {
      int shares = atoi(reqargv[i+1]);

      if (shares < 1) {
        pr_ctrls_add_response(ctrl, "downshares (%d) must be greater than 1",
          shares);
        send_tab = FALSE;
        i += 2;
        continue;
      }

      shaper_tab.def_downshares = shares;
      pr_ctrls_add_response(ctrl, "default downshares (%u) set",
        shaper_tab.def_downshares);

      i += 2;

    } else if (strcmp(reqargv[i], "priority") == 0) {
      int prio = atoi(reqargv[i+1]);

      if (prio < 0) {
        pr_ctrls_add_response(ctrl, "priority (%d) must be greater than 0",
          prio);
        send_tab = FALSE;
        i += 2;
        continue;
      }

      shaper_tab.def_prio = prio;
      pr_ctrls_add_response(ctrl, "default priority (%u) set",
        shaper_tab.def_prio);

      i += 2;

    } else if (strcmp(reqargv[i], "rate") == 0) {
      char *tmp;
      long double rate;

      rate = strtod(reqargv[i+1], &tmp);

      if (tmp && *tmp) {
        pr_ctrls_add_response(ctrl, "invalid rate value (%s)", reqargv[i+1]);
        send_tab = FALSE;
        i += 2;
        continue;
      }

      if (rate < 0.0) {
        pr_ctrls_add_response(ctrl, "rate must be greater than 0 (%3.2Lf)",
          rate);
        send_tab = FALSE;
        i += 2;
        continue;
      }

      shaper_tab.downrate = rate;
      shaper_tab.uprate = rate;
      pr_ctrls_add_response(ctrl, "overall rates (%3.2Lf down, %3.2Lf up) set",
        shaper_tab.downrate, shaper_tab.uprate);

      i += 2;

    } else if (strcmp(reqargv[i], "shares") == 0) {
      int shares = atoi(reqargv[i+1]);

      if (shares < 1) {
        pr_ctrls_add_response(ctrl, "shares (%d) must be greater than 1",
          shares);
        send_tab = FALSE;
        i += 2;
        continue;
      }

      shaper_tab.def_downshares = shares;
      shaper_tab.def_upshares = shares;
      pr_ctrls_add_response(ctrl, "default shares (%u down, %u up) set",
        shaper_tab.def_downshares, shaper_tab.def_upshares);

      i += 2;

    } else if (strcmp(reqargv[i], "uprate") == 0) {
      char *tmp;
      long double rate;

      rate = strtod(reqargv[i+1], &tmp);

      if (tmp && *tmp) {
        pr_ctrls_add_response(ctrl, "invalid uprate value (%s)", reqargv[i+1]);
        send_tab = FALSE;
        i += 2;
        continue;
      }

      if (rate < 0.0) {
        pr_ctrls_add_response(ctrl, "uprate must be greater than 0 (%3.2Lf)",
          rate);
        send_tab = FALSE;
        i += 2;
        continue;
      }

      shaper_tab.uprate = rate;
      pr_ctrls_add_response(ctrl, "overall uprate (%3.2Lf) set",
        shaper_tab.uprate);

      i += 2;

    } else if (strcmp(reqargv[i], "upshares") == 0) {
      int shares = atoi(reqargv[i+1]);

      if (shares < 1) {
        pr_ctrls_add_response(ctrl, "upshares (%d) must be greater than 1",
          shares);
        send_tab = FALSE;
        i += 2;
        continue;
      }

      shaper_tab.def_upshares = shares;
      pr_ctrls_add_response(ctrl, "default upshares (%u) set",
        shaper_tab.def_upshares);

      i += 2;

    } else {
      pr_ctrls_add_response(ctrl, "unknown shaper all option '%s'",
        reqargv[i]);
      send_tab = FALSE;
      i += 2;
      continue;
    }
  }

  if (!send_tab) {
    shaper_table_lock(LOCK_UN);
    return -1;
  }

  if (shaper_table_send() < 0) {
    shaper_table_lock(LOCK_UN);
    pr_ctrls_add_response(ctrl, "error handling request");
    return -1;
  }

  if (shaper_table_flush() < 0) {
    shaper_table_lock(LOCK_UN);
    pr_ctrls_add_response(ctrl, "error handling request");
    return -1;
  }

  shaper_table_lock(LOCK_UN);
  return 0;
}

/* usage: shaper info */
static int shaper_handle_info(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register unsigned int i;
  struct shaper_sess *sess_list;
  unsigned int total_downshares = 0, total_upshares = 0;
  char *downbuf = NULL, *upbuf = NULL;
  size_t downbufsz = 14, upbufsz = 14;

  if (shaper_table_lock(LOCK_SH) < 0) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "unable to read-lock ShaperTable: %s", strerror(errno));
    pr_ctrls_add_response(ctrl, "error handling request");
    return -1;
  }

  if (shaper_table_refresh() < 0) {
    int xerrno = errno;
    shaper_table_lock(LOCK_UN);

    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "error refreshing ShaperTable: %s", strerror(xerrno));
    pr_ctrls_add_response(ctrl, "error handling request");
    return -1;
  }

  pr_ctrls_add_response(ctrl, "Overall Rates: %3.2Lf KB/s down, %3.2Lf KB/s up",
    shaper_tab.downrate, shaper_tab.uprate);
  pr_ctrls_add_response(ctrl, "Default Shares Per Session: %u down, %u up",
    shaper_tab.def_downshares, shaper_tab.def_upshares);
  pr_ctrls_add_response(ctrl, "Default Priority: %u", shaper_tab.def_prio);
  pr_ctrls_add_response(ctrl, "Number of Shaped Sessions: %u",
    shaper_tab.nsessions);

  sess_list = shaper_tab.sess_list->elts;

  for (i = 0; i < shaper_tab.nsessions; i++) {
    total_downshares += (shaper_tab.def_downshares +
      sess_list[i].sess_downincr);
    total_upshares += (shaper_tab.def_upshares +
      sess_list[i].sess_upincr);
  }

  if (shaper_tab.nsessions) {
    pr_ctrls_add_response(ctrl, "%-5s %8s %-14s %11s %-14s %11s",
      "PID", "Priority", "DShares", "DRate (KB/s)", "UShares", "URate (KB/s)");
    pr_ctrls_add_response(ctrl, "----- -------- -------------- ------------ -------------- ------------");
    downbuf = palloc(ctrl->ctrls_tmp_pool, downbufsz);
    upbuf = palloc(ctrl->ctrls_tmp_pool, upbufsz);
  }

  for (i = 0; i < shaper_tab.nsessions; i++) {
    memset(downbuf, '\0', downbufsz);
    memset(upbuf, '\0', upbufsz);

    pr_snprintf(downbuf, downbufsz, "%u/%u (%s%d)",
      shaper_tab.def_downshares + sess_list[i].sess_downincr, total_downshares,
      sess_list[i].sess_downincr > 0 ? "+" : "", sess_list[i].sess_downincr);
    downbuf[downbufsz-1] = '\0';

    pr_snprintf(upbuf, upbufsz, "%u/%u (%s%d)",
      shaper_tab.def_upshares + sess_list[i].sess_upincr, total_upshares,
      sess_list[i].sess_upincr > 0 ? "+" : "", sess_list[i].sess_upincr);
    upbuf[upbufsz-1] = '\0';

    pr_ctrls_add_response(ctrl, "%5u %8u %14s  %11.2Lf %14s  %11.2Lf",
      (unsigned int) sess_list[i].sess_pid, sess_list[i].sess_prio,
      downbuf, sess_list[i].sess_downrate, upbuf, sess_list[i].sess_uprate);
  }

  shaper_table_lock(LOCK_UN);
  return 0;
}

/* usage: shaper sess class|host|user name [priority prio] [shares incr]
 *    [downshares incr] [upshares incr]
 */
static int shaper_handle_sess(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register int i;
  int adjusted = FALSE, send_tab = TRUE;
  int prio = -1, downincr = 0, upincr = 0;

  if (reqargc < 4 ||
      reqargc > 6 ||
      reqargc % 2 != 0) {
    pr_ctrls_add_response(ctrl, "wrong number of parameters");
    return -1;
  }

  for (i = 2; i < reqargc;) {
    if (strcmp(reqargv[i], "downshares") == 0) {

      if (*reqargv[i+1] != '+' && *reqargv[i+1] != '-') {
        pr_ctrls_add_response(ctrl,
          "downshares (%s) must start with '+' or '-'", reqargv[i+1]);
        return -1;
      }

      downincr = atoi(reqargv[i+1]);

      if (downincr == 0) {
        pr_ctrls_add_response(ctrl, "downshares cannot be 0");
        send_tab = FALSE;
        i += 2;
        continue;
      }

      pr_ctrls_add_response(ctrl, "adjusted session downshares by %s%d",
        downincr > 0 ? "+" : "", downincr);

      i += 2;

    } else if (strcmp(reqargv[i], "priority") == 0) {
      prio = atoi(reqargv[i+1]);

      if (prio < 0) {
        pr_ctrls_add_response(ctrl, "priority (%d) must be greater than 0",
          prio);
        send_tab = FALSE;
        i += 2;
        continue;
      }

      pr_ctrls_add_response(ctrl, "set session priority to %u", prio);
      i += 2;

    } else if (strcmp(reqargv[i], "shares") == 0) {
      int incr;

      if (*reqargv[i+1] != '+' && *reqargv[i+1] != '-') {
        pr_ctrls_add_response(ctrl, "shares (%s) must start with '+' or '-'",
          reqargv[i+1]);
        return -1;
      }

      incr = atoi(reqargv[i+1]);

      if (incr == 0) {
        pr_ctrls_add_response(ctrl, "shares cannot be 0");
        send_tab = FALSE;
        i += 2;
        continue;
      }

      pr_ctrls_add_response(ctrl,
        "adjusted session downshares and upshares by %s%d",
        incr > 0 ? "+" : "", incr);

      downincr = upincr = incr;
      i += 2;

    } else if (strcmp(reqargv[i], "upshares") == 0) {

      if (*reqargv[i+1] != '+' && *reqargv[i+1] != '-') {
        pr_ctrls_add_response(ctrl,
          "upshares (%s) must start with '+' or '-'", reqargv[i+1]);
        return -1;
      }

      upincr = atoi(reqargv[i+1]);

      if (upincr == 0) {
        pr_ctrls_add_response(ctrl, "upshares cannot be 0");
        send_tab = FALSE;
        i += 2;
        continue;
      }

      pr_ctrls_add_response(ctrl, "adjusted session upshares by %s%d",
        upincr > 0 ? "+" : "", upincr);

      i += 2;

    } else {
      pr_ctrls_add_response(ctrl, "unknown shaper session option '%s'",
        reqargv[i]);
      send_tab = FALSE;
      i += 2;
      continue;
    }
  }

  if (!send_tab)
    return -1;

  /* Sessions that are not shaped (i.e. excluded from mod_shaper) cannot be
   * adjusted.  If exempted at login time, they cannot later be shaped.
   */
  /* XXX add ability to add non-shaped session to ShaperTable at
   * post-login time?  And/or remove a session from ShaperTable before
   * session exit?
   */

  if (strcmp(reqargv[0], "user") == 0) {
    pr_scoreboard_entry_t *score;
    const char *user = reqargv[1];

    if (pr_rewind_scoreboard() < 0)
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error rewinding scoreboard: %s", strerror(errno));

    while ((score = pr_scoreboard_entry_read()) != NULL) {
      pr_signals_handle();

      if (strcmp(score->sce_user, user) == 0) {
        if (shaper_table_sess_modify(score->sce_pid, prio, downincr,
            upincr) < 0) {
          (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
            "error adjusting pid %u: %s", (unsigned int) score->sce_pid,
            strerror(errno));
          pr_ctrls_add_response(ctrl, "error adjusting pid %u: %s",
            (unsigned int) score->sce_pid, strerror(errno));

        } else
          adjusted = TRUE;
      }
    }

    pr_restore_scoreboard();

  } else if (strcmp(reqargv[0], "host") == 0) {
    pr_scoreboard_entry_t *score;
    const char *addr;
    const pr_netaddr_t *na;

    na = pr_netaddr_get_addr(ctrl->ctrls_tmp_pool, reqargv[1], NULL);
    if (na == NULL) {
      pr_ctrls_add_response(ctrl, "error resolving '%s': %s", reqargv[1],
        strerror(errno));
      return -1;
    }

    addr = pr_netaddr_get_ipstr(na);

    if (pr_rewind_scoreboard() < 0)
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error rewinding scoreboard: %s", strerror(errno));

    while ((score = pr_scoreboard_entry_read()) != NULL) {
      pr_signals_handle();

      if (strcmp(score->sce_client_addr, addr) == 0) {
        if (shaper_table_sess_modify(score->sce_pid, prio, downincr,
            upincr) < 0) {
          (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
            "error adjusting pid %u: %s", (unsigned int) score->sce_pid,
            strerror(errno));
          pr_ctrls_add_response(ctrl, "error adjusting pid %u: %s",
            (unsigned int) score->sce_pid, strerror(errno));

        } else {
          adjusted = TRUE;
        }
      }
    }

    pr_restore_scoreboard();

  } else if (strcmp(reqargv[0], "class") == 0) {
    pr_scoreboard_entry_t *score;
    const char *class = reqargv[1];

    if (pr_rewind_scoreboard() < 0)
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error rewinding scoreboard: %s", strerror(errno));

    while ((score = pr_scoreboard_entry_read()) != NULL) {
      pr_signals_handle();

      if (strcmp(score->sce_class, class) == 0) {
        if (shaper_table_sess_modify(score->sce_pid, prio, downincr,
            upincr) < 0) {
          (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
            "error adjusting pid %u: %s", (unsigned int) score->sce_pid,
            strerror(errno));
          pr_ctrls_add_response(ctrl, "error adjusting pid %u: %s",
            (unsigned int) score->sce_pid, strerror(errno));

        } else {
          adjusted = TRUE;
        }
      }
    }

    pr_restore_scoreboard();

  } else {
    pr_ctrls_add_response(ctrl, "unknown shaper session target type: '%s'",
      reqargv[0]);
    return -1;
  }

  if (adjusted) {
    pr_ctrls_add_response(ctrl, "sessions adjusted");
  }

  return 0;
}

static int shaper_handle_shaper(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {

  /* Sanity check */
  if (reqargc == 0 || reqargv == NULL) {
    pr_ctrls_add_response(ctrl, "shaper: missing required parameters");
    return -1;
  }

  if (strcmp(reqargv[0], "all") == 0) {

    /* Check the all ACL */
    if (!ctrls_check_acl(ctrl, shaper_acttab, "all")) {

      /* Access denied */
      pr_ctrls_add_response(ctrl, "access denied");
      return -1;
    }

    return shaper_handle_all(ctrl, --reqargc, ++reqargv);

  } else if (strcmp(reqargv[0], "info") == 0) {

    /* Check the info ACL */
    if (!ctrls_check_acl(ctrl, shaper_acttab, "info")) {

      /* Access denied */
      pr_ctrls_add_response(ctrl, "access denied");
      return -1;
    }

    return shaper_handle_info(ctrl, --reqargc, ++reqargv);

  } else if (strcmp(reqargv[0], "sess") == 0) {

    /* Check the sess ACL */
    if (!ctrls_check_acl(ctrl, shaper_acttab, "sess")) {

      /* Access denied */
      pr_ctrls_add_response(ctrl, "access denied");
      return -1;
    }

    return shaper_handle_sess(ctrl, --reqargc, ++reqargv);
  }

  pr_ctrls_add_response(ctrl, "unknown shaper action: '%s'", reqargv[0]);
  return -1;
}

/* Configuration handlers
 */

/* usage: ShaperAll [priority prio] [rate rate] [downrate rate] [uprate rate]
 *   [shares nshares] [downshares nshares] [upshares nshares]
 */
MODRET set_shaperall(cmd_rec *cmd) {
  register unsigned int i;

  if (cmd->argc-1 < 2 || cmd->argc-1 > 14 || (cmd->argc-1) % 2 != 0)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT);

  for (i = 1; i < cmd->argc;) {
    if (strcmp(cmd->argv[i], "downrate") == 0) {
      char *tmp;
      long double rate;

      rate = strtod(cmd->argv[i+1], &tmp);

      if (tmp && *tmp)
        CONF_ERROR(cmd, "invalid downrate parameter");

      if (rate < 0.0)
        CONF_ERROR(cmd, "downrate must be greater than 0");

      shaper_tab.downrate = rate;
      i += 2;

    } else if (strcmp(cmd->argv[i], "downshares") == 0) {
      int shares = atoi(cmd->argv[i+1]);

      if (shares < 1)
        CONF_ERROR(cmd, "downshares must be greater than 1");

      shaper_tab.def_downshares = shares;
      i += 2;

    } else if (strcmp(cmd->argv[i], "priority") == 0) {
      int prio = atoi(cmd->argv[i+1]);

      if (prio < 0)
        CONF_ERROR(cmd, "priority must be greater than 0");

      shaper_tab.def_prio = prio;
      i += 2;

    } else if (strcmp(cmd->argv[i], "rate") == 0) {
      char *tmp;
      long double rate;

      rate = strtod(cmd->argv[i+1], &tmp);

      if (tmp && *tmp)
        CONF_ERROR(cmd, "invalid rate parameter");

      if (rate < 0.0)
        CONF_ERROR(cmd, "rate must be greater than 0");

      shaper_tab.downrate = rate;
      shaper_tab.uprate = rate;
      i += 2;

    } else if (strcmp(cmd->argv[i], "shares") == 0) {
      int shares = atoi(cmd->argv[i+1]);

      if (shares < 1)
        CONF_ERROR(cmd, "shares must be greater than 1");

      shaper_tab.def_downshares = shares;
      shaper_tab.def_upshares = shares;
      i += 2;

    } else if (strcmp(cmd->argv[i], "uprate") == 0) {
      char *tmp;
      long double rate;

      rate = strtod(cmd->argv[i+1], &tmp);

      if (tmp && *tmp)
        CONF_ERROR(cmd, "invalid uprate parameter");

      if (rate < 0.0)
        CONF_ERROR(cmd, "uprate must be greater than 0");

      shaper_tab.uprate = rate;
      i += 2;

    } else if (strcmp(cmd->argv[i], "upshares") == 0) {
      int shares = atoi(cmd->argv[i+1]);

      if (shares < 1)
        CONF_ERROR(cmd, "upshares must be greater than 1");

      shaper_tab.def_upshares = shares;
      i += 2;

    } else
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown option: '",
        cmd->argv[i], "'", NULL));
  }

  return PR_HANDLED(cmd);
}

/* usage: ShaperControlsACLs actions|all allow|deny user|group list */
MODRET set_shaperctrlsacls(cmd_rec *cmd) {
  char *bad_action = NULL, **actions = NULL;

  CHECK_ARGS(cmd, 4);
  CHECK_CONF(cmd, CONF_ROOT);

  actions = ctrls_parse_acl(cmd->tmp_pool, cmd->argv[1]);

  /* Check the second parameter to make sure it is "allow" or "deny" */
  if (strcmp(cmd->argv[2], "allow") != 0 &&
      strcmp(cmd->argv[2], "deny") != 0)
    CONF_ERROR(cmd, "second parameter must be 'allow' or 'deny'");

  /* Check the third parameter to make sure it is "user" or "group" */
  if (strcmp(cmd->argv[3], "user") != 0 &&
      strcmp(cmd->argv[3], "group") != 0)
    CONF_ERROR(cmd, "third parameter must be 'user' or 'group'");

  bad_action = ctrls_set_module_acls(shaper_acttab, shaper_pool, actions,
    cmd->argv[2], cmd->argv[3], cmd->argv[4]);
  if (bad_action != NULL)
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown shaper action: '",
      bad_action, "'", NULL));

  return PR_HANDLED(cmd);
}

/* usage: ShaperEngine on|off */
MODRET set_shaperengine(cmd_rec *cmd) {
  int bool;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = bool;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: ShaperLog path|"none" */
MODRET set_shaperlog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (strcasecmp(cmd->argv[0], "none") != 0 &&
      pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  shaper_log_path = pstrdup(shaper_pool, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: ShaperSession [priority prio] [shares num] [downshares num]
 *   [upshares num]
 */
MODRET set_shapersession(cmd_rec *cmd) {
  int prio = -1;
  int downshares = 0, upshares = 0;
  config_rec *c;

  register unsigned int i;

  if (cmd->argc-1 < 2 ||
      cmd->argc-1 > 8 ||
      (cmd->argc-1) % 2 != 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  for (i = 1; i < cmd->argc;) {
    if (strcmp(cmd->argv[i], "downshares") == 0) {
      char *shareno;

      shareno = cmd->argv[i+1];
      if (*shareno != '+' &&
          *shareno != '-') {
        CONF_ERROR(cmd, "downshares parameter must start with '+' or '-'");
      }

      downshares = atoi(shareno);
      i += 2;

    } else if (strcmp(cmd->argv[i], "priority") == 0) {
      prio = atoi(cmd->argv[i+1]);
      if (prio < 0) {
        CONF_ERROR(cmd, "priority must be greater than 0");
      }

      i += 2;

    } else if (strcmp(cmd->argv[i], "shares") == 0) {
      char *shareno;

      shareno = cmd->argv[i+1];
      if (*shareno != '+' &&
          *shareno != '-') {
        CONF_ERROR(cmd, "shares parameter must start with '+' or '-'");
      }

      downshares = upshares = atoi(shareno);
      i += 2;

    } else if (strcmp(cmd->argv[i], "upshares") == 0) {
      char *shareno;

      shareno = cmd->argv[i+1];
      if (*shareno != '+' &&
          *shareno != '-') {
        CONF_ERROR(cmd, "upshares parameter must start with '+' or '-'");
      }

      upshares = atoi(shareno);
      i += 2;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown option: '",
        (char *) cmd->argv[i], "'", NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 3, NULL, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = (unsigned int) prio;
  c->argv[1] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = downshares;
  c->argv[2] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[2]) = upshares;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: ShaperTable path */
MODRET set_shapertable(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  shaper_tab_path = pstrdup(shaper_pool, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET shaper_pre_pass(cmd_rec *cmd) {

  /* Make sure this session process has the ShaperTable open.
   *
   * NOTE: I'm not sure this is needed anymore, since an fd to the
   * ShaperTable is opened during the 'core.postparse' event handler,
   * in the daemon process.
   */

  PRIVS_ROOT
  shaper_tabfd = open(shaper_tab_path, O_RDWR);
  PRIVS_RELINQUISH

  if (shaper_tabfd < 0)
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "unable to open ShaperTable: %s", strerror(errno));

  return PR_DECLINED(cmd);
}

MODRET shaper_post_pass(cmd_rec *cmd) {
  config_rec *c;
  int downincr = 0, upincr = 0;
  unsigned int prio = -1;

  c = find_config(TOPLEVEL_CONF, CONF_PARAM, "ShaperEngine", FALSE);
  if (c != NULL &&
      *((unsigned char *) c->argv[0]) == TRUE) {
    shaper_engine = TRUE;

  } else {
    /* Don't need the ShaperTable open anymore. */
    close(shaper_tabfd);
    shaper_tabfd = -1;

    return PR_DECLINED(cmd);
  }

  if (!shaper_tab_path) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "ShaperTable not configured, disabling ShaperEngine");
    shaper_engine = FALSE;
    return PR_DECLINED(cmd);
  }

  if (shaper_tabfd < 0) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "ShaperTable not open, disabling ShaperEngine");
    shaper_engine = FALSE;
    return PR_DECLINED(cmd);
  }

  if (shaper_tab.downrate < 0.0 || shaper_tab.uprate < 0.0) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "overall rates negative or not configured, disabling ShaperEngine");
    shaper_engine = FALSE;
    return PR_DECLINED(cmd);
  }

  pr_event_register(&shaper_module, "core.exit", shaper_sess_exit_ev, NULL);
  pr_event_register(&shaper_module, "core.signal.USR2", shaper_sigusr2_ev,
    NULL);

  c = find_config(TOPLEVEL_CONF, CONF_PARAM, "ShaperSession", FALSE);
  if (c) {
    prio = *((unsigned int *) c->argv[0]);
    downincr = *((int *) c->argv[1]);
    upincr = *((int *) c->argv[2]);
  }

  /* Update the ShaperTable, adding a new entry for the current session. */
  if (shaper_table_sess_add(getpid(), prio, downincr, upincr) < 0) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "error adding session to ShaperTable: %s", strerror(errno));
  }

  return PR_DECLINED(cmd);
}

MODRET shaper_post_err_pass(cmd_rec *cmd) {

  /* Close the ShaperTable if we failed to authenticate. */
  close(shaper_tabfd);
  shaper_tabfd = -1;

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

static void shaper_shutdown_ev(const void *event_data, void *user_data) {

  /* Remove the queue from the system, and delete the ShaperTable.  We can
   * only do this reliably when the standalone daemon process exits; if it's
   * an inetd process, there may be other proftpd processes still running.
   */
  if (getpid() == mpid &&
      ServerType == SERVER_STANDALONE) {

    if (shaper_qid >= 0) {
      shaper_remove_queue();
    }

    if (shaper_tab_path) {
      if (pr_fsio_unlink(shaper_tab_path) < 0) {
        pr_log_debug(DEBUG9, MOD_SHAPER_VERSION
          ": error unlinking '%s': %s", shaper_tab_path, strerror(errno));
      }
    }
  }

  return;
}

static void shaper_sess_exit_ev(const void *event_data, void *user_data) {

  /* Remove this session from the ShaperTable. */
  if (shaper_table_sess_remove(getpid()) < 0) {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "error removing session from ShaperTable: %s", strerror(errno));
  }

  /* Clear any messages for this session from the queue as well. */
  shaper_msg_clear(getpid());

  return;
}

#if defined(PR_SHARED_MODULE)
static void shaper_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_shaper.c", (const char *) event_data) == 0) {
    /* Unregister ourselves from all events. */
    pr_event_unregister(&shaper_module, NULL, NULL);

    /* Unregister all control actions. */
    (void) pr_ctrls_unregister(&shaper_module, "shaper");

    if (shaper_scrub_timer_id != -1) {
      (void) pr_timer_remove(shaper_scrub_timer_id, &shaper_module);
      shaper_scrub_timer_id = -1;
    }

    if (shaper_pool) {
      destroy_pool(shaper_pool);
      shaper_pool = NULL;
      shaper_tab_pool = NULL;
      shaper_tab.sess_list = NULL;
    }
  }
}
#endif /* PR_SHARED_MODULE */

static void shaper_postparse_ev(const void *event_data, void *user_data) {
  if (shaper_log_path &&
      strcasecmp(shaper_log_path, "none") != 0 &&
      pr_log_openfile(shaper_log_path, &shaper_logfd, 0660) < 0) {
    pr_log_debug(DEBUG2, MOD_SHAPER_VERSION
      ": error opening ShaperLog '%s': %s", shaper_log_path, strerror(errno));
    shaper_logfd = -1;
  }

  if (shaper_tab_path) {
    pr_fh_t *fh;
    int xerrno;
    struct stat st;

    PRIVS_ROOT
    fh = pr_fsio_open(shaper_tab_path, O_RDWR|O_CREAT);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (fh == NULL) {
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error opening ShaperTable '%s': %s", shaper_tab_path,
        strerror(xerrno));
      pr_log_debug(DEBUG0, MOD_SHAPER_VERSION
        ": error opening ShaperTable '%s': %s", shaper_tab_path,
        strerror(xerrno));
      pr_session_disconnect(&shaper_module, PR_SESS_DISCONNECT_BAD_CONFIG,
        NULL);
    }

    if (pr_fsio_fstat(fh, &st) < 0) {
      xerrno = errno;

      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error checking ShaperTable '%s': %s", shaper_tab_path,
        strerror(xerrno));
      pr_log_debug(DEBUG0, MOD_SHAPER_VERSION
        ": error checking ShaperTable '%s': %s", shaper_tab_path,
        strerror(xerrno));

      pr_fsio_close(fh);
      pr_session_disconnect(&shaper_module, PR_SESS_DISCONNECT_BAD_CONFIG,
        NULL);
    }

    if (S_ISDIR(st.st_mode)) {
      xerrno = EISDIR;

      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error using ShaperTable '%s': %s", shaper_tab_path,
        strerror(xerrno));
      pr_log_debug(DEBUG0, MOD_SHAPER_VERSION
        ": error using ShaperTable '%s': %s", shaper_tab_path,
        strerror(xerrno));
      
      pr_fsio_close(fh);
      pr_session_disconnect(&shaper_module, PR_SESS_DISCONNECT_BAD_CONFIG,
        NULL);
    }

    /* Initialize ShaperTable */
    if (shaper_table_init(fh) < 0)
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error initializing ShaperTable: %s", strerror(errno));

    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "determining queue ID for path '%s'", shaper_tab_path);

    shaper_qid = shaper_get_queue(shaper_tab_path);
    if (shaper_qid < 0) {
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error obtaining queue ID: %s", strerror(errno));

    } else {
      struct msqid_ds ds;

      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "obtained queue ID %d", shaper_qid);

      if (msgctl(shaper_qid, IPC_STAT, &ds) < 0) {
        (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
          "error checking queue ID %d: %s", shaper_qid, strerror(errno));

      } else {
        shaper_qmaxbytes = ds.msg_qbytes;
      }

      /* We could be being restarted, in which case we want to send our
       * reinitialized table to existing sessions.
       */

      if (shaper_table_lock(LOCK_EX) < 0) {
        (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
          "error locking ShaperTable: %s", strerror(errno));
        return;
      }

      if (shaper_table_refresh() < 0) {
        shaper_table_lock(LOCK_UN);
        return;
      }

      if (shaper_table_send() < 0) {
        shaper_table_lock(LOCK_UN);
        return;
      }

      if (shaper_table_flush() < 0) {
        shaper_table_lock(LOCK_UN);
        return;
      }

      shaper_table_lock(LOCK_UN);
    }

    if (shaper_scrub_timer_id == -1) {
      shaper_scrub_timer_id = pr_timer_add(SHAPER_SCRUB_INTERVAL, -1,
        &shaper_module, shaper_table_scrub_cb, "shaper table scrubber");
    }

  } else {
    (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
      "no ShaperTable configured");
  }

}

static void shaper_restart_ev(const void *event_data, void *user_data) {
  register unsigned int i;

  (void) close(shaper_logfd);
  shaper_logfd = -1;
  shaper_log_path = NULL;

  if (shaper_pool) {
    destroy_pool(shaper_pool);

    /* Make sure to mark subpools as invalid now as well. */
    shaper_tab_pool = NULL;
    shaper_tab.sess_list = NULL;
  }

  shaper_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(shaper_pool, MOD_SHAPER_VERSION);

  for (i = 0; shaper_acttab[i].act_action; i++) {
    shaper_acttab[i].act_acl = pcalloc(shaper_pool, sizeof(ctrls_acl_t));
    ctrls_init_acl(shaper_acttab[i].act_acl);
  }

  if (shaper_scrub_timer_id != -1) {
    (void) pr_timer_remove(shaper_scrub_timer_id, &shaper_module);
    shaper_scrub_timer_id = -1;
  }

  return;
}

static void shaper_sigusr2_ev(const void *event_data, void *user_data) {
  int res;

  /* Check the queue for any messages for us. */
  res = shaper_msg_recv();

  switch (res) {
    case -1:
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "error receiving updates for pid %lu: %s", (unsigned long) getpid(),
        strerror(errno));
      break;

    case 0:
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "received signal, no updates for pid %lu", (unsigned long) getpid());
      break;

    default:
      (void) pr_log_writefile(shaper_logfd, MOD_SHAPER_VERSION,
        "received signal, read in %d %s for pid %lu", res,
        res == 1 ? "update" : "updates", (unsigned long) getpid());
  }

  return;
}

/* Initialization functions
 */

static int shaper_init(void) {

  shaper_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(shaper_pool, MOD_SHAPER_VERSION);

  shaper_tab.def_prio = SHAPER_DEFAULT_PRIO;
  shaper_tab.downrate = SHAPER_DEFAULT_RATE;
  shaper_tab.def_downshares = SHAPER_DEFAULT_DOWNSHARES;
  shaper_tab.uprate = SHAPER_DEFAULT_RATE;
  shaper_tab.def_upshares = SHAPER_DEFAULT_UPSHARES;
  shaper_tab.nsessions = 0;

  if (pr_ctrls_register(&shaper_module, "shaper", "tune mod_shaper settings",
      shaper_handle_shaper) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_SHAPER_VERSION
      ": error registering 'shaper' control: %s", strerror(errno));

  } else {
    register unsigned int i;

    for (i = 0; shaper_acttab[i].act_action; i++) {
      shaper_acttab[i].act_acl = pcalloc(shaper_pool, sizeof(ctrls_acl_t));
      ctrls_init_acl(shaper_acttab[i].act_acl);
    }
  }

#if defined(PR_SHARED_MODULE)
  pr_event_register(&shaper_module, "core.module-unload", shaper_mod_unload_ev,
    NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&shaper_module, "core.postparse", shaper_postparse_ev,
    NULL);
  pr_event_register(&shaper_module, "core.restart", shaper_restart_ev, NULL);
  pr_event_register(&shaper_module, "core.shutdown", shaper_shutdown_ev, NULL);

  return 0;
}

static int shaper_sess_init(void) {

  /* The ShaperTable scrubbing timer should only run in the daemon. */
  pr_timer_remove(shaper_scrub_timer_id, &shaper_module);

  return 0;
}

/* Module API tables
 */

static ctrls_acttab_t shaper_acttab[] = {
  { "all",	NULL, NULL, NULL },
  { "info",	NULL, NULL, NULL },
  { "sess",	NULL, NULL, NULL },
  { NULL, NULL, NULL, NULL }
};

static conftable shaper_conftab[] = {
  { "ShaperAll",		set_shaperall,		NULL },
  { "ShaperControlsACLs",	set_shaperctrlsacls,	NULL },
  { "ShaperEngine",		set_shaperengine,	NULL },
  { "ShaperLog",		set_shaperlog,		NULL },
  { "ShaperSession",		set_shapersession,	NULL },
  { "ShaperTable",		set_shapertable,	NULL },
  { NULL }
};

static cmdtable shaper_cmdtab[] = {
  { PRE_CMD,		C_PASS, G_NONE, shaper_pre_pass,	FALSE, FALSE },
  { POST_CMD,		C_PASS, G_NONE, shaper_post_pass,	FALSE, FALSE },
  { POST_CMD_ERR,	C_PASS, G_NONE, shaper_post_err_pass,	FALSE, FALSE },
  { 0, NULL }
};

module shaper_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "shaper",

  /* Module configuration handler table */
  shaper_conftab,

  /* Module command handler table */
  shaper_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  shaper_init,

  /* Session initialization function */
  shaper_sess_init,

  /* Module version */
  MOD_SHAPER_VERSION
};
