/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1993-1996, 1998-2005, 2007-2016
 *	Todd C. Miller <Todd.Miller@sudo.ws>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#ifndef SUDO_SUDO_H
#define SUDO_SUDO_H

#include <limits.h>
#include <pathnames.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

#include "sudo_gettext.h"	/* must be included before sudo_compat.h */

#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_queue.h"
#include "sudo_util.h"

#ifdef HAVE_PRIV_SET
# include <priv.h>
#endif

/* Enable asserts() to avoid static analyzer false positives. */
#if !(defined(SUDO_DEVEL) || defined(__clang_analyzer__) || defined(__COVERITY__))
# define NDEBUG
#endif

#ifdef __TANDEM
# define ROOT_UID	65535
#else
# define ROOT_UID	0
#endif

/*
 * Various modes sudo can be in (based on arguments) in hex
 */
#define MODE_RUN		0x00000001
#define MODE_EDIT		0x00000002
#define MODE_VALIDATE		0x00000004
#define MODE_INVALIDATE		0x00000008
#define MODE_KILL		0x00000010
#define MODE_VERSION		0x00000020
#define MODE_HELP		0x00000040
#define MODE_LIST		0x00000080
#define MODE_CHECK		0x00000100
#define MODE_MASK		0x0000ffff

/* Mode flags */
/* XXX - prune this */
#define MODE_BACKGROUND		0x00010000
#define MODE_SHELL		0x00020000
#define MODE_LOGIN_SHELL	0x00040000
#define MODE_IMPLIED_SHELL	0x00080000
#define MODE_RESET_HOME		0x00100000
#define MODE_PRESERVE_GROUPS	0x00200000
#define MODE_PRESERVE_ENV	0x00400000
#define MODE_NONINTERACTIVE	0x00800000
#define MODE_LONG_LIST		0x01000000

/*
 * Flags for tgetpass()
 */
#define TGP_NOECHO	0x00		/* turn echo off reading pw (default) */
#define TGP_ECHO	0x01		/* leave echo on when reading passwd */
#define TGP_STDIN	0x02		/* read from stdin, not /dev/tty */
#define TGP_ASKPASS	0x04		/* read from askpass helper program */
#define TGP_MASK	0x08		/* mask user input when reading */
#define TGP_NOECHO_TRY	0x10		/* turn off echo if possible */
#define TGP_BELL	0x20		/* bell on password prompt */

/* name/value pairs for command line settings. */
struct sudo_settings {
    const char *name;
    const char *value;
};

struct user_details {
    pid_t pid;
    pid_t ppid;
    pid_t pgid;
    pid_t tcpgid;
    pid_t sid;
    uid_t uid;
    uid_t euid;
    uid_t gid;
    uid_t egid;
    const char *username;
    const char *cwd;
    const char *tty;
    const char *host;
    const char *shell;
    GETGROUPS_T *groups;
    int ngroups;
    int ts_rows;
    int ts_cols;
};

#define CD_SET_UID		0x000001
#define CD_SET_EUID		0x000002
#define CD_SET_GID		0x000004
#define CD_SET_EGID		0x000008
#define CD_PRESERVE_GROUPS	0x000010
#define CD_NOEXEC		0x000020
#define CD_SET_PRIORITY		0x000040
#define CD_SET_UMASK		0x000080
#define CD_SET_TIMEOUT		0x000100
#define CD_SUDOEDIT		0x000200
#define CD_BACKGROUND		0x000400
#define CD_RBAC_ENABLED		0x000800
#define CD_USE_PTY		0x001000
#define CD_SET_UTMP		0x002000
#define CD_EXEC_BG		0x004000
#define CD_SUDOEDIT_COPY	0x008000
#define CD_SUDOEDIT_FOLLOW	0x010000
#define CD_SUDOEDIT_CHECKDIR	0x020000
#define CD_SET_GROUPS		0x040000
#define CD_LOGIN_SHELL		0x080000
#define CD_OVERRIDE_UMASK	0x100000

struct preserved_fd {
    TAILQ_ENTRY(preserved_fd) entries;
    int lowfd;
    int highfd;
    int flags;
};
TAILQ_HEAD(preserved_fd_list, preserved_fd);

struct command_details {
    uid_t uid;
    uid_t euid;
    gid_t gid;
    gid_t egid;
    mode_t umask;
    int priority;
    int timeout;
    int ngroups;
    int closefrom;
    int flags;
    int execfd;
    struct preserved_fd_list preserved_fds;
    struct passwd *pw;
    GETGROUPS_T *groups;
    const char *command;
    const char *cwd;
    const char *login_class;
    const char *chroot;
    const char *selinux_role;
    const char *selinux_type;
    const char *utmp_user;
    const char *tty;
    char **argv;
    char **envp;
#ifdef HAVE_PRIV_SET
    priv_set_t *privs;
    priv_set_t *limitprivs;
#endif
};

/* Status passed between parent and child via socketpair */
struct command_status {
#define CMD_INVALID	0
#define CMD_ERRNO	1
#define CMD_WSTATUS	2
#define CMD_SIGNO	3
#define CMD_PID		4
#define CMD_TTYWINCH	5
    int type;
    int val;
};

/* Garbage collector data types. */
enum sudo_gc_types {
    GC_UNKNOWN,
    GC_VECTOR,
    GC_PTR
};

/* For fatal() and fatalx() (XXX - needed?) */
void cleanup(int);

/* tgetpass.c */
char *tgetpass(const char *prompt, int timeout, int flags,
    struct sudo_conv_callback *callback);

/* exec.c */
int sudo_execute(struct command_details *details, struct command_status *cstat);

/* parse_args.c */
int parse_args(int argc, char **argv, int *nargc, char ***nargv,
    struct sudo_settings **settingsp, char ***env_addp);
extern int tgetpass_flags;

/* get_pty.c */
bool get_pty(int *master, int *slave, char *name, size_t namesz, uid_t uid);

/* sudo.c */
int policy_init_session(struct command_details *details);
int run_command(struct command_details *details);
int os_init_common(int argc, char *argv[], char *envp[]);
bool gc_add(enum sudo_gc_types type, void *v);
bool set_user_groups(struct command_details *details);
extern const char *list_user;
extern struct user_details user_details;
extern int sudo_debug_instance;

/* sudo_edit.c */
int sudo_edit(struct command_details *details);

/* parse_args.c */
void usage(int);

/* openbsd.c */
int os_init_openbsd(int argc, char *argv[], char *envp[]);

/* selinux.c */
int selinux_restore_tty(void);
int selinux_setup(const char *role, const char *type, const char *ttyn,
    int ttyfd);
void selinux_execve(int fd, const char *path, char *const argv[],
    char *envp[], bool noexec);

/* solaris.c */
void set_project(struct passwd *);
int os_init_solaris(int argc, char *argv[], char *envp[]);

/* hooks.c */
/* XXX - move to sudo_plugin_int.h? */
struct sudo_hook;
int register_hook(struct sudo_hook *hook);
int deregister_hook(struct sudo_hook *hook);
int process_hooks_getenv(const char *name, char **val);
int process_hooks_setenv(const char *name, const char *value, int overwrite);
int process_hooks_putenv(char *string);
int process_hooks_unsetenv(const char *name);

/* env_hooks.c */
char *getenv_unhooked(const char *name);

/* interfaces.c */
int get_net_ifs(char **addrinfo);

/* ttyname.c */
char *get_process_ttyname(char *name, size_t namelen);

/* signal.c */
struct sigaction;
int sudo_sigaction(int signo, struct sigaction *sa, struct sigaction *osa);
void init_signals(void);
void restore_signals(void);
void save_signals(void);
bool signal_pending(int signo);

/* preload.c */
void preload_static_symbols(void);

/* preserve_fds.c */
int add_preserved_fd(struct preserved_fd_list *pfds, int fd);
void closefrom_except(int startfd, struct preserved_fd_list *pfds);
void parse_preserved_fds(struct preserved_fd_list *pfds, const char *fdstr);

/* setpgrp_nobg.c */
int tcsetpgrp_nobg(int fd, pid_t pgrp_id);

/* limits.c */
void disable_coredump();
void restore_limits(void);
void restore_nproc(void);
void unlimit_nproc(void);
void unlimit_sudo(void);

#endif /* SUDO_SUDO_H */
