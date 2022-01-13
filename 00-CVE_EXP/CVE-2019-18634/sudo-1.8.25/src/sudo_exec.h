/*
 * Copyright (c) 2010-2016 Todd C. Miller <Todd.Miller@sudo.ws>
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
 */

#ifndef SUDO_EXEC_H
#define SUDO_EXEC_H

/*
 * Older systems may not support MSG_WAITALL but it shouldn't really be needed.
 */
#ifndef MSG_WAITALL
# define MSG_WAITALL 0
#endif

/*
 * Some older systems support siginfo but predate SI_USER.
 */
#ifdef SI_USER
# define USER_SIGNALED(_info) ((_info) != NULL && (_info)->si_code == SI_USER)
#else
# define USER_SIGNALED(_info) ((_info) != NULL && (_info)->si_code <= 0)
#endif

/*
 * Indices into io_fds[] when running a command in a pty.
 */
#define SFD_STDIN	0
#define SFD_STDOUT	1
#define SFD_STDERR	2
#define SFD_MASTER	3
#define SFD_SLAVE	4
#define SFD_USERTTY	5

/*
 * Special values to indicate whether continuing in foreground or background.
 */
#define SIGCONT_FG	-2
#define SIGCONT_BG	-3

/*
 * Positions in saved_signals[]
 */
#define SAVED_SIGALRM	 0
#define SAVED_SIGCHLD	 1
#define SAVED_SIGCONT	 2
#define SAVED_SIGHUP	 3
#define SAVED_SIGINT	 4
#define SAVED_SIGPIPE	 5
#define SAVED_SIGQUIT	 6
#define SAVED_SIGTERM	 7
#define SAVED_SIGTSTP	 8
#define SAVED_SIGTTIN	 9
#define SAVED_SIGTTOU	10
#define SAVED_SIGUSR1	11
#define SAVED_SIGUSR2	12

/*
 * Error codes for sesh
 */
#define SESH_SUCCESS	    0		/* successful operation */
#define SESH_ERR_FAILURE    1		/* unspecified error */
#define SESH_ERR_INVALID    30		/* invalid -e arg value */
#define SESH_ERR_BAD_PATHS  31		/* odd number of paths */
#define SESH_ERR_NO_FILES   32		/* copy error, no files copied */
#define SESH_ERR_SOME_FILES 33		/* copy error, some files copied */

/*
 * Symbols shared between exec.c, exec_nopty.c, exec_pty.c and exec_monitor.c
 */
struct command_details;
struct command_status;

/* exec.c */
void exec_cmnd(struct command_details *details, int errfd);
void terminate_command(pid_t pid, bool use_pgrp);
bool sudo_terminated(struct command_status *cstat);

/* exec_common.c */
int sudo_execve(int fd, const char *path, char *const argv[], char *envp[], bool noexec);
char **disable_execute(char *envp[], const char *dso);

/* exec_nopty.c */
void exec_nopty(struct command_details *details, struct command_status *cstat);

/* exec_pty.c */
bool exec_pty(struct command_details *details, struct command_status *cstat);
void pty_cleanup(void);
int pty_make_controlling(void);
extern int io_fds[6];

/* exec_monitor.c */
int exec_monitor(struct command_details *details, sigset_t *omask, bool foreground, int backchannel);

/* utmp.c */
bool utmp_login(const char *from_line, const char *to_line, int ttyfd,
    const char *user);
bool utmp_logout(const char *line, int status);

#endif /* SUDO_EXEC_H */
