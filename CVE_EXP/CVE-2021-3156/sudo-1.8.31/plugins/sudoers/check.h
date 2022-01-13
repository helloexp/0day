/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1993-1996,1998-2005, 2007-2014
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

#ifndef SUDOERS_CHECK_H
#define SUDOERS_CHECK_H

/* Status codes for timestamp_status() */
#define TS_CURRENT		0
#define TS_OLD			1
#define TS_MISSING		2
#define TS_ERROR		3
#define TS_FATAL		4

/*
 * Time stamps are now stored in a single file which contains multiple
 * records.  Each record starts with a 16-bit version number and a 16-bit
 * record size.  Multiple record types can coexist in the same file.
 */
#define	TS_VERSION		2

/* Time stamp entry types */
#define TS_GLOBAL		0x01	/* not restricted by tty or ppid */
#define TS_TTY			0x02	/* restricted by tty */
#define TS_PPID			0x03	/* restricted by ppid */
#define TS_LOCKEXCL		0x04	/* special lock record */

/* Time stamp flags */
#define TS_DISABLED		0x01	/* entry disabled */
#define TS_ANYUID		0x02	/* ignore uid, only valid in the key */

struct timestamp_entry_v1 {
    unsigned short version;	/* version number */
    unsigned short size;	/* entry size */
    unsigned short type;	/* TS_GLOBAL, TS_TTY, TS_PPID */
    unsigned short flags;	/* TS_DISABLED, TS_ANYUID */
    uid_t auth_uid;		/* uid to authenticate as */
    pid_t sid;			/* session ID associated with tty/ppid */
    struct timespec ts;		/* time stamp (CLOCK_MONOTONIC) */
    union {
	dev_t ttydev;		/* tty device number */
	pid_t ppid;		/* parent pid */
    } u;
};

struct timestamp_entry {
    unsigned short version;	/* version number */
    unsigned short size;	/* entry size */
    unsigned short type;	/* TS_GLOBAL, TS_TTY, TS_PPID */
    unsigned short flags;	/* TS_DISABLED, TS_ANYUID */
    uid_t auth_uid;		/* uid to authenticate as */
    pid_t sid;			/* session ID associated with tty/ppid */
    struct timespec start_time;	/* session/ppid start time */
    struct timespec ts;		/* time stamp (CLOCK_MONOTONIC) */
    union {
	dev_t ttydev;		/* tty device number */
	pid_t ppid;		/* parent pid */
    } u;
};

void *timestamp_open(const char *user, pid_t sid);
void  timestamp_close(void *vcookie);
bool  timestamp_lock(void *vcookie, struct passwd *pw);
bool  timestamp_update(void *vcookie, struct passwd *pw);
int   timestamp_status(void *vcookie, struct passwd *pw);
int   get_starttime(pid_t pid, struct timespec *starttime);
bool  already_lectured(int status);
int   set_lectured(void);

#endif /* SUDOERS_CHECK_H */
