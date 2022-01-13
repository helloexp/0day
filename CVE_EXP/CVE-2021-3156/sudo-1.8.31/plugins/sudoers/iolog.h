/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2018 Todd C. Miller <Todd.Miller@sudo.ws>
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

#ifndef SUDOERS_IOLOG_H
#define SUDOERS_IOLOG_H

#ifdef HAVE_ZLIB_H
# include <zlib.h>	/* for gzFile */
#endif

/*
 * I/O log event types as stored as the first field in the timing file.
 * Changing existing values will result in incompatible I/O log files.
 */
#define IO_EVENT_STDIN		0
#define IO_EVENT_STDOUT		1
#define IO_EVENT_STDERR		2
#define IO_EVENT_TTYIN		3
#define IO_EVENT_TTYOUT		4
#define IO_EVENT_WINSIZE	5
#define IO_EVENT_TTYOUT_1_8_7	6
#define IO_EVENT_SUSPEND	7
#define IO_EVENT_COUNT		8

/* Default maximum session ID */
#define SESSID_MAX      2176782336U

union io_fd {
    FILE *f;
#ifdef HAVE_ZLIB_H
    gzFile g;
#endif
    void *v;
};

/*
 * Info present in the I/O log file
 */
struct log_info {
    char *cwd;
    char *user;
    char *runas_user;
    char *runas_group;
    char *tty;
    char *cmd;
    time_t tstamp;
    int rows;
    int cols;
};

struct timing_closure {
    const char *decimal;
    struct timespec *max_delay;
    union io_fd fd;
    int event;
    union {
	struct {
	    int rows;
	    int cols;
	} winsize;
	size_t nbytes; // XXX
	int signo;
    } u;
};

/* iolog_util.c */
bool parse_timing(const char *buf, struct timespec *delay, struct timing_closure *timing);
char *parse_delay(const char *cp, struct timespec *delay, const char *decimal_point);
struct log_info *parse_logfile(const char *logfile);
void free_log_info(struct log_info *li);
void adjust_delay(struct timespec *delay, struct timespec *max_delay, double scale_factor);

#endif /* SUDOERS_IOLOG_H */
