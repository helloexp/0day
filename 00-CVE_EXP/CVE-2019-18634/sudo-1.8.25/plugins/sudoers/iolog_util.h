/*
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

#ifndef SUDOERS_IOLOG_UTIL_H
#define SUDOERS_IOLOG_UTIL_H

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
    int idx;
    union {
	struct {
	    int rows;
	    int cols;
	} winsize;
	size_t nbytes; // XXX
    } u;
};

/*
 * I/O log fd numbers as stored in the timing file.
 * This list must be kept in sync with iolog.h.
 */
#ifndef IOFD_MAX
# define IOFD_STDIN	0
# define IOFD_STDOUT	1
# define IOFD_STDERR	2
# define IOFD_TTYIN	3
# define IOFD_TTYOUT	4
# define IOFD_TIMING	5
# define IOFD_MAX	6
#endif

bool parse_timing(const char *buf, struct timespec *delay, struct timing_closure *timing);
char *parse_delay(const char *cp, struct timespec *delay, const char *decimal_point);
struct log_info *parse_logfile(const char *logfile);
void free_log_info(struct log_info *li);
void adjust_delay(struct timespec *delay, struct timespec *max_delay, double scale_factor);

#endif /* SUDOERS_IOLOG_UTIL_H */
