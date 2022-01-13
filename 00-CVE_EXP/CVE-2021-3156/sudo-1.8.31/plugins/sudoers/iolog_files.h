/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2013 Todd C. Miller <Todd.Miller@sudo.ws>
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

#ifndef SUDOERS_IOLOG_FILES_H
#define SUDOERS_IOLOG_FILES_H

/*
 * Indexes into io_log_files[]
 */
#define IOFD_STDIN	0
#define IOFD_STDOUT	1
#define IOFD_STDERR	2
#define IOFD_TTYIN	3
#define IOFD_TTYOUT	4
#define IOFD_TIMING	5
#define IOFD_MAX	6

struct io_log_file {
    bool enabled;
    const char *suffix;
    union io_fd fd;
};

static struct io_log_file io_log_files[] = {
    { false, "/stdin" },	/* IOFD_STDIN */
    { false, "/stdout" },	/* IOFD_STDOUT */
    { false, "/stderr" },	/* IOFD_STDERR */
    { false, "/ttyin" },	/* IOFD_TTYIN  */
    { false, "/ttyout" },	/* IOFD_TTYOUT */
    { true,  "/timing" },	/* IOFD_TIMING */
    { false, NULL }		/* IOFD_MAX */
};

#endif /* SUDOERS_IOLOG_H */
