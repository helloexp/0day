/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2017 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "sudo.h"

static volatile sig_atomic_t got_sigttou;

/*
 * SIGTTOU signal handler for tcsetpgrp_nobg() that just sets a flag.
 */
static void
sigttou(int signo)
{
    got_sigttou = 1;
}

/*
 * Like tcsetpgrp() but restarts on EINTR _except_ for SIGTTOU.
 * Returns 0 on success or -1 on failure, setting errno.
 * Sets got_sigttou on failure if interrupted by SIGTTOU.
 */
int
tcsetpgrp_nobg(int fd, pid_t pgrp_id)
{
    struct sigaction sa, osa;
    int rc;

    /*
     * If we receive SIGTTOU from tcsetpgrp() it means we are
     * not in the foreground process group.
     * This avoid a TOCTOU race compared to using tcgetpgrp().
     */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* do not restart syscalls */
    sa.sa_handler = sigttou;
    got_sigttou = 0;
    (void)sigaction(SIGTTOU, &sa, &osa);
    do {
	rc = tcsetpgrp(fd, pgrp_id);
    } while (rc != 0 && errno == EINTR && !got_sigttou);
    (void)sigaction(SIGTTOU, &osa, NULL);

    return rc;
}
