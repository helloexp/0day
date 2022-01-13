/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2011-2015, 2017 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_util.h"

/* TCSASOFT is a BSD extension that ignores control flags and speed. */
#ifndef TCSASOFT
# define TCSASOFT	0
#endif

/* Non-standard termios input flags */
#ifndef IUCLC
# define IUCLC		0
#endif
#ifndef IMAXBEL
# define IMAXBEL	0
#endif
#ifndef IUTF8
# define IUTF8	0
#endif

/* Non-standard termios output flags */
#ifndef OLCUC
# define OLCUC	0
#endif
#ifndef ONLCR
# define ONLCR	0
#endif
#ifndef OCRNL
# define OCRNL	0
#endif
#ifndef ONOCR
# define ONOCR	0
#endif
#ifndef ONLRET
# define ONLRET	0
#endif

/* Non-standard termios local flags */
#ifndef XCASE
# define XCASE		0
#endif
#ifndef IEXTEN
# define IEXTEN		0
#endif
#ifndef ECHOCTL
# define ECHOCTL	0
#endif
#ifndef ECHOKE
# define ECHOKE		0
#endif
#ifndef PENDIN
# define PENDIN		0
#endif

static struct termios term, oterm;
static int changed;

/* tgetpass() needs to know the erase and kill chars for cbreak mode. */
__dso_public int sudo_term_eof;
__dso_public int sudo_term_erase;
__dso_public int sudo_term_kill;

static volatile sig_atomic_t got_sigttou;

/*
 * SIGTTOU signal handler for term_restore that just sets a flag.
 */
static void
sigttou(int signo)
{
    got_sigttou = 1;
}

/*
 * Like tcsetattr() but restarts on EINTR _except_ for SIGTTOU.
 * Returns 0 on success or -1 on failure, setting errno.
 * Sets got_sigttou on failure if interrupted by SIGTTOU.
 */
static int
tcsetattr_nobg(int fd, int flags, struct termios *tp)
{
    struct sigaction sa, osa;
    int rc;

    /*
     * If we receive SIGTTOU from tcsetattr() it means we are
     * not in the foreground process group.
     * This should be less racy than using tcgetpgrp().
     */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sigttou;
    got_sigttou = 0;
    sigaction(SIGTTOU, &sa, &osa);
    do {
	rc = tcsetattr(fd, flags, tp);
    } while (rc != 0 && errno == EINTR && !got_sigttou);
    sigaction(SIGTTOU, &osa, NULL);

    return rc;
}

/*
 * Restore saved terminal settings if we are in the foreground process group.
 * Returns true on success or false on failure.
 */
bool
sudo_term_restore_v1(int fd, bool flush)
{
    debug_decl(sudo_term_restore, SUDO_DEBUG_UTIL)

    if (changed) {
	const int flags = flush ? (TCSASOFT|TCSAFLUSH) : (TCSASOFT|TCSADRAIN);
	if (tcsetattr_nobg(fd, flags, &oterm) != 0)
	    debug_return_bool(false);
	changed = 0;
    }
    debug_return_bool(true);
}

/*
 * Disable terminal echo.
 * Returns true on success or false on failure.
 */
bool
sudo_term_noecho_v1(int fd)
{
    debug_decl(sudo_term_noecho, SUDO_DEBUG_UTIL)

    if (!changed && tcgetattr(fd, &oterm) != 0)
	debug_return_bool(false);
    (void) memcpy(&term, &oterm, sizeof(term));
    CLR(term.c_lflag, ECHO|ECHONL);
#ifdef VSTATUS
    term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
    if (tcsetattr_nobg(fd, TCSASOFT|TCSADRAIN, &term) == 0) {
	changed = 1;
	debug_return_bool(true);
    }
    debug_return_bool(false);
}

/*
 * Set terminal to raw mode.
 * Returns true on success or false on failure.
 */
bool
sudo_term_raw_v1(int fd, int isig)
{
    struct termios term;
    debug_decl(sudo_term_raw, SUDO_DEBUG_UTIL)

    if (!changed && tcgetattr(fd, &oterm) != 0)
	debug_return_bool(false);
    (void) memcpy(&term, &oterm, sizeof(term));
    /* Set terminal to raw mode */
    term.c_cc[VMIN] = 1;
    term.c_cc[VTIME] = 0;
    CLR(term.c_iflag, ICRNL | IGNCR | INLCR | IUCLC | IXON);
    CLR(term.c_oflag, OPOST);
    CLR(term.c_lflag, ECHO | ICANON | ISIG | IEXTEN);
    if (isig)
	SET(term.c_lflag, ISIG);
    if (tcsetattr_nobg(fd, TCSASOFT|TCSADRAIN, &term) == 0) {
	changed = 1;
    	debug_return_bool(true);
    }
    debug_return_bool(false);
}

/*
 * Set terminal to cbreak mode.
 * Returns true on success or false on failure.
 */
bool
sudo_term_cbreak_v1(int fd)
{
    debug_decl(sudo_term_cbreak, SUDO_DEBUG_UTIL)

    if (!changed && tcgetattr(fd, &oterm) != 0)
	debug_return_bool(false);
    (void) memcpy(&term, &oterm, sizeof(term));
    /* Set terminal to half-cooked mode */
    term.c_cc[VMIN] = 1;
    term.c_cc[VTIME] = 0;
    /* cppcheck-suppress redundantAssignment */
    CLR(term.c_lflag, ECHO | ECHONL | ICANON | IEXTEN);
    /* cppcheck-suppress redundantAssignment */
    SET(term.c_lflag, ISIG);
#ifdef VSTATUS
    term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
    if (tcsetattr_nobg(fd, TCSASOFT|TCSADRAIN, &term) == 0) {
	sudo_term_eof = term.c_cc[VEOF];
	sudo_term_erase = term.c_cc[VERASE];
	sudo_term_kill = term.c_cc[VKILL];
	changed = 1;
	debug_return_bool(true);
    }
    debug_return_bool(false);
}

/* Termios flags to copy between terminals. */
#define INPUT_FLAGS (IGNPAR|PARMRK|INPCK|ISTRIP|INLCR|IGNCR|ICRNL|IUCLC|IXON|IXANY|IXOFF|IMAXBEL|IUTF8)
#define OUTPUT_FLAGS (OPOST|OLCUC|ONLCR|OCRNL|ONOCR|ONLRET)
#define CONTROL_FLAGS (CS7|CS8|PARENB|PARODD)
#define LOCAL_FLAGS (ISIG|ICANON|XCASE|ECHO|ECHOE|ECHOK|ECHONL|NOFLSH|TOSTOP|IEXTEN|ECHOCTL|ECHOKE|PENDIN)

/*
 * Copy terminal settings from one descriptor to another.
 * We cannot simply copy the struct termios as src and dst may be
 * different terminal types (pseudo-tty vs. console or glass tty).
 * Returns true on success or false on failure.
 */
bool
sudo_term_copy_v1(int src, int dst)
{
    struct termios tt_src, tt_dst;
    struct winsize wsize;
    speed_t speed;
    int i;
    debug_decl(sudo_term_copy, SUDO_DEBUG_UTIL)

    if (tcgetattr(src, &tt_src) != 0 || tcgetattr(dst, &tt_dst) != 0)
	debug_return_bool(false);

    /* Clear select input, output, control and local flags. */
    CLR(tt_dst.c_iflag, INPUT_FLAGS);
    CLR(tt_dst.c_oflag, OUTPUT_FLAGS);
    CLR(tt_dst.c_cflag, CONTROL_FLAGS);
    CLR(tt_dst.c_lflag, LOCAL_FLAGS);

    /* Copy select input, output, control and local flags. */
    SET(tt_dst.c_iflag, (tt_src.c_iflag & INPUT_FLAGS));
    SET(tt_dst.c_oflag, (tt_src.c_oflag & OUTPUT_FLAGS));
    SET(tt_dst.c_cflag, (tt_src.c_cflag & CONTROL_FLAGS));
    SET(tt_dst.c_lflag, (tt_src.c_lflag & LOCAL_FLAGS));

    /* Copy special chars from src verbatim. */
    for (i = 0; i < NCCS; i++)
	tt_dst.c_cc[i] = tt_src.c_cc[i];

    /* Copy speed from src (zero output speed closes the connection). */
    if ((speed = cfgetospeed(&tt_src)) == B0)
	speed = B38400;
    cfsetospeed(&tt_dst, speed);
    speed = cfgetispeed(&tt_src);
    cfsetispeed(&tt_dst, speed);

    if (tcsetattr_nobg(dst, TCSASOFT|TCSAFLUSH, &tt_dst) == -1)
	debug_return_bool(false);

    if (ioctl(src, TIOCGWINSZ, &wsize) == 0)
	(void)ioctl(dst, TIOCSWINSZ, &wsize);

    debug_return_bool(true);
}
