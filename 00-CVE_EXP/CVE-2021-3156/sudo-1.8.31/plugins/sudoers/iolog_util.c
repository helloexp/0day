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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <time.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

#include "sudo_gettext.h"	/* must be included before sudo_compat.h */

#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "sudo_debug.h"
#include "sudo_util.h"
#include "iolog.h"

static int timing_event_adj;

struct log_info *
parse_logfile(const char *logfile)
{
    FILE *fp;
    char *buf = NULL, *cp, *ep;
    const char *errstr;
    size_t bufsize = 0, cwdsize = 0, cmdsize = 0;
    struct log_info *li = NULL;
    debug_decl(parse_logfile, SUDO_DEBUG_UTIL)

    fp = fopen(logfile, "r");
    if (fp == NULL) {
	sudo_warn(U_("unable to open %s"), logfile);
	goto bad;
    }

    /*
     * ID file has three lines:
     *  1) a log info line
     *  2) cwd
     *  3) command with args
     */
    if ((li = calloc(1, sizeof(*li))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (getdelim(&buf, &bufsize, '\n', fp) == -1 ||
	getdelim(&li->cwd, &cwdsize, '\n', fp) == -1 ||
	getdelim(&li->cmd, &cmdsize, '\n', fp) == -1) {
	sudo_warn(U_("%s: invalid log file"), logfile);
	goto bad;
    }

    /* Strip the newline from the cwd and command. */
    li->cwd[strcspn(li->cwd, "\n")] = '\0';
    li->cmd[strcspn(li->cmd, "\n")] = '\0';

    /*
     * Crack the log line (rows and cols not present in old versions).
     *	timestamp:user:runas_user:runas_group:tty:rows:cols
     * XXX - probably better to use strtok and switch on the state.
     */
    buf[strcspn(buf, "\n")] = '\0';
    cp = buf;

    /* timestamp */
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: time stamp field is missing"), logfile);
	goto bad;
    }
    *ep = '\0';
    li->tstamp = sudo_strtonum(cp, 0, TIME_T_MAX, &errstr);
    if (errstr != NULL) {
	sudo_warn(U_("%s: time stamp %s: %s"), logfile, cp, errstr);
	goto bad;
    }

    /* user */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: user field is missing"), logfile);
	goto bad;
    }
    if ((li->user = strndup(cp, (size_t)(ep - cp))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* runas user */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: runas user field is missing"), logfile);
	goto bad;
    }
    if ((li->runas_user = strndup(cp, (size_t)(ep - cp))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* runas group */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: runas group field is missing"), logfile);
	goto bad;
    }
    if (cp != ep) {
	if ((li->runas_group = strndup(cp, (size_t)(ep - cp))) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    }

    /* tty, followed by optional rows + columns */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	/* just the tty */
	if ((li->tty = strdup(cp)) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    } else {
	/* tty followed by rows + columns */
	if ((li->tty = strndup(cp, (size_t)(ep - cp))) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	cp = ep + 1;
	/* need to NULL out separator to use sudo_strtonum() */
	/* XXX - use sudo_strtonumx */
	if ((ep = strchr(cp, ':')) != NULL) {
	    *ep = '\0';
	}
	li->rows = sudo_strtonum(cp, 1, INT_MAX, &errstr);
	if (errstr != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"%s: tty rows %s: %s", logfile, cp, errstr);
	}
	if (ep != NULL) {
	    cp = ep + 1;
	    li->cols = sudo_strtonum(cp, 1, INT_MAX, &errstr);
	    if (errstr != NULL) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "%s: tty cols %s: %s", logfile, cp, errstr);
	    }
	}
    }
    fclose(fp);
    free(buf);
    debug_return_ptr(li);

bad:
    if (fp != NULL)
	fclose(fp);
    free(buf);
    free_log_info(li);
    debug_return_ptr(NULL);
}

void
adjust_delay(struct timespec *delay, struct timespec *max_delay,
     double scale_factor)
{
    double seconds;
    debug_decl(adjust_delay, SUDO_DEBUG_UTIL)

    if (scale_factor != 1.0) {
	/* Order is important: we don't want to double the remainder. */
        seconds = (double)delay->tv_sec / scale_factor;
        delay->tv_sec = (time_t)seconds;
        delay->tv_nsec /= scale_factor;
        delay->tv_nsec += (seconds - delay->tv_sec) * 1000000000;
        while (delay->tv_nsec >= 1000000000) {
            delay->tv_sec++;
            delay->tv_nsec -= 1000000000;
        }
    }

    /* Clamp to max delay. */
    if (max_delay != NULL) {
	if (sudo_timespeccmp(delay, max_delay, >)) {
	    delay->tv_sec = max_delay->tv_sec;
	    delay->tv_nsec = max_delay->tv_nsec;
	}
    }

    debug_return;
}

/*
 * Parse the delay as seconds and nanoseconds: %lld.%09ld
 * Sudo used to write this as a double, but since timing data is logged
 * in the C locale this may not match the current locale.
 */
char *
parse_delay(const char *cp, struct timespec *delay, const char *decimal_point)
{
    char numbuf[(((sizeof(long long) * 8) + 2) / 3) + 2];
    const char *errstr, *ep;
    long long llval;
    size_t len;
    debug_decl(parse_delay, SUDO_DEBUG_UTIL)

    /* Parse seconds (whole number portion). */
    for (ep = cp; isdigit((unsigned char)*ep); ep++)
	continue;
    len = (size_t)(ep - cp);
    if (len >= sizeof(numbuf)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "%s: number of seconds is too large", cp);
	debug_return_ptr(NULL);
    }
    memcpy(numbuf, cp, len);
    numbuf[len] = '\0';
    delay->tv_sec = sudo_strtonum(numbuf, 0, TIME_T_MAX, &errstr);
    if (errstr != NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "%s: number of seconds is %s", numbuf, errstr);
	debug_return_ptr(NULL);
    }

    /* Radix may be in user's locale for sudo < 1.7.4 so accept that too. */
    if (*ep != '.' && *ep != *decimal_point) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid characters after seconds: %s", ep);
	debug_return_ptr(NULL);
    }
    cp = ep + 1;

    /* Parse fractional part, we may read more precision than we can store. */
    for (ep = cp; isdigit((unsigned char)*ep); ep++)
	continue;
    len = (size_t)(ep - cp);
    if (len >= sizeof(numbuf)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "%s: number of nanoseconds is too large", cp);
	debug_return_ptr(NULL);
    }
    memcpy(numbuf, cp, len);
    numbuf[len] = '\0';
    llval = sudo_strtonum(numbuf, 0, LLONG_MAX, &errstr);
    if (errstr != NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "%s: number of nanoseconds is %s", numbuf, errstr);
	debug_return_ptr(NULL);
    }

    /* Adjust fractional part to nanosecond precision. */
    if (len < 9) {
	/* Convert to nanosecond precision. */
	do {
	    llval *= 10;
	} while (++len < 9);
    } else if (len > 9) {
	/* Clamp to nanoseconds. */
	do {
	    llval /= 10;
	} while (--len > 9);
    }
    delay->tv_nsec = (long)llval;

    /* Advance to the next field. */
    while (isspace((unsigned char)*ep))
	ep++;

    debug_return_str((char *)ep);
}

/*
 * Parse a timing line, which is formatted as:
 *	IO_EVENT_TTYOUT sleep_time num_bytes
 *	IO_EVENT_WINSIZE sleep_time rows cols
 *	IO_EVENT_SUSPEND sleep_time signo
 * Where type is IO_EVENT_*, sleep_time is the number of seconds to sleep
 * before writing the data and num_bytes is the number of bytes to output.
 * Returns true on success and false on failure.
 */
bool
parse_timing(const char *buf, struct timespec *delay,
    struct timing_closure *timing)
{
    unsigned long ulval;
    char *cp, *ep;
    debug_decl(parse_timing, SUDO_DEBUG_UTIL)

    /* Clear fd. */
    timing->fd.v = NULL;

    /* Parse event type. */
    ulval = strtoul(buf, &ep, 10);
    if (ep == buf || !isspace((unsigned char) *ep))
	goto bad;
    if (ulval >= IO_EVENT_COUNT)
	goto bad;
    if (ulval == IO_EVENT_TTYOUT_1_8_7) {
	/* work around a bug in timing files generated by sudo 1.8.7 */
	timing_event_adj = 2;
    }
    timing->event = (int)ulval - timing_event_adj;
    for (cp = ep + 1; isspace((unsigned char) *cp); cp++)
	continue;

    /* Parse delay, returns the next field or NULL on error. */
    if ((cp = parse_delay(cp, delay, timing->decimal)) == NULL)
	goto bad;

    switch (timing->event) {
    case IO_EVENT_SUSPEND:
	/* Signal name (no leading SIG prefix) or number. */
	if (str2sig(cp, &timing->u.signo) == -1)
	    goto bad;
	break;
    case IO_EVENT_WINSIZE:
	ulval = strtoul(cp, &ep, 10);
	if (ep == cp || !isspace((unsigned char) *ep))
	    goto bad;
	if (ulval > INT_MAX)
	    goto bad;
	timing->u.winsize.rows = (int)ulval;
	for (cp = ep + 1; isspace((unsigned char) *cp); cp++)
	    continue;

	ulval = strtoul(cp, &ep, 10);
	if (ep == cp || *ep != '\0')
	    goto bad;
	if (ulval > INT_MAX)
	    goto bad;
	timing->u.winsize.cols = (int)ulval;
	break;
    default:
	errno = 0;
	ulval = strtoul(cp, &ep, 10);
	if (ep == cp || *ep != '\0')
	    goto bad;
	/* Note: assumes SIZE_MAX == ULONG_MAX */
	if (errno == ERANGE && ulval == ULONG_MAX)
	    goto bad;
	timing->u.nbytes = (size_t)ulval;
	break;
    }

    debug_return_bool(true);
bad:
    debug_return_bool(false);
}

void
free_log_info(struct log_info *li)
{
    if (li != NULL) {
	free(li->cwd);
	free(li->user);
	free(li->runas_user);
	free(li->runas_group);
	free(li->tty);
	free(li->cmd);
	free(li);
    }
}
