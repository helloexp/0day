/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2004-2005, 2010-2015, 2017-2018
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
 */

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <sys/types.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

#define DEFAULT_TEXT_DOMAIN	"sudo"
#include "sudo_gettext.h"	/* must be included before sudo_compat.h */

#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "sudo_queue.h"
#include "sudo_util.h"
#include "sudo_plugin.h"

#ifndef HAVE_GETADDRINFO
# include "compat/getaddrinfo.h"
#endif

struct sudo_fatal_callback {
    SLIST_ENTRY(sudo_fatal_callback) entries;
    void (*func)(void);
};
SLIST_HEAD(sudo_fatal_callback_list, sudo_fatal_callback);

static struct sudo_fatal_callback_list callbacks = SLIST_HEAD_INITIALIZER(&callbacks);
static sudo_conv_t sudo_warn_conversation;
static bool (*sudo_warn_setlocale)(bool, int *);
static bool (*sudo_warn_setlocale_prev)(bool, int *);

static void warning(const char *errstr, const char *fmt, va_list ap);

static void
do_cleanup(void)
{
    struct sudo_fatal_callback *cb;

    /* Run callbacks, removing them from the list as we go. */
    while ((cb = SLIST_FIRST(&callbacks)) != NULL) {
	SLIST_REMOVE_HEAD(&callbacks, entries);
	cb->func();
	free(cb);
    }
}

void
sudo_fatal_nodebug_v1(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    warning(strerror(errno), fmt, ap);
    va_end(ap);
    do_cleanup();
    exit(EXIT_FAILURE);
}

void
sudo_fatalx_nodebug_v1(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    warning(NULL, fmt, ap);
    va_end(ap);
    do_cleanup();
    exit(EXIT_FAILURE);
}

void
sudo_vfatal_nodebug_v1(const char *fmt, va_list ap)
{
    warning(strerror(errno), fmt, ap);
    do_cleanup();
    exit(EXIT_FAILURE);
}

void
sudo_vfatalx_nodebug_v1(const char *fmt, va_list ap)
{
    warning(NULL, fmt, ap);
    do_cleanup();
    exit(EXIT_FAILURE);
}

void
sudo_warn_nodebug_v1(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    warning(strerror(errno), fmt, ap);
    va_end(ap);
}

void
sudo_warnx_nodebug_v1(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    warning(NULL, fmt, ap);
    va_end(ap);
}

void
sudo_vwarn_nodebug_v1(const char *fmt, va_list ap)
{
    warning(strerror(errno), fmt, ap);
}

void
sudo_vwarnx_nodebug_v1(const char *fmt, va_list ap)
{
    warning(NULL, fmt, ap);
}

void
sudo_gai_fatal_nodebug_v1(int errnum, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    warning(gai_strerror(errnum), fmt, ap);
    va_end(ap);
    do_cleanup();
    exit(EXIT_FAILURE);
}

void
sudo_gai_vfatal_nodebug_v1(int errnum, const char *fmt, va_list ap)
{
    warning(gai_strerror(errnum), fmt, ap);
    do_cleanup();
    exit(EXIT_FAILURE);
}

void
sudo_gai_warn_nodebug_v1(int errnum, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    warning(gai_strerror(errnum), fmt, ap);
    va_end(ap);
}

void
sudo_gai_vwarn_nodebug_v1(int errnum, const char *fmt, va_list ap)
{
    warning(gai_strerror(errnum), fmt, ap);
}

static void
warning(const char *errstr, const char *fmt, va_list ap)
{
    int cookie;

    /* Set user locale if setter was specified. */
    if (sudo_warn_setlocale != NULL)
	sudo_warn_setlocale(false, &cookie);

    if (sudo_warn_conversation != NULL) {
	struct sudo_conv_message msgs[6];
	char static_buf[1024], *buf = static_buf;
	int nmsgs = 0;

	/* Use conversation function. */
        msgs[nmsgs].msg_type = SUDO_CONV_ERROR_MSG;
	msgs[nmsgs++].msg = getprogname();
        if (fmt != NULL) {
		va_list ap2;
		int buflen;

		/* Use static buffer if possible, else dynamic. */
		va_copy(ap2, ap);
		buflen = vsnprintf(static_buf, sizeof(static_buf), fmt, ap2);
		va_end(ap2);
		if (buflen >= ssizeof(static_buf)) {
		    buf = malloc(++buflen);
		    if (buf != NULL)
			(void)vsnprintf(buf, buflen, fmt, ap);
		    else
			buf = static_buf;
		}
		msgs[nmsgs].msg_type = SUDO_CONV_ERROR_MSG;
		msgs[nmsgs++].msg = ": ";
		msgs[nmsgs].msg_type = SUDO_CONV_ERROR_MSG;
		msgs[nmsgs++].msg = buf;
        }
        if (errstr != NULL) {
	    msgs[nmsgs].msg_type = SUDO_CONV_ERROR_MSG;
	    msgs[nmsgs++].msg = ": ";
	    msgs[nmsgs].msg_type = SUDO_CONV_ERROR_MSG;
	    msgs[nmsgs++].msg = errstr;
        }
	msgs[nmsgs].msg_type = SUDO_CONV_ERROR_MSG;
	msgs[nmsgs++].msg = "\n";
	sudo_warn_conversation(nmsgs, msgs, NULL, NULL);
	if (buf != static_buf)
	    free(buf);
    } else {
	/* Write to the standard error. */
        fputs(getprogname(), stderr);
        if (fmt != NULL) {
                fputs(": ", stderr);
                vfprintf(stderr, fmt, ap);
        }
        if (errstr != NULL) {
            fputs(": ", stderr);
            fputs(errstr, stderr);
        }
        putc('\n', stderr);
    }

    /* Restore old locale as needed. */
    if (sudo_warn_setlocale != NULL)
	sudo_warn_setlocale(true, &cookie);
}

/*
 * Register a callback to be run when sudo_fatal()/sudo_fatalx() is called.
 */
int
sudo_fatal_callback_register_v1(sudo_fatal_callback_t func)
{
    struct sudo_fatal_callback *cb;

    /* Do not register the same callback twice.  */
    SLIST_FOREACH(cb, &callbacks, entries) {
	if (func == cb->func)
	    return -1;		/* dupe! */
    }

    /* Allocate and insert new callback. */
    cb = malloc(sizeof(*cb));
    if (cb == NULL)
	return -1;
    cb->func = func;
    SLIST_INSERT_HEAD(&callbacks, cb, entries);

    return 0;
}

/*
 * Deregister a sudo_fatal()/sudo_fatalx() callback.
 */
int
sudo_fatal_callback_deregister_v1(sudo_fatal_callback_t func)
{
    struct sudo_fatal_callback *cb, **prev;

    /* Search for callback and remove if found, dupes are not allowed. */
    SLIST_FOREACH_PREVPTR(cb, prev, &callbacks, entries) {
	if (cb->func == func) {
	    if (cb == SLIST_FIRST(&callbacks))
		SLIST_REMOVE_HEAD(&callbacks, entries);
	    else
		SLIST_REMOVE_AFTER(*prev, entries);
	    free(cb);
	    return 0;
	}
    }

    return -1;
}

/*
 * Set the conversation function to use for output insteaf of the
 * standard error.  If conv is NULL, switch back to standard error.
 */
void
sudo_warn_set_conversation_v1(sudo_conv_t conv)
{
    sudo_warn_conversation = conv;
}

/*
 * Set the locale function so the plugin can use a non-default
 * locale for user warnings.
 */
void
sudo_warn_set_locale_func_v1(bool (*func)(bool, int *))
{
    sudo_warn_setlocale_prev = sudo_warn_setlocale;
    sudo_warn_setlocale = func;
}

#ifdef HAVE_LIBINTL_H
char *
sudo_warn_gettext_v1(const char *domainname, const char *msgid)
{
    int cookie;
    char *msg;

    /* Set user locale if setter was specified. */
    if (sudo_warn_setlocale != NULL)
	sudo_warn_setlocale(false, &cookie);

    msg = dgettext(domainname, msgid);

    /* Restore old locale as needed. */
    if (sudo_warn_setlocale != NULL)
	sudo_warn_setlocale(true, &cookie);

    return msg;
}
#endif /* HAVE_LIBINTL_H */
