/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2016-2017 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <syslog.h>

#include "sudo_compat.h"

#ifndef HAVE_VSYSLOG
void
sudo_vsyslog(int pri, const char *fmt, va_list ap)
{
    int saved_errno = errno;
    char *cp, *ep, msgbuf[8192], new_fmt[2048];
    va_list ap2;
    size_t len;

    /* Rewrite fmt, replacing %m with an errno string. */
    for (cp = new_fmt, ep = new_fmt + sizeof(new_fmt); *fmt != '\0'; fmt++) {
	if (fmt[0] == '%' && fmt[1] == 'm') {
	    fmt++;
	    len = strlcpy(cp, strerror(saved_errno), (ep - cp));
	    if (len >= (size_t)(ep - cp))
		len = (size_t)(ep - cp) - 1;
	    cp += len;
	} else {
	    if (fmt[0] == '%' && fmt[1] == '%') {
		    fmt++;
		    if (cp < ep - 1)
			*cp++ = '%';
	    }
	    if (cp < ep - 1)
		*cp++ = *fmt;
	}
    }
    *cp = '\0';

    /* Format message and log it, using a static buffer if possible. */
    va_copy(ap2, ap);
    len = (size_t)vsnprintf(msgbuf, sizeof(msgbuf), new_fmt, ap2);
    va_end(ap2);
    if (len < sizeof(msgbuf)) {
	syslog(pri, "%s", msgbuf);
    } else {
	/* Too big for static buffer? */
	char *buf;
	if (vasprintf(&buf, new_fmt, ap) != -1) {
	    syslog(pri, "%s", buf);
	    free(buf);
	}
    }
}
#endif /* HAVE_VSYSLOG */
