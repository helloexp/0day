/*
 * Copyright (c) 2009-2010, 2012-2015 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <config.h>

#ifndef HAVE_GETLINE

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <limits.h>

#include "sudo_compat.h"

#ifdef HAVE_FGETLN
ssize_t
sudo_getline(char **bufp, size_t *bufsizep, FILE *fp)
{
    char *buf, *cp;
    size_t bufsize;
    size_t len;

    buf = fgetln(fp, &len);
    if (buf) {
	bufsize = *bufp ? *bufsizep : 0;
	if (bufsize == 0 || bufsize - 1 < len) {
	    bufsize = len + 1;
	    cp = realloc(*bufp, bufsize);
	    if (cp == NULL)
		return -1;
	    *bufp = cp;
	    *bufsizep = bufsize;
	}
	memcpy(*bufp, buf, len);
	(*bufp)[len] = '\0';
    }
    return buf ? len : -1;
}
#else
ssize_t
sudo_getline(char **bufp, size_t *bufsizep, FILE *fp)
{
    char *buf, *cp;
    size_t bufsize;
    ssize_t len = 0;

    buf = *bufp;
    bufsize = *bufsizep;
    if (buf == NULL || bufsize == 0) {
	bufsize = LINE_MAX;
	cp = realloc(buf, bufsize);
	if (cp == NULL)
	    return -1;
	buf = cp;
    }

    for (;;) {
	if (fgets(buf + len, bufsize - len, fp) == NULL) {
	    len = -1;
	    break;
	}
	len = strlen(buf);
	if (!len || buf[len - 1] == '\n' || feof(fp))
	    break;
	cp = reallocarray(buf, bufsize, 2);
	if (cp == NULL)
	    return -1;
	bufsize *= 2;
	buf = cp;
    }
    *bufp = buf;
    *bufsizep = bufsize;
    return len;
}
#endif /* HAVE_FGETLN */
#endif /* HAVE_GETLINE */
