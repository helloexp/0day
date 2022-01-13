/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2019 Todd C. Miller <Todd.Miller@sudo.ws>
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

#ifndef HAVE_GETDELIM

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

ssize_t
sudo_getdelim(char **buf, size_t *bufsize, int delim, FILE *fp)
{
    char *cp, *ep;
    int ch;

    if (*buf == NULL || *bufsize == 0) {
	char *tmp = realloc(*buf, LINE_MAX);
	if (tmp == NULL)
	    return -1;
	*buf = tmp;
	*bufsize = LINE_MAX;
    }
    cp = *buf;
    ep = cp + *bufsize;

    do {
	if (cp + 1 >= ep) {
	    char *tmp = reallocarray(*buf, *bufsize, 2);
	    if (tmp == NULL)
		goto bad;
	    cp = tmp + (cp - *buf);
	    *buf = tmp;
	    *bufsize *= 2;
	}
	if ((ch = getc(fp)) == EOF) {
	    if (feof(fp))
		break;
	    goto bad;
	}
	*cp++ = ch;
    } while (ch != delim);

    /* getdelim(3) should never return a length of 0. */
    if (cp != *buf) {
	*cp = '\0';
	return (ssize_t)(cp - *buf);
    }
bad:
    /* Error, push back what was read if possible. */
    while (cp > *buf) {
	if (ungetc(*cp--, fp) == EOF)
	    break;
    }
    return -1;
}
#endif /* HAVE_GETDELIM */
