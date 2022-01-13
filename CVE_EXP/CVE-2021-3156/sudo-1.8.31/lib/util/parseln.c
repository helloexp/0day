/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2007, 2013-2016 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRING_H */
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif

#include "sudo_compat.h"
#include "sudo_util.h"
#include "sudo_debug.h"

/*
 * Read a line of input, honoring line continuation chars.
 * Remove comments and strip off leading and trailing spaces.
 * Returns the line length and updates the buf and bufsize pointers.
 * XXX - just use a struct w/ state, including getdelim buffer?
 *       could also make comment char and line continuation configurable
 */
ssize_t
sudo_parseln_v2(char **bufp, size_t *bufsizep, unsigned int *lineno, FILE *fp, int flags)
{
    size_t linesize = 0, total = 0;
    ssize_t len;
    char *cp, *line = NULL;
    bool continued, comment;
    debug_decl(sudo_parseln, SUDO_DEBUG_UTIL)

    do {
	comment = false;
	continued = false;
	len = getdelim(&line, &linesize, '\n', fp);
	if (len == -1)
	    break;
	if (lineno != NULL)
	    (*lineno)++;

	/* Remove trailing newline(s) if present. */
	while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
	    line[--len] = '\0';

	/* Remove comments or check for line continuation (but not both) */
	if ((cp = strchr(line, '#')) != NULL) {
	    if (cp == line || !ISSET(flags, PARSELN_COMM_BOL)) {
		*cp = '\0';
		len = (ssize_t)(cp - line);
		comment = true;
	    }
	}
	if (!comment && !ISSET(flags, PARSELN_CONT_IGN)) {
	    if (len > 0 && line[len - 1] == '\\' && (len == 1 || line[len - 2] != '\\')) {
		line[--len] = '\0';
		continued = true;
	    }
	}

	/* Trim leading and trailing whitespace */
	if (!continued) {
	    while (len > 0 && isblank((unsigned char)line[len - 1]))
		line[--len] = '\0';
	}
	for (cp = line; isblank((unsigned char)*cp); cp++)
	    len--;

	if (*bufp == NULL || total + len >= *bufsizep) {
	    void *tmp;
	    size_t size = total + len + 1;

	    if (size < 64) {
		size = 64;
	    } else if (size <= 0x80000000) {
		/* Round up to next highest power of two. */
		size--;
		size |= size >> 1;
		size |= size >> 2;
		size |= size >> 4;
		size |= size >> 8;
		size |= size >> 16;
		size++;
	    }
	    if ((tmp = realloc(*bufp, size)) == NULL) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "unable to allocate memory");
		len = -1;
		total = 0;
		break;
	    }
	    *bufp = tmp;
	    *bufsizep = size;
	}
	memcpy(*bufp + total, cp, len + 1);
	total += len;
    } while (continued);
    free(line);
    if (len == -1 && total == 0)
	debug_return_ssize_t(-1);
    debug_return_ssize_t(total);
}

ssize_t
sudo_parseln_v1(char **bufp, size_t *bufsizep, unsigned int *lineno, FILE *fp)
{
    return sudo_parseln_v2(bufp, bufsizep, lineno, fp, 0);
}
