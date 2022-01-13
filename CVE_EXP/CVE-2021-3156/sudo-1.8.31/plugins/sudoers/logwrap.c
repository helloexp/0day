/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2011, 2014-2016 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include "sudoers.h"

int
writeln_wrap(FILE *fp, char *line, size_t linelen, size_t maxlen)
{
    char *indent = "";
    char *beg = line;
    char *end;
    int len, outlen = 0;
    debug_decl(writeln_wrap, SUDOERS_DEBUG_LOGGING)

    /*
     * Print out line with word wrap around maxlen characters.
     */
    while (linelen > maxlen) {
	end = beg + maxlen;
	while (end != beg && *end != ' ')
	    end--;
	if (beg == end) {
	    /* Unable to find word break within maxlen, look beyond. */
	    end = strchr(beg + maxlen, ' ');
	    if (end == NULL)
		break;	/* no word break */
	}
	len = fprintf(fp, "%s%.*s\n", indent, (int)(end - beg), beg);
	if (len < 0)
	    debug_return_int(-1);
	outlen += len;
	while (*end == ' ')
	    end++;
	linelen -= (end - beg);
	beg = end;
	if (indent[0] == '\0') {
	    indent = LOG_INDENT;
	    maxlen -= sizeof(LOG_INDENT) - 1;
	}
    }
    /* Print remainder, if any. */
    if (linelen) {
	len = fprintf(fp, "%s%s\n", indent, beg);
	if (len < 0)
	    debug_return_int(-1);
	outlen += len;
    }

    debug_return_int(outlen);
}
