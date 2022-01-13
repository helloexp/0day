/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2013-2015 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define DEFAULT_TEXT_DOMAIN	"sudo"
#include "sudo_gettext.h"	/* must be included before sudo_compat.h */

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_util.h"

/*
 * Parse an octal file mode in the range [0, 0777].
 * On success, returns the parsed mode and clears errstr.
 * On error, returns 0 and sets errstr.
 */
int
sudo_strtomode_v1(const char *cp, const char **errstr)
{
    char *ep;
    long lval;
    debug_decl(sudo_strtomode, SUDO_DEBUG_UTIL)

    errno = 0;
    lval = strtol(cp, &ep, 8);
    if (ep == cp || *ep != '\0') {
	if (errstr != NULL)
	    *errstr = N_("invalid value");
	errno = EINVAL;
	debug_return_int(0);
    }
    if (lval < 0 || lval > ACCESSPERMS) {
	if (errstr != NULL)
	    *errstr = lval < 0 ? N_("value too small") : N_("value too large");
	errno = ERANGE;
	debug_return_int(0);
    }
    if (errstr != NULL)
	*errstr = NULL;
    debug_return_int((int)lval);
}
