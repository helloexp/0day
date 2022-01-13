/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2017 Todd C. Miller <Todd.Miller@sudo.ws>
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
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "sudoers.h"

/*
 * Create any parent directories needed by path (but not path itself).
 * Note that path is modified but is restored before it returns.
 */
bool
sudo_mkdir_parents(char *path, uid_t uid, gid_t gid, mode_t mode, bool quiet)
{
    struct stat sb;
    char *slash = path;
    debug_decl(sudo_mkdir_parents, SUDOERS_DEBUG_UTIL)

    /* cppcheck-suppress nullPointerRedundantCheck */
    while ((slash = strchr(slash + 1, '/')) != NULL) {
	*slash = '\0';
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	    "mkdir %s, mode 0%o, uid %d, gid %d", path, (unsigned int)mode,
	    (int)uid, (int)gid);
	if (mkdir(path, mode) == 0) {
	    if (uid != (uid_t)-1 && gid != (gid_t)-1) {
		if (chown(path, uid, gid) != 0) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
			"%s: unable to chown %d:%d %s", __func__,
			(int)uid, (int)gid, path);
		}
	    }
	} else {
	    if (errno != EEXIST) {
		if (!quiet)
		    sudo_warn(U_("unable to mkdir %s"), path);
		goto bad;
	    }
	    /* Already exists, make sure it is a directory. */
	    if (stat(path, &sb) != 0) {
		if (!quiet)
		    sudo_warn(U_("unable to stat %s"), path);
		goto bad;
	    }
	    if (!S_ISDIR(sb.st_mode)) {
		if (!quiet)
		    sudo_warnx(U_("%s exists but is not a directory (0%o)"),
			path, (unsigned int) sb.st_mode);
		goto bad;
	    }
	}
	*slash = '/';
    }

    debug_return_bool(true);
bad:
    /* We must restore the path before we return. */
    *slash = '/';
    debug_return_bool(false);
}
