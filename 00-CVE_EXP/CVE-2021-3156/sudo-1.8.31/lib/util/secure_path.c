/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2012, 2014-2016 Todd C. Miller <Todd.Miller@sudo.ws>
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
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <errno.h>

#include "sudo_compat.h"
#include "sudo_util.h"
#include "sudo_debug.h"

/*
 * Verify that path is the right type and not writable by other users.
 */
static int
sudo_secure_path(const char *path, unsigned int type, uid_t uid, gid_t gid, struct stat *sbp)
{
    struct stat sb;
    int ret = SUDO_PATH_MISSING;
    debug_decl(sudo_secure_path, SUDO_DEBUG_UTIL)

    if (path != NULL && stat(path, &sb) == 0) {
	if ((sb.st_mode & _S_IFMT) != type) {
	    ret = SUDO_PATH_BAD_TYPE;
	} else if (uid != (uid_t)-1 && sb.st_uid != uid) {
	    ret = SUDO_PATH_WRONG_OWNER;
	} else if (sb.st_mode & S_IWOTH) {
	    ret = SUDO_PATH_WORLD_WRITABLE;
	} else if (ISSET(sb.st_mode, S_IWGRP) &&
	    (gid == (gid_t)-1 || sb.st_gid != gid)) {
	    ret = SUDO_PATH_GROUP_WRITABLE;
	} else {
	    ret = SUDO_PATH_SECURE;
	}
	if (sbp)
	    (void) memcpy(sbp, &sb, sizeof(struct stat));
    }

    debug_return_int(ret);
}

/*
 * Verify that path is a regular file and not writable by other users.
 */
int
sudo_secure_file_v1(const char *path, uid_t uid, gid_t gid, struct stat *sbp)
{
    return sudo_secure_path(path, _S_IFREG, uid, gid, sbp);
}

/*
 * Verify that path is a directory and not writable by other users.
 */
int
sudo_secure_dir_v1(const char *path, uid_t uid, gid_t gid, struct stat *sbp)
{
    return sudo_secure_path(path, _S_IFDIR, uid, gid, sbp);
}
