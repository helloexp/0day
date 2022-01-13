/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2010-2019 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>

#include "sudoers.h"
#include "sudo_dso.h"

#if defined(HAVE_DLOPEN) || defined(HAVE_SHL_LOAD)

static void *group_handle;
static struct sudoers_group_plugin *group_plugin;
const char *path_plugin_dir = _PATH_SUDO_PLUGIN_DIR;

/*
 * Load the specified plugin and run its init function.
 * Returns -1 if unable to open the plugin, else it returns
 * the value from the plugin's init function.
 */
int
group_plugin_load(char *plugin_info)
{
    struct stat sb;
    char *args, path[PATH_MAX];
    char **argv = NULL;
    int len, rc = -1;
    debug_decl(group_plugin_load, SUDOERS_DEBUG_UTIL)

    /*
     * Fill in .so path and split out args (if any).
     */
    if ((args = strpbrk(plugin_info, " \t")) != NULL) {
	len = snprintf(path, sizeof(path), "%s%.*s",
	    (*plugin_info != '/') ? path_plugin_dir : "",
	    (int)(args - plugin_info), plugin_info);
	args++;
    } else {
	len = snprintf(path, sizeof(path), "%s%s",
	    (*plugin_info != '/') ? path_plugin_dir : "", plugin_info);
    }
    if (len < 0 || len >= ssizeof(path)) {
	errno = ENAMETOOLONG;
	sudo_warn("%s%s",
	    (*plugin_info != '/') ? path_plugin_dir : "", plugin_info);
	goto done;
    }

    /* Sanity check plugin path. */
    if (stat(path, &sb) != 0) {
	sudo_warn("%s", path);
	goto done;
    }
    if (sb.st_uid != ROOT_UID) {
	sudo_warnx(U_("%s must be owned by uid %d"), path, ROOT_UID);
	goto done;
    }
    if ((sb.st_mode & (S_IWGRP|S_IWOTH)) != 0) {
	sudo_warnx(U_("%s must only be writable by owner"), path);
	goto done;
    }

    /* Open plugin and map in symbol. */
    group_handle = sudo_dso_load(path, SUDO_DSO_LAZY|SUDO_DSO_GLOBAL);
    if (!group_handle) {
	const char *errstr = sudo_dso_strerror();
	sudo_warnx(U_("unable to load %s: %s"), path,
	    errstr ? errstr : "unknown error");
	goto done;
    }
    group_plugin = sudo_dso_findsym(group_handle, "group_plugin");
    if (group_plugin == NULL) {
	sudo_warnx(U_("unable to find symbol \"group_plugin\" in %s"), path);
	goto done;
    }

    if (SUDO_API_VERSION_GET_MAJOR(group_plugin->version) != GROUP_API_VERSION_MAJOR) {
	sudo_warnx(U_("%s: incompatible group plugin major version %d, expected %d"),
	    path, SUDO_API_VERSION_GET_MAJOR(group_plugin->version),
	    GROUP_API_VERSION_MAJOR);
	goto done;
    }

    /*
     * Split args into a vector if specified.
     */
    if (args != NULL) {
	int ac = 0;
	bool wasblank = true;
	char *cp, *last;

        for (cp = args; *cp != '\0'; cp++) {
            if (isblank((unsigned char)*cp)) {
                wasblank = true;
            } else if (wasblank) {
                wasblank = false;
                ac++;
            }
        }
	if (ac != 0) {
	    argv = reallocarray(NULL, ac + 1, sizeof(char *));
	    if (argv == NULL) {
		sudo_warnx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
		goto done;
	    }
	    ac = 0;
	    cp = strtok_r(args, " \t", &last);
	    while (cp != NULL) {
		argv[ac++] = cp;
		cp = strtok_r(NULL, " \t", &last);
	    }
	    argv[ac] = NULL;
	}
    }

    rc = (group_plugin->init)(GROUP_API_VERSION, sudo_printf, argv);

done:
    free(argv);

    if (rc != true) {
	if (group_handle != NULL) {
	    sudo_dso_unload(group_handle);
	    group_handle = NULL;
	    group_plugin = NULL;
	}
    }

    debug_return_int(rc);
}

void
group_plugin_unload(void)
{
    debug_decl(group_plugin_unload, SUDOERS_DEBUG_UTIL)

    if (group_plugin != NULL) {
	(group_plugin->cleanup)();
	group_plugin = NULL;
    }
    if (group_handle != NULL) {
	sudo_dso_unload(group_handle);
	group_handle = NULL;
    }
    debug_return;
}

int
group_plugin_query(const char *user, const char *group,
    const struct passwd *pwd)
{
    debug_decl(group_plugin_query, SUDOERS_DEBUG_UTIL)

    if (group_plugin == NULL)
	debug_return_int(false);
    debug_return_int((group_plugin->query)(user, group, pwd));
}

#else /* !HAVE_DLOPEN && !HAVE_SHL_LOAD */

/*
 * No loadable shared object support.
 */

int
group_plugin_load(char *plugin_info)
{
    debug_decl(group_plugin_load, SUDOERS_DEBUG_UTIL)
    debug_return_int(false);
}

void
group_plugin_unload(void)
{
    debug_decl(group_plugin_unload, SUDOERS_DEBUG_UTIL)
    debug_return;
}

int
group_plugin_query(const char *user, const char *group,
    const struct passwd *pwd)
{
    debug_decl(group_plugin_query, SUDOERS_DEBUG_UTIL)
    debug_return_int(false);
}

#endif /* HAVE_DLOPEN || HAVE_SHL_LOAD */

/*
 * Group plugin sudoers callback.
 */
bool
cb_group_plugin(const union sudo_defs_val *sd_un)
{
    bool rc = true;
    debug_decl(cb_group_plugin, SUDOERS_DEBUG_PLUGIN)

    /* Unload any existing group plugin before loading a new one. */
    group_plugin_unload();
    if (sd_un->str != NULL)
	rc = group_plugin_load(sd_un->str);
    debug_return_bool(rc);
}
