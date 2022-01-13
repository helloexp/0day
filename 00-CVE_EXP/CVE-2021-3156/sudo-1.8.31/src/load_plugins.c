/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2018 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include "sudo.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"
#include "sudo_dso.h"

/* We always use the same name for the sudoers plugin, regardless of the OS */
#define SUDOERS_PLUGIN	"sudoers.so"

#ifdef ENABLE_SUDO_PLUGIN_API
static int
sudo_stat_plugin(struct plugin_info *info, char *fullpath,
    size_t pathsize, struct stat *sb)
{
    int status = -1;
    debug_decl(sudo_stat_plugin, SUDO_DEBUG_PLUGIN)

    if (info->path[0] == '/') {
	if (strlcpy(fullpath, info->path, pathsize) >= pathsize) {
	    sudo_warnx(U_("error in %s, line %d while loading plugin \"%s\""),
		_PATH_SUDO_CONF, info->lineno, info->symbol_name);
	    sudo_warnx(U_("%s: %s"), info->path, strerror(ENAMETOOLONG));
	    goto done;
	}
	status = stat(fullpath, sb);
    } else {
	int len;

#ifdef STATIC_SUDOERS_PLUGIN
	/* Check static symbols. */
	if (strcmp(info->path, SUDOERS_PLUGIN) == 0) {
	    if (strlcpy(fullpath, info->path, pathsize) >= pathsize) {
		sudo_warnx(U_("error in %s, line %d while loading plugin \"%s\""),
		    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
		sudo_warnx(U_("%s: %s"), info->path, strerror(ENAMETOOLONG));
		goto done;
	    }
	    /* Plugin is static, fake up struct stat. */
	    memset(sb, 0, sizeof(*sb));
	    sb->st_uid = ROOT_UID;
	    sb->st_mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	    status = 0;
	    goto done;
	}
#endif /* STATIC_SUDOERS_PLUGIN */

	if (sudo_conf_plugin_dir_path() == NULL) {
	    errno = ENOENT;
	    goto done;
	}

	len = snprintf(fullpath, pathsize, "%s%s", sudo_conf_plugin_dir_path(),
	    info->path);
	if (len < 0 || (size_t)len >= pathsize) {
	    sudo_warnx(U_("error in %s, line %d while loading plugin \"%s\""),
		_PATH_SUDO_CONF, info->lineno, info->symbol_name);
	    sudo_warnx(U_("%s%s: %s"), sudo_conf_plugin_dir_path(), info->path,
		strerror(ENAMETOOLONG));
	    goto done;
	}
	/* Try parent dir for compatibility with old plugindir default. */
	if ((status = stat(fullpath, sb)) != 0) {
	    char *cp = strrchr(fullpath, '/');
	    if (cp > fullpath + 4 && cp[-5] == '/' && cp[-4] == 's' &&
		cp[-3] == 'u' && cp[-2] == 'd' && cp[-1] == 'o') {
		int serrno = errno;
		strlcpy(cp - 4, info->path, pathsize - (cp - 4 - fullpath));
		if ((status = stat(fullpath, sb)) != 0)
		    errno = serrno;
	    }
	}
    }
done:
    debug_return_int(status);
}

static bool
sudo_check_plugin(struct plugin_info *info, char *fullpath, size_t pathsize)
{
    struct stat sb;
    bool ret = false;
    debug_decl(sudo_check_plugin, SUDO_DEBUG_PLUGIN)

    if (sudo_stat_plugin(info, fullpath, pathsize, &sb) != 0) {
	sudo_warnx(U_("error in %s, line %d while loading plugin \"%s\""),
	    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
	if (info->path[0] == '/') {
	    sudo_warn("%s", info->path);
	} else {
	    sudo_warn("%s%s",
		sudo_conf_plugin_dir_path() ? sudo_conf_plugin_dir_path() : "",
		info->path);
	}
	goto done;
    }
    if (sb.st_uid != ROOT_UID) {
	sudo_warnx(U_("error in %s, line %d while loading plugin \"%s\""),
	    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
	sudo_warnx(U_("%s must be owned by uid %d"), fullpath, ROOT_UID);
	goto done;
    }
    if ((sb.st_mode & (S_IWGRP|S_IWOTH)) != 0) {
	sudo_warnx(U_("error in %s, line %d while loading plugin \"%s\""),
	    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
	sudo_warnx(U_("%s must be only be writable by owner"), fullpath);
	goto done;
    }
    ret = true;

done:
    debug_return_bool(ret);
}
#else
static bool
sudo_check_plugin(struct plugin_info *info, char *fullpath, size_t pathsize)
{
    debug_decl(sudo_check_plugin, SUDO_DEBUG_PLUGIN)
    (void)strlcpy(fullpath, info->path, pathsize);
    debug_return_bool(true);
}
#endif /* ENABLE_SUDO_PLUGIN_API */

/*
 * Load the plugin specified by "info".
 */
static bool
sudo_load_plugin(struct plugin_container *policy_plugin,
    struct plugin_container_list *io_plugins, struct plugin_info *info)
{
    struct plugin_container *container = NULL;
    struct generic_plugin *plugin;
    char path[PATH_MAX];
    void *handle = NULL;
    debug_decl(sudo_load_plugin, SUDO_DEBUG_PLUGIN)

    /* Sanity check plugin and fill in path */
    if (!sudo_check_plugin(info, path, sizeof(path)))
	goto bad;

    /* Open plugin and map in symbol */
    handle = sudo_dso_load(path, SUDO_DSO_LAZY|SUDO_DSO_GLOBAL);
    if (!handle) {
	const char *errstr = sudo_dso_strerror();
	sudo_warnx(U_("error in %s, line %d while loading plugin \"%s\""),
	    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
	sudo_warnx(U_("unable to load %s: %s"), path,
	    errstr ? errstr : "unknown error");
	goto bad;
    }
    plugin = sudo_dso_findsym(handle, info->symbol_name);
    if (!plugin) {
	sudo_warnx(U_("error in %s, line %d while loading plugin \"%s\""),
	    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
	sudo_warnx(U_("unable to find symbol \"%s\" in %s"), info->symbol_name, path);
	goto bad;
    }

    if (plugin->type != SUDO_POLICY_PLUGIN && plugin->type != SUDO_IO_PLUGIN) {
	sudo_warnx(U_("error in %s, line %d while loading plugin \"%s\""),
	    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
	sudo_warnx(U_("unknown policy type %d found in %s"), plugin->type, path);
	goto bad;
    }
    if (SUDO_API_VERSION_GET_MAJOR(plugin->version) != SUDO_API_VERSION_MAJOR) {
	sudo_warnx(U_("error in %s, line %d while loading plugin \"%s\""),
	    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
	sudo_warnx(U_("incompatible plugin major version %d (expected %d) found in %s"),
	    SUDO_API_VERSION_GET_MAJOR(plugin->version),
	    SUDO_API_VERSION_MAJOR, path);
	goto bad;
    }
    if (plugin->type == SUDO_POLICY_PLUGIN) {
	if (policy_plugin->handle != NULL) {
	    /* Ignore duplicate entries. */
	    if (strcmp(policy_plugin->name, info->symbol_name) != 0) {
		sudo_warnx(U_("ignoring policy plugin \"%s\" in %s, line %d"),
		    info->symbol_name, _PATH_SUDO_CONF, info->lineno);
		sudo_warnx(U_("only a single policy plugin may be specified"));
		goto bad;
	    }
	    sudo_warnx(U_("ignoring duplicate policy plugin \"%s\" in %s, line %d"),
		info->symbol_name, _PATH_SUDO_CONF, info->lineno);
	    goto bad;
	}
	policy_plugin->handle = handle;
	policy_plugin->path = strdup(path);
	if (policy_plugin->path == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto bad;
	}
	policy_plugin->name = info->symbol_name;
	policy_plugin->options = info->options;
	policy_plugin->debug_instance = SUDO_DEBUG_INSTANCE_INITIALIZER;
	policy_plugin->u.generic = plugin;
	policy_plugin->debug_files = sudo_conf_debug_files(path);
    } else if (plugin->type == SUDO_IO_PLUGIN) {
	/* Check for duplicate entries. */
	TAILQ_FOREACH(container, io_plugins, entries) {
	    if (strcmp(container->name, info->symbol_name) == 0) {
		sudo_warnx(U_("ignoring duplicate I/O plugin \"%s\" in %s, line %d"),
		    info->symbol_name, _PATH_SUDO_CONF, info->lineno);
		sudo_dso_unload(handle);
		handle = NULL;
		break;
	    }
	}
	container = calloc(1, sizeof(*container));
	if (container == NULL || (container->path = strdup(path)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto bad;
	}
	container->handle = handle;
	container->name = info->symbol_name;
	container->options = info->options;
	container->debug_instance = SUDO_DEBUG_INSTANCE_INITIALIZER;
	container->u.generic = plugin;
	container->debug_files = sudo_conf_debug_files(path);
	TAILQ_INSERT_TAIL(io_plugins, container, entries);
    }

    /* Zero out info strings that we now own (see above). */
    info->symbol_name = NULL;
    info->options = NULL;

    debug_return_bool(true);
bad:
    free(container);
    if (handle != NULL)
	sudo_dso_unload(handle);
    debug_return_bool(false);
}

static void
free_plugin_info(struct plugin_info *info)
{
    free(info->path);
    free(info->symbol_name);
    if (info->options != NULL) {
	int i = 0;
	while (info->options[i] != NULL)
	    free(info->options[i++]);
	free(info->options);
    }
    free(info);
}

/*
 * Load the plugins listed in sudo.conf.
 */
bool
sudo_load_plugins(struct plugin_container *policy_plugin,
    struct plugin_container_list *io_plugins)
{
    struct plugin_container *container;
    struct plugin_info_list *plugins;
    struct plugin_info *info, *next;
    bool ret = false;
    debug_decl(sudo_load_plugins, SUDO_DEBUG_PLUGIN)

    /* Walk the plugin list from sudo.conf, if any and free it. */
    plugins = sudo_conf_plugins();
    TAILQ_FOREACH_SAFE(info, plugins, entries, next) {
	ret = sudo_load_plugin(policy_plugin, io_plugins, info);
	if (!ret)
	    goto done;
	free_plugin_info(info);
    }
    TAILQ_INIT(plugins);

    /*
     * If no policy plugin, fall back to the default (sudoers).
     * If there is also no I/O log plugin, use sudoers for that too.
     */
    if (policy_plugin->handle == NULL) {
	/* Default policy plugin */
	info = calloc(1, sizeof(*info));
	if (info == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto done;
	}
	info->symbol_name = strdup("sudoers_policy");
	info->path = strdup(SUDOERS_PLUGIN);
	if (info->symbol_name == NULL || info->path == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    free_plugin_info(info);
	    goto done;
	}
	/* info->options = NULL; */
	ret = sudo_load_plugin(policy_plugin, io_plugins, info);
	free_plugin_info(info);
	if (!ret)
	    goto done;

	/* Default I/O plugin */
	if (TAILQ_EMPTY(io_plugins)) {
	    info = calloc(1, sizeof(*info));
	    if (info == NULL) {
		sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
		goto done;
	    }
	    info->symbol_name = strdup("sudoers_io");
	    info->path = strdup(SUDOERS_PLUGIN);
	    if (info->symbol_name == NULL || info->path == NULL) {
		sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
		free_plugin_info(info);
		goto done;
	    }
	    /* info->options = NULL; */
	    ret = sudo_load_plugin(policy_plugin, io_plugins, info);
	    free_plugin_info(info);
	    if (!ret)
		goto done;
	}
    }
    if (policy_plugin->u.policy->check_policy == NULL) {
	sudo_warnx(U_("policy plugin %s does not include a check_policy method"),
	    policy_plugin->name);
	ret = false;
	goto done;
    }

    /* Install hooks (XXX - later). */
    sudo_debug_set_active_instance(SUDO_DEBUG_INSTANCE_INITIALIZER);
    if (policy_plugin->u.policy->version >= SUDO_API_MKVERSION(1, 2)) {
	if (policy_plugin->u.policy->register_hooks != NULL)
	    policy_plugin->u.policy->register_hooks(SUDO_HOOK_VERSION, register_hook);
    }
    TAILQ_FOREACH(container, io_plugins, entries) {
	if (container->u.io->version >= SUDO_API_MKVERSION(1, 2)) {
	    if (container->u.io->register_hooks != NULL)
		container->u.io->register_hooks(SUDO_HOOK_VERSION, register_hook);
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);

done:
    debug_return_bool(ret);
}
