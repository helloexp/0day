/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2010-2017 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <netinet/in.h>
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
#include <grp.h>
#include <pwd.h>

#include "sudoers.h"
#include "sudoers_version.h"
#include "interfaces.h"

/*
 * Info passed in from the sudo front-end.
 */
struct sudoers_policy_open_info {
    char * const *settings;
    char * const *user_info;
    char * const *plugin_args;
};

/*
 * Command execution args to be filled in: argv, envp and command info.
 */
struct sudoers_exec_args {
    char ***argv;
    char ***envp;
    char ***info;
};

static unsigned int sudo_version;
static const char *interfaces_string;
sudo_conv_t sudo_conv;
sudo_printf_t sudo_printf;
const char *path_ldap_conf = _PATH_LDAP_CONF;
const char *path_ldap_secret = _PATH_LDAP_SECRET;

extern __dso_public struct policy_plugin sudoers_policy;

#ifdef HAVE_BSD_AUTH_H
extern char *login_style;
#endif /* HAVE_BSD_AUTH_H */

static int
parse_bool(const char *line, int varlen, int *flags, int fval)
{
    debug_decl(parse_bool, SUDOERS_DEBUG_PLUGIN)

    switch (sudo_strtobool(line + varlen + 1)) {
    case true:
	SET(*flags, fval);
	debug_return_int(true);
    case false:
	CLR(*flags, fval);
	debug_return_int(false);
    default:
	sudo_warn(U_("invalid %.*s set by sudo front-end"),
	    varlen, line);
	debug_return_int(-1);
    }
}

/*
 * Deserialize args, settings and user_info arrays.
 * Fills in struct sudo_user and other common sudoers state.
 */
int
sudoers_policy_deserialize_info(void *v, char **runas_user, char **runas_group)
{
    struct sudoers_policy_open_info *info = v;
    char * const *cur;
    const char *p, *errstr, *groups = NULL;
    const char *remhost = NULL;
    int flags = 0;
    debug_decl(sudoers_policy_deserialize_info, SUDOERS_DEBUG_PLUGIN)

#define MATCHES(s, v)	\
    (strncmp((s), (v), sizeof(v) - 1) == 0)

#define CHECK(s, v) do {	\
    if ((s)[sizeof(v) - 1] == '\0') { \
	sudo_warn(U_("invalid %.*s set by sudo front-end"), \
	    (int)(sizeof(v) - 2), v); \
	goto bad; \
    } \
} while (0)

    /* Parse sudo.conf plugin args. */
    if (info->plugin_args != NULL) {
	for (cur = info->plugin_args; *cur != NULL; cur++) {
	    if (MATCHES(*cur, "sudoers_file=")) {
		CHECK(*cur, "sudoers_file=");
		sudoers_file = *cur + sizeof("sudoers_file=") - 1;
		continue;
	    }
	    if (MATCHES(*cur, "sudoers_uid=")) {
		p = *cur + sizeof("sudoers_uid=") - 1;
		sudoers_uid = (uid_t) sudo_strtoid(p, &errstr);
		if (errstr != NULL) {
		    sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		    goto bad;
		}
		continue;
	    }
	    if (MATCHES(*cur, "sudoers_gid=")) {
		p = *cur + sizeof("sudoers_gid=") - 1;
		sudoers_gid = (gid_t) sudo_strtoid(p, &errstr);
		if (errstr != NULL) {
		    sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		    goto bad;
		}
		continue;
	    }
	    if (MATCHES(*cur, "sudoers_mode=")) {
		p = *cur + sizeof("sudoers_mode=") - 1;
		sudoers_mode = sudo_strtomode(p, &errstr);
		if (errstr != NULL) {
		    sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		    goto bad;
		}
		continue;
	    }
	    if (MATCHES(*cur, "ldap_conf=")) {
		CHECK(*cur, "ldap_conf=");
		path_ldap_conf = *cur + sizeof("ldap_conf=") - 1;
		continue;
	    }
	    if (MATCHES(*cur, "ldap_secret=")) {
		CHECK(*cur, "ldap_secret=");
		path_ldap_secret = *cur + sizeof("ldap_secret=") - 1;
		continue;
	    }
	}
    }

    /* Parse command line settings. */
    user_closefrom = -1;
    for (cur = info->settings; *cur != NULL; cur++) {
	if (MATCHES(*cur, "closefrom=")) {
	    errno = 0;
	    p = *cur + sizeof("closefrom=") - 1;
	    user_closefrom = sudo_strtonum(p, 4, INT_MAX, &errstr);
	    if (user_closefrom == 0) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "runas_user=")) {
	    CHECK(*cur, "runas_user=");
	    *runas_user = *cur + sizeof("runas_user=") - 1;
	    SET(sudo_user.flags, RUNAS_USER_SPECIFIED);
	    continue;
	}
	if (MATCHES(*cur, "runas_group=")) {
	    CHECK(*cur, "runas_group=");
	    *runas_group = *cur + sizeof("runas_group=") - 1;
	    SET(sudo_user.flags, RUNAS_GROUP_SPECIFIED);
	    continue;
	}
	if (MATCHES(*cur, "prompt=")) {
	    /* Allow epmpty prompt. */
	    user_prompt = *cur + sizeof("prompt=") - 1;
	    def_passprompt_override = true;
	    continue;
	}
	if (MATCHES(*cur, "set_home=")) {
	    if (parse_bool(*cur, sizeof("set_home") - 1, &flags,
		MODE_RESET_HOME) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "preserve_environment=")) {
	    if (parse_bool(*cur, sizeof("preserve_environment") - 1, &flags,
		MODE_PRESERVE_ENV) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "run_shell=")) {
	    if (parse_bool(*cur, sizeof("run_shell") -1, &flags,
		MODE_SHELL) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "login_shell=")) {
	    if (parse_bool(*cur, sizeof("login_shell") - 1, &flags,
		MODE_LOGIN_SHELL) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "implied_shell=")) {
	    if (parse_bool(*cur, sizeof("implied_shell") - 1, &flags,
		MODE_IMPLIED_SHELL) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "preserve_groups=")) {
	    if (parse_bool(*cur, sizeof("preserve_groups") - 1, &flags,
		MODE_PRESERVE_GROUPS) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "ignore_ticket=")) {
	    if (parse_bool(*cur, sizeof("ignore_ticket") -1, &flags,
		MODE_IGNORE_TICKET) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "noninteractive=")) {
	    if (parse_bool(*cur, sizeof("noninteractive") - 1, &flags,
		MODE_NONINTERACTIVE) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "sudoedit=")) {
	    if (parse_bool(*cur, sizeof("sudoedit") - 1, &flags,
		MODE_EDIT) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "login_class=")) {
	    CHECK(*cur, "login_class=");
	    login_class = *cur + sizeof("login_class=") - 1;
	    def_use_loginclass = true;
	    continue;
	}
#ifdef HAVE_PRIV_SET
	if (MATCHES(*cur, "runas_privs=")) {
	    CHECK(*cur, "runas_privs=");
	    def_privs = *cur + sizeof("runas_privs=") - 1;
	    continue;
	}
	if (MATCHES(*cur, "runas_limitprivs=")) {
	    CHECK(*cur, "runas_limitprivs=");
	    def_limitprivs = *cur + sizeof("runas_limitprivs=") - 1;
	    continue;
	}
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
	if (MATCHES(*cur, "selinux_role=")) {
	    CHECK(*cur, "selinux_role=");
	    user_role = *cur + sizeof("selinux_role=") - 1;
	    continue;
	}
	if (MATCHES(*cur, "selinux_type=")) {
	    CHECK(*cur, "selinux_type=");
	    user_type = *cur + sizeof("selinux_type=") - 1;
	    continue;
	}
#endif /* HAVE_SELINUX */
#ifdef HAVE_BSD_AUTH_H
	if (MATCHES(*cur, "bsdauth_type=")) {
	    CHECK(*cur, "login_style=");
	    login_style = *cur + sizeof("bsdauth_type=") - 1;
	    continue;
	}
#endif /* HAVE_BSD_AUTH_H */
	if (MATCHES(*cur, "network_addrs=")) {
	    interfaces_string = *cur + sizeof("network_addrs=") - 1;
	    if (!set_interfaces(interfaces_string)) {
		sudo_warn(U_("unable to parse network address list"));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "max_groups=")) {
	    errno = 0;
	    p = *cur + sizeof("max_groups=") - 1;
	    sudo_user.max_groups = sudo_strtonum(p, 1, INT_MAX, &errstr);
	    if (sudo_user.max_groups == 0) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "remote_host=")) {
	    CHECK(*cur, "remote_host=");
	    remhost = *cur + sizeof("remote_host=") - 1;
	    continue;
	}
	if (MATCHES(*cur, "timeout=")) {
	    p = *cur + sizeof("timeout=") - 1;
	    user_timeout = parse_timeout(p);
	    if (user_timeout == -1) {
		if (errno == ERANGE)
		    sudo_warnx(U_("%s: %s"), p, U_("timeout value too large"));
		else
		    sudo_warnx(U_("%s: %s"), p, U_("invalid timeout value"));
		goto bad;
	    }
	    continue;
	}
#ifdef ENABLE_SUDO_PLUGIN_API
	if (MATCHES(*cur, "plugin_dir=")) {
	    CHECK(*cur, "plugin_dir=");
	    path_plugin_dir = *cur + sizeof("plugin_dir=") - 1;
	    continue;
	}
#endif
    }

    user_gid = (gid_t)-1;
    user_sid = (pid_t)-1;
    user_uid = (gid_t)-1;
    user_umask = (mode_t)-1;
    for (cur = info->user_info; *cur != NULL; cur++) {
	if (MATCHES(*cur, "user=")) {
	    CHECK(*cur, "user=");
	    if ((user_name = strdup(*cur + sizeof("user=") - 1)) == NULL)
		goto oom;
	    continue;
	}
	if (MATCHES(*cur, "uid=")) {
	    p = *cur + sizeof("uid=") - 1;
	    user_uid = (uid_t) sudo_strtoid(p, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "gid=")) {
	    p = *cur + sizeof("gid=") - 1;
	    user_gid = (gid_t) sudo_strtoid(p, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "groups=")) {
	    CHECK(*cur, "groups=");
	    groups = *cur + sizeof("groups=") - 1;
	    continue;
	}
	if (MATCHES(*cur, "cwd=")) {
	    CHECK(*cur, "cwd=");
	    if ((user_cwd = strdup(*cur + sizeof("cwd=") - 1)) == NULL)
		goto oom;
	    continue;
	}
	if (MATCHES(*cur, "tty=")) {
	    CHECK(*cur, "tty=");
	    if ((user_ttypath = strdup(*cur + sizeof("tty=") - 1)) == NULL)
		goto oom;
	    user_tty = user_ttypath;
	    if (strncmp(user_tty, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
		user_tty += sizeof(_PATH_DEV) - 1;
	    continue;
	}
	if (MATCHES(*cur, "host=")) {
	    CHECK(*cur, "host=");
	    if ((user_host = strdup(*cur + sizeof("host=") - 1)) == NULL)
		goto oom;
	    if ((p = strchr(user_host, '.')) != NULL) {
		user_shost = strndup(user_host, (size_t)(p - user_host));
		if (user_shost == NULL)
		    goto oom;
	    } else {
		user_shost = user_host;
	    }
	    continue;
	}
	if (MATCHES(*cur, "lines=")) {
	    errno = 0;
	    p = *cur + sizeof("lines=") - 1;
	    sudo_user.lines = sudo_strtonum(p, 1, INT_MAX, &errstr);
	    if (sudo_user.lines == 0) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "cols=")) {
	    errno = 0;
	    p = *cur + sizeof("cols=") - 1;
	    sudo_user.cols = sudo_strtonum(p, 1, INT_MAX, &errstr);
	    if (sudo_user.cols == 0) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "sid=")) {
	    p = *cur + sizeof("sid=") - 1;
	    user_sid = (pid_t) sudo_strtoid(p, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "umask=")) {
	    p = *cur + sizeof("umask=") - 1;
	    sudo_user.umask = sudo_strtomode(p, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
    }

    /* User name, user-ID, group-ID and host name must be specified. */
    if (user_name == NULL) {
	sudo_warnx(U_("user name not set by sudo front-end"));
	goto bad;
    }
    if (user_uid == (uid_t)-1) {
	sudo_warnx(U_("user-ID not set by sudo front-end"));
	goto bad;
    }
    if (user_gid == (gid_t)-1) {
	sudo_warnx(U_("group-ID not set by sudo front-end"));
	goto bad;
    }
    if (user_host == NULL) {
	sudo_warnx(U_("host name not set by sudo front-end"));
	goto bad;
    }

    if ((user_runhost = strdup(remhost ? remhost : user_host)) == NULL)
	goto oom;
    if ((p = strchr(user_runhost, '.')) != NULL) {
	user_srunhost = strndup(user_runhost, (size_t)(p - user_runhost));
	if (user_srunhost == NULL)
	    goto oom;
    } else {
	user_srunhost = user_runhost;
    }
    if (user_cwd == NULL) {
	if ((user_cwd = strdup("unknown")) == NULL)
	    goto oom;
    }
    if (user_tty == NULL) {
	if ((user_tty = strdup("unknown")) == NULL)
	    goto oom;
	/* user_ttypath remains NULL */
    }

    if (groups != NULL) {
	/* sudo_parse_gids() will print a warning on error. */
	user_ngids = sudo_parse_gids(groups, &user_gid, &user_gids);
	if (user_ngids == -1)
	    goto bad;
    }

    /* umask is only set in user_info[] for API 1.10 and above. */
    if (user_umask == (mode_t)-1) {
	user_umask = umask(0);
	umask(user_umask);
    }

    /* Always reset the environment for a login shell. */
    if (ISSET(flags, MODE_LOGIN_SHELL))
	def_env_reset = true;

    /* Some systems support fexecve() which we use for digest matches. */
    cmnd_fd = -1;

    /* Dump settings and user info (XXX - plugin args) */
    for (cur = info->settings; *cur != NULL; cur++)
	sudo_debug_printf(SUDO_DEBUG_INFO, "settings: %s", *cur);
    for (cur = info->user_info; *cur != NULL; cur++)
	sudo_debug_printf(SUDO_DEBUG_INFO, "user_info: %s", *cur);

#undef MATCHES
    debug_return_int(flags);

oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
bad:
    debug_return_int(MODE_ERROR);
}

/*
 * Setup the execution environment.
 * Builds up the command_info list and sets argv and envp.
 * Consumes iolog_path if not NULL.
 * Returns 1 on success and -1 on error.
 */
int
sudoers_policy_exec_setup(char *argv[], char *envp[], mode_t cmnd_umask,
    char *iolog_path, void *v)
{
    struct sudoers_exec_args *exec_args = v;
    char **command_info;
    int info_len = 0;
    debug_decl(sudoers_policy_exec_setup, SUDOERS_DEBUG_PLUGIN)

    /* Increase the length of command_info as needed, it is *not* checked. */
    command_info = calloc(48, sizeof(char *));
    if (command_info == NULL)
	goto oom;

    command_info[info_len] = sudo_new_key_val("command", safe_cmnd);
    if (command_info[info_len++] == NULL)
	goto oom;
    if (def_log_input || def_log_output) {
	if (iolog_path)
	    command_info[info_len++] = iolog_path;	/* now owned */
	if (def_log_input) {
	    if ((command_info[info_len++] = strdup("iolog_stdin=true")) == NULL)
		goto oom;
	    if ((command_info[info_len++] = strdup("iolog_ttyin=true")) == NULL)
		goto oom;
	}
	if (def_log_output) {
	    if ((command_info[info_len++] = strdup("iolog_stdout=true")) == NULL)
		goto oom;
	    if ((command_info[info_len++] = strdup("iolog_stderr=true")) == NULL)
		goto oom;
	    if ((command_info[info_len++] = strdup("iolog_ttyout=true")) == NULL)
		goto oom;
	}
	if (def_compress_io) {
	    if ((command_info[info_len++] = strdup("iolog_compress=true")) == NULL)
		goto oom;
	}
	if (def_maxseq) {
	    if (asprintf(&command_info[info_len++], "maxseq=%u", def_maxseq) == -1)
		goto oom;
	}
    }
    if (ISSET(sudo_mode, MODE_EDIT)) {
	if ((command_info[info_len++] = strdup("sudoedit=true")) == NULL)
	    goto oom;
	if (!def_sudoedit_checkdir) {
	    if ((command_info[info_len++] = strdup("sudoedit_checkdir=false")) == NULL)
		goto oom;
	}
	if (def_sudoedit_follow) {
	    if ((command_info[info_len++] = strdup("sudoedit_follow=true")) == NULL)
		goto oom;
	}
    }
    if (ISSET(sudo_mode, MODE_LOGIN_SHELL)) {
	/* Set cwd to run user's homedir. */
	if ((command_info[info_len++] = sudo_new_key_val("cwd", runas_pw->pw_dir)) == NULL)
	    goto oom;
    }
    if (def_stay_setuid) {
	if (asprintf(&command_info[info_len++], "runas_uid=%u",
	    (unsigned int)user_uid) == -1)
	    goto oom;
	if (asprintf(&command_info[info_len++], "runas_gid=%u",
	    (unsigned int)user_gid) == -1)
	    goto oom;
	if (asprintf(&command_info[info_len++], "runas_euid=%u",
	    (unsigned int)runas_pw->pw_uid) == -1)
	    goto oom;
	if (asprintf(&command_info[info_len++], "runas_egid=%u",
	    runas_gr ? (unsigned int)runas_gr->gr_gid :
	    (unsigned int)runas_pw->pw_gid) == -1)
	    goto oom;
    } else {
	if (asprintf(&command_info[info_len++], "runas_uid=%u",
	    (unsigned int)runas_pw->pw_uid) == -1)
	    goto oom;
	if (asprintf(&command_info[info_len++], "runas_gid=%u",
	    runas_gr ? (unsigned int)runas_gr->gr_gid :
	    (unsigned int)runas_pw->pw_gid) == -1)
	    goto oom;
    }
    if (def_preserve_groups) {
	if ((command_info[info_len++] = strdup("preserve_groups=true")) == NULL)
	    goto oom;
    } else {
	int i, len;
	gid_t egid;
	size_t glsize;
	char *cp, *gid_list;
	struct gid_list *gidlist;

	/* Only use results from a group db query, not the front end. */
	gidlist = sudo_get_gidlist(runas_pw, ENTRY_TYPE_QUERIED);

	/* We reserve an extra spot in the list for the effective gid. */
	glsize = sizeof("runas_groups=") - 1 +
	    ((gidlist->ngids + 1) * (MAX_UID_T_LEN + 1));
	gid_list = malloc(glsize);
	if (gid_list == NULL)
	    goto oom;
	memcpy(gid_list, "runas_groups=", sizeof("runas_groups=") - 1);
	cp = gid_list + sizeof("runas_groups=") - 1;

	/* On BSD systems the effective gid is the first group in the list. */
	egid = runas_gr ? (unsigned int)runas_gr->gr_gid :
	    (unsigned int)runas_pw->pw_gid;
	len = snprintf(cp, glsize - (cp - gid_list), "%u", (unsigned int)egid);
	if (len < 0 || (size_t)len >= glsize - (cp - gid_list)) {
	    sudo_warnx(U_("internal error, %s overflow"), __func__);
	    free(gid_list);
	    goto bad;
	}
	cp += len;
	for (i = 0; i < gidlist->ngids; i++) {
	    if (gidlist->gids[i] != egid) {
		len = snprintf(cp, glsize - (cp - gid_list), ",%u",
		     (unsigned int) gidlist->gids[i]);
		if (len < 0 || (size_t)len >= glsize - (cp - gid_list)) {
		    sudo_warnx(U_("internal error, %s overflow"), __func__);
		    free(gid_list);
		    goto bad;
		}
		cp += len;
	    }
	}
	command_info[info_len++] = gid_list;
	sudo_gidlist_delref(gidlist);
    }
    if (def_closefrom >= 0) {
	if (asprintf(&command_info[info_len++], "closefrom=%d", def_closefrom) == -1)
	    goto oom;
    }
    if (def_ignore_iolog_errors) {
	if ((command_info[info_len++] = strdup("ignore_iolog_errors=true")) == NULL)
	    goto oom;
    }
    if (def_noexec) {
	if ((command_info[info_len++] = strdup("noexec=true")) == NULL)
	    goto oom;
    }
    if (def_exec_background) {
	if ((command_info[info_len++] = strdup("exec_background=true")) == NULL)
	    goto oom;
    }
    if (def_set_utmp) {
	if ((command_info[info_len++] = strdup("set_utmp=true")) == NULL)
	    goto oom;
    }
    if (def_use_pty) {
	if ((command_info[info_len++] = strdup("use_pty=true")) == NULL)
	    goto oom;
    }
    if (def_utmp_runas) {
	if ((command_info[info_len++] = sudo_new_key_val("utmp_user", runas_pw->pw_name)) == NULL)
	    goto oom;
    }
    if (def_iolog_mode != (S_IRUSR|S_IWUSR)) {
	if (asprintf(&command_info[info_len++], "iolog_mode=0%o", (unsigned int)def_iolog_mode) == -1)
	    goto oom;
    }
    if (def_iolog_user != NULL) {
	if ((command_info[info_len++] = sudo_new_key_val("iolog_user", def_iolog_user)) == NULL)
	    goto oom;
    }
    if (def_iolog_group != NULL) {
	if ((command_info[info_len++] = sudo_new_key_val("iolog_group", def_iolog_group)) == NULL)
	    goto oom;
    }
    if (def_command_timeout > 0 || user_timeout > 0) {
	int timeout = user_timeout;
	if (timeout == 0 || def_command_timeout < timeout)
	    timeout = def_command_timeout;
	if (asprintf(&command_info[info_len++], "timeout=%u", timeout) == -1)
	    goto oom;
    }
    if (cmnd_umask != ACCESSPERMS) {
	if (asprintf(&command_info[info_len++], "umask=0%o", (unsigned int)cmnd_umask) == -1)
	    goto oom;
    }
    if (force_umask) {
	if ((command_info[info_len++] = strdup("umask_override=true")) == NULL)
	    goto oom;
    }
    if (cmnd_fd != -1) {
	if (sudo_version < SUDO_API_MKVERSION(1, 9)) {
	    /* execfd only supported by plugin API 1.9 and higher */
	    close(cmnd_fd);
	    cmnd_fd = -1;
	} else {
	    if (asprintf(&command_info[info_len++], "execfd=%d", cmnd_fd) == -1)
		goto oom;
	}
    }
#ifdef HAVE_LOGIN_CAP_H
    if (def_use_loginclass) {
	if ((command_info[info_len++] = sudo_new_key_val("login_class", login_class)) == NULL)
	    goto oom;
    }
#endif /* HAVE_LOGIN_CAP_H */
#ifdef HAVE_SELINUX
    if (user_role != NULL) {
	if ((command_info[info_len++] = sudo_new_key_val("selinux_role", user_role)) == NULL)
	    goto oom;
    }
    if (user_type != NULL) {
	if ((command_info[info_len++] = sudo_new_key_val("selinux_type", user_type)) == NULL)
	    goto oom;
    }
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
    if (runas_privs != NULL) {
	if ((command_info[info_len++] = sudo_new_key_val("runas_privs", runas_privs)) == NULL)
	    goto oom;
    }
    if (runas_limitprivs != NULL) {
	if ((command_info[info_len++] = sudo_new_key_val("runas_limitprivs", runas_limitprivs)) == NULL)
	    goto oom;
    }
#endif /* HAVE_SELINUX */

    /* Free on exit; they are not available in the close function. */
    sudoers_gc_add(GC_VECTOR, argv);
    sudoers_gc_add(GC_VECTOR, envp);
    sudoers_gc_add(GC_VECTOR, command_info);

    /* Fill in exec environment info. */
    *(exec_args->argv) = argv;
    *(exec_args->envp) = envp;
    *(exec_args->info) = command_info;

    debug_return_int(true);

oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
bad:
    while (info_len--)
	free(command_info[info_len]);
    free(command_info);
    debug_return_int(-1);
}

static int
sudoers_policy_open(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, char * const settings[],
    char * const user_info[], char * const envp[], char * const args[])
{
    struct sudo_conf_debug_file_list debug_files = TAILQ_HEAD_INITIALIZER(debug_files);
    struct sudoers_policy_open_info info;
    const char *cp, *plugin_path = NULL;
    char * const *cur;
    debug_decl(sudoers_policy_open, SUDOERS_DEBUG_PLUGIN)

    sudo_version = version;
    sudo_conv = conversation;
    sudo_printf = plugin_printf;

    /* Plugin args are only specified for API version 1.2 and higher. */
    if (sudo_version < SUDO_API_MKVERSION(1, 2))
	args = NULL;

    /* Initialize the debug subsystem.  */
    for (cur = settings; (cp = *cur) != NULL; cur++) {
	if (strncmp(cp, "debug_flags=", sizeof("debug_flags=") - 1) == 0) {
	    cp += sizeof("debug_flags=") - 1;
	    if (!sudoers_debug_parse_flags(&debug_files, cp))
		debug_return_int(-1);
	    continue;
	}
	if (strncmp(cp, "plugin_path=", sizeof("plugin_path=") - 1) == 0) {
	    plugin_path = cp + sizeof("plugin_path=") - 1;
	    continue;
	}
    }
    if (!sudoers_debug_register(plugin_path, &debug_files))
	debug_return_int(-1);

    /* Call the sudoers init function. */
    info.settings = settings;
    info.user_info = user_info;
    info.plugin_args = args;
    debug_return_int(sudoers_policy_init(&info, envp));
}

static void
sudoers_policy_close(int exit_status, int error_code)
{
    debug_decl(sudoers_policy_close, SUDOERS_DEBUG_PLUGIN)

    /* We do not currently log the exit status. */
    if (error_code) {
	errno = error_code;
	sudo_warn(U_("unable to execute %s"), safe_cmnd);
    }

    /* Close the session we opened in sudoers_policy_init_session(). */
    if (ISSET(sudo_mode, MODE_RUN|MODE_EDIT))
	(void)sudo_auth_end_session(runas_pw);

    /* Deregister the callback for sudo_fatal()/sudo_fatalx(). */
    sudo_fatal_callback_deregister(sudoers_cleanup);

    /* Free remaining references to password and group entries. */
    /* XXX - move cleanup to function in sudoers.c */
    sudo_pw_delref(sudo_user.pw);
    sudo_user.pw = NULL;
    sudo_pw_delref(runas_pw);
    runas_pw = NULL;
    if (runas_gr != NULL) {
	sudo_gr_delref(runas_gr);
	runas_gr = NULL;
    }
    if (user_gid_list != NULL) {
	sudo_gidlist_delref(user_gid_list);
	user_gid_list = NULL;
    }
    free(user_gids);
    user_gids = NULL;

    sudoers_debug_deregister();

    return;
}

/*
 * The init_session function is called before executing the command
 * and before uid/gid changes occur.
 * Returns 1 on success, 0 on failure and -1 on error.
 */
static int
sudoers_policy_init_session(struct passwd *pwd, char **user_env[])
{
    debug_decl(sudoers_policy_init_session, SUDOERS_DEBUG_PLUGIN)

    /* user_env is only specified for API version 1.2 and higher. */
    if (sudo_version < SUDO_API_MKVERSION(1, 2))
	user_env = NULL;

    debug_return_int(sudo_auth_begin_session(pwd, user_env));
}

static int
sudoers_policy_check(int argc, char * const argv[], char *env_add[],
    char **command_infop[], char **argv_out[], char **user_env_out[])
{
    struct sudoers_exec_args exec_args;
    int ret;
    debug_decl(sudoers_policy_check, SUDOERS_DEBUG_PLUGIN)

    if (!ISSET(sudo_mode, MODE_EDIT))
	SET(sudo_mode, MODE_RUN);

    exec_args.argv = argv_out;
    exec_args.envp = user_env_out;
    exec_args.info = command_infop;

    ret = sudoers_policy_main(argc, argv, 0, env_add, false, &exec_args);
    if (ret == true && sudo_version >= SUDO_API_MKVERSION(1, 3)) {
	/* Unset close function if we don't need it to avoid extra process. */
	if (!def_log_input && !def_log_output && !def_use_pty &&
	    !sudo_auth_needs_end_session())
	    sudoers_policy.close = NULL;
    }
    debug_return_int(ret);
}

static int
sudoers_policy_validate(void)
{
    debug_decl(sudoers_policy_validate, SUDOERS_DEBUG_PLUGIN)

    user_cmnd = "validate";
    SET(sudo_mode, MODE_VALIDATE);

    debug_return_int(sudoers_policy_main(0, NULL, I_VERIFYPW, NULL, false, NULL));
}

static void
sudoers_policy_invalidate(int remove)
{
    debug_decl(sudoers_policy_invalidate, SUDOERS_DEBUG_PLUGIN)

    user_cmnd = "kill";
    /* XXX - plugin API should support a return value for fatal errors. */
    timestamp_remove(remove);
    sudoers_cleanup();

    debug_return;
}

static int
sudoers_policy_list(int argc, char * const argv[], int verbose,
    const char *list_user)
{
    int ret;
    debug_decl(sudoers_policy_list, SUDOERS_DEBUG_PLUGIN)

    user_cmnd = "list";
    if (argc)
	SET(sudo_mode, MODE_CHECK);
    else
	SET(sudo_mode, MODE_LIST);
    if (list_user) {
	list_pw = sudo_getpwnam(list_user);
	if (list_pw == NULL) {
	    sudo_warnx(U_("unknown user: %s"), list_user);
	    debug_return_int(-1);
	}
    }
    ret = sudoers_policy_main(argc, argv, I_LISTPW, NULL, verbose, NULL);
    if (list_user) {
	sudo_pw_delref(list_pw);
	list_pw = NULL;
    }

    debug_return_int(ret);
}

static int
sudoers_policy_version(int verbose)
{
    debug_decl(sudoers_policy_version, SUDOERS_DEBUG_PLUGIN)

    sudo_printf(SUDO_CONV_INFO_MSG, _("Sudoers policy plugin version %s\n"),
	PACKAGE_VERSION);
    sudo_printf(SUDO_CONV_INFO_MSG, _("Sudoers file grammar version %d\n"),
	SUDOERS_GRAMMAR_VERSION);

    if (verbose) {
	sudo_printf(SUDO_CONV_INFO_MSG, _("\nSudoers path: %s\n"), sudoers_file);
#ifdef HAVE_LDAP
# ifdef _PATH_NSSWITCH_CONF
	sudo_printf(SUDO_CONV_INFO_MSG, _("nsswitch path: %s\n"), _PATH_NSSWITCH_CONF);
# endif
	sudo_printf(SUDO_CONV_INFO_MSG, _("ldap.conf path: %s\n"), path_ldap_conf);
	sudo_printf(SUDO_CONV_INFO_MSG, _("ldap.secret path: %s\n"), path_ldap_secret);
#endif
	dump_auth_methods();
	dump_defaults();
	sudo_printf(SUDO_CONV_INFO_MSG, "\n");
	if (interfaces_string != NULL) {
	    dump_interfaces(interfaces_string);
	    sudo_printf(SUDO_CONV_INFO_MSG, "\n");
	}
    }
    debug_return_int(true);
}

static struct sudo_hook sudoers_hooks[] = {
    { SUDO_HOOK_VERSION, SUDO_HOOK_SETENV, sudoers_hook_setenv, NULL },
    { SUDO_HOOK_VERSION, SUDO_HOOK_UNSETENV, sudoers_hook_unsetenv, NULL },
    { SUDO_HOOK_VERSION, SUDO_HOOK_GETENV, sudoers_hook_getenv, NULL },
    { SUDO_HOOK_VERSION, SUDO_HOOK_PUTENV, sudoers_hook_putenv, NULL },
    { 0, 0, NULL, NULL }
};

/*
 * Register environment function hooks.
 * Note that we have not registered sudoers with the debug subsystem yet.
 */
static void
sudoers_policy_register_hooks(int version, int (*register_hook)(struct sudo_hook *hook))
{
    struct sudo_hook *hook;

    for (hook = sudoers_hooks; hook->hook_fn != NULL; hook++) {
	if (register_hook(hook) != 0) {
	    sudo_warn_nodebug(
		U_("unable to register hook of type %d (version %d.%d)"),
		hook->hook_type, SUDO_API_VERSION_GET_MAJOR(hook->hook_version),
		SUDO_API_VERSION_GET_MINOR(hook->hook_version));
	}
    }
}

__dso_public struct policy_plugin sudoers_policy = {
    SUDO_POLICY_PLUGIN,
    SUDO_API_VERSION,
    sudoers_policy_open,
    sudoers_policy_close,
    sudoers_policy_version,
    sudoers_policy_check,
    sudoers_policy_list,
    sudoers_policy_validate,
    sudoers_policy_invalidate,
    sudoers_policy_init_session,
    sudoers_policy_register_hooks
};
