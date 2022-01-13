/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1993-1996, 1998-2019 Todd C. Miller <Todd.Miller@sudo.ws>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#ifdef __TANDEM
# include <floss.h>
#endif

#include <config.h>

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <grp.h>
#include <time.h>
#include <netdb.h>
#ifdef HAVE_LOGIN_CAP_H
# include <login_cap.h>
# ifndef LOGIN_DEFROOTCLASS
#  define LOGIN_DEFROOTCLASS	"daemon"
# endif
# ifndef LOGIN_SETENV
#  define LOGIN_SETENV	0
# endif
#endif
#ifdef HAVE_SELINUX
# include <selinux/selinux.h>
#endif
#include <ctype.h>

#include "sudoers.h"
#include "parse.h"
#include "auth/sudo_auth.h"

#ifndef HAVE_GETADDRINFO
# include "compat/getaddrinfo.h"
#endif

/*
 * Prototypes
 */
static bool cb_fqdn(const union sudo_defs_val *);
static bool cb_runas_default(const union sudo_defs_val *);
static bool cb_tty_tickets(const union sudo_defs_val *);
static bool cb_umask(const union sudo_defs_val *);
static int set_cmnd(void);
static int create_admin_success_flag(void);
static bool init_vars(char * const *);
static bool set_loginclass(struct passwd *);
static bool set_runasgr(const char *, bool);
static bool set_runaspw(const char *, bool);
static bool tty_present(void);

/*
 * Globals
 */
struct sudo_user sudo_user;
struct passwd *list_pw;
uid_t timestamp_uid;
gid_t timestamp_gid;
#ifdef HAVE_BSD_AUTH_H
char *login_style;
#endif /* HAVE_BSD_AUTH_H */
bool force_umask;
int sudo_mode;

static char *prev_user;
static char *runas_user;
static char *runas_group;
static struct sudo_nss_list *snl;
static bool unknown_runas_uid;
static bool unknown_runas_gid;

#ifdef __linux__
static struct rlimit nproclimit;
#endif

/* XXX - must be extern for audit bits of sudo_auth.c */
int NewArgc;
char **NewArgv;

/*
 * Unlimit the number of processes since Linux's setuid() will
 * apply resource limits when changing uid and return EAGAIN if
 * nproc would be exceeded by the uid switch.
 */
static void
unlimit_nproc(void)
{
#ifdef __linux__
    struct rlimit rl;
    debug_decl(unlimit_nproc, SUDOERS_DEBUG_UTIL)

    if (getrlimit(RLIMIT_NPROC, &nproclimit) != 0)
	    sudo_warn("getrlimit(RLIMIT_NPROC)");
    rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
	rl.rlim_cur = rl.rlim_max = nproclimit.rlim_max;
	if (setrlimit(RLIMIT_NPROC, &rl) != 0)
	    sudo_warn("setrlimit(RLIMIT_NPROC)");
    }
    debug_return;
#endif /* __linux__ */
}

/*
 * Restore saved value of RLIMIT_NPROC.
 */
static void
restore_nproc(void)
{
#ifdef __linux__
    debug_decl(restore_nproc, SUDOERS_DEBUG_UTIL)

    if (setrlimit(RLIMIT_NPROC, &nproclimit) != 0)
	sudo_warn("setrlimit(RLIMIT_NPROC)");

    debug_return;
#endif /* __linux__ */
}

int
sudoers_policy_init(void *info, char * const envp[])
{
    struct sudo_nss *nss, *nss_next;
    int oldlocale, sources = 0;
    int ret = -1;
    debug_decl(sudoers_policy_init, SUDOERS_DEBUG_PLUGIN)

    bindtextdomain("sudoers", LOCALEDIR);

    /* Register fatal/fatalx callback. */
    sudo_fatal_callback_register(sudoers_cleanup);

    /* Initialize environment functions (including replacements). */
    if (!env_init(envp))
	debug_return_int(-1);

    /* Setup defaults data structures. */
    if (!init_defaults()) {
	sudo_warnx(U_("unable to initialize sudoers default values"));
	debug_return_int(-1);
    }

    /* Parse info from front-end. */
    sudo_mode = sudoers_policy_deserialize_info(info, &runas_user, &runas_group);
    if (ISSET(sudo_mode, MODE_ERROR))
	debug_return_int(-1);

    if (!init_vars(envp))
	debug_return_int(-1);

    /* Parse nsswitch.conf for sudoers order. */
    snl = sudo_read_nss();

    /* LDAP or NSS may modify the euid so we need to be root for the open. */
    if (!set_perms(PERM_ROOT))
	debug_return_int(-1);

    /*
     * Open and parse sudoers, set global defaults.
     * Uses the C locale unless another is specified in sudoers.
     */
    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);
    sudo_warn_set_locale_func(sudoers_warn_setlocale);
    init_parser(sudoers_file, false, false);
    TAILQ_FOREACH_SAFE(nss, snl, entries, nss_next) {
	if (nss->open(nss) == -1 || (nss->parse_tree = nss->parse(nss)) == NULL) {
	    TAILQ_REMOVE(snl, nss, entries);
	    continue;
	}

	sources++;
	if (nss->getdefs(nss) == -1 || !update_defaults(nss->parse_tree, NULL,
	    SETDEF_GENERIC|SETDEF_HOST|SETDEF_USER|SETDEF_RUNAS, false)) {
	    log_warningx(SLOG_SEND_MAIL|SLOG_NO_STDERR,
		N_("problem with defaults entries"));
	}
    }
    if (sources == 0) {
	sudo_warnx(U_("no valid sudoers sources found, quitting"));
	goto cleanup;
    }

    /* Set login class if applicable (after sudoers is parsed). */
    if (set_loginclass(runas_pw ? runas_pw : sudo_user.pw))
	ret = true;

cleanup:
    if (!restore_perms())
	ret = -1;

    /* Restore user's locale. */
    sudo_warn_set_locale_func(NULL);
    sudoers_setlocale(oldlocale, NULL);

    debug_return_int(ret);
}

int
sudoers_policy_main(int argc, char * const argv[], int pwflag, char *env_add[],
    bool verbose, void *closure)
{
    char **edit_argv = NULL;
    char *iolog_path = NULL;
    mode_t cmnd_umask = ACCESSPERMS;
    struct sudo_nss *nss;
    int cmnd_status = -1, oldlocale, validated;
    int ret = -1;
    debug_decl(sudoers_policy_main, SUDOERS_DEBUG_PLUGIN)

    sudo_warn_set_locale_func(sudoers_warn_setlocale);

    unlimit_nproc();

    /* Is root even allowed to run sudo? */
    if (user_uid == 0 && !def_root_sudo) {
	/* Not an audit event. */
	sudo_warnx(U_("sudoers specifies that root is not allowed to sudo"));
	goto bad;
    }

    if (!set_perms(PERM_INITIAL))
	goto bad;

    /* Environment variables specified on the command line. */
    if (env_add != NULL && env_add[0] != NULL)
	sudo_user.env_vars = env_add;

    /*
     * Make a local copy of argc/argv, with special handling
     * for pseudo-commands and the '-i' option.
     */
    if (argc == 0) {
	NewArgc = 1;
	NewArgv = reallocarray(NULL, NewArgc + 1, sizeof(char *));
	if (NewArgv == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto done;
	}
	NewArgv[0] = user_cmnd;
	NewArgv[1] = NULL;
    } else {
	/* Must leave an extra slot before NewArgv for bash's --login */
	NewArgc = argc;
	NewArgv = reallocarray(NULL, NewArgc + 2, sizeof(char *));
	if (NewArgv == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto done;
	}
	NewArgv++;	/* reserve an extra slot for --login */
	memcpy(NewArgv, argv, argc * sizeof(char *));
	NewArgv[NewArgc] = NULL;
	if (ISSET(sudo_mode, MODE_LOGIN_SHELL) && runas_pw != NULL) {
	    NewArgv[0] = strdup(runas_pw->pw_shell);
	    if (NewArgv[0] == NULL) {
		sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
		free(NewArgv);
		goto done;
	    }
	}
    }

    /* If given the -P option, set the "preserve_groups" flag. */
    if (ISSET(sudo_mode, MODE_PRESERVE_GROUPS))
	def_preserve_groups = true;

    /* Find command in path and apply per-command Defaults. */
    cmnd_status = set_cmnd();
    if (cmnd_status == NOT_FOUND_ERROR)
	goto done;

    /* Check for -C overriding def_closefrom. */
    if (user_closefrom >= 0 && user_closefrom != def_closefrom) {
	if (!def_closefrom_override) {
	    /* XXX - audit? */
	    sudo_warnx(U_("you are not permitted to use the -C option"));
	    goto bad;
	}
	def_closefrom = user_closefrom;
    }

    /*
     * Check sudoers sources, using the locale specified in sudoers.
     */
    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);
    validated = sudoers_lookup(snl, sudo_user.pw, FLAG_NO_USER | FLAG_NO_HOST,
	pwflag);
    if (ISSET(validated, VALIDATE_ERROR)) {
	/* The lookup function should have printed an error. */
	goto done;
    }

    /* Restore user's locale. */
    sudoers_setlocale(oldlocale, NULL);

    if (safe_cmnd == NULL) {
	if ((safe_cmnd = strdup(user_cmnd)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto done;
	}
    }

    /* Defer uid/gid checks until after defaults have been updated. */
    if (unknown_runas_uid && !def_runas_allow_unknown_id) {
	audit_failure(NewArgc, NewArgv, N_("unknown user: %s"),
	    runas_pw->pw_name);
	sudo_warnx(U_("unknown user: %s"), runas_pw->pw_name);
	goto done;
    }
    if (runas_gr != NULL) {
	if (unknown_runas_gid && !def_runas_allow_unknown_id) {
	    audit_failure(NewArgc, NewArgv, N_("unknown group: %s"),
		runas_gr->gr_name);
	    sudo_warnx(U_("unknown group: %s"), runas_gr->gr_name);
	    goto done;
	}
    }

    /*
     * Look up the timestamp dir owner if one is specified.
     */
    if (def_timestampowner) {
	struct passwd *pw = NULL;

	if (*def_timestampowner == '#') {
	    const char *errstr;
	    uid_t uid = sudo_strtoid(def_timestampowner + 1, &errstr);
	    if (errstr == NULL)
		pw = sudo_getpwuid(uid);
	}
	if (pw == NULL)
	    pw = sudo_getpwnam(def_timestampowner);
	if (pw != NULL) {
	    timestamp_uid = pw->pw_uid;
	    timestamp_gid = pw->pw_gid;
	    sudo_pw_delref(pw);
	} else {
	    log_warningx(SLOG_SEND_MAIL,
		N_("timestamp owner (%s): No such user"), def_timestampowner);
	    timestamp_uid = ROOT_UID;
	    timestamp_gid = ROOT_GID;
	}
    }

    /* If no command line args and "shell_noargs" is not set, error out. */
    if (ISSET(sudo_mode, MODE_IMPLIED_SHELL) && !def_shell_noargs) {
	/* Not an audit event. */
	ret = -2; /* usage error */
	goto done;
    }

    /* Bail if a tty is required and we don't have one.  */
    if (def_requiretty && !tty_present()) {
	audit_failure(NewArgc, NewArgv, N_("no tty"));
	sudo_warnx(U_("sorry, you must have a tty to run sudo"));
	goto bad;
    }

    /* Check runas user's shell. */
    if (!check_user_shell(runas_pw)) {
	log_warningx(SLOG_RAW_MSG, N_("invalid shell for user %s: %s"),
	    runas_pw->pw_name, runas_pw->pw_shell);
	goto bad;
    }

    /*
     * We don't reset the environment for sudoedit or if the user
     * specified the -E command line flag and they have setenv privs.
     */
    if (ISSET(sudo_mode, MODE_EDIT) ||
	(ISSET(sudo_mode, MODE_PRESERVE_ENV) && def_setenv))
	def_env_reset = false;

    /* Build a new environment that avoids any nasty bits. */
    if (!rebuild_env())
	goto bad;

    /* Require a password if sudoers says so.  */
    switch (check_user(validated, sudo_mode)) {
    case true:
	/* user authenticated successfully. */
	break;
    case false:
	/* Note: log_denial() calls audit for us. */
	if (!ISSET(validated, VALIDATE_SUCCESS)) {
	    /* Only display a denial message if no password was read. */
	    if (!log_denial(validated, def_passwd_tries <= 0))
		goto done;
	}
	goto bad;
    default:
	/* some other error, ret is -1. */
	goto done;
    }

    /* If run as root with SUDO_USER set, set sudo_user.pw to that user. */
    /* XXX - causes confusion when root is not listed in sudoers */
    if (sudo_mode & (MODE_RUN | MODE_EDIT) && prev_user != NULL) {
	if (user_uid == 0 && strcmp(prev_user, "root") != 0) {
	    struct passwd *pw;

	    if ((pw = sudo_getpwnam(prev_user)) != NULL) {
		    if (sudo_user.pw != NULL)
			sudo_pw_delref(sudo_user.pw);
		    sudo_user.pw = pw;
	    }
	}
    }

    /* If the user was not allowed to run the command we are done. */
    if (!ISSET(validated, VALIDATE_SUCCESS)) {
	/* Note: log_failure() calls audit for us. */
	if (!log_failure(validated, cmnd_status))
	    goto done;
	goto bad;
    }

    /* Create Ubuntu-style dot file to indicate sudo was successful. */
    if (create_admin_success_flag() == -1)
	goto done;

    /* Finally tell the user if the command did not exist. */
    if (cmnd_status == NOT_FOUND_DOT) {
	audit_failure(NewArgc, NewArgv, N_("command in current directory"));
	sudo_warnx(U_("ignoring \"%s\" found in '.'\nUse \"sudo ./%s\" if this is the \"%s\" you wish to run."), user_cmnd, user_cmnd, user_cmnd);
	goto bad;
    } else if (cmnd_status == NOT_FOUND) {
	if (ISSET(sudo_mode, MODE_CHECK)) {
	    audit_failure(NewArgc, NewArgv, N_("%s: command not found"),
		NewArgv[0]);
	    sudo_warnx(U_("%s: command not found"), NewArgv[0]);
	} else {
	    audit_failure(NewArgc, NewArgv, N_("%s: command not found"),
		user_cmnd);
	    sudo_warnx(U_("%s: command not found"), user_cmnd);
	}
	goto bad;
    }

    /* If user specified a timeout make sure sudoers allows it. */
    if (!def_user_command_timeouts && user_timeout > 0) {
	/* XXX - audit/log? */
	sudo_warnx(U_("sorry, you are not allowed set a command timeout"));
	goto bad;
    }

    /* If user specified env vars make sure sudoers allows it. */
    if (ISSET(sudo_mode, MODE_RUN) && !def_setenv) {
	if (ISSET(sudo_mode, MODE_PRESERVE_ENV)) {
	    /* XXX - audit/log? */
	    sudo_warnx(U_("sorry, you are not allowed to preserve the environment"));
	    goto bad;
	} else {
	    if (!validate_env_vars(sudo_user.env_vars))
		goto bad;
	}
    }

    if (ISSET(sudo_mode, (MODE_RUN | MODE_EDIT))) {
	if ((def_log_input || def_log_output) && def_iolog_file && def_iolog_dir) {
	    const char prefix[] = "iolog_path=";
	    iolog_path = expand_iolog_path(prefix, def_iolog_dir,
		def_iolog_file, &sudo_user.iolog_file);
	    if (iolog_path == NULL) {
		if (!def_ignore_iolog_errors)
		    goto done;
		/* Unable to expand I/O log path, disable I/O logging. */
		def_log_input = false;
		def_log_output = false;
	    } else {
		sudo_user.iolog_file++;
	    }
	}
    }

    if (!log_allowed(validated) && !def_ignore_logfile_errors)
	goto bad;

    switch (sudo_mode & MODE_MASK) {
	case MODE_CHECK:
	    ret = display_cmnd(snl, list_pw ? list_pw : sudo_user.pw);
	    break;
	case MODE_LIST:
	    ret = display_privs(snl, list_pw ? list_pw : sudo_user.pw, verbose);
	    break;
	case MODE_VALIDATE:
	    /* Nothing to do. */
	    ret = true;
	    break;
	case MODE_RUN:
	case MODE_EDIT:
	    /* ret set by sudoers_policy_exec_setup() below. */
	    break;
	default:
	    /* Should not happen. */
	    sudo_warnx("internal error, unexpected sudo mode 0x%x", sudo_mode);
	    goto done;
    }

    /* Cleanup sudoers sources */
    TAILQ_FOREACH(nss, snl, entries) {
	nss->close(nss);
    }
    if (def_group_plugin)
	group_plugin_unload();
    init_parser(NULL, false, false);

    if (ISSET(sudo_mode, (MODE_VALIDATE|MODE_CHECK|MODE_LIST))) {
	/* ret already set appropriately */
	goto done;
    }

    /*
     * Set umask based on sudoers.
     * If user's umask is more restrictive, OR in those bits too
     * unless umask_override is set.
     */
    if (def_umask != ACCESSPERMS) {
	cmnd_umask = def_umask;
	if (!def_umask_override)
	    cmnd_umask |= user_umask;
    }

    if (ISSET(sudo_mode, MODE_LOGIN_SHELL)) {
	char *p;

	/* Convert /bin/sh -> -sh so shell knows it is a login shell */
	if ((p = strrchr(NewArgv[0], '/')) == NULL)
	    p = NewArgv[0];
	*p = '-';
	NewArgv[0] = p;

	/*
	 * Newer versions of bash require the --login option to be used
	 * in conjunction with the -c option even if the shell name starts
	 * with a '-'.  Unfortunately, bash 1.x uses -login, not --login
	 * so this will cause an error for that.
	 */
	if (NewArgc > 1 && strcmp(NewArgv[0], "-bash") == 0 &&
	    strcmp(NewArgv[1], "-c") == 0) {
	    /* Use the extra slot before NewArgv so we can store --login. */
	    NewArgv--;
	    NewArgc++;
	    NewArgv[0] = NewArgv[1];
	    NewArgv[1] = "--login";
	}

#if defined(_AIX) || (defined(__linux__) && !defined(HAVE_PAM))
	/* Insert system-wide environment variables. */
	if (!read_env_file(_PATH_ENVIRONMENT, true, false))
	    sudo_warn("%s", _PATH_ENVIRONMENT);
#endif
#ifdef HAVE_LOGIN_CAP_H
	/* Set environment based on login class. */
	if (login_class) {
	    login_cap_t *lc = login_getclass(login_class);
	    if (lc != NULL) {
		setusercontext(lc, runas_pw, runas_pw->pw_uid, LOGIN_SETPATH|LOGIN_SETENV);
		login_close(lc);
	    }
	}
#endif /* HAVE_LOGIN_CAP_H */
    }

    /* Insert system-wide environment variables. */
    if (def_restricted_env_file) {
	if (!read_env_file(def_restricted_env_file, false, true))
	    sudo_warn("%s", def_restricted_env_file);
    }
    if (def_env_file) {
	if (!read_env_file(def_env_file, false, false))
	    sudo_warn("%s", def_env_file);
    }

    /* Insert user-specified environment variables. */
    if (!insert_env_vars(sudo_user.env_vars))
	goto done;

    /* Note: must call audit before uid change. */
    if (ISSET(sudo_mode, MODE_EDIT)) {
	int edit_argc;
	const char *env_editor;

	free(safe_cmnd);
	safe_cmnd = find_editor(NewArgc - 1, NewArgv + 1, &edit_argc,
	    &edit_argv, NULL, &env_editor, false);
	if (safe_cmnd == NULL) {
	    if (errno != ENOENT)
		goto done;
	    audit_failure(NewArgc, NewArgv, N_("%s: command not found"),
		env_editor ? env_editor : def_editor);
	    sudo_warnx(U_("%s: command not found"),
		env_editor ? env_editor : def_editor);
	    goto bad;
	}
	if (audit_success(edit_argc, edit_argv) != 0 && !def_ignore_audit_errors)
	    goto done;

	/* We want to run the editor with the unmodified environment. */
	env_swap_old();
    } else {
	if (audit_success(NewArgc, NewArgv) != 0 && !def_ignore_audit_errors)
	    goto done;
    }

    /* Setup execution environment to pass back to front-end. */
    ret = sudoers_policy_exec_setup(edit_argv ? edit_argv : NewArgv,
	env_get(), cmnd_umask, iolog_path, closure);

    /* Zero out stashed copy of environment, it is owned by the front-end. */
    (void)env_init(NULL);

    goto done;

bad:
    ret = false;

done:
    if (!rewind_perms())
	ret = -1;

    restore_nproc();

    /* Destroy the password and group caches and free the contents. */
    sudo_freepwcache();
    sudo_freegrcache();

    sudo_warn_set_locale_func(NULL);

    debug_return_int(ret);
}

/*
 * Initialize timezone and fill in sudo_user struct.
 */
static bool
init_vars(char * const envp[])
{
    char * const * ep;
    bool unknown_user = false;
    debug_decl(init_vars, SUDOERS_DEBUG_PLUGIN)

    if (!sudoers_initlocale(setlocale(LC_ALL, NULL), def_sudoers_locale)) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_bool(false);
    }

#define MATCHES(s, v)	\
    (strncmp((s), (v), sizeof(v) - 1) == 0 && (s)[sizeof(v) - 1] != '\0')

    for (ep = envp; *ep; ep++) {
	switch (**ep) {
	    case 'K':
		if (MATCHES(*ep, "KRB5CCNAME="))
		    user_ccname = *ep + sizeof("KRB5CCNAME=") - 1;
		break;
	    case 'P':
		if (MATCHES(*ep, "PATH="))
		    user_path = *ep + sizeof("PATH=") - 1;
		break;
	    case 'S':
		if (MATCHES(*ep, "SUDO_PROMPT=")) {
		    /* Don't override "sudo -p prompt" */
		    if (user_prompt == NULL)
			user_prompt = *ep + sizeof("SUDO_PROMPT=") - 1;
		    break;
		}
		if (MATCHES(*ep, "SUDO_USER="))
		    prev_user = *ep + sizeof("SUDO_USER=") - 1;
		break;
	    }
    }
#undef MATCHES

    /*
     * Get a local copy of the user's passwd struct and group list if we
     * don't already have them.
     */
    if (sudo_user.pw == NULL) {
	if ((sudo_user.pw = sudo_getpwnam(user_name)) == NULL) {
	    /*
	     * It is not unusual for users to place "sudo -k" in a .logout
	     * file which can cause sudo to be run during reboot after the
	     * YP/NIS/NIS+/LDAP/etc daemon has died.
	     */
	    if (sudo_mode == MODE_KILL || sudo_mode == MODE_INVALIDATE) {
		sudo_warnx(U_("unknown uid: %u"), (unsigned int) user_uid);
		debug_return_bool(false);
	    }

	    /* Need to make a fake struct passwd for the call to log_warningx(). */
	    sudo_user.pw = sudo_mkpwent(user_name, user_uid, user_gid, NULL, NULL);
	    unknown_user = true;
	}
    }
    if (user_gid_list == NULL)
	user_gid_list = sudo_get_gidlist(sudo_user.pw, ENTRY_TYPE_ANY);

    /* Store initialize permissions so we can restore them later. */
    if (!set_perms(PERM_INITIAL))
	debug_return_bool(false);

    /* Set fqdn callback. */
    sudo_defs_table[I_FQDN].callback = cb_fqdn;

    /* Set group_plugin callback. */
    sudo_defs_table[I_GROUP_PLUGIN].callback = cb_group_plugin;

    /* Set runas callback. */
    sudo_defs_table[I_RUNAS_DEFAULT].callback = cb_runas_default;

    /* Set locale callback. */
    sudo_defs_table[I_SUDOERS_LOCALE].callback = sudoers_locale_callback;

    /* Set maxseq callback. */
    sudo_defs_table[I_MAXSEQ].callback = cb_maxseq;

    /* Set iolog_user callback. */
    sudo_defs_table[I_IOLOG_USER].callback = cb_iolog_user;

    /* Set iolog_group callback. */
    sudo_defs_table[I_IOLOG_GROUP].callback = cb_iolog_group;

    /* Set iolog_mode callback. */
    sudo_defs_table[I_IOLOG_MODE].callback = cb_iolog_mode;

    /* Set tty_tickets callback. */
    sudo_defs_table[I_TTY_TICKETS].callback = cb_tty_tickets;

    /* Set umask callback. */
    sudo_defs_table[I_UMASK].callback = cb_umask;

    /* It is now safe to use log_warningx() and set_perms() */
    if (unknown_user) {
	log_warningx(SLOG_SEND_MAIL, N_("unknown uid: %u"),
	    (unsigned int) user_uid);
	debug_return_bool(false);
    }

    /*
     * Set runas passwd/group entries based on command line or sudoers.
     * Note that if runas_group was specified without runas_user we
     * run the command as the invoking user.
     */
    if (runas_group != NULL) {
	if (!set_runasgr(runas_group, false))
	    debug_return_bool(false);
	if (!set_runaspw(runas_user ? runas_user : user_name, false))
	    debug_return_bool(false);
    } else {
	if (!set_runaspw(runas_user ? runas_user : def_runas_default, false))
	    debug_return_bool(false);
    }

    debug_return_bool(true);
}

/*
 * Fill in user_cmnd, user_args, user_base and user_stat variables
 * and apply any command-specific defaults entries.
 */
static int
set_cmnd(void)
{
    struct sudo_nss *nss;
    char *path = user_path;
    int ret = FOUND;
    debug_decl(set_cmnd, SUDOERS_DEBUG_PLUGIN)

    /* Allocate user_stat for find_path() and match functions. */
    user_stat = calloc(1, sizeof(struct stat));
    if (user_stat == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(NOT_FOUND_ERROR);
    }

    /* Default value for cmnd, overridden below. */
    if (user_cmnd == NULL)
	user_cmnd = NewArgv[0];

    if (sudo_mode & (MODE_RUN | MODE_EDIT | MODE_CHECK)) {
	if (ISSET(sudo_mode, MODE_RUN | MODE_CHECK)) {
	    if (def_secure_path && !user_is_exempt())
		path = def_secure_path;
	    if (!set_perms(PERM_RUNAS))
		debug_return_int(-1);
	    ret = find_path(NewArgv[0], &user_cmnd, user_stat, path,
		def_ignore_dot, NULL);
	    if (!restore_perms())
		debug_return_int(-1);
	    if (ret == NOT_FOUND) {
		/* Failed as root, try as invoking user. */
		if (!set_perms(PERM_USER))
		    debug_return_int(-1);
		ret = find_path(NewArgv[0], &user_cmnd, user_stat, path,
		    def_ignore_dot, NULL);
		if (!restore_perms())
		    debug_return_int(-1);
	    }
	    if (ret == NOT_FOUND_ERROR) {
		if (errno == ENAMETOOLONG)
		    audit_failure(NewArgc, NewArgv, N_("command too long"));
		log_warning(0, "%s", NewArgv[0]);
		debug_return_int(ret);
	    }
	}

	/* set user_args */
	if (NewArgc > 1) {
	    char *to, *from, **av;
	    size_t size, n;

	    /* Alloc and build up user_args. */
	    for (size = 0, av = NewArgv + 1; *av; av++)
		size += strlen(*av) + 1;
	    if (size == 0 || (user_args = malloc(size)) == NULL) {
		sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
		debug_return_int(-1);
	    }
	    if (ISSET(sudo_mode, MODE_SHELL|MODE_LOGIN_SHELL)) {
		/*
		 * When running a command via a shell, the sudo front-end
		 * escapes potential meta chars.  We unescape non-spaces
		 * for sudoers matching and logging purposes.
		 */
		for (to = user_args, av = NewArgv + 1; (from = *av); av++) {
		    while (*from) {
			if (from[0] == '\\' && !isspace((unsigned char)from[1]))
			    from++;
			*to++ = *from++;
		    }
		    *to++ = ' ';
		}
		*--to = '\0';
	    } else {
		for (to = user_args, av = NewArgv + 1; *av; av++) {
		    n = strlcpy(to, *av, size - (to - user_args));
		    if (n >= size - (to - user_args)) {
			sudo_warnx(U_("internal error, %s overflow"), __func__);
			debug_return_int(-1);
		    }
		    to += n;
		    *to++ = ' ';
		}
		*--to = '\0';
	    }
	}
    }

    if ((user_base = strrchr(user_cmnd, '/')) != NULL)
	user_base++;
    else
	user_base = user_cmnd;

    /* Convert "sudo sudoedit" -> "sudoedit" */
    if (ISSET(sudo_mode, MODE_RUN) && strcmp(user_base, "sudoedit") == 0) {
	CLR(sudo_mode, MODE_RUN);
	SET(sudo_mode, MODE_EDIT);
	sudo_warnx(U_("sudoedit doesn't need to be run via sudo"));
	user_base = user_cmnd = "sudoedit";
    }

    TAILQ_FOREACH(nss, snl, entries) {
	if (!update_defaults(nss->parse_tree, NULL, SETDEF_CMND, false)) {
	    log_warningx(SLOG_SEND_MAIL|SLOG_NO_STDERR,
		N_("problem with defaults entries"));
	}
    }

    debug_return_int(ret);
}

/*
 * Open sudoers and sanity check mode/owner/type.
 * Returns a handle to the sudoers file or NULL on error.
 */
FILE *
open_sudoers(const char *sudoers, bool doedit, bool *keepopen)
{
    struct stat sb;
    FILE *fp = NULL;
    bool perm_root = false;
    debug_decl(open_sudoers, SUDOERS_DEBUG_PLUGIN)

    if (!set_perms(PERM_SUDOERS))
	debug_return_ptr(NULL);

again:
    switch (sudo_secure_file(sudoers, sudoers_uid, sudoers_gid, &sb)) {
	case SUDO_PATH_SECURE:
	    /*
	     * If we are expecting sudoers to be group readable by
	     * SUDOERS_GID but it is not, we must open the file as root,
	     * not uid 1.
	     */
	    if (sudoers_uid == ROOT_UID && ISSET(sudoers_mode, S_IRGRP)) {
		if (!ISSET(sb.st_mode, S_IRGRP) || sb.st_gid != SUDOERS_GID) {
		    if (!perm_root) {
			if (!restore_perms() || !set_perms(PERM_ROOT))
			    debug_return_ptr(NULL);
		    }
		}
	    }
	    /*
	     * Open sudoers and make sure we can read it so we can present
	     * the user with a reasonable error message (unlike the lexer).
	     */
	    if ((fp = fopen(sudoers, "r")) == NULL) {
		log_warning(SLOG_SEND_MAIL, N_("unable to open %s"), sudoers);
	    } else {
		if (sb.st_size != 0 && fgetc(fp) == EOF) {
		    log_warning(SLOG_SEND_MAIL,
			N_("unable to read %s"), sudoers);
		    fclose(fp);
		    fp = NULL;
		} else {
		    /* Rewind fp and set close on exec flag. */
		    rewind(fp);
		    (void) fcntl(fileno(fp), F_SETFD, 1);
		}
	    }
	    break;
	case SUDO_PATH_MISSING:
	    /*
	     * If we tried to stat() sudoers as non-root but got EACCES,
	     * try again as root.
	     */
	    if (errno == EACCES && geteuid() != ROOT_UID) {
		int serrno = errno;
		if (restore_perms()) {
		    if (!set_perms(PERM_ROOT))
			debug_return_ptr(NULL);
		    perm_root = true;
		    goto again;
		}
		errno = serrno;
	    }
	    log_warning(SLOG_SEND_MAIL, N_("unable to stat %s"), sudoers);
	    break;
	case SUDO_PATH_BAD_TYPE:
	    log_warningx(SLOG_SEND_MAIL,
		N_("%s is not a regular file"), sudoers);
	    break;
	case SUDO_PATH_WRONG_OWNER:
	    log_warningx(SLOG_SEND_MAIL,
		N_("%s is owned by uid %u, should be %u"), sudoers,
		(unsigned int) sb.st_uid, (unsigned int) sudoers_uid);
	    break;
	case SUDO_PATH_WORLD_WRITABLE:
	    log_warningx(SLOG_SEND_MAIL, N_("%s is world writable"), sudoers);
	    break;
	case SUDO_PATH_GROUP_WRITABLE:
	    log_warningx(SLOG_SEND_MAIL,
		N_("%s is owned by gid %u, should be %u"), sudoers,
		(unsigned int) sb.st_gid, (unsigned int) sudoers_gid);
	    break;
	default:
	    /* NOTREACHED */
	    break;
    }

    if (!restore_perms()) {
	/* unable to change back to root */
	if (fp != NULL) {
	    fclose(fp);
	    fp = NULL;
	}
    }

    debug_return_ptr(fp);
}

#ifdef HAVE_LOGIN_CAP_H
static bool
set_loginclass(struct passwd *pw)
{
    const int errflags = SLOG_RAW_MSG;
    login_cap_t *lc;
    bool ret = true;
    debug_decl(set_loginclass, SUDOERS_DEBUG_PLUGIN)

    if (!def_use_loginclass)
	goto done;

    if (login_class && strcmp(login_class, "-") != 0) {
	if (user_uid != 0 && pw->pw_uid != 0) {
	    sudo_warnx(U_("only root can use \"-c %s\""), login_class);
	    ret = false;
	    goto done;
	}
    } else {
	login_class = pw->pw_class;
	if (!login_class || !*login_class)
	    login_class =
		(pw->pw_uid == 0) ? LOGIN_DEFROOTCLASS : LOGIN_DEFCLASS;
    }

    /* Make sure specified login class is valid. */
    lc = login_getclass(login_class);
    if (!lc || !lc->lc_class || strcmp(lc->lc_class, login_class) != 0) {
	/*
	 * Don't make it an error if the user didn't specify the login
	 * class themselves.  We do this because if login.conf gets
	 * corrupted we want the admin to be able to use sudo to fix it.
	 */
	log_warningx(errflags, N_("unknown login class: %s"), login_class);
	def_use_loginclass = false;
	if (login_class)
	    ret = false;
    }
    login_close(lc);
done:
    debug_return_bool(ret);
}
#else
static bool
set_loginclass(struct passwd *pw)
{
    return true;
}
#endif /* HAVE_LOGIN_CAP_H */

#ifndef AI_FQDN
# define AI_FQDN AI_CANONNAME
#endif

/*
 * Look up the fully qualified domain name of host.
 * Use AI_FQDN if available since "canonical" is not always the same as fqdn.
 * Returns true on success, setting longp and shortp.
 * Returns false on failure, longp and shortp are unchanged.
 */
static int
resolve_host(const char *host, char **longp, char **shortp)
{
    struct addrinfo *res0, hint;
    char *cp, *lname, *sname;
    int ret;
    debug_decl(resolve_host, SUDOERS_DEBUG_PLUGIN)

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_FQDN;

    if ((ret = getaddrinfo(host, NULL, &hint, &res0)) != 0)
	debug_return_int(ret);
    if ((lname = strdup(res0->ai_canonname)) == NULL) {
	freeaddrinfo(res0);
	debug_return_int(EAI_MEMORY);
    }
    if ((cp = strchr(lname, '.')) != NULL) {
	sname = strndup(lname, (size_t)(cp - lname));
	if (sname == NULL) {
	    free(lname);
	    freeaddrinfo(res0);
	    debug_return_int(EAI_MEMORY);
	}
    } else {
	sname = lname;
    }
    freeaddrinfo(res0);
    *longp = lname;
    *shortp = sname;

    debug_return_int(0);
}

/*
 * Look up the fully qualified domain name of user_host and user_runhost.
 * Sets user_host, user_shost, user_runhost and user_srunhost.
 */
static bool
cb_fqdn(const union sudo_defs_val *sd_un)
{
    bool remote;
    char *lhost, *shost;
    debug_decl(cb_fqdn, SUDOERS_DEBUG_PLUGIN)

    /* Nothing to do if fqdn flag is disabled. */
    if (sd_un != NULL && !sd_un->flag)
	debug_return_bool(true);

    /* If the -h flag was given we need to resolve both host and runhost. */
    remote = strcmp(user_runhost, user_host) != 0;

    /* First resolve user_host, setting user_host and user_shost. */
    if (resolve_host(user_host, &lhost, &shost) != 0) {
	int rc = resolve_host(user_runhost, &lhost, &shost);
	if (rc != 0) {
	    gai_log_warning(SLOG_SEND_MAIL|SLOG_RAW_MSG, rc,
		N_("unable to resolve host %s"), user_host);
	    debug_return_bool(false);
	}
    }
    if (user_shost != user_host)
	free(user_shost);
    free(user_host);
    user_host = lhost;
    user_shost = shost;

    /* Next resolve user_runhost, setting user_runhost and user_srunhost. */
    lhost = shost = NULL;
    if (remote) {
	if (!resolve_host(user_runhost, &lhost, &shost)) {
	    sudo_warnx(U_("unable to resolve host %s"), user_runhost);
	}
    } else {
	/* Not remote, just use user_host. */
	if ((lhost = strdup(user_host)) != NULL) {
	    if (user_shost != user_host)
		shost = strdup(user_shost);
	    else
		shost = lhost;
	}
	if (lhost == NULL || shost == NULL) {
	    free(lhost);
	    if (lhost != shost)
		free(shost);
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    debug_return_bool(false);
	}
    }
    if (lhost != NULL && shost != NULL) {
	if (user_srunhost != user_runhost)
	    free(user_srunhost);
	free(user_runhost);
	user_runhost = lhost;
	user_srunhost = shost;
    }

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"host %s, shost %s, runhost %s, srunhost %s",
	user_host, user_shost, user_runhost, user_srunhost);
    debug_return_bool(true);
}

/*
 * Get passwd entry for the user we are going to run commands as
 * and store it in runas_pw.  By default, commands run as "root".
 */
static bool
set_runaspw(const char *user, bool quiet)
{
    struct passwd *pw = NULL;
    debug_decl(set_runaspw, SUDOERS_DEBUG_PLUGIN)

    unknown_runas_uid = false;
    if (*user == '#') {
	const char *errstr;
	uid_t uid = sudo_strtoid(user + 1, &errstr);
	if (errstr == NULL) {
	    if ((pw = sudo_getpwuid(uid)) == NULL) {
		unknown_runas_uid = true;
		pw = sudo_fakepwnam(user, user_gid);
	    }
	}
    }
    if (pw == NULL) {
	if ((pw = sudo_getpwnam(user)) == NULL) {
	    if (!quiet)
		log_warningx(SLOG_RAW_MSG, N_("unknown user: %s"), user);
	    debug_return_bool(false);
	}
    }
    if (runas_pw != NULL)
	sudo_pw_delref(runas_pw);
    runas_pw = pw;
    debug_return_bool(true);
}

/*
 * Get group entry for the group we are going to run commands as
 * and store it in runas_gr.
 */
static bool
set_runasgr(const char *group, bool quiet)
{
    struct group *gr = NULL;
    debug_decl(set_runasgr, SUDOERS_DEBUG_PLUGIN)

    unknown_runas_gid = false;
    if (*group == '#') {
	const char *errstr;
	gid_t gid = sudo_strtoid(group + 1, &errstr);
	if (errstr == NULL) {
	    if ((gr = sudo_getgrgid(gid)) == NULL) {
		unknown_runas_gid = true;
		gr = sudo_fakegrnam(group);
	    }
	}
    }
    if (gr == NULL) {
	if ((gr = sudo_getgrnam(group)) == NULL) {
	    if (!quiet)
		log_warningx(SLOG_RAW_MSG, N_("unknown group: %s"), group);
	    debug_return_bool(false);
	}
    }
    if (runas_gr != NULL)
	sudo_gr_delref(runas_gr);
    runas_gr = gr;
    debug_return_bool(true);
}

/*
 * Callback for runas_default sudoers setting.
 */
static bool
cb_runas_default(const union sudo_defs_val *sd_un)
{
    debug_decl(cb_runas_default, SUDOERS_DEBUG_PLUGIN)

    /* Only reset runaspw if user didn't specify one. */
    if (!runas_user && !runas_group)
	debug_return_bool(set_runaspw(sd_un->str, true));
    debug_return_bool(true);
}

/*
 * Callback for tty_tickets sudoers setting.
 */
static bool
cb_tty_tickets(const union sudo_defs_val *sd_un)
{
    debug_decl(cb_tty_tickets, SUDOERS_DEBUG_PLUGIN)

    /* Convert tty_tickets -> timestamp_type */
    if (sd_un->flag)
	def_timestamp_type = tty;
    else
	def_timestamp_type = global;
    debug_return_bool(true);
}

/*
 * Callback for umask sudoers setting.
 */
static bool
cb_umask(const union sudo_defs_val *sd_un)
{
    debug_decl(cb_umask, SUDOERS_DEBUG_PLUGIN)

    /* Force umask if explicitly set in sudoers. */
    force_umask = sd_un->mode != ACCESSPERMS;

    debug_return_bool(true);
}

/*
 * Cleanup hook for sudo_fatal()/sudo_fatalx()
 */
void
sudoers_cleanup(void)
{
    struct sudo_nss *nss;
    debug_decl(sudoers_cleanup, SUDOERS_DEBUG_PLUGIN)

    if (snl != NULL) {
	TAILQ_FOREACH(nss, snl, entries) {
	    nss->close(nss);
	}
    }
    if (def_group_plugin)
	group_plugin_unload();
    sudo_freepwcache();
    sudo_freegrcache();

    debug_return;
}

#ifdef USE_ADMIN_FLAG
static int
create_admin_success_flag(void)
{
    char flagfile[PATH_MAX];
    int len, ret = -1;
    debug_decl(create_admin_success_flag, SUDOERS_DEBUG_PLUGIN)

    /* Check whether the user is in the sudo or admin group. */
    if (!user_in_group(sudo_user.pw, "sudo") &&
	!user_in_group(sudo_user.pw, "admin"))
	debug_return_int(true);

    /* Build path to flag file. */
    len = snprintf(flagfile, sizeof(flagfile), "%s/.sudo_as_admin_successful",
	user_dir);
    if (len < 0 || len >= ssizeof(flagfile))
	debug_return_int(false);

    /* Create admin flag file if it doesn't already exist. */
    if (set_perms(PERM_USER)) {
	int fd = open(flagfile, O_CREAT|O_WRONLY|O_NONBLOCK|O_EXCL, 0644);
	ret = fd != -1 || errno == EEXIST;
	if (fd != -1)
	    close(fd);
	if (!restore_perms())
	    ret = -1;
    }
    debug_return_int(ret);
}
#else /* !USE_ADMIN_FLAG */
static int
create_admin_success_flag(void)
{
    /* STUB */
    return true;
}
#endif /* USE_ADMIN_FLAG */

static bool
tty_present(void)
{
    debug_decl(tty_present, SUDOERS_DEBUG_PLUGIN)
    
    if (user_ttypath == NULL) {
	int fd = open(_PATH_TTY, O_RDWR);
	if (fd == -1)
	    debug_return_bool(false);
	close(fd);
    }
    debug_return_bool(true);
}
