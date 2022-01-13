/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1999-2005, 2007-2018
 *	Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <pwd.h>
#include <ctype.h>
#include <syslog.h>

#include "sudoers.h"
#include <gram.h>

/*
 * For converting between syslog numbers and strings.
 */
struct strmap {
    char *name;
    int num;
};

static struct strmap facilities[] = {
#ifdef LOG_AUTHPRIV
	{ "authpriv",	LOG_AUTHPRIV },
#endif
	{ "auth",	LOG_AUTH },
	{ "daemon",	LOG_DAEMON },
	{ "user",	LOG_USER },
	{ "local0",	LOG_LOCAL0 },
	{ "local1",	LOG_LOCAL1 },
	{ "local2",	LOG_LOCAL2 },
	{ "local3",	LOG_LOCAL3 },
	{ "local4",	LOG_LOCAL4 },
	{ "local5",	LOG_LOCAL5 },
	{ "local6",	LOG_LOCAL6 },
	{ "local7",	LOG_LOCAL7 },
	{ NULL,		-1 }
};

static struct strmap priorities[] = {
	{ "alert",	LOG_ALERT },
	{ "crit",	LOG_CRIT },
	{ "debug",	LOG_DEBUG },
	{ "emerg",	LOG_EMERG },
	{ "err",	LOG_ERR },
	{ "info",	LOG_INFO },
	{ "notice",	LOG_NOTICE },
	{ "warning",	LOG_WARNING },
	{ "none",	-1 },
	{ NULL,		-1 }
};

static struct early_default early_defaults[] = {
    { I_IGNORE_UNKNOWN_DEFAULTS },
#ifdef FQDN
    { I_FQDN, true },
#else
    { I_FQDN },
#endif
    { I_MATCH_GROUP_BY_GID },
    { I_GROUP_PLUGIN },
    { I_RUNAS_DEFAULT },
    { I_SUDOERS_LOCALE },
    { -1 }
};

/*
 * Local prototypes.
 */
static bool store_int(const char *str, union sudo_defs_val *sd_un);
static bool store_list(const char *str, union sudo_defs_val *sd_un, int op);
static bool store_mode(const char *str, union sudo_defs_val *sd_un);
static int  store_str(const char *str, union sudo_defs_val *sd_un);
static bool store_syslogfac(const char *str, union sudo_defs_val *sd_un);
static bool store_syslogpri(const char *str, union sudo_defs_val *sd_un);
static bool store_timeout(const char *str, union sudo_defs_val *sd_un);
static bool store_tuple(const char *str, union sudo_defs_val *sd_un, struct def_values *tuple_vals);
static bool store_uint(const char *str, union sudo_defs_val *sd_un);
static bool store_timespec(const char *str, union sudo_defs_val *sd_un);
static bool list_op(const char *str, size_t, union sudo_defs_val *sd_un, enum list_ops op);
static const char *logfac2str(int);
static const char *logpri2str(int);

/*
 * Table describing compile-time and run-time options.
 */
#include <def_data.c>

/*
 * Print version and configure info.
 */
void
dump_defaults(void)
{
    struct sudo_defs_types *cur;
    struct list_member *item;
    struct def_values *def;
    char *desc;
    debug_decl(dump_defaults, SUDOERS_DEBUG_DEFAULTS)

    for (cur = sudo_defs_table; cur->name; cur++) {
	if (cur->desc) {
	    desc = _(cur->desc);
	    switch (cur->type & T_MASK) {
		case T_FLAG:
		    if (cur->sd_un.flag)
			sudo_printf(SUDO_CONV_INFO_MSG, "%s\n", desc);
		    break;
		case T_STR:
		    if (cur->sd_un.str) {
			sudo_printf(SUDO_CONV_INFO_MSG, desc, cur->sd_un.str);
			sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    }
		    break;
		case T_LOGFAC:
		    if (cur->sd_un.ival) {
			sudo_printf(SUDO_CONV_INFO_MSG, desc,
			    logfac2str(cur->sd_un.ival));
			sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    }
		    break;
		case T_LOGPRI:
		    if (cur->sd_un.ival) {
			sudo_printf(SUDO_CONV_INFO_MSG, desc,
			    logpri2str(cur->sd_un.ival));
			sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    }
		    break;
		case T_INT:
		    sudo_printf(SUDO_CONV_INFO_MSG, desc, cur->sd_un.ival);
		    sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    break;
		case T_UINT:
		    sudo_printf(SUDO_CONV_INFO_MSG, desc, cur->sd_un.uival);
		    sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    break;
		case T_TIMESPEC: {
		    /* display timespec in minutes as a double */
		    double d = cur->sd_un.tspec.tv_sec +
			(cur->sd_un.tspec.tv_nsec / 1000000000.0);
		    sudo_printf(SUDO_CONV_INFO_MSG, desc, d / 60.0);
		    sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    break;
		}
		case T_MODE:
		    sudo_printf(SUDO_CONV_INFO_MSG, desc, cur->sd_un.mode);
		    sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    break;
		case T_LIST:
		    if (!SLIST_EMPTY(&cur->sd_un.list)) {
			sudo_printf(SUDO_CONV_INFO_MSG, "%s\n", desc);
			SLIST_FOREACH(item, &cur->sd_un.list, entries) {
			    sudo_printf(SUDO_CONV_INFO_MSG,
				"\t%s\n", item->value);
			}
		    }
		    break;
		case T_TIMEOUT:
		    if (cur->sd_un.ival) {
			sudo_printf(SUDO_CONV_INFO_MSG, desc,
			    cur->sd_un.ival);
			sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    }
		    break;
		case T_TUPLE:
		    for (def = cur->values; def->sval; def++) {
			if (cur->sd_un.tuple == def->nval) {
			    sudo_printf(SUDO_CONV_INFO_MSG, desc, def->sval);
			    break;
			}
		    }
		    sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    break;
	    }
	}
    }
    debug_return;
}

/*
 * Find the index of the specified Defaults name in sudo_defs_table[]
 * On success, returns the matching index or -1 on failure.
 */
static int
find_default(const char *name, const char *file, int lineno, bool quiet)
{
    int i;
    debug_decl(find_default, SUDOERS_DEBUG_DEFAULTS)

    for (i = 0; sudo_defs_table[i].name != NULL; i++) {
	if (strcmp(name, sudo_defs_table[i].name) == 0)
	    debug_return_int(i);
    }
    if (!quiet && !def_ignore_unknown_defaults) {
	if (lineno > 0) {
	    sudo_warnx(U_("%s:%d unknown defaults entry \"%s\""),
		file, lineno, name);
	} else {
	    sudo_warnx(U_("%s: unknown defaults entry \"%s\""),
		file, name);
	}
    }
    debug_return_int(-1);
}

/*
 * Parse a defaults entry, storing the parsed entry in sd_un.
 * Returns true on success or false on failure.
 */
static bool
parse_default_entry(struct sudo_defs_types *def, const char *val, int op,
    union sudo_defs_val *sd_un, const char *file, int lineno, bool quiet)
{
    int rc;
    debug_decl(parse_default_entry, SUDOERS_DEBUG_DEFAULTS)

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: %s:%d %s=%s op=%d",
	__func__, file, lineno, def->name, val ? val : "", op);

    /*
     * If no value specified, the boolean flag must be set for non-flags.
     * Only flags and tuples support boolean "true".
     */
    if (val == NULL) {
	switch (def->type & T_MASK) {
	case T_FLAG:
	    break;
	case T_TUPLE:
	    if (ISSET(def->type, T_BOOL))
		break;
	    /* FALLTHROUGH */
	case T_LOGFAC:
	    if (op == true) {
		/* Use default syslog facility if none specified. */
		val = LOGFAC;
	    }
	    break;
	default:
	    if (!ISSET(def->type, T_BOOL) || op != false) {
		if (!quiet) {
		    if (lineno > 0) {
			sudo_warnx(U_("%s:%d no value specified for \"%s\""),
			    file, lineno, def->name);
		    } else {
			sudo_warnx(U_("%s: no value specified for \"%s\""),
			    file, def->name);
		    }
		}
		debug_return_bool(false);
	    }
	}
    }

    switch (def->type & T_MASK) {
	case T_LOGFAC:
	    rc = store_syslogfac(val, sd_un);
	    break;
	case T_LOGPRI:
	    rc = store_syslogpri(val, sd_un);
	    break;
	case T_STR:
	    if (ISSET(def->type, T_PATH) && val != NULL && *val != '/') {
		if (!quiet) {
		    if (lineno > 0) {
			sudo_warnx(U_("%s:%d values for \"%s\" must start with a '/'"),
			    file, lineno, def->name);
		    } else {
			sudo_warnx(U_("%s: values for \"%s\" must start with a '/'"),
			    file, def->name);
		    }
		}
		rc = -1;
		break;
	    }
	    rc =  store_str(val, sd_un);
	    break;
	case T_INT:
	    rc = store_int(val, sd_un);
	    break;
	case T_UINT:
	    rc = store_uint(val, sd_un);
	    break;
	case T_MODE:
	    rc = store_mode(val, sd_un);
	    break;
	case T_FLAG:
	    if (val != NULL) {
		if (!quiet) {
		    if (lineno > 0) {
			sudo_warnx(U_("%s:%d option \"%s\" does not take a value"),
			    file, lineno, def->name);
		    } else {
			sudo_warnx(U_("%s: option \"%s\" does not take a value"),
			    file, def->name);
		    }
		}
		rc = -1;
		break;
	    }
	    sd_un->flag = op;
	    rc = true;
	    break;
	case T_LIST:
	    rc = store_list(val, sd_un, op);
	    break;
	case T_TIMEOUT:
	    rc = store_timeout(val, sd_un);
	    break;
	case T_TUPLE:
	    rc = store_tuple(val, sd_un, def->values);
	    break;
	case T_TIMESPEC:
	    rc = store_timespec(val, sd_un);
	    break;
	default:
	    if (!quiet) {
		if (lineno > 0) {
		    sudo_warnx(U_("%s:%d invalid Defaults type 0x%x for option \"%s\""),
			file, lineno, def->type, def->name);
		} else {
		    sudo_warnx(U_("%s: invalid Defaults type 0x%x for option \"%s\""),
			file, def->type, def->name);
		}
	    }
	    rc = -1;
	    break;
    }
    if (rc == false) {
	if (!quiet) {
	    if (lineno > 0) {
		sudo_warnx(U_("%s:%d value \"%s\" is invalid for option \"%s\""),
		    file, lineno, val, def->name);
	    } else {
		sudo_warnx(U_("%s: value \"%s\" is invalid for option \"%s\""),
		    file, val, def->name);
	    }
	}
    }

    debug_return_bool(rc == true);
}

struct early_default *
is_early_default(const char *name)
{
    struct early_default *early;
    debug_decl(is_early_default, SUDOERS_DEBUG_DEFAULTS)

    for (early = early_defaults; early->idx != -1; early++) {
	if (strcmp(name, sudo_defs_table[early->idx].name) == 0)
	    debug_return_ptr(early);
    }
    debug_return_ptr(NULL);
}

static bool
run_callback(struct sudo_defs_types *def)
{
    debug_decl(run_callback, SUDOERS_DEBUG_DEFAULTS)

    if (def->callback == NULL)
	debug_return_bool(true);
    debug_return_bool(def->callback(&def->sd_un));
}

/*
 * Sets/clears an entry in the defaults structure.
 * Runs the callback if present on success.
 */
bool
set_default(const char *var, const char *val, int op, const char *file,
    int lineno, bool quiet)
{
    int idx;
    debug_decl(set_default, SUDOERS_DEBUG_DEFAULTS)

    idx = find_default(var, file, lineno, quiet);
    if (idx != -1) {
	/* Set parsed value in sudo_defs_table and run callback (if any). */
	struct sudo_defs_types *def = &sudo_defs_table[idx];
	if (parse_default_entry(def, val, op, &def->sd_un, file, lineno, quiet))
	    debug_return_bool(run_callback(def));
    }
    debug_return_bool(false);
}

/*
 * Like set_default() but stores the matching default value
 * and does not run callbacks.
 */
bool
set_early_default(const char *var, const char *val, int op, const char *file,
    int lineno, bool quiet, struct early_default *early)
{
    int idx;
    debug_decl(set_early_default, SUDOERS_DEBUG_DEFAULTS)

    idx = find_default(var, file, lineno, quiet);
    if (idx != -1) {
	/* Set parsed value in sudo_defs_table but defer callback (if any). */
	struct sudo_defs_types *def = &sudo_defs_table[idx];
	if (parse_default_entry(def, val, op, &def->sd_un, file, lineno, quiet)) {
	    early->run_callback = true;
	    debug_return_bool(true);
	}
    }
    debug_return_bool(false);
}

/*
 * Run callbacks for early defaults.
 */
bool
run_early_defaults(void)
{
    struct early_default *early;
    bool ret = true;
    debug_decl(run_early_defaults, SUDOERS_DEBUG_DEFAULTS)

    for (early = early_defaults; early->idx != -1; early++) {
	if (early->run_callback) {
	    if (!run_callback(&sudo_defs_table[early->idx]))
		ret = false;
	    early->run_callback = false;
	}
    }
    debug_return_bool(ret);
}

static void
free_defs_val(int type, union sudo_defs_val *sd_un)
{
    switch (type & T_MASK) {
	case T_STR:
	    free(sd_un->str);
	    break;
	case T_LIST:
	    (void)list_op(NULL, 0, sd_un, freeall);
	    break;
    }
    memset(sd_un, 0, sizeof(*sd_un));
}

/*
 * Set default options to compiled-in values.
 * Any of these may be overridden at runtime by a "Defaults" file.
 */
bool
init_defaults(void)
{
    static int firsttime = 1;
    struct sudo_defs_types *def;
    debug_decl(init_defaults, SUDOERS_DEBUG_DEFAULTS)

    /* Clear any old settings. */
    if (!firsttime) {
	for (def = sudo_defs_table; def->name != NULL; def++)
	    free_defs_val(def->type, &def->sd_un);
    }

    /* First initialize the flags. */
#ifdef LONG_OTP_PROMPT
    def_long_otp_prompt = true;
#endif
#ifdef IGNORE_DOT_PATH
    def_ignore_dot = true;
#endif
#ifdef ALWAYS_SEND_MAIL
    def_mail_always = true;
#endif
#ifdef SEND_MAIL_WHEN_NO_USER
    def_mail_no_user = true;
#endif
#ifdef SEND_MAIL_WHEN_NO_HOST
    def_mail_no_host = true;
#endif
#ifdef SEND_MAIL_WHEN_NOT_OK
    def_mail_no_perms = true;
#endif
#ifndef NO_LECTURE
    def_lecture = once;
#endif
#ifndef NO_AUTHENTICATION
    def_authenticate = true;
#endif
#ifndef NO_ROOT_SUDO
    def_root_sudo = true;
#endif
#ifdef HOST_IN_LOG
    def_log_host = true;
#endif
#ifdef SHELL_IF_NO_ARGS
    def_shell_noargs = true;
#endif
#ifdef SHELL_SETS_HOME
    def_set_home = true;
#endif
#ifndef DONT_LEAK_PATH_INFO
    def_path_info = true;
#endif
#ifdef USE_INSULTS
    def_insults = true;
#endif
#ifdef FQDN
    def_fqdn = true;
#endif
#ifdef ENV_EDITOR
    def_env_editor = true;
#endif
#ifdef UMASK_OVERRIDE
    def_umask_override = true;
#endif
    def_timestamp_type = TIMESTAMP_TYPE;
    if ((def_iolog_file = strdup("%{seq}")) == NULL)
	goto oom;
    if ((def_iolog_dir = strdup(_PATH_SUDO_IO_LOGDIR)) == NULL)
	goto oom;
    if ((def_sudoers_locale = strdup("C")) == NULL)
	goto oom;
    def_env_reset = ENV_RESET;
    def_set_logname = true;
    def_closefrom = STDERR_FILENO + 1;
    if ((def_pam_service = strdup("sudo")) == NULL)
	goto oom;
#ifdef HAVE_PAM_LOGIN
    if ((def_pam_login_service = strdup("sudo-i")) == NULL)
	goto oom;
#else
    if ((def_pam_login_service = strdup("sudo")) == NULL)
	goto oom;
#endif
#ifdef NO_PAM_SESSION
    def_pam_session = false;
#else
    def_pam_session = true;
#endif
#ifdef HAVE_INNETGR
    def_use_netgroups = true;
#endif
    def_netgroup_tuple = false;
    def_sudoedit_checkdir = true;
    def_iolog_mode = S_IRUSR|S_IWUSR;
    def_fdexec = digest_only;
    def_log_allowed = true;
    def_log_denied = true;
    def_runas_allow_unknown_id = false;

    /* Syslog options need special care since they both strings and ints */
#if (LOGGING & SLOG_SYSLOG)
    (void) store_syslogfac(LOGFAC, &sudo_defs_table[I_SYSLOG].sd_un);
    (void) store_syslogpri(PRI_SUCCESS, &sudo_defs_table[I_SYSLOG_GOODPRI].sd_un);
    (void) store_syslogpri(PRI_FAILURE, &sudo_defs_table[I_SYSLOG_BADPRI].sd_un);
#endif

    /* Password flags also have a string and integer component. */
    (void) store_tuple("any", &sudo_defs_table[I_LISTPW].sd_un, sudo_defs_table[I_LISTPW].values);
    (void) store_tuple("all", &sudo_defs_table[I_VERIFYPW].sd_un, sudo_defs_table[I_VERIFYPW].values);

    /* Then initialize the int-like things. */
#ifdef SUDO_UMASK
    def_umask = SUDO_UMASK;
#else
    def_umask = ACCESSPERMS;
#endif
    def_loglinelen = MAXLOGFILELEN;
    def_timestamp_timeout.tv_sec = TIMEOUT * 60;
    def_passwd_timeout.tv_sec = PASSWORD_TIMEOUT * 60;
    def_passwd_tries = TRIES_FOR_PASSWORD;
#ifdef HAVE_ZLIB_H
    def_compress_io = true;
#endif
    def_ignore_audit_errors = true;
    def_ignore_iolog_errors = false;
    def_ignore_logfile_errors = true;

    /* Now do the strings */
    if ((def_mailto = strdup(MAILTO)) == NULL)
	goto oom;
    if ((def_mailsub = strdup(N_(MAILSUBJECT))) == NULL)
	goto oom;
    if ((def_badpass_message = strdup(_(INCORRECT_PASSWORD))) == NULL)
	goto oom;
    if ((def_lecture_status_dir = strdup(_PATH_SUDO_LECTURE_DIR)) == NULL)
	goto oom;
    if ((def_timestampdir = strdup(_PATH_SUDO_TIMEDIR)) == NULL)
	goto oom;
    if ((def_passprompt = strdup(_(PASSPROMPT))) == NULL)
	goto oom;
    if ((def_runas_default = strdup(RUNAS_DEFAULT)) == NULL)
	goto oom;
#ifdef _PATH_SUDO_SENDMAIL
    if ((def_mailerpath = strdup(_PATH_SUDO_SENDMAIL)) == NULL)
	goto oom;
#endif
    if ((def_mailerflags = strdup("-t")) == NULL)
	goto oom;
#if (LOGGING & SLOG_FILE)
    if ((def_logfile = strdup(_PATH_SUDO_LOGFILE)) == NULL)
	goto oom;
#endif
#ifdef EXEMPTGROUP
    if ((def_exempt_group = strdup(EXEMPTGROUP)) == NULL)
	goto oom;
#endif
#ifdef SECURE_PATH
    if ((def_secure_path = strdup(SECURE_PATH)) == NULL)
	goto oom;
#endif
    if ((def_editor = strdup(EDITOR)) == NULL)
	goto oom;
    def_set_utmp = true;
    def_pam_acct_mgmt = true;
    def_pam_setcred = true;
    def_syslog_maxlen = MAXSYSLOGLEN;
    def_case_insensitive_user = true;
    def_case_insensitive_group = true;

    /* Reset the locale. */
    if (!firsttime) {
	if (!sudoers_initlocale(NULL, def_sudoers_locale))
	    goto oom;
    }

    /* Finally do the lists (currently just environment tables). */
    if (!init_envtables())
	goto oom;

    firsttime = 0;

    debug_return_bool(true);
oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    debug_return_bool(false);
}

/*
 * Check whether a defaults entry matches the specified type.
 * Returns true if it matches, else false.
 */
static bool
default_type_matches(struct defaults *d, int what)
{
    debug_decl(default_type_matches, SUDOERS_DEBUG_DEFAULTS)

    switch (d->type) {
    case DEFAULTS:
	if (ISSET(what, SETDEF_GENERIC))
	    debug_return_bool(true);
	break;
    case DEFAULTS_USER:
	if (ISSET(what, SETDEF_USER))
	    debug_return_bool(true);
	break;
    case DEFAULTS_RUNAS:
	if (ISSET(what, SETDEF_RUNAS))
	    debug_return_bool(true);
	break;
    case DEFAULTS_HOST:
	if (ISSET(what, SETDEF_HOST))
	    debug_return_bool(true);
	break;
    case DEFAULTS_CMND:
	if (ISSET(what, SETDEF_CMND))
	    debug_return_bool(true);
	break;
    }
    debug_return_bool(false);
}

/*
 * Check whether a defaults entry's binding matches.
 * Returns true if it matches, else false.
 */
static bool
default_binding_matches(struct sudoers_parse_tree *parse_tree,
    struct defaults *d, int what)
{
    debug_decl(default_binding_matches, SUDOERS_DEBUG_DEFAULTS)

    switch (d->type) {
    case DEFAULTS:
	debug_return_bool(true);
	break;
    case DEFAULTS_USER:
	if (userlist_matches(parse_tree, sudo_user.pw, d->binding) == ALLOW)
	    debug_return_bool(true);
	break;
    case DEFAULTS_RUNAS:
	if (runaslist_matches(parse_tree, d->binding, NULL, NULL, NULL) == ALLOW)
	    debug_return_bool(true);
	break;
    case DEFAULTS_HOST:
	if (hostlist_matches(parse_tree, sudo_user.pw, d->binding) == ALLOW)
	    debug_return_bool(true);
	break;
    case DEFAULTS_CMND:
	if (cmndlist_matches(parse_tree, d->binding) == ALLOW)
	    debug_return_bool(true);
	break;
    }
    debug_return_bool(false);
}

/*
 * Update the global defaults based on the given defaults list.
 * Pass in an OR'd list of which default types to update.
 */
bool
update_defaults(struct sudoers_parse_tree *parse_tree,
    struct defaults_list *defs, int what, bool quiet)
{
    struct defaults *d;
    bool ret = true;
    debug_decl(update_defaults, SUDOERS_DEBUG_DEFAULTS)

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"what: 0x%02x", what);

    /* If no defaults list specified, use the global one in the parse tree. */
    if (defs == NULL)
	defs = &parse_tree->defaults;

    /*
     * First apply Defaults values marked as early.
     */
    TAILQ_FOREACH(d, defs, entries) {
	struct early_default *early = is_early_default(d->var);
	if (early == NULL)
	    continue;

	/* Defaults type and binding must match. */
	if (!default_type_matches(d, what) ||
	    !default_binding_matches(parse_tree, d, what))
	    continue;

	/* Copy the value to sudo_defs_table and mark as early. */
	if (!set_early_default(d->var, d->val, d->op, d->file, d->lineno,
	    quiet, early))
	    ret = false;
    }
    /* Run callbacks for early defaults (if any) */
    if (!run_early_defaults())
	ret = false;

    /*
     * Then set the rest of the defaults.
     */
    TAILQ_FOREACH(d, defs, entries) {
	/* Skip Defaults marked as early, we already did them. */
	if (is_early_default(d->var))
	    continue;

	/* Defaults type and binding must match. */
	if (!default_type_matches(d, what) ||
	    !default_binding_matches(parse_tree, d, what))
	    continue;

	/* Copy the value to sudo_defs_table and run callback (if any) */
	if (!set_default(d->var, d->val, d->op, d->file, d->lineno, quiet))
	    ret = false;
    }
    debug_return_bool(ret);
}

/*
 * Check all defaults entries without actually setting them.
 */
bool
check_defaults(struct sudoers_parse_tree *parse_tree, bool quiet)
{
    struct defaults *d;
    bool ret = true;
    int idx;
    debug_decl(check_defaults, SUDOERS_DEBUG_DEFAULTS)

    TAILQ_FOREACH(d, &parse_tree->defaults, entries) {
	idx = find_default(d->var, d->file, d->lineno, quiet);
	if (idx != -1) {
	    struct sudo_defs_types *def = &sudo_defs_table[idx];
	    union sudo_defs_val sd_un;
	    memset(&sd_un, 0, sizeof(sd_un));
	    if (parse_default_entry(def, d->val, d->op, &sd_un, d->file,
		d->lineno, quiet)) {
		free_defs_val(def->type, &sd_un);
		continue;
	    }
	}
	/* There was an error in the entry, flag it. */
	d->error = true;
	ret = false;
    }
    debug_return_bool(ret);
}

static bool
store_int(const char *str, union sudo_defs_val *sd_un)
{
    const char *errstr;
    int i;
    debug_decl(store_int, SUDOERS_DEBUG_DEFAULTS)

    if (str == NULL) {
	sd_un->ival = 0;
    } else {
	i = sudo_strtonum(str, INT_MIN, INT_MAX, &errstr);
	if (errstr != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"%s: %s", str, errstr);
	    debug_return_bool(false);
	}
	sd_un->ival = i;
    }
    debug_return_bool(true);
}

static bool
store_uint(const char *str, union sudo_defs_val *sd_un)
{
    const char *errstr;
    unsigned int u;
    debug_decl(store_uint, SUDOERS_DEBUG_DEFAULTS)

    if (str == NULL) {
	sd_un->uival = 0;
    } else {
	u = sudo_strtonum(str, 0, UINT_MAX, &errstr);
	if (errstr != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"%s: %s", str, errstr);
	    debug_return_bool(false);
	}
	sd_un->uival = u;
    }
    debug_return_bool(true);
}

static bool
store_timespec(const char *str, union sudo_defs_val *sd_un)
{
    struct timespec ts;
    char sign = '+';
    int i;
    debug_decl(store_timespec, SUDOERS_DEBUG_DEFAULTS)

    sudo_timespecclear(&ts);
    if (str != NULL) {
	/* Convert from minutes to timespec. */
	if (*str == '+' || *str == '-')
	    sign = *str++;
	while (*str != '\0' && *str != '.') {
		if (!isdigit((unsigned char)*str))
		    debug_return_bool(false);	/* invalid number */
		if (ts.tv_sec > TIME_T_MAX / 10)
		    debug_return_bool(false);	/* overflow */
		ts.tv_sec *= 10;
		ts.tv_sec += *str++ - '0';
	}
	if (*str++ == '.') {
	    /* Convert optional fractional component to nanosecs. */
	    for (i = 100000000; i > 0; i /= 10) {
		if (*str == '\0')
		    break;
		if (!isdigit((unsigned char)*str))
		    debug_return_bool(false);	/* invalid number */
		ts.tv_nsec += i * (*str++ - '0');
	    }
	}
	/* Convert from minutes to seconds. */
	if (ts.tv_sec > TIME_T_MAX / 60)
	    debug_return_bool(false);	/* overflow */
	ts.tv_sec *= 60;
	ts.tv_nsec *= 60;
	while (ts.tv_nsec >= 1000000000) {
	    ts.tv_sec++;
	    ts.tv_nsec -= 1000000000;
	}
    }
    if (sign == '-') {
	sd_un->tspec.tv_sec = -ts.tv_sec;
	sd_un->tspec.tv_nsec = -ts.tv_nsec;
    } else {
	sd_un->tspec.tv_sec = ts.tv_sec;
	sd_un->tspec.tv_nsec = ts.tv_nsec;
    }
    debug_return_bool(true);
}

static bool
store_tuple(const char *str, union sudo_defs_val *sd_un,
    struct def_values *tuple_vals)
{
    struct def_values *v;
    debug_decl(store_tuple, SUDOERS_DEBUG_DEFAULTS)

    /*
     * Look up tuple value by name to find enum def_tuple value.
     * For negation to work the first element of enum def_tuple
     * must be equivalent to boolean false.
     */
    if (str == NULL) {
	sd_un->ival = 0;
    } else {
	for (v = tuple_vals; v->sval != NULL; v++) {
	    if (strcmp(v->sval, str) == 0) {
		sd_un->tuple = v->nval;
		break;
	    }
	}
	if (v->sval == NULL)
	    debug_return_bool(false);
    }
    debug_return_bool(true);
}

static int
store_str(const char *str, union sudo_defs_val *sd_un)
{
    debug_decl(store_str, SUDOERS_DEBUG_DEFAULTS)

    free(sd_un->str);
    if (str == NULL) {
	sd_un->str = NULL;
    } else {
	if ((sd_un->str = strdup(str)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    debug_return_int(-1);
	}
    }
    debug_return_int(true);
}

static bool
store_list(const char *str, union sudo_defs_val *sd_un, int op)
{
    debug_decl(store_list, SUDOERS_DEBUG_DEFAULTS)

    /* Remove all old members. */
    if (op == false || op == true)
	(void)list_op(NULL, 0, sd_un, freeall);

    /* Split str into multiple space-separated words and act on each one. */
    if (str != NULL) {
	const char *cp, *ep;
	const char *end = str + strlen(str);
	const enum list_ops lop = op == '-' ? delete : add;

	for (cp = sudo_strsplit(str, end, " \t", &ep); cp != NULL;
	    cp = sudo_strsplit(NULL, end, " \t", &ep)) {
	    if (!list_op(cp, ep - cp, sd_un, lop))
		debug_return_bool(false);
	}
    }
    debug_return_bool(true);
}

static bool
store_syslogfac(const char *str, union sudo_defs_val *sd_un)
{
    struct strmap *fac;
    debug_decl(store_syslogfac, SUDOERS_DEBUG_DEFAULTS)

    if (str == NULL) {
	sd_un->ival = false;
	debug_return_bool(true);
    }
    for (fac = facilities; fac->name != NULL; fac++) {
	if (strcmp(str, fac->name) == 0) {
	    sd_un->ival = fac->num;
	    debug_return_bool(true);
	}
    }
    debug_return_bool(false);		/* not found */
}

static const char *
logfac2str(int n)
{
    struct strmap *fac;
    debug_decl(logfac2str, SUDOERS_DEBUG_DEFAULTS)

    for (fac = facilities; fac->name && fac->num != n; fac++)
	continue;
    debug_return_const_str(fac->name);
}

static bool
store_syslogpri(const char *str, union sudo_defs_val *sd_un)
{
    struct strmap *pri;
    debug_decl(store_syslogpri, SUDOERS_DEBUG_DEFAULTS)

    if (str == NULL) {
	sd_un->ival = -1;
	debug_return_bool(true);
    }
    for (pri = priorities; pri->name != NULL; pri++) {
	if (strcmp(str, pri->name) == 0) {
	    sd_un->ival = pri->num;
	    debug_return_bool(true);
	}
    }
    debug_return_bool(false); 	/* not found */
}

static const char *
logpri2str(int n)
{
    struct strmap *pri;
    debug_decl(logpri2str, SUDOERS_DEBUG_DEFAULTS)

    for (pri = priorities; pri->name != NULL; pri++) {
	if (pri->num == n)
	    debug_return_const_str(pri->name);
    }
    debug_return_const_str("unknown");
}

static bool
store_mode(const char *str, union sudo_defs_val *sd_un)
{
    mode_t mode;
    const char *errstr;
    debug_decl(store_mode, SUDOERS_DEBUG_DEFAULTS)

    if (str == NULL) {
	sd_un->mode = ACCESSPERMS;
    } else {
	mode = sudo_strtomode(str, &errstr);
	if (errstr != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"%s is %s", str, errstr);
	    debug_return_bool(false);
	}
	sd_un->mode = mode;
    }
    debug_return_bool(true);
}

static bool
store_timeout(const char *str, union sudo_defs_val *sd_un)
{
    debug_decl(store_mode, SUDOERS_DEBUG_DEFAULTS)

    if (str == NULL) {
	sd_un->ival = 0;
    } else {
	int seconds = parse_timeout(str);
	if (seconds == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
		"%s", str);
	    debug_return_bool(false);
	}
	sd_un->ival = seconds;
    }
    debug_return_bool(true);
}

static bool
list_op(const char *str, size_t len, union sudo_defs_val *sd_un,
    enum list_ops op)
{
    struct list_member *cur, *prev = NULL;
    debug_decl(list_op, SUDOERS_DEBUG_DEFAULTS)

    if (op == freeall) {
	while ((cur = SLIST_FIRST(&sd_un->list)) != NULL) {
	    SLIST_REMOVE_HEAD(&sd_un->list, entries);
	    free(cur->value);
	    free(cur);
	}
	debug_return_bool(true);
    }

    SLIST_FOREACH(cur, &sd_un->list, entries) {
	if ((strncmp(cur->value, str, len) == 0 && cur->value[len] == '\0')) {

	    if (op == add)
		debug_return_bool(true); /* already exists */

	    /* Delete node */
	    if (prev == NULL)
		SLIST_REMOVE_HEAD(&sd_un->list, entries);
	    else
		SLIST_REMOVE_AFTER(prev, entries);
	    free(cur->value);
	    free(cur);
	    break;
	}
	prev = cur;
    }

    /* Add new node to the head of the list. */
    if (op == add) {
	cur = calloc(1, sizeof(struct list_member));
	if (cur == NULL || (cur->value = strndup(str, len)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    free(cur);
	    debug_return_bool(false);
	}
	SLIST_INSERT_HEAD(&sd_un->list, cur, entries);
    }
    debug_return_bool(true);
}
