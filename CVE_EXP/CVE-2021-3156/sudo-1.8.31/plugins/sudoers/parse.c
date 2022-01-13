/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2004-2005, 2007-2019 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <ctype.h>
#include <grp.h>
#include <pwd.h>
#include <time.h>

#include "sudoers.h"
#include "sudo_lbuf.h"
#include <gram.h>

/*
 * Look up the user in the sudoers parse tree for pseudo-commands like
 * list, verify and kill.
 */
static int
sudoers_lookup_pseudo(struct sudo_nss_list *snl, struct passwd *pw,
    int validated, int pwflag)
{
    int match;
    struct sudo_nss *nss;
    struct cmndspec *cs;
    struct privilege *priv;
    struct userspec *us;
    struct defaults *def;
    int nopass;
    enum def_tuple pwcheck;
    debug_decl(sudoers_lookup_pseudo, SUDOERS_DEBUG_PARSER)

    pwcheck = (pwflag == -1) ? never : sudo_defs_table[pwflag].sd_un.tuple;
    nopass = (pwcheck == never || pwcheck == all) ? true : false;

    if (list_pw == NULL)
	SET(validated, FLAG_NO_CHECK);
    CLR(validated, FLAG_NO_USER);
    CLR(validated, FLAG_NO_HOST);
    match = DENY;
    TAILQ_FOREACH(nss, snl, entries) {
	if (nss->query(nss, pw) == -1) {
	    /* The query function should have printed an error message. */
	    SET(validated, VALIDATE_ERROR);
	    break;
	}
	TAILQ_FOREACH(us, &nss->parse_tree->userspecs, entries) {
	    if (userlist_matches(nss->parse_tree, pw, &us->users) != ALLOW)
		continue;
	    TAILQ_FOREACH(priv, &us->privileges, entries) {
		int priv_nopass = UNSPEC;

		if (hostlist_matches(nss->parse_tree, pw, &priv->hostlist) != ALLOW)
		    continue;
		TAILQ_FOREACH(def, &priv->defaults, entries) {
		    if (strcmp(def->var, "authenticate") == 0)
			priv_nopass = !def->op;
		}
		TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
		    if (pwcheck == any) {
			if (cs->tags.nopasswd == true || priv_nopass == true)
			    nopass = true;
		    } else if (pwcheck == all) {
			if (cs->tags.nopasswd != true && priv_nopass != true)
			    nopass = false;
		    }
		    if (match == ALLOW)
			continue;
		    /* Only check the command when listing another user. */
		    if (user_uid == 0 || list_pw == NULL ||
			user_uid == list_pw->pw_uid ||
			cmnd_matches(nss->parse_tree, cs->cmnd) == ALLOW)
			    match = ALLOW;
		}
	    }
	}
    }
    if (match == ALLOW || user_uid == 0) {
	/* User has an entry for this host. */
	SET(validated, VALIDATE_SUCCESS);
    } else if (match == DENY)
	SET(validated, VALIDATE_FAILURE);
    if (pwcheck == always && def_authenticate)
	SET(validated, FLAG_CHECK_USER);
    else if (nopass == true)
	def_authenticate = false;
    debug_return_int(validated);
}

static int
sudoers_lookup_check(struct sudo_nss *nss, struct passwd *pw,
    int *validated, struct cmndspec **matching_cs,
    struct defaults_list **defs, time_t now)
{
    int host_match, runas_match, cmnd_match;
    struct cmndspec *cs;
    struct privilege *priv;
    struct userspec *us;
    struct member *matching_user;
    debug_decl(sudoers_lookup_check, SUDOERS_DEBUG_PARSER)

    TAILQ_FOREACH_REVERSE(us, &nss->parse_tree->userspecs, userspec_list, entries) {
	if (userlist_matches(nss->parse_tree, pw, &us->users) != ALLOW)
	    continue;
	CLR(*validated, FLAG_NO_USER);
	TAILQ_FOREACH_REVERSE(priv, &us->privileges, privilege_list, entries) {
	    host_match = hostlist_matches(nss->parse_tree, pw, &priv->hostlist);
	    if (host_match == ALLOW)
		CLR(*validated, FLAG_NO_HOST);
	    else
		continue;
	    TAILQ_FOREACH_REVERSE(cs, &priv->cmndlist, cmndspec_list, entries) {
		if (cs->notbefore != UNSPEC) {
		    if (now < cs->notbefore)
			continue;
		}
		if (cs->notafter != UNSPEC) {
		    if (now > cs->notafter)
			continue;
		}
		matching_user = NULL;
		runas_match = runaslist_matches(nss->parse_tree,
		    cs->runasuserlist, cs->runasgrouplist, &matching_user,
		    NULL);
		if (runas_match == ALLOW) {
		    cmnd_match = cmnd_matches(nss->parse_tree, cs->cmnd);
		    if (cmnd_match != UNSPEC) {
			/*
			 * If user is running command as himself,
			 * set runas_pw = sudo_user.pw.
			 * XXX - hack, want more general solution
			 */
			if (matching_user && matching_user->type == MYSELF) {
			    sudo_pw_delref(runas_pw);
			    sudo_pw_addref(sudo_user.pw);
			    runas_pw = sudo_user.pw;
			}
			*matching_cs = cs;
			*defs = &priv->defaults;
			sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
			    "userspec matched @ %s:%d %s", us->file, us->lineno,
			    cmnd_match ? "allowed" : "denied");
			debug_return_int(cmnd_match);
		    }
		}
	    }
	}
    }
    debug_return_int(UNSPEC);
}

/*
 * Apply cmndspec-specific settngs including SELinux role/type,
 * Solaris privs, and command tags.
 */
static bool
apply_cmndspec(struct cmndspec *cs)
{
    debug_decl(apply_cmndspec, SUDOERS_DEBUG_PARSER)

    if (cs != NULL) {
#ifdef HAVE_SELINUX
	/* Set role and type if not specified on command line. */
	if (user_role == NULL) {
	    if (cs->role != NULL) {
		user_role = strdup(cs->role);
		if (user_role == NULL) {
		    sudo_warnx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		    debug_return_bool(false);
		}
	    } else {
		user_role = def_role;
	    }
	}
	if (user_type == NULL) {
	    if (cs->type != NULL) {
		user_type = strdup(cs->type);
		if (user_type == NULL) {
		    sudo_warnx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		    debug_return_bool(false);
		}
	    } else {
		user_type = def_type;
	    }
	}
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
	/* Set Solaris privilege sets */
	if (runas_privs == NULL) {
	    if (cs->privs != NULL) {
		runas_privs = strdup(cs->privs);
		if (runas_privs == NULL) {
		    sudo_warnx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		    debug_return_bool(false);
		}
	    } else {
		runas_privs = def_privs;
	    }
	}
	if (runas_limitprivs == NULL) {
	    if (cs->limitprivs != NULL) {
		runas_limitprivs = strdup(cs->limitprivs);
		if (runas_limitprivs == NULL) {
		    sudo_warnx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		    debug_return_bool(false);
		}
	    } else {
		runas_limitprivs = def_limitprivs;
	    }
	}
#endif /* HAVE_PRIV_SET */
	if (cs->timeout > 0)
	    def_command_timeout = cs->timeout;
	if (cs->tags.nopasswd != UNSPEC)
	    def_authenticate = !cs->tags.nopasswd;
	if (cs->tags.noexec != UNSPEC)
	    def_noexec = cs->tags.noexec;
	if (cs->tags.setenv != UNSPEC)
	    def_setenv = cs->tags.setenv;
	if (cs->tags.log_input != UNSPEC)
	    def_log_input = cs->tags.log_input;
	if (cs->tags.log_output != UNSPEC)
	    def_log_output = cs->tags.log_output;
	if (cs->tags.send_mail != UNSPEC) {
	    if (cs->tags.send_mail) {
		def_mail_all_cmnds = true;
	    } else {
		def_mail_all_cmnds = false;
		def_mail_always = false;
		def_mail_no_perms = false;
	    }
	}
	if (cs->tags.follow != UNSPEC)
	    def_sudoedit_follow = cs->tags.follow;
    }

    debug_return_bool(true);
}

/*
 * Look up the user in the sudoers parse tree and check to see if they are
 * allowed to run the specified command on this host as the target user.
 */
int
sudoers_lookup(struct sudo_nss_list *snl, struct passwd *pw, int validated,
    int pwflag)
{
    struct defaults_list *defs = NULL;
    struct sudoers_parse_tree *parse_tree = NULL;
    struct cmndspec *cs = NULL;
    struct sudo_nss *nss;
    int m, match = UNSPEC;
    time_t now;
    debug_decl(sudoers_lookup, SUDOERS_DEBUG_PARSER)

    /*
     * Special case checking the "validate", "list" and "kill" pseudo-commands.
     */
    if (pwflag)
	debug_return_int(sudoers_lookup_pseudo(snl, pw, validated, pwflag));

    /* Need to be runas user while stat'ing things. */
    if (!set_perms(PERM_RUNAS))
	debug_return_int(validated);

    /* Query each sudoers source and check the user. */
    time(&now);
    TAILQ_FOREACH(nss, snl, entries) {
	if (nss->query(nss, pw) == -1) {
	    /* The query function should have printed an error message. */
	    SET(validated, VALIDATE_ERROR);
	    break;
	}

	m = sudoers_lookup_check(nss, pw, &validated, &cs, &defs, now);
	if (m != UNSPEC) {
	    match = m;
	    parse_tree = nss->parse_tree;
	}

	if (!sudo_nss_can_continue(nss, m))
	    break;
    }
    if (match != UNSPEC) {
	if (defs != NULL)
	    update_defaults(parse_tree, defs, SETDEF_GENERIC, false);
	if (!apply_cmndspec(cs))
	    SET(validated, VALIDATE_ERROR);
	else if (match == ALLOW)
	    SET(validated, VALIDATE_SUCCESS);
	else
	    SET(validated, VALIDATE_FAILURE);
    }
    if (!restore_perms())
	SET(validated, VALIDATE_ERROR);
    debug_return_int(validated);
}

static int
display_priv_short(struct sudoers_parse_tree *parse_tree, struct passwd *pw,
    struct userspec *us, struct sudo_lbuf *lbuf)
{
    struct privilege *priv;
    int nfound = 0;
    debug_decl(display_priv_short, SUDOERS_DEBUG_PARSER)

    TAILQ_FOREACH(priv, &us->privileges, entries) {
	struct cmndspec *cs, *prev_cs = NULL;
	struct cmndtag tags;

	if (hostlist_matches(parse_tree, pw, &priv->hostlist) != ALLOW)
	    continue;

	sudoers_defaults_list_to_tags(&priv->defaults, &tags);
	TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
	    /* Start a new line if RunAs changes. */
	    if (prev_cs == NULL || RUNAS_CHANGED(cs, prev_cs)) {
		struct member *m;

		if (cs != TAILQ_FIRST(&priv->cmndlist))
		    sudo_lbuf_append(lbuf, "\n");
		sudo_lbuf_append(lbuf, "    (");
		if (cs->runasuserlist != NULL) {
		    TAILQ_FOREACH(m, cs->runasuserlist, entries) {
			if (m != TAILQ_FIRST(cs->runasuserlist))
			    sudo_lbuf_append(lbuf, ", ");
			sudoers_format_member(lbuf, parse_tree, m, ", ",
			    RUNASALIAS);
		    }
		} else if (cs->runasgrouplist == NULL) {
		    sudo_lbuf_append(lbuf, "%s", def_runas_default);
		} else {
		    sudo_lbuf_append(lbuf, "%s", pw->pw_name);
		}
		if (cs->runasgrouplist != NULL) {
		    sudo_lbuf_append(lbuf, " : ");
		    TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
			if (m != TAILQ_FIRST(cs->runasgrouplist))
			    sudo_lbuf_append(lbuf, ", ");
			sudoers_format_member(lbuf, parse_tree, m, ", ",
			    RUNASALIAS);
		    }
		}
		sudo_lbuf_append(lbuf, ") ");
	    } else if (cs != TAILQ_FIRST(&priv->cmndlist)) {
		sudo_lbuf_append(lbuf, ", ");
	    }
	    sudoers_format_cmndspec(lbuf, parse_tree, cs, prev_cs, tags, true);
	    prev_cs = cs;
	    nfound++;
	}
	sudo_lbuf_append(lbuf, "\n");
    }
    debug_return_int(nfound);
}

/*
 * Compare the current cmndspec with the previous one to determine
 * whether we need to start a new long entry for "sudo -ll".
 * Returns true if we should start a new long entry, else false.
 */
static bool
new_long_entry(struct cmndspec *cs, struct cmndspec *prev_cs)
{
    debug_decl(new_long_entry, SUDOERS_DEBUG_PARSER)

    if (prev_cs == NULL)
	debug_return_bool(true);
    if (RUNAS_CHANGED(cs, prev_cs) || TAGS_CHANGED(prev_cs->tags, cs->tags))
	debug_return_bool(true);
#ifdef HAVE_PRIV_SET
    if (cs->privs && (!prev_cs->privs || strcmp(cs->privs, prev_cs->privs) != 0))
	debug_return_bool(true);
    if (cs->limitprivs && (!prev_cs->limitprivs || strcmp(cs->limitprivs, prev_cs->limitprivs) != 0))
	debug_return_bool(true);
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
    if (cs->role && (!prev_cs->role || strcmp(cs->role, prev_cs->role) != 0))
	debug_return_bool(true);
    if (cs->type && (!prev_cs->type || strcmp(cs->type, prev_cs->type) != 0))
	debug_return_bool(true);
#endif /* HAVE_SELINUX */
    if (cs->timeout != prev_cs->timeout)
	debug_return_bool(true);
    if (cs->notbefore != prev_cs->notbefore)
	debug_return_bool(true);
    if (cs->notafter != prev_cs->notafter)
	debug_return_bool(true);
    debug_return_bool(false);
}

static int
display_priv_long(struct sudoers_parse_tree *parse_tree, struct passwd *pw,
    struct userspec *us, struct sudo_lbuf *lbuf)
{
    struct privilege *priv;
    int nfound = 0;
    debug_decl(display_priv_long, SUDOERS_DEBUG_PARSER)

    TAILQ_FOREACH(priv, &us->privileges, entries) {
	struct cmndspec *cs, *prev_cs;

	if (hostlist_matches(parse_tree, pw, &priv->hostlist) != ALLOW)
	    continue;
	prev_cs = NULL;
	TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
	    struct defaults *d;
	    struct member *m;

	    if (new_long_entry(cs, prev_cs)) {
		int olen;

		if (priv->ldap_role != NULL) {
		    sudo_lbuf_append(lbuf, _("\nLDAP Role: %s\n"),
			priv->ldap_role);
		} else {
		    sudo_lbuf_append(lbuf, _("\nSudoers entry:\n"));
		}
		sudo_lbuf_append(lbuf, _("    RunAsUsers: "));
		if (cs->runasuserlist != NULL) {
		    TAILQ_FOREACH(m, cs->runasuserlist, entries) {
			if (m != TAILQ_FIRST(cs->runasuserlist))
			    sudo_lbuf_append(lbuf, ", ");
			sudoers_format_member(lbuf, parse_tree, m, ", ",
			    RUNASALIAS);
		    }
		} else if (cs->runasgrouplist == NULL) {
		    sudo_lbuf_append(lbuf, "%s", def_runas_default);
		} else {
		    sudo_lbuf_append(lbuf, "%s", pw->pw_name);
		}
		sudo_lbuf_append(lbuf, "\n");
		if (cs->runasgrouplist != NULL) {
		    sudo_lbuf_append(lbuf, _("    RunAsGroups: "));
		    TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
			if (m != TAILQ_FIRST(cs->runasgrouplist))
			    sudo_lbuf_append(lbuf, ", ");
			sudoers_format_member(lbuf, parse_tree, m, ", ",
			    RUNASALIAS);
		    }
		    sudo_lbuf_append(lbuf, "\n");
		}
		olen = lbuf->len;
		sudo_lbuf_append(lbuf, _("    Options: "));
		TAILQ_FOREACH(d, &priv->defaults, entries) {
		    sudoers_format_default(lbuf, d);
		    sudo_lbuf_append(lbuf, ", ");
		}
		if (TAG_SET(cs->tags.setenv))
		    sudo_lbuf_append(lbuf, "%ssetenv, ", cs->tags.setenv ? "" : "!");
		if (TAG_SET(cs->tags.noexec))
		    sudo_lbuf_append(lbuf, "%snoexec, ", cs->tags.noexec ? "" : "!");
		if (TAG_SET(cs->tags.nopasswd))
		    sudo_lbuf_append(lbuf, "%sauthenticate, ", cs->tags.nopasswd ? "!" : "");
		if (TAG_SET(cs->tags.log_input))
		    sudo_lbuf_append(lbuf, "%slog_input, ", cs->tags.log_input ? "" : "!");
		if (TAG_SET(cs->tags.log_output))
		    sudo_lbuf_append(lbuf, "%slog_output, ", cs->tags.log_output ? "" : "!");
		if (lbuf->buf[lbuf->len - 2] == ',') {
		    lbuf->len -= 2;	/* remove trailing ", " */
		    sudo_lbuf_append(lbuf, "\n");
		} else {
		    lbuf->len = olen;	/* no options */
		}
#ifdef HAVE_PRIV_SET
		if (cs->privs)
		    sudo_lbuf_append(lbuf, "    Privs: %s\n", cs->privs);
		if (cs->limitprivs)
		    sudo_lbuf_append(lbuf, "    Limitprivs: %s\n", cs->limitprivs);
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
		if (cs->role)
		    sudo_lbuf_append(lbuf, "    Role: %s\n", cs->role);
		if (cs->type)
		    sudo_lbuf_append(lbuf, "    Type: %s\n", cs->type);
#endif /* HAVE_SELINUX */
		if (cs->timeout > 0) {
		    char numbuf[(((sizeof(int) * 8) + 2) / 3) + 2];
		    (void)snprintf(numbuf, sizeof(numbuf), "%d", cs->timeout);
		    sudo_lbuf_append(lbuf, "    Timeout: %s\n", numbuf);
		}
		if (cs->notbefore != UNSPEC) {
		    char buf[sizeof("CCYYMMDDHHMMSSZ")];
		    struct tm *tm = gmtime(&cs->notbefore);
		    if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%SZ", tm) != 0)
			sudo_lbuf_append(lbuf, "    NotBefore: %s\n", buf);
		}
		if (cs->notafter != UNSPEC) {
		    char buf[sizeof("CCYYMMDDHHMMSSZ")];
		    struct tm *tm = gmtime(&cs->notafter);
		    if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%SZ", tm) != 0)
			sudo_lbuf_append(lbuf, "    NotAfter: %s\n", buf);
		}
		sudo_lbuf_append(lbuf, _("    Commands:\n"));
	    }
	    sudo_lbuf_append(lbuf, "\t");
	    sudoers_format_member(lbuf, parse_tree, cs->cmnd, "\n\t",
		CMNDALIAS);
	    sudo_lbuf_append(lbuf, "\n");
	    prev_cs = cs;
	    nfound++;
	}
    }
    debug_return_int(nfound);
}

static int
sudo_display_userspecs(struct sudoers_parse_tree *parse_tree, struct passwd *pw,
    struct sudo_lbuf *lbuf, bool verbose)
{
    struct userspec *us;
    int nfound = 0;
    debug_decl(sudo_display_userspecs, SUDOERS_DEBUG_PARSER)

    TAILQ_FOREACH(us, &parse_tree->userspecs, entries) {
	if (userlist_matches(parse_tree, pw, &us->users) != ALLOW)
	    continue;

	if (verbose)
	    nfound += display_priv_long(parse_tree, pw, us, lbuf);
	else
	    nfound += display_priv_short(parse_tree, pw, us, lbuf);
    }
    if (sudo_lbuf_error(lbuf))
	debug_return_int(-1);
    debug_return_int(nfound);
}

/*
 * Display matching Defaults entries for the given user on this host.
 */
static int
display_defaults(struct sudoers_parse_tree *parse_tree, struct passwd *pw,
    struct sudo_lbuf *lbuf)
{
    struct defaults *d;
    char *prefix;
    int nfound = 0;
    debug_decl(display_defaults, SUDOERS_DEBUG_PARSER)

    if (lbuf->len == 0 || isspace((unsigned char)lbuf->buf[lbuf->len - 1]))
	prefix = "    ";
    else
	prefix = ", ";

    TAILQ_FOREACH(d, &parse_tree->defaults, entries) {
	switch (d->type) {
	    case DEFAULTS_HOST:
		if (hostlist_matches(parse_tree, pw, d->binding) != ALLOW)
		    continue;
		break;
	    case DEFAULTS_USER:
		if (userlist_matches(parse_tree, pw, d->binding) != ALLOW)
		    continue;
		break;
	    case DEFAULTS_RUNAS:
	    case DEFAULTS_CMND:
		continue;
	}
	sudo_lbuf_append(lbuf, "%s", prefix);
	sudoers_format_default(lbuf, d);
	prefix = ", ";
	nfound++;
    }
    if (sudo_lbuf_error(lbuf))
	debug_return_int(-1);
    debug_return_int(nfound);
}

/*
 * Display Defaults entries of the given type.
 */
static int
display_bound_defaults_by_type(struct sudoers_parse_tree *parse_tree,
    int deftype, struct sudo_lbuf *lbuf)
{
    struct defaults *d;
    struct member_list *binding = NULL;
    struct member *m;
    char *dsep;
    int atype, nfound = 0;
    debug_decl(display_bound_defaults_by_type, SUDOERS_DEBUG_PARSER)

    switch (deftype) {
	case DEFAULTS_HOST:
	    atype = HOSTALIAS;
	    dsep = "@";
	    break;
	case DEFAULTS_USER:
	    atype = USERALIAS;
	    dsep = ":";
	    break;
	case DEFAULTS_RUNAS:
	    atype = RUNASALIAS;
	    dsep = ">";
	    break;
	case DEFAULTS_CMND:
	    atype = CMNDALIAS;
	    dsep = "!";
	    break;
	default:
	    debug_return_int(-1);
    }
    TAILQ_FOREACH(d, &parse_tree->defaults, entries) {
	if (d->type != deftype)
	    continue;

	nfound++;
	if (binding != d->binding) {
	    binding = d->binding;
	    if (nfound != 1)
		sudo_lbuf_append(lbuf, "\n");
	    sudo_lbuf_append(lbuf, "    Defaults%s", dsep);
	    TAILQ_FOREACH(m, binding, entries) {
		if (m != TAILQ_FIRST(binding))
		    sudo_lbuf_append(lbuf, ",");
		sudoers_format_member(lbuf, parse_tree, m, ", ", atype);
		sudo_lbuf_append(lbuf, " ");
	    }
	} else
	    sudo_lbuf_append(lbuf, ", ");
	sudoers_format_default(lbuf, d);
    }

    if (sudo_lbuf_error(lbuf))
	debug_return_int(-1);
    debug_return_int(nfound);
}

/*
 * Display Defaults entries that are per-runas or per-command
 */
static int
display_bound_defaults(struct sudoers_parse_tree *parse_tree,
    struct passwd *pw, struct sudo_lbuf *lbuf)
{
    int nfound = 0;
    debug_decl(display_bound_defaults, SUDOERS_DEBUG_PARSER)

    /* XXX - should only print ones that match what the user can do. */
    nfound += display_bound_defaults_by_type(parse_tree, DEFAULTS_RUNAS, lbuf);
    nfound += display_bound_defaults_by_type(parse_tree, DEFAULTS_CMND, lbuf);

    if (sudo_lbuf_error(lbuf))
	debug_return_int(-1);
    debug_return_int(nfound);
}

static int
output(const char *buf)
{
    struct sudo_conv_message msg;
    struct sudo_conv_reply repl;
    debug_decl(output, SUDOERS_DEBUG_NSS)

    /* Call conversation function */
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = SUDO_CONV_INFO_MSG;
    msg.msg = buf;
    memset(&repl, 0, sizeof(repl));
    if (sudo_conv(1, &msg, &repl, NULL) == -1)
	debug_return_int(0);
    debug_return_int(strlen(buf));
}

/*
 * Print out privileges for the specified user.
 * Returns true on success or -1 on error.
 */
int
display_privs(struct sudo_nss_list *snl, struct passwd *pw, bool verbose)
{
    struct sudo_nss *nss;
    struct sudo_lbuf def_buf, priv_buf;
    struct stat sb;
    int cols, count, olen, n;
    debug_decl(display_privs, SUDOERS_DEBUG_PARSER)

    cols = sudo_user.cols;
    if (fstat(STDOUT_FILENO, &sb) == 0 && S_ISFIFO(sb.st_mode))
	cols = 0;
    sudo_lbuf_init(&def_buf, output, 4, NULL, cols);
    sudo_lbuf_init(&priv_buf, output, 8, NULL, cols);

    sudo_lbuf_append(&def_buf, _("Matching Defaults entries for %s on %s:\n"),
	pw->pw_name, user_srunhost);
    count = 0;
    TAILQ_FOREACH(nss, snl, entries) {
	n = display_defaults(nss->parse_tree, pw, &def_buf);
	if (n == -1)
	    goto bad;
	count += n;
    }
    if (count != 0) {
	sudo_lbuf_append(&def_buf, "\n\n");
    } else {
	/* Undo Defaults header. */
	def_buf.len = 0;
    }

    /* Display Runas and Cmnd-specific defaults. */
    olen = def_buf.len;
    sudo_lbuf_append(&def_buf, _("Runas and Command-specific defaults for %s:\n"),
	pw->pw_name);
    count = 0;
    TAILQ_FOREACH(nss, snl, entries) {
	n = display_bound_defaults(nss->parse_tree, pw, &def_buf);
	if (n == -1)
	    goto bad;
	count += n;
    }
    if (count != 0) {
	sudo_lbuf_append(&def_buf, "\n\n");
    } else {
	/* Undo Defaults header. */
	def_buf.len = olen;
    }

    /* Display privileges from all sources. */
    sudo_lbuf_append(&priv_buf,
	_("User %s may run the following commands on %s:\n"),
	pw->pw_name, user_srunhost);
    count = 0;
    TAILQ_FOREACH(nss, snl, entries) {
	if (nss->query(nss, pw) != -1) {
	    n = sudo_display_userspecs(nss->parse_tree, pw, &priv_buf, verbose);
	    if (n == -1)
		goto bad;
	    count += n;
	}
    }
    if (count == 0) {
	def_buf.len = 0;
	priv_buf.len = 0;
	sudo_lbuf_append(&priv_buf,
	    _("User %s is not allowed to run sudo on %s.\n"),
	    pw->pw_name, user_srunhost);
    }
    if (sudo_lbuf_error(&def_buf) || sudo_lbuf_error(&priv_buf))
	goto bad;

    sudo_lbuf_print(&def_buf);
    sudo_lbuf_print(&priv_buf);

    sudo_lbuf_destroy(&def_buf);
    sudo_lbuf_destroy(&priv_buf);

    debug_return_int(true);
bad:
    sudo_lbuf_destroy(&def_buf);
    sudo_lbuf_destroy(&priv_buf);

    debug_return_int(-1);
}

static int
display_cmnd_check(struct sudoers_parse_tree *parse_tree, struct passwd *pw,
    time_t now)
{
    int host_match, runas_match, cmnd_match;
    struct cmndspec *cs;
    struct privilege *priv;
    struct userspec *us;
    debug_decl(display_cmnd_check, SUDOERS_DEBUG_PARSER)

    TAILQ_FOREACH_REVERSE(us, &parse_tree->userspecs, userspec_list, entries) {
	if (userlist_matches(parse_tree, pw, &us->users) != ALLOW)
	    continue;
	TAILQ_FOREACH_REVERSE(priv, &us->privileges, privilege_list, entries) {
	    host_match = hostlist_matches(parse_tree, pw, &priv->hostlist);
	    if (host_match != ALLOW)
		continue;
	    TAILQ_FOREACH_REVERSE(cs, &priv->cmndlist, cmndspec_list, entries) {
		if (cs->notbefore != UNSPEC) {
		    if (now < cs->notbefore)
			continue;
		}
		if (cs->notafter != UNSPEC) {
		    if (now > cs->notafter)
			continue;
		}
		runas_match = runaslist_matches(parse_tree, cs->runasuserlist,
		    cs->runasgrouplist, NULL, NULL);
		if (runas_match == ALLOW) {
		    cmnd_match = cmnd_matches(parse_tree, cs->cmnd);
		    if (cmnd_match != UNSPEC)
			debug_return_int(cmnd_match);
		}
	    }
	}
    }
    debug_return_int(UNSPEC);
}

/*
 * Check user_cmnd against sudoers and print the matching entry if the
 * command is allowed.
 * Returns true if the command is allowed, false if not or -1 on error.
 */
int
display_cmnd(struct sudo_nss_list *snl, struct passwd *pw)
{
    struct sudo_nss *nss;
    int m, match = UNSPEC;
    int ret = false;
    time_t now;
    debug_decl(display_cmnd, SUDOERS_DEBUG_PARSER)

    /* Iterate over each source, checking for the command. */
    time(&now);
    TAILQ_FOREACH(nss, snl, entries) {
	if (nss->query(nss, pw) == -1) {
	    /* The query function should have printed an error message. */
	    debug_return_int(-1);
	}

	m = display_cmnd_check(nss->parse_tree, pw, now);
	if (m != UNSPEC)
	    match = m;

	if (!sudo_nss_can_continue(nss, m))
	    break;
    }
    if (match == ALLOW) {
	const int len = sudo_printf(SUDO_CONV_INFO_MSG, "%s%s%s\n",
	    safe_cmnd, user_args ? " " : "", user_args ? user_args : "");
	ret = len < 0 ? -1 : true;
    }
    debug_return_int(ret);
}
