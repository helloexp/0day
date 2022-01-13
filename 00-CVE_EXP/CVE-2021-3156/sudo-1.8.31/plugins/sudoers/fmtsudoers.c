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
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <time.h>

#include "sudoers.h"
#include "sudo_lbuf.h"
#include <gram.h>

/*
 * Write the contents of a struct member to the lbuf.
 * If alias_type is not UNSPEC, expand aliases using that type with
 * the specified separator (which must not be NULL in the UNSPEC case).
 */
static bool
sudoers_format_member_int(struct sudo_lbuf *lbuf,
    struct sudoers_parse_tree *parse_tree, char *name, int type, bool negated,
    const char *separator, int alias_type)
{
    struct alias *a;
    struct member *m;
    struct sudo_command *c;
    debug_decl(sudoers_format_member_int, SUDOERS_DEBUG_UTIL)

    switch (type) {
	case ALL:
	    sudo_lbuf_append(lbuf, "%sALL", negated ? "!" : "");
	    break;
	case MYSELF:
	    sudo_lbuf_append(lbuf, "%s%s", negated ? "!" : "",
		user_name ? user_name : "");
	    break;
	case COMMAND:
	    c = (struct sudo_command *) name;
	    if (c->digest != NULL) {
		sudo_lbuf_append(lbuf, "%s:%s ",
		    digest_type_to_name(c->digest->digest_type),
		    c->digest->digest_str);
	    }
	    if (negated)
		sudo_lbuf_append(lbuf, "!");
	    sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED" \t", "%s", c->cmnd);
	    if (c->args) {
		sudo_lbuf_append(lbuf, " ");
		sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s", c->args);
	    }
	    break;
	case USERGROUP:
	    /* Special case for %#gid, %:non-unix-group, %:#non-unix-gid */
	    if (strpbrk(name, " \t") == NULL) {
		if (*++name == ':') {
		    name++;
		    sudo_lbuf_append(lbuf, "%s", "%:");
		} else {
		    sudo_lbuf_append(lbuf, "%s", "%");
		}
	    }
	    goto print_word;
	case ALIAS:
	    if (alias_type != UNSPEC) {
		if ((a = alias_get(parse_tree, name, alias_type)) != NULL) {
		    TAILQ_FOREACH(m, &a->members, entries) {
			if (m != TAILQ_FIRST(&a->members))
			    sudo_lbuf_append(lbuf, "%s", separator);
			sudoers_format_member_int(lbuf, parse_tree, m->name,
			    m->type, negated ? !m->negated : m->negated,
			    separator, alias_type);
		    }
		    alias_put(a);
		    break;
		}
	    }
	    /* FALLTHROUGH */
	default:
	print_word:
	    /* Do not quote UID/GID, all others get quoted. */
	    if (name[0] == '#' &&
		name[strspn(name + 1, "0123456789") + 1] == '\0') {
		sudo_lbuf_append(lbuf, "%s%s", negated ? "!" : "", name);
	    } else {
		if (strpbrk(name, " \t") != NULL) {
		    sudo_lbuf_append(lbuf, "%s\"", negated ? "!" : "");
		    sudo_lbuf_append_quoted(lbuf, "\"", "%s", name);
		    sudo_lbuf_append(lbuf, "\"");
		} else {
		    sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s%s",
			negated ? "!" : "", name);
		}
	    }
	    break;
    }
    debug_return_bool(!sudo_lbuf_error(lbuf));
}

bool
sudoers_format_member(struct sudo_lbuf *lbuf,
    struct sudoers_parse_tree *parse_tree, struct member *m,
    const char *separator, int alias_type)
{
    return sudoers_format_member_int(lbuf, parse_tree, m->name, m->type,
	m->negated, separator, alias_type);
}

/*
 * Store a defaults entry as a command tag.
 */
bool
sudoers_defaults_to_tags(const char *var, const char *val, int op,
    struct cmndtag *tags)
{
    bool ret = true;
    debug_decl(sudoers_defaults_to_tags, SUDOERS_DEBUG_UTIL)

    if (op == true || op == false) {
	if (strcmp(var, "authenticate") == 0) {
	    tags->nopasswd = op == false;
	} else if (strcmp(var, "sudoedit_follow") == 0) {
	    tags->follow = op == true;
	} else if (strcmp(var, "log_input") == 0) {
	    tags->log_input = op == true;
	} else if (strcmp(var, "log_output") == 0) {
	    tags->log_output = op == true;
	} else if (strcmp(var, "noexec") == 0) {
	    tags->noexec = op == true;
	} else if (strcmp(var, "setenv") == 0) {
	    tags->setenv = op == true;
	} else if (strcmp(var, "mail_all_cmnds") == 0 ||
	    strcmp(var, "mail_always") == 0 ||
	    strcmp(var, "mail_no_perms") == 0) {
	    tags->send_mail = op == true;
	} else {
	    ret = false;
	}
    } else {
	ret = false;
    }
    debug_return_bool(ret);
}

/*
 * Convert a defaults list to command tags.
 */
bool
sudoers_defaults_list_to_tags(struct defaults_list *defs, struct cmndtag *tags)
{
    bool ret = true;
    struct defaults *d;
    debug_decl(sudoers_defaults_list_to_tags, SUDOERS_DEBUG_UTIL)

    TAGS_INIT(*tags);
    if (defs != NULL) {
	TAILQ_FOREACH(d, defs, entries) {
	    if (!sudoers_defaults_to_tags(d->var, d->val, d->op, tags)) {
		if (d->val != NULL) {
		    sudo_debug_printf(SUDO_DEBUG_WARN,
			"unable to convert defaults to tag: %s%s%s", d->var,
			d->op == '+' ? "+=" : d->op == '-' ? "-=" : "=", d->val);
		} else {
		    sudo_debug_printf(SUDO_DEBUG_WARN,
			"unable to convert defaults to tag: %s%s%s",
			d->op == false ? "!" : "", d->var, "");
		}
		ret = false;
	    }
	}
    }
    debug_return_bool(ret);
}

#define	FIELD_CHANGED(ocs, ncs, fld) \
	((ocs) == NULL || (ncs)->fld != (ocs)->fld)

#define	TAG_CHANGED(ocs, ncs, t, tt) \
	(TAG_SET((t).tt) && FIELD_CHANGED(ocs, ncs, tags.tt))

/*
 * Write a cmndspec to lbuf in sudoers format.
 */
bool
sudoers_format_cmndspec(struct sudo_lbuf *lbuf,
    struct sudoers_parse_tree *parse_tree, struct cmndspec *cs,
    struct cmndspec *prev_cs, struct cmndtag tags, bool expand_aliases)
{
    debug_decl(sudoers_format_cmndspec, SUDOERS_DEBUG_UTIL)

    /* Merge privilege-level tags with cmndspec tags. */
    TAGS_MERGE(tags, cs->tags);

#ifdef HAVE_PRIV_SET
    if (cs->privs != NULL && FIELD_CHANGED(prev_cs, cs, privs))
	sudo_lbuf_append(lbuf, "PRIVS=\"%s\" ", cs->privs);
    if (cs->limitprivs != NULL && FIELD_CHANGED(prev_cs, cs, limitprivs))
	sudo_lbuf_append(lbuf, "LIMITPRIVS=\"%s\" ", cs->limitprivs);
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
    if (cs->role != NULL && FIELD_CHANGED(prev_cs, cs, role))
	sudo_lbuf_append(lbuf, "ROLE=%s ", cs->role);
    if (cs->type != NULL && FIELD_CHANGED(prev_cs, cs, type))
	sudo_lbuf_append(lbuf, "TYPE=%s ", cs->type);
#endif /* HAVE_SELINUX */
    if (cs->timeout > 0 && FIELD_CHANGED(prev_cs, cs, timeout)) {
	char numbuf[(((sizeof(int) * 8) + 2) / 3) + 2];
	(void)snprintf(numbuf, sizeof(numbuf), "%d", cs->timeout);
	sudo_lbuf_append(lbuf, "TIMEOUT=%s ", numbuf);
    }
    if (cs->notbefore != UNSPEC && FIELD_CHANGED(prev_cs, cs, notbefore)) {
	char buf[sizeof("CCYYMMDDHHMMSSZ")];
	struct tm *tm = gmtime(&cs->notbefore);
	if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%SZ", tm) != 0)
	    sudo_lbuf_append(lbuf, "NOTBEFORE=%s ", buf);
    }
    if (cs->notafter != UNSPEC && FIELD_CHANGED(prev_cs, cs, notafter)) {
	char buf[sizeof("CCYYMMDDHHMMSSZ")];
	struct tm *tm = gmtime(&cs->notafter);
	if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%SZ", tm) != 0)
	    sudo_lbuf_append(lbuf, "NOTAFTER=%s ", buf);
    }
    if (TAG_CHANGED(prev_cs, cs, tags, setenv))
	sudo_lbuf_append(lbuf, tags.setenv ? "SETENV: " : "NOSETENV: ");
    if (TAG_CHANGED(prev_cs, cs, tags, noexec))
	sudo_lbuf_append(lbuf, tags.noexec ? "NOEXEC: " : "EXEC: ");
    if (TAG_CHANGED(prev_cs, cs, tags, nopasswd))
	sudo_lbuf_append(lbuf, tags.nopasswd ? "NOPASSWD: " : "PASSWD: ");
    if (TAG_CHANGED(prev_cs, cs, tags, log_input))
	sudo_lbuf_append(lbuf, tags.log_input ? "LOG_INPUT: " : "NOLOG_INPUT: ");
    if (TAG_CHANGED(prev_cs, cs, tags, log_output))
	sudo_lbuf_append(lbuf, tags.log_output ? "LOG_OUTPUT: " : "NOLOG_OUTPUT: ");
    if (TAG_CHANGED(prev_cs, cs, tags, send_mail))
	sudo_lbuf_append(lbuf, tags.send_mail ? "MAIL: " : "NOMAIL: ");
    if (TAG_CHANGED(prev_cs, cs, tags, follow))
	sudo_lbuf_append(lbuf, tags.follow ? "FOLLOW: " : "NOFOLLOW: ");
    sudoers_format_member(lbuf, parse_tree, cs->cmnd, ", ",
	expand_aliases ? CMNDALIAS : UNSPEC);
    debug_return_bool(!sudo_lbuf_error(lbuf));
}

/*
 * Write a privilege to lbuf in sudoers format.
 */
bool
sudoers_format_privilege(struct sudo_lbuf *lbuf,
    struct sudoers_parse_tree *parse_tree, struct privilege *priv,
    bool expand_aliases)
{
    struct cmndspec *cs, *prev_cs;
    struct cmndtag tags;
    struct member *m;
    debug_decl(sudoers_format_privilege, SUDOERS_DEBUG_UTIL)

    /* Convert per-privilege defaults to tags. */
    sudoers_defaults_list_to_tags(&priv->defaults, &tags);

    /* Print hosts list. */
    TAILQ_FOREACH(m, &priv->hostlist, entries) {
	if (m != TAILQ_FIRST(&priv->hostlist))
	    sudo_lbuf_append(lbuf, ", ");
	sudoers_format_member(lbuf, parse_tree, m, ", ",
	    expand_aliases ? HOSTALIAS : UNSPEC);
    }

    /* Print commands. */
    sudo_lbuf_append(lbuf, " = ");
    prev_cs = NULL;
    TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
	if (prev_cs == NULL || RUNAS_CHANGED(cs, prev_cs)) {
	    if (cs != TAILQ_FIRST(&priv->cmndlist))
		sudo_lbuf_append(lbuf, ", ");
	    if (cs->runasuserlist != NULL || cs->runasgrouplist != NULL)
		sudo_lbuf_append(lbuf, "(");
	    if (cs->runasuserlist != NULL) {
		TAILQ_FOREACH(m, cs->runasuserlist, entries) {
		    if (m != TAILQ_FIRST(cs->runasuserlist))
			sudo_lbuf_append(lbuf, ", ");
		    sudoers_format_member(lbuf, parse_tree, m, ", ",
			expand_aliases ? RUNASALIAS : UNSPEC);
		}
	    }
	    if (cs->runasgrouplist != NULL) {
		sudo_lbuf_append(lbuf, " : ");
		TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
		    if (m != TAILQ_FIRST(cs->runasgrouplist))
			sudo_lbuf_append(lbuf, ", ");
		    sudoers_format_member(lbuf, parse_tree, m, ", ",
			expand_aliases ? RUNASALIAS : UNSPEC);
		}
	    }
	    if (cs->runasuserlist != NULL || cs->runasgrouplist != NULL)
		sudo_lbuf_append(lbuf, ") ");
	} else if (cs != TAILQ_FIRST(&priv->cmndlist)) {
	    sudo_lbuf_append(lbuf, ", ");
	}
	sudoers_format_cmndspec(lbuf, parse_tree, cs, prev_cs, tags,
	    expand_aliases);
	prev_cs = cs;
    }

    debug_return_bool(!sudo_lbuf_error(lbuf));
}

/*
 * Write a userspec to lbuf in sudoers format.
 */
bool
sudoers_format_userspec(struct sudo_lbuf *lbuf,
    struct sudoers_parse_tree *parse_tree,
    struct userspec *us, bool expand_aliases)
{
    struct privilege *priv;
    struct sudoers_comment *comment;
    struct member *m;
    debug_decl(sudoers_format_userspec, SUDOERS_DEBUG_UTIL)

    /* Print comments (if any). */
    STAILQ_FOREACH(comment, &us->comments, entries) {
	sudo_lbuf_append(lbuf, "# %s\n", comment->str);
    }

    /* Print users list. */
    TAILQ_FOREACH(m, &us->users, entries) {
	if (m != TAILQ_FIRST(&us->users))
	    sudo_lbuf_append(lbuf, ", ");
	sudoers_format_member(lbuf, parse_tree, m, ", ",
	    expand_aliases ? USERALIAS : UNSPEC);
    }

    TAILQ_FOREACH(priv, &us->privileges, entries) {
	if (priv != TAILQ_FIRST(&us->privileges))
	    sudo_lbuf_append(lbuf, " : ");
	else
	    sudo_lbuf_append(lbuf, " ");
	if (!sudoers_format_privilege(lbuf, parse_tree, priv, expand_aliases))
	    break;
    }
    sudo_lbuf_append(lbuf, "\n");

    debug_return_bool(!sudo_lbuf_error(lbuf));
}

/*
 * Write a userspec_list to lbuf in sudoers format.
 */
bool
sudoers_format_userspecs(struct sudo_lbuf *lbuf,
    struct sudoers_parse_tree *parse_tree, const char *separator,
    bool expand_aliases, bool flush)
{
    struct userspec *us;
    debug_decl(sudoers_format_userspecs, SUDOERS_DEBUG_UTIL)

    TAILQ_FOREACH(us, &parse_tree->userspecs, entries) {
	if (separator != NULL && us != TAILQ_FIRST(&parse_tree->userspecs))
	    sudo_lbuf_append(lbuf, "%s", separator);
	if (!sudoers_format_userspec(lbuf, parse_tree, us, expand_aliases))
	    break;
	sudo_lbuf_print(lbuf);
    }

    debug_return_bool(!sudo_lbuf_error(lbuf));
}

/*
 * Format and append a defaults entry to the specified lbuf.
 */
bool
sudoers_format_default(struct sudo_lbuf *lbuf, struct defaults *d)
{
    debug_decl(sudoers_format_default, SUDOERS_DEBUG_UTIL)

    if (d->val != NULL) {
	sudo_lbuf_append(lbuf, "%s%s", d->var,
	    d->op == '+' ? "+=" : d->op == '-' ? "-=" : "=");
	if (strpbrk(d->val, " \t") != NULL) {
	    sudo_lbuf_append(lbuf, "\"");
	    sudo_lbuf_append_quoted(lbuf, "\"", "%s", d->val);
	    sudo_lbuf_append(lbuf, "\"");
	} else
	    sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s", d->val);
    } else {
	sudo_lbuf_append(lbuf, "%s%s", d->op == false ? "!" : "", d->var);
    }
    debug_return_bool(!sudo_lbuf_error(lbuf));
}

/*
 * Format and append a defaults line to the specified lbuf.
 * If next, is specified, it must point to the next defaults
 * entry in the list; this is used to print multiple defaults
 * entries with the same binding on a single line.
 */
bool
sudoers_format_default_line( struct sudo_lbuf *lbuf,
    struct sudoers_parse_tree *parse_tree, struct defaults *d,
    struct defaults **next, bool expand_aliases)
{
    struct member *m;
    int alias_type;
    debug_decl(sudoers_format_default_line, SUDOERS_DEBUG_UTIL)

    /* Print Defaults type and binding (if present) */
    switch (d->type) {
	case DEFAULTS_HOST:
	    sudo_lbuf_append(lbuf, "Defaults@");
	    alias_type = expand_aliases ? HOSTALIAS : UNSPEC;
	    break;
	case DEFAULTS_USER:
	    sudo_lbuf_append(lbuf, "Defaults:");
	    alias_type = expand_aliases ? USERALIAS : UNSPEC;
	    break;
	case DEFAULTS_RUNAS:
	    sudo_lbuf_append(lbuf, "Defaults>");
	    alias_type = expand_aliases ? RUNASALIAS : UNSPEC;
	    break;
	case DEFAULTS_CMND:
	    sudo_lbuf_append(lbuf, "Defaults!");
	    alias_type = expand_aliases ? CMNDALIAS : UNSPEC;
	    break;
	default:
	    sudo_lbuf_append(lbuf, "Defaults");
	    alias_type = UNSPEC;
	    break;
    }
    TAILQ_FOREACH(m, d->binding, entries) {
	if (m != TAILQ_FIRST(d->binding))
	    sudo_lbuf_append(lbuf, ", ");
	sudoers_format_member(lbuf, parse_tree, m, ", ", alias_type);
    }

    sudo_lbuf_append(lbuf, " ");
    sudoers_format_default(lbuf, d);

    if (next != NULL) {
	/* Merge Defaults with the same binding, there may be multiple. */
	struct defaults *n;
	while ((n = TAILQ_NEXT(d, entries)) && d->binding == n->binding) {
	    sudo_lbuf_append(lbuf, ", ");
	    sudoers_format_default(lbuf, n);
	    d = n;
	}
	*next = n;
    }
    sudo_lbuf_append(lbuf, "\n");

    debug_return_bool(!sudo_lbuf_error(lbuf));
}
