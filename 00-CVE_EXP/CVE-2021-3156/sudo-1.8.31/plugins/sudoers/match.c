/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1996, 1998-2005, 2007-2019
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
#ifdef HAVE_SYS_SYSTEMINFO_H
# include <sys/systeminfo.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#ifdef HAVE_NETGROUP_H
# include <netgroup.h>
#else
# include <netdb.h>
#endif /* HAVE_NETGROUP_H */
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

#include "sudoers.h"
#include <gram.h>

#ifdef HAVE_FNMATCH
# include <fnmatch.h>
#else
# include "compat/fnmatch.h"
#endif /* HAVE_FNMATCH */

static struct member_list empty = TAILQ_HEAD_INITIALIZER(empty);

/*
 * Check whether user described by pw matches member.
 * Returns ALLOW, DENY or UNSPEC.
 */
int
user_matches(struct sudoers_parse_tree *parse_tree, const struct passwd *pw,
    const struct member *m)
{
    const char *lhost = parse_tree->lhost ? parse_tree->lhost : user_runhost;
    const char *shost = parse_tree->shost ? parse_tree->shost : user_srunhost;
    int matched = UNSPEC;
    struct alias *a;
    debug_decl(user_matches, SUDOERS_DEBUG_MATCH)

    switch (m->type) {
	case ALL:
	    matched = !m->negated;
	    break;
	case NETGROUP:
	    if (netgr_matches(m->name,
		def_netgroup_tuple ? lhost : NULL,
		def_netgroup_tuple ? shost : NULL, pw->pw_name))
		matched = !m->negated;
	    break;
	case USERGROUP:
	    if (usergr_matches(m->name, pw->pw_name, pw))
		matched = !m->negated;
	    break;
	case ALIAS:
	    if ((a = alias_get(parse_tree, m->name, USERALIAS)) != NULL) {
		/* XXX */
		int rc = userlist_matches(parse_tree, pw, &a->members);
		if (rc != UNSPEC)
		    matched = m->negated ? !rc : rc;
		alias_put(a);
		break;
	    }
	    /* FALLTHROUGH */
	case WORD:
	    if (userpw_matches(m->name, pw->pw_name, pw))
		matched = !m->negated;
	    break;
    }
    debug_return_int(matched);
}

/*
 * Check for user described by pw in a list of members.
 * Returns ALLOW, DENY or UNSPEC.
 */
int
userlist_matches(struct sudoers_parse_tree *parse_tree, const struct passwd *pw,
    const struct member_list *list)
{
    struct member *m;
    int matched = UNSPEC;
    debug_decl(userlist_matches, SUDOERS_DEBUG_MATCH)

    TAILQ_FOREACH_REVERSE(m, list, member_list, entries) {
	if ((matched = user_matches(parse_tree, pw, m)) != UNSPEC)
	    break;
    }
    debug_return_int(matched);
}

struct gid_list *
runas_getgroups(void)
{
    const struct passwd *pw;
    debug_decl(runas_getgroups, SUDOERS_DEBUG_MATCH)

    if (def_preserve_groups) {
	sudo_gidlist_addref(user_gid_list);
	debug_return_ptr(user_gid_list);
    }

    /* Only use results from a group db query, not the front end. */
    pw = runas_pw ? runas_pw : sudo_user.pw;
    debug_return_ptr(sudo_get_gidlist(pw, ENTRY_TYPE_QUERIED));
}

/*
 * Check for user described by pw in a list of members.
 * If both lists are empty compare against def_runas_default.
 * Returns ALLOW, DENY or UNSPEC.
 */
int
runaslist_matches(struct sudoers_parse_tree *parse_tree,
    const struct member_list *user_list, const struct member_list *group_list,
    struct member **matching_user, struct member **matching_group)
{
    const char *lhost = parse_tree->lhost ? parse_tree->lhost : user_runhost;
    const char *shost = parse_tree->shost ? parse_tree->shost : user_srunhost;
    int user_matched = UNSPEC;
    int group_matched = UNSPEC;
    struct member *m;
    struct alias *a;
    int rc;
    debug_decl(runaslist_matches, SUDOERS_DEBUG_MATCH)

    if (ISSET(sudo_user.flags, RUNAS_USER_SPECIFIED) || !ISSET(sudo_user.flags, RUNAS_GROUP_SPECIFIED)) {
	/* If no runas user or runas group listed in sudoers, use default. */
	if (user_list == NULL && group_list == NULL) {
	    debug_return_int(userpw_matches(def_runas_default,
		runas_pw->pw_name, runas_pw));
	}

	if (user_list != NULL) {
	    TAILQ_FOREACH_REVERSE(m, user_list, member_list, entries) {
		switch (m->type) {
		    case ALL:
			user_matched = !m->negated;
			break;
		    case NETGROUP:
			if (netgr_matches(m->name,
			    def_netgroup_tuple ? lhost : NULL,
			    def_netgroup_tuple ? shost : NULL,
			    runas_pw->pw_name))
			    user_matched = !m->negated;
			break;
		    case USERGROUP:
			if (usergr_matches(m->name, runas_pw->pw_name, runas_pw))
			    user_matched = !m->negated;
			break;
		    case ALIAS:
			a = alias_get(parse_tree, m->name, RUNASALIAS);
			if (a != NULL) {
			    rc = runaslist_matches(parse_tree, &a->members,
				&empty, matching_user, NULL);
			    if (rc != UNSPEC)
				user_matched = m->negated ? !rc : rc;
			    alias_put(a);
			    break;
			}
			/* FALLTHROUGH */
		    case WORD:
			if (userpw_matches(m->name, runas_pw->pw_name, runas_pw))
			    user_matched = !m->negated;
			break;
		    case MYSELF:
			if (!ISSET(sudo_user.flags, RUNAS_USER_SPECIFIED) ||
			    strcmp(user_name, runas_pw->pw_name) == 0)
			    user_matched = !m->negated;
			break;
		}
		if (user_matched != UNSPEC) {
		    if (matching_user != NULL && m->type != ALIAS)
			*matching_user = m;
		    break;
		}
	    }
	}
    }

    /*
     * Skip checking runas group if none was specified.
     */
    if (ISSET(sudo_user.flags, RUNAS_GROUP_SPECIFIED)) {
	if (user_matched == UNSPEC) {
	    if (strcmp(user_name, runas_pw->pw_name) == 0)
		user_matched = ALLOW;	/* only changing group */
	}
	if (group_list != NULL) {
	    TAILQ_FOREACH_REVERSE(m, group_list, member_list, entries) {
		switch (m->type) {
		    case ALL:
			group_matched = !m->negated;
			break;
		    case ALIAS:
			a = alias_get(parse_tree, m->name, RUNASALIAS);
			if (a != NULL) {
			    rc = runaslist_matches(parse_tree, &empty,
				&a->members, NULL, matching_group);
			    if (rc != UNSPEC)
				group_matched = m->negated ? !rc : rc;
			    alias_put(a);
			    break;
			}
			/* FALLTHROUGH */
		    case WORD:
			if (group_matches(m->name, runas_gr))
			    group_matched = !m->negated;
			break;
		}
		if (group_matched != UNSPEC) {
		    if (matching_group != NULL && m->type != ALIAS)
			*matching_group = m;
		    break;
		}
	    }
	}
	if (group_matched == UNSPEC) {
	    struct gid_list *runas_groups;
	    /*
	     * The runas group was not explicitly allowed by sudoers.
	     * Check whether it is one of the target user's groups.
	     */
	    if (runas_pw->pw_gid == runas_gr->gr_gid) {
		group_matched = ALLOW;	/* runas group matches passwd db */
	    } else if ((runas_groups = runas_getgroups()) != NULL) {
		int i;

		for (i = 0; i < runas_groups->ngids; i++) {
		    if (runas_groups->gids[i] == runas_gr->gr_gid) {
			group_matched = ALLOW;	/* matched aux group vector */
			break;
		    }
		}
		sudo_gidlist_delref(runas_groups);
	    }
	}
    }

    if (user_matched == DENY || group_matched == DENY)
	debug_return_int(DENY);
    if (user_matched == group_matched || runas_gr == NULL)
	debug_return_int(user_matched);
    debug_return_int(UNSPEC);
}

/*
 * Check for lhost and shost in a list of members.
 * Returns ALLOW, DENY or UNSPEC.
 */
static int
hostlist_matches_int(struct sudoers_parse_tree *parse_tree,
    const struct passwd *pw, const char *lhost, const char *shost,
    const struct member_list *list)
{
    struct member *m;
    int matched = UNSPEC;
    debug_decl(hostlist_matches, SUDOERS_DEBUG_MATCH)

    TAILQ_FOREACH_REVERSE(m, list, member_list, entries) {
	matched = host_matches(parse_tree, pw, lhost, shost, m);
	if (matched != UNSPEC)
	    break;
    }
    debug_return_int(matched);
}

/*
 * Check for user_runhost and user_srunhost in a list of members.
 * Returns ALLOW, DENY or UNSPEC.
 */
int
hostlist_matches(struct sudoers_parse_tree *parse_tree, const struct passwd *pw,
    const struct member_list *list)
{
    const char *lhost = parse_tree->lhost ? parse_tree->lhost : user_runhost;
    const char *shost = parse_tree->shost ? parse_tree->shost : user_srunhost;

    return hostlist_matches_int(parse_tree, pw, lhost, shost, list);
}

/*
 * Check whether host or shost matches member.
 * Returns ALLOW, DENY or UNSPEC.
 */
int
host_matches(struct sudoers_parse_tree *parse_tree, const struct passwd *pw,
    const char *lhost, const char *shost, const struct member *m)
{
    struct alias *a;
    int matched = UNSPEC;
    debug_decl(host_matches, SUDOERS_DEBUG_MATCH)

    switch (m->type) {
	case ALL:
	    matched = !m->negated;
	    break;
	case NETGROUP:
	    if (netgr_matches(m->name, lhost, shost,
		def_netgroup_tuple ? pw->pw_name : NULL))
		matched = !m->negated;
	    break;
	case NTWKADDR:
	    if (addr_matches(m->name))
		matched = !m->negated;
	    break;
	case ALIAS:
	    a = alias_get(parse_tree, m->name, HOSTALIAS);
	    if (a != NULL) {
		/* XXX */
		int rc = hostlist_matches_int(parse_tree, pw, lhost, shost,
		    &a->members);
		if (rc != UNSPEC)
		    matched = m->negated ? !rc : rc;
		alias_put(a);
		break;
	    }
	    /* FALLTHROUGH */
	case WORD:
	    if (hostname_matches(shost, lhost, m->name))
		matched = !m->negated;
	    break;
    }
    debug_return_int(matched);
}

/*
 * Check for cmnd and args in a list of members.
 * Returns ALLOW, DENY or UNSPEC.
 */
int
cmndlist_matches(struct sudoers_parse_tree *parse_tree,
    const struct member_list *list)
{
    struct member *m;
    int matched = UNSPEC;
    debug_decl(cmndlist_matches, SUDOERS_DEBUG_MATCH)

    TAILQ_FOREACH_REVERSE(m, list, member_list, entries) {
	matched = cmnd_matches(parse_tree, m);
	if (matched != UNSPEC)
	    break;
    }
    debug_return_int(matched);
}

/*
 * Check cmnd and args.
 * Returns ALLOW, DENY or UNSPEC.
 */
int
cmnd_matches(struct sudoers_parse_tree *parse_tree, const struct member *m)
{
    struct alias *a;
    struct sudo_command *c;
    int rc, matched = UNSPEC;
    debug_decl(cmnd_matches, SUDOERS_DEBUG_MATCH)

    switch (m->type) {
	case ALL:
	    matched = !m->negated;
	    break;
	case ALIAS:
	    a = alias_get(parse_tree, m->name, CMNDALIAS);
	    if (a != NULL) {
		rc = cmndlist_matches(parse_tree, &a->members);
		if (rc != UNSPEC)
		    matched = m->negated ? !rc : rc;
		alias_put(a);
	    }
	    break;
	case COMMAND:
	    c = (struct sudo_command *)m->name;
	    if (command_matches(c->cmnd, c->args, c->digest))
		matched = !m->negated;
	    break;
    }
    debug_return_int(matched);
}

/*
 * Returns true if the hostname matches the pattern, else false
 */
bool
hostname_matches(const char *shost, const char *lhost, const char *pattern)
{
    const char *host;
    bool rc;
    debug_decl(hostname_matches, SUDOERS_DEBUG_MATCH)

    host = strchr(pattern, '.') != NULL ? lhost : shost;
    if (has_meta(pattern)) {
	rc = !fnmatch(pattern, host, FNM_CASEFOLD);
    } else {
	rc = !strcasecmp(host, pattern);
    }
    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"host %s matches sudoers pattern %s: %s",
	host, pattern, rc ? "true" : "false");
    debug_return_bool(rc);
}

/*
 * Returns true if the user/uid from sudoers matches the specified user/uid,
 * else returns false.
 */
bool
userpw_matches(const char *sudoers_user, const char *user, const struct passwd *pw)
{
    const char *errstr;
    uid_t uid;
    bool rc;
    debug_decl(userpw_matches, SUDOERS_DEBUG_MATCH)

    if (pw != NULL && *sudoers_user == '#') {
	uid = (uid_t) sudo_strtoid(sudoers_user + 1, &errstr);
	if (errstr == NULL && uid == pw->pw_uid) {
	    rc = true;
	    goto done;
	}
    }
    if (def_case_insensitive_user)
	rc = strcasecmp(sudoers_user, user) == 0;
    else
	rc = strcmp(sudoers_user, user) == 0;
done:
    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"user %s matches sudoers user %s: %s",
	user, sudoers_user, rc ? "true" : "false");
    debug_return_bool(rc);
}

/*
 * Returns true if the group/gid from sudoers matches the specified group/gid,
 * else returns false.
 */
bool
group_matches(const char *sudoers_group, const struct group *gr)
{
    const char *errstr;
    gid_t gid;
    bool rc;
    debug_decl(group_matches, SUDOERS_DEBUG_MATCH)

    if (*sudoers_group == '#') {
	gid = (gid_t) sudo_strtoid(sudoers_group + 1, &errstr);
	if (errstr == NULL && gid == gr->gr_gid) {
	    rc = true;
	    goto done;
	}
    }
    if (def_case_insensitive_group)
	rc = strcasecmp(sudoers_group, gr->gr_name) == 0;
    else
	rc = strcmp(sudoers_group, gr->gr_name) == 0;
done:
    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"group %s matches sudoers group %s: %s",
	gr->gr_name, sudoers_group, rc ? "true" : "false");
    debug_return_bool(rc);
}

/*
 * Returns true if the given user belongs to the named group,
 * else returns false.
 */
bool
usergr_matches(const char *group, const char *user, const struct passwd *pw)
{
    bool matched = false;
    struct passwd *pw0 = NULL;
    debug_decl(usergr_matches, SUDOERS_DEBUG_MATCH)

    /* Make sure we have a valid usergroup, sudo style */
    if (*group++ != '%') {
	sudo_debug_printf(SUDO_DEBUG_DIAG, "user group %s has no leading '%%'",
	    group);
	goto done;
    }

    /* Query group plugin for %:name groups. */
    if (*group == ':' && def_group_plugin) {
	if (group_plugin_query(user, group + 1, pw) == true)
	    matched = true;
	goto done;
    }

    /* Look up user's primary gid in the passwd file. */
    if (pw == NULL) {
	if ((pw0 = sudo_getpwnam(user)) == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_DIAG, "unable to find %s in passwd db",
		user);
	    goto done;
	}
	pw = pw0;
    }

    if (user_in_group(pw, group)) {
	matched = true;
	goto done;
    }

    /* Query the group plugin for Unix groups too? */
    if (def_group_plugin && def_always_query_group_plugin) {
	if (group_plugin_query(user, group, pw) == true) {
	    matched = true;
	    goto done;
	}
    }

done:
    if (pw0 != NULL)
	sudo_pw_delref(pw0);

    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"user %s matches group %s: %s", user, group, matched ? "true" : "false");
    debug_return_bool(matched);
}

#if defined(HAVE_GETDOMAINNAME) || defined(SI_SRPC_DOMAIN)
/*
 * Check the domain for invalid characters.
 * Linux getdomainname(2) returns (none) if no domain is set.
 */
static bool
valid_domain(const char *domain)
{
    const char *cp;
    debug_decl(valid_domain, SUDOERS_DEBUG_MATCH)

    for (cp = domain; *cp != '\0'; cp++) {
	/* Check for illegal characters, Linux may use "(none)". */
	if (*cp == '(' || *cp == ')' || *cp == ',' || *cp == ' ')
	    break;
    }
    if (cp == domain || *cp != '\0')
	debug_return_bool(false);
    debug_return_bool(true);
}

/*
 * Get NIS-style domain name and copy from static storage or NULL if none.
 */
const char *
sudo_getdomainname(void)
{
    static char *domain;
    static bool initialized;
    debug_decl(sudo_getdomainname, SUDOERS_DEBUG_MATCH)

    if (!initialized) {
	size_t host_name_max;
	int rc;

# ifdef _SC_HOST_NAME_MAX
	host_name_max = (size_t)sysconf(_SC_HOST_NAME_MAX);
	if (host_name_max == (size_t)-1)
# endif
	    host_name_max = 255;    /* POSIX and historic BSD */

	domain = malloc(host_name_max + 1);
	if (domain != NULL) {
	    domain[0] = '\0';
# ifdef SI_SRPC_DOMAIN
	    rc = sysinfo(SI_SRPC_DOMAIN, domain, host_name_max + 1);
# else
	    rc = getdomainname(domain, host_name_max + 1);
# endif
	    if (rc == -1 || !valid_domain(domain)) {
		/* Error or invalid domain name. */
		free(domain);
		domain = NULL;
	    }
	} else {
	    /* XXX - want to pass error back to caller */
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to allocate memory");
	}
	initialized = true;
    }
    debug_return_str(domain);
}
#else
const char *
sudo_getdomainname(void)
{
    debug_decl(sudo_getdomainname, SUDOERS_DEBUG_MATCH)
    debug_return_ptr(NULL);
}
#endif /* HAVE_GETDOMAINNAME || SI_SRPC_DOMAIN */

/*
 * Returns true if "host" and "user" belong to the netgroup "netgr",
 * else return false.  Either of "lhost", "shost" or "user" may be NULL
 * in which case that argument is not checked...
 */
bool
netgr_matches(const char *netgr, const char *lhost, const char *shost, const char *user)
{
#ifdef HAVE_INNETGR
    const char *domain;
#endif
    bool rc = false;
    debug_decl(netgr_matches, SUDOERS_DEBUG_MATCH)

    if (!def_use_netgroups) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "netgroups are disabled");
	debug_return_bool(false);
    }

#ifdef HAVE_INNETGR
    /* make sure we have a valid netgroup, sudo style */
    if (*netgr++ != '+') {
	sudo_debug_printf(SUDO_DEBUG_DIAG, "netgroup %s has no leading '+'",
	    netgr);
	debug_return_bool(false);
    }

    /* get the domain name (if any) */
    domain = sudo_getdomainname();

    if (innetgr(netgr, lhost, user, domain))
	rc = true;
    else if (lhost != shost && innetgr(netgr, shost, user, domain))
	rc = true;

    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"netgroup %s matches (%s|%s, %s, %s): %s", netgr, lhost ? lhost : "",
	shost ? shost : "", user ? user : "", domain ? domain : "",
	rc ? "true" : "false");
#endif /* HAVE_INNETGR */

    debug_return_bool(rc);
}
