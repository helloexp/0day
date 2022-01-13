/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1996, 1998-2005, 2007-2018
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
#ifdef HAVE_NETGROUP_H
# include <netgroup.h>
#endif /* HAVE_NETGROUP_H */
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tsgetgrpw.h"
#include "sudoers.h"
#include "interfaces.h"
#include "sudo_conf.h"
#include "sudo_lbuf.h"
#include <gram.h>

#ifndef YYDEBUG
# define YYDEBUG 0
#endif

enum sudoers_formats {
    format_ldif,
    format_sudoers
};

/*
 * Function Prototypes
 */
static void dump_sudoers(struct sudo_lbuf *lbuf);
static void usage(void) __attribute__((__noreturn__));
static void set_runaspw(const char *);
static void set_runasgr(const char *);
static bool cb_runas_default(const union sudo_defs_val *);
static int testsudoers_error(const char *msg);
static int testsudoers_output(const char *buf);

/* tsgetgrpw.c */
extern void setgrfile(const char *);
extern void setgrent(void);
extern void endgrent(void);
extern struct group *getgrent(void);
extern struct group *getgrnam(const char *);
extern struct group *getgrgid(gid_t);
extern void setpwfile(const char *);
extern void setpwent(void);
extern void endpwent(void);
extern struct passwd *getpwent(void);
extern struct passwd *getpwnam(const char *);
extern struct passwd *getpwuid(uid_t);

/* gram.y */
extern int (*trace_print)(const char *msg);

/*
 * Globals
 */
struct sudo_user sudo_user;
struct passwd *list_pw;
static char *runas_group, *runas_user;

#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
extern char *malloc_options;
#endif
#if YYDEBUG
extern int sudoersdebug;
#endif

__dso_public int main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    enum sudoers_formats input_format = format_sudoers;
    struct cmndspec *cs;
    struct privilege *priv;
    struct userspec *us;
    char *p, *grfile, *pwfile;
    const char *errstr;
    int match, host_match, runas_match, cmnd_match;
    int ch, dflag, exitcode = EXIT_FAILURE;
    struct sudo_lbuf lbuf;
    debug_decl(main, SUDOERS_DEBUG_MAIN)

#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
    malloc_options = "S";
#endif
#if YYDEBUG
    sudoersdebug = 1;
#endif

    initprogname(argc > 0 ? argv[0] : "testsudoers");

    if (!sudoers_initlocale(setlocale(LC_ALL, ""), def_sudoers_locale))
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    sudo_warn_set_locale_func(sudoers_warn_setlocale);
    bindtextdomain("sudoers", LOCALEDIR); /* XXX - should have own domain */
    textdomain("sudoers");

    /* No word wrap on output. */
    sudo_lbuf_init(&lbuf, testsudoers_output, 0, NULL, 0);

    /* Initialize the debug subsystem. */
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG) == -1)
	goto done;
    if (!sudoers_debug_register(getprogname(), sudo_conf_debug_files(getprogname())))
	goto done;

    dflag = 0;
    grfile = pwfile = NULL;
    while ((ch = getopt(argc, argv, "dg:G:h:i:P:p:tu:U:")) != -1) {
	switch (ch) {
	    case 'd':
		dflag = 1;
		break;
	    case 'G':
		sudoers_gid = (gid_t)sudo_strtoid(optarg, &errstr);
		if (errstr != NULL)
		    sudo_fatalx("group-ID %s: %s", optarg, errstr);
		break;
	    case 'g':
		runas_group = optarg;
		SET(sudo_user.flags, RUNAS_GROUP_SPECIFIED);
		break;
	    case 'h':
		user_host = optarg;
		break;
	    case 'i':
		if (strcasecmp(optarg, "ldif") == 0) {
		    input_format = format_ldif;
		} else if (strcasecmp(optarg, "sudoers") == 0) {
		    input_format = format_sudoers;
		} else {
		    sudo_warnx(U_("unsupported input format %s"), optarg);
		    usage();
		}
		break;
	    case 'p':
		pwfile = optarg;
		break;
	    case 'P':
		grfile = optarg;
		break;
	    case 't':
		trace_print = testsudoers_error;
		break;
	    case 'U':
		sudoers_uid = (uid_t)sudo_strtoid(optarg, &errstr);
		if (errstr != NULL)
		    sudo_fatalx("user-ID %s: %s", optarg, errstr);
		break;
	    case 'u':
		runas_user = optarg;
		SET(sudo_user.flags, RUNAS_USER_SPECIFIED);
		break;
	    default:
		usage();
		break;
	}
    }
    argc -= optind;
    argv += optind;

    /* Set group/passwd file and init the cache. */
    if (grfile)
	setgrfile(grfile);
    if (pwfile)
	setpwfile(pwfile);

    if (argc < 2) {
	if (!dflag)
	    usage();
	user_name = argc ? *argv++ : "root";
	user_cmnd = user_base = "true";
	argc = 0;
    } else {
	user_name = *argv++;
	user_cmnd = *argv++;
	if ((p = strrchr(user_cmnd, '/')) != NULL)
	    user_base = p + 1;
	else
	    user_base = user_cmnd;
	argc -= 2;
    }
    if ((sudo_user.pw = sudo_getpwnam(user_name)) == NULL)
	sudo_fatalx(U_("unknown user: %s"), user_name);

    if (user_host == NULL) {
	if ((user_host = sudo_gethostname()) == NULL)
	    sudo_fatal("gethostname");
    }
    if ((p = strchr(user_host, '.'))) {
	*p = '\0';
	if ((user_shost = strdup(user_host)) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	*p = '.';
    } else {
	user_shost = user_host;
    }
    user_runhost = user_host;
    user_srunhost = user_shost;

    /* Fill in user_args from argv. */
    if (argc > 0) {
	char *to, **from;
	size_t size, n;

	for (size = 0, from = argv; *from; from++)
	    size += strlen(*from) + 1;

	if ((user_args = malloc(size)) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	for (to = user_args, from = argv; *from; from++) {
	    n = strlcpy(to, *from, size - (to - user_args));
	    if (n >= size - (to - user_args))
		sudo_fatalx(U_("internal error, %s overflow"), getprogname());
	    to += n;
	    *to++ = ' ';
	}
	*--to = '\0';
    }

    /* Initialize default values. */
    if (!init_defaults())
	sudo_fatalx(U_("unable to initialize sudoers default values"));

    /* Set group_plugin callback. */
    sudo_defs_table[I_GROUP_PLUGIN].callback = cb_group_plugin;

    /* Set runas callback. */
    sudo_defs_table[I_RUNAS_DEFAULT].callback = cb_runas_default;

    /* Set locale callback. */
    sudo_defs_table[I_SUDOERS_LOCALE].callback = sudoers_locale_callback;

    /* Load ip addr/mask for each interface. */
    if (get_net_ifs(&p) > 0) {
	if (!set_interfaces(p))
	    sudo_fatal(U_("unable to parse network address list"));
    }

    /* Allocate space for data structures in the parser. */
    init_parser("sudoers", false, true);

    /*
     * Set runas passwd/group entries based on command line or sudoers.
     * Note that if runas_group was specified without runas_user we
     * run the command as the invoking user.
     */
    if (runas_group != NULL) {
        set_runasgr(runas_group);
        set_runaspw(runas_user ? runas_user : user_name);
    } else
        set_runaspw(runas_user ? runas_user : def_runas_default);

    /* Parse the policy file. */
    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, NULL);
    switch (input_format) {
    case format_ldif:
        if (!sudoers_parse_ldif(&parsed_policy, stdin, NULL, true))
	    (void) printf("Parse error in LDIF");
	else
	    (void) fputs("Parses OK", stdout);
        break;
    case format_sudoers:
	if (sudoersparse() != 0 || parse_error) {
	    parse_error = true;
	    if (errorlineno != -1)
		(void) printf("Parse error in %s near line %d",
		    errorfile, errorlineno);
	    else
		(void) printf("Parse error in %s", errorfile);
	} else {
	    (void) fputs("Parses OK", stdout);
	}
        break;
    default:
        sudo_fatalx("error: unhandled input %d", input_format);
    }

    if (!update_defaults(&parsed_policy, NULL, SETDEF_ALL, false))
	(void) fputs(" (problem with defaults entries)", stdout);
    puts(".");

    if (dflag) {
	(void) putchar('\n');
	dump_sudoers(&lbuf);
	if (argc < 2) {
	    exitcode = parse_error ? 1 : 0;
	    goto done;
	}
    }

    /* This loop must match the one in sudo_file_lookup() */
    printf("\nEntries for user %s:\n", user_name);
    match = UNSPEC;
    TAILQ_FOREACH_REVERSE(us, &parsed_policy.userspecs, userspec_list, entries) {
	if (userlist_matches(&parsed_policy, sudo_user.pw, &us->users) != ALLOW)
	    continue;
	TAILQ_FOREACH_REVERSE(priv, &us->privileges, privilege_list, entries) {
	    sudo_lbuf_append(&lbuf, "\n");
	    sudoers_format_privilege(&lbuf, &parsed_policy, priv, false);
	    sudo_lbuf_print(&lbuf);
	    host_match = hostlist_matches(&parsed_policy, sudo_user.pw,
		&priv->hostlist);
	    if (host_match == ALLOW) {
		puts("\thost  matched");
		TAILQ_FOREACH_REVERSE(cs, &priv->cmndlist, cmndspec_list, entries) {
		    runas_match = runaslist_matches(&parsed_policy,
			cs->runasuserlist, cs->runasgrouplist, NULL, NULL);
		    if (runas_match == ALLOW) {
			puts("\trunas matched");
			cmnd_match = cmnd_matches(&parsed_policy, cs->cmnd);
			if (cmnd_match != UNSPEC)
			    match = cmnd_match;
			printf("\tcmnd  %s\n", match == ALLOW ? "allowed" :
			    match == DENY ? "denied" : "unmatched");
		    }
		}
	    } else
		puts(U_("\thost  unmatched"));
	}
    }
    puts(match == ALLOW ? U_("\nCommand allowed") :
	match == DENY ?  U_("\nCommand denied") :  U_("\nCommand unmatched"));

    /*
     * Exit codes:
     *	0 - parsed OK and command matched.
     *	1 - parse error
     *	2 - command not matched
     *	3 - command denied
     */
    exitcode = parse_error ? 1 : (match == ALLOW ? 0 : match + 3);
done:
    sudo_lbuf_destroy(&lbuf);
    sudo_freepwcache();
    sudo_freegrcache();
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, exitcode);
    exit(exitcode);
}

static void
set_runaspw(const char *user)
{
    struct passwd *pw = NULL;
    debug_decl(set_runaspw, SUDOERS_DEBUG_UTIL)

    if (*user == '#') {
	const char *errstr;
	uid_t uid = sudo_strtoid(user + 1, &errstr);
	if (errstr == NULL) {
	    if ((pw = sudo_getpwuid(uid)) == NULL)
		pw = sudo_fakepwnam(user, user_gid);
	}
    }
    if (pw == NULL) {
	if ((pw = sudo_getpwnam(user)) == NULL)
	    sudo_fatalx(U_("unknown user: %s"), user);
    }
    if (runas_pw != NULL)
	sudo_pw_delref(runas_pw);
    runas_pw = pw;
    debug_return;
}

static void
set_runasgr(const char *group)
{
    struct group *gr = NULL;
    debug_decl(set_runasgr, SUDOERS_DEBUG_UTIL)

    if (*group == '#') {
	const char *errstr;
	gid_t gid = sudo_strtoid(group + 1, &errstr);
	if (errstr == NULL) {
	    if ((gr = sudo_getgrgid(gid)) == NULL)
		gr = sudo_fakegrnam(group);
	}
    }
    if (gr == NULL) {
	if ((gr = sudo_getgrnam(group)) == NULL)
	    sudo_fatalx(U_("unknown group: %s"), group);
    }
    if (runas_gr != NULL)
	sudo_gr_delref(runas_gr);
    runas_gr = gr;
    debug_return;
}

/* 
 * Callback for runas_default sudoers setting.
 */
static bool
cb_runas_default(const union sudo_defs_val *sd_un)
{
    /* Only reset runaspw if user didn't specify one. */
    if (!runas_user && !runas_group)
        set_runaspw(sd_un->str);
    return true;
}

void
sudo_setspent(void)
{
    return;
}

void
sudo_endspent(void)
{
    return;
}

FILE *
open_sudoers(const char *sudoers, bool doedit, bool *keepopen)
{
    struct stat sb;
    FILE *fp = NULL;
    char *sudoers_base;
    debug_decl(open_sudoers, SUDOERS_DEBUG_UTIL)

    sudoers_base = strrchr(sudoers, '/');
    if (sudoers_base != NULL)
	sudoers_base++;

    switch (sudo_secure_file(sudoers, sudoers_uid, sudoers_gid, &sb)) {
	case SUDO_PATH_SECURE:
	    fp = fopen(sudoers, "r");
	    break;
	case SUDO_PATH_MISSING:
	    sudo_warn("unable to stat %s", sudoers_base);
	    break;
	case SUDO_PATH_BAD_TYPE:
	    sudo_warnx("%s is not a regular file", sudoers_base);
	    break;
	case SUDO_PATH_WRONG_OWNER:
	    sudo_warnx("%s should be owned by uid %u",
		sudoers_base, (unsigned int) sudoers_uid);
	    break;
	case SUDO_PATH_WORLD_WRITABLE:
	    sudo_warnx("%s is world writable", sudoers_base);
	    break;
	case SUDO_PATH_GROUP_WRITABLE:
	    sudo_warnx("%s should be owned by gid %u",
		sudoers_base, (unsigned int) sudoers_gid);
	    break;
	default:
	    /* NOTREACHED */
	    break;
    }

    debug_return_ptr(fp);
}

bool
init_envtables(void)
{
    return(true);
}

bool
set_perms(int perm)
{
    return true;
}

bool
restore_perms(void)
{
    return true;
}

static bool
print_defaults(struct sudo_lbuf *lbuf)
{
    struct defaults *def, *next;
    debug_decl(print_defaults, SUDOERS_DEBUG_UTIL)

    TAILQ_FOREACH_SAFE(def, &parsed_policy.defaults, entries, next)
	sudoers_format_default_line(lbuf, &parsed_policy, def, &next, false);

    debug_return_bool(!sudo_lbuf_error(lbuf));
}

static int
print_alias(struct sudoers_parse_tree *parse_tree, struct alias *a, void *v)
{
    struct sudo_lbuf *lbuf = v;
    struct member *m;
    debug_decl(print_alias, SUDOERS_DEBUG_UTIL)

    sudo_lbuf_append(lbuf, "%s %s = ", alias_type_to_string(a->type),
	a->name);
    TAILQ_FOREACH(m, &a->members, entries) {
	if (m != TAILQ_FIRST(&a->members))
	    sudo_lbuf_append(lbuf, ", ");
	sudoers_format_member(lbuf, parse_tree, m, NULL, UNSPEC);
    }
    sudo_lbuf_append(lbuf, "\n");

    debug_return_int(sudo_lbuf_error(lbuf) ? -1 : 0);
}

static bool
print_aliases(struct sudo_lbuf *lbuf)
{
    debug_decl(print_aliases, SUDOERS_DEBUG_UTIL)

    alias_apply(&parsed_policy, print_alias, lbuf);

    debug_return_bool(!sudo_lbuf_error(lbuf));
}

static void
dump_sudoers(struct sudo_lbuf *lbuf)
{
    debug_decl(dump_sudoers, SUDOERS_DEBUG_UTIL)

    /* Print Defaults */
    if (!print_defaults(lbuf))
	goto done;
    if (lbuf->len > 0) {
	sudo_lbuf_print(lbuf);
	sudo_lbuf_append(lbuf, "\n");
    }

    /* Print Aliases */
    if (!print_aliases(lbuf))
	goto done;
    if (lbuf->len > 1) {
	sudo_lbuf_print(lbuf);
	sudo_lbuf_append(lbuf, "\n");
    }

    /* Print User_Specs */
    if (!sudoers_format_userspecs(lbuf, &parsed_policy, NULL, false, true))
	goto done;
    if (lbuf->len > 1) {
	sudo_lbuf_print(lbuf);
    }

done:
    if (sudo_lbuf_error(lbuf)) {
	if (errno == ENOMEM)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    }

    debug_return;
}

static int
testsudoers_output(const char *buf)
{
    return fputs(buf, stdout);
}

static int
testsudoers_error(const char *buf)
{
    return fputs(buf, stderr);
}

static void
usage(void)
{
    (void) fprintf(stderr, "usage: %s [-dt] [-G sudoers_gid] [-g group] [-h host] [-i input_format] [-P grfile] [-p pwfile] [-U sudoers_uid] [-u user] <user> <command> [args]\n", getprogname());
    exit(1);
}
