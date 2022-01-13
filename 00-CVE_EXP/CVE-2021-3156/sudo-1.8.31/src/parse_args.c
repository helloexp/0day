/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1993-1996, 1998-2017 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <assert.h>

#include <sudo_usage.h>
#include "sudo.h"
#include "sudo_lbuf.h"

#ifdef HAVE_GETOPT_LONG
# include <getopt.h>
# else
# include "compat/getopt.h"
#endif /* HAVE_GETOPT_LONG */

int tgetpass_flags;

/*
 * Local functions.
 */
static void help(void) __attribute__((__noreturn__));
static void usage_excl(int);

/*
 * Mapping of command line flags to name/value settings.
 */
static struct sudo_settings sudo_settings[] = {
#define ARG_BSDAUTH_TYPE 0
    { "bsdauth_type" },
#define ARG_LOGIN_CLASS 1
    { "login_class" },
#define ARG_PRESERVE_ENVIRONMENT 2
    { "preserve_environment" },
#define ARG_RUNAS_GROUP 3
    { "runas_group" },
#define ARG_SET_HOME 4
    { "set_home" },
#define ARG_USER_SHELL 5
    { "run_shell" },
#define ARG_LOGIN_SHELL 6
    { "login_shell" },
#define ARG_IGNORE_TICKET 7
    { "ignore_ticket" },
#define ARG_PROMPT 8
    { "prompt" },
#define ARG_SELINUX_ROLE 9
    { "selinux_role" },
#define ARG_SELINUX_TYPE 10
    { "selinux_type" },
#define ARG_RUNAS_USER 11
    { "runas_user" },
#define ARG_PROGNAME 12
    { "progname" },
#define ARG_IMPLIED_SHELL 13
    { "implied_shell" },
#define ARG_PRESERVE_GROUPS 14
    { "preserve_groups" },
#define ARG_NONINTERACTIVE 15
    { "noninteractive" },
#define ARG_SUDOEDIT 16
    { "sudoedit" },
#define ARG_CLOSEFROM 17
    { "closefrom" },
#define ARG_NET_ADDRS 18
    { "network_addrs" },
#define ARG_MAX_GROUPS 19
    { "max_groups" },
#define ARG_PLUGIN_DIR 20
    { "plugin_dir" },
#define ARG_REMOTE_HOST 21
    { "remote_host" },
#define ARG_TIMEOUT 22
    { "timeout" },
#define NUM_SETTINGS 23
    { NULL }
};

struct environment {
    char **envp;		/* pointer to the new environment */
    size_t env_size;		/* size of new_environ in char **'s */
    size_t env_len;		/* number of slots used, not counting NULL */
};

/*
 * Default flags allowed when running a command.
 */
#define DEFAULT_VALID_FLAGS	(MODE_BACKGROUND|MODE_PRESERVE_ENV|MODE_RESET_HOME|MODE_LOGIN_SHELL|MODE_NONINTERACTIVE|MODE_SHELL)

/* Option number for the --host long option due to ambiguity of the -h flag. */
#define OPT_HOSTNAME	256

/*
 * Available command line options, both short and long.
 * Note that we must disable arg permutation to support setting environment
 * variables and to better support the optional arg of the -h flag.
 */
static const char short_opts[] =  "+Aa:BbC:c:D:Eeg:Hh::iKklnPp:r:SsT:t:U:u:Vv";
static struct option long_opts[] = {
    { "askpass",	no_argument,		NULL,	'A' },
    { "auth-type",	required_argument,	NULL,	'a' },
    { "background",	no_argument,		NULL,	'b' },
    { "bell",	        no_argument,		NULL,	'B' },
    { "close-from",	required_argument,	NULL,	'C' },
    { "login-class",	required_argument,	NULL,	'c' },
    { "preserve-env",	optional_argument,	NULL,	'E' },
    { "edit",		no_argument,		NULL,	'e' },
    { "group",		required_argument,	NULL,	'g' },
    { "set-home",	no_argument,		NULL,	'H' },
    { "help",		no_argument,		NULL,	'h' },
    { "host",		required_argument,	NULL,	OPT_HOSTNAME },
    { "login",		no_argument,		NULL,	'i' },
    { "remove-timestamp", no_argument,		NULL,	'K' },
    { "reset-timestamp", no_argument,		NULL,	'k' },
    { "list",		no_argument,		NULL,	'l' },
    { "non-interactive", no_argument,		NULL,	'n' },
    { "preserve-groups", no_argument,		NULL,	'P' },
    { "prompt",		required_argument,	NULL,	'p' },
    { "role",		required_argument,	NULL,	'r' },
    { "stdin",		no_argument,		NULL,	'S' },
    { "shell",		no_argument,		NULL,	's' },
    { "type",		required_argument,	NULL,	't' },
    { "command-timeout",required_argument,	NULL,	'T' },
    { "other-user",	required_argument,	NULL,	'U' },
    { "user",		required_argument,	NULL,	'u' },
    { "version",	no_argument,		NULL,	'V' },
    { "validate",	no_argument,		NULL,	'v' },
    { NULL,		no_argument,		NULL,	'\0' },
};

/*
 * Insert a key=value pair into the specified environment.
 */
static void
env_insert(struct environment *e, char *pair)
{
    debug_decl(env_insert, SUDO_DEBUG_ARGS)

    /* Make sure we have at least two slots free (one for NULL). */
    if (e->env_len + 1 >= e->env_size) {
	char **tmp;

	if (e->env_size == 0)
	    e->env_size = 16;
	tmp = reallocarray(e->envp, e->env_size, 2 * sizeof(char *));
	if (tmp == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	e->envp = tmp;
	e->env_size *= 2;
    }
    e->envp[e->env_len++] = pair;
    e->envp[e->env_len] = NULL;

    debug_return;
}

/*
 * Format as var=val and insert into the specified environment.
 */
static void
env_set(struct environment *e, char *var, char *val)
{
    char *pair;
    debug_decl(env_set, SUDO_DEBUG_ARGS)

    pair = sudo_new_key_val(var, val);
    if (pair == NULL) {
	sudo_fatalx(U_("%s: %s"),
	    __func__, U_("unable to allocate memory"));
    }
    env_insert(e, pair);

    debug_return;
}

/*
 * Parse a comma-separated list of env vars and add to the
 * specified environment.
 */
static void
parse_env_list(struct environment *e, char *list)
{
    char *cp, *last, *val;
    debug_decl(parse_env_list, SUDO_DEBUG_ARGS)

    for ((cp = strtok_r(list, ",", &last)); cp != NULL;
	(cp = strtok_r(NULL, ",", &last))) {
	if (strchr(cp, '=') != NULL) {
	    sudo_warnx(U_("invalid environment variable name: %s"), cp);
	    usage(1);
	}
	if ((val = getenv(cp)) != NULL)
	    env_set(e, cp, val);
    }
    debug_return;
}

/*
 * Command line argument parsing.
 * Sets nargc and nargv which corresponds to the argc/argv we'll use
 * for the command to be run (if we are running one).
 */
int
parse_args(int argc, char **argv, int *nargc, char ***nargv,
    struct sudo_settings **settingsp, char ***env_addp)
{
    struct environment extra_env;
    int mode = 0;		/* what mode is sudo to be run in? */
    int flags = 0;		/* mode flags */
    int valid_flags = DEFAULT_VALID_FLAGS;
    int ch, i;
    char *cp;
    const char *runas_user = NULL;
    const char *runas_group = NULL;
    const char *progname;
    int proglen;
    debug_decl(parse_args, SUDO_DEBUG_ARGS)

    /* Is someone trying something funny? */
    if (argc <= 0)
	usage(1);

    /* Pass progname to plugin so it can call initprogname() */
    progname = getprogname();
    sudo_settings[ARG_PROGNAME].value = progname;

    /* First, check to see if we were invoked as "sudoedit". */
    proglen = strlen(progname);
    if (proglen > 4 && strcmp(progname + proglen - 4, "edit") == 0) {
	progname = "sudoedit";
	mode = MODE_EDIT;
	sudo_settings[ARG_SUDOEDIT].value = "true";
    }

    /* Load local IP addresses and masks. */
    if (get_net_ifs(&cp) > 0)
	sudo_settings[ARG_NET_ADDRS].value = cp;

    /* Set max_groups from sudo.conf. */
    i = sudo_conf_max_groups();
    if (i != -1) {
	if (asprintf(&cp, "%d", i) == -1)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	sudo_settings[ARG_MAX_GROUPS].value = cp;
    }

    /* Returns true if the last option string was "-h" */
#define got_host_flag	(optind > 1 && argv[optind - 1][0] == '-' && \
	    argv[optind - 1][1] == 'h' && argv[optind - 1][2] == '\0')

    /* Returns true if the last option string was "--" */
#define got_end_of_args	(optind > 1 && argv[optind - 1][0] == '-' && \
	    argv[optind - 1][1] == '-' && argv[optind - 1][2] == '\0')

    /* Returns true if next option is an environment variable */
#define is_envar (optind < argc && argv[optind][0] != '/' && \
	    strchr(argv[optind], '=') != NULL)

    /* Space for environment variables is lazy allocated. */
    memset(&extra_env, 0, sizeof(extra_env));

    /* XXX - should fill in settings at the end to avoid dupes */
    for (;;) {
	/*
	 * Some trickiness is required to allow environment variables
	 * to be interspersed with command line options.
	 */
	if ((ch = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
	    switch (ch) {
		case 'A':
		    SET(tgetpass_flags, TGP_ASKPASS);
		    break;
#ifdef HAVE_BSD_AUTH_H
		case 'a':
		    assert(optarg != NULL);
		    if (*optarg == '\0')
			usage(1);
		    sudo_settings[ARG_BSDAUTH_TYPE].value = optarg;
		    break;
#endif
		case 'b':
		    SET(flags, MODE_BACKGROUND);
		    break;
		case 'B':
		    SET(tgetpass_flags, TGP_BELL);
		    break;
		case 'C':
		    assert(optarg != NULL);
		    if (sudo_strtonum(optarg, 3, INT_MAX, NULL) == 0) {
			sudo_warnx(U_("the argument to -C must be a number greater than or equal to 3"));
			usage(1);
		    }
		    sudo_settings[ARG_CLOSEFROM].value = optarg;
		    break;
#ifdef HAVE_LOGIN_CAP_H
		case 'c':
		    assert(optarg != NULL);
		    if (*optarg == '\0')
			usage(1);
		    sudo_settings[ARG_LOGIN_CLASS].value = optarg;
		    break;
#endif
		case 'D':
		    /* Ignored for backwards compatibility. */
		    break;
		case 'E':
		    /*
		     * Optional argument is a comma-separated list of
		     * environment variables to preserve.
		     * If not present, preserve everything.
		     */
		    if (optarg == NULL) {
			sudo_settings[ARG_PRESERVE_ENVIRONMENT].value = "true";
			SET(flags, MODE_PRESERVE_ENV);
		    } else {
			parse_env_list(&extra_env, optarg);
		    }
		    break;
		case 'e':
		    if (mode && mode != MODE_EDIT)
			usage_excl(1);
		    mode = MODE_EDIT;
		    sudo_settings[ARG_SUDOEDIT].value = "true";
		    valid_flags = MODE_NONINTERACTIVE;
		    break;
		case 'g':
		    assert(optarg != NULL);
		    if (*optarg == '\0')
			usage(1);
		    runas_group = optarg;
		    sudo_settings[ARG_RUNAS_GROUP].value = optarg;
		    break;
		case 'H':
		    sudo_settings[ARG_SET_HOME].value = "true";
		    break;
		case 'h':
		    if (optarg == NULL) {
			/*
			 * Optional args support -hhostname, not -h hostname.
			 * If we see a non-option after the -h flag, treat as
			 * remote host and bump optind to skip over it.
			 */
			if (got_host_flag && !is_envar &&
			    argv[optind] != NULL && argv[optind][0] != '-') {
			    sudo_settings[ARG_REMOTE_HOST].value = argv[optind++];
			    continue;
			}
			if (mode && mode != MODE_HELP) {
			    if (strcmp(progname, "sudoedit") != 0)
				usage_excl(1);
			}
			mode = MODE_HELP;
			valid_flags = 0;
			break;
		    }
		    /* FALLTHROUGH */
		case OPT_HOSTNAME:
		    assert(optarg != NULL);
		    if (*optarg == '\0')
			usage(1);
		    sudo_settings[ARG_REMOTE_HOST].value = optarg;
		    break;
		case 'i':
		    sudo_settings[ARG_LOGIN_SHELL].value = "true";
		    SET(flags, MODE_LOGIN_SHELL);
		    break;
		case 'k':
		    sudo_settings[ARG_IGNORE_TICKET].value = "true";
		    break;
		case 'K':
		    sudo_settings[ARG_IGNORE_TICKET].value = "true";
		    if (mode && mode != MODE_KILL)
			usage_excl(1);
		    mode = MODE_KILL;
		    valid_flags = 0;
		    break;
		case 'l':
		    if (mode) {
			if (mode == MODE_LIST)
			    SET(flags, MODE_LONG_LIST);
			else
			    usage_excl(1);
		    }
		    mode = MODE_LIST;
		    valid_flags = MODE_NONINTERACTIVE|MODE_LONG_LIST;
		    break;
		case 'n':
		    SET(flags, MODE_NONINTERACTIVE);
		    sudo_settings[ARG_NONINTERACTIVE].value = "true";
		    break;
		case 'P':
		    sudo_settings[ARG_PRESERVE_GROUPS].value = "true";
		    break;
		case 'p':
		    /* An empty prompt is allowed. */
		    assert(optarg != NULL);
		    sudo_settings[ARG_PROMPT].value = optarg;
		    break;
#ifdef HAVE_SELINUX
		case 'r':
		    assert(optarg != NULL);
		    if (*optarg == '\0')
			usage(1);
		    sudo_settings[ARG_SELINUX_ROLE].value = optarg;
		    break;
		case 't':
		    assert(optarg != NULL);
		    if (*optarg == '\0')
			usage(1);
		    sudo_settings[ARG_SELINUX_TYPE].value = optarg;
		    break;
#endif
		case 'T':
		    /* Plugin determines whether empty timeout is allowed. */
		    assert(optarg != NULL);
		    sudo_settings[ARG_TIMEOUT].value = optarg;
		    break;
		case 'S':
		    SET(tgetpass_flags, TGP_STDIN);
		    break;
		case 's':
		    sudo_settings[ARG_USER_SHELL].value = "true";
		    SET(flags, MODE_SHELL);
		    break;
		case 'U':
		    assert(optarg != NULL);
		    if (*optarg == '\0')
			usage(1);
		    list_user = optarg;
		    break;
		case 'u':
		    assert(optarg != NULL);
		    if (*optarg == '\0')
			usage(1);
		    runas_user = optarg;
		    sudo_settings[ARG_RUNAS_USER].value = optarg;
		    break;
		case 'v':
		    if (mode && mode != MODE_VALIDATE)
			usage_excl(1);
		    mode = MODE_VALIDATE;
		    valid_flags = MODE_NONINTERACTIVE;
		    break;
		case 'V':
		    if (mode && mode != MODE_VERSION)
			usage_excl(1);
		    mode = MODE_VERSION;
		    valid_flags = 0;
		    break;
		default:
		    usage(1);
	    }
	} else if (!got_end_of_args && is_envar) {
	    /* Insert key=value pair, crank optind and resume getopt. */
	    env_insert(&extra_env, argv[optind]);
	    optind++;
	} else {
	    /* Not an option or an environment variable -- we're done. */
	    break;
	}
    }

    argc -= optind;
    argv += optind;

    if (!mode) {
	/* Defer -k mode setting until we know whether it is a flag or not */
	if (sudo_settings[ARG_IGNORE_TICKET].value != NULL) {
	    if (argc == 0 && !(flags & (MODE_SHELL|MODE_LOGIN_SHELL))) {
		mode = MODE_INVALIDATE;	/* -k by itself */
		sudo_settings[ARG_IGNORE_TICKET].value = NULL;
		valid_flags = 0;
	    }
	}
	if (!mode)
	    mode = MODE_RUN;		/* running a command */
    }

    if (argc > 0 && mode == MODE_LIST)
	mode = MODE_CHECK;

    if (ISSET(flags, MODE_LOGIN_SHELL)) {
	if (ISSET(flags, MODE_SHELL)) {
	    sudo_warnx(U_("you may not specify both the `-i' and `-s' options"));
	    usage(1);
	}
	if (ISSET(flags, MODE_PRESERVE_ENV)) {
	    sudo_warnx(U_("you may not specify both the `-i' and `-E' options"));
	    usage(1);
	}
	SET(flags, MODE_SHELL);
    }
    if ((flags & valid_flags) != flags)
	usage(1);
    if (mode == MODE_EDIT &&
       (ISSET(flags, MODE_PRESERVE_ENV) || extra_env.env_len != 0)) {
	if (ISSET(mode, MODE_PRESERVE_ENV))
	    sudo_warnx(U_("the `-E' option is not valid in edit mode"));
	if (extra_env.env_len != 0)
	    sudo_warnx(U_("you may not specify environment variables in edit mode"));
	usage(1);
    }
    if ((runas_user != NULL || runas_group != NULL) &&
	!ISSET(mode, MODE_EDIT | MODE_RUN | MODE_CHECK | MODE_VALIDATE)) {
	usage(1);
    }
    if (list_user != NULL && mode != MODE_LIST && mode != MODE_CHECK) {
	sudo_warnx(U_("the `-U' option may only be used with the `-l' option"));
	usage(1);
    }
    if (ISSET(tgetpass_flags, TGP_STDIN) && ISSET(tgetpass_flags, TGP_ASKPASS)) {
	sudo_warnx(U_("the `-A' and `-S' options may not be used together"));
	usage(1);
    }
    if ((argc == 0 && mode == MODE_EDIT) ||
	(argc > 0 && !ISSET(mode, MODE_RUN | MODE_EDIT | MODE_CHECK)))
	usage(1);
    if (argc == 0 && mode == MODE_RUN && !ISSET(flags, MODE_SHELL)) {
	SET(flags, (MODE_IMPLIED_SHELL | MODE_SHELL));
	sudo_settings[ARG_IMPLIED_SHELL].value = "true";
    }
#ifdef ENABLE_SUDO_PLUGIN_API
    sudo_settings[ARG_PLUGIN_DIR].value = sudo_conf_plugin_dir_path();
#endif

    if (mode == MODE_HELP)
	help();

    /*
     * For shell mode we need to rewrite argv
     */
    if (ISSET(mode, MODE_RUN) && ISSET(flags, MODE_SHELL)) {
	char **av, *cmnd = NULL;
	int ac = 1;

	if (argc != 0) {
	    /* shell -c "command" */
	    char *src, *dst;
	    size_t cmnd_size = (size_t) (argv[argc - 1] - argv[0]) +
		strlen(argv[argc - 1]) + 1;

	    cmnd = dst = reallocarray(NULL, cmnd_size, 2);
	    if (cmnd == NULL)
		sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    if (!gc_add(GC_PTR, cmnd))
		exit(1);

	    for (av = argv; *av != NULL; av++) {
		for (src = *av; *src != '\0'; src++) {
		    /* quote potential meta characters */
		    if (!isalnum((unsigned char)*src) && *src != '_' && *src != '-' && *src != '$')
			*dst++ = '\\';
		    *dst++ = *src;
		}
		*dst++ = ' ';
	    }
	    if (cmnd != dst)
		dst--;  /* replace last space with a NUL */
	    *dst = '\0';

	    ac += 2; /* -c cmnd */
	}

	av = reallocarray(NULL, ac + 1, sizeof(char *));
	if (av == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	if (!gc_add(GC_PTR, av))
	    exit(1);

	av[0] = (char *)user_details.shell; /* plugin may override shell */
	if (cmnd != NULL) {
	    av[1] = "-c";
	    av[2] = cmnd;
	}
	av[ac] = NULL;

	argv = av;
	argc = ac;
    }

    if (mode == MODE_EDIT) {
#if defined(HAVE_SETRESUID) || defined(HAVE_SETREUID) || defined(HAVE_SETEUID)
	/* Must have the command in argv[0]. */
	argc++;
	argv--;
	argv[0] = "sudoedit";
#else
	sudo_fatalx(U_("sudoedit is not supported on this platform"));
#endif
    }

    *settingsp = sudo_settings;
    *env_addp = extra_env.envp;
    *nargc = argc;
    *nargv = argv;
    debug_return_int(mode | flags);
}

static int
usage_err(const char *buf)
{
    return fputs(buf, stderr);
}

static int
usage_out(const char *buf)
{
    return fputs(buf, stdout);
}

/*
 * Give usage message and exit.
 * The actual usage strings are in sudo_usage.h for configure substitution.
 */
void
usage(int fatal)
{
    struct sudo_lbuf lbuf;
    char *uvec[6];
    int i, ulen;

    /*
     * Use usage vectors appropriate to the progname.
     */
    if (strcmp(getprogname(), "sudoedit") == 0) {
	uvec[0] = &SUDO_USAGE5[3];
	uvec[1] = NULL;
    } else {
	uvec[0] = SUDO_USAGE1;
	uvec[1] = SUDO_USAGE2;
	uvec[2] = SUDO_USAGE3;
	uvec[3] = SUDO_USAGE4;
	uvec[4] = SUDO_USAGE5;
	uvec[5] = NULL;
    }

    /*
     * Print usage and wrap lines as needed, depending on the
     * tty width.
     */
    ulen = (int)strlen(getprogname()) + 8;
    sudo_lbuf_init(&lbuf, fatal ? usage_err : usage_out, ulen, NULL,
	user_details.ts_cols);
    for (i = 0; uvec[i] != NULL; i++) {
	sudo_lbuf_append(&lbuf, "usage: %s%s", getprogname(), uvec[i]);
	sudo_lbuf_print(&lbuf);
    }
    sudo_lbuf_destroy(&lbuf);
    if (fatal)
	exit(1);
}

/*
 * Tell which options are mutually exclusive and exit.
 */
static void
usage_excl(int fatal)
{
    debug_decl(usage_excl, SUDO_DEBUG_ARGS)

    sudo_warnx(U_("Only one of the -e, -h, -i, -K, -l, -s, -v or -V options may be specified"));
    usage(fatal);
}

static void
help(void)
{
    struct sudo_lbuf lbuf;
    const int indent = 32;
    const char *pname = getprogname();
    debug_decl(help, SUDO_DEBUG_ARGS)

    sudo_lbuf_init(&lbuf, usage_out, indent, NULL, user_details.ts_cols);
    if (strcmp(pname, "sudoedit") == 0)
	sudo_lbuf_append(&lbuf, _("%s - edit files as another user\n\n"), pname);
    else
	sudo_lbuf_append(&lbuf, _("%s - execute a command as another user\n\n"), pname);
    sudo_lbuf_print(&lbuf);

    usage(0);

    sudo_lbuf_append(&lbuf, _("\nOptions:\n"));
    sudo_lbuf_append(&lbuf, "  -A, --askpass                 %s\n",
	_("use a helper program for password prompting"));
#ifdef HAVE_BSD_AUTH_H
    sudo_lbuf_append(&lbuf, "  -a, --auth-type=type          %s\n",
	_("use specified BSD authentication type"));
#endif
    sudo_lbuf_append(&lbuf, "  -b, --background              %s\n",
	_("run command in the background"));
    sudo_lbuf_append(&lbuf, "  -B, --bell                    %s\n",
	_("ring bell when prompting"));
    sudo_lbuf_append(&lbuf, "  -C, --close-from=num          %s\n",
	_("close all file descriptors >= num"));
#ifdef HAVE_LOGIN_CAP_H
    sudo_lbuf_append(&lbuf, "  -c, --login-class=class       %s\n",
	_("run command with the specified BSD login class"));
#endif
    sudo_lbuf_append(&lbuf, "  -E, --preserve-env            %s\n",
	_("preserve user environment when running command"));
    sudo_lbuf_append(&lbuf, "      --preserve-env=list       %s\n",
	_("preserve specific environment variables"));
    sudo_lbuf_append(&lbuf, "  -e, --edit                    %s\n",
	_("edit files instead of running a command"));
    sudo_lbuf_append(&lbuf, "  -g, --group=group             %s\n",
	_("run command as the specified group name or ID"));
    sudo_lbuf_append(&lbuf, "  -H, --set-home                %s\n",
	_("set HOME variable to target user's home dir"));
    sudo_lbuf_append(&lbuf, "  -h, --help                    %s\n",
	_("display help message and exit"));
    sudo_lbuf_append(&lbuf, "  -h, --host=host               %s\n",
	_("run command on host (if supported by plugin)"));
    sudo_lbuf_append(&lbuf, "  -i, --login                   %s\n",
	_("run login shell as the target user; a command may also be specified"));
    sudo_lbuf_append(&lbuf, "  -K, --remove-timestamp        %s\n",
	_("remove timestamp file completely"));
    sudo_lbuf_append(&lbuf, "  -k, --reset-timestamp         %s\n",
	_("invalidate timestamp file"));
    sudo_lbuf_append(&lbuf, "  -l, --list                    %s\n",
	_("list user's privileges or check a specific command; use twice for longer format"));
    sudo_lbuf_append(&lbuf, "  -n, --non-interactive         %s\n",
	_("non-interactive mode, no prompts are used"));
    sudo_lbuf_append(&lbuf, "  -P, --preserve-groups         %s\n",
	_("preserve group vector instead of setting to target's"));
    sudo_lbuf_append(&lbuf, "  -p, --prompt=prompt           %s\n",
	_("use the specified password prompt"));
#ifdef HAVE_SELINUX
    sudo_lbuf_append(&lbuf, "  -r, --role=role               %s\n",
	_("create SELinux security context with specified role"));
#endif
    sudo_lbuf_append(&lbuf, "  -S, --stdin                   %s\n",
	_("read password from standard input"));
    sudo_lbuf_append(&lbuf, "  -s, --shell                   %s\n",
	_("run shell as the target user; a command may also be specified"));
#ifdef HAVE_SELINUX
    sudo_lbuf_append(&lbuf, "  -t, --type=type               %s\n",
	_("create SELinux security context with specified type"));
#endif
    sudo_lbuf_append(&lbuf, "  -T, --command-timeout=timeout %s\n",
	_("terminate command after the specified time limit"));
    sudo_lbuf_append(&lbuf, "  -U, --other-user=user         %s\n",
	_("in list mode, display privileges for user"));
    sudo_lbuf_append(&lbuf, "  -u, --user=user               %s\n",
	_("run command (or edit file) as specified user name or ID"));
    sudo_lbuf_append(&lbuf, "  -V, --version                 %s\n",
	_("display version information and exit"));
    sudo_lbuf_append(&lbuf, "  -v, --validate                %s\n",
	_("update user's timestamp without running a command"));
    sudo_lbuf_append(&lbuf, "  --                            %s\n",
	_("stop processing command line arguments"));
    sudo_lbuf_print(&lbuf);
    sudo_lbuf_destroy(&lbuf);
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, 0);
    exit(0);
}
