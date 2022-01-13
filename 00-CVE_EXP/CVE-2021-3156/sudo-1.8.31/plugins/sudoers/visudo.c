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

/*
 * Lock the sudoers file for safe editing (ala vipw) and check for parse errors.
 */

#ifdef __TANDEM
# include <floss.h>
#endif

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#ifndef __TANDEM
# include <sys/file.h>
#endif
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sudoers.h"
#include "interfaces.h"
#include "redblack.h"
#include "sudoers_version.h"
#include "sudo_conf.h"
#include <gram.h>

#ifdef HAVE_GETOPT_LONG
# include <getopt.h>
# else
# include "compat/getopt.h"
#endif /* HAVE_GETOPT_LONG */

struct sudoersfile {
    TAILQ_ENTRY(sudoersfile) entries;
    char *path;
    char *tpath;
    bool modified;
    bool doedit;
    int fd;
};
TAILQ_HEAD(sudoersfile_list, sudoersfile);

/*
 * Function prototypes
 */
static void quit(int);
static int whatnow(void);
static int check_aliases(bool strict, bool quiet);
static char *get_editor(int *editor_argc, char ***editor_argv);
static bool check_syntax(const char *, bool, bool, bool);
static bool edit_sudoers(struct sudoersfile *, char *, int, char **, int);
static bool install_sudoers(struct sudoersfile *, bool);
static int print_unused(struct sudoers_parse_tree *, struct alias *, void *);
static bool reparse_sudoers(char *, int, char **, bool, bool);
static int run_command(char *, char **);
static void parse_sudoers_options(void);
static void setup_signals(void);
static void help(void) __attribute__((__noreturn__));
static void usage(int);
static void visudo_cleanup(void);

extern void get_hostname(void);
extern void sudoersrestart(FILE *);

/*
 * Globals
 */
struct sudo_user sudo_user;
struct passwd *list_pw;
static struct sudoersfile_list sudoerslist = TAILQ_HEAD_INITIALIZER(sudoerslist);
static bool checkonly;
static const char short_opts[] =  "cf:hqsVx:";
static struct option long_opts[] = {
    { "check",		no_argument,		NULL,	'c' },
    { "export",		required_argument,	NULL,	'x' },
    { "file",		required_argument,	NULL,	'f' },
    { "help",		no_argument,		NULL,	'h' },
    { "quiet",		no_argument,		NULL,	'q' },
    { "strict",		no_argument,		NULL,	's' },
    { "version",	no_argument,		NULL,	'V' },
    { NULL,		no_argument,		NULL,	'\0' },
};

__dso_public int main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    struct sudoersfile *sp;
    char *editor, **editor_argv;
    const char *export_path = NULL;
    int ch, oldlocale, editor_argc, exitcode = 0;
    bool quiet, strict, fflag;
    debug_decl(main, SUDOERS_DEBUG_MAIN)

#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
    {
	extern char *malloc_options;
	malloc_options = "S";
    }
#endif

    initprogname(argc > 0 ? argv[0] : "visudo");
    if (!sudoers_initlocale(setlocale(LC_ALL, ""), def_sudoers_locale))
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    sudo_warn_set_locale_func(sudoers_warn_setlocale);
    bindtextdomain("sudoers", LOCALEDIR); /* XXX - should have visudo domain */
    textdomain("sudoers");

    if (argc < 1)
	usage(1);

    /* Register fatal/fatalx callback. */
    sudo_fatal_callback_register(visudo_cleanup);

    /* Set sudoers locale callback. */
    sudo_defs_table[I_SUDOERS_LOCALE].callback = sudoers_locale_callback;

    /* Read debug and plugin sections of sudo.conf. */
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG|SUDO_CONF_PLUGINS) == -1)
	exit(EXIT_FAILURE);

    /* Initialize the debug subsystem. */
    if (!sudoers_debug_register(getprogname(), sudo_conf_debug_files(getprogname())))
	exit(EXIT_FAILURE);

    /* Parse sudoers plugin options, if any. */
    parse_sudoers_options();

    /*
     * Arg handling.
     */
    checkonly = fflag = quiet = strict = false;
    while ((ch = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
	switch (ch) {
	    case 'V':
		(void) printf(_("%s version %s\n"), getprogname(),
		    PACKAGE_VERSION);
		(void) printf(_("%s grammar version %d\n"), getprogname(),
		    SUDOERS_GRAMMAR_VERSION);
		goto done;
	    case 'c':
		checkonly = true;	/* check mode */
		break;
	    case 'f':
		sudoers_file = optarg;	/* sudoers file path */
		fflag = true;
		break;
	    case 'h':
		help();
		break;
	    case 's':
		strict = true;		/* strict mode */
		break;
	    case 'q':
		quiet = true;		/* quiet mode */
		break;
	    case 'x':
		export_path = optarg;
		break;
	    default:
		usage(1);
	}
    }
    argc -= optind;
    argv += optind;

    /* Check for optional sudoers file argument. */
    switch (argc) {
    case 0:
	break;
    case 1:
	/* Only accept sudoers file if no -f was specified. */
	if (!fflag) {
	    sudoers_file = *argv;
	    fflag = true;
	}
	break;
    default:
	usage(1);
    }

    if (export_path != NULL) {
	/* Backwards compatibility for the time being. */
	sudo_warnx(U_("the -x option will be removed in a future release"));
	sudo_warnx(U_("please consider using the cvtsudoers utility instead"));
	execlp("cvtsudoers", "cvtsudoers", "-f", "json", "-o", export_path,
	    sudoers_file, (char *)0);
	sudo_fatal(U_("unable to execute %s"), "cvtsudoers");
    }

    /* Mock up a fake sudo_user struct. */
    user_cmnd = user_base = "";
    if (geteuid() == 0) {
	const char *user = getenv("SUDO_USER");
	if (user != NULL && *user != '\0')
	    sudo_user.pw = sudo_getpwnam(user);
    }
    if (sudo_user.pw == NULL) {
	if ((sudo_user.pw = sudo_getpwuid(getuid())) == NULL)
	    sudo_fatalx(U_("you do not exist in the %s database"), "passwd");
    }
    get_hostname();

    /* Setup defaults data structures. */
    if (!init_defaults())
	sudo_fatalx(U_("unable to initialize sudoers default values"));

    if (checkonly) {
	exitcode = check_syntax(sudoers_file, quiet, strict, fflag) ? 0 : 1;
	goto done;
    }

    /*
     * Parse the existing sudoers file(s) to highlight any existing
     * errors and to pull in editor and env_editor conf values.
     */
    if ((sudoersin = open_sudoers(sudoers_file, true, NULL)) == NULL)
	exit(1);
    init_parser(sudoers_file, quiet, true);
    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);
    (void) sudoersparse();
    (void) update_defaults(&parsed_policy, NULL,
	SETDEF_GENERIC|SETDEF_HOST|SETDEF_USER, quiet);
    sudoers_setlocale(oldlocale, NULL);

    editor = get_editor(&editor_argc, &editor_argv);

    /* Install signal handlers to clean up temp files if we are killed. */
    setup_signals();

    /* Edit the sudoers file(s) */
    TAILQ_FOREACH(sp, &sudoerslist, entries) {
	if (!sp->doedit)
	    continue;
	if (sp != TAILQ_FIRST(&sudoerslist)) {
	    printf(_("press return to edit %s: "), sp->path);
	    while ((ch = getchar()) != EOF && ch != '\n')
		    continue;
	}
	edit_sudoers(sp, editor, editor_argc, editor_argv, -1);
    }

    /*
     * Check edited files for a parse error, re-edit any that fail
     * and install the edited files as needed.
     */
    if (reparse_sudoers(editor, editor_argc, editor_argv, strict, quiet)) {
	TAILQ_FOREACH(sp, &sudoerslist, entries) {
	    (void) install_sudoers(sp, fflag);
	}
    }
    free(editor);

done:
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, exitcode);
    exit(exitcode);
}

static char *
get_editor(int *editor_argc, char ***editor_argv)
{
    char *editor_path = NULL, **whitelist = NULL;
    const char *env_editor;
    static char *files[] = { "+1", "sudoers" };
    unsigned int whitelist_len = 0;
    debug_decl(get_editor, SUDOERS_DEBUG_UTIL)

    /* Build up editor whitelist from def_editor unless env_editor is set. */
    if (!def_env_editor) {
	const char *cp, *ep;
	const char *def_editor_end = def_editor + strlen(def_editor);

	/* Count number of entries in whitelist and split into a list. */
	for (cp = sudo_strsplit(def_editor, def_editor_end, ":", &ep);
	    cp != NULL; cp = sudo_strsplit(NULL, def_editor_end, ":", &ep)) {
	    whitelist_len++;
	}
	whitelist = reallocarray(NULL, whitelist_len + 1, sizeof(char *));
	if (whitelist == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	whitelist_len = 0;
	for (cp = sudo_strsplit(def_editor, def_editor_end, ":", &ep);
	    cp != NULL; cp = sudo_strsplit(NULL, def_editor_end, ":", &ep)) {
	    whitelist[whitelist_len] = strndup(cp, (size_t)(ep - cp));
	    if (whitelist[whitelist_len] == NULL)
		sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    whitelist_len++;
	}
	whitelist[whitelist_len] = NULL;
    }

    editor_path = find_editor(2, files, editor_argc, editor_argv, whitelist,
	&env_editor, true);
    if (editor_path == NULL) {
	if (def_env_editor && env_editor != NULL) {
	    /* We are honoring $EDITOR so this is a fatal error. */
	    sudo_fatalx(U_("specified editor (%s) doesn't exist"), env_editor);
	}
	sudo_fatalx(U_("no editor found (editor path = %s)"), def_editor);
    }

    if (whitelist != NULL) {
	while (whitelist_len--)
	    free(whitelist[whitelist_len]);
	free(whitelist);
    }

    debug_return_str(editor_path);
}

/*
 * List of editors that support the "+lineno" command line syntax.
 * If an entry starts with '*' the tail end of the string is matched.
 * No other wild cards are supported.
 */
static char *lineno_editors[] = {
    "ex",
    "nex",
    "vi",
    "nvi",
    "vim",
    "elvis",
    "*macs",
    "mg",
    "vile",
    "jove",
    "pico",
    "nano",
    "ee",
    "joe",
    "zile",
    NULL
};

/*
 * Check whether or not the specified editor matched lineno_editors[].
 * Returns true if yes, false if no.
 */
static bool
editor_supports_plus(const char *editor)
{
    const char *editor_base = strrchr(editor, '/');
    const char *cp;
    char **av;
    debug_decl(editor_supports_plus, SUDOERS_DEBUG_UTIL)

    if (editor_base != NULL)
	editor_base++;
    else
	editor_base = editor;
    if (*editor_base == 'r')
	editor_base++;

    for (av = lineno_editors; (cp = *av) != NULL; av++) {
	/* We only handle a leading '*' wildcard. */
	if (*cp == '*') {
	    size_t blen = strlen(editor_base);
	    size_t clen = strlen(++cp);
	    if (blen >= clen) {
		if (strcmp(cp, editor_base + blen - clen) == 0)
		    break;
	    }
	} else if (strcmp(cp, editor_base) == 0)
	    break;
    }
    debug_return_bool(cp != NULL);
}

/*
 * Edit each sudoers file.
 * Returns true on success, else false.
 */
static bool
edit_sudoers(struct sudoersfile *sp, char *editor, int editor_argc,
    char **editor_argv, int lineno)
{
    int tfd;				/* sudoers temp file descriptor */
    bool modified;			/* was the file modified? */
    int ac;				/* argument count */
    char linestr[64];			/* string version of lineno */
    struct timespec ts, times[2];	/* time before and after edit */
    struct timespec orig_mtim;		/* starting mtime of sudoers file */
    off_t orig_size;			/* starting size of sudoers file */
    struct stat sb;			/* stat buffer */
    bool ret = false;			/* return value */
    debug_decl(edit_sudoers, SUDOERS_DEBUG_UTIL)

    if (fstat(sp->fd, &sb) == -1)
	sudo_fatal(U_("unable to stat %s"), sp->path);
    orig_size = sb.st_size;
    mtim_get(&sb, orig_mtim);

    /* Create the temp file if needed and set timestamp. */
    if (sp->tpath == NULL) {
	if (asprintf(&sp->tpath, "%s.tmp", sp->path) == -1)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	tfd = open(sp->tpath, O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU|S_IRUSR);
	if (tfd < 0)
	    sudo_fatal("%s", sp->tpath);

	/* Copy sp->path -> sp->tpath and reset the mtime. */
	if (orig_size != 0) {
	    char buf[4096], lastch = '\0';
	    ssize_t nread;

	    (void) lseek(sp->fd, (off_t)0, SEEK_SET);
	    while ((nread = read(sp->fd, buf, sizeof(buf))) > 0) {
		if (write(tfd, buf, nread) != nread)
		    sudo_fatal(U_("write error"));
		lastch = buf[nread - 1];
	    }

	    /* Add missing newline at EOF if needed. */
	    if (lastch != '\n') {
		lastch = '\n';
		if (write(tfd, &lastch, 1) != 1)
		    sudo_fatal(U_("write error"));
	    }
	}
	(void) close(tfd);
    }
    times[0].tv_sec = times[1].tv_sec = orig_mtim.tv_sec;
    times[0].tv_nsec = times[1].tv_nsec = orig_mtim.tv_nsec;
    (void) utimensat(AT_FDCWD, sp->tpath, times, 0);

    /* Disable +lineno if editor doesn't support it. */
    if (lineno > 0 && !editor_supports_plus(editor))
	lineno = -1;

    /*
     * The last 3 slots in the editor argv are: "-- +1 sudoers"
     * Replace those placeholders with the real values.
     */
    ac = editor_argc - 3;
    if (lineno > 0) {
	(void)snprintf(linestr, sizeof(linestr), "+%d", lineno);
	editor_argv[ac++] = linestr;
    }
    editor_argv[ac++] = "--";
    editor_argv[ac++] = sp->tpath;
    editor_argv[ac++] = NULL;

    /*
     * Do the edit:
     *  We cannot check the editor's exit value against 0 since
     *  XPG4 specifies that vi's exit value is a function of the
     *  number of errors during editing (?!?!).
     */
    if (sudo_gettime_real(&times[0]) == -1) {
	sudo_warn(U_("unable to read the clock"));
	goto done;
    }

    if (run_command(editor, editor_argv) != -1) {
	if (sudo_gettime_real(&times[1]) == -1) {
	    sudo_warn(U_("unable to read the clock"));
	    goto done;
	}
	/*
	 * Sanity checks.
	 */
	if (stat(sp->tpath, &sb) < 0) {
	    sudo_warnx(U_("unable to stat temporary file (%s), %s unchanged"),
		sp->tpath, sp->path);
	    goto done;
	}
	if (sb.st_size == 0 && orig_size != 0) {
	    /* Avoid accidental zeroing of main sudoers file. */
	    if (sp == TAILQ_FIRST(&sudoerslist)) {
		sudo_warnx(U_("zero length temporary file (%s), %s unchanged"),
		    sp->tpath, sp->path);
		goto done;
	    }
	}
    } else {
	sudo_warnx(U_("editor (%s) failed, %s unchanged"), editor, sp->path);
	goto done;
    }

    /* Set modified bit if the user changed the file. */
    modified = true;
    mtim_get(&sb, ts);
    if (orig_size == sb.st_size && sudo_timespeccmp(&orig_mtim, &ts, ==)) {
	/*
	 * If mtime and size match but the user spent no measurable
	 * time in the editor we can't tell if the file was changed.
	 */
	if (sudo_timespeccmp(&times[0], &times[1], !=))
	    modified = false;
    }

    /*
     * If modified in this edit session, mark as modified.
     */
    if (modified)
	sp->modified = modified;
    else
	sudo_warnx(U_("%s unchanged"), sp->tpath);

    ret = true;
done:
    debug_return_bool(ret);
}

/*
 * Check Defaults and Alias entries.
 * Sets parse_error on error and errorfile/errorlineno if possible.
 */
static void
check_defaults_and_aliases(bool strict, bool quiet)
{
    debug_decl(check_defaults_and_aliases, SUDOERS_DEBUG_UTIL)

    if (!check_defaults(&parsed_policy, quiet)) {
	struct defaults *d;
	rcstr_delref(errorfile);
	errorfile = NULL;
	errorlineno = -1;
	/* XXX - should edit all files with errors */
	TAILQ_FOREACH(d, &parsed_policy.defaults, entries) {
	    if (d->error) {
		/* Defaults parse error, set errorfile/errorlineno. */
		errorfile = rcstr_addref(d->file);
		errorlineno = d->lineno;
		break;
	    }
	}
	parse_error = true;
    } else if (check_aliases(strict, quiet) != 0) {
	rcstr_delref(errorfile);
	errorfile = NULL;	/* don't know which file */
	errorlineno = -1;
	parse_error = true;
    }
    debug_return;
}

/*
 * Parse sudoers after editing and re-edit any ones that caused a parse error.
 */
static bool
reparse_sudoers(char *editor, int editor_argc, char **editor_argv,
    bool strict, bool quiet)
{
    struct sudoersfile *sp, *last;
    FILE *fp;
    int ch, oldlocale;
    debug_decl(reparse_sudoers, SUDOERS_DEBUG_UTIL)

    /*
     * Parse the edited sudoers files and do sanity checking
     */
    while ((sp = TAILQ_FIRST(&sudoerslist)) != NULL) {
	last = TAILQ_LAST(&sudoerslist, sudoersfile_list);
	fp = fopen(sp->tpath, "r+");
	if (fp == NULL)
	    sudo_fatalx(U_("unable to re-open temporary file (%s), %s unchanged."),
		sp->tpath, sp->path);

	/* Clean slate for each parse */
	if (!init_defaults())
	    sudo_fatalx(U_("unable to initialize sudoers default values"));
	init_parser(sp->path, quiet, true);

	/* Parse the sudoers temp file(s) */
	sudoersrestart(fp);
	sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);
	if (sudoersparse() && !parse_error) {
	    sudo_warnx(U_("unabled to parse temporary file (%s), unknown error"),
		sp->tpath);
	    parse_error = true;
	    rcstr_delref(errorfile);
	    if ((errorfile = rcstr_dup(sp->path)) == NULL)
		sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	}
	fclose(sudoersin);
	if (!parse_error) {
	    (void) update_defaults(&parsed_policy, NULL,
		SETDEF_GENERIC|SETDEF_HOST|SETDEF_USER, true);
	    check_defaults_and_aliases(strict, quiet);
	}
	sudoers_setlocale(oldlocale, NULL);

	/*
	 * Got an error, prompt the user for what to do now.
	 */
	if (parse_error) {
	    switch (whatnow()) {
	    case 'Q':
		parse_error = false;	/* ignore parse error */
		break;
	    case 'x':
		visudo_cleanup();	/* discard changes */
		debug_return_bool(false);
	    case 'e':
	    default:
		/* Edit file with the parse error */
		TAILQ_FOREACH(sp, &sudoerslist, entries) {
		    if (errorfile == NULL || strcmp(sp->path, errorfile) == 0) {
			edit_sudoers(sp, editor, editor_argc, editor_argv,
			    errorlineno);
			if (errorfile != NULL)
			    break;
		    }
		}
		if (errorfile != NULL && sp == NULL) {
		    sudo_fatalx(U_("internal error, unable to find %s in list!"),
			sudoers);
		}
		break;
	    }
	}

	/* If any new #include directives were added, edit them too. */
	if ((sp = TAILQ_NEXT(last, entries)) != NULL) {
	    bool modified = false;
	    do {
		printf(_("press return to edit %s: "), sp->path);
		while ((ch = getchar()) != EOF && ch != '\n')
			continue;
		edit_sudoers(sp, editor, editor_argc, editor_argv, -1);
		if (sp->modified)
		    modified = true;
	    } while ((sp = TAILQ_NEXT(sp, entries)) != NULL);

	    /* Reparse sudoers if newly added includes were modified. */
	    if (modified)
		continue;
	}

	/* If all sudoers files parsed OK we are done. */
	if (!parse_error)
	    break;
    }

    debug_return_bool(true);
}

/*
 * Set the owner and mode on a sudoers temp file and
 * move it into place.  Returns true on success, else false.
 */
static bool
install_sudoers(struct sudoersfile *sp, bool oldperms)
{
    struct stat sb;
    bool ret = false;
    debug_decl(install_sudoers, SUDOERS_DEBUG_UTIL)

    if (sp->tpath == NULL)
	goto done;

    if (!sp->modified) {
	/*
	 * No changes but fix owner/mode if needed.
	 */
	(void) unlink(sp->tpath);
	if (!oldperms && fstat(sp->fd, &sb) != -1) {
	    if (sb.st_uid != sudoers_uid || sb.st_gid != sudoers_gid) {
		if (chown(sp->path, sudoers_uid, sudoers_gid) != 0) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
			"%s: unable to chown %d:%d %s", __func__,
			(int)sudoers_uid, (int)sudoers_gid, sp->path);
		}
	    }
	    if ((sb.st_mode & ACCESSPERMS) != sudoers_mode) {
		if (chmod(sp->path, sudoers_mode) != 0) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
			"%s: unable to chmod 0%o %s", __func__,
			(int)sudoers_mode, sp->path);
		}
	    }
	}
	ret = true;
	goto done;
    }

    /*
     * Change mode and ownership of temp file so when
     * we move it to sp->path things are kosher.
     */
    if (oldperms) {
	/* Use perms of the existing file.  */
	if (fstat(sp->fd, &sb) == -1)
	    sudo_fatal(U_("unable to stat %s"), sp->path);
	if (chown(sp->tpath, sb.st_uid, sb.st_gid) != 0) {
	    sudo_warn(U_("unable to set (uid, gid) of %s to (%u, %u)"),
		sp->tpath, (unsigned int)sb.st_uid, (unsigned int)sb.st_gid);
	}
	if (chmod(sp->tpath, sb.st_mode & ACCESSPERMS) != 0) {
	    sudo_warn(U_("unable to change mode of %s to 0%o"), sp->tpath,
		(unsigned int)(sb.st_mode & ACCESSPERMS));
	}
    } else {
	if (chown(sp->tpath, sudoers_uid, sudoers_gid) != 0) {
	    sudo_warn(U_("unable to set (uid, gid) of %s to (%u, %u)"),
		sp->tpath, (unsigned int)sudoers_uid,
		(unsigned int)sudoers_gid);
	    goto done;
	}
	if (chmod(sp->tpath, sudoers_mode) != 0) {
	    sudo_warn(U_("unable to change mode of %s to 0%o"), sp->tpath,
		(unsigned int)sudoers_mode);
	    goto done;
	}
    }

    /*
     * Now that sp->tpath is sane (parses ok) it needs to be
     * rename(2)'d to sp->path.  If the rename(2) fails we try using
     * mv(1) in case sp->tpath and sp->path are on different file systems.
     */
    if (rename(sp->tpath, sp->path) == 0) {
	free(sp->tpath);
	sp->tpath = NULL;
    } else {
	if (errno == EXDEV) {
	    char *av[4];
	    sudo_warnx(U_("%s and %s not on the same file system, using mv to rename"),
	      sp->tpath, sp->path);

	    /* Build up argument vector for the command */
	    if ((av[0] = strrchr(_PATH_MV, '/')) != NULL)
		av[0]++;
	    else
		av[0] = _PATH_MV;
	    av[1] = sp->tpath;
	    av[2] = sp->path;
	    av[3] = NULL;

	    /* And run it... */
	    if (run_command(_PATH_MV, av)) {
		sudo_warnx(U_("command failed: '%s %s %s', %s unchanged"),
		    _PATH_MV, sp->tpath, sp->path, sp->path);
		(void) unlink(sp->tpath);
		free(sp->tpath);
		sp->tpath = NULL;
		goto done;
	    }
	    free(sp->tpath);
	    sp->tpath = NULL;
	} else {
	    sudo_warn(U_("error renaming %s, %s unchanged"), sp->tpath, sp->path);
	    (void) unlink(sp->tpath);
	    goto done;
	}
    }
    ret = true;
done:
    debug_return_bool(ret);
}

/*
 * Assuming a parse error occurred, prompt the user for what they want
 * to do now.  Returns the first letter of their choice.
 */
static int
whatnow(void)
{
    int choice, c;
    debug_decl(whatnow, SUDOERS_DEBUG_UTIL)

    for (;;) {
	(void) fputs(_("What now? "), stdout);
	choice = getchar();
	for (c = choice; c != '\n' && c != EOF;)
	    c = getchar();

	switch (choice) {
	    case EOF:
		choice = 'x';
		/* FALLTHROUGH */
	    case 'e':
	    case 'x':
	    case 'Q':
		debug_return_int(choice);
	    default:
		(void) puts(_("Options are:\n"
		    "  (e)dit sudoers file again\n"
		    "  e(x)it without saving changes to sudoers file\n"
		    "  (Q)uit and save changes to sudoers file (DANGER!)\n"));
	}
    }
}

/*
 * Install signal handlers for visudo.
 */
static void
setup_signals(void)
{
    struct sigaction sa;
    debug_decl(setup_signals, SUDOERS_DEBUG_UTIL)

    /*
     * Setup signal handlers to cleanup nicely.
     */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = quit;
    (void) sigaction(SIGTERM, &sa, NULL);
    (void) sigaction(SIGHUP, &sa, NULL);
    (void) sigaction(SIGINT, &sa, NULL);
    (void) sigaction(SIGQUIT, &sa, NULL);

    debug_return;
}

static int
run_command(char *path, char **argv)
{
    int status;
    pid_t pid, rv;
    debug_decl(run_command, SUDOERS_DEBUG_UTIL)

    switch (pid = sudo_debug_fork()) {
	case -1:
	    sudo_fatal(U_("unable to execute %s"), path);
	    break;	/* NOTREACHED */
	case 0:
	    closefrom(STDERR_FILENO + 1);
	    execv(path, argv);
	    sudo_warn(U_("unable to run %s"), path);
	    _exit(127);
	    break;	/* NOTREACHED */
    }

    for (;;) {
	rv = waitpid(pid, &status, 0);
	if (rv == -1 && errno != EINTR)
	    break;
	if (rv != -1 && !WIFSTOPPED(status))
	    break;
    }

    if (rv != -1)
	rv = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    debug_return_int(rv);
}

static bool
check_owner(const char *path, bool quiet)
{
    struct stat sb;
    bool ok = true;
    debug_decl(check_owner, SUDOERS_DEBUG_UTIL)

    if (stat(path, &sb) == 0) {
	if (sb.st_uid != sudoers_uid || sb.st_gid != sudoers_gid) {
	    ok = false;
	    if (!quiet) {
		fprintf(stderr,
		    _("%s: wrong owner (uid, gid) should be (%u, %u)\n"),
		    path, (unsigned int)sudoers_uid, (unsigned int)sudoers_gid);
		}
	}
	if ((sb.st_mode & ALLPERMS) != sudoers_mode) {
	    ok = false;
	    if (!quiet) {
		fprintf(stderr, _("%s: bad permissions, should be mode 0%o\n"),
		    path, (unsigned int)sudoers_mode);
	    }
	}
    }
    debug_return_bool(ok);
}

static bool
check_syntax(const char *sudoers_file, bool quiet, bool strict, bool oldperms)
{
    bool ok = false;
    int oldlocale;
    debug_decl(check_syntax, SUDOERS_DEBUG_UTIL)

    if (strcmp(sudoers_file, "-") == 0) {
	sudoersin = stdin;
	sudoers_file = "stdin";
    } else if ((sudoersin = fopen(sudoers_file, "r")) == NULL) {
	if (!quiet)
	    sudo_warn(U_("unable to open %s"), sudoers_file);
	goto done;
    }
    if (!init_defaults())
	sudo_fatalx(U_("unable to initialize sudoers default values"));
    init_parser(sudoers_file, quiet, true);
    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);
    if (sudoersparse() && !parse_error) {
	if (!quiet)
	    sudo_warnx(U_("failed to parse %s file, unknown error"), sudoers_file);
	parse_error = true;
	rcstr_delref(errorfile);
	if ((errorfile = rcstr_dup(sudoers_file)) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    }
    if (!parse_error) {
	(void) update_defaults(&parsed_policy, NULL,
	    SETDEF_GENERIC|SETDEF_HOST|SETDEF_USER, true);
	check_defaults_and_aliases(strict, quiet);
    }
    sudoers_setlocale(oldlocale, NULL);
    ok = !parse_error;

    if (parse_error) {
	if (!quiet) {
	    if (errorlineno != -1)
		(void) printf(_("parse error in %s near line %d\n"),
		    errorfile, errorlineno);
	    else if (errorfile != NULL)
		(void) printf(_("parse error in %s\n"), errorfile);
	}
    } else {
	struct sudoersfile *sp;

	/* Parsed OK, check mode and owner. */
	if (oldperms || check_owner(sudoers_file, quiet)) {
	    if (!quiet)
		(void) printf(_("%s: parsed OK\n"), sudoers_file);
	} else {
	    ok = false;
	}
	TAILQ_FOREACH(sp, &sudoerslist, entries) {
	    if (oldperms || check_owner(sp->path, quiet)) {
		if (!quiet)
		    (void) printf(_("%s: parsed OK\n"), sp->path);
	    } else {
		ok = false;
	    }
	}
    }

done:
    debug_return_bool(ok);
}

static bool
lock_sudoers(struct sudoersfile *entry)
{
    int ch;
    debug_decl(lock_sudoers, SUDOERS_DEBUG_UTIL)

    if (!sudo_lock_file(entry->fd, SUDO_TLOCK)) {
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    sudo_warnx(U_("%s busy, try again later"), entry->path);
	    debug_return_bool(false);
	}
	sudo_warn(U_("unable to lock %s"), entry->path);
	(void) fputs(_("Edit anyway? [y/N]"), stdout);
	ch = getchar();
	if (tolower(ch) != 'y')
	    debug_return_bool(false);
    }
    debug_return_bool(true);
}

/*
 * Used to open (and lock) the initial sudoers file and to also open
 * any subsequent files #included via a callback from the parser.
 */
FILE *
open_sudoers(const char *path, bool doedit, bool *keepopen)
{
    struct sudoersfile *entry;
    FILE *fp;
    int open_flags;
    debug_decl(open_sudoers, SUDOERS_DEBUG_UTIL)

    if (checkonly)
	open_flags = O_RDONLY;
    else
	open_flags = O_RDWR | O_CREAT;

    /* Check for existing entry */
    TAILQ_FOREACH(entry, &sudoerslist, entries) {
	if (strcmp(path, entry->path) == 0)
	    break;
    }
    if (entry == NULL) {
	entry = calloc(1, sizeof(*entry));
	if (entry == NULL || (entry->path = strdup(path)) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	/* entry->tpath = NULL; */
	/* entry->modified = false; */
	entry->doedit = doedit;
	entry->fd = open(entry->path, open_flags, sudoers_mode);
	if (entry->fd == -1) {
	    sudo_warn("%s", entry->path);
	    free(entry);
	    debug_return_ptr(NULL);
	}
	if (!checkonly && !lock_sudoers(entry))
	    debug_return_ptr(NULL);
	if ((fp = fdopen(entry->fd, "r")) == NULL)
	    sudo_fatal("%s", entry->path);
	TAILQ_INSERT_TAIL(&sudoerslist, entry, entries);
    } else {
	/* Already exists, open .tmp version if there is one. */
	if (entry->tpath != NULL) {
	    if ((fp = fopen(entry->tpath, "r")) == NULL)
		sudo_fatal("%s", entry->tpath);
	} else {
	    if ((fp = fdopen(entry->fd, "r")) == NULL)
		sudo_fatal("%s", entry->path);
	    rewind(fp);
	}
    }
    if (keepopen != NULL)
	*keepopen = true;
    debug_return_ptr(fp);
}

static int
check_alias(char *name, int type, char *file, int lineno, bool strict, bool quiet)
{
    struct member *m;
    struct alias *a;
    int errors = 0;
    debug_decl(check_alias, SUDOERS_DEBUG_ALIAS)

    if ((a = alias_get(&parsed_policy, name, type)) != NULL) {
	/* check alias contents */
	TAILQ_FOREACH(m, &a->members, entries) {
	    if (m->type != ALIAS)
		continue;
	    errors += check_alias(m->name, type, a->file, a->lineno, strict, quiet);
	}
	alias_put(a);
    } else {
	if (!quiet) {
	    if (errno == ELOOP) {
		fprintf(stderr, strict ?
		    U_("Error: %s:%d cycle in %s \"%s\"") :
		    U_("Warning: %s:%d cycle in %s \"%s\""),
		    file, lineno, alias_type_to_string(type), name);
	    } else {
		fprintf(stderr, strict ?
		    U_("Error: %s:%d %s \"%s\" referenced but not defined") :
		    U_("Warning: %s:%d %s \"%s\" referenced but not defined"),
		    file, lineno, alias_type_to_string(type), name);
	    }
	    fputc('\n', stderr);
	    if (strict && errorfile == NULL) {
		errorfile = rcstr_addref(file);
		errorlineno = lineno;
	    }
	}
	errors++;
    }

    debug_return_int(errors);
}

/*
 * Iterate through the sudoers datastructures looking for undefined
 * aliases or unused aliases.
 */
static int
check_aliases(bool strict, bool quiet)
{
    struct rbtree *used_aliases;
    struct cmndspec *cs;
    struct member *m;
    struct privilege *priv;
    struct userspec *us;
    int errors = 0;
    debug_decl(check_aliases, SUDOERS_DEBUG_ALIAS)

    used_aliases = alloc_aliases();
    if (used_aliases == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(-1);
    }

    /* Forward check. */
    TAILQ_FOREACH(us, &parsed_policy.userspecs, entries) {
	TAILQ_FOREACH(m, &us->users, entries) {
	    if (m->type == ALIAS) {
		errors += check_alias(m->name, USERALIAS,
		    us->file, us->lineno, strict, quiet);
	    }
	}
	TAILQ_FOREACH(priv, &us->privileges, entries) {
	    TAILQ_FOREACH(m, &priv->hostlist, entries) {
		if (m->type == ALIAS) {
		    errors += check_alias(m->name, HOSTALIAS,
			us->file, us->lineno, strict, quiet);
		}
	    }
	    TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
		if (cs->runasuserlist != NULL) {
		    TAILQ_FOREACH(m, cs->runasuserlist, entries) {
			if (m->type == ALIAS) {
			    errors += check_alias(m->name, RUNASALIAS,
				us->file, us->lineno, strict, quiet);
			}
		    }
		}
		if (cs->runasgrouplist != NULL) {
		    TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
			if (m->type == ALIAS) {
			    errors += check_alias(m->name, RUNASALIAS,
				us->file, us->lineno, strict, quiet);
			}
		    }
		}
		if ((m = cs->cmnd)->type == ALIAS) {
		    errors += check_alias(m->name, CMNDALIAS,
			us->file, us->lineno, strict, quiet);
		}
	    }
	}
    }

    /* Reverse check (destructive) */
    if (!alias_find_used(&parsed_policy, used_aliases))
	errors++;
    free_aliases(used_aliases);

    /* If all aliases were referenced we will have an empty tree. */
    if (!no_aliases(&parsed_policy) && !quiet)
	alias_apply(&parsed_policy, print_unused, NULL);

    debug_return_int(strict ? errors : 0);
}

static int
print_unused(struct sudoers_parse_tree *parse_tree, struct alias *a, void *v)
{
    fprintf(stderr, U_("Warning: %s:%d unused %s \"%s\""),
	a->file, a->lineno, alias_type_to_string(a->type), a->name);
    fputc('\n', stderr);
    return 0;
}

static void
parse_sudoers_options(void)
{
    struct plugin_info_list *plugins;
    debug_decl(parse_sudoers_options, SUDOERS_DEBUG_UTIL)

    plugins = sudo_conf_plugins();
    if (plugins) {
	struct plugin_info *info;

	TAILQ_FOREACH(info, plugins, entries) {
	    if (strcmp(info->symbol_name, "sudoers_policy") == 0)
		break;
	}
	if (info != NULL && info->options != NULL) {
	    char * const *cur;

#define MATCHES(s, v)	\
    (strncmp((s), (v), sizeof(v) - 1) == 0 && (s)[sizeof(v) - 1] != '\0')

	    for (cur = info->options; *cur != NULL; cur++) {
		const char *errstr, *p;
		id_t id;

		if (MATCHES(*cur, "sudoers_file=")) {
		    sudoers_file = *cur + sizeof("sudoers_file=") - 1;
		    continue;
		}
		if (MATCHES(*cur, "sudoers_uid=")) {
		    p = *cur + sizeof("sudoers_uid=") - 1;
		    id = sudo_strtoid(p, &errstr);
		    if (errstr == NULL)
			sudoers_uid = (uid_t) id;
		    continue;
		}
		if (MATCHES(*cur, "sudoers_gid=")) {
		    p = *cur + sizeof("sudoers_gid=") - 1;
		    id = sudo_strtoid(p, &errstr);
		    if (errstr == NULL)
			sudoers_gid = (gid_t) id;
		    continue;
		}
		if (MATCHES(*cur, "sudoers_mode=")) {
		    p = *cur + sizeof("sudoers_mode=") - 1;
		    id = (id_t) sudo_strtomode(p, &errstr);
		    if (errstr == NULL)
			sudoers_mode = (mode_t) id;
		    continue;
		}
	    }
#undef MATCHES
	}
    }
    debug_return;
}

/*
 * Unlink any sudoers temp files that remain.
 */
static void
visudo_cleanup(void)
{
    struct sudoersfile *sp;

    TAILQ_FOREACH(sp, &sudoerslist, entries) {
	if (sp->tpath != NULL)
	    (void) unlink(sp->tpath);
    }
}

/*
 * Unlink sudoers temp files (if any) and exit.
 */
static void
quit(int signo)
{
    struct sudoersfile *sp;
    struct iovec iov[4];

    TAILQ_FOREACH(sp, &sudoerslist, entries) {
	if (sp->tpath != NULL)
	    (void) unlink(sp->tpath);
    }

#define	emsg	 " exiting due to signal: "
    iov[0].iov_base = (char *)getprogname();
    iov[0].iov_len = strlen(iov[0].iov_base);
    iov[1].iov_base = emsg;
    iov[1].iov_len = sizeof(emsg) - 1;
    iov[2].iov_base = strsignal(signo);
    iov[2].iov_len = strlen(iov[2].iov_base);
    iov[3].iov_base = "\n";
    iov[3].iov_len = 1;
    ignore_result(writev(STDERR_FILENO, iov, 4));
    _exit(signo);
}

static void
usage(int fatal)
{
    (void) fprintf(fatal ? stderr : stdout,
	"usage: %s [-chqsV] [[-f] sudoers ]\n", getprogname());
    if (fatal)
	exit(1);
}

static void
help(void)
{
    (void) printf(_("%s - safely edit the sudoers file\n\n"), getprogname());
    usage(0);
    (void) puts(_("\nOptions:\n"
	"  -c, --check              check-only mode\n"
	"  -f, --file=sudoers       specify sudoers file location\n"
	"  -h, --help               display help message and exit\n"
	"  -q, --quiet              less verbose (quiet) syntax error messages\n"
	"  -s, --strict             strict syntax checking\n"
	"  -V, --version            display version information and exit\n"));
    exit(0);
}
