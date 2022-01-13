/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2019 Todd C. Miller <Todd.Miller@sudo.ws>
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

#ifdef __TANDEM
# include <floss.h>
#endif

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <grp.h>
#include <pwd.h>
#include <time.h>
#ifdef HAVE_SELINUX
# include <selinux/selinux.h>		/* for is_selinux_enabled() */
#endif
#ifdef HAVE_SETAUTHDB
# include <usersec.h>
#endif /* HAVE_SETAUTHDB */
#if defined(HAVE_GETPRPWNAM) && defined(HAVE_SET_AUTH_PARAMETERS)
# ifdef __hpux
#  undef MAXINT
#  include <hpsecurity.h>
# else
#  include <sys/security.h>
# endif /* __hpux */
# include <prot.h>
#endif /* HAVE_GETPRPWNAM && HAVE_SET_AUTH_PARAMETERS */

#include <sudo_usage.h>
#include "sudo.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

/*
 * Local variables
 */
struct plugin_container policy_plugin;
struct plugin_container_list io_plugins = TAILQ_HEAD_INITIALIZER(io_plugins);
struct user_details user_details;
const char *list_user; /* extern for parse_args.c */
int sudo_debug_instance = SUDO_DEBUG_INSTANCE_INITIALIZER;
static struct command_details command_details;
static int sudo_mode;

struct sudo_gc_entry {
    SLIST_ENTRY(sudo_gc_entry) entries;
    enum sudo_gc_types type;
    union {
	char **vec;
	void *ptr;
    } u;
};
SLIST_HEAD(sudo_gc_list, sudo_gc_entry);
#ifdef NO_LEAKS
static struct sudo_gc_list sudo_gc_list = SLIST_HEAD_INITIALIZER(sudo_gc_list);
#endif

/*
 * Local functions
 */
static void fix_fds(void);
static void sudo_check_suid(const char *path);
static char **get_user_info(struct user_details *);
static void command_info_to_details(char * const info[],
    struct command_details *details);
static void gc_init(void);

/* Policy plugin convenience functions. */
static int policy_open(struct plugin_container *plugin,
    struct sudo_settings *settings,
    char * const user_info[], char * const user_env[]);
static void policy_close(struct plugin_container *plugin, int exit_status,
    int error);
static int policy_show_version(struct plugin_container *plugin, int verbose);
static int policy_check(struct plugin_container *plugin, int argc,
    char * const argv[], char *env_add[], char **command_info[],
    char **argv_out[], char **user_env_out[]);
static int policy_list(struct plugin_container *plugin, int argc,
    char * const argv[], int verbose, const char *list_user);
static int policy_validate(struct plugin_container *plugin);
static void policy_invalidate(struct plugin_container *plugin, int remove);

/* I/O log plugin convenience functions. */
static int iolog_open(struct plugin_container *plugin,
    struct sudo_settings *settings, char * const user_info[],
    char * const command_details[], int argc, char * const argv[],
    char * const user_env[]);
static void iolog_close(struct plugin_container *plugin, int exit_status,
    int error);
static int iolog_show_version(struct plugin_container *plugin, int verbose);
static void iolog_unlink(struct plugin_container *plugin);
static void free_plugin_container(struct plugin_container *plugin, bool ioplugin);

__dso_public int main(int argc, char *argv[], char *envp[]);

int
main(int argc, char *argv[], char *envp[])
{
    int nargc, ok, status = 0;
    char **nargv, **env_add;
    char **user_info, **command_info, **argv_out, **user_env_out;
    struct sudo_settings *settings;
    struct plugin_container *plugin, *next;
    sigset_t mask;
    debug_decl_vars(main, SUDO_DEBUG_MAIN)

    initprogname(argc > 0 ? argv[0] : "sudo");

    /* Crank resource limits to unlimited. */
    unlimit_sudo();

    /* Make sure fds 0-2 are open and do OS-specific initialization. */
    fix_fds();
    os_init(argc, argv, envp);

    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE_NAME, LOCALEDIR);
    textdomain(PACKAGE_NAME);

    (void) tzset();

    /* Must be done before we do any password lookups */
#if defined(HAVE_GETPRPWNAM) && defined(HAVE_SET_AUTH_PARAMETERS)
    (void) set_auth_parameters(argc, argv);
# ifdef HAVE_INITPRIVS
    initprivs();
# endif
#endif /* HAVE_GETPRPWNAM && HAVE_SET_AUTH_PARAMETERS */

    /* Initialize the debug subsystem. */
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG) == -1)
	exit(EXIT_FAILURE);
    sudo_debug_instance = sudo_debug_register(getprogname(),
	NULL, NULL, sudo_conf_debug_files(getprogname()));
    if (sudo_debug_instance == SUDO_DEBUG_INSTANCE_ERROR)
	exit(EXIT_FAILURE);

    /* Make sure we are setuid root. */
    sudo_check_suid(argc > 0 ? argv[0] : "sudo");

    /* Save original signal state and setup default signal handlers. */
    save_signals();
    init_signals();

    /* Reset signal mask to the default value (unblock). */
    (void) sigemptyset(&mask);
    (void) sigprocmask(SIG_SETMASK, &mask, NULL);

    /* Parse the rest of sudo.conf. */
    sudo_conf_read(NULL, SUDO_CONF_ALL & ~SUDO_CONF_DEBUG);

    /* Fill in user_info with user name, uid, cwd, etc. */
    if ((user_info = get_user_info(&user_details)) == NULL)
	exit(EXIT_FAILURE); /* get_user_info printed error message */

    /* Disable core dumps if not enabled in sudo.conf. */
    if (sudo_conf_disable_coredump())
	disable_coredump();

    /* Parse command line arguments. */
    sudo_mode = parse_args(argc, argv, &nargc, &nargv, &settings, &env_add);
    sudo_debug_printf(SUDO_DEBUG_DEBUG, "sudo_mode %d", sudo_mode);

    /* Print sudo version early, in case of plugin init failure. */
    if (ISSET(sudo_mode, MODE_VERSION)) {
	printf(_("Sudo version %s\n"), PACKAGE_VERSION);
	if (user_details.uid == ROOT_UID)
	    (void) printf(_("Configure options: %s\n"), CONFIGURE_ARGS);
    }

    /* Use conversation function for sudo_(warn|fatal)x? for plugins. */
    sudo_warn_set_conversation(sudo_conversation);

    /* Load plugins. */
    if (!sudo_load_plugins(&policy_plugin, &io_plugins))
	sudo_fatalx(U_("fatal error, unable to load plugins"));

    /* Open policy plugin. */
    ok = policy_open(&policy_plugin, settings, user_info, envp);
    if (ok != 1) {
	if (ok == -2)
	    usage(1);
	else
	    sudo_fatalx(U_("unable to initialize policy plugin"));
    }

    switch (sudo_mode & MODE_MASK) {
	case MODE_VERSION:
	    policy_show_version(&policy_plugin, !user_details.uid);
	    TAILQ_FOREACH(plugin, &io_plugins, entries) {
		ok = iolog_open(plugin, settings, user_info, NULL,
		    nargc, nargv, envp);
		if (ok != -1)
		    iolog_show_version(plugin, !user_details.uid);
	    }
	    break;
	case MODE_VALIDATE:
	case MODE_VALIDATE|MODE_INVALIDATE:
	    ok = policy_validate(&policy_plugin);
	    exit(ok != 1);
	case MODE_KILL:
	case MODE_INVALIDATE:
	    policy_invalidate(&policy_plugin, sudo_mode == MODE_KILL);
	    exit(0);
	    break;
	case MODE_CHECK:
	case MODE_CHECK|MODE_INVALIDATE:
	case MODE_LIST:
	case MODE_LIST|MODE_INVALIDATE:
	    ok = policy_list(&policy_plugin, nargc, nargv,
		ISSET(sudo_mode, MODE_LONG_LIST), list_user);
	    exit(ok != 1);
	case MODE_EDIT:
	case MODE_RUN:
	    ok = policy_check(&policy_plugin, nargc, nargv, env_add,
		&command_info, &argv_out, &user_env_out);
	    sudo_debug_printf(SUDO_DEBUG_INFO, "policy plugin returns %d", ok);
	    if (ok != 1) {
		if (ok == -2)
		    usage(1);
		exit(EXIT_FAILURE); /* plugin printed error message */
	    }
	    /* Reset nargv/nargc based on argv_out. */
	    /* XXX - leaks old nargv in shell mode */
	    for (nargv = argv_out, nargc = 0; nargv[nargc] != NULL; nargc++)
		continue;
	    if (nargc == 0)
		sudo_fatalx(U_("plugin did not return a command to execute"));
	    /* Open I/O plugins once policy plugin succeeds. */
	    TAILQ_FOREACH_SAFE(plugin, &io_plugins, entries, next) {
		ok = iolog_open(plugin, settings, user_info,
		    command_info, nargc, nargv, user_env_out);
		switch (ok) {
		case 1:
		    break;
		case 0:
		    /* I/O plugin asked to be disabled, remove and free. */
		    iolog_unlink(plugin);
		    break;
		case -2:
		    usage(1);
		    break;
		default:
		    sudo_fatalx(U_("error initializing I/O plugin %s"),
			plugin->name);
		}
	    }
	    /* Setup command details and run command/edit. */
	    command_info_to_details(command_info, &command_details);
	    command_details.tty = user_details.tty;
	    command_details.argv = argv_out;
	    command_details.envp = user_env_out;
	    if (ISSET(sudo_mode, MODE_LOGIN_SHELL))
		SET(command_details.flags, CD_LOGIN_SHELL);
	    if (ISSET(sudo_mode, MODE_BACKGROUND))
		SET(command_details.flags, CD_BACKGROUND);
	    /* Become full root (not just setuid) so user cannot kill us. */
	    if (setuid(ROOT_UID) == -1)
		sudo_warn("setuid(%d)", ROOT_UID);
	    if (ISSET(command_details.flags, CD_SUDOEDIT)) {
		status = sudo_edit(&command_details);
	    } else {
		status = run_command(&command_details);
	    }
	    /* The close method was called by sudo_edit/run_command. */
	    break;
	default:
	    sudo_fatalx(U_("unexpected sudo mode 0x%x"), sudo_mode);
    }

    /*
     * If the command was terminated by a signal, sudo needs to terminated
     * the same way.  Otherwise, the shell may ignore a keyboard-generated
     * signal.  However, we want to avoid having sudo dump core itself.
     */
    if (WIFSIGNALED(status)) {
	struct sigaction sa;

	if (WCOREDUMP(status))
	    disable_coredump();

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_DFL;
	sigaction(WTERMSIG(status), &sa, NULL);
	sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys,
	    WTERMSIG(status) | 128);                
	kill(getpid(), WTERMSIG(status));
    }
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys,
	WEXITSTATUS(status));
    exit(WEXITSTATUS(status));
}

int
os_init_common(int argc, char *argv[], char *envp[])
{
#ifdef STATIC_SUDOERS_PLUGIN
    preload_static_symbols();
#endif
    gc_init();
    return 0;
}

/*
 * Ensure that stdin, stdout and stderr are open; set to /dev/null if not.
 * Some operating systems do this automatically in the kernel or libc.
 */
static void
fix_fds(void)
{
    int miss[3], devnull = -1;
    debug_decl(fix_fds, SUDO_DEBUG_UTIL)

    /*
     * stdin, stdout and stderr must be open; set them to /dev/null
     * if they are closed.
     */
    miss[STDIN_FILENO] = fcntl(STDIN_FILENO, F_GETFL, 0) == -1;
    miss[STDOUT_FILENO] = fcntl(STDOUT_FILENO, F_GETFL, 0) == -1;
    miss[STDERR_FILENO] = fcntl(STDERR_FILENO, F_GETFL, 0) == -1;
    if (miss[STDIN_FILENO] || miss[STDOUT_FILENO] || miss[STDERR_FILENO]) {
	devnull = open(_PATH_DEVNULL, O_RDWR, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if (devnull == -1)
	    sudo_fatal(U_("unable to open %s"), _PATH_DEVNULL);
	if (miss[STDIN_FILENO] && dup2(devnull, STDIN_FILENO) == -1)
	    sudo_fatal("dup2");
	if (miss[STDOUT_FILENO] && dup2(devnull, STDOUT_FILENO) == -1)
	    sudo_fatal("dup2");
	if (miss[STDERR_FILENO] && dup2(devnull, STDERR_FILENO) == -1)
	    sudo_fatal("dup2");
	if (devnull > STDERR_FILENO)
	    close(devnull);
    }
    debug_return;
}

/*
 * Allocate space for groups and fill in using sudo_getgrouplist2()
 * for when we cannot (or don't want to) use getgroups().
 * Returns 0 on success and -1 on failure.
 */
static int
fill_group_list(struct user_details *ud)
{
    int ret = -1;
    debug_decl(fill_group_list, SUDO_DEBUG_UTIL)

    /*
     * If user specified a max number of groups, use it, otherwise let
     * sudo_getgrouplist2() allocate the group vector.
     */
    ud->ngroups = sudo_conf_max_groups();
    if (ud->ngroups > 0) {
	ud->groups = reallocarray(NULL, ud->ngroups, sizeof(GETGROUPS_T));
	if (ud->groups != NULL) {
	    /* No error on insufficient space if user specified max_groups. */
	    (void)sudo_getgrouplist2(ud->username, ud->gid, &ud->groups,
		&ud->ngroups);
	    ret = 0;
	}
    } else {
	ud->groups = NULL;
	ret = sudo_getgrouplist2(ud->username, ud->gid, &ud->groups,
	    &ud->ngroups);
    }
    if (ret == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: %s: unable to get groups via sudo_getgrouplist2()",
	    __func__, ud->username);
    } else {
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: %s: got %d groups via sudo_getgrouplist2()",
	    __func__, ud->username, ud->ngroups);
    }
    debug_return_int(ret);
}

static char *
get_user_groups(struct user_details *ud)
{
    char *cp, *gid_list = NULL;
    size_t glsize;
    int i, len, group_source;
    debug_decl(get_user_groups, SUDO_DEBUG_UTIL)

    ud->groups = NULL;
    group_source = sudo_conf_group_source();
    if (group_source != GROUP_SOURCE_DYNAMIC) {
	int maxgroups = (int)sysconf(_SC_NGROUPS_MAX);
	if (maxgroups < 0)
	    maxgroups = NGROUPS_MAX;

	if ((ud->ngroups = getgroups(0, NULL)) > 0) {
	    /* Use groups from kernel if not too many or source is static. */
	    if (ud->ngroups < maxgroups || group_source == GROUP_SOURCE_STATIC) {
		ud->groups = reallocarray(NULL, ud->ngroups, sizeof(GETGROUPS_T));
		if (ud->groups == NULL)
		    goto done;
		if (getgroups(ud->ngroups, ud->groups) < 0) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
			"%s: %s: unable to get %d groups via getgroups()",
			__func__, ud->username, ud->ngroups);
		    free(ud->groups);
		    ud->groups = NULL;
		} else {
		    sudo_debug_printf(SUDO_DEBUG_INFO,
			"%s: %s: got %d groups via getgroups()",
			__func__, ud->username, ud->ngroups);
		}
	    }
	}
    }
    if (ud->groups == NULL) {
	/*
	 * Query group database if kernel list is too small or disabled.
	 * Typically, this is because NFS can only support up to 16 groups.
	 */
	if (fill_group_list(ud) == -1)
	    goto done;
    }

    /*
     * Format group list as a comma-separated string of gids.
     */
    glsize = sizeof("groups=") - 1 + (ud->ngroups * (MAX_UID_T_LEN + 1));
    if ((gid_list = malloc(glsize)) == NULL)
	goto done;
    memcpy(gid_list, "groups=", sizeof("groups=") - 1);
    cp = gid_list + sizeof("groups=") - 1;
    for (i = 0; i < ud->ngroups; i++) {
	len = snprintf(cp, glsize - (cp - gid_list), "%s%u",
	    i ? "," : "", (unsigned int)ud->groups[i]);
	if (len < 0 || (size_t)len >= glsize - (cp - gid_list))
	    sudo_fatalx(U_("internal error, %s overflow"), __func__);
	cp += len;
    }
done:
    debug_return_str(gid_list);
}

/*
 * Return user information as an array of name=value pairs.
 * and fill in struct user_details (which shares the same strings).
 */
static char **
get_user_info(struct user_details *ud)
{
    char *cp, **user_info, path[PATH_MAX];
    unsigned int i = 0;
    mode_t mask;
    struct passwd *pw;
    int fd;
    debug_decl(get_user_info, SUDO_DEBUG_UTIL)

    /*
     * On BSD systems you can set a hint to keep the password and
     * group databases open instead of having to open and close
     * them all the time.  Since sudo does a lot of password and
     * group lookups, keeping the file open can speed things up.
     */
#ifdef HAVE_SETPASSENT
    setpassent(1);
#endif /* HAVE_SETPASSENT */
#ifdef HAVE_SETGROUPENT
    setgroupent(1);
#endif /* HAVE_SETGROUPENT */

    memset(ud, 0, sizeof(*ud));

    /* XXX - bound check number of entries */
    user_info = reallocarray(NULL, 32, sizeof(char *));
    if (user_info == NULL)
	goto oom;

    ud->pid = getpid();
    ud->ppid = getppid();
    ud->pgid = getpgid(0);
    ud->tcpgid = -1;
    fd = open(_PATH_TTY, O_RDWR);
    if (fd != -1) {
	ud->tcpgid = tcgetpgrp(fd);
	close(fd);
    }
    ud->sid = getsid(0);

    ud->uid = getuid();
    ud->euid = geteuid();
    ud->gid = getgid();
    ud->egid = getegid();

#ifdef HAVE_SETAUTHDB
    aix_setauthdb(IDtouser(ud->uid), NULL);
#endif
    pw = getpwuid(ud->uid);
#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif
    if (pw == NULL)
	sudo_fatalx(U_("you do not exist in the %s database"), "passwd");

    user_info[i] = sudo_new_key_val("user", pw->pw_name);
    if (user_info[i] == NULL)
	goto oom;
    ud->username = user_info[i] + sizeof("user=") - 1;

    /* Stash user's shell for use with the -s flag; don't pass to plugin. */
    if ((ud->shell = getenv("SHELL")) == NULL || ud->shell[0] == '\0') {
	ud->shell = pw->pw_shell[0] ? pw->pw_shell : _PATH_SUDO_BSHELL;
    }
    if ((ud->shell = strdup(ud->shell)) == NULL)
	goto oom;

    if (asprintf(&user_info[++i], "pid=%d", (int)ud->pid) == -1)
	goto oom;
    if (asprintf(&user_info[++i], "ppid=%d", (int)ud->ppid) == -1)
	goto oom;
    if (ud->pgid != -1) {
	if (asprintf(&user_info[++i], "pgid=%d", (int)ud->pgid) == -1)
	    goto oom;
    }
    if (ud->tcpgid != -1) {
	if (asprintf(&user_info[++i], "tcpgid=%d", (int)ud->tcpgid) == -1)
	    goto oom;
    }
    if (ud->sid != -1) {
	if (asprintf(&user_info[++i], "sid=%d", (int)ud->sid) == -1)
	    goto oom;
    }
    if (asprintf(&user_info[++i], "uid=%u", (unsigned int)ud->uid) == -1)
	goto oom;
    if (asprintf(&user_info[++i], "euid=%u", (unsigned int)ud->euid) == -1)
	goto oom;
    if (asprintf(&user_info[++i], "gid=%u", (unsigned int)ud->gid) == -1)
	goto oom;
    if (asprintf(&user_info[++i], "egid=%u", (unsigned int)ud->egid) == -1)
	goto oom;

    if ((cp = get_user_groups(ud)) == NULL)
	goto oom;
    user_info[++i] = cp;

    mask = umask(0);
    umask(mask);
    if (asprintf(&user_info[++i], "umask=0%o", (unsigned int)mask) == -1)
	goto oom;

    if (getcwd(path, sizeof(path)) != NULL) {
	user_info[++i] = sudo_new_key_val("cwd", path);
	if (user_info[i] == NULL)
	    goto oom;
	ud->cwd = user_info[i] + sizeof("cwd=") - 1;
    }

    if (get_process_ttyname(path, sizeof(path)) != NULL) {
	user_info[++i] = sudo_new_key_val("tty", path);
	if (user_info[i] == NULL)
	    goto oom;
	ud->tty = user_info[i] + sizeof("tty=") - 1;
    } else {
	/* tty may not always be present */
	if (errno != ENOENT)
	    sudo_warn(U_("unable to determine tty"));
    }

    cp = sudo_gethostname();
    user_info[++i] = sudo_new_key_val("host", cp ? cp : "localhost");
    free(cp);
    if (user_info[i] == NULL)
	goto oom;
    ud->host = user_info[i] + sizeof("host=") - 1;

    sudo_get_ttysize(&ud->ts_rows, &ud->ts_cols);
    if (asprintf(&user_info[++i], "lines=%d", ud->ts_rows) == -1)
	goto oom;
    if (asprintf(&user_info[++i], "cols=%d", ud->ts_cols) == -1)
	goto oom;

    user_info[++i] = NULL;

    /* Add to list of vectors to be garbage collected at exit. */
    if (!gc_add(GC_VECTOR, user_info))
	goto bad;

    debug_return_ptr(user_info);
oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
bad:
    while (i--)
	free(user_info[i]);
    free(user_info);
    debug_return_ptr(NULL);
}

/*
 * Convert a command_info array into a command_details structure.
 */
static void
command_info_to_details(char * const info[], struct command_details *details)
{
    int i;
    id_t id;
    char *cp;
    const char *errstr;
    debug_decl(command_info_to_details, SUDO_DEBUG_PCOMM)

    memset(details, 0, sizeof(*details));
    details->closefrom = -1;
    details->execfd = -1;
    details->flags = CD_SUDOEDIT_CHECKDIR | CD_SET_GROUPS;
    TAILQ_INIT(&details->preserved_fds);

#define SET_STRING(s, n) \
    if (strncmp(s, info[i], sizeof(s) - 1) == 0 && info[i][sizeof(s) - 1]) { \
	details->n = info[i] + sizeof(s) - 1; \
	break; \
    }
#define SET_FLAG(s, n) \
    if (strncmp(s, info[i], sizeof(s) - 1) == 0) { \
	switch (sudo_strtobool(info[i] + sizeof(s) - 1)) { \
	    case true: \
		SET(details->flags, n); \
		break; \
	    case false: \
		CLR(details->flags, n); \
		break; \
	    default: \
		sudo_debug_printf(SUDO_DEBUG_ERROR, \
		    "invalid boolean value for %s", info[i]); \
		break; \
	} \
	break; \
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "command info from plugin:");
    for (i = 0; info[i] != NULL; i++) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "    %d: %s", i, info[i]);
	switch (info[i][0]) {
	    case 'c':
		SET_STRING("chroot=", chroot)
		SET_STRING("command=", command)
		SET_STRING("cwd=", cwd)
		if (strncmp("closefrom=", info[i], sizeof("closefrom=") - 1) == 0) {
		    cp = info[i] + sizeof("closefrom=") - 1;
		    details->closefrom = sudo_strtonum(cp, 0, INT_MAX, &errstr);
		    if (errstr != NULL)
			sudo_fatalx(U_("%s: %s"), info[i], U_(errstr));
		    break;
		}
		break;
	    case 'e':
		SET_FLAG("exec_background=", CD_EXEC_BG)
		if (strncmp("execfd=", info[i], sizeof("execfd=") - 1) == 0) {
		    cp = info[i] + sizeof("execfd=") - 1;
		    details->execfd = sudo_strtonum(cp, 0, INT_MAX, &errstr);
		    if (errstr != NULL)
			sudo_fatalx(U_("%s: %s"), info[i], U_(errstr));
#ifdef HAVE_FEXECVE
		    /* Must keep fd open during exec. */
		    add_preserved_fd(&details->preserved_fds, details->execfd);
#else
		    /* Plugin thinks we support fexecve() but we don't. */
		    (void)fcntl(details->execfd, F_SETFD, FD_CLOEXEC);
		    details->execfd = -1;
#endif
		    break;
		}
		break;
	    case 'l':
		SET_STRING("login_class=", login_class)
		break;
	    case 'n':
		if (strncmp("nice=", info[i], sizeof("nice=") - 1) == 0) {
		    cp = info[i] + sizeof("nice=") - 1;
		    details->priority = sudo_strtonum(cp, INT_MIN, INT_MAX,
			&errstr);
		    if (errstr != NULL)
			sudo_fatalx(U_("%s: %s"), info[i], U_(errstr));
		    SET(details->flags, CD_SET_PRIORITY);
		    break;
		}
		SET_FLAG("noexec=", CD_NOEXEC)
		break;
	    case 'p':
		SET_FLAG("preserve_groups=", CD_PRESERVE_GROUPS)
		if (strncmp("preserve_fds=", info[i], sizeof("preserve_fds=") - 1) == 0) {
		    parse_preserved_fds(&details->preserved_fds,
			info[i] + sizeof("preserve_fds=") - 1);
		    break;
		}
		break;
	    case 'r':
		if (strncmp("runas_egid=", info[i], sizeof("runas_egid=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_egid=") - 1;
		    id = sudo_strtoid(cp, &errstr);
		    if (errstr != NULL)
			sudo_fatalx(U_("%s: %s"), info[i], U_(errstr));
		    details->egid = (gid_t)id;
		    SET(details->flags, CD_SET_EGID);
		    break;
		}
		if (strncmp("runas_euid=", info[i], sizeof("runas_euid=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_euid=") - 1;
		    id = sudo_strtoid(cp, &errstr);
		    if (errstr != NULL)
			sudo_fatalx(U_("%s: %s"), info[i], U_(errstr));
		    details->euid = (uid_t)id;
		    SET(details->flags, CD_SET_EUID);
		    break;
		}
		if (strncmp("runas_gid=", info[i], sizeof("runas_gid=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_gid=") - 1;
		    id = sudo_strtoid(cp, &errstr);
		    if (errstr != NULL)
			sudo_fatalx(U_("%s: %s"), info[i], U_(errstr));
		    details->gid = (gid_t)id;
		    SET(details->flags, CD_SET_GID);
		    break;
		}
		if (strncmp("runas_groups=", info[i], sizeof("runas_groups=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_groups=") - 1;
		    details->ngroups = sudo_parse_gids(cp, NULL, &details->groups);
		    /* sudo_parse_gids() will print a warning on error. */
		    if (details->ngroups == -1)
			exit(EXIT_FAILURE); /* XXX */
		    break;
		}
		if (strncmp("runas_uid=", info[i], sizeof("runas_uid=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_uid=") - 1;
		    id = sudo_strtoid(cp, &errstr);
		    if (errstr != NULL)
			sudo_fatalx(U_("%s: %s"), info[i], U_(errstr));
		    details->uid = (uid_t)id;
		    SET(details->flags, CD_SET_UID);
		    break;
		}
#ifdef HAVE_PRIV_SET
		if (strncmp("runas_privs=", info[i], sizeof("runas_privs=") - 1) == 0) {
                    const char *endp;
		    cp = info[i] + sizeof("runas_privs=") - 1;
	            if (*cp != '\0') {
			details->privs = priv_str_to_set(cp, ",", &endp);
			if (details->privs == NULL)
			    sudo_warn("invalid runas_privs %s", endp);
		    }
		    break;
		}
		if (strncmp("runas_limitprivs=", info[i], sizeof("runas_limitprivs=") - 1) == 0) {
                    const char *endp;
		    cp = info[i] + sizeof("runas_limitprivs=") - 1;
	            if (*cp != '\0') {
			details->limitprivs = priv_str_to_set(cp, ",", &endp);
			if (details->limitprivs == NULL)
			    sudo_warn("invalid runas_limitprivs %s", endp);
		    }
		    break;
		}
#endif /* HAVE_PRIV_SET */
		break;
	    case 's':
		SET_STRING("selinux_role=", selinux_role)
		SET_STRING("selinux_type=", selinux_type)
		SET_FLAG("set_utmp=", CD_SET_UTMP)
		SET_FLAG("sudoedit=", CD_SUDOEDIT)
		SET_FLAG("sudoedit_checkdir=", CD_SUDOEDIT_CHECKDIR)
		SET_FLAG("sudoedit_follow=", CD_SUDOEDIT_FOLLOW)
		break;
	    case 't':
		if (strncmp("timeout=", info[i], sizeof("timeout=") - 1) == 0) {
		    cp = info[i] + sizeof("timeout=") - 1;
		    details->timeout = sudo_strtonum(cp, 0, INT_MAX, &errstr);
		    if (errstr != NULL)
			sudo_fatalx(U_("%s: %s"), info[i], U_(errstr));
		    SET(details->flags, CD_SET_TIMEOUT);
		    break;
		}
		break;
	    case 'u':
		if (strncmp("umask=", info[i], sizeof("umask=") - 1) == 0) {
		    cp = info[i] + sizeof("umask=") - 1;
		    details->umask = sudo_strtomode(cp, &errstr);
		    if (errstr != NULL)
			sudo_fatalx(U_("%s: %s"), info[i], U_(errstr));
		    SET(details->flags, CD_SET_UMASK);
		    break;
		}
		SET_FLAG("umask_override=", CD_OVERRIDE_UMASK)
		SET_FLAG("use_pty=", CD_USE_PTY)
		SET_STRING("utmp_user=", utmp_user)
		break;
	}
    }

    if (!ISSET(details->flags, CD_SET_EUID))
	details->euid = details->uid;
    if (!ISSET(details->flags, CD_SET_EGID))
	details->egid = details->gid;
    if (!ISSET(details->flags, CD_SET_UMASK))
	CLR(details->flags, CD_OVERRIDE_UMASK);

#ifdef HAVE_SETAUTHDB
    aix_setauthdb(IDtouser(details->euid), NULL);
#endif
    details->pw = getpwuid(details->euid);
#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif
    if (details->pw != NULL && (details->pw = pw_dup(details->pw)) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

#ifdef HAVE_SELINUX
    if (details->selinux_role != NULL && is_selinux_enabled() > 0)
	SET(details->flags, CD_RBAC_ENABLED);
#endif
    debug_return;
}

static void
sudo_check_suid(const char *sudo)
{
    char pathbuf[PATH_MAX];
    struct stat sb;
    bool qualified;
    debug_decl(sudo_check_suid, SUDO_DEBUG_PCOMM)

    if (geteuid() != ROOT_UID) {
	/* Search for sudo binary in PATH if not fully qualified. */
	qualified = strchr(sudo, '/') != NULL;
	if (!qualified) {
	    char *path = getenv_unhooked("PATH");
	    if (path != NULL) {
		const char *cp, *ep;
		const char *pathend = path + strlen(path);

		for (cp = sudo_strsplit(path, pathend, ":", &ep); cp != NULL;
		    cp = sudo_strsplit(NULL, pathend, ":", &ep)) {

		    int len = snprintf(pathbuf, sizeof(pathbuf), "%.*s/%s",
			(int)(ep - cp), cp, sudo);
		    if (len < 0 || len >= ssizeof(pathbuf))
			continue;
		    if (access(pathbuf, X_OK) == 0) {
			sudo = pathbuf;
			qualified = true;
			break;
		    }
		}
	    }
	}

	if (qualified && stat(sudo, &sb) == 0) {
	    /* Try to determine why sudo was not running as root. */
	    if (sb.st_uid != ROOT_UID || !ISSET(sb.st_mode, S_ISUID)) {
		sudo_fatalx(
		    U_("%s must be owned by uid %d and have the setuid bit set"),
		    sudo, ROOT_UID);
	    } else {
		sudo_fatalx(U_("effective uid is not %d, is %s on a file system "
		    "with the 'nosuid' option set or an NFS file system without"
		    " root privileges?"), ROOT_UID, sudo);
	    }
	} else {
	    sudo_fatalx(
		U_("effective uid is not %d, is sudo installed setuid root?"),
		ROOT_UID);
	}
    }
    debug_return;
}

bool
set_user_groups(struct command_details *details)
{
    bool ret = false;
    debug_decl(set_user_groups, SUDO_DEBUG_EXEC)

    if (!ISSET(details->flags, CD_PRESERVE_GROUPS)) {
	if (details->ngroups >= 0) {
	    if (sudo_setgroups(details->ngroups, details->groups) < 0) {
		sudo_warn(U_("unable to set supplementary group IDs"));
		goto done;
	    }
	}
    }
#ifdef HAVE_SETEUID
    if (ISSET(details->flags, CD_SET_EGID) && setegid(details->egid)) {
	sudo_warn(U_("unable to set effective gid to runas gid %u"),
	    (unsigned int)details->egid);
	goto done;
    }
#endif
    if (ISSET(details->flags, CD_SET_GID) && setgid(details->gid)) {
	sudo_warn(U_("unable to set gid to runas gid %u"),
	    (unsigned int)details->gid);
	goto done;
    }
    ret = true;

done:
    CLR(details->flags, CD_SET_GROUPS);
    debug_return_bool(ret);
}

/*
 * Run the command and wait for it to complete.
 * Returns wait status suitable for use with the wait(2) macros.
 */
int
run_command(struct command_details *details)
{
    struct plugin_container *plugin;
    struct command_status cstat;
    int status = W_EXITCODE(1, 0);
    debug_decl(run_command, SUDO_DEBUG_EXEC)

    cstat.type = CMD_INVALID;
    cstat.val = 0;

    sudo_execute(details, &cstat);

    switch (cstat.type) {
    case CMD_ERRNO:
	/* exec_setup() or execve() returned an error. */
	sudo_debug_printf(SUDO_DEBUG_DEBUG,
	    "calling policy close with errno %d", cstat.val);
	policy_close(&policy_plugin, 0, cstat.val);
	TAILQ_FOREACH(plugin, &io_plugins, entries) {
	    sudo_debug_printf(SUDO_DEBUG_DEBUG,
		"calling I/O close with errno %d", cstat.val);
	    iolog_close(plugin, 0, cstat.val);
	}
	break;
    case CMD_WSTATUS:
	/* Command ran, exited or was killed. */
	status = cstat.val;
#ifdef HAVE_SELINUX
	if (ISSET(details->flags, CD_SUDOEDIT_COPY))
	    break;
#endif
	sudo_debug_printf(SUDO_DEBUG_DEBUG,
	    "calling policy close with wait status %d", status);
	policy_close(&policy_plugin, status, 0);
	TAILQ_FOREACH(plugin, &io_plugins, entries) {
	    sudo_debug_printf(SUDO_DEBUG_DEBUG,
		"calling I/O close with wait status %d", status);
	    iolog_close(plugin, status, 0);
	}
	break;
    default:
	sudo_warnx(U_("unexpected child termination condition: %d"), cstat.type);
	break;
    }
    debug_return_int(status);
}

/*
 * Format struct sudo_settings as name=value pairs for the plugin
 * to consume.  Returns a NULL-terminated plugin-style array of pairs.
 */
static char **
format_plugin_settings(struct plugin_container *plugin,
    struct sudo_settings *sudo_settings)
{
    size_t plugin_settings_size;
    struct sudo_debug_file *debug_file;
    struct sudo_settings *setting;
    char **plugin_settings;
    unsigned int i = 0;
    debug_decl(format_plugin_settings, SUDO_DEBUG_PCOMM)

    /* Determine sudo_settings array size (including plugin_path and NULL) */
    plugin_settings_size = 2;
    for (setting = sudo_settings; setting->name != NULL; setting++)
	plugin_settings_size++;
    if (plugin->debug_files != NULL) {
	TAILQ_FOREACH(debug_file, plugin->debug_files, entries)
	    plugin_settings_size++;
    }

    /* Allocate and fill in. */
    plugin_settings = reallocarray(NULL, plugin_settings_size, sizeof(char *));
    if (plugin_settings == NULL)
	goto bad;
    plugin_settings[i] = sudo_new_key_val("plugin_path", plugin->path);
    if (plugin_settings[i] == NULL)
	goto bad;
    for (setting = sudo_settings; setting->name != NULL; setting++) {
        if (setting->value != NULL) {
            sudo_debug_printf(SUDO_DEBUG_INFO, "settings: %s=%s",
                setting->name, setting->value);
	    plugin_settings[++i] =
		sudo_new_key_val(setting->name, setting->value);
	    if (plugin_settings[i] == NULL)
		goto bad;
        }
    }
    if (plugin->debug_files != NULL) {
	TAILQ_FOREACH(debug_file, plugin->debug_files, entries) {
	    /* XXX - quote filename? */
	    if (asprintf(&plugin_settings[++i], "debug_flags=%s %s",
		debug_file->debug_file, debug_file->debug_flags) == -1)
		goto bad;
	}
    }
    plugin_settings[++i] = NULL;

    /* Add to list of vectors to be garbage collected at exit. */
    if (!gc_add(GC_VECTOR, plugin_settings))
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    debug_return_ptr(plugin_settings);
bad:
    while (i--)
	free(plugin_settings[i]);
    free(plugin_settings);
    debug_return_ptr(NULL);
}

static int
policy_open(struct plugin_container *plugin, struct sudo_settings *settings,
    char * const user_info[], char * const user_env[])
{
    char **plugin_settings;
    int ret;
    debug_decl(policy_open, SUDO_DEBUG_PCOMM)

    /* Convert struct sudo_settings to plugin_settings[] */
    plugin_settings = format_plugin_settings(plugin, settings);
    if (plugin_settings == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(-1);
    }

    /*
     * Backwards compatibility for older API versions
     */
    sudo_debug_set_active_instance(SUDO_DEBUG_INSTANCE_INITIALIZER);
    switch (plugin->u.generic->version) {
    case SUDO_API_MKVERSION(1, 0):
    case SUDO_API_MKVERSION(1, 1):
	ret = plugin->u.policy_1_0->open(plugin->u.io_1_0->version,
	    sudo_conversation_1_7, sudo_conversation_printf, plugin_settings,
	    user_info, user_env);
	break;
    default:
	ret = plugin->u.policy->open(SUDO_API_VERSION, sudo_conversation,
	    sudo_conversation_printf, plugin_settings, user_info, user_env,
	    plugin->options);
    }

    /* Stash plugin debug instance ID if set in open() function. */
    plugin->debug_instance = sudo_debug_get_active_instance();
    sudo_debug_set_active_instance(sudo_debug_instance);

    debug_return_int(ret);
}

static void
policy_close(struct plugin_container *plugin, int exit_status, int error_code)
{
    debug_decl(policy_close, SUDO_DEBUG_PCOMM)
    if (plugin->u.policy->close != NULL) {
	sudo_debug_set_active_instance(plugin->debug_instance);
	plugin->u.policy->close(exit_status, error_code);
	sudo_debug_set_active_instance(sudo_debug_instance);
    } else if (error_code) {
	errno = error_code;
	sudo_warn(U_("unable to execute %s"), command_details.command);
    }
    debug_return;
}

static int
policy_show_version(struct plugin_container *plugin, int verbose)
{
    int ret;
    debug_decl(policy_show_version, SUDO_DEBUG_PCOMM)

    if (plugin->u.policy->show_version == NULL)
	debug_return_int(true);
    sudo_debug_set_active_instance(plugin->debug_instance);
    ret = plugin->u.policy->show_version(verbose);
    sudo_debug_set_active_instance(sudo_debug_instance);
    debug_return_int(ret);
}

static int
policy_check(struct plugin_container *plugin, int argc, char * const argv[],
    char *env_add[], char **command_info[], char **argv_out[],
    char **user_env_out[])
{
    int ret;
    debug_decl(policy_check, SUDO_DEBUG_PCOMM)

    if (plugin->u.policy->check_policy == NULL) {
	sudo_fatalx(U_("policy plugin %s is missing the `check_policy' method"),
	    plugin->name);
    }
    sudo_debug_set_active_instance(plugin->debug_instance);
    ret = plugin->u.policy->check_policy(argc, argv, env_add, command_info,
	argv_out, user_env_out);
    sudo_debug_set_active_instance(sudo_debug_instance);
    debug_return_int(ret);
}

static int
policy_list(struct plugin_container *plugin, int argc, char * const argv[],
    int verbose, const char *list_user)
{
    int ret;
    debug_decl(policy_list, SUDO_DEBUG_PCOMM)

    if (plugin->u.policy->list == NULL) {
	sudo_warnx(U_("policy plugin %s does not support listing privileges"),
	    plugin->name);
	debug_return_int(false);
    }
    sudo_debug_set_active_instance(plugin->debug_instance);
    ret = plugin->u.policy->list(argc, argv, verbose, list_user);
    sudo_debug_set_active_instance(sudo_debug_instance);
    debug_return_int(ret);
}

static int
policy_validate(struct plugin_container *plugin)
{
    int ret;
    debug_decl(policy_validate, SUDO_DEBUG_PCOMM)

    if (plugin->u.policy->validate == NULL) {
	sudo_warnx(U_("policy plugin %s does not support the -v option"),
	    plugin->name);
	debug_return_int(false);
    }
    sudo_debug_set_active_instance(plugin->debug_instance);
    ret = plugin->u.policy->validate();
    sudo_debug_set_active_instance(sudo_debug_instance);
    debug_return_int(ret);
}

static void
policy_invalidate(struct plugin_container *plugin, int remove)
{
    debug_decl(policy_invalidate, SUDO_DEBUG_PCOMM)
    if (plugin->u.policy->invalidate == NULL) {
	sudo_fatalx(U_("policy plugin %s does not support the -k/-K options"),
	    plugin->name);
    }
    sudo_debug_set_active_instance(plugin->debug_instance);
    plugin->u.policy->invalidate(remove);
    sudo_debug_set_active_instance(sudo_debug_instance);
    debug_return;
}

int
policy_init_session(struct command_details *details)
{
    int ret = true;
    debug_decl(policy_init_session, SUDO_DEBUG_PCOMM)

    /*
     * We set groups, including supplementary group vector,
     * as part of the session setup.  This allows for dynamic
     * groups to be set via pam_group(8) in pam_setcred(3).
     */
    if (ISSET(details->flags, CD_SET_GROUPS)) {
	/* set_user_groups() prints error message on failure. */
	if (!set_user_groups(details))
	    goto done;
    }

    /* Session setup may override sudoers umask so set it first. */
    if (ISSET(details->flags, CD_SET_UMASK))
	(void) umask(details->umask);

    if (policy_plugin.u.policy->init_session) {
	/*
	 * Backwards compatibility for older API versions
	 */
	sudo_debug_set_active_instance(policy_plugin.debug_instance);
	switch (policy_plugin.u.generic->version) {
	case SUDO_API_MKVERSION(1, 0):
	case SUDO_API_MKVERSION(1, 1):
	    ret = policy_plugin.u.policy_1_0->init_session(details->pw);
	    break;
	default:
	    ret = policy_plugin.u.policy->init_session(details->pw,
		&details->envp);
	}
	sudo_debug_set_active_instance(sudo_debug_instance);
    }
done:
    debug_return_int(ret);
}

static int
iolog_open(struct plugin_container *plugin, struct sudo_settings *settings,
    char * const user_info[], char * const command_info[],
    int argc, char * const argv[], char * const user_env[])
{
    char **plugin_settings;
    int ret;
    debug_decl(iolog_open, SUDO_DEBUG_PCOMM)

    /* Convert struct sudo_settings to plugin_settings[] */
    plugin_settings = format_plugin_settings(plugin, settings);
    if (plugin_settings == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(-1);
    }

    /*
     * Backwards compatibility for older API versions
     */
    sudo_debug_set_active_instance(plugin->debug_instance);
    switch (plugin->u.generic->version) {
    case SUDO_API_MKVERSION(1, 0):
	ret = plugin->u.io_1_0->open(plugin->u.io_1_0->version,
	    sudo_conversation_1_7, sudo_conversation_printf, plugin_settings,
	    user_info, argc, argv, user_env);
	break;
    case SUDO_API_MKVERSION(1, 1):
	ret = plugin->u.io_1_1->open(plugin->u.io_1_1->version,
	    sudo_conversation_1_7, sudo_conversation_printf, plugin_settings,
	    user_info, command_info, argc, argv, user_env);
	break;
    default:
	ret = plugin->u.io->open(SUDO_API_VERSION, sudo_conversation,
	    sudo_conversation_printf, plugin_settings, user_info, command_info,
	    argc, argv, user_env, plugin->options);
    }

    /* Stash plugin debug instance ID if set in open() function. */
    plugin->debug_instance = sudo_debug_get_active_instance();
    sudo_debug_set_active_instance(sudo_debug_instance);

    debug_return_int(ret);
}

static void
iolog_close(struct plugin_container *plugin, int exit_status, int error_code)
{
    debug_decl(iolog_close, SUDO_DEBUG_PCOMM)

    if (plugin->u.io->close != NULL) {
	sudo_debug_set_active_instance(plugin->debug_instance);
	plugin->u.io->close(exit_status, error_code);
	sudo_debug_set_active_instance(sudo_debug_instance);
    }
    debug_return;
}

static int
iolog_show_version(struct plugin_container *plugin, int verbose)
{
    int ret;
    debug_decl(iolog_show_version, SUDO_DEBUG_PCOMM)

    if (plugin->u.io->show_version == NULL)
	debug_return_int(true);

    sudo_debug_set_active_instance(plugin->debug_instance);
    ret = plugin->u.io->show_version(verbose);
    sudo_debug_set_active_instance(sudo_debug_instance);
    debug_return_int(ret);
}

/*
 * Remove the specified I/O logging plugin from the io_plugins list.
 * Deregisters any hooks before unlinking, then frees the container.
 */
static void
iolog_unlink(struct plugin_container *plugin)
{
    debug_decl(iolog_unlink, SUDO_DEBUG_PCOMM)

    /* Deregister hooks, if any. */
    if (plugin->u.io->version >= SUDO_API_MKVERSION(1, 2)) {
	if (plugin->u.io->deregister_hooks != NULL) {
	    sudo_debug_set_active_instance(plugin->debug_instance);
	    plugin->u.io->deregister_hooks(SUDO_HOOK_VERSION,
		deregister_hook);
	    sudo_debug_set_active_instance(sudo_debug_instance);
	}
    }
    /* Remove from io_plugins list and free. */
    TAILQ_REMOVE(&io_plugins, plugin, entries);
    free_plugin_container(plugin, true);

    debug_return;
}

static void
free_plugin_container(struct plugin_container *plugin, bool ioplugin)
{
    debug_decl(free_plugin_container, SUDO_DEBUG_PLUGIN)

    free(plugin->path);
    free(plugin->name);
    if (plugin->options != NULL) {
	int i = 0;
	while (plugin->options[i] != NULL)
	    free(plugin->options[i++]);
	free(plugin->options);
    }
    if (ioplugin)
	free(plugin);

    debug_return;
}

bool
gc_add(enum sudo_gc_types type, void *v)
{
#ifdef NO_LEAKS
    struct sudo_gc_entry *gc;
    debug_decl(gc_add, SUDO_DEBUG_MAIN)

    if (v == NULL)
	debug_return_bool(false);

    gc = calloc(1, sizeof(*gc));
    if (gc == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_bool(false);
    }
    switch (type) {
    case GC_PTR:
	gc->u.ptr = v;
	break;
    case GC_VECTOR:
	gc->u.vec = v;
	break;
    default:
	free(gc);
	sudo_warnx("unexpected garbage type %d", type);
	debug_return_bool(false);
    }
    gc->type = type;
    SLIST_INSERT_HEAD(&sudo_gc_list, gc, entries);
    debug_return_bool(true);
#else
    return true;
#endif /* NO_LEAKS */
}

#ifdef NO_LEAKS
static void
gc_run(void)
{
    struct plugin_container *plugin;
    struct sudo_gc_entry *gc;
    char **cur;
    debug_decl(gc_run, SUDO_DEBUG_MAIN)

    /* Collect garbage. */
    while ((gc = SLIST_FIRST(&sudo_gc_list))) {
	SLIST_REMOVE_HEAD(&sudo_gc_list, entries);
	switch (gc->type) {
	case GC_PTR:
	    free(gc->u.ptr);
	    free(gc);
	    break;
	case GC_VECTOR:
	    for (cur = gc->u.vec; *cur != NULL; cur++)
		free(*cur);
	    free(gc->u.vec);
	    free(gc);
	    break;
	default:
	    sudo_warnx("unexpected garbage type %d", gc->type);
	}
    }

    /* Free plugin structs. */
    free_plugin_container(&policy_plugin, false);
    while ((plugin = TAILQ_FIRST(&io_plugins))) {
	TAILQ_REMOVE(&io_plugins, plugin, entries);
	free_plugin_container(plugin, true);
    }

    debug_return;
}
#endif /* NO_LEAKS */

static void
gc_init(void)
{
#ifdef NO_LEAKS
    atexit(gc_run);
#endif
}
