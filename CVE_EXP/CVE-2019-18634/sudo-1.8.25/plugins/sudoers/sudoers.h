/*
 * Copyright (c) 1993-1996, 1998-2005, 2007-2017
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

#ifndef SUDOERS_SUDOERS_H
#define SUDOERS_SUDOERS_H

#include <limits.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

#define DEFAULT_TEXT_DOMAIN	"sudoers"
#include "sudo_gettext.h"	/* must be included before sudo_compat.h */

#include <pathnames.h>
#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "sudo_queue.h"
#include "defaults.h"
#include "logging.h"
#include "parse.h"
#include "sudo_nss.h"
#include "sudo_plugin.h"
#include "sudo_conf.h"
#include "sudo_util.h"
#include "sudoers_debug.h"

/*
 * Supplementary group IDs for a user.
 */
struct gid_list {
    int ngids;
    GETGROUPS_T *gids;
};

/*
 * Supplementary group names for a user.
 */
struct group_list {
    int ngroups;
    char **groups;
};

/*
 * Info pertaining to the invoking user.
 */
struct sudo_user {
    struct passwd *pw;
    struct passwd *_runas_pw;
    struct group *_runas_gr;
    struct stat *cmnd_stat;
    char *name;
    char *path;
    char *tty;
    char *ttypath;
    char *host;
    char *shost;
    char *runhost;
    char *srunhost;
    char *prompt;
    char *cmnd;
    char *cmnd_args;
    char *cmnd_base;
    char *cmnd_safe;
    char *class_name;
    char *krb5_ccname;
    struct gid_list *gid_list;
    char * const * env_vars;
#ifdef HAVE_SELINUX
    char *role;
    char *type;
#endif
#ifdef HAVE_PRIV_SET
    char *privs;
    char *limitprivs;
#endif
    const char *cwd;
    char *iolog_file;
    GETGROUPS_T *gids;
    int   execfd;
    int   ngids;
    int   closefrom;
    int   lines;
    int   cols;
    int   flags;
    int   max_groups;
    int   timeout;
    mode_t umask;
    uid_t uid;
    uid_t gid;
    pid_t sid;
};

/*
 * sudo_get_gidlist() type values
 */
#define ENTRY_TYPE_ANY		0x00
#define ENTRY_TYPE_QUERIED	0x01
#define ENTRY_TYPE_FRONTEND	0x02

/*
 * sudo_user flag values
 */
#define RUNAS_USER_SPECIFIED	0x01
#define RUNAS_GROUP_SPECIFIED	0x02

/*
 * Return values for sudoers_lookup(), also used as arguments for log_auth()
 * Note: cannot use '0' as a value here.
 */
#define VALIDATE_ERROR		0x001
#define VALIDATE_SUCCESS	0x002
#define VALIDATE_FAILURE	0x004
#define FLAG_CHECK_USER		0x010
#define FLAG_NO_USER		0x020
#define FLAG_NO_HOST		0x040
#define FLAG_NO_CHECK		0x080
#define FLAG_NON_INTERACTIVE	0x100
#define FLAG_BAD_PASSWORD	0x200

/*
 * find_path()/set_cmnd() return values
 */
#define FOUND			0
#define NOT_FOUND		1
#define NOT_FOUND_DOT		2
#define NOT_FOUND_ERROR		3
#define NOT_FOUND_PATH		4

/*
 * Various modes sudo can be in (based on arguments) in hex
 */
#define MODE_RUN		0x00000001
#define MODE_EDIT		0x00000002
#define MODE_VALIDATE		0x00000004
#define MODE_INVALIDATE		0x00000008
#define MODE_KILL		0x00000010
#define MODE_VERSION		0x00000020
#define MODE_HELP		0x00000040
#define MODE_LIST		0x00000080
#define MODE_CHECK		0x00000100
#define MODE_ERROR		0x00000200
#define MODE_MASK		0x0000ffff

/* Mode flags */
#define MODE_BACKGROUND		0x00010000 /* XXX - unused */
#define MODE_SHELL		0x00020000
#define MODE_LOGIN_SHELL	0x00040000
#define MODE_IMPLIED_SHELL	0x00080000
#define MODE_RESET_HOME		0x00100000
#define MODE_PRESERVE_GROUPS	0x00200000
#define MODE_PRESERVE_ENV	0x00400000
#define MODE_NONINTERACTIVE	0x00800000
#define MODE_IGNORE_TICKET	0x01000000

/*
 * Used with set_perms()
 */
#define PERM_INITIAL		0x00
#define PERM_ROOT		0x01
#define PERM_USER		0x02
#define PERM_FULL_USER		0x03
#define PERM_SUDOERS		0x04
#define PERM_RUNAS		0x05
#define PERM_TIMESTAMP		0x06
#define PERM_IOLOG		0x07

/*
 * Shortcuts for sudo_user contents.
 */
#define user_name		(sudo_user.name)
#define user_uid		(sudo_user.uid)
#define user_gid		(sudo_user.gid)
#define user_sid		(sudo_user.sid)
#define user_umask		(sudo_user.umask)
#define user_passwd		(sudo_user.pw->pw_passwd)
#define user_dir		(sudo_user.pw->pw_dir)
#define user_gids		(sudo_user.gids)
#define user_ngids		(sudo_user.ngids)
#define user_gid_list		(sudo_user.gid_list)
#define user_tty		(sudo_user.tty)
#define user_ttypath		(sudo_user.ttypath)
#define user_cwd		(sudo_user.cwd)
#define user_cmnd		(sudo_user.cmnd)
#define user_args		(sudo_user.cmnd_args)
#define user_base		(sudo_user.cmnd_base)
#define user_stat		(sudo_user.cmnd_stat)
#define user_path		(sudo_user.path)
#define user_prompt		(sudo_user.prompt)
#define user_host		(sudo_user.host)
#define user_shost		(sudo_user.shost)
#define user_runhost		(sudo_user.runhost)
#define user_srunhost		(sudo_user.srunhost)
#define user_ccname		(sudo_user.krb5_ccname)
#define safe_cmnd		(sudo_user.cmnd_safe)
#define cmnd_fd			(sudo_user.execfd)
#define login_class		(sudo_user.class_name)
#define runas_pw		(sudo_user._runas_pw)
#define runas_gr		(sudo_user._runas_gr)
#define user_role		(sudo_user.role)
#define user_type		(sudo_user.type)
#define user_closefrom		(sudo_user.closefrom)
#define	runas_privs		(sudo_user.privs)
#define	runas_limitprivs	(sudo_user.limitprivs)
#define user_timeout		(sudo_user.timeout)

#ifdef __TANDEM
# define ROOT_UID	65535
#else
# define ROOT_UID	0
#endif
#define ROOT_GID	0

struct sudo_lbuf;
struct passwd;
struct stat;
struct timespec;

/*
 * Function prototypes
 */
#define YY_DECL int sudoerslex(void)

/* goodpath.c */
bool sudo_goodpath(const char *path, struct stat *sbp);

/* findpath.c */
int find_path(const char *infile, char **outfile, struct stat *sbp,
    const char *path, int ignore_dot, char * const *whitelist);

/* check.c */
int check_user(int validate, int mode);
bool user_is_exempt(void);

/* prompt.c */
char *expand_prompt(const char *old_prompt, const char *auth_user);

/* timestamp.c */
int timestamp_remove(bool unlinkit);

/* sudo_auth.c */
bool sudo_auth_needs_end_session(void);
int verify_user(struct passwd *pw, char *prompt, int validated, struct sudo_conv_callback *callback);
int sudo_auth_begin_session(struct passwd *pw, char **user_env[]);
int sudo_auth_end_session(struct passwd *pw);
int sudo_auth_init(struct passwd *pw);
int sudo_auth_approval(struct passwd *pw, int validated, bool exempt);
int sudo_auth_cleanup(struct passwd *pw);

/* set_perms.c */
bool rewind_perms(void);
bool set_perms(int);
bool restore_perms(void);
int pam_prep_user(struct passwd *);

/* gram.y */
int sudoersparse(void);
extern char *login_style;
extern char *errorfile;
extern int errorlineno;
extern bool parse_error;
extern bool sudoers_warnings;

/* toke.l */
YY_DECL;
extern FILE *sudoersin;
extern const char *sudoers_file;
extern char *sudoers;
extern mode_t sudoers_mode;
extern uid_t sudoers_uid;
extern gid_t sudoers_gid;
extern int sudolineno;
extern int last_token;

/* defaults.c */
void dump_defaults(void);
void dump_auth_methods(void);

/* getspwuid.c */
char *sudo_getepw(const struct passwd *);

/* pwutil.c */
typedef struct cache_item * (*sudo_make_pwitem_t)(uid_t uid, const char *user);
typedef struct cache_item * (*sudo_make_gritem_t)(gid_t gid, const char *group);
typedef struct cache_item * (*sudo_make_gidlist_item_t)(const struct passwd *pw, char * const *gids, unsigned int type);
typedef struct cache_item * (*sudo_make_grlist_item_t)(const struct passwd *pw, char * const *groups);
__dso_public struct group *sudo_getgrgid(gid_t);
__dso_public struct group *sudo_getgrnam(const char *);
__dso_public void sudo_gr_addref(struct group *);
__dso_public void sudo_gr_delref(struct group *);
bool user_in_group(const struct passwd *, const char *);
struct group *sudo_fakegrnam(const char *);
struct gid_list *sudo_get_gidlist(const struct passwd *pw, unsigned int type);
struct group_list *sudo_get_grlist(const struct passwd *pw);
struct passwd *sudo_fakepwnam(const char *, gid_t);
struct passwd *sudo_mkpwent(const char *user, uid_t uid, gid_t gid, const char *home, const char *shell);
struct passwd *sudo_getpwnam(const char *);
struct passwd *sudo_getpwuid(uid_t);
void sudo_endspent(void);
void sudo_freegrcache(void);
void sudo_freepwcache(void);
void sudo_gidlist_addref(struct gid_list *);
void sudo_gidlist_delref(struct gid_list *);
void sudo_grlist_addref(struct group_list *);
void sudo_grlist_delref(struct group_list *);
void sudo_pw_addref(struct passwd *);
void sudo_pw_delref(struct passwd *);
int  sudo_set_gidlist(struct passwd *pw, char * const *gids, unsigned int type);
int  sudo_set_grlist(struct passwd *pw, char * const *groups);
void sudo_pwutil_set_backend(sudo_make_pwitem_t, sudo_make_gritem_t, sudo_make_gidlist_item_t, sudo_make_grlist_item_t);
void sudo_setspent(void);

/* timestr.c */
char *get_timestr(time_t, int);

/* boottime.c */
bool get_boottime(struct timespec *);

/* iolog.c */
bool io_nextid(char *iolog_dir, char *iolog_dir_fallback, char sessid[7]);
bool cb_maxseq(const union sudo_defs_val *sd_un);
bool cb_iolog_user(const union sudo_defs_val *sd_un);
bool cb_iolog_group(const union sudo_defs_val *sd_un);
bool cb_iolog_mode(const union sudo_defs_val *sd_un);
extern uid_t iolog_uid;
extern gid_t iolog_gid;

/* iolog_path.c */
char *expand_iolog_path(const char *prefix, const char *dir, const char *file,
    char **slashp);

/* env.c */
char **env_get(void);
bool env_merge(char * const envp[]);
bool env_swap_old(void);
bool env_init(char * const envp[]);
bool init_envtables(void);
bool insert_env_vars(char * const envp[]);
bool read_env_file(const char *path, bool overwrite, bool restricted);
bool rebuild_env(void);
bool validate_env_vars(char * const envp[]);
int sudo_setenv(const char *var, const char *val, int overwrite);
int sudo_unsetenv(const char *var);
char *sudo_getenv(const char *name);
int sudoers_hook_getenv(const char *name, char **value, void *closure);
int sudoers_hook_putenv(char *string, void *closure);
int sudoers_hook_setenv(const char *name, const char *value, int overwrite, void *closure);
int sudoers_hook_unsetenv(const char *name, void *closure);

/* env_pattern.c */
bool matches_env_pattern(const char *pattern, const char *var, bool *full_match);

/* sudoers.c */
FILE *open_sudoers(const char *, bool, bool *);
int sudoers_policy_init(void *info, char * const envp[]);
int sudoers_policy_main(int argc, char * const argv[], int pwflag, char *env_add[], bool verbose, void *closure);
void sudoers_cleanup(void);
extern struct sudo_user sudo_user;
extern struct passwd *list_pw;
extern int sudo_mode;
extern uid_t timestamp_uid;
extern gid_t timestamp_gid;
extern sudo_conv_t sudo_conv;
extern sudo_printf_t sudo_printf;

/* sudoers_debug.c */
bool sudoers_debug_parse_flags(struct sudo_conf_debug_file_list *debug_files, const char *entry);
bool sudoers_debug_register(const char *plugin_path, struct sudo_conf_debug_file_list *debug_files);
void sudoers_debug_deregister(void);

/* policy.c */
int sudoers_policy_deserialize_info(void *v, char **runas_user, char **runas_group);
int sudoers_policy_exec_setup(char *argv[], char *envp[], mode_t cmnd_umask, char *iolog_path, void *v);
extern const char *path_ldap_conf;
extern const char *path_ldap_secret;

/* group_plugin.c */
int group_plugin_load(char *plugin_info);
void group_plugin_unload(void);
int group_plugin_query(const char *user, const char *group,
    const struct passwd *pwd);
bool cb_group_plugin(const union sudo_defs_val *sd_un);
extern const char *path_plugin_dir;

/* editor.c */
char *find_editor(int nfiles, char **files, int *argc_out, char ***argv_out,
     char * const *whitelist, const char **env_editor, bool env_error);

/* mkdir_parents.c */
bool sudo_mkdir_parents(char *path, uid_t uid, gid_t gid, mode_t mode, bool quiet);

/* gc.c */
enum sudoers_gc_types {
    GC_UNKNOWN,
    GC_VECTOR,
    GC_PTR
};
bool sudoers_gc_add(enum sudoers_gc_types type, void *ptr);
bool sudoers_gc_remove(enum sudoers_gc_types type, void *ptr);
void sudoers_gc_init(void);

/* rcstr.c */
char *rcstr_dup(const char *src);
char *rcstr_alloc(size_t len);
char *rcstr_addref(const char *s);
void rcstr_delref(const char *s);

#endif /* SUDOERS_SUDOERS_H */
