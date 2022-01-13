/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1996, 1998-2000, 2004, 2007-2018
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
 */

#ifndef SUDOERS_PARSE_H
#define SUDOERS_PARSE_H

#include "sudo_queue.h"

/* Characters that must be quoted in sudoers. */
#define SUDOERS_QUOTED	":\\,=#\""

/* Returns true if string 's' contains meta characters. */
#define has_meta(s)	(strpbrk(s, "\\?*[]") != NULL)

#undef UNSPEC
#define UNSPEC	-1
#undef DENY
#define DENY	 0
#undef ALLOW
#define ALLOW	 1
#undef IMPLIED
#define IMPLIED	 2

/*
 * Initialize all tags to UNSPEC.
 */
#define TAGS_INIT(t)	do {						       \
    (t).follow = UNSPEC;						       \
    (t).log_input = UNSPEC;						       \
    (t).log_output = UNSPEC;						       \
    (t).noexec = UNSPEC;						       \
    (t).nopasswd = UNSPEC;						       \
    (t).send_mail = UNSPEC;						       \
    (t).setenv = UNSPEC;						       \
} while (0)

/*
 * Copy any tags set in t2 into t, overriding the value in t.
 */
#define TAGS_MERGE(t, t2) do {						       \
    if ((t2).follow != UNSPEC)						       \
	(t).follow = (t2).follow;					       \
    if ((t2).log_input != UNSPEC)					       \
	(t).log_input = (t2).log_input;					       \
    if ((t2).log_output != UNSPEC)					       \
	(t).log_output = (t2).log_output;				       \
    if ((t2).noexec != UNSPEC)						       \
	(t).noexec = (t2).noexec;					       \
    if ((t2).nopasswd != UNSPEC)					       \
	(t).nopasswd = (t2).nopasswd;					       \
    if ((t2).send_mail != UNSPEC)					       \
	(t).send_mail = (t2).send_mail;					       \
    if ((t2).setenv != UNSPEC)						       \
	(t).setenv = (t2).setenv;					       \
} while (0)

/*
 * Returns true if any tag are not UNSPEC, else false.
 */
#define TAGS_SET(t)							       \
    ((t).follow != UNSPEC || (t).log_input != UNSPEC ||			       \
     (t).log_output != UNSPEC || (t).noexec != UNSPEC ||		       \
     (t).nopasswd != UNSPEC || (t).send_mail != UNSPEC ||		       \
     (t).setenv != UNSPEC)

/*
 * Returns true if the specified tag is not UNSPEC or IMPLIED, else false.
 */
#define TAG_SET(tt) \
    ((tt) != UNSPEC && (tt) != IMPLIED)

/*
 * Returns true if any tags set in nt differ between ot and nt, else false.
 */
#define TAGS_CHANGED(ot, nt) \
    ((TAG_SET((nt).follow) && (nt).follow != (ot).follow) || \
    (TAG_SET((nt).log_input) && (nt).log_input != (ot).log_input) || \
    (TAG_SET((nt).log_output) && (nt).log_output != (ot).log_output) || \
    (TAG_SET((nt).noexec) && (nt).noexec != (ot).noexec) || \
    (TAG_SET((nt).nopasswd) && (nt).nopasswd != (ot).nopasswd) || \
    (TAG_SET((nt).setenv) && (nt).setenv != (ot).setenv) || \
    (TAG_SET((nt).send_mail) && (nt).send_mail != (ot).send_mail))

/*
 * Returns true if the runas user and group lists match, else false.
 */
#define RUNAS_CHANGED(cs1, cs2) \
     ((cs1)->runasuserlist != (cs2)->runasuserlist || \
     (cs1)->runasgrouplist != (cs2)->runasgrouplist)

struct command_digest {
    unsigned int digest_type;
    char *digest_str;
};

/*
 * A command with option args and digest.
 * XXX - merge into struct member
 */
struct sudo_command {
    char *cmnd;
    char *args;
    struct command_digest *digest;
};

/*
 * Tags associated with a command.
 * Possible values: true, false, IMPLIED, UNSPEC.
 */
struct cmndtag {
    signed int nopasswd: 3;
    signed int noexec: 3;
    signed int setenv: 3;
    signed int log_input: 3;
    signed int log_output: 3;
    signed int send_mail: 3;
    signed int follow: 3;
};

/*
 * Per-command option container struct.
 */
struct command_options {
    time_t notbefore;			/* time restriction */
    time_t notafter;			/* time restriction */
    int timeout;			/* command timeout */
#ifdef HAVE_SELINUX
    char *role, *type;			/* SELinux role and type */
#endif
#ifdef HAVE_PRIV_SET
    char *privs, *limitprivs;		/* Solaris privilege sets */
#endif
};

/*
 * The parsed sudoers file is stored as a collection of linked lists,
 * modelled after the yacc grammar.
 *
 * Other than the alias struct, which is stored in a red-black tree,
 * the data structure used is a doubly-linked tail queue.  While sudoers
 * is being parsed, a headless tail queue is used where the first entry
 * acts as the head and the prev pointer does double duty as the tail pointer.
 * This makes it possible to trivally append sub-lists.  In addition, the prev
 * pointer is always valid (even if it points to itself).  Unlike a circle
 * queue, the next pointer of the last entry is NULL and does not point back
 * to the head.  When the tail queue is finalized, it is converted to a
 * normal BSD tail queue.
 */

/*
 * Tail queue list head structure.
 */
TAILQ_HEAD(defaults_list, defaults);
TAILQ_HEAD(userspec_list, userspec);
TAILQ_HEAD(member_list, member);
TAILQ_HEAD(privilege_list, privilege);
TAILQ_HEAD(cmndspec_list, cmndspec);
STAILQ_HEAD(comment_list, sudoers_comment);

/*
 * Structure describing a user specification and list thereof.
 */
struct userspec {
    TAILQ_ENTRY(userspec) entries;
    struct member_list users;		/* list of users */
    struct privilege_list privileges;	/* list of privileges */
    struct comment_list comments;	/* optional comments */
    int lineno;				/* line number in sudoers */
    char *file;				/* name of sudoers file */
};

/*
 * Structure describing a privilege specification.
 */
struct privilege {
    TAILQ_ENTRY(privilege) entries;
    char *ldap_role;			/* LDAP sudoRole */
    struct member_list hostlist;	/* list of hosts */
    struct cmndspec_list cmndlist;	/* list of Cmnd_Specs */
    struct defaults_list defaults;	/* list of sudoOptions */
};

/*
 * Structure describing a linked list of Cmnd_Specs.
 * XXX - include struct command_options instad of its contents inline
 */
struct cmndspec {
    TAILQ_ENTRY(cmndspec) entries;
    struct member_list *runasuserlist;	/* list of runas users */
    struct member_list *runasgrouplist;	/* list of runas groups */
    struct member *cmnd;		/* command to allow/deny */
    struct cmndtag tags;		/* tag specificaion */
    int timeout;			/* command timeout */
    time_t notbefore;			/* time restriction */
    time_t notafter;			/* time restriction */
#ifdef HAVE_SELINUX
    char *role, *type;			/* SELinux role and type */
#endif
#ifdef HAVE_PRIV_SET
    char *privs, *limitprivs;		/* Solaris privilege sets */
#endif
};

/*
 * Generic structure to hold users, hosts, commands.
 */
struct member {
    TAILQ_ENTRY(member) entries;
    char *name;				/* member name */
    short type;				/* type (see gram.h) */
    short negated;			/* negated via '!'? */
};

struct runascontainer {
    struct member *runasusers;
    struct member *runasgroups;
};

struct sudoers_comment {
    STAILQ_ENTRY(sudoers_comment) entries;
    char *str;
};

/*
 * Generic structure to hold {User,Host,Runas,Cmnd}_Alias
 * Aliases are stored in a red-black tree, sorted by name and type.
 */
struct alias {
    char *name;				/* alias name */
    unsigned short type;		/* {USER,HOST,RUNAS,CMND}ALIAS */
    short used;				/* "used" flag for cycle detection */
    int lineno;				/* line number of alias entry */
    char *file;				/* file the alias entry was in */
    struct member_list members;		/* list of alias members */
};

/*
 * Structure describing a Defaults entry in sudoers.
 */
struct defaults {
    TAILQ_ENTRY(defaults) entries;
    char *var;				/* variable name */
    char *val;				/* variable value */
    struct member_list *binding;	/* user/host/runas binding */
    char *file;				/* file Defaults entry was in */
    short type;				/* DEFAULTS{,_USER,_RUNAS,_HOST} */
    char op;				/* true, false, '+', '-' */
    char error;				/* parse error flag */
    int lineno;				/* line number of Defaults entry */
};

/*
 * Parsed sudoers policy.
 */
struct sudoers_parse_tree {
    struct userspec_list userspecs;
    struct defaults_list defaults;
    struct rbtree *aliases;
    const char *shost, *lhost;
};

/* alias.c */
struct rbtree *alloc_aliases(void);
void free_aliases(struct rbtree *aliases);
bool no_aliases(struct sudoers_parse_tree *parse_tree);
const char *alias_add(struct sudoers_parse_tree *parse_tree, char *name, int type, char *file, int lineno, struct member *members);
const char *alias_type_to_string(int alias_type);
struct alias *alias_get(struct sudoers_parse_tree *parse_tree, const char *name, int type);
struct alias *alias_remove(struct sudoers_parse_tree *parse_tree, char *name, int type);
bool alias_find_used(struct sudoers_parse_tree *parse_tree, struct rbtree *used_aliases);
void alias_apply(struct sudoers_parse_tree *parse_tree, int (*func)(struct sudoers_parse_tree *, struct alias *, void *), void *cookie);
void alias_free(void *a);
void alias_put(struct alias *a);

/* gram.c */
extern struct sudoers_parse_tree parsed_policy;
bool init_parser(const char *path, bool quiet, bool strict);
void free_member(struct member *m);
void free_members(struct member_list *members);
void free_privilege(struct privilege *priv);
void free_userspec(struct userspec *us);
void free_userspecs(struct userspec_list *usl);
void free_default(struct defaults *def, struct member_list **binding);
void free_defaults(struct defaults_list *defs);
void init_parse_tree(struct sudoers_parse_tree *parse_tree, const char *shost, const char *lhost);
void free_parse_tree(struct sudoers_parse_tree *parse_tree);
void reparent_parse_tree(struct sudoers_parse_tree *new_tree);

/* match_addr.c */
bool addr_matches(char *n);

/* match_command.c */
bool command_matches(const char *sudoers_cmnd, const char *sudoers_args, const struct command_digest *digest);

/* match_digest.c */
bool digest_matches(int fd, const char *file, const struct command_digest *digest);

/* match.c */
struct group;
struct passwd;
bool group_matches(const char *sudoers_group, const struct group *gr);
bool hostname_matches(const char *shost, const char *lhost, const char *pattern);
bool netgr_matches(const char *netgr, const char *lhost, const char *shost, const char *user);
bool usergr_matches(const char *group, const char *user, const struct passwd *pw);
bool userpw_matches(const char *sudoers_user, const char *user, const struct passwd *pw);
int cmnd_matches(struct sudoers_parse_tree *parse_tree, const struct member *m);
int cmndlist_matches(struct sudoers_parse_tree *parse_tree, const struct member_list *list);
int host_matches(struct sudoers_parse_tree *parse_tree, const struct passwd *pw, const char *host, const char *shost, const struct member *m);
int hostlist_matches(struct sudoers_parse_tree *parse_tree, const struct passwd *pw, const struct member_list *list);
int runaslist_matches(struct sudoers_parse_tree *parse_tree, const struct member_list *user_list, const struct member_list *group_list, struct member **matching_user, struct member **matching_group);
int user_matches(struct sudoers_parse_tree *parse_tree, const struct passwd *pw, const struct member *m);
int userlist_matches(struct sudoers_parse_tree *parse_tree, const struct passwd *pw, const struct member_list *list);
const char *sudo_getdomainname(void);
struct gid_list *runas_getgroups(void);

/* toke.c */
void init_lexer(void);

/* hexchar.c */
int hexchar(const char *s);

/* base64.c */
size_t base64_decode(const char *str, unsigned char *dst, size_t dsize);
size_t base64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_len);

/* timeout.c */
int parse_timeout(const char *timestr);

/* gmtoff.c */
long get_gmtoff(time_t *clock);

/* gentime.c */
time_t parse_gentime(const char *expstr);

/* filedigest.c */
unsigned char *sudo_filedigest(int fd, const char *file, int digest_type, size_t *digest_len);

/* digestname.c */
const char *digest_type_to_name(int digest_type);

/* parse.c */
struct sudo_nss_list;
int sudoers_lookup(struct sudo_nss_list *snl, struct passwd *pw, int validated, int pwflag);
int display_privs(struct sudo_nss_list *snl, struct passwd *pw, bool verbose);
int display_cmnd(struct sudo_nss_list *snl, struct passwd *pw);

/* parse_ldif.c */
bool sudoers_parse_ldif(struct sudoers_parse_tree *parse_tree, FILE *fp, const char *sudoers_base, bool store_options);

/* fmtsudoers.c */
struct sudo_lbuf;
bool sudoers_format_cmndspec(struct sudo_lbuf *lbuf, struct sudoers_parse_tree *parse_tree, struct cmndspec *cs, struct cmndspec *prev_cs, struct cmndtag tags, bool expand_aliases);
bool sudoers_format_default(struct sudo_lbuf *lbuf, struct defaults *d);
bool sudoers_format_default_line(struct sudo_lbuf *lbuf, struct sudoers_parse_tree *parse_tree, struct defaults *d, struct defaults **next, bool expand_aliases);
bool sudoers_format_member(struct sudo_lbuf *lbuf, struct sudoers_parse_tree *parse_tree, struct member *m, const char *separator, int alias_type);
bool sudoers_format_privilege(struct sudo_lbuf *lbuf, struct sudoers_parse_tree *parse_tree, struct privilege *priv, bool expand_aliases);
bool sudoers_format_userspec(struct sudo_lbuf *lbuf, struct sudoers_parse_tree *parse_tree, struct userspec *us, bool expand_aliases);
bool sudoers_format_userspecs(struct sudo_lbuf *lbuf, struct sudoers_parse_tree *parse_tree, const char *separator, bool expand_aliases, bool flush);
bool sudoers_defaults_to_tags(const char *var, const char *val, int op, struct cmndtag *tags);
bool sudoers_defaults_list_to_tags(struct defaults_list *defs, struct cmndtag *tags);

#endif /* SUDOERS_PARSE_H */
