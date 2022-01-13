/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2003-2018 Todd C. Miller <Todd.Miller@sudo.ws>
 * Copyright (c) 2011 Daniel Kopecek <dkopecek@redhat.com>
 *
 * This code is derived from software contributed by Aaron Spangler.
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

#ifdef HAVE_SSSD

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
#include <time.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>

#include <errno.h>
#include <stdint.h>

#include "sudoers.h"
#include "gram.h"
#include "sudo_lbuf.h"
#include "sudo_ldap.h"
#include "sudo_dso.h"

/* SSSD <--> SUDO interface - do not change */
struct sss_sudo_attr {
    char *name;
    char **values;
    unsigned int num_values;
};

struct sss_sudo_rule {
    unsigned int num_attrs;
    struct sss_sudo_attr *attrs;
};

struct sss_sudo_result {
    unsigned int num_rules;
    struct sss_sudo_rule *rules;
};

typedef int  (*sss_sudo_send_recv_t)(uid_t, const char*, const char*,
                                     uint32_t*, struct sss_sudo_result**);

typedef int  (*sss_sudo_send_recv_defaults_t)(uid_t, const char*, uint32_t*,
                                              char**, struct sss_sudo_result**);

typedef void (*sss_sudo_free_result_t)(struct sss_sudo_result*);

typedef int  (*sss_sudo_get_values_t)(struct sss_sudo_rule*, const char*,
                                      char***);

typedef void (*sss_sudo_free_values_t)(char**);

/* sudo_nss handle */
struct sudo_sss_handle {
    char *domainname;
    char *ipa_host;
    char *ipa_shost;
    struct passwd *pw;
    void *ssslib;
    struct sudoers_parse_tree parse_tree;
    sss_sudo_send_recv_t fn_send_recv;
    sss_sudo_send_recv_defaults_t fn_send_recv_defaults;
    sss_sudo_free_result_t fn_free_result;
    sss_sudo_get_values_t fn_get_values;
    sss_sudo_free_values_t fn_free_values;
};

static int
get_ipa_hostname(char **shostp, char **lhostp)
{
    size_t linesize = 0;
    char *lhost = NULL;
    char *shost = NULL;
    char *line = NULL;
    int ret = false;
    ssize_t len;
    FILE *fp;
    debug_decl(get_ipa_hostname, SUDOERS_DEBUG_SSSD)

    fp = fopen(_PATH_SSSD_CONF, "r");
    if (fp != NULL) {
	while ((len = getdelim(&line, &linesize, '\n', fp)) != -1) {
	    char *cp = line;

	    /* Trim trailing and leading spaces. */
	    while (len > 0 && isspace((unsigned char)line[len - 1]))
		line[--len] = '\0';
	    while (isspace((unsigned char)*cp))
		cp++;

	    /*
	     * Match ipa_hostname = foo
	     * Note: currently ignores the domain (XXX)
	     */
	    if (strncmp(cp, "ipa_hostname", 12) == 0) {
		cp += 12;
		/* Trim " = " after "ipa_hostname" */
		while (isblank((unsigned char)*cp))
		    cp++;
		if (*cp++ != '=')
		    continue;
		while (isblank((unsigned char)*cp))
		    cp++;
		/* Ignore empty value */
		if (*cp == '\0')
		    continue;
		lhost = strdup(cp);
		if (lhost != NULL && (cp = strchr(lhost, '.')) != NULL) {
		    shost = strndup(lhost, (size_t)(cp - lhost));
		} else {
		    shost = lhost;
		}
		if (shost != NULL && lhost != NULL) {
		    sudo_debug_printf(SUDO_DEBUG_INFO,
			"ipa_hostname %s overrides %s", lhost, user_host);
		    *shostp = shost;
		    *lhostp = lhost;
		    ret = true;
		} else {
		    sudo_warnx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		    free(shost);
		    free(lhost);
		    ret = -1;
		}
		break;
	    }
	}
	fclose(fp);
	free(line);
    }
    debug_return_int(ret);
}

/*
 * SSSD doesn't handle netgroups, we have to ensure they are correctly filtered
 * in sudo. The rules may contain mixed sudoUser specification so we have to
 * check not only for netgroup membership but also for user and group matches.
 * Otherwise, a netgroup non-match could override a user/group match.
 */
static bool
sudo_sss_check_user(struct sudo_sss_handle *handle, struct sss_sudo_rule *rule)
{
    const char *host = handle->ipa_host ? handle->ipa_host : user_runhost;
    const char *shost = handle->ipa_shost ? handle->ipa_shost : user_srunhost;
    char **val_array;
    int i, ret = false;
    debug_decl(sudo_sss_check_user, SUDOERS_DEBUG_SSSD);

    if (rule == NULL)
	debug_return_bool(false);

    switch (handle->fn_get_values(rule, "sudoUser", &val_array)) {
    case 0:
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	debug_return_bool(false);
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "handle->fn_get_values(sudoUser): != 0");
	debug_return_bool(false);
    }

    /* Walk through sudoUser values.  */
    for (i = 0; val_array[i] != NULL && !ret; ++i) {
	const char *val = val_array[i];

	sudo_debug_printf(SUDO_DEBUG_DEBUG, "val[%d]=%s", i, val);
	switch (*val) {
	case '+':
	    /* Netgroup spec found, check membership. */
	    if (netgr_matches(val, def_netgroup_tuple ? host : NULL,
		def_netgroup_tuple ? shost : NULL, handle->pw->pw_name)) {
		ret = true;
	    }
	    break;
	case '%':
	    /* User group found, check membership. */
	    if (usergr_matches(val, handle->pw->pw_name, handle->pw)) {
		ret = true;
	    }
	    break;
	default:
	    /* Not a netgroup or user group. */
	    if (strcmp(val, "ALL") == 0 ||
		userpw_matches(val, handle->pw->pw_name, handle->pw)) {
		ret = true;
	    }
	    break;
	}
	sudo_debug_printf(SUDO_DEBUG_DIAG,
	    "sssd/ldap sudoUser '%s' ... %s (%s)", val,
	    ret ? "MATCH!" : "not", handle->pw->pw_name);
    }
    handle->fn_free_values(val_array);
    debug_return_bool(ret);
}

static char *
val_array_iter(void **vp)
{
    char **val_array = *vp;

    *vp = val_array + 1;

    return *val_array;
}

static bool
sss_to_sudoers(struct sudo_sss_handle *handle,
    struct sss_sudo_result *sss_result)
{
    struct userspec *us;
    struct member *m;
    unsigned int i;
    debug_decl(sss_to_sudoers, SUDOERS_DEBUG_SSSD)

    /* We only have a single userspec */
    if ((us = calloc(1, sizeof(*us))) == NULL)
	goto oom;
    TAILQ_INIT(&us->users);
    TAILQ_INIT(&us->privileges);
    STAILQ_INIT(&us->comments);
    TAILQ_INSERT_TAIL(&handle->parse_tree.userspecs, us, entries);

    /* We only include rules where the user matches. */
    if ((m = calloc(1, sizeof(*m))) == NULL)
	goto oom;
    m->type = ALL;
    TAILQ_INSERT_TAIL(&us->users, m, entries);

    /*
     * Treat each sudoRole as a separate privilege.
     *
     * Sssd has already sorted the rules in descending order.
     * The conversion to a sudoers parse tree requires that entries be
     * in *ascending* order so we we iterate from last to first.
     */
    for (i = sss_result->num_rules; i-- > 0; ) {
	struct sss_sudo_rule *rule = sss_result->rules + i;
	char **cmnds, **runasusers = NULL, **runasgroups = NULL;
	char **opts = NULL, **notbefore = NULL, **notafter = NULL;
	char **hosts = NULL, **cn_array = NULL, *cn = NULL;
	struct privilege *priv = NULL;

	/*
	 * We don't know whether a rule was included due to a user/group
	 * match or because it contained a netgroup.
	 */
	if (!sudo_sss_check_user(handle, rule))
	    continue;

	switch (handle->fn_get_values(rule, "sudoCommand", &cmnds)) {
	case 0:
	    break;
	case ENOENT:
	    /* Ignore sudoRole without sudoCommand. */
	    continue;
	default:
	    goto cleanup;
	}

	/* Get the entry's dn for long format printing. */
	switch (handle->fn_get_values(rule, "cn", &cn_array)) {
	case 0:
	    cn = cn_array[0];
	    break;
	case ENOENT:
	    break;
	default:
	    goto cleanup;
	}

	/* Get sudoHost */
	switch (handle->fn_get_values(rule, "sudoHost", &hosts)) {
	case 0:
	case ENOENT:
	    break;
	default:
	    goto cleanup;
	}

	/* Get sudoRunAsUser / sudoRunAs */
	switch (handle->fn_get_values(rule, "sudoRunAsUser", &runasusers)) {
	case 0:
	    break;
	case ENOENT:
	    switch (handle->fn_get_values(rule, "sudoRunAs", &runasusers)) {
		case 0:
		case ENOENT:
		    break;
		default:
		    goto cleanup;
	    }
	    break;
	default:
	    goto cleanup;
	}

	/* Get sudoRunAsGroup */
	switch (handle->fn_get_values(rule, "sudoRunAsGroup", &runasgroups)) {
	case 0:
	case ENOENT:
	    break;
	default:
	    goto cleanup;
	}

	/* Get sudoNotBefore */
	switch (handle->fn_get_values(rule, "sudoNotBefore", &notbefore)) {
	case 0:
	case ENOENT:
	    break;
	default:
	    goto cleanup;
	}

	/* Get sudoNotAfter */
	switch (handle->fn_get_values(rule, "sudoNotAfter", &notafter)) {
	case 0:
	case ENOENT:
	    break;
	default:
	    goto cleanup;
	}

	/* Parse sudoOptions. */
	switch (handle->fn_get_values(rule, "sudoOption", &opts)) {
	case 0:
	case ENOENT:
	    break;
	default:
	    goto cleanup;
	}

	priv = sudo_ldap_role_to_priv(cn, hosts, runasusers, runasgroups,
	    cmnds, opts, notbefore ? notbefore[0] : NULL,
	    notafter ? notafter[0] : NULL, false, true, val_array_iter);

    cleanup:
	if (cn_array != NULL)
	    handle->fn_free_values(cn_array);
	if (cmnds != NULL)
	    handle->fn_free_values(cmnds);
	if (hosts != NULL)
	    handle->fn_free_values(hosts);
	if (runasusers != NULL)
	    handle->fn_free_values(runasusers);
	if (runasgroups != NULL)
	    handle->fn_free_values(runasgroups);
	if (opts != NULL)
	    handle->fn_free_values(opts);
	if (notbefore != NULL)
	    handle->fn_free_values(notbefore);
	if (notafter != NULL)
	    handle->fn_free_values(notafter);

	if (priv == NULL)
	    goto oom;
	TAILQ_INSERT_TAIL(&us->privileges, priv, entries);
    }

    debug_return_bool(true);

oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    free_userspecs(&handle->parse_tree.userspecs);
    debug_return_bool(false);
}

static bool
sudo_sss_parse_options(struct sudo_sss_handle *handle, struct sss_sudo_rule *rule, struct defaults_list *defs)
{
    int i;
    char *source = NULL;
    bool ret = false;
    char **val_array = NULL;
    char **cn_array = NULL;
    debug_decl(sudo_sss_parse_options, SUDOERS_DEBUG_SSSD);

    if (rule == NULL)
	debug_return_bool(true);

    switch (handle->fn_get_values(rule, "sudoOption", &val_array)) {
    case 0:
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	debug_return_bool(true);
    case ENOMEM:
	goto oom;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR, "handle->fn_get_values(sudoOption): != 0");
	debug_return_bool(false);
    }

    /* Use sudoRole in place of file name in defaults. */
    if (handle->fn_get_values(rule, "cn", &cn_array) == 0) {
	if (cn_array[0] != NULL) {
	    char *cp;
	    if (asprintf(&cp, "sudoRole %s", cn_array[0]) == -1)
		goto oom;
	    source = rcstr_dup(cp);
	    free(cp);
	    if (source == NULL)
		goto oom;
	}
	handle->fn_free_values(cn_array);
	cn_array = NULL;
    }
    if (source == NULL) {
	if ((source = rcstr_dup("sudoRole UNKNOWN")) == NULL)
	    goto oom;
    }

    /* Walk through options, appending to defs. */
    for (i = 0; val_array[i] != NULL; i++) {
	char *var, *val;
	int op;

	op = sudo_ldap_parse_option(val_array[i], &var, &val);
	if (!sudo_ldap_add_default(var, val, op, source, defs))
	    goto oom;
    }
    ret = true;
    goto done;

oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

done:
    rcstr_delref(source);
    handle->fn_free_values(val_array);
    debug_return_bool(ret);
}

static struct sss_sudo_result *
sudo_sss_result_get(struct sudo_nss *nss, struct passwd *pw)
{
    struct sudo_sss_handle *handle = nss->handle;
    struct sss_sudo_result *sss_result = NULL;
    uint32_t sss_error = 0, rc;
    debug_decl(sudo_sss_result_get, SUDOERS_DEBUG_SSSD);

    sudo_debug_printf(SUDO_DEBUG_DIAG, "  username=%s", pw->pw_name);
    sudo_debug_printf(SUDO_DEBUG_DIAG, "domainname=%s",
	handle->domainname ? handle->domainname : "NULL");

    rc = handle->fn_send_recv(pw->pw_uid, pw->pw_name,
	handle->domainname, &sss_error, &sss_result);
    switch (rc) {
    case 0:
	switch (sss_error) {
	case 0:
	    if (sss_result != NULL) {
		sudo_debug_printf(SUDO_DEBUG_INFO, "Received %u rule(s)",
		    sss_result->num_rules);
	    } else {
		sudo_debug_printf(SUDO_DEBUG_ERROR,
		    "Internal error: sss_result == NULL && sss_error == 0");
		debug_return_ptr(NULL);
	    }
	    break;
	case ENOENT:
	    sudo_debug_printf(SUDO_DEBUG_INFO, "The user was not found in SSSD.");
	    debug_return_ptr(NULL);
	default:
	    sudo_debug_printf(SUDO_DEBUG_ERROR, "sss_error=%u\n", sss_error);
	    debug_return_ptr(NULL);
	}
	break;
    case ENOMEM:
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	/* FALLTHROUGH */
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR, "handle->fn_send_recv: rc=%d", rc);
	debug_return_ptr(NULL);
    }

    debug_return_ptr(sss_result);
}

/* sudo_nss implementation */
static int
sudo_sss_close(struct sudo_nss *nss)
{
    struct sudo_sss_handle *handle = nss->handle;
    debug_decl(sudo_sss_close, SUDOERS_DEBUG_SSSD);

    if (handle != NULL) {
	sudo_dso_unload(handle->ssslib);
	if (handle->pw != NULL)
	    sudo_pw_delref(handle->pw);
	free(handle->ipa_host);
	if (handle->ipa_host != handle->ipa_shost)
	    free(handle->ipa_shost);
	free_parse_tree(&handle->parse_tree);
	free(handle);
	nss->handle = NULL;
    }
    debug_return_int(0);
}

static int
sudo_sss_open(struct sudo_nss *nss)
{
    struct sudo_sss_handle *handle;
    static const char path[] = _PATH_SSSD_LIB"/libsss_sudo.so";
    debug_decl(sudo_sss_open, SUDOERS_DEBUG_SSSD);

    if (nss->handle != NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "%s: called with non-NULL handle %p", __func__, nss->handle);
	sudo_sss_close(nss);
    }

    /* Create a handle container. */
    handle = calloc(1, sizeof(struct sudo_sss_handle));
    if (handle == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(ENOMEM);
    }

    /* Load symbols */
    handle->ssslib = sudo_dso_load(path, SUDO_DSO_LAZY);
    if (handle->ssslib == NULL) {
	const char *errstr = sudo_dso_strerror();
	sudo_warnx(U_("unable to load %s: %s"), path,
	    errstr ? errstr : "unknown error");
	sudo_warnx(U_("unable to initialize SSS source. Is SSSD installed on your machine?"));
	free(handle);
	debug_return_int(EFAULT);
    }

    handle->fn_send_recv =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_send_recv");
    if (handle->fn_send_recv == NULL) {
	sudo_warnx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_send_recv");
	free(handle);
	debug_return_int(EFAULT);
    }

    handle->fn_send_recv_defaults =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_send_recv_defaults");
    if (handle->fn_send_recv_defaults == NULL) {
	sudo_warnx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_send_recv_defaults");
	free(handle);
	debug_return_int(EFAULT);
    }

    handle->fn_free_result =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_free_result");
    if (handle->fn_free_result == NULL) {
	sudo_warnx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_free_result");
	free(handle);
	debug_return_int(EFAULT);
    }

    handle->fn_get_values =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_get_values");
    if (handle->fn_get_values == NULL) {
	sudo_warnx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_get_values");
	free(handle);
	debug_return_int(EFAULT);
    }

    handle->fn_free_values =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_free_values");
    if (handle->fn_free_values == NULL) {
	sudo_warnx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_free_values");
	free(handle);
	debug_return_int(EFAULT);
    }

    /*
     * If runhost is the same as the local host, check for ipa_hostname
     * in sssd.conf and use it in preference to user_runhost.
     */
    if (strcasecmp(user_runhost, user_host) == 0) {
	if (get_ipa_hostname(&handle->ipa_shost, &handle->ipa_host) == -1) {
	    free(handle);
	    debug_return_int(ENOMEM);
	}
    }

    /* The "parse tree" contains userspecs, defaults, aliases and hostnames. */
    init_parse_tree(&handle->parse_tree, handle->ipa_host, handle->ipa_shost);
    nss->handle = handle;

    sudo_debug_printf(SUDO_DEBUG_DEBUG, "handle=%p", handle);

    debug_return_int(0);
}

/*
 * Perform query for user and host and convert to sudoers parse tree.
 */
static int
sudo_sss_query(struct sudo_nss *nss, struct passwd *pw)
{
    struct sudo_sss_handle *handle = nss->handle;
    struct sss_sudo_result *sss_result = NULL;
    int ret = 0;
    debug_decl(sudo_sss_query, SUDOERS_DEBUG_SSSD);

    if (handle == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "%s: called with NULL handle", __func__);
	debug_return_int(-1);
    }

    /* Use cached result if it matches pw. */
    if (handle->pw != NULL) {
	if (pw == handle->pw)
	    goto done;
	sudo_pw_delref(handle->pw);
	handle->pw = NULL;
    }

    /* Free old userspecs, if any. */
    free_userspecs(&handle->parse_tree.userspecs);

    /* Fetch list of sudoRole entries that match user and host. */
    sss_result = sudo_sss_result_get(nss, pw);

    sudo_debug_printf(SUDO_DEBUG_DIAG,
	"searching SSSD/LDAP for sudoers entries for user %s, host %s",
	 pw->pw_name, user_runhost);

    /* Stash a ref to the passwd struct in the handle. */
    sudo_pw_addref(pw);
    handle->pw = pw;

    /* Convert to sudoers parse tree if the user was found. */
    if (sss_result != NULL) {
	if (!sss_to_sudoers(handle, sss_result)) {
	    ret = -1;
	    goto done;
	}
    }

done:
    /* Cleanup */
    handle->fn_free_result(sss_result);
    if (ret == -1) {
	free_userspecs(&handle->parse_tree.userspecs);
	if (handle->pw != NULL) {
	    sudo_pw_delref(handle->pw);
	    handle->pw = NULL;
	}
    }

    sudo_debug_printf(SUDO_DEBUG_DIAG, "Done with LDAP searches");

    debug_return_int(ret);
}

/*
 * Return the initialized (but empty) sudoers parse tree.
 * The contents will be populated by the getdefs() and query() functions.
 */
static struct sudoers_parse_tree *
sudo_sss_parse(struct sudo_nss *nss)
{
    struct sudo_sss_handle *handle = nss->handle;
    debug_decl(sudo_sss_parse, SUDOERS_DEBUG_SSSD);

    if (handle == NULL) {
    	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "%s: called with NULL handle", __func__);
	debug_return_ptr(NULL);
    }

    debug_return_ptr(&handle->parse_tree);
}

static int
sudo_sss_getdefs(struct sudo_nss *nss)
{
    struct sudo_sss_handle *handle = nss->handle;
    struct sss_sudo_result *sss_result = NULL;
    static bool cached;
    uint32_t sss_error;
    unsigned int i;
    int rc;
    debug_decl(sudo_sss_getdefs, SUDOERS_DEBUG_SSSD);

    if (handle == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "%s: called with NULL handle", __func__);
	debug_return_int(-1);
    }

    /* Use cached result if present. */
    if (cached)
	debug_return_int(0);

    sudo_debug_printf(SUDO_DEBUG_DIAG, "Looking for cn=defaults");

    /* NOTE: these are global defaults, user-ID and name are not used. */
    rc = handle->fn_send_recv_defaults(sudo_user.pw->pw_uid,
	sudo_user.pw->pw_name, &sss_error, &handle->domainname, &sss_result);
    switch (rc) {
    case 0:
	break;
    case ENOMEM:
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	/* FALLTHROUGH */
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "handle->fn_send_recv_defaults: rc=%d, sss_error=%u", rc, sss_error);
	debug_return_int(-1);
    }

    switch (sss_error) {
    case 0:
	/* Success */
	for (i = 0; i < sss_result->num_rules; ++i) {
	    struct sss_sudo_rule *sss_rule = sss_result->rules + i;
	    sudo_debug_printf(SUDO_DEBUG_DIAG,
		"Parsing cn=defaults, %d/%d", i, sss_result->num_rules);
	    if (!sudo_sss_parse_options(handle, sss_rule,
		&handle->parse_tree.defaults))
		goto bad;
	}
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "No global defaults entry found in SSSD.");
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR, "sss_error=%u\n", sss_error);
	goto bad;
    }
    handle->fn_free_result(sss_result);
    cached = true;
    debug_return_int(0);

bad:
    handle->fn_free_result(sss_result);
    debug_return_int(-1);
}

/* sudo_nss implementation */
struct sudo_nss sudo_nss_sss = {
    { NULL, NULL },
    sudo_sss_open,
    sudo_sss_close,
    sudo_sss_parse,
    sudo_sss_query,
    sudo_sss_getdefs
};

#endif /* HAVE_SSSD */
