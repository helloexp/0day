/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1999-2005, 2007-2008, 2010-2015
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

#ifdef HAVE_KERB5

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRING_H */
#include <unistd.h>
#include <pwd.h>
#include <krb5.h>
#ifdef HAVE_HEIMDAL
#include <com_err.h>
#endif

#include "sudoers.h"
#include "sudo_auth.h"

#ifdef HAVE_HEIMDAL
# define extract_name(c, p)		krb5_principal_get_comp_string(c, p, 1)
# define krb5_free_data_contents(c, d)	krb5_data_free(d)
#else
# define extract_name(c, p)		(krb5_princ_component(c, p, 1)->data)
#endif

#ifndef HAVE_KRB5_VERIFY_USER
static int verify_krb_v5_tgt(krb5_context, krb5_creds *, char *);
#endif
static struct _sudo_krb5_data {
    krb5_context	sudo_context;
    krb5_principal	princ;
    krb5_ccache		ccache;
} sudo_krb5_data = { NULL, NULL, NULL };
typedef struct _sudo_krb5_data *sudo_krb5_datap;

#ifdef SUDO_KRB5_INSTANCE
static const char *sudo_krb5_instance = SUDO_KRB5_INSTANCE;
#else
static const char *sudo_krb5_instance = NULL;
#endif

#ifndef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
static krb5_error_code
krb5_get_init_creds_opt_alloc(krb5_context context,
    krb5_get_init_creds_opt **opts)
{
    *opts = malloc(sizeof(krb5_get_init_creds_opt));
    if (*opts == NULL)
	return KRB5_CC_NOMEM;
    krb5_get_init_creds_opt_init(*opts);
    return 0;
}

static void
krb5_get_init_creds_opt_free(krb5_get_init_creds_opt *opts)
{
    free(opts);
}
#endif

int
sudo_krb5_setup(struct passwd *pw, char **promptp, sudo_auth *auth)
{
    static char	*krb5_prompt;
    debug_decl(sudo_krb5_init, SUDOERS_DEBUG_AUTH)

    if (krb5_prompt == NULL) {
	krb5_context	sudo_context;
	krb5_principal	princ;
	char		*pname;
	krb5_error_code	error;

	sudo_context = ((sudo_krb5_datap) auth->data)->sudo_context;
	princ = ((sudo_krb5_datap) auth->data)->princ;

	/*
	 * Really, we need to tell the caller not to prompt for password. The
	 * API does not currently provide this unless the auth is standalone.
	 */
	if ((error = krb5_unparse_name(sudo_context, princ, &pname))) {
	    log_warningx(0,
		N_("%s: unable to convert principal to string ('%s'): %s"),
		auth->name, pw->pw_name, error_message(error));
	    debug_return_int(AUTH_FAILURE);
	}

	/* Only rewrite prompt if user didn't specify their own. */
	/*if (!strcmp(prompt, PASSPROMPT)) { */
	    if (asprintf(&krb5_prompt, "Password for %s: ", pname) == -1) {
		log_warningx(0, N_("unable to allocate memory"));
		free(pname);
		debug_return_int(AUTH_FATAL);
	    }
	/*}*/
	free(pname);
    }
    *promptp = krb5_prompt;

    debug_return_int(AUTH_SUCCESS);
}

int
sudo_krb5_init(struct passwd *pw, sudo_auth *auth)
{
    krb5_context	sudo_context;
    krb5_error_code 	error;
    char		cache_name[64], *pname = pw->pw_name;
    debug_decl(sudo_krb5_init, SUDOERS_DEBUG_AUTH)

    auth->data = (void *) &sudo_krb5_data; /* Stash all our data here */

    if (sudo_krb5_instance != NULL) {
	int len = asprintf(&pname, "%s%s%s", pw->pw_name,
	    sudo_krb5_instance[0] != '/' ? "/" : "", sudo_krb5_instance);
	if (len == -1) {
	    log_warningx(0, N_("unable to allocate memory"));
	    debug_return_int(AUTH_FATAL);
	}
    }

#ifdef HAVE_KRB5_INIT_SECURE_CONTEXT
    error = krb5_init_secure_context(&(sudo_krb5_data.sudo_context));
#else
    error = krb5_init_context(&(sudo_krb5_data.sudo_context));
#endif
    if (error)
	goto done;
    sudo_context = sudo_krb5_data.sudo_context;

    error = krb5_parse_name(sudo_context, pname, &(sudo_krb5_data.princ));
    if (error) {
	log_warningx(0, N_("%s: unable to parse '%s': %s"), auth->name, pname,
	    error_message(error));
	goto done;
    }

    (void) snprintf(cache_name, sizeof(cache_name), "MEMORY:sudocc_%ld",
		    (long) getpid());
    if ((error = krb5_cc_resolve(sudo_context, cache_name,
	&(sudo_krb5_data.ccache)))) {
	log_warningx(0, N_("%s: unable to resolve credential cache: %s"),
	    auth->name, error_message(error));
	goto done;
    }

done:
    if (sudo_krb5_instance != NULL)
	free(pname);
    debug_return_int(error ? AUTH_FAILURE : AUTH_SUCCESS);
}

#ifdef HAVE_KRB5_VERIFY_USER
int
sudo_krb5_verify(struct passwd *pw, char *pass, sudo_auth *auth, struct sudo_conv_callback *callback)
{
    krb5_context	sudo_context;
    krb5_principal	princ;
    krb5_ccache		ccache;
    krb5_error_code	error;
    debug_decl(sudo_krb5_verify, SUDOERS_DEBUG_AUTH)

    sudo_context = ((sudo_krb5_datap) auth->data)->sudo_context;
    princ = ((sudo_krb5_datap) auth->data)->princ;
    ccache = ((sudo_krb5_datap) auth->data)->ccache;

    error = krb5_verify_user(sudo_context, princ, ccache, pass, 1, NULL);
    debug_return_int(error ? AUTH_FAILURE : AUTH_SUCCESS);
}
#else
int
sudo_krb5_verify(struct passwd *pw, char *pass, sudo_auth *auth, struct sudo_conv_callback *callback)
{
    krb5_context	sudo_context;
    krb5_principal	princ;
    krb5_creds		credbuf, *creds = NULL;
    krb5_ccache		ccache;
    krb5_error_code	error;
    krb5_get_init_creds_opt *opts = NULL;
    debug_decl(sudo_krb5_verify, SUDOERS_DEBUG_AUTH)

    sudo_context = ((sudo_krb5_datap) auth->data)->sudo_context;
    princ = ((sudo_krb5_datap) auth->data)->princ;
    ccache = ((sudo_krb5_datap) auth->data)->ccache;

    /* Set default flags based on the local config file. */
    error = krb5_get_init_creds_opt_alloc(sudo_context, &opts);
    if (error) {
	log_warningx(0, N_("%s: unable to allocate options: %s"), auth->name,
	    error_message(error));
	goto done;
    }
#ifdef HAVE_HEIMDAL
    krb5_get_init_creds_opt_set_default_flags(sudo_context, NULL,
	krb5_principal_get_realm(sudo_context, princ), opts);
#endif

    /* Note that we always obtain a new TGT to verify the user */
    if ((error = krb5_get_init_creds_password(sudo_context, &credbuf, princ,
					     pass, krb5_prompter_posix,
					     NULL, 0, NULL, opts))) {
	/* Don't print error if just a bad password */
	if (error != KRB5KRB_AP_ERR_BAD_INTEGRITY) {
	    log_warningx(0, N_("%s: unable to get credentials: %s"),
		auth->name, error_message(error));
	}
	goto done;
    }
    creds = &credbuf;

    /* Verify the TGT to prevent spoof attacks. */
    if ((error = verify_krb_v5_tgt(sudo_context, creds, auth->name)))
	goto done;

    /* Store credential in cache. */
    if ((error = krb5_cc_initialize(sudo_context, ccache, princ))) {
	log_warningx(0, N_("%s: unable to initialize credential cache: %s"),
	    auth->name, error_message(error));
    } else if ((error = krb5_cc_store_cred(sudo_context, ccache, creds))) {
	log_warningx(0, N_("%s: unable to store credential in cache: %s"),
	    auth->name, error_message(error));
    }

done:
    if (opts) {
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_FREE_TWO_ARGS
	krb5_get_init_creds_opt_free(sudo_context, opts);
#else
	krb5_get_init_creds_opt_free(opts);
#endif
    }
    if (creds)
	krb5_free_cred_contents(sudo_context, creds);
    debug_return_int(error ? AUTH_FAILURE : AUTH_SUCCESS);
}
#endif

int
sudo_krb5_cleanup(struct passwd *pw, sudo_auth *auth)
{
    krb5_context	sudo_context;
    krb5_principal	princ;
    krb5_ccache		ccache;
    debug_decl(sudo_krb5_cleanup, SUDOERS_DEBUG_AUTH)

    sudo_context = ((sudo_krb5_datap) auth->data)->sudo_context;
    princ = ((sudo_krb5_datap) auth->data)->princ;
    ccache = ((sudo_krb5_datap) auth->data)->ccache;

    if (sudo_context) {
	if (ccache)
	    krb5_cc_destroy(sudo_context, ccache);
	if (princ)
	    krb5_free_principal(sudo_context, princ);
	krb5_free_context(sudo_context);
    }

    debug_return_int(AUTH_SUCCESS);
}

#ifndef HAVE_KRB5_VERIFY_USER
/*
 * Verify the Kerberos ticket-granting ticket just retrieved for the
 * user.  If the Kerberos server doesn't respond, assume the user is
 * trying to fake us out (since we DID just get a TGT from what is
 * supposedly our KDC).
 *
 * Returns 0 for successful authentication, non-zero for failure.
 */
static int
verify_krb_v5_tgt(krb5_context sudo_context, krb5_creds *cred, char *auth_name)
{
    krb5_error_code	error;
    krb5_principal	server;
    krb5_verify_init_creds_opt vopt;
    debug_decl(verify_krb_v5_tgt, SUDOERS_DEBUG_AUTH)

    /*
     * Get the server principal for the local host.
     * (Use defaults of "host" and canonicalized local name.)
     */
    if ((error = krb5_sname_to_principal(sudo_context, NULL, NULL,
					KRB5_NT_SRV_HST, &server))) {
	log_warningx(0, N_("%s: unable to get host principal: %s"), auth_name,
	    error_message(error));
	debug_return_int(-1);
    }

    /* Initialize verify opts and set secure mode */
    krb5_verify_init_creds_opt_init(&vopt);
    krb5_verify_init_creds_opt_set_ap_req_nofail(&vopt, 1);

    /* verify the Kerberos ticket-granting ticket we just retrieved */
    error = krb5_verify_init_creds(sudo_context, cred, server, NULL,
				   NULL, &vopt);
    krb5_free_principal(sudo_context, server);
    if (error) {
	log_warningx(0, N_("%s: Cannot verify TGT! Possible attack!: %s"),
	    auth_name, error_message(error));
    }
    debug_return_int(error);
}
#endif

#endif /* HAVE_KERB5 */
