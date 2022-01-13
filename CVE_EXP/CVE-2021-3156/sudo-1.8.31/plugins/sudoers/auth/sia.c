/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1999-2005, 2007, 2010-2015
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

#ifdef HAVE_SIA_SES_INIT

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
#include <pwd.h>
#include <signal.h>
#include <siad.h>

#include "sudoers.h"
#include "sudo_auth.h"

static char **sudo_argv;
static int sudo_argc;

int
sudo_sia_setup(struct passwd *pw, char **promptp, sudo_auth *auth)
{
    SIAENTITY *siah;
    int i;
    debug_decl(sudo_sia_setup, SUDOERS_DEBUG_AUTH)

    /* Rebuild argv for sia_ses_init() */
    sudo_argc = NewArgc + 1;
    sudo_argv = reallocarray(NULL, sudo_argc + 1, sizeof(char *));
    if (sudo_argv == NULL) {
	log_warningx(0, N_("unable to allocate memory"));
	debug_return_int(AUTH_FATAL);
    }
    sudo_argv[0] = "sudo";
    for (i = 0; i < NewArgc; i++)
	sudo_argv[i + 1] = NewArgv[i];
    sudo_argv[sudo_argc] = NULL;

    /* We don't let SIA prompt the user for input. */
    if (sia_ses_init(&siah, sudo_argc, sudo_argv, NULL, pw->pw_name, user_ttypath, 0, NULL) != SIASUCCESS) {
	log_warning(0, N_("unable to initialize SIA session"));
	debug_return_int(AUTH_FATAL);
    }

    auth->data = siah;
    debug_return_int(AUTH_SUCCESS);
}

int
sudo_sia_verify(struct passwd *pw, char *prompt, sudo_auth *auth,
    struct sudo_conv_callback *callback)
{
    SIAENTITY *siah = auth->data;
    char *pass;
    int rc;
    debug_decl(sudo_sia_verify, SUDOERS_DEBUG_AUTH)

    /* Get password, return AUTH_INTR if we got ^C */
    pass = auth_getpass(prompt, SUDO_CONV_PROMPT_ECHO_OFF, callback);
    if (pass == NULL)
	debug_return_int(AUTH_INTR);

    /* Check password and zero out plaintext copy. */
    rc = sia_ses_authent(NULL, pass, siah);
    memset_s(pass, SUDO_CONV_REPL_MAX, 0, strlen(pass));
    free(pass);

    if (rc == SIASUCCESS)
	debug_return_int(AUTH_SUCCESS);
    if (ISSET(rc, SIASTOP))
	debug_return_int(AUTH_FATAL);
    debug_return_int(AUTH_FAILURE);
}

int
sudo_sia_cleanup(struct passwd *pw, sudo_auth *auth)
{
    SIAENTITY *siah = auth->data;
    debug_decl(sudo_sia_cleanup, SUDOERS_DEBUG_AUTH)

    (void) sia_ses_release(&siah);
    auth->data = NULL;
    free(sudo_argv);
    debug_return_int(AUTH_SUCCESS);
}

int
sudo_sia_begin_session(struct passwd *pw, char **user_envp[], sudo_auth *auth)
{
    SIAENTITY *siah;
    int status = AUTH_FATAL;
    debug_decl(sudo_sia_begin_session, SUDOERS_DEBUG_AUTH)

    /* Re-init sia for the target user's session. */
    if (sia_ses_init(&siah, NewArgc, NewArgv, NULL, pw->pw_name, user_ttypath, 0, NULL) != SIASUCCESS) {
	log_warning(0, N_("unable to initialize SIA session"));
	goto done;
    }

    if (sia_make_entity_pwd(pw, siah) != SIASUCCESS) {
	sudo_warn("sia_make_entity_pwd");
	goto done;
    }

    status = AUTH_FAILURE;		/* no more fatal errors. */

    siah->authtype = SIA_A_NONE;
    if (sia_ses_estab(sia_collect_trm, siah) != SIASUCCESS) {
	sudo_warn("sia_ses_estab");
	goto done;
    }

    if (sia_ses_launch(sia_collect_trm, siah) != SIASUCCESS) {
	sudo_warn("sia_ses_launch");
	goto done;
    }

    status = AUTH_SUCCESS;

done:
    (void) sia_ses_release(&siah);
    debug_return_int(status);
}

#endif /* HAVE_SIA_SES_INIT */
