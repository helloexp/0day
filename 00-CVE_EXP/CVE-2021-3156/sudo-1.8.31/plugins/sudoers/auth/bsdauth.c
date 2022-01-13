/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2000-2005, 2007-2008, 2010-2015
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

#ifdef HAVE_BSD_AUTH_H

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
#include <ctype.h>
#include <pwd.h>
#include <signal.h>

#include <login_cap.h>
#include <bsd_auth.h>

#include "sudoers.h"
#include "sudo_auth.h"

# ifndef LOGIN_DEFROOTCLASS
#  define LOGIN_DEFROOTCLASS	"daemon"
# endif

struct bsdauth_state {
    auth_session_t *as;
    login_cap_t *lc;
};

int
bsdauth_init(struct passwd *pw, sudo_auth *auth)
{
    static struct bsdauth_state state;
    debug_decl(bsdauth_init, SUDOERS_DEBUG_AUTH)

    /* Get login class based on auth user, which may not be invoking user. */
    if (pw->pw_class && *pw->pw_class)
	state.lc = login_getclass(pw->pw_class);
    else
	state.lc = login_getclass(pw->pw_uid ? LOGIN_DEFCLASS : LOGIN_DEFROOTCLASS);
    if (state.lc == NULL) {
	log_warning(0,
	    N_("unable to get login class for user %s"), pw->pw_name);
	debug_return_int(AUTH_FATAL);
    }

    if ((state.as = auth_open()) == NULL) {
	log_warning(0, N_("unable to begin bsd authentication"));
	login_close(state.lc);
	debug_return_int(AUTH_FATAL);
    }

    /* XXX - maybe sanity check the auth style earlier? */
    login_style = login_getstyle(state.lc, login_style, "auth-sudo");
    if (login_style == NULL) {
	log_warningx(0, N_("invalid authentication type"));
	auth_close(state.as);
	login_close(state.lc);
	debug_return_int(AUTH_FATAL);
    }

     if (auth_setitem(state.as, AUTHV_STYLE, login_style) < 0 ||
	auth_setitem(state.as, AUTHV_NAME, pw->pw_name) < 0 ||
	auth_setitem(state.as, AUTHV_CLASS, login_class) < 0) {
	log_warningx(0, N_("unable to initialize BSD authentication"));
	auth_close(state.as);
	login_close(state.lc);
	debug_return_int(AUTH_FATAL);
    }

    auth->data = (void *) &state;
    debug_return_int(AUTH_SUCCESS);
}

int
bsdauth_verify(struct passwd *pw, char *prompt, sudo_auth *auth, struct sudo_conv_callback *callback)
{
    char *pass;
    char *s;
    size_t len;
    int authok = 0;
    struct sigaction sa, osa;
    auth_session_t *as = ((struct bsdauth_state *) auth->data)->as;
    debug_decl(bsdauth_verify, SUDOERS_DEBUG_AUTH)

    /* save old signal handler */
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_DFL;
    (void) sigaction(SIGCHLD, &sa, &osa);

    /*
     * If there is a challenge then print that instead of the normal
     * prompt.  If the user just hits return we prompt again with echo
     * turned on, which is useful for challenge/response things like
     * S/Key.
     */
    if ((s = auth_challenge(as)) == NULL) {
	pass = auth_getpass(prompt, SUDO_CONV_PROMPT_ECHO_OFF, callback);
    } else {
	pass = auth_getpass(s, SUDO_CONV_PROMPT_ECHO_OFF, callback);
	if (pass && *pass == '\0') {
	    if ((prompt = strrchr(s, '\n')))
		prompt++;
	    else
		prompt = s;

	    /*
	     * Append '[echo on]' to the last line of the challenge and
	     * reprompt with echo turned on.
	     */
	    len = strlen(prompt) - 1;
	    while (isspace(prompt[len]) || prompt[len] == ':')
		prompt[len--] = '\0';
	    if (asprintf(&s, "%s [echo on]: ", prompt) == -1) {
		log_warningx(0, N_("unable to allocate memory"));
		debug_return_int(AUTH_FATAL);
	    }
	    free(pass);
	    pass = auth_getpass(s, SUDO_CONV_PROMPT_ECHO_ON, callback);
	    free(s);
	}
    }

    if (pass) {
	authok = auth_userresponse(as, pass, 1);
	memset_s(pass, SUDO_CONV_REPL_MAX, 0, strlen(pass));
	free(pass);
    }

    /* restore old signal handler */
    (void) sigaction(SIGCHLD, &osa, NULL);

    if (authok)
	debug_return_int(AUTH_SUCCESS);

    if (!pass)
	debug_return_int(AUTH_INTR);

    if ((s = auth_getvalue(as, "errormsg")) != NULL)
	log_warningx(0, "%s", s);
    debug_return_int(AUTH_FAILURE);
}

int
bsdauth_approval(struct passwd *pw, sudo_auth *auth, bool exempt)
{
    struct bsdauth_state *state = auth->data;
    debug_decl(bsdauth_approval, SUDOERS_DEBUG_AUTH)

    if (auth_approval(state->as, state->lc, pw->pw_name, "auth-sudo") == 0) {
	if (auth_getstate(state->as) & AUTH_EXPIRED)
	    log_warningx(0, "%s", N_("your account has expired"));
	else
	    log_warningx(0, "%s", N_("approval failed"));
	debug_return_int(AUTH_FAILURE);
    }
    debug_return_int(AUTH_SUCCESS);
}

int
bsdauth_cleanup(struct passwd *pw, sudo_auth *auth)
{
    struct bsdauth_state *state = auth->data;
    debug_decl(bsdauth_cleanup, SUDOERS_DEBUG_AUTH)

    if (state != NULL) {
	auth_close(state->as);
	login_close(state->lc);
    }

    debug_return_int(AUTH_SUCCESS);
}

#endif /* HAVE_BSD_AUTH_H */
