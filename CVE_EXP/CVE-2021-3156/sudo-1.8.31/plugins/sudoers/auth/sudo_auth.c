/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1999-2005, 2008-2018 Todd C. Miller <Todd.Miller@sudo.ws>
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
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <pwd.h>
#include <time.h>
#include <signal.h>

#include "sudoers.h"
#include "sudo_auth.h"
#include "insults.h"

static sudo_auth auth_switch[] = {
/* Standalone entries first */
#ifdef HAVE_AIXAUTH
    AUTH_ENTRY("aixauth", FLAG_STANDALONE, sudo_aix_init, NULL, sudo_aix_verify, NULL, sudo_aix_cleanup, NULL, NULL)
#endif
#ifdef HAVE_PAM
    AUTH_ENTRY("pam", FLAG_STANDALONE, sudo_pam_init, NULL, sudo_pam_verify, sudo_pam_approval, sudo_pam_cleanup, sudo_pam_begin_session, sudo_pam_end_session)
#endif
#ifdef HAVE_SECURID
    AUTH_ENTRY("SecurId", FLAG_STANDALONE, sudo_securid_init, sudo_securid_setup, sudo_securid_verify, NULL, NULL, NULL, NULL)
#endif
#ifdef HAVE_SIA_SES_INIT
    AUTH_ENTRY("sia", FLAG_STANDALONE, NULL, sudo_sia_setup, sudo_sia_verify, NULL, sudo_sia_cleanup, sudo_sia_begin_session, NULL)
#endif
#ifdef HAVE_FWTK
    AUTH_ENTRY("fwtk", FLAG_STANDALONE, sudo_fwtk_init, NULL, sudo_fwtk_verify, NULL, sudo_fwtk_cleanup, NULL, NULL)
#endif
#ifdef HAVE_BSD_AUTH_H
    AUTH_ENTRY("bsdauth", FLAG_STANDALONE, bsdauth_init, NULL, bsdauth_verify, bsdauth_approval, bsdauth_cleanup, NULL, NULL)
#endif

/* Non-standalone entries */
#ifndef WITHOUT_PASSWD
    AUTH_ENTRY("passwd", 0, sudo_passwd_init, NULL, sudo_passwd_verify, NULL, sudo_passwd_cleanup, NULL, NULL)
#endif
#if defined(HAVE_GETPRPWNAM) && !defined(WITHOUT_PASSWD)
    AUTH_ENTRY("secureware", 0, sudo_secureware_init, NULL, sudo_secureware_verify, NULL, sudo_secureware_cleanup, NULL, NULL)
#endif
#ifdef HAVE_AFS
    AUTH_ENTRY("afs", 0, NULL, NULL, sudo_afs_verify, NULL, NULL, NULL, NULL)
#endif
#ifdef HAVE_DCE
    AUTH_ENTRY("dce", 0, NULL, NULL, sudo_dce_verify, NULL, NULL, NULL, NULL)
#endif
#ifdef HAVE_KERB5
    AUTH_ENTRY("kerb5", 0, sudo_krb5_init, sudo_krb5_setup, sudo_krb5_verify, NULL, sudo_krb5_cleanup, NULL, NULL)
#endif
#ifdef HAVE_SKEY
    AUTH_ENTRY("S/Key", 0, NULL, sudo_rfc1938_setup, sudo_rfc1938_verify, NULL, NULL, NULL, NULL)
#endif
#ifdef HAVE_OPIE
    AUTH_ENTRY("OPIE", 0, NULL, sudo_rfc1938_setup, sudo_rfc1938_verify, NULL, NULL, NULL, NULL)
#endif
    AUTH_ENTRY(NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
};

static bool standalone;

/*
 * Initialize sudoers authentication method(s).
 * Returns 0 on success and -1 on error.
 */
int
sudo_auth_init(struct passwd *pw)
{
    sudo_auth *auth;
    int status = AUTH_SUCCESS;
    debug_decl(sudo_auth_init, SUDOERS_DEBUG_AUTH)

    if (auth_switch[0].name == NULL)
	debug_return_int(0);

    /* Initialize auth methods and unconfigure the method if necessary. */
    for (auth = auth_switch; auth->name; auth++) {
	if (auth->init && !IS_DISABLED(auth)) {
	    /* Disable if it failed to init unless there was a fatal error. */
	    status = (auth->init)(pw, auth);
	    if (status == AUTH_FAILURE)
		SET(auth->flags, FLAG_DISABLED);
	    else if (status == AUTH_FATAL)
		break;		/* assume error msg already printed */
	}
    }

    /*
     * Make sure we haven't mixed standalone and shared auth methods.
     * If there are multiple standalone methods, only use the first one.
     */
    if ((standalone = IS_STANDALONE(&auth_switch[0]))) {
	bool found = false;
	for (auth = auth_switch; auth->name; auth++) {
	    if (IS_DISABLED(auth))
		continue;
	    if (!IS_STANDALONE(auth)) {
		audit_failure(NewArgc, NewArgv,
		    N_("invalid authentication methods"));
		log_warningx(SLOG_SEND_MAIL,
		    N_("Invalid authentication methods compiled into sudo!  "
		    "You may not mix standalone and non-standalone authentication."));
		debug_return_int(-1);
	    }
	    if (!found) {
		/* Found first standalone method. */
		found = true;
		continue;
	    }
	    /* Disable other standalone methods. */
	    SET(auth->flags, FLAG_DISABLED);
	}
    }

    /* Set FLAG_ONEANDONLY if there is only one auth method. */
    for (auth = auth_switch; auth->name; auth++) {
	/* Find first enabled auth method. */
	if (!IS_DISABLED(auth)) {
	    sudo_auth *first = auth;
	    /* Check for others. */
	    for (; auth->name; auth++) {
		if (!IS_DISABLED(auth))
		    break;
	    }
	    if (auth->name == NULL)
		SET(first->flags, FLAG_ONEANDONLY);
	    break;
	}
    }

    debug_return_int(status == AUTH_FATAL ? -1 : 0);
}

/*
 * Cleanup all authentication approval methods.
 * Returns true on success, false on failure and -1 on error.
 */
int
sudo_auth_approval(struct passwd *pw, int validated, bool exempt)
{
    sudo_auth *auth;
    debug_decl(sudo_auth_approval, SUDOERS_DEBUG_AUTH)

    /* Call approval routines. */
    for (auth = auth_switch; auth->name; auth++) {
	if (auth->approval && !IS_DISABLED(auth)) {
	    int status = (auth->approval)(pw, auth, exempt);
	    if (status != AUTH_SUCCESS) {
		/* Assume error msg already printed. */
		log_auth_failure(validated, 0);
		debug_return_int(status == AUTH_FAILURE ? false : -1);
	    }
	}
    }
    debug_return_int(true);
}

/*
 * Cleanup all authentication methods.
 * Returns 0 on success and -1 on error.
 */
int
sudo_auth_cleanup(struct passwd *pw)
{
    sudo_auth *auth;
    debug_decl(sudo_auth_cleanup, SUDOERS_DEBUG_AUTH)

    /* Call cleanup routines. */
    for (auth = auth_switch; auth->name; auth++) {
	if (auth->cleanup && !IS_DISABLED(auth)) {
	    int status = (auth->cleanup)(pw, auth);
	    if (status == AUTH_FATAL) {
		/* Assume error msg already printed. */
		debug_return_int(-1);
	    }
	}
    }
    debug_return_int(0);
}

static void
pass_warn(void)
{
    const char *warning = def_badpass_message;
    debug_decl(pass_warn, SUDOERS_DEBUG_AUTH)

#ifdef INSULT
    if (def_insults)
	warning = INSULT;
#endif
    sudo_printf(SUDO_CONV_ERROR_MSG|SUDO_CONV_PREFER_TTY, "%s\n", warning);

    debug_return;
}

static bool
user_interrupted(void)
{
    sigset_t mask;

    return (sigpending(&mask) == 0 &&
	(sigismember(&mask, SIGINT) || sigismember(&mask, SIGQUIT)));
}

/*
 * Verify the specified user.
 * Returns true if verified, false if not or -1 on error.
 */
int
verify_user(struct passwd *pw, char *prompt, int validated,
    struct sudo_conv_callback *callback)
{
    unsigned int ntries;
    int ret, status, success = AUTH_FAILURE;
    sudo_auth *auth;
    sigset_t mask, omask;
    struct sigaction sa, saved_sigtstp;
    debug_decl(verify_user, SUDOERS_DEBUG_AUTH)

    /* Make sure we have at least one auth method. */
    if (auth_switch[0].name == NULL) {
	audit_failure(NewArgc, NewArgv, N_("no authentication methods"));
    	log_warningx(SLOG_SEND_MAIL,
	    N_("There are no authentication methods compiled into sudo!  "
	    "If you want to turn off authentication, use the "
	    "--disable-authentication configure option."));
	debug_return_int(-1);
    }

    /* Enable suspend during password entry. */
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_DFL;
    (void) sigaction(SIGTSTP, &sa, &saved_sigtstp);

    /*
     * We treat authentication as a critical section and block
     * keyboard-generated signals such as SIGINT and SIGQUIT
     * which might otherwise interrupt a sleep(3).
     * They are temporarily unblocked by auth_getpass().
     */
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGQUIT);
    (void) sigprocmask(SIG_BLOCK, &mask, &omask);

    for (ntries = 0; ntries < def_passwd_tries; ntries++) {
	int num_methods = 0;
	char *pass = NULL;

	/* If user attempted to interrupt password verify, quit now. */
	if (user_interrupted())
	    goto done;

	if (ntries != 0)
	    pass_warn();

	/* Do any per-method setup and unconfigure the method if needed */
	for (auth = auth_switch; auth->name; auth++) {
	    if (IS_DISABLED(auth))
		continue;
	    num_methods++;
	    if (auth->setup != NULL) {
		status = (auth->setup)(pw, &prompt, auth);
		if (status == AUTH_FAILURE)
		    SET(auth->flags, FLAG_DISABLED);
		else if (status == AUTH_FATAL || user_interrupted())
		    goto done;		/* assume error msg already printed */
	    }
	}
	if (num_methods == 0) {
	    audit_failure(NewArgc, NewArgv, N_("no authentication methods"));
	    log_warningx(SLOG_SEND_MAIL,
		N_("Unable to initialize authentication methods."));
	    debug_return_int(-1);
	}

	/* Get the password unless the auth function will do it for us */
	if (!standalone) {
	    pass = auth_getpass(prompt, SUDO_CONV_PROMPT_ECHO_OFF, callback);
	    if (pass == NULL)
		break;
	}

	/* Call authentication functions. */
	for (auth = auth_switch; auth->name; auth++) {
	    if (IS_DISABLED(auth))
		continue;

	    success = auth->status =
		(auth->verify)(pw, standalone ? prompt : pass, auth, callback);
	    if (success != AUTH_FAILURE)
		break;
	}
	if (pass != NULL) {
	    memset_s(pass, SUDO_CONV_REPL_MAX, 0, strlen(pass));
	    free(pass);
	}

	if (success != AUTH_FAILURE)
	    goto done;
    }

done:
    /* Restore signal handlers and signal mask. */
    (void) sigaction(SIGTSTP, &saved_sigtstp, NULL);
    (void) sigprocmask(SIG_SETMASK, &omask, NULL);

    switch (success) {
	case AUTH_SUCCESS:
	    ret = true;
	    break;
	case AUTH_INTR:
	case AUTH_FAILURE:
	    if (ntries != 0)
		validated |= FLAG_BAD_PASSWORD;
	    log_auth_failure(validated, ntries);
	    ret = false;
	    break;
	case AUTH_FATAL:
	default:
	    log_auth_failure(validated, 0);
	    ret = -1;
	    break;
    }

    debug_return_int(ret);
}

/*
 * Call authentication method begin session hooks.
 * Returns 1 on success and -1 on error.
 */
int
sudo_auth_begin_session(struct passwd *pw, char **user_env[])
{
    sudo_auth *auth;
    debug_decl(sudo_auth_begin_session, SUDOERS_DEBUG_AUTH)

    for (auth = auth_switch; auth->name; auth++) {
	if (auth->begin_session && !IS_DISABLED(auth)) {
	    int status = (auth->begin_session)(pw, user_env, auth);
	    if (status != AUTH_SUCCESS) {
		/* Assume error msg already printed. */
		debug_return_int(-1);
	    }
	}
    }
    debug_return_int(1);
}

bool
sudo_auth_needs_end_session(void)
{
    sudo_auth *auth;
    bool needed = false;
    debug_decl(sudo_auth_needs_end_session, SUDOERS_DEBUG_AUTH)

    for (auth = auth_switch; auth->name; auth++) {
	if (auth->end_session && !IS_DISABLED(auth)) {
	    needed = true;
	    break;
	}
    }
    debug_return_bool(needed);
}

/*
 * Call authentication method end session hooks.
 * Returns 1 on success and -1 on error.
 */
int
sudo_auth_end_session(struct passwd *pw)
{
    sudo_auth *auth;
    int status;
    debug_decl(sudo_auth_end_session, SUDOERS_DEBUG_AUTH)

    for (auth = auth_switch; auth->name; auth++) {
	if (auth->end_session && !IS_DISABLED(auth)) {
	    status = (auth->end_session)(pw, auth);
	    if (status == AUTH_FATAL) {
		/* Assume error msg already printed. */
		debug_return_int(-1);
	    }
	}
    }
    debug_return_int(1);
}

/*
 * Prompts the user for a password using the conversation function.
 * Returns the plaintext password or NULL.
 * The user is responsible for freeing the returned value.
 */
char *
auth_getpass(const char *prompt, int type, struct sudo_conv_callback *callback)
{
    struct sudo_conv_message msg;
    struct sudo_conv_reply repl;
    sigset_t mask, omask;
    debug_decl(auth_getpass, SUDOERS_DEBUG_AUTH)

    /* Mask user input if pwfeedback set and echo is off. */
    if (type == SUDO_CONV_PROMPT_ECHO_OFF && def_pwfeedback)
	type = SUDO_CONV_PROMPT_MASK;

    /* If visiblepw set, do not error out if there is no tty. */
    if (def_visiblepw)
	type |= SUDO_CONV_PROMPT_ECHO_OK;

    /* Unblock SIGINT and SIGQUIT during password entry. */
    /* XXX - do in tgetpass() itself instead? */
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGQUIT);
    (void) sigprocmask(SIG_UNBLOCK, &mask, &omask);

    /* Call conversation function. */
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = type;
    msg.timeout = def_passwd_timeout.tv_sec;
    msg.msg = prompt;
    memset(&repl, 0, sizeof(repl));
    sudo_conv(1, &msg, &repl, callback);
    /* XXX - check for ENOTTY? */

    /* Restore previous signal mask. */
    (void) sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_str_masked(repl.reply);
}

void
dump_auth_methods(void)
{
    sudo_auth *auth;
    debug_decl(dump_auth_methods, SUDOERS_DEBUG_AUTH)

    sudo_printf(SUDO_CONV_INFO_MSG, _("Authentication methods:"));
    for (auth = auth_switch; auth->name; auth++)
	sudo_printf(SUDO_CONV_INFO_MSG, " '%s'", auth->name);
    sudo_printf(SUDO_CONV_INFO_MSG, "\n");

    debug_return;
}
