/*
 * Copyright (c) 1999-2005, 2007-2018 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <config.h>

#ifdef HAVE_AIXAUTH

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
#include <usersec.h>

#include "sudoers.h"
#include "sudo_auth.h"

/*
 * For a description of the AIX authentication API, see
 * http://publib16.boulder.ibm.com/doc_link/en_US/a_doc_lib/libs/basetrf1/authenticate.htm
 */

#ifdef HAVE_PAM
# define AIX_AUTH_UNKNOWN	0
# define AIX_AUTH_STD		1
# define AIX_AUTH_PAM		2

static int
sudo_aix_authtype(void)
{
    size_t linesize = 0;
    ssize_t len;
    char *cp, *line = NULL;
    bool in_stanza = false;
    int authtype = AIX_AUTH_UNKNOWN;
    FILE *fp;
    debug_decl(sudo_aix_authtype, SUDOERS_DEBUG_AUTH)

    if ((fp = fopen("/etc/security/login.cfg", "r")) != NULL) {
	while (authtype == AIX_AUTH_UNKNOWN && (len = getline(&line, &linesize, fp)) != -1) {
	    /* First remove comments. */
	    if ((cp = strchr(line, '#')) != NULL) {
		*cp = '\0';
		len = (ssize_t)(cp - line);
	    }

	    /* Next remove trailing newlines and whitespace. */
	    while (len > 0 && isspace((unsigned char)line[len - 1]))
		line[--len] = '\0';

	    /* Skip blank lines. */
	    if (len == 0)
		continue;

	    /* Match start of the usw stanza. */
	    if (!in_stanza) {
		if (strncmp(line, "usw:", 4) == 0)
		    in_stanza = true;
		continue;
	    }

	    /* Check for end of the usw stanza. */
	    if (!isblank((unsigned char)line[0])) {
		in_stanza = false;
		break;
	    }

	    /* Skip leading blanks. */
	    cp = line;
	    do {
		cp++;
	    } while (isblank((unsigned char)*cp));

	    /* Match "auth_type = (PAM_AUTH|STD_AUTH)". */
	    if (strncmp(cp, "auth_type", 9) != 0)
		continue;
	    cp += 9;
	    while (isblank((unsigned char)*cp))
		cp++;
	    if (*cp++ != '=')
		continue;
	    while (isblank((unsigned char)*cp))
		cp++;
	    if (strcmp(cp, "PAM_AUTH") == 0)
		authtype = AIX_AUTH_PAM;
	    else if (strcmp(cp, "STD_AUTH") == 0)
		authtype = AIX_AUTH_STD;
	}
	free(line);
        fclose(fp);
    }

    debug_return_int(authtype);
}
#endif /* HAVE_PAM */

int
sudo_aix_init(struct passwd *pw, sudo_auth *auth)
{
    debug_decl(sudo_aix_init, SUDOERS_DEBUG_AUTH)

#ifdef HAVE_PAM
    /* Check auth_type in /etc/security/login.cfg. */
    if (sudo_aix_authtype() == AIX_AUTH_PAM) {
	if (sudo_pam_init_quiet(pw, auth) == AUTH_SUCCESS) {
	    /* Fail AIX authentication so we can use PAM instead. */
	    debug_return_int(AUTH_FAILURE);
	}
    }
#endif
    debug_return_int(AUTH_SUCCESS);
}

int
sudo_aix_verify(struct passwd *pw, char *prompt, sudo_auth *auth, struct sudo_conv_callback *callback)
{
    char *pass, *message = NULL;
    int result = 1, reenter = 0;
    int ret = AUTH_SUCCESS;
    debug_decl(sudo_aix_verify, SUDOERS_DEBUG_AUTH)

    do {
	pass = auth_getpass(prompt, SUDO_CONV_PROMPT_ECHO_OFF, callback);
	if (pass == NULL)
	    break;
	free(message);
	message = NULL;
	result = authenticate(pw->pw_name, pass, &reenter, &message);
	memset_s(pass, SUDO_CONV_REPL_MAX, 0, strlen(pass));
	free(pass);
	prompt = message;
    } while (reenter);

    if (result != 0) {
	/* Display error message, if any. */
	if (message != NULL) {
	    struct sudo_conv_message msg;
	    struct sudo_conv_reply repl;

	    memset(&msg, 0, sizeof(msg));
	    msg.msg_type = SUDO_CONV_ERROR_MSG;
	    msg.msg = message;
	    memset(&repl, 0, sizeof(repl));
	    sudo_conv(1, &msg, &repl, NULL);
	}
	ret = pass ? AUTH_FAILURE : AUTH_INTR;
    }
    free(message);
    debug_return_int(ret);
}

int
sudo_aix_cleanup(struct passwd *pw, sudo_auth *auth)
{
    debug_decl(sudo_aix_cleanup, SUDOERS_DEBUG_AUTH)

    /* Unset AUTHSTATE as it may not be correct for the runas user. */
    if (sudo_unsetenv("AUTHSTATE") == -1)
	debug_return_int(AUTH_FAILURE);

    debug_return_int(AUTH_SUCCESS);
}

#endif /* HAVE_AIXAUTH */
