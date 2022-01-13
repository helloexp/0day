/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2016 Todd C. Miller <Todd.Miller@sudo.ws>
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
#ifdef HAVE_PRIV_SET
# include <priv.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include "sudo.h"
#include "sudo_exec.h"

#ifdef RTLD_PRELOAD_VAR
/*
 * Add a DSO file to LD_PRELOAD or the system equivalent.
 */
static char **
preload_dso(char *envp[], const char *dso_file)
{
    char *preload = NULL;
    int env_len;
    int preload_idx = -1;
    bool present = false;
# ifdef RTLD_PRELOAD_ENABLE_VAR
    bool enabled = false;
# else
    const bool enabled = true;
# endif
    debug_decl(preload_dso, SUDO_DEBUG_UTIL)

    /*
     * Preload a DSO file.  For a list of LD_PRELOAD-alikes, see
     * http://www.fortran-2000.com/ArnaudRecipes/sharedlib.html
     * XXX - need to support 32-bit and 64-bit variants
     */

    /* Count entries in envp, looking for LD_PRELOAD as we go. */
    for (env_len = 0; envp[env_len] != NULL; env_len++) {
	if (preload_idx == -1 && strncmp(envp[env_len], RTLD_PRELOAD_VAR "=",
	    sizeof(RTLD_PRELOAD_VAR)) == 0) {
	    const char *cp = envp[env_len] + sizeof(RTLD_PRELOAD_VAR);
	    const char *end = cp + strlen(cp);
	    const char *ep;
	    const size_t dso_len = strlen(dso_file);

	    /* Check to see if dso_file is already present. */
	    for (cp = sudo_strsplit(cp, end, RTLD_PRELOAD_DELIM, &ep);
		cp != NULL; cp = sudo_strsplit(NULL, end, RTLD_PRELOAD_DELIM,
		&ep)) {
		if ((size_t)(ep - cp) == dso_len) {
		    if (memcmp(cp, dso_file, dso_len) == 0) {
			/* already present */
			present = true;
			break;
		    }
		}
	    }

	    /* Save index of existing LD_PRELOAD variable. */
	    preload_idx = env_len;
	    continue;
	}
# ifdef RTLD_PRELOAD_ENABLE_VAR
	if (strncmp(envp[env_len], RTLD_PRELOAD_ENABLE_VAR "=", sizeof(RTLD_PRELOAD_ENABLE_VAR)) == 0) {
	    enabled = true;
	    continue;
	}
# endif
    }

    /*
     * Make a new copy of envp as needed.
     * It would be nice to realloc the old envp[] but we don't know
     * whether it was dynamically allocated. [TODO: plugin API]
     */
    if (preload_idx == -1 || !enabled) {
	const int env_size = env_len + 1 + (preload_idx == -1) + enabled;

	char **nenvp = reallocarray(NULL, env_size, sizeof(*envp));
	if (nenvp == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	memcpy(nenvp, envp, env_len * sizeof(*envp));
	nenvp[env_len] = NULL;
	envp = nenvp;
    }

    /* Prepend our LD_PRELOAD to existing value or add new entry at the end. */
    if (!present) {
	if (preload_idx == -1) {
# ifdef RTLD_PRELOAD_DEFAULT
	    asprintf(&preload, "%s=%s%s%s", RTLD_PRELOAD_VAR, dso_file,
		RTLD_PRELOAD_DELIM, RTLD_PRELOAD_DEFAULT);
# else
	    preload = sudo_new_key_val(RTLD_PRELOAD_VAR, dso_file);
# endif
	    if (preload == NULL) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	    envp[env_len++] = preload;
	    envp[env_len] = NULL;
	} else {
	    int len = asprintf(&preload, "%s=%s%s%s", RTLD_PRELOAD_VAR,
		dso_file, RTLD_PRELOAD_DELIM, envp[preload_idx]);
	    if (len == -1) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	    envp[preload_idx] = preload;
	}
    }
# ifdef RTLD_PRELOAD_ENABLE_VAR
    if (!enabled) {
	envp[env_len++] = RTLD_PRELOAD_ENABLE_VAR "=";
	envp[env_len] = NULL;
    }
# endif

    debug_return_ptr(envp);
}
#endif /* RTLD_PRELOAD_VAR */

/*
 * Disable execution of child processes in the command we are about
 * to run.  On systems with privilege sets, we can remove the exec
 * privilege.  On other systems we use LD_PRELOAD and the like.
 */
char **
disable_execute(char *envp[], const char *dso)
{
    debug_decl(disable_execute, SUDO_DEBUG_UTIL)

#ifdef HAVE_PRIV_SET
    /* Solaris privileges, remove PRIV_PROC_EXEC post-execve. */
    (void)priv_set(PRIV_ON, PRIV_INHERITABLE, "PRIV_FILE_DAC_READ", NULL);
    (void)priv_set(PRIV_ON, PRIV_INHERITABLE, "PRIV_FILE_DAC_WRITE", NULL);
    (void)priv_set(PRIV_ON, PRIV_INHERITABLE, "PRIV_FILE_DAC_SEARCH", NULL);
    if (priv_set(PRIV_OFF, PRIV_LIMIT, "PRIV_PROC_EXEC", NULL) == 0)
	debug_return_ptr(envp);
    sudo_warn(U_("unable to remove PRIV_PROC_EXEC from PRIV_LIMIT"));
#endif /* HAVE_PRIV_SET */

#ifdef RTLD_PRELOAD_VAR
    if (dso != NULL)
	envp = preload_dso(envp, dso);
#endif /* RTLD_PRELOAD_VAR */

    debug_return_ptr(envp);
}

/*
 * Like execve(2) but falls back to running through /bin/sh
 * ala execvp(3) if we get ENOEXEC.
 */
int
sudo_execve(int fd, const char *path, char *const argv[], char *envp[], bool noexec)
{
    debug_decl(sudo_execve, SUDO_DEBUG_UTIL)

    sudo_debug_execve(SUDO_DEBUG_INFO, path, argv, envp);

    /* Modify the environment as needed to disable further execve(). */
    if (noexec)
	envp = disable_execute(envp, sudo_conf_noexec_path());

#ifdef HAVE_FEXECVE
    if (fd != -1)
	    fexecve(fd, argv, envp);
    else
#endif
	    execve(path, argv, envp);
    if (fd == -1 && errno == ENOEXEC) {
	int argc;
	char **nargv;

	for (argc = 0; argv[argc] != NULL; argc++)
	    continue;
	nargv = reallocarray(NULL, argc + 2, sizeof(char *));
	if (nargv != NULL) {
	    nargv[0] = "sh";
	    nargv[1] = (char *)path;
	    memcpy(nargv + 2, argv + 1, argc * sizeof(char *));
	    execve(_PATH_SUDO_BSHELL, nargv, envp);
	    free(nargv);
	}
    }
    debug_return_int(-1);
}
