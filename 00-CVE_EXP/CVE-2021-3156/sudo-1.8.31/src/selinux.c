/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2016 Todd C. Miller <Todd.Miller@sudo.ws>
 * Copyright (c) 2008 Dan Walsh <dwalsh@redhat.com>
 *
 * Borrowed heavily from newrole source code
 * Authors:
 *	Anthony Colatrella
 *	Tim Fraser
 *	Steve Grubb <sgrubb@redhat.com>
 *	Darrel Goeddel <DGoeddel@trustedcs.com>
 *	Michael Thompson <mcthomps@us.ibm.com>
 *	Dan Walsh <dwalsh@redhat.com>
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

#ifdef HAVE_SELINUX

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include <selinux/selinux.h>           /* for is_selinux_enabled() */
#include <selinux/context.h>           /* for context-mangling functions */
#include <selinux/get_default_type.h>
#include <selinux/get_context_list.h>

#ifdef HAVE_LINUX_AUDIT
# include <libaudit.h>
#endif

#include "sudo.h"
#include "sudo_exec.h"

static struct selinux_state {
    security_context_t old_context;
    security_context_t new_context;
    security_context_t tty_con_raw;
    security_context_t new_tty_con_raw;
    const char *ttyn;
    int ttyfd;
    int enforcing;
} se_state;

#ifdef HAVE_LINUX_AUDIT
static int
audit_role_change(const security_context_t old_context,
    const security_context_t new_context, const char *ttyn, int result)
{
    int au_fd, rc = -1;
    char *message;
    debug_decl(audit_role_change, SUDO_DEBUG_SELINUX)

    au_fd = audit_open();
    if (au_fd == -1) {
        /* Kernel may not have audit support. */
        if (errno != EINVAL && errno != EPROTONOSUPPORT && errno != EAFNOSUPPORT
)
            sudo_fatal(U_("unable to open audit system"));
    } else {
	/* audit role change using the same format as newrole(1) */
	rc = asprintf(&message, "newrole: old-context=%s new-context=%s",
	    old_context, new_context);
	if (rc == -1)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	rc = audit_log_user_message(au_fd, AUDIT_USER_ROLE_CHANGE,
	    message, NULL, NULL, ttyn, result);
	if (rc <= 0)
	    sudo_warn(U_("unable to send audit message"));
	free(message);
	close(au_fd);
    }

    debug_return_int(rc);
}
#endif

/*
 * This function attempts to revert the relabeling done to the tty.
 * fd		   - referencing the opened ttyn
 * ttyn		   - name of tty to restore
 *
 * Returns 0 on success and -1 on failure.
 */
int
selinux_restore_tty(void)
{
    int ret = -1;
    security_context_t chk_tty_con_raw = NULL;
    debug_decl(selinux_restore_tty, SUDO_DEBUG_SELINUX)

    if (se_state.ttyfd == -1 || se_state.new_tty_con_raw == NULL) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: no tty, skip relabel",
	    __func__);
	debug_return_int(0);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: %s -> %s",
	__func__, se_state.new_tty_con_raw, se_state.tty_con_raw);

    /* Verify that the tty still has the context set by sudo. */
    if (fgetfilecon_raw(se_state.ttyfd, &chk_tty_con_raw) == -1) {
	sudo_warn(U_("unable to fgetfilecon %s"), se_state.ttyn);
	goto skip_relabel;
    }

    if (strcmp(chk_tty_con_raw, se_state.new_tty_con_raw) != 0) {
	sudo_warnx(U_("%s changed labels"), se_state.ttyn);
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: not restoring tty label, expected %s, have %s",
	    __func__, se_state.new_tty_con_raw, chk_tty_con_raw);
	goto skip_relabel;
    }

    if (fsetfilecon_raw(se_state.ttyfd, se_state.tty_con_raw) == -1) {
	sudo_warn(U_("unable to restore context for %s"), se_state.ttyn);
	goto skip_relabel;
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: successfully set tty label to %s",
	__func__, se_state.tty_con_raw);
    ret = 0;

skip_relabel:
    if (se_state.ttyfd != -1) {
	close(se_state.ttyfd);
	se_state.ttyfd = -1;
    }
    freecon(chk_tty_con_raw);
    debug_return_int(ret);
}

/*
 * This function attempts to relabel the tty. If this function fails, then
 * the contexts are free'd and -1 is returned. On success, 0 is returned
 * and tty_con_raw and new_tty_con_raw are set.
 *
 * This function will not fail if it can not relabel the tty when selinux is
 * in permissive mode.
 */
static int
relabel_tty(const char *ttyn, int ptyfd)
{
    security_context_t tty_con = NULL;
    security_context_t new_tty_con = NULL;
    struct stat sb;
    int fd;
    debug_decl(relabel_tty, SUDO_DEBUG_SELINUX)

    se_state.ttyfd = ptyfd;

    /* It is perfectly legal to have no tty. */
    if (ptyfd == -1 && ttyn == NULL) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: no tty, skip relabel",
	    __func__);
	debug_return_int(0);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: relabeling tty %s", __func__, ttyn);

    /* If sudo is not allocating a pty for the command, open current tty. */
    if (ptyfd == -1) {
	se_state.ttyfd = open(ttyn, O_RDWR|O_NOCTTY|O_NONBLOCK);
	if (se_state.ttyfd == -1 || fstat(se_state.ttyfd, &sb) == -1) {
	    sudo_warn(U_("unable to open %s, not relabeling tty"), ttyn);
	    goto bad;
	}
	if (!S_ISCHR(sb.st_mode)) {
	    sudo_warn(U_("%s is not a character device, not relabeling tty"),
		ttyn);
	    goto bad;
	}
	(void)fcntl(se_state.ttyfd, F_SETFL,
	    fcntl(se_state.ttyfd, F_GETFL, 0) & ~O_NONBLOCK);
    }

    if (fgetfilecon(se_state.ttyfd, &tty_con) == -1) {
	sudo_warn(U_("unable to get current tty context, not relabeling tty"));
	goto bad;
    }

    if (tty_con != NULL) {
	security_class_t tclass = string_to_security_class("chr_file");
	if (tclass == 0) {
	    sudo_warn(U_("unknown security class \"chr_file\", not relabeling tty"));
	    goto bad;
	}
	if (security_compute_relabel(se_state.new_context, tty_con,
	    tclass, &new_tty_con) == -1) {
	    sudo_warn(U_("unable to get new tty context, not relabeling tty"));
	    goto bad;
	}
    }

    if (new_tty_con != NULL) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: tty context %s -> %s",
	    __func__, tty_con, new_tty_con);
	if (fsetfilecon(se_state.ttyfd, new_tty_con) == -1) {
	    sudo_warn(U_("unable to set new tty context"));
	    goto bad;
	}
    }

    if (ptyfd != -1) {
	/* Reopen pty that was relabeled, std{in,out,err} are reset later. */
	se_state.ttyfd = open(ttyn, O_RDWR|O_NOCTTY, 0);
	if (se_state.ttyfd == -1 || fstat(se_state.ttyfd, &sb) == -1) {
	    sudo_warn(U_("unable to open %s"), ttyn);
	    goto bad;
	}
	if (!S_ISCHR(sb.st_mode)) {
	    sudo_warn(U_("%s is not a character device, not relabeling tty"),
		ttyn);
	    goto bad;
	}
	if (dup2(se_state.ttyfd, ptyfd) == -1) {
	    sudo_warn("dup2");
	    goto bad;
	}
    } else {
	/* Re-open tty to get new label and reset std{in,out,err} */
	close(se_state.ttyfd);
	se_state.ttyfd = open(ttyn, O_RDWR|O_NOCTTY|O_NONBLOCK);
	if (se_state.ttyfd == -1 || fstat(se_state.ttyfd, &sb) == -1) {
	    sudo_warn(U_("unable to open %s"), ttyn);
	    goto bad;
	}
	if (!S_ISCHR(sb.st_mode)) {
	    sudo_warn(U_("%s is not a character device, not relabeling tty"),
		ttyn);
	    goto bad;
	}
	(void)fcntl(se_state.ttyfd, F_SETFL,
	    fcntl(se_state.ttyfd, F_GETFL, 0) & ~O_NONBLOCK);
	for (fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
	    if (isatty(fd) && dup2(se_state.ttyfd, fd) == -1) {
		sudo_warn("dup2");
		goto bad;
	    }
	}
    }
    /* Retain se_state.ttyfd so we can restore label when command finishes. */
    (void)fcntl(se_state.ttyfd, F_SETFD, FD_CLOEXEC);

    se_state.ttyn = ttyn;
    if (selinux_trans_to_raw_context(tty_con, &se_state.tty_con_raw) == -1)
	goto bad;
    if (selinux_trans_to_raw_context(new_tty_con, &se_state.new_tty_con_raw) == -1)
	goto bad;
    freecon(tty_con);
    freecon(new_tty_con);
    debug_return_int(0);

bad:
    if (se_state.ttyfd != -1 && se_state.ttyfd != ptyfd) {
	close(se_state.ttyfd);
	se_state.ttyfd = -1;
    }
    freecon(se_state.tty_con_raw);
    se_state.tty_con_raw = NULL;
    freecon(se_state.new_tty_con_raw);
    se_state.new_tty_con_raw = NULL;
    freecon(tty_con);
    freecon(new_tty_con);
    debug_return_int(se_state.enforcing ? -1 : 0);
}

/*
 * Returns a new security context based on the old context and the
 * specified role and type.
 */
security_context_t
get_exec_context(security_context_t old_context, const char *role, const char *type)
{
    security_context_t new_context = NULL;
    context_t context = NULL;
    char *typebuf = NULL;
    debug_decl(get_exec_context, SUDO_DEBUG_SELINUX)
    
    /* We must have a role, the type is optional (we can use the default). */
    if (role == NULL) {
	sudo_warnx(U_("you must specify a role for type %s"), type);
	errno = EINVAL;
	goto bad;
    }
    if (type == NULL) {
	if (get_default_type(role, &typebuf)) {
	    sudo_warnx(U_("unable to get default type for role %s"), role);
	    errno = EINVAL;
	    goto bad;
	}
	type = typebuf;
    }
    
    /* 
     * Expand old_context into a context_t so that we can extract and modify 
     * its components easily. 
     */
    if ((context = context_new(old_context)) == NULL) {
	sudo_warn(U_("failed to get new context"));
	goto bad;
    }
    
    /*
     * Replace the role and type in "context" with the role and
     * type we will be running the command as.
     */
    if (context_role_set(context, role)) {
	sudo_warn(U_("failed to set new role %s"), role);
	goto bad;
    }
    if (context_type_set(context, type)) {
	sudo_warn(U_("failed to set new type %s"), type);
	goto bad;
    }
      
    /*
     * Convert "context" back into a string and verify it.
     */
    if ((new_context = strdup(context_str(context))) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto bad;
    }
    if (security_check_context(new_context) == -1) {
	sudo_warnx(U_("%s is not a valid context"), new_context);
	errno = EINVAL;
	goto bad;
    }

    context_free(context);
    debug_return_str(new_context);

bad:
    free(typebuf);
    context_free(context);
    freecon(new_context);
    debug_return_str(NULL);
}

/* 
 * Determine the exec and tty contexts in preparation for fork/exec.
 * Must run as root, before forking the child process.
 * Sets the tty context but not the exec context (which happens later).
 * If ptyfd is not -1, it indicates we are running
 * in a pty and do not need to reset std{in,out,err}.
 * Returns 0 on success and -1 on failure.
 */
int
selinux_setup(const char *role, const char *type, const char *ttyn,
    int ptyfd)
{
    int ret = -1;
    debug_decl(selinux_setup, SUDO_DEBUG_SELINUX)

    /* Store the caller's SID in old_context. */
    if (getprevcon(&se_state.old_context)) {
	sudo_warn(U_("failed to get old context"));
	goto done;
    }

    se_state.enforcing = security_getenforce();
    if (se_state.enforcing == -1) {
	sudo_warn(U_("unable to determine enforcing mode."));
	goto done;
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: old context %s", __func__,
	se_state.old_context);
    se_state.new_context = get_exec_context(se_state.old_context, role, type);
    if (se_state.new_context == NULL) {
#ifdef HAVE_LINUX_AUDIT
	audit_role_change(se_state.old_context, "?", se_state.ttyn, 0);
#endif
	goto done;
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: new context %s", __func__,
	se_state.new_context);
    
    if (relabel_tty(ttyn, ptyfd) == -1) {
	sudo_warn(U_("unable to set tty context to %s"), se_state.new_context);
	goto done;
    }

#ifdef HAVE_LINUX_AUDIT
    audit_role_change(se_state.old_context, se_state.new_context,
	se_state.ttyn, 1);
#endif

    ret = 0;

done:
    debug_return_int(ret);
}

void
selinux_execve(int fd, const char *path, char *const argv[], char *envp[],
    bool noexec)
{
    char **nargv;
    const char *sesh;
    int argc, nargc, serrno;
    debug_decl(selinux_execve, SUDO_DEBUG_SELINUX)

    sesh = sudo_conf_sesh_path();
    if (sesh == NULL) {
	sudo_warnx("internal error: sesh path not set");
	errno = EINVAL;
	debug_return;
    }

    if (setexeccon(se_state.new_context)) {
	sudo_warn(U_("unable to set exec context to %s"), se_state.new_context);
	if (se_state.enforcing)
	    debug_return;
    }

#ifdef HAVE_SETKEYCREATECON
    if (setkeycreatecon(se_state.new_context)) {
	sudo_warn(U_("unable to set key creation context to %s"), se_state.new_context);
	if (se_state.enforcing)
	    debug_return;
    }
#endif /* HAVE_SETKEYCREATECON */

    /*
     * Build new argv with sesh as argv[0].
     * If argv[0] ends in -noexec, sesh will disable execute
     * for the command it runs.
     */
    for (argc = 0; argv[argc] != NULL; argc++)
	continue;
    nargv = reallocarray(NULL, argc + 3, sizeof(char *));
    if (nargv == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return;
    }
    if (noexec)
	nargv[0] = *argv[0] == '-' ? "-sesh-noexec" : "sesh-noexec";
    else
	nargv[0] = *argv[0] == '-' ? "-sesh" : "sesh";
    nargc = 1;
    if (fd != -1 && asprintf(&nargv[nargc++], "--execfd=%d", fd) == -1) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return;
    }
    nargv[nargc++] = (char *)path;
    memcpy(&nargv[nargc], &argv[1], argc * sizeof(char *)); /* copies NULL */

    /* sesh will handle noexec for us. */
    sudo_execve(-1, sesh, nargv, envp, false);
    serrno = errno;
    free(nargv);
    errno = serrno;
    debug_return;
}

#endif /* HAVE_SELINUX */
