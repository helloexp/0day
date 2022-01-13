/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2015 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include "sudoers.h"

#ifdef HAVE_BSM_AUDIT
# include "bsm_audit.h"
#endif
#ifdef HAVE_LINUX_AUDIT
# include "linux_audit.h"
#endif
#ifdef HAVE_SOLARIS_AUDIT
# include "solaris_audit.h"
#endif

int
audit_success(int argc, char *argv[])
{
    int rc = 0;
    debug_decl(audit_success, SUDOERS_DEBUG_AUDIT)

    if (!def_log_allowed)
	debug_return_int(0);

    if (argv != NULL) {
#ifdef HAVE_BSM_AUDIT
	if (bsm_audit_success(argv) == -1)
	    rc = -1;
#endif
#ifdef HAVE_LINUX_AUDIT
	if (linux_audit_command(argv, 1) == -1)
	    rc = -1;
#endif
#ifdef HAVE_SOLARIS_AUDIT
	if (solaris_audit_success(argc, argv) == -1)
	    rc = -1;
#endif
    }

    debug_return_int(rc);
}

int
audit_failure(int argc, char *argv[], char const *const fmt, ...)
{
    int rc = 0;
    debug_decl(audit_success, SUDOERS_DEBUG_AUDIT)

    if (!def_log_denied)
	debug_return_int(0);

#if defined(HAVE_BSM_AUDIT) || defined(HAVE_LINUX_AUDIT)
    if (argv != NULL) {
	va_list ap;
	int oldlocale;

	/* Audit error messages should be in the sudoers locale. */
	sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

#ifdef HAVE_BSM_AUDIT
	va_start(ap, fmt);
	if (bsm_audit_failure(argv, _(fmt), ap) == -1)
	    rc = -1;
	va_end(ap);
#endif
#ifdef HAVE_LINUX_AUDIT
	va_start(ap, fmt);
	if (linux_audit_command(argv, 0) == -1)
	    rc = -1;
	va_end(ap);
#endif
#ifdef HAVE_SOLARIS_AUDIT
	va_start(ap, fmt);
	if (solaris_audit_failure(argc, argv, _(fmt), ap) == -1)
	    rc = -1;
	va_end(ap);
#endif

	sudoers_setlocale(oldlocale, NULL);
    }
#endif /* HAVE_BSM_AUDIT || HAVE_LINUX_AUDIT */

    debug_return_int(rc);
}
