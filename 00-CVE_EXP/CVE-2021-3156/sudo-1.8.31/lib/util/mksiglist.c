/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2010-2012, 2015 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <signal.h>

#include "sudo_compat.h"

__dso_public int main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    static char *sudo_sys_siglist[NSIG];
    int i;

#include "mksiglist.h"

    printf("#include <config.h>\n");
    printf("#include <sys/types.h>\n");
    printf("#include <signal.h>\n");
    printf("#include \"sudo_compat.h\"\n\n");
    printf("const char *const sudo_sys_siglist[NSIG] = {\n");
    for (i = 0; i < NSIG; i++) {
	if (sudo_sys_siglist[i] != NULL) {
	    printf("    \"%s\",\n", sudo_sys_siglist[i]);
	} else {
	    printf("    \"Signal %d\",\n", i);
	}
    }
    printf("};\n");

    exit(0);
}
