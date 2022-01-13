/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2013-2014 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <stddef.h>
#include <errno.h>
#include <limits.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif

#include "sudo_compat.h"

#ifndef RSIZE_MAX
# if defined(SIZE_MAX)
#  define RSIZE_MAX (SIZE_MAX >> 1)
# elif defined(__LP64__)
#  define RSIZE_MAX 0x7fffffffffffffffUL
# else
#  define RSIZE_MAX 0x7fffffffU
# endif
#endif

/*
 * Simple implementation of C11 memset_s() function.
 * We use a volatile pointer when updating the byte string.
 * Most compilers will avoid optimizing away access to a
 * volatile pointer, even if the pointer appears to be unused
 * after the call.
 *
 * Note that C11 does not specify the return value on error, only
 * that it be non-zero.  We use EINVAL for all errors.
 */
errno_t
sudo_memset_s(void *v, rsize_t smax, int c, rsize_t n)
{
    errno_t ret = 0;
    volatile unsigned char *s = v;

    /* Fatal runtime-constraint violations. */
    if (s == NULL || smax > RSIZE_MAX) {
	ret = errno = EINVAL;
	goto done;
    }
    /* Non-fatal runtime-constraint violation, n must not exceed smax. */
    if (n > smax) {
	n = smax;
	ret = errno = EINVAL;
    }
    /* Updating through a volatile pointer should not be optimized away. */
    while (n--)
	*s++ = (unsigned char)c;
done:
    return ret;
}
