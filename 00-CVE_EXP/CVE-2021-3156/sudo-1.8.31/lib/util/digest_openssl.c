/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2013-2018 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <fcntl.h>
#include <errno.h>

#include <openssl/sha.h>

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_digest.h"

union ANY_CTX {
    SHA256_CTX sha256;
    SHA512_CTX sha512;
};

static struct digest_function {
    const unsigned int digest_len;
    int (*init)(union ANY_CTX *);
    int (*update)(union ANY_CTX *, const void *, size_t);
    int (*final)(unsigned char *, union ANY_CTX *);
} digest_functions[] = {
    {
	SHA224_DIGEST_LENGTH,
	(int (*)(union ANY_CTX *))SHA224_Init,
	(int (*)(union ANY_CTX *, const void *, size_t))SHA224_Update,
	(int (*)(unsigned char *, union ANY_CTX *))SHA224_Final
    }, {
	SHA256_DIGEST_LENGTH,
	(int (*)(union ANY_CTX *))SHA256_Init,
	(int (*)(union ANY_CTX *, const void *, size_t))SHA256_Update,
	(int (*)(unsigned char *, union ANY_CTX *))SHA256_Final
    }, {
	SHA384_DIGEST_LENGTH,
	(int (*)(union ANY_CTX *))SHA384_Init,
	(int (*)(union ANY_CTX *, const void *, size_t))SHA384_Update,
	(int (*)(unsigned char *, union ANY_CTX *))SHA384_Final
    }, {
	SHA512_DIGEST_LENGTH,
	(int (*)(union ANY_CTX *))SHA512_Init,
	(int (*)(union ANY_CTX *, const void *, size_t))SHA512_Update,
	(int (*)(unsigned char *, union ANY_CTX *))SHA512_Final
    }, {
	0
    }
};

struct sudo_digest {
    struct digest_function *func;
    union ANY_CTX ctx;
};

struct sudo_digest *
sudo_digest_alloc_v1(int digest_type)
{
    debug_decl(sudo_digest_alloc, SUDO_DEBUG_UTIL)
    struct digest_function *func = NULL;
    struct sudo_digest *dig;
    int i;

    for (i = 0; digest_functions[i].digest_len != 0; i++) {
	if (digest_type == i) {
	    func = &digest_functions[i];
	    break;
	}
    }
    if (func == NULL) {
	errno = EINVAL;
	debug_return_ptr(NULL);
    }

    if ((dig = malloc(sizeof(*dig))) == NULL)
	debug_return_ptr(NULL);
    func->init(&dig->ctx);
    dig->func = func;

    debug_return_ptr(dig);
}

void
sudo_digest_free_v1(struct sudo_digest *dig)
{
    debug_decl(sudo_digest_free, SUDO_DEBUG_UTIL)

    free(dig);

    debug_return;
}

void
sudo_digest_reset_v1(struct sudo_digest *dig)
{
    debug_decl(sudo_digest_reset, SUDO_DEBUG_UTIL)

    dig->func->init(&dig->ctx);

    debug_return;
}
int
sudo_digest_getlen_v1(int digest_type)
{
    debug_decl(sudo_digest_getlen, SUDO_DEBUG_UTIL)
    int i;

    for (i = 0; digest_functions[i].digest_len != 0; i++) {
	if (digest_type == i)
	    debug_return_int(digest_functions[i].digest_len);
    }

    debug_return_int(-1);
}

void
sudo_digest_update_v1(struct sudo_digest *dig, const void *data, size_t len)
{
    debug_decl(sudo_digest_update, SUDO_DEBUG_UTIL)

    dig->func->update(&dig->ctx, data, len);

    debug_return;
}

void
sudo_digest_final_v1(struct sudo_digest *dig, unsigned char *md)
{
    debug_decl(sudo_digest_final, SUDO_DEBUG_UTIL)

    dig->func->final(md, &dig->ctx);

    debug_return;
}
