/*
 * Copyright (c) 1997-8 Andrew G Morgan <morgan@linux.kernel.org>
 *
 * See end of file for Log.
 *
 * This file deals with allocation and deallocation of internal
 * capability sets as specified by POSIX.1e (formerlly, POSIX 6).
 */

#include "libcap.h"

/*
 * This function duplicates an internal capability set (x3) with
 * Obtain a blank set of capabilities
 */

cap_t cap_init(void)
{
    __u32 *raw_data;
    cap_t result;

    raw_data = malloc( sizeof(__u32) + sizeof(*result) );

    if (raw_data == NULL) {
       _cap_debug("out of memory");
       errno = ENOMEM;
       return NULL;
    }

    *raw_data = CAP_T_MAGIC;
    result = (cap_t) (raw_data + 1);
    memset(result, 0, sizeof(*result));

    result->head.version = _LINUX_CAPABILITY_VERSION_1;

    return result;
}

/*
 * This is an internal library function to duplicate a string and
 * tag the result as something cap_free can handle.
 */

char *_libcap_strdup(const char *old)
{
    __u32 *raw_data;

    if (old == NULL) {
       errno = EINVAL;
       return NULL;
    }

    raw_data = malloc( sizeof(__u32) + strlen(old) + 1 );
    if (raw_data == NULL) {
       errno = ENOMEM;
       return NULL;
    }

    *(raw_data++) = CAP_S_MAGIC;
    strcpy((char *) raw_data, old);

    return ((char *) raw_data);
}

/*
 * This function duplicates an internal capability set with
 * malloc()'d memory. It is the responsibility of the user to call
 * cap_free() to liberate it.
 */

cap_t cap_dup(cap_t cap_d)
{
    cap_t result;

    if (!good_cap_t(cap_d)) {
	_cap_debug("bad argument");
	errno = EINVAL;
	return NULL;
    }

    result = cap_init();
    if (result == NULL) {
	_cap_debug("out of memory");
	return NULL;
    }

    memcpy(result, cap_d, sizeof(*cap_d));

    return result;
}


/*
 * Scrub and then liberate an internal capability set.
 */

int cap_free(void *data_p)
{

    if ( good_cap_t(data_p) ) {
        data_p = -1 + (__u32 *) data_p;
        memset(data_p, 0, sizeof(__u32) + sizeof(struct _cap_struct));
        free(data_p);
        data_p = NULL;
        return 0;
    }

    if ( good_cap_string(data_p) ) {
        int length = strlen(data_p) + sizeof(__u32);
        data_p = -1 + (__u32 *) data_p;
        memset(data_p, 0, length);
        free(data_p);
        data_p = NULL;
        return 0;
    }

    _cap_debug("don't recognize what we're supposed to liberate");
    errno = EINVAL;
    return -1;
}

/*
 * $Log: cap_alloc.c,v $
 * Revision 1.3  2008-08-06 17:00:41  castaglia
 *
 * Bug#3096 - libcap version errors on newer Linux kernel.  Newer Linux kernels
 * have a _LINUX_CAPABILITY_VERSION_2 macro, and redefine the old
 * _LINUX_CAPABILITY_VERSION macro.  To play better with such kernels, redefine
 * the bundled libcap to use _LINUX_CAPABILITY_VERSION_1.
 *
 * Revision 1.2  2003/05/15 00:49:13  castaglia
 *
 * Bug#2000 - mod_cap should not use bundled libcap.  This patch updates the
 * bundled libcap; I won't be closing the bug report just yet.
 *
 * Revision 1.1  2003/01/03 02:16:17  jwm
 *
 * Turning mod_linuxprivs into a core module, mod_cap. This is by no means
 * complete.
 *
 * Revision 1.2  1999/09/07 23:14:19  macgyver
 * Updated capabilities library and model.
 *
 * Revision 1.1.1.1  1999/04/17 22:16:31  morgan
 * release 1.0 of libcap
 *
 * Revision 1.3  1998/05/24 22:54:09  morgan
 * updated for 2.1.104
 *
 * Revision 1.2  1997/04/28 00:57:11  morgan
 * fixes and zefram's patches
 *
 * Revision 1.1  1997/04/21 04:32:52  morgan
 * Initial revision
 *
 */
