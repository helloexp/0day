/*
 * Copyright (c) 1997 Andrew G Morgan <morgan@linux.kernel.org>
 *
 * See end of file for Log.
 *
 * This file contains internal definitions for the various functions in
 * this small capability library.
 */

#ifndef LIBCAP_H
#define LIBCAP_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/sys/capability.h"

#ifndef __u8
#define __u8    unsigned char
#endif /* __8 */

#ifndef __u32
#define __u32   unsigned int
#endif /* __u32 */

/* include the names for the caps and a definition of __CAP_BITS */
#include "cap_names.h"

/*
 * This is a pointer to a struct containing three consecutive
 * capability sets in the order of the cap_flag_t type: the are
 * effective,inheritable and permitted.  This is the type that the
 * user-space routines think of as 'internal' capabilities - this is
 * the type that is passed to the kernel with the system calls related
 * to processes.
 */

#define CAP_T_MAGIC 0xCA90D0
struct _cap_struct {
    struct __user_cap_header_struct head;
    struct __user_cap_data_struct set;
};

/* string magic for cap_free */
#define CAP_S_MAGIC 0xCA95D0

/* Older Linux kernels only define _LINUX_CAPABILITY_VERSION.  Newer Linux
 * kernels use _LINUX_CAPABILITY_VERSION_1 and _LINUX_CAPABILITY_VERSION_2,
 * and define _LINUX_CAPABILITY_VERSION to be _LINUX_CAPABILITY_VERSION_2.
 * This means that, for proper compilation and functioning on the newer
 * kernels, we need to use _LINUX_CAPABILITY_VERSION_1.  But to make sure
 * we still compile on the older Linux kernels, we need to make define
 * our own _LINUX_CAPABILITY_VERSION_1 to be _LINUX_CAPABILITY_VERSION.
 */
#if !defined(_LINUX_CAPABILITY_VERSION_1) && \
     defined(_LINUX_CAPABILITY_VERSION)
# define _LINUX_CAPABILITY_VERSION_1		_LINUX_CAPABILITY_VERSION
#endif

/*
 * Do we match the local kernel?
 */

#if !defined(_LINUX_CAPABILITY_VERSION_1) || \
            (_LINUX_CAPABILITY_VERSION_1 != 0x19980330)

# error "Kernel <linux/capability.h> does not match library"
# error "file "libcap.h" --> fix and recompile libcap"

#endif

/*
 * kernel API cap set abstraction
 */

#define NUMBER_OF_CAP_SETS      3   /* effective, inheritable, permitted */
#define CAP_SET_SIZE (sizeof(struct __user_cap_data_struct)/NUMBER_OF_CAP_SETS)
#define __CAP_BLKS   (CAP_SET_SIZE/sizeof(__u32))
typedef struct {
    __u32 _blk[__CAP_BLKS];
} __cap_s;
#define raise_cap(x)   _blk[(x)>>5] |= (1<<((x)&31))
#define lower_cap(x)   _blk[(x)>>5] &= ~(1<<((x)&31))
#define isset_cap(y,x) ((y)->_blk[(x)>>5] & (1<<((x)&31)))

/*
 * Private definitions for internal use by the library.
 */

#define __libcap_check_magic(c,magic) ((c) && *(-1+(__u32 *)(c)) == (magic))
#define good_cap_t(c)        __libcap_check_magic(c, CAP_T_MAGIC)
#define good_cap_string(c)   __libcap_check_magic(c, CAP_S_MAGIC)

/*
 * library debugging
 */
#ifdef DEBUG

#include <stdio.h>
# define _cap_debug(f, x...)  { \
    fprintf(stderr, __FUNCTION__ "(" __FILE__ ":%d): ", __LINE__); \
    fprintf(stderr, f, ## x); \
    fprintf(stderr, "\n"); \
}
# define _cap_debugcap(s, c) \
    fprintf(stderr, __FUNCTION__ "(" __FILE__ ":%d): " s \
       "%08x\n", __LINE__, *(c))

#else /* !DEBUG */

# define _cap_debug(f, x...)
# define _cap_debugcap(s, c)

#endif /* DEBUG */

extern char *_libcap_strdup(const char *text);

/*
 * These are semi-public prototypes, they will only be defined in
 * <sys/capability.h> if _POSIX_SOURCE is not #define'd, so we
 * place them here too.
 */

extern int capset(cap_user_header_t header, cap_user_data_t data);
extern int capget(cap_user_header_t header, const cap_user_data_t data);
extern int capgetp(pid_t pid, cap_t cap_d);
extern int capsetp(pid_t pid, cap_t cap_d);

#endif /* LIBCAP_H */

/*
 * $Log: libcap.h,v $
 * Revision 1.5  2008-08-23 02:49:48  castaglia
 *
 * Fix typo (missing backslash).
 *
 * Revision 1.4  2008/08/22 16:35:52  castaglia
 *
 * Try to handle the change in Linux capability version macro names for
 * older kernels (which don't define/use the new names).
 *
 * Revision 1.3  2008/08/06 17:00:41  castaglia
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
 * Revision 1.2  1999/04/17 23:25:10  morgan
 * fixes from peeterj
 *
 * Revision 1.1.1.1  1999/04/17 22:16:31  morgan
 * release 1.0 of libcap
 *
 * Revision 1.5  1998/06/08 00:15:28  morgan
 * accommodate alpha (glibc?)
 *
 * Revision 1.4  1998/06/07 15:58:23  morgan
 * accommodate real kernel header files :*)
 *
 * Revision 1.3  1998/05/24 22:54:09  morgan
 * updated for 2.1.104
 *
 * Revision 1.2  1997/04/28 00:57:11  morgan
 * zefram's replacement file with a number of bug fixes from AGM
 *
 * Revision 1.1  1997/04/21 04:32:52  morgan
 * Initial revision
 *
 */
