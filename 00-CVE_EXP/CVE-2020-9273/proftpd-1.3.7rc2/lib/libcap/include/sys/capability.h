/*
 * <sys/capability.h>
 *
 * 
 * Copyright (C) 1997   Aleph One
 * Copyright (C) 1997-8 Andrew G. Morgan <morgan@linux.kernel.org>
 *
 * defunct POSIX.1e Standard: 25.2 Capabilities           <sys/capability.h>
 */

#ifndef _SYS_CAPABILITY_H
#define _SYS_CAPABILITY_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file complements the kernel file by providing prototype
 * information for the user library.
 */

#define _LINUX_FS_H
#include <sys/types.h>
#include <linux/capability.h>

/*
 * POSIX capability types
 */

/*
 * Opaque capability handle (defined internally by libcap)
 * internal capability representation
 */
typedef struct _cap_struct *cap_t;

/* "external" capability representation is a (void *) */

/*
 * This is the type used to identify capabilities
 */

typedef int cap_value_t;

/*
 * Set identifiers
 */
typedef enum {
    CAP_EFFECTIVE=0,                        /* Specifies the effective flag */
    CAP_PERMITTED=1,                        /* Specifies the permitted flag */
    CAP_INHERITABLE=2                     /* Specifies the inheritable flag */
} cap_flag_t;

/*
 * These are the states available to each capability
 */
typedef enum {
    CAP_CLEAR=0,                            /* The flag is cleared/disabled */
    CAP_SET=1                                    /* The flag is set/enabled */
} cap_flag_value_t;

/*
 * User-space capability manipulation routines
 */

/* libcap/cap_alloc.c */
cap_t   cap_dup(cap_t);
int     cap_free(void *);
cap_t   cap_init(void);

/* libcap/cap_flag.c */
int     cap_get_flag(cap_t, cap_value_t, cap_flag_t, cap_flag_value_t *);
int     cap_set_flag(cap_t, cap_flag_t, int, cap_value_t *, cap_flag_value_t);
int     cap_clear(cap_t);

/* libcap/cap_file.c */
cap_t   cap_get_fd(int);
cap_t   cap_get_file(const char *);
int     cap_set_fd(int, cap_t);
int     cap_set_file(const char *, cap_t);

/* libcap/cap_proc.c */
cap_t   cap_get_proc(void);
int     cap_set_proc(cap_t);

/* libcap/cap_extint.c */
ssize_t cap_size(cap_t);
ssize_t cap_copy_ext(void *, cap_t, ssize_t);
cap_t   cap_copy_int(const void *);

/* libcap/cap_text.c */
cap_t   cap_from_text(const char *);
char *  cap_to_text(cap_t, ssize_t *);

/*
 * Linux capability system calls: defined in libcap but only available
 * if the following _POSIX_SOURCE is _undefined_
 */

#if !defined(_POSIX_SOURCE)

extern int capset(cap_user_header_t header, cap_user_data_t data);
extern int capget(cap_user_header_t header, const cap_user_data_t data);
extern int capgetp(pid_t pid, cap_t cap_d);
extern int capsetp(pid_t pid, cap_t cap_d);
extern char const *_cap_names[];

#endif /* !defined(_POSIX_SOURCE) */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_CAPABILITY_H */
