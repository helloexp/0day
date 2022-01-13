/*
 * Copyright (c) 1997 Andrew G Morgan <morgan@linux.kernel.org>
 *
 * See end of file for Log.
 *
 * This file deals with setting capabilities on files.
 */

#include "libcap.h"

/*
 * Get the capabilities of an open file, as specified by its file
 * descriptor.
 */

cap_t cap_get_fd(int fildes)
{
    cap_t result;

    /* allocate a new capability set */
    result = cap_init();
    if (result) {
	_cap_debug("getting fildes capabilities");

	/* fill the capability sets via a system call */
	if (_fgetfilecap(fildes, sizeof(struct __cap_s),
			      &result->set[CAP_INHERITABLE],
			      &result->set[CAP_PERMITTED],
			      &result->set[CAP_EFFECTIVE] )) {
	    cap_free(&result);
	}
    }

    return result;
}

/*
 * Set the capabilities on a named file.
 */

cap_t cap_get_file(const char *filename)
{
    cap_t result;

    /* allocate a new capability set */
    result = cap_init();
    if (result) {
	_cap_debug("getting named file capabilities");

	/* fill the capability sets via a system call */
	if (_getfilecap(filename, sizeof(struct __cap_s),
			     &result->set[CAP_INHERITABLE],
			     &result->set[CAP_PERMITTED],
			     &result->set[CAP_EFFECTIVE] ))
	    cap_free(&result);
    }

    return result;
}

/*
 * Set the capabilities of an open file, as specified by its file
 * descriptor.
 */

int cap_set_fd(int fildes, cap_t cap_d)
{
    if (!good_cap_t(cap_d)) {
	errno = EINVAL;
	return -1;
    }

    _cap_debug("setting fildes capabilities");
    return _fsetfilecap(fildes, sizeof(struct __cap_s),
			  &cap_d->set[CAP_INHERITABLE],
			  &cap_d->set[CAP_PERMITTED],
			  &cap_d->set[CAP_EFFECTIVE] );
}

/*
 * Set the capabilities of a named file.
 */

int cap_set_file(const char *filename, cap_t cap_d)
{
    if (!good_cap_t(cap_d)) {
	errno = EINVAL;
	return -1;
    }

    _cap_debug("setting filename capabilities");
    return _setfilecap(filename, sizeof(struct __cap_s),
			  &cap_d->set[CAP_INHERITABLE],
			  &cap_d->set[CAP_PERMITTED],
			  &cap_d->set[CAP_EFFECTIVE] );
}

/*
 * $Log: cap_file.c,v $
 * Revision 1.1  2003-01-03 02:16:17  jwm
 *
 * Turning mod_linuxprivs into a core module, mod_cap. This is by no means
 * complete.
 *
 * Revision 1.1  1999/09/07 23:14:19  macgyver
 * Updated capabilities library and model.
 *
 * Revision 1.1.1.1  1999/04/17 22:16:31  morgan
 * release 1.0 of libcap
 *
 * Revision 1.5  1998/05/24 22:54:09  morgan
 * updated for 2.1.104
 *
 * Revision 1.4  1997/05/14 05:17:13  morgan
 * bug-fix from zefram (errno no set on success)
 *
 * Revision 1.3  1997/05/04 05:35:46  morgan
 * fixed errno setting. syscalls do this part
 *
 * Revision 1.2  1997/04/28 00:57:11  morgan
 * fixes and zefram's patches
 *
 * Revision 1.1  1997/04/21 04:32:52  morgan
 * Initial revision
 *
 */
