/*
 * Copyright (c) 1997-8 Andrew G. Morgan <morgan@linux.kernel.org>
 *
 * See end of file for Log.
 *
 * This file deals with flipping of capabilities on internal
 * capability sets as specified by POSIX.1e (formerlly, POSIX 6).
 */

#include "libcap.h"

/*
 * Return the state of a specified capability flag.  The state is
 * returned as the contents of *raised.  The capability is from one of
 * the sets stored in cap_d as specified by set and value
 */

int cap_get_flag(cap_t cap_d, cap_value_t value, cap_flag_t set,
		 cap_flag_value_t *raised)
{
    /*
     * Do we have a set and a place to store its value?
     * Is it a known capability?
     */

    if (raised && good_cap_t(cap_d) && value >= 0 && value < __CAP_BITS
	&& set >= 0 && set < NUMBER_OF_CAP_SETS) {
	__cap_s *cap_p = (__cap_s *) (set*CAP_SET_SIZE
				      + (__u8 *) &cap_d->set);

	*raised = isset_cap(cap_p,value) ? CAP_SET:CAP_CLEAR;
	return 0;

    } else {

	_cap_debug("invalid arguments");
	errno = EINVAL;
	return -1;

    }
}

/*
 * raise/lower a selection of capabilities
 */

int cap_set_flag(cap_t cap_d, cap_flag_t set,
		 int no_values, cap_value_t *array_values,
		 cap_flag_value_t raise)
{
    /*
     * Do we have a set and a place to store its value?
     * Is it a known capability?
     */

    if (good_cap_t(cap_d) && no_values > 0 && no_values <= __CAP_BITS
	&& (set >= 0) && (set < NUMBER_OF_CAP_SETS)
	&& (raise == CAP_SET || raise == CAP_CLEAR) ) {
	int i;
	for (i=0; i<no_values; ++i) {
	    if (array_values[i] < 0 || array_values[i] >= __CAP_BITS) {
		_cap_debug("weird capability (%d) - skipped", array_values[i]);
	    } else {
		int value = array_values[i];
		__cap_s *cap_p = (__cap_s *) (set*CAP_SET_SIZE
					      + (__u8 *) &cap_d->set);

		if (raise == CAP_SET) {
		    cap_p->raise_cap(value);
		} else {
		    cap_p->lower_cap(value);
		}
	    }
	}
	return 0;

    } else {

	_cap_debug("invalid arguments");
	errno = EINVAL;
	return -1;

    }
}

/*
 *  Reset the capability to be empty (nothing raised)
 */

int cap_clear(cap_t cap_d)
{
    if (good_cap_t(cap_d)) {

	memset(&(cap_d->set), 0, sizeof(cap_d->set));
	return 0;

    } else {

	_cap_debug("invalid pointer");
	errno = EINVAL;
	return -1;

    }
}

/*
 * $Log: cap_flag.c,v $
 * Revision 1.1  2003-01-03 02:16:17  jwm
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
 * Revision 1.4  1998/09/20 23:07:59  morgan
 * fixed lower bound check on 'set'.
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
