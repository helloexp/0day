/*
 * Copyright (c) 1997-8 Andrew G Morgan <morgan@linux.kernel.org>
 *
 * See end of file for Log.
 *
 * This file deals with exchanging internal and external
 * representations of capability sets.
 */

#include "libcap.h"

/*
 * External representation for capabilities. (exported as a fixed
 * length (void *))
 */
#define CAP_EXT_MAGIC "\220\302\001\121"
#define CAP_EXT_MAGIC_SIZE 4
const static __u8 external_magic[CAP_EXT_MAGIC_SIZE+1] = CAP_EXT_MAGIC;

struct cap_ext_struct {
    __u8 magic[CAP_EXT_MAGIC_SIZE];
    __u8 length_of_capset;
/* note, we arrange these so the caps are stacked with byte-size
   resolution */
    __u8 bytes[CAP_SET_SIZE][NUMBER_OF_CAP_SETS];
};

/*
 * return size of external capability set
 */

ssize_t cap_size(cap_t caps)
{
    return sizeof(struct cap_ext_struct);
}

/*
 * Copy the internal (cap_d) capability set into an external
 * representation.  The external representation is portable to other
 * Linux architectures.
 */

ssize_t cap_copy_ext(void *cap_ext, cap_t cap_d, ssize_t length)
{
    struct cap_ext_struct *result = (struct cap_ext_struct *) cap_ext;
    __u32 *from = (__u32 *) &(cap_d->set);
    int i;

    /* valid arguments? */
    if (!good_cap_t(cap_d) || length < sizeof(struct cap_ext_struct)
	|| cap_ext == NULL) {
	errno = EINVAL;
	return -1;
    }

    /* fill external capability set */
    memcpy(&result->magic, external_magic, CAP_EXT_MAGIC_SIZE);
    result->length_of_capset = CAP_SET_SIZE;

    for (i=0; i<NUMBER_OF_CAP_SETS; ++i) {
	int j;
	for (j=0; j<CAP_SET_SIZE; ) {
	    __u32 val = *from++;

	    result->bytes[j++][i] =  val        & 0xFF;
	    result->bytes[j++][i] = (val >>= 8) & 0xFF;
	    result->bytes[j++][i] = (val >>= 8) & 0xFF;
	    result->bytes[j++][i] = (val >> 8)  & 0xFF;
	}
    }

    /* All done: return length of external representation */
    return (sizeof(struct cap_ext_struct));
}

/*
 * Import an external representation to produce an internal rep.
 * the internal rep should be liberated with cap_free().
 */

/*
 * XXX - need to take a little more care when importing small
 * capability sets.
 */

cap_t cap_copy_int(const void *cap_ext)
{
    const struct cap_ext_struct *export =
	(const struct cap_ext_struct *) cap_ext;
    cap_t cap_d = NULL;
    int set, blen;
    __u32 * to = (__u32 *) &cap_d->set;

    /* Does the external representation make sense? */
    if (export == NULL || !memcmp(export->magic, external_magic
				  , CAP_EXT_MAGIC_SIZE)) {
	errno = EINVAL;
	return NULL;
    }

    /* Obtain a new internal capability set */
    if (!(cap_d = cap_init()))
       return NULL;

    blen = export->length_of_capset;
    for (set=0; set<=NUMBER_OF_CAP_SETS; ++set) {
	int blk;
	int bno = 0;
	for (blk=0; blk<(CAP_SET_SIZE/4); ++blk) {
	    __u32 val = 0;

	    if (bno != blen)
		val  = export->bytes[bno++][set];
	    if (bno != blen)
		val |= export->bytes[bno++][set] << 8;
	    if (bno != blen)
		val |= export->bytes[bno++][set] << 16;
	    if (bno != blen)
		val |= export->bytes[bno++][set] << 24;

	    *to++ = val;
	}
    }

    /* all done */
    return cap_d;
}

/*
 * $Log: cap_extint.c,v $
 * Revision 1.1  2003-01-03 02:16:17  jwm
 *
 * Turning mod_linuxprivs into a core module, mod_cap. This is by no means
 * complete.
 *
 * Revision 1.3  1999/09/17 03:54:08  macgyver
 * Corrected gcc warning.
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
