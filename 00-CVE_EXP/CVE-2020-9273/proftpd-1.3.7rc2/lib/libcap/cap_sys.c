/*
 * Copyright (c) 1997-8 Andrew G. Morgan   <morgan@linux.kernel.org>
 *
 * This file contains the system calls for getting and setting
 * capabilities
 */

#include "libcap.h"
#define __LIBRARY__
#include <linux/unistd.h>

/*
 * $Log: cap_sys.c,v $
 * Revision 1.2  2005-01-25 19:30:55  castaglia
 *
 * Bug#2503 - Bundled libcap library does not compile on IA64 machine.
 *
 * Revision 1.1  2003/01/03 02:16:17  jwm
 *
 * Turning mod_linuxprivs into a core module, mod_cap. This is by no means
 * complete.
 *
 * Revision 1.3  1999/09/07 23:14:19  macgyver
 * Updated capabilities library and model.
 *
 * Revision 1.1.1.1  1999/04/17 22:16:31  morgan
 * release 1.0 of libcap
 *
 * Revision 1.4  1998/06/08 00:14:01  morgan
 * change to accommodate alpha (glibc?)
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
