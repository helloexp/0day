/*
 * Copyright (c) 1997-8 Andrew G. Morgan <morgan@linux.kernel.org>
 *
 * This is a file to make the capability <-> string mappings for
 * libcap.
 */

#include <stdio.h>
#include <stdlib.h>
#include <linux/capability.h>

/*
 * #include 'sed' generated array
 */

struct {
    int index;
    const char *name;
} const list[] = {
#include "cap_names.sed"
    {-1, NULL}
};

/* this should be more than big enough (factor of three at least) */
const char *pointers[8*sizeof(struct __user_cap_data_struct)];

int main(void)
{
    int i, maxcaps=0;

    for ( i=0; list[i].index >= 0 && list[i].name; ++i ) {
	if (maxcaps <= list[i].index) {
	    maxcaps = list[i].index + 1;
	}
	pointers[list[i].index] = list[i].name;
    }

    printf("/*\n"
	   " * DO NOT EDIT: this file is generated automatically from\n"
	   " *\n"
	   " *     <linux/capability.h>\n"
	   " */\n"
	   "#define __CAP_BITS   %d\n"
	   "\n"
	   "#ifdef LIBCAP_PLEASE_INCLUDE_ARRAY\n"
	   "  char const *_cap_names[__CAP_BITS] = {\n", maxcaps);

    for (i=0; i<maxcaps; ++i) {
	if (pointers[i])
	    printf("      /* %d */\t\"%s\",\n", i, pointers[i]);
	else
	    printf("      /* %d */\tNULL,\t\t/* - presently unused */\n", i);
    }

    printf("  };\n"
	   "#endif /* LIBCAP_PLEASE_INCLUDE_ARRAY */\n"
	   "\n"
	   "/* END OF FILE */\n");

    exit(0);
}

/*
 * $Log: _makenames.c,v $
 * Revision 1.1  2003-01-03 02:16:17  jwm
 *
 * Turning mod_linuxprivs into a core module, mod_cap. This is by no means
 * complete.
 *
 * Revision 1.2  1999/09/07 23:14:19  macgyver
 * Updated capabilities library and model.
 *
 * Revision 1.3  1999/05/14 04:46:15  morgan
 * another attempt to fix the bug Chris Evans found
 *
 * Revision 1.2  1999/05/14 04:38:06  morgan
 * Fix from Chris Evans: off by one error when computing the name array
 *
 * Revision 1.1.1.1  1999/04/17 22:16:31  morgan
 * release 1.0 of libcap
 *
 * Revision 1.4  1998/06/07 15:50:12  morgan
 * updated to accommodate kernel's real header file :*)
 *
 * Revision 1.3  1998/05/24 22:54:09  morgan
 * updated for 2.1.104
 *
 * Revision 1.2  1997/05/04 05:35:46  morgan
 * cleaned up to #include sed output. also generates whole cap_names.c file
 *
 * Revision 1.1  1997/04/28 00:57:11  morgan
 * Initial revision
 *
 */
