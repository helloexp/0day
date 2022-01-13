#! /bin/sh

# Shell script to build os.c. There doesn't have to be an OS-specific os.c
# file, but if there is, it gets copied at the start of os.c. The basic src
# copy of os.c contains generic functions, controlled in some cases by
# macro switches so that where they are common to a number of OS, they can
# just be switched in.

scripts=../scripts

# First off, get the OS type, and check that there is a make file for it.

os=`$scripts/os-type -generic` || exit 1

if	test ! -r ../OS/Makefile-$os
then    echo ""
	echo "*** Sorry - operating system $os is not supported"
        echo "*** See OS/Makefile-* for supported systems" 1>&2
        echo ""
	exit 1;
fi

# Now build the file

rm -f os.c
echo '#include "exim.h"' > os.c || exit 1
test -r ../OS/os.c-$os && cat ../OS/os.c-$os >> os.c
echo '#include "../src/os.c"' >> os.c || exit 1

# End of Configure-os.c
