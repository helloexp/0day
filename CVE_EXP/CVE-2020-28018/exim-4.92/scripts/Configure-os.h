#! /bin/sh

# Shell script to create a link to the appropriate OS-specific header file.

scripts=../scripts

# Get the OS type, and check that there is a make file for it.

os=`$scripts/os-type -generic` || exit 1

if	test ! -r ../OS/Makefile-$os
then    echo ""
	echo "*** Sorry - operating system $os is not supported"
        echo "*** See OS/Makefile-* for supported systems" 1>&2
        echo ""
	exit 1;
fi

# Ensure there is an OS-specific header file, and link it to os.h. There should
# always be one if there is a make file for the OS, so its absence is somewhat
# disastrous.

if	test ! -r ../OS/os.h-$os
then    echo ""
	echo "*** Build error: OS/os.h-$os file is missing"
        echo ""
	exit 1;
fi
rm -f os.h

# In order to accommodate for the fudge below, copy the file instead of
# symlinking it. Otherwise we pollute the clean copy with the fudge.
cp -p ../OS/os.h-$os os.h || exit 1

# Special-purpose fudge for older versions of Linux (pre 2.1.15) that
# use the structure name "options" instead of "ip_options".

if [ "$os" != "Linux" -a "$os" != "Linux-libc5" ] ; then exit 0; fi

grep ip_options /usr/include/linux/ip.h >/dev/null
if [ $? = 0 ] ; then exit 0; fi

cat >>os.h <<End

/* Fudge added because this Linux doesn't appear to have a definition
for ip_options in /usr/include/linux/ip.h. */

#define ip_options options
End

# End of Configure-os.h
