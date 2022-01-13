tpl: fast, easy serialization in C
==============================================================================

Documentation for tpl is available in the doc/ directory or at:

    http://tpl.sourceforge.net

You can build tpl as a library, like so:

    ./configure
    make
    make install

This installs libtpl.so and libtpl.a into a standard system library directory.
You can customize the install directory using configure's "--prefix" option:

    ./configure --prefix=/some/directory

For other options accepted by configure, run "./configure --help".

NON-LIBRARY OPTION
------------------
Alternatively, if you don't want to muck around with libraries, you can simply        
copy these two files into your own C project and build them with your program:

    src/tpl.h
    src/tpl.c

WINDOWS
-------
You can build tpl as a DLL under Visual Studio 2008. Or you can use MinGW or
Cygwin.

SELF-TEST SUITE
---------------
The automated self-test can be run by doing:

    cd tests
    make

LICENSE
-------
The BSD license applies to this software. The text is in the LICENSE file.

CREDITS
-------
Many people have contributed to tpl, both bits of code and ideas. Rather than
listing them all here, at risk of omitting anyone- I just wish to say thank
you. Some particular features are noted with contributors' names in the
ChangeLog. 

Feel free to send me questions, comments or bug reports.

Troy D. Hanson, February 5, 2010 
thanson@users.sourceforge.net

PROFTPD EDITS
--------------

Given a source distribution of libtpl:

  # cp libtpl-<version>/src/tpl.h proftpd-<version>/include/
  # cp libtpl-<version>/src/tpl.c proftpd-<version>/lib/

The following edits were made to the copy of tpl.c, to fix compiler warnings:
All occurrences of:

  #if  __STDC_VERSION__ < 199901

in tpl.c are changed to:

  #if defined(__STDC_VERSION__) &&  __STDC_VERSION__ < 199901

since gcc does not always define the __STDC_VERSION macro.

And the calc_field_addr() function in tpl.c was declared static, since the
compiler was warning about no previous declarations of this function, and
it is only ever called from within tpl.c.

TJ Saunders, January 2011
