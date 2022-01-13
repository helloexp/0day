THE EXIM MAIL TRANSFER AGENT VERSION 4
--------------------------------------

Copyright (c) 1995 - 2018 University of Cambridge.
See the file NOTICE for conditions of use and distribution.

There is a book about Exim by Philip Hazel called "The Exim SMTP Mail Server",
published by UIT Cambridge in May 2003. This is the official guide for Exim 4.
The current edition covers release 4.10 and a few later extensions.

The O'Reilly book about Exim ("Exim The Mail Transfer Agent" by Philip Hazel)
covers Exim 3, which is now deprecated. Exim 4 has a large number of changes
from Exim 3, though the basic structure and philosophy remains the same. The
older book may be helpful for the background, but a lot of the detail has
changed, so it is likely to be confusing to newcomers.

There is a website at https://www.exim.org; this contains details of the
mailing list exim-users@exim.org.

A copy of the Exim FAQ should be available from the same source that you used
to obtain the Exim distribution. Additional formats for the documentation
(PostScript, PDF, Texinfo, and HTML) should also be available there.


EXIM DISTRIBUTION
-----------------

Unpacking the tar file should produce a single directory called exim-<version>,
containing the following files and directories:

ACKNOWLEDGMENTS  some acknowledgments
CHANGES          a conventional file name; it indirects to some files in doc/
LICENCE          the GNU General Public Licence
Local/           an empty directory for local configuration files
Makefile         top level Makefile
NOTICE           notice about conditions of use
OS/              directory containing OS-specific files
README           this file
README.UPDATING  special notes about updating from previous versions
doc/             directory of documentation files
exim_monitor/    directory of source files for the Exim monitor
scripts/         directory of scripts used in the build process
src/             directory of source files
util/            directory of independent utilities

Please see the documentation files for full instructions on how to build,
install, and run Exim. For straightforward installations on operating systems
to which Exim has already been ported, the building process is as follows:

. Ensure that the top-level Exim directory (e.g. exim-4.80) is the current
  directory (containing the files and directories listed above).

. Edit the file called src/EDITME and put the result in a new file called
  Local/Makefile. There are comments in src/EDITME telling you what the various
  parameters are. You must at least provide values for BIN_DIRECTORY,
  CONFIGURE_FILE, EXIM_USER and EXIM_GROUP (if EXIM_USER is numeric), and it is
  recommended that SPOOL_DIRECTORY also be defined here if it is a fixed path.

. There are a number of additional parameters whose defaults can also be
  overridden by additions to Local/Makefile. The basic defaults are in
  OS/Makefile-Default, but these settings are overridden for some operating
  systems by values on OS/Makefile-<osname>. The most commonly-required change
  is probably the setting of CC, which defines the command to run the C
  compiler, and which defaults to gcc. To change it to cc, add the following
  line to Local/Makefile:

  CC=cc

  If you are running the Berkeley DB package as your dbm library, then it is
  worth putting USE_DB=yes in Local/Makefile, to get Exim to use the native
  interface. This is the default for some operating systems. See
  doc/dbm.discuss.txt for discussion on dbm libraries.

. If you want to compile the Exim monitor, edit the file called
  exim_monitor/EDITME and put the result in a file called Local/eximon.conf.
  If you are not going to compile the Exim monitor, you should have commented
  out the line starting EXIM_MONITOR= when creating Local/Makefile. There are
  comments in exim_monitor/EDITME about the values set therein, but in this
  case everything can be defaulted if you wish.

. If your system is not POSIX compliant by default, then you might experience
  fewer problems if you help point the build tools to the POSIX variants. For
  instance, on Solaris:

  PATH=/usr/xpg4/bin:$PATH make SHELL=/usr/xpg4/bin/sh

. Type "make". This will determine what your machine's architecture and
  operating system are, and create a build directory from those names (e.g.
  "build-SunOS5-sparc"). Symbolic links are created from the build directory
  to the source directory. A configured make file called <build-dir>/makefile
  is then created, and "make" then goes on to use this to build various
  binaries and scripts inside the build directory.

. Type "make install", while running as root, to install the binaries,
  scripts, and a default configuration file. To see what this command is
  going to do before risking it, run "../scripts/exim_install -n" (not as
  root) from within the build directory.

. When you are ready to try running Exim, see the section entitled "Testing"
  in the chapter called "Building and Installing Exim" in doc/spec.txt, or in
  one of the other forms of the documentation.

. Running the install script does NOT replace /usr/sbin/sendmail or
  /usr/lib/sendmail with a link to Exim. That step you must perform by hand
  when you are satisfied that Exim is running correctly.

. Note that the default configuration refers to an alias file called
  /etc/aliases. It used to be the case that every Unix had that file, because
  it was the Sendmail default. These days, there are systems that don't have
  /etc/aliases, so you might need to set it up. Your aliases should at least
  include an alias for "postmaster".

. Consider notifying users of the change of MTA. Exim has different
  capabilities, and there are various operational differences, such as stricter
  adherence to the RFCs than some MTAs, and differences in the text of
  messages produced by various command-line options.

. The default configuration file will use your host's fully qualified name (as
  obtained from the uname() function) as the only local mail domain and as the
  domain which is used to qualify unqualified local mail addresses. See the
  comments in the default configuration file if you want to change these.

The operating systems currently supported are: AIX, BSD/OS (aka BSDI), Darwin
(Mac OS X), DGUX, FreeBSD, GNU/Hurd, GNU/Linux, HI-OSF (Hitachi), HP-UX, IRIX,
MIPS RISCOS, NetBSD, OpenBSD, QNX, SCO, SCO SVR4.2 (aka UNIX-SV), Solaris (aka
SunOS5), SunOS4, Tru64-Unix (formerly Digital Unix, formerly DEC-OSF1), Ultrix,
and Unixware. However, code is not available for determining system load
averages on Ultrix. There are also configuration files for compiling Exim in
the Cygwin environment that can be installed on systems running Windows.
However, the documentation supplied with the distribution does not contain any
information about running Exim in the Cygwin environment.


******* Modifying the building process ******

Instructions for overriding the build-time options for Exim are given in the
manual. You should never have to modify any of the supplied files; it should be
possible to override everything that is necessary by creating suitable files in
the Local directory. This means that you won't need to redo your modifications
for the next release of Exim. If you find you can't avoid changing some other
file, let me know and I'll see if I can find a way of making that unnecessary.

Briefly, the building process concatenates a number of files in order to
construct its working makefile. If <ostype> and <archtype> are the operating
system and architecture types respectively, the files used are:

  OS/Makefile-Default
  OS/Makefile-<ostype>
  Local/Makefile
  Local/Makefile-<ostype>
  Local/Makefile-<archtype>
  Local/Makefile-<ostype>-<archtype>
  OS/Makefile-Base

Of the Local/* files, only Local/Makefile is required to exist; the rest are
optional. Because of the way "make" works, values set in later files override
values set in earlier ones. Thus you can set up general options that are
overridden for specify operating systems and/or architectures if you wish.


******* IMPORTANT FOR GNU/LINUX USERS *******

Exim 4 won't work with some versions of Linux if you put its spool directory on
an NFS partition. You get an error about "directory sync failed". This is
because of a bug in Linux NFS. A fix has been promised in due course. It is in
any case much better to put Exim's spool directory on local disc.

If you get an error complaining about the lack of functions such as dbm_open()
when building Exim, the problem is that it hasn't been able to find a DBM
library. See the file doc/dbm.discuss.txt for a discussion about the various
DBM libraries.

Different versions of Linux come with different DBM libraries, stored in
different places. As well as setting USE_DB=yes in Local/Makefile if Berkeley
DB is in use, it may also be necessary to set a value in DBMLIB to specify the
inclusion of the DBM library, for example: DBMLIB=-ldb or DBMLIB=-lgdbm.

If you are using RedHat 7.0, which has DB3 as its DBM library, you need to
install the db-devel package before building Exim. This will have a name like
db3-devel-3.1.14-16.i386.rpm (but check which release of DB3 you have).

The building scripts now distinguish between versions of Linux with the older
libc5 and the more recent ones that use libc6. In the latter case, USE_DB and
-ldb are the default settings, because DB is standard with libc6.

It appears that with glibc-2.1.x (a minor libc upgrade), they have standardised
on Berkeley DB2 (instead of DB1 in glibc-2.0.x). If you want to get DB1 back,
you need to set

  INCLUDE=-I/usr/include/db1
  DBMLIB=-ldb1

in your Local/Makefile. If you omit DBMLIB=-ldb1 Exim will link successfully
using the DB1 compatibility interface to DB2, but it will expect the file
format to be that of DB2, and so will not be able to read existing DB1 files.


******* IMPORTANT FOR FREEBSD USERS *******

On FreeBSD there is a file called /etc/mail/mailer.conf which selects what to
run for various MTA calls. Instead of changing /usr/sbin/sendmail, you should
edit this file instead, to read something like this:

sendmail          /usr/exim/bin/exim
send-mail         /usr/exim/bin/exim
mailq             /usr/exim/bin/exim -bp
newaliases        /usr/bin/true

You will most probably need to add the line:

daily_status_include_submit_mailq="NO"  # No separate 'submit' queue

to /etc/periodic.conf. This stops FreeBSD running the command "mailq -Ac"
(which Exim doesn't understand) to list a separate submit queue (which Exim
doesn't have).

If you are using FreeBSD prior to 3.0-RELEASE, and you are not using the ports
mechanism to install Exim, then you should install the perl5 package
(/usr/local/bin/perl) and use that instead of perl in the base system, which is
perl4 up until 3.0-RELEASE. If you are using the ports mechanism, this is
handled for you.

If you are upgrading from version 2.11 of Exim or earlier, and you are using
DBM files, and you did not previously have USE_DB=yes in your Local/Makefile,
then you will either have to put USE_DB=no in your Local/Makefile or (better)
rebuild your DBM data files. The default for FreeBSD has been changed to
USE_DB=yes, since FreeBSD comes with Berkeley DB. However, using the native DB
interface means that the data files no longer have the ".db" extension.



******* IMPORTANT FOR Tru64 (aka Digital Unix aka DEC-OSF1) USERS *******

The default compiler may not recognize ANSI C by default. You may have to set

CC=cc
CFLAGS=-std1

in Local/Makefile in order to compile Exim. A user reported another small
problem with this operating system: In the file /usr/include/net/if.h a
semicolon was missing at the end of line 143.



******* IMPORTANT FOR SCO USERS *******

The building scripts assume the existence of the "ar" command, which is part of
the Development System. However, it is also possible to use the "gar" command
that is part of the GNU utilities that are distributed with the 5.0.7 release.
If you have "gar" and not "ar" you should include

AR=gar

in your Local/Makefile.



******* IMPORTANT FOR Unixware 2.x USERS *******

Unixware does not include db/dbm/ndbm with its standard compiler (it is
available with /usr/ucb/cc, but that has bugs of its own). You should install
gcc and Berkeley DB (or another dbm library if you really insist). If you use a
different dbm library you will need to override the default setting of DBMLIB.

DB 1.85 and 2.x can be found at http://www.sleepycat.com/. They have different
characteristics. See the discussion of dbm libraries in doc/dbm.discuss.txt. DB
needs to be compiled with gcc and you need a 'cc' in your path before the
Unixware CC to compile it.

Don't bother even starting to install exim on Unixware unless you have
installed gcc and use it for everything.


******* IMPORTANT FOR SOLARIS 2.3 (SUNOS 5.3) USERS *******

The file /usr/include/sysexits.h does not exist on Solaris 2.3 (and presumably
earlier versions), though it is present in 2.4 and later versions. To compile
Exim on Solaris 2.3 it is necessary to include the line

CFLAGS=-O -DNO_SYSEXITS -DEX_TEMPFAIL=75

in your Local/Makefile.


******* IMPORTANT FOR IRIX USERS *******

There are problems with some versions of gcc on IRIX, as a result of which all
DNS lookups yield either 0.0.0.0 or 255.255.255.255. Releases of gcc after
2.7.2.3 (which works ok) are affected. Specifically, 2.8.* is affected, as are
the 2.95 series. From release 3.21 of Exim, a workaround for this problem
should automatically be enabled when Exim is compiled on IRIX using gcc.

As from version 2.03 there is IRIX-specific code in Exim to obtain a list of
all the IP addresses on local interfaces, including alias addresses, because
the standard code gives only non-alias addresses in IRIX. The code came from
SGI, with the comment:

"On 6.2 you need the libc patch to get the sysctl() stub and the networking
kernel patch to get the support."

It seems that this code doesn't work on at least some earlier versions of IRIX
(e.g. IRIX 5.3). If you can't compile under IRIX and the problem appears to
relate to sysctl(), try commenting or #ifdef-ing out all the code in the
file OS/os.c-IRIX.


******* IMPORTANT FOR HP-UX USERS *******

There are two different sets of configuration files for HP-UX. Those ending in
HP-UX-9 are used for HP-UX version 9, and have been tested on HP-UX version
9.05. Those ending in HP-UX are for later releases, and have been tested on
HP-UX version 11.00. If you are using a version of HP-UX between 9.05 and
11.00, you may need to edit the file OS/os.h-HP-UX if you encounter problems
building Exim.

If you want to use the Sieve facility in Exim, the alias iso-8859-1 should be
added to the alias definition for iso81 in /usr/lib/nls/iconv/config.iconv. You
also need to add a new alias definition: "alias utf8 utf-8".


******* IMPORTANT FOR QNX USERS *******

1. Exim makes some assumptions about the shell in the makefiles. The "normal"
   QNX shell (ksh) will not work. You need to install "bash", which can be
   obtained from the QNX freeware on QUICS. Install it to /usr/local/bin/bash
   Then you need to change the SHELL definition at the top of the main Makefile
   to SHELL=/usr/local/bin/bash. The file OS/Makefile-QNX sets the variable
   MAKE_SHELL to /usr/local/bin/bash. If you install bash in a different place,
   you will need to set MAKE_SHELL in your Local/Makefile in order to override
   this.

2. For some strange reason make will fail at building "exim_dbmbuild" when
   called the first time. However simply calling make a second time will solve
   the problem. Alternatively, run "make makefile" and then "make".


******* IMPORTANT FOR ULTRIX USERS *******

You need to set SHELL explicitly in the make call when building on ULTRIX,
that is, type "make SHELL=sh5".


******* IMPORTANT FOR GNU/HURD USERS *******

GNU/Hurd doesn't (at the time of writing, June 1999) have the ioctls for
finding out the IP addresses of the local interfaces. You therefore have to set
local_interfaces yourself. Otherwise it will treat only 127.0.0.1 as local.

Philip Hazel
