ProFTPD 1.3.x README
====================

Status
------
[![Build Status](https://travis-ci.org/proftpd/proftpd.svg?branch=master)](https://travis-ci.org/proftpd/proftpd)
[![Coverage Status](https://coveralls.io/repos/proftpd/proftpd/badge.svg?branch=master&service=github)](https://coveralls.io/github/proftpd/proftpd?branch=master)
[![Coverity Scan Status](https://scan.coverity.com/projects/198/badge.svg)](https://scan.coverity.com/projects/198)
[![Release](https://img.shields.io/badge/release-1.3.6a-brightgreen.svg)](https://github.com/proftpd/proftpd/releases/latest)
[![License](https://img.shields.io/badge/license-GPL-brightgreen.svg)](https://img.shields.io/badge/license-GPL-brightgreen.svg)

Introduction
------------

ProFTPD is a highly configurable FTP daemon for Unix and Unix-like
operating systems.  See the _**README.ports**_ file for more details about
the platforms on which ProFTPD in known or thought to build and run.

ProFTPD grew from a desire for a secure and configurable FTP server.
It was inspired by a significant admiration of the Apache web server.
Unlike most other Unix FTP servers, it has not been derived from the old
BSD `ftpd` code base, but is a completely new design and implementation.

ProFTPD's extensive configurability provides systems administrators great
flexibility in user authentication and access controls, including virtual
users and easy `chroot()` FTP sessions for individual users.

ProFTPD is popular with many service providers for delivering update
access to user web pages, without resorting to Unix shell accounts.

Latest Release
--------------

- ftp://ftp.proftpd.org/distrib/source/
- http://www.proftpd.org/

>see _**RELEASE_NOTES**_ for an overview of the changes in this release.

Major Features
--------------

- A single main configuration file, with directives and directive groups patterned after those of the Apache web server. 

- Per directory ".ftpaccess" configuration similar to Apache's ".htaccess". 

- Designed to run either as a stand-alone server or from `inetd`/`xinetd`.

- Multiple virtual FTP servers and anonymous FTP services. 

- Multiple password files.

- Shadow password support, including support for expired accounts.

- Multiple authentication methods, including PAM, LDAP, SQL, and RADIUS.

- Virtual users.

- ProFTPD never executes any external program at any time. There is no `SITE EXEC` command, and all file and directory listings are generated internally, without using an external ls command.

- Anonymous FTP and other chroot directories do not require any specific directory structure, executable programs or other system files. 

- Modular architecture with an API that facilitates well structured extensions to meet user needs.

- Visibility of directories or files controlled based on Unix style permissions or user/group ownership. 

- Logging and utmp/wtmp support.  Logging is compatible with `wu-ftpd`, and extended, customizable logging is available.

- If supported by the capabilities the host system, it can run as a non-privileged user in stand-alone mode, thwarting attacks aimed at exploiting "root" privileges.

- GPLv2 source license.  The source code is available to audit.

Documentation
-------------

- The [doc/](doc/) directory
- http://www.proftpd.org/docs/

Installation Overview
---------------------

For detailed installation instructions, see the _**INSTALL**_ file in the root directory of the source distribution.

The ProFTPD source distribution is designed to be configured using the GNU autotools, so compiling and installing follows the familiar command sequence of

    $ ./configure
    $ make
    $ make install

However, a significant portion of ProFTPD's configurability is done at compile time, so it is highly recommended that you read _**INSTALL**_ and all of the _**README.***_ files that pertain to your platform and desired features before building the sources.

ProFTPD uses a single configuration file.  A few examples are included in the [sample-configurations/](sample-configurations/) subdirectory of the source distribution.

On most systems, the `inetd` or `xinetd` configuration must be changed, either to remove the current ftpd entry to run ProFTPD standalone, or to change the current ftpd entry to use the proftpd daemon.

Questions
---------

If you have questions, please ask them on the appropriate [mailing lists](http://www.proftpd.org/lists.html).

If you don't understand the documentation, please tell us, so we can explain it better.  The general idea is: if you need to ask for help, then something needs to be fixed so you (and others) don't need to ask for help.  Asking questions helps us to know what needs to be documented, described, and/or fixed.
