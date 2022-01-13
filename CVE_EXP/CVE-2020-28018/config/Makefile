##################################################
#          The Exim mail transport agent         #
##################################################

# This is the template for Exim's main build-time configuration file. It
# contains settings that are independent of any operating system. These are
# things that are mostly sysadmin choices. The items below are divided into
# those you must specify, those you probably want to specify, those you might
# often want to specify, and those that you almost never need to mention.

# Edit this file and save the result to a file called Local/Makefile within the
# Exim distribution directory before running the "make" command.

# Things that depend on the operating system have default settings in
# OS/Makefile-Default, but these are overridden for some OS by files called
# called OS/Makefile-<osname>. You can further override these by creating files
# called Local/Makefile-<osname>, where "<osname>" stands for the name of your
# operating system - look at the names in the OS directory to see which names
# are recognized.

# However, if you are building Exim for a single OS only, you don't need to
# worry about setting up Local/Makefile-<osname>. Any build-time configuration
# settings you require can in fact be placed in the one file called
# Local/Makefile. It is only if you are building for several OS from the same
# source files that you need to worry about splitting off your own OS-dependent
# settings into separate files. (There's more explanation about how this all
# works in the toplevel README file, under "Modifying the building process", as
# well as in the Exim specification.)

# One OS-specific thing that may need to be changed is the command for running
# the C compiler; the overall default is gcc, but some OS Makefiles specify cc.
# You can override anything that is set by putting CC=whatever in your
# Local/Makefile.

# NOTE: You should never need to edit any of the distributed Makefiles; all
# overriding can be done in your Local/Makefile(s). This will make it easier
# for you when the next release comes along.

# The location of the X11 libraries is something else that is quite variable
# even between different versions of the same operating system (and indeed
# there are different versions of X11 as well, of course). The four settings
# concerned here are X11, XINCLUDE, XLFLAGS (linking flags) and X11_LD_LIB
# (dynamic run-time library). You need not worry about X11 unless you want to
# compile the Exim monitor utility. Exim itself does not use X11.

# Another area of variability between systems is the type and location of the
# DBM library package. Exim has support for ndbm, gdbm, tdb, and Berkeley DB.
# By default the code assumes ndbm; this often works with gdbm or DB, provided
# they are correctly installed, via their compatibility interfaces. However,
# Exim can also be configured to use the native calls for Berkeley DB (obsolete
# versions 1.85, 2.x, 3.x, or the current 4.x version) and also for gdbm.

# For some operating systems, a default DBM library (other than ndbm) is
# selected by a setting in the OS-specific Makefile. Most modern OS now have
# a DBM library installed as standard, and in many cases this will be selected
# for you by the OS-specific configuration. If Exim compiles without any
# problems, you probably do not have to worry about the DBM library. If you
# do want or need to change it, you should first read the discussion in the
# file doc/dbm.discuss.txt, which also contains instructions for testing Exim's
# interface to the DBM library.

# In Local/Makefiles blank lines and lines starting with # are ignored. It is
# also permitted to use the # character to add a comment to a setting, for
# example
#
# EXIM_GID=42   # the "mail" group
#
# However, with some versions of "make" this works only if there is no white
# space between the end of the setting and the #, so perhaps it is best
# avoided. A consequence of this facility is that it is not possible to have
# the # character present in any setting, but I can't think of any cases where
# this would be wanted.
###############################################################################



###############################################################################
#                    THESE ARE THINGS YOU MUST SPECIFY                        #
###############################################################################

# Exim will not build unless you specify BIN_DIRECTORY, CONFIGURE_FILE, and
# EXIM_USER. You also need EXIM_GROUP if EXIM_USER specifies a uid by number.

# If you don't specify SPOOL_DIRECTORY, Exim won't fail to build. However, it
# really is a very good idea to specify it here rather than at run time. This
# is particularly true if you let the logs go to their default location in the
# spool directory, because it means that the location of the logs is known
# before Exim has read the run time configuration file.

#------------------------------------------------------------------------------
# BIN_DIRECTORY defines where the exim binary will be installed by "make
# install". The path is also used internally by Exim when it needs to re-invoke
# itself, either to send an error message, or to recover root privilege. Exim's
# utility binaries and scripts are also installed in this directory. There is
# no "standard" place for the binary directory. Some people like to keep all
# the Exim files under one directory such as /usr/exim; others just let the
# Exim binaries go into an existing directory such as /usr/sbin or
# /usr/local/sbin. The installation script will try to create this directory,
# and any superior directories, if they do not exist.

BIN_DIRECTORY=/usr/exim/bin


#------------------------------------------------------------------------------
# CONFIGURE_FILE defines where Exim's run time configuration file is to be
# found. It is the complete pathname for the file, not just a directory. The
# location of all other run time files and directories can be changed in the
# run time configuration file. There is a lot of variety in the choice of
# location in different OS, and in the preferences of different sysadmins. Some
# common locations are in /etc or /etc/mail or /usr/local/etc or
# /usr/local/etc/mail. Another possibility is to keep all the Exim files under
# a single directory such as /usr/exim. Whatever you choose, the installation
# script will try to make the directory and any superior directories if they
# don't exist. It will also install a default runtime configuration if this
# file does not exist.

CONFIGURE_FILE=/var/lib/exim4/config.autogenerated

# It is possible to specify a colon-separated list of files for CONFIGURE_FILE.
# In this case, Exim will use the first of them that exists when it is run.
# However, if a list is specified, the installation script no longer tries to
# make superior directories or to install a default runtime configuration.


#------------------------------------------------------------------------------
# The Exim binary must normally be setuid root, so that it starts executing as
# root, but (depending on the options with which it is called) it does not
# always need to retain the root privilege. These settings define the user and
# group that is used for Exim processes when they no longer need to be root. In
# particular, this applies when receiving messages and when doing remote
# deliveries. (Local deliveries run as various non-root users, typically as the
# owner of a local mailbox.) Specifying these values as root is not supported.

EXIM_USER=exim

# If you specify EXIM_USER as a name, this is looked up at build time, and the
# uid number is built into the binary. However, you can specify that this
# lookup is deferred until runtime. In this case, it is the name that is built
# into the binary. You can do this by a setting of the form:

# EXIM_USER=ref:exim

# In other words, put "ref:" in front of the user name. If you set EXIM_USER
# like this, any value specified for EXIM_GROUP is also passed "by reference".
# Although this costs a bit of resource at runtime, it is convenient to use
# this feature when building binaries that are to be run on multiple systems
# where the name may refer to different uids. It also allows you to build Exim
# on a system where there is no Exim user defined.

# If the setting of EXIM_USER is numeric (e.g. EXIM_USER=42), there must
# also be a setting of EXIM_GROUP. If, on the other hand, you use a name
# for EXIM_USER (e.g. EXIM_USER=exim), you don't need to set EXIM_GROUP unless
# you want to use a group other than the default group for the given user.

# EXIM_GROUP=

# Many sites define a user called "exim", with an appropriate default group,
# and use
#
# EXIM_USER=exim
#
# while leaving EXIM_GROUP unspecified (commented out).


#------------------------------------------------------------------------------
# SPOOL_DIRECTORY defines the directory where all the data for messages in
# transit is kept. It is strongly recommended that you define it here, though
# it is possible to leave this till the run time configuration.

# Exim creates the spool directory if it does not exist. The owner and group
# will be those defined by EXIM_USER and EXIM_GROUP, and this also applies to
# all the files and directories that are created in the spool directory.

# Almost all installations choose this:

SPOOL_DIRECTORY=/var/log/exim4



###############################################################################
#           THESE ARE THINGS YOU PROBABLY WANT TO SPECIFY                     #
###############################################################################

# If you need extra header file search paths on all compiles, put the -I
# options in INCLUDE.  If you want the extra searches only for certain
# parts of the build, see more specific xxx_INCLUDE variables below.

# INCLUDE=-I/example/include

# You need to specify some routers and transports if you want the Exim that you
# are building to be capable of delivering mail. You almost certainly need at
# least one type of lookup. You should consider whether you want to build
# the Exim monitor or not.

# If you need to override how pkg-config finds configuration files for
# installed software, then you can set that here; wildcards will be expanded.

# PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig : /opt/*/lib/pkgconfig


#------------------------------------------------------------------------------
# These settings determine which individual router drivers are included in the
# Exim binary. There are no defaults in the code; those routers that are wanted
# must be defined here by setting the appropriate variables to the value "yes".
# Including a router in the binary does not cause it to be used automatically.
# It has also to be configured in the run time configuration file. By
# commenting out those you know you don't want to use, you can make the binary
# a bit smaller. If you are unsure, leave all of these included for now.

ROUTER_ACCEPT=yes
ROUTER_DNSLOOKUP=yes
ROUTER_IPLITERAL=yes
ROUTER_MANUALROUTE=yes
ROUTER_QUERYPROGRAM=yes
ROUTER_REDIRECT=yes

# This one is very special-purpose, so is not included by default.

# ROUTER_IPLOOKUP=yes


#------------------------------------------------------------------------------
# These settings determine which individual transport drivers are included in
# the Exim binary. There are no defaults; those transports that are wanted must
# be defined here by setting the appropriate variables to the value "yes".
# Including a transport in the binary does not cause it to be used
# automatically. It has also to be configured in the run time configuration
# file. By commenting out those you know you don't want to use, you can make
# the binary a bit smaller. If you are unsure, leave all of these included for
# now.

TRANSPORT_APPENDFILE=yes
TRANSPORT_AUTOREPLY=yes
TRANSPORT_PIPE=yes
TRANSPORT_SMTP=yes

# This one is special-purpose, and commonly not required, so it is not
# included by default.

TRANSPORT_LMTP=yes


#------------------------------------------------------------------------------
# The appendfile transport can write messages to local mailboxes in a number
# of formats. The code for three specialist formats, maildir, mailstore, and
# MBX, is included only when requested. If you do not know what this is about,
# leave these settings commented out.

SUPPORT_MAILDIR=yes
SUPPORT_MAILSTORE=yes
# SUPPORT_MBX=yes


#------------------------------------------------------------------------------
# See below for dynamic lookup modules.
#
# If not using package management but using this anyway, then think about how
# you perform upgrades and revert them. You should consider the benefit of
# embedding the Exim version number into LOOKUP_MODULE_DIR, so that you can
# maintain two concurrent sets of modules.
#
# *BEWARE*: ability to modify the files in LOOKUP_MODULE_DIR is equivalent to
# the ability to modify the Exim binary, which is often setuid root!  The Exim
# developers only intend this functionality be used by OS software packagers
# and we suggest that such packagings' integrity checks should be paranoid
# about the permissions of the directory and the files within.

# LOOKUP_MODULE_DIR=/usr/lib/exim/lookups/

# To build a module dynamically, you'll need to define CFLAGS_DYNAMIC for
# your platform.  Eg:
# CFLAGS_DYNAMIC=-shared -rdynamic
# CFLAGS_DYNAMIC=-shared -rdynamic -fPIC

#------------------------------------------------------------------------------
# These settings determine which file and database lookup methods are included
# in the binary. See the manual chapter entitled "File and database lookups"
# for discussion. DBM and lsearch (linear search) are included by default. If
# you are unsure about the others, leave them commented out for now.
# LOOKUP_DNSDB does *not* refer to general mail routing using the DNS. It is
# for the specialist case of using the DNS as a general database facility (not
# common).
# If set to "2" instead of "yes" then the corresponding lookup will be
# built as a module and must be installed into LOOKUP_MODULE_DIR. You need to
# add -export-dynamic -rdynamic to EXTRALIBS. You may also need to add -ldl to
# EXTRALIBS so that dlopen() is available to Exim. You need to define
# LOOKUP_MODULE_DIR above so the exim binary actually loads dynamic lookup
# modules.
# Also, instead of adding all the libraries/includes to LOOKUP_INCLUDE and
# LOOKUP_LIBS, add them to the respective LOOKUP_*_INCLUDE and LOOKUP_*_LIBS
# (where * is the name as given here in this list). That ensures that only
# the dynamic library and not the exim binary will be linked against the
# library.
# NOTE: LDAP cannot be built as a module!
#
# For Redis you need to have hiredis installed on your system
# (https://github.com/redis/hiredis).
# Depending on where it is installed you may have to edit the CFLAGS
# (often += -I/usr/local/include) and LDFLAGS (-lhiredis) lines.

# If your system has pkg-config then the _INCLUDE/_LIBS setting can be
# handled for you automatically by also defining the _PC variable to reference
# the name of the pkg-config package, if such is available.

LOOKUP_DBM=yes
LOOKUP_LSEARCH=yes
LOOKUP_DNSDB=yes

LOOKUP_CDB=yes
# LOOKUP_DSEARCH=yes
# LOOKUP_IBASE=yes
# LOOKUP_LDAP=yes
# LOOKUP_MYSQL=yes
# LOOKUP_MYSQL_PC=mariadb
# LOOKUP_NIS=yes
# LOOKUP_NISPLUS=yes
# LOOKUP_ORACLE=yes
LOOKUP_PASSWD=yes
# LOOKUP_PGSQL=yes
# LOOKUP_REDIS=yes
# LOOKUP_SQLITE=yes
# LOOKUP_SQLITE_PC=sqlite3
# LOOKUP_WHOSON=yes

# These two settings are obsolete; all three lookups are compiled when
# LOOKUP_LSEARCH is enabled. However, we retain these for backward
# compatibility. Setting one forces LOOKUP_LSEARCH if it is not set.

LOOKUP_WILDLSEARCH=yes
LOOKUP_NWILDLSEARCH=yes


#------------------------------------------------------------------------------
# If you have set LOOKUP_LDAP=yes, you should set LDAP_LIB_TYPE to indicate
# which LDAP library you have. Unfortunately, though most of their functions
# are the same, there are minor differences. Currently Exim knows about four
# LDAP libraries: the one from the University of Michigan (also known as
# OpenLDAP 1), OpenLDAP 2, the Netscape SDK library, and the library that comes
# with Solaris 7 onwards. Uncomment whichever of these you are using.

# LDAP_LIB_TYPE=OPENLDAP1
# LDAP_LIB_TYPE=OPENLDAP2
# LDAP_LIB_TYPE=NETSCAPE
# LDAP_LIB_TYPE=SOLARIS

# If you don't set any of these, Exim assumes the original University of
# Michigan (OpenLDAP 1) library.


#------------------------------------------------------------------------------
# The PCRE library is required for Exim.  There is no longer an embedded
# version of the PCRE library included with the source code, instead you
# must use a system library or build your own copy of PCRE.
# In either case you must specify the library link info here.  If the
# PCRE header files are not in the standard search path you must also
# modify the INCLUDE path (above)
#
# Use PCRE_CONFIG to query the pcre-config command (first found in $PATH)
# to find the include files and libraries, else use PCRE_LIBS and set INCLUDE
# too if needed.

PCRE_CONFIG=yes
# PCRE_LIBS=-lpcre


#------------------------------------------------------------------------------
# Uncomment the following line to add DANE support
# Note: Enabling this unconditionally overrides DISABLE_DNSSEC
# For DANE under GnuTLS we need an additional library.  See TLS_LIBS below.
SUPPORT_DANE=yes

#------------------------------------------------------------------------------
# Additional libraries and include directories may be required for some
# lookup styles (e.g. LDAP, MYSQL or PGSQL). LOOKUP_LIBS is included only on
# the command for linking Exim itself, not on any auxiliary programs. You
# don't need to set LOOKUP_INCLUDE if the relevant directories are already
# specified in INCLUDE. The settings below are just examples; -lpq is for
# PostgreSQL, -lgds is for Interbase, -lsqlite3 is for SQLite, -lhiredis
# is for Redis.
#
# You do not need to use this for any lookup information added via pkg-config.

# LOOKUP_INCLUDE=-I /usr/local/ldap/include -I /usr/local/mysql/include -I /usr/local/pgsql/include
# LOOKUP_LIBS=-L/usr/local/lib -lldap -llber -lmysqlclient -lpq -lgds -lsqlite3


#------------------------------------------------------------------------------
# Compiling the Exim monitor: If you want to compile the Exim monitor, a
# program that requires an X11 display, then EXIM_MONITOR should be set to the
# value "eximon.bin". Comment out this setting to disable compilation of the
# monitor. The locations of various X11 directories for libraries and include
# files are defaulted in the OS/Makefile-Default file, but can be overridden in
# local OS-specific make files.

EXIM_MONITOR=eximon.bin


#------------------------------------------------------------------------------
# Compiling Exim with content scanning support: If you want to compile Exim
# with support for message body content scanning, set WITH_CONTENT_SCAN to
# the value "yes". This will give you malware and spam scanning in the DATA ACL,
# and the MIME ACL. Please read the documentation to learn more about these
# features.

# WITH_CONTENT_SCAN=yes

# If you have content scanning you may wish to only include some of the scanner
# interfaces.  Uncomment any of these lines to remove that code.

# DISABLE_MAL_FFROTD=yes
# DISABLE_MAL_FFROT6D=yes
# DISABLE_MAL_DRWEB=yes
# DISABLE_MAL_FSECURE=yes
# DISABLE_MAL_SOPHIE=yes
# DISABLE_MAL_CLAM=yes
# DISABLE_MAL_AVAST=yes
# DISABLE_MAL_SOCK=yes
# DISABLE_MAL_CMDLINE=yes

# These scanners are claimed to be no longer existent.

DISABLE_MAL_AVE=yes
DISABLE_MAL_KAV=yes
DISABLE_MAL_MKS=yes


#------------------------------------------------------------------------------
# If built with TLS, Exim includes code to support DKIM (DomainKeys Identified
# Mail, RFC4871) signing and verification.  Verification of signatures is
# turned on by default.  See the spec for information on conditionally
# disabling it.  To disable the inclusion of the entire feature, set
# DISABLE_DKIM to "yes"

# DISABLE_DKIM=yes

#------------------------------------------------------------------------------
# Uncomment the following line to remove Per-Recipient-Data-Response support.

# DISABLE_PRDR=yes

#------------------------------------------------------------------------------
# Uncomment the following line to remove OCSP stapling support in TLS,
# from Exim.  Note it can only be supported when built with
# GnuTLS 3.1.3 or later, or OpenSSL

# DISABLE_OCSP=yes

#------------------------------------------------------------------------------
# By default, Exim has support for checking the AD bit in a DNS response, to
# determine if DNSSEC validation was successful.  If your system libraries
# do not support that bit, then set DISABLE_DNSSEC to "yes"
# Note: Enabling SUPPORT_DANE unconditionally overrides this setting.

#DISABLE_DNSSEC=yes

# To disable support for Events set DISABLE_EVENT to "yes"

# DISABLE_EVENT=yes


#------------------------------------------------------------------------------
# Compiling Exim with experimental features. These are documented in
# experimental-spec.txt. "Experimental" means that the way these features are
# implemented may still change. Backward compatibility is not guaranteed.

# Uncomment the following line to add support for talking to dccifd.  This
# defaults the socket path to /usr/local/dcc/var/dccifd.
# Doing so will also explicitly turn on the WITH_CONTENT_SCAN option.

# EXPERIMENTAL_DCC=yes

# Uncomment the following lines to add SRS (Sender rewriting scheme) support.
# You need to have libsrs_alt installed on your system (srs.mirtol.com).
# Depending on where it is installed you may have to edit the CFLAGS and
# LDFLAGS lines.

# EXPERIMENTAL_SRS=yes
# CFLAGS  += -I/usr/local/include
# LDFLAGS += -lsrs_alt

# Uncomment the following line to add DMARC checking capability, implemented
# using libopendmarc libraries. You must have SPF and DKIM support enabled also.
# EXPERIMENTAL_DMARC=yes
# DMARC_TLD_FILE= /etc/exim/opendmarc.tlds
# CFLAGS += -I/usr/local/include
# LDFLAGS += -lopendmarc

# Uncomment the following line to add ARC (Authenticated Received Chain)
# support.  You must have SPF and DKIM support enabled also.
# EXPERIMENTAL_ARC=yes

# Uncomment the following lines to add Brightmail AntiSpam support. You need
# to have the Brightmail client SDK installed. Please check the experimental
# documentation for implementation details. You need to edit the CFLAGS and
# LDFLAGS lines.

# EXPERIMENTAL_BRIGHTMAIL=yes
# CFLAGS  += -I/opt/brightmail/bsdk-6.0/include
# LDFLAGS += -lxml2_single -lbmiclient_single -L/opt/brightmail/bsdk-6.0/lib

# Uncomment the following to include extra information in fail DSN message (bounces)
# EXPERIMENTAL_DSN_INFO=yes

# Uncomment the following to add LMDB lookup support
# You need to have LMDB installed on your system (https://github.com/LMDB/lmdb)
# Depending on where it is installed you may have to edit the CFLAGS and LDFLAGS lines.
# EXPERIMENTAL_LMDB=yes
# CFLAGS += -I/usr/local/include
# LDFLAGS += -llmdb

# Uncomment the following line to add queuefile transport support
# EXPERIMENTAL_QUEUEFILE=yes

# Uncomment the following to add REQUIRETLS support.
# You must also have SUPPORT_TLS enabled.
# Ref: https://datatracker.ietf.org/doc/draft-fenton-smtp-require-tls
# EXPERIMENTAL_REQUIRETLS=yes

###############################################################################
#                 THESE ARE THINGS YOU MIGHT WANT TO SPECIFY                  #
###############################################################################

# The items in this section are those that are commonly changed according to
# the sysadmin's preferences, but whose defaults are often acceptable. The
# first five are concerned with security issues, where differing levels of
# paranoia are appropriate in different environments. Sysadmins also vary in
# their views on appropriate levels of defence in these areas. If you do not
# understand these issues, go with the defaults, which are used by many sites.


#------------------------------------------------------------------------------
# Although Exim is normally a setuid program, owned by root, it refuses to run
# local deliveries as root by default. There is a runtime option called
# "never_users" which lists the users that must never be used for local
# deliveries. There is also the setting below, which provides a list that
# cannot be overridden at runtime. This guards against problems caused by
# unauthorized changes to the runtime configuration. You are advised not to
# remove "root" from this option, but you can add other users if you want. The
# list is colon-separated. It must NOT contain any spaces.

# FIXED_NEVER_USERS=root:bin:daemon
FIXED_NEVER_USERS=root


#------------------------------------------------------------------------------
# By default, Exim insists that its configuration file be owned by root. You
# can specify one additional permitted owner here.

# CONFIGURE_OWNER=

# If the configuration file is group-writeable, Exim insists by default that it
# is owned by root. You can specify one additional permitted group owner here.

# CONFIGURE_GROUP=

# If you specify CONFIGURE_OWNER or CONFIGURE_GROUP as a name, this is looked
# up at build time, and the uid or gid number is built into the binary.
# However, you can specify that the lookup is deferred until runtime. In this
# case, it is the name that is built into the binary. You can do this by a
# setting of the form:

# CONFIGURE_OWNER=ref:mail
# CONFIGURE_GROUP=ref:sysadmin

# In other words, put "ref:" in front of the user or group name. Although this
# costs a bit of resource at runtime, it is convenient to use this feature when
# building binaries that are to be run on multiple systems where the names may
# refer to different uids or gids. It also allows you to build Exim on a system
# where the relevant user or group is not defined.


#------------------------------------------------------------------------------
# The -C option allows Exim to be run with an alternate runtime configuration
# file. When this is used by root, root privilege is retained by the binary
# (for any other caller including the Exim user, it is dropped). You can
# restrict the location of alternate configurations by defining a prefix below.
# Any file used with -C must then start with this prefix (except that /dev/null
# is also permitted if the caller is root, because that is used in the install
# script). If the prefix specifies a directory that is owned by root, a
# compromise of the Exim account does not permit arbitrary alternate
# configurations to be used. The prefix can be more restrictive than just a
# directory (the second example).

# ALT_CONFIG_PREFIX=/some/directory/
# ALT_CONFIG_PREFIX=/some/directory/exim.conf-


#------------------------------------------------------------------------------
# When a user other than root uses the -C option to override the configuration
# file (including the Exim user when re-executing Exim to regain root
# privileges for local message delivery), this will normally cause Exim to
# drop root privileges. The TRUSTED_CONFIG_LIST option, specifies a file which
# contains a list of trusted configuration filenames, one per line. If the -C
# option is used by the Exim user or by the user specified in the
# CONFIGURE_OWNER setting, to specify a configuration file which is listed in
# the TRUSTED_CONFIG_LIST file, then root privileges are not dropped by Exim.

# TRUSTED_CONFIG_LIST=/usr/exim/trusted_configs


#------------------------------------------------------------------------------
# Uncommenting this option disables the use of the -D command line option,
# which changes the values of macros in the runtime configuration file.
# This is another protection against somebody breaking into the Exim account.

# DISABLE_D_OPTION=yes


#------------------------------------------------------------------------------
# By contrast, you might be maintaining a system which relies upon the ability
# to override values with -D and assumes that these will be passed through to
# the delivery processes.  As of Exim 4.73, this is no longer the case by
# default.  Going forward, we strongly recommend that you use a shim Exim
# configuration file owned by root stored under TRUSTED_CONFIG_LIST.
# That shim can set macros before .include'ing your main configuration file.
#
# As a strictly transient measure to ease migration to 4.73, the
# WHITELIST_D_MACROS value defines a colon-separated list of macro-names
# which are permitted to be overridden from the command-line which will be
# honoured by the Exim user.  So these are macros that can persist to delivery
# time.
# Examples might be -DTLS or -DSPOOL=/some/dir.  The values on the
# command-line are filtered to only permit: [A-Za-z0-9_/.-]*
#
# This option is highly likely to be removed in a future release.  It exists
# only to make 4.73 as easy as possible to migrate to.  If you use it, we
# encourage you to schedule time to rework your configuration to not depend
# upon it.  Most people should not need to use this.
#
# By default, no macros are whitelisted for -D usage.

# WHITELIST_D_MACROS=TLS:SPOOL

#------------------------------------------------------------------------------
# Exim has support for the AUTH (authentication) extension of the SMTP
# protocol, as defined by RFC 2554. If you don't know what SMTP authentication
# is, you probably won't want to include this code, so you should leave these
# settings commented out. If you do want to make use of SMTP authentication,
# you must uncomment at least one of the following, so that appropriate code is
# included in the Exim binary. You will then need to set up the run time
# configuration to make use of the mechanism(s) selected.

AUTH_CRAM_MD5=yes
# AUTH_CYRUS_SASL=yes
# AUTH_DOVECOT=yes
# AUTH_GSASL=yes
# AUTH_GSASL_PC=libgsasl
# AUTH_HEIMDAL_GSSAPI=yes
# AUTH_HEIMDAL_GSSAPI_PC=heimdal-gssapi
# AUTH_HEIMDAL_GSSAPI_PC=heimdal-gssapi heimdal-krb5
AUTH_PLAINTEXT=yes
# AUTH_SPA=yes
# AUTH_TLS=yes

# Heimdal through 1.5 required pkg-config 'heimdal-gssapi'; Heimdal 7.1
# requires multiple pkg-config files to work with Exim, so the second example
# above is needed.

#------------------------------------------------------------------------------
# If you specified AUTH_CYRUS_SASL above, you should ensure that you have the
# Cyrus SASL library installed before trying to build Exim, and you probably
# want to uncomment the first line below.
# Similarly for GNU SASL, unless pkg-config is used via AUTH_GSASL_PC.
# Ditto for AUTH_HEIMDAL_GSSAPI(_PC).

# AUTH_LIBS=-lsasl2
# AUTH_LIBS=-lgsasl
# AUTH_LIBS=-lgssapi -lheimntlm -lkrb5 -lhx509 -lcom_err -lhcrypto -lasn1 -lwind -lroken -lcrypt


#------------------------------------------------------------------------------
# When Exim is decoding MIME "words" in header lines, most commonly for use
# in the $header_xxx expansion, it converts any foreign character sets to the
# one that is set in the headers_charset option. The default setting is
# defined by this setting:

HEADERS_CHARSET="ISO-8859-1"

# If you are going to make use of $header_xxx expansions in your configuration
# file, or if your users are going to use them in filter files, and the normal
# character set on your host is something other than ISO-8859-1, you might
# like to specify a different default here. This value can be overridden in
# the runtime configuration, and it can also be overridden in individual filter
# files.
#
# IMPORTANT NOTE: The iconv() function is needed for character code
# conversions. Please see the next item...


#------------------------------------------------------------------------------
# Character code conversions are possible only if the iconv() function is
# installed on your operating system. There are two places in Exim where this
# is relevant: (a) The $header_xxx expansion (see the previous item), and (b)
# the Sieve filter support. For those OS where iconv() is known to be installed
# as standard, the file in OS/Makefile-xxxx contains
#
# HAVE_ICONV=yes
#
# If you are not using one of those systems, but have installed iconv(), you
# need to uncomment that line above. In some cases, you may find that iconv()
# and its header file are not in the default places. You might need to use
# something like this:
#
# HAVE_ICONV=yes
# CFLAGS=-O -I/usr/local/include
# EXTRALIBS_EXIM=-L/usr/local/lib -liconv
#
# but of course there may need to be other things in CFLAGS and EXTRALIBS_EXIM
# as well.
#
# nb: FreeBSD as of 4.89 defines LIBICONV_PLUG to pick up the system iconv
# more reliably.  If you explicitly want the libiconv Port then as well
# as adding -liconv you'll want to unset LIBICONV_PLUG.  If you actually need
# this, let us know, but for now the Exim Maintainers are assuming that this
# is uncommon and so you'll need to edit OS/os.h-FreeBSD yourself to remove
# the define.


#------------------------------------------------------------------------------
# The passwords for user accounts are normally encrypted with the crypt()
# function. Comparisons with encrypted passwords can be done using Exim's
# "crypteq" expansion operator. (This is commonly used as part of the
# configuration of an authenticator for use with SMTP AUTH.) At least one
# operating system has an extended function called crypt16(), which uses up to
# 16 characters of a password (the normal crypt() uses only the first 8). Exim
# supports the use of crypt16() as well as crypt() but note the warning below.

# You can always indicate a crypt16-encrypted password by preceding it with
# "{crypt16}". If you want the default handling (without any preceding
# indicator) to use crypt16(), uncomment the following line:

# DEFAULT_CRYPT=crypt16

# If you do that, you can still access the basic crypt() function by preceding
# an encrypted password with "{crypt}". For more details, see the description
# of the "crypteq" condition in the manual chapter on string expansions.

# Some operating systems do not include a crypt16() function, so Exim has one
# of its own, which it uses unless HAVE_CRYPT16 is defined. Normally, that will
# be set in an OS-specific Makefile for the OS that have such a function, so
# you should not need to bother with it.

# *** WARNING *** WARNING *** WARNING *** WARNING *** WARNING ***
# It turns out that the above is not entirely accurate. As well as crypt16()
# there is a function called bigcrypt() that some operating systems have. This
# may or may not use the same algorithm, and both of them may be different to
# Exim's built-in crypt16() that is used unless HAVE_CRYPT16 is defined.
#
# However, since there is now a move away from the traditional crypt()
# functions towards using SHA1 and other algorithms, tidying up this area of
# Exim is seen as very low priority. In practice, if you need to, you can
# define DEFAULT_CRYPT to the name of any function that has the same interface
# as the traditional crypt() function.
# *** WARNING *** WARNING *** WARNING *** WARNING *** WARNING ***


#------------------------------------------------------------------------------
# Exim can be built to support the SMTP STARTTLS command, which implements
# Transport Layer Security using SSL (Secure Sockets Layer). To do this, you
# must install the OpenSSL library package or the GnuTLS library. Exim contains
# no cryptographic code of its own. Uncomment the following lines if you want
# to build Exim with TLS support. If you don't know what this is all about,
# leave these settings commented out.

# This setting is required for any TLS support (either OpenSSL or GnuTLS)
SUPPORT_TLS=yes

# Uncomment one of these settings if you are using OpenSSL; pkg-config vs not
USE_OPENSSL_PC=openssl
TLS_LIBS=-lssl -lcrypto

# Uncomment the first and either the second or the third of these if you
# are using GnuTLS.  If you have pkg-config, then the second, else the third.
# USE_GNUTLS=yes
# USE_GNUTLS_PC=gnutls
# TLS_LIBS=-lgnutls -ltasn1 -lgcrypt

# If using GnuTLS older than 2.10 and using pkg-config then note that Exim's
# build process will require libgcrypt-config to exist in your $PATH.  A
# version that old is likely to become unsupported by Exim in 2017.

# The security fix we provide with the gnutls_allow_auto_pkcs11 option
# (4.82 PP/09) introduces a compatibility regression.  The symbol is
# not available if GnuTLS is build without p11-kit (--without-p11-kit
# configure option).  In this case use AVOID_GNUTLS_PKCS11=yes when
# building Exim.
# AVOID_GNUTLS_PKCS11=yes

# If you are running Exim as a server, note that just building it with TLS
# support is not all you need to do. You also need to set up a suitable
# certificate, and tell Exim about it by means of the tls_certificate
# and tls_privatekey run time options. You also need to set tls_advertise_hosts
# to specify the hosts to which Exim advertises TLS support. On the other hand,
# if you are running Exim only as a client, building it with TLS support
# is all you need to do.

# If you are using pkg-config then you should not need to worry where the
# libraries and headers are installed, as the pkg-config .pc specification
# should include all -L/-I information necessary.  If not using pkg-config
# then you might need to specify the locations too.

# Additional libraries and include files are required for both OpenSSL and
# GnuTLS. The TLS_LIBS settings above assume that the libraries are installed
# with all your other libraries. If they are in a special directory, you may
# need something like

TLS_LIBS=-L/usr/local/openssl/lib -lssl -lcrypto
# or
# TLS_LIBS=-L/opt/gnu/lib -lgnutls -ltasn1 -lgcrypt

# For DANE under GnuTLS we need an additional library.
# TLS_LIBS += -lgnutls-dane

# TLS_LIBS is included only on the command for linking Exim itself, not on any
# auxiliary programs. If the include files are not in a standard place, you can
# set TLS_INCLUDE to specify where they are, for example:

TLS_INCLUDE=-I/usr/local/openssl/include/
# or
# TLS_INCLUDE=-I/opt/gnu/include

# You don't need to set TLS_INCLUDE if the relevant directories are already
# specified in INCLUDE.


#------------------------------------------------------------------------------
# The default distribution of Exim contains only the plain text form of the
# documentation. Other forms are available separately. If you want to install
# the documentation in "info" format, first fetch the Texinfo documentation
# sources from the ftp directory and unpack them, which should create files
# with the extension "texinfo" in the doc directory. You may find that the
# version number of the texinfo files is different to your Exim version number,
# because the main documentation isn't updated as often as the code. For
# example, if you have Exim version 4.43, the source tarball unpacks into a
# directory called exim-4.43, but the texinfo tarball unpacks into exim-4.40.
# In this case, move the contents of exim-4.40/doc into exim-4.43/doc after you
# have unpacked them. Then set INFO_DIRECTORY to the location of your info
# directory. This varies from system to system, but is often /usr/share/info.
# Once you have done this, "make install" will build the info files and
# install them in the directory you have defined.

# INFO_DIRECTORY=/usr/share/info


#------------------------------------------------------------------------------
# Exim log directory and files: Exim creates several log files inside a
# single log directory. You can define the directory and the form of the
# log file name here. If you do not set anything, Exim creates a directory
# called "log" inside its spool directory (see SPOOL_DIRECTORY above) and uses
# the filenames "mainlog", "paniclog", and "rejectlog". If you want to change
# this, you can set LOG_FILE_PATH to a path name containing one occurrence of
# %s. This will be replaced by one of the strings "main", "panic", or "reject"
# to form the final file names. Some installations may want something like this:

# LOG_FILE_PATH=/var/log/exim_%slog

# which results in files with names /var/log/exim_mainlog, etc. The directory
# in which the log files are placed must exist; Exim does not try to create
# it for itself. It is also your responsibility to ensure that Exim is capable
# of writing files using this path name. The Exim user (see EXIM_USER above)
# must be able to create and update files in the directory you have specified.

# You can also configure Exim to use syslog, instead of or as well as log
# files, by settings such as these

# LOG_FILE_PATH=syslog
# LOG_FILE_PATH=syslog:/var/log/exim_%slog

# The first of these uses only syslog; the second uses syslog and also writes
# to log files. Do not include white space in such a setting as it messes up
# the building process.


#------------------------------------------------------------------------------
# When logging to syslog, the following option caters for syslog replacements
# that are able to accept log entries longer than the 1024 characters allowed
# by RFC 3164. It is up to you to make sure your syslog daemon can handle this.
# Non-printable characters are usually unacceptable regardless, so log entries
# are still split on newline characters.

# SYSLOG_LONG_LINES=yes

# If you are not interested in the process identifier (pid) of the Exim that is
# making the call to syslog, then comment out the following line.

SYSLOG_LOG_PID=yes


#------------------------------------------------------------------------------
# Cycling log files: this variable specifies the maximum number of old
# log files that are kept by the exicyclog log-cycling script. You don't have
# to use exicyclog. If your operating system has other ways of cycling log
# files, you can use them instead. The exicyclog script isn't run by default;
# you have to set up a cron job for it if you want it.

EXICYCLOG_MAX=10


#------------------------------------------------------------------------------
# The compress command is used by the exicyclog script to compress old log
# files. Both the name of the command and the suffix that it adds to files
# need to be defined here. See also the EXICYCLOG_MAX configuration.

COMPRESS_COMMAND=/usr/bin/gzip
COMPRESS_SUFFIX=gz


#------------------------------------------------------------------------------
# If the exigrep utility is fed compressed log files, it tries to uncompress
# them using this command.

# Leave it empty to enforce autodetection at runtime:
# ZCAT_COMMAND=
#
# Omit the path if you want to use your system's PATH:
# ZCAT_COMMAND=zcat
#
# Or specify the full pathname:
ZCAT_COMMAND=/usr/bin/zcat

#------------------------------------------------------------------------------
# Compiling in support for embedded Perl: If you want to be able to
# use Perl code in Exim's string manipulation language and you have Perl
# (version 5.004 or later) installed, set EXIM_PERL to perl.o. Using embedded
# Perl costs quite a lot of resources. Only do this if you really need it.

# EXIM_PERL=perl.o


#------------------------------------------------------------------------------
# Support for dynamically-loaded string expansion functions via ${dlfunc. If
# you are using gcc the dynamically-loaded object must be compiled with the
# -shared option, and you will need to add -export-dynamic to EXTRALIBS so
# that the local_scan API is made available by the linker. You may also need
# to add -ldl to EXTRALIBS so that dlopen() is available to Exim.

# EXPAND_DLFUNC=yes


#------------------------------------------------------------------------------
# Exim has support for PAM (Pluggable Authentication Modules), a facility
# which is available in the latest releases of Solaris and in some GNU/Linux
# distributions (see http://ftp.kernel.org/pub/linux/libs/pam/). The Exim
# support, which is intended for use in conjunction with the SMTP AUTH
# facilities, is included only when requested by the following setting:

# SUPPORT_PAM=yes

# You probably need to add -lpam to EXTRALIBS, and in some releases of
# GNU/Linux -ldl is also needed.


#------------------------------------------------------------------------------
# Proxying.
#
# If you may want to use outbound (client-side) proxying, using Socks5,
# uncomment the line below.

# SUPPORT_SOCKS=yes

# If you may want to use inbound (server-side) proxying, using Proxy Protocol,
# uncomment the line below.

# SUPPORT_PROXY=yes


#------------------------------------------------------------------------------
# Internationalisation.
#
# Uncomment the following to include Internationalisation features.  This is the
# SMTPUTF8 ESMTP extension, and associated facilities for handling UTF8 domain
# and localparts, per RFC 3490 (IDNA2003).
# You need to have the IDN library installed.
# If you want IDNA2008 mappings per RFCs 5890, 6530 and 6533, you additionally
# need libidn2 and SUPPORT_I18N_2008.

# SUPPORT_I18N=yes
# LDFLAGS += -lidn
# SUPPORT_I18N_2008=yes
# LDFLAGS += -lidn -lidn2


#------------------------------------------------------------------------------
# Uncomment the following lines to add SPF support. You need to have libspf2
# installed on your system (www.libspf2.org). Depending on where it is installed
# you may have to edit the CFLAGS and LDFLAGS lines.

# SUPPORT_SPF=yes
# CFLAGS  += -I/usr/local/include
# LDFLAGS += -lspf2


#------------------------------------------------------------------------------
# Support for authentication via Radius is also available. The Exim support,
# which is intended for use in conjunction with the SMTP AUTH facilities,
# is included only when requested by setting the following parameter to the
# location of your Radius configuration file:

# RADIUS_CONFIG_FILE=/etc/radiusclient/radiusclient.conf
# RADIUS_CONFIG_FILE=/etc/radius.conf

# If you have set RADIUS_CONFIG_FILE, you should also set one of these to
# indicate which RADIUS library is used:

# RADIUS_LIB_TYPE=RADIUSCLIENT
# RADIUS_LIB_TYPE=RADIUSCLIENTNEW
# RADIUS_LIB_TYPE=RADLIB

# RADIUSCLIENT is the radiusclient library; you probably need to add
#   -lradiusclient to EXTRALIBS.
#
# The API for the radiusclient library was changed at release 0.4.0.
# Unfortunately, the header file does not define a version number that clients
# can use to support both the old and new APIs. If you are using version 0.4.0
# or later of the radiusclient library, you should use RADIUSCLIENTNEW.
#
# RADLIB is the Radius library that comes with FreeBSD (the header file is
#   called radlib.h); you probably need to add -lradius to EXTRALIBS.
#
# If you do not set RADIUS_LIB_TYPE, Exim assumes the radiusclient library,
# using the original API.


#------------------------------------------------------------------------------
# Support for authentication via the Cyrus SASL pwcheck daemon is available.
# Note, however, that pwcheck is now deprecated in favour of saslauthd (see
# next item). The Exim support for pwcheck, which is intented for use in
# conjunction with the SMTP AUTH facilities, is included only when requested by
# setting the following parameter to the location of the pwcheck daemon's
# socket.
#
# There is no need to install all of SASL on your system. You just need to run
# ./configure --with-pwcheck, cd to the pwcheck directory within the sources,
# make and make install. You must create the socket directory (default
# /var/pwcheck) and chown it to Exim's user and group. Once you have installed
# pwcheck, you should arrange for it to be started by root at boot time.

# CYRUS_PWCHECK_SOCKET=/var/pwcheck/pwcheck


#------------------------------------------------------------------------------
# Support for authentication via the Cyrus SASL saslauthd daemon is available.
# The Exim support, which is intended for use in conjunction with the SMTP AUTH
# facilities, is included only when requested by setting the following
# parameter to the location of the saslauthd daemon's socket.
#
# There is no need to install all of SASL on your system. You just need to run
# ./configure --with-saslauthd (and any other options you need, for example, to
# select or deselect authentication mechanisms), cd to the saslauthd directory
# within the sources, make and make install. You must create the socket
# directory (default /var/state/saslauthd) and chown it to Exim's user and
# group. Once you have installed saslauthd, you should arrange for it to be
# started by root at boot time.

# CYRUS_SASLAUTHD_SOCKET=/var/state/saslauthd/mux


#------------------------------------------------------------------------------
# TCP wrappers: If you want to use tcpwrappers from within Exim, uncomment
# this setting. See the manual section entitled "Use of tcpwrappers" in the
# chapter on building and installing Exim.
#
# USE_TCP_WRAPPERS=yes
#
# You may well also have to specify a local "include" file and an additional
# library for TCP wrappers, so you probably need something like this:
#
# USE_TCP_WRAPPERS=yes
# CFLAGS=-O -I/usr/local/include
# EXTRALIBS_EXIM=-L/usr/local/lib -lwrap
#
# but of course there may need to be other things in CFLAGS and EXTRALIBS_EXIM
# as well.
#
# To use a name other than exim in the tcpwrappers config file,
# e.g. if you're running multiple daemons with different access lists,
# or multiple MTAs with the same access list, define
# TCP_WRAPPERS_DAEMON_NAME accordingly
#
# TCP_WRAPPERS_DAEMON_NAME="exim"


#------------------------------------------------------------------------------
# The default action of the exim_install script (which is run by "make
# install") is to install the Exim binary with a unique name such as
# exim-4.43-1, and then set up a symbolic link called "exim" to reference it,
# moving the symbolic link from any previous version. If you define NO_SYMLINK
# (the value doesn't matter), the symbolic link is not created or moved. You
# will then have to "turn Exim on" by setting up the link manually.

# NO_SYMLINK=yes


#------------------------------------------------------------------------------
# Another default action of the install script is to install a default runtime
# configuration file if one does not exist. This configuration has a router for
# expanding system aliases. The default assumes that these aliases are kept
# in the traditional file called /etc/aliases. If such a file does not exist,
# the installation script creates one that contains just comments (no actual
# aliases). The following setting can be changed to specify a different
# location for the system alias file.

SYSTEM_ALIASES_FILE=/etc/aliases


#------------------------------------------------------------------------------
# There are some testing options (-be, -bt, -bv) that read data from the
# standard input when no arguments are supplied. By default, the input lines
# are read using the standard fgets() function. This does not support line
# editing during interactive input (though the terminal's "erase" character
# works as normal). If your operating system has the readline() function, and
# in addition supports dynamic loading of library functions, you can cause
# Exim to use readline() for the -be testing option (only) by uncommenting the
# following setting. Dynamic loading is used so that the library is loaded only
# when the -be testing option is given; by the time the loading occurs,
# Exim has given up its root privilege and is running as the calling user. This
# is the reason why readline() is NOT supported for -bt and -bv, because Exim
# runs as root or as exim, respectively, for those options. When USE_READLINE
# is "yes", as well as supporting line editing, a history of input lines in the
# current run is maintained.

# USE_READLINE=yes

# You may need to add -ldl to EXTRALIBS when you set USE_READLINE=yes.
# Note that this option adds to the size of the Exim binary, because the
# dynamic loading library is not otherwise included.

# If libreadline is not in the normal library paths, then because Exim is
# setuid you'll need to ensure that the correct directory is stamped into
# the binary so that dlopen will find it.
# Eg, on macOS/Darwin with a third-party install of libreadline, perhaps:

# EXTRALIBS_EXIM+=-Wl,-rpath,/usr/local/opt/readline/lib


#------------------------------------------------------------------------------
# Uncomment this setting to include IPv6 support.

# HAVE_IPV6=yes

###############################################################################
#              THINGS YOU ALMOST NEVER NEED TO MENTION                        #
###############################################################################

# The settings in this section are available for use in special circumstances.
# In the vast majority of installations you need not change anything below.


#------------------------------------------------------------------------------
# The following commands live in different places in some OS. Either the
# ultimate default settings, or the OS-specific files should already point to
# the right place, but they can be overridden here if necessary. These settings
# are used when building various scripts to ensure that the correct paths are
# used when the scripts are run. They are not used in the Makefile itself. Perl
# is not necessary for running Exim unless you set EXIM_PERL (see above) to get
# it embedded, but there are some utilities that are Perl scripts. If you
# haven't got Perl, Exim will still build and run; you just won't be able to
# use those utilities.

# CHOWN_COMMAND=/usr/bin/chown
# CHGRP_COMMAND=/usr/bin/chgrp
# CHMOD_COMMAND=/usr/bin/chmod
# MV_COMMAND=/bin/mv
# RM_COMMAND=/bin/rm
# TOUCH_COMMAND=/usr/bin/touch
# PERL_COMMAND=/usr/bin/perl


#------------------------------------------------------------------------------
# The following macro can be used to change the command for building a library
# of functions. By default the "ar" command is used, with options "cq".
# Only in rare circumstances should you need to change this.

# AR=ar cq


#------------------------------------------------------------------------------
# In some operating systems, the value of the TMPDIR environment variable
# controls where temporary files are created. Exim does not make use of
# temporary files, except when delivering to MBX mailboxes. However, if Exim
# calls any external libraries (e.g. DBM libraries), they may use temporary
# files, and thus be influenced by the value of TMPDIR. For this reason, when
# Exim starts, it checks the environment for TMPDIR, and if it finds it is set,
# it replaces the value with what is defined here. Commenting this setting
# suppresses the check altogether. Older installations call this macro
# just TMPDIR, but this has side effects at build time. At runtime
# TMPDIR is checked as before.

EXIM_TMPDIR="/tmp"


#------------------------------------------------------------------------------
# The following macros can be used to change the default modes that are used
# by the appendfile transport. In most installations the defaults are just
# fine, and in any case, you can change particular instances of the transport
# at run time if you want.

# APPENDFILE_MODE=0600
# APPENDFILE_DIRECTORY_MODE=0700
# APPENDFILE_LOCKFILE_MODE=0600


#------------------------------------------------------------------------------
# In some installations there may be multiple machines sharing file systems,
# where a different configuration file is required for Exim on the different
# machines. If CONFIGURE_FILE_USE_NODE is defined, then Exim will first look
# for a configuration file whose name is that defined by CONFIGURE_FILE,
# with the node name obtained by uname() tacked on the end, separated by a
# period (for example, /usr/exim/configure.host.in.some.domain). If this file
# does not exist, then the bare configuration file name is tried.

# CONFIGURE_FILE_USE_NODE=yes


#------------------------------------------------------------------------------
# In some esoteric configurations two different versions of Exim are run,
# with different setuid values, and different configuration files are required
# to handle the different cases. If CONFIGURE_FILE_USE_EUID is defined, then
# Exim will first look for a configuration file whose name is that defined
# by CONFIGURE_FILE, with the effective uid tacked on the end, separated by
# a period (for example, /usr/exim/configure.0). If this file does not exist,
# then the bare configuration file name is tried. In the case when both
# CONFIGURE_FILE_USE_EUID and CONFIGURE_FILE_USE_NODE are set, four files
# are tried: <name>.<euid>.<node>, <name>.<node>, <name>.<euid>, and <name>.

# CONFIGURE_FILE_USE_EUID=yes


#------------------------------------------------------------------------------
# The size of the delivery buffers: These specify the sizes (in bytes) of
# the buffers that are used when copying a message from the spool to a
# destination. There is rarely any need to change these values.

# DELIVER_IN_BUFFER_SIZE=8192
# DELIVER_OUT_BUFFER_SIZE=8192


#------------------------------------------------------------------------------
# The mode of the database directory: Exim creates a directory called "db"
# in its spool directory, to hold its databases of hints. This variable
# determines the mode of the created directory. The default value in the
# source is 0750.

# EXIMDB_DIRECTORY_MODE=0750


#------------------------------------------------------------------------------
# Database file mode: The mode of files created in the "db" directory defaults
# to 0640 in the source, and can be changed here.

# EXIMDB_MODE=0640


#------------------------------------------------------------------------------
# Database lock file mode: The mode of zero-length files created in the "db"
# directory to use for locking purposes defaults to 0640 in the source, and
# can be changed here.

# EXIMDB_LOCKFILE_MODE=0640


#------------------------------------------------------------------------------
# This parameter sets the maximum length of the header portion of a message
# that Exim is prepared to process. The default setting is one megabyte. The
# limit exists in order to catch rogue mailers that might connect to your SMTP
# port, start off a header line, and then just pump junk at it for ever. The
# message_size_limit option would also catch this, but it may not be set.
# The value set here is the default; it can be changed at runtime.

# HEADER_MAXSIZE="(1024*1024)"


#------------------------------------------------------------------------------
# The mode of the input directory: The input directory is where messages are
# kept while awaiting delivery. Exim creates it if necessary, using a mode
# which can be defined here (default 0750).

# INPUT_DIRECTORY_MODE=0750


#------------------------------------------------------------------------------
# The mode of Exim's log directory, when it is created by Exim inside the spool
# directory, defaults to 0750 but can be changed here.

# LOG_DIRECTORY_MODE=0750


#------------------------------------------------------------------------------
# The log files themselves are created as required, with a mode that defaults
# to 0640, but which can be changed here.

# LOG_MODE=0640


#------------------------------------------------------------------------------
# The TESTDB lookup is for performing tests on the handling of lookup results,
# and is not useful for general running. It should be included only when
# debugging the code of Exim.

# LOOKUP_TESTDB=yes


#------------------------------------------------------------------------------
# /bin/sh is used by default as the shell in which to run commands that are
# defined in the makefiles. This can be changed if necessary, by uncommenting
# this line and specifying another shell, but note that a Bourne-compatible
# shell is expected.

# MAKE_SHELL=/bin/sh


#------------------------------------------------------------------------------
# The maximum number of named lists of each type (address, domain, host, and
# local part) can be increased by changing this value. It should be set to
# a multiple of 16.

# MAX_NAMED_LIST=16


#------------------------------------------------------------------------------
# Network interfaces: Unless you set the local_interfaces option in the runtime
# configuration file to restrict Exim to certain interfaces only, it will run
# code to find all the interfaces there are on your host. Unfortunately,
# the call to the OS that does this requires a buffer large enough to hold
# data for all the interfaces - it was designed in the days when a host rarely
# had more than three or four interfaces. Nowadays hosts can have very many
# virtual interfaces running on the same hardware. If you have more than 250
# virtual interfaces, you will need to uncomment this setting and increase the
# value.

# MAXINTERFACES=250


#------------------------------------------------------------------------------
# Per-message logs: While a message is in the process of being delivered,
# comments on its progress are written to a message log, for the benefit of
# human administrators. These logs are held in a directory called "msglog"
# in the spool directory. Its mode defaults to 0750, but can be changed here.
# The message log directory is also used for storing files that are used by
# transports for returning data to a message's sender (see the "return_output"
# option for transports).

# MSGLOG_DIRECTORY_MODE=0750


#------------------------------------------------------------------------------
# There are three options which are used when compiling the Perl interface and
# when linking with Perl. The default values for these are placed automatically
# at the head of the Makefile by the script which builds it. However, if you
# want to override them, you can do so here.

# PERL_CC=
# PERL_CCOPTS=
# PERL_LIBS=


#------------------------------------------------------------------------------
# If you wish to disable valgrind in the binary, define NVALGRIND=1.
# This should not be needed.

# NVALGRIND=1

#------------------------------------------------------------------------------
# Identifying the daemon: When an Exim daemon starts up, it writes its pid
# (process id) to a file so that it can easily be identified. The path of the
# file can be specified here. Some installations may want something like this:

# PID_FILE_PATH=/var/lock/exim.pid

# If PID_FILE_PATH is not defined, Exim writes a file in its spool directory
# using the name "exim-daemon.pid".

# If you start up a daemon without the -bd option (for example, with just
# the -q15m option), a pid file is not written. Also, if you override the
# configuration file with the -oX option, no pid file is written. In other
# words, the pid file is written only for a "standard" daemon.


#------------------------------------------------------------------------------
# If Exim creates the spool directory, it is given this mode, defaulting in the
# source to 0750.

# SPOOL_DIRECTORY_MODE=0750


#------------------------------------------------------------------------------
# The mode of files on the input spool which hold the contents of messages can
# be changed here. The default is 0640 so that information from the spool is
# available to anyone who is a member of the Exim group.

# SPOOL_MODE=0640


#------------------------------------------------------------------------------
# Moving frozen messages: If the following is uncommented, Exim is compiled
# with support for automatically moving frozen messages out of the main spool
# directory, a facility that is found useful by some large installations. A
# run time option is required to cause the moving actually to occur. Such
# messages become "invisible" to the normal management tools.

# SUPPORT_MOVE_FROZEN_MESSAGES=yes


#------------------------------------------------------------------------------
# Expanding match_* second parameters: BE CAREFUL IF ENABLING THIS!
# It has proven too easy in practice for administrators to configure security
# problems into their Exim install, by treating match_domain{}{} and friends
# as a form of string comparison, where the second string comes from untrusted
# data. Because these options take lists, which can include lookup;LOOKUPDATA
# style elements, a foe can then cause Exim to, eg, execute an arbitrary MySQL
# query, dropping tables.
# From Exim 4.77 onwards, the second parameter is not expanded; it can still
# be a list literal, or a macro, or a named list reference.  There is also
# the new expansion condition "inlisti" which does expand the second parameter,
# but treats it as a list of strings; also, there's "eqi" which is probably
# what is normally wanted.
#
# If you really need to have the old behaviour, know what you are doing and
# will not complain if your system is compromised as a result of doing so, then
# uncomment this option to get the old behaviour back.

# EXPAND_LISTMATCH_RHS=yes

#------------------------------------------------------------------------------
# Disabling the use of fsync(): DO NOT UNCOMMENT THE FOLLOWING LINE unless you
# really, really, really know what you are doing. And even then, think again.
# You should never uncomment this when compiling a binary for distribution.
# Use it only when compiling Exim for your own use.
#
# Uncommenting this line enables the use of a runtime option called
# disable_fsync, which can be used to stop Exim using fsync() to ensure that
# files are written to disc before proceeding. When this is disabled, crashes
# and hardware problems such as power outages can cause data to be lost. This
# feature should only be used in very exceptional circumstances. YOU HAVE BEEN
# WARNED.

# ENABLE_DISABLE_FSYNC=yes

# End of EDITME for Exim 4.
