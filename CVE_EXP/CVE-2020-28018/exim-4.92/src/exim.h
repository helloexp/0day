/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


/* Source files for exim all #include this header, which drags in everything
that is needed. They don't all need everything, of course, but it's far too
messy to have each one importing its own list, and anyway, most of them need
most of these includes. */

#ifndef EXIM_H
#define EXIM_H

/* Assume most systems have statfs() unless os.h undefines this macro */

#define HAVE_STATFS

/* Similarly, assume most systems have srandom() unless os.h undefines it.
This call dates back at least as far as SUSv2. */

#define HAVE_SRANDOM

/* This is primarily for the Gnu C library; we define it before os.h so that
os.h has a chance to hurriedly undef it, Just In Case.  We need C99 for some
64-bit math support, and defining _ISOC99_SOURCE breaks <resolv.h> and friends.
*/

#define _GNU_SOURCE 1

/* First of all include the os-specific header, which might set things that
are needed by any of the other headers, including system headers. */

#include "os.h"

/* If it didn't define os_find_running_interfaces, use the common function. */

#ifndef os_find_running_interfaces
# define os_find_running_interfaces os_common_find_running_interfaces
#endif

/* If it didn't define the base for "base 62" numbers, we really do use 62.
This is the case for all real Unix and Unix-like OS. It's only Cygwin and
Darwin, with their case-insensitive file systems, that can't use base 62 for
making unique names. */

#ifndef BASE_62
# define BASE_62 62
#endif

/* The maximum value of localhost_number depends on the base being used */

#if BASE_62 == 62
# define LOCALHOST_MAX  16
#else
# define LOCALHOST_MAX  10
#endif

/* If not overridden by os.h, dynamic libraries have filenames ending .so */
#ifndef DYNLIB_FN_EXT
# define DYNLIB_FN_EXT "so"
#endif

/* ANSI C standard includes */

#include <ctype.h>
#include <locale.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Unix includes */

#include <errno.h>
#if defined(__svr4__) && defined(__sparc) && ! defined(__EXTENSIONS__)
# define __EXTENSIONS__  /* so that SunOS 5 gets NGROUPS_MAX */
# include <limits.h>
# undef  __EXTENSIONS__
#else
# include <limits.h>
#endif

/* C99 integer types, figure out how to undo this if needed for older systems */

#include <inttypes.h>

/* Just in case some aged system doesn't define them... */

#ifndef INT_MAX
# define INT_MAX 2147483647
#endif

#ifndef INT_MIN
# define INT_MIN (-INT_MAX - 1)
#endif

#ifndef SHRT_MAX
# define SHRT_MAX 32767
#endif

#ifndef UCHAR_MAX
# define UCHAR_MAX 255
#endif


/* To match int_eximarith_t.  Define in OS/os.h-<your-system> to override. */
#ifndef EXIM_ARITH_MAX
# define EXIM_ARITH_MAX ((int_eximarith_t)9223372036854775807LL)
#endif
#ifndef EXIM_ARITH_MIN
# define EXIM_ARITH_MIN (-EXIM_ARITH_MAX - 1)
#endif

/* Some systems have PATH_MAX and some have MAX_PATH_LEN. */

#ifndef PATH_MAX
# ifdef MAX_PATH_LEN
#  define PATH_MAX MAX_PATH_LEN
# else
#  define PATH_MAX 1024
# endif
#endif

#include <sys/types.h>
#include <sys/file.h>
#include <dirent.h>
#include <netdb.h>
#ifndef NO_POLL_H
# include <poll.h>
#endif
#include <pwd.h>
#include <grp.h>
#include <syslog.h>

/* Not all systems have flock() available. Those that do must define LOCK_SH
in sys/file.h. */

#ifndef LOCK_SH
# define NO_FLOCK
#endif

#ifndef NO_SYSEXITS        /* some OS don't have this */
# include <sysexits.h>
#endif

/* A few OS don't have socklen_t; their os.h files define EXIM_SOCKLEN_T to
be size_t or whatever. We used to use SOCKLEN_T, but then it was discovered
that this is used by the AIX include files. */

#ifndef EXIM_SOCKLEN_T
# define EXIM_SOCKLEN_T socklen_t
#endif

/* Ensure that the sysexits we reference are defined */

#ifndef EX_UNAVAILABLE
# define EX_UNAVAILABLE 69        /* service unavailable; used for execv fail */
#endif
#ifndef EX_CANTCREAT
# define EX_CANTCREAT   73        /* can't create file: treat as temporary */
#endif
#ifndef EX_TEMPFAIL
# define EX_TEMPFAIL    75        /* temp failure; user is invited to retry */
#endif
#ifndef EX_CONFIG
# define EX_CONFIG      78        /* configuration error */
#endif

/* This one is not in any sysexits file that I've come across */

#define EX_EXECFAILED 127        /* execve() failed */


#include <sys/time.h>
#include <sys/param.h>

#ifndef NO_SYS_RESOURCE_H  /* QNX doesn't have this */
# include <sys/resource.h>
#endif

#include <sys/socket.h>

/* If we are on an IPv6 system, the macro AF_INET6 will have been defined in
the sys/socket.h header. It is helpful to have this defined on an IPv4 system
so that it can appear in the code, even if it is never actually used when
the code is run. It saves some #ifdef occurrences. */

#ifndef AF_INET6
# define AF_INET6 24
#endif

#include <sys/ioctl.h>

/* The new standard is statvfs; some OS have statfs. For statvfs the block
counts must be multiplied by the "fragment size" f_frsize to get the actual
size. In other cases the value seems to be f_bsize (which is sometimes the only
block size), so we use a macro to get that instead.

Also arrange to be able to cut it out altogether for way-out OS that don't have
anything. I've indented a bit here to try to make the mess a bit more
intelligible. Note that simply defining one name to be another when
HAVE_SYS_STATVFS_H is not set will not work if the system has a statvfs macro
or a macro with entries f_frsize and f_bsize. */

#ifdef HAVE_STATFS
  #ifdef HAVE_SYS_STATVFS_H
    #include <sys/statvfs.h>
    #define STATVFS statvfs
    #define F_FRSIZE f_frsize
  #else
    #define STATVFS statfs
    #define F_FRSIZE f_bsize
    #ifdef HAVE_SYS_VFS_H
      #include <sys/vfs.h>
      #ifdef HAVE_SYS_STATFS_H
      #include <sys/statfs.h>
      #endif
    #endif
    #ifdef HAVE_SYS_MOUNT_H
    #include <sys/mount.h>
    #endif
  #endif

  /* Macros for the fields for the available space for non-superusers; define
  these only if the OS header has not. Not all OS have f_favail; those that
  are known to have it define F_FAVAIL as f_favail. The default is to use
  f_free. */

  #ifndef F_BAVAIL
  # define F_BAVAIL f_bavail
  #endif

  #ifndef F_FAVAIL
  # define F_FAVAIL f_ffree
  #endif

  /* All the systems I've been able to look at seem to have F_FILES */

  #ifndef F_FILES
  # define F_FILES  f_files
  #endif

#endif


#ifndef  SIOCGIFCONF   /* HACK for SunOS 5 */
# include <sys/sockio.h>
#endif

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <fcntl.h>

/* There's a shambles in IRIX6 - it defines EX_OK in unistd.h which conflicts
with the definition in sysexits.h. Exim does not actually use this macro, so we
just undefine it. It would be nice to be able to re-instate the definition from
sysexits.h if there is no definition in unistd.h, but I do not think there is a
way to do this in C because macro definitions are not scanned for other macros
at definition time. [The code here used to assume they were, until I was
disabused of the notion. Luckily, since EX_OK is not used, it didn't matter.] */

#ifdef EX_OK
# undef EX_OK
#endif

#include <unistd.h>

#include <utime.h>
#ifndef NO_NET_IF_H
# include <net/if.h>
#endif
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>


/* While IPv6 is still young the definitions of T_AAAA and T_A6 may not be
included in arpa/nameser.h. Fudge them here. */

#ifndef T_AAAA
#define T_AAAA 28
#endif

#ifndef T_A6
#define T_A6 38
#endif

/* Ancient systems (e.g. SunOS4) don't appear to have T_TXT defined in their
header files. I don't suppose they have T_SRV either. */

#ifndef T_TXT
# define T_TXT 16
#endif

#ifndef T_SRV
# define T_SRV 33
#endif

/* Many systems do not have T_SPF. */

#ifndef T_SPF
# define T_SPF 99
#endif

/* New TLSA record for DANE */
#ifndef T_TLSA
# define T_TLSA 52
#endif
#define MAX_TLSA_EXPANDED_SIZE 8192

/* It seems that some versions of arpa/nameser.h don't define *any* of the
T_xxx macros, which seem to be non-standard nowadays. Just to be on the safe
side, put in definitions for all the ones that Exim uses. */

#ifndef T_A
# define T_A 1
#endif

#ifndef T_CNAME
# define T_CNAME 5
#endif

#ifndef T_SOA
# define T_SOA 6
#endif

#ifndef T_MX
# define T_MX 15
#endif

#ifndef T_NS
# define T_NS 2
#endif

#ifndef T_PTR
# define T_PTR 12
#endif


/* We define a few private types for special DNS lookups:

 . T_ZNS gets the nameservers of the enclosing zone of a domain

 . T_MXH gets the MX hostnames only (without their priorities)

 . T_CSA gets the domain's Client SMTP Authorization SRV record

 . T_ADDRESSES looks up both AAAA (or A6) and A records

If any of these names appear in the RRtype list at:
  <http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml>
then we should rename Exim's private type away from the conflict.
*/

#define T_ZNS (-1)
#define T_MXH (-2)
#define T_CSA (-3)
#define T_ADDRESSES (-4)

/* The resolv.h header defines __P(x) on some Solaris 2.5.1 systems (without
checking that it is already defined, in fact). This conflicts with other
headers that behave likewise (see below), leading to compiler warnings. Arrange
to undefine it if resolv.h defines it. */

#if defined(__P)
# define __P_WAS_DEFINED_BEFORE_RESOLV
#endif

#include <resolv.h>

#if defined(__P) && ! defined (__P_WAS_DEFINED_BEFORE_RESOLV)
# undef __P
#endif

/* If not defined by os.h, we do nothing special to push DNS resolver state
back to be available by the classic resolver routines.  Also, provide
prototype for our get routine, unless defined away. */

#ifndef os_put_dns_resolver_res
# define os_put_dns_resolver_res(R) do {/**/} while(0)
#endif
#ifndef os_get_dns_resolver_res
res_state os_get_dns_resolver_res(void);
#endif

/* These three are to support the IP option logging code. Linux is
different to everyone else and there are also other systems which don't
have netinet/ip_var.h, so there's a general macro to control its inclusion. */

#include <netinet/in_systm.h>
#include <netinet/ip.h>

#ifndef NO_IP_VAR_H
# include <netinet/ip_var.h>
#endif

/* Linux (and some others) uses a different type for the 2nd argument of
iconv(). It's os.h file defines ICONV_ARG2_TYPE. For the rest, define a default
here. */

#ifndef ICONV_ARG2_TYPE
# define ICONV_ARG2_TYPE char **
#endif

/* One OS uses a different type for the 5th argument of getsockopt */

#ifndef GETSOCKOPT_ARG5_TYPE
# define GETSOCKOPT_ARG5_TYPE socklen_t *
#endif

/* One operating system uses a different type for the 2nd argument of select().
Its os.h file defines SELECT_ARG2_TYPE. For the rest, define a default here. */

#ifndef SELECT_ARG2_TYPE
# define SELECT_ARG2_TYPE fd_set
#endif

/* One operating system uses a different type for the 4th argument of
dn_expand(). Its os.h file defines DN_EXPAND_ARG4_TYPE. For the rest, define a
default here. */

#ifndef DN_EXPAND_ARG4_TYPE
# define DN_EXPAND_ARG4_TYPE char *
#endif

/* One operating system defines a different type for the yield of inet_addr().
In Exim code, its value is always assigned to the s_addr members of address
structures. Casting the yield to the type of s_addr should fix the problem,
since the size of the data is correct. Just in case this ever has to be
changed, use a macro for the type, and define it here so that it is possible to
use different values for specific OS if ever necessary. */

#ifndef S_ADDR_TYPE
# define S_ADDR_TYPE u_long
#endif

/* (At least) one operating system (Solaris) defines a different type for the
second argument of pam_converse() - the difference is the absence of "const".
Its os.h file defines PAM_CONVERSE_ARG2_TYPE. For the rest, define a default
here. */

#ifndef PAM_CONVERSE_ARG2_TYPE
# define PAM_CONVERSE_ARG2_TYPE const struct pam_message
#endif

/* One operating system (SunOS4) defines getc, ungetc, feof, and ferror as
macros and not as functions. Exim needs them to be assignable functions. This
flag gets set to cause this to be sorted out here. */

#ifdef FUDGE_GETC_AND_FRIENDS
# undef getc
extern int getc(FILE *);
# undef ungetc
extern int ungetc(int, FILE *);
# undef feof
extern int feof(FILE *);
# undef ferror
extern int ferror(FILE *);
#endif

/* The header from the PCRE regex package */

#include <pcre.h>

/* Exim includes are in several files. Note that local_scan.h #includes
config.h, mytypes.h, and store.h, so we don't need to mention them explicitly.
*/

#include "local_scan.h"
#include "macros.h"
#include "dbstuff.h"
#include "structs.h"
#include "blob.h"
#include "globals.h"
#include "hash.h"
#include "functions.h"
#include "dbfunctions.h"
#include "osfunctions.h"

#ifdef EXPERIMENTAL_BRIGHTMAIL
# include "bmi_spam.h"
#endif
#ifdef SUPPORT_SPF
# include "spf.h"
#endif
#ifdef EXPERIMENTAL_SRS
# include "srs.h"
#endif
#ifndef DISABLE_DKIM
# include "dkim.h"
#endif
#ifdef EXPERIMENTAL_DMARC
# include "dmarc.h"
# include <opendmarc/dmarc.h>
#endif

/* The following stuff must follow the inclusion of config.h because it
requires various things that are set therein. */

#if HAVE_ICONV             /* Not all OS have this */
# include <iconv.h>
#endif

#if defined(USE_READLINE) || defined(EXPAND_DLFUNC) || defined (LOOKUP_MODULE_DIR)
# include <dlfcn.h>
#endif

#ifdef ENABLE_DISABLE_FSYNC
# define EXIMfsync(f) (disable_fsync? 0 : fsync(f))
#else
# define EXIMfsync(f) fsync(f)
#endif

/* Backward compatibility; LOOKUP_LSEARCH now includes all three */

#if (!defined LOOKUP_LSEARCH) && (defined LOOKUP_WILDLSEARCH || defined LOOKUP_NWILDLSEARCH)
# define LOOKUP_LSEARCH yes
#endif

/* Define a union to hold either an IPv4 or an IPv6 sockaddr structure; this
simplifies some of the coding.  We include the sockaddr to reduce type-punning
issues in C99. */

union sockaddr_46 {
  struct sockaddr_in v4;
  #if HAVE_IPV6
  struct sockaddr_in6 v6;
  #endif
  struct sockaddr v0;
};

/* If SUPPORT_TLS is not defined, ensure that USE_GNUTLS is also not defined
so that if USE_GNUTLS *is* set, we can assume SUPPORT_TLS is also set.
Likewise, OSCP, AUTH_TLS and CERTNAMES cannot be supported. */

#ifndef SUPPORT_TLS
# undef USE_GNUTLS
# ifndef DISABLE_OCSP
#  define DISABLE_OCSP
# endif
# undef EXPERIMENTAL_CERTNAMES
# undef AUTH_TLS
#endif

/* If SPOOL_DIRECTORY, LOG_FILE_PATH or PID_FILE_PATH have not been defined,
set them to the null string. */

#ifndef SPOOL_DIRECTORY
  #define SPOOL_DIRECTORY ""
#endif
#ifndef LOG_FILE_PATH
  #define LOG_FILE_PATH ""
#endif
#ifndef PID_FILE_PATH
  #define PID_FILE_PATH ""
#endif

/* The EDQUOT error code isn't universally available, though it is widespread.
There is a particular shambles in SunOS5, where it did not exist originally,
but got installed with a particular patch for Solaris 2.4. There is a
configuration variable for specifying what the system's "over quota" error is,
which will end up in config.h if supplied in OS/Makefile-xxx. If it is not set,
default to EDQUOT if it exists, otherwise ENOSPC. */

#ifndef ERRNO_QUOTA
# ifdef  EDQUOT
#  define ERRNO_QUOTA EDQUOT
# else
#  define ERRNO_QUOTA ENOSPC
# endif
#endif

/* DANE w/o DNSSEC is useless */
#if defined(SUPPORT_DANE) && defined(DISABLE_DNSSEC)
# error DANE support requires DNSSEC support
#endif

/* Some platforms (FreeBSD, OpenBSD, Solaris) do not seem to define this */

#ifndef POLLRDHUP
# define POLLRDHUP (POLLIN | POLLHUP)
#endif

/* Some platforms (Darwin) have to define a larger limit on groups membership */

#ifndef EXIM_GROUPLIST_SIZE
# define EXIM_GROUPLIST_SIZE NGROUPS_MAX
#endif

#endif
/* End of exim.h */
