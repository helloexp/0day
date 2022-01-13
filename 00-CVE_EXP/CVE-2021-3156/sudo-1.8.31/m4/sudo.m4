dnl Local m4 macros for autoconf (used by sudo)
dnl
dnl SPDX-License-Identifier: ISC
dnl
dnl Copyright (c) 1994-1996, 1998-2005, 2007-2015
dnl	Todd C. Miller <Todd.Miller@sudo.ws>
dnl
dnl Permission to use, copy, modify, and distribute this software for any
dnl purpose with or without fee is hereby granted, provided that the above
dnl copyright notice and this permission notice appear in all copies.
dnl
dnl THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
dnl WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
dnl MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
dnl ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
dnl WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
dnl ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
dnl OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
dnl
dnl XXX - should cache values in all cases!!!
dnl
dnl checks for programs

dnl
dnl check for sendmail in well-known locations
dnl
AC_ARG_VAR([SENDMAILPROG], [The fully-qualified path to the sendmail program to use.])
AC_DEFUN([SUDO_PROG_SENDMAIL], [
    AC_PATH_PROG([SENDMAILPROG], [sendmail], [], [/usr/sbin$PATH_SEPARATOR/usr/lib$PATH_SEPARATOR/usr/etc$PATH_SEPARATOR/usr/ucblib$PATH_SEPARATOR/usr/local/lib$PATH_SEPARATOR/usr/local/bin])
    test -n "${ac_cv_path_SENDMAILPROG}" && SUDO_DEFINE_UNQUOTED(_PATH_SUDO_SENDMAIL, "${ac_cv_path_SENDMAILPROG}")
])dnl

dnl
dnl check for vi in well-known locations
dnl
AC_ARG_VAR([VIPROG], [The fully-qualified path to the vi program to use.])
AC_DEFUN([SUDO_PROG_VI], [
    AC_PATH_PROG([VIPROG], [vi], [], [/usr/bin$PATH_SEPARATOR/bin$PATH_SEPARATOR/usr/ucb$PATH_SEPARATOR/usr/bsd$PATH_SEPARATOR/usr/local/bin])
    test -n "${ac_cv_path_VIPROG}" && SUDO_DEFINE_UNQUOTED(_PATH_VI, "${ac_cv_path_VIPROG}")
])dnl

dnl
dnl check for mv in well-known locations
dnl
AC_ARG_VAR([MVPROG], [The fully-qualified path to the mv program to use.])
AC_DEFUN([SUDO_PROG_MV], [
    AC_PATH_PROG([MVPROG], [mv], [], [/usr/bin$PATH_SEPARATOR/bin$PATH_SEPARATOR/usr/ucb$PATH_SEPARATOR/usr/local/bin])
    test -n "${ac_cv_path_MVPROG}" && SUDO_DEFINE_UNQUOTED(_PATH_MV, "${ac_cv_path_MVPROG}")
])dnl

dnl
dnl check for bourne shell in well-known locations
dnl
AC_ARG_VAR([BSHELLPROG], [The fully-qualified path to the Bourne shell to use.])
AC_DEFUN([SUDO_PROG_BSHELL], [
    AC_PATH_PROG([BSHELLPROG], [sh], [/usr/bin$PATH_SEPARATOR/bin$PATH_SEPARATOR/usr/sbin$PATH_SEPARATOR/sbin])
    test -n "${ac_cv_path_BSHELLPROG}" && SUDO_DEFINE_UNQUOTED(_PATH_BSHELL, "${ac_cv_path_BSHELLPROG}")
])dnl

dnl
dnl check for utmp file
dnl
AC_DEFUN([SUDO_PATH_UTMP], [AC_MSG_CHECKING([for utmp file path])
found=no
for p in "/var/run/utmp" "/var/adm/utmp" "/etc/utmp"; do
    if test -r "$p"; then
	found=yes
	AC_MSG_RESULT([$p])
	SUDO_DEFINE_UNQUOTED(_PATH_UTMP, "$p")
	break
    fi
done
if test X"$found" != X"yes"; then
    AC_MSG_RESULT([not found])
fi
])dnl

dnl
dnl Where the log file goes, use /var/log if it exists, else /{var,usr}/adm
dnl
AC_DEFUN([SUDO_LOGFILE], [AC_MSG_CHECKING(for log file location)
if test -n "$with_logpath"; then
    AC_MSG_RESULT($with_logpath)
    SUDO_DEFINE_UNQUOTED(_PATH_SUDO_LOGFILE, "$with_logpath")
elif test -d "/var/log"; then
    AC_MSG_RESULT(/var/log/sudo.log)
    SUDO_DEFINE(_PATH_SUDO_LOGFILE, "/var/log/sudo.log")
elif test -d "/var/adm"; then
    AC_MSG_RESULT(/var/adm/sudo.log)
    SUDO_DEFINE(_PATH_SUDO_LOGFILE, "/var/adm/sudo.log")
elif test -d "/usr/adm"; then
    AC_MSG_RESULT(/usr/adm/sudo.log)
    SUDO_DEFINE(_PATH_SUDO_LOGFILE, "/usr/adm/sudo.log")
else
    AC_MSG_RESULT(unknown, you will have to set _PATH_SUDO_LOGFILE by hand)
fi
])dnl

dnl
dnl Detect time zone file directory, if any.
dnl
AC_DEFUN([SUDO_TZDIR], [AC_MSG_CHECKING(time zone data directory)
tzdir="$with_tzdir"
if test -z "$tzdir"; then
    tzdir=no
    for d in /usr/share /usr/share/lib /usr/lib /etc; do
	if test -d "$d/zoneinfo"; then
	    tzdir="$d/zoneinfo"
	    break
	fi
    done
fi
AC_MSG_RESULT([$tzdir])
if test "${tzdir}" != "no"; then
    SUDO_DEFINE_UNQUOTED(_PATH_ZONEINFO, "$tzdir")
fi
])dnl

dnl
dnl Parent directory for time stamp dir.
dnl
AC_DEFUN([SUDO_RUNDIR], [AC_MSG_CHECKING(for sudo run dir location)
rundir="$with_rundir"
if test -z "$rundir"; then
    for d in /run /var/run /var/db /var/lib /var/adm /usr/adm; do
	if test -d "$d"; then
	    rundir="$d/sudo"
	    break
	fi
    done
fi
AC_MSG_RESULT([$rundir])
SUDO_DEFINE_UNQUOTED(_PATH_SUDO_TIMEDIR, "$rundir/ts")
])dnl

dnl
dnl Parent directory for the lecture status dir.
dnl
AC_DEFUN([SUDO_VARDIR], [AC_MSG_CHECKING(for sudo var dir location)
vardir="$with_vardir"
if test -z "$vardir"; then
    for d in /var/db /var/lib /var/adm /usr/adm; do
	if test -d "$d"; then
	    vardir="$d/sudo"
	    break
	fi
    done
fi
AC_MSG_RESULT([$vardir])
SUDO_DEFINE_UNQUOTED(_PATH_SUDO_LECTURE_DIR, "$vardir/lectured")
])dnl

dnl
dnl Where the I/O log files go, use /var/log/sudo-io if
dnl /var/log exists, else /{var,usr}/adm/sudo-io
dnl
AC_DEFUN([SUDO_IO_LOGDIR], [
    AC_MSG_CHECKING(for I/O log dir location)
    if test "${with_iologdir-yes}" != "yes"; then
	iolog_dir="$with_iologdir"
    elif test -d "/var/log"; then
	iolog_dir="/var/log/sudo-io"
    elif test -d "/var/adm"; then
	iolog_dir="/var/adm/sudo-io"
    else
	iolog_dir="/usr/adm/sudo-io"
    fi
    if test "${with_iologdir}" != "no"; then
	SUDO_DEFINE_UNQUOTED(_PATH_SUDO_IO_LOGDIR, "$iolog_dir")
    fi
    AC_MSG_RESULT($iolog_dir)
])dnl

dnl
dnl check for working fnmatch(3)
dnl
AC_DEFUN([SUDO_FUNC_FNMATCH],
[AC_MSG_CHECKING([for working fnmatch with FNM_CASEFOLD])
AC_CACHE_VAL(sudo_cv_func_fnmatch,
[rm -f conftestdata; > conftestdata
AC_RUN_IFELSE([AC_LANG_SOURCE([[#include <fnmatch.h>
main() { exit(fnmatch("/*/bin/echo *", "/usr/bin/echo just a test", FNM_CASEFOLD)); }]])], [sudo_cv_func_fnmatch=yes], [sudo_cv_func_fnmatch=no],
  [sudo_cv_func_fnmatch=no])
rm -f core core.* *.core])
AC_MSG_RESULT($sudo_cv_func_fnmatch)
AS_IF([test $sudo_cv_func_fnmatch = yes], [$1], [$2])])

dnl
dnl Attempt to check for working PIE support.
dnl This is a bit of a hack but on Solaris 10 with GNU ld and GNU as
dnl we can end up with strange values from malloc().
dnl A better check would be to verify that ASLR works with PIE.
dnl
AC_DEFUN([SUDO_WORKING_PIE],
[AC_MSG_CHECKING([for working PIE support])
AC_CACHE_VAL(sudo_cv_working_pie,
[rm -f conftestdata; > conftestdata
AC_RUN_IFELSE([AC_LANG_SOURCE([AC_INCLUDES_DEFAULT
main() { char *p = malloc(1024); if (p == NULL) return 1; memset(p, 0, 1024); return 0; }])], [sudo_cv_working_pie=yes], [sudo_cv_working_pie=no],
  [sudo_cv_working_pie=no])
rm -f core core.* *.core])
AC_MSG_RESULT($sudo_cv_working_pie)
AS_IF([test $sudo_cv_working_pie = yes], [$1], [$2])])

dnl
dnl check for isblank(3)
dnl
AC_DEFUN([SUDO_FUNC_ISBLANK],
  [AC_CACHE_CHECK([for isblank], [sudo_cv_func_isblank],
    [AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <ctype.h>]], [[return (isblank('a'));]])],
    [sudo_cv_func_isblank=yes], [sudo_cv_func_isblank=no])])
] [
  if test "$sudo_cv_func_isblank" = "yes"; then
    AC_DEFINE(HAVE_ISBLANK, 1, [Define if you have isblank(3).])
  else
    AC_LIBOBJ(isblank)
    SUDO_APPEND_COMPAT_EXP(isblank)
  fi
])

AC_DEFUN([SUDO_CHECK_LIB], [
    _sudo_check_lib_extras=`echo "$5"|sed -e 's/[ 	]*//g' -e 's/-l/_/g'`
    AC_MSG_CHECKING([for $2 in -l$1${5+ }$5])
    AC_CACHE_VAL([sudo_cv_lib_$1''_$2$_sudo_check_lib_extras], [
	SUDO_CHECK_LIB_OLIBS="$LIBS"
	LIBS="$LIBS -l$1${5+ }$5"
	AC_LINK_IFELSE(
	    [AC_LANG_CALL([], [$2])],
	    [eval sudo_cv_lib_$1''_$2$_sudo_check_lib_extras=yes],
	    [eval sudo_cv_lib_$1''_$2$_sudo_check_lib_extras=no]
	)
	LIBS="$SUDO_CHECK_LIB_OLIBS"
    ])
    if eval test \$sudo_cv_lib_$1''_$2$_sudo_check_lib_extras = "yes"; then
	AC_MSG_RESULT([yes])
	$3
    else
	AC_MSG_RESULT([no])
	$4
    fi
])

dnl
dnl check unsetenv() return value
dnl
AC_DEFUN([SUDO_FUNC_UNSETENV_VOID],
  [AC_CACHE_CHECK([whether unsetenv returns void], [sudo_cv_func_unsetenv_void],
    [AC_RUN_IFELSE([AC_LANG_PROGRAM(
      [AC_INCLUDES_DEFAULT
        int unsetenv();
      ], [
        [return unsetenv("FOO") != 0;]
      ])
    ],
    [sudo_cv_func_unsetenv_void=no],
    [sudo_cv_func_unsetenv_void=yes],
    [sudo_cv_func_unsetenv_void=no])])
    if test $sudo_cv_func_unsetenv_void = yes; then
      AC_DEFINE(UNSETENV_VOID, 1,
        [Define to 1 if the `unsetenv' function returns void instead of `int'.])
    fi
  ])

dnl
dnl check putenv() argument for const
dnl
AC_DEFUN([SUDO_FUNC_PUTENV_CONST],
[AC_CACHE_CHECK([whether putenv takes a const argument],
sudo_cv_func_putenv_const,
[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([AC_INCLUDES_DEFAULT
int putenv(const char *string) {return 0;}], [])],
    [sudo_cv_func_putenv_const=yes],
    [sudo_cv_func_putenv_const=no])
  ])
  if test $sudo_cv_func_putenv_const = yes; then
    AC_DEFINE(PUTENV_CONST, const, [Define to const if the `putenv' takes a const argument.])
  else
    AC_DEFINE(PUTENV_CONST, [])
  fi
])

dnl
dnl check whether au_close() takes 3 or 4 arguments
dnl
AC_DEFUN([SUDO_FUNC_AU_CLOSE_SOLARIS11],
[AC_CACHE_CHECK([whether au_close() takes 4 arguments],
sudo_cv_func_au_close_solaris11,
[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([AC_INCLUDES_DEFAULT
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_uevents.h>

int au_close(int d, int keep, au_event_t event, au_emod_t emod) {return 0;}], [])],
    [sudo_cv_func_au_close_solaris11=yes],
    [sudo_cv_func_au_close_solaris11=no])
  ])
  if test $sudo_cv_func_au_close_solaris11 = yes; then
    AC_DEFINE(HAVE_AU_CLOSE_SOLARIS11, 1, [Define to 1 if the `au_close' functions takes 4 arguments like Solaris 11.])
  fi
])

dnl
dnl Check if the data argument for the sha2 functions is void * or u_char *
dnl
AC_DEFUN([SUDO_FUNC_SHA2_VOID_PTR],
[AC_CACHE_CHECK([whether the data argument of SHA224Update() is void *],
sudo_cv_func_sha2_void_ptr,
[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([AC_INCLUDES_DEFAULT
#include <sha2.h>
void SHA224Update(SHA2_CTX *context, const void *data, size_t len) {return;}], [])],
    [sudo_cv_func_sha2_void_ptr=yes],
    [sudo_cv_func_sha2_void_ptr=no])
  ])
  if test $sudo_cv_func_sha2_void_ptr = yes; then
    AC_DEFINE(SHA2_VOID_PTR, 1,
      [Define to 1 if the sha2 functions use `const void *' instead of `const unsigned char'.])
  fi
])

dnl
dnl check for sa_len field in struct sockaddr
dnl
AC_DEFUN([SUDO_SOCK_SA_LEN], [
    AC_CHECK_MEMBER([struct sockaddr.sa_len], 
	[AC_DEFINE(HAVE_STRUCT_SOCKADDR_SA_LEN, 1, [Define if your struct sockaddr has an sa_len field.])],
	[], [
#	  include <sys/types.h>
#	  include <sys/socket.h>] 
    )]
)

dnl
dnl check for sin_len field in struct sockaddr_in
dnl
AC_DEFUN([SUDO_SOCK_SIN_LEN], [
    AC_CHECK_MEMBER([struct sockaddr_in.sin_len],
	[AC_DEFINE(HAVE_STRUCT_SOCKADDR_IN_SIN_LEN, 1, [Define if your struct sockaddr_in has a sin_len field.])],
	[], [
#	  include <sys/types.h>
#	  include <sys/socket.h>]
    )]
)

dnl
dnl check for max length of uid_t in string representation.
dnl we can't really trust UID_MAX or MAXUID since they may exist
dnl only for backwards compatibility.
dnl
AC_DEFUN([SUDO_UID_T_LEN],
[AC_REQUIRE([AC_TYPE_UID_T])
AC_MSG_CHECKING(max length of uid_t)
AC_CACHE_VAL(sudo_cv_uid_t_len,
[rm -f conftestdata
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdio.h>
#include <pwd.h>
#include <limits.h>
#include <sys/types.h>
main() {
  FILE *f;
  char b[1024];
  uid_t u = (uid_t) -1;

  if ((f = fopen("conftestdata", "w")) == NULL)
    exit(1);

  (void) sprintf(b, "%lu", (unsigned long) u);
  (void) fprintf(f, "%d\n", strlen(b));
  (void) fclose(f);
  exit(0);
}]])], [sudo_cv_uid_t_len=`cat conftestdata`], [sudo_cv_uid_t_len=10], [sudo_cv_uid_t_len=10])
])
rm -f conftestdata
AC_MSG_RESULT($sudo_cv_uid_t_len)
AC_DEFINE_UNQUOTED(MAX_UID_T_LEN, $sudo_cv_uid_t_len, [Define to the max length of a uid_t in string context (excluding the NUL).])
])

dnl
dnl There are three different utmp variants we need to check for.
dnl SUDO_CHECK_UTMP_MEMBERS(utmp_type)
dnl
AC_DEFUN([SUDO_CHECK_UTMP_MEMBERS], [
    dnl
    dnl Check for utmp/utmpx/utmps struct members.
    dnl
    AC_CHECK_MEMBER([struct $1.ut_id], [
	AC_DEFINE(HAVE_STRUCT_UTMP_UT_ID, 1, [Define to 1 if `ut_id' is a member of `struct utmp'.])
    ], [], [
#	include <sys/types.h>
#	include <$1.h>
    ])
    AC_CHECK_MEMBER([struct $1.ut_pid], [
	AC_DEFINE(HAVE_STRUCT_UTMP_UT_PID, 1, [Define to 1 if `ut_pid' is a member of `struct utmp'.])
    ], [], [
#	include <sys/types.h>
#	include <$1.h>
    ])
    AC_CHECK_MEMBER([struct $1.ut_tv], [
	AC_DEFINE(HAVE_STRUCT_UTMP_UT_TV, 1, [Define to 1 if `ut_tv' is a member of `struct utmp'.])
    ], [], [
#	include <sys/types.h>
#	include <$1.h>
    ])
    AC_CHECK_MEMBER([struct $1.ut_type], [
	AC_DEFINE(HAVE_STRUCT_UTMP_UT_TYPE, 1, [Define to 1 if `ut_type' is a member of `struct utmp'.])
    ], [], [
#	include <sys/types.h>
#	include <$1.h>
    ])
    dnl
    dnl Older struct utmp has ut_name instead of ut_user
    dnl
    if test "$1" = "utmp"; then
	AC_CHECK_MEMBERS([struct utmp.ut_user], [], [], [
#	include <sys/types.h>
#	include <$1.h>
	])
    fi
    dnl
    dnl Check for ut_exit.__e_termination first, then ut_exit.e_termination
    dnl We need to have already defined _GNU_SOURCE on glibc which only has
    dnl __e_termination visible when _GNU_SOURCE is *not* defined.
    dnl
    AC_CHECK_MEMBER([struct $1.ut_exit.__e_termination], [
	AC_DEFINE(HAVE_STRUCT_UTMP_UT_EXIT, 1, [Define to 1 if `ut_exit' is a member of `struct utmp'.])
	AC_DEFINE(HAVE_STRUCT_UTMP_UT_EXIT___E_TERMINATION, 1, [Define to 1 if `ut_exit.__e_termination' is a member of `struct utmp'.])
    ], [
	AC_CHECK_MEMBER([struct $1.ut_exit.e_termination], [
	    AC_DEFINE(HAVE_STRUCT_UTMP_UT_EXIT, 1, [Define to 1 if `ut_exit' is a member of `struct utmp'.])
	    AC_DEFINE(HAVE_STRUCT_UTMP_UT_EXIT_E_TERMINATION, 1, [Define to 1 if `ut_exit.e_termination' is a member of `struct utmp'.])
	], [], [
#	    include <sys/types.h>
#	    include <$1.h>
	])
    ], [
#	include <sys/types.h>
#	include <$1.h>
    ])
])

dnl
dnl Append a libpath to an LDFLAGS style variable if not already present.
dnl Also appends to the _R version unless rpath is disabled.
dnl
AC_DEFUN([SUDO_APPEND_LIBPATH], [
    AX_APPEND_FLAG([-L$2], [$1])
    if test X"$enable_rpath" = X"yes"; then
	AX_APPEND_FLAG([-R$2], [$1_R])
    fi
])

dnl
dnl Append one or more symbols to COMPAT_EXP
dnl
AC_DEFUN([SUDO_APPEND_COMPAT_EXP], [
    for _sym in $1; do
	COMPAT_EXP="${COMPAT_EXP}${_sym}
"
    done
])

dnl
dnl Determine the mail spool location
dnl NOTE: must be run *after* check for paths.h
dnl
AC_DEFUN([SUDO_MAILDIR], [
maildir=no
if test X"$ac_cv_header_paths_h" = X"yes"; then
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([AC_INCLUDES_DEFAULT
#include <paths.h>],
[char *p = _PATH_MAILDIR;])], [maildir=yes], [])
fi
if test $maildir = no; then
    # Solaris has maillock.h which defines MAILDIR
    AC_CHECK_HEADERS(maillock.h, [
	SUDO_DEFINE(_PATH_MAILDIR, MAILDIR)
	maildir=yes
    ])
    if test $maildir = no; then
	for d in /var/mail /var/spool/mail /usr/spool/mail; do
	    if test -d "$d"; then
		maildir=yes
		SUDO_DEFINE_UNQUOTED(_PATH_MAILDIR, "$d")
		break
	    fi
	done
	if test $maildir = no; then
	    # unable to find mail dir, hope for the best
	    SUDO_DEFINE_UNQUOTED(_PATH_MAILDIR, "/var/mail")
	fi
    fi
fi
])

dnl
dnl private versions of AC_DEFINE and AC_DEFINE_UNQUOTED that don't support
dnl tracing that we use to define paths for pathnames.h so autoheader doesn't
dnl put them in config.h.in.  An awful hack.
dnl
m4_define([SUDO_DEFINE],
[cat >>confdefs.h <<\EOF
[@%:@define] $1 m4_if($#, 2, [$2], $#, 3, [$2], 1)
EOF
])

m4_define([SUDO_DEFINE_UNQUOTED],
[cat >>confdefs.h <<EOF
[@%:@define] $1 m4_if($#, 2, [$2], $#, 3, [$2], 1)
EOF
])
