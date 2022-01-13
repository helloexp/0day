# PR_FUNC_SETGRENT_VOID
# ---------------------
# Check whether setgret returns void, and #define SETGRENT_VOID in
# that case.
AC_DEFUN([PR_FUNC_SETGRENT_VOID],
[AC_CACHE_CHECK([whether setgrent returns void], [ac_cv_func_setgrent_void],
  [AC_RUN_IFELSE([
    #include <sys/types.h>
    #include <grp.h>
    int main(int argc, char *argv[]) {
      int i = 0;
      getgrent();
      i = setgrent();
      return (i != 1);
    }
  ],
  [ac_cv_func_setgrent_void=no],
  [ac_cv_func_setgrent_void=yes],
  [ac_cv_func_setgrent_void=yes],
)])

if test $ac_cv_func_setgrent_void = yes; then
  AC_DEFINE(SETGRENT_VOID, 1,
    [Define to 1 if the `setgrent' function returns void instead of `int'.])
fi
])

# PR_CHECK_CC_OPT
# ---------------------
# Check whether the C compiler accepts the given option
AC_DEFUN(PR_CHECK_CC_OPT,
  [AC_MSG_CHECKING([whether ${CC-cc} accepts -[$1]])
   echo 'void f(){}' > conftest.c
   if test -z "`${CC-cc} -c -$1 conftest.c 2>&1`"; then
     AC_MSG_RESULT(yes)
     CFLAGS="$CFLAGS -$1"
   else
     AC_MSG_RESULT(no)
   fi
   rm -fr conftest*
  ])

# PR_CHECK_SS_FAMILY
# ---------------------
# Check which member of the struct sockaddr_storage contains the family
# information
AC_DEFUN([PR_CHECK_SS_FAMILY],
[
  AC_MSG_CHECKING([whether ss_family is defined])
  AC_TRY_COMPILE([
    #include <stdio.h>
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/socket.h>
  ],
  [
    do {
     struct sockaddr_storage a;
     (void) a.ss_family;
    } while(0)
  ],
  [
    AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_SS_FAMILY, 1,
      [Define if you have sockaddr_storage.ss_family.])
  ],
  [
    AC_MSG_RESULT(no)
    AC_MSG_CHECKING([whether __ss_family is defined])
    AC_TRY_COMPILE([
      #include <stdio.h>
      #include <unistd.h>
      #include <sys/types.h>
      #include <sys/socket.h>
    ],
    [
      do {
       struct sockaddr_storage a;
       (void) a.__ss_family;
      } while(0)
    ],
    [
      AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE___SS_FAMILY, 1,
        [Define if you have sockaddr_store.__ss_family.])
    ],
    [
      AC_MSG_RESULT(no)
    ])
  ])
])

# PR_CHECK_STRUCT_ADDRINFO
# ---------------------
# Check whether the system has a struct addrinfo defined
AC_DEFUN([PR_CHECK_STRUCT_ADDRINFO],
[AC_MSG_CHECKING([whether struct addrinfo is defined])
 AC_TRY_COMPILE(
 [ #include <stdio.h>
   #ifdef HAVE_UNISTD_H
   # include <unistd.h>
   #endif
   #include <sys/types.h>
   #include <sys/socket.h>
   #include <netdb.h>
 ],
 [do {
   struct addrinfo a;
   (void) a.ai_flags;
  } while(0)
 ],
 [AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_STRUCT_ADDRINFO, 1,
    [Define if you have struct addrinfo])
 ],
 [AC_MSG_RESULT(no)
 ])
])

# PR_CHECK_STRUCT_SS
# ---------------------
# Check whether the system has a struct sockaddr_storage defined
AC_DEFUN([PR_CHECK_STRUCT_SS],
[AC_MSG_CHECKING([whether struct sockaddr_storage is defined])
 AC_TRY_COMPILE(
 [ #include <stdio.h>
   #ifdef HAVE_UNISTD_H
   # include <unistd.h>
   #endif
   #include <sys/types.h>
   #include <sys/socket.h>
   #include <netdb.h>
 ],
 [do {
   struct sockaddr_storage ss;
  } while(0)
 ],
 [AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_STRUCT_SS, 1, [Define if you have struct sockaddr_storage])
 ],
 [AC_MSG_RESULT(no)
 ])
])

# PR_CHECK_SS_LEN
# ---------------------
# Check which member of the struct sockaddr_storage contains the length
# information
AC_DEFUN([PR_CHECK_SS_LEN],
[
  AC_MSG_CHECKING([whether ss_len is defined])
  AC_TRY_COMPILE([
    #include <stdio.h>
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/socket.h>
  ],
  [
    do {
     struct sockaddr_storage a;
     (void) a.ss_len;
    } while(0)
  ],
  [
    AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_SS_LEN, 1,
      [Define if you have sockaddr_storage.ss_len.])
  ],
  [
    AC_MSG_RESULT(no)
    AC_MSG_CHECKING([whether __ss_len is defined])
    AC_TRY_COMPILE([
      #include <stdio.h>
      #include <unistd.h>
      #include <sys/types.h>
      #include <sys/socket.h>
    ],
    [
      do {
       struct sockaddr_storage a;
       (void) a.__ss_len;
      } while(0)
    ],
    [
      AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE___SS_LEN, 1, 
        [Define if you have sockaddr_storage.__ss_len.])
    ],
    [
      AC_MSG_RESULT(no)
    ])
  ])
])

