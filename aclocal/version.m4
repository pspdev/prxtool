AC_DEFUN([PRXTOOL_VERSIONING],
m4_define([PRXTOOL_VERSION],[0.1.0]))

AC_DEFUN(AC_PRXTOOL_VERSION,
[
AC_REQUIRE([PRXTOOL_VERSIONING])
AC_BEFORE([$0], [AM_INIT_AUTOMAKE])

AC_MSG_CHECKING([for prxtool version])
AS_IF([test -r "${srcdir}/aclocal/version.m4"],
[],
[AC_MSG_ERROR([Unable to find aclocal/version.m4])])
AC_MSG_RESULT([PRXTOOL_VERSION])
])
