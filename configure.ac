#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT(libslips, 0.1, libslips@cisco.com)
AM_INIT_AUTOMAKE(libslips, 0.1)
AC_CONFIG_SRCDIR([src/slips.cc])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

# Checks for programs.
AC_PROG_CXX([g++-4.9 g++])
AC_PROG_CC([gcc-4.9 gcc])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_CHECK_FUNCS([memset modf])

LT_INIT
AC_CONFIG_FILES([Makefile
                 src/Makefile
                 code/Makefile])

AC_ARG_ENABLE(debug,
AS_HELP_STRING([--enable-debug], [enable debugging, default: no]),
[case "${enableval}" in
             yes) debug=true ;;
             no)  debug=false ;;
             *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac], [debug=false])

AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")
AC_OUTPUT
