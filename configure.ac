#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(paperkey, 0.5, dshaw@jabberwocky.com)
AC_REVISION([$Id$])
AC_COPYRIGHT([Copyright (C) 2007 David Shaw])
AC_GNU_SOURCE
AC_CONFIG_SRCDIR([paperkey.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([std-options])

# Checks for programs.
AC_PROG_CC
gl_EARLY
AC_PROG_RANLIB

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.

# Gnulib stuff.
gl_SOURCE_BASE(gl)
gl_M4_BASE(gl/m4)
gl_LIB(libgl)
gl_MODULES(getopt crypto/sha1)
gl_INIT

AC_ARG_ENABLE(optimization,
   AC_HELP_STRING([--disable-optimization],[disable compiler optimization]),
   [if test $enableval = no ; then
      CFLAGS=`echo $CFLAGS | sed 's/-O[[0-9]]//'`
   fi])

AM_CONDITIONAL(USING_GCC, test "$GCC" = yes)

AC_CONFIG_FILES([gl/Makefile Makefile checks/Makefile paperkey.spec])
AC_OUTPUT
