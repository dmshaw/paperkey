#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([paperkey],[1.7-devel],[dshaw@jabberwocky.com])
m4_define(_COPYRIGHT_STRING,
   [[Copyright (C) 2007, 2008, 2009, 2012, 2013, 2016, 2017, 2018 David Shaw <dshaw@jabberwocky.com>]])
AC_COPYRIGHT(_COPYRIGHT_STRING)
AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_SRCDIR([paperkey.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([std-options])
AC_CANONICAL_HOST
AC_DEFINE(COPYRIGHT_STRING,"_COPYRIGHT_STRING",[The copyright string])
AM_CONDITIONAL(CROSS_COMPILING, test "$cross_compiling" = "yes")
AM_CONDITIONAL(MINGW32_BUILD, test "$host_os" = "mingw32")

# This is so "make dist" when cross compiling has a "-win32" at the
# end of the name.
if test "$host_os" = "mingw32" ; then
   VERSION="$VERSION-win32"
fi

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

# Gnulib.
gl_INIT

AC_ARG_ENABLE(optimization,
   AS_HELP_STRING([--disable-optimization],[disable compiler optimization]),
   [if test $enableval = no ; then
      CFLAGS=`echo $CFLAGS | sed 's/-O[[0-9]]//'`
   fi])

AM_CONDITIONAL(USING_GCC, test "$GCC" = yes)

AC_DEFINE_UNQUOTED(HOST_OS,"$host_os",[Build host OS])

AC_CONFIG_FILES([gl/Makefile Makefile checks/Makefile paperkey.spec])
AC_OUTPUT
