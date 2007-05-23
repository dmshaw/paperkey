#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.60)
AC_REVISION([$Id$])
AC_INIT(paperkey, 0.1, dshaw@jabberwocky.com)
AC_CONFIG_SRCDIR([paperkey.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([std-options])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT32_T
AC_CHECK_TYPE([int_least16_t],,
   AC_DEFINE(int_least16_t,uint32_t,[An integer type with at least 16 bits]))

# Checks for library functions.

if test "$GCC" = yes; then
   CFLAGS="$CFLAGS -Wall -W -pedantic"
fi

AC_CONFIG_FILES([Makefile checks/Makefile])
AC_OUTPUT
