#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_REVISION([$Id$])
AC_INIT(paperkey, 0.1, dshaw@jabberwocky.com)
AC_CONFIG_SRCDIR([paperkey.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([std-options])
# AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC

if test "$GCC" = yes; then
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        CFLAGS="$CFLAGS -Wall -pedantic"
    else
        CFLAGS="$CFLAGS -Wall"
    fi
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
