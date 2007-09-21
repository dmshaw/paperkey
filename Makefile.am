# $Id$

ACLOCAL_AMFLAGS=-I gl/m4

SUBDIRS=gl . checks

AM_CPPFLAGS=-I$(top_srcdir)/gl
LDADD=gl/libgl.a

if USING_GCC
AM_CPPFLAGS+=-Wall -W -pedantic
endif

bin_PROGRAMS=paperkey

paperkey_SOURCES=paperkey.c packets.c packets.h parse.c parse.h extract.c extract.h restore.c restore.h output.c output.h
