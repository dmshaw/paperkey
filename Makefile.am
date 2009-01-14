# $Id$

ACLOCAL_AMFLAGS=-I gl/m4
EXTRA_DIST=paperkey.spec $(man_MANS)
SUBDIRS=gl . checks

AM_CPPFLAGS=-I$(top_srcdir)/gl
LDADD=gl/libgl.a

if USING_GCC
AM_CPPFLAGS+=-Wall -W -pedantic
endif

man_MANS=paperkey.1

bin_PROGRAMS=paperkey

paperkey_SOURCES=paperkey.c packets.c packets.h parse.c parse.h extract.c extract.h restore.c restore.h output.c output.h

if MINGW32_BUILD
EXTRA_DIST+=README.WIN32 paperkey.txt paperkey.exe
paperkey.txt: paperkey.1
	nroff -man paperkey.1 > paperkey.txt
endif
