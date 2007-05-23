#!/bin/sh

# $Id$

../paperkey --secret-key ${srcdir}/papertest.sec --output papertest.txt || exit 1
../paperkey --secrets papertest.txt --pubring ${srcdir}/papertest.pub --output regen.pgp || exit 1
cmp ./regen.pgp ${srcdir}/verify.pgp
