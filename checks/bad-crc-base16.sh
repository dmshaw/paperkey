#!/bin/sh

# $Id$

../paperkey --secret-key ${srcdir}/papertest.sec | head -n -1 > papertest.txt || exit 1
../paperkey --secrets papertest.txt --pubring ${srcdir}/papertest.pub --output regen.pgp 2>/dev/null && exit 1
exit 0
