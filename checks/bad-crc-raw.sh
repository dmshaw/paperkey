#!/bin/sh

# $Id$

../paperkey --secret-key ${srcdir}/papertest.sec --output-type raw | head -c -1 > papertest.raw || exit 1
../paperkey --secrets papertest.raw --pubring ${srcdir}/papertest.pub --output regen.pgp 2>/dev/null && exit 1
exit 0
