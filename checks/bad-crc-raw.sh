#!/bin/sh

# $Id$

../paperkey --secret-key ${srcdir}/papertest.sec --output-type raw | head -c -1 > papertest.bin || exit 1
../paperkey --secrets papertest.bin --pubring ${srcdir}/papertest.pub --output regen.pgp 2>/dev/null && exit 1
exit 0
