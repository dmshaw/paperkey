#!/bin/sh

../paperkey --secret-key ${srcdir}/papertest.sec --output-type raw --output papertest.bin || exit 1
../paperkey --secrets papertest.bin --pubring ${srcdir}/papertest.pub --output regen.pgp || exit 1
cmp ./regen.pgp ${srcdir}/papertest.sec
