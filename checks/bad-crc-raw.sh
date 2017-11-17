#!/bin/sh

../paperkey --secrets ${srcdir}/corrupt-raw.bin --pubring ${srcdir}/papertest.pub --output regen.pgp 2>/dev/null
if test $? -ne 1 ; then
    exit 1
fi

exit 0
