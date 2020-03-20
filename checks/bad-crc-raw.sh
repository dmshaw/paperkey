#!/bin/sh

# Feed paperkey a binary/raw file with corrupt CRC.  It should fail.

../paperkey --secrets ${srcdir}/corrupt-raw.bin --pubring ${srcdir}/papertest.pub >/dev/null 2>&1
if test $? -ne 1 ; then
    exit 1
fi

exit 0
