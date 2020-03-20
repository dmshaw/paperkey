#!/bin/sh

# Feed paperkey a text file with corrupt CRC.  It should fail.

../paperkey --secrets ${srcdir}/corrupt-base16.txt --pubring ${srcdir}/papertest.pub >/dev/null 2>&1
if test $? -ne 1 ; then
    exit 1
fi

exit 0
