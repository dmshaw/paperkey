#!/bin/sh

../paperkey --secret-key ${srcdir}/papertest-dsa100.sec --output papertest-dsa100.txt 2>/dev/null
if test $? -ne 1 ; then
    exit 1
fi

exit 0
