#!/bin/sh

../paperkey --secret-key ${srcdir}/papertest-dsa100.sec >/dev/null 2>&1
if test $? -ne 1 ; then
    exit 1
fi

exit 0
