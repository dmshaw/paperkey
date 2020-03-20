#!/bin/sh

# Feed paperkey an algo-100 primary.  It should fail.

../paperkey --secret-key ${srcdir}/papertest-100.sec >/dev/null 2>&1
if test $? -ne 1 ; then
    exit 1
fi

exit 0
