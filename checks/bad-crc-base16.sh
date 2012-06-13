#!/bin/sh

../paperkey --secrets ${srcdir}/corrupt-base16.txt --pubring ${srcdir}/papertest.pub --output regen.pgp 2>/dev/null && exit 1
exit 0
