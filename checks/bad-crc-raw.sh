#!/bin/sh

# $Id$

../paperkey --secrets ${srcdir}/corrupt-raw.bin --pubring ${srcdir}/papertest.pub --output regen.pgp 2>/dev/null && exit 1
exit 0
