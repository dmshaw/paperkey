#!/bin/sh

# $Id$

../paperkey --secret-key papertest.sec --output papertest.txt || exit 1
../paperkey --secrets papertest.txt --pubring papertest.pub --output regen.pgp || exit 1
cmp regen.pgp verify.pgp
