#!/bin/sh

../paperkey --secret-key ./papertest.sec --output papertest.txt
../paperkey --secrets papertest.txt --pubring ./papertest.pub --output regen.pgp
cmp regen.pgp verify.pgp
