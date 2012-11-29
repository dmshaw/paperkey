#!/bin/sh

for type in rsa dsaelg ecc ; do
    ../paperkey --secret-key ${srcdir}/papertest-${type}.sec --output-type raw --output papertest-${type}.bin || exit 1
    ../paperkey --secrets papertest-${type}.bin --pubring ${srcdir}/papertest-${type}.pub --output regen.pgp || exit 1
    cmp ./regen.pgp ${srcdir}/papertest-${type}.sec || exit 1
    /bin/echo -n "$type "
done
