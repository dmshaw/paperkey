#!/bin/sh

for type in rsa dsaelg ecc eddsa ; do
    ../paperkey --secret-key ${srcdir}/papertest-${type}.sec --output-type raw --output papertest-${type}.bin || exit 1
    ../paperkey --secrets papertest-${type}.bin --pubring ${srcdir}/papertest-${type}.pub --output regen-raw-${type}.pgp || exit 1
    cmp ./regen-raw-${type}.pgp ${srcdir}/papertest-${type}.sec || exit 1
    /bin/echo -n "$type "
done
