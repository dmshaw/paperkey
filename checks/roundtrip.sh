#!/bin/sh

# Roundtrip base16 test - go from a secret key to base16 then back to
# a secret key.

for type in rsa dsaelg ecc eddsa ; do
    ../paperkey --secret-key ${srcdir}/papertest-${type}.sec --output papertest-${type}.txt || exit 1
    ../paperkey --secrets papertest-${type}.txt --pubring ${srcdir}/papertest-${type}.pub --output regen-${type}.pgp || exit 1
    cmp ./regen-${type}.pgp ${srcdir}/papertest-${type}.sec || exit 1
    /bin/echo -n "$type "
done
