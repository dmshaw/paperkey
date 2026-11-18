#!/bin/sh

# Feed paperkey secret key packets that are cut off in the middle of
# the public key material (the length byte of an MPI or curve OID is
# missing).  It should fail cleanly without reading past the end of
# the packet.  Run under AddressSanitizer to see the difference.

# Version 4 RSA key (algorithm 1) with only one byte of the first MPI
# length present.
printf '\225\000\007\004\000\000\000\000\001\004' > truncated-rsa.bin

# Version 4 ECDH key (algorithm 18) with no curve OID length byte.
printf '\225\000\006\004\000\000\000\000\022' > truncated-ecdh.bin

for f in truncated-rsa.bin truncated-ecdh.bin ; do
    ../paperkey --secret-key $f >/dev/null 2>&1
    if test $? -ne 1 ; then
	exit 1
    fi
done

exit 0
