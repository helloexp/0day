#!/bin/sh
#
# Test round-tripping of LDIF -> sudoers -> LDIF
#

./cvtsudoers -c "" -i LDIF -f sudoers $TESTDIR/test24.out.ok | \
    ./cvtsudoers -c "" -b "ou=SUDOers,dc=sudo,dc=ws"
