#!/bin/sh
#
# Test round-tripping of LDIF -> sudoers -> LDIF
#

exec 2>&1
./cvtsudoers -c "" -i LDIF -f sudoers $TESTDIR/test24.out.ok | \
    ./cvtsudoers -c "" -b "ou=SUDOers,dc=sudo,dc=ws"
