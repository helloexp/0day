#!/bin/sh
#
# Test round-tripping of sudoers -> LDIF -> sudoers
#

exec 2>&1
./cvtsudoers -c "" -b "ou=SUDOers,dc=sudo,dc=ws" $TESTDIR/test23.out.ok | \
    ./cvtsudoers -c "" -i LDIF -f sudoers | grep -v '^#'
