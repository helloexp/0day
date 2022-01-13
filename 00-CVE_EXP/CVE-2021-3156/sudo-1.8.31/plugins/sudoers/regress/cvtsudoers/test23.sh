#!/bin/sh
#
# Test round-tripping of sudoers -> LDIF -> sudoers
#

./cvtsudoers -c "" -b "ou=SUDOers,dc=sudo,dc=ws" $TESTDIR/test23.out.ok | \
    ./cvtsudoers -c "" -i LDIF -f sudoers | grep -v '^#'
