#!/bin/sh
#
# Test runas defaults filtering
#

exec 2>&1
./cvtsudoers -c "" -f sudoers -s aliases,privileges -d runas $TESTDIR/sudoers

exit 0
