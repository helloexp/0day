#!/bin/sh
#
# Test host defaults filtering
#

exec 2>&1
./cvtsudoers -c "" -f sudoers -s aliases,privileges -d host $TESTDIR/sudoers

exit 0
