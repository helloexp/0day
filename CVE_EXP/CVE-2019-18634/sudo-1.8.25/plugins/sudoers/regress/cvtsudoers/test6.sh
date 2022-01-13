#!/bin/sh
#
# Test global defaults filtering
#

exec 2>&1
./cvtsudoers -c "" -f sudoers -s aliases,privileges -d global $TESTDIR/sudoers

exit 0
