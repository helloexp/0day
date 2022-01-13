#!/bin/sh
#
# Test user defaults filtering
#

exec 2>&1
./cvtsudoers -c "" -f sudoers -s aliases,privileges -d user $TESTDIR/sudoers

exit 0
