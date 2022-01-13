#!/bin/sh
#
# Test command defaults filtering
#

exec 2>&1
./cvtsudoers -c "" -f sudoers -s aliases,privileges -d command $TESTDIR/sudoers

exit 0
