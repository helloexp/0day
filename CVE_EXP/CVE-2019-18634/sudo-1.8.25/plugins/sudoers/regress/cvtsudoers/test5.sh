#!/bin/sh
#
# Test defaults type filtering
#

exec 2>&1
./cvtsudoers -c "" -f sudoers -s aliases,privileges -d all $TESTDIR/sudoers

exit 0
