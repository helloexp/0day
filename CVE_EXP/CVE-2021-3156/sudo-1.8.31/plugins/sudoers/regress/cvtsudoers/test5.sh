#!/bin/sh
#
# Test defaults type filtering
#

./cvtsudoers -c "" -f sudoers -s aliases,privileges -d all $TESTDIR/sudoers

exit 0
