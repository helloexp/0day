#!/bin/sh
#
# Test global defaults filtering
#

./cvtsudoers -c "" -f sudoers -s aliases,privileges -d global $TESTDIR/sudoers

exit 0
