#!/bin/sh
#
# Test user defaults filtering
#

./cvtsudoers -c "" -f sudoers -s aliases,privileges -d user $TESTDIR/sudoers

exit 0
