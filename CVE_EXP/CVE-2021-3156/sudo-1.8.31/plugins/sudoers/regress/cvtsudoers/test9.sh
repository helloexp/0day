#!/bin/sh
#
# Test host defaults filtering
#

./cvtsudoers -c "" -f sudoers -s aliases,privileges -d host $TESTDIR/sudoers

exit 0
