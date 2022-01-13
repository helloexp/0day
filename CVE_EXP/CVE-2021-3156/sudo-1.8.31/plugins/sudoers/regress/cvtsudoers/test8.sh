#!/bin/sh
#
# Test runas defaults filtering
#

./cvtsudoers -c "" -f sudoers -s aliases,privileges -d runas $TESTDIR/sudoers

exit 0
