#!/bin/sh
#
# Test group and host filters
#

exec 2>&1
./cvtsudoers -c "" -f sudoers -m group=wheel,host=blackhole $TESTDIR/sudoers

exit 0
