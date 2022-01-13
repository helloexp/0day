#!/bin/sh
#
# Test group and host filters
#

./cvtsudoers -c "" -f sudoers -m group=wheel,host=blackhole $TESTDIR/sudoers

exit 0
