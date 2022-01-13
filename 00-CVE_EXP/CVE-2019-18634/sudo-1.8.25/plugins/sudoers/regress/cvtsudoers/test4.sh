#!/bin/sh
#
# Test group and host filters, expanding aliases
#

exec 2>&1
./cvtsudoers -c "" -f sudoers -e -m group=wheel,host=blackhole $TESTDIR/sudoers

exit 0
