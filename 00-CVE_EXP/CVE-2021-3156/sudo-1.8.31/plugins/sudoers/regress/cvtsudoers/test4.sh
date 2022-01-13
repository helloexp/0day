#!/bin/sh
#
# Test group and host filters, expanding aliases
#

./cvtsudoers -c "" -f sudoers -e -m group=wheel,host=blackhole $TESTDIR/sudoers

exit 0
