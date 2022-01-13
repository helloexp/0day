#!/bin/sh
#
# Test that Aliases are removed when filtering by defaults type
#

exec 2>&1
./cvtsudoers -c "" -f sudoers -d runas $TESTDIR/sudoers.defs
