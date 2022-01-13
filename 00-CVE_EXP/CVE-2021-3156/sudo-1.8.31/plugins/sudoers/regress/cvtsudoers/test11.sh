#!/bin/sh
#
# Test that Aliases are removed when filtering by defaults type
#

./cvtsudoers -c "" -f sudoers -d command $TESTDIR/sudoers.defs
