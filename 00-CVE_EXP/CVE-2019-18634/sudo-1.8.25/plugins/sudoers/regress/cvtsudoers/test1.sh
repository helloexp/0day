#!/bin/sh
#
# Test user and host filters
#

exec 2>&1
./cvtsudoers -c "" -f sudoers -m user=millert,host=hercules $TESTDIR/sudoers

exit 0
