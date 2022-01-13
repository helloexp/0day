#!/bin/sh
#
# Test user and host filters
#

./cvtsudoers -c "" -f sudoers -m user=millert,host=hercules $TESTDIR/sudoers

exit 0
