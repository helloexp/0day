#!/bin/sh
#
# Test user and host filters, expanding aliases
#

exec 2>&1
./cvtsudoers -c "" -f sudoers -e -m user=millert,host=hercules $TESTDIR/sudoers

exit 0
