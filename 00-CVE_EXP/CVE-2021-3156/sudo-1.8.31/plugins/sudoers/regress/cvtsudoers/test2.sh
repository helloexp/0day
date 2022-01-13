#!/bin/sh
#
# Test user and host filters, expanding aliases
#

./cvtsudoers -c "" -f sudoers -e -m user=millert,host=hercules $TESTDIR/sudoers

exit 0
