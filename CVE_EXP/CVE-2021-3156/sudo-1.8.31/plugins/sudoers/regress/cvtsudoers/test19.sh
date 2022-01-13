#!/bin/sh
#
# Test filters and pruning; alias contents don't get pruned
#

./cvtsudoers -c "" -f sudoers -p -m user=FULLTIMERS,host=SERVERS $TESTDIR/sudoers
