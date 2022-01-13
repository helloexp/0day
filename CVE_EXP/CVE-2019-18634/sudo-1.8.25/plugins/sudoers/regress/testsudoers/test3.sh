#!/bin/sh
#
# Test #include facility
#

MYUID=`\ls -lnd $TESTDIR/test3.d | awk '{print $3}'`
MYGID=`\ls -lnd $TESTDIR/test3.d | awk '{print $4}'`
exec 2>&1
./testsudoers -U $MYUID -G $MYGID root id <<EOF
#includedir $TESTDIR/test3.d
EOF

exit 0
