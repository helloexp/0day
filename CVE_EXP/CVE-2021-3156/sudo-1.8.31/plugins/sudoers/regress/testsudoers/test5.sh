#!/bin/sh
#
# Test sudoers file mode check
#

# Avoid warnings about memory leaks when there is a syntax error
ASAN_OPTIONS=detect_leaks=0; export ASAN_OPTIONS

# Create test file
TESTFILE=`pwd`/regress/testsudoers/test5.inc
cat >$TESTFILE <<EOF
root ALL = ALL
EOF

MYUID=`\ls -ln $TESTFILE | awk '{print $3}'`
MYGID=`\ls -ln $TESTFILE | awk '{print $4}'`
exec 2>&1

# Test world writable
chmod 666 $TESTFILE
./testsudoers -U $MYUID -G $MYGID root id <<EOF
#include $TESTFILE
EOF

# Test group writable
chmod 664 $TESTFILE
./testsudoers -U $MYUID -G -2 root id <<EOF
#include $TESTFILE
EOF

rm -f $TESTFILE
exit 0
