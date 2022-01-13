#!/bin/sh
#
# Test cvtsudoers.conf
#

exec 2>&1
./cvtsudoers -c $TESTDIR/test20.conf <<EOF
Defaults:SOMEUSERS authenticate, timestamp_timeout=0
User_Alias SOMEUSERS = user1, user2, user3

SOMEUSERS ALL = /usr/bin/id
EOF
