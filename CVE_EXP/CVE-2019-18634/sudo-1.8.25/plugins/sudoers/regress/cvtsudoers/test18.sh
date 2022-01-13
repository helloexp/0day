#!/bin/sh
#
# Test filters and pruning
#

exec 2>&1
./cvtsudoers -c "" -f sudoers -p -m group=group1,host=somehost <<EOF
user1, user2, user3, %group1 ALL = ALL
EOF
