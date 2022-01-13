#!/bin/sh
#
# Verify sudoers matching by gid.
#

exec 2>&1
./testsudoers root id <<EOF
%#0 ALL = ALL
EOF

exit 0
