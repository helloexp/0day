#!/bin/sh
#
# Test alias expasion when converting to JSON.
# See https://bugzilla.sudo.ws/show_bug.cgi?id=853
#

./cvtsudoers -c "" -e -f json <<EOF
Cmnd_Alias	CMDA=/path/to/cmda
Cmnd_Alias	CMDB=/path/to/cmdb
Cmnd_Alias	CMDC=/path/to/cmdc
User_Alias	USERS=user1,user2,user3
USERS		ALL=CMDA,!CMDB,CMDC
EOF
