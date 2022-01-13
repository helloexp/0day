#!/bin/sh
#
# Test base64 encoding of non-safe strings
#

./cvtsudoers -c "" -b "ou=SUDOers©,dc=sudo,dc=ws" <<EOF
Defaults badpass_message="Bad password¡"

root ALL = ALL
EOF
