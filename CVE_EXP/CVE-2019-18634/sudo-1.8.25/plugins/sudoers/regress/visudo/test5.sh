#!/bin/sh
#
# Test comment on the last line with no newline
#

printf "# one comment\n#two comments" | ./visudo -csf -

exit 0
