#! /bin/sh

# This script can be interposed between a calling program and another
# program, in order to log the arguments which are being used. This can
# be helpful in finding out what is going on if some program is calling
# Exim with arguments it doesn't understand.

# Set this to the the path of the program that must ultimately be called.

CALL=exim

# Set this to the name of the file where the data is to be logged. The
# script writes on the end of it. It must be accessible to the user who
# runs the script.

LOGFILE=/home/ph10/tmp/zz

# The arguments are copied to the log file

echo $@ >>$LOGFILE

# The real program is now called

exec $CALL $@

# End
