#! /bin/sh

# Build the config.h file, using the buildconfig program, first ensuring that
# it exists.

# 22-May-1996: remove the use of the "-a" flag for /bin/sh because it is not
# implemented in the FreeBSD shell. Sigh.

# 12-Mar-1997: add s/#.*$// to the sed script to allow for comments on the
# ends of settings - someone got caught.

# 18-Apr-1997: put the tab character into a variable to stop it getting
# lost by accident (which has happened a couple of times).

# 19-Jan-1998: indented settings in the makefile weren't being handled
# correctly; added [$st]* before \\([A-Z] in the pattern, to ignore leading
# space. Oddly, the pattern previously read ^\([A-Z which didn't seem to
# cause a problem (but did when the new bit was put in).

# 04-May-2005: if $1 is set, copy it into $MAKE, and then use $MAKE, if set,
# instead of "make" so that if gmake is used, it is used consistently.

if [ "$1" != "" ] ; then MAKE=$1 ; fi
if [ "$MAKE" = "" ] ; then MAKE=make ; fi

$MAKE buildconfig || exit 1

# BEWARE: tab characters needed in the following sed command. They have had
# a nasty tendency to get lost in the past, causing a problem if a tab has
# actually been present in makefile. Use a variable to hold a space and a
# tab to keep the tab in one place. This makes the sed option horrendous to
# read, but the whole script is safer.

st='	 '

(sed -n \
  "/\\\$/d;s/#.*\$//;s/^[$st]*\\([A-Z][^:!+$st]*\\)[$st]*=[$st]*\\([^$st]*\\)[$st]*\$/\\1=\\2 export \\1/p" \
  < Makefile ; echo "./buildconfig") | /bin/sh

# If buildconfig ends with an error code, it will have output an error
# message. Ensure that a broken config.h gets deleted.

if [ $? != 0 ] ; then
  rm -f config.h
  exit 1
fi

# Double-check that config.h is complete.

if [ "`tail -1 config.h`" != "/* End of config.h */" ] ; then
  echo "*** config.h appears to be incomplete"
  echo "*** unexpected failure in buildconfig program"
  exit 1
fi

echo ">>> config.h built"
echo ""

# vim: set ft=sh :
# End of Configure-config.h
