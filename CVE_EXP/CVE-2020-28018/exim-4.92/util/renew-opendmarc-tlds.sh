#!/bin/sh -eu
#
# Short version of this script:
#   curl -f -o /var/cache/exim/opendmarc.tlds https://publicsuffix.org/list/public_suffix_list.dat
# but run as Exim runtime user, writing to a place it can write to, and with
# sanity checks and atomic replacement.
#
# For now, we deliberately leave the invalid file around for analysis
# with .<pid> suffix.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~8< cut here >8~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
# Create a cron-job as the Exim run-time user to invoke this daily, with a
# single parameter, 'cron'.  Eg:
#
#    3 4 * * *	  /usr/local/sbin/renew-opendmarc-tlds.sh cron
#
# That will, at 3 minutes past the 4th hour (in whatever timezone cron is
# running it) invoke this script with 'cron'; we will then sleep between 10 and
# 50 seconds, before continuing.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~8< cut here >8~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
# This should be "pretty portable"; the only things it depends upon are:
#  * a POSIX shell which additionally implements 'local' (dash works)
#  * the 'curl' command; change the fetch_candidate() function to replace that
#  * the 'stat' command, to get the size of a file; else Perl
#    + change size_of() if need be; it's defined per-OS
#  * the 'hexdump' command and /dev/urandom existing
#    + used when invoked with 'cron', to avoid retrieving on a minute boundary
#      and contending with many other automated systems.
#    + with bash/zsh, can replace with: $(( 10 + ( RANDOM % 40 ) ))
#    + on Debian/Ubuntu systems, hexdump is in the 'bsdmainutils' package.

# Consider putting an email address inside the parentheses, something like
# noc@example.org or other reachable address, so that if something goes wrong
# and the server operators need to step in, they can see from logs who to
# contact instead of just blocking your IP:
readonly CurlUserAgent='renew-opendmarc-tlds/0.1 (distributed with Exim)'

# change this to your Exim run-time user (exim -n -bP exim_user) :
readonly RuntimeUser='_exim'

# Do not make this a directory which untrusted users can write to:
readonly StateDir='/var/cache/exim'

readonly URL='https://publicsuffix.org/list/public_suffix_list.dat'

readonly TargetShortFile='opendmarc.tlds'

# When replacing, new file must be at least this percentage the size of
# the old one or it's an error:
readonly MinNewSizeRation=90

# Each of these regexps must be matched by the file, or it's an error:
readonly MustExistRegexps='
  ^ac\.uk$
  ^org$
  ^tech$
  '

# =======================8< end of configuration >8=======================

set -eu

readonly FullTargetPath="${StateDir}/${TargetShortFile}"
readonly WorkingFile="${FullTargetPath}.$$"

progname="$(basename "$0")"
note() { printf >&2 '%s: %s\n' "$progname" "$*"; }
die() { note "$@"; exit 1; }

# guard against stomping on file-permissions
[ ".$(id -un)" = ".${RuntimeUser:?}" ] || \
  die "must be invoked as ${RuntimeUser}"

fetch_candidate() {
	curl --user-agent "$CurlUserAgent" -fSs -o "${WorkingFile}" "${URL}"
}

case $(uname -s) in
*BSD|Darwin)
	size_of() { stat -f %z "$1"; }
	;;
Linux)
	size_of() { stat -c %s "$1"; }
	;;
*)
	# why do we live in a world where Perl is the safe portable solution
	# to getting the size of a file?
	size_of() { perl -le 'print((stat($ARGV[0]))[7])' -- "$1"; }
	;;
esac

sanity_check_candidate() {
	local new_size prev_size re
	new_size="$(size_of "$WorkingFile")"

	for re in $MustExistRegexps; do
		grep -qs "$re" -- "$WorkingFile" || \
		  die "regexp $re not found in $WorkingFile"
	done

	if ! prev_size="$(size_of "$FullTargetPath")"; then
		note "missing previous file, can't size-compare: $FullTargetPath"
		# We're sane by definition, probably initial fetch, and the
		# stat failure and this note will be printed.  That's fine; if
		# a cron invocation is missing the file then something has gone
		# badly wrong.
		return 0
	fi
	local ratio
	ratio=$(expr $new_size \* 100 / $prev_size)
	if [ $ratio -lt $MinNewSizeRation ]; then
		die "New $TargetShortFile candidate only ${ratio}% size of old; $new_size vs $prev_size"
	fi
}

if [ "${1:-.}" = "cron" ]; then
	shift
	# Don't pull on-the-minute, wait for off-cycle-peak
	sleep $(( ($(dd if=/dev/urandom bs=1 count=1 2>/dev/null | hexdump -e '1/1 "%u"') % 40) + 10))
fi

umask 022
fetch_candidate
sanity_check_candidate
mv -- "$WorkingFile" "$FullTargetPath"
