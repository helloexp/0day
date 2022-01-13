#!/usr/bin/env perl
#
# Copyright (c) 2017 Todd C. Miller <Todd.Miller@sudo.ws>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# Simple script to massage "git log" output into a GNU style ChangeLog.
# The goal is to emulate "hg log --style=changelog" via perl format.

use warnings;

my $format="%ad  %aN  <%aE>%n%h%n%B%n";
my @cmd = ("git", "log", "--log-size", "--name-only", "--date=short", "--format=$format", @ARGV);
open(LOG, '-|', @cmd) || die "$0: unable to run git log: $!";

my $hash;
my $body;
my @files;
my $key_date = "";
my $log_size = 0;
my @lines;

while (<LOG>) {
    chomp;
    if (/^log size (\d+)$/) {
	$log_size = $1;

	# Print previous entry if there is one
	print_entry($hash, $body, @files) if defined($hash);

	# Init new entry
	undef $hash;
	undef $body;
	undef @files;
	undef @lines;

	# Read entry and split on newlines
	read(LOG, my $buf, $log_size) ||
	    die "$0: unable to read $log_size bytes: $!\n";
	@lines = split(/\r?\n/, $buf);

	# Check for continued entry (duplicate Date + Author)
	$_ = shift(@lines);
	if ($_ ne $key_date) {
	    # New entry
	    print "$_\n\n";
	    $key_date = $_;
	}

	# Hash comes first
	$hash = shift(@lines);

	# Commit message body (multi-line)
	foreach (@lines) {
	    last if $_ eq "--HG--";
	    if (defined($body)) {
		$_ = "\r" if $_ eq "";
		$body .= " $_";
	    } else {
		$body = $_;
	    }
	}
    } else {
	# Not a log entry, must be the file list
	push(@files, $_) unless $_ eq "";
    }
}

# Print the last entry
print_entry($hash, $body, @files) if defined($hash);

exit(0);

sub print_entry
{
    my $hash = '[' . shift . ']';
    my $body = shift;
    my $files = "* " . join(", ", @_) . ":";

    local $= = 9999;	# to silence warning (hack)

    format =
	^<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< ~~
	$files
	^<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< ~~
	$body
	@*
	$hash

.
    write;
}
