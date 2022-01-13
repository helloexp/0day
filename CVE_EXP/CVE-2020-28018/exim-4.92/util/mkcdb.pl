#!/usr/bin/perl -wT
#
# Create cdb file from flat alias file. DPC: 15/10/98.
# Args:      source  (may be relative or absolute)
#            target  (may be relative or absolute. Default = source)
# Generates: target.cdb
#            target.tmp
#
# Little Perl script to convert flat file into CDB file. Two advantages over
# cdbmake-12 awk script that is distributed with CDB:
#  1) Handles 'dpc22:dpc22@hermes' as well as 'dpc22 dpc22@hermes'
#  2) Perl works with arbitrary length strings: awk chokes at 1,024 chars
#
# Cambridge: hermes/src/admin/mkcdb,v 1.9 2005/02/15 18:14:12 fanf2 Exp

use strict;

BEGIN { pop @INC if $INC[-1] eq '.' };
$ENV{'PATH'} = "";
umask(022);

my $CDB = '/opt/cdb/bin/cdbmake';

my $prog = $0;
$prog =~ s|(.*/)?([^/]+)|$2|;

my $source;
my $target;
if (@ARGV == 1) {
    $source = shift(@ARGV);
    $target = $source;
} elsif (@ARGV == 2) {
    $source = shift(@ARGV);
    $target = shift(@ARGV);
} else {
    die("$prog: usage: <source> [<target>]\n");
}
# trust the invoker ?!
$source =~ /(.*)/;
$source = $1;
$target =~ /(.*)/;
$target = $1;

open(SOURCE, "< ${source}")
    or die("$prog: open < $source: $!\n");

open(PIPE, "| $CDB $target.cdb $target.tmp")
    or die("$prog: open | $CDB $target: $!\n");

sub add_item ($$) {
    my $key = shift;
    my $val = shift;
    printf PIPE ("+%d,%d:%s->%s\n", length($key), length($val), $key, $val);
}

sub add_line ($) {
    my $line = shift;
    if ($line =~ /^([^\s:]+)\s*:\s*(.*)$/s) {   # key : values
        add_item($1,$2);
        return;
    }
    if ($line =~ /^(\S+)\s+(.*)$/s) {       # key: values
        add_item($1,$2);
        return;
    }
    if ($line =~ /^(\S+)$/s) {              # key (empty value)
        add_item($1,'');
        return;
    }
    warn "$prog: unrecognized item: $line";
}

my $data;
while(<SOURCE>) {
    next if /^#/ or /^\s*$/;
    m/^(\s*)(\S.*)\s+$/s;
    if (length($1) == 0) {
            add_line($data) if defined $data;
            $data = $2;
    } else {
            $data .= " $2";
    }
}
add_line($data) if defined $data;
print PIPE "\n";

close(SOURCE)
    or die("$prog: close < $source: $!\n");
close(PIPE)
    or die($! ? "$prog: close | $CDB $target: $!\n"
           : "$prog: close | $CDB $target: exited $?\n");

exit 0;
