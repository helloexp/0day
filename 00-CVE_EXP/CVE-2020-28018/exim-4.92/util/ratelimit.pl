#!/usr/bin/perl -wT

use strict;

BEGIN { pop @INC if $INC[-1] eq '.' };

sub usage () {
  print <<END;
usage: ratelimit.pl [options] <period> <regex> <logfile>

The aim of this script is to compute clients' peak sending rates
from an Exim log file, using the same formula as Exim's ratelimit
ACL condition. This is so that you can get an idea of a reasonable
limit setting before you deploy the restrictions.

options:

-d          Show debugging information to stderr
-p          Show progress of parse the log to stderr

<period>    The smoothing period in seconds, as defined by the
            documentation for the ratelimit ACL condition.

            This script isn't perfectly accurate, because the time
            stamps in Exim's log files are only accurate to a second
            whereas internally Exim computes sender rates to the
            accuracy of your computer's clock (typically 10ms).

<regex>     The second argument is a regular expression.

            Each line is matched against the regular expression.
            Lines that do not match are ignored. The regex may
            contain 0, 1, or 2 () capturing sub-expressions.

            If there are no () sub-expressions, then every line that
            matches is used to compute a single rate. Its maximum
            value is reported when the script finishes.

            If there is one () sub-expression, then the text matched
            by the sub-expression is used to identify a rate lookup
            key, similar to the lookup key used by the ratelimit
            ACL condition. For example, you might write a regex
            to match the client IP address, or the authenticated
            username. Separate rates are computed for each different
            client and the maximum rate for each client is reported
            when the script finishes.

            If there are two () sub-expressions, then the text matched
            by the first sub-expression is used to identify a rate
            lookup key as above, and the second is used to match the
            message size recorded in the log line, e.g. "S=(\\d+)".
            In this case the byte rate is computed instead of the
            message rate, similar to the per_byte option of the
            ratelimit ACL condition.

<logfile>   The log files to be processed can be specified on the
            command line after the other arguments; if no filenames
            are specified the script will read from stdin.

examples:

./ratelimit.pl 1 ' <= .*? \[(.*?)\]' <logfile>

            Compute burst sending rate like ACL condition
            ratelimit = 0 / 1s / strict / \$sender_host_address

./ratelimit.pl 3600 '<= (.*?) ' <logfile>

            Compute sending rate like ACL condition
            ratelimit = 0 / 1h / strict / \$sender_address

END
  exit 1;
}

sub iso2unix (@) {
  my ($y,$m,$d,$H,$M,$S,$zs,$zh,$zm) = @_;
  use integer;
  $y -= $m < 3;
  $m += $m < 3 ? 10 : -2;
  my $z = defined $zs ? "${zs}1" * ($zh * 60 + $zm) : 0;
  my $t = $y/400 - $y/100 + $y/4 + $y*365
        + $m*367/12 + $d - 719499;
  return $t * 86400
       + $H * 3600
       + $M * 60
       + $S
       - $z;
}

my $debug = 0;
my $progress = 0;
while (@ARGV && $ARGV[0] =~ /^-\w+$/) {
  $debug = 1    if $ARGV[0] =~ s/(-\w*)d(\w*)/$1$2/;
  $progress = 1 if $ARGV[0] =~ s/(-\w*)p(\w*)/$1$2/;
  shift if $ARGV[0] eq "-";
}

usage if @ARGV < 2;

my $progtime = "";

my $period = shift;

my $re_txt = shift;
my $re = qr{$re_txt}o;

my %time;
my %rate;
my %max;

sub debug ($) {
  my $key = shift;
  printf STDERR "%s\t%12d %8s %5.2f %5.2f\n",
    $_, $time{$key}, $key, $max{$key}, $rate{$key};
}

while (<>) {
  next unless $_ =~ $re;
  my $key = $1 || "";
  my $size = $2 || 1.0;
  my $time = iso2unix
    ($_ =~ m{^(\d{4})-(\d\d)-(\d\d)[ ]
              (\d\d):(\d\d):(\d\d)[ ]
              (?:([+-])(\d\d)(\d\d)[ ])?
            }x);
  if ($progress) {
    my $prog_now = substr $_, 0, 14;
    if ($progtime ne $prog_now) {
      $progtime = $prog_now;
      print STDERR "$progtime\n";
    }
  }
  if (not defined $time{$key}) {
    $time{$key} = $time;
    $rate{$key} = 0.0;
    $max{$key} = 0.0;
    debug $key if $debug;
    next;
  }
  # see acl_ratelimit() for details of the following
  my $interval = $time - $time{$key};
  $interval = 1e-9 if $interval <= 0.0;
  my $i_over_p = $interval / $period;
  my $a = exp(-$i_over_p);
  $time{$key} = $time;
  $rate{$key} = $size * (1.0 - $a) / $i_over_p + $a * $rate{$key};
  $max{$key} = $rate{$key} if $rate{$key} > $max{$key};
  debug $key if $debug;
}

print map {
  " " x (20 - length) .
  "$_ : $max{$_}\n"
} sort {
  $max{$a} <=> $max{$b}
} keys %max;

# eof
