#!/usr/bin/perl
# Copyright (C) 2012 Wizards Internet Ltd
# License GPLv2: GNU GPL version 2 <http://www.gnu.org/licenses/old-licenses/gpl-2.0.html>
use strict;
BEGIN { pop @INC if $INC[-1] eq '.' };
use Getopt::Std;
$Getopt::Std::STANDARD_HELP_VERSION=1;
use IO::Handle;
use Date::Parse;
my ($o,$i,$s,$f,$t,$u,$VERSION);
$VERSION='1.0';
$o={'m'=>10};
getopts("c:i:u:a:o:m:fv",$o);
usage('No issuer specified') if ! $o->{'i'} && ! -f $o->{'i'};
usage('No certificate specified') if ! $o->{'c'} && ! -f $o->{'c'};
usage('No CA chain specified') if ! $o->{'a'} && ! -f $o->{'a'};
usage('No OCSP file specified') if ! $o->{'o'};
usage('No URL specified') if ! $o->{'u'};
$o->{'t'}=$o->{'o'}.'.tmp';

# check if we need to
if (     $o->{'f'}
    || ! -f $o->{'o'}
    || ( -M $o->{'o'} > 0 )
   )
{
    $i = new IO::Handle;
    open( $i, "openssl ocsp -issuer $o->{'i'} -cert $o->{'c'} -url $o->{'u'} -CAfile $o->{'a'} -respout $o->{'t'} 2>/dev/null |" ) || die 'Unable to execute ocsp command';
    $s = <$i> || die 'Unable to read status';
    $f = <$i> || die 'Unable to read update time';
    $t = <$i> || die 'Unable to read next update time';
    close $i;
    # Status ok ?
    chomp($s);
    chomp($f);
    chomp($t);
    $s =~ s/[^:]*: //;
    $f =~ s/[^:]*: //;
    $t =~ s/[^:]*: //;
    $t = str2time($t);
    die "OCSP status is $s" if $s ne 'good';
    warn "Next Update $t" if $o->{'v'};
    # response is good, adjust mod time and move into place.
    $u = $t - $o->{'m'} * (($t - time)/100);
    utime $u,$u,$o->{'t'};
    rename $o->{'t'},$o->{'o'};
}
exit;

sub
usage
{
    my $m = shift;
    print STDERR "$m\n" if $m;
    HELP_MESSAGE(\*STDERR);
    die;
}
sub
HELP_MESSAGE
{
    my $h = shift;
    print $h <<EOF
Usage: $0 -i issuer -c certificate -u ocsp_url -a ca_certs -o response [-v] [-f]

For a certificate    "www.example.com.pem"
  signed by          "signing.example.net.pem"
  signed by root CA  "ca.example.net.pem"
  with OCSP server   http://ocsp.example.net/

Ensure there is a file with the signing chain

  cat ca.example.net.pem signing.example.net.pem >chain.pem

The update procedure would be

    ocsp_fetch -i signing.example.net.pem \
        -c www.example.com.pem \
    -u http://ocsp.example.net/ \
    -a chain.pem \
    -o www.example.com.ocsp.der
EOF
}
# vi: aw ai sw=4
# End of File
