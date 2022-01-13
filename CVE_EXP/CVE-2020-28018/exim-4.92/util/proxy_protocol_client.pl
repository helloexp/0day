#!/usr/bin/perl
#
# Copyright (C) 2014 Todd Lyons
# License GPLv2: GNU GPL version 2
# <http://www.gnu.org/licenses/old-licenses/gpl-2.0.html>
#
# This script emulates a proxy which uses Proxy Protocol to communicate
# to a backend server.  It should be run from an IP which is configured
# to be a Proxy Protocol connection (or not, if you are testing error
# scenarios) because Proxy Protocol specs require not to fall back to a
# non-proxied mode.
#
# The script is interactive, so when you run it, you are expected to
# perform whatever conversation is required for the protocol being
# tested.  It uses STDIN/STDOUT, so you can also pipe output to/from the
# script.  It was originally written to test Exim's Proxy Protocol
# code, and it could be tested like this:
#
# swaks --pipe 'perl proxy_protocol_client.pl --server-ip
#   host.internal.lan' --from user@example.com --to user@example.net
#
use strict;
use warnings;
BEGIN { pop @INC if $INC[-1] eq '.' };
use IO::Select;
use IO::Socket;
use Getopt::Long;
use Data::Dumper;

my %opts;
GetOptions( \%opts,
  'help',
  '6|ipv6',
  'dest-ip:s',
  'dest-port:i',
  'source-ip:s',
  'source-port:i',
  'server-ip:s',
  'server-port:i',
  'version:i'
);
&usage() if ($opts{help} || !$opts{'server-ip'});

my ($dest_ip,$source_ip,$dest_port,$source_port);
my %socket_map;
my $status_line = "Testing Proxy Protocol Version " .
                  ($opts{version} ? $opts{version} : '2') .
                  ":\n";

# All ip's and ports are in network byte order in version 2 mode, but are
# simple strings when in version 1 mode.  The binary_pack_*() functions
# return the required data for the Proxy Protocol version being used.

# Use provided source or fall back to www.mrball.net
$source_ip   = $opts{'source-ip'} ?  binary_pack_ip($opts{'source-ip'}) :
                 $opts{6} ?
                 binary_pack_ip("2001:470:d:367::50") :
                 binary_pack_ip("208.89.139.252");
$source_port = $opts{'source-port'} ?
                 binary_pack_port($opts{'source-port'}) :
                 binary_pack_port(43118);

$status_line .= "-> " if (!$opts{version} || $opts{version} == 2);

# Use provided dest or fall back to mail.exim.org
$dest_ip   = $opts{'dest-ip'} ?  binary_pack_ip($opts{'dest-ip'}) :
               $opts{6} ?
               binary_pack_ip("2001:630:212:8:204:23ff:fed6:b664") :
               binary_pack_ip("131.111.8.192");
$dest_port = $opts{'dest-port'} ?
               binary_pack_port($opts{'dest-port'}) :
               binary_pack_port(25);

# The IP and port of the Proxy Protocol backend real server being tested,
# don't binary pack it.
my $server_ip   = $opts{'server-ip'};
my $server_port = $opts{'server-port'} ? $opts{'server-port'} : 25;

my $s = IO::Select->new(); # for socket polling

sub generate_preamble {
  my @preamble;
  if (!$opts{version} || $opts{version} == 2) {
    @preamble = (
      "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", # 12 byte v2 header
      "\x21",                                             # top 4 bits declares v2
                                                          # bottom 4 bits is command
      $opts{6} ? "\x21" : "\x11",                         # inet6/4 and TCP (stream)
      $opts{6} ? "\x00\x24" : "\x00\x0b",                 # 36 bytes / 12 bytes
      $source_ip,
      $dest_ip,
      $source_port,
      $dest_port
    );
  }
  else {
    @preamble = (
      "PROXY", " ",                                       # Request proxy mode
      $opts{6} ? "TCP6" : "TCP4", " ",                    # inet6/4 and TCP (stream)
      $source_ip, " ",                                    
      $dest_ip, " ",
      $source_port, " ",
      $dest_port,
      "\x0d\x0a"
    );
    $status_line .= join "", @preamble;
  }
  print "\n", $status_line, "\n";
  print "\n" if (!$opts{version} || $opts{version} == 2);
  return @preamble;
}

sub binary_pack_port {
  my $port = shift();
  if ($opts{version} && $opts{version} == 1) {
    return $port
      if ($port && $port =~ /^\d+$/ && $port > 0 && $port < 65536);
    die "Not a valid port: $port";
  }
  $status_line .= $port." ";
  $port = pack "S", $port;
  return $port;
}

sub binary_pack_ip {
  my $ip = shift();
  if ( $ip =~ m/\./ && !$opts{6}) {
    if (IP4_valid($ip)) {
      return $ip if ($opts{version} && $opts{version} == 1);
      $status_line .= $ip.":";
      $ip = pack "C*", split /\./, $ip;
    }
    else { die "Invalid IPv4: $ip"; }
  }
  elsif ($ip =~ m/:/ && $opts{6}) {
    $ip = pad_ipv6($ip);
    if (IP6_valid($ip)) {
      return $ip if ($opts{version} && $opts{version} == 1);
      $status_line .= $ip.":";
      $ip = pack "S>*", map hex, split /:/, $ip;
    }
    else { die "Invalid IPv6: $ip"; }
  }
  else { die "Mismatching IP families passed: $ip"; }
  return $ip;
}

sub pad_ipv6 {
  my $ip = shift();
  my @ip = split /:/, $ip;
  my $segments = scalar @ip;
  return $ip if ($segments == 8);
  $ip = "";
  for (my $count=1; $count <= $segments; $count++) {
    my $block = $ip[$count-1];
    if ($block) {
      $ip .= $block;
      $ip .= ":" unless $count == $segments;
    }
    elsif ($count == 1) {
      # Somebody passed us ::1, fix it, but it's not really valid
      $ip = "0:";
    }
    else {
      $ip .= join ":", map "0", 0..(8-$segments);
      $ip .= ":";
    }
  }
  return $ip;
}

sub IP6_valid {
  my $ip = shift;
  $ip = lc($ip);
  return 0 unless ($ip =~ /^[0-9a-f:]+$/);
  my @ip = split /:/, $ip;
  return 0 if (scalar @ip != 8);
  return 1;
}

sub IP4_valid {
  my $ip = shift;
  $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  foreach ($1,$2,$3,$4){
    if ($_  <256 && $_ >0) {next;}
    return 0;
  }
  return 1;
}

sub go_interactive {
  my $continue = 1;
  while($continue) {
    # Check for input on both ends, recheck every 5 sec
    for my $socket ($s->can_read(5)) {
      my $remote = $socket_map{$socket};
      my $buffer;
      my $read = $socket->sysread($buffer, 4096);
      if ($read) {
        $remote->syswrite($buffer);
      }
      else {
        $continue = 0;
      }
    }
  }
}

sub connect_stdin_to_proxy {
  my $sock = new IO::Socket::INET(
               PeerAddr => $server_ip,
               PeerPort => $server_port,
               Proto    => 'tcp'
             );

  die "Could not create socket: $!\n" unless $sock;
  # Add sockets to the Select group
  $s->add(\*STDIN);
  $s->add($sock);
  # Tie the sockets together using this hash
  $socket_map{\*STDIN} = $sock;
  $socket_map{$sock} = \*STDOUT;
  return $sock;
}

sub usage {
  chomp(my $prog = `basename $0`);
  print <<EOF;
Usage: $prog [required] [optional]
  Required:
    --server-ip   IP of server to test proxy configuration,
                  a hostname is ok, but for only this setting
  Optional:
    --server-port Port server is listening on (default 25)
    --6           IPv6 source/dest (default IPv4), if none specified,
                  some default, reverse resolvable IP's are used for
                  the source and dest ip/port
    --dest-ip     Public IP of the proxy server
    --dest-port   Port of public IP of proxy server
    --source-ip   IP connecting to the proxy server
    --source-port Port of IP connecting to the proxy server
    --help        This output
EOF
  exit;
}


my $sock = connect_stdin_to_proxy();
my @preamble = generate_preamble();
print $sock @preamble;
go_interactive();
