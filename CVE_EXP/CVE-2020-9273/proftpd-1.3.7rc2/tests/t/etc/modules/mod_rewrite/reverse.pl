#!/usr/bin/env perl
use strict;

use File::Basename qw(basename);
use Getopt::Long;
use IO::Handle;

my $default_delay = 0.5;
my $program = basename($0);
my %opts = ();

GetOptions(\%opts, 'delay=f', 'fifo=s', 'pidfile=s', 'help', 'verbose');

usage() if $opts{'help'};

my $delay = $opts{'delay'} ? $opts{'delay'} : $default_delay;

die "$program: missing required --fifo parameter\n" unless $opts{'fifo'};
my $fifo = $opts{'fifo'};

my $verbose = $opts{'verbose'} ? 1 : 0;

open(my $fifo_fh, "+> $fifo") or die "$program: unable to open $fifo: $!\n";

if ($opts{'pidfile'}) {
  my $path = $opts{'pidfile'};

  if (open(my $fh, ">> $path")) {
    print $fh "$$\n";
    unless (close($fh)) {
      die("$program: can't write pidfile '$path': $!\n");
    }

  } else {
    die("$program: can't open pidfile '$path': $!\n");
  }
}

while (1) {
  my $key = <$fifo_fh>;
  chomp($key);
  print STDERR "$program: read '$key'\n" if $verbose;

  # Lookup a value for the given key.
  my $value = lookup_value($key);

  print $fifo_fh "$value\n" if $verbose;
  $fifo_fh->flush();

  print STDERR "$program: wrote '$value'\n" if $verbose;

  # Wait for the buffer's byte to be cleared before reading again.
#  wait_fifo($fifo_fh);
}

close($fifo_fh);
print STDOUT "$program: done\n" if $verbose;

exit 0;

# --------------------------------------------------------------------------
sub lookup_value {
  my ($key) = @_;

  # NOTE: do something to obtain a value for the given key here.
  chomp(my $value = $key);

  $value = join('', reverse(split(//, $value)));
  return $value;
}

# --------------------------------------------------------------------------
sub usage {
  print STDOUT <<END_OF_USAGE;

usage: $program [options]

  --delay         Configure the buffer check delay.
                  The default is $default_delay seconds.

  --fifo          Configure the path to the FIFO.  Required.

  --help          Displays this message.

  --verbose       Enables verbose output while $program runs.

END_OF_USAGE

  exit 0;
}

# --------------------------------------------------------------------------
sub wait_fifo {
  my ($fh) = @_;

  # Now we get tricky.  Use ioctl(2) to poll the number of bytes to
  # be read from the FIFO filehandle.  When the number drops to zero,
  # it means that the data we just wrote has been read from the buffer
  # by some other process, so we can go back to the top of this loop.
  # Otherwise, if this program loops faster than the reader/writer on
  # the other end of the FIFO, we'd end up reading the data we just
  # wrote.  Quite annoying, actually.
  #
  # Note: this value must be manually extracted from the system header files
  # using the following program:
  #
  # -------- fionread.c -------------------
  #  #include <stdio.h>
  #  #include <sys/ioctl.h>
  #
  #  int main(int argc, char *argv[]) {
  #   printf("%#08x\n", FIONREAD);
  #   return 0;
  # }
  # ---------------------------------------
  #
  # > cc -o fionread fionread.c
  # > ./fionread

  my $FIONREAD = 0x00541b;

  # Hack for my Mac laptop
  if ($^O eq 'darwin') {
    $FIONREAD = 0x4004667f;
  }

  my $size = pack('L', 0);
  ioctl($fh, $FIONREAD, $size) or die "$program: unable to use ioctl: $!\n";
  $size = unpack('L', $size);

  while ($size != 0) {
    print STDERR "$program: waiting for buffer ($size bytes) to be read\n" if $verbose;
    select(undef, undef, undef, $delay);

    $size = pack('L', 0);
    ioctl($fh, $FIONREAD, $size) or die "$program: unable to use ioctl: $!\n";
    $size = unpack('L', $size);
  }
}
