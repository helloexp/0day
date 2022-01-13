#!/usr/bin/env perl

use strict;

my $lock_file = "/tmp/tls-passphrase.lock";
if (-f $lock_file) {
  print STDERR "Passphrase already obtained (see lock file $lock_file); exiting\n";
  exit 1;
}

if (open(my $fh, "> $lock_file")) {
  close($fh);

  my $passphrase = "password";
  print STDOUT "$passphrase\n";
  exit 0;

} else {
  print STDERR "Error opening lock file $lock_file: $!\n";
}

exit 1;
