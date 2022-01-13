#!/usr/bin/env perl

use warnings;
use strict;
BEGIN { pop @INC if $INC[-1] eq '.' };

use Fcntl qw(:DEFAULT :flock :seek);
use File::Find;
use File::Spec;

use constant MIN_AGE => 60; # seconds
my $exim = exists $ENV{'EXIM_BINARY'} ? $ENV{'EXIM_BINARY'} : 'exim';

my %known_okay = map {$_=>1} qw( linux darwin freebsd );
unless (exists $known_okay{$^O}) {
  warn "for ease, this perl uses flock, not fcntl, assuming they're the same\n";
  warn "this is not known by this author to be the case on $^O\n";
  warn "please investigate and either add to allowed-list in script, or rewrite\n";
  die "bailing out";

  # Another approach to rewriting script: stop all exim receivers and
  # queue-runners, prevent them from starting, then add your OS to the list and
  # run, even though the locking type is wrong, relying upon not actually
  # contending.
}

my $spool_dir = `$exim -n -bP spool_directory`;
chomp $spool_dir;

chdir(File::Spec->catfile($spool_dir, 'input'))
    or die "chdir($spool_dir/input) failed: $!\n";

my $exim_msgid_r = qr/(?:[0-9A-Za-z]{6}-[0-9A-Za-z]{6}-[0-9A-Za-z]{2})/;
my $spool_dfile_r = qr/^(($exim_msgid_r)-D)\z/o;

sub fh_ends_newline {
  my ($fh, $dfn, $verbose) = @_;
  seek($fh, -1, 2) or do { warn "seek(file($dfn)) failed: $!\n"; return -1 };
  my $count = read $fh, my $ch, 1;
  if ($count == -1) { warn "failed to read last byte of $dfn\n"; return -1 };
  if ($count == 0) { warn "file shrunk by one??  problem with $dfn\n"; return -1 };
  if ($ch eq "\n") { print "okay!\n" if $verbose; return 1 }
  print "PROBLEM: $dfn missing final newline (got $ch)\n" if $verbose;
  return 0;
}


sub each_found_file {
  return unless $_ =~ $spool_dfile_r;
  my ($msgid, $dfn) = ($2, $1);

  # We should have already upgraded Exim before invoking us, thus any spool
  # files will be old and we can reduce spending time trying to lock files
  # still being written to, etc.
  my @st = lstat($dfn) or return;
  if ($^T - $st[9] < MIN_AGE) { return };
  -f "./${msgid}-H" || return;

  print "consider: $dfn\n";
  open(my $fh, '+<:raw', $dfn) or do {
    warn "open($dfn) failed: $!\n";
    return;
  };
  # return with a lexical FH in modern Perl should guarantee close, AIUI

  # we do our first check without a lock, so that we can scan past messages
  # being handled by Exim quickly, and only lock up on those which Exim is
  # trying and failing to deliver.  However, since Exim will be hung on remote
  # hosts, this is likely.  Thus best to kill queue-runners first.

  return if fh_ends_newline($fh, $dfn, 0); # also returns on error
  print "Problem? $msgid probably missing newline, locking to be sure ...\n";
  flock($fh, LOCK_EX) or do { warn "flock(file($dfn)) failed: $!\n"; return };
  return if fh_ends_newline($fh, $dfn, 1); # also returns on error

  fixup_message($msgid, $dfn, $fh);

  close($fh) or warn "close($dfn) failed: $!\n";
};

sub fixup_message {
  my ($msgid, $dfn, $fh) = @_;
  # we can't freeze the message, our lock stops that, which is good!

  seek($fh, 0, 2) or do { warn "seek(file($dfn)) failed: $!\n"; return -1 };

  my $r = inc_message_header_linecount($msgid);
  if ($r < 0) {
    warn "failed to fix message headers in ${msgid}-H so not editing message\n";
    return;
  }

  print {$fh} "\n";

  print "${msgid}: added newline\n";
};

sub inc_message_header_linecount {
  my ($msgid) = @_;
  my $name_in = "${msgid}-H";
  my $name_out = "${msgid}-chunkfix";

  open(my $in, '<:perlio', $name_in) or do { warn "open(${name_in}) failed: $!\n"; return -1 };
  open(my $out, '>:perlio', $name_out) or do { warn "write-open(${name_out}) failed: $!\n"; return -1 };
  my $seen = 0;
  my $lc;
  foreach (<$in>) {
    if ($seen) {
      print {$out} $_;
      next;
    }
    if (/^(-body_linecount\s+)(\d+)(\s*)$/) {
      $lc = $2 + 1;
      print {$out} "${1}${lc}${3}";
      $seen = 1;
      next;
    }
    print {$out} $_;
  }
  close($in) or do {
    warn "read-close(${msgid}-H) failed, assuming incomplete: $!\n";
    close($out);
    unlink $name_out;
    return -1;
  };
  close($out) or do {
    warn "write-close(${msgid}-chunkfix) failed, aborting: $!\n";
    unlink $name_out;
    return -1;
  };

  my @target = stat($name_in) or do { warn "stat($name_in) failed: $!\n"; unlink $name_out; return -1 };
  my @created = stat($name_out) or do { warn "stat($name_out) failed: $!\n"; unlink $name_out; return -1 };
  # 4=uid, 5=gid, 2=mode
  if (($created[5] != $target[5]) or ($created[4] != $target[4])) {
    chown $target[4], $target[5], $name_out or do {
      warn "chown($name_out) failed: $!\n";
      unlink $name_out;
      return -1;
    };
  }
  if (($created[2]&07777) != ($target[2]&0x7777)) {
    chmod $target[2]&0x7777, $name_out or do {
      warn "chmod($name_out) failed: $!\n";
      unlink $name_out;
      return -1;
    };
  }

  rename $name_out, $name_in or do {
    warn "rename '${msgid}-chunkfix' -> '${msgid}-H' failed: $!\n";
    unlink $name_out;
    return -1;
  };

  print "${msgid}: linecount set to $lc\n";
  return 1;
}

find({wanted => \&each_found_file}, '.');
