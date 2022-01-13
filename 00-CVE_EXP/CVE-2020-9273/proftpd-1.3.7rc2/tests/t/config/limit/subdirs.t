#!/usr/bin/env perl

use lib qw(t/lib);
use strict;

use Test::Unit::HarnessUnit;

$| = 1;

my $r = Test::Unit::HarnessUnit->new();
$r->start("ProFTPD::Tests::Config::Limit::SubDirectories");
