#!/usr/bin/env perl

use strict;

use Cwd qw(abs_path);
use File::Spec;
use Getopt::Long;
use Test::Harness qw(&runtests $verbose);

my $opts = {};
GetOptions($opts, 'h|help', 'C|class=s@', 'K|keep-tmpfiles', 'F|file-pattern=s',
  'V|verbose');

if ($opts->{h}) {
  usage();
}

if ($opts->{K}) {
  $ENV{KEEP_TMPFILES} = 1;
}

if ($opts->{V}) {
  $ENV{TEST_VERBOSE} = 1;
  $verbose = 1;
}

# We use this, rather than use(), since use() is equivalent to a BEGIN
# block, and we want the module to be loaded at run-time.

my $test_dir = (File::Spec->splitpath(abs_path(__FILE__)))[1];
push(@INC, "$test_dir/t/lib");

require ProFTPD::TestSuite::Utils;
import ProFTPD::TestSuite::Utils qw(:testsuite);

# This is to handle the case where this tests.pl script might be
# being used to run test files other than those that ship with proftpd,
# e.g. to run the tests that come with third-party modules.
unless (defined($ENV{PROFTPD_TEST_BIN})) {
  $ENV{PROFTPD_TEST_BIN} = File::Spec->catfile($test_dir, '..', 'proftpd');
}

# Set this environment variable, for other test cases which may want to
# know the directory, and not necessarily just the location of the uninstalled
# `proftpd' binary.  This is useful, for example, for using the utilities.
$ENV{PROFTPD_TEST_PATH} = $test_dir;

$| = 1;

my $test_files;

if (scalar(@ARGV) > 0) {
  $test_files = [@ARGV];

} else {
  $test_files = [qw(
    t/http.t
    t/smtp.t
    t/ssh2.t
    t/logins.t
    t/commands/user.t
    t/commands/pass.t
    t/commands/pwd.t
    t/commands/cwd.t
    t/commands/cdup.t
    t/commands/syst.t
    t/commands/type.t
    t/commands/mkd.t
    t/commands/rmd.t
    t/commands/dele.t
    t/commands/mdtm.t
    t/commands/size.t 
    t/commands/mode.t
    t/commands/stru.t
    t/commands/allo.t
    t/commands/noop.t
    t/commands/feat.t
    t/commands/help.t
    t/commands/quit.t
    t/commands/rang.t
    t/commands/rnfr.t
    t/commands/rnto.t
    t/commands/rest.t
    t/commands/pasv.t
    t/commands/epsv.t
    t/commands/port.t
    t/commands/eprt.t
    t/commands/nlst.t
    t/commands/list.t
    t/commands/retr.t
    t/commands/stor.t
    t/commands/stou.t
    t/commands/appe.t
    t/commands/stat.t
    t/commands/abor.t
    t/commands/mlsd.t
    t/commands/mlst.t
    t/commands/mff.t
    t/commands/mfmt.t
    t/commands/opts.t
    t/commands/host.t
    t/commands/clnt.t
    t/commands/site/chgrp.t
    t/commands/site/chmod.t
    t/config/accessdenymsg.t
    t/config/accessgrantmsg.t
    t/config/allowfilter.t
    t/config/allowforeignaddress.t
    t/config/allowoverwrite.t
    t/config/anonrejectpasswords.t
    t/config/anonrequirepassword.t
    t/config/authaliasonly.t
    t/config/authgroupfile.t
    t/config/authorder.t
    t/config/authuserfile.t
    t/config/authusingalias.t
    t/config/classes.t
    t/config/commandbuffersize.t
    t/config/createhome.t
    t/config/defaultchdir.t
    t/config/defaultroot.t
    t/config/deferwelcome.t
    t/config/deleteabortedstores.t
    t/config/denyfilter.t
    t/config/dirfakegroup.t
    t/config/dirfakemode.t
    t/config/dirfakeuser.t
    t/config/displaychdir.t
    t/config/displayconnect.t
    t/config/displayfiletransfer.t 
    t/config/displaylogin.t
    t/config/displayquit.t
    t/config/envvars.t
    t/config/factsoptions.t
    t/config/groupowner.t
    t/config/hiddenstores.t
    t/config/hidefiles.t
    t/config/hidegroup.t
    t/config/hidenoaccess.t
    t/config/hideuser.t
    t/config/ifdefine.t
    t/config/include.t
    t/config/listoptions.t
    t/config/masqueradeaddress.t
    t/config/maxclients.t
    t/config/maxclientsperclass.t
    t/config/maxclientsperhost.t
    t/config/maxclientsperuser.t
    t/config/maxcommandrate.t
    t/config/maxconnectionsperhost.t
    t/config/maxinstances.t
    t/config/maxloginattempts.t
    t/config/maxpasswordsize.t
    t/config/maxretrievefilesize.t
    t/config/maxstorefilesize.t
    t/config/maxtransfersperhost.t
    t/config/maxtransfersperuser.t
    t/config/multilinerfc2228.t
    t/config/order.t
    t/config/passiveports.t
    t/config/pathallowfilter.t
    t/config/pathdenyfilter.t
    t/config/protocols.t
    t/config/requirevalidshell.t
    t/config/rewritehome.t
    t/config/rlimitchroot.t
    t/config/rlimitcpu.t
    t/config/rlimitmemory.t
    t/config/rlimitopenfiles.t
    t/config/rootrevoke.t
    t/config/serveradmin.t
    t/config/serverident.t
    t/config/setenv.t
    t/config/showsymlinks.t
    t/config/socketoptions.t
    t/config/storeuniqueprefix.t
    t/config/sysloglevel.t
    t/config/timeoutidle.t
    t/config/timeoutlogin.t
    t/config/timeoutnotransfer.t
    t/config/timeoutsession.t
    t/config/timeoutstalled.t
    t/config/trace.t
    t/config/traceoptions.t
    t/config/transferrate.t
    t/config/umask.t
    t/config/useftpusers.t
    t/config/useglobbing.t
    t/config/useralias.t
    t/config/userowner.t
    t/config/userpassword.t
    t/config/usesendfile.t
    t/config/virtualhost.t
    t/config/directory/limits.t
    t/config/directory/umask.t
    t/config/ftpaccess/dele.t
    t/config/ftpaccess/empty.t
    t/config/ftpaccess/merging.t
    t/config/ftpaccess/retr.t
    t/config/limit/anonymous.t
    t/config/limit/login.t
    t/config/limit/mfmt.t
    t/config/limit/opts.t
    t/config/limit/rmd.t
    t/config/limit/xmkd.t
    t/config/limit/filters.t
    t/config/limit/subdirs.t
    t/logging/extendedlog.t
    t/logging/serverlog.t
    t/logging/systemlog.t
    t/logging/transferlog.t
    t/signals/term.t
    t/signals/hup.t
    t/signals/segv.t
    t/signals/abrt.t
    t/telnet.t
    t/utils/ftpcount.t
    t/utils/ftpwho.t
  )];

  # Now interrogate the build to see which module/feature-specific test files
  # should be added to the list.
  my $order = 0;

  my $FEATURE_TESTS = {
    't/modules/mod_auth_file.t' => {
      order => ++$order,
      test_class => [qw(mod_auth_file)],
    },

    't/modules/mod_auth_otp.t' => {
      order => ++$order,
      test_class => [qw(mod_auth_otp mod_sql mod_sql_sqlite)],
    },

    't/modules/mod_auth_otp/sftp.t' => {
      order => ++$order,
      test_class => [qw(mod_auth_otp mod_sftp mod_sql mod_sql_sqlite)],
    },

    't/modules/mod_ban.t' => {
      order => ++$order,
      test_class => [qw(mod_ban)],
    },

    't/modules/mod_ban/memcache.t' => {
      order => ++$order,
      test_class => [qw(mod_ban mod_memcache)],
    },

    't/modules/mod_cap.t' => {
      order => ++$order,
      test_class => [qw(mod_cap)],
    },

    't/modules/mod_copy.t' => {
      order => ++$order,
      test_class => [qw(mod_copy)],
    },

    't/modules/mod_ctrls.t' => {
      order => ++$order,
      test_class => [qw(mod_ctrls)],
    },

    't/modules/mod_deflate.t' => {
      order => ++$order,
      test_class => [qw(mod_deflate)],
    },

    't/modules/mod_delay.t' => {
      order => ++$order,
      test_class => [qw(mod_delay)],
    },

    't/modules/mod_digest.t' => {
      order => ++$order,
      test_class => [qw(mod_digest)],
    },

    't/modules/mod_dynmasq.t' => {
      order => ++$order,
      test_class => [qw(mod_dynmasq)],
    },

    't/modules/mod_exec.t' => {
      order => ++$order,
      test_class => [qw(mod_exec)],
    },

    't/modules/mod_facl.t' => {
      order => ++$order,
      test_class => [qw(mod_facl)],
    },

    't/modules/mod_geoip.t' => {
      order => ++$order,
      test_class => [qw(mod_geoip)],
    },

    't/modules/mod_geoip/sql.t' => {
      order => ++$order,
      test_class => [qw(mod_geoip mod_sql mod_sql_sqlite)],
    },

    't/modules/mod_ifversion.t' => {
      order => ++$order,
      test_class => [qw(mod_ifversion)],
    },

    't/modules/mod_lang.t' => {
      order => ++$order,
      test_class => [qw(mod_lang)],
    },

    't/modules/mod_log_forensic.t' => {
      order => ++$order,
      test_class => [qw(mod_log_forensic)],
    },

    't/modules/mod_quotatab_file.t' => {
      order => ++$order,
      test_class => [qw(mod_quotatab mod_quotatab_file)],
    },

    't/modules/mod_quotatab_sql.t' => {
      order => ++$order,
      test_class => [qw(mod_quotatab mod_quotatab_sql mod_sql_sqlite)],
    },

    't/modules/mod_quotatab/copy.t' => {
      order => ++$order,
      test_class => [qw(mod_copy mod_quotatab mod_quotatab_sql mod_sql_sqlite)],
    },

    't/modules/mod_quotatab/site_misc.t' => {
      order => ++$order,
      test_class => [qw(
        mod_copy
        mod_quotatab
        mod_quotatab_sql
        mod_sql_sqlite
        mod_site_misc
      )],
    },

    't/modules/mod_ratio.t' => {
      order => ++$order,
      test_class => [qw(mod_ratio)],
    },

    't/modules/mod_readme.t' => {
      order => ++$order,
      test_class => [qw(mod_readme)],
    },

    't/modules/mod_redis.t' => {
      order => ++$order,
      test_class => [qw(mod_redis)],
    },

    't/modules/mod_rewrite.t' => {
      order => ++$order,
      test_class => [qw(mod_rewrite)],
    },

    't/modules/mod_rlimit.t' => {
      order => ++$order,
      test_class => [qw(mod_rlimit)],
    },

    't/modules/mod_sftp.t' => {
      order => ++$order,
      test_class => [qw(mod_sftp)],
    },

    't/modules/mod_sftp/ban.t' => {
      order => ++$order,
      test_class => [qw(mod_ban mod_sftp)],
    },

    't/modules/mod_sftp/exec.t' => {
      order => ++$order,
      test_class => [qw(mod_exec mod_sftp)],
    },

    't/modules/mod_sftp/fips.t' => {
      order => ++$order,
      test_class => [qw(feat_openssl_fips mod_sftp)],
    },

    't/modules/mod_sftp/rewrite.t' => {
      order => ++$order,
      test_class => [qw(mod_rewrite mod_sftp)],
    },

    't/modules/mod_sftp/sql.t' => {
      order => ++$order,
      test_class => [qw(mod_sftp mod_sql_sqlite)],
    },

    't/modules/mod_sftp/wrap2.t' => {
      order => ++$order,
      test_class => [qw(mod_sftp mod_wrap2)],
    },

    't/modules/mod_sftp_pam.t' => {
      order => ++$order,
      test_class => [qw(mod_sftp mod_sftp_pam)],
    },

    't/modules/mod_sftp_sql.t' => {
      order => ++$order,
      test_class => [qw(mod_sftp mod_sftp_sql mod_sql_sqlite)],
    },

    't/modules/mod_shaper.t' => {
      order => ++$order,
      test_class => [qw(mod_shaper)],
    },

    't/modules/mod_site.t' => {
      order => ++$order,
      test_class => [qw(mod_site)],
    },

    't/modules/mod_site_misc.t' => {
      order => ++$order,
      test_class => [qw(mod_site_misc)],
    },

    't/modules/mod_snmp.t' => {
      order => ++$order,
      test_class => [qw(mod_snmp)],
    },

    't/modules/mod_sql.t' => {
      order => ++$order,
      test_class => [qw(mod_sql)],
    },

    't/modules/mod_sql_passwd.t' => {
      order => ++$order,
      test_class => [qw(mod_sql_passwd mod_sql_sqlite)],
    },

    't/modules/mod_sql_passwd/fips.t' => {
      order => ++$order,
      test_class => [qw(feat_openssl_fips mod_sql_passwd mod_sql_sqlite mod_sftp)],
    },

    't/modules/mod_sql_odbc.t' => {
      order => ++$order,
      test_class => [qw(mod_sql_odbc)],
    },

    't/modules/mod_sql_sqlite.t' => {
      order => ++$order,
      test_class => [qw(mod_sql_sqlite)],
    },

    't/modules/mod_statcache.t' => {
      order => ++$order,
      test_class => [qw(mod_statcache)],
    },

    't/modules/mod_tls.t' => {
      order => ++$order,
      test_class => [qw(mod_tls)],
    },

    't/modules/mod_tls_fscache.t' => {
      order => ++$order,
      test_class => [qw(mod_tls_fscache)],
    },

    't/modules/mod_tls_memcache.t' => {
      order => ++$order,
      test_class => [qw(mod_tls_memcache)],
    },

    't/modules/mod_tls_shmcache.t' => {
      order => ++$order,
      test_class => [qw(mod_tls_shmcache)],
    },

    't/modules/mod_unique_id.t' => {
      order => ++$order,
      test_class => [qw(mod_unique_id)],
    },

    't/modules/mod_wrap.t' => {
      order => ++$order,
      test_class => [qw(mod_wrap)],
    },

    't/modules/mod_wrap2_file.t' => {
      order => ++$order,
      test_class => [qw(mod_wrap2_file)],
    },

    't/modules/mod_wrap2_redis.t' => {
      order => ++$order,
      test_class => [qw(mod_redis mod_wrap2_redis)],
    },

    't/modules/mod_wrap2_sql.t' => {
      order => ++$order,
      test_class => [qw(mod_sql_sqlite mod_wrap2_sql)],
    },
  };

  my @feature_tests = testsuite_get_runnable_tests($FEATURE_TESTS);
  my $feature_ntests = scalar(@feature_tests);
  if ($feature_ntests > 1 ||
      ($feature_ntests == 1 && $feature_tests[0] ne 'testsuite_empty_test')) {
    push(@$test_files, @feature_tests);
  }
}

$ENV{PROFTPD_TEST} = 1;

if (defined($opts->{C})) {
  $ENV{PROFTPD_TEST_ENABLE_CLASS} = join(':', @{ $opts->{C} });

} else {
  # Disable all 'inprogress' and 'slow' tests by default
  $ENV{PROFTPD_TEST_DISABLE_CLASS} = 'inprogress:slow';
}

if (defined($opts->{F})) {
  # Using the provided string as a regex, and run only the tests whose
  # files match the pattern

  my $file_pattern = $opts->{F};

  my $filtered_files = [];
  foreach my $test_file (@$test_files) {
    if ($test_file =~ /$file_pattern/) {
      push(@$filtered_files, $test_file);
    }
  }

  $test_files = $filtered_files;
}

runtests(@$test_files) if scalar(@$test_files) > 0;

exit 0;

sub usage {
  print STDOUT <<EOH;

$0: [--help] [--class=\$name] [--verbose]

Examples:

  perl $0
  perl $0 --class foo
  perl $0 --class bar --class baz

EOH
  exit 0;
}
