#!/usr/bin/perl -w

use Cwd;
use File::Copy;
use File::Path;
use Getopt::Long 'GetOptions';
use strict;

#==================== config =====================
my $logfile        = 'test.log';
my $output_dir     = 'output';
my $conf_dir       = 'conf';
my $run_dir        = 'run';
my $test_install_dir = 'fwsnort-install';

my $fwsnortCmd = "$test_install_dir/usr/sbin/fwsnort";
my $fwsnort_sh = "$test_install_dir/var/lib/fwsnort/fwsnort.sh";

my $cmd_out_tmp    = 'cmd.out';
my $default_conf   = "$conf_dir/default_fwsnort.conf";

### alert tcp $EXTERNAL_NET any -> $HOME_NET 7597 (msg:"BACKDOOR QAZ Worm Client Login access"; \
### flow:to_server,established; content:"qazwsx.hsq"; reference:MCAFEE,98775; \
### classtype:misc-activity; sid:108; rev:6;)
my $simple_sig_id = 108;
#================== end config ===================

my $current_test_file = "$output_dir/init";
my $YES = 1;
my $NO  = 0;
my $IGNORE = 2;
my $passed = 0;
my $failed = 0;
my $executed = 0;
my $test_include = '';
my @tests_to_include = ();
my $test_exclude = '';
my @tests_to_exclude = ();
my $list_mode = 0;
my $diff_mode = 0;
my $fw_exec = 0;
my $saved_last_results = 0;
my $test_system_install = 0;
my $PRINT_LEN = 68;
my $REQUIRED = 1;
my $OPTIONAL = 0;
my $MATCH_ALL_RE = 1;
my $MATCH_SINGLE_RE = 2;
my $help = 0;

my %test_keys = (
    'category'        => $REQUIRED,
    'subcategory'     => $OPTIONAL,
    'detail'          => $REQUIRED,
    'function'        => $REQUIRED,
    'cmdline'         => $OPTIONAL,
    'fatal'           => $OPTIONAL,
    'exec_err'        => $OPTIONAL,
    'match_all'       => $OPTIONAL,
    'fw_exec'         => $OPTIONAL,
    'postive_output_matches'  => $OPTIONAL,
    'negative_output_matches' => $OPTIONAL,
);

my @args_cp = @ARGV;

exit 1 unless GetOptions(
    'fwsnort-path=s'      => \$fwsnortCmd,
    'test-include=s'      => \$test_include,
    'include=s'           => \$test_include,  ### synonym
    'test-exclude=s'      => \$test_exclude,
    'exclude=s'           => \$test_exclude,  ### synonym
    'test-system-install' => \$test_system_install,
    'List-mode'           => \$list_mode,
    'diff'                => \$diff_mode,
    'enable-fw-exec'      => \$fw_exec,
    'help'                => \$help
);

&usage() if $help;

### define all tests
my @tests = (
    {
        'category' => 'install',
        'detail'   => "test directory: $test_install_dir",
        'err_msg'  => 'could not install',
        'function' => \&install_test_dir,
        'cmdline'  => "./install.pl --install-test-dir",
        'exec_err' => $NO,
        'fatal'    => $YES
    },
    {
        'category' => 'compilation',
        'detail'   => 'fwsnort compiles',
        'err_msg'  => 'could not compile',
        'function' => \&generic_exec,
        'cmdline'  => "perl -c $fwsnortCmd",
        'exec_err' => $NO,
        'fatal'    => $YES
    },
    {
        'category' => 'operations',
        'detail'   => '--help',
        'err_msg'  => 'could not get --help output',
        'function' => \&generic_exec,
        'cmdline'  => "$fwsnortCmd -h -c $default_conf",
        'exec_err' => $NO,
        'fatal'    => $NO
    },
    {
        'category' => 'operations',
        'detail'   => '--dump-conf',
        'err_msg'  => 'could not get --Dump-conf output',
        'function' => \&generic_exec,
        'cmdline'  => "$fwsnortCmd --Dump-conf -c $default_conf --no-ipt-test",
        'exec_err' => $NO,
        'fatal'    => $NO
    },
    {
        'category' => 'operations',
        'detail'   => '--ipt-list',
        'err_msg'  => 'could not get --ipt-list output',
        'function' => \&generic_exec,
        'cmdline'  => "$fwsnortCmd --ipt-list -c $default_conf --no-ipt-test",
        'exec_err' => $NO,
        'fatal'    => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "--ipt-check-capabilities",
        'err_msg'   => "could not check iptables capabilities",
        'positive_output_matches' => [
            qr/iptables\shas/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --ipt-check-capabilities --verbose -c $default_conf",
        'exec_err'  => $NO,
        'fatal'     => $NO
    },

    {
        'category'  => 'operations',
        'detail'    => "--snort-sid $simple_sig_id EXTERNAL->HOME",
        'err_msg'   => "did not translate sid: $simple_sig_id",
        'positive_output_matches' => [qr/Found\ssid\:\s$simple_sig_id/,
            qr/Successful\stranslation/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --no-ipt-test -c $default_conf --snort-sid $simple_sig_id",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "--snort-sid 1292 HOME->EXTERNAL",
        'err_msg'   => "did not translate sid: 1292",
        'positive_output_matches' => [qr/Found\ssid\:\s1292/,
            qr/Successful\stranslation/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --no-ipt-test -c $default_conf --snort-sid 1292",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },

    {
        'category'  => 'operations',
        'detail'    => "multiple rules --snort-sid $simple_sig_id,109,321",
        'err_msg'   => "did not translate sid: $simple_sig_id",
        'positive_output_matches' => [qr/Found\ssid/,
            qr/Found\ssid\:\s109/,
            qr/Found\ssid\:\s321/,
            qr/Successful\stranslation/,
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --no-ipt-test -c $default_conf --snort-sid $simple_sig_id,109,321",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "--snort-sid badsid",
        'err_msg'   => 'translated badsid signature',
        'positive_output_matches' => [
            qr/No\sSnort\srules\scould\sbe\stranslated/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --no-ipt-test -c $default_conf --snort-sid badsid",
        'exec_err'  => $YES,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "--include-type backdoor",
        'err_msg'   => "did not translate backdoor signatures",
        'positive_output_matches' => [
            qr/backdoor\.rules/,
            qr/Generated\siptables\srules\sfor/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --no-ipt-test -c $default_conf --include-type backdoor",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "--strict --include-type backdoor",
        'err_msg'   => "did not translate backdoor signatures",
        'positive_output_matches' => [
            qr/backdoor\.rules/,
            qr/Generated\siptables\srules\sfor/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --no-ipt-test -c $default_conf --strict --include-type backdoor",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "--include-type emerging-all",
        'err_msg'   => "did not translate emerging-all signatures",
        'positive_output_matches' => [
            qr/emerging-all\.rules/,
            qr/Generated\siptables\srules\sfor/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --no-ipt-test -c $default_conf --include-type emerging-all",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },

    {
        'category'  => 'operations',
        'detail'    => "multiple files --include-type backdoor,dns,ftp",
        'err_msg'   => "did not translate backdoor,dns,ftp signatures",
        'positive_output_matches' => [
            qr/backdoor\.rules/,
            qr/dns\.rules/,
            qr/ftp\.rules/,
            qr/Generated\siptables\srules\sfor/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --no-ipt-test -c $default_conf --include-type backdoor,dns,ftp",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "--exclude-type emerging-all",
        'err_msg'   => "did not translate signatures",
        'positive_output_matches' => [
            qr/backdoor\.rules/,
            qr/dns\.rules/,
            qr/ftp\.rules/,
            qr/Generated\siptables\srules\sfor/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --no-ipt-test -c $default_conf --exclude-type emerging-all",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "multiple --exclude-type emerging-all,backdoor,dns,ftp",
        'err_msg'   => "did not translate signatures",
        'positive_output_matches' => [
            qr/chat\.rules/,
            qr/ddos\.rules/,
            qr/Generated\siptables\srules\sfor/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --no-ipt-test -c $default_conf --exclude-type emerging-all,backdoor,dns,ftp",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "--include-type backdoor,dns,ftp --exclude-type dns",
        'err_msg'   => "did not translate backdoor,ftp signatures",
        'positive_output_matches' => [
            qr/backdoor\.rules/,
            qr/ftp\.rules/,
            qr/Generated\siptables\srules\sfor/
        ],
        'negative_output_matches' => [
            qr/dns\.rules/,
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --no-ipt-test -c $default_conf --include-type backdoor,dns,ftp --exclude-type dns",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "--snort-sid $simple_sig_id,109,321 --exclude-regex sid\:109",
        'err_msg'   => "did not translate sid: $simple_sig_id",
        'positive_output_matches' => [qr/Found\ssid/,
            qr/Found\ssid\:\s321/,
            qr/Successful\stranslation/,
        ],
        'negative_output_matches' => [
            qr/Found\ssid\:\s109/,
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --no-ipt-test -c $default_conf --snort-sid $simple_sig_id,109,321 --exclude-regex sid\:109",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "--snort-sid $simple_sig_id,109,321 --include-regex sid\:109",
        'err_msg'   => "did not translate sid: $simple_sig_id",
        'positive_output_matches' => [qr/Found\ssid/,
            qr/Found\ssid\:\s109/,
            qr/Successful\stranslation/,
        ],
        'negative_output_matches' => [
            qr/Found\ssid\:\s321/,
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --no-ipt-test -c $default_conf --snort-sid $simple_sig_id,109,321 --include-regex sid\:109",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },

    ### ip6tables testing
    {
        'category'  => 'operations',
        'detail'    => "ip6tables --snort-sid $simple_sig_id",
        'err_msg'   => "did not translate sid: $simple_sig_id",
        'positive_output_matches' => [qr/Found\ssid\:\s$simple_sig_id/,
            qr/Successful\stranslation/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --ip6tables --no-ipt-test -c $default_conf --snort-sid $simple_sig_id",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "ip6tables  --snort-sid $simple_sig_id,109,321",
        'err_msg'   => "did not translate sid: $simple_sig_id",
        'positive_output_matches' => [qr/Found\ssid/,
            qr/Found\ssid\:\s109/,
            qr/Found\ssid\:\s321/,
            qr/Successful\stranslation/,
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --ip6tables --no-ipt-test -c $default_conf --snort-sid $simple_sig_id,109,321",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "ip6tables --snort-sid badsid",
        'err_msg'   => 'translated badsid signature',
        'positive_output_matches' => [
            qr/No\sSnort\srules\scould\sbe\stranslated/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --ip6tables --no-ipt-test -c $default_conf --snort-sid badsid",
        'exec_err'  => $YES,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "ip6tables --include-type backdoor",
        'err_msg'   => "did not translate backdoor signatures",
        'positive_output_matches' => [
            qr/backdoor\.rules/,
            qr/Generated\sip6tables\srules\sfor/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --ip6tables --no-ipt-test -c $default_conf --include-type backdoor",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "ip6tables --strict --include-type backdoor",
        'err_msg'   => "did not translate backdoor signatures",
        'positive_output_matches' => [
            qr/backdoor\.rules/,
            qr/Generated\sip6tables\srules\sfor/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --ip6tables --no-ipt-test -c $default_conf --strict --include-type backdoor",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "ip6tables --include-type emerging-all",
        'err_msg'   => "did not translate emerging-all signatures",
        'positive_output_matches' => [
            qr/emerging-all\.rules/,
            qr/Generated\sip6tables\srules\sfor/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --ip6tables --no-ipt-test -c $default_conf --include-type emerging-all",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },

    {
        'category'  => 'operations',
        'detail'    => "ip6tables --include-type backdoor,dns,ftp",
        'err_msg'   => "did not translate backdoor,dns,ftp signatures",
        'positive_output_matches' => [
            qr/backdoor\.rules/,
            qr/dns\.rules/,
            qr/ftp\.rules/,
            qr/Generated\sip6tables\srules\sfor/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --ip6tables --no-ipt-test -c $default_conf --include-type backdoor,dns,ftp",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "ip6tables --exclude-type emerging-all",
        'err_msg'   => "did not translate signatures",
        'positive_output_matches' => [
            qr/backdoor\.rules/,
            qr/dns\.rules/,
            qr/ftp\.rules/,
            qr/Generated\sip6tables\srules\sfor/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --ip6tables --no-ipt-test -c $default_conf --exclude-type emerging-all",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "ip6tables --ex... emerging-all,backdoor,dns,ftp",
        'err_msg'   => "did not translate signatures",
        'positive_output_matches' => [
            qr/chat\.rules/,
            qr/ddos\.rules/,
            qr/Generated\sip6tables\srules\sfor/
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --ip6tables --no-ipt-test -c $default_conf --exclude-type emerging-all,backdoor,dns,ftp",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "ip6tables --in.. backdoor,dns,ftp --ex.. dns",
        'err_msg'   => "did not translate backdoor,ftp signatures",
        'positive_output_matches' => [
            qr/backdoor\.rules/,
            qr/ftp\.rules/,
            qr/Generated\sip6tables\srules\sfor/
        ],
        'negative_output_matches' => [
            qr/dns\.rules/,
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --ip6tables --no-ipt-test -c $default_conf --include-type backdoor,dns,ftp --exclude-type dns",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "ip6tables --sn.. $simple_sig_id,109,321 --ex.. sid\:109",
        'err_msg'   => "did not translate sid: $simple_sig_id",
        'positive_output_matches' => [qr/Found\ssid/,
            qr/Found\ssid\:\s321/,
            qr/Successful\stranslation/,
        ],
        'negative_output_matches' => [
            qr/Found\ssid\:\s109/,
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --ip6tables --no-ipt-test -c $default_conf --snort-sid $simple_sig_id,109,321 --exclude-regex sid\:109",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },
    {
        'category'  => 'operations',
        'detail'    => "ip6tables --sn.. $simple_sig_id,109,321 --in.. sid\:109",
        'err_msg'   => "did not translate sid: $simple_sig_id",
        'positive_output_matches' => [qr/Found\ssid/,
            qr/Found\ssid\:\s109/,
            qr/Successful\stranslation/,
        ],
        'negative_output_matches' => [
            qr/Found\ssid\:\s321/,
        ],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&generic_exec,
        'cmdline'   => "$fwsnortCmd --ip6tables --no-ipt-test -c $default_conf --snort-sid $simple_sig_id,109,321 --include-regex sid\:109",
        'fw_exec'   => $fw_exec,
        'exec_err'  => $NO,
        'fatal'     => $NO
    },

    {
        'category'  => 'errors',
        'detail'    => 'look for perl warnings',
        'err_msg'   => 'found perl warnings',
        'negative_output_matches' => [qr/Use\sof\suninitialized\svalue/i,
            qr/Missing\sargument/,
            qr/Argument.*isn\'t\snumeric/],
        'match_all' => $MATCH_ALL_RE,
        'function'  => \&look_for_warnings,
        'cmdline'   => "grep -i uninit $output_dir/*.test",
        'exec_err'  => $IGNORE,
        'fatal'     => $NO
    },
);

### make sure everything looks as expected before continuing
&init();

&logr("\n[+] Starting the fwsnort test suite...\n\n" .
    "    args: @args_cp\n\n"
);

### save the results from any previous test suite run
### so that we can potentially compare them with --diff
if ($saved_last_results) {
    &logr("    Saved results from previous run " .
        "to: ${output_dir}.last/\n\n");
}

### main loop through all of the tests
for my $test_hr (@tests) {
    &run_test($test_hr);
}

&logr("\n[+] passed/failed/executed: $passed/$failed/$executed tests\n\n");

copy $logfile, "$output_dir/$logfile" or die $!;

exit 0;

#===================== end main =======================

sub run_test() {
    my $test_hr = shift;

    my $msg = "[$test_hr->{'category'}]";
    $msg .= " [$test_hr->{'subcategory'}]" if $test_hr->{'subcategory'};
    $msg .= " $test_hr->{'detail'}";

    return unless &process_include_exclude($msg);

    if ($list_mode) {
        print $msg, "\n";
        return;
    }

    &dots_print($msg);

    $executed++;
    $current_test_file  = "$output_dir/$executed.test";

    &write_test_file("[+] TEST: $msg\n");
    if (&{$test_hr->{'function'}}($test_hr)) {
        &logr("pass ($executed)\n");
        $passed++;
    } else {
        &logr("fail ($executed)\n");
        $failed++;

        if ($test_hr->{'fatal'} eq $YES) {
            die "[*] required test failed, exiting.";
        }
    }

    return;
}

sub look_for_warnings() {
    my $test_hr = shift;

    my $orig_test_file = $current_test_file;

    $current_test_file = "$output_dir/grep.output";

    my $rv = &generic_exec($test_hr);

    copy $current_test_file, $orig_test_file;
    unlink $current_test_file;

    return $rv;
}

sub install_test_dir() {
    my $test_hr = shift;

    my $rv = 1;
    my $curr_pwd = cwd() or die $!;

    if (-d $test_install_dir) {
        rmtree $test_install_dir or die $!;
    }
    mkdir $test_install_dir  or die $!;

    chdir '..' or die $!;

    my $exec_rv = &run_cmd($test_hr->{'cmdline'},
                "test/$cmd_out_tmp", "test/$current_test_file");

    if ($test_hr->{'exec_err'} eq $YES) {
        $rv = 0 if $exec_rv;
    } elsif ($test_hr->{'exec_err'} eq $NO) {
        $rv = 0 unless $exec_rv;
    } else {
        $rv = 1;
    }

    if ($test_hr->{'positive_output_matches'}) {
        $rv = 0 unless &file_find_regex(
            $test_hr->{'positive_output_matches'},
            $test_hr->{'match_all'},
            $current_test_file);
    }

    if ($test_hr->{'negative_output_matches'}) {
        $rv = 0 if &file_find_regex(
            $test_hr->{'negative_output_matches'},
            $test_hr->{'match_all'},
            $current_test_file);
    }

    chdir $curr_pwd or die $!;

    return $rv;
}

sub generic_exec() {
    my $test_hr = shift;

    my $rv = 1;

    my $exec_rv = &run_cmd($test_hr->{'cmdline'},
                $cmd_out_tmp, $current_test_file);

    if ($test_hr->{'exec_err'} eq $YES) {
        $rv = 0 if $exec_rv;
    } elsif ($test_hr->{'exec_err'} eq $NO) {
        $rv = 0 unless $exec_rv;
    } else {
        $rv = 1;
    }

    if ($test_hr->{'positive_output_matches'}) {
        $rv = 0 unless &file_find_regex(
            $test_hr->{'positive_output_matches'},
            $test_hr->{'match_all'},
            $current_test_file);
    }

    if ($test_hr->{'negative_output_matches'}) {
        $rv = 0 if &file_find_regex(
            $test_hr->{'negative_output_matches'},
            $test_hr->{'match_all'},
            $current_test_file);
    }

    if ($test_hr->{'fw_exec'} eq $YES) {
        if (-e $fwsnort_sh) {
            $rv = 0 unless &run_cmd($fwsnort_sh, $cmd_out_tmp, $current_test_file);
            if ($test_hr->{'detail'} =~ /ip6tables/) {
                $rv = 0 unless &run_cmd("$fwsnortCmd --ipt-list --ip6tables",
                        $cmd_out_tmp, $current_test_file);
            } else {
                $rv = 0 unless &run_cmd("$fwsnortCmd --ipt-list", $cmd_out_tmp, $current_test_file);
            }
            $rv = 0 unless &run_cmd("$fwsnort_sh -r", $cmd_out_tmp, $current_test_file);
        } else {
            &write_test_file("[-] $fwsnort_sh script does not exist.\n");
        }
    }

    return $rv;
}

sub run_cmd() {
    my ($cmd, $cmd_out, $file) = @_;

    if (-e $file) {
        open F, ">> $file"
            or die "[*] Could not open $file: $!";
        print F localtime() . " CMD: $cmd\n";
        close F;
    } else {
        open F, "> $file"
            or die "[*] Could not open $file: $!";
        print F localtime() . " CMD: $cmd\n";
        close F;
    }

    my $rv = ((system "$cmd > $cmd_out 2>&1") >> 8);

    open C, "< $cmd_out" or die "[*] Could not open $cmd_out: $!";
    my @cmd_lines = <C>;
    close C;

    open F, ">> $file" or die "[*] Could not open $file: $!";
    print F $_ for @cmd_lines;
    close F;

    if ($rv == 0) {
        return 1;
    }
    return 0;
}

sub file_find_regex() {
    my ($re_ar, $match_all_flag, $file) = @_;

    my @write_lines = ();
    my @file_lines  = ();

    open F, "< $file" or die "[*] Could not open $file: $!";
    while (<F>) {
        push @file_lines, $_;
    }
    close F;

    my $found = 0;
    RE: for my $re (@$re_ar) {
        $found = 0;
        LINE: for my $line (@file_lines) {
            next LINE if $line =~ /file_file_regex\(\)/;
            if ($line =~ $re) {
                push @write_lines, "[.] file_find_regex() " .
                    "Matched '$re' with line: $line (file: $file)\n";
                $found = 1;
                last LINE;
            }
        }
        if ($found) {
            if ($match_all_flag == $MATCH_SINGLE_RE) {
                last RE;
            }
        } else {
            push @write_lines, "[.] file_find_regex() " .
                "did not match '$re' (file: $file)\n";
            if ($match_all_flag == $MATCH_ALL_RE) {
                last RE;
            }
        }
    }

    for my $line (@write_lines) {
        &write_test_file($line);
    }

    return $found;
}

sub dots_print() {
    my $msg = shift;
    &logr($msg);
    my $dots = '';
    for (my $i=length($msg); $i < $PRINT_LEN; $i++) {
        $dots .= '.';
    }
    &logr($dots);
    return;
}

sub init() {

    $|++; ### turn off buffering

    $< == 0 and $> == 0 or
        die "[*] $0: You must be root (or equivalent ",
            "UID 0 account) to effectively test fwsnort";

    ### validate test hashes
    my $hash_num = 0;
    for my $test_hr (@tests) {
        for my $key (keys %test_keys) {
            if ($test_keys{$key} == $REQUIRED) {
                die "[*] Missing '$key' element in hash: $hash_num"
                    unless defined $test_hr->{$key};
            } else {
                $test_hr->{$key} = '' unless defined $test_hr->{$key};
            }
        }
        $hash_num++;
    }

    die "[*] $conf_dir directory does not exist." unless -d $conf_dir;
    die "[*] default config $default_conf does not exist" unless -e $default_conf;

    if (-d $output_dir) {
        if (-d "${output_dir}.last") {
            rmtree "${output_dir}.last"
                or die "[*] rmtree ${output_dir}.last $!";
        }
        mkdir "${output_dir}.last"
            or die "[*] ${output_dir}.last: $!";
        for my $file (glob("$output_dir/*.test")) {
            if ($file =~ m|.*/(.*)|) {
                copy $file, "${output_dir}.last/$1" or die $!;
            }
        }
        if (-e "$output_dir/init") {
            copy "$output_dir/init", "${output_dir}.last/init";
        }
        if (-e $logfile) {
            copy $logfile, "${output_dir}.last/$logfile" or die $!;
        }
        $saved_last_results = 1;
    } else {
        mkdir $output_dir or die "[*] Could not mkdir $output_dir: $!";
    }
    unless (-d $run_dir) {
        mkdir $run_dir or die "[*] Could not mkdir $run_dir: $!";
    }

    for my $file (glob("$output_dir/*.test")) {
        unlink $file or die "[*] Could not unlink($file)";
    }
    if (-e "$output_dir/init") {
        unlink "$output_dir/init" or die $!;
    }

    if (-e $logfile) {
        unlink $logfile or die $!;
    }

    if ($test_include) {
        @tests_to_include = split /\s*,\s*/, $test_include;
    }
    if ($test_exclude) {
        @tests_to_exclude = split /\s*,\s*/, $test_exclude;
    }

    return;
}

sub process_include_exclude() {
    my $msg = shift;

    ### inclusions/exclusions
    if (@tests_to_include) {
        my $found = 0;
        for my $test (@tests_to_include) {
            if ($msg =~ /$test/) {
                $found = 1;
                last;
            }
        }
        return 0 unless $found;
    }
    if (@tests_to_exclude) {
        my $found = 0;
        for my $test (@tests_to_exclude) {
            if ($msg =~ /$test/) {
                $found = 1;
                last;
            }
        }
        return 0 if $found;
    }
    return 1;
}

sub write_test_file() {
    my $msg = shift;

    if (-e $current_test_file) {
        open F, ">> $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        print F $msg;
        close F;
    } else {
        open F, "> $current_test_file"
            or die "[*] Could not open $current_test_file: $!";
        print F $msg;
        close F;
    }
    return;
}

sub logr() {
    my $msg = shift;
    print STDOUT $msg;
    open F, ">> $logfile" or die $!;
    print F $msg;
    close F;
    return;
}

sub usage() {
    ### FIXME
}
