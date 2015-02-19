#!/usr/bin/perl -w

use lib '../lib';
use Data::Dumper;
use Getopt::Long 'GetOptions';
use strict;

require IPTables::Parse;

#==================== config =====================
my $iptables_bin    = '/sbin/iptables';
my $ip6tables_bin   = '/sbin/ip6tables';
my $fw_cmd_bin      = '/bin/firewall-cmd';

my $logfile   = 'test.log';
my $PRINT_LEN = 68;
#================== end config ===================

my $verbose = 0;
my $debug   = 0;
my $help    = 0;

die "[*] See 'psad -h' for usage information" unless (GetOptions(
    'verbose' => \$verbose,
    'debug'   => \$debug,
    'help'    => \$help,
));
&usage() if $help;

my %ipt_opts = (
    'iptables' => $iptables_bin,
    'iptout'   => '/tmp/iptables.out',
    'ipterr'   => '/tmp/iptables.err',
    'debug'    => $debug,
    'verbose'  => $verbose
);

my %ipt6_opts = (
    'iptables' => $ip6tables_bin,
    'iptout'   => '/tmp/iptables.out',
    'ipterr'   => '/tmp/iptables.err',
    'debug'    => $debug,
    'verbose'  => $verbose
);

my %targets = (
    'ACCEPT' => '',
    'DROP'   => '',
    'QUEUE'  => '',
    'RETURN' => '',
);

my %iptables_chains = (
    'mangle' => [qw/PREROUTING INPUT OUTPUT FORWARD POSTROUTING/],
    'raw'    => [qw/PREROUTING OUTPUT/],
    'filter' => [qw/INPUT OUTPUT FORWARD/],
    'nat'    => [qw/PREROUTING OUTPUT POSTROUTING/]
);

my %ip6tables_chains = (
    'mangle' => [qw/PREROUTING INPUT OUTPUT FORWARD POSTROUTING/],
    'raw'    => [qw/PREROUTING OUTPUT/],
    'filter' => [qw/INPUT OUTPUT FORWARD/],
);

my $passed = 0;
my $failed = 0;
my $executed = 0;

&init();

&iptables_tests();
&ip6tables_tests();

&logr("\n[+] passed/failed/executed: $passed/$failed/$executed tests\n\n");

exit 0;

sub iptables_tests() {

    &logr("[+] Running $iptables_bin tests...\n");

    my $ipt_obj = new IPTables::Parse(%ipt_opts)
        or die "[*] Could not acquire IPTables::Parse object";

    &chain_policy_tests($ipt_obj, \%iptables_chains);
    &chain_rules_tests($ipt_obj, \%iptables_chains);
    &default_log_tests($ipt_obj);
    &default_drop_tests($ipt_obj);

    return;
}

sub ip6tables_tests() {

    &logr("\n[+] Running $ip6tables_bin tests...\n");

    my $ipt_obj = new IPTables::Parse(%ipt6_opts)
        or die "[*] Could not acquire IPTables::Parse object";

    &chain_policy_tests($ipt_obj, \%ip6tables_chains);
    &chain_rules_tests($ipt_obj, \%ip6tables_chains);
    &default_log_tests($ipt_obj);
    &default_drop_tests($ipt_obj);

    return;
}

sub default_log_tests() {
    my $ipt_obj = shift;

    for my $chain (qw/INPUT OUTPUT FORWARD/) {
        &dots_print("default_log(): filter $chain");

        my ($ipt_log, $rv) = $ipt_obj->default_log('filter', $chain);
        $executed++;
        if ($rv) {
            &logr("pass ($executed) (found)\n");
            $passed++;
        } else {
            &logr("fail ($executed) (not found)\n");
            $failed++;
        }
    }
    return;
}

sub default_drop_tests() {
    my $ipt_obj = shift;

    for my $chain (qw/INPUT OUTPUT FORWARD/) {
        &dots_print("default_drop(): filter $chain");

        my ($ipt_drop, $rv) = $ipt_obj->default_drop('filter', $chain);
        $executed++;
        if ($rv) {
            &logr("pass ($executed) (found)\n");
            $passed++;
        } else {
            &logr("fail ($executed) (not found)\n");
            $failed++;
        }
    }
    return;
}

sub chain_policy_tests() {
    my ($ipt_obj, $tables_chains_hr) = @_;

    for my $table (keys %$tables_chains_hr) {
        for my $chain (@{$tables_chains_hr->{$table}}) {
            &dots_print("chain_policy(): $table $chain policy");

            my $target = $ipt_obj->chain_policy($table, $chain);

            $executed++;

            if (defined $targets{$target}) {
                &logr("pass ($executed) ($target)\n");
                $passed++;
            } else {
                &logr("fail ($executed) ($target)\n");
                &logr("   Unrecognized target '$target'\n");
                $failed++;
            }
        }
    }

    return;
}

sub chain_rules_tests() {
    my ($ipt_obj, $tables_chains_hr) = @_;

    for my $table (keys %$tables_chains_hr) {

        &dots_print("list_table_chains(): $table");

        my $chains_ar = $ipt_obj->list_table_chains($table);
        if ($#$chains_ar > -1) {
            &logr("pass ($executed)\n");
            $passed++;
        } else {
            &logr("fail ($executed)\n");
            $failed++;
        }
        $executed++;

        for my $chain (@{$tables_chains_hr->{$table}}) {
            &dots_print("chain_rules(): $table $chain rules");

            my ($rv, $out_ar, $err_ar) = $ipt_obj->exec_iptables(
                "$ipt_obj->{'_cmd'} -t $table -v -n -L $chain");

            my $rules_ar = $ipt_obj->chain_rules($table, $chain);

            $executed++;

            my $matched_state = 1;
            for (my $i=2; $i<=$#$out_ar; $i++) {
                if ($out_ar->[$i] =~ /\sctstate/) {
                    unless (defined $rules_ar->[$i-2]->{'ctstate'}
                            and $rules_ar->[$i-2]->{'ctstate'}) {
                        $matched_state = 0;
                        last;
                    }
                } elsif ($out_ar->[$i] =~ /\sstate/) {
                    unless (defined $rules_ar->[$i-2]->{'state'}
                            and $rules_ar->[$i-2]->{'state'}) {
                        $matched_state = 0;
                        last;
                    }
                }
            }

            ### compare raw rules list with parsed chain_rules()
            ### output - basic number check
            if (($#$out_ar - 2) == $#$rules_ar and $matched_state) {
                &logr("pass ($executed)\n");
                $passed++;
            } else {
                &logr("fail ($executed)\n");
                if ($matched_state) {
                    &logr("    chain_rules() missed extended state info.\n");
                } else {
                    if (($#$out_ar - 2) > $#$rules_ar) {
                        &logr("    chain_rules() missed rules.\n");
                    } elsif (($#$out_ar - 2) < $#$rules_ar) {
                        &logr("    chain_rules() added inappropriate rules.\n");
                    }
                }
                $failed++;
            }
        }
    }

    return;
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

sub logr() {
    my $msg = shift;
    print STDOUT $msg;
    open F, ">> $logfile" or die $!;
    print F $msg;
    close F;
    return;
}

sub init() {

    $|++; ### turn off buffering

    $< == 0 && $> == 0 or
        die "[*] $0: You must be root (or equivalent ",
            "UID 0 account) to effectively test fwknop";

    unlink $logfile if -e $logfile;

    if (-e $fw_cmd_bin and -x $fw_cmd_bin) {
        $ipt_opts{'firewall-cmd'}  = $fw_cmd_bin;
        $ipt6_opts{'firewall-cmd'} = $fw_cmd_bin;
        $ipt6_opts{'use_ipv6'}     = 1;
    } else {
        for my $bin ($iptables_bin, $ip6tables_bin) {
            die "[*] $bin does not exist" unless -e $bin;
            die "[*] $bin not executable" unless -x $bin;
        }
    }

    return;
}

sub usage() {
    print "$0 [--debug] [--verbose] [-h]\n";
    exit 0;
}
