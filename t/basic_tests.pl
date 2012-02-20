#!/usr/bin/perl -w

use lib '../lib';
use Data::Dumper;
use strict;

require IPTables::Parse;

#==================== config =====================
my $iptables_bin  = '/sbin/iptables';
my $ip6tables_bin = '/sbin/ip6tables';

my $logfile   = 'test.log';
my $PRINT_LEN = 68;
#================== end config ===================

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
    my %opts = (
        'iptables' => $iptables_bin,
        'iptout'   => '/tmp/iptables.out',
        'ipterr'   => '/tmp/iptables.err',
        'debug'    => 0,
        'verbose'  => 0
    );

    my $ipt_obj = new IPTables::Parse(%opts)
        or die "[*] Could not acquire IPTables::Parse object";

    &chain_policy_tests($ipt_obj, \%iptables_chains);
    &chain_rules_tests($ipt_obj, \%iptables_chains);
    &default_log_tests($ipt_obj);
    &default_drop_tests($ipt_obj);

    return;
}

sub ip6tables_tests() {

    &logr("\n[+] Running $ip6tables_bin tests...\n");
    my %opts = (
        'iptables' => $ip6tables_bin,
        'iptout'   => '/tmp/ip6tables.out',
        'ipterr'   => '/tmp/ip6tables.err',
        'debug'    => 0,
        'verbose'  => 0
    );

    my $ipt_obj = new IPTables::Parse(%opts)
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

        my $ipt_log = $ipt_obj->default_log('filter', $chain);
        $executed++;
        if ($ipt_log) {
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
        &dots_print("default_log(): filter $chain");

        my $ipt_drop = $ipt_obj->default_drop('filter', $chain);
        $executed++;
        if ($ipt_drop) {
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
        for my $chain (@{$tables_chains_hr->{$table}}) {
            &dots_print("chain_rules(): $table $chain rules");

            my ($rv, $out_ar, $err_ar) = $ipt_obj->exec_iptables(
                "$ipt_obj->{'_iptables'} -t $table -v -n -L $chain");

            my $rules_ar = $ipt_obj->chain_rules($table, $chain);

            ### compare raw rules list with parsed chain_rules()
            ### output - basic number check
            $executed++;

            if (($#$out_ar - 2) == $#$rules_ar) {
                &logr("pass ($executed)\n");
                $passed++;
            } else {
                &logr("fail ($executed)\n");
                if (($#$out_ar - 2) > $#$rules_ar) {
                    &logr("    chain_rules() missed rules.\n");
                } elsif (($#$out_ar - 2) < $#$rules_ar) {
                    &logr("    chain_rules() added inappropriate rules.\n");
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
    for my $bin ($iptables_bin, $ip6tables_bin) {
        die "[*] $bin does not exist" unless -e $bin;
        die "[*] $bin not executable" unless -x $bin;
    }

    return;
}
