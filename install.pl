#!/usr/bin/perl -w
#
#######################################################################
#
# File: install.pl
#
# Purpose: To install fwsnort
#
# Author: Michael Rash <mbr@cipherydne.com>
#
# License: GPL
#
#######################################################################
#
# $Id$
#

use File::Copy;
use Getopt::Long;
use strict;

#========================= config ========================
my $sbin_dir    = '/usr/sbin';
my $fwsnort_dir = '/etc/fwsnort';
my $rules_dir   = "${fwsnort_dir}/snort-1.8.7_rules";

### system binaries
my $perlCmd = '/usr/bin/perl';
my $makeCmd = '/usr/bin/make';
#======================= end config ======================

### establish some defaults
my $install   = 1;
my $uninstall = 0;
my $help      = 0;

&usage(1) unless (GetOptions(
    'install'   => \$install,  ### default mode (already enabled)
    'uninstall' => \$uninstall, ### uninstall fwsnort
    'help'      => \$help
));

&usage(0) if $help;

die " ** Cannot install and unistall.  Exiting."
    if $install && $uninstall;

die " ** \"$perlCmd\" is not executable." unless -x $perlCmd;
die " ** \"$makeCmd\" is not executable." unless -x $makeCmd;

### check to make sure we are running as root
$< == 0 && $> == 0 or die "You need to be root (or equivalent UID 0" .
    " account) to install/uninstall fwsnort!\n";

&uninstall() if $uninstall;
&install()   if $install;

exit 0;
#===================== end main ===================

sub install() {
    die " ** You must run install.pl from the fwsnort " .
        "sources directory." unless -e 'fwsnort' && -e 'fwsnort.conf';

    unless (-d $fwsnort_dir) {
        print " .. mkdir $fwsnort_dir\n";
        mkdir $fwsnort_dir, 0500;
    }
    unless (-d $rules_dir) {
        print " .. mkdir $rules_dir\n";
        mkdir $rules_dir, 0500;
    }

    ### install Net::IPv4Addr
    print " .. Installing the Net::IPv4Addr perl module.\n";
    chdir 'Net-IPv4Addr-0.10' or die " ** Could not chdir to ",
        "Net-IPv4Addr-0.10: $!";
    unless (-e 'Makefile.PL' && -e 'IPv4Addr.pm') {
        die " ** Your Net::IPv4Addr sources are incomplete!";
    }
    system "$perlCmd Makefile.PL";
    system $makeCmd;
    system "$makeCmd test";
    system "$makeCmd install";
    chdir '..';

    opendir D, 'snort-1.8.7_rules' or die " ** Could not open " .
        'the snort-1.8.7_rules directory';
    my @rfiles = readdir D;
    closedir D;
    shift @rfiles; shift @rfiles;
    for my $rfile (@rfiles) {
        next unless $rfile =~ /\.rules$/;
        print " .. Copying snort-1.8.7_rules/${rfile} " .
            "-> ${rules_dir}/${rfile}\n";
        copy "snort-1.8.7_rules/${rfile}", "${rules_dir}/${rfile}";
    }

    print " .. Copying fwsnort.conf -> ${fwsnort_dir}/fwsnort.conf\n";
    copy 'fwsnort.conf', "${fwsnort_dir}/fwsnort.conf";
    chmod 0600, "${fwsnort_dir}/fwsnort.conf";

    print " .. Copying fwsnort -> ${sbin_dir}/fwsnort\n";
    copy 'fwsnort', "${sbin_dir}/fwsnort";
    chmod 0500, "${sbin_dir}/fwsnort";

    return;
}

sub uninstall() {

    return;
}

sub usage() {
    my $exit = shift;

    exit $exit;
}
