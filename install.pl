#!/usr/bin/perl -w
#
#######################################################################
#
# File: install.pl
#
# Purpose: To install fwsnort
#
# Author: Michael B. Rash <mbr@cipherydne.com>
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
my $rules_dir   = "${fwsnort_dir}/snort_rules";

### system binaries
my $iptablesCmd = '/sbin/iptables';
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

### check to make sure we are running as root
$< == 0 && $> == 0 or die "You need to be root (or equivalent UID 0" .
    " account) to install/uninstall fwsnort!\n";

&uninstall() if $uninstall;
&install()   if $install;

exit 0;
#===================== end main ===================

sub install() {
    die " ** You must run install.pl from the fwsnort " .
        "sources directory." unless -e 'fwsnort';

    unless (-d $fwsnort_dir) {
        print " .. mkdir $fwsnort_dir\n";
        mkdir $fwsnort_dir, 0500;
    }
    unless (-d $rules_dir) {
        print " .. mkdir $rules_dir\n";
        mkdir $rules_dir, 0500
    }

    opendir D, 'snort_rules' or die " ** Could not open " .
        "the snort_rules directory";
    my @rfiles = readdir D;
    closedir D;
    shift @rfiles; shift @rfiles;
    for my $rfile (@rfiles) {
        next unless $rfile =~ /\.rules$/;
        print " .. Copying snort_rules/${rfile} " .
            "-> ${rules_dir}/${rfile}\n";
        copy "snort_rules/${rfile}", "${rules_dir}/${rfile}";
    }

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
