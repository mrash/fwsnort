#!/usr/bin/perl -w
#
#######################################################################
#
# File: install.pl
#
# Purpose: This is the installation script for fwsnort.
#
# Author: Michael Rash <mbr@cipherydne.com>
#
# License (GNU Public License):
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
#    USA
#
# TODO:
#   - Write the uninstall() routine. :)
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
my $perlCmd = '/usr/bin/perl';
my $makeCmd = '/usr/bin/make';
my $gzipCmd = '/bin/gzip';
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

die " ** Cannot both install and unistall.  Exiting."
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
    chdir 'Net-IPv4Addr' or die " ** Could not chdir to ",
        "Net-IPv4Addr: $!";
    unless (-e 'Makefile.PL' && -e 'IPv4Addr.pm') {
        die " ** Your Net::IPv4Addr sources are incomplete!";
    }
    system "$perlCmd Makefile.PL";
    system $makeCmd;
    system "$makeCmd test";
    system "$makeCmd install";
    chdir '..';

    ### installing IPTables::Parse
    print " .. Installing the IPTables::Parse perl module\n";
    chdir 'IPTables/Parse' or die " ** Could not chdir to ",
        "IPTables/Parse: $!";
    unless (-e 'Makefile.PL') {
        die " ** Your source directory appears to be incomplete!  " .
            "IPTables::Parse is missing.\n    Download the latest sources " .
            "from http://www.cipherdyne.org\n";
    }
    system "$perlCmd Makefile.PL";
    system $makeCmd;
#    system "$Cmds{'make'} test";
    system "$makeCmd install";
    chdir '../..';
    print "\n\n";

    opendir D, 'snort_rules' or die " ** Could not open " .
        'the snort_rules directory';
    my @rfiles = readdir D;
    closedir D;
    shift @rfiles; shift @rfiles;
    print " .. Copying all rules files to $rules_dir\n";
    for my $rfile (@rfiles) {
        next unless $rfile =~ /\.rules$/;
        print " .. Installing $rfile\n";
        copy "snort_rules/${rfile}", "${rules_dir}/${rfile}";
    }

    print "\n";

    ### install the fwsnort.8 man page
    &install_manpage();

    print " .. Copying fwsnort.conf -> ${fwsnort_dir}/fwsnort.conf\n";
    copy 'fwsnort.conf', "${fwsnort_dir}/fwsnort.conf";
    chmod 0600, "${fwsnort_dir}/fwsnort.conf";

    print " .. Copying fwsnort -> ${sbin_dir}/fwsnort\n";
    copy 'fwsnort', "${sbin_dir}/fwsnort";
    chmod 0500, "${sbin_dir}/fwsnort";

    print "\n========================================================\n",
        "\n .. fwsnort will generate an iptables script located at:\n",
        "    /etc/fwsnort/fwsnort.sh when executed.\n",
        "\n .. fwsnort has been successfully installed!\n\n";

    return;
}

sub uninstall() {
    ### FIXME
    return;
}

sub install_manpage() {
    my $manpage = 'fwsnort.8';
    ### remove old man page
    unlink "/usr/local/man/man8/${manpage}" if
        (-e "/usr/local/man/man8/${manpage}");

    ### default location to put the psad man page, but check with
    ### /etc/man.config
    my $mpath = '/usr/share/man/man8';
    if (-e '/etc/man.config') {
        ### prefer to install $manpage in /usr/local/man/man8 if
        ### this directory is configured in /etc/man.config
        open M, '< /etc/man.config' or
            die " ** Could not open /etc/man.config: $!";
        my @lines = <M>;
        close M;
        ### prefer the path "/usr/share/man"
        my $found = 0;
        for my $line (@lines) {
            chomp $line;
            if ($line =~ m|^MANPATH\s+/usr/share/man|) {
                $found = 1;
                last;
            }
        }
        ### try to find "/usr/local/man" if we didn't find /usr/share/man
        unless ($found) {
            for my $line (@lines) {
                chomp $line;
                if ($line =~ m|^MANPATH\s+/usr/local/man|) {
                    $mpath = '/usr/local/man/man8';
                    $found = 1;
                    last;
                }
            }
        }
        ### if we still have not found one of the above man paths,
        ### just select the first one out of /etc/man.config
        unless ($found) {
            for my $line (@lines) {
                chomp $line;
                if ($line =~ m|^MANPATH\s+(\S+)|) {
                    $mpath = $1;
                    last;
                }
            }
        }
    }
    mkdir $mpath, 0755 unless -d $mpath;
    my $mfile = "${mpath}/${manpage}";
    print " .. Installing $manpage man page as $mfile\n";
    copy $manpage, $mfile or die " ** Could not copy $manpage to " .
        "$mfile: $!";
    chmod 0644, $mfile;
    print " .. Compressing manpage $mfile\n";
    ### remove the old one so gzip doesn't prompt us
    unlink "${mfile}.gz" if -e "${mfile}.gz";
    system "$gzipCmd $mfile";
    return;
}

sub usage() {
    my $exit = shift;
    print <<_HELP_;
install.pl:
    -i --install     - install fwsnort
    -u --uninstall   - uninstall fwsnort
    -h --help        - print help and exit
_HELP_
    exit $exit;
}
