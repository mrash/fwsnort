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

use IO::Socket;
use File::Copy;
use File::Path;
use Getopt::Long;
use strict;

#========================= config ========================
my $sbin_dir    = '/usr/sbin';
my $lib_dir     = '/usr/lib/fwsnort';
my $fwsnort_dir = '/etc/fwsnort';
my $rules_dir   = "${fwsnort_dir}/snort_rules";

### Snort.org no longer allows auto downloads of signatures
my $bleeding_snort_website = 'www.bleedingsnort.com';

### system binaries
my $perlCmd = '/usr/bin/perl';
my $makeCmd = '/usr/bin/make';
my $wgetCmd = '/usr/bin/wget';
my $gzipCmd = '/bin/gzip';
my $tarCmd  = '/bin/tar';
#======================= end config ======================

### establish some defaults
my $uninstall = 0;
my $help      = 0;

my %cmds = (
    'perl' => $perlCmd,
    'make' => $makeCmd,
    'gzip' => $gzipCmd,
    'wget' => $wgetCmd,
    'tar'  => $tarCmd
);

&usage(1) unless (GetOptions(
    'uninstall' => \$uninstall, ### uninstall fwsnort
    'help'      => \$help
));

&usage(0) if $help;

### make sure the system binaries are where we think they are.
&check_commands();

### check to make sure we are running as root
$< == 0 && $> == 0 or die "You need to be root (or equivalent UID 0",
    " account) to install/uninstall fwsnort!\n";

if ($uninstall) {
    &uninstall();
} else {
    &install()
}
exit 0;
#===================== end main ===================

sub install() {
    die "[*] You must run install.pl from the fwsnort " .
        "sources directory." unless -e 'fwsnort' and -e 'fwsnort.conf';

    unless (-d $fwsnort_dir) {
        print "[+] mkdir $fwsnort_dir\n";
        mkdir $fwsnort_dir, 0500;
    }
    unless (-d $rules_dir) {
        print "[+] mkdir $rules_dir\n";
        mkdir $rules_dir, 0500;
    }
    unless (-d $lib_dir) {
        print "[+] mkdir $lib_dir\n";
        mkdir $lib_dir, 0755;
    }

    ### install Net::IPv4Addr
    print "[+] Installing the Net::IPv4Addr perl module in $lib_dir/.\n";
    chdir 'Net-IPv4Addr' or die "[*] Could not chdir to ",
        "Net-IPv4Addr: $!";
    unless (-e 'Makefile.PL' && -e 'IPv4Addr.pm') {
        die "[*] Your Net::IPv4Addr sources are incomplete!";
    }
    system "$perlCmd Makefile.PL PREFIX=$lib_dir LIB=$lib_dir";
    system $makeCmd;
#    system "$makeCmd test";
    system "$makeCmd install";
    chdir '..';

    ### installing IPTables::Parse
    print "[+] Installing the IPTables::Parse perl module in $lib_dir/\n";
    chdir 'IPTables/Parse' or die "[*] Could not chdir to ",
        "IPTables/Parse: $!";
    unless (-e 'Makefile.PL') {
        die "[*] Your source directory appears to be incomplete!  " .
            "IPTables::Parse is missing.\n    Download the latest sources " .
            "from http://www.cipherdyne.org\n";
    }
    system "$perlCmd Makefile.PL PREFIX=$lib_dir LIB=$lib_dir";
    system $makeCmd;
#    system "$Cmds{'make'} test";
    system "$makeCmd install";
    chdir '../..';
    print "\n\n";

    my $local_rules_dir = 'snort_rules';
    if (&query_get_bleeding_snort()) {
        chdir $local_rules_dir or die "[*] Could not chdir $local_rules_dir";
        if (-e 'bleeding-all.rules') {
            move 'bleeding-all.rules', 'bleeding-all.rules.tmp'
                or die "[*] Could not move bleeding-all.rules -> ",
                "bleeding-all.rules.tmp";
        }
        system "$cmds{'wget'} http://$bleeding_snort_website/bleeding-all.rules";
        if (-e 'bleeding-all.rules') {  ### successful download
            unlink 'bleeding-all.rules.tmp';
        } else {
            print "[-] Could not download bleeding-all.rules file.\n";
            if (-e 'bleeding-all.rules.tmp') {
                ### move the original back
                move 'bleeding-all.rules', 'bleeding-all.rules.tmp'
                    or die "[*] Could not move bleeding-all.rules -> ",
                    "bleeding-all.rules.tmp";
            }
        }
        chdir '..';
    }

    opendir D, $local_rules_dir or die "[*] Could not open ",
        "the $local_rules_dir directory: $!";
    my @rfiles = readdir D;
    closedir D;
    shift @rfiles; shift @rfiles;
    print "[+] Copying all rules files to $rules_dir\n";
    for my $rfile (@rfiles) {
        next unless $rfile =~ /\.rules$/;
        print "[+] Installing $rfile\n";
        copy "snort_rules/${rfile}", "${rules_dir}/${rfile}" or
            die "[*] Could not copy snort_rules/${rfile} ",
                "-> ${rules_dir}/${rfile}";
    }

    print "\n";

    ### install the fwsnort.8 man page
    &install_manpage();

    my $preserve_rv = 0;
    if (-e "${fwsnort_dir}/fwsnort.conf") {
        $preserve_rv = &query_preserve_config();
    }

    if ($preserve_rv) {
        &preserve_config();
    } else {
        print "[+] Copying fwsnort.conf -> ${fwsnort_dir}/fwsnort.conf\n";
        copy 'fwsnort.conf', "${fwsnort_dir}/fwsnort.conf";
        chmod 0600, "${fwsnort_dir}/fwsnort.conf";
    }

    print "[+] Copying fwsnort -> ${sbin_dir}/fwsnort\n";
    copy 'fwsnort', "${sbin_dir}/fwsnort";
    chmod 0500, "${sbin_dir}/fwsnort";

    print "\n========================================================\n",
        "\n[+] fwsnort will generate an iptables script located at:\n",
        "    /etc/fwsnort/fwsnort.sh when executed.\n",
        "\n[+] fwsnort has been successfully installed!\n\n";

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

    ### default location to put the fwsnort man page, but check with
    ### /etc/man.config
    my $mpath = '/usr/share/man/man8';
    if (-e '/etc/man.config') {
        ### prefer to install $manpage in /usr/local/man/man8 if
        ### this directory is configured in /etc/man.config
        open M, '< /etc/man.config' or
            die "[*] Could not open /etc/man.config: $!";
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
    print "[+] Installing $manpage man page as $mfile\n";
    copy $manpage, $mfile or die "[*] Could not copy $manpage to " .
        "$mfile: $!";
    chmod 0644, $mfile;
    print "[+] Compressing manpage $mfile\n";
    ### remove the old one so gzip doesn't prompt us
    unlink "${mfile}.gz" if -e "${mfile}.gz";
    system "$gzipCmd $mfile";
    return;
}

sub query_get_bleeding_snort() {
    my $ans = '';
    print "[+] Would you like to download the latest Snort rules from \n",
        "    http://$bleeding_snort_website/?\n";
    while ($ans ne 'y' && $ans ne 'n') {
        print "    ([y]/n)?  ";
        $ans = <STDIN>;
        return 1 if $ans eq "\n";
        chomp $ans;
    }
    if ($ans eq 'y') {
        return 1;
    }
    return 0;
}

sub check_commands() {
    my @path = qw(
        /bin
        /usr/bin
        /usr/local/bin
    );
    CMD: for my $cmd (keys %cmds) {
        unless (-x $cmds{$cmd}) {
            my $found = 0;
            PATH: for my $dir (@path) {
                if (-x "${dir}/${cmd}") {
                    $cmds{$cmd} = "${dir}/${cmd}";
                    $found = 1;
                    last PATH;
                }
            }
            unless ($found) {
                die "[*] Could not find $cmd, edit the ",
                    "config section of install.pl";
            }
        }
    }

    return;
}

sub query_preserve_config() {
    my $ans = '';
    while ($ans ne 'y' && $ans ne 'n') {
        print "[+] Would you like to preserve the config from the\n",
            '    existing fwsnort installation ([y]/n)?  ';
        $ans = <STDIN>;
        return 1 if $ans eq "\n";
        chomp $ans;
    }
    if ($ans eq 'y') {
        return 1;
    }
    return 0;
}

sub preserve_config() {
    my $file = 'fwsnort.conf';
    open C, "< $file" or die "[*] Could not open $file: $!";
    my @new_lines = <C>;
    close C;

    open CO, "< ${fwsnort_dir}/$file" or die "[*] Could not open ",
        "${fwsnort_dir}/$file: $!";
    my @orig_lines = <CO>;
    close CO;

    print "[+] Preserving existing config: ${fwsnort_dir}/$file\n";
    ### write to a tmp file and then move.
    open CONF, "> ${fwsnort_dir}/${file}.new" or die "[*] Could not open ",
        "${fwsnort_dir}/${file}.new: $!";
    for my $new_line (@new_lines) {
        if ($new_line =~ /^\s*#/) {
            print CONF $new_line;
        } elsif ($new_line =~ /^\s*(\S+)/) {
            my $var = $1;
            my $found = 0;
            for my $orig_line (@orig_lines) {
                if ($orig_line =~ /^\s*$var\s/) {
                    print CONF $orig_line;
                    $found = 1;
                    last;
                }
            }
            unless ($found) {
                print CONF $new_line;
            }
        } else {
            print CONF $new_line;
        }
    }
    close CONF;
    move "${fwsnort_dir}/${file}.new", "${fwsnort_dir}/$file";
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
