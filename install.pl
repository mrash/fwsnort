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

use Cwd;
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

### map perl modules to versions
my %required_perl_modules = (
    'Net::IPv4Addr' => {
        'force-install' => 0,
        'mod-dir' => 'Net-IPv4Addr'
    },
    'IPTables::Parse' => {
        'force-install' => 1,
        'mod-dir' => 'IPTables-Parse'
    }
);

### establish some defaults
my $uninstall = 0;
my $cmdline_force_install = 0;
my $force_install_re = '';
my $help = 0;

my $src_dir = getcwd() or die "[*] Could not get current working directory.";

my %cmds = (
    'perl' => $perlCmd,
    'make' => $makeCmd,
    'gzip' => $gzipCmd,
    'wget' => $wgetCmd,
    'tar'  => $tarCmd
);

### make Getopts case sensitive
Getopt::Long::Configure('no_ignore_case');

&usage(1) unless (GetOptions(
    'force-mod-install' => \$cmdline_force_install,  ### force install of all modules
    'Force-mod-regex=s' => \$force_install_re, ### force specific mod install with regex
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

    ### install perl modules
    for my $module (keys %required_perl_modules) {
        &install_perl_module($module);
    }

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

sub install_perl_module() {
    my $mod_name = shift;

    die '[*] Missing force-install key in required_perl_modules hash.'
        unless defined $required_perl_modules{$mod_name}{'force-install'};
    die '[*] Missing mod-dir key in required_perl_modules hash.'
        unless defined $required_perl_modules{$mod_name}{'mod-dir'};

    my $version = '(NA)';

    my $mod_dir = $required_perl_modules{$mod_name}{'mod-dir'};

    if (-e "$mod_dir/VERSION") {
        open F, "< $mod_dir/VERSION" or
            die "[*] Could not open $mod_dir/VERSION: $!";
        $version = <F>;
        close F;
        chomp $version;
    } else {
        print "[-] Warning: VERSION file does not exist in $mod_dir\n";
    }

    my $install_module = 0;

    if ($required_perl_modules{$mod_name}{'force-install'}
            or $cmdline_force_install) {
        ### install regardless of whether the module may already be
        ### installed
        $install_module = 1;
    } elsif ($force_install_re and $force_install_re =~ /$mod_name/) {
        print "[+] Forcing installation of $mod_name module.\n";
        $install_module = 1;
    } else {
        if (has_perl_module($mod_name)) {
            print "[+] Module $mod_name is already installed in the ",
                "system perl tree, skipping.\n";
        } else {
            ### install the module in the /usr/lib/fwknop directory because
            ### it is not already installed.
            $install_module = 1;
        }
    }

    if ($install_module) {
        unless (-d $lib_dir) {
            print "[+] Creating $lib_dir\n";
            mkdir $lib_dir, 0755 or die "[*] Could not mkdir $lib_dir: $!";
        }
        print "[+] Installing the $mod_name $version perl " .
            "module in $lib_dir/\n";
        my $mod_dir = $required_perl_modules{$mod_name}{'mod-dir'};
        chdir $mod_dir or die "[*] Could not chdir to ",
            "$mod_dir: $!";
        unless (-e 'Makefile.PL') {
            die "[*] Your $mod_name source directory appears to be incomplete!\n",
                "    Download the latest sources from ",
                "http://www.cipherdyne.org/\n";
        }
        system "$cmds{'make'} clean" if -e 'Makefile';
        system "$cmds{'perl'} Makefile.PL PREFIX=$lib_dir LIB=$lib_dir";
        system $cmds{'make'};
#        system "$cmds{'make'} test";
        system "$cmds{'make'} install";
        chdir $src_dir or die "[*] Could not chdir $src_dir: $!";

        print "\n\n";
    }
    return;
}

sub has_perl_module() {
    my $module = shift;

    # 5.8.0 has a bug with require Foo::Bar alone in an eval, so an
    # extra statement is a workaround.
    my $file = "$module.pm";
    $file =~ s{::}{/}g;
    eval { require $file };

    return $@ ? 0 : 1;
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
    my $printed_intf_warning = 0;
    open CONF, "> ${fwsnort_dir}/${file}.new" or die "[*] Could not open ",
        "${fwsnort_dir}/${file}.new: $!";
    for my $new_line (@new_lines) {
        if ($new_line =~ /^\s*#/) {
            print CONF $new_line;
        } elsif ($new_line =~ /^\s*(\S+)/) {
            my $var = $1;
            my $found = 0;
            for my $orig_line (@orig_lines) {
                if ($orig_line =~ /^\s*\S+INTF\s/) {
                    ### interfaces are no longer used!
                    unless ($printed_intf_warning) {
                        print "    NOTE: Interfaces are no longer used as of the ",
                        "0.8.0 release;\n    removing $var\n";
                        $printed_intf_warning = 1;
                    }
                }
                if ($orig_line =~ /^\s*$var\s/
                        and $orig_line !~ /INTF/) {
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
install.pl: [-F] [-f] [-u] [-h]
    -f, --force-mod-install        - Install all perl modules regardless
                                     of whether they already installed on
                                     the system.
    -F, --Force-mod-regex <regex>  - Install perl module that matches a
                                     specific regular expression.
    -u, --uninstall   - uninstall fwsnort
    -h, --help        - print help and exit
_HELP_
    exit $exit;
}
