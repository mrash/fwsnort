#!/usr/bin/perl -w
#
#######################################################################
#
# File: install.pl
#
# Purpose: This is the installation script for fwsnort.
#
# Copyright (C) 2003-2011 Michael Rash (mbr@cipherdyne.org)
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
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
#    USA
#
# TODO:
#   - Write the uninstall() routine.
#
#######################################################################
#

use Cwd;
use IO::Socket;
use File::Copy;
use File::Path;
use Getopt::Long;
use strict;

#========================= config ========================
my $fwsnort_conf_file = 'fwsnort.conf';

my $sbin_dir     = '/usr/sbin';
my $install_root = '/';

my $update_website = 'www.emergingthreats.net';

### system binaries
my $perlCmd = '/usr/bin/perl';
my $makeCmd = '/usr/bin/make';
my $wgetCmd = '/usr/bin/wget';
my $gzipCmd = '/bin/gzip';
my $tarCmd  = '/bin/tar';
#======================= end config ======================

my %config = ();

### map perl modules to versions
my %required_perl_modules = (
    'NetAddr::IP' => {
        'force-install' => 0,
        'mod-dir' => 'NetAddr-IP'
    },
    'IPTables::Parse' => {
        'force-install' => 1,
        'mod-dir' => 'IPTables-Parse'
    }
);

### rules update link
my $rules_url = 'http://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules';

### establish some defaults
my $uninstall = 0;
my $skip_module_install   = 0;
my $cmdline_force_install = 0;
my $install_test_dir = 0;
my $force_mod_re = '';
my $exclude_mod_re = '';
my $deps_dir = 'deps';
my $help = 0;
my $locale = 'C';  ### default LC_ALL env variable
my $no_locale = 0;

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
    'Force-mod-regex=s' => \$force_mod_re, ### force specific mod install with regex
    'Exclude-mod-regex=s' => \$exclude_mod_re, ### exclude a particular perl module
    'Skip-mod-install'  => \$skip_module_install,
    'rules-url=s' => \$rules_url,
    'uninstall' => \$uninstall, ### uninstall fwsnort
    'install-test-dir'  => \$install_test_dir,
    'LC_ALL=s'  => \$locale,
    'no-LC_ALL' => \$no_locale,
    'help'      => \$help
));

&usage(0) if $help;

### set LC_ALL env variable
$ENV{'LC_ALL'} = $locale unless $no_locale;

### make a copy of the original fwsnort.conf file and restore at the end
copy $fwsnort_conf_file, "${fwsnort_conf_file}.orig" or die "[*] Could not ",
    "copy $fwsnort_conf_file -> $fwsnort_conf_file.orig";

if ($install_test_dir) {
    $install_root = getcwd() . '/test/fwsnort-install';
}

&import_config();

$force_mod_re = qr|$force_mod_re| if $force_mod_re;
$exclude_mod_re = qr|$exclude_mod_re| if $exclude_mod_re;

### see if the deps/ directory exists, and if not then we are installing
### from the -nodeps sources so don't install any perl modules
$skip_module_install = 1 unless -d $deps_dir;

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

### restore the original fwsnort.conf file (this is just the local one in the
### sources directory).
if (-e "${fwsnort_conf_file}.orig") {
    unlink $fwsnort_conf_file if -e $fwsnort_conf_file;
    move "${fwsnort_conf_file}.orig", $fwsnort_conf_file;
}

exit 0;
#===================== end main ===================

sub install() {
    die "[*] You must run install.pl from the fwsnort " .
        "sources directory." unless -e 'fwsnort' and -e 'fwsnort.conf';

    unless (-d $config{'CONF_DIR'}) {
        &full_mkdir($config{'CONF_DIR'}, 0500);
    }
    unless (-d $config{'RULES_DIR'}) {
        &full_mkdir($config{'RULES_DIR'}, 0500);
    }

    ### install perl modules
    unless ($skip_module_install) {
        for my $module (keys %required_perl_modules) {
            &install_perl_module($module);
        }
    }
    chdir $src_dir or die "[*] Could not chdir $src_dir: $!";

    my $local_rules_dir = 'deps/snort_rules';
    if (-d 'deps' and -d $local_rules_dir
            and &query_get_emerging_threats_sigs()) {
        chdir $local_rules_dir or die "[*] Could not chdir $local_rules_dir";
        if (-e 'emerging-all.rules') {
            move 'emerging-all.rules', 'emerging-all.rules.tmp'
                or die "[*] Could not move emerging-all.rules -> ",
                "emerging-all.rules.tmp";
        }
        system "$cmds{'wget'} $rules_url";
        if (-e 'emerging-all.rules') {  ### successful download
            unlink 'emerging-all.rules.tmp';
        } else {
            print "[-] Could not download emerging-all.rules file.\n";
            if (-e 'emerging-all.rules.tmp') {
                ### move the original back
                move 'emerging-all.rules', 'emerging-all.rules.tmp'
                    or die "[*] Could not move emerging-all.rules -> ",
                    "emerging-all.rules.tmp";
            }
        }
        chdir '../..';
    }

    if (-d 'deps' and -d $local_rules_dir) {
        opendir D, $local_rules_dir or die "[*] Could not open ",
            "the $local_rules_dir directory: $!";
        my @rfiles = readdir D;
        closedir D;

        print "[+] Copying all rules files to $config{'RULES_DIR'}\n";
        for my $rfile (@rfiles) {
            next unless $rfile =~ /\.rules$/;
            print "[+] Installing $rfile\n";
            copy "$local_rules_dir/${rfile}", "$config{'RULES_DIR'}/${rfile}"
                or die "[*] Could not copy $local_rules_dir/${rfile} ",
                    "-> $config{'RULES_DIR'}/${rfile}";
        }
    }

    print "\n";

    ### install the fwsnort.8 man page
    &install_manpage();

    my $preserve_rv = 0;
    if (-e "$config{'CONF_DIR'}/fwsnort.conf") {
        $preserve_rv = &query_preserve_config();
    }

    if ($preserve_rv) {
        &preserve_config();
    } else {
        print "[+] Copying fwsnort.conf -> $config{'CONF_DIR'}/fwsnort.conf\n";
        copy 'fwsnort.conf', "$config{'CONF_DIR'}/fwsnort.conf";
        chmod 0600, "$config{'CONF_DIR'}/fwsnort.conf";
    }

    print "[+] Copying fwsnort -> ${sbin_dir}/fwsnort\n";
    copy 'fwsnort', "${sbin_dir}/fwsnort";
    chmod 0500, "${sbin_dir}/fwsnort";

    print "\n========================================================\n",
        "\n[+] fwsnort will generate an iptables script located at:\n",
        "    /var/lib/fwsnort.sh when executed.\n",
        "\n[+] fwsnort has been successfully installed!\n\n";

    return;
}

sub install_perl_module() {
    my $mod_name = shift;

    chdir $src_dir or die "[*] Could not chdir $src_dir: $!";
    chdir $deps_dir or die "[*] Could not chdir($deps_dir): $!";

    die '[*] Missing force-install key in required_perl_modules hash.'
        unless defined $required_perl_modules{$mod_name}{'force-install'};
    die '[*] Missing mod-dir key in required_perl_modules hash.'
        unless defined $required_perl_modules{$mod_name}{'mod-dir'};

    if ($exclude_mod_re and $exclude_mod_re =~ /$mod_name/) {
        print "[+] Excluding installation of $mod_name module.\n";
        return;
    }

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
    } elsif ($force_mod_re and $force_mod_re =~ /$mod_name/) {
        print "[+] Forcing installation of $mod_name module.\n";
        $install_module = 1;
    } else {
        if (has_perl_module($mod_name)) {
            print "[+] Module $mod_name is already installed in the ",
                "system perl tree, skipping.\n";
        } else {
            ### install the module in the /usr/lib/fwsnort directory because
            ### it is not already installed.
            $install_module = 1;
        }
    }

    if ($install_module) {
        unless (-d $config{'LIBS_DIR'}) {
            print "[+] Creating $config{'LIBS_DIR'}\n";
            &full_mkdir($config{'LIBS_DIR'}, 0755);
        }
        print "[+] Installing the $mod_name $version perl " .
            "module in $config{'LIBS_DIR'}/\n";
        my $mod_dir = $required_perl_modules{$mod_name}{'mod-dir'};
        chdir $mod_dir or die "[*] Could not chdir to ",
            "$mod_dir: $!";
        unless (-e 'Makefile.PL') {
            die "[*] Your $mod_name source directory appears to be incomplete!\n",
                "    Download the latest sources from ",
                "http://www.cipherdyne.org/\n";
        }
        system "$cmds{'make'} clean" if -e 'Makefile';
        system "$cmds{'perl'} Makefile.PL " .
            "PREFIX=$config{'LIBS_DIR'} LIB=$config{'LIBS_DIR'}";
        system $cmds{'make'};
#        system "$cmds{'make'} test";
        system "$cmds{'make'} install";

        print "\n\n";
    }
    chdir $src_dir or die "[*] Could not chdir $src_dir: $!";
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
    &full_mkdir($mpath, 0755);
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

sub query_get_emerging_threats_sigs() {
    return 0 if $install_test_dir;
    my $ans = '';
    print "[+] Would you like to download the latest Snort rules from \n",
        "    http://$update_website/?\n";
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

sub import_config() {
    open C, "< $fwsnort_conf_file"
        or die "[*] Could not open $fwsnort_conf_file: $!";
    while (<C>) {
        next if /^\s*#/;
        if (/^\s*(\S+)\s+(.*?)\;/) {
            my $varname = $1;
            my $val     = $2;
            if ($val =~ m|/.+| and $varname =~ /^\s*(\S+)Cmd$/) {
                ### found a command
                $cmds{$1} = $val;
            } else {
                $config{$varname} = $val;
            }
        }
    }
    close C;

    ### see if the install root is the same as the default in fwsnort.conf and
    ### update if not
    if ($install_root ne '/') {
        $install_root = getcwd() . "/$install_root"
            unless $install_root =~ m|^/|;
        $config{'INSTALL_ROOT'} = $install_root;
        $sbin_dir = $config{'INSTALL_ROOT'} . $sbin_dir;

        &put_var('INSTALL_ROOT', $install_root, $fwsnort_conf_file);
    }

    ### resolve internal vars within variable values
    &expand_vars();

    for my $dir ($install_root,
            $sbin_dir,
            $config{'LOG_DIR'},
            $config{'LIB_DIR'},
            $config{'STATE_DIR'},
            $config{'QUEUE_RULES_DIR'},
            $config{'ARCHIVE_DIR'},
        ) {
        &full_mkdir($dir, 0755) unless -d $dir;
    }

    &required_vars();

    return;
}

sub expand_vars() {

    my $has_sub_var = 1;
    my $resolve_ctr = 0;

    while ($has_sub_var) {
        $resolve_ctr++;
        $has_sub_var = 0;
        if ($resolve_ctr >= 20) {
            die "[*] Exceeded maximum variable resolution counter.";
        }
        for my $hr (\%config, \%cmds) {
            for my $var (keys %$hr) {
                my $val = $hr->{$var};
                if ($val =~ m|\$(\w+)|) {
                    my $sub_var = $1;
                    die "[*] sub-ver $sub_var not allowed within same ",
                        "variable $var" if $sub_var eq $var;
                    if (defined $config{$sub_var}) {
                        if ($sub_var eq 'INSTALL_ROOT' and $config{$sub_var} eq '/') {
                            $val =~ s|\$$sub_var||;
                        } else {
                            $val =~ s|\$$sub_var|$config{$sub_var}|;
                        }
                        $hr->{$var} = $val;
                    } else {
                        die "[*] sub-var \"$sub_var\" not defined in ",
                            "config for var: $var."
                    }
                    $has_sub_var = 1;
                }
            }
        }
    }
    return;
}

sub put_var() {
    my ($var, $value, $file) = @_;

    open RF, "< $file" or die "[*] Could not open $file: $!";
    my @lines = <RF>;
    close RF;
    open F, "> $file" or die "[*] Could not open $file: $!";
    for my $line (@lines) {
        if ($line =~ /^\s*$var\s+.*;/) {
            printf F "%-24s%s;\n", $var, $value;
        } else {
            print F $line;
        }
    }
    close F;
    return;
}

sub required_vars() {
    my @required_vars = qw(
        CONF_DIR RULES_DIR ARCHIVE_DIR QUEUE_RULES_DIR LOG_DIR LIBS_DIR
        CONF_FILE FWSNORT_SCRIPT LOG_FILE
    );
    for my $var (@required_vars) {
        die "[*] Variable $var not defined in $fwsnort_conf_file. Exiting.\n"
            unless defined $config{$var};
    }
    return;
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
    return 0 if $install_test_dir;
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

    open CO, "< $config{'CONF_DIR'}/$file" or die "[*] Could not open ",
        "$config{'CONF_DIR'}/$file: $!";
    my @orig_lines = <CO>;
    close CO;

    print "[+] Preserving existing config: $config{'CONF_DIR'}/$file\n";
    ### write to a tmp file and then move.
    my $printed_intf_warning = 0;
    open CONF, "> $config{'CONF_DIR'}/${file}.new" or die "[*] Could not open ",
        "$config{'CONF_DIR'}/${file}.new: $!";
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
    move "$config{'CONF_DIR'}/${file}.new", "$config{'CONF_DIR'}/$file";
    return;
}

sub full_mkdir() {
    my ($dir, $perms) = @_;

    my @dirs = split /\//, $dir;
    my $path = $dirs[0];
    shift @dirs;
    for my $d (@dirs) {
        next unless $d and $d =~ /\S/;
        $path .= "/$d";
        unless (-d $path) {
            printf "[+] mkdir $path, %o\n", $perms;
            mkdir $path, $perms or die "[*] Could not mkdir($path): $!";
        }
    }
    return;
}

sub usage() {
    my $exit = shift;
    print <<_HELP_;
install.pl: [options]
    -f, --force-mod-install        - Install all perl modules regardless
                                     of whether they already installed on
                                     the system.
    -F, --Force-mod-regex <regex>  - Install perl module that matches a
                                     specific regular expression.
    -E, --Exclude-mod-regex <re>   - Exclude a perl module that matches this
                                     regular expression.
    -S, --Skip-mod-install         - Skip installation of modules.
    -r, --rules-url <url>          - Specify the URL to use for updating the
                                     Emerging Threats rule set - the default is:
                                     $rules_url
    --install-test-dir             - Install fwsnort in test/fwsnort-install
                                     for test suite.
    -u, --uninstall   - uninstall fwsnort
    -h, --help        - print help and exit
_HELP_
    exit $exit;
}
