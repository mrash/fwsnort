#
##################################################################
#
# File: IPTables::Parse.pm
#
# Purpose: Perl interface to parse iptables rulesets.
#
# Author: Michael Rash (mbr@cipherdyne.com)
#
# Version: 0.1
#
##################################################################
#
# $Id$
#

package IPTables::Parse;

use 5.006;
use Carp;
use strict;
use warnings;

my $VERSION = '0.1';

sub new() {
    my $class = shift;
    my %args  = @_;

    my $self = {
        _iptables => $args{'iptables'} || '/sbin/iptables'
    };
    croak " ** $self->{'_iptables'} incorrect path.\n"
        unless -e $self->{'_iptables'};
    croak " ** $self->{'_iptables'} not executable.\n"
        unless -x $self->{'_iptables'};
    bless $self, $class;
}

sub chain_action_rules() {
    my $self   = shift;
    my $table  = shift || croak " ** Specify a table, e.g. \"nat\"";
    my $chain  = shift || croak " ** Specify a chain, e.g. \"OUTPUT\"";
    my $action = shift || croak " ** Specify either ",
        "\"ACCEPT, DROP, or LOG\"";
    my $iptables  = $self->{'_iptables'};
    my @ipt_lines = `$iptables -t $table -nL $chain`;
    my $rule_ctr = 0;
    my %chain = ();

    LINE: for my $line (@ipt_lines) {
        $rule_ctr++;
        chomp $line;
        ### ACCEPT tcp  -- 164.109.8.0/24  0.0.0.0/0  tcp dpt:22 flags:0x16/0x02
        ### ACCEPT tcp  -- 216.109.125.67  0.0.0.0/0  tcp dpts:7000:7500
        ### ACCEPT udp  -- 0.0.0.0/0       0.0.0.0/0  udp dpts:7000:7500
        ### ACCEPT udp  -- 0.0.0.0/0       0.0.0.0/0  udp dpt:!7000
        ### ACCEPT icmp --  0.0.0.0/0      0.0.0.0/0
        ### ACCEPT tcp  --  0.0.0.0/0      0.0.0.0/0  tcp spt:35000 dpt:5000
        ### ACCEPT tcp  --  10.1.1.1       0.0.0.0/0
        if ($line =~ m|^$action\s+(\S+)\s+\-\-\s+(\S+)\s+(\S+)\s*(.*)|) {
            my $proto = $1;
            my $src   = $2;
            my $dst   = $3;
            my $p_str = $4;
            if ($p_str || $proto eq 'tcp' || $proto eq 'udp') {
                ### for now we can only handle tcp and udp protocols
                ### if there is anything in the "port" section of the rule
                next LINE unless $proto eq 'tcp' or $proto eq 'udp';
                my $s_port  = '0:0';  ### any to any
                my $d_port  = '0:0';
                if ($p_str =~ /dpts?:(\S+)/) {
                    $d_port = $1;
                }
                if ($p_str =~ /spts?:(\S+)/) {
                    $s_port = $1;
                }
                $chain{$proto}{$s_port}{$d_port}{$src}{$dst}
                    = $rule_ctr;
            } else {
                $chain{$proto}{$src}{$dst} = $rule_ctr;
            }
        }
    }
    return \%chain;
}

sub default_drop() {
    my $self  = shift;
    my $table = shift || croak " ** Specify a table, e.g. \"nat\"";
    my $chain = shift || croak " ** Specify a chain, e.g. \"OUTPUT\"";
    my $iptables  = $self->{'_iptables'};
    my @ipt_lines = `$iptables -t $table -nL $chain`;
    my %protocols = ();
    my $rule_ctr = 0;
    my $prefix;
    my $any_ip = '(?:0\.){3}0/0';

    unless (@ipt_lines) {
        return ' ** Could not get iptables output!', 0;
    }

    for my $line (@ipt_lines) {
        $rule_ctr++;
        chomp $line;

        if ($line =~ m|^LOG\s+(\w+)\s+\-\-\s+
            $any_ip\s+$any_ip\s+(.*)|x) {
            my $proto  = $1;
            my $p_tmp  = $2;
            my $prefix = 'NONE';
            ### LOG flags 0 level 4 prefix `DROP '
            if ($p_tmp && $p_tmp =~ m|LOG\s+flags\s+0.*prefix\s+
                \`\s*(.+?)\s*\'|x) {
                $prefix = $1;
            }
            ### $proto may equal 'all' here
            $protocols{$proto}{'LOG'}{'prefix'} = $prefix;
            $protocols{$proto}{'LOG'}{'rulenum'} = $rule_ctr;
        } elsif ($line =~ m|^DROP\s+(\w+)\s+\-\-\s+
            $any_ip\s+$any_ip\s*$|x) {
            ### DROP    all  --  0.0.0.0/0     0.0.0.0/0
            $protocols{$1}{'DROP'} = $rule_ctr;
        }
    }
    return \%protocols;
}

1;
__END__

=head1 NAME

IPTables::Parse - Perl extension for parsing iptables firewall rulesets

=head1 SYNOPSIS

    use IPTables::Parse;

    my $table = 'filter';
    my $chain = 'INPUT';
    if (&IPTables::Parse::default_drop($table, $chain)) {
        print " .. Table: $table, chain: $chain has a default rule\n";
    } else {
        print " .. No default drop rule in table: $table, chain: $chain.\n";
    }

=head1 DESCRIPTION

IPTables::Parse provides a perl module interface to parse iptables rulesets.

=head1 AUTHOR

Michael B. Rash, E<lt>mbr@cipherdyne.comE<gt>

=head1 SEE ALSO

L<perl>.

=cut
