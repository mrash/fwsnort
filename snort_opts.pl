#!/usr/bin/perl -w
#
########################################################################
#
# File: snort_opts.pl
#
# Purpose: To parse snort rules and display a listing of snort fields
#          along with how many snort rules in which each field is
#          found.
#
########################################################################
#

my %options = (
    'flow'         => 0,
    'flowbits'     => 0,
    'msg'          => 0,
    'logto'        => 0,
    'ttl'          => 0,
    'tos'          => 0,
    'id'           => 0,
    'ipopts'       => 0,
    'fragbits'     => 0,
    'dsize'        => 0,
    'flags'        => 0,
    'seq'          => 0,
    'ack'          => 0,
    'itype'        => 0,
    'icode'        => 0,
    'icmp_id'      => 0,
    'icmp_seq'     => 0,
    'content'      => 0,
    'uricontent'   => 0,
    'content-list' => 0,
    'offset'       => 0,
    'depth'        => 0,
    'nocase'       => 0,
    'session'      => 0,
    'rpc'          => 0,
    'resp'         => 0,
    'react'        => 0,
    'reference'    => 0,
    'sid'          => 0,
    'rev'          => 0,
    'classtype'    => 0,
    'priority'     => 0,
    'tag'          => 0,
    'ip_proto'     => 0,
    'sameip'       => 0,
    'stateless'    => 0,
    'regex'        => 0,
    'distance'     => 0,
    'within'       => 0,
    'byte_jump'    => 0,
    'byte_test'    => 0,
    'pcre'         => 0,
    'http_header'  => 0,
    'http_uri'     => 0,
    'urilen'       => 0,
    'http_method'  => 0,
    'fast_pattern' => 0,
    'metadata'     => 0,
    'threshold'    => 0,
    'detection_filter' => 0,
);

my $dir   = 'deps/snort_rules';
my $total_rules = 0;

opendir D, $dir or die "[*] Could not open $dir: $!";
my @rfiles = readdir D;
closedir D;

print "[+] Calculating snort rule keyword percentages:\n";
for my $rfile (@rfiles) {
    next unless $rfile =~ /\.rules/;
    open R, "< $dir/$rfile" or die $!;
    my @lines = <R>;
    close R;

    for my $line (@lines) {
        chomp $line;
        next unless $line =~ /\S/;
        next if $line =~ /^#/;
        $total_rules++;
        if ($line =~ /^\s*alert/) {
            for my $opt (keys %options) {
                if ($line =~ /\s$opt[:;]/) {
                    $options{$opt}++;
                } elsif ($line =~ /\($opt[:;]/) {
                    $options{$opt}++;
                } elsif ($line =~ /;$opt[:;]/) {
                    $options{$opt}++;
                }
            }
        }
    }
}

my $max_opt_len = 0;
for my $opt (keys %options) {
    $max_opt_len = length($opt) if length($opt) > $max_opt_len;
}

for my $opt (sort {$options{$b} <=> $options{$a}} keys %options) {
    printf("%${max_opt_len}s %13s", $opt, "$options{$opt}/$total_rules  ");
    print sprintf("%.1f", $options{$opt} / $total_rules * 100) . "%\n";
}

exit 0;
