#!/usr/bin/perl -w

use strict;

my $file       = $ARGV[0] || '';
my $spoof_addr = $ARGV[1] || '';
my $dst_addr   = $ARGV[2] || '';

die "$0 <spoof IP> <dst IP>" unless $spoof_addr and $dst_addr;

open F, "< $file" or die $!;
my @lines = <F>;
close F;

# alert udp $EXTERNAL_NET 60000 -> $HOME_NET 2140 \
# (msg:"BACKDOOR DeepThroat 3.1 Keylogger on Server ON"; \
# content:"KeyLogger Is Enabled On port"; reference:arachnids,106; \
# classtype:misc-activity; sid:165; rev:5;)

my $ctr = 0;
SIG: for my $line (@lines) {
    my $msg = '';
    my $content = '';
    my $spt = 10000;
    my $dpt = 10000;

    next SIG if $line =~ /^\s*#/;

    ### make sure it is an inbound sig
    if ($line =~ /^\s*alert\s+udp\s+\S+\s+(\S+)\s*\S+
            \s*(\$HOME_NET|any)\s+(\S+)/x) {
        my $tmp_spt = $1;
        my $tmp_dpt = $3;
        $spt = $1 if $tmp_spt =~ /(\d+)/;
        $dpt = $1 if $tmp_dpt =~ /(\d+)/;
    } else {
        next SIG;
    }

    ### can't handle multiple content fields yet
    next SIG if $line =~ /content\:.*\s*content\:/;

    $msg = $1 if $line =~ /\s*msg\:\"(.*?)\"\;/;
    $content = $1 if $line =~ /\s*content\:\"(.*)\"\;/;

    next SIG unless $msg and $content;
#    next SIG if $content =~ /\|.+\|/;

    open F, "> /tmp/sspoof" or die $!;
    print F $content, "\n";
    close F;

    my $conv_content = '';
    my $hex_mode = 0;
    my @chars = split //, $content;
    for (my $i=0; $i<=$#chars; $i++) {
        if ($chars[$i] eq '|') {
            if ($hex_mode) {
                $hex_mode = 0;
            } else {
                $hex_mode = 1;
            }
            next;
        }
        if ($hex_mode) {
            if ($chars[$i] eq ' ') {
                next;
            }
            my $tmp_chars = $chars[$i] . $chars[$i+1];
            $i++;
            $conv_content .= sprintf("%c", hex($tmp_chars));
        } else {
            $conv_content .= $chars[$i];
        }
    }

    my $len = length($conv_content);

#    hping --spoof 68.142.226.32 -c 1 --udp -E /etc/hosts -d 100 -p 60000 rivendell.cipherdyne.org

    my $hpingCmd = "/usr/sbin/hping -c 1 --udp -E /tmp/sspoof " .
        "-d $len -s $spt -p $dpt --spoof $spoof_addr $dst_addr";

    print "[+] Spoofing: $msg $spoof_addr $dst_addr:$dpt\n";
    print "HPING: $hpingCmd\n";
    print "CONTENT: $content\n";
    open HPING, "$hpingCmd |" or die $!;
    close HPING;
}
exit 0;
