%define name fwsnort
%define version 1.6.3
%define release 1
%define fwsnortlibdir %_libdir/%name
%define fwsnortlogdir /var/log/fwsnort

### get the first @INC directory that includes the string "linux".
### This may be 'i386-linux', or 'i686-linux-thread-multi', etc.
%define fwsnortmoddir `perl -e '$path=q|i386-linux|; for (@INC) { if($_ =~ m|.*/(.*linux.*)|) {$path = $1; last; }} print $path'`

Summary: Fwsnort translates Snort rules into equivalent iptables rules
Name: %name
Version: %version
Release: %release
License: GPL
Group: System/Servers
Url: http://www.cipherdyne.org/fwsnort/
Source: %name-%version.tar.gz
BuildRoot: %_tmppath/%{name}-buildroot
Requires: iptables
BuildRequires: perl-ExtUtils-MakeMaker
#Prereq: rpm-helper

%description
fwsnort translates Snort rules into equivalent iptables rules and generates
a Bourne shell script that implements the resulting iptables commands. This
ruleset allows network traffic that exhibits Snort signatures to be logged
and/or dropped by iptables directly without putting any interface into
promiscuous mode or queuing packets from kernel to user space. In addition,
fwsnort (optionally) uses the IPTables::Parse module to parse the iptables
ruleset on the machine to determine which Snort rules are applicable to the
specific iptables policy.  After all, if iptables is blocking all inbound
http traffic from external addresses, it is probably not of much use to try
detecting inbound attacks against against tcp/80. By default fwsnort
generates iptables rules that log Snort sid's with --log-prefix to klogd
where the messages can be analyzed with a log watcher such as logwatch or
psad (see http://www.cipherdyne.org/psad). fwsnort relies on the iptables
string match extension to match Snort content fields in the application portion
of ip traffic. Since Snort rules can contain hex data in content fields,
fwsnort implements a patch against iptables-1.2.7a which adds a
"--hex-string" option which will accept content fields such as
"|0d0a5b52504c5d3030320d0a|". fwsnort bundles the latest rule set from
Emerging Threats (http://www.emergingthreats.net) and also includes all rules
from the Snort-2.3.3 IDS - the final Snort rule set that was released under
the GPL.  fwsnort is able to translate well over 60% of all bundled rules.
For more information about the translation strategy as well as
advantages/disadvantages of the method used by fwsnort to obtain intrusion
detection data, see the README included with the fwsnort sources or browse
to: http://www.cipherdyne.org/fwsnort/

%prep
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%setup -q

cd deps
cd IPTables-Parse && perl Makefile.PL PREFIX=%fwsnortlibdir LIB=%fwsnortlibdir
cd ..
cd NetAddr-IP && perl Makefile.PL PREFIX=%fwsnortlibdir LIB=%fwsnortlibdir
cd ../..

%build
### build perl modules used by fwsnort
cd deps
make OPTS="$RPM_OPT_FLAGS" -C IPTables-Parse
make OPTS="$RPM_OPT_FLAGS" -C NetAddr-IP
cd ..

%install
### config directory
### log directory
mkdir -p $RPM_BUILD_ROOT%fwsnortlogdir

### fwsnort module dirs
mkdir -p $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/IPTables/Parse
mkdir -p $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/Util
mkdir -p $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP
mkdir -p $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/InetBase
mkdir -p $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/NetAddr/IP
mkdir -p $RPM_BUILD_ROOT%fwsnortlibdir/IPTables

mkdir -p $RPM_BUILD_ROOT%_bindir
mkdir -p $RPM_BUILD_ROOT%{_mandir}/man8
mkdir -p $RPM_BUILD_ROOT%_sbindir
### fwsnort config
mkdir -p $RPM_BUILD_ROOT%_sysconfdir/%name

install -m 500 fwsnort $RPM_BUILD_ROOT%_sbindir/
install -m 644 fwsnort.conf $RPM_BUILD_ROOT%_sysconfdir/%name/
install -m 644 fwsnort.8 $RPM_BUILD_ROOT%{_mandir}/man8/

### install perl modules used by fwsnort
cd deps
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/hostenum.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/hostenum.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/compactref.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/compactref.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/nprefix.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/nprefix.al
[ -e NetAddr-IP/blib/lib/auto/NetAddr/IP/.packlist ] && install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/.packlist $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/.packlist
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/re.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/re.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/prefix.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/prefix.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/do_prefix.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/do_prefix.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/wildcard.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/wildcard.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/_compact_v6.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/_compact_v6.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/autosplit.ix $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/autosplit.ix
[ -e NetAddr-IP/blib/lib/auto/NetAddr/IP/Util/Util.so ] && install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/Util/Util.so $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/Util/Util.so
[ -e NetAddr-IP/blib/lib/auto/NetAddr/IP/Util/Util.bs ] && install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/Util/Util.bs $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/Util/Util.bs
[ -e NetAddr-IP/blib/lib/auto/NetAddr/IP/Util/autosplit.ix ] && install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/Util/autosplit.ix $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/Util/autosplit.ix
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/shiftleft.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/shiftleft.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/ipv4to6.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/ipv4to6.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/maskanyto6.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/maskanyto6.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/comp128.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/comp128.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/_deadlen.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/_deadlen.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/sub128.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/sub128.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/notcontiguous.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/notcontiguous.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/bcdn2bin.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/bcdn2bin.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/add128.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/add128.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/ipv6to4.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/ipv6to4.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/_bcdcheck.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/_bcdcheck.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/mask4to6.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/mask4to6.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/_128x2.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/_128x2.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/ipanyto6.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/ipanyto6.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/hasbits.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/hasbits.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/bcdn2txt.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/bcdn2txt.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/slowadd128.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/slowadd128.al
[ -e NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/autosplit.ix ] && install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/autosplit.ix $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/autosplit.ix
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/simple_pack.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/simple_pack.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/bcd2bin.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/bcd2bin.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/bin2bcdn.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/bin2bcdn.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/_bin2bcdn.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/_bin2bcdn.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/bin2bcd.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/bin2bcd.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/_sa128.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/_sa128.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/_bcd2bin.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/_bcd2bin.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/addconst.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/addconst.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/UtilPP/_128x10.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/UtilPP/_128x10.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/mod_version.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/mod_version.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/_splitref.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/_splitref.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/_compV6.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/_compV6.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/InetBase/inet_any2n.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/InetBase/inet_any2n.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/InetBase/_inet_ntop.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/InetBase/_inet_ntop.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/InetBase/inet_n2ad.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/InetBase/inet_n2ad.al
[ -e NetAddr-IP/blib/lib/auto/NetAddr/IP/InetBase/autosplit.ix ] && install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/InetBase/autosplit.ix $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/InetBase/autosplit.ix
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/InetBase/_packzeros.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/InetBase/_packzeros.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/InetBase/inet_n2dx.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/InetBase/inet_n2dx.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/InetBase/ipv6_aton.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/InetBase/ipv6_aton.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/InetBase/ipv6_ntoa.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/InetBase/ipv6_ntoa.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/InetBase/inet_ntoa.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/InetBase/inet_ntoa.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/InetBase/_inet_pton.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/InetBase/_inet_pton.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/coalesce.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/coalesce.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/re6.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/re6.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/short.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/short.al
install -m 444 NetAddr-IP/blib/lib/auto/NetAddr/IP/_splitplan.al $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/NetAddr/IP/_splitplan.al
install -m 444 NetAddr-IP/blib/lib/NetAddr/IP/InetBase.pm $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/NetAddr/IP/InetBase.pm
install -m 444 NetAddr-IP/blib/lib/NetAddr/IP/UtilPP.pm $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/NetAddr/IP/UtilPP.pm
install -m 444 NetAddr-IP/blib/lib/NetAddr/IP/Util.pm $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/NetAddr/IP/Util.pm
install -m 444 NetAddr-IP/blib/lib/NetAddr/IP/Lite.pm $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/NetAddr/IP/Lite.pm
install -m 444 NetAddr-IP/blib/lib/NetAddr/IP/Util_IS.pm $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/NetAddr/IP/Util_IS.pm
install -m 444 NetAddr-IP/blib/lib/NetAddr/IP.pm $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/NetAddr/IP.pm
install -m 444 IPTables-Parse/blib/lib/IPTables/Parse.pm $RPM_BUILD_ROOT%fwsnortlibdir/IPTables/Parse.pm
cd ..

### install snort rules files
cp -r deps/snort_rules $RPM_BUILD_ROOT%_sysconfdir/%name

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%pre
### not used

%post
### not used

%preun
### not used

%files
%defattr(-,root,root)
%dir %fwsnortlogdir
%_sbindir/*
%{_mandir}/man8/*

%dir %_sysconfdir/%name
%config(noreplace) %_sysconfdir/%name/fwsnort.conf

%dir %_sysconfdir/%name/snort_rules
%config(noreplace) %_sysconfdir/%name/snort_rules/*

%_libdir/%name

%changelog
* Fri Dec 21 2012 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.6.3 release

* Sat Apr 28 2012 Michael Rash <mbr@cipherydne.org>
- Updated to use the NetAddr::IP module for all IP/subnet calculations
- fwsnort-1.6.2 release

* Thu Aug 11 2011 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.6.1 release

* Wed Jul 27 2011 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.6 release

* Sat Jan 08 2011 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.5 release

* Tue Jan 05 2010 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.1 release

* Sat May 29 2009 Michael Rash <mbr@cipherydne.org>
- Added the "BuildRequires: perl-ExtUtils-MakeMaker" statement.
- fwsnort-1.0.6 release

* Thu Aug 21 2008 Michael Rash <mbr@cipherydne.org>
- Updated to use the deps/ directory for all perl module sources.
- fwsnort-1.0.5 release

* Tue Jan 22 2008 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.0.4 release

* Thu Nov 22 2007 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.0.3 release

* Sun Aug 26 2007 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.0.2 release

* Sun Aug 26 2007 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.0.1 release

* Thu Apr 19 2007 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.0 release

* Fri Mar 22 2007 Michael Rash <mbr@cipherydne.org>
- fwsnort-0.9.0 release

* Sat Feb 17 2007 Michael Rash <mbr@cipherydne.org>
- fwsnort-0.8.2 release

* Mon Sep 04 2006 Michael Rash <mbr@cipherydne.org>
- Updated to install new IPTables::Parse module out of the IPTables-Parse
  directory.
- Removed smtpdaemon requirement since fwsnort does not deal with email.

* Fri Nov 11 2005 Michael Rash <mbr@cipherydne.org>
- Initial RPM release
