%define name fwsnort
%define version 0.8.2
%define release 1
%define fwsnortlibdir %_libdir/%name
%define fwsnortlogdir /var/log/fwsnort

### get the first @INC directory that includes the string "linux".
### This may be 'i386-linux', or 'i686-linux-thread-multi', etc.
%define fwsnortmoddir `perl -e '$path='i386-linux'; for (@INC) { if($_ =~ m|.*/(.*linux.*)|) {$path = $1; last; }} print $path'`

Summary: Fwsnort translates Snort rules into equivalent Netfilter rules
Name: %name
Version: %version
Release: %release
License: GPL
Group: System/Servers
Url: http://www.cipherdyne.org/fwsnort/
Source: %name-%version.tar.gz
BuildRoot: %_tmppath/%{name}-buildroot
Requires: iptables
#Prereq: rpm-helper

%description
fwsnort translates Snort rules into equivalent Netfilter rules and generates
a Bourne shell script that implements the resulting iptables commands. This
ruleset allows network traffic that exhibits Snort signatures to be logged
and/or dropped by Netfilter directly without putting any interface into
promiscuous mode or queuing packets from kernel to user space. In addition,
fwsnort (optionally) uses the IPTables::Parse module to parse the Netfilter
ruleset on the machine to determine which Snort rules are applicable to the
specific Netfilter policy.  After all, if Netfilter is blocking all inbound
http traffic from external addresses, it is probably not of much use to try
detecting inbound attacks against against tcp/80. By default fwsnort
generates Netfilter rules that log Snort sid's with --log-prefix to klogd
where the messages can be analyzed with a log watcher such as logwatch or
psad (see http://www.cipherdyne.org/psad). fwsnort relies on the Netfilter
string match module to match Snort content fields in the application portion
of ip traffic. Since Snort rules can contain hex data in content fields,
fwsnort implements a patch against iptables-1.2.7a which adds a
"--hex-string" option which will accept content fields such as
"|0d0a5b52504c5d3030320d0a|". fwsnort is able to translate approximately 54%
of all rules from the Snort-2.3 IDS into equivalent Netfilter rules. For
more information about the translation strat- egy as well as
advantages/disadvantages of the method used by fwsnort to obtain intrusion
detection data, see the README included with the fwsnort sources or browse
to: http://www.cipherdyne.org/projects/fwsnort/.

%prep
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%setup -q

for i in $(grep -r "use lib" . | cut -d: -f1); do
	awk '/use lib/ { sub("/usr/lib/fwsnort", "%_libdir/%name") } { print }' $i > $i.tmp
	mv $i.tmp $i
done

cd IPTables-Parse && perl Makefile.PL PREFIX=%fwsnortlibdir LIB=%fwsnortlibdir
cd ..
cd Net-IPv4Addr && perl Makefile.PL PREFIX=%fwsnortlibdir LIB=%fwsnortlibdir
cd ..

%build
### build perl modules used by fwsnort
make OPTS="$RPM_OPT_FLAGS" -C IPTables-Parse
make OPTS="$RPM_OPT_FLAGS" -C Net-IPv4Addr

%install
### config directory
### log directory
mkdir -p $RPM_BUILD_ROOT%fwsnortlogdir

### fwsnort module dirs
mkdir -p $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/Net/IPv4Addr
mkdir -p $RPM_BUILD_ROOT%fwsnortlibdir/%fwsnortmoddir/auto/IPTables/Parse
mkdir -p $RPM_BUILD_ROOT%fwsnortlibdir/auto/Net/IPv4Addr
mkdir -p $RPM_BUILD_ROOT%fwsnortlibdir/Net
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
install -m 444 Net-IPv4Addr/blib/lib/auto/Net/IPv4Addr/autosplit.ix $RPM_BUILD_ROOT%fwsnortlibdir/auto/Net/IPv4Addr/autosplit.ix
install -m 444 Net-IPv4Addr/blib/lib/Net/IPv4Addr.pm $RPM_BUILD_ROOT%fwsnortlibdir/Net/IPv4Addr.pm
install -m 444 IPTables-Parse/blib/lib/IPTables/Parse.pm $RPM_BUILD_ROOT%fwsnortlibdir/IPTables/Parse.pm

### install snort rules files
cp -r snort_rules $RPM_BUILD_ROOT%_sysconfdir/%name

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
* Sat Feb 17 2007 Michael Rash <mbr@cipherydne.org>
- fwsnort-0.8.2 release

* Mon Sep 04 2006 Michael Rash <mbr@cipherydne.org>
- Updated to install new IPTables::Parse module out of the IPTables-Parse
  directory.
- Removed smtpdaemon requirement since fwsnort does not deal with email.

* Fri Nov 11 2005 Michael Rash <mbr@cipherydne.org>
- Initial RPM release
