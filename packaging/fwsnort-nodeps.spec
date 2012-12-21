%define name fwsnort
%define version 1.6.3
%define release 1
%define fwsnortlogdir /var/log/fwsnort

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

%build

%install
### config directory
### log directory
mkdir -p $RPM_BUILD_ROOT%fwsnortlogdir

mkdir -p $RPM_BUILD_ROOT%_bindir
mkdir -p $RPM_BUILD_ROOT%{_mandir}/man8
mkdir -p $RPM_BUILD_ROOT%_sbindir
### fwsnort config
mkdir -p $RPM_BUILD_ROOT%_sysconfdir/%name

install -m 500 fwsnort $RPM_BUILD_ROOT%_sbindir/
install -m 644 fwsnort.conf $RPM_BUILD_ROOT%_sysconfdir/%name/
install -m 644 fwsnort.8 $RPM_BUILD_ROOT%{_mandir}/man8/

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

%changelog
* Fri Dec 21 2012 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.6.3 release

* Sat Apr 28 2012 Michael Rash <mbr@cipherydne.org>
- Updated to use the NetAddr::IP module for all IP/subnet calculations
- fwsnort-1.6.2 release

* Thu Aug 11 2011 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.6.1 release

* Wed Jul 27 2010 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.6 release

* Sat Jan 08 2010 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.5 release

* Tue Jan 05 2010 Michael Rash <mbr@cipherydne.org>
- fwsnort-1.1 release

* Sat May 29 2009 Michael Rash <mbr@cipherydne.org>
- Added the "BuildRequires: perl-ExtUtils-MakeMaker" statement.
- fwsnort-1.0.6 release

* Thu Aug 21 2008 Michael Rash <mbr@cipherydne.org>
- Added the fwsnort-nodeps.spec file.
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
