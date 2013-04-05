Name:           dns_parse
Version:        2.0.6
Release:        4%{?dist}
Summary:        Converts pcap files of DNS data into something more manageable.
Source:         dns_parse-%{version}.tar.gz
Group:          Applications/Internet
License:        GPLv2+
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires:       python

BuildRequires:  gcc libpcap

%description
This package provides a command line tool, dns_parse, that converts pcap files
of DNS data (currently UDP only) into a readable and easily parsable format.
This data can then be easily fed into splunk or searched directly using grep.
The raw files are actually slightly larger than the original pcap files, but
compress much more readily.

It also provides:
  A configurable script for processing a directory of files using dns_parse.
  A configurable init script for capturing the DNS data.

%prep
%setup 

%build
make

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
/usr/local/sbin/dns_parse
/usr/local/sbin/dns_parse_cron
/etc/init.d/dnscapture
%config /etc/dnscapture.conf
%config /etc/dns_parse.cfg

%changelog
* Tue Mar 12 2013 Paul Ferrell <pferrell@lanl.gov> - 2.0.0
- Added support for TCP, IPv6, IP fragmentation, and MPLS.
- Added UDP packet deduplication.

* Thu Oct 28 2010 Paul Ferrell <pferrell@lanl.gov> - 0.2.0
- Added a couple of useful scripts to simplify dns capture and parsing, 
- and their config files.

* Wed Aug 19 2010 Paul Ferrell <pferrell@lanl.gov> - 0.1.9
- Added -r option, to print the rr names instead of type, class numbers.

* Tue Aug 17 2010 Paul Ferrell <pferrell@lanl.gov> - 0.1.8
- Multi bug fixes, improved error handling, fixed some memory issues.

* Wed Aug 11 2010 Paul Ferrell <pferrell@lanl.gov> - 0.1.0 
- Initial Build

