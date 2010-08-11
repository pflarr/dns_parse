Name:           dns_parse
Version:        0.1.0
Release:        4%{?dist}
Summary:        Converts pcap files of DNS data into something more manageable.
Source:         dns_parse-%{version}.tar.gz
Group:          Applications/Internet
License:        GPLv2+
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  gcc libpcap

%description
This package provides a command line tool, dns_parse, that converts pcap files
of DNS data (currently UDP only) into a readable and easily parsable format.
This data can then be easily fed into splunk or searched directly using grep.
The raw files are actually slightly larger than the original pcap files, but
compress much more readily.

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

%changelog
* Wed Aug 11 2010 Paul Ferrell <pferrell@lanl.gov> - 1.4.2
- Initial Build
