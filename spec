#
# $Id$
#
# Author: Rich O'Hare  <rohare2@gmail.com
#
# System security certification scripts
#
%define Name certify
%define Version 3.8
%define Release 24%{?dist}

Name: %{Name}
Version: %{Version}
Release: %{Release}
Source: certify-3.8-24.tgz
License: GPLv2
Group: Applications/System
URL: https://github.com/rohare2/certify
BuildArch: noarch
Vendor: Rich O'Hare
Packager: Rich O'Hare <rohare2@gmail.com>
Provides: check.py, harden.py, setup.py
Requires: python-argparse >= 1.2
Requires: pexpect >= 2.3
Requires: lshw
Requires: redhat-lsb
Summary: Tools for managing operating system security
%define _unpackaged_files_terminate_build 0

%description
Certify is a toolset for managing system security.  It includes 
scripts for hardening and checking system security.  It can also 
optionally install and configure Aide and Clamav.  Cron files
are provided to automate recurring tasks.

%prep
%setup -q -n %{Name}

%build
exit 0

%install
#rm -rf %RPM_BUILD_ROOT/*
make install
exit 0

%clean
#rm -fR %RPM_BUILD_ROOT/*
exit 0

%files
%defattr(644, root, root)
%config(noreplace) %attr(740, root, root) /usr/local/certify/certify_config.py
%attr(740, root, root) /usr/local/certify/harden.py
%attr(740, root, root) /usr/local/certify/check.py
%attr(740, root, root) /usr/local/certify/setup.py
%attr(740, root, root) /usr/local/certify/testPassword.py
%attr(750, root, root) %dir /usr/local/certify/savedfiles
/etc/gdm/banner.png
/etc/logrotate.d/certify
%attr(644, root, root) /etc/cron.d/certify.cron
/etc/gconf/gconf.xml.mandatory/%gconf-tree.xml
/usr/share/doc/%{Name}-%{Version}/readme
/usr/share/doc/%{Name}-%{Version}/changelog
/usr/share/doc/%{Name}-%{Version}/banner.png.llnl
/usr/share/doc/%{Name}-%{Version}/banner.png.sample
%config(noreplace) %attr(744, root, root) /etc/firewalld/services/simpana.xml
%config(noreplace) %attr(744, root, root) /etc/firewalld/services/splunk.xml
