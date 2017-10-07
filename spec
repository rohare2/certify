#
# $Id$
#
# Author: Rich O'Hare  <rohare2@gmail.com
#
# System security certification scripts
#
%define Version 3.7
%define Release 1

Name: certify
Version: %{Version}
Release: %{Release}
Source: certify-%{Version}-${Release}.tgz
License: GPLv2
Group: Applications/System
URL: https://github.com/rohare2/certify
BuildArch: noarch
Vendor: Rich O'Hare
Packager: Rich O'Hare <rohare2@gmail.com>
Provides: check.py, harden.py, aide_check, aide_update
Requires: python-argparse >= 1.2
Requires: pexpect >= 2.3
Requires: python-paramiko >= 1.7
Requires: lshw
Requires: redhat-lsb
Requires: aide
Requires: clamav
Requires: logwatch
Summary: Tools for managing operating system security
%define _unpackaged_files_terminate_build 0

%description
Certify is a toolset for managing system security.  It includes 
scripts for hardening and checking system security.  Cron files
are provided to automate the process.

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
%attr(740, root, root) /usr/local/certify/check.py
%attr(740, root, root) /usr/local/certify/certify_config.py
%attr(740, root, root) /usr/local/certify/harden.py
%attr(740, root, root) /usr/local/certify/testPassword.py
/etc/gdm/banner.png
/etc/logrotate.d/certify
%config(noreplace) %attr(744, root, root) /etc/cron.daily/certify_md5chk.cron
%config(noreplace) %attr(744, root, root) /etc/cron.weekly/certify_check.cron
%config(noreplace) %attr(744, root, root) /etc/cron.monthly/certify_harden.cron
/etc/gconf/gconf.xml.mandatory/%gconf-tree.xml
/usr/share/doc/%{Name}-%{Version}/readme
/usr/share/doc/%{Name}-%{Version}/changelog
/usr/share/doc/%{Name}-%{Version}/banner.png.llnl
/usr/share/doc/%{Name}-%{Version}/banner.png.sample
%attr(750, root, root) %dir /usr/local/certify/savedfiles
%attr(750, root, root) /usr/sbin/aide_check
%attr(750, root, root) /usr/sbin/aide_update
