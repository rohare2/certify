#!/usr/bin/perl -w
# Makefile.PL
# $Id$
# $Date$
#
use strict;

my $debug = 0;

# determine hostname
my $hostname = `uname -n`;
chomp $hostname;

# determine acceptable arguments
my @open = ('gs');
my @high = ('jwics','hal','wnet','titan');
my (@all,@good_args);
if ($hostname eq "www.ohares.us" ||
		$hostname eq "master.ohares.us") {
	@all = ('ohares');
	@good_args = ('ohares','all');
} elsif ($hostname eq "corbin.llnl.gov" ||
		$hostname eq "captive.llnl.gov" ||
		$hostname eq "convict.llnl.gov" ||
		$hostname eq "serf.llnl.gov" ||
	 	$hostname eq "slave.llnl.gov") {
	@all = ('gs','hal','jwics');
	@good_args = ('all','gs','hal','high','jwics','open');
} else {
	die "Must be run from a known host";
}

my $baseDir = `pwd`;
chomp $baseDir;
my @net;

($#ARGV >= 0 && grep(/$ARGV[0]/i, @good_args)) || $#ARGV < 0 or
	die "unknown network argument\nvalid networks: @good_args\n";

if ( $#ARGV >= 0 ) {
	if ($ARGV[0] eq 'high') {
		@net = @high;
	} elsif ($ARGV[0] eq 'open') {
		 @net = @open;
	} elsif ($ARGV[0] eq 'all') {
		@net = @all;
	} else {
		@net = @ARGV;
	}
} else {
	@net = @all;
}

system("git log > changelog");

# software version
-f "VERSION" or die "No version file";
my $swVersion = `cat VERSION`;
chomp $swVersion;

# software release
-f "RELEASE" or die "No release file";
my $swRelease = `cat RELEASE`;
chomp $swRelease;

# Linux release number
my $osRelease = `lsb_release -sr`;
chomp $osRelease;
$osRelease =~ s/\..*//;

my $redhatDistro;
my $centosDistro;

my $releaseFile = `cat /etc/redhat-release`;
if ($releaseFile =~ /Red ?Hat/) {
	$releaseFile =~ /Client/ && ($redhatDistro = "redhat${osRelease}_client");
	$releaseFile =~ /Server/ && ($redhatDistro = "redhat${osRelease}_server");
	$releaseFile =~ /Workstation/ && ($redhatDistro = "redhat${osRelease}_workstation");
	$centosDistro = "centos${osRelease}";
} else {
	print "Must be executed from a Red Hat system\n";
	exit 1;
}

sub changeFiles {
	my $net = shift;
	my $distro = shift;

	# Edit Makefile
	my $file = 'Makefile';
	open (INPUT,"<$file") or die;
	my @input_array=<INPUT>;
	close(INPUT);
	my $input_scalar=join("",@input_array);

	if ($input_scalar =~ /^Version=/m) {
		my $origStr = 'Version=.*$';
		my $replStr = "Version= ${swVersion}";
		$input_scalar =~ s/$origStr/$replStr/m;
	}

	if ($input_scalar =~ /^Package=/m) {
		my $origStr = '^Package=.*$';
		my $replStr = "Package= certify-${swVersion}-${swRelease}.${distro}.${net}";
		$input_scalar =~ s/$origStr/$replStr/m;
	}

	open (OUTPUT, "> $file") or die;
	print OUTPUT "$input_scalar";
	close OUTPUT;

	# Edit spec
	$file = 'spec';
	open (INPUT,"<$file") or die;
	@input_array=<INPUT>;
	close(INPUT);
	$input_scalar=join("",@input_array);

	if ($input_scalar =~ /^%define Version/m) {
		my $origStr = '%define Version.*$';
		my $replStr = "%define Version ${swVersion}";
		$input_scalar =~ s/$origStr/$replStr/m;
	}

	if ($input_scalar =~ /^Release:/m) {
		my $origStr = '^Release:.*$';
		my $replStr = "Release: ${swRelease}.${distro}.${net}";
		$input_scalar =~ s/$origStr/$replStr/m;
	}

	if ($input_scalar =~ /^Source:/m) {
		my $origStr = '^Source:.*$';
		my $replStr = "Source: certify-${swVersion}-${swRelease}.${distro}.${net}.tgz";
		$input_scalar =~ s/$origStr/$replStr/m;
	}

	if ($input_scalar =~ /^Distribution:/m) {
		my $origStr = '^Distribution:.*$';
		my $replStr = "Distribution: ${distro}";
		$input_scalar =~ s/$origStr/$replStr/m;
	}

	if ($input_scalar =~ /^BuildArch:/m) {
		my $origStr = '^BuildArch:.*$';
		my $replStr = "BuildArch: noarch";
		$input_scalar =~ s/$origStr/$replStr/m;
	}

	# delete any existing firewalld entries
	if ($input_scalar =~ /^%config.*firewalld/m) {
		my $origStr = '^%config.*firewalld.*simpana.*$\n';
		$input_scalar =~ s/$origStr//m;

		$origStr = '^%config.*firewalld.*splunk.*$\n';
		$input_scalar =~ s/$origStr//m;
	}

	# Add firewalld entries if RHEL7 or later
	if ($osRelease >= 7){
		my $simpana = '%config(noreplace) %attr(744, root, root) /etc/firewalld/service/simpana';
		my $splunk = '%config(noreplace) %attr(744, root, root) /etc/firewalld/service/splunk';
		$input_scalar = $input_scalar . $simpana;
		$input_scalar = $input_scalar . "\n" . $splunk . "\n";
	}

	open (OUTPUT, "> $file") or die;
	print OUTPUT "$input_scalar";
	close OUTPUT;

	# certify_config.py
	$file = 'certify_config.py';
	if (defined $net && $net ne '') {
		open (INPUT,"<$file") or die;
		@input_array=<INPUT>;
		close(INPUT);
		$input_scalar=join("",@input_array);

		if ($net eq 'hal' || $net eq 'jwics' || $net eq 'titan') {
			if ($input_scalar =~ /^minlen/m) {
				my $origStr = '^minlen.*$';
				my $replStr = "minlen = 12";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
			if ($input_scalar =~ /^pass_max_days/m) {
				my $origStr = '^pass_max_days.*$';
				my $replStr = "pass_max_days = 90";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
		} elsif ($net eq 'wnet') {
			if ($input_scalar =~ /^minlen/m) {
				my $origStr = '^minlen.*$';
				my $replStr = "minlen = 14";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
			if ($input_scalar =~ /^pass_max_days/m) {
				my $origStr = '^pass_max_days.*$';
				my $replStr = "pass_max_days = 90";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
		} elsif ($net eq 'gs') {
			if ($input_scalar =~ /^minlen/m) {
				my $origStr = '^minlen.*$';
				my $replStr = "minlen = 8";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
			if ($input_scalar =~ /^pass_max_days/m) {
				my $origStr = '^pass_max_days.*$';
				my $replStr = "pass_max_days = 180";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
		} elsif ($net eq 'ohares') {
			if ($input_scalar =~ /^minlen/m) {
				my $origStr = '^minlen.*$';
				my $replStr = "minlen = 10";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
			if ($input_scalar =~ /^pass_max_days/m) {
				my $origStr = '^pass_max_days.*$';
				my $replStr = "pass_max_days = 180";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
		} else {
			if ($input_scalar =~ /^minlen/m) {
				my $origStr = '^minlen.*$';
				my $replStr = "minlen = 8";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
			if ($input_scalar =~ /^pass_max_days/m) {
				my $origStr = '^pass_max_days.*$';
				my $replStr = "pass_max_days = 180";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
		}

		if ($net eq 'hal' || $net eq 'jwics' || $net eq 'titan' || $net eq 'wnet') {
			if ($input_scalar =~ /^USB_STORAGE/m) {
				my $origStr = '^USB_STORAGE.*$';
				my $replStr = "USB_STORAGE = 'n'";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
		} else {
			if ($input_scalar =~ /^USB_STORAGE/m) {
				my $origStr = '^USB_STORAGE.*$';
				my $replStr = "USB_STORAGE = 'y'";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
		}

		open (OUTPUT, "> $file") or die;
		print OUTPUT "$input_scalar";
		close OUTPUT;
	} else {
		die "No network defined\n";
	}

	# my.cnf.certify
	$file = 'my.cnf.certify';
	if (defined $net && $net ne '') {
		open (INPUT,"<$file") or die;
		my @input_array=<INPUT>;
		close(INPUT);
		my $input_scalar=join("",@input_array);
		my ($origStr, $replStr);

		if ($net eq 'hal') {
			if ($input_scalar =~ /^host/m) {
				my $origStr = '^host.*$';
				my $replStr = "host = jupiter.doe.ic.gov";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
		} elsif ($net eq 'jwics') {
			if ($input_scalar =~ /^host/m) {
				my $origStr = '^host.*$';
				my $replStr = "host = corbin.llnl-doe.ic.gov";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
		} elsif ($net eq 'wnet') {
			if ($input_scalar =~ /^host/m) {
				my $origStr = '^host.*$';
				my $replStr = "host = yum.wnet.gov";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
		} elsif ($net eq 'gs') {
			if ($input_scalar =~ /^host/m) {
				my $origStr = '^host.*$';
				my $replStr = "host = corbin.llnl.gov";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
		} elsif ($net eq 'ohares') {
			if ($input_scalar =~ /^host/m) {
				my $origStr = '^host.*$';
				my $replStr = "host = www.ohares.us";
				$input_scalar =~ s/$origStr/$replStr/m;
			}
		} else {
			die "No network defined\n";
		}

		open (OUTPUT, "> $file") or die;
		print OUTPUT "$input_scalar";
		close OUTPUT;
	} else {
		die "No network defined\n";
	}
}

# Build rpms
sub buildRPMS {
	foreach my $net (@net) {
		foreach my $distro ($redhatDistro,$centosDistro) {
			foreach my $location ('nfs/ddn', 'nfs/sun', 'nfs/netapp') {
				######### remove when ready
				next;
				if ( -d "$location") { 
					chdir "${baseDir}/${location}";
					if ( -f "Makefile.PL" ) {
						system("./Makefile.PL $net $distro");
					} else {
						die "File Makefile.PL missing\n";
					}
				} else {
					die "$location missing\n";
				}
				chdir "$baseDir";
			}
			chdir "$baseDir";
			changeFiles($net,$distro);
			$net ne '' && system("make rpmbuild");
		}
	}
}

buildRPMS();
`rm changelog`;

# PGP sign the rpms
print "Sign RPM packages\n";
system("rpm --addsign $ENV{HOME}/rpmbuild/RPMS/*/certify*.rpm");

exit 0;
