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
if ($domainname eq "www.ohares.us" ||
		$domainname eq "master.ohares.us") {
	@all = ('ohares');
	@good_args = ('ohares','all');
} elsif ($hostname eq "corbin" ||
		$hostname eq "zdiv-rhel5-client-i386" ||
		$hostname eq "zdiv-rhel5-client-x86_64" ||
		$hostname eq "zdiv-rhel6-workstation" ||
		$hostname eq "zdiv-rhel7-server" ||
	 	$hostname eq "zdiv-rhel7-workstation") {
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

sub changeFiles {
	my $net = shift;
	my $distro = shift;

	# Makefile
	my $file = 'Makefile';
	open (INPUT,"<$file") or die;
	my @input_array=<INPUT>;
	close(INPUT);
	my $input_scalar=join("",@input_array);
	my ($origStr, $replStr);

	-f "VERSION" or die "No version file";
	my $version = `cat VERSION`;
	chomp $version;
	if ($input_scalar =~ /^Version= /m) {
		my $origStr = '^Version=.*$';
		my $replStr = "Version= $version";
		$input_scalar =~ s/$origStr/$replStr/m;
	}

	-f "RELEASE" or die "No release file";
	my $releaseNo = `cat RELEASE`;
	chomp $releaseNo;


	my $release = `lsb_release -sr`;
	chomp $release;
	$release =~ s/\..*//;

	my $arch = `uname -i`;
	chomp $arch;

	if ($input_scalar =~ /^Release= /m) {
		my $origStr = '^Release=.*$';
		my $replStr = "Release= ${releaseNo}.${distro}${release}_${arch}.${net}";
		$input_scalar =~ s/$origStr/$replStr/m;
	}

	if ($input_scalar =~ /^Distro= /m) {
		my $origStr = '^Distro=.*$';
		my $replStr = "Distro= ${distro}${release}_${arch}";
		$input_scalar =~ s/$origStr/$replStr/m;
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
	foreach my $entry (@net) {
		foreach my $distro ('redhat','centos') {
			foreach my $location ('nfs/ddn', 'nfs/sun', 'nfs/netapp') {
				if ( -d "$location") { 
					chdir "${baseDir}/${location}";
					if ( -f "Makefile.PL" ) {
						system("./Makefile.PL $entry $distro");
					} else {
						die "File Makefile.PL missing\n";
					}
				} else {
					die "$location missing\n";
				}
				chdir "$baseDir";
			}
			chdir "$baseDir";
			changeFiles($entry,$distro);
			$entry ne '' && system("make rpmbuild");
		}
	}
}

buildRPMS();
`rm changelog`;

# PGP sign the rpms
print "Sign RPM packages\n";
system("rpm --addsign $ENV{HOME}/rpmbuild/RPMS/noarch/certify*.rpm");

exit 0;
