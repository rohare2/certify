#!/usr/bin/perl -w
# Makefile.PL
# $Id$
# $Date$
#
use strict;

my $debug = 0;

my $baseDir = `pwd`;
chomp $baseDir;

system("git log > changelog");

sub changeFiles {
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

	if ($input_scalar =~ /^Release= /m) {
		my $origStr = '^Release=.*$';
		my $replStr = "Release= ${releaseNo}.${distro}${release}";
		$input_scalar =~ s/$origStr/$replStr/m;
	}

	if ($input_scalar =~ /^Distro= /m) {
		my $origStr = '^Distro=.*$';
		my $replStr = "Distro= ${distro}${release}";
		$input_scalar =~ s/$origStr/$replStr/m;
	}

	open (OUTPUT, "> $file") or die;
	print OUTPUT "$input_scalar";
	close OUTPUT;

}

# Build rpms
sub buildRPMS {
	foreach my $distro ('redhat','centos') {
		foreach my $location ('nfs/ddn', 'nfs/sun', 'nfs/netapp') {
			if ( -d "$location") { 
				chdir "${baseDir}/${location}";
				if ( -f "Makefile.PL" ) {
					system("./Makefile.PL $distro");
				} else {
					die "File Makefile.PL missing\n";
				}
			} else {
				die "$location missing\n";
			}
			chdir "$baseDir";
		}
		chdir "$baseDir";
		changeFiles($distro);
		system("make rpmbuild");
	}
}

buildRPMS();
`rm changelog`;

# PGP sign the rpms
print "Sign RPM packages\n";
system("rpm --addsign $ENV{HOME}/rpmbuild/RPMS/noarch/certify*.rpm");

exit 0;
